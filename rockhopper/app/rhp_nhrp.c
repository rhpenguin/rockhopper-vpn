/*

	Copyright (C) 2015-2016 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.

	You can redistribute and/or modify this software under the
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/

//
// A NHRP's minimum implementation required for DMVPN.
//

/*

	- Flexible Dynamic Mesh VPN:
			https://tools.ietf.org/html/draft-detienne-dmvpn-01

	- Shortcut Switching Enhancements for NHRP in DMVPN Networks
			http://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipaddr_nhrp/configuration/xe-3s/Shortcut_Switching_Enhancements_for_NHRP_in_DMVPN_Networks.html

	- Cisco's NAT extension (NHRP):
			http://www.cisco.com/c/en/us/td/docs/ios/ios_xe/sec_secure_connectivity/configuration/guide/convert/sec_dmvpn_xe_3s_book/sec_dmvpn_dt_spokes_b_nat_xe.html#wp1062435

*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <asm/types.h>
#include <sys/capability.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <linux/errqueue.h>

#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_protocol.h"
#include "rhp_packet.h"
#include "rhp_netsock.h"
#include "rhp_wthreads.h"
#include "rhp_config.h"
#include "rhp_vpn.h"
#include "rhp_ikev2.h"
#include "rhp_ikev2_mesg.h"
#include "rhp_forward.h"
#include "rhp_eoip.h"
#include "rhp_esp.h"
#include "rhp_nhrp.h"

rhp_mutex_t rhp_nhrp_lock;

static u32 _rhp_nhrp_hashtbl_rnd;

static rhp_nhrp_cache**	_rhp_nhrp_cache_hash_tbl = NULL;
static rhp_nhrp_cache _rhp_nhrp_list_head;

static rhp_timer _rhp_nhrp_cache_timer;


static u32 _rhp_nhrp_req_sess_hashtbl_rnd;

static rhp_nhrp_req_session**	_rhp_nhrp_req_sess_hash_tbl = NULL;

static u32 _rhp_dmvpn_conn_shortcut_rnd;

rhp_nhrp_cache_global_statistics rhp_nhrp_cache_statistics_tbl;

void rhp_nhrp_get_statistics(rhp_nhrp_cache_global_statistics* table)
{
	RHP_TRC(0,RHPTRCID_NHRP_GET_STATISTICS,"x",table);
	RHP_LOCK(&rhp_nhrp_lock);
	memcpy(table,&rhp_nhrp_cache_statistics_tbl,sizeof(rhp_nhrp_cache_global_statistics));
	RHP_UNLOCK(&rhp_nhrp_lock);
	RHP_TRC(0,RHPTRCID_NHRP_GET_STATISTICS_RTRN,"x",table);
}

void rhp_nhrp_clear_statistics()
{
	RHP_TRC(0,RHPTRCID_NHRP_CLEAR_STATISTICS,"");
	RHP_LOCK(&rhp_nhrp_lock);
	memset(&rhp_nhrp_cache_statistics_tbl,0,
			sizeof(rhp_nhrp_cache_global_statistics) - sizeof(rhp_nhrp_cache_global_statistics_dont_clear));
	RHP_UNLOCK(&rhp_nhrp_lock);
	RHP_TRC(0,RHPTRCID_NHRP_CLEAR_STATISTICS_RTRN,"");
}


struct _rhp_nhrp_bridge_ctx {
	rhp_ip_addr protocol_addr;
	rhp_ip_addr nbma_addr;
	rhp_vpn_ref* rx_vpn_ref;
};
typedef struct _rhp_nhrp_bridge_ctx	rhp_nhrp_bridge_ctx;

static void _rhp_nhrp_update_bridge_cache_task(int worker_index,void *ctx)
{
	int err = -EINVAL;
	rhp_nhrp_bridge_ctx* br_ctx = (rhp_nhrp_bridge_ctx*)ctx;
	rhp_vpn* rx_vpn = RHP_VPN_REF(br_ctx->rx_vpn_ref);

	RHP_TRC(0,RHPTRCID_NHRP_UPDATE_BRIDGE_CACHE_TASK,"dxx",worker_index,br_ctx,rx_vpn);
	rhp_ip_addr_dump("br_ctx->protocol_addr",&(br_ctx->protocol_addr));

	RHP_LOCK(&(rx_vpn->lock));

	if( !_rhp_atomic_read(&(rx_vpn->is_active)) ){
		err = -EINVAL;
		goto error;
	}

	err = rhp_bridge_static_neigh_cache_create(
					rx_vpn->vpn_realm_id,rx_vpn->internal_net_info.dummy_peer_mac,
					&(br_ctx->protocol_addr),RHP_BRIDGE_SIDE_VPN,RHP_BRIDGE_SCACHE_DUMMY);
	if( err ){
		RHP_BUG("%d",err);
	}


error:
	RHP_UNLOCK(&(rx_vpn->lock));
	rhp_vpn_unhold(br_ctx->rx_vpn_ref);

	_rhp_free(br_ctx);

	RHP_TRC(0,RHPTRCID_NHRP_UPDATE_BRIDGE_CACHE_TASK_RTRN,"dxxE",worker_index,br_ctx,rx_vpn,err);
	return;
}

static void _rhp_nhrp_delete_bridge_cache_task(int worker_index,void *ctx)
{
	int err = -EINVAL;
	rhp_nhrp_bridge_ctx* br_ctx = (rhp_nhrp_bridge_ctx*)ctx;
	rhp_vpn* rx_vpn = RHP_VPN_REF(br_ctx->rx_vpn_ref);

	RHP_TRC(0,RHPTRCID_NHRP_DELETE_BRIDGE_CACHE_TASK,"dxx",worker_index,br_ctx,rx_vpn);
	rhp_ip_addr_dump("br_ctx->protocol_addr",&(br_ctx->protocol_addr));
	rhp_ip_addr_dump("br_ctx->nbma_addr",&(br_ctx->nbma_addr));

	// rx_vpn may be already destroyed. Don't touch the object itself.

	err = rhp_bridge_static_neigh_cache_delete(
					rx_vpn->vpn_realm_id,&(br_ctx->protocol_addr),NULL,NULL);
	if( err ){
		RHP_TRC(0,RHPTRCID_NHRP_DELETE_BRIDGE_CACHE_TASK_NO_ENT,"dxx",worker_index,br_ctx,rx_vpn);
	}


	rhp_vpn_unhold(br_ctx->rx_vpn_ref);

	_rhp_free(br_ctx);

	RHP_TRC(0,RHPTRCID_NHRP_DELETE_BRIDGE_CACHE_TASK_RTRN,"dxxE",worker_index,br_ctx,rx_vpn,err);
	return;
}

static int _rhp_nhrp_update_bridge_cache(rhp_ip_addr* protocol_addr,
		rhp_ip_addr* nbma_addr,rhp_vpn* rx_vpn,int do_delete)
{
	int err = -EINVAL;
	rhp_nhrp_bridge_ctx* br_ctx = NULL;

	RHP_TRC(0,RHPTRCID_NHRP_UPDATE_BRIDGE_CACHE,"xxd",protocol_addr,rx_vpn,do_delete);
	rhp_ip_addr_dump("protocol_addr",protocol_addr);
	rhp_ip_addr_dump("nbma_addr",nbma_addr);

	br_ctx = (rhp_nhrp_bridge_ctx*)_rhp_malloc(sizeof(rhp_nhrp_bridge_ctx));
	if( br_ctx == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	memset(br_ctx,0,sizeof(rhp_nhrp_bridge_ctx));

	memcpy(&(br_ctx->protocol_addr),protocol_addr,sizeof(rhp_ip_addr));

	if( nbma_addr ){
		memcpy(&(br_ctx->nbma_addr),nbma_addr,sizeof(rhp_ip_addr));
	}

	br_ctx->rx_vpn_ref = rhp_vpn_hold_ref(rx_vpn);

	err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_1,
			(!do_delete ? _rhp_nhrp_update_bridge_cache_task : _rhp_nhrp_delete_bridge_cache_task),
			br_ctx);
	if( err ){
		rhp_vpn_unhold(br_ctx->rx_vpn_ref);
		_rhp_free(br_ctx);
		goto error;
	}

	RHP_TRC(0,RHPTRCID_NHRP_UPDATE_BRIDGE_CACHE_RTRN,"xx",protocol_addr,rx_vpn);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_UPDATE_BRIDGE_CACHE_ERR,"xxE",protocol_addr,rx_vpn,err);
	return err;
}


void rhp_nhrp_cache_dump(char* label,rhp_nhrp_cache* nhrp_c)
{
	_RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
  if( !_RHP_TRC_COND(_rhp_trc_user_id(),0) ){
    return;
  }

  if( nhrp_c == NULL ){
    RHP_TRC(0,RHPTRCID_NHRP_DUMP_NULL,"s",label);
    return;
  }

  RHP_TRC(0,RHPTRCID_NHRP_DUMP,"sxxxxxutMbbdd",label,nhrp_c,nhrp_c->next_hash,nhrp_c->pre_list,nhrp_c->next_list,RHP_VPN_REF(nhrp_c->vpn_ref),nhrp_c->vpn_realm_id,nhrp_c->created_time,nhrp_c->vpn_dummy_mac,nhrp_c->uniqueness,nhrp_c->static_cache,nhrp_c->rx_hold_time,nhrp_c->rx_mtu);
  rhp_ip_addr_dump("protocol_addr",&(nhrp_c->protocol_addr));
  rhp_ip_addr_dump("nbma_addr",&(nhrp_c->nbma_addr));
  rhp_ip_addr_dump("nat_addr",&(nhrp_c->nat_addr));

  return;
}

static int _rhp_nhrp_hash(int addr_family,u8* protocol_ip)
{
  u32 hval = 0;

  if( addr_family == AF_INET ){
  	hval = _rhp_hash_ipv4_1(*((u32*)protocol_ip),_rhp_nhrp_hashtbl_rnd);
  }else if( addr_family == AF_INET6 ){
  	hval = _rhp_hash_ipv6_1(protocol_ip,_rhp_nhrp_hashtbl_rnd);
  }else{
  	RHP_BUG("%d",addr_family);
  }

  return (hval % rhp_gcfg_nhrp_cache_hash_size);
}

static void _rhp_nhrp_free_cache(rhp_nhrp_cache* nhrp_c)
{
  RHP_TRC(0,RHPTRCID_NHRP_FREE_CACHE,"xx",nhrp_c,RHP_VPN_REF(nhrp_c->vpn_ref));

	if( nhrp_c->vpn_ref ){
		rhp_vpn_unhold(nhrp_c->vpn_ref);
	}

	_rhp_free(nhrp_c);
	return;
}

static rhp_nhrp_cache* _rhp_nhrp_cache_alloc()
{
	rhp_nhrp_cache* nhrp_c;

	nhrp_c = (rhp_nhrp_cache*)_rhp_malloc(sizeof(rhp_nhrp_cache));
	if( nhrp_c == NULL ){
    RHP_BUG("");
    return NULL;
	}

	memset(nhrp_c,0,sizeof(rhp_nhrp_cache));

	nhrp_c->tag[0] = '#';
	nhrp_c->tag[1] = 'N';
	nhrp_c->tag[2] = 'R';
	nhrp_c->tag[3] = 'C';

	nhrp_c->created_time = _rhp_get_time();

  RHP_TRC(0,RHPTRCID_CACHE_CACHE_ALLOC,"x",nhrp_c);
	return nhrp_c;
}

static int _rhp_nhrp_cache_delete(rhp_nhrp_cache* nhrp_c)
{
  int err = 0;
  u32 hval;
  rhp_nhrp_cache *nhrp_c_tmp = NULL,*nhrp_c_tmp_p;

  RHP_TRC(0,RHPTRCID_NHRP_CACHE_DELETE,"x",nhrp_c);

  hval = _rhp_nhrp_hash(nhrp_c->protocol_addr.addr_family,nhrp_c->protocol_addr.addr.raw);

  nhrp_c_tmp = _rhp_nhrp_cache_hash_tbl[hval];
  nhrp_c_tmp_p = NULL;
  while( nhrp_c_tmp ){

    if( nhrp_c_tmp == nhrp_c ){
   	  break;
    }

    nhrp_c_tmp_p = nhrp_c_tmp;
    nhrp_c_tmp = nhrp_c_tmp->next_hash;
  }

  if( nhrp_c_tmp == NULL ){
    err = -ENOENT;
    RHP_TRC(0,RHPTRCID_NHRP_CACHE_DELETE_NOT_FOUND,"x",nhrp_c);
    goto error;
  }

	err = _rhp_nhrp_update_bridge_cache(
					&(nhrp_c->protocol_addr),&(nhrp_c->nbma_addr),
					RHP_VPN_REF(nhrp_c->vpn_ref),1);
	if( err ){
		RHP_BUG("%d",err);
		err = 0;
	}

  if( nhrp_c_tmp_p ){
    nhrp_c_tmp_p->next_hash = nhrp_c_tmp->next_hash;
  }else{
    _rhp_nhrp_cache_hash_tbl[hval] = nhrp_c_tmp->next_hash;
  }

  nhrp_c->pre_list->next_list = nhrp_c->next_list;
  if( nhrp_c->next_list ){
  	nhrp_c->next_list->pre_list = nhrp_c->pre_list;
  }
  nhrp_c->pre_list = NULL;
  nhrp_c->next_list = NULL;

  rhp_nhrp_cache_statistics_tbl.dc.cache_num--;

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,nhrp_c->vpn_realm_id,RHP_LOG_ID_NHRP_CACHE_DELETE,"AAAu",&(nhrp_c->protocol_addr),&(nhrp_c->nbma_addr),&(nhrp_c->nat_addr),rhp_nhrp_cache_statistics_tbl.dc.cache_num);

  RHP_TRC(0,RHPTRCID_NHRP_CACHE_DELETE_RTRN,"x",nhrp_c);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_CACHE_DELETE_ERR,"xE",nhrp_c,err);
	return err;
}

static int _rhp_nhrp_cache_put(rhp_nhrp_cache* nhrp_c)
{
	int err = -EINVAL;
  u32 hval;

  RHP_TRC(0,RHPTRCID_NHRP_CACHE_PUT,"x",nhrp_c);
  rhp_nhrp_cache_dump("_rhp_nhrp_cache_put",nhrp_c);


  hval = _rhp_nhrp_hash(nhrp_c->protocol_addr.addr_family,nhrp_c->protocol_addr.addr.raw);

  if( rhp_nhrp_cache_statistics_tbl.dc.cache_num
  			> (unsigned long)rhp_gcfg_nhrp_cache_max_entries ){

    RHP_TRC(0,RHPTRCID_NHRP_CACHE_PUT_TOO_MANY_ENTRIES,"xqd",nhrp_c,(u64)rhp_nhrp_cache_statistics_tbl.dc.cache_num,rhp_gcfg_nhrp_cache_max_entries);
  	return RHP_STATUS_NHRP_MAX_CACHE_NUM_REACHED;
  }

  nhrp_c->next_hash = _rhp_nhrp_cache_hash_tbl[hval];
  _rhp_nhrp_cache_hash_tbl[hval] = nhrp_c;

  nhrp_c->next_list = _rhp_nhrp_list_head.next_list;
  if( _rhp_nhrp_list_head.next_list ){
	  _rhp_nhrp_list_head.next_list->pre_list = nhrp_c;
  }
  nhrp_c->pre_list = &_rhp_nhrp_list_head;
  _rhp_nhrp_list_head.next_list = nhrp_c;


	err = _rhp_nhrp_update_bridge_cache(
					&(nhrp_c->protocol_addr),&(nhrp_c->nbma_addr),
					RHP_VPN_REF(nhrp_c->vpn_ref),0);
	if( err ){
		RHP_BUG("%d",err);
		err = 0;
	}

  rhp_nhrp_cache_statistics_tbl.dc.cache_num++;

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,nhrp_c->vpn_realm_id,RHP_LOG_ID_NHRP_CACHE_PUT,"AAAu",&(nhrp_c->protocol_addr),&(nhrp_c->nbma_addr),&(nhrp_c->nat_addr),rhp_nhrp_cache_statistics_tbl.dc.cache_num);

  RHP_TRC(0,RHPTRCID_NHRP_CACHE_PUT_RTRN,"xd",nhrp_c,rhp_nhrp_cache_statistics_tbl.dc.cache_num);
  return 0;
}

static rhp_nhrp_cache* _rhp_nhrp_cache_get(unsigned long realm_id,
		int addr_family,u8* protocol_addr)
{
  rhp_nhrp_cache* nhrp_c = NULL;
  u32 hval;
  int is_linklocal = 0;

  if( addr_family == AF_INET ){
  	RHP_TRC(0,RHPTRCID_NHRP_CACHE_GET_V4,"Ld4u","AF",addr_family,*((u32*)protocol_addr),realm_id);
  }else if( addr_family == AF_INET6 ){
  	RHP_TRC(0,RHPTRCID_NHRP_CACHE_GET_V6,"Ld6u","AF",addr_family,protocol_addr,realm_id);
  	is_linklocal = rhp_ipv6_is_linklocal(protocol_addr);
  }else{
  	RHP_BUG("%d",addr_family);
  	return NULL;
  }

  if( is_linklocal ){

  	if( realm_id == 0 || realm_id == RHP_VPN_REALM_ID_UNKNOWN ){
  		goto not_found;
  	}

  }else{

  	realm_id = 0;
  }


  rhp_nhrp_cache_statistics_tbl.referenced++;

  hval = _rhp_nhrp_hash(addr_family,protocol_addr);

  nhrp_c = _rhp_nhrp_cache_hash_tbl[hval];
  while( nhrp_c ){

  	if( !rhp_ip_addr_cmp_value(&(nhrp_c->protocol_addr),
  				(addr_family == AF_INET ? 4 : 16),protocol_addr) &&
  			(realm_id == 0 || realm_id == nhrp_c->vpn_realm_id) ){
      break;
    }

    nhrp_c = nhrp_c->next_hash;
  }

  if( nhrp_c ){

  	RHP_TRC(0,RHPTRCID_NHRP_CACHE_GET_RTRN,"xxd",nhrp_c,RHP_VPN_REF(nhrp_c->vpn_ref),is_linklocal);
  	rhp_nhrp_cache_dump("_rhp_nhrp_cache_get",nhrp_c);

  }else{

not_found:
    rhp_nhrp_cache_statistics_tbl.cached_not_found++;
    if( addr_family == AF_INET ){
    	RHP_TRC(0,RHPTRCID_NHRP_CACHE_GET_V4_NO_ENT,"Ld4d","AF",addr_family,*((u32*)protocol_addr),is_linklocal);
    }else if( addr_family == AF_INET6 ){
    	RHP_TRC(0,RHPTRCID_NHRP_CACHE_GET_V6_NO_ENT,"Ld6d","AF",addr_family,protocol_addr,is_linklocal);
    }
  }

  return nhrp_c;
}

int rhp_nhrp_cache_flush_by_vpn(rhp_vpn* vpn)
{
	int err = 0;
  rhp_nhrp_cache* nhrp_c = NULL;
  int n = 0;

  RHP_LOCK(&rhp_nhrp_lock);

  nhrp_c = _rhp_nhrp_list_head.next_list;
  while( nhrp_c ){

    rhp_nhrp_cache* nhrp_c_n = nhrp_c->next_list;

  	if( RHP_VPN_REF(nhrp_c->vpn_ref) == vpn ){

  		if( !_rhp_nhrp_cache_delete(nhrp_c) ){
				_rhp_nhrp_free_cache(nhrp_c);
  		}

  		n++;
  	}

  	nhrp_c = nhrp_c_n;
  }

  RHP_UNLOCK(&rhp_nhrp_lock);

  if( !err && n < 1 ){
  	err = -ENOENT;
  }

  return err;
}

//
// [CAUTION]
//
//   Caller must NOT acquire rhp_bridge_lock, rlm->lock and (rhp_ifc_entry*)v_ifc->lock.
//
int rhp_nhrp_cache_get(
		int addr_family,u8* protocol_addr,unsigned long ll_proto_addr_rlm_id,
		unsigned long* peer_rlm_id_r,rhp_ip_addr* peer_nbma_addr_r,u8* vpn_dummy_per_mac_r)
{
	int err = -ENOENT;
  rhp_nhrp_cache* nhrp_c = NULL;

  RHP_LOCK(&rhp_nhrp_lock);

  nhrp_c = _rhp_nhrp_cache_get(ll_proto_addr_rlm_id,addr_family,protocol_addr);
  if( nhrp_c ){

  	peer_nbma_addr_r->addr_family = nhrp_c->nbma_addr.addr_family;
  	memcpy(peer_nbma_addr_r->addr.raw,nhrp_c->nbma_addr.addr.raw,16);

		memcpy(vpn_dummy_per_mac_r,nhrp_c->vpn_dummy_mac,6);

		*peer_rlm_id_r = nhrp_c->vpn_realm_id;

		err = 0;
  }

  RHP_UNLOCK(&rhp_nhrp_lock);

  return err;
}

//
// [CAUTION]
//
//   Caller must NOT acquire rhp_bridge_lock, rlm->lock and (rhp_ifc_entry*)v_ifc->lock.
//
rhp_vpn* rhp_nhrp_cache_get_vpn(
		int addr_family,u8* protocol_addr,unsigned long rlm_id)
{
  rhp_nhrp_cache* nhrp_c = NULL;
  rhp_vpn* vpn = NULL;

  RHP_LOCK(&rhp_nhrp_lock);

  nhrp_c = _rhp_nhrp_cache_get(rlm_id,addr_family,protocol_addr);
  if( nhrp_c ){

  	vpn = RHP_VPN_REF(nhrp_c->vpn_ref);
  	if( vpn ){
  		rhp_vpn_hold(vpn);
  	}
  }

  RHP_UNLOCK(&rhp_nhrp_lock);

  return vpn;
}


int rhp_nhrp_cache_get_peer_dummy_mac(
		int addr_family,u8* protocol_addr,unsigned long ll_proto_addr_rlm_id,
		u8* vpn_dummy_per_mac_r)
{
	int err = -ENOENT;
  rhp_nhrp_cache* nhrp_c = NULL;

  RHP_LOCK(&rhp_nhrp_lock);

  nhrp_c = _rhp_nhrp_cache_get(ll_proto_addr_rlm_id,addr_family,protocol_addr);
  if( nhrp_c ){

		if( !_rhp_mac_addr_null(nhrp_c->vpn_dummy_mac) ){

			memcpy(vpn_dummy_per_mac_r,nhrp_c->vpn_dummy_mac,6);

			err = 0;
		}
  }

  RHP_UNLOCK(&rhp_nhrp_lock);

  if( addr_family == AF_INET ){
  	RHP_TRC(0,RHPTRCID_NHRP_CACHE_GET_PEER_DUMMY_MAC_V4,"Ld4uM","AF",addr_family,*((u32*)protocol_addr),ll_proto_addr_rlm_id,vpn_dummy_per_mac_r);
  }else if( addr_family == AF_INET6 ){
  	RHP_TRC(0,RHPTRCID_NHRP_CACHE_GET_PEER_DUMMY_MAC_V6,"Ld6uM","AF",addr_family,protocol_addr,ll_proto_addr_rlm_id,vpn_dummy_per_mac_r);
  }else{
  	RHP_BUG("%d",addr_family);
  }
  return err;
}

int rhp_nhrp_cache_enum(unsigned long rlm_id,int src_proto_addr_family,
		int (*callback)(rhp_nhrp_cache* nhrp_c,void* ctx),void* ctx)
{
	int err = 0;
  rhp_nhrp_cache* nhrp_c = NULL;
  int n = 0;

  RHP_LOCK(&rhp_nhrp_lock);

  nhrp_c = _rhp_nhrp_list_head.next_list;
  while( nhrp_c ){

  	if( (rlm_id == 0 || rlm_id == nhrp_c->vpn_realm_id) &&
  			(src_proto_addr_family == AF_UNSPEC || src_proto_addr_family == nhrp_c->protocol_addr.addr_family) ){

  		err = callback(nhrp_c,ctx);
  		if( err ){
  			break;
  		}
  		n++;
  	}

  	nhrp_c = nhrp_c->next_list;
  }

  RHP_UNLOCK(&rhp_nhrp_lock);

  if( !err && n < 1 ){
  	err = -ENOENT;
  }

  return err;
}


static int _rhp_nhrp_cache_delete_vpn_addr(rhp_vpn* rx_vpn,rhp_ip_addr* peer_proto_addr)
{
	rhp_ip_addr_list *next_hop_addr = rx_vpn->nhrp.nhs_next_hop_addrs, *next_hop_addr_p = NULL;

	while( next_hop_addr ){

		if( !rhp_ip_addr_cmp_ip_only(&(next_hop_addr->ip_addr),peer_proto_addr) ){
			break;
		}

		next_hop_addr_p = next_hop_addr;
		next_hop_addr = next_hop_addr->next;
	}

	if( next_hop_addr == NULL ){
		return -ENOENT;
	}


	if( next_hop_addr_p ){

		next_hop_addr_p->next = next_hop_addr->next;

	}else{

		rx_vpn->nhrp.nhs_next_hop_addrs = next_hop_addr->next;
	}

	rx_vpn->nhrp.nhs_next_hop_addrs_num--;

	_rhp_free(next_hop_addr);

	return 0;
}


struct _rhp_nhrp_cache_del_vpn_lst {

	struct _rhp_nhrp_cache_del_vpn_lst* next;

	rhp_vpn* rx_vpn;
	rhp_ip_addr peer_proto_addr;
};
typedef struct _rhp_nhrp_cache_del_vpn_lst rhp_nhrp_cache_del_vpn_lst;

static int _rhp_nhrp_cache_aging_del_vpns(rhp_nhrp_cache_del_vpn_lst* del_vpn_lst_head)
{
	rhp_nhrp_cache_del_vpn_lst* del_vpn_lst = del_vpn_lst_head;

	while( del_vpn_lst ){

		rhp_nhrp_cache_del_vpn_lst* del_vpn_lst_n = del_vpn_lst->next;

		RHP_LOCK(&(del_vpn_lst->rx_vpn->lock));

		if( _rhp_atomic_read(&(del_vpn_lst->rx_vpn->is_active)) ){

			_rhp_nhrp_cache_delete_vpn_addr(del_vpn_lst->rx_vpn,&(del_vpn_lst->peer_proto_addr));
		}

		RHP_UNLOCK(&(del_vpn_lst->rx_vpn->lock));
		_rhp_free(del_vpn_lst);

		del_vpn_lst = del_vpn_lst_n;
  }

	return 0;
}

static int _rhp_nhrp_cache_aging_exec = 0;
static int _rhp_nhrp_update_addr_task_pending = 0;


static void _rhp_nhrp_cache_aging_task(int worker_idx,void *ctx)
{
	int err = -EINVAL;
  rhp_nhrp_cache *nhrp_c_tmp,*nhrp_c_tmp_n;
  time_t now = _rhp_get_time();
  struct timespec proc_start,proc_now;
  rhp_nhrp_cache_del_vpn_lst *del_vpn_lst_head = NULL, *del_vpn_lst;

  RHP_TRC(0,RHPTRCID_NHRP_CACHE_AGING_TASK,"dxu",worker_idx,ctx,now);

  RHP_LOCK(&rhp_nhrp_lock);

  if( _rhp_nhrp_update_addr_task_pending ){
  	goto next_interval;
  }

  clock_gettime(CLOCK_MONOTONIC,&proc_start);

  {
	  nhrp_c_tmp = _rhp_nhrp_list_head.next_list;

	  while( nhrp_c_tmp ){

	  	nhrp_c_tmp_n = nhrp_c_tmp->next_list;

	  	if( !(nhrp_c_tmp->static_cache) ){

	  		rhp_vpn* vpn = RHP_VPN_REF(nhrp_c_tmp->vpn_ref);

	  		if(	nhrp_c_tmp->rx_hold_time < 1 ||
	  				((now - nhrp_c_tmp->created_time) >= (time_t)nhrp_c_tmp->rx_hold_time) ||
	  				(vpn && !_rhp_atomic_read(&(vpn->is_active))) ){

	  			if( vpn ){

						del_vpn_lst = (rhp_nhrp_cache_del_vpn_lst*)_rhp_malloc(sizeof(rhp_nhrp_cache_del_vpn_lst));
						if( del_vpn_lst == NULL ){

							RHP_BUG("");

						}else{

							memset(del_vpn_lst,0,sizeof(rhp_nhrp_cache_del_vpn_lst));

							del_vpn_lst->rx_vpn = vpn;
							rhp_vpn_hold(vpn)

							memcpy(&(del_vpn_lst->peer_proto_addr),&(nhrp_c_tmp->protocol_addr),sizeof(rhp_ip_addr));

							del_vpn_lst->next = del_vpn_lst_head;
							del_vpn_lst_head = del_vpn_lst;
						}
	  			}

	  			if( !_rhp_nhrp_cache_delete(nhrp_c_tmp) ){
	  				_rhp_nhrp_free_cache(nhrp_c_tmp);
	  			}
	  		}
	  	}

	  	{
				clock_gettime(CLOCK_MONOTONIC,&proc_now);

				if( proc_start.tv_sec != proc_now.tv_sec ||
						proc_now.tv_nsec - proc_start.tv_nsec > RHP_NET_CACHE_AGING_TASK_MAX_NSEC ){

					goto schedule_again;
				}
	  	}

	  	nhrp_c_tmp = nhrp_c_tmp_n;
	  }
  }

  RHP_UNLOCK(&rhp_nhrp_lock);


  {
  	int schedule_again;

  	rhp_ip_routing_nhrp_aging_cache(&schedule_again);
  	if( schedule_again ){

  		RHP_LOCK(&rhp_nhrp_lock);

  		goto schedule_again;
  	}
  }


  RHP_LOCK(&rhp_nhrp_lock);

  _rhp_nhrp_cache_aging_exec = 0;

  RHP_UNLOCK(&rhp_nhrp_lock);


  _rhp_nhrp_cache_aging_del_vpns(del_vpn_lst_head);

  RHP_TRC(0,RHPTRCID_NHRP_CACHE_AGING_TASK_RTRN,"");
  return;


schedule_again:
	err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_2,_rhp_nhrp_cache_aging_task,NULL);
	if( err ){
		_rhp_nhrp_cache_aging_exec = 0; // Next interval.
	}

	RHP_UNLOCK(&rhp_nhrp_lock);

  _rhp_nhrp_cache_aging_del_vpns(del_vpn_lst_head);

	RHP_TRC(0,RHPTRCID_NHRP_CACHE_AGING_TASK_SCHEDULE_AGAIN,"tutudE",proc_start.tv_sec,proc_start.tv_nsec,proc_now.tv_sec,proc_now.tv_nsec,_rhp_nhrp_cache_aging_exec,err);
	return;


next_interval:
  _rhp_nhrp_cache_aging_exec = 0;

  RHP_UNLOCK(&rhp_nhrp_lock);

  _rhp_nhrp_cache_aging_del_vpns(del_vpn_lst_head);

	RHP_TRC(0,RHPTRCID_NHRP_CACHE_AGING_TASK_NEXT_INTERVAL,"dE",_rhp_nhrp_cache_aging_exec,err);
  return;
}

static void _rhp_nhrp_cache_aging_timer(void *ctx,rhp_timer *timer)
{
	int err = 0;

  RHP_TRC(0,RHPTRCID_NHRP_CACHE_AGING_TIMER,"xx",ctx,timer);

	RHP_LOCK(&rhp_nhrp_lock);

	if( _rhp_nhrp_cache_aging_exec || _rhp_nhrp_update_addr_task_pending ){
	  RHP_TRC(0,RHPTRCID_NHRP_CACHE_AGING_TIMER_ADD_TASK_ALREADY_INVOKED,"xxdd",ctx,timer,_rhp_nhrp_cache_aging_exec,_rhp_nhrp_update_addr_task_pending);
		goto next_interval;
	}

  if( rhp_wts_dispach_ok(RHP_WTS_DISP_LEVEL_HIGH_2,1) ){

  	err = rhp_wts_add_task(RHP_WTS_DISP_RULE_MISC,
  					RHP_WTS_DISP_LEVEL_HIGH_2,NULL,_rhp_nhrp_cache_aging_task,NULL);
  	if( err ){
  	  RHP_TRC(0,RHPTRCID_NHRP_CACHE_AGING_TIMER_ADD_TASK_ERR,"xxE",ctx,timer,err);
  		goto next_interval;
  	}

  	_rhp_nhrp_cache_aging_exec = 1;
  }

next_interval:
  rhp_timer_reset(&(_rhp_nhrp_cache_timer));
  rhp_timer_add(&(_rhp_nhrp_cache_timer),(time_t)rhp_gcfg_nhrp_cache_aging_interval);

	RHP_UNLOCK(&rhp_nhrp_lock);

  RHP_TRC(0,RHPTRCID_NHRP_CACHE_AGING_TIMER_RTRN,"xx",ctx,timer);
	return;
}



static void _rhp_nhrp_req_sess_free(rhp_nhrp_req_session* nhrp_sess)
{
  RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_FREE,"xdxx",nhrp_sess,nhrp_sess->pkt_q_num,nhrp_sess->pkt_q.head,nhrp_sess->pkt_q.tail);

	if( rhp_timer_pending(&(nhrp_sess->timer)) ){
		RHP_BUG("");
		return;
	}

	while( 1 ){

		rhp_packet* pkt = _rhp_pkt_q_deq(&(nhrp_sess->pkt_q));
		if( pkt == NULL ){
			break;
		}

		nhrp_sess->pkt_q_num--;

		rhp_pkt_unhold(pkt);
	  rhp_nhrp_cache_statistics_tbl.dc.request_session_queued_num--;
	}

	_rhp_free(nhrp_sess);

  RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_FREE_RTRN,"x",nhrp_sess);
	return;
}

static void _rhp_nhrp_req_sess_hold(rhp_nhrp_req_session* nhrp_sess)
{
  _rhp_atomic_inc(&(nhrp_sess->refcnt));
  RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_HOLD,"xd",nhrp_sess,_rhp_atomic_read(&(nhrp_sess->refcnt)));
}

static void _rhp_nhrp_req_sess_unhold(rhp_nhrp_req_session* nhrp_sess)
{
  RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_UNHOLD,"xd",nhrp_sess,_rhp_atomic_read(&(nhrp_sess->refcnt)));

  if( _rhp_atomic_dec_and_test(&(nhrp_sess->refcnt)) ){

  	_rhp_nhrp_req_sess_free(nhrp_sess);
  }
}


static int _rhp_nhrp_req_sess_delete(rhp_nhrp_req_session* nhrp_sess)
{
  int err = 0;
  u32 hval;
  rhp_nhrp_req_session *nhrp_sess_tmp = NULL,*nhrp_sess_tmp_p;

  RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_DELETE,"xupdxj",nhrp_sess,nhrp_sess->vpn_realm_id,RHP_VPN_UNIQUE_ID_SIZE,nhrp_sess->vpn_uid,nhrp_sess->pkt_q_num,nhrp_sess->pkt_q.head,nhrp_sess->tx_request_id);

  hval = _rhp_nhrp_hash(nhrp_sess->target_protocol_ip.addr_family,nhrp_sess->target_protocol_ip.addr.raw);

  nhrp_sess_tmp = _rhp_nhrp_req_sess_hash_tbl[hval];
  nhrp_sess_tmp_p = NULL;
  while( nhrp_sess_tmp ){

    if( nhrp_sess_tmp == nhrp_sess ){
   	  break;
    }

    nhrp_sess_tmp_p = nhrp_sess_tmp;
    nhrp_sess_tmp = nhrp_sess_tmp->next_hash;
  }

  if( nhrp_sess_tmp == NULL ){
    err = -ENOENT;
    goto error;
  }

  if( nhrp_sess_tmp_p ){
  	nhrp_sess_tmp_p->next_hash = nhrp_sess_tmp->next_hash;
  }else{
    _rhp_nhrp_req_sess_hash_tbl[hval] = nhrp_sess_tmp->next_hash;
  }

  rhp_nhrp_cache_statistics_tbl.dc.request_sessions--;

  RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_DELETE_RTRN,"xuj",nhrp_sess,rhp_nhrp_cache_statistics_tbl.dc.request_sessions,hval);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_DELETE_ERR,"xE",nhrp_sess,err);
	return err;
}

static void _rhp_nhrp_req_sess_timer(void* arg,rhp_timer* timer)
{
	int err = -EINVAL;
	rhp_nhrp_req_session* nhrp_sess = (rhp_nhrp_req_session*)arg;
	rhp_packet* req_pkt_d = NULL;
	rhp_nhrp_cache *nhrp_c_dst = NULL;
	int completed = 0;
	unsigned long vpn_realm_id;
  u8 vpn_uid[RHP_VPN_UNIQUE_ID_SIZE];
  rhp_ip_addr target_protocol_ip, src_nbma_ip;
	rhp_vpn_ref* vpn_ref = NULL;
	rhp_vpn* vpn = NULL;
	rhp_ifc_addr* ifc_addr;
	int sess_type = 0, retrans_err = 0;

  RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_TIMER,"xx",arg,timer);


	RHP_LOCK(&rhp_nhrp_lock);

	sess_type = nhrp_sess->request_type;

	vpn_realm_id = nhrp_sess->vpn_realm_id;
	memcpy(vpn_uid,nhrp_sess->vpn_uid,RHP_VPN_UNIQUE_ID_SIZE);

	memcpy(&target_protocol_ip,&(nhrp_sess->target_protocol_ip),sizeof(rhp_ip_addr));
	memcpy(&src_nbma_ip,&(nhrp_sess->src_nbma_ip),sizeof(rhp_ip_addr));

	rhp_ip_addr_dump("target_protocol_ip",&target_protocol_ip);
	rhp_ip_addr_dump("src_nbma_ip",&src_nbma_ip);

	RHP_UNLOCK(&rhp_nhrp_lock);



	vpn_ref = rhp_vpn_get_by_unique_id(vpn_uid);
	vpn = RHP_VPN_REF(vpn_ref);

	if( vpn == NULL ){

		RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_TIMER_NO_VPN_FOUND,"xxp",arg,timer,RHP_VPN_UNIQUE_ID_SIZE,vpn_uid);

		RHP_LOCK(&rhp_nhrp_lock); // Locked scope starts from here.
		goto error;
	}


	RHP_LOCK(&(vpn->lock));

	if( !_rhp_atomic_read(&(vpn->is_active)) ){

		RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_TIMER_VPN_NOT_ACTIVE,"xxxp",arg,timer,vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn_uid);
		RHP_UNLOCK(&(vpn->lock));

		RHP_LOCK(&rhp_nhrp_lock); // Locked scope starts from here.
		goto error;
	}

	if( src_nbma_ip.addr_family == AF_INET || src_nbma_ip.addr_family == AF_INET6 ){

		if( rhp_ip_addr_cmp_value(&src_nbma_ip,
					(vpn->local.if_info.addr_family == AF_INET ? 4 : 16),vpn->local.if_info.addr.raw) ){

			rhp_if_entry_dump("vpn->local.if_info.addr_family",&(vpn->local.if_info));
			RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_TIMER_VPN_NBMA_ADDR_CHANGED,"xxxp",arg,timer,vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn_uid);

			RHP_UNLOCK(&(vpn->lock));

			RHP_LOCK(&rhp_nhrp_lock); // Locked scope starts from here.
			goto error;
		}
	}


	if( nhrp_sess->request_type == RHP_PROTO_NHRP_PKT_REGISTRATION_REQ ||
			nhrp_sess->request_type == RHP_PROTO_NHRP_PKT_PURGE_REQ ){

		rhp_vpn_realm* rlm;
		rhp_ifc_entry* v_ifc;

		rlm = vpn->rlm;
		if( rlm == NULL ){

			RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_TIMER_VPN_NO_RLM_FOUND,"xxxp",arg,timer,vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn_uid);

			RHP_UNLOCK(&(vpn->lock));

			RHP_LOCK(&rhp_nhrp_lock); // Locked scope starts from here.
			goto error;
		}


		RHP_LOCK(&(rlm->lock));

		if( !_rhp_atomic_read(&(rlm->is_active)) ){

			RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_TIMER_VPN_RLM_NOT_ACTIVE,"xxxxp",arg,timer,vpn,rlm,RHP_VPN_UNIQUE_ID_SIZE,vpn_uid);

			RHP_UNLOCK(&(rlm->lock));
			RHP_UNLOCK(&(vpn->lock));

			RHP_LOCK(&rhp_nhrp_lock); // Locked scope starts from here.
			goto error;
		}


		v_ifc = rlm->internal_ifc->ifc;
		if( v_ifc == NULL ){

			RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_TIMER_VPN_NO_V_IFC,"xxxxp",arg,timer,vpn,rlm,RHP_VPN_UNIQUE_ID_SIZE,vpn_uid);

			RHP_UNLOCK(&(rlm->lock));
			RHP_UNLOCK(&(vpn->lock));

			RHP_LOCK(&rhp_nhrp_lock); // Locked scope starts from here.
			goto error;
		}


		RHP_LOCK(&(v_ifc->lock));

		ifc_addr = v_ifc->ifc_addrs;
		while( ifc_addr ){

			if( !rhp_ip_addr_cmp_ip_only(&target_protocol_ip,&(ifc_addr->addr)) ){
				break;
			}

			ifc_addr = ifc_addr->lst_next;
		}

		if( ifc_addr == NULL ){

			RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_TIMER_VPN_NO_V_IFC_ADDR,"xxxxxp",arg,timer,vpn,rlm,v_ifc,RHP_VPN_UNIQUE_ID_SIZE,vpn_uid);

			RHP_UNLOCK(&(v_ifc->lock));
			RHP_UNLOCK(&(rlm->lock));
			RHP_UNLOCK(&(vpn->lock));

			RHP_LOCK(&rhp_nhrp_lock); // Locked scope starts from here.
			goto error;
		}

		RHP_UNLOCK(&(v_ifc->lock));

		RHP_UNLOCK(&(rlm->lock));
	}

	RHP_UNLOCK(&(vpn->lock));



	RHP_LOCK(&rhp_nhrp_lock);

  RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_TIMER_TX_PKT,"xxdxd",arg,timer,nhrp_sess->pkt_q_num,nhrp_sess->pkt_q.head,nhrp_sess->done);
  rhp_ip_addr_dump("nhrp_sess->dst_protocol_ip",&(nhrp_sess->target_protocol_ip));

	nhrp_c_dst = _rhp_nhrp_cache_get(nhrp_sess->vpn_realm_id,
			nhrp_sess->target_protocol_ip.addr_family,nhrp_sess->target_protocol_ip.addr.raw);

  if( nhrp_c_dst ){

  	if( !_rhp_nhrp_req_sess_delete(nhrp_sess) ){
  	  _rhp_nhrp_req_sess_unhold(nhrp_sess);
  	}else{
  		RHP_BUG("");
  	}

		rhp_nhrp_cache_statistics_tbl.dc.request_session_queued_num--;

		completed = 1;

	  RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_TIMER_CACHE_FOUND,"xxx",arg,timer,nhrp_c_dst);

  }else{

  	rhp_packet* req_pkt;
  	time_t retry_timeout;

		if( nhrp_sess->done ){

			RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_TIMER_DONE,"xxddd",arg,timer,nhrp_sess->retries,nhrp_sess->done,rhp_gcfg_nhrp_request_session_retry_times);
			goto error;

		}else if( nhrp_sess->retries > rhp_gcfg_nhrp_request_session_retry_times ){

			retrans_err = 1;

			RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_TIMER_MAX_RETRIES,"xxddd",arg,timer,nhrp_sess->retries,nhrp_sess->done,rhp_gcfg_nhrp_request_session_retry_times);
			goto error;
		}


		req_pkt = _rhp_pkt_q_peek(&(nhrp_sess->pkt_q));
		if( req_pkt == NULL ){
			RHP_BUG("");
			goto error;
		}

		req_pkt_d = rhp_pkt_dup(req_pkt);
		if( req_pkt_d == NULL ){
		  RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_TIMER_DUP_PKT_ERR,"xxx",arg,timer,req_pkt);
			// Retry later in timer handler.
		}

		rhp_nhrp_cache_statistics_tbl.tx_request_retried++;

		nhrp_sess->retries++;

		retry_timeout = rhp_gcfg_nhrp_request_session_timeout*nhrp_sess->retries;
		if( retry_timeout > rhp_gcfg_nhrp_request_session_timeout_max ){
			retry_timeout = rhp_gcfg_nhrp_request_session_timeout_max;
		}

		rhp_timer_reset(timer);
		rhp_timer_add(timer,retry_timeout);
  }

	RHP_UNLOCK(&rhp_nhrp_lock);


	//
	// No lock(rhp_nhrp_lock) is needed anymore.
	//

  if( req_pkt_d ){

  	rhp_vpn_realm* tx_rlm = rhp_realm_get(vpn_realm_id);
  	if( tx_rlm == NULL ){
  		RHP_BUG("%d",vpn_realm_id);
  		goto error;
  	}

		rhp_gre_send_access_point(tx_rlm,req_pkt_d);
		if( err == RHP_STATUS_NO_GRE_ENCAP ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,tx_rlm->id,RHP_LOG_ID_NHRP_RETRANSMIT_REGISTRATION_REQ_MESG_NOT_GRE_ENCAP,"VE",vpn,err);
		}else if( err == RHP_STATUS_TX_ACCESS_POINT_NO_VPN ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,tx_rlm->id,RHP_LOG_ID_NHRP_RETRANSMIT_REGISTRATION_REQ_MESG_NO_HUB_OR_NHS_CONFIGURED,"VE",vpn,err);
		}else if( !err ){
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,tx_rlm->id,RHP_LOG_ID_NHRP_RETRANSMIT_REGISTRATION_REQ_MESG,"VE",vpn,err);
		}

  	rhp_pkt_unhold(req_pkt_d);

  	rhp_realm_unhold(tx_rlm);
  }

  if( completed ){

  	_rhp_nhrp_req_sess_unhold(nhrp_sess);
  }

  if( vpn ){

		rhp_vpn_unhold(vpn_ref);
  }

  RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_TIMER_RTRN,"xxx",arg,timer,vpn);
	return;

error:

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_NHRP_REQ_SESS_TIMER_ERR,"VnE",vpn,nhrp_sess,err);

	if( !_rhp_nhrp_req_sess_delete(nhrp_sess) ){
		_rhp_nhrp_req_sess_unhold(nhrp_sess);
	}else{
		RHP_BUG("");
	}
	nhrp_sess = NULL;

	rhp_nhrp_cache_statistics_tbl.tx_request_err++;

	RHP_UNLOCK(&rhp_nhrp_lock);


	if( vpn ){

		RHP_LOCK(&(vpn->lock));

		if( sess_type == RHP_PROTO_NHRP_PKT_PURGE_REQ ){

		  RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_TIMER_ERR_PEND_PURGE_REG_GAVE_UP_START_REGISTRATION,"xxxdd",arg,timer,vpn,vpn->nhrp.nhc_pending_purge_reqs,rhp_gcfg_nhrp_registration_req_tx_margin_time);

			vpn->nhrp.nhc_pending_purge_reqs--;

			if( vpn->nhrp.nhc_pending_purge_reqs < 1 ){

				vpn->start_nhc_registration_timer(vpn,(time_t)rhp_gcfg_nhrp_registration_req_tx_margin_time);

				vpn->nhrp.nhc_pending_purge_reqs = 0;
			}

		}else if( sess_type == RHP_PROTO_NHRP_PKT_REGISTRATION_REQ &&
							retrans_err ){

		  RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_TIMER_ERR_REGISTRATION_REQ_ERR_INTERVAL_START,"xxdd",arg,timer,vpn,rhp_gcfg_nhrp_cache_update_interval_error);

			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_NHRP_REQ_SESS_TIMER_REGISTRATION_REQ_RETRY_FAILED,"VLE",vpn,"NHRP_PKT_TYPE",sess_type,err);

			vpn->quit_nhc_registration_timer(vpn);

			vpn->start_nhc_registration_timer(vpn,(time_t)rhp_gcfg_nhrp_cache_update_interval_error);
		}

		RHP_UNLOCK(&(vpn->lock));
		rhp_vpn_unhold(vpn_ref);
	}

  if( req_pkt_d ){
  	rhp_pkt_unhold(req_pkt_d);
  }

  RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_TIMER_ERR,"xxx",arg,timer,vpn);
	return;
}

static rhp_nhrp_req_session* _rhp_nhrp_req_sess_alloc(
		unsigned long rlm_id,
		u8* vpn_uid,
		u32 tx_request_id,
		int request_type, // RHP_PROTO_NHRP_PKT_XXX_REQ
		int target_addr_family,u8* target_protocol_addr,
		int src_nbma_addr_family,u8* src_nbma_addr)
{
	rhp_nhrp_req_session* nhrp_sess = NULL;

	if( target_addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_ALLOC_V4,"upjdLd4",rlm_id,RHP_VPN_UNIQUE_ID_SIZE,vpn_uid,tx_request_id,request_type,"AF",target_addr_family,*((u32*)target_protocol_addr));
	}else if( target_addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_ALLOC_V6,"upjdLd6",rlm_id,RHP_VPN_UNIQUE_ID_SIZE,vpn_uid,tx_request_id,request_type,"AF",target_addr_family,target_protocol_addr);
	}else{
		RHP_BUG("%d",target_addr_family);
	}

	nhrp_sess = (rhp_nhrp_req_session*)_rhp_malloc(sizeof(rhp_nhrp_req_session));
	if( nhrp_sess == NULL ){
		goto error;
	}
	memset(nhrp_sess,0,sizeof(rhp_nhrp_req_session));

	nhrp_sess->tag[0] = '#';
	nhrp_sess->tag[1] = 'N';
	nhrp_sess->tag[2] = 'R';
	nhrp_sess->tag[3] = 'S';

	nhrp_sess->request_type = request_type;
	nhrp_sess->vpn_realm_id = rlm_id;

	nhrp_sess->target_protocol_ip.addr_family = target_addr_family;
	if( target_addr_family == AF_INET ){

		nhrp_sess->target_protocol_ip.addr.v4 = *((u32*)target_protocol_addr);

	}else if( target_addr_family == AF_INET6 ){

		memcpy(nhrp_sess->target_protocol_ip.addr.v6,target_protocol_addr,16);

	}else{
		RHP_BUG("%d",target_addr_family);
		goto error;
	}

	if( src_nbma_addr_family == AF_INET ){

		nhrp_sess->src_nbma_ip.addr_family = src_nbma_addr_family;
		nhrp_sess->src_nbma_ip.addr.v4 = *((u32*)src_nbma_addr);

	}else if( src_nbma_addr_family == AF_INET6 ){

		nhrp_sess->src_nbma_ip.addr_family = src_nbma_addr_family;
		memcpy(nhrp_sess->src_nbma_ip.addr.v6,src_nbma_addr,16);

	}else{

		nhrp_sess->src_nbma_ip.addr_family = AF_UNSPEC;
	}

	memcpy(nhrp_sess->vpn_uid,vpn_uid,RHP_VPN_UNIQUE_ID_SIZE);

	rhp_timer_init(&(nhrp_sess->timer),_rhp_nhrp_req_sess_timer,nhrp_sess);

	_rhp_pkt_q_init(&(nhrp_sess->pkt_q));

  _rhp_atomic_init((&nhrp_sess->refcnt));
  _rhp_atomic_set((&nhrp_sess->refcnt),1);

	nhrp_sess->created_time = _rhp_get_time();
	nhrp_sess->tx_request_id = tx_request_id;

  RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_ALLOC_RTRN,"x",nhrp_sess);
	return nhrp_sess;

error:
	if( nhrp_sess ){
		_rhp_nhrp_req_sess_unhold(nhrp_sess);
	}
  RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_ALLOC_ERR,"");
	return NULL;
}

static void _rhp_nhrp_req_sess_put(rhp_nhrp_req_session* nhrp_sess)
{
  u32 hval;

  if( nhrp_sess->target_protocol_ip.addr_family == AF_INET ){
  	RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_PUT_V4,"xupdxjLd4",nhrp_sess,nhrp_sess->vpn_realm_id,RHP_VPN_UNIQUE_ID_SIZE,nhrp_sess->vpn_uid,nhrp_sess->pkt_q_num,nhrp_sess->pkt_q.head,nhrp_sess->tx_request_id,"AF",nhrp_sess->target_protocol_ip.addr_family,nhrp_sess->target_protocol_ip.addr.v4);
  }else if( nhrp_sess->target_protocol_ip.addr_family == AF_INET6 ){
  	RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_PUT_V6,"xupdxjLd6",nhrp_sess,nhrp_sess->vpn_realm_id,RHP_VPN_UNIQUE_ID_SIZE,nhrp_sess->vpn_uid,nhrp_sess->pkt_q_num,nhrp_sess->pkt_q.head,nhrp_sess->tx_request_id,"AF",nhrp_sess->target_protocol_ip.addr_family,nhrp_sess->target_protocol_ip.addr.v6);
  }else{
  	RHP_BUG("%d",nhrp_sess->target_protocol_ip.addr_family);
  }

  hval = _rhp_nhrp_hash(nhrp_sess->target_protocol_ip.addr_family,
  		nhrp_sess->target_protocol_ip.addr.raw);

  nhrp_sess->next_hash = _rhp_nhrp_req_sess_hash_tbl[hval];
  _rhp_nhrp_req_sess_hash_tbl[hval] = nhrp_sess;

  rhp_nhrp_cache_statistics_tbl.dc.request_sessions++;

  _rhp_nhrp_req_sess_hold(nhrp_sess);

  RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_PUT_RTRN,"xuj",nhrp_sess,rhp_nhrp_cache_statistics_tbl.dc.request_sessions,hval);
  return;
}

static rhp_nhrp_req_session* _rhp_nhrp_req_sess_get(
		unsigned long rlm_id,
		int request_type, // RHP_PROTO_NHRP_PKT_XXX_REQ
		int target_addr_family,u8* target_protocol_ip)
{
  rhp_nhrp_req_session* nhrp_sess = NULL;
  u32 hval;

  if( target_addr_family == AF_INET ){
  	RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_GET_V4,"udLd4",rlm_id,request_type,"AF",target_addr_family,*((u32*)target_protocol_ip));
  }else if( target_addr_family == AF_INET6 ){
  	RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_GET_V6,"udLd6",rlm_id,request_type,"AF",target_addr_family,target_protocol_ip);
  }else{
  	RHP_BUG("%d",target_addr_family);
  	return NULL;
  }

  hval = _rhp_nhrp_hash(target_addr_family,target_protocol_ip);

  nhrp_sess = _rhp_nhrp_req_sess_hash_tbl[hval];

  while( nhrp_sess ){

  	if( !rhp_ip_addr_cmp_value(&(nhrp_sess->target_protocol_ip),
  				(target_addr_family == AF_INET ? 4 : 16),target_protocol_ip) &&
  			(!rlm_id || rlm_id == nhrp_sess->vpn_realm_id) &&
  			(!request_type || request_type == nhrp_sess->request_type) ){
      break;
  	}

    nhrp_sess = nhrp_sess->next_hash;
  }

  if( nhrp_sess ){
  	RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_GET_RTRN,"udxxupdxjj",rlm_id,request_type,target_protocol_ip,nhrp_sess,nhrp_sess->vpn_realm_id,RHP_VPN_UNIQUE_ID_SIZE,nhrp_sess->vpn_uid,nhrp_sess->pkt_q_num,nhrp_sess->pkt_q.head,nhrp_sess->tx_request_id,hval);
  }else{
  	RHP_TRC(0,RHPTRCID_NHRP_REQ_SESS_GET_NO_ENT,"udxj",rlm_id,request_type,target_protocol_ip,hval);
  }
  return nhrp_sess;
}

static int _rhp_nhrp_exec_request_session(
		unsigned long rlm_id,
		u8* vpn_uid,
		u32 tx_request_id,
		int request_type, // RHP_PROTO_NHRP_PKT_XXX_REQ
		int target_addr_family,u8* target_protocol_addr,
		int src_nbma_addr_family,u8* src_nbma_addr,
		rhp_packet* tx_pkt,
		rhp_nhrp_req_session** nhrp_sess_r)
{
	int err = -EINVAL;
	rhp_nhrp_req_session* nhrp_sess = NULL;

	if( target_addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_NHRP_EXEC_REQUEST_SESSION_V4,"upjdLd4xx",rlm_id,RHP_VPN_UNIQUE_ID_SIZE,vpn_uid,tx_request_id,request_type,"AF",target_addr_family,*((u32*)target_protocol_addr),tx_pkt,nhrp_sess_r);
	}else if( target_addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_NHRP_EXEC_REQUEST_SESSION_V6,"upjdLd6xx",rlm_id,RHP_VPN_UNIQUE_ID_SIZE,vpn_uid,tx_request_id,request_type,"AF",target_addr_family,target_protocol_addr,tx_pkt,nhrp_sess_r);
	}else{
		RHP_BUG("%d",target_addr_family);
	}

	if( src_nbma_addr_family == AF_INET && src_nbma_addr ){
		RHP_TRC(0,RHPTRCID_NHRP_EXEC_REQUEST_SESSION_SRC_NBMA_V4,"upjdLd4x",rlm_id,RHP_VPN_UNIQUE_ID_SIZE,vpn_uid,tx_request_id,request_type,"AF",src_nbma_addr_family,*((u32*)src_nbma_addr),tx_pkt);
	}else if( src_nbma_addr_family == AF_INET && src_nbma_addr ){
		RHP_TRC(0,RHPTRCID_NHRP_EXEC_REQUEST_SESSION_SRC_NBMA_V6,"upjdLd6x",rlm_id,RHP_VPN_UNIQUE_ID_SIZE,vpn_uid,tx_request_id,request_type,"AF",src_nbma_addr_family,src_nbma_addr,tx_pkt);
	}

	if( rhp_nhrp_cache_statistics_tbl.dc.request_sessions
				> (unsigned long)rhp_gcfg_nhrp_max_request_sessions ){

		RHP_TRC(0,RHPTRCID_NHRP_EXEC_REQUEST_SESSION_MAX_SESS_REQCHED,"upjud",rlm_id,RHP_VPN_UNIQUE_ID_SIZE,vpn_uid,tx_request_id,rhp_nhrp_cache_statistics_tbl.dc.request_sessions,rhp_gcfg_nhrp_max_request_sessions);

		err = RHP_STATUS_NHRP_MAX_REQ_SESS_REACHED;
		goto error;
	}

	if( target_addr_family != AF_INET &&
			target_addr_family != AF_INET6 ){

		RHP_BUG("%d",target_addr_family);

		err = -EINVAL;
		goto error;
	}

	if( request_type != RHP_PROTO_NHRP_PKT_RESOLUTION_REQ &&
			request_type != RHP_PROTO_NHRP_PKT_REGISTRATION_REQ &&
			request_type != RHP_PROTO_NHRP_PKT_PURGE_REQ ){

		RHP_BUG("%d",request_type);

		err = -EINVAL;
		goto error;
	}


	nhrp_sess = _rhp_nhrp_req_sess_alloc(rlm_id,vpn_uid,tx_request_id,
								request_type,target_addr_family,target_protocol_addr,
								src_nbma_addr_family,src_nbma_addr);
	if( nhrp_sess == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}


	_rhp_pkt_q_enq(&(nhrp_sess->pkt_q),tx_pkt);
	nhrp_sess->pkt_q_num++;
	rhp_pkt_hold(tx_pkt);


	_rhp_nhrp_req_sess_put(nhrp_sess);

	_rhp_nhrp_req_sess_hold(nhrp_sess);
	rhp_timer_add(&(nhrp_sess->timer),rhp_gcfg_nhrp_request_session_timeout);

	rhp_nhrp_cache_statistics_tbl.tx_request++;

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,rlm_id,RHP_LOG_ID_NHRP_REQ_SESS_START,"Nn",vpn_uid,nhrp_sess);

	if( nhrp_sess_r ){
		*nhrp_sess_r = nhrp_sess;
	}else{
		// _rhp_nhrp_req_sess_put() and timer alredy hold nhrp_sess.
		_rhp_nhrp_req_sess_unhold(nhrp_sess);
	}

	RHP_TRC(0,RHPTRCID_NHRP_EXEC_REQUEST_SESSION_RTRN,"upjx",rlm_id,RHP_VPN_UNIQUE_ID_SIZE,vpn_uid,tx_request_id,nhrp_sess);
	return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,rlm_id,RHP_LOG_ID_NHRP_REQ_SESS_START_ERR,"NnE",vpn_uid,nhrp_sess,err);

	if( nhrp_sess ){
		_rhp_nhrp_req_sess_unhold(nhrp_sess);
	}

	RHP_TRC(0,RHPTRCID_NHRP_EXEC_REQUEST_SESSION_ERR,"upjE",rlm_id,RHP_VPN_UNIQUE_ID_SIZE,vpn_uid,tx_request_id,err);
	return err;
}


static int _rhp_nhrp_rx_valid_addr(rhp_ip_addr* rx_addr)
{
	int err = -EINVAL;

	rhp_ip_addr_dump("_rhp_nhrp_rx_valid_addr",rx_addr);

	if( rhp_ip_addr_null(rx_addr) ){
		err = RHP_STATUS_NHRP_INVALID_ADDR;
		RHP_TRC(0,RHPTRCID_NHRP_RX_VALID_ADDR_ERR_NULL,"x",rx_addr);
		goto error;
	}

	if( rhp_ip_is_loopback(rx_addr) ){
		err = RHP_STATUS_NHRP_INVALID_ADDR;
		RHP_TRC(0,RHPTRCID_NHRP_RX_VALID_ADDR_ERR_LOOPBACK,"x",rx_addr);
		goto error;
	}

	if( rhp_ip_multicast(rx_addr->addr_family,rx_addr->addr.raw) ){
		err = RHP_STATUS_NHRP_INVALID_ADDR;
		RHP_TRC(0,RHPTRCID_NHRP_RX_VALID_ADDR_ERR_MULTICAST,"x",rx_addr);
		goto error;
	}

	return 0;

error:
	return err;
}

static int _rhp_nhrp_rx_valid_addr2_v4(rhp_ip_addr* rx_addr,u32 local_addr_v4,int prefix_len)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_NHRP_RX_VALID_ADDR2_V4_,"x4d",rx_addr,local_addr_v4,prefix_len);
	rhp_ip_addr_dump("_rhp_nhrp_rx_valid_addr2_v4",rx_addr);

	if( rx_addr->addr_family == AF_INET ){

		u32 network_addr, bc_addr;
		u32 local_addr_v4_mask = rhp_ipv4_prefixlen_to_netmask(prefix_len);

		if( local_addr_v4 == 0 ){
			err = RHP_STATUS_NHRP_INVALID_ADDR;
			RHP_TRC(0,RHPTRCID_NHRP_RX_VALID_ADDR2_V4_ERR_LOCAL_ADDR_NULL,"x",rx_addr);
			goto error;
		}

		network_addr = (local_addr_v4 & local_addr_v4_mask);
		bc_addr = (network_addr | ~local_addr_v4_mask);

		if( rx_addr->addr.v4 == network_addr ){
			err = RHP_STATUS_NHRP_INVALID_ADDR;
			RHP_TRC(0,RHPTRCID_NHRP_RX_VALID_ADDR2_V4_ERR_NETWORK_ADDR,"x",rx_addr);
			goto error;
		}

		if( rx_addr->addr.v4 == bc_addr ){
			err = RHP_STATUS_NHRP_INVALID_ADDR;
			RHP_TRC(0,RHPTRCID_NHRP_RX_VALID_ADDR2_V4_ERR_BROADCAST_ADDR,"x",rx_addr);
			goto error;
		}
	}

	return 0;

error:
	return err;
}

static int _rhp_nhrp_get_def_mtu(rhp_vpn* vpn,int* mtu_r)
{
	rhp_childsa* cur_childsa;

	RHP_TRC(0,RHPTRCID_NHRP_GET_DEF_MTU,"xxx",vpn,mtu_r,vpn->childsa_list_head);

	cur_childsa = vpn->childsa_list_head;
	while( cur_childsa ){

		// Newer one is adopted.
		if( cur_childsa->state == RHP_CHILDSA_STAT_MATURE 		||
				cur_childsa->state == RHP_CHILDSA_STAT_REKEYING 	||
				cur_childsa->state == RHP_IPSECSA_STAT_V1_MATURE 	||
				cur_childsa->state == RHP_IPSECSA_STAT_V1_REKEYING ){
			break;
		}

		cur_childsa = cur_childsa->next_vpn_list;
	}

	if( cur_childsa == NULL ){
		RHP_TRC(0,RHPTRCID_NHRP_GET_DEF_MTU_NO_ENT,"xx",vpn,vpn->childsa_list_head);
		return -ENOENT;
	}

	*mtu_r = cur_childsa->pmtu_default;

	RHP_TRC(0,RHPTRCID_NHRP_GET_DEF_MTU_RTRN,"xxxd",vpn,vpn->childsa_list_head,cur_childsa,*mtu_r);
	return 0;
}


static rhp_ifc_addr* _rhp_nhrp_get_internal_addr(rhp_ifc_entry* v_ifc,int addr_family)
{
	int i;
	rhp_ifc_addr* if_addr = v_ifc->ifc_addrs;
	rhp_ifc_addr *v6_lladdr = NULL, *v6_addr_tmp = NULL, *v6_addr_static = NULL;

	RHP_TRC(0,RHPTRCID_NHRP_GET_INTERNAL_ADDR,"xdLd",v_ifc,v_ifc->ifc_addrs_num,"AF",addr_family);
	v_ifc->dump_no_lock("_rhp_nhrp_get_internal_addr",v_ifc);

	for( i = 0; i < v_ifc->ifc_addrs_num; i++ ){

		if( if_addr->addr.addr_family == addr_family ){

			if( addr_family == AF_INET ){

				break;

			}else if( addr_family == AF_INET6 ){

				if( rhp_ipv6_is_linklocal(if_addr->addr.addr.v6) ){
					v6_lladdr = if_addr;
				}else if( RHP_IFA_F_TEMPORARY(if_addr->if_addr_flags) ){
					v6_addr_tmp = if_addr;
				}else if( RHP_IFA_F_PERMANENT(if_addr->if_addr_flags) ){
					v6_addr_static = if_addr;
				}
			}
		}

		if_addr = if_addr->lst_next;
	}

	if( if_addr ){
		RHP_TRC(0,RHPTRCID_NHRP_GET_INTERNAL_ADDR_RTRN,"xx",v_ifc,if_addr);
		rhp_ip_addr_dump("if_addr",&(if_addr->addr));
		return if_addr;
	}else{
		if( v6_addr_static ){
			RHP_TRC(0,RHPTRCID_NHRP_GET_INTERNAL_ADDR_V6_STATIC_RTRN,"xx",v_ifc,v6_addr_static);
			rhp_ip_addr_dump("v6_addr_static",&(v6_addr_static->addr));
			return v6_addr_static;
		}else if( v6_addr_tmp ){
			RHP_TRC(0,RHPTRCID_NHRP_GET_INTERNAL_ADDR_V6_TEMP_RTRN,"xx",v_ifc,v6_addr_tmp);
			rhp_ip_addr_dump("v6_addr_tmp",&(v6_addr_tmp->addr));
			return v6_addr_tmp;
		}else if( v6_lladdr ){
			RHP_TRC(0,RHPTRCID_NHRP_GET_INTERNAL_ADDR_V6_LINKLOCAL_RTRN,"xx",v_ifc,v6_lladdr);
			rhp_ip_addr_dump("v6_lladdr",&(v6_lladdr->addr));
			return v6_lladdr;
		}
	}

	RHP_TRC(0,RHPTRCID_NHRP_GET_INTERNAL_ADDR_NO_ENT,"x",v_ifc);
	return NULL;
}

static rhp_ifc_addr* _rhp_nhrp_get_internal_v6_lladdr(rhp_ifc_entry* v_ifc)
{
	int i;
	rhp_ifc_addr* if_addr = v_ifc->ifc_addrs;

	RHP_TRC(0,RHPTRCID_NHRP_GET_INTERNAL_V6_LLADDR,"x",v_ifc);
	v_ifc->dump_no_lock("_rhp_nhrp_get_internal_v6_lladdr",v_ifc);

	for( i = 0; i < v_ifc->ifc_addrs_num; i++ ){

		if( if_addr->addr.addr_family == AF_INET6 ){

			if( rhp_ipv6_is_linklocal(if_addr->addr.addr.v6) ){
				RHP_TRC(0,RHPTRCID_NHRP_GET_INTERNAL_V6_LLADDR_RTRN,"xx",v_ifc,if_addr);
				rhp_ip_addr_dump("if_addr->addr",&(if_addr->addr));
				return if_addr;
			}
		}

		if_addr = if_addr->lst_next;
	}

	RHP_TRC(0,RHPTRCID_NHRP_GET_INTERNAL_V6_LLADDR_NO_ENT,"x",v_ifc);
	return NULL;
}

static rhp_ip_addr* _rhp_nhrp_get_nhs_peer_addr(rhp_vpn* vpn,int addr_family)
{
	rhp_ip_addr_list* peer_addr = vpn->internal_net_info.peer_addrs;
	rhp_ip_addr_list *v6_lladdr = NULL, *v6_addr = NULL;

	RHP_TRC(0,RHPTRCID_NHRP_GET_NHS_PEER_ADDR,"xLdx",vpn,"AF",addr_family,vpn->internal_net_info.peer_addrs);

	while( peer_addr ){

		if( peer_addr->ip_addr.addr_family == addr_family ){

			if( addr_family == AF_INET ){

				break;

			}else if( addr_family == AF_INET6 ){

				if( rhp_ipv6_is_linklocal(peer_addr->ip_addr.addr.v6) ){
					v6_lladdr = peer_addr;
				}else{
					v6_addr = peer_addr;
				}
			}
		}

		peer_addr = peer_addr->next;
	}

	if( peer_addr ){
		RHP_TRC(0,RHPTRCID_NHRP_GET_NHS_PEER_ADDR_RTRN,"xx",vpn,peer_addr);
		rhp_ip_addr_dump("peer_addr->ip_addr",&(peer_addr->ip_addr));
		return &(peer_addr->ip_addr);
	}else{
		if( v6_addr ){
			RHP_TRC(0,RHPTRCID_NHRP_GET_NHS_PEER_ADDR_V6_ADDR_RTRN,"xx",vpn,v6_addr);
			rhp_ip_addr_dump("v6_addr->ip_addr",&(v6_addr->ip_addr));
			return &(v6_addr->ip_addr);
		}else if( v6_lladdr ){
			RHP_TRC(0,RHPTRCID_NHRP_GET_NHS_PEER_ADDR_V6_LINKLOCAL_RTRN,"xx",vpn,v6_lladdr);
			rhp_ip_addr_dump("v6_lladdr->ip_addr",&(v6_lladdr->ip_addr));
			return &(v6_lladdr->ip_addr);
		}
	}

	RHP_TRC(0,RHPTRCID_NHRP_GET_NHS_PEER_ADDR_NO_ENT,"x",vpn);
	return NULL;
}


// Currently, for RHP_PROTO_NHRP_PKT_REGISTRATION_REQ
// and RHP_PROTO_NHRP_PKT_RESOLUTION_REQ.
static int _rhp_nhrp_rx_req_verify(rhp_nhrp_mesg* rx_nhrp_mesg,rhp_vpn* rx_vpn,u8 pkt_type,
		rhp_ip_addr* src_nbma_addr,rhp_ip_addr* src_proto_addr,rhp_ip_addr* dst_proto_addr)
{
	int err = -EINVAL;
	rhp_vpn_realm* rlm = rx_vpn->rlm;
  rhp_ifc_entry* v_ifc;
	rhp_ifc_addr* if_addr;
	int i, flag;
	rhp_ip_addr local_addr_v4;

	RHP_TRC(0,RHPTRCID_NHRP_RX_REQ_VERIFY,"xxbxxxx",rx_nhrp_mesg,rx_vpn,pkt_type,src_nbma_addr,src_proto_addr,dst_proto_addr,rlm);
	rhp_ip_addr_dump("src_nbma_addr",src_nbma_addr);
	rhp_ip_addr_dump("src_proto_addr",src_proto_addr);
	rhp_ip_addr_dump("dst_proto_addr",dst_proto_addr);


	memset(&local_addr_v4,0,sizeof(rhp_ip_addr));

	if( rlm == NULL ){
		err = -EINVAL;
		RHP_TRC(0,RHPTRCID_NHRP_RX_REQ_VERIFY_NO_RLM,"xx",rx_nhrp_mesg,rx_vpn);
		goto error;
	}


	{
		err = _rhp_nhrp_rx_valid_addr(src_nbma_addr);
		if( err ){
			RHP_TRC(0,RHPTRCID_NHRP_RX_REQ_VERIFY_INVALID_SRC_NBMA_ADDR,"xxx",rx_nhrp_mesg,rx_vpn,src_nbma_addr);
			goto error;
		}

		if( rx_vpn->local.if_info.addr_family != src_nbma_addr->addr_family ){
			RHP_TRC(0,RHPTRCID_NHRP_RX_REQ_VERIFY_INVALID_SRC_NBMA_ADDR_2,"xxxdd",rx_nhrp_mesg,rx_vpn,src_nbma_addr,rx_vpn->local.if_info.addr_family,src_nbma_addr->addr_family);
			goto error;
		}

		if( src_nbma_addr->addr_family == AF_INET ){

			err = _rhp_nhrp_rx_valid_addr2_v4(src_nbma_addr,
							rx_vpn->local.if_info.addr.v4,rx_vpn->local.if_info.prefixlen);
			if( err ){
				RHP_TRC(0,RHPTRCID_NHRP_RX_REQ_VERIFY_INVALID_SRC_PROTO_ADDR_3,"xxx",rx_nhrp_mesg,rx_vpn,rlm);
				goto error;
			}
		}

		err = _rhp_nhrp_rx_valid_addr(src_proto_addr);
		if( err ){
			RHP_TRC(0,RHPTRCID_NHRP_RX_REQ_VERIFY_INVALID_SRC_PROTO_ADDR,"xxx",rx_nhrp_mesg,rx_vpn,src_proto_addr);
			goto error;
		}

		err = _rhp_nhrp_rx_valid_addr(dst_proto_addr);
		if( err ){
			RHP_TRC(0,RHPTRCID_NHRP_RX_REQ_VERIFY_INVALID_DST_PROTO_ADDR,"xxx",rx_nhrp_mesg,rx_vpn,dst_proto_addr);
			goto error;
		}


		if( !rhp_ip_addr_cmp_ip_only(src_nbma_addr,src_proto_addr) ){
			err = RHP_STATUS_NHRP_INVALID_ADDR;
			RHP_TRC(0,RHPTRCID_NHRP_RX_REQ_VERIFY_SRC_NBMA_PROTO_ADDRS_SAME,"xxxx",rx_nhrp_mesg,rx_vpn,src_nbma_addr,src_proto_addr);
			goto error;
		}

		if( !rhp_ip_addr_cmp_ip_only(src_proto_addr,dst_proto_addr) ){
			err = RHP_STATUS_NHRP_INVALID_ADDR;
			RHP_TRC(0,RHPTRCID_NHRP_RX_REQ_VERIFY_SRC_PROTO_DST_PROTO_ADDRS_SAME,"xxxx",rx_nhrp_mesg,rx_vpn,src_proto_addr,dst_proto_addr);
			goto error;
		}
	}


	RHP_LOCK(&(rlm->lock));

	v_ifc = rlm->internal_ifc->ifc;
	if( v_ifc == NULL ){
		RHP_UNLOCK(&(rlm->lock));
		RHP_TRC(0,RHPTRCID_NHRP_RX_REQ_VERIFY_NO_V_IFC,"xxx",rx_nhrp_mesg,rx_vpn,rlm);
		goto error;
	}


	RHP_LOCK(&(v_ifc->lock));

	v_ifc->dump_no_lock("_rhp_nhrp_rx_req_verify",v_ifc);

	flag = 0;
	if_addr = v_ifc->ifc_addrs;
	for( i = 0; i < v_ifc->ifc_addrs_num; i++ ){

		if( pkt_type == RHP_PROTO_NHRP_PKT_REGISTRATION_REQ ){

			if( !rhp_ip_addr_cmp_ip_only(dst_proto_addr,&(if_addr->addr)) ){
				flag = 1;
			}
		}

		if( rhp_ip_addr_null(&local_addr_v4) &&
				if_addr->addr.addr_family == AF_INET ){

			memcpy(&local_addr_v4,&(if_addr->addr),sizeof(rhp_ip_addr));
		}

		if_addr = if_addr->lst_next;
	}

	RHP_UNLOCK(&(v_ifc->lock));

	RHP_UNLOCK(&(rlm->lock));


	rhp_ip_addr_dump("local_addr_v4",&local_addr_v4);


	if( pkt_type == RHP_PROTO_NHRP_PKT_REGISTRATION_REQ && !flag ){
		err = RHP_STATUS_NHRP_INVALID_ADDR;
		RHP_TRC(0,RHPTRCID_NHRP_RX_REQ_VERIFY_NO_VALID_DST_PROTO_ADDR_FOUND,"xxx",rx_nhrp_mesg,rx_vpn,rlm);
		goto error;
	}


	if( src_proto_addr->addr_family == AF_INET ){

		err = _rhp_nhrp_rx_valid_addr2_v4(src_proto_addr,local_addr_v4.addr.v4,local_addr_v4.prefixlen);
		if( err ){
			RHP_TRC(0,RHPTRCID_NHRP_RX_REQ_VERIFY_INVALID_SRC_PROTO_ADDR_2,"xxx",rx_nhrp_mesg,rx_vpn,rlm);
			goto error;
		}
	}

	if( pkt_type == RHP_PROTO_NHRP_PKT_RESOLUTION_REQ ){

		if( dst_proto_addr->addr_family == AF_INET ){

			err = _rhp_nhrp_rx_valid_addr2_v4(dst_proto_addr,local_addr_v4.addr.v4,local_addr_v4.prefixlen);
			if( err ){
				RHP_TRC(0,RHPTRCID_NHRP_RX_REQ_VERIFY_INVALID_DST_PROTO_ADDR_2,"xxx",rx_nhrp_mesg,rx_vpn,rlm);
				goto error;
			}
		}
	}

	RHP_TRC(0,RHPTRCID_NHRP_RX_REQ_VERIFY_RTRN,"xxx",rx_nhrp_mesg,rx_vpn,rlm);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_RX_REQ_VERIFY_ERR,"xxxE",rx_nhrp_mesg,rx_vpn,rlm,err);
	return err;
}

static int _rhp_nhrp_check_mesg_loop(rhp_nhrp_ext* fwd_trans_nhs_ext,rhp_ifc_entry* v_ifc)
{
	int err = -EINVAL;
	rhp_nhrp_cie* nhrp_cie;
	rhp_ifc_addr* if_addr;
	int i, loop_detected = 0;

	RHP_TRC(0,RHPTRCID_NHRP_CHECK_MESG_LOOP,"xx",fwd_trans_nhs_ext,v_ifc);

	if_addr = v_ifc->ifc_addrs;
	for( i = 0; i < v_ifc->ifc_addrs_num; i++ ){

		nhrp_cie = fwd_trans_nhs_ext->cie_list_head;
		while( nhrp_cie ){

			rhp_ip_addr fwd_nhs_proto_addr;

			memset(&fwd_nhs_proto_addr,0,sizeof(rhp_ip_addr));

			err = nhrp_cie->get_clt_protocol_addr(nhrp_cie,&fwd_nhs_proto_addr);
			if( err ){
				goto error;
			}

			if( !loop_detected &&
					!rhp_ip_addr_cmp_ip_only(&fwd_nhs_proto_addr,&(if_addr->addr)) ){

				RHP_TRC(0,RHPTRCID_NHRP_CHECK_MESG_LOOP_ADDRS,"xxxx",fwd_trans_nhs_ext,v_ifc,fwd_nhs_proto_addr,if_addr);

				loop_detected = 1;
				break;
			}

			nhrp_cie = nhrp_cie->next;
		}

		if( fwd_trans_nhs_ext->cie_list_head == NULL || loop_detected ){
			break;
		}
	}

	if( !loop_detected ){

		RHP_TRC(0,RHPTRCID_NHRP_CHECK_MESG_LOOP_RTRN,"xx",fwd_trans_nhs_ext,v_ifc);
		return 0;
	}

	err = RHP_STATUS_NHRP_NO_FWD_LOOP_DETECTED;

error:
	RHP_TRC(0,RHPTRCID_NHRP_CHECK_MESG_LOOP_ERR,"xxE",fwd_trans_nhs_ext,v_ifc,err);
	return err;
}

static int _rhp_nhrp_tx_rep_set_responder_ext(rhp_nhrp_mesg* tx_nhrp_mesg,
		rhp_vpn* tx_vpn,rhp_ip_addr* clt_proto_addr,int mtu)
{
	int err = -EINVAL;
	rhp_nhrp_cie* nhrp_ext_resp_addr_cie = NULL;
	rhp_nhrp_ext* nhrp_ext_resp_addr
		= tx_nhrp_mesg->get_extension(tx_nhrp_mesg,RHP_PROTO_NHRP_EXT_TYPE_RESPONDER_ADDRESS);

	RHP_TRC(0,RHPTRCID_NHRP_TX_REP_SET_RESPONDER_EXT,"xxxd",tx_nhrp_mesg,tx_vpn,clt_proto_addr,mtu);
	rhp_ip_addr_dump("clt_proto_addr",clt_proto_addr);

	if( !mtu ){

		err = _rhp_nhrp_get_def_mtu(tx_vpn,&mtu);
		if( err ){
			goto error;
		}
	}

	if( nhrp_ext_resp_addr == NULL ){

		nhrp_ext_resp_addr = rhp_nhrp_ext_alloc(RHP_PROTO_NHRP_EXT_TYPE_RESPONDER_ADDRESS,1);
		if( nhrp_ext_resp_addr == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = tx_nhrp_mesg->add_extension(tx_nhrp_mesg,nhrp_ext_resp_addr);
		if( err ){
			rhp_nhrp_ext_free(nhrp_ext_resp_addr);
			goto error;
		}
	}

	nhrp_ext_resp_addr_cie = nhrp_ext_resp_addr->cie_list_head;
	if( nhrp_ext_resp_addr_cie == NULL ){

		nhrp_ext_resp_addr_cie = rhp_nhrp_cie_alloc(RHP_PROTO_NHRP_CIE_CODE_SUCCESS);
		if( nhrp_ext_resp_addr_cie == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}

		err = nhrp_ext_resp_addr->add_cie(nhrp_ext_resp_addr,nhrp_ext_resp_addr_cie);
		if( err ){
			rhp_nhrp_cie_free(nhrp_ext_resp_addr_cie);
			goto error;
		}

	}else{

		nhrp_ext_resp_addr_cie->code = (u8)RHP_PROTO_NHRP_CIE_CODE_SUCCESS;
	}


	nhrp_ext_resp_addr_cie->set_mtu(nhrp_ext_resp_addr_cie,(rhp_gcfg_nhrp_cie_mtu ? (u16)rhp_gcfg_nhrp_cie_mtu : mtu));

	nhrp_ext_resp_addr_cie->set_hold_time(nhrp_ext_resp_addr_cie,
			(u16)rhp_gcfg_nhrp_cache_hold_time);


	err = nhrp_ext_resp_addr_cie->set_clt_nbma_addr(nhrp_ext_resp_addr_cie,
					tx_vpn->local.if_info.addr_family,tx_vpn->local.if_info.addr.raw);
	if( err ){
		goto error;
	}

	err = nhrp_ext_resp_addr_cie->set_clt_protocol_addr(nhrp_ext_resp_addr_cie,
					clt_proto_addr->addr_family,clt_proto_addr->addr.raw);
	if( err ){
		goto error;
	}

	RHP_TRC(0,RHPTRCID_NHRP_TX_REP_SET_RESPONDER_EXT_RTRN,"xx",tx_nhrp_mesg,tx_vpn);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_TX_REP_SET_RESPONDER_EXT_ERR,"xxE",tx_nhrp_mesg,tx_vpn,err);
	return err;
}

static int _rhp_nhrp_nhs_tx_rep_set_nat_ext(rhp_nhrp_mesg* tx_nhrp_mesg,
		rhp_ip_addr* rx_nbma_addr,rhp_ip_addr* proto_addr,int tx_mtu)
{
	int err = -EINVAL;
	rhp_nhrp_cie* nhrp_ext_cisco_nat_cie = NULL;
	rhp_nhrp_ext* nhrp_ext_cisco_nat
		= tx_nhrp_mesg->get_extension(tx_nhrp_mesg,RHP_PROTO_NHRP_EXT_TYPE_NAT_ADDRESS);

	RHP_TRC(0,RHPTRCID_NHRP_TX_REP_SET_NAT_EXT,"xxxxd",tx_nhrp_mesg,rx_nbma_addr,proto_addr,tx_mtu);
	rhp_ip_addr_dump("rx_nbma_addr",rx_nbma_addr);
	rhp_ip_addr_dump("proto_addr",proto_addr);

	if( nhrp_ext_cisco_nat == NULL ){

		nhrp_ext_cisco_nat = rhp_nhrp_ext_alloc(RHP_PROTO_NHRP_EXT_TYPE_NAT_ADDRESS,0);
		if( nhrp_ext_cisco_nat == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		err = tx_nhrp_mesg->add_extension(tx_nhrp_mesg,nhrp_ext_cisco_nat);
		if( err ){
			rhp_nhrp_ext_free(nhrp_ext_cisco_nat);
			goto error;
		}
	}

	nhrp_ext_cisco_nat_cie = nhrp_ext_cisco_nat->cie_list_head;
	if( nhrp_ext_cisco_nat_cie == NULL ){

		nhrp_ext_cisco_nat_cie = rhp_nhrp_cie_alloc(RHP_PROTO_NHRP_CIE_CODE_SUCCESS);
		if( nhrp_ext_cisco_nat_cie == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}

		err = nhrp_ext_cisco_nat->add_cie(nhrp_ext_cisco_nat,nhrp_ext_cisco_nat_cie);
		if( err ){
			goto error;
		}
	}

	nhrp_ext_cisco_nat_cie->set_hold_time(nhrp_ext_cisco_nat_cie,0);

	nhrp_ext_cisco_nat_cie->set_mtu(nhrp_ext_cisco_nat_cie,
			(rhp_gcfg_nhrp_cie_mtu ? (u16)rhp_gcfg_nhrp_cie_mtu : (u16)tx_mtu));

	nhrp_ext_cisco_nat_cie->set_prefix_len(nhrp_ext_cisco_nat_cie,32);


	err = nhrp_ext_cisco_nat_cie->set_clt_nbma_addr(nhrp_ext_cisco_nat_cie,
					rx_nbma_addr->addr_family,rx_nbma_addr->addr.raw);
	if( err ){
		goto error;
	}

	err = nhrp_ext_cisco_nat_cie->set_clt_protocol_addr(nhrp_ext_cisco_nat_cie,
					proto_addr->addr_family,proto_addr->addr.raw);
	if( err ){
		goto error;
	}

	RHP_TRC(0,RHPTRCID_NHRP_TX_REP_SET_NAT_EXT_RTRN,"x",tx_nhrp_mesg);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_TX_REP_SET_NAT_EXT_ERR,"xE",tx_nhrp_mesg,err);
	return err;
}

static int _rhp_nhrp_tx_rep_set_nat_ext(rhp_nhrp_mesg* tx_nhrp_mesg,
		rhp_ip_addr* nbma_addr,rhp_ip_addr* proto_addr,int tx_mtu)
{
	int err = -EINVAL;
	rhp_nhrp_cie* nhrp_ext_cisco_nat_cie = NULL;
	rhp_nhrp_ext* nhrp_ext_cisco_nat
		= tx_nhrp_mesg->get_extension(tx_nhrp_mesg,RHP_PROTO_NHRP_EXT_TYPE_NAT_ADDRESS);

	RHP_TRC(0,RHPTRCID_NHRP_TX_REP_SET_NAT_EXT,"xxxd",tx_nhrp_mesg,nbma_addr,proto_addr,tx_mtu);
	rhp_ip_addr_dump("nbma_addr",nbma_addr);
	rhp_ip_addr_dump("proto_addr",proto_addr);

	if( nhrp_ext_cisco_nat == NULL ){

		nhrp_ext_cisco_nat = rhp_nhrp_ext_alloc(RHP_PROTO_NHRP_EXT_TYPE_NAT_ADDRESS,0);
		if( nhrp_ext_cisco_nat == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		err = tx_nhrp_mesg->add_extension(tx_nhrp_mesg,nhrp_ext_cisco_nat);
		if( err ){
			rhp_nhrp_ext_free(nhrp_ext_cisco_nat);
			goto error;
		}
	}

	{
		nhrp_ext_cisco_nat_cie = nhrp_ext_cisco_nat->cie_list_head;
		while( nhrp_ext_cisco_nat_cie ){
			rhp_nhrp_cie* nhrp_cie_tmp_n = nhrp_ext_cisco_nat_cie->next;
			rhp_nhrp_cie_free(nhrp_ext_cisco_nat_cie);
			nhrp_ext_cisco_nat_cie = nhrp_cie_tmp_n;
		}
		nhrp_ext_cisco_nat->cie_list_head = NULL;
		nhrp_ext_cisco_nat->cie_list_tail = NULL;
	}

	if( nbma_addr->addr_family == AF_INET || nbma_addr->addr_family == AF_INET6 ){

		nhrp_ext_cisco_nat_cie = rhp_nhrp_cie_alloc(RHP_PROTO_NHRP_CIE_CODE_SUCCESS);
		if( nhrp_ext_cisco_nat_cie == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}

		err = nhrp_ext_cisco_nat->add_cie(nhrp_ext_cisco_nat,nhrp_ext_cisco_nat_cie);
		if( err ){
			rhp_nhrp_cie_free(nhrp_ext_cisco_nat_cie);
			goto error;
		}

		nhrp_ext_cisco_nat_cie->set_hold_time(nhrp_ext_cisco_nat_cie,0);

		nhrp_ext_cisco_nat_cie->set_mtu(nhrp_ext_cisco_nat_cie,
				(rhp_gcfg_nhrp_cie_mtu ? (u16)rhp_gcfg_nhrp_cie_mtu : (u16)tx_mtu));

		nhrp_ext_cisco_nat_cie->set_prefix_len(nhrp_ext_cisco_nat_cie,32);


		err = nhrp_ext_cisco_nat_cie->set_clt_nbma_addr(nhrp_ext_cisco_nat_cie,
						nbma_addr->addr_family,nbma_addr->addr.raw);
		if( err ){
			goto error;
		}

		err = nhrp_ext_cisco_nat_cie->set_clt_protocol_addr(nhrp_ext_cisco_nat_cie,
						proto_addr->addr_family,proto_addr->addr.raw);
		if( err ){
			goto error;
		}
	}

	RHP_TRC(0,RHPTRCID_NHRP_TX_REP_SET_NAT_EXT_RTRN,"x",tx_nhrp_mesg);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_TX_REP_SET_NAT_EXT_ERR,"xE",tx_nhrp_mesg,err);
	return err;
}

#ifdef RHP_DBG_NHRP_TX_REG_REQ_WD
static rhp_timer _rhp_nhrp_tx_registration_req_wd;
static time_t _rhp_nhrp_tx_registration_req_wd_last = 0;
static time_t _rhp_nhrp_tx_registration_req_wd_max = 90;
static time_t _rhp_nhrp_tx_registration_req_wd_interval = 10;

static void _rhp_nhrp_tx_registration_req_wd_timer(void *ctx,rhp_timer *timer)
{
	time_t now = _rhp_get_time();

	if( _rhp_nhrp_tx_registration_req_wd_last &&
			now - _rhp_nhrp_tx_registration_req_wd_last > _rhp_nhrp_tx_registration_req_wd_max ){

		_rhp_panic();
	}

  rhp_timer_reset(&(_rhp_nhrp_tx_registration_req_wd));
  rhp_timer_add(&(_rhp_nhrp_tx_registration_req_wd),_rhp_nhrp_tx_registration_req_wd_interval);

  return;
}
#endif // RHP_DBG_NHRP_TX_REG_REQ_WD


static rhp_nhrp_mesg* _rhp_nhrp_tx_registration_req_alloc(rhp_vpn* tx_vpn,u16 f_addr_family,
		rhp_ifc_addr* if_addr,rhp_ip_addr* nhs_addr_v4_p,rhp_ip_addr* nhs_addr_v6_p,int mtu)
{
	int err = -EINVAL;
	rhp_nhrp_mesg* tx_nhrp_mesg = NULL;
	rhp_nhrp_cie* nhrp_cie;
	rhp_nhrp_ext* nhrp_ext;

	RHP_TRC(0,RHPTRCID_NHRP_TX_REGISTRATION_REQ_ALLOC,"xWxxxd",tx_vpn,f_addr_family,if_addr,nhs_addr_v4_p,nhs_addr_v6_p,mtu);
	rhp_ip_addr_dump("nhs_addr_v4_p",nhs_addr_v4_p);
	rhp_ip_addr_dump("nhs_addr_v6_p",nhs_addr_v6_p);


	tx_nhrp_mesg = rhp_nhrp_mesg_new_tx(f_addr_family,RHP_PROTO_NHRP_PKT_REGISTRATION_REQ);
	if( tx_nhrp_mesg == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	err = tx_nhrp_mesg->m.mandatory->set_flags(tx_nhrp_mesg,
					(RHP_PROTO_NHRP_REG_FLAG_U | RHP_PROTO_NHRP_FLAG_CISCO_NAT_EXT));
	if( err ){
		goto error;
	}

	err = tx_nhrp_mesg->m.mandatory->set_src_nbma_addr(tx_nhrp_mesg,
					tx_vpn->local.if_info.addr_family,tx_vpn->local.if_info.addr.raw);
	if( err ){
		goto error;
	}

	err = tx_nhrp_mesg->m.mandatory->set_src_protocol_addr(tx_nhrp_mesg,
					if_addr->addr.addr_family,if_addr->addr.addr.raw);
	if( err ){
		goto error;
	}

	if( if_addr->addr.addr_family == AF_INET ){

		err = tx_nhrp_mesg->m.mandatory->set_dst_protocol_addr(tx_nhrp_mesg,
						nhs_addr_v4_p->addr_family,nhs_addr_v4_p->addr.raw);
		if( err ){
			goto error;
		}

	}else if( if_addr->addr.addr_family == AF_INET6 ){

		err = tx_nhrp_mesg->m.mandatory->set_dst_protocol_addr(tx_nhrp_mesg,
						nhs_addr_v6_p->addr_family,nhs_addr_v6_p->addr.raw);
		if( err ){
			goto error;
		}
	}


	{
		nhrp_cie = rhp_nhrp_cie_alloc(RHP_PROTO_NHRP_CIE_CODE_NONE);
		if( nhrp_cie == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = tx_nhrp_mesg->m.mandatory->add_cie(tx_nhrp_mesg,nhrp_cie);
		if( err ){
			rhp_nhrp_cie_free(nhrp_cie);
			goto error;
		}

		err = nhrp_cie->set_mtu(nhrp_cie,
				(rhp_gcfg_nhrp_cie_mtu ? (u16)rhp_gcfg_nhrp_cie_mtu : (u16)mtu));
		if( err ){
			goto error;
		}

		err = nhrp_cie->set_hold_time(nhrp_cie,(u16)rhp_gcfg_nhrp_cache_hold_time);
		if( err ){
			goto error;
		}

		// [RFC2332] 5.2.3 NHRP Registration Request
		//  Prefix Length
		//    If the "U" bit is set in the common header then this
		//    field MUST be set to 0xFF.
		//
		//  However, Cisco device sets it as 32 (IPv4).
		//
		if( if_addr->addr.addr_family == AF_INET ){
			err = nhrp_cie->set_prefix_len(nhrp_cie,rhp_gcfg_nhrp_registration_req_cie_prefix_len);
		}else{ // IPv6
			err = nhrp_cie->set_prefix_len(nhrp_cie,rhp_gcfg_nhrp_registration_req_cie_prefix_len_v6);
		}
		if( err ){
			goto error;
		}
	}


	{
		nhrp_ext = rhp_nhrp_ext_alloc(RHP_PROTO_NHRP_EXT_TYPE_RESPONDER_ADDRESS,1);
		if( nhrp_ext == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = tx_nhrp_mesg->add_extension(tx_nhrp_mesg,nhrp_ext);
		if( err ){
			rhp_nhrp_ext_free(nhrp_ext);
			goto error;
		}
	}

	{
		nhrp_ext = rhp_nhrp_ext_alloc(RHP_PROTO_NHRP_EXT_TYPE_FORWARD_TRANSIT_NHS_RECORD,1);
		if( nhrp_ext == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = tx_nhrp_mesg->add_extension(tx_nhrp_mesg,nhrp_ext);
		if( err ){
			rhp_nhrp_ext_free(nhrp_ext);
			goto error;
		}
	}

	{
		nhrp_ext = rhp_nhrp_ext_alloc(RHP_PROTO_NHRP_EXT_TYPE_REVERSE_TRANSIT_NHS_RECORD,1);
		if( nhrp_ext == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = tx_nhrp_mesg->add_extension(tx_nhrp_mesg,nhrp_ext);
		if( err ){
			rhp_nhrp_ext_free(nhrp_ext);
			goto error;
		}
	}

	{
		//
		// Cisco's NAT extension:
		//

		if( if_addr->addr.addr_family == AF_INET ){

			err = _rhp_nhrp_tx_rep_set_nat_ext(tx_nhrp_mesg,
							&(tx_vpn->peer_addr),nhs_addr_v4_p,mtu);
			if( err ){
				goto error;
			}

		}else if( if_addr->addr.addr_family == AF_INET6 ){

			err = _rhp_nhrp_tx_rep_set_nat_ext(tx_nhrp_mesg,
							&(tx_vpn->peer_addr),nhs_addr_v6_p,mtu);
			if( err ){
				goto error;
			}
		}
	}

	RHP_TRC(0,RHPTRCID_NHRP_TX_REGISTRATION_REQ_ALLOC_RTRN,"xx",tx_vpn,tx_nhrp_mesg);
	return tx_nhrp_mesg;

error:
	if( tx_nhrp_mesg ){
		rhp_nhrp_mesg_unhold(tx_nhrp_mesg);
	}
	RHP_TRC(0,RHPTRCID_NHRP_TX_REGISTRATION_REQ_ALLOC_ERR,"x",tx_vpn);
	return NULL;
}

//
// Caller must NOT acquire tx_vpn->lock.
//
int rhp_nhrp_tx_registration_req(rhp_vpn* tx_vpn)
{
	int err = -EINVAL;
	rhp_vpn_realm* tx_rlm = NULL;
	rhp_nhrp_mesg *tx_nhrp_mesgs_head = NULL, *tx_nhrp_mesgs_tail = NULL;
  rhp_ifc_entry* v_ifc = NULL;
	rhp_ifc_addr* if_addr;
	rhp_ip_addr *nhs_addr_v4_p = NULL, *nhs_addr_v6_p = NULL;
	u16 f_addr_family;
	int mtu;
  int i, n = 0;
  u8 vpn_uid[RHP_VPN_UNIQUE_ID_SIZE];

	RHP_TRC(0,RHPTRCID_NHRP_TX_REGISTRATION_REQ,"xxx",tx_vpn,tx_rlm,v_ifc);


	RHP_LOCK(&(tx_vpn->lock));

	if( !_rhp_atomic_read(&(tx_vpn->is_active)) ){
		err = -EINVAL;
  	RHP_TRC(0,RHPTRCID_NHRP_TX_REGISTRATION_REQ_VPN_NOT_ACTIVE,"x",tx_vpn);
  	goto error;
	}

	memcpy(vpn_uid,tx_vpn->unique_id,RHP_VPN_UNIQUE_ID_SIZE);


	tx_rlm = tx_vpn->rlm;
	if( tx_rlm == NULL ){
		err = -EINVAL;
  	RHP_TRC(0,RHPTRCID_NHRP_TX_REGISTRATION_REQ_VPN_NO_RLM_FOUND,"x",tx_vpn);
  	goto error;
	}

	RHP_LOCK(&(tx_rlm->lock));

	if( !_rhp_atomic_read(&(tx_rlm->is_active)) ){
		err = -EINVAL;
  	RHP_TRC(0,RHPTRCID_NHRP_TX_REGISTRATION_REQ_RLM_NOT_ACTIVE,"xx",tx_vpn,tx_rlm);
  	goto error;
	}


	v_ifc = tx_rlm->internal_ifc->ifc;
  if( v_ifc == NULL ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_NHRP_TX_REGISTRATION_REQ_NO_V_IFC,"xx",tx_vpn,tx_rlm);
  	goto error;
  }

	RHP_LOCK(&(v_ifc->lock));
	v_ifc->dump_no_lock("rhp_nhrp_tx_registration_req",v_ifc);


	if( tx_vpn->local.if_info.addr_family == AF_INET ){

		f_addr_family = RHP_PROTO_NHRP_ADDR_FAMILY_IPV4;

	}else if( tx_vpn->local.if_info.addr_family == AF_INET6 ){

		f_addr_family = RHP_PROTO_NHRP_ADDR_FAMILY_IPV6;

	}else{

		err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_NHRP_TX_REGISTRATION_REQ_NO_ITNL_ADDR,"xx",tx_vpn,tx_rlm);
		goto error;
	}


	{
		nhs_addr_v4_p = _rhp_nhrp_get_nhs_peer_addr(tx_vpn,AF_INET);
		rhp_ip_addr_dump("nhs_addr_v4_p",nhs_addr_v4_p);

		nhs_addr_v6_p = _rhp_nhrp_get_nhs_peer_addr(tx_vpn,AF_INET6);
		rhp_ip_addr_dump("nhs_addr_v6_p",nhs_addr_v6_p);

		if( rhp_ip_addr_null(nhs_addr_v4_p) && rhp_ip_addr_null(nhs_addr_v6_p) ){
			err = -ENOENT;
			RHP_TRC(0,RHPTRCID_NHRP_TX_REGISTRATION_REQ_NO_NHS_ADDR_FOUND,"xx",tx_vpn,tx_rlm);
			goto error;
		}
	}


	err = _rhp_nhrp_get_def_mtu(tx_vpn,&mtu);
	if( err ){
		RHP_TRC(0,RHPTRCID_NHRP_TX_REGISTRATION_REQ_NO_DEF_MTU_FOUND,"xx",tx_vpn,tx_rlm);
		goto error;
	}


	if_addr = v_ifc->ifc_addrs;
	for( i = 0; i < v_ifc->ifc_addrs_num; i++ ){

		rhp_nhrp_mesg* tx_nhrp_mesg;
		rhp_packet* tx_pkt;

		if( (if_addr->addr.addr_family != AF_INET &&
				 if_addr->addr.addr_family != AF_INET6) ){
			goto next;
		}

		if( (if_addr->addr.addr_family == AF_INET && nhs_addr_v4_p == NULL) ||
				(if_addr->addr.addr_family == AF_INET6 && nhs_addr_v6_p == NULL) ){
			goto next;
		}


		tx_nhrp_mesg = _rhp_nhrp_tx_registration_req_alloc(tx_vpn,
										f_addr_family,if_addr,nhs_addr_v4_p,nhs_addr_v6_p,mtu);
		if( tx_nhrp_mesg == NULL ){
			err = -ENOMEM;
			RHP_BUG("%d",err);
			goto error;
		}

		if( tx_nhrp_mesgs_head == NULL ){
			tx_nhrp_mesgs_head = tx_nhrp_mesg;
		}else{
			tx_nhrp_mesgs_tail->next = tx_nhrp_mesg;
		}
		tx_nhrp_mesgs_tail = tx_nhrp_mesg;



		err = tx_nhrp_mesg->serialize(tx_nhrp_mesg,tx_vpn,0,&tx_pkt);
		if( err ){

			RHP_BUG("%d",err);
			goto error;

		}else{

			tx_nhrp_mesg->tx_pkt_ref = rhp_pkt_hold_ref(tx_pkt);

			rhp_pkt_unhold(tx_pkt);

			n++;
		}


		{
			rhp_nhrp_addr_map* nhc_addr_map = tx_vpn->nhrp.nhc_addr_maps_head;
			rhp_ip_addr src_proto_addr, src_nbma_addr;

			tx_nhrp_mesg->m.mandatory->get_src_protocol_addr(tx_nhrp_mesg,&src_proto_addr);
			tx_nhrp_mesg->m.mandatory->get_src_nbma_addr(tx_nhrp_mesg,&src_nbma_addr);

			while( nhc_addr_map ){

				if( nhc_addr_map->proto_addr_family == src_proto_addr.addr_family &&
						((nhc_addr_map->proto_addr_family == AF_INET &&
							nhc_addr_map->proto_addr.v4 == src_proto_addr.addr.v4) ||
						 (nhc_addr_map->proto_addr_family == AF_INET6 &&
							!memcmp(nhc_addr_map->proto_addr.v6,src_proto_addr.addr.v6,16))) ){
					break;
				}

				nhc_addr_map = nhc_addr_map->next;
			}


			if( nhc_addr_map == NULL ){

				nhc_addr_map = (rhp_nhrp_addr_map*)_rhp_malloc(sizeof(rhp_nhrp_addr_map));

				if( nhc_addr_map ){

					memset(nhc_addr_map,0,sizeof(rhp_nhrp_addr_map));

					nhc_addr_map->nbma_addr_family = src_nbma_addr.addr_family;
					memcpy(nhc_addr_map->nbma_addr.raw,src_nbma_addr.addr.raw,16);

					nhc_addr_map->proto_addr_family = src_proto_addr.addr_family;
					memcpy(nhc_addr_map->proto_addr.raw,src_proto_addr.addr.raw,16);

					nhc_addr_map->next = tx_vpn->nhrp.nhc_addr_maps_head;
					tx_vpn->nhrp.nhc_addr_maps_head = nhc_addr_map;

					rhp_nhrp_addr_map_dump("tx_registration_req:NEW",nhc_addr_map);

				}else{

					RHP_BUG("");
				}

			}else{

				nhc_addr_map->nbma_addr_family = src_nbma_addr.addr_family;
				memcpy(nhc_addr_map->nbma_addr.raw,src_nbma_addr.addr.raw,16);

				rhp_nhrp_addr_map_dump("tx_registration_req:UPDATED",nhc_addr_map);
			}
		}

next:
		if_addr = if_addr->lst_next;
	}

	if( n < 1 ){
		err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_NHRP_TX_REGISTRATION_REQ_NO_TX_MESG,"xx",tx_vpn,tx_rlm);
		goto error;
	}

	RHP_UNLOCK(&(v_ifc->lock));
	RHP_UNLOCK(&(tx_rlm->lock));

	rhp_realm_hold(tx_rlm); // (*zz*)

	RHP_UNLOCK(&(tx_vpn->lock));



	//
	// All errors are ignored from here.
	//

	RHP_LOCK(&rhp_nhrp_lock);
	{
		rhp_nhrp_mesg* tx_nhrp_mesg = tx_nhrp_mesgs_head;

		while( tx_nhrp_mesg ){

			u32 tx_request_id;
			rhp_packet* tx_pkt = RHP_PKT_REF(tx_nhrp_mesg->tx_pkt_ref);
			rhp_ip_addr src_proto_addr, src_nbma_addr;

			tx_nhrp_mesg->m.mandatory->get_src_protocol_addr(tx_nhrp_mesg,&src_proto_addr);
			tx_nhrp_mesg->m.mandatory->get_src_nbma_addr(tx_nhrp_mesg,&src_nbma_addr);

			tx_request_id = tx_nhrp_mesg->m.mandatory->get_request_id(tx_nhrp_mesg);

			err = _rhp_nhrp_exec_request_session(
							tx_rlm->id,
							vpn_uid,
							tx_request_id,
							RHP_PROTO_NHRP_PKT_REGISTRATION_REQ,
							src_proto_addr.addr_family,src_proto_addr.addr.raw,
							src_nbma_addr.addr_family,src_nbma_addr.addr.raw,
							tx_pkt,NULL);
			if( err ){
				RHP_BUG("%d",err); // Error ignored.
			}

			tx_nhrp_mesg = tx_nhrp_mesg->next;
		}
	}
	RHP_UNLOCK(&rhp_nhrp_lock);


	{
		rhp_nhrp_mesg* tx_nhrp_mesg = tx_nhrp_mesgs_head;

		while( tx_nhrp_mesg ){

			rhp_nhrp_mesg* tx_nhrp_mesg_n = tx_nhrp_mesg->next;
			rhp_packet* tx_pkt = RHP_PKT_REF(tx_nhrp_mesg->tx_pkt_ref);
			rhp_packet* tx_pkt_d = rhp_pkt_dup(tx_pkt);

			if( tx_pkt_d ){

				// tx_vpn->lock and tx_rlm->lock will be acquired in rhp_gre_send_access_point().
				err = rhp_gre_send_access_point(tx_rlm,tx_pkt_d);
				if( err == RHP_STATUS_NO_GRE_ENCAP ){
					RHP_LOG_DE(RHP_LOG_SRC_IKEV2,tx_rlm->id,RHP_LOG_ID_NHRP_TX_REGISTRATION_REQ_MESG_NOT_GRE_ENCAP,"VBE",tx_vpn,tx_nhrp_mesg,err);
				}else if( err == RHP_STATUS_TX_ACCESS_POINT_NO_VPN ){
					RHP_LOG_DE(RHP_LOG_SRC_IKEV2,tx_rlm->id,RHP_LOG_ID_NHRP_TX_REGISTRATION_REQ_MESG_NO_HUB_OR_NHS_CONFIGURED,"VBE",tx_vpn,tx_nhrp_mesg,err);
				}else if( !err ){
					RHP_LOG_D(RHP_LOG_SRC_IKEV2,tx_rlm->id,RHP_LOG_ID_NHRP_TX_REGISTRATION_REQ_MESG,"VBE",tx_vpn,tx_nhrp_mesg,err);
				}

				rhp_pkt_unhold(tx_pkt_d);

			}else{

				// Retry later in timer handler.
				RHP_BUG("");
			}


			rhp_nhrp_mesg_unhold(tx_nhrp_mesg);
			tx_nhrp_mesg = tx_nhrp_mesg_n;
		}

		tx_nhrp_mesgs_head = NULL;
	}

	rhp_realm_unhold(tx_rlm); // (*zz*)

#ifdef RHP_DBG_NHRP_TX_REG_REQ_WD
	_rhp_nhrp_tx_registration_req_wd_last = _rhp_get_time();
#endif // RHP_DBG_NHRP_TX_REG_REQ_WD

	RHP_TRC(0,RHPTRCID_NHRP_TX_REGISTRATION_REQ_RTRN,"xxxd",tx_vpn,tx_rlm,v_ifc,n);
	return 0;


error:

	if( v_ifc ){
		RHP_UNLOCK(&(v_ifc->lock));
	}
	if( tx_rlm ){
		RHP_UNLOCK(&(tx_rlm->lock));
	}
	RHP_UNLOCK(&(tx_vpn->lock));

	if( tx_nhrp_mesgs_head ){

		rhp_nhrp_mesg* tx_nhrp_mesg = tx_nhrp_mesgs_head;
		while( tx_nhrp_mesg ){
			rhp_nhrp_mesg* tx_nhrp_mesg_n = tx_nhrp_mesg->next;
			rhp_nhrp_mesg_unhold(tx_nhrp_mesg);
			tx_nhrp_mesg = tx_nhrp_mesg_n;
		}
	}

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(tx_vpn ? tx_vpn->vpn_realm_id : 0),RHP_LOG_ID_NHRP_TX_REGISTRATION_REQ_ERR,"VE",tx_vpn,err);

	RHP_TRC(0,RHPTRCID_NHRP_TX_REGISTRATION_REQ_ERR,"xxxE",tx_vpn,tx_rlm,v_ifc,err);
	return err;
}

static int _rhp_nhrp_tx_registration_rep(rhp_nhrp_mesg* rx_nhrp_mesg,
		rhp_vpn* rx_vpn,int tx_mtu,int cie_err_code /*RHP_PROTO_NHRP_CIE_CODE_XXX*/,
		rhp_packet** tx_pkt_r)
{
	int err = -EINVAL;
	rhp_nhrp_mesg* tx_nhrp_mesg = NULL;
	rhp_ip_addr nhs_nbma_addr, nhs_proto_addr;
	rhp_ip_addr rx_nhc_nbma_addr, nhc_nbma_addr, nhc_proto_addr;
	u16 rx_m_flags = rx_nhrp_mesg->m.mandatory->get_flags(rx_nhrp_mesg);
	int max_mesg_len = 0;

	RHP_TRC(0,RHPTRCID_NHRP_TX_REGISTRATION_REP,"xxxddw",rx_nhrp_mesg,rx_vpn,tx_pkt_r,tx_mtu,cie_err_code,rx_m_flags);

	memset(&nhs_nbma_addr,0,sizeof(rhp_ip_addr));
	memset(&nhs_proto_addr,0,sizeof(rhp_ip_addr));
	memset(&rx_nhc_nbma_addr,0,sizeof(rhp_ip_addr));
	memset(&nhc_nbma_addr,0,sizeof(rhp_ip_addr));
	memset(&nhc_proto_addr,0,sizeof(rhp_ip_addr));


	//
	// Rx NHS's NBMA addr and Protocol addr are already verified.
	//
	err = rx_nhrp_mesg->get_rx_nbma_dst_addr(rx_nhrp_mesg,&nhs_nbma_addr);
  if( err ){
  	goto error;
  }

  err = rx_nhrp_mesg->m.mandatory->get_dst_protocol_addr(rx_nhrp_mesg,&nhs_proto_addr);
  if( err ){
  	goto error;
  }

	err = rx_nhrp_mesg->get_rx_nbma_src_addr(rx_nhrp_mesg,&rx_nhc_nbma_addr);
  if( err ){
  	goto error;
  }

	err = rx_nhrp_mesg->m.mandatory->get_src_nbma_addr(rx_nhrp_mesg,&nhc_nbma_addr);
  if( err ){
  	goto error;
  }

  err = rx_nhrp_mesg->m.mandatory->get_src_protocol_addr(rx_nhrp_mesg,&nhc_proto_addr);
  if( err ){
  	goto error;
  }


	tx_nhrp_mesg = rhp_nhrp_mesg_dup(rx_nhrp_mesg);
	if( tx_nhrp_mesg == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	tx_nhrp_mesg->f_packet_type = RHP_PROTO_NHRP_PKT_REGISTRATION_REP;

	tx_nhrp_mesg->m.mandatory->dont_update_request_id(tx_nhrp_mesg,1);

	{
		rhp_nhrp_cie* nhrp_m_cie = tx_nhrp_mesg->m.mandatory->cie_list_head;

		if( nhrp_m_cie == NULL ){

			nhrp_m_cie = rhp_nhrp_cie_alloc((u8)cie_err_code);
			if( nhrp_m_cie == NULL ){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}

			err = tx_nhrp_mesg->m.mandatory->add_cie(tx_nhrp_mesg,nhrp_m_cie);
			if( err ){
				rhp_nhrp_cie_free(nhrp_m_cie);
				goto error;
			}

			nhrp_m_cie->set_mtu(nhrp_m_cie,
					(rhp_gcfg_nhrp_cie_mtu ? (u16)rhp_gcfg_nhrp_cie_mtu : (u16)tx_mtu));

			nhrp_m_cie->set_hold_time(nhrp_m_cie,(u16)rhp_gcfg_nhrp_cache_hold_time);

		}else{

			max_mesg_len = nhrp_m_cie->get_mtu(nhrp_m_cie); // Actually, Req's mtu.

			nhrp_m_cie->code = (u8)cie_err_code;
		}
	}


	err = _rhp_nhrp_tx_rep_set_responder_ext(tx_nhrp_mesg,rx_vpn,&nhs_proto_addr,tx_mtu);
	if( err ){
		goto error;
	}


	if( RHP_PROTO_NHRP_RES_FLAG_CISCO_NAT_EXT(rx_m_flags) ){
/*
		rhp_nhrp_ext* nhrp_ext_cisco_nat;

		nhrp_ext_cisco_nat
			= tx_nhrp_mesg->remove_extension(tx_nhrp_mesg,RHP_PROTO_NHRP_EXT_TYPE_NAT_ADDRESS);
		if( nhrp_ext_cisco_nat ){
			rhp_nhrp_ext_free(nhrp_ext_cisco_nat);
		}
*/
		err = _rhp_nhrp_nhs_tx_rep_set_nat_ext(tx_nhrp_mesg,&rx_nhc_nbma_addr,
						&nhc_proto_addr,tx_mtu);
		if( err ){
			goto error;
		}
	}


	{
		rhp_packet* tx_pkt = NULL;

		err = tx_nhrp_mesg->serialize(tx_nhrp_mesg,rx_vpn,max_mesg_len,&tx_pkt);
		if( !err ){
			*tx_pkt_r = tx_pkt;
		}
	}

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,rx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_TX_REGISTRATION_REP,"VBB",rx_vpn,rx_nhrp_mesg,tx_nhrp_mesg);

	rhp_nhrp_mesg_unhold(tx_nhrp_mesg);

	RHP_TRC(0,RHPTRCID_NHRP_TX_REGISTRATION_REP_RTRN,"xxxd",rx_nhrp_mesg,rx_vpn,*tx_pkt_r,max_mesg_len);
	return 0;

error:

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,rx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_TX_REGISTRATION_REP,"VBBE",rx_vpn,rx_nhrp_mesg,tx_nhrp_mesg,err);

	if( tx_nhrp_mesg ){
		rhp_nhrp_mesg_unhold(tx_nhrp_mesg);
	}
	RHP_TRC(0,RHPTRCID_NHRP_TX_REGISTRATION_REP_ERR,"xxE",rx_nhrp_mesg,rx_vpn,err);
	return err;
}

static int _rhp_nhrp_rx_registration_req(rhp_nhrp_mesg* rx_nhrp_mesg,rhp_vpn* rx_vpn,int *tx_mtu_r)
{
	int err = -EINVAL;
	rhp_ip_addr src_nbma_addr, src_proto_addr, dst_proto_addr;
	int def_mtu, new_cache = 0;
	rhp_nhrp_cache* nhrp_c = NULL;
	rhp_packet* rx_pkt = RHP_PKT_REF(rx_nhrp_mesg->rx_pkt_ref);
	rhp_nhrp_cie* nhrp_cie;
	u16 m_flags;

	RHP_TRC(0,RHPTRCID_NHRP_RX_REGISTRATION_REQ,"xxxx",rx_nhrp_mesg,rx_vpn,tx_mtu_r,rx_pkt);

	memset(&src_nbma_addr,0,sizeof(rhp_ip_addr));
	memset(&src_proto_addr,0,sizeof(rhp_ip_addr));
	memset(&dst_proto_addr,0,sizeof(rhp_ip_addr));

	if( rx_pkt->nhrp.nbma_addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_NHRP_RX_REGISTRATION_REQ_RX_PKT_NBMA_ADDR_V4,"xx44",rx_nhrp_mesg,rx_vpn,*((u32*)rx_pkt->nhrp.nbma_src_addr),*((u32*)rx_pkt->nhrp.nbma_dst_addr));
	}else if( rx_pkt->nhrp.nbma_addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_NHRP_RX_REGISTRATION_REQ_RX_PKT_NBMA_ADDR_V6,"xx66",rx_nhrp_mesg,rx_vpn,rx_pkt->nhrp.nbma_src_addr,rx_pkt->nhrp.nbma_dst_addr);
	}else{
		RHP_TRC(0,RHPTRCID_NHRP_RX_REGISTRATION_REQ_RX_PKT_NBMA_ADDR_NONE,"xxLd",rx_nhrp_mesg,rx_vpn,"AF",rx_pkt->nhrp.nbma_addr_family);
	}

	{
		err = rx_nhrp_mesg->m.mandatory->get_src_nbma_addr(rx_nhrp_mesg,&src_nbma_addr);
		if( err ){
			goto error;
		}

		err = rx_nhrp_mesg->m.mandatory->get_src_protocol_addr(rx_nhrp_mesg,&src_proto_addr);
		if( err ){
			goto error;
		}

		err = rx_nhrp_mesg->m.mandatory->get_dst_protocol_addr(rx_nhrp_mesg,&dst_proto_addr);
		if( err ){
			goto error;
		}
	}


	err = _rhp_nhrp_rx_req_verify(rx_nhrp_mesg,rx_vpn,
					RHP_PROTO_NHRP_PKT_REGISTRATION_REQ,
					&src_nbma_addr,&src_proto_addr,&dst_proto_addr);
	if( err ){
		goto error;
	}


	err = _rhp_nhrp_get_def_mtu(rx_vpn,&def_mtu);
	if( err ){
		goto error;
	}


	RHP_LOCK(&rhp_nhrp_lock);

	nhrp_c = _rhp_nhrp_cache_get(rx_vpn->vpn_realm_id,
						src_proto_addr.addr_family,src_proto_addr.addr.raw);
	if( nhrp_c ){

		// Different IPsec VPNs may use the same NBMA address and so
		// only duplication of protocol address is checked here.

		if( RHP_VPN_REF(nhrp_c->vpn_ref) != rx_vpn ){
			err = RHP_STATUS_NHRP_RX_DUPLICATED_ADDR;
			RHP_TRC(0,RHPTRCID_NHRP_RX_REGISTRATION_REQ_RX_DUP_ADDR,"xxxxx",rx_nhrp_mesg,rx_vpn,tx_mtu_r,rx_pkt,RHP_VPN_REF(nhrp_c->vpn_ref));
			goto error_l;
		}

		if( rhp_gcfg_nhrp_strictly_check_addr_uniqueness &&
				nhrp_c->uniqueness ){
			err = RHP_STATUS_NHRP_RX_DUPLICATED_ADDR;
			RHP_TRC(0,RHPTRCID_NHRP_RX_REGISTRATION_REQ_RX_DUP_ADDR_2,"xxxxx",rx_nhrp_mesg,rx_vpn,tx_mtu_r,rx_pkt,RHP_VPN_REF(nhrp_c->vpn_ref));
			goto error_l;
		}

		memcpy(&(nhrp_c->nbma_addr),&src_nbma_addr,sizeof(rhp_ip_addr));

		nhrp_c->created_time = _rhp_get_time();

	}else{

		if( rx_vpn->nhrp.nhs_next_hop_addrs_num > rhp_gcfg_internal_net_max_peer_addrs ){
			err = RHP_STATUS_NHRP_MAX_CACHE_NUM_REACHED;
			RHP_TRC(0,RHPTRCID_NHRP_RX_REGISTRATION_REQ_MAX_PEERS_REACHED,"xxxdd",rx_nhrp_mesg,rx_vpn,rx_pkt,rx_vpn->nhrp.nhs_next_hop_addrs_num,rhp_gcfg_internal_net_max_peer_addrs);
			goto error_l;
		}

		nhrp_c = _rhp_nhrp_cache_alloc();
		if( nhrp_c == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error_l;
		}

		nhrp_c->vpn_realm_id = rx_vpn->vpn_realm_id;
		nhrp_c->vpn_ref = rhp_vpn_hold_ref(rx_vpn);

		memcpy(&(nhrp_c->nbma_addr),&src_nbma_addr,sizeof(rhp_ip_addr));
		memcpy(&(nhrp_c->protocol_addr),&src_proto_addr,sizeof(rhp_ip_addr));

		memcpy(nhrp_c->vpn_dummy_mac,rx_vpn->internal_net_info.dummy_peer_mac,6);

		new_cache = 1;
	}



	if( !rhp_ip_addr_cmp_value(&src_nbma_addr,
				(rx_pkt->nhrp.nbma_addr_family == AF_INET ? 4 : 16),rx_pkt->nhrp.nbma_src_addr) ){

		memset(&(nhrp_c->nat_addr),0,sizeof(rhp_ip_addr));
		nhrp_c->nat_addr.addr_family = AF_UNSPEC;

	}else{

		if( rx_pkt->nhrp.nbma_addr_family == AF_INET ){
			RHP_TRC(0,RHPTRCID_NHRP_RX_REGISTRATION_REQ_PEER_BEHIND_A_NAT_V4,"xxxLd4",rx_nhrp_mesg,rx_vpn,rx_pkt,"AF",rx_pkt->nhrp.nbma_addr_family,*((u32*)rx_pkt->nhrp.nbma_src_addr));
		}else if( rx_pkt->nhrp.nbma_addr_family == AF_INET6 ){
			RHP_TRC(0,RHPTRCID_NHRP_RX_REGISTRATION_REQ_PEER_BEHIND_A_NAT_V6,"xxxLd6",rx_nhrp_mesg,rx_vpn,rx_pkt,"AF",rx_pkt->nhrp.nbma_addr_family,rx_pkt->nhrp.nbma_src_addr);
		}else{
			RHP_TRC(0,RHPTRCID_NHRP_RX_REGISTRATION_REQ_PEER_BEHIND_A_NAT_UNKNOWN_AF,"xxxLd",rx_nhrp_mesg,rx_vpn,rx_pkt,rx_pkt->nhrp.nbma_addr_family);
		}
		rhp_ip_addr_dump("PEER_BEHIND_A_NAT",&src_nbma_addr);


		nhrp_c->nat_addr.addr_family = rx_pkt->nhrp.nbma_addr_family;

		if( nhrp_c->nat_addr.addr_family == AF_INET ){

			nhrp_c->nat_addr.addr.v4 = *((u32*)rx_pkt->nhrp.nbma_src_addr);

		}else if( nhrp_c->nat_addr.addr_family == AF_INET6 ){

			memcpy(nhrp_c->nat_addr.addr.v6,rx_pkt->nhrp.nbma_src_addr,16);
		}
	}


	m_flags = rx_nhrp_mesg->m.mandatory->get_flags(rx_nhrp_mesg);
	nhrp_c->uniqueness = (RHP_PROTO_NHRP_RES_FLAG_U_UNIQUE(m_flags) ? 1 : 0);

	nhrp_c->authoritative = 1;


	nhrp_cie = rx_nhrp_mesg->m.mandatory->cie_list_head;
	if( nhrp_cie ){

		u16 hold_time = nhrp_cie->get_hold_time(nhrp_cie);
		u16 mtu = nhrp_cie->get_mtu(nhrp_cie);

		if( hold_time ){
			nhrp_c->rx_hold_time = hold_time;
		}else{
			nhrp_c->rx_hold_time = rhp_gcfg_nhrp_cache_hold_time;
		}

		if( mtu ){
			nhrp_c->rx_mtu = mtu;
		}else{
			nhrp_c->rx_mtu = def_mtu;
		}
	}

	if( new_cache ){

		err = _rhp_nhrp_cache_put(nhrp_c);
		if( err ){
			goto error_l;
		}
	}
	nhrp_c = NULL;

	RHP_UNLOCK(&rhp_nhrp_lock);


	if( new_cache ){

		rhp_ip_addr_list* next_hop_addr = rx_vpn->nhrp.nhs_next_hop_addrs;

		while( next_hop_addr ){

			if( !rhp_ip_addr_cmp_ip_only(&(next_hop_addr->ip_addr),&src_proto_addr) ){
				break;
			}

			next_hop_addr = next_hop_addr->next;
		}

		if( next_hop_addr == NULL ){

			next_hop_addr = (rhp_ip_addr_list*)_rhp_malloc(sizeof(rhp_ip_addr_list));
			if( next_hop_addr == NULL ){

				RHP_BUG("");

			}else{

				memset(next_hop_addr,0,sizeof(rhp_ip_addr_list));
				memcpy(&(next_hop_addr->ip_addr),&src_proto_addr,sizeof(rhp_ip_addr_list));

				next_hop_addr->next = rx_vpn->nhrp.nhs_next_hop_addrs;
				rx_vpn->nhrp.nhs_next_hop_addrs = next_hop_addr;

				rx_vpn->nhrp.nhs_next_hop_addrs_num++;
			}
		}
	}


	*tx_mtu_r = def_mtu;

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,rx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_RX_REGISTRATION_REQ,"VB",rx_vpn,rx_nhrp_mesg);

	RHP_TRC(0,RHPTRCID_NHRP_RX_REGISTRATION_REQ_RTRN,"xxxd",rx_nhrp_mesg,rx_vpn,rx_pkt,*tx_mtu_r);
	return 0;

error_l:
	RHP_UNLOCK(&rhp_nhrp_lock);

	if( new_cache && nhrp_c ){
		_rhp_nhrp_free_cache(nhrp_c);
	}

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,rx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_RX_REGISTRATION_REQ_ERR,"VBE",rx_vpn,rx_nhrp_mesg,err);
	RHP_TRC(0,RHPTRCID_NHRP_RX_REGISTRATION_REQ_ERR,"xxxE",rx_nhrp_mesg,rx_vpn,rx_pkt,err);
	return err;
}

static int _rhp_nhrp_rx_registration_rep(rhp_nhrp_mesg* rx_nhrp_mesg,rhp_vpn* rx_vpn)
{
	int err = -EINVAL;
	rhp_ip_addr src_nbma_addr, src_proto_addr;
	rhp_nhrp_req_session* nhrp_sess = NULL;
	rhp_nhrp_cie* nhrp_cie;
	time_t next_tx_req_interval = (time_t)rhp_gcfg_nhrp_cache_update_interval;
	u16 rx_m_flags = 0;

	RHP_TRC(0,RHPTRCID_NHRP_RX_REGISTRATION_REP,"xxd",rx_nhrp_mesg,rx_vpn,rhp_gcfg_nhrp_cache_update_interval);

	memset(&src_nbma_addr,0,sizeof(rhp_ip_addr));
	memset(&src_proto_addr,0,sizeof(rhp_ip_addr));

	{
		err = rx_nhrp_mesg->m.mandatory->get_src_nbma_addr(rx_nhrp_mesg,&src_nbma_addr);
		if( err ){
			goto error;
		}

		err = rx_nhrp_mesg->m.mandatory->get_src_protocol_addr(rx_nhrp_mesg,&src_proto_addr);
		if( err ){
			goto error;
		}
	}

	rx_m_flags = rx_nhrp_mesg->m.mandatory->get_flags(rx_nhrp_mesg);


	RHP_LOCK(&rhp_nhrp_lock);

	nhrp_sess =  _rhp_nhrp_req_sess_get(
			rx_vpn->vpn_realm_id,
			RHP_PROTO_NHRP_PKT_REGISTRATION_REQ,
			src_proto_addr.addr_family,src_proto_addr.addr.raw);

	if( nhrp_sess == NULL ){
		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_NHRP_RX_REGISTRATION_REP_UNKNOWN_REP_SESS,"xx",rx_nhrp_mesg,rx_vpn);
		goto error_l;
	}

	if( nhrp_sess->tx_request_id !=
				rx_nhrp_mesg->m.mandatory->get_request_id(rx_nhrp_mesg) ){
		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_NHRP_RX_REGISTRATION_REP_UNKNOWN_REP_ID,"xxjj",rx_nhrp_mesg,rx_vpn,nhrp_sess->tx_request_id,rx_nhrp_mesg->m.mandatory->get_request_id(rx_nhrp_mesg));
		goto error_l;
	}

	if( memcmp(nhrp_sess->vpn_uid,rx_vpn->unique_id,RHP_VPN_UNIQUE_ID_SIZE) ){
		err = RHP_STATUS_NHRP_RX_FROM_UNKNOWN_VPN;
		RHP_TRC(0,RHPTRCID_NHRP_RX_REGISTRATION_REP_UNKNOWN_VPN,"xxxpp",rx_nhrp_mesg,rx_vpn,nhrp_sess,RHP_VPN_UNIQUE_ID_SIZE,nhrp_sess->vpn_uid,RHP_VPN_UNIQUE_ID_SIZE,rx_vpn->unique_id);
		goto error_l;
	}

	err = rhp_timer_delete(&(nhrp_sess->timer));
	if( err ){
		nhrp_sess->done = 1;
		RHP_TRC(0,RHPTRCID_NHRP_RX_REGISTRATION_REP_SESS_TIMER_HANDLER_WAITING,"xxxx",rx_nhrp_mesg,rx_vpn,nhrp_sess,&(nhrp_sess->timer));
		goto error_l;
	}
	_rhp_nhrp_req_sess_unhold(nhrp_sess);


	if( !_rhp_nhrp_req_sess_delete(nhrp_sess) ){
		_rhp_nhrp_req_sess_unhold(nhrp_sess);
	}else{
		RHP_BUG("");
	}
	nhrp_sess = NULL;


	nhrp_cie = rx_nhrp_mesg->m.mandatory->cie_list_head;
	if( nhrp_cie == NULL ||
			nhrp_cie->code != RHP_PROTO_NHRP_CIE_CODE_SUCCESS ){

		next_tx_req_interval = (time_t)rhp_gcfg_nhrp_cache_update_interval_error;

		RHP_TRC(0,RHPTRCID_NHRP_RX_REGISTRATION_REP_SESS_TIMER_ERROR_INTERVAL,"xxxbdx",rx_nhrp_mesg,rx_vpn,nhrp_cie,(nhrp_cie ? nhrp_cie->code : 0),rhp_gcfg_nhrp_cache_update_interval_error,nhrp_sess);
	}

	RHP_UNLOCK(&rhp_nhrp_lock);


	if( RHP_PROTO_NHRP_RES_FLAG_CISCO_NAT_EXT(rx_m_flags) ){

		rhp_nhrp_ext* nhrp_ext_cisco_nat;
		rhp_nhrp_cie* nhrp_ext_cisco_nat_cie = NULL;

		nhrp_ext_cisco_nat
			= rx_nhrp_mesg->get_extension(rx_nhrp_mesg,RHP_PROTO_NHRP_EXT_TYPE_NAT_ADDRESS);

		if( nhrp_ext_cisco_nat ){

			nhrp_ext_cisco_nat_cie = nhrp_ext_cisco_nat->cie_list_head;
			while( nhrp_ext_cisco_nat_cie ){

				rhp_ip_addr nhc_nbma_addr, nhc_proto_addr;
				rhp_nhrp_addr_map* nhc_addr_map;

				memset(&nhc_nbma_addr,0,sizeof(rhp_ip_addr));
				memset(&nhc_proto_addr,0,sizeof(rhp_ip_addr));

				nhrp_ext_cisco_nat_cie->get_clt_nbma_addr(nhrp_ext_cisco_nat_cie,
								&nhc_nbma_addr);

				nhrp_ext_cisco_nat_cie->get_clt_protocol_addr(nhrp_ext_cisco_nat_cie,
								&nhc_proto_addr);


				nhc_addr_map = rx_vpn->nhrp.nhc_addr_maps_head;
				while( nhc_addr_map ){

					rhp_nhrp_addr_map_dump("nhc_addr_map",nhc_addr_map);

					if( nhc_proto_addr.addr_family == nhc_addr_map->proto_addr_family &&
							((nhc_proto_addr.addr_family == AF_INET && nhc_proto_addr.addr.v4 == nhc_addr_map->proto_addr.v4) ||
							 (nhc_proto_addr.addr_family == AF_INET6 && !memcmp(nhc_proto_addr.addr.v6,nhc_addr_map->proto_addr.v6,16))) ){

						nhc_addr_map->nat_nbma_addr_family = nhc_nbma_addr.addr_family;
						memcpy(nhc_addr_map->nat_nbma_addr.raw,nhc_nbma_addr.addr.raw,16);

						rhp_nhrp_addr_map_dump("nhc_addr_map:NAT-UPDATED",nhc_addr_map);
						break;
					}

					nhc_addr_map = nhc_addr_map->next;
				}

				nhrp_ext_cisco_nat_cie = nhrp_ext_cisco_nat_cie->next;
			}
		}
	}


	rx_vpn->start_nhc_registration_timer(rx_vpn,next_tx_req_interval);

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,rx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_RX_REGISTRATION_REP,"VB",rx_vpn,rx_nhrp_mesg);

	RHP_TRC(0,RHPTRCID_NHRP_RX_REGISTRATION_REP_RTRN,"xxx",rx_nhrp_mesg,rx_vpn,nhrp_sess);
	return 0;

error_l:
	RHP_UNLOCK(&rhp_nhrp_lock);

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,rx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_RX_REGISTRATION_REP_ERR,"VBE",rx_vpn,rx_nhrp_mesg,err);
	RHP_TRC(0,RHPTRCID_NHRP_RX_REGISTRATION_REP_ERR,"xxxE",rx_nhrp_mesg,rx_vpn,nhrp_sess,err);
	return err;
}



static rhp_nhrp_mesg* _rhp_nhrp_tx_purge_req_alloc(rhp_vpn* tx_vpn,u16 f_addr_family,
		rhp_ip_addr* src_proto_addr,rhp_ip_addr* dst_proto_addr)
{
	int err = -EINVAL;
	rhp_nhrp_mesg* tx_nhrp_mesg = NULL;
	rhp_nhrp_cie* nhrp_cie;
	rhp_nhrp_ext* nhrp_ext;
	int mtu;

	RHP_TRC(0,RHPTRCID_NHRP_TX_PURGE_REQ_ALLOC,"xWxx",tx_vpn,f_addr_family,src_proto_addr,dst_proto_addr);
	rhp_ip_addr_dump("src_proto_addr",src_proto_addr);
	rhp_ip_addr_dump("dst_proto_addr",dst_proto_addr);


	err = _rhp_nhrp_get_def_mtu(tx_vpn,&mtu);
	if( err ){
		goto error;
	}


	tx_nhrp_mesg = rhp_nhrp_mesg_new_tx(f_addr_family,RHP_PROTO_NHRP_PKT_PURGE_REQ);
	if( tx_nhrp_mesg == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}


	err = tx_nhrp_mesg->m.mandatory->set_flags(tx_nhrp_mesg,RHP_PROTO_NHRP_FLAG_CISCO_NAT_EXT);
	if( err ){
		goto error;
	}

	err = tx_nhrp_mesg->m.mandatory->set_src_nbma_addr(tx_nhrp_mesg,
					tx_vpn->local.if_info.addr_family,tx_vpn->local.if_info.addr.raw);
	if( err ){
		goto error;
	}

	err = tx_nhrp_mesg->m.mandatory->set_src_protocol_addr(tx_nhrp_mesg,
					src_proto_addr->addr_family,src_proto_addr->addr.raw);
	if( err ){
		goto error;
	}

	err = tx_nhrp_mesg->m.mandatory->set_dst_protocol_addr(tx_nhrp_mesg,
						dst_proto_addr->addr_family,dst_proto_addr->addr.raw);
	if( err ){
		goto error;
	}


	{
		nhrp_cie = rhp_nhrp_cie_alloc(RHP_PROTO_NHRP_CIE_CODE_NONE);
		if( nhrp_cie == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = tx_nhrp_mesg->m.mandatory->add_cie(tx_nhrp_mesg,nhrp_cie);
		if( err ){
			rhp_nhrp_cie_free(nhrp_cie);
			goto error;
		}

		err = nhrp_cie->set_mtu(nhrp_cie,0);
		if( err ){
			goto error;
		}

		err = nhrp_cie->set_hold_time(nhrp_cie,0);
		if( err ){
			goto error;
		}

		err = nhrp_cie->set_prefix_len(nhrp_cie,0xFF);
		if( err ){
			goto error;
		}

		err = nhrp_cie->set_clt_protocol_addr(nhrp_cie,src_proto_addr->addr_family,src_proto_addr->addr.raw);
		if( err ){
			goto error;
		}
	}


	{
		nhrp_ext = rhp_nhrp_ext_alloc(RHP_PROTO_NHRP_EXT_TYPE_RESPONDER_ADDRESS,1);
		if( nhrp_ext == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = tx_nhrp_mesg->add_extension(tx_nhrp_mesg,nhrp_ext);
		if( err ){
			rhp_nhrp_ext_free(nhrp_ext);
			goto error;
		}
	}

	{
		nhrp_ext = rhp_nhrp_ext_alloc(RHP_PROTO_NHRP_EXT_TYPE_FORWARD_TRANSIT_NHS_RECORD,1);
		if( nhrp_ext == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = tx_nhrp_mesg->add_extension(tx_nhrp_mesg,nhrp_ext);
		if( err ){
			rhp_nhrp_ext_free(nhrp_ext);
			goto error;
		}
	}

	{
		nhrp_ext = rhp_nhrp_ext_alloc(RHP_PROTO_NHRP_EXT_TYPE_REVERSE_TRANSIT_NHS_RECORD,1);
		if( nhrp_ext == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = tx_nhrp_mesg->add_extension(tx_nhrp_mesg,nhrp_ext);
		if( err ){
			rhp_nhrp_ext_free(nhrp_ext);
			goto error;
		}
	}

	{
		//
		// Cisco's NAT extension:
		//

		err = _rhp_nhrp_tx_rep_set_nat_ext(tx_nhrp_mesg,
						&(tx_vpn->peer_addr),dst_proto_addr,mtu);
		if( err ){
			goto error;
		}
	}

	RHP_TRC(0,RHPTRCID_NHRP_TX_PURGE_REQ_ALLOC_RTRN,"xx",tx_vpn,tx_nhrp_mesg);
	return tx_nhrp_mesg;

error:
	if( tx_nhrp_mesg ){
		rhp_nhrp_mesg_unhold(tx_nhrp_mesg);
	}
	RHP_TRC(0,RHPTRCID_NHRP_TX_PURGE_REQ_ALLOC_ERR,"x",tx_vpn);
	return NULL;
}

//
// [CAUTION]
//  Caller must NOT acquire tx_vpn->lock.
//
int rhp_nhrp_tx_purge_req(rhp_vpn* tx_vpn,rhp_ip_addr* purged_proto_addr)
{
	int err = -EINVAL;
	rhp_vpn_realm* tx_rlm = NULL;
	u16 f_addr_family;
	rhp_ip_addr* nhs_addr_p = NULL;
	rhp_nhrp_mesg* tx_nhrp_mesg = NULL;
	rhp_packet* tx_pkt = NULL;
  u8 vpn_uid[RHP_VPN_UNIQUE_ID_SIZE];

	RHP_TRC(0,RHPTRCID_NHRP_TX_PURGE_REQ,"xx",tx_vpn,purged_proto_addr);
	rhp_ip_addr_dump("purged_proto_addr",purged_proto_addr);


	RHP_LOCK(&(tx_vpn->lock));

	if( !_rhp_atomic_read(&(tx_vpn->is_active)) ){
		err = -EINVAL;
		goto error;
	}


	if( tx_vpn->local.if_info.addr_family == AF_INET ){

		f_addr_family = RHP_PROTO_NHRP_ADDR_FAMILY_IPV4;

	}else if( tx_vpn->local.if_info.addr_family == AF_INET6 ){

		f_addr_family = RHP_PROTO_NHRP_ADDR_FAMILY_IPV6;

	}else{

		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_NHRP_TX_PURGE_REQ_NO_LOCAL_IP_ADDR,"xxxLd",tx_vpn,tx_rlm,purged_proto_addr,"AF",tx_vpn->local.if_info.addr_family);
		goto error;
	}

	memcpy(vpn_uid,tx_vpn->unique_id,RHP_VPN_UNIQUE_ID_SIZE);


	tx_rlm = tx_vpn->rlm;
	if( tx_rlm == NULL ){
		err = -EINVAL;
		goto error;
	}


	nhs_addr_p = _rhp_nhrp_get_nhs_peer_addr(tx_vpn,purged_proto_addr->addr_family);
	rhp_ip_addr_dump("nhs_addr_p",nhs_addr_p);

	if( rhp_ip_addr_null(nhs_addr_p) ){
		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_NHRP_TX_PURGE_REQ_NO_NHS_ADDR_FOUND,"xx",tx_vpn,tx_rlm);
		goto error;
	}


	tx_nhrp_mesg = _rhp_nhrp_tx_purge_req_alloc(tx_vpn,
									f_addr_family,purged_proto_addr,nhs_addr_p);
	if( tx_nhrp_mesg == NULL ){
		err = -ENOMEM;
		RHP_BUG("%d",err);
		goto error;
	}

	err = tx_nhrp_mesg->serialize(tx_nhrp_mesg,tx_vpn,0,&tx_pkt);
	if( err ){

		RHP_BUG("%d",err);
		goto error;
	}

	rhp_realm_hold(tx_rlm);

	RHP_UNLOCK(&(tx_vpn->lock));



	//
	// All errors are ignored from here.
	//

	if( tx_nhrp_mesg ){

		rhp_packet* tx_pkt_d;

		RHP_LOCK(&rhp_nhrp_lock);
		{
			u32 tx_request_id = tx_nhrp_mesg->m.mandatory->get_request_id(tx_nhrp_mesg);

			err = _rhp_nhrp_exec_request_session(
							tx_rlm->id,
							vpn_uid,
							tx_request_id,
							RHP_PROTO_NHRP_PKT_PURGE_REQ,
							purged_proto_addr->addr_family,purged_proto_addr->addr.raw,
							AF_UNSPEC,NULL,
							tx_pkt,NULL);
			if( err ){

				RHP_BUG("%d",err);
			}
		}
		RHP_UNLOCK(&rhp_nhrp_lock);


		tx_pkt_d = rhp_pkt_dup(tx_pkt);
		if( tx_pkt_d ){

			// tx_vpn->lock and tx_rlm->lock will be acquired in rhp_gre_send_access_point().
			rhp_gre_send_access_point(tx_rlm,tx_pkt_d);
			rhp_pkt_unhold(tx_pkt_d);

		}else{

			// Retry later in timer handler.
			RHP_BUG("");
		}

		rhp_nhrp_mesg_unhold(tx_nhrp_mesg);
		tx_nhrp_mesg = NULL;

		rhp_pkt_unhold(tx_pkt);
		tx_pkt = NULL;
	}

	rhp_realm_unhold(tx_rlm);

	RHP_TRC(0,RHPTRCID_NHRP_TX_PURGE_REQ_RTRN,"xxx",tx_vpn,tx_rlm,tx_pkt);
	return 0;

error:
	RHP_UNLOCK(&(tx_vpn->lock));

	if( tx_nhrp_mesg ){
		rhp_nhrp_mesg_unhold(tx_nhrp_mesg);
	}

	if( tx_pkt ){
		rhp_pkt_unhold(tx_pkt);
	}

	RHP_TRC(0,RHPTRCID_NHRP_TX_PURGE_REQ_ERR,"xxxE",tx_vpn,tx_rlm,tx_pkt,err);
	return err;
}

static int _rhp_nhrp_tx_purge_rep(rhp_nhrp_mesg* rx_nhrp_mesg,rhp_vpn* rx_vpn,rhp_packet** tx_pkt_r)
{
	int err = -EINVAL;
	rhp_nhrp_mesg* tx_nhrp_mesg = NULL;
	rhp_ip_addr nhs_proto_addr, rx_nhc_nbma_addr, nhc_nbma_addr, nhc_proto_addr;
	u16 rx_m_flags = rx_nhrp_mesg->m.mandatory->get_flags(rx_nhrp_mesg);
	int mtu;

	RHP_TRC(0,RHPTRCID_NHRP_TX_PURGE_REP,"xxx",rx_nhrp_mesg,rx_vpn,tx_pkt_r);

	memset(&nhc_nbma_addr,0,sizeof(rhp_ip_addr));
	memset(&rx_nhc_nbma_addr,0,sizeof(rhp_ip_addr));
	memset(&nhs_proto_addr,0,sizeof(rhp_ip_addr));
	memset(&nhc_proto_addr,0,sizeof(rhp_ip_addr));


	err = _rhp_nhrp_get_def_mtu(rx_vpn,&mtu);
	if( err ){
		goto error;
	}

	//
	// Rx NHS's Protocol addr is already verified.
	//

  err = rx_nhrp_mesg->m.mandatory->get_dst_protocol_addr(rx_nhrp_mesg,&nhs_proto_addr);
  if( err ){
  	goto error;
  }

	err = rx_nhrp_mesg->get_rx_nbma_src_addr(rx_nhrp_mesg,&rx_nhc_nbma_addr);
  if( err ){
  	goto error;
  }

	err = rx_nhrp_mesg->m.mandatory->get_src_nbma_addr(rx_nhrp_mesg,&nhc_nbma_addr);
  if( err ){
  	goto error;
  }

  err = rx_nhrp_mesg->m.mandatory->get_src_protocol_addr(rx_nhrp_mesg,&nhc_proto_addr);
  if( err ){
  	goto error;
  }


	tx_nhrp_mesg = rhp_nhrp_mesg_dup(rx_nhrp_mesg);
	if( tx_nhrp_mesg == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	tx_nhrp_mesg->f_packet_type = RHP_PROTO_NHRP_PKT_PURGE_REP;

	tx_nhrp_mesg->m.mandatory->dont_update_request_id(tx_nhrp_mesg,1);


	err = _rhp_nhrp_tx_rep_set_responder_ext(tx_nhrp_mesg,rx_vpn,&nhs_proto_addr,mtu);
	if( err ){
		goto error;
	}


	if( RHP_PROTO_NHRP_RES_FLAG_CISCO_NAT_EXT(rx_m_flags) ){

		rhp_nhrp_ext* nhrp_ext_cisco_nat;

		nhrp_ext_cisco_nat = tx_nhrp_mesg->remove_extension(tx_nhrp_mesg,RHP_PROTO_NHRP_EXT_TYPE_NAT_ADDRESS);
		if( nhrp_ext_cisco_nat ){
			rhp_nhrp_ext_free(nhrp_ext_cisco_nat);
		}

		err = _rhp_nhrp_nhs_tx_rep_set_nat_ext(tx_nhrp_mesg,&rx_nhc_nbma_addr,
						&nhc_proto_addr,mtu);
		if( err ){
			goto error;
		}
	}


	{
		rhp_packet* tx_pkt = NULL;

		err = tx_nhrp_mesg->serialize(tx_nhrp_mesg,rx_vpn,0,&tx_pkt);
		if( !err ){
			*tx_pkt_r = tx_pkt;
		}
	}

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,rx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_TX_PURGE_REP,"VBB",rx_vpn,rx_nhrp_mesg,tx_nhrp_mesg);

	rhp_nhrp_mesg_unhold(tx_nhrp_mesg);

	RHP_TRC(0,RHPTRCID_NHRP_TX_PURGE_REP_RTRN,"xxx",rx_nhrp_mesg,rx_vpn,*tx_pkt_r);
	return 0;

error:

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,rx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_TX_PURGE_REP_ERR,"VBB",rx_vpn,rx_nhrp_mesg,tx_nhrp_mesg);

	if( tx_nhrp_mesg ){
		rhp_nhrp_mesg_unhold(tx_nhrp_mesg);
	}
	RHP_TRC(0,RHPTRCID_NHRP_TX_PURGE_REP_ERR,"xxE",rx_nhrp_mesg,rx_vpn,err);
	return err;
}

static int _rhp_nhrp_rx_purge_req(rhp_nhrp_mesg* rx_nhrp_mesg,rhp_vpn* rx_vpn,u16* m_flags_r)
{
	int err = -EINVAL;
	rhp_ip_addr src_clt_proto_addr, dst_proto_addr;
	rhp_nhrp_cache* nhrp_c = NULL;
	rhp_vpn_realm* rlm = rx_vpn->rlm;
  rhp_ifc_entry* v_ifc;
	rhp_ifc_addr* if_addr;
	int i, flag;
	rhp_nhrp_cie* nhrp_cie;
	u16 m_flags;

	RHP_TRC(0,RHPTRCID_NHRP_RX_PURGE_REQ,"xxxx",rx_nhrp_mesg,rx_vpn,m_flags_r,rlm);

	memset(&src_clt_proto_addr,0,sizeof(rhp_ip_addr));
	memset(&dst_proto_addr,0,sizeof(rhp_ip_addr));


	if( rlm == NULL ){
		err = -EINVAL;
		RHP_TRC(0,RHPTRCID_NHRP_RX_PURGE_REQ_NO_RLM_FOUND,"xx",rx_nhrp_mesg,rx_vpn);
		goto error;
	}


	err = rx_nhrp_mesg->m.mandatory->get_dst_protocol_addr(rx_nhrp_mesg,&dst_proto_addr);
	if( err ){
		goto error;
	}


	RHP_LOCK(&(rlm->lock));

	v_ifc = rlm->internal_ifc->ifc;
	if( v_ifc == NULL ){
		RHP_UNLOCK(&(rlm->lock));
		RHP_TRC(0,RHPTRCID_NHRP_RX_PURGE_REQ_NO_V_IFC_FOUND,"xx",rx_nhrp_mesg,rx_vpn);
		goto error;
	}

	v_ifc->dump_no_lock("_rhp_nhrp_rx_purge_req",v_ifc);


	RHP_LOCK(&(v_ifc->lock));

	flag = 0;
	if_addr = v_ifc->ifc_addrs;
	for( i = 0; i < v_ifc->ifc_addrs_num; i++ ){

		if( !rhp_ip_addr_cmp_ip_only(&dst_proto_addr,&(if_addr->addr)) ){
			flag = 1;
		}

		if_addr = if_addr->lst_next;
	}

	RHP_UNLOCK(&(v_ifc->lock));

	RHP_UNLOCK(&(rlm->lock));


	if( !flag ){
		err = RHP_STATUS_NHRP_INVALID_ADDR;
		RHP_TRC(0,RHPTRCID_NHRP_RX_PURGE_REQ_NO_ITNL_ADDR_DST_PROTO_ADDR_FOUND,"xx",rx_nhrp_mesg,rx_vpn);
		goto error;
	}



	m_flags = rx_nhrp_mesg->m.mandatory->get_flags(rx_nhrp_mesg);


	nhrp_cie = rx_nhrp_mesg->m.mandatory->cie_list_head;
	if( nhrp_cie ){

		err = nhrp_cie->get_clt_protocol_addr(nhrp_cie,&src_clt_proto_addr);
		if( err ){
			goto error;
		}
	}


	RHP_LOCK(&rhp_nhrp_lock);

	nhrp_c = _rhp_nhrp_cache_get(rx_vpn->vpn_realm_id,
						src_clt_proto_addr.addr_family,src_clt_proto_addr.addr.raw);
	if( nhrp_c == NULL ){
		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_NHRP_RX_PURGE_REQ_NO_CACHE_FOUND,"xx",rx_nhrp_mesg,rx_vpn);
		goto error_l;
	}


	if( RHP_VPN_REF(nhrp_c->vpn_ref) != rx_vpn ){
		err = RHP_STATUS_NHRP_RX_FROM_UNKNOWN_VPN;
		RHP_TRC(0,RHPTRCID_NHRP_RX_PURGE_REQ_UNKNOWN_RX_VPN,"xxx",rx_nhrp_mesg,rx_vpn,RHP_VPN_REF(nhrp_c->vpn_ref));
		goto error_l;
	}


	if( !_rhp_nhrp_cache_delete(nhrp_c) ){
		_rhp_nhrp_free_cache(nhrp_c);
	}else{
		RHP_TRC(0,RHPTRCID_NHRP_RX_PURGE_REQ_DEL_CACHE_ERR,"xxx",rx_nhrp_mesg,rx_vpn,nhrp_c);
	}

	RHP_UNLOCK(&rhp_nhrp_lock);


	_rhp_nhrp_cache_delete_vpn_addr(rx_vpn,&src_clt_proto_addr);


	*m_flags_r = m_flags;

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,rx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_RX_PURGE_REQ,"VB",rx_vpn,rx_nhrp_mesg);

	RHP_TRC(0,RHPTRCID_NHRP_RX_PURGE_REQ_RTRN,"xxxw",rx_nhrp_mesg,rx_vpn,nhrp_c,*m_flags_r);
	return 0;

error_l:
	RHP_UNLOCK(&rhp_nhrp_lock);

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,rx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_RX_PURGE_REQ_ERR,"VBE",rx_vpn,rx_nhrp_mesg,err);

	RHP_TRC(0,RHPTRCID_NHRP_RX_PURGE_REQ_ERR,"xxxE",rx_nhrp_mesg,rx_vpn,nhrp_c,err);
	return err;
}

static int _rhp_nhrp_rx_purge_rep(rhp_nhrp_mesg* rx_nhrp_mesg,rhp_vpn* rx_vpn)
{
	int err = -EINVAL;
	rhp_ip_addr src_proto_addr;
	rhp_nhrp_req_session* nhrp_sess = NULL;
	rhp_nhrp_cie* nhrp_m_cie;

	RHP_TRC(0,RHPTRCID_NHRP_RX_PURGE_REP,"xxd",rx_nhrp_mesg,rx_vpn,rx_vpn->nhrp.nhc_pending_purge_reqs);

	memset(&src_proto_addr,0,sizeof(rhp_ip_addr));


	nhrp_m_cie = rx_nhrp_mesg->m.mandatory->cie_list_head;
	if( nhrp_m_cie ){

		err = nhrp_m_cie->get_clt_protocol_addr(nhrp_m_cie,&src_proto_addr);
		if( err ){
			goto error;
		}
	}

	if( src_proto_addr.addr_family != AF_INET && src_proto_addr.addr_family != AF_INET6 ){
		err = RHP_STATUS_NHRP_INVALID_PKT;
		goto error;
	}


	RHP_LOCK(&rhp_nhrp_lock);

	nhrp_sess =  _rhp_nhrp_req_sess_get(
			rx_vpn->vpn_realm_id,
			RHP_PROTO_NHRP_PKT_PURGE_REQ,
			src_proto_addr.addr_family,src_proto_addr.addr.raw);

	if( nhrp_sess == NULL ){
		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_NHRP_RX_PURGE_REP_NO_CACHE_FOUND,"xx",rx_nhrp_mesg,rx_vpn);
		goto error_l;
	}

	if( nhrp_sess->tx_request_id !=
				rx_nhrp_mesg->m.mandatory->get_request_id(rx_nhrp_mesg) ){
		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_NHRP_RX_PURGE_REP_INVALID_TX_REQ_ID,"xxjj",rx_nhrp_mesg,rx_vpn,nhrp_sess->tx_request_id,rx_nhrp_mesg->m.mandatory->get_request_id(rx_nhrp_mesg));
		goto error_l;
	}

	if( memcmp(nhrp_sess->vpn_uid,rx_vpn->unique_id,RHP_VPN_UNIQUE_ID_SIZE) ){
		err = RHP_STATUS_NHRP_RX_FROM_UNKNOWN_VPN;
		RHP_TRC(0,RHPTRCID_NHRP_RX_PURGE_REP_UNKNOWN_VPN_ID,"xxpp",rx_nhrp_mesg,rx_vpn,RHP_VPN_UNIQUE_ID_SIZE,nhrp_sess->vpn_uid,RHP_VPN_UNIQUE_ID_SIZE,rx_vpn->unique_id);
		goto error_l;
	}

	err = rhp_timer_delete(&(nhrp_sess->timer));
	if( err ){
		nhrp_sess->done = 1;
		RHP_TRC(0,RHPTRCID_NHRP_RX_PURGE_REP_SESS_TIMER_HANDLER_WAITING,"xxx",rx_nhrp_mesg,rx_vpn,&(nhrp_sess->timer));
		goto error_l;
	}
	_rhp_nhrp_req_sess_unhold(nhrp_sess);


	if( !_rhp_nhrp_req_sess_delete(nhrp_sess) ){
		_rhp_nhrp_req_sess_unhold(nhrp_sess);
	}else{
		RHP_BUG("");
	}
	nhrp_sess = NULL;

	RHP_UNLOCK(&rhp_nhrp_lock);


	rx_vpn->nhrp.nhc_pending_purge_reqs--;
	if( rx_vpn->nhrp.nhc_pending_purge_reqs < 1 ){

		rx_vpn->start_nhc_registration_timer(rx_vpn,rhp_gcfg_nhrp_registration_req_tx_margin_time);

		rx_vpn->nhrp.nhc_pending_purge_reqs = 0;
	}

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,rx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_RX_PURGE_REP,"VBd",rx_vpn,rx_nhrp_mesg,rx_vpn->nhrp.nhc_pending_purge_reqs);

	RHP_TRC(0,RHPTRCID_NHRP_RX_PURGE_REP_RTRN,"xx",rx_nhrp_mesg,rx_vpn);
	return 0;

error_l:
	RHP_UNLOCK(&rhp_nhrp_lock);

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,rx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_RX_PURGE_REP_ERR,"VBE",rx_vpn,rx_nhrp_mesg,err);

	RHP_TRC(0,RHPTRCID_NHRP_RX_PURGE_REP_ERR,"xxE",rx_nhrp_mesg,rx_vpn,err);
	return err;
}



static rhp_nhrp_mesg* _rhp_nhrp_tx_resolution_req_alloc(rhp_vpn* tx_vpn,u16 f_addr_family,
		rhp_ip_addr* rslv_proto_addr,rhp_ifc_addr* nhc_if_addr,rhp_ip_addr* nhs_addr_p,int mtu)
{
	int err = -EINVAL;
	rhp_nhrp_mesg* tx_nhrp_mesg = NULL;
	rhp_nhrp_cie* nhrp_cie;
	rhp_nhrp_ext* nhrp_ext;
	rhp_ip_addr nat_nbma_addr;
	rhp_nhrp_addr_map* nhc_addr_map;

	RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REQ_ALLOC,"xWxxxd",tx_vpn,f_addr_family,rslv_proto_addr,nhc_if_addr,nhs_addr_p,mtu);
	rhp_ip_addr_dump("rslv_proto_addr",rslv_proto_addr);
	rhp_ip_addr_dump("nhc_if_addr",&(nhc_if_addr->addr));
	rhp_ip_addr_dump("nhs_addr_p",nhs_addr_p);


	memset(&nat_nbma_addr,0,sizeof(rhp_ip_addr));

	nhc_addr_map = tx_vpn->nhrp.nhc_addr_maps_head;
	while( nhc_addr_map ){

		if( !rhp_ip_addr_cmp_value(&(nhc_if_addr->addr),
					(nhc_addr_map->proto_addr_family == AF_INET ? 4 : 16),
					nhc_addr_map->proto_addr.raw) ){

			nat_nbma_addr.addr_family = nhc_addr_map->nat_nbma_addr_family;
			memcpy(nat_nbma_addr.addr.raw,nhc_addr_map->nat_nbma_addr.raw,16);

			break;
		}

		nhc_addr_map = nhc_addr_map->next;
	}


	tx_nhrp_mesg = rhp_nhrp_mesg_new_tx(f_addr_family,RHP_PROTO_NHRP_PKT_RESOLUTION_REQ);
	if( tx_nhrp_mesg == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}


	err = tx_nhrp_mesg->m.mandatory->set_flags(tx_nhrp_mesg,
					(RHP_PROTO_NHRP_RES_FLAG_Q | RHP_PROTO_NHRP_RES_FLAG_A |
					 RHP_PROTO_NHRP_FLAG_CISCO_NAT_EXT));
	if( err ){
		goto error;
	}

	err = tx_nhrp_mesg->m.mandatory->set_src_nbma_addr(tx_nhrp_mesg,
					tx_vpn->local.if_info.addr_family,tx_vpn->local.if_info.addr.raw);
	if( err ){
		goto error;
	}

	err = tx_nhrp_mesg->m.mandatory->set_src_protocol_addr(tx_nhrp_mesg,
					nhc_if_addr->addr.addr_family,nhc_if_addr->addr.addr.raw);
	if( err ){
		goto error;
	}

	err = tx_nhrp_mesg->m.mandatory->set_dst_protocol_addr(tx_nhrp_mesg,
			rslv_proto_addr->addr_family,rslv_proto_addr->addr.raw);
	if( err ){
		goto error;
	}


	{
		nhrp_cie = rhp_nhrp_cie_alloc(RHP_PROTO_NHRP_CIE_CODE_NONE);
		if( nhrp_cie == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = tx_nhrp_mesg->m.mandatory->add_cie(tx_nhrp_mesg,nhrp_cie);
		if( err ){
			rhp_nhrp_cie_free(nhrp_cie);
			goto error;
		}

		err = nhrp_cie->set_mtu(nhrp_cie,
				(rhp_gcfg_nhrp_cie_mtu ? (u16)rhp_gcfg_nhrp_cie_mtu : (u16)mtu));
		if( err ){
			goto error;
		}

		err = nhrp_cie->set_hold_time(nhrp_cie,0);
		if( err ){
			goto error;
		}

		err = nhrp_cie->set_prefix_len(nhrp_cie,0);
		if( err ){
			goto error;
		}
	}


	{
		nhrp_ext = rhp_nhrp_ext_alloc(RHP_PROTO_NHRP_EXT_TYPE_RESPONDER_ADDRESS,1);
		if( nhrp_ext == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = tx_nhrp_mesg->add_extension(tx_nhrp_mesg,nhrp_ext);
		if( err ){
			rhp_nhrp_ext_free(nhrp_ext);
			goto error;
		}
	}

	{
		nhrp_ext = rhp_nhrp_ext_alloc(RHP_PROTO_NHRP_EXT_TYPE_FORWARD_TRANSIT_NHS_RECORD,1);
		if( nhrp_ext == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = tx_nhrp_mesg->add_extension(tx_nhrp_mesg,nhrp_ext);
		if( err ){
			rhp_nhrp_ext_free(nhrp_ext);
			goto error;
		}

#ifdef RHP_DBG_NHRP_MESG_LOOP_TEST_1
		{
			rhp_ip_addr test_clt_proto_addr, test_clt_nbma_addr;

			nhrp_cie = rhp_nhrp_cie_alloc(RHP_PROTO_NHRP_CIE_CODE_NONE);
			if( nhrp_cie == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			memset(&test_clt_proto_addr,0,sizeof(rhp_ip_addr));
			memset(&test_clt_nbma_addr,0,sizeof(rhp_ip_addr));

			test_clt_proto_addr.addr_family = AF_INET;
			test_clt_proto_addr.addr.v4 = htonl(0xC0A8DC0A);

			test_clt_nbma_addr.addr_family = AF_INET;
			test_clt_nbma_addr.addr.v4 = htonl(0xC0A80064);

			err = nhrp_ext->add_cie(nhrp_ext,nhrp_cie);
			if( err ){
				rhp_nhrp_cie_free(nhrp_cie);
				goto error;
			}

			err = nhrp_cie->set_mtu(nhrp_cie,0);
			if( err ){
				goto error;
			}

			err = nhrp_cie->set_hold_time(nhrp_cie,(u16)rhp_gcfg_nhrp_cache_hold_time);
			if( err ){
				goto error;
			}

			err = nhrp_cie->set_prefix_len(nhrp_cie,0);
			if( err ){
				goto error;
			}

			err = nhrp_cie->set_clt_protocol_addr(nhrp_cie,
					test_clt_proto_addr.addr_family,test_clt_proto_addr.addr.raw);
			if( err ){
				goto error;
			}

			err = nhrp_cie->set_clt_nbma_addr(nhrp_cie,
					test_clt_nbma_addr.addr_family,test_clt_nbma_addr.addr.raw);
			if( err ){
				goto error;
			}
		}
#endif // RHP_DBG_NHRP_MESG_LOOP_TEST_1
	}

	{
		nhrp_ext = rhp_nhrp_ext_alloc(RHP_PROTO_NHRP_EXT_TYPE_REVERSE_TRANSIT_NHS_RECORD,1);
		if( nhrp_ext == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = tx_nhrp_mesg->add_extension(tx_nhrp_mesg,nhrp_ext);
		if( err ){
			rhp_nhrp_ext_free(nhrp_ext);
			goto error;
		}
	}

	//
	// Cisco's NAT extension:
	//
	err = _rhp_nhrp_tx_rep_set_nat_ext(tx_nhrp_mesg,
					&nat_nbma_addr,&(nhc_if_addr->addr),mtu);
	if( err ){
		goto error;
	}

	RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REQ_ALLOC_RTRN,"xx",tx_vpn,tx_nhrp_mesg);
	return tx_nhrp_mesg;

error:
	if( tx_nhrp_mesg ){
		rhp_nhrp_mesg_unhold(tx_nhrp_mesg);
	}
	RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REQ_ALLOC_ERR,"x",tx_vpn);
	return NULL;
}

//
// [CAUTION]
//  Caller must NOT acquire tx_vpn->lock.
//
int rhp_nhrp_tx_resolution_req(rhp_vpn* tx_vpn,rhp_ip_addr* rslv_proto_addr)
{
	int err = -EINVAL;
	rhp_vpn_realm* tx_rlm = NULL;
	rhp_nhrp_mesg* tx_nhrp_mesg = NULL;
	rhp_packet* tx_pkt = NULL;
	rhp_ifc_entry* v_ifc = NULL;
	rhp_ifc_addr* nhc_if_addr;
	rhp_ip_addr* nhs_addr_p = NULL;
	u16 f_addr_family;
	int mtu;
  int n = 0;
  u8 vpn_uid[RHP_VPN_UNIQUE_ID_SIZE];

	RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REQ,"xxx",tx_vpn,tx_rlm,v_ifc);

	if( rslv_proto_addr->addr_family == AF_INET ){

		if( rslv_proto_addr->addr.v4 == 0xFFFFFFFF ||
				rhp_ip_multicast(AF_INET,(u8*)&(rslv_proto_addr->addr.v4)) ){
	  	RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_V4_BC_MC_ADDR_IGNORED,"x4",tx_vpn,rslv_proto_addr->addr.v4);
			return -EINVAL;
		}

	}else if( rslv_proto_addr->addr_family == AF_INET6 ){

		if( rhp_ip_multicast(AF_INET6,rslv_proto_addr->addr.v6) ){
	  	RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_V6_MC_ADDR_IGNORED,"x6",tx_vpn,rslv_proto_addr->addr.v6);
			return -EINVAL;
		}

	}else{
		RHP_BUG("%d",rslv_proto_addr->addr_family);
		return -EINVAL;
	}


	RHP_LOCK(&(tx_vpn->lock));

	if( !_rhp_atomic_read(&(tx_vpn->is_active)) ){
		err = -EINVAL;
  	RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REQ_VPN_NOT_ACTIVE,"x",tx_vpn);
  	goto error;
	}

	memcpy(vpn_uid,tx_vpn->unique_id,RHP_VPN_UNIQUE_ID_SIZE);


	tx_rlm = tx_vpn->rlm;
	if( tx_rlm == NULL ){
		err = -EINVAL;
  	RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REQ_VPN_NO_RLM_FOUND,"x",tx_vpn);
  	goto error;
	}

	RHP_LOCK(&(tx_rlm->lock));

	if( !_rhp_atomic_read(&(tx_rlm->is_active)) ){
		err = -EINVAL;
  	RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REQ_RLM_NOT_ACTIVE,"xx",tx_vpn,tx_rlm);
  	goto error;
	}


	v_ifc = tx_rlm->internal_ifc->ifc;
  if( v_ifc == NULL ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REQ_NO_V_IFC,"xx",tx_vpn,tx_rlm);
  	goto error;
  }

	RHP_LOCK(&(v_ifc->lock));
	v_ifc->dump_no_lock("rhp_nhrp_tx_resolution_req",v_ifc);


	if( tx_vpn->local.if_info.addr_family == AF_INET ){

		f_addr_family = RHP_PROTO_NHRP_ADDR_FAMILY_IPV4;

	}else if( tx_vpn->local.if_info.addr_family == AF_INET6 ){

		f_addr_family = RHP_PROTO_NHRP_ADDR_FAMILY_IPV6;

	}else{

		err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REQ_NO_ITNL_ADDR,"xx",tx_vpn,tx_rlm);
		goto error;
	}


	nhs_addr_p = _rhp_nhrp_get_nhs_peer_addr(tx_vpn,rslv_proto_addr->addr_family);
	rhp_ip_addr_dump("nhs_addr_p",nhs_addr_p);

	if( rhp_ip_addr_null(nhs_addr_p) ){
		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REQ_NO_NHS_ADDR_FOUND,"xx",tx_vpn,tx_rlm);
		goto error;
	}


	err = _rhp_nhrp_get_def_mtu(tx_vpn,&mtu);
	if( err ){
		goto error;
	}


	nhc_if_addr = _rhp_nhrp_get_internal_addr(v_ifc,rslv_proto_addr->addr_family);
	if( nhc_if_addr == NULL ){
		err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_NO_SRC_PROTO_ADDR,"xx",tx_vpn,tx_rlm);
		goto error;
	}


	if( rslv_proto_addr->addr_family == AF_INET &&
			rhp_ip_subnet_broadcast(&(nhc_if_addr->addr),AF_INET,(u8*)&(rslv_proto_addr->addr.v4)) ){
  	RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_V4_SUBNET_ADDR_IGNORED,"xxx4d4",tx_vpn,v_ifc,nhc_if_addr,nhc_if_addr->addr.addr.v4,nhc_if_addr->addr.prefixlen,rslv_proto_addr->addr.v4);
		err = -EINVAL;
		goto error;
	}


	tx_nhrp_mesg = _rhp_nhrp_tx_resolution_req_alloc(tx_vpn,
										f_addr_family,rslv_proto_addr,nhc_if_addr,nhs_addr_p,mtu);
	if( tx_nhrp_mesg == NULL ){
		err = -ENOMEM;
		RHP_BUG("%d",err);
		goto error;
	}


	err = tx_nhrp_mesg->serialize(tx_nhrp_mesg,tx_vpn,0,&tx_pkt);
	if( err ){

		RHP_BUG("%d",err);
		goto error;

	}else{

		tx_nhrp_mesg->tx_pkt_ref = rhp_pkt_hold_ref(tx_pkt);

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,tx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_TX_RESOLUTION_REQ,"VB",tx_vpn,tx_nhrp_mesg);

		rhp_pkt_unhold(tx_pkt);
	}

	RHP_UNLOCK(&(v_ifc->lock));
	RHP_UNLOCK(&(tx_rlm->lock));

	rhp_realm_hold(tx_rlm); // (*zz*)

	RHP_UNLOCK(&(tx_vpn->lock));



	//
	// All errors are ignored from here.
	//

	RHP_LOCK(&rhp_nhrp_lock);
	{
		u32 tx_request_id;
		rhp_ip_addr src_proto_addr, src_nbma_addr;
		rhp_nhrp_req_session* nhrp_sess;

		nhrp_sess =  _rhp_nhrp_req_sess_get(
				tx_rlm->id,
				RHP_PROTO_NHRP_PKT_RESOLUTION_REQ,
				rslv_proto_addr->addr_family,rslv_proto_addr->addr.raw);

		if( nhrp_sess == NULL ){

			tx_pkt = RHP_PKT_REF(tx_nhrp_mesg->tx_pkt_ref);

			tx_nhrp_mesg->m.mandatory->get_src_protocol_addr(tx_nhrp_mesg,&src_proto_addr);
			tx_nhrp_mesg->m.mandatory->get_src_nbma_addr(tx_nhrp_mesg,&src_nbma_addr);

			tx_request_id = tx_nhrp_mesg->m.mandatory->get_request_id(tx_nhrp_mesg);

			err = _rhp_nhrp_exec_request_session(
							tx_rlm->id,
							vpn_uid,
							tx_request_id,
							RHP_PROTO_NHRP_PKT_RESOLUTION_REQ,
							rslv_proto_addr->addr_family,rslv_proto_addr->addr.raw,
							src_nbma_addr.addr_family,src_nbma_addr.addr.raw,
							tx_pkt,NULL);
			if( err ){
				RHP_BUG("%d",err); // Error ignored.
			}
		}
	}
	RHP_UNLOCK(&rhp_nhrp_lock);


	{
		rhp_packet* tx_pkt_d;

		tx_pkt = RHP_PKT_REF(tx_nhrp_mesg->tx_pkt_ref);

		tx_pkt_d = rhp_pkt_dup(tx_pkt);
		if( tx_pkt_d ){

			// tx_vpn->lock and tx_rlm->lock will be acquired in rhp_gre_send_access_point().
			rhp_gre_send_access_point(tx_rlm,tx_pkt_d);
			rhp_pkt_unhold(tx_pkt_d);

		}else{

			// Retry later in timer handler.
			RHP_BUG("");
		}

		rhp_nhrp_mesg_unhold(tx_nhrp_mesg);
		tx_nhrp_mesg = NULL;
	}

	rhp_realm_unhold(tx_rlm); // (*zz*)


	RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REQ_RTRN,"xxxd",tx_vpn,tx_rlm,v_ifc,n);
	return 0;


error:

	if( v_ifc ){
		RHP_UNLOCK(&(v_ifc->lock));
	}
	if( tx_rlm ){
		RHP_UNLOCK(&(tx_rlm->lock));
	}

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,tx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_TX_RESOLUTION_REQ,"VBE",tx_vpn,tx_nhrp_mesg,err);

	RHP_UNLOCK(&(tx_vpn->lock));

	if( tx_nhrp_mesg ){

		rhp_nhrp_mesg_unhold(tx_nhrp_mesg);
	}

	RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REQ_ERR,"xxxE",tx_vpn,tx_rlm,v_ifc,err);
	return err;
}

static void _rhp_nhrp_tx_resolution_req_task(int worker_index,void *ctx)
{
	int err = -EINVAL;
	rhp_nhrp_mesg* rx_nhrp_mesg_trf_ind = (rhp_nhrp_mesg*)ctx;
	rhp_vpn_ref* tx_vpn_ref = rx_nhrp_mesg_trf_ind->tx_vpn_ref;
	rhp_vpn* tx_vpn = RHP_VPN_REF(tx_vpn_ref);
	rhp_ip_addr rslv_proto_addr, org_src_addr;

	RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REQ_TASK,"dxxx",worker_index,rx_nhrp_mesg_trf_ind,tx_vpn_ref,tx_vpn);

	rx_nhrp_mesg_trf_ind->tx_vpn_ref = NULL;

	memset(&rslv_proto_addr,0,sizeof(rhp_ip_addr));
	memset(&org_src_addr,0,sizeof(rhp_ip_addr));

	//
	// TODO: rslv_proto_addr should be gotten from Destination Protocol
	//       Address (Traffic Indication mesg's Mandatory header)?
	//
	err = rx_nhrp_mesg_trf_ind->m.traffic->get_org_mesg_addrs(rx_nhrp_mesg_trf_ind,&org_src_addr,&rslv_proto_addr);
	if( err ){
		goto error;
	}

	err = _rhp_nhrp_rx_valid_addr(&rslv_proto_addr);
	if( err ){
		RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REQ_TASK_INVALID_RSLV_ADDR,"xx",rx_nhrp_mesg_trf_ind,tx_vpn);
		goto error;
	}

	err = _rhp_nhrp_rx_valid_addr(&org_src_addr);
	if( err ){
		RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REQ_TASK_INVALID_ORG_SRC_ADDR,"xx",rx_nhrp_mesg_trf_ind,tx_vpn);
		goto error;
	}

	if( (rslv_proto_addr.addr_family == AF_INET &&
			 rhp_ifc_is_my_ip_v4(rslv_proto_addr.addr.v4)) ||
			(rslv_proto_addr.addr_family == AF_INET6 &&
			 rhp_ifc_is_my_ip_v6(rslv_proto_addr.addr.v6)) ){
		RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REQ_TASK_INVALID_RSLV_ADDR_MY_ADDR,"xx",rx_nhrp_mesg_trf_ind,tx_vpn);
		err = -EINVAL;
		goto error;
	}


	RHP_LOCK(&(tx_vpn->lock));
	{
		rhp_vpn_realm* rlm = tx_vpn->rlm;
	  rhp_ifc_entry* v_ifc;
		rhp_ip_addr local_addr_v4;

		memset(&local_addr_v4,0,sizeof(rhp_ip_addr));


		if( !_rhp_atomic_read(&(tx_vpn->is_active)) ){
			err = -EINVAL;
			RHP_UNLOCK(&(tx_vpn->lock));
			goto error;
		}


		RHP_LOCK(&(rlm->lock));

		v_ifc = rlm->internal_ifc->ifc;
		if( v_ifc == NULL ){
			RHP_UNLOCK(&(rlm->lock));
			RHP_UNLOCK(&(tx_vpn->lock));
			RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REQ_TASK_NO_V_IFC,"xxx",rx_nhrp_mesg_trf_ind,tx_vpn,rlm);
			goto error;
		}

		if( rslv_proto_addr.addr_family == AF_INET ){

			rhp_ifc_addr* if_addr;

			RHP_LOCK(&(v_ifc->lock));

			if_addr = _rhp_nhrp_get_internal_addr(v_ifc,AF_INET);
			if( if_addr ){
				memcpy(&local_addr_v4,&(if_addr->addr),sizeof(rhp_ip_addr));
			}

			RHP_UNLOCK(&(v_ifc->lock));
		}

		RHP_UNLOCK(&(rlm->lock));


		if( rslv_proto_addr.addr_family == AF_INET ){

			err = _rhp_nhrp_rx_valid_addr2_v4(&rslv_proto_addr,local_addr_v4.addr.v4,local_addr_v4.prefixlen);
			if( err ){
				RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REQ_TASK_INVALID_RSLV_ADDR_2,"xx",rx_nhrp_mesg_trf_ind,tx_vpn);
				RHP_UNLOCK(&(tx_vpn->lock));
				goto error;
			}

			err = _rhp_nhrp_rx_valid_addr2_v4(&org_src_addr,local_addr_v4.addr.v4,local_addr_v4.prefixlen);
			if( err ){
				RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REQ_TASK_INVALID_ORG_SRC_ADDR_2,"xx",rx_nhrp_mesg_trf_ind,tx_vpn);
				RHP_UNLOCK(&(tx_vpn->lock));
				goto error;
			}
		}
	}
	RHP_UNLOCK(&(tx_vpn->lock));


	//
	// Is the org_src_addr really behind this spoke gw/host?
	//
	{
		unsigned long out_realm_id = 0;

		if( rslv_proto_addr.addr_family == AF_INET && org_src_addr.addr_family == AF_INET ){

			u32 local_next_hop_addr = 0;

			err = rhp_ip_routing_slow_v4(
							rslv_proto_addr.addr.v4,org_src_addr.addr.v4,
							&local_next_hop_addr,&out_realm_id,NULL);

			if( err ){

				RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REQ_TASK_LOCAL_SRC_UNREACH_V4,"xx44uE",rx_nhrp_mesg_trf_ind,tx_vpn,rslv_proto_addr.addr.v4,org_src_addr.addr.v4,out_realm_id,err);
				goto error;

			}else if( out_realm_id != 0 ){ // Outbund traffic...

				if( !rhp_ifc_is_my_ip_v4(org_src_addr.addr.v4) ){

					RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REQ_TASK_LOCAL_SRC_UNREACH_NOT_MY_IP_V4,"xx44uE",rx_nhrp_mesg_trf_ind,tx_vpn,rslv_proto_addr.addr.v4,org_src_addr.addr.v4,out_realm_id,err);
					goto error;
				}
			}

		}else if( rslv_proto_addr.addr_family == AF_INET6 && org_src_addr.addr_family == AF_INET6 ){

			u8 local_next_hop_addr[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

			err = rhp_ip_routing_slow_v6(
							rslv_proto_addr.addr.v6,org_src_addr.addr.v6,
							local_next_hop_addr,&out_realm_id,NULL);

			if( err ){

				RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REQ_TASK_LOCAL_SRC_UNREACH_V6,"xx66uE",rx_nhrp_mesg_trf_ind,tx_vpn,rslv_proto_addr.addr.v6,org_src_addr.addr.v6,out_realm_id,err);
				goto error;

			}else if( out_realm_id != 0 ){

				if( !rhp_ifc_is_my_ip_v6(org_src_addr.addr.v6) ){

					RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REQ_TASK_LOCAL_SRC_UNREACH_NOT_MY_IP_V6,"xx66uE",rx_nhrp_mesg_trf_ind,tx_vpn,rslv_proto_addr.addr.v6,org_src_addr.addr.v6,out_realm_id,err);
					goto error;
				}
			}

		}else{
			err = -EINVAL;
			RHP_BUG("%d, %d",rslv_proto_addr.addr_family,org_src_addr.addr_family);
			goto error;
		}
	}


	err = rhp_nhrp_tx_resolution_req(tx_vpn,&rslv_proto_addr);
	if( err ){
		goto error;
	}


error:
	rhp_nhrp_mesg_unhold(rx_nhrp_mesg_trf_ind);
	rhp_vpn_unhold(tx_vpn_ref);

	RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REQ_TASK_RTRN,"xxxE",rx_nhrp_mesg_trf_ind,tx_vpn_ref,tx_vpn,err);
	return;
}

static int _rhp_nhrp_invoke_tx_resolution_req(rhp_nhrp_mesg* rx_nhrp_mesg_trf_ind,rhp_vpn* rx_vpn)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_NHRP_INVOKE_TX_RESOLUTION_REQ_TASK,"xxx",rx_nhrp_mesg_trf_ind,rx_vpn,RHP_PKT_REF(rx_nhrp_mesg_trf_ind->rx_pkt_ref));

	rx_nhrp_mesg_trf_ind->tx_vpn_ref = rhp_vpn_hold_ref(rx_vpn);
	rhp_nhrp_mesg_hold(rx_nhrp_mesg_trf_ind);

	err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_3,
					_rhp_nhrp_tx_resolution_req_task,rx_nhrp_mesg_trf_ind);

	if( err ){
		RHP_BUG("%d",err);
		rhp_nhrp_mesg_unhold(rx_nhrp_mesg_trf_ind);
		goto error;
	}

	RHP_TRC(0,RHPTRCID_NHRP_INVOKE_TX_RESOLUTION_REQ_TASK_RTRN,"xx",rx_nhrp_mesg_trf_ind,rx_vpn);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_INVOKE_TX_RESOLUTION_REQ_TASK_ERR,"xxE",rx_nhrp_mesg_trf_ind,rx_vpn,err);
	return err;
}

static int _rhp_nhrp_q_resolution_req(rhp_vpn* vpn,rhp_nhrp_mesg* rx_nhrp_mesg)
{
	RHP_TRC(0,RHPTRCID_NHRP_Q_RESOLUTION_REQ,"xxxx",vpn,rx_nhrp_mesg,vpn->nhrp.pend_resolution_req_q.head,vpn->nhrp.pend_resolution_req_q.tail);
	if( vpn->nhrp.pend_resolution_req_q.head == NULL ){
		vpn->nhrp.pend_resolution_req_q.head = rx_nhrp_mesg;
	}else{
		vpn->nhrp.pend_resolution_req_q.tail->next = rx_nhrp_mesg;
	}
	vpn->nhrp.pend_resolution_req_q.tail = rx_nhrp_mesg;
	return 0;
}

static int _rhp_nhrp_tx_resolution_rep(rhp_vpn* tx_vpn,rhp_nhrp_mesg* rx_nhrp_mesg,
		rhp_packet** tx_pkt_r)
{
	int err = -EINVAL;
	rhp_nhrp_mesg* tx_nhrp_mesg = NULL;
	rhp_nhrp_cie* nhrp_cie;
	u16 m_flags;
	rhp_ip_addr dst_proto_addr, clt_proto_addr, clt_nbma_addr;
	int mtu, cie_prefix_len;
	rhp_packet* tx_pkt = NULL;

	RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REP,"xxx",tx_vpn,rx_nhrp_mesg,tx_pkt_r);
	rhp_ip_addr_dump("resolution_rep_dst_network",&(rx_nhrp_mesg->resolution_rep_dst_network));
	rhp_ip_addr_dump("resolution_rep_my_itnl_addr",&(rx_nhrp_mesg->resolution_rep_my_itnl_addr));


	memset(&dst_proto_addr,0,sizeof(rhp_ip_addr));
	memset(&clt_proto_addr,0,sizeof(rhp_ip_addr));
	memset(&clt_nbma_addr,0,sizeof(rhp_ip_addr));

	err = _rhp_nhrp_get_def_mtu(tx_vpn,&mtu);
	if( err ){
		goto error;
	}


	err = rx_nhrp_mesg->m.mandatory->get_dst_protocol_addr(rx_nhrp_mesg,&dst_proto_addr);
	if( err ){
		goto error;
	}


	tx_nhrp_mesg = rhp_nhrp_mesg_dup(rx_nhrp_mesg);
	if( tx_nhrp_mesg == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	tx_nhrp_mesg->f_packet_type = RHP_PROTO_NHRP_PKT_RESOLUTION_REP;

	tx_nhrp_mesg->m.mandatory->dont_update_request_id(tx_nhrp_mesg,1);

	m_flags = rx_nhrp_mesg->m.mandatory->get_flags(rx_nhrp_mesg);
	m_flags |= (RHP_PROTO_NHRP_RES_FLAG_A | RHP_PROTO_NHRP_RES_FLAG_D);
	if( dst_proto_addr.addr_family == AF_INET ){
		m_flags |= RHP_PROTO_NHRP_RES_FLAG_U;
	}



	nhrp_cie = tx_nhrp_mesg->m.mandatory->cie_list_head;
	if( nhrp_cie == NULL ){

		nhrp_cie = rhp_nhrp_cie_alloc(RHP_PROTO_NHRP_CIE_CODE_NONE);
		if( nhrp_cie == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		err = tx_nhrp_mesg->m.mandatory->add_cie(tx_nhrp_mesg,nhrp_cie);
		if( err ){
			rhp_nhrp_cie_free(nhrp_cie);
			goto error;
		}
	}

	err = nhrp_cie->set_mtu(nhrp_cie,
			(rhp_gcfg_nhrp_cie_mtu ? (u16)rhp_gcfg_nhrp_cie_mtu : (u16)mtu));
	if( err ){
		goto error;
	}

	err = nhrp_cie->set_hold_time(nhrp_cie,(u16)rhp_gcfg_nhrp_cache_hold_time);
	if( err ){
		goto error;
	}


	{
		if( !rhp_ip_addr_cmp_ip_only(&(rx_nhrp_mesg->resolution_rep_my_itnl_addr),&dst_proto_addr) ){

			if( dst_proto_addr.addr_family == AF_INET ){
				cie_prefix_len = 32;
			}else if( dst_proto_addr.addr_family == AF_INET6 ){
				cie_prefix_len = 128;
			}else{
				RHP_BUG("%d",dst_proto_addr.addr_family);
				err = -EINVAL;
				goto error;
			}

		}else if( rhp_ip_same_subnet(&(rx_nhrp_mesg->resolution_rep_dst_network),
					dst_proto_addr.addr_family,dst_proto_addr.addr.raw) ){

			cie_prefix_len = rx_nhrp_mesg->resolution_rep_dst_network.prefixlen;

		}else if( dst_proto_addr.addr_family == AF_INET ){

			cie_prefix_len = 32;

		}else if( dst_proto_addr.addr_family == AF_INET6 ){

			cie_prefix_len = 128;

		}else{
			err = -EINVAL;
			goto error;
		}

		err = nhrp_cie->set_prefix_len(nhrp_cie,cie_prefix_len);
		if( err ){
			goto error;
		}
	}


	err = nhrp_cie->set_clt_nbma_addr(nhrp_cie,
					tx_vpn->local.if_info.addr_family,tx_vpn->local.if_info.addr.raw);
	if( err ){
		goto error;
	}


	{
		rhp_vpn_realm* rlm = tx_vpn->rlm;
	  rhp_ifc_entry* v_ifc;
		rhp_ifc_addr *if_addr;

		if( !_rhp_atomic_read(&(tx_vpn->is_active)) ){
			err = -EINVAL;
			goto error;
		}


		RHP_LOCK(&(rlm->lock));

		v_ifc = rlm->internal_ifc->ifc;
		if( v_ifc == NULL ){
			RHP_UNLOCK(&(rlm->lock));
			RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REP_NO_V_IFC,"xxx",rx_nhrp_mesg,tx_vpn,rlm);
			goto error;
		}


		RHP_LOCK(&(v_ifc->lock));

		if_addr = _rhp_nhrp_get_internal_addr(v_ifc,dst_proto_addr.addr_family);
		if( if_addr == NULL ){

			RHP_UNLOCK(&(v_ifc->lock));
			RHP_UNLOCK(&(rlm->lock));

			err = -ENOENT;
			RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REP_NO_V_IF_ADDR,"xxx",rx_nhrp_mesg,tx_vpn,rlm);
			goto error;
		}

		memcpy(&clt_proto_addr,&(if_addr->addr),sizeof(rhp_ip_addr));

		err = nhrp_cie->set_clt_protocol_addr(nhrp_cie,
						if_addr->addr.addr_family,if_addr->addr.addr.raw);
		if( err ){

			RHP_UNLOCK(&(v_ifc->lock));
			RHP_UNLOCK(&(rlm->lock));

			goto error;
		}


		if( dst_proto_addr.addr_family == AF_INET6 ){

			if_addr = _rhp_nhrp_get_internal_v6_lladdr(v_ifc);
			if( if_addr ){

				rhp_nhrp_cie* nhrp_cie_lladdr = rhp_nhrp_cie_alloc(RHP_PROTO_NHRP_CIE_CODE_NONE);
				if( nhrp_cie == NULL ){
					RHP_BUG("");

					RHP_UNLOCK(&(v_ifc->lock));
					RHP_UNLOCK(&(rlm->lock));

					err = -ENOMEM;
					goto error;
				}

				err = tx_nhrp_mesg->m.mandatory->add_cie(tx_nhrp_mesg,nhrp_cie_lladdr);
				if( err ){

					rhp_nhrp_cie_free(nhrp_cie_lladdr);

					RHP_UNLOCK(&(v_ifc->lock));
					RHP_UNLOCK(&(rlm->lock));

					goto error;
				}

				err = nhrp_cie_lladdr->set_mtu(nhrp_cie_lladdr,
						(rhp_gcfg_nhrp_cie_mtu ? (u16)rhp_gcfg_nhrp_cie_mtu : (u16)mtu));
				if( err ){

					RHP_UNLOCK(&(v_ifc->lock));
					RHP_UNLOCK(&(rlm->lock));

					goto error;
				}

				err = nhrp_cie_lladdr->set_hold_time(nhrp_cie_lladdr,
								(u16)rhp_gcfg_nhrp_cache_hold_time);
				if( err ){

					RHP_UNLOCK(&(v_ifc->lock));
					RHP_UNLOCK(&(rlm->lock));

					goto error;
				}

				err = nhrp_cie_lladdr->set_prefix_len(nhrp_cie_lladdr,cie_prefix_len);
				if( err ){

					RHP_UNLOCK(&(v_ifc->lock));
					RHP_UNLOCK(&(rlm->lock));

					goto error;
				}

				err = nhrp_cie_lladdr->set_clt_nbma_addr(nhrp_cie_lladdr,
								tx_vpn->local.if_info.addr_family,tx_vpn->local.if_info.addr.raw);
				if( err ){

					RHP_UNLOCK(&(v_ifc->lock));
					RHP_UNLOCK(&(rlm->lock));

					goto error;
				}

				err = nhrp_cie_lladdr->set_clt_protocol_addr(nhrp_cie_lladdr,
								if_addr->addr.addr_family,if_addr->addr.addr.raw);
				if( err ){

					RHP_UNLOCK(&(v_ifc->lock));
					RHP_UNLOCK(&(rlm->lock));

					goto error;
				}
			}
			rhp_ip_addr_dump("if_addr_ll",&(if_addr->addr));


		}else{

			m_flags |= RHP_PROTO_NHRP_RES_FLAG_U;
		}

		RHP_UNLOCK(&(v_ifc->lock));

		RHP_UNLOCK(&(rlm->lock));
	}


	err = _rhp_nhrp_tx_rep_set_responder_ext(tx_nhrp_mesg,tx_vpn,&clt_proto_addr,mtu);
	if( err ){
		goto error;
	}


#ifdef RHP_DBG_NHRP_MESG_LOOP_TEST_2
	{
		rhp_nhrp_ext* nhrp_ext
			= tx_nhrp_mesg->get_extension(tx_nhrp_mesg,RHP_PROTO_NHRP_EXT_TYPE_REVERSE_TRANSIT_NHS_RECORD);
		if( nhrp_ext == NULL ){
			err = -EINVAL;
			goto error;
		}

		{
			rhp_ip_addr test_clt_proto_addr, test_clt_nbma_addr;

			nhrp_cie = rhp_nhrp_cie_alloc(RHP_PROTO_NHRP_CIE_CODE_NONE);
			if( nhrp_cie == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			memset(&test_clt_proto_addr,0,sizeof(rhp_ip_addr));
			memset(&test_clt_nbma_addr,0,sizeof(rhp_ip_addr));

			test_clt_proto_addr.addr_family = AF_INET;
			test_clt_proto_addr.addr.v4 = htonl(0xC0A8DC0A);

			test_clt_nbma_addr.addr_family = AF_INET;
			test_clt_nbma_addr.addr.v4 = htonl(0xC0A80064);

			err = nhrp_ext->add_cie(nhrp_ext,nhrp_cie);
			if( err ){
				rhp_nhrp_cie_free(nhrp_cie);
				goto error;
			}

			err = nhrp_cie->set_mtu(nhrp_cie,0);
			if( err ){
				goto error;
			}

			err = nhrp_cie->set_hold_time(nhrp_cie,(u16)rhp_gcfg_nhrp_cache_hold_time);
			if( err ){
				goto error;
			}

			err = nhrp_cie->set_prefix_len(nhrp_cie,0);
			if( err ){
				goto error;
			}

			err = nhrp_cie->set_clt_protocol_addr(nhrp_cie,
					test_clt_proto_addr.addr_family,test_clt_proto_addr.addr.raw);
			if( err ){
				goto error;
			}

			err = nhrp_cie->set_clt_nbma_addr(nhrp_cie,
					test_clt_nbma_addr.addr_family,test_clt_nbma_addr.addr.raw);
			if( err ){
				goto error;
			}
		}
	}
#endif // RHP_DBG_NHRP_MESG_LOOP_TEST_2


	{
		//
		// Cisco's NAT extension:
		//

		rhp_nhrp_addr_map* nhc_addr_map;
		rhp_ip_addr nat_nbma_addr;

		memset(&nat_nbma_addr,0,sizeof(rhp_ip_addr));

		nhc_addr_map = tx_vpn->nhrp.nhc_addr_maps_head;
		while( nhc_addr_map ){

			if( !rhp_ip_addr_cmp_value(&clt_proto_addr,
						(nhc_addr_map->proto_addr_family == AF_INET ? 4 : 16),
						nhc_addr_map->proto_addr.raw) ){

				nat_nbma_addr.addr_family = nhc_addr_map->nat_nbma_addr_family;
				memcpy(nat_nbma_addr.addr.raw,nhc_addr_map->nat_nbma_addr.raw,16);

				break;
			}

			nhc_addr_map = nhc_addr_map->next;
		}

		err = _rhp_nhrp_tx_rep_set_nat_ext(tx_nhrp_mesg,
						&nat_nbma_addr,&clt_proto_addr,mtu);
		if( err ){
			goto error;
		}
	}


	err = tx_nhrp_mesg->m.mandatory->set_flags(tx_nhrp_mesg,m_flags);
	if( err ){
		goto error;
	}


	err = tx_nhrp_mesg->serialize(tx_nhrp_mesg,tx_vpn,0,&tx_pkt);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,tx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_TX_RESOLUTION_REP,"VBB",tx_vpn,rx_nhrp_mesg,tx_nhrp_mesg);

	rhp_nhrp_mesg_unhold(tx_nhrp_mesg);


	*tx_pkt_r = tx_pkt;

	RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REP_RTRN,"xxx",tx_vpn,rx_nhrp_mesg,*tx_pkt_r);
	return 0;

error:

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,tx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_TX_RESOLUTION_REP_ERR,"VBBE",tx_vpn,rx_nhrp_mesg,tx_nhrp_mesg,err);

	if( tx_nhrp_mesg ){
		rhp_nhrp_mesg_unhold(tx_nhrp_mesg);
	}

	RHP_TRC(0,RHPTRCID_NHRP_TX_RESOLUTION_REP_ERR,"xxE",tx_vpn,rx_nhrp_mesg,err);
	return err;
}


static int _rhp_nhrp_rx_resolution_req_peer_addrs(rhp_nhrp_mesg* rx_nhrp_mesg,
		rhp_ip_addr* peer_nbma_addr_r,rhp_ip_addr* peer_proto_addr_r)
{
	int err = -EINVAL;
	rhp_ip_addr src_nbma_addr, src_proto_addr;
	u16 rx_m_flags = rx_nhrp_mesg->m.mandatory->get_flags(rx_nhrp_mesg);

	memset(&src_nbma_addr,0,sizeof(rhp_ip_addr));
	memset(&src_proto_addr,0,sizeof(rhp_ip_addr));


	if( RHP_PROTO_NHRP_RES_FLAG_CISCO_NAT_EXT(rx_m_flags) ){

		rhp_nhrp_ext* nhrp_ext_cisco_nat
			= rx_nhrp_mesg->get_extension(rx_nhrp_mesg,RHP_PROTO_NHRP_EXT_TYPE_NAT_ADDRESS);

		if( nhrp_ext_cisco_nat ){

			rhp_nhrp_cie* nhrp_ext_cisco_nat_cie = nhrp_ext_cisco_nat->cie_list_head;
			if( nhrp_ext_cisco_nat_cie ){

				nhrp_ext_cisco_nat_cie->get_clt_nbma_addr(nhrp_ext_cisco_nat_cie,
								&src_nbma_addr);
			}
		}
	}

	if( rhp_ip_addr_null(&src_nbma_addr) ){

		err = rx_nhrp_mesg->m.mandatory->get_src_nbma_addr(rx_nhrp_mesg,&src_nbma_addr);
		if( err ){
			goto error;
		}
	}

	if( peer_proto_addr_r ){

		err = rx_nhrp_mesg->m.mandatory->get_src_protocol_addr(rx_nhrp_mesg,&src_proto_addr);
		if( err ){
			goto error;
		}
	}

	if( !rhp_ip_addr_null(&src_nbma_addr) &&
			(peer_proto_addr_r && !rhp_ip_addr_null(&src_proto_addr)) ){


		memcpy(peer_nbma_addr_r,&src_nbma_addr,sizeof(rhp_ip_addr));

		if( peer_proto_addr_r ){
			memcpy(peer_proto_addr_r,&src_proto_addr,sizeof(rhp_ip_addr));
		}


		RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_PEER_NBMA_ADDR,"x",rx_nhrp_mesg);
		rhp_ip_addr_dump("peer_nbma_addr_r",peer_nbma_addr_r);
		rhp_ip_addr_dump("peer_proto_addr_r",peer_proto_addr_r);

		return 0;
	}
	err = -ENOENT;

error:
	RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_PEER_NBMA_ADDR_NO_ENT,"x",rx_nhrp_mesg);
	return err;
}

static int _rhp_nhrp_rx_resolution_rep_peer_nbma_addr(rhp_nhrp_mesg* rx_nhrp_mesg,
		rhp_ip_addr* peer_nbma_addr_r)
{
	int err = -EINVAL;
	rhp_ip_addr src_nbma_addr;
	rhp_nhrp_cie* nhrp_cie;
	u16 rx_m_flags = rx_nhrp_mesg->m.mandatory->get_flags(rx_nhrp_mesg);

	memset(&src_nbma_addr,0,sizeof(rhp_ip_addr));

	if( RHP_PROTO_NHRP_RES_FLAG_CISCO_NAT_EXT(rx_m_flags) ){

		rhp_nhrp_ext* nhrp_ext_cisco_nat
			= rx_nhrp_mesg->get_extension(rx_nhrp_mesg,RHP_PROTO_NHRP_EXT_TYPE_NAT_ADDRESS);

		if( nhrp_ext_cisco_nat ){

			rhp_nhrp_cie* nhrp_ext_cisco_nat_cie = nhrp_ext_cisco_nat->cie_list_head;
			while( nhrp_ext_cisco_nat_cie ){

				rhp_ip_addr src_proto_addr;

				memset(&src_proto_addr,0,sizeof(rhp_ip_addr));

				nhrp_ext_cisco_nat_cie->get_clt_protocol_addr(nhrp_ext_cisco_nat_cie,&src_proto_addr);

				if( !((src_proto_addr.addr_family == AF_INET &&
						   rhp_ifc_is_my_ip_v4(src_proto_addr.addr.v4)) ||
						  (src_proto_addr.addr_family == AF_INET6 &&
						   rhp_ifc_is_my_ip_v6(src_proto_addr.addr.v6))) ){

					nhrp_ext_cisco_nat_cie->get_clt_nbma_addr(nhrp_ext_cisco_nat_cie,
								&src_nbma_addr);

					break;
				}

				nhrp_ext_cisco_nat_cie = nhrp_ext_cisco_nat_cie->next;
			}
		}
	}

	if( rhp_ip_addr_null(&src_nbma_addr) ){

		nhrp_cie = rx_nhrp_mesg->m.mandatory->cie_list_head;
		if( nhrp_cie ){

			err = nhrp_cie->get_clt_nbma_addr(nhrp_cie,&src_nbma_addr);
			if( err ){
				goto error;
			}
		}
	}

	if( !rhp_ip_addr_null(&src_nbma_addr) ){

		memcpy(peer_nbma_addr_r,&src_nbma_addr,sizeof(rhp_ip_addr));

		RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REP_PEER_NBMA_ADDR,"x",rx_nhrp_mesg);
		rhp_ip_addr_dump("peer_nbma_addr_r",peer_nbma_addr_r);
		return 0;
	}
	err = -ENOENT;

error:
	RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REP_PEER_NBMA_ADDR_NO_ENT,"x",rx_nhrp_mesg);
	return err;
}


struct _rhp_conn_shortcut_ratelimit_tmr_ctx {
	unsigned long rx_vpn_realm_id;
	rhp_ip_addr peer_nbma_addr;
};
typedef struct _rhp_conn_shortcut_ratelimit_tmr_ctx rhp_conn_shortcut_ratelimit_tmr_ctx;

static void _rhp_nhrp_connect_shortcut_vpn_ratelimit_timer(void *ctx)
{
	rhp_conn_shortcut_ratelimit_tmr_ctx* rl_ctx
		= (rhp_conn_shortcut_ratelimit_tmr_ctx*)ctx;

	rhp_vpn_connect_i_pending_clear(rl_ctx->rx_vpn_realm_id,
			NULL,&(rl_ctx->peer_nbma_addr));

	_rhp_free(rl_ctx);

	return;
}

static int _rhp_nhrp_connect_shortcut_vpn_start_ratelimit(
		unsigned long rx_vpn_realm_id,rhp_ip_addr* peer_nbma_addr)
{
	int err = -EINVAL;
	rhp_conn_shortcut_ratelimit_tmr_ctx* rl_ctx = NULL;

	rl_ctx
	= (rhp_conn_shortcut_ratelimit_tmr_ctx*)_rhp_malloc(sizeof(rhp_conn_shortcut_ratelimit_tmr_ctx));
	if( rl_ctx == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	memset(rl_ctx,0,sizeof(rhp_conn_shortcut_ratelimit_tmr_ctx));

	rl_ctx->rx_vpn_realm_id = rx_vpn_realm_id;
	memcpy(&(rl_ctx->peer_nbma_addr),peer_nbma_addr,sizeof(rhp_ip_addr));

	err = rhp_timer_oneshot(_rhp_nhrp_connect_shortcut_vpn_ratelimit_timer,
					rl_ctx,(time_t)rhp_gcfg_dmvpn_connect_shortcut_rate_limit);
	if( err ){
		goto error;
	}

	return 0;

error:
	if( rl_ctx ){
		_rhp_free(rl_ctx);
	}
	return err;
}

static int _rhp_nhrp_rx_resolution_req_handle_shortcut(rhp_nhrp_mesg* rx_nhrp_mesg,
		unsigned long rlm_id,u8 ikev1_init_mode,int dont_connect);

static void _rhp_nhrp_connect_shortcut_vpn_task(void* ctx)
{
	int err = -EINVAL;
	rhp_vpn_conn_args* conn_args = (rhp_vpn_conn_args*)ctx;
	int pending = 0;

	RHP_TRC(0,RHPTRCID_NHRP_CONNECT_SHORTCUT_VPN_TASK,"xuxbd",conn_args,conn_args->nhrp_rx_vpn_realm_id,conn_args->pend_nhrp_resolution_req,conn_args->ikev1_init_mode,rhp_gcfg_dmvpn_connect_shortcut_rate_limit);
	rhp_ip_addr_dump("conn_args->peer_addr",conn_args->peer_addr);


	if( rhp_vpn_connect_i_pending_put(conn_args->nhrp_rx_vpn_realm_id,NULL,conn_args->peer_addr) ){
		RHP_TRC(0,RHPTRCID_NHRP_CONNECT_SHORTCUT_VPN_TASK_CONN_ALREADY_STARTED,"x",conn_args);
		err = -EBUSY;
		goto error;
	}
	pending = 1;


	err = rhp_vpn_connect_i(conn_args->nhrp_rx_vpn_realm_id,conn_args,NULL,0);

	if( err == RHP_STATUS_IKESA_EXISTS &&
			conn_args->pend_nhrp_resolution_req ){

		err = _rhp_nhrp_rx_resolution_req_handle_shortcut(
							conn_args->pend_nhrp_resolution_req,conn_args->nhrp_rx_vpn_realm_id,
							conn_args->ikev1_init_mode,1);
		if( err ){
			goto error;
		}

	}else if( err ){
		goto error;
	}

	if( rhp_gcfg_dmvpn_connect_shortcut_rate_limit ){

		_rhp_nhrp_connect_shortcut_vpn_start_ratelimit(
				conn_args->nhrp_rx_vpn_realm_id,conn_args->peer_addr);
	}


	RHP_LOG_D(RHP_LOG_SRC_IKEV2,conn_args->nhrp_rx_vpn_realm_id,RHP_LOG_ID_NHRP_CONNECT_SHORTCUT,"AB",conn_args->peer_addr,conn_args->pend_nhrp_resolution_req);
	err = 0;

error:
	if( err == -EBUSY ){
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,conn_args->nhrp_rx_vpn_realm_id,RHP_LOG_ID_NHRP_CONNECT_SHORTCUT_PENDING,"ABE",conn_args->peer_addr,conn_args->pend_nhrp_resolution_req,err);
	}else if( err ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,conn_args->nhrp_rx_vpn_realm_id,RHP_LOG_ID_NHRP_CONNECT_SHORTCUT_ERR,"ABE",conn_args->peer_addr,conn_args->pend_nhrp_resolution_req,err);
	}
	if( conn_args->peer_addr ){

		if( err && pending ){
			rhp_vpn_connect_i_pending_clear(conn_args->nhrp_rx_vpn_realm_id,
					NULL,conn_args->peer_addr);
		}

		_rhp_free(conn_args->peer_addr);
	}
	if( conn_args->nhrp_peer_proto_addr ){
		_rhp_free(conn_args->nhrp_peer_proto_addr);
	}
	if( conn_args->pend_nhrp_resolution_req ){
		rhp_nhrp_mesg_unhold(conn_args->pend_nhrp_resolution_req);
	}
	_rhp_free(conn_args);

	RHP_TRC(0,RHPTRCID_NHRP_CONNECT_SHORTCUT_VPN_TASK_RTRN,"xE",conn_args,err);
	return;
}

static int _rhp_nhrp_connect_shortcut_vpn(unsigned long rlm_id,
		rhp_ip_addr* peer_nbma_addr,rhp_ip_addr* peer_proto_addr,
		u8 ikev1_init_mode,rhp_nhrp_mesg* rx_nhrp_mesg)
{
	int err = -EINVAL;
  u32 random_secs;
	rhp_vpn_conn_args* conn_args = (rhp_vpn_conn_args*)_rhp_malloc(sizeof(rhp_vpn_conn_args));
	u8 nhrp_pkt_type = (rx_nhrp_mesg ? rx_nhrp_mesg->get_packet_type(rx_nhrp_mesg) : 0);

	if( conn_args == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	memset(conn_args,0,sizeof(rhp_vpn_conn_args));

	RHP_TRC(0,RHPTRCID_NHRP_CONNECT_SHORTCUT_VPN,"uxxxxbb",rlm_id,peer_nbma_addr,peer_proto_addr,rx_nhrp_mesg,conn_args,nhrp_pkt_type,ikev1_init_mode);
	rhp_ip_addr_dump("peer_nbma_addr",peer_nbma_addr);
	rhp_ip_addr_dump("peer_proto_addr",peer_proto_addr);

	conn_args->peer_addr = (rhp_ip_addr*)_rhp_malloc(sizeof(rhp_ip_addr));
	if( conn_args->peer_addr == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	memcpy(conn_args->peer_addr,peer_nbma_addr,sizeof(rhp_ip_addr));

	conn_args->nhrp_peer_proto_addr = (rhp_ip_addr*)_rhp_malloc(sizeof(rhp_ip_addr));
	if( conn_args->nhrp_peer_proto_addr == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	memcpy(conn_args->nhrp_peer_proto_addr,peer_proto_addr,sizeof(rhp_ip_addr));


	if( rx_nhrp_mesg &&
			nhrp_pkt_type == RHP_PROTO_NHRP_PKT_RESOLUTION_REQ ){

		conn_args->pend_nhrp_resolution_req = rx_nhrp_mesg;
		rhp_nhrp_mesg_hold(rx_nhrp_mesg);
	}

	conn_args->nhrp_rx_vpn_realm_id = rlm_id;

	conn_args->ikev1_init_mode = ikev1_init_mode;

	conn_args->mobike_disabled = 1;
	conn_args->nhrp_dmvpn_shortcut = 1;
	conn_args->auth_tkt_conn_type = RHP_AUTH_TKT_CONN_TYPE_SPOKE2SPOKE;

	if( rhp_gcfg_dmvpn_connect_shortcut_wait_random_range ){

		if( rhp_random_bytes((u8*)&random_secs,sizeof(random_secs)) ){
			RHP_BUG("");
			return 0;
		}

		random_secs
			= random_secs % rhp_gcfg_dmvpn_connect_shortcut_wait_random_range;

	}else{

		random_secs = 0;
	}

	err = rhp_timer_oneshot(_rhp_nhrp_connect_shortcut_vpn_task,conn_args,
					(time_t)random_secs);
	if( err ){
		goto error;
	}

	RHP_TRC(0,RHPTRCID_NHRP_CONNECT_SHORTCUT_VPN_RTRN,"uxx",rlm_id,rx_nhrp_mesg,conn_args);
	return 0;

error:
	if( conn_args ){

		if( conn_args->peer_addr ){
			_rhp_free(conn_args->peer_addr);
		}
		if( conn_args->nhrp_peer_proto_addr ){
			_rhp_free(conn_args->nhrp_peer_proto_addr);
		}
		if( conn_args->pend_nhrp_resolution_req ){
			rhp_nhrp_mesg_unhold(conn_args->pend_nhrp_resolution_req);
		}
		_rhp_free(conn_args);
	}
	RHP_TRC(0,RHPTRCID_NHRP_CONNECT_SHORTCUT_VPN_ERR,"uxxE",rlm_id,rx_nhrp_mesg,conn_args,err);
	return err;
}

//
// Tasks to handle a shortcut VPN connection to the same NBMA dest addr
// are dispatched to the same worker thread (First In, First Out).
// This avoids simultaneously connecting VPN with the dest address and
// sending NHRP resolution reply in unexpected-order to the dest address
// (i.e. the VPN connection's remote peer).
//
static int _rhp_nhrp_rx_resolution_req_handle_shortcut(rhp_nhrp_mesg* rx_nhrp_mesg,
		unsigned long rlm_id,u8 ikev1_init_mode,int dont_connect)
{
	int err = -EINVAL;
	rhp_ip_addr peer_nbma_addr, peer_proto_addr;
	rhp_vpn_ref* tx_vpn_ref = NULL;
	rhp_vpn* tx_vpn = NULL;
	int do_connect = 0;
	rhp_packet* tx_pkt = NULL;
	rhp_ikesa* cur_ikesa = NULL;

	RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_HANDLE_SHORTCUT,"xudb",rx_nhrp_mesg,rlm_id,dont_connect,ikev1_init_mode);

	memset(&peer_nbma_addr,0,sizeof(rhp_ip_addr));
	memset(&peer_proto_addr,0,sizeof(rhp_ip_addr));


	err = _rhp_nhrp_rx_resolution_req_peer_addrs(rx_nhrp_mesg,&peer_nbma_addr,&peer_proto_addr);
	if( err ){
		RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_HANDLE_SHORTCUT_PEER_ADDR_ERR,"xuE",rx_nhrp_mesg,rlm_id,err);
		goto error;
	}

	//
	// [TODO] Multiple shortcut-responders behind a NAT device
	//        located in their site. They may share a common NATed
	//        NBMA pub address. To distinguish them, this node needs
	//        some extra info like internal NRHP protocol addresses of
	//        the NATed remote responders. But, NHRP cache created by
	//        NHRP RESOLUTION Req/Resp is not reliable because of
	//        a variable holding-time and a exchange timing.
	//
	{
		rhp_vpn_list* vpn_lst_head = NULL;

		err = rhp_vpn_get_by_peer_addr_impl(rlm_id,
						peer_nbma_addr.addr_family,peer_nbma_addr.addr.raw,&vpn_lst_head);
		if( !err ){

			tx_vpn_ref = rhp_vpn_hold_ref(RHP_VPN_REF(vpn_lst_head->vpn_ref));
			tx_vpn = RHP_VPN_REF(tx_vpn_ref);

			rhp_vpn_list_free(vpn_lst_head);

			RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_HANDLE_SHORTCUT_TX_VPN_FOUND,"xuxx",rx_nhrp_mesg,rlm_id,tx_vpn_ref,tx_vpn);
		}
	}

	if( tx_vpn ){

		RHP_LOCK(&(tx_vpn->lock));

		cur_ikesa = tx_vpn->ikesa_list_head;
		while( cur_ikesa ){

			RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_HANDLE_SHORTCUT_CUR_IKESA,"xuxxLd",rx_nhrp_mesg,rlm_id,tx_vpn,cur_ikesa,"IKESA_STAT",cur_ikesa->state);

			if( cur_ikesa->state == RHP_IKESA_STAT_ESTABLISHED ||	// IKEv2
					cur_ikesa->state == RHP_IKESA_STAT_REKEYING 	 ||	// IKEv2
					cur_ikesa->state == RHP_IKESA_STAT_V1_ESTABLISHED ||
					cur_ikesa->state == RHP_IKESA_STAT_V1_REKEYING ){

				err = _rhp_nhrp_tx_resolution_rep(tx_vpn,rx_nhrp_mesg,&tx_pkt);
				if( err ){
					RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_HANDLE_SHORTCUT_IKESA_ESTAB_TX_RSLV_REP_ERR,"xuxE",rx_nhrp_mesg,rlm_id,tx_vpn,err);
					RHP_UNLOCK(&(tx_vpn->lock));
					goto error;
				}

				RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_HANDLE_SHORTCUT_IKESA_ESTAB_FOUND,"xuxxLd",rx_nhrp_mesg,rlm_id,tx_vpn,cur_ikesa,"IKESA_STAT",cur_ikesa->state);

				break;

			}else if( cur_ikesa->state == RHP_IKESA_STAT_I_IKE_SA_INIT_SENT 	|| // IKEv2
								cur_ikesa->state == RHP_IKESA_STAT_I_AUTH_SENT 					|| // IKEv2
								cur_ikesa->state == RHP_IKESA_STAT_I_AUTH_EAP_SENT 			|| // IKEv2
								cur_ikesa->state == RHP_IKESA_STAT_R_IKE_SA_INIT_SENT 	|| // IKEv2
								cur_ikesa->state == RHP_IKESA_STAT_V1_MAIN_1ST_SENT_I 	||
								cur_ikesa->state == RHP_IKESA_STAT_V1_MAIN_3RD_SENT_I 	||
								cur_ikesa->state == RHP_IKESA_STAT_V1_MAIN_5TH_SENT_I 	||
								cur_ikesa->state == RHP_IKESA_STAT_V1_MAIN_2ND_SENT_R 	||
								cur_ikesa->state == RHP_IKESA_STAT_V1_MAIN_4TH_SENT_R 	||
								cur_ikesa->state == RHP_IKESA_STAT_V1_AGG_1ST_SENT_I 		||
								cur_ikesa->state == RHP_IKESA_STAT_V1_AGG_WAIT_COMMIT_I ||
								cur_ikesa->state == RHP_IKESA_STAT_V1_AGG_2ND_SENT_R ){

				err = _rhp_nhrp_q_resolution_req(tx_vpn,rx_nhrp_mesg);
				if( err ){
					RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_HANDLE_SHORTCUT_IKESA_NEGOTIATING_Q_RSLV_REQ_ERR,"xuxE",rx_nhrp_mesg,rlm_id,tx_vpn,err);
					RHP_UNLOCK(&(tx_vpn->lock));
					goto error;
				}

				RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_HANDLE_SHORTCUT_IKESA_NEGOTIATING_FOUND,"xuxxLd",rx_nhrp_mesg,rlm_id,tx_vpn,cur_ikesa,"IKESA_STAT",cur_ikesa->state);

				break;
			}

			cur_ikesa = cur_ikesa->next_vpn_list;
		}

		if( cur_ikesa == NULL ){

			RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_HANDLE_SHORTCUT_NO_CUR_IKESA_FOUND,"xux",rx_nhrp_mesg,rlm_id,tx_vpn);

			do_connect = 1;
		}

		RHP_UNLOCK(&(tx_vpn->lock));

	}else{

		RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_HANDLE_SHORTCUT_NO_CUR_VPN_FOUND,"xu",rx_nhrp_mesg,rlm_id);

		do_connect = 1;
	}


	if( !dont_connect && do_connect ){

		err = _rhp_nhrp_connect_shortcut_vpn(rlm_id,
						&peer_nbma_addr,&peer_proto_addr,ikev1_init_mode,rx_nhrp_mesg);
		if( err ){
			RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_HANDLE_SHORTCUT_CONN_VPN_ERR,"xuxxE",rx_nhrp_mesg,rlm_id,tx_vpn,cur_ikesa,err);
			goto error;
		}

	}else{

		RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_HANDLE_SHORTCUT_CONN_VPN_SKIPPED,"xuxxdd",rx_nhrp_mesg,rlm_id,tx_vpn,cur_ikesa,dont_connect,do_connect);
	}

	if( tx_pkt ){

		if( tx_vpn ){

			if( !rhp_gcfg_dmvpn_tx_resolution_rep_via_nhs ){

				rhp_gre_send(tx_vpn,tx_pkt);

			}else{

				// For Debug...

				rhp_vpn_realm* tx_rlm = rhp_realm_get(tx_vpn->vpn_realm_id);
				if( tx_rlm == NULL ){

					RHP_BUG("%d",tx_vpn->vpn_realm_id);

				}else{

					rhp_gre_send_access_point(tx_rlm,tx_pkt);
					rhp_realm_unhold(tx_rlm);
				}
			}
		}

		rhp_pkt_unhold(tx_pkt);

	}else{

		RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_HANDLE_SHORTCUT_NO_TX_PKT_ALLOCATED_ERR,"xuxx",rx_nhrp_mesg,rlm_id,tx_vpn,cur_ikesa);
	}

	if( tx_vpn_ref ){
		rhp_vpn_unhold(tx_vpn_ref);
	}

	RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_HANDLE_SHORTCUT_RTRN,"xuxLddxxx",rx_nhrp_mesg,rlm_id,cur_ikesa,"IKESA_STAT",(cur_ikesa ? cur_ikesa->state : 0),do_connect,tx_pkt,tx_vpn,tx_vpn_ref);
	return 0;

error:
	if( tx_vpn_ref ){
		rhp_vpn_unhold(tx_vpn_ref);
	}

	RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_HANDLE_SHORTCUT_ERR,"xxuE",rx_nhrp_mesg,tx_vpn,rlm_id,err);
	return err;
}

static int _rhp_nhrp_fwd_resolution_req(rhp_nhrp_mesg* rx_nhrp_mesg,rhp_vpn* rx_vpn,
		unsigned long out_realm_id,rhp_ip_addr* next_hop_proto_addr,rhp_ip_addr* my_proto_addr)
{
	int err = -EINVAL;
	rhp_vpn* fwd_vpn = NULL;
	rhp_nhrp_mesg* fwd_nhrp_mesg = NULL;
	rhp_nhrp_cie* nhrp_cie;
	rhp_nhrp_ext *fwd_trans_nhs_ext = NULL, *cisco_nat_ext = NULL;
	rhp_packet* fwd_pkt = NULL;
	rhp_ip_addr rx_src_nbma_addr, rx_src_proto_addr, rx_nbma_addr;

	RHP_TRC(0,RHPTRCID_NHRP_FWD_RESOLUTION_REQ,"xxuxx",rx_nhrp_mesg,rx_vpn,out_realm_id,next_hop_proto_addr,my_proto_addr);
	rhp_ip_addr_dump("next_hop_proto_addr",next_hop_proto_addr);
	rhp_ip_addr_dump("my_proto_addr",my_proto_addr);

	memset(&rx_src_nbma_addr,0,sizeof(rhp_ip_addr));
	memset(&rx_src_proto_addr,0,sizeof(rhp_ip_addr));
	memset(&rx_nbma_addr,0,sizeof(rhp_ip_addr));

	rx_nhrp_mesg->m.mandatory->get_src_nbma_addr(rx_nhrp_mesg,&rx_src_nbma_addr);
	rx_nhrp_mesg->m.mandatory->get_src_protocol_addr(rx_nhrp_mesg,&rx_src_proto_addr);

	rx_nhrp_mesg->get_rx_nbma_src_addr(rx_nhrp_mesg,&rx_nbma_addr);


	fwd_vpn = rhp_nhrp_cache_get_vpn(
							next_hop_proto_addr->addr_family,next_hop_proto_addr->addr.raw,
							out_realm_id);

	if( fwd_vpn == NULL ){

		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_NHRP_FWD_RESOLUTION_REQ_NEXT_HOP_NOT_VIA_VPN,"xxx",rx_nhrp_mesg,rx_vpn,fwd_vpn);
		goto error;

	}else if( fwd_vpn == rx_vpn ){

		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_NHRP_FWD_RESOLUTION_REQ_NEXT_HOP_VIA_SAME_RX_VPN,"xxx",rx_nhrp_mesg,rx_vpn,fwd_vpn);
		goto error;
	}


	RHP_LOCK(&(fwd_vpn->lock));

	if( fwd_vpn->internal_net_info.encap_mode_c != RHP_VPN_ENCAP_GRE ||
			fwd_vpn->nhrp.role == RHP_NHRP_SERVICE_NONE ||
			!fwd_vpn->nhrp.dmvpn_enabled ){

		RHP_UNLOCK(&(fwd_vpn->lock));

		err = RHP_STATUS_NO_GRE_ENCAP;
		RHP_TRC(0,RHPTRCID_NHRP_FWD_RESOLUTION_REQ_NEXT_HOP_VIA_GRE_ENCAP_VPN,"xxxddd",rx_nhrp_mesg,rx_vpn,fwd_vpn,fwd_vpn->internal_net_info.encap_mode_c,fwd_vpn->nhrp.role,fwd_vpn->nhrp.dmvpn_enabled);

		goto error;
	}

	RHP_UNLOCK(&(fwd_vpn->lock));



	fwd_nhrp_mesg = rhp_nhrp_mesg_dup(rx_nhrp_mesg);
	if( fwd_nhrp_mesg == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	fwd_nhrp_mesg->dec_hop_count(fwd_nhrp_mesg);

	fwd_nhrp_mesg->m.mandatory->dont_update_request_id(fwd_nhrp_mesg,1);



	if( !rhp_ip_addr_null(&rx_src_nbma_addr) &&
			!rhp_ip_addr_null(&rx_src_proto_addr) &&
			rhp_ip_addr_cmp_ip_only(&rx_src_nbma_addr,&rx_nbma_addr) ){

		rhp_nhrp_cie* cisco_nat_cie = NULL;
		u16 rx_m_flags = fwd_nhrp_mesg->m.mandatory->get_flags(fwd_nhrp_mesg);

		RHP_LOCK(&(rx_vpn->lock));

		if( !rhp_ip_addr_cmp_ip_only(&(rx_vpn->peer_addr),&rx_nbma_addr) ){

			cisco_nat_ext
				= fwd_nhrp_mesg->get_extension(fwd_nhrp_mesg,RHP_PROTO_NHRP_EXT_TYPE_NAT_ADDRESS);

			if( cisco_nat_ext == NULL ||
					cisco_nat_ext->cie_list_head == NULL ){

				if( cisco_nat_ext == NULL ){

					cisco_nat_ext = rhp_nhrp_ext_alloc(RHP_PROTO_NHRP_EXT_TYPE_NAT_ADDRESS,0);
					if( cisco_nat_ext == NULL ){

						RHP_BUG("");
						err = -ENOMEM;

						RHP_UNLOCK(&(rx_vpn->lock));

						goto error;
					}

					err = fwd_nhrp_mesg->add_extension(fwd_nhrp_mesg,cisco_nat_ext);
					if( err ){

						rhp_nhrp_ext_free(cisco_nat_ext);

						RHP_UNLOCK(&(rx_vpn->lock));

						goto error;
					}
				}

				cisco_nat_cie = rhp_nhrp_cie_alloc(RHP_PROTO_NHRP_CIE_CODE_SUCCESS);
				if( cisco_nat_cie == NULL ){

					err = -ENOMEM;
					RHP_BUG("");

					RHP_UNLOCK(&(rx_vpn->lock));

					goto error;
				}

				err = cisco_nat_ext->add_cie(cisco_nat_ext,cisco_nat_cie);
				if( err ){

					RHP_UNLOCK(&(rx_vpn->lock));

					goto error;
				}

				cisco_nat_cie->set_hold_time(cisco_nat_cie,0);

				cisco_nat_cie->set_mtu(cisco_nat_cie,rhp_gcfg_nhrp_cie_mtu);

				cisco_nat_cie->set_prefix_len(cisco_nat_cie,32);

				err = cisco_nat_cie->set_clt_nbma_addr(cisco_nat_cie,
								rx_nbma_addr.addr_family,rx_nbma_addr.addr.raw);
				if( err ){

					RHP_UNLOCK(&(rx_vpn->lock));

					goto error;
				}

				err = cisco_nat_cie->set_clt_protocol_addr(cisco_nat_cie,
								rx_src_proto_addr.addr_family,rx_src_proto_addr.addr.raw);
				if( err ){

					RHP_UNLOCK(&(rx_vpn->lock));

					goto error;
				}

				fwd_nhrp_mesg->m.mandatory->set_flags(fwd_nhrp_mesg,
						(rx_m_flags | RHP_PROTO_NHRP_FLAG_CISCO_NAT_EXT));
			}
		}

		RHP_UNLOCK(&(rx_vpn->lock));
	}



	RHP_LOCK(&(fwd_vpn->lock));

	{
		fwd_trans_nhs_ext
			= fwd_nhrp_mesg->get_extension(fwd_nhrp_mesg,RHP_PROTO_NHRP_EXT_TYPE_FORWARD_TRANSIT_NHS_RECORD);

		if( fwd_trans_nhs_ext == NULL ){

			RHP_UNLOCK(&(fwd_vpn->lock));

			err = RHP_STATUS_NHRP_NO_FWD_TRANSIT_NHS_RECORDS;
			goto error;
		}

		nhrp_cie = rhp_nhrp_cie_alloc(RHP_PROTO_NHRP_CIE_CODE_NONE);
		if( nhrp_cie == NULL ){

			RHP_UNLOCK(&(fwd_vpn->lock));

			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		err = fwd_trans_nhs_ext->add_cie(fwd_trans_nhs_ext,nhrp_cie);
		if( err ){

			rhp_nhrp_cie_free(nhrp_cie);

			RHP_UNLOCK(&(fwd_vpn->lock));
			goto error;
		}

		err = nhrp_cie->set_mtu(nhrp_cie,0);
		if( err ){
			RHP_UNLOCK(&(fwd_vpn->lock));
			goto error;
		}

		err = nhrp_cie->set_hold_time(nhrp_cie,(u16)rhp_gcfg_nhrp_cache_hold_time);
		if( err ){
			RHP_UNLOCK(&(fwd_vpn->lock));
			goto error;
		}

		err = nhrp_cie->set_prefix_len(nhrp_cie,0);
		if( err ){
			RHP_UNLOCK(&(fwd_vpn->lock));
			goto error;
		}

		err = nhrp_cie->set_clt_protocol_addr(nhrp_cie,
						my_proto_addr->addr_family,my_proto_addr->addr.raw);
		if( err ){
			RHP_UNLOCK(&(fwd_vpn->lock));
			goto error;
		}

		err = nhrp_cie->set_clt_nbma_addr(nhrp_cie,
						rx_vpn->local.if_info.addr_family,rx_vpn->local.if_info.addr.raw);
		if( err ){
			RHP_UNLOCK(&(fwd_vpn->lock));
			goto error;
		}
	}


	err = fwd_nhrp_mesg->serialize(fwd_nhrp_mesg,fwd_vpn,0,&fwd_pkt);
	if( err ){

		RHP_UNLOCK(&(fwd_vpn->lock));

		RHP_BUG("%d",err);
		goto error;
	}

	fwd_nhrp_mesg->tx_pkt_ref = rhp_pkt_hold_ref(fwd_pkt);

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,rx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_FWD_RESOLUTION_REQ,"VBB",fwd_vpn,rx_nhrp_mesg,fwd_nhrp_mesg);

	RHP_UNLOCK(&(fwd_vpn->lock));


	//
	// All errors are ignored from here.
	//

	// fwd_vpn->lock will be acquired in rhp_gre_send().
	rhp_gre_send(fwd_vpn,fwd_pkt);


	err = 0;

error:

	if( err ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,rx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_FWD_RESOLUTION_REQ_ERR,"BE",rx_nhrp_mesg,err);
	}

	if( fwd_vpn ){
		rhp_vpn_unhold(fwd_vpn);
	}

	if( fwd_nhrp_mesg ){
		rhp_nhrp_mesg_unhold(fwd_nhrp_mesg);
	}

	if( fwd_pkt ){
		rhp_pkt_unhold(fwd_pkt);
	}

	RHP_TRC(0,RHPTRCID_NHRP_FWD_RESOLUTION_REQ_RTRN,"xxxxxE",rx_nhrp_mesg,rx_vpn,fwd_vpn,fwd_nhrp_mesg,fwd_pkt,err);
	return err;
}

static void _rhp_nhrp_rx_resolution_req_task(int worker_index,void *ctx)
{
	int err = -EINVAL;
	rhp_nhrp_mesg* rx_nhrp_mesg = (rhp_nhrp_mesg*)ctx;
	rhp_vpn_ref* rx_vpn_ref = rx_nhrp_mesg->rx_vpn_ref;
	rhp_vpn* rx_vpn = RHP_VPN_REF(rx_vpn_ref);
	rhp_ip_addr rslv_proto_addr, src_proto_addr, next_hop_proto_addr;
	unsigned long out_realm_id = 0;
	rhp_nhrp_ext* fwd_trans_nhs_ext = NULL;
	int fwd_mesg = 0;
	rhp_vpn_realm* rx_rlm = NULL;

	RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_TASK,"dxxxd",worker_index,rx_nhrp_mesg,rx_vpn_ref,rx_vpn,rhp_gcfg_dmvpn_only_tx_resolution_rep_via_nhs);

	rx_nhrp_mesg->rx_vpn_ref = NULL;

	memset(&src_proto_addr,0,sizeof(rhp_ip_addr));
	memset(&rslv_proto_addr,0,sizeof(rhp_ip_addr));
	memset(&next_hop_proto_addr,0,sizeof(rhp_ip_addr));


	err = rx_nhrp_mesg->m.mandatory->get_src_protocol_addr(rx_nhrp_mesg,&src_proto_addr);
	if( err ){
		goto error;
	}

	err = rx_nhrp_mesg->m.mandatory->get_dst_protocol_addr(rx_nhrp_mesg,&rslv_proto_addr);
	if( err ){
		goto error;
	}


	fwd_trans_nhs_ext
		= rx_nhrp_mesg->get_extension(rx_nhrp_mesg,RHP_PROTO_NHRP_EXT_TYPE_FORWARD_TRANSIT_NHS_RECORD);

	if( fwd_trans_nhs_ext == NULL ){
		err = RHP_STATUS_NHRP_NO_FWD_TRANSIT_NHS_RECORDS;
		goto error;
	}


	RHP_LOCK(&(rx_vpn->lock));

	if( !_rhp_atomic_read(&(rx_vpn->is_active)) ){

		RHP_UNLOCK(&(rx_vpn->lock));

		err = -EINVAL;
  	RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_VPN_NOT_ACTIVE,"x",rx_vpn);
  	goto error;
	}

	{
		rx_rlm = rx_vpn->rlm;
	  rhp_ifc_entry* v_ifc = NULL;
		rhp_ifc_addr* if_addr;

		if( rx_rlm == NULL ){

			RHP_UNLOCK(&(rx_vpn->lock));

			err = -EINVAL;
			RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_VPN_NO_RLM_FOUND,"x",rx_vpn);
			goto error;
		}

		RHP_LOCK(&(rx_rlm->lock));

		if( !_rhp_atomic_read(&(rx_rlm->is_active)) ){

			RHP_UNLOCK(&(rx_vpn->lock));

			err = -EINVAL;
			RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_RLM_NOT_ACTIVE,"xx",rx_vpn,rx_rlm);
			goto error;
		}

		v_ifc = rx_rlm->internal_ifc->ifc;
		if( v_ifc == NULL ){

			RHP_UNLOCK(&(rx_rlm->lock));
			RHP_UNLOCK(&(rx_vpn->lock));

			err = -ENOENT;
			RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_NO_V_IFC,"xx",rx_vpn,rx_rlm);
			goto error;
		}

		RHP_LOCK(&(v_ifc->lock));

		// Find an internal_if_addr by resolved addr family(IPv4 or IPv6).
		if_addr = _rhp_nhrp_get_internal_addr(v_ifc,rslv_proto_addr.addr_family);
		if( if_addr == NULL ){

			RHP_UNLOCK(&(v_ifc->lock));
			RHP_UNLOCK(&(rx_rlm->lock));
			RHP_UNLOCK(&(rx_vpn->lock));

			err = -ENOENT;
			RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_NO_NHS_ADDR,"xx",rx_nhrp_mesg,rx_vpn);
			goto error;
		}

		memcpy(&(rx_nhrp_mesg->resolution_rep_my_itnl_addr),&(if_addr->addr),sizeof(rhp_ip_addr));


		err = _rhp_nhrp_check_mesg_loop(fwd_trans_nhs_ext,v_ifc);
		if( err ){

			RHP_UNLOCK(&(v_ifc->lock));
			RHP_UNLOCK(&(rx_rlm->lock));
			RHP_UNLOCK(&(rx_vpn->lock));

			RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_LOOP_DETECTED,"xx",rx_nhrp_mesg,rx_vpn);
			goto error;
		}

		RHP_UNLOCK(&(v_ifc->lock));

		RHP_UNLOCK(&(rx_rlm->lock));
		rx_rlm = NULL;
	}
	RHP_UNLOCK(&(rx_vpn->lock));



	if( src_proto_addr.addr_family == AF_INET &&
			rslv_proto_addr.addr_family == AF_INET ){

		err = rhp_ip_routing_slow_v4(
						src_proto_addr.addr.v4,rslv_proto_addr.addr.v4,
						&(next_hop_proto_addr.addr.v4),&out_realm_id,
						&(rx_nhrp_mesg->resolution_rep_dst_network));
		if( err ){
			goto error;
		}

	}else if( src_proto_addr.addr_family == AF_INET6 &&
						rslv_proto_addr.addr_family == AF_INET6 ){

		err = rhp_ip_routing_slow_v6(
						src_proto_addr.addr.v6,rslv_proto_addr.addr.v6,
						next_hop_proto_addr.addr.v6,&out_realm_id,
						&(rx_nhrp_mesg->resolution_rep_dst_network));
		if( err ){
			goto error;
		}

	}else{
		err = -EINVAL;
		goto error;
	}

	next_hop_proto_addr.addr_family = rslv_proto_addr.addr_family;


	if( out_realm_id &&
			out_realm_id != rx_vpn->vpn_realm_id ){

		//
		// TODO: Inter-vpn-realm NHRP short-cut support.
		//

		err = -ENOENT;
		goto error;
	}

	if( out_realm_id ){

		if( rslv_proto_addr.addr_family == AF_INET ){

			if( !rhp_ifc_is_my_ip_v4(rslv_proto_addr.addr.v4) ){
				fwd_mesg = 1;
			}

		}else if( rslv_proto_addr.addr_family == AF_INET6 ){

			if( !rhp_ifc_is_my_ip_v6(rslv_proto_addr.addr.v6) ){
				fwd_mesg = 1;
			}
		}
	}

	if( fwd_mesg ){

		err = _rhp_nhrp_fwd_resolution_req(rx_nhrp_mesg,rx_vpn,
						out_realm_id,&next_hop_proto_addr,&(rx_nhrp_mesg->resolution_rep_my_itnl_addr));
		if( err ){
			goto error;
		}

	}else{

		if( !rhp_gcfg_dmvpn_only_tx_resolution_rep_via_nhs ){

			err = _rhp_nhrp_rx_resolution_req_handle_shortcut(rx_nhrp_mesg,rx_vpn->vpn_realm_id,
							rx_vpn->cfg_peer->ikev1_init_mode,0);
			if( err ){
				goto error;
			}

		}else{

			RHP_LOCK(&(rx_vpn->lock));

			rx_rlm = rx_vpn->rlm;
			if( rx_rlm ){

				rhp_packet* tx_pkt = NULL;

				rhp_realm_hold(rx_rlm);

				err = _rhp_nhrp_tx_resolution_rep(rx_vpn,rx_nhrp_mesg,&tx_pkt);
				RHP_UNLOCK(&(rx_vpn->lock));

				if( !err ){

					rhp_gre_send_access_point(rx_rlm,tx_pkt);
					rhp_pkt_unhold(tx_pkt);

				}else{

					RHP_BUG("%d",err);
				}

				rhp_realm_unhold(rx_rlm);
				rx_rlm = NULL;

			}else{

				RHP_BUG("%d",rx_vpn->vpn_realm_id);

				RHP_UNLOCK(&(rx_vpn->lock));
			}
		}
	}

error:
	rhp_nhrp_mesg_unhold(rx_nhrp_mesg);
	rhp_vpn_unhold(rx_vpn_ref);


	RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_TASK_RTRN,"xxxudE",rx_nhrp_mesg,rx_vpn_ref,rx_vpn,out_realm_id,fwd_mesg,err);
	return;
}

static int _rhp_nhrp_invoke_rx_resolution_req_task(rhp_nhrp_mesg* rx_nhrp_mesg,rhp_vpn* rx_vpn)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_NHRP_INVOKE_RX_RESOLUTION_REQ_TASK,"xxxb",rx_nhrp_mesg,rx_vpn,RHP_PKT_REF(rx_nhrp_mesg->rx_pkt_ref),rx_nhrp_mesg->rx_hop_count);

	if( rx_nhrp_mesg->rx_hop_count <= 1 ){
		err = RHP_STATUS_NHRP_HOP_LIMIT_REACHED;
		goto error;
	}

  if( rhp_wts_dispach_ok(RHP_WTS_DISP_LEVEL_HIGH_2,0) ){

  	rx_nhrp_mesg->rx_vpn_ref = rhp_vpn_hold_ref(rx_vpn);
  	rhp_nhrp_mesg_hold(rx_nhrp_mesg);


		err = rhp_wts_add_task(
						RHP_WTS_DISP_RULE_DMVPN_HANDLE_SHORTCUT,
						RHP_WTS_DISP_LEVEL_HIGH_3,rx_nhrp_mesg,
						_rhp_nhrp_rx_resolution_req_task,rx_nhrp_mesg);
		if( err ){
			RHP_BUG("%d",err);
			rhp_nhrp_mesg_unhold(rx_nhrp_mesg);
			goto error;
		}

		if( rx_nhrp_mesg->rx_pkt_ref ){
			rhp_pkt_pending(RHP_PKT_REF(rx_nhrp_mesg->rx_pkt_ref));
		}

  }else{

  	err = -EBUSY;
  	goto error;
  }

	RHP_TRC(0,RHPTRCID_NHRP_INVOKE_RX_RESOLUTION_REQ_TASK_RTRN,"xx",rx_nhrp_mesg,rx_vpn);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_INVOKE_RX_RESOLUTION_REQ_TASK_ERR,"xxE",rx_nhrp_mesg,rx_vpn,err);
	return err;
}

static int _rhp_nhrp_rx_resolution_req(rhp_nhrp_mesg* rx_nhrp_mesg,rhp_vpn* rx_vpn)
{
	int err = -EINVAL;
	rhp_ip_addr src_nbma_addr, src_proto_addr, rslv_proto_addr;
	rhp_packet* rx_pkt = RHP_PKT_REF(rx_nhrp_mesg->rx_pkt_ref);

	RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ,"xxxd",rx_nhrp_mesg,rx_vpn,rx_pkt,rx_vpn->nhrp.dmvpn_enabled);

	if( !rx_vpn->nhrp.dmvpn_enabled ){
		err = 0;
		goto error;
	}

	memset(&src_nbma_addr,0,sizeof(rhp_ip_addr));
	memset(&src_proto_addr,0,sizeof(rhp_ip_addr));
	memset(&rslv_proto_addr,0,sizeof(rhp_ip_addr));

	if( rx_pkt->nhrp.nbma_addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_RX_PKT_NBMA_ADDR_V4,"xx44",rx_nhrp_mesg,rx_vpn,*((u32*)rx_pkt->nhrp.nbma_src_addr),*((u32*)rx_pkt->nhrp.nbma_dst_addr));
	}else if( rx_pkt->nhrp.nbma_addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_RX_PKT_NBMA_ADDR_V6,"xx66",rx_nhrp_mesg,rx_vpn,rx_pkt->nhrp.nbma_src_addr,rx_pkt->nhrp.nbma_dst_addr);
	}else{
		RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_RX_PKT_NBMA_ADDR_NONE,"xxLd",rx_nhrp_mesg,rx_vpn,"AF",rx_pkt->nhrp.nbma_addr_family);
	}

	{
		err = rx_nhrp_mesg->m.mandatory->get_src_nbma_addr(rx_nhrp_mesg,&src_nbma_addr);
		if( err ){
			goto error;
		}

		err = rx_nhrp_mesg->m.mandatory->get_src_protocol_addr(rx_nhrp_mesg,&src_proto_addr);
		if( err ){
			goto error;
		}

		err = rx_nhrp_mesg->m.mandatory->get_dst_protocol_addr(rx_nhrp_mesg,&rslv_proto_addr);
		if( err ){
			goto error;
		}
	}


	err = _rhp_nhrp_rx_req_verify(rx_nhrp_mesg,rx_vpn,
					RHP_PROTO_NHRP_PKT_RESOLUTION_REQ,
					&src_nbma_addr,&src_proto_addr,&rslv_proto_addr);
	if( err ){
		goto error;
	}


	err = _rhp_nhrp_invoke_rx_resolution_req_task(rx_nhrp_mesg,rx_vpn);
	if( err ){
		goto error;
	}

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,rx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_RX_RESOLUTION_REQ,"VB",rx_vpn,rx_nhrp_mesg);


	RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_RTRN,"xxx",rx_nhrp_mesg,rx_vpn,rx_pkt);
	return 0;

error:

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,rx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_RX_RESOLUTION_REQ_ERR,"VBE",rx_vpn,rx_nhrp_mesg,err);

	RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REQ_ERR,"xxxE",rx_nhrp_mesg,rx_vpn,rx_pkt,err);
	return err;
}

static void _rhp_nhrp_tx_queued_resolution_rep_task(void *ctx)
{
	int err = -EINVAL;
	rhp_vpn_ref* tx_vpn_ref = (rhp_vpn_ref*)ctx;
	rhp_vpn* tx_vpn = RHP_VPN_REF(tx_vpn_ref);
	rhp_nhrp_mesg* rx_nhrp_mesg;
	rhp_packet_q tx_pkt_q;

	RHP_TRC(0,RHPTRCID_NHRP_TX_QUEUED_RESOLUTION_REP_TASK,"xx",tx_vpn_ref,tx_vpn);

	_rhp_pkt_q_init(&tx_pkt_q);

	RHP_LOCK(&(tx_vpn->lock));

	rx_nhrp_mesg = tx_vpn->nhrp.pend_resolution_req_q.head;
	while( rx_nhrp_mesg ){

		rhp_nhrp_mesg* rx_nhrp_mesg_n = rx_nhrp_mesg->next;
		rhp_packet* tx_pkt = NULL;

		err = _rhp_nhrp_tx_resolution_rep(tx_vpn,rx_nhrp_mesg,&tx_pkt);
		if( !err ){

			_rhp_pkt_q_enq(&tx_pkt_q,tx_pkt);

		}else{
			RHP_BUG("%d",err);
		}

		rhp_nhrp_mesg_unhold(rx_nhrp_mesg);

		rx_nhrp_mesg = rx_nhrp_mesg_n;
	}

	tx_vpn->nhrp.pend_resolution_req_q.head = NULL;
	tx_vpn->nhrp.pend_resolution_req_q.tail = NULL;

	RHP_UNLOCK(&(tx_vpn->lock));


	{
		rhp_packet* tx_pkt = _rhp_pkt_q_deq(&tx_pkt_q);

		while( tx_pkt ){


			if( !rhp_gcfg_dmvpn_tx_resolution_rep_via_nhs ){

				rhp_gre_send(tx_vpn,tx_pkt);

			}else{

				// For Debug...

		  	rhp_vpn_realm* tx_rlm = rhp_realm_get(tx_vpn->vpn_realm_id);
		  	if( tx_rlm == NULL ){

		  		RHP_BUG("%d",tx_vpn->vpn_realm_id);

		  	}else{

		  		rhp_gre_send_access_point(tx_rlm,tx_pkt);
			  	rhp_realm_unhold(tx_rlm);
		  	}
			}

			rhp_pkt_unhold(tx_pkt);

			tx_pkt = _rhp_pkt_q_deq(&tx_pkt_q);
		}
	}

	rhp_vpn_unhold(tx_vpn_ref);

	RHP_TRC(0,RHPTRCID_NHRP_TX_QUEUED_RESOLUTION_REQ_TASK_RTRN,"x",tx_vpn);
	return;
}

int rhp_nhrp_tx_queued_resolution_rep(rhp_vpn* tx_vpn)
{
	int err = -EINVAL;
	rhp_vpn_ref* tx_vpn_ref;

	RHP_TRC(0,RHPTRCID_NHRP_TX_QUEUED_RESOLUTION_REP,"x",tx_vpn);

	tx_vpn_ref = rhp_vpn_hold_ref(tx_vpn);

	err = rhp_timer_oneshot(_rhp_nhrp_tx_queued_resolution_rep_task,tx_vpn_ref,1);
	if( err ){
		RHP_BUG("%d",err);
		rhp_vpn_unhold(tx_vpn_ref);
		goto error;
	}

	RHP_TRC(0,RHPTRCID_NHRP_TX_QUEUED_RESOLUTION_REP_RTRN,"x",tx_vpn);
	return 0;

error:
	{
		rhp_nhrp_mesg* rx_nhrp_mesg = tx_vpn->nhrp.pend_resolution_req_q.head;
		while( rx_nhrp_mesg ){
			rhp_nhrp_mesg* rx_nhrp_mesg_n = rx_nhrp_mesg->next;
			rhp_nhrp_mesg_unhold(rx_nhrp_mesg);
			rx_nhrp_mesg = rx_nhrp_mesg_n;
		}
		tx_vpn->nhrp.pend_resolution_req_q.head = NULL;
		tx_vpn->nhrp.pend_resolution_req_q.tail = NULL;
	}

	RHP_TRC(0,RHPTRCID_NHRP_TX_QUEUED_RESOLUTION_REP_ERR,"xE",tx_vpn,err);
	return err;
}


//
// For redundant shortcuts tunnels which was simultaneously
// connected.
// By this dmy_metric value, either tunnel is expected to be
// idle and so the idle-timer will close it.
//
//  Ugly....
//
static int _rhp_nhrp_rt_entry_dmy_metric(rhp_ikesa* cur_ikesa)
{
	u8 *ni,*nr;
	int dmy_metric;

	ni = cur_ikesa->nonce_i->get_nonce(cur_ikesa->nonce_i);
	nr = cur_ikesa->nonce_r->get_nonce(cur_ikesa->nonce_r);

	if( ni == NULL || nr == NULL ){
		dmy_metric = 0;
	}else{
		dmy_metric = (int)ni[0] + (int)nr[0];
	}

	RHP_TRC(0,RHPTRCID_NHRP_RT_ENTRY_DMY_METRIC,"xd",cur_ikesa,dmy_metric);
	return dmy_metric;
}

#define RHP_NHRP_RESOLUTION_REP_MAX_PEER_PROTO_ADDRS	2
static int _rhp_nhrp_rx_resolution_rep(rhp_nhrp_mesg* rx_nhrp_mesg,rhp_vpn* rx_vpn)
{
	int err = -EINVAL;
	rhp_ip_addr dst_proto_addr, peer_nbma_addr, peer_dst_network;
	rhp_ip_addr peer_proto_addrs[RHP_NHRP_RESOLUTION_REP_MAX_PEER_PROTO_ADDRS]; // [0]: Linklocal, [1]: Global
	rhp_nhrp_req_session* nhrp_sess = NULL;
	rhp_nhrp_cie* nhrp_cie;
	rhp_vpn_list* tx_vpn_lst_head = NULL;
	int hold_time = 0, peer_dst_prefix_len = 0, i;

	RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REP,"xxd",rx_nhrp_mesg,rx_vpn,rx_vpn->nhrp.dmvpn_shortcut);

	rx_nhrp_mesg->rx_vpn_ref = NULL;

	memset(&dst_proto_addr,0,sizeof(rhp_ip_addr));
	memset(&peer_nbma_addr,0,sizeof(rhp_ip_addr));
	memset(&peer_dst_network,0,sizeof(rhp_ip_addr));
	memset(peer_proto_addrs,0,sizeof(rhp_ip_addr)*RHP_NHRP_RESOLUTION_REP_MAX_PEER_PROTO_ADDRS);


	err = rx_nhrp_mesg->m.mandatory->get_dst_protocol_addr(rx_nhrp_mesg,&dst_proto_addr);
	if( err ){
		goto error;
	}

	if( dst_proto_addr.addr_family != AF_INET && dst_proto_addr.addr_family != AF_INET6 ){
		err = RHP_STATUS_NHRP_INVALID_PKT;
		goto error;
	}

	{
		RHP_LOCK(&(rx_vpn->lock));

		if( rx_vpn->nhrp.dmvpn_shortcut ){

			memcpy(&peer_nbma_addr,&(rx_vpn->peer_addr),sizeof(rhp_ip_addr));

		}else{

			err = _rhp_nhrp_rx_resolution_rep_peer_nbma_addr(rx_nhrp_mesg,&peer_nbma_addr);
			if( err ){
				RHP_UNLOCK(&(rx_vpn->lock));
				goto error;
			}
		}

		RHP_UNLOCK(&(rx_vpn->lock));

		rhp_ip_addr_dump("peer_nbma_addr",&peer_nbma_addr);
	}

	{
		nhrp_cie = rx_nhrp_mesg->m.mandatory->cie_list_head;
		while( nhrp_cie ){

			rhp_ip_addr peer_proto_addr;

			memset(&peer_proto_addr,0,sizeof(rhp_ip_addr));

			if( !peer_dst_prefix_len ){
				peer_dst_prefix_len = (int)nhrp_cie->get_prefix_len(nhrp_cie);
			}

			if( !hold_time ){
				hold_time = (int)nhrp_cie->get_hold_time(nhrp_cie);
			}

			err = nhrp_cie->get_clt_protocol_addr(nhrp_cie,&peer_proto_addr);
			if( err ){
				goto error;
			}

			if( dst_proto_addr.addr_family != peer_proto_addr.addr_family ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				goto error;
			}

			if( peer_proto_addr.addr_family == AF_INET ){
				peer_proto_addr.prefixlen = 32;
				peer_proto_addr.netmask.v4 = rhp_ipv4_prefixlen_to_netmask(32);
			}else if( peer_proto_addr.addr_family == AF_INET6 ){
				peer_proto_addr.prefixlen = 128;
				rhp_ipv6_prefixlen_to_netmask(128,peer_proto_addr.netmask.v6);
			}

			if( rhp_ip_is_linklocal(peer_proto_addr.addr_family,peer_proto_addr.addr.raw) ){
				memcpy(&(peer_proto_addrs[0]),&peer_proto_addr,sizeof(rhp_ip_addr));
			}else if( rhp_ip_addr_null(&(peer_proto_addrs[1])) ){
				memcpy(&(peer_proto_addrs[1]),&peer_proto_addr,sizeof(rhp_ip_addr));
			}

			nhrp_cie = nhrp_cie->next;
		}

		if( !peer_dst_prefix_len ){
			if( dst_proto_addr.addr_family == AF_INET ){
				peer_dst_prefix_len = 32;
			}else if( dst_proto_addr.addr_family == AF_INET6 ){
				peer_dst_prefix_len = 128;
			}
		}

		if( !hold_time ){
			hold_time = rhp_gcfg_nhrp_cache_hold_time;
		}
	}

	err = rhp_ip_network_addr(dst_proto_addr.addr_family,dst_proto_addr.addr.raw,
					peer_dst_prefix_len,&peer_dst_network);
	if( err ){
		goto error;
	}


	RHP_LOCK(&rhp_nhrp_lock);

	nhrp_sess =  _rhp_nhrp_req_sess_get(
			rx_vpn->vpn_realm_id,
			RHP_PROTO_NHRP_PKT_RESOLUTION_REQ,
			dst_proto_addr.addr_family,dst_proto_addr.addr.raw);

	if( nhrp_sess == NULL ){

		RHP_UNLOCK(&rhp_nhrp_lock);

		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REP_NO_CACHE_FOUND,"xx",rx_nhrp_mesg,rx_vpn);
		goto error;
	}

	if( nhrp_sess->tx_request_id !=
				rx_nhrp_mesg->m.mandatory->get_request_id(rx_nhrp_mesg) ){

		RHP_UNLOCK(&rhp_nhrp_lock);

		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REP_INVALID_TX_REQ_ID,"xxjj",rx_nhrp_mesg,rx_vpn,nhrp_sess->tx_request_id,rx_nhrp_mesg->m.mandatory->get_request_id(rx_nhrp_mesg));
		goto error;
	}


	err = rhp_timer_delete(&(nhrp_sess->timer));
	if( err ){

		nhrp_sess->done = 1;

		RHP_UNLOCK(&rhp_nhrp_lock);

		RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REP_SESS_TIMER_HANDLER_WAITING,"xxx",rx_nhrp_mesg,rx_vpn,&(nhrp_sess->timer));
		goto error;
	}
	_rhp_nhrp_req_sess_unhold(nhrp_sess);


	if( !_rhp_nhrp_req_sess_delete(nhrp_sess) ){
		_rhp_nhrp_req_sess_unhold(nhrp_sess);
	}else{
		RHP_BUG("");
	}
	nhrp_sess = NULL;

	RHP_UNLOCK(&rhp_nhrp_lock);


	//
	// [TODO] Multiple shortcut-responders behind a NAT device
	//        located in their site. They may share a common NATed
	//        NBMA pub address. To distinguish them, this node needs
	//        some extra info like internal NRHP protocol addresses of
	//        the NATed remote responders. But, NHRP cache created by
	//        NHRP RESOLUTION Req/Resp is not reliable because of
	//        a variable holding-time and a exchange timing.
	//
	err = rhp_vpn_get_by_peer_addr_impl(rx_vpn->vpn_realm_id,
			peer_nbma_addr.addr_family,peer_nbma_addr.addr.raw,&tx_vpn_lst_head);
	if( err ){

		//
		// Waiting for the next retry...
		//

		err = -ENOENT;
		goto error;

	}else{

		//
		// If VPN connections are simultaneously established,
		// two connections may be found. A redundant connection
		// will be closed by idle timer. Each routing entry with
		// dmy_metric is added into a routing table for it.
		//

		rhp_vpn_list* tx_vpn_lst = tx_vpn_lst_head;

		while( tx_vpn_lst ){

			rhp_vpn* tx_vpn = RHP_VPN_REF(tx_vpn_lst->vpn_ref);
			rhp_ikesa* cur_ikesa = NULL;
			rhp_vpn_realm* tx_rlm = NULL;
			rhp_ifc_entry* v_ifc = NULL;
			int oif_index;
			int dmy_metric = 0;


			RHP_LOCK(&(tx_vpn->lock));

			tx_rlm = tx_vpn->rlm;
			if( tx_rlm == NULL ){

				RHP_UNLOCK(&(tx_vpn->lock));

				err = -EINVAL;
				RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REP_VPN_NO_RLM_FOUND,"x",tx_vpn);
				goto error;
			}


			RHP_LOCK(&(tx_rlm->lock));
			{
				if( !_rhp_atomic_read(&(tx_rlm->is_active)) ){

					RHP_UNLOCK(&(tx_rlm->lock));
					RHP_UNLOCK(&(tx_vpn->lock));

					err = -EINVAL;
					RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REP_RLM_NOT_ACTIVE,"xx",tx_vpn,tx_rlm);
					goto error;
				}


				v_ifc = tx_rlm->internal_ifc->ifc;
				if( v_ifc == NULL ){

					RHP_UNLOCK(&(tx_rlm->lock));
					RHP_UNLOCK(&(tx_vpn->lock));

					err = -ENOENT;
					RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REP_NO_V_IFC,"xx",tx_vpn,tx_rlm);
					goto error;
				}

				RHP_LOCK(&(v_ifc->lock));
				{

					oif_index = v_ifc->if_index;
				}
				RHP_UNLOCK(&(v_ifc->lock));
			}
			RHP_UNLOCK(&(tx_rlm->lock));


			cur_ikesa = tx_vpn->ikesa_list_head;
			while( cur_ikesa ){

				RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REP_CUR_IKESA,"xuxxLdd",rx_nhrp_mesg,tx_vpn->vpn_realm_id,tx_vpn,cur_ikesa,"IKESA_STAT",cur_ikesa->state,oif_index);

				if( cur_ikesa->state == RHP_IKESA_STAT_ESTABLISHED ||	// IKEv2
						cur_ikesa->state == RHP_IKESA_STAT_REKEYING 	 ||	// IKEv2
						cur_ikesa->state == RHP_IKESA_STAT_V1_ESTABLISHED ||
						cur_ikesa->state == RHP_IKESA_STAT_V1_REKEYING ){

					dmy_metric = _rhp_nhrp_rt_entry_dmy_metric(cur_ikesa);

					RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REP_CUR_IKESA_FOUND,"xuxxLddd",rx_nhrp_mesg,tx_vpn->vpn_realm_id,tx_vpn,cur_ikesa,"IKESA_STAT",cur_ikesa->state,dmy_metric,oif_index);

					break;
				}

				cur_ikesa = cur_ikesa->next_vpn_list;
			}

			if( cur_ikesa == NULL ){

				RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REP_NO_CUR_IKESA,"xux",rx_nhrp_mesg,tx_vpn->vpn_realm_id,tx_vpn);

				RHP_UNLOCK(&(tx_vpn->lock));

				err = -ENOENT;
				goto error;
			}

			for( i = 0; i < RHP_NHRP_RESOLUTION_REP_MAX_PEER_PROTO_ADDRS; i++){

				if( !rhp_ip_addr_null(&(peer_proto_addrs[i])) ){

					err = rhp_ip_routing_nhrp_add_cache(&peer_dst_network,&(peer_proto_addrs[i]),
									tx_vpn->vpn_realm_id,oif_index,tx_vpn,(time_t)hold_time,dmy_metric);
					if( err ){
						RHP_BUG("%d",err);
					}

					err = rhp_ip_routing_nhrp_add_cache(&(peer_proto_addrs[i]),NULL,
									tx_vpn->vpn_realm_id,oif_index,tx_vpn,(time_t)hold_time,dmy_metric);
					if( err ){
						RHP_BUG("%d",err);
					}
				}
			}

			RHP_UNLOCK(&(tx_vpn->lock));

			RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REP_TX_VPN,"xxxxd",tx_vpn,cur_ikesa,tx_rlm,v_ifc,dmy_metric);

			tx_vpn_lst = tx_vpn_lst->next;
		}
	}


	if( tx_vpn_lst_head ){
		rhp_vpn_list_free(tx_vpn_lst_head);
	}

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,rx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_RX_RESOLUTION_REP,"VB",rx_vpn,rx_nhrp_mesg);

	RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REP_RTRN,"xxx",rx_nhrp_mesg,rx_vpn,tx_vpn_lst_head);
	return err;

error:
	if( tx_vpn_lst_head ){
		rhp_vpn_list_free(tx_vpn_lst_head);
	}

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,rx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_RX_RESOLUTION_REP_ERR,"VBE",rx_vpn,rx_nhrp_mesg,err);

	RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REP_ERR,"xxxE",rx_nhrp_mesg,rx_vpn,tx_vpn_lst_head,err);
	return err;
}

static int _rhp_nhrp_fwd_resolution_rep(rhp_nhrp_mesg* rx_nhrp_mesg,rhp_vpn* rx_vpn,
		unsigned long out_realm_id,rhp_ip_addr* next_hop_proto_addr,rhp_ip_addr* my_proto_addr)
{
	int err = -EINVAL;
	rhp_vpn* fwd_vpn = NULL;
	rhp_nhrp_mesg* fwd_nhrp_mesg = NULL;
	rhp_nhrp_cie* nhrp_cie;
	rhp_nhrp_ext* rvrs_trans_nhs_ext = NULL;
	rhp_packet* fwd_pkt = NULL;

	RHP_TRC(0,RHPTRCID_NHRP_FWD_RESOLUTION_REP,"xxuxx",rx_nhrp_mesg,rx_vpn,out_realm_id,next_hop_proto_addr,my_proto_addr);
	rhp_ip_addr_dump("next_hop_proto_addr",next_hop_proto_addr);
	rhp_ip_addr_dump("my_proto_addr",my_proto_addr);


	fwd_vpn = rhp_nhrp_cache_get_vpn(
							next_hop_proto_addr->addr_family,next_hop_proto_addr->addr.raw,
							out_realm_id);

	if( fwd_vpn == NULL ){

		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_NHRP_FWD_RESOLUTION_REP_NEXT_HOP_NOT_VIA_VPN,"xxx",rx_nhrp_mesg,rx_vpn,fwd_vpn);
		goto error;

	}else if( fwd_vpn == rx_vpn ){

		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_NHRP_FWD_RESOLUTION_REP_NEXT_HOP_VIA_SAME_RX_VPN,"xxx",rx_nhrp_mesg,rx_vpn,fwd_vpn);
		goto error;
	}


	RHP_LOCK(&(fwd_vpn->lock));

	if( fwd_vpn->internal_net_info.encap_mode_c != RHP_VPN_ENCAP_GRE ||
			fwd_vpn->nhrp.role == RHP_NHRP_SERVICE_NONE ||
			!fwd_vpn->nhrp.dmvpn_enabled ){

		RHP_UNLOCK(&(fwd_vpn->lock));

		err = RHP_STATUS_NO_GRE_ENCAP;
		RHP_TRC(0,RHPTRCID_NHRP_FWD_RESOLUTION_REP_NEXT_HOP_VIA_GRE_ENCAP_VPN,"xxxddd",rx_nhrp_mesg,rx_vpn,fwd_vpn,fwd_vpn->internal_net_info.encap_mode_c,fwd_vpn->nhrp.role,fwd_vpn->nhrp.dmvpn_enabled);
		goto error;
	}


	fwd_nhrp_mesg = rhp_nhrp_mesg_dup(rx_nhrp_mesg);
	if( fwd_nhrp_mesg == NULL ){

		RHP_UNLOCK(&(fwd_vpn->lock));

		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	fwd_nhrp_mesg->dec_hop_count(fwd_nhrp_mesg);

	fwd_nhrp_mesg->m.mandatory->dont_update_request_id(fwd_nhrp_mesg,1);


	{
		rvrs_trans_nhs_ext
			= fwd_nhrp_mesg->get_extension(fwd_nhrp_mesg,RHP_PROTO_NHRP_EXT_TYPE_REVERSE_TRANSIT_NHS_RECORD);

		if( rvrs_trans_nhs_ext == NULL ){

			RHP_UNLOCK(&(fwd_vpn->lock));

			err = RHP_STATUS_NHRP_NO_RVRS_TRANSIT_NHS_RECORDS;
			goto error;
		}

		nhrp_cie = rhp_nhrp_cie_alloc(RHP_PROTO_NHRP_CIE_CODE_NONE);
		if( nhrp_cie == NULL ){

			RHP_UNLOCK(&(fwd_vpn->lock));

			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		err = rvrs_trans_nhs_ext->add_cie(rvrs_trans_nhs_ext,nhrp_cie);
		if( err ){

			rhp_nhrp_cie_free(nhrp_cie);

			RHP_UNLOCK(&(fwd_vpn->lock));
			goto error;
		}

		err = nhrp_cie->set_mtu(nhrp_cie,0);
		if( err ){
			RHP_UNLOCK(&(fwd_vpn->lock));
			goto error;
		}

		err = nhrp_cie->set_hold_time(nhrp_cie,(u16)rhp_gcfg_nhrp_cache_hold_time);
		if( err ){
			RHP_UNLOCK(&(fwd_vpn->lock));
			goto error;
		}

		err = nhrp_cie->set_prefix_len(nhrp_cie,0);
		if( err ){
			RHP_UNLOCK(&(fwd_vpn->lock));
			goto error;
		}

		err = nhrp_cie->set_clt_protocol_addr(nhrp_cie,
						my_proto_addr->addr_family,my_proto_addr->addr.raw);
		if( err ){
			RHP_UNLOCK(&(fwd_vpn->lock));
			goto error;
		}

		err = nhrp_cie->set_clt_nbma_addr(nhrp_cie,
						rx_vpn->local.if_info.addr_family,rx_vpn->local.if_info.addr.raw);
		if( err ){
			RHP_UNLOCK(&(fwd_vpn->lock));
			goto error;
		}
	}

	err = fwd_nhrp_mesg->serialize(fwd_nhrp_mesg,fwd_vpn,0,&fwd_pkt);
	if( err ){

		RHP_UNLOCK(&(fwd_vpn->lock));

		RHP_BUG("%d",err);
		goto error;
	}

	fwd_nhrp_mesg->tx_pkt_ref = rhp_pkt_hold_ref(fwd_pkt);

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,rx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_FWD_RESOLUTION_REP,"VBB",fwd_vpn,rx_nhrp_mesg,fwd_nhrp_mesg);

	RHP_UNLOCK(&(fwd_vpn->lock));


	//
	// All errors are ignored from here.
	//

	// fwd_vpn->lock will be acquired in rhp_gre_send().
	rhp_gre_send(fwd_vpn,fwd_pkt);

	err = 0;

error:

	if( err ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,rx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_FWD_RESOLUTION_REP_ERR,"BE",rx_nhrp_mesg,err);
	}

	if( fwd_vpn ){
		rhp_vpn_unhold(fwd_vpn);
	}

	if( fwd_nhrp_mesg ){
		rhp_nhrp_mesg_unhold(fwd_nhrp_mesg);
	}

	if( fwd_pkt ){
		rhp_pkt_unhold(fwd_pkt);
	}

	RHP_TRC(0,RHPTRCID_NHRP_FWD_RESOLUTION_REP_RTRN,"xxxxxE",rx_nhrp_mesg,rx_vpn,fwd_vpn,fwd_nhrp_mesg,fwd_pkt,err);
	return err;
}

static void _rhp_nhrp_rx_resolution_rep_task(int worker_index,void *ctx)
{
	int err = -EINVAL;
	rhp_nhrp_mesg* rx_nhrp_mesg = (rhp_nhrp_mesg*)ctx;
	rhp_vpn_ref* rx_vpn_ref = rx_nhrp_mesg->rx_vpn_ref;
	rhp_vpn* rx_vpn = RHP_VPN_REF(rx_vpn_ref);
	rhp_ip_addr src_proto_addr, dst_proto_addr, next_hop_proto_addr,
							resp_ext_clt_proto_addr, my_proto_addr;
	int fwd_flag = 0, i;
	rhp_nhrp_ext *rvrs_trans_nhs_ext = NULL, *resp_addr_ext = NULL;
	rhp_nhrp_cie* nhrp_cie;
	unsigned long out_realm_id = 0;


	RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REP_TASK,"dxxx",worker_index,rx_nhrp_mesg,rx_vpn,rx_vpn_ref);

	rx_nhrp_mesg->rx_vpn_ref = NULL;

	memset(&src_proto_addr,0,sizeof(rhp_ip_addr));
	memset(&dst_proto_addr,0,sizeof(rhp_ip_addr));
	memset(&next_hop_proto_addr,0,sizeof(rhp_ip_addr));
	memset(&resp_ext_clt_proto_addr,0,sizeof(rhp_ip_addr));
	memset(&my_proto_addr,0,sizeof(rhp_ip_addr));


	err = rx_nhrp_mesg->m.mandatory->get_src_protocol_addr(rx_nhrp_mesg,&src_proto_addr);
	if( err ){
		goto error;
	}

	if( src_proto_addr.addr_family != AF_INET && src_proto_addr.addr_family != AF_INET6 ){
		err = RHP_STATUS_NHRP_INVALID_PKT;
		goto error;
	}


	err = rx_nhrp_mesg->m.mandatory->get_dst_protocol_addr(rx_nhrp_mesg,&dst_proto_addr);
	if( err ){
		goto error;
	}


	rvrs_trans_nhs_ext
		= rx_nhrp_mesg->get_extension(rx_nhrp_mesg,RHP_PROTO_NHRP_EXT_TYPE_REVERSE_TRANSIT_NHS_RECORD);

	if( rvrs_trans_nhs_ext == NULL ){
		err = RHP_STATUS_NHRP_NO_RVRS_TRANSIT_NHS_RECORDS;
		goto error;
	}

	{
		resp_addr_ext
			= rx_nhrp_mesg->get_extension(rx_nhrp_mesg,RHP_PROTO_NHRP_EXT_TYPE_RESPONDER_ADDRESS);

		if( resp_addr_ext == NULL ){
			err = RHP_STATUS_NHRP_NO_RESPONDER_ADDR_EXT;
			goto error;
		}


		nhrp_cie = resp_addr_ext->cie_list_head;
		while( nhrp_cie ){

			err = nhrp_cie->get_clt_protocol_addr(nhrp_cie,&resp_ext_clt_proto_addr);
			if( err ){
				goto error;
			}

			if( resp_ext_clt_proto_addr.addr_family == src_proto_addr.addr_family ){
				break;
			}

			nhrp_cie = nhrp_cie->next;
		}

		if( nhrp_cie == NULL ){
			err = RHP_STATUS_NHRP_NO_RESPONDER_ADDR_EXT;
			goto error;
		}
	}


	RHP_LOCK(&(rx_vpn->lock));
	{
		rhp_vpn_realm* rlm = rx_vpn->rlm;
		rhp_ifc_entry* v_ifc;
		rhp_ifc_addr* if_addr;

		if( !_rhp_atomic_read(&(rx_vpn->is_active)) ){

			RHP_UNLOCK(&(rx_vpn->lock));

			err = -EINVAL;
			goto error;
		}


		rlm = rx_vpn->rlm;
		RHP_LOCK(&(rlm->lock));

		v_ifc = rlm->internal_ifc->ifc;
		if( v_ifc == NULL ){

			RHP_UNLOCK(&(rlm->lock));
			RHP_UNLOCK(&(rx_vpn->lock));

			RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REP_NO_V_IFC_FOUND,"xx",rx_nhrp_mesg,rx_vpn);
			goto error;
		}

		v_ifc->dump_no_lock("_rhp_nhrp_rx_resolution_rep_task",v_ifc);


		RHP_LOCK(&(v_ifc->lock));


		if_addr = _rhp_nhrp_get_internal_addr(v_ifc,src_proto_addr.addr_family);
		if( if_addr == NULL ){

			RHP_UNLOCK(&(v_ifc->lock));
			RHP_UNLOCK(&(rlm->lock));
			RHP_UNLOCK(&(rx_vpn->lock));

			err = -ENOENT;
			RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REP_NO_MY_ADDR,"xx",rx_nhrp_mesg,rx_vpn);
			goto error;
		}

		memcpy(&my_proto_addr,&(if_addr->addr),sizeof(rhp_ip_addr));



		err = _rhp_nhrp_check_mesg_loop(rvrs_trans_nhs_ext,v_ifc);
		if( err ){

			RHP_UNLOCK(&(v_ifc->lock));
			RHP_UNLOCK(&(rlm->lock));
			RHP_UNLOCK(&(rx_vpn->lock));

			RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REP_LOOP_DETECTED,"xx",rx_nhrp_mesg,rx_vpn);
			goto error;
		}



		fwd_flag = 1;
		if_addr = v_ifc->ifc_addrs;
		for( i = 0; i < v_ifc->ifc_addrs_num; i++ ){

			if( !rhp_ip_addr_cmp_ip_only(&resp_ext_clt_proto_addr,&(if_addr->addr)) ){

				RHP_UNLOCK(&(v_ifc->lock));
				RHP_UNLOCK(&(rlm->lock));
				RHP_UNLOCK(&(rx_vpn->lock));

				err = RHP_STATUS_NHRP_NO_FWD_LOOP_DETECTED;
				goto error;
			}

			if( !rhp_ip_addr_cmp_ip_only(&src_proto_addr,&(if_addr->addr)) ){
				fwd_flag = 0;
			}

			if_addr = if_addr->lst_next;
		}

		RHP_UNLOCK(&(v_ifc->lock));

		RHP_UNLOCK(&(rlm->lock));
	}
	RHP_UNLOCK(&(rx_vpn->lock));



	if( !fwd_flag ){

		err = _rhp_nhrp_rx_resolution_rep(rx_nhrp_mesg,rx_vpn);
		if( err ){
			goto error;
		}

	}else{


		if( src_proto_addr.addr_family == AF_INET &&
				dst_proto_addr.addr_family == AF_INET ){

			err = rhp_ip_routing_slow_v4(
							resp_ext_clt_proto_addr.addr.v4,src_proto_addr.addr.v4,
							&(next_hop_proto_addr.addr.v4),&out_realm_id,NULL);
			if( err ){
				goto error;
			}

		}else if( src_proto_addr.addr_family == AF_INET6 &&
							dst_proto_addr.addr_family == AF_INET6 ){

			err = rhp_ip_routing_slow_v6(
							resp_ext_clt_proto_addr.addr.v6,src_proto_addr.addr.v6,
							next_hop_proto_addr.addr.v6,&out_realm_id,NULL);
			if( err ){
				goto error;
			}

		}else{
			err = -EINVAL;
			goto error;
		}

		next_hop_proto_addr.addr_family = src_proto_addr.addr_family;


		if( out_realm_id == 0 ||
				out_realm_id != rx_vpn->vpn_realm_id ){

			//
			// TODO: Inter-vpn-realm NHRP short-cut support.
			//

			err = -ENOENT;
			goto error;
		}


		err = _rhp_nhrp_fwd_resolution_rep(rx_nhrp_mesg,rx_vpn,
						out_realm_id,&next_hop_proto_addr,&my_proto_addr);
		if( err ){
			goto error;
		}
	}


	rhp_vpn_unhold(rx_vpn_ref);

	rhp_nhrp_mesg_unhold(rx_nhrp_mesg);

	RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REP_TASK_RTRN,"xxd",rx_nhrp_mesg,rx_vpn,fwd_flag);
	return;


error:

	rhp_vpn_unhold(rx_vpn_ref);

	rhp_nhrp_mesg_unhold(rx_nhrp_mesg);

	RHP_TRC(0,RHPTRCID_NHRP_RX_RESOLUTION_REP_TASK_ERR,"xxdE",rx_nhrp_mesg,rx_vpn,fwd_flag,err);
	return;
}

static int _rhp_nhrp_invoke_rx_resolution_rep(rhp_nhrp_mesg* rx_nhrp_mesg,rhp_vpn* rx_vpn)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_NHRP_INVOKE_RX_RESOLUTION_REP_TASK,"xxb",rx_nhrp_mesg,rx_vpn,rx_nhrp_mesg->rx_hop_count);

	if( rx_nhrp_mesg->rx_hop_count <= 1 ){
		err = RHP_STATUS_NHRP_HOP_LIMIT_REACHED;
		goto error;
	}


	rx_nhrp_mesg->rx_vpn_ref = rhp_vpn_hold_ref(rx_vpn);
	rhp_nhrp_mesg_hold(rx_nhrp_mesg);

	err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_2,
					_rhp_nhrp_rx_resolution_rep_task,rx_nhrp_mesg);
	if( err ){
		RHP_BUG("%d",err);
		rhp_nhrp_mesg_unhold(rx_nhrp_mesg);
		goto error;
	}

	if( rx_nhrp_mesg->rx_pkt_ref ){
		rhp_pkt_pending(RHP_PKT_REF(rx_nhrp_mesg->rx_pkt_ref));
	}

	RHP_TRC(0,RHPTRCID_NHRP_INVOKE_RX_RESOLUTION_REP_TASK_RTRN,"xx",rx_nhrp_mesg,rx_vpn);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_INVOKE_RX_RESOLUTION_REP_TASK_ERR,"xxE",rx_nhrp_mesg,rx_vpn,err);
	return err;
}



static rhp_nhrp_mesg* _rhp_nhrp_tx_traffic_indication_alloc(rhp_vpn* tx_vpn,u16 f_addr_family,
		rhp_ifc_addr* v_if_addr,rhp_packet* rx_pkt_d)
{
	int err = -EINVAL;
	rhp_nhrp_mesg* tx_nhrp_mesg = NULL;
	rhp_ip_addr src_nbma_addr, dst_proto_addr;
	int orig_pkt_len;
	rhp_nhrp_ext* nhrp_ext;
  int tx_mtu;

	RHP_TRC(0,RHPTRCID_NHRP_TX_TRAFFIC_INDICATION_ALLOC,"xWxx",tx_vpn,f_addr_family,v_if_addr,rx_pkt_d);
	rhp_ip_addr_dump("v_if_addr",&(v_if_addr->addr));

	memset(&src_nbma_addr,0,sizeof(rhp_ip_addr));
	memset(&dst_proto_addr,0,sizeof(rhp_ip_addr));

	err = _rhp_nhrp_get_def_mtu(tx_vpn,&tx_mtu);
	if( err ){
		goto error;
	}

	tx_nhrp_mesg = rhp_nhrp_mesg_new_tx(f_addr_family,RHP_PROTO_NHRP_PKT_TRAFFIC_INDICATION);
	if( tx_nhrp_mesg == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	src_nbma_addr.addr_family = tx_vpn->local.if_info.addr_family;
	memcpy(src_nbma_addr.addr.raw,tx_vpn->local.if_info.addr.raw,16);

	if( v_if_addr->addr.addr_family == AF_INET &&
			rx_pkt_d->l2.eth->protocol == RHP_PROTO_ETH_IP ){

		dst_proto_addr.addr_family = AF_INET;
		dst_proto_addr.addr.v4 = rx_pkt_d->l3.iph_v4->src_addr;

		orig_pkt_len = (int)ntohs(rx_pkt_d->l3.iph_v4->total_len);

	}else if( v_if_addr->addr.addr_family == AF_INET6 &&
						rx_pkt_d->l2.eth->protocol == RHP_PROTO_ETH_IPV6 ){

		dst_proto_addr.addr_family = AF_INET6;
		memcpy(dst_proto_addr.addr.v6,rx_pkt_d->l3.iph_v6->src_addr,16);

		orig_pkt_len = (int)(ntohs(rx_pkt_d->l3.iph_v6->payload_len) + sizeof(rhp_proto_ip_v6));

	}else{

		err = -EINVAL;
		goto error;
	}

	if( rx_pkt_d->l3.raw + orig_pkt_len > rx_pkt_d->tail ){
		err = -EINVAL;
		goto error;
	}


	if( orig_pkt_len > rhp_gcfg_nhrp_traffic_indication_orig_pkt_len ){
		orig_pkt_len = rhp_gcfg_nhrp_traffic_indication_orig_pkt_len;
	}


	tx_nhrp_mesg->m.traffic->set_traffic_code(tx_nhrp_mesg,RHP_PROTO_NHRP_TRAFFIC_CODE_NHRP);


	err = tx_nhrp_mesg->m.traffic->set_src_nbma_addr(tx_nhrp_mesg,src_nbma_addr.addr_family,src_nbma_addr.addr.raw);
	if( err ){
		goto error;
	}

	err = tx_nhrp_mesg->m.traffic->set_src_protocol_addr(tx_nhrp_mesg,v_if_addr->addr.addr_family,v_if_addr->addr.addr.raw);
	if( err ){
		goto error;
	}

	err = tx_nhrp_mesg->m.traffic->set_dst_protocol_addr(tx_nhrp_mesg,dst_proto_addr.addr_family,dst_proto_addr.addr.raw);
	if( err ){
		goto error;
	}


	err = tx_nhrp_mesg->m.traffic->set_traffic_org_mesg(tx_nhrp_mesg,orig_pkt_len,rx_pkt_d->l3.raw);
	if( err ){
		goto error;
	}


	{
		nhrp_ext = rhp_nhrp_ext_alloc(RHP_PROTO_NHRP_EXT_TYPE_FORWARD_TRANSIT_NHS_RECORD,1);
		if( nhrp_ext == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = tx_nhrp_mesg->add_extension(tx_nhrp_mesg,nhrp_ext);
		if( err ){
			rhp_nhrp_ext_free(nhrp_ext);
			goto error;
		}
	}

	{
		nhrp_ext = rhp_nhrp_ext_alloc(RHP_PROTO_NHRP_EXT_TYPE_REVERSE_TRANSIT_NHS_RECORD,1);
		if( nhrp_ext == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = tx_nhrp_mesg->add_extension(tx_nhrp_mesg,nhrp_ext);
		if( err ){
			rhp_nhrp_ext_free(nhrp_ext);
			goto error;
		}
	}


	err = _rhp_nhrp_nhs_tx_rep_set_nat_ext(tx_nhrp_mesg,&(tx_vpn->peer_addr),
					&dst_proto_addr,(rhp_gcfg_nhrp_cie_mtu ? (u16)rhp_gcfg_nhrp_cie_mtu : tx_mtu));
	if( err ){
		goto error;
	}


	RHP_TRC(0,RHPTRCID_NHRP_TX_TRAFFIC_INDICATION_ALLOC_RTRN,"xx",tx_vpn,tx_nhrp_mesg);
	return tx_nhrp_mesg;

error:
	if( tx_nhrp_mesg ){
		rhp_nhrp_mesg_unhold(tx_nhrp_mesg);
	}
	RHP_TRC(0,RHPTRCID_NHRP_TX_TRAFFIC_INDICATION_ALLOC_ERR,"x",tx_vpn);
	return NULL;
}

//
// Caller must NOT acquire tx_vpn->lock.
//
int rhp_nhrp_tx_traffic_indication(rhp_vpn* tx_vpn,rhp_packet* rx_pkt_d)
{
	int err = -EINVAL;
	rhp_vpn_realm* tx_rlm = NULL;
	rhp_nhrp_mesg *tx_nhrp_mesg = NULL;
  rhp_ifc_entry* v_ifc = NULL;
	rhp_ifc_addr* if_addr;
	u16 f_addr_family;
  int proto_addr_family = AF_UNSPEC;
  rhp_packet* tx_pkt = NULL;

	RHP_TRC(0,RHPTRCID_NHRP_TX_TRAFFIC_INDICATION,"xxxx",tx_vpn,rx_pkt_d,tx_rlm,v_ifc);

	if( rx_pkt_d->l2.raw == NULL || rx_pkt_d->l3.raw == NULL ){
		RHP_BUG("0x%x, 0x%x",(unsigned long)rx_pkt_d->l2.raw,(unsigned long)rx_pkt_d->l3.raw);
		return -EINVAL;
	}


	if( rx_pkt_d->l2.eth->protocol == RHP_PROTO_ETH_IP ){

		proto_addr_family = AF_INET;

		if( rx_pkt_d->l3.iph_v4->dst_addr == 0xFFFFFFFF ||
				rhp_ip_multicast(AF_INET,(u8*)&(rx_pkt_d->l3.iph_v4->dst_addr)) ){
	  	RHP_TRC(0,RHPTRCID_NHRP_TX_TRAFFIC_INDICATION_V4_BC_MC_ADDR_IGNORED,"xx4",tx_vpn,rx_pkt_d,rx_pkt_d->l3.iph_v4->dst_addr);
			return -EINVAL;
		}

	}else if( rx_pkt_d->l2.eth->protocol == RHP_PROTO_ETH_IPV6 ){

		proto_addr_family = AF_INET6;

		if( rhp_ip_multicast(AF_INET6,rx_pkt_d->l3.iph_v6->dst_addr) ){
	  	RHP_TRC(0,RHPTRCID_NHRP_TX_TRAFFIC_INDICATION_V6_MC_ADDR_IGNORED,"xx6",tx_vpn,rx_pkt_d,rx_pkt_d->l3.iph_v6->dst_addr);
			return -EINVAL;
		}

	}else{
		RHP_BUG("0x%x",ntohs(rx_pkt_d->l2.eth->protocol));
		return -EINVAL;
	}


	RHP_LOCK(&(tx_vpn->lock));

	if( !_rhp_atomic_read(&(tx_vpn->is_active)) ){
		err = -EINVAL;
  	RHP_TRC(0,RHPTRCID_NHRP_TX_TRAFFIC_INDICATION_VPN_NOT_ACTIVE,"x",tx_vpn);
  	goto error;
	}


	if( tx_vpn->local.if_info.addr_family == AF_INET ){

		f_addr_family = RHP_PROTO_NHRP_ADDR_FAMILY_IPV4;

	}else if( tx_vpn->local.if_info.addr_family == AF_INET6 ){

		f_addr_family = RHP_PROTO_NHRP_ADDR_FAMILY_IPV6;

	}else{

		err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_NHRP_TX_TRAFFIC_INDICATION_NO_ITNL_ADDR,"xx",tx_vpn,tx_rlm);
		goto error;
	}


	tx_rlm = tx_vpn->rlm;
	if( tx_rlm == NULL ){
		err = -EINVAL;
  	RHP_TRC(0,RHPTRCID_NHRP_TX_TRAFFIC_INDICATION_VPN_NO_RLM_FOUND,"x",tx_vpn);
  	goto error;
	}

	RHP_LOCK(&(tx_rlm->lock));

	if( !_rhp_atomic_read(&(tx_rlm->is_active)) ){
		err = -EINVAL;
  	RHP_TRC(0,RHPTRCID_NHRP_TX_TRAFFIC_INDICATION_RLM_NOT_ACTIVE,"xx",tx_vpn,tx_rlm);
  	goto error;
	}


	v_ifc = tx_rlm->internal_ifc->ifc;
  if( v_ifc == NULL ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_NHRP_TX_TRAFFIC_INDICATION_NO_V_IFC,"xx",tx_vpn,tx_rlm);
  	goto error;
  }

	RHP_LOCK(&(v_ifc->lock));

	if_addr = _rhp_nhrp_get_internal_addr(v_ifc,proto_addr_family);
	if( if_addr == NULL ){
		err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_NHRP_TX_TRAFFIC_INDICATION_NO_SRC_PROTO_ADDR,"xxx",tx_vpn,rx_pkt_d,tx_rlm);
		goto error;
	}


	if( proto_addr_family == AF_INET &&
			rhp_ip_subnet_broadcast(&(if_addr->addr),AF_INET,(u8*)&(rx_pkt_d->l3.iph_v4->dst_addr)) ){
  	RHP_TRC(0,RHPTRCID_NHRP_TX_TRAFFIC_INDICATION_V4_SUBNET_ADDR_IGNORED,"xxxx4d4",tx_vpn,rx_pkt_d,v_ifc,if_addr,if_addr->addr.addr.v4,if_addr->addr.prefixlen,rx_pkt_d->l3.iph_v4->dst_addr);
		err = -EINVAL;
		goto error;
	}


	tx_nhrp_mesg = _rhp_nhrp_tx_traffic_indication_alloc(tx_vpn,
									f_addr_family,if_addr,rx_pkt_d);
	if( tx_nhrp_mesg == NULL ){
		err = -ENOMEM;
		RHP_BUG("%d",err);
		goto error;
	}


	err = tx_nhrp_mesg->serialize(tx_nhrp_mesg,tx_vpn,0,&tx_pkt);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	tx_nhrp_mesg->tx_pkt_ref = rhp_pkt_hold_ref(tx_pkt);


	RHP_UNLOCK(&(v_ifc->lock));
	RHP_UNLOCK(&(tx_rlm->lock));
	v_ifc = NULL;
	v_ifc = NULL;

	RHP_UNLOCK(&(tx_vpn->lock));


	//
	// All errors are ignored from here.
	//

	{
		// tx_vpn->lock will be acquired in rhp_gre_send().
		rhp_gre_send(tx_vpn,tx_pkt);

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,tx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_TX_TRAFFIC_INDICATION_MESG,"VBE",tx_vpn,tx_nhrp_mesg,err);

		rhp_nhrp_mesg_unhold(tx_nhrp_mesg);
		tx_nhrp_mesg = NULL;

		rhp_pkt_unhold(tx_pkt);
		tx_pkt = NULL;
	}


	RHP_TRC(0,RHPTRCID_NHRP_TX_TRAFFIC_INDICATION_RTRN,"xxxxx",tx_vpn,tx_rlm,v_ifc,tx_nhrp_mesg,tx_pkt);
	return 0;


error:

	if( v_ifc ){
		RHP_UNLOCK(&(v_ifc->lock));
	}
	if( tx_rlm ){
		RHP_UNLOCK(&(tx_rlm->lock));
	}
	RHP_UNLOCK(&(tx_vpn->lock));

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,tx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_TX_TRAFFIC_INDICATION_MESG_ERR,"VBE",tx_vpn,tx_nhrp_mesg,err);
	if( tx_nhrp_mesg ){
		rhp_nhrp_mesg_unhold(tx_nhrp_mesg);
	}

	if( tx_pkt ){

		rhp_pkt_unhold(tx_pkt);
	}

	RHP_TRC(0,RHPTRCID_NHRP_TX_TRAFFIC_INDICATION_ERR,"xxxE",tx_vpn,tx_rlm,v_ifc,err);
	return err;
}

static void _rhp_nhrp_tx_traffic_indication_task(int worker_index,void *ctx)
{
	int err = -EINVAL;
	rhp_packet* rx_pkt_d = (rhp_packet*)ctx;
	rhp_vpn_ref* tx_vpn_ref = (rhp_vpn_ref*)rx_pkt_d->priv;
	rhp_vpn* tx_vpn = RHP_VPN_REF(tx_vpn_ref);

	RHP_TRC(0,RHPTRCID_NHRP_TX_TRAFFIC_INDICATION_TASK,"dxxx",worker_index,rx_pkt_d,tx_vpn_ref,tx_vpn);

	if( !_rhp_atomic_read(&(tx_vpn->is_active)) ){
		err = -EINVAL;
		goto error;
	}

	err = rhp_nhrp_tx_traffic_indication(tx_vpn,rx_pkt_d);
	if( err ){
		goto error;
	}

error:
	rhp_pkt_unhold(rx_pkt_d);
	rhp_vpn_unhold(tx_vpn_ref);

	RHP_TRC(0,RHPTRCID_NHRP_TX_TRAFFIC_INDICATION_TASK_RTRN,"xxxE",rx_pkt_d,tx_vpn_ref,tx_vpn,err);
	return;
}

int rhp_nhrp_invoke_tx_traffic_indication_task(rhp_vpn* tx_vpn,rhp_packet* rx_pkt)
{
	int err = -EINVAL;
	rhp_packet* rx_pkt_d = rhp_pkt_dup(rx_pkt);

	RHP_TRC(0,RHPTRCID_NHRP_INVOKE_TX_TRAFFIC_INDICATION_TASK,"xxx",rx_pkt,tx_vpn,rx_pkt_d);

	if( rx_pkt_d == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	rx_pkt_d->priv = rhp_vpn_hold_ref(tx_vpn);

	err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_3,
					_rhp_nhrp_tx_traffic_indication_task,rx_pkt_d);

	if( err ){
		RHP_BUG("%d",err);
		rhp_pkt_unhold(rx_pkt_d);
		goto error;
	}

	RHP_TRC(0,RHPTRCID_NHRP_INVOKE_TX_TRAFFIC_INDICATION_TASK_RTRN,"xxx",rx_pkt,tx_vpn,rx_pkt_d);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_INVOKE_TX_TRAFFIC_INDICATION_TASK_ERR,"xxxE",rx_pkt,tx_vpn,rx_pkt_d,err);
	return err;
}

static int _rhp_nhrp_rx_traffic_indication(rhp_nhrp_mesg* rx_nhrp_mesg,rhp_vpn* rx_vpn)
{
	int err = -EINVAL;
	rhp_nhrp_req_session* nhrp_sess = NULL;
	rhp_ip_addr rslv_proto_addr;

	RHP_TRC(0,RHPTRCID_NHRP_RX_TRAFFIC_INDICATION,"xxddd",rx_nhrp_mesg,rx_vpn,rx_vpn->nhrp.role,rx_vpn->nhrp.dmvpn_enabled,rhp_gcfg_dmvpn_dont_handle_traffic_indication);

	if( rhp_gcfg_dmvpn_dont_handle_traffic_indication ){
		err = 0;
		goto error;
	}

	if( rx_vpn->nhrp.role != RHP_NHRP_SERVICE_CLIENT ||
			!rx_vpn->nhrp.dmvpn_enabled ){
		err = 0;
		goto error;
	}


	RHP_LOCK(&rhp_nhrp_lock);

	memset(&rslv_proto_addr,0,sizeof(rhp_ip_addr));

	err = rx_nhrp_mesg->m.traffic->get_org_mesg_addrs(rx_nhrp_mesg,NULL,&rslv_proto_addr);
	if( err ){
		RHP_UNLOCK(&rhp_nhrp_lock);
		goto error;
	}

	nhrp_sess =  _rhp_nhrp_req_sess_get(
									rx_vpn->vpn_realm_id,
									RHP_PROTO_NHRP_PKT_RESOLUTION_REQ,
									rslv_proto_addr.addr_family,rslv_proto_addr.addr.raw);
	if( nhrp_sess ){
		err = -EEXIST;
		RHP_UNLOCK(&rhp_nhrp_lock);
		RHP_TRC(0,RHPTRCID_NHRP_RX_TRAFFIC_INDICATION_CACHE_FOUND,"xx",rx_nhrp_mesg,rx_vpn);
		goto error;
	}

	RHP_UNLOCK(&rhp_nhrp_lock);

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,rx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_RX_TRAFFIC_INDICATION,"VB",rx_vpn,rx_nhrp_mesg);


	err = _rhp_nhrp_invoke_tx_resolution_req(rx_nhrp_mesg,rx_vpn);
	if( err ){
		goto error;
	}


	RHP_TRC(0,RHPTRCID_NHRP_RX_TRAFFIC_INDICATION_RTRN,"xx",rx_nhrp_mesg,rx_vpn);
	return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,rx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_RX_TRAFFIC_INDICATION_ERR,"VBE",rx_vpn,rx_nhrp_mesg,err);

	RHP_TRC(0,RHPTRCID_NHRP_RX_TRAFFIC_INDICATION_ERR,"xxE",rx_nhrp_mesg,rx_vpn,err);
	return err;
}



static u32 _rhp_nhrp_tx_request_id = 0;

u32 rhp_nhrp_tx_next_request_id()
{
	u32 ret;

	RHP_LOCK(&rhp_nhrp_lock);

	ret = _rhp_nhrp_tx_request_id++;

	RHP_UNLOCK(&rhp_nhrp_lock);

	RHP_TRC(0,RHPTRCID_NHRP_TX_NEXT_REQUEST_ID,"j",ret);
	return ret;
}


static void _rhp_rx_nhrp_from_vpn_task(rhp_packet* rx_pkt)
{
	int err = -EINVAL;
	rhp_nhrp_mesg* rx_nhrp_mesg = NULL;
	rhp_vpn* rx_vpn = RHP_VPN_REF(rx_pkt->esp_rx_vpn_ref);
	rhp_packet* tx_pkt_rep = NULL;

	RHP_TRC(0,RHPTRCID_RX_NHRP_FROM_VPN_TASK,"xxppa",rx_pkt,rx_vpn,((((u8*)rx_pkt->l3.nhrp_greh) + sizeof(rhp_proto_nhrp)) <= rx_pkt->end ? sizeof(rhp_proto_gre) : 0),(u8*)rx_pkt->l3.nhrp_greh,((((u8*)rx_pkt->l4.nhrph) + sizeof(rhp_proto_nhrp)) <= rx_pkt->end ? sizeof(rhp_proto_nhrp) : 0),(u8*)rx_pkt->l4.nhrph,(rx_pkt->tail - (u8*)rx_pkt->l3.nhrp_greh > 0 ? rx_pkt->tail - (u8*)rx_pkt->l3.nhrp_greh : 0),RHP_TRC_FMT_A_GRE_NHRP,0,0,(u8*)rx_pkt->l3.nhrp_greh);
	rhp_pkt_trace_dump("rhp_rx_nhrp_from_vpn",rx_pkt);


	if( rx_pkt->type != RHP_PKT_GRE_NHRP ){
		RHP_BUG("%d",rx_pkt->type);
		err = -EINVAL;
		goto error;
	}

	if( rx_vpn == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}


	RHP_LOCK(&(rx_vpn->lock));

	if( !_rhp_atomic_read(&(rx_vpn->is_active)) ){
		err = -EINVAL;
		RHP_TRC(0,RHPTRCID_RX_NHRP_FROM_VPN_TASK_VPN_NOT_ACTIVE,"xx",rx_pkt,rx_vpn);
		goto error;
	}

	if( rx_vpn->nhrp.role == RHP_NHRP_SERVICE_NONE ){
		err = -EINVAL;
		RHP_TRC(0,RHPTRCID_RX_NHRP_FROM_VPN_TASK_NHRP_DISABLED,"xxb",rx_pkt,rx_vpn,rx_pkt->l4.nhrph->fixed.packet_type);
		goto error;
	}

	if( rx_vpn->nhrp.role != RHP_NHRP_SERVICE_SERVER &&
			(rx_pkt->l4.nhrph->fixed.packet_type == RHP_PROTO_NHRP_PKT_REGISTRATION_REQ ||
			 rx_pkt->l4.nhrph->fixed.packet_type == RHP_PROTO_NHRP_PKT_PURGE_REQ ) ){
		err = RHP_STATUS_NHRP_NOT_NHS;
		RHP_TRC(0,RHPTRCID_RX_NHRP_FROM_VPN_TASK_NOT_NHS,"xxb",rx_pkt,rx_vpn,rx_pkt->l4.nhrph->fixed.packet_type);
		goto error;
	}

	if( rx_vpn->nhrp.role != RHP_NHRP_SERVICE_CLIENT &&
			(rx_pkt->l4.nhrph->fixed.packet_type == RHP_PROTO_NHRP_PKT_TRAFFIC_INDICATION ||
			 rx_pkt->l4.nhrph->fixed.packet_type == RHP_PROTO_NHRP_PKT_REGISTRATION_REP ||
			 rx_pkt->l4.nhrph->fixed.packet_type == RHP_PROTO_NHRP_PKT_PURGE_REP) ){
		err = RHP_STATUS_NHRP_NOT_NHC;
		RHP_TRC(0,RHPTRCID_RX_NHRP_FROM_VPN_TASK_NOT_NHC,"xxb",rx_pkt,rx_vpn,rx_pkt->l4.nhrph->fixed.packet_type);
		goto error;
	}

	err = rhp_nhrp_mesg_new_rx(rx_pkt,&rx_nhrp_mesg);
	if( err ){
		goto error;
	}

	// rx_vpn->nhrp.key may be NULL if not cofigured.
	if( rx_nhrp_mesg->ext_auth_check_key(rx_nhrp_mesg,rx_vpn->nhrp.key_len,rx_vpn->nhrp.key) ){

		err = RHP_STATUS_NHRP_INVALID_EXT_AUTH_KEY;
		RHP_TRC(0,RHPTRCID_RX_NHRP_FROM_VPN_TASK_INVALID_EXT_AUTH_KEY,"xxb",rx_pkt,rx_vpn,rx_pkt->l4.nhrph->fixed.packet_type);

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,rx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_RX_INVALID_AUTHENTICATION_EXT,"VB",rx_vpn,rx_nhrp_mesg);

		goto error;
	}

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,rx_vpn->vpn_realm_id,RHP_LOG_ID_NHRP_RX_MESG,"VB",rx_vpn,rx_nhrp_mesg);


	switch( rx_nhrp_mesg->get_packet_type(rx_nhrp_mesg) ){

	case RHP_PROTO_NHRP_PKT_RESOLUTION_REQ:

		err = _rhp_nhrp_rx_resolution_req(rx_nhrp_mesg,rx_vpn);
		if( err ){
			goto error;
		}

		break;

	case RHP_PROTO_NHRP_PKT_RESOLUTION_REP:

		err = _rhp_nhrp_invoke_rx_resolution_rep(rx_nhrp_mesg,rx_vpn);
		if( err ){
			goto error;
		}

		break;

	case RHP_PROTO_NHRP_PKT_REGISTRATION_REQ:
	{
		int cie_err_code = RHP_PROTO_NHRP_CIE_CODE_SUCCESS;
		int tx_mtu;

		err = _rhp_nhrp_rx_registration_req(rx_nhrp_mesg,rx_vpn,&tx_mtu);
		if( err == RHP_STATUS_NHRP_RX_DUPLICATED_ADDR ){

			cie_err_code = RHP_PROTO_NHRP_CIE_CODE_ADDR_COLLISION;

		}else if( err == RHP_STATUS_NHRP_MAX_CACHE_NUM_REACHED || err == -ENOMEM ){

			cie_err_code = RHP_PROTO_NHRP_CIE_CODE_NO_RESOURCE;

		}else if( err ){

			cie_err_code = RHP_PROTO_NHRP_CIE_CODE_ADMIN_PROHIBITED;
		}

		err = _rhp_nhrp_tx_registration_rep(rx_nhrp_mesg,rx_vpn,tx_mtu,cie_err_code,&tx_pkt_rep);
		if( err ){
			goto error;
		}
	}
		break;

	case RHP_PROTO_NHRP_PKT_REGISTRATION_REP:

		err = _rhp_nhrp_rx_registration_rep(rx_nhrp_mesg,rx_vpn);
		if( err ){
			goto error;
		}

		break;

	case RHP_PROTO_NHRP_PKT_PURGE_REQ:
	{
		u16 m_flags = 0;

		err = _rhp_nhrp_rx_purge_req(rx_nhrp_mesg,rx_vpn,&m_flags);
		if( err == -EINVAL ){
			// Trace...
		}

		if( !RHP_PROTO_NHRP_PRG_FLAG_N_NO_REPLY(m_flags) ){

			err = _rhp_nhrp_tx_purge_rep(rx_nhrp_mesg,rx_vpn,&tx_pkt_rep);
			if( err ){
				goto error;
			}
		}
	}
		break;

	case RHP_PROTO_NHRP_PKT_PURGE_REP:

		err = _rhp_nhrp_rx_purge_rep(rx_nhrp_mesg,rx_vpn);
		if( err ){
			goto error;
		}

		break;

	case RHP_PROTO_NHRP_PKT_ERROR_INDICATION:

		break;

	case RHP_PROTO_NHRP_PKT_TRAFFIC_INDICATION:

		err = _rhp_nhrp_rx_traffic_indication(rx_nhrp_mesg,rx_vpn);
		if( err ){
			goto error;
		}

		break;

	default:
		err = RHP_STATUS_NHRP_NOT_SUPPORTED_ATTR;
		RHP_TRC(0,RHPTRCID_RX_NHRP_FROM_VPN_TASK_UNSUP_PKT_TYPE,"xx",rx_pkt,rx_vpn);
		goto error;
	}

	RHP_UNLOCK(&(rx_vpn->lock));


	if( tx_pkt_rep ){

		// rx_vpn->lock will be acquired by rhp_gre_send().
		rhp_gre_send(rx_vpn,tx_pkt_rep);
		rhp_pkt_unhold(tx_pkt_rep);
	}

	rhp_nhrp_mesg_unhold(rx_nhrp_mesg);
	rhp_pkt_unhold(rx_pkt);

	RHP_TRC(0,RHPTRCID_RX_NHRP_FROM_VPN_TASK_RTRN,"xxxx",rx_pkt,rx_vpn,tx_pkt_rep,rx_nhrp_mesg);
	return;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(rx_vpn ? rx_vpn->vpn_realm_id : 0),RHP_LOG_ID_NHRP_RX_INVALID_MESG,"VE",rx_vpn,err);

	if( rx_vpn ){
		RHP_UNLOCK(&(rx_vpn->lock));
	}
	if( rx_nhrp_mesg ){
		rhp_nhrp_mesg_unhold(rx_nhrp_mesg);
	}
	if( tx_pkt_rep ){
		rhp_pkt_unhold(tx_pkt_rep);
	}

	rhp_pkt_unhold(rx_pkt);

	RHP_TRC(0,RHPTRCID_RX_NHRP_FROM_VPN_TASK_ERR,"xxxxE",rx_pkt,rx_vpn,tx_pkt_rep,rx_nhrp_mesg,err);
	return;
}

int rhp_rx_nhrp_from_vpn(unsigned long vpn_realm_id,rhp_vpn* rx_vpn,rhp_packet* rx_pkt)
{
	int err;

	RHP_TRC(0,RHPTRCID_RX_NHRP_FROM_VPN,"uxx",vpn_realm_id,rx_pkt,rx_vpn);

	rx_pkt->process_packet = _rhp_rx_nhrp_from_vpn_task;

	rhp_pkt_hold(rx_pkt);

  err = rhp_wts_sta_invoke_task(RHP_WTS_DISP_RULE_NETSOCK,RHP_WTS_STA_TASK_NAME_PKT,
			RHP_WTS_DISP_LEVEL_HIGH_2,rx_pkt,rx_pkt);
  if( err ){
  	rhp_pkt_unhold(rx_pkt);
  }

	RHP_TRC(0,RHPTRCID_RX_NHRP_FROM_VPN_RTRN,"uxxE",vpn_realm_id,rx_pkt,rx_vpn,err);
  return err;
}


void rhp_nhrp_addr_map_dump(char* label,rhp_nhrp_addr_map* nhrp_addr_map)
{
	rhp_ip_addr nbma_addr, proto_addr;

	_RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
  if( !_RHP_TRC_COND(_rhp_trc_user_id(),0) ){
    return;
  }

  if( nhrp_addr_map == NULL ){
    RHP_TRC(0,RHPTRCID_NHRP_ADDR_MAP_DUMP_NULL,"s",label);
    return;
  }

	memset(&nbma_addr,0,sizeof(rhp_ip_addr));
	memset(&proto_addr,0,sizeof(rhp_ip_addr));

	nbma_addr.addr_family = nhrp_addr_map->nbma_addr_family;
	memcpy(nbma_addr.addr.raw,nhrp_addr_map->nbma_addr.raw,16);

	proto_addr.addr_family = nhrp_addr_map->proto_addr_family;
	memcpy(proto_addr.addr.raw,nhrp_addr_map->proto_addr.raw,16);


	RHP_TRC(0,RHPTRCID_NHRP_ADDR_MAP_DUMP,"sx",label,nhrp_addr_map);
  rhp_ip_addr_dump("nhrp_addr_map.nbma_addr",&nbma_addr);
  rhp_ip_addr_dump("nhrp_addr_map.proto_addr",&proto_addr);

	return;
}


static int _rhp_nhrp_update_addr_task_vpn_cb(rhp_vpn* vpn,void* ctx)
{
	int err = -EINVAL;
	rhp_nhrp_addr_map *nhc_addr_map, *nhc_addr_map_p;
	rhp_vpn_realm* rlm = NULL;
	rhp_ifc_entry* v_ifc = NULL;
	rhp_ifc_addr* v_ifc_addr = NULL;
	rhp_ip_addr_list* purged_addrs_head = NULL;
	int n = 0, forcedly = 0;

	RHP_TRC(0,RHPTRCID_NHRP_UPDATE_ADDR_TASK_VPN_CB,"xx",vpn,ctx);


	RHP_LOCK(&(vpn->lock));

	if( !_rhp_atomic_read(&(vpn->is_active))){
		err = -EINVAL;
		RHP_TRC(0,RHPTRCID_NHRP_UPDATE_ADDR_TASK_VPN_CB_VPN_NOT_ACTIVE,"xx",vpn,ctx);
		goto error;
	}


	forcedly = vpn->nhrp.nhc_update_addr_forcedly;
	vpn->nhrp.nhc_update_addr_forcedly = 0;


	if( vpn->nhrp.role != RHP_NHRP_SERVICE_CLIENT ){
		err = 0;
		RHP_TRC(0,RHPTRCID_NHRP_UPDATE_ADDR_TASK_VPN_CB_VPN_NOT_NHC,"xxd",vpn,ctx,vpn->nhrp.role);
		goto error;
	}


	rlm = vpn->rlm;
	if( rlm == NULL ){
		err = -EINVAL;
		RHP_TRC(0,RHPTRCID_NHRP_UPDATE_ADDR_TASK_VPN_CB_VPN_NO_RLM_FOUND,"xx",vpn,ctx);
		goto error;
	}

	RHP_LOCK(&(rlm->lock));

	if( !_rhp_atomic_read(&(rlm->is_active))){
		err = -EINVAL;
		RHP_UNLOCK(&(rlm->lock));
		RHP_TRC(0,RHPTRCID_NHRP_UPDATE_ADDR_TASK_VPN_CB_VPN_RLM_NOT_ACTIVE,"xxx",vpn,ctx,rlm);
		goto error;
	}

	v_ifc = rlm->internal_ifc->ifc;
	if( v_ifc == NULL ){
		err = -EINVAL;
		RHP_UNLOCK(&(rlm->lock));
		RHP_TRC(0,RHPTRCID_NHRP_UPDATE_ADDR_TASK_VPN_CB_VPN_NO_V_IFC,"xxx",vpn,ctx,rlm);
		goto error;
	}


	RHP_LOCK(&(v_ifc->lock));

	v_ifc->dump_no_lock("_rhp_nhrp_update_addr_task_vpn_cb",v_ifc);


	nhc_addr_map = vpn->nhrp.nhc_addr_maps_head;
	while( nhc_addr_map ){

		int flag = 0;

		rhp_nhrp_addr_map_dump("purge_addr_task: nhc_addr_map",nhc_addr_map);
		rhp_if_entry_dump("purge_addr_task: vpn->local.if_info",&(vpn->local.if_info));

		if( !forcedly ){

			if( vpn->local.if_info.addr_family == nhc_addr_map->nbma_addr_family &&
					(vpn->local.if_info.addr_family == AF_INET ?
							(vpn->local.if_info.addr.v4 == nhc_addr_map->nbma_addr.v4) :
							(!memcmp(vpn->local.if_info.addr.v6,nhc_addr_map->nbma_addr.v6,16))) ){

				RHP_TRC(0,RHPTRCID_NHRP_UPDATE_ADDR_TASK_VPN_CB_VPN_ADDR_MAP_NBMA_ADDR_FOUND,"xxxxxx",vpn,ctx,rlm,v_ifc,nhc_addr_map,&(vpn->local.if_info));

				flag |= 0x1;
			}

			v_ifc_addr = v_ifc->ifc_addrs;
			while( v_ifc_addr ){

				rhp_ip_addr_dump("purge_addr_task: v_ifc_addr",&(v_ifc_addr->addr));

				if( !rhp_ip_addr_cmp_value(&(v_ifc_addr->addr),
							(nhc_addr_map->proto_addr_family == AF_INET ? 4 : 16),
							nhc_addr_map->proto_addr.raw) ){

					RHP_TRC(0,RHPTRCID_NHRP_UPDATE_ADDR_TASK_VPN_CB_VPN_ADDR_MAP_PROTO_ADDR_FOUND,"xxxxxxx",vpn,ctx,rlm,v_ifc,nhc_addr_map,v_ifc_addr,&(v_ifc_addr->addr));

					flag |= 0x2;
					break;
				}

				v_ifc_addr = v_ifc_addr->lst_next;
			}
		}

		if( flag != 3 ){
			RHP_TRC(0,RHPTRCID_NHRP_UPDATE_ADDR_TASK_VPN_CB_VPN_PURGE_ADDR_MAP,"xxxxx",vpn,ctx,rlm,v_ifc,nhc_addr_map);
			nhc_addr_map->flag = 1;
		}

		nhc_addr_map = nhc_addr_map->next;
	}

	RHP_UNLOCK(&(v_ifc->lock));
	RHP_UNLOCK(&(rlm->lock));


	nhc_addr_map_p = NULL;
	nhc_addr_map = vpn->nhrp.nhc_addr_maps_head;
	while( nhc_addr_map ){

		rhp_nhrp_addr_map* nhc_addr_map_n = nhc_addr_map->next;

		if( nhc_addr_map->flag ){

			rhp_ip_addr_list* purged_addr_lst = (rhp_ip_addr_list*)_rhp_malloc(sizeof(rhp_ip_addr_list));
			if( purged_addr_lst == NULL ){

				RHP_BUG("");

			}else{

				memset(purged_addr_lst,0,sizeof(rhp_ip_addr_list));

				purged_addr_lst->ip_addr.addr_family = nhc_addr_map->proto_addr_family;
				memcpy(purged_addr_lst->ip_addr.addr.raw,nhc_addr_map->proto_addr.raw,16);

				purged_addr_lst->next = purged_addrs_head;
				purged_addrs_head = purged_addr_lst;
			}

			if( nhc_addr_map_p == NULL ){
				vpn->nhrp.nhc_addr_maps_head = nhc_addr_map_n;
			}else{
				nhc_addr_map_p->next = nhc_addr_map_n;
			}

			_rhp_free(nhc_addr_map);

		}else{

			nhc_addr_map_p = nhc_addr_map;
		}

		nhc_addr_map = nhc_addr_map_n;
	}

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_NHRP_UPDATE_ADDR,"V",vpn);

	RHP_UNLOCK(&(vpn->lock));


	{
		rhp_ip_addr_list* purged_addr_lst = purged_addrs_head;

		while( purged_addr_lst ){

			rhp_ip_addr_list* purged_addr_lst_n = purged_addr_lst->next;


			RHP_LOCK(&rhp_nhrp_lock);
			{
				rhp_nhrp_req_session* nhrp_sess = _rhp_nhrp_req_sess_get(vpn->vpn_realm_id,0,
							purged_addr_lst->ip_addr.addr_family,purged_addr_lst->ip_addr.addr.raw);

				if( nhrp_sess ){

					err = rhp_timer_delete(&(nhrp_sess->timer));
					if( err ){
						nhrp_sess->done = 1;
					}else{
						_rhp_nhrp_req_sess_unhold(nhrp_sess);
					}

					if( !_rhp_nhrp_req_sess_delete(nhrp_sess) ){
						_rhp_nhrp_req_sess_unhold(nhrp_sess);
					}else{
						RHP_BUG("");
					}
				}
			}
			RHP_UNLOCK(&rhp_nhrp_lock);


			err = rhp_nhrp_tx_purge_req(vpn,&(purged_addr_lst->ip_addr));
			if( err ){
				RHP_BUG("%d",err);
			}else{
				n++;
			}

			_rhp_free(purged_addr_lst);

			purged_addr_lst = purged_addr_lst_n;
		}
	}

	if( n ){

		RHP_LOCK(&(vpn->lock));
		{
			vpn->quit_nhc_registration_timer(vpn);

			vpn->nhrp.nhc_pending_purge_reqs = n;

			vpn->nhrp.nhc_update_addr_pending = 0;
		}
		RHP_UNLOCK(&(vpn->lock));
	}

	RHP_TRC(0,RHPTRCID_NHRP_UPDATE_ADDR_TASK_VPN_CB_VPN_RTRN,"xxxxd",vpn,ctx,rlm,v_ifc,forcedly);
	return 0;

error:

	if( err ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_NHRP_UPDATE_ADDR_ERR,"VE",vpn,err);
	}

	vpn->nhrp.nhc_update_addr_pending = 0;

	RHP_UNLOCK(&(vpn->lock));

	RHP_TRC(0,RHPTRCID_NHRP_UPDATE_ADDR_TASK_VPN_CB_VPN_ERR,"xxxxdE",vpn,ctx,rlm,v_ifc,forcedly,err);
	return 0;
}

static void _rhp_nhrp_update_addr_task_any(void *ctx)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_NHRP_UPDATE_ADDR_TASK_ANY,"x",ctx);

	err = rhp_vpn_enum(0,_rhp_nhrp_update_addr_task_vpn_cb,NULL);
	if( err ){
		RHP_TRC(0,RHPTRCID_NHRP_UPDATE_ADDR_TASK_VPN_ENUM_ANY_ERR,"xE",ctx,err);
		goto error;
	}

	RHP_LOCK(&rhp_nhrp_lock);
	_rhp_nhrp_update_addr_task_pending = 0;
	RHP_UNLOCK(&rhp_nhrp_lock);

	RHP_TRC(0,RHPTRCID_NHRP_UPDATE_ADDR_TASK_ANY_RTRN,"x",ctx);
	return;

error:

	RHP_LOCK(&rhp_nhrp_lock);
	_rhp_nhrp_update_addr_task_pending = 0;
	RHP_UNLOCK(&rhp_nhrp_lock);

	RHP_TRC(0,RHPTRCID_NHRP_UPDATE_ADDR_TASK_ANY_ERR,"xE",ctx,err);
	return;
}

static void _rhp_nhrp_update_addr_task_vpn(void *ctx)
{
	int err = -EINVAL;
	rhp_vpn_ref* vpn_ref = (rhp_vpn_ref*)ctx;
	rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);

	RHP_TRC(0,RHPTRCID_NHRP_UPDATE_ADDR_TASK_VPN,"xx",ctx,vpn);

	// vpn->lock will be acquired by this cb.
	err = _rhp_nhrp_update_addr_task_vpn_cb(vpn,NULL);
	if( err ){
		RHP_TRC(0,RHPTRCID_NHRP_UPDATE_ADDR_TASK_VPN_ERR,"xxE",ctx,vpn,err);
		goto error;
	}

	rhp_vpn_unhold(vpn_ref);

	RHP_TRC(0,RHPTRCID_NHRP_UPDATE_ADDR_TASK_VPN_RTRN,"xx",ctx,vpn);
	return;

error:

	rhp_vpn_unhold(vpn_ref);

	RHP_TRC(0,RHPTRCID_NHRP_UPDATE_ADDR_TASK_VPN_ERR,"xxE",ctx,vpn,err);
	return;
}

// vpn may be NULL. It means any vpns.
int rhp_nhrp_invoke_update_addr_task(rhp_vpn* vpn,int forcedly,int conv_time)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_NHRP_INVOKE_UPDATE_ADDR_TASK,"dxdd",conv_time,vpn,forcedly,_rhp_nhrp_update_addr_task_pending);

	if( vpn == NULL ){

		RHP_LOCK(&rhp_nhrp_lock);

		if( _rhp_nhrp_update_addr_task_pending ){

			RHP_TRC(0,RHPTRCID_NHRP_INVOKE_UPDATE_ADDR_TASK_PENDING,"");

			RHP_UNLOCK(&rhp_nhrp_lock);
			err = 0;

			goto error;
		}

		err = rhp_timer_oneshot(_rhp_nhrp_update_addr_task_any,NULL,(time_t)conv_time);
		if( err ){

			RHP_BUG("%d",err);

			RHP_UNLOCK(&rhp_nhrp_lock);
			goto error;
		}

		_rhp_nhrp_update_addr_task_pending = 1;

		RHP_UNLOCK(&rhp_nhrp_lock);

	}else{

		rhp_vpn_ref* vpn_ref = NULL;

		vpn->nhrp.nhc_update_addr_forcedly = forcedly;

		if( vpn->nhrp.nhc_update_addr_pending ){
			err = 0;
			RHP_TRC(0,RHPTRCID_NHRP_INVOKE_UPDATE_ADDR_TASK_VPN_PENDING,"x",vpn);
			goto error;
		}

		vpn_ref = rhp_vpn_hold_ref(vpn);
		err = rhp_timer_oneshot(_rhp_nhrp_update_addr_task_vpn,vpn_ref,(time_t)conv_time);
		if( err ){
			rhp_vpn_unhold(vpn_ref);
			RHP_BUG("%d",err);
			goto error;
		}

		vpn->nhrp.nhc_update_addr_pending = 1;
	}

	RHP_TRC(0,RHPTRCID_NHRP_INVOKE_UPDATE_ADDR_TASK_RTRN,"x",vpn);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_INVOKE_UPDATE_ADDR_TASK_ERR,"xE",vpn,err);
	return err;
}



static void _rhp_nhrp_cache_flush_task(int worker_index,void *ctx)
{
	rhp_vpn* vpn_ref = (rhp_vpn_ref*)ctx;
	rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);

  RHP_TRC(0,RHPTRCID_NHRP_CACHE_FLUSH_TASK,"dxx",worker_index,vpn,vpn_ref);

  //
  // vpn may be already destroyed. Don't touch the object itself.
  //

	rhp_nhrp_cache_flush_by_vpn(vpn);

	rhp_ip_routing_nhrp_flush_cache_by_vpn(vpn);

	rhp_vpn_unhold(vpn_ref);

  RHP_TRC(0,RHPTRCID_NHRP_CACHE_FLUSH_TASK_RTRN,"xx",vpn,vpn_ref);
	return;
}

int rhp_nhrp_cache_invoke_flush_task(rhp_vpn* vpn)
{
	int err;
	rhp_vpn_ref* vpn_ref;

  RHP_TRC(0,RHPTRCID_NHRP_CACHE_INVOKE_FLUSH_TASK,"x",vpn);

  vpn_ref = rhp_vpn_hold_ref(vpn);

  err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_1,
  				_rhp_nhrp_cache_flush_task,(void*)vpn_ref);
	if( err ){
		RHP_BUG("%d",err);
		rhp_vpn_unhold(vpn_ref);
	}

  RHP_TRC(0,RHPTRCID_NHRP_CACHE_INVOKE_FLUSH_TASK_RTRN,"xxE",vpn,vpn_ref,err);
	return err;
}


static u32 _rhp_nhrp_dmvpn_conn_shortcut_disp_hash(void *key_seed,int* err)
{
	u32 ret = 0;
	rhp_nhrp_mesg* rx_nhrp_mesg = (rhp_nhrp_mesg*)key_seed;
	rhp_ip_addr src_nbma_addr;

	memset(&src_nbma_addr,0,sizeof(rhp_ip_addr));

	*err = rx_nhrp_mesg->m.mandatory->get_src_nbma_addr(rx_nhrp_mesg,&src_nbma_addr);
	if( *err ){
		return 0;
	}

	if( src_nbma_addr.addr_family == AF_INET ){
		ret = _rhp_hash_ipv4_1(src_nbma_addr.addr.v4,_rhp_dmvpn_conn_shortcut_rnd);
	}else if( src_nbma_addr.addr_family == AF_INET6 ){
		ret = _rhp_hash_ipv6_1(src_nbma_addr.addr.v6,_rhp_dmvpn_conn_shortcut_rnd);
	}else{
		*err = -EINVAL;
		return 0;
	}

	*err = 0;
	return ret;
}

int rhp_nhrp_init()
{
	int err;

  if( rhp_random_bytes((u8*)&_rhp_nhrp_hashtbl_rnd,sizeof(_rhp_nhrp_hashtbl_rnd)) ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( rhp_random_bytes((u8*)&_rhp_nhrp_req_sess_hashtbl_rnd,sizeof(_rhp_nhrp_req_sess_hashtbl_rnd)) ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( rhp_random_bytes((u8*)&_rhp_dmvpn_conn_shortcut_rnd,sizeof(_rhp_dmvpn_conn_shortcut_rnd)) ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( rhp_random_bytes((u8*)&_rhp_nhrp_tx_request_id,sizeof(_rhp_nhrp_tx_request_id)) ){
    RHP_BUG("");
    return -EINVAL;
  }


  _rhp_mutex_init("NRT",&(rhp_nhrp_lock));

  _rhp_nhrp_cache_hash_tbl
  	= (rhp_nhrp_cache**)_rhp_malloc(sizeof(rhp_nhrp_cache*)*rhp_gcfg_nhrp_cache_hash_size);
  if( _rhp_nhrp_cache_hash_tbl == NULL ){
  	RHP_BUG("");
  	return -ENOMEM;
  }
  memset(_rhp_nhrp_cache_hash_tbl,0,sizeof(rhp_nhrp_cache*)*rhp_gcfg_nhrp_cache_hash_size);


  memset(&_rhp_nhrp_list_head,0,sizeof(rhp_nhrp_cache));
  _rhp_nhrp_list_head.tag[0] = '#';
  _rhp_nhrp_list_head.tag[1] = 'N';
  _rhp_nhrp_list_head.tag[2] = 'R';
  _rhp_nhrp_list_head.tag[3] = 'T';


  _rhp_nhrp_req_sess_hash_tbl
  	= (rhp_nhrp_req_session**)_rhp_malloc(sizeof(rhp_nhrp_req_session*)*rhp_gcfg_nhrp_cache_hash_size);
  if( _rhp_nhrp_req_sess_hash_tbl == NULL ){
  	RHP_BUG("");
  	return -ENOMEM;
  }
  memset(_rhp_nhrp_req_sess_hash_tbl,0,sizeof(rhp_nhrp_req_session*)*rhp_gcfg_nhrp_cache_hash_size);


  err = rhp_wts_register_disp_rule(RHP_WTS_DISP_RULE_DMVPN_HANDLE_SHORTCUT,
  		_rhp_nhrp_dmvpn_conn_shortcut_disp_hash);
  if( err ){
  	RHP_BUG("%d",err);
  	return err;
  }


  rhp_timer_init(&(_rhp_nhrp_cache_timer),_rhp_nhrp_cache_aging_timer,NULL);
  rhp_timer_add(&(_rhp_nhrp_cache_timer),(time_t)rhp_gcfg_nhrp_cache_aging_interval);

#ifdef RHP_DBG_NHRP_TX_REG_REQ_WD
  rhp_timer_init(&(_rhp_nhrp_tx_registration_req_wd),_rhp_nhrp_tx_registration_req_wd_timer,NULL);
  rhp_timer_add(&(_rhp_nhrp_tx_registration_req_wd),_rhp_nhrp_tx_registration_req_wd_interval);
#endif // RHP_DBG_NHRP_TX_REG_REQ_WD

  RHP_TRC(0,RHPTRCID_NHRP_INIT,"");
  return 0;
}

int rhp_nhrp_cleanup()
{
  _rhp_mutex_destroy(&(rhp_nhrp_lock));

  RHP_TRC(0,RHPTRCID_NHRP_CLEANUP,"");
  return 0;
}
