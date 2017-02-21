/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.

	You can redistribute and/or modify this software under the
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

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
#include <byteswap.h>
#include <net/if.h>
#include <arpa/inet.h>


#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_protocol.h"
#include "rhp_packet.h"
#include "rhp_netsock.h"
#include "rhp_config.h"
#include "rhp_vpn.h"
#include "rhp_ikev2_mesg.h"
#include "rhp_ikev2.h"
#include "rhp_wthreads.h"

extern rhp_mutex_t rhp_vpn_lock;


static rhp_internal_address* _rhp_internal_address_htbl_peerid[RHP_VPN_HASH_TABLE_SIZE];
static rhp_internal_address* _rhp_internal_address_htbl_eap_peerid[RHP_VPN_HASH_TABLE_SIZE];
static rhp_internal_address* _rhp_internal_address_htbl_addr_v4[RHP_VPN_HASH_TABLE_SIZE];
static rhp_internal_address* _rhp_internal_address_htbl_addr_v6[RHP_VPN_HASH_TABLE_SIZE];
static rhp_internal_address _rhp_internal_address_list_head;
static u32 _rhp_internal_address_htbl_rnd;

static rhp_timer _rhp_vpn_internal_address_timer;
static void _rhp_vpn_internal_address_aging_timer(void *ctx,rhp_timer *timer);


int rhp_vpn_addr_pool_init()
{
  if( rhp_random_bytes((u8*)&_rhp_internal_address_htbl_rnd,sizeof(_rhp_internal_address_htbl_rnd)) ){
    RHP_BUG("");
    return -EINVAL;
  }

  memset(_rhp_internal_address_htbl_peerid,0,sizeof(rhp_internal_address*)*RHP_VPN_HASH_TABLE_SIZE);
  memset(_rhp_internal_address_htbl_eap_peerid,0,sizeof(rhp_internal_address*)*RHP_VPN_HASH_TABLE_SIZE);
  memset(_rhp_internal_address_htbl_addr_v4,0,sizeof(rhp_internal_address*)*RHP_VPN_HASH_TABLE_SIZE);
  memset(_rhp_internal_address_htbl_addr_v6,0,sizeof(rhp_internal_address*)*RHP_VPN_HASH_TABLE_SIZE);

  memset(&_rhp_internal_address_list_head,0,sizeof(rhp_internal_address));
  _rhp_internal_address_list_head.tag[0] = '#';
  _rhp_internal_address_list_head.tag[1] = 'I';
  _rhp_internal_address_list_head.tag[2] = 'N';
  _rhp_internal_address_list_head.tag[3] = 'A';

  rhp_timer_init(&(_rhp_vpn_internal_address_timer),_rhp_vpn_internal_address_aging_timer,NULL);

  RHP_TRC(0,RHPTRCID_VPN_ADDR_POOL_INIT,"");
  return  0;
}


static void _rhp_internal_addr_free(rhp_internal_address* intr_addr)
{
  RHP_TRC(0,RHPTRCID_INTERNAL_ADDR_FREE,"x",intr_addr);

	rhp_ikev2_id_clear(&(intr_addr->peer_id));

	rhp_eap_id_clear(&(intr_addr->eap_peer_id));

	_rhp_free(intr_addr);

	return;
}

static rhp_internal_address* _rhp_internal_addr_alloc(rhp_vpn* vpn,
		rhp_ip_addr* assigned_addr_v4,rhp_ip_addr* assigned_addr_v6)
{
	int err = -EINVAL;
	rhp_internal_address* intr_addr = NULL;

  RHP_TRC(0,RHPTRCID_INTERNAL_ADDR_ALLOC,"xuxx",vpn,vpn->vpn_realm_id,assigned_addr_v4,assigned_addr_v6);
  rhp_ikev2_id_dump("peer_id",&(vpn->peer_id));
  rhp_ip_addr_dump("assigned_addr_v4",assigned_addr_v4);
  rhp_ip_addr_dump("assigned_addr_v6",assigned_addr_v6);
  rhp_eap_id_dump("eap.peer_id",&(vpn->eap.peer_id));

  if( assigned_addr_v4 == NULL && assigned_addr_v6 == NULL ){
  	RHP_BUG("");
		return NULL;
  }

	intr_addr = (rhp_internal_address*)_rhp_malloc(sizeof(rhp_internal_address));
	if( intr_addr == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(intr_addr,0,sizeof(rhp_internal_address));

	intr_addr->tag[0] = '#';
	intr_addr->tag[1] = 'I';
	intr_addr->tag[2] = 'N';
	intr_addr->tag[3] = 'A';

	intr_addr->assigned_addr_v4.addr_family = AF_UNSPEC;
	intr_addr->assigned_addr_v6.addr_family = AF_UNSPEC;

	intr_addr->assigned_addr_v4.tag = RHP_IPADDR_TAG_IKEV2_CFG_ASSIGNED;
	intr_addr->assigned_addr_v6.tag = RHP_IPADDR_TAG_IKEV2_CFG_ASSIGNED;

	intr_addr->vpn_realm_id = vpn->vpn_realm_id;

	if( assigned_addr_v4 && assigned_addr_v4->addr.v4 ){

		intr_addr->assigned_addr_v4.addr_family = AF_INET;
		intr_addr->assigned_addr_v4.addr.v4 = assigned_addr_v4->addr.v4;
		intr_addr->assigned_addr_v4.prefixlen = assigned_addr_v4->prefixlen;
		intr_addr->assigned_addr_v4.netmask.v4 = assigned_addr_v4->netmask.v4;
	}

	if( assigned_addr_v6 && !rhp_ipv6_addr_null(assigned_addr_v6->addr.v6) ){

		intr_addr->assigned_addr_v6.addr_family = AF_INET6;
		memcpy(intr_addr->assigned_addr_v6.addr.v6,assigned_addr_v6->addr.v6,16);

		intr_addr->assigned_addr_v6.prefixlen = assigned_addr_v6->prefixlen;
		memcpy(intr_addr->assigned_addr_v6.netmask.v6,assigned_addr_v6->addr.v6,16);
	}

	if( rhp_ikev2_id_dup(&(intr_addr->peer_id),&(vpn->peer_id)) ){
		RHP_BUG("");
		_rhp_internal_addr_free(intr_addr);
		return NULL;
	}

	if( !rhp_eap_id_is_null(&(vpn->eap.peer_id))){

		err = rhp_eap_id_setup(vpn->eap.eap_method,
						vpn->eap.peer_id.identity_len,vpn->eap.peer_id.identity,vpn->is_v1,
						&(intr_addr->eap_peer_id));
		if( err ){
			RHP_BUG("");
			_rhp_internal_addr_free(intr_addr);
			return NULL;
		}
	}

  rhp_ikev2_id_dump("intr_addr.peer_id",&(intr_addr->peer_id));
  rhp_ip_addr_dump("intr_addr.assigned_addr_v4",&(intr_addr->assigned_addr_v4));
  rhp_ip_addr_dump("intr_addr.assigned_addr_v6",&(intr_addr->assigned_addr_v6));
  RHP_TRC(0,RHPTRCID_INTERNAL_ADDR_ALLOC_RTRN,"xud",intr_addr,intr_addr->vpn_realm_id,intr_addr->expire);
	return intr_addr;
}

static int _rhp_internal_addr_peer_id_hash(rhp_ikev2_id* peer_id,u32* hval_r)
{
	int err = -EINVAL;
	u32 hval;

	err = rhp_ikev2_id_hash(peer_id,_rhp_internal_address_htbl_rnd,&hval);
	if( err ){
		RHP_BUG("%d",err);
		return err;
	}

	hval = hval % RHP_VPN_HASH_TABLE_SIZE;

	*hval_r = hval;
	return 0;
}

static int _rhp_internal_addr_eap_peer_id_hash(rhp_eap_id* eap_peer_id,u32* hval_r)
{
	int err = -EINVAL;
	u32 hval;

	err = rhp_eap_id_hash(eap_peer_id,_rhp_internal_address_htbl_rnd,&hval);
	if( err ){
		RHP_BUG("%d",err);
		return err;
	}

	hval = hval % RHP_VPN_HASH_TABLE_SIZE;

	*hval_r = hval;
	return 0;
}


static rhp_internal_address* _rhp_internal_addr_peer_id_get(rhp_vpn* vpn)
{
	int err = -EINVAL;
	u32 hval;
	rhp_internal_address* intr_addr = NULL;

  RHP_TRC(0,RHPTRCID_INTERNAL_ADDR_PEER_ID_GET,"xu",vpn,vpn->vpn_realm_id);
  rhp_ikev2_id_dump("peer_id",&(vpn->peer_id));
  rhp_eap_id_dump("eap.peer_id",&(vpn->eap.peer_id));

  if( !rhp_eap_id_is_null(&(vpn->eap.peer_id))){

		err = _rhp_internal_addr_eap_peer_id_hash(&(vpn->eap.peer_id),&hval);
		if( err ){
			RHP_TRC(0,RHPTRCID_INTERNAL_ADDR_EAP_PEER_ID_GET_ERR,"xE",intr_addr,err);
			return NULL;
		}

		intr_addr = _rhp_internal_address_htbl_eap_peerid[hval];
		while( intr_addr ){

			if( (vpn->vpn_realm_id == intr_addr->vpn_realm_id) &&
					!rhp_eap_id_cmp(&(intr_addr->eap_peer_id),&(vpn->eap.peer_id)) ){

				break;
			}

			intr_addr = intr_addr->hash_eap_peer_id_next;
		}

  }else{

		err = _rhp_internal_addr_peer_id_hash(&(vpn->peer_id),&hval);
		if( err ){
			RHP_TRC(0,RHPTRCID_INTERNAL_ADDR_PEER_ID_GET_ERR,"xE",intr_addr,err);
			return NULL;
		}

		intr_addr = _rhp_internal_address_htbl_peerid[hval];
		while( intr_addr ){

			if( (vpn->vpn_realm_id == intr_addr->vpn_realm_id) &&
					 !rhp_ikev2_id_cmp(&(vpn->peer_id),&(intr_addr->peer_id)) &&
					 rhp_eap_id_is_null(&(intr_addr->eap_peer_id)) ){

				break;
			}

			intr_addr = intr_addr->hash_peer_id_next;
		}
  }

  RHP_TRC(0,RHPTRCID_INTERNAL_ADDR_PEER_ID_GET_RTRN,"x",intr_addr);
	return intr_addr;
}


static int _rhp_internal_addr_hash(rhp_ip_addr* assigned_addr,u32* hval_r)
{
	u32 hval;

	if( assigned_addr->addr_family == AF_INET ){

		hval = _rhp_hash_ipv4_1(assigned_addr->addr.v4,_rhp_internal_address_htbl_rnd);
		hval = hval % RHP_VPN_HASH_TABLE_SIZE;
		*hval_r = hval;

	}else if( assigned_addr->addr_family == AF_INET6 ){

		hval = _rhp_hash_ipv6_1(assigned_addr->addr.v6,_rhp_internal_address_htbl_rnd);
		hval = hval % RHP_VPN_HASH_TABLE_SIZE;
		*hval_r = hval;

	}else{
		RHP_BUG("%d",assigned_addr->addr_family);
		return -EINVAL;
	}
	return 0;
}

static rhp_internal_address* _rhp_internal_addr_get(unsigned long vpn_realm_id,
		rhp_ip_addr* assigned_addr)
{
	int err = -EINVAL;
	u32 hval;
	rhp_internal_address* intr_addr;

  RHP_TRC(0,RHPTRCID_INTERNAL_ADDR_ADDR_GET,"ux",vpn_realm_id,assigned_addr);
  rhp_ip_addr_dump("assigned_addr",assigned_addr);

	err = _rhp_internal_addr_hash(assigned_addr,&hval);
	if( err ){
		RHP_BUG("%d",err);
		return NULL;
	}

	if( assigned_addr->addr_family == AF_INET ){
		intr_addr = _rhp_internal_address_htbl_addr_v4[hval];
	}else if( assigned_addr->addr_family == AF_INET6 ){
		intr_addr = _rhp_internal_address_htbl_addr_v6[hval];
	}else{
		RHP_BUG("%d",err);
		return NULL;
	}

	while( intr_addr ){

		rhp_ip_addr* assigned_addr_tmp = NULL;

		if( assigned_addr->addr_family == AF_INET ){
			assigned_addr_tmp = &(intr_addr->assigned_addr_v4);
		}else if( assigned_addr->addr_family == AF_INET6 ){
			assigned_addr_tmp = &(intr_addr->assigned_addr_v6);
		}

		if( (vpn_realm_id == intr_addr->vpn_realm_id) &&
				assigned_addr_tmp &&
				!rhp_ip_addr_cmp(assigned_addr,assigned_addr_tmp) ){

			break;
		}

		if( assigned_addr->addr_family == AF_INET ){
			intr_addr = intr_addr->hash_addr_v4_next;
		}else{ // AF_INET6
			intr_addr = intr_addr->hash_addr_v6_next;
		}
	}

  RHP_TRC(0,RHPTRCID_INTERNAL_ADDR_ADDR_GETRTRN,"x",intr_addr);
	return intr_addr;
}

static void _rhp_internal_addr_delete_lst(int addr_family,rhp_internal_address *intr_addr_d)
{
	int err;
	u32 hval;
	rhp_internal_address *intr_addr = NULL,*intr_addr_p;

  RHP_TRC(0,RHPTRCID_INTERNAL_ADDR_DELETE_LST,"Ldx","AF",addr_family,intr_addr_d);

	if( (addr_family == AF_INET &&
			 intr_addr_d->assigned_addr_v4.addr_family != AF_INET) ||
			(addr_family == AF_INET6 &&
			 intr_addr_d->assigned_addr_v6.addr_family != AF_INET6) ){

		RHP_TRC(0,RHPTRCID_INTERNAL_ADDR_DELETE_LST_UNKNOWN_ADDR_FAMILY,"Ldxdd","AF",addr_family,intr_addr_d,intr_addr_d->assigned_addr_v4.addr_family,intr_addr_d->assigned_addr_v6.addr_family);
		return;
	}

	err = _rhp_internal_addr_hash(
			(addr_family == AF_INET ?
					&(intr_addr_d->assigned_addr_v4) : &(intr_addr_d->assigned_addr_v6)),
			&hval);

	if( !err ){

		if( addr_family == AF_INET ){
			intr_addr = _rhp_internal_address_htbl_addr_v4[hval];
		}else{ // AF_INET6
			intr_addr = _rhp_internal_address_htbl_addr_v6[hval];
		}

		intr_addr_p = NULL;
		while( intr_addr ){

			if( intr_addr == intr_addr_d ){
				break;
			}

			intr_addr_p = intr_addr;

			if( addr_family == AF_INET ){
				intr_addr = intr_addr->hash_addr_v4_next;
			}else{ // AF_INET6
				intr_addr = intr_addr->hash_addr_v6_next;
			}
		}

		if( intr_addr ){

			if( intr_addr_p ){

				if( addr_family == AF_INET ){
					intr_addr_p->hash_addr_v4_next = intr_addr->hash_addr_v4_next;
				}else{ // AF_INET6
					intr_addr_p->hash_addr_v6_next = intr_addr->hash_addr_v6_next;
				}

			}else{

				if( addr_family == AF_INET ){
					_rhp_internal_address_htbl_addr_v4[hval] = intr_addr->hash_addr_v4_next;
				}else{ // AF_INET6
					_rhp_internal_address_htbl_addr_v6[hval] = intr_addr->hash_addr_v6_next;
				}
			}

			if( addr_family == AF_INET ){
				intr_addr->hash_addr_v4_next = NULL;
			}else{ // AF_INET6
				intr_addr->hash_addr_v6_next = NULL;
			}
		}

	  RHP_TRC(0,RHPTRCID_INTERNAL_ADDR_DELETE_LST_RTRN,"Ldx","AF",addr_family,intr_addr_d);

	}else{
		RHP_BUG("%d",err);
	}
}

static void _rhp_internal_addr_delete(rhp_internal_address *intr_addr_d)
{
	int err = -EINVAL;
	rhp_internal_address *intr_addr = NULL,*intr_addr_p;

  RHP_TRC(0,RHPTRCID_INTERNAL_ADDR_DELETE,"xu",intr_addr_d,intr_addr_d->vpn_realm_id);
  rhp_ikev2_id_dump("assigned_addr",&(intr_addr_d->peer_id));
  rhp_ip_addr_dump("assigned_addr_v4",&(intr_addr_d->assigned_addr_v4));
  rhp_ip_addr_dump("assigned_addr_v6",&(intr_addr_d->assigned_addr_v6));
  rhp_eap_id_dump("eap_peer_id",&(intr_addr_d->eap_peer_id));

	{
  	u32 hval;

  	err = _rhp_internal_addr_peer_id_hash(&(intr_addr_d->peer_id),&hval);
		if( !err ){

			intr_addr = _rhp_internal_address_htbl_peerid[hval];
			intr_addr_p = NULL;
			while( intr_addr ){

				if( intr_addr_d == intr_addr ){
					break;
				}

				intr_addr_p = intr_addr;
				intr_addr = intr_addr->hash_peer_id_next;
			}

			if( intr_addr ){

				if( intr_addr_p ){
					intr_addr_p->hash_peer_id_next = intr_addr->hash_peer_id_next;
				}else{
					_rhp_internal_address_htbl_peerid[hval] = intr_addr->hash_peer_id_next;
				}
				intr_addr->hash_peer_id_next = NULL;
			}

		}else{
			RHP_BUG("");
		}
	}

	if( !rhp_eap_id_is_null(&(intr_addr_d->eap_peer_id)) ){

		if( intr_addr_d->eap_peer_id.identity_len < 1 ){

			RHP_BUG("");

		}else{

			u32 hval;

			err = _rhp_internal_addr_eap_peer_id_hash(&(intr_addr_d->eap_peer_id),&hval);
			if( !err ){

				intr_addr = _rhp_internal_address_htbl_eap_peerid[hval];
				intr_addr_p = NULL;
				while( intr_addr ){

					if( intr_addr_d == intr_addr ){
						break;
					}

					intr_addr_p = intr_addr;
					intr_addr = intr_addr->hash_eap_peer_id_next;
				}

				if( intr_addr ){

					if( intr_addr_p ){
						intr_addr_p->hash_eap_peer_id_next = intr_addr->hash_eap_peer_id_next;
					}else{
						_rhp_internal_address_htbl_eap_peerid[hval] = intr_addr->hash_eap_peer_id_next;
					}
					intr_addr->hash_eap_peer_id_next = NULL;
				}

			}else{
				RHP_BUG("");
			}
		}
	}

	_rhp_internal_addr_delete_lst(AF_INET,intr_addr_d);
	_rhp_internal_addr_delete_lst(AF_INET6,intr_addr_d);

  {
		intr_addr->lst_prev->lst_next = intr_addr->lst_next;
	  if( intr_addr->lst_next ){
	  	intr_addr->lst_next->lst_prev = intr_addr->lst_prev;
	  }
	  intr_addr->lst_prev = NULL;
	  intr_addr->lst_next = NULL;
  }

  RHP_TRC(0,RHPTRCID_INTERNAL_ADDR_DELETE_RTRN,"xu",intr_addr_d,intr_addr_d->vpn_realm_id);
	return;
}

static int _rhp_internal_addr_put(rhp_internal_address* intr_addr)
{
	int err = -EINVAL;

  RHP_TRC(0,RHPTRCID_INTERNAL_ADDR_PUT,"x",intr_addr);
  rhp_ikev2_id_dump("_rhp_internal_addr_put.peer_id",&(intr_addr->peer_id));
  rhp_ip_addr_dump("_rhp_internal_addr_put.assigned_addr_v4",&(intr_addr->assigned_addr_v4));
  rhp_ip_addr_dump("_rhp_internal_addr_put.assigned_addr_v6",&(intr_addr->assigned_addr_v6));
  rhp_eap_id_dump("_rhp_internal_addr_put.eap_peer_id",&(intr_addr->eap_peer_id));

	if( !rhp_eap_id_is_null(&(intr_addr->eap_peer_id)) ){

		if( intr_addr->eap_peer_id.identity_len < 1 ){

			RHP_BUG("");

		}else{

			u32 hval;

			err = _rhp_internal_addr_eap_peer_id_hash(&(intr_addr->eap_peer_id),&hval);
			if( err ){
				RHP_BUG("");
				return err;
			}

			intr_addr->hash_eap_peer_id_next = _rhp_internal_address_htbl_eap_peerid[hval];
			_rhp_internal_address_htbl_eap_peerid[hval] = intr_addr;
		}

	}else{

  	u32 hval;

  	err = _rhp_internal_addr_peer_id_hash(&(intr_addr->peer_id),&hval);
		if( err ){
			RHP_BUG("");
			return err;
		}

		intr_addr->hash_peer_id_next = _rhp_internal_address_htbl_peerid[hval];
		_rhp_internal_address_htbl_peerid[hval] = intr_addr;
	}

	if( intr_addr->assigned_addr_v4.addr.v4 ){

		u32 hval;

		err = _rhp_internal_addr_hash(&(intr_addr->assigned_addr_v4),&hval);
		if( err ){
			RHP_BUG("");
			return err;
		}

		intr_addr->hash_addr_v4_next = _rhp_internal_address_htbl_addr_v4[hval];
		_rhp_internal_address_htbl_addr_v4[hval] = intr_addr;
	}

	if( !rhp_ipv6_addr_null(intr_addr->assigned_addr_v6.addr.v6) ){

		u32 hval;

		err = _rhp_internal_addr_hash(&(intr_addr->assigned_addr_v6),&hval);
		if( err ){
			RHP_BUG("");
			return err;
		}

		intr_addr->hash_addr_v6_next = _rhp_internal_address_htbl_addr_v6[hval];
		_rhp_internal_address_htbl_addr_v6[hval] = intr_addr;
	}

  {
		intr_addr->lst_next = _rhp_internal_address_list_head.lst_next;
	  if( _rhp_internal_address_list_head.lst_next ){
	  	_rhp_internal_address_list_head.lst_next->lst_prev = intr_addr;
	  }
	  intr_addr->lst_prev = &_rhp_internal_address_list_head;
	  _rhp_internal_address_list_head.lst_next = intr_addr;
  }

  RHP_TRC(0,RHPTRCID_INTERNAL_ADDR_PUT_RTRN,"x",intr_addr);
	return 0;
}

static int _rhp_vpn_internal_address_assign_v4(rhp_vpn* vpn,rhp_vpn_realm* rlm,
		rhp_ip_addr* cur_addr,rhp_ip_addr* new_addr)
{
	int err = -EINVAL;
	rhp_internal_address* intr_addr = NULL;
	rhp_internal_peer_address* peer_addr = rlm->config_server.peer_addrs;
	rhp_internal_address_pool* addr_pool = rlm->config_server.addr_pools;

	RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_ASSIGN_V4,"xxxxxx",vpn,rlm,cur_addr,new_addr,peer_addr,addr_pool);

	while( peer_addr ){

		if( !rhp_ikev2_id_cmp_no_alt_id(&(vpn->peer_id),&(peer_addr->peer_id)) ||
				(vpn->peer_id.alt_id && !rhp_ikev2_id_cmp_no_alt_id(vpn->peer_id.alt_id,&(peer_addr->peer_id)) ) ){
			break;
		}

		peer_addr = peer_addr->next;
	}

	if( peer_addr ){

		memcpy(new_addr,&(peer_addr->peer_address),sizeof(rhp_ip_addr));
		new_addr->tag = RHP_IPADDR_TAG_IKEV2_CFG_ASSIGNED;

	  RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_ASSIGN_V4_FIXED_ADDR_FOUND,"xxx",vpn,rlm,new_addr);

  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_INTERNAL_ADDRESS_RESERVED,"VIA",vpn,&(peer_addr->peer_id),&(peer_addr->peer_address));

  	return 0;
	}


	while( addr_pool ){

		rhp_ip_addr* last_addr = &(addr_pool->last);
		rhp_ip_addr* netmask = &(addr_pool->netmask);
		u32 ipv4_last_addr = last_addr->addr.v4;
		u32 ipv4_netmask = netmask->addr.v4;
		u32 ipv4_end = ntohl(addr_pool->end.addr.v4);
		u32 ipv4_last_addr_start = ipv4_last_addr;
		int cur_addr_flag = 0;

		while( 1 ){

			u32 ipv4_be;
			rhp_ip_addr* cand_addr = NULL;
			rhp_vpn* col_vpn = NULL;
			rhp_vpn_ref* col_vpn_ref = NULL;

			if( !cur_addr_flag &&
					cur_addr && cur_addr->addr_family == AF_INET && cur_addr->addr.v4 &&
					!rhp_ip_addr_gteq_ip(cur_addr,&(addr_pool->start)) &&
					!rhp_ip_addr_lteq_ip(cur_addr,&(addr_pool->end)) ){

				RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_ASSIGN_V4_PEER_REQ_CUR_ADDR,"xxx",vpn,rlm,cur_addr);

				cand_addr = cur_addr;
				cur_addr_flag = 1;

				ipv4_be = (cand_addr->addr.v4 & (~ipv4_netmask));
				if( (ipv4_be == 0) || (ipv4_be == ~ipv4_netmask) ){
					continue;
				}

			}else{

				ipv4_last_addr = ntohl(ipv4_last_addr);
				ipv4_last_addr++;

				if( ipv4_last_addr > ipv4_end ){
					ipv4_last_addr = addr_pool->start.addr.v4;
				}else{
					ipv4_last_addr = htonl(ipv4_last_addr);
				}

				if( ipv4_last_addr_start == ipv4_last_addr ){
					RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_ASSIGN_V4_NEW_ADDR_NOT_FOUND,"xxx",vpn,rlm,new_addr);
					break; // NOT found...
				}

				ipv4_be = (ipv4_last_addr & (~ipv4_netmask));
				if( (ipv4_be == 0) || (ipv4_be == ~ipv4_netmask) ){
					continue;
				}

				last_addr->addr.v4 = ipv4_last_addr;
				cand_addr = last_addr;
			}

			{
				col_vpn_ref = rhp_vpn_get_by_peer_internal_addr_no_lock(vpn->vpn_realm_id,cand_addr);
				col_vpn = RHP_VPN_REF(col_vpn_ref);
				if( col_vpn ){

				  RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_ASSIGN_V4_NEW_ADDR_FOUND_BUT_COLLISION_ERR,"xxx",vpn,rlm,col_vpn);

				  rhp_vpn_unhold(col_vpn_ref);
					continue;
				}
			}

			intr_addr = _rhp_internal_addr_get(vpn->vpn_realm_id,cand_addr);
			if( intr_addr ){

				if( intr_addr->expire == 0 ){
					continue;
				}

	  		_rhp_internal_addr_delete(intr_addr);
	  		_rhp_internal_addr_free(intr_addr);
			}

			memcpy(new_addr,cand_addr,sizeof(rhp_ip_addr));
			new_addr->tag = RHP_IPADDR_TAG_IKEV2_CFG_ASSIGNED;

    	return 0;
		}

		addr_pool = addr_pool->next;
	}

	err = -ENOENT;

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_INTERNAL_ADDRESS_V4_FAILED_TO_ASSIGN,"VI",vpn,(peer_addr ? &(peer_addr->peer_id) : NULL));

	RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_ASSIGN_V4_ERR,"xxxE",vpn,rlm,new_addr,err);

	return err;
}

// Max range for assigned addresses: lower 64bits of IPv6 address.
static int _rhp_vpn_internal_address_assign_v6(rhp_vpn* vpn,rhp_vpn_realm* rlm,
		rhp_ip_addr* cur_addr,rhp_ip_addr* new_addr)
{
	int err = -EINVAL;
	rhp_internal_address* intr_addr = NULL;
	rhp_internal_peer_address* peer_addr = rlm->config_server.peer_addrs_v6;
	rhp_internal_address_pool* addr_pool = rlm->config_server.addr_pools_v6;

	RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_ASSIGN_V6,"xxxxxx",vpn,rlm,cur_addr,new_addr,peer_addr,addr_pool);


	while( peer_addr ){

		if( !rhp_ikev2_id_cmp_no_alt_id(&(vpn->peer_id),&(peer_addr->peer_id)) ||
				(vpn->peer_id.alt_id && !rhp_ikev2_id_cmp_no_alt_id(vpn->peer_id.alt_id,&(peer_addr->peer_id)) ) ){
			break;
		}

		peer_addr = peer_addr->next;
	}

	if( peer_addr ){

		memcpy(new_addr,&(peer_addr->peer_address),sizeof(rhp_ip_addr));
		new_addr->tag = RHP_IPADDR_TAG_IKEV2_CFG_ASSIGNED;

	  RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_ASSIGN_V6_FIXED_ADDR_FOUND,"xxx",vpn,rlm,new_addr);

  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_INTERNAL_ADDRESS_RESERVED,"VIA",vpn,&(peer_addr->peer_id),&(peer_addr->peer_address));

  	return 0;
	}


	while( addr_pool ){

		rhp_ip_addr* last_addr = &(addr_pool->last);
		u64 ipv6_last_addr = ((u64*)last_addr->addr.v6)[1];
		u64 ipv6_end = _rhp_ntohll(((u64*)addr_pool->end.addr.v6)[1]);
		u64 ipv6_last_addr_start = ipv6_last_addr;

		while( 1 ){

			rhp_vpn* col_vpn = NULL;
			rhp_vpn_ref* col_vpn_ref = NULL;
			rhp_ip_addr* cand_addr = NULL;
			int cur_addr_flag = 0;

			if( !cur_addr_flag &&
					cur_addr && cur_addr->addr_family == AF_INET6 &&
					!rhp_ipv6_addr_null(cur_addr->addr.v6) &&
					!rhp_ip_addr_gteq_ip(cur_addr,&(addr_pool->start)) &&
					!rhp_ip_addr_lteq_ip(cur_addr,&(addr_pool->end)) ){

				RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_ASSIGN_V6_PEER_REQ_CUR_ADDR,"xxx",vpn,rlm,cur_addr);

				cand_addr = cur_addr;
				cur_addr_flag = 1;

			}else{

				ipv6_last_addr = _rhp_ntohll(ipv6_last_addr);
				ipv6_last_addr++;

				if( ipv6_last_addr > ipv6_end ){
					ipv6_last_addr = ((u64*)addr_pool->start.addr.v6)[1];
				}else{
					ipv6_last_addr = _rhp_htonll(ipv6_last_addr);
				}

				if( ipv6_last_addr_start == ipv6_last_addr ){
					RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_ASSIGN_V6_NEW_ADDR_NOT_FOUND,"xxx",vpn,rlm,new_addr);
					break; // NOT found...
				}

				((u64*)last_addr->addr.v6)[1] = ipv6_last_addr;
				cand_addr = last_addr;
			}

			{
				col_vpn_ref = rhp_vpn_get_by_peer_internal_addr_no_lock(vpn->vpn_realm_id,cand_addr);
				col_vpn = RHP_VPN_REF(col_vpn_ref);
				if( col_vpn ){

				  RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_ASSIGN_V6_NEW_ADDR_FOUND_BUT_COLLISION_ERR,"xxx",vpn,rlm,col_vpn);

				  rhp_vpn_unhold(col_vpn_ref);
					continue;
				}
			}

			intr_addr = _rhp_internal_addr_get(vpn->vpn_realm_id,cand_addr);
			if( intr_addr ){

				if( intr_addr->expire == 0 ){
					continue;
				}

	  		_rhp_internal_addr_delete(intr_addr);
	  		_rhp_internal_addr_free(intr_addr);
			}

			memcpy(new_addr,cand_addr,sizeof(rhp_ip_addr));
			new_addr->tag = RHP_IPADDR_TAG_IKEV2_CFG_ASSIGNED;

    	return 0;
		}

		addr_pool = addr_pool->next;
	}

	err = -ENOENT;

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_INTERNAL_ADDRESS_V6_FAILED_TO_ASSIGN,"VI",vpn,(peer_addr ? &(peer_addr->peer_id) : NULL));

	RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_ASSIGN_V6_ERR,"xxxE",vpn,rlm,new_addr,err);

	return err;
}

int rhp_vpn_internal_address_get(rhp_vpn* vpn,rhp_ip_addr_list** addrs_head_r)
{
	int err = -EINVAL;
	rhp_internal_address* intr_addr;
	rhp_ip_addr_list *addr_head = NULL, *addr_v4 = NULL, *addr_v6 = NULL;

	RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_GET,"xx",vpn,addrs_head_r);

	RHP_LOCK(&rhp_vpn_lock);

	intr_addr = _rhp_internal_addr_peer_id_get(vpn);
	if( intr_addr == NULL ){
		err = -ENOENT;
		goto error;
	}

  if( intr_addr->assigned_addr_v4.addr.v4 ){

  	addr_v4 = (rhp_ip_addr_list*)_rhp_malloc(sizeof(rhp_ip_addr_list));
  	if( addr_v4 == NULL ){
  		RHP_BUG("");
  		err = -ENOMEM;
  		goto error;
  	}

  	addr_v4->next = NULL;

  	memcpy(&(addr_v4->ip_addr),&(intr_addr->assigned_addr_v4),sizeof(rhp_ip_addr));

  	addr_head = addr_v4;
  }

  if( !rhp_ipv6_addr_null(intr_addr->assigned_addr_v6.addr.v6) ){

  	addr_v6 = (rhp_ip_addr_list*)_rhp_malloc(sizeof(rhp_ip_addr_list));
  	if( addr_v6 == NULL ){
  		RHP_BUG("");
  		err = -ENOMEM;
  		goto error;
  	}

  	addr_v6->next = NULL;

  	memcpy(&(addr_v6->ip_addr),&(intr_addr->assigned_addr_v6),sizeof(rhp_ip_addr));

  	if( addr_head ){
  		addr_head->next = addr_v6;
  	}else{
  		addr_head = addr_v6;
  	}
  }

  if( addr_head == NULL ){
  	err = -ENOENT;
  	goto error;
  }


  *addrs_head_r = addr_head;

	RHP_UNLOCK(&rhp_vpn_lock);

	rhp_ip_addr_dump("addrs_head_r",&((*addrs_head_r)->ip_addr));
	if( (*addrs_head_r)->next ){
		rhp_ip_addr_dump("addrs_head_r->next",&((*addrs_head_r)->next->ip_addr));
	}

	RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_GET_RTRN,"xxx",vpn,*addrs_head_r,(*addrs_head_r ? (*addrs_head_r)->next : NULL) );
	return 0;

error:
	RHP_UNLOCK(&rhp_vpn_lock);
	if( addr_v4 ){
		_rhp_free(addr_v4);
	}
	if( addr_v6 ){
		_rhp_free(addr_v6);
	}
	RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_GET_ERR,"xE",vpn,err);
	return err;
}

int rhp_vpn_internal_address_is_assigned(rhp_vpn* vpn,rhp_ip_addr* addr)
{
	int ret = 0;
	rhp_internal_address* intr_addr;

	RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_IS_ASSIGNED,"xx",vpn,addr);
	rhp_ip_addr_dump("addr",addr);

	RHP_LOCK(&rhp_vpn_lock);

	intr_addr = _rhp_internal_addr_peer_id_get(vpn);
	if( intr_addr ){

		if( rhp_ip_addr_cmp_ip_only(addr,&(intr_addr->assigned_addr_v4)) ||
				rhp_ip_addr_cmp_ip_only(addr,&(intr_addr->assigned_addr_v6)) ){
			ret = 1;
		}
	}

	RHP_UNLOCK(&rhp_vpn_lock);

	RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_IS_ASSIGNED_RTRN,"xxd",vpn,addr,ret);
	return ret;
}


int rhp_vpn_internal_address_assign(rhp_vpn* vpn,rhp_vpn_realm* rlm,
		rhp_ip_addr* cur_addr_v4,rhp_ip_addr* cur_addr_v6,
		rhp_ip_addr* new_addr_v4,rhp_ip_addr* new_addr_v6)
{
	int err = -EINVAL;
	rhp_internal_address* intr_addr;
	rhp_ip_addr cur_addr_v4_c, cur_addr_v6_c, new_addr_v4_cand, new_addr_v6_cand;
	int ok = 0;

  RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_ASSIGN,"xxxxxx",vpn,rlm,cur_addr_v4,new_addr_v4,cur_addr_v6,new_addr_v6);
  rhp_ikev2_id_dump("peer_id",&(vpn->peer_id));
	rhp_ip_addr_dump("cur_addr_v4",cur_addr_v4);
	rhp_ip_addr_dump("cur_addr_v6",cur_addr_v6);

	memset(&new_addr_v4_cand,0,sizeof(rhp_ip_addr));
	memset(&new_addr_v6_cand,0,sizeof(rhp_ip_addr));
	new_addr_v4_cand.addr_family = AF_UNSPEC;
	new_addr_v6_cand.addr_family = AF_UNSPEC;


	RHP_LOCK(&rhp_vpn_lock);

	intr_addr = _rhp_internal_addr_peer_id_get(vpn);
	if( intr_addr ){

		rhp_ip_addr_dump("assigned_addr_v4",&(intr_addr->assigned_addr_v4));
		rhp_ip_addr_dump("assigned_addr_v6",&(intr_addr->assigned_addr_v6));

		if( (new_addr_v4 && intr_addr->assigned_addr_v4.addr.v4 == 0) ||
				(new_addr_v6 && rhp_ipv6_addr_null(intr_addr->assigned_addr_v6.addr.v6)) ){

  	  RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_ASSIGN_CACHE_FOUND_BUT_NOT_ENOUGH,"xx",vpn,rlm);

  	  if( intr_addr->assigned_addr_v4.addr.v4 ){

  	  	memcpy(&cur_addr_v4_c,&(intr_addr->assigned_addr_v4),sizeof(rhp_ip_addr));
  	  	cur_addr_v4 = &cur_addr_v4_c;
  	  }

  	  if( !rhp_ipv6_addr_null(intr_addr->assigned_addr_v6.addr.v6) ){

  	  	memcpy(&cur_addr_v6_c,&(intr_addr->assigned_addr_v6),sizeof(rhp_ip_addr));
  	  	cur_addr_v6 = &cur_addr_v6_c;
  	  }

  		_rhp_internal_addr_delete(intr_addr);
  		_rhp_internal_addr_free(intr_addr);

		}else{

			if( new_addr_v4 ){

				memcpy(new_addr_v4,&(intr_addr->assigned_addr_v4),sizeof(rhp_ip_addr));

				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_INTERNAL_ADDRESS_CACHE_FOUND,"VAA",vpn,&(intr_addr->assigned_addr_v4),cur_addr_v4);
			}

			if( new_addr_v6 ){

				memcpy(new_addr_v6,&(intr_addr->assigned_addr_v6),sizeof(rhp_ip_addr));

				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_INTERNAL_ADDRESS_CACHE_FOUND,"VAA",vpn,&(intr_addr->assigned_addr_v6),cur_addr_v6);
			}

			intr_addr->expire = 0;

			goto end;
		}
	}


	if( new_addr_v4 ){

		if( !_rhp_vpn_internal_address_assign_v4(vpn,rlm,cur_addr_v4,&new_addr_v4_cand) ){
			ok++;
		}
	}

	if( new_addr_v6 ){

		if( !_rhp_vpn_internal_address_assign_v6(vpn,rlm,cur_addr_v6,&new_addr_v6_cand) ){
			ok++;
		}
	}


	if( ok ){

		intr_addr = _rhp_internal_addr_alloc(vpn,&new_addr_v4_cand,&new_addr_v6_cand);
		if( intr_addr == NULL ){
			RHP_BUG("");
			goto error;
		}

		err = _rhp_internal_addr_put(intr_addr);
		if( err ){
			RHP_BUG("");
			_rhp_internal_addr_free(intr_addr);
			goto error;
		}

		if( new_addr_v4 ){

			memcpy(new_addr_v4,&(intr_addr->assigned_addr_v4),sizeof(rhp_ip_addr));

			if( !rhp_ip_addr_null(&(intr_addr->assigned_addr_v4)) ){
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_INTERNAL_ADDRESS_NEW,"VIA",vpn,&(vpn->peer_id),&(intr_addr->assigned_addr_v4));
			}
		}

		if( new_addr_v6 ){

			memcpy(new_addr_v6,&(intr_addr->assigned_addr_v6),sizeof(rhp_ip_addr));

			if( !rhp_ip_addr_null(&(intr_addr->assigned_addr_v6)) ){
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_INTERNAL_ADDRESS_NEW,"VIA",vpn,&(vpn->peer_id),&(intr_addr->assigned_addr_v6));
			}
		}

	}else{

		err = -ENOENT;

		RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_ASSIGN_NOT_AVAILABLE,"xx",vpn,rlm);

		if( !vpn->internal_net_info.peer_exec_ipv6_autoconf ){
			RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_INTERNAL_ADDRESS_NO_POOL,"VI",vpn,&(vpn->peer_id));
		}

		goto error;
	}

end:
	if( !rhp_timer_pending(&(_rhp_vpn_internal_address_timer)) ){

		rhp_timer_reset(&(_rhp_vpn_internal_address_timer));
  	rhp_timer_add(&(_rhp_vpn_internal_address_timer),(time_t)rhp_gcfg_internal_address_aging_interval);
	}

	RHP_UNLOCK(&rhp_vpn_lock);

	rhp_ip_addr_dump("rhp_vpn_internal_address_assign.new_addr_v4",new_addr_v4);
	rhp_ip_addr_dump("rhp_vpn_internal_address_assign.new_addr_v6",new_addr_v6);
  RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_ASSIGN_RTRN,"xx",vpn,rlm);

	return 0;

error:
	RHP_UNLOCK(&rhp_vpn_lock);

	if( !vpn->internal_net_info.peer_exec_ipv6_autoconf ){
		RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_INTERNAL_ADDRESS_FAILED_TO_ASSIGN,"VI",vpn,&(vpn->peer_id));
	}

	RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_ASSIGN_ERR,"xxE",vpn,rlm,err);
	return err;
}


int rhp_vpn_internal_address_free(rhp_vpn* vpn,int dont_hold)
{
	int err = -EINVAL;
	rhp_internal_address* intr_addr;
	rhp_vpn_realm* rlm = vpn->rlm;
	time_t hold_time;

  RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_FREE,"xudx",vpn,vpn->vpn_realm_id,dont_hold,rlm);

	if( rlm == NULL ){
	  RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_FREE_NO_RLM_ERR,"xu",vpn,vpn->vpn_realm_id);
		return -EINVAL;
	}

	RHP_LOCK(&(rlm->lock));
	{
		hold_time = (time_t)(rlm->config_server.addr_hold_hours*3600);
	}
	RHP_UNLOCK(&(rlm->lock));


	RHP_LOCK(&rhp_vpn_lock);

	intr_addr = _rhp_internal_addr_peer_id_get(vpn);
	if( intr_addr ){

		if( !dont_hold ){

			intr_addr->expire = _rhp_get_time() + hold_time;

			RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_FREE_EXPIRE,"xuxdd",vpn,vpn->vpn_realm_id,intr_addr,hold_time,intr_addr->expire);

		}else{

  		_rhp_internal_addr_delete(intr_addr);
  		_rhp_internal_addr_free(intr_addr);
		}

	}else{

		err = -ENOENT;
		goto error;
	}

	RHP_UNLOCK(&rhp_vpn_lock);

  RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_FREE_RTRN,"xu",vpn,vpn->vpn_realm_id);
	return 0;

error:
	RHP_UNLOCK(&rhp_vpn_lock);

  RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_FREE_ERR,"xuE",vpn,vpn->vpn_realm_id,err);
	return err;
}

void rhp_vpn_internal_address_clear_cache(unsigned long vpn_realm_id)
{
	rhp_internal_address *intr_addr,*intr_addr_n;

  RHP_TRC_FREQ(0,RHPTRCID_INTERNAL_ADDRESS_CLEAR_CACHE,"u",vpn_realm_id);

  RHP_LOCK(&rhp_vpn_lock);

  intr_addr = _rhp_internal_address_list_head.lst_next;

  while( intr_addr ){

  	intr_addr_n = intr_addr->lst_next;

  	if( intr_addr->vpn_realm_id == vpn_realm_id && intr_addr->expire ){

  		_rhp_internal_addr_delete(intr_addr);
  		_rhp_internal_addr_free(intr_addr);
  	}

  	intr_addr = intr_addr_n;
  }

  RHP_UNLOCK(&rhp_vpn_lock);

  RHP_TRC_FREQ(0,RHPTRCID_INTERNAL_ADDRESS_CLEAR_CACHE_RTRN,"u",vpn_realm_id);
  return;
}


int rhp_vpn_internal_address_enum(unsigned long rlm_id,int (*callback)(rhp_internal_address* intr_addr,void* ctx),void* ctx)
{
	int err = -EINVAL;
	rhp_internal_address *intr_addr,*intr_addr_n;
	int n = 0;

	RHP_LOCK(&rhp_vpn_lock);

	intr_addr = _rhp_internal_address_list_head.lst_next;
	while( intr_addr ){

		intr_addr_n = intr_addr->lst_next;

		if( rlm_id == 0 || intr_addr->vpn_realm_id == rlm_id ){

			err = callback(intr_addr,ctx);
			if( err ){

  	  	if( err == RHP_STATUS_ENUM_OK ){
  	  		err = 0;
  	  	}

  	  	break;
			}
		}

		n++;
		intr_addr = intr_addr_n;
	}

	if( n == 0 ){
		err = -ENOENT;
	}

  RHP_UNLOCK(&rhp_vpn_lock);

  return err;
}


static int _rhp_vpn_internal_addr_aging_exec = 0;

static void _rhp_vpn_internal_address_aging_task(int worker_idx,void *ctx)
{
	rhp_internal_address *intr_addr,*intr_addr_n;
  time_t now = _rhp_get_time();

  RHP_TRC_FREQ(0,RHPTRCID_INTERNAL_ADDRESS_AGING_TASK,"dx",worker_idx,ctx);

  RHP_LOCK(&rhp_vpn_lock);

  intr_addr = _rhp_internal_address_list_head.lst_next;

  while( intr_addr ){

  	intr_addr_n = intr_addr->lst_next;

  	if( intr_addr->expire && (intr_addr->expire <= now) ){

  	  RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_AGING_TASK_EXPIRE,"xdd",intr_addr,now,intr_addr->expire);

  		_rhp_internal_addr_delete(intr_addr);
  		_rhp_internal_addr_free(intr_addr);

  	}else{

  		_RHP_TRC_FLG_UPDATE(_rhp_trc_user_freq_id());
  	  if( _RHP_TRC_COND(_rhp_trc_user_freq_id(),0) ){
    	  RHP_TRC(0,RHPTRCID_INTERNAL_ADDRESS_AGING_TASK_NOT_EXPIRE,"xudd",intr_addr,intr_addr->vpn_realm_id,now,intr_addr->expire);
  	  	rhp_ikev2_id_dump("NOT EXPIRED",&(intr_addr->peer_id));
  	  	rhp_ip_addr_dump("NOT EXPIRED - v4",&(intr_addr->assigned_addr_v4));
  	  	rhp_ip_addr_dump("NOT EXPIRED - v6",&(intr_addr->assigned_addr_v6));
  	  }
  	}

  	intr_addr = intr_addr_n;
  }

	_rhp_vpn_internal_addr_aging_exec = 0;

  RHP_UNLOCK(&rhp_vpn_lock);

  RHP_TRC_FREQ(0,RHPTRCID_INTERNAL_ADDRESS_AGING_TASK_RTRN,"dx",worker_idx,ctx);
  return;
}


static void _rhp_vpn_internal_address_aging_timer(void *ctx,rhp_timer *timer)
{
	int err = 0;

  RHP_TRC_FREQ(0,RHPTRCID_INTERNAL_ADDRESS_AGING_TIMER,"xx",ctx,timer);

	RHP_LOCK(&rhp_vpn_lock);

	if( _rhp_vpn_internal_addr_aging_exec ){
	  RHP_TRC_FREQ(0,RHPTRCID_INTERNAL_ADDRESS_AGING_TIMER_NEXT_INTERVAL1,"xxd",ctx,timer,_rhp_vpn_internal_addr_aging_exec);
		goto next_interval;
	}

  if( rhp_wts_dispach_ok(RHP_WTS_DISP_LEVEL_LOW_3,1) ){

  	err = rhp_wts_add_task(RHP_WTS_DISP_RULE_MISC,
  					RHP_WTS_DISP_LEVEL_LOW_3,NULL,_rhp_vpn_internal_address_aging_task,NULL);
  	if( err ){
  	  RHP_TRC_FREQ(0,RHPTRCID_INTERNAL_ADDRESS_AGING_TIMER_NEXT_INTERVAL2,"xx",ctx,timer);
  		goto next_interval;
  	}

  	_rhp_vpn_internal_addr_aging_exec = 1;
  }

next_interval:
  rhp_timer_reset(&(_rhp_vpn_internal_address_timer));
  rhp_timer_add(&(_rhp_vpn_internal_address_timer),(time_t)rhp_gcfg_internal_address_aging_interval);

	RHP_UNLOCK(&rhp_vpn_lock);

  RHP_TRC_FREQ(0,RHPTRCID_INTERNAL_ADDRESS_AGING_TIMER_RTRN,"xx",ctx,timer);
	return;
}


int rhp_vpn_internal_addr_pool_v6_included(rhp_vpn_realm* rlm,rhp_ip_addr* addr)
{
	rhp_internal_peer_address* peer_addr = rlm->config_server.peer_addrs_v6;
	rhp_internal_address_pool* addr_pool = rlm->config_server.addr_pools_v6;
	rhp_ip_addr_dump("addr_pool_v6_included.addr",addr);

	RHP_TRC(0,RHPTRCID_INTERNAL_ADDR_POOL_V6_INCLUDED,"xxxx",rlm,addr,peer_addr,addr_pool);

	while( peer_addr ){

		if( !rhp_ip_addr_cmp_ip_only(&(peer_addr->peer_address),addr) ){
			RHP_TRC(0,RHPTRCID_INTERNAL_ADDR_POOL_V6_INCLUDED_RESERVED_ADDR_FOUND,"xx",rlm,addr);
	  	return 1;
		}

		peer_addr = peer_addr->next;
	}


	while( addr_pool ){

		rhp_ip_addr_dump("addr_pool_v6_included.start",&(addr_pool->start));
		rhp_ip_addr_dump("addr_pool_v6_included.end",&(addr_pool->end));

		if( addr_pool->start.addr_family == AF_INET6 &&
				!rhp_ip_addr_gteq_ip(addr,&(addr_pool->start)) &&
				!rhp_ip_addr_lteq_ip(addr,&(addr_pool->end)) ){

			return 1;
		}

		addr_pool = addr_pool->next;
	}

	RHP_TRC(0,RHPTRCID_INTERNAL_ADDR_POOL_V6_INCLUDED_NOT_FOUND,"xx",rlm,addr);
	return 0;
}

