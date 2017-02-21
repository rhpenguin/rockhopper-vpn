/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/capability.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <time.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
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
#include "rhp_wthreads.h"
#include "rhp_config.h"
#include "rhp_vpn.h"
#include "rhp_ikev2.h"
#include "rhp_ikev2_mesg.h"
#include "rhp_forward.h"
#include "rhp_eoip.h"
#include "rhp_tuntap.h"
#include "rhp_esp.h"
#include "rhp_ipv6.h"


extern int rhp_vpn_gen_or_add_local_mac(u8* added_mac,u8* mac_addr_r);
extern void rhp_vpn_clear_local_mac(u8* mac_addr);


rhp_mutex_t rhp_ifc_lock;
rhp_ifc_notifier  rhp_ifc_notifiers[RHP_IFC_NOTIFIER_MAX+1];
static rhp_ifc_entry* _rhp_ifc_list_head = NULL;


static void _rhp_ifc_dump_impl(char* label,rhp_ifc_entry* ifc)
{
	rhp_ifc_addr* ifc_addr;
	int i = 1;

  RHP_TRC(0,RHPTRCID_IFC_DUMP,"sxsMdxduLdddM",label,ifc,ifc->if_name,ifc->mac,ifc->if_index,ifc->if_flags,ifc->mtu,ifc->tuntap_vpn_realm_id,"VIF_TYPE",ifc->tuntap_type,ifc->tuntap_fd,ifc->ipip_dummy_mac_flag,ifc->ipip_dummy_mac);

  ifc_addr = ifc->ifc_addrs;
  while( ifc_addr ){

    RHP_TRC(0,RHPTRCID_IFC_DUMP_IFC_ADDR,"sdxxxxddd",label,i,ifc_addr,ifc_addr->lst_prev,ifc_addr->lst_next,ifc_addr->if_addr_flags,ifc_addr->net_sk_ike,ifc_addr->net_sk_esp,ifc_addr->net_sk_nat_t);
    rhp_ip_addr_dump(label,&(ifc_addr->addr));

  	ifc_addr = ifc_addr->lst_next;
  	i++;
  }

  return;
}

static void _rhp_ifc_dump_lock(char* label,rhp_ifc_entry* ifc)
{
	_RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
  if( !_RHP_TRC_COND(_rhp_trc_user_id(),0) ){
    return;
  }

	RHP_LOCK(&(ifc->lock));
	_rhp_ifc_dump_impl(label,ifc);
	RHP_UNLOCK(&(ifc->lock));

  return;
}

static void _rhp_ifc_dump_no_lock(char* label,rhp_ifc_entry* ifc)
{
	_RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
  if( !_RHP_TRC_COND(_rhp_trc_user_id(),0) ){
    return;
  }

	_rhp_ifc_dump_impl(label,ifc);

  return;
}

rhp_ifc_addr* rhp_ifc_addr_alloc()
{
	rhp_ifc_addr* ifc_addr = (rhp_ifc_addr*)_rhp_malloc(sizeof(rhp_ifc_addr));

	if( ifc_addr == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(ifc_addr,0,sizeof(rhp_ifc_addr));

	ifc_addr->tag[0] = '#';
	ifc_addr->tag[1] = 'N';
	ifc_addr->tag[2] = 'E';
	ifc_addr->tag[3] = 'A';

	ifc_addr->net_sk_ike = -1;
	ifc_addr->net_sk_esp = -1;
	ifc_addr->net_sk_nat_t = -1;

	ifc_addr->addr.addr_family = AF_UNSPEC;

  RHP_TRC(0,RHPTRCID_IFC_ADDR_ALLOC,"x",ifc_addr);

	return ifc_addr;
}

static void _rhp_ifc_addr_free(rhp_ifc_addr* ifc_addr)
{
  RHP_TRC(0,RHPTRCID_IFC_ADDR_FREE,"x",ifc_addr);
	_rhp_free_zero(ifc_addr,sizeof(rhp_ifc_addr));
}

static rhp_ifc_addr* _rhp_ifc_addr_get_addr(rhp_ifc_entry* ifc,int addr_family,u8* addr)
{
	rhp_ifc_addr *ifc_addr = ifc->ifc_addrs;

	if( addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_IFC_ADDR_GET_ADDR,"xLd4",ifc,"AF",addr_family,*((u32*)addr));
	}else{
		RHP_TRC(0,RHPTRCID_IFC_ADDR_GET_ADDR_V6,"xLd6",ifc,"AF",addr_family,addr);
	}

	while( ifc_addr ){

		if( (ifc_addr->addr.addr_family == addr_family) &&
				(( addr_family == AF_INET && ifc_addr->addr.addr.v4 == *((u32*)addr) ) ||
				 ( addr_family == AF_INET6 && rhp_ipv6_is_same_addr(ifc_addr->addr.addr.v6,addr))) ){

			break;
		}

		ifc_addr = ifc_addr->lst_next;
	}

	if( ifc_addr ){
    RHP_TRC(0,RHPTRCID_IFC_ADDR_GET_ADDR_DUMP,"xxxxddd",ifc_addr,ifc_addr->lst_prev,ifc_addr->lst_next,ifc_addr->if_addr_flags,ifc_addr->net_sk_ike,ifc_addr->net_sk_esp,ifc_addr->net_sk_nat_t);
    rhp_ip_addr_dump("_rhp_ifc_addr_get_addr",&(ifc_addr->addr));
	}

	RHP_TRC(0,RHPTRCID_IFC_ADDR_GET_ADDR_RTRN,"xx",ifc,ifc_addr);
	return ifc_addr;
}

static void _rhp_ifc_addr_move_addr_to_top(rhp_ifc_entry* ifc,rhp_ifc_addr* ifc_addr)
{
	RHP_TRC(0,RHPTRCID_IFC_ADDR_MOVE_ADDR_TO_TOP,"xxxx",ifc,ifc_addr,ifc_addr->lst_prev,ifc_addr->lst_next);

	if( ifc_addr->lst_prev ){

		ifc_addr->lst_prev->lst_next = ifc_addr->lst_next;
		if( ifc_addr->lst_next ){
			ifc_addr->lst_next->lst_prev = ifc_addr->lst_prev;
		}

		ifc->ifc_addrs->lst_prev = ifc_addr;
		ifc_addr->lst_prev = NULL;
		ifc_addr->lst_next = ifc->ifc_addrs;
		ifc->ifc_addrs = ifc_addr;
	}

	RHP_TRC(0,RHPTRCID_IFC_ADDR_MOVE_ADDR_TO_TOP_RTRN,"xxxx",ifc,ifc_addr,ifc_addr->lst_prev,ifc_addr->lst_next);
	return;
}

static int _rhp_ifc_addr_delete_addr(rhp_ifc_entry* ifc,int addr_family,u8* addr)
{
	rhp_ifc_addr *ifc_addr = ifc->ifc_addrs;

	if( addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_IFC_ADDR_DELETE_ADDR,"xLd4",ifc,"AF",addr_family,*((u32*)addr));
	}else{
		RHP_TRC(0,RHPTRCID_IFC_ADDR_DELETE_ADDR_V6,"xLd6",ifc,"AF",addr_family,addr);
	}

	while( ifc_addr ){

		if( (ifc_addr->addr.addr_family == addr_family) &&
				(( addr_family == AF_INET && ifc_addr->addr.addr.v4 == *((u32*)addr) ) ||
				 ( addr_family == AF_INET6 && rhp_ipv6_is_same_addr(ifc_addr->addr.addr.v6,addr))) ){
			break;
		}

		ifc_addr = ifc_addr->lst_next;
	}

	if( ifc_addr == NULL ){
		RHP_TRC(0,RHPTRCID_IFC_ADDR_DELETE_ADDR_ENOENT,"x",ifc);
		return -ENOENT;
	}

	if( ifc_addr->lst_prev ){
		ifc_addr->lst_prev->lst_next = ifc_addr->lst_next;
		if( ifc_addr->lst_next ){
			ifc_addr->lst_next->lst_prev = ifc_addr->lst_prev;
		}
	}else{
		ifc->ifc_addrs = ifc_addr->lst_next;
		if( ifc_addr->lst_next ){
			ifc_addr->lst_next->lst_prev = NULL;
		}
	}

	if( ifc_addr->net_sk_ike != -1 ||
			ifc_addr->net_sk_esp != -1 ||
			ifc_addr->net_sk_nat_t != -1 ){
		RHP_BUG("0x%x, 0x%x, %d, %d, %d",ifc,ifc_addr,ifc_addr->net_sk_ike,ifc_addr->net_sk_esp,ifc_addr->net_sk_nat_t);
	}

	ifc->ifc_addrs_num--;
	if( ifc->ifc_addrs_num < 0 ){
		RHP_BUG("");
	}

	_rhp_free(ifc_addr);

	RHP_TRC(0,RHPTRCID_IFC_ADDR_DELETE_ADDR_RTRN,"xx",ifc,ifc_addr);
	return 0;
}

static rhp_ifc_addr* _rhp_ifc_addr_set_addr(rhp_ifc_entry* ifc,
		int addr_family,u8* addr,int prefixlen,u32 ipv6_scope_id)
{
	rhp_ifc_addr *ifc_addr,*ifc_addr_e;

	if( addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_IFC_ADDR_SET_ADDR,"xLd4dj",ifc,"AF",addr_family,*((u32*)addr),prefixlen,ipv6_scope_id);
	}else{
		RHP_TRC(0,RHPTRCID_IFC_ADDR_SET_ADDR_V6,"xLd6dj",ifc,"AF",addr_family,addr,prefixlen,ipv6_scope_id);
	}

	ifc_addr = _rhp_ifc_addr_get_addr(ifc,addr_family,addr);
	if( ifc_addr ){
		RHP_TRC(0,RHPTRCID_IFC_ADDR_SET_ADDR_ALREADY_EXISTS,"xx",ifc,ifc_addr);
		return ifc_addr;
	}

	ifc_addr = rhp_ifc_addr_alloc();
	if( ifc_addr == NULL ){
		RHP_BUG("");
		return NULL;
	}

	ifc_addr->addr.addr_family = addr_family;
	ifc_addr->addr.prefixlen = prefixlen;

	if( addr_family == AF_INET ){

		ifc_addr->addr.addr.v4 = *((u32*)addr);
		ifc_addr->addr.netmask.v4 = rhp_ipv4_prefixlen_to_netmask(prefixlen);

	}else if( addr_family == AF_INET6 ){

		ifc_addr->addr.ipv6_scope_id = ipv6_scope_id;

		memcpy(ifc_addr->addr.addr.v6,addr,16);
		rhp_ipv6_prefixlen_to_netmask(prefixlen,ifc_addr->addr.netmask.v6);

	}else{
		RHP_BUG("%d",addr_family);
		_rhp_ifc_addr_free(ifc_addr);
		return NULL;
	}

	ifc_addr_e = ifc->ifc_addrs;
	while( ifc_addr_e && ifc_addr_e->lst_next ){
		ifc_addr_e = ifc_addr_e->lst_next;
	}

	if( ifc_addr_e == NULL ){
		ifc->ifc_addrs = ifc_addr;
	}else{
		ifc_addr_e->lst_next = ifc_addr;
		ifc_addr->lst_prev = ifc_addr_e;
	}

	ifc->ifc_addrs_num++;

	RHP_TRC(0,RHPTRCID_IFC_ADDR_SET_ADDR_RTRN,"xxxx",ifc,ifc_addr,ifc_addr->lst_prev,ifc_addr->lst_next);
	return ifc_addr;
}

static int _rhp_ifc_addr_enum_addrs(rhp_ifc_entry* ifc,
		int (*callback)(rhp_ifc_entry* ifc,rhp_ifc_addr* ifc_addr,void* cb_ctx),void* ctx)
{
	int err = -EINVAL;
	rhp_ifc_addr* ifc_addr = ifc->ifc_addrs;

	RHP_TRC(0,RHPTRCID_IFC_ADDR_ENUM_ADDRS,"xYx",ifc,callback,ctx);

	while( ifc_addr ){

		err = callback(ifc,ifc_addr,ctx);
		if( err ){
			break;
		}

		ifc_addr = ifc_addr->lst_next;
	}

	RHP_TRC(0,RHPTRCID_IFC_ADDR_ENUM_ADDRS_RTRN,"xYxE",ifc,callback,ctx,err);
	return err;
}


static rhp_ifc_addr* _rhp_ifc_addr_select_src_addr(rhp_ifc_entry* ifc,
		int addr_family,u8* dst_addr,int def_route)
{
	int err = -EINVAL;
	rhp_ifc_addr* ifc_addr = NULL;
	rhp_ifc_addr* ifc_addr_w = NULL;
	rhp_ip_addr dest;

	memset(&dest,0,sizeof(rhp_ip_addr));
	dest.addr_family = addr_family;

	if( addr_family == AF_INET ){

		RHP_TRC(0,RHPTRCID_IFC_ADDR_SELECT_SRC_ADDR,"xLd4d",ifc,"AF",addr_family,*((u32*)dst_addr),def_route);

		memcpy(dest.addr.raw,dst_addr,4);

	}else if( addr_family == AF_INET6 ){

		RHP_TRC(0,RHPTRCID_IFC_ADDR_SELECT_SRC_ADDR_V6,"xLd6d",ifc,"AF",addr_family,dst_addr,def_route);

		memcpy(dest.addr.raw,dst_addr,16);

	}else{

		RHP_TRC(0,RHPTRCID_IFC_ADDR_SELECT_SRC_ADDR_UNKWON_AF,"xLdxd",ifc,"AF",addr_family,dst_addr,def_route);

		goto end;
	}


	ifc_addr = ifc->ifc_addrs;
	while( ifc_addr ){

		if( ifc_addr->addr.addr_family != addr_family ){
			goto next;
		}

		if( ifc_addr_w == NULL ){

			if( rhp_ip_valid_peer_addrs(addr_family,ifc_addr->addr.addr.raw,dst_addr) ){
				ifc_addr_w = ifc_addr;
			}

		}else{

			int gw0 = 0;
			int gw1 = 0;

			// rhp_ip_addr_dump("gw0",&(ifc_addr->def_route_map.gateway_addr));
			// rhp_ip_addr_dump("gw1",&(ifc_addr_w->def_route_map.gateway_addr));
			// rhp_ip_addr_dump("ifc_addr->addr",&(ifc_addr->addr));
			// rhp_ip_addr_dump("ifc_addr_w->addr",&(ifc_addr_w->addr));
			// rhp_ip_addr_dump("dst_addr",&dest);

			if( def_route ){

				gw0 = (!rhp_ip_addr_null(&(ifc_addr->def_route_map.gateway_addr)) &&
						       !rhp_ip_is_linklocal(addr_family,ifc_addr->addr.addr.raw));
				gw1 = (!rhp_ip_addr_null(&(ifc_addr_w->def_route_map.gateway_addr)) &&
						       !rhp_ip_is_linklocal(addr_family,ifc_addr_w->addr.addr.raw));

				if( !rhp_ip_same_subnet2(addr_family,ifc_addr->addr.addr.raw,dst_addr,ifc_addr->addr.prefixlen) &&
					 !rhp_ip_same_subnet2(addr_family,ifc_addr_w->addr.addr.raw,dst_addr,ifc_addr_w->addr.prefixlen) ){

					if( gw0 && !gw1 ){
						ifc_addr_w = ifc_addr;
						goto next;
					}
				}
			}

			if( !rhp_ip_valid_peer_addrs(addr_family,ifc_addr->addr.addr.raw,dst_addr) ){
				goto next;
			}

			if( addr_family == AF_INET ){

				err = rhp_ipv4_cmp_src_addr(
						&(ifc_addr->addr),&(ifc_addr_w->addr),&dest);

			}else if( addr_family == AF_INET6 ){

				err = rhp_ipv6_cmp_src_addr(
						&(ifc_addr->addr),ifc_addr->if_addr_flags,
						&(ifc_addr_w->addr),ifc_addr_w->if_addr_flags,
						&dest);

			}else{

				err = -1;
			}

			if( err < 0 ){

				goto next;

			}else if( err == 0 ){

				if( def_route && gw0 && !gw1 ){
					ifc_addr_w = ifc_addr;
				}

			}else if( err == 1 ){

				ifc_addr_w = ifc_addr;

			}else{ // err == 2
				// ifc_addr_w wins.
			}
		}

next:
		ifc_addr = ifc_addr->lst_next;
	}

	ifc_addr = ifc_addr_w;

end:
	if( ifc_addr ){
    rhp_ip_addr_dump("ifc_addr->addr",&(ifc_addr->addr));
	}
	RHP_TRC(0,RHPTRCID_IFC_ADDR_SELECT_SRC_ADDR_RTRN,"xx",ifc,ifc_addr);
	return ifc_addr;
}


static int _rhp_ifc_addr_enum_by_def_route(rhp_ifc_entry* ifc,rhp_rt_map_entry* def_route_map,
		void (*callback)(rhp_ifc_entry* ifc,rhp_rt_map_entry* def_route_map,rhp_ifc_addr* ifc_addr,void* ctx),
		void* ctx)
{
	int err = -EINVAL;
	int n = 0;
	rhp_ifc_addr *ifc_addr = ifc->ifc_addrs;

	RHP_TRC(0,RHPTRCID_IFC_ADDR_ENUM_BY_DEF_ROUTE,"xxYx",ifc,def_route_map,callback,ctx);

	if( !rhp_ip_addr_null(&(def_route_map->dest_network)) ){
		RHP_BUG("");
		return err;
	}

	while( ifc_addr ){

		if( (def_route_map->addr_family == AF_INET &&
				 rhp_ip_same_subnet_v4(def_route_map->gateway_addr.addr.v4,
															 ifc_addr->addr.addr.v4,ifc_addr->addr.prefixlen)) ||
				(def_route_map->addr_family == AF_INET6 &&
				 rhp_ip_same_subnet_v6(def_route_map->gateway_addr.addr.v6,
															 ifc_addr->addr.addr.v6,ifc_addr->addr.prefixlen)) ){

			RHP_TRC(0,RHPTRCID_IFC_ADDR_ENUM_BY_DEF_ROUTE_CB,"xxxYx",ifc,def_route_map,ifc_addr,callback,ctx);
			callback(ifc,def_route_map,ifc_addr,ctx);

			n++;
		}

		ifc_addr = ifc_addr->lst_next;
	}

	if( n == 0 ){
		RHP_TRC(0,RHPTRCID_IFC_ADDR_ENUM_BY_DEF_ROUTE_NOENT,"xxYx",ifc,def_route_map,callback,ctx);
		return -ENOENT;
	}

	RHP_TRC(0,RHPTRCID_IFC_ADDR_ENUM_BY_DEF_ROUTE_RTRN,"xxYx",ifc,def_route_map,callback,ctx);
	return 0;
}

static void _rhp_ifc_addr_update_def_route_cb(rhp_ifc_entry* ifc,
		rhp_rt_map_entry* def_route_map,rhp_ifc_addr* ifc_addr,void* ctx)
{
	RHP_TRC(0,RHPTRCID_IFC_ADDR_UPDATE_DEF_ROUTE_CB,"xxxx",ifc,def_route_map,ifc_addr,ctx);

	memcpy(&(ifc_addr->def_route_map),def_route_map,sizeof(rhp_rt_map_entry));

	return;
}

static int _rhp_ifc_addr_update_def_route(rhp_ifc_entry* ifc,rhp_rt_map_entry* def_route_map)
{
	int err;

	RHP_TRC(0,RHPTRCID_IFC_ADDR_UPDATE_DEF_ROUTE,"xx",ifc,def_route_map);

	err = _rhp_ifc_addr_enum_by_def_route(ifc,def_route_map,
					_rhp_ifc_addr_update_def_route_cb,NULL);

	RHP_TRC(0,RHPTRCID_IFC_ADDR_UPDATE_DEF_ROUTE_RTRN,"xxE",ifc,def_route_map,err);
	return err;
}

static void _rhp_ifc_addr_clear_def_route_cb(rhp_ifc_entry* ifc,
		rhp_rt_map_entry* def_route_map,rhp_ifc_addr* ifc_addr,void* ctx)
{
	RHP_TRC(0,RHPTRCID_IFC_ADDR_CLEAR_DEF_ROUTE_CB,"xxxx",ifc,def_route_map,ifc_addr,ctx);

	memset(&(ifc_addr->def_route_map),0,sizeof(rhp_rt_map_entry));

	return;
}

static int _rhp_ifc_addr_clear_def_route(rhp_ifc_entry* ifc,rhp_rt_map_entry* def_route_map)
{
	int err;

	RHP_TRC(0,RHPTRCID_IFC_ADDR_CLEAR_DEF_ROUTE,"xx",ifc,def_route_map);

	err = _rhp_ifc_addr_enum_by_def_route(ifc,def_route_map,
					_rhp_ifc_addr_clear_def_route_cb,NULL);

	RHP_TRC(0,RHPTRCID_IFC_ADDR_CLEAR_DEF_ROUTE_RTRN,"xxE",ifc,def_route_map,err);
	return err;
}

rhp_ifc_entry* rhp_ifc_alloc()
{
  rhp_ifc_entry* ifc = (rhp_ifc_entry*)_rhp_malloc(sizeof(rhp_ifc_entry));

  if( ifc == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(ifc,0,sizeof(rhp_ifc_entry));

  ifc->tag[0] = '#';
  ifc->tag[1] = 'N';
  ifc->tag[2] = 'W';
  ifc->tag[3] = 'C';

  _rhp_atomic_init(&(ifc->refcnt));
  _rhp_atomic_init(&(ifc->is_active));
  _rhp_atomic_init(&(ifc->cfg_users_v4));
  _rhp_atomic_init(&(ifc->cfg_users_v6));

  _rhp_atomic_flag_init(&(ifc->tx_esp_pkt_pend_flag));
  _rhp_atomic_flag_init(&(ifc->rx_esp_pkt_pend_flag));

  _rhp_atomic_flag_init(&(ifc->tx_tuntap_pkt_pend_flag));
  _rhp_atomic_flag_init(&(ifc->rx_tuntap_pkt_pend_flag));


  _rhp_mutex_init("IFL",&(ifc->lock));

  ifc->if_index = -1;

  ifc->tuntap_fd = -1;

  ifc->get_addr = _rhp_ifc_addr_get_addr;
	ifc->delete_addr = _rhp_ifc_addr_delete_addr;
	ifc->set_addr = _rhp_ifc_addr_set_addr;
	ifc->enum_addrs = _rhp_ifc_addr_enum_addrs;
	ifc->select_src_addr = _rhp_ifc_addr_select_src_addr;
	ifc->move_addr_to_top = _rhp_ifc_addr_move_addr_to_top;
	ifc->update_def_route = _rhp_ifc_addr_update_def_route;
	ifc->clear_def_route = _rhp_ifc_addr_clear_def_route;

  ifc->dump_lock = _rhp_ifc_dump_lock;
  ifc->dump_no_lock = _rhp_ifc_dump_no_lock;

  RHP_TRC(0,RHPTRCID_NETMNG_IFC_ALLOC,"x",ifc);

  return ifc;
}

static void _rhp_ifc_free(rhp_ifc_entry* ifc)
{
  int i;

  RHP_TRC(0,RHPTRCID_NETMNG_IFC_FREE,"x",ifc);

  for( i = 0; i <= RHP_IFC_NOTIFIER_MAX;i++ ){
    if( rhp_ifc_notifiers[i].callback ){
      rhp_ifc_notifiers[i].callback(RHP_IFC_EVT_DESTROY,ifc,NULL,NULL,rhp_ifc_notifiers[i].ctx);
    }
  }

  {
  	rhp_ifc_addr *ifc_addr = ifc->ifc_addrs, *ifc_addr_n = NULL;

  	while( ifc_addr ){
  		ifc_addr_n = ifc_addr->lst_next;
  		_rhp_ifc_addr_free(ifc_addr);
  		ifc_addr = ifc_addr_n;
  	}
  }

  _rhp_mutex_destroy(&(ifc->lock));

  _rhp_atomic_destroy(&(ifc->refcnt));
  _rhp_atomic_destroy(&(ifc->is_active));
  _rhp_atomic_destroy(&(ifc->cfg_users_v4));
  _rhp_atomic_destroy(&(ifc->cfg_users_v6));

	_rhp_atomic_flag_destroy(&(ifc->tx_esp_pkt_pend_flag));
	_rhp_atomic_flag_destroy(&(ifc->rx_esp_pkt_pend_flag));

  _rhp_atomic_flag_destroy(&(ifc->tx_tuntap_pkt_pend_flag));
  _rhp_atomic_flag_destroy(&(ifc->rx_tuntap_pkt_pend_flag));

  _rhp_free_zero(ifc,sizeof(rhp_ifc_entry));

  return;
}

void rhp_ifc_hold(rhp_ifc_entry* ifc)
{
  _rhp_atomic_inc(&(ifc->refcnt));
  RHP_TRC(0,RHPTRCID_NETMNG_IFC_HOLD,"xd",ifc,_rhp_atomic_read(&(ifc->refcnt)));
}

void rhp_ifc_unhold(rhp_ifc_entry* ifc)
{
  RHP_TRC(0,RHPTRCID_NETMNG_IFC_UNHOLD,"xd",ifc,_rhp_atomic_read(&(ifc->refcnt)));
  if( _rhp_atomic_dec_and_test(&(ifc->refcnt)) ){
    _rhp_ifc_free(ifc);
  }
}

void rhp_ifc_put(rhp_ifc_entry* ifc)
{

  RHP_TRC(0,RHPTRCID_NETMNG_IFC_PUT,"x",ifc);

  RHP_LOCK(&rhp_ifc_lock);

  rhp_vpn_gen_or_add_local_mac(ifc->mac,NULL);

  if( _rhp_ifc_list_head ){
    ifc->next = _rhp_ifc_list_head;
  }
  _rhp_ifc_list_head = ifc;

  _rhp_atomic_set(&(ifc->is_active),1);
  rhp_ifc_hold(ifc);

  RHP_UNLOCK(&rhp_ifc_lock);

  return;
}

rhp_ifc_entry* rhp_ifc_get(char* if_name)
{
  rhp_ifc_entry* ifc;

  RHP_LOCK(&rhp_ifc_lock);

  ifc = _rhp_ifc_list_head;

  while( ifc ){

  	if( !strcmp(ifc->if_name,if_name) ){
      break;
    }

  	ifc = ifc->next;
  }

  if( ifc ){
    rhp_ifc_hold(ifc);
  }

  RHP_UNLOCK(&rhp_ifc_lock);

  RHP_TRC(0,RHPTRCID_NETMNG_IFC_GET,"sx",if_name,ifc);

  return ifc;
}

#define RHP_IFC_ENUM_LST_LEN		128
int rhp_ifc_enum(int (*callback)(rhp_ifc_entry* ifc,void* ctx),void* ctx)
{
	int err = -EINVAL;
	rhp_ifc_entry** ifc_list_head = NULL;
	rhp_ifc_entry* ifc;
	int ifc_list_num = RHP_IFC_ENUM_LST_LEN;
	int n = 0,i;

  RHP_TRC(0,RHPTRCID_NETMNG_IFC_ENUM,"Yx",callback,ctx);

	ifc_list_head = (rhp_ifc_entry**)_rhp_malloc(sizeof(rhp_ifc_entry*)*ifc_list_num);
	if( ifc_list_head == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}
	memset(ifc_list_head,0,sizeof(rhp_ifc_entry*)*ifc_list_num);


  RHP_LOCK(&rhp_ifc_lock);

  ifc = _rhp_ifc_list_head;

  while( ifc ){

  	if( n >= ifc_list_num ){

  		rhp_ifc_entry** tmp;

  		ifc_list_num += RHP_IFC_ENUM_LST_LEN;

  		tmp = (rhp_ifc_entry**)_rhp_malloc(sizeof(rhp_ifc_entry*)*ifc_list_num);
  		if( tmp == NULL ){

  			RHP_BUG("");

  			for( i = 0; i < n; i++ ){
  				rhp_ifc_unhold(ifc_list_head[i]);
  			}
  			_rhp_free(ifc_list_head);

  			RHP_UNLOCK(&rhp_ifc_lock);

  			return -ENOMEM;
  		}

  		memset(tmp,0,sizeof(rhp_ifc_entry*)*ifc_list_num);

  		memcpy(tmp,ifc_list_head,sizeof(rhp_ifc_entry*)*n);
			_rhp_free(ifc_list_head);

			ifc_list_head = tmp;
  	}

  	ifc_list_head[n] = ifc;
  	rhp_ifc_hold(ifc);

  	n++;
  	ifc = ifc->next;
  }

  RHP_UNLOCK(&rhp_ifc_lock);

  if( n == 0 ){
  	_rhp_free(ifc_list_head);
    RHP_TRC(0,RHPTRCID_NETMNG_IFC_ENUM_NO_ENT,"Yx",callback,ctx);
  	return -ENOENT;
  }

  for( i = 0; i < n; i++ ){

  	ifc = ifc_list_head[i];

		err = callback(ifc,ctx);
		if( err ){

	  	if( err == RHP_STATUS_ENUM_OK ){
	  		err = 0;
	  	}

			break;
		}
  }

	for( i = 0; i < n; i++ ){
		rhp_ifc_unhold(ifc_list_head[i]);
	}

	_rhp_free(ifc_list_head);

  RHP_TRC(0,RHPTRCID_NETMNG_IFC_ENUM_RTRN,"Yx",callback,ctx);
	return 0;
}

rhp_ifc_entry* rhp_ifc_dmy_vif_get()
{
  rhp_ifc_entry* ifc;

  RHP_LOCK(&rhp_ifc_lock);

  ifc = _rhp_ifc_list_head;
  while( ifc ){

  	if( ifc->is_dmy_tuntap ){
  		break;
  	}

    ifc = ifc->next;
  }

  if( ifc ){
    rhp_ifc_hold(ifc);
  }

  RHP_UNLOCK(&rhp_ifc_lock);

  RHP_TRC(0,RHPTRCID_NETMNG_IFC_DMY_VIF_GET,"x",ifc);

  return ifc;
}

//
// TODO : Adopting HASH based implementation NOT linked list!
//
rhp_ifc_entry* rhp_ifc_get_by_if_idx(int if_index)
{
  rhp_ifc_entry *ifc,*ifc_p = NULL;

  RHP_LOCK(&rhp_ifc_lock);

  ifc = _rhp_ifc_list_head;

  while( ifc ){

  	if( ifc->if_index == if_index ){
      break;
    }

  	ifc_p = ifc;
    ifc = ifc->next;
  }

  if( ifc ){

  	if( ifc_p ){
  		ifc_p->next = ifc->next;
    	ifc->next = _rhp_ifc_list_head;
    	_rhp_ifc_list_head = ifc;
  	}

    rhp_ifc_hold(ifc);
  }

  RHP_UNLOCK(&rhp_ifc_lock);

  if( ifc ){
  	RHP_TRC(0,RHPTRCID_NETMNG_IFC_GET_BY_IF_IDX,"dsx",if_index,ifc->if_name,ifc);
  }else{
  	RHP_TRC(0,RHPTRCID_NETMNG_IFC_GET_BY_IF_IDX,"dsx",if_index,"",ifc);
  }

  return ifc;
}

extern int rhp_bridge_delete_static_cache(unsigned long vpn_realm_id,u8* peer_mac);

void rhp_ifc_delete(rhp_ifc_entry* ifc)
{
  rhp_ifc_entry *ret,*retp = NULL;

  RHP_TRC(0,RHPTRCID_NETMNG_IFC_DELETE,"x",ifc);

  RHP_LOCK(&rhp_ifc_lock);

  ret = _rhp_ifc_list_head;
  while( ret ){

    if( ifc == ret ){
      break;
    }

    retp = ret;
    ret = ret->next;
  }

  if( ret ){

  	rhp_vpn_clear_local_mac(ifc->mac);

  	if( !_rhp_mac_addr_null(ifc->v6_aux_lladdr.mac) ){

  		rhp_bridge_static_cache_delete(ifc->tuntap_vpn_realm_id,ifc->v6_aux_lladdr.mac);

  	 	rhp_vpn_clear_local_mac(ifc->v6_aux_lladdr.mac);
  	}

    if( retp ){
      retp->next = ret->next;
    }else{
      _rhp_ifc_list_head = ret->next;
    }

    _rhp_atomic_set(&(ret->is_active),0);
    rhp_ifc_unhold(ret);

  }else{
    RHP_TRC(0,RHPTRCID_NETMNG_IFC_DELETE_NOT_FOUND,"x",ifc);
  }

  RHP_UNLOCK(&rhp_ifc_lock);
}

int rhp_ifc_addr_is_active(rhp_ifc_entry* ifc,rhp_ifc_addr* ifc_addr)
{
	if( ifc_addr->net_sk_ike == -1 ){
		goto not_active;
	}

	if( ifc_addr->addr.addr_family == AF_INET &&
			ifc_addr->addr.addr.v4 != 0 &&
			!rhp_ipv4_is_loopback(ifc_addr->addr.addr.v4) ){

		RHP_TRC(0,RHPTRCID_IFC_ADDR_IS_ACTIVE_V4,"xx",ifc,ifc_addr);
		return 1;

	}else if( ifc_addr->addr.addr_family == AF_INET6 &&
						!rhp_ipv6_addr_null(ifc_addr->addr.addr.v6) &&
						!rhp_ipv6_is_loopback(ifc_addr->addr.addr.v6) ){

		RHP_TRC(0,RHPTRCID_IFC_ADDR_IS_ACTIVE_V6,"xx",ifc,ifc_addr);
		return 1;
	}

not_active:
	RHP_TRC(0,RHPTRCID_IFC_ADDR_IS_NOT_ACTIVE,"xx",ifc,ifc_addr);
	return 0;
}

static int rhp_ifc_is_active_addr_cb(rhp_ifc_entry* ifc,rhp_ifc_addr* ifc_addr,void* ctx)
{
	int* ret = (int*)ctx;

	*ret = rhp_ifc_addr_is_active(ifc,ifc_addr);
	if( *ret ){
		return RHP_STATUS_ENUM_OK;
	}

	return 0;
}

int rhp_ifc_is_active(rhp_ifc_entry* ifc,int addr_family,u8* addr)
{
	int ret = 0;

	if( !_rhp_atomic_read(&(ifc->is_active)) ||
    !(ifc->if_flags & IFF_UP) ){

		goto not_active;
	}

	if( (addr_family == AF_INET || addr_family == AF_INET6) && addr ){

		rhp_ifc_addr* ifc_addr = ifc->get_addr(ifc,addr_family,addr);
		if( ifc_addr == NULL ){
			goto not_active;
		}

		ret = rhp_ifc_addr_is_active(ifc,ifc_addr);

	}else{

		ifc->enum_addrs(ifc,rhp_ifc_is_active_addr_cb,&ret);
	}

	if( !ret ){
		goto not_active;
	}

	RHP_TRC(0,RHPTRCID_IFC_IS_ACTIVE,"x",ifc);
  return 1;

not_active:
	RHP_TRC(0,RHPTRCID_IFC_IS_NOT_ACTIVE,"x",ifc);
	return 0;
}

int rhp_ifc_is_active_peer_addr(rhp_ifc_entry* ifc,rhp_ip_addr* peer_addr)
{
	rhp_ifc_addr* ifc_addr;

	if( peer_addr == NULL ){
		return rhp_ifc_is_active(ifc,AF_UNSPEC,NULL);
	}

	if( !_rhp_atomic_read(&(ifc->is_active)) ||
    !(ifc->if_flags & IFF_UP) ){

		goto not_active;
	}

	ifc_addr = ifc->ifc_addrs;
	while( ifc_addr ){

		if( ifc_addr->addr.addr_family != peer_addr->addr_family ){
			goto next;
		}

		if( !rhp_ip_valid_peer_addrs(ifc_addr->addr.addr_family,
					ifc_addr->addr.addr.raw,peer_addr->addr.raw) ){
			goto next;
		}

		if( rhp_ifc_addr_is_active(ifc,ifc_addr) ){
			RHP_TRC(0,RHPTRCID_IFC_IS_ACTIVE_PEER_ADDR,"xx",ifc,ifc_addr);
			return 1;
		}

next:
		ifc_addr = ifc_addr->lst_next;
	}

not_active:
		RHP_TRC(0,RHPTRCID_IFC_IS_NOT_ACTIVE_PEER_ADDR,"x",ifc);
		return 0;
}

int rhp_ifc_is_active_ifc_addr(rhp_ifc_entry* ifc,rhp_ifc_addr* ifc_addr)
{
	int ret = 0;

	if( !_rhp_atomic_read(&(ifc->is_active)) ||
    !(ifc->if_flags & IFF_UP) ){

		goto not_active;
	}

	if( ifc_addr == NULL ){
		goto not_active;
	}

	ret = rhp_ifc_addr_is_active(ifc,ifc_addr);
	if( !ret ){
		goto not_active;
	}

	RHP_TRC(0,RHPTRCID_IFC_IS_ACTIVE_IFC_ADDR,"x",ifc);
  return 1;

not_active:
	RHP_TRC(0,RHPTRCID_IFC_IS_NOT_ACTIVE_IFC_ADDR,"x",ifc);
	return 0;
}

// Caller must hold ifc->refcnt.
void rhp_ifc_call_notifiers(int event,rhp_ifc_entry* ifc,rhp_if_entry* new_info,rhp_if_entry* old)
{
  int i;

  for( i = 0; i <= RHP_IFC_NOTIFIER_MAX;i++ ){

    if( rhp_ifc_notifiers[i].callback ){

      RHP_TRC(0,RHPTRCID_NETMNG_IFC_CALL_NOTIFIER,"Ydxx",rhp_ifc_notifiers[i].callback,event,ifc,rhp_ifc_notifiers[i].ctx);
      ifc->dump_lock("rhp_ifc_call_notifiers",ifc);
      rhp_if_entry_dump("rhp_ifc_call_notifiers_new",new_info);
      rhp_if_entry_dump("rhp_ifc_call_notifiers_old",old);

      rhp_ifc_notifiers[i].callback(event,ifc,new_info,old,rhp_ifc_notifiers[i].ctx);
    }
  }

  return;
}

int rhp_ifc_copy_to_if_entry(rhp_ifc_entry* ifc,rhp_if_entry* if_info_r,int addr_family,u8* addr)
{
	rhp_ifc_addr* ifc_addr;

	ifc->dump_no_lock("rhp_ifc_to_if_entry",ifc);

 	ifc_addr = ifc->get_addr(ifc,addr_family,addr);
 	if( ifc_addr ){

 		memcpy(if_info_r->if_name,ifc->if_name,RHP_IFNAMSIZ);
 		memcpy(if_info_r->mac,ifc->mac,6);

 		if_info_r->if_index = ifc->if_index;
 		if_info_r->if_flags = ifc->if_flags;
 		if_info_r->mtu = ifc->mtu;

 		if_info_r->addr_family = addr_family;
 		memcpy(if_info_r->addr.raw,ifc_addr->addr.addr.raw,16);
 		if_info_r->prefixlen = ifc_addr->addr.prefixlen;

 		if_info_r->if_addr_flags = ifc_addr->if_addr_flags;

 	}else{

 		RHP_BUG("");
 		return -EINVAL;
 	}

	rhp_if_entry_dump("rhp_ifc_copy_to_if_entry",if_info_r);

  return 0;
}

int rhp_ifc_copy_if_info(rhp_if_entry* if_info_from,rhp_ifc_entry* ifc_to)
{
	ifc_to->dump_no_lock("rhp_ifc_copy_if_info_b4",ifc_to);
	rhp_if_entry_dump("rhp_ifc_copy_if_info",if_info_from);

	memcpy(ifc_to->if_name,if_info_from->if_name,RHP_IFNAMSIZ);
	memcpy(ifc_to->mac,if_info_from->mac,6);

	ifc_to->if_index = if_info_from->if_index;
	ifc_to->if_flags = if_info_from->if_flags;
	ifc_to->mtu = if_info_from->mtu;

	ifc_to->dump_no_lock("rhp_ifc_copy_if_info",ifc_to);
  return 0;
}

int rhp_ifc_copy_if_info2(rhp_ifc_entry* ifc_from,rhp_if_entry* if_info_to)
{
	ifc_from->dump_no_lock("rhp_ifc_copy_if_info_b4",ifc_from);
	rhp_if_entry_dump("rhp_ifc_copy_if_info",if_info_to);

	memcpy(if_info_to->if_name,ifc_from->if_name,RHP_IFNAMSIZ);
	memcpy(if_info_to->mac,ifc_from->mac,6);

	if_info_to->if_index = ifc_from->if_index;
	if_info_to->if_flags = ifc_from->if_flags;
	if_info_to->mtu = ifc_from->mtu;

	ifc_from->dump_no_lock("rhp_ifc_copy_if_info",ifc_from);
  return 0;
}

int rhp_ifc_entry_cmp(rhp_ifc_entry* ifc,rhp_if_entry* if_info)
{
	rhp_ifc_addr* ifc_addr;

	RHP_TRC(0,RHPTRCID_IFC_ENTRY_CMP,"xx",ifc,if_info);
	ifc->dump_no_lock("ifc",ifc);
	rhp_if_entry_dump("if_info",if_info);

	if( ifc->if_index != if_info->if_index ){
		goto error;
	}

	ifc_addr = ifc->get_addr(ifc,if_info->addr_family,if_info->addr.raw);
	if( ifc_addr == NULL ){
		goto error;
	}

	if( ifc_addr->addr.addr_family != if_info->addr_family ){
		goto error;
	}

	if( ifc_addr->addr.addr_family == AF_INET ){
		if( ifc_addr->addr.addr.v4 != if_info->addr.v4 ){
			goto error;
		}
	}else if( ifc_addr->addr.addr_family == AF_INET6 ){
		if( memcmp(ifc_addr->addr.addr.v6,if_info->addr.v6,16) ){
			goto error;
		}
	}

	if( (ifc->if_flags & IFF_UP) != (if_info->if_flags & IFF_UP) ){
		goto error;
	}

	if( memcmp(ifc->mac,if_info->mac,6) ){
		goto error;
	}

	RHP_TRC(0,RHPTRCID_IFC_ENTRY_CMP_SAME,"xx",ifc,if_info);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IFC_ENTRY_CMP_NOT_SAME,"xx",ifc,if_info);
	return -1;
}


#define RHP_IFC_MY_IP_HASH_TABLE_SIZE	13
struct _rhp_ifc_my_ip {

	u8 tag[4]; // '#MYI'

	struct _rhp_ifc_my_ip* next;

  int addr_family; // AF_INET or AF_INET6

  union {
    u32 v4;
    u8  v6[16];
    u8  raw[16];
  } addr;
};
typedef struct _rhp_ifc_my_ip		rhp_ifc_my_ip;

static rhp_ifc_my_ip* _rhp_ifc_my_ip_hashtbl[RHP_IFC_MY_IP_HASH_TABLE_SIZE];
static u32 _rhp_ifc_my_ip_hashtbl_rnd;

static u32 _rhp_ifc_my_ip_hash_v4(u32 ip)
{
	u32 hash;

	hash = _rhp_hash_ipv4_1(ip,_rhp_ifc_my_ip_hashtbl_rnd);

	return (hash % RHP_IFC_MY_IP_HASH_TABLE_SIZE);
}

static u32 _rhp_ifc_my_ip_hash_v6(u8* ip)
{
	u32 hash;

	hash = _rhp_hash_ipv6_1(ip,_rhp_ifc_my_ip_hashtbl_rnd);

	return (hash % RHP_IFC_MY_IP_HASH_TABLE_SIZE);
}

static rhp_ifc_my_ip* _rhp_ifc_my_ip_delete(int addr_family,u8* ip)
{
	rhp_ifc_my_ip *my_ip, *my_ip_tmp = NULL;
	u32 hash;

	if( addr_family == AF_INET ){
		hash = _rhp_ifc_my_ip_hash_v4(*((u32*)ip));
	}else if( addr_family == AF_INET6 ){
		hash = _rhp_ifc_my_ip_hash_v6(ip);
	}else{
		return NULL;
	}

  my_ip = _rhp_ifc_my_ip_hashtbl[hash];
  while( my_ip ){

  	if( my_ip->addr_family == addr_family &&
  			((addr_family == AF_INET && my_ip->addr.v4 == *((u32*)ip)) ||
  			 (addr_family == AF_INET6 && rhp_ipv6_is_same_addr(my_ip->addr.v6,ip))) ){
  		break;
  	}

  	my_ip_tmp = my_ip;
  	my_ip = my_ip->next;
  }

  if( my_ip ){

  	if( my_ip_tmp ){
  		my_ip_tmp->next = my_ip->next;
  	}else{
  		_rhp_ifc_my_ip_hashtbl[hash] = my_ip->next;
  	}
  }

	return my_ip;
}

static rhp_ifc_my_ip* _rhp_ifc_my_ip_get(int addr_family,u8* ip)
{
	rhp_ifc_my_ip *my_ip;
	u32 hash;

	if( addr_family == AF_INET ){
		hash = _rhp_ifc_my_ip_hash_v4(*((u32*)ip));
	}else if( addr_family == AF_INET6 ){
		hash = _rhp_ifc_my_ip_hash_v6(ip);
	}else{
		return NULL;
	}

  my_ip = _rhp_ifc_my_ip_hashtbl[hash];
  while( my_ip ){

  	if( my_ip->addr_family == addr_family &&
  			((addr_family == AF_INET && my_ip->addr.v4 == *((u32*)ip)) ||
  			 (addr_family == AF_INET6 && rhp_ipv6_is_same_addr(my_ip->addr.v6,ip))) ){

  		return my_ip;
  	}

  	my_ip = my_ip->next;
  }

	return NULL;
}

int rhp_ifc_is_my_ip_v4(u32 ip)
{
	rhp_ifc_my_ip* my_ip;
	int ret = 0;

	RHP_LOCK(&rhp_ifc_lock);

	my_ip = _rhp_ifc_my_ip_get(AF_INET,(u8*)&ip);
	if( my_ip ){
		ret = 1;
	}

  RHP_UNLOCK(&rhp_ifc_lock);

  return ret;
}

int rhp_ifc_is_my_ip_v6(u8* ip)
{
	rhp_ifc_my_ip* my_ip;
	int ret = 0;

	RHP_LOCK(&rhp_ifc_lock);

	my_ip = _rhp_ifc_my_ip_get(AF_INET6,ip);
	if( my_ip ){
		ret = 1;
	}

  RHP_UNLOCK(&rhp_ifc_lock);

  return ret;
}


void rhp_ifc_my_ip_update(rhp_if_entry* ifent_old,rhp_if_entry* ifent_new)
{
	rhp_ifc_my_ip* my_ip = NULL;
	u32 hash = 0;
	int old_null = (ifent_old->addr_family == AF_INET && ifent_old->addr.v4 == 0) ||
								 (ifent_old->addr_family == AF_INET6 && rhp_ipv6_addr_null(ifent_old->addr.v6));
	int new_null = (ifent_new->addr_family == AF_INET && ifent_new->addr.v4 == 0) ||
								 (ifent_new->addr_family == AF_INET6 && rhp_ipv6_addr_null(ifent_new->addr.v6));


	RHP_LOCK(&rhp_ifc_lock);

	if( ifent_old->addr_family == AF_INET || ifent_new->addr_family == AF_INET ){

		if( !old_null ){

			my_ip = _rhp_ifc_my_ip_delete(ifent_old->addr_family,ifent_old->addr.raw);
		}

		if( !new_null && my_ip == NULL ){

			my_ip = (rhp_ifc_my_ip*)_rhp_malloc(sizeof(rhp_ifc_my_ip));
			if( my_ip == NULL ){
				RHP_BUG("");
				goto error;
			}

			memset(my_ip,0,sizeof(rhp_ifc_my_ip));

			my_ip->tag[0] = '#';
			my_ip->tag[1] = 'M';
			my_ip->tag[2] = 'Y';
			my_ip->tag[3] = 'I';
		}

		if( my_ip ){

			my_ip->addr_family = ifent_new->addr_family;
			memcpy(my_ip->addr.raw,ifent_new->addr.raw,16);

			if( my_ip->addr_family == AF_INET ){
				hash = _rhp_ifc_my_ip_hash_v4(ifent_new->addr.v4);
			}else if( my_ip->addr_family == AF_INET6 ){
				hash = _rhp_ifc_my_ip_hash_v6(ifent_new->addr.v6);
			}

			my_ip->next = _rhp_ifc_my_ip_hashtbl[hash];
			_rhp_ifc_my_ip_hashtbl[hash] = my_ip;
		}
	}

error:
	RHP_UNLOCK(&rhp_ifc_lock);

	return;
}

void rhp_ifc_my_ip_clear(rhp_if_entry* ifent)
{
	rhp_ifc_my_ip* my_ip = NULL;

	RHP_LOCK(&rhp_ifc_lock);

	my_ip = _rhp_ifc_my_ip_delete(ifent->addr_family,ifent->addr.raw);
	if( my_ip ){
		_rhp_free(my_ip);
	}else{
    RHP_TRC(0,RHPTRCID_NETMNG_IFC_MY_IP_CLEAR_NO_ENT,"x",ifent);
	}

	RHP_UNLOCK(&rhp_ifc_lock);

	return;
}


int rhp_ifc_init()
{
  _rhp_mutex_init("IFC",&rhp_ifc_lock);

  memset(rhp_ifc_notifiers,0,sizeof(rhp_ifc_notifier)*(RHP_IFC_NOTIFIER_MAX+1));


  if( rhp_random_bytes((u8*)&_rhp_ifc_my_ip_hashtbl_rnd,sizeof(_rhp_ifc_my_ip_hashtbl_rnd)) ){
    RHP_BUG("");
    return -EINVAL;
  }

  memset(_rhp_ifc_my_ip_hashtbl,0,sizeof(rhp_ifc_my_ip*)*RHP_IFC_MY_IP_HASH_TABLE_SIZE);

  return 0;
}


int rhp_ifc_cleanup()
{
  rhp_ifc_entry* v_ifc;

  RHP_LOCK(&rhp_ifc_lock);
  {
		v_ifc = _rhp_ifc_list_head;
		while( v_ifc ){

			if( v_ifc->tuntap_fd != -1 ){
				rhp_tuntap_close(v_ifc);
			}

			v_ifc = v_ifc->next;
		}
  }
  RHP_UNLOCK(&rhp_ifc_lock);

  _rhp_mutex_destroy(&rhp_ifc_lock);

	return 0;
}
