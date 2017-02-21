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
#include <sys/capability.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_packet.h"
#include "rhp_netsock.h"
#include "rhp_timer.h"
#include "rhp_wthreads.h"
#include "rhp_config.h"
#include "rhp_ikev2_mesg.h"
#include "rhp_http.h"
#include "rhp_dns_pxy.h"
#include "rhp_vpn.h"


extern rhp_mutex_t rhp_cfg_lock;
extern rhp_vpn_realm* rhp_realm_list_head;

static rhp_vpn_realm_disabled* rhp_realm_disabled_list_head = NULL;


// TODO : If rlm->my_interfaces is "ANY" , sort by interface type.(ex) LAN interfaces have
//        higher priorities than WLAN interfaces. etc...
static rhp_cfg_if* _rhp_realm_get_next_my_interface(rhp_vpn_realm* rlm,
		char* cur_if_name,rhp_ip_addr* peer_addr)
{
  rhp_cfg_if* cfg_if = NULL;

  // cfg_if->ifc is already linked to rlm->my_interfaces. rhp_ifc_hold() not needed;

  RHP_TRC(0,RHPTRCID_REALM_GET_NEXT_MY_INTERFACE,"xsx",rlm,cur_if_name,peer_addr);
  if( peer_addr ){
  	rhp_ip_addr_dump("_rhp_realm_get_next_my_interface",peer_addr);
  }

	cfg_if = rlm->my_interfaces;

	if( cur_if_name ){

  	while( cfg_if ){

    if( !strcmp(cur_if_name,cfg_if->if_name) ){
    	cfg_if = cfg_if->next;
    	break;
     }

     cfg_if = cfg_if->next;
  	}
  }

  while( cfg_if ){

  	if( cfg_if->ifc ){

  		RHP_LOCK(&(cfg_if->ifc->lock));

  		cfg_if->ifc->dump_no_lock("_rhp_realm_get_next_my_interface",cfg_if->ifc);

  		if( rhp_ifc_is_active_peer_addr(cfg_if->ifc,peer_addr) ){
        RHP_UNLOCK(&(cfg_if->ifc->lock));
        break;
      }

  		RHP_UNLOCK(&(cfg_if->ifc->lock));
    }

  	cfg_if = cfg_if->next;
  }

  RHP_TRC(0,RHPTRCID_REALM_GET_NEXT_MY_INTERFACE_RTRN,"xx",rlm,cfg_if);
  return cfg_if;
}


static rhp_cfg_if* _rhp_realm_get_next_my_interface_def_route(rhp_vpn_realm* rlm,
		char* cur_if_name,rhp_ip_addr* peer_addr)
{
  rhp_cfg_if* cfg_if = NULL;

  // cfg_if->ifc is already linked to rlm->my_interfaces. rhp_ifc_hold() not needed;

  RHP_TRC(0,RHPTRCID_REALM_GET_NEXT_MY_INTERFACE_DEF_ROUTE,"xsx",rlm,cur_if_name,peer_addr);
  if( peer_addr ){
  	rhp_ip_addr_dump("_rhp_realm_get_next_my_interface_def_route",peer_addr);
  }

	cfg_if = rlm->my_interfaces;

	if( cur_if_name ){

  	while( cfg_if ){

    if( !strcmp(cur_if_name,cfg_if->if_name) ){
    	cfg_if = cfg_if->next;
    	break;
     }

     cfg_if = cfg_if->next;
  	}
  }

  while( cfg_if ){

  	if( cfg_if->ifc ){

  		RHP_LOCK(&(cfg_if->ifc->lock));

  		cfg_if->ifc->dump_no_lock("_rhp_realm_get_next_my_interface_def_route",cfg_if->ifc);

  		if( rhp_ifc_is_active_peer_addr(cfg_if->ifc,peer_addr) ){
        RHP_UNLOCK(&(cfg_if->ifc->lock));
        break;
      }

  		RHP_UNLOCK(&(cfg_if->ifc->lock));
    }

  	cfg_if = cfg_if->next;
  }

  RHP_TRC(0,RHPTRCID_REALM_GET_NEXT_MY_INTERFACE_DEF_ROUTE_RTRN,"xx",rlm,cfg_if);
  return cfg_if;
}

// [CAUTION]
//  This func internally calls ifc->lock. Caller must NOT acquire it.
static int _rhp_realm_my_interface_cmp_priority(rhp_vpn_realm* rlm,
		int current_if_index,int checked_if_index,rhp_ip_addr* peer_addr)
{
  rhp_cfg_if* cfg_if = NULL;
  int flag = 0;
  int cur_pri = -1, checked_pri = -1;

  // cfg_if->ifc is already linked to rlm->my_interfaces. rhp_ifc_hold() not needed;

  RHP_TRC(0,RHPTRCID_MY_INTERFACE_CMP_PRIORITY,"xddx",rlm,current_if_index,checked_if_index,peer_addr);
  if( peer_addr ){
  	rhp_ip_addr_dump("_rhp_realm_my_interface_cmp_priority",peer_addr);
  }

  if( current_if_index == checked_if_index ){
    RHP_TRC(0,RHPTRCID_MY_INTERFACE_CMP_PRIORITY_SAME_IF_IDX,"xdd",rlm,current_if_index,checked_if_index);
  	return 0;
  }

  if( current_if_index < 0 || checked_if_index < 0 ){
    RHP_TRC(0,RHPTRCID_MY_INTERFACE_CMP_PRIORITY_NOT_ACTIVE,"xdd",rlm,current_if_index,checked_if_index);
  	return 0;
  }

	cfg_if = rlm->my_interfaces;
	while( cfg_if ){

  	if( cfg_if->ifc ){

  		RHP_LOCK(&(cfg_if->ifc->lock));

  		if( rhp_ifc_is_active_peer_addr(cfg_if->ifc,peer_addr) ){

				if( cfg_if->ifc->if_index == current_if_index ){

					cur_pri = cfg_if->priority;

				}else	if( cfg_if->ifc->if_index == checked_if_index ){

					checked_pri = cfg_if->priority;
				}
  		}

  		RHP_UNLOCK(&(cfg_if->ifc->lock));

  		if( cur_pri >= 0 && checked_pri >= 0 ){
  			break;
  		}
  	}

  	cfg_if = cfg_if->next;
	}

	if( cur_pri >= 0 && checked_pri >= 0 &&
			cur_pri >= checked_pri ){

		flag = 1;
	}

  RHP_TRC(0,RHPTRCID_MY_INTERFACE_CMP_PRIORITY_RTRN,"xddd",rlm,current_if_index,checked_if_index,flag);
  return flag;
}


static rhp_cfg_if* _rhp_realm_get_my_interface(rhp_vpn_realm* rlm,
		char* if_name,int addr_family)
{
  rhp_cfg_if* cfg_if = NULL;

  // cfg_if->ifc is already linked to rlm->my_interfaces. rhp_ifc_hold() not needed;
  cfg_if = rlm->my_interfaces;

  while( cfg_if ){

    if( !strcmp(if_name,cfg_if->if_name) ){

      if( (addr_family == -1 ||
      		 cfg_if->addr_family == AF_UNSPEC ||
      		 cfg_if->addr_family == addr_family) &&
      		rhp_ifc_is_active(cfg_if->ifc,AF_UNSPEC,NULL) ){

        RHP_TRC(0,RHPTRCID_REALM_GET_MY_INTERFACE,"xsLdx",rlm,if_name,"AF",addr_family,cfg_if);
        return cfg_if;
      }

      RHP_TRC(0,RHPTRCID_REALM_GET_MY_INTERFACE_FOUND_BUT_NOT_ACTIVE,"xsLd",rlm,if_name,"AF",addr_family);
      return NULL;
    }

    cfg_if = cfg_if->next;
  }

  RHP_TRC(0,RHPTRCID_REALM_GET_MY_INTERFACE_NOT_FOUND,"xsLd",rlm,if_name,"AF",addr_family);
  return NULL;
}

// Caller must decrement ifc->users by rhp_ifc_unhold().
static rhp_cfg_internal_if* _rhp_realm_get_internal_if(rhp_vpn_realm* rlm)
{
  RHP_TRC(0,RHPTRCID_REALM_GET_TUNIF,"xx",rlm,rlm->internal_ifc);
  return rlm->internal_ifc; // ifc is already linked to rlm->internal_ifc. rhp_ifc_hold() not needed;
}

static rhp_cfg_peer* _rhp_realm_get_peer_by_primary_addr(rhp_vpn_realm* rlm,rhp_ip_addr* addr)
{
  rhp_cfg_peer* cfg_peer = rlm->peers;

  rhp_ip_addr_dump("_rhp_realm_get_peer_by_primary_addr",addr);

  if( addr == NULL ){
  	RHP_BUG("");
  	return NULL;
  }

  while( cfg_peer ){

    if( !rhp_ip_addr_cmp(addr,&(cfg_peer->primary_addr)) ){
      break;
    }

    cfg_peer = cfg_peer->next;
  }

  RHP_TRC(0,RHPTRCID_REALM_GET_PEER_BY_PRIMARY_ADDR,"xxx",rlm,addr,cfg_peer);
  return cfg_peer;
}

static rhp_cfg_peer* _rhp_realm_get_peer_by_id(rhp_vpn_realm* rlm,rhp_ikev2_id* id)
{
  rhp_cfg_peer* cfg_peer = rlm->peers;
  rhp_cfg_peer* cfg_peer2 = NULL;

  rhp_ikev2_id_dump("_rhp_realm_get_peer_by_id",id);

  if( id == NULL ){
  	RHP_BUG("");
  	return NULL;
  }

  while( cfg_peer ){

  	if( cfg_peer->id.alt_id == NULL ){

  		if( !rhp_ikev2_id_cmp_no_alt_id(id,&(cfg_peer->id)) ){
  			break;
  		}

  	}else{

  		if( !rhp_ikev2_id_cmp(id,&(cfg_peer->id)) ){
  			break;
  		}
  	}

    if( cfg_peer2 == NULL &&
    		cfg_peer->id.type == RHP_PROTO_IKE_ID_ANY &&
    		rhp_ip_addr_null(&(cfg_peer->primary_addr)) ){

    	cfg_peer2 = cfg_peer;
    }

    cfg_peer = cfg_peer->next;
  }

  if( cfg_peer == NULL ){
    cfg_peer = cfg_peer2; // ANY_ID
  }

  RHP_TRC(0,RHPTRCID_REALM_GET_PEER_BY_ID,"xxxx",rlm,id,id->alt_id,cfg_peer);
  if( cfg_peer ){
    RHP_TRC(0,RHPTRCID_REALM_GET_PEER_BY_ID_INFO,"xsss",cfg_peer,cfg_peer->primary_addr_fqdn,cfg_peer->primary_tx_if_name,cfg_peer->secondary_tx_if_name);
  	rhp_ip_addr_dump("primary_addr",&(cfg_peer->primary_addr));
  	rhp_ip_addr_dump("secondary_addr",&(cfg_peer->secondary_addr));
		rhp_ip_addr_dump("ikev2_cfg_rmt_clt_old_addr_v4",&(cfg_peer->ikev2_cfg_rmt_clt_old_addr_v4));
		rhp_ip_addr_dump("ikev2_cfg_rmt_clt_old_addr_v6",&(cfg_peer->ikev2_cfg_rmt_clt_old_addr_v6));
  }

  return cfg_peer;
}


void rhp_realm_free_peer_cfg(rhp_cfg_peer* peers)
{
  rhp_cfg_peer *cfg_peer,*cfg_peer_n;
  rhp_traffic_selector *cfg_ts,*cfg_ts_n;

  cfg_peer = peers;
  while( cfg_peer ){

    cfg_peer_n = cfg_peer->next;

    RHP_TRC(0,RHPTRCID_REALM_FREE_PEER_CFG,"x",cfg_peer);

    if( cfg_peer->vpn_aoc_objid ){
    	rhp_vpn_aoc_delete(cfg_peer->vpn_aoc_objid);
    }

    rhp_ikev2_id_clear(&(cfg_peer->id));

    cfg_ts = cfg_peer->my_tss;
    while( cfg_ts ){
    	cfg_ts_n = cfg_ts->next;
      _rhp_free_zero(cfg_ts,sizeof(rhp_traffic_selector));
      cfg_ts = cfg_ts_n;
    }

    cfg_ts = cfg_peer->peer_tss;
    while( cfg_ts ){
    	cfg_ts_n = cfg_ts->next;
      _rhp_free_zero(cfg_ts,sizeof(rhp_traffic_selector));
      cfg_ts = cfg_ts_n;
    }

    if( cfg_peer->primary_tx_if_name ){
    	_rhp_free(cfg_peer->primary_tx_if_name);
    }
    if( cfg_peer->secondary_tx_if_name ){
    	_rhp_free(cfg_peer->secondary_tx_if_name);
    }

    if( cfg_peer->primary_addr_fqdn ){
    	_rhp_free(cfg_peer->primary_addr_fqdn);
    }

    _rhp_free_zero(cfg_peer,sizeof(rhp_cfg_peer));

    cfg_peer = cfg_peer_n;
  }

  return;
}

static rhp_cfg_peer* _rhp_realm_dup_cfg_peers(rhp_cfg_peer* cfg_peer,rhp_ikev2_id* peer_id,rhp_ip_addr* peer_addr)
{
  rhp_cfg_peer* dup_cfg_peer;
  rhp_traffic_selector *tss, *dup_tss, *dup_tss_p;
  int err;

  RHP_TRC(0,RHPTRCID_REALM_DUP_CFG_PEERS,"xxx",cfg_peer,peer_id,peer_addr);
  rhp_ikev2_id_dump("_rhp_realm_dup_cfg_peers",peer_id);
  rhp_ip_addr_dump("_rhp_realm_dup_cfg_peers",peer_addr);

  dup_cfg_peer = (rhp_cfg_peer*)_rhp_malloc(sizeof(rhp_cfg_peer));
  if( dup_cfg_peer == NULL ){
  	RHP_BUG("");
  	return NULL;
  }

  memcpy(dup_cfg_peer,cfg_peer,sizeof(rhp_cfg_peer));

  dup_cfg_peer->next = NULL;
  dup_cfg_peer->my_tss = NULL;
  dup_cfg_peer->peer_tss = NULL;
  dup_cfg_peer->my_tss_num = 0;
  dup_cfg_peer->peer_tss_num = 0;
  dup_cfg_peer->vpn_aoc_objid = 0;

  if( peer_addr ){
  	memcpy(&(dup_cfg_peer->primary_addr),peer_addr,sizeof(rhp_ip_addr));
  }
  rhp_ip_addr_dump("_rhp_realm_dup_cfg_peers.dup",&(dup_cfg_peer->primary_addr));


  if( cfg_peer->primary_tx_if_name ){

  	dup_cfg_peer->primary_tx_if_name = _rhp_malloc(strlen(cfg_peer->primary_tx_if_name) + 1);
		if( dup_cfg_peer->primary_tx_if_name == NULL ){
			RHP_BUG("");
			goto error;
		}
		dup_cfg_peer->primary_tx_if_name[0] = '\0';
		strcpy(dup_cfg_peer->primary_tx_if_name,cfg_peer->primary_tx_if_name);
  }

  if( cfg_peer->secondary_tx_if_name ){

		dup_cfg_peer->secondary_tx_if_name = _rhp_malloc(strlen(cfg_peer->secondary_tx_if_name) + 1);
		if( dup_cfg_peer->secondary_tx_if_name == NULL ){
			RHP_BUG("");
			goto error;
		}
		dup_cfg_peer->secondary_tx_if_name[0] = '\0';
		strcpy(dup_cfg_peer->secondary_tx_if_name,cfg_peer->secondary_tx_if_name);
  }

  memset(&(dup_cfg_peer->id),0,sizeof(rhp_ikev2_id));
  if( peer_id == NULL ){
		err = rhp_ikev2_id_dup(&(dup_cfg_peer->id),&(cfg_peer->id));
  }else{
		err = rhp_ikev2_id_dup(&(dup_cfg_peer->id),peer_id);
  }
	if( err ){
		RHP_BUG("");
		goto error;
	}
  rhp_ikev2_id_dump("_rhp_realm_dup_cfg_peers.dup",&(dup_cfg_peer->id));


  if( cfg_peer->primary_addr_fqdn ){

		dup_cfg_peer->primary_addr_fqdn = _rhp_malloc(strlen(cfg_peer->primary_addr_fqdn) + 1);
		if( dup_cfg_peer->primary_addr_fqdn == NULL ){
			RHP_BUG("");
			goto error;
		}
		dup_cfg_peer->primary_addr_fqdn[0] = '\0';
		strcpy(dup_cfg_peer->primary_addr_fqdn,cfg_peer->primary_addr_fqdn);
  }


  tss = cfg_peer->my_tss;
  dup_tss_p = NULL;
  while( tss ){

  	dup_tss = (rhp_traffic_selector*)_rhp_malloc(sizeof(rhp_traffic_selector));
		if( dup_tss == NULL ){
			RHP_BUG("");
			goto error;
		}

		memcpy(dup_tss,tss,sizeof(rhp_traffic_selector));
		dup_tss->next = NULL;

		if( dup_tss_p == NULL ){
			dup_cfg_peer->my_tss = dup_tss;
		}else{
			dup_tss_p->next = dup_tss;
		}
		dup_cfg_peer->my_tss_num++;

		dup_tss_p = dup_tss;

		tss = tss->next;
  }
	rhp_cfg_traffic_selectors_dump("_rhp_realm_dup_cfg_peers.my_tss",cfg_peer->my_tss,NULL);
	rhp_cfg_traffic_selectors_dump("_rhp_realm_dup_cfg_peers.my_dup_tss",dup_cfg_peer->my_tss,NULL);

  tss = cfg_peer->peer_tss;
  dup_tss_p = NULL;
  while( tss ){

  	dup_tss = (rhp_traffic_selector*)_rhp_malloc(sizeof(rhp_traffic_selector));
		if( dup_tss == NULL ){
			RHP_BUG("");
			goto error;
		}

		memcpy(dup_tss,tss,sizeof(rhp_traffic_selector));
		dup_tss->next = NULL;

		if( dup_tss_p == NULL ){
			dup_cfg_peer->peer_tss = dup_tss;
		}else{
			dup_tss_p->next = dup_tss;
		}
		dup_cfg_peer->peer_tss_num++;

		dup_tss_p = dup_tss;

		tss = tss->next;
  }
	rhp_cfg_traffic_selectors_dump("_rhp_realm_dup_cfg_peers.peer_tss",cfg_peer->peer_tss,NULL);
	rhp_cfg_traffic_selectors_dump("_rhp_realm_dup_cfg_peers.peer_dup_tss",dup_cfg_peer->peer_tss,NULL);

  RHP_TRC(0,RHPTRCID_REALM_DUP_CFG_PEERS_RTRN,"xxxxdd",cfg_peer,peer_id,peer_addr,dup_cfg_peer,dup_cfg_peer->my_tss_num,dup_cfg_peer->peer_tss_num);
  return dup_cfg_peer;

error:
	rhp_realm_free_peer_cfg(dup_cfg_peer);

	RHP_TRC(0,RHPTRCID_REALM_DUP_CFG_PEERS_ERR,"xxx",cfg_peer,peer_id,peer_addr);
	return NULL;
}

static rhp_cfg_peer* _rhp_realm_dup_peer_by_id(rhp_vpn_realm* rlm,
		rhp_ikev2_id* peer_id,rhp_ip_addr* peer_addr)
{
  rhp_cfg_peer *cfg_peer,*dup_cfg_peer;

  cfg_peer = rlm->get_peer_by_id(rlm,peer_id);
  if( cfg_peer == NULL ){
  	RHP_TRC(0,RHPTRCID_REALM_DUP_PEER_BY_ID_NO_PEER_CFG_FOUND,"xxx",rlm,peer_id,peer_addr);
  	return NULL;
  }

  dup_cfg_peer = _rhp_realm_dup_cfg_peers(cfg_peer,peer_id,peer_addr);
  if( dup_cfg_peer == NULL ){
  	RHP_BUG("");
  	return NULL;
  }

	RHP_TRC(0,RHPTRCID_REALM_DUP_PEER_BY_ID,"xxxx",rlm,peer_id,peer_addr,dup_cfg_peer);
  return dup_cfg_peer;
}

static int _rhp_realm_is_configued_peer(rhp_vpn_realm* rlm,rhp_ikev2_id* peer_id)
{
  rhp_cfg_peer *cfg_peer;

  cfg_peer = rlm->get_peer_by_id(rlm,peer_id);
  if( cfg_peer == NULL ){
  	RHP_BUG("");
  	return 0;
  }

  if( cfg_peer->id.type == RHP_PROTO_IKE_ID_ANY ){
  	RHP_TRC(0,RHPTRCID_REALM_IS_CONFIGUED_PEER_NOT_CONFIGUED,"xxx",rlm,peer_id,cfg_peer);
  	return 0;
  }

	RHP_TRC(0,RHPTRCID_REALM_IS_CONFIGUED_PEER,"xxx",rlm,peer_id,cfg_peer);
  return 1;
}


static int _rhp_realm_enum_route_map_by_peerid(rhp_vpn_realm* rlm,rhp_ikev2_id* peer_id,
		int (*callback)(struct _rhp_vpn_realm* rlm,rhp_ikev2_id* peer_id,rhp_route_map* rtmap,void* ctx),void* ctx)
{
	int err = -EINVAL;
	rhp_route_map* rtmap = rlm->route_maps;
	int cnt = 0;

	RHP_TRC(0,RHPTRCID_REALM_ENUM_ROUTE_MAP_BY_PEERID,"xxYx",rlm,peer_id,callback,ctx);
	rhp_ikev2_id_dump("_rhp_realm_enum_route_map_by_peerid",peer_id);

	while( rtmap ){

		rhp_route_map* rtmap_n = rtmap->next;

		if( !rhp_ikev2_id_cmp_no_alt_id(&(rtmap->gateway_peer_id),peer_id) ){

			err = callback(rlm,peer_id,rtmap,ctx);
			if( err ){
				RHP_TRC(0,RHPTRCID_REALM_ENUM_ROUTE_MAP_BY_PEERID_ERR,"xxYxE",rlm,peer_id,callback,ctx,err);
				return err;
			}

			cnt++;
		}

		rtmap = rtmap_n;
	}

	if( cnt == 0 ){
		RHP_TRC(0,RHPTRCID_REALM_ENUM_ROUTE_MAP_BY_PEERID_NO_ENT,"xxYx",rlm,peer_id,callback,ctx);
		return -ENOENT;
	}

	RHP_TRC(0,RHPTRCID_REALM_ENUM_ROUTE_MAP_BY_PEERID_RTRN,"xxYxd",rlm,peer_id,callback,ctx,cnt);
	return 0;
}

static int _rhp_realm_enum_route_map_by_ikev2_cfg(rhp_vpn_realm* rlm,
		int (*callback)(struct _rhp_vpn_realm* rlm,rhp_route_map* rtmap,void* ctx),void* ctx)
{
	int err = -EINVAL;
	rhp_route_map* rtmap = rlm->route_maps;
	int cnt = 0;

	RHP_TRC(0,RHPTRCID_REALM_ENUM_ROUTE_MAP_BY_IKEV2_CFG,"xYx",rlm,callback,ctx);

	while( rtmap ){

		rhp_route_map* rtmap_n = rtmap->next;

		rhp_rtmap_dump("_rhp_realm_enum_route_map_by_ikev2_cfg",rtmap);
		RHP_TRC(0,RHPTRCID_REALM_ENUM_ROUTE_MAP_BY_IKEV2_CFG_RLM_INFO,"xxds",rlm,rlm->internal_ifc,(rlm->internal_ifc ? rlm->internal_ifc->addrs_type : 0),(rlm->internal_ifc ? rlm->internal_ifc->if_name : NULL));

		if( rtmap->ikev2_cfg ||
				( (rtmap->dest_addr.addr_family == AF_INET || rtmap->dest_addr.addr_family == AF_INET6) &&
					rtmap->tx_interface &&
					rlm->internal_ifc &&
					rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_IKEV2CFG &&
					!strcmp(rlm->internal_ifc->if_name,rtmap->tx_interface) )){

			// For IPv6, rhpvifN always has a LinkLocal address and so route
			// entries via dev are never cleaned up.

			err = callback(rlm,rtmap,ctx);
			if( err ){
				RHP_TRC(0,RHPTRCID_REALM_ENUM_ROUTE_MAP_BY_IKEV2_CFG_ERR,"xYxE",rlm,callback,ctx,err);
				return err;
			}

			cnt++;
		}

		rtmap = rtmap_n;
	}

	if( cnt == 0 ){
		RHP_TRC(0,RHPTRCID_REALM_ENUM_ROUTE_MAP_BY_IKEV2_CFG_NO_ENT,"xYx",rlm,callback,ctx);
		return -ENOENT;
	}

	RHP_TRC(0,RHPTRCID_REALM_ENUM_ROUTE_MAP_BY_IKEV2_CFG_RTRN,"xYxd",rlm,callback,ctx,cnt);
	return 0;
}

static void _rhp_realm_rtmap_free(rhp_route_map* rtmap)
{
	RHP_TRC(0,RHPTRCID_REALM_RTMAP_FREE,"x",rtmap);

	if( rtmap->tx_interface ){
		_rhp_free(rtmap->tx_interface);
	}
	_rhp_free(rtmap);

	RHP_TRC(0,RHPTRCID_REALM_RTMAP_FREE_RTRN,"x",rtmap);
	return;
}

static int _rhp_realm_rtmap_put_ikev2_cfg(rhp_vpn_realm* rlm,rhp_ip_addr* dest_addr,
		rhp_ip_addr* gateway_addr,char* tx_interface)
{
	int err = -EINVAL;
	rhp_route_map *rtmap = NULL,*rtmap_tail = NULL;

	RHP_TRC(0,RHPTRCID_REALM_RTMAP_PUT_IKEV2_CFG,"xxxs",rlm,dest_addr,gateway_addr,tx_interface);
	rhp_ip_addr_dump("_rhp_realm_rtmap_put_ikev2_cfg.dest_addr",dest_addr);
	if( gateway_addr ){
		rhp_ip_addr_dump("_rhp_realm_rtmap_put_ikev2_cfg.gateway_addr",gateway_addr);
	}

	rtmap = (rhp_route_map*)_rhp_malloc(sizeof(rhp_route_map));
	if( rtmap == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memset(rtmap,0,sizeof(rhp_route_map));

	rtmap->tag[0] = '#';
	rtmap->tag[1] = 'R';
	rtmap->tag[2] = 'M';
	rtmap->tag[3] = 'P';

	memcpy(&(rtmap->dest_addr),dest_addr,sizeof(rhp_ip_addr));

	if( gateway_addr ){

		memcpy(&(rtmap->gateway_addr),gateway_addr,sizeof(rhp_ip_addr));

	}else if( tx_interface && tx_interface[0] != '\0' ){

		int tx_if_len = strlen(tx_interface);

		if( tx_if_len >= RHP_IFNAMSIZ ){
			err = -EINVAL;
			RHP_BUG("%d",tx_if_len);
			goto error;
		}

		rtmap->tx_interface = (char*)_rhp_malloc(tx_if_len);
		if( rtmap->tag == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		memcpy(rtmap->tx_interface,tx_interface,tx_if_len);
		rtmap->tx_interface[tx_if_len] = '\0';
	}

	rtmap->ikev2_cfg = 1;


  rtmap_tail = rlm->route_maps;
  while( rtmap_tail ){
  	if( rtmap_tail->next == NULL ){
  		break;
  	}
  	rtmap_tail = rtmap_tail->next;
  }

  if( rtmap_tail == NULL ){
  	rlm->route_maps = rtmap;
  }else{
  	rtmap_tail->next = rtmap;
  }

	RHP_TRC(0,RHPTRCID_REALM_RTMAP_PUT_IKEV2_CFG_RTRN,"xxxx",rlm,dest_addr,gateway_addr,rtmap);
	return 0;

error:
	if( rtmap ){
		_rhp_realm_rtmap_free(rtmap);
	}
	return err;
}

static void _rhp_realm_rtmap_delete(rhp_vpn_realm*rlm,rhp_route_map* rtmap)
{
	rhp_route_map* rtmap_d = rlm->route_maps;
	rhp_route_map* rtmap_d_p = NULL;

	RHP_TRC(0,RHPTRCID_REALM_RTMAP_DELETE,"xx",rlm,rtmap);

	while( rtmap_d ){

		if( rtmap_d == rtmap ){
			break;
		}

		rtmap_d_p = rtmap_d;
		rtmap_d = rtmap_d->next;
	}

	if( rtmap_d == NULL ){
		RHP_BUG("");
	}else{

		if( rtmap_d_p ){
			rtmap_d_p->next = rtmap_d->next;
		}else{
			rlm->route_maps = rtmap_d->next;
		}

		_rhp_realm_rtmap_free(rtmap_d);
	}

	RHP_TRC(0,RHPTRCID_REALM_RTMAP_DELETE_RTRN,"xx",rlm,rtmap);
	return;
}

static void _rhp_realm_set_access_point(rhp_vpn_realm* rlm,rhp_vpn* vpn)
{

	RHP_TRC(0,RHPTRCID_REALM_SET_ACCESS_POINT,"xxxbb",rlm,vpn,RHP_VPN_REF(rlm->access_point_peer_vpn_ref),rlm->nhrp.auth_tkt_enabled,vpn->auth_ticket.conn_type);

	if( rlm->access_point_peer_vpn_ref ){
		rhp_vpn_unhold(rlm->access_point_peer_vpn_ref);
	}

	rlm->access_point_peer_vpn_ref = rhp_vpn_hold_ref(vpn);


	if( rlm->nhrp.auth_tkt_enabled &&
			!vpn->is_v1 &&
			vpn->auth_ticket.conn_type != RHP_AUTH_TKT_CONN_TYPE_HUB2SPOKE ){

		RHP_BUG("%d",vpn->auth_ticket.conn_type);
	}

	return;
}

static int _rhp_realm_null_auth_configured(rhp_vpn_realm* rlm)
{
	if( rlm->null_auth_for_peers ||
			(rlm->my_auth.my_auth_method == RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH) ){
		return 1;
	}
	return 0;
}

static int _rhp_realm_get_internal_if_subnet_addr(rhp_vpn_realm* rlm,
		int addr_family,rhp_ip_addr* subnet_addr_r)
{
	rhp_ip_addr_list *internal_ifc_addrs = NULL, *internal_ifc_addr;

  RHP_TRC(0,RHPTRCID_REALM_GET_INTERNAL_IF_SUBNET_ADDR,"xxLdx",rlm,rlm->internal_ifc,"AF",addr_family,subnet_addr_r);

	if( rlm->internal_ifc == NULL ){
	  RHP_TRC(0,RHPTRCID_REALM_GET_INTERNAL_IF_SUBNET_ADDR_NO_INTERNAL_IF,"x",rlm);
		return -ENOENT;
	}

	if( rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_NONE ){

		internal_ifc_addrs = rlm->internal_ifc->bridge_addrs;

	}else{

		internal_ifc_addrs = rlm->internal_ifc->addrs;
	}


	internal_ifc_addr = internal_ifc_addrs;
	while( internal_ifc_addr ){

		if( !rhp_ip_addr_null(&(internal_ifc_addr->ip_addr)) &&
				(internal_ifc_addr->ip_addr.addr_family == addr_family) &&
				( addr_family == AF_INET ||
				 (addr_family == AF_INET6 && !rhp_ipv6_is_linklocal(internal_ifc_addr->ip_addr.addr.v6))) ){
			break;
		}

		internal_ifc_addr = internal_ifc_addr->next;
	}

	if( internal_ifc_addr ){

		if( addr_family == AF_INET ){

			u32 netmask_v4 = internal_ifc_addr->ip_addr.netmask.v4;

			subnet_addr_r->addr_family = AF_INET;

			if( !netmask_v4 ){
				netmask_v4 = rhp_ipv4_prefixlen_to_netmask(internal_ifc_addr->ip_addr.prefixlen);
			}

			subnet_addr_r->addr.v4 = (internal_ifc_addr->ip_addr.addr.v4 & netmask_v4);
			subnet_addr_r->netmask.v4 = netmask_v4;
			subnet_addr_r->prefixlen = internal_ifc_addr->ip_addr.prefixlen;

			rhp_ip_addr_dump("subnet_addr_r:v4",subnet_addr_r);
		  RHP_TRC(0,RHPTRCID_REALM_GET_INTERNAL_IF_SUBNET_ADDR_V4,"x4d",rlm,netmask_v4,internal_ifc_addr->ip_addr.prefixlen);
			return 0;

		}else if( addr_family == AF_INET6 ){

			int i;
			u8 netmask_v6[16];
			rhp_ipv6_prefixlen_to_netmask(internal_ifc_addr->ip_addr.prefixlen,netmask_v6);

			subnet_addr_r->addr_family = AF_INET6;

			for( i = 0; i < 16; i++ ){
				subnet_addr_r->addr.v6[i] = (internal_ifc_addr->ip_addr.addr.v6[i] & netmask_v6[i]);
			}

			memcpy(subnet_addr_r->netmask.v6,netmask_v6,16);
			subnet_addr_r->prefixlen = internal_ifc_addr->ip_addr.prefixlen;

			rhp_ip_addr_dump("subnet_addr_r:v6",subnet_addr_r);
		  RHP_TRC(0,RHPTRCID_REALM_GET_INTERNAL_IF_SUBNET_ADDR_V6,"x6d",rlm,netmask_v6,internal_ifc_addr->ip_addr.prefixlen);
			return 0;
		}
	}

  RHP_TRC(0,RHPTRCID_REALM_GET_INTERNAL_IF_SUBNET_ADDR_NO_INTERNAL_ADDR,"x",rlm);
	return -ENOENT;
}

rhp_vpn_realm* rhp_realm_alloc()
{
  rhp_vpn_realm* rlm = (rhp_vpn_realm*)_rhp_malloc(sizeof(rhp_vpn_realm));

  if( rlm == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(rlm,0,sizeof(rhp_vpn_realm));

  rlm->tag[0] = '#';
  rlm->tag[1] = 'V';
  rlm->tag[2] = 'R';
  rlm->tag[3] = 'M';

  _rhp_mutex_init("RLM",&(rlm->lock));

  _rhp_atomic_init((&rlm->refcnt));
  _rhp_atomic_init((&rlm->is_active));

  rlm->get_next_my_interface = _rhp_realm_get_next_my_interface;
  rlm->get_next_my_interface_def_route = _rhp_realm_get_next_my_interface_def_route;
  rlm->get_my_interface = _rhp_realm_get_my_interface;
  rlm->get_internal_if = _rhp_realm_get_internal_if;
  rlm->my_interface_cmp_priority = _rhp_realm_my_interface_cmp_priority;
  rlm->get_peer_by_primary_addr = _rhp_realm_get_peer_by_primary_addr;
  rlm->get_peer_by_id = _rhp_realm_get_peer_by_id;
  rlm->dup_peer_by_id = _rhp_realm_dup_peer_by_id;
  rlm->is_configued_peer = _rhp_realm_is_configued_peer;
  rlm->enum_route_map_by_peerid = _rhp_realm_enum_route_map_by_peerid;
  rlm->enum_route_map_by_ikev2_cfg = _rhp_realm_enum_route_map_by_ikev2_cfg;
  rlm->rtmap_put_ikev2_cfg = _rhp_realm_rtmap_put_ikev2_cfg;
  rlm->rtmap_delete = _rhp_realm_rtmap_delete;
  rlm->set_access_point = _rhp_realm_set_access_point;
  rlm->null_auth_configured = _rhp_realm_null_auth_configured;
  rlm->get_internal_if_subnet_addr = _rhp_realm_get_internal_if_subnet_addr;

  rlm->realm_created_time = -1;
  rlm->realm_updated_time = -1;
  rlm->sess_resume_policy_index = -1;

  RHP_TRC(0,RHPTRCID_REALM_ALLOC,"x",rlm);
  return rlm;
}

static void _rhp_realm_check_ifc_socket_close_task(int worker_idx,void *ctx)
{
	rhp_ifc_entry* ifc = (rhp_ifc_entry*)ctx;

  RHP_TRC(0,RHPTRCID_REALM_CHECK_IFC_SOCKET_CLOSE_TASK,"x",ifc);

	RHP_LOCK(&(ifc->lock));

	rhp_realm_close_ifc_socket_if_no_users(ifc);

  RHP_UNLOCK(&(ifc->lock));

  rhp_ifc_unhold(ifc);

  RHP_TRC(0,RHPTRCID_REALM_CHECK_IFC_SOCKET_CLOSE_TASK_RTRN,"x",ifc);
  return;
}

static void _rhp_realm_check_ifc_socket_close(rhp_ifc_entry* ifc)
{
	int err;

  RHP_TRC(0,RHPTRCID_REALM_CHECK_IFC_SOCKET_CLOSE,"x",ifc);

	rhp_ifc_hold(ifc);

	err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_LOW_3,_rhp_realm_check_ifc_socket_close_task,ifc);
	if( err ){
		RHP_BUG("%d",err);
		rhp_ifc_unhold(ifc);
	}

  RHP_TRC(0,RHPTRCID_REALM_CHECK_IFC_SOCKET_CLOSE_RTRN,"x",ifc);
	return;
}

void rhp_realm_free(rhp_vpn_realm* rlm)
{
  RHP_TRC(0,RHPTRCID_REALM_FREE,"xd",rlm,rlm->id);

  if( rlm->access_point_peer_vpn_ref ){
  	rhp_vpn_unhold(rlm->access_point_peer_vpn_ref);
  }

  {
    rhp_cfg_if *cfg_if,*cfg_if2;

    cfg_if = rlm->my_interfaces;
    while( cfg_if ){

      cfg_if2 = cfg_if->next;

      if( cfg_if->ifc ){

      	if( cfg_if->addr_family == AF_INET ){
      		rhp_ifc_cfg_users_dec(cfg_if->ifc,AF_INET);
      	}else if( cfg_if->addr_family == AF_INET6 ){
      		rhp_ifc_cfg_users_dec(cfg_if->ifc,AF_INET6);
      	}else if( cfg_if->addr_family == AF_UNSPEC ){
      		rhp_ifc_cfg_users_dec(cfg_if->ifc,AF_INET);
      		rhp_ifc_cfg_users_dec(cfg_if->ifc,AF_INET6);
      	}else{
      		RHP_BUG("%d",cfg_if->addr_family);
      	}

        _rhp_realm_check_ifc_socket_close(cfg_if->ifc);

        rhp_ifc_unhold(cfg_if->ifc);
        cfg_if->ifc = NULL;
      }

      if( cfg_if->if_name ){
        _rhp_free_zero(cfg_if->if_name,strlen(cfg_if->if_name));
      }
      _rhp_free_zero(cfg_if,sizeof(rhp_cfg_if));

      cfg_if = cfg_if2;
    }
  }

  if( rlm->internal_ifc ){

  	rhp_ip_addr_list *addr_lst, *addr_lst_n;

  	if( rlm->internal_ifc->bridge_name ){
  		_rhp_free(rlm->internal_ifc->bridge_name);
  	}

  	if( rlm->internal_ifc->ifc ){
      rhp_ifc_unhold(rlm->internal_ifc->ifc);
      rlm->internal_ifc->ifc = NULL;
  	}

    if( rlm->internal_ifc->if_name ){
      _rhp_free_zero(rlm->internal_ifc->if_name,strlen(rlm->internal_ifc->if_name));
    }

    addr_lst = rlm->internal_ifc->addrs;
    while( addr_lst ){
    	addr_lst_n = addr_lst->next;
    	_rhp_free(addr_lst);
    	addr_lst = addr_lst_n;
    }

    addr_lst = rlm->internal_ifc->bridge_addrs;
    while( addr_lst ){
    	addr_lst_n = addr_lst->next;
    	_rhp_free(addr_lst);
    	addr_lst = addr_lst_n;
    }

    _rhp_free_zero(rlm->internal_ifc,sizeof(rhp_cfg_internal_if));
  }

  rhp_realm_free_peer_cfg(rlm->peers);

	_rhp_split_dns_domain_free(rlm->split_dns.domains);


  {
  	rhp_route_map *rtmap,*rtmap_n;

  	rtmap = rlm->route_maps;
  	while( rtmap ){

  		rtmap_n = rtmap->next;

  		_rhp_realm_rtmap_free(rtmap);

  		rtmap = rtmap_n;
  	}
  }

	_rhp_internal_route_map_free(rlm->config_server.rt_maps);
	_rhp_internal_route_map_free(rlm->config_server.rt_maps_v6);

  {
  	rhp_internal_address_pool *addr_pool,*addr_pool_n;

  	addr_pool = rlm->config_server.addr_pools;
  	while( addr_pool ){

  		addr_pool_n = addr_pool->next;

  		_rhp_free(addr_pool);

  		addr_pool = addr_pool_n;
  	}

  	addr_pool = rlm->config_server.addr_pools_v6;
  	while( addr_pool ){

  		addr_pool_n = addr_pool->next;

  		_rhp_free(addr_pool);

  		addr_pool = addr_pool_n;
  	}
  }

  {
  	rhp_internal_peer_address *peer_addr,*peer_addr_n;

  	peer_addr = rlm->config_server.peer_addrs;
  	while( peer_addr ){

  		peer_addr_n = peer_addr->next;

  		_rhp_free(peer_addr);

  		peer_addr = peer_addr_n;
  	}

  	peer_addr = rlm->config_server.peer_addrs_v6;
  	while( peer_addr ){

  		peer_addr_n = peer_addr->next;

  		_rhp_free(peer_addr);

  		peer_addr = peer_addr_n;
  	}
  }


	_rhp_split_dns_domain_free(rlm->config_server.domains);


	if( rlm->my_auth.my_cert_issuer_dn_der ){
		_rhp_free(rlm->my_auth.my_cert_issuer_dn_der);
	}

	if( rlm->my_auth.untrust_sub_ca_cert_issuer_dn_der ){
		_rhp_free(rlm->my_auth.untrust_sub_ca_cert_issuer_dn_der);
	}

	if( rlm->nhrp.key ){
		_rhp_free(rlm->nhrp.key);
	}

  _rhp_mutex_destroy(&(rlm->lock));
  _rhp_atomic_destroy((&rlm->refcnt));
  _rhp_atomic_destroy((&rlm->is_active));

  if( rlm->name ){
    _rhp_free_zero(rlm->name,strlen(rlm->name));
  }

  _rhp_free_zero(rlm,sizeof(rhp_vpn_realm));

  RHP_TRC(0,RHPTRCID_REALM_FREE_RTRN,"x",rlm);
}

void rhp_realm_hold(rhp_vpn_realm* rlm)
{
  _rhp_atomic_inc(&(rlm->refcnt));
  RHP_TRC(0,RHPTRCID_REALM_HOLD,"xd",rlm,_rhp_atomic_read(&(rlm->refcnt)));
}

void rhp_realm_unhold(rhp_vpn_realm* rlm)
{
  RHP_TRC(0,RHPTRCID_REALM_UNHOLD,"xd",rlm,_rhp_atomic_read(&(rlm->refcnt)));

  if( _rhp_atomic_dec_and_test(&(rlm->refcnt)) ){

    if( rlm->destructor ){
      rlm->destructor(rlm);
    }

    rhp_realm_free(rlm);
  }
}

static rhp_vpn_realm* _rhp_realm_get_no_lock(unsigned long id)
{
  rhp_vpn_realm* rlm;

  rlm = rhp_realm_list_head;

  while( rlm ){
    if( rlm->id == id ){
      break;
    }
    rlm = rlm->next;
  }

  if( rlm ){
    rhp_realm_hold(rlm);
  }

  if( rlm ){
    RHP_TRC(0,RHPTRCID_REALM_GET_L,"xd",rlm,rlm->id);
  }else{
    RHP_TRC(0,RHPTRCID_REALM_GET_L_ERR,"d",id);
  }
  return rlm;
}

rhp_vpn_realm* rhp_realm_get(unsigned long id)
{
  rhp_vpn_realm* rlm;

  RHP_LOCK(&rhp_cfg_lock);

  rlm = _rhp_realm_get_no_lock(id);

  RHP_UNLOCK(&rhp_cfg_lock);

  if( rlm ){
    RHP_TRC(0,RHPTRCID_REALM_GET,"xd",rlm,rlm->id);
  }else{
    RHP_TRC(0,RHPTRCID_REALM_GET_ERR,"d",id);
  }
  return rlm;
}

int rhp_realm_put(rhp_vpn_realm* rlm)
{
	int err = -EINVAL;
  rhp_vpn_realm *rlm_c = NULL,*rlm_p = NULL;

  RHP_TRC(0,RHPTRCID_REALM_PUT,"xd",rlm,rlm->id);

  RHP_LOCK(&rhp_cfg_lock);

  rlm_c = _rhp_realm_get_no_lock(rlm->id);
  if( rlm_c ){
  	RHP_BUG("rlm->id: %d",rlm->id);
  	err = -EEXIST;
    rhp_realm_unhold(rlm);
  	goto error;
  }

  rlm_c = rhp_realm_list_head;

  while( rlm_c ){
    if( rlm_c->id > rlm->id ){
      break;
    }
    rlm_p = rlm_c;
    rlm_c = rlm_c->next;
  }

  if( rlm_p == NULL ){
    rhp_realm_list_head = rlm;
    rlm->next = rlm_c;
  }else{
    rlm->next = rlm_p->next;
    rlm_p->next = rlm;
  }

  rhp_realm_hold(rlm);
  err = 0;

error:
  RHP_UNLOCK(&rhp_cfg_lock);
  return err;
}


#define RHP_RLM_ENUM_LST_LEN		32
int rhp_realm_enum(unsigned long rlm_id,int (*callback)(rhp_vpn_realm* rlm,void* ctx),void* ctx)
{
  int err = -EINVAL;
  rhp_vpn_realm** rlm_list_head;
	int rlm_list_num = RHP_RLM_ENUM_LST_LEN;
  rhp_vpn_realm *rlm;
  int n = 0,i;


  RHP_TRC(0,RHPTRCID_REALM_ENUM,"uYx",rlm_id,callback,ctx);

  if( callback == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  rlm_list_head = (rhp_vpn_realm**)_rhp_malloc(sizeof(rhp_vpn_realm*)*rlm_list_num);
  if( rlm_list_head == NULL ){
  	RHP_BUG("");
  	return -ENOMEM;
  }
	memset(rlm_list_head,0,sizeof(rhp_vpn_realm*)*rlm_list_num);


  RHP_LOCK(&rhp_cfg_lock);

  rlm = rhp_realm_list_head;

  while( rlm ){

  	if( rlm_id == 0 || rlm->id == rlm_id ){

			if( n >= rlm_list_num ){

				rhp_vpn_realm** tmp;

				rlm_list_num += RHP_RLM_ENUM_LST_LEN;

				tmp = (rhp_vpn_realm**)_rhp_malloc(sizeof(rhp_vpn_realm*)*rlm_list_num);
				if( tmp == NULL ){

					RHP_BUG("");

				  for( i = 0; i < n; i++ ){
				  	rhp_realm_unhold(rlm_list_head[i]);
				  }

					_rhp_free(rlm_list_head);
					RHP_UNLOCK(&rhp_cfg_lock);

					return -ENOMEM;
				}

				memset(tmp,0,sizeof(rhp_vpn_realm*)*rlm_list_num);

				memcpy(tmp,rlm_list_head,sizeof(rhp_vpn_realm*)*n);
				_rhp_free(rlm_list_head);

				rlm_list_head = tmp;
			}

			rlm_list_head[n] = rlm;
			rhp_realm_hold(rlm);

			n++;
  	}

    rlm = rlm->next;
  }

  RHP_UNLOCK(&rhp_cfg_lock);


  if( n == 0 ){
  	_rhp_free(rlm_list_head);
    RHP_TRC(0,RHPTRCID_REALM_ENUM_NO_ENT,"u",rlm_id);
  	return -ENOENT;
  }

  for( i = 0; i < n; i++ ){

  	rlm = rlm_list_head[i];

		err = callback(rlm,ctx);
  	if( err ){

	  	if( err == RHP_STATUS_ENUM_OK ){
	  		err = 0;
	  	}

			break;
		}
  }


  for( i = 0; i < n; i++ ){
  	rhp_realm_unhold(rlm_list_head[i]);
  }

  _rhp_free(rlm_list_head);

  RHP_TRC(0,RHPTRCID_REALM_ENUM_RTRN,"ud",rlm_id,n);
  return 0;
}


void rhp_realm_delete(rhp_vpn_realm* rlm)
{
  rhp_vpn_realm* tmp;
  rhp_vpn_realm* tmp2 = NULL;

  RHP_TRC(0,RHPTRCID_REALM_DELETE,"xd",rlm,rlm->id);

  RHP_LOCK(&rhp_cfg_lock);

  tmp = rhp_realm_list_head;

  while( tmp ){
    if( tmp == rlm ){
      RHP_TRC(0,RHPTRCID_REALM_DELETE_NO_ENT,"xd",rlm,rlm->id);
      break;
    }
    tmp2 = tmp;
    tmp = tmp->next;
  }

  if( tmp == NULL ){
    goto error;
  }

  if( tmp2 ){
    tmp2->next = tmp->next;
  }else{
  	rhp_realm_list_head = tmp->next;
  }

  rlm->next = NULL;
  rhp_realm_unhold(rlm);

error:
  RHP_UNLOCK(&rhp_cfg_lock);
}

rhp_vpn_realm* rhp_realm_delete_by_id(unsigned long rlm_id)
{
  rhp_vpn_realm* rlm = NULL;
  rhp_vpn_realm* tmp2 = NULL;

  RHP_TRC(0,RHPTRCID_REALM_DELETE_BY_ID,"d",rlm_id);

  RHP_LOCK(&rhp_cfg_lock);

  rlm = rhp_realm_list_head;

  while( rlm ){

    if( rlm->id == rlm_id ){
      break;
    }

    tmp2 = rlm;
    rlm = rlm->next;
  }

  if( rlm == NULL ){
    RHP_TRC(0,RHPTRCID_REALM_DELETE_BY_ID_NO_ENT,"d",rlm_id);
    goto error;
  }

  if( tmp2 ){
    tmp2->next = rlm->next;
  }else{
  	rhp_realm_list_head = rlm->next;
  }

  rlm->next = NULL;
  rhp_realm_hold(rlm);

  rhp_realm_unhold(rlm);

error:
  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_REALM_DELETE_BY_ID_RTRN,"dx",rlm_id,rlm);
  return rlm;
}


int rhp_realm_disabled_exists(unsigned long rlm_id)
{
	rhp_vpn_realm_disabled* rlm_disabled;
	int flag = 0;

  RHP_TRC(0,RHPTRCID_REALM_DISABLED_EXISTS,"d",rlm_id);

  RHP_LOCK(&rhp_cfg_lock);

  rlm_disabled = rhp_realm_disabled_list_head;
  while( rlm_disabled ){

  	if( rlm_disabled->id == rlm_id ){
  		flag = 1;
  		break;
  	}

  	rlm_disabled = rlm_disabled->next;
  }

  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_REALM_DISABLED_EXISTS_RTRN,"dd",rlm_id,flag);
  return flag;
}

static void _rhp_realm_disabled_free(rhp_vpn_realm_disabled* rlm_disabled)
{
  RHP_TRC(0,RHPTRCID_REALM_DISABLED_FREE,"xd",rlm_disabled,rlm_disabled->id);

  if( rlm_disabled->name ){
		_rhp_free(rlm_disabled->name);
	}
	if( rlm_disabled->mode_label ){
		_rhp_free(rlm_disabled->mode_label);
	}
	if( rlm_disabled->description ){
		_rhp_free(rlm_disabled->description);
	}
	_rhp_free(rlm_disabled);

	RHP_TRC(0,RHPTRCID_REALM_DISABLED_FREE_RTRN,"x",rlm_disabled);
}

int rhp_realm_disabled_put(unsigned long rlm_id,
		char* name,char* mode_label,char* description,time_t created_time,time_t updated_time)
{
	int err = -EINVAL;
	rhp_vpn_realm_disabled* rlm_disabled = NULL;
	int slen;

  RHP_TRC(0,RHPTRCID_REALM_DISABLED_PUT,"dsss",rlm_id,name,mode_label,description);

	rlm_disabled = (rhp_vpn_realm_disabled*)_rhp_malloc(sizeof(rhp_vpn_realm_disabled));
	if( rlm_disabled == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memset(rlm_disabled,0,sizeof(rhp_vpn_realm_disabled));

	rlm_disabled->id = rlm_id;

	if( name ){

		slen = strlen(name) + 1;

		rlm_disabled->name = (char*)_rhp_malloc(slen);
		if( rlm_disabled->name == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
		memcpy(rlm_disabled->name,name,slen);
	}

	if( mode_label ){

		slen = strlen(mode_label) + 1;

		rlm_disabled->mode_label = (char*)_rhp_malloc(slen);
		if( rlm_disabled->mode_label == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
		memcpy(rlm_disabled->mode_label,mode_label,slen);
	}

	if( description ){

		slen = strlen(description) + 1;

		rlm_disabled->description = (char*)_rhp_malloc(slen);
		if( rlm_disabled->description == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
		memcpy(rlm_disabled->description,description,slen);
	}

	rlm_disabled->created_time = created_time;
	rlm_disabled->updated_time = updated_time;


  RHP_LOCK(&rhp_cfg_lock);

	rlm_disabled->next = rhp_realm_disabled_list_head;
	rhp_realm_disabled_list_head = rlm_disabled;

  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_REALM_DISABLED_PUT_RTRN,"dx",rlm_id,rlm_disabled);
  return 0;

error:
	if(rlm_disabled){
		_rhp_realm_disabled_free(rlm_disabled);
	}

  RHP_TRC(0,RHPTRCID_REALM_DISABLED_PUT_ERR,"dE",rlm_id,err);
	return err;
}

int rhp_realm_disabled_delete(unsigned long rlm_id)
{
	int err = -EINVAL;
	rhp_vpn_realm_disabled *rlm_disabled = NULL, *rlm_disabled_p = NULL;

  RHP_TRC(0,RHPTRCID_REALM_DISABLED_DELETE,"d",rlm_id);

  RHP_LOCK(&rhp_cfg_lock);

  rlm_disabled = rhp_realm_disabled_list_head;
  while( rlm_disabled ){

  	if( rlm_disabled->id == rlm_id ){
  		break;
  	}

  	rlm_disabled_p = rlm_disabled;
  	rlm_disabled = rlm_disabled->next;
  }

  if( rlm_disabled ){

  	if( rlm_disabled_p ){
  		rlm_disabled_p->next = rlm_disabled->next;
  	}else{
  		rhp_realm_disabled_list_head = rlm_disabled->next;
  	}

  	_rhp_realm_disabled_free(rlm_disabled);

  	err = 0;

  }else{

  	err = -ENOENT;
  }

  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_REALM_DISABLED_DELETE_RTRN,"dxE",rlm_id,rlm_disabled,err);
  return err;
}

int rhp_realm_disabled_enum(unsigned long rlm_id,
		int (*callback)(rhp_vpn_realm_disabled* rlm_disabled,void* ctx),void* ctx)
{
	int err = 0;
	rhp_vpn_realm_disabled* rlm_disabled;
	int n = 0;

  RHP_TRC(0,RHPTRCID_REALM_DISABLED_ENUM,"dYx",rlm_id,callback,ctx);

  RHP_LOCK(&rhp_cfg_lock);

  rlm_disabled = rhp_realm_disabled_list_head;
  while( rlm_disabled ){

  	if( !rlm_id || rlm_disabled->id == rlm_id ){

  		n++;

  		err = callback(rlm_disabled,ctx);
  		if( err || rlm_id ){
  			break;
  		}
  	}

  	rlm_disabled = rlm_disabled->next;
  }

  RHP_UNLOCK(&rhp_cfg_lock);

  if( !err && n == 0 ){
  	err = -ENOENT;
  }

  RHP_TRC(0,RHPTRCID_REALM_DISABLED_ENUM_RTRN,"dYxdE",rlm_id,callback,ctx,n,err);
  return err;
}

struct _rhp_search_by_split_dns_ctx{
	rhp_vpn_realm* rlm_r;
	int addr_family;
	char* domain_name;
	int search_any;
};
typedef struct _rhp_search_by_split_dns_ctx	rhp_search_by_split_dns_ctx;

static int _rhp_realm_search_by_split_dns_cb(rhp_vpn_realm* rlm,void* ctx_d)
{
	rhp_search_by_split_dns_ctx* ctx = (rhp_search_by_split_dns_ctx*)ctx_d;
	int v4_flag = 0, v6_flag = 0;

  RHP_TRC_FREQ(0,RHPTRCID_REALM_SEARCH_BY_SPLIT_DNS_CB,"xLdsd",ctx,"AF",ctx->addr_family,ctx->domain_name,ctx->search_any);

	RHP_LOCK(&(rlm->lock));

	v4_flag = !rhp_ip_addr_null(&(rlm->split_dns.internal_server_addr));
	v6_flag = !rhp_ip_addr_null(&(rlm->split_dns.internal_server_addr_v6));

	if( (ctx->addr_family == AF_UNSPEC && (v4_flag || v6_flag)) ||
			(v4_flag && ctx->addr_family == AF_INET) ||
			(v6_flag && ctx->addr_family == AF_INET6) ){

		rhp_split_dns_domain* domain = rlm->split_dns.domains;

		if( ctx->search_any && domain == NULL ){

			RHP_TRC_FREQ(0,RHPTRCID_REALM_SEARCH_BY_SPLIT_DNS_CB_MARK_ANY_DOMAIN,"xsxu",ctx,ctx->domain_name,rlm,rlm->id);

	    rhp_realm_hold(rlm);
	    ctx->rlm_r = rlm;

	    goto found;
		}

		while( domain ){

		  RHP_TRC_FREQ(0,RHPTRCID_REALM_SEARCH_BY_SPLIT_DNS_CB_DOMAIN,"xxusxs",ctx,rlm,rlm->id,ctx->domain_name,domain,domain->name);

			if( !rhp_string_suffix_search((u8*)ctx->domain_name,strlen(ctx->domain_name),domain->name) ){

		    rhp_realm_hold(rlm);
		    ctx->rlm_r = rlm;

		    goto found;
			}

			domain = domain->next;
		}
	}

	RHP_UNLOCK(&(rlm->lock));

  RHP_TRC_FREQ(0,RHPTRCID_REALM_SEARCH_BY_SPLIT_DNS_CB_GO_NEXT,"xsdd",ctx,ctx->domain_name,v4_flag,v6_flag);
 	return 0;

found:
	RHP_UNLOCK(&(rlm->lock));
  RHP_TRC_FREQ(0,RHPTRCID_REALM_SEARCH_BY_SPLIT_DNS_CB_FOUND,"xxdsdd",ctx,ctx->rlm_r,ctx->rlm_r->id,ctx->domain_name,v4_flag,v6_flag);

	return RHP_STATUS_ENUM_OK;
}


//
// CAUTION: Intenally, rhp_cfg_lock AND rlm->lock are acquired!
// Caller MUST NOT hold both of them before call this function.
//
rhp_vpn_realm* rhp_realm_search_by_split_dns(int addr_family,char* domain_name)
{
	rhp_search_by_split_dns_ctx ctx;

	RHP_TRC(0,RHPTRCID_REALM_SEARCH_BY_SPLIT_DNS,"Lds","AF",addr_family,domain_name);

	ctx.domain_name = domain_name;
	ctx.addr_family = addr_family;
	ctx.rlm_r = NULL;

	ctx.search_any = 0;
	rhp_realm_enum(0,_rhp_realm_search_by_split_dns_cb,(void*)&ctx);

  if( ctx.rlm_r ){

    RHP_TRC(0,RHPTRCID_REALM_SEARCH_BY_SPLIT_DNS_FOUND,"xus",ctx.rlm_r,ctx.rlm_r->id,domain_name);

  }else{

  	if( _rhp_atomic_read(&rhp_vpn_fwd_any_dns_queries) ){

  		ctx.search_any = 1;
  		rhp_realm_enum(0,_rhp_realm_search_by_split_dns_cb,(void*)&ctx);
  	}

    if( ctx.rlm_r ){
      RHP_TRC(0,RHPTRCID_REALM_SEARCH_BY_SPLIT_DNS_FOUND_ANY,"xusfd",ctx.rlm_r,ctx.rlm_r->id,domain_name,_rhp_atomic_read(&rhp_vpn_fwd_any_dns_queries),rhp_gcfg_dns_pxy_fwd_any_queries_to_vpn);
    }else{
    	RHP_TRC(0,RHPTRCID_REALM_SEARCH_BY_SPLIT_DNS_NOT_FOUND,"sfd",domain_name,_rhp_atomic_read(&rhp_vpn_fwd_any_dns_queries),rhp_gcfg_dns_pxy_fwd_any_queries_to_vpn);
    }
  }

  return ctx.rlm_r;
}

int rhp_realms_setup_vif_cb(rhp_vpn_realm* rlm,void* ctx)
{
  int err = -EINVAL;

  RHP_TRC(0,RHPTRCID_REALM_SETUP_VIF_CB,"xu",rlm,rlm->id);

	RHP_LOCK(&(rlm->lock));

	err = rhp_ipc_send_create_vif(rlm);
	if( err ){
		RHP_BUG("%d",err);
	}

	RHP_UNLOCK(&(rlm->lock));

  RHP_TRC(0,RHPTRCID_REALM_SETUP_VIF_CB_RTRN,"xE",rlm,err);
  return 0;
}

int rhp_realms_setup_vif()
{
  RHP_TRC(0,RHPTRCID_REALM_SETUP_VIF,"");

	rhp_realm_enum(0,rhp_realms_setup_vif_cb,NULL);

#ifdef RHP_CREATE_DMY_VIF
	RHP_LOCK(&rhp_cfg_lock);

	err = rhp_ipc_send_create_vif_raw(0,RHP_VIRTUAL_DMY_IF_NAME,NULL,rlm->id,1,0,0);
	if( err ){
		RHP_BUG("%d",err);
	}
  RHP_UNLOCK(&rhp_cfg_lock);
#endif // RHP_CREATE_DMY_VIF

  RHP_TRC(0,RHPTRCID_REALM_SETUP_VIF_RTRN,"");
  return 0;
}

int rhp_realms_setup_route(unsigned long rlm_id)
{
  int err = -EINVAL;
  rhp_vpn_realm* rlm;

  RHP_TRC(0,RHPTRCID_REALM_SETUP_ROUTE,"u",rlm_id);

  rlm = rhp_realm_get(rlm_id);
  if( rlm == NULL ){
  	err = -ENOENT;
  	goto error;
  }

	RHP_LOCK(&(rlm->lock));
	{
		rhp_ipc_send_update_all_static_routes(rlm);
	}
	RHP_UNLOCK(&(rlm->lock));

  err = 0;
  rhp_realm_unhold(rlm);

error:
  RHP_TRC(0,RHPTRCID_REALM_SETUP_ROUTE_RTRN,"uxE",rlm_id,rlm,err);
  return err;
}

int rhp_realms_flush_route(unsigned long rlm_id)
{
  int err = -EINVAL;
  rhp_vpn_realm* rlm;

  RHP_TRC(0,RHPTRCID_REALM_SETUP_ROUTE,"u",rlm_id);

  rlm = rhp_realm_get(rlm_id);
  if( rlm == NULL ){
  	err = -ENOENT;
  	goto error;
  }

	RHP_LOCK(&(rlm->lock));
	{
		rhp_ipc_send_delete_all_static_routes(rlm);
	}
	RHP_UNLOCK(&(rlm->lock));

  err = 0;
  rhp_realm_unhold(rlm);

error:
  RHP_TRC(0,RHPTRCID_REALM_SETUP_ROUTE_RTRN,"uxE",rlm_id,rlm,err);
  return err;
}

static void _rhp_realm_delete_and_free_cfg_if(rhp_vpn_realm* rlm,char* if_name,int is_def_route)
{
  rhp_cfg_if* cfg_if;
	rhp_cfg_if* cfg_if_p = NULL;

  RHP_TRC(0,RHPTRCID_REALM_DELETE_CFG_IF,"xsd",rlm,if_name,is_def_route);

	cfg_if = rlm->my_interfaces;
	while( cfg_if ){

		if( !strcmp(cfg_if->if_name,if_name) &&
				cfg_if->is_by_def_route == is_def_route ){
			break;
		}

		cfg_if_p = cfg_if;
		cfg_if = cfg_if->next;
	}

	if( cfg_if == NULL ){
	  RHP_TRC(0,RHPTRCID_REALM_DELETE_CFG_IF_NO_ENT,"xsd",rlm,if_name,is_def_route);
		return;
	}

	if( cfg_if_p ){
		cfg_if_p->next = cfg_if->next;
	}else{
		rlm->my_interfaces = cfg_if->next;
	}

	if( cfg_if->if_name ){
		_rhp_free(cfg_if->if_name);
	}

	if( cfg_if->ifc ){
		rhp_ifc_unhold(cfg_if->ifc);
		cfg_if->ifc = NULL;
	}

	_rhp_free(cfg_if);

  if( is_def_route ){
		RHP_LOG_D(RHP_LOG_SRC_CFG,rlm->id,RHP_LOG_ID_SRC_IF_BY_DEFAULT_FOUTE_DELETED,"s",if_name);
  }

  RHP_TRC(0,RHPTRCID_REALM_DELETE_CFG_IF_RTRN,"xsd",rlm,if_name,is_def_route);
  return;
}

// [FixMe] Ugly....
static int _rhp_realm_is_wlan_name(char* if_name)
{
	if( strlen(if_name) >= 2 &&
			if_name[0] == 'w' && if_name[1] == 'l' ){
		return 1;
	}
	return 0;
}

static rhp_cfg_if* _rhp_realm_alloc_and_put_cfg_if(rhp_vpn_realm* rlm,
		rhp_ifc_entry* ifc,int priority,int addr_family,int is_def_route)
{
  rhp_cfg_if* cfg_if = NULL;
	rhp_cfg_if *cfg_if_p = NULL,*cfg_if_c;

	RHP_TRC(0,RHPTRCID_REALM_ALLOC_CFG_IF,"xuxsLdd",rlm,rlm->id,ifc,ifc->if_name,"AF",addr_family,is_def_route);

	cfg_if = rlm->my_interfaces;
	while( cfg_if ){

		if( !strcmp(cfg_if->if_name,ifc->if_name) ){
			break;
		}

		cfg_if = cfg_if->next;
	}

	if( cfg_if ){

		RHP_TRC(0,RHPTRCID_REALM_ALLOC_CFG_IF_EXITS,"xdxdxLdLd",rlm,rlm->id,ifc,is_def_route,cfg_if,"AF",cfg_if->addr_family,"AF",addr_family);

		if( is_def_route ){

			if( cfg_if->addr_family == AF_INET && addr_family == AF_INET6 ){
				cfg_if->addr_family = AF_UNSPEC;
				rhp_ifc_cfg_users_inc(ifc,AF_INET6);
			}else if( cfg_if->addr_family == AF_INET6 && addr_family == AF_INET ){
				cfg_if->addr_family = AF_UNSPEC;
				rhp_ifc_cfg_users_inc(ifc,AF_INET);
			}
		}

		RHP_TRC(0,RHPTRCID_REALM_ALLOC_CFG_IF_UPDATED,"xxdLd",rlm,cfg_if,cfg_if->priority,"AF",cfg_if->addr_family);

		goto cfg_if_updated;
	}

	cfg_if = (rhp_cfg_if*)_rhp_malloc(sizeof(rhp_cfg_if));
	if( cfg_if == NULL ){
		RHP_BUG("");
		goto error;
	}
	memset(cfg_if,0,sizeof(rhp_cfg_if));

	cfg_if->tag[0] = '#';
	cfg_if->tag[0] = 'C';
	cfg_if->tag[0] = 'F';
	cfg_if->tag[0] = 'I';

	cfg_if->if_name = _rhp_malloc(RHP_IFNAMSIZ + 1);
	if( cfg_if->if_name == NULL ){
		RHP_BUG("");
		_rhp_free(cfg_if);
		goto error;
	}
	memset(cfg_if->if_name,0,RHP_IFNAMSIZ + 1);

	strcpy(cfg_if->if_name,ifc->if_name);

	cfg_if->priority = priority;
	cfg_if->is_by_def_route = is_def_route;
	cfg_if->addr_family = addr_family;

	cfg_if->ifc = ifc;
	rhp_ifc_hold(ifc);

	if( addr_family == AF_INET ){
		rhp_ifc_cfg_users_inc(ifc,AF_INET);
	}else if( addr_family == AF_INET6 ){
		rhp_ifc_cfg_users_inc(ifc,AF_INET6);
	}else if( addr_family == AF_UNSPEC ){
		rhp_ifc_cfg_users_inc(ifc,AF_INET);
		rhp_ifc_cfg_users_inc(ifc,AF_INET6);
	}else{
		RHP_BUG("");
	}

	cfg_if_c = rlm->my_interfaces;
	while( cfg_if_c ){

		if( cfg_if_c->priority > cfg_if->priority ){
			break;
		}else if( cfg_if_c->priority == cfg_if->priority ){

			// [FixMe] Wireless I/F has a lower priority. Ugly...
			if( !_rhp_realm_is_wlan_name(cfg_if->if_name) &&
					_rhp_realm_is_wlan_name(cfg_if_c->if_name) ){
/*
					strstr(cfg_if->if_name,"wlan") == NULL &&
					strstr(cfg_if_c->if_name,"wlan") != NULL ){
*/
				RHP_TRC(0,RHPTRCID_REALM_ALLOC_CFG_IF_WLAN_IF_FOUND,"xdxss",rlm,rlm->id,ifc,cfg_if->if_name,cfg_if_c->if_name);
				break;
			}

			if( strlen(cfg_if_c->if_name) > strlen(cfg_if->if_name) ||
					strcmp(cfg_if_c->if_name,cfg_if->if_name) > 0 ){

				RHP_TRC(0,RHPTRCID_REALM_ALLOC_CFG_IF_NAME_CMP_IF_FOUND,"xdxss",rlm,rlm->id,ifc,cfg_if->if_name,cfg_if_c->if_name);
				break;
			}

		  // Add to tail.
		}

		cfg_if_p = cfg_if_c;
		cfg_if_c = cfg_if_c->next;
	}

	if( cfg_if_p == NULL ){
		cfg_if->next = rlm->my_interfaces;
		rlm->my_interfaces = cfg_if;
	}else{
		cfg_if->next = cfg_if_p->next;
		cfg_if_p->next = cfg_if;
	}

	if( rlm->my_interface_use_def_route ){

		rhp_ifc_addr* ifc_addr = ifc->ifc_addrs;
		while( ifc_addr ){

			rhp_if_entry if_info;

			rhp_ifc_copy_to_if_entry(ifc,&if_info,ifc_addr->addr.addr_family,ifc_addr->addr.addr.raw);
			RHP_LOG_D(RHP_LOG_SRC_CFG,rlm->id,RHP_LOG_ID_SRC_IF_BY_DEFAULT_FOUTE_ADDED,"F",&(if_info));

			ifc_addr = ifc_addr->lst_next;
		}
	}

	RHP_TRC(0,RHPTRCID_REALM_ALLOC_CFG_IF_RTRN,"xxdLd",rlm,cfg_if,cfg_if->priority,"AF",cfg_if->addr_family);

	return cfg_if;

cfg_if_updated:
error:
	return NULL;
}

void rhp_realm_setup_ifc(rhp_vpn_realm* rlm,rhp_ifc_entry* ifc,
			int is_def_route,int def_route_addr_family)
{
  rhp_cfg_if* cfg_if = NULL;

  RHP_TRC(0,RHPTRCID_REALM_SETUP_IFC,"xuxsdLd",rlm,rlm->id,ifc,ifc->if_name,is_def_route,"AF",def_route_addr_family);

  if( rlm->internal_ifc &&
  		!strcmp(rlm->internal_ifc->if_name,ifc->if_name) ){

    RHP_TRC(0,RHPTRCID_REALM_SETUP_IFC_TUN_IFC,"xuxs",rlm,rlm->id,ifc,ifc->if_name);

    if( rlm->internal_ifc->ifc == NULL ){

    	ifc->tuntap_nhrp_service = (u8)rlm->nhrp.service;
    	ifc->tuntap_dmvpn_enabled = (u8)rlm->nhrp.dmvpn_enabled;

      rlm->internal_ifc->ifc = ifc;
      rhp_ifc_hold(ifc);

      rlm->internal_ifc->default_mtu = ifc->mtu;

      RHP_TRC(0,RHPTRCID_REALM_SETUP_IFC_TUN_IFC_SET,"xd",rlm->internal_ifc,rlm->internal_ifc->default_mtu);
    }

  }else if( rlm->my_interfaces_any ||
  					(is_def_route && rlm->my_interface_use_def_route) ){

  	if( rlm->is_not_ready ){

			RHP_TRC(0,RHPTRCID_REALM_SETUP_IFC_MY_IFC_ANY_RLM_NOT_READY,"xuxs",rlm,rlm->id,ifc,ifc->if_name);

  	}else{

  		int addr_family;

  		if( rlm->my_interfaces_any ){
  			addr_family = AF_UNSPEC;
  		}else{
  			addr_family = def_route_addr_family;
  		}

  		if( _rhp_realm_alloc_and_put_cfg_if(rlm,ifc,
  					INT_MAX,addr_family,is_def_route) == NULL ){
  			RHP_TRC(0,RHPTRCID_REALM_SETUP_IFC_MY_IFC_ANY_RLM_FAILED,"xuxs",rlm,rlm->id,ifc,ifc->if_name);
				goto update_if_out;
  		}
  	}

  }else if( rlm->my_interfaces ){

    RHP_TRC(0,RHPTRCID_REALM_SETUP_IFC_MY_IFC,"xuxs",rlm,rlm->id,ifc,ifc->if_name);

    cfg_if = rlm->my_interfaces;
    while( cfg_if ){

      if( !strcmp(cfg_if->if_name,ifc->if_name) ){

        if( cfg_if->ifc == NULL ){

        	cfg_if->ifc = ifc;
          rhp_ifc_hold(ifc);

          if( cfg_if->addr_family == AF_INET ){
          	rhp_ifc_cfg_users_inc(ifc,AF_INET);
          }else if( cfg_if->addr_family == AF_INET6 ){
          	rhp_ifc_cfg_users_inc(ifc,AF_INET6);
          }else if( cfg_if->addr_family == AF_UNSPEC ){
          	rhp_ifc_cfg_users_inc(ifc,AF_INET);
          	rhp_ifc_cfg_users_inc(ifc,AF_INET6);
          }else{
          	RHP_BUG("%d",cfg_if->addr_family);
          }

          RHP_TRC(0,RHPTRCID_REALM_SETUP_IFC_MY_IFC_SET,"xd",cfg_if,cfg_if->priority);
        }

        break;
      }

      cfg_if = cfg_if->next;
    }
  }

update_if_out:

	RHP_TRC(0,RHPTRCID_REALM_SETUP_IFC_RTRN,"xuxs",rlm,rlm->id,ifc,ifc->if_name);
  return;
}

static void _rhp_realm_cleanup_ifc(rhp_vpn_realm* rlm,rhp_ifc_entry* ifc,
		int addr_family,
		int is_def_route,int* cfg_if_deleted_r)
{
  rhp_cfg_if* cfg_if = NULL;

  RHP_TRC(0,RHPTRCID_REALM_CLEANUP_IFC,"xuxsLddx",rlm,rlm->id,ifc,ifc->if_name,"AF",addr_family,is_def_route,cfg_if_deleted_r);

	if( cfg_if_deleted_r ){
		*cfg_if_deleted_r = 0;
	}

  if( rlm->internal_ifc &&
  		!strcmp(rlm->internal_ifc->if_name,ifc->if_name) ){

    RHP_TRC(0,RHPTRCID_REALM_CLEANUP_IFC_TUN_IFC,"xuxs",rlm,rlm->id,ifc,ifc->if_name);

    if( ifc != rlm->internal_ifc->ifc ){
      RHP_BUG(" 0x%x(%d) 0x%x != 0x%x ",rlm,rlm->id,ifc,rlm->internal_ifc->ifc);
    }

    if( rlm->internal_ifc->ifc ){

    	RHP_TRC(0,RHPTRCID_REALM_CLEANUP_IFC_TUN_IFC_DEL,"x",rlm->internal_ifc);

      rhp_ifc_unhold(rlm->internal_ifc->ifc);
      rlm->internal_ifc->ifc = NULL;
    }

  }else{

    RHP_TRC(0,RHPTRCID_REALM_CLEANUP_IFC_MY_IFC,"xuxs",rlm,rlm->id,ifc,ifc->if_name);

    cfg_if = rlm->my_interfaces;
    while( cfg_if ){

      if( !strcmp(cfg_if->if_name,ifc->if_name) &&
      		cfg_if->is_by_def_route == is_def_route &&
      		addr_family != -1 ){

        if( cfg_if->ifc && ifc != cfg_if->ifc ){
          RHP_BUG(" 0x%x(%d) 0x%x != 0x%x ",rlm,rlm->id,ifc,cfg_if->ifc);
        }

        if( cfg_if->ifc ){

          RHP_TRC(0,RHPTRCID_REALM_CLEANUP_IFC_MY_IFC_DEL,"xddLd",cfg_if,cfg_if->priority,rlm->my_interfaces_any,"AF",cfg_if->addr_family);

          if( addr_family == AF_INET ){

            if( cfg_if->addr_family == AF_INET ){

            	rhp_ifc_cfg_users_dec(ifc,AF_INET);

            	cfg_if->addr_family = -1;

            }else if( cfg_if->addr_family == AF_UNSPEC ){

            	rhp_ifc_cfg_users_dec(ifc,AF_INET);

            	cfg_if->addr_family = AF_INET6;
            }

          }else if( addr_family == AF_INET6 ){

            if( cfg_if->addr_family == AF_INET6 ){

            	rhp_ifc_cfg_users_dec(ifc,AF_INET6);

            	cfg_if->addr_family = -1;

            }else if( cfg_if->addr_family == AF_UNSPEC ){

            	rhp_ifc_cfg_users_dec(ifc,AF_INET6);

            	cfg_if->addr_family = AF_INET;
            }

          }else if( addr_family == AF_UNSPEC ){

          	rhp_ifc_cfg_users_dec(ifc,AF_INET);
          	rhp_ifc_cfg_users_dec(ifc,AF_INET6);

          	cfg_if->addr_family = -1;
          }

          _rhp_realm_check_ifc_socket_close(cfg_if->ifc);

          RHP_TRC(0,RHPTRCID_REALM_CLEANUP_IFC_MY_IFC_DEL_2,"xdLd",cfg_if,cfg_if->priority,"AF",cfg_if->addr_family);

          if( cfg_if->addr_family == -1 ){

          	rhp_ifc_unhold(cfg_if->ifc);
          	cfg_if->ifc = NULL;

          	if( cfg_if_deleted_r ){
          		*cfg_if_deleted_r = 1;
          	}
          }
        }

        break;
      }

      cfg_if = cfg_if->next;
    }
  }

  RHP_TRC(0,RHPTRCID_REALM_CLEANUP_IFC_RTRN,"xuxsd",rlm,rlm->id,ifc,ifc->if_name,(cfg_if_deleted_r ? *cfg_if_deleted_r : -1));
  return;
}

static void _rhp_realm_open_ifc_socket_retry_handler(void *ctx)
{
	int err = -EINVAL;
	rhp_ifc_entry* ifc = (rhp_ifc_entry*)ctx;

  RHP_TRC(0,RHPTRCID_REALM_OPEN_IFC_SOCKET_RETRY_HANDLER,"xs",ifc,ifc->if_name);

  RHP_LOCK(&(ifc->lock));

	if( _rhp_atomic_read(&(ifc->is_active)) ){

		err = rhp_realm_open_ifc_socket(ifc,1);
		if( err ){
			RHP_LOG_E(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_OPEN_SOCKET_RETRY_ERR,"sE",ifc->if_name,err);
		}else{
			RHP_LOG_I(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_OPEN_SOCKET_RETRY_OK,"s",ifc->if_name);
		}

	}else{

	  RHP_TRC(0,RHPTRCID_REALM_OPEN_IFC_SOCKET_RETRY_HANDLER_IFC_NOT_ACTIVE,"x",ifc);
	}

  RHP_UNLOCK(&(ifc->lock));

  rhp_ifc_unhold(ifc);

  RHP_TRC(0,RHPTRCID_REALM_OPEN_IFC_SOCKET_RETRY_HANDLER_RTRN,"x",ifc);
}

int rhp_realm_open_ifc_socket(rhp_ifc_entry* ifc,int retried)
{
	int err = -EINVAL;
	int addr_family = -1;

  RHP_TRC(0,RHPTRCID_REALM_OPEN_IFC_SOCKET,"xsdddd",ifc,ifc->if_name,ifc->cfg_users_v4.c,ifc->cfg_users_v6.c,rhp_main_net_epoll_fd,retried);

  if( rhp_ifc_cfg_users(ifc,AF_INET) && rhp_ifc_cfg_users(ifc,AF_INET6) ){
  	addr_family = AF_UNSPEC;
  }else if( rhp_ifc_cfg_users(ifc,AF_INET) ){
  	addr_family = AF_INET;
  }else if( rhp_ifc_cfg_users(ifc,AF_INET6) ){
  	addr_family = AF_INET6;
  }

  if( addr_family != -1 ){

		if( (err = rhp_netsock_check_and_open_all(ifc,addr_family)) ){

			RHP_TRC(0,RHPTRCID_REALM_OPEN_IFC_SOCKET_OPEN_SOCKET_ERR,"xsE",ifc,ifc->if_name,err);

			if( !retried ){

				rhp_ifc_hold(ifc);

				RHP_TRC(0,RHPTRCID_REALM_OPEN_IFC_SOCKET_OPEN_GO_RETRY,"xsd",ifc,ifc->if_name,rhp_gcfg_net_event_convergence_interval);

				if( rhp_timer_oneshot(_rhp_realm_open_ifc_socket_retry_handler,(void*)ifc,
						rhp_gcfg_net_event_convergence_interval) ){
					RHP_BUG("");
					rhp_ifc_unhold(ifc);
				}

				err = -EBUSY;

			}else{
				RHP_BUG(" 0x%x : %s ",ifc,ifc->if_name);
			}

      goto error;
		}
	}

  err = 0;

error:
	RHP_TRC(0,RHPTRCID_REALM_OPEN_IFC_SOCKET_RTRN,"xsdE",ifc,ifc->if_name,retried,err);
	return err;
}

static void _rhp_realm_close_ifc_socket(rhp_ifc_entry* ifc,rhp_if_entry* new_info,rhp_if_entry* old_info)
{
	rhp_ifc_addr* ifc_addr;
	rhp_if_entry* key_info;

  RHP_TRC(0,RHPTRCID_REALM_CLOSE_IFC_SOCKET,"xsddxx",ifc,ifc->if_name,ifc->cfg_users_v4.c,ifc->cfg_users_v6.c,new_info,old_info);
  rhp_if_entry_dump("rhp_realm_close_ifc_socket.new_info",new_info);
  rhp_if_entry_dump("rhp_realm_close_ifc_socket.old_info",old_info);

	if( old_info == NULL || new_info == NULL ){
		RHP_BUG("");
		return;
	}

	if( new_info->addr_family != AF_UNSPEC ){
		key_info = new_info;
	}else if( old_info->addr_family != AF_UNSPEC ){
		key_info = old_info;
	}else{
		goto skip;
	}


	ifc_addr = ifc->get_addr(ifc,key_info->addr_family,key_info->addr.raw);

	if( ifc_addr && ifc_addr->net_sk_ike != -1 ){

		if( (ifc_addr->addr.addr_family == AF_INET &&
				 (new_info->addr.v4 == 0 || new_info->addr.v4 != old_info->addr.v4)) ||
				(ifc_addr->addr.addr_family == AF_INET6 &&
				 (rhp_ipv6_addr_null(new_info->addr.v6) || !rhp_ipv6_is_same_addr(new_info->addr.v6,old_info->addr.v6))) ){

			rhp_netsock_close(ifc,ifc_addr);
		}
	}

skip:
	RHP_TRC(0,RHPTRCID_REALM_CLOSE_IFC_SOCKET_RTRN,"xs",ifc,ifc->if_name);
  return;
}

// Caller must acquire ifc->lock.
void rhp_realm_close_ifc_socket_if_no_users(rhp_ifc_entry* ifc)
{
	long refcnt_v4,refcnt_v6;
	int addr_family = -1;

  RHP_TRC(0,RHPTRCID_REALM_CLOSE_IFC_SOCKET_IF_NO_USERS,"xsdd",ifc,ifc->if_name,ifc->cfg_users_v4.c,ifc->cfg_users_v6.c);

  refcnt_v4 = rhp_ifc_cfg_users(ifc,AF_INET);
  refcnt_v6 = rhp_ifc_cfg_users(ifc,AF_INET6);

  if( refcnt_v4 == 0 && refcnt_v6 == 0 ){
  	addr_family = AF_UNSPEC;
  }else if( refcnt_v4 == 0 ){
  	addr_family = AF_INET;
  }else if( refcnt_v6 == 0 ){
  	addr_family = AF_INET6;
  }else if( refcnt_v4 < 0 || refcnt_v6 < 0 ){
  	RHP_BUG("%d,%d",refcnt_v4,refcnt_v6);
  }

  if( addr_family != -1 ){

  	rhp_netsock_close_all(ifc,addr_family);
	}

	RHP_TRC(0,RHPTRCID_REALM_CLOSE_IFC_SOCKET_IF_NO_USERS_RTRN,"xsdd",ifc,ifc->if_name,refcnt_v4,refcnt_v6);
}


static int _rhp_realm_get_def_ikev1_cand_cb0(rhp_vpn_realm* rlm,void* ctx)
{
	rhp_ikev2_id* peer_id = (rhp_ikev2_id*)ctx;
	rhp_cfg_peer* cfg_peer = NULL;

	RHP_LOCK(&(rlm->lock));

	cfg_peer = rlm->get_peer_by_id(rlm,peer_id);
	if( cfg_peer && (cfg_peer->id.type != RHP_PROTO_IKE_ID_ANY) ){

		peer_id->priv = (unsigned long)rlm;
		rhp_realm_hold(rlm);

		RHP_UNLOCK(&(rlm->lock));

	  RHP_TRC(0,RHPTRCID_REALM_GET_DEF_IKEV1_CAND_CB0,"xxu",peer_id,rlm,rlm->id);

		return RHP_STATUS_ENUM_OK;
	}

	RHP_UNLOCK(&(rlm->lock));

	return 0;
}

static int _rhp_realm_get_def_ikev1_cand_cb1(rhp_vpn_realm* rlm,void* ctx)
{
	rhp_ip_addr* peer_addr = (rhp_ip_addr*)ctx;
	rhp_cfg_peer* cfg_peer = NULL;

	RHP_LOCK(&(rlm->lock));

	cfg_peer = rlm->get_peer_by_primary_addr(rlm,peer_addr);
	if( cfg_peer ){

		peer_addr->priv = (unsigned long)rlm;
		rhp_realm_hold(rlm);

		RHP_UNLOCK(&(rlm->lock));

	  RHP_TRC(0,RHPTRCID_REALM_GET_DEF_IKEV1_CAND_CB1,"xxu",peer_addr,rlm,rlm->id);

		return RHP_STATUS_ENUM_OK;
	}

	RHP_UNLOCK(&(rlm->lock));

	return 0;
}

static int _rhp_realm_get_def_ikev1_cand_cb2(rhp_vpn_realm* rlm,void* ctx)
{
	rhp_ikev2_id* peer_id = (rhp_ikev2_id*)ctx;
	rhp_cfg_peer* cfg_peer = NULL;

	RHP_LOCK(&(rlm->lock));

	cfg_peer = rlm->get_peer_by_id(rlm,peer_id);
	if( (cfg_peer && (cfg_peer->id.type == RHP_PROTO_IKE_ID_ANY)) ||
			rlm->peers == NULL ){

		peer_id->priv = (unsigned long)rlm;
		rhp_realm_hold(rlm);

		RHP_UNLOCK(&(rlm->lock));

	  RHP_TRC(0,RHPTRCID_REALM_GET_DEF_IKEV1_CAND_CB2,"xxu",peer_id,rlm,rlm->id);

		return RHP_STATUS_ENUM_OK;
	}

	RHP_UNLOCK(&(rlm->lock));

	return 0;
}

//
// Mainly, for IKEv1 Main mode.
//
rhp_vpn_realm* rhp_realm_get_def_ikev1(rhp_ikev2_id* peer_id,rhp_ip_addr* peer_addr)
{
  rhp_vpn_realm* rlm = NULL;
  unsigned long priv_val,priv_val2;

  RHP_TRC(0,RHPTRCID_REALM_GET_DEF_IKEV1,"dxxx",rhp_gcfg_ikev1_enabled,peer_id,peer_addr,peer_addr->priv);
  rhp_ikev2_id_dump("peer_id",peer_id);
  rhp_ip_addr_dump("peer_addr",peer_addr);

  if( !rhp_gcfg_ikev1_enabled ){
  	return NULL;
  }

  priv_val = peer_id->priv;
  peer_id->priv = 0;
  priv_val2 = peer_addr->priv;
  peer_addr->priv = 0;

  rhp_realm_enum(0,_rhp_realm_get_def_ikev1_cand_cb0,(void*)peer_id);

  // rlm is already held by _rhp_realm_get_def_ikev1_cand_cb0().
  rlm = (rhp_vpn_realm*)peer_id->priv;

  if( rlm == NULL ){

    rhp_realm_enum(0,_rhp_realm_get_def_ikev1_cand_cb1,(void*)peer_addr);

    // rlm is already held by _rhp_realm_get_def_ikev1_cand_cb1().
    rlm = (rhp_vpn_realm*)peer_addr->priv;
  }

  if( rlm == NULL ){

    rhp_realm_enum(0,_rhp_realm_get_def_ikev1_cand_cb2,(void*)peer_id);

    // rlm is already held by _rhp_realm_get_def_ikev1_cand_cb2().
    rlm = (rhp_vpn_realm*)peer_id->priv;
  }

  peer_id->priv = priv_val;
  peer_addr->priv = priv_val2;

  if( rlm ){
    RHP_TRC(0,RHPTRCID_REALM_GET_DEF_IKEV1_RTRN,"xdx",rlm,rlm->id,peer_id);
  }else{
    RHP_TRC(0,RHPTRCID_REALM_GET_DEF_IKEV1_ERR,"x",peer_id);
  }

	return rlm;
}


struct _rhp_rlm_ntfyifc_cb_ctx {
	int event;
	rhp_ifc_entry* ifc;
	rhp_rtmapc_entry* rtmapc;
};
typedef struct _rhp_rlm_ntfyifc_cb_ctx		rhp_rlm_ntfyifc_cb_ctx;

static int _rhp_realm_ifc_notifier_cb(rhp_vpn_realm* rlm,void* ctx)
{
	int err = -EINVAL;
	int event = ((rhp_rlm_ntfyifc_cb_ctx*)ctx)->event;
	rhp_ifc_entry* ifc = ((rhp_rlm_ntfyifc_cb_ctx*)ctx)->ifc;

	RHP_TRC(0,RHPTRCID_REALM_IFC_NOTIFIER_CB,"xxLdx",rlm,ctx,"IFC_EVT",event,ifc);

  RHP_LOCK(&(rlm->lock));
  RHP_LOCK(&(ifc->lock));

	if( !_rhp_atomic_read(&(ifc->is_active)) ){
		RHP_TRC(0,RHPTRCID_REALM_IFC_NOTIFIER_CB_IF_NOT_ACTIVE,"x",ifc);
		err = 0;
		goto error_l;
	}

  switch( event ){

  case RHP_IFC_EVT_UPDATE_IF:
  {
    rhp_realm_setup_ifc(rlm,ifc,0,-1);
  }
  break;

  case RHP_IFC_EVT_DELETE_IF:
  {
    _rhp_realm_cleanup_ifc(rlm,ifc,-1,0,NULL);
  }
  break;

  case RHP_IFC_EVT_UPDATE_ADDR:
  case RHP_IFC_EVT_DELETE_ADDR:
  case RHP_IFC_EVT_DESTROY:
    break;

  default:
    RHP_BUG("%d",event);
    break;
  }

error_l:
  RHP_UNLOCK(&(ifc->lock));
  RHP_UNLOCK(&(rlm->lock));

	RHP_TRC(0,RHPTRCID_REALM_IFC_NOTIFIER_CB_RTRN,"xx",rlm,ctx);
  return 0;
}

static void _rhp_realm_ifc_notifier(int event,rhp_ifc_entry* ifc,
		rhp_if_entry* new_info,rhp_if_entry* old_info,void* ctx)
{
	int err = -EINVAL;

  RHP_TRC(0,RHPTRCID_CFG_IFC_NOTIFIER,"Ldsxxxx","IFC_EVT",event,ifc->if_name,ifc,ctx,new_info,old_info);
  rhp_if_entry_dump("new_info",new_info);
  rhp_if_entry_dump("old_info",old_info);

	if( !_rhp_atomic_read(&(ifc->is_active)) ){
	  RHP_TRC(0,RHPTRCID_CFG_IFC_NOTIFIER_IFC_NOT_ACTIVE,"Ldsxxxx","IFC_EVT",event,ifc->if_name,ifc,ctx,new_info,old_info);
		return;
	}

	RHP_LOG_D(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_IF_CACHE_STATUS,"sLFF",ifc->if_name,"IFC_EVT",event,old_info,new_info);

  switch( event ){

  case RHP_IFC_EVT_UPDATE_IF:
  case RHP_IFC_EVT_DELETE_IF:
  {
  	rhp_rlm_ntfyifc_cb_ctx enum_ctx;

    enum_ctx.ifc = ifc;
    enum_ctx.event = event;

    err = rhp_realm_enum(0,_rhp_realm_ifc_notifier_cb,&enum_ctx);
    if( err && err != -ENOENT && err != RHP_STATUS_ENUM_OK ){
    	RHP_BUG("%d",err);
    }
  }
  	break;

  case RHP_IFC_EVT_UPDATE_ADDR:

  	RHP_TRC(0,RHPTRCID_CFG_IFC_NOTIFIER_UPDATE_ADDR,"xs",ifc,ifc->if_name);
  	RHP_LOG_I(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_IF_CACHE_ADDR_STATUS_CHANED,"sLFF",ifc->if_name,"IFC_EVT",event,old_info,new_info);

    RHP_LOCK(&(ifc->lock));

    rhp_realm_open_ifc_socket(ifc,0);

    RHP_UNLOCK(&(ifc->lock));

    break;

  case RHP_IFC_EVT_DELETE_ADDR:

  	RHP_TRC(0,RHPTRCID_CFG_IFC_NOTIFIER_UPDATE_DEL,"xs",ifc,ifc->if_name);
  	RHP_LOG_I(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_IF_CACHE_ADDR_STATUS_CHANED,"sLFF",ifc->if_name,"IFC_EVT",event,old_info,new_info);

    RHP_LOCK(&(ifc->lock));

    _rhp_realm_close_ifc_socket(ifc,new_info,old_info);

    RHP_UNLOCK(&(ifc->lock));

    break;

  case RHP_IFC_EVT_DESTROY:
    break;

  default:
    RHP_BUG("%d",event);
    break;
  }

  RHP_TRC(0,RHPTRCID_CFG_IFC_NOTIFIER_RTRN,"ux",event,ifc);
  return;
}

static int _rhp_realm_rtmapc_notifier_cb(rhp_vpn_realm* rlm,void* ctx)
{
	int err = -EINVAL;
	int event = ((rhp_rlm_ntfyifc_cb_ctx*)ctx)->event;
	rhp_rtmapc_entry* rtmapc = ((rhp_rlm_ntfyifc_cb_ctx*)ctx)->rtmapc;
	rhp_ifc_entry* ifc = NULL;
	int addr_family = -1;
	rhp_rt_map_entry info;

	RHP_TRC(0,RHPTRCID_REALM_RTMAPC_NOTIFIER_CB,"xxLdx",rlm,ctx,"RTMAP_EVT",event,rtmapc);

  RHP_LOCK(&(rlm->lock));

	if( !_rhp_atomic_read(&(rtmapc->is_active)) ){
		RHP_TRC(0,RHPTRCID_REALM_RTMAPC_NOTIFIER_CB_IF_NOT_ACTIVE,"x",rtmapc);
		err = 0;
		goto error_l;
	}

  RHP_LOCK(&(rtmapc->lock));

	if( (rtmapc->info.type == RHP_RTMAP_TYPE_DEFAULT ||
			 rtmapc->info.type == RHP_RTMAP_TYPE_DYNAMIC_DEFAULT) ){

		if( rlm->my_interface_use_def_route ){

			ifc = rhp_ifc_get(rtmapc->info.oif_name);
			if( ifc == NULL ){
				RHP_BUG("%s",rtmapc->info.oif_name);
				RHP_UNLOCK(&(rtmapc->lock));
				goto error_l;
			}
		}

		if( rlm->internal_ifc &&
				rlm->internal_ifc->bridge_name &&
				!strcmp(rlm->internal_ifc->bridge_name,rtmapc->info.oif_name) ){

			if( !rhp_ip_addr_null(&(rtmapc->info.gateway_addr)) ){

				if( event == RHP_RTMAPC_EVT_UPDATED ){

					RHP_TRC(0,RHPTRCID_REALM_RTMAPC_NOTIFIER_CB_BRIDGE_SYS_DEF_GW_UPDATE,"xxxLd",rlm,ctx,rtmapc,"AF",rtmapc->info.addr_family);
					rhp_ip_addr_dump("BRIDGE_SYS_DEF_GW_UPDATE_V4_B4",&(rlm->internal_ifc->sys_def_gw_addr));
					rhp_ip_addr_dump("BRIDGE_SYS_DEF_GW_UPDATE_V6_B4",&(rlm->internal_ifc->sys_def_gw_addr_v6));

					if( rtmapc->info.addr_family == AF_INET ){
						memcpy(&(rlm->internal_ifc->sys_def_gw_addr),&(rtmapc->info.gateway_addr),sizeof(rhp_ip_addr));
					}else if( rtmapc->info.addr_family == AF_INET6 ){
						memcpy(&(rlm->internal_ifc->sys_def_gw_addr_v6),&(rtmapc->info.gateway_addr),sizeof(rhp_ip_addr));
					}

					rhp_ip_addr_dump("BRIDGE_SYS_DEF_GW_UPDATE_V4",&(rlm->internal_ifc->sys_def_gw_addr));
					rhp_ip_addr_dump("BRIDGE_SYS_DEF_GW_UPDATE_V6",&(rlm->internal_ifc->sys_def_gw_addr_v6));

				}else if( event == RHP_RTMAPC_EVT_DELETED ){

					RHP_TRC(0,RHPTRCID_REALM_RTMAPC_NOTIFIER_CB_BRIDGE_SYS_DEF_GW_DELETE,"xxxLd",rlm,ctx,rtmapc,"AF",rtmapc->info.addr_family);
					rhp_ip_addr_dump("BRIDGE_SYS_DEF_GW_DELETE_V4_B4",&(rlm->internal_ifc->sys_def_gw_addr));
					rhp_ip_addr_dump("BRIDGE_SYS_DEF_GW_DELETE_V6_B4",&(rlm->internal_ifc->sys_def_gw_addr_v6));

					if( rtmapc->info.addr_family == AF_INET ){
						memset(&(rlm->internal_ifc->sys_def_gw_addr),0,sizeof(rhp_ip_addr));
					}else if( rtmapc->info.addr_family == AF_INET6 ){
						memset(&(rlm->internal_ifc->sys_def_gw_addr_v6),0,sizeof(rhp_ip_addr));
					}
				}
			}
		}
	}

	addr_family = rtmapc->info.addr_family;

	memcpy(&info,&(rtmapc->info),sizeof(rhp_rt_map_entry));

	RHP_UNLOCK(&(rtmapc->lock));


  switch( event ){

  case RHP_RTMAPC_EVT_UPDATED:
  {
  	if( rlm->my_interface_use_def_route && ifc ){

  		RHP_LOCK(&(ifc->lock));

  		ifc->update_def_route(ifc,&info);

      rhp_realm_setup_ifc(rlm,ifc,1,addr_family);

      rhp_realm_open_ifc_socket(ifc,0);

  	  RHP_UNLOCK(&(ifc->lock));
  	}
  }
  break;

  case RHP_RTMAPC_EVT_DELETED:
  {
  	if( rlm->my_interface_use_def_route && ifc ){

  		int if_cfg_deleted = 0;

  		RHP_LOCK(&(ifc->lock));

  		_rhp_realm_cleanup_ifc(rlm,ifc,addr_family,1,&if_cfg_deleted);

  		ifc->clear_def_route(ifc,&info);

  	  RHP_UNLOCK(&(ifc->lock));

  	  if( if_cfg_deleted ){

  	  	_rhp_realm_delete_and_free_cfg_if(rlm,info.oif_name,1);
  	  }
  	}
  }
  break;

  case RHP_IFC_EVT_DESTROY:
    break;

  default:
    RHP_BUG("%d",event);
    break;
  }

error_l:
  RHP_UNLOCK(&(rlm->lock));

  if( ifc ){
	  rhp_ifc_unhold(ifc);
  }

	RHP_TRC(0,RHPTRCID_REALM_RTMAPC_NOTIFIER_CB_RTRN,"xxx",rlm,ctx,rtmapc);
  return 0;
}

static void _rhp_realm_rtmapc_notifier(int event,rhp_rtmapc_entry* rtmapc,rhp_rt_map_entry* old,void* ctx)
{
	int err = -EINVAL;

  RHP_TRC(0,RHPTRCID_CFG_RTMAPCC_NOTIFIER,"Ldxxx","RTMAP_EVT",event,rtmapc,old,ctx);
  rtmapc->dump("_rhp_realm_rtmapc_notifier:new",rtmapc);
  rhp_rtmap_entry_dump("_rhp_realm_rtmapc_notifier:old",old);

  if( old ){
  	RHP_LOG_D(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_RTMAP_CACHE_STATUS,"LLAAsAAs","RTMAP_EVT",event,"RTMAP_TYPE",rtmapc->info.type,&(rtmapc->info.dest_network),&(rtmapc->info.gateway_addr),rtmapc->info.oif_name,&(old->dest_network),&(old->gateway_addr),old->oif_name);
  }else{
  	RHP_LOG_D(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_RTMAP_CACHE_STATUS,"LLAAsAAs","RTMAP_EVT",event,"RTMAP_TYPE",rtmapc->info.type,&(rtmapc->info.dest_network),&(rtmapc->info.gateway_addr),rtmapc->info.oif_name,NULL,NULL,"");
  }

  switch( event ){

  case RHP_RTMAPC_EVT_UPDATED:
  case RHP_RTMAPC_EVT_DELETED:
  {
  	rhp_rlm_ntfyifc_cb_ctx enum_ctx;

    enum_ctx.rtmapc = rtmapc;
    enum_ctx.event = event;

    err = rhp_realm_enum(0,_rhp_realm_rtmapc_notifier_cb,&enum_ctx);
    if( err && err != -ENOENT && err != RHP_STATUS_ENUM_OK ){
    	RHP_BUG("%d",err);
    }
  }
  	break;

  case RHP_RTMAPC_EVT_DESTROY:
    break;

  default:
    RHP_BUG("%d",event);
    break;
  }

  RHP_TRC(0,RHPTRCID_CFG_RTMAPCC_NOTIFIER_RTRN,"ux",event,rtmapc);
  return;
}

void rhp_realm_set_notifiers()
{
  rhp_ifc_notifiers[RHP_IFC_NOTIFIER_CFG].callback = _rhp_realm_ifc_notifier;
  rhp_ifc_notifiers[RHP_IFC_NOTIFIER_CFG].ctx = NULL;
  RHP_LINE("rhp_cfg_set_notifiers() : 0x%x,0x%x",_rhp_realm_ifc_notifier,NULL);

  rhp_rtmapc_notifiers[RHP_RTMAPC_NOTIFIER_CFG].callback = _rhp_realm_rtmapc_notifier;
  rhp_rtmapc_notifiers[RHP_RTMAPC_NOTIFIER_CFG].ctx = NULL;
  RHP_LINE("rhp_cfg_set_notifiers() (2) : 0x%x,0x%x",_rhp_realm_rtmapc_notifier,NULL);
}


