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
#include <asm/types.h>
#include <linux/types.h>
#include <asm/byteorder.h>
#include <unistd.h>
#include <sys/capability.h>
#include <sys/socket.h>
#include <time.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>

#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_config.h"
#include "rhp_packet.h"
#include "rhp_tuntap.h"
#include "rhp_wthreads.h"
#include "rhp_crypto.h"
#include "rhp_vpn.h"
#include "rhp_forward.h"
#include "rhp_dns_pxy.h"
#include "rhp_ipv6.h"
#include "rhp_pcap.h"


//#define RHP_TUNTAP_EPOLL_EVT_MASK		(EPOLLIN | EPOLLERR)
#define RHP_TUNTAP_EPOLL_EVT_MASK		(EPOLLIN)

static u32 _rhp_tuntap_disp_hash_rnd = 0;


static void _rhp_tuntap_pcap_write(rhp_packet* pkt)
{
	rhp_pcap_write_pkt(pkt);

	return;
}

static u32 _rhp_tuntap_read_disp_hash(void *key_seed,int* err)
{
  rhp_packet *pkt = (rhp_packet*)key_seed;

  if( pkt->type == RHP_PKT_PLAIN_ETHER_TAP ){

    rhp_proto_ether* ethh = pkt->l2.eth;

    if( ethh == NULL ){
    	RHP_BUG("%d",pkt->type);
    	goto error;
    }

    //
  	// Packets with the same Dst MAC should be dispatched to the same worker thread.
    // These packets tend to be dispatched to the same Child SA.
    //

		*err = 0;
  	return  _rhp_hash_bytes(ethh->dst_addr,6,_rhp_tuntap_disp_hash_rnd);

  }else if( pkt->type == RHP_PKT_PLAIN_IPV4_TUNNEL ){

  	RHP_BUG("%d",pkt->type);

  }else{

  	RHP_BUG("%d",pkt->type);
  }

error:
	*err = -EINVAL;
  return 0;
}

// ifc->lock must be acquired.
static int _rhp_tuntap_open(rhp_ifc_entry* v_ifc,
			unsigned long vpn_realm_id,int type/*RHP_VIF_TYPE_XXX*/,int addrs_type)
{
  int err = -EINVAL;
  int tunfd = -1;
  struct ifreq req;
  struct epoll_event ep_evt;

	RHP_TRC(0,RHPTRCID_TUNTAP_OPEN,"xuLdLd",v_ifc,vpn_realm_id,"VIF_TYPE",type,"VIF_ADDR",addrs_type);
	v_ifc->dump_no_lock("rhp_tuntap_open:v_ifc",v_ifc);

  tunfd = open("/dev/net/tun",(O_RDWR | O_NONBLOCK));

  if( tunfd < 0 ){
    err = -errno;
    RHP_BUG("%d",err);
    goto error;
  }

  memset(&req,0,sizeof(req));

  strcpy(req.ifr_name,v_ifc->if_name);

  req.ifr_flags |= IFF_TAP;

	RHP_TRC(0,RHPTRCID_TUNTAP_OPEN_IOCTL,"xp",v_ifc,sizeof(req),&req);

  if( ioctl(tunfd,TUNSETIFF,(void*)&req) < 0 ){
    err = -errno;
    RHP_BUG("%d",err);
    goto error;
  }

  RHP_TUNTAP_EPOLL_IFC(&(v_ifc->tuntap_fd_epoll_ctx)) = (unsigned long)NULL;

  {
  	v_ifc->tuntap_fd_epoll_ctx.event_type = RHP_MAIN_EPOLL_TUNDEV;

    RHP_TUNTAP_EPOLL_IFC(&(v_ifc->tuntap_fd_epoll_ctx)) =  (unsigned long)v_ifc; // (**)
    rhp_ifc_hold(v_ifc); // (**)

    memset(&ep_evt,0,sizeof(struct epoll_event));
    ep_evt.events = RHP_TUNTAP_EPOLL_EVT_MASK;
    ep_evt.data.ptr = (void*)&(v_ifc->tuntap_fd_epoll_ctx);

    if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_ADD,tunfd,&ep_evt) < 0 ){
      err = -errno;
      RHP_BUG("%d",err);
      goto error;
    }
  }

  v_ifc->tuntap_fd = tunfd;
  v_ifc->tuntap_type = type;
  v_ifc->tuntap_vpn_realm_id = vpn_realm_id;
  v_ifc->tuntap_addrs_type = addrs_type;

	RHP_TRC(0,RHPTRCID_TUNTAP_OPEN_RTRN,"x",v_ifc);
	v_ifc->dump_no_lock("rhp_tuntap_open:v_ifc",v_ifc);

	return 0;

error:

	if( tunfd >= 0 ){
    close(tunfd);
	}

	RHP_TRC(0,RHPTRCID_TUNTAP_OPEN_ERR,"xE",v_ifc,err);
	return err;
}

// ifc->lock must be acquired.
void rhp_tuntap_close(rhp_ifc_entry* v_ifc)
{
  struct epoll_event ep_evt; // See man 2 epoll_ctl ---BUG REPORT---

	RHP_TRC(0,RHPTRCID_TUNTAP_CLOSE,"x",v_ifc);
	v_ifc->dump_no_lock("rhp_tuntap_close:v_ifc",v_ifc);

  if( v_ifc->tuntap_fd == -1 ){
    RHP_BUG("");
    goto error;
  }

  {
    memset(&ep_evt,0,sizeof(struct epoll_event));

    if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_DEL,v_ifc->tuntap_fd,&ep_evt) < 0 ){
      RHP_BUG("%d",-errno);
    }

    close(v_ifc->tuntap_fd);

    RHP_TUNTAP_EPOLL_IFC(&(v_ifc->tuntap_fd_epoll_ctx)) =  (unsigned long)NULL;
    rhp_ifc_unhold(v_ifc); // ifc->tuntap_fd_epoll_ctx.params[0]

    v_ifc->tuntap_fd = -1;
  }

error:
	RHP_TRC(0,RHPTRCID_TUNTAP_CLOSE_RTRN,"x",v_ifc);
	return;
}


struct _rhp_tuntap_ntfyifc_cb_ctx {
	int event;
	rhp_ifc_entry* ifc;
	rhp_if_entry* new_info;
	rhp_if_entry* old_info;
};
typedef struct _rhp_tuntap_ntfyifc_cb_ctx rhp_tuntap_ntfyifc_cb_ctx;

static int _rhp_tuntap_bridge_ifc_notifier_cb(rhp_vpn_realm* rlm,void* ctx)
{
	int err = -EINVAL;
	int event = ((rhp_tuntap_ntfyifc_cb_ctx*)ctx)->event;
	rhp_ifc_entry* br_ifc = ((rhp_tuntap_ntfyifc_cb_ctx*)ctx)->ifc;
	rhp_if_entry* new_info = ((rhp_tuntap_ntfyifc_cb_ctx*)ctx)->new_info;
	rhp_if_entry* old_info = ((rhp_tuntap_ntfyifc_cb_ctx*)ctx)->old_info;

	RHP_TRC(0,RHPTRCID_TUNTAP_BRIDGE_IFC_NOTIFIER_CB,"xxLdxxx",rlm,ctx,"IFC_EVT",event,br_ifc,new_info,old_info);
	rhp_if_entry_dump("new_info",new_info);
	rhp_if_entry_dump("old_info",old_info);

	RHP_LOCK(&(rlm->lock));
	RHP_LOCK(&(br_ifc->lock));

	if( !_rhp_atomic_read(&(br_ifc->is_active)) ){
		RHP_TRC(0,RHPTRCID_TUNTAP_BRIDGE_IFC_NOTIFIER_CB_IF_NOT_ACTIVE,"x",br_ifc);
		err = 0;
		goto error_l;
	}

	if( rlm->internal_ifc &&
			rlm->internal_ifc->bridge_name &&
			!strcmp(rlm->internal_ifc->bridge_name,br_ifc->if_name) ){

		rhp_ip_addr_list *addr_lst,*addr_lst_p = NULL;

		RHP_TRC(0,RHPTRCID_TUNTAP_IFC_NOTIFIER_BR_IFC,"xdxxs",rlm,rlm->id,rlm->internal_ifc,br_ifc,rlm->internal_ifc->bridge_name);

		addr_lst = rlm->internal_ifc->bridge_addrs;
		while( addr_lst ){

			if( addr_lst->ip_addr.addr_family == old_info->addr_family &&
					!memcmp(addr_lst->ip_addr.addr.raw,old_info->addr.raw,16)){
				break;
			}

			addr_lst_p = addr_lst;
			addr_lst = addr_lst->next;
		}

		if( event == RHP_IFC_EVT_UPDATE_ADDR ){

			if( addr_lst == NULL ){

				addr_lst = (rhp_ip_addr_list*)_rhp_malloc(sizeof(rhp_ip_addr_list));
				if( addr_lst == NULL ){
					RHP_BUG("");
					err = -ENOMEM;
					goto error_l;
				}

				memset(addr_lst,0,sizeof(rhp_ip_addr_list));

				addr_lst->next = rlm->internal_ifc->bridge_addrs;
				rlm->internal_ifc->bridge_addrs = addr_lst;
			}

			rhp_ip_addr_set(&(addr_lst->ip_addr),new_info->addr_family,
					new_info->addr.raw,NULL,new_info->prefixlen,0,0);

			RHP_TRC(0,RHPTRCID_TUNTAP_IFC_NOTIFIER_UPDATE_BR_IFC_ADDR,"xx",br_ifc,addr_lst);
			rhp_ip_addr_dump("_rhp_tuntap_bridge_ifc_notifier_cb_upd",&(addr_lst->ip_addr));

		}else if( event == RHP_IFC_EVT_DELETE_ADDR ){

			RHP_TRC(0,RHPTRCID_TUNTAP_IFC_NOTIFIER_DELETE_BR_IFC_ADDR,"xxx",br_ifc,addr_lst,addr_lst_p);

			if( addr_lst ){

				rhp_ip_addr_dump("_rhp_tuntap_bridge_ifc_notifier_cb_del",&(addr_lst->ip_addr));

				if( addr_lst_p ){
					addr_lst_p->next = addr_lst->next;
				}else{
					rlm->internal_ifc->bridge_addrs = addr_lst->next;
				}

				_rhp_free(addr_lst);
				addr_lst = NULL;
			}

		}else{

			RHP_TRC(0,RHPTRCID_TUNTAP_BRIDGE_IFC_NOTIFIER_CB_NOP_BR_IFC_ADDR,"x",br_ifc);
		}
	}

error_l:
	RHP_UNLOCK(&(br_ifc->lock));
	RHP_UNLOCK(&(rlm->lock));

	RHP_TRC(0,RHPTRCID_TUNTAP_BRIDGE_IFC_NOTIFIER_CB_RTRN,"xx",rlm,ctx);
	return 0;
}

static void _rhp_tuntap_bridge_ifc_notifier(int event,rhp_ifc_entry* ifc,rhp_if_entry* new_info,rhp_if_entry* old_info)
{
  int err = -EINVAL;
  rhp_tuntap_ntfyifc_cb_ctx enum_ctx;

  RHP_TRC(0,RHPTRCID_TUNTAP_BRIDGE_IFC_NOTIFIER,"Ldsxxx","IFC_EVT",event,ifc->if_name,ifc,new_info,old_info);
  rhp_if_entry_dump("_rhp_tuntap_bridge_ifc_notifier.old",old_info);
  rhp_if_entry_dump("_rhp_tuntap_bridge_ifc_notifier.new",new_info);

  enum_ctx.ifc = ifc;
  enum_ctx.event = event;
  enum_ctx.new_info = new_info;
  enum_ctx.old_info = old_info;

  err = rhp_realm_enum(0,_rhp_tuntap_bridge_ifc_notifier_cb,&enum_ctx);
  if( err && err != -ENOENT && err != RHP_STATUS_ENUM_OK ){
  	RHP_BUG("%d",err);
  }

  RHP_TRC(0,RHPTRCID_TUNTAP_BRIDGE_IFC_NOTIFIER_RTRN,"LdxE","IFC_EVT",event,ifc,err);
  return;
}

static int _rhp_tuntap_vpn_route_updated_cb(rhp_vpn* vpn,void* ctx)
{
	rhp_ifc_entry* v_ifc = (rhp_ifc_entry*)ctx;

	RHP_TRC(0,RHPTRCID_TUNTAP_VPN_ROUTE_UPDATED_CB,"xxds",vpn,v_ifc,vpn->internal_net_info.exec_ipv6_autoconf,v_ifc->if_name);

  RHP_LOCK(&(vpn->lock));

  if( vpn->internal_net_info.exec_ipv6_autoconf ){

  	rhp_vpn_internal_route_update_impl(vpn,1);
  }

  RHP_UNLOCK(&(vpn->lock));

	RHP_TRC(0,RHPTRCID_TUNTAP_VPN_ROUTE_UPDATED_CB_RTRN,"xxd",vpn,v_ifc,vpn->internal_net_info.exec_ipv6_autoconf);
  return 0;
}

static int _rhp_tuntap_ifc_notifier_cb(rhp_vpn_realm* rlm,void* ctx)
{
	int err = -EINVAL;
	int event = ((rhp_tuntap_ntfyifc_cb_ctx*)ctx)->event;
	rhp_ifc_entry* v_ifc = ((rhp_tuntap_ntfyifc_cb_ctx*)ctx)->ifc;
	rhp_if_entry* new_info = ((rhp_tuntap_ntfyifc_cb_ctx*)ctx)->new_info;
	rhp_if_entry* old_info = ((rhp_tuntap_ntfyifc_cb_ctx*)ctx)->old_info;
  unsigned long rlm_id = 0;
  int route_update = 0;
  int vpn_route_updated = 0;

	RHP_TRC(0,RHPTRCID_TUNTAP_IFC_NOTIFIER_CB,"xxLdx",rlm,ctx,"IFC_EVT",event,v_ifc);
	rhp_if_entry_dump("new_info",new_info);
	rhp_if_entry_dump("old_info",old_info);

	RHP_LOCK(&(rlm->lock));
	RHP_LOCK(&(v_ifc->lock));

	if( !_rhp_atomic_read(&(v_ifc->is_active)) ){
		RHP_TRC(0,RHPTRCID_TUNTAP_IFC_NOTIFIER_TUN_IF_NOT_ACTIVE,"x",v_ifc);
		err = 0;
		goto error_l;
	}

	rlm_id = rlm->id;

  if( !strcmp(v_ifc->if_name,RHP_VIRTUAL_DMY_IF_NAME) ){
		v_ifc->is_dmy_tuntap = 1;
  }


	if( v_ifc->is_dmy_tuntap ||
			(rlm->internal_ifc && !strcmp(rlm->internal_ifc->if_name,v_ifc->if_name)) ){

		RHP_TRC(0,RHPTRCID_TUNTAP_IFC_NOTIFIER_TUN_IFC,"xdxxsd",rlm,rlm->id,rlm->internal_ifc,v_ifc,v_ifc->if_name,v_ifc->tuntap_deleting);

		if( v_ifc->tuntap_deleting && event != RHP_IFC_EVT_DELETE_IF ){
			RHP_TRC(0,RHPTRCID_TUNTAP_IFC_NOTIFIER_TUN_IFC_NOW_DELETING,"xdxxs",rlm,rlm->id,rlm->internal_ifc,v_ifc,v_ifc->if_name);
			goto end;
		}

		switch( event ){

		case RHP_IFC_EVT_UPDATE_IF:
		{
			if( v_ifc->tuntap_fd == -1 ){

				err = _rhp_tuntap_open(v_ifc,rlm_id,
								RHP_VIF_TYPE_ETHER_TAP,rlm->internal_ifc->addrs_type);
				if( err ){
					RHP_BUG(" 0x%x : %s ERR:%d",v_ifc,v_ifc->if_name,err);
					goto error_l;
				}

				if( v_ifc->is_dmy_tuntap ){

					err = rhp_vpn_gen_or_add_local_mac(NULL,v_ifc->tuntap_dmy_peer_mac);
					if( err ){
						RHP_BUG("");
						goto error_l;
					}
				}


				if( !rhp_gcfg_ipv6_disabled ){

					err = rhp_vpn_gen_or_add_local_mac(NULL,v_ifc->v6_aux_lladdr.mac);
					if( err ){
						RHP_BUG("");
						goto error_l;
					}

					err = rhp_ipv6_rlm_lladdr_start_alloc(rlm_id,v_ifc,1);
					if( err ){
						RHP_BUG("");
						goto error_l;
					}

					err = rhp_bridge_static_cache_create(rlm_id,
									v_ifc->v6_aux_lladdr.mac,
									RHP_BRIDGE_SIDE_TUNTAP,RHP_BRIDGE_SCACHE_V6_DUMMY_LL_ADDR);
					if( err ){
						RHP_BUG("");
						goto error_l;
					}
				}


				if( rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_NONE ){

					if( rlm->internal_ifc->bridge_name ){

						err = rhp_ipc_send_bridge_ctrl(rlm->internal_ifc->bridge_name,rlm->internal_ifc->if_name,1);
						if( err ){
							RHP_BUG("%d",err);
						}
					}
				}

				route_update = 1;
			}
		}
		break;

		case RHP_IFC_EVT_DELETE_IF:
		{
			if( v_ifc->tuntap_fd != -1 ){

				rhp_tuntap_close(v_ifc);


				if( !rhp_gcfg_ipv6_disabled ){

					if( !rhp_ip_addr_null(&(v_ifc->v6_aux_lladdr.lladdr)) ){

						rhp_bridge_static_neigh_cache_delete(
							v_ifc->tuntap_vpn_realm_id,&(v_ifc->v6_aux_lladdr.lladdr),NULL,NULL);
					}
				}
			}
		}
		break;

		case RHP_IFC_EVT_UPDATE_ADDR:
		{
			if( rlm->internal_ifc->addrs_type != RHP_VIF_ADDR_STATIC &&
					rlm->internal_ifc->addrs_type != RHP_VIF_ADDR_NONE ){

				rhp_ip_addr_list* addr_lst = rlm->internal_ifc->addrs;
				while( addr_lst ){

					if( addr_lst->ip_addr.addr_family == old_info->addr_family &&
							!memcmp(addr_lst->ip_addr.addr.raw,old_info->addr.raw,16)){
						break;
					}

					addr_lst = addr_lst->next;
				}

				if( addr_lst == NULL ){

					addr_lst = (rhp_ip_addr_list*)_rhp_malloc(sizeof(rhp_ip_addr_list));
					if( addr_lst == NULL ){
						RHP_BUG("");
						err = -ENOMEM;
						goto error_l;
					}

					memset(addr_lst,0,sizeof(rhp_ip_addr_list));

					addr_lst->next = rlm->internal_ifc->addrs;
					rlm->internal_ifc->addrs = addr_lst;

					if( rlm->internal_ifc->ikev2_config_ipv6_auto ){
						vpn_route_updated = 1;
					}
				}

				rhp_ip_addr_set(&(addr_lst->ip_addr),
						new_info->addr_family,new_info->addr.raw,NULL,new_info->prefixlen,0,0);

				rhp_ip_addr_dump("_rhp_tuntap_ifc_notifier_cb_upd",&(addr_lst->ip_addr));
			}


			if( rlm->internal_ifc->addrs_type != RHP_VIF_ADDR_NONE ){

				rhp_ip_addr local_addr;

				memset(&local_addr,0,sizeof(rhp_ip_addr));

				local_addr.addr_family = new_info->addr_family;
				memcpy(local_addr.addr.raw,new_info->addr.raw,16);

				rhp_bridge_static_neigh_cache_delete(rlm->id,&local_addr,NULL,NULL);

				err = rhp_bridge_static_neigh_cache_create(
								rlm->id,
								new_info->mac,&local_addr,
								RHP_BRIDGE_SIDE_TUNTAP,RHP_BRIDGE_SCACHE_DUMMY);
				if( err ){
					RHP_BUG("%d",err);
				}
			}
		}
		break;

		case RHP_IFC_EVT_DELETE_ADDR:
		{
			if( rlm->internal_ifc->addrs_type != RHP_VIF_ADDR_STATIC &&
					rlm->internal_ifc->addrs_type != RHP_VIF_ADDR_NONE ){

				rhp_ip_addr_list *addr_lst, *addr_lst_p = NULL;

				addr_lst = rlm->internal_ifc->addrs;
				while( addr_lst ){

					if( addr_lst->ip_addr.addr_family == old_info->addr_family &&
							!memcmp(addr_lst->ip_addr.addr.raw,old_info->addr.raw,16)){
						break;
					}

					addr_lst_p = addr_lst;
					addr_lst = addr_lst->next;
				}

				if( addr_lst ){

					rhp_ip_addr_dump("_rhp_tuntap_ifc_notifier_cb_del",&(addr_lst->ip_addr));

					if( addr_lst_p ){
						addr_lst_p->next = addr_lst->next;
					}else{
						rlm->internal_ifc->addrs = addr_lst->next;
					}

					_rhp_free(addr_lst);
					addr_lst = NULL;
				}
			}

			if( rlm->internal_ifc->addrs_type != RHP_VIF_ADDR_NONE ){

				rhp_ip_addr local_addr;

				memset(&local_addr,0,sizeof(rhp_ip_addr));

				local_addr.addr_family = old_info->addr_family;
				memcpy(local_addr.addr.raw,old_info->addr.raw,16);

				rhp_bridge_static_neigh_cache_delete(rlm->id,&local_addr,NULL,NULL);
			}
		}
		break;

		default:
			RHP_TRC(0,RHPTRCID_TUNTAP_IFC_NOTIFIER_NOT_INTERESTED,"Ldxx","IFC_EVT",event,v_ifc,rlm);
			break;
		}

		goto end;
	}

	RHP_UNLOCK(&(v_ifc->lock));
	RHP_UNLOCK(&(rlm->lock));

	RHP_TRC(0,RHPTRCID_TUNTAP_IFC_NOTIFIER_CB_RTRN,"xx",rlm,ctx);
	return 0;

end:
	RHP_UNLOCK(&(v_ifc->lock));
	RHP_UNLOCK(&(rlm->lock));

	if( rlm_id ){

		if( route_update ){

			err = rhp_realms_setup_route(rlm_id);
			if( err ){
				RHP_BUG("%d",err);
				err = 0;
			}
		}

		if( vpn_route_updated ){

			err = rhp_vpn_enum(rlm_id,_rhp_tuntap_vpn_route_updated_cb,v_ifc);
			if( err ){
				RHP_TRC(0,RHPTRCID_TUNTAP_IFC_NOTIFIER_CB_VPN_ROUTE_UPDATED_CB_ERR,"uxE",rlm_id,v_ifc,err);
				err = 0;
			}
		}
	}

	RHP_TRC(0,RHPTRCID_TUNTAP_IFC_NOTIFIER_CB_ENUM_OK,"xux",rlm,rlm_id,ctx);
	return RHP_STATUS_ENUM_OK;

error_l:
	RHP_UNLOCK(&(v_ifc->lock));
	RHP_UNLOCK(&(rlm->lock));

	RHP_TRC(0,RHPTRCID_TUNTAP_IFC_NOTIFIER_CB_ERR,"xuxE",rlm,rlm_id,ctx,err);
	return err;
}

static void _rhp_tuntap_ifc_notifier(int event,rhp_ifc_entry* ifc,rhp_if_entry* new_info,
		rhp_if_entry* old_info,void* ctx)
{
  int err = -EINVAL;
  rhp_tuntap_ntfyifc_cb_ctx enum_ctx;

  RHP_TRC(0,RHPTRCID_TUNTAP_IFC_NOTIFIER,"Ldsxxxx","IFC_EVT",event,ifc->if_name,ifc,new_info,old_info,ctx);
  rhp_if_entry_dump("_rhp_tuntap_ifc_notifier.old",old_info);
  rhp_if_entry_dump("_rhp_tuntap_ifc_notifier.new",new_info);

	if( !_rhp_atomic_read(&(ifc->is_active)) ){
	  RHP_TRC(0,RHPTRCID_TUNTAP_IFC_NOTIFIER_IFC_NOT_ACTIVE,"Ldsxxxx","IFC_EVT",event,ifc->if_name,ifc,new_info,old_info,ctx);
	  return;
	}

  if( event != RHP_IFC_EVT_UPDATE_IF &&
  		event != RHP_IFC_EVT_DELETE_IF &&
  		event != RHP_IFC_EVT_UPDATE_ADDR &&
  		event != RHP_IFC_EVT_DELETE_ADDR ){

  	RHP_TRC(0,RHPTRCID_TUNTAP_IFC_NOTIFIER_NOT_INTERESTED,"Ldx","IFC_EVT",event,ifc);
  	goto ignore;
  }


  if( strstr(ifc->if_name,RHP_VIRTUAL_IF_NAME) == NULL ){

  	_rhp_tuntap_bridge_ifc_notifier(event,ifc,new_info,old_info);
    return;
  }

  enum_ctx.ifc = ifc;
  enum_ctx.event = event;
  enum_ctx.new_info = new_info;
  enum_ctx.old_info = old_info;

  err = rhp_realm_enum(0,_rhp_tuntap_ifc_notifier_cb,&enum_ctx);
  if( err && err != -ENOENT && err != RHP_STATUS_ENUM_OK ){
  	RHP_BUG("%d",err);
  }

ignore:
	RHP_TRC(0,RHPTRCID_TUNTAP_IFC_NOTIFIER_RTRN,"Ldx","IFC_EVT",event,ifc);
  return;
}

int rhp_tuntap_init()
{
  int err = 0;

  if( rhp_random_bytes((u8*)&_rhp_tuntap_disp_hash_rnd,sizeof(_rhp_tuntap_disp_hash_rnd)) ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  if( (err = rhp_wts_register_disp_rule(RHP_WTS_DISP_RULE_TUNTAP,_rhp_tuntap_read_disp_hash)) ){
    RHP_BUG("");
    goto error;
  }

  rhp_ifc_notifiers[RHP_IFC_NOTIFIER_TUNTAP].callback = _rhp_tuntap_ifc_notifier;
  rhp_ifc_notifiers[RHP_IFC_NOTIFIER_TUNTAP].ctx = NULL;

error:
	RHP_TRC(0,RHPTRCID_TUNTAP_INIT,"E",err);
	return err;
}


void rhp_tuntap_read_dispached_task(rhp_packet *pkt)
{
	RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_DISPACHED_TASK,"xLd",pkt,"PKT",pkt->type);

  switch( pkt->type ){

  case RHP_PKT_PLAIN_ETHER_TAP:

  	rhp_bridge_pkt_to_vpn(pkt);
  	break;

  case RHP_PKT_PLAIN_IPV4_TUNNEL:

  	break;

  case RHP_PKT_PLAIN_IPV6_TUNNEL:

  	break;

  default:
    RHP_BUG("%d",pkt->type);
    break;
  }

  rhp_pkt_unhold(pkt);

  return;
}

static int _rhp_tuntap_read_dispach_packet(rhp_packet *pkt)
{
	int disp_pri;

	RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_DISPACH_PACKET,"xLd",pkt,"PKT",pkt->type);

	if( rhp_gcfg_forward_critical_pkt_preferentially &&
			rhp_is_critical_pkt(pkt) ){
		disp_pri = RHP_WTS_DISP_LEVEL_HIGH_2;
	}else{
		disp_pri = RHP_WTS_DISP_LEVEL_LOW_2;
	}

	pkt->process_packet = rhp_tuntap_read_dispached_task;

	return rhp_wts_sta_invoke_task(RHP_WTS_DISP_RULE_TUNTAP,
			RHP_WTS_STA_TASK_NAME_PKT,disp_pri,pkt,pkt);
}

static int _rhp_tuntap_read_restart(rhp_ifc_entry* v_ifc)
{
	int err = 0;
  struct epoll_event ep_evt;

  RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_READ_RESTART,"xfdd",v_ifc,v_ifc->tx_esp_pkt_pend_flag.c,v_ifc->tx_esp_pkt_pend_flag.flag,v_ifc->tuntap_fd);

  if( v_ifc->tuntap_fd != -1 ){

		memset(&ep_evt,0,sizeof(struct epoll_event));
		ep_evt.events = RHP_TUNTAP_EPOLL_EVT_MASK;
		ep_evt.data.ptr = (void*)&(v_ifc->tuntap_fd_epoll_ctx);

		if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_MOD,v_ifc->tuntap_fd,&ep_evt) < 0 ){
			err = -errno;
			RHP_BUG("%d",err);
		}
  }

  v_ifc->statistics.tuntap.read_restart++;

  RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_READ_RESTART_RTRN,"xE",v_ifc,err);
  return err;
}

static int _rhp_tuntap_read_stop(rhp_ifc_entry* v_ifc)
{
	int err = 0;
  struct epoll_event ep_evt;

  RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_READ_STOP,"xfdd",v_ifc,v_ifc->tx_esp_pkt_pend_flag.c,v_ifc->tx_esp_pkt_pend_flag.flag,v_ifc->tuntap_fd);

  if( v_ifc->tuntap_fd != -1 ){

		memset(&ep_evt,0,sizeof(struct epoll_event));
		ep_evt.events = 0;
		ep_evt.data.ptr = (void*)&(v_ifc->tuntap_fd_epoll_ctx);

		if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_MOD,v_ifc->tuntap_fd,&ep_evt) < 0 ){
			err = -errno;
			RHP_BUG("%d",err);
		}
  }

	v_ifc->statistics.tuntap.read_stop++;

  RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_READ_STOP_RTRN,"xE",v_ifc,err);
  return err;
}

static void _rhp_tuntap_rx_pkt_done_final(rhp_packet* pkt)
{
	rhp_ifc_entry* v_ifc = (rhp_ifc_entry*)pkt->esp_pkt_pend_done_ctx;

	RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_RX_PKT_DONE_FINAL,"xxsLddfd",pkt,v_ifc,v_ifc->if_name,"VIF_TYPE",v_ifc->tuntap_type,v_ifc->tuntap_fd,v_ifc->tx_esp_pkt_pend_flag.c,v_ifc->tx_esp_pkt_pend_flag.flag);

  RHP_LOCK(&(v_ifc->lock));

  _rhp_tuntap_read_restart(v_ifc);

  RHP_UNLOCK(&(v_ifc->lock));
	rhp_ifc_unhold(v_ifc);

	pkt->esp_pkt_pend_done_ctx = NULL;
	pkt->esp_pkt_pend_done = NULL;
	rhp_pkt_unhold(pkt);

	RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_RX_PKT_DONE_FINAL_RTRN,"xx",pkt,v_ifc);
	return;
}

static int _rhp_tuntap_rx_pkt_done(rhp_packet* pkt)
{
	int err;
	rhp_ifc_entry* v_ifc = (rhp_ifc_entry*)pkt->esp_pkt_pend_done_ctx;

	RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_RX_PKT_DONE,"xxsLddfd",pkt,v_ifc,v_ifc->if_name,"VIF_TYPE",v_ifc->tuntap_type,v_ifc->tuntap_fd,v_ifc->tx_esp_pkt_pend_flag.c,v_ifc->tx_esp_pkt_pend_flag.flag);

	if( _rhp_atomic_flag_dec_and_test(&(v_ifc->tx_esp_pkt_pend_flag),0,NULL) ){

		// Nobody knows when pkt->esp_pkt_pend_done()(rhp_pkt_unhold) is called. So, just to make sure,
		// switch the context to avoid racing condition of v_ifc->lock.
		pkt->process_packet = _rhp_tuntap_rx_pkt_done_final;
		rhp_pkt_hold(pkt);

		err = rhp_wts_sta_invoke_task(RHP_WTS_DISP_RULE_SAME_WORKER,
								RHP_WTS_STA_TASK_NAME_PKT,RHP_WTS_DISP_LEVEL_HIGH_3,NULL,pkt);

		if( err ){
			RHP_BUG("%d",err);
		}

		RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_RX_PKT_DONE_PENDING,"xx",pkt,v_ifc);
		return 1;

	}else{

		pkt->esp_pkt_pend_done = NULL;
		rhp_ifc_unhold(v_ifc);
	}

	RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_RX_PKT_DONE_RTRN,"xx",pkt,v_ifc);
	return 0;
}

static void _rhp_tuntap_read_statistics(rhp_ifc_entry* v_ifc,rhp_packet* pkt,ssize_t mesg_len)
{
	v_ifc->statistics.tuntap.read_pkts++;
	v_ifc->statistics.tuntap.read_bytes += mesg_len;

	if( pkt->l2.raw ){

		switch( pkt->l2.eth->protocol ){

		case RHP_PROTO_ETH_IP:

			v_ifc->statistics.tuntap.read_ipv4_pkts++;

			if( pkt->l2.raw + sizeof(rhp_proto_ip_v4) < pkt->end ){

				rhp_proto_ip_v4* iph = (rhp_proto_ip_v4*)(pkt->l2.eth + 1);

				switch( iph->protocol ){
				case RHP_PROTO_IP_ICMP:
					v_ifc->statistics.tuntap.read_ipv4_icmp_pkts++;
					break;
				case RHP_PROTO_IP_TCP:
					v_ifc->statistics.tuntap.read_ipv4_tcp_pkts++;
					break;
				case RHP_PROTO_IP_UDP:
				case RHP_PROTO_IP_UDPLITE:
					v_ifc->statistics.tuntap.read_ipv4_udp_pkts++;
					break;
				default:
					v_ifc->statistics.tuntap.read_ipv4_other_pkts++;
					break;
				}

			}else{

				v_ifc->statistics.tuntap.read_ipv4_other_pkts++;
			}
			break;

		case RHP_PROTO_ETH_IPV6:

			v_ifc->statistics.tuntap.read_ipv6_pkts++;

			if( pkt->l2.raw + sizeof(rhp_proto_ip_v6) < pkt->end ){

				rhp_proto_ip_v6* ip6h = (rhp_proto_ip_v6*)(pkt->l2.eth + 1);
				u8 protocol = 0;
				u8 protos[4] = {RHP_PROTO_IP_IPV6_ICMP,RHP_PROTO_IP_UDP,RHP_PROTO_IP_TCP,RHP_PROTO_IP_UDPLITE};
				int protos_num = 4;

				rhp_proto_ip_v6_upper_layer(ip6h,pkt->end,protos_num,protos,&protocol);

				switch( protocol ){
				case RHP_PROTO_IP_IPV6_ICMP:
					v_ifc->statistics.tuntap.read_ipv6_icmp_pkts++;
					break;
				case RHP_PROTO_IP_TCP:
					v_ifc->statistics.tuntap.read_ipv6_tcp_pkts++;
					break;
				case RHP_PROTO_IP_UDP:
				case RHP_PROTO_IP_UDPLITE:
					v_ifc->statistics.tuntap.read_ipv6_udp_pkts++;
					break;
				default:
					v_ifc->statistics.tuntap.read_ipv6_other_pkts++;
					break;
				}

			}else{

				v_ifc->statistics.tuntap.read_ipv6_other_pkts++;
			}
			break;

		case RHP_PROTO_ETH_ARP:
			v_ifc->statistics.tuntap.read_arp_pkts++;
			break;

		default:
			v_ifc->statistics.tuntap.read_other_pkts++;
			break;
		}

	}else{

		v_ifc->statistics.tuntap.read_other_pkts++;
	}

	return;
}

static void _rhp_tuntap_read_statistics_err(rhp_ifc_entry* v_ifc,rhp_packet* pkt)
{
	v_ifc->statistics.tuntap.read_err_pkts++;

	if( pkt->l2.raw ){

		switch( pkt->l2.eth->protocol ){

		case RHP_PROTO_ETH_IP:

			v_ifc->statistics.tuntap.read_err_ipv4_pkts++;

			if( pkt->l2.raw + sizeof(rhp_proto_ip_v4) < pkt->end ){

				rhp_proto_ip_v4* iph = (rhp_proto_ip_v4*)(pkt->l2.eth + 1);

				switch( iph->protocol ){
				case RHP_PROTO_IP_ICMP:
					v_ifc->statistics.tuntap.read_err_ipv4_icmp_pkts++;
					break;
				case RHP_PROTO_IP_TCP:
					v_ifc->statistics.tuntap.read_err_ipv4_tcp_pkts++;
					break;
				case RHP_PROTO_IP_UDP:
				case RHP_PROTO_IP_UDPLITE:
					v_ifc->statistics.tuntap.read_err_ipv4_udp_pkts++;
					break;
				default:
					v_ifc->statistics.tuntap.read_err_ipv4_other_pkts++;
					break;
				}

			}else{

				v_ifc->statistics.tuntap.read_err_ipv4_other_pkts++;
			}
			break;

		case RHP_PROTO_ETH_IPV6:

			v_ifc->statistics.tuntap.read_err_ipv6_pkts++;

			if( pkt->l2.raw + sizeof(rhp_proto_ip_v6) < pkt->end ){

				rhp_proto_ip_v6* ip6h = (rhp_proto_ip_v6*)(pkt->l2.eth + 1);
				u8 protocol = 0;
				u8 protos[4] = {RHP_PROTO_IP_IPV6_ICMP,RHP_PROTO_IP_UDP,RHP_PROTO_IP_TCP,RHP_PROTO_IP_UDPLITE};
				int protos_num = 4;

				rhp_proto_ip_v6_upper_layer(ip6h,pkt->end,protos_num,protos,&protocol);

				switch( protocol ){
				case RHP_PROTO_IP_IPV6_ICMP:
					v_ifc->statistics.tuntap.read_err_ipv6_icmp_pkts++;
					break;
				case RHP_PROTO_IP_TCP:
					v_ifc->statistics.tuntap.read_err_ipv6_tcp_pkts++;
					break;
				case RHP_PROTO_IP_UDP:
				case RHP_PROTO_IP_UDPLITE:
					v_ifc->statistics.tuntap.read_err_ipv6_udp_pkts++;
					break;
				default:
					v_ifc->statistics.tuntap.read_err_ipv6_other_pkts++;
					break;
				}

			}else{

				v_ifc->statistics.tuntap.read_err_ipv6_other_pkts++;
			}
			break;

		case RHP_PROTO_ETH_ARP:
			v_ifc->statistics.tuntap.read_err_arp_pkts++;
			break;

		default:
			v_ifc->statistics.tuntap.read_err_other_pkts++;
			break;
		}

	}else{

		v_ifc->statistics.tuntap.read_err_other_pkts++;
	}

	return;
}


static int _rhp_tuntap_is_loop_pkt_v4(rhp_packet* pkt)
{
	rhp_proto_ip_v4* iph = (rhp_proto_ip_v4*)_rhp_pkt_try_push(pkt,sizeof(rhp_proto_ip_v4));

	if( iph ){

		if( iph->protocol == RHP_PROTO_IP_ESP ){

			if( rhp_ifc_is_my_ip_v4(iph->src_addr) ){
				return 1;
			}

		}else if( iph->protocol == RHP_PROTO_IP_UDP ){

			rhp_proto_udp* udph = (rhp_proto_udp*)(((u8*)iph) + iph->ihl*4);

			if( (u8*)(udph + 1) <= pkt->end &&
					rhp_ifc_is_my_ip_v4(iph->src_addr) &&
				  ( udph->src_port == htons(rhp_gcfg_ike_port) ||
				  	udph->src_port == htons(rhp_gcfg_ike_port_nat_t)) ){

				return 1;
			}
		}
	}

	return 0;
}

static int _rhp_tuntap_is_loop_pkt_v6(rhp_packet* pkt)
{
	rhp_proto_ip_v6* ip6h = (rhp_proto_ip_v6*)_rhp_pkt_try_push(pkt,sizeof(rhp_proto_ip_v6));

	if( ip6h ){

		u8 protos[2] = {RHP_PROTO_IP_ESP, RHP_PROTO_IP_UDP};
		u8 proto = 0;
		u8* hdr;

		hdr = rhp_proto_ip_v6_upper_layer(ip6h,pkt->end,2,protos,&proto);
		if( hdr ){

			if( proto == RHP_PROTO_IP_ESP ){

				if( rhp_ifc_is_my_ip_v6(ip6h->src_addr) ){
					return 1;
				}

			}else if( proto == RHP_PROTO_IP_UDP ){

				rhp_proto_udp* udph = (rhp_proto_udp*)hdr;

				if( (u8*)(udph + 1) <= pkt->end &&
						rhp_ifc_is_my_ip_v6(ip6h->src_addr) &&
					  ( udph->src_port == htons(rhp_gcfg_ike_port) ||
					  	udph->src_port == htons(rhp_gcfg_ike_port_nat_t)) ){

					return 1;
				}
			}
		}
	}

	return 0;
}

static int _rhp_tuntap_read_check_ipv6_nd(rhp_ifc_entry* v_ifc,rhp_packet* pkt)
{
	if( rhp_gcfg_ipv6_drop_router_adv ){

		if( v_ifc->tuntap_addrs_type == RHP_VIF_ADDR_STATIC ||
				v_ifc->tuntap_addrs_type == RHP_VIF_ADDR_IKEV2CFG ){

			rhp_proto_ip_v6* ip6h = (rhp_proto_ip_v6*)_rhp_pkt_try_push(pkt,sizeof(rhp_proto_ip_v6));
			if( ip6h ){

				u8 protos = RHP_PROTO_IP_IPV6_ICMP;
				u8* hdr;

				hdr = rhp_proto_ip_v6_upper_layer(ip6h,pkt->end,1,&protos,NULL);
				if( hdr ){

					rhp_proto_icmp6* icmpv6h = (rhp_proto_icmp6*)hdr;

					if( (u8*)(icmpv6h + 1) <= pkt->end &&
							icmpv6h->type == RHP_PROTO_ICMP6_TYPE_ROUTER_SOLICIT ){
						return 1;
					}
				}
			}
		}
	}

	return 0;
}


static int _rhp_tuntap_read(rhp_ifc_entry* v_ifc)
{
  int err = -EINVAL;
  int tun_fd = v_ifc->tuntap_fd;
  rhp_packet* pkt = NULL;

	RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_READ,"xsLdd",v_ifc,v_ifc->if_name,"VIF_TYPE",v_ifc->tuntap_type,v_ifc->tuntap_fd);

  while( 1 ){

    int buf_len = 0;
    int pkt_type = 0;
    u8* buf;
    ssize_t mesg_len;
    int stop_recv = 0;

    pkt = NULL;

    if( !RHP_PROCESS_IS_ACTIVE() ){
      err = -EINTR;
      RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_READ_NOT_ACTIVE,"");
      goto error;
    }

    buf_len = v_ifc->mtu + sizeof(struct tun_pi) + 32;

    pkt = rhp_pkt_alloc(buf_len);
    if( pkt == NULL ){
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }

    buf = pkt->data;

    //
    // [CAUTION]
  	// Tuntap read() may return with no data(mesg_len == 0) on Ubuntu 15.04(?).
    //
    mesg_len = read(tun_fd,buf,(buf_len - pkt->len));
    if( mesg_len <= 0 ){

      err = -errno;
      RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_READ_ERR,"xsE",v_ifc,v_ifc->if_name,err);
      goto error;
    }

    RHP_BINDUMP_FREQ(0,"_rhp_tuntap_read.read",mesg_len,buf);

    if( mesg_len < (ssize_t)sizeof(struct tun_pi)){
      RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_READ_ERR_MESG_LEN_TUN_PI,"xsdE",v_ifc,v_ifc->if_name,mesg_len,err);
      rhp_pkt_unhold(pkt);
      continue;
    }

    _rhp_pkt_push(pkt,sizeof(struct tun_pi));
    _rhp_pkt_pull(pkt,sizeof(struct tun_pi));

    if( v_ifc->tuntap_type == RHP_VIF_TYPE_IP_TUNNEL ){

//    pkt_type = RHP_PKT_PLAIN_IPV4_TUNNEL;
    	err = -EINVAL;
    	RHP_BUG("%s:%d",v_ifc->if_name,v_ifc->tuntap_type);
    	goto error;

    }else if( v_ifc->tuntap_type == RHP_VIF_TYPE_ETHER_TAP ){

      rhp_proto_ether* ethh;
      int l3_rem;

      if( mesg_len < (ssize_t)(sizeof(struct tun_pi) + sizeof(rhp_proto_ether)) ){
        RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_READ_ERR_MESG_LEN_ETHER,"xsdE",v_ifc,v_ifc->if_name,mesg_len,err);
        rhp_pkt_unhold(pkt);
        continue;
      }

      RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_READ_ETHER_TAP_PKT,"xsa",v_ifc,v_ifc->if_name,(mesg_len - sizeof(struct tun_pi)),RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,pkt->data);


    	pkt_type = RHP_PKT_PLAIN_ETHER_TAP;

      l3_rem = (mesg_len - sizeof(struct tun_pi) - sizeof(rhp_proto_ether));

      ethh = (rhp_proto_ether*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ether));
      if( ethh == NULL ){
      	 err = -EINVAL;
      	 RHP_BUG("%s:%d",v_ifc->if_name,v_ifc->tuntap_type);
      	 goto error;
   	 	}
      pkt->l2.raw = (u8*)ethh;



    	if( ethh->protocol == RHP_PROTO_ETH_IP ){

    		if( l3_rem <= (int)sizeof(rhp_proto_ip_v4) ){
					RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_READ_IPV4_TOO_SHORT,"xsdd",v_ifc,v_ifc->if_name,l3_rem,mesg_len);
					err = -EINVAL;
					goto error;
    		}

        if( rhp_gcfg_check_pkt_routing_loop ){

					if( _rhp_tuntap_is_loop_pkt_v4(pkt) ){
						RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_READ_IS_LOOP_PKT,"xs",v_ifc,v_ifc->if_name);
						err = -EINVAL;
						goto error;
					}
        }

    	}else if( ethh->protocol == RHP_PROTO_ETH_IPV6 ){

    		if( l3_rem <= (int)sizeof(rhp_proto_ip_v6) ){
					RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_READ_IPV6_TOO_SHORT,"xsdd",v_ifc,v_ifc->if_name,l3_rem,mesg_len);
					err = -EINVAL;
					goto error;
    		}

        if( rhp_gcfg_check_pkt_routing_loop ){
					if( _rhp_tuntap_is_loop_pkt_v6(pkt) ){
						RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_READ_IS_LOOP_PKT_V6,"xs",v_ifc,v_ifc->if_name);
						err = -EINVAL;
						goto error;
					}
        }

    		//
    		// If the packet's src address is link-local and addrs_type
    		// is RHP_VIF_ADDR_IKEV2CFG, the packet may be dropped later
    		// by traffic-selectors.
    		//

        if( _rhp_tuntap_read_check_ipv6_nd(v_ifc,pkt) ){

  				RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_READ_IPV6_ND_CHECKED,"xs",v_ifc,v_ifc->if_name);

  				v_ifc->statistics.tuntap.drop_icmpv6_router_solicit++;
  				err = 0;
  				goto error;
        }
			}


      pkt->l3.raw = _rhp_pkt_push(pkt,l3_rem);
      if( pkt->l3.raw == NULL ){
      	err = -EINVAL;
      	RHP_BUG("");
      	goto error;
      }

    }else{

    	err = -EINVAL;
    	RHP_BUG("%s:%d",v_ifc->if_name,v_ifc->tuntap_type);
    	goto error;
    }

    pkt->type = pkt_type;

    pkt->rx_if_index = v_ifc->if_index;
    pkt->rx_ifc = v_ifc;
    rhp_ifc_hold(pkt->rx_ifc);


    pkt->esp_pkt_pend_done = _rhp_tuntap_rx_pkt_done;
    pkt->esp_pkt_pend_done_ctx = v_ifc;
    rhp_ifc_hold(v_ifc);


  	if( v_ifc->tuntap_nhrp_service == RHP_NHRP_SERVICE_CLIENT &&
  			v_ifc->tuntap_dmvpn_enabled ){

  		pkt->dmvpn_enabled = 1;
  	}

		if( _rhp_atomic_flag_inc_and_test(&(v_ifc->tx_esp_pkt_pend_flag),rhp_gcfg_tuntap_rx_pkt_upper_limit,NULL) ){

			_rhp_tuntap_read_stop(v_ifc);
			stop_recv = 1;
    }

		rhp_pkt_trace_dump("_rhp_tuntap_read",pkt);


		if( rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_VIF] &&
				(!rhp_packet_capture_realm_id || !rhp_packet_capture_realm_id == v_ifc->tuntap_vpn_realm_id) ){

			_rhp_tuntap_pcap_write(pkt);
		}


    err = _rhp_tuntap_read_dispach_packet(pkt);
    if( err ){

    	RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_READ_DISP_ERR,"xsE",v_ifc,v_ifc->if_name,err);

      rhp_pkt_unhold(pkt);
      continue;
    }

		if( stop_recv ){
    	break;
    }

		_rhp_tuntap_read_statistics(v_ifc,pkt,mesg_len);
  }


  RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_READ_RTRN,"xs",v_ifc,v_ifc->if_name);
  return 0;

error:
	if( pkt ){
		if( err && err != -EAGAIN && err != -EINTR ){
			_rhp_tuntap_read_statistics_err(v_ifc,pkt);
		}
    rhp_pkt_unhold(pkt);
	}

	RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_READ_ERR,"xsE",v_ifc,v_ifc->if_name,err);
	return err;
}

static u16 _rhp_tuntap_dmy_read_icmp_seq = 1;

void rhp_tuntap_dmy_pkt_read(unsigned long rlm_id,u8 protocol,u8* src_mac,u8* dst_mac,
		rhp_ip_addr* src_ip_addr,rhp_ip_addr* dst_ip_addr,unsigned int data_len,u64 esp_tx_seq)
{
  int err = -EINVAL;
  int tun_fd;
  rhp_ifc_entry* v_ifc = NULL;
  int buf_len = 0;
  u8* buf;
  rhp_packet* pkt = NULL;
  rhp_proto_ether* ethh;
  rhp_proto_ip_v4* iph;
  rhp_proto_udp* udph;
  rhp_proto_icmp* icmph;
  rhp_proto_icmp_echo* icmp_echoh;
  int pkt_type;
  int i;

	RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_DMY_PKT_READ,"ubMMxxdq",rlm_id,protocol,src_mac,dst_mac,src_ip_addr,dst_ip_addr,data_len,esp_tx_seq);
	rhp_ip_addr_dump("_rhp_tuntap_dummy_read.src_addr",src_ip_addr);
	rhp_ip_addr_dump("_rhp_tuntap_dummy_read.dst_addr",dst_ip_addr);

	if( data_len == 0 ){
		RHP_BUG("");
		return;
	}

	if( src_ip_addr->addr_family != AF_INET || dst_ip_addr->addr_family != AF_INET ){
		RHP_BUG("%d,%d",src_ip_addr->addr_family,dst_ip_addr->addr_family);
		return;
	}

	if( data_len & 0x00000001 ){
		data_len++;
	}

  {
		rhp_vpn_realm* rlm = rhp_realm_get(rlm_id);

		if( rlm == NULL ){
			RHP_BUG("%d",rlm_id);
			return;
		}

		RHP_LOCK(&(rlm->lock));
		{
			v_ifc = rlm->internal_ifc->ifc;
			if( v_ifc ){
				rhp_ifc_hold(v_ifc);
			}
		}
		RHP_UNLOCK(&(rlm->lock));

		rhp_realm_unhold(rlm);
  }

  if( v_ifc == NULL ){
		RHP_BUG("");
  	return;
  }


  RHP_LOCK(&(v_ifc->lock));

	RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_DMY_PKT_READ_INFO,"xsLdd",v_ifc,v_ifc->if_name,"VIF_TYPE",v_ifc->tuntap_type,v_ifc->tuntap_fd);

  tun_fd = v_ifc->tuntap_fd;

  {

    if( !RHP_PROCESS_IS_ACTIVE() ){
      err = -EINTR;
      RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_DMY_PKT_READ_NOT_ACTIVE,"");
      goto error_l;
    }

    buf_len = sizeof(struct tun_pi) + sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v4) + data_len;

    switch( protocol ){
    case RHP_PROTO_IP_ICMP:
    	buf_len += sizeof(rhp_proto_icmp) + sizeof(rhp_proto_icmp_echo);
    	break;
    case RHP_PROTO_IP_UDP:
    	buf_len += sizeof(rhp_proto_udp);
    	break;
    default:
    	RHP_BUG("%d",protocol);
    	err = -EINVAL;
    	goto error_l;
    }


    pkt = rhp_pkt_alloc(buf_len);
    if( pkt == NULL ){
      err = -ENOMEM;
      RHP_BUG("");
      goto error_l;
    }

    pkt->dmy_pkt_esp_tx_seq = esp_tx_seq;

    _rhp_pkt_push(pkt,sizeof(struct tun_pi));
    _rhp_pkt_pull(pkt,sizeof(struct tun_pi));

    if( v_ifc->tuntap_type == RHP_VIF_TYPE_ETHER_TAP ){

    	pkt_type = RHP_PKT_PLAIN_ETHER_TAP;

      ethh = (rhp_proto_ether*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ether));
      if( ethh == NULL ){
      	 err = -EINVAL;
      	 RHP_BUG("%s:%d",v_ifc->if_name,v_ifc->tuntap_type);
      	 goto error_l;
   	 	}
      pkt->l2.raw = (u8*)ethh;

      if( src_mac && !_rhp_mac_addr_null(src_mac) ){
      	memcpy(ethh->src_addr,src_mac,6);
      }else{
    		if( rhp_random_bytes(ethh->src_addr,6) ){
    			ethh->src_addr[5] = 0x01;
    		}
    		ethh->src_addr[0] &= 0xFE;
    		ethh->src_addr[0] |= 0x02; // Local address
      }

      if( dst_mac && !_rhp_mac_addr_null(dst_mac) ){
      	memcpy(ethh->dst_addr,dst_mac,6);
      }else{
    		if( rhp_random_bytes(ethh->dst_addr,6) ){
    			ethh->dst_addr[5] = 0x01;
    		}
    		ethh->dst_addr[0] &= 0xFE;
    		ethh->dst_addr[0] |= 0x02; // Local address
      }

      ethh->protocol = RHP_PROTO_ETH_IP;

      iph = (rhp_proto_ip_v4*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ip_v4));
      if( iph == NULL ){
      	err = -EINVAL;
      	goto error_l;
      }
      pkt->l3.raw = (u8*)iph;

      iph->ver = 4;
			iph->ihl = 5;
			iph->tos = 0;
			iph->id = 0;
			iph->frag = 0;
			iph->ttl = 64;
			iph->protocol = protocol;
			iph->check_sum = 0;
			iph->src_addr = src_ip_addr->addr.v4;
			iph->dst_addr = dst_ip_addr->addr.v4;

      switch( protocol ){

      case RHP_PROTO_IP_ICMP:
      {
      	icmph = (rhp_proto_icmp*)_rhp_pkt_push(pkt,sizeof(rhp_proto_icmp));
        if( icmph == NULL ){
        	err = -EINVAL;
        	goto error_l;
        }

        icmph->type = RHP_PROTO_ICMP_TYPE_ECHO_REQUEST;
        icmph->code = 0;
        icmph->check_sum = 0;

        icmp_echoh = (rhp_proto_icmp_echo*)_rhp_pkt_push(pkt,sizeof(rhp_proto_icmp_echo));
        if( icmp_echoh == NULL ){
        	err = -EINVAL;
        	goto error_l;
        }

        icmp_echoh->id = 0xAABB;
        icmp_echoh->seq = htons(_rhp_tuntap_dmy_read_icmp_seq++);

        buf = (u8*)_rhp_pkt_push(pkt,data_len);
        if( buf == NULL ){
        	err = -EINVAL;
        	goto error_l;
        }

        for( i = 0; i < (int)data_len; i++ ){
        	buf[i] = 'I';
        }

  			iph->total_len
  			= htons(sizeof(rhp_proto_ip_v4) + sizeof(rhp_proto_icmp) + sizeof(rhp_proto_icmp_echo) + data_len);

        _rhp_proto_icmp_set_csum(icmph,
        		sizeof(rhp_proto_icmp) + sizeof(rhp_proto_icmp_echo) + data_len);
      }
      	break;

      case RHP_PROTO_IP_UDP:
      {
        udph = (rhp_proto_udp*)_rhp_pkt_push(pkt,sizeof(rhp_proto_udp));
        if( udph == NULL ){
        	err = -EINVAL;
        	goto error_l;
        }

        udph->src_port = src_ip_addr->port;
        udph->dst_port = dst_ip_addr->port;
        udph->check_sum = 0;
        udph->len = htons(sizeof(rhp_proto_udp) + data_len);

        buf = (u8*)_rhp_pkt_push(pkt,data_len);
        if( buf == NULL ){
        	err = -EINVAL;
        	goto error_l;
        }

        for( i = 0; i < (int)data_len; i++ ){
        	buf[i] = 'U';
        }

  			iph->total_len = htons(sizeof(rhp_proto_ip_v4) + sizeof(rhp_proto_udp) + data_len);

        _rhp_proto_ip_v4_udp_set_csum(src_ip_addr->addr.v4,dst_ip_addr->addr.v4,udph);
      }
      	break;

      default:
      	RHP_BUG("%d",protocol);
      	err = -EINVAL;
      	goto error_l;
      }

    }else{

    	RHP_BUG("%s:%d",v_ifc->if_name,v_ifc->tuntap_type);
    	err = -EINVAL;
    	goto error_l;
    }

    _rhp_proto_ip_v4_set_csum(iph);

    pkt->type = pkt_type;

    pkt->rx_if_index = v_ifc->if_index;
    pkt->rx_ifc = v_ifc;
    rhp_ifc_hold(v_ifc);

    RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_DMY_PKT_READ_ETHER_TAP_PKT,"xsa",v_ifc,v_ifc->if_name,(sizeof(rhp_proto_ether) + ntohs(iph->total_len)),RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,ethh);

    rhp_pkt_trace_dump("_rhp_tuntap_dummy_read",pkt);

    err = _rhp_tuntap_read_dispach_packet(pkt);

    if( err ){
      RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_DMY_PKT_READ_DISP_ERR,"xsE",v_ifc,v_ifc->if_name,err);
      rhp_pkt_unhold(pkt);
    }
  }

  RHP_UNLOCK(&(v_ifc->lock));
	rhp_ifc_unhold(v_ifc);

  RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_DMY_PKT_READ_RTRN,"xs",v_ifc,v_ifc->if_name);
  return;

error_l:
  RHP_UNLOCK(&(v_ifc->lock));
	rhp_ifc_unhold(v_ifc);

  if( pkt ){
    rhp_pkt_unhold(pkt);
  }
  RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_DMY_PKT_READ_ERR,"xsE",v_ifc,v_ifc->if_name,err);
	return;
}

static void _rhp_tuntap_write_statistics(rhp_ifc_entry* v_ifc,rhp_packet* pkt,ssize_t mesg_len)
{
	v_ifc->statistics.tuntap.write_pkts++;
	v_ifc->statistics.tuntap.write_bytes += mesg_len;

	if( pkt->l2.raw ){

		switch( pkt->l2.eth->protocol ){

		case RHP_PROTO_ETH_IP:

			v_ifc->statistics.tuntap.write_ipv4_pkts++;

			if( pkt->l2.raw + sizeof(rhp_proto_ip_v4) < pkt->end ){

				rhp_proto_ip_v4* iph = (rhp_proto_ip_v4*)(pkt->l2.eth + 1);

				switch( iph->protocol ){
				case RHP_PROTO_IP_ICMP:
					v_ifc->statistics.tuntap.write_ipv4_icmp_pkts++;
					break;
				case RHP_PROTO_IP_TCP:
					v_ifc->statistics.tuntap.write_ipv4_tcp_pkts++;
					break;
				case RHP_PROTO_IP_UDP:
				case RHP_PROTO_IP_UDPLITE:
					v_ifc->statistics.tuntap.write_ipv4_udp_pkts++;
					break;
				default:
					v_ifc->statistics.tuntap.write_ipv4_other_pkts++;
					break;
				}

			}else{

				v_ifc->statistics.tuntap.write_ipv4_other_pkts++;
			}
			break;

		case RHP_PROTO_ETH_IPV6:

			v_ifc->statistics.tuntap.write_ipv6_pkts++;

			if( pkt->l2.raw + sizeof(rhp_proto_ip_v6) < pkt->end ){

				rhp_proto_ip_v6* ip6h = (rhp_proto_ip_v6*)(pkt->l2.eth + 1);
				u8 protocol = 0;
				u8 protos[4] = {RHP_PROTO_IP_IPV6_ICMP,RHP_PROTO_IP_UDP,RHP_PROTO_IP_TCP,RHP_PROTO_IP_UDPLITE};
				int protos_num = 4;

				rhp_proto_ip_v6_upper_layer(ip6h,pkt->end,protos_num,protos,&protocol);

				switch( protocol ){
				case RHP_PROTO_IP_IPV6_ICMP:
					v_ifc->statistics.tuntap.write_ipv6_icmp_pkts++;
					break;
				case RHP_PROTO_IP_TCP:
					v_ifc->statistics.tuntap.write_ipv6_tcp_pkts++;
					break;
				case RHP_PROTO_IP_UDP:
				case RHP_PROTO_IP_UDPLITE:
					v_ifc->statistics.tuntap.write_ipv6_udp_pkts++;
					break;
				default:
					v_ifc->statistics.tuntap.write_ipv6_other_pkts++;
					break;
				}

			}else{

				v_ifc->statistics.tuntap.write_ipv6_other_pkts++;
			}
			break;

		case RHP_PROTO_ETH_ARP:
			v_ifc->statistics.tuntap.write_arp_pkts++;
			break;

		default:
			v_ifc->statistics.tuntap.write_other_pkts++;
			break;
		}

	}else{

		v_ifc->statistics.tuntap.write_other_pkts++;
	}

	return;
}

static void _rhp_tuntap_write_statistics_err(rhp_ifc_entry* v_ifc,rhp_packet* pkt)
{
	v_ifc->statistics.tuntap.write_err_pkts++;

	if( pkt->l2.raw ){

		switch( pkt->l2.eth->protocol ){

		case RHP_PROTO_ETH_IP:

			v_ifc->statistics.tuntap.write_err_ipv4_pkts++;

			if( pkt->l2.raw + sizeof(rhp_proto_ip_v4) < pkt->end ){

				rhp_proto_ip_v4* iph = (rhp_proto_ip_v4*)(pkt->l2.eth + 1);

				switch( iph->protocol ){
				case RHP_PROTO_IP_ICMP:
					v_ifc->statistics.tuntap.write_err_ipv4_icmp_pkts++;
					break;
				case RHP_PROTO_IP_TCP:
					v_ifc->statistics.tuntap.write_err_ipv4_tcp_pkts++;
					break;
				case RHP_PROTO_IP_UDP:
				case RHP_PROTO_IP_UDPLITE:
					v_ifc->statistics.tuntap.write_err_ipv4_udp_pkts++;
					break;
				default:
					v_ifc->statistics.tuntap.write_err_ipv4_other_pkts++;
					break;
				}

			}else{

				v_ifc->statistics.tuntap.write_err_ipv4_other_pkts++;
			}
			break;

		case RHP_PROTO_ETH_IPV6:

			v_ifc->statistics.tuntap.write_err_ipv6_pkts++;

			if( pkt->l2.raw + sizeof(rhp_proto_ip_v6) < pkt->end ){

				rhp_proto_ip_v6* ip6h = (rhp_proto_ip_v6*)(pkt->l2.eth + 1);
				u8 protocol = 0;
				u8 protos[4] = {RHP_PROTO_IP_IPV6_ICMP,RHP_PROTO_IP_UDP,RHP_PROTO_IP_TCP,RHP_PROTO_IP_UDPLITE};
				int protos_num = 4;

				rhp_proto_ip_v6_upper_layer(ip6h,pkt->end,protos_num,protos,&protocol);

				switch( protocol ){
				case RHP_PROTO_IP_IPV6_ICMP:
					v_ifc->statistics.tuntap.write_err_ipv6_icmp_pkts++;
					break;
				case RHP_PROTO_IP_TCP:
					v_ifc->statistics.tuntap.write_err_ipv6_tcp_pkts++;
					break;
				case RHP_PROTO_IP_UDP:
				case RHP_PROTO_IP_UDPLITE:
					v_ifc->statistics.tuntap.write_err_ipv6_udp_pkts++;
					break;
				default:
					v_ifc->statistics.tuntap.write_err_ipv6_other_pkts++;
					break;
				}

			}else{

				v_ifc->statistics.tuntap.write_err_ipv6_other_pkts++;
			}
			break;

		case RHP_PROTO_ETH_ARP:
			v_ifc->statistics.tuntap.write_err_arp_pkts++;
			break;

		default:
			v_ifc->statistics.tuntap.write_err_other_pkts++;
			break;
		}

	}else{

		v_ifc->statistics.tuntap.write_err_other_pkts++;
	}

	return;
}

static int _rhp_tuntap_write_check_ipv6_nd(rhp_ifc_entry* v_ifc,rhp_proto_ether* ethh,u8* end)
{
	if( rhp_gcfg_ipv6_drop_router_adv ){

		if( v_ifc->tuntap_addrs_type == RHP_VIF_ADDR_STATIC ||
				v_ifc->tuntap_addrs_type == RHP_VIF_ADDR_IKEV2CFG ){

			rhp_proto_ip_v6* ip6h = (rhp_proto_ip_v6*)(ethh + 1);
			if( (u8*)(ip6h + 1) <= end ){

				u8 protos = RHP_PROTO_IP_IPV6_ICMP;
				u8* hdr;

				hdr = rhp_proto_ip_v6_upper_layer(ip6h,end,1,&protos,NULL);
				if( hdr ){

					rhp_proto_icmp6* icmpv6h = (rhp_proto_icmp6*)hdr;

					if( (u8*)(icmpv6h + 1) <= end &&
							icmpv6h->type == RHP_PROTO_ICMP6_TYPE_ROUTER_ADV ){
						return 1;
					}
				}
			}
		}
	}
	return 0;
}

int rhp_tuntap_write(rhp_ifc_entry* v_ifc,rhp_packet* pkt)
{
	int err = -EINVAL;
	ssize_t mesg_len;
  struct tun_pi pi = {0,0};
  struct iovec iov[2];

	RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_WRITE,"xx",v_ifc,pkt);

  RHP_LOCK(&(v_ifc->lock));

	RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_WRITE_PARAMS,"xsLdxLddM",v_ifc,v_ifc->if_name,"VIF_TYPE",v_ifc->tuntap_type,pkt,"PKT",pkt->type,v_ifc->is_dmy_tuntap,v_ifc->mac);
	rhp_pkt_trace_dump("rhp_tuntap_write",pkt);


  if( !_rhp_atomic_read(&(v_ifc->is_active)) || v_ifc->tuntap_fd < -1 ){
  	err = 0;
  	RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_WRITE_NOT_ACTIVE,"xx",v_ifc,pkt);
  	goto error;
  }

  if( pkt->l2.raw == NULL ){
  	RHP_BUG("%s",v_ifc->if_name);
  	err = -EINVAL;
  	goto error;
  }

  RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_WRITE_PKT,"xsa",v_ifc,v_ifc->if_name,pkt->len,RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,pkt->l2.raw);

  if( v_ifc->is_dmy_tuntap ){
  	memcpy(pkt->l2.eth->src_addr,v_ifc->tuntap_dmy_peer_mac,6);
  	memcpy(pkt->l2.eth->dst_addr,v_ifc->mac,6);
  }

	if( pkt->l2.eth->protocol == RHP_PROTO_ETH_IPV6 &&
			_rhp_tuntap_write_check_ipv6_nd(v_ifc,pkt->l2.eth,pkt->end) ){

		RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_WRITE_IPV6_ND_CHECK,"xx",v_ifc,pkt);

		v_ifc->statistics.tuntap.drop_icmpv6_router_adv++;
		err = 0;
  	goto error;
  }

	pi.proto = pkt->l2.eth->protocol;

	iov[0].iov_len = sizeof(pi);
	iov[0].iov_base = &pi;

  if( pkt->type == RHP_PKT_PLAIN_ETHER_TAP ){

  	if( v_ifc->tuntap_type != RHP_VIF_TYPE_ETHER_TAP ){
    	RHP_BUG("%s",v_ifc->if_name);
    	err = -EINVAL;
    	goto error;
  	}

  }else if( pkt->type == RHP_PKT_PLAIN_IPV4_TUNNEL ){
/*
  	if( v_ifc->tuntap_type != RHP_VIF_TYPE_IP_TUNNEL ){
    	RHP_BUG("%s",v_ifc->if_name);
    	err = -EINVAL;
    	goto error;
  	}
*/
  	RHP_BUG("%s:%d",v_ifc->if_name,pkt->type);
  	err = -EINVAL;
  	goto error;

  }else{
  	RHP_BUG("%s:%d",v_ifc->if_name,pkt->type);
  	err = -EINVAL;
  	goto error;
  }

	iov[1].iov_len = pkt->len;
	iov[1].iov_base = pkt->l2.raw;

	RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_WRITE_EXEC,"xp",v_ifc,iov[1].iov_len,iov[1].iov_base);

	if( rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_VIF] &&
			(!rhp_packet_capture_realm_id || !rhp_packet_capture_realm_id == v_ifc->tuntap_vpn_realm_id) ){

		_rhp_tuntap_pcap_write(pkt);
	}


  mesg_len = writev(v_ifc->tuntap_fd,iov,2);
  if( mesg_len < 0 ){
    err = -errno;
    RHP_BUG("%s : %d",v_ifc->if_name,err);
    goto error;
  }

	_rhp_tuntap_write_statistics(v_ifc,pkt,mesg_len);

	RHP_UNLOCK(&(v_ifc->lock));

	RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_WRITE_RTRN,"xxd",v_ifc,pkt,mesg_len);
	return 0;

error:
	if( err ){
		_rhp_tuntap_write_statistics_err(v_ifc,pkt);
	}
	RHP_UNLOCK(&(v_ifc->lock));

	RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_WRITE_ERR,"xxE",v_ifc,pkt,err);
	return err;
}

int rhp_tuntap_handle_event(struct epoll_event* epoll_evt)
{
  int err = 0;
  rhp_epoll_ctx* epoll_ctx = (rhp_epoll_ctx*)epoll_evt->data.ptr;
  rhp_ifc_entry* v_ifc = (rhp_ifc_entry*)RHP_TUNTAP_EPOLL_IFC(epoll_ctx);

	RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_HANDLE_EVENT,"xxx",epoll_evt,epoll_ctx,v_ifc);

  if( v_ifc == NULL ){
    err = -ENODEV;
    RHP_BUG("");
    goto error;
  }


  RHP_LOCK(&(v_ifc->lock));

	RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_HANDLE_EVENT_VIFC,"xxxuLdd",epoll_evt,epoll_ctx,v_ifc,v_ifc->tuntap_vpn_realm_id,"VIF_TYPE",v_ifc->tuntap_type,v_ifc->tuntap_fd);
	v_ifc->dump_no_lock("rhp_tuntap_handle_event",v_ifc);

  if( !_rhp_atomic_read(&(v_ifc->is_active)) ){
    err = -ENODEV;
  	RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_HANDLE_EVENT_VIFC_NOT_ACTIVE,"xxx",epoll_evt,epoll_ctx,v_ifc);
    goto error_l;
  }

  if( v_ifc->tuntap_fd < 0 ){
    err = -ENODEV;
    RHP_BUG("");
    goto error_l;
  }

  if( epoll_evt->events & EPOLLERR ){
  	// TODO : Write Log...
  	RHP_BUG("");
  }

  err = _rhp_tuntap_read(v_ifc);

error_l:
  RHP_UNLOCK(&(v_ifc->lock));

error:
	RHP_TRC_FREQ(0,RHPTRCID_TUNTAP_HANDLE_EVENT_RTRN,"xxxE",epoll_evt,epoll_ctx,v_ifc,err);
	return err;
}



