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
#include <sys/resource.h>

#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_wthreads.h"
#include "rhp_timer.h"
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_packet.h"
#include "rhp_netsock.h"
#include "rhp_config.h"
#include "rhp_crypto.h"
#include "rhp_http.h"
#include "rhp_vpn.h"
#include "rhp_tuntap.h"

extern rhp_mutex_t rhp_cfg_lock;
extern rhp_vpn_realm* rhp_realm_list_head;

int rhp_main_netmng_ipc_start()
{
  int err = 0;
  rhp_ipcmsg_nm_request* ipcmsg;

  RHP_TRC(0,RHPTRCID_MAIN_NETMNG_START,"");

  ipcmsg = (rhp_ipcmsg_nm_request*)rhp_ipc_alloc_msg(RHP_IPC_NETMNG_REGISTER,sizeof(rhp_ipcmsg_nm_request));

  if( ipcmsg == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  ipcmsg->len = sizeof(rhp_ipcmsg_nm_request);

  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipcmsg,ipcmsg->len,0) < 0 ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

error:
  if( ipcmsg ){
    _rhp_free_zero(ipcmsg,ipcmsg->len);
  }

  RHP_TRC(0,RHPTRCID_MAIN_NETMNG_START_RTRN,"xE",ipcmsg,err);
  return err;
}

int rhp_main_ipc_handle(rhp_ipcmsg *ipcmsg)
{
  int ret = 0;
  rhp_ifc_entry *ifc;
  rhp_rtmapc_entry* rtmapc;

  RHP_TRC(0,RHPTRCID_MAIN_NETMNG_HANDLE_IPC,"xLu",ipcmsg,"IPC",ipcmsg->type);

  switch( ipcmsg->type ){

    case RHP_IPC_NETMNG_UPDATE_IF:
    case RHP_IPC_NETMNG_UPDATE_ADDR:
    case RHP_IPC_NETMNG_DELETE_ADDR:
    {
  		rhp_ipcmsg_nm_update_if* update_if_msg = (rhp_ipcmsg_nm_update_if*)ipcmsg;
  		rhp_if_entry ifc_old, ifc_new;
      int event = 0;

      memset(&ifc_old,0,sizeof(rhp_if_entry));
      memset(&ifc_new,0,sizeof(rhp_if_entry));

      switch( ipcmsg->type ){
      case RHP_IPC_NETMNG_UPDATE_IF:
        event = RHP_IFC_EVT_UPDATE_IF;
        break;
      case RHP_IPC_NETMNG_UPDATE_ADDR:
        event = RHP_IFC_EVT_UPDATE_ADDR;
        break;
      case RHP_IPC_NETMNG_DELETE_ADDR:
        event = RHP_IFC_EVT_DELETE_ADDR;
        break;
      }

      ifc = rhp_ifc_get(update_if_msg->info.if_name);
      if( ifc == NULL ){

        if( ipcmsg->type == RHP_IPC_NETMNG_UPDATE_IF ){

					ifc = rhp_ifc_alloc();
					if( ifc == NULL ){
						RHP_BUG("");
						goto error;
					}

					if( rhp_ifc_copy_if_info(&(update_if_msg->info),ifc) ){
						RHP_BUG("");
						goto error;
					}

					_rhp_atomic_set(&(ifc->is_active),1);
					rhp_ifc_put(ifc); // ifc->refcnt : 0 ==> 1


					rhp_ifc_hold(ifc);

					rhp_ifc_call_notifiers(event,ifc,NULL,NULL);

					rhp_ifc_unhold(ifc);
        }

      }else{ // ifc != NULL

    		rhp_ifc_addr* ifc_addr;
    		int nop = 0;

      	RHP_LOCK(&(ifc->lock));

      	if( rhp_ifc_copy_if_info2(ifc,&ifc_old) ){
      		RHP_BUG("");
         	RHP_UNLOCK(&(ifc->lock));
         	goto error;
      	}

      	if( rhp_ifc_copy_if_info2(ifc,&ifc_new) ){
      		RHP_BUG("");
         	RHP_UNLOCK(&(ifc->lock));
         	goto error;
      	}

      	if( ipcmsg->type == RHP_IPC_NETMNG_UPDATE_ADDR ){

      		rhp_ipcmsg_nm_update_addr* update_msg = (rhp_ipcmsg_nm_update_addr*)ipcmsg;

      		ifc_addr = ifc->get_addr(ifc,update_msg->info.addr_family,update_msg->info.addr.raw);
      		if( ifc_addr ){

      			ifc_old.addr_family = ifc_addr->addr.addr_family;
          	memcpy(ifc_old.addr.raw,ifc_addr->addr.addr.raw,16);
          	ifc_old.prefixlen = ifc_addr->addr.prefixlen;
          	ifc_old.if_addr_flags = ifc_addr->if_addr_flags;

      		}else{

      			ifc_addr = ifc->set_addr(ifc,update_msg->info.addr_family,update_msg->info.addr.raw,
      																update_msg->info.prefixlen,ifc->if_index);
      			if( ifc_addr == NULL ){
      				RHP_BUG("");
             	RHP_UNLOCK(&(ifc->lock));
      				goto error;
      			}

      			ifc_old.addr_family = AF_UNSPEC;
						memset(ifc_old.addr.raw,0,16);
						ifc_old.prefixlen = 0;
						ifc_old.if_addr_flags = 0;
      		}

      		ifc_addr->if_addr_flags = update_msg->info.if_addr_flags;

      		ifc_new.addr_family = update_msg->info.addr_family;
        	memcpy(ifc_new.addr.raw,update_msg->info.addr.raw,16);
        	ifc_new.prefixlen = update_msg->info.prefixlen;
        	ifc_new.if_addr_flags = update_msg->info.if_addr_flags;

      	}else	if( ipcmsg->type == RHP_IPC_NETMNG_DELETE_ADDR ){

      		rhp_ipcmsg_nm_delete_addr* del_msg = (rhp_ipcmsg_nm_delete_addr*)ipcmsg;

      		ifc_addr = ifc->get_addr(ifc,del_msg->info.addr_family,del_msg->info.addr.raw);
      		if( ifc_addr ){

						ifc_old.addr_family = del_msg->info.addr_family;
						memcpy(ifc_old.addr.raw,del_msg->info.addr.raw,16);
						ifc_old.prefixlen = del_msg->info.prefixlen;
						ifc_old.if_addr_flags = del_msg->info.if_addr_flags;

						ifc_new.addr_family = AF_UNSPEC;
						memset(ifc_new.addr.raw,0,16);
						ifc_new.prefixlen = 0;
						ifc_new.if_addr_flags = del_msg->info.if_addr_flags;

      		}else{

      			nop = 1;
      		}

      	}else	if( ipcmsg->type == RHP_IPC_NETMNG_UPDATE_IF ){

      		ifc->if_index = update_if_msg->info.if_index;
      		ifc->if_flags = update_if_msg->info.if_flags;
      		ifc->mtu = update_if_msg->info.mtu;
        }

      	ifc->dump_no_lock("MAIN_NETMNG_XXX",ifc);

      	RHP_UNLOCK(&(ifc->lock));


      	if( !nop ){

      		if( event != RHP_IFC_EVT_UPDATE_ADDR ||
      				rhp_if_entry_cmp(&ifc_old,&ifc_new) ){

      			rhp_ifc_call_notifiers(event,ifc,&ifc_new,&ifc_old);

      		}else{

        	  RHP_TRC_FREQ(0,RHPTRCID_MAIN_NETMNG_HANDLE_IPC_NETMNG_UPDATE_ADDR_IGNORED,"xLus",ipcmsg,"IPC",ipcmsg->type,ifc_old.if_name);
      		}

					if( ipcmsg->type == RHP_IPC_NETMNG_UPDATE_ADDR ){

						rhp_ifc_my_ip_update(&ifc_old,&ifc_new);

					}else	if( ipcmsg->type == RHP_IPC_NETMNG_DELETE_ADDR ){

						ifc->delete_addr(ifc,ifc_old.addr_family,ifc_old.addr.raw);

						rhp_ifc_my_ip_clear(&ifc_old);
					}
      	}

      	rhp_ifc_unhold(ifc); // For rhp_ifc_get()
      }
    }
    break;

    case RHP_IPC_NETMNG_DELETE_IF:
    {
      rhp_ipcmsg_nm_delete_if *dellink_msg = (rhp_ipcmsg_nm_delete_if*)ipcmsg;

      ifc = rhp_ifc_get(dellink_msg->if_name);
      if( ifc ){

        ifc->dump_lock("MAIN_NETMNG_DELETED_IFC",ifc);

        rhp_ifc_call_notifiers(RHP_IFC_EVT_DELETE_IF,ifc,NULL,NULL);
        rhp_ifc_unhold(ifc);

        _rhp_atomic_set(&(ifc->is_active),0);
        rhp_ifc_delete(ifc); // ifc->refcnt : ==> 0 . Don't access ifc anymore!
      }
    }
    break;

		case RHP_IPC_NETMNG_ROUTEMAP_UPDATED:
    {
    	rhp_ipcmsg_nm_route_map_updated *updrtmap_msg = (rhp_ipcmsg_nm_route_map_updated*)ipcmsg;
    	rhp_rt_map_entry rtmapc_old;

    	rhp_rtmap_entry_dump("IPC_NETMNG_ROUTEMAP_UPDATED",&(updrtmap_msg->info));

    	if( (updrtmap_msg->info.addr_family != AF_INET && updrtmap_msg->info.addr_family != AF_INET6) ||
    			(rhp_ip_addr_null(&(updrtmap_msg->info.gateway_addr)) && updrtmap_msg->info.oif_name[0] == '\0') ){

    		RHP_TRC_FREQ(0,RHPTRCID_MAIN_NETMNG_HANDLE_IPC_RTMAP_UPDATED_IGNORED_1,"xLu",ipcmsg,"IPC",ipcmsg->type);

    	}else{

				rtmapc = rhp_rtmapc_get(&(updrtmap_msg->info));
				if( rtmapc == NULL ){

					rtmapc = rhp_rtmapc_alloc();
					if( rtmapc == NULL ){
						RHP_BUG("");
						goto error;
					}

					memcpy(&(rtmapc->info),&(updrtmap_msg->info),sizeof(rhp_rt_map_entry));

					_rhp_atomic_set(&(rtmapc->is_active),1);

					rhp_rtmapc_hold(rtmapc); // (xx)
					rhp_rtmapc_put(rtmapc); // rtmapc->refcnt : 0 ==> 1

					rtmapc->dump("MAIN_NETMNG_NEW_RTMAPC",rtmapc);

					rhp_rtmapc_call_notifiers(RHP_RTMAPC_EVT_UPDATED,rtmapc,NULL);

					rhp_rtmapc_unhold(rtmapc); // (xx)

				}else{

					RHP_LOCK(&(rtmapc->lock));

					memcpy(&rtmapc_old,&(rtmapc->info),sizeof(rhp_rt_map_entry));
					memcpy(&(rtmapc->info),&(updrtmap_msg->info),sizeof(rhp_rt_map_entry));

					RHP_UNLOCK(&(rtmapc->lock));

					rtmapc->dump("MAIN_NETMNG_UPD_RTMAPC",rtmapc);

					if( rhp_rtmap_entry_cmp(&(rtmapc->info),&rtmapc_old) ){

						rhp_rtmapc_call_notifiers(RHP_RTMAPC_EVT_UPDATED,rtmapc,&rtmapc_old);

					}else{

						RHP_TRC_FREQ(0,RHPTRCID_MAIN_NETMNG_HANDLE_IPC_RTMAP_UPDATED_IGNORED_2,"xLu",ipcmsg,"IPC",ipcmsg->type);
					}

					rhp_rtmapc_unhold(rtmapc); // For rhp_rtmapc_get()
				}
    	}
    }
	    break;

		case RHP_IPC_NETMNG_ROUTEMAP_DELETED:
    {
    	rhp_ipcmsg_nm_route_map_deleted *delrtmap_msg = (rhp_ipcmsg_nm_route_map_deleted*)ipcmsg;

      rtmapc = rhp_rtmapc_get(&(delrtmap_msg->info));
      if( rtmapc ){

        rtmapc->dump("MAIN_NETMNG_DELETED_RTMAPC",rtmapc);

        rhp_rtmapc_call_notifiers(RHP_RTMAPC_EVT_DELETED,rtmapc,NULL);
        rhp_rtmapc_unhold(rtmapc);

        _rhp_atomic_set(&(rtmapc->is_active),0);
        rhp_rtmapc_delete(rtmapc); // rtmapc->refcnt : ==> 0 . Don't access rtmapc anymore!

      }else{

      	rhp_rtmap_entry_dump("IPC_NETMNG_ROUTEMAP_DELETED: NOENT",&(delrtmap_msg->info));
      }
    }
	    break;

    default:
      RHP_BUG("%d",ipcmsg->type);
      goto error;
  }

error:
  if( ipcmsg ){
    _rhp_free_zero(ipcmsg,ipcmsg->len);
  }

  RHP_TRC(0,RHPTRCID_MAIN_NETMNG_HANDLE_IPC_RECVMSG_RTRN_MAIN,"xd",ipcmsg,ret);
  return ret;
}

int rhp_ipc_send_create_vif_raw(unsigned long rlm_id,char* vif_name,
			rhp_cfg_internal_if* vif_info,int exec_up,int v6_disable,int v6_autoconf)
{
	int err = -EINVAL;
  rhp_ipcmsg_vif_create* ipcmsg = NULL;

	RHP_TRC(0,RHPTRCID_CFG_IPC_SEND_CREATE_VIF_RAW_RAW,"usxddd",rlm_id,vif_name,vif_info,exec_up,v6_disable,v6_autoconf);

  ipcmsg = (rhp_ipcmsg_vif_create*)rhp_ipc_alloc_msg(RHP_IPC_NETMNG_VIF_CREATE,sizeof(rhp_ipcmsg_vif_create));
  if( ipcmsg == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  ipcmsg->len = sizeof(rhp_ipcmsg_vif_create);
  ipcmsg->interface_type = RHP_VIF_TYPE_ETHER_TAP;

  ipcmsg->vpn_realm_id = rlm_id;
  strcpy(ipcmsg->info_v4.if_name,vif_name);
  strcpy(ipcmsg->info_v6.if_name,vif_name);
  ipcmsg->exec_up_down = exec_up;
  ipcmsg->v6_disable = v6_disable;
	ipcmsg->v6_autoconf = v6_autoconf;

  if( vif_info ){

  	if( vif_info->fixed_mtu ){
  		ipcmsg->info_v4.mtu = vif_info->fixed_mtu;
  		ipcmsg->info_v6.mtu = vif_info->fixed_mtu;
  	}

		if( vif_info->addrs_type == RHP_VIF_ADDR_STATIC ){

	  	rhp_ip_addr_list *addr_lst, *addr_v4 = NULL,*addr_v6 = NULL;

	  	addr_lst = vif_info->addrs;
	  	while( addr_lst ){
	  		if( addr_lst->ip_addr.addr_family == AF_INET ){
	  			addr_v4 = addr_lst;
	  		}else if( addr_lst->ip_addr.addr_family == AF_INET6 ){
	  			addr_v6 = addr_lst;
	  		}
	  		addr_lst = addr_lst->next;
	  	}


			if( addr_v4 ){

				ipcmsg->info_v4.addr_family = addr_v4->ip_addr.addr_family;
				ipcmsg->info_v4.addr.v4 = addr_v4->ip_addr.addr.v4;
				ipcmsg->info_v4.prefixlen = addr_v4->ip_addr.prefixlen;
			}

			if( addr_v6 ){

				ipcmsg->info_v6.addr_family = addr_v6->ip_addr.addr_family;
				memcpy(ipcmsg->info_v6.addr.v6,addr_v6->ip_addr.addr.v6,16);
				ipcmsg->info_v6.prefixlen = addr_v6->ip_addr.prefixlen;
			}

		}else{

			ipcmsg->exec_up_down = 1;
		}
  }

  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipcmsg,ipcmsg->len,0) < 0 ){
    err = -EINVAL;
    RHP_BUG("%d",rlm_id);
    goto error;
  }


  err = 0;

error:
	if( ipcmsg ){
		_rhp_free_zero(ipcmsg,ipcmsg->len);
	}

	RHP_TRC(0,RHPTRCID_CFG_IPC_SEND_CREATE_VIF_RAW_RTRN,"us",rlm_id,vif_name);
  return err;
}

int rhp_ipc_send_create_vif(rhp_vpn_realm* rlm)
{
	int err;
	int v6_autoconf = RHP_IPC_VIF_V6_AUTOCONF_DISABLE, v6_disable = rhp_gcfg_ipv6_disabled;
	RHP_TRC(0,RHPTRCID_CFG_IPC_SEND_CREATE_VIF,"xus",rlm,rlm->id,rlm->internal_ifc->if_name);

	if( !rhp_gcfg_ipv6_disabled ){

		if( rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_STATIC ){

			v6_autoconf = RHP_IPC_VIF_V6_AUTOCONF_DISABLE;

		}else if( rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_NONE ){

			v6_disable = 1;
			v6_autoconf = RHP_IPC_VIF_V6_AUTOCONF_DISABLE;

		}else if( rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_IKEV2CFG ){
/*
			if( rlm->internal_ifc->ikev2_config_ipv6_auto ){
				v6_autoconf = RHP_IPC_VIF_V6_AUTOCONF_ENABLE_ADDR;
			}else{
*/
				v6_autoconf = RHP_IPC_VIF_V6_AUTOCONF_DISABLE;
/*
			}
*/
		}

	}else{

		v6_autoconf = RHP_IPC_VIF_V6_AUTOCONF_DISABLE;
	}

	err = rhp_ipc_send_create_vif_raw(rlm->id,rlm->internal_ifc->if_name,
					rlm->internal_ifc,1,v6_disable,v6_autoconf);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

error:
	RHP_TRC(0,RHPTRCID_CFG_IPC_SEND_CREATE_VIF_RTRN,"xuE",rlm,rlm->id,err);
  return err;
}


int rhp_ipc_send_vif_exec_ipv6_autoconf(unsigned long rlm_id,char* vif_name)
{
	int err = -EINVAL;
	rhp_ipcmsg_vif_update* ipcmsg = NULL;

	RHP_TRC(0,RHPTRCID_CFG_IPC_SEND_VIF_EXEC_IPV6_AUTOCONF,"us",rlm_id,vif_name);

  ipcmsg = (rhp_ipcmsg_vif_update*)rhp_ipc_alloc_msg(RHP_IPC_NETMNG_VIF_EXEC_IPV6_AUTOCONF,
  					sizeof(rhp_ipcmsg_vif_update));
  if( ipcmsg == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  ipcmsg->len = sizeof(rhp_ipcmsg_vif_update);
  ipcmsg->interface_type = RHP_VIF_TYPE_ETHER_TAP;

  ipcmsg->vpn_realm_id = rlm_id;

  strcpy(ipcmsg->if_info.if_name,vif_name);

  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipcmsg,ipcmsg->len,0) < 0 ){
    err = -EINVAL;
    RHP_BUG("%d",rlm_id);
    goto error;
  }

  err = 0;

error:
	if( ipcmsg ){
		_rhp_free_zero(ipcmsg,ipcmsg->len);
	}

	RHP_TRC(0,RHPTRCID_CFG_IPC_SEND_VIF_EXEC_IPV6_AUTOCONF_RTRN,"usE",rlm_id,vif_name,err);
  return err;
}

int rhp_ipc_send_update_vif_raw(unsigned long rlm_id,char* vif_name,
		unsigned int updated_flag,rhp_if_entry* if_info)
{
	int err = -EINVAL;
	rhp_ipcmsg_vif_update* ipcmsg = NULL;

	RHP_TRC(0,RHPTRCID_CFG_IPC_SEND_UPDATE_VIF_RAW_RAW,"usxx",rlm_id,vif_name,updated_flag,if_info);

  ipcmsg = (rhp_ipcmsg_vif_update*)rhp_ipc_alloc_msg(RHP_IPC_NETMNG_VIF_UPDATE,
  					sizeof(rhp_ipcmsg_vif_update));
  if( ipcmsg == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  ipcmsg->len = sizeof(rhp_ipcmsg_vif_update);
  ipcmsg->interface_type = RHP_VIF_TYPE_ETHER_TAP;

  ipcmsg->vpn_realm_id = rlm_id;


  {
  	strcpy(ipcmsg->if_info.if_name,vif_name);

  	ipcmsg->updated_flag = updated_flag;

  	if( updated_flag & RHP_IPC_VIF_UPDATE_MTU ){
  		ipcmsg->if_info.mtu = if_info->mtu;
  	}

  	if( (updated_flag & RHP_IPC_VIF_UPDATE_ADDR) ||
  			(updated_flag & RHP_IPC_VIF_DELETE_ADDR) ){

			ipcmsg->if_info.addr_family = if_info->addr_family;

			if( if_info->addr_family == AF_INET ){

				ipcmsg->if_info.addr.v4 = if_info->addr.v4;
				ipcmsg->if_info.prefixlen = if_info->prefixlen;

			}else	if( if_info->addr_family == AF_INET6 ){

				memcpy(ipcmsg->if_info.addr.v6,if_info->addr.v6,16);
				ipcmsg->if_info.prefixlen = if_info->prefixlen;

			}else{
				RHP_BUG("%d",if_info->addr_family);
				err = -EINVAL;
				goto error;
			}
  	}
  }

  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipcmsg,ipcmsg->len,0) < 0 ){
    err = -EINVAL;
    RHP_BUG("%d",rlm_id);
    goto error;
  }

  err = 0;

error:
	if( ipcmsg ){
		_rhp_free_zero(ipcmsg,ipcmsg->len);
	}

	RHP_TRC(0,RHPTRCID_CFG_IPC_SEND_UPDATE_VIF_RAW_RAW_RTRN,"usE",rlm_id,vif_name,err);
  return err;
}

int rhp_ipc_send_delete_vif_raw(unsigned long rlm_id,char* vif_name)
{
	int err = -EINVAL;
	rhp_ipcmsg_vif_delete* ipcmsg = NULL;

	RHP_TRC(0,RHPTRCID_CFG_IPC_DELETE_VIF_RAW,"us",rlm_id,vif_name);

	ipcmsg = (rhp_ipcmsg_vif_delete*)rhp_ipc_alloc_msg(RHP_IPC_NETMNG_VIF_DELETE,
					 sizeof(rhp_ipcmsg_vif_delete));

	if( ipcmsg == NULL ){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}

	ipcmsg->len = sizeof(rhp_ipcmsg_vif_delete);
  ipcmsg->interface_type = RHP_VIF_TYPE_ETHER_TAP;

  ipcmsg->vpn_realm_id = rlm_id;
	strcpy(ipcmsg->if_name,vif_name);

	if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipcmsg,ipcmsg->len,0) < 0 ){
		err = -EINVAL;
		RHP_BUG("%d",rlm_id);
	}

  err = 0;

error:
	if( ipcmsg ){
		_rhp_free_zero(ipcmsg,ipcmsg->len);
	}

	RHP_TRC(0,RHPTRCID_CFG_IPC_DELETE_VIF_RAW_RTRN,"us",rlm_id,vif_name);
  return err;
}

int rhp_ipc_send_delete_vif(rhp_vpn_realm* rlm)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_CFG_IPC_SEND_DELETE_VIF,"xus",rlm,rlm->id,rlm->internal_ifc->if_name);

	err = rhp_ipc_send_delete_vif_raw(rlm->id,rlm->internal_ifc->if_name);

	if( !err ){

		if( rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_NONE &&
				rlm->internal_ifc->bridge_name ){

			err = rhp_ipc_send_bridge_ctrl(rlm->internal_ifc->bridge_name,rlm->internal_ifc->if_name,0);
		}
	}

	RHP_TRC(0,RHPTRCID_CFG_IPC_SEND_DELETE_VIF_RTRN,"xu",rlm,rlm->id);
  return err;
}

int rhp_ipc_send_update_route(rhp_vpn_realm* rlm,rhp_route_map* rtmap,rhp_ip_addr* gateway_addr)
{
	int err = -EINVAL;
	rhp_ipcmsg_nm_route_update* ipcmsg = NULL;

	RHP_TRC(0,RHPTRCID_CFG_IPC_SEND_UPDATE__ROUTE,"xuxusx",rlm,rlm->id,rtmap,rtmap->metric,rtmap->tx_interface,gateway_addr);
  rhp_ip_addr_dump("rhp_ipc_send_update_route.gateway_addr",gateway_addr);
	rhp_ip_addr_dump("rhp_ipc_send_update_route.rtmap->dest_addr",&(rtmap->dest_addr));
	rhp_ip_addr_dump("rhp_ipc_send_update_route.rtmap->gateway_addr",&(rtmap->gateway_addr));
	rhp_ip_addr_dump("rhp_ipc_send_update_route.rtmap->dest_addr",&(rtmap->dest_addr));
	rhp_ikev2_id_dump("rhp_ipc_send_update_route.rtmap->gateway_peer_id",&(rtmap->gateway_peer_id));

	if( gateway_addr == NULL || rhp_ip_addr_null(gateway_addr) ){
		gateway_addr = &(rtmap->gateway_addr);
	}

  ipcmsg = (rhp_ipcmsg_nm_route_update*)rhp_ipc_alloc_msg(RHP_IPC_NETMNG_ROUTE_UPDATE,
  					sizeof(rhp_ipcmsg_nm_route_update));
  if( ipcmsg == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  ipcmsg->len = sizeof(rhp_ipcmsg_nm_route_update);

  ipcmsg->vpn_realm_id = rlm->id;

	memcpy(&(ipcmsg->dest_addr),&(rtmap->dest_addr),sizeof(rhp_ip_addr));

  if( !rhp_ip_addr_null(gateway_addr) ){

  	memcpy(&(ipcmsg->nexthop_addr),gateway_addr,sizeof(rhp_ip_addr));

  }else if( rtmap->tx_interface && (rtmap->tx_interface[0] != '\0' ) ){

  	ipcmsg->if_name[0] = '\0';
  	strcpy(ipcmsg->if_name,rtmap->tx_interface);

  }else{
  	RHP_BUG("");
  }

  if( rtmap->metric ){
  	ipcmsg->metric = rtmap->metric;
  }

  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipcmsg,ipcmsg->len,0) < 0 ){
    err = -EINVAL;
    RHP_BUG("%d",rlm->id);
    goto error;
  }

  err = 0;

error:
	if( ipcmsg ){
		_rhp_free_zero(ipcmsg,ipcmsg->len);
	}

	RHP_TRC(0,RHPTRCID_CFG_IPC_SEND_UPDATE__ROUTE_RTRN,"xuxE",rlm,rlm->id,rtmap,err);
  return err;
}

int rhp_ipc_send_delete_route(rhp_vpn_realm* rlm,rhp_route_map* rtmap,rhp_ip_addr* gateway_addr)
{
	int err = -EINVAL;
	rhp_ipcmsg_nm_route_delete* ipcmsg = NULL;

	RHP_TRC(0,RHPTRCID_CFG_IPC_SEND_DELETE__ROUTE,"xuxusx",rlm,rlm->id,rtmap,rtmap->metric,rtmap->tx_interface,gateway_addr);
  rhp_ip_addr_dump("rhp_ipc_send_delete_route.gateway_addr",gateway_addr);
	rhp_ip_addr_dump("rhp_ipc_send_delete_route.rtmap->dest_addr",&(rtmap->dest_addr));
	rhp_ip_addr_dump("rhp_ipc_send_delete_route.rtmap->gateway_addr",&(rtmap->gateway_addr));
	rhp_ip_addr_dump("rhp_ipc_send_delete_route.rtmap->dest_addr",&(rtmap->dest_addr));
	rhp_ikev2_id_dump("rhp_ipc_send_delete_route.rtmap->gateway_peer_id",&(rtmap->gateway_peer_id));

	if( gateway_addr == NULL || rhp_ip_addr_null(gateway_addr) ){
		gateway_addr = &(rtmap->gateway_addr);
	}

  ipcmsg = (rhp_ipcmsg_nm_route_delete*)rhp_ipc_alloc_msg(RHP_IPC_NETMNG_ROUTE_DELETE,
           sizeof(rhp_ipcmsg_nm_route_delete));

  if( ipcmsg == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  ipcmsg->len = sizeof(rhp_ipcmsg_nm_route_delete);

  ipcmsg->vpn_realm_id = rlm->id;

	memcpy(&(ipcmsg->dest_addr),&(rtmap->dest_addr),sizeof(rhp_ip_addr));

  if( !rhp_ip_addr_null(gateway_addr) ){

  	memcpy(&(ipcmsg->nexthop_addr),gateway_addr,sizeof(rhp_ip_addr));

  }else if( rtmap->tx_interface && (rtmap->tx_interface[0] != '\0') ){

  	ipcmsg->if_name[0] = '\0';
  	strcpy(ipcmsg->if_name,rtmap->tx_interface);

  }else{
  	RHP_BUG("");
  }

  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipcmsg,ipcmsg->len,0) < 0 ){
    err = -EINVAL;
    RHP_BUG("%d",rlm->id);
    goto error;
  }

  err = 0;

error:
	if( ipcmsg ){
		_rhp_free_zero(ipcmsg,ipcmsg->len);
	}

	RHP_TRC(0,RHPTRCID_CFG_IPC_SEND_DELETE__ROUTE_RTRN,"xuxE",rlm,rlm->id,rtmap,err);
  return err;
}

int rhp_ipc_send_update_all_static_routes(rhp_vpn_realm* rlm)
{
	int err = -EINVAL;
	rhp_route_map* rtmap = rlm->route_maps;

  RHP_TRC(0,RHPTRCID_CFG_IPC_SEND_UPDATE_ALL_STATIC_ROUTES,"xu",rlm,rlm->id);

	while( rtmap ){

		if( !rtmap->ikev2_cfg &&
				(rtmap->tx_interface || !rhp_ip_addr_null(&(rtmap->gateway_addr))) ){

			err = rhp_ipc_send_update_route(rlm,rtmap,NULL);
			if( err ){
				RHP_BUG("%d",err);
			}
		}

		rtmap = rtmap->next;
	}

	return 0;
}

int rhp_ipc_send_delete_all_static_routes(rhp_vpn_realm* rlm)
{
	int err = -EINVAL;
	rhp_route_map* rtmap = rlm->route_maps;

  RHP_TRC(0,RHPTRCID_CFG_IPC_SEND_DELETE_ALL_STATIC_ROUTES,"xu",rlm,rlm->id);

	while( rtmap ){

		if( !rtmap->ikev2_cfg &&
				(rtmap->tx_interface || !rhp_ip_addr_null(&(rtmap->gateway_addr))) ){

			err = rhp_ipc_send_delete_route(rlm,rtmap,NULL);
			if( err ){
				RHP_BUG("%d",err);
			}
		}

		rtmap = rtmap->next;
	}

	return 0;
}

int rhp_ipc_send_my_id_resolve_req(unsigned long rlm_id)
{
	int err = -EINVAL;
  rhp_ipcmsg_resolve_my_id_req* ipcmsg = NULL;

  RHP_TRC(0,RHPTRCID_CFG_IPC_SEND_MY_ID_RESOLVE_REQ,"u",rlm_id);

  ipcmsg = (rhp_ipcmsg_resolve_my_id_req*)rhp_ipc_alloc_msg(RHP_IPC_RESOLVE_MY_ID_REQUEST,
           sizeof(rhp_ipcmsg_resolve_my_id_req));

  if( ipcmsg == NULL ){
    err = -ENOMEM;
    RHP_BUG("%d",rlm_id);
    goto error;
  }

  ipcmsg->len = sizeof(rhp_ipcmsg_resolve_my_id_req);
  ipcmsg->txn_id = 0;
  ipcmsg->my_realm_id = rlm_id;

  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipcmsg,ipcmsg->len,0) < 0 ){
    err = -EINVAL;
    RHP_BUG("%d",rlm_id);
    goto error;
  }

  _rhp_free_zero(ipcmsg,ipcmsg->len);

	RHP_TRC(0,RHPTRCID_CFG_IPC_SEND_MY_ID_RESOLVE_REQ_RTRN,"u",rlm_id);
  return 0;

error:
	if( ipcmsg ){
		_rhp_free_zero(ipcmsg,ipcmsg->len);
	}

	RHP_TRC(0,RHPTRCID_CFG_IPC_SEND_MY_ID_RESOLVE_REQ_ERR,"uE",rlm_id,err);
	return err;
}

int rhp_ipc_send_my_ids_resolve_req()
{
  int err = 0;
  rhp_vpn_realm* rlm;

  RHP_TRC(0,RHPTRCID_IPC_SEND_MY_IDS_RESOLVE_REQ,"");

  RHP_LOCK(&rhp_cfg_lock);

  rlm = rhp_realm_list_head;

  while( rlm ){

  	err = rhp_ipc_send_my_id_resolve_req(rlm->id); // rlm->id is immutable. rlm->lock is NOT acquired here.
  	if( err ){
  		RHP_BUG("%d",err);
  		goto error_l;
  	}

    RHP_TRC(0,RHPTRCID_IPC_SEND_MY_IDS_RESOLVE_REQ_TX_RLM,"d",rlm->id);

    rlm = rlm->next;
  }

error_l:
  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_IPC_SEND_MY_IDS_RESOLVE_REQ_RTRN,"d",err);
  return err;
}

int rhp_ipc_send_bridge_ctrl(char* bridge_name,char* vif_name,int add_or_delete)
{
	int err = -EINVAL;
	rhp_ipcmsg_netmng_bridge_ctrl brctl;

	RHP_TRC(0,RHPTRCID_IPC_SEND_BRIDGE_CTRL,"ssd",bridge_name,vif_name,add_or_delete);

	if( strlen(bridge_name) + 1 > RHP_IFNAMSIZ ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( strlen(vif_name) + 1 > RHP_IFNAMSIZ ){
		RHP_BUG("");
		return -EINVAL;
	}

	brctl.tag[0] = '#';
	brctl.tag[1] = 'I';
	brctl.tag[2] = 'M';
	brctl.tag[3] = 'S';

	brctl.len = sizeof(rhp_ipcmsg_netmng_bridge_ctrl);

	if( add_or_delete ){
		brctl.type = RHP_IPC_NETMNG_BRIDGE_ADD;
	}else{
		brctl.type = RHP_IPC_NETMNG_BRIDGE_DELETE;
	}

	brctl.reserved = 0;

	strcpy(brctl.bridge_name,bridge_name);
	strcpy(brctl.vif_name,vif_name);

  err = rhp_ipc_send(RHP_MY_PROCESS,(void*)&brctl,brctl.len,0);
  if( err < 0 ){
  	RHP_BUG("%d",err);
  }else{
  	err = 0;
  }

  return err;
}

