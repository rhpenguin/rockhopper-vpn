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
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_timer.h"
#include "rhp_wthreads.h"
#include "rhp_config.h"
#include "rhp_crypto.h"

static rhp_atomic_t _rhp_netmng_registered;

static rhp_mutex_t _rhp_syspxy_netmng_lock;


static int _rhp_sysinfo_netmng_dumproute_cb(struct nlmsghdr *nlh,void* priv1,void* priv2,void *ctx)
{
  int err = 0;
  rhp_ipcmsg *ipc_tx_msg = NULL;
	rhp_rt_map_entry rt_map_info;
  int dump_ipv6 = (int)ctx;

  RHP_TRC(0,RHPTRCID_SYSINFO_NETMNG_DUMPROUTE_CB,"xLwuxxd",nlh,"NETLINK_MSG",nlh->nlmsg_type,nlh->nlmsg_seq,priv1,priv2,ctx,dump_ipv6);

  memset(&rt_map_info,0,sizeof(rhp_rt_map_entry));

  switch( nlh->nlmsg_type ){

  case NLMSG_DONE:

  	if( dump_ipv6 ){
  		rhp_netmng_send_dumproute(_rhp_sysinfo_netmng_dumproute_cb,(void*)0,AF_INET6);
  	}
  	err = RHP_STATUS_NETMNG_DONE;
  	break;

  case NLMSG_ERROR:
  {
  	struct nlmsgerr* errmsg = (struct nlmsgerr*)(nlh+1);

  	RHP_BUG("NLMSG_ERROR! %d",errmsg->error);
  }
  	break;

  case RTM_NEWROUTE:
  {
  	rhp_ipcmsg_nm_route_map_updated* nm_rtmap_updated_ipcmsg;

  	if( rhp_netmng_parse_routemsg(nlh,&rt_map_info) ){
  		break;
  	}

  	nm_rtmap_updated_ipcmsg
  	= (rhp_ipcmsg_nm_route_map_updated*)rhp_ipc_alloc_msg(RHP_IPC_NETMNG_ROUTEMAP_UPDATED,sizeof(rhp_ipcmsg_nm_route_map_updated));
  	if( nm_rtmap_updated_ipcmsg == NULL ){
  		RHP_BUG("");
  		goto error;
  	}

  	nm_rtmap_updated_ipcmsg->len = sizeof(rhp_ipcmsg_nm_route_map_updated);
  	memcpy(&(nm_rtmap_updated_ipcmsg->info),&rt_map_info,sizeof(rhp_rt_map_entry));

  	ipc_tx_msg = (rhp_ipcmsg*)nm_rtmap_updated_ipcmsg;
  }
  break;

  default:
  	RHP_LINE("%d",nlh->nlmsg_type);
  	err = RHP_STATUS_NETMNG_NOT_INTERESTED;
  	break;
  }

  if( ipc_tx_msg ){

  	if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipc_tx_msg,ipc_tx_msg->len,0) < 0 ){
  	  RHP_TRC(0,RHPTRCID_SYSINFO_NETMNG_DUMPROUTE_CB_IPC_SEND_ERR,"xE",nlh,err);
  	  goto error;
    }

  	_rhp_free_zero(ipc_tx_msg,ipc_tx_msg->len);
  }

  RHP_TRC(0,RHPTRCID_SYSINFO_NETMNG_DUMPROUTE_CB_RTRN,"xLdE",nlh,"NETLINK_MSG",nlh->nlmsg_type,err);
  return err;

error:
	if( ipc_tx_msg ){
		_rhp_free(ipc_tx_msg);
	}

	RHP_TRC(0,RHPTRCID_SYSINFO_NETMNG_DUMPROUTE_CB_ERR,"xLdE",nlh,"NETLINK_MSG",nlh->nlmsg_type,err);
	return err;
}

static int _rhp_sysinfo_netmng_dumpaddr_cb(struct nlmsghdr *nlh,void* priv1,void* priv2,void *ctx)
{
  int err = 0;
  rhp_ipcmsg *ipc_tx_msg = NULL;
  rhp_if_entry ifent;
  int dump_ipv6 = (int)ctx;

  RHP_TRC(0,RHPTRCID_SYSINFO_NETMNG_DUMPADDR_CB,"xLwuxxxd",nlh,"NETLINK_MSG",nlh->nlmsg_type,nlh->nlmsg_seq,priv1,priv2,ctx,dump_ipv6);

  memset(&ifent,0,sizeof(rhp_if_entry));

  switch( nlh->nlmsg_type ){

  case NLMSG_DONE:

  	if( dump_ipv6 ){

  		rhp_netmng_send_dumpaddr(_rhp_sysinfo_netmng_dumpaddr_cb,(void*)0,AF_INET6);

  	}else{

  		rhp_netmng_send_dumproute(_rhp_sysinfo_netmng_dumproute_cb,
  				(void*)!rhp_gcfg_ipv6_disabled,AF_INET);
  	}
  	err = RHP_STATUS_NETMNG_DONE;
  	break;

  case NLMSG_ERROR:
  {
  	struct nlmsgerr* errmsg = (struct nlmsgerr*)(nlh+1);

  	RHP_BUG("NLMSG_ERROR! %d",errmsg->error);
  }
  	break;

  case RTM_NEWADDR:
  {
  	rhp_ipcmsg_nm_update_addr* nm_update_addr_ipcmsg;

  	if( rhp_netmng_parse_ifaddrmsg(nlh,&ifent) ){
  		RHP_BUG("%d",nlh->nlmsg_type);
  		break;
  	}

  	nm_update_addr_ipcmsg = (rhp_ipcmsg_nm_update_addr*)rhp_ipc_alloc_msg(RHP_IPC_NETMNG_UPDATE_ADDR,sizeof(rhp_ipcmsg_nm_update_addr));
  	if( nm_update_addr_ipcmsg == NULL ){
  		RHP_BUG("");
  		goto error;
  	}

  	nm_update_addr_ipcmsg->len = sizeof(rhp_ipcmsg_nm_update_addr);
  	memcpy(&(nm_update_addr_ipcmsg->info),&ifent,sizeof(rhp_if_entry));

  	ipc_tx_msg = (rhp_ipcmsg*)nm_update_addr_ipcmsg;
  }
  break;

  default:
  	RHP_LINE("%d",nlh->nlmsg_type);
  	err = RHP_STATUS_NETMNG_NOT_INTERESTED;
  	break;
  }

  if( ipc_tx_msg ){

  	if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipc_tx_msg,ipc_tx_msg->len,0) < 0 ){
  	  RHP_TRC(0,RHPTRCID_SYSINFO_NETMNG_DUMPADDR_CB_IPC_SEND_ERR,"xE",nlh,err);
  	  goto error;
    }

  	_rhp_free_zero(ipc_tx_msg,ipc_tx_msg->len);
  }

  RHP_TRC(0,RHPTRCID_SYSINFO_NETMNG_DUMPADDR_CB_RTRN,"xLdE",nlh,"NETLINK_MSG",nlh->nlmsg_type,err);
  return err;

error:
	if( ipc_tx_msg ){
		_rhp_free(ipc_tx_msg);
	}

	RHP_TRC(0,RHPTRCID_SYSINFO_NETMNG_DUMPADDR_CB_ERR,"xLdE",nlh,"NETLINK_MSG",nlh->nlmsg_type,err);
	return err;
}


static int _rhp_sysinfo_netmng_dumplink_cb(struct nlmsghdr *nlh,void* priv1,void* priv2,void *ctx)
{
  rhp_ipcmsg *ipc_tx_msg = NULL;
  rhp_if_entry ifent;
  int err = 0;

  RHP_TRC(0,RHPTRCID_SYSINFO_NETMNG_DUMPLINK_CB,"xLwuxx",nlh,"NETLINK_MSG",nlh->nlmsg_type,nlh->nlmsg_seq,priv1,priv2,ctx);

  memset(&ifent,0,sizeof(rhp_if_entry));

  switch( nlh->nlmsg_type ){

  case NLMSG_DONE:

  	rhp_netmng_send_dumpaddr(_rhp_sysinfo_netmng_dumpaddr_cb,
  			(void*)!rhp_gcfg_ipv6_disabled,AF_INET);

  	err = RHP_STATUS_NETMNG_DONE;

//  	rhp_ipc_send_nop(RHP_MY_PROCESS,88);
  	break;

  case NLMSG_ERROR:
  {
  	struct nlmsgerr* errmsg = (struct nlmsgerr*)(nlh+1);

  	RHP_BUG("NLMSG_ERROR! %d",errmsg->error);
  }
  	break;

  case RTM_NEWLINK:
  {
  	rhp_ipcmsg_nm_update_if* nm_update_if_ipcmsg;

  	if( rhp_netmng_parse_ifinfomsg(nlh,&ifent) ){
  		RHP_BUG("%d",nlh->nlmsg_type);
  		goto error;
  	}

  	nm_update_if_ipcmsg = (rhp_ipcmsg_nm_update_if*)rhp_ipc_alloc_msg(RHP_IPC_NETMNG_UPDATE_IF,sizeof(rhp_ipcmsg_nm_update_if));
  	if( nm_update_if_ipcmsg == NULL ){
  		RHP_BUG("");
  		goto error;
  	}

  	nm_update_if_ipcmsg->len = sizeof(rhp_ipcmsg_nm_update_if);
  	memcpy(&(nm_update_if_ipcmsg->info),&ifent,sizeof(rhp_if_entry));

  	ipc_tx_msg = (rhp_ipcmsg*)nm_update_if_ipcmsg;
  }
  	break;

  default:
  	err = RHP_STATUS_NETMNG_NOT_INTERESTED;
  	RHP_LINE("%d",nlh->nlmsg_type);
  	break;
  }

  if( ipc_tx_msg ){

  	if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipc_tx_msg,ipc_tx_msg->len,0) < 0 ){
  		RHP_TRC(0,RHPTRCID_SYSINFO_NETMNG_DUMPLINK_CB_IPC_SEND_ERR,"xE",nlh,err);
  		goto error;
    }

  	_rhp_free_zero(ipc_tx_msg,ipc_tx_msg->len);
  }

  RHP_TRC(0,RHPTRCID_SYSINFO_NETMNG_DUMPLINK_CB_RTRN,"xLdE",nlh,"NETLINK_MSG",nlh->nlmsg_type,err);
  return err;

error:
	if( ipc_tx_msg ){
		_rhp_free(ipc_tx_msg);
	}

	RHP_TRC(0,RHPTRCID_SYSINFO_NETMNG_DUMPLINK_CB_ERR,"xLdE",nlh,"NETLINK_MSG",nlh->nlmsg_type,err);
	return err;
}

static void _rhp_sysinfo_netmng_cb(struct nlmsghdr *nlh,void *ctx)
{
  rhp_ipcmsg *ipc_tx_msg = NULL;
  rhp_if_entry ifent;
  rhp_rt_map_entry rtmap_ent;

  memset(&ifent,0,sizeof(rhp_if_entry));
  memset(&rtmap_ent,0,sizeof(rhp_rt_map_entry));

  RHP_TRC(0,RHPTRCID_SYSINFO_NETMNG_CB,"xLwux",nlh,"NETLINK_MSG",nlh->nlmsg_type,nlh->nlmsg_seq,ctx);

  switch( nlh->nlmsg_type ){

  case NLMSG_DONE:

  	RHP_TRC(0,RHPTRCID_SYSINFO_NETMNG_CB_NLMSGDONE,"");
  	break;

  case NLMSG_ERROR:
  {
  	struct nlmsgerr* errmsg = (struct nlmsgerr*)(nlh+1);

  	RHP_BUG("NLMSG_ERROR! %d",errmsg->error);
  	RHP_TRC(0,RHPTRCID_SYSINFO_NETMNG_CB_NLMSGERR,"dp",errmsg->error,sizeof(struct nlmsghdr),&(errmsg->msg));
  }
  	break;

  case RTM_NEWLINK:
  {
  	if( rhp_netmng_parse_ifinfomsg(nlh,&ifent) ){
  		RHP_BUG("%d",nlh->nlmsg_type);
  		goto error;
  	}

  	if( _rhp_atomic_read(&_rhp_netmng_registered) ){

  		rhp_ipcmsg_nm_update_if* nm_update_if_ipcmsg
  		= (rhp_ipcmsg_nm_update_if*)rhp_ipc_alloc_msg(RHP_IPC_NETMNG_UPDATE_IF,sizeof(rhp_ipcmsg_nm_update_if));

  		if( nm_update_if_ipcmsg == NULL ){
  			RHP_BUG("");
  			goto error;
  		}

  		nm_update_if_ipcmsg->len = sizeof(rhp_ipcmsg_nm_update_if);
  		memcpy(&(nm_update_if_ipcmsg->info),&ifent,sizeof(rhp_if_entry));

  		ipc_tx_msg = (rhp_ipcmsg*)nm_update_if_ipcmsg;

  	}else{
    	RHP_TRC(0,RHPTRCID_SYSINFO_NETMNG_CB_NEWLINK_NOT_REGISTERED,"x",nlh);
  	}
  }
  	break;

  case RTM_DELLINK:
  {
  	if( rhp_netmng_parse_ifinfomsg(nlh,&ifent) ){
  		RHP_BUG("%d",nlh->nlmsg_type);
  		goto error;
  	}

  	if( _rhp_atomic_read(&_rhp_netmng_registered) ){

  		rhp_ipcmsg_nm_delete_if* nm_delete_if_ipcmsg
  		= (rhp_ipcmsg_nm_delete_if*)rhp_ipc_alloc_msg(RHP_IPC_NETMNG_DELETE_IF,sizeof(rhp_ipcmsg_nm_delete_if));

  		if( nm_delete_if_ipcmsg == NULL ){
  			RHP_BUG("");
  			goto error;
  		}

  		nm_delete_if_ipcmsg->len = sizeof(rhp_ipcmsg_nm_delete_if);
  		strcpy(nm_delete_if_ipcmsg->if_name,ifent.if_name);

  		ipc_tx_msg = (rhp_ipcmsg*)nm_delete_if_ipcmsg;

  	}else{
    	RHP_TRC(0,RHPTRCID_SYSINFO_NETMNG_CB_DELLINK_NOT_REGISTERED,"x",nlh);
  	}
  }
    break;

  case RTM_NEWADDR:
  {
  	if( rhp_netmng_parse_ifaddrmsg(nlh,&ifent) ){
        RHP_BUG("%d",nlh->nlmsg_type);
        break;
      }

      if( _rhp_atomic_read(&_rhp_netmng_registered) ){

        rhp_ipcmsg_nm_update_addr* ipcmsg
        = (rhp_ipcmsg_nm_update_addr*)rhp_ipc_alloc_msg(RHP_IPC_NETMNG_UPDATE_ADDR,sizeof(rhp_ipcmsg_nm_update_addr));

        if( ipcmsg == NULL ){
          RHP_BUG("");
          goto error;
        }

        ipcmsg->len = sizeof(rhp_ipcmsg_nm_update_addr);
        memcpy(&(ipcmsg->info),&ifent,sizeof(rhp_if_entry));

        ipc_tx_msg = (rhp_ipcmsg*)ipcmsg;

      }else{
      	RHP_TRC(0,RHPTRCID_SYSINFO_NETMNG_CB_NEWADDR_NOT_REGISTERED,"x",nlh);
      }
    }
    break;

  case RTM_DELADDR:
  {
  	if( rhp_netmng_parse_ifaddrmsg(nlh,&ifent) ){
  		RHP_BUG("%d",nlh->nlmsg_type);
  		break;
  	}

  	if( _rhp_atomic_read(&_rhp_netmng_registered) ){

  		rhp_ipcmsg_nm_delete_addr* nm_delete_addr_ipcmsg
        = (rhp_ipcmsg_nm_delete_addr*)rhp_ipc_alloc_msg(RHP_IPC_NETMNG_DELETE_ADDR,sizeof(rhp_ipcmsg_nm_delete_addr));

  		if( nm_delete_addr_ipcmsg == NULL ){
  			RHP_BUG("");
  			goto error;
  		}

  		nm_delete_addr_ipcmsg->len = sizeof(rhp_ipcmsg_nm_delete_addr);
  		memcpy(&(nm_delete_addr_ipcmsg->info),&ifent,sizeof(rhp_if_entry));

  		ipc_tx_msg = (rhp_ipcmsg*)nm_delete_addr_ipcmsg;

  	}else{
  		RHP_TRC(0,RHPTRCID_SYSINFO_NETMNG_CB_DELADDR_NOT_REGISTERED,"x",nlh);
  	}
  }
    break;

  case RTM_NEWROUTE:
  {
  	if( rhp_netmng_parse_routemsg(nlh,&rtmap_ent) ){
  		break;
  	}

  	if( _rhp_atomic_read(&_rhp_netmng_registered) ){

  		rhp_ipcmsg_nm_route_map_updated* nm_rtmap_updated_ipcmsg;

			nm_rtmap_updated_ipcmsg
			= (rhp_ipcmsg_nm_route_map_updated*)rhp_ipc_alloc_msg(RHP_IPC_NETMNG_ROUTEMAP_UPDATED,sizeof(rhp_ipcmsg_nm_route_map_updated));
			if( nm_rtmap_updated_ipcmsg == NULL ){
				RHP_BUG("");
				goto error;
			}

			nm_rtmap_updated_ipcmsg->len = sizeof(rhp_ipcmsg_nm_route_map_updated);
			memcpy(&(nm_rtmap_updated_ipcmsg->info),&rtmap_ent,sizeof(rhp_rt_map_entry));

			ipc_tx_msg = (rhp_ipcmsg*)nm_rtmap_updated_ipcmsg;

  	}else{
  		RHP_TRC(0,RHPTRCID_SYSINFO_NETMNG_CB_NEWROUTE_NOT_REGISTERED,"x",nlh);
  	}
  }
  break;

  case RTM_DELROUTE:
  {
  	if( rhp_netmng_parse_routemsg(nlh,&rtmap_ent) ){
  		break;
  	}

  	if( _rhp_atomic_read(&_rhp_netmng_registered) ){

  		rhp_ipcmsg_nm_route_map_deleted* nm_rtmap_deleted_ipcmsg;

  		nm_rtmap_deleted_ipcmsg
			= (rhp_ipcmsg_nm_route_map_deleted*)rhp_ipc_alloc_msg(RHP_IPC_NETMNG_ROUTEMAP_DELETED,sizeof(rhp_ipcmsg_nm_route_map_deleted));
			if( nm_rtmap_deleted_ipcmsg == NULL ){
				RHP_BUG("");
				goto error;
			}

			nm_rtmap_deleted_ipcmsg->len = sizeof(rhp_ipcmsg_nm_route_map_deleted);
			memcpy(&(nm_rtmap_deleted_ipcmsg->info),&rtmap_ent,sizeof(rhp_rt_map_entry));

			ipc_tx_msg = (rhp_ipcmsg*)nm_rtmap_deleted_ipcmsg;

  	}else{
  		RHP_TRC(0,RHPTRCID_SYSINFO_NETMNG_CB_DELROUTE_NOT_REGISTERED,"x",nlh);
  	}
  }
  break;

  default:
		RHP_TRC(0,RHPTRCID_SYSINFO_NETMNG_CB_NOT_SUPPORTED,"xw",nlh,nlh->nlmsg_type);
  	break;
  }

  if( ipc_tx_msg ){

  	if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipc_tx_msg,ipc_tx_msg->len,0) < 0 ){
      RHP_TRC(0,RHPTRCID_SYSINFO_NETMNG_CB_IPC_SEND_ERR,"xxdd",RHP_MY_PROCESS,ipc_tx_msg,ipc_tx_msg->len,0);
      goto error;
    }

  	_rhp_free_zero(ipc_tx_msg,ipc_tx_msg->len);
  }

  RHP_TRC(0,RHPTRCID_SYSINFO_NETMNG_CB_RTRN,"x",nlh);
  return;

error:
  if( ipc_tx_msg ){
    _rhp_free(ipc_tx_msg);
  }

  RHP_TRC(0,RHPTRCID_SYSINFO_NETMNG_CB_ERR,"x",nlh);
  return;
}


static char *_rhp_nl_buf[RHP_NETMNG_BUFSZ];

void rhp_syspxy_handle_netmng()
{
  int err = 0;

  RHP_TRC(0,RHPTRCID_SYSPXY_HANDLE_NETMNG,"");

  err = rhp_netmng_recvmsg(_rhp_nl_buf,RHP_NETMNG_BUFSZ,MSG_DONTWAIT,_rhp_sysinfo_netmng_cb,(void*)1);
  if( err ){
  	RHP_TRC(0,RHPTRCID_SYSPXY_HANDLE_NETMNG_ERROR,"d",err);
  }else{
  	RHP_TRC(0,RHPTRCID_SYSPXY_HANDLE_NETMNG_RTRN,"");
  }
  return;
}



struct _rhp_syspxy_netmng_opr {

	u8 tag[4]; // "#SYO"

	struct _rhp_syspxy_netmng_opr* next;

	union {
		rhp_ipcmsg_vif_create* 					vif_create_req;
		rhp_ipcmsg_vif_update* 					vif_update_req;
		rhp_ipcmsg_nm_route_update* 		rt_update_req;
		rhp_ipcmsg_netmng_dns_pxy_rdir* dns_pxy_rdir;
		rhp_ipcmsg_netmng_bridge_ctrl* 	brctl_req;
		rhp_ipcmsg* 										raw_req;
	} req_ipcmsg;
};
typedef struct _rhp_syspxy_netmng_opr rhp_syspxy_netmng_opr;

rhp_syspxy_netmng_opr* _rhp_syspxy_netmng_vif_lst_head = NULL;
rhp_syspxy_netmng_opr* _rhp_syspxy_netmng_rt_lst_head = NULL;
rhp_syspxy_netmng_opr* _rhp_syspxy_netmng_dns_pxy_lst_head = NULL;
rhp_syspxy_netmng_opr* _rhp_syspxy_netmng_brctl_lst_head = NULL;


static int _rhp_syspxy_netcfg_add(rhp_ipcmsg* ipcmsg)
{
	int err = -EINVAL;
	rhp_syspxy_netmng_opr* opr = (rhp_syspxy_netmng_opr*)_rhp_malloc(sizeof(rhp_syspxy_netmng_opr));

  RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_ADD,"x",ipcmsg);

	if( opr == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		return err;
	}

	memset(opr,0,sizeof(rhp_syspxy_netmng_opr));

	opr->tag[0] = '#';
	opr->tag[1] = 'S';
	opr->tag[2] = 'Y';
	opr->tag[3] = 'O';

	opr->req_ipcmsg.raw_req = ipcmsg;

	RHP_LOCK(&_rhp_syspxy_netmng_lock);
	{
		if( ipcmsg->type == RHP_IPC_NETMNG_VIF_CREATE ){

			opr->next = _rhp_syspxy_netmng_vif_lst_head;
			_rhp_syspxy_netmng_vif_lst_head = opr;

		}else if( ipcmsg->type == RHP_IPC_NETMNG_VIF_UPDATE ){

				opr->next = _rhp_syspxy_netmng_vif_lst_head;
				_rhp_syspxy_netmng_vif_lst_head = opr;

		}else if( ipcmsg->type == RHP_IPC_NETMNG_ROUTE_UPDATE ){

			opr->next = _rhp_syspxy_netmng_rt_lst_head;
			_rhp_syspxy_netmng_rt_lst_head = opr;

		}else if( ipcmsg->type == RHP_IPC_NETMNG_DNSPXY_RDIR_START ){

			opr->next = _rhp_syspxy_netmng_dns_pxy_lst_head;
			_rhp_syspxy_netmng_dns_pxy_lst_head = opr;

		}else if( ipcmsg->type == RHP_IPC_NETMNG_BRIDGE_ADD ){

			opr->next = _rhp_syspxy_netmng_brctl_lst_head;
			_rhp_syspxy_netmng_brctl_lst_head = opr;

		}else{
			_rhp_free(opr);
		}
	}
	RHP_UNLOCK(&_rhp_syspxy_netmng_lock);

	return 0;
}

static void _rhp_syspxy_netcfg_vif_delete(char* if_name)
{
	rhp_syspxy_netmng_opr *opr,*opr_p = NULL;

  RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_VIF_DELETE,"s",if_name);

	RHP_LOCK(&_rhp_syspxy_netmng_lock);

	opr = _rhp_syspxy_netmng_vif_lst_head;

	while( opr ){

		if( opr->req_ipcmsg.raw_req->type == RHP_IPC_NETMNG_VIF_CREATE ){

			if( !strcmp(if_name,opr->req_ipcmsg.vif_create_req->info_v4.if_name) ){
				break;
			}

		}else if( opr->req_ipcmsg.raw_req->type == RHP_IPC_NETMNG_VIF_UPDATE ){

			if( !strcmp(if_name,opr->req_ipcmsg.vif_update_req->if_info.if_name) ){
				break;
			}
		}

		opr_p = opr;
		opr = opr->next;
	}

	if( opr == NULL ){
	  RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_VIF_DELETE_NOT_FOUND,"s",if_name);
		goto error;
	}

	if( opr_p ){
		opr_p->next = opr->next;
	}else{
		_rhp_syspxy_netmng_vif_lst_head = opr->next;
	}

	_rhp_free_zero(opr->req_ipcmsg.raw_req,opr->req_ipcmsg.raw_req->len);
	_rhp_free(opr);

error:
	RHP_UNLOCK(&_rhp_syspxy_netmng_lock);

	return;
}

static void _rhp_syspxy_netcfg_vif_delete_prm(rhp_syspxy_netmng_opr* opr_d)
{
	rhp_syspxy_netmng_opr *opr,*opr_p = NULL;

  RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_VIF_DELETE_PRM,"xs",opr_d,opr_d->req_ipcmsg.vif_create_req->info_v4.if_name);

	opr = _rhp_syspxy_netmng_vif_lst_head;

	while( opr ){

		if( opr == opr_d ){
			break;
		}

		opr_p = opr;
		opr = opr->next;
	}

	if( opr == NULL ){
	  RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_VIF_DELETE_PRM_NOT_FOUND,"x",opr_d);
		goto error;
	}

	if( opr_p ){
		opr_p->next = opr->next;
	}else{
		_rhp_syspxy_netmng_vif_lst_head = opr->next;
	}

	_rhp_free_zero(opr->req_ipcmsg.raw_req,opr->req_ipcmsg.raw_req->len);
	_rhp_free(opr);

error:
	return;
}


static int _rhp_syspxy_netcfg_vif_exists(char* if_name)
{
	int result = 0;
	rhp_syspxy_netmng_opr *opr;

  RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_VIF_EXISTS,"s",if_name);

	RHP_LOCK(&_rhp_syspxy_netmng_lock);

	opr = _rhp_syspxy_netmng_vif_lst_head;

	while( opr ){

		if( opr->req_ipcmsg.raw_req->type == RHP_IPC_NETMNG_VIF_CREATE ){

			if( !strcmp(if_name,opr->req_ipcmsg.vif_create_req->info_v4.if_name) ){
				result = 1;
				break;
			}

		}else if( opr->req_ipcmsg.raw_req->type == RHP_IPC_NETMNG_VIF_UPDATE ){

			if( !strcmp(if_name,opr->req_ipcmsg.vif_update_req->if_info.if_name) ){
				result = 1;
				break;
			}
		}

		opr = opr->next;
	}

	RHP_UNLOCK(&_rhp_syspxy_netmng_lock);

  RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_VIF_EXISTS_RTRN,"sd",if_name,result);
	return result;
}

static void _rhp_syspxy_netcfg_route_delete(char* tx_interface,  rhp_ip_addr* dest_addr,rhp_ip_addr* nexthop_addr)
{
	rhp_syspxy_netmng_opr *opr,*opr_p = NULL;

  RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_ROUTE_DELETE,"sxx",tx_interface,dest_addr,nexthop_addr);
	rhp_ip_addr_dump("_rhp_syspxy_netcfg_route_delete.dest_addr",dest_addr);
	rhp_ip_addr_dump("_rhp_syspxy_netcfg_route_delete.nexthop_addr",nexthop_addr);

	RHP_LOCK(&_rhp_syspxy_netmng_lock);

	opr = _rhp_syspxy_netmng_rt_lst_head;

	while( opr ){

		if( !rhp_ip_addr_cmp(dest_addr,&(opr->req_ipcmsg.rt_update_req->dest_addr)) ){

			if(  tx_interface && !strcmp(opr->req_ipcmsg.rt_update_req->if_name,tx_interface) ){
				break;
			}

			if( !rhp_ip_addr_cmp(nexthop_addr,&(opr->req_ipcmsg.rt_update_req->nexthop_addr)) ){
				break;
			}
		}

		opr_p = opr;
		opr = opr->next;
	}

	if( opr == NULL ){
	  RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_ROUTE_DELETE_NOT_FOUND,"sxx",tx_interface,dest_addr,nexthop_addr);
		goto error;
	}

	if( opr_p ){
		opr_p->next = opr->next;
	}else{
		_rhp_syspxy_netmng_rt_lst_head = opr->next;
	}

	_rhp_free_zero(opr->req_ipcmsg.raw_req,opr->req_ipcmsg.raw_req->len);
	_rhp_free(opr);

error:
	RHP_UNLOCK(&_rhp_syspxy_netmng_lock);

	return;
}

static void _rhp_syspxy_netcfg_route_delete_prm(rhp_syspxy_netmng_opr* opr_d)
{
	rhp_syspxy_netmng_opr *opr,*opr_p = NULL;

  RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_ROUTE_DELETE_PRM,"xs",opr_d,opr_d->req_ipcmsg.rt_update_req->if_name);
	rhp_ip_addr_dump("_rhp_syspxy_netcfg_route_delete_prm.dest_addr",&(opr_d->req_ipcmsg.rt_update_req->dest_addr));
	rhp_ip_addr_dump("_rhp_syspxy_netcfg_route_delete_prm.nexthop_addr",&(opr_d->req_ipcmsg.rt_update_req->nexthop_addr));

	opr = _rhp_syspxy_netmng_rt_lst_head;

	while( opr ){

		if( opr == opr_d ){
			break;
		}

		opr_p = opr;
		opr = opr->next;
	}

	if( opr == NULL ){
	  RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_ROUTE_DELETE_PRM_NOT_FOUND,"x",opr_d);
		goto error;
	}

	if( opr_p ){
		opr_p->next = opr->next;
	}else{
		_rhp_syspxy_netmng_rt_lst_head = opr->next;
	}

	_rhp_free_zero(opr->req_ipcmsg.raw_req,opr->req_ipcmsg.raw_req->len);
	_rhp_free(opr);

error:

	return;
}

static int _rhp_syspxy_netcfg_route_exists(char* tx_interface,  rhp_ip_addr* dest_addr,rhp_ip_addr* nexthop_addr,unsigned long* metric_r)
{
	int result = 0;
	rhp_syspxy_netmng_opr *opr;
	int metric = 0;

  RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_ROUTE_EXISTS,"sxxx",tx_interface,dest_addr,nexthop_addr,metric_r);
	rhp_ip_addr_dump("_rhp_syspxy_netcfg_route_exists.dest_addr",dest_addr);
	rhp_ip_addr_dump("_rhp_syspxy_netcfg_route_exists.nexthop_addr",nexthop_addr);

	RHP_LOCK(&_rhp_syspxy_netmng_lock);

	opr = _rhp_syspxy_netmng_rt_lst_head;

	while( opr ){

		if( !rhp_ip_addr_cmp(dest_addr,&(opr->req_ipcmsg.rt_update_req->dest_addr)) ){

			if(  tx_interface && !strcmp(opr->req_ipcmsg.rt_update_req->if_name,tx_interface) ){

				metric = opr->req_ipcmsg.rt_update_req->metric;
				result = 1;
				break;
			}

			if( !rhp_ip_addr_cmp(nexthop_addr,&(opr->req_ipcmsg.rt_update_req->nexthop_addr)) ){

				metric = opr->req_ipcmsg.rt_update_req->metric;
				result = 1;
				break;
			}
		}

		opr = opr->next;
	}

	if( result && metric_r ){
		*metric_r = metric;
	}

	RHP_UNLOCK(&_rhp_syspxy_netmng_lock);

  RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_ROUTE_EXISTS_RTRN,"dd",result,metric);
	return result;
}


static void _rhp_syspxy_netcfg_dns_pxy_delete(rhp_ip_addr* inet_name_server_addr,u16 internal_port)
{
	rhp_syspxy_netmng_opr *opr,*opr_p = NULL;

  RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_DNS_PXY_DELETE,"xW",inet_name_server_addr,internal_port);
	rhp_ip_addr_dump("_rhp_syspxy_netcfg_dns_pxy_delete.inet_name_server_addr",inet_name_server_addr);

	RHP_LOCK(&_rhp_syspxy_netmng_lock);

	opr = _rhp_syspxy_netmng_dns_pxy_lst_head;

	while( opr ){

		if( !rhp_ip_addr_cmp(inet_name_server_addr,&(opr->req_ipcmsg.dns_pxy_rdir->inet_name_server_addr)) &&
				(opr->req_ipcmsg.dns_pxy_rdir->internal_port == internal_port) ){
			break;
		}

		opr_p = opr;
		opr = opr->next;
	}

	if( opr == NULL ){
	  RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_DNS_PXY_DELETE_NOT_FOUND,"xW",inet_name_server_addr,internal_port);
		goto error;
	}

	if( opr_p ){
		opr_p->next = opr->next;
	}else{
		_rhp_syspxy_netmng_dns_pxy_lst_head = opr->next;
	}

	_rhp_free_zero(opr->req_ipcmsg.raw_req,opr->req_ipcmsg.raw_req->len);
	_rhp_free(opr);

error:
	RHP_UNLOCK(&_rhp_syspxy_netmng_lock);

	return;
}

static void _rhp_syspxy_netcfg_dns_pxy_delete_prm(rhp_syspxy_netmng_opr* opr_d)
{
	rhp_syspxy_netmng_opr *opr,*opr_p = NULL;

	RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_DNS_PXY_DELETE_PRM,"xxW",opr_d,opr_d->req_ipcmsg.dns_pxy_rdir->inet_name_server_addr,opr_d->req_ipcmsg.dns_pxy_rdir->internal_port);
	rhp_ip_addr_dump("_rhp_syspxy_netcfg_dns_pxy_delete_prm.inet_name_server_addr",&(opr_d->req_ipcmsg.dns_pxy_rdir->inet_name_server_addr));

	opr = _rhp_syspxy_netmng_dns_pxy_lst_head;

	while( opr ){

		if( opr == opr_d ){
			break;
		}

		opr_p = opr;
		opr = opr->next;
	}

	if( opr == NULL ){
	  RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_DNS_PXY_DELETE_PRM_NOT_FOUND,"x",opr_d);
		goto error;
	}

	if( opr_p ){
		opr_p->next = opr->next;
	}else{
		_rhp_syspxy_netmng_dns_pxy_lst_head = opr->next;
	}

	_rhp_free_zero(opr->req_ipcmsg.raw_req,opr->req_ipcmsg.raw_req->len);
	_rhp_free(opr);

error:

	return;
}

static int _rhp_syspxy_netcfg_dns_pxy_exists(rhp_ip_addr* inet_name_server_addr,u16 internal_port)
{
	int result = 0;
	rhp_syspxy_netmng_opr *opr;

  RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_DNS_PXY_EXISTS,"xW",inet_name_server_addr,internal_port);
	rhp_ip_addr_dump("_rhp_syspxy_netcfg_dnspxy_exists.inet_name_server_addr",inet_name_server_addr);

	RHP_LOCK(&_rhp_syspxy_netmng_lock);

	opr = _rhp_syspxy_netmng_dns_pxy_lst_head;

	while( opr ){

		if( !rhp_ip_addr_cmp(inet_name_server_addr,&(opr->req_ipcmsg.dns_pxy_rdir->inet_name_server_addr)) ){

			if( internal_port  ){

				if( (opr->req_ipcmsg.dns_pxy_rdir->internal_port == internal_port) ){
					result = 1;
				}

			}else{
				result = 1;
			}

			break;
		}

		opr = opr->next;
	}

	RHP_UNLOCK(&_rhp_syspxy_netmng_lock);

  RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_DNS_PXY_EXISTS_RTRN,"d",result);
	return result;
}


static void _rhp_syspxy_netcfg_brctl_delete(char* bridge_name,char* vif_name)
{
	rhp_syspxy_netmng_opr *opr,*opr_p = NULL;

  RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_BRCTL_DELETE,"ss",bridge_name,vif_name);

	RHP_LOCK(&_rhp_syspxy_netmng_lock);

	opr = _rhp_syspxy_netmng_brctl_lst_head;

	while( opr ){

		if( !strcmp(bridge_name,opr->req_ipcmsg.brctl_req->bridge_name) && !strcmp(vif_name,opr->req_ipcmsg.brctl_req->vif_name) ){
			break;
		}

		opr_p = opr;
		opr = opr->next;
	}

	if( opr == NULL ){
	  RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_BRCTL_DELETE_NOT_FOUND,"ss",bridge_name,vif_name);
		goto error;
	}

	if( opr_p ){
		opr_p->next = opr->next;
	}else{
		_rhp_syspxy_netmng_brctl_lst_head = opr->next;
	}

	_rhp_free_zero(opr->req_ipcmsg.raw_req,opr->req_ipcmsg.raw_req->len);
	_rhp_free(opr);

error:
	RHP_UNLOCK(&_rhp_syspxy_netmng_lock);

	return;
}

static void _rhp_syspxy_netcfg_brctl_delete_prm(rhp_syspxy_netmng_opr* opr_d)
{
	rhp_syspxy_netmng_opr *opr,*opr_p = NULL;

	RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_BRCTL_DELETE_PRM,"xss",opr_d,opr_d->req_ipcmsg.brctl_req->bridge_name,opr_d->req_ipcmsg.brctl_req->vif_name);

	opr = _rhp_syspxy_netmng_brctl_lst_head;

	while( opr ){

		if( opr == opr_d ){
			break;
		}

		opr_p = opr;
		opr = opr->next;
	}

	if( opr == NULL ){
	  RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_BRCTL_DELETE_PRM_NOT_FOUND,"x",opr_d);
		goto error;
	}

	if( opr_p ){
		opr_p->next = opr->next;
	}else{
		_rhp_syspxy_netmng_brctl_lst_head = opr->next;
	}

	_rhp_free_zero(opr->req_ipcmsg.raw_req,opr->req_ipcmsg.raw_req->len);
	_rhp_free(opr);

error:

	return;
}

static int _rhp_syspxy_netcfg_brctl_exists(char* bridge_name,char* vif_name)
{
	int result = 0;
	rhp_syspxy_netmng_opr *opr;

  RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_BRCTL_EXISTS,"ss",bridge_name,vif_name);

	RHP_LOCK(&_rhp_syspxy_netmng_lock);

	opr = _rhp_syspxy_netmng_brctl_lst_head;

	while( opr ){

		if( !strcmp(bridge_name,opr->req_ipcmsg.brctl_req->bridge_name) &&
				!strcmp(vif_name,opr->req_ipcmsg.brctl_req->vif_name) ){
			result = 1;
			break;
		}

		opr = opr->next;
	}

	RHP_UNLOCK(&_rhp_syspxy_netmng_lock);

  RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_BRCTL_EXISTS_RTRN,"d",result);
	return result;
}


static void _rhp_syspxy_netcfg_flush()
{
	rhp_syspxy_netmng_opr *opr,*opr_n;

  RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_FLUSH,"");

	RHP_LOCK(&_rhp_syspxy_netmng_lock);

	{
		opr = _rhp_syspxy_netmng_brctl_lst_head;

		while( opr ){

			opr_n = opr->next;

			rhp_netmng_bridge_ctrl(opr->req_ipcmsg.brctl_req->bridge_name,opr->req_ipcmsg.brctl_req->vif_name,0);

			_rhp_syspxy_netcfg_brctl_delete_prm(opr);

			opr = opr_n;
		}
	}

	{
		opr = _rhp_syspxy_netmng_dns_pxy_lst_head;

		while( opr ){

			opr_n = opr->next;

			rhp_netmng_dns_pxy_exec_redir(&(opr->req_ipcmsg.dns_pxy_rdir->inet_name_server_addr),
					opr->req_ipcmsg.dns_pxy_rdir->internal_port,0);

			_rhp_syspxy_netcfg_dns_pxy_delete_prm(opr);

			opr = opr_n;
		}
	}

	{
		opr = _rhp_syspxy_netmng_rt_lst_head;

		while( opr ){

			opr_n = opr->next;

			rhp_netmng_route_delete(opr->req_ipcmsg.rt_update_req->if_name,
					&(opr->req_ipcmsg.rt_update_req->dest_addr),&(opr->req_ipcmsg.rt_update_req->nexthop_addr));

			_rhp_syspxy_netcfg_route_delete_prm(opr);

			opr = opr_n;
		}
	}

	{
		opr = _rhp_syspxy_netmng_vif_lst_head;

		while( opr ){

			opr_n = opr->next;

			rhp_netmng_vif_delete(opr->req_ipcmsg.vif_create_req->interface_type,
					opr->req_ipcmsg.vif_create_req->info_v4.if_name);

			_rhp_syspxy_netcfg_vif_delete_prm(opr);

			opr = opr_n;
		}
	}

	RHP_UNLOCK(&_rhp_syspxy_netmng_lock);

  RHP_TRC(0,RHPTRCID_SYSPXY_NETCFG_FLUSH_RTRN,"");
	return;
}


int _rhp_syspxy_netcfg_apply_firewall_rules(rhp_ipcmsg* ipcmsg)
{
	int err = -EINVAL;
	rhp_ipcmsg_fw_rules* ipc_fw_rules = (rhp_ipcmsg_fw_rules*)ipcmsg;
	u8 *p;
	unsigned int i;

	if( ipcmsg->len < sizeof(rhp_ipcmsg_fw_rules) ){
		RHP_BUG("%d",ipcmsg->len);
		err = -EINVAL;
		goto error;
	}

	if( ipc_fw_rules->rules_num ){

		u8* end_p;

		p = (u8*)(ipc_fw_rules + 1);
		end_p = p + ipcmsg->len;

		for( i = 0; i < ipc_fw_rules->rules_num; i++ ){

			rhp_ipcmsg_fw_rule* fw_rule = (rhp_ipcmsg_fw_rule*)p;
			unsigned int t_len;

			if( p >= end_p ){
				RHP_BUG("");
				break;
			}

			if( p + sizeof(rhp_ipcmsg_fw_rule) >= end_p ){
				RHP_BUG("");
				break;
			}

			if( p + fw_rule->len >= end_p ){
				RHP_BUG("");
				break;
			}

			t_len = sizeof(rhp_ipcmsg_fw_rule) + fw_rule->traffic_len + fw_rule->action_len + fw_rule->if_len
					+ fw_rule->filter_pos_len + fw_rule->arg0_len + fw_rule->arg1_len;

			if( (p + t_len) >= end_p ){
				RHP_BUG("");
				break;
			}

			if( t_len != fw_rule->len ){
				RHP_BUG("");
				break;
			}

			p += fw_rule->len;
		}

		if( i != ipc_fw_rules->rules_num ){
			RHP_BUG("%d, %d",i,ipc_fw_rules->rules_num);
			err = -EINVAL;
			goto error;
		}
	}


	err = rhp_netmng_firewall_rules_flush();
	if( err ){
		goto error;
	}


	if( ipc_fw_rules->rules_num ){

		p = (u8*)(ipc_fw_rules + 1);

		for( i = 0; i < ipc_fw_rules->rules_num; i++ ){

			rhp_ipcmsg_fw_rule* fw_rule = (rhp_ipcmsg_fw_rule*)p;
			char* traffic = NULL;
			char* action = NULL;
			char* interface = NULL;
			char* filter_pos = NULL;
			u8* arg0 = NULL;
			u8* arg1 = NULL;

			p = (u8*)(fw_rule + 1);

			if( fw_rule->traffic_len ){
				traffic = (char*)p;
				p += fw_rule->traffic_len;
			}
			if( fw_rule->action_len ){
				action = (char*)p;
				p += fw_rule->action_len;
			}
			if( fw_rule->if_len ){
				interface = (char*)p;
				p += fw_rule->if_len;
			}
			if( fw_rule->filter_pos_len ){
				filter_pos = (char*)p;
				p += fw_rule->filter_pos_len;
			}
			if( fw_rule->arg0_len ){
				arg0 = p;
				p += fw_rule->arg0_len;
			}
			if( fw_rule->arg1_len ){
				arg1 = p;
				p += fw_rule->arg1_len;
			}

			err = rhp_netmng_firewall_rules_apply(traffic,action,interface,filter_pos,fw_rule->arg0_len,arg0,fw_rule->arg1_len,arg1);
			if( err ){
				goto error;
			}
		}
	}

	return 0;

error:
	return err;
}

int rhp_syspxy_netmng_handle_ipc(rhp_ipcmsg* ipcmsg)
{
  int err = 0;

  RHP_TRC(0,RHPTRCID_SYSPXY_NETMNG_HANDLE_IPC,"xLd",ipcmsg,"IPC",ipcmsg->type);

  switch( ipcmsg->type ){

  case RHP_IPC_NETMNG_REGISTER:

  	_rhp_atomic_inc(&_rhp_netmng_registered);

  	rhp_netmng_send_dumplink(_rhp_sysinfo_netmng_dumplink_cb,NULL);
  	break;

  case RHP_IPC_NETMNG_VIF_CREATE:
  {
  	rhp_ipcmsg_vif_create* vif_create_msg = NULL;

  	if( ipcmsg->len < sizeof(rhp_ipcmsg_vif_create) ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}

  	vif_create_msg = (rhp_ipcmsg_vif_create*)ipcmsg;

  	if( rhp_auth_policy_permitted_if_entry(vif_create_msg->vpn_realm_id,
  				&(vif_create_msg->info_v4)) ){
  		err = -EPERM;
  		goto error;
  	}

  	if( rhp_auth_policy_permitted_if_entry(vif_create_msg->vpn_realm_id,
  				&(vif_create_msg->info_v6)) ){
  		err = -EPERM;
  		goto error;
  	}

  	if( !_rhp_syspxy_netcfg_vif_exists(vif_create_msg->info_v4.if_name) ){

  		rhp_netmng_vif_create(vif_create_msg->interface_type,
  				&(vif_create_msg->info_v4),&(vif_create_msg->info_v6),
  				vif_create_msg->vpn_realm_id,
  				vif_create_msg->exec_up_down,vif_create_msg->v6_disable,vif_create_msg->v6_autoconf);

  		_rhp_syspxy_netcfg_add((rhp_ipcmsg*)vif_create_msg);
  		ipcmsg = NULL;
  	}
  }
  	break;

  case RHP_IPC_NETMNG_VIF_DELETE:
	{
		rhp_ipcmsg_vif_delete* vif_delete_msg = (rhp_ipcmsg_vif_delete*)ipcmsg;

  	if( ipcmsg->len < sizeof(rhp_ipcmsg_vif_delete) ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}

  	if( _rhp_syspxy_netcfg_vif_exists(vif_delete_msg->if_name) ){

  		rhp_netmng_vif_delete(vif_delete_msg->interface_type,vif_delete_msg->if_name);

  		_rhp_syspxy_netcfg_vif_delete(vif_delete_msg->if_name);
  	}
  }
  	break;

  case RHP_IPC_NETMNG_VIF_UPDATE:
	{
		rhp_ipcmsg_vif_update* vif_update_msg = (rhp_ipcmsg_vif_update*)ipcmsg;

  	if( ipcmsg->len < sizeof(rhp_ipcmsg_vif_update) ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}


  	if( rhp_auth_policy_permitted_if_entry(
  				vif_update_msg->vpn_realm_id,&(vif_update_msg->if_info)) ){
  		err = -EPERM;
  		RHP_BUG("");
  		goto error;
  	}

  	if( _rhp_syspxy_netcfg_vif_exists(vif_update_msg->if_info.if_name) ){

  		if( vif_update_msg->updated_flag & RHP_IPC_VIF_DELETE_ADDR ){

  			rhp_netmng_vif_delete_addr(vif_update_msg->updated_flag,&(vif_update_msg->if_info));

  		}else{

  			rhp_netmng_vif_update(vif_update_msg->updated_flag,&(vif_update_msg->if_info));
  		}

  		_rhp_syspxy_netcfg_vif_delete(vif_update_msg->if_info.if_name);
  		_rhp_syspxy_netcfg_add((rhp_ipcmsg*)vif_update_msg);
  		ipcmsg = NULL;
  	}
  }
  	break;

  case RHP_IPC_NETMNG_ROUTE_UPDATE:
  {
  	rhp_ipcmsg_nm_route_update* nm_rt_update = (rhp_ipcmsg_nm_route_update*)ipcmsg;
		unsigned long metric = 0;
		unsigned long metric_base = 0, metric_max = 0;

  	if( ipcmsg->len < sizeof(rhp_ipcmsg_nm_route_update) ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}

  	if( rhp_auth_policy_permitted_addr(nm_rt_update->vpn_realm_id,&(nm_rt_update->dest_addr),&metric_base,&metric_max) ){
  		err = -EPERM;
  		RHP_BUG("");
  		goto error;
  	}

  	if( rhp_auth_policy_permitted_addr(nm_rt_update->vpn_realm_id,&(nm_rt_update->nexthop_addr),NULL,NULL) ){
  		err = -EPERM;
  		RHP_BUG("");
  		goto error;
  	}

  	if( !_rhp_syspxy_netcfg_route_exists(nm_rt_update->if_name,&(nm_rt_update->dest_addr),&(nm_rt_update->nexthop_addr),&metric) ||
  			(metric != nm_rt_update->metric) ){

  		_rhp_syspxy_netcfg_route_delete(nm_rt_update->if_name,&(nm_rt_update->dest_addr),&(nm_rt_update->nexthop_addr));
  		_rhp_syspxy_netcfg_add((rhp_ipcmsg*)nm_rt_update);
  		ipcmsg = NULL;
  	}

		{
			metric = nm_rt_update->metric;

			metric += metric_base;

			if( metric > metric_max ){
				metric = metric_max;
			}

			if( metric < metric_base ){
				metric = metric_base;
			}
		}

		rhp_netmng_route_update(nm_rt_update->if_name,&(nm_rt_update->dest_addr),&(nm_rt_update->nexthop_addr),metric);
  }
  	break;

  case RHP_IPC_NETMNG_ROUTE_DELETE:
  {
  	rhp_ipcmsg_nm_route_delete* nm_rt_delete = (rhp_ipcmsg_nm_route_delete*)ipcmsg;

  	if( ipcmsg->len < sizeof(rhp_ipcmsg_nm_route_delete) ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}

  	if( _rhp_syspxy_netcfg_route_exists(nm_rt_delete->if_name,&(nm_rt_delete->dest_addr),&(nm_rt_delete->nexthop_addr),NULL) ){

  		rhp_netmng_route_delete(nm_rt_delete->if_name,&(nm_rt_delete->dest_addr),&(nm_rt_delete->nexthop_addr));

  		_rhp_syspxy_netcfg_route_delete(nm_rt_delete->if_name,&(nm_rt_delete->dest_addr),&(nm_rt_delete->nexthop_addr));
  	}
  }
  	break;

  case RHP_IPC_NETMNG_DNSPXY_RDIR_START:
  {
  	rhp_ipcmsg_netmng_dns_pxy_rdir* dns_pxy_rdir_start = (rhp_ipcmsg_netmng_dns_pxy_rdir*)ipcmsg;

  	if( ipcmsg->len < sizeof(rhp_ipcmsg_netmng_dns_pxy_rdir) ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}

		if( !_rhp_syspxy_netcfg_dns_pxy_exists(&(dns_pxy_rdir_start->inet_name_server_addr),0) ){

			rhp_netmng_dns_pxy_exec_redir(&(dns_pxy_rdir_start->inet_name_server_addr),
					dns_pxy_rdir_start->internal_port,1);

			_rhp_syspxy_netcfg_dns_pxy_delete(&(dns_pxy_rdir_start->inet_name_server_addr),
					dns_pxy_rdir_start->internal_port);
			_rhp_syspxy_netcfg_add((rhp_ipcmsg*)dns_pxy_rdir_start);
  		ipcmsg = NULL;

  		if( dns_pxy_rdir_start->inet_name_server_addr.addr_family == AF_INET ){
  			RHP_LOG_D(RHP_LOG_SRC_NETMNG,0,RHP_LOG_ID_DNS_PXY_ENABLE_REDIRECT,"4W",dns_pxy_rdir_start->inet_name_server_addr.addr.v4,dns_pxy_rdir_start->internal_port);
  		}else if( dns_pxy_rdir_start->inet_name_server_addr.addr_family == AF_INET6 ){
  			RHP_LOG_D(RHP_LOG_SRC_NETMNG,0,RHP_LOG_ID_DNS_PXY_ENABLE_REDIRECT_V6,"6W",dns_pxy_rdir_start->inet_name_server_addr.addr.v6,dns_pxy_rdir_start->internal_port);
  		}
		}
  }
  	break;

  case RHP_IPC_NETMNG_DNSPXY_RDIR_END:
  {
  	rhp_ipcmsg_netmng_dns_pxy_rdir* dns_pxy_rdir_end = (rhp_ipcmsg_netmng_dns_pxy_rdir*)ipcmsg;

  	if( ipcmsg->len < sizeof(rhp_ipcmsg_netmng_dns_pxy_rdir) ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}

		if( _rhp_syspxy_netcfg_dns_pxy_exists(&(dns_pxy_rdir_end->inet_name_server_addr),dns_pxy_rdir_end->internal_port) ){

			rhp_netmng_dns_pxy_exec_redir(&(dns_pxy_rdir_end->inet_name_server_addr),
					dns_pxy_rdir_end->internal_port,0);

			_rhp_syspxy_netcfg_dns_pxy_delete(&(dns_pxy_rdir_end->inet_name_server_addr),
					dns_pxy_rdir_end->internal_port);

  		if( dns_pxy_rdir_end->inet_name_server_addr.addr_family == AF_INET ){
  			RHP_LOG_D(RHP_LOG_SRC_NETMNG,0,RHP_LOG_ID_DNS_PXY_DISABLE_REDIRECT,"4W",dns_pxy_rdir_end->inet_name_server_addr.addr.v4,dns_pxy_rdir_end->internal_port);
  		}else if( dns_pxy_rdir_end->inet_name_server_addr.addr_family == AF_INET6 ){
  			RHP_LOG_D(RHP_LOG_SRC_NETMNG,0,RHP_LOG_ID_DNS_PXY_DISABLE_REDIRECT_V6,"6W",dns_pxy_rdir_end->inet_name_server_addr.addr.v6,dns_pxy_rdir_end->internal_port);
  		}
		}
  }
  	break;

  case RHP_IPC_NETMNG_BRIDGE_ADD:
  {
  	rhp_ipcmsg_netmng_bridge_ctrl* brctl_add = (rhp_ipcmsg_netmng_bridge_ctrl*)ipcmsg;

  	if( ipcmsg->len < sizeof(rhp_ipcmsg_netmng_bridge_ctrl) ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}

		if( !_rhp_syspxy_netcfg_brctl_exists(brctl_add->bridge_name,brctl_add->vif_name) ){

			rhp_netmng_bridge_ctrl(brctl_add->bridge_name,brctl_add->vif_name,1);

			_rhp_syspxy_netcfg_brctl_delete(brctl_add->bridge_name,brctl_add->vif_name);
			_rhp_syspxy_netcfg_add((rhp_ipcmsg*)brctl_add);
  		ipcmsg = NULL;
		}
  }
  	break;

  case RHP_IPC_NETMNG_BRIDGE_DELETE:
  {
  	rhp_ipcmsg_netmng_bridge_ctrl* brctl_delete = (rhp_ipcmsg_netmng_bridge_ctrl*)ipcmsg;

  	if( ipcmsg->len < sizeof(rhp_ipcmsg_netmng_bridge_ctrl) ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}

		if( _rhp_syspxy_netcfg_brctl_exists(brctl_delete->bridge_name,brctl_delete->vif_name) ){

			rhp_netmng_bridge_ctrl(brctl_delete->bridge_name,brctl_delete->vif_name,0);

			_rhp_syspxy_netcfg_brctl_delete(brctl_delete->bridge_name,brctl_delete->vif_name);
  	}
  }
  	break;


  case RHP_IPC_FIREWALL_RULES_APPLY:

  	err = _rhp_syspxy_netcfg_apply_firewall_rules(ipcmsg);
  	break;

  case RHP_IPC_NETMNG_VIF_EXEC_IPV6_AUTOCONF:
  {
  	rhp_ipcmsg_vif_update* vif_exec_ipv6_autoconf = (rhp_ipcmsg_vif_update*)ipcmsg;

  	if( _rhp_syspxy_netcfg_vif_exists(vif_exec_ipv6_autoconf->if_info.if_name) ){

			rhp_netmng_vif_exec_ipv6_autoconf(vif_exec_ipv6_autoconf->vpn_realm_id,&(vif_exec_ipv6_autoconf->if_info));
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

  RHP_TRC(0,RHPTRCID_SYSPXY_NETMNG_HANDLE_IPC_RTRN_SYSPXY,"E",err);
  return err;
}

int rhp_syspxy_netmng_init()
{
	_rhp_atomic_init(&_rhp_netmng_registered);
  _rhp_mutex_init("SNM",&(_rhp_syspxy_netmng_lock));

	RHP_TRC(0,RHPTRCID_SYSPXY_NETMNG_INIT,"");
	return 0;
}

int rhp_syspxy_netmng_cleanup()
{

	_rhp_syspxy_netcfg_flush();


	_rhp_mutex_destroy(&_rhp_syspxy_netmng_lock);
	_rhp_atomic_destroy(&_rhp_netmng_registered);

	RHP_TRC(0,RHPTRCID_SYSPXY_NETMNG_CLEANUP,"");
	return 0;
}
