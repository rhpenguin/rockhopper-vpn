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
#include "rhp_dns_pxy.h"
#include "rhp_pcap.h"


static int _rhp_main_caps_num = 2;
static cap_value_t _rhp_main_caps[] = {CAP_NET_BIND_SERVICE,CAP_NET_RAW};

int rhp_main_net_epoll_fd = -1;
int rhp_main_admin_epoll_fd = -1;

static rhp_thread_t _rhp_main_admin_thread;
static u32 _rhp_ikev2_ike_auth_ipc_handle_rnd = 0;

u8 rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_MAX + 1];
unsigned long rhp_packet_capture_realm_id = 0;


static int _rhp_main_ipc_start()
{
  int err = 0;

  err = rhp_main_netmng_ipc_start();
  if( err ){
  	goto error;
  }

error:

  RHP_TRC(0,RHPTRCID_MAIN_IPC_START,"E",err);
  return err;
}

static u32 _rhp_ikev2_ike_auth_ipc_handle_disp_hash(void *key_seed,int* err)
{
  rhp_ipcmsg_auth_comm* auth_comm = (rhp_ipcmsg_auth_comm*)key_seed;
  u32* tmp = (u32*)&(auth_comm->txn_id);
  return _rhp_hash_2u32(tmp[0],tmp[1],_rhp_ikev2_ike_auth_ipc_handle_rnd);
}

static void _rhp_ikev2_ike_auth_ipc_handle_cb(int worker_idx,void* ctx)
{
  rhp_ipcmsg *ipcmsg = (rhp_ipcmsg*)ctx;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_CB,"dx",worker_idx,ipcmsg);

  rhp_ikev2_ike_auth_ipc_handle(ipcmsg);
  if( ipcmsg ){
    _rhp_free_zero(ipcmsg,ipcmsg->len);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_CB_RTRN,"x",ipcmsg);
  return;
}

extern int rhp_ui_log_syspxy_ipc_handle(rhp_ipcmsg* ipcmsg);

static int _rhp_main_handle_ipc()
{
  int ret = 0;
  rhp_ipcmsg *ipcmsg = NULL;

  RHP_TRC(0,RHPTRCID_MAIN_HANDLE_IPC,"");

  while( 1 ){

		if( rhp_ipc_recvmsg(RHP_MY_PROCESS,&ipcmsg,MSG_DONTWAIT) ){
			RHP_TRC(0,RHPTRCID_HANDLE_IPC_RECVMSG_ERR_MAIN,"");
			break;
		}

		RHP_TRC(0,RHPTRCID_MAIN_HANDLE_IPC_RECVMSG_MAIN,"xLu",ipcmsg,"IPC",ipcmsg->type);

		switch( ipcmsg->type ){

		case RHP_IPC_EXIT_REQUEST:
			ret = RHP_STATUS_EXIT;
			goto exit;

		case RHP_IPC_NOP:
			goto ignore;

		case RHP_IPC_NETMNG_UPDATE_IF:
		case RHP_IPC_NETMNG_UPDATE_ADDR:
		case RHP_IPC_NETMNG_DELETE_ADDR:
		case RHP_IPC_NETMNG_DELETE_IF:
		case RHP_IPC_NETMNG_ROUTEMAP_UPDATED:
		case RHP_IPC_NETMNG_ROUTEMAP_DELETED:

			ret = rhp_main_ipc_handle(ipcmsg);
			ipcmsg = NULL;
			break;

		case RHP_IPC_SIGN_PSK_REPLY:
		case RHP_IPC_VERIFY_PSK_REPLY:
		case RHP_IPC_SIGN_RSASIG_REPLY:
		case RHP_IPC_VERIFY_RSASIG_REPLY:
		case RHP_IPC_VERIFY_AND_SIGN_REPLY:

			if( ipcmsg->len < sizeof(rhp_ipcmsg_auth_comm) ){
				RHP_BUG("%d",ipcmsg->len);
				goto ignore;
			}

			if( (ret = rhp_wts_dispach_check(RHP_WTS_DISP_LEVEL_HIGH_1,0)) ){ // Waiting...
				RHP_BUG("%d",ret);
				goto ignore;
			}

			ret = rhp_wts_add_task(RHP_WTS_DISP_RULE_AUTHREP,RHP_WTS_DISP_LEVEL_HIGH_1,ipcmsg,_rhp_ikev2_ike_auth_ipc_handle_cb,ipcmsg);
			if( ret ){
				RHP_BUG("%d",ret);
				goto ignore;
			}
			ipcmsg = NULL;

			break;

		case RHP_IPC_AUTH_BASIC_REPLY:
		case RHP_IPC_AUTH_COOKIE_REPLY:
		{
			if( ipcmsg->len < sizeof(rhp_ipcmsg_auth_rep) ){
				RHP_BUG("%d",ipcmsg->len);
				goto ignore;
			}

			if( ((rhp_ipcmsg_auth_rep*)ipcmsg)->request_user == RHP_IPC_USER_ADMIN_SERVER_HTTP ){

				rhp_http_server_auth_ipc_handle(ipcmsg);

			}else{
			 RHP_BUG("%d",((rhp_ipcmsg_auth_rep*)ipcmsg)->request_user);
			 goto ignore;
			}
		}
			break;

		case RHP_IPC_SYSPXY_CFG_REPLY:
		{
			if( ipcmsg->len < sizeof(rhp_ipcmsg_syspxy_cfg_rep) ){
				RHP_BUG("%d",ipcmsg->len);
				goto ignore;
			}

			if( ((rhp_ipcmsg_syspxy_cfg_rep*)ipcmsg)->request_user == RHP_IPC_USER_ADMIN_SERVER_HTTP ){

				rhp_http_server_cfg_ipc_handle(ipcmsg);

			}else{
			 RHP_BUG("%d",((rhp_ipcmsg_syspxy_cfg_rep*)ipcmsg)->request_user);
			 goto ignore;
			}
		}
			break;

		case RHP_IPC_RESOLVE_MY_ID_REPLY:
		case RHP_IPC_CA_PUBKEY_DIGESTS_UPDATE:

			rhp_cfg_ipc_handle(ipcmsg);
			ipcmsg = NULL;
			break;

		case RHP_IPC_SYSPXY_LOG_RECORD:
		{
			if( ipcmsg->len < sizeof(rhp_ipcmsg_syspxy_log_record) ){
				RHP_BUG("%d",ipcmsg->len);
				goto ignore;
			}

			rhp_ui_log_syspxy_ipc_handle(ipcmsg);
			ipcmsg = NULL;
		}
			break;

		default:

			rhp_ipc_call_handler(RHP_MY_PROCESS,&ipcmsg);
			break;
		}

ignore:
		if( ipcmsg ){
			_rhp_free_zero(ipcmsg,ipcmsg->len);
		}
  }

exit:
  RHP_TRC(0,RHPTRCID_MAIN_HANDLE_IPC_RTRN,"E",ret);
  return ret;
}

static void* _rhp_main_admin_run(void* arg)
{
  int err;
  struct epoll_event *ep_evt = NULL;

  RHP_TRC(0,RHPTRCID_MAIN_ADMIN_RUN,"");

  err = rhp_sig_clear();
  if( err ){
  	RHP_BUG("%",err);
  	return NULL;
  }

  rhp_trace_tid = gettid();

  RHP_TRC(0,RHPTRCID_MAIN_ADMIN_RUN_START,"d",rhp_trace_tid);

  ep_evt = (struct epoll_event*)_rhp_malloc(sizeof(struct epoll_event)*rhp_gcfg_main_epoll_events);
  if( ep_evt == NULL ){
  	RHP_BUG("");
  	goto error;
  }
  memset(ep_evt,0,sizeof(struct epoll_event)*rhp_gcfg_main_epoll_events);

  RHP_TRC(0,RHPTRCID_MAIN_ADMIN_RUN_START,"");

  while( 1 ){

  	int i;
  	int evtnum;

  	if( !RHP_PROCESS_IS_ACTIVE() ){
      RHP_TRC(0,RHPTRCID_NOT_ACTIVE,"s","rhp_main_admin_run():1");
      break;
    }

  	if( (evtnum = epoll_wait(rhp_main_admin_epoll_fd,ep_evt,rhp_gcfg_main_epoll_events,RHP_EPOLL_POLLTIME)) < 0 ){

  		err = -errno;

  		RHP_TRC(0,RHPTRCID_EPOLL_ERROR,"d",err);

  		if( err == -EINTR ){
  			err = 0;
  			continue;
      }

  		RHP_TRCSTR(0,"rhp_main_admin_epoll_fd:0x%x",rhp_main_admin_epoll_fd);

  		goto error;

  	}else if( evtnum == 0 ){
  		continue;
    }

  	for( i = 0; i < evtnum; i++ ){

  		if( !RHP_PROCESS_IS_ACTIVE() ){
        RHP_TRC(0,RHPTRCID_NOT_ACTIVE,"s","rhp_main_admin_run():2");
        break;
      }

  		RHP_TRC(0,RHPTRCID_EPOLL_EVENT,"xd",ep_evt[i].data.ptr,((rhp_epoll_ctx*)ep_evt[i].data.ptr)->event_type);

  		switch( ((rhp_epoll_ctx*)ep_evt[i].data.ptr)->event_type ){

  		case RHP_MAIN_EPOLL_HTTP_LISTEN:
  			rhp_http_server_listen_handle_event(&(ep_evt[i]));
  			break;

  		case RHP_MAIN_EPOLL_HTTP_SERVER:
  			rhp_http_server_conn_handle_event(&(ep_evt[i]));
  			break;

  		default:
  			RHP_BUG("0x%x",((rhp_epoll_ctx*)ep_evt[i].data.ptr)->event_type);
  			break;
  		}
  	}
  }

error:
	if( ep_evt ){
   _rhp_free(ep_evt);
  }

  RHP_TRC(0,RHPTRCID_MAIN_ADMIN_RUN_RTRN,"");
  return NULL;
}


extern int rhp_ikev2_init();
extern void rhp_ikev2_cleanup();
extern int rhp_ikev1_init();
extern void rhp_ikev1_cleanup();
extern int rhp_vpn_init();
extern int rhp_vpn_cleanup();
extern int rhp_ui_init();
extern int rhp_ui_cleanup();
extern int rhp_bridge_init();
extern int rhp_bridge_cleanup();
extern int rhp_ip_bridge_init();
extern int rhp_ip_bridge_cleanup();
extern int rhp_esp_init();
extern int rhp_esp_cleanup();
extern int rhp_eap_init();
extern int rhp_eap_cleanup();
extern int rhp_pkt_main_init();
extern int rhp_dns_pxy_main_init();
extern int rhp_dns_pxy_main_cleanup();
extern int rhp_vpn_conn_mng_init();
extern int rhp_ui_log_init();
extern int rhp_ui_log_cleanup();
extern int rhp_rtmapc_init();
extern int rhp_rtmapc_cleanup();
extern int rhp_ikev2_qcd_init();
extern int rhp_ikev2_qcd_cleanup();
extern int rhp_ikev2_mobike_init();
extern int rhp_ikev2_mobike_cleanup();
extern int rhp_dns_resolve_init();
extern int rhp_dns_resolve_cleanup();
extern int rhp_ikev2_sess_resume_init();
extern int rhp_ikev2_sess_resume_cleanup();
extern int rhp_ikev2_rx_internal_net_init();
extern int rhp_ikev2_rx_internal_net_cleanup();
extern int rhp_radius_acct_init();
extern int rhp_radius_acct_cleanup();
extern int rhp_ip_routing_init();
extern int rhp_ip_routing_cleanup();
extern int rhp_nhrp_init();
extern int rhp_nhrp_cleanup();


extern void rhp_realm_set_notifiers();
extern int rhp_ip_routing_set_notifier();


extern int rhp_http_clt_main_handle_event(struct epoll_event* epoll_evt);

extern char* rhp_dbg_trace_file_name(int process_role,char* tag);

extern void rhp_ui_http_packet_capture_timer_update_cb(rhp_pcap_status* status,void* cb_ctx);


static RHP_EPOLL_EVENT_CB _epoll_event_callbacks[RHP_MAIN_EPOLL_EVENT_CALLBACKS_MAX];

int rhp_main_epoll_register(
		int event_type, // RHP_MAIN_EPOLL_XXX (>= RHP_MAIN_EPOLL_EVENT_CB_START)
		RHP_EPOLL_EVENT_CB event_cb)
{
	if( event_type >= RHP_MAIN_EPOLL_EVENT_CB_START &&
			event_type < (RHP_MAIN_EPOLL_EVENT_CB_START + RHP_MAIN_EPOLL_EVENT_CALLBACKS_MAX) ){

		_epoll_event_callbacks[event_type - RHP_MAIN_EPOLL_EVENT_CB_START] = event_cb;

		return 0;
	}

	RHP_BUG("%d",event_type);
	return -EINVAL;
}


void rhp_main_pre_cleanup()
{
	if( !rhp_vpn_forcedly_close_conns(0) ){
		sleep(rhp_gcfg_forcedly_close_vpns_wait_secs);
	}
}

#ifdef RHP_MEMORY_DBG
extern void rhp_memory_dbg_init();
extern void rhp_memory_dbg_start();
#endif

#ifdef RHP_EVENT_FUNCTION
extern int rhp_event_init();
#endif // RHP_EVENT_FUNCTION


void rhp_main_run()
{
  int err;
  rhp_process* prc = &(rhp_process_info[RHP_PROCESS_ROLE_MAIN]);
  struct epoll_event *ep_evt = NULL;
  rhp_epoll_ctx ipc_ctx;
  struct rlimit core_ctrl;

  RHP_TRC(0,RHPTRCID_MAIN_RUN,"");

  rhp_mem_statistics_init();


  memset(rhp_syspxy_conf_path,0,strlen(rhp_syspxy_conf_path)+1);

  memset(_epoll_event_callbacks,0,sizeof(RHP_EPOLL_EVENT_CB)*RHP_MAIN_EPOLL_EVENT_CALLBACKS_MAX);

  memset(rhp_packet_capture_flags,0,sizeof(u8)*(RHP_PKT_CAP_FLAG_MAX + 1));


  if( RHP_MY_PROCESS->core_dump && RHP_MY_PROCESS->debug ){
    core_ctrl.rlim_cur = RLIM_INFINITY;
    core_ctrl.rlim_max = RLIM_INFINITY;
  }else{
    core_ctrl.rlim_cur = 0;
    core_ctrl.rlim_max = 0;
  }
  setrlimit(RLIMIT_CORE, &core_ctrl);

#ifdef RHP_MEMORY_DBG
  rhp_memory_dbg_init();
  rhp_memory_dbg_start();
#endif

  xmlInitParser();

#ifdef RHP_REFCNT_DEBUG
#ifdef RHP_REFCNT_DEBUG_X
  rhp_refcnt_dbg_init();
#endif // RHP_REFCNT_DEBUG_X
#endif // RHP_REFCNT_DEBUG


  if( (err = rhp_cmd_exec_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_crypto_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_cert_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_cfg_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_dns_resolve_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_vpn_conn_mng_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  rhp_cfg_init_load(rhp_main_conf_path); // Error is ignored...


  ep_evt = (struct epoll_event*)_rhp_malloc(sizeof(struct epoll_event)*rhp_gcfg_main_epoll_events);
  if( ep_evt == NULL ){
    err = -ENOMEM;
    RHP_BUG("%d",err);
    goto error;
  }
  memset(ep_evt,0,sizeof(struct epoll_event)*rhp_gcfg_main_epoll_events);

  if( (err = rhp_caps_set(prc,_rhp_main_caps_num,_rhp_main_caps)) ){
    RHP_BUG("%d",err);
    goto error;
  }


	if( rhp_gcfg_dbg_direct_file_trace ){

		char* f_name = rhp_dbg_trace_file_name(RHP_PROCESS_ROLE_MAIN,"main");
		if( f_name ){
			rhp_trace_f_init(f_name,rhp_gcfg_dbg_f_trace_max_size);
			free(f_name); // Don't use rhp_free()!
		}
	}


  if( (err = rhp_wts_init(rhp_gcfg_wts_main_workers)) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_timer_start()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_ifc_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_rtmapc_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_cert_start()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_pkt_main_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  rhp_ipc_close(RHP_PEER_PROCESS);

  if( (err = rhp_ikev2_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_ikev1_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_netsock_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_tuntap_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_vpn_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }


  err = rhp_pcap_init(
  				(time_t)rhp_gcfg_packet_capture_timer_check_interval,
  				rhp_ui_http_packet_capture_timer_update_cb,NULL);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }


  if( (err = rhp_bridge_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_ip_bridge_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_ip_routing_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_esp_init()) ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  if( (err = rhp_http_server_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_eap_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_ikev2_qcd_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_ikev2_rx_internal_net_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_ikev2_mobike_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_ikev2_sess_resume_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_nhrp_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_radius_acct_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }


#ifdef RHP_EVENT_FUNCTION
  if( (err = rhp_event_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }
#endif // RHP_EVENT_FUNCTION

  if( (err = rhp_ui_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }


  {
    if( (rhp_main_net_epoll_fd = epoll_create(rhp_gcfg_main_epoll_events)) < 0 ){
      err = -errno;
      RHP_BUG("%d",err);
      goto error;
    }

  	// EPOLL callbacks DON'T sleep!
    if( (rhp_main_admin_epoll_fd = epoll_create(rhp_gcfg_main_epoll_events)) < 0 ){
      err = -errno;
      RHP_BUG("%d",err);
      goto error;
    }

    memset(&ipc_ctx,sizeof(0),sizeof(rhp_epoll_ctx));
    ipc_ctx.event_type = RHP_MAIN_EPOLL_IPC;
//    ep_evt[0].events = EPOLLIN | EPOLLERR;
    ep_evt[0].events = EPOLLIN;
    ep_evt[0].data.ptr = (void*)&ipc_ctx;

    if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_ADD,RHP_MY_PROCESS->ipc_read_pipe,&(ep_evt[0])) < 0 ){
      err = -errno;
      RHP_BUG("%d",err);
      goto error;
    }
  }

  rhp_realm_set_notifiers();
  rhp_ip_routing_set_notifier();

  {
    if( rhp_random_bytes((u8*)&_rhp_ikev2_ike_auth_ipc_handle_rnd,sizeof(_rhp_ikev2_ike_auth_ipc_handle_rnd)) ){
      RHP_BUG("");
      err = -EINVAL;
      goto error;
    }

    err = rhp_wts_register_disp_rule(RHP_WTS_DISP_RULE_AUTHREP,_rhp_ikev2_ike_auth_ipc_handle_disp_hash);
    if( err ){
      RHP_BUG("%d",err);
      goto error;
    }
  }


  if( (err = _rhp_main_ipc_start()) ){
    RHP_BUG("%d",err);
    goto error;
  }

	RHP_LOCK(&rhp_cfg_lock);
	{
		err = rhp_cfg_apply_firewall_rules(rhp_cfg_firewall_rules,rhp_cfg_admin_services);
		if( err ){
	  	RHP_UNLOCK(&rhp_cfg_lock);
	    RHP_BUG("%d",err);
	    goto error;
		}
	}
	RHP_UNLOCK(&rhp_cfg_lock);

  {
    if( (err = rhp_ipc_send_my_ids_resolve_req()) ){
      RHP_BUG("%d",err);
      goto error;
    }

    if( (err = rhp_realms_setup_vif()) ){
      RHP_BUG("%d",err);
      goto error;
    }
  }


  {
    if( ( err = _rhp_thread_create(&_rhp_main_admin_thread,_rhp_main_admin_run,NULL)) ){
      err = -err;
      RHP_BUG("");
      goto error;
    }

    if( (err = rhp_admin_servers_start()) ){

      rhp_admin_servers_retry_start();

      err = 0;
    }
  }

  if( (err = rhp_dns_pxy_main_init()) ){ // After epoll_create()....
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_ui_log_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  rhp_vpn_aoc_start();

  RHP_TRC(0,RHPTRCID_MAIN_RUN_START,"dd",rhp_main_net_epoll_fd,rhp_main_admin_epoll_fd);
  RHP_LOG_I(RHP_LOG_SRC_MAIN,0,RHP_LOG_ID_MAIN_PROCESS_START,"");

  while( 1 ){

  	int i;
  	int evtnum;

  	if( !RHP_PROCESS_IS_ACTIVE() ){
      RHP_TRC(0,RHPTRCID_MAIN_NOT_ACTIVE_1,"");
      break;
    }

  	RHP_TRC_FREQ(0,RHPTRCID_EPOLL_WAIT,"d",rhp_main_net_epoll_fd);

  	if( (evtnum = epoll_wait(rhp_main_net_epoll_fd,ep_evt,rhp_gcfg_main_epoll_events,RHP_EPOLL_POLLTIME)) < 0 ){

  		err = -errno;

  		RHP_TRC(0,RHPTRCID_MAIN_EPOLL_WAIT_ERROR,"dE",rhp_main_net_epoll_fd,err);

     if( err == -EINTR ){
    	 err = 0;
       continue;
      }

      goto error;

    }else if( evtnum == 0 ){ // EPOLL timeout/No event has occured.

    	rhp_dns_pxy_exec_gc();

    	continue;
    }

  	for( i = 0; i < evtnum; i++ ){

  		rhp_epoll_ctx* epoll_ctx;

  		if( !RHP_PROCESS_IS_ACTIVE() ){
        RHP_TRC(0,RHPTRCID_MAIN_NOT_ACTIVE_2,"");
        break;
      }

  		epoll_ctx = (rhp_epoll_ctx*)ep_evt[i].data.ptr;

  		RHP_TRC(0,RHPTRCID_MAIN_EPOLL_EVENT,"ddxLdx",i,evtnum,ep_evt[i].data.ptr,"MAIN_EOPLL_EVENT",epoll_ctx->event_type,ep_evt[i].events);

  		if( ep_evt[i].events & EPOLLERR ){
    		RHP_TRC(0,RHPTRCID_MAIN_EPOLL_EVENT_ERR,"ddxLd",i,evtnum,ep_evt[i].data.ptr,"MAIN_EOPLL_EVENT",epoll_ctx->event_type);
  		}

  		switch( epoll_ctx->event_type ){

  		case RHP_MAIN_EPOLL_IPC:

				if( _rhp_main_handle_ipc() == RHP_STATUS_EXIT ){ // This call may sleep...
					RHP_TRC(0,RHPTRCID_MAIN_HANDLE_IPC_EXIT,"");
					goto error;
				}
  			break;

  		case RHP_MAIN_EPOLL_NETSOCK: // Dispached to WThreads... This call DOESN'T sleep...

  			rhp_netsock_handle_event(&(ep_evt[i]));
 				break;

  		case RHP_MAIN_EPOLL_TUNDEV: // Dispached to WThreads... This call DOESN'T sleep...

  			rhp_tuntap_handle_event(&(ep_evt[i]));
  			break;

  		case RHP_MAIN_EPOLL_DNSPXY_RSLVR:
  		case RHP_MAIN_EPOLL_DNSPXY_PROTECTED_V4:
  		case RHP_MAIN_EPOLL_DNSPXY_PROTECTED_V6:
  		case RHP_MAIN_EPOLL_DNSPXY_INET_V4:
  		case RHP_MAIN_EPOLL_DNSPXY_INET_V6:

				rhp_dns_pxy_main_handle_event(&(ep_evt[i]));
				break;

  		case RHP_MAIN_EPOLL_HTTP_CLT_GET_CONNECT:
  		case RHP_MAIN_EPOLL_HTTP_CLT_GET_RECV:

				rhp_http_clt_main_handle_event(&(ep_evt[i]));
  			break;

  		default:

  			if( epoll_ctx->event_type >= RHP_MAIN_EPOLL_EVENT_CB_START &&
  					epoll_ctx->event_type < (RHP_MAIN_EPOLL_EVENT_CB_START + RHP_MAIN_EPOLL_EVENT_CALLBACKS_MAX) ){

  				RHP_EPOLL_EVENT_CB epoll_event_cb;

  				if( (epoll_event_cb = _epoll_event_callbacks[epoll_ctx->event_type - RHP_MAIN_EPOLL_EVENT_CB_START]) ){

  					err = epoll_event_cb(&(ep_evt[i]),epoll_ctx);

  				}else{

  					err = -ENOENT;
  				}
    			if( err ){
    			  RHP_TRC(0,RHPTRCID_MAIN_RUN_EVENT_CB_ERR,"xdxdYE",&(ep_evt[i]),i,epoll_ctx,_epoll_event_callbacks[epoll_ctx->event_type - RHP_MAIN_EPOLL_EVENT_CB_START],err);
    			}

  			}else{

  				RHP_BUG("%d",epoll_ctx->event_type);
  			}

  			break;
  		}
  	}
  }

error:

	rhp_ui_cleanup();

	rhp_ui_log_cleanup();

	rhp_vpn_aoc_stop();

	rhp_admin_servers_stop();

	rhp_dns_pxy_main_cleanup();

	rhp_radius_acct_cleanup();

	rhp_nhrp_cleanup();

	rhp_ikev2_sess_resume_cleanup();

	rhp_ikev2_rx_internal_net_cleanup();

	rhp_ikev2_mobike_cleanup();

	rhp_ikev2_qcd_cleanup();

	rhp_eap_cleanup();

  rhp_http_server_cleanup();

  rhp_esp_cleanup();

  rhp_ikev1_cleanup();
  rhp_ikev2_cleanup();

  rhp_ip_routing_cleanup();
  rhp_ip_bridge_cleanup();
  rhp_bridge_cleanup();

	rhp_pcap_cleanup();

  rhp_vpn_cleanup();

  rhp_rtmapc_cleanup();
  rhp_ifc_cleanup();

  rhp_dns_resolve_cleanup();

	if( rhp_main_net_epoll_fd > 0 ){
		close(rhp_main_net_epoll_fd);
  }

	if( rhp_main_admin_epoll_fd > 0 ){
		close(rhp_main_admin_epoll_fd);
  }

  rhp_free_caps(prc);

  if( ep_evt ){
   _rhp_free(ep_evt);
  }

  xmlCleanupParser();
  rhp_cmd_exec_cleanup();

#ifdef RHP_REFCNT_DEBUG
#ifdef RHP_REFCNT_DEBUG_X
  rhp_refcnt_dbg_cleanup();
#endif // RHP_REFCNT_DEBUG_X
#endif // RHP_REFCNT_DEBUG

  RHP_TRC(0,RHPTRCID_MAIN_RUN_RTRN,"");

  return;
}


