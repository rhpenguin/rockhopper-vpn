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

static int _rhp_syspxy_caps_num = 2;
static cap_value_t _rhp_syspxy_caps[] = {CAP_NET_ADMIN,CAP_NET_RAW};

char* rhp_syspxy_auth_conf_path = NULL;

extern char* rhp_netmng_cmd_path;
extern char* rhp_netmng_cmd_dir;

extern char* rhp_mng_cmd_path;
extern char* rhp_mng_cmd_dir;

extern char* rhp_syspxy_cert_store_path;
extern char* rhp_syspxy_policy_conf_path;

extern char* rhp_syspxy_cfg_bkup_cmd_path;
extern char* rhp_syspxy_cfg_bkup_path;

extern char* rhp_syspxy_home_dir;

extern char* rhp_syspxy_cfg_cert_cmd_path;
extern char* rhp_syspxy_cfg_cert_uploaded_path;

extern char* rhp_syspxy_qcd_secret_path;

extern char* rhp_syspxy_sess_resume_key_path;
extern char* rhp_syspxy_sess_resume_old_key_path;

extern char* rhp_syspxy_sess_resume_revocation_bfltr_path;
extern char* rhp_syspxy_sess_resume_revocation_old_bfltr_path;


extern int rhp_syspxy_ui_ipc_handle(rhp_ipcmsg *ipcmsg);

static int _rhp_syspxy_handle_ipc()
{
  int err = 0;
  int ret = 0;
  rhp_ipcmsg *ipcmsg = NULL;

  RHP_TRC(0,RHPTRCID_SYSPXY_HANDLE_IPC,"");

  while( 1 ){

  	unsigned long msg_type;

  	if( (err = rhp_ipc_recvmsg(RHP_MY_PROCESS,&ipcmsg,MSG_DONTWAIT)) ){
  		RHP_TRC(0,RHPTRCID_HANDLE_IPC_RECVMSG_ERR_SYSPXY,"E",err);
  		break;
  	}

    RHP_TRC(0,RHPTRCID_HANDLE_IPC_RECVMSG_SYSPXY,"xLu",ipcmsg,"IPC",ipcmsg->type);

    msg_type = ipcmsg->type;

    switch( ipcmsg->type ){

    case 	RHP_IPC_NOP:
      goto ignore;

    case RHP_IPC_NETMNG_REGISTER:
    case RHP_IPC_NETMNG_VIF_CREATE:
    case RHP_IPC_NETMNG_VIF_DELETE:
    case RHP_IPC_NETMNG_VIF_UPDATE:
    case RHP_IPC_NETMNG_ROUTE_UPDATE:
    case RHP_IPC_NETMNG_ROUTE_DELETE:
    case RHP_IPC_NETMNG_DNSPXY_RDIR_START:
    case RHP_IPC_NETMNG_DNSPXY_RDIR_END:
    case RHP_IPC_NETMNG_BRIDGE_ADD:
    case RHP_IPC_NETMNG_BRIDGE_DELETE:
    case RHP_IPC_FIREWALL_RULES_APPLY:
    case RHP_IPC_NETMNG_VIF_EXEC_IPV6_AUTOCONF:

    	rhp_syspxy_netmng_handle_ipc(ipcmsg); // ipcmsg is freed!
      ipcmsg = NULL;

      if( msg_type == RHP_IPC_NETMNG_REGISTER ){

      	rhp_auth_ipc_send_ca_pubkey_digests_update();
      }
      break;

    case RHP_IPC_EXIT_REQUEST:

      ret = RHP_STATUS_EXIT;
      goto exit;

    case RHP_IPC_AUTH_BASIC_REQUEST:
    case RHP_IPC_AUTH_COOKIE_REQUEST:
    case RHP_IPC_SIGN_REQUEST:
    case RHP_IPC_VERIFY_PSK_REQUEST:
    case RHP_IPC_VERIFY_RSASIG_REQUEST:
    case RHP_IPC_RESOLVE_MY_ID_REQUEST:
    case RHP_IPC_VERIFY_AND_SIGN_REQUEST:

    	// TODO : rhp_prc_ipcmsg_wts_handler should be used for IKEv2's heary crypto processing.
      rhp_auth_ipc_handle(ipcmsg); // ipcmsg is freed!
      ipcmsg = NULL;
      break;

    case RHP_IPC_SYSPXY_CFG_REQUEST:

      rhp_syspxy_ui_ipc_handle(ipcmsg); // ipcmsg is freed!
      ipcmsg = NULL;
      break;

#ifdef RHP_MEMORY_DBG
    case RHP_IPC_SYSPXY_MEMORY_DBG:
    {
      rhp_ipcmsg_syspxy_mem_dbg* mem_dbg = (rhp_ipcmsg_syspxy_mem_dbg*)ipcmsg;

      rhp_memory_dbg_leak_print(mem_dbg->start_time,mem_dbg->elapsing_time);
    }
      break;
#endif // RHP_MEMORY_DBG

    case RHP_IPC_SYSPXY_LOG_CTRL:
    {
    	rhp_ipcmsg_syspxy_log_ctrl* log_ctrl = (rhp_ipcmsg_syspxy_log_ctrl*)ipcmsg;

    	rhp_log_enable_debug_level(log_ctrl->debug_flag);
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
  RHP_TRC(0,RHPTRCID_SYSPXY_HANDLE_IPC_RTRN,"E",ret);
  return ret;
}

static int _rhp_syspxy_conf_parse_netmng_script(xmlNodePtr node,void* ctx)
{
	int ret_len;

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"script"),RHP_XML_DT_STRING,
  		&rhp_netmng_cmd_path,&ret_len,NULL,0) ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"dir"),RHP_XML_DT_STRING,
  		&rhp_netmng_cmd_dir,&ret_len,NULL,0) ){
    RHP_BUG("");
    return -EINVAL;
  }

  return 0;
}

static int _rhp_syspxy_conf_parse_mng_script(xmlNodePtr node,void* ctx)
{
	int ret_len;

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"script"),RHP_XML_DT_STRING,
  		&rhp_mng_cmd_path,&ret_len,NULL,0) ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"dir"),RHP_XML_DT_STRING,
  		&rhp_mng_cmd_dir,&ret_len,NULL,0) ){
    RHP_BUG("");
    return -EINVAL;
  }

  return 0;
}

static int _rhp_syspxy_conf_parse_cfg_bkup_script(xmlNodePtr node,void* ctx)
{
	int ret_len;

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"script"),RHP_XML_DT_STRING,
  		&rhp_syspxy_cfg_bkup_cmd_path,&ret_len,NULL,0) ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"res_dir"),RHP_XML_DT_STRING,
  		&rhp_syspxy_cfg_bkup_path,&ret_len,NULL,0) ){
    RHP_BUG("");
    return -EINVAL;
  }

  return 0;
}

static int _rhp_syspxy_conf_parse_cfg_cert_script(xmlNodePtr node,void* ctx)
{
	int ret_len;

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"script"),RHP_XML_DT_STRING,
  		&rhp_syspxy_cfg_cert_cmd_path,&ret_len,NULL,0) ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"stored_dir"),RHP_XML_DT_STRING,
  		&rhp_syspxy_cfg_cert_uploaded_path,&ret_len,NULL,0) ){
    RHP_BUG("");
    return -EINVAL;
  }

  return 0;
}

static int _rhp_syspxy_conf_parse_home(xmlNodePtr node,void* ctx)
{
	int ret_len;

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"dir"),RHP_XML_DT_STRING,
  		&rhp_syspxy_home_dir,&ret_len,NULL,0) ){
    RHP_BUG("");
    return -EINVAL;
  }

  return 0;
}

static int _rhp_syspxy_conf_parse_auth_conf(xmlNodePtr node,void* ctx)
{
	int ret_len;

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"path"),
  			RHP_XML_DT_STRING,&rhp_syspxy_auth_conf_path,&ret_len,NULL,0) ){
    RHP_BUG("");
    return -EINVAL;
  }

  return 0;
}

static int _rhp_syspxy_conf_parse_cert_store_conf(xmlNodePtr node,void* ctx)
{
	int err;
	int ret_len;

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"path"),
  				RHP_XML_DT_STRING,&rhp_syspxy_cert_store_path,&ret_len,NULL,0);
  if( err == -ENOENT ){
  	err = 0;
  }else if( err ){
    RHP_BUG("%d",err);
    return -EINVAL;
  }

  return 0;
}

static int _rhp_syspxy_conf_parse_policy_conf(xmlNodePtr node,void* ctx)
{
	int err;
	int ret_len;

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"path"),
  			RHP_XML_DT_STRING,&rhp_syspxy_policy_conf_path,&ret_len,NULL,0);
  if( err == -ENOENT ){
  	err = 0;
  }else if( err ){
    RHP_BUG("%d",err);
    return -EINVAL;
  }

  return 0;
}

static int _rhp_syspxy_conf_parse_qcd_secret(xmlNodePtr node,void* ctx)
{
	int ret_len;

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"path"),
  			RHP_XML_DT_STRING,&rhp_syspxy_qcd_secret_path,&ret_len,NULL,0) ){
    RHP_BUG("");
    return -EINVAL;
  }

  return 0;
}

static int _rhp_syspxy_conf_parse_sess_resume_key(xmlNodePtr node,void* ctx)
{
	int ret_len;

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"key_path"),
  			RHP_XML_DT_STRING,&rhp_syspxy_sess_resume_key_path,&ret_len,NULL,0) ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"old_key_path"),
  			RHP_XML_DT_STRING,&rhp_syspxy_sess_resume_old_key_path,&ret_len,NULL,0) ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"revocation_bfltr_path"),
  			RHP_XML_DT_STRING,&rhp_syspxy_sess_resume_revocation_bfltr_path,&ret_len,NULL,0) ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"revocation_old_bfltr_path"),
  			RHP_XML_DT_STRING,&rhp_syspxy_sess_resume_revocation_old_bfltr_path,&ret_len,NULL,0) ){
    RHP_BUG("");
    return -EINVAL;
  }

  return 0;
}


static int _rhp_syspxy_conf_init_load(char* conf_xml_path)
{
  int err = 0;
  xmlDocPtr doc;
  xmlNodePtr root_node;

  RHP_TRC(0,RHPTRCID_SYSPXY_CONF_INIT_LOAD,"s",conf_xml_path);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return -EPERM;
  }

  doc = xmlParseFile(conf_xml_path);
  if( doc == NULL )
  {
    RHP_BUG(" %s ",conf_xml_path);
    return -ENOENT;
  }

  root_node = xmlDocGetRootElement(doc);
  if( root_node == NULL ){
    err = -ENOENT;
    RHP_BUG(" %s ",conf_xml_path);
    goto error;
  }

  if( xmlStrcmp(root_node->name,(xmlChar*)"rhp_protected_config") ){
    err = -ENOENT;
    RHP_BUG(" %s ",conf_xml_path);
    goto error;
  }

  if( (err = rhp_xml_enum_tags(root_node,(xmlChar*)"netmng_script",_rhp_syspxy_conf_parse_netmng_script,NULL,0)) ){
    RHP_BUG("");
    goto error;
  }

  if( (err = rhp_xml_enum_tags(root_node,(xmlChar*)"mng_script",_rhp_syspxy_conf_parse_mng_script,NULL,0)) ){
    RHP_BUG("");
    goto error;
  }

  if( (err = rhp_xml_enum_tags(root_node,(xmlChar*)"home",_rhp_syspxy_conf_parse_home,NULL,0)) ){
    RHP_BUG("");
    goto error;
  }

  if( (err = rhp_xml_enum_tags(root_node,(xmlChar*)"cfg_bkup_script",_rhp_syspxy_conf_parse_cfg_bkup_script,NULL,0)) ){
    RHP_BUG("");
    goto error;
  }

  if( (err = rhp_xml_enum_tags(root_node,(xmlChar*)"cfg_cert_file_script",_rhp_syspxy_conf_parse_cfg_cert_script,NULL,0)) ){
    RHP_BUG("");
    goto error;
  }

  if( (err = rhp_xml_enum_tags(root_node,(xmlChar*)"auth_conf",_rhp_syspxy_conf_parse_auth_conf,NULL,0)) ){
    RHP_BUG("");
    goto error;
  }

  if( (err = rhp_xml_enum_tags(root_node,(xmlChar*)"cert_store",_rhp_syspxy_conf_parse_cert_store_conf,NULL,0)) ){
    RHP_BUG("");
    goto error;
  }

  if( (err = rhp_xml_enum_tags(root_node,(xmlChar*)"policy_conf",_rhp_syspxy_conf_parse_policy_conf,NULL,0)) ){
    RHP_BUG("");
    goto error;
  }

  if( (err = rhp_xml_enum_tags(root_node,(xmlChar*)"qcd_secret",_rhp_syspxy_conf_parse_qcd_secret,NULL,0)) ){
    RHP_BUG("");
    goto error;
  }

  if( (err = rhp_xml_enum_tags(root_node,(xmlChar*)"sess_resume_key",_rhp_syspxy_conf_parse_sess_resume_key,NULL,0)) ){
    RHP_BUG("");
    goto error;
  }


  xmlFreeDoc(doc);

  RHP_TRC(0,RHPTRCID_SYSPXY_CONF_INIT_LOAD_RTRN,"sd",conf_xml_path,0);
  return 0;

error:
  xmlFreeDoc(doc);

  RHP_TRC(0,RHPTRCID_SYSPXY_CONF_INIT_LOAD_RTRN,"sd",conf_xml_path,err);
  return err;
}


extern int rhp_auth_cfg_init();
extern int rhp_ui_log_init();
extern int rhp_ui_log_cleanup();
extern int rhp_eap_init();
extern int rhp_eap_cleanup();
extern int rhp_ikev2_qcd_syspxy_init();
extern int rhp_ikev2_qcd_syspxy_cleanup();
extern int rhp_ikev2_sess_resume_syspxy_init();
extern int rhp_ikev2_sess_resume_syspxy_cleanup();
extern int rhp_auth_init_radius_cfg();
extern int rhp_syspxy_ikev1_auth_init();
extern int rhp_syspxy_ikev1_auth_cleanup();

extern char* rhp_dbg_trace_file_name(int process_role,char* tag);

#ifdef RHP_MEMORY_DBG
extern void rhp_memory_dbg_init();
extern void rhp_memory_dbg_start();
#endif

void rhp_syspxy_run()
{
  int err;
  rhp_process* prc = &(rhp_process_info[RHP_PROCESS_ROLE_SYSPXY]);
  int ep_fd = -1;
  struct epoll_event ep_evt[RHP_SYSPXY_EPOLL_MAX];
  struct rlimit core_ctrl;

  RHP_TRC(0,RHPTRCID_SYSPXY_RUN,"");

  rhp_mem_statistics_init();

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

  if( (err = _rhp_syspxy_conf_init_load(rhp_syspxy_conf_path)) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_syspxy_netmng_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_auth_cfg_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }


  rhp_auth_init_load(rhp_syspxy_auth_conf_path); // Error is ignored...

  if( (err = rhp_caps_set(prc,_rhp_syspxy_caps_num,_rhp_syspxy_caps)) ){
    goto error;
    RHP_BUG("%d",err);
  }

	if( rhp_gcfg_dbg_direct_file_trace ){

		char* f_name = rhp_dbg_trace_file_name(RHP_PROCESS_ROLE_SYSPXY,"syspxy");
		if( f_name ){
			rhp_trace_f_init(f_name,rhp_gcfg_dbg_f_trace_max_size);
			free(f_name); // Don't use rhp_free()!
		}
	}

  rhp_ipc_close(RHP_PEER_PROCESS);

  if( (err = rhp_wts_init(rhp_gcfg_wts_syspxy_workers)) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_timer_start()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_netmng_init(rhp_gcfg_ipv6_disabled)) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_cert_start()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_eap_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_ikev2_qcd_syspxy_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_ikev2_sess_resume_syspxy_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_syspxy_ikev1_auth_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }


  memset(ep_evt,0,sizeof(struct epoll_event)*RHP_SYSPXY_EPOLL_MAX);

//  ep_evt[0].events = EPOLLIN | EPOLLERR;
  ep_evt[0].events = EPOLLIN;
  ep_evt[0].data.fd = rhp_nl_sk;

//  ep_evt[1].events = EPOLLIN | EPOLLERR;
  ep_evt[1].events = EPOLLIN;
  ep_evt[1].data.fd = RHP_MY_PROCESS->ipc_read_pipe;

  if( (ep_fd = epoll_create(RHP_SYSPXY_EPOLL_MAX)) < 0 ){
    err = -errno;
    RHP_BUG("%d",err);
    goto error;
  }

  if( epoll_ctl(ep_fd,EPOLL_CTL_ADD,rhp_nl_sk,&(ep_evt[0])) < 0 ){
    err = -errno;
    RHP_BUG("%d",err);
    goto error;
  }

  if( epoll_ctl(ep_fd,EPOLL_CTL_ADD,RHP_MY_PROCESS->ipc_read_pipe,&(ep_evt[1])) < 0 ){
    err = -errno;
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_ui_log_init()) ){
    RHP_BUG("%d",err);
    goto error;
  }

	err = rhp_auth_init_radius_cfg();
	if( err ){
    RHP_BUG("%d",err);
    goto error;
	}


  RHP_TRC(0,RHPTRCID_SYSPXY_RUN_START,"d",ep_fd);
  RHP_LOG_I(RHP_LOG_SRC_SYSPXY,0,RHP_LOG_ID_PROTECTED_PROCESS_START,"");

  while( 1 ){

    int i;
    int evtnum;

    if( !RHP_PROCESS_IS_ACTIVE() ){
      RHP_TRC(0,RHPTRCID_SYS_PXY_NOT_ACTIVE_1,"");
      break;
    }

    if( (evtnum = epoll_wait(ep_fd,ep_evt,RHP_SYSPXY_EPOLL_MAX,RHP_EPOLL_POLLTIME)) < 0 ){

      err = -errno;

      RHP_TRC(0,RHPTRCID_SYSPXY_EPOLL_WAIT_ERROR,"E",err);

      if( err == -EINTR ){
    	  err = 0;
        continue;
      }

      goto error;

    }else if( evtnum == 0 ){
      continue;
    }

    for( i = 0; i < evtnum; i++ ){

    	RHP_TRC(0,RHPTRCID_SYSPXY_EPOLL_EVENT,"dddx",i,evtnum,ep_evt[i].data.fd,ep_evt[i].events);

    	if( !RHP_PROCESS_IS_ACTIVE() ){
        RHP_TRC(0,RHPTRCID_SYS_PXY_NOT_ACTIVE_2,"");
        break;
      }

    	if( ep_evt[i].events & EPOLLERR ){
    		RHP_TRC(0,RHPTRCID_EPOLL_IPC_ERROR,"x",ep_evt[i].events);
    		RHP_BUG("");
    	}

  		if( ep_evt[i].data.fd == rhp_nl_sk ){

  			RHP_TRC(0,RHPTRCID_EPOLL_EVENT_NL_SK,"x",ep_evt[i].data.fd);

  			rhp_syspxy_handle_netmng();

  		}else if( ep_evt[i].data.fd == RHP_MY_PROCESS->ipc_read_pipe ){

  			RHP_TRC(0,RHPTRCID_EPOLL_EVENT_IPC_SK,"x",ep_evt[i].data.fd);

  			if( _rhp_syspxy_handle_ipc() == RHP_STATUS_EXIT ){
  				RHP_TRC(0,RHPTRCID_HANDLE_IPC_EXIT,"");
  				goto error;
        }

  		}else{
       RHP_TRC(0,RHPTRCID_EPOLL_EVENT_UNKNOWN,"x",ep_evt[i].data.fd);
      }
    }
  }

error:
  if( ep_fd > 0 ){
    close(ep_fd);
  }

  rhp_ui_log_cleanup();

  rhp_syspxy_ikev1_auth_cleanup();

  rhp_ikev2_sess_resume_syspxy_cleanup();

  rhp_ikev2_qcd_syspxy_cleanup();

	rhp_eap_cleanup();

  rhp_syspxy_netmng_cleanup();

  rhp_netmng_cleanup();
  rhp_free_caps(prc);

  xmlCleanupParser();

  rhp_cmd_exec_cleanup();

#ifdef RHP_REFCNT_DEBUG
#ifdef RHP_REFCNT_DEBUG_X
  rhp_refcnt_dbg_cleanup();
#endif // RHP_REFCNT_DEBUG_X
#endif // RHP_REFCNT_DEBUG

  RHP_TRC(0,RHPTRCID_SYSPXY_RUN_RTRN,"");
  return;
}
