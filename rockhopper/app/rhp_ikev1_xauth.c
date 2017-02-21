/*

	Copyright (C) 2015-2016 TETSUHARU HANADA <rhpenguine@gmail.com>
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

#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_protocol.h"
#include "rhp_packet.h"
#include "rhp_netsock.h"
#include "rhp_wthreads.h"
#include "rhp_packet.h"
#include "rhp_config.h"
#include "rhp_ikev2_mesg.h"
#include "rhp_vpn.h"
#include "rhp_ikev2.h"
#include "rhp_forward.h"
#include "rhp_eap.h"
#include "rhp_eap_auth_impl.h"
#include "rhp_eap_sup_impl.h"
#include "rhp_radius_impl.h"



u8 rhp_proto_ikev1_xauth_vid[8]
= {0x09,0,0x26,0x89,0xDF,0xD6,0xB7,0x12};


extern int rhp_ikev2_eap_auth_set_peer_ident(rhp_vpn* vpn);

extern int rhp_ikev2_ike_auth_r_eap_rebind_rlm(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg);

extern int rhp_ikev1_rx_r_comp(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_vpn_realm* rlm,
		rhp_ikev2_mesg* rx_ikemesg,int is_rekeyed);

extern int rhp_ikev1_r_clear_old_vpn(rhp_vpn* new_vpn,rhp_ikesa** new_ikesa,
		int rx_initial_contact,int* is_rekeyed_r);

extern int rhp_ikev1_recv_impl(int addr_family,rhp_packet* pkt);


static int _rhp_ikev1_rx_xauth_r_update_p2_sess(rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_ikemesg)
{
	int err = -EINVAL;
	rhp_ikev1_p2_session* p2_sess;
	u8 exchange_type = rx_ikemesg->get_exchange_type(rx_ikemesg);
	u32 mesg_id = rx_ikemesg->get_mesg_id(rx_ikemesg);

	RHP_TRC(0,RHPTRCID_IKEV1_RX_XAUTH_R_UPDATE_P2_SESS,"xxbkLd",ikesa,rx_ikemesg,exchange_type,mesg_id,"IKESA_STAT",ikesa->state);

	p2_sess = rhp_ikev1_p2_session_get(ikesa,mesg_id,exchange_type);
	if( p2_sess ){

		if( rx_ikemesg->v1_p2_iv_len == p2_sess->iv_len ){

			memcpy(p2_sess->iv_last_rx_blk,
				rx_ikemesg->v1_p2_rx_last_blk,rx_ikemesg->v1_p2_iv_len);
		}

		err = 0;

	}else{

		RHP_BUG("0x%lx, %d, %d",p2_sess,rx_ikemesg->v1_p2_iv_len,(p2_sess ? p2_sess->iv_len : 0));
		err = -EINVAL;
	}

	RHP_TRC(0,RHPTRCID_IKEV1_RX_XAUTH_R_UPDATE_P2_SESS_RTRN,"xxx",ikesa,rx_ikemesg,p2_sess);
	return err;
}


static int _rhp_ikev1_xauth_r_init(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
	rhp_vpn_realm* rlm = vpn->rlm;

  RHP_TRC(0,RHPTRCID_IKEV1_XAUTH_R_INIT,"xxx",vpn,ikesa,rx_ikemesg,tx_ikemesg);


  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV1_XAUTH_R_INIT_RLM_NOT_ACTIVE,"xxx",vpn,ikesa,rx_ikemesg,rlm);
    goto error_l;
  }


	vpn->eap.impl_ctx = rhp_eap_auth_impl_vpn_init(vpn->eap.eap_method,vpn,rlm,ikesa);
	if( vpn->eap.impl_ctx == NULL ){
	  RHP_TRC(0,RHPTRCID_IKEV1_XAUTH_R_INIT_FAIL_TO_GET_IMPL_CTX,"xxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg,rlm);
    goto error_l;
	}

  RHP_UNLOCK(&(rlm->lock));


  err = rhp_eap_auth_impl_init_req(vpn,ikesa,rx_ikemesg,tx_ikemesg,vpn->eap.impl_ctx);
  if( err == RHP_EAP_STAT_PENDING ){

  	// This XAUTH message is forwarded to an external authentication service like a Rockhopper
  	// protected process.

  	err = RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;
    rhp_vpn_hold(vpn); //(HxOxH)

		ikesa->busy_flag = 1;

  }else if( err == RHP_EAP_STAT_CONTINUE ){

  	// TODO: Not Implemented yet.
  	err = 0;

  }else{

  	RHP_TRC(0,RHPTRCID_IKEV1_XAUTH_R_INIT_IMPL_INIT_REQ_ERR,"xxxE",vpn,ikesa,rx_ikemesg,tx_ikemesg,err);

  	err = -EINVAL;
    goto error;
  }

	ikesa->eap.state = RHP_IKESA_EAP_STAT_R_PEND;

	RHP_TRC(0,RHPTRCID_IKEV1_XAUTH_R_INIT_RTRN,"xxxE",vpn,ikesa,rx_ikemesg,tx_ikemesg,err);
  return err;

error_l:
	RHP_UNLOCK(&(rlm->lock));
error:

	RHP_TRC(0,RHPTRCID_IKEV1_XAUTH_R_INIT_RTRN,"xxxE",vpn,ikesa,rx_ikemesg,tx_ikemesg,err);
	return err;
}


struct _rhp_xauth_r_task_ctx {

	rhp_vpn_ref* vpn_ref;

	int ikesa_side;
	u8 ikesa_spi[RHP_PROTO_IKE_SPI_SIZE];

	rhp_ikev2_mesg* rx_ikemesg;
};
typedef struct _rhp_xauth_r_task_ctx	rhp_xauth_r_task_ctx;

static void _rhp_xauth_r_task_ctx_free(rhp_xauth_r_task_ctx* xauth_r_ctx)
{
  RHP_TRC(0,RHPTRCID_XAUTH_R_TASK_CTX_FREE,"xxxdG",xauth_r_ctx,RHP_VPN_REF(xauth_r_ctx->vpn_ref),xauth_r_ctx->rx_ikemesg,xauth_r_ctx->ikesa_side,xauth_r_ctx->ikesa_spi);

  if( xauth_r_ctx->vpn_ref ){
		rhp_vpn_unhold(xauth_r_ctx->vpn_ref);
	}

	if( xauth_r_ctx->rx_ikemesg ){
		rhp_ikev2_unhold_mesg(xauth_r_ctx->rx_ikemesg);
	}

	_rhp_free(xauth_r_ctx);

	return;
}

static void _rhp_ikev1_xauth_r_task(int worker_index,void *ctx)
{
	int err = -EINVAL;
	rhp_xauth_r_task_ctx* xauth_r_ctx = (rhp_xauth_r_task_ctx*)ctx;
	rhp_vpn* vpn = RHP_VPN_REF(xauth_r_ctx->vpn_ref);
	rhp_ikesa* ikesa;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  u32 tx_mesg_id;

  RHP_TRC(0,RHPTRCID_IKEV1_XAUTH_R_TASK,"xxxdG",xauth_r_ctx,RHP_VPN_REF(xauth_r_ctx->vpn_ref),xauth_r_ctx->rx_ikemesg,xauth_r_ctx->ikesa_side,xauth_r_ctx->ikesa_spi);

	RHP_LOCK(&(vpn->lock));

	if( !_rhp_atomic_read(&(vpn->is_active)) ){
	  RHP_TRC(0,RHPTRCID_IKEV1_XAUTH_R_TASK_VPN_NOT_ACTIVE,"xxx",xauth_r_ctx,vpn,xauth_r_ctx->rx_ikemesg);
		err = -EINVAL;
		goto error;
	}

	ikesa = vpn->ikesa_get(vpn,xauth_r_ctx->ikesa_side,xauth_r_ctx->ikesa_spi);
	if( ikesa == NULL ){
	  RHP_TRC(0,RHPTRCID_IKEV1_XAUTH_R_TASK_VPN_NO_IKESA,"xxx",xauth_r_ctx,vpn,xauth_r_ctx->rx_ikemesg);
		err = -ENOENT;
		goto error;
	}

	if( ikesa->eap.state != RHP_IKESA_EAP_STAT_DEFAULT ){
  	err = RHP_STATUS_BAD_SA_STATE;
	  RHP_TRC(0,RHPTRCID_IKEV1_XAUTH_R_TASK_BAD_EAP_STAT,"xxxLdGLd",xauth_r_ctx->rx_ikemesg,vpn,ikesa,"IKE_SIDE",xauth_r_ctx->ikesa_side,xauth_r_ctx->ikesa_spi,"EAP_STAT",ikesa->eap.state);
		goto error;
	}

  {
		err = rhp_random_bytes((u8*)&tx_mesg_id,sizeof(u32));
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		tx_ikemesg = rhp_ikev1_new_mesg_tx(RHP_PROTO_IKEV1_EXCHG_TRANSACTION,tx_mesg_id,0);
		if( tx_ikemesg == NULL ){
			RHP_BUG("");
			goto error;
		}

		tx_ikemesg->set_mesg_id(tx_ikemesg,tx_mesg_id);
  }


  err = _rhp_ikev1_xauth_r_init(vpn,ikesa,xauth_r_ctx->rx_ikemesg,tx_ikemesg);
  if( err && err != RHP_STATUS_IKEV2_MESG_HANDLER_PENDING ){
	  RHP_TRC(0,RHPTRCID_IKEV1_XAUTH_R_TASK_START_ERR,"xxx",xauth_r_ctx,vpn,xauth_r_ctx->rx_ikemesg);
  	goto error;
  }

  if( !err ){

    tx_ikemesg->v1_start_retx_timer = 1;

    rhp_ikev1_p2_session_tx_put(ikesa,
    		tx_ikemesg->get_mesg_id(tx_ikemesg),tx_ikemesg->get_exchange_type(tx_ikemesg),0,0);

  	rhp_ikev1_send_mesg(vpn,ikesa,tx_ikemesg,RHP_IKEV1_MESG_HANDLER_XAUTH);

  }else{

  	// Pending...
  }

  err = 0;

error:
	RHP_UNLOCK(&(vpn->lock));

	_rhp_xauth_r_task_ctx_free(xauth_r_ctx);

	if( tx_ikemesg ){
		rhp_ikev2_unhold_mesg(tx_ikemesg);
	}

  RHP_TRC(0,RHPTRCID_IKEV1_XAUTH_R_TASK_RTRN,"xxxE",xauth_r_ctx,vpn,tx_ikemesg,err);
	return;
}

int rhp_ikev1_xauth_r_invoke_task(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_ikemesg)
{
	int err = -EINVAL;
	rhp_xauth_r_task_ctx* xauth_r_ctx = NULL;

	xauth_r_ctx = (rhp_xauth_r_task_ctx*)_rhp_malloc(sizeof(rhp_xauth_r_task_ctx));
	if( xauth_r_ctx == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	memset(xauth_r_ctx,0,sizeof(rhp_xauth_r_task_ctx));

	xauth_r_ctx->vpn_ref = rhp_vpn_hold_ref(vpn);

	xauth_r_ctx->ikesa_side = ikesa->side;
	memcpy(xauth_r_ctx->ikesa_spi,ikesa->get_my_spi(ikesa),RHP_PROTO_IKE_SPI_SIZE);

	xauth_r_ctx->rx_ikemesg = rx_ikemesg;
	rhp_ikev2_hold_mesg(rx_ikemesg);

	err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_2,_rhp_ikev1_xauth_r_task,xauth_r_ctx);
	if( err ){
		RHP_BUG("%d",err);
		_rhp_xauth_r_task_ctx_free(xauth_r_ctx);
	}

error:
	return err;
}


static void rhp_xauth_r_handle_mode_cfg_pkt(int worker_index,void *ctx)
{
	int err = -EINVAL;
	rhp_vpn_ref* vpn_ref = (rhp_vpn_ref*)ctx;
	rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);
	rhp_packet* pkt = NULL;
	int addr_family = AF_UNSPEC;
	rhp_ikesa* ikesa = NULL;
	int ikesa_side;
	u8 ikesa_spi[RHP_PROTO_IKE_SPI_SIZE];

  RHP_TRC(0,RHPTRCID_XAUTH_R_HANDLE_MODE_CFG_PKT,"dxx",worker_index,vpn_ref,vpn);

	RHP_LOCK(&(vpn->lock));

	if( !_rhp_atomic_read(&(vpn->is_active)) ){
	  RHP_TRC(0,RHPTRCID_XAUTH_R_HANDLE_MODE_CFG_PKT_VPN_NOT_ACTIVE,"dxx",worker_index,vpn_ref,vpn);
		err = -EINVAL;
		goto error;
	}

	ikesa = vpn->ikesa_list_head;
	while( ikesa ){

	  RHP_TRC(0,RHPTRCID_XAUTH_R_HANDLE_MODE_CFG_PKT_PEND_IKESA,"dxxxxdd",worker_index,vpn_ref,vpn,ikesa,RHP_PKT_REF(ikesa->v1.mode_cfg_pending_pkt_ref),ikesa->state,ikesa->eap.state);

		if( ikesa->v1.mode_cfg_pending_pkt_ref ){
			break;
		}

		ikesa = ikesa->next_vpn_list;
	}

	if( ikesa == NULL ){
	  RHP_TRC(0,RHPTRCID_XAUTH_R_HANDLE_MODE_CFG_PKT_NO_PEND_IKESA,"dxx",worker_index,vpn_ref,vpn);
		err = -ENOENT;
		goto error;
	}

	ikesa_side = ikesa->side;
	memcpy(ikesa_spi,ikesa->get_my_spi,RHP_PROTO_IKE_SPI_SIZE);

  RHP_TRC(0,RHPTRCID_XAUTH_R_HANDLE_MODE_CFG_PKT_PEND_IKESA_FOUND,"dxxxLdGddx",worker_index,vpn_ref,vpn,ikesa,"IKE_SIDE",ikesa_side,ikesa_spi,ikesa->state,ikesa->eap.state,RHP_PKT_REF(ikesa->v1.mode_cfg_pending_pkt_ref));


	pkt = RHP_PKT_REF(ikesa->v1.mode_cfg_pending_pkt_ref);
	if( pkt == NULL ){
		err = -ENOENT;
		RHP_BUG("");
		goto error;
	}

	if( pkt->type == RHP_PKT_IPV4_IKE ){
		addr_family = AF_INET;
	}else if( pkt->type == RHP_PKT_IPV6_IKE ){
		addr_family = AF_INET6;
	}else{
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	RHP_UNLOCK(&(vpn->lock));


	rhp_ikev1_recv_impl(addr_family,pkt);


	RHP_LOCK(&(vpn->lock));

	ikesa = vpn->ikesa_get(vpn,ikesa_side,ikesa_spi);
	if( ikesa == NULL ){
	  RHP_TRC(0,RHPTRCID_XAUTH_R_HANDLE_MODE_CFG_PKT_NO_PEND_IKESA_2,"dxx",worker_index,vpn_ref,vpn);
		err = -ENOENT;
		goto error;
	}


error:

	if( ikesa ){

		ikesa->busy_flag = 0;

		if( ikesa->v1.mode_cfg_pending_pkt_ref ){

			rhp_pkt_unhold(ikesa->v1.mode_cfg_pending_pkt_ref);
			ikesa->v1.mode_cfg_pending_pkt_ref = NULL;
		}
	}

	RHP_UNLOCK(&(vpn->lock));
	rhp_vpn_unhold(vpn_ref)

  RHP_TRC(0,RHPTRCID_XAUTH_R_HANDLE_MODE_CFG_PKT_RTRN,"dxxE",worker_index,vpn_ref,vpn,err);
	return;
}

void rhp_xauth_recv_callback(rhp_vpn* vpn,int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* rx_ikemesg,
		rhp_ikev2_mesg* tx_ikemesg,int eap_stat/*RHP_EAP_STAT_XXX*/,int is_init_req)
{
	int err = -EINVAL;
	int caller_type;
	rhp_ikesa* ikesa = NULL;
	int tx_auth_err = 0;
	rhp_ikev2_payload* attr_err_pld = NULL;

  RHP_TRC(0,RHPTRCID_XAUTH_RECV_CALLBACK,"xLdLdGxxLd",vpn,"EAP_ROLE",vpn->eap.role,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,rx_ikemesg,tx_ikemesg,"EAP_STAT",eap_stat);

  ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
  if( ikesa == NULL ){
    RHP_TRC(0,RHPTRCID_XAUTH_RECV_CALLBACK_NO_IKESA,"xx",vpn,rx_ikemesg);
    err = -ENOENT;
  	goto error_vpn;
  }

  ikesa->busy_flag = 0;

  if( vpn->eap.role != RHP_EAP_AUTHENTICATOR ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error_vpn;
  }


  if( eap_stat == RHP_EAP_STAT_CONTINUE ){

  	caller_type = RHP_IKEV1_MESG_HANDLER_END;


    tx_ikemesg->v1_start_retx_timer = 1;

    if( is_init_req ){

    	rhp_ikev1_p2_session_tx_put(ikesa,
					tx_ikemesg->get_mesg_id(tx_ikemesg),tx_ikemesg->get_exchange_type(tx_ikemesg),0,0);

    }else{

    	_rhp_ikev1_rx_xauth_r_update_p2_sess(ikesa,rx_ikemesg);
    }

  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_XAUTH_SERVER_AUTH_CONTINUE,"KVP",rx_ikemesg,vpn,ikesa);


  }else if( eap_stat == RHP_EAP_STAT_COMPLETED ){

    rhp_vpn_realm* rlm;

		rhp_ikev2_eap_auth_set_peer_ident(vpn);


  	err = rhp_ikev2_ike_auth_r_eap_rebind_rlm(vpn,ikesa,rx_ikemesg);
  	if( err ){
    	goto error_vpn;
  	}


    rlm = vpn->rlm;
    if( rlm == NULL ){
    	RHP_BUG("");
    	err = -EINVAL;
    	goto error_vpn;
    }

  	RHP_LOCK(&(rlm->lock));

		err = vpn->check_cfg_address(vpn,rlm,rx_ikemesg->rx_pkt);
		if( err ){

			RHP_UNLOCK(&(rlm->lock));

			RHP_TRC(0,RHPTRCID_XAUTH_RECV_CALLBACK_CHECK_CFG_ADDR_ERR,"xxxxE",rx_ikemesg,rx_ikemesg->rx_pkt,vpn,rlm,err);

			rhp_ikev2_g_statistics_inc(rx_ikev1_req_unknown_if_err_packets);

			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->v1.def_realm_id,RHP_LOG_ID_XAUTH_SERVER_RX_PKT_VIA_UNCONFIGURED_IF,"KVi",rx_ikemesg,vpn,rx_ikemesg->rx_pkt->rx_if_index);

			err = RHP_STATUS_INVALID_IKEV2_MESG_CHECK_CFG_ADDR_ERR;
    	goto error_vpn;
		}

  	RHP_UNLOCK(&(rlm->lock));


  	err = rhp_ikev1_r_clear_old_vpn(vpn,&ikesa,1,NULL);
		if( err ){
			goto error_vpn;
		}


  	RHP_LOCK(&(rlm->lock));

		err = rhp_ikev1_rx_r_comp(vpn,ikesa,rlm,rx_ikemesg,0);
		if( err && err != RHP_STATUS_IKEV2_MESG_HANDLER_END ){
			RHP_UNLOCK(&(rlm->lock));
			goto error_vpn;
		}

  	RHP_UNLOCK(&(rlm->lock));


    rhp_ikev1_p2_session_clear(ikesa,
    		rx_ikemesg->get_mesg_id(rx_ikemesg),rx_ikemesg->get_exchange_type(rx_ikemesg),0);


		ikesa->eap.state = RHP_IKESA_EAP_STAT_R_COMP;

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_XAUTH_SERVER_AUTH_COMPLETED,"KVPe",rx_ikemesg,vpn,ikesa,&(vpn->eap.peer_id));

  	caller_type = RHP_IKEV1_MESG_HANDLER_XAUTH;


  	if( ikesa->v1.mode_cfg_pending_pkt_ref ){

  	  ikesa->busy_flag = 1;

  		rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_2,rhp_xauth_r_handle_mode_cfg_pkt,rhp_vpn_hold_ref(vpn));
  	}


  }else{

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_XAUTH_SERVER_AUTH_ERROR,"KVP",rx_ikemesg,vpn,ikesa);

		rhp_ikev2_g_statistics_inc(ikesa_auth_errors);

  	err = eap_stat;
  	tx_auth_err = 1;
  	caller_type = RHP_IKEV1_MESG_HANDLER_XAUTH;

    goto error_vpn;
  }


  if( is_init_req ){

  	rhp_ikev1_send_mesg(vpn,ikesa,tx_ikemesg,RHP_IKEV1_MESG_HANDLER_XAUTH);

  }else{

  	rhp_ikev1_call_next_rx_mesg_handlers(rx_ikemesg,vpn,
  		my_ikesa_side,my_ikesa_spi,tx_ikemesg,caller_type);
  }


  err = 0;

  // rhp_eap_auth_impl_recv() or rhp_eap_sup_impl_recv() held the vpn and returned PENDING. *(HxOxH)
  rhp_vpn_unhold(vpn);

  RHP_TRC(0,RHPTRCID_XAUTH_RECV_CALLBACK_EAP_STAT_RTRN,"xxd",vpn,rx_ikemesg,ikesa->eap.state);
  return;


error_vpn:
	if( ikesa ){

		attr_err_pld = tx_ikemesg->get_payload(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_ATTR);
		if( tx_auth_err && attr_err_pld ){


	  	rhp_ikev1_call_next_rx_mesg_handlers(rx_ikemesg,vpn,
	  					my_ikesa_side,my_ikesa_spi,tx_ikemesg,caller_type);

			ikesa->timers->schedule_delete(vpn,ikesa,rhp_gcfg_ikev1_xauth_tx_error_margin);

		}else{

			rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_DELETE_WAIT);
			ikesa->timers->schedule_delete(vpn,ikesa,0);
		}
	}

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_XAUTH_SERVER_AUTH_FAILED,"KVPE",rx_ikemesg,vpn,ikesa,err);

  // rhp_eap_auth_impl_recv() or rhp_eap_sup_impl_recv() held the vpn and returned PENDING. *(HxOxH)
  rhp_vpn_unhold(vpn);

  RHP_TRC(0,RHPTRCID_XAUTH_RECV_CALLBACK_EAP_STAT_ERR,"xxdxE",vpn,rx_ikemesg,tx_auth_err,attr_err_pld,err);
  return;
}

static int _rhp_ikev1_rx_xauth_verify_attr_pld(rhp_ikev2_payload* payload,
		rhp_ikev1_attr_attr* attr_attr,void* ctx)
{
	int* found = (int*)ctx;
	u16 attr_type = attr_attr->get_attr_type(attr_attr);

	switch( attr_type ){
	case RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_TYPE:
	case RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_USER_NAME:
	case RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_USER_PASSWORD:
	case RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_PASSCODE:
	case RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_MESSAGE:
	case RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_CHALLENGE:
	case RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_DOMAIN:
	case RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_STATUS:
	case RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_NEXT_PIN:
	case RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_ANSWER:
		(*found)++;
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_XAUTH_VERIFY_ATTR_PLD_ATTR,"xxwd",payload,attr_attr,attr_type,*found);
		break;
	default:
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_XAUTH_VERIFY_ATTR_PLD_ATTR_NOT_INTERESTED,"xxwd",payload,attr_attr,attr_type,*found);
		break;
	}

	return 0;
}

static int _rhp_ikev1_rx_xauth_get_payload(rhp_ikev2_mesg* rx_ikemesg,rhp_vpn* vpn,rhp_ikev2_payload** rx_attr_pld_r)
{
	int err = -EINVAL;
  rhp_ikev2_payload* rx_attr_pld = NULL;
  int xauth_attrs = 0;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_XAUTH_GET_PAYLOAD,"xxx",rx_ikemesg,vpn,rx_attr_pld_r);

  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


  rx_attr_pld = rx_ikemesg->get_payload(rx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_ATTR);
  if( rx_attr_pld == NULL ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_IKEV1_RX_IKE_XAUTH_GET_PAYLOAD_NOT_FOUND,"xxE",rx_ikemesg,vpn,err);
  	goto error;
  }


  rx_attr_pld->ext.v1_attr->enum_attr(rx_attr_pld,_rhp_ikev1_rx_xauth_verify_attr_pld,&xauth_attrs);
  if( xauth_attrs < 1 ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_IKEV1_RX_IKE_XAUTH_GET_PAYLOAD_XAUTH_ATTR_NOT_FOUND,"xxE",rx_ikemesg,vpn,err);
  	goto error;
  }


  *rx_attr_pld_r = rx_attr_pld;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_XAUTH_GET_PAYLOAD_RTRN,"xxx",rx_ikemesg,vpn,*rx_attr_pld_r);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV1_RX_XAUTH_GET_PAYLOAD_ERR,"xxxE",rx_ikemesg,vpn,rx_attr_pld_r,err);
	return err;
}

static int _rhp_ikev1_rx_xauth_r_pend(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_ikemesg,
		rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
  rhp_ikev2_payload* rx_attr_pld = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_XAUTH_R_PEND,"xxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg);


  err = _rhp_ikev1_rx_xauth_get_payload(rx_ikemesg,vpn,&rx_attr_pld);
  if( err ){
    goto error;
  }


  {
		ikesa->timers->quit_retransmit_timer(vpn,ikesa);

		if( ikesa->req_retx_ikemesg ){

			ikesa->set_retrans_request(ikesa,NULL);

			rhp_ikev2_unhold_mesg(ikesa->req_retx_ikemesg);
			ikesa->req_retx_ikemesg = NULL;
		}
  }


  err = rhp_eap_auth_impl_recv(vpn,ikesa,rx_ikemesg,rx_attr_pld,tx_ikemesg,vpn->eap.impl_ctx);
  if( err == RHP_EAP_STAT_PENDING ){

  	// This XAUTH message is forwarded to an external authentication service like a Rockhopper
  	// protected process.

  	err = RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;
    rhp_vpn_hold(vpn);

		ikesa->busy_flag = 1;

  }else if( err == RHP_EAP_STAT_CONTINUE ){

  	// TODO: Not Implemented yet.
  	err = 0;

  }else if( err == RHP_EAP_STAT_COMPLETED ){

  	// TODO: Not Implemented yet.
  	err = 0;

  }else{

    RHP_TRC(0,RHPTRCID_IKEV1_RX_XAUTH_R_PEND_IMPL_RECV_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);

  	err = -EINVAL;
    goto error;
  }

error:
	RHP_TRC(0,RHPTRCID_IKEV1_RX_XAUTH_R_PEND_RTRN,"xxxE",vpn,ikesa,rx_ikemesg,err);
	return err;
}

int rhp_ikev1_xauth_pending(rhp_vpn* vpn,rhp_ikesa* ikesa,u8 exchange_type,rhp_packet* pkt)
{

	if( exchange_type == RHP_PROTO_IKEV1_EXCHG_TRANSACTION &&
			vpn->eap.role == RHP_EAP_AUTHENTICATOR &&
			vpn->origin_side == RHP_IKE_RESPONDER && ikesa->side == RHP_IKE_RESPONDER &&
			ikesa->state == RHP_IKESA_STAT_V1_XAUTH_PEND_R &&
			ikesa->eap.state == RHP_IKESA_EAP_STAT_R_PEND ){
	  RHP_TRC_FREQ(0,RHPTRCID_IKEV1_XAUTH_PENDING_IS_PENDING,"xxxLbdd",pkt,vpn,ikesa,"PROTO_IKE_EXCHG",exchange_type,ikesa->state,ikesa->eap.state);
		return 1;
	}

  RHP_TRC_FREQ(0,RHPTRCID_IKEV1_XAUTH_PENDING_NOT_PENDING,"xxxLbddddd",pkt,vpn,ikesa,"PROTO_IKE_EXCHG",exchange_type,vpn->eap.role,ikesa->state,ikesa->eap.state,vpn->origin_side,ikesa->side);
	return 0;
}

int rhp_ikev1_rx_xauth(rhp_ikev2_mesg* rx_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_ikemesg->get_exchange_type(rx_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_XAUTH,"xxLdGxLb",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

	if( exchange_type != RHP_PROTO_IKEV1_EXCHG_TRANSACTION ){
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_XAUTH_NOT_TRANSACTION_EXCHG,"xxLb",rx_ikemesg,vpn,"PROTO_IKE_EXCHG",exchange_type);
		return 0;
	}

	if( vpn->eap.role != RHP_EAP_AUTHENTICATOR ){
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_XAUTH_NOT_AUTHENTICATOR,"xx",rx_ikemesg,vpn);
  	err = 0;
  	goto error;
  }

  if( !rx_ikemesg->decrypted ){
  	err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_XAUTH_NOT_DECRYPTED,"xx",rx_ikemesg,vpn);
  	goto error;
  }


	if( my_ikesa_spi == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

	ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
	if( ikesa == NULL ){
		err = -ENOENT;
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_XAUTH_NO_IKESA,"xxLdG",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
		goto error;
	}

	if( vpn->origin_side != RHP_IKE_RESPONDER ||
			ikesa->side != RHP_IKE_RESPONDER ){
    err = 0;
    goto ignored;
	}

  if( ikesa->state != RHP_IKESA_STAT_V1_XAUTH_PEND_R ){
    err = 0;
    goto ignored;
  }

	if( ikesa->eap.state == RHP_IKESA_EAP_STAT_R_PEND ){

		err = _rhp_ikev1_rx_xauth_r_pend(vpn,ikesa,rx_ikemesg,tx_ikemesg);

	}else if( ikesa->eap.state == RHP_IKESA_EAP_STAT_R_COMP ){

	  {
			ikesa->timers->quit_retransmit_timer(vpn,ikesa);

			if( ikesa->req_retx_ikemesg ){

				ikesa->set_retrans_request(ikesa,NULL);

				rhp_ikev2_unhold_mesg(ikesa->req_retx_ikemesg);
				ikesa->req_retx_ikemesg = NULL;
			}
	  }

		err = 0;
		goto error;

	}else{
  	err = RHP_STATUS_BAD_SA_STATE;
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_XAUTH_BAD_EAP_STAT2,"xxLdGLd",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"EAP_STAT",ikesa->eap.state);
		goto error;
	}


  err = 0;

ignored:
error:
	RHP_TRC(0,RHPTRCID_IKEV1_RX_XAUTH_RTRN,"xxxE",rx_ikemesg,vpn,tx_ikemesg,err);
  return err;
}

