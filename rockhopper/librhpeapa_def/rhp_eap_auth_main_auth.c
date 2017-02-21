/*

	Copyright (C) 2009-2012 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.

 	This library can be distributed under the terms of BSD license.
 	Also see the original wpa_supplicant's README.

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

#include "wpa_supplicant/includes.h"

#include "wpa_supplicant/common.h"
#include "wpa_supplicant/ms_funcs.h"
#include "wpa_supplicant/eap_i.h"

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
#include "rhp_ikev2_mesg.h"
#include "rhp_vpn.h"
#include "rhp_ikev2.h"
#include "rhp_eap_auth_impl.h"
#include "rhp_radius_impl.h"
#include "rhp_eap_auth_priv.h"


static void _rhp_eap_auth_main_ipc_handler(int worker_idx,void* wts_ctx)
{
	int err = -EINVAL;
	rhp_ipcmsg_eap_handle_rep* ipc_rep = (rhp_ipcmsg_eap_handle_rep*)wts_ctx;
	rhp_eap_auth_impl_ctx* ctx = NULL;
	rhp_vpn_ref* vpn_ref = NULL;
	rhp_vpn* vpn = NULL;
	rhp_ikesa* ikesa = NULL;
	rhp_ikev2_mesg* rx_ikemesg = NULL;
	rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_MAIN_IPC_HANDLER,"xx",wts_ctx,ipc_rep);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_MAIN ){
    RHP_BUG("");
    return;
  }

	if( ipc_rep->len < sizeof(rhp_ipcmsg_eap_handle_rep) ){
		RHP_BUG("%d:%d",ipc_rep->len,sizeof(rhp_ipcmsg_eap_handle_rep));
		return;
	}

	if( ipc_rep->type != RHP_IPC_EAP_AUTH_HANDLE_REPLY ){
		RHP_BUG("%d",ipc_rep->type);
		return;
	}

  RHP_TRC(0,RHPTRCID_EAP_AUTH_MAIN_IPC_HANDLER_IPC_REP_DATA,"xxEuupLdGdd",ipc_rep,vpn,ipc_rep->status,ipc_rep->vpn_realm_id,ipc_rep->rebound_vpn_realm_id,RHP_VPN_UNIQUE_ID_SIZE,ipc_rep->unique_id,"IKE_SIDE",ipc_rep->side,ipc_rep->spi,ipc_rep->eap_mesg_len,ipc_rep->msk_len);


  vpn_ref = rhp_vpn_ikesa_spi_get(ipc_rep->side,ipc_rep->spi);
  vpn = RHP_VPN_REF(vpn_ref);
  if( vpn == NULL ){
    RHP_TRC(0,RHPTRCID_EAP_AUTH_MAIN_IPC_HANDLER_NO_VPN,"xxLdG",wts_ctx,ipc_rep,"IKE_SIDE",ipc_rep->side,ipc_rep->spi);
    goto error;
  }

  RHP_LOCK(&(vpn->lock));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_EAP_AUTH_MAIN_IPC_HANDLER_VPN_NOT_ACTIVE,"xx",ipc_rep,vpn);
    goto error_vpn_l;
  }


  ikesa = vpn->ikesa_get(vpn,ipc_rep->side,ipc_rep->spi);
  if( ikesa == NULL ){
    RHP_TRC(0,RHPTRCID_EAP_AUTH_MAIN_IPC_HANDLER_NO_IKESA,"xxLdG",ipc_rep,vpn,"IKE_SIDE",ipc_rep->side,ipc_rep->spi);
  	goto error_vpn_l;
  }


  ctx = (rhp_eap_auth_impl_ctx*)vpn->eap.impl_ctx;
  if( ctx == NULL ){
  	RHP_BUG("");
  	goto error_vpn_l;
  }

	rx_ikemesg = ctx->rx_ikemesg;
	ctx->rx_ikemesg = NULL;
	tx_ikemesg = ctx->tx_ikemesg;
	ctx->tx_ikemesg = NULL;

	if( ipc_rep->eap_mesg_len &&
			((ipc_rep->eap_mesg_len < sizeof(rhp_proto_eap)) /*Min len = EAP Header*/ ||
			(ipc_rep->len - sizeof(rhp_ipcmsg_eap_handle_rep)) < sizeof(rhp_proto_eap)) ){
		RHP_BUG("");
		err = -EINVAL;
		goto error_vpn_l;
	}

	if( ipc_rep->eap_mesg_len ){ // EAP FAILURE also

		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_EAP,&ikepayload) ){
			RHP_BUG("");
			goto error_vpn_l;
		}

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

		err = ikepayload->ext.eap->set_eap_message(ikepayload,
				(u8*)(ipc_rep + 1),(int)ipc_rep->eap_mesg_len);

		if( err ){
			RHP_BUG("");
			goto error_vpn_l;
		}
	}


	if( ipc_rep->status != RHP_EAP_STAT_CONTINUE &&
			ipc_rep->status != RHP_EAP_STAT_COMPLETED ){

    RHP_TRC(0,RHPTRCID_EAP_AUTH_MAIN_IPC_HANDLER_RX_EAP_ERR,"xxE",ipc_rep,vpn,ipc_rep->status);

		err = RHP_STATUS_EAP_STAT_ERROR;
		goto error_vpn_l;

	}else if( ipc_rep->status == RHP_EAP_STAT_COMPLETED ){

		ctx->is_completed = 1;

		if( ipc_rep->msk_len != 64 ){
			RHP_BUG("%d",ipc_rep->msk_len);
		}else{
			memcpy(ctx->msk,(((u8*)(ipc_rep + 1)) + ipc_rep->eap_mesg_len),64);
		}

		RHP_TRC(0,RHPTRCID_EAP_AUTH_MAIN_IPC_HANDLER_MSK,"xxp",wts_ctx,ipc_rep,64,ctx->msk);

		if( ipc_rep->peer_identity_len ){

			ctx->peer_identity = (u8*)_rhp_malloc(ipc_rep->peer_identity_len + 1);
			if( ctx->peer_identity == NULL ){
				RHP_BUG("");
			}else{

				memcpy(ctx->peer_identity,
						(((u8*)(ipc_rep + 1)) + ipc_rep->eap_mesg_len + ipc_rep->msk_len),ipc_rep->peer_identity_len);

				ctx->peer_identity_len = ipc_rep->peer_identity_len;
				ctx->peer_identity[ctx->peer_identity_len] = '\0';
			}
		}

		vpn->eap.rebound_vpn_realm_id = ipc_rep->rebound_vpn_realm_id;
	}


	rhp_eap_recv_callback(vpn,ikesa->side,ikesa->resp_spi,rx_ikemesg,tx_ikemesg,ipc_rep->status);

  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

	rhp_ikev2_unhold_mesg(rx_ikemesg);
	rhp_ikev2_unhold_mesg(tx_ikemesg);

	_rhp_free_zero(ipc_rep,ipc_rep->len);

  RHP_TRC(0,RHPTRCID_EAP_AUTH_MAIN_IPC_HANDLER_RTRN,"xx",ipc_rep,vpn);
	return;


error_vpn_l:
	if( ikesa && rx_ikemesg && tx_ikemesg ){

		rhp_eap_recv_callback(vpn,ikesa->side,ikesa->resp_spi,rx_ikemesg,tx_ikemesg,RHP_EAP_STAT_ERROR);
	}

	if( ipc_rep->status != RHP_EAP_STAT_CONTINUE ){
		ctx->is_completed = 1;
	}

	RHP_UNLOCK(&(vpn->lock));
	rhp_vpn_unhold(vpn_ref);

error:
	if( rx_ikemesg ){
		rhp_ikev2_unhold_mesg(rx_ikemesg);
	}

	if( tx_ikemesg ){
		rhp_ikev2_unhold_mesg(tx_ikemesg);
	}

	_rhp_free_zero(ipc_rep,ipc_rep->len);

  RHP_TRC(0,RHPTRCID_EAP_AUTH_MAIN_IPC_HANDLER_ERR,"xxE",ipc_rep,vpn,err);
	return;
}

static int _rhp_eap_auth_main_xauth_add_hash_buf(rhp_ikev2_mesg* ikemesg,
		int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_packet* pkt_for_hash = (rhp_packet*)ctx;
	u8 pld_id = payload->get_payload_id(payload);

  RHP_TRC(0,RHPTRCID_EAP_AUTH_MAIN_XAUTH_ADD_HASH_BUF,"xxLbxxd",ikemesg,payload,"PROTO_IKE_PAYLOAD",payload->payload_id,ctx,pkt_for_hash,ikemesg->tx_mesg_len);

  if( pld_id == RHP_PROTO_IKEV1_PAYLOAD_ATTR ){

		err = payload->ext_serialize(payload,pkt_for_hash);
		if( err ){
			RHP_TRC(0,RHPTRCID_EAP_AUTH_MAIN_XAUTH_ADD_HASH_BUF_ERR,"xxLbxE",ikemesg,payload,"PROTO_IKE_PAYLOAD",payload->payload_id,ctx,err);
			return err;
		}
  }

  RHP_TRC(0,RHPTRCID_EAP_AUTH_MAIN_XAUTH_ADD_HASH_BUF_RTRN,"xxxd",ikemesg,payload,pkt_for_hash,ikemesg->tx_mesg_len);
	return 0;
}

static void _rhp_eap_auth_main_xauth_ipc_handler(int worker_idx,void* wts_ctx)
{
	int err = -EINVAL;
	rhp_ipcmsg_eap_handle_rep* ipc_rep = (rhp_ipcmsg_eap_handle_rep*)wts_ctx;
	rhp_eap_auth_impl_ctx* ctx = NULL;
	rhp_vpn_ref* vpn_ref = NULL;
	rhp_vpn* vpn = NULL;
	rhp_ikesa* ikesa = NULL;
	rhp_ikev2_mesg* rx_ikemesg = NULL;
	rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_MAIN_XAUTH_IPC_HANDLER,"xx",wts_ctx,ipc_rep);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_MAIN ){
    RHP_BUG("");
    return;
  }

	if( ipc_rep->len < sizeof(rhp_ipcmsg_eap_handle_rep) ){
		RHP_BUG("%d:%d",ipc_rep->len,sizeof(rhp_ipcmsg_eap_handle_rep));
		return;
	}

	if( ipc_rep->type != RHP_IPC_XAUTH_AUTH_HANDLE_REPLY ){
		RHP_BUG("%d",ipc_rep->type);
		return;
	}

  RHP_TRC(0,RHPTRCID_EAP_AUTH_MAIN_XAUTH_IPC_HANDLER_IPC_REP_DATA,"xxEuupLdGdd",ipc_rep,vpn,ipc_rep->status,ipc_rep->vpn_realm_id,ipc_rep->rebound_vpn_realm_id,RHP_VPN_UNIQUE_ID_SIZE,ipc_rep->unique_id,"IKE_SIDE",ipc_rep->side,ipc_rep->spi,ipc_rep->eap_mesg_len,ipc_rep->msk_len);


  vpn_ref = rhp_vpn_ikesa_spi_get(ipc_rep->side,ipc_rep->spi);
  vpn = RHP_VPN_REF(vpn_ref);
  if( vpn == NULL ){
    RHP_TRC(0,RHPTRCID_EAP_AUTH_MAIN_XAUTH_IPC_HANDLER_NO_VPN,"xxLdG",wts_ctx,ipc_rep,"IKE_SIDE",ipc_rep->side,ipc_rep->spi);
    goto error;
  }

  RHP_LOCK(&(vpn->lock));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_EAP_AUTH_MAIN_XAUTH_IPC_HANDLER_VPN_NOT_ACTIVE,"xx",ipc_rep,vpn);
    goto error_vpn_l;
  }


  ikesa = vpn->ikesa_get(vpn,ipc_rep->side,ipc_rep->spi);
  if( ikesa == NULL ){
    RHP_TRC(0,RHPTRCID_EAP_AUTH_MAIN_XAUTH_IPC_HANDLER_NO_IKESA,"xxLdG",ipc_rep,vpn,"IKE_SIDE",ipc_rep->side,ipc_rep->spi);
  	goto error_vpn_l;
  }


  ctx = (rhp_eap_auth_impl_ctx*)vpn->eap.impl_ctx;
  if( ctx == NULL ){
  	RHP_BUG("");
  	goto error_vpn_l;
  }

	rx_ikemesg = ctx->rx_ikemesg;
	ctx->rx_ikemesg = NULL;
	tx_ikemesg = ctx->tx_ikemesg;
	ctx->tx_ikemesg = NULL;

	if( ipc_rep->eap_mesg_len &&
			((ipc_rep->eap_mesg_len < sizeof(rhp_proto_ikev1_attribute_payload)) /*Min len = EAP Header*/ ||
			(ipc_rep->len - sizeof(rhp_ipcmsg_eap_handle_rep)) < sizeof(rhp_proto_ikev1_attribute_payload)) ){
		RHP_BUG("");
		err = -EINVAL;
		goto error_vpn_l;
	}


	if( ipc_rep->eap_mesg_len ){

		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_ATTR,&ikepayload) ){
			RHP_BUG("");
			goto error_vpn_l;
		}

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

	  ikepayload->payloadh = (rhp_proto_ike_payload*)(ipc_rep + 1);
	  ikepayload->is_v1 = 1;

	  err = rhp_ikev1_attr_payload_parse(
	  			(rhp_proto_ikev1_attribute_payload*)(ipc_rep + 1),
	  			(int)ipc_rep->eap_mesg_len,ikepayload);
		if( err ){
			RHP_BUG("");
			goto error_vpn_l;
		}


		err = rhp_ikev1_tx_info_mesg_hash_add(vpn,ikesa,
					tx_ikemesg,_rhp_eap_auth_main_xauth_add_hash_buf);
		if( err ){
			RHP_BUG("");
			goto error_vpn_l;
		}
	}


	if( ipc_rep->status != RHP_EAP_STAT_CONTINUE &&
			ipc_rep->status != RHP_EAP_STAT_COMPLETED ){

    RHP_TRC(0,RHPTRCID_EAP_AUTH_MAIN_XAUTH_IPC_HANDLER_RX_EAP_ERR,"xxE",ipc_rep,vpn,ipc_rep->status);

		err = RHP_STATUS_EAP_STAT_ERROR;
		goto error_vpn_l;

	}else if( ipc_rep->status == RHP_EAP_STAT_COMPLETED ){

		ctx->is_completed = 1;

		if( ipc_rep->peer_identity_len ){

			ctx->peer_identity = (u8*)_rhp_malloc(ipc_rep->peer_identity_len + 1);
			if( ctx->peer_identity == NULL ){
				RHP_BUG("");
			}else{

				memcpy(ctx->peer_identity,
						(((u8*)(ipc_rep + 1)) + ipc_rep->eap_mesg_len + ipc_rep->msk_len),ipc_rep->peer_identity_len);

				ctx->peer_identity_len = ipc_rep->peer_identity_len;
				ctx->peer_identity[ctx->peer_identity_len] = '\0';
			}
		}

		vpn->eap.rebound_vpn_realm_id = ipc_rep->rebound_vpn_realm_id;
	}


	rhp_xauth_recv_callback(vpn,ikesa->side,ikesa->resp_spi,rx_ikemesg,tx_ikemesg,
			ipc_rep->status,ipc_rep->is_init_req);

  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

	rhp_ikev2_unhold_mesg(rx_ikemesg);
	rhp_ikev2_unhold_mesg(tx_ikemesg);

	_rhp_free_zero(ipc_rep,ipc_rep->len);

  RHP_TRC(0,RHPTRCID_EAP_AUTH_MAIN_XAUTH_IPC_HANDLER_RTRN,"xx",ipc_rep,vpn);
	return;


error_vpn_l:
	if( ikesa && rx_ikemesg && tx_ikemesg ){

		rhp_xauth_recv_callback(vpn,ikesa->side,ikesa->resp_spi,rx_ikemesg,tx_ikemesg,
				RHP_EAP_STAT_ERROR,ipc_rep->is_init_req);
	}

	if( ipc_rep->status != RHP_EAP_STAT_CONTINUE ){
		ctx->is_completed = 1;
	}

	RHP_UNLOCK(&(vpn->lock));
	rhp_vpn_unhold(vpn_ref);

error:
	if( rx_ikemesg ){
		rhp_ikev2_unhold_mesg(rx_ikemesg);
	}

	if( tx_ikemesg ){
		rhp_ikev2_unhold_mesg(tx_ikemesg);
	}

	_rhp_free_zero(ipc_rep,ipc_rep->len);

  RHP_TRC(0,RHPTRCID_EAP_AUTH_MAIN_XAUTH_IPC_HANDLER_ERR,"xxE",ipc_rep,vpn,err);
	return;
}



static void* _rhp_eap_auth_impl_vpn_init(int method,rhp_vpn* vpn,rhp_vpn_realm* rlm,rhp_ikesa* ikesa)
{
	rhp_eap_auth_impl_ctx* ctx = NULL;

	RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_VPN_INIT_L,"Ldxxx","EAP_TYPE",method,vpn,rlm,ikesa);


	ctx = (rhp_eap_auth_impl_ctx*)_rhp_malloc(sizeof(rhp_eap_auth_impl_ctx));
	if( ctx == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(ctx,0,sizeof(rhp_eap_auth_impl_ctx));

	ctx->method = method;

	ctx->tag[0] = '#';
	ctx->tag[1] = 'E';
	ctx->tag[2] = 'A';
	ctx->tag[3] = 'A';

	ctx->vpn_ref = rhp_vpn_hold_ref(vpn);

  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_EAP_LOCAL_AUTH_IS_ENABLED,"VP",vpn,ikesa);

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_VPN_INIT_L_RTRN,"Ldxxxx","EAP_TYPE",method,vpn,rlm,ikesa,ctx);

	return (void*)ctx;
}

void* rhp_eap_auth_impl_vpn_init(int method,rhp_vpn* vpn,rhp_vpn_realm* rlm,rhp_ikesa* ikesa)
{
	void* ctx = NULL;

	RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_VPN_INIT,"Ldxxx","EAP_TYPE",method,vpn,rlm,ikesa);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_MAIN ){
    RHP_BUG("");
    return NULL;
  }

	if( method < RHP_PROTO_EAP_TYPE_PRIV_MIN ||
			method == RHP_PROTO_EAP_TYPE_PRIV_IKEV1_XAUTH_PAP ){

		ctx = _rhp_eap_auth_impl_vpn_init(method,vpn,rlm,ikesa);

	}else if( method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS ){

		RHP_LOCK(&rhp_eap_radius_cfg_lock);

		if( rhp_gcfg_eap_radius->enabled ){

			ctx = rhp_eap_auth_impl_vpn_init_for_radius(vpn,rlm,ikesa);
		}

		RHP_UNLOCK(&rhp_eap_radius_cfg_lock);

	}else{

		RHP_BUG("%d",method);
		return NULL;
	}

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_VPN_INIT_RTRN,"Ldxxxx","EAP_TYPE",method,vpn,rlm,ikesa,ctx);
	return ctx;
}

static void _rhp_eap_auth_impl_vpn_cleanup(rhp_vpn* vpn,void* impl_ctx)
{
	rhp_eap_auth_impl_ctx* ctx = (rhp_eap_auth_impl_ctx*)impl_ctx;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_VPN_L_CLEANUP,"xxxd",vpn,impl_ctx,RHP_VPN_REF(ctx->vpn_ref),ctx->is_completed);

	if( RHP_VPN_REF(ctx->vpn_ref) != vpn ){
		RHP_BUG("");
	}

	if( !ctx->is_completed ){

		rhp_ipcmsg_eap_handle_cancel ipc_cancel;

		memset(&ipc_cancel,0,sizeof(rhp_ipcmsg_eap_handle_cancel));

		ipc_cancel.tag[0] = '#';
		ipc_cancel.tag[1] = 'I';
		ipc_cancel.tag[2] = 'M';
		ipc_cancel.tag[3] = 'S';
		ipc_cancel.len = sizeof(rhp_ipcmsg_eap_handle_cancel);
		ipc_cancel.type = RHP_IPC_EAP_AUTH_HANDLE_CANCEL;
		ipc_cancel.vpn_realm_id = vpn->vpn_realm_id;
		memcpy(ipc_cancel.unique_id,vpn->unique_id,RHP_VPN_UNIQUE_ID_SIZE);

	  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)&ipc_cancel,ipc_cancel.len,0) < 0 ){
	    RHP_BUG("");
	  }
	}

	if( ctx->rx_ikemesg ){
		rhp_ikev2_unhold_mesg(ctx->rx_ikemesg);
	}

	if( ctx->tx_ikemesg ){
		rhp_ikev2_unhold_mesg(ctx->tx_ikemesg);
	}

	rhp_vpn_unhold(ctx->vpn_ref);

	if( ctx->peer_identity ){
		_rhp_free(ctx->peer_identity);
	}

	_rhp_free_zero(ctx,sizeof(rhp_eap_auth_impl_ctx));

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_VPN_CLEANUP_L_RTRN,"x",impl_ctx);
	return;
}

void rhp_eap_auth_impl_vpn_cleanup(rhp_vpn* vpn,void* impl_ctx)
{
	rhp_eap_auth_impl_ctx_comm* ctx = (rhp_eap_auth_impl_ctx_comm*)impl_ctx;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_VPN_CLEANUP,"xxd",vpn,impl_ctx,ctx->method);

	if( ctx->method < RHP_PROTO_EAP_TYPE_PRIV_MIN ||
			ctx->method == RHP_PROTO_EAP_TYPE_PRIV_IKEV1_XAUTH_PAP ){

		_rhp_eap_auth_impl_vpn_cleanup(vpn,impl_ctx);

	}else if( ctx->method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS ){

		rhp_eap_auth_impl_vpn_cleanup_for_radius(vpn,impl_ctx);
	}

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_VPN_CLEANUP_RTRN,"xxd",vpn,impl_ctx,ctx->method);
	return;
}


static int _rhp_eap_auth_impl_init_req(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg,void* impl_ctx)
{
	int err = -EINVAL;
	rhp_eap_auth_impl_ctx* ctx = (rhp_eap_auth_impl_ctx*)impl_ctx;
	rhp_ipcmsg_eap_handle_req ipc_req;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_INIT_REQ_L,"xxxxxx",vpn,RHP_VPN_REF(ctx->vpn_ref),ikesa,rx_ikemesg,tx_ikemesg,impl_ctx);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_MAIN ){
    RHP_BUG("");
    return -EPERM;
  }

	if( RHP_VPN_REF(ctx->vpn_ref) != vpn ){
		RHP_BUG("");
		return -EINVAL;
	}

	memset(&ipc_req,0,sizeof(rhp_ipcmsg_eap_handle_req));

	{
		ipc_req.tag[0] = '#';
		ipc_req.tag[1] = 'I';
		ipc_req.tag[2] = 'M';
		ipc_req.tag[3] = 'S';


		ipc_req.len = sizeof(rhp_ipcmsg_eap_handle_req);

		if( ctx->method == RHP_PROTO_EAP_TYPE_PRIV_IKEV1_XAUTH_PAP ){

			ipc_req.type = RHP_IPC_XAUTH_AUTH_HANDLE_REQUEST;

		}else{

			ipc_req.type = RHP_IPC_EAP_AUTH_HANDLE_REQUEST;
		}

		ipc_req.txn_id = rhp_ikesa_new_ipc_txn_id();
		ipc_req.vpn_realm_id = vpn->vpn_realm_id;
		ipc_req.init_req = 1;
		ipc_req.eap_mesg_len = 0;
		memcpy(ipc_req.unique_id,vpn->unique_id,RHP_VPN_UNIQUE_ID_SIZE);
		ipc_req.side = ikesa->side;
		memcpy(ipc_req.spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
		ipc_req.peer_notified_realm_id = vpn->peer_notified_realm_id;
		ipc_req.is_init_req = 1;
	}


  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)&ipc_req,ipc_req.len,0) < 0 ){
  	err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  ctx->rx_ikemesg = rx_ikemesg;
	rhp_ikev2_hold_mesg(rx_ikemesg);

  ctx->tx_ikemesg = tx_ikemesg;
	rhp_ikev2_hold_mesg(tx_ikemesg);

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_INIT_REQ_L_RTRN,"xxx",vpn,ikesa,rx_ikemesg);
	return RHP_EAP_STAT_PENDING;

error:
	RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_INIT_REQ_L_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);
	return err;
}

int rhp_eap_auth_impl_init_req(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg,void* impl_ctx)
{
	rhp_eap_auth_impl_ctx_comm* ctx = (rhp_eap_auth_impl_ctx_comm*)impl_ctx;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_INIT_REQ,"xxxxxd",vpn,ikesa,rx_ikemesg,tx_ikemesg,impl_ctx,ctx->method);

	if( ctx->method < RHP_PROTO_EAP_TYPE_PRIV_MIN ||
			ctx->method == RHP_PROTO_EAP_TYPE_PRIV_IKEV1_XAUTH_PAP ){

		return _rhp_eap_auth_impl_init_req(vpn,ikesa,rx_ikemesg,tx_ikemesg,impl_ctx);

	}else if( ctx->method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS ){

		return rhp_eap_auth_impl_init_req_for_radius(vpn,ikesa,rx_ikemesg,tx_ikemesg,impl_ctx);
	}

	RHP_BUG("%d",ctx->method);
	return -EINVAL;
}

static int _rhp_eap_auth_impl_recv_eap(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_payload* rx_eap_pld,rhp_ikev2_mesg* tx_ikemesg,void* impl_ctx)
{
	int err = -EINVAL;
	rhp_eap_auth_impl_ctx* ctx = (rhp_eap_auth_impl_ctx*)impl_ctx;
	rhp_ipcmsg_eap_handle_req* ipc_req = NULL;
	int len = sizeof(rhp_ipcmsg_eap_handle_req);
	u8* eap_msg = NULL;
	int eap_msg_len = 0;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_RECV_EAP_L,"xxxxxx",vpn,ikesa,rx_ikemesg,rx_eap_pld,tx_ikemesg,impl_ctx);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_MAIN ){
    RHP_BUG("");
    return -EPERM;
  }

	eap_msg = rx_eap_pld->ext.eap->get_eap_message(rx_eap_pld,&eap_msg_len);
	if( eap_msg == NULL ){
	  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_RECV_EAP_L_NO_EAP_MESG,"xxx",vpn,ikesa,rx_ikemesg);
		err = RHP_STATUS_INVALID_MSG;
		goto error;
	}

	len += eap_msg_len;

	ipc_req = (rhp_ipcmsg_eap_handle_req*)rhp_ipc_alloc_msg(RHP_IPC_EAP_AUTH_HANDLE_REQUEST,len);
	if( ipc_req == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	ipc_req->len = len;
	ipc_req->type = RHP_IPC_EAP_AUTH_HANDLE_REQUEST;
	ipc_req->txn_id = rhp_ikesa_new_ipc_txn_id();
	ipc_req->vpn_realm_id = vpn->vpn_realm_id;
	ipc_req->init_req = 0;
	ipc_req->eap_mesg_len = eap_msg_len;
	memcpy(ipc_req->unique_id,vpn->unique_id,RHP_VPN_UNIQUE_ID_SIZE);
	ipc_req->side = ikesa->side;
	memcpy(ipc_req->spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
	ipc_req->peer_notified_realm_id = vpn->peer_notified_realm_id;

	if( eap_msg ){
		memcpy((ipc_req + 1),eap_msg,eap_msg_len);
	}

  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipc_req,ipc_req->len,0) < 0 ){
  	err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  ctx->rx_ikemesg = rx_ikemesg;
	rhp_ikev2_hold_mesg(rx_ikemesg);

  ctx->tx_ikemesg = tx_ikemesg;
	rhp_ikev2_hold_mesg(tx_ikemesg);

  _rhp_free_zero(ipc_req,ipc_req->len);

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_RECV_EAP_L_NO_EAP_MESG_RTRN,"xxx",vpn,ikesa,rx_ikemesg);
	return RHP_EAP_STAT_PENDING;

error:
	if( ipc_req ){
	  _rhp_free_zero(ipc_req,ipc_req->len);
	}
	RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_RECV_EAP_L_NO_EAP_MESG_ERR,"xxx",vpn,ikesa,rx_ikemesg,err);
	return err;
}

static int _rhp_eap_auth_impl_recv_xauth(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_payload* rx_xauth_attr_pld,rhp_ikev2_mesg* tx_ikemesg,void* impl_ctx)
{
	int err = -EINVAL;
	rhp_eap_auth_impl_ctx* ctx = (rhp_eap_auth_impl_ctx*)impl_ctx;
	rhp_ipcmsg_eap_handle_req* ipc_req = NULL;
	int len = sizeof(rhp_ipcmsg_eap_handle_req);
	u8* attr_pld = NULL;
	int attr_pld_len = 0;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_RECV_XAUTH_L,"xxxxxx",vpn,ikesa,rx_ikemesg,rx_xauth_attr_pld,tx_ikemesg,impl_ctx);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_MAIN ){
    RHP_BUG("");
    return -EPERM;
  }

  attr_pld = (u8*)rx_xauth_attr_pld->payloadh;
	if( attr_pld == NULL ){
	  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_RECV_XAUTH_L_NO_EAP_MESG,"xxx",vpn,ikesa,rx_ikemesg);
		err = RHP_STATUS_INVALID_MSG;
		goto error;
	}

	attr_pld_len = ntohs(rx_xauth_attr_pld->payloadh->len);
	len += attr_pld_len;

	ipc_req = (rhp_ipcmsg_eap_handle_req*)rhp_ipc_alloc_msg(RHP_IPC_XAUTH_AUTH_HANDLE_REQUEST,len);
	if( ipc_req == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	ipc_req->len = len;
	ipc_req->type = RHP_IPC_XAUTH_AUTH_HANDLE_REQUEST;
	ipc_req->txn_id = rhp_ikesa_new_ipc_txn_id();
	ipc_req->vpn_realm_id = vpn->vpn_realm_id;
	ipc_req->init_req = 0;
	ipc_req->eap_mesg_len = attr_pld_len;
	memcpy(ipc_req->unique_id,vpn->unique_id,RHP_VPN_UNIQUE_ID_SIZE);
	ipc_req->side = ikesa->side;
	memcpy(ipc_req->spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
	ipc_req->peer_notified_realm_id = vpn->peer_notified_realm_id;

	if( attr_pld ){
		memcpy((ipc_req + 1),attr_pld,attr_pld_len);
	}

  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipc_req,ipc_req->len,0) < 0 ){
  	err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  ctx->rx_ikemesg = rx_ikemesg;
	rhp_ikev2_hold_mesg(rx_ikemesg);

  ctx->tx_ikemesg = tx_ikemesg;
	rhp_ikev2_hold_mesg(tx_ikemesg);

  _rhp_free_zero(ipc_req,ipc_req->len);

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_RECV_XAUTH_L_NO_EAP_MESG_RTRN,"xxx",vpn,ikesa,rx_ikemesg);
	return RHP_EAP_STAT_PENDING;

error:
	if( ipc_req ){
	  _rhp_free_zero(ipc_req,ipc_req->len);
	}
	RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_RECV_XAUTH_L_NO_EAP_MESG_ERR,"xxx",vpn,ikesa,rx_ikemesg,err);
	return err;
}

int rhp_eap_auth_impl_recv(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_payload* rx_eap_or_xauth_attr_pld,rhp_ikev2_mesg* tx_ikemesg,void* impl_ctx)
{
	rhp_eap_auth_impl_ctx_comm* ctx = (rhp_eap_auth_impl_ctx_comm*)impl_ctx;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_RECV,"xxxxxxd",vpn,ikesa,rx_ikemesg,rx_eap_or_xauth_attr_pld,tx_ikemesg,impl_ctx,ctx->method);

	if( ctx->method < RHP_PROTO_EAP_TYPE_PRIV_MIN ){

		return _rhp_eap_auth_impl_recv_eap(vpn,ikesa,rx_ikemesg,rx_eap_or_xauth_attr_pld,tx_ikemesg,impl_ctx);

	}else if( ctx->method == RHP_PROTO_EAP_TYPE_PRIV_IKEV1_XAUTH_PAP ){

		return _rhp_eap_auth_impl_recv_xauth(vpn,ikesa,rx_ikemesg,rx_eap_or_xauth_attr_pld,tx_ikemesg,impl_ctx);

	}else if( ctx->method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS ){

		return rhp_eap_auth_impl_recv_for_radius(vpn,ikesa,rx_ikemesg,rx_eap_or_xauth_attr_pld,tx_ikemesg,impl_ctx);
	}

	RHP_BUG("%d",ctx->method);
	return -EINVAL;
}


static int _rhp_eap_auth_get_msk(rhp_vpn* vpn,void* impl_ctx,int* msk_len_r,u8** msk_r)
{
	rhp_eap_auth_impl_ctx* ctx = (rhp_eap_auth_impl_ctx*)impl_ctx;
	u8* ret;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_GET_MSK_L,"xxxx",vpn,impl_ctx,msk_len_r,msk_r);

	if( !ctx->is_completed ){
		RHP_BUG("");
		return -ENOENT;
	}

	ret = (u8*)_rhp_malloc(64);
	if( ret == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	memcpy(ret,ctx->msk,64);

	*msk_len_r = 64;
	*msk_r = ret;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_GET_MSK_L_RTRN,"xxp",vpn,impl_ctx,*msk_len_r,*msk_r);
	return 0;
}

int rhp_eap_auth_get_msk(rhp_vpn* vpn,void* impl_ctx,int* msk_len_r,u8** msk_r)
{
	rhp_eap_auth_impl_ctx_comm* ctx = (rhp_eap_auth_impl_ctx_comm*)impl_ctx;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_GET_MSK,"xxxxd",vpn,impl_ctx,msk_len_r,msk_r,ctx->method);

	if( ctx->method < RHP_PROTO_EAP_TYPE_PRIV_MIN ){

		return _rhp_eap_auth_get_msk(vpn,impl_ctx,msk_len_r,msk_r);

	}else if( ctx->method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS ){

		return rhp_eap_auth_get_msk_for_radius(vpn,impl_ctx,msk_len_r,msk_r);
	}

	RHP_BUG("%d",ctx->method);
	return -EINVAL;
}

static int _rhp_eap_auth_get_peer_identity(rhp_vpn* vpn,void* impl_ctx,int* ident_len_r,u8** ident_r)
{
	rhp_eap_auth_impl_ctx* ctx = (rhp_eap_auth_impl_ctx*)impl_ctx;
	u8* ret;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_GET_PEER_IDENTITY_L,"xxxx",vpn,impl_ctx,ident_len_r,ident_r);

	if( !ctx->is_completed ){
		RHP_BUG("");
		return -ENOENT;
	}

	if( ctx->peer_identity_len < 1 ){
		RHP_BUG("");
		return -ENOENT;
	}

	ret = (u8*)_rhp_malloc(ctx->peer_identity_len);
	if( ret == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	memcpy(ret,ctx->peer_identity,ctx->peer_identity_len);

	*ident_len_r = ctx->peer_identity_len;
	*ident_r = ret;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_GET_PEER_IDENTITY_L_RTRN,"xxp",vpn,impl_ctx,*ident_len_r,*ident_r);
	return 0;
}

int rhp_eap_auth_get_peer_identity(rhp_vpn* vpn,void* impl_ctx,int* ident_len_r,u8** ident_r)
{
	rhp_eap_auth_impl_ctx_comm* ctx = (rhp_eap_auth_impl_ctx_comm*)impl_ctx;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_GET_PEER_IDENTITY,"xxxxd",vpn,impl_ctx,ident_len_r,ident_r,ctx->method);

	if( ctx->method < RHP_PROTO_EAP_TYPE_PRIV_MIN ||
			ctx->method == RHP_PROTO_EAP_TYPE_PRIV_IKEV1_XAUTH_PAP ){

		return _rhp_eap_auth_get_peer_identity(vpn,impl_ctx,ident_len_r,ident_r);

	}else if( ctx->method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS ){

		return rhp_eap_auth_get_peer_identity_for_radius(vpn,impl_ctx,ident_len_r,ident_r);
	}

	RHP_BUG("%d",ctx->method);
	return -EINVAL;
}


extern char* rhp_eap_method2str_def(int method);

char* rhp_eap_auth_impl_method2str(int method)
{
	return rhp_eap_method2str_def(method);
}

extern int rhp_eap_str2method_def(char* method_name);

int rhp_eap_auth_str2method(char* method_name)
{
	return rhp_eap_str2method_def(method_name);
}


int rhp_eap_auth_impl_method_is_supported(int method)
{
	int ret = 0;

	switch(method){

	case RHP_PROTO_EAP_TYPE_MS_CHAPV2:
	case RHP_PROTO_EAP_TYPE_PRIV_RADIUS:
	case RHP_PROTO_EAP_TYPE_PRIV_IKEV1_XAUTH_PAP:

		ret = 1;
		break;

	default:
		break;
	}

	return ret;
}


int rhp_eap_auth_impl_radius_set_secret(int index,u8* secret,int secret_len)
{
	if( index < 0 || index > RHP_RADIUS_SECRET_IDX_MAX ){
		RHP_BUG("%d",index);
		return -EINVAL;
	}
	return rhp_radius_impl_set_secret(index,secret,secret_len);
}


extern int rhp_eap_syspxy_auth_init();
extern int rhp_eap_syspxy_auth_cleanup();


static rhp_prc_ipcmsg_wts_handler _rhp_eap_auth_main_ipc = {
	wts_type: RHP_WTS_DISP_RULE_AUTHREP,
	wts_disp_priority: RHP_WTS_DISP_LEVEL_HIGH_1,
	wts_disp_wait: 1,
	wts_is_fixed_rule: 0,
	wts_task_handler: _rhp_eap_auth_main_ipc_handler
};

static rhp_prc_ipcmsg_wts_handler _rhp_eap_auth_main_xauth_ipc = {
	wts_type: RHP_WTS_DISP_RULE_AUTHREP,
	wts_disp_priority: RHP_WTS_DISP_LEVEL_HIGH_1,
	wts_disp_wait: 1,
	wts_is_fixed_rule: 0,
	wts_task_handler: _rhp_eap_auth_main_xauth_ipc_handler
};

extern rhp_atomic_t _rhp_eap_auth_radius_open_sessions;

int rhp_eap_auth_impl_init()
{
	int err;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_INIT,"Ld","PROCESS_ROLE",RHP_MY_PROCESS->role);

  if( RHP_MY_PROCESS->role == RHP_PROCESS_ROLE_MAIN ){

  	err = _rhp_atomic_init(&_rhp_eap_auth_radius_open_sessions);
  	if( err ){
			RHP_BUG("");
			return err;
  	}
  	_rhp_atomic_set(&_rhp_eap_auth_radius_open_sessions,0);


		err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_EAP_AUTH_HANDLE_REPLY,
						NULL,&_rhp_eap_auth_main_ipc);
		if( err ){
			RHP_BUG("");
			return err;
		}


		err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_XAUTH_AUTH_HANDLE_REPLY,
						NULL,&_rhp_eap_auth_main_xauth_ipc);
		if( err ){
			RHP_BUG("");
			return err;
		}

  }else if( RHP_MY_PROCESS->role == RHP_PROCESS_ROLE_SYSPXY ){

  	err = rhp_eap_syspxy_auth_init();
  	if( err ){
			RHP_BUG("");
			return err;
		}
  }

  err = rhp_radius_impl_init();
  if( err ){
  	RHP_BUG("%d",err);
  	return err;
  }

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_INIT_RTRN,"");
  return 0;
}

int rhp_eap_auth_impl_cleanup()
{
	int err = -EINVAL;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_CLEANUP,"Ld","PROCESS_ROLE",RHP_MY_PROCESS->role);

  if( RHP_MY_PROCESS->role == RHP_PROCESS_ROLE_SYSPXY ){

  	err = rhp_eap_syspxy_auth_cleanup();
		if( err ){
			RHP_BUG("");
			return err;
		}
  }

  err = rhp_radius_impl_cleanup();
  if( err ){
  	RHP_BUG("%d",err);
  	return err;
  }

  _rhp_atomic_destroy(&_rhp_eap_auth_radius_open_sessions);

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_CLEANUP_RTRN,"");
	return 0;
}

