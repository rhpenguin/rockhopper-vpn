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
#include "rhp_vpn.h"
#include "rhp_http.h"
#include "rhp_eap_sup_impl.h"

struct _rhp_eap_sup_impl_ctx {

	u8 tag[4]; // '#ESI'

	int method;

	rhp_vpn_ref* vpn_ref;

	int is_completed;

	rhp_ikev2_mesg* rx_ikemesg;
	rhp_ikev2_mesg* tx_ikemesg;

	// MS-CHAPv2: MSK = server MS-MPPE-Recv-Key + MS-MPPE-Send-Key + 32 bytes zeroes (padding)
	u8 msk[64];

	u8* my_identity;
	int my_identity_len;
};
typedef struct _rhp_eap_sup_impl_ctx	rhp_eap_sup_impl_ctx;


extern int rhp_eap_sup_syspxy_init();
extern int rhp_eap_sup_syspxy_cleanup();


rhp_ipcmsg_eap_user_key* _rhp_eap_sup_main_alloc_ipc_user_key(
		unsigned long rlm_id,u8* unique_id,
		int my_ikesa_side,u8* my_ikesa_spi,
		int eap_method,u8* user_id,int user_id_len,u8* user_key,int user_key_len,u64 txn_id)
{
	rhp_ipcmsg_eap_user_key* ipc_key = NULL;
  int ipc_key_len = sizeof(rhp_ipcmsg_eap_user_key);

  RHP_TRC(0,RHPTRCID_EAP_SUP_MAIN_ALLOC_IPC_USER_KEY,"upLdGdppq",rlm_id,RHP_VPN_UNIQUE_ID_SIZE,unique_id,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,eap_method,user_id_len,user_id,user_key_len,user_key,txn_id);

	ipc_key_len += user_id_len + user_key_len;

	ipc_key = (rhp_ipcmsg_eap_user_key*)rhp_ipc_alloc_msg(RHP_IPC_EAP_SUP_USER_KEY,ipc_key_len);
	if(ipc_key == NULL){
		RHP_BUG("");
		goto error;
	}
	ipc_key->len = ipc_key_len;

	ipc_key->txn_id = txn_id;
	ipc_key->vpn_realm_id = rlm_id;
	memcpy(ipc_key->unique_id,unique_id,RHP_VPN_UNIQUE_ID_SIZE);
	ipc_key->side = my_ikesa_side;
	memcpy(ipc_key->spi,my_ikesa_spi,RHP_PROTO_IKE_SPI_SIZE);

	ipc_key->eap_method = (unsigned int)eap_method;
	ipc_key->user_id_len = user_id_len;
	ipc_key->user_key_len = user_key_len;

	memcpy((u8*)(ipc_key + 1),user_id,user_id_len);
	memcpy(((u8*)(ipc_key + 1)) + user_id_len,user_key,user_key_len);

  RHP_TRC(0,RHPTRCID_EAP_SUP_MAIN_ALLOC_IPC_USER_KEY_RTRN,"uqx",rlm_id,txn_id,ipc_key);
	return ipc_key;

error:
	RHP_TRC(0,RHPTRCID_EAP_SUP_MAIN_ALLOC_IPC_USER_KEY_ERR,"uq",rlm_id,txn_id);
	return NULL;
}

void* rhp_eap_sup_impl_vpn_init(int method,rhp_vpn* vpn,rhp_vpn_realm* rlm,rhp_ikesa* ikesa,
		u8* eap_user_id,int eap_user_id_len,u8* eap_user_key,int eap_user_key_len)
{
	rhp_eap_sup_impl_ctx* ctx = NULL;
	rhp_ipcmsg_eap_user_key* ipc_key = NULL;

  RHP_TRC(0,RHPTRCID_EAP_SUP_IMPL_VPN_INIT,"Ldxxx","EAP_TYPE",method,vpn,rlm,ikesa);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_MAIN ){
    RHP_BUG("");
    return NULL;
  }

  if( (eap_user_id && eap_user_key == NULL) || (eap_user_id == NULL && eap_user_key) ){
    RHP_BUG("");
    return NULL;
  }

  if( eap_user_id && eap_user_key ){

  	ipc_key = _rhp_eap_sup_main_alloc_ipc_user_key(vpn->vpn_realm_id,vpn->unique_id,
				ikesa->side,ikesa->init_spi,
				method,eap_user_id,eap_user_id_len,eap_user_key,eap_user_key_len,0);

		if( ipc_key == NULL ){
			RHP_BUG("");
			return NULL;
		}
  }

	ctx = (rhp_eap_sup_impl_ctx*)_rhp_malloc(sizeof(rhp_eap_sup_impl_ctx));
	if( ctx == NULL ){

		RHP_BUG("");

		if( ipc_key ){
			_rhp_free_zero(ipc_key,ipc_key->len);
		}
		return NULL;
	}

	memset(ctx,0,sizeof(rhp_eap_sup_impl_ctx));

	ctx->tag[0] = '#';
	ctx->tag[1] = 'E';
	ctx->tag[2] = 'S';
	ctx->tag[3] = 'I';

	ctx->method = method;

	ctx->vpn_ref = rhp_vpn_hold_ref(vpn);

	if( ipc_key ){
		if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipc_key,ipc_key->len,0) < 0 ){
			RHP_BUG("");
		}

		_rhp_free_zero(ipc_key,ipc_key->len);
	}

  RHP_TRC(0,RHPTRCID_EAP_SUP_IMPL_VPN_INIT_RTRN,"Ldxxxx","EAP_TYPE",method,vpn,rlm,ikesa,ctx);
	return (void*)ctx;
}

void rhp_eap_sup_impl_vpn_cleanup(rhp_vpn* vpn,void* impl_ctx)
{
	rhp_eap_sup_impl_ctx* ctx = (rhp_eap_sup_impl_ctx*)impl_ctx;

  if( ctx == NULL ){
    RHP_TRC(0,RHPTRCID_EAP_SUP_IMPL_VPN_CLEANUP_NO_SUP_CTX,"xx",vpn,impl_ctx);
  	return;
  }

  RHP_TRC(0,RHPTRCID_EAP_SUP_IMPL_VPN_CLEANUP,"xxxd",vpn,RHP_VPN_REF(ctx->vpn_ref),impl_ctx,ctx->is_completed);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_MAIN ){
    RHP_BUG("");
    return;
  }

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
		ipc_cancel.type = RHP_IPC_EAP_SUP_HANDLE_CANCEL;
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

	_rhp_free_zero(ctx,sizeof(rhp_eap_sup_impl_ctx));

  RHP_TRC(0,RHPTRCID_EAP_SUP_IMPL_VPN_CLEANUP_RTRN,"x",impl_ctx);
	return;
}

int rhp_eap_sup_impl_recv(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_payload* rx_eap_pld,rhp_ikev2_mesg* tx_ikemesg,void* impl_ctx)
{
	int err = -EINVAL;
	rhp_eap_sup_impl_ctx* ctx = (rhp_eap_sup_impl_ctx*)impl_ctx;
	rhp_ipcmsg_eap_handle_req* ipc_req = NULL;
	int len = sizeof(rhp_ipcmsg_eap_handle_req);
	u8* eap_msg = NULL;
	int eap_msg_len = 0;

  RHP_TRC(0,RHPTRCID_EAP_SUP_IMPL_RECV,"xxxxxx",vpn,ikesa,rx_ikemesg,rx_eap_pld,tx_ikemesg,impl_ctx);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_MAIN ){
    RHP_BUG("");
    return -EPERM;
  }

	eap_msg = rx_eap_pld->ext.eap->get_eap_message(rx_eap_pld,&eap_msg_len);
	if( eap_msg == NULL ){
	  RHP_TRC(0,RHPTRCID_EAP_SUP_IMPL_RECV_NO_EAP_MESG,"xxx",vpn,ikesa,rx_ikemesg);
		err = RHP_STATUS_INVALID_MSG;
		goto error;
	}

	len += eap_msg_len;

	ipc_req = (rhp_ipcmsg_eap_handle_req*)rhp_ipc_alloc_msg(RHP_IPC_EAP_SUP_HANDLE_REQUEST,len);
	if( ipc_req == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	ipc_req->len = len;
	ipc_req->type = RHP_IPC_EAP_SUP_HANDLE_REQUEST;
	ipc_req->txn_id = rhp_ikesa_new_ipc_txn_id();
	ipc_req->vpn_realm_id = vpn->vpn_realm_id;
	ipc_req->init_req = 0;
	ipc_req->eap_mesg_len = eap_msg_len;
	memcpy(ipc_req->unique_id,vpn->unique_id,RHP_VPN_UNIQUE_ID_SIZE);
	ipc_req->side = ikesa->side;
	memcpy(ipc_req->spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);

	ipc_req->eap_method = vpn->eap.eap_method;

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

  RHP_TRC(0,RHPTRCID_EAP_SUP_IMPL_RECV_RTRN,"xxx",vpn,ikesa,rx_ikemesg);
	return RHP_EAP_STAT_PENDING;

error:
	if( ipc_req ){
	  _rhp_free_zero(ipc_req,ipc_req->len);
	}
	RHP_TRC(0,RHPTRCID_EAP_SUP_IMPL_RECV_ERR,"xxx",vpn,ikesa,rx_ikemesg,err);
	return err;
}

int rhp_eap_sup_impl_get_msk(rhp_vpn* vpn,void* impl_ctx,int* msk_len_r,u8** msk_r)
{
	rhp_eap_sup_impl_ctx* ctx = (rhp_eap_sup_impl_ctx*)impl_ctx;
	u8* ret;

  RHP_TRC(0,RHPTRCID_EAP_SUP_GET_MSK,"xxxx",vpn,impl_ctx,msk_len_r,msk_r);

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

  RHP_TRC(0,RHPTRCID_EAP_SUP_GET_MSK_RTRN,"xxp",vpn,impl_ctx,*msk_len_r,*msk_r);
	return 0;
}

int rhp_eap_sup_get_my_identity(rhp_vpn* vpn,void* impl_ctx,int* ident_len_r,u8** ident_r)
{
	rhp_eap_sup_impl_ctx* ctx = (rhp_eap_sup_impl_ctx*)impl_ctx;
	u8* ret;

  RHP_TRC(0,RHPTRCID_EAP_SUP_GET_MY_IDENTITY,"xxxx",vpn,impl_ctx,ident_len_r,ident_r);

	if( !ctx->is_completed ){
		RHP_BUG("");
		return -ENOENT;
	}

	if( ctx->my_identity_len < 1 ){
		RHP_BUG("");
		return -ENOENT;
	}

	ret = (u8*)_rhp_malloc(ctx->my_identity_len);
	if( ret == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	memcpy(ret,ctx->my_identity,ctx->my_identity_len);

	*ident_len_r = ctx->my_identity_len;
	*ident_r = ret;

  RHP_TRC(0,RHPTRCID_EAP_SUP_GET_MY_IDENTITY_RTRN,"xxp",vpn,impl_ctx,*ident_len_r,*ident_r);
	return 0;
}

static void _rhp_eap_sup_main_reply_ipc_handler(int worker_idx,void* wts_ctx)
{
	int err = -EINVAL;
	rhp_ipcmsg_eap_handle_rep* ipc_rep = (rhp_ipcmsg_eap_handle_rep*)wts_ctx;
	rhp_eap_sup_impl_ctx* ctx = NULL;
	rhp_vpn_ref* vpn_ref = NULL;
	rhp_vpn* vpn = NULL;
	rhp_ikesa* ikesa = NULL;
	rhp_ikev2_mesg* rx_ikemesg = NULL;
	rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_EAP_SUP_MAIN_REPLY_IPC_HANDLER,"x",ipc_rep);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_MAIN ){
    RHP_BUG("");
    return;
  }

	if( ipc_rep->len < sizeof(rhp_ipcmsg_eap_handle_rep) ){
		RHP_BUG("%d:%d",ipc_rep->len,sizeof(rhp_ipcmsg_eap_handle_rep));
		return;
	}

	if( ipc_rep->type != RHP_IPC_EAP_SUP_HANDLE_REPLY ){
		RHP_BUG("%d",ipc_rep->type);
		return;
	}

  RHP_TRC(0,RHPTRCID_EAP_SUP_MAIN_REPLY_IPC_HANDLER_IPC_REP_DATA,"xEuupLdGdd",ipc_rep,ipc_rep->status,ipc_rep->vpn_realm_id,ipc_rep->rebound_vpn_realm_id,RHP_VPN_UNIQUE_ID_SIZE,ipc_rep->unique_id,"IKE_SIDE",ipc_rep->side,ipc_rep->spi,ipc_rep->eap_mesg_len,ipc_rep->msk_len);



  vpn_ref = rhp_vpn_get_by_unique_id(ipc_rep->unique_id);
	vpn = RHP_VPN_REF(vpn_ref);
  if( vpn == NULL ){
    RHP_TRC(0,RHPTRCID_EAP_SUP_MAIN_REPLY_IPC_HANDLER_NO_VPN,"xLdG",ipc_rep,"IKE_SIDE",ipc_rep->side,ipc_rep->spi);
    goto error;
  }

  RHP_LOCK(&(vpn->lock));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_EAP_AUTH_SUP_IPC_HANDLER_VPN_NOT_ACTIVE,"xx",ipc_rep,vpn);
    goto error_vpn_l;
  }


  ikesa = vpn->ikesa_get(vpn,ipc_rep->side,ipc_rep->spi);
  if( ikesa == NULL ){
    RHP_TRC(0,RHPTRCID_EAP_SUP_MAIN_REPLY_IPC_HANDLER_NO_IKESA,"xxLdG",ipc_rep,vpn,"IKE_SIDE",ipc_rep->side,ipc_rep->spi);
  	goto error_vpn_l;
  }

  ctx = (rhp_eap_sup_impl_ctx*)vpn->eap.impl_ctx;
  if( ctx == NULL ){
  	RHP_BUG("");
  	goto error_vpn_l;
  }

	rx_ikemesg = ctx->rx_ikemesg;
	ctx->rx_ikemesg = NULL;
	tx_ikemesg = ctx->tx_ikemesg;
	ctx->tx_ikemesg = NULL;

	if( ipc_rep->eap_mesg_len &&
			( (ipc_rep->eap_mesg_len < sizeof(rhp_proto_eap)) /*Min len = EAP Header*/ ||
			(ipc_rep->len - sizeof(rhp_ipcmsg_eap_handle_rep)) < sizeof(rhp_proto_eap)) ){
		RHP_BUG("");
		err = -EINVAL;
		goto error_vpn_l;
	}

	if( ipc_rep->eap_mesg_len ){

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

    RHP_TRC(0,RHPTRCID_EAP_SUP_MAIN_REPLY_IPC_HANDLER_RX_EAP_ERR,"xxE",ipc_rep,vpn,ipc_rep->status);

		err = RHP_STATUS_EAP_STAT_ERROR;
		goto error_vpn_l;

	}else if( ipc_rep->status == RHP_EAP_STAT_COMPLETED ){

		ctx->is_completed = 1;

		if( ipc_rep->msk_len != 64 ){
			RHP_BUG("%d",ipc_rep->msk_len);
		}else{
			memcpy(ctx->msk,(((u8*)(ipc_rep + 1)) + ipc_rep->eap_mesg_len),64);
		}


		if( ipc_rep->my_identity_len ){

			ctx->my_identity = (u8*)_rhp_malloc(ipc_rep->my_identity_len + 1);
			if( ctx->my_identity == NULL ){
				RHP_BUG("");
			}else{

				memcpy(ctx->my_identity,
						(((u8*)(ipc_rep + 1)) + ipc_rep->eap_mesg_len + ipc_rep->msk_len),ipc_rep->my_identity_len);

				ctx->my_identity_len = ipc_rep->my_identity_len;
				ctx->my_identity[ctx->my_identity_len] = '\0';
			}
		}

		RHP_TRC(0,RHPTRCID_EAP_SUP_MAIN_REPLY_IPC_HANDLER_MSK_AND_MY_ID,"xpp",ipc_rep,64,ctx->msk,ctx->my_identity_len,ctx->my_identity);
	}


	rhp_eap_recv_callback(vpn,ikesa->side,ikesa->init_spi,rx_ikemesg,tx_ikemesg,ipc_rep->status);

  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

	rhp_ikev2_unhold_mesg(rx_ikemesg);
	rhp_ikev2_unhold_mesg(tx_ikemesg);

  _rhp_free_zero(ipc_rep,ipc_rep->len);

  RHP_TRC(0,RHPTRCID_EAP_SUP_MAIN_REPLY_IPC_HANDLER_RTRN,"xx",ipc_rep,vpn);
	return;


error_vpn_l:
	if( ikesa && rx_ikemesg && tx_ikemesg ){

		rhp_eap_recv_callback(vpn,ikesa->side,ikesa->init_spi,rx_ikemesg,tx_ikemesg,RHP_EAP_STAT_ERROR);
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

	if( ipc_rep ){
		_rhp_free_zero(ipc_rep,ipc_rep->len);
	}

  RHP_TRC(0,RHPTRCID_EAP_SUP_MAIN_REPLY_IPC_HANDLER_ERR,"xxE",ipc_rep,vpn,err);
	return;
}


// user_id_len and user_key_len : '\0' NOT included.
static void _rhp_eap_sup_main_user_key_req_cb(void* ctx,rhp_vpn* vpn,int my_ikesa_side,u8* my_ikesa_spi,
		int eap_method,u8* user_id,int user_id_len,u8* user_key,int user_key_len)
{
	int err = -EINVAL;
	rhp_ipcmsg_eap_user_key* ipc_key_rep = NULL;

	RHP_TRC(0,RHPTRCID_EAP_SUP_MAIN_USER_KEY_REQ_CB,"xxLdGdpp",ctx,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,eap_method,user_id_len,user_id,user_key_len,user_key);

  if( vpn->eap.ask_usr_key_ipc_txn_id == (u64)-1 ){
  	RHP_BUG("");
  	goto error;
  }

  if( user_id_len <= 0 || user_key_len <= 0 ){
  	RHP_BUG("");
  	goto error;
  }

  ipc_key_rep = _rhp_eap_sup_main_alloc_ipc_user_key(vpn->vpn_realm_id,vpn->unique_id,
  		my_ikesa_side,my_ikesa_spi,
  		eap_method,user_id,user_id_len,user_key,user_key_len,
  		vpn->eap.ask_usr_key_ipc_txn_id);

	if(ipc_key_rep == NULL){
		RHP_BUG("");
		goto error;
	}

  vpn->eap.ask_usr_key_ipc_txn_id = (u64)-1;

	if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipc_key_rep,ipc_key_rep->len,0) < 0 ){
		RHP_BUG("");
		goto error;
  }

error:
	if( ipc_key_rep ){
		_rhp_free_zero(ipc_key_rep,ipc_key_rep->len);
	}

	RHP_TRC(0,RHPTRCID_EAP_SUP_MAIN_USER_KEY_REQ_CB_RTRN,"xx",ctx,vpn);
	return;
}

static void _rhp_eap_sup_main_user_key_req_ipc_handler(int worker_idx,void* wts_ctx)
{
	int err = -EINVAL;
	rhp_ipcmsg_eap_user_key_req* ipc_req = (rhp_ipcmsg_eap_user_key_req*)wts_ctx;
	rhp_eap_sup_impl_ctx* ctx = NULL;
	rhp_vpn_ref* vpn_ref = NULL;
	rhp_vpn* vpn = NULL;
	rhp_ikesa* ikesa = NULL;

  RHP_TRC(0,RHPTRCID_EAP_SUP_MAIN_USER_KEY_REQ_IPC_HANDLER,"x",ipc_req);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_MAIN ){
    RHP_BUG("");
    return;
  }

	if( ipc_req->len < sizeof(rhp_ipcmsg_eap_user_key_req) ){
		RHP_BUG("%d:%d",ipc_req->len,sizeof(rhp_ipcmsg_eap_user_key_req));
		return;
	}

	if( ipc_req->type != RHP_IPC_EAP_SUP_USER_KEY_REQUEST ){
		RHP_BUG("%d",ipc_req->type);
		return;
	}

  RHP_TRC(0,RHPTRCID_EAP_SUP_MAIN_USER_KEY_REQ_IPC_HANDLER_IPC_REP_DATA,"xupLdG",ipc_req,ipc_req->vpn_realm_id,RHP_VPN_UNIQUE_ID_SIZE,ipc_req->unique_id,"IKE_SIDE",ipc_req->side,ipc_req->spi);

  vpn_ref = rhp_vpn_get_by_unique_id(ipc_req->unique_id);
	vpn = RHP_VPN_REF(vpn_ref);
  if( vpn == NULL ){
    RHP_TRC(0,RHPTRCID_EAP_SUP_MAIN_USER_KEY_REQ_IPC_HANDLER_NO_VPN,"xpLdG",ipc_req,RHP_VPN_UNIQUE_ID_SIZE,ipc_req->unique_id,"IKE_SIDE",ipc_req->side,ipc_req->spi);
    goto error;
  }

  RHP_LOCK(&(vpn->lock));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_EAP_AUTH_SUP_IPC_HANDLER_VPN_NOT_ACTIVE,"xx",ipc_req,vpn);
    goto error_vpn_l;
  }

  vpn->eap.ask_usr_key_ipc_txn_id = (u64)-1;

  ikesa = vpn->ikesa_get(vpn,ipc_req->side,ipc_req->spi);
  if( ikesa == NULL ){
    RHP_TRC(0,RHPTRCID_EAP_SUP_MAIN_USER_KEY_REQ_IPC_HANDLER_NO_IKESA,"xxLdG",ipc_req,vpn,"IKE_SIDE",ipc_req->side,ipc_req->spi);
  	goto error_vpn_l;
  }

  if( ikesa->eap.state != RHP_IKESA_EAP_STAT_I_PEND ){
  	RHP_BUG("%d",ikesa->eap.state);
    RHP_TRC(0,RHPTRCID_EAP_SUP_MAIN_USER_KEY_REQ_IPC_HANDLER_EAP_BAD_STAT,"xxLdGLd",ipc_req,vpn,"IKE_SIDE",ipc_req->side,ipc_req->spi,"EAP_STAT",ikesa->eap.state);
  	goto error_vpn_l;
  }

  ctx = (rhp_eap_sup_impl_ctx*)vpn->eap.impl_ctx;
  if( ctx == NULL ){
  	RHP_BUG("");
  	goto error_vpn_l;
  }

  {
  	u8 *user_id = NULL;
  	int user_id_len = (int)ipc_req->user_id_len;

  	if( user_id_len > 0 ){

  		user_id = (u8*)(ipc_req + 1);

  	}else{
  	  RHP_TRC(0,RHPTRCID_EAP_SUP_MAIN_USER_KEY_REQ_IPC_HANDLER_NO_USER_ID,"xx",ipc_req,vpn);
  	}

		err = rhp_eap_sup_ask_for_user_key(vpn,ikesa->side,ikesa->init_spi,
						(int)ipc_req->eap_method,user_id,user_id_len,
						_rhp_eap_sup_main_user_key_req_cb,NULL);

		if( err ){
			RHP_BUG("%d",err);
			goto error_vpn_l;
		}
  }

  vpn->eap.ask_usr_key_ipc_txn_id = ipc_req->txn_id;

  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

  _rhp_free_zero(ipc_req,ipc_req->len);

  RHP_TRC(0,RHPTRCID_EAP_SUP_MAIN_USER_KEY_REQ_IPC_HANDLER_RTRN,"xx",ipc_req,vpn);
	return;


error_vpn_l:

	if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
	}

	RHP_UNLOCK(&(vpn->lock));
	rhp_vpn_unhold(vpn_ref);

error:
	if( ipc_req ){
		_rhp_free_zero(ipc_req,ipc_req->len);
	}
	RHP_TRC(0,RHPTRCID_EAP_SUP_MAIN_USER_KEY_REQ_IPC_HANDLER_ERR,"xxE",ipc_req,vpn,err);
	return;
}

static void _rhp_eap_sup_main_user_key_cached_ipc_handler(int worker_idx,void* wts_ctx)
{
	rhp_ipcmsg_eap_user_key_clear_cache* ipc_req = (rhp_ipcmsg_eap_user_key_clear_cache*)wts_ctx;
  rhp_vpn_realm* rlm = NULL;

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_USER_KEY_CACHED_IPC_HANDLER,"xx",wts_ctx,ipc_req);

	if( ipc_req->len < sizeof(rhp_ipcmsg_eap_user_key_clear_cache) ){
		RHP_BUG("");
		goto error;
	}

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_USER_KEY_CACHED_IPC_HANDLER_TYPE,"xLd",ipc_req,"IPC",ipc_req->type);

	if( ipc_req->type != RHP_IPC_EAP_SUP_USER_KEY_CACHED ){

		RHP_BUG("%d",ipc_req->type);
		goto error;
	}

	if( ipc_req->len < sizeof(rhp_ipcmsg_eap_user_key_clear_cache) ){
		RHP_BUG("%d",ipc_req->len);
		goto error;
	}

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_USER_KEY_CACHED_IPC_HANDLER_INFO,"xLdu",ipc_req,"IPC",ipc_req->type,ipc_req->vpn_realm_id);

	if( ipc_req->vpn_realm_id < 1 ){
		RHP_BUG("");
		goto error;
	}

  rlm = rhp_realm_get(ipc_req->vpn_realm_id);
  if( rlm ){

	  RHP_LOCK(&(rlm->lock));

  	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_USER_KEY_CACHED_IPC_HANDLER_CACHED_FLAG,"xudd",ipc_req,ipc_req->vpn_realm_id,rlm->my_auth.eap_sup.enabled,rlm->my_auth.eap_sup.user_key_cached);

  	if( rlm->my_auth.eap_sup.enabled ){
  		rlm->my_auth.eap_sup.user_key_cached = 1;
  	}

	  RHP_UNLOCK(&(rlm->lock));

  }else{
  	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_USER_KEY_CACHED_IPC_HANDLER_NO_RLM,"xu",ipc_req,ipc_req->vpn_realm_id);
  }

error:

	if( ipc_req ){
		_rhp_free_zero(ipc_req,ipc_req->len);
	}

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_USER_KEY_CACHED_IPC_HANDLER_RTRN,"x",ipc_req);
	return;
}


int rhp_eap_sup_impl_is_enabled(rhp_vpn_realm* rlm,rhp_eap_sup_info* info_r)
{
	if( rlm->my_auth.eap_sup.enabled ){

		if( info_r ){

			info_r->eap_method = rlm->my_auth.eap_sup.method;
			info_r->ask_for_user_key = rlm->my_auth.eap_sup.ask_for_user_key;
			info_r->user_key_cache_enabled = rlm->my_auth.eap_sup.user_key_cache_enabled;
			info_r->user_key_is_cached = rlm->my_auth.eap_sup.user_key_cached;

		  RHP_TRC(0,RHPTRCID_EAP_SUP_IMPL_IS_ENABLED_1,"xxdddd",rlm,info_r,info_r->eap_method,info_r->ask_for_user_key,info_r->user_key_cache_enabled,info_r->user_key_is_cached);

		}else{
		  RHP_TRC(0,RHPTRCID_EAP_SUP_IMPL_IS_ENABLED_2,"xx",rlm,info_r);
		}
		return 1;
	}

  RHP_TRC(0,RHPTRCID_EAP_SUP_IMPL_IS_ENABLED_NOT_ENABLED,"xx",rlm,info_r);
	return 0;
}

int rhp_eap_sup_impl_clear_user_key_cache(rhp_vpn_realm* rlm)
{
	if( rlm->my_auth.eap_sup.enabled ){

		rlm->my_auth.eap_sup.user_key_cached = 0;

		{
			rhp_ipcmsg_eap_user_key_clear_cache ipc_msg;
			memset(&ipc_msg,0,sizeof(rhp_ipcmsg_eap_user_key_clear_cache));

			ipc_msg.tag[0] = '#';
			ipc_msg.tag[1] = 'I';
			ipc_msg.tag[2] = 'M';
			ipc_msg.tag[3] = 'S';

			ipc_msg.len = sizeof(rhp_ipcmsg_eap_user_key_clear_cache);
			ipc_msg.type = RHP_IPC_EAP_SUP_USER_KEY_CLEAR_CACHE;
			ipc_msg.vpn_realm_id = rlm->id;

			if( rhp_ipc_send(RHP_MY_PROCESS,(void*)&ipc_msg,ipc_msg.len,0) < 0 ){
				RHP_BUG("");
	    }
		}

	  RHP_TRC(0,RHPTRCID_EAP_SUP_IMPL_CLEAR_USER_KEY_CACHE,"x",rlm);
		return 0;
	}

  RHP_TRC(0,RHPTRCID_EAP_SUP_IMPL_CLEAR_USER_KEY_CACHE_ERR,"x",rlm);
	return -EINVAL;
}

extern char* rhp_eap_method2str_def(int method);

char* rhp_eap_sup_impl_method2str(int method)
{
	return rhp_eap_method2str_def(method);
}

extern int rhp_eap_str2method_def(char* method_name);

int rhp_eap_sup_impl_str2method(char* method_name)
{
	return rhp_eap_str2method_def(method_name);
}


static rhp_prc_ipcmsg_wts_handler _rhp_eap_sup_main_reply_ipc = {
	wts_type: RHP_WTS_DISP_RULE_AUTHREP,
	wts_disp_priority: RHP_WTS_DISP_LEVEL_HIGH_1,
	wts_disp_wait: 1,
	wts_is_fixed_rule: 0,
	wts_task_handler: _rhp_eap_sup_main_reply_ipc_handler
};

static rhp_prc_ipcmsg_wts_handler _rhp_eap_sup_main_user_key_req_ipc = {
	wts_type: RHP_WTS_DISP_RULE_AUTHREP,
	wts_disp_priority: RHP_WTS_DISP_LEVEL_HIGH_1,
	wts_disp_wait: 1,
	wts_is_fixed_rule: 0,
	wts_task_handler: _rhp_eap_sup_main_user_key_req_ipc_handler
};

static rhp_prc_ipcmsg_wts_handler _rhp_eap_sup_main_user_key_cached_ipc = {
	wts_type: RHP_WTS_DISP_RULE_RAND,
	wts_disp_priority: RHP_WTS_DISP_LEVEL_HIGH_1,
	wts_disp_wait: 1,
	wts_is_fixed_rule: 0,
	wts_task_handler: _rhp_eap_sup_main_user_key_cached_ipc_handler
};

int rhp_eap_sup_impl_init()
{
	int err;

  RHP_TRC(0,RHPTRCID_EAP_SUP_IMPL_INIT,"Ld","PROCESS_ROLE",RHP_MY_PROCESS->role);

  if( RHP_MY_PROCESS->role == RHP_PROCESS_ROLE_MAIN ){

		err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_EAP_SUP_HANDLE_REPLY,
						NULL,&_rhp_eap_sup_main_reply_ipc);

		if( err ){
			RHP_BUG("");
			return err;
		}

		err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_EAP_SUP_USER_KEY_REQUEST,
						NULL,&_rhp_eap_sup_main_user_key_req_ipc);

		if( err ){
			RHP_BUG("");
			return err;
		}

		err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_EAP_SUP_USER_KEY_CACHED,
						NULL,&_rhp_eap_sup_main_user_key_cached_ipc);

		if( err ){
			RHP_BUG("");
			return err;
		}

  }else if( RHP_MY_PROCESS->role == RHP_PROCESS_ROLE_SYSPXY ){

  	err = rhp_eap_sup_syspxy_init();
  	if( err ){
			RHP_BUG("");
			return err;
		}
  }

  RHP_TRC(0,RHPTRCID_EAP_SUP_IMPL_INIT_RTRN,"");
  return 0;
}

int rhp_eap_sup_impl_cleanup()
{
	int err = -EINVAL;

  RHP_TRC(0,RHPTRCID_EAP_SUP_IMPL_CLEANUP,"Ld","PROCESS_ROLE",RHP_MY_PROCESS->role);

  if( RHP_MY_PROCESS->role == RHP_PROCESS_ROLE_SYSPXY ){

  	err = rhp_eap_sup_syspxy_cleanup();
		if( err ){
			RHP_BUG("");
			return err;
		}
  }

  RHP_TRC(0,RHPTRCID_EAP_SUP_IMPL_CLEANUP_RTRN,"");
	return 0;
}




