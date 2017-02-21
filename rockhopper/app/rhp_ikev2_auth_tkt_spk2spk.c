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
#include "rhp_eap_sup_impl.h"
#include "rhp_eap_auth_impl.h"
#include "rhp_http.h"
#include "rhp_radius_impl.h"
#include "rhp_nhrp.h"


struct _rhp_ikev2_auth_tkt_get_tkt_ctx {

	rhp_vpn_ref* rx_hb2spk_vpn_ref;

	int hb2spk_my_ikesa_side;
	u8 hb2spk_my_ikesa_spi[RHP_PROTO_IKE_SPI_SIZE];

	rhp_ikev2_mesg* rx_hb2spk_resp_ikemesg;

	int cb_err;

	rhp_vpn_ref* spk2spk_vpn_ref;
};
typedef struct _rhp_ikev2_auth_tkt_get_tkt_ctx	rhp_ikev2_auth_tkt_get_tkt_ctx;


static void _rhp_ikev2_auth_tkt_get_tkt_ctx_free(rhp_ikev2_auth_tkt_get_tkt_ctx* get_tkt_ctx)
{
	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_GET_TKT_CTX_FREE,"xxxxxx",get_tkt_ctx,get_tkt_ctx->rx_hb2spk_vpn_ref,RHP_VPN_REF(get_tkt_ctx->rx_hb2spk_vpn_ref),get_tkt_ctx->rx_hb2spk_resp_ikemesg,get_tkt_ctx->spk2spk_vpn_ref,RHP_VPN_REF(get_tkt_ctx->spk2spk_vpn_ref));

	if( get_tkt_ctx->rx_hb2spk_vpn_ref ){
		rhp_vpn_unhold(get_tkt_ctx->rx_hb2spk_vpn_ref);
	}

	if( get_tkt_ctx->rx_hb2spk_resp_ikemesg ){
		rhp_ikev2_unhold_mesg(get_tkt_ctx->rx_hb2spk_resp_ikemesg);
	}

	if( get_tkt_ctx->spk2spk_vpn_ref ){
		rhp_vpn_unhold(get_tkt_ctx->spk2spk_vpn_ref);
	}

	_rhp_free(get_tkt_ctx);

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_GET_TKT_CTX_FREE_RTRN,"x",get_tkt_ctx);
	return;
}

int rhp_ikev2_auth_vpn_tkt_set_session_key(rhp_vpn* spk2spk_vpn,int session_key_len,u8* session_key,
		int n_enc_auth_tkt_len,u8* n_enc_auth_tkt)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_VPN_TKT_SET_SESSION_KEY,"xxpp",spk2spk_vpn,spk2spk_vpn->auth_ticket.spk2spk_session_key,session_key_len,session_key,n_enc_auth_tkt_len,n_enc_auth_tkt);

	if( spk2spk_vpn->auth_ticket.spk2spk_session_key ){
		_rhp_free_zero(spk2spk_vpn->auth_ticket.spk2spk_session_key,spk2spk_vpn->auth_ticket.spk2spk_session_key_len);
		spk2spk_vpn->auth_ticket.spk2spk_session_key = NULL;
		spk2spk_vpn->auth_ticket.spk2spk_session_key_len = 0;
	}

	if( session_key_len && session_key ){

		spk2spk_vpn->auth_ticket.spk2spk_session_key = (u8*)_rhp_malloc(session_key_len);
		if( spk2spk_vpn->auth_ticket.spk2spk_session_key == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		memcpy(spk2spk_vpn->auth_ticket.spk2spk_session_key,session_key,session_key_len);
		spk2spk_vpn->auth_ticket.spk2spk_session_key_len = session_key_len;
	}

	if( n_enc_auth_tkt_len && n_enc_auth_tkt ){

		if( spk2spk_vpn->auth_ticket.spk2spk_n_enc_auth_tkt ){
			_rhp_free_zero(spk2spk_vpn->auth_ticket.spk2spk_n_enc_auth_tkt,spk2spk_vpn->auth_ticket.spk2spk_n_enc_auth_tkt_len);
			spk2spk_vpn->auth_ticket.spk2spk_n_enc_auth_tkt = NULL;
			spk2spk_vpn->auth_ticket.spk2spk_n_enc_auth_tkt_len = 0;
		}

		spk2spk_vpn->auth_ticket.spk2spk_n_enc_auth_tkt = (u8*)_rhp_malloc(n_enc_auth_tkt_len);
		if( spk2spk_vpn->auth_ticket.spk2spk_n_enc_auth_tkt == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		memcpy(spk2spk_vpn->auth_ticket.spk2spk_n_enc_auth_tkt,n_enc_auth_tkt,n_enc_auth_tkt_len);
		spk2spk_vpn->auth_ticket.spk2spk_n_enc_auth_tkt_len = n_enc_auth_tkt_len;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_VPN_TKT_SET_SESSION_KEY_RTRN,"x",spk2spk_vpn);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_VPN_TKT_SET_SESSION_KEY_ERR,"xE",spk2spk_vpn,err);
	return err;
}

//
// [CAUTION]
// rx_hb2spk_resp_ikemesg may be NULL if cb_err is set.
//
static void _rhp_ikev2_auth_tkt_spk2spk_get_tkt_rx_task(int worker_index,void *ctx)
{
	int err = -EINVAL;
	rhp_ikev2_auth_tkt_get_tkt_ctx* get_tkt_ctx = (rhp_ikev2_auth_tkt_get_tkt_ctx*)ctx;
	rhp_vpn_ref* spk2spk_vpn_ref = (rhp_vpn_ref*)get_tkt_ctx->spk2spk_vpn_ref;
	rhp_vpn* spk2spk_vpn = RHP_VPN_REF(spk2spk_vpn_ref);
	rhp_ikesa* ikesa = NULL;
	rhp_ikev2_mesg* rx_hb2spk_resp_ikemesg = get_tkt_ctx->rx_hb2spk_resp_ikemesg;
	rhp_tkt_auth_srch_plds_ctx s_pld_ctx;
	rhp_ikev2_n_auth_tkt_payload* rx_n_auth_tkt_payload = NULL;
  int mesg_octets_len = 0, session_key_len = 0, n_enc_auth_tkt_len = 0;
  u8 *mesg_octets = NULL, *session_key = NULL, *n_enc_auth_tkt_data = NULL;
  rhp_ipcmsg* sign_req = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_GET_TKT_RX_TASK,"dxxxxxx",worker_index,get_tkt_ctx,get_tkt_ctx->spk2spk_vpn_ref,RHP_VPN_REF(get_tkt_ctx->spk2spk_vpn_ref),rx_hb2spk_resp_ikemesg,get_tkt_ctx->rx_hb2spk_vpn_ref,RHP_VPN_REF(get_tkt_ctx->rx_hb2spk_vpn_ref));


	memset(&s_pld_ctx,0,sizeof(rhp_tkt_auth_srch_plds_ctx));

	get_tkt_ctx->spk2spk_vpn_ref = NULL;
	get_tkt_ctx->rx_hb2spk_resp_ikemesg = NULL;


	RHP_LOCK(&(spk2spk_vpn->lock));

	if( !_rhp_atomic_read(&(spk2spk_vpn->is_active)) ){
		err = -EINVAL;
		goto error_l;
	}

	//
	// [CAUTION]
	// rx_hb2spk_resp_ikemesg may be NULL if cb_err is set.
	//

	{
		ikesa = spk2spk_vpn->ikesa_list_head;
		while( ikesa ){

			if( ikesa->side == RHP_IKE_INITIATOR &&
					ikesa->state == RHP_IKESA_STAT_I_IKE_SA_INIT_SENT ){
				break;
			}

			ikesa = ikesa->next_vpn_list;
		}

		if( ikesa == NULL ){
			err = -ENOENT;
			goto error_l;
		}
	}

	if( get_tkt_ctx->cb_err ){
		err = get_tkt_ctx->cb_err;
		goto error_l;
	}

	if( rx_hb2spk_resp_ikemesg == NULL ){
		err = -EINVAL;
		RHP_BUG("");
		goto error_l;
	}



  s_pld_ctx.vpn = spk2spk_vpn;
	s_pld_ctx.ikesa = ikesa;

	{
		s_pld_ctx.dup_flag = 0;
		u16 auth_tkt_n_ids[3] = { RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_AUTH_TICKET,
															RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_ENC_AUTH_TICKET,
															RHP_PROTO_IKE_NOTIFY_RESERVED};

		err = rx_hb2spk_resp_ikemesg->search_payloads(rx_hb2spk_resp_ikemesg,0,
						rhp_ikev2_mesg_srch_cond_n_mesg_ids,auth_tkt_n_ids,
						rhp_ikev2_auth_tkt_srch_n_cb,&s_pld_ctx);

		if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
			goto error_l;
		}
		err = 0;
	}

	if( s_pld_ctx.n_auth_tkt_payload == NULL || s_pld_ctx.n_enc_auth_tkt_payload == NULL ){

		RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_GET_TKT_RX_TASK_NO_TKT,"dxxxxx",worker_index,get_tkt_ctx,spk2spk_vpn,ikesa,s_pld_ctx.n_auth_tkt_payload,s_pld_ctx.n_enc_auth_tkt_payload);

		err = -ENOENT;
		goto error_l;
	}


	{
		rhp_ikev2_n_auth_tkt_attr* auth_tkt_attr_sess_key;

		err = rhp_ikev2_new_payload_n_auth_tkt_rx(rx_hb2spk_resp_ikemesg,s_pld_ctx.n_auth_tkt_payload,
				&rx_n_auth_tkt_payload);
		if( err ){
			goto error_l;
		}

		if( rx_n_auth_tkt_payload->get_auth_tkt_type(rx_n_auth_tkt_payload)
					!= RHP_PROTO_IKEV2_AUTH_TKT_TYPE_RESPONSE ){
			err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;
			goto error_l;
		}
		err = 0;

		auth_tkt_attr_sess_key
			= rx_n_auth_tkt_payload->get_attr(rx_n_auth_tkt_payload,RHP_PROTO_IKEV2_AUTH_TKT_ATTR_SESSION_KEY,0);
		if( auth_tkt_attr_sess_key == NULL ){
			err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;
			goto error_l;
		}

		session_key = auth_tkt_attr_sess_key->get_attr_val(auth_tkt_attr_sess_key,&session_key_len);
		if( session_key == NULL ){
			err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;
			goto error_l;
		}

		if( session_key_len < rhp_gcfg_ikev2_auth_tkt_shortcut_session_key_min_len ){
			err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;
			goto error_l;
		}

		if( session_key_len > rhp_gcfg_ikev2_auth_tkt_shortcut_session_key_max_len ){
			err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;
			goto error_l;
		}
	}

	{
		n_enc_auth_tkt_len
			= s_pld_ctx.n_enc_auth_tkt_payload->ext.n->get_data_len(s_pld_ctx.n_enc_auth_tkt_payload);
		n_enc_auth_tkt_data
			= s_pld_ctx.n_enc_auth_tkt_payload->ext.n->get_data(s_pld_ctx.n_enc_auth_tkt_payload);

		if( n_enc_auth_tkt_len < (int)sizeof(rhp_proto_ikev2_auth_tkt_header) +
				                     RHP_PROTO_IKE_SPI_SIZE + (int)sizeof(rhp_proto_ikev2_auth_tkt_attr) ||
				n_enc_auth_tkt_data == NULL ){

			err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;
			goto error_l;
		}
	}


	err = rhp_ikev2_auth_vpn_tkt_set_session_key(spk2spk_vpn,session_key_len,session_key,
					n_enc_auth_tkt_len,n_enc_auth_tkt_data);
	if( err ){
			goto error_l;
	}


  err = rhp_ikev2_ike_auth_mesg_octets(RHP_IKE_INITIATOR,ikesa,
  				0,NULL,0,&mesg_octets_len,&mesg_octets);
	if( err ){
		goto error_l;
	}

  err = rhp_ikev2_ike_auth_ipc_sign_req(ikesa->pend_rx_ikemesg,
  				spk2spk_vpn->vpn_realm_id,ikesa,
  				mesg_octets_len,mesg_octets,
  				ikesa->keys.v2.sk_p_len,ikesa->keys.v2.sk_pi,
  				session_key_len,session_key,
  				&sign_req,1);

  if( err ){
		goto error_l;
  }

  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)sign_req,sign_req->len,0) < 0 ){
    err = -EINVAL;
    RHP_BUG("");
		goto error_l;
  }

	RHP_UNLOCK(&(spk2spk_vpn->lock));


	rhp_ikev2_payload_n_auth_tkt_free(rx_n_auth_tkt_payload);

	_rhp_ikev2_auth_tkt_get_tkt_ctx_free(get_tkt_ctx);

	rhp_ikev2_auth_tkt_srch_clear_ctx(&s_pld_ctx);

	rhp_ikev2_unhold_mesg(rx_hb2spk_resp_ikemesg);

	rhp_vpn_unhold(spk2spk_vpn_ref);

	_rhp_free_zero(mesg_octets,mesg_octets_len);

	_rhp_free_zero(sign_req,sign_req->len);


	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_GET_TKT_RX_TASK_RTRN,"dxxx",worker_index,get_tkt_ctx,spk2spk_vpn,ikesa);
	return;


error_l:
	if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		ikesa->timers->schedule_delete(spk2spk_vpn,ikesa,0);
	}

	RHP_UNLOCK(&(spk2spk_vpn->lock));

	if( rx_n_auth_tkt_payload ){
		rhp_ikev2_payload_n_auth_tkt_free(rx_n_auth_tkt_payload);
	}

	_rhp_ikev2_auth_tkt_get_tkt_ctx_free(get_tkt_ctx);

	rhp_ikev2_auth_tkt_srch_clear_ctx(&s_pld_ctx);

	if( rx_hb2spk_resp_ikemesg ){
		rhp_ikev2_unhold_mesg(rx_hb2spk_resp_ikemesg);
	}

	rhp_vpn_unhold(spk2spk_vpn_ref);

	if( mesg_octets ){
    _rhp_free_zero(mesg_octets,mesg_octets_len);
  }

  if( sign_req ){
  	_rhp_free_zero(sign_req,sign_req->len);
  }

	rhp_ikev2_g_statistics_inc(ikesa_auth_errors);

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_GET_TKT_RX_TASK_ERR,"dxxxE",worker_index,get_tkt_ctx,spk2spk_vpn,ikesa,err);
	return;
}

//
// [CAUTION]
// rx_hb2spk_resp_ikemesg may be NULL if cb_err is set.
//
void _rhp_ikev2_auth_tkt_spk2spk_get_tkt_rx_cb(
		rhp_vpn* rx_hb2spk_vpn,
		int hb2spk_my_ikesa_side,u8* hb2spk_my_ikesa_spi,
		int cb_err,rhp_ikev2_mesg* rx_hb2spk_resp_ikemesg,rhp_vpn* spk2spk_vpn)
{
	int err = -EINVAL;
	rhp_ikev2_auth_tkt_get_tkt_ctx* get_tkt_ctx = _rhp_malloc(sizeof(rhp_ikev2_auth_tkt_get_tkt_ctx));

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_GET_TKT_RX_CB,"xdpExx",rx_hb2spk_vpn,hb2spk_my_ikesa_side,RHP_PROTO_IKE_SPI_SIZE,hb2spk_my_ikesa_spi,cb_err,rx_hb2spk_resp_ikemesg,spk2spk_vpn);

	if( get_tkt_ctx == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memset(get_tkt_ctx,0,sizeof(rhp_ikev2_auth_tkt_get_tkt_ctx));

	get_tkt_ctx->rx_hb2spk_vpn_ref = rhp_vpn_hold_ref(rx_hb2spk_vpn);

	if( rx_hb2spk_resp_ikemesg ){
		get_tkt_ctx->rx_hb2spk_resp_ikemesg = rx_hb2spk_resp_ikemesg;
		rhp_ikev2_hold_mesg(rx_hb2spk_resp_ikemesg);
	}

	get_tkt_ctx->hb2spk_my_ikesa_side = hb2spk_my_ikesa_side;
	memcpy(get_tkt_ctx->hb2spk_my_ikesa_spi,hb2spk_my_ikesa_spi,RHP_PROTO_IKE_SPI_SIZE);

	get_tkt_ctx->spk2spk_vpn_ref = rhp_vpn_hold_ref(spk2spk_vpn);

	get_tkt_ctx->cb_err = cb_err;

	err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_1,
			_rhp_ikev2_auth_tkt_spk2spk_get_tkt_rx_task,get_tkt_ctx);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_GET_TKT_RX_CB_RTRN,"xxx",rx_hb2spk_vpn,rx_hb2spk_resp_ikemesg,spk2spk_vpn);
	return;

error:
	if( get_tkt_ctx ){
		_rhp_ikev2_auth_tkt_get_tkt_ctx_free(get_tkt_ctx);
	}
	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_GET_TKT_RX_CB_ERR,"xxxE",rx_hb2spk_vpn,rx_hb2spk_resp_ikemesg,spk2spk_vpn,err);
	return;
}

static void _rhp_ikev2_auth_tkt_spk2spk_get_tkt_task(int worker_index,void *ctx)
{
	int err = -EINVAL;
	rhp_vpn_ref* spk2spk_vpn_ref = (rhp_vpn_ref*)ctx;
	rhp_vpn* spk2spk_vpn = RHP_VPN_REF(spk2spk_vpn_ref);
	rhp_ikesa* ikesa = NULL;
	rhp_vpn_realm* tx_rlm = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_GET_TKT_TASK,"dxx",worker_index,spk2spk_vpn_ref,spk2spk_vpn);

	RHP_LOCK(&(spk2spk_vpn->lock));

	if( !_rhp_atomic_read(&(spk2spk_vpn->is_active)) ){
		err = -EINVAL;
		goto error_l;
	}

	{
		ikesa = spk2spk_vpn->ikesa_list_head;
		while( ikesa ){

			if( ikesa->state == RHP_IKESA_STAT_I_IKE_SA_INIT_SENT ){
				break;
			}

			ikesa = ikesa->next_vpn_list;
		}

		if( ikesa == NULL ){
			err = -ENOENT;
			goto error_l;
		}
	}


	tx_rlm = spk2spk_vpn->rlm;

	if( tx_rlm == NULL ){
		err = -EINVAL;
		goto error_l;
	}

	if( !_rhp_atomic_read(&(tx_rlm->is_active)) ){
		err = -EINVAL;
		goto error_l;
	}

	rhp_realm_hold(tx_rlm);

	RHP_UNLOCK(&(spk2spk_vpn->lock));


	err =  rhp_ikev2_auth_tkt_hb2spk_tx_tkt_req(tx_rlm,
					&(spk2spk_vpn->auth_ticket.spk2spk_resp_pub_addr), // Immutable fields
					&(spk2spk_vpn->auth_ticket.spk2spk_resp_itnl_addr),
					(spk2spk_vpn->auth_ticket.spk2spk_resp_id.type != RHP_PROTO_IKE_ID_ANY ? &(spk2spk_vpn->auth_ticket.spk2spk_resp_id) : NULL),
					_rhp_ikev2_auth_tkt_spk2spk_get_tkt_rx_cb,
					spk2spk_vpn);
	if( err ){
		goto error_l;
	}


	rhp_vpn_unhold(spk2spk_vpn_ref);

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_GET_TKT_TASK_RTRN,"dxxxx",worker_index,spk2spk_vpn_ref,spk2spk_vpn,tx_rlm,ikesa);
	return;


error_l:

	if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		ikesa->timers->schedule_delete(spk2spk_vpn,ikesa,0);
	}

	RHP_UNLOCK(&(spk2spk_vpn->lock));

	rhp_vpn_unhold(spk2spk_vpn_ref);

	if( tx_rlm ){
		rhp_realm_unhold(tx_rlm);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_GET_TKT_TASK_ERR,"dxxxxE",worker_index,spk2spk_vpn_ref,spk2spk_vpn,tx_rlm,ikesa,err);
	return;
}

int rhp_ikev2_auth_tkt_spk2spk_invoke_get_tkt_task(rhp_vpn* spk2spk_vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err = -EINVAL;
	rhp_vpn_ref* spk2spk_vpn_ref = rhp_vpn_hold_ref(spk2spk_vpn);

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_INVOKE_GET_TKT_TASK,"xxxx",spk2spk_vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);

	err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_1,
					_rhp_ikev2_auth_tkt_spk2spk_get_tkt_task,spk2spk_vpn_ref);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}


  ikesa->pend_rx_ikemesg = rx_resp_ikemesg;
  rhp_ikev2_hold_mesg(rx_resp_ikemesg);

  ikesa->pend_tx_ikemesg = tx_req_ikemesg;
  rhp_ikev2_hold_mesg(tx_req_ikemesg);

  ikesa->busy_flag = 1;

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_INVOKE_GET_TKT_TASK_RTRN,"xxxx",spk2spk_vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);

	return RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;

error:

	if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		ikesa->timers->schedule_delete(spk2spk_vpn,ikesa,0);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_INVOKE_GET_TKT_TASK_ERR,"xxxxE",spk2spk_vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,err);
	return err;
}



struct _rhp_ikev2_auth_tkt_dec_tkt_ctx {

	rhp_vpn_ref* spk2spk_vpn_ref;
	int spk2spk_my_ikesa_side;
	u8 spk2spk_my_ikesa_spi[RHP_PROTO_IKE_SPI_SIZE];

	rhp_vpn_ref* hb2spk_vpn_ref;
	int hb2spk_my_ikesa_side;
	u8 hb2spk_my_ikesa_spi[RHP_PROTO_IKE_SPI_SIZE];


	rhp_ikev2_mesg* rx_req_ikemesg;
	rhp_ikev2_mesg* tx_resp_ikemesg;

	u8* n_enc_auth_tkt_spi;
	rhp_ikev2_payload* n_enc_auth_tkt_payload;

	u16 reserved0;
	u16 notify_error;
	unsigned long notify_error_arg;
};
typedef struct _rhp_ikev2_auth_tkt_dec_tkt_ctx	rhp_ikev2_auth_tkt_dec_tkt_ctx;

static void _rhp_ikev2_auth_tkt_dec_tkt_ctx_free(rhp_ikev2_auth_tkt_dec_tkt_ctx* dec_tkt_ctx)
{
	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_DEC_TKT_CTX_FREE,"xxxxxxx",dec_tkt_ctx,dec_tkt_ctx->hb2spk_vpn_ref,RHP_VPN_REF(dec_tkt_ctx->hb2spk_vpn_ref),dec_tkt_ctx->spk2spk_vpn_ref,RHP_VPN_REF(dec_tkt_ctx->spk2spk_vpn_ref),dec_tkt_ctx->rx_req_ikemesg,dec_tkt_ctx->tx_resp_ikemesg);

	if( dec_tkt_ctx->hb2spk_vpn_ref ){
		rhp_vpn_unhold(dec_tkt_ctx->hb2spk_vpn_ref);
	}

	if( dec_tkt_ctx->spk2spk_vpn_ref ){
		rhp_vpn_unhold(dec_tkt_ctx->spk2spk_vpn_ref);
	}

	if( dec_tkt_ctx->rx_req_ikemesg ){
		rhp_ikev2_unhold_mesg(dec_tkt_ctx->rx_req_ikemesg);
	}

	if( dec_tkt_ctx->tx_resp_ikemesg ){
		rhp_ikev2_unhold_mesg(dec_tkt_ctx->tx_resp_ikemesg);
	}

	_rhp_free(dec_tkt_ctx);

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_DEC_TKT_CTX_FREE_RTRN,"x",dec_tkt_ctx);
	return;
}

static int _rhp_ikev2_auth_tkt_srch_n_enc_auth_tkt_cb(rhp_ikev2_mesg* rx_ikemesg,
		int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_ikev2_auth_payload* auth_payload = (rhp_ikev2_auth_payload*)payload->ext.id;
  rhp_ikev2_auth_tkt_dec_tkt_ctx* dec_tkt_ctx = (rhp_ikev2_auth_tkt_dec_tkt_ctx*)ctx;
  int n_data_len = payload->ext.n->get_data_len(payload);
  u8* n_data = payload->ext.n->get_data(payload);

  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SRCH_N_ENC_AUTH_TKT_CB,"xdxxx",rx_ikemesg,enum_end,payload,auth_payload,ctx);

  if( auth_payload == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( dec_tkt_ctx->n_enc_auth_tkt_payload ){
    RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SRCH_N_ENC_AUTH_TKT_CB_DUP_ERR,"xx",rx_ikemesg,payload);
    return RHP_STATUS_INVALID_MSG;
  }


  if( n_data_len < (int)RHP_PROTO_IKE_SPI_SIZE + (int)sizeof(rhp_proto_ikev2_auth_tkt_header) || n_data == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SRCH_N_ENC_AUTH_TKT_CB_INVALID_N_DATA_LEN_ERR,"xx",rx_ikemesg,payload);
    return RHP_STATUS_INVALID_MSG;
  }

  dec_tkt_ctx->n_enc_auth_tkt_spi = n_data;
  dec_tkt_ctx->n_enc_auth_tkt_payload = payload;

 	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(dec_tkt_ctx->hb2spk_vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(dec_tkt_ctx->hb2spk_vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_PARSE_N_ENC_AUTH_TKT_PAYLOAD,"K",rx_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SRCH_N_ENC_AUTH_TKT_CB_RTRN,"xxE",rx_ikemesg,payload,err);
  return 0;
}


static int _rhp_ikev2_auth_tkt_hb2spk_check_dec_tkt(
		rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload,rhp_vpn* hb2spk_vpn)
{
	int err = -EINVAL;
	rhp_ikev2_n_auth_tkt_attr* auth_tkt_attr;
	u8* attr_val = NULL;
	int attr_val_len = 0;
	u16 attr_sub_type;
	rhp_ikev2_id authenticator_id, resp_id;
	int session_key_len = 0;
	u8* session_key = NULL;
	int64_t expire_time = -1, now = -1;
	rhp_ip_addr init_pub_ip, init_itnl_ip;

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_CHECK_DEC_TKT,"xx",n_auth_tkt_payload,hb2spk_vpn);

	memset(&authenticator_id,0,sizeof(rhp_ikev2_id));
	memset(&resp_id,0,sizeof(rhp_ikev2_id));
	memset(&init_pub_ip,0,sizeof(rhp_ip_addr));
	memset(&init_itnl_ip,0,sizeof(rhp_ip_addr));


	{
		auth_tkt_attr
			= n_auth_tkt_payload->get_attr(n_auth_tkt_payload,
					RHP_PROTO_IKEV2_AUTH_TKT_ATTR_EXPIRATION_TIME,0);
		if( auth_tkt_attr == NULL ){
			err = -ENOENT;
			goto error;
		}

		attr_val = auth_tkt_attr->get_attr_val(auth_tkt_attr,&attr_val_len);
		if( attr_val == NULL ){
			err = -ENOENT;
			goto error;
		}

		if( attr_val_len != sizeof(int64_t) ){
			err = -EINVAL;
			goto error;
		}

		expire_time = (int64_t)_rhp_ntohll(*((int64_t*)attr_val));
		now = (int64_t)_rhp_get_realtime();

		if( expire_time <= now ){
			RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_CHECK_DEC_TKT_EXPIRED,"xxTT",n_auth_tkt_payload,hb2spk_vpn,expire_time,now);
			err = -EINVAL;
			goto error;
		}
	}

	{
		auth_tkt_attr
			= n_auth_tkt_payload->get_attr(n_auth_tkt_payload,
				RHP_PROTO_IKEV2_AUTH_TKT_ATTR_SESSION_KEY,0);
		if( auth_tkt_attr == NULL ){
			err = -ENOENT;
			goto error;
		}

		attr_val = auth_tkt_attr->get_attr_val(auth_tkt_attr,&attr_val_len);
		if( attr_val == NULL ){
			err = -ENOENT;
			goto error;
		}

		session_key_len = attr_val_len;

		if( attr_val_len < rhp_gcfg_ikev2_auth_tkt_shortcut_session_key_min_len ){
			RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_CHECK_DEC_TKT_SESS_KEY_TOO_SHORT,"xxdd",n_auth_tkt_payload,hb2spk_vpn,attr_val_len,rhp_gcfg_ikev2_auth_tkt_shortcut_session_key_min_len);
			err = -EINVAL;
			goto error;
		}

		if( attr_val_len > rhp_gcfg_ikev2_auth_tkt_shortcut_session_key_max_len ){
			RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_CHECK_DEC_TKT_SESS_KEY_TOO_LONG,"xxdd",n_auth_tkt_payload,hb2spk_vpn,attr_val_len,rhp_gcfg_ikev2_auth_tkt_shortcut_session_key_max_len);
			err = -EINVAL;
			goto error;
		}

		session_key = attr_val;
	}


	{
		auth_tkt_attr
			= n_auth_tkt_payload->get_attr(n_auth_tkt_payload,
					RHP_PROTO_IKEV2_AUTH_TKT_ATTR_AUTHENTICATOR_ID,0);
		if( auth_tkt_attr == NULL ){
			err = -ENOENT;
			goto error;
		}

		attr_val = auth_tkt_attr->get_attr_val(auth_tkt_attr,&attr_val_len);
		if( attr_val == NULL ){
			err = -ENOENT;
			goto error;
		}

		attr_sub_type = auth_tkt_attr->get_attr_sub_type(auth_tkt_attr);


		err = rhp_ikev2_id_setup((int)attr_sub_type,attr_val,attr_val_len,&authenticator_id);
		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_CHECK_DEC_TKT_SESS_KEY_INVALID_AUTHENTICATOR_ID,"xxdp",n_auth_tkt_payload,hb2spk_vpn,attr_sub_type,attr_val_len,attr_val);
			err = -EINVAL;
			goto error;
		}

		rhp_ikev2_id_dump("authenticator_id",&authenticator_id);
		rhp_ikev2_id_dump("hb2spk_vpn->peer_id",&(hb2spk_vpn->peer_id));

		if( rhp_ikev2_id_cmp_no_alt_id(&(hb2spk_vpn->peer_id),&authenticator_id) ){

			rhp_ikev2_id_dump("hb2spk_vpn->peer_id.alt_id",hb2spk_vpn->peer_id.alt_id);

			if( hb2spk_vpn->peer_id.alt_id == NULL ||
					rhp_ikev2_id_cmp_no_alt_id(hb2spk_vpn->peer_id.alt_id,&authenticator_id) ){

				RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_CHECK_DEC_TKT_SESS_KEY_INVALID_AUTHENTICATOR_ID_2,"xx",n_auth_tkt_payload,hb2spk_vpn);

				err = -EINVAL;
				goto error;
			}
		}
	}

	{
		auth_tkt_attr
			= n_auth_tkt_payload->get_attr(n_auth_tkt_payload,
					RHP_PROTO_IKEV2_AUTH_TKT_ATTR_RESPONDER_ID,0);
		if( auth_tkt_attr == NULL ){
			err = -ENOENT;
			goto error;
		}

		attr_val = auth_tkt_attr->get_attr_val(auth_tkt_attr,&attr_val_len);
		if( attr_val == NULL ){
			err = -ENOENT;
			goto error;
		}

		attr_sub_type = auth_tkt_attr->get_attr_sub_type(auth_tkt_attr);


		err = rhp_ikev2_id_setup((int)attr_sub_type,attr_val,attr_val_len,&resp_id);
		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_CHECK_DEC_TKT_SESS_KEY_INVALID_RESPONDER_ID,"xxdp",n_auth_tkt_payload,hb2spk_vpn,attr_sub_type,attr_val_len,attr_val);
			err = -EINVAL;
			goto error;
		}

		rhp_ikev2_id_dump("resp_id",&resp_id);
		rhp_ikev2_id_dump("hb2spk_vpn->my_id",&(hb2spk_vpn->my_id));

		if( rhp_ikev2_id_cmp_no_alt_id(&(hb2spk_vpn->my_id),&resp_id) ){

			rhp_ikev2_id_dump("hb2spk_vpn->my_id.alt_id",hb2spk_vpn->my_id.alt_id);

			if( hb2spk_vpn->my_id.alt_id == NULL ||
					rhp_ikev2_id_cmp_no_alt_id(hb2spk_vpn->my_id.alt_id,&resp_id) ){

				RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_CHECK_DEC_TKT_SESS_KEY_INVALID_RESPONDER_ID_2,"xx",n_auth_tkt_payload,hb2spk_vpn);

				err = -EINVAL;
				goto error;
			}
		}
	}

	{
		auth_tkt_attr
			= n_auth_tkt_payload->get_attr(n_auth_tkt_payload,
					RHP_PROTO_IKEV2_AUTH_TKT_ATTR_RESPONDER_PUB_IP,0);
		if( auth_tkt_attr == NULL ){
			err = -ENOENT;
			goto error;
		}

		attr_val = auth_tkt_attr->get_attr_val(auth_tkt_attr,&attr_val_len);
		if( attr_val == NULL ){
			err = -ENOENT;
			goto error;
		}

		attr_sub_type = auth_tkt_attr->get_attr_sub_type(auth_tkt_attr);

		if( attr_sub_type == 4 && attr_val_len == 4 ){

			init_pub_ip.addr_family = AF_INET;
			init_pub_ip.addr.v4 = *((u32*)attr_val);

			rhp_ip_addr_dump("init_pub_ip",&init_pub_ip);

			if( hb2spk_vpn->local.if_info.addr_family != AF_INET ||
					hb2spk_vpn->local.if_info.addr.v4 != *((u32*)attr_val) ){
				RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_CHECK_DEC_TKT_SESS_KEY_INVALID_RESPONDER_PUB_IP,"xx",n_auth_tkt_payload,hb2spk_vpn);
				err = -EINVAL;
				goto error;
			}

		}else if( attr_sub_type == 6 && attr_val_len == 16 ){

			init_pub_ip.addr_family = AF_INET6;
			memcpy(init_pub_ip.addr.v6,attr_val,16);

			rhp_ip_addr_dump("init_pub_ip",&init_pub_ip);

			if( hb2spk_vpn->local.if_info.addr_family != AF_INET6 ||
					memcmp(hb2spk_vpn->local.if_info.addr.v6,attr_val,16) ){
				RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_CHECK_DEC_TKT_SESS_KEY_INVALID_RESPONDER_PUB_IP_V6,"xx",n_auth_tkt_payload,hb2spk_vpn);
				err = -EINVAL;
				goto error;
			}

		}else{
			RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_CHECK_DEC_TKT_SESS_KEY_INVALID_RESPONDER_PUB_IP_2,"xxdp",n_auth_tkt_payload,hb2spk_vpn,attr_sub_type,attr_val_len,attr_val);
			err = -EINVAL;
			goto error;
		}
	}

	{
		rhp_vpn_realm* rlm;
	  rhp_ifc_entry* v_ifc = NULL;
		rhp_ifc_addr* if_addr;

		auth_tkt_attr
			= n_auth_tkt_payload->get_attr(n_auth_tkt_payload,
					RHP_PROTO_IKEV2_AUTH_TKT_ATTR_RESPONDER_ITNL_IP,0);
		if( auth_tkt_attr == NULL ){
			err = -ENOENT;
			goto error;
		}

		attr_val = auth_tkt_attr->get_attr_val(auth_tkt_attr,&attr_val_len);
		if( attr_val == NULL ){
			err = -ENOENT;
			goto error;
		}

		attr_sub_type = auth_tkt_attr->get_attr_sub_type(auth_tkt_attr);

		if( !(attr_sub_type == 4 && attr_val_len == 4) &&
				!(attr_sub_type == 6 && attr_val_len == 16) ){
			RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_CHECK_DEC_TKT_SESS_KEY_INVALID_RESPONDER_ITNL_IP,"xxdp",n_auth_tkt_payload,hb2spk_vpn,attr_sub_type,attr_val_len,attr_val);
			err = -EINVAL;
			goto error;
		}

		if( attr_sub_type == 4 ){
			init_itnl_ip.addr_family = AF_INET;
		}else if( attr_sub_type == 6 ){
			init_itnl_ip.addr_family = AF_INET6;
		}
		memcpy(init_itnl_ip.addr.raw,attr_val,attr_val_len);

		rhp_ip_addr_dump("init_itnl_ip",&init_itnl_ip);


		rlm = hb2spk_vpn->rlm;
		if( rlm == NULL ){
			RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_CHECK_DEC_TKT_SESS_KEY_INVALID_RESPONDER_ITNL_IP_NO_RLM,"xx",n_auth_tkt_payload,hb2spk_vpn);
			err = -EINVAL;
	  	goto error;
		}

		RHP_LOCK(&(rlm->lock));

		if( !_rhp_atomic_read(&(rlm->is_active)) ){

			RHP_UNLOCK(&(rlm->lock));

			RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_CHECK_DEC_TKT_SESS_KEY_INVALID_RESPONDER_ITNL_IP_RLM_NOT_ACTIVE,"xxx",n_auth_tkt_payload,hb2spk_vpn,rlm);

			err = -EINVAL;
	  	goto error;
		}


		v_ifc = rlm->internal_ifc->ifc;
	  if( v_ifc == NULL ){

	  	RHP_UNLOCK(&(rlm->lock));

			RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_CHECK_DEC_TKT_SESS_KEY_INVALID_RESPONDER_ITNL_IP_NO_VIFC,"xxx",n_auth_tkt_payload,hb2spk_vpn,rlm);

	  	err = -ENOENT;
	  	goto error;
	  }

		RHP_LOCK(&(v_ifc->lock));
		v_ifc->dump_no_lock("hb2spk_check_dec_tkt",v_ifc);

		if_addr = v_ifc->ifc_addrs;
		while( if_addr ){

			if( !rhp_ip_addr_cmp_ip_only(&(if_addr->addr),&init_itnl_ip) ){
				break;
			}

			if_addr = if_addr->lst_next;
		}

		if( if_addr == NULL ){

			RHP_UNLOCK(&(v_ifc->lock));
			RHP_UNLOCK(&(rlm->lock));

			RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_CHECK_DEC_TKT_SESS_KEY_INVALID_RESPONDER_ITNL_IP_NO_MATCHED_VIFC_IF_ADDR,"xxxx",n_auth_tkt_payload,hb2spk_vpn,rlm,v_ifc);

			err = -EINVAL;
	  	goto error;
		}


		RHP_UNLOCK(&(v_ifc->lock));

		RHP_UNLOCK(&(rlm->lock));
	}

	rhp_ikev2_id_clear(&authenticator_id);
	rhp_ikev2_id_clear(&resp_id);

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_CHECK_DEC_TKT_RTRN,"xxpTT",n_auth_tkt_payload,hb2spk_vpn,session_key_len,session_key,expire_time,now);
	return 0;

error:

	rhp_ikev2_id_clear(&authenticator_id);
	rhp_ikev2_id_clear(&resp_id);

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_CHECK_DEC_TKT_ERR,"xxTTdE",n_auth_tkt_payload,hb2spk_vpn,now,expire_time,session_key_len,err);
	return err;
}

static int _rhp_ikev2_auth_tkt_spk2spk_check_dec_tkt(
		rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload,
		rhp_vpn* spk2spk_vpn)
{
	int err = -EINVAL;
	rhp_ikev2_n_auth_tkt_attr* auth_tkt_attr;
	u8* attr_val = NULL;
	int attr_val_len = 0;
	u16 attr_sub_type;
	rhp_ip_addr rx_pub_src_addr, rx_pub_dst_addr;

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_CHECK_DEC_TKT,"xxx",rx_req_ikemesg,n_auth_tkt_payload,spk2spk_vpn);

	memset(&rx_pub_src_addr,0,sizeof(rhp_ip_addr));
	memset(&rx_pub_dst_addr,0,sizeof(rhp_ip_addr));


	err = rx_req_ikemesg->rx_get_src_addr(rx_req_ikemesg,&rx_pub_src_addr);
	if( err ){
		goto error;
	}

	err = rx_req_ikemesg->rx_get_dst_addr(rx_req_ikemesg,&rx_pub_dst_addr);
	if( err ){
		goto error;
	}


	{
		auth_tkt_attr
			= n_auth_tkt_payload->get_attr(n_auth_tkt_payload,
					RHP_PROTO_IKEV2_AUTH_TKT_ATTR_RESPONDER_PUB_IP,0);
		if( auth_tkt_attr == NULL ){
			err = -ENOENT;
			goto error;
		}

		attr_val = auth_tkt_attr->get_attr_val(auth_tkt_attr,&attr_val_len);
		if( attr_val == NULL ){
			err = -ENOENT;
			goto error;
		}

		attr_sub_type = auth_tkt_attr->get_attr_sub_type(auth_tkt_attr);

		if( attr_sub_type == 4 && attr_val_len == 4 ){

			if( rx_pub_dst_addr.addr_family != AF_INET ||
					rx_pub_dst_addr.addr.v4 != *((u32*)attr_val) ){
				RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_CHECK_DEC_TKT_INVALID_RESPONDER_PUB_IP,"xxxdd44",rx_req_ikemesg,n_auth_tkt_payload,spk2spk_vpn,attr_sub_type,rx_pub_dst_addr.addr_family,rx_pub_dst_addr.addr.v4,*((u32*)attr_val));
				err = -EINVAL;
				goto error;
			}

		}else if( attr_sub_type == 6 && attr_val_len == 16 ){

			if( rx_pub_dst_addr.addr_family != AF_INET6 ||
					memcmp(rx_pub_dst_addr.addr.v6,attr_val,16) ){
				RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_CHECK_DEC_TKT_INVALID_RESPONDER_PUB_IP_V6,"xxxdd66",rx_req_ikemesg,n_auth_tkt_payload,spk2spk_vpn,attr_sub_type,rx_pub_dst_addr.addr_family,rx_pub_dst_addr.addr.v6,attr_val);
				err = -EINVAL;
				goto error;
			}

		}else{
			RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_CHECK_DEC_TKT_INVALID_RESPONDER_PUB_IP_2,"xxxdp",rx_req_ikemesg,n_auth_tkt_payload,spk2spk_vpn,attr_sub_type,attr_val_len,attr_val);
			err = -EINVAL;
			goto error;
		}
	}

	{
		auth_tkt_attr
			= n_auth_tkt_payload->get_attr(n_auth_tkt_payload,
					RHP_PROTO_IKEV2_AUTH_TKT_ATTR_INITIATOR_PUB_IP,0);
		if( auth_tkt_attr == NULL ){
			err = -ENOENT;
			goto error;
		}

		attr_val = auth_tkt_attr->get_attr_val(auth_tkt_attr,&attr_val_len);
		if( attr_val == NULL ){
			err = -ENOENT;
			goto error;
		}

		attr_sub_type = auth_tkt_attr->get_attr_sub_type(auth_tkt_attr);

		if( attr_sub_type == 4 && attr_val_len == 4 ){

			if( rx_pub_src_addr.addr_family != AF_INET ||
					rx_pub_src_addr.addr.v4 != *((u32*)attr_val) ){
				RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_CHECK_DEC_TKT_INVALID_INITIATOR_PUB_IP,"xxxdd44",rx_req_ikemesg,n_auth_tkt_payload,spk2spk_vpn,attr_sub_type,rx_pub_dst_addr.addr_family,rx_pub_dst_addr.addr.v4,*((u32*)attr_val));
				err = -EINVAL;
				goto error;
			}

		}else if( attr_sub_type == 6 && attr_val_len == 16 ){

			if( rx_pub_src_addr.addr_family != AF_INET6 ||
					memcmp(rx_pub_src_addr.addr.v6,attr_val,16) ){
				RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_CHECK_DEC_TKT_INVALID_INITIATOR_PUB_IP_V6,"xxxdd66",rx_req_ikemesg,n_auth_tkt_payload,spk2spk_vpn,attr_sub_type,rx_pub_dst_addr.addr_family,rx_pub_dst_addr.addr.v6,attr_val);
				err = -EINVAL;
				goto error;
			}

		}else{
			RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_CHECK_DEC_TKT_INVALID_INITIATOR_PUB_IP_2,"xxxdp",rx_req_ikemesg,n_auth_tkt_payload,spk2spk_vpn,attr_sub_type,attr_val_len,attr_val);
			err = -EINVAL;
			goto error;
		}
	}

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_CHECK_DEC_TKT_RTRN,"xxx",rx_req_ikemesg,n_auth_tkt_payload,spk2spk_vpn);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_CHECK_DEC_TKT_ERR,"xxxE",rx_req_ikemesg,n_auth_tkt_payload,spk2spk_vpn,err);
	return err;
}

static void _rhp_ikev2_auth_tkt_spk2spk_dec_tkt_task(int worker_index,void *ctx)
{
	int err = -EINVAL, err2;
  rhp_ikev2_auth_tkt_dec_tkt_ctx* dec_tkt_ctx = (rhp_ikev2_auth_tkt_dec_tkt_ctx*)ctx;
  rhp_vpn_ref* spk2spk_vpn_ref = dec_tkt_ctx->spk2spk_vpn_ref;
  rhp_vpn* spk2spk_vpn = RHP_VPN_REF(spk2spk_vpn_ref);
  rhp_vpn_ref* hb2spk_vpn_ref = dec_tkt_ctx->hb2spk_vpn_ref;
  rhp_vpn* hb2spk_vpn = RHP_VPN_REF(hb2spk_vpn_ref);
  rhp_ikesa *spk2spk_ikesa = NULL, *hb2spk_ikesa = NULL;
  u16 notify_mesg_type = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;
  unsigned long notify_error_arg = 0;
  rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_DEC_TKT_TASK,"dxxxxx",worker_index,dec_tkt_ctx,spk2spk_vpn_ref,RHP_VPN_REF(spk2spk_vpn_ref),hb2spk_vpn_ref,RHP_VPN_REF(hb2spk_vpn_ref));

  RHP_LOCK(&(hb2spk_vpn->lock));

  if( !_rhp_atomic_read(&(hb2spk_vpn->is_active)) ){

  	RHP_UNLOCK(&(hb2spk_vpn->lock));

  	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_DEC_TKT_TASK_HB2SPK_VPN_NOT_ACTIVE,"dxxx",worker_index,dec_tkt_ctx,spk2spk_vpn,hb2spk_vpn);

  	err = -EINVAL;
  	goto error_notify;
  }

  if( hb2spk_vpn->auth_ticket.conn_type == RHP_AUTH_TKT_CONN_TYPE_DISABLED ){

  	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_DEC_TKT_TASK_HB2SPK_VPN_DISABLED,"dxxxb",worker_index,dec_tkt_ctx,spk2spk_vpn,hb2spk_vpn,hb2spk_vpn->auth_ticket.conn_type);

  	RHP_UNLOCK(&(hb2spk_vpn->lock));

  	err = -EINVAL;
  	goto error_notify;
  }

  if( hb2spk_vpn->auth_ticket.conn_type != RHP_AUTH_TKT_CONN_TYPE_HUB2SPOKE ){

  	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_DEC_TKT_TASK_HB2SPK_VPN_NOT_HB2SPK_CONN,"dxxxb",worker_index,dec_tkt_ctx,spk2spk_vpn,hb2spk_vpn,hb2spk_vpn->auth_ticket.conn_type);

  	RHP_UNLOCK(&(hb2spk_vpn->lock));

  	err = -EINVAL;
  	goto error_notify;
  }

  if( !hb2spk_vpn->cfg_peer->is_access_point ){

  	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_DEC_TKT_TASK_HB2SPK_VPN_PEER_NOT_ACCESSPOINT,"dxxxd",worker_index,dec_tkt_ctx,spk2spk_vpn,hb2spk_vpn,hb2spk_vpn->cfg_peer->is_access_point);

  	RHP_UNLOCK(&(hb2spk_vpn->lock));

  	err = -EINVAL;
  	goto error_notify;
  }

  hb2spk_ikesa = hb2spk_vpn->ikesa_get(hb2spk_vpn,
  								dec_tkt_ctx->hb2spk_my_ikesa_side,dec_tkt_ctx->hb2spk_my_ikesa_spi);
  if( hb2spk_ikesa == NULL ){

  	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_DEC_TKT_TASK_HB2SPK_VPN_NO_IKESA,"dxxx",worker_index,dec_tkt_ctx,spk2spk_vpn,hb2spk_vpn);

  	RHP_UNLOCK(&(hb2spk_vpn->lock));

  	err = -ENOENT;
  	goto error_notify;
  }

  if( hb2spk_ikesa->state != RHP_IKESA_STAT_ESTABLISHED &&
  		hb2spk_ikesa->state != RHP_IKESA_STAT_REKEYING ){

  	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_DEC_TKT_TASK_HB2SPK_VPN_BAD_IKESA_STAT,"dxxxxLd",worker_index,dec_tkt_ctx,spk2spk_vpn,hb2spk_vpn,hb2spk_ikesa,"IKESA_STAT",hb2spk_ikesa->state);

  	RHP_UNLOCK(&(hb2spk_vpn->lock));

  	err = -EINVAL;
  	goto error_notify;
  }


  err = rhp_ikev2_new_payload_n_enc_auth_tkt_rx(
  				dec_tkt_ctx->rx_req_ikemesg,dec_tkt_ctx->n_enc_auth_tkt_payload,hb2spk_vpn,
  				&n_auth_tkt_payload);
  if( err ){

  	RHP_UNLOCK(&(hb2spk_vpn->lock));

  	err = -EINVAL;
  	goto error_notify;
  }


  err = _rhp_ikev2_auth_tkt_hb2spk_check_dec_tkt(n_auth_tkt_payload,hb2spk_vpn);
  if( err ){

  	RHP_UNLOCK(&(hb2spk_vpn->lock));

  	err = -EINVAL;
  	goto error_notify;
  }


  n_auth_tkt_payload->hb2spk_vpn_realm_id = hb2spk_vpn->vpn_realm_id;

	RHP_UNLOCK(&(hb2spk_vpn->lock));



  RHP_LOCK(&(spk2spk_vpn->lock));

  if( !_rhp_atomic_read(&(spk2spk_vpn->is_active)) ){

  	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_DEC_TKT_TASK_SPK2SPK_VPN_NOT_ACTIVE,"dxxx",worker_index,dec_tkt_ctx,spk2spk_vpn,hb2spk_vpn);

  	RHP_UNLOCK(&(spk2spk_vpn->lock));

  	err = -EINVAL;
  	goto error;
  }

  spk2spk_ikesa
  	= spk2spk_vpn->ikesa_get(spk2spk_vpn,
  			dec_tkt_ctx->spk2spk_my_ikesa_side,dec_tkt_ctx->spk2spk_my_ikesa_spi);
  if( spk2spk_ikesa == NULL ){

  	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_DEC_TKT_TASK_SPK2SPK_VPN_NO_IKESA,"dxxx",worker_index,dec_tkt_ctx,spk2spk_vpn,hb2spk_vpn);

  	RHP_UNLOCK(&(spk2spk_vpn->lock));

  	err = -ENOENT;
  	goto error;
  }

  if( spk2spk_ikesa->state != RHP_IKESA_STAT_R_IKE_SA_INIT_SENT ){

  	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_DEC_TKT_TASK_SPK2SPK_VPN_NOT_ACTIVE,"dxxxxLd",worker_index,dec_tkt_ctx,spk2spk_vpn,hb2spk_vpn,spk2spk_ikesa,"IKESA_STAT",spk2spk_ikesa->state);

  	RHP_UNLOCK(&(spk2spk_vpn->lock));

  	err = -EINVAL;
  	goto error;
  }


  err = _rhp_ikev2_auth_tkt_spk2spk_check_dec_tkt(
  				dec_tkt_ctx->rx_req_ikemesg,n_auth_tkt_payload,spk2spk_vpn);
  if( err ){

  	RHP_UNLOCK(&(spk2spk_vpn->lock));

  	err = -EINVAL;
  	goto error_notify_l;
  }


  err = rhp_ikev2_rx_ike_auth_req_impl(spk2spk_vpn,spk2spk_ikesa,
  				dec_tkt_ctx->rx_req_ikemesg,dec_tkt_ctx->tx_resp_ikemesg,n_auth_tkt_payload);
  if( err != RHP_STATUS_IKEV2_MESG_HANDLER_PENDING ){ // err == 0 is also wrong here.

  	if( !err ){
  		RHP_BUG("");
  		err = -EINVAL;
  	}

  	RHP_UNLOCK(&(spk2spk_vpn->lock));

  	// rhp_ikev2_rx_ike_auth_req_impl will tx error notify mesg.
  	goto error;
  }

  RHP_UNLOCK(&(spk2spk_vpn->lock));


  _rhp_ikev2_auth_tkt_dec_tkt_ctx_free(dec_tkt_ctx);

	rhp_ikev2_payload_n_auth_tkt_free(n_auth_tkt_payload);

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_DEC_TKT_TASK_RTRN,"dxxxxx",worker_index,dec_tkt_ctx,spk2spk_vpn,hb2spk_vpn,hb2spk_ikesa,spk2spk_ikesa);
  return;


error:
	_rhp_ikev2_auth_tkt_dec_tkt_ctx_free(dec_tkt_ctx);

	if( n_auth_tkt_payload ){
		rhp_ikev2_payload_n_auth_tkt_free(n_auth_tkt_payload);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_DEC_TKT_TASK_ERR,"dxxxxxE",worker_index,dec_tkt_ctx,spk2spk_vpn,hb2spk_vpn,hb2spk_ikesa,spk2spk_ikesa,err);
	return;


error_notify:
	RHP_LOCK(&(spk2spk_vpn->lock));

  if( !_rhp_atomic_read(&(spk2spk_vpn->is_active)) ){
  	RHP_UNLOCK(&(spk2spk_vpn->lock));
  	goto error;
  }

  spk2spk_ikesa
  	= spk2spk_vpn->ikesa_get(spk2spk_vpn,
  			dec_tkt_ctx->spk2spk_my_ikesa_side,dec_tkt_ctx->spk2spk_my_ikesa_spi);


error_notify_l:

	if( spk2spk_ikesa == NULL ){
		RHP_UNLOCK(&(spk2spk_vpn->lock));
		goto error;
	}

	err2 = rhp_ikev2_new_pkt_ike_auth_error_notify(spk2spk_ikesa,dec_tkt_ctx->tx_resp_ikemesg,0,0,
						notify_mesg_type,notify_error_arg);

	if( err2 == RHP_STATUS_SUCCESS ){

		rhp_ikev2_call_next_rx_request_mesg_handlers(dec_tkt_ctx->rx_req_ikemesg,spk2spk_vpn,
						spk2spk_ikesa->side,(spk2spk_ikesa->side == RHP_IKE_INITIATOR ? spk2spk_ikesa->init_spi : spk2spk_ikesa->resp_spi),
						dec_tkt_ctx->tx_resp_ikemesg,RHP_IKEV2_MESG_HANDLER_END);
	}

	rhp_ikesa_set_state(spk2spk_ikesa,RHP_IKESA_STAT_DELETE_WAIT);
	spk2spk_ikesa->timers->schedule_delete(spk2spk_vpn,spk2spk_ikesa,0);

  RHP_UNLOCK(&(spk2spk_vpn->lock));

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_DEC_TKT_TASK_TX_ERR_NOTIFY,"dxxxxxE",worker_index,dec_tkt_ctx,spk2spk_vpn,hb2spk_vpn,hb2spk_ikesa,spk2spk_ikesa,err);

	goto error;
}

//
// A VPN Realm for vpn is not resolved yet.
//
int rhp_ikev2_auth_tkt_spk2spk_invoke_dec_tkt_task(
		rhp_vpn* spk2spk_vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,
		rhp_ikev2_mesg* tx_resp_ikemesg,u16* notify_error_r,unsigned long* notify_error_arg_r)
{
	int err = -EINVAL;
  rhp_ikev2_auth_tkt_dec_tkt_ctx* dec_tkt_ctx = NULL;
  rhp_vpn_ref* hb2spk_vpn_ref = NULL;
  rhp_vpn* hb2spk_vpn = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_INVOKE_DEC_TKT_TASK,"xxxxxxd",spk2spk_vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,notify_error_r,notify_error_arg_r,spk2spk_vpn->peer_is_rockhopper);

  if( !spk2spk_vpn->peer_is_rockhopper ){
  	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_INVOKE_DEC_TKT_TASK_PEER_NOT_ROCKHOPPER,"xxx",spk2spk_vpn,ikesa,rx_req_ikemesg);
  	return 0;
  }


  dec_tkt_ctx
  	= (rhp_ikev2_auth_tkt_dec_tkt_ctx*)_rhp_malloc(sizeof(rhp_ikev2_auth_tkt_dec_tkt_ctx));
  if( dec_tkt_ctx == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }
  memset(dec_tkt_ctx,0,sizeof(rhp_ikev2_auth_tkt_dec_tkt_ctx));

  {
		err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
				rhp_ikev2_mesg_srch_cond_n_mesg_id,(void*)((unsigned long)RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_ENC_AUTH_TICKET),
				_rhp_ikev2_auth_tkt_srch_n_enc_auth_tkt_cb,dec_tkt_ctx);

		if( err == -ENOENT ){

	  	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_INVOKE_DEC_TKT_TASK_NO_ENC_AUTH_TKT_NOTIFY,"xxx",spk2spk_vpn,ikesa,rx_req_ikemesg);

			err = 0;
			goto ignored;

		}else if( err && err != RHP_STATUS_ENUM_OK ){

			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(spk2spk_vpn ? spk2spk_vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_REQ_PARSE_N_ENC_AUTH_TKT_PAYLOAD_ERR,"KVPE",rx_req_ikemesg,spk2spk_vpn,ikesa,err);

			if( dec_tkt_ctx->notify_error ){
				*notify_error_r = dec_tkt_ctx->notify_error;
				*notify_error_arg_r = dec_tkt_ctx->notify_error_arg;
			}

			RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_ENC_AUTH_TKT_PARSE_ERR,"xxxE",spk2spk_vpn,ikesa,rx_req_ikemesg,err);
			goto error;
		}

		if( dec_tkt_ctx->n_enc_auth_tkt_payload == NULL ){

	  	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_INVOKE_DEC_TKT_TASK_NO_ENC_AUTH_TKT_NOTIFY_2,"xxx",spk2spk_vpn,ikesa,rx_req_ikemesg);

			err = 0;
			goto ignored;
		}
  }

  //
  // [CAUTION]
  // Don't acquire hb2spk_vpn->lock in this context.
  //
	{
		int n_enc_auth_tkt_spi_side = 0;

		hb2spk_vpn_ref = rhp_vpn_ikesa_spi_get(RHP_IKE_INITIATOR,dec_tkt_ctx->n_enc_auth_tkt_spi);
		hb2spk_vpn = RHP_VPN_REF(hb2spk_vpn_ref);
		if( hb2spk_vpn_ref == NULL ){

			hb2spk_vpn_ref = rhp_vpn_ikesa_spi_get(RHP_IKE_RESPONDER,dec_tkt_ctx->n_enc_auth_tkt_spi);
			hb2spk_vpn = RHP_VPN_REF(hb2spk_vpn_ref);

			n_enc_auth_tkt_spi_side = RHP_IKE_RESPONDER;

		}else{

			n_enc_auth_tkt_spi_side = RHP_IKE_INITIATOR;
		}

		if( hb2spk_vpn_ref == NULL ){

	  	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_INVOKE_DEC_TKT_TASK_NO_HB2SPK_VPN_CONN,"xxx",spk2spk_vpn,ikesa,rx_req_ikemesg);

			*notify_error_r = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;
			*notify_error_arg_r = 0;

			err = -ENOENT;
			goto error;
		}

		dec_tkt_ctx->hb2spk_vpn_ref = hb2spk_vpn_ref; // Already held by rhp_vpn_ikesa_spi_get().

		dec_tkt_ctx->hb2spk_my_ikesa_side = n_enc_auth_tkt_spi_side;
		memcpy(dec_tkt_ctx->hb2spk_my_ikesa_spi,dec_tkt_ctx->n_enc_auth_tkt_spi,RHP_PROTO_IKE_SPI_SIZE);
	}


	dec_tkt_ctx->spk2spk_vpn_ref = rhp_vpn_hold_ref(spk2spk_vpn);

	dec_tkt_ctx->spk2spk_my_ikesa_side = ikesa->side;
	memcpy(dec_tkt_ctx->spk2spk_my_ikesa_spi,ikesa->get_my_spi(ikesa),RHP_PROTO_IKE_SPI_SIZE);

	dec_tkt_ctx->rx_req_ikemesg = rx_req_ikemesg;
	rhp_ikev2_hold_mesg(rx_req_ikemesg);

	dec_tkt_ctx->tx_resp_ikemesg = tx_resp_ikemesg;
	rhp_ikev2_hold_mesg(tx_resp_ikemesg);


	err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_1,
					_rhp_ikev2_auth_tkt_spk2spk_dec_tkt_task,dec_tkt_ctx);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_INVOKE_DEC_TKT_TASK_RTRN,"xxxxx",spk2spk_vpn,ikesa,rx_req_ikemesg,hb2spk_vpn,dec_tkt_ctx);

  return RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;

ignored:
error:
	if( dec_tkt_ctx ){
		_rhp_ikev2_auth_tkt_dec_tkt_ctx_free(dec_tkt_ctx);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SPK2SPK_INVOKE_DEC_TKT_TASK_ERR_OR_IGNORED,"xxxxxE",spk2spk_vpn,ikesa,rx_req_ikemesg,hb2spk_vpn,dec_tkt_ctx,err);
	return err;
}


