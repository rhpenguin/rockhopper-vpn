/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
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
#include "rhp_http.h"


static int _rhp_ikev2_delete_srch_d_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_delete_srch_plds_ctx* s_pld_ctx = (rhp_delete_srch_plds_ctx*)ctx;
  rhp_ikev2_d_payload* d_payload = (rhp_ikev2_d_payload*)payload->ext.d;
	u8 protocol_id;

 	RHP_TRC(0,RHPTRCID_IKEV2_DELETE_SRCH_D__CB,"xdxxxx",rx_ikemesg,enum_end,payload,ctx,s_pld_ctx->vpn,s_pld_ctx->ikesa);

  if( d_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  protocol_id = d_payload->get_protocol_id(payload);

  if( protocol_id == RHP_PROTO_IKE_PROTOID_IKE ){

  	if( s_pld_ctx->ikesa_dup_flag > 1 ){
	   	RHP_TRC(0,RHPTRCID_IKEV2_DELETE_SRCH_D__CB_DUP_ERR,"xxxxx",rx_ikemesg,payload,s_pld_ctx);
	   	err = RHP_STATUS_INVALID_MSG;
	   	goto error;
  	}

  	s_pld_ctx->ikesa_my_side = s_pld_ctx->ikesa->side;
  	s_pld_ctx->ikesa_my_spi = s_pld_ctx->ikesa->get_my_spi(s_pld_ctx->ikesa);

  	s_pld_ctx->ikesa_dup_flag++;

  }else if( protocol_id == RHP_PROTO_IKE_PROTOID_ESP ){

  	int spis_num;
  	u32 *spis,*tmp;

  	spis_num = d_payload->get_spis_num(payload);
  	spis = d_payload->get_spis(payload);

  	if( spis_num < 1 || spis == NULL ){
  		err = RHP_STATUS_INVALID_MSG;
	   	RHP_TRC(0,RHPTRCID_IKEV2_DELETE_SRCH_D__CB_INVALID_SPI_NUM,"xxxxx",rx_ikemesg,payload,s_pld_ctx,spis_num,spis);
  		goto error;
  	}

  	tmp = (u32*)_rhp_malloc(sizeof(u32)*(spis_num + s_pld_ctx->childsa_outb_spis_num));
  	if( tmp == NULL ){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}

  	if( s_pld_ctx->childsa_outb_spis ){

  		memcpy(tmp,s_pld_ctx->childsa_outb_spis,(sizeof(u32)*s_pld_ctx->childsa_outb_spis_num));
  		memcpy((tmp + s_pld_ctx->childsa_outb_spis_num),spis,(sizeof(u32)*spis_num));

  		_rhp_free(s_pld_ctx->childsa_outb_spis);

  	}else{

  		memcpy(tmp,spis,(sizeof(u32)*spis_num));
  	}

  	s_pld_ctx->childsa_outb_spis = tmp;
  	s_pld_ctx->childsa_outb_spis_num += spis_num;

  	s_pld_ctx->childsa_dup_flag++;
  }

 	RHP_TRC(0,RHPTRCID_IKEV2_DELETE_SRCH_D__CB_RTRN,"xxx",rx_ikemesg,payload,ctx);
  return 0;

error:

	s_pld_ctx->ikesa_my_side = 0;
	s_pld_ctx->ikesa_my_spi = NULL;

	if( s_pld_ctx->childsa_outb_spis ){
		_rhp_free(s_pld_ctx->childsa_outb_spis);
		s_pld_ctx->childsa_outb_spis = NULL;
	}
	s_pld_ctx->childsa_outb_spis_num = 0;

 	RHP_TRC(0,RHPTRCID_IKEV2_DELETE_SRCH_D__CB_RTRN,"xxxE",rx_ikemesg,payload,ctx,err);
	return err;
}


static int _rhp_ikev2_delete_ikesa_req(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_vpn_realm* rlm,
		rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg,rhp_delete_srch_plds_ctx* s_pld_ctx)
{
  int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_DELETE_IKESA_REQ,"xxxxxx",vpn,ikesa,rlm,rx_req_ikemesg,tx_resp_ikemesg,s_pld_ctx);

	{
		if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_D,&ikepayload) ){
     RHP_BUG("");
			err = -EINVAL;
			goto error;
    }

		tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

		ikepayload->ext.d->set_protocol_id(ikepayload,RHP_PROTO_IKE_PROTOID_IKE);
	}

	if( ikesa->state == RHP_IKESA_STAT_ESTABLISHED ||
			ikesa->state == RHP_IKESA_STAT_REKEYING ||
			ikesa->state == RHP_IKESA_STAT_DELETE ){

		RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_DELETE_IKESA_REQ,"KVP",rx_req_ikemesg,vpn,ikesa);

		ikesa->timers->quit_lifetime_timer(vpn,ikesa);

		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);

		ikesa->timers->start_lifetime_timer(vpn,ikesa,(time_t)rlm->ikesa.lifetime_deleted,0);

		ikesa->expire_soft = 0;
		ikesa->expire_hard = _rhp_get_time() + (time_t)rlm->ikesa.lifetime_deleted;


		if( vpn->ikesa_num == 1 ){ // This is the last IKE SA...

			rhp_http_bus_broadcast_async(vpn->vpn_realm_id,1,1,
					rhp_ui_http_vpn_close_serialize,
					rhp_ui_http_vpn_bus_btx_async_cleanup,(void*)rhp_vpn_hold_ref(vpn)); // (*x*)

			if( vpn->eap.eap_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS &&
					!vpn->radius.acct_term_cause ){
				vpn->radius.acct_term_cause = RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_USER_REQUEST;
			}
		}

	}else{
		RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_DELETE_IKESA_REQ_IGNORED,"KVP",rx_req_ikemesg,vpn,ikesa);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_DELETE_IKESA_REQ_RTRN,"xxxxx",vpn,ikesa,rlm,rx_req_ikemesg,tx_resp_ikemesg);
	return 0;

error:
	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_DELETE_IKESA_REQ_ERR,"KVE",rx_req_ikemesg,vpn,err);
	RHP_TRC(0,RHPTRCID_IKEV2_DELETE_IKESA_REQ,"xxxxxE",vpn,ikesa,rlm,rx_req_ikemesg,tx_resp_ikemesg,err);
	return err;
}

static int _rhp_ikev2_delete_childsa_req(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_vpn_realm* rlm,
		rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg,rhp_delete_srch_plds_ctx* s_pld_ctx)
{
  int err = -EINVAL;
  rhp_ikev2_payload* d_ikepayload = NULL;
  rhp_childsa* childsa = NULL;
  int i;
 	int deleted_childsa = 0;

	RHP_TRC(0,RHPTRCID_IKEV2_DELETE_CHILDSA_REQ,"xxxxxx",vpn,ikesa,rlm,rx_req_ikemesg,tx_resp_ikemesg,s_pld_ctx);

 	{
	 	if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_D,&d_ikepayload) ){
	     RHP_BUG("");
	     goto error;
	 	}

  	d_ikepayload->ext.d->set_protocol_id(d_ikepayload,RHP_PROTO_IKE_PROTOID_ESP);
 	}

 	for( i = 0; i < s_pld_ctx->childsa_outb_spis_num; i++ ){

 		childsa = vpn->childsa_get(vpn,RHP_DIR_OUTBOUND,s_pld_ctx->childsa_outb_spis[i]);

		if( childsa == NULL ){
			RHP_TRC(0,RHPTRCID_IKEV2_DELETE_CHILDSA_REQ_NO_CHILDSA,"xxxdH",vpn,ikesa,rlm,RHP_DIR_OUTBOUND,s_pld_ctx->childsa_outb_spis[i]);
	  	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_DELETE_CHILDSA_REQ_NOT_FOUND,"KVdH",rx_req_ikemesg,vpn,(i + 1),s_pld_ctx->childsa_outb_spis[i]);
			continue;
		}

		if( d_ikepayload->ext.d->set_spi(d_ikepayload,childsa->spi_inb) ){
			RHP_BUG("");
			goto error;
		}

		if( childsa->state == RHP_CHILDSA_STAT_MATURE ||
				childsa->state == RHP_CHILDSA_STAT_REKEYING ||
				childsa->state == RHP_CHILDSA_STAT_DELETE ){

  		childsa->timers->quit_lifetime_timer(vpn,childsa);

			rhp_childsa_set_state(childsa,RHP_CHILDSA_STAT_DELETE_WAIT);

  		childsa->timers->start_lifetime_timer(vpn,childsa,(time_t)rlm->childsa.lifetime_deleted,0);

    	childsa->expire_soft = 0;
    	childsa->expire_hard = _rhp_get_time() + rlm->childsa.lifetime_deleted;
		}

  	RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_DELETE_CHILDSA_REQ,"KVdC",rx_req_ikemesg,vpn,(i + 1),childsa);
		deleted_childsa++;
 	}

 	if( deleted_childsa ){
 		tx_resp_ikemesg->put_payload(tx_resp_ikemesg,d_ikepayload);
 	}else{
 		rhp_ikev2_destroy_payload(d_ikepayload);
 	}

	RHP_TRC(0,RHPTRCID_IKEV2_DELETE_CHILDSA_REQ_RTRN,"xxxxxd",vpn,ikesa,rlm,rx_req_ikemesg,tx_resp_ikemesg,deleted_childsa);
	return 0;

error:
	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_DELETE_CHILDSA_REQ_ERR,"KVE",rx_req_ikemesg,vpn,err);
	RHP_TRC(0,RHPTRCID_IKEV2_DELETE_CHILDSA_REQ_ERR,"xxxxxE",vpn,ikesa,rlm,rx_req_ikemesg,tx_resp_ikemesg,err);
	return err;
}

static int _rhp_ikev2_rx_delete_req(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg)
{
  int err = 0;
  rhp_vpn_realm* rlm = NULL;
  rhp_delete_srch_plds_ctx s_pld_ctx;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_DELETE_REQ_L,"xxxxLd",vpn,ikesa,rx_req_ikemesg,rx_req_ikemesg->rx_pkt,"IKESA_STAT",ikesa->state);

  memset(&s_pld_ctx,0,sizeof(rhp_delete_srch_plds_ctx));

  if( rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
   RHP_BUG("");
   err = RHP_STATUS_INVALID_MSG;
   goto error;
  }

  rlm = vpn->rlm;
  if( rlm == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_DELETE_REQ_L_NO_RLM,"xxx",vpn,ikesa,rx_req_ikemesg);
  	goto error;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_DELETE_REQ_L_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,rx_req_ikemesg,rlm);
  	goto error_l;
  }

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;
  s_pld_ctx.rlm = rlm;


  {
  	s_pld_ctx.ikesa_dup_flag = 0;
  	s_pld_ctx.childsa_dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
		  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_D),
		  			_rhp_ikev2_delete_srch_d_cb,&s_pld_ctx);

    if( err && (err != RHP_STATUS_ENUM_OK) && (err != -ENOENT) ){
    	RHP_TRC(0,RHPTRCID_IKEV2_RX_DELETE_REQ_L_ENUM_D_PLD_ERR,"xxxxE",vpn,ikesa,rx_req_ikemesg,rlm,err);
     goto error_l;
    }
  }

  if( s_pld_ctx.childsa_outb_spis ){

  	err = _rhp_ikev2_delete_childsa_req(vpn,ikesa,rlm,rx_req_ikemesg,tx_resp_ikemesg,&s_pld_ctx);
  	if( err ){
  		goto error_l;
  	}
  }

  if( s_pld_ctx.ikesa_my_spi ){

  	err = _rhp_ikev2_delete_ikesa_req(vpn,ikesa,rlm,rx_req_ikemesg,tx_resp_ikemesg,&s_pld_ctx);
  	if( err ){
  		goto error_l;
  	}
  }

  RHP_UNLOCK(&(rlm->lock));

  if( s_pld_ctx.childsa_outb_spis || s_pld_ctx.ikesa_my_spi ){
  	rhp_vpn_clear_unique_ids_tls_cache(vpn->vpn_realm_id);
  }

  if( s_pld_ctx.childsa_outb_spis ){
  	_rhp_free(s_pld_ctx.childsa_outb_spis);
  }

	RHP_TRC(0,RHPTRCID_IKEV2_RX_DELETE_REQ_L_RTRN,"xxx",vpn,ikesa,rx_req_ikemesg);
  return 0;

error_l:
  RHP_UNLOCK(&(rlm->lock));
error:

	if( s_pld_ctx.childsa_outb_spis ){
		_rhp_free(s_pld_ctx.childsa_outb_spis);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_RX_DELETE_REQ_L_ERR,"xxxE",vpn,ikesa,rx_req_ikemesg,err);
	return err;
}

static int _rhp_ikev2_delete_ikesa_rep(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_resp_ikemesg,
		rhp_delete_srch_plds_ctx* s_pld_ctx)
{
	RHP_TRC(0,RHPTRCID_IKEV2_DELETE_IKESA_REP,"xxxxdLd",vpn,ikesa,rx_resp_ikemesg,s_pld_ctx,vpn->deleting,"IKESA_STAT",ikesa->state);

	if( vpn->deleting && ikesa->state == RHP_IKESA_STAT_DELETE_WAIT ){

		//
		// Deleted by user or UI.
		//

		ikesa->timers->schedule_delete(vpn,ikesa,1);

	}else{

		//
		// Waiting for destroying this IKE SA for 'lifetime_deleted' to retransmit response
		// for simultaneous DELETE mesgs' collision.
		//
	}

	RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_DELETE_IKESA_RESP,"KVP",rx_resp_ikemesg,vpn,ikesa);

	RHP_TRC(0,RHPTRCID_IKEV2_DELETE_IKESA_REP_RTRN,"xxxx",vpn,ikesa,rx_resp_ikemesg,s_pld_ctx);
	return 0;
}

static int _rhp_ikev2_delete_childsa_rep(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,
		rhp_delete_srch_plds_ctx* s_pld_ctx)
{
  rhp_childsa* childsa = NULL;
  int i;

	RHP_TRC(0,RHPTRCID_IKEV2_DELETE_CHILDSA_REP,"xxxx",vpn,ikesa,rx_req_ikemesg,s_pld_ctx);

  for( i = 0; i < s_pld_ctx->childsa_outb_spis_num; i++ ){

  	childsa = vpn->childsa_get(vpn,RHP_DIR_OUTBOUND,s_pld_ctx->childsa_outb_spis[i]);

  	if( childsa == NULL ){
  		RHP_TRC(0,RHPTRCID_IKEV2_DELETE_CHILDSA_REP_NO_CHILDSA,"xxdH",vpn,ikesa,RHP_DIR_OUTBOUND,s_pld_ctx->childsa_outb_spis[i]);
  		RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_DELETE_CHILDSA_RESP_NOT_FOUND,"KVdH",rx_req_ikemesg,vpn,(i + 1),s_pld_ctx->childsa_outb_spis[i]);
  		continue;
  	}

		RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_DELETE_CHILDSA_RESP,"KVdC",rx_req_ikemesg,vpn,(i + 1),childsa);

    if( childsa->state != RHP_CHILDSA_STAT_DELETE_WAIT ){
    	RHP_BUG("childsa->state:%d",childsa->state);
    }

    childsa->timers->schedule_delete(vpn,childsa,0);
  }

	RHP_TRC(0,RHPTRCID_IKEV2_DELETE_CHILDSA_REP_RTRN,"xxxx",vpn,ikesa,rx_req_ikemesg,s_pld_ctx);
	return 0;
}

static int _rhp_ikev2_rx_delete_rep(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_resp_ikemesg)
{
  int err = 0;
  rhp_delete_srch_plds_ctx s_pld_ctx;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_DELETE_REP_L,"xxxxLd",vpn,ikesa,rx_resp_ikemesg,rx_resp_ikemesg->rx_pkt,"IKESA_STAT",ikesa->state);

  if( rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  memset(&s_pld_ctx,0,sizeof(rhp_delete_srch_plds_ctx));

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;


  {
  	s_pld_ctx.ikesa_dup_flag = 0;
  	s_pld_ctx.childsa_dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
		  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_D),
		  			_rhp_ikev2_delete_srch_d_cb,&s_pld_ctx);

    if( err && (err != RHP_STATUS_ENUM_OK) && (err != -ENOENT) ){
    	RHP_TRC(0,RHPTRCID_IKEV2_RX_DELETE_REP_L_ENUM_D_PLD_ERR,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
     goto error;
    }
  }

  if( s_pld_ctx.childsa_outb_spis ){

  	err = _rhp_ikev2_delete_childsa_rep(vpn,ikesa,rx_resp_ikemesg,&s_pld_ctx);
  	if( err ){
  		goto error;
  	}
  }

  if( s_pld_ctx.ikesa_my_spi ){

  	err = _rhp_ikev2_delete_ikesa_rep(vpn,ikesa,rx_resp_ikemesg,&s_pld_ctx);
  	if( err ){
  		goto error;
  	}
  }

  if( s_pld_ctx.childsa_outb_spis ){
  	_rhp_free(s_pld_ctx.childsa_outb_spis);
  }

	RHP_TRC(0,RHPTRCID_IKEV2_RX_DELETE_REP_L_RTRN,"xxx",vpn,ikesa,rx_resp_ikemesg);
	return 0;

error:
	if( s_pld_ctx.childsa_outb_spis ){
		_rhp_free(s_pld_ctx.childsa_outb_spis);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_RX_DELETE_REP_L_ERR,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
	return err;
}

int rhp_ikev2_rx_delete_sa_req(rhp_ikev2_mesg* rx_req_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_req_ikemesg->get_exchange_type(rx_req_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_DELETE_REQ,"xxLdGxLb",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_resp_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

  if( !rx_req_ikemesg->decrypted ){
  	err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_DELETE_REQ_NOT_DECRYPTED,"xxLdG",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
  	goto error;
  }

	if( exchange_type == RHP_PROTO_IKE_EXCHG_INFORMATIONAL ){

		if( my_ikesa_spi == NULL ){
	    RHP_BUG("");
	    err = -EINVAL;
	    goto error;
	  }

		ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
		if( ikesa == NULL ){
			err = -ENOENT;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_DELETE_REQ_NO_IKESA,"xxLdG",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}

		err = _rhp_ikev2_rx_delete_req(vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);

	}else{
		err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_DELETE_REQ_NOT_INTERESTED,"xxLdG",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
	}

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_DELETE_REQ_RTRN,"xxxE",rx_req_ikemesg,vpn,tx_resp_ikemesg,err);
  return err;
}

int rhp_ikev2_rx_delete_sa_rep(rhp_ikev2_mesg* rx_resp_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_resp_ikemesg->get_exchange_type(rx_resp_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_DELETE_REP,"xxLdGxLb",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_req_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

  if( !rx_resp_ikemesg->decrypted ){
  	err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_DELETE_REP_NOT_DECRYPTED,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
  	goto error;
  }

	if( exchange_type == RHP_PROTO_IKE_EXCHG_INFORMATIONAL ){

		if( my_ikesa_spi == NULL ){
	    RHP_BUG("");
	    err = -EINVAL;
	    goto error;
	  }

		ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
		if( ikesa == NULL ){
			err = -ENOENT;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_DELETE_REP_NO_IKESA,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}

		err = _rhp_ikev2_rx_delete_rep(vpn,ikesa,rx_resp_ikemesg);

	}else{
		err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_DELETE_REP_NOT_INTERESTED,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
	}

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_DELETE_REP_RTRN,"xxxE",rx_resp_ikemesg,vpn,tx_req_ikemesg,err);
  return err;
}


