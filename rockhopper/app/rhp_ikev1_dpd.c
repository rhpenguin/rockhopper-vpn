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


static u8 _rhp_proto_ikev1_dpd_vid[16]
= {0xAF, 0xCA, 0xD7, 0x13, 0x68, 0xA1, 0xF1,0xC9, 0x6B, 0x86, 0x96, 0xFC, 0x77, 0x57,0x01,0x00};


struct _rhp_v1_dpd_srch_plds_ctx {

	rhp_vpn* vpn;
	rhp_ikesa* ikesa;

	rhp_ikev2_payload* r_u_there_payload;

	rhp_ikev2_payload* r_u_there_ack_payload;
};
typedef struct _rhp_v1_dpd_srch_plds_ctx rhp_v1_dpd_srch_plds_ctx;


static int _rhp_ikev1_dpd_new_pkt_p1_vid(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_DPD_NEW_PKT_P1_VID,"xxx",vpn,ikesa,tx_ikemesg);

  {
    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_VID,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.vid->set_vid(ikepayload,16,_rhp_proto_ikev1_dpd_vid) ){
      RHP_BUG("");
      goto error;
    }
  }

  RHP_TRC(0,RHPTRCID_IKEV1_DPD_NEW_PKT_P1_VID_RTRN,"xxx",vpn,ikesa,tx_ikemesg);
  return 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV1_DPD_NEW_PKT_P1_VID_ERR,"xxE",vpn,ikesa,err);
  return err;
}

int rhp_ikev1_tx_dpd_req(rhp_ikev2_mesg* tx_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,int req_initiator)
{
	int err = -EINVAL;
	rhp_ikesa* ikesa = NULL;
	rhp_vpn_realm* rlm = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_TX_DPD_REQ,"xxLdGLdd",tx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKEV1_MESG_HDLR",req_initiator,rhp_gcfg_ikev1_dpd_enabled);

  if( !rhp_gcfg_ikev1_dpd_enabled ){
  	err = 0;
  	goto ignore;
  }

	if( req_initiator == RHP_IKEV1_MESG_HANDLER_P1_MAIN 	||
			req_initiator == RHP_IKEV1_MESG_HANDLER_P1_AGGRESSIVE ){

		if( my_ikesa_spi == NULL ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
		if( ikesa == NULL ){
			err = -ENOENT;
		  RHP_TRC(0,RHPTRCID_IKEV1_TX_DPD_REQ_NO_IKESA,"xxLdG",tx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}


		rlm = vpn->rlm;
		if( rlm == NULL ){
			err = -EINVAL;
			RHP_BUG("");
			goto error;
		}

		RHP_LOCK(&(rlm->lock));

		if( !_rhp_atomic_read(&(rlm->is_active)) ){
			err = -EINVAL;
		  RHP_TRC(0,RHPTRCID_IKEV1_TX_DPD_REQ_RLM_NOT_ACTIVE,"xxx",tx_ikemesg,vpn,rlm);
			RHP_UNLOCK(&(rlm->lock));
			goto error;
		}

		if( !rlm->v1.dpd_enabled ){
		  RHP_TRC(0,RHPTRCID_IKEV1_TX_DPD_REQ_DPD_DISABLED,"xxxd",tx_ikemesg,vpn,rlm,rlm->v1.dpd_enabled);
			RHP_UNLOCK(&(rlm->lock));
			goto ignore;
		}

		RHP_UNLOCK(&(rlm->lock));

		if( ikesa->state == RHP_IKESA_STAT_V1_MAIN_1ST_SENT_I ||
				ikesa->state == RHP_IKESA_STAT_V1_AGG_1ST_SENT_I ){

			err = _rhp_ikev1_dpd_new_pkt_p1_vid(vpn,ikesa,tx_ikemesg);
			if( err ){
				goto error;
			}

		}else{

			RHP_TRC(0,RHPTRCID_IKEV1_TX_DPD_REQ_P1_NOT_INTERESTED,"xxxd",tx_ikemesg,vpn,ikesa,ikesa->state);
			goto ignore;
		}
	}

ignore:
	RHP_TRC(0,RHPTRCID_IKEV1_TX_DPD_REQ_RTRN,"xxLd",tx_ikemesg,vpn,"IKEV2_MESG_HDLR",req_initiator);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV1_TX_DPD_REQ_ERR,"xxLdE",tx_ikemesg,vpn,"IKEV2_MESG_HDLR",req_initiator,err);
  return err;
}


static int _rhp_ikev1_dpd_srch_vid_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_v1_dpd_srch_plds_ctx* s_pld_ctx = (rhp_v1_dpd_srch_plds_ctx*)ctx;
  rhp_ikev2_vid_payload* vid_payload = (rhp_ikev2_vid_payload*)payload->ext.vid;
  int vid_len;
  u8* vid;

  RHP_TRC(0,RHPTRCID_IKEV1_DPD_SRCH_VID_CB,"xdxxxxx",rx_ikemesg,enum_end,payload,vid_payload,ctx,s_pld_ctx->vpn,s_pld_ctx->ikesa);

  if( vid_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }


  vid_len = vid_payload->get_vid_len(payload);
  vid = vid_payload->get_vid(payload);

  if( vid_len < 1 || vid == NULL ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV1_DPD_SRCH_VID_CB_INVALID_VID_ERR,"x",rx_ikemesg);
  	goto error;
  }

  if( vid_len == 16 &&
  		!memcmp(vid,_rhp_proto_ikev1_dpd_vid,16)){

  	s_pld_ctx->vpn->v1.peer_dpd_supproted = 1;
  }

  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV1_DPD_SRCH_VID_CB_RTRN,"xxxxxdE",rx_ikemesg,payload,vid_payload,s_pld_ctx->vpn,s_pld_ctx->ikesa,s_pld_ctx->vpn->v1.peer_dpd_supproted,err);
  return err;
}

static int _rhp_ikev1_rx_dpd_p1_r(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_v1_dpd_srch_plds_ctx s_pld_ctx;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_P1_R,"xxxx",rx_ikemesg,vpn,ikesa,tx_ikemesg);

  memset(&s_pld_ctx,0,sizeof(rhp_v1_dpd_srch_plds_ctx));

  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
  	RHP_BUG("");
  	goto error;
  }

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;

	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_VID),
			_rhp_ikev1_dpd_srch_vid_cb,&s_pld_ctx);

  if( err && err != RHP_STATUS_ENUM_OK ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_P1_R_ENUM_SA_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
  	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_DPD_REQ_PARSE_VID_PAYLOAD_ERR,"KVPE",rx_ikemesg,NULL,ikesa,err);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


  if( vpn->v1.peer_dpd_supproted ){

		err = _rhp_ikev1_dpd_new_pkt_p1_vid(vpn,ikesa,tx_ikemesg);
		if( err ){
			goto error;
		}

  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_DPD_PEER_SUPPORTED,"KVP",rx_ikemesg,vpn,ikesa);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_P1_R_RTRN,"xxxd",rx_ikemesg,vpn,ikesa,vpn->v1.peer_dpd_supproted);
  return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_DPD_VID_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
  RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_P1_R_ERR,"xxxE",rx_ikemesg,vpn,ikesa,err);
  return err;
}

static int _rhp_ikev1_rx_dpd_p1_i(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_v1_dpd_srch_plds_ctx s_pld_ctx;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_P1_I,"xxxx",rx_ikemesg,vpn,ikesa,tx_ikemesg);

  if( !rhp_gcfg_ikev1_dpd_enabled ){
  	err = 0;
  	goto ignored;
  }


  memset(&s_pld_ctx,0,sizeof(rhp_v1_dpd_srch_plds_ctx));

  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
  	RHP_BUG("");
  	goto error;
  }

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;

	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_VID),
			_rhp_ikev1_dpd_srch_vid_cb,&s_pld_ctx);

  if( err && err != RHP_STATUS_ENUM_OK ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_P1_I_ENUM_SA_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
  	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_DPD_REQ_PARSE_VID_PAYLOAD_ERR,"KVPE",rx_ikemesg,NULL,ikesa,err);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  if( !vpn->v1.peer_dpd_supproted ){

    RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_P1_I_PEER_NOT_SUPPROTED,"xxxd",rx_ikemesg,vpn,ikesa,err);

  }else{

  	// [Initiator] For Aggressive-mode.
    if( !rhp_timer_pending(&(ikesa->timers->keep_alive_timer)) ){

    	rhp_vpn_realm* rlm = vpn->rlm;

			if( rlm == NULL ){
				RHP_BUG("");
				err = -EINVAL;
				goto error;
			}

			RHP_LOCK(&(rlm->lock));

			if( !_rhp_atomic_read(&(rlm->is_active)) ){
				RHP_UNLOCK(&(rlm->lock));
				err = -EINVAL;
				goto error;
			}

			if( rlm->v1.dpd_enabled ){

				ikesa->timers->start_keep_alive_timer(vpn,ikesa,(time_t)rlm->ikesa.keep_alive_interval);

				vpn->v1.dpd_enabled = 1;
			}

			RHP_UNLOCK(&(rlm->lock));
    }
  }

  err = 0;


ignored:
  RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_P1_I_RTRN,"xxxd",rx_ikemesg,vpn,ikesa,vpn->v1.peer_dpd_supproted);
  return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_DPD_VID_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
  RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_P1_I_ERR,"xxxE",rx_ikemesg,vpn,ikesa,err);
  return err;
}



static int _rhp_ikev1_tx_dpd_add_hash_buf(rhp_ikev2_mesg* ikemesg,
		int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_packet* pkt_for_hash = (rhp_packet*)ctx;
	u8 pld_id = payload->get_payload_id(payload);

  RHP_TRC(0,RHPTRCID_IKEV1_TX_DPD_ADD_HASH_BUF,"xxLbxxd",ikemesg,payload,"PROTO_IKE_PAYLOAD",payload->payload_id,ctx,pkt_for_hash,ikemesg->tx_mesg_len);

  if( pld_id == RHP_PROTO_IKEV1_PAYLOAD_N ){

		err = payload->ext_serialize(payload,pkt_for_hash);
		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV1_TX_DPD_ADD_HASH_BUF_ERR,"xxLbxE",ikemesg,payload,"PROTO_IKE_PAYLOAD",payload->payload_id,ctx,err);
			return err;
		}
  }

  RHP_TRC(0,RHPTRCID_IKEV1_TX_DPD_ADD_HASH_BUF_RTRN,"xxxd",ikemesg,payload,pkt_for_hash,ikemesg->tx_mesg_len);
	return 0;
}

rhp_ikev2_mesg* rhp_ikev1_new_pkt_dpd_r_u_there(rhp_vpn* vpn,rhp_ikesa* ikesa,u32* dpd_seq_r)
{
	int err = -EINVAL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_ikev2_payload* n_ikepayload;

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_DPD_R_U_THERE,"xxx",vpn,ikesa,dpd_seq_r);

	tx_ikemesg = rhp_ikev1_new_mesg_tx(RHP_PROTO_IKEV1_EXCHG_INFORMATIONAL,0,0);
	if( tx_ikemesg == NULL ){
		err = -ENOMEM;
	  RHP_BUG("");
	  goto error;
	}

  {
  	u32 tx_mesg_id;

		err = rhp_random_bytes((u8*)&tx_mesg_id,sizeof(u32));
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		tx_ikemesg->set_mesg_id(tx_ikemesg,tx_mesg_id);
  }

	if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_N,&n_ikepayload) ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	tx_ikemesg->put_payload(tx_ikemesg,n_ikepayload);


	n_ikepayload->ext.n->set_protocol_id(n_ikepayload,RHP_PROTO_IKEV1_PROP_PROTO_ID_ISAKMP);

	n_ikepayload->ext.n->set_message_type(n_ikepayload,RHP_PROTO_IKEV1_N_ST_DPD_R_U_THERE);

	n_ikepayload->ext.n->v1_set_ikesa_spi(n_ikepayload,ikesa->init_spi,ikesa->resp_spi);

	{
		u32 dpd_seq = htonl(ikesa->v1.dpd_seq);

	  //
	  // A DPD's R_U_THERE_ACK's mesg ID (INFORMATIONAL exchange) may not be
		// the same one and so a DPD's seq ID is used instead.
	  //

		*dpd_seq_r = ikesa->v1.dpd_seq;
		ikesa->v1.dpd_seq++;

		err = n_ikepayload->ext.n->set_data(n_ikepayload,sizeof(u32),(u8*)&dpd_seq);
		if( err ){
			RHP_BUG("");
			goto error;
		}
	}


	if( rhp_ikev1_tx_info_mesg_hash_add(vpn,ikesa,
				tx_ikemesg,_rhp_ikev1_tx_dpd_add_hash_buf) ){
		RHP_BUG("");
		err = -EINVAL;
    goto error;
	}

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_DPD_R_U_THERE_RTRN,"xxxj",vpn,ikesa,tx_ikemesg,*dpd_seq_r);
	return tx_ikemesg;

error:
	if( tx_ikemesg ){
		rhp_ikev2_unhold_mesg(tx_ikemesg);
	}
	RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_DPD_R_U_THERE_ERR,"xxE",vpn,ikesa,err);
	return NULL;
}

static int _rhp_ikev1_new_pkt_dpd_r_u_there_ack(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg,rhp_ikev2_payload* r_u_there_payload)
{
	int err = -EINVAL;
  rhp_ikev2_payload* n_ikepayload;

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_DPD_R_U_THERE_ACK,"xxxxx",vpn,ikesa,rx_ikemesg,rx_ikemesg,r_u_there_payload);

	if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_N,&n_ikepayload) ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	tx_ikemesg->put_payload(tx_ikemesg,n_ikepayload);


	n_ikepayload->ext.n->set_protocol_id(n_ikepayload,RHP_PROTO_IKEV1_PROP_PROTO_ID_ISAKMP);

	n_ikepayload->ext.n->set_message_type(n_ikepayload,RHP_PROTO_IKEV1_N_ST_DPD_R_U_THERE_ACK);

	n_ikepayload->ext.n->v1_set_ikesa_spi(n_ikepayload,ikesa->init_spi,ikesa->resp_spi);

	{
		int dpd_seq_len = r_u_there_payload->ext.n->get_data_len(r_u_there_payload);
		u8* dpd_seq = r_u_there_payload->ext.n->get_data(r_u_there_payload);

		if( dpd_seq_len != 4 || dpd_seq == NULL ){
			err = RHP_STATUS_INVALID_MSG;
			goto error;
		}

		err = n_ikepayload->ext.n->set_data(n_ikepayload,sizeof(u32),(u8*)dpd_seq);
		if( err ){
			RHP_BUG("");
			goto error;
		}
	}


	if( rhp_ikev1_tx_info_mesg_hash_add(vpn,ikesa,
				tx_ikemesg,_rhp_ikev1_tx_dpd_add_hash_buf) ){
		RHP_BUG("");
		err = -EINVAL;
    goto error;
	}

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_DPD_R_U_THERE_ACK_RTRN,"xxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_DPD_R_U_THERE_ACK_ERR,"xxxxE",vpn,ikesa,rx_ikemesg,tx_ikemesg,err);
	return err;
}


static int _rhp_ikev1_dpd_srch_n_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_v1_dpd_srch_plds_ctx* s_pld_ctx = (rhp_v1_dpd_srch_plds_ctx*)ctx;
  rhp_ikev2_n_payload* n_payload = (rhp_ikev2_n_payload*)payload->ext.n;
  u16 notify_mesg_type;

  RHP_TRC(0,RHPTRCID_IKEV1_DPD_SRCH_N_CB,"xdxxxxx",rx_ikemesg,enum_end,payload,n_payload,ctx,s_pld_ctx->vpn,s_pld_ctx->ikesa);
  if( n_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  notify_mesg_type = n_payload->get_message_type(payload);

  if( notify_mesg_type == RHP_PROTO_IKEV1_N_ST_DPD_R_U_THERE ){

  	s_pld_ctx->r_u_there_payload = payload;

  }else if( notify_mesg_type == RHP_PROTO_IKEV1_N_ST_DPD_R_U_THERE_ACK ){

  	s_pld_ctx->r_u_there_ack_payload = payload;
  }

  err = 0;

  RHP_TRC(0,RHPTRCID_IKEV1_DPD_SRCH_N_CB_RTRN,"xxxxwxxE",rx_ikemesg,payload,n_payload,ctx,notify_mesg_type,s_pld_ctx->r_u_there_payload,s_pld_ctx->r_u_there_ack_payload,err);
  return err;
}

#ifdef RHP_DBG_V1_DPD_TEST_1
static int _rhp_ikev1_rx_dpd_test_rx_r_u_there = 0;
#endif // RHP_DBG_V1_DPD_TEST_1

static int _rhp_ikev1_rx_dpd_r_u_there(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg,rhp_v1_dpd_srch_plds_ctx* s_pld_ctx)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_R_U_THERE,"xxxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg,s_pld_ctx);

#ifdef RHP_DBG_V1_DPD_TEST_1
	_rhp_ikev1_rx_dpd_test_rx_r_u_there++;
	RHP_BUG("%d",_rhp_ikev1_rx_dpd_test_rx_r_u_there);
	if( _rhp_ikev1_rx_dpd_test_rx_r_u_there > 2 ){
		RHP_BUG("");
		err = 0;
		goto error;
	}
#endif // RHP_DBG_V1_DPD_TEST_1

	err = _rhp_ikev1_new_pkt_dpd_r_u_there_ack(vpn,ikesa,
					rx_ikemesg,tx_ikemesg,s_pld_ctx->r_u_there_payload);
	if( err ){
		goto error;
	}

  rhp_ikev1_p2_session_rx_put(ikesa,rx_ikemesg,1);

  tx_ikemesg->v1_set_retrans_resp = 1;

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_DPD_R_U_THERE,"KVP",rx_ikemesg,vpn,ikesa);

	RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_R_U_THERE_RTRN,"xxxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg,s_pld_ctx);
	return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_DPD_R_U_THERE_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
	RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_R_U_THERE_ERR,"xxxxx#",vpn,ikesa,rx_ikemesg,tx_ikemesg,s_pld_ctx,err);
	return err;
}

static int _rhp_ikev1_rx_dpd_r_u_there_ack(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_v1_dpd_srch_plds_ctx* s_pld_ctx)
{
	int err = -EINVAL;
	int dpd_seq_len;
	u8* dpd_seq;

	RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_R_U_THERE_ACK,"xxxxx",vpn,ikesa,rx_ikemesg,s_pld_ctx,ikesa->keep_alive.req_mesg_id);

	dpd_seq_len
		= s_pld_ctx->r_u_there_ack_payload->ext.n->get_data_len(s_pld_ctx->r_u_there_ack_payload);
	dpd_seq
		= s_pld_ctx->r_u_there_ack_payload->ext.n->get_data(s_pld_ctx->r_u_there_ack_payload);

	if( dpd_seq_len != 4 || dpd_seq == NULL ){
		RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_R_U_THERE_ACK_INVALID_SEQ_DATA,"xxxx",vpn,ikesa,rx_ikemesg,s_pld_ctx);
		err = RHP_STATUS_INVALID_MSG;
		goto error;
	}

	if( ntohl(*((u32*)dpd_seq)) != (ikesa->v1.dpd_seq - 1) ){
		RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_R_U_THERE_ACK_NOT_INTERESTED,"xxxx",vpn,ikesa,rx_ikemesg,s_pld_ctx);
		err = 0;
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

  //
  // A R-U-THERE-ACK reply's mesg ID may be different from a R-U-THERE-REQ's one
  // (as a one-way IKE Informational mesg).
  //
  rhp_ikev1_p2_session_clear(ikesa,
  		ikesa->keep_alive.req_mesg_id,rx_ikemesg->get_exchange_type(rx_ikemesg),
  		(ikesa->v1.dpd_seq - 1));


  ikesa->statistics.rx_keep_alive_reply_packets++;

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_DPD_R_U_THERE_ACK,"KVP",rx_ikemesg,vpn,ikesa);

	RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_R_U_THERE_ACK_RTRN,"xxxxqqq",vpn,ikesa,rx_ikemesg,s_pld_ctx,ikesa->statistics.rx_encrypted_packets,ikesa->statistics.rx_keep_alive_reply_packets,ikesa->timers->last_rx_encrypted_packets);
	return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_DPD_R_U_THERE_ACK_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
	RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_R_U_THERE_ACK_ERR,"xxxxE",vpn,ikesa,rx_ikemesg,s_pld_ctx,err);
	return err;
}

static int _rhp_ikev1_rx_dpd(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = -EINVAL;
  rhp_vpn_realm* rlm = NULL;
  rhp_v1_dpd_srch_plds_ctx s_pld_ctx;

	RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_L,"xxxxLd",vpn,ikesa,rx_ikemesg,rx_ikemesg->rx_pkt,"IKESA_STAT",ikesa->state);

  memset(&s_pld_ctx,0,sizeof(rhp_v1_dpd_srch_plds_ctx));

  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
   RHP_BUG("");
   err = RHP_STATUS_INVALID_MSG;
   goto error;
  }

  if( !vpn->v1.peer_dpd_supproted ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_L_PEER_DPD_DISABLED,"xxx",vpn,ikesa,rx_ikemesg);
    RHP_UNLOCK(&(rlm->lock));
  	err = 0;
  	goto ignore;
  }

  rlm = vpn->rlm;
  if( rlm == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_L_NO_RLM,"xxx",vpn,ikesa,rx_ikemesg);
  	err = -EINVAL;
  	goto error;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
  	RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_L_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,rx_ikemesg,rlm);
    RHP_UNLOCK(&(rlm->lock));
  	err = -EINVAL;
  	goto error;
  }

  if( !rlm->v1.dpd_enabled ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_L_DISABLED,"xxx",vpn,ikesa,rx_ikemesg);
    RHP_UNLOCK(&(rlm->lock));
  	err = 0;
  	goto ignore;
  }

  RHP_UNLOCK(&(rlm->lock));


  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;

  {
  	u16 mesg_ids[3] = {	RHP_PROTO_IKEV1_N_ST_DPD_R_U_THERE,
  											RHP_PROTO_IKEV1_N_ST_DPD_R_U_THERE_ACK,
  											RHP_PROTO_IKE_NOTIFY_RESERVED};

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
			  			rhp_ikev2_mesg_srch_cond_n_mesg_ids,mesg_ids,
			  			_rhp_ikev1_dpd_srch_n_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){

      RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_L_PLD_PARSE_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);
      goto error;
    }

  	if( s_pld_ctx.r_u_there_payload == NULL &&
  			s_pld_ctx.r_u_there_ack_payload == NULL ){

      RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_L_NOT_INTERESTED_1,"xxx",vpn,ikesa,rx_ikemesg);

  		err = 0;
  		goto ignore;
  	}

    err = 0;
  }


	err = rhp_ikev1_rx_info_mesg_hash_verify(vpn,ikesa,rx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_N);
	if( err ){
  	goto error;
	}


	if( s_pld_ctx.r_u_there_payload ){

		err = _rhp_ikev1_rx_dpd_r_u_there(vpn,ikesa,rx_ikemesg,tx_ikemesg,&s_pld_ctx);
		if( err ){
			goto error;
		}

	}else if( s_pld_ctx.r_u_there_ack_payload ){

		err = _rhp_ikev1_rx_dpd_r_u_there_ack(vpn,ikesa,rx_ikemesg,&s_pld_ctx);
		if( err ){
			goto error;
		}
	}


	RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_L_RTRN,"xxx",vpn,ikesa,rx_ikemesg);
  return 0;

ignore:
error:
	RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_L_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);
	return 0; // Ignored.
}

int rhp_ikev1_rx_dpd(rhp_ikev2_mesg* rx_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_ikemesg)
{
	int err;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_ikemesg->get_exchange_type(rx_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD,"xxLdGxLbdd",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_ikemesg,"PROTO_IKE_EXCHG",exchange_type,rhp_gcfg_ikev1_dpd_enabled,vpn->v1.peer_dpd_supproted);

  if( !rhp_gcfg_ikev1_dpd_enabled ){
  	err = 0;
  	goto ignore;
  }


  if( exchange_type == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ||
  		exchange_type == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){

    if( !vpn->v1.peer_dpd_supproted ){

    	// This mesg may include the first DPD Vendor ID.

			if( my_ikesa_spi == NULL ){
				RHP_BUG("");
				err = -EINVAL;
				goto error;
			}

			ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
			if( ikesa == NULL ){
				err = -ENOENT;
				RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_P1_NO_IKESA,"xxLdG",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
				goto error;
			}

			if( vpn->origin_side == RHP_IKE_INITIATOR ){

				err = _rhp_ikev1_rx_dpd_p1_i(vpn,ikesa,rx_ikemesg,tx_ikemesg);

			}else{

				err = _rhp_ikev1_rx_dpd_p1_r(vpn,ikesa,rx_ikemesg,tx_ikemesg);
			}

    }else{

			RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_P1_ALREADY_RX_VID_SO_IGNORED,"xxLdG",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
    	err = 0;
    }

  }else if( exchange_type == RHP_PROTO_IKEV1_EXCHG_INFORMATIONAL ){

		if( my_ikesa_spi == NULL ){
	    RHP_BUG("");
	    err = -EINVAL;
	    goto error;
	  }

	  if( !rx_ikemesg->decrypted ){
	  	err = 0;
		  RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_NOT_DECRYPTED,"xxLdG",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
	  	goto error;
	  }

		ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
		if( ikesa == NULL ){
			err = -ENOENT;
		  RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_NO_IKESA,"xxLdG",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}

		err = _rhp_ikev1_rx_dpd(vpn,ikesa,rx_ikemesg,tx_ikemesg);

	}else{

		err = 0;
		RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_NOT_INTERESTED,"xxx",rx_ikemesg,vpn,tx_ikemesg);
	}

ignore:
error:
	RHP_TRC(0,RHPTRCID_IKEV1_RX_DPD_RTRN,"xxxE",rx_ikemesg,vpn,tx_ikemesg,err);
  return err;
}
