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
#include "rhp_esp.h"
#include "rhp_forward.h"
#include "rhp_nhrp.h"



static int _rhp_ikev2_create_child_sa_new_pkt_req(rhp_vpn* vpn,rhp_vpn_realm* rlm,
		rhp_ikesa* ikesa,rhp_childsa* childsa,rhp_ikev2_mesg* tx_req_ikemesg)
{
  int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_NEW_PKT_REQ,"xxxxxLd",vpn,rlm,ikesa,childsa,tx_req_ikemesg,"CHILDSA_MODE",childsa->ipsec_mode);

	if( childsa->ipsec_mode == RHP_CHILDSA_MODE_TRANSPORT ){

		if( rhp_ikev2_new_payload_tx(tx_req_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_req_ikemesg->put_payload(tx_req_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);
		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_USE_TRANSPORT_MODE);
	}

  {
    if( (err = rhp_ikev2_new_payload_tx(tx_req_ikemesg,RHP_PROTO_IKE_PAYLOAD_SA,&ikepayload)) ){
      RHP_BUG("");
      goto error;
    }

    tx_req_ikemesg->put_payload(tx_req_ikemesg,ikepayload);

    if( (err = ikepayload->ext.sa->set_def_childsa_prop(ikepayload,(u8*)&(childsa->spi_inb),RHP_PROTO_IPSEC_SPI_SIZE,0)) ){
      RHP_BUG("");
      goto error;
    }
  }

  {
    if( (err = rhp_ikev2_new_payload_tx(tx_req_ikemesg,RHP_PROTO_IKE_PAYLOAD_TS_I,&ikepayload)) ){
      RHP_BUG("");
      goto error;
    }

    tx_req_ikemesg->put_payload(tx_req_ikemesg,ikepayload);

    if( (err = ikepayload->ext.ts->set_i_tss(ikepayload,rlm,vpn->cfg_peer,NULL,NULL)) ){
      RHP_BUG("");
      goto error;
    }
  }

  {
    if( (err = rhp_ikev2_new_payload_tx(tx_req_ikemesg,RHP_PROTO_IKE_PAYLOAD_TS_R,&ikepayload)) ){
      RHP_BUG("");
      goto error;
    }

    tx_req_ikemesg->put_payload(tx_req_ikemesg,ikepayload);

    if( (err = ikepayload->ext.ts->set_i_tss(ikepayload,rlm,vpn->cfg_peer,NULL,NULL)) ){
      RHP_BUG("");
      goto error;
    }
  }

	if( (rlm->encap_mode_c & RHP_VPN_ENCAP_ETHERIP) && vpn->peer_is_rockhopper ){

		if( rhp_ikev2_new_payload_tx(tx_req_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_req_ikemesg->put_payload(tx_req_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);
		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_ETHERIP_ENCAP);

	}else if( (rlm->encap_mode_c & RHP_VPN_ENCAP_GRE) && vpn->peer_is_rockhopper ){

		if( rhp_ikev2_new_payload_tx(tx_req_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_req_ikemesg->put_payload(tx_req_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);
		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_GRE_ENCAP);
	}

  RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_NEW_PKT_REQ_RTRN,"xxxxx",vpn,rlm,ikesa,childsa,tx_req_ikemesg);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_NEW_PKT_REQ_ERR,"xxxxxE",vpn,rlm,ikesa,childsa,tx_req_ikemesg,err);
  return err;
}

static void _rhp_ikev2_create_child_sa_tx_comp_cb(rhp_vpn* vpn,rhp_ikesa* tx_ikesa,
		rhp_ikev2_mesg* tx_ikemesg,rhp_packet* serialized_pkt)
{
  rhp_childsa* childsa = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_TX_COMP_CB,"xxxxx",vpn,tx_ikesa,tx_ikemesg,tx_ikemesg->rx_pkt,serialized_pkt);

  childsa = vpn->childsa_get(vpn,RHP_DIR_INBOUND,tx_ikemesg->childsa_spi_inb);

  if( childsa ){

  	childsa->parent_ikesa.side = tx_ikesa->side;

  	memcpy(childsa->parent_ikesa.init_spi,tx_ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
  	memcpy(childsa->parent_ikesa.resp_spi,tx_ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);

  	childsa->gen_message_id = tx_ikemesg->get_mesg_id(tx_ikemesg);

  }else{

  	RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_TX_COMP_CB_CHILDSA_NOT_FOUND,"xxx",vpn,tx_ikesa,tx_ikemesg);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_TX_COMP_CB_RTRN,"xxx",vpn,tx_ikesa,tx_ikemesg);
  return;
}

static int _rhp_ikev2_create_child_sa_req(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err = -EINVAL;
  rhp_childsa* childsa = NULL;
  rhp_vpn_realm* rlm = vpn->rlm;

  RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_REQ,"xxxxd",vpn,ikesa,rx_resp_ikemesg,rlm->encap_mode_c,vpn->peer_is_rockhopper);

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
  	err = -EINVAL;
    RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_REQ_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,rx_resp_ikemesg,rlm);
  	goto error;
  }

  RHP_LOCK(&(rlm->lock));

  childsa = rhp_childsa_alloc(RHP_IKE_INITIATOR,0);
  if( childsa == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error_l;
  }

  childsa->gen_type = RHP_CHILDSA_GEN_IKE_AUTH;

  err = childsa->generate_inb_spi(childsa);
  if( err ){
    RHP_BUG("");
    goto error_l;
  }


  childsa->timers = rhp_childsa_new_timers(childsa->spi_inb,childsa->spi_outb);
  if( childsa->timers == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error_l;
  }

	if( (rlm->encap_mode_c & RHP_VPN_ENCAP_ETHERIP) && vpn->peer_is_rockhopper ){

		childsa->ipsec_mode = RHP_CHILDSA_MODE_TRANSPORT;

	}else if( rlm->encap_mode_c & RHP_VPN_ENCAP_IPIP ){

		childsa->ipsec_mode = RHP_CHILDSA_MODE_TUNNEL;

	}else if( rlm->encap_mode_c & RHP_VPN_ENCAP_GRE ){

		childsa->ipsec_mode = RHP_CHILDSA_MODE_TRANSPORT;

	}else{

		RHP_BUG("0x%x",rlm->encap_mode_c);
		goto error_l;
	}


	err = _rhp_ikev2_create_child_sa_new_pkt_req(vpn,rlm,ikesa,childsa,tx_req_ikemesg);
	if( err ){
		RHP_BUG("%d",err);
		goto error_l;
	}


  rhp_childsa_set_state(childsa,RHP_CHILDSA_STAT_LARVAL);

  err = rhp_vpn_inb_childsa_put(vpn,childsa->spi_inb);
  if( err ){
    RHP_BUG("");
    goto error_l;
  }

  vpn->childsa_put(vpn,childsa);

  childsa->timers->start_lifetime_timer(vpn,childsa,(time_t)rlm->childsa.lifetime_larval,1);

	RHP_UNLOCK(&(rlm->lock));


	tx_req_ikemesg->childsa_spi_inb = childsa->spi_inb;
	tx_req_ikemesg->packet_serialized = _rhp_ikev2_create_child_sa_tx_comp_cb;

  RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_REQ_RTRN,"xxx",vpn,ikesa,tx_req_ikemesg);
  return 0;

error_l:
	RHP_UNLOCK(&(rlm->lock));
error:

	if( childsa ){
    rhp_childsa_destroy(vpn,childsa);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_REQ_ERR,"xxxE",vpn,ikesa,tx_req_ikemesg,err);
  return err;
}

static int _rhp_ikev2_create_child_sa_new_pkt_error_notify_rep(rhp_ikev2_mesg* tx_ikemesg,rhp_ikesa* ikesa,
		u8 protocol_id,u32 childsa_spi,u16 notify_mesg_type,unsigned long arg0)
{
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_NEW_PKT_ERROR_NOTIFY_REP,"xxbULwx",tx_ikemesg,ikesa,protocol_id,childsa_spi,"PROTO_IKE_NOTIFY",notify_mesg_type,arg0);

  {
  	if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
    	RHP_BUG("");
    	goto error;
    }

  	tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

  	ikepayload->ext.n->set_message_type(ikepayload,notify_mesg_type);

  	if( childsa_spi ){
  		ikepayload->ext.n->set_spi(ikepayload,childsa_spi);
    	ikepayload->ext.n->set_protocol_id(ikepayload,protocol_id);
    }else{
    	ikepayload->ext.n->set_protocol_id(ikepayload,0);
    }

    switch( notify_mesg_type ){

    case RHP_PROTO_IKE_NOTIFY_ERR_NO_PROPOSAL_CHOSEN:
    	break;

    case RHP_PROTO_IKE_NOTIFY_ERR_TS_UNACCEPTABLE:
    	break;

    case RHP_PROTO_IKE_NOTIFY_ERR_NO_ADDITIONAL_SAS:
    	break;

    case RHP_PROTO_IKE_NOTIFY_ERR_INVALID_SPI:
   	  break;

    default:
      RHP_BUG("%d",notify_mesg_type);
      goto error;
    }
  }

 	tx_ikemesg->tx_flag = RHP_IKEV2_SEND_REQ_FLAG_URGENT;

  RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_NEW_PKT_ERROR_NOTIFY_REP_RTRN,"x",tx_ikemesg);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_NEW_PKT_ERROR_NOTIFY_REP_ERR,"x",tx_ikemesg);
	return -1; // ikepayload will be released later by rhp_ikev2_destroy_mesg().
}

int rhp_ikev2_create_child_sa_srch_sa_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
  rhp_ikev2_sa_payload* sa_payload = (rhp_ikev2_sa_payload*)payload->ext.sa;
  rhp_childsa_srch_plds_ctx* s_pld_ctx = (rhp_childsa_srch_plds_ctx*)ctx;
  rhp_res_sa_proposal* res_prop = &(s_pld_ctx->resolved_prop.v2);

  RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_REQ_SRCH_SA_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

  if( sa_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_REQ_SRCH_SA_CB_DUP_ERR,"xxx",rx_ikemesg,payload,ctx);
    goto error;
  }

  err = sa_payload->get_matched_childsa_prop(payload,res_prop);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_REQ_SRCH_SA_CB_NOT_MACHED_PROP,"xxxxE",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg,sa_payload,err);
    s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_NO_PROPOSAL_CHOSEN;
    goto error;
  }

  s_pld_ctx->sa_payload = payload;

  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_REQ_SRCH_SA_CB_RTRN,"xxxE",rx_ikemesg,payload,ctx,err);
  return err;
}

static int _rhp_ikev2_create_child_sa_srch_childsa_n_info_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_childsa_srch_plds_ctx* s_pld_ctx = (rhp_childsa_srch_plds_ctx*)ctx;
  rhp_ikev2_n_payload* n_payload = (rhp_ikev2_n_payload*)payload->ext.n;
  u16 notify_mesg_type;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_SRCH_CHILDSA_N_INFO_CB,"xdxxx",rx_ikemesg,enum_end,payload,n_payload,ctx);

  if( n_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  notify_mesg_type = n_payload->get_message_type(payload);

  if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_USE_TRANSPORT_MODE ){

  	s_pld_ctx->use_trans_port_mode = 1;

  }else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_ESP_TFC_PADDING_NOT_SUPPORTED ){

  	s_pld_ctx->esp_tfc_padding_not_supported = 1;

  }else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_ETHERIP_ENCAP ){

  	s_pld_ctx->use_etherip_encap = 1;

  }else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_GRE_ENCAP ){

  	s_pld_ctx->use_gre_encap = 1;
  }


  s_pld_ctx->dup_flag++;
  err = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_SRCH_CHILDSA_N_INFO_CB_RTRN,"xxxxwbbbbE",rx_ikemesg,payload,n_payload,ctx,notify_mesg_type,s_pld_ctx->use_trans_port_mode,s_pld_ctx->esp_tfc_padding_not_supported,s_pld_ctx->use_etherip_encap,s_pld_ctx->use_gre_encap,err);
  return err;
}


int rhp_ikev2_create_child_sa_req_srch_ts_i_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_childsa_srch_plds_ctx* s_pld_ctx = (rhp_childsa_srch_plds_ctx*)ctx;
  rhp_ikev2_ts_payload* ts_i_payload = (rhp_ikev2_ts_payload*)payload->ext.ts;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_SRCH_TS_I_CB,"xdxxdd",rx_ikemesg,enum_end,payload,ctx,s_pld_ctx->vpn->peer_is_remote_client,s_pld_ctx->rlm->config_server.reject_client_ts);

  if( ts_i_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  if( ts_i_payload->tss_head ){
  	ts_i_payload->tss_head->dump2log(ts_i_payload->tss_head,"TS_I",(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0));
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_REQ_SRCH_TS_I_CB_DUP_ERR,"xx",rx_ikemesg,ctx);
    goto error;
  }

  if( s_pld_ctx->vpn->peer_is_remote_client &&
  		s_pld_ctx->rlm->config_server.reject_client_ts ){

  	rhp_ikev2_traffic_selector* ts = ts_i_payload->tss_head;
  	while( ts ){

  		if( !rhp_childsa_is_any_traffic_selector(ts) ){

  	  	s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_TS_UNACCEPTABLE;
  	  	err = RHP_STATUS_INVALID_MSG;

  	    RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_REQ_SRCH_TS_I_CB_REJECT_CLIENTS_TS,"xx",rx_ikemesg,ctx);

    		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_CFG_REQ_CLIENT_ANY_TS_NOT_ALLOWED,"K",rx_ikemesg);

  	    goto error;
  		}
  		ts = ts->next;
  	}
  }

  err = ts_i_payload->get_matched_tss(payload,s_pld_ctx->rlm,s_pld_ctx->vpn->cfg_peer,&(s_pld_ctx->res_tss_i));
  if( err ){

  	RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_REQ_SRCH_TS_I_CB_NOT_MATCHED,"xxxxE",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg,ts_i_payload,err);

  	s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_TS_UNACCEPTABLE;
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

  s_pld_ctx->ts_i_payload = payload;

  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_REQ_SRCH_TS_I_CB_RTRN,"xxxE",rx_ikemesg,payload,ctx,err);
  return err;
}

int rhp_ikev2_create_child_sa_req_srch_ts_r_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_childsa_srch_plds_ctx* s_pld_ctx = (rhp_childsa_srch_plds_ctx*)ctx;
  rhp_ikev2_ts_payload* ts_r_payload = (rhp_ikev2_ts_payload*)payload->ext.ts;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_SRCH_TS_R_CB,"xdxxdd",rx_ikemesg,enum_end,payload,ctx,s_pld_ctx->vpn->peer_is_remote_client,s_pld_ctx->rlm->config_server.reject_client_ts);

  if( ts_r_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  if( ts_r_payload->tss_head ){
  	ts_r_payload->tss_head->dump2log(ts_r_payload->tss_head,"TS_R",(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0));
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_REQ_SRCH_TS_R_CB_DUP_ERR,"xx",rx_ikemesg,ctx);
    goto error;
  }

  if( s_pld_ctx->vpn->peer_is_remote_client &&
  		s_pld_ctx->rlm->config_server.reject_client_ts ){

  	rhp_ikev2_traffic_selector* ts = ts_r_payload->tss_head;
  	while( ts ){

  		if( !rhp_childsa_is_any_traffic_selector(ts) ){

  	  	s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_TS_UNACCEPTABLE;
  	  	err = RHP_STATUS_INVALID_MSG;

  	    RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_REQ_SRCH_TS_R_CB_REJECT_CLIENTS_TS,"xx",rx_ikemesg,ctx);

    		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_CFG_REQ_CLIENT_ANY_TS_NOT_ALLOWED,"K",rx_ikemesg);

  	    goto error;
  		}
  		ts = ts->next;
  	}
  }


  err = ts_r_payload->get_matched_tss(payload,s_pld_ctx->rlm,s_pld_ctx->vpn->cfg_peer,&(s_pld_ctx->res_tss_r));

  if( err ){

  	RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_REQ_SRCH_TS_R_CB_NOT_MATCHED,"xxxxE",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg,ts_r_payload,err);

  	s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_TS_UNACCEPTABLE;
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

  s_pld_ctx->ts_r_payload = payload;

  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_REQ_SRCH_TS_R_CB_RTRN,"xxxE",rx_ikemesg,payload,ctx,err);
  return err;
}

int rhp_ikev2_create_child_sa_rep_srch_ts_i_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_childsa_srch_plds_ctx* s_pld_ctx = (rhp_childsa_srch_plds_ctx*)ctx;
  rhp_ikev2_ts_payload* ts_i_payload = (rhp_ikev2_ts_payload*)payload->ext.ts;
  rhp_childsa_ts* extended_tss = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_SRCH_TS_I_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

  if( ts_i_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  if( ts_i_payload->tss_head ){
  	ts_i_payload->tss_head->dump2log(ts_i_payload->tss_head,"TS_I",(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0));
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_REP_SRCH_TS_I_CB_DUP_ERR,"xx",rx_ikemesg,ctx);
    goto error;
  }

  if( s_pld_ctx->vpn->ts_extended_flag ){

  	extended_tss = s_pld_ctx->vpn->last_my_tss;
  }

  err = ts_i_payload->check_tss(payload,s_pld_ctx->rlm,s_pld_ctx->vpn->cfg_peer,extended_tss,&(s_pld_ctx->res_tss_i));
  if( err ){

  	RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_REP_SRCH_TS_I_CB_NOT_MATCHED,"xxxxE",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg,ts_i_payload,err);

  	s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_TS_UNACCEPTABLE;
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

  s_pld_ctx->ts_i_payload = payload;

  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_REP_SRCH_TS_I_CB_RTRN,"xxxE",rx_ikemesg,payload,ctx,err);
  return err;
}

int rhp_ikev2_create_child_sa_rep_srch_ts_r_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_childsa_srch_plds_ctx* s_pld_ctx = (rhp_childsa_srch_plds_ctx*)ctx;
  rhp_ikev2_ts_payload* ts_r_payload = (rhp_ikev2_ts_payload*)payload->ext.ts;
  rhp_childsa_ts* extended_tss = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_SRCH_TS_R_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

  if( ts_r_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  if( ts_r_payload->tss_head ){
  	ts_r_payload->tss_head->dump2log(ts_r_payload->tss_head,"TS_R",(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0));
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_REP_SRCH_TS_R_CB_DUP_ERR,"xx",rx_ikemesg,ctx);
    goto error;
  }

  if( s_pld_ctx->vpn->ts_extended_flag ){

  	extended_tss = s_pld_ctx->vpn->last_peer_tss;
  }

  err = ts_r_payload->check_tss(payload,s_pld_ctx->rlm,s_pld_ctx->vpn->cfg_peer,extended_tss,&(s_pld_ctx->res_tss_r));
  if( err ){

  	RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_REP_SRCH_TS_R_CB_NOT_MATCHED,"xxxxE",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg,ts_r_payload,err);

  	s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_TS_UNACCEPTABLE;
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

  s_pld_ctx->ts_r_payload = payload;

  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_REP_SRCH_TS_R_CB_RTRN,"xxxE",rx_ikemesg,payload,ctx,err);
  return err;
}

static int _rhp_ikev2_create_child_sa_tx_resp_srch_cp_cb(rhp_ikev2_mesg* tx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
  rhp_childsa_srch_plds_ctx* s_pld_ctx = (rhp_childsa_srch_plds_ctx*)ctx;
  rhp_ikev2_cp_payload* cp_payload = (rhp_ikev2_cp_payload*)payload->ext.cp;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_TX_RESP_SRCH_CP_CB,"xdxxx",tx_ikemesg,enum_end,payload,ctx,cp_payload);

  if( cp_payload == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  s_pld_ctx->dup_flag++; // Only single IP address is currently assigned by Rockhopper.

  if( s_pld_ctx->dup_flag > 1 ){
  	RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  s_pld_ctx->res_cp_internal_addr_v4 = cp_payload->get_attr_internal_addr_v4(payload);
  s_pld_ctx->res_cp_internal_addr_v6 = cp_payload->get_attr_internal_addr_v6(payload);

  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_TX_RESP_SRCH_CP_CB_RTRN,"xxxE",tx_ikemesg,payload,ctx,err);
  return err;
}


static int _rhp_ikev2_create_child_sa_new_pkt_rep(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_childsa_srch_plds_ctx* s_pld_ctx,rhp_childsa *childsa,rhp_ikev2_mesg* tx_resp_ikemesg,
		int exchange_type,rhp_res_sa_proposal* res_prop)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_CREATE_CHILD_SA_REP,"xxxxxwx",vpn,ikesa,s_pld_ctx,childsa,tx_resp_ikemesg,exchange_type,res_prop);

	if( childsa->ipsec_mode == RHP_CHILDSA_MODE_TRANSPORT ){

		if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);
		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_USE_TRANSPORT_MODE);
	}

  {
    if( (err = rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_SA,&ikepayload)) ){
      RHP_BUG("%d",err);
      goto error;
    }

    tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

    err = ikepayload->ext.sa->set_matched_childsa_prop(ikepayload,&(s_pld_ctx->resolved_prop.v2),childsa->spi_inb);
    if( err ){
      RHP_BUG("%d",err);
      goto error;
    }
  }


  if( exchange_type == RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA ){

  	int nonce_len = childsa->rekey_nonce_r->get_nonce_len(childsa->rekey_nonce_r);
  	u8* nonce = childsa->rekey_nonce_r->get_nonce(childsa->rekey_nonce_r);

  	if( nonce == NULL ){
  		RHP_BUG("");
  		goto error;
    }

    if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_N_I_R,&ikepayload) ){
    	RHP_BUG("");
    	goto error;
    }

    tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

    if( ikepayload->ext.nir->set_nonce(ikepayload,nonce_len,nonce) ){
    	RHP_BUG("");
    	goto error;
    }

    if( res_prop->pfs ){

    	int key_len;
      u8* key = childsa->rekey_dh->get_my_pub_key(childsa->rekey_dh,&key_len);
      if( key == NULL ){
        RHP_BUG("");
        goto error;
      }

      if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_KE,&ikepayload) ){
        RHP_BUG("");
        goto error;
      }

      tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

      if( ikepayload->ext.ke->set_key(ikepayload,res_prop->dhgrp_id,key_len,key) ){
        RHP_BUG("");
        goto error;
      }
    }
  }


  {
    if( (err = rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_TS_I,&ikepayload)) ){
      RHP_BUG("%d",err);
      goto error;
    }

    tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

    ikepayload->ext.ts->set_matched_r_tss(ikepayload,s_pld_ctx->res_tss_i);
    s_pld_ctx->res_tss_i = NULL;

    if( s_pld_ctx->ts_i_payload->ext.ts->reconfirm_tss(s_pld_ctx->ts_i_payload,ikepayload) ){

    	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_CREATE_CHILD_SA_REP_RECONFIRM_TSS_TS_I_NOT_MATCHED,"xxxxx",vpn,ikesa,s_pld_ctx,childsa,tx_resp_ikemesg);

    	s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_TS_UNACCEPTABLE;

    	err = RHP_STATUS_INVALID_MSG;
    	goto error;
    }
  }

  {
    if( (err = rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_TS_R,&ikepayload)) ){
      RHP_BUG("%d",err);
      goto error;
    }

    tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

    ikepayload->ext.ts->set_matched_r_tss(ikepayload,s_pld_ctx->res_tss_r);
    s_pld_ctx->res_tss_r = NULL;

    if( s_pld_ctx->ts_r_payload->ext.ts->reconfirm_tss(s_pld_ctx->ts_r_payload,ikepayload) ){

    	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_CREATE_CHILD_SA_REP_RECONFIRM_TSS_TS_R_NOT_MATCHED,"xxxxx",vpn,ikesa,s_pld_ctx,childsa,tx_resp_ikemesg);

    	s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_TS_UNACCEPTABLE;

    	err = RHP_STATUS_INVALID_MSG;
    	goto error;
    }
  }


  if( (vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_ETHERIP) && vpn->peer_is_rockhopper ){

		if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);
		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_ETHERIP_ENCAP);

  }else if( (vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_GRE) && vpn->peer_is_rockhopper ){

		if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);
		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_GRE_ENCAP);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_CREATE_CHILD_SA_REP_RTRN,"xxxxx",vpn,ikesa,s_pld_ctx,childsa,tx_resp_ikemesg);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_CREATE_CHILD_SA_REP_ERR,"xxxxxE",vpn,ikesa,s_pld_ctx,childsa,tx_resp_ikemesg,err);
	return err;
}

int rhp_ikev2_create_child_sa_srch_childsa_nir_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_childsa_srch_plds_ctx* s_pld_ctx = (rhp_childsa_srch_plds_ctx*)ctx;
  rhp_ikev2_nir_payload* nir_payload = (rhp_ikev2_nir_payload*)payload->ext.sa;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_NIR_CB,"xdxxx",rx_ikemesg,enum_end,payload,nir_payload,ctx);

  if( nir_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_NIR_CB_DUP_ERR,"xxxx",rx_ikemesg,payload,nir_payload,ctx);
  	return RHP_STATUS_INVALID_MSG;
  }

  s_pld_ctx->nonce_len = nir_payload->get_nonce_len(payload);
  if( s_pld_ctx->nonce_len < 0 ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_CHILDSA_NIR_PLD_BAD_NONCE_LEN,"xxd",s_pld_ctx->vpn,rx_ikemesg,s_pld_ctx->nonce_len);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  s_pld_ctx->prf_key_len = rhp_crypto_prf_key_len(s_pld_ctx->ikesa->prop.v2.prf_id);
  if( s_pld_ctx->prf_key_len < 0 ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_CHILDSA_NIR_PLD_BAD_PRF_KEY_LEN_1,"xxd",s_pld_ctx->vpn,rx_ikemesg,s_pld_ctx->prf_key_len);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  if( (s_pld_ctx->prf_key_len >> 1) > s_pld_ctx->nonce_len ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_CHILDSA_NIR_PLD_BAD_PRF_KEY_LEN_2,"xxdd",s_pld_ctx->vpn,rx_ikemesg,(s_pld_ctx->prf_key_len >> 1),s_pld_ctx->nonce_len);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  s_pld_ctx->nonce = nir_payload->get_nonce(payload);
  if( s_pld_ctx->nonce == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_CHILDSA_NIR_PLD_NO_NONCE,"xx",s_pld_ctx->vpn,rx_ikemesg);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  s_pld_ctx->nir_payload = payload;
  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_NIR_CB_RTRN,"xxxxE",rx_ikemesg,payload,nir_payload,ctx,err);
  return err;
}

int rhp_ikev2_create_child_sa_srch_childsa_ke_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_childsa_srch_plds_ctx* s_pld_ctx = (rhp_childsa_srch_plds_ctx*)ctx;
  rhp_ikev2_ke_payload* ke_payload = (rhp_ikev2_ke_payload*)payload->ext.ke;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_KE_CB,"xdxxx",rx_ikemesg,enum_end,payload,ke_payload,ctx);

  if( ke_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_KE_CB_DUP_ERR,"xxxx",rx_ikemesg,payload,ke_payload,ctx);
  	return RHP_STATUS_INVALID_MSG;
  }

  s_pld_ctx->dhgrp = ke_payload->get_dhgrp(payload);

	if( s_pld_ctx->dhgrp != s_pld_ctx->resolved_prop.v2.dhgrp_id ){

		RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_KE_CB_DHGRP_NOT_MATCHED,"xxww",s_pld_ctx->vpn,rx_ikemesg,s_pld_ctx->dhgrp,s_pld_ctx->resolved_prop.v2.dhgrp_id);

		s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_NO_PROPOSAL_CHOSEN;

		err = RHP_STATUS_INVALID_MSG;
		goto error;
	}

	s_pld_ctx->peer_dh_pub_key_len = ke_payload->get_key_len(payload);
	s_pld_ctx->peer_dh_pub_key = ke_payload->get_key(payload);

	if( s_pld_ctx->peer_dh_pub_key_len < 0 || s_pld_ctx->peer_dh_pub_key == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_KE_CB_PLD_BAD_DH_PUB_KEY,"xxdx",s_pld_ctx->vpn,rx_ikemesg,s_pld_ctx->peer_dh_pub_key_len,s_pld_ctx->peer_dh_pub_key);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
	}

  s_pld_ctx->ke_payload = payload;
  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_KE_CB_RTRN,"xxxxE",rx_ikemesg,payload,ke_payload,ctx,err);
  return err;
}


// cb_ctx : rhp_ikev2_traffic_selector
int rhp_ikev2_childsa_add_v6_ra_tss_dup_eval(rhp_ikev2_traffic_selector* ts,void* cb_ctx)
{
	return rhp_ikev2_ts_cmp_ts2tss_same_or_any(ts,(rhp_ikev2_traffic_selector*)cb_ctx);
}

int rhp_ikev2_create_child_sa_add_v6_ext_ts(rhp_childsa_srch_plds_ctx* s_pld_ctx,
		rhp_ikev2_traffic_selector* my_tss_ext,rhp_ikev2_traffic_selector* peer_tss_ext,
		rhp_ikev2_traffic_selector* my_tss_ext2,rhp_ikev2_traffic_selector* peer_tss_ext2,
		int mark_pending)
{
	int err = -EINVAL;
	rhp_ikev2_traffic_selector *tss_head_i_d = NULL, *tss_head_r_d = NULL,
														 *tss_head_i_d2 = NULL, *tss_head_r_d2 = NULL, *tss_d_tail;

	RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_ADD_V6_EXT_TS,"xxxxxd",s_pld_ctx,my_tss_ext,peer_tss_ext,my_tss_ext2,peer_tss_ext2,mark_pending);
	my_tss_ext->dump(my_tss_ext,"rhp_ikev2_create_child_sa_add_v6_ext_ts.my_tss_ext");
	peer_tss_ext->dump(peer_tss_ext,"rhp_ikev2_create_child_sa_add_v6_ext_ts.peer_tss_ext");
	if( my_tss_ext2 ){
		my_tss_ext2->dump(my_tss_ext2,"rhp_ikev2_create_child_sa_add_v6_ext_ts.my_tss_ext2");
	}
	if( peer_tss_ext2 ){
		peer_tss_ext2->dump(peer_tss_ext2,"rhp_ikev2_create_child_sa_add_v6_ext_ts.peer_tss_ext2");
	}


	if( mark_pending ){

		rhp_ikev2_traffic_selector* org_ts = s_pld_ctx->res_tss_i;
		while( org_ts ){

			if( org_ts->get_ts_type(org_ts) == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){
				org_ts->is_pending = 1;
			}

			org_ts = org_ts->next;
		}

		org_ts = s_pld_ctx->res_tss_r;
		while( org_ts ){

			if( org_ts->get_ts_type(org_ts) == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){
				org_ts->is_pending = 1;
			}

			org_ts = org_ts->next;
		}
	}


	err = rhp_ikev2_dup_tss(peer_tss_ext,&tss_head_i_d,
					(!mark_pending ? rhp_ikev2_childsa_add_v6_ra_tss_dup_eval : NULL),
					s_pld_ctx->res_tss_i);
	if( err && err != -ENOENT ){
		goto error;
	}
	err = 0;

	if( peer_tss_ext2 ){

		err = rhp_ikev2_dup_tss(peer_tss_ext2,&tss_head_i_d2,
						(!mark_pending ? rhp_ikev2_childsa_add_v6_ra_tss_dup_eval : NULL),
						s_pld_ctx->res_tss_i);
		if( err && err != -ENOENT ){
			goto error;
		}
		err = 0;
	}

	err = rhp_ikev2_dup_tss(my_tss_ext,&tss_head_r_d,
					(!mark_pending ? rhp_ikev2_childsa_add_v6_ra_tss_dup_eval : NULL),
					s_pld_ctx->res_tss_r);
	if( err && err != -ENOENT ){
		goto error;
	}
	err = 0;

	if( my_tss_ext2 ){

		err = rhp_ikev2_dup_tss(my_tss_ext2,&tss_head_r_d2,
						(!mark_pending ? rhp_ikev2_childsa_add_v6_ra_tss_dup_eval : NULL),
						s_pld_ctx->res_tss_r);
		if( err && err != -ENOENT ){
			goto error;
		}
		err = 0;
	}


	if( tss_head_i_d ){

		tss_head_i_d->dump(tss_head_i_d,"rhp_ikev2_create_child_sa_add_v6_ext_ts.tss_head_i_d");

		tss_d_tail = s_pld_ctx->res_tss_i;
		if( tss_d_tail ){

			while( tss_d_tail && tss_d_tail->next ){
				tss_d_tail = tss_d_tail->next;
			}

			tss_d_tail->next = tss_head_i_d;

		}else{

			s_pld_ctx->res_tss_i = tss_head_i_d;
		}

	}else{
		RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_ADD_V6_EXT_TS_NO_TSS_HEAD_I_D,"xxx",s_pld_ctx,my_tss_ext,peer_tss_ext);
	}

	if( tss_head_i_d2 ){

		tss_head_i_d2->dump(tss_head_i_d2,"rhp_ikev2_create_child_sa_add_v6_ext_ts.tss_head_i_d2");

		tss_d_tail = s_pld_ctx->res_tss_i;
		if( tss_d_tail ){

			while( tss_d_tail && tss_d_tail->next ){
				tss_d_tail = tss_d_tail->next;
			}

			tss_d_tail->next = tss_head_i_d2;

		}else{

			s_pld_ctx->res_tss_i = tss_head_i_d2;
		}

	}else{
		RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_ADD_V6_EXT_TS_NO_TSS_HEAD_I_D2,"xxx",s_pld_ctx,my_tss_ext,peer_tss_ext);
	}

	if( tss_head_r_d ){

		tss_head_r_d->dump(tss_head_r_d,"rhp_ikev2_create_child_sa_add_v6_ext_ts.tss_head_r_d");

		tss_d_tail = s_pld_ctx->res_tss_r;
		if( tss_d_tail ){

			while( tss_d_tail && tss_d_tail->next ){
				tss_d_tail = tss_d_tail->next;
			}

			tss_d_tail->next = tss_head_r_d;

		}else{

			s_pld_ctx->res_tss_r = tss_head_r_d;
		}

	}else{
		RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_ADD_V6_EXT_TS_NO_TSS_HEAD_R_D,"xxx",s_pld_ctx,my_tss_ext,peer_tss_ext);
	}

	if( tss_head_r_d2 ){

		tss_head_r_d2->dump(tss_head_r_d2,"rhp_ikev2_create_child_sa_add_v6_ext_ts.tss_head_r_d2");

		tss_d_tail = s_pld_ctx->res_tss_r;
		if( tss_d_tail ){

			while( tss_d_tail && tss_d_tail->next ){
				tss_d_tail = tss_d_tail->next;
			}

			tss_d_tail->next = tss_head_r_d2;

		}else{

			s_pld_ctx->res_tss_r = tss_head_r_d2;
		}

	}else{
		RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_ADD_V6_EXT_TS_NO_TSS_HEAD_R_D2,"xxx",s_pld_ctx,my_tss_ext,peer_tss_ext);
	}

	if( s_pld_ctx->res_tss_i ){
		s_pld_ctx->res_tss_i->dump(s_pld_ctx->res_tss_i,"s_pld_ctx->res_tss_i");
	}
	if( s_pld_ctx->res_tss_r ){
		s_pld_ctx->res_tss_r->dump(s_pld_ctx->res_tss_r,"s_pld_ctx->res_tss_r");
	}
	RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_ADD_V6_EXT_TS_RTRN,"xxxxx",s_pld_ctx,my_tss_ext,peer_tss_ext,s_pld_ctx->res_tss_i,s_pld_ctx->res_tss_r);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_ADD_V6_EXT_TS_ERR,"xxxE",s_pld_ctx,my_tss_ext,peer_tss_ext,err);
	return err;
}

int rhp_ikev2_create_child_sa_add_v6_accept_ra_ts(rhp_childsa_srch_plds_ctx* s_pld_ctx)
{
	return rhp_ikev2_create_child_sa_add_v6_ext_ts(s_pld_ctx,
			rhp_ikev2_cfg_my_v6_ra_tss,rhp_ikev2_cfg_peer_v6_ra_tss,NULL,NULL,0);
}

int rhp_ikev2_create_child_sa_add_v6_auto_ts(rhp_childsa_srch_plds_ctx* s_pld_ctx,int mark_pending)
{
	int err = -EINVAL;
	rhp_vpn_realm* rlm = s_pld_ctx->rlm;
	u8 my_ts_buf[sizeof(rhp_proto_ike_ts_selector) + 32];
	u8 peer_ts_buf[sizeof(rhp_proto_ike_ts_selector) + 32];
	rhp_proto_ike_ts_selector *my_ts = (rhp_proto_ike_ts_selector*)my_ts_buf,
														*peer_ts = (rhp_proto_ike_ts_selector*)peer_ts_buf;
	rhp_ikev2_traffic_selector *my_tss_ext2 = NULL,*peer_tss_ext2 = NULL;
	rhp_ip_addr subnet_addr;
	u8 *start_addr, *end_addr;

	memset(&subnet_addr,0,sizeof(rhp_ip_addr));
	memset(my_ts,0,sizeof(rhp_proto_ike_ts_selector));
	memset(peer_ts,0,sizeof(rhp_proto_ike_ts_selector));

	{
		err = rhp_ikev2_alloc_ts(RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE,&my_tss_ext2);
		if( err ){
			RHP_BUG("");
			goto error;
		}

		my_tss_ext2->tsh = my_ts;
	}

	{
		err = rhp_ikev2_alloc_ts(RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE,&peer_tss_ext2);
		if( err ){
			RHP_BUG("");
			goto error;
		}

		peer_tss_ext2->tsh = peer_ts;
	}


	err = rlm->get_internal_if_subnet_addr(rlm,AF_INET6,&subnet_addr);
	if( err ){

		err = rhp_ikev2_create_child_sa_add_v6_ext_ts(s_pld_ctx,
						rhp_ikev2_cfg_my_v6_auto_tss,rhp_ikev2_cfg_peer_v6_auto_tss,NULL,NULL,
						mark_pending);

		goto end;
	}

	{
		my_ts->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
		my_ts->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
		my_ts->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
		my_ts->start_port.icmp.type = 0;
		my_ts->start_port.icmp.code = 0;
		my_ts->end_port.icmp.type = 0xFF;
		my_ts->end_port.icmp.code = 0xFF;
		start_addr = (u8*)(my_ts + 1);
		end_addr = start_addr + 16;

		rhp_ipv6_subnet_addr_range(subnet_addr.addr.v6,subnet_addr.prefixlen,start_addr,end_addr);
	}

	{
		peer_ts->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
		peer_ts->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
		peer_ts->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
		peer_ts->start_port.icmp.type = 0;
		peer_ts->start_port.icmp.code = 0;
		peer_ts->end_port.icmp.type = 0xFF;
		peer_ts->end_port.icmp.code = 0xFF;
		start_addr = (u8*)(peer_ts + 1);
		end_addr = start_addr + 16;

		rhp_ipv6_subnet_addr_range(subnet_addr.addr.v6,subnet_addr.prefixlen,start_addr,end_addr);
	}

	err = rhp_ikev2_create_child_sa_add_v6_ext_ts(s_pld_ctx,
					rhp_ikev2_cfg_my_v6_auto_tss,rhp_ikev2_cfg_peer_v6_auto_tss,my_tss_ext2,peer_tss_ext2,
					mark_pending);
	if( err ){
		goto error;
	}

end:
error:
	if( my_tss_ext2 ){
		my_tss_ext2->tsh = NULL;
		rhp_ikev2_ts_payload_free_ts(my_tss_ext2);
	}
	if( peer_tss_ext2 ){
		peer_tss_ext2->tsh = NULL;
		rhp_ikev2_ts_payload_free_ts(peer_tss_ext2);
	}

	return err;
}

int rhp_ikev2_create_child_sa_purge_af_tss(rhp_ikev2_mesg* tx_resp_ikemesg,
		rhp_childsa_srch_plds_ctx* s_pld_ctx,u8 purged_ts_type,unsigned int* ts_extended_flag_r)
{
	int i;

	for( i = 0; i < 2; i++ ){

		rhp_ikev2_traffic_selector *res_ts,*res_ts_p = NULL, *res_ts_n = NULL;

		if( i == 0 ){
			res_ts = s_pld_ctx->res_tss_i;
		}else{
			res_ts = s_pld_ctx->res_tss_r;
		}

		while( res_ts ){

			u8 ts_type = res_ts->get_ts_type(res_ts);

			res_ts_n = res_ts->next;

			if( ts_type == purged_ts_type ){

				if( res_ts_p == NULL ){

					if( i == 0 ){
						s_pld_ctx->res_tss_i = res_ts->next;
					}else{
						s_pld_ctx->res_tss_r = res_ts->next;
					}

				}else{

					res_ts_p->next = res_ts->next;
				}

				res_ts->next = NULL;
				if( i == 0 ){
					res_ts->dump(res_ts,"rhp_ikev2_create_child_sa_purge_af_tss_i.purged");
				}else{
					res_ts->dump(res_ts,"rhp_ikev2_create_child_sa_purge_af_tss_r.purged");
				}

				rhp_ikev2_ts_payload_free_ts(res_ts);

				if( ts_extended_flag_r ){
					*ts_extended_flag_r |= RHP_VPN_TS_EXT_FLG_NARROW_CP;
				}

			}else{

				res_ts_p = res_ts;
			}

			res_ts = res_ts_n;
		}
	}

	return 0;
}

int rhp_ikev2_create_child_sa_mod_tss_cp(rhp_ikev2_mesg* tx_resp_ikemesg,
		rhp_childsa_srch_plds_ctx* s_pld_ctx,unsigned int ts_extended_flag_0)
{
	int err = -EINVAL;
	rhp_ip_addr *cp_internal_addr_v4 = NULL, *cp_internal_addr_v6 = NULL;
	unsigned int ts_extended_flag = ts_extended_flag_0;
	rhp_vpn* vpn = s_pld_ctx->vpn;
	rhp_ikesa* ikesa = s_pld_ctx->ikesa;
	rhp_vpn_realm* rlm = s_pld_ctx->rlm;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_MOD_TSS_CP,"xxxxxxxddd",tx_resp_ikemesg,s_pld_ctx,vpn,ikesa,rlm,s_pld_ctx->res_tss_i,s_pld_ctx->res_tss_r,rlm->config_server.allow_v6_ra,vpn->internal_net_info.peer_exec_ipv6_autoconf,ts_extended_flag_0);

	if( s_pld_ctx->res_tss_i == NULL || s_pld_ctx->res_tss_r == NULL ){
		s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_TS_UNACCEPTABLE;
		RHP_BUG("0x%x, 0x%x",s_pld_ctx->res_tss_i,s_pld_ctx->res_tss_r);
		return -EINVAL;
	}

	s_pld_ctx->res_tss_i->dump(s_pld_ctx->res_tss_i,"Mod TS_I with CP-B4");
	s_pld_ctx->res_tss_r->dump(s_pld_ctx->res_tss_r,"Mod TS_R with CP-B4");


	s_pld_ctx->dup_flag = 0;

	err = tx_resp_ikemesg->search_payloads(tx_resp_ikemesg,0,
			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_CP),
			_rhp_ikev2_create_child_sa_tx_resp_srch_cp_cb,s_pld_ctx);

  if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_MOD_TSS_CP_CP_PLD_ERR,"xxxE",vpn,ikesa,tx_resp_ikemesg,err);

  	if( s_pld_ctx->notify_error ){
      goto error;
  	}

  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }


	if( s_pld_ctx->res_cp_internal_addr_v4 ){

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_MOD_TSS_CP_CP_RESP,"xxxx",vpn,ikesa,tx_resp_ikemesg,s_pld_ctx->res_cp_internal_addr_v4);
  	rhp_ip_addr_dump("s_pld_ctx.res_cp_internal_addr_v4",s_pld_ctx->res_cp_internal_addr_v4);

  	cp_internal_addr_v4 = s_pld_ctx->res_cp_internal_addr_v4;

	}else if( vpn->internal_net_info.peer_addr_v4_cp == RHP_IKEV2_CFG_CP_ADDR_ASSIGNED ){

		cp_internal_addr_v4 = rhp_ip_search_addr_list(vpn->internal_net_info.peer_addrs,
				rhp_ip_search_addr_list_cb_addr_ipv4_tag,(void*)RHP_IPADDR_TAG_IKEV2_CFG_ASSIGNED);

		RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_MOD_TSS_CP_USE_OLD_INFO,"xxxx",vpn,ikesa,tx_resp_ikemesg,cp_internal_addr_v4);
  	rhp_ip_addr_dump("vpn->internal_net_info.cp_internal_addr_v4",cp_internal_addr_v4);
	}

	if( s_pld_ctx->res_cp_internal_addr_v6 ){

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_MOD_TSS_CP_CP_RESP_V6,"xxxx",vpn,ikesa,tx_resp_ikemesg,s_pld_ctx->res_cp_internal_addr_v6);
  	rhp_ip_addr_dump("s_pld_ctx.res_cp_internal_addr_v6",s_pld_ctx->res_cp_internal_addr_v6);

  	cp_internal_addr_v6 = s_pld_ctx->res_cp_internal_addr_v6;

	}else if( vpn->internal_net_info.peer_addr_v6_cp == RHP_IKEV2_CFG_CP_ADDR_ASSIGNED ){

		cp_internal_addr_v6 = rhp_ip_search_addr_list(vpn->internal_net_info.peer_addrs,
				rhp_ip_search_addr_list_cb_addr_ipv6_tag,(void*)RHP_IPADDR_TAG_IKEV2_CFG_ASSIGNED);

		RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_MOD_TSS_CP_USE_OLD_INFO,"xxxx",vpn,ikesa,tx_resp_ikemesg,cp_internal_addr_v6);
  	rhp_ip_addr_dump("vpn->internal_net_info.cp_internal_addr_v6",cp_internal_addr_v6);
	}


	if( cp_internal_addr_v4 || cp_internal_addr_v6 ){

		rhp_ikev2_traffic_selector *res_ts = s_pld_ctx->res_tss_i,
				*res_ts_p = NULL, *res_ts_n = NULL;

		while( res_ts ){

			rhp_ip_addr* cp_internal_addr = NULL;
			u8 ts_type = res_ts->get_ts_type(res_ts);

			res_ts_n = res_ts->next;

			if( ts_type == RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE ){

				cp_internal_addr = cp_internal_addr_v4;

			}else if( ts_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){

				cp_internal_addr = cp_internal_addr_v6;

			}else{

				res_ts_p = res_ts;

				goto next;
			}

			if( cp_internal_addr ){

				if( res_ts->addr_is_included(res_ts,cp_internal_addr) ){

					err = res_ts->replace_start_addr(res_ts,cp_internal_addr);
					if( err ){
						RHP_BUG("");
						goto error;
					}

					err = res_ts->replace_end_addr(res_ts,cp_internal_addr);
					if( err ){
						RHP_BUG("");
						goto error;
					}

					ts_extended_flag |= RHP_VPN_TS_EXT_FLG_NARROW_CP;

				}else{

					RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_MOD_TSS_CP_INTERNAL_ADDR_NOT_MATCHED_TS,"xxxx",vpn,ikesa,tx_resp_ikemesg,res_ts);
					goto del_ts;
				}

				res_ts_p = res_ts;

			}else{

				RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_MOD_TSS_CP_NO_INTERNAL_ADDR_FOR_IP_VER,"xxxx",vpn,ikesa,tx_resp_ikemesg,res_ts);

				if( ts_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE &&
						vpn->internal_net_info.peer_exec_ipv6_autoconf ){

					goto next;
				}

del_ts:
				if( res_ts_p == NULL ){

					s_pld_ctx->res_tss_i = res_ts->next;

				}else{

					res_ts_p->next = res_ts->next;
				}

				res_ts->next = NULL;
				res_ts->dump(res_ts,"rhp_ikev2_create_child_sa_mod_tss_cp.purged");

				rhp_ikev2_ts_payload_free_ts(res_ts);

				ts_extended_flag |= RHP_VPN_TS_EXT_FLG_NARROW_CP;
			}

next:
			res_ts = res_ts_n;
		}

	}else{

		RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REPLACE_TS_I_NOT_APPLIED,"xxx",vpn,ikesa,tx_resp_ikemesg);
	}


	if( s_pld_ctx->res_tss_i == NULL || s_pld_ctx->res_tss_r == NULL ){

		RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_MOD_TSS_CP_NO_INTERNAL_ADDR_NO_TSS,"xxxxx",vpn,ikesa,tx_resp_ikemesg,s_pld_ctx->res_tss_i,s_pld_ctx->res_tss_r);

		s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_TS_UNACCEPTABLE;

		err = RHP_STATUS_INVALID_MSG;
		goto error;
	}


	if( rlm->config_server.allow_v6_ra &&
			cp_internal_addr_v6 ){

		err = rhp_ikev2_create_child_sa_add_v6_accept_ra_ts(s_pld_ctx);
		if( !err ){

			ts_extended_flag |= RHP_VPN_TS_EXT_FLG_IPV6_ALLOW_RA;

		}else if( err && err != -ENOENT ){
			goto error;
		}
		err = 0;

	}else{

		RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_MOD_TSS_CP_NO_V6RA_TSS,"xxxx",tx_resp_ikemesg,s_pld_ctx,vpn,ikesa);
	}


	s_pld_ctx->res_tss_i->dump(s_pld_ctx->res_tss_i,"Mod TS_I with CP-AFTR");
	s_pld_ctx->res_tss_r->dump(s_pld_ctx->res_tss_r,"Mod TS_R with CP-AFTR");

	if( ts_extended_flag_0 != (unsigned int)-1 && ts_extended_flag ){

		vpn->ts_extended_flag |= ts_extended_flag;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_MOD_TSS_CP_RTRN,"xxxxx",tx_resp_ikemesg,s_pld_ctx,vpn,ikesa,vpn->ts_extended_flag);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_MOD_TSS_CP_ERR,"xxxxxE",tx_resp_ikemesg,s_pld_ctx,vpn,ikesa,vpn->ts_extended_flag,err);
	return err;
}


static int _rhp_ikev2_rx_create_child_sa_req_sec_params(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_childsa* childsa,
		rhp_vpn_realm* rlm,u8 exchange_type,rhp_childsa_srch_plds_ctx* s_pld_ctx)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_SEC_PARAMS,"xxxxbx",vpn,ikesa,childsa,rlm,exchange_type,s_pld_ctx);

	childsa->integ_inb = rhp_crypto_integ_alloc(s_pld_ctx->resolved_prop.v2.integ_id);
	if( childsa->integ_inb == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	childsa->integ_outb = rhp_crypto_integ_alloc(s_pld_ctx->resolved_prop.v2.integ_id);
	if( childsa->integ_outb == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	childsa->encr = rhp_crypto_encr_alloc(s_pld_ctx->resolved_prop.v2.encr_id,
										s_pld_ctx->resolved_prop.v2.encr_key_bits);
	if( childsa->encr == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	childsa->rx_anti_replay.window_mask = rhp_crypto_bn_alloc(rlm->childsa.anti_replay_win_size);
	if( childsa->rx_anti_replay.window_mask == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_SEC_PARAMS_RTRN,"xxx",vpn,ikesa,childsa);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_SEC_PARAMS_ERR,"xxxE",vpn,ikesa,childsa,err);
	return err;
}

static void _rhp_ikev2_rx_create_child_sa_req_mark_collision_sa(rhp_vpn* vpn,rhp_childsa* childsa)
{
  rhp_childsa *col_childsa = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_MARK_COLLISION_SA,"xxx",vpn,childsa,vpn->childsa_list_head);

  col_childsa = vpn->childsa_list_head;
  while( col_childsa ){


    if( col_childsa != childsa &&
    		col_childsa->state == RHP_CHILDSA_STAT_LARVAL ){

    	col_childsa->collision_detected = 1;
      childsa->collision_detected = 1;
    }

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_MARK_COLLISION_SA_COL_SA,"xxxLdd",vpn,childsa,col_childsa,"CHILDSA_STAT",col_childsa->state,col_childsa->collision_detected);

    // TODO : col_childsa whose state is RHP_CHILDSA_STAT_MATURE(negotiation's
    //        collision may have occured...) should be deleted???

    col_childsa = col_childsa->next_vpn_list;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_MARK_COLLISION_SA_RTRN,"xxxd",vpn,childsa,childsa->collision_detected);
}

int rhp_ikev2_rx_create_child_sa_req_encap_mode(rhp_vpn* vpn,rhp_vpn_realm* rlm,
		rhp_childsa_srch_plds_ctx* s_pld_ctx,int* encap_mode_c_r)
{
	int err = -EINVAL;
  int encap_mode_c;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_ENCAP_MODE,"xxxddxdddd",vpn,rlm,s_pld_ctx,vpn->peer_is_remote_client,rlm->config_server.disable_non_ip,rlm->encap_mode_c,s_pld_ctx->use_trans_port_mode,s_pld_ctx->use_etherip_encap,s_pld_ctx->use_gre_encap,vpn->peer_is_rockhopper);

  if( vpn->peer_is_remote_client && rlm->config_server.disable_non_ip ){

  	encap_mode_c = RHP_VPN_ENCAP_IPIP;

  }else if( rlm->encap_mode_c == RHP_VPN_ENCAP_GRE ){

  	if( !s_pld_ctx->use_trans_port_mode || s_pld_ctx->use_etherip_encap ){

  		s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_NO_PROPOSAL_CHOSEN;

    	err = RHP_STATUS_NO_PROPOSAL_CHOSEN;
      goto notify_error;
  	}

  	encap_mode_c = RHP_VPN_ENCAP_GRE;

  }else if( (rlm->encap_mode_c & RHP_VPN_ENCAP_ETHERIP) &&
  					 s_pld_ctx->use_trans_port_mode && s_pld_ctx->use_etherip_encap ){

  	encap_mode_c = RHP_VPN_ENCAP_ETHERIP;

  }else if( (rlm->encap_mode_c & RHP_VPN_ENCAP_GRE) &&
  					s_pld_ctx->use_trans_port_mode && s_pld_ctx->use_gre_encap ){

  	encap_mode_c = RHP_VPN_ENCAP_GRE;

  }else if( (rlm->encap_mode_c & RHP_VPN_ENCAP_GRE) &&
  					s_pld_ctx->use_trans_port_mode && !vpn->peer_is_rockhopper ){

  	// For Inter-op...Ugly!

  	encap_mode_c = RHP_VPN_ENCAP_GRE;

  }else if( rlm->encap_mode_c & RHP_VPN_ENCAP_IPIP ){

  	if( s_pld_ctx->use_gre_encap || s_pld_ctx->use_trans_port_mode ){

  		s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_NO_PROPOSAL_CHOSEN;

    	err = RHP_STATUS_NO_PROPOSAL_CHOSEN;
      goto notify_error;
  	}

  	encap_mode_c = RHP_VPN_ENCAP_IPIP;

  }else{

  	s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_NO_PROPOSAL_CHOSEN;

  	err = RHP_STATUS_NO_PROPOSAL_CHOSEN;
    goto notify_error;
  }

  *encap_mode_c_r = encap_mode_c;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_ENCAP_MODE_RTRN,"xxxLd",vpn,rlm,s_pld_ctx,"VPN_ENCAP",encap_mode_c);
  return 0;

notify_error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_ENCAP_MODE_ERR,"xxxE",vpn,rlm,s_pld_ctx,err);
	return err;
}

int rhp_ikev2_rx_create_child_sa_req_internal_net(rhp_vpn* vpn,rhp_childsa* childsa,rhp_vpn_realm* rlm,
		rhp_childsa_srch_plds_ctx* s_pld_ctx,int encap_mode_c)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_INTERNAL_NET,"xxxxbbbxbdMLd",vpn,childsa,rlm,s_pld_ctx,s_pld_ctx->use_etherip_encap,s_pld_ctx->use_gre_encap,s_pld_ctx->use_trans_port_mode,rlm->encap_mode_c,vpn->peer_is_remote_client,rlm->config_server.disable_non_ip,vpn->internal_net_info.exchg_peer_mac,"VPN_ENCAP",encap_mode_c);

  vpn->internal_net_info.encap_mode_c = encap_mode_c;

	if( encap_mode_c == RHP_VPN_ENCAP_ETHERIP ){

		childsa->ipsec_mode = RHP_CHILDSA_MODE_TRANSPORT;

		{
			u8* peer_mac = vpn->internal_net_info.exchg_peer_mac;

			if( !_rhp_mac_addr_null(peer_mac) && vpn->internal_net_info.peer_addrs ){

				err = rhp_bridge_static_cache_reset_for_vpn(vpn->vpn_realm_id,vpn,
								peer_mac,vpn->internal_net_info.peer_addrs,
								RHP_BRIDGE_SCACHE_IKEV2_EXCHG);

				if( err ){
					RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_L_BRDG_CACHE_ETHER_IP_ERR,"x",vpn);
				}
			}
			err = 0;
		}

	}else{

		//
		// RHP_VPN_ENCAP_IPIP or RHP_VPN_ENCAP_GRE
		//

		if( encap_mode_c == RHP_VPN_ENCAP_GRE ){

			childsa->ipsec_mode = RHP_CHILDSA_MODE_TRANSPORT;

		}else if( encap_mode_c == RHP_VPN_ENCAP_IPIP ){

			childsa->ipsec_mode = RHP_CHILDSA_MODE_TUNNEL;

		}else{
			RHP_BUG("%d",encap_mode_c);
		}

		if( vpn->internal_net_info.peer_addrs ){

			err = rhp_bridge_static_cache_reset_for_vpn(vpn->vpn_realm_id,vpn,
							vpn->internal_net_info.dummy_peer_mac,vpn->internal_net_info.peer_addrs,
							RHP_BRIDGE_SCACHE_DUMMY);

			if( err ){
				RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_L_BRDG_CACHE_IPIP_ERR,"x",vpn);
			}

		}else{

			RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_L_BRDG_CACHE_IPIP_NO_PEER_ADDRS,"x",vpn);
		}
		err = 0;
	}

	rhp_bridge_cache_flush_by_vpn(vpn);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_INTERNAL_NET_RTRN,"xxxxLdLdx",vpn,childsa,rlm,s_pld_ctx,"VPN_ENCAP",vpn->internal_net_info.encap_mode_c,"CHILDSA_MODE",childsa->ipsec_mode,vpn->internal_net_info.peer_addrs);
	return 0;
}

static int _rhp_ikev2_rx_create_child_sa_req(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_childsa *childsa = NULL,*cur_childsa = NULL;
  rhp_vpn_realm* rlm = vpn->rlm;
  rhp_childsa_srch_plds_ctx s_pld_ctx;
	u8 exchange_type = rx_req_ikemesg->get_exchange_type(rx_req_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_L,"xxxxxLb",vpn,ikesa,rx_req_ikemesg,rx_req_ikemesg->rx_pkt,tx_resp_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
  	err = -EINVAL;
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_L_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,rx_req_ikemesg,vpn->rlm);
  	goto error_rlm_l;
  }

  if( rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error_rlm_l;
  }


  memset(&s_pld_ctx,0,sizeof(rhp_childsa_srch_plds_ctx));

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;
  s_pld_ctx.rlm = rlm;

  //
  // Multiple IPsec SAs NOT supported. Sorry.
  //
  if( exchange_type == RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA ){

  	cur_childsa = vpn->childsa_list_head;
  	while( cur_childsa ){

  		if( cur_childsa->state == RHP_CHILDSA_STAT_LARVAL 	||
  				cur_childsa->state == RHP_CHILDSA_STAT_MATURE 	||
  				cur_childsa->state == RHP_CHILDSA_STAT_REKEYING ){

  			s_pld_ctx.notify_error = RHP_PROTO_IKE_NOTIFY_ERR_NO_ADDITIONAL_SAS;

#ifdef RHP_DBUG_NO_ADDITIONAL_SAS_ERR
  			RHP_BUG("cur_childsa: 0x%x, state: %d",cur_childsa,cur_childsa->state);
  			_rhp_panic_time_bomb(30);
#endif // RHP_DBUG_NO_ADDITIONAL_SAS_ERR

  			goto notify_error;
  		}

  		cur_childsa = cur_childsa->next_vpn_list;
  	}
  }


  {
  	s_pld_ctx.dup_flag = 0;

    memset(&(s_pld_ctx.resolved_prop.v2),0,sizeof(rhp_res_sa_proposal));

    if( exchange_type == RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA ){
    	s_pld_ctx.resolved_prop.v2.pfs = rlm->childsa.pfs;
    }

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_SA),
    		rhp_ikev2_create_child_sa_srch_sa_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK ){

     RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_L_SA_PLD_ERR,"xxxE",vpn,ikesa,rx_req_ikemesg,err);

    	if( s_pld_ctx.notify_error ){
        goto notify_error;
    	}

   		err = RHP_STATUS_INVALID_MSG;
    	goto error_rlm_l;
  	}

    RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_L_MATCHED_PROP,"xxxxbbbpwdwwwwd",vpn,ikesa,rx_req_ikemesg,s_pld_ctx.sa_payload,s_pld_ctx.resolved_prop.v2.number,s_pld_ctx.resolved_prop.v2.protocol_id,s_pld_ctx.resolved_prop.v2.spi_len,RHP_PROTO_SPI_MAX_SIZE,s_pld_ctx.resolved_prop.v2.spi,s_pld_ctx.resolved_prop.v2.encr_id,s_pld_ctx.resolved_prop.v2.encr_key_bits,s_pld_ctx.resolved_prop.v2.prf_id,s_pld_ctx.resolved_prop.v2.integ_id,s_pld_ctx.resolved_prop.v2.dhgrp_id,s_pld_ctx.resolved_prop.v2.esn,s_pld_ctx.resolved_prop.v2.pfs);
  	err = 0;
  }


  {
  	s_pld_ctx.dup_flag = 0;
  	u16 csa_mesg_ids[5] = {	RHP_PROTO_IKE_NOTIFY_ST_USE_TRANSPORT_MODE,
  													RHP_PROTO_IKE_NOTIFY_ST_ESP_TFC_PADDING_NOT_SUPPORTED,
  													RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_ETHERIP_ENCAP,
  													RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_GRE_ENCAP,
  													RHP_PROTO_IKE_NOTIFY_RESERVED};

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
			  			rhp_ikev2_mesg_srch_cond_n_mesg_ids,csa_mesg_ids,
			  			_rhp_ikev2_create_child_sa_srch_childsa_n_info_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){

      RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_CHILDSA_N_PLD_ERR,"xxxE",vpn,ikesa,rx_req_ikemesg,err);
      goto error_rlm_l;
    }

    err = 0;
  }


  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_TS_I),
  			rhp_ikev2_create_child_sa_req_srch_ts_i_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK ){

  		RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_L_TS_I_ERR,"xxxE",vpn,ikesa,rx_req_ikemesg,err);

    	if( s_pld_ctx.notify_error ){
        goto notify_error;
    	}

  		err = RHP_STATUS_INVALID_MSG;
    	goto error_rlm_l;
    }

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_L_MATCHED_TS_I,"xxxxx",vpn,ikesa,rx_req_ikemesg,s_pld_ctx.ts_i_payload,s_pld_ctx.res_tss_i);

  	s_pld_ctx.res_tss_i->dump(s_pld_ctx.res_tss_i,"rhp_ikev2_rx_create_child_sa_r:ts_i");
  	err = 0;
  }


  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_TS_R),
  			rhp_ikev2_create_child_sa_req_srch_ts_r_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_L_TS_R_ERR,"xxxE",vpn,ikesa,rx_req_ikemesg,err);

    	if( s_pld_ctx.notify_error ){
        goto notify_error;
    	}

    	err = RHP_STATUS_INVALID_MSG;
    	goto error_rlm_l;
    }

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_L_MATCHED_TS_R,"xxxxx",vpn,ikesa,rx_req_ikemesg,s_pld_ctx.ts_r_payload,s_pld_ctx.res_tss_r);

  	s_pld_ctx.res_tss_r->dump(s_pld_ctx.res_tss_r,"rhp_ikev2_rx_create_child_sa_r:ts_r");
  	err = 0;
  }


  if( exchange_type == RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA ){

  	s_pld_ctx.dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  						rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_N_I_R),
  						rhp_ikev2_create_child_sa_srch_childsa_nir_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_L_NO_NIR_PLD_1,"xxxE",vpn,ikesa,rx_req_ikemesg,err);
    	err = RHP_STATUS_INVALID_MSG;

    	if( s_pld_ctx.notify_error ){
    		goto notify_error;
    	}

    	goto error_rlm_l;
    }


    if( rlm->childsa.pfs ){

    	s_pld_ctx.dup_flag = 0;

    	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
    						rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_KE),
    						rhp_ikev2_create_child_sa_srch_childsa_ke_cb,&s_pld_ctx);

      if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){

      	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_L_NO_KE_PLD_1,"xxxE",vpn,ikesa,rx_req_ikemesg,err);
      	err = RHP_STATUS_INVALID_MSG;

      	if( s_pld_ctx.notify_error ){
      		goto notify_error;
      	}

      	goto error_rlm_l;
      }
    }
  }


  //
  // Setup TSi/r for CP payload in TX Resp message.
  //
  {
  	unsigned int ts_extended_flag = 0;

  	// If the remote initiator peer requested CP_ADDR_IPv4/6 and it was not assigned
  	// in rhp_ikev2_cfg.c vpn->internal_net_info.peer_addr_v4_cp is still
  	// RHP_IKEV2_CFG_CP_ADDR_REQUESTED.
  	// (If it was successfully assigned, vpn->internal_net_info.peer_addr_v4_cp was set
  	// RHP_IKEV2_CFG_CP_ADDR_ASSIGNED.)
  	// So, unassigned address family's traffic selectors are purged here.

		if( vpn->internal_net_info.peer_addr_v4_cp == RHP_IKEV2_CFG_CP_ADDR_REQUESTED ){

			err = rhp_ikev2_create_child_sa_purge_af_tss(tx_resp_ikemesg,&s_pld_ctx,
							RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE,&ts_extended_flag);
			if( err ){
				RHP_BUG("%d",err);
				goto error_rlm_l;
			}
		}

		if( vpn->internal_net_info.peer_addr_v6_cp == RHP_IKEV2_CFG_CP_ADDR_REQUESTED &&
				!vpn->internal_net_info.peer_exec_ipv6_autoconf ){

			err = rhp_ikev2_create_child_sa_purge_af_tss(tx_resp_ikemesg,&s_pld_ctx,
							RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE,&ts_extended_flag);
			if( err ){
				RHP_BUG("%d",err);
				goto error_rlm_l;
			}
		}

		if( s_pld_ctx.res_tss_r == NULL || s_pld_ctx.res_tss_i == NULL ){
			RHP_BUG("");
			s_pld_ctx.notify_error = RHP_PROTO_IKE_NOTIFY_ERR_TS_UNACCEPTABLE;
			goto notify_error;
		}

		if( rhp_realm_cfg_svr_narrow_ts_i(rlm,vpn) ){

			err = rhp_ikev2_create_child_sa_mod_tss_cp(tx_resp_ikemesg,&s_pld_ctx,ts_extended_flag);

			if( s_pld_ctx.notify_error ){

				RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_TX_NTFY_ERR,"xxxxw",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,s_pld_ctx.notify_error);
				goto notify_error;
			}

			err = 0;

		}else{

			RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_NO_CP,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
		}

		if( vpn->internal_net_info.peer_exec_ipv6_autoconf ){

			err = rhp_ikev2_create_child_sa_add_v6_auto_ts(&s_pld_ctx,
							vpn->internal_net_info.ipv6_autoconf_narrow_ts_i);
			if( !err ){

				vpn->ts_extended_flag |= (RHP_VPN_TS_EXT_FLG_IPV6_ALLOW_AUTOCONFIG | ts_extended_flag);

			}else if( err && err != -ENOENT ){

				goto error_rlm_l;
			}
			err = 0;
		}
  }


  if( exchange_type == RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA ){

  	childsa = rhp_childsa_alloc2_r(&(s_pld_ctx.resolved_prop.v2),rlm);
		if( childsa == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error_rlm_l;
		}

	  childsa->gen_type = RHP_CHILDSA_GEN_CREATE_CHILD_SA;

	}else{ // IKE_SA_INIT

  	childsa = rhp_childsa_alloc(RHP_IKE_RESPONDER,0);

		if( childsa == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error_rlm_l;
		}

	  childsa->gen_type = RHP_CHILDSA_GEN_IKE_AUTH;

		childsa->parent_ikesa.side = ikesa->side;
		memcpy(childsa->parent_ikesa.init_spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
		memcpy(childsa->parent_ikesa.resp_spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);

		memcpy(&(childsa->prop.v2),&(s_pld_ctx.resolved_prop.v2),sizeof(rhp_res_sa_proposal));

		err = childsa->generate_inb_spi(childsa);
		if( err ){
			RHP_BUG("%d",err);
			goto error_rlm_l;
		}

		childsa->set_outb_spi(childsa,*((u32*)s_pld_ctx.resolved_prop.v2.spi));


	  // Setup security alg's params
	  err = _rhp_ikev2_rx_create_child_sa_req_sec_params(vpn,ikesa,childsa,rlm,exchange_type,&s_pld_ctx);
	  if( err ){
	    RHP_BUG("%d",err);
	    goto error_rlm_l;
	  }
  }


  childsa->timers = rhp_childsa_new_timers(childsa->spi_inb,childsa->spi_outb);
	if( childsa->timers == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error_rlm_l;
	}

	{
		int encap_mode_c;

		err = rhp_ikev2_rx_create_child_sa_req_encap_mode(vpn,rlm,&s_pld_ctx,&encap_mode_c);
		if( err ){

			RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_L_INVALID_ENCAP_MODE,"xxxxdbbb",vpn,ikesa,rx_req_ikemesg,rlm->encap_mode_c,s_pld_ctx.use_trans_port_mode,s_pld_ctx.use_etherip_encap,s_pld_ctx.use_gre_encap);

			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_CREATED_CHILDSA_RESPONDER_ENCAP_MODE_NOT_MATCHED,"KVC",rx_req_ikemesg,vpn,childsa);

			if( s_pld_ctx.notify_error ){
				goto notify_error;
			}

			goto error_rlm_l;
		}


		// Setup internal network
		err = rhp_ikev2_rx_create_child_sa_req_internal_net(vpn,childsa,rlm,&s_pld_ctx,encap_mode_c);
		if( err ){

			RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_L_ITNL_NET_ERR,"xxxxdbbb",vpn,ikesa,rx_req_ikemesg,rlm->encap_mode_c,s_pld_ctx.use_trans_port_mode,s_pld_ctx.use_etherip_encap,s_pld_ctx.use_gre_encap);

			goto error_rlm_l;
		}
	}


  err = childsa->set_traffic_selectors(childsa,s_pld_ctx.res_tss_r,s_pld_ctx.res_tss_i,vpn);
  if( err ){
    RHP_BUG("%d",err);
    goto error_rlm_l;
  }


  {
		childsa->esn = s_pld_ctx.resolved_prop.v2.esn;

		if( childsa->esn ){
			childsa->rx_anti_replay.rx_seq.esn.b = 1;
			childsa->rx_anti_replay.rx_seq.esn.t = 1;
		}else{
			childsa->rx_anti_replay.rx_seq.non_esn.last = 1;
		}
  }


	if( exchange_type == RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA ){

	  err = childsa->rekey_nonce_i->set_nonce(childsa->rekey_nonce_i,s_pld_ctx.nonce,s_pld_ctx.nonce_len);
	  if( err ){
	    RHP_BUG("%d",err);
	    goto error_rlm_l;
	  }

		err = childsa->setup_sec_params2(ikesa,childsa);

	}else{ // IKE_SA_INIT

		err = childsa->setup_sec_params(ikesa,childsa);
	}

	if( err ){
		RHP_BUG("%d",err);
		goto error_rlm_l;
	}


  if( s_pld_ctx.esp_tfc_padding_not_supported || !rlm->childsa.tfc_padding ){
  	childsa->tfc_padding = 0;
  }else{
  	childsa->tfc_padding = 1;
  }


  childsa->anti_replay = rlm->childsa.anti_replay;
  childsa->out_of_order_drop = rlm->childsa.out_of_order_drop;


  err = _rhp_ikev2_create_child_sa_new_pkt_rep(vpn,ikesa,&s_pld_ctx,childsa,
  		tx_resp_ikemesg,exchange_type,&(s_pld_ctx.resolved_prop.v2));

  if( err ){

		if( s_pld_ctx.notify_error ){
	  	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_L_NEW_PKT_REP_NTFY_ERR,"xxx",vpn,ikesa,rx_req_ikemesg);
	    goto notify_error;
		}

  	RHP_BUG("%d",err);
  	goto error_rlm_l;
  }


  {
		rhp_childsa_calc_pmtu(vpn,rlm,childsa);
		childsa->exec_pmtud = rlm->childsa.exec_pmtud;
  }


  rhp_childsa_set_state(childsa,RHP_CHILDSA_STAT_MATURE);
  vpn->created_childsas++;

  if( ikesa->state == RHP_IKESA_STAT_ESTABLISHED ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_L_SET_EXEC_AUTO_RECONNECT,"xxxx",vpn,ikesa,childsa,rx_req_ikemesg);
  	vpn->exec_auto_reconnect = 1;
  }


  {
		childsa->established_time = _rhp_get_time();
		childsa->expire_hard = childsa->established_time + (time_t)rlm->childsa.lifetime_hard;
		childsa->expire_soft = childsa->established_time + (time_t)rlm->childsa.lifetime_soft;

		childsa->timers->start_lifetime_timer(vpn,childsa,(time_t)rlm->childsa.lifetime_soft,1);
  }


  err = rhp_vpn_inb_childsa_put(vpn,childsa->spi_inb);
  if( err ){
    RHP_BUG("%d",err);
    goto error_rlm_l;
  }

  vpn->childsa_put(vpn,childsa);


  rhp_esp_add_childsa_to_impl(vpn,childsa);

  RHP_UNLOCK(&(rlm->lock));


  // Mark collision childsa.
  _rhp_ikev2_rx_create_child_sa_req_mark_collision_sa(vpn,childsa);


  if( (err = rhp_vpn_clear_unique_ids_tls_cache(vpn->vpn_realm_id)) ){
  	RHP_BUG("%d",err);
  }
  err = 0;


  if( s_pld_ctx.res_tss_i ){
    rhp_ikev2_ts_payload_free_tss(s_pld_ctx.res_tss_i);
  }
  if( s_pld_ctx.res_tss_r ){
    rhp_ikev2_ts_payload_free_tss(s_pld_ctx.res_tss_r);
  }


  if( vpn->nhrp.pend_resolution_req_q.head ){

  	rhp_nhrp_tx_queued_resolution_rep(vpn);
  }


	if( vpn->nhrp.dmvpn_shortcut &&
			vpn->vpn_conn_idle_timeout ){

		err = vpn->start_vpn_conn_idle_timer(vpn);
		if( err ){
			RHP_BUG("%d",err);
		}
		err = 0;
	}

	RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_CREATED_CHILDSA_RESPONDER,"KVC",rx_req_ikemesg,vpn,childsa);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_L_RTRN,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
  return 0;

notify_error:
  err = _rhp_ikev2_create_child_sa_new_pkt_error_notify_rep(tx_resp_ikemesg,ikesa,
  						RHP_PROTO_IKE_PROTOID_IKE,0,s_pld_ctx.notify_error,s_pld_ctx.notify_error_arg);

  if( err ){
  	RHP_BUG("%d",err);
  	goto error_rlm_l;
  }else{
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CREATE_CHILD_SA_REQ_TX_ERR_NOTIFY,"KVPL",rx_req_ikemesg,vpn,ikesa,"PROTO_IKE_NOTIFY",s_pld_ctx.notify_error);
  }

  err = RHP_STATUS_IKEV2_DESTROY_SA_AFTER_TX;

error_rlm_l:
	RHP_UNLOCK(&(rlm->lock));

  if( childsa ){
  	rhp_childsa_destroy(vpn,childsa);
  }

  if( s_pld_ctx.res_tss_i ){
    rhp_ikev2_ts_payload_free_tss(s_pld_ctx.res_tss_i);
  }
  if( s_pld_ctx.res_tss_r ){
    rhp_ikev2_ts_payload_free_tss(s_pld_ctx.res_tss_r);
  }

	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_CREATED_CHILDSA_RESPONDER_ERR,"KVEL",rx_req_ikemesg,vpn,err,"PROTO_IKE_NOTIFY",s_pld_ctx.notify_error);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_L_ERR,"xxxxLwE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err,"PROTO_IKE_NOTIFY",s_pld_ctx.notify_error);
  return err;
}

static void _rhp_childsa_cleanup_dup_childsa_handler(void *ctx)
{
  int err = -EINVAL;
  rhp_vpn_ref* vpn_ref = (rhp_vpn_ref*)ctx;
  rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);
  rhp_childsa* col_childsa = NULL;
  rhp_childsa *colsa0 = NULL,*colsa1 = NULL;
  rhp_ikesa* col_ikesa = NULL;
	rhp_ikesa *colikesa0 = NULL,*colikesa1 = NULL;

  RHP_TRC(0,RHPTRCID_CLEANUP_CHILDSA_DUP_CHILDSA_HANDLER,"x",vpn);

  RHP_LOCK(&(vpn->lock));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_CLEANUP_CHILDSA_DUP_CHILDSA_HANDLER_VPN_NOT_ACTIVE,"x",vpn);
    goto error;
  }

  col_childsa = vpn->childsa_list_head;
  while( col_childsa ){

  	if( col_childsa->collision_detected ){

  		u8* ikesa_my_spi;

  		if( col_childsa->state == RHP_CHILDSA_STAT_LARVAL ){
  			goto retry;
  		}else if( col_childsa->state != RHP_CHILDSA_STAT_MATURE ){
  			goto ignore;
  		}

  		if( col_childsa->parent_ikesa.side == RHP_IKE_INITIATOR ){
  			ikesa_my_spi = col_childsa->parent_ikesa.init_spi;
    	}else{
    		ikesa_my_spi = col_childsa->parent_ikesa.resp_spi;
    	}

  		col_ikesa = vpn->ikesa_get(vpn,col_childsa->parent_ikesa.side,ikesa_my_spi);
    	if( col_ikesa == NULL ){
    		RHP_BUG("");
  			goto error;
    	}

  		if( colsa0 == NULL ){
  			colsa0 = col_childsa;
  			colikesa0 = col_ikesa;
  		}else if( colsa1 == NULL ){
  			colsa1 = col_childsa;
  			colikesa1 = col_ikesa;
  		}

  		col_childsa->collision_detected = 0;
  	}

  	col_childsa = col_childsa->next_vpn_list;
  }

  if( colsa0 && colsa1 ){

  	rhp_crypto_nonce *col_nonce0 = NULL,*col_nonce1 = NULL;

  	if( rhp_crypto_nonce_cmp(colikesa0->nonce_i,colikesa0->nonce_r) <= 0 ){
  		col_nonce0 = colikesa0->nonce_i;
  	}else{
  		col_nonce0 = colikesa0->nonce_r;
  	}

  	if( rhp_crypto_nonce_cmp(colikesa1->nonce_i,colikesa1->nonce_r) <= 0 ){
  		col_nonce1 = colikesa1->nonce_i;
  	}else{
  		col_nonce1 = colikesa1->nonce_r;
  	}

  	if( rhp_crypto_nonce_cmp(col_nonce0,col_nonce1) <= 0 ){
  		col_childsa = colsa0;
  		col_ikesa = colikesa0;
  	}else{
  		col_childsa = colsa1;
  		col_ikesa = colikesa1;
  	}

  	if( col_ikesa->side != RHP_IKE_INITIATOR ){

  		// This collision SA is NOT initiated by this node. Peer node will sent Delete SA mesg soon!

  		rhp_ikesa* topikesa = NULL;
  		rhp_childsa* topsa = NULL;

  		if( colikesa0->side == RHP_IKE_INITIATOR ){
  			topsa = colsa0;
  			topikesa = colikesa0;
  		}else if( colikesa1->side == RHP_IKE_INITIATOR ){
  			topsa = colsa1;
  			topikesa = colikesa1;
  		}

  		if( topikesa ){
  			vpn->ikesa_move_to_top(vpn,topikesa);
  		}

  		if( topsa ){
  			vpn->childsa_move_to_top(vpn,topsa);
  		}

  	  RHP_TRC(0,RHPTRCID_CLEANUP_CHILDSA_DUP_CHILDSA_HANDLER_NOT_INITIATOR_IGNORED,"xxxxx",vpn,col_childsa,colsa0,colsa1,topsa);
  		goto ignore;
  	}

	  RHP_TRC(0,RHPTRCID_CLEANUP_CHILDSA_DUP_CHILDSA_HANDLER_DELETED_SA,"xxxx",vpn,col_childsa,colsa0,colsa1);

	  col_childsa->delete_ikesa_too = 1;
  	col_childsa->timers->schedule_delete(vpn,col_childsa,0);

  	if( (err = rhp_vpn_clear_unique_ids_tls_cache(vpn->vpn_realm_id)) ){
  		RHP_BUG("%d",err);
  	}

  	err = 0;
  }

ignore:
  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

  RHP_TRC(0,RHPTRCID_CLEANUP_CHILDSA_DUP_CHILDSA_HANDLER_RTRN,"x",vpn);
  return;

error:
  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

  RHP_TRC(0,RHPTRCID_CLEANUP_CHILDSA_DUP_CHILDSA_HANDLER_ERR,"xE",vpn,err);
  return;

retry:
	rhp_timer_oneshot(_rhp_childsa_cleanup_dup_childsa_handler,rhp_vpn_hold_ref(vpn),RHP_CFG_CLEANUP_DUP_SA_MARGIN);

  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

  RHP_TRC(0,RHPTRCID_CLEANUP_CHILDSA_DUP_CHILDSA_HANDLER_RETRY,"x",vpn);
	return;
}

void rhp_childsa_cleanup_dup_childsa_handler2(void *ctx)
{
  int err = -EINVAL;
  rhp_vpn_ref* vpn_ref = (rhp_vpn_ref*)ctx;
  rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);
  rhp_childsa* col_childsa = NULL;
  rhp_childsa *colsa0 = NULL,*colsa1 = NULL;

  RHP_TRC(0,RHPTRCID_CREATE_CHILD_SA_CLEANUP_DUP_CHILDSA_HANDLER,"x",vpn);

  RHP_LOCK(&(vpn->lock));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_CREATE_CHILD_SA_CLEANUP_DUP_CHILDSA_HANDLER_VPN_NOT_ACTIVE,"x",vpn);
    goto error;
  }

  col_childsa = vpn->childsa_list_head;
  while( col_childsa ){

  	if( col_childsa->collision_detected ){

  		if( col_childsa->state == RHP_CHILDSA_STAT_LARVAL ){
  			goto retry;
  		}else if( col_childsa->state != RHP_CHILDSA_STAT_MATURE ){
  			goto ignore;
  		}

  		if( colsa0 == NULL ){
  			colsa0 = col_childsa;
  		}else if( colsa1 == NULL ){
  			colsa1 = col_childsa;
  		}

  		col_childsa->collision_detected = 0;
  	}

  	col_childsa = col_childsa->next_vpn_list;
  }

  if( colsa0 && colsa1 ){

  	rhp_crypto_nonce *col_nonce0 = NULL,*col_nonce1 = NULL;

  	if( rhp_crypto_nonce_cmp(colsa0->rekey_nonce_i,colsa0->rekey_nonce_r) <= 0 ){
  		col_nonce0 = colsa0->rekey_nonce_i;
  	}else{
  		col_nonce0 = colsa0->rekey_nonce_r;
  	}

  	if( rhp_crypto_nonce_cmp(colsa1->rekey_nonce_i,colsa1->rekey_nonce_r) <= 0 ){
  		col_nonce1 = colsa1->rekey_nonce_i;
  	}else{
  		col_nonce1 = colsa1->rekey_nonce_r;
  	}

  	if( rhp_crypto_nonce_cmp(col_nonce0,col_nonce1) <= 0 ){
  		col_childsa = colsa0;
  	}else{
  		col_childsa = colsa1;
  	}

  	if( col_childsa->side != RHP_IKE_INITIATOR ){

  		// This collision SA is NOT initiated by this node. Peer node will sent Delete SA mesg soon!

  		rhp_childsa* topsa = NULL;

  		if( colsa0->side == RHP_IKE_INITIATOR ){
  			topsa = colsa0;
  		}else if( colsa1->side == RHP_IKE_INITIATOR ){
  			topsa = colsa1;
  		}

  		if( topsa ){
  			vpn->childsa_move_to_top(vpn,topsa);
  		}

  	  RHP_TRC(0,RHPTRCID_CREATE_CHILD_SA_CLEANUP_DUP_CHILDSA_HANDLER_NOT_INITIATOR_IGNORED,"xxxxx",vpn,col_childsa,colsa0,colsa1,topsa);
  		goto ignore;
  	}

	  RHP_TRC(0,RHPTRCID_CREATE_CHILD_SA_CLEANUP_DUP_CHILDSA_HANDLER_DELETED_SA,"xxxx",vpn,col_childsa,colsa0,colsa1);

  	col_childsa->timers->schedule_delete(vpn,col_childsa,0);

  	if( (err = rhp_vpn_clear_unique_ids_tls_cache(vpn->vpn_realm_id)) ){
  		RHP_BUG("%d",err);
  	}

  	err = 0;
  }

ignore:
  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

  RHP_TRC(0,RHPTRCID_CREATE_CHILD_SA_CLEANUP_DUP_CHILDSA_HANDLER_RTRN,"x",vpn);
  return;

error:
  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

  RHP_TRC(0,RHPTRCID_CREATE_CHILD_SA_CLEANUP_DUP_CHILDSA_HANDLER_ERR,"xE",vpn,err);
  return;

retry:
	rhp_timer_oneshot(rhp_childsa_cleanup_dup_childsa_handler2,rhp_vpn_hold_ref(vpn),RHP_CFG_CLEANUP_DUP_SA_MARGIN);

  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

  RHP_TRC(0,RHPTRCID_CREATE_CHILD_SA_CLEANUP_DUP_CHILDSA_HANDLER_RETRY,"x",vpn);
	return;
}


int rhp_childsa_detect_exchg_collision(rhp_vpn* vpn)
{
	int err = 0;
  rhp_childsa *col_childsa = NULL;

  RHP_TRC(0,RHPTRCID_CHILDSA_EXCHG_COLLISION,"x",vpn);

  col_childsa = vpn->childsa_list_head;
  while( col_childsa ){

  	if( col_childsa->collision_detected ){
    	err = RHP_STATUS_CHILDSA_COLLISION;
    	break;
  	}

  	col_childsa = col_childsa->next_vpn_list;
  }

	RHP_TRC(0,RHPTRCID_CHILDSA_EXCHG_COLLISION_RTRN,"xxE",vpn,col_childsa,err);
	return err;
}


static int _rhp_ikev2_rx_create_child_sa_rep_sec_params(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_childsa* childsa,
		rhp_vpn_realm* rlm,u8 exchange_type,rhp_childsa_srch_plds_ctx* s_pld_ctx)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILDSA_REP_SEC_PARAMS,"xxxxbxd",vpn,ikesa,childsa,rlm,exchange_type,s_pld_ctx,s_pld_ctx->resolved_prop.v2.esn);


  childsa->integ_inb = rhp_crypto_integ_alloc(s_pld_ctx->resolved_prop.v2.integ_id);
  if( childsa->integ_inb == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  childsa->integ_outb = rhp_crypto_integ_alloc(s_pld_ctx->resolved_prop.v2.integ_id);
  if( childsa->integ_outb == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  childsa->encr = rhp_crypto_encr_alloc(s_pld_ctx->resolved_prop.v2.encr_id,
  									s_pld_ctx->resolved_prop.v2.encr_key_bits);
  if( childsa->encr == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  childsa->rx_anti_replay.window_mask = rhp_crypto_bn_alloc(rlm->childsa.anti_replay_win_size);
  if( childsa->rx_anti_replay.window_mask == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }


  childsa->esn = s_pld_ctx->resolved_prop.v2.esn;

  if( childsa->esn ){
  	childsa->rx_anti_replay.rx_seq.esn.b = 1;
  	childsa->rx_anti_replay.rx_seq.esn.t = 1;
  }else{
  	childsa->rx_anti_replay.rx_seq.non_esn.last = 1;
  }


  if( exchange_type == RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA ){

  	childsa->rekey_nonce_r = rhp_crypto_nonce_alloc();
		if( childsa->rekey_nonce_r == NULL ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

	  err = childsa->rekey_nonce_r->set_nonce(childsa->rekey_nonce_r,s_pld_ctx->nonce,s_pld_ctx->nonce_len);
	  if( err ){
	  	RHP_BUG("%d",err);
	  	goto error;
	  }

		if( rlm->childsa.pfs ){

			err = childsa->rekey_nonce_r->set_nonce(childsa->rekey_nonce_r,s_pld_ctx->nonce,s_pld_ctx->nonce_len);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			err = childsa->rekey_dh->set_peer_pub_key(childsa->rekey_dh,s_pld_ctx->peer_dh_pub_key,s_pld_ctx->peer_dh_pub_key_len);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			err = childsa->rekey_dh->compute_key(childsa->rekey_dh);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}
		}

	  err = childsa->setup_sec_params2(ikesa,childsa);
	  if( err ){
	  	RHP_BUG("%d",err);
	  	goto error;
	  }

  }else{


		err = childsa->setup_sec_params(ikesa,childsa);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
  }

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILDSA_REP_SEC_PARAMS_RTRN,"xxx",vpn,ikesa,childsa);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILDSA_REP_SEC_PARAMS_ERR,"xxxE",vpn,ikesa,childsa,err);
	return err;
}

int rhp_ikev2_rx_create_child_sa_rep_encap_mode(rhp_vpn* vpn,rhp_vpn_realm* rlm,
		rhp_childsa_srch_plds_ctx* s_pld_ctx,int* encap_mode_c_r)
{
	int encap_mode_c;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_ENCAP_MODE,"xxxxdddd",vpn,rlm,s_pld_ctx,rlm->encap_mode_c,s_pld_ctx->use_trans_port_mode,s_pld_ctx->use_etherip_encap,s_pld_ctx->use_gre_encap,vpn->peer_is_rockhopper);

	if( rlm->encap_mode_c == RHP_VPN_ENCAP_GRE ){

		if( !s_pld_ctx->use_trans_port_mode || s_pld_ctx->use_etherip_encap ){
			goto error;
		}

  	encap_mode_c = RHP_VPN_ENCAP_GRE;

	}else if( (rlm->encap_mode_c & RHP_VPN_ENCAP_ETHERIP) &&
  					s_pld_ctx->use_trans_port_mode && s_pld_ctx->use_etherip_encap ){

  	encap_mode_c = RHP_VPN_ENCAP_ETHERIP;

  }else if( (rlm->encap_mode_c & RHP_VPN_ENCAP_GRE) &&
  					s_pld_ctx->use_trans_port_mode && s_pld_ctx->use_gre_encap ){

  	encap_mode_c = RHP_VPN_ENCAP_GRE;

  }else if( (rlm->encap_mode_c & RHP_VPN_ENCAP_GRE) &&
  					s_pld_ctx->use_trans_port_mode && !vpn->peer_is_rockhopper ){

  	// For inter-op...Ugly!

  	encap_mode_c = RHP_VPN_ENCAP_GRE;

  }else if( rlm->encap_mode_c & RHP_VPN_ENCAP_IPIP ){

  	if( s_pld_ctx->use_trans_port_mode ){
			goto error;
  	}

  	encap_mode_c = RHP_VPN_ENCAP_IPIP;

  }else{

		goto error;
  }

	*encap_mode_c_r = encap_mode_c;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_ENCAP_MODE_RTRN,"xxxLd",vpn,rlm,s_pld_ctx,"VPN_ENCAP",encap_mode_c);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_ENCAP_MODE_ERR,"xxx",vpn,rlm,s_pld_ctx);
	return RHP_STATUS_NO_PROPOSAL_CHOSEN;
}

int rhp_ikev2_rx_create_child_sa_rep_internal_net(rhp_vpn* vpn, rhp_vpn_realm* rlm,
		rhp_childsa* childsa,rhp_childsa_srch_plds_ctx* s_pld_ctx)
{
	int err = -EINVAL;
  int encap_mode_c = RHP_VPN_ENCAP_ETHERIP;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_INTERNAL_NET,"xxxxbbbxbdM",vpn,childsa,rlm,s_pld_ctx,s_pld_ctx->use_etherip_encap,s_pld_ctx->use_gre_encap,s_pld_ctx->use_trans_port_mode,rlm->encap_mode_c,vpn->peer_is_remote_client,rlm->config_server.disable_non_ip,vpn->internal_net_info.exchg_peer_mac);

	err = rhp_ikev2_rx_create_child_sa_rep_encap_mode(vpn,rlm,s_pld_ctx,&encap_mode_c);
	if( err ){
		RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_L_INVALID_ENCAP_MODE,"xxdbbb",vpn,childsa,rlm->encap_mode_c,s_pld_ctx->use_trans_port_mode,s_pld_ctx->use_etherip_encap,s_pld_ctx->use_gre_encap);
		goto error;
	}


	vpn->internal_net_info.encap_mode_c = encap_mode_c;

	if( encap_mode_c == RHP_VPN_ENCAP_ETHERIP ){

		u8* peer_mac;

		childsa->ipsec_mode = RHP_CHILDSA_MODE_TRANSPORT;

		peer_mac = vpn->internal_net_info.exchg_peer_mac;

		if( !_rhp_mac_addr_null(peer_mac) && vpn->internal_net_info.peer_addrs ){

			err = rhp_bridge_static_cache_reset_for_vpn(vpn->vpn_realm_id,vpn,
							peer_mac,vpn->internal_net_info.peer_addrs,
							RHP_BRIDGE_SCACHE_IKEV2_EXCHG);

			if( err ){
				RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_L_BRDG_CACHE_ETHER_IP_ERR,"xx",vpn,childsa);
			}
		}
		err = 0;

		if( rlm->internal_ifc->ifc ){

			rhp_ifc_entry* v_ifc = rlm->internal_ifc->ifc;

			RHP_LOCK(&(v_ifc->lock));
			{

				v_ifc->ipip_dummy_mac_flag = 0;

				RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_L_CLEAR_IPIP_DMY_MAC,"xxdM",vpn,childsa,v_ifc->ipip_dummy_mac_flag,v_ifc->ipip_dummy_mac);
			}
			RHP_UNLOCK(&(v_ifc->lock));
		}

	}else{ // RHP_VPN_ENCAP_IPIP / GRE

		if( encap_mode_c == RHP_VPN_ENCAP_GRE ){
			childsa->ipsec_mode = RHP_CHILDSA_MODE_TRANSPORT;
		}else{
			childsa->ipsec_mode = RHP_CHILDSA_MODE_TUNNEL;
		}

		if( vpn->internal_net_info.peer_addrs ){

			err = rhp_bridge_static_cache_reset_for_vpn(vpn->vpn_realm_id,vpn,
							vpn->internal_net_info.dummy_peer_mac,vpn->internal_net_info.peer_addrs,
							RHP_BRIDGE_SCACHE_DUMMY);

			if( err ){
				RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_L_BRDG_CACHE_IPIP_ERR,"xx",vpn,childsa);
			}
		}
		err = 0;

		if( !rlm->is_access_point && rlm->internal_ifc->ifc ){

			rhp_ifc_entry* v_ifc = rlm->internal_ifc->ifc;

			RHP_LOCK(&(v_ifc->lock));
			{
				if( rlm->internal_ifc->addrs_type != RHP_VIF_ADDR_NONE ){ // NOT Bridged!

					//
					// Only for a remote client (an End Node).
					//

					v_ifc->ipip_dummy_mac_flag = 1;
					memcpy(v_ifc->ipip_dummy_mac,vpn->internal_net_info.dummy_peer_mac,6);

					RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_L_SET_IPIP_DMY_MAC,"xxdM",vpn,childsa,v_ifc->ipip_dummy_mac_flag,v_ifc->ipip_dummy_mac);

				}else{

					v_ifc->ipip_dummy_mac_flag = 0;

					RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_L_CLEAR_IPIP_DMY_MAC_2,"xxdM",vpn,childsa,v_ifc->ipip_dummy_mac_flag,v_ifc->ipip_dummy_mac);
				}
			}
			RHP_UNLOCK(&(v_ifc->lock));
		}
	}

	rhp_bridge_cache_flush_by_vpn(vpn);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_INTERNAL_NET_RTRN,"xxxxLdLdx",vpn,childsa,rlm,s_pld_ctx,"VPN_ENCAP",vpn->internal_net_info.encap_mode_c,"CHILDSA_MODE",childsa->ipsec_mode,vpn->internal_net_info.peer_addrs);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_INTERNAL_NET_ERR,"xxxxLdLdLwxE",vpn,childsa,rlm,s_pld_ctx,"VPN_ENCAP",encap_mode_c,"CHILDSA_MODE",childsa->ipsec_mode,"PROTO_IKE_NOTIFY",s_pld_ctx->notify_error,vpn->internal_net_info.peer_addrs,err);
	return -EINVAL;
}


int rhp_ikev2_rx_create_child_sa_rep_delete_ikesa(rhp_vpn* vpn,rhp_ikesa* ikesa)
{
  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_CHILDSA_DELETE_IKESA,"xxdd",vpn,ikesa,rhp_gcfg_ikev2_max_create_child_sa_failure,vpn->create_child_sa_failed);

  if( rhp_gcfg_ikev2_max_create_child_sa_failure &&
  		vpn->create_child_sa_failed > rhp_gcfg_ikev2_max_create_child_sa_failure ){

  	ikesa->timers->schedule_delete(vpn,ikesa,0);
  }
  return 0;
}

static int _rhp_ikev2_rx_create_child_sa_rep(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ikev2_mesg* tx_req_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_childsa* childsa = NULL;
  rhp_vpn_realm* rlm = NULL;
  rhp_childsa_srch_plds_ctx s_pld_ctx;
  int immediately_delete = 0;
  int exchg_col = 0;
	u8 exchange_type = rx_resp_ikemesg->get_exchange_type(rx_resp_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_L,"xxxxxxLb",vpn,ikesa,rx_resp_ikemesg,rx_resp_ikemesg->rx_pkt,tx_req_ikemesg,vpn->rlm,"PROTO_IKE_EXCHG",exchange_type);


	childsa = vpn->childsa_list_head;
	while( childsa ){

		if( childsa->parent_ikesa.side == ikesa->side &&
				!memcmp(childsa->parent_ikesa.init_spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE) &&
				!memcmp(childsa->parent_ikesa.resp_spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE) ){

			if( (childsa->gen_message_id == rx_resp_ikemesg->get_mesg_id(rx_resp_ikemesg)) ||
					(vpn->eap.role == RHP_EAP_SUPPLICANT && exchange_type == RHP_PROTO_IKE_EXCHG_IKE_AUTH) ){

				break;
			}
		}

		childsa = childsa->next_vpn_list;
	}

	if( childsa == NULL ){
		RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_I_CHILDSA_NOT_FOUND,"xxx",vpn,ikesa,rx_resp_ikemesg);
		err = 0; // Maybe now rekeying...
		goto error;
	}


	if( exchange_type == RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA	){

		if( childsa->gen_type != RHP_CHILDSA_GEN_CREATE_CHILD_SA ){ // For Rekey Exchange.
			RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_I_NOT_INTERESTED_GEN_TYPE,"xxxxd",vpn,ikesa,rx_resp_ikemesg,childsa,childsa->gen_type);
			err = 0;
			goto ignore;
		}

	}else{

		if( childsa->gen_type != RHP_CHILDSA_GEN_IKE_AUTH ){
			RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_I_BAD_GEN_TYPE_2,"xxxxd",vpn,ikesa,rx_resp_ikemesg,childsa,childsa->gen_type);
			err = RHP_STATUS_INVALID_MSG;
			goto error;
		}
	}


  if( childsa->state != RHP_CHILDSA_STAT_LARVAL ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_I_CHILDSA_BAD_CHILDSA_STATE,"xxxxd",vpn,ikesa,rx_resp_ikemesg,childsa,childsa->state);
    err = RHP_STATUS_INVALID_MSG;
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
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_L_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,rx_resp_ikemesg,vpn->rlm);
  	goto error_rlm_l;
  }

  if( rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error_rlm_l;
  }


  memset(&s_pld_ctx,0,sizeof(rhp_childsa_srch_plds_ctx));

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;
  s_pld_ctx.rlm = rlm;

  {
  	s_pld_ctx.dup_flag = 0;

    memset(&(s_pld_ctx.resolved_prop.v2),0,sizeof(rhp_res_sa_proposal));

    if( exchange_type == RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA ){
    	s_pld_ctx.resolved_prop.v2.pfs = rlm->childsa.pfs;
    }

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_SA),
    		rhp_ikev2_create_child_sa_srch_sa_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK ){

     RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_L_SA_PLD_ERR,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
     err = RHP_STATUS_INVALID_MSG;
    	goto error_rlm_l;
  	}

    RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_L_MATCHED_PROP,"xxxxbbbpwdwwwwd",vpn,ikesa,rx_resp_ikemesg,s_pld_ctx.sa_payload,s_pld_ctx.resolved_prop.v2.number,s_pld_ctx.resolved_prop.v2.protocol_id,s_pld_ctx.resolved_prop.v2.spi_len,RHP_PROTO_SPI_MAX_SIZE,s_pld_ctx.resolved_prop.v2.spi,s_pld_ctx.resolved_prop.v2.encr_id,s_pld_ctx.resolved_prop.v2.encr_key_bits,s_pld_ctx.resolved_prop.v2.prf_id,s_pld_ctx.resolved_prop.v2.integ_id,s_pld_ctx.resolved_prop.v2.dhgrp_id,s_pld_ctx.resolved_prop.v2.esn,s_pld_ctx.resolved_prop.v2.pfs);
  }


  if( exchange_type == RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA ){

		{
			s_pld_ctx.dup_flag = 0;

			err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
					rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_N_I_R),
					rhp_ikev2_create_child_sa_srch_childsa_nir_cb,&s_pld_ctx);

			if( err && err != RHP_STATUS_ENUM_OK ){
				RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_L_NO_NIR_PLD_1,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
				err = RHP_STATUS_INVALID_MSG;
				goto error_rlm_l;
			}
		}

		if( rlm->childsa.pfs ){

			s_pld_ctx.dup_flag = 0;

			err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
							rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_KE),
							rhp_ikev2_create_child_sa_srch_childsa_ke_cb,&s_pld_ctx);

			if( err && err != RHP_STATUS_ENUM_OK ){
				RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_L_NO_KE_PLD_1,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
				err = RHP_STATUS_INVALID_MSG;
				goto error_rlm_l;
			}
		}
  }


  {
  	s_pld_ctx.dup_flag = 0;
  	u16 csa_mesg_ids[5] = {	RHP_PROTO_IKE_NOTIFY_ST_USE_TRANSPORT_MODE,
  													RHP_PROTO_IKE_NOTIFY_ST_ESP_TFC_PADDING_NOT_SUPPORTED,
  													RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_ETHERIP_ENCAP,
  													RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_GRE_ENCAP,
  													RHP_PROTO_IKE_NOTIFY_RESERVED};

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
			  			rhp_ikev2_mesg_srch_cond_n_mesg_ids,csa_mesg_ids,
			  			_rhp_ikev2_create_child_sa_srch_childsa_n_info_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_CHILDSA_N_PLD_ERR,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
      goto error_rlm_l;
    }
  }


  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_TS_I),
  			rhp_ikev2_create_child_sa_rep_srch_ts_i_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK ){
  		RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_L_TS_I_ERR,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
  		err = RHP_STATUS_INVALID_MSG;
    	goto error_rlm_l;
    }

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_L_MATCHED_TS_I,"xxxxx",vpn,ikesa,rx_resp_ikemesg,s_pld_ctx.ts_i_payload,s_pld_ctx.res_tss_i);
    rhp_cfg_traffic_selectors_dump("rhp_ikev2_rx_create_child_sa_r.ts_i",NULL,s_pld_ctx.res_tss_i);
  }


  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_TS_R),
  			rhp_ikev2_create_child_sa_rep_srch_ts_r_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
  		RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_L_TS_R_ERR,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
  		err = RHP_STATUS_INVALID_MSG;
    	goto error_rlm_l;
    }

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_L_MATCHED_TS_R,"xxxxx",vpn,ikesa,rx_resp_ikemesg,s_pld_ctx.ts_r_payload,s_pld_ctx.res_tss_r);
    rhp_cfg_traffic_selectors_dump("rhp_ikev2_rx_create_child_sa_r.ts_r",NULL,s_pld_ctx.res_tss_r);
  }


  childsa->timers->quit_lifetime_timer(vpn,childsa);

  err = rhp_childsa_detect_exchg_collision(vpn);
  if( err == RHP_STATUS_CHILDSA_COLLISION ){
  	err = 0;
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_I_COL_OCCURED,"xxxx",vpn,ikesa,rx_resp_ikemesg,childsa);
    exchg_col = 1;
  }else if( err ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_I_COL_CHECK_ERR,"xxxxE",vpn,ikesa,rx_resp_ikemesg,childsa,err);
  	goto error_rlm_l;
  }


  memcpy(&(childsa->prop.v2),&(s_pld_ctx.resolved_prop.v2),sizeof(rhp_res_sa_proposal));

  childsa->set_outb_spi(childsa,*((u32*)s_pld_ctx.resolved_prop.v2.spi));
  childsa->timers->spi_outb = childsa->spi_outb;



	// Setup internal network
  err = rhp_ikev2_rx_create_child_sa_rep_internal_net(vpn,rlm,childsa,&s_pld_ctx);
  if( err ){
  	immediately_delete = 1;
  	err = 0;
  }


  err = childsa->set_traffic_selectors(childsa,s_pld_ctx.res_tss_i,s_pld_ctx.res_tss_r,vpn);
  if( err ){
    RHP_BUG("");
    goto error_rlm_l;
  }


  // Setup security alg's params
  err = _rhp_ikev2_rx_create_child_sa_rep_sec_params(vpn,ikesa,childsa,rlm,exchange_type,&s_pld_ctx);
  if( err ){
    RHP_BUG("");
    goto error_rlm_l;
  }


  if( s_pld_ctx.esp_tfc_padding_not_supported || !rlm->childsa.tfc_padding ){
  	childsa->tfc_padding = 0;
  }else{
  	childsa->tfc_padding = 1;
  }


  childsa->anti_replay = rlm->childsa.anti_replay;
  childsa->out_of_order_drop = rlm->childsa.out_of_order_drop;


  {
		rhp_childsa_calc_pmtu(vpn,rlm,childsa);
		childsa->exec_pmtud = rlm->childsa.exec_pmtud;
  }


  rhp_childsa_set_state(childsa,RHP_CHILDSA_STAT_MATURE);
  vpn->created_childsas++;

  if( ikesa->state == RHP_IKESA_STAT_ESTABLISHED ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_L_SET_EXEC_AUTO_RECONNECT,"xxxx",vpn,ikesa,childsa,rx_resp_ikemesg);
  	vpn->exec_auto_reconnect = 1;
  }


  childsa->established_time = _rhp_get_time();
	childsa->expire_hard = childsa->established_time + (time_t)rlm->childsa.lifetime_hard;
	childsa->expire_soft = childsa->established_time + (time_t)rlm->childsa.lifetime_soft;

  childsa->timers->start_lifetime_timer(vpn,childsa,(time_t)rlm->childsa.lifetime_soft,1);


  rhp_esp_add_childsa_to_impl(vpn,childsa);

  RHP_UNLOCK(&(rlm->lock));



  if( exchg_col ){

  	rhp_vpn_ref* vpn_ref = rhp_vpn_hold_ref(vpn);

    if( exchange_type == RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA ){

  		rhp_timer_oneshot(rhp_childsa_cleanup_dup_childsa_handler2,vpn_ref,RHP_CFG_CLEANUP_DUP_SA_MARGIN);

    }else{

    	rhp_timer_oneshot(_rhp_childsa_cleanup_dup_childsa_handler,vpn_ref,RHP_CFG_CLEANUP_DUP_SA_MARGIN);
  	}

  }else{

  	//
  	// In other cases duplicate or old IKE SA(s) and Child SA(s) were deleted by INITIAL_CONTACT notification.
  	//

  	vpn->ikesa_move_to_top(vpn,ikesa);
  	vpn->childsa_move_to_top(vpn,childsa);
  }


  if( (err = rhp_vpn_clear_unique_ids_tls_cache(vpn->vpn_realm_id)) ){
  	RHP_BUG("%d",err);
  }
  err = 0;

  //
  // Don't free s_pld_ctx.res_tss_i and s_pld_ctx.res_tss_r here! These are linked to ts_payload.
  //

  if( immediately_delete ){

  	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_CREATED_CHILDSA_INITIATOR_ERR2,"KVC",rx_resp_ikemesg,vpn,childsa);

  	childsa->timers->schedule_delete(vpn,childsa,0);
    vpn->create_child_sa_failed++;

    rhp_ikev2_rx_create_child_sa_rep_delete_ikesa(vpn,ikesa);

  }else{

    vpn->create_child_sa_failed = 0;

  	RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_CREATED_CHILDSA_INITIATOR,"KVC",rx_resp_ikemesg,vpn,childsa);


		if( vpn->nhrp.role == RHP_NHRP_SERVICE_CLIENT &&
				vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_GRE &&
				!vpn->nhrp.dmvpn_shortcut ){

			err = vpn->start_nhc_registration_timer(vpn,(time_t)rhp_gcfg_nhrp_registration_req_tx_margin_time);
			if( err ){
				RHP_BUG("%d",err);
			}
			err = 0;
		}


		if( vpn->nhrp.pend_resolution_req_q.head ){

			rhp_nhrp_tx_queued_resolution_rep(vpn);
		}


		if( vpn->nhrp.dmvpn_shortcut &&
				vpn->vpn_conn_idle_timeout ){

			err = vpn->start_vpn_conn_idle_timer(vpn);
			if( err ){
				RHP_BUG("%d",err);
			}
			err = 0;
		}
  }

ignore:
  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_L_RTRN,"xxxd",vpn,ikesa,rx_resp_ikemesg,immediately_delete);
  return 0;

error_rlm_l:
	RHP_UNLOCK(&(rlm->lock));

error:
  if( childsa ){

  	childsa->timers->schedule_delete(vpn,childsa,0);

  	vpn->create_child_sa_failed++;
  }


  rhp_ikev2_rx_create_child_sa_rep_delete_ikesa(vpn,ikesa);


  //
  // Don't free s_pld_ctx.res_tss_i and s_pld_ctx.res_tss_r here! These are linked to ts_payload.
  //

	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_CREATED_CHILDSA_INITIATOR_ERR,"KVE",rx_resp_ikemesg,vpn,err);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_L_ERR,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
  return err;
}

int rhp_ikev2_rx_create_child_sa_req(rhp_ikev2_mesg* rx_req_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_req_ikemesg->get_exchange_type(rx_req_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ,"xxLdGxLb",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_resp_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

	if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_AUTH ){

		if( !RHP_PROTO_IKE_HDR_INITIATOR(rx_req_ikemesg->rx_pkt->app.ikeh->flag) ){
			err = RHP_STATUS_INVALID_MSG;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_INVALID_MESG1,"xx",rx_req_ikemesg,vpn);
			goto error;
	  }

	}else if( exchange_type == RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA ){

		if( rx_req_ikemesg->for_rekey_req ){
		  err = 0;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_IS_REKEY_EXCHG,"xx",rx_req_ikemesg,vpn);
		  goto error;
		}

	}else{
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_EXCHG_TYPE_NOT_INTERESTED,"xx",rx_req_ikemesg,vpn);
		return 0;
	}

  if( !rx_req_ikemesg->decrypted ){
  	err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_NOT_DECRYPTED,"xx",rx_req_ikemesg,vpn);
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
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_NO_IKESA,"xxLdG",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
		goto error;
	}

	if( ikesa->state != RHP_IKESA_STAT_ESTABLISHED && ikesa->state != RHP_IKESA_STAT_REKEYING ){
		err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_IKESA_STATE_NOT_INTERESTED,"xxLdGLd",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state);
		goto error;
	}

  err = _rhp_ikev2_rx_create_child_sa_req(vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REQ_RTRN,"xxxE",rx_req_ikemesg,vpn,tx_resp_ikemesg,err);
  return err;
}

int rhp_ikev2_rx_create_child_sa_rep(rhp_ikev2_mesg* rx_resp_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_resp_ikemesg->get_exchange_type(rx_resp_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP,"xxLdGxLb",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_req_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

	if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ||
			exchange_type == RHP_PROTO_IKE_EXCHG_SESS_RESUME ){

		if( RHP_PROTO_IKE_HDR_INITIATOR(rx_resp_ikemesg->rx_pkt->app.ikeh->flag) ){
			err = RHP_STATUS_INVALID_MSG;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_INVALID_MESG_1,"xx",rx_resp_ikemesg,vpn);
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
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_NO_IKESA1,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}

		if( ikesa->state != RHP_IKESA_STAT_I_AUTH_SENT ){
			err = 0;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_NOT_INTERESTED_1,"xxLdGLd",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state);
			goto error;
		}

		err = _rhp_ikev2_create_child_sa_req(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);


	}else if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_AUTH ||
						exchange_type == RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA ){

	  if( !rx_resp_ikemesg->decrypted ){
	  	err = 0;
			RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_NOT_DECRYPTED,"xx",rx_resp_ikemesg,vpn);
	  	goto error;
	  }

		if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_AUTH ){

			if( RHP_PROTO_IKE_HDR_INITIATOR(rx_resp_ikemesg->rx_pkt->app.ikeh->flag) ){
				err = RHP_STATUS_INVALID_MSG;
				RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_INVALID_MESG_2,"xx",rx_resp_ikemesg,vpn);
				goto error;
			}

		}else if( exchange_type == RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA ){

			if( rx_resp_ikemesg->for_rekey_req ){
			  err = 0;
			  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_IS_REKEY_EXCHG,"xx",rx_resp_ikemesg,vpn);
			  goto error;
			}
		}

		if( my_ikesa_spi == NULL ){
	    RHP_BUG("");
	    err = -EINVAL;
	    goto error;
	  }

		ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
		if( ikesa == NULL ){
			err = -ENOENT;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_NO_IKESA_2,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}

		if( ikesa->state != RHP_IKESA_STAT_ESTABLISHED && ikesa->state != RHP_IKESA_STAT_REKEYING ){
			err = 0;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_BAD_IKESA_STAT_2,"xxLdGLd",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state);
			goto error;
		}

	  err = _rhp_ikev2_rx_create_child_sa_rep(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);

	}else{

		err = 0;
		RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_NOT_INTERESTED_2,"xxx",rx_resp_ikemesg,vpn,tx_req_ikemesg);
	}

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_CREATE_CHILD_SA_REP_RTRN,"xxxE",rx_resp_ikemesg,vpn,tx_req_ikemesg,err);
  return err;
}


//
// For a peer, like Win7/8, which creates and deletes Child SAs dynamically.
//
// vpn->lock must be acuqred before calling this func.
int rhp_ikev2_create_child_sa_dyn_create(rhp_vpn* vpn)
{
  int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;
  rhp_childsa* new_childsa = NULL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_vpn_realm* rlm = NULL;
  rhp_ikesa* ikesa = NULL;

  //
  // Currently multiple Child SAs NOT supported.
  //


  RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_DYN_CREATE,"xxxd",vpn,vpn->rlm,vpn->ikesa_list_head,vpn->ts_extended_flag);

  if( vpn->ikesa_num < 1 ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  if( vpn->childsa_num > 0 ){ // Already started CREATE_CHILD_SA exchnge or established.
  	err = -EBUSY;
    RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_DYN_CREATE_BUSY,"xd",vpn,vpn->childsa_num);
  	goto error;
  }

  if( rhp_ikev2_mobike_pending(vpn) || rhp_ikev2_mobike_ka_pending(vpn) ){
  	err = 0;
    RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_DYN_CREATE_MOBIKE_RT_CK_PEND,"x",vpn);
  	goto ignored;
  }

  rlm = vpn->rlm;
  if( rlm == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_DYN_CREATE_NO_RLM,"x",vpn);
    goto error;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_DYN_CREATE_RLM_NOT_ACTIVE,"xx",vpn,rlm);
    goto error;
  }


  ikesa = vpn->ikesa_list_head;
  if( ikesa == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }


  new_childsa = rhp_childsa_alloc2_i(vpn,rlm->childsa.pfs);
  if( new_childsa == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

  new_childsa->gen_type = RHP_CHILDSA_GEN_CREATE_CHILD_SA;

  new_childsa->timers = rhp_childsa_new_timers(new_childsa->spi_inb,new_childsa->spi_outb);
  if( new_childsa->timers == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }


  tx_ikemesg = rhp_ikev2_new_mesg_tx(RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA,0,0);
  if( tx_ikemesg == NULL ){
    RHP_BUG("");
    goto error;
  }

	if( vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_ETHERIP ||
			vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_GRE ){

		new_childsa->ipsec_mode = RHP_CHILDSA_MODE_TRANSPORT;

		{
			if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
				RHP_BUG("");
				goto error;
			}

			tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

			ikepayload->ext.n->set_protocol_id(ikepayload,0);
			ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_USE_TRANSPORT_MODE);
		}

	}else{ // RHP_VPN_ENCAP_IPIP

		new_childsa->ipsec_mode = RHP_CHILDSA_MODE_TUNNEL;
	}

  {
  	u16 rekey_pfs_dhgrp_id = 0;

    if( (err = rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_SA,&ikepayload)) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( rlm->childsa.pfs ){
   	  rekey_pfs_dhgrp_id = new_childsa->rekey_dh->grp;
    }

    err = ikepayload->ext.sa->set_def_childsa_prop(ikepayload,(u8*)&(new_childsa->spi_inb),
  		 RHP_PROTO_IPSEC_SPI_SIZE,rekey_pfs_dhgrp_id);

    if( err ){
    	RHP_BUG("");
    	goto error;
    }
  }

  {
    int nonce_len = new_childsa->rekey_nonce_i->get_nonce_len(new_childsa->rekey_nonce_i);
    u8* nonce = new_childsa->rekey_nonce_i->get_nonce(new_childsa->rekey_nonce_i);

    if( nonce == NULL ){
      RHP_BUG("");
      goto error;
    }

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N_I_R,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.nir->set_nonce(ikepayload,nonce_len,nonce) ){
      RHP_BUG("");
      goto error;
    }
  }

  if( rlm->childsa.pfs ){

  	int key_len;
    u8* key = new_childsa->rekey_dh->get_my_pub_key(new_childsa->rekey_dh,&key_len);
    if( key == NULL ){
      RHP_BUG("");
      goto error;
    }

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_KE,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.ke->set_key(ikepayload,new_childsa->rekey_dh->grp,key_len,key) ){
      RHP_BUG("");
      goto error;
    }
  }


  {
  	if( (err = rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_TS_I,&ikepayload)) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( vpn->ts_extended_flag ){

    	if( vpn->last_my_tss == NULL ){
    		err = -EINVAL;
    		RHP_BUG("");
    		goto error;
    	}

			if( (err = ikepayload->ext.ts->set_tss(ikepayload,vpn->last_my_tss)) ){
				RHP_BUG("");
				goto error;
			}

    }else{

      if( (err = ikepayload->ext.ts->set_i_tss(ikepayload,rlm,vpn->cfg_peer,NULL,NULL)) ){
        RHP_BUG("");
        goto error;
      }
    }
  }

  {
  	if( (err = rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_TS_R,&ikepayload)) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( vpn->ts_extended_flag ){

    	if( vpn->last_peer_tss == NULL ){
    		err = -EINVAL;
    		RHP_BUG("");
    		goto error;
    	}

			if( (err = ikepayload->ext.ts->set_tss(ikepayload,vpn->last_peer_tss)) ){
				RHP_BUG("");
				goto error;
			}

    }else{

      // cp_internal_addr may be NULL.
      if( (err = ikepayload->ext.ts->set_i_tss(ikepayload,rlm,vpn->cfg_peer,NULL,NULL)) ){
        RHP_BUG("");
        goto error;
      }
    }
  }


	if( (vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_ETHERIP) && vpn->peer_is_rockhopper ){

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    ikepayload->ext.n->set_protocol_id(ikepayload,0);
    ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_ETHERIP_ENCAP);

	}else if( (vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_GRE) && vpn->peer_is_rockhopper ){

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    ikepayload->ext.n->set_protocol_id(ikepayload,0);
    ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_GRE_ENCAP);
	}

	RHP_UNLOCK(&(rlm->lock));


  rhp_childsa_set_state(new_childsa,RHP_CHILDSA_STAT_LARVAL);

  err = rhp_vpn_inb_childsa_put(vpn,new_childsa->spi_inb);
  if( err ){
    RHP_BUG("");
    goto error_no_rlm_lock;
  }

  vpn->childsa_put(vpn,new_childsa);

  new_childsa->timers->start_lifetime_timer(vpn,new_childsa,(time_t)rlm->childsa.lifetime_larval,1);


  tx_ikemesg->childsa_spi_inb = new_childsa->spi_inb;
  tx_ikemesg->packet_serialized = _rhp_ikev2_create_child_sa_tx_comp_cb;

	rhp_ikev2_send_request(vpn,NULL,tx_ikemesg,RHP_IKEV2_MESG_HANDLER_REKEY);
	rhp_ikev2_unhold_mesg(tx_ikemesg);


ignored:
  RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_DYN_CREATE_RTRN,"xxx",vpn,new_childsa,tx_ikemesg);
  return 0;

error:
	if( rlm ){
		RHP_UNLOCK(&(rlm->lock));
	}
error_no_rlm_lock:
  if( new_childsa ){
  	rhp_childsa_destroy(vpn,new_childsa);
  }

  if( tx_ikemesg ){
    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_CREATE_CHILD_SA_DYN_CREATE_ERR,"xE",vpn,err);
  return -EINVAL;
}

