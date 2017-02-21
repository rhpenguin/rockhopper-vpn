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


static u8 _rhp_proto_ikev1_nat_vid[16]
= {0x4a,0x13,0x1c,0x81,0x07,0x03,0x58,0x45,0x5c,0x57,0x28,0xf2,0x0e,0x95,0x45,0x2f};

#define RHP_IKEV1_NAT_T_HASH_BUF_LEN	(RHP_PROTO_IKE_SPI_SIZE*2 + 16 + 2) // 16 : IPv6 address , 2 : port


static int _rhp_ikev1_nat_t_new_pkt_p1_vid(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_NEW_PKT_P1_VID,"xxx",vpn,ikesa,tx_ikemesg);

  {
    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_VID,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.vid->set_vid(ikepayload,16,_rhp_proto_ikev1_nat_vid) ){
      RHP_BUG("");
      goto error;
    }
  }

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_NEW_PKT_P1_VID_RTRN,"xxx",vpn,ikesa,tx_ikemesg);
  return 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_NEW_PKT_P1_VID_ERR,"xxE",vpn,ikesa,err);
  return err;
}

int rhp_ikev1_tx_nat_t_req(rhp_ikev2_mesg* tx_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,int req_initiator)
{
	int err = -EINVAL;
	rhp_ikesa* ikesa = NULL;
	rhp_vpn_realm* rlm = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_TX_NAT_T_REQ,"xxLdGLdd",tx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKEV1_MESG_HDLR",req_initiator,tx_ikemesg->add_nat_t_info);

  if( rhp_gcfg_ikev1_nat_t_disabled ){
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
		  RHP_TRC(0,RHPTRCID_IKEV1_TX_NAT_T_REQ_NO_IKESA,"xxLdG",tx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
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
		  RHP_TRC(0,RHPTRCID_IKEV1_TX_NAT_T_REQ_RLM_NOT_ACTIVE,"xxx",tx_ikemesg,vpn,rlm);
			RHP_UNLOCK(&(rlm->lock));
			goto error;
		}

		if( !rlm->ikesa.nat_t ){
		  RHP_TRC(0,RHPTRCID_IKEV1_TX_NAT_T_REQ_NAT_T_DISABLED,"xxxd",tx_ikemesg,vpn,rlm,rlm->ikesa.nat_t);
			RHP_UNLOCK(&(rlm->lock));
			goto ignore;
		}

		RHP_UNLOCK(&(rlm->lock));

		if( ikesa->state == RHP_IKESA_STAT_V1_MAIN_1ST_SENT_I ||
				ikesa->state == RHP_IKESA_STAT_V1_AGG_1ST_SENT_I ){

			err = _rhp_ikev1_nat_t_new_pkt_p1_vid(vpn,ikesa,tx_ikemesg);
			if( err ){
				goto error;
			}

		}else{

			RHP_TRC(0,RHPTRCID_IKEV1_TX_NAT_T_REQ_P1_NOT_INTERESTED,"xxxd",tx_ikemesg,vpn,ikesa,ikesa->state);
			goto ignore;
		}
	}

ignore:
	RHP_TRC(0,RHPTRCID_IKEV1_TX_NAT_T_REQ_RTRN,"xxLd",tx_ikemesg,vpn,"IKEV2_MESG_HDLR",req_initiator);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV1_TX_NAT_T_REQ_ERR,"xxLdE",tx_ikemesg,vpn,"IKEV2_MESG_HDLR",req_initiator,err);
  return err;
}

static int _rhp_ikev1_nat_t_srch_vid_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_nat_t_srch_plds_ctx* s_pld_ctx = (rhp_nat_t_srch_plds_ctx*)ctx;
  rhp_ikev2_vid_payload* vid_payload = (rhp_ikev2_vid_payload*)payload->ext.vid;
  int vid_len;
  u8* vid;

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_SRCH_VID_CB,"xdxxxxx",rx_ikemesg,enum_end,payload,vid_payload,ctx,s_pld_ctx->vpn,s_pld_ctx->ikesa);

  if( vid_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }


  vid_len = vid_payload->get_vid_len(payload);
  vid = vid_payload->get_vid(payload);

  if( vid_len < 1 || vid == NULL ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_SRCH_VID_CB_INVALID_VID_ERR,"x",rx_ikemesg);
  	goto error;
  }

  if( vid_len == 16 &&
  		!memcmp(vid,_rhp_proto_ikev1_nat_vid,16)){

  	s_pld_ctx->vpn->v1.peer_nat_t_supproted = 1;
  }

  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_SRCH_VID_CB_RTRN,"xxxxxdE",rx_ikemesg,payload,vid_payload,s_pld_ctx->vpn,s_pld_ctx->ikesa,s_pld_ctx->vpn->v1.peer_nat_t_supproted,err);
  return err;
}

static int _rhp_ikev1_rx_nat_t_main_r_1(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_nat_t_srch_plds_ctx s_pld_ctx;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_MAIN_R_REQ_1,"xxxx",rx_ikemesg,vpn,ikesa,tx_ikemesg);


  memset(&s_pld_ctx,0,sizeof(rhp_nat_t_srch_plds_ctx));

  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
  	RHP_BUG("");
  	goto error;
  }

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;
  s_pld_ctx.rlm = NULL; // realm is NOT resolved yet.

	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_VID),
			_rhp_ikev1_nat_t_srch_vid_cb,&s_pld_ctx);

  if( err && err != RHP_STATUS_ENUM_OK ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_MAIN_R_REQ_1_ENUM_SA_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
  	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_NAT_T_REQ_PARSE_VID_PAYLOAD_ERR,"KVPE",rx_ikemesg,NULL,ikesa,err);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


  if( vpn->v1.peer_nat_t_supproted ){

		err = _rhp_ikev1_nat_t_new_pkt_p1_vid(vpn,ikesa,tx_ikemesg);
		if( err ){
			goto error;
		}

  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_NAT_T_REQ_PEER_NAT_T_SUPPORTED,"KVP",rx_ikemesg,vpn,ikesa);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_MAIN_R_REQ_1_RTRN,"xxxd",rx_ikemesg,vpn,ikesa,vpn->v1.peer_nat_t_supproted);
  return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_NAT_T_REQ_VID_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
  RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_MAIN_R_REQ_1_ERR,"xxxE",rx_ikemesg,vpn,ikesa,err);
  return err;
}


static int _rhp_ikev1_nat_t_dst_hash(rhp_vpn* vpn,rhp_ikesa* ikesa,u8** hash_r,int* hash_len_r,
		rhp_ikev2_mesg* rx_ikemesg)
{
  int err = -EINVAL;
  u8 buf[RHP_IKEV1_NAT_T_HASH_BUF_LEN];
  u8* p = buf;
  int p_len = 0;
  u8* hash = NULL;
  int hash_len;
	rhp_crypto_hash* v1_hash = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_DST_HASH,"xxxxx",vpn,ikesa,hash_r,hash_len_r,rx_ikemesg);

  memcpy(p,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
  p += RHP_PROTO_IKE_SPI_SIZE;
  p_len += RHP_PROTO_IKE_SPI_SIZE;

  memcpy(p,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
  p += RHP_PROTO_IKE_SPI_SIZE;
  p_len += RHP_PROTO_IKE_SPI_SIZE;

  rhp_ip_addr_dump("_rhp_ikev1_nat_t_dst_hash:ikesa->peer_addr",&(vpn->peer_addr));


  if( rx_ikemesg ){

  	if( rx_ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE ){

      memcpy(p,&(rx_ikemesg->rx_pkt->l3.iph_v4->src_addr),4);
      p += 4;
      p_len += 4;

  	}else	if( rx_ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE ){

      memcpy(p,rx_ikemesg->rx_pkt->l3.iph_v6->src_addr,16);
      p += 16;
      p_len += 16;

  	}else{
  		RHP_BUG("");
  		goto error;
  	}

  }else if( vpn->peer_addr.addr_family == AF_INET ){

  	memcpy(p,&(vpn->peer_addr.addr.v4),4);
    p += 4;
    p_len += 4;

  }else if( vpn->peer_addr.addr_family == AF_INET6 ){

  	memcpy(p,vpn->peer_addr.addr.v6,16);
    p += 16;
    p_len += 16;

  }else{
    RHP_BUG("%d",vpn->peer_addr.addr_family);
    goto error;
  }


  if( rx_ikemesg ){

  	if( rx_ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE ||
  			rx_ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE ){

      memcpy(p,&(rx_ikemesg->rx_pkt->l4.udph->src_port),2);

  	}else{
  		RHP_BUG("");
  		goto error;
  	}

  }else{

  	memcpy(p,&(vpn->peer_addr.port),2);
  }
  p += 2;
  p_len += 2;

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_DST_HASH_BUF,"xp",ikesa,p_len,buf);


	{
		v1_hash = rhp_crypto_hash_alloc(ikesa->prop.v1.hash_alg);
		if( v1_hash == NULL ){
			RHP_BUG("%d",ikesa->prop.v1.hash_alg);
			err = -EINVAL;
			goto error;
		}

		hash_len = v1_hash->get_output_len(v1_hash);

		hash = (u8*)_rhp_malloc(hash_len);
		if( hash == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		err = v1_hash->compute(v1_hash,buf,p_len,hash,hash_len);
		if( err ){
			goto error;
		}
	}


	rhp_crypto_hash_free(v1_hash);

  *hash_r = hash;
  *hash_len_r = hash_len;

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_DST_HASH_RTRN,"xpp",ikesa,p_len,buf,*hash_len_r,*hash_r);
  return 0;

error:
	if( v1_hash ){
		rhp_crypto_hash_free(v1_hash);
	}
	if( hash ){
		_rhp_free(hash);
	}
	RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_DST_HASH_ERR,"xE",ikesa,err);
	return err;
}

static int _rhp_ikev1_nat_t_src_hash(rhp_vpn* vpn,rhp_ikesa* ikesa,u8** hash_r,int* hash_len_r,
		rhp_ikev2_mesg* rx_ikemesg)
{
  int err = -EINVAL;
  u8 buf[RHP_IKEV1_NAT_T_HASH_BUF_LEN];
  u8* p = buf;
  int p_len = 0;
  u8* hash = NULL;
  int hash_len;
	rhp_crypto_hash* v1_hash = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_SRC_HASH,"xxxxx",vpn,ikesa,hash_r,hash_len_r,rx_ikemesg);

  memcpy(p,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
  p += RHP_PROTO_IKE_SPI_SIZE;
  p_len += RHP_PROTO_IKE_SPI_SIZE;

  memcpy(p,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
  p += RHP_PROTO_IKE_SPI_SIZE;
  p_len += RHP_PROTO_IKE_SPI_SIZE;

  rhp_if_entry_dump("_rhp_ikev1_nat_t_src_hash:ikesa->local.if_info",&(vpn->local.if_info));


  if( rx_ikemesg ){

  	if( rx_ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE ){

      memcpy(p,&(rx_ikemesg->rx_pkt->l3.iph_v4->dst_addr),4);
      p += 4;
      p_len += 4;

  	}else	if( rx_ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE ){

      memcpy(p,rx_ikemesg->rx_pkt->l3.iph_v6->dst_addr,16);
      p += 16;
      p_len += 16;

  	}else{
  		RHP_BUG("");
  		goto error;
  	}

	}else if( vpn->local.if_info.addr_family == AF_INET ){

    memcpy(p,&(vpn->local.if_info.addr.v4),4);
    p += 4;
    p_len += 4;

	}else if( vpn->local.if_info.addr_family == AF_INET6 ){

		memcpy(p,vpn->local.if_info.addr.v6,16);
    p += 16;
    p_len += 16;

	}else{
    RHP_BUG("%d",vpn->local.if_info.addr_family);
    goto error;
  }


  if( rx_ikemesg ){

  	if( rx_ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE ||
  			rx_ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE ){

      memcpy(p,&(rx_ikemesg->rx_pkt->l4.udph->dst_port),2);

  	}else{
  		RHP_BUG("");
  		goto error;
  	}

  }else{

  	memcpy(p,&(vpn->local.port),2);
  }
  p += 2;
  p_len += 2;

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_SRC_HASH_BUF,"xp",ikesa,p_len,buf);

	{
		v1_hash = rhp_crypto_hash_alloc(ikesa->prop.v1.hash_alg);
		if( v1_hash == NULL ){
			RHP_BUG("%d",ikesa->prop.v1.hash_alg);
			err = -EINVAL;
			goto error;
		}

		hash_len = v1_hash->get_output_len(v1_hash);

		hash = (u8*)_rhp_malloc(hash_len);
		if( hash == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		err = v1_hash->compute(v1_hash,buf,p_len,hash,hash_len);
		if( err ){
			goto error;
		}
	}

	rhp_crypto_hash_free(v1_hash);

  *hash_r = hash;
  *hash_len_r = hash_len;

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_SRC_HASH_RTRN,"xxpp",vpn,ikesa,p_len,buf,*hash_len_r,*hash_r);
  return 0;

error:
	if( v1_hash ){
		rhp_crypto_hash_free(v1_hash);
	}
	if( hash ){
		_rhp_free(hash);
	}
	RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_SRC_HASH_ERR,"xxE",vpn,ikesa,err);
	return err;
}


static int _rhp_ikev1_nat_t_peer_dst_hash(rhp_ikesa* ikesa,rhp_ikev2_payload* nat_d_dst_payload,
		u8** hash_r,int* hash_len_r)
{
  int err = -EINVAL;
  u8 buf[RHP_IKEV1_NAT_T_HASH_BUF_LEN];
  u8* p = buf;
  int p_len = 0;
  rhp_ikev2_mesg* rx_ikemesg = nat_d_dst_payload->ikemesg;
  rhp_packet* rx_pkt;
  u8* hash = NULL;
  int hash_len;
	rhp_crypto_hash* v1_hash = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_PEER_DST_HASH,"xxxx",ikesa,nat_d_dst_payload,hash_r,hash_len_r);

  if( rx_ikemesg == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  rx_pkt = rx_ikemesg->rx_pkt;
  if( rx_pkt == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  memcpy(p,rx_ikemesg->get_init_spi(rx_ikemesg),RHP_PROTO_IKE_SPI_SIZE);
  p += RHP_PROTO_IKE_SPI_SIZE;
  p_len += RHP_PROTO_IKE_SPI_SIZE;

  memcpy(p,rx_ikemesg->get_resp_spi(rx_ikemesg),RHP_PROTO_IKE_SPI_SIZE);
  p += RHP_PROTO_IKE_SPI_SIZE;
  p_len += RHP_PROTO_IKE_SPI_SIZE;

  if( rx_pkt->type == RHP_PKT_IPV4_IKE ){

  	memcpy(p,&(rx_pkt->l3.iph_v4->dst_addr),4);
  	p += 4;
    p_len += 4;

  }else if( rx_pkt->type == RHP_PKT_IPV6_IKE ){

  	memcpy(p,rx_pkt->l3.iph_v6->dst_addr,16);
  	p += 16;
    p_len += 16;

  }else{
    RHP_BUG("%d",rx_pkt->type);
    goto error;
  }

  memcpy(p,&(rx_pkt->l4.udph->dst_port),2);
  p += 2;
  p_len += 2;

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_PEER_DST_HASH_BUF,"xp",ikesa,p_len,buf);

	{
		v1_hash = rhp_crypto_hash_alloc(ikesa->prop.v1.hash_alg);
		if( v1_hash == NULL ){
			RHP_BUG("%d",ikesa->prop.v1.hash_alg);
			err = -EINVAL;
			goto error;
		}

		hash_len = v1_hash->get_output_len(v1_hash);

		hash = (u8*)_rhp_malloc(hash_len);
		if( hash == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		err = v1_hash->compute(v1_hash,buf,p_len,hash,hash_len);
		if( err ){
			goto error;
		}
	}

	rhp_crypto_hash_free(v1_hash);

  *hash_r = hash;
  *hash_len_r = hash_len;

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_PEER_DST_HASH_RTRN,"xxpp",ikesa,nat_d_dst_payload,p_len,buf,*hash_len_r,*hash_r);
  return 0;

error:
	if( v1_hash ){
		rhp_crypto_hash_free(v1_hash);
	}
	if( hash ){
		_rhp_free(hash);
	}
	RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_PEER_DST_HASH_ERR,"xxE",ikesa,nat_d_dst_payload,err);
	return err;
}

static int _rhp_ikev1_nat_t_peer_src_hash(rhp_ikesa* ikesa,
		rhp_ikev2_payload* nat_d_src_payload,u8** hash_r,int* hash_len_r)
{
  int err = -EINVAL;
  u8 buf[RHP_IKEV1_NAT_T_HASH_BUF_LEN];
  u8* p = buf;
  int p_len = 0;
  rhp_ikev2_mesg* rx_ikemesg = nat_d_src_payload->ikemesg;
  rhp_packet* rx_pkt;
  u8* hash = NULL;
  int hash_len;
	rhp_crypto_hash* v1_hash = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_PEER_SRC_HASH,"xxxx",ikesa,nat_d_src_payload,hash_r,hash_len_r);

  if( rx_ikemesg == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  rx_pkt = rx_ikemesg->rx_pkt;
  if( rx_pkt == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  memcpy(p,rx_ikemesg->get_init_spi(rx_ikemesg),RHP_PROTO_IKE_SPI_SIZE);
  p += RHP_PROTO_IKE_SPI_SIZE;
  p_len += RHP_PROTO_IKE_SPI_SIZE;

  memcpy(p,rx_ikemesg->get_resp_spi(rx_ikemesg),RHP_PROTO_IKE_SPI_SIZE);
  p += RHP_PROTO_IKE_SPI_SIZE;
  p_len += RHP_PROTO_IKE_SPI_SIZE;

  if( rx_pkt->type == RHP_PKT_IPV4_IKE ){

    memcpy(p,&(rx_pkt->l3.iph_v4->src_addr),4);
    p += 4;
    p_len += 4;

  }else if( rx_pkt->type == RHP_PKT_IPV6_IKE ){

  	memcpy(p,rx_pkt->l3.iph_v6->src_addr,16);
    p += 16;
    p_len += 16;

  }else{
    RHP_BUG("%d",rx_pkt->type);
    goto error;
  }

  memcpy(p,&(rx_pkt->l4.udph->src_port),2);
  p += 2;
  p_len += 2;

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_PEER_SRC_HASH_BUF,"xp",ikesa,p_len,buf);

	{
		v1_hash = rhp_crypto_hash_alloc(ikesa->prop.v1.hash_alg);
		if( v1_hash == NULL ){
			RHP_BUG("%d",ikesa->prop.v1.hash_alg);
			err = -EINVAL;
			goto error;
		}

		hash_len = v1_hash->get_output_len(v1_hash);

		hash = (u8*)_rhp_malloc(hash_len);
		if( hash == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		err = v1_hash->compute(v1_hash,buf,p_len,hash,hash_len);
		if( err ){
			goto error;
		}
	}

	rhp_crypto_hash_free(v1_hash);

  *hash_r = hash;
  *hash_len_r = hash_len;

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_PEER_SRC_HASH_RTRN,"xxpp",ikesa,nat_d_src_payload,p_len,buf,*hash_len_r,*hash_r);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_PEER_SRC_HASH_RTRN,"xxE",ikesa,nat_d_src_payload,err);
	return err;
}

static int _rhp_ikev1_nat_t_src_check(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_payload* nat_d_src_payload)
{
  int err;
  u8* hval = NULL;
  int hval_len;
  int hash_len = 0;
  u8* hash = NULL;

	RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_SRC_CHECK,"xxxx",vpn,ikesa,nat_d_src_payload,vpn->nat_t_info.behind_a_nat);

  err = _rhp_ikev1_nat_t_peer_src_hash(ikesa,nat_d_src_payload,&hval,&hval_len);
  if( err ){
  	RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_SRC_CHECK_PEER_HASH_ERR,"xxE",ikesa,nat_d_src_payload,err);
  	goto error;
  }

  hash_len = nat_d_src_payload->ext.v1_nat_d->get_hash_len(nat_d_src_payload);
  if( hash_len != hval_len ){
  	RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_SRC_CHECK_NOTIFIED_HASH_LEN_ERR,"xxd",ikesa,nat_d_src_payload,hash_len);
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

  hash = nat_d_src_payload->ext.v1_nat_d->get_hash(nat_d_src_payload);
  if( hash == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_SRC_CHECK_NO_NOTIFIED_HASH_VAL,"xx",ikesa,nat_d_src_payload);
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_SRC_CHECK_CMP,"xxpp",ikesa,nat_d_src_payload,hash_len,hash,hval_len,hval);

  if( memcmp(hash,hval,hash_len) ){
  	err = RHP_STATUS_BEHIND_A_NAT;
  }else{
  	err = 0;
  }

  _rhp_free(hval);

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_SRC_CHECK_RTRN,"xxxxE",vpn,ikesa,nat_d_src_payload,vpn->nat_t_info.behind_a_nat,err);
  return err;

error:
  if( hval ){
    _rhp_free(hval);
  }
  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_SRC_CHECK_ERR,"xxE",ikesa,nat_d_src_payload,err);
  return err;
}

static int _rhp_ikev1_nat_t_dst_check(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_payload* nat_d_dst_payload)
{
  int err;
  u8* hval = NULL;
  int hval_len;
  int hash_len = 0;
  u8* hash = NULL;

	RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_DST_CHECK,"xxxx",vpn,ikesa,nat_d_dst_payload,vpn->nat_t_info.behind_a_nat);

  err = _rhp_ikev1_nat_t_peer_dst_hash(ikesa,nat_d_dst_payload,&hval,&hval_len);
  if( err ){
  	RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_DST_CHECK_PEER_HASH_ERR,"xxE",ikesa,nat_d_dst_payload,err);
  	goto error;
  }

  hash_len = nat_d_dst_payload->ext.v1_nat_d->get_hash_len(nat_d_dst_payload);
  if( hash_len != hval_len ){
  	RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_DST_CHECK_NOTIFIED_HASH_LEN_ERR,"xxd",ikesa,nat_d_dst_payload,hash_len);
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

  hash = nat_d_dst_payload->ext.v1_nat_d->get_hash(nat_d_dst_payload);
  if( hash == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_DST_CHECK_NO_NOTIFIED_HASH_VAL,"xx",ikesa,nat_d_dst_payload);
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_DST_CHECK_CMP,"xxpp",ikesa,nat_d_dst_payload,hash_len,hash,hval_len,hval);

  if( memcmp(hash,hval,hash_len) ){
  	err = RHP_STATUS_BEHIND_A_NAT;
  }else{
  	err = 0;
  }

  _rhp_free(hval);

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_DST_CHECK_RTRN,"xxxxE",vpn,ikesa,nat_d_dst_payload,vpn->nat_t_info.behind_a_nat,err);
  return err;

error:
  if( hval ){
    _rhp_free(hval);
  }
  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_DST_CHECK_ERR,"xxxE",vpn,ikesa,nat_d_dst_payload,err);
  return err;
}


static int _rhp_ikev1_nat_t_new_pkt_p1_nat_d(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_NEW_PKT_P1_NAT_D,"xxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg);

  // Destination address
  {
    u8* nat_t_dst_hash = NULL;
    int nat_t_dst_hash_len = 0;

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_NAT_D,&ikepayload) ){
      RHP_BUG("");
      err = -EINVAL;
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);


    if( _rhp_ikev1_nat_t_dst_hash(vpn,ikesa,&nat_t_dst_hash,&nat_t_dst_hash_len,rx_ikemesg) ){
      RHP_BUG("");
      err = -EINVAL;
      goto error;
    }

    if( ikepayload->ext.v1_nat_d->set_hash(ikepayload,nat_t_dst_hash_len,nat_t_dst_hash) ){
      RHP_BUG("");
      _rhp_free(nat_t_dst_hash);
      err = -EINVAL;
      goto error;
     }

    _rhp_free(nat_t_dst_hash);
  }


  // Source address(es)
  {
    u8* nat_t_src_hash = NULL;
    int nat_t_src_hash_len = 0;

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_NAT_D,&ikepayload) ){
      RHP_BUG("");
      err = -EINVAL;
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( _rhp_ikev1_nat_t_src_hash(vpn,ikesa,&nat_t_src_hash,&nat_t_src_hash_len,rx_ikemesg) ){
      RHP_BUG("");
      err = -EINVAL;
      goto error;
    }

    if( ikepayload->ext.v1_nat_d->set_hash(ikepayload,nat_t_src_hash_len,nat_t_src_hash) ){
      RHP_BUG("");
      _rhp_free(nat_t_src_hash);
      err = -EINVAL;
      goto error;
     }

    _rhp_free(nat_t_src_hash);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_NEW_PKT_P1_NAT_D_RTRN,"xxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg);

  return 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_NEW_PKT_P1_NAT_D_ERR,"xxxxE",vpn,ikesa,rx_ikemesg,tx_ikemesg,err);
  return err;
}

static int _rhp_ikev1_rx_nat_t_main_i_2(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_nat_t_srch_plds_ctx s_pld_ctx;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_MAIN_I_2,"xxxxbd",rx_ikemesg,vpn,ikesa,tx_ikemesg,rx_ikemesg->v1_ignored,rhp_gcfg_ikev1_nat_t_disabled);

  if( rhp_gcfg_ikev1_nat_t_disabled ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_MAIN_I_2_NAT_T_DISABLED,"xxxx",rx_ikemesg,vpn,ikesa,tx_ikemesg);
  	err = 0;
  	goto ignored;
  }

  if( rx_ikemesg->v1_ignored ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_MAIN_I_2_MARK_IGNORED,"xxxx",rx_ikemesg,vpn,ikesa,tx_ikemesg);
  	err = 0;
  	goto ignored;
  }

  memset(&s_pld_ctx,0,sizeof(rhp_nat_t_srch_plds_ctx));

  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
  	RHP_BUG("");
  	goto error;
  }

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;
  s_pld_ctx.rlm = NULL; // realm is NOT resolved yet.

	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_VID),
			_rhp_ikev1_nat_t_srch_vid_cb,&s_pld_ctx);

  if( err && err != RHP_STATUS_ENUM_OK ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_MAIN_I_2_ENUM_SA_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
  	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_NAT_T_REQ_PARSE_VID_PAYLOAD_ERR,"KVPE",rx_ikemesg,NULL,ikesa,err);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  if( !vpn->v1.peer_nat_t_supproted ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_MAIN_I_2_PEER_NOT_SUPPROTED,"xxd",rx_ikemesg,ikesa,err);
  	err = 0;
  	goto ignored;
  }


  err = _rhp_ikev1_nat_t_new_pkt_p1_nat_d(vpn,ikesa,rx_ikemesg,tx_ikemesg);
  if( err ){
  	goto error;
  }


ignored:
  RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_MAIN_I_2_RTRN,"xxxd",rx_ikemesg,vpn,ikesa,vpn->v1.peer_nat_t_supproted);
  return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_NAT_T_REQ_VID_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
  RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_MAIN_I_2_ERR,"xxxE",rx_ikemesg,vpn,ikesa,err);
  return err;
}

static int _rhp_ikev1_nat_t_srch_nat_d_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_nat_t_srch_plds_ctx* s_pld_ctx = (rhp_nat_t_srch_plds_ctx*)ctx;

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_SRCH_NAT_D_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

  if( enum_end ){

  	if( s_pld_ctx->n_nat_t_src_num == 0 && s_pld_ctx->n_nat_t_dst_num == 0 ){
  		goto end;
  	}

  	if( ( s_pld_ctx->n_nat_t_src_num == 0 && s_pld_ctx->n_nat_t_dst_num ) ||
 		    ( s_pld_ctx->n_nat_t_src_num && s_pld_ctx->n_nat_t_dst_num == 0 ) ){
  		RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_SRCH_NAT_D_CB_NUM_ERR,"xdd",rx_ikemesg,s_pld_ctx->n_nat_t_src_num,s_pld_ctx->n_nat_t_dst_num);
  		goto end;
  	}

  	if( s_pld_ctx->behind_a_nat ){

  		s_pld_ctx->exec_nat_t = 1;
	  }

  }else{

  	rhp_ikev1_nat_d_payload* nat_d_payload = (rhp_ikev1_nat_d_payload*)payload->ext.v1_nat_d;

  	if( nat_d_payload == NULL ){
  		RHP_BUG("");
    	return -EINVAL;
    }


  	if( s_pld_ctx->n_nat_t_dst_num > 0 ){

  		s_pld_ctx->n_nat_t_src_num++;

  		if( !s_pld_ctx->peer_not_behind_a_nat ){

				err = _rhp_ikev1_nat_t_src_check(s_pld_ctx->vpn,s_pld_ctx->ikesa,payload);

				if( err == RHP_STATUS_BEHIND_A_NAT ){
					s_pld_ctx->behind_a_nat |= RHP_IKESA_BEHIND_A_NAT_PEER;
					err = 0;
				}else if( err ){
					RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_SRCH_NAT_D_CB_SRC_CHECK_ERR,"xxE",rx_ikemesg,payload,err);
					goto error;
				}else{
					s_pld_ctx->peer_not_behind_a_nat = 1;
					s_pld_ctx->behind_a_nat &= ~RHP_IKESA_BEHIND_A_NAT_PEER;
				}
  		}

  	}else{

  		s_pld_ctx->n_nat_t_dst_num++;

  		err = _rhp_ikev1_nat_t_dst_check(s_pld_ctx->vpn,s_pld_ctx->ikesa,payload);

  		if( err == RHP_STATUS_BEHIND_A_NAT ){

  			s_pld_ctx->behind_a_nat |= RHP_IKESA_BEHIND_A_NAT_LOCAL;

  			err = 0;

  		}else if( err ){
  			RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_SRCH_NAT_D_CB_DST_CHECK_ERR,"xxE",rx_ikemesg,payload,err);
  			goto error;
	    }
    }
  }

end:
  err = 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV1_NAT_T_SRCH_N_CB_RTRN,"xxxE",rx_ikemesg,payload,ctx,err);
 	return err;
}

static int _rhp_ikev1_rx_nat_t_main_r_3(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_nat_t_srch_plds_ctx s_pld_ctx;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_MAIN_R_3,"x",rx_ikemesg);

  memset(&s_pld_ctx,0,sizeof(rhp_nat_t_srch_plds_ctx));

  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
  	RHP_BUG("");
  	goto error;
  }

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;
  s_pld_ctx.rlm = NULL; // realm is NOT resolved yet.

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,1,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_NAT_D),
  			_rhp_ikev1_nat_t_srch_nat_d_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){

  		RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_MAIN_R_3_ENUM_N_NAT_T_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);

    	goto error;
  	}
  	err = 0;

    vpn->nat_t_info.behind_a_nat = s_pld_ctx.behind_a_nat;
    vpn->nat_t_info.exec_nat_t = s_pld_ctx.exec_nat_t;

    if( vpn->nat_t_info.exec_nat_t ){

    	vpn->peer_addr.port = htons(rhp_gcfg_ike_port_nat_t);

  		//
  		// [CAUTION]
  		//   Once NAT is detected between peers, the following IKE messages are
  		//   transmitted from the NAT-T port (4500).
  		//
    	vpn->nat_t_info.use_nat_t_port = 1;

    	tx_ikemesg->v1_dont_nat_t_port = rx_ikemesg->rx_pkt->l4.udph->src_port;
    }
  }

  RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_MAIN_R_3_ENUM_N_STATUS,"xxxxd",rx_ikemesg,ikesa,vpn,vpn->nat_t_info.behind_a_nat,vpn->nat_t_info.exec_nat_t);

  if( rx_ikemesg->rx_pkt->l4.udph->dst_port == vpn->local.port_nat_t ){

    vpn->nat_t_info.use_nat_t_port = 1;

    RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_MAIN_R_3_ENUM_USE_NAT_T_PORT,"xxxdW",rx_ikemesg,ikesa,vpn,vpn->nat_t_info.use_nat_t_port,rx_ikemesg->rx_pkt->l4.udph->dst_port);
  }

  if( s_pld_ctx.n_nat_t_src_num && s_pld_ctx.n_nat_t_dst_num ){

    err = _rhp_ikev1_nat_t_new_pkt_p1_nat_d(vpn,ikesa,rx_ikemesg,tx_ikemesg);
  	if( err ){
	  	RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_MAIN_R_3_ALLOC_RESP_PKT_ERR,"xxE",rx_ikemesg,ikesa,err);
	  	goto error;
	  }
  }

  if( s_pld_ctx.peer_not_behind_a_nat ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_MAIN_NATT_R_3_NO_NAT,"KVP",rx_ikemesg,vpn,ikesa);
  }
	if( s_pld_ctx.behind_a_nat & RHP_IKESA_BEHIND_A_NAT_PEER ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_MAIN_NATT_R_3_PEER_BEHIND_A_NAT,"KVP",rx_ikemesg,vpn,ikesa);
	}
	if( s_pld_ctx.behind_a_nat & RHP_IKESA_BEHIND_A_NAT_LOCAL ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_MAIN_NATT_R_3_LOCAL_BEHIND_A_NAT,"KVP",rx_ikemesg,vpn,ikesa);
	}

  RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_MAIN_R_3_RTRN,"xx",rx_ikemesg,ikesa);
  return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_MAIN_NATT_R_3_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
  RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_MAIN_R_3_ERR,"xxE",rx_ikemesg,ikesa,err);
  return err;
}

static int _rhp_ikev1_rx_nat_t_main_i_4(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_vpn_realm* rlm = NULL;
  rhp_nat_t_srch_plds_ctx s_pld_ctx;

  RHP_TRC(0,RHPTRCID_RX_IKEV1_RX_NAT_T_MAIN_I_4,"xxxx",rx_ikemesg,tx_ikemesg,vpn,ikesa);

  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


  rlm = vpn->rlm;
  if( rlm == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  RHP_LOCK(&(rlm->lock));

	if( !_rhp_atomic_read(&(rlm->is_active)) ){
		err = -EINVAL;
		goto error_l;
	}

	if( !rlm->ikesa.nat_t ){
		goto ignore_l;
	}

  memset(&s_pld_ctx,0,sizeof(rhp_nat_t_srch_plds_ctx));

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;
  s_pld_ctx.rlm = rlm;

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,1,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_NAT_D),
  			_rhp_ikev1_nat_t_srch_nat_d_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
  		RHP_TRC(0,RHPTRCID_RX_IKEV1_RX_NAT_T_MAIN_I_4_ENUM_N_NAT_T_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);
    	goto error_l;
  	}
  	err = 0;

    vpn->nat_t_info.behind_a_nat = s_pld_ctx.behind_a_nat;
    vpn->nat_t_info.exec_nat_t = s_pld_ctx.exec_nat_t;

    if( vpn->nat_t_info.exec_nat_t ){

    	vpn->peer_addr.port = htons(rhp_gcfg_ike_port_nat_t);

  		//
  		// [CAUTION]
  		//   Once NAT is detected between peers, the following IKE messages are
  		//   transmitted from the NAT-T port (4500).
  		//
    	vpn->nat_t_info.use_nat_t_port = 1;

    	RHP_TRC(0,RHPTRCID_RX_IKEV1_RX_NAT_T_MAIN_I_4_CHANGE_PEER_PORT,"xxxW",vpn,ikesa,rx_ikemesg,vpn->peer_addr.port);
    }
  }


ignore_l:
	RHP_UNLOCK(&(rlm->lock));


  RHP_TRC(0,RHPTRCID_RX_IKEV1_RX_NAT_T_MAIN_I_4_ENUM_N_STATUS,"xxxxd",rx_ikemesg,vpn,ikesa,vpn->nat_t_info.behind_a_nat,vpn->nat_t_info.exec_nat_t);

  if( s_pld_ctx.peer_not_behind_a_nat ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_MAIN_NATT_I_4_NO_NAT,"KVP",rx_ikemesg,vpn,ikesa);
  }
	if( s_pld_ctx.behind_a_nat & RHP_IKESA_BEHIND_A_NAT_PEER ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_MAIN_NATT_I_4_PEER_BEHIND_A_NAT,"KVP",rx_ikemesg,vpn,ikesa);
	}
	if( s_pld_ctx.behind_a_nat & RHP_IKESA_BEHIND_A_NAT_LOCAL ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_MAIN_NATT_I_4_LOCAL_BEHIND_A_NAT,"KVP",rx_ikemesg,vpn,ikesa);
	}

  RHP_TRC(0,RHPTRCID_RX_IKEV1_RX_NAT_T_MAIN_I_4_RTRN,"xxx",rx_ikemesg,vpn,ikesa);
  return 0;

error_l:
	RHP_UNLOCK(&(rlm->lock));
error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_MAIN_NATT_I_4_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
  if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
  }
  RHP_TRC(0,RHPTRCID_RX_IKEV1_RX_NAT_T_MAIN_I_4_ERR,"xxx",rx_ikemesg,vpn,ikesa);
  return err;
}


static int _rhp_ikev1_rx_nat_t_aggressive_r_1(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_nat_t_srch_plds_ctx s_pld_ctx;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_AGGRESSIVE_R_1,"xxxx",rx_ikemesg,vpn,ikesa,tx_ikemesg);

  if( rhp_gcfg_ikev1_nat_t_disabled ){
  	err = 0;
  	goto ignored;
  }

  memset(&s_pld_ctx,0,sizeof(rhp_nat_t_srch_plds_ctx));

  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
  	RHP_BUG("");
  	goto error;
  }

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;
  s_pld_ctx.rlm = NULL; // realm is NOT resolved yet.

	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_VID),
			_rhp_ikev1_nat_t_srch_vid_cb,&s_pld_ctx);

  if( err && err != RHP_STATUS_ENUM_OK ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_AGGRESSIVE_R_1_ENUM_SA_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
  	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_NAT_T_REQ_PARSE_VID_PAYLOAD_ERR,"KVPE",rx_ikemesg,NULL,ikesa,err);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  if( !vpn->v1.peer_nat_t_supproted ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_AGGRESSIVE_R_1_PEER_NOT_SUPPROTED,"xxd",rx_ikemesg,ikesa,err);
  	err = 0;
  	goto ignored;
  }


	err = _rhp_ikev1_nat_t_new_pkt_p1_vid(vpn,ikesa,tx_ikemesg);
	if( err ){
		goto error;
	}

  err = _rhp_ikev1_nat_t_new_pkt_p1_nat_d(vpn,ikesa,rx_ikemesg,tx_ikemesg);
  if( err ){
  	goto error;
  }

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_NAT_T_REQ_PEER_NAT_T_SUPPORTED,"KVP",rx_ikemesg,vpn,ikesa);


ignored:
  RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_AGGRESSIVE_R_1_RTRN,"xxxd",rx_ikemesg,vpn,ikesa,vpn->v1.peer_nat_t_supproted);
  return 0;

error:
	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_NAT_T_REQ_VID_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
  RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_AGGRESSIVE_R_1_ERR,"xxxE",rx_ikemesg,vpn,ikesa,err);
  return err;
}

static int _rhp_ikev1_rx_nat_t_aggressive_i_2(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_nat_t_srch_plds_ctx s_pld_ctx;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_AGGRESSIVE_I_2,"x",rx_ikemesg);

  memset(&s_pld_ctx,0,sizeof(rhp_nat_t_srch_plds_ctx));

  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
  	RHP_BUG("");
  	goto error;
  }

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;
  s_pld_ctx.rlm = NULL; // realm is NOT resolved yet.

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,1,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_NAT_D),
  			_rhp_ikev1_nat_t_srch_nat_d_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){

  		RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_AGGRESSIVE_I_2_ENUM_N_NAT_T_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);

    	goto error;
  	}
  	err = 0;

    vpn->nat_t_info.behind_a_nat = s_pld_ctx.behind_a_nat;
    vpn->nat_t_info.exec_nat_t = s_pld_ctx.exec_nat_t;

    if( vpn->nat_t_info.exec_nat_t ){

    	vpn->peer_addr.port = htons(rhp_gcfg_ike_port_nat_t);

  		//
  		// [CAUTION]
  		//   Once NAT is detected between peers, the following IKE messages are
  		//   transmitted from the NAT-T port (4500).
  		//
    	vpn->nat_t_info.use_nat_t_port = 1;

    	tx_ikemesg->v1_dont_nat_t_port = rx_ikemesg->rx_pkt->l4.udph->src_port;
    }
  }

  RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_AGGRESSIVE_I_2_ENUM_N_STATUS,"xxxxd",rx_ikemesg,ikesa,vpn,vpn->nat_t_info.behind_a_nat,vpn->nat_t_info.exec_nat_t);

  if( rx_ikemesg->rx_pkt->l4.udph->dst_port == vpn->local.port_nat_t ){

    vpn->nat_t_info.use_nat_t_port = 1;

    RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_AGGRESSIVE_I_2_ENUM_USE_NAT_T_PORT,"xxxdW",rx_ikemesg,ikesa,vpn,vpn->nat_t_info.use_nat_t_port,rx_ikemesg->rx_pkt->l4.udph->dst_port);
  }

  if( s_pld_ctx.n_nat_t_src_num && s_pld_ctx.n_nat_t_dst_num ){

    err = _rhp_ikev1_nat_t_new_pkt_p1_nat_d(vpn,ikesa,rx_ikemesg,tx_ikemesg);
  	if( err ){
	  	RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_AGGRESSIVE_I_2_ALLOC_RESP_PKT_ERR,"xxE",rx_ikemesg,ikesa,err);
	  	goto error;
	  }
  }

  if( s_pld_ctx.peer_not_behind_a_nat ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_NATT_I_2_NO_NAT,"KVP",rx_ikemesg,vpn,ikesa);
  }
	if( s_pld_ctx.behind_a_nat & RHP_IKESA_BEHIND_A_NAT_PEER ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_NATT_I_2_PEER_BEHIND_A_NAT,"KVP",rx_ikemesg,vpn,ikesa);
	}
	if( s_pld_ctx.behind_a_nat & RHP_IKESA_BEHIND_A_NAT_LOCAL ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_NATT_I_2_LOCAL_BEHIND_A_NAT,"KVP",rx_ikemesg,vpn,ikesa);
	}

  RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_AGGRESSIVE_I_2_RTRN,"xx",rx_ikemesg,ikesa);
  return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_NATT_I_2_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
  RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_AGGRESSIVE_I_2_ERR,"xxE",rx_ikemesg,ikesa,err);
  return err;
}

static int _rhp_ikev1_rx_nat_t_aggressive_r_3(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_vpn_realm* rlm = NULL;
  rhp_nat_t_srch_plds_ctx s_pld_ctx;

  RHP_TRC(0,RHPTRCID_RX_IKEV1_RX_NAT_T_AGGRESSIVE_R_3,"xxxx",rx_ikemesg,tx_ikemesg,vpn,ikesa);

  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


  rlm = vpn->rlm;
  if( rlm == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  RHP_LOCK(&(rlm->lock));

	if( !_rhp_atomic_read(&(rlm->is_active)) ){
		err = -EINVAL;
		goto error_l;
	}

	if( !rlm->ikesa.nat_t ){
		goto ignore_l;
	}

  memset(&s_pld_ctx,0,sizeof(rhp_nat_t_srch_plds_ctx));

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;
  s_pld_ctx.rlm = rlm;

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,1,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_NAT_D),
  			_rhp_ikev1_nat_t_srch_nat_d_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
  		RHP_TRC(0,RHPTRCID_RX_IKEV1_RX_NAT_T_AGGRESSIVE_R_3_ENUM_N_NAT_T_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);
    	goto error_l;
  	}
  	err = 0;

    vpn->nat_t_info.behind_a_nat = s_pld_ctx.behind_a_nat;
    vpn->nat_t_info.exec_nat_t = s_pld_ctx.exec_nat_t;

    if( vpn->nat_t_info.exec_nat_t ){

    	vpn->peer_addr.port = htons(rhp_gcfg_ike_port_nat_t);

  		//
  		// [CAUTION]
  		//   Once NAT is detected between peers, the following IKE messages are
  		//   transmitted from the NAT-T port (4500).
  		//
    	vpn->nat_t_info.use_nat_t_port = 1;

    	RHP_TRC(0,RHPTRCID_RX_IKEV1_RX_NAT_T_AGGRESSIVE_R_3_CHANGE_PEER_PORT,"xxxW",vpn,ikesa,rx_ikemesg,vpn->peer_addr.port);
    }
  }


ignore_l:
	RHP_UNLOCK(&(rlm->lock));


  RHP_TRC(0,RHPTRCID_RX_IKEV1_RX_NAT_T_AGGRESSIVE_R_3_ENUM_N_STATUS,"xxxxd",rx_ikemesg,vpn,ikesa,vpn->nat_t_info.behind_a_nat,vpn->nat_t_info.exec_nat_t);

  if( s_pld_ctx.peer_not_behind_a_nat ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_NATT_R_3_NO_NAT,"KVP",rx_ikemesg,vpn,ikesa);
  }
	if( s_pld_ctx.behind_a_nat & RHP_IKESA_BEHIND_A_NAT_PEER ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_NATT_R_3_PEER_BEHIND_A_NAT,"KVP",rx_ikemesg,vpn,ikesa);
	}
	if( s_pld_ctx.behind_a_nat & RHP_IKESA_BEHIND_A_NAT_LOCAL ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_NATT_R_3_LOCAL_BEHIND_A_NAT,"KVP",rx_ikemesg,vpn,ikesa);
	}

  RHP_TRC(0,RHPTRCID_RX_IKEV1_RX_NAT_T_AGGRESSIVE_R_3_RTRN,"xxx",rx_ikemesg,vpn,ikesa);
  return 0;

error_l:
	RHP_UNLOCK(&(rlm->lock));
error:
	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_NATT_R_3_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
  if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
  }
  RHP_TRC(0,RHPTRCID_RX_IKEV1_RX_NAT_T_AGGRESSIVE_R_3_ERR,"xxx",rx_ikemesg,vpn,ikesa);
  return err;
}


int rhp_ikev1_rx_nat_t(rhp_ikev2_mesg* rx_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
	rhp_ikesa* ikesa = NULL;
	rhp_vpn_realm* rlm = NULL;
	u8 exchange_type = rx_ikemesg->get_exchange_type(rx_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T,"xxLdGxLb",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_ikemesg,"PROTO_IKE_EXCHG");

  if( rhp_gcfg_ikev1_nat_t_disabled ){
  	err = 0;
  	goto ignored;
  }

	if( exchange_type == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ||
			exchange_type == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){

		if( my_ikesa_spi == NULL ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
		if( ikesa == NULL ){
			err = -ENOENT;
		  RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_NO_IKESA2,"xxLdG",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}

	  if( ikesa->v1.nat_t_d_done ){
	  	err = 0;
	  	goto ignored;
	  }


		rlm = vpn->rlm;
		if( rlm ){ // Realm may not be resolved for a P1 responder.

			RHP_LOCK(&(rlm->lock));

			if( !_rhp_atomic_read(&(rlm->is_active)) ){
				err = -EINVAL;
				RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_RLM_NOT_ACTIVE,"xxx",tx_ikemesg,vpn,rlm);
				RHP_UNLOCK(&(rlm->lock));
				goto error;
			}

			if( !rlm->ikesa.nat_t ){
				RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_DISABLED,"xxxd",tx_ikemesg,vpn,rlm,rlm->ikesa.nat_t);
				RHP_UNLOCK(&(rlm->lock));
				err = 0;
				goto ignored;
			}

			RHP_UNLOCK(&(rlm->lock));
		}

		//
		// ikesa->state is already updated by main/agg mode handler.
		//
		if( ikesa->state == RHP_IKESA_STAT_V1_MAIN_2ND_SENT_R ){

			err = _rhp_ikev1_rx_nat_t_main_r_1(vpn,ikesa,rx_ikemesg,tx_ikemesg);

		}else if( ikesa->state == RHP_IKESA_STAT_V1_MAIN_3RD_SENT_I ){

			err = _rhp_ikev1_rx_nat_t_main_i_2(vpn,ikesa,rx_ikemesg,tx_ikemesg);

		}else if( ikesa->state == RHP_IKESA_STAT_V1_MAIN_4TH_SENT_R ){

			err = _rhp_ikev1_rx_nat_t_main_r_3(vpn,ikesa,rx_ikemesg,tx_ikemesg);
			ikesa->v1.nat_t_d_done = 1;

		}else if( ikesa->state == RHP_IKESA_STAT_V1_MAIN_5TH_SENT_I ){

			err = _rhp_ikev1_rx_nat_t_main_i_4(vpn,ikesa,rx_ikemesg,tx_ikemesg);
			ikesa->v1.nat_t_d_done = 1;


		}else if( ikesa->state == RHP_IKESA_STAT_V1_AGG_2ND_SENT_R ){

			err = _rhp_ikev1_rx_nat_t_aggressive_r_1(vpn,ikesa,rx_ikemesg,tx_ikemesg);

		}else if( ikesa->v1.p1_exchange_mode == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE &&
							(ikesa->state == RHP_IKESA_STAT_V1_ESTABLISHED ||
							 ikesa->state == RHP_IKESA_STAT_V1_AGG_WAIT_COMMIT_I) ){

			if( ikesa->side == RHP_IKE_INITIATOR ){

				err = _rhp_ikev1_rx_nat_t_aggressive_i_2(vpn,ikesa,rx_ikemesg,tx_ikemesg);

			}else if( ikesa->side == RHP_IKE_RESPONDER ){

				err = _rhp_ikev1_rx_nat_t_aggressive_r_3(vpn,ikesa,rx_ikemesg,tx_ikemesg);

			}else{
				RHP_BUG("%d",ikesa->side);
				err = -EINVAL;
			}
			ikesa->v1.nat_t_d_done = 1;

		}else{

			err = 0;
			RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_NOT_INTERESTED_1,"xxxd",rx_ikemesg,vpn,tx_ikemesg,ikesa->state);
		}

	}else{

		err = 0;
		RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_NOT_INTERESTED_2,"xxx",rx_ikemesg,vpn,tx_ikemesg);
	}

ignored:
error:
	RHP_TRC(0,RHPTRCID_IKEV1_RX_NAT_T_RTRN,"xxxdE",rx_ikemesg,vpn,tx_ikemesg,(ikesa ? ikesa->v1.nat_t_d_done : -1),err);
  return err;
}
