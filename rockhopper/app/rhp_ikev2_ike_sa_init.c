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


extern rhp_mutex_t rhp_vpn_lock;

#define RHP_IKEV2_COOKIE_SECRET_LEN		128

static rhp_timer _rhp_ikev2_cookie_timer;

u32 _rhp_ikev2_cookie_secret_version = 1;
u8 _rhp_ikev2_cookie_secret_current[RHP_IKEV2_COOKIE_SECRET_LEN];
u8 _rhp_ikev2_cookie_secret_old[RHP_IKEV2_COOKIE_SECRET_LEN];

static rhp_crypto_prf* _rhp_ikev2_cookie_prf_current = NULL;
static rhp_crypto_prf* _rhp_ikev2_cookie_prf_old = NULL;

static rhp_atomic_t _rhp_ikesa_cookie_pend_pkts;



struct _rhp_ikev2_ike_sa_init_tx_err_ctx {
	u16 notify_mesg_type;
	unsigned long arg0;
};
typedef struct _rhp_ikev2_ike_sa_init_tx_err_ctx	rhp_ikev2_ike_sa_init_tx_err_ctx;

static int rhp_ikev2_ike_sa_init_tx_error_rep_plds_cb(rhp_ikev2_mesg* tx_ikemesg,void* ctx)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;
	rhp_ikev2_ike_sa_init_tx_err_ctx* plds_cb_ctx = (rhp_ikev2_ike_sa_init_tx_err_ctx*)ctx;

  if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
    RHP_BUG("");
    goto error;
  }

  tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

  ikepayload->ext.n->set_protocol_id(ikepayload,0);
  ikepayload->ext.n->set_message_type(ikepayload,plds_cb_ctx->notify_mesg_type);

  switch( plds_cb_ctx->notify_mesg_type ){

  case RHP_PROTO_IKE_NOTIFY_ERR_NO_PROPOSAL_CHOSEN:
    break;

  case RHP_PROTO_IKE_NOTIFY_ERR_INVALID_KE_PAYLOAD:
   {
    u16 dhgrp = htons((u16)plds_cb_ctx->arg0);
    if( ikepayload->ext.n->set_data(ikepayload,sizeof(u16),(u8*)&dhgrp) ){
      RHP_BUG("");
      goto error;
     }
   }
   break;

  case RHP_PROTO_IKE_NOTIFY_ST_COOKIE:
  {
   u8* cookie = (u8*)plds_cb_ctx->arg0;
   if( ikepayload->ext.n->set_data(ikepayload,RHP_IKEV2_COOKIE_LEN,cookie) ){
     RHP_BUG("");
     goto error;
    }
  }
    break;

  default:
    RHP_BUG("%d",plds_cb_ctx->notify_mesg_type);
    goto error;
  }

  return 0;

error:
	return err;
}

int rhp_ikev2_ike_sa_init_tx_error_rep(rhp_ikev2_mesg* rx_ikemesg,
		u16 notify_mesg_type,unsigned long arg0)
{
  int err = -EINVAL;
  union {
  	rhp_proto_ip_v4* v4;
  	rhp_proto_ip_v6* v6;
  	u8* raw;
  } iph_i;
  rhp_proto_udp* udph_i;
  rhp_proto_ike* ikeh_i;
  rhp_ifc_entry* rx_ifc;
  rhp_ikev2_ike_sa_init_tx_err_ctx pld_cb_ctx;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_TX_ERR_R,"xLwu",rx_ikemesg,"PROTO_IKE_NOTIFY",notify_mesg_type,arg0);

	iph_i.raw = rx_ikemesg->rx_pkt->l3.raw;
  udph_i = rx_ikemesg->rx_pkt->l4.udph;
  ikeh_i = rx_ikemesg->rx_pkt->app.ikeh;
  rx_ifc = rx_ikemesg->rx_pkt->rx_ifc;

  memset(&pld_cb_ctx,0,sizeof(rhp_ikev2_ike_sa_init_tx_err_ctx));
  pld_cb_ctx.notify_mesg_type = notify_mesg_type;
  pld_cb_ctx.arg0 = arg0;

  if( rx_ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE ){

  	err = rhp_ikev2_tx_plain_error_rep_v4(iph_i.v4,udph_i,ikeh_i,rx_ifc,
  					rhp_ikev2_ike_sa_init_tx_error_rep_plds_cb,(void*)&pld_cb_ctx);

  }else if( rx_ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE ){

  	err = rhp_ikev2_tx_plain_error_rep_v6(iph_i.v6,udph_i,ikeh_i,rx_ifc,
  					rhp_ikev2_ike_sa_init_tx_error_rep_plds_cb,(void*)&pld_cb_ctx);

  }else{
  	RHP_BUG("");
  	err = -EINVAL;
  }
  if( err ){
  	goto error;
  }


	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_SA_INIT_TX_ERR_NOTIFY,"KL",rx_ikemesg,"PROTO_IKE_NOTIFY",notify_mesg_type);

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_TX_ERR_R_RTRN,"x",rx_ikemesg);
  return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_SA_INIT_TX_ERR_NOTIFY_FAILED,"KLE",rx_ikemesg,"PROTO_IKE_NOTIFY",notify_mesg_type,err);

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_TX_ERR_R_ERR,"xE",rx_ikemesg,err);
  return err;
}

static void _rhp_ikev2_ike_sa_init_cookie_timer(void *ctx,rhp_timer *timer)
{
  int err;
  u8 tmp[RHP_IKEV2_COOKIE_SECRET_LEN];

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_COOKIE_TIMER,"xx",ctx,timer);

  RHP_LOCK(&rhp_vpn_lock);

  if( !rhp_random_bytes(tmp,RHP_IKEV2_COOKIE_SECRET_LEN) ){

    err = _rhp_ikev2_cookie_prf_current->set_key(_rhp_ikev2_cookie_prf_current,tmp,RHP_IKEV2_COOKIE_SECRET_LEN);
    if( err ){
      RHP_BUG("%d",err);
      goto error;
    }

    err = _rhp_ikev2_cookie_prf_old->set_key(_rhp_ikev2_cookie_prf_old,_rhp_ikev2_cookie_secret_current,RHP_IKEV2_COOKIE_SECRET_LEN);
    if( err ){
      RHP_BUG("%d",err);
      goto error;
    }

    memcpy(_rhp_ikev2_cookie_secret_old,_rhp_ikev2_cookie_secret_current,RHP_IKEV2_COOKIE_SECRET_LEN);
    memcpy(_rhp_ikev2_cookie_secret_current,tmp,RHP_IKEV2_COOKIE_SECRET_LEN);

    _rhp_ikev2_cookie_secret_version++;
    if( _rhp_ikev2_cookie_secret_version == 0 ){
    	_rhp_ikev2_cookie_secret_version = 1;
    }

    RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_COOKIE_TIMER_COOKIE_DATA,"xxu",ctx,timer,_rhp_ikev2_cookie_secret_version);

  }else{
    RHP_BUG("");
  }

error:
  rhp_timer_reset(&(_rhp_ikev2_cookie_timer));
  rhp_timer_add(&(_rhp_ikev2_cookie_timer),(time_t)rhp_gcfg_ikesa_cookie_refresh_interval);

  RHP_UNLOCK(&rhp_vpn_lock);

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_COOKIE_TIMER_RTRN,"xx",ctx,timer);
  return;
}

int rhp_ikev2_setup_cookie_timer()
{
  int err;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SETUP_COOKIE_TIMER,"");

  if( rhp_random_bytes(_rhp_ikev2_cookie_secret_current,RHP_IKEV2_COOKIE_SECRET_LEN) ){
    RHP_BUG("");
    return -EINVAL;
  }
  memset(_rhp_ikev2_cookie_secret_old,0,RHP_IKEV2_COOKIE_SECRET_LEN);

  _rhp_ikev2_cookie_prf_current = rhp_crypto_prf_alloc(RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA1);
  if( _rhp_ikev2_cookie_prf_current == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  _rhp_ikev2_cookie_prf_old = rhp_crypto_prf_alloc(RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA1);
  if( _rhp_ikev2_cookie_prf_old == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  err = _rhp_ikev2_cookie_prf_current->set_key(_rhp_ikev2_cookie_prf_current,
  		_rhp_ikev2_cookie_secret_current,RHP_IKEV2_COOKIE_SECRET_LEN);

  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

  _rhp_atomic_init(&_rhp_ikesa_cookie_pend_pkts);

  rhp_timer_init(&(_rhp_ikev2_cookie_timer),_rhp_ikev2_ike_sa_init_cookie_timer,NULL);
  rhp_timer_add(&(_rhp_ikev2_cookie_timer),(time_t)rhp_gcfg_ikesa_cookie_refresh_interval);

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SETUP_COOKIE_TIMER_RTRN,"");
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SETUP_COOKIE_TIMER_RTRN,"E",err);
	return err;
}


// 16 : sizeof(ipv6_addr)
#define RHP_GEN_COOKIE_BUF_LEN	(RHP_PROTO_IKE_NONCE_MAX_SZ + 16 + RHP_PROTO_IKE_SPI_SIZE + RHP_IKEV2_COOKIE_SECRET_LEN)
static __thread u8 _rhp_gen_cookie_buf[RHP_GEN_COOKIE_BUF_LEN];

static int _rhp_ikev2_ike_sa_init_gen_cookie(rhp_ikev2_mesg* rx_ikemesg,int flag_current_cookie,
		rhp_ikev2_payload* nir_payload_i,u8* cookie_r)
{
  int err = -EINVAL;
  int buf_len = 0;
  u8* nonce_i;
  int nonce_i_len;
  u8* p = _rhp_gen_cookie_buf;
  rhp_crypto_prf* prf;

	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_GEN_COOKIE,"xdxx",rx_ikemesg,flag_current_cookie,nir_payload_i,cookie_r);

  nonce_i_len = nir_payload_i->ext.nir->get_nonce_len(nir_payload_i);

  nonce_i = nir_payload_i->ext.nir->get_nonce(nir_payload_i);
  if( nonce_i == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_GEN_COOKIE_NO_NONCE_I,"xx",rx_ikemesg,nir_payload_i);
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

  buf_len += nonce_i_len;
  if( buf_len > RHP_GEN_COOKIE_BUF_LEN ){
  	RHP_BUG("%d, %d",buf_len,RHP_GEN_COOKIE_BUF_LEN);
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }
  memcpy(p,nonce_i,nonce_i_len);
  p += nonce_i_len;

  if( rx_ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE ){

  	buf_len += sizeof(u32);
    if( buf_len > RHP_GEN_COOKIE_BUF_LEN ){
    	RHP_BUG("%d, %d",buf_len,RHP_GEN_COOKIE_BUF_LEN);
    	err = RHP_STATUS_INVALID_MSG;
    	goto error;
    }
  	memcpy(p,&(rx_ikemesg->rx_pkt->l3.iph_v4->src_addr),sizeof(u32));
  	p += sizeof(u32);

  }else if( rx_ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE ){

  	buf_len += 16;
    if( buf_len > RHP_GEN_COOKIE_BUF_LEN ){
    	RHP_BUG("%d, %d",buf_len,RHP_GEN_COOKIE_BUF_LEN);
    	err = RHP_STATUS_INVALID_MSG;
    	goto error;
    }
  	memcpy(p,&(rx_ikemesg->rx_pkt->l3.iph_v6->src_addr),16);
  	p += 16;

  }else{
  	RHP_BUG("%d",rx_ikemesg->rx_pkt->type);
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

  buf_len += RHP_PROTO_IKE_SPI_SIZE;
  if( buf_len > RHP_GEN_COOKIE_BUF_LEN ){
  	RHP_BUG("%d, %d",buf_len,RHP_GEN_COOKIE_BUF_LEN);
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }
  memcpy(p,&(rx_ikemesg->rx_pkt->app.ikeh->init_spi),RHP_PROTO_IKE_SPI_SIZE);
  p += RHP_PROTO_IKE_SPI_SIZE;

  if( flag_current_cookie ){
    prf = _rhp_ikev2_cookie_prf_current;
    *((u32*)cookie_r) = htonl(_rhp_ikev2_cookie_secret_version);
  }else{
    prf = _rhp_ikev2_cookie_prf_old;
    *((u32*)cookie_r) = htonl((_rhp_ikev2_cookie_secret_version - 1));
  }

  err = prf->compute(prf,_rhp_gen_cookie_buf,buf_len,(cookie_r+sizeof(u32)),(RHP_IKEV2_COOKIE_LEN-sizeof(u32)));
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_GEN_COOKIE_RTRN,"xxp",rx_ikemesg,nir_payload_i,RHP_IKEV2_COOKIE_LEN,cookie_r);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_GEN_COOKIE_ERR,"xxE",rx_ikemesg,nir_payload_i,err);
	return err;
}

static int _rhp_ikev2_ike_sa_init_verify_cookie(rhp_ikev2_mesg* rx_ikemesg,
		rhp_ikev2_payload* n_cookie_payload,rhp_ikev2_payload* nir_payload_i,u8* new_cookie_r)
{
  int err = -EINVAL,err2;
  u8* cookie = n_cookie_payload->ext.n->get_data(n_cookie_payload);
  u32 ver;
  int ver_flag;

	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_VERIFY_COOKIE,"xxxx",rx_ikemesg,n_cookie_payload,nir_payload_i,new_cookie_r);

  if( cookie == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_VERIFY_COOKIE_NO_COOKIE_DATA,"xxx",rx_ikemesg,n_cookie_payload,nir_payload_i);
    goto error;
  }

  ver = ntohl(*((u32*)cookie));

  RHP_LOCK(&rhp_vpn_lock);

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_VERIFY_COOKIE_COOKIE_VER,"xuu",rx_ikemesg,ver,_rhp_ikev2_cookie_secret_version);

  if( ver == _rhp_ikev2_cookie_secret_version ){

    ver_flag = 1;

  }else if( ver &&
  				 ((ver == 0xFFFFFFFF && _rhp_ikev2_cookie_secret_version == 1) ||
  					(ver == (_rhp_ikev2_cookie_secret_version - 1))) ){

  	ver_flag = 0;

  }else{

  	err = RHP_STATUS_COOKIE_NOT_MATCHED;
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_VERIFY_COOKIE_BAD_COOKIE_VER,"xuu",rx_ikemesg,ver,_rhp_ikev2_cookie_secret_version);
    goto gen_new_cookie_l;
  }

  err = _rhp_ikev2_ike_sa_init_gen_cookie(rx_ikemesg,ver_flag,nir_payload_i,new_cookie_r);
  if( err ){
    RHP_BUG("%d",err);
    goto error_l;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_VERIFY_COOKIE_COOKIE_DATA,"xpp",rx_ikemesg,RHP_IKEV2_COOKIE_LEN,new_cookie_r,RHP_IKEV2_COOKIE_LEN,cookie);

  if( memcmp(new_cookie_r,cookie,RHP_IKEV2_COOKIE_LEN) ){

    err = RHP_STATUS_COOKIE_NOT_MATCHED;

    if( !ver_flag ){
      RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_VERIFY_COOKIE_BAD_COOKIE_1,"xpp",rx_ikemesg,RHP_IKEV2_COOKIE_LEN,new_cookie_r,RHP_IKEV2_COOKIE_LEN,cookie);
      goto gen_new_cookie_l;
    }

    RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_VERIFY_COOKIE_BAD_COOKIE_2,"xpp",rx_ikemesg,RHP_IKEV2_COOKIE_LEN,new_cookie_r,RHP_IKEV2_COOKIE_LEN,cookie);
    goto error_l;
  }

  RHP_UNLOCK(&rhp_vpn_lock);

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKEV2_VERIFY_COOKIE_OK,"K",rx_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_VERIFY_COOKIE_RTRN,"xx",rx_ikemesg,nir_payload_i);
  return 0;

error_l:
  RHP_UNLOCK(&rhp_vpn_lock);
error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKEV2_VERIFY_COOKIE_ERR,"KE",rx_ikemesg,err);
	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_VERIFY_COOKIE_ERR,"xxE",rx_ikemesg,nir_payload_i,err);
	return err;

gen_new_cookie_l:
  err2 = _rhp_ikev2_ike_sa_init_gen_cookie(rx_ikemesg,1,nir_payload_i,new_cookie_r);
  if( err2 ){
    RHP_BUG("%d",err2);
    err = err2;
  }else{
  	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKEV2_VERIFY_COOKIE_ERR_GEN_NEW_COOKIE,"K",rx_ikemesg);
  }
  goto error_l;
}

static void _rhp_ikev2_ike_sa_init_cookie_task(rhp_packet* pkt_i)
{
  int err = 0;
  rhp_ikev2_mesg* rx_ikemesg = NULL;
  rhp_ikev2_payload* n_cookie_payload = NULL;
  u8 new_cookie[RHP_IKEV2_COOKIE_LEN];
  int new_cookie_created = 0;
  rhp_ikev2_payload* nir_payload_i = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_COOKIE_TASK,"x",pkt_i);

  _rhp_atomic_dec(&_rhp_ikesa_cookie_pend_pkts);


  err = rhp_ikev2_new_mesg_rx(pkt_i,NULL,NULL,NULL,&rx_ikemesg,&n_cookie_payload,&nir_payload_i,NULL);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  if( nir_payload_i == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_COOKIE_TASK_NO_NIR_PAYLOAD_I,"x",pkt_i);
  	goto error;
  }

  if( n_cookie_payload ){

  	int data_len = n_cookie_payload->ext.n->get_data_len(n_cookie_payload);

  	if( data_len != RHP_IKEV2_COOKIE_LEN ){
    	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_COOKIE_TASK_BAD_COOKIE_LEN,"xxd",pkt_i,n_cookie_payload,data_len);
  		goto error;
  	}

  	err = _rhp_ikev2_ike_sa_init_verify_cookie(rx_ikemesg,n_cookie_payload,nir_payload_i,new_cookie);
  	if( err == 0 ){
    	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_COOKIE_TASK_REDISPATCHE_1,"xx",pkt_i,n_cookie_payload);
    	goto redispatch;
  	}else if( err && err != RHP_STATUS_COOKIE_NOT_MATCHED ){
    	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_COOKIE_TASK_COOKIE_NOT_MATCHED,"xxE",pkt_i,n_cookie_payload,err);
    	goto error;
    }
  	err = 0;

  	new_cookie_created = 1;
  }

  if( !rhp_ikesa_cookie_active(0) ){
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_COOKIE_TASK_REDISPATCHE_2,"xx",pkt_i,n_cookie_payload);
  	goto redispatch;
  }

  if( !new_cookie_created ){

    RHP_LOCK(&rhp_vpn_lock);

    err = _rhp_ikev2_ike_sa_init_gen_cookie(rx_ikemesg,1,nir_payload_i,new_cookie);
    if( err ){

      RHP_BUG("%d",err);

      RHP_UNLOCK(&rhp_vpn_lock);
      goto error;
    }

    RHP_UNLOCK(&rhp_vpn_lock);
  }

  rhp_ikev2_ike_sa_init_tx_error_rep(rx_ikemesg,RHP_PROTO_IKE_NOTIFY_ST_COOKIE,
  		(unsigned long)new_cookie);

	rhp_ikev2_g_statistics_inc(tx_ikev2_resp_cookie_packets);

  rhp_ikev2_unhold_mesg(rx_ikemesg);
  rhp_pkt_unhold(pkt_i);

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_COOKIE_TASK_RTRN,"xx",pkt_i,n_cookie_payload);
  return;

redispatch:
	if( rhp_wts_dispach_ok(RHP_WTS_DISP_LEVEL_HIGH_2,0) ){

		if( rx_ikemesg ){
			pkt_i->cookie_checked_rx_mesg = rx_ikemesg;
			rhp_ikev2_hold_mesg(rx_ikemesg);
		}

		err = rhp_netsock_rx_dispach_packet(pkt_i);
		if( err ){
			RHP_BUG("%d",err);
			rhp_pkt_unhold(pkt_i);
    }

  }else{
  	rhp_pkt_unhold(pkt_i);
  }

	if( rx_ikemesg ){
		rhp_ikev2_unhold_mesg(rx_ikemesg);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_COOKIE_TASK_RTRN_REDISPATCH,"xx",pkt_i,n_cookie_payload);
  return;

error:
  if( rx_ikemesg ){
    rhp_ikev2_unhold_mesg(rx_ikemesg);
  }

  rhp_pkt_unhold(pkt_i);

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_COOKIE_TASK_ERR,"xx",pkt_i,n_cookie_payload);
  return;
}


int rhp_ikev2_ike_sa_init_disp_cookie_handler(rhp_packet* pkt_i)
{
  int err;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_DISP_COOKIE_HANDLER,"x",pkt_i);

	if( _rhp_atomic_read(&_rhp_ikesa_cookie_pend_pkts) >= rhp_gcfg_ikesa_cookie_max_pend_packets ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_DISP_COOKIE_HANDLER_BUSY_1,"xd",pkt_i,_rhp_ikesa_cookie_pend_pkts.c);
    return -EBUSY;
	}

  if( !rhp_wts_dispach_ok(RHP_WTS_DISP_LEVEL_LOW_3,1) ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_DISP_COOKIE_HANDLER_BUSY_2,"x",pkt_i);
    return -EBUSY;
  }

  rhp_pkt_hold(pkt_i);
  pkt_i->process_packet = _rhp_ikev2_ike_sa_init_cookie_task;

  _rhp_atomic_inc(&_rhp_ikesa_cookie_pend_pkts);

  // Cookies task is dispatched to a MISC worker.
  err = rhp_wts_sta_invoke_task(RHP_WTS_DISP_RULE_MISC,
					RHP_WTS_STA_TASK_NAME_PKT,RHP_WTS_DISP_LEVEL_LOW_3,pkt_i,pkt_i);

  if( err ){
    rhp_pkt_unhold(pkt_i);
    _rhp_atomic_dec(&_rhp_ikesa_cookie_pend_pkts);
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_DISP_COOKIE_HANDLER_ADD_TASK_ERR,"xE",pkt_i,err);
    return err;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_DISP_COOKIE_HANDLER_RTRN,"x",pkt_i);
  return 0;
}

// This API internally (in sa_payload->set_def_ikesa_prop()) acquire rhp_cfg_lock. So, a caller must not call this API
// with rlm->lock and rhp_cfg_lock locked.
rhp_ikev2_mesg* rhp_ikev2_new_pkt_ike_sa_init_req(
		rhp_ikesa* ikesa,u16 dhgrp_id,int cookie_len,u8* cookie)
{
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_SA_INIT_REQ,"x",ikesa);

  tx_ikemesg = rhp_ikev2_new_mesg_tx(RHP_PROTO_IKE_EXCHG_IKE_SA_INIT,0,0);
  if( tx_ikemesg == NULL ){
    RHP_BUG("");
    goto error;
  }

  if( cookie ){

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    ikepayload->ext.n->set_protocol_id(ikepayload,0);

    ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_COOKIE);

    if( ikepayload->ext.n->set_data(ikepayload,cookie_len,cookie) ){
      RHP_BUG("");
      goto error;
    }
  }

  {
    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_SA,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.sa->set_def_ikesa_prop(ikepayload,NULL,0,dhgrp_id) ){
      RHP_BUG("");
      goto error;
    }
  }

  {
    int key_len;
    u8* key = ikesa->dh->get_my_pub_key(ikesa->dh,&key_len);

    if( key == NULL ){
      RHP_BUG("");
      goto error;
    }

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_KE,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.ke->set_key(ikepayload,ikesa->dh->grp,key_len,key) ){
      RHP_BUG("");
      goto error;
    }
  }

  {
    int nonce_len = ikesa->nonce_i->get_nonce_len(ikesa->nonce_i);
    u8* nonce = ikesa->nonce_i->get_nonce(ikesa->nonce_i);

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

  if( rhp_gcfg_ikev2_enable_fragmentation ){

		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);
		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_FRAG_SUPPORTED);

		ikepayload->set_non_critical(ikepayload,1);
  }


  {
    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_V,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.vid->copy_my_app_vid(ikepayload) ){
      RHP_BUG("");
      goto error;
    }
  }

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_SA_INIT_REQ_RTRN,"xx",ikesa,tx_ikemesg);

  return tx_ikemesg;

error:
  if( tx_ikemesg ){
    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKEV2_TX_ALLOC_IKE_SA_INIT_REQ_ERR,"P",ikesa);
  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_SA_INIT_REQ_ERR,"x",ikesa);
  return NULL;
}

int rhp_ikev2_ike_sa_init_i_try_secondary(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ip_addr* secondary_peer_addr,rhp_cfg_if* cfg_if,rhp_ikev2_mesg** new_1st_mesg_r)
{
  int err = -EINVAL;
  rhp_ikev2_mesg *old_1st_mesg,*new_1st_mesg = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_I_TRY_SECONDARY,"xxxxdd",vpn,ikesa,secondary_peer_addr,cfg_if,vpn->sess_resume.gen_by_sess_resume,ikesa->gen_by_sess_resume);
  if( secondary_peer_addr ){
  	rhp_ip_addr_dump("rhp_ikev2_ike_sa_init_i_try_secondary:secondary_peer_addr",secondary_peer_addr);
  }
  if( cfg_if ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_I_TRY_SECONDARY_CFG_IF_NAME,"xxs",vpn,cfg_if,cfg_if->if_name);
  }

  if( secondary_peer_addr == NULL && cfg_if == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  {
		old_1st_mesg = ikesa->signed_octets.ikemesg_i_1st;
		ikesa->signed_octets.ikemesg_i_1st = NULL;
		rhp_ikev2_unhold_mesg(old_1st_mesg);


		if( ikesa->req_retx_pkt ){
			ikesa->set_retrans_request(ikesa,NULL);
		}

		if( ikesa->req_retx_ikemesg ){

			rhp_ikev2_unhold_mesg(ikesa->req_retx_ikemesg);
			ikesa->req_retx_ikemesg = NULL;
		}
  }

  if( secondary_peer_addr ){

  	vpn->set_peer_addr(vpn,secondary_peer_addr,secondary_peer_addr);
  }

  if( cfg_if ){

  	if( cfg_if->ifc == NULL ){
  		RHP_BUG("");
  		err = -EINVAL;
  		goto error;
  	}

  	RHP_LOCK(&(cfg_if->ifc->lock));
  	{
  		rhp_ifc_addr* ifc_addr;

  		ifc_addr = cfg_if->ifc->select_src_addr(cfg_if->ifc,
  								vpn->peer_addr.addr_family,vpn->peer_addr.addr.raw,cfg_if->is_by_def_route);

  		if( ifc_addr == NULL ){
  	  	RHP_UNLOCK(&(cfg_if->ifc->lock));
  			err = -ENOENT;
  			goto error;
  		}

  		vpn->set_local_net_info(vpn,cfg_if->ifc,ifc_addr->addr.addr_family,ifc_addr->addr.addr.raw);
  	}
  	RHP_UNLOCK(&(cfg_if->ifc->lock));
  }


  if( vpn->sess_resume.gen_by_sess_resume ){

  	rhp_vpn_sess_resume_material* sess_resume_material_i = vpn->sess_resume_get_material_i(vpn);

  	if( sess_resume_material_i == NULL ){
  		RHP_BUG("");
  		err = -EINVAL;
  		goto error;
  	}

  	new_1st_mesg = rhp_ikev2_new_pkt_sess_resume_req(vpn,ikesa,sess_resume_material_i,0,NULL);

  }else{

  	new_1st_mesg = rhp_ikev2_new_pkt_ike_sa_init_req(ikesa,0,0,NULL);
  }
	if( new_1st_mesg == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

  ikesa->req_message_id = (u32)-1;

  ikesa->signed_octets.ikemesg_i_1st = new_1st_mesg;
  rhp_ikev2_hold_mesg(new_1st_mesg);

  *new_1st_mesg_r = new_1st_mesg;


  if( vpn->peer_addr.addr_family == AF_INET ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKEV2_IKE_SA_INIT_TRY_SECONDARY_ROUTE,"4Ws",vpn->peer_addr.addr.v4,vpn->peer_addr.port,vpn->local.if_info.if_name);
  }else if( vpn->peer_addr.addr_family == AF_INET6 ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKEV2_IKE_SA_INIT_TRY_SECONDARY_ROUTE_V6,"6Ws",vpn->peer_addr.addr.v6,vpn->peer_addr.port,vpn->local.if_info.if_name);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_I_TRY_SECONDARY_RTRN,"xxxx",vpn,ikesa,secondary_peer_addr,cfg_if);
  return 0;

error:
  if( new_1st_mesg ){
    rhp_ikev2_unhold_mesg(new_1st_mesg);
  }

  if( vpn->peer_addr.addr_family == AF_INET ){
  	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKEV2_IKE_SA_INIT_TRY_SECONDARY_ROUTE_ERR,"4Ws",vpn->peer_addr.addr.v4,vpn->peer_addr.port,vpn->local.if_info.if_name);
  }else if( vpn->peer_addr.addr_family == AF_INET6 ){
  	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKEV2_IKE_SA_INIT_TRY_SECONDARY_ROUTE_V6_ERR,"6Ws",vpn->peer_addr.addr.v6,vpn->peer_addr.port,vpn->local.if_info.if_name);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_I_TRY_SECONDARY_ERR,"xxxxE",vpn,ikesa,secondary_peer_addr,cfg_if,err);
  return err;
}


static int _rhp_ikev2_rx_ike_sa_init_i_invalid_ke(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_payload* n_payload_r)
{
  int err = -EINVAL;
  u8* n_data;
  u16 dhgrp_id = 0;
  rhp_ikev2_mesg *old_1st_mesg,*new_1st_mesg = NULL;
  rhp_vpn_realm* rlm;
  int n_data_len;
  u16 old_grp = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_I_INVALID_KE,"xxxx",vpn,vpn->rlm,ikesa,n_payload_r);

  n_data_len = n_payload_r->ext.n->get_data_len(n_payload_r);

  if( n_data_len != sizeof(u16) ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_I_INVALID_KE_BAD_N_DATA_LEN,"xxxd",vpn,vpn->rlm,ikesa,n_data_len);
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

  n_data = n_payload_r->ext.n->get_data(n_payload_r);

  if( n_data == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_I_INVALID_KE_NO_N_DATA,"xxx",vpn,vpn->rlm,ikesa);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  dhgrp_id = ntohs(*((u16*)n_data));

	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_I_INVALID_KE_NOTIFIED_DHGRP,"xxxxw",vpn,vpn->rlm,ikesa,dhgrp_id);

  old_1st_mesg = ikesa->signed_octets.ikemesg_i_1st;
  ikesa->signed_octets.ikemesg_i_1st = NULL;
  rhp_ikev2_unhold_mesg(old_1st_mesg);

  old_grp = ikesa->dh->grp;
  rhp_crypto_dh_free(ikesa->dh);

  ikesa->dh = rhp_crypto_dh_alloc(dhgrp_id);
  if( ikesa->dh == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  if( ikesa->dh->generate_key(ikesa->dh) ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  new_1st_mesg = rhp_ikev2_new_pkt_ike_sa_init_req(
  		ikesa,dhgrp_id,ikesa->cookies.cookie_len,ikesa->cookies.cookie);
  if( new_1st_mesg == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  ikesa->req_message_id = (u32)-1;

  ikesa->signed_octets.ikemesg_i_1st = new_1st_mesg;
  rhp_ikev2_hold_mesg(new_1st_mesg);


  rhp_ikev2_send_request(vpn,ikesa,new_1st_mesg,RHP_IKEV2_MESG_HANDLER_IKESA_INIT);
  rhp_ikev2_unhold_mesg(new_1st_mesg);

  ikesa->timers->retx_counter = 0;

  rlm = vpn->rlm;
  if( rlm == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_I_INVALID_KE_NO_RLM,"xx",vpn,ikesa);
  	goto error;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_I_INVALID_KE_RLM_NOT_ACTIVE,"xxx",vpn,vpn->rlm,ikesa);
  	goto error_l;
  }

  ikesa->timers->start_lifetime_timer(vpn,ikesa,rlm->ikesa.lifetime_larval,1);

  RHP_UNLOCK(&(rlm->lock));

 	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_SA_INIT_RETRY_KE,"VPww",vpn,ikesa,old_grp,dhgrp_id);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_I_INVALID_KE_RTRN,"xxx",vpn,vpn->rlm,ikesa);
	return 0;

error_l:
  RHP_UNLOCK(&(rlm->lock));
error:
  if( new_1st_mesg ){
    rhp_ikev2_unhold_mesg(new_1st_mesg);
  }

 	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_SA_INIT_RETRY_KE_ERR,"VPwwE",vpn,ikesa,old_grp,dhgrp_id,err);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_I_INVALID_KE_ERR,"xxxE",vpn,vpn->rlm,ikesa,err);
	return err;
}


#ifdef RHP_PKT_DBG_IKEV2_BAD_COOKIE_TEST

#define RHP_IKEV2_TEST_BAD_COOKIE_TX_TIMES	(RHP_IKESA_MAX_COOKIE_RETRIES - 1)
static int _rhp_ikev2_test_bad_cookie_tx_times =	0;

void rhp_ikev2_test_bad_cookie(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_payload* n_payload_r,u8* cookie,int cookie_len)
{

	if( cookie_len <= 1 || cookie == NULL ){
		RHP_BUG("");
		return;
	}

	if( _rhp_ikev2_test_bad_cookie_tx_times >= RHP_IKEV2_TEST_BAD_COOKIE_TX_TIMES ){
		_rhp_ikev2_test_bad_cookie_tx_times = 0;
		return;
	}

	cookie[4] <<= 1;

	if( ikesa->cookies.cookie ){
		ikesa->cookies.cookie[4] <<= 1;
	}

	_rhp_ikev2_test_bad_cookie_tx_times++;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_I_COOKIE_COOKIE_DATA_TX_BAD_COOKIE,"dxxxxp",_rhp_ikev2_test_bad_cookie_tx_times,vpn,vpn->rlm,ikesa,n_payload_r,cookie_len,cookie);

	return;
}

#endif // RHP_PKT_DBG_IKEV2_BAD_COOKIE_TEST


static int _rhp_ikev2_rx_ike_sa_init_i_cookie(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_payload* n_payload_r)
{
  int err = -EINVAL;
  int cookie_len = 0;
  u8* cookie = NULL;
  rhp_ikev2_mesg *old_1st_mesg,*new_1st_mesg = NULL;
  rhp_vpn_realm* rlm;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_I_COOKIE,"xxxx",vpn,vpn->rlm,ikesa,n_payload_r);

  cookie_len = n_payload_r->ext.n->get_data_len(n_payload_r);

  if( cookie_len < RHP_PROTO_IKE_NOTIFY_COOKIE_MIN_SZ && cookie_len > RHP_PROTO_IKE_NOTIFY_COOKIE_MAX_SZ ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_I_COOKIE_BAD_COOKIE_LEN,"xxxddd",vpn,vpn->rlm,ikesa,cookie_len,RHP_PROTO_IKE_NOTIFY_COOKIE_MIN_SZ,RHP_PROTO_IKE_NOTIFY_COOKIE_MAX_SZ);
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

  cookie = n_payload_r->ext.n->get_data(n_payload_r);
  if( cookie == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_I_COOKIE_NO_COOKIE_DATA,"xxxx",vpn,vpn->rlm,ikesa,n_payload_r);
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_I_COOKIE_COOKIE_DATA,"xxxxp",vpn,vpn->rlm,ikesa,n_payload_r,cookie_len,cookie);

  if( ikesa->cookies.cookie ){
    _rhp_free(ikesa->cookies.cookie);
    ikesa->cookies.cookie = NULL;
    ikesa->cookies.cookie_len = 0;
  }

  ikesa->cookies.cookie = (u8*)_rhp_malloc(cookie_len);
  if( ikesa->cookies.cookie == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  ikesa->cookies.cookie_len = cookie_len;
  memcpy(ikesa->cookies.cookie,cookie,cookie_len);

#ifdef RHP_PKT_DBG_IKEV2_BAD_COOKIE_TEST
  rhp_ikev2_test_bad_cookie(vpn,ikesa,n_payload_r,cookie,cookie_len);
#endif // RHP_PKT_DBG_IKEV2_BAD_COOKIE_TEST


  old_1st_mesg = ikesa->signed_octets.ikemesg_i_1st;
  ikesa->signed_octets.ikemesg_i_1st = NULL;
  rhp_ikev2_unhold_mesg(old_1st_mesg);
  old_1st_mesg = NULL;


  new_1st_mesg = rhp_ikev2_new_pkt_ike_sa_init_req(ikesa,ikesa->dh->grp,cookie_len,cookie);
  if( new_1st_mesg == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  ikesa->req_message_id = (u32)-1;

  ikesa->signed_octets.ikemesg_i_1st = new_1st_mesg;
  rhp_ikev2_hold_mesg(new_1st_mesg);


  rhp_ikev2_send_request(vpn,ikesa,new_1st_mesg,RHP_IKEV2_MESG_HANDLER_IKESA_INIT);
  rhp_ikev2_unhold_mesg(new_1st_mesg);
  new_1st_mesg = NULL;

  ikesa->timers->retx_counter = 0;

  rlm = vpn->rlm;
  if( rlm == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_I_COOKIE_NO_RLM,"xxx",vpn,vpn->rlm,ikesa);
  	goto error;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_I_COOKIE_RLM_NOT_ACTIVE,"xxx",vpn,vpn->rlm,ikesa);
  	goto error_l;
  }

  ikesa->timers->start_lifetime_timer(vpn,ikesa,rlm->ikesa.lifetime_larval,1);

  RHP_UNLOCK(&(rlm->lock));

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_COOKIE_OK,"VP",vpn,ikesa);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_I_COOKIE_RTRN,"xxxx",vpn,vpn->rlm,ikesa,n_payload_r);
	return 0;

error_l:
  RHP_UNLOCK(&(rlm->lock));
error:
  if( new_1st_mesg ){
    rhp_ikev2_unhold_mesg(new_1st_mesg);
  }

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_COOKIE_ERR,"VPE",vpn,ikesa,err);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_I_COOKIE_ERR,"xxxxE",vpn,vpn->rlm,ikesa,n_payload_r,err);
	return err;
}


static int _rhp_ikev2_ike_sa_init_srch_sa_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_ike_sa_init_srch_plds_ctx* s_pld_ctx = (rhp_ike_sa_init_srch_plds_ctx*)ctx;
  rhp_ikev2_sa_payload* sa_payload = (rhp_ikev2_sa_payload*)payload->ext.sa;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_SA_CB,"xdxxx",rx_ikemesg,enum_end,payload,sa_payload,ctx);

  if( sa_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_SA_CB_DUP_ERR,"xd",rx_ikemesg,s_pld_ctx->dup_flag);
  	goto error;
  }

  memset(&(s_pld_ctx->resolved_prop.v2),0,sizeof(rhp_res_sa_proposal));

  err = sa_payload->get_matched_ikesa_prop(payload,&(s_pld_ctx->resolved_prop.v2));
  if( err ){

  	s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_NO_PROPOSAL_CHOSEN;

  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_SA_CB_NO_MATCHED_PROP,"xxxE",rx_ikemesg,s_pld_ctx->vpn,s_pld_ctx->ikesa,err);
    goto error;
  }

  s_pld_ctx->prf_key_len = rhp_crypto_prf_key_len(s_pld_ctx->resolved_prop.v2.prf_id);
  if( s_pld_ctx->prf_key_len < 0 ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_SA_CB_PRF_KEY_LEN_ERR,"xxxd",rx_ikemesg,s_pld_ctx->vpn,s_pld_ctx->ikesa,s_pld_ctx->prf_key_len);
    goto error;
  }

  s_pld_ctx->sa_payload = payload;
  err = 0;

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_PARSE_SA_PAYLOAD,"Kbbwdwww",rx_ikemesg,s_pld_ctx->resolved_prop.v2.number,s_pld_ctx->resolved_prop.v2.protocol_id,s_pld_ctx->resolved_prop.v2.encr_id,s_pld_ctx->resolved_prop.v2.encr_key_bits,s_pld_ctx->resolved_prop.v2.prf_id,s_pld_ctx->resolved_prop.v2.integ_id,s_pld_ctx->resolved_prop.v2.dhgrp_id);

error:
  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_SA_CB_RTRN,"xxxE",rx_ikemesg,payload,sa_payload,err);
  return err;
}


static int _rhp_ikev2_ike_sa_init_srch_ke_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_ike_sa_init_srch_plds_ctx* s_pld_ctx = (rhp_ike_sa_init_srch_plds_ctx*)ctx;
  rhp_ikev2_ke_payload* ke_payload = (rhp_ikev2_ke_payload*)payload->ext.ke;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_KE_CB,"xdxxx",rx_ikemesg,enum_end,payload,ke_payload,ctx);

  if( ke_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_KE_CB_DUP_ERR,"xd",rx_ikemesg,s_pld_ctx->dup_flag);
  	goto error;
  }

  s_pld_ctx->dhgrp = ke_payload->get_dhgrp(payload);
  if( s_pld_ctx->dhgrp != s_pld_ctx->resolved_prop.v2.dhgrp_id ){

  	s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_INVALID_KE_PAYLOAD;
  	s_pld_ctx->notify_error_arg = s_pld_ctx->resolved_prop.v2.dhgrp_id;

  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_KE_CB_DHGRP_NOT_MATCHED,"xxxww",rx_ikemesg,s_pld_ctx->vpn,s_pld_ctx->ikesa,s_pld_ctx->dhgrp,s_pld_ctx->resolved_prop.v2.dhgrp_id);
  	goto error;
  }

  s_pld_ctx->peer_dh_pub_key_len = ke_payload->get_key_len(payload);
  s_pld_ctx->peer_dh_pub_key = ke_payload->get_key(payload);
  if( s_pld_ctx->peer_dh_pub_key_len < 0 || s_pld_ctx->peer_dh_pub_key == NULL ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_KE_CB_GET_DH_PUTKEY_ERR,"xxxd",rx_ikemesg,s_pld_ctx->vpn,s_pld_ctx->ikesa,s_pld_ctx->peer_dh_pub_key_len);
  	goto error;
  }


  s_pld_ctx->ke_payload = payload;
  err = 0;

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_PARSE_KE_PAYLOAD,"Kw",rx_ikemesg,s_pld_ctx->dhgrp);

error:
  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_KE_CB_RTRN,"xxxE",rx_ikemesg,payload,ke_payload,err);
  return err;
}

int rhp_ikev2_ike_sa_init_srch_nir_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_ike_sa_init_srch_plds_ctx* s_pld_ctx = (rhp_ike_sa_init_srch_plds_ctx*)ctx;
  rhp_ikev2_nir_payload* nir_payload = (rhp_ikev2_nir_payload*)payload->ext.sa;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_NIR_CB,"xdxxx",rx_ikemesg,enum_end,payload,nir_payload,ctx);

  if( nir_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_NIR_CB_DUP_ERR,"xd",rx_ikemesg,s_pld_ctx->dup_flag);
  	goto error;
  }

  s_pld_ctx->nonce_len = nir_payload->get_nonce_len(payload);

  if( (s_pld_ctx->prf_key_len >> 1) > s_pld_ctx->nonce_len ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_NIR_CB_BAD_NONCE_LEN,"xxxdd",rx_ikemesg,s_pld_ctx->vpn,s_pld_ctx->ikesa,(s_pld_ctx->prf_key_len >> 1),s_pld_ctx->nonce_len);
  	goto error;
  }

  s_pld_ctx->nonce = nir_payload->get_nonce(payload);
  if( s_pld_ctx->nonce == NULL ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_NIR_CB_GET_NONCE_ERR,"xxx",rx_ikemesg,s_pld_ctx->vpn,s_pld_ctx->ikesa);
  	goto error;
  }

  s_pld_ctx->nir_payload = payload;
  err = 0;

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_PARSE_N_I_R_PAYLOAD,"Kd",rx_ikemesg,s_pld_ctx->nonce_len);

error:
  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_NIR_CB_RTRN,"xxxxE",rx_ikemesg,payload,nir_payload,ctx,err);
  return err;
}

int rhp_ikev2_ike_sa_init_srch_n_cookie_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_ike_sa_init_srch_plds_ctx* s_pld_ctx = (rhp_ike_sa_init_srch_plds_ctx*)ctx;
  rhp_ikev2_n_payload* n_payload = (rhp_ikev2_n_payload*)payload->ext.n;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_N_COOKIE_CB,"xdxxx",rx_ikemesg,enum_end,payload,n_payload,ctx);

  if( n_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_N_COOKIE_CB_DUP_ERR,"xd",rx_ikemesg,s_pld_ctx->dup_flag);
  	goto error;
  }

	if( s_pld_ctx->ikesa->cookies.cookie_retry >= RHP_IKESA_MAX_COOKIE_RETRIES ){
  	err = RHP_STATUS_IKEV2_COOKIE_MAX_RETRIED;
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_I_MAX_COOKIE_RETRIED,"xxxdd",rx_ikemesg,s_pld_ctx->vpn,s_pld_ctx->ikesa,s_pld_ctx->ikesa->cookies.cookie_retry,RHP_IKESA_MAX_COOKIE_RETRIES);
 		goto error;
 	}

	s_pld_ctx->ikesa->cookies.cookie_retry++;

  s_pld_ctx->n_cookie_payload = payload;
  err = RHP_STATUS_IKEV2_RETRY_COOKIE;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_N_COOKIE_CB_RTRN,"xxxx",rx_ikemesg,payload,n_payload,ctx);
  return err;
}

static int _rhp_ikev2_ike_sa_init_srch_n_invald_ke_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_ike_sa_init_srch_plds_ctx* s_pld_ctx = (rhp_ike_sa_init_srch_plds_ctx*)ctx;
  rhp_ikev2_n_payload* n_payload = (rhp_ikev2_n_payload*)payload->ext.n;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_N_INVALID_KE_CB,"xdxxx",rx_ikemesg,enum_end,payload,n_payload,ctx);

  if( n_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_N_INVALID_KE_CB_DUP_ERR,"xd",rx_ikemesg,s_pld_ctx->dup_flag);
  	goto error;
  }

  s_pld_ctx->n_invalid_ke_payload = payload;
  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_N_INVALID_KE_CB_RTRN,"xxxx",rx_ikemesg,payload,n_payload,ctx);
  return err;
}


static int _rhp_ikev2_ike_sa_init_srch_n_error_cb(rhp_ikev2_mesg* ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_ike_sa_init_srch_plds_ctx* s_pld_ctx = (rhp_ike_sa_init_srch_plds_ctx*)ctx;
  rhp_ikev2_n_payload* n_payload = (rhp_ikev2_n_payload*)payload->ext.n;
  u16 notify_mesg_type;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_N_ERROR_CB,"xdxxx",ikemesg,enum_end,payload,n_payload,ctx);

  if( n_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  notify_mesg_type = n_payload->get_message_type(payload);

  //
  // TODO : Handling only interested notify-error codes.
  //
  if( notify_mesg_type >= RHP_PROTO_IKE_NOTIFY_ERR_MIN && notify_mesg_type <= RHP_PROTO_IKE_NOTIFY_ERR_MAX ){

    RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_N_ERROR_CB_ERROR_FOUND,"xxxLw",ikemesg,payload,n_payload,"PROTO_IKE_NOTIFY",notify_mesg_type);

    s_pld_ctx->n_error_payload = payload;
    s_pld_ctx->n_err = notify_mesg_type;

    return RHP_STATUS_ENUM_OK;
  }

  s_pld_ctx->dup_flag++;
  err = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_N_ERROR_CB_RTRN,"xxxxLwE",ikemesg,payload,n_payload,ctx,"PROTO_IKE_NOTIFY",notify_mesg_type,err);
  return err;
}

static int _rhp_ikev2_ike_sa_init_srch_cert_req_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_ike_sa_init_srch_plds_ctx* s_pld_ctx = (rhp_ike_sa_init_srch_plds_ctx*)ctx;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_CERTREQ_CB,"xdxu",rx_ikemesg,enum_end,payload,s_pld_ctx->dup_flag);

  if( enum_end ){

  	if( s_pld_ctx->certreq_payload_head ){

  		s_pld_ctx->certreq_payload_num = s_pld_ctx->dup_flag;
  	 	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_CERTREQ_PAYLOADS,"Kd",rx_ikemesg,s_pld_ctx->certreq_payload_num);

  	}else{

  		RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_CERTREQ_CB_NO_CERT_REQ_PLD,"xxx",rx_ikemesg,s_pld_ctx->vpn,s_pld_ctx->ikesa);
  	 	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_NO_CERTREQ_PAYLOAD,"K",rx_ikemesg);
  	}

  }else{

	  rhp_ikev2_certreq_payload* certreq_payload = (rhp_ikev2_certreq_payload*)payload->ext.cert;
	  rhp_ikev2_payload* certreq_payload_head = NULL;
	  u8 enc;

	  if( certreq_payload == NULL ){
	  	RHP_BUG("");
	  	return -EINVAL;
	  }

	  enc = certreq_payload->get_cert_encoding(payload);

	  if( enc != RHP_PROTO_IKE_CERTENC_X509_CERT_SIG ){

	  	s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;

	  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_CERTREQ_CB_UNKNOWN_ENCODE,"xxxb",rx_ikemesg,s_pld_ctx->vpn,s_pld_ctx->ikesa,enc);

  	 	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_CERTREQ_PAYLOAD_UNSUPPORTED_ENCODE,"Kd",rx_ikemesg,(int)enc);

	  	err = RHP_STATUS_IKEV2_AUTH_FAILED;
	  	goto error;
	  }

	  s_pld_ctx->dup_flag++;

	  if( s_pld_ctx->dup_flag == 1 ){

	  	s_pld_ctx->certreq_payload_head = payload;

	  }else if( s_pld_ctx->dup_flag > rhp_gcfg_max_cert_payloads ){

	    RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_CERTREQ_CB_TOO_MANY,"xxud",rx_ikemesg,payload,s_pld_ctx->dup_flag,rhp_gcfg_max_cert_payloads);

  	 	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_CERTREQ_PAYLOAD_TOO_MANY_REQS,"Kd",rx_ikemesg,s_pld_ctx->dup_flag,rhp_gcfg_max_cert_payloads);

	    err = RHP_STATUS_INVALID_MSG;
	    goto error;

	  }else{

	  	certreq_payload_head = s_pld_ctx->certreq_payload_head;

	  	if( certreq_payload_head->list_next == NULL ){
	  		certreq_payload_head->list_next = payload;
	  	}else{
	  		certreq_payload_head->list_tail->list_next = payload;
	    }
	  	certreq_payload_head->list_tail = payload;
	  }
  }

  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_CERTREQ_CB_RTRN,"xxuE",rx_ikemesg,payload,s_pld_ctx->dup_flag,err);
  return err;
}

int rhp_ikev2_ike_sa_init_srch_n_http_cert_lookup_supported_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_ike_sa_init_srch_plds_ctx* s_pld_ctx = (rhp_ike_sa_init_srch_plds_ctx*)ctx;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_N_HTTP_CERT_LOOKUP_SUPPORTED_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_N_HTTP_CERT_LOOKUP_SUPPORTED_CB_DUP_ERR,"xx",rx_ikemesg,ctx);
    goto error;
  }

  s_pld_ctx->http_cert_lookup_supported = 1;
  err = 0;

 	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_N_HTTP_CERT_LOOKUP_SUPPORTED_PAYLOAD,"K",rx_ikemesg);

error:
	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_N_HTTP_CERT_LOOKUP_SUPPORTED_CB_RTRN,"xxxE",rx_ikemesg,payload,ctx,err);
	return err;
}

int rhp_ikev2_ike_sa_init_srch_n_frag_supported_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_ike_sa_init_srch_plds_ctx* s_pld_ctx = (rhp_ike_sa_init_srch_plds_ctx*)ctx;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_N_FRAG_SUPPORTED_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_N_FRAG_SUPPORTED_CB_DUP_ERR,"xx",rx_ikemesg,ctx);
    goto error;
  }

  s_pld_ctx->frag_supported = 1;
  err = 0;

 	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_N_FRAGMENTATION_SUPPORTED_PAYLOAD,"K",rx_ikemesg);

error:
	RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_SRCH_N_FRAG_SUPPORTED_CB_RTRN,"xxxE",rx_ikemesg,payload,ctx,err);
	return err;
}

//
// IKEv1: s_pld_ctx->vpn may be NULL.
//
int rhp_ikev2_ike_sa_init_srch_my_vid_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
  int err = 0;
	rhp_ike_sa_init_srch_plds_ctx* s_pld_ctx = (rhp_ike_sa_init_srch_plds_ctx*)ctx;
	rhp_ikev2_vid_payload* vid_payload = (rhp_ikev2_vid_payload*)payload->ext.vid;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_MY_VID_CB,"xdxxx",rx_ikemesg,enum_end,payload,vid_payload,ctx);

  if( vid_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  s_pld_ctx->peer_is_rockhopper = vid_payload->is_my_app_id(payload,&(s_pld_ctx->peer_rockhopper_ver));
	err = 0;

	if( s_pld_ctx->peer_is_rockhopper ){
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_V_PAYLOAD_PEER_IS_ROCKHOPPER,"Kd",rx_ikemesg,s_pld_ctx->dup_flag);
	}else{
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_V_PAYLOAD,"Kd",rx_ikemesg,s_pld_ctx->dup_flag);
	}

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_MY_VID_CB_RTRN,"xxxxE",rx_ikemesg,payload,vid_payload,ctx,err);
  return err;
}


static int _rhp_ikev2_rx_ike_sa_init_rep(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_resp_ikemesg,
		rhp_ikev2_mesg* tx_req_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_proto_ike* ikeh;
  rhp_ike_sa_init_srch_plds_ctx s_pld_ctx;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_L,"xxxx",rx_resp_ikemesg,tx_req_ikemesg,vpn,ikesa);

  ikeh = rx_resp_ikemesg->rx_pkt->app.ikeh;

  if( ikesa->state != RHP_IKESA_STAT_I_IKE_SA_INIT_SENT ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_I_IKESA_BAD_STATE,"xxxd",rx_resp_ikemesg,vpn,ikesa,ikesa->state);
    err = RHP_STATUS_BAD_SA_STATE;
    goto error;
  }

  if( rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


  ikesa->timers->quit_lifetime_timer(vpn,ikesa);


  memset(&s_pld_ctx,0,sizeof(rhp_ike_sa_init_srch_plds_ctx));

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  					rhp_ikev2_mesg_srch_cond_n_mesg_id,(void*)((unsigned long)RHP_PROTO_IKE_NOTIFY_ST_COOKIE),
  					rhp_ikev2_ike_sa_init_srch_n_cookie_cb,&s_pld_ctx);

  	if( err == RHP_STATUS_IKEV2_RETRY_COOKIE ){

  		err = _rhp_ikev2_rx_ike_sa_init_i_cookie(vpn,ikesa,s_pld_ctx.n_cookie_payload);
    	if( err ){
    		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_L_COOKIE_RX_ERR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
    		goto error;
    	}

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_L_COOKIE_RETRY,"xxxd",rx_resp_ikemesg,vpn,ikesa,ikesa->cookies.cookie_retry);
    	goto retry;

  	}else if( err != -ENOENT ){

  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_L_COOKIE_RX_ENUM_N_COOKIE_ERR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_RESP_PARSE_N_COOKIE_PAYLOAD_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
    	goto error;

    }else{
    	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_RESP_NO_N_COOKIE_PAYLOAD,"KVP",rx_resp_ikemesg,vpn,ikesa);
    }
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_n_mesg_id,(void*)((unsigned long)RHP_PROTO_IKE_NOTIFY_ERR_INVALID_KE_PAYLOAD),
  			_rhp_ikev2_ike_sa_init_srch_n_invald_ke_cb,&s_pld_ctx);

  	if( err == 0 || err == RHP_STATUS_ENUM_OK ){

 			err = _rhp_ikev2_rx_ike_sa_init_i_invalid_ke(vpn,ikesa,s_pld_ctx.n_invalid_ke_payload);
     	if( err ){
        RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_L_N_INVALID_KE_ERR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
        goto error;
     	}

     	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_L_INVALID_KE_RETRY,"xxx",rx_resp_ikemesg,vpn,ikesa);

     	goto retry;

  	}else if( err != -ENOENT ){
    	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_L_ENUM_N_INVALID_KE_ERR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_RESP_PARSE_N_INVALID_KE_PAYLOAD_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
    	goto error;
    }
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_N),
  			_rhp_ikev2_ike_sa_init_srch_n_error_cb,&s_pld_ctx);

    if( ( err == 0 || err == RHP_STATUS_ENUM_OK ) && (s_pld_ctx.n_error_payload != NULL ) ){

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_L_PEER_NOTIFIED_ERROR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);

     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_RESP_N_ERR_PAYLOAD,"KVPL",rx_resp_ikemesg,vpn,ikesa,"PROTO_IKE_NOTIFY",s_pld_ctx.n_err);

    	err = RHP_STATUS_PEER_NOTIFIED_ERROR;
   	  goto error;

    }else if( err && err != -ENOENT ){
    	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_L_ENUM_N_ERROR_ERR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_RESP_PARSE_N_ERR_PAYLOAD_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
    	goto error;
    }
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_SA),
  			_rhp_ikev2_ike_sa_init_srch_sa_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_L_ENUM_SA_PLD_ERR,"xxxd",rx_resp_ikemesg,vpn,ikesa,err);
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_RESP_PARSE_SA_PAYLOAD_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_N_I_R),
  			rhp_ikev2_ike_sa_init_srch_nir_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_L_ENUM_NIR_PLD_ERR,"xxxd",rx_resp_ikemesg,vpn,ikesa,err);
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_RESP_PARSE_N_I_R_PAYLOAD_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_KE),
  			_rhp_ikev2_ike_sa_init_srch_ke_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_L_ENUM_SA_PLD_ERR,"xxxd",rx_resp_ikemesg,vpn,ikesa,err);
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_RESP_PARSE_KE_PAYLOAD_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,1,
    		rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_CERTREQ),
    		_rhp_ikev2_ike_sa_init_srch_cert_req_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_L_ENUM_CERTREQ_PLD_ERR,"xxxd",rx_resp_ikemesg,vpn,ikesa,err);
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_RESP_PARSE_CERTREQ_PAYLOAD_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
  		goto error;
  	}
  }

  if( rhp_gcfg_hash_url_enabled(RHP_IKE_INITIATOR) ){

  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_n_mesg_id,
  			(void*)((unsigned long)RHP_PROTO_IKE_NOTIFY_ST_HTTP_CERT_LOOKUP_SUPPORTED),
  			rhp_ikev2_ike_sa_init_srch_n_http_cert_lookup_supported_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_L_HTTP_LOOKUP_SUPPORTED_ERR,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_RESP_PARSE_N_HTTP_CERT_LOOKUP_PAYLOAD_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
    	goto error;
  	}

  	ikesa->peer_http_cert_lookup_supported = s_pld_ctx.http_cert_lookup_supported;
  	vpn->peer_http_cert_lookup_supported = s_pld_ctx.http_cert_lookup_supported;
  }

  if( rhp_gcfg_ikev2_enable_fragmentation ){

  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_n_mesg_id,
  			(void*)((unsigned long)RHP_PROTO_IKE_NOTIFY_ST_FRAG_SUPPORTED),
  			rhp_ikev2_ike_sa_init_srch_n_frag_supported_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_L_FRAG_SUPPORTED_ERR,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_RESP_PARSE_N_FRAGMENTATION_PAYLOAD_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
    	goto error;
  	}

  	vpn->exec_ikev2_frag = s_pld_ctx.frag_supported;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_I_ENUM_N_STATUS,"xxxdd",rx_resp_ikemesg,vpn,ikesa,ikesa->peer_http_cert_lookup_supported,vpn->exec_ikev2_frag);

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  			rhp_ikev2_mesg_search_cond_my_verndor_id,NULL,
  			rhp_ikev2_ike_sa_init_srch_my_vid_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_L_ENUM_MY_VENDOR_ID_ERR,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_RESP_PARSE_V_PAYLOAD_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
    	goto error;
  	}
  }


  memcpy(&(ikesa->prop.v2),&(s_pld_ctx.resolved_prop.v2),sizeof(rhp_res_sa_proposal));

  ikesa->prf = rhp_crypto_prf_alloc(s_pld_ctx.resolved_prop.v2.prf_id);
  if( ikesa->prf == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_L_I_PRF_ALLOC_ERR,"xxx",rx_resp_ikemesg,vpn,ikesa);
   	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_RESP_PRF_ALG_ERR,"KVPdE",rx_resp_ikemesg,vpn,ikesa,s_pld_ctx.resolved_prop.v2.prf_id,err);
    err = -EINVAL;
    goto error;
  }

  ikesa->integ_i = rhp_crypto_integ_alloc(s_pld_ctx.resolved_prop.v2.integ_id);
  if( ikesa->integ_i == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_L_I_INTEG_I_ALLOC_ERR,"xxx",rx_resp_ikemesg,vpn,ikesa);
   	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_RESP_INTEG_ALG_ERR,"KVPdE",rx_resp_ikemesg,vpn,ikesa,s_pld_ctx.resolved_prop.v2.integ_id,err);
    err = -EINVAL;
    goto error;
  }

  ikesa->integ_r = rhp_crypto_integ_alloc(s_pld_ctx.resolved_prop.v2.integ_id);
  if( ikesa->integ_r == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_L_I_INTEG_I_ALLOC_ERR,"xxx",rx_resp_ikemesg,vpn,ikesa);
   	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_RESP_INTEG_ALG_ERR,"KVPdE",rx_resp_ikemesg,vpn,ikesa,s_pld_ctx.resolved_prop.v2.integ_id,err);
    err = -EINVAL;
    goto error;
  }

  ikesa->encr = rhp_crypto_encr_alloc(s_pld_ctx.resolved_prop.v2.encr_id,s_pld_ctx.resolved_prop.v2.encr_key_bits);
  if( ikesa->encr == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_L_I_ENCR_ALLOC_ERR,"xxx",rx_resp_ikemesg,vpn,ikesa);
   	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_RESP_ENCR_ALG_ERR,"KVPddE",rx_resp_ikemesg,vpn,ikesa,s_pld_ctx.resolved_prop.v2.encr_id,s_pld_ctx.resolved_prop.v2.encr_key_bits,err);
    err = -EINVAL;
    goto error;
  }


  ikesa->set_resp_spi(ikesa,ikeh->resp_spi);

  err = ikesa->nonce_r->set_nonce(ikesa->nonce_r,s_pld_ctx.nonce,s_pld_ctx.nonce_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  err = ikesa->dh->set_peer_pub_key(ikesa->dh,s_pld_ctx.peer_dh_pub_key,s_pld_ctx.peer_dh_pub_key_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  err = ikesa->dh->compute_key(ikesa->dh);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

	err = ikesa->generate_keys(ikesa);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

  err = ikesa->encr->set_enc_key(ikesa->encr,ikesa->keys.v2.sk_ei,ikesa->keys.v2.sk_e_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  err = ikesa->encr->set_dec_key(ikesa->encr,ikesa->keys.v2.sk_er,ikesa->keys.v2.sk_e_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  err = ikesa->integ_i->set_key(ikesa->integ_i,ikesa->keys.v2.sk_ai,ikesa->keys.v2.sk_a_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  err = ikesa->integ_r->set_key(ikesa->integ_r,ikesa->keys.v2.sk_ar,ikesa->keys.v2.sk_a_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  ikesa->signed_octets.ikemesg_r_2nd = rx_resp_ikemesg;
  rhp_ikev2_hold_mesg(rx_resp_ikemesg);
  rhp_pkt_pending(rx_resp_ikemesg->rx_pkt);

  vpn->peer_is_rockhopper = s_pld_ctx.peer_is_rockhopper;
  vpn->peer_rockhopper_ver = s_pld_ctx.peer_rockhopper_ver;
  ikesa->peer_is_rockhopper = s_pld_ctx.peer_is_rockhopper;
  ikesa->peer_rockhopper_ver = s_pld_ctx.peer_rockhopper_ver;

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_RESP_OK,"KVP",rx_resp_ikemesg,vpn,ikesa);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_L_RTRN,"xxx",rx_resp_ikemesg,vpn,ikesa);
  return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_RESP_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
  if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_L_ERR,"xxx",rx_resp_ikemesg,vpn,ikesa);
  return err;

retry:
	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_RESP_WAIT_RETRY,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_L_RTRN_RETRY,"xxx",rx_resp_ikemesg,vpn,ikesa);
  return RHP_STATUS_IKEV2_MESG_HANDLER_END;
}

static int _rhp_ikev2_new_pkt_ike_sa_init_rep(rhp_ikesa* ikesa,rhp_ikev2_mesg* tx_resp_ikemesg,int exec_ikev2_frag)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_REP,"xxd",ikesa,tx_resp_ikemesg,exec_ikev2_frag);

  {
    if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_SA,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

    if( ikepayload->ext.sa->set_matched_ikesa_prop(ikepayload,&(ikesa->prop.v2),NULL,0) ){
      RHP_BUG("");
      goto error;
    }
  }

  {
    int key_len;
    u8* key = ikesa->dh->get_my_pub_key(ikesa->dh,&key_len);

    if( key == NULL ){
      RHP_BUG("");
      goto error;
    }

    if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_KE,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

    if( ikepayload->ext.ke->set_key(ikepayload,ikesa->dh->grp,key_len,key) ){
      RHP_BUG("");
      goto error;
    }
  }

  {
    int nonce_len = ikesa->nonce_r->get_nonce_len(ikesa->nonce_r);
    u8* nonce = ikesa->nonce_r->get_nonce(ikesa->nonce_r);

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
  }

  if( rhp_gcfg_hash_url_enabled(RHP_IKE_RESPONDER) ){

	 	err = rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload);
	 	if( err ){
	     RHP_BUG("");
	     goto error;
	 	}

	 	tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

	 	ikepayload->ext.n->set_protocol_id(ikepayload,0);

	 	ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_HTTP_CERT_LOOKUP_SUPPORTED);
  }

  if( ikesa->peer_is_rockhopper && !rhp_gcfg_responder_tx_all_cas_certreq ){

    //
  	// [CAUTION]
  	//
  	// In this case, this Rockhopper implementation sends 'empty' certificate request.
    // Because realm is not resolved for the IKE_SA_INIT responder yet. This is
    // a limitation for this implementation ((i.e.)For role-based policy matching).
  	// But we want to notify only cert encoding type supported by this implementation.
    //

  	if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_CERTREQ,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

  	tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

  	ikepayload->ext.certreq->set_cert_encoding(ikepayload,RHP_PROTO_IKE_CERTENC_X509_CERT_SIG);

  }else{

  	//
  	// Send all CAs' hashes by default.
  	//

  	if( rhp_gcfg_responder_tx_all_cas_certreq ){

  		u8* digests = NULL;
  		int digests_len = 0;
  		int digest_len = 0;

  		err = rhp_cfg_get_all_ca_pubkey_digests(&digests,&digests_len,&digest_len);
  		if( !err ){

  	  	if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_CERTREQ,&ikepayload) ){
  	      RHP_BUG("");
  	      goto error;
  	    }

  	  	tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

  	  	ikepayload->ext.certreq->set_cert_encoding(ikepayload,RHP_PROTO_IKE_CERTENC_X509_CERT_SIG);

  	  	err = ikepayload->ext.certreq->set_ca_keys(ikepayload,digests_len,digests);
  	  	if( err ){
  	      RHP_BUG("");
  	      _rhp_free(digests);
  	      goto error;
  	  	}

  	  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_SA_INIT_RESP_TX_ALL_CAS_CERTREQ,"P",ikesa);
	      _rhp_free(digests);

  		}else{

  		  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_REP_NO_CA_PUBKEY_DIGESTS,"xxE",ikesa,tx_resp_ikemesg,err);
    		err = 0;
  		}
  	}
  }

  if( exec_ikev2_frag ){

		if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);
		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_FRAG_SUPPORTED);

		ikepayload->set_non_critical(ikepayload,1);
  }


  {
    if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_V,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

    if( ikepayload->ext.vid->copy_my_app_vid(ikepayload) ){
      RHP_BUG("");
      goto error;
    }
  }

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_REP_RTRN,"xx",ikesa,tx_resp_ikemesg);
  return 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_REP_ERR,"xE",ikesa,err);
  return err;
}

static int _rhp_ikev2_rx_ike_sa_init_req_no_vpn(rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg,
		rhp_vpn** vpn_i,int* my_ikesa_side_i,u8* my_ikesa_spi_i)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_ikesa* ikesa = NULL;
  rhp_ip_addr peer_addr, rx_addr;
  rhp_proto_ike* ikeh = rx_req_ikemesg->rx_pkt->app.ikeh;
  rhp_vpn* larval_vpn = NULL;
  rhp_ikesa_init_i* init_i = NULL;
  rhp_ike_sa_init_srch_plds_ctx s_pld_ctx;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REQ_L,"x",rx_req_ikemesg);

  rhp_ip_addr_reset(&peer_addr);
  rhp_ip_addr_reset(&rx_addr);

  if( rx_req_ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE ){

    rhp_ip_addr_set(&peer_addr,AF_INET,
    		(u8*)&(rx_req_ikemesg->rx_pkt->l3.iph_v4->src_addr),NULL,32,
    		rx_req_ikemesg->rx_pkt->l4.udph->src_port,0);

    rhp_ip_addr_set2(&rx_addr,AF_INET,
    		(u8*)&(rx_req_ikemesg->rx_pkt->l3.iph_v4->dst_addr),
    		rx_req_ikemesg->rx_pkt->l4.udph->dst_port);

    RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_R_PEER_ADDR,"xd4WXd",rx_req_ikemesg,peer_addr.addr_family,peer_addr.addr.v4,peer_addr.port,peer_addr.netmask.v4,peer_addr.prefixlen);

  }else if( rx_req_ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE ){

    rhp_ip_addr_set(&peer_addr,AF_INET6,
    		rx_req_ikemesg->rx_pkt->l3.iph_v6->src_addr,NULL,128,
    		rx_req_ikemesg->rx_pkt->l4.udph->src_port,0);

    rhp_ip_addr_set2(&rx_addr,AF_INET6,
    		(u8*)&(rx_req_ikemesg->rx_pkt->l3.iph_v6->dst_addr),
    		rx_req_ikemesg->rx_pkt->l4.udph->dst_port);

    RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_R_PEER_ADDR_V6,"xd6WXd",rx_req_ikemesg,peer_addr.addr_family,peer_addr.addr.v6,peer_addr.port,peer_addr.netmask.v4,peer_addr.prefixlen);

  }else{
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  memset(&s_pld_ctx,0,sizeof(rhp_ike_sa_init_srch_plds_ctx));

  s_pld_ctx.ikesa = ikesa;

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_SA),
  			_rhp_ikev2_ike_sa_init_srch_sa_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_RX_IKEV2_IKE_SA_INIT_REQ_ENUM_SA_PLD_ERR,"xxd",rx_req_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKE_SA_INIT_REQ_PARSE_SA_PAYLOAD_ERR,"KVPE",rx_req_ikemesg,NULL,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_N_I_R),
  			rhp_ikev2_ike_sa_init_srch_nir_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_RX_IKEV2_IKE_SA_INIT_REQ_ENUM_NIR_PLD_ERR,"xxd",rx_req_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKE_SA_INIT_REQ_PARSE_N_I_R_PAYLOAD_ERR,"KVPE",rx_req_ikemesg,NULL,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_KE),
  			_rhp_ikev2_ike_sa_init_srch_ke_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_RX_IKEV2_IKE_SA_INIT_REQ_ENUM_SA_PLD_ERR,"xxd",rx_req_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKE_SA_INIT_REQ_PARSE_KE_PAYLOAD_ERR,"KVPE",rx_req_ikemesg,NULL,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  			rhp_ikev2_mesg_search_cond_my_verndor_id,NULL,
  			rhp_ikev2_ike_sa_init_srch_my_vid_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
  		RHP_TRC(0,RHPTRCID_RX_IKEV2_IKE_SA_INIT_REQ_ENUM_MY_VENDOR_ID_ERR,"xxE",ikesa,rx_req_ikemesg,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKE_SA_INIT_REQ_PARSE_V_PAYLOAD_ERR,"KVPE",rx_req_ikemesg,NULL,ikesa,err);
    	goto error;
  	}
  }


  if( rhp_gcfg_ikev2_enable_fragmentation ){

  	s_pld_ctx.dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_n_mesg_id,
  			(void*)((unsigned long)RHP_PROTO_IKE_NOTIFY_ST_FRAG_SUPPORTED),
  			rhp_ikev2_ike_sa_init_srch_n_frag_supported_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_L_FRAG_SUPPORTED_ERR,"xxE",ikesa,rx_req_ikemesg,err);
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKE_SA_INIT_RESP_PARSE_N_FRAGMENTATION_SUPPORTED_PAYLOAD_ERR,"KVPE",rx_req_ikemesg,NULL,ikesa,err);
    	goto error;
  	}
  }


  larval_vpn = rhp_vpn_alloc(NULL,NULL,NULL,NULL,RHP_IKE_RESPONDER); // (xx*)
  if( larval_vpn == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  RHP_LOCK(&(larval_vpn->lock));

  _rhp_atomic_set(&(larval_vpn->is_active),1);

  ikesa = rhp_ikesa_new_r(&(s_pld_ctx.resolved_prop.v2));
  if( ikesa == NULL ){
  	RHP_BUG("");
    err = -EINVAL;
  	goto error;
  }

  ikesa->timers = rhp_ikesa_new_timers(RHP_IKE_RESPONDER,ikesa->resp_spi);
  if( ikesa->timers == NULL ){
  	RHP_BUG("");
    err = -EINVAL;
  	goto error;
  }

  larval_vpn->ikesa_put(larval_vpn,ikesa);


  init_i = rhp_ikesa_alloc_init_i(ikesa->resp_spi,&peer_addr,rx_req_ikemesg);
  if( init_i == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  larval_vpn->exec_ikev2_frag = s_pld_ctx.frag_supported;

  larval_vpn->peer_is_rockhopper = s_pld_ctx.peer_is_rockhopper;
  larval_vpn->peer_rockhopper_ver = s_pld_ctx.peer_rockhopper_ver;
  ikesa->peer_is_rockhopper = s_pld_ctx.peer_is_rockhopper;
  ikesa->peer_rockhopper_ver = s_pld_ctx.peer_rockhopper_ver;


  err = rhp_vpn_ikesa_spi_put(larval_vpn,ikesa->side,ikesa->resp_spi);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

 	RHP_LOCK(&(rx_req_ikemesg->rx_pkt->rx_ifc->lock));
 	{
 		larval_vpn->set_local_net_info(larval_vpn,rx_req_ikemesg->rx_pkt->rx_ifc,
 				rx_addr.addr_family,rx_addr.addr.raw);
  }
	RHP_UNLOCK(&(rx_req_ikemesg->rx_pkt->rx_ifc->lock));

  ikesa->set_init_spi(ikesa,ikeh->init_spi);

  larval_vpn->set_peer_addr(larval_vpn,&peer_addr,&peer_addr);


  err = ikesa->nonce_i->set_nonce(ikesa->nonce_i,s_pld_ctx.nonce,s_pld_ctx.nonce_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  err = ikesa->dh->set_peer_pub_key(ikesa->dh,s_pld_ctx.peer_dh_pub_key,s_pld_ctx.peer_dh_pub_key_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  memcpy(&(ikesa->prop.v2),&(s_pld_ctx.resolved_prop.v2),sizeof(rhp_res_sa_proposal));


  err = _rhp_ikev2_new_pkt_ike_sa_init_rep(ikesa,tx_resp_ikemesg,larval_vpn->exec_ikev2_frag);
  if( err ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_R_ALLOC_RESP_PKT_ERR,"xxE",rx_req_ikemesg,ikesa,err);
  	goto error;
  }


  rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_R_IKE_SA_INIT_SENT);


  ikesa->signed_octets.ikemesg_i_1st = rx_req_ikemesg;
  rhp_ikev2_hold_mesg(rx_req_ikemesg);
  rhp_pkt_pending(rx_req_ikemesg->rx_pkt);

  ikesa->signed_octets.ikemesg_r_2nd = tx_resp_ikemesg;
  rhp_ikev2_hold_mesg(tx_resp_ikemesg);


  rhp_ikesa_init_i_put(init_i,&(ikesa->ike_init_i_hash));
  init_i = NULL;

  ikesa->timers->start_lifetime_timer(larval_vpn,ikesa,rhp_gcfg_ikesa_lifetime_larval,1);

  larval_vpn->origin_peer_port = rx_req_ikemesg->rx_pkt->l4.udph->src_port;

  {
		larval_vpn->connecting = 1;
		rhp_ikesa_half_open_sessions_inc();
  }

  RHP_LOG_D(RHP_LOG_SRC_IKEV2,(larval_vpn ? larval_vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_REQ_OK,"KVP",rx_req_ikemesg,larval_vpn,ikesa);


  *vpn_i = larval_vpn;
  *my_ikesa_side_i = ikesa->side;
  memcpy(my_ikesa_spi_i,ikesa->get_my_spi(ikesa),RHP_PROTO_IKE_SPI_SIZE);

  RHP_UNLOCK(&(larval_vpn->lock));

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REQ_L_RTRN,"xx",rx_req_ikemesg,ikesa);
  return 0;

error:

	if( s_pld_ctx.notify_error ){
    rhp_ikev2_ike_sa_init_tx_error_rep(rx_req_ikemesg,s_pld_ctx.notify_error,s_pld_ctx.notify_error_arg);
  }

	if( larval_vpn ){

		rhp_vpn_ref* larval_vpn_ref = rhp_vpn_hold_ref(larval_vpn); // (xx*)

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,larval_vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_SA_INIT_REQ_ERR,"KVPLE",rx_req_ikemesg,larval_vpn,ikesa,"PROTO_IKE_NOTIFY",s_pld_ctx.notify_error,err);

    rhp_vpn_destroy(larval_vpn); // ikesa is also released.

    RHP_UNLOCK(&(larval_vpn->lock));
		rhp_vpn_unhold(larval_vpn_ref); // (xx*)

	}else{

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKE_SA_INIT_REQ_ERR,"KVPLE",rx_req_ikemesg,NULL,ikesa,"PROTO_IKE_NOTIFY",s_pld_ctx.notify_error,err);
  }

	if( init_i ){
    rhp_ikesa_free_init_i(init_i);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REQ_L_ERR,"xxE",rx_req_ikemesg,ikesa,err);
  return err;
}

int rhp_ikev2_rx_ike_sa_init_req_no_vpn(rhp_ikev2_mesg* rx_req_ikemesg,
		rhp_ikev2_mesg* tx_resp_ikemesg,rhp_vpn** vpn_i,int* my_ikesa_side_i,u8* my_ikesa_spi_i)
{
	int err = -EINVAL;
	u8 exchange_type = rx_req_ikemesg->get_exchange_type(rx_req_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REQ,"xxLb",rx_req_ikemesg,tx_resp_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

	if( exchange_type != RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ){
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REQ_NOT_IKE_SA_INIT_EXCHG,"xLb",rx_req_ikemesg,"PROTO_IKE_EXCHG",exchange_type);
		return 0;
	}

	if( !RHP_PROTO_IKE_HDR_INITIATOR(rx_req_ikemesg->rx_pkt->app.ikeh->flag) ){
		err = RHP_STATUS_INVALID_MSG;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REQ_INVALID_MESG1,"x",rx_req_ikemesg);
		goto error;
  }

	if( *vpn_i || *my_ikesa_side_i != -1 ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

	err = _rhp_ikev2_rx_ike_sa_init_req_no_vpn(rx_req_ikemesg,tx_resp_ikemesg,vpn_i,my_ikesa_side_i,my_ikesa_spi_i);

error:
	if( !err ){
		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REQ_RTRN,"xxxLdG",rx_req_ikemesg,tx_resp_ikemesg,*vpn_i,"IKE_SIDE",*my_ikesa_side_i,my_ikesa_spi_i);
	}else{
		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REQ_ERR,"xxxE",rx_req_ikemesg,tx_resp_ikemesg,err);
	}
  return err;
}

int rhp_ikev2_rx_ike_sa_init_rep(rhp_ikev2_mesg* rx_resp_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_resp_ikemesg->get_exchange_type(rx_resp_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP,"xxLdGxLb",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_req_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

	if( exchange_type != RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ){
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_NOT_IKE_SA_INIT_EXCHG,"xxLb",rx_resp_ikemesg,vpn,"PROTO_IKE_EXCHG",exchange_type);
		return 0;
	}

	if( RHP_PROTO_IKE_HDR_INITIATOR(rx_resp_ikemesg->rx_pkt->app.ikeh->flag) ){
		err = RHP_STATUS_INVALID_MSG;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_INVALID_MESG1,"xx",rx_resp_ikemesg,vpn);
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
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_NO_IKESA,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
		goto error;
	}

	if( ikesa->gen_by_sess_resume ){
		err = RHP_STATUS_INVALID_MSG;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_GEN_BY_SESS_RESUME_SA,"xxLdGx",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,ikesa);
		goto error;
	}

	err = _rhp_ikev2_rx_ike_sa_init_rep(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_REP_RTRN,"xxxE",rx_resp_ikemesg,vpn,tx_req_ikemesg,err);
  return err;
}

