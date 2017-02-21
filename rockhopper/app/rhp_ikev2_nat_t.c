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


#define RHP_IKEV2_NAT_T_HASH_BUF_LEN	(RHP_PROTO_IKE_SPI_SIZE*2 + 16 + 2) // 16 : IPv6 address , 2 : port

static int _rhp_ikev2_nat_t_src_hash(rhp_vpn* vpn,rhp_ikesa* ikesa,u8** hash_r,int* hash_len_r,
		int use_nat_t_port,rhp_ikev2_mesg* rx_req_ikemesg)
{
  int err = -EINVAL;
  u8 buf[RHP_IKEV2_NAT_T_HASH_BUF_LEN];
  u8* p = buf;
  int p_len = 0;
  u8* hash = NULL;
  int hash_len;

  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_SRC_HASH,"xxxxddx",vpn,ikesa,hash_r,hash_len_r,vpn->nat_t_info.exec_nat_t,use_nat_t_port,rx_req_ikemesg);

  memcpy(p,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
  p += RHP_PROTO_IKE_SPI_SIZE;
  p_len += RHP_PROTO_IKE_SPI_SIZE;

  memcpy(p,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
  p += RHP_PROTO_IKE_SPI_SIZE;
  p_len += RHP_PROTO_IKE_SPI_SIZE;

  rhp_if_entry_dump("_rhp_ikev2_nat_t_src_hash:ikesa->local.if_info",&(vpn->local.if_info));


  if( rx_req_ikemesg ){

  	if( rx_req_ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE ){

      memcpy(p,&(rx_req_ikemesg->rx_pkt->l3.iph_v4->dst_addr),4);
      p += 4;
      p_len += 4;

  	}else	if( rx_req_ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE ){

      memcpy(p,rx_req_ikemesg->rx_pkt->l3.iph_v6->dst_addr,16);
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


  if( rx_req_ikemesg ){

  	if( rx_req_ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE ||
  			rx_req_ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE ){

      memcpy(p,&(rx_req_ikemesg->rx_pkt->l4.udph->dst_port),2);

  	}else{
  		RHP_BUG("");
  		goto error;
  	}

  }else if( use_nat_t_port &&
  		      (vpn->nat_t_info.exec_nat_t || vpn->nat_t_info.use_nat_t_port) ){

    memcpy(p,&(vpn->local.port_nat_t),2);

  }else{

  	memcpy(p,&(vpn->local.port),2);
  }
  p += 2;
  p_len += 2;

  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_SRC_HASH_BUF,"xp",ikesa,p_len,buf);

  err = rhp_crypto_md(RHP_CRYPTO_MD_SHA1,buf,p_len,&hash,&hash_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  *hash_r = hash;
  *hash_len_r = hash_len;

  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_SRC_HASH_RTRN,"xxpp",vpn,ikesa,p_len,buf,*hash_len_r,*hash_r);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_SRC_HASH_ERR,"xxE",vpn,ikesa,err);
	return err;
}

static int _rhp_ikev2_nat_t_peer_src_hash(rhp_ikesa* ikesa,rhp_ikev2_payload* n_src_payload,u8** hash_r,int* hash_len_r)
{
  int err = -EINVAL;
  u8 buf[RHP_IKEV2_NAT_T_HASH_BUF_LEN];
  u8* p = buf;
  int p_len = 0;
  rhp_ikev2_mesg* rx_ikemesg = n_src_payload->ikemesg;
  rhp_packet* rx_pkt;
  u8* hash = NULL;
  int hash_len;

  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_PEER_SRC_HASH,"xxxx",ikesa,n_src_payload,hash_r,hash_len_r);

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

  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_PEER_SRC_HASH_BUF,"xp",ikesa,p_len,buf);

  err = rhp_crypto_md(RHP_CRYPTO_MD_SHA1,buf,p_len,&hash,&hash_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  *hash_r = hash;
  *hash_len_r = hash_len;

  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_PEER_SRC_HASH_RTRN,"xxpp",ikesa,n_src_payload,p_len,buf,*hash_len_r,*hash_r);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_PEER_SRC_HASH_RTRN,"xxE",ikesa,n_src_payload,err);
	return err;
}

static int _rhp_ikev2_nat_t_dst_hash(rhp_vpn* vpn,rhp_ikesa* ikesa,u8** hash_r,int* hash_len_r,
		rhp_ikev2_mesg* rx_req_ikemesg)
{
  int err = -EINVAL;
  u8 buf[RHP_IKEV2_NAT_T_HASH_BUF_LEN];
  u8* p = buf;
  int p_len = 0;
  u8* hash = NULL;
  int hash_len;

  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_DST_HASH,"xxxxx",vpn,ikesa,hash_r,hash_len_r,rx_req_ikemesg);

  memcpy(p,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
  p += RHP_PROTO_IKE_SPI_SIZE;
  p_len += RHP_PROTO_IKE_SPI_SIZE;

  memcpy(p,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
  p += RHP_PROTO_IKE_SPI_SIZE;
  p_len += RHP_PROTO_IKE_SPI_SIZE;

  rhp_ip_addr_dump("_rhp_ikev2_nat_t_dst_hash:ikesa->peer_addr",&(vpn->peer_addr));


  if( rx_req_ikemesg ){

  	if( rx_req_ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE ){

      memcpy(p,&(rx_req_ikemesg->rx_pkt->l3.iph_v4->src_addr),4);
      p += 4;
      p_len += 4;

  	}else	if( rx_req_ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE ){

      memcpy(p,rx_req_ikemesg->rx_pkt->l3.iph_v6->src_addr,16);
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


  if( rx_req_ikemesg ){

  	if( rx_req_ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE ||
  			rx_req_ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE ){

      memcpy(p,&(rx_req_ikemesg->rx_pkt->l4.udph->src_port),2);

  	}else{
  		RHP_BUG("");
  		goto error;
  	}

  }else{

  	memcpy(p,&(vpn->peer_addr.port),2);
  }
  p += 2;
  p_len += 2;

  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_DST_HASH_BUF,"xp",ikesa,p_len,buf);


  err = rhp_crypto_md(RHP_CRYPTO_MD_SHA1,buf,p_len,&hash,&hash_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  *hash_r = hash;
  *hash_len_r = hash_len;

  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_DST_HASH_RTRN,"xpp",ikesa,p_len,buf,*hash_len_r,*hash_r);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_DST_HASH_ERR,"xE",ikesa,err);
	return err;
}

int rhp_ikev2_nat_t_peer_dst_hash(rhp_ikesa* ikesa,rhp_ikev2_payload* n_dst_payload,
		int dst_addr_len,u8* dst_addr,u8** hash_r,int* hash_len_r)
{
  int err = -EINVAL;
  u8 buf[RHP_IKEV2_NAT_T_HASH_BUF_LEN];
  u8* p = buf;
  int p_len = 0;
  rhp_ikev2_mesg* rx_ikemesg = n_dst_payload->ikemesg;
  rhp_packet* rx_pkt;
  u8* hash = NULL;
  int hash_len;

  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_PEER_DST_HASH,"xxpxx",ikesa,n_dst_payload,dst_addr_len,dst_addr,hash_r,hash_len_r);

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

  if( dst_addr && dst_addr_len == 4 ){

  	memcpy(p,dst_addr,4);
  	p += 4;
    p_len += 4;

  }else if( dst_addr && dst_addr_len == 16 ){

  	memcpy(p,dst_addr,16);
  	p += 16;
    p_len += 16;

  }else if( rx_pkt->type == RHP_PKT_IPV4_IKE ){

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

  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_PEER_DST_HASH_BUF,"xp",ikesa,p_len,buf);


  err = rhp_crypto_md(RHP_CRYPTO_MD_SHA1,buf,p_len,&hash,&hash_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  *hash_r = hash;
  *hash_len_r = hash_len;

  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_PEER_DST_HASH_RTRN,"xxpp",ikesa,n_dst_payload,p_len,buf,*hash_len_r,*hash_r);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_PEER_DST_HASH_ERR,"xxE",ikesa,n_dst_payload,err);
	return err;
}


static int _rhp_ikev2_nat_t_src_check(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_payload* n_src_payload)
{
  int err;
  u8* hval = NULL;
  int hval_len;
  int notified_hash_len = 0;
  u8* notified_hash = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_SRC_CHECK,"xxxx",vpn,ikesa,n_src_payload,vpn->nat_t_info.behind_a_nat);

  err = _rhp_ikev2_nat_t_peer_src_hash(ikesa,n_src_payload,&hval,&hval_len);
  if( err ){
  	RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_SRC_CHECK_PEER_HASH_ERR,"xxE",ikesa,n_src_payload,err);
  	goto error;
  }

  notified_hash_len = n_src_payload->ext.n->get_data_len(n_src_payload);
  if( notified_hash_len != RHP_IKEV2_NAT_T_HASH_LEN ){
  	RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_SRC_CHECK_NOTIFIED_HASH_LEN_ERR,"xxd",ikesa,n_src_payload,notified_hash_len);
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

  notified_hash = n_src_payload->ext.n->get_data(n_src_payload);
  if( notified_hash == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_SRC_CHECK_NO_NOTIFIED_HASH_VAL,"xx",ikesa,n_src_payload);
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_SRC_CHECK_CMP,"xxpp",ikesa,n_src_payload,notified_hash_len,notified_hash,hval_len,hval);

  if( memcmp(notified_hash,hval,notified_hash_len) ){
  	err = RHP_STATUS_BEHIND_A_NAT;
  }else{
  	err = 0;
  }

  _rhp_free(hval);

  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_SRC_CHECK_RTRN,"xxxxE",vpn,ikesa,n_src_payload,vpn->nat_t_info.behind_a_nat,err);
  return err;

error:
  if( hval ){
    _rhp_free(hval);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_SRC_CHECK_ERR,"xxE",ikesa,n_src_payload,err);
  return err;
}

int rhp_ikev2_nat_t_dst_check(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_payload* n_dst_payload,int dst_addr_len,u8* dst_addr)
{
  int err;
  u8* hval = NULL;
  int hval_len;
  int notified_hash_len = 0;
  u8* notified_hash = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_DST_CHECK,"xxxxp",vpn,ikesa,n_dst_payload,vpn->nat_t_info.behind_a_nat,dst_addr_len,dst_addr);

  err = rhp_ikev2_nat_t_peer_dst_hash(ikesa,n_dst_payload,dst_addr_len,dst_addr,&hval,&hval_len);
  if( err ){
  	RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_DST_CHECK_PEER_HASH_ERR,"xxE",ikesa,n_dst_payload,err);
  	goto error;
  }

  notified_hash_len = n_dst_payload->ext.n->get_data_len(n_dst_payload);
  if( notified_hash_len != RHP_IKEV2_NAT_T_HASH_LEN ){
  	RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_DST_CHECK_NOTIFIED_HASH_LEN_ERR,"xxd",ikesa,n_dst_payload,notified_hash_len);
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

  notified_hash = n_dst_payload->ext.n->get_data(n_dst_payload);
  if( notified_hash == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_DST_CHECK_NO_NOTIFIED_HASH_VAL,"xx",ikesa,n_dst_payload);
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_DST_CHECK_CMP,"xxpp",ikesa,n_dst_payload,notified_hash_len,notified_hash,hval_len,hval);

  if( memcmp(notified_hash,hval,notified_hash_len) ){
  	err = RHP_STATUS_BEHIND_A_NAT;
  }else{
  	err = 0;
  }

  _rhp_free(hval);

  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_DST_CHECK_RTRN,"xxxxE",vpn,ikesa,n_dst_payload,vpn->nat_t_info.behind_a_nat,err);
  return err;

error:
  if( hval ){
    _rhp_free(hval);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_DST_CHECK_ERR,"xxxE",vpn,ikesa,n_dst_payload,err);
  return err;
}


static int _rhp_ikev2_nat_t_new_pkt_req(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_ikemesg,
		int use_nat_t_port)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_NEW_PKT_REQ,"xxxxd",vpn,ikesa,rx_req_ikemesg,tx_ikemesg,use_nat_t_port);

  {
    u8* nat_t_src_hash = NULL;	// SHA-1
    int nat_t_src_hash_len;

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
      RHP_BUG("");
      err = -EINVAL;
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    ikepayload->ext.n->set_protocol_id(ikepayload,0);

    ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_NAT_DETECTION_SOURCE_IP);

    if( _rhp_ikev2_nat_t_src_hash(vpn,ikesa,&nat_t_src_hash,&nat_t_src_hash_len,use_nat_t_port,rx_req_ikemesg) ){
      RHP_BUG("");
      err = -EINVAL;
      goto error;
    }

    if( ikepayload->ext.n->set_data(ikepayload,RHP_IKEV2_NAT_T_HASH_LEN,nat_t_src_hash) ){
      RHP_BUG("");
      _rhp_free(nat_t_src_hash);
      err = -EINVAL;
      goto error;
     }

    _rhp_free(nat_t_src_hash);
  }

  {
    u8* nat_t_dst_hash = NULL;	// SHA-1
    int nat_t_dst_hash_len;

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
      RHP_BUG("");
      err = -EINVAL;
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    ikepayload->ext.n->set_protocol_id(ikepayload,0);

    ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_NAT_DETECTION_DESTINATION_IP);

    if( _rhp_ikev2_nat_t_dst_hash(vpn,ikesa,&nat_t_dst_hash,&nat_t_dst_hash_len,rx_req_ikemesg) ){
      RHP_BUG("");
      err = -EINVAL;
      goto error;
    }

    if( ikepayload->ext.n->set_data(ikepayload,RHP_IKEV2_NAT_T_HASH_LEN,nat_t_dst_hash) ){
      RHP_BUG("");
      _rhp_free(nat_t_dst_hash);
      err = -EINVAL;
      goto error;
     }

    _rhp_free(nat_t_dst_hash);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_NEW_PKT_REQ_RTRN,"xx",ikesa,tx_ikemesg);

  return 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_NEW_PKT_REQ_ERR,"xE",ikesa,err);
  return err;
}

// Don't use this API for IKE_SA_INIT exchg.
int rhp_ikev2_nat_t_new_pkt_req(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
	return _rhp_ikev2_nat_t_new_pkt_req(vpn,ikesa,rx_req_ikemesg,tx_ikemesg,1);
}


static int _rhp_ikev2_nat_t_new_pkt_rep(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg,int use_nat_t_port)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_NEW_PKT_REP,"xxxxd",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,use_nat_t_port);

  {
    u8* nat_t_src_hash = NULL;	// SHA-1
    int nat_t_src_hash_len;

    if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
      RHP_BUG("");
      err = -EINVAL;
      goto error;
    }

    tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

    ikepayload->ext.n->set_protocol_id(ikepayload,0);

    ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_NAT_DETECTION_SOURCE_IP);

    if( _rhp_ikev2_nat_t_src_hash(vpn,ikesa,&nat_t_src_hash,&nat_t_src_hash_len,use_nat_t_port,rx_req_ikemesg) ){
      RHP_BUG("");
      err = -EINVAL;
      goto error;
    }

    if( ikepayload->ext.n->set_data(ikepayload,RHP_IKEV2_NAT_T_HASH_LEN,nat_t_src_hash) ){
      RHP_BUG("");
      _rhp_free(nat_t_src_hash);
      err = -EINVAL;
      goto error;
     }

    _rhp_free(nat_t_src_hash);
  }

  {
    u8* nat_t_dst_hash = NULL; // SHA-1
    int nat_t_dst_hash_len;

    if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
      RHP_BUG("");
      err = -EINVAL;
      goto error;
    }

    tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

    ikepayload->ext.n->set_protocol_id(ikepayload,0);

    ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_NAT_DETECTION_DESTINATION_IP);

    if( _rhp_ikev2_nat_t_dst_hash(vpn,ikesa,&nat_t_dst_hash,&nat_t_dst_hash_len,rx_req_ikemesg) ){
      RHP_BUG("");
      err = -EINVAL;
      goto error;
    }

    if( ikepayload->ext.n->set_data(ikepayload,RHP_IKEV2_NAT_T_HASH_LEN,nat_t_dst_hash) ){
      RHP_BUG("");
      _rhp_free(nat_t_dst_hash);
      err = -EINVAL;
      goto error;
     }

    _rhp_free(nat_t_dst_hash);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_NEW_PKT_REP_RTRN,"xx",ikesa,tx_resp_ikemesg);
  return 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_NEW_PKT_REP_ERR,"xE",ikesa,err);
  return err;
}

static int _rhp_ikev2_nat_t_srch_n_nat_t_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_nat_t_srch_plds_ctx* s_pld_ctx = (rhp_nat_t_srch_plds_ctx*)ctx;

  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_SRCH_N_NAT_T_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

  if( enum_end ){

  	if( s_pld_ctx->n_nat_t_src_num == 0 && s_pld_ctx->n_nat_t_dst_num == 0 ){
  		goto end;
  	}

  	if( ( s_pld_ctx->n_nat_t_src_num == 0 && s_pld_ctx->n_nat_t_dst_num ) ||
 		    ( s_pld_ctx->n_nat_t_src_num && s_pld_ctx->n_nat_t_dst_num == 0 ) ){
  		RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_SRCH_N_NAT_T_CB_NUM_ERR,"xdd",rx_ikemesg,s_pld_ctx->n_nat_t_src_num,s_pld_ctx->n_nat_t_dst_num);
  		goto end;
  	}

		if( s_pld_ctx->n_nat_t_dst_num > 1 ){
  		RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_SRCH_N_NAT_T_CB_DST_ERR,"xdd",rx_ikemesg,s_pld_ctx->n_nat_t_src_num,s_pld_ctx->n_nat_t_dst_num);
  		goto end;
		}

  	if( rx_ikemesg->is_response(rx_ikemesg) ){

  		if( s_pld_ctx->n_nat_t_src_num > 1 ){
    		RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_SRCH_N_NAT_T_CB_SRC_ERR,"xdd",rx_ikemesg,s_pld_ctx->n_nat_t_src_num,s_pld_ctx->n_nat_t_dst_num);
    		goto end;
  		}
  	}

  	if( s_pld_ctx->behind_a_nat ){

  		s_pld_ctx->exec_nat_t = 1;
	  }

  }else{

  	rhp_ikev2_n_payload* n_payload = (rhp_ikev2_n_payload*)payload->ext.n;
  	u16 notify_mesg_type;

  	if( n_payload == NULL ){
  		RHP_BUG("");
    	return -EINVAL;
    }

  	notify_mesg_type = n_payload->get_message_type(payload);

  	if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_NAT_DETECTION_SOURCE_IP ){

  		if( rx_ikemesg->is_response(rx_ikemesg) && s_pld_ctx->n_nat_t_src_num ){
    		err = RHP_STATUS_INVALID_MSG;
    		goto error;
  		}

  		s_pld_ctx->n_nat_t_src_num++;

  		if( !s_pld_ctx->peer_not_behind_a_nat ){

				err = _rhp_ikev2_nat_t_src_check(s_pld_ctx->vpn,s_pld_ctx->ikesa,payload);

				if( err == RHP_STATUS_BEHIND_A_NAT ){
					s_pld_ctx->behind_a_nat |= RHP_IKESA_BEHIND_A_NAT_PEER;
					err = 0;
				}else if( err ){
					RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_SRCH_N_NAT_T_CB_SRC_CHECK_ERR,"xxE",rx_ikemesg,payload,err);
					goto error;
				}else{
					s_pld_ctx->peer_not_behind_a_nat = 1;
					s_pld_ctx->behind_a_nat &= ~RHP_IKESA_BEHIND_A_NAT_PEER;
				}
  		}

  	}else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_NAT_DETECTION_DESTINATION_IP ){

  		if( s_pld_ctx->n_nat_t_dst_num ){
    		err = RHP_STATUS_INVALID_MSG;
    		goto error;
  		}

  		s_pld_ctx->n_nat_t_dst_num++;

  		err = rhp_ikev2_nat_t_dst_check(s_pld_ctx->vpn,s_pld_ctx->ikesa,payload,0,NULL);

  		if( err == RHP_STATUS_BEHIND_A_NAT ){

  			s_pld_ctx->behind_a_nat |= RHP_IKESA_BEHIND_A_NAT_LOCAL;

  			err = 0;

  		}else if( err ){
  			RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_SRCH_N_NAT_T_CB_DST_CHECK_ERR,"xxE",rx_ikemesg,payload,err);
  			goto error;
	    }
    }
  }

end:
  err = 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_SRCH_N_CB_RTRN,"xxxE",rx_ikemesg,payload,ctx,err);
 	return err;
}

static int _rhp_ikev2_rx_nat_t_ike_sa_init_rep(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_resp_ikemesg,
		rhp_ikev2_mesg* tx_req_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_vpn_realm* rlm = NULL;
  rhp_nat_t_srch_plds_ctx s_pld_ctx;

  RHP_TRC(0,RHPTRCID_RX_IKEV2_NAT_T_IKE_SA_INIT_REP_L,"xxxx",rx_resp_ikemesg,tx_req_ikemesg,vpn,ikesa);

  if( rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
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
  	u16 nat_t_n_ids[3] = { RHP_PROTO_IKE_NOTIFY_ST_NAT_DETECTION_SOURCE_IP,
  												 RHP_PROTO_IKE_NOTIFY_ST_NAT_DETECTION_DESTINATION_IP,
  												 RHP_PROTO_IKE_NOTIFY_RESERVED};

  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,1,
  			rhp_ikev2_mesg_srch_cond_n_mesg_ids,nat_t_n_ids,
  			_rhp_ikev2_nat_t_srch_n_nat_t_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
  		RHP_TRC(0,RHPTRCID_RX_IKEV2_NAT_T_IKE_SA_INIT_REP_L_ENUM_N_NAT_T_ERR,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
    	goto error_l;
  	}
  	err = 0;

    vpn->nat_t_info.behind_a_nat = s_pld_ctx.behind_a_nat;
    vpn->nat_t_info.exec_nat_t = s_pld_ctx.exec_nat_t;

    if( vpn->nat_t_info.exec_nat_t ){

    	vpn->peer_addr.port = htons(rhp_gcfg_ike_port_nat_t);

  		//
  		// [CAUTION]
  		//   Once NAT is detected between peers, the following IKEv2 messages are
  		//   transmitted from the NAT-T port (4500).
  		//   This is for an inte-op consideration.
  		//
    	vpn->nat_t_info.use_nat_t_port = 1;

    	RHP_TRC(0,RHPTRCID_RX_IKEV2_NAT_T_IKE_SA_INIT_REP_L_CHANGE_PEER_PORT,"xxxW",vpn,ikesa,rx_resp_ikemesg,vpn->peer_addr.port);
    }
  }


ignore_l:
	RHP_UNLOCK(&(rlm->lock));


  RHP_TRC(0,RHPTRCID_RX_IKEV2_NAT_T_IKE_SA_INIT_REP_L_ENUM_N_STATUS,"xxxxd",rx_resp_ikemesg,vpn,ikesa,vpn->nat_t_info.behind_a_nat,vpn->nat_t_info.exec_nat_t);

  if( s_pld_ctx.peer_not_behind_a_nat ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_SA_INIT_NATT_RESP_NO_NAT,"KVP",rx_resp_ikemesg,vpn,ikesa);
  }
	if( s_pld_ctx.behind_a_nat & RHP_IKESA_BEHIND_A_NAT_PEER ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_SA_INIT_NATT_RESP_PEER_BEHIND_A_NAT,"KVP",rx_resp_ikemesg,vpn,ikesa);
	}
	if( s_pld_ctx.behind_a_nat & RHP_IKESA_BEHIND_A_NAT_LOCAL ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_SA_INIT_NATT_RESP_LOCAL_BEHIND_A_NAT,"KVP",rx_resp_ikemesg,vpn,ikesa);
	}

  RHP_TRC(0,RHPTRCID_RX_IKEV2_NAT_T_IKE_SA_INIT_REP_L_RTRN,"xxx",rx_resp_ikemesg,vpn,ikesa);
  return 0;

error_l:
	RHP_UNLOCK(&(rlm->lock));
error:
	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_SA_INIT_NATT_RESP_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
  if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
  }
  RHP_TRC(0,RHPTRCID_RX_IKEV2_NAT_T_IKE_SA_INIT_REP_L_ERR,"xxx",rx_resp_ikemesg,vpn,ikesa);
  return err;
}

static int _rhp_ikev2_rx_nat_t_info_rep(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_resp_ikemesg,
		rhp_ikev2_mesg* tx_req_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_nat_t_srch_plds_ctx s_pld_ctx;

  RHP_TRC(0,RHPTRCID_RX_IKEV2_NAT_T_INFO_REP_L,"xxxx",rx_resp_ikemesg,tx_req_ikemesg,vpn,ikesa);

  if( rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  memset(&s_pld_ctx,0,sizeof(rhp_nat_t_srch_plds_ctx));

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;

  {
  	u16 nat_t_n_ids[3] = { RHP_PROTO_IKE_NOTIFY_ST_NAT_DETECTION_SOURCE_IP,
  												 RHP_PROTO_IKE_NOTIFY_ST_NAT_DETECTION_DESTINATION_IP,
  												 RHP_PROTO_IKE_NOTIFY_RESERVED};

  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,1,
			  			rhp_ikev2_mesg_srch_cond_n_mesg_ids,nat_t_n_ids,
			  			_rhp_ikev2_nat_t_srch_n_nat_t_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
  		RHP_TRC(0,RHPTRCID_RX_IKEV2_NAT_T_INFO_REP_L_ENUM_N_NAT_T_ERR,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
    	goto error;
  	}
  	err = 0;
  }

  RHP_TRC(0,RHPTRCID_RX_IKEV2_NAT_T_INFO_REP_L_ENUM_N_STATUS,"xxxx",rx_resp_ikemesg,vpn,ikesa,s_pld_ctx.behind_a_nat);

	if( s_pld_ctx.exec_nat_t && s_pld_ctx.behind_a_nat ){

		rx_resp_ikemesg->nat_t_detected = 1;
		rx_resp_ikemesg->nat_t_behind_a_nat = s_pld_ctx.behind_a_nat;
	}

  if( s_pld_ctx.peer_not_behind_a_nat ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_INFO_NATT_RESP_NO_NAT,"KVP",rx_resp_ikemesg,vpn,ikesa);
  }
	if( s_pld_ctx.behind_a_nat & RHP_IKESA_BEHIND_A_NAT_PEER ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_INFO_NATT_RESP_PEER_BEHIND_A_NAT,"KVP",rx_resp_ikemesg,vpn,ikesa);
	}
	if( s_pld_ctx.behind_a_nat & RHP_IKESA_BEHIND_A_NAT_LOCAL ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_INFO_NATT_RESP_LOCAL_BEHIND_A_NAT,"KVP",rx_resp_ikemesg,vpn,ikesa);
	}

  RHP_TRC(0,RHPTRCID_RX_IKEV2_NAT_T_INFO_REP_L_RTRN,"xxx",rx_resp_ikemesg,vpn,ikesa);
  return 0;

error:
  if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
  }

	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_INFO_NATT_RESP_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);

  RHP_TRC(0,RHPTRCID_RX_IKEV2_NAT_T_INFO_REP_L_ERR,"xxx",rx_resp_ikemesg,vpn,ikesa);
  return err;
}

static int _rhp_ikev2_rx_nat_t_ike_sa_init_req(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_nat_t_srch_plds_ctx s_pld_ctx;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_IKE_SA_INIT_REQ_L,"x",rx_req_ikemesg);

  memset(&s_pld_ctx,0,sizeof(rhp_nat_t_srch_plds_ctx));

  if( rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
  	RHP_BUG("");
  	goto error;
  }

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;
  s_pld_ctx.rlm = NULL; // realm is NOT resolved yet.

  {
  	u16 nat_t_n_ids[3] = { RHP_PROTO_IKE_NOTIFY_ST_NAT_DETECTION_SOURCE_IP,
  												 RHP_PROTO_IKE_NOTIFY_ST_NAT_DETECTION_DESTINATION_IP,
  												 RHP_PROTO_IKE_NOTIFY_RESERVED};

  	s_pld_ctx.dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,1,
			  			rhp_ikev2_mesg_srch_cond_n_mesg_ids,nat_t_n_ids,_rhp_ikev2_nat_t_srch_n_nat_t_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){

  		RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_IKE_SA_INIT_REQ_L_ENUM_N_NAT_T_ERR,"xxxE",vpn,ikesa,rx_req_ikemesg,err);

  		if( s_pld_ctx.notify_error ){
  			goto notify_error;
  		}

    	goto error;
  	}
  	err = 0;

    vpn->nat_t_info.behind_a_nat = s_pld_ctx.behind_a_nat;
    vpn->nat_t_info.exec_nat_t = s_pld_ctx.exec_nat_t;

    if( vpn->nat_t_info.exec_nat_t ){

  		//
  		// [CAUTION]
  		//   Once NAT is detected between peers, the following IKEv2 messages are
  		//   transmitted from the NAT-T port (4500).
  		//   This is for an inte-op consideration.
  		//
    	vpn->nat_t_info.use_nat_t_port = 1;
    }
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_IKE_SA_INIT_REQ_L_ENUM_N_STATUS,"xxxxd",rx_req_ikemesg,ikesa,vpn,vpn->nat_t_info.behind_a_nat,vpn->nat_t_info.exec_nat_t);

  if( rx_req_ikemesg->rx_pkt->l4.udph->dst_port == vpn->local.port_nat_t ){

    vpn->nat_t_info.use_nat_t_port = 1;

    RHP_TRC(0,RHPTRCID_IKEV2_IKE_SA_INIT_R_ENUM_USE_NAT_T_PORT,"xxxdW",rx_req_ikemesg,ikesa,vpn,vpn->nat_t_info.use_nat_t_port,rx_req_ikemesg->rx_pkt->l4.udph->dst_port);
  }

  if( s_pld_ctx.n_nat_t_src_num && s_pld_ctx.n_nat_t_dst_num ){

  	err = _rhp_ikev2_nat_t_new_pkt_rep(vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,(vpn->nat_t_info.use_nat_t_port ? 1 : 0));
  	if( err ){
	  	RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_IKE_SA_INIT_REQ_L_ALLOC_RESP_PKT_ERR,"xxE",rx_req_ikemesg,ikesa,err);
	  	goto error;
	  }
  }

  if( s_pld_ctx.peer_not_behind_a_nat ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_SA_INIT_NATT_REQ_NO_NAT,"KVP",rx_req_ikemesg,vpn,ikesa);
  }
	if( s_pld_ctx.behind_a_nat & RHP_IKESA_BEHIND_A_NAT_PEER ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_SA_INIT_NATT_REQ_PEER_BEHIND_A_NAT,"KVP",rx_req_ikemesg,vpn,ikesa);
	}
	if( s_pld_ctx.behind_a_nat & RHP_IKESA_BEHIND_A_NAT_LOCAL ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_SA_INIT_NATT_REQ_LOCAL_BEHIND_A_NAT,"KVP",rx_req_ikemesg,vpn,ikesa);
	}

  RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_IKE_SA_INIT_REQ_L_RTRN,"xx",rx_req_ikemesg,ikesa);
  return 0;

notify_error:
	rhp_ikev2_ike_sa_init_tx_error_rep(rx_req_ikemesg,s_pld_ctx.notify_error,s_pld_ctx.notify_error_arg);

error:
	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_SA_INIT_NATT_REQ_ERR,"KVPE",rx_req_ikemesg,vpn,ikesa,err);
  RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_IKE_SA_INIT_REQ_L_ERR,"xxE",rx_req_ikemesg,ikesa,err);
  return err;
}

static int _rhp_ikev2_rx_nat_t_info_req(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_nat_t_srch_plds_ctx s_pld_ctx;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_INFO_REQ_L,"x",rx_req_ikemesg);

  if( rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
  	RHP_BUG("");
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

  memset(&s_pld_ctx,0,sizeof(rhp_nat_t_srch_plds_ctx));

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;

  {
  	u16 nat_t_n_ids[3] = { RHP_PROTO_IKE_NOTIFY_ST_NAT_DETECTION_SOURCE_IP,
  												 RHP_PROTO_IKE_NOTIFY_ST_NAT_DETECTION_DESTINATION_IP,
  												 RHP_PROTO_IKE_NOTIFY_RESERVED};

  	s_pld_ctx.dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,1,
		  			rhp_ikev2_mesg_srch_cond_n_mesg_ids,nat_t_n_ids,
		  			_rhp_ikev2_nat_t_srch_n_nat_t_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){

  		RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_INFO_REQ_L_ENUM_N_NAT_T_ERR,"xxxE",vpn,ikesa,rx_req_ikemesg,err);

  		if( s_pld_ctx.notify_error ){
  			goto notify_error;
  		}

  		goto error;
  	}
  	err = 0;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_INFO_REQ_L_ENUM_N_STATUS,"xxx",rx_req_ikemesg,ikesa,s_pld_ctx.behind_a_nat);

  if( s_pld_ctx.n_nat_t_src_num && s_pld_ctx.n_nat_t_dst_num ){

	  err = _rhp_ikev2_nat_t_new_pkt_rep(vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,1);
	  if( err ){
	  	RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_INFO_REQ_L_ALLOC_RESP_PKT_ERR,"xxE",rx_req_ikemesg,ikesa,err);
	  	goto error;
	  }
  }

	if( s_pld_ctx.exec_nat_t && s_pld_ctx.behind_a_nat ){

		rx_req_ikemesg->nat_t_detected = 1;
		rx_req_ikemesg->nat_t_behind_a_nat = s_pld_ctx.behind_a_nat;
	}

  if( s_pld_ctx.peer_not_behind_a_nat ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_INFO_NATT_REQ_NO_NAT,"KVP",rx_req_ikemesg,vpn,ikesa);
  }
	if( s_pld_ctx.behind_a_nat & RHP_IKESA_BEHIND_A_NAT_PEER ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_INFO_NATT_REQ_PEER_BEHIND_A_NAT,"KVP",rx_req_ikemesg,vpn,ikesa);
	}
	if( s_pld_ctx.behind_a_nat & RHP_IKESA_BEHIND_A_NAT_LOCAL ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_INFO_NATT_REQ_LOCAL_BEHIND_A_NAT,"KVP",rx_req_ikemesg,vpn,ikesa);
	}

  RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_INFO_REQ_L_RTRN,"xx",rx_req_ikemesg,ikesa);
  return 0;

notify_error:
//
// TODO : Tx encrypted Err notify mesg.
//	rhp_ikev2_ike_sa_init_tx_error_rep(rx_req_ikemesg,s_pld_ctx.notify_error,s_pld_ctx.notify_error_arg);
//

error:
	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_INFO_NATT_REQ_ERR,"KVPE",rx_req_ikemesg,vpn,ikesa,err);
	RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_INFO_REQ_L_ERR,"xxE",rx_req_ikemesg,ikesa,err);
  return err;
}


int rhp_ikev2_tx_nat_t_req(rhp_ikev2_mesg* tx_req_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,int req_initiator)
{
	int err = -EINVAL;
	rhp_ikesa* ikesa = NULL;
	rhp_vpn_realm* rlm = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_TX_NAT_T_REQ,"xxLdGLdd",tx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKEV2_MESG_HDLR",req_initiator,tx_req_ikemesg->add_nat_t_info);

	if( req_initiator == RHP_IKEV2_MESG_HANDLER_IKESA_INIT 	||
			req_initiator == RHP_IKEV2_MESG_HANDLER_SESS_RESUME ||
			tx_req_ikemesg->add_nat_t_info ){

		int use_nat_t_port = (req_initiator == RHP_IKEV2_MESG_HANDLER_IKESA_INIT) ? 0 : 1;

		if( my_ikesa_spi == NULL ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
		if( ikesa == NULL ){
			err = -ENOENT;
		  RHP_TRC(0,RHPTRCID_IKEV2_TX_NAT_T_REQ_NO_IKESA,"xxLdG",tx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
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
		  RHP_TRC(0,RHPTRCID_IKEV2_TX_NAT_T_REQ_RLM_NOT_ACTIVE,"xxx",tx_req_ikemesg,vpn,rlm);
			RHP_UNLOCK(&(rlm->lock));
			goto error;
		}

		if( !rlm->ikesa.nat_t ){
		  RHP_TRC(0,RHPTRCID_IKEV2_TX_NAT_T_REQ_NAT_T_DISABLED,"xxxd",tx_req_ikemesg,vpn,rlm,rlm->ikesa.nat_t);
			RHP_UNLOCK(&(rlm->lock));
			goto ignore;
		}

		RHP_UNLOCK(&(rlm->lock));

		err = _rhp_ikev2_nat_t_new_pkt_req(vpn,ikesa,NULL,tx_req_ikemesg,use_nat_t_port);
		if( err ){
			goto error;
		}
	}

ignore:
	RHP_TRC(0,RHPTRCID_IKEV2_TX_NAT_T_REQ_RTRN,"xxLd",tx_req_ikemesg,vpn,"IKEV2_MESG_HDLR",req_initiator);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_TX_NAT_T_REQ_ERR,"xxLdE",tx_req_ikemesg,vpn,"IKEV2_MESG_HDLR",req_initiator,err);
  return err;
}

int rhp_ikev2_rx_nat_t_req(rhp_ikev2_mesg* rx_req_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err = -EINVAL;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_req_ikemesg->get_exchange_type(rx_req_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_REQ,"xxLdGxLb",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_resp_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

	if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ||
			exchange_type == RHP_PROTO_IKE_EXCHG_SESS_RESUME ){

		if( !RHP_PROTO_IKE_HDR_INITIATOR(rx_req_ikemesg->rx_pkt->app.ikeh->flag) ){
			err = RHP_STATUS_INVALID_MSG;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_REQ_INVALID_MESG1,"xx",rx_req_ikemesg,vpn);
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
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_REQ_NO_IKESA2,"xxLdG",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}

		err = _rhp_ikev2_rx_nat_t_ike_sa_init_req(vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);


	}else if( exchange_type == RHP_PROTO_IKE_EXCHG_INFORMATIONAL ){

		if( my_ikesa_spi == NULL ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

	  if( !rx_req_ikemesg->decrypted ){
	  	err = 0;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_REQ_NOT_DECRYPTED,"xxLdG",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
	  	goto error;
	  }

		ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
		if( ikesa == NULL ){
			err = -ENOENT;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_REQ_NO_IKESA2,"xxLdG",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}

		err = _rhp_ikev2_rx_nat_t_info_req(vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);

	}else{
		err = 0;
		RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_REQ_NOT_INTERESTED,"xxx",rx_req_ikemesg,vpn,tx_resp_ikemesg);
	}

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_REQ_RTRN,"xxxE",rx_req_ikemesg,vpn,tx_resp_ikemesg,err);
  return err;
}

int rhp_ikev2_rx_nat_t_rep(rhp_ikev2_mesg* rx_resp_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err = -EINVAL;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_resp_ikemesg->get_exchange_type(rx_resp_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_REP,"xxLdGxLb",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_req_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

	if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ||
			exchange_type == RHP_PROTO_IKE_EXCHG_SESS_RESUME ){

		if( RHP_PROTO_IKE_HDR_INITIATOR(rx_resp_ikemesg->rx_pkt->app.ikeh->flag) ){
			err = RHP_STATUS_INVALID_MSG;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_REP_INVALID_MESG1,"xx",rx_resp_ikemesg,vpn);
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
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_REP_NO_IKESA1,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}

		err = _rhp_ikev2_rx_nat_t_ike_sa_init_rep(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);


	}else if( exchange_type == RHP_PROTO_IKE_EXCHG_INFORMATIONAL ){

		if( my_ikesa_spi == NULL ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

	  if( !rx_resp_ikemesg->decrypted ){
	  	err = 0;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_REP_NOT_DECRYPTED,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
	  	goto error;
	  }

		ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
		if( ikesa == NULL ){
			err = -ENOENT;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_REP_NO_IKESA2,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}

		err = _rhp_ikev2_rx_nat_t_info_rep(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);

	}else{
		err = 0;
		RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_REP_NOT_INTERESTED,"xxx",rx_resp_ikemesg,vpn,tx_req_ikemesg);
	}

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_NAT_T_REP_RTRN,"xxxE",rx_resp_ikemesg,vpn,tx_req_ikemesg,err);
  return err;
}

static int _rhp_ikev2_nat_t_change_peer_addr_port_check(rhp_vpn* vpn,rhp_ikesa* ikesa)
{

	if( !(vpn->nat_t_info.behind_a_nat & RHP_IKESA_BEHIND_A_NAT_PEER) &&
			!(vpn->nat_t_info.behind_a_nat & RHP_IKESA_BEHIND_A_NAT_LOCAL) ){

		RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_CHANTE_PEER_ADDR_PORT_CHECK_BOTH_LOCAL_AND_PEER_NOT_BEHIND_A_NAT,"xxdd",vpn,ikesa,vpn->nat_t_info.behind_a_nat,rhp_gcfg_behind_a_nat_dont_change_addr_port);
		return 0;
	}

	// A host bihind a NAT MUST NOT change peer address and port,
	// because it may opens a DoS attack possibility...
	if( vpn->nat_t_info.behind_a_nat & RHP_IKESA_BEHIND_A_NAT_LOCAL ){

		switch( rhp_gcfg_behind_a_nat_dont_change_addr_port ){

		case 0:
			break;

		case 1:
			if( vpn->origin_side != RHP_IKE_RESPONDER ){
				RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_CHANTE_PEER_ADDR_PORT_CHECK_NOT_RESPONDER,"xx",vpn,ikesa);
				return 0;
			}
			break;

		default:
			RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_CHANTE_PEER_ADDR_PORT_CHECK_NOT_ALLOWED,"xxx",vpn,ikesa);
			return 0;
		}
	}

	RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_CHANTE_PEER_ADDR_PORT_CHECK_OK,"xxLd",vpn,ikesa,"IKE_SIDE",vpn->origin_side);
	return 1;
}


int rhp_ikev2_nat_t_change_peer_addr_port(rhp_vpn* vpn,
		int addr_family,u8* new_ip_addr_b,u16 new_port,u16 peer_tx_dest_port,int checked)
{
	union _ipaddr {
		u32 v4;
		u8 v6[16];
		u8 raw[16];
	} old_ip_addr, new_ip_addr;
	u16 old_port;
	int old_addr_family;
	time_t now = _rhp_get_time();


	old_addr_family = vpn->peer_addr.addr_family;

	//
	// TODO: Supporting addr change like IPv4 NAT => IPv6 NAT
	//       and IPv6 NAT => IPv4 NAT.
	//
	if( old_addr_family != addr_family ){
		RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_CHANGE_PEER_ADDR_PORT_IP_VERSION_MISMATCHED,"xLdLd",vpn,"AF",old_addr_family,"AF",addr_family);
		return RHP_STATUS_MISMATCHED_IP_VERSION;
	}

	memcpy(old_ip_addr.raw,vpn->peer_addr.addr.raw,16);


	if( addr_family == AF_INET ){
		new_ip_addr.v4 = *((u32*)new_ip_addr_b);
	}else if( addr_family == AF_INET6 ){
		memcpy(new_ip_addr.v6,new_ip_addr_b,16);
	}else{
		RHP_BUG("");
		return -EINVAL;
	}

	old_port = vpn->peer_addr.port;


	if( vpn->ikesa_list_head == NULL ){

		if( addr_family == AF_INET ){
			RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_CHANGE_PEER_ADDR_PORT_NO_IKESA,"x4W4WW",vpn,old_ip_addr.v4,old_port,vpn->peer_addr.addr.v4,vpn->peer_addr.port,peer_tx_dest_port);
		}else if( addr_family == AF_INET6 ){
			RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_CHANGE_PEER_ADDR_PORT_NO_IKESA_V6,"x6W6WW",vpn,old_ip_addr.v6,old_port,vpn->peer_addr.addr.v6,vpn->peer_addr.port,peer_tx_dest_port);
		}

		return -ENOENT;
	}

	if( !checked ){

		if( !_rhp_ikev2_nat_t_change_peer_addr_port_check(vpn,vpn->ikesa_list_head) ){

			if( addr_family == AF_INET ){
				RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_CHANGE_PEER_ADDR_PORT_IGNORED,"x4W4WW",vpn,old_ip_addr.v4,old_port,vpn->peer_addr.addr.v4,vpn->peer_addr.port,peer_tx_dest_port);
			}else if( addr_family == AF_INET6 ){
				RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_CHANGE_PEER_ADDR_PORT_IGNORED_V6,"x6W6WW",vpn,old_ip_addr.v6,old_port,vpn->peer_addr.addr.v6,vpn->peer_addr.port,peer_tx_dest_port);
			}

			return -EINVAL;
		}
	}

	if( rhp_gcfg_peer_addr_change_min_interval && vpn->nat_t_info.last_addr_changed &&
			now - vpn->nat_t_info.last_addr_changed < rhp_gcfg_peer_addr_change_min_interval ){

		if( addr_family == AF_INET ){
			RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_CHANGE_PEER_ADDR_PORT_IGNORED_TOO_FAST,"x4W4WWff",vpn,old_ip_addr.v4,old_port,vpn->peer_addr.addr.v4,vpn->peer_addr.port,peer_tx_dest_port,(unsigned long)now,(unsigned long)vpn->nat_t_info.last_addr_changed);
		}else if( addr_family == AF_INET6 ){
			RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_CHANGE_PEER_ADDR_PORT_IGNORED_TOO_FAST_V6,"x6W6WWff",vpn,old_ip_addr.v6,old_port,vpn->peer_addr.addr.v6,vpn->peer_addr.port,peer_tx_dest_port,(unsigned long)now,(unsigned long)vpn->nat_t_info.last_addr_changed);
		}

		return -EINVAL;
	}


	memcpy(vpn->peer_addr.addr.raw,new_ip_addr.raw,16);
	vpn->peer_addr.port = new_port;

	vpn->nat_t_info.last_addr_changed = _rhp_get_time();

	if( addr_family == AF_INET ){
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_PEER_ADDR_V4_PORT_CHANGED,"V4W4W",vpn,old_ip_addr.v4,old_port,new_ip_addr.v4,new_port);
	}else if( addr_family == AF_INET6 ){
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_PEER_ADDR_V6_PORT_CHANGED,"V6W6W",vpn,old_ip_addr.v6,old_port,new_ip_addr.v6,new_port);
	}

	if( peer_tx_dest_port ){

		if( peer_tx_dest_port == htons(rhp_gcfg_ike_port_nat_t) ){

  		//
  		// [CAUTION]
  		//   Once NAT is detected between peers, the following IKEv2 messages are
  		//   transmitted from the NAT-T port (4500).
  		//   This is for an inte-op consideration.
  		//
			vpn->nat_t_info.use_nat_t_port = 1;
		}
	}

	if( addr_family == AF_INET ){
		RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_CHANGE_PEER_ADDR_PORT,"x4W4WWd",vpn,old_ip_addr.v4,old_port,vpn->peer_addr.addr.v4,vpn->peer_addr.port,peer_tx_dest_port,checked);
	}else if( addr_family == AF_INET6 ){
		RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_CHANGE_PEER_ADDR_PORT_V6,"x6W6WWd",vpn,old_ip_addr.v6,old_port,vpn->peer_addr.addr.v6,vpn->peer_addr.port,peer_tx_dest_port,checked);
	}

	{
		rhp_ikesa* cur_ikesa = vpn->ikesa_list_head;

		while( cur_ikesa ){

			cur_ikesa->timers->keep_alive_forced = 1;

			cur_ikesa = cur_ikesa->next_vpn_list;
		}
	}

	{
		rhp_childsa* cur_childsa = vpn->childsa_list_head;

		while( cur_childsa ){

			if( cur_childsa->ipsec_mode == RHP_CHILDSA_MODE_TRANSPORT ){

				rhp_childsa_ts* peer_tss = cur_childsa->peer_tss;

				while( peer_tss ){

					if( peer_tss->start_addr.addr_family == old_addr_family &&
							(((peer_tss->start_addr.addr_family == AF_INET) &&
							  (peer_tss->start_addr.addr.v4 == old_ip_addr.v4)) ||
							 ((peer_tss->start_addr.addr_family == AF_INET6) &&
							  (rhp_ipv6_is_same_addr(peer_tss->start_addr.addr.v6,old_ip_addr.v6)))) ){

						if( addr_family == AF_INET ){
							RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_CHANGE_PEER_ADDR_PORT_TSS_START_ADDR,"xxx44",vpn,cur_childsa,peer_tss,peer_tss->start_addr.addr.v4,new_ip_addr.v4);
						}else if( addr_family == AF_INET6 ){
							RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_CHANGE_PEER_ADDR_PORT_TSS_START_ADDR_V6,"xxx66",vpn,cur_childsa,peer_tss,peer_tss->start_addr.addr.v6,new_ip_addr.v6);
						}

						memcpy(peer_tss->start_addr.addr.raw,new_ip_addr.raw,16);
					}

					if( peer_tss->end_addr.addr_family == old_addr_family &&
							(((peer_tss->end_addr.addr_family == AF_INET) &&
							  (peer_tss->end_addr.addr.v4 == old_ip_addr.v4)) ||
							 ((peer_tss->end_addr.addr_family == AF_INET6) &&
							  (rhp_ipv6_is_same_addr(peer_tss->end_addr.addr.v6,old_ip_addr.v6)))) ){

						if( addr_family == AF_INET ){
							RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_CHANGE_PEER_ADDR_PORT_TSS_END_ADDR,"xxx44",vpn,cur_childsa,peer_tss,peer_tss->end_addr.addr.v4,new_ip_addr.v4);
						}else if( addr_family == AF_INET6 ){
							RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_CHANGE_PEER_ADDR_PORT_TSS_END_ADDR_V6,"xxx66",vpn,cur_childsa,peer_tss,peer_tss->end_addr.addr.v6,new_ip_addr.v6);
						}

						memcpy(peer_tss->end_addr.addr.raw,new_ip_addr.raw,16);
					}

					peer_tss = peer_tss->next;
				}
			}

			cur_childsa = cur_childsa->next_vpn_list;
		}
	}

	return 0;
}

int rhp_ikev2_nat_t_rx_from_unknown_peer(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_packet* rx_pkt,rhp_proto_ike* ikeh)
{
  u8 exchange_type;
  int my_side;
  int allowed = 0;

	if( vpn == NULL || ikesa == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

  RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_RX_FROM_UNKNOWN_PEER,"xxxLddd",vpn,ikesa,rx_pkt,"IKESA_STAT",ikesa->state,vpn->nat_t_info.exec_nat_t,rhp_gcfg_strict_peer_addr_port_check);


  if( vpn->peer_addr.addr_family != AF_INET &&
  		vpn->peer_addr.addr_family != AF_INET6 ){
  	return -EINVAL;
  }

  //
  // TODO: Supporting addr change like IPv4 NAT => IPv6 NAT and IPv6 NAT => IPv4 NAT.
  //
  if( (vpn->peer_addr.addr_family == AF_INET && rx_pkt->type != RHP_PKT_IPV4_IKE) ||
  		(vpn->peer_addr.addr_family == AF_INET6 && rx_pkt->type != RHP_PKT_IPV6_IKE) ){

	  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_RX_FROM_UNKNOWN_PEER_PROTO_FAMILY_MISMATCHED,"xxxLdLd",vpn,ikesa,rx_pkt,"AF",vpn->peer_addr.addr_family,"PKT",rx_pkt->type);
		return RHP_STATUS_INVALID_MSG;
  }

  ikeh = rx_pkt->app.ikeh;
  exchange_type = ikeh->exchange_type;
  my_side = ikesa->side;

	if( vpn->nat_t_info.exec_nat_t || !rhp_gcfg_strict_peer_addr_port_check ){

		// OK

	}else if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_AUTH ){

		//
		// [CAUTION]
		//
		//   For remote peers using the NAT-T port (4500) even on Non-NAT-T
		//   environment like Win 7/8 or MOBIKE-enabled peers.
		//
		//   Incidentally, vpn->nat_t_info.exec_nat_t is already enabled
		//   in the IKE_SA_INIT exchg on NAT-T env.
		//

		if( my_side != RHP_IKE_RESPONDER ){
		  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_RX_FROM_UNKNOWN_PEER_IKE_AUTH_BAD_IKESA_SIDE,"xxxLd",vpn,ikesa,rx_pkt,"EAP_STAT",ikesa->eap.state);
			return RHP_STATUS_INVALID_MSG;
		}

		if( ntohl(ikeh->message_id) != 1 ){
		  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_RX_FROM_UNKNOWN_PEER_IKE_AUTH_BAD_IKESA_MESG_ID,"xxxJ",vpn,ikesa,rx_pkt,ikeh->message_id);
			return RHP_STATUS_INVALID_MSG;
		}

  	if( (vpn->peer_addr.addr_family == AF_INET &&
  			 vpn->peer_addr.addr.v4 != rx_pkt->l3.iph_v4->src_addr) ||
  			(vpn->peer_addr.addr_family == AF_INET6 &&
  			 !rhp_ipv6_is_same_addr(vpn->peer_addr.addr.v6,rx_pkt->l3.iph_v6->src_addr)) ){

  		if( vpn->peer_addr.addr_family == AF_INET ){
  			RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_RX_FROM_UNKNOWN_PEER_IKE_AUTH_SRC_ADDR_UNKNOWN,"xxx44",vpn,ikesa,rx_pkt,vpn->peer_addr.addr.v4,rx_pkt->l3.iph_v4->src_addr);
  		}else if( vpn->peer_addr.addr_family == AF_INET6 ){
  			RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_RX_FROM_UNKNOWN_PEER_IKE_AUTH_SRC_ADDR_UNKNOWN_V6,"xxx66",vpn,ikesa,rx_pkt,vpn->peer_addr.addr.v6,rx_pkt->l3.iph_v6->src_addr);
  		}

  		return RHP_STATUS_INVALID_MSG;
  	}

  	if( rx_pkt->l4.udph->src_port != htons(rhp_gcfg_ike_port_nat_t) || // This is for NON NAT-T env.
  			rx_pkt->l4.udph->dst_port != vpn->local.port_nat_t ){
		  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_RX_FROM_UNKNOWN_PEER_IKE_AUTH_DST_NOT_IKE_PORT,"xxxwwW",vpn,ikesa,rx_pkt,rx_pkt->l4.udph->src_port,rx_pkt->l4.udph->dst_port,(u16)rhp_gcfg_ike_port_nat_t);
			return RHP_STATUS_INVALID_MSG;
		}

	  RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_RX_FROM_UNKNOWN_PEER_IKE_AUTH_OK,"xxx",vpn,ikesa,rx_pkt);
	  allowed = 1;

		if( vpn->peer_addr.addr_family == AF_INET ){
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_AUTH_IKE_IPV4_PORT_CHANGED,"V4WW",vpn,rx_pkt->l3.iph_v4->src_addr,rx_pkt->l4.udph->src_port,rx_pkt->l4.udph->dst_port);
		}else if( vpn->peer_addr.addr_family == AF_INET6 ){
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_AUTH_IKE_IPV6_PORT_CHANGED,"V6WW",vpn,rx_pkt->l3.iph_v6->src_addr,rx_pkt->l4.udph->src_port,rx_pkt->l4.udph->dst_port);
		}

	}else	if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ||
						exchange_type == RHP_PROTO_IKE_EXCHG_SESS_RESUME ){

		RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_RX_FROM_UNKNOWN_PEER_BAD_EXCHG_TYPE,"xxxLb",vpn,ikesa,rx_pkt,"PROTO_IKE_EXCHG",exchange_type);
		return RHP_STATUS_INVALID_MSG;

	}else{

	  RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_RX_FROM_UNKNOWN_PEER_NAT_T_DISABLED,"xxxd",vpn,ikesa,rx_pkt,vpn->nat_t_info.exec_nat_t);
		return RHP_STATUS_INVALID_MSG;
	}

	if( ikesa->state != RHP_IKESA_STAT_R_IKE_SA_INIT_SENT &&
			ikesa->state != RHP_IKESA_STAT_ESTABLISHED &&
			ikesa->state != RHP_IKESA_STAT_REKEYING ){

	  RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_RX_FROM_UNKNOWN_PEER_BAD_IKESA_STAT,"xxxLd",vpn,ikesa,rx_pkt,"IKESA_STAT",ikesa->state);
		return RHP_STATUS_INVALID_MSG;
	}


	if( !allowed ){

		if( !_rhp_ikev2_nat_t_change_peer_addr_port_check(vpn,ikesa) ){

		  RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_RX_FROM_UNKNOWN_PEER_NOT_CHECK_ERR,"xxx",vpn,ikesa,rx_pkt);
			return RHP_STATUS_INVALID_MSG;
		}
	}

	{
		u8* src_addr = NULL;

		if( vpn->peer_addr.addr_family == AF_INET ){
			src_addr = (u8*)&(rx_pkt->l3.iph_v4->src_addr);
		}else if( vpn->peer_addr.addr_family == AF_INET6 ){
			src_addr = rx_pkt->l3.iph_v6->src_addr;
		}

		rhp_ikev2_nat_t_change_peer_addr_port(vpn,vpn->peer_addr.addr_family,src_addr,
				rx_pkt->l4.udph->src_port,rx_pkt->l4.udph->dst_port,1);
	}

  RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_RX_FROM_UNKNOWN_PEER_RTRN,"xxx",vpn,ikesa,rx_pkt);
	return 0;
}

static rhp_packet* _rhp_ikev2_nat_t_new_keep_alive_pkt_v4(rhp_vpn* vpn,rhp_ikesa* ikesa)
{
	rhp_packet *tx_pkt = NULL;
	rhp_proto_ether* dmy_ethh = NULL;
	rhp_proto_ip_v4* dmy_iph = NULL;
	rhp_proto_udp* dmy_udph = NULL;
	u8* dmy_data = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_NEW_KEEP_ALIVE_PKT_V4,"xx",vpn,ikesa);

	tx_pkt = rhp_pkt_alloc(sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v4) + sizeof(rhp_proto_udp) + 1);
  if( tx_pkt == NULL ){
    RHP_BUG("");
    goto error;
  }

  tx_pkt->type = RHP_PKT_IPV4_IKE;

  dmy_ethh = (rhp_proto_ether*)_rhp_pkt_push(tx_pkt,sizeof(rhp_proto_ether));
  dmy_iph = (rhp_proto_ip_v4*)_rhp_pkt_push(tx_pkt,sizeof(rhp_proto_ip_v4));
  dmy_udph = (rhp_proto_udp*)_rhp_pkt_push(tx_pkt,sizeof(rhp_proto_udp));
  dmy_data = (u8*)_rhp_pkt_push(tx_pkt,1);

  tx_pkt->l2.eth = dmy_ethh;
  tx_pkt->l3.iph_v4 = dmy_iph;
  tx_pkt->l4.udph = dmy_udph;
  tx_pkt->app.raw = dmy_data;

  dmy_ethh->protocol = RHP_PROTO_ETH_IP;

  dmy_iph->ver = 4;
  dmy_iph->ihl = 5;
  dmy_iph->tos = 0;
  dmy_iph->total_len= htons(sizeof(rhp_proto_ip_v4) + sizeof(rhp_proto_udp) + 1);
  dmy_iph->id = 0;
  dmy_iph->frag = 0;
  dmy_iph->ttl = 64;
  dmy_iph->protocol = RHP_PROTO_IP_UDP;
  dmy_iph->check_sum = 0;
  dmy_iph->src_addr = vpn->local.if_info.addr.v4;
  dmy_iph->dst_addr = vpn->peer_addr.addr.v4;

  dmy_udph->len = htons(sizeof(rhp_proto_udp) + 1);
  dmy_udph->check_sum = 0;
  dmy_udph->src_port = vpn->local.port_nat_t;
  dmy_udph->dst_port = vpn->peer_addr.port;

  *dmy_data = 0xFF;
  tx_pkt->nat_t_keep_alive = 1;


  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_NEW_KEEP_ALIVE_PKT_V4_PKT,"xxxa",vpn,ikesa,tx_pkt,(tx_pkt->tail - tx_pkt->data),RHP_TRC_FMT_A_MAC_IPV4_NAT_T_KEEPALIVE,0,0,tx_pkt->data);
  rhp_pkt_trace_dump("_rhp_ikev2_nat_t_new_keep_alive_pkt_v4",tx_pkt);

  RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_NEW_KEEP_ALIVE_PKT_V4_RTRN,"xxx",vpn,ikesa,tx_pkt);
  return tx_pkt;

error:
  if( tx_pkt ){
    rhp_pkt_unhold(tx_pkt);
  }
  RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_NEW_KEEP_ALIVE_PKT_V4_ERR,"xx",vpn,ikesa);
  return NULL;
}

static rhp_packet* _rhp_ikev2_nat_t_new_keep_alive_pkt_v6(rhp_vpn* vpn,rhp_ikesa* ikesa)
{
	rhp_packet *tx_pkt = NULL;
	rhp_proto_ether* dmy_ethh = NULL;
	rhp_proto_ip_v6* dmy_ip6h = NULL;
	rhp_proto_udp* dmy_udph = NULL;
	u8* dmy_data = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_NEW_KEEP_ALIVE_PKT_V6,"xx",vpn,ikesa);

	tx_pkt = rhp_pkt_alloc(sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v6) + sizeof(rhp_proto_udp) + 1);
  if( tx_pkt == NULL ){
    RHP_BUG("");
    goto error;
  }

  tx_pkt->type = RHP_PKT_IPV6_IKE;

  dmy_ethh = (rhp_proto_ether*)_rhp_pkt_push(tx_pkt,sizeof(rhp_proto_ether));
  dmy_ip6h = (rhp_proto_ip_v6*)_rhp_pkt_push(tx_pkt,sizeof(rhp_proto_ip_v6));
  dmy_udph = (rhp_proto_udp*)_rhp_pkt_push(tx_pkt,sizeof(rhp_proto_udp));
  dmy_data = (u8*)_rhp_pkt_push(tx_pkt,1);

  tx_pkt->l2.eth = dmy_ethh;
  tx_pkt->l3.iph_v6 = dmy_ip6h;
  tx_pkt->l4.udph = dmy_udph;
  tx_pkt->app.raw = dmy_data;

  dmy_ethh->protocol = RHP_PROTO_ETH_IPV6;

	dmy_ip6h->ver = 6;
	dmy_ip6h->priority = 0;
	dmy_ip6h->payload_len = htons(sizeof(rhp_proto_udp) + 1);
	dmy_ip6h->flow_label[0] = 0;
	dmy_ip6h->flow_label[1] = 0;
	dmy_ip6h->flow_label[2] = 0;
	dmy_ip6h->next_header = RHP_PROTO_IP_UDP;
	dmy_ip6h->hop_limit = 64;
	memcpy(dmy_ip6h->src_addr,vpn->local.if_info.addr.v6,16);
	memcpy(dmy_ip6h->dst_addr,vpn->peer_addr.addr.v6,16);

  dmy_udph->len = htons(sizeof(rhp_proto_udp) + 1);
  dmy_udph->check_sum = 0;
  dmy_udph->src_port = vpn->local.port_nat_t;
  dmy_udph->dst_port = vpn->peer_addr.port;

  *dmy_data = 0xFF;
  tx_pkt->nat_t_keep_alive = 1;


  RHP_TRC(0,RHPTRCID_IKEV2_NAT_T_NEW_KEEP_ALIVE_PKT_V6_PKT,"xxxa",vpn,ikesa,tx_pkt,(tx_pkt->tail - tx_pkt->data),RHP_TRC_FMT_A_MAC_IPV6_NAT_T_KEEPALIVE,0,0,tx_pkt->data);
  rhp_pkt_trace_dump("_rhp_ikev2_nat_t_new_keep_alive_pkt_v6",tx_pkt);

  RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_NEW_KEEP_ALIVE_PKT_V6_RTRN,"xxx",vpn,ikesa,tx_pkt);
  return tx_pkt;

error:
  if( tx_pkt ){
    rhp_pkt_unhold(tx_pkt);
  }
  RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_NEW_KEEP_ALIVE_PKT_V6_ERR,"xx",vpn,ikesa);
  return NULL;
}

int rhp_ikev2_nat_t_send_keep_alive(rhp_vpn* vpn,rhp_ikesa* ikesa)
{
	int err = -EINVAL;
	rhp_packet *tx_pkt = NULL,*pkt_d = NULL;
	int i;

  RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_SEND_KEEP_ALIVE,"xx",vpn,ikesa);

	if( vpn->local.if_info.addr_family != AF_INET &&
			vpn->local.if_info.addr_family != AF_INET6 ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	if( vpn->peer_addr.port == vpn->origin_peer_port ){
		err = -EINVAL;
	  RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_SEND_KEEP_ALIVE_PEER_PORT_IS_NOT_NAT_T,"xxWW",vpn,ikesa,vpn->peer_addr.port,vpn->origin_peer_port);
		goto error;
	}

	if( vpn->local.if_info.addr_family == AF_INET ){
		tx_pkt = _rhp_ikev2_nat_t_new_keep_alive_pkt_v4(vpn,ikesa);
	}else if( vpn->local.if_info.addr_family == AF_INET6 ){
		tx_pkt = _rhp_ikev2_nat_t_new_keep_alive_pkt_v6(vpn,ikesa);
	}
	if( tx_pkt == NULL ){
		err = -ENOMEM;
	  RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_SEND_KEEP_ALIVE_NEW_PKT_ERR,"xxWW",vpn,ikesa,vpn->peer_addr.port,vpn->origin_peer_port);
		goto error;
	}


  for( i = 0; i < rhp_gcfg_nat_t_keep_alive_packets; i++ ){

  	if( i == (rhp_gcfg_nat_t_keep_alive_packets - 1) ){
  		pkt_d = tx_pkt;
  		tx_pkt = NULL;
  	}else{
  		pkt_d = rhp_pkt_dup(tx_pkt);
  	}

		if( pkt_d ){

			rhp_ifc_entry* tx_ifc = rhp_ifc_get_by_if_idx(vpn->local.if_info.if_index);  // (***)

			if( tx_ifc == NULL ){
				RHP_BUG("");
			}else{

				pkt_d->tx_ifc = tx_ifc;
				rhp_ifc_hold(pkt_d->tx_ifc);

				err = rhp_netsock_send(pkt_d->tx_ifc,pkt_d);
				if( err < 0 ){
					RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_SEND_KEEP_ALIVE_NETSOCK_SEND_ERR,"xxxxE",vpn,ikesa,tx_pkt,pkt_d,err);
				}
			}
			err = 0;

			rhp_pkt_unhold(pkt_d);
			rhp_ifc_unhold(tx_ifc); // (***)
			pkt_d = NULL;

		}else{
			RHP_BUG("");
		}
  }

  if( tx_pkt ){
    rhp_pkt_unhold(tx_pkt);
  }

  RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_SEND_KEEP_ALIVE_RTRN,"xx",vpn,ikesa);
  return 0;

error:
  if( tx_pkt ){
    rhp_pkt_unhold(tx_pkt);
  }
  if( pkt_d ){
    rhp_pkt_unhold(pkt_d);
  }
  RHP_TRC_FREQ(0,RHPTRCID_IKEV2_NAT_T_SEND_KEEP_ALIVE_ERR,"xx",vpn,ikesa);
  return err;
}
