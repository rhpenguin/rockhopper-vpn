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
#include "rhp_ikesa.h"
#include "rhp_ikev2_mesg.h"

static int _rhp_ikev2_certreq_payload_get_ca_keys_len(rhp_ikev2_payload* payload)
{
  int len;
  if( payload->ext.certreq->ca_keys ){
    len = payload->ext.certreq->ca_keys_len;
  }else{
    len = payload->get_len_rx(payload);
    len -= sizeof(rhp_proto_ike_certreq_payload);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_CERTREQ_PAYLOAD_GET_CA_KEYS_LEN,"xxd",payload,payload->ext.certreq->ca_keys,len);
  return len;
}

static int _rhp_ikev2_certreq_payload_get_ca_keys_num(rhp_ikev2_payload* payload)
{
  int len = _rhp_ikev2_certreq_payload_get_ca_keys_len(payload);
  RHP_TRC(0,RHPTRCID_IKEV2_CERTREQ_PAYLOAD_GET_CA_KEY_NUM,"xd",payload,( len / RHP_PROTO_IKE_CERTENC_SHA1_DIGEST_LEN ));
  return ( len / RHP_PROTO_IKE_CERTENC_SHA1_DIGEST_LEN );
}

static int _rhp_ikev2_certreq_payload_get_ca_key_len(rhp_ikev2_payload* payload)
{
  RHP_TRC(0,RHPTRCID_IKEV2_CERTREQ_PAYLOAD_GET_CA_KEY_LEN,"xd",payload,RHP_PROTO_IKE_CERTENC_SHA1_DIGEST_LEN);
  return RHP_PROTO_IKE_CERTENC_SHA1_DIGEST_LEN;
}

static u8* _rhp_ikev2_certreq_payload_get_ca_keys(rhp_ikev2_payload* payload)
{
  u8* ret;
  rhp_proto_ike_certreq_payload* certreq_payloadh;
  int len = _rhp_ikev2_certreq_payload_get_ca_key_len(payload);

  if( payload->ext.certreq->ca_keys ){
    ret = payload->ext.certreq->ca_keys;
  }else{
    if( len ){
      certreq_payloadh = (rhp_proto_ike_certreq_payload*)(payload->payloadh);
      ret = (u8*)(certreq_payloadh + 1);
    }else{  
      ret = NULL;
    }
  }
  RHP_TRC(0,RHPTRCID_IKEV2_CERTREQ_PAYLOAD_GET_CA_KEYS,"xxxp",payload,payload->ext.certreq->ca_keys,ret,len,ret);
  return ret;
}

static u8 _rhp_ikev2_certreq_payload_get_cert_encoding(rhp_ikev2_payload* payload)
{
  u8 ret;
  rhp_proto_ike_certreq_payload* certreq_payloadh;

  if( payload->ext.certreq->cert_encoding ){
    ret = payload->ext.certreq->cert_encoding;
  }else{
    certreq_payloadh = (rhp_proto_ike_certreq_payload*)(payload->payloadh);
    ret = certreq_payloadh->cert_encoding;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_CERTREQ_PAYLOAD_GET_CERT_ENCODING,"xb",payload,ret);
  return ret;
}

static void _rhp_ikev2_certreq_payload_set_cert_encoding(rhp_ikev2_payload* payload,u8 cert_encoding)
{
  payload->ext.certreq->cert_encoding = cert_encoding;

  RHP_TRC(0,RHPTRCID_IKEV2_CERTREQ_PAYLOAD_SET_CERT_ENCODING,"xb",payload,cert_encoding);
  return;
}

static void _rhp_ikev2_certreq_payload_destructor(rhp_ikev2_payload* payload)
{
  RHP_TRC(0,RHPTRCID_IKEV2_CERTREQ_PAYLOAD_DESTRUCTOR,"xx",payload,payload->ext.certreq->ca_keys);

  if( payload->ext.certreq->ca_keys ){
    _rhp_free(payload->ext.certreq->ca_keys);
    payload->ext.certreq->ca_keys = NULL;
    payload->ext.certreq->ca_keys_len = 0;
  }
  return;
}

static int _rhp_ikev2_certreq_payload_serialize(rhp_ikev2_payload* payload,rhp_packet* pkt)
{
  int len;
  rhp_proto_ike_certreq_payload* p;

  RHP_TRC(0,RHPTRCID_IKEV2_CERTREQ_PAYLOAD_SERIALIZE,"xx",payload,pkt);

  len = sizeof(rhp_proto_ike_certreq_payload) + payload->ext.certreq->ca_keys_len;

  p = (rhp_proto_ike_certreq_payload*)rhp_pkt_expand_tail(pkt,len);
  if( p == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  p->next_payload = payload->get_next_payload(payload);
  p->critical_rsv = RHP_PROTO_IKE_PLD_SET_CRITICAL;
  p->len = htons(len);
  p->cert_encoding = payload->ext.certreq->cert_encoding;

  if( payload->ext.certreq->ca_keys ){
    memcpy((p + 1),payload->ext.certreq->ca_keys,payload->ext.certreq->ca_keys_len);
  }

  payload->ikemesg->tx_mesg_len += len;

  p->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
  if( payload->next ){
    p->next_payload = payload->next->get_payload_id(payload->next);
  }
    
  RHP_TRC(0,RHPTRCID_IKEV2_CERTREQ_PAYLOAD_SERIALIZE_RTRN,"");
  rhp_pkt_trace_dump("_rhp_ikev2_certreq_payload_serialize(1)",pkt);
  return 0;
}

static int _rhp_ikev2_certreq_payload_set_ca_keys(rhp_ikev2_payload* payload,int ca_keys_len,u8* ca_keys)
{
  RHP_TRC(0,RHPTRCID_IKEV2_CERTREQ_PAYLOAD_SET_CA_KEYS,"xp",payload,ca_keys_len,ca_keys);

  if( payload->ext.certreq->ca_keys ){
    RHP_BUG("");
    return -EEXIST;
  }

  payload->ext.certreq->ca_keys = (u8*)_rhp_malloc(ca_keys_len);
  if( payload->ext.certreq->ca_keys == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  memcpy(payload->ext.certreq->ca_keys,ca_keys,ca_keys_len);
  payload->ext.certreq->ca_keys_len = ca_keys_len;

  return 0;
}

rhp_ikev2_certreq_payload* _rhp_ikev2_alloc_certreq_payload()
{
  rhp_ikev2_certreq_payload* certreq_payload;

  certreq_payload = (rhp_ikev2_certreq_payload*)_rhp_malloc(sizeof(rhp_ikev2_certreq_payload));
  if( certreq_payload == NULL ){
    return NULL;
  }

  memset(certreq_payload,0,sizeof(rhp_ikev2_certreq_payload));

  certreq_payload->get_ca_keys_len = _rhp_ikev2_certreq_payload_get_ca_keys_len;
  certreq_payload->get_ca_key_len = _rhp_ikev2_certreq_payload_get_ca_key_len;
  certreq_payload->get_ca_keys_num = _rhp_ikev2_certreq_payload_get_ca_keys_num;
  certreq_payload->get_ca_keys = _rhp_ikev2_certreq_payload_get_ca_keys;
  certreq_payload->set_ca_keys = _rhp_ikev2_certreq_payload_set_ca_keys;
  certreq_payload->set_cert_encoding = _rhp_ikev2_certreq_payload_set_cert_encoding;
  certreq_payload->get_cert_encoding = _rhp_ikev2_certreq_payload_get_cert_encoding;

  RHP_TRC(0,RHPTRCID_IKEV2_ALLOC_VID_PAYLOAD,"x",certreq_payload);
  return certreq_payload;
}


int rhp_ikev2_certreq_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                 rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_certreq_payload* certreq_payload;
  rhp_proto_ike_certreq_payload* certreq_payloadh = (rhp_proto_ike_certreq_payload*)payloadh;
  int vlen;
  
  RHP_TRC(0,RHPTRCID_IKEV2_CERTREQ_PAYLOAD_NEW_RX,"xbxdxp",ikemesg,payload_id,payloadh,payload_len,payload,payload_len,payloadh);

  if( payload_len < (int)sizeof(rhp_proto_ike_certreq_payload) ){ // No authorities' data OK.
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_CERTREQ_PAYLOAD_NEW_RX_INVALID_MESG_1,"xdd",ikemesg,payload_len,sizeof(rhp_proto_ike_certreq_payload));
    goto error;
  }

  vlen = payload_len - sizeof(rhp_proto_ike_certreq_payload);
  if( vlen < 0 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_CERTREQ_PAYLOAD_NEW_RX_INVALID_MESG_2,"xd",ikemesg,vlen);
    goto error;
  }

  certreq_payload = _rhp_ikev2_alloc_certreq_payload();
  if( certreq_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.certreq = certreq_payload;
  payload->ext_destructor = _rhp_ikev2_certreq_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_certreq_payload_serialize;

  certreq_payloadh = (rhp_proto_ike_certreq_payload*)_rhp_pkt_pull(ikemesg->rx_pkt,payload_len);
  if( certreq_payloadh == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_CERTREQ_PAYLOAD_NEW_RX_INVALID_MESG_3,"x",ikemesg);
    goto error;
  }

  if( vlen && (vlen % RHP_PROTO_IKE_CERTENC_SHA1_DIGEST_LEN) ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_CERTREQ_PAYLOAD_NEW_RX_INVALID_MESG_4,"xdd",ikemesg,vlen,RHP_PROTO_IKE_CERTENC_SHA1_DIGEST_LEN);
    goto error;
  }
  
  RHP_TRC(0,RHPTRCID_IKEV2_CERTREQ_PAYLOAD_NEW_RX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_CERTREQ_PAYLOAD_NEW_RX_ERR,"xE",ikemesg,err);
  return err;
}

int rhp_ikev2_certreq_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_certreq_payload* certreq_payload;

  RHP_TRC(0,RHPTRCID_IKEV2_CERTREQ_PAYLOAD_NEW_TX,"xLbx",ikemesg,"PROTO_IKE_PAYLOAD",payload_id,payload);

  certreq_payload = _rhp_ikev2_alloc_certreq_payload();
  if( certreq_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.certreq = certreq_payload;
  payload->ext_destructor = _rhp_ikev2_certreq_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_certreq_payload_serialize;
  
  RHP_TRC(0,RHPTRCID_IKEV2_CERTREQ_PAYLOAD_NEW_TX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_CERTREQ_PAYLOAD_NEW_TX_ERR,"xE",ikemesg,err);
  return err;
}
