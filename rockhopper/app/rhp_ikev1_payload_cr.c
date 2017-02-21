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
#include "rhp_ikesa.h"
#include "rhp_ikev2_mesg.h"

static int _rhp_ikev1_cr_payload_get_ca_len(rhp_ikev2_payload* payload)
{
  int len;
  if( payload->ext.v1_cr->ca ){
    len = payload->ext.v1_cr->ca_len;
  }else{
    len = payload->get_len_rx(payload);
    len -= sizeof(rhp_proto_ikev1_cr_payload);
  }
  RHP_TRC(0,RHPTRCID_IKEV1_CR_PAYLOAD_GET_CERT_LEN,"xxd",payload,payload->ext.v1_cr->ca,len);
  return len;
}

static u8* _rhp_ikev1_cr_payload_get_ca(rhp_ikev2_payload* payload)
{
  u8* ret;
  rhp_proto_ikev1_cr_payload* cr_payloadh;
  int len = _rhp_ikev1_cr_payload_get_ca_len(payload);

  if( payload->ext.v1_cr->ca ){
    ret = payload->ext.v1_cr->ca;
  }else{
    if( len ){
      cr_payloadh = (rhp_proto_ikev1_cr_payload*)(payload->payloadh);
      ret = (u8*)(cr_payloadh + 1);
    }else{
      ret = NULL;
    }
  }
  RHP_TRC(0,RHPTRCID_IKEV1_CR_PAYLOAD_GET_CERT,"xxxp",payload,payload->ext.v1_cr->ca,ret,len,ret);
  return ret;
}

static u8 _rhp_ikev1_cr_payload_get_cert_encoding(rhp_ikev2_payload* payload)
{
  u8 ret;
  rhp_proto_ikev1_cr_payload* cr_payloadh;

  if( payload->ext.v1_cr->cert_encoding ){
    ret = payload->ext.v1_cr->cert_encoding;
  }else{
    cr_payloadh = (rhp_proto_ikev1_cr_payload*)(payload->payloadh);
    ret = cr_payloadh->cert_encoding;
  }
  RHP_TRC(0,RHPTRCID_IKEV1_CR_PAYLOAD_GET_CERT_ENCODING,"xb",payload,ret);
  return ret;
}

static void _rhp_ikev1_cr_payload_set_cert_encoding(rhp_ikev2_payload* payload,u8 cert_encoding)
{
  payload->ext.v1_cr->cert_encoding = cert_encoding;

  RHP_TRC(0,RHPTRCID_IKEV1_CR_PAYLOAD_SET_CERT_ENCODING,"xb",payload,cert_encoding);
  return;
}

static void _rhp_ikev1_cr_payload_destructor(rhp_ikev2_payload* payload)
{
  RHP_TRC(0,RHPTRCID_IKEV1_CR_PAYLOAD_DESTRUCTOR,"xx",payload,payload->ext.v1_cr->ca);

  if( payload->ext.v1_cr->ca ){
    _rhp_free(payload->ext.v1_cr->ca);
    payload->ext.v1_cr->ca = NULL;
    payload->ext.v1_cr->ca_len = 0;
  }
  return;
}

static int _rhp_ikev1_cr_payload_serialize(rhp_ikev2_payload* payload,rhp_packet* pkt)
{
  int len;
  rhp_proto_ikev1_cr_payload* p;

  RHP_TRC(0,RHPTRCID_IKEV1_CR_PAYLOAD_SERIALIZE,"xx",payload,pkt);

  if( payload->ext.v1_cr->ca == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  len = sizeof(rhp_proto_ikev1_cr_payload) + payload->ext.v1_cr->ca_len;

  p = (rhp_proto_ikev1_cr_payload*)rhp_pkt_expand_tail(pkt,len);
  if( p == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  p->next_payload = payload->get_next_payload(payload);
  p->reserved = 0;
  p->len = htons(len);
  p->cert_encoding = payload->ext.v1_cr->cert_encoding;

  if( payload->ext.v1_cr->ca ){
    memcpy((p + 1),payload->ext.v1_cr->ca,payload->ext.v1_cr->ca_len);
  }

  payload->ikemesg->tx_mesg_len += len;

  p->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
  if( payload->next ){
    p->next_payload = payload->next->get_payload_id(payload->next);
  }
    
  RHP_TRC(0,RHPTRCID_IKEV1_CR_PAYLOAD_SERIALIZE_RTRN,"");
  rhp_pkt_trace_dump("_rhp_ikev1_cr_payload_serialize(1)",pkt);
  return 0;
}

static int _rhp_ikev1_cr_payload_set_ca(rhp_ikev2_payload* payload,int ca_len,u8* ca)
{
  RHP_TRC(0,RHPTRCID_IKEV1_CR_PAYLOAD_SET_CERT,"xp",payload,ca_len,ca);

  if( payload->ext.v1_cr->ca ){
    RHP_BUG("");
    return -EEXIST;
  }

  payload->ext.v1_cr->ca = (u8*)_rhp_malloc(ca_len);
  if( payload->ext.v1_cr->ca == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  memcpy(payload->ext.v1_cr->ca,ca,ca_len);
  payload->ext.v1_cr->ca_len = ca_len;

  return 0;
}

static rhp_ikev1_cr_payload* _rhp_ikev1_alloc_cr_payload()
{
  rhp_ikev1_cr_payload* cr_payload;

  cr_payload = (rhp_ikev1_cr_payload*)_rhp_malloc(sizeof(rhp_ikev1_cr_payload));
  if( cr_payload == NULL ){
    return NULL;
  }

  memset(cr_payload,0,sizeof(rhp_ikev1_cr_payload));

  cr_payload->get_ca_len = _rhp_ikev1_cr_payload_get_ca_len;
  cr_payload->get_ca = _rhp_ikev1_cr_payload_get_ca;
  cr_payload->set_ca = _rhp_ikev1_cr_payload_set_ca;
  cr_payload->set_cert_encoding = _rhp_ikev1_cr_payload_set_cert_encoding;
  cr_payload->get_cert_encoding = _rhp_ikev1_cr_payload_get_cert_encoding;

  
  RHP_TRC(0,RHPTRCID_IKEV2_ALLOC_CERT_PAYLOAD,"x",cr_payload);
  return cr_payload;
}


int rhp_ikev1_cr_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                 rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev1_cr_payload* cr_payload;
  rhp_proto_ikev1_cr_payload* cr_payloadh = (rhp_proto_ikev1_cr_payload*)payloadh;
  int vlen;
  
  RHP_TRC(0,RHPTRCID_IKEV1_CR_PAYLOAD_NEW_RX,"xbxdxp",ikemesg,payload_id,payloadh,payload_len,payload,payload_len,payloadh);

  if( payload_len < (int)sizeof(rhp_proto_ikev1_cr_payload) ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV1_CR_PAYLOAD_NEW_RX_INVALID_MESG_1,"xdd",ikemesg,payload_len,sizeof(rhp_proto_ikev1_cr_payload));
    goto error;
  }

  vlen = payload_len - sizeof(rhp_proto_ikev1_cr_payload);
  if( vlen < 0 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV1_CR_PAYLOAD_NEW_RX_INVALID_MESG_2,"xd",ikemesg,vlen);
    goto error;
  }

  cr_payload = _rhp_ikev1_alloc_cr_payload();
  if( cr_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.v1_cr = cr_payload;
  payload->ext_destructor = _rhp_ikev1_cr_payload_destructor;
  payload->ext_serialize = _rhp_ikev1_cr_payload_serialize;

  cr_payloadh = (rhp_proto_ikev1_cr_payload*)_rhp_pkt_pull(ikemesg->rx_pkt,payload_len);
  if( cr_payloadh == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV1_CR_PAYLOAD_NEW_RX_INVALID_MESG_4,"x",ikemesg);
    goto error;
  }


  RHP_TRC(0,RHPTRCID_IKEV1_CR_PAYLOAD_NEW_RX_RTRN,"xd",ikemesg,vlen);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_CR_PAYLOAD_NEW_RX_ERR,"xE",ikemesg,err);
  return err;
}

int rhp_ikev1_cr_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev1_cr_payload* cr_payload;

  RHP_TRC(0,RHPTRCID_IKEV1_CR_PAYLOAD_NEW_TX,"xLbx",ikemesg,"PROTO_IKE_PAYLOAD",payload_id,payload);

  cr_payload = _rhp_ikev1_alloc_cr_payload();
  if( cr_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.v1_cr = cr_payload;
  payload->ext_destructor = _rhp_ikev1_cr_payload_destructor;
  payload->ext_serialize = _rhp_ikev1_cr_payload_serialize;
  
  RHP_TRC(0,RHPTRCID_IKEV1_CR_PAYLOAD_NEW_TX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_CR_PAYLOAD_NEW_TX_ERR,"xE",ikemesg,err);
  return err;
}


