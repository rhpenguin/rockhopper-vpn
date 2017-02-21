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


static int _rhp_ikev1_sig_payload_get_sig_len(rhp_ikev2_payload* payload)
{
  int len;
  if( payload->ext.v1_sig->sig ){
    len = payload->ext.v1_sig->sig_len;
  }else{
    len = payload->get_len_rx(payload);
    len -= sizeof(rhp_proto_ikev1_sig_payload);
  }
  RHP_TRC(0,RHPTRCID_IKEV1_SIG_PAYLOAD_GET_KEY_LEN,"xxd",payload,payload->ext.v1_sig->sig,len);
  return len;
}

static u8* _rhp_ikev1_sig_payload_get_sig(rhp_ikev2_payload* payload)
{
  u8* ret;
  rhp_proto_ikev1_sig_payload* sig_payloadh;
  int sig_len = _rhp_ikev1_sig_payload_get_sig_len(payload);
  if( payload->ext.v1_sig->sig ){
    ret = payload->ext.v1_sig->sig;
  }else{
    sig_payloadh = (rhp_proto_ikev1_sig_payload*)(payload->payloadh);
    ret = (u8*)(sig_payloadh + 1);
  }
  RHP_TRC(0,RHPTRCID_IKEV1_SIG_PAYLOAD_GET_KEY,"xxxp",payload,payload->ext.v1_sig->sig,ret,sig_len,ret);
  return ret;
}

static void _rhp_ikev1_sig_payload_destructor(rhp_ikev2_payload* payload)
{
  RHP_TRC(0,RHPTRCID_IKEV1_SIG_PAYLOAD_DESTRUCTOR,"xx",payload,payload->ext.v1_sig->sig);

  if( payload->ext.v1_sig->sig ){
    _rhp_free(payload->ext.v1_sig->sig);
    payload->ext.v1_sig->sig = NULL;
    payload->ext.v1_sig->sig_len = 0;
  }
  return;
}

static int _rhp_ikev1_sig_payload_serialize(rhp_ikev2_payload* payload,rhp_packet* pkt)
{
  RHP_TRC(0,RHPTRCID_IKEV1_SIG_PAYLOAD_SERIALIZE,"xxx",payload,pkt,payload->ext.v1_sig->sig);
  
  if( payload->ext.v1_sig->sig ){

    int len = sizeof(rhp_proto_ikev1_sig_payload) + payload->ext.v1_sig->sig_len;
    rhp_proto_ikev1_sig_payload* p;

    p = (rhp_proto_ikev1_sig_payload*)rhp_pkt_expand_tail(pkt,len);
    if( p == NULL ){
      RHP_BUG("");
      return -ENOMEM;
    }
    
    p->next_payload = payload->get_next_payload(payload);
    p->reserved = 0;
    p->len = htons(len);

    memcpy((p + 1),payload->ext.v1_sig->sig,payload->ext.v1_sig->sig_len);
    
    payload->ikemesg->tx_mesg_len += len;

    p->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
    if( payload->next ){
      p->next_payload = payload->next->get_payload_id(payload->next);
    }
    
    RHP_TRC(0,RHPTRCID_IKEV1_SIG_PAYLOAD_SERIALIZE_RTRN,"xx",payload,pkt);
    rhp_pkt_trace_dump("_rhp_ikev1_sig_payload_serialize",pkt);
    return 0;
  }

  RHP_TRC(0,RHPTRCID_IKEV1_SIG_PAYLOAD_SERIALIZE_ERR,"xx",payload,pkt);
  return -EINVAL;
}

static int _rhp_ikev1_sig_payload_set_sig(rhp_ikev2_payload* payload,int sig_len,u8* sig)
{
  RHP_TRC(0,RHPTRCID_IKEV1_SIG_PAYLOAD_SET_SIG,"xp",payload,sig_len,sig);

  if( payload->ext.v1_sig->sig ){
    RHP_BUG("");
    return -EEXIST;
  }

  payload->ext.v1_sig->sig = (u8*)_rhp_malloc(sig_len);
  if( payload->ext.v1_sig->sig == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  memcpy(payload->ext.v1_sig->sig,sig,sig_len);
  payload->ext.v1_sig->sig_len = sig_len;

  return 0;
}

rhp_ikev1_sig_payload* _rhp_ikev1_alloc_sig_payload()
{
  rhp_ikev1_sig_payload* sig_payload;

  sig_payload = (rhp_ikev1_sig_payload*)_rhp_malloc(sizeof(rhp_ikev1_sig_payload));
  if( sig_payload == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(sig_payload,0,sizeof(rhp_ikev1_sig_payload));

  sig_payload->get_sig_len = _rhp_ikev1_sig_payload_get_sig_len;
  sig_payload->get_sig = _rhp_ikev1_sig_payload_get_sig;
  sig_payload->set_sig = _rhp_ikev1_sig_payload_set_sig;

  RHP_TRC(0,RHPTRCID_IKEV1_ALLOC_SIG_PAYLOAD,"x",sig_payload);
  return sig_payload;
}

int rhp_ikev1_sig_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                          rhp_proto_ikev1_sig_payload* payloadh,int payload_len,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev1_sig_payload* sig_payload;
  rhp_proto_ikev1_sig_payload* sig_payloadh = (rhp_proto_ikev1_sig_payload*)payloadh;

  RHP_TRC(0,RHPTRCID_IKEV1_SIG_PAYLOAD_NEW_RX,"xbxdxp",ikemesg,payload_id,payloadh,payload_len,payload,payload_len,payloadh);

  if( payload_len <= (int)sizeof(rhp_proto_ikev1_sig_payload) ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV1_SIG_PAYLOAD_NEW_RX_INVALID_MESG_1,"xdd",ikemesg,payload_len,sizeof(rhp_proto_ikev1_sig_payload));
    goto error;
  }
  
  sig_payload = _rhp_ikev1_alloc_sig_payload();
  if( sig_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.v1_sig = sig_payload;
  payload->ext_destructor = _rhp_ikev1_sig_payload_destructor;
  payload->ext_serialize = _rhp_ikev1_sig_payload_serialize;

  sig_payloadh = (rhp_proto_ikev1_sig_payload*)_rhp_pkt_pull(ikemesg->rx_pkt,payload_len);
  if( sig_payloadh == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV1_SIG_PAYLOAD_NEW_RX_INVALID_MESG_r,"x",ikemesg);
    goto error;
  }
  
  RHP_TRC(0,RHPTRCID_IKEV1_SIG_PAYLOAD_NEW_RX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_SIG_PAYLOAD_NEW_RX_ERR,"xE",ikemesg,err);
  return err;
}

int rhp_ikev1_sig_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev1_sig_payload* sig_payload;

  RHP_TRC(0,RHPTRCID_IKEV1_SIG_PAYLOAD_NEW_TX,"xLbx",ikemesg,"PROTO_IKE_PAYLOAD",payload_id,payload);

  sig_payload = _rhp_ikev1_alloc_sig_payload();
  if( sig_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.v1_sig = sig_payload;
  payload->ext_destructor = _rhp_ikev1_sig_payload_destructor;
  payload->ext_serialize = _rhp_ikev1_sig_payload_serialize;

  RHP_TRC(0,RHPTRCID_IKEV1_SIG_PAYLOAD_NEW_TX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_SIG_PAYLOAD_NEW_TX_ERR,"xE",ikemesg,err);
  return err;
}

