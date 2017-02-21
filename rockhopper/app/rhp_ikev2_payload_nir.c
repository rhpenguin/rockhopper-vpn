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

static int _rhp_ikev2_nir_payload_get_nonce_len(rhp_ikev2_payload* payload)
{
  int len;
  if( payload->ext.nir->nonce ){
    len = payload->ext.nir->nonce_len;
  }else{
    len = payload->get_len_rx(payload);
    len -= sizeof(rhp_proto_ike_nonce_payload);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_NIR_PAYLOAD_GET_NONCE_LEN,"xxd",payload,payload->ext.nir->nonce,len);
  return len;
}

static u8* _rhp_ikev2_nir_payload_get_nonce(rhp_ikev2_payload* payload)
{
  u8* ret;
  rhp_proto_ike_nonce_payload* nir_payloadh;
  int len  = _rhp_ikev2_nir_payload_get_nonce_len(payload);

  if( payload->ext.nir->nonce ){
    ret = payload->ext.nir->nonce;
  }else{
    nir_payloadh = (rhp_proto_ike_nonce_payload*)(payload->payloadh);
    ret = (u8*)(nir_payloadh + 1);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_NIR_PAYLOAD_GET_NONCE,"xxxp",payload,payload->ext.nir->nonce,ret,len,ret);
  return ret;
}

static void _rhp_ikev2_nir_payload_destructor(rhp_ikev2_payload* payload)
{
  RHP_TRC(0,RHPTRCID_IKEV2_NIR_PAYLOAD_DESTRUCTOR,"xx",payload,payload->ext.nir->nonce);

  if( payload->ext.nir->nonce ){
    _rhp_free(payload->ext.nir->nonce);
    payload->ext.nir->nonce = NULL;
    payload->ext.nir->nonce_len = 0;
  }
  return;
}

static int _rhp_ikev2_nir_payload_serialize(rhp_ikev2_payload* payload,rhp_packet* pkt)
{
  RHP_TRC(0,RHPTRCID_IKEV2_NIR_PAYLOAD_SERIALIZE,"xxx",payload,pkt,payload->ext.nir->nonce);

  if( payload->ext.nir->nonce ){

    int len = sizeof(rhp_proto_ike_nonce_payload) + payload->ext.nir->nonce_len;
    rhp_proto_ike_nonce_payload* p;

    p = (rhp_proto_ike_nonce_payload*)rhp_pkt_expand_tail(pkt,len);

    if( p == NULL ){
      return -ENOMEM;
    }

    p->next_payload = payload->get_next_payload(payload);
    if( payload->is_v1 ){
    	p->critical_rsv = 0;
    }else{
    	p->critical_rsv = RHP_PROTO_IKE_PLD_SET_CRITICAL;
    }
    p->len = htons(len);

    memcpy((p + 1),payload->ext.nir->nonce,payload->ext.nir->nonce_len);

    payload->ikemesg->tx_mesg_len += len;

    p->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
    if( payload->next ){
      p->next_payload = payload->next->get_payload_id(payload->next);
    }
    
    RHP_TRC(0,RHPTRCID_IKEV2_NIR_PAYLOAD_SERIALIZE_RTRN,"");
    rhp_pkt_trace_dump("_rhp_ikev2_nir_payload_serialize",pkt);
    return 0;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_NIR_PAYLOAD_SERIALIZE_ERR,"");
  return -EINVAL;
}

static int _rhp_ikev2_nir_payload_set_nonce(struct _rhp_ikev2_payload* payload,int nonce_len,u8* nonce)
{

  RHP_TRC(0,RHPTRCID_IKEV2_NIR_PAYLOAD_SET_NONCE,"xp",payload,nonce_len,nonce);

  if( payload->ext.nir->nonce ){
    RHP_BUG("");
    return -EEXIST;
  }

  payload->ext.nir->nonce = (u8*)_rhp_malloc(nonce_len);
  if( payload->ext.nir->nonce == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  memcpy(payload->ext.nir->nonce,nonce,nonce_len);
  payload->ext.nir->nonce_len = nonce_len;

  return 0;
}

rhp_ikev2_nir_payload* _rhp_ikev2_alloc_nir_payload()
{
  rhp_ikev2_nir_payload* nir_payload;

  nir_payload = (rhp_ikev2_nir_payload*)_rhp_malloc(sizeof(rhp_ikev2_nir_payload));
  if( nir_payload == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(nir_payload,0,sizeof(rhp_ikev2_nir_payload));

  nir_payload->get_nonce_len = _rhp_ikev2_nir_payload_get_nonce_len;
  nir_payload->get_nonce = _rhp_ikev2_nir_payload_get_nonce;
  nir_payload->set_nonce = _rhp_ikev2_nir_payload_set_nonce;

  RHP_TRC(0,RHPTRCID_IKEV2_ALLOC_NIR_PAYLOAD,"x",nir_payload);
  return nir_payload;
}


int rhp_ikev2_nir_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                  rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_nir_payload* nir_payload;
  rhp_proto_ike_nonce_payload* nir_payloadh = (rhp_proto_ike_nonce_payload*)payloadh;
  int nlen;

  RHP_TRC(0,RHPTRCID_IKEV2_NIR_PAYLOAD_NEW_RX,"xbxdxp",ikemesg,payload_id,payloadh,payload_len,payload,payload_len,payloadh);

  if( payload_len <= (int)sizeof(rhp_proto_ike_nonce_payload) ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_NIR_PAYLOAD_NEW_RX_INVALID_MESG_1,"xdd",ikemesg,payload_len,sizeof(rhp_proto_ike_nonce_payload));
    goto error;
  }

  nlen = payload_len - sizeof(rhp_proto_ike_nonce_payload);
  if( nlen < RHP_PROTO_IKE_NONCE_MIN_SZ || nlen > RHP_PROTO_IKE_NONCE_MAX_SZ ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_NIR_PAYLOAD_NEW_RX_INVALID_MESG_2,"xddd",ikemesg,nlen,RHP_PROTO_IKE_NONCE_MIN_SZ,RHP_PROTO_IKE_NONCE_MAX_SZ);
    goto error;
  }

  nir_payload = _rhp_ikev2_alloc_nir_payload();
  if( nir_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.nir = nir_payload;
  payload->ext_destructor = _rhp_ikev2_nir_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_nir_payload_serialize;

  nir_payloadh = (rhp_proto_ike_nonce_payload*)_rhp_pkt_pull(ikemesg->rx_pkt,payload_len);
  if( nir_payloadh == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_NIR_PAYLOAD_NEW_RX_INVALID_MESG_3,"x",ikemesg);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_NIR_PAYLOAD_NEW_RX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_NIR_PAYLOAD_NEW_RX_ERR,"xE",ikemesg,err);
  return err;
}

int rhp_ikev2_nir_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_nir_payload* nir_payload;

  RHP_TRC(0,RHPTRCID_IKEV2_NIR_PAYLOAD_NEW_TX,"xLbx",ikemesg,"PROTO_IKE_PAYLOAD",payload_id,payload);

  nir_payload = _rhp_ikev2_alloc_nir_payload();
  if( nir_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.nir = nir_payload;
  payload->ext_destructor = _rhp_ikev2_nir_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_nir_payload_serialize;

  RHP_TRC(0,RHPTRCID_IKEV2_NIR_PAYLOAD_NEW_TX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_NIR_PAYLOAD_NEW_TX_ERR,"xE",ikemesg,err);
  return err;
}
