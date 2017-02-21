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


static u8 _rhp_ikev2_auth_payload_get_auth_method(rhp_ikev2_payload* payload)
{
  u8 ret;
  rhp_proto_ike_auth_payload* auth_payloadh = (rhp_proto_ike_auth_payload*)payload->payloadh;
  if( auth_payloadh ){
    ret = auth_payloadh->auth_method;
  }else{
    ret = payload->ext.auth->auth_method;
  }
  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_PAYLOAD_GET_AUTH_METHOD,"xxw",payload,auth_payloadh,ret);
  return ret;
}

static void _rhp_ikev2_auth_payload_destructor(rhp_ikev2_payload* payload)
{
  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_PAYLOAD_DESTRUCTOR,"xxx",payload,payload->ext.auth,payload->ext.auth->auth_data);

  if( payload->ext.auth->auth_data ){
  	_rhp_free(payload->ext.auth->auth_data);
  }

  return;
}

static int _rhp_ikev2_auth_payload_set_auth_data(rhp_ikev2_payload* payload,u8 auth_method,int auth_data_len,u8* auth_data)
{
  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_PAYLOAD_SET_AUTH_METHOD,"xbp",payload,auth_method,auth_data_len,auth_data);

  if( payload->ext.auth->auth_data ){
    RHP_BUG("");
    return -EEXIST;
  }

  payload->ext.auth->auth_data = (u8*)_rhp_malloc(auth_data_len);
  if( payload->ext.auth->auth_data == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  memcpy(payload->ext.auth->auth_data,auth_data,auth_data_len);
  payload->ext.auth->auth_data_len = auth_data_len;
  payload->ext.auth->auth_method = auth_method;

  return 0;
}

static int _rhp_ikev2_auth_payload_get_auth_data_len(rhp_ikev2_payload* payload)
{
  int len;
  if( payload->ext.auth->auth_data ){
    len = payload->ext.auth->auth_data_len;
  }else{
    len = payload->get_len_rx(payload);
    len -= sizeof(rhp_proto_ike_auth_payload);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_PAYLOAD_GET_KEY_LEN,"xxd",payload,payload->ext.auth->auth_data,len);
  return len;
}

static u8* _rhp_ikev2_auth_payload_get_auth_data(rhp_ikev2_payload* payload)
{
  u8* ret;
  rhp_proto_ike_auth_payload* auth_payloadh;
  int auth_data_len = _rhp_ikev2_auth_payload_get_auth_data_len(payload);
  if( payload->ext.auth->auth_data ){
    ret = payload->ext.auth->auth_data;
  }else{
    auth_payloadh = (rhp_proto_ike_auth_payload*)(payload->payloadh);
    ret = (u8*)(auth_payloadh + 1);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_PAYLOAD_GET_KEY,"xxxp",payload,payload->ext.auth->auth_data,ret,auth_data_len,ret);
  return ret;
}

static int _rhp_ikev2_auth_payload_serialize(rhp_ikev2_payload* payload,rhp_packet* pkt)
{
  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_PAYLOAD_SERIALIZE,"xx",payload,pkt);
  
  if( payload->ext.auth->auth_data ){

    int len = sizeof(rhp_proto_ike_auth_payload) + payload->ext.auth->auth_data_len;
    rhp_proto_ike_auth_payload* p;

    p = (rhp_proto_ike_auth_payload*)rhp_pkt_expand_tail(pkt,len);
    if( p == NULL ){
      RHP_BUG("");
      return -ENOMEM;
    }
    
    p->next_payload = payload->get_next_payload(payload);
    p->critical_rsv = RHP_PROTO_IKE_PLD_SET_CRITICAL;
    p->len = htons(len);
    p->auth_method = payload->ext.auth->get_auth_method(payload);
    p->reserved1 = 0;
    p->reserved2 = 0;

    memcpy((p + 1),payload->ext.auth->auth_data,payload->ext.auth->auth_data_len);
    
    payload->ikemesg->tx_mesg_len += len;

    p->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
    if( payload->next ){
      p->next_payload = payload->next->get_payload_id(payload->next);
    }
    
    RHP_TRC(0,RHPTRCID_IKEV2_AUTH_PAYLOAD_SERIALIZE_RTRN,"");
    rhp_pkt_trace_dump("_rhp_ikev2_auth_payload_serialize(1)",pkt);
    return 0;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_PAYLOAD_SERIALIZE_ERR,"");
  return -EINVAL;
}

rhp_ikev2_auth_payload* _rhp_ikev2_alloc_auth_payload()
{
  rhp_ikev2_auth_payload* auth_payload;

  auth_payload = (rhp_ikev2_auth_payload*)_rhp_malloc(sizeof(rhp_ikev2_auth_payload));
  if( auth_payload == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(auth_payload,0,sizeof(rhp_ikev2_auth_payload));

  auth_payload->get_auth_method = _rhp_ikev2_auth_payload_get_auth_method;
  auth_payload->set_auth_data = _rhp_ikev2_auth_payload_set_auth_data;
  auth_payload->get_auth_data = _rhp_ikev2_auth_payload_get_auth_data;
  auth_payload->get_auth_data_len = _rhp_ikev2_auth_payload_get_auth_data_len;

  RHP_TRC(0,RHPTRCID_IKEV2_ALLOC_AUTH_PAYLOAD,"x",auth_payload);
  return auth_payload;
}

int rhp_ikev2_auth_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_auth_payload* auth_payload;
  rhp_proto_ike_auth_payload* auth_payloadh = (rhp_proto_ike_auth_payload*)payloadh;
  u8 auth_method;

  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_PAYLOAD_NEW_RX,"xbxdxp",ikemesg,payload_id,payloadh,payload_len,payload,payload_len,payloadh);

  if( payload_len <= (int)sizeof(rhp_proto_ike_auth_payload) ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_AUTH_PAYLOAD_NEW_RX_INVALID_MESG_1,"xdd",ikemesg,payload_len,sizeof(rhp_proto_ike_auth_payload));
    goto error;
  }

  auth_method = auth_payloadh->auth_method;
  
  switch( auth_method ){
    case RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG:
    case RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY:
    case RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH:
    	break;
    case RHP_PROTO_IKE_AUTHMETHOD_DSS_SIG:
    default:    
      err = RHP_STATUS_UNKNOWN_PARAM;
      RHP_TRC(0,RHPTRCID_IKEV2_AUTH_PAYLOAD_NEW_RX_INVALID_MESG_2,"xb",ikemesg,auth_method);
      goto error;
  }
  
  auth_payload = _rhp_ikev2_alloc_auth_payload();
  if( auth_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.auth = auth_payload;
  payload->ext_destructor = _rhp_ikev2_auth_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_auth_payload_serialize;

  auth_payloadh = (rhp_proto_ike_auth_payload*)_rhp_pkt_pull(ikemesg->rx_pkt,payload_len);
  if( auth_payloadh == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_AUTH_PAYLOAD_NEW_RX_INVALID_MESG_3,"x",ikemesg);
    goto error;
  }
  
  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_PAYLOAD_NEW_RX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_PAYLOAD_NEW_RX_ERR,"xE",ikemesg,err);
  return err;
}

int rhp_ikev2_auth_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_auth_payload* auth_payload;

  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_PAYLOAD_NEW_TX,"xLbx",ikemesg,"PROTO_IKE_PAYLOAD",payload_id,payload);

  auth_payload = _rhp_ikev2_alloc_auth_payload();
  if( auth_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.auth = auth_payload;
  payload->ext_destructor = _rhp_ikev2_auth_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_auth_payload_serialize;

  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_PAYLOAD_NEW_TX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_PAYLOAD_NEW_TX_ERR,"xE",ikemesg,err);
  return err;
}

