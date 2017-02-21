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


static u8 _rhp_ikev2_id_payload_get_id_type(rhp_ikev2_payload* payload)
{
  u8 ret;
  rhp_proto_ike_id_payload* id_payloadh = (rhp_proto_ike_id_payload*)payload->payloadh;
  if( id_payloadh ){
    ret = id_payloadh->id_type;
  }else{
    ret = payload->ext.id->id_type;
  }
  RHP_TRC(0,RHPTRCID_IKEV2_ID_PAYLOAD_GET_ID_TYPE,"xxb",payload,id_payloadh,ret);
  return ret;
}

static int _rhp_ikev2_id_payload_get_id_len(rhp_ikev2_payload* payload)
{
  int len;
  if( payload->ext.id->id ){
    len = payload->ext.id->id_len;
  }else{
    len = payload->get_len_rx(payload);
    len -= sizeof(rhp_proto_ike_id_payload);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_ID_PAYLOAD_GET_ID_LEN,"xxd",payload,payload->ext.id->id,len);
  return len;
}

static u8* _rhp_ikev2_id_payload_get_id(rhp_ikev2_payload* payload)
{
  u8* ret;
  rhp_proto_ike_id_payload* id_payloadh;
  int id_len = _rhp_ikev2_id_payload_get_id_len(payload);

  if( id_len ){

		if( payload->ext.id->id ){
			ret = payload->ext.id->id;
		}else{
			id_payloadh = (rhp_proto_ike_id_payload*)(payload->payloadh);
			ret = (u8*)(id_payloadh + 1);
		}

  }else{

  	u8 id_type = payload->ext.id->get_id_type(payload);

    if( !rhp_ikev2_is_null_auth_id(id_type) ){
    	RHP_BUG("%d",id_type);
    }

    ret = NULL;
  }
  RHP_TRC(0,RHPTRCID_IKEV2_ID_PAYLOAD_GET_ID,"xxxp",payload,payload->ext.id->id,ret,id_len,ret);
  return ret;
}

static void _rhp_ikev2_id_payload_destructor(rhp_ikev2_payload* payload)
{
  RHP_TRC(0,RHPTRCID_IKEV2_ID_PAYLOAD_DESTRUCTOR,"xx",payload,payload->ext.id->id);

  if( payload->ext.id->id ){
    _rhp_free(payload->ext.id->id);
    payload->ext.id->id = NULL;
    payload->ext.id->id_len = 0;
  }
  
  return;
}

static int _rhp_ikev2_id_payload_serialize(rhp_ikev2_payload* payload,rhp_packet* pkt)
{
	u8 id_type = payload->ext.id->get_id_type(payload);

	RHP_TRC(0,RHPTRCID_IKEV2_ID_PAYLOAD_SERIALIZE,"xxxb",payload,pkt,payload->ext.id->id,id_type);
  
  if( payload->ext.id->id || id_type == RHP_PROTO_IKE_ID_NULL_ID ){

    int len = sizeof(rhp_proto_ike_id_payload) + payload->ext.id->id_len;
    rhp_proto_ike_id_payload* p;

    p = (rhp_proto_ike_id_payload*)rhp_pkt_expand_tail(pkt,len);
    if( p == NULL ){
      RHP_BUG("");
      return -ENOMEM;
    }
    
    p->next_payload = payload->get_next_payload(payload);
    p->critical_rsv = RHP_PROTO_IKE_PLD_SET_CRITICAL;
    p->len = htons(len);
    p->id_type = payload->ext.id->get_id_type(payload);
    p->reserved1 = 0;
    p->reserved2 = 0;

    if( payload->ext.id->id_len ){
    	memcpy((p + 1),payload->ext.id->id,payload->ext.id->id_len);
    }
    
    payload->ikemesg->tx_mesg_len += len;

    p->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
    if( payload->next ){
      p->next_payload = payload->next->get_payload_id(payload->next);
    }
    
    RHP_TRC(0,RHPTRCID_IKEV2_ID_PAYLOAD_SERIALIZE_RTRN,"xx",payload,pkt);
    rhp_pkt_trace_dump("_rhp_ikev2_id_payload_serialize",pkt);
    return 0;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_ID_PAYLOAD_SERIALIZE_ERR,"xx",payload,pkt);
  return -EINVAL;
}

static int _rhp_ikev2_id_payload_set_id(rhp_ikev2_payload* payload,int id_type,int id_len,u8* id)
{
  RHP_TRC(0,RHPTRCID_IKEV2_ID_PAYLOAD_SET_ID,"xbp",payload,id_type,id_len,id);

	id_type = rhp_ikev2_to_null_auth_id(id_type);

  if( id_type != RHP_PROTO_IKE_ID_NULL_ID ){

    if( payload->ext.id->id ){
      RHP_BUG("");
      return -EEXIST;
    }

		payload->ext.id->id = (u8*)_rhp_malloc(id_len);
		if( payload->ext.id->id == NULL ){
			RHP_BUG("");
			return -ENOMEM;
		}

		memcpy(payload->ext.id->id,id,id_len);
		payload->ext.id->id_len = id_len;

  }else{

		payload->ext.id->id = NULL;
		payload->ext.id->id_len = 0;
  }

  payload->ext.id->id_type = id_type;

  return 0;
}


static int _rhp_ikev2_id_payload_is_initiator(rhp_ikev2_payload* payload)
{
	int ret;
  if( payload->payload_id == RHP_PROTO_IKE_PAYLOAD_ID_I ){
    ret = RHP_TRUE;    
  }else{
    ret = RHP_FALSE;    
  }
  
  RHP_TRC(0,RHPTRCID_IKEV2_ID_PAYLOAD_IS_INITIATOR,"xd",payload,ret);
  return ret;
}


static rhp_ikev2_id_payload* _rhp_ikev2_alloc_id_payload()
{
  rhp_ikev2_id_payload* id_payload;

  id_payload = (rhp_ikev2_id_payload*)_rhp_malloc(sizeof(rhp_ikev2_id_payload));
  if( id_payload == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(id_payload,0,sizeof(rhp_ikev2_id_payload));

  id_payload->get_id_type = _rhp_ikev2_id_payload_get_id_type;
  id_payload->get_id_len = _rhp_ikev2_id_payload_get_id_len;
  id_payload->get_id = _rhp_ikev2_id_payload_get_id;
  id_payload->set_id = _rhp_ikev2_id_payload_set_id;
  id_payload->is_initiator = _rhp_ikev2_id_payload_is_initiator;

  RHP_TRC(0,RHPTRCID_IKEV2_ALLOC_ID_PAYLOAD,"x",id_payload);
  return id_payload;
}

int rhp_ikev2_id_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_id_payload* id_payload;
  rhp_proto_ike_id_payload* id_payloadh = (rhp_proto_ike_id_payload*)payloadh;
  u8 id_type;
  int id_len;

  RHP_TRC(0,RHPTRCID_IKEV2_ID_PAYLOAD_NEW_RX,"xbxdxp",ikemesg,payload_id,payloadh,payload_len,payload,payload_len,payloadh);

  if( payload_len < (int)sizeof(rhp_proto_ike_id_payload) ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_ID_PAYLOAD_NEW_RX_INVALID_MESG_1,"xdd",ikemesg,payload_len,sizeof(rhp_proto_ike_id_payload));
    goto error;
  }

  id_type = id_payloadh->id_type;
  
  switch( id_type ){
    
    case RHP_PROTO_IKE_ID_FQDN:
    case RHP_PROTO_IKE_ID_RFC822_ADDR:
    case RHP_PROTO_IKE_ID_DER_ASN1_DN:
    case RHP_PROTO_IKE_ID_IPV4_ADDR:
    case RHP_PROTO_IKE_ID_IPV6_ADDR:
    case RHP_PROTO_IKE_ID_NULL_ID:
      break;
    
    case RHP_PROTO_IKE_ID_DER_ASN1_GN:
    case RHP_PROTO_IKE_ID_KEY_ID:
    default:
      err = RHP_STATUS_UNKNOWN_PARAM;
      RHP_TRC(0,RHPTRCID_IKEV2_ID_PAYLOAD_NEW_RX_INVALID_MESG_2,"xb",ikemesg,id_type);
      goto error;
  }
  
  id_len = payload_len - sizeof(rhp_proto_ike_id_payload);
  if( id_type == RHP_PROTO_IKE_ID_NULL_ID ){

  	if( id_len ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_IKEV2_ID_PAYLOAD_NEW_RX_INVALID_MESG_ID_NULL_LEN,"xd",ikemesg,id_len);
			goto error;
  	}

  }else{

  	if( id_len < 1 ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_IKEV2_ID_PAYLOAD_NEW_RX_INVALID_MESG_INVALID_LEN,"xd",ikemesg,id_len);
			goto error;
  	}
  }
  
  id_payload = _rhp_ikev2_alloc_id_payload();
  if( id_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.id = id_payload;
  payload->ext_destructor = _rhp_ikev2_id_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_id_payload_serialize;

  id_payloadh = (rhp_proto_ike_id_payload*)_rhp_pkt_pull(ikemesg->rx_pkt,payload_len);
  if( id_payloadh == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_ID_PAYLOAD_NEW_RX_INVALID_MESG_4,"x",ikemesg);
    goto error;
  }
  
  RHP_TRC(0,RHPTRCID_IKEV2_ID_PAYLOAD_NEW_RX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_ID_PAYLOAD_NEW_RX_ERR,"xE",ikemesg,err);
  return err;
}

int rhp_ikev2_id_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_id_payload* id_payload;

  RHP_TRC(0,RHPTRCID_IKEV2_ID_PAYLOAD_NEW_TX,"xLbx",ikemesg,"PROTO_IKE_PAYLOAD",payload_id,payload);

  id_payload = _rhp_ikev2_alloc_id_payload();
  if( id_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.id = id_payload;
  payload->ext_destructor = _rhp_ikev2_id_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_id_payload_serialize;

  RHP_TRC(0,RHPTRCID_IKEV2_ID_PAYLOAD_NEW_TX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_ID_PAYLOAD_NEW_TX_ERR,"xE",ikemesg,err);
  return err;
}

