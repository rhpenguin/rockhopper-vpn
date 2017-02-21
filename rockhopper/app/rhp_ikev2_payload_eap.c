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


static u8 _rhp_ikev2_eap_payload_get_code(rhp_ikev2_payload* payload)
{
  u8 code;
  rhp_proto_ike_payload* eap_payloadh;

  if( payload->ext.eap->tx_eap_mesg ){
    code = *((u8*)payload->ext.eap->tx_eap_mesg);
  }else{
    eap_payloadh = (rhp_proto_ike_payload*)(payload->payloadh);
    code = *((u8*)(eap_payloadh + 1));
  }
  RHP_TRC(0,RHPTRCID_IKEV2_EAP_PAYLOAD_GET_CODE,"xLb",payload,"EAP_CODE",code);
  return code;
}

static u8 _rhp_ikev2_eap_payload_get_identifier(rhp_ikev2_payload* payload)
{
  u8 ident;
  rhp_proto_ike_payload* eap_payloadh;

  if( payload->ext.eap->tx_eap_mesg ){
  	ident = *(((u8*)payload->ext.eap->tx_eap_mesg) + 1);
  }else{
    eap_payloadh = (rhp_proto_ike_payload*)(payload->payloadh);
    ident = *(((u8*)(eap_payloadh + 1)) + 1);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_EAP_PAYLOAD_GET_IDENTIFIER,"xb",payload,ident);
  return ident;
}

static u8 _rhp_ikev2_eap_payload_get_type(rhp_ikev2_payload* payload)
{
  u8 type;
  u8 code;
  rhp_proto_ike_payload* eap_payloadh;

  code = _rhp_ikev2_eap_payload_get_code(payload);

  if( code != RHP_PROTO_EAP_CODE_REQUEST &&
  		code != RHP_PROTO_EAP_CODE_RESPONSE ){
  	RHP_BUG("code: %d",code);
  	return 0;
  }

  if( payload->ext.eap->tx_eap_mesg ){
  	type = *(((u8*)payload->ext.eap->tx_eap_mesg) + 4);
  }else{
    eap_payloadh = (rhp_proto_ike_payload*)(payload->payloadh);
    type = *(((u8*)(eap_payloadh + 1)) + 4);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_EAP_PAYLOAD_GET_TYPE,"xLb",payload,"EAP_TYPE",type);
  return type;
}


static void _rhp_ikev2_eap_payload_destructor(rhp_ikev2_payload* payload)
{
  RHP_TRC(0,RHPTRCID_IKEV2_EAP_PAYLOAD_DESTRUCTOR,"xx",payload,payload->ext.eap->tx_eap_mesg);

  if( payload->ext.eap->tx_eap_mesg ){
    _rhp_free(payload->ext.eap->tx_eap_mesg);
    payload->ext.eap->tx_eap_mesg = NULL;
    payload->ext.eap->tx_eap_mesg_len = 0;
  }

  return;
}

static int _rhp_ikev2_eap_payload_serialize(rhp_ikev2_payload* payload,rhp_packet* pkt)
{
  RHP_TRC(0,RHPTRCID_IKEV2_EAP_PAYLOAD_SERIALIZE,"xx",payload,pkt);

  if( payload->ext.eap->tx_eap_mesg ){

    int len = sizeof(rhp_proto_ike_payload) + payload->ext.eap->tx_eap_mesg_len;
    rhp_proto_ike_payload* p;

    p = (rhp_proto_ike_payload*)rhp_pkt_expand_tail(pkt,len);
    if( p == NULL ){
      RHP_BUG("");
      return -ENOMEM;
    }

    p->next_payload = payload->get_next_payload(payload);
    p->critical_rsv = 0;
    p->len = htons(len);

    memcpy((p + 1),payload->ext.eap->tx_eap_mesg,payload->ext.eap->tx_eap_mesg_len);

    payload->ikemesg->tx_mesg_len += len;

    p->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
    if( payload->next ){
      p->next_payload = payload->next->get_payload_id(payload->next);
    }

    RHP_TRC(0,RHPTRCID_IKEV2_EAP_PAYLOAD_SERIALIZE_RTRN,"xx",payload,pkt);
    rhp_pkt_trace_dump("_rhp_ikev2_eap_payload_serialize",pkt);
    return 0;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_EAP_PAYLOAD_SERIALIZE_ERR,"xx",payload,pkt);
  return -EINVAL;
}


static int _rhp_ikev2_eap_payload_set_eap_message(rhp_ikev2_payload* payload,u8* eap_mesg,int eap_mesg_len)
{
  if( eap_mesg_len < (int)sizeof(rhp_proto_eap) ){
    RHP_BUG("%d",eap_mesg_len);
    return -EINVAL;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_EAP_PAYLOAD_SET_EAP_MESSAGE,"xLbp",payload,"EAP_CODE",eap_mesg[0],eap_mesg_len,eap_mesg);

  if( payload->ext.eap->tx_eap_mesg ){
    RHP_BUG("");
    return -EEXIST;
  }

  payload->ext.eap->tx_eap_mesg = (u8*)_rhp_malloc(eap_mesg_len);
  if( payload->ext.eap->tx_eap_mesg == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  memcpy(payload->ext.eap->tx_eap_mesg,eap_mesg,eap_mesg_len);
  payload->ext.eap->tx_eap_mesg_len = eap_mesg_len;

  return 0;
}

static u8* _rhp_ikev2_eap_payload_get_eap_message(rhp_ikev2_payload* payload,int* eap_mesg_len_r)
{
	u8* ret = NULL;
	int ret_len = 0;
  rhp_proto_ike_payload* eap_payloadh;

  if( payload->ext.eap->tx_eap_mesg ){
  	ret = payload->ext.eap->tx_eap_mesg;
  	ret_len = payload->ext.eap->tx_eap_mesg_len;
  }else{
    eap_payloadh = (rhp_proto_ike_payload*)(payload->payloadh);
    ret = (u8*)(eap_payloadh + 1);
    ret_len = ntohs(eap_payloadh->len) - sizeof(rhp_proto_ike_payload);
  }

  *eap_mesg_len_r = ret_len;

  RHP_TRC(0,RHPTRCID_IKEV2_EAP_PAYLOAD_GET_EAP_MESSAGE,"xLbp",payload,"EAP_CODE",ret[0],*eap_mesg_len_r,(ret_len ? ret : NULL));
  return (ret_len ? ret : NULL);
}


rhp_ikev2_eap_payload* _rhp_ikev2_alloc_eap_payload()
{
  rhp_ikev2_eap_payload* eap_payload;

  eap_payload = (rhp_ikev2_eap_payload*)_rhp_malloc(sizeof(rhp_ikev2_eap_payload));
  if( eap_payload == NULL ){
  	RHP_BUG("");
    return NULL;
  }

  memset(eap_payload,0,sizeof(rhp_ikev2_eap_payload));

  eap_payload->get_code = _rhp_ikev2_eap_payload_get_code;
  eap_payload->get_identifier = _rhp_ikev2_eap_payload_get_identifier;
  eap_payload->get_type = _rhp_ikev2_eap_payload_get_type;
  eap_payload->set_eap_message = _rhp_ikev2_eap_payload_set_eap_message;
  eap_payload->get_eap_message = _rhp_ikev2_eap_payload_get_eap_message;

  RHP_TRC(0,RHPTRCID_IKEV2_ALLOC_EAP_PAYLOAD,"x",eap_payload);
  return eap_payload;
}


int rhp_ikev2_eap_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                 rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_eap_payload* eap_payload;
  rhp_proto_ike_eap_payload* eap_payloadh = (rhp_proto_ike_eap_payload*)payloadh;
  int vlen, eap_len;
  u8* endp;

  RHP_TRC(0,RHPTRCID_IKEV2_EAP_PAYLOAD_NEW_RX,"xbxdxp",ikemesg,payload_id,payloadh,payload_len,payload,payload_len,payloadh);

  if( payload_len < (int)sizeof(rhp_proto_ike_eap_payload) ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_EAP_PAYLOAD_NEW_RX_INVALID_MESG_1,"xdd",ikemesg,payload_len,sizeof(rhp_proto_ike_eap_payload));
    goto error;
  }

  vlen = payload_len - sizeof(rhp_proto_ike_eap_payload);
  if( vlen < 0 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_EAP_PAYLOAD_NEW_RX_INVALID_MESG_2,"xd",ikemesg,vlen);
    goto error;
  }

  endp = ikemesg->rx_pkt->end;
  eap_len = ntohs(eap_payloadh->eap_len);

  if( eap_len < (int)sizeof(rhp_proto_eap) ||
  		(eap_len + (int)sizeof(rhp_proto_ike_payload)) != payload_len ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_EAP_PAYLOAD_NEW_RX_INVALID_MESG_3,"xd",ikemesg,eap_len);
  }

  if( ((u8*)payloadh) + sizeof(rhp_proto_ike_payload) + eap_len > endp ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_EAP_PAYLOAD_NEW_RX_INVALID_MESG_EAP_MESG_LEN,"xd",ikemesg,eap_len);
  }

  if( eap_payloadh->eap_code == RHP_PROTO_EAP_CODE_REQUEST ){

  	if( eap_len < (int)sizeof(rhp_proto_eap_request) ){
      err = RHP_STATUS_INVALID_MSG;
      RHP_TRC(0,RHPTRCID_IKEV2_EAP_PAYLOAD_NEW_RX_INVALID_MESG_EAP_REQUEST,"xd",ikemesg,eap_len);
      goto error;
  	}

  }else if( eap_payloadh->eap_code == RHP_PROTO_EAP_CODE_RESPONSE ){

  	if( eap_len < (int)sizeof(rhp_proto_eap_response) ){
  		err = RHP_STATUS_INVALID_MSG;
  		RHP_TRC(0,RHPTRCID_IKEV2_EAP_PAYLOAD_NEW_RX_INVALID_MESG_EAP_RESPONSE,"xd",ikemesg,eap_len);
      goto error;
  	}

  }else if( eap_payloadh->eap_code == RHP_PROTO_EAP_CODE_SUCCESS ){

  	if( eap_len < (int)sizeof(rhp_proto_eap_success) ){
  		err = RHP_STATUS_INVALID_MSG;
  		RHP_TRC(0,RHPTRCID_IKEV2_EAP_PAYLOAD_NEW_RX_INVALID_MESG_EAP_SUCCESS,"xd",ikemesg,eap_len);
      goto error;
  	}

  }else if( eap_payloadh->eap_code == RHP_PROTO_EAP_CODE_FAILURE ){

  	if( eap_len < (int)sizeof(rhp_proto_eap_failure) ){
  		err = RHP_STATUS_INVALID_MSG;
  		RHP_TRC(0,RHPTRCID_IKEV2_EAP_PAYLOAD_NEW_RX_INVALID_MESG_EAP_FAILURE,"xd",ikemesg,eap_len);
      goto error;
  	}
  }



  eap_payload = _rhp_ikev2_alloc_eap_payload();
  if( eap_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.eap = eap_payload;
  payload->ext_destructor = _rhp_ikev2_eap_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_eap_payload_serialize;

  eap_payloadh = (rhp_proto_ike_eap_payload*)_rhp_pkt_pull(ikemesg->rx_pkt,payload_len);
  if( eap_payloadh == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_EAP_PAYLOAD_NEW_RX_INVALID_MESG_4,"x",ikemesg);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_EAP_PAYLOAD_NEW_RX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_EAP_PAYLOAD_NEW_RX_ERR,"xE",ikemesg,err);
  return err;
}

int rhp_ikev2_eap_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_eap_payload* eap_payload;

  RHP_TRC(0,RHPTRCID_IKEV2_EAP_PAYLOAD_NEW_TX,"xbx",ikemesg,payload_id,payload);

  eap_payload = _rhp_ikev2_alloc_eap_payload();
  if( eap_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.eap = eap_payload;
  payload->ext_destructor = _rhp_ikev2_eap_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_eap_payload_serialize;

  RHP_TRC(0,RHPTRCID_IKEV2_EAP_PAYLOAD_NEW_TX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_EAP_PAYLOAD_NEW_TX_ERR,"xE",ikemesg,err);
  return err;
}



