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


static u16 _rhp_ikev2_ke_payload_get_dhgrp(rhp_ikev2_payload* payload)
{
  u16 ret;
  rhp_proto_ike_ke_payload* ke_payloadh = (rhp_proto_ike_ke_payload*)payload->payloadh;
  if( ke_payloadh ){
    ret = ntohs(ke_payloadh->dh_group);
  }else{
    ret = payload->ext.ke->dhgrp;
  }
  RHP_TRC(0,RHPTRCID_IKEV2_KE_PAYLOAD_GET_DHGRP,"xxw",payload,ke_payloadh,ret);
  return ret;
}

static int _rhp_ikev2_ke_payload_get_key_len(rhp_ikev2_payload* payload)
{
  int len;
  if( payload->ext.ke->key ){
    len = payload->ext.ke->key_len;
  }else{
    len = payload->get_len_rx(payload);
    len -= sizeof(rhp_proto_ike_ke_payload);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_KE_PAYLOAD_GET_KEY_LEN,"xxd",payload,payload->ext.ke->key,len);
  return len;
}

static u8* _rhp_ikev2_ke_payload_get_key(rhp_ikev2_payload* payload)
{
  u8* ret;
  rhp_proto_ike_ke_payload* ke_payloadh;
  int key_len = _rhp_ikev2_ke_payload_get_key_len(payload);
  if( payload->ext.ke->key ){
    ret = payload->ext.ke->key;
  }else{
    ke_payloadh = (rhp_proto_ike_ke_payload*)(payload->payloadh);
    ret = (u8*)(ke_payloadh + 1);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_KE_PAYLOAD_GET_KEY,"xxxp",payload,payload->ext.ke->key,ret,key_len,ret);
  return ret;
}

static void _rhp_ikev2_ke_payload_destructor(rhp_ikev2_payload* payload)
{
  RHP_TRC(0,RHPTRCID_IKEV2_KE_PAYLOAD_DESTRUCTOR,"xx",payload,payload->ext.ke->key);

  if( payload->ext.ke->key ){
    _rhp_free(payload->ext.ke->key);
    payload->ext.ke->key = NULL;
    payload->ext.ke->key_len = 0;
  }
  return;
}

static int _rhp_ikev2_ke_payload_serialize(rhp_ikev2_payload* payload,rhp_packet* pkt)
{
  RHP_TRC(0,RHPTRCID_IKEV2_KE_PAYLOAD_SERIALIZE,"xxx",payload,pkt,payload->ext.ke->key);
  
  if( payload->ext.ke->key ){

    int len = sizeof(rhp_proto_ike_ke_payload) + payload->ext.ke->key_len;
    rhp_proto_ike_ke_payload* p;

    p = (rhp_proto_ike_ke_payload*)rhp_pkt_expand_tail(pkt,len);
    if( p == NULL ){
      RHP_BUG("");
      return -ENOMEM;
    }
    
    p->next_payload = payload->get_next_payload(payload);
    p->critical_rsv = RHP_PROTO_IKE_PLD_SET_CRITICAL;
    p->len = htons(len);
    p->dh_group = htons(payload->ext.ke->get_dhgrp(payload));
    p->reserved2 = 0;

    memcpy((p + 1),payload->ext.ke->key,payload->ext.ke->key_len);
    
    payload->ikemesg->tx_mesg_len += len;

    p->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
    if( payload->next ){
      p->next_payload = payload->next->get_payload_id(payload->next);
    }
    
    RHP_TRC(0,RHPTRCID_IKEV2_KE_PAYLOAD_SERIALIZE_RTRN,"xx",payload,pkt);
    rhp_pkt_trace_dump("_rhp_ikev2_ke_payload_serialize",pkt);
    return 0;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_KE_PAYLOAD_SERIALIZE_ERR,"xx",payload,pkt);
  return -EINVAL;
}

static int _rhp_ikev2_ke_payload_set_key(rhp_ikev2_payload* payload,u16 dhgrp,int key_len,u8* key)
{
  RHP_TRC(0,RHPTRCID_IKEV2_KE_PAYLOAD_SET_KEY,"xp",payload,key_len,key);

  if( payload->ext.ke->key ){
    RHP_BUG("");
    return -EEXIST;
  }

  payload->ext.ke->key = (u8*)_rhp_malloc(key_len);
  if( payload->ext.ke->key == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  memcpy(payload->ext.ke->key,key,key_len);
  payload->ext.ke->key_len = key_len;
  payload->ext.ke->dhgrp = dhgrp;

  return 0;
}

rhp_ikev2_ke_payload* _rhp_ikev2_alloc_ke_payload()
{
  rhp_ikev2_ke_payload* ke_payload;

  ke_payload = (rhp_ikev2_ke_payload*)_rhp_malloc(sizeof(rhp_ikev2_ke_payload));
  if( ke_payload == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(ke_payload,0,sizeof(rhp_ikev2_ke_payload));

  ke_payload->get_dhgrp = _rhp_ikev2_ke_payload_get_dhgrp;
  ke_payload->get_key_len = _rhp_ikev2_ke_payload_get_key_len;
  ke_payload->get_key = _rhp_ikev2_ke_payload_get_key;
  ke_payload->set_key = _rhp_ikev2_ke_payload_set_key;

  RHP_TRC(0,RHPTRCID_IKEV2_ALLOC_KE_PAYLOAD,"x",ke_payload);
  return ke_payload;
}

int rhp_ikev2_ke_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                          rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_ke_payload* ke_payload;
  rhp_proto_ike_ke_payload* ke_payloadh = (rhp_proto_ike_ke_payload*)payloadh;
  int keylen;
  u16 dhgrp;

  RHP_TRC(0,RHPTRCID_IKEV2_KE_PAYLOAD_NEW_RX,"xbxdxp",ikemesg,payload_id,payloadh,payload_len,payload,payload_len,payloadh);

  if( payload_len <= (int)sizeof(rhp_proto_ike_ke_payload) ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_KE_PAYLOAD_NEW_RX_INVALID_MESG_1,"xdd",ikemesg,payload_len,sizeof(rhp_proto_ike_ke_payload));
    goto error;
  }

  dhgrp = ntohs(ke_payloadh->dh_group);
  
  keylen = _rhp_proto_dh_keylen(dhgrp);
  if( keylen < 0 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_KE_PAYLOAD_NEW_RX_INVALID_MESG_2,"xd",ikemesg,keylen);
    goto error;
  }

  if( keylen != payload_len - (int)sizeof(rhp_proto_ike_ke_payload) ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_KE_PAYLOAD_NEW_RX_INVALID_MESG_3,"xddd",ikemesg,keylen,payload_len,sizeof(rhp_proto_ike_ke_payload));
    goto error;
  }
  
  ke_payload = _rhp_ikev2_alloc_ke_payload();
  if( ke_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.ke = ke_payload;
  payload->ext_destructor = _rhp_ikev2_ke_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_ke_payload_serialize;

  ke_payloadh = (rhp_proto_ike_ke_payload*)_rhp_pkt_pull(ikemesg->rx_pkt,payload_len);
  if( ke_payloadh == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_KE_PAYLOAD_NEW_RX_INVALID_MESG_r,"x",ikemesg);
    goto error;
  }
  
  RHP_TRC(0,RHPTRCID_IKEV2_KE_PAYLOAD_NEW_RX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_KE_PAYLOAD_NEW_RX_ERR,"xE",ikemesg,err);
  return err;
}

int rhp_ikev2_ke_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_ke_payload* ke_payload;

  RHP_TRC(0,RHPTRCID_IKEV2_KE_PAYLOAD_NEW_TX,"xLbx",ikemesg,"PROTO_IKE_PAYLOAD",payload_id,payload);

  ke_payload = _rhp_ikev2_alloc_ke_payload();
  if( ke_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.ke = ke_payload;
  payload->ext_destructor = _rhp_ikev2_ke_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_ke_payload_serialize;

  RHP_TRC(0,RHPTRCID_IKEV2_KE_PAYLOAD_NEW_TX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_KE_PAYLOAD_NEW_TX_ERR,"xE",ikemesg,err);
  return err;
}

