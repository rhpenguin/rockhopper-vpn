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


static int _rhp_ikev1_nat_oa_payload_get_orig_addr_family(rhp_ikev2_payload* payload)
{
  int addr_family;

  if( payload->ext.v1_nat_oa->addr_family == AF_INET ||
  		payload->ext.v1_nat_oa->addr_family == AF_INET6 ){

  	addr_family = payload->ext.v1_nat_oa->addr_family;

  }else{

    rhp_proto_ikev1_nat_oa_payload* nat_oa_payloadh
    	= (rhp_proto_ikev1_nat_oa_payload*)(payload->payloadh);

    if( nat_oa_payloadh->id_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR ){

    	addr_family = AF_INET;

    }else if( nat_oa_payloadh->id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR ){

    	addr_family = AF_INET6;

    }else{

    	RHP_BUG("%d",nat_oa_payloadh->id_type);
    	return -EINVAL;
    }
  }

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_OA_PAYLOAD_GET_ORIG_ADDR_FAMILY,"xLd",payload,"AF",addr_family);
  return addr_family;
}

static u8* _rhp_ikev1_nat_oa_payload_get_orig_addr(rhp_ikev2_payload* payload)
{
  u8* ret;
  int len;
  rhp_proto_ikev1_nat_oa_payload* nat_oa_payloadh;

  if( payload->ext.v1_nat_oa->addr_family == AF_INET ){
    ret = payload->ext.v1_nat_oa->addr;
    len = 4;
  }else if( payload->ext.v1_nat_oa->addr_family == AF_INET6 ){
    ret = payload->ext.v1_nat_oa->addr;
    len = 16;
  }else{
    nat_oa_payloadh = (rhp_proto_ikev1_nat_oa_payload*)(payload->payloadh);
    ret = (u8*)(nat_oa_payloadh + 1);
    len = payload->get_len_rx(payload);
    len -= sizeof(rhp_proto_ikev1_nat_oa_payload);
  }

  if( len == 4 ){
    RHP_TRC(0,RHPTRCID_IKEV1_NAT_OA_PAYLOAD_GET_ORIG_ADDR_V4,"x4",payload,*((u32*)ret));
  }else if( len == 16 ){
    RHP_TRC(0,RHPTRCID_IKEV1_NAT_OA_PAYLOAD_GET_ORIG_ADDR_V6,"x6",payload,ret);
  }else{
  	RHP_BUG("%d",len);
  }
  return ret;
}

static void _rhp_ikev1_nat_oa_payload_destructor(rhp_ikev2_payload* payload)
{
  RHP_TRC(0,RHPTRCID_IKEV1_NAT_OA_PAYLOAD_DESTRUCTOR,"xx",payload,payload->ext.v1_nat_oa);
  return;
}

static int _rhp_ikev1_nat_oa_payload_serialize(rhp_ikev2_payload* payload,rhp_packet* pkt)
{
  int len, addr_len;
  u8 id_type;
  rhp_proto_ikev1_nat_oa_payload* p;

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_OA_PAYLOAD_SERIALIZE,"xx",payload,pkt);

  len = sizeof(rhp_proto_ikev1_nat_oa_payload);
  if( payload->ext.v1_nat_oa->addr_family == AF_INET ){
  	addr_len = 4;
  	len += 4;
  	id_type = RHP_PROTO_IKEV1_ID_IPV4_ADDR;
  }else if( payload->ext.v1_nat_oa->addr_family == AF_INET6 ){
  	addr_len = 16;
  	len += 16;
  	id_type = RHP_PROTO_IKEV1_ID_IPV6_ADDR;
  }else{
  	RHP_BUG("%d",payload->ext.v1_nat_oa->addr_family);
  	return -EINVAL;
  }

  p = (rhp_proto_ikev1_nat_oa_payload*)rhp_pkt_expand_tail(pkt,len);
  if( p == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  p->next_payload = payload->get_next_payload(payload);
  p->reserved = 0;
  p->reserved1 = 0;
  p->reserved2 = 0;

  p->len = htons(len);

  p->id_type = id_type;
  memcpy((p + 1),payload->ext.v1_nat_oa->addr,addr_len);

  payload->ikemesg->tx_mesg_len += len;

  p->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
  if( payload->next ){
    p->next_payload = payload->next->get_payload_id(payload->next);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_OA_PAYLOAD_SERIALIZE_RTRN,"xx",payload,pkt);
  rhp_pkt_trace_dump("_rhp_ikev1_nat_oa_payload_serialize",pkt);
  return 0;

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_OA_PAYLOAD_SERIALIZE_ERR,"xx",payload,pkt);
  return -EINVAL;
}

static int _rhp_ikev1_nat_oa_payload_set_orig_addr(rhp_ikev2_payload* payload,int addr_family,u8* addr)
{
	int addr_len;

	if( addr_family == AF_INET ){
	  RHP_TRC(0,RHPTRCID_IKEV1_NAT_OA_PAYLOAD_SET_ORIG_ADDR_V4,"xLd4",payload,"AF",addr_family,*((u32*)addr));
	  addr_len = 4;
	}else if( addr_family == AF_INET6 ){
	  RHP_TRC(0,RHPTRCID_IKEV1_NAT_OA_PAYLOAD_SET_ORIG_ADDR_V6,"xLd6",payload,"AF",addr_family,addr);
	  addr_len = 16;
	}else{
		RHP_BUG("%d",addr_family);
		return -EINVAL;
	}

  payload->ext.v1_nat_oa->addr_family = addr_family;
  memcpy(payload->ext.v1_nat_oa->addr,addr,addr_len);

  return 0;
}

rhp_ikev1_nat_oa_payload* _rhp_ikev1_alloc_nat_oa_payload()
{
  rhp_ikev1_nat_oa_payload* nat_oa_payload;

  nat_oa_payload = (rhp_ikev1_nat_oa_payload*)_rhp_malloc(sizeof(rhp_ikev1_nat_oa_payload));
  if( nat_oa_payload == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(nat_oa_payload,0,sizeof(rhp_ikev1_nat_oa_payload));

  nat_oa_payload->get_orig_addr_family = _rhp_ikev1_nat_oa_payload_get_orig_addr_family;
  nat_oa_payload->get_orig_addr = _rhp_ikev1_nat_oa_payload_get_orig_addr;
  nat_oa_payload->set_orig_addr = _rhp_ikev1_nat_oa_payload_set_orig_addr;

  nat_oa_payload->addr_family = AF_UNSPEC;

  RHP_TRC(0,RHPTRCID_IKEV1_ALLOC_NAT_OA_PAYLOAD,"x",nat_oa_payload);
  return nat_oa_payload;
}

int rhp_ikev1_nat_oa_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                          rhp_proto_ikev1_nat_oa_payload* payloadh,int payload_len,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev1_nat_oa_payload* nat_oa_payload;
  rhp_proto_ikev1_nat_oa_payload* nat_oa_payloadh = (rhp_proto_ikev1_nat_oa_payload*)payloadh;

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_OA_PAYLOAD_NEW_RX,"xbxdxp",ikemesg,payload_id,payloadh,payload_len,payload,payload_len,payloadh);

  if( payload_len <= (int)sizeof(rhp_proto_ikev1_nat_oa_payload) ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV1_NAT_OA_PAYLOAD_NEW_RX_INVALID_MESG_1,"xdd",ikemesg,payload_len,sizeof(rhp_proto_ikev1_nat_oa_payload));
    goto error;
  }

  nat_oa_payload = _rhp_ikev1_alloc_nat_oa_payload();
  if( nat_oa_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.v1_nat_oa = nat_oa_payload;
  payload->ext_destructor = _rhp_ikev1_nat_oa_payload_destructor;
  payload->ext_serialize = _rhp_ikev1_nat_oa_payload_serialize;

  nat_oa_payloadh = (rhp_proto_ikev1_nat_oa_payload*)_rhp_pkt_pull(ikemesg->rx_pkt,payload_len);
  if( nat_oa_payloadh == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV1_NAT_OA_PAYLOAD_NEW_RX_INVALID_MESG_r,"x",ikemesg);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_OA_PAYLOAD_NEW_RX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_OA_PAYLOAD_NEW_RX_ERR,"xE",ikemesg,err);
  return err;
}

int rhp_ikev1_nat_oa_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev1_nat_oa_payload* nat_oa_payload;

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_OA_PAYLOAD_NEW_TX,"xLbx",ikemesg,"PROTO_IKE_PAYLOAD",payload_id,payload);

  nat_oa_payload = _rhp_ikev1_alloc_nat_oa_payload();
  if( nat_oa_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.v1_nat_oa = nat_oa_payload;
  payload->ext_destructor = _rhp_ikev1_nat_oa_payload_destructor;
  payload->ext_serialize = _rhp_ikev1_nat_oa_payload_serialize;

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_OA_PAYLOAD_NEW_TX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_NAT_OA_PAYLOAD_NEW_TX_ERR,"xE",ikemesg,err);
  return err;
}

