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

static u8 _rhp_ikev1_attr_payload_get_type(rhp_ikev2_payload* payload)
{
  u8 ret;
  rhp_proto_ikev1_attribute_payload* attr_payloadh
  	= (rhp_proto_ikev1_attribute_payload*)(payload->payloadh);

  if( attr_payloadh ){
    ret = attr_payloadh->type;
  }else{
    ret = payload->ext.v1_attr->type;
  }
  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_GET_TYPE,"xxb",payload,attr_payloadh,ret);
  return ret;
}

static void _rhp_ikev1_attr_payload_set_type(rhp_ikev2_payload* payload,u8 type)
{
  payload->ext.v1_attr->type = type;
  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_SET_TYPE,"xb",payload,type);
  return;
}


void _rhp_ikev1_attr_payload_set_attr_type(rhp_ikev1_attr_attr* attr_attr,u16 attr_type)
{
	attr_attr->attr_type = attr_type;
  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_SET_ATTR_TYPE,"xd",attr_attr,attr_type);
}

u16 _rhp_ikev1_attr_payload_get_attr_type(rhp_ikev1_attr_attr* attr_attr)
{
  u16 ret;

  if( attr_attr->attr_attrh ){

    ret = RHP_PROTO_IKE_ATTR_TYPE(attr_attr->attr_attrh->attr_type);

  }else{

  	ret = attr_attr->attr_type;
  }

  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_GET_ATTR_TYPE,"xxd",attr_attr,attr_attr->attr_attrh,ret);
  return ret;
}

int _rhp_ikev1_attr_payload_get_attr_len(rhp_ikev1_attr_attr* attr_attr)
{
  int ret;

  if( attr_attr->attr_attrh ){

  	if( RHP_PROTO_IKE_ATTR_AF(attr_attr->attr_attrh->attr_type) ){
  		ret = sizeof(u16);
  	}else{
  		ret = ntohs(attr_attr->attr_attrh->len_or_value);
  	}

  }else{

    ret = attr_attr->attr_len;
  }

  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_GET_ATTR_LEN,"xxd",attr_attr,attr_attr->attr_attrh,ret);
  return ret;
}

u8* _rhp_ikev1_attr_payload_get_attr(rhp_ikev1_attr_attr* attr_attr)
{
  u8* ret;
  int len;

  if( attr_attr->attr_attrh ){

  	if( RHP_PROTO_IKE_ATTR_AF(attr_attr->attr_attrh->attr_type) ){
  		ret = (u8*)(&(attr_attr->attr_attrh->len_or_value));
  	}else{
  		ret = (u8*)(attr_attr->attr_attrh + 1);
  	}

  }else{

  	ret = attr_attr->attr_val;
  }

  len = _rhp_ikev1_attr_payload_get_attr_len(attr_attr);

  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_GET_ATTR,"xxp",attr_attr,attr_attr->attr_attrh,len,ret);
  return ret;
}

int _rhp_ikev1_attr_payload_set_attr(rhp_ikev1_attr_attr* attr_attr,int attr_len,u8* attr_val)
{
	if( attr_val ){

		attr_attr->attr_val = (u8*)_rhp_malloc(attr_len);
		if( attr_attr->attr_val == NULL ){
			RHP_BUG("");
			return -ENOMEM;
		}

		memcpy(attr_attr->attr_val,attr_val,attr_len);
		attr_attr->attr_len = attr_len;
	}

  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_SET_ATTR,"xp",attr_attr,attr_len,attr_val);
	return 0;
}


static rhp_ikev1_attr_attr* _rhp_ikev1_attr_payload_alloc_attr(u16 attr_type)
{
	rhp_ikev1_attr_attr* attr_attr;

	attr_attr = (rhp_ikev1_attr_attr*)_rhp_malloc(sizeof(rhp_ikev1_attr_attr));
	if( attr_attr == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(attr_attr,0,sizeof(rhp_ikev1_attr_attr));

	attr_attr->attr_type = attr_type;

	attr_attr->set_attr_type = _rhp_ikev1_attr_payload_set_attr_type;
	attr_attr->get_attr_type = _rhp_ikev1_attr_payload_get_attr_type;
	attr_attr->get_attr_len = _rhp_ikev1_attr_payload_get_attr_len;
	attr_attr->get_attr = _rhp_ikev1_attr_payload_get_attr;
	attr_attr->set_attr = _rhp_ikev1_attr_payload_set_attr;

  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_ALLOC_ATTR,"Ldx","IKEV1_ATTR_ATTR_TYPE",attr_type,attr_attr);
	return attr_attr;
}

static void _rhp_ikev1_attr_payload_put_attr(rhp_ikev2_payload* payload,rhp_ikev1_attr_attr* attr_attr)
{
	int attr_type = attr_attr->get_attr_type(attr_attr);
	int attr_len = attr_attr->get_attr_len(attr_attr);
	u8* attr_val = attr_attr->get_attr(attr_attr);

  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_PUT_ATTR,"xxLdp",payload,attr_attr,"IKEV1_ATTR_ATTR_TYPE",attr_type,attr_len,attr_val);

	switch( attr_type ){

	case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_ADDRESS:

		payload->ext.v1_attr->attr_attr_ext.internal_addr_v4.addr_family = AF_INET;

		if( attr_val ){
			payload->ext.v1_attr->attr_attr_ext.internal_addr_v4.addr.v4 = *((u32*)(attr_val));
		}

		rhp_ip_addr_dump("_rhp_ikev1_attr_payload_put_attr: ipv4",&(payload->ext.v1_attr->attr_attr_ext.internal_addr_v4));
		break;

	case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_NETMASK:

		payload->ext.v1_attr->attr_attr_ext.internal_addr_v4.addr_family = AF_INET;

		if( attr_val ){
			payload->ext.v1_attr->attr_attr_ext.internal_addr_v4.netmask.v4 = *((u32*)(attr_val));
			payload->ext.v1_attr->attr_attr_ext.internal_addr_v4.prefixlen = rhp_ipv4_netmask_to_prefixlen(*((u32*)(attr_val)));
		}

		rhp_ip_addr_dump("_rhp_ikev1_attr_payload_put_attr: ipv4_netmask",&(payload->ext.v1_attr->attr_attr_ext.internal_addr_v4));
		break;

	case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_ADDRESS:

		payload->ext.v1_attr->attr_attr_ext.internal_addr_v6.addr_family = AF_INET6;

		if( attr_val ){
			memcpy(payload->ext.v1_attr->attr_attr_ext.internal_addr_v6.addr.v6,attr_val,16);
		}

		rhp_ip_addr_dump("_rhp_ikev1_attr_payload_put_attr: ipv6",&(payload->ext.v1_attr->attr_attr_ext.internal_addr_v6));
		break;


	case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_NETMASK:

		payload->ext.v1_attr->attr_attr_ext.internal_addr_v6.addr_family = AF_INET6;

		if( attr_val ){
			memcpy(payload->ext.v1_attr->attr_attr_ext.internal_addr_v6.netmask.v6,attr_val,16);
			payload->ext.v1_attr->attr_attr_ext.internal_addr_v6.prefixlen
				= rhp_ipv6_netmask_to_prefixlen(attr_val);
		}

		rhp_ip_addr_dump("_rhp_ikev1_attr_payload_put_attr: ipv6_netmask",&(payload->ext.v1_attr->attr_attr_ext.internal_addr_v6));
		break;

	default:
		break;
	}

  if( payload->ext.v1_attr->attr_attr_head == NULL ){
    payload->ext.v1_attr->attr_attr_head = attr_attr;
  }else{
    payload->ext.v1_attr->attr_attr_tail->next = attr_attr;
  }
  payload->ext.v1_attr->attr_attr_tail = attr_attr;
  payload->ext.v1_attr->attr_num++;

  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_PUT_ATTR_RTRN,"xx",payload,attr_attr);
  return;
}

static int _rhp_ikev1_attr_payload_put_attr_rx(rhp_ikev2_payload* payload,rhp_proto_ikev1_attr* attr_attrh)
{
	rhp_ikev1_attr_attr* attr_attr;
	int attr_len;
	u8* attr_val;

  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_PUT_ATTR_RX,"xxxpx",payload,attr_attrh,attr_attrh->attr_type,sizeof(rhp_proto_ikev1_attr),attr_attrh,RHP_PROTO_IKE_ATTR_TYPE(attr_attrh->attr_type));

	attr_attr = _rhp_ikev1_attr_payload_alloc_attr(RHP_PROTO_IKE_ATTR_TYPE(attr_attrh->attr_type));
	if( attr_attr == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	attr_attr->attr_attrh = attr_attrh;

	_rhp_ikev1_attr_payload_put_attr(payload,attr_attr);

	attr_len = attr_attr->get_attr_len(attr_attr);
	attr_val = attr_attr->get_attr(attr_attr);

	RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_PUT_ATTR_RX_RTRN,"xxpp",payload,attr_attr,(int)sizeof(rhp_proto_ikev1_attr) + attr_len,attr_attr->attr_attrh,attr_len,attr_val);
	return 0;
}

static int _rhp_ikev1_attr_payload_enum_attr(rhp_ikev2_payload* payload,
      int (*callback)(rhp_ikev2_payload* payload,rhp_ikev1_attr_attr* attr_attr,void* ctx),void* ctx)
{
	int err = -EINVAL;
	rhp_ikev1_attr_attr* attr_attr = payload->ext.v1_attr->attr_attr_head;

  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_ENUM_ATTR,"xYx",payload,callback,ctx);

  if( attr_attr == NULL ){
    RHP_BUG("");
    return -ENOENT;
  }

	while( attr_attr ){

		err = callback(payload,attr_attr,ctx);
		if( err ){
		  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_ENUM_ATTR_ERR,"E",err);
			return err;
		}

		attr_attr = attr_attr->next;
	}

  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_ENUM_ATTR_RTRN,"");
	return 0;
}

static int _rhp_ikev1_attr_payload_alloc_and_put_attr(rhp_ikev2_payload* payload,
		u16 attr_type,int attr_len,u8* attr_val)
{
	int err = -EINVAL;
	rhp_ikev1_attr_attr* attr_attr;

  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_ALLOC_AND_PUT_ATTR,"xLwp",payload,"IKEV1_ATTR_ATTR_TYPE",attr_type,attr_len,attr_val);

	attr_attr = _rhp_ikev1_attr_payload_alloc_attr(attr_type);
	if( attr_attr == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	if( attr_val ){

		err = attr_attr->set_attr(attr_attr,attr_len,attr_val);
		if( err ){
			RHP_BUG("%d",err);
			_rhp_free(attr_attr);
			return err;
		}

	}else{
	  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_ALLOC_AND_PUT_ATTR_NO_VAL,"x",payload);
	}

	_rhp_ikev1_attr_payload_put_attr(payload,attr_attr);

  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_ALLOC_AND_PUT_ATTR_RTRN,"x",payload);
	return 0;
}

static rhp_ip_addr* _rhp_ikev1_attr_payload_get_attr_internal_addr_v4(rhp_ikev2_payload* payload)
{
	rhp_ip_addr* ret = &(payload->ext.v1_attr->attr_attr_ext.internal_addr_v4);

	RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_GET_ATTR_INTERNAL_ADDR_V4,"x",payload);

	if( ret->addr_family == AF_INET ){

		rhp_ip_addr_dump("attr_get_attr_internal_addr_v4",ret);
		RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_GET_ATTR_INTERNAL_ADDR_V4_RTRN,"xx",payload,ret);
		return ret;
	}

	RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_GET_ATTR_INTERNAL_ADDR_V4_ERR,"x",payload);
	return NULL;
}

static rhp_ip_addr* _rhp_ikev1_attr_payload_get_attr_internal_addr_v6(rhp_ikev2_payload* payload)
{
	rhp_ip_addr* ret = &(payload->ext.v1_attr->attr_attr_ext.internal_addr_v6);

	RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_GET_ATTR_INTERNAL_ADDR_V6,"x",payload);

	if( ret->addr_family == AF_INET6 ){

		rhp_ip_addr_dump("attr_get_attr_internal_addr_v6",ret);
		RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_GET_ATTR_INTERNAL_ADDR_V6_RTRN,"xx",payload,ret);
		return ret;
	}

	RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_GET_ATTR_INTERNAL_ADDR_V6_ERR,"x",payload);
	return NULL;
}

rhp_ikev1_attr_payload* _rhp_ikev2_alloc_attr_payload()
{
  rhp_ikev1_attr_payload* attr_payload;

  attr_payload = (rhp_ikev1_attr_payload*)_rhp_malloc(sizeof(rhp_ikev1_attr_payload));
  if( attr_payload == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(attr_payload,0,sizeof(rhp_ikev1_attr_payload));

  attr_payload->get_type = _rhp_ikev1_attr_payload_get_type;
  attr_payload->set_type = _rhp_ikev1_attr_payload_set_type;
  attr_payload->put_attr_rx = _rhp_ikev1_attr_payload_put_attr_rx;
  attr_payload->enum_attr = _rhp_ikev1_attr_payload_enum_attr;
  attr_payload->alloc_and_put_attr = _rhp_ikev1_attr_payload_alloc_and_put_attr;
  attr_payload->get_attr_internal_addr_v4 = _rhp_ikev1_attr_payload_get_attr_internal_addr_v4;
  attr_payload->get_attr_internal_addr_v6 = _rhp_ikev1_attr_payload_get_attr_internal_addr_v6;

  RHP_TRC(0,RHPTRCID_IKEV2_ALLOC_ATTR_PAYLOAD,"x",attr_payload);
  return attr_payload;
}


static void _rhp_ikev1_attr_payload_destructor(rhp_ikev2_payload* payload)
{
  rhp_ikev1_attr_attr *attr_attr,*attr_attr_n;

  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_DESTRUCTOR,"xx",payload,payload->ext.v1_attr);

  attr_attr = payload->ext.v1_attr->attr_attr_head;
  while( attr_attr ){

  	attr_attr_n = attr_attr->next;

  	if( attr_attr->attr_val ){
  		_rhp_free(attr_attr->attr_val);
  	}
  	_rhp_free(attr_attr);

  	attr_attr = attr_attr_n;
  }

  payload->ext.v1_attr->attr_attr_head = NULL;

	return;
}

static int _rhp_ikev1_attr_payload_serialize(rhp_ikev2_payload* payload,rhp_packet* pkt)
{
  int err = -EINVAL;
  rhp_ikev1_attr_attr* attr_attr = payload->ext.v1_attr->attr_attr_head;
  int len = sizeof(rhp_proto_ikev1_attribute_payload);
  rhp_proto_ikev1_attribute_payload* pldh;
  rhp_proto_ikev1_attr* attr_attrh;
  int attr_attr_offset = 0;

  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_SERIALIZE,"xx",payload,pkt);

  pldh = (rhp_proto_ikev1_attribute_payload*)rhp_pkt_expand_tail(pkt,len);
  if( pldh == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }
  attr_attr_offset = ((u8*)pldh) - pkt->head;

  pldh->next_payload = payload->get_next_payload(payload);
  pldh->id = 0;
  pldh->type = payload->ext.v1_attr->get_type(payload);
  pldh->reserved = 0;
  pldh->reserved1 = 0;

  while( attr_attr ){

      int af_flag = 0;
      int attr_attr_len = sizeof(rhp_proto_ikev1_attr);
      u16 attr_attr_type = attr_attr->get_attr_type(attr_attr);
      int attr_attr_val_len = attr_attr->get_attr_len(attr_attr);
    	u8* attr_attr_val = attr_attr->get_attr(attr_attr);

      switch( attr_attr_type ){

      case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_ADDRESS:
      case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_NETMASK:
      case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_DNS:
      case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_NBNS:
      case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_ADDRESS_EXPIRY:
      case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_DHCP:
      case RHP_PROTO_IKEV1_CFG_ATTR_APPLICATION_VERSION:
      case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_ADDRESS:
      case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_NETMASK:
      case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_DNS:
      case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_NBNS:
      case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_DHCP:
      case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_SUBNET:
      case RHP_PROTO_IKEV1_CFG_ATTR_SUPPORTED_ATTRIBUTES:
      case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_SUBNET:
      case RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_USER_NAME:
      case RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_USER_PASSWORD:
      case RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_PASSCODE:
      case RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_MESSAGE:
      case RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_CHALLENGE:
      case RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_DOMAIN:
      case RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_NEXT_PIN:
      case RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_ANSWER:
      case RHP_PROTO_IKE_CFG_ATTR_RHP_DNS_SFX:
      case RHP_PROTO_IKE_CFG_ATTR_RHP_IPV4_GATEWAY:
      case RHP_PROTO_IKE_CFG_ATTR_RHP_IPV6_GATEWAY:

        attr_attr_len += attr_attr_val_len;
      	break;

      case RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_TYPE:
      case RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_STATUS:

      	af_flag = 1;
      	break;

      default:

      	RHP_BUG("%d",attr_attr_type);
        attr_attr_len += attr_attr_val_len;
      	break;
      }

      attr_attrh = (rhp_proto_ikev1_attr*)rhp_pkt_expand_tail(pkt,attr_attr_len);
      if( attr_attrh == NULL ){
        err = -ENOMEM;
        RHP_BUG("");
        goto error;
      }

      if( af_flag ){

      	attr_attrh->attr_type = RHP_PROTO_IKE_ATTR_SET_AF(htons(attr_attr_type));

      	if( attr_attr_val ){
      		attr_attrh->len_or_value = *((u16*)attr_attr_val);
      	}else{
      		attr_attrh->len_or_value = 0;
      	}

      }else{

      	attr_attrh->attr_type = htons(attr_attr_type);
      	attr_attrh->len_or_value = htons(attr_attr_val_len);

      	if( attr_attr_val ){
      		memcpy((u8*)(attr_attrh + 1),attr_attr_val,attr_attr_val_len);
      	}
      }

      len += attr_attr_len;

      attr_attr = attr_attr->next;
  }

  pldh = (rhp_proto_ikev1_attribute_payload*)(pkt->head + attr_attr_offset);

  pldh->len = htons(len);
  payload->ikemesg->tx_mesg_len += len;

  pldh->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
  if( payload->next ){
    pldh->next_payload = payload->next->get_payload_id(payload->next);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_SERIALIZE_RTRN,"xx",payload,pkt);
  rhp_pkt_trace_dump("_rhp_ikev1_attr_payload_serialize",pkt);
  return 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_SERIALIZE_ERR,"xxE",payload,pkt,err);
  return err;
}

int rhp_ikev1_attr_payload_parse(
		rhp_proto_ikev1_attribute_payload* attr_payloadh,int payload_len,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev1_attr_payload* attr_payload;
  u8 *p,*end;
  int rem;

  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_PARSE,"xdxp",attr_payloadh,payload_len,payload,payload_len,attr_payloadh);

  if( payload_len < (int)sizeof(rhp_proto_ikev1_attribute_payload) ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_PARSE_INVALID_MESG_1,"xdd",attr_payloadh,payload_len,sizeof(rhp_proto_ikev1_attribute_payload));
    goto error;
  }

  if( payload->ext.v1_attr ){

  	attr_payload = payload->ext.v1_attr;

  }else{

  	attr_payload = _rhp_ikev2_alloc_attr_payload();
		if( attr_payload == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}

		payload->ext.v1_attr = attr_payload;
		payload->ext_destructor = _rhp_ikev1_attr_payload_destructor;
		payload->ext_serialize = _rhp_ikev1_attr_payload_serialize;
  }

  switch( attr_payloadh->type ){
  case RHP_PROTO_IKEV1_CFG_REQUEST:
  case RHP_PROTO_IKEV1_CFG_REPLY:
  case RHP_PROTO_IKEV1_CFG_SET:
  case RHP_PROTO_IKEV1_CFG_ACK:
  	break;
  default:
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_PARSE_INVALID_MESG_UNSUP_TYPE,"xd",attr_payloadh,attr_payloadh->type);
    goto error;
  }


  p = (u8*)(attr_payloadh + 1);
  end = ((u8*)attr_payloadh) + payload_len;
  rem = end - p;

  while( rem > 0 ){

  	int attr_attr_len = 0;
  	rhp_proto_ikev1_attr* attr_attrh;

  	if( p >= end ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_PARSE_INVALID_ATTR_LEN_ERR,"xE",attr_payloadh,err);
			goto error;
  	}

  	attr_attrh = (rhp_proto_ikev1_attr*)p;

  	if( !RHP_PROTO_IKE_ATTR_AF(attr_attrh->attr_type) ){
  		attr_attr_len += ntohs(attr_attrh->len_or_value);
  	}

  	if( ((u8*)attr_attrh) + (int)sizeof(rhp_proto_ikev1_attr) + attr_attr_len > end ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_PARSE_INVALID_ATTR_LEN_ERR_2,"xE",attr_payloadh,err);
			goto error;
  	}

  	err = attr_payload->put_attr_rx(payload,attr_attrh);
  	if( err ){
			RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_PARSE_PUT_CP_ATTR_ERR,"xE",attr_payloadh,err);
  		goto error;
    }

  	RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_PARSE_ATTR_VAL,"xxp",attr_payloadh,attr_attrh,(int)sizeof(rhp_proto_ikev1_attr) + attr_attr_len,attr_attrh);

  	p = ((u8*)attr_attrh) + (int)sizeof(rhp_proto_ikev1_attr) + attr_attr_len;
  	rem -= (int)sizeof(rhp_proto_ikev1_attr) + attr_attr_len;
  }


  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_PARSE_RTRN,"x",attr_payloadh);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_PARSE_ERR,"xE",attr_payloadh,err);
  return err;
}

int rhp_ikev1_attr_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                 rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_proto_ikev1_attribute_payload* attr_payloadh;

  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_NEW_RX,"xbxdxp",ikemesg,payload_id,payloadh,payload_len,payload,payload_len,payloadh);


  attr_payloadh = (rhp_proto_ikev1_attribute_payload*)_rhp_pkt_pull(ikemesg->rx_pkt,payload_len);
  if( attr_payloadh == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_NEW_RX_INVALID_MESG_2,"x",ikemesg);
    goto error;
  }

  err = rhp_ikev1_attr_payload_parse(attr_payloadh,payload_len,payload);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_NEW_RX_INVALID_MESG_2,"x",ikemesg);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_NEW_RX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_NEW_RX_ERR,"xE",ikemesg,err);
  return err;
}

int rhp_ikev1_attr_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev1_attr_payload* attr_payload;

  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_NEW_TX,"xLbx",ikemesg,"PROTO_IKE_PAYLOAD",payload_id,payload);

  attr_payload = _rhp_ikev2_alloc_attr_payload();
  if( attr_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.v1_attr = attr_payload;
  payload->ext_destructor = _rhp_ikev1_attr_payload_destructor;
  payload->ext_serialize = _rhp_ikev1_attr_payload_serialize;

  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_NEW_TX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_ATTR_PAYLOAD_NEW_TX_ERR,"xE",ikemesg,err);
  return err;
}

