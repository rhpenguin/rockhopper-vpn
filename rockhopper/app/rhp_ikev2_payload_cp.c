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

static u8 _rhp_ikev2_cp_payload_get_cfg_type(rhp_ikev2_payload* payload)
{
  u8 ret;
  rhp_proto_ike_cp_payload* cp_payloadh = (rhp_proto_ike_cp_payload*)(payload->payloadh);

  if( cp_payloadh ){
    ret = cp_payloadh->cfg_type;
  }else{
    ret = payload->ext.cp->cfg_type;
  }
  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_GET_TYPE,"xxb",payload,cp_payloadh,ret);
  return ret;
}

static void _rhp_ikev2_cp_payload_set_cfg_type(rhp_ikev2_payload* payload,u8 cfg_type)
{
  payload->ext.cp->cfg_type = cfg_type;
  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_SET_TYPE,"xb",payload,cfg_type);
  return;
}


void _rhp_ikev2_cp_payload_set_attr_type(rhp_ikev2_cp_attr* cp_attr,u16 attr_type)
{
	cp_attr->attr_type = attr_type;
  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_SET_ATTR_TYPE,"xw",cp_attr,attr_type);
}

u16 _rhp_ikev2_cp_payload_get_attr_type(rhp_ikev2_cp_attr* cp_attr)
{
  u16 ret;

  if( cp_attr->cp_attrh ){
    ret = ntohs(RHP_PROTO_IKE_CFG_ATTR_TYPE(cp_attr->cp_attrh->cfg_attr_type_rsv));
  }else{
    ret = cp_attr->attr_type;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_GET_ATTR_TYPE,"xw",cp_attr,ret);
  return ret;
}

int _rhp_ikev2_cp_payload_get_attr_len(rhp_ikev2_cp_attr* cp_attr)
{
  int ret;

  if( cp_attr->cp_attrh ){
    ret = ntohs(cp_attr->cp_attrh->len);
  }else{
    ret = cp_attr->attr_len;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_GET_ATTR_LEN,"xd",cp_attr,ret);
  return ret;
}

u8* _rhp_ikev2_cp_payload_get_attr(rhp_ikev2_cp_attr* cp_attr)
{
  u8* ret;
  int len;

  if( cp_attr->cp_attrh ){
    ret = (u8*)(cp_attr->cp_attrh + 1);
  }else{
    ret = cp_attr->attr_val;
  }

  len = _rhp_ikev2_cp_payload_get_attr_len(cp_attr);

  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_GET_ATTR,"xp",cp_attr,len,ret);
  return ret;
}

int _rhp_ikev2_cp_payload_set_attr(rhp_ikev2_cp_attr* cp_attr,int attr_len,u8* attr_val)
{
	if( attr_val ){

		cp_attr->attr_val = (u8*)_rhp_malloc(attr_len);
		if( cp_attr->attr_val == NULL ){
			RHP_BUG("");
			return -ENOMEM;
		}

		memcpy(cp_attr->attr_val,attr_val,attr_len);
		cp_attr->attr_len = attr_len;
	}

  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_SET_ATTR,"xp",cp_attr,attr_len,attr_val);
	return 0;
}


static rhp_ikev2_cp_attr* _rhp_ikev2_cp_payload_alloc_attr(u16 attr_type)
{
	rhp_ikev2_cp_attr* cp_attr;

	cp_attr = (rhp_ikev2_cp_attr*)_rhp_malloc(sizeof(rhp_ikev2_cp_attr));
	if( cp_attr == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(cp_attr,0,sizeof(rhp_ikev2_cp_attr));

	cp_attr->attr_type = attr_type;

	cp_attr->set_attr_type = _rhp_ikev2_cp_payload_set_attr_type;
	cp_attr->get_attr_type = _rhp_ikev2_cp_payload_get_attr_type;
	cp_attr->get_attr_len = _rhp_ikev2_cp_payload_get_attr_len;
	cp_attr->get_attr = _rhp_ikev2_cp_payload_get_attr;
	cp_attr->set_attr = _rhp_ikev2_cp_payload_set_attr;

  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_ALLOC_ATTR,"Lwx","IKEV2_CFG_ATTR_TYPE",attr_type,cp_attr);
	return cp_attr;
}

static void _rhp_ikev2_cp_payload_put_cp_attr(rhp_ikev2_payload* payload,rhp_ikev2_cp_attr* cp_attr)
{
  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_PUT_ATTR,"xxLwp",payload,cp_attr,"IKEV2_CFG_ATTR_TYPE",cp_attr->attr_type,cp_attr->attr_len,cp_attr->attr_val);

	switch( cp_attr->attr_type ){

	case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_ADDRESS:

		payload->ext.cp->cp_attr_ext.internal_addr_v4.addr_family = AF_INET;

		if( cp_attr->attr_val ){
			payload->ext.cp->cp_attr_ext.internal_addr_v4.addr.v4 = *((u32*)(cp_attr->attr_val));
		}

		rhp_ip_addr_dump("_rhp_ikev2_cp_payload_put_cp_attr: ipv4",&(payload->ext.cp->cp_attr_ext.internal_addr_v4));
		break;

	case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_NETMASK:

		payload->ext.cp->cp_attr_ext.internal_addr_v4.addr_family = AF_INET;

		if( cp_attr->attr_val ){
			payload->ext.cp->cp_attr_ext.internal_addr_v4.netmask.v4 = *((u32*)(cp_attr->attr_val));
			payload->ext.cp->cp_attr_ext.internal_addr_v4.prefixlen = rhp_ipv4_netmask_to_prefixlen(*((u32*)(cp_attr->attr_val)));
		}

		rhp_ip_addr_dump("_rhp_ikev2_cp_payload_put_cp_attr: ipv4_netmask",&(payload->ext.cp->cp_attr_ext.internal_addr_v4));
		break;

	case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_ADDRESS:

		payload->ext.cp->cp_attr_ext.internal_addr_v6.addr_family = AF_INET6;

		if( cp_attr->attr_val ){
			memcpy(payload->ext.cp->cp_attr_ext.internal_addr_v6.addr.v6,cp_attr->attr_val,16);
			payload->ext.cp->cp_attr_ext.internal_addr_v6.prefixlen = cp_attr->attr_val[16];
		}

		rhp_ip_addr_dump("_rhp_ikev2_cp_payload_put_cp_attr: ipv6",&(payload->ext.cp->cp_attr_ext.internal_addr_v6));
		break;

	default:
		break;
	}

  if( payload->ext.cp->cp_attr_head == NULL ){
    payload->ext.cp->cp_attr_head = cp_attr;
  }else{
    payload->ext.cp->cp_attr_tail->next = cp_attr;
  }
  payload->ext.cp->cp_attr_tail = cp_attr;
  payload->ext.cp->attr_num++;

  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_PUT_ATTR_RTRN,"xx",payload,cp_attr);
  return;
}

static int _rhp_ikev2_cp_payload_put_attr_rx(rhp_ikev2_payload* payload,rhp_proto_ike_cfg_attr* cp_attrh)
{
	rhp_ikev2_cp_attr* cp_attr;

  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_PUT_ATTR_RX,"xx",payload,cp_attrh);

	cp_attr = _rhp_ikev2_cp_payload_alloc_attr(RHP_PROTO_IKE_CFG_ATTR_TYPE(cp_attrh->cfg_attr_type_rsv));
	if( cp_attr == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	cp_attr->cp_attrh = cp_attrh;

	_rhp_ikev2_cp_payload_put_cp_attr(payload,cp_attr);

	RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_PUT_ATTR_RX_RTRN,"xx",payload,cp_attrh);
	return 0;
}

static int _rhp_ikev2_cp_payload_enum_attr(rhp_ikev2_payload* payload,
      int (*callback)(rhp_ikev2_payload* payload,rhp_ikev2_cp_attr* cp_attr,void* ctx),void* ctx)
{
	int err = -EINVAL;
	rhp_ikev2_cp_attr* cp_attr = payload->ext.cp->cp_attr_head;

  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_ENUM_ATTR,"xYx",payload,callback,ctx);

  if( cp_attr == NULL ){
    RHP_BUG("");
    return -ENOENT;
  }

	while( cp_attr ){

		err = callback(payload,cp_attr,ctx);
		if( err ){
		  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_ENUM_ATTR_ERR,"E",err);
			return err;
		}

		cp_attr = cp_attr->next;
	}

  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_ENUM_ATTR_RTRN,"");
	return 0;
}

static int _rhp_ikev2_cp_payload_alloc_and_put_attr(rhp_ikev2_payload* payload,u16 attr_type,int attr_len,u8* attr_val)
{
	int err = -EINVAL;
	rhp_ikev2_cp_attr* cp_attr;

  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_ALLOC_AND_PUT_ATTR,"xLwp",payload,"IKEV2_CFG_ATTR_TYPE",attr_type,attr_len,attr_val);

	cp_attr = _rhp_ikev2_cp_payload_alloc_attr(attr_type);
	if( cp_attr == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	if( attr_val ){

		err = cp_attr->set_attr(cp_attr,attr_len,attr_val);
		if( err ){
			RHP_BUG("%d",err);
			_rhp_free(cp_attr);
			return err;
		}

	}else{
	  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_ALLOC_AND_PUT_ATTR_NO_VAL,"x",payload);
	}

	_rhp_ikev2_cp_payload_put_cp_attr(payload,cp_attr);

  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_ALLOC_AND_PUT_ATTR_RTRN,"x",payload);
	return 0;
}

static rhp_ip_addr* _rhp_ikev2_cp_payload_get_attr_internal_addr_v4(rhp_ikev2_payload* payload)
{
	rhp_ip_addr* ret = &(payload->ext.cp->cp_attr_ext.internal_addr_v4);

	RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_GET_ATTR_INTERNAL_ADDR_V4,"x",payload);

	if( ret->addr_family == AF_INET ){

		rhp_ip_addr_dump("cp_get_attr_internal_addr_v4",ret);
		RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_GET_ATTR_INTERNAL_ADDR_V4_RTRN,"xx",payload,ret);
		return ret;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_GET_ATTR_INTERNAL_ADDR_V4_ERR,"x",payload);
	return NULL;
}

static rhp_ip_addr* _rhp_ikev2_cp_payload_get_attr_internal_addr_v6(rhp_ikev2_payload* payload)
{
	rhp_ip_addr* ret = &(payload->ext.cp->cp_attr_ext.internal_addr_v6);

	RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_GET_ATTR_INTERNAL_ADDR_V6,"x",payload);

	if( ret->addr_family == AF_INET6 ){

		rhp_ip_addr_dump("cp_get_attr_internal_addr_v6",ret);
		RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_GET_ATTR_INTERNAL_ADDR_V6_RTRN,"xx",payload,ret);
		return ret;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_GET_ATTR_INTERNAL_ADDR_V6_ERR,"x",payload);
	return NULL;
}

rhp_ikev2_cp_payload* _rhp_ikev2_alloc_cp_payload()
{
  rhp_ikev2_cp_payload* cp_payload;

  cp_payload = (rhp_ikev2_cp_payload*)_rhp_malloc(sizeof(rhp_ikev2_cp_payload));
  if( cp_payload == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(cp_payload,0,sizeof(rhp_ikev2_cp_payload));

  cp_payload->get_cfg_type = _rhp_ikev2_cp_payload_get_cfg_type;
  cp_payload->set_cfg_type = _rhp_ikev2_cp_payload_set_cfg_type;
  cp_payload->put_attr_rx = _rhp_ikev2_cp_payload_put_attr_rx;
  cp_payload->enum_attr = _rhp_ikev2_cp_payload_enum_attr;
  cp_payload->alloc_and_put_attr = _rhp_ikev2_cp_payload_alloc_and_put_attr;
  cp_payload->get_attr_internal_addr_v4 = _rhp_ikev2_cp_payload_get_attr_internal_addr_v4;
  cp_payload->get_attr_internal_addr_v6 = _rhp_ikev2_cp_payload_get_attr_internal_addr_v6;

  RHP_TRC(0,RHPTRCID_IKEV2_ALLOC_CP_PAYLOAD,"x",cp_payload);
  return cp_payload;
}


static void _rhp_ikev2_cp_payload_destructor(rhp_ikev2_payload* payload)
{
  rhp_ikev2_cp_attr *cp_attr,*cp_attr_n;

  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_DESTRUCTOR,"xx",payload,payload->ext.cp);

  cp_attr = payload->ext.cp->cp_attr_head;
  while( cp_attr ){

  	cp_attr_n = cp_attr->next;

  	if( cp_attr->attr_val ){
  		_rhp_free(cp_attr->attr_val);
  	}
  	_rhp_free(cp_attr);

  	cp_attr = cp_attr_n;
  }

  payload->ext.cp->cp_attr_head = NULL;

	return;
}

static int _rhp_ikev2_cp_payload_serialize(rhp_ikev2_payload* payload,rhp_packet* pkt)
{
  int err = -EINVAL;
  rhp_ikev2_cp_attr* cp_attr = payload->ext.cp->cp_attr_head;

  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_SERIALIZE,"xx",payload,pkt);

  if( cp_attr ){

    int len = sizeof(rhp_proto_ike_cp_payload);
    rhp_proto_ike_cp_payload* pldh;
    rhp_proto_ike_cfg_attr* cp_attrh;
    int cp_attr_offset = 0;

    pldh = (rhp_proto_ike_cp_payload*)rhp_pkt_expand_tail(pkt,len);
    if( pldh == NULL ){
      RHP_BUG("");
      return -ENOMEM;
    }
    cp_attr_offset = ((u8*)pldh) - pkt->head;

    pldh->next_payload = payload->get_next_payload(payload);
    pldh->critical_rsv = RHP_PROTO_IKE_PLD_SET_CRITICAL;

    pldh->cfg_type = payload->ext.cp->cfg_type;

    while( cp_attr ){

      int cp_attr_len;

      cp_attr_len = sizeof(rhp_proto_ike_cfg_attr) + cp_attr->attr_len;

      cp_attrh = (rhp_proto_ike_cfg_attr*)rhp_pkt_expand_tail(pkt,cp_attr_len);
      if( cp_attrh == NULL ){
        err = -ENOMEM;
        RHP_BUG("");
        goto error;
      }

      cp_attrh->cfg_attr_type_rsv = htons(cp_attr->attr_type);
      cp_attrh->len = htons(cp_attr_len - sizeof(rhp_proto_ike_cfg_attr));

      if( cp_attr->attr_val ){
      	memcpy((cp_attrh + 1),cp_attr->attr_val,cp_attr->attr_len);
      }

      len += cp_attr_len;

      cp_attr = cp_attr->next;
    }

    pldh = (rhp_proto_ike_cp_payload*)(pkt->head + cp_attr_offset);

    pldh->len = htons(len);
    payload->ikemesg->tx_mesg_len += len;

    pldh->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
    if( payload->next ){
      pldh->next_payload = payload->next->get_payload_id(payload->next);
    }

    RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_SERIALIZE_RTRN,"xx",payload,pkt);
    rhp_pkt_trace_dump("_rhp_ikev2_cp_payload_serialize",pkt);
    return 0;
  }

error:
  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_SERIALIZE_ERR,"xxE",payload,pkt,err);
  return err;
}

int rhp_ikev2_cp_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                 rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_cp_payload* cp_payload;
  rhp_proto_ike_cp_payload* cp_payloadh = (rhp_proto_ike_cp_payload*)payloadh;
  u8 *p,*end;
  int rem;

  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_NEW_RX,"xbxdxp",ikemesg,payload_id,payloadh,payload_len,payload,payload_len,payloadh);

  if( payload_len < (int)sizeof(rhp_proto_ike_cp_payload) ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_NEW_RX_INVALID_MESG_1,"xdd",ikemesg,payload_len,sizeof(rhp_proto_ike_cp_payload));
    goto error;
  }

  cp_payload = _rhp_ikev2_alloc_cp_payload();
  if( cp_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.cp = cp_payload;
  payload->ext_destructor = _rhp_ikev2_cp_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_cp_payload_serialize;

  cp_payloadh = (rhp_proto_ike_cp_payload*)_rhp_pkt_pull(ikemesg->rx_pkt,payload_len);
  if( cp_payloadh == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_NEW_RX_INVALID_MESG_2,"x",ikemesg);
    goto error;
  }

  p = (u8*)(cp_payloadh + 1);
  end = ((u8*)cp_payloadh) + payload_len;
  rem = end - p;

  while( rem > 0 ){

  	int cp_attr_len;
  	rhp_proto_ike_cfg_attr* cp_attrh;

  	if( p >= end ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_NEW_RX_INVALID_ATTR_LEN_ERR,"xE",ikemesg,err);
			goto error;
  	}

  	cp_attrh = (rhp_proto_ike_cfg_attr*)p;
  	cp_attr_len = sizeof(rhp_proto_ike_cfg_attr) + ntohs(cp_attrh->len);

  	err = cp_payload->put_attr_rx(payload,cp_attrh);
  	if( err ){
			RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_NEW_RX_PUT_CP_ATTR_ERR,"xE",ikemesg,err);
  		goto error;
    }

  	p = ((u8*)cp_attrh) + cp_attr_len;
  	rem -= cp_attr_len;
  }


  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_NEW_RX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_NEW_RX_ERR,"xE",ikemesg,err);
  return err;
}

int rhp_ikev2_cp_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_cp_payload* cp_payload;

  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_NEW_TX,"xLbx",ikemesg,"PROTO_IKE_PAYLOAD",payload_id,payload);

  cp_payload = _rhp_ikev2_alloc_cp_payload();
  if( cp_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.cp = cp_payload;
  payload->ext_destructor = _rhp_ikev2_cp_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_cp_payload_serialize;

  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_NEW_TX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_CP_PAYLOAD_NEW_TX_ERR,"xE",ikemesg,err);
  return err;
}

