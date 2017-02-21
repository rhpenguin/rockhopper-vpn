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

/*
int rhp_ikev1_id_type_to_v2_ts_type(int v1_id_type)
{
	switch( v1_id_type ){
	case RHP_PROTO_IKEV1_ID_IPV4_ADDR_RANGE:
		return RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE;
	case RHP_PROTO_IKEV1_ID_IPV6_ADDR_RANGE:
		return RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
	default:
		RHP_BUG("%d",v1_id_type);
		break;
	}
	return -EINVAL;
}
*/

static u8 _rhp_ikev1_id_payload_get_id_type(rhp_ikev2_payload* payload)
{
  u8 ret;
  rhp_proto_ikev1_id_payload* id_payloadh = (rhp_proto_ikev1_id_payload*)payload->payloadh;
  if( id_payloadh ){
    ret = id_payloadh->id_type;
  }else{
    ret = payload->ext.v1_id->id_type;
  }
  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_GET_ID_TYPE,"xxb",payload,id_payloadh,ret);
  return ret;
}

static int _rhp_ikev1_id_payload_get_id_len(rhp_ikev2_payload* payload)
{
  int len;
  if( payload->ext.v1_id->id ){
    len = payload->ext.v1_id->id_len;
  }else{
    len = payload->get_len_rx(payload);
    len -= sizeof(rhp_proto_ikev1_id_payload);
  }
  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_GET_ID_LEN,"xxd",payload,payload->ext.v1_id->id,len);
  return len;
}

static u8* _rhp_ikev1_id_payload_get_id(rhp_ikev2_payload* payload)
{
  u8* ret;
  rhp_proto_ikev1_id_payload* id_payloadh;
  int id_len = _rhp_ikev1_id_payload_get_id_len(payload);

  if( id_len ){

		if( payload->ext.v1_id->id ){
			ret = payload->ext.v1_id->id;
		}else{
			id_payloadh = (rhp_proto_ikev1_id_payload*)(payload->payloadh);
			ret = (u8*)(id_payloadh + 1);
		}

  }else{

    ret = NULL;
  }

  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_GET_ID,"xxxp",payload,payload->ext.v1_id->id,ret,id_len,ret);
  return ret;
}

static void _rhp_ikev1_id_payload_destructor(rhp_ikev2_payload* payload)
{
  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_DESTRUCTOR,"xx",payload,payload->ext.v1_id->id);

  if( payload->ext.v1_id->id ){
    _rhp_free(payload->ext.v1_id->id);
    payload->ext.v1_id->id = NULL;
    payload->ext.v1_id->id_len = 0;
  }
  
  return;
}

static int _rhp_ikev1_id_payload_serialize(rhp_ikev2_payload* payload,rhp_packet* pkt)
{
	u8 id_type = payload->ext.v1_id->get_id_type(payload);

	RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_SERIALIZE,"xxxb",payload,pkt,payload->ext.v1_id->id,id_type);
  
  if( payload->ext.v1_id->id || id_type == RHP_PROTO_IKE_ID_NULL_ID ){

    int len = sizeof(rhp_proto_ikev1_id_payload) + payload->ext.v1_id->id_len;
    rhp_proto_ikev1_id_payload* p;

    p = (rhp_proto_ikev1_id_payload*)rhp_pkt_expand_tail(pkt,len);
    if( p == NULL ){
      RHP_BUG("");
      return -ENOMEM;
    }
    
    p->next_payload = payload->get_next_payload(payload);
    p->reserved = 0;
    p->len = htons(len);
    p->id_type = payload->ext.v1_id->get_id_type(payload);

    if( payload->ext.v1_id->protocol_id ){
      p->protocol_id = payload->ext.v1_id->protocol_id;
    }else{
      p->protocol_id = 0;
    }

    if( payload->ext.v1_id->port ){
      p->port = htons(payload->ext.v1_id->port);
    }else{
      p->port = 0;
    }

    if( payload->ext.v1_id->id_len ){
    	memcpy((p + 1),payload->ext.v1_id->id,payload->ext.v1_id->id_len);
    }
    
    payload->ikemesg->tx_mesg_len += len;

    p->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
    if( payload->next ){
      p->next_payload = payload->next->get_payload_id(payload->next);
    }
    
    RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_SERIALIZE_RTRN,"xx",payload,pkt);
    rhp_pkt_trace_dump("_rhp_ikev1_id_payload_serialize",pkt);
    return 0;
  }

  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_SERIALIZE_ERR,"xx",payload,pkt);
  return -EINVAL;
}

static int _rhp_ikev1_id_payload_set_id(rhp_ikev2_payload* payload,int id_type,int id_len,u8* id)
{
  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_SET_ID,"xbp",payload,id_type,id_len,id);

  if( payload->ext.v1_id->id ){
    RHP_BUG("");
    return -EEXIST;
  }

	payload->ext.v1_id->id = (u8*)_rhp_malloc(id_len);
	if( payload->ext.v1_id->id == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	memcpy(payload->ext.v1_id->id,id,id_len);
	payload->ext.v1_id->id_len = id_len;

  payload->ext.v1_id->id_type = id_type;

  return 0;
}


static u8 _rhp_ikev1_id_payload_get_protocol_id(rhp_ikev2_payload* payload)
{
	u8 ret;
  rhp_proto_ikev1_id_payload* id_payloadh = (rhp_proto_ikev1_id_payload*)payload->payloadh;

  if( id_payloadh ){
    ret = id_payloadh->protocol_id;
  }else{
    ret = payload->ext.v1_id->protocol_id;
  }

  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_GET_PROTOCOL_ID,"xd",payload,ret);
  return ret;
}

static u16 _rhp_ikev1_id_payload_get_port(rhp_ikev2_payload* payload)
{
	u16 ret;
  rhp_proto_ikev1_id_payload* id_payloadh = (rhp_proto_ikev1_id_payload*)payload->payloadh;

  if( id_payloadh ){
    ret = ntohs(id_payloadh->port);
  }else{
    ret = payload->ext.v1_id->port;
  }
  
  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_GET_PORT,"xw",payload,ret);
  return ret;
}


static int _rhp_ikev1_id_payload_set_cfg_ts(rhp_ikev2_payload* payload,
		rhp_vpn_realm* rlm,int addr_family,rhp_traffic_selector* cfg_tss,
		rhp_ip_addr* cp_internal_addr,rhp_ip_addr* gre_addr,
		rhp_childsa_ts** csa_ts_r)
{
  int err = -EINVAL;
  rhp_traffic_selector* cfg_ts = cfg_tss;
  int id_type;
	int buf_len;
	u8 buf[32];
	rhp_childsa_ts* csa_ts = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_SET_CFG_TS,"xLdxxxLdxx",payload,rlm,cfg_tss,cp_internal_addr,"AF",addr_family,gre_addr);

  if( cp_internal_addr &&
  		cp_internal_addr->addr_family != addr_family ){
  	RHP_BUG("%d,%d",cp_internal_addr->addr_family,addr_family);
  	err = -EINVAL;
  	goto error;
  }

  csa_ts = (rhp_childsa_ts*)_rhp_malloc(sizeof(rhp_childsa_ts));
  if( csa_ts == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }
  memset(csa_ts,0,sizeof(rhp_childsa_ts));

  csa_ts->is_v1 = 1;

	csa_ts->start_addr.addr_family = addr_family;
	csa_ts->end_addr.addr_family = addr_family;

	payload->ext.v1_id->port = 0;
	payload->ext.v1_id->protocol_id = 0;


  while( cfg_ts ){

  	if( addr_family == AF_INET &&
				cfg_ts->ts_type == RHP_CFG_IKEV1_TS_IPV4_ADDR_RANGE &&
				cfg_ts->ts_is_subnet ){

			payload->ext.v1_id->port = cfg_ts->start_port;
			payload->ext.v1_id->protocol_id = cfg_ts->protocol;

			buf_len = 8;
			memcpy(buf,cfg_ts->addr.subnet.addr.raw,4);
			memcpy((buf + 4),cfg_ts->addr.subnet.netmask.raw,4);

			id_type = RHP_PROTO_IKEV1_ID_IPV4_ADDR_SUBNET;

			break;

  	}else if( addr_family == AF_INET &&
  						cfg_ts->ts_type == RHP_CFG_IKEV1_TS_IPV4_ADDR_RANGE ){

  		payload->ext.v1_id->port = cfg_ts->start_port;
  		payload->ext.v1_id->protocol_id = cfg_ts->protocol;

  		buf_len = 8;

			memcpy(buf,cfg_ts->addr.range.start.addr.raw,4);
			memcpy((buf + 4),cfg_ts->addr.range.end.addr.raw,4);

			id_type = RHP_PROTO_IKEV1_ID_IPV4_ADDR_RANGE;

  		break;

  	}else if( addr_family == AF_INET6 &&
  						cfg_ts->ts_type == RHP_CFG_IKEV1_TS_IPV6_ADDR_RANGE &&
  						cfg_ts->ts_is_subnet ){

  		payload->ext.v1_id->port = cfg_ts->start_port;
  		payload->ext.v1_id->protocol_id = cfg_ts->protocol;

  		buf_len = 32;
  		memcpy(buf,cfg_ts->addr.subnet.addr.raw,16);
  		memcpy((buf + 16),cfg_ts->addr.subnet.netmask.raw,16);

			id_type = RHP_PROTO_IKEV1_ID_IPV6_ADDR_SUBNET;

  		break;

  	}else if( addr_family == AF_INET6 &&
  						cfg_ts->ts_type == RHP_CFG_IKEV1_TS_IPV6_ADDR_RANGE ){

  		payload->ext.v1_id->port = cfg_ts->start_port;
  		payload->ext.v1_id->protocol_id = cfg_ts->protocol;

  		buf_len = 32;
  		memcpy(buf,cfg_ts->addr.range.start.addr.raw,16);
  		memcpy((buf + 16),cfg_ts->addr.range.end.addr.raw,16);

			id_type = RHP_PROTO_IKEV1_ID_IPV6_ADDR_RANGE;

  		break;
  	}

  	cfg_ts = cfg_ts->next;
  }

  if( cfg_ts ){

		csa_ts->ts_or_id_type = id_type;
		csa_ts->protocol = cfg_ts->protocol;
		csa_ts->start_port = cfg_ts->start_port;

		if( id_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR_SUBNET ){

			memcpy(&(csa_ts->start_addr),&(cfg_ts->addr.subnet),sizeof(rhp_ip_addr));

			rhp_ipv4_subnet_addr_range(cfg_ts->addr.subnet.addr.v4,
					cfg_ts->addr.subnet.netmask.v4,NULL,&(csa_ts->end_addr.addr.v4));

			csa_ts->v1_prefix_len = cfg_ts->addr.subnet.prefixlen;

		}else if( id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR_SUBNET ){

			memcpy(&(csa_ts->start_addr),&(cfg_ts->addr.subnet),sizeof(rhp_ip_addr));

			rhp_ipv6_subnet_addr_range(cfg_ts->addr.subnet.addr.v6,
					cfg_ts->addr.subnet.prefixlen,NULL,csa_ts->end_addr.addr.v6);

			csa_ts->v1_prefix_len = cfg_ts->addr.subnet.prefixlen;

		}else{

			memcpy(&(csa_ts->start_addr),&(cfg_ts->addr.range.start),sizeof(rhp_ip_addr));
			memcpy(&(csa_ts->end_addr),&(cfg_ts->addr.range.end),sizeof(rhp_ip_addr));
		}

  }else{

  	if( gre_addr ){

  		if( gre_addr->addr_family == AF_INET ){

    		buf_len = 4;
    		memcpy(buf,gre_addr->addr.raw,4);

  			id_type = RHP_PROTO_IKEV1_ID_IPV4_ADDR;
    		payload->ext.v1_id->protocol_id = RHP_PROTO_IP_GRE;

    		payload->ext.v1_id->gre_ts_auto_generated = 1;

  			csa_ts->ts_or_id_type = RHP_PROTO_IKEV1_ID_IPV4_ADDR_RANGE;
  			csa_ts->protocol = RHP_PROTO_IP_GRE;
  			csa_ts->start_addr.addr.v4 = gre_addr->addr.v4;
  			csa_ts->end_addr.addr.v4 = gre_addr->addr.v4;

  		}else if( gre_addr->addr_family == AF_INET6 ){

    		buf_len = 16;
    		memcpy(buf,gre_addr->addr.raw,16);
    		payload->ext.v1_id->protocol_id = RHP_PROTO_IP_GRE;

    		payload->ext.v1_id->gre_ts_auto_generated = 1;

  			id_type = RHP_PROTO_IKEV1_ID_IPV6_ADDR;

  			csa_ts->ts_or_id_type = RHP_PROTO_IKEV1_ID_IPV6_ADDR_RANGE;
  			csa_ts->protocol = RHP_PROTO_IP_GRE;
  			memcpy(csa_ts->start_addr.addr.v6,gre_addr->addr.v6,16);
  			memcpy(csa_ts->end_addr.addr.v6,gre_addr->addr.v6,16);

  		}else{
  			RHP_BUG("%d",gre_addr->addr_family);
  			err = -EINVAL;
  			goto error;
  		}

  	}else if( addr_family == AF_INET ){

  		u32 start_any = 0;
  		u32 end_eny = 0xFFFFFFFF;

  		buf_len = 8;
  		memcpy(buf,&start_any,4);
  		memcpy((buf + 4),&end_eny,4);

			id_type = RHP_PROTO_IKEV1_ID_IPV4_ADDR_RANGE;

			csa_ts->ts_or_id_type = id_type;
			csa_ts->start_addr.addr.v4 = start_any;
			csa_ts->end_addr.addr.v4 = end_eny;

  	}else if( addr_family == AF_INET6 ){

  		u8 start_any[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  		u8 end_eny[16] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

  		buf_len = 32;
  		memcpy(buf,start_any,16);
  		memcpy((buf + 4),end_eny,16);

			id_type = RHP_PROTO_IKEV1_ID_IPV6_ADDR_RANGE;

			csa_ts->ts_or_id_type = id_type;
			memcpy(csa_ts->start_addr.addr.v6,start_any,16);
			memcpy(csa_ts->end_addr.addr.v6,end_eny,16);

  	}else{
  		RHP_BUG("%d",addr_family);
  		err = -EINVAL;
  		goto error;
  	}
  }

  if( cp_internal_addr ){

  	if( addr_family == AF_INET ){

  		buf_len = 8;

			memcpy(buf,cp_internal_addr->addr.raw,4);
			memcpy((buf + 4),cp_internal_addr->addr.raw,4);

			id_type = RHP_PROTO_IKEV1_ID_IPV4_ADDR_RANGE;

			csa_ts->ts_or_id_type = id_type;
			csa_ts->start_addr.addr.v4 = cp_internal_addr->addr.v4;
			csa_ts->end_addr.addr.v4 = cp_internal_addr->addr.v4;

  	}else if( addr_family == AF_INET6 ){

  		buf_len = 32;
			memcpy(buf,cp_internal_addr->addr.raw,16);
			memcpy((buf + 4),cp_internal_addr->addr.raw,16);

			id_type = RHP_PROTO_IKEV1_ID_IPV6_ADDR_RANGE;

			csa_ts->ts_or_id_type = id_type;
			memcpy(csa_ts->start_addr.addr.v6,cp_internal_addr->addr.v6,16);
			memcpy(csa_ts->end_addr.addr.v6,cp_internal_addr->addr.v6,16);
  	}
  }

	if( csa_ts->start_port == 0 ){
		csa_ts->end_port = 0xFFFF;
	}else{
		csa_ts->end_port = cfg_ts->start_port;
	}

	err = payload->ext.v1_id->set_id(payload,id_type,buf_len,buf);
	if( err ){
		goto error;
	}

	*csa_ts_r = csa_ts;

  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_SET_CFG_TS_CSA_TS,"xdbbWWbbbb",csa_ts,csa_ts->is_v1,csa_ts->ts_or_id_type,csa_ts->protocol,csa_ts->start_port,csa_ts->end_port,csa_ts->icmp_start_type,csa_ts->icmp_end_type,csa_ts->icmp_start_code,csa_ts->icmp_end_code);
  rhp_ip_addr_dump("start_addr.csa_ts",&(csa_ts->start_addr));
  rhp_ip_addr_dump("end_addr.csa_ts",&(csa_ts->end_addr));

  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_SET_CFG_TS_RTRN,"xxx",payload,cfg_tss,*csa_ts_r);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_SET_CFG_TS_ERR,"xxE",payload,cfg_tss,err);
	return err;
}

static int _rhp_ikev1_id_payload_set_csa_ts(rhp_ikev2_payload* payload,rhp_childsa_ts* csa_ts)
{
  int err = -EINVAL;
	int buf_len;
	u8 buf[32];

  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_SET_CSA_TS,"xx",payload,csa_ts);

  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_SET_CSA_TS_CSA_TS,"xdbbWWbbbbb",csa_ts,csa_ts->is_v1,csa_ts->ts_or_id_type,csa_ts->protocol,csa_ts->start_port,csa_ts->end_port,csa_ts->icmp_start_type,csa_ts->icmp_end_type,csa_ts->icmp_start_code,csa_ts->icmp_end_code,csa_ts->ts_or_id_type_org);
  rhp_ip_addr_dump("start_addr.csa_ts",&(csa_ts->start_addr));
  rhp_ip_addr_dump("end_addr.csa_ts",&(csa_ts->end_addr));


	payload->ext.v1_id->port = csa_ts->start_port;
	payload->ext.v1_id->protocol_id = csa_ts->protocol;

	if( csa_ts->ts_or_id_type_org == RHP_PROTO_IKEV1_ID_IPV4_ADDR ){

		buf_len = 4;

		memcpy(buf,csa_ts->start_addr.addr.raw,4);

	}else if( csa_ts->ts_or_id_type_org == RHP_PROTO_IKEV1_ID_IPV4_ADDR_RANGE ){

		buf_len = 8;

		memcpy(buf,csa_ts->start_addr.addr.raw,4);
		memcpy((buf + 4),csa_ts->end_addr.addr.raw,4);

	}else if( csa_ts->ts_or_id_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR_SUBNET ){

		u32 netmask = rhp_ipv4_prefixlen_to_netmask(csa_ts->v1_prefix_len);

		buf_len = 8;

		memcpy(buf,csa_ts->start_addr.addr.raw,4);
		memcpy((buf + 4),&netmask,4);

	}else if( csa_ts->ts_or_id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR ){

		buf_len = 16;

		memcpy(buf,csa_ts->start_addr.addr.raw,16);

	}else if( csa_ts->ts_or_id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR_RANGE ){

		buf_len = 32;

		memcpy(buf,csa_ts->start_addr.addr.raw,16);
		memcpy((buf + 16),csa_ts->end_addr.addr.raw,16);

	}else if( csa_ts->ts_or_id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR_SUBNET ){

		u8 netmask[16];

		rhp_ipv6_prefixlen_to_netmask(csa_ts->v1_prefix_len,netmask);

		buf_len = 32;

		memcpy(buf,csa_ts->start_addr.addr.raw,16);
		memcpy((buf + 16),netmask,16);

	}else{

		RHP_BUG("%d,%d",csa_ts->ts_or_id_type,csa_ts->ts_or_id_type_org);
		return -EINVAL;
	}

	err = payload->ext.v1_id->set_id(payload,csa_ts->ts_or_id_type_org,buf_len,buf);
	if( err ){
		goto error;
	}


  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_SET_CSA_TS_RTRN,"xx",payload,csa_ts);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_SET_CSA_TS_ERR,"xxE",payload,csa_ts,err);
	return err;
}

// rlm->lock must be acquired.
static int _rhp_ikev1_id_payload_set_i_ts(rhp_ikev2_payload* payload,rhp_vpn_realm* rlm,
		int side,int addr_family,rhp_cfg_peer* cfg_peer,rhp_ip_addr* cp_internal_addr,
		rhp_ip_addr* gre_addr,rhp_childsa_ts** csa_ts_r)
{
  int err;
  rhp_traffic_selector *tss;

  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_SET_I_TS,"xxxxLdLdxx",payload,rlm,cfg_peer,cp_internal_addr,"IKE_SIDE",side,"AF",addr_family,gre_addr,csa_ts_r);
  rhp_ip_addr_dump("gre_addr",gre_addr);
  rhp_ip_addr_dump("cp_internal_addr",cp_internal_addr);

  if( side == RHP_IKE_INITIATOR ){
    tss = cfg_peer->my_tss;
  }else{
    tss = cfg_peer->peer_tss;
  }

  err = _rhp_ikev1_id_payload_set_cfg_ts(payload,rlm,addr_family,tss,cp_internal_addr,
  				gre_addr,csa_ts_r);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_SET_I_TS_RTRN,"xxx",payload,rlm,cfg_peer);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_SET_I_TS_ERR,"xxxE",payload,rlm,cfg_peer,err);
  return err;
}

static rhp_childsa_ts* _rhp_ikev1_id_payload_to_csa_ts(rhp_ikev2_payload* payload)
{
	rhp_childsa_ts* csa_ts;
	u8 id_type = payload->ext.v1_id->get_id_type(payload);
	int id_len = payload->ext.v1_id->get_id_len(payload);
	u8* id_val = payload->ext.v1_id->get_id(payload);

  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_TO_CSA_TS,"xLbp",payload,"PROTO_IKE_TS",id_type,id_len,id_val);

	csa_ts = (rhp_childsa_ts*)_rhp_malloc(sizeof(rhp_childsa_ts));
	if( csa_ts == NULL ){
		RHP_BUG("");
		return NULL;
	}
	memset(csa_ts,0,sizeof(rhp_childsa_ts));

  csa_ts->is_v1 = 1;
	csa_ts->ts_or_id_type_org = id_type;

  if( id_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR ){
  	csa_ts->ts_or_id_type = RHP_PROTO_IKEV1_ID_IPV4_ADDR_RANGE;
  }else if( id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR ){
  	csa_ts->ts_or_id_type = RHP_PROTO_IKEV1_ID_IPV6_ADDR_RANGE;
  }else{
  	csa_ts->ts_or_id_type = id_type;
  }
	csa_ts->protocol = payload->ext.v1_id->get_protocol_id(payload);
	csa_ts->start_port = payload->ext.v1_id->get_port(payload);
	if( csa_ts->start_port == 0 ){
		csa_ts->end_port = 0xFFFF;
	}else{
		csa_ts->end_port = csa_ts->start_port;
	}

	if( id_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR && id_len == 4 ){

		csa_ts->start_addr.addr_family = AF_INET;
		csa_ts->end_addr.addr_family = AF_INET;
		csa_ts->start_addr.addr.v4 = *((u32*)id_val);
		csa_ts->end_addr.addr.v4 = *((u32*)id_val);

	}else if( id_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR_SUBNET && id_len == 8 ){

		u32 netmask;

		csa_ts->start_addr.addr_family = AF_INET;
		csa_ts->end_addr.addr_family = AF_INET;

		csa_ts->start_addr.addr.v4 = *((u32*)id_val);

		netmask = *(((u32*)id_val) + 1);
		csa_ts->v1_prefix_len = rhp_ipv4_netmask_to_prefixlen(netmask);

		rhp_ipv4_subnet_addr_range(*((u32*)id_val),netmask,
				NULL,&(csa_ts->end_addr.addr.v4));

	}else if( id_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR_RANGE && id_len == 8 ){

		csa_ts->start_addr.addr_family = AF_INET;
		csa_ts->end_addr.addr_family = AF_INET;

		csa_ts->start_addr.addr.v4 = *((u32*)id_val);
		csa_ts->end_addr.addr.v4 = *(((u32*)id_val) + 1);

	}else if( id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR && id_len == 16 ){

		csa_ts->start_addr.addr_family = AF_INET6;
		csa_ts->end_addr.addr_family = AF_INET6;
		memcpy(csa_ts->start_addr.addr.v6,id_val,16);
		memcpy(csa_ts->end_addr.addr.v6,id_val,16);

	}else if( id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR_SUBNET && id_len == 32 ){

		csa_ts->start_addr.addr_family = AF_INET;
		csa_ts->end_addr.addr_family = AF_INET;

		memcpy(csa_ts->start_addr.addr.v6,id_val,16);

		csa_ts->v1_prefix_len = rhp_ipv6_netmask_to_prefixlen((id_val + 16));

		rhp_ipv6_subnet_addr_range(id_val,csa_ts->v1_prefix_len,
				NULL,csa_ts->end_addr.addr.v6);

	}else if( id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR_RANGE && id_len == 32 ){

		csa_ts->start_addr.addr_family = AF_INET6;
		csa_ts->end_addr.addr_family = AF_INET6;

		memcpy(csa_ts->start_addr.addr.v6,id_val,16);
		memcpy(csa_ts->end_addr.addr.v6,(id_val + 16),16);

	}else{

		RHP_BUG("%d,%d",id_type,id_len);
		_rhp_free(csa_ts);
		return NULL;
	}


  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_TO_CSA_TS_RTRN,"xx",payload,csa_ts);
	rhp_childsa_ts_dump("_rhp_ikev1_id_payload_to_csa_ts",csa_ts);

	return csa_ts;
}

//
// For Child SA Respnder's API
//
// rlm->lock must be acquired. -ENOENT : Acceptable traffic selector(s) not found.

static int _rhp_ikev1_id_payload_get_matched_ts(rhp_ikev2_payload* payload,
		int side,rhp_vpn_realm* rlm,rhp_cfg_peer* cfg_peer,rhp_ip_addr* gre_addr)
{
  rhp_traffic_selector* tss;
  int tss_num;
  int ret;

  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_GET_MATCHED_TS,"xdxxx",payload,side,rlm,cfg_peer,gre_addr);
  rhp_ip_addr_dump("gre_addr",gre_addr);

  if( side == RHP_IKE_INITIATOR ){
    tss = cfg_peer->peer_tss;
    tss_num = cfg_peer->peer_tss_num;
  }else{
    tss = cfg_peer->my_tss;
    tss_num = cfg_peer->my_tss_num;
  }


  ret = rhp_childsa_ikev1_match_traffic_selectors_cfg(tss_num,tss,payload,gre_addr);

  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_GET_MATCHED_TS_RTRN,"xxxE",payload,rlm,cfg_peer,ret);
  return ret;
}

//
// For Child SA Initiator's API.
//
// rlm->lock must be acquired.
//
// -ENOENT : Acceptable traffic selector(s) not found.
//
static int _rhp_ikev1_id_payload_check_ts(rhp_ikev2_payload* payload,int side,
		rhp_childsa* childsa)
{
	int ret = -1;
	rhp_childsa_ts* csa_ts;
  rhp_childsa_ts* ts;
  int is_my_ts_any = 0;

  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_CHECK_TS,"xdxxx",payload,side,childsa,childsa->my_tss,childsa->peer_tss);

  if( side == RHP_IKE_INITIATOR ){
  	csa_ts = childsa->my_tss;
  }else{
  	csa_ts = childsa->peer_tss;
  }

  is_my_ts_any = rhp_childsa_ts_is_any(csa_ts);


  ts = _rhp_ikev1_id_payload_to_csa_ts(payload);
  if( ts ){

  	if( is_my_ts_any ||
  			(ts->protocol == csa_ts->protocol &&
  			 ts->start_port == csa_ts->start_port &&
  			 ts->end_port == csa_ts->end_port &&
  			 !rhp_ip_addr_cmp_ip_only(&(ts->start_addr),&(csa_ts->start_addr)) &&
  	  	 !rhp_ip_addr_cmp_ip_only(&(ts->end_addr),&(csa_ts->end_addr))) ){

  		ret = 0;
  	}

  	_rhp_free(ts);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_CHECK_TS_RTRN,"xxxdE",payload,childsa,csa_ts,is_my_ts_any,ret);
  return ret;
}


static rhp_ikev1_id_payload* _rhp_ikev1_alloc_id_payload()
{
  rhp_ikev1_id_payload* id_payload;

  id_payload = (rhp_ikev1_id_payload*)_rhp_malloc(sizeof(rhp_ikev1_id_payload));
  if( id_payload == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(id_payload,0,sizeof(rhp_ikev1_id_payload));

  id_payload->get_id_type = _rhp_ikev1_id_payload_get_id_type;
  id_payload->get_id_len = _rhp_ikev1_id_payload_get_id_len;
  id_payload->get_id = _rhp_ikev1_id_payload_get_id;
  id_payload->set_id = _rhp_ikev1_id_payload_set_id;
  id_payload->get_protocol_id = _rhp_ikev1_id_payload_get_protocol_id;
  id_payload->get_port = _rhp_ikev1_id_payload_get_port;
  id_payload->set_i_ts = _rhp_ikev1_id_payload_set_i_ts;
  id_payload->to_csa_ts = _rhp_ikev1_id_payload_to_csa_ts;
  id_payload->get_matched_ts = _rhp_ikev1_id_payload_get_matched_ts;
  id_payload->check_ts = _rhp_ikev1_id_payload_check_ts;
  id_payload->set_csa_ts = _rhp_ikev1_id_payload_set_csa_ts;

  RHP_TRC(0,RHPTRCID_IKEV1_ALLOC_ID_PAYLOAD,"x",id_payload);
  return id_payload;
}

int rhp_ikev1_id_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev1_id_payload* id_payload;
  rhp_proto_ikev1_id_payload* id_payloadh = (rhp_proto_ikev1_id_payload*)payloadh;
  u8 id_type;
  int id_len;

  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_NEW_RX,"xbxdxp",ikemesg,payload_id,payloadh,payload_len,payload,payload_len,payloadh);

  if( payload_len < (int)sizeof(rhp_proto_ikev1_id_payload) ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_NEW_RX_INVALID_MESG_1,"xdd",ikemesg,payload_len,sizeof(rhp_proto_ikev1_id_payload));
    goto error;
  }

  id_type = id_payloadh->id_type;
  
  switch( id_type ){
    
		case RHP_PROTO_IKEV1_ID_IPV4_ADDR:
		case RHP_PROTO_IKEV1_ID_FQDN:
		case RHP_PROTO_IKEV1_ID_USER_FQDN:
		case RHP_PROTO_IKEV1_ID_IPV4_ADDR_SUBNET:
		case RHP_PROTO_IKEV1_ID_IPV6_ADDR:
		case RHP_PROTO_IKEV1_ID_IPV6_ADDR_SUBNET:
		case RHP_PROTO_IKEV1_ID_IPV4_ADDR_RANGE:
		case RHP_PROTO_IKEV1_ID_IPV6_ADDR_RANGE:
		case RHP_PROTO_IKEV1_ID_DER_ASN1_DN:
      break;
    
		case RHP_PROTO_IKEV1_ID_LIST:
    default:
      err = RHP_STATUS_UNKNOWN_PARAM;
      RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_NEW_RX_INVALID_MESG_2,"xb",ikemesg,id_type);
      goto error;
  }
  
  id_len = payload_len - sizeof(rhp_proto_ikev1_id_payload);
	if( id_len < 1 ){
		err = RHP_STATUS_INVALID_MSG;
		RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_NEW_RX_INVALID_MESG_INVALID_LEN,"xd",ikemesg,id_len);
		goto error;
	}

  
  id_payload = _rhp_ikev1_alloc_id_payload();
  if( id_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.v1_id = id_payload;
  payload->ext_destructor = _rhp_ikev1_id_payload_destructor;
  payload->ext_serialize = _rhp_ikev1_id_payload_serialize;

  id_payloadh = (rhp_proto_ikev1_id_payload*)_rhp_pkt_pull(ikemesg->rx_pkt,payload_len);
  if( id_payloadh == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_NEW_RX_INVALID_MESG_4,"x",ikemesg);
    goto error;
  }
  
  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_NEW_RX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_NEW_RX_ERR,"xE",ikemesg,err);
  return err;
}

int rhp_ikev1_id_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev1_id_payload* id_payload;

  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_NEW_TX,"xLbx",ikemesg,"PROTO_IKE_PAYLOAD",payload_id,payload);

  id_payload = _rhp_ikev1_alloc_id_payload();
  if( id_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.v1_id = id_payload;
  payload->ext_destructor = _rhp_ikev1_id_payload_destructor;
  payload->ext_serialize = _rhp_ikev1_id_payload_serialize;

  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_NEW_TX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_ID_PAYLOAD_NEW_TX_ERR,"xE",ikemesg,err);
  return err;
}

