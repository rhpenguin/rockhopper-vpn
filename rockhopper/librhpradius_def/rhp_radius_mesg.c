/*

	Copyright (C) 2015-2016 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.

	This library may be distributed, used, and modified under the terms of
	BSD license:

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are
	met:

	1. Redistributions of source code must retain the above copyright
		 notice, this list of conditions and the following disclaimer.

	2. Redistributions in binary form must reproduce the above copyright
		 notice, this list of conditions and the following disclaimer in the
		 documentation and/or other materials provided with the distribution.

	3. Neither the name(s) of the above-listed copyright holder(s) nor the
		 names of its contributors may be used to endorse or promote products
		 derived from this software without specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
	"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
	LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
	A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
	OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
	SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
	LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
	DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
	THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
	OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
#include "rhp_timer.h"
#include "rhp_packet.h"
#include "rhp_netsock.h"
#include "rhp_packet.h"
#include "rhp_config.h"
#include "rhp_crypto.h"
#include "rhp_radius_impl.h"
#include "rhp_radius_priv.h"


static u8 _rhp_radius_mesg_get_code(rhp_radius_mesg* radius_mesg)
{
	rhp_radius_mesg_priv* radius_mesg_priv = (rhp_radius_mesg_priv*)radius_mesg->priv;
	rhp_proto_radius* radiush;
	rhp_packet* rx_pkt = NULL;

  if( radius_mesg_priv->rx_pkt_ref ){

  	rx_pkt = RHP_PKT_REF(radius_mesg_priv->rx_pkt_ref);
  	radiush = (rhp_proto_radius*)rx_pkt->app.raw;

  }else{

  	radiush = radius_mesg_priv->tx_radiush;
  }

  RHP_TRC(0,RHPTRCID_RADIUS_MESG_GET_CODE,"xxxb",radius_mesg,radius_mesg_priv,rx_pkt,radiush->code);
  return radiush->code;
}

static void _rhp_radius_mesg_set_code(rhp_radius_mesg* radius_mesg,u8 code)
{
	rhp_radius_mesg_priv* radius_mesg_priv = (rhp_radius_mesg_priv*)radius_mesg->priv;

	if( radius_mesg_priv->tx_radiush ){

		radius_mesg_priv->tx_radiush->code = code;
	  RHP_TRC(0,RHPTRCID_RADIUS_MESG_SET_CODE,"xxxb",radius_mesg,radius_mesg_priv,radius_mesg_priv->tx_radiush,radius_mesg_priv->tx_radiush->code);

	}else{
		RHP_BUG("");
	}

	return;
}

static u8 _rhp_radius_mesg_get_id(rhp_radius_mesg* radius_mesg)
{
	rhp_radius_mesg_priv* radius_mesg_priv = (rhp_radius_mesg_priv*)radius_mesg->priv;
	rhp_proto_radius* radiush;
	rhp_packet* rx_pkt = NULL;

  if( radius_mesg_priv->rx_pkt_ref ){

  	rx_pkt = RHP_PKT_REF(radius_mesg_priv->rx_pkt_ref);
  	radiush = (rhp_proto_radius*)rx_pkt->app.raw;

  }else{

  	radiush = radius_mesg_priv->tx_radiush;
  }

  RHP_TRC(0,RHPTRCID_RADIUS_MESG_GET_ID,"xxxxb",radius_mesg,radius_mesg_priv,rx_pkt,radius_mesg_priv->tx_radiush,radiush->id);
  return radiush->id;
}

static void _rhp_radius_mesg_set_id(rhp_radius_mesg* radius_mesg,u8 id)
{
	rhp_radius_mesg_priv* radius_mesg_priv = (rhp_radius_mesg_priv*)radius_mesg->priv;

	if( radius_mesg_priv->tx_radiush ){

		radius_mesg_priv->tx_radiush->id = id;
	  RHP_TRC(0,RHPTRCID_RADIUS_MESG_SET_ID,"xxxb",radius_mesg,radius_mesg_priv,radius_mesg_priv->tx_radiush,radius_mesg_priv->tx_radiush->id);

	}else{
		RHP_BUG("");
	}

	return;
}

static u16 _rhp_radius_mesg_get_len(rhp_radius_mesg* radius_mesg)
{
	rhp_radius_mesg_priv* radius_mesg_priv = (rhp_radius_mesg_priv*)radius_mesg->priv;
	rhp_proto_radius* radiush;
	rhp_packet* rx_pkt = NULL;

  if( radius_mesg_priv->rx_pkt_ref ){

  	rx_pkt = RHP_PKT_REF(radius_mesg_priv->rx_pkt_ref);
  	radiush = (rhp_proto_radius*)rx_pkt->app.raw;

  }else{

  	radiush = radius_mesg_priv->tx_radiush;
  }

  RHP_TRC(0,RHPTRCID_RADIUS_MESG_GET_LEN,"xxxJ",radius_mesg,radius_mesg_priv,rx_pkt,radiush->len);
  return ntohs(radiush->len);
}

static u8* _rhp_radius_mesg_get_authenticator(rhp_radius_mesg* radius_mesg)
{
	rhp_radius_mesg_priv* radius_mesg_priv = (rhp_radius_mesg_priv*)radius_mesg->priv;
	rhp_proto_radius* radiush;
	rhp_packet* rx_pkt = NULL;

  if( radius_mesg_priv->rx_pkt_ref ){

  	rx_pkt = RHP_PKT_REF(radius_mesg_priv->rx_pkt_ref);
  	radiush = (rhp_proto_radius*)rx_pkt->app.raw;

  }else{

  	radiush = radius_mesg_priv->tx_radiush;
  }

  RHP_TRC(0,RHPTRCID_RADIUS_MESG_GET_AUTHENTICATOR,"xxxp",radius_mesg,radius_mesg_priv,rx_pkt,RHP_RADIUS_AUTHENTICATOR_LEN,radiush->authenticator);
  return radiush->authenticator;
}

static void _rhp_radius_mesg_set_authenticator(rhp_radius_mesg* radius_mesg,u8* authenticator)
{
	rhp_radius_mesg_priv* radius_mesg_priv = (rhp_radius_mesg_priv*)radius_mesg->priv;

	if( radius_mesg_priv->tx_radiush ){

		memcpy(radius_mesg_priv->tx_radiush->authenticator,authenticator,RHP_RADIUS_AUTHENTICATOR_LEN);
	  RHP_TRC(0,RHPTRCID_RADIUS_MESG_SET_AUTHENTICATOR,"xxxp",radius_mesg,radius_mesg_priv,radius_mesg_priv->tx_radiush,RHP_RADIUS_AUTHENTICATOR_LEN,radius_mesg_priv->tx_radiush->authenticator);

	}else{
		RHP_BUG("");
	}

	return;
}

static void _rhp_radius_mesg_put_attr(rhp_radius_mesg* radius_mesg,rhp_radius_attr* radius_attr)
{
  RHP_TRC(0,RHPTRCID_RADIUS_MESG_PUT_ATTR,"xxLbd",radius_mesg,radius_attr,"PROTO_RADIUS_ATTR",radius_attr->attr_type,(radius_mesg->attr_num + 1));

  if( radius_mesg->attr_head == NULL ){
    radius_mesg->attr_head = radius_attr;
  }else{
    radius_mesg->attr_tail->next = radius_attr;
  }
  radius_mesg->attr_tail = radius_attr;

  if( radius_attr->radius_mesg == NULL ){
  	radius_attr->radius_mesg = radius_mesg;
  }

  radius_mesg->attr_num++;

  return;
}

static void _rhp_radius_mesg_put_attr_head(rhp_radius_mesg* radius_mesg,rhp_radius_attr* radius_attr)
{
  RHP_TRC(0,RHPTRCID_RADIUS_MESG_PUT_ATTR_HEAD,"xxLbd",radius_mesg,radius_attr,"PROTO_RADIUS_ATTR",radius_attr->attr_type,(radius_mesg->attr_num + 1));

	radius_attr->next = radius_mesg->attr_head;
  if( radius_mesg->attr_tail == NULL ){
    radius_mesg->attr_tail = radius_attr;
  }
  radius_mesg->attr_head = radius_attr;

  if( radius_attr->radius_mesg == NULL ){
  	radius_attr->radius_mesg = radius_mesg;
  }

  radius_mesg->attr_num++;

  return;
}

static void _rhp_radius_mesg_set_termination_request(rhp_radius_mesg* radius_mesg,int flag)
{
	rhp_radius_mesg_priv* radius_mesg_priv = (rhp_radius_mesg_priv*)radius_mesg->priv;
	radius_mesg_priv->is_term_req = (u8)flag;
  RHP_TRC(0,RHPTRCID_RADIUS_MESG_SET_TERMINATION_REQUEST,"xxd",radius_mesg,radius_mesg_priv,flag);
	return;
}

static int _rhp_radius_mesg_attr_match_priv_attr_tag(rhp_radius_attr* radius_attr,char* priv_attr_string_value_tag)
{
	int ret = -ENOENT;
	char* str = NULL;
	int val_len = 0;
	u8* val = radius_attr->ext.basic->get_attr_value(radius_attr,&val_len);

	if( val == NULL ){
		return -ENOENT;
	}

	if( val_len <= strlen(priv_attr_string_value_tag) ){
		return -ENOENT;
	}

	str = (char*)_rhp_malloc(val_len + 1);
	if( str == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}
	memcpy(str,val,val_len);
	str[val_len] = '\0';

	ret = ( strstr(str,priv_attr_string_value_tag) == NULL ? -ENOENT : 0);
	if( str ){
		_rhp_free(str);
	}

	return ret;
}

static int _rhp_radius_mesg_enum_attrs(rhp_radius_mesg* radius_mesg,u8 type,char* priv_attr_string_value_tag,
		int (*callback)(rhp_radius_mesg* radius_mesg,rhp_radius_attr* radius_attr,char* priv_attr_string_value_tag,void* cb_ctx),void* ctx)
{
	int err = -EINVAL;
	rhp_radius_attr* radius_attr = radius_mesg->attr_head;
	int n = 0;

	while( radius_attr ){

		if( !type ||
				(radius_attr->get_attr_type(radius_attr) == type) ){

			if( priv_attr_string_value_tag == NULL ||
					!type ||
					!_rhp_radius_mesg_attr_match_priv_attr_tag(radius_attr,priv_attr_string_value_tag) ){

				err = callback(radius_mesg,radius_attr,priv_attr_string_value_tag,ctx);
				if( err ){
					goto error;
				}
			}

			n++;
		}

		radius_attr = radius_attr->next;
	}

	if( n == 0 ){
		err = -ENOENT;
	}else{
		err = 0;
	}

error:
	RHP_TRC(0,RHPTRCID_RADIUS_MESG_ENUM_ATTRS,"xxLbdsE",radius_mesg,radius_mesg->attr_head,"PROTO_RADIUS_ATTR",type,n,priv_attr_string_value_tag,err);
	return err;
}

static rhp_radius_attr* _rhp_radius_mesg_get_attr(rhp_radius_mesg* radius_mesg,u8 type,char* priv_attr_string_value_tag)
{
	rhp_radius_attr* radius_attr = radius_mesg->attr_head;
	while( radius_attr ){

		if( radius_attr->get_attr_type(radius_attr) == type ){

			if( priv_attr_string_value_tag == NULL ||
					!_rhp_radius_mesg_attr_match_priv_attr_tag(radius_attr,priv_attr_string_value_tag) ){

				break;
			}
		}

		radius_attr = radius_attr->next;
	}
  RHP_TRC(0,RHPTRCID_RADIUS_MESG_GET_ATTR,"xxxLbs",radius_mesg,radius_mesg->attr_head,radius_attr,"PROTO_RADIUS_ATTR",type,priv_attr_string_value_tag);
	return radius_attr;
}

static rhp_radius_attr* _rhp_radius_mesg_get_attr_eap(rhp_radius_mesg* radius_mesg,u8 eap_code,u8 eap_type)
{
	rhp_radius_attr* radius_attr = radius_mesg->attr_head;
	while( radius_attr ){

		if( radius_attr->get_attr_type(radius_attr) == RHP_RADIUS_ATTR_TYPE_EAP &&
				( !eap_code || (radius_attr->ext.eap->get_eap_code(radius_attr) == eap_code) ) &&
				( !eap_type || (radius_attr->ext.eap->get_eap_type(radius_attr) == eap_type) ) ){
			break;
		}

		radius_attr = radius_attr->next;
	}
  RHP_TRC(0,RHPTRCID_RADIUS_MESG_GET_ATTR_EAP,"xxxLbLb",radius_mesg,radius_mesg->attr_head,radius_attr,"PROTO_EAP_CODE",eap_code,"PROTO_EAP_TYPE",eap_type);
	return radius_attr;
}

static rhp_radius_attr* _rhp_radius_mesg_get_attr_vendor_ms(rhp_radius_mesg* radius_mesg,u8 vendor_type)
{
	rhp_radius_attr* radius_attr = radius_mesg->attr_head;
	while( radius_attr ){

		if( radius_attr->get_attr_type(radius_attr) == RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC &&
				radius_attr->get_attr_vendor_id(radius_attr) == RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC_MICROSOFT &&
				radius_attr->ext.ms->get_vendor_type(radius_attr) == vendor_type ){
			break;
		}

		radius_attr = radius_attr->next;
	}
  RHP_TRC(0,RHPTRCID_RADIUS_MESG_GET_ATTR_VENDOR_MS,"xxxLb",radius_mesg,radius_mesg->attr_head,radius_attr,"PROTO_RADIUS_MS_TYPE",vendor_type);
	return radius_attr;
}

static int _rhp_radius_mesg_serialize_alloc_pkt(rhp_radius_mesg* radius_mesg,rhp_radius_session* radius_sess,rhp_packet** pkt_r)
{
	int err = -EINVAL;
  rhp_proto_ether* dmy_ethh;
  union {
  	rhp_proto_ip_v4* v4;
    rhp_proto_ip_v6* v6;
    u8* raw;
  } dmy_iph;
  rhp_proto_udp* dmy_udph;
  rhp_proto_radius* radiush;
  rhp_packet* pkt = NULL;
  rhp_ip_addr nas_addr, server_addr_port;

  RHP_TRC(0,RHPTRCID_RADIUS_MESG_SERIALIZE_ALLOC_PKT,"xxx",radius_mesg,radius_sess,pkt_r);

  {
		memset(&nas_addr,0,sizeof(rhp_ip_addr));
		nas_addr.addr_family = AF_UNSPEC;
		memset(&server_addr_port,0,sizeof(rhp_ip_addr));
		server_addr_port.addr_family = AF_UNSPEC;

		// This may be still null because socket is not open.
		radius_sess->get_nas_addr(radius_sess,&nas_addr);

		radius_sess->get_server_addr(radius_sess,&server_addr_port);
  }


  pkt = rhp_pkt_alloc(RHP_RADIUS_PKT_DEFAULT_SIZE);
  if( pkt == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }

  dmy_ethh = (rhp_proto_ether*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ether));
	memset(dmy_ethh->dst_addr,0,6);
	memset(dmy_ethh->src_addr,0,6);



  if( server_addr_port.addr_family == AF_INET ){

    dmy_ethh->protocol = RHP_PROTO_ETH_IP;

  	pkt->type = RHP_PKT_IPV4_RADIUS;

  	dmy_iph.raw = (u8*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ip_v4));


	  dmy_iph.v4->ver = 4;
	  dmy_iph.v4->ihl = 5;
	  dmy_iph.v4->tos = 0;
	  dmy_iph.v4->total_len = 0;
	  dmy_iph.v4->id = 0;
	  dmy_iph.v4->frag = 0;
	  dmy_iph.v4->ttl = 64;
	  dmy_iph.v4->protocol = RHP_PROTO_IP_UDP;
	  dmy_iph.v4->check_sum = 0;

		// This may be still null because socket is not open.
		if( nas_addr.addr_family != AF_UNSPEC ){
			dmy_iph.v4->src_addr = nas_addr.addr.v4;
		}else{
			dmy_iph.v4->src_addr = 0;
		}

	  dmy_iph.v4->dst_addr = server_addr_port.addr.v4;

  }else if( server_addr_port.addr_family == AF_INET6 ){

    dmy_ethh->protocol = RHP_PROTO_ETH_IPV6;

  	pkt->type = RHP_PKT_IPV6_RADIUS;

		dmy_iph.raw = (u8*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ip_v6));

		dmy_iph.v6->ver = 6;
		dmy_iph.v6->priority = 0;
		dmy_iph.v6->flow_label[0] = 0;
		dmy_iph.v6->flow_label[1] = 0;
		dmy_iph.v6->flow_label[2] = 0;
		dmy_iph.v6->payload_len = 0;
		dmy_iph.v6->next_header = RHP_PROTO_IP_UDP;
		dmy_iph.v6->hop_limit = 64;

		// This may be still null because socket is not open.
		if( nas_addr.addr_family != AF_UNSPEC ){
			memcpy(dmy_iph.v6->src_addr,nas_addr.addr.v6,16);
		}else{
			memset(dmy_iph.v6->src_addr,0,16);
		}

		memcpy(dmy_iph.v6->dst_addr,server_addr_port.addr.v6,16);

  }else{
    RHP_BUG("%d",server_addr_port.addr_family);
    err = -EINVAL;
    goto error;
  }

  {
    dmy_udph = (rhp_proto_udp*)_rhp_pkt_push(pkt,sizeof(rhp_proto_udp));

		dmy_udph->len = 0;
		dmy_udph->check_sum = 0;

		// This may be still null because socket is not open.
		if( nas_addr.addr_family != AF_UNSPEC ){
			dmy_udph->src_port = nas_addr.port;
		}else{
			dmy_udph->src_port = 0;
		}

		dmy_udph->dst_port = server_addr_port.port;
  }


  radiush = (rhp_proto_radius*)_rhp_pkt_push(pkt,sizeof(rhp_proto_radius));

  pkt->l2.eth = dmy_ethh;
	pkt->l3.raw = dmy_iph.raw;
	pkt->l4.udph = dmy_udph;
	pkt->app.raw = (u8*)radiush;

	*pkt_r = pkt;

  RHP_TRC(0,RHPTRCID_RADIUS_MESG_SERIALIZE_ALLOC_PKT_RTRN,"xxx",radius_mesg,radius_sess,pkt);
  return 0;

error:
	if( pkt ){
		rhp_pkt_unhold(pkt);
	}
  RHP_TRC(0,RHPTRCID_RADIUS_MESG_SERIALIZE_ALLOC_PKT_ERR,"xxE",radius_mesg,radius_sess,err);
	return err;
}

static int _rhp_radius_mesg_serialize(rhp_radius_mesg* radius_mesg,rhp_radius_session* radius_sess,rhp_packet** pkt_r)
{
	int err = -EINVAL;
	rhp_radius_session_priv* radius_sess_priv = (rhp_radius_session_priv*)radius_sess->priv;
	rhp_radius_mesg_priv* radius_mesg_priv = (rhp_radius_mesg_priv*)radius_mesg->priv;
	rhp_packet* pkt = NULL;
  rhp_proto_radius* radiush;

  RHP_TRC(0,RHPTRCID_RADIUS_MESG_SERIALIZE,"xxxx",radius_mesg,radius_sess,pkt_r,radius_mesg_priv);

	err = _rhp_radius_mesg_serialize_alloc_pkt(radius_mesg,radius_sess,&pkt);
	if( err ){
		goto error;
	}

	{
		radiush = (rhp_proto_radius*)pkt->app.raw;

		if( radius_mesg_priv->tx_radiush->id == 0 ){
			radiush->id = radius_mesg_priv->tx_radiush->id = ++radius_sess_priv->tx_mesg_id;
		}

		radiush->code = radius_mesg_priv->tx_radiush->code;
	}


  //
  //
  // [CAUTION] rhp_pkt_realloc() may be called. Don't access pointers of dmy_xxxhs,
  //           and radiush any more. Get a new pointer from pkt.
  //
  //
	{
		rhp_radius_attr* radius_attr = radius_mesg->attr_head;
		while( radius_attr ){

			rhp_radius_attr_priv* radius_attr_priv = (rhp_radius_attr_priv*)radius_attr->priv;

			err = radius_attr_priv->ext_serialize(radius_attr,pkt);
			if( err ){
				goto error;
			}

			radius_attr = radius_attr->next;
		}

		radiush->len = htons(radius_mesg_priv->tx_mesg_len);
	}

	{
		if( pkt->type == RHP_PKT_IPV4_RADIUS ){

			// [CAUTION] rhp_pkt_realloc() may be called. Get a new pointer from pkt.
			pkt->l3.iph_v4->total_len
				= htons(sizeof(rhp_proto_ip_v4) + sizeof(rhp_proto_udp) + radius_mesg_priv->tx_mesg_len);

		}else if( pkt->type == RHP_PKT_IPV6_RADIUS ){

			// [CAUTION] rhp_pkt_realloc() may be called. Get a new pointer from pkt.
			pkt->l3.iph_v6->payload_len
				= htons(sizeof(rhp_proto_udp) + radius_mesg_priv->tx_mesg_len);
		}

		// [CAUTION] rhp_pkt_realloc() may be called. Get a new pointer from pkt.
		pkt->l4.udph->len
			= htons(sizeof(rhp_proto_udp) + radius_mesg_priv->tx_mesg_len);
	}


	radius_mesg_priv->tx_pkt_ref = rhp_pkt_hold_ref(pkt);

	rhp_pkt_trace_dump("_rhp_radius_mesg_serialize",pkt);
	*pkt_r = pkt;

  RHP_TRC(0,RHPTRCID_RADIUS_MESG_SERIALIZE_RTRN,"xxxxxda",radius_mesg,radius_sess,radius_mesg_priv,pkt,radius_mesg_priv->tx_pkt_ref,radius_mesg_priv->tx_mesg_len,((((u8*)pkt->l4.udph) + ntohs(pkt->l4.udph->len)) - (u8*)pkt->l2.raw),RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,pkt->l2.raw);
  return 0;

error:
	if( pkt ){
		rhp_pkt_unhold(pkt);
	}
  RHP_TRC(0,RHPTRCID_RADIUS_MESG_SERIALIZE_ERR,"xxxE",radius_mesg,radius_sess,radius_mesg_priv,err);
	return err;
}

static void _rhp_radius_mesg_get_src_addr_port(rhp_radius_mesg* radius_mesg,rhp_ip_addr* addr_port_r)
{
	rhp_radius_mesg_priv* radius_mesg_priv = (rhp_radius_mesg_priv*)radius_mesg->priv;
	rhp_packet* pkt = NULL;

	if( radius_mesg_priv->tx_pkt_ref ){
		pkt = RHP_PKT_REF(radius_mesg_priv->tx_pkt_ref);
	}else if( radius_mesg_priv->rx_pkt_ref ){
		pkt = RHP_PKT_REF(radius_mesg_priv->rx_pkt_ref);
	}

	if( pkt ){

		if( pkt->type == RHP_PKT_IPV4_RADIUS ){
			addr_port_r->addr_family = AF_INET;
			if( pkt->l3.raw ){
				addr_port_r->addr.v4 = pkt->l3.iph_v4->src_addr;
			}else{
				addr_port_r->addr.v4 = 0;
			}
			if( pkt->l4.raw ){
				addr_port_r->port = pkt->l4.udph->src_port;
			}else{
				addr_port_r->port = 0;
			}
		}else if( pkt->type == RHP_PKT_IPV6_RADIUS ){
			addr_port_r->addr_family = AF_INET6;
			if( pkt->l3.raw ){
				memcpy(addr_port_r->addr.v6,pkt->l3.iph_v6->src_addr,16);
			}else{
				memset(addr_port_r->addr.v6,0,16);
			}
			if( pkt->l4.raw ){
				addr_port_r->port = pkt->l4.udph->src_port;
			}else{
				addr_port_r->port = 0;
			}
		}
	}

	return;
}

static void _rhp_radius_mesg_get_dst_addr_port(rhp_radius_mesg* radius_mesg,rhp_ip_addr* addr_port_r)
{
	rhp_radius_mesg_priv* radius_mesg_priv = (rhp_radius_mesg_priv*)radius_mesg->priv;
	rhp_packet* pkt = NULL;

	if( radius_mesg_priv->tx_pkt_ref ){
		pkt = RHP_PKT_REF(radius_mesg_priv->tx_pkt_ref);
	}else if( radius_mesg_priv->rx_pkt_ref ){
		pkt = RHP_PKT_REF(radius_mesg_priv->rx_pkt_ref);
	}

	if( pkt ){

		if( pkt->type == RHP_PKT_IPV4_RADIUS ){
			addr_port_r->addr_family = AF_INET;
			if( pkt->l3.raw ){
				addr_port_r->addr.v4 = pkt->l3.iph_v4->dst_addr;
			}else{
				addr_port_r->addr.v4 = 0;
			}
			if( pkt->l4.raw ){
				addr_port_r->port = pkt->l4.udph->dst_port;
			}else{
				addr_port_r->port = 0;
			}
		}else if( pkt->type == RHP_PKT_IPV6_RADIUS ){
			addr_port_r->addr_family = AF_INET6;
			if( pkt->l3.raw ){
				memcpy(addr_port_r->addr.v6,pkt->l3.iph_v6->dst_addr,16);
			}else{
				memset(addr_port_r->addr.v6,0,16);
			}
			if( pkt->l4.raw ){
				addr_port_r->port = pkt->l4.udph->dst_port;
			}else{
				addr_port_r->port = 0;
			}
		}
	}

	return;
}



static void _rhp_radius_free_mesg(rhp_radius_mesg* radius_mesg)
{
	rhp_radius_mesg_priv* radius_mesg_priv = (rhp_radius_mesg_priv*)radius_mesg->priv;

  RHP_TRC(0,RHPTRCID_RADIUS_FREE_MESG,"xxxxxx",radius_mesg,radius_mesg_priv,radius_mesg_priv->tx_radiush,radius_mesg->attr_head,RHP_PKT_REF(radius_mesg_priv->tx_pkt_ref),RHP_PKT_REF(radius_mesg_priv->rx_pkt_ref ));


	if( radius_mesg_priv->tx_radiush ){
		_rhp_free(radius_mesg_priv->tx_radiush);
	}

  if( radius_mesg_priv->tx_pkt_ref ){
    rhp_pkt_unhold(radius_mesg_priv->tx_pkt_ref);
  }

  if( radius_mesg_priv->rx_pkt_ref ){
    rhp_pkt_unhold(radius_mesg_priv->rx_pkt_ref);
  }

  {
  	rhp_radius_attr* radius_attr = radius_mesg->attr_head;
  	while( radius_attr ){

  		rhp_radius_attr* radius_attr_n = radius_attr->next;
  		rhp_radius_attr_destroy(radius_attr);
  		radius_attr = radius_attr_n;
  	}
  }

  if( radius_mesg_priv->rx_accept_attrs ){
  	_rhp_radius_access_accept_attrs_free(radius_mesg_priv->rx_accept_attrs);
  }

  _rhp_atomic_destroy(&(radius_mesg->refcnt));

  _rhp_free_zero(radius_mesg_priv,sizeof(rhp_radius_mesg_priv));
  _rhp_free_zero(radius_mesg,sizeof(radius_mesg));

  RHP_TRC(0,RHPTRCID_RADIUS_FREE_MESG_RTRN,"xx",radius_mesg,radius_mesg_priv);
  return;
}

void rhp_radius_free_mesg(rhp_radius_mesg* radius_mesg)
{
	_rhp_radius_free_mesg(radius_mesg);
}


static rhp_radius_access_accept_attrs* _rhp_radius_mesg_get_access_accept_attributes(rhp_radius_mesg* radius_mesg)
{
	rhp_radius_mesg_priv* radius_mesg_priv = (rhp_radius_mesg_priv*)radius_mesg->priv;
	rhp_radius_access_accept_attrs* rx_accept_attrs = radius_mesg_priv->rx_accept_attrs;

	radius_mesg_priv->rx_accept_attrs = NULL;
	return rx_accept_attrs;
}

static unsigned long _rhp_radius_mesg_get_realm_id_by_access_accept_attrs(rhp_radius_mesg* radius_mesg)
{
	return ((rhp_radius_mesg_priv*)radius_mesg->priv)->rebound_rlm_id;
}


static rhp_radius_mesg* _rhp_radius_alloc_mesg(int for_tx)
{
	rhp_radius_mesg* radius_mesg = NULL;

  RHP_TRC(0,RHPTRCID_RADIUS_ALLOC_MESG,"d",for_tx);

	radius_mesg = (rhp_radius_mesg*)_rhp_malloc(sizeof(rhp_radius_mesg));
	if( radius_mesg == NULL ){
		RHP_BUG("");
		goto error;
	}

	memset(radius_mesg,0,sizeof(rhp_radius_mesg));


	radius_mesg->priv = (void*)_rhp_malloc(sizeof(rhp_radius_mesg_priv));
	if( radius_mesg->priv == NULL ){
		RHP_BUG("");
		_rhp_free(radius_mesg);
		goto error;
	}

	memset(radius_mesg->priv,0,sizeof(rhp_radius_mesg_priv));


	if( for_tx ){

		((rhp_radius_mesg_priv*)radius_mesg->priv)->tx_radiush = (rhp_proto_radius*)_rhp_malloc(sizeof(rhp_proto_radius));
		if( ((rhp_radius_mesg_priv*)radius_mesg->priv)->tx_radiush == NULL ){
			RHP_BUG("");
			_rhp_free(radius_mesg->priv);
			_rhp_free(radius_mesg);
			goto error;
		}

		memset(((rhp_radius_mesg_priv*)radius_mesg->priv)->tx_radiush,0,sizeof(rhp_proto_radius));
	}

	radius_mesg->tag[0] = '#';
	radius_mesg->tag[1] = 'R';
	radius_mesg->tag[2] = 'M';
	radius_mesg->tag[3] = 'G';

	radius_mesg->get_code = _rhp_radius_mesg_get_code;
	radius_mesg->set_code = _rhp_radius_mesg_set_code;
	radius_mesg->get_id = _rhp_radius_mesg_get_id;
	radius_mesg->set_id = _rhp_radius_mesg_set_id;
	radius_mesg->get_len = _rhp_radius_mesg_get_len;
	radius_mesg->get_authenticator = _rhp_radius_mesg_get_authenticator;
	radius_mesg->set_authenticator = _rhp_radius_mesg_set_authenticator;
	radius_mesg->put_attr = _rhp_radius_mesg_put_attr;
	radius_mesg->put_attr_head = _rhp_radius_mesg_put_attr_head;
	radius_mesg->get_attr = _rhp_radius_mesg_get_attr;
	radius_mesg->get_attr_eap = _rhp_radius_mesg_get_attr_eap;
	radius_mesg->get_attr_vendor_ms = _rhp_radius_mesg_get_attr_vendor_ms;
	radius_mesg->set_termination_request = _rhp_radius_mesg_set_termination_request;
	radius_mesg->get_access_accept_attributes = _rhp_radius_mesg_get_access_accept_attributes;
	radius_mesg->get_realm_id_by_access_accept_attrs = _rhp_radius_mesg_get_realm_id_by_access_accept_attrs;
	radius_mesg->enum_attrs = _rhp_radius_mesg_enum_attrs;
	radius_mesg->get_src_addr_port = _rhp_radius_mesg_get_src_addr_port;
	radius_mesg->get_dst_addr_port = _rhp_radius_mesg_get_dst_addr_port;


	((rhp_radius_mesg_priv*)radius_mesg->priv)->tag[0] = '#';
	((rhp_radius_mesg_priv*)radius_mesg->priv)->tag[1] = 'R';
	((rhp_radius_mesg_priv*)radius_mesg->priv)->tag[2] = 'M';
	((rhp_radius_mesg_priv*)radius_mesg->priv)->tag[3] = 'I';

	((rhp_radius_mesg_priv*)radius_mesg->priv)->serialize = _rhp_radius_mesg_serialize;


  _rhp_atomic_init(&(radius_mesg->refcnt));
  _rhp_atomic_set(&(radius_mesg->refcnt),1);

  RHP_TRC(0,RHPTRCID_RADIUS_ALLOC_MESG_RTRN,"xxx",radius_mesg,radius_mesg->priv,((rhp_radius_mesg_priv*)radius_mesg->priv)->tx_radiush);
	return radius_mesg;

error:
	RHP_TRC(0,RHPTRCID_RADIUS_ALLOC_MESG_ERR,"d",for_tx);
	return NULL;
}


rhp_radius_mesg* rhp_radius_new_mesg_tx(u8 code,u8 id)
{
	rhp_radius_mesg* radius_mesg = _rhp_radius_alloc_mesg(1);
	rhp_radius_mesg_priv* radius_mesg_priv;

	RHP_TRC(0,RHPTRCID_RADIUS_NEW_MESG_TX,"bbx",code,id,radius_mesg);

	if( radius_mesg == NULL ){
		RHP_BUG("");
		return NULL;
	}

	radius_mesg_priv = (rhp_radius_mesg_priv*)radius_mesg->priv;


	radius_mesg_priv->tx_radiush->code = code;
	radius_mesg_priv->tx_radiush->id = id;

	radius_mesg_priv->tx_mesg_len = sizeof(rhp_proto_radius);

	RHP_TRC(0,RHPTRCID_RADIUS_NEW_MESG_TX_RTRN,"bbxx",code,id,radius_mesg,radius_mesg_priv);
	return radius_mesg;
}


int rhp_radius_new_mesg_rx(rhp_radius_session* radius_sess,rhp_packet* pkt,rhp_radius_mesg** radius_mesg_r)
{
	int err = -EINVAL;
	rhp_proto_radius* radiush = (rhp_proto_radius*)pkt->app.raw;
	int radius_len = 0;
	rhp_radius_mesg* radius_mesg = NULL;
	rhp_radius_mesg_priv* radius_mesg_priv = NULL;
	int attr_num = 0;

	RHP_TRC(0,RHPTRCID_RADIUS_NEW_MESG_RX,"xxxa",radius_sess,pkt,radius_mesg_r,((((u8*)pkt->l4.udph) + ntohs(pkt->l4.udph->len)) - (u8*)pkt->l2.raw),RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,pkt->l2.raw);

	if( radiush == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	if( (u8*)(radiush + 1) >= pkt->end ){
		err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
		RHP_TRC(0,RHPTRCID_RADIUS_NEW_MESG_RX_INVALID_LEN_1,"xxxx",radius_sess,pkt,(u8*)(radiush + 1),pkt->end);
		goto error;
	}

	radius_len = ntohs(radiush->len);
	if( radius_len < (int)sizeof(rhp_proto_radius) ||
			radius_len < rhp_gcfg_radius_min_pkt_len ||
			radius_len > rhp_gcfg_radius_max_pkt_len ||
			((u8*)radiush) + radius_len > pkt->end ){
		err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
		RHP_TRC(0,RHPTRCID_RADIUS_NEW_MESG_RX_INVALID_LEN_2,"xxxxd",radius_sess,pkt,(((u8*)radiush) + radius_len),pkt->end,radius_len);
		goto error;
	}


  pkt->data = pkt->app.raw;
	if( _rhp_pkt_pull(pkt,sizeof(rhp_proto_radius)) == NULL ){
		RHP_BUG("");
		RHP_TRC(0,RHPTRCID_RADIUS_NEW_MESG_RX_INVALID_PKT_APP_RAW_PT,"xxxxd",radius_sess,pkt,radiush,pkt->app.raw,sizeof(rhp_proto_radius));
		goto error;
	}


	if( !rhp_radius_session_rx_supported_code(radius_sess->usage,radiush->code) ){
		err = RHP_STATUS_RADIUS_UNSUP_MESG_CODE;
		RHP_TRC(0,RHPTRCID_RADIUS_NEW_MESG_RX_NOT_INTERESTED_CODE,"xxxb",radius_sess,pkt,radiush,radiush->code);
		goto error;
	}


	radius_mesg = _rhp_radius_alloc_mesg(0);
	if( radius_mesg == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	radius_mesg_priv = (rhp_radius_mesg_priv*)radius_mesg->priv;

	if( radiush->code == RHP_RADIUS_CODE_ACCESS_ACCEPT ){

		radius_mesg_priv->rx_accept_attrs = rhp_radius_alloc_access_accept_attrs();
		if( radius_mesg_priv->rx_accept_attrs == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		radius_sess->get_nas_addr(radius_sess,
				&(radius_mesg_priv->rx_accept_attrs->orig_nas_addr));
	}

	radius_mesg_priv->rx_pkt_ref = rhp_pkt_hold_ref(pkt);


	{
		rhp_proto_radius_attr* radius_attrh = (rhp_proto_radius_attr*)pkt->data;
		rhp_radius_attr* radius_attr_eap = NULL;
		int rem = radius_len - sizeof(rhp_proto_radius);

		//
		// radius_attrh's buf is not safe here.
		//

		while( rem > 0 && (u8*)radius_attrh < pkt->end ){

			rhp_radius_attr* radius_attr;

	    if( _rhp_pkt_try_pull(pkt,sizeof(rhp_proto_radius_attr)) ){
	      err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
	  		RHP_TRC(0,RHPTRCID_RADIUS_NEW_MESG_RX_INVALID_LEN_3,"xxx",radius_sess,pkt,radius_mesg_priv);
	      goto error;
	    }

	    if( radius_attrh->len < (int)sizeof(rhp_proto_radius_attr) ||
	    		_rhp_pkt_try_pull(pkt,radius_attrh->len) ){
	      err = RHP_STATUS_INVALID_MSG;
	  		RHP_TRC(0,RHPTRCID_RADIUS_NEW_MESG_RX_INVALID_LEN_4,"xxxdd",radius_sess,pkt,radius_mesg_priv,radius_attrh->len,sizeof(rhp_proto_radius_attr));
	      goto error;
	    }


	    if( radius_attrh->type == RHP_RADIUS_ATTR_TYPE_EAP && radius_attr_eap ){
				radius_attr = radius_attr_eap;
			}else{
				radius_attr = NULL;
			}

	    err = rhp_radius_new_attr_rx(radius_sess,radius_mesg,radius_attrh,radius_attrh->len,&radius_attr);
	    if( err ){

	  		RHP_TRC(0,RHPTRCID_RADIUS_NEW_MESG_RX_PARSE_ATTR_ERR,"xxxE",radius_sess,pkt,radius_mesg_priv,err);

	    	if( err == RHP_STATUS_RADIUS_UNKNOWN_ATTR ){

	    		if( _rhp_pkt_pull(pkt,radius_attrh->len) != NULL ){
	  	  		RHP_TRC(0,RHPTRCID_RADIUS_NEW_MESG_RX_PARSE_ATTR_ERR_IGNORED,"xxxd",radius_sess,pkt,radius_mesg_priv,radius_attrh->len);
	    			err = 0;
	    			goto next;
	    		}
	    	}

	    	goto error;
	    }

	    if( radius_attr && (radius_attr_eap != radius_attr) ){
	    	radius_mesg->put_attr(radius_mesg,radius_attr);
	    }

	    if( radius_attr_eap == NULL &&
	    		radius_attrh->type == RHP_RADIUS_ATTR_TYPE_EAP ){ // For EAP defrag.
	    	radius_attr_eap = radius_attr;
	    }

next:
			rem -= radius_attrh->len;
			radius_attrh = (rhp_proto_radius_attr*)pkt->data;
			attr_num++;
		}

		if( radiush->code != RHP_RADIUS_CODE_ACCESS_REJECT &&
				radiush->code != RHP_RADIUS_CODE_ACCT_RESPONSE &&
				attr_num < 1 ){
			err = RHP_STATUS_RADIUS_MESG_NO_ATTRS_FOUND;
			RHP_TRC(0,RHPTRCID_RADIUS_NEW_MESG_RX_NO_ATTRS_FOUND,"xxx",radius_sess,pkt,radius_mesg_priv);
			goto error;
		}
	}

	*radius_mesg_r = radius_mesg;

	RHP_TRC(0,RHPTRCID_RADIUS_NEW_MESG_RX_RTRN,"xxxxdx",radius_sess,pkt,radius_mesg_priv,radius_mesg_priv->rx_pkt_ref,attr_num,radius_mesg);
	return 0;

error:
	if( radius_mesg ){
		rhp_radius_mesg_unhold(radius_mesg);
	}
	RHP_TRC(0,RHPTRCID_RADIUS_NEW_MESG_RX_ERR,"xxxE",radius_sess,pkt,radius_mesg_priv,err);
	return err;
}

#ifndef RHP_REFCNT_DEBUG

void rhp_radius_mesg_hold(rhp_radius_mesg* radius_mesg)
{
  _rhp_atomic_inc(&(radius_mesg->refcnt));
  RHP_TRC(0,RHPTRCID_RADIUS_MESG_HOLD,"xd",radius_mesg,rhp_atomic_read(&(radius_mesg->refcnt)));
}

void rhp_radius_mesg_unhold(rhp_radius_mesg* radius_mesg)
{
#ifdef  RHP_CK_OBJ_TAG_GDB
	radius_mesg = RHP_CK_OBJTAG("#RMG",radius_mesg);
#endif // RHP_CK_OBJ_TAG_GDB

  RHP_TRC(0,RHPTRCID_RADIUS_MESG_UNHOLD,"xd",radius_mesg,rhp_atomic_read(&(radius_mesg->refcnt)));

  if( _rhp_atomic_dec_and_test(&(radius_mesg->refcnt)) ){

    RHP_TRC(0,RHPTRCID_RADIUS_MESG_UNHOLD_DESTROY,"xd",radius_mesg,rhp_atomic_read(&(radius_mesg->refcnt)));
  	_rhp_radius_free_mesg(radius_mesg);
  }
}
#else // RHP_REFCNT_DEBUG
//
// See rhp_radius_priv.h
//
#endif // RHP_REFCNT_DEBUG


int rhp_radius_mesg_check(rhp_packet *rx_pkt)
{
	int err = -EINVAL;
	rhp_proto_radius* rx_radiush = (rhp_proto_radius*)rx_pkt->app.raw;
	u8* endp = rx_pkt->end;
	int radius_len = 0;

	RHP_TRC(0,RHPTRCID_RADIUS_MESG_CHECK,"x",rx_pkt);

	if( (u8*)(rx_radiush + 1) >= endp ){
		err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
		RHP_TRC(0,RHPTRCID_RADIUS_MESG_CHECK_INVALID_LEN_1,"xxx",rx_pkt,(u8*)(rx_radiush + 1),endp);
		goto error;
	}

	radius_len = ntohs(rx_radiush->len);
	if( radius_len < (int)sizeof(rhp_proto_radius) ||
			radius_len < rhp_gcfg_radius_min_pkt_len ||
			radius_len > rhp_gcfg_radius_max_pkt_len ||
			((u8*)rx_radiush) + radius_len > endp ){
		err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
		RHP_TRC(0,RHPTRCID_RADIUS_MESG_CHECK_INVALID_LEN_2,"xdxx",rx_pkt,radius_len,(((u8*)rx_radiush) + radius_len),endp);
		goto error;
	}

	RHP_TRC_FREQ(0,RHPTRCID_RADIUS_MESG_CHECK_RADIUS_DATA,"xp",rx_pkt,radius_len,(u8*)rx_radiush);

	{
		rhp_proto_radius_attr* radius_attrh = (rhp_proto_radius_attr*)(rx_radiush + 1);
		int verify_ok = 0;
		int rem = radius_len - sizeof(rhp_proto_radius);

		while( rem > 0 && (u8*)radius_attrh < endp ){

			if( (u8*)(radius_attrh + 1) > endp ){
				err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
				RHP_TRC(0,RHPTRCID_RADIUS_MESG_CHECK_INVALID_LEN_3,"xxxxx",rx_pkt,(u8*)rx_radiush,endp,radius_attrh,(u8*)(radius_attrh + 1));
				goto error;
			}

			if( ((u8*)radius_attrh) + radius_attrh->len > endp ){
				err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
				RHP_TRC(0,RHPTRCID_RADIUS_MESG_CHECK_INVALID_LEN_4,"xxxxxd",rx_pkt,(u8*)rx_radiush,endp,radius_attrh,((u8*)radius_attrh) + radius_attrh->len,radius_attrh->len);
				goto error;
			}

			if( radius_attrh->len < sizeof(rhp_proto_radius_attr) ){
				err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
				RHP_TRC(0,RHPTRCID_RADIUS_MESG_CHECK_INVALID_LEN_5,"xxxxdd",rx_pkt,(u8*)rx_radiush,endp,radius_attrh,radius_attrh->len,sizeof(rhp_proto_radius_attr));
				goto error;
			}

			if( radius_attrh->type == RHP_RADIUS_ATTR_TYPE_MESG_AUTH ){

				if( radius_attrh->len != 18 ){
					err = RHP_STATUS_RADIUS_INVALID_MESG_AUTHENTICATOR_LEN;
					RHP_TRC(0,RHPTRCID_RADIUS_MESG_CHECK_INVALID_LEN_6,"xxxxd",rx_pkt,(u8*)rx_radiush,endp,radius_attrh,radius_attrh->len);
					goto error;
				}

				verify_ok |= 0x1;

			}else	if( radius_attrh->type == RHP_RADIUS_ATTR_TYPE_EAP ){

				if( radius_attrh->len < sizeof(rhp_proto_radius_attr) + sizeof(rhp_proto_eap) ){
					err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
					RHP_TRC(0,RHPTRCID_RADIUS_MESG_CHECK_INVALID_LEN_7,"xxxxddd",rx_pkt,(u8*)rx_radiush,endp,radius_attrh,radius_attrh->len,sizeof(rhp_proto_radius_attr),sizeof(rhp_proto_eap));
					goto error;
				}

				verify_ok |= 0x2;
			}

			rem -= radius_attrh->len;
			radius_attrh = (rhp_proto_radius_attr*)(((u8*)radius_attrh) + radius_attrh->len);
		}

		if( rx_radiush->code != RHP_RADIUS_CODE_ACCESS_REJECT &&
				rx_radiush->code != RHP_RADIUS_CODE_ACCT_RESPONSE &&
				verify_ok != 0x3 ){
			RHP_TRC(0,RHPTRCID_RADIUS_MESG_CHECK_SOME_ATTRS_NOT_FOUND_ERR,"xd",rx_pkt,verify_ok);
			err = RHP_STATUS_RADIUS_INVALID_ATTR;
			goto error;
		}
	}

	RHP_TRC(0,RHPTRCID_RADIUS_MESG_CHECK_RTRN,"x",rx_pkt);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_RADIUS_MESG_CHECK_ERR,"xE",rx_pkt,err);
	return err;
}

