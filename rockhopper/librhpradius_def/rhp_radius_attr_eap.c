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


static u8 _rhp_radius_attr_eap_get_eap_code(rhp_radius_attr* radius_attr)
{
	rhp_radius_attr_eap* radius_attr_eap = radius_attr->ext.eap;
	rhp_radius_attr_priv* radius_attr_priv = (rhp_radius_attr_priv*)radius_attr->priv;
	u8 eap_code = 0;

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_EAP_GET_EAP_CODE,"xxxxx",radius_attr,radius_attr_priv,radius_attr_eap,radius_attr_priv->eap_attrh_rx_defrag,radius_attr_eap->eap_packet);

	if( radius_attr_priv->eap_attrh_rx_defrag ){

		eap_code = radius_attr_priv->eap_attrh_rx_defrag->code;

	}else{

		if( radius_attr_eap->eap_packet ){

			eap_code = radius_attr_eap->eap_packet->code;
		}
	}

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_EAP_GET_EAP_CODE_RTRN,"xb",radius_attr,eap_code);
	return eap_code;
}

static u8 _rhp_radius_attr_eap_get_eap_type(rhp_radius_attr* radius_attr)
{
	rhp_radius_attr_eap* radius_attr_eap = radius_attr->ext.eap;
	rhp_radius_attr_priv* radius_attr_priv = (rhp_radius_attr_priv*)radius_attr->priv;
	rhp_proto_eap* eaph = NULL;
	u8 eap_type = 0;

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_EAP_GET_EAP_TYPE,"xxxxx",radius_attr,radius_attr_priv,radius_attr_eap,radius_attr_priv->eap_attrh_rx_defrag,radius_attr_eap->eap_packet);

	if( radius_attr_priv->eap_attrh_rx_defrag ){

		eaph = radius_attr_priv->eap_attrh_rx_defrag;

	}else{

		eaph = radius_attr_eap->eap_packet;
	}

	if( eaph ){

		if( eaph->code == RHP_PROTO_EAP_CODE_REQUEST ){

			eap_type = ((rhp_proto_eap_request*)eaph)->type;

		}else if( eaph->code == RHP_PROTO_EAP_CODE_RESPONSE ){

			eap_type = ((rhp_proto_eap_response*)eaph)->type;
		}
	}

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_EAP_GET_EAP_TYPE_RTRN,"xbb",radius_attr,eap_type,(eaph ? eaph->code : 0));
	return eap_type;
}

static int _rhp_radius_attr_eap_set_eap_packet(
		rhp_radius_attr* radius_attr,u8 packet_len,rhp_proto_eap* packet)
{
	rhp_radius_attr_eap* radius_attr_eap = radius_attr->ext.eap;
	rhp_proto_eap* new_buf = NULL;

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_EAP_SET_EAP_PACKET,"xxp",radius_attr,radius_attr_eap,(int)packet_len,(u8*)packet);

	if( packet ){

		new_buf = (rhp_proto_eap*)_rhp_malloc(packet_len);
		if( new_buf == NULL ){
			RHP_BUG("");
			return -ENOMEM;
		}

		memcpy(new_buf,packet,packet_len);
	}

	if( radius_attr_eap->eap_packet ){
		_rhp_free_zero(radius_attr_eap->eap_packet,radius_attr_eap->eap_packet_len);
	}

	radius_attr_eap->eap_packet = new_buf;
	radius_attr_eap->eap_packet_len = packet_len;

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_EAP_SET_EAP_PACKET_RTRN,"xp",radius_attr,(int)radius_attr_eap->eap_packet_len,(u8*)radius_attr_eap->eap_packet);
	return 0;
}

static rhp_proto_eap* _rhp_radius_attr_eap_get_eap_packet(rhp_radius_attr* radius_attr,int* packet_len_r)
{
	rhp_radius_attr_eap* radius_attr_eap = radius_attr->ext.eap;
	rhp_radius_attr_priv* radius_attr_priv = (rhp_radius_attr_priv*)radius_attr->priv;
	rhp_proto_eap* ret = NULL;
	int ret_len = 0;

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_EAP_GET_EAP_PACKET,"xxxxxx",radius_attr,radius_attr_priv,radius_attr_eap,packet_len_r,radius_attr_priv->eap_attrh_rx_defrag,radius_attr_eap->eap_packet);

	if( radius_attr_priv->eap_attrh_rx_defrag ){

		ret_len = radius_attr_priv->eap_attrh_rx_defrag_len;
		ret = radius_attr_priv->eap_attrh_rx_defrag;

	}else{

		ret_len = radius_attr_eap->eap_packet_len;
		ret = radius_attr_eap->eap_packet;
	}

	*packet_len_r = ret_len;

	RHP_TRC(0,RHPTRCID_RADIUS_ATTR_EAP_GET_EAP_PACKET_RTRN,"xp",radius_attr,ret_len,(u8*)ret);
	return ret;
}

static rhp_radius_attr_eap* _rhp_radius_attr_eap_alloc()
{
	rhp_radius_attr_eap* radius_attr_eap = (rhp_radius_attr_eap*)_rhp_malloc(sizeof(rhp_radius_attr_eap));

	if( radius_attr_eap == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(radius_attr_eap,0,sizeof(rhp_radius_attr_eap));

	radius_attr_eap->get_eap_code = _rhp_radius_attr_eap_get_eap_code;
	radius_attr_eap->get_eap_type = _rhp_radius_attr_eap_get_eap_type;
	radius_attr_eap->set_eap_packet = _rhp_radius_attr_eap_set_eap_packet;
	radius_attr_eap->get_eap_packet = _rhp_radius_attr_eap_get_eap_packet;

	RHP_TRC(0,RHPTRCID_RADIUS_ATTR_EAP_ALLOC,"x",radius_attr_eap);
	return radius_attr_eap;
}

static int _rhp_radius_attr_eap_ext_serialize(rhp_radius_attr* radius_attr,rhp_packet* pkt)
{
	rhp_radius_attr_eap* radius_attr_eap = radius_attr->ext.eap;

	RHP_TRC(0,RHPTRCID_RADIUS_ATTR_EAP_EXT_SERIALIZE,"xxxx",radius_attr,radius_attr_eap,pkt,radius_attr_eap->eap_packet);

	if( radius_attr_eap->eap_packet ){

		u8* cur = (u8*)radius_attr_eap->eap_packet;
		int cur_rem = radius_attr_eap->eap_packet_len;
    rhp_proto_radius_attr* p;
    int i = 0;

    while( cur_rem > 0 ){

    	int attr_len;

    	if( cur_rem > RHP_RADIUS_ATTR_VAL_MAX_LEN ){
    		attr_len = RHP_RADIUS_ATTR_VAL_MAX_LEN;
    	}else{
    		attr_len = cur_rem;
    	}

      p = (rhp_proto_radius_attr*)rhp_pkt_expand_tail(pkt,
      			(attr_len + (int)sizeof(rhp_proto_radius_attr)));
      if( p == NULL ){
        RHP_BUG("");
        return -ENOMEM;
      }

      p->len = attr_len + sizeof(rhp_proto_radius_attr);
      p->type = radius_attr->get_attr_type(radius_attr);
      memcpy((p + 1),cur,attr_len);

      ((rhp_radius_mesg_priv*)radius_attr->radius_mesg->priv)->tx_mesg_len += attr_len + (int)sizeof(rhp_proto_radius_attr);

    	RHP_TRC(0,RHPTRCID_RADIUS_ATTR_EAP_EXT_SERIALIZE_ATTR,"xdddp",radius_attr,i,cur_rem,((rhp_radius_mesg_priv*)radius_attr->radius_mesg->priv)->tx_mesg_len,p->len,(u8*)p);

      cur += attr_len;
      cur_rem -= attr_len;
      i++;
    }

  	RHP_TRC(0,RHPTRCID_RADIUS_ATTR_EAP_EXT_SERIALIZE_RTRN,"x",radius_attr);
    return 0;
  }

	RHP_TRC(0,RHPTRCID_RADIUS_ATTR_EAP_EXT_SERIALIZE_ERR,"x",radius_attr);
  return -EINVAL;
}

static void _rhp_radius_attr_eap_ext_destructor(rhp_radius_attr* radius_attr)
{
	rhp_radius_attr_eap* radius_attr_eap = radius_attr->ext.eap;
	rhp_radius_attr_priv* radius_attr_priv = (rhp_radius_attr_priv*)radius_attr->priv;

	RHP_TRC(0,RHPTRCID_RADIUS_ATTR_EAP_EXT_DESTRUCTOR,"xxxxx",radius_attr,radius_attr_priv,radius_attr_eap,radius_attr_eap->eap_packet,radius_attr_priv->eap_attrh_rx_defrag);

	if( radius_attr_eap->eap_packet ){
		_rhp_free_zero(radius_attr_eap->eap_packet,radius_attr_eap->eap_packet_len);
	}

	if( radius_attr_priv->eap_attrh_rx_defrag ){
		_rhp_free_zero(radius_attr_priv->eap_attrh_rx_defrag,radius_attr_priv->eap_attrh_rx_defrag_len);
	}

	return;
}


int rhp_radius_attr_eap_new_rx(rhp_radius_mesg* radius_mesg,u8 attr_type,u32 vendor_id,
								rhp_proto_radius_attr* radius_attrh,int radius_attr_len,rhp_radius_attr* radius_attr)
{
  int err = 0;
  rhp_radius_attr_eap* radius_attr_eap;
	rhp_radius_attr_priv* radius_attr_priv = (rhp_radius_attr_priv*)radius_attr->priv;
  rhp_packet* rx_pkt = RHP_PKT_REF(((rhp_radius_mesg_priv*)radius_mesg->priv)->rx_pkt_ref);
  rhp_proto_eap* eaph;
  int eap_len;

	RHP_TRC(0,RHPTRCID_RADIUS_ATTR_EAP_NEW_RX,"xbupxxx",radius_mesg,attr_type,vendor_id,radius_attr_len,(u8*)radius_attrh,radius_attr,radius_attr_priv->eap_attrh_rx_defrag,rx_pkt);

  if( radius_attr_priv->eap_attrh_rx_defrag == NULL ){

		if( radius_attr_len < (int)sizeof(rhp_proto_radius_attr) + (int)sizeof(rhp_proto_eap) ){
			err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
			RHP_TRC(0,RHPTRCID_RADIUS_ATTR_EAP_NEW_RX_INVALID_MESG_LEN_1,"xddd",radius_mesg,radius_attr_len,sizeof(rhp_proto_radius_attr),sizeof(rhp_proto_eap));
			goto error;
		}

		eaph = (rhp_proto_eap*)(radius_attrh + 1);
		eap_len = ntohs(eaph->len);

		if( (eaph->code == RHP_PROTO_EAP_CODE_REQUEST || eaph->code == RHP_PROTO_EAP_CODE_RESPONSE) &&
				eap_len < (int)sizeof(rhp_proto_eap_request) ){
			err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
			RHP_TRC(0,RHPTRCID_RADIUS_ATTR_EAP_NEW_RX_INVALID_MESG_LEN_2,"xdd",radius_mesg,eap_len,sizeof(rhp_proto_eap_request));
			goto error;
		}


		radius_attr_priv->eap_attrh_rx_defrag_len = radius_attr_len - sizeof(rhp_proto_radius_attr);
		radius_attr_priv->eap_attrh_rx_defrag = (rhp_proto_eap*)_rhp_malloc(radius_attr_priv->eap_attrh_rx_defrag_len);
		if( radius_attr_priv->eap_attrh_rx_defrag == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			radius_attr_priv->eap_attrh_rx_defrag_len = 0;
			goto error;
		}
		memcpy(radius_attr_priv->eap_attrh_rx_defrag,eaph,radius_attr_priv->eap_attrh_rx_defrag_len);

		radius_attr_eap = _rhp_radius_attr_eap_alloc();
		if( radius_attr_eap == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}

		radius_attr->ext.eap = radius_attr_eap;
		((rhp_radius_attr_priv*)radius_attr->priv)->ext_serialize = _rhp_radius_attr_eap_ext_serialize;
		((rhp_radius_attr_priv*)radius_attr->priv)->ext_destructor = _rhp_radius_attr_eap_ext_destructor;

  }else{

  	int exp_len;
  	u8* exp_buf;

		if( radius_attr_len < (int)sizeof(rhp_proto_radius_attr) ){
			err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
			RHP_TRC(0,RHPTRCID_RADIUS_ATTR_EAP_NEW_RX_INVALID_MESG_LEN_3,"xdd",radius_mesg,radius_attr_len,sizeof(rhp_proto_radius_attr));
			goto error;
		}

		eaph = radius_attr_priv->eap_attrh_rx_defrag;
		eap_len = ntohs(eaph->len);


		exp_len = radius_attr_priv->eap_attrh_rx_defrag_len + (radius_attr_len - sizeof(rhp_proto_radius_attr));

		if( exp_len > eap_len ){
			err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
			RHP_TRC(0,RHPTRCID_RADIUS_ATTR_EAP_NEW_RX_INVALID_MESG_LEN_4,"xddddd",radius_mesg,exp_len,eap_len,radius_attr_priv->eap_attrh_rx_defrag_len,radius_attr_len,sizeof(rhp_proto_radius_attr));
			goto error;
		}


		exp_buf = (u8*)_rhp_malloc(exp_len);
		if( exp_buf == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
		memcpy(exp_buf,radius_attr_priv->eap_attrh_rx_defrag,radius_attr_priv->eap_attrh_rx_defrag_len);
		memcpy((exp_buf + radius_attr_priv->eap_attrh_rx_defrag_len),
				(u8*)(radius_attrh + 1),(radius_attr_len - sizeof(rhp_proto_radius_attr)));

		_rhp_free_zero(radius_attr_priv->eap_attrh_rx_defrag,radius_attr_priv->eap_attrh_rx_defrag_len);

		radius_attr_priv->eap_attrh_rx_defrag = (rhp_proto_eap*)exp_buf;
		radius_attr_priv->eap_attrh_rx_defrag_len = exp_len;
  }


	if( _rhp_pkt_pull(rx_pkt,radius_attr_len) == NULL ){
		err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
		RHP_TRC(0,RHPTRCID_RADIUS_ATTR_EAP_NEW_RX_INVALID_MESG_LEN_5,"xd",radius_mesg,radius_attr_len);
		goto error;
	}

	RHP_TRC(0,RHPTRCID_RADIUS_ATTR_EAP_NEW_RX_RTRN,"xxp",radius_mesg,radius_attr,radius_attr_priv->eap_attrh_rx_defrag_len,(u8*)radius_attr_priv->eap_attrh_rx_defrag);
  return 0;

error:
  if( ((rhp_radius_attr_priv*)radius_attr->priv)->ext_destructor ){
  	((rhp_radius_attr_priv*)radius_attr->priv)->ext_destructor(radius_attr);
  }

	RHP_TRC(0,RHPTRCID_RADIUS_ATTR_EAP_NEW_RX_ERR,"xxE",radius_mesg,radius_attr,err);
  return err;
}


int rhp_radius_attr_eap_new_tx(rhp_radius_mesg* radius_mesg,
			u8 attr_type,u32 nop,rhp_radius_attr* radius_attr)
{
  int err = 0;
  rhp_radius_attr_eap* radius_attr_eap;

	RHP_TRC(0,RHPTRCID_RADIUS_ATTR_EAP_NEW_TX,"xbux",radius_mesg,attr_type,nop,radius_attr);

  radius_attr_eap = _rhp_radius_attr_eap_alloc();
  if( radius_attr_eap == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  radius_attr->ext.eap = radius_attr_eap;
  ((rhp_radius_attr_priv*)radius_attr->priv)->ext_serialize = _rhp_radius_attr_eap_ext_serialize;
  ((rhp_radius_attr_priv*)radius_attr->priv)->ext_destructor = _rhp_radius_attr_eap_ext_destructor;

	RHP_TRC(0,RHPTRCID_RADIUS_ATTR_EAP_NEW_TX_RTRN,"xxx",radius_mesg,radius_attr,radius_attr->ext.eap);
  return 0;

error:
	if( ((rhp_radius_attr_priv*)radius_attr->priv)->ext_destructor ){
		((rhp_radius_attr_priv*)radius_attr->priv)->ext_destructor(radius_attr);
	}
	RHP_TRC(0,RHPTRCID_RADIUS_ATTR_EAP_NEW_TX_RTRN,"xxE",radius_mesg,radius_attr,err);
  return err;
}
