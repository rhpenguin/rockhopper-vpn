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


static u8 _rhp_radius_attr_vendor_ms_get_vendor_type(rhp_radius_attr* radius_attr)
{
	rhp_radius_attr_vendor_ms* radius_attr_ms = radius_attr->ext.ms;
	rhp_radius_attr_priv* radius_attr_priv = (rhp_radius_attr_priv*)radius_attr->priv;
	u8 vendor_type = 0;

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_VENDOR_MS_GET_VENDOR_TYPE,"xxxx",radius_attr,radius_attr_priv,radius_attr_ms,radius_attr_priv->radius_attrh);

	if( radius_attr_priv->radius_attrh ){

	  rhp_proto_radius_attr_vendor* vendorh = (rhp_proto_radius_attr_vendor*)radius_attr_priv->radius_attrh;
	  rhp_proto_radius_attr_vendor_ms* msh = (rhp_proto_radius_attr_vendor_ms*)(vendorh + 1);

	  vendor_type = msh->vendor_type;

	}else{

		if( radius_attr_ms->vendor_attr ){
			vendor_type = radius_attr_ms->vendor_attr->vendor_type;
		}
	}

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_VENDOR_MS_GET_VENDOR_TYPE_RTRN,"xxxb",radius_attr,radius_attr_priv,radius_attr_ms,vendor_type);
	return vendor_type;
}

static int _rhp_radius_attr_vendor_ms_set_vendor_attr(
		rhp_radius_attr* radius_attr,rhp_proto_radius_attr_vendor_ms* vendor_attr,int vendor_attr_len)
{
	rhp_radius_attr_vendor_ms* radius_attr_ms = radius_attr->ext.ms;
	rhp_proto_radius_attr_vendor_ms* new_buf = NULL;

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_VENDOR_MS_SET_VENDOR_ATTR,"xxp",radius_attr,radius_attr_ms,vendor_attr_len,(u8*)vendor_attr);

	if( vendor_attr ){

		new_buf = (rhp_proto_radius_attr_vendor_ms*)_rhp_malloc(vendor_attr_len);
		if( new_buf == NULL ){
			RHP_BUG("");
			return -ENOMEM;
		}

		memcpy(new_buf,vendor_attr,vendor_attr_len);
	}

	if( radius_attr_ms->vendor_attr ){
		_rhp_free_zero(radius_attr_ms->vendor_attr,radius_attr_ms->vendor_attr_len);
	}

	radius_attr_ms->vendor_attr = new_buf;
	radius_attr_ms->vendor_attr_len = vendor_attr_len;

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_VENDOR_MS_SET_VENDOR_ATTR_RTRN,"xxp",radius_attr,radius_attr_ms,radius_attr_ms->vendor_attr_len,radius_attr_ms->vendor_attr);
	return 0;
}

static rhp_proto_radius_attr_vendor_ms* _rhp_radius_attr_vendor_ms_get_vendor_attr(
		rhp_radius_attr* radius_attr,int* vendor_attr_len_r)
{
	rhp_radius_attr_vendor_ms* radius_attr_ms = radius_attr->ext.ms;
	rhp_radius_attr_priv* radius_attr_priv = (rhp_radius_attr_priv*)radius_attr->priv;
	rhp_proto_radius_attr_vendor_ms* ret = NULL;
	int ret_len = 0;

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_VENDOR_MS_GET_VENDOR_ATTR,"xxxxx",radius_attr,radius_attr_priv,radius_attr_ms,radius_attr_priv->radius_attrh,radius_attr_ms->vendor_attr);

	if( radius_attr_priv->radius_attrh ){

	  rhp_proto_radius_attr_vendor* vendorh = (rhp_proto_radius_attr_vendor*)radius_attr_priv->radius_attrh;
	  rhp_proto_radius_attr_vendor_ms* msh = (rhp_proto_radius_attr_vendor_ms*)(vendorh + 1);

	  ret_len = msh->vendor_len;
		ret = msh;

	}else{

		ret_len = radius_attr_ms->vendor_attr_len;
		ret = radius_attr_ms->vendor_attr;
	}

	*vendor_attr_len_r = ret_len;

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_VENDOR_MS_GET_VENDOR_ATTR_RTRN,"xxxp",radius_attr,radius_attr_priv,radius_attr_ms,ret_len,ret);
	return ret;
}


static rhp_radius_attr_vendor_ms* _rhp_radius_attr_vendor_ms_alloc()
{
	rhp_radius_attr_vendor_ms* radius_attr_ms = (rhp_radius_attr_vendor_ms*)_rhp_malloc(sizeof(rhp_radius_attr_vendor_ms));

	if( radius_attr_ms == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(radius_attr_ms,0,sizeof(rhp_radius_attr_vendor_ms));

	radius_attr_ms->get_vendor_type = _rhp_radius_attr_vendor_ms_get_vendor_type;
	radius_attr_ms->set_vendor_attr = _rhp_radius_attr_vendor_ms_set_vendor_attr;
	radius_attr_ms->get_vendor_attr = _rhp_radius_attr_vendor_ms_get_vendor_attr;

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_VENDOR_MS_ALLOC,"x",radius_attr_ms);
	return radius_attr_ms;
}

static int _rhp_radius_attr_vendor_ms_ext_serialize(rhp_radius_attr* radius_attr,rhp_packet* pkt)
{
	rhp_radius_attr_vendor_ms* radius_attr_ms = radius_attr->ext.ms;

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_VENDOR_MS_EXT_SERIALIZE,"xxxx",radius_attr,radius_attr_ms,pkt,radius_attr_ms->vendor_attr);

	if( radius_attr_ms->vendor_attr ){

    int len = sizeof(rhp_proto_radius_attr_vendor) + radius_attr_ms->vendor_attr_len;
    rhp_proto_radius_attr_vendor* p;

    p = (rhp_proto_radius_attr_vendor*)rhp_pkt_expand_tail(pkt,len);
    if( p == NULL ){
      RHP_BUG("");
      return -ENOMEM;
    }

    p->len = len;
    p->type = radius_attr->get_attr_type(radius_attr);
    p->vendor_id = htonl(RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC_MICROSOFT);

    memcpy((p + 1),radius_attr_ms->vendor_attr,radius_attr_ms->vendor_attr_len);

    ((rhp_radius_mesg_priv*)radius_attr->radius_mesg->priv)->tx_mesg_len += len;

    RHP_TRC(0,RHPTRCID_RADIUS_ATTR_VENDOR_MS_EXT_SERIALIZE_RTRN,"xxxdp",radius_attr,radius_attr_ms,pkt,((rhp_radius_mesg_priv*)radius_attr->radius_mesg->priv)->tx_mesg_len,len,(u8*)p);
    return 0;
  }

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_VENDOR_MS_EXT_SERIALIZE_ERR,"xxx",radius_attr,radius_attr_ms,pkt);
  return -EINVAL;
}

static void _rhp_radius_attr_vendor_ms_ext_destructor(rhp_radius_attr* radius_attr)
{
	rhp_radius_attr_vendor_ms* radius_attr_ms = radius_attr->ext.ms;

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_VENDOR_MS_DESTRUCTOR,"xxx",radius_attr,radius_attr_ms,radius_attr_ms->vendor_attr);

	if( radius_attr_ms->vendor_attr ){
		_rhp_free_zero(radius_attr_ms->vendor_attr,radius_attr_ms->vendor_attr_len);
	}

	return;
}


int rhp_radius_attr_vendor_ms_new_rx(rhp_radius_mesg* radius_mesg,u8 attr_type,u32 vendor_id,
								rhp_proto_radius_attr* radius_attrh,int radius_attr_len,rhp_radius_attr* radius_attr)
{
  int err = 0;
  rhp_radius_attr_vendor_ms* radius_attr_ms;
  rhp_packet* rx_pkt = RHP_PKT_REF(((rhp_radius_mesg_priv*)radius_mesg->priv)->rx_pkt_ref);
  rhp_proto_radius_attr_vendor* vendorh = (rhp_proto_radius_attr_vendor*)radius_attrh;
  rhp_proto_radius_attr_vendor_ms* msh;
  int ms_len;

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_VENDOR_MS_NEW_RX,"xbuxxp",radius_mesg,attr_type,vendor_id,radius_attr,rx_pkt,radius_attr_len,(u8*)radius_attrh);

  if( radius_attr_len
  			< (int)sizeof(rhp_proto_radius_attr_vendor) + (int)sizeof(rhp_proto_radius_attr_vendor_ms) ){
    err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
    RHP_TRC(0,RHPTRCID_RADIUS_ATTR_VENDOR_MS_NEW_RX_INVALID_MESG_LEN_1,"xxddd",radius_mesg,radius_attr,radius_attr_len,sizeof(rhp_proto_radius_attr_vendor),sizeof(rhp_proto_radius_attr_vendor_ms));
    goto error;
  }

  if( vendorh->vendor_id != htonl(RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC_MICROSOFT) ){
    err = RHP_STATUS_RADIUS_INVALID_ATTR;
    RHP_TRC(0,RHPTRCID_RADIUS_ATTR_VENDOR_MS_NEW_RX_INVALID_VENDOR_ID,"xxUu",radius_mesg,radius_attr,vendorh->vendor_id,RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC_MICROSOFT);
    goto error;
  }

  msh = (rhp_proto_radius_attr_vendor_ms*)(vendorh + 1);
  ms_len = msh->vendor_len;


  if( (radius_attr_len - sizeof(rhp_proto_radius_attr_vendor)) != ms_len ){
    err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
    RHP_TRC(0,RHPTRCID_RADIUS_ATTR_VENDOR_MS_NEW_RX_INVALID_MESG_LEN_2,"xxddd",radius_mesg,radius_attr,radius_attr_len,ms_len,sizeof(rhp_proto_radius_attr_vendor));
    goto error;
  }


  if( (msh->vendor_type == RHP_RADIUS_VENDOR_MS_ATTR_TYPE_MPPE_SEND_KEY ||
  		 msh->vendor_type == RHP_RADIUS_VENDOR_MS_ATTR_TYPE_MPPE_RECV_KEY) &&
  		ms_len < sizeof(rhp_proto_radius_attr_vendor_ms_mppe_send_key) ){
    RHP_TRC(0,RHPTRCID_RADIUS_ATTR_VENDOR_MS_NEW_RX_INVALID_MESG_LEN_3,"xxbdd",radius_mesg,radius_attr,msh->vendor_type,ms_len,sizeof(rhp_proto_radius_attr_vendor_ms_mppe_send_key));
    err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
    goto error;
  }


  radius_attr_ms = _rhp_radius_attr_vendor_ms_alloc();
  if( radius_attr_ms == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  radius_attr->ext.ms = radius_attr_ms;
  ((rhp_radius_attr_priv*)radius_attr->priv)->ext_serialize = _rhp_radius_attr_vendor_ms_ext_serialize;
  ((rhp_radius_attr_priv*)radius_attr->priv)->ext_destructor = _rhp_radius_attr_vendor_ms_ext_destructor;


  if( _rhp_pkt_pull(rx_pkt,radius_attr_len) == NULL ){
    err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
    RHP_TRC(0,RHPTRCID_RADIUS_ATTR_VENDOR_MS_NEW_RX_INVALID_MESG_LEN_4,"xxd",radius_mesg,radius_attr,radius_attr_len);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_VENDOR_MS_NEW_RX_RTRN,"xx",radius_mesg,radius_attr);
  return 0;

error:
  if( ((rhp_radius_attr_priv*)radius_attr->priv)->ext_destructor ){
  	((rhp_radius_attr_priv*)radius_attr->priv)->ext_destructor(radius_attr);
  }

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_VENDOR_MS_NEW_RX_ERR,"xxE",radius_mesg,radius_attr,err);
  return err;
}


int rhp_radius_attr_vendor_ms_new_tx(rhp_radius_mesg* radius_mesg,
			u8 attr_type,u32 nop,rhp_radius_attr* radius_attr)
{
  int err = 0;
  rhp_radius_attr_vendor_ms* radius_attr_ms;

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_VENDOR_MS_NEW_TX,"xbux",radius_mesg,attr_type,nop,radius_attr);

  radius_attr_ms = _rhp_radius_attr_vendor_ms_alloc();
  if( radius_attr_ms == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  radius_attr->ext.ms = radius_attr_ms;
  ((rhp_radius_attr_priv*)radius_attr->priv)->ext_serialize = _rhp_radius_attr_vendor_ms_ext_serialize;
  ((rhp_radius_attr_priv*)radius_attr->priv)->ext_destructor = _rhp_radius_attr_vendor_ms_ext_destructor;

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_VENDOR_MS_NEW_TX_RTRN,"xxx",radius_mesg,radius_attr,radius_attr_ms);
  return 0;

error:
	if( ((rhp_radius_attr_priv*)radius_attr->priv)->ext_destructor ){
		((rhp_radius_attr_priv*)radius_attr->priv)->ext_destructor(radius_attr);
	}

	RHP_TRC(0,RHPTRCID_RADIUS_ATTR_VENDOR_MS_NEW_TX_ERR,"xxE",radius_mesg,radius_attr,err);
  return err;
}

