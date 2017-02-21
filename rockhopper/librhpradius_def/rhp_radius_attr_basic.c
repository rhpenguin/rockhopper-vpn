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

static int _rhp_radius_attr_basic_set_attr_value(rhp_radius_attr* radius_attr,u8 attr_value_len,u8* attr_value)
{
	rhp_radius_attr_basic* radius_attr_basic = radius_attr->ext.basic;
	u8* new_buf = NULL;

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_BASIC_SET_ATTR_VALUE,"xxp",radius_attr,radius_attr_basic,(int)attr_value_len,attr_value);

	if( attr_value ){

		if( attr_value_len > RHP_RADIUS_ATTR_VAL_MAX_LEN ){
			RHP_BUG("%d",attr_value_len);
			attr_value_len = RHP_RADIUS_ATTR_VAL_MAX_LEN;
		}

		new_buf = (u8*)_rhp_malloc(attr_value_len);
		if( new_buf == NULL ){
			RHP_BUG("");
			return -ENOMEM;
		}

		memcpy(new_buf,attr_value,attr_value_len);
	}

	if( radius_attr_basic->attr_value ){
		_rhp_free_zero(radius_attr_basic->attr_value,radius_attr_basic->attr_value_len);
	}

	radius_attr_basic->attr_value = new_buf;
	radius_attr_basic->attr_value_len = attr_value_len;

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_BASIC_SET_ATTR_VALUE_RTRN,"xxp",radius_attr,radius_attr_basic,radius_attr_basic->attr_value_len,radius_attr_basic->attr_value);
	return 0;
}

static u8* _rhp_radius_attr_basic_get_attr_value(rhp_radius_attr* radius_attr,int* attr_val_len_r)
{
	rhp_radius_attr_basic* radius_attr_basic = radius_attr->ext.basic;
	rhp_radius_attr_priv* radius_attr_priv = (rhp_radius_attr_priv*)radius_attr->priv;
	u8* ret = NULL;
	int ret_len = 0;

	RHP_TRC(0,RHPTRCID_RADIUS_ATTR_BASIC_GET_ATTR_VALUE,"xxxxx",radius_attr,radius_attr_basic,radius_attr_priv,radius_attr_priv->radius_attrh,attr_val_len_r);

	if( radius_attr_priv->radius_attrh ){

		ret_len = radius_attr_priv->radius_attrh->len - sizeof(rhp_proto_radius_attr);
		ret = (u8*)(radius_attr_priv->radius_attrh + 1);

	}else{

		ret_len = radius_attr_basic->attr_value_len;
		ret = radius_attr_basic->attr_value;
	}

	*attr_val_len_r = ret_len;

	RHP_TRC(0,RHPTRCID_RADIUS_ATTR_BASIC_GET_ATTR_VALUE_RTRN,"xxxp",radius_attr,radius_attr_basic,radius_attr_priv,(int)ret_len,ret);
	return ret;
}

static int _rhp_radius_attr_basic_ext_serialize(rhp_radius_attr* radius_attr,rhp_packet* pkt)
{
	rhp_radius_attr_basic* radius_attr_basic = radius_attr->ext.basic;

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_BASIC_EXT_SERIALIZE,"xxx",radius_attr,radius_attr_basic,pkt);

	if( radius_attr_basic->attr_value ){

    int len = sizeof(rhp_proto_radius_attr) + radius_attr_basic->attr_value_len;
    rhp_proto_radius_attr* p;

    p = (rhp_proto_radius_attr*)rhp_pkt_expand_tail(pkt,len);
    if( p == NULL ){
      RHP_BUG("");
      return -ENOMEM;
    }

    p->len = len;
    p->type = radius_attr->get_attr_type(radius_attr);

    memcpy((p + 1),radius_attr_basic->attr_value,radius_attr_basic->attr_value_len);

    ((rhp_radius_mesg_priv*)radius_attr->radius_mesg->priv)->tx_mesg_len += len;

    RHP_TRC(0,RHPTRCID_RADIUS_ATTR_BASIC_EXT_SERIALIZE_RTRN,"xxxxdp",radius_attr,radius_attr_basic,pkt,radius_attr_basic->attr_value,((rhp_radius_mesg_priv*)radius_attr->radius_mesg->priv)->tx_mesg_len,len,p);
    return 0;
  }

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_BASIC_EXT_SERIALIZE_ERR,"xxx",radius_attr,radius_attr_basic,pkt);
  return -EINVAL;
}

static void _rhp_radius_attr_basic_ext_destructor(rhp_radius_attr* radius_attr)
{
	rhp_radius_attr_basic* radius_attr_basic = radius_attr->ext.basic;

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_BASIC_EXT_DESTRUCTOR,"xxx",radius_attr,radius_attr_basic,radius_attr_basic->attr_value);

	if( radius_attr_basic->attr_value ){
		_rhp_free_zero(radius_attr_basic->attr_value,radius_attr_basic->attr_value_len);
	}

	return;
}


static rhp_radius_attr_basic* _rhp_radius_attr_basic_alloc()
{
	rhp_radius_attr_basic* radius_attr_basic
		= (rhp_radius_attr_basic*)_rhp_malloc(sizeof(rhp_radius_attr_basic));

	if( radius_attr_basic == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(radius_attr_basic,0,sizeof(rhp_radius_attr_basic));

	radius_attr_basic->set_attr_value = _rhp_radius_attr_basic_set_attr_value;
	radius_attr_basic->get_attr_value = _rhp_radius_attr_basic_get_attr_value;

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_BASIC_ALLOC,"x",radius_attr_basic);

	return radius_attr_basic;
}


int rhp_radius_attr_basic_new_rx(rhp_radius_mesg* radius_mesg,u8 attr_type,u32 vendor_id,
								rhp_proto_radius_attr* radius_attrh,int radius_attr_len,rhp_radius_attr* radius_attr)
{
  int err = 0;
  rhp_radius_attr_basic* radius_attr_basic;
  rhp_packet* rx_pkt = RHP_PKT_REF(((rhp_radius_mesg_priv*)radius_mesg->priv)->rx_pkt_ref);

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_BASIC_NEW_RX,"xbuxxp",radius_mesg,attr_type,vendor_id,radius_attr,rx_pkt,radius_attr_len,(u8*)radius_attrh);

  if( radius_attr_len < (int)sizeof(rhp_proto_radius_attr) ){
    err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
    goto error;
  }

  radius_attr_basic = _rhp_radius_attr_basic_alloc();
  if( radius_attr_basic == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  radius_attr->ext.basic = radius_attr_basic;
  ((rhp_radius_attr_priv*)radius_attr->priv)->ext_serialize = _rhp_radius_attr_basic_ext_serialize;
  ((rhp_radius_attr_priv*)radius_attr->priv)->ext_destructor = _rhp_radius_attr_basic_ext_destructor;


  if( _rhp_pkt_pull(rx_pkt,radius_attr_len) == NULL ){
    err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
    goto error;
  }

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_BASIC_NEW_RX_RTRN,"xbuxx",radius_mesg,attr_type,vendor_id,radius_attr,radius_attr->ext.basic);
  return 0;

error:
  if( ((rhp_radius_attr_priv*)radius_attr->priv)->ext_destructor ){
  	((rhp_radius_attr_priv*)radius_attr->priv)->ext_destructor(radius_attr);
  }

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_BASIC_NEW_RX_ERR,"xbuxE",radius_mesg,attr_type,vendor_id,radius_attr,err);
  return err;
}

int rhp_radius_attr_basic_new_tx(rhp_radius_mesg* radius_mesg,
			u8 attr_type,u32 nop,rhp_radius_attr* radius_attr)
{
  int err = 0;
  rhp_radius_attr_basic* radius_attr_basic;

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_BASIC_NEW_TX,"xbux",radius_mesg,attr_type,nop,radius_attr);

  radius_attr_basic = _rhp_radius_attr_basic_alloc();
  if( radius_attr_basic == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  radius_attr->ext.basic = radius_attr_basic;
  ((rhp_radius_attr_priv*)radius_attr->priv)->ext_serialize = _rhp_radius_attr_basic_ext_serialize;
  ((rhp_radius_attr_priv*)radius_attr->priv)->ext_destructor = _rhp_radius_attr_basic_ext_destructor;

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_BASIC_NEW_TX_RTRN,"xbuxx",radius_mesg,attr_type,nop,radius_attr,radius_attr->ext.basic);
  return 0;

error:
	if( ((rhp_radius_attr_priv*)radius_attr->priv)->ext_destructor ){
		((rhp_radius_attr_priv*)radius_attr->priv)->ext_destructor(radius_attr);
	}

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_BASIC_NEW_TX_ERR,"xbuxE",radius_mesg,attr_type,nop,radius_attr,err);
	return err;
}
