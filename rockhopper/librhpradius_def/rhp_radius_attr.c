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


typedef int (*RHP_RADIUS_NEW_ATTR_RX)(rhp_radius_mesg* radius_mesg,u8 attr_type,u32 vendor_id,
								rhp_proto_radius_attr* radius_attrh,int radius_attr_len,rhp_radius_attr* radius_attr);

extern int rhp_radius_attr_basic_new_rx(rhp_radius_mesg* radius_mesg,u8 attr_type,u32 vendor_id,
								rhp_proto_radius_attr* radius_attrh,int radius_attr_len,rhp_radius_attr* radius_attr);

extern int rhp_radius_attr_eap_new_rx(rhp_radius_mesg* radius_mesg,u8 attr_type,u32 vendor_id,
								rhp_proto_radius_attr* radius_attrh,int radius_attr_len,rhp_radius_attr* radius_attr);

extern int rhp_radius_attr_vendor_ms_new_rx(rhp_radius_mesg* radius_mesg,u8 attr_type,u32 vendor_id,
								rhp_proto_radius_attr* radius_attrh,int radius_attr_len,rhp_radius_attr* radius_attr);


static RHP_RADIUS_NEW_ATTR_RX _rhp_radius_new_rx_attr_cb(u8 type,u32 vendor_id)
{
	RHP_RADIUS_NEW_ATTR_RX cb = NULL;

	if( type == RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC &&
			vendor_id  == RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC_MICROSOFT ){

		cb = rhp_radius_attr_vendor_ms_new_rx;

	}else{

		switch( type ){

		case RHP_RADIUS_ATTR_TYPE_EAP:
			cb = rhp_radius_attr_eap_new_rx;
			break;

		default:
			cb = rhp_radius_attr_basic_new_rx;
			break;
		}
	}

  RHP_TRC(0,RHPTRCID_RADIUS_NEW_RX_ATTR_CB,"buY",type,vendor_id,cb);
	return cb;
}



typedef int (*RHP_RADIUS_NEW_ATTR_TX)(rhp_radius_mesg* radius_mesg,u8 attr_type,u32 vendor_id,rhp_radius_attr* radius_attr);

extern int rhp_radius_attr_basic_new_tx(rhp_radius_mesg* radius_mesg,u8 attr_type,u32 nop,rhp_radius_attr* radius_attr);

extern int rhp_radius_attr_eap_new_tx(rhp_radius_mesg* radius_mesg,u8 attr_type,u32 nop,rhp_radius_attr* radius_attr);

extern int rhp_radius_attr_vendor_ms_new_tx(rhp_radius_mesg* radius_mesg,u8 attr_type,u32 vendor_id,rhp_radius_attr* radius_attr);


static RHP_RADIUS_NEW_ATTR_TX _rhp_radius_new_tx_attr_cb(u8 type,u32 vendor_id)
{
	RHP_RADIUS_NEW_ATTR_TX cb = NULL;

	if( type == RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC &&
			vendor_id  == RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC_MICROSOFT ){

		cb = rhp_radius_attr_vendor_ms_new_tx;

	}else{

		switch( type ){

		case RHP_RADIUS_ATTR_TYPE_EAP:
			cb = rhp_radius_attr_eap_new_tx;
			break;

		default:
			cb = rhp_radius_attr_basic_new_tx;
			break;
		}
	}

  RHP_TRC(0,RHPTRCID_RADIUS_NEW_TX_ATTR_CB,"buY",type,vendor_id,cb);
	return cb;
}


static u8 _rhp_radius_attr_get_attr_type(rhp_radius_attr* radius_attr)
{
	rhp_radius_attr_priv* radius_attr_priv = (rhp_radius_attr_priv*)radius_attr->priv;
	u8 attr_type;

	if( radius_attr_priv->radius_attrh ){
		attr_type = radius_attr_priv->radius_attrh->type;
	}else{
		attr_type = radius_attr->attr_type;
	}

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_GET_ATTR_TYPE,"xxb",radius_attr,radius_attr_priv,attr_type);
	return attr_type;
}

static u32 _rhp_radius_attr_get_attr_vendor_id(rhp_radius_attr* radius_attr)
{
	rhp_radius_attr_priv* radius_attr_priv = (rhp_radius_attr_priv*)radius_attr->priv;
	u32 vendor_id = 0;

	if( radius_attr_priv->radius_attrh ){

		if( radius_attr_priv->radius_attrh->type == RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC ){
			vendor_id = ntohl(((rhp_proto_radius_attr_vendor*)radius_attr_priv->radius_attrh)->vendor_id);
		}

	}else{

		vendor_id = radius_attr->vendor_id;
	}

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_GET_ATTR_VENDOR_ID,"xxxu",radius_attr,radius_attr_priv,radius_attr_priv->radius_attrh,vendor_id);
	return vendor_id;
}

static rhp_radius_attr* _rhp_radius_attr_alloc()
{
	rhp_radius_attr* radius_attr = (rhp_radius_attr*)_rhp_malloc(sizeof(rhp_radius_attr));

	if( radius_attr == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(radius_attr,0,sizeof(rhp_radius_attr));

	radius_attr->priv = (void*)_rhp_malloc(sizeof(rhp_radius_attr_priv));
	if( radius_attr->priv == NULL ){
		RHP_BUG("");
		_rhp_free(radius_attr);
		return NULL;
	}

	memset(radius_attr->priv,0,sizeof(rhp_radius_attr_priv));


	radius_attr->tag[0] = '#';
	radius_attr->tag[1] = 'R';
	radius_attr->tag[2] = 'D';
	radius_attr->tag[3] = 'A';

	radius_attr->get_attr_type = _rhp_radius_attr_get_attr_type;
	radius_attr->get_attr_vendor_id = _rhp_radius_attr_get_attr_vendor_id;


	((rhp_radius_attr_priv*)radius_attr->priv)->tag[0] = '#';
	((rhp_radius_attr_priv*)radius_attr->priv)->tag[1] = 'R';
	((rhp_radius_attr_priv*)radius_attr->priv)->tag[2] = 'A';
	((rhp_radius_attr_priv*)radius_attr->priv)->tag[3] = 'I';

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_ALLOC,"xx",radius_attr,radius_attr->priv);
	return radius_attr;
}

void rhp_radius_attr_destroy(rhp_radius_attr* radius_attr)
{
	rhp_radius_attr_priv* radius_attr_priv = (rhp_radius_attr_priv*)radius_attr->priv;

  RHP_TRC(0,RHPTRCID_RADIUS_ATTR_DESTROY,"xxxY",radius_attr,radius_attr_priv,radius_attr->ext.raw,radius_attr_priv->ext_destructor);

  if( radius_attr->ext.raw ){

    if( radius_attr_priv->ext_destructor ){
    	radius_attr_priv->ext_destructor(radius_attr);
    }

  	_rhp_free(radius_attr->ext.raw);
  }

  _rhp_free(radius_attr->priv);
  _rhp_free(radius_attr);

  return;
}

int rhp_radius_new_attr_tx(rhp_radius_session* radius_sess,rhp_radius_mesg* radius_mesg,
		u8 attr_type,u32 vendor_id,rhp_radius_attr** radius_attr_r)
{
  int err;
  rhp_radius_attr* radius_attr = NULL;
  RHP_RADIUS_NEW_ATTR_TX cb;

  RHP_TRC(0,RHPTRCID_RADIUS_NEW_ATTR_TX,"xxbux",radius_sess,radius_mesg,attr_type,vendor_id,radius_attr_r);

  cb = _rhp_radius_new_tx_attr_cb(attr_type,vendor_id);
  if( cb == NULL ){
    RHP_TRC(0,RHPTRCID_RADIUS_NEW_ATTR_TX_NO_CB_FOUND,"xx",radius_sess,radius_mesg);
    return RHP_STATUS_RADIUS_UNKNOWN_ATTR;
  }

  radius_attr = _rhp_radius_attr_alloc();
  if( radius_attr == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  radius_attr->radius_mesg = radius_mesg;
  radius_attr->attr_type = attr_type;
  radius_attr->vendor_id = vendor_id;

  err = cb(radius_mesg,attr_type,vendor_id,radius_attr);
  if( err ){
  	rhp_radius_attr_destroy(radius_attr);
    RHP_TRC(0,RHPTRCID_RADIUS_NEW_ATTR_TX_ERR,"xxYE",radius_sess,radius_mesg,cb,err);
    return err;
  }

  *radius_attr_r = radius_attr;

  RHP_TRC(0,RHPTRCID_RADIUS_NEW_ATTR_TX_RTRN,"xxY",radius_sess,radius_mesg,cb);
  return 0;
}

int rhp_radius_new_attr_rx(rhp_radius_session* radius_sess,rhp_radius_mesg* radius_mesg,
		rhp_proto_radius_attr* radius_attrh,int radius_attr_len,rhp_radius_attr** radius_attr_r)
{
  int err;
  rhp_radius_mesg_priv* radius_mesg_priv = (rhp_radius_mesg_priv*)radius_mesg->priv;
  rhp_radius_attr* radius_attr = *radius_attr_r;
  RHP_RADIUS_NEW_ATTR_RX cb = NULL;
  rhp_packet* rx_pkt = RHP_PKT_REF(radius_mesg_priv->rx_pkt_ref);
  u8 attr_type;
  u32 vendor_id = 0;

  RHP_TRC(0,RHPTRCID_RADIUS_NEW_ATTR_RX,"xxxxp",radius_sess,radius_mesg,radius_attr_r,*radius_attr_r,radius_attr_len,(u8*)radius_attrh);

  attr_type = radius_attrh->type;
  if( attr_type == RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC ){

    if( _rhp_pkt_try_pull(rx_pkt,sizeof(rhp_proto_radius_attr_vendor)) ){
      err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
      RHP_TRC(0,RHPTRCID_RADIUS_NEW_ATTR_RX_INVALID_VENDOR_ATTR_LEN,"xx",radius_sess,radius_mesg);
      goto error;
    }

  	vendor_id = ntohl(((rhp_proto_radius_attr_vendor*)radius_attrh)->vendor_id);
  }

  cb = _rhp_radius_new_rx_attr_cb(attr_type,vendor_id);
  if( cb == NULL ){
    RHP_TRC(0,RHPTRCID_RADIUS_NEW_ATTR_RX_CB_NOT_FOUND,"xx",radius_sess,radius_mesg);
    return RHP_STATUS_UNKNOWN_PAYLOAD;
  }

  if( radius_attr == NULL ){

  	radius_attr = _rhp_radius_attr_alloc();
		if( radius_attr == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		radius_attr->radius_mesg = radius_mesg;

		((rhp_radius_attr_priv*)radius_attr->priv)->radius_attrh = radius_attrh;
  }


  err = cb(radius_mesg,attr_type,vendor_id,radius_attrh,radius_attr_len,radius_attr);
  if( err ){
    RHP_TRC(0,RHPTRCID_RADIUS_NEW_ATTR_RX_CB_ERR,"xxYE",radius_sess,radius_mesg,cb,err);
  	goto error;
  }

  if( *radius_attr_r == NULL ){
  	*radius_attr_r = radius_attr;
  }

  RHP_TRC(0,RHPTRCID_RADIUS_NEW_ATTR_RX_RTRN,"xxxY",radius_sess,radius_mesg,radius_attr,cb);
  return 0;

error:
	if( radius_attr ){
  	rhp_radius_attr_destroy(radius_attr);
	}
  RHP_TRC(0,RHPTRCID_RADIUS_NEW_ATTR_RX_ERR,"xxYE",radius_sess,radius_mesg,cb,err);
	return err;
}

