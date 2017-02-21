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

static u8* _rhp_ikev2_vid_my_app_id_md = NULL;
static int _rhp_ikev2_vid_my_app_id_md_len = 0;


static int _rhp_ikev2_vid_payload_get_vid_len(rhp_ikev2_payload* payload)
{
  int len;
  if( payload->ext.vid->vid ){
    len = payload->ext.vid->vid_len;
  }else{
    len = payload->get_len_rx(payload);
    len -= sizeof(rhp_proto_ike_vid_payload);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_VID_PAYLOAD_GET_VID_LEN,"xxd",payload,payload->ext.vid->vid,len);
  return len;
}

static u8* _rhp_ikev2_vid_payload_get_vid(rhp_ikev2_payload* payload)
{
  u8* ret;
  rhp_proto_ike_vid_payload* vid_payloadh;
  int len = _rhp_ikev2_vid_payload_get_vid_len(payload);

  if( payload->ext.vid->vid ){
    ret = payload->ext.vid->vid;
  }else{
    vid_payloadh = (rhp_proto_ike_vid_payload*)(payload->payloadh);
    ret = (u8*)(vid_payloadh + 1);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_VID_PAYLOAD_GET_VID,"xxxp",payload,payload->ext.vid->vid,ret,len,ret);
  return ret;
}

static void _rhp_ikev2_vid_payload_destructor(rhp_ikev2_payload* payload)
{
  RHP_TRC(0,RHPTRCID_IKEV2_VID_PAYLOAD_DESTRUCTOR,"xx",payload,payload->ext.vid->vid);

  if( payload->ext.vid->vid ){
    _rhp_free(payload->ext.vid->vid);
    payload->ext.vid->vid = NULL;
    payload->ext.vid->vid_len = 0;
  }
  return;
}

static int _rhp_ikev2_vid_payload_serialize(rhp_ikev2_payload* payload,rhp_packet* pkt)
{
  RHP_TRC(0,RHPTRCID_IKEV2_VID_PAYLOAD_SERIALIZE,"xx",payload,pkt);

  if( payload->ext.vid->vid ){

    int len = sizeof(rhp_proto_ike_vid_payload) + payload->ext.vid->vid_len;
    rhp_proto_ike_vid_payload* p;

    p = (rhp_proto_ike_vid_payload*)rhp_pkt_expand_tail(pkt,len);
    if( p == NULL ){
      RHP_BUG("");
      return -ENOMEM;
    }

    p->next_payload = payload->get_next_payload(payload);
    p->critical_rsv = 0;
    p->len = htons(len);

    memcpy((p + 1),payload->ext.vid->vid,payload->ext.vid->vid_len);

    payload->ikemesg->tx_mesg_len += len;

    p->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
    if( payload->next ){
      p->next_payload = payload->next->get_payload_id(payload->next);
    }

    RHP_TRC(0,RHPTRCID_IKEV2_VID_PAYLOAD_SERIALIZE_RTRN,"xx",payload,pkt);
    rhp_pkt_trace_dump("_rhp_ikev2_vid_payload_serialize",pkt);
    return 0;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_VID_PAYLOAD_SERIALIZE_ERR,"xx",payload,pkt);
  return -EINVAL;
}

static int _rhp_ikev2_vid_payload_set_vid(rhp_ikev2_payload* payload,int vid_len,u8* vid)
{
  RHP_TRC(0,RHPTRCID_IKEV2_VID_PAYLOAD_SET_VID,"xp",payload,vid_len,vid);

  if( payload->ext.vid->vid ){
    RHP_BUG("");
    return -EEXIST;
  }

  payload->ext.vid->vid = (u8*)_rhp_malloc(vid_len);
  if( payload->ext.vid->vid == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  memcpy(payload->ext.vid->vid,vid,vid_len);
  payload->ext.vid->vid_len = vid_len;

  return 0;
}

static int _rhp_ikev2_vid_payload_copy_my_app_vid(rhp_ikev2_payload* payload)
{
  int ret = 0;
  u8 ver = RHP_MY_VENDOR_ID_VER;

  payload->ext.vid->vid = (u8*)_rhp_malloc(_rhp_ikev2_vid_my_app_id_md_len+sizeof(u8));
  if( payload->ext.vid->vid == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  payload->ext.vid->vid_len = _rhp_ikev2_vid_my_app_id_md_len+sizeof(u8);
  memcpy(payload->ext.vid->vid,&ver,sizeof(u8));
  memcpy((payload->ext.vid->vid+sizeof(u8)),_rhp_ikev2_vid_my_app_id_md,_rhp_ikev2_vid_my_app_id_md_len);

  RHP_TRC(0,RHPTRCID_IKEV2_VID_PAYLOAD_GENERATE_MY_APP_VID,"xdp",payload,ret,_rhp_ikev2_vid_my_app_id_md_len,_rhp_ikev2_vid_my_app_id_md);
  return 0;
}

static int _rhp_ikev2_vid_payload_is_my_app_id(rhp_ikev2_payload* payload,u8* ver_r)
{
  int ret;
  u8* vid;

  vid = payload->ext.vid->get_vid(payload);

  if( (int)(_rhp_ikev2_vid_my_app_id_md_len+sizeof(u8)) == payload->ext.vid->get_vid_len(payload) &&
      !memcmp(_rhp_ikev2_vid_my_app_id_md,(vid+sizeof(u8)),_rhp_ikev2_vid_my_app_id_md_len) ){
    ret = 1;
  }else{
    ret = 0;
  }

  if( ret && ver_r ){
    *ver_r = *((u8*)vid);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_VID_PAYLOAD_IS_MY_APP_ID,"xE",payload,ret);
  return ret;
}

rhp_ikev2_vid_payload* _rhp_ikev2_alloc_vid_payload()
{
  rhp_ikev2_vid_payload* vid_payload;

  vid_payload = (rhp_ikev2_vid_payload*)_rhp_malloc(sizeof(rhp_ikev2_vid_payload));
  if( vid_payload == NULL ){
    return NULL;
  }

  memset(vid_payload,0,sizeof(rhp_ikev2_vid_payload));

  vid_payload->get_vid_len = _rhp_ikev2_vid_payload_get_vid_len;
  vid_payload->get_vid = _rhp_ikev2_vid_payload_get_vid;
  vid_payload->set_vid = _rhp_ikev2_vid_payload_set_vid;
  vid_payload->copy_my_app_vid = _rhp_ikev2_vid_payload_copy_my_app_vid;
  vid_payload->is_my_app_id = _rhp_ikev2_vid_payload_is_my_app_id;

  RHP_TRC(0,RHPTRCID_IKEV2_ALLOC_VID_PAYLOAD,"x",vid_payload);
  return vid_payload;
}


int rhp_ikev2_vid_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                 rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_vid_payload* vid_payload;
  rhp_proto_ike_vid_payload* vid_payloadh = (rhp_proto_ike_vid_payload*)payloadh;
  int vlen;

  RHP_TRC(0,RHPTRCID_IKEV2_VID_PAYLOAD_NEW_RX,"xbxdxp",ikemesg,payload_id,payloadh,payload_len,payload,payload_len,payloadh);

  if( payload_len <= (int)sizeof(rhp_proto_ike_vid_payload) ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_VID_PAYLOAD_NEW_RX_INVALID_MESG_1,"xdd",ikemesg,payload_len,sizeof(rhp_proto_ike_vid_payload));
    goto error;
  }

  vlen = payload_len - sizeof(rhp_proto_ike_vid_payload);
  if( vlen < 1 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_VID_PAYLOAD_NEW_RX_INVALID_MESG_2,"xd",ikemesg,vlen);
    goto error;
  }

  vid_payload = _rhp_ikev2_alloc_vid_payload();
  if( vid_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.vid = vid_payload;
  payload->ext_destructor = _rhp_ikev2_vid_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_vid_payload_serialize;

  vid_payloadh = (rhp_proto_ike_vid_payload*)_rhp_pkt_pull(ikemesg->rx_pkt,payload_len);
  if( vid_payloadh == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_VID_PAYLOAD_NEW_RX_INVALID_MESG_3,"x",ikemesg);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_VID_PAYLOAD_NEW_RX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_VID_PAYLOAD_NEW_RX_ERR,"xE",ikemesg,err);
  return err;
}

int rhp_ikev2_vid_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_vid_payload* vid_payload;

  RHP_TRC(0,RHPTRCID_IKEV2_VID_PAYLOAD_NEW_TX,"xbx",ikemesg,payload_id,payload);

  vid_payload = _rhp_ikev2_alloc_vid_payload();
  if( vid_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.vid = vid_payload;
  payload->ext_destructor = _rhp_ikev2_vid_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_vid_payload_serialize;

  RHP_TRC(0,RHPTRCID_IKEV2_VID_PAYLOAD_NEW_TX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_VID_PAYLOAD_NEW_TX_ERR,"xE",ikemesg,err);
  return err;
}


int rhp_ikev2_vid_payload_init()
{
  int err;

  if( (err = rhp_crypto_md(RHP_CRYPTO_MD_SHA1,(u8*)RHP_MY_VENDOR_ID,strlen(RHP_MY_VENDOR_ID)+1,
       &_rhp_ikev2_vid_my_app_id_md,&_rhp_ikev2_vid_my_app_id_md_len)) ){
    RHP_BUG("");
    return err;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_VID_PAYLOAD_INIT,"");

  return 0;
}

void rhp_ikev2_vid_payload_cleanup()
{
  RHP_TRC(0,RHPTRCID_IKEV2_VID_PAYLOAD_CLEANUP,"");

  if( _rhp_ikev2_vid_my_app_id_md ){
    _rhp_free(_rhp_ikev2_vid_my_app_id_md);
    _rhp_ikev2_vid_my_app_id_md = NULL;
    _rhp_ikev2_vid_my_app_id_md_len = 0;
  }

  return;
}

