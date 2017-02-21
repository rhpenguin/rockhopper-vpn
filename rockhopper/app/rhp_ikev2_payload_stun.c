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
#include "rhp_stun.h"


static void _rhp_ikev2_stun_payload_destructor(rhp_ikev2_payload* payload)
{
  RHP_TRC(0,RHPTRCID_IKEV2_STUN_PAYLOAD_DESTRUCTOR,"xx",payload,payload->ext.stun->stun_mesg);

  if( payload->ext.stun->stun_mesg ){

  	rhp_stun_mesg_free(payload->ext.stun->stun_mesg);
  	payload->ext.stun->stun_mesg = NULL;
  }

  return;
}

static int _rhp_ikev2_stun_payload_serialize(rhp_ikev2_payload* payload,rhp_packet* pkt)
{
	int err = -EINVAL;
	u8* buf = NULL;
	int buf_len = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_STUN_PAYLOAD_SERIALIZE,"xx",payload,pkt);

  if( payload->ext.stun->stun_mesg ){

  	rhp_stun_mesg* stun_mesg = payload->ext.stun->stun_mesg;
    int len = sizeof(rhp_proto_ike_stun_payload);
    rhp_proto_ike_stun_payload* p;


    err = stun_mesg->serialize(stun_mesg,0,&buf,&buf_len);
    if( err ){
    	goto error;
    }

    len += buf_len;


    p = (rhp_proto_ike_stun_payload*)rhp_pkt_expand_tail(pkt,len);
    if( p == NULL ){
      RHP_BUG("");
      err = -ENOMEM;
      goto error;
    }

    p->next_payload = payload->get_next_payload(payload);
    p->critical_rsv = 0;
    p->len = htons(len);

    memcpy((p + 1),buf,buf_len);

    payload->ikemesg->tx_mesg_len += len;

    p->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
    if( payload->next ){
      p->next_payload = payload->next->get_payload_id(payload->next);
    }

    _rhp_free(buf);

    RHP_TRC(0,RHPTRCID_IKEV2_STUN_PAYLOAD_SERIALIZE_RTRN,"xx",payload,pkt);
    rhp_pkt_trace_dump("_rhp_ikev2_stun_payload_serialize",pkt);

    return 0;
  }

error:
  if( buf ){
    _rhp_free(buf);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_STUN_PAYLOAD_SERIALIZE_ERR,"xx",payload,pkt);
  return err;
}

static int _rhp_ikev2_stun_payload_bind_alloc_tx_req(rhp_ikev2_payload* payload)
{
	int err = -EINVAL;

  RHP_TRC(0,RHPTRCID_IKEV2_STUN_PAYLOAD_BIND_ALLOC_TX_REQ,"x",payload);

	if( payload->ext.stun->stun_mesg == NULL ){

		err = rhp_stun_bind_tx_new_req_mesg(&(payload->ext.stun->stun_mesg));
		if( err ){
			goto error;
		}

	}else{
		err = -EINVAL;
		RHP_BUG("");
	}

  RHP_TRC(0,RHPTRCID_IKEV2_STUN_PAYLOAD_BIND_ALLOC_TX_REQ_RTRN,"x",payload);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_STUN_PAYLOAD_BIND_ALLOC_TX_REQ_ERR,"xE",payload,err);
	return err;
}

static int _rhp_ikev2_stun_payload_bind_alloc_tx_resp(rhp_ikev2_payload* payload, rhp_ikev2_mesg* rx_req_ikemesg)
{
	int err = -EINVAL;
	rhp_ikev2_payload* rx_req_payload;
	rhp_ip_addr def_src_addr;

  RHP_TRC(0,RHPTRCID_IKEV2_STUN_PAYLOAD_BIND_ALLOC_TX_RESP,"xxx",payload,rx_req_ikemesg,rx_req_ikemesg->rx_pkt);

	if( payload->ext.stun->stun_mesg == NULL ){

	  rx_req_payload = rx_req_ikemesg->get_payload(rx_req_ikemesg,RHP_PROTO_IKE_PAYLOAD_RHP_STUN);
	  if( rx_req_payload == NULL ){
	  	err = -ENOENT;
	  	goto error;
	  }

	  {
			memset(&def_src_addr,0,sizeof(rhp_ip_addr));

			err = rx_req_ikemesg->rx_get_src_addr(rx_req_ikemesg,&def_src_addr);
			if( err ){
		  	goto error;
			}
		}

		err = rhp_stun_bind_tx_new_resp_mesg(rx_req_payload->ext.stun->stun_mesg,&def_src_addr,&(payload->ext.stun->stun_mesg));
		if( err ){
			goto error;
		}

	}else{

		err = -EINVAL;
		RHP_BUG("");
	}

  RHP_TRC(0,RHPTRCID_IKEV2_STUN_PAYLOAD_BIND_ALLOC_TX_RESP_RTRN,"xxx",payload,rx_req_ikemesg,payload->ext.stun->stun_mesg);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_STUN_PAYLOAD_BIND_ALLOC_TX_RESP_ERR,"xxE",payload,rx_req_ikemesg,err);
	return err;
}

static int _rhp_ikev2_stun_payload_bind_rx_resp_mapped_addr(rhp_ikev2_payload* payload, rhp_ip_addr** mapped_addr_r)
{
	int err = -EINVAL;

  RHP_TRC(0,RHPTRCID_IKEV2_STUN_PAYLOAD_BIND_RX_RESP_MAPPED_ADDR,"xx",payload,mapped_addr_r);

	if( payload->ext.stun->stun_mesg == NULL ){
		err = -EINVAL;
		goto error;
	}

	err = rhp_stun_bind_resp_attr_mapped_addr(payload->ext.stun->stun_mesg,mapped_addr_r);
	if( err ){
		goto error;
	}

  RHP_TRC(0,RHPTRCID_IKEV2_STUN_PAYLOAD_BIND_RX_RESP_MAPPED_ADDR_RTRN,"xx",payload,*mapped_addr_r);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_STUN_PAYLOAD_BIND_RX_RESP_MAPPED_ADDR_ERR,"xE",payload,err);
	return err;
}

static void _rhp_ikev2_stun_payload_bind_stun_mesg(rhp_ikev2_payload* payload,rhp_stun_mesg* stun_mesg)
{
	RHP_TRC(0,RHPTRCID_IKEV2_STUN_PAYLOAD_BIND_STUN_MESG,"xx",payload,stun_mesg);

	if( payload->ext.stun->stun_mesg ){
		RHP_BUG("");
		return;
	}

	payload->ext.stun->stun_mesg = stun_mesg;

	return;
}

static rhp_stun_mesg* _rhp_ikev2_stun_payload_get_stun_mesg(rhp_ikev2_payload* payload)
{
	RHP_TRC(0,RHPTRCID_IKEV2_STUN_PAYLOAD_GET_STUN_MESG,"xx",payload,payload->ext.stun->stun_mesg);

	return payload->ext.stun->stun_mesg;
}

static rhp_stun_mesg* _rhp_ikev2_stun_payload_unbind_stun_mesg(rhp_ikev2_payload* payload)
{
	rhp_stun_mesg* stun_mesg = payload->ext.stun->stun_mesg;
	payload->ext.stun->stun_mesg = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_STUN_PAYLOAD_UNBIND_STUN_MESG,"xx",payload,stun_mesg);
	return stun_mesg;
}

rhp_ikev2_stun_payload* _rhp_ikev2_alloc_stun_payload()
{
  rhp_ikev2_stun_payload* stun_payload;

  stun_payload = (rhp_ikev2_stun_payload*)_rhp_malloc(sizeof(rhp_ikev2_stun_payload));
  if( stun_payload == NULL ){
  	RHP_BUG("");
    return NULL;
  }

  memset(stun_payload,0,sizeof(rhp_ikev2_stun_payload));

  stun_payload->set_stun_mesg = _rhp_ikev2_stun_payload_bind_stun_mesg;
  stun_payload->unset_stun_mesg = _rhp_ikev2_stun_payload_unbind_stun_mesg;
  stun_payload->get_stun_mesg = _rhp_ikev2_stun_payload_get_stun_mesg;

  stun_payload->bind_alloc_tx_req = _rhp_ikev2_stun_payload_bind_alloc_tx_req;
  stun_payload->bind_alloc_tx_resp = _rhp_ikev2_stun_payload_bind_alloc_tx_resp;
  stun_payload->bind_rx_resp_mapped_addr = _rhp_ikev2_stun_payload_bind_rx_resp_mapped_addr;

  RHP_TRC(0,RHPTRCID_IKEV2_ALLOC_VID_PAYLOAD,"x",stun_payload);
  return stun_payload;
}


int rhp_ikev2_stun_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                 rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_stun_payload* stun_payload;
  rhp_proto_ike_stun_payload* stun_payloadh = (rhp_proto_ike_stun_payload*)payloadh;
	rhp_stun_mesg* stun_mesg = NULL;
  int vlen;

  RHP_TRC(0,RHPTRCID_IKEV2_STUN_PAYLOAD_NEW_RX,"xbxdxp",ikemesg,payload_id,payloadh,payload_len,payload,payload_len,payloadh);

  if( payload_len <= (int)sizeof(rhp_proto_ike_stun_payload) ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_STUN_PAYLOAD_NEW_RX_INVALID_MESG_1,"xdd",ikemesg,payload_len,sizeof(rhp_proto_ike_stun_payload));
    goto error;
  }

  vlen = payload_len - sizeof(rhp_proto_ike_stun_payload);
  if( vlen < (int)sizeof(rhp_proto_stun) ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_STUN_PAYLOAD_NEW_RX_INVALID_MESG_2,"xdd",ikemesg,vlen,sizeof(rhp_proto_stun));
    goto error;
  }

  err = rhp_stun_mesg_new_rx((u8*)(stun_payloadh + 1),vlen,0,&stun_mesg);
	if( err ){
		goto error;
	}

  stun_payload = _rhp_ikev2_alloc_stun_payload();
  if( stun_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.stun = stun_payload;
  payload->ext_destructor = _rhp_ikev2_stun_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_stun_payload_serialize;

  stun_payloadh = (rhp_proto_ike_stun_payload*)_rhp_pkt_pull(ikemesg->rx_pkt,payload_len);
  if( stun_payloadh == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_STUN_PAYLOAD_NEW_RX_INVALID_MESG_3,"x",ikemesg);
    goto error;
  }

  stun_payload->stun_mesg = stun_mesg;
  stun_mesg = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_STUN_PAYLOAD_NEW_RX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }
  if( stun_mesg ){
  	rhp_stun_mesg_free(stun_mesg);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_STUN_PAYLOAD_NEW_RX_ERR,"xE",ikemesg,err);
  return err;
}

int rhp_ikev2_stun_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_stun_payload* stun_payload;

  RHP_TRC(0,RHPTRCID_IKEV2_STUN_PAYLOAD_NEW_TX,"xbx",ikemesg,payload_id,payload);

  stun_payload = _rhp_ikev2_alloc_stun_payload();
  if( stun_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.stun = stun_payload;
  payload->ext_destructor = _rhp_ikev2_stun_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_stun_payload_serialize;

  RHP_TRC(0,RHPTRCID_IKEV2_STUN_PAYLOAD_NEW_TX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_STUN_PAYLOAD_NEW_TX_ERR,"xE",ikemesg,err);
  return err;
}



