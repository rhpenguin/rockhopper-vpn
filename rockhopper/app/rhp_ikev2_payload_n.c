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
#include "rhp_ikev2.h"

static u8 _rhp_ikev2_n_payload_get_protocol_id(rhp_ikev2_payload* payload)
{
  u8 ret;

  if( payload->payloadh ){

  	if( !payload->is_v1 ){
  		ret = ((rhp_proto_ike_notify_payload*)payload->payloadh)->protocol_id;
  	}else{
  		ret = ((rhp_proto_ikev1_n_payload*)payload->payloadh)->protocol_id;
  	}

  }else{

  	ret = payload->ext.n->protocol_id;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_GET_PROTOCOL_ID,"xdxLb",payload,payload->is_v1,payload->payloadh,(!payload->is_v1 ? "PROTO_IKE_PROTOID" : "PROTO_IKEV1_PROTOID"),ret);
  return ret;
}

static void _rhp_ikev2_n_payload_set_protocol_id(rhp_ikev2_payload* payload,u8 protocol_id)
{
  payload->ext.n->protocol_id = protocol_id;
  RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_SET_PROTOCOL_ID,"xLb",payload,"PROTO_IKE_PROTOID",protocol_id);
  return;
}

static int _rhp_ikev2_n_payload_get_spi_len(rhp_ikev2_payload* payload)
{
  int len;

  if( payload->payloadh ){

  	if( !payload->is_v1 ){
  		len = ((rhp_proto_ike_notify_payload*)payload->payloadh)->spi_len;
  	}else{
  		len = ((rhp_proto_ikev1_n_payload*)payload->payloadh)->spi_len;
  	}

  }else{
    len = payload->ext.n->spi_len;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_GET_SPI_LEN,"xdxd",payload,payload->is_v1,payload->payloadh,len);
  return len;
}

static u32 _rhp_ikev2_n_payload_get_spi(rhp_ikev2_payload* payload)
{
  u32 ret = 0;

  if( payload->payloadh ){

  	if( !payload->is_v1 ){
  		if( ((rhp_proto_ike_notify_payload*)payload->payloadh) ){
  			ret = *((u32*)(((rhp_proto_ike_notify_payload*)payload->payloadh) + 1));
  		}
  	}else{
  		if( ((rhp_proto_ikev1_n_payload*)payload->payloadh) ){
  			ret = *((u32*)(((rhp_proto_ikev1_n_payload*)payload->payloadh) + 1));
  		}
  	}

  }else{
    ret = payload->ext.n->spi;
  }
  RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_GET_SPI,"xdxH",payload,payload->is_v1,payload->payloadh,ret);
  return ret;
}

static void _rhp_ikev2_n_payload_set_spi(rhp_ikev2_payload* payload,u32 spi)
{
  payload->ext.n->spi_len = RHP_PROTO_IPSEC_SPI_SIZE;
  payload->ext.n->spi = spi;
  RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_SET_SPI,"xdH",payload,RHP_PROTO_IPSEC_SPI_SIZE,spi);
  return;
}

static u16 _rhp_ikev2_n_payload_get_message_type(rhp_ikev2_payload* payload)
{
  u16 ret;

  if( payload->payloadh ){

  	if( !payload->is_v1 ){
  		ret = ntohs(((rhp_proto_ike_notify_payload*)payload->payloadh)->notify_mesg_type);
  	}else{
  		ret = ntohs(((rhp_proto_ikev1_n_payload*)payload->payloadh)->notify_mesg_type);
  	}

  }else{
    ret = payload->ext.n->message_type;
  }
  RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_GET_MESSAGE_TYPE,"xdxLd",payload,payload->is_v1,payload->payloadh,(!payload->is_v1 ? "PROTO_IKE_NOTIFY" : "PROTO_IKEV1_NOTIFY"),(int)ret);
  return ret;
}

static void _rhp_ikev2_n_payload_set_message_type(rhp_ikev2_payload* payload,u16 message_type)
{
  payload->ext.n->message_type = message_type;
  RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_SET_MESSAGE_TYPE,"xdLd",payload,payload->is_v1,(!payload->is_v1 ? "PROTO_IKE_NOTIFY" : "PROTO_IKEV1_NOTIFY"),(int)message_type);

  if( !payload->is_v1 ){
		if( payload->ikemesg &&
				 message_type >= RHP_PROTO_IKE_NOTIFY_ERR_MIN && message_type <= RHP_PROTO_IKE_NOTIFY_ERR_PRIV_END ){

			payload->ikemesg->put_n_payload_err++;
			RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_SET_MESSAGE_TYPE_PUT_N_ERR,"xxLb",payload->ikemesg,payload,"PROTO_IKE_PAYLOAD",payload->payload_id);
		}
  }else{
		if( payload->ikemesg &&
				 message_type >= RHP_PROTO_IKEV1_N_ERR_MIN && message_type <= RHP_PROTO_IKEV1_N_ERR_END ){

			payload->ikemesg->put_n_payload_err++;
			RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_SET_MESSAGE_TYPE_PUT_V1_N_ERR,"xxLb",payload->ikemesg,payload,"PROTO_IKE_PAYLOAD",payload->payload_id);
		}
  }

  return;
}

static int _rhp_ikev2_n_payload_get_data_len(rhp_ikev2_payload* payload)
{
  int len;

  if( payload->payloadh ){

    len = payload->get_len_rx(payload);

  	if( !payload->is_v1 ){
	    len -= sizeof(rhp_proto_ike_notify_payload)
	    			 + ((rhp_proto_ike_notify_payload*)payload->payloadh)->spi_len;
  	}else{
	    len -= sizeof(rhp_proto_ikev1_n_payload)
	    			 + ((rhp_proto_ikev1_n_payload*)payload->payloadh)->spi_len;
  	}

  }else{

    len = payload->ext.n->data_len;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_GET_DATA_LEN,"xdxd",payload,payload->is_v1,payload->payloadh,len);
  return len;
}

static u8* _rhp_ikev2_n_payload_get_data(rhp_ikev2_payload* payload)
{
  u8* data;
  int data_len;

  if( payload->payloadh ){

  	if( !payload->is_v1 ){
    	data = ((u8*)(((rhp_proto_ike_notify_payload*)payload->payloadh) + 1))
    				 + ((rhp_proto_ike_notify_payload*)payload->payloadh)->spi_len;
  	}else{
    	data = ((u8*)(((rhp_proto_ikev1_n_payload*)payload->payloadh) + 1))
    				 + ((rhp_proto_ikev1_n_payload*)payload->payloadh)->spi_len;
  	}

  }else{
  	data = payload->ext.n->data;
  }

  data_len = _rhp_ikev2_n_payload_get_data_len(payload);
  
  RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_GET_DATA,"xdxp",payload,payload->is_v1,payload->payloadh,data_len,data);
  return data;
}

static int _rhp_ikev2_n_payload_set_data(rhp_ikev2_payload* payload,int data_len,u8* data)
{
  RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_SET_DATA,"xp",payload,data_len,data);
	
	if( payload->ext.n->data ){
    _rhp_free(payload->ext.n->data);
  }
  
  payload->ext.n->data = (u8*)_rhp_malloc(data_len);
  if( payload->ext.n->data == NULL ){
    RHP_BUG("");
    payload->ext.n->data_len = 0;
    return -ENOMEM;
  }
  
  memcpy(payload->ext.n->data,data,data_len);
  payload->ext.n->data_len = data_len;
  
  return 0;
}

static int _rhp_ikev2_n_payload_set_data2(rhp_ikev2_payload* payload,
		int data0_len,u8* data0,int data1_len,u8* data1)
{
	u8* p = NULL;
  RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_SET_DATA,"xpp",payload,data0_len,data0,data1_len,data1);

	if( payload->ext.n->data ){
    _rhp_free(payload->ext.n->data);
  }

  payload->ext.n->data = (u8*)_rhp_malloc(data0_len + data1_len);
  if( payload->ext.n->data == NULL ){
    RHP_BUG("");
    payload->ext.n->data_len = 0;
    return -ENOMEM;
  }

  p = payload->ext.n->data;

  if( data0_len && data0 ){
  	memcpy(p,data0,data0_len);
  	p += data0_len;
  }

  if( data1_len && data1 ){
  	memcpy(p,data1,data1_len);
  	p += data1_len;
  }

  payload->ext.n->data_len = (data0_len + data1_len);

  return 0;
}

u8* _rhp_ikev2_n_payload_v1_get_ikesa_spi(rhp_ikev2_payload* payload)
{
  u8* ret;
  int len;

  if( !payload->is_v1 ){
  	RHP_BUG("");
  	return NULL;
  }

  if( payload->payloadh ){

  	ret = ((u8*)(((rhp_proto_ikev1_d_payload*)payload->payloadh) + 1));
  	len = payload->get_len_rx(payload) - sizeof(rhp_proto_ikev1_d_payload);

  }else{

  	ret = payload->ext.n->v1_ikesa_spi;
  	len = 16;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_V1_GET_IKESA_SPI,"xp",payload,len,ret);
  return ret;
}

int _rhp_ikev2_n_payload_v1_set_ikesa_spi(rhp_ikev2_payload* payload,u8* init_cookie,u8* resp_cookie)
{
  RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_V1_SET_IKESA_SPI,"xpp",payload,8,init_cookie,8,resp_cookie);

  if( !payload->is_v1 ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  if( payload->ext.n->spi_len ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  memcpy(payload->ext.n->v1_ikesa_spi,init_cookie,8);
  memcpy((payload->ext.n->v1_ikesa_spi + 8),resp_cookie,8);

  RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_V1_SET_IKESA_SPI_RTRN,"xp",payload,16,payload->ext.n->v1_ikesa_spi);
  return 0;
}

static rhp_ikev2_n_payload* _rhp_ikev2_alloc_n_payload()
{
  rhp_ikev2_n_payload* n_payload;

  n_payload = (rhp_ikev2_n_payload*)_rhp_malloc(sizeof(rhp_ikev2_n_payload));
  if( n_payload == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(n_payload,0,sizeof(rhp_ikev2_n_payload));

  n_payload->get_protocol_id = _rhp_ikev2_n_payload_get_protocol_id;
  n_payload->set_protocol_id = _rhp_ikev2_n_payload_set_protocol_id;
  n_payload->get_spi_len = _rhp_ikev2_n_payload_get_spi_len;
  n_payload->get_spi = _rhp_ikev2_n_payload_get_spi;
  n_payload->set_spi = _rhp_ikev2_n_payload_set_spi;
  n_payload->get_message_type = _rhp_ikev2_n_payload_get_message_type;
  n_payload->set_message_type = _rhp_ikev2_n_payload_set_message_type;
  n_payload->get_data_len = _rhp_ikev2_n_payload_get_data_len;
  n_payload->get_data = _rhp_ikev2_n_payload_get_data;
  n_payload->set_data = _rhp_ikev2_n_payload_set_data;
  n_payload->set_data2 = _rhp_ikev2_n_payload_set_data2;
  n_payload->v1_get_ikesa_spi = _rhp_ikev2_n_payload_v1_get_ikesa_spi;
  n_payload->v1_set_ikesa_spi = _rhp_ikev2_n_payload_v1_set_ikesa_spi;

  RHP_TRC(0,RHPTRCID_IKEV2_ALLOC_N_PAYLOAD,"x",n_payload);
  return n_payload;
}


static void _rhp_ikev2_n_payload_destructor(rhp_ikev2_payload* payload)
{
  RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_DESTRUCTOR,"xxx",payload,payload->ext.n,payload->ext.n->data);

	if( payload->ext.n->data ){
    _rhp_free(payload->ext.n->data);
    payload->ext.n->data = NULL;
    payload->ext.n->data_len = 0;
  }
	
	return;
}

static int _rhp_ikev2_n_payload_serialize(rhp_ikev2_payload* payload,rhp_packet* pkt)
{
  int len;
  union {
  	rhp_proto_ike_payload* raw;
  	rhp_proto_ikev1_n_payload* v1;
  	rhp_proto_ike_notify_payload* v2;
  } p;

  RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_SERIALIZE,"xx",payload,pkt);

  if( !payload->is_v1 ){
  	len = sizeof(rhp_proto_ike_notify_payload) + payload->ext.n->spi_len + payload->ext.n->data_len;
  }else{
  	len = sizeof(rhp_proto_ikev1_n_payload) + payload->ext.n->data_len;
  	if( payload->ext.n->spi_len ){
  		len += payload->ext.n->spi_len;
  	}else{
  		len += 16;
  	}
  }
  
  p.raw = (rhp_proto_ike_payload*)rhp_pkt_expand_tail(pkt,len);
  if( p.raw == NULL ){
  	RHP_BUG("len:%d",len);
  	return -ENOMEM;
  }


  if( !payload->is_v1 ){

  	if( payload->non_critical ){
			p.v2->critical_rsv = 0;
		}else{
			p.v2->critical_rsv = RHP_PROTO_IKE_PLD_SET_CRITICAL;
		}

		p.v2->protocol_id = payload->ext.n->protocol_id;
		p.v2->spi_len = payload->ext.n->spi_len;
		p.v2->notify_mesg_type = htons(payload->ext.n->message_type);

		if( payload->ext.n->spi_len ){
			*((u32*)(p.v2 + 1)) = payload->ext.n->spi;
		}

		if( payload->ext.n->data_len ){
			memcpy(((u8*)(p.v2 + 1)) + payload->ext.n->spi_len,payload->ext.n->data,payload->ext.n->data_len);
		}

  }else{

  	p.v1->reserved = 0;
		p.v1->doi = htonl(RHP_PROTO_IKEV1_DOI_IPSEC);
		p.v1->protocol_id = payload->ext.n->protocol_id;
  	if( payload->ext.n->spi_len ){
  		p.v1->spi_len = payload->ext.n->spi_len;
  	}else{
  		p.v1->spi_len = 16;
  	}
		p.v1->notify_mesg_type = htons(payload->ext.n->message_type);

		if( payload->ext.n->spi_len ){
			*((u32*)(p.v1 + 1)) = payload->ext.n->spi;
		}else{
			memcpy((p.v1 + 1),payload->ext.n->v1_ikesa_spi,16);
		}

		if( payload->ext.n->data_len ){
			memcpy(((u8*)(p.v1 + 1)) + p.v1->spi_len,payload->ext.n->data,payload->ext.n->data_len);
		}
  }

  p.raw->len = htons(len);
  
  payload->ikemesg->tx_mesg_len += len;
  
  p.raw->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
  if( payload->next ){
    p.raw->next_payload = payload->next->get_payload_id(payload->next);
  }
    
  if( !payload->is_v1 ){
		if( payload->ext.n->message_type >= RHP_PROTO_IKE_NOTIFY_ERR_MIN && payload->ext.n->message_type <= RHP_PROTO_IKE_NOTIFY_ERR_PRIV_END ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_TX_ERR_NOTIFY,"KL",payload->ikemesg,"PROTO_IKE_NOTIFY",(int)payload->ext.n->message_type);
		}
  }else{
		if( payload->ext.n->message_type >= RHP_PROTO_IKEV1_N_ERR_MIN && payload->ext.n->message_type <= RHP_PROTO_IKEV1_N_ERR_END ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKEV1_TX_ERR_NOTIFY,"KL",payload->ikemesg,"PROTO_IKEV1_NOTIFY",(int)payload->ext.n->message_type);
		}
  }

  RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_SERIALIZE_RTRN,"xx",payload,pkt);
  rhp_pkt_trace_dump("_rhp_ikev2_n_payload_serialize",pkt);

  return 0;
}

int rhp_ikev2_n_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                 rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_n_payload* n_payload;
  union {
  	rhp_proto_ike_payload* raw;
  	rhp_proto_ikev1_n_payload* v1;
  	rhp_proto_ike_notify_payload* v2;
  } n_payloadh;
  u16 mesg_type = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_NEW_RX,"xdbxdxp",ikemesg,ikemesg->is_v1,payload_id,payloadh,payload_len,payload,payload_len,payloadh);

  n_payloadh.raw = payloadh;

  if( !ikemesg->is_v1 ){

  	if( payload_len < (int)sizeof(rhp_proto_ike_notify_payload) ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_NEW_RX_INVALID_MESG_1,"xdd",ikemesg,payload_len,sizeof(rhp_proto_ike_notify_payload));
			goto error;
		}

	  mesg_type = ntohs(n_payloadh.v2->notify_mesg_type);

  }else{

		if( payload_len < (int)sizeof(rhp_proto_ikev1_n_payload) ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_NEW_RX_INVALID_MESG_V1_1,"xdd",ikemesg,payload_len,sizeof(rhp_proto_ikev1_n_payload));
			goto error;
		}

	  mesg_type = ntohs(n_payloadh.v1->notify_mesg_type);
  }


  n_payload = _rhp_ikev2_alloc_n_payload();
  if( n_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  if( !ikemesg->is_v1 ){
		if( mesg_type >= RHP_PROTO_IKE_NOTIFY_ERR_MIN && mesg_type <= RHP_PROTO_IKE_NOTIFY_ERR_PRIV_END ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_RX_ERR_NOTIFY,"KL",ikemesg,"PROTO_IKE_NOTIFY",(int)mesg_type);
		}
  }else{
		if( mesg_type >= RHP_PROTO_IKEV1_N_ERR_MIN && mesg_type <= RHP_PROTO_IKEV1_N_ERR_END ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKEV1_RX_ERR_NOTIFY,"KL",ikemesg,"PROTO_IKEV1_NOTIFY",(int)mesg_type);
		}
  }

  payload->ext.n = n_payload;
  payload->ext_destructor = _rhp_ikev2_n_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_n_payload_serialize;

  n_payloadh.raw = (rhp_proto_ike_payload*)_rhp_pkt_pull(ikemesg->rx_pkt,payload_len);
  if( n_payloadh.raw == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_NEW_RX_INVALID_MESG_2,"x",ikemesg);
    goto error;
  }


  if( !ikemesg->is_v1 &&
  		mesg_type == RHP_PROTO_IKE_NOTIFY_ST_REKEY_SA ){

  	ikemesg->for_rekey_req = 1;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_NEW_RX_RTRN,"xxxLw",ikemesg,payload,n_payload,(!ikemesg->is_v1 ? "PROTO_IKE_NOTIFY" : "PROTO_IKEV1_NOTIFY"),mesg_type);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_NEW_RX_ERR,"xLwE",ikemesg,(!ikemesg->is_v1 ? "PROTO_IKE_NOTIFY" : "PROTO_IKEV1_NOTIFY"),mesg_type,err);
  return err;
}

int rhp_ikev2_n_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_n_payload* n_payload;

  RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_NEW_TX,"xLbx",ikemesg,"PROTO_IKE_PAYLOAD",payload_id,payload);

  n_payload = _rhp_ikev2_alloc_n_payload();
  if( n_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.n = n_payload;
  payload->ext_destructor = _rhp_ikev2_n_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_n_payload_serialize;

  RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_NEW_TX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_N_PAYLOAD_NEW_TX_ERR,"xxxE",ikemesg,payload,n_payload,err);
  return err;
}

