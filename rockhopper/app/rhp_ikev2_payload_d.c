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

u8 _rhp_ikev2_d_payload_get_protocol_id(rhp_ikev2_payload* payload)
{
  u8 ret;

  if( payload->payloadh ){

    if( !payload->is_v1 ){
      ret = ((rhp_proto_ike_delete_payload*)payload->payloadh)->protocol_id;
    }else{
      ret = ((rhp_proto_ikev1_d_payload*)payload->payloadh)->protocol_id;
    }

  }else{
    ret = payload->ext.d->protocol_id;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_GET_PROTOCOL_ID,"xb",payload,ret);
  return ret;
}

void _rhp_ikev2_d_payload_set_protocol_id(rhp_ikev2_payload* payload,u8 protocol_id)
{
  payload->ext.d->protocol_id = protocol_id;

  if( !payload->is_v1 ){
		if( protocol_id == RHP_PROTO_IKE_PROTOID_ESP || protocol_id == RHP_PROTO_IKE_PROTOID_AH ){
			payload->ext.d->spi_len = RHP_PROTO_IPSEC_SPI_SIZE;
		}else if( protocol_id == RHP_PROTO_IKE_PROTOID_IKE ){
			payload->ext.d->spi_len = 0;
		}else{
			RHP_BUG("%d",protocol_id);
		}
  }else{
		if( protocol_id == RHP_PROTO_IKEV1_PROP_PROTO_ID_ESP || protocol_id == RHP_PROTO_IKEV1_PROP_PROTO_ID_AH ){
			payload->ext.d->spi_len = RHP_PROTO_IPSEC_SPI_SIZE;
		}else if( protocol_id == RHP_PROTO_IKEV1_PROP_PROTO_ID_ISAKMP ){
			payload->ext.d->spi_len = 0;
		}else{
			RHP_BUG("%d",protocol_id);
		}
  }
  
  RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_SET_PROTOCOL_ID,"xb",payload,protocol_id);
  return;
}

int _rhp_ikev2_d_payload_get_spi_len(rhp_ikev2_payload* payload)
{
  int len;

  if( payload->payloadh ){

    if( !payload->is_v1 ){
			len = ((rhp_proto_ike_delete_payload*)payload->payloadh)->spi_len;
    }else{
			len = ((rhp_proto_ikev1_d_payload*)payload->payloadh)->spi_len;
    }

  }else{
    len = payload->ext.d->spi_len;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_GET_SPI_LEN,"xd",payload,len);
  return len;
}

int _rhp_ikev2_d_payload_get_spis_num(rhp_ikev2_payload* payload)
{
  int num;

  if( payload->payloadh ){

    if( !payload->is_v1 ){
    	num = ntohs(((rhp_proto_ike_delete_payload*)payload->payloadh)->spi_num);
    }else{
    	num = ntohs(((rhp_proto_ikev1_d_payload*)payload->payloadh)->spi_num);
    }

  }else{
    num = payload->ext.d->spis_num;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_GET_SPIS_NUM,"xd",payload,num);
  return num;
}

int _rhp_ikev2_d_payload_get_spis_len(rhp_ikev2_payload* payload)
{
  int len;

  if( payload->payloadh ){

  	len = payload->get_len_rx(payload);

    if( !payload->is_v1 ){
    	len -= sizeof(rhp_proto_ike_delete_payload);
    }else{
    	len -= sizeof(rhp_proto_ikev1_d_payload);
    }

  }else{

  	if( payload->ext.d->spis_num ){

  		len = (payload->ext.d->spis_num * payload->ext.d->spi_len);

  	}else{

  		if( payload->is_v1 ){
      	len = 16;
      }else{
      	len = 0;
      }
  	}
  }

  RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_GET_SPIS_LEN,"xd",payload,len);
  return len;
}

u32* _rhp_ikev2_d_payload_get_spis(rhp_ikev2_payload* payload)
{
  u32* ret;
  int len;

  if( payload->payloadh ){

    if( !payload->is_v1 ){
    	ret = ((u32*)(((rhp_proto_ike_delete_payload*)payload->payloadh) + 1));
    }else{
    	ret = ((u32*)(((rhp_proto_ikev1_d_payload*)payload->payloadh) + 1));
    }

  }else{
    ret = payload->ext.d->spis;
  }

  len = _rhp_ikev2_d_payload_get_spis_len(payload);

  RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_GET_SPIS,"xp",payload,len,ret);
  return ret;
}

int _rhp_ikev2_d_payload_set_spi(rhp_ikev2_payload* payload,u32 spi)
{
  u32* buf;	
  int buf_len;

  RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_SET_SPI,"xH",payload,spi);
  
  buf_len = sizeof(u32)*(payload->ext.d->spis_num + 1);

  buf = (u32*)_rhp_malloc(buf_len);
  if( buf == NULL ){
  	RHP_BUG("");
   return -ENOMEM;    	 
  }

  memset(buf,0,buf_len);

  if( payload->ext.d->spis ){
  	memcpy(buf,payload->ext.d->spis,payload->ext.d->spis_len);
    _rhp_free(payload->ext.d->spis);
  }

  buf[payload->ext.d->spis_num] = spi;
  
  payload->ext.d->spis = buf;
  payload->ext.d->spis_len = buf_len;
  payload->ext.d->spis_num++;

  RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_SET_SPI_RTRN,"xHdp",payload,spi,payload->ext.d->spis_num,payload->ext.d->spis_len,payload->ext.d->spis);
  return 0;
}

u8* _rhp_ikev2_d_payload_v1_get_ikesa_spi(rhp_ikev2_payload* payload)
{
  u8* ret;
  int len;

  if( !payload->is_v1 ){
  	RHP_BUG("");
  	return NULL;
  }

  if( payload->payloadh ){

  	ret = ((u8*)(((rhp_proto_ikev1_d_payload*)payload->payloadh) + 1));

  }else{

  	ret = payload->ext.d->v1_ikesa_spi;
  }

  len = _rhp_ikev2_d_payload_get_spis_len(payload);

  RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_V1_GET_IKESA_SPI,"xp",payload,len,ret);
  return ret;
}

int _rhp_ikev2_d_payload_v1_set_ikesa_spi(rhp_ikev2_payload* payload,u8* init_cookie,u8* resp_cookie)
{
  RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_V1_SET_IKESA_SPI,"xpp",payload,8,init_cookie,8,resp_cookie);

  if( !payload->is_v1 ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  if( payload->ext.d->spis ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  memcpy(payload->ext.d->v1_ikesa_spi,init_cookie,8);
  memcpy((payload->ext.d->v1_ikesa_spi + 8),resp_cookie,8);

  RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_V1_SET_IKESA_SPI_RTRN,"xp",payload,16,payload->ext.d->v1_ikesa_spi);
  return 0;
}


rhp_ikev2_d_payload* _rhp_ikev2_alloc_d_payload()
{
  rhp_ikev2_d_payload* d_payload;

  d_payload = (rhp_ikev2_d_payload*)_rhp_malloc(sizeof(rhp_ikev2_d_payload));
  if( d_payload == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(d_payload,0,sizeof(rhp_ikev2_d_payload));

  d_payload->get_protocol_id = _rhp_ikev2_d_payload_get_protocol_id;
  d_payload->set_protocol_id = _rhp_ikev2_d_payload_set_protocol_id;
  d_payload->get_spi_len = _rhp_ikev2_d_payload_get_spi_len;
  d_payload->get_spis_num = _rhp_ikev2_d_payload_get_spis_num;
  d_payload->get_spis_len = _rhp_ikev2_d_payload_get_spis_len;
  d_payload->get_spis = _rhp_ikev2_d_payload_get_spis;
  d_payload->set_spi = _rhp_ikev2_d_payload_set_spi;
  d_payload->v1_get_ikesa_spi = _rhp_ikev2_d_payload_v1_get_ikesa_spi;
  d_payload->v1_set_ikesa_spi = _rhp_ikev2_d_payload_v1_set_ikesa_spi;

  RHP_TRC(0,RHPTRCID_IKEV2_ALLOC_D_PAYLOAD,"x",d_payload);
  return d_payload;
}


static void _rhp_ikev2_d_payload_destructor(rhp_ikev2_payload* payload)
{
  RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_DESTRUCTOR,"x",payload);

  if( payload->ext.d->spis ){
    _rhp_free(payload->ext.d->spis);
    payload->ext.d->spis = NULL;
    payload->ext.d->spis_len = 0;
    payload->ext.d->spis_num = 0;
  }
  
  return;
}

static int _rhp_ikev2_d_payload_serialize(rhp_ikev2_payload* payload,rhp_packet* pkt)
{
  int len;
  union {
  	rhp_proto_ike_payload* raw;
  	rhp_proto_ikev1_d_payload* v1;
  	rhp_proto_ike_delete_payload* v2;
  } p;

  RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_SERIALIZE,"xx",payload,pkt);

  if( !payload->is_v1 ){

  	len = sizeof(rhp_proto_ike_delete_payload) + payload->ext.d->spis_len;

  }else{

  	len = sizeof(rhp_proto_ikev1_d_payload);
  	if( payload->ext.d->spis_len ){
  		len += payload->ext.d->spis_len;
  	}else{
  		len += 16;
  	}
  }
  
  p.raw = (rhp_proto_ike_payload*)rhp_pkt_expand_tail(pkt,len);
  if( p.raw == NULL ){
  	RHP_BUG("");
   return -ENOMEM;
  }

  if( !payload->is_v1 ){

		p.v2->critical_rsv = RHP_PROTO_IKE_PLD_SET_CRITICAL;
		p.v2->protocol_id = payload->ext.d->protocol_id;
		p.v2->spi_len = payload->ext.d->spi_len;
		p.v2->spi_num = htons(payload->ext.d->spis_num);

		if( payload->ext.d->spis_len ){
			memcpy((p.v2 + 1),payload->ext.d->spis,payload->ext.d->spis_len);
		}

  }else{

		p.v1->reserved = 0;
		p.v1->doi = htonl(RHP_PROTO_IKEV1_DOI_IPSEC);

		p.v1->protocol_id = payload->ext.d->protocol_id;

		if( payload->ext.d->spis_len ){

			p.v1->spi_len = payload->ext.d->spi_len;
			p.v1->spi_num = htons(payload->ext.d->spis_num);
			memcpy((p.v1 + 1),payload->ext.d->spis,payload->ext.d->spis_len);

		}else{

			p.v1->spi_len = 16;
			p.v1->spi_num = htons(1);
			memcpy((p.v1 + 1),payload->ext.d->v1_ikesa_spi,16);
		}
  }

	p.raw->len = htons(len);

  payload->ikemesg->tx_mesg_len += len;
  
  p.raw->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
  if( payload->next ){
    p.raw->next_payload = payload->next->get_payload_id(payload->next);
  }
    
  RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_SERIALIZE_RTRN,"xx",payload,pkt);
  rhp_pkt_trace_dump("_rhp_ikev2_d_payload_serialize",pkt);
  return 0;
}

int rhp_ikev2_d_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                               rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_d_payload* d_payload;
  union {
  	rhp_proto_ike_payload* raw;
  	rhp_proto_ikev1_d_payload* v1;
  	rhp_proto_ike_delete_payload* v2;
  } d_payloadh;
  int spis_len;

  RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_NEW_RX,"xbxdxp",ikemesg,payload_id,payloadh,payload_len,payload,payload_len,payloadh);

  d_payloadh.raw = payloadh;


  if( !ikemesg->is_v1 ){

		if( payload_len < (int)sizeof(rhp_proto_ike_delete_payload) ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_NEW_RX_INVALID_MESG_1,"xdd",ikemesg,payload_len,sizeof(rhp_proto_ike_delete_payload));
			goto error;
		}

		spis_len = payload_len - sizeof(rhp_proto_ike_delete_payload);

		if( d_payloadh.v2->protocol_id == RHP_PROTO_IKE_PROTOID_IKE ){

			if( spis_len != 0 || d_payloadh.v2->spi_len != 0 || ntohs(d_payloadh.v2->spi_num) != 0 ){
				RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_NEW_RX_INVALID_MESG_2,"xddw",ikemesg,spis_len,d_payloadh.v2->spi_len,ntohs(d_payloadh.v2->spi_num));
				err = RHP_STATUS_INVALID_MSG;
				goto error;
			}

		}else if( d_payloadh.v2->protocol_id == RHP_PROTO_IKE_PROTOID_ESP ||
							d_payloadh.v2->protocol_id == RHP_PROTO_IKE_PROTOID_AH ){

			u16 spi_num = ntohs(d_payloadh.v2->spi_num);

			if( spi_num == 0 ){
				err = RHP_STATUS_INVALID_MSG;
				RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_NEW_RX_INVALID_MESG_3,"xbd",ikemesg,d_payloadh.v2->spi_len,RHP_PROTO_IPSEC_SPI_SIZE);
				goto error;
			}

			if( d_payloadh.v2->spi_len != RHP_PROTO_IPSEC_SPI_SIZE ){
				err = RHP_STATUS_INVALID_MSG;
				RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_NEW_RX_INVALID_MESG_4,"xbd",ikemesg,d_payloadh.v2->spi_len,RHP_PROTO_IPSEC_SPI_SIZE);
				goto error;
			}

			if( spis_len != spi_num*RHP_PROTO_IPSEC_SPI_SIZE ){
				RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_NEW_RX_INVALID_MESG_5,"xdd",ikemesg,spis_len,(int)(spi_num*RHP_PROTO_IPSEC_SPI_SIZE));
				err = RHP_STATUS_INVALID_MSG;
				goto error;
			}
		}

  }else{

  	u16 spi_num;

		if( payload_len < (int)sizeof(rhp_proto_ikev1_d_payload) ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_NEW_RX_INVALID_MESG_V1_1,"xdd",ikemesg,payload_len,sizeof(rhp_proto_ike_delete_payload));
			goto error;
		}


		spis_len = payload_len - sizeof(rhp_proto_ikev1_d_payload);

		spi_num = ntohs(d_payloadh.v1->spi_num);
		if( spi_num == 0 ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_NEW_RX_INVALID_MESG_V1_2,"xw",ikemesg,spi_num);
			goto error;
		}

		if( d_payloadh.v1->protocol_id == RHP_PROTO_IKEV1_PROP_PROTO_ID_ISAKMP ){

			if( d_payloadh.v1->spi_len != 16 ){
				RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_NEW_RX_INVALID_MESG_V1_3,"xdd",ikemesg,spis_len,d_payloadh.v1->spi_len);
				err = RHP_STATUS_INVALID_MSG;
				goto error;
			}

			if( spis_len != spi_num*16 ){
				RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_NEW_RX_INVALID_MESG_V1_4,"xdd",ikemesg,spis_len,(int)(spi_num*16));
				err = RHP_STATUS_INVALID_MSG;
				goto error;
			}

		}else if( d_payloadh.v1->protocol_id == RHP_PROTO_IKEV1_PROP_PROTO_ID_ESP ||
							d_payloadh.v1->protocol_id == RHP_PROTO_IKEV1_PROP_PROTO_ID_AH ){


			if( d_payloadh.v1->spi_len != RHP_PROTO_IPSEC_SPI_SIZE ){
				err = RHP_STATUS_INVALID_MSG;
				RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_NEW_RX_INVALID_MESG_V1_5,"xbd",ikemesg,d_payloadh.v1->spi_len,RHP_PROTO_IPSEC_SPI_SIZE);
				goto error;
			}

			if( spis_len != spi_num*RHP_PROTO_IPSEC_SPI_SIZE ){
				RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_NEW_RX_INVALID_MESG_V1_6,"xdd",ikemesg,spis_len,(int)(spi_num*RHP_PROTO_IPSEC_SPI_SIZE));
				err = RHP_STATUS_INVALID_MSG;
				goto error;
			}
		}
  }

  d_payload = _rhp_ikev2_alloc_d_payload();
  if( d_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.d = d_payload;
  payload->ext_destructor = _rhp_ikev2_d_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_d_payload_serialize;

  if( !ikemesg->is_v1 ){

		d_payloadh.v2 = (rhp_proto_ike_delete_payload*)_rhp_pkt_pull(ikemesg->rx_pkt,payload_len);
		if( d_payloadh.v2 == NULL ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_NEW_RX_INVALID_MESG_6,"x",ikemesg);
			goto error;
		}

  }else{

		d_payloadh.v1 = (rhp_proto_ikev1_d_payload*)_rhp_pkt_pull(ikemesg->rx_pkt,payload_len);
		if( d_payloadh.v1 == NULL ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_NEW_RX_INVALID_MESG_V1_6,"x",ikemesg);
			goto error;
		}
  }

	RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_NEW_RX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_NEW_RX_ERR,"xE",ikemesg,err);
  return err;
}

int rhp_ikev2_d_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_d_payload* d_payload;

  RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_NEW_TX,"xLbx",ikemesg,"PROTO_IKE_PAYLOAD",payload_id,payload);

  d_payload = _rhp_ikev2_alloc_d_payload();
  if( d_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.d = d_payload;
  payload->ext_destructor = _rhp_ikev2_d_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_d_payload_serialize;

  RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_NEW_TX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_D_PAYLOAD_NEW_TX_ERR,"xd",ikemesg,err);
  return err;
}

