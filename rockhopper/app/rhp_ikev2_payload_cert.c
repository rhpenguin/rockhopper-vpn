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

static int _rhp_ikev2_cert_payload_get_cert_len(rhp_ikev2_payload* payload)
{
  int len;
  if( payload->ext.cert->cert ){
    len = payload->ext.cert->cert_len;
  }else{
    len = payload->get_len_rx(payload);
    len -= sizeof(rhp_proto_ike_cert_payload);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_CERT_PAYLOAD_GET_CERT_LEN,"xxd",payload,payload->ext.cert->cert,len);
  return len;
}

static u8* _rhp_ikev2_cert_payload_get_cert(rhp_ikev2_payload* payload)
{
  u8* ret;
  rhp_proto_ike_cert_payload* cert_payloadh;
  int len = _rhp_ikev2_cert_payload_get_cert_len(payload);

  if( payload->ext.cert->cert ){
    ret = payload->ext.cert->cert;
  }else{
    if( len ){
      cert_payloadh = (rhp_proto_ike_cert_payload*)(payload->payloadh);
      ret = (u8*)(cert_payloadh + 1);
    }else{
      ret = NULL;
    }
  }
  RHP_TRC(0,RHPTRCID_IKEV2_CERT_PAYLOAD_GET_CERT,"xxxp",payload,payload->ext.cert->cert,ret,len,ret);
  return ret;
}

static u8 _rhp_ikev2_cert_payload_get_cert_encoding(rhp_ikev2_payload* payload)
{
  u8 ret;
  rhp_proto_ike_cert_payload* cert_payloadh;

  if( payload->ext.cert->cert_encoding ){
    ret = payload->ext.cert->cert_encoding;
  }else{
    cert_payloadh = (rhp_proto_ike_cert_payload*)(payload->payloadh);
    ret = cert_payloadh->cert_encoding;
  }
  RHP_TRC(0,RHPTRCID_IKEV2_CERT_PAYLOAD_GET_CERT_ENCODING,"xb",payload,ret);
  return ret;
}

static void _rhp_ikev2_cert_payload_set_cert_encoding(rhp_ikev2_payload* payload,u8 cert_encoding)
{
  payload->ext.cert->cert_encoding = cert_encoding;

  RHP_TRC(0,RHPTRCID_IKEV2_CERT_PAYLOAD_SET_CERT_ENCODING,"xb",payload,cert_encoding);
  return;
}

static void _rhp_ikev2_cert_payload_destructor(rhp_ikev2_payload* payload)
{
  RHP_TRC(0,RHPTRCID_IKEV2_CERT_PAYLOAD_DESTRUCTOR,"xx",payload,payload->ext.cert->cert);

  if( payload->ext.cert->cert ){
    _rhp_free(payload->ext.cert->cert);
    payload->ext.cert->cert = NULL;
    payload->ext.cert->cert_len = 0;
  }
  return;
}

static int _rhp_ikev2_cert_payload_serialize(rhp_ikev2_payload* payload,rhp_packet* pkt)
{
  int len;
  rhp_proto_ike_cert_payload* p;

  RHP_TRC(0,RHPTRCID_IKEV2_CERT_PAYLOAD_SERIALIZE,"xx",payload,pkt);

  if( payload->ext.cert->cert == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  len = sizeof(rhp_proto_ike_cert_payload) + payload->ext.cert->cert_len;

  p = (rhp_proto_ike_cert_payload*)rhp_pkt_expand_tail(pkt,len);
  if( p == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  p->next_payload = payload->get_next_payload(payload);
  if( payload->is_v1 ){
  	p->critical_rsv = 0;
  }else{
  	p->critical_rsv = RHP_PROTO_IKE_PLD_SET_CRITICAL;
  }
  p->len = htons(len);
  p->cert_encoding = payload->ext.cert->cert_encoding;

  if( payload->ext.cert->cert ){
    memcpy((p + 1),payload->ext.cert->cert,payload->ext.cert->cert_len);
  }

  payload->ikemesg->tx_mesg_len += len;

  p->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
  if( payload->next ){
    p->next_payload = payload->next->get_payload_id(payload->next);
  }
    
  RHP_TRC(0,RHPTRCID_IKEV2_CERT_PAYLOAD_SERIALIZE_RTRN,"");
  rhp_pkt_trace_dump("_rhp_ikev2_cert_payload_serialize(1)",pkt);
  return 0;
}

static int _rhp_ikev2_cert_payload_set_cert(rhp_ikev2_payload* payload,int cert_len,u8* cert)
{
  RHP_TRC(0,RHPTRCID_IKEV2_CERT_PAYLOAD_SET_CERT,"xp",payload,cert_len,cert);

  if( payload->ext.cert->cert ){
    RHP_BUG("");
    return -EEXIST;
  }

  payload->ext.cert->cert = (u8*)_rhp_malloc(cert_len);
  if( payload->ext.cert->cert == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  memcpy(payload->ext.cert->cert,cert,cert_len);
  payload->ext.cert->cert_len = cert_len;

  return 0;
}

static rhp_ikev2_cert_payload* _rhp_ikev2_alloc_cert_payload()
{
  rhp_ikev2_cert_payload* cert_payload;

  cert_payload = (rhp_ikev2_cert_payload*)_rhp_malloc(sizeof(rhp_ikev2_cert_payload));
  if( cert_payload == NULL ){
    return NULL;
  }

  memset(cert_payload,0,sizeof(rhp_ikev2_cert_payload));

  cert_payload->get_cert_len = _rhp_ikev2_cert_payload_get_cert_len;
  cert_payload->get_cert = _rhp_ikev2_cert_payload_get_cert;
  cert_payload->set_cert = _rhp_ikev2_cert_payload_set_cert;
  cert_payload->set_cert_encoding = _rhp_ikev2_cert_payload_set_cert_encoding;
  cert_payload->get_cert_encoding = _rhp_ikev2_cert_payload_get_cert_encoding;

  
  RHP_TRC(0,RHPTRCID_IKEV2_ALLOC_CERT_PAYLOAD,"x",cert_payload);
  return cert_payload;
}


int rhp_ikev2_cert_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                 rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_cert_payload* cert_payload;
  rhp_proto_ike_cert_payload* cert_payloadh = (rhp_proto_ike_cert_payload*)payloadh;
  int vlen;
  
  RHP_TRC(0,RHPTRCID_IKEV2_CERT_PAYLOAD_NEW_RX,"xbxdxp",ikemesg,payload_id,payloadh,payload_len,payload,payload_len,payloadh);

  if( payload_len <= (int)sizeof(rhp_proto_ike_cert_payload) ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_CERT_PAYLOAD_NEW_RX_INVALID_MESG_1,"xdd",ikemesg,payload_len,sizeof(rhp_proto_ike_cert_payload));
    goto error;
  }

  vlen = payload_len - sizeof(rhp_proto_ike_cert_payload);
  if( vlen < 1 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_CERT_PAYLOAD_NEW_RX_INVALID_MESG_2,"xd",ikemesg,vlen);
    goto error;
  }

  if( cert_payloadh->cert_encoding == RHP_PROTO_IKE_CERTENC_X509_CERT_HASH_URL ){

  	if( vlen < (int)(RHP_IKEV2_CERT_HASH_LEN + RHP_IKEV2_CERT_HASH_URL_MIN_LEN) ){
      RHP_TRC(0,RHPTRCID_IKEV2_CERT_PAYLOAD_NEW_RX_INVALID_MESG_3,"xd",ikemesg,vlen); // This error is handled later.
  	}
  }

  cert_payload = _rhp_ikev2_alloc_cert_payload();
  if( cert_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.cert = cert_payload;
  payload->ext_destructor = _rhp_ikev2_cert_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_cert_payload_serialize;

  cert_payloadh = (rhp_proto_ike_cert_payload*)_rhp_pkt_pull(ikemesg->rx_pkt,payload_len);
  if( cert_payloadh == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_CERT_PAYLOAD_NEW_RX_INVALID_MESG_4,"x",ikemesg);
    goto error;
  }


  RHP_TRC(0,RHPTRCID_IKEV2_CERT_PAYLOAD_NEW_RX_RTRN,"xd",ikemesg,vlen);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_CERT_PAYLOAD_NEW_RX_ERR,"xE",ikemesg,err);
  return err;
}

int rhp_ikev2_cert_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_cert_payload* cert_payload;

  RHP_TRC(0,RHPTRCID_IKEV2_CERT_PAYLOAD_NEW_TX,"xLbx",ikemesg,"PROTO_IKE_PAYLOAD",payload_id,payload);

  cert_payload = _rhp_ikev2_alloc_cert_payload();
  if( cert_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.cert = cert_payload;
  payload->ext_destructor = _rhp_ikev2_cert_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_cert_payload_serialize;
  
  RHP_TRC(0,RHPTRCID_IKEV2_CERT_PAYLOAD_NEW_TX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_CERT_PAYLOAD_NEW_TX_ERR,"xE",ikemesg,err);
  return err;
}


rhp_ikev2_rx_cert_pld* rhp_ikev2_rx_cert_pld_alloc(rhp_ikev2_payload* payload,int is_ca_cert)
{
	rhp_ikev2_rx_cert_pld* cert_data = NULL;
	rhp_ikev2_cert_payload* cert_payload = (rhp_ikev2_cert_payload*)payload->ext.cert;
	int p_len;
	u8* p = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_ALLOC,"xd",payload,is_ca_cert);

	cert_data = (rhp_ikev2_rx_cert_pld*)_rhp_malloc(sizeof(rhp_ikev2_rx_cert_pld));
	if( cert_data == NULL ){
		RHP_BUG("");
		goto error;
	}
	memset(cert_data,0,sizeof(rhp_ikev2_rx_cert_pld));

	cert_data->encoding = cert_payload->get_cert_encoding(payload);
	cert_data->len = cert_payload->get_cert_len(payload);
  cert_data->is_ca_cert = is_ca_cert;

  if( cert_data->encoding == RHP_PROTO_IKE_CERTENC_X509_CERT_SIG ){

  	p_len = cert_payload->get_cert_len(payload);

  	p = (u8*)_rhp_malloc(p_len);
  	if( p == NULL ){
  		RHP_BUG("");
  		goto error;
  	}

  	memcpy(p,cert_payload->get_cert(payload),p_len);

  	cert_data->val_lens[RHP_RX_CERT_PLD_VAL_X509_SIG_DER] = p_len;
  	cert_data->vals[RHP_RX_CERT_PLD_VAL_X509_SIG_DER] = p;
  	p = NULL;

    RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_ALLOC_X509_CERT_SIG_DATA,"xp",payload,cert_data->val_lens[RHP_RX_CERT_PLD_VAL_X509_SIG_DER],cert_data->vals[RHP_RX_CERT_PLD_VAL_X509_SIG_DER]);

  }else if( cert_data->encoding == RHP_PROTO_IKE_CERTENC_X509_CERT_HASH_URL ){

  	{
			p_len = RHP_IKEV2_CERT_HASH_LEN;

			p = (u8*)_rhp_malloc(p_len);
			if( p == NULL ){
				RHP_BUG("");
				goto error;
			}

			memcpy(p,cert_payload->get_cert(payload),p_len);

	  	cert_data->val_lens[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_HASH] = p_len;
	  	cert_data->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_HASH] = p;
	  	p = NULL;

	    RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_ALLOC_X509_CERT_HASH_URL_HASH_DATA,"xp",payload,cert_data->val_lens[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_HASH],cert_data->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_HASH]);
  	}

  	{
  		p_len = cert_data->len - cert_data->val_lens[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_HASH] + 1;

			p = (u8*)_rhp_malloc(p_len);
			if( p == NULL ){
				RHP_BUG("");
				goto error;
			}

			memcpy(p,(cert_payload->get_cert(payload) + cert_data->val_lens[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_HASH]),(p_len - 1));
			p[p_len - 1] = '\0';

	  	cert_data->val_lens[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_URL] = p_len;
	  	cert_data->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_URL] = p;
	  	p = NULL;

	    RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_ALLOC_X509_CERT_HASH_URL_URL_DATA,"xp",payload,cert_data->val_lens[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_URL],cert_data->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_URL]);
  	}

  }else{
  	RHP_BUG("");
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_ALLOC_RTRN,"xx",payload,cert_data);
	return cert_data;

error:
	if( p ){
		_rhp_free(p);
	}
  RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_ALLOC_ERR,"x",payload);
	return NULL;
}

void rhp_ikev2_rx_cert_pld_free(rhp_ikev2_rx_cert_pld* cert_data)
{
	int i;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_FREE,"x",cert_data);

	if( cert_data ){

		for( i = 0; i < RHP_RX_CERT_PLD_VAL_NUM; i++ ){
			if( cert_data->vals[i] ){
				_rhp_free(cert_data->vals[i]);
			}
		}

		_rhp_free(cert_data);
	}

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_FREE_RTRN,"x",cert_data);
	return;
}

int rhp_ikev2_rx_cert_pld_merge_ders(rhp_ikev2_rx_cert_pld* cert_data,u8** merged_buf_r,int* merged_buf_len_r)
{
	int err = -EINVAL;
	rhp_ikev2_rx_cert_pld* cert_data_tmp = NULL;
	u8 *merged_buf = NULL, *p;
	int merged_buf_len = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_MERGE_DERS,"xxx",cert_data,merged_buf_r,merged_buf_len_r);

  cert_data_tmp = cert_data;
	while( cert_data_tmp ){

	  if( cert_data_tmp->encoding == RHP_PROTO_IKE_CERTENC_X509_CERT_SIG ){

	  	if( cert_data_tmp->vals[RHP_RX_CERT_PLD_VAL_X509_SIG_DER] == NULL ){
	  	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_MERGE_DERS_NO_DER_DATA_1,"xx",cert_data,cert_data_tmp);
	  		err = -ENOENT;
	  		goto error;
	  	}

	  	merged_buf_len += sizeof(rhp_cert_data) + cert_data_tmp->val_lens[RHP_RX_CERT_PLD_VAL_X509_SIG_DER];
  	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_MERGE_DERS_DER_DATA_LEN_1,"xxddd",cert_data,cert_data_tmp,sizeof(rhp_cert_data),cert_data_tmp->val_lens[RHP_RX_CERT_PLD_VAL_X509_SIG_DER],merged_buf_len);

	  }else if( cert_data_tmp->encoding == RHP_PROTO_IKE_CERTENC_X509_CERT_HASH_URL ){

	  	if( cert_data_tmp->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_DER] == NULL ){
	  	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_MERGE_DERS_NO_DER_DATA_2,"xx",cert_data,cert_data_tmp);
	  		err = -ENOENT;
	  		goto error;
	  	}

	  	merged_buf_len += sizeof(rhp_cert_data) + cert_data_tmp->val_lens[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_DER];
  	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_MERGE_DERS_DER_DATA_LEN_2,"xxddd",cert_data,cert_data_tmp,sizeof(rhp_cert_data),cert_data_tmp->val_lens[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_DER],merged_buf_len);

	  }else{
  	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_MERGE_DERS_DATA_LEN_INVALID_DER_ENC,"xxd",cert_data,cert_data_tmp,cert_data_tmp->encoding);
	  	err = -EINVAL;
	  	goto error;
	  }

		cert_data_tmp = cert_data_tmp->next;
	}

	if( merged_buf_len <= (int)sizeof(rhp_cert_data) ){
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_MERGE_DERS_NO_DER_DATA_4,"xd",cert_data,merged_buf_len);
		err = -ENOENT;
		goto error;
	}


	merged_buf = (u8*)_rhp_malloc(merged_buf_len);
	if( merged_buf == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memset(merged_buf,0,merged_buf_len);
	p = merged_buf;

	cert_data_tmp = cert_data;
	while( cert_data_tmp ){

	  if( cert_data_tmp->encoding == RHP_PROTO_IKE_CERTENC_X509_CERT_SIG ){

	  	((rhp_cert_data*)p)->type = RHP_CERT_DATA_DER;
	  	((rhp_cert_data*)p)->len = cert_data_tmp->val_lens[RHP_RX_CERT_PLD_VAL_X509_SIG_DER];
	  	p += sizeof(rhp_cert_data);

	  	memcpy(p,cert_data_tmp->vals[RHP_RX_CERT_PLD_VAL_X509_SIG_DER],cert_data_tmp->val_lens[RHP_RX_CERT_PLD_VAL_X509_SIG_DER]);
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_MERGE_DERS_DER_DATA_1,"xxp",cert_data,cert_data_tmp,cert_data_tmp->val_lens[RHP_RX_CERT_PLD_VAL_X509_SIG_DER],p);

	  	p += cert_data_tmp->val_lens[RHP_RX_CERT_PLD_VAL_X509_SIG_DER];

	  }else if( cert_data_tmp->encoding == RHP_PROTO_IKE_CERTENC_X509_CERT_HASH_URL ){

	  	((rhp_cert_data*)p)->type = RHP_CERT_DATA_HASH_URL;
	  	((rhp_cert_data*)p)->len = cert_data_tmp->val_lens[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_DER];
	  	p += sizeof(rhp_cert_data);

	  	memcpy(p,cert_data_tmp->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_DER],cert_data_tmp->val_lens[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_DER]);
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_MERGE_DERS_DER_DATA_2,"xxp",cert_data,cert_data_tmp,cert_data_tmp->val_lens[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_DER],p);

		  p += cert_data_tmp->val_lens[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_DER];

	  }else{
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_MERGE_DERS_DER_INVALID_ENC,"xxd",cert_data,cert_data_tmp,cert_data_tmp->encoding);
	  	err = -EINVAL;
	  	goto error;
	  }

		cert_data_tmp = cert_data_tmp->next;
	}

	*merged_buf_r = merged_buf;
	*merged_buf_len_r = merged_buf_len;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_MERGE_DERS_RTRN,"xp",cert_data,*merged_buf_len_r,merged_buf_r);
	return 0;

error:
	if( merged_buf ){
		_rhp_free(merged_buf);
	}
  RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_MERGE_DERS_ERR,"xE",cert_data,err);
	return err;
}

static int _rhp_ikev2_rx_cert_pld_get_der_impl(rhp_ikev2_rx_cert_pld* cert_data,u8** buf_r,int* buf_len_r,int split)
{
	int err = -EINVAL;
	u8* buf = NULL;
	int buf_len = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_GET_DER_IMPL,"xxxd",cert_data,buf_r,buf_len_r,split);

  if( cert_data->encoding == RHP_PROTO_IKE_CERTENC_X509_CERT_SIG ){

  	buf_len = cert_data->val_lens[RHP_RX_CERT_PLD_VAL_X509_SIG_DER];
  	buf = cert_data->vals[RHP_RX_CERT_PLD_VAL_X509_SIG_DER];
  	if( split ){
  		cert_data->val_lens[RHP_RX_CERT_PLD_VAL_X509_SIG_DER] = 0;
  		cert_data->vals[RHP_RX_CERT_PLD_VAL_X509_SIG_DER] = NULL;
  	}
    RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_GET_DER_IMPL_X509_CERT_SIG_DATA,"xp",cert_data,buf_len,buf);

  }else if( cert_data->encoding == RHP_PROTO_IKE_CERTENC_X509_CERT_HASH_URL ){

  	buf_len = cert_data->val_lens[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_DER];
  	buf = cert_data->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_DER];
  	if( split ){
  		cert_data->val_lens[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_DER] = 0;
  		cert_data->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_DER] = NULL;
  	}
    RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_GET_DER_IMPL_X509_CERT_HASH_URL_DATA,"xp",cert_data,buf_len,buf);

  }else{
    RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_GET_DER_IMPL_INVALID_ENC,"xd",cert_data,cert_data->encoding);
  	err = -EINVAL;
  	goto error;
  }

  if( buf == NULL || buf_len == 0 ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_GET_DER_IMPL_NO_DATA,"x",cert_data);
  	err = -ENOENT;
  	goto error;
  }

	*buf_r = buf;
	*buf_len_r = buf_len;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_GET_DER_IMPL_RTRN,"x",cert_data);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_GET_DER_IMPL_ERR,"xE",cert_data,err);
	return err;
}

int rhp_ikev2_rx_cert_pld_peek_der(rhp_ikev2_rx_cert_pld* cert_data,u8** merged_buf_r,int* merged_buf_len_r)
{
	return _rhp_ikev2_rx_cert_pld_get_der_impl(cert_data,merged_buf_r,merged_buf_len_r,0);
}

int rhp_ikev2_rx_cert_pld_split_der(rhp_ikev2_rx_cert_pld* cert_data,u8** merged_buf_r,int* merged_buf_len_r)
{
	return _rhp_ikev2_rx_cert_pld_get_der_impl(cert_data,merged_buf_r,merged_buf_len_r,1);
}

int rhp_ikev2_rx_cert_pld_split_hash_url(rhp_ikev2_rx_cert_pld* cert_data,char** url_r,u8** hash_r,int* hash_len_r)
{
	int err = -EINVAL;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_SPLIT_HASH_URL,"xxxx",cert_data,url_r,hash_r,hash_len_r);

  if( cert_data->encoding == RHP_PROTO_IKE_CERTENC_X509_CERT_SIG ){

  	err = -ENOENT;
  	goto error;

  }else if( cert_data->encoding == RHP_PROTO_IKE_CERTENC_X509_CERT_HASH_URL ){

  	*url_r = (char*)cert_data->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_URL];
  	cert_data->val_lens[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_URL] = 0;
  	cert_data->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_URL] = NULL;

  	*hash_len_r = cert_data->val_lens[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_HASH];
  	*hash_r = cert_data->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_HASH];
  	cert_data->val_lens[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_HASH] = 0;
  	cert_data->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_HASH] = NULL;

  }else{
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_SPLIT_HASH_URL_RTRN,"xsp",cert_data,*url_r,*hash_len_r,*hash_r);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_CERT_PLD_SPLIT_HASH_URL_ERR,"xE",cert_data,err);
	return err;
}
