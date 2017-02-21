/*

	Copyright (C) 2015-2016 TETSUHARU HANADA <rhpenguine@gmail.com>
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
#include "rhp_ikev2_mesg.h"
#include "rhp_ikesa.h"
#include "rhp_ikev2.h"
#include "rhp_vpn.h"


static u16 _rhp_ikev2_payload_n_auth_tkt_attr_get_attr_type(rhp_ikev2_n_auth_tkt_attr* tkt_attr)
{
	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_ATTR_GET_ATTR_TYPE,"xLw",tkt_attr,"AUTH_TKT_ATTR",tkt_attr->tkt_attr_type);
	return tkt_attr->tkt_attr_type;
}

static void _rhp_ikev2_payload_n_auth_tkt_attr_set_attr_sub_type(rhp_ikev2_n_auth_tkt_attr* tkt_attr,
		u16 attr_sub_type)
{
	tkt_attr->tkt_attr_sub_type = attr_sub_type;
	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_ATTR_SET_ATTR_SUB_TYPE,"xLww",tkt_attr,"AUTH_TKT_ATTR",tkt_attr->tkt_attr_type,tkt_attr->tkt_attr_sub_type);
	return;
}

static u16 _rhp_ikev2_payload_n_auth_tkt_attr_get_attr_sub_type(rhp_ikev2_n_auth_tkt_attr* tkt_attr)
{
	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_ATTR_GET_ATTR_SUB_TYPE,"xLww",tkt_attr,"AUTH_TKT_ATTR",tkt_attr->tkt_attr_type,tkt_attr->tkt_attr_sub_type);
	return tkt_attr->tkt_attr_sub_type;
}

static u8* _rhp_ikev2_payload_n_auth_tkt_attr_get_attr_val(rhp_ikev2_n_auth_tkt_attr* tkt_attr,
		int *val_len_r)
{
	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_ATTR_GET_ATTR_VAL,"xLwwp",tkt_attr,"AUTH_TKT_ATTR",tkt_attr->tkt_attr_type,tkt_attr->tkt_attr_sub_type,tkt_attr->tkt_attr_len,tkt_attr->tkt_attr_val);
	*val_len_r = tkt_attr->tkt_attr_len;
	return tkt_attr->tkt_attr_val;
}

static int _rhp_ikev2_payload_n_auth_tkt_attr_set_attr_val(rhp_ikev2_n_auth_tkt_attr* tkt_attr,
		int len,u8* val)
{
	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_ATTR_SET_ATTR_VAL,"xLwwpp",tkt_attr,"AUTH_TKT_ATTR",tkt_attr->tkt_attr_type,tkt_attr->tkt_attr_sub_type,tkt_attr->tkt_attr_len,tkt_attr->tkt_attr_val,len,val);

	if( tkt_attr->tkt_attr_val ){
		_rhp_free(tkt_attr->tkt_attr_val);
		tkt_attr->tkt_attr_len = 0;
	}

	tkt_attr->tkt_attr_val = (u8*)_rhp_malloc(len + 1);
	if( tkt_attr->tkt_attr_val == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	memcpy(tkt_attr->tkt_attr_val,val,len);
	tkt_attr->tkt_attr_val[len] = '\0';
	tkt_attr->tkt_attr_len = len;

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_ATTR_SET_ATTR_VAL_RTRN,"xLwwp",tkt_attr,"AUTH_TKT_ATTR",tkt_attr->tkt_attr_type,tkt_attr->tkt_attr_sub_type,tkt_attr->tkt_attr_len,tkt_attr->tkt_attr_val);
	return 0;
}

void rhp_ikev2_payload_n_auth_tkt_attr_free(rhp_ikev2_n_auth_tkt_attr* tkt_attr)
{
	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_ATTR_FREE,"xLwwp",tkt_attr,"AUTH_TKT_ATTR",tkt_attr->tkt_attr_type,tkt_attr->tkt_attr_sub_type,tkt_attr->tkt_attr_len,tkt_attr->tkt_attr_val);

	if( tkt_attr->tkt_attr_val ){
		_rhp_free(tkt_attr->tkt_attr_val);
	}
	_rhp_free(tkt_attr);

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_ATTR_FREE_RTRN,"x",tkt_attr);
	return;
}

rhp_ikev2_n_auth_tkt_attr* rhp_ikev2_payload_n_auth_tkt_attr_alloc(u16 tkt_attr_type)
{
	rhp_ikev2_n_auth_tkt_attr* tkt_attr
		= (rhp_ikev2_n_auth_tkt_attr*)_rhp_malloc(sizeof(rhp_ikev2_n_auth_tkt_attr));

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_ATTR_ALLOC,"Lwx","AUTH_TKT_ATTR",tkt_attr_type,tkt_attr);

	if( tkt_attr == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(tkt_attr,0,sizeof(rhp_ikev2_n_auth_tkt_attr));

	tkt_attr->tkt_attr_type = tkt_attr_type;

	tkt_attr->get_attr_type = _rhp_ikev2_payload_n_auth_tkt_attr_get_attr_type;
	tkt_attr->set_attr_sub_type = _rhp_ikev2_payload_n_auth_tkt_attr_set_attr_sub_type;
	tkt_attr->get_attr_sub_type = _rhp_ikev2_payload_n_auth_tkt_attr_get_attr_sub_type;
	tkt_attr->get_attr_val = _rhp_ikev2_payload_n_auth_tkt_attr_get_attr_val;
	tkt_attr->set_attr_val = _rhp_ikev2_payload_n_auth_tkt_attr_set_attr_val;

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_ATTR_ALLOC_RTRN,"Lwx","AUTH_TKT_ATTR",tkt_attr_type,tkt_attr);
	return tkt_attr;
}


static u16 _rhp_ikev2_payload_n_auth_tkt_get_mesg_type(rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload)
{
	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_GET_MESG_TYPE,"xLw",n_auth_tkt_payload,"PROTO_IKE_NOTIFY",n_auth_tkt_payload->mesg_type);
	return n_auth_tkt_payload->mesg_type;
}

static u8 _rhp_ikev2_payload_n_auth_tkt_get_auth_tkt_type(rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload)
{
	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_GET_AUTH_TKT_TYPE,"xLw",n_auth_tkt_payload,"AUTH_TKT",n_auth_tkt_payload->auth_tkt_type);
	return n_auth_tkt_payload->auth_tkt_type;
}

static int _rhp_ikev2_payload_n_auth_tkt_add_attr(rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload,
		rhp_ikev2_n_auth_tkt_attr* auth_tkt_attr)
{
	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_ADD_ATTR,"xxLwwxx",n_auth_tkt_payload,auth_tkt_attr,"AUTH_TKT_ATTR",auth_tkt_attr->tkt_attr_type,auth_tkt_attr->tkt_attr_sub_type,n_auth_tkt_payload->attr_head,n_auth_tkt_payload->attr_tail);

	if( n_auth_tkt_payload->attr_head == NULL ){
		n_auth_tkt_payload->attr_head = auth_tkt_attr;
	}else{
		n_auth_tkt_payload->attr_tail->next = auth_tkt_attr;
	}
	n_auth_tkt_payload->attr_tail = auth_tkt_attr;

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_ADD_ATTR_RTRN,"xxLw",n_auth_tkt_payload,auth_tkt_attr,"AUTH_TKT_ATTR",auth_tkt_attr->tkt_attr_type);
	return 0;
}

static rhp_ikev2_n_auth_tkt_attr* _rhp_ikev2_payload_n_auth_tkt_get_attr(rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload,
		u16 tkt_attr_type,u16 tkt_attr_sub_type)
{
	rhp_ikev2_n_auth_tkt_attr* auth_tkt_attr = n_auth_tkt_payload->attr_head;

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_GET_ATTR,"xLww",n_auth_tkt_payload,"AUTH_TKT",tkt_attr_type,tkt_attr_sub_type);

	while( auth_tkt_attr ){
		if( auth_tkt_attr->tkt_attr_type == tkt_attr_type &&
				(tkt_attr_sub_type == 0 || auth_tkt_attr->tkt_attr_sub_type == tkt_attr_sub_type)){
			break;
		}
		auth_tkt_attr = auth_tkt_attr->next;
	}

	if( auth_tkt_attr == NULL ){
		RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_GET_ATTR_NO_ENT,"xLww",n_auth_tkt_payload,"AUTH_TKT",tkt_attr_type,tkt_attr_sub_type);
		return NULL;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_GET_ATTR_RTRN,"xxLww",n_auth_tkt_payload,auth_tkt_attr,"AUTH_TKT",auth_tkt_attr->tkt_attr_type,auth_tkt_attr->tkt_attr_sub_type);
	return auth_tkt_attr;
}


static int _rhp_ikev2_payload_n_auth_tkt_serialize_data(rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload,
		int* pld_len_r,u8** pld_buf_r)
{
	int err = -EINVAL;
  int attrs_num = 0;
  int pld_len, attrs_len = 0;
	u8 *pld_buf = NULL, *p;
	u8 auth_tkt_type = n_auth_tkt_payload->get_auth_tkt_type(n_auth_tkt_payload);
	rhp_proto_ikev2_auth_tkt_header* auth_tkt_h;
	rhp_ikev2_n_auth_tkt_attr* auth_tkt_attr;

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_SERIALIZE_DATA,"xxx",n_auth_tkt_payload,pld_len_r,pld_buf_r);

	auth_tkt_attr = n_auth_tkt_payload->attr_head;
	while( auth_tkt_attr ){
		attrs_len += sizeof(rhp_proto_ikev2_auth_tkt_attr) + auth_tkt_attr->tkt_attr_len;
		attrs_num++;
		auth_tkt_attr = auth_tkt_attr->next;
	}

	pld_len = sizeof(rhp_proto_ikev2_auth_tkt_header) + attrs_len;


	pld_buf = (u8*)_rhp_malloc(pld_len);
	if( pld_buf == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	p = pld_buf;

	{
		auth_tkt_h = (rhp_proto_ikev2_auth_tkt_header*)p;

		auth_tkt_h->auth_tkt_type = auth_tkt_type;
		auth_tkt_h->reserved = 0;
		auth_tkt_h->auth_tkt_attrs_num = htons((u16)attrs_num);

		p += sizeof(rhp_proto_ikev2_auth_tkt_header);
	}

	{
		auth_tkt_attr = n_auth_tkt_payload->attr_head;
		while( auth_tkt_attr ){

			rhp_proto_ikev2_auth_tkt_attr* attrh = (rhp_proto_ikev2_auth_tkt_attr*)p;

			attrh->tkt_attr_len
					= htons((u16)((int)sizeof(rhp_proto_ikev2_auth_tkt_attr) + auth_tkt_attr->tkt_attr_len));
			attrh->tkt_attr_type = htons(auth_tkt_attr->tkt_attr_type);
			attrh->tkt_attr_sub_type = htons(auth_tkt_attr->tkt_attr_sub_type);
			p += sizeof(rhp_proto_ikev2_auth_tkt_attr);

			memcpy(p,auth_tkt_attr->tkt_attr_val,auth_tkt_attr->tkt_attr_len);
			p += auth_tkt_attr->tkt_attr_len;

			RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_SERIALIZE_DATA_ATTR,"xxWLWWp",n_auth_tkt_payload,auth_tkt_attr,attrh->tkt_attr_len,"AUTH_TKT_ATTR",attrh->tkt_attr_type,attrh->tkt_attr_sub_type,ntohs(attrh->tkt_attr_len),attrh);

			auth_tkt_attr = auth_tkt_attr->next;
		}
	}

	*pld_len_r = pld_len;
	*pld_buf_r = pld_buf;

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_SERIALIZE_DATA_RTRN,"xdp",n_auth_tkt_payload,attrs_num,*pld_len_r,*pld_buf_r);
	return 0;

error:

	if( pld_buf ){
		_rhp_free(pld_buf);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_SERIALIZE_DATA_ERR,"xE",n_auth_tkt_payload,err);
	return err;
}

static int _rhp_ikev2_payload_n_auth_tkt_serialize_data_enc(rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload,
		rhp_vpn* resp_vpn,rhp_ikesa* resp_ikesa,int* pld_len_r,u8** pld_buf_r)
{
	int err = -EINVAL;
  rhp_crypto_integ* resp_integ = NULL;
  int attrs_num = 0;
	int iv_len = 0, icv_len = 0, pld_len, attrs_len = 0, pad_len = 0, aligned_len = 0;
	u8 *pld_buf = NULL, *p, *peer_spi, *iv_p, *plain_p = NULL, *icv_p;
	u8 auth_tkt_type = n_auth_tkt_payload->get_auth_tkt_type(n_auth_tkt_payload);
	rhp_proto_ikev2_auth_tkt_header* auth_tkt_h;
	rhp_ikev2_n_auth_tkt_attr* auth_tkt_attr;
  rhp_crypto_integ* integ = NULL;
  rhp_crypto_encr* encr = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_SERIALIZE_DATA_ENC,"xxxxx",n_auth_tkt_payload,resp_vpn,resp_ikesa,pld_len_r,pld_buf_r);

	auth_tkt_attr = n_auth_tkt_payload->attr_head;
	while( auth_tkt_attr ){
		attrs_len += auth_tkt_attr->tkt_attr_len + (int)sizeof(rhp_proto_ikev2_auth_tkt_attr);
		attrs_num++;
		auth_tkt_attr = auth_tkt_attr->next;
	}


  if( resp_ikesa->side == RHP_IKE_INITIATOR ){
    resp_integ = resp_ikesa->integ_i;
  }else{
    resp_integ = resp_ikesa->integ_r;
  }

	iv_len = resp_ikesa->encr->get_iv_len(resp_ikesa->encr);
	icv_len = resp_integ->get_output_len(resp_integ);

	aligned_len = resp_ikesa->encr->get_block_aligned_len(resp_ikesa->encr,
									(int)sizeof(rhp_proto_ikev2_auth_tkt_header) + attrs_len + 1); // 1 : pad_len

	// Pad_len fieled NOT included.
	pad_len = aligned_len - ((int)sizeof(rhp_proto_ikev2_auth_tkt_header) + attrs_len + 1);

	pld_len = RHP_PROTO_IKE_SPI_SIZE + iv_len + aligned_len + icv_len;


	pld_buf = (u8*)_rhp_malloc(pld_len);
	if( pld_buf == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	p = pld_buf;

	{
		if( resp_ikesa->side == RHP_IKE_INITIATOR ){
			peer_spi = resp_ikesa->resp_spi;
		}else{
			peer_spi = resp_ikesa->init_spi;
		}
		memcpy(p,peer_spi,RHP_PROTO_IKE_SPI_SIZE);
		p += RHP_PROTO_IKE_SPI_SIZE;
	}

	{
		iv_p = p;
		p += iv_len;
	}

	{
		auth_tkt_h = (rhp_proto_ikev2_auth_tkt_header*)p;

		auth_tkt_h->auth_tkt_type = auth_tkt_type;
		auth_tkt_h->reserved = 0;
		auth_tkt_h->auth_tkt_attrs_num = htons((u16)attrs_num);

		p += (int)sizeof(rhp_proto_ikev2_auth_tkt_header);
	}

	{
		auth_tkt_attr = n_auth_tkt_payload->attr_head;
		while( auth_tkt_attr ){

			rhp_proto_ikev2_auth_tkt_attr* attrh = (rhp_proto_ikev2_auth_tkt_attr*)p;

			attrh->tkt_attr_len
				= htons((u16)((int)sizeof(rhp_proto_ikev2_auth_tkt_attr) + auth_tkt_attr->tkt_attr_len));
			attrh->tkt_attr_type = htons(auth_tkt_attr->tkt_attr_type);
			attrh->tkt_attr_sub_type = htons(auth_tkt_attr->tkt_attr_sub_type);
			p += (int)sizeof(rhp_proto_ikev2_auth_tkt_attr);

			memcpy(p,auth_tkt_attr->tkt_attr_val,auth_tkt_attr->tkt_attr_len);
			p += auth_tkt_attr->tkt_attr_len;

			RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_SERIALIZE_DATA_ENC_ATTR,"xxWLWWp",n_auth_tkt_payload,auth_tkt_attr,attrh->tkt_attr_len,"AUTH_TKT_ATTR",attrh->tkt_attr_type,attrh->tkt_attr_sub_type,ntohs(attrh->tkt_attr_len),attrh);

			auth_tkt_attr = auth_tkt_attr->next;
		}
	}

	{
		int i;
		for( i = 0; i < pad_len; i++ ){
			p[i] = (u8)i;
		}
		p[i] = pad_len;
		p += (pad_len + 1);
	}

	icv_p = p;
	memset(p,0,icv_len);


	plain_p = (u8*)_rhp_malloc(aligned_len);
	if( plain_p == NULL ){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	memcpy(plain_p,(u8*)auth_tkt_h,aligned_len);

	RHP_TRC_FREQ(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_SERIALIZE_DATA_PLAIN,"xp",n_auth_tkt_payload,aligned_len,plain_p);

	encr = rhp_crypto_encr_alloc(resp_ikesa->prop.v2.encr_id,resp_ikesa->prop.v2.encr_key_bits);
  if( encr == NULL ){
    RHP_BUG("");
    goto error;
  }

  err = encr->set_enc_key(encr,resp_ikesa->keys.v2.sk_dmvpn_e,resp_ikesa->keys.v2.sk_dmvpn_e_len);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

  integ = rhp_crypto_integ_alloc(resp_ikesa->prop.v2.integ_id);
  if( integ == NULL ){
    RHP_BUG("");
    goto error;
  }

  err = integ->set_key(integ,resp_ikesa->keys.v2.sk_dmvpn_a,resp_ikesa->keys.v2.sk_dmvpn_a_len);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

	memcpy(iv_p,encr->get_enc_iv(encr),iv_len);

	err = encr->encrypt(encr,plain_p,aligned_len,(u8*)auth_tkt_h,aligned_len);
	if( err ){
		RHP_BUG("");
		goto error;
	}

	RHP_TRC_FREQ(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_SERIALIZE_DATA_ENC_DATA,"xp",n_auth_tkt_payload,aligned_len,auth_tkt_h);

	err = integ->compute(integ,pld_buf,pld_len,icv_p,icv_len);
	if( err ){
		RHP_BUG("");
		goto error;
	}

	RHP_TRC_FREQ(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_SERIALIZE_DATA_INTEG,"xpp",n_auth_tkt_payload,pld_len,pld_buf,icv_len,icv_p);

	_rhp_free(plain_p);
	rhp_crypto_encr_free(encr);
	rhp_crypto_integ_free(integ);

	*pld_len_r = pld_len;
	*pld_buf_r = pld_buf;

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_SERIALIZE_DATA_ENC_RTRN,"xxxdp",n_auth_tkt_payload,resp_vpn,resp_ikesa,attrs_num,*pld_len_r,*pld_buf_r);
	return 0;

error:

	if( pld_buf ){
		_rhp_free(pld_buf);
	}

	if( plain_p ){
		_rhp_free(plain_p);
	}

	if( encr ){
		rhp_crypto_encr_free(encr);
	}
	if( integ ){
		rhp_crypto_integ_free(integ);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_SERIALIZE_DATA_ENC_ERR,"xE",n_auth_tkt_payload,err);
	return err;
}

static int _rhp_ikev2_payload_n_auth_tkt_serialize(rhp_ikev2_mesg* tx_ikemesg,
		rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload,
		rhp_vpn* resp_vpn,rhp_ikesa* resp_ikesa,rhp_ikev2_payload** n_payload_r)
{
	int err = -EINVAL;
	u16 mesg_type = n_auth_tkt_payload->get_mesg_type(n_auth_tkt_payload);
	int pld_len = 0;
	u8* pld_buf = NULL;
	rhp_ikev2_payload* n_payload = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_SERIALIZE,"xxLwLwxxx",tx_ikemesg,n_auth_tkt_payload,"PROTO_IKE_NOTIFY",mesg_type,"AUTH_TKT",n_auth_tkt_payload->auth_tkt_type,resp_vpn,resp_ikesa,n_payload_r);

	if( mesg_type == RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_AUTH_TICKET ){

		err = _rhp_ikev2_payload_n_auth_tkt_serialize_data(n_auth_tkt_payload,
						&pld_len,&pld_buf);
		if( err ){
			goto error;
		}

	}else if( mesg_type == RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_ENC_AUTH_TICKET ){

		err = _rhp_ikev2_payload_n_auth_tkt_serialize_data_enc(n_auth_tkt_payload,resp_vpn,resp_ikesa,
						&pld_len,&pld_buf);
		if( err ){
			goto error;
		}

	}else{
		RHP_BUG("%d",ntohs(mesg_type));
		err = -EINVAL;
		goto error;
	}


	if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&n_payload) ){
		RHP_BUG("");
		goto error;
	}

	n_payload->ext.n->set_protocol_id(n_payload,0);

	n_payload->ext.n->set_message_type(n_payload,mesg_type);

	if( n_payload->ext.n->set_data(n_payload,pld_len,pld_buf) ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	_rhp_free(pld_buf);

	*n_payload_r = n_payload;

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_SERIALIZE_RTRN,"xxx",tx_ikemesg,n_auth_tkt_payload,*n_payload_r);
	return 0;

error:
	if( n_payload ){
		rhp_ikev2_destroy_payload(n_payload);
	}
	if( pld_buf ){
		_rhp_free(pld_buf);
	}
	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_SERIALIZE_ERR,"xxE",tx_ikemesg,n_auth_tkt_payload,err);
	return err;
}

void rhp_ikev2_payload_n_auth_tkt_free(rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload)
{
	rhp_ikev2_n_auth_tkt_attr* tkt_attr = n_auth_tkt_payload->attr_head;

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_FREE,"xx",n_auth_tkt_payload,tkt_attr);

	while( tkt_attr ){
		rhp_ikev2_n_auth_tkt_attr* tkt_attr_n = tkt_attr->next;
		rhp_ikev2_payload_n_auth_tkt_attr_free(tkt_attr);
		tkt_attr = tkt_attr_n;
	}

	_rhp_free(n_auth_tkt_payload);

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_FREE_RTRN,"x",n_auth_tkt_payload);
	return;
}

static rhp_ikev2_n_auth_tkt_payload* _rhp_ikev2_payload_n_auth_tkt_alloc(u16 mesg_type,u8 auth_tkt_type)
{
	rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload
		= (rhp_ikev2_n_auth_tkt_payload*)_rhp_malloc(sizeof(rhp_ikev2_n_auth_tkt_payload));

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_ALLOC,"xLwLw",n_auth_tkt_payload,"PROTO_IKE_NOTIFY",mesg_type,"AUTH_TKT",auth_tkt_type);

	if( n_auth_tkt_payload == NULL ){
		RHP_BUG("");
		goto error;
	}
	memset(n_auth_tkt_payload,0,sizeof(rhp_ikev2_n_auth_tkt_payload));

	n_auth_tkt_payload->mesg_type = mesg_type;
	n_auth_tkt_payload->auth_tkt_type = auth_tkt_type;

	n_auth_tkt_payload->get_mesg_type = _rhp_ikev2_payload_n_auth_tkt_get_mesg_type;
	n_auth_tkt_payload->get_auth_tkt_type = _rhp_ikev2_payload_n_auth_tkt_get_auth_tkt_type;
	n_auth_tkt_payload->add_attr = _rhp_ikev2_payload_n_auth_tkt_add_attr;
	n_auth_tkt_payload->get_attr = _rhp_ikev2_payload_n_auth_tkt_get_attr;
	n_auth_tkt_payload->serialize = _rhp_ikev2_payload_n_auth_tkt_serialize;

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_ALLOC_RTRN,"x",n_auth_tkt_payload);
	return n_auth_tkt_payload;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_ALLOC_ERR,"");
	return NULL;
}

static int _rhp_ikev2_n_auth_tkt_rx_parse(u16 mesg_type,
		int auth_tkt_len,rhp_proto_ikev2_auth_tkt_header* auth_tkt_h,
		rhp_ikev2_n_auth_tkt_payload** n_auth_tkt_payload_r)
{
	int err = -EINVAL;
	u8* endp;
	rhp_proto_ikev2_auth_tkt_attr* auth_attr_h;
	rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload = NULL;
	int i = 0, attrs_num = 0;

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_RX_PARSE,"Lwpxp","PROTO_IKE_NOTIFY",mesg_type,auth_tkt_len,auth_tkt_h,n_auth_tkt_payload_r,auth_tkt_len,(u8*)auth_tkt_h);

	if( auth_tkt_len < (int)sizeof(rhp_proto_ikev2_auth_tkt_header) ){
		err = -EINVAL;
		RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_RX_PARSE_INVALID_LEN_0,"Lddd","PROTO_IKE_NOTIFY",mesg_type,auth_tkt_len,(int)sizeof(rhp_proto_ikev2_auth_tkt_header));
		goto error;
	}

	endp = ((u8*)auth_tkt_h) + auth_tkt_len;


	n_auth_tkt_payload = _rhp_ikev2_payload_n_auth_tkt_alloc(mesg_type,0);
	if( n_auth_tkt_payload == NULL ){
		err = -ENOMEM;
		goto error;
	}


	n_auth_tkt_payload->auth_tkt_type = auth_tkt_h->auth_tkt_type;
	attrs_num = ntohs(auth_tkt_h->auth_tkt_attrs_num);

	auth_attr_h = (rhp_proto_ikev2_auth_tkt_attr*)(auth_tkt_h + 1);
	for( i = 0; i < attrs_num; i++ ){

		int attr_len;
		rhp_ikev2_n_auth_tkt_attr* auth_tkt_attr;

		if( (u8*)auth_attr_h >= endp ){
			RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_RX_PARSE_ATTR_END,"Ldxx","PROTO_IKE_NOTIFY",mesg_type,auth_attr_h,endp);
			break;
		}

		if( ((u8*)auth_attr_h) + sizeof(rhp_proto_ikev2_auth_tkt_attr) > endp ){
			err = -EINVAL;
			RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_RX_PARSE_INVALID_LEN_1,"Ldxxd","PROTO_IKE_NOTIFY",mesg_type,auth_attr_h,endp,sizeof(rhp_proto_ikev2_auth_tkt_attr));
			goto error;
		}

		attr_len = ntohs(auth_attr_h->tkt_attr_len);

		if( ((u8*)auth_attr_h) + attr_len > endp ){
			err = -EINVAL;
			RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_RX_PARSE_INVALID_LEN_2,"Ldxxd","PROTO_IKE_NOTIFY",mesg_type,auth_attr_h,endp,attr_len);
			goto error;
		}

		RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_RX_PARSE_ATTR_DATA,"Ldxp","PROTO_IKE_NOTIFY",mesg_type,endp,attr_len,(u8*)auth_attr_h);

		auth_tkt_attr = rhp_ikev2_payload_n_auth_tkt_attr_alloc(ntohs(auth_attr_h->tkt_attr_type));
		if( auth_tkt_attr == NULL ){
			err = -ENOMEM;
			goto error;
		}

		if( auth_attr_h->tkt_attr_sub_type ){
			auth_tkt_attr->set_attr_sub_type(auth_tkt_attr,ntohs(auth_attr_h->tkt_attr_sub_type));
		}

		if( attr_len > (int)sizeof(rhp_proto_ikev2_auth_tkt_attr) ){

			err = auth_tkt_attr->set_attr_val(auth_tkt_attr,
						(attr_len - sizeof(rhp_proto_ikev2_auth_tkt_attr)),(u8*)(auth_attr_h + 1));
			if( err ){
				goto error;
			}

			err = n_auth_tkt_payload->add_attr(n_auth_tkt_payload,auth_tkt_attr);
			if( err ){
				rhp_ikev2_payload_n_auth_tkt_attr_free(auth_tkt_attr);
				goto error;
			}
		}

		auth_attr_h = (rhp_proto_ikev2_auth_tkt_attr*)(((u8*)auth_attr_h) + attr_len);
	}

	if( i != attrs_num ){
		err = -EINVAL;
		goto error;
	}

	*n_auth_tkt_payload_r = n_auth_tkt_payload;

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_RX_PARSE_RTRN,"Lddx","PROTO_IKE_NOTIFY",mesg_type,attrs_num,*n_auth_tkt_payload_r);
	return 0;

error:
	if( n_auth_tkt_payload ){
		rhp_ikev2_payload_n_auth_tkt_free(n_auth_tkt_payload);
	}
	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_RX_PARSE_ERR,"LdddE","PROTO_IKE_NOTIFY",mesg_type,i,attrs_num,err);
	return err;
}

int rhp_ikev2_new_payload_n_auth_tkt_rx(rhp_ikev2_mesg* ikemesg,rhp_ikev2_payload* n_payload,
		rhp_ikev2_n_auth_tkt_payload** n_auth_tkt_payload_r)
{
	int err = -EINVAL;
	int auth_tkt_len = 0;
	rhp_proto_ikev2_auth_tkt_header* auth_tkt_h;
	rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_RX,"xxLwx",ikemesg,n_payload,"PROTO_IKE_NOTIFY",n_payload->ext.n->get_message_type(n_payload),n_auth_tkt_payload_r);

	auth_tkt_len = n_payload->ext.n->get_data_len(n_payload);
	if( auth_tkt_len < (int)sizeof(rhp_proto_ikev2_auth_tkt_header) ){
		RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_RX_INVALID_LEN,"xxLwdd",ikemesg,n_payload,"PROTO_IKE_NOTIFY",n_payload->ext.n->get_message_type(n_payload),auth_tkt_len,(int)sizeof(rhp_proto_ikev2_auth_tkt_header));
		err = -EINVAL;
		goto error;
	}

	auth_tkt_h = (rhp_proto_ikev2_auth_tkt_header*)n_payload->ext.n->get_data(n_payload);


	err = _rhp_ikev2_n_auth_tkt_rx_parse(RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_AUTH_TICKET,
			auth_tkt_len,auth_tkt_h,&n_auth_tkt_payload);
	if( err ){
		goto error;
	}

	*n_auth_tkt_payload_r = n_auth_tkt_payload;

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_RX_RTRN,"xxLwx",ikemesg,n_payload,"PROTO_IKE_NOTIFY",n_payload->ext.n->get_message_type(n_payload),*n_auth_tkt_payload_r);
	return 0;

error:
	if( n_auth_tkt_payload ){
		rhp_ikev2_payload_n_auth_tkt_free(n_auth_tkt_payload);
	}
	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_RX_ERR,"xxLwE",ikemesg,n_payload,"PROTO_IKE_NOTIFY",n_payload->ext.n->get_message_type(n_payload),err);
	return err;
}

int rhp_ikev2_new_payload_n_enc_auth_tkt_rx(rhp_ikev2_mesg* ikemesg,rhp_ikev2_payload* n_payload,
		rhp_vpn* resp_vpn,rhp_ikev2_n_auth_tkt_payload** n_auth_tkt_payload_r)
{
	int err = -EINVAL;
	rhp_ikesa* resp_ikesa = NULL;
	int iv_len = 0, icv_len = 0, pld_len = 0, pad_len = 0, enc_len;
	u8 *pld_buf, *my_spi, *enc_p = NULL, *icv_p = NULL;
	rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload = NULL;
  rhp_crypto_integ* integ = NULL;
  rhp_crypto_encr* encr = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_ENC_AUTH_TKT_RX,"xxxLwx",ikemesg,n_payload,resp_vpn,"PROTO_IKE_NOTIFY",n_payload->ext.n->get_message_type(n_payload),n_auth_tkt_payload_r);

	pld_len = n_payload->ext.n->get_data_len(n_payload);
	if( pld_len < 1 ){
		RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_ENC_AUTH_TKT_RX_INVALID_LEN_0,"xxxd",ikemesg,n_payload,resp_vpn,pld_len);
		err = -EINVAL;
		goto error;
	}

	if( pld_len <= RHP_PROTO_IKE_SPI_SIZE ){
		RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_ENC_AUTH_TKT_RX_INVALID_LEN_1,"xxxdd",ikemesg,n_payload,resp_vpn,pld_len,(int)RHP_PROTO_IKE_SPI_SIZE);
		err = -EINVAL;
		goto error;
	}

	pld_buf = n_payload->ext.n->get_data(n_payload);
	my_spi = pld_buf;


	resp_ikesa = resp_vpn->ikesa_list_head;
	while( resp_ikesa ){

		if( (resp_ikesa->state == RHP_IKESA_STAT_ESTABLISHED ||
				 resp_ikesa->state == RHP_IKESA_STAT_REKEYING) &&
				!memcmp(resp_ikesa->init_spi,my_spi,RHP_PROTO_IKE_SPI_SIZE) ){

			RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_ENC_AUTH_TKT_RX_INIT_IKESA,"xxxxdp",ikemesg,n_payload,resp_vpn,resp_ikesa,resp_ikesa->side,RHP_PROTO_IKE_SPI_SIZE,resp_ikesa->init_spi);
			break;
		}

		resp_ikesa = resp_ikesa->next_vpn_list;
	}

	if( resp_ikesa == NULL ){

		resp_ikesa = resp_vpn->ikesa_list_head;
		while( resp_ikesa ){

			if( (resp_ikesa->state == RHP_IKESA_STAT_ESTABLISHED ||
					 resp_ikesa->state == RHP_IKESA_STAT_REKEYING) &&
					!memcmp(resp_ikesa->resp_spi,my_spi,RHP_PROTO_IKE_SPI_SIZE) ){

				RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_ENC_AUTH_TKT_RX_RESP_IKESA,"xxxxdp",ikemesg,n_payload,resp_vpn,resp_ikesa,resp_ikesa->side,RHP_PROTO_IKE_SPI_SIZE,resp_ikesa->resp_spi);
				break;
			}

			resp_ikesa = resp_ikesa->next_vpn_list;
		}
	}

	if( resp_ikesa == NULL ){
		RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_ENC_AUTH_TKT_RX_NO_IKESA,"xxx",ikemesg,n_payload,resp_vpn);
		err = -ENOENT;
		goto error;
	}


	iv_len = resp_ikesa->encr->get_iv_len(resp_ikesa->encr);
	if( resp_ikesa->side == RHP_IKE_INITIATOR ){
		icv_len = resp_ikesa->integ_i->get_output_len(resp_ikesa->integ_i);
	}else{
		icv_len = resp_ikesa->integ_r->get_output_len(resp_ikesa->integ_r);
	}


	if( pld_len < (int)RHP_PROTO_IKE_SPI_SIZE +
							  iv_len + (int)sizeof(rhp_proto_ikev2_auth_tkt_header) + 1 + icv_len ){
		RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_ENC_AUTH_TKT_RX_INVALID_LEN_2,"xxxxddddd",ikemesg,n_payload,resp_vpn,resp_ikesa,pld_len,(int)RHP_PROTO_IKE_SPI_SIZE,iv_len,(int)sizeof(rhp_proto_ikev2_auth_tkt_header),icv_len);
		err = -EINVAL;
		goto error;
	}

	enc_len = pld_len - (RHP_PROTO_IKE_SPI_SIZE + iv_len + icv_len);

	enc_p = (u8*)_rhp_malloc(enc_len + icv_len);
	if( enc_p == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	memcpy(enc_p,(pld_buf + RHP_PROTO_IKE_SPI_SIZE + iv_len),(enc_len + icv_len));
	memset((pld_buf + RHP_PROTO_IKE_SPI_SIZE + iv_len + enc_len),0,icv_len);


	icv_p = (u8*)_rhp_malloc(icv_len);
	if( icv_p == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}


  integ = rhp_crypto_integ_alloc(resp_ikesa->prop.v2.integ_id);
  if( integ == NULL ){
    RHP_BUG("");
    goto error;
  }

  err = integ->set_key(integ,
  				resp_ikesa->keys.v2.sk_dmvpn_a,resp_ikesa->keys.v2.sk_dmvpn_a_len);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

	err = integ->compute(integ,(u8*)pld_buf,pld_len,icv_p,icv_len);
	if( err ){
		RHP_BUG("");
		goto error;
	}

	if( memcmp(icv_p,(enc_p + enc_len),icv_len) ){
		RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_ENC_AUTH_TKT_RX_INVALID_INTEG,"xxxxpp",ikemesg,n_payload,resp_vpn,resp_ikesa,icv_len,icv_p,icv_len,(enc_p + enc_len));
		err = -EINVAL;
		goto error;
	}


	encr = rhp_crypto_encr_alloc(resp_ikesa->prop.v2.encr_id,resp_ikesa->prop.v2.encr_key_bits);
  if( encr == NULL ){
    RHP_BUG("");
    goto error;
  }

  err = encr->set_dec_key(encr,resp_ikesa->keys.v2.sk_dmvpn_e,resp_ikesa->keys.v2.sk_dmvpn_e_len);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

  err = encr->decrypt(encr,(pld_buf + RHP_PROTO_IKE_SPI_SIZE + iv_len),
  				enc_len,enc_p,enc_len,(pld_buf + RHP_PROTO_IKE_SPI_SIZE));
	if( err ){
		RHP_BUG("");
		goto error;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_ENC_AUTH_TKT_RX_DEC,"xxxxpp",ikemesg,n_payload,resp_vpn,resp_ikesa,enc_len,enc_p,enc_len,(pld_buf + RHP_PROTO_IKE_SPI_SIZE));

	pad_len = *((enc_p + enc_len) - 1);

	if( (enc_p + enc_len - pad_len - 1)
			<= enc_p + (int)sizeof(rhp_proto_ikev2_auth_tkt_header) ){
		RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_ENC_AUTH_TKT_RX_INVALID_LEN_3,"xxxxdxddd",ikemesg,n_payload,resp_vpn,resp_ikesa,pad_len,enc_p,enc_len,pad_len,(int)sizeof(rhp_proto_ikev2_auth_tkt_header));
		err = -EINVAL;
		goto error;
	}

	enc_len -= (pad_len + 1);


	err = _rhp_ikev2_n_auth_tkt_rx_parse(RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_ENC_AUTH_TICKET,
					enc_len,(rhp_proto_ikev2_auth_tkt_header*)enc_p,&n_auth_tkt_payload);
	if( err ){
		goto error;
	}


	_rhp_free(enc_p);
	_rhp_free(icv_p);
	rhp_crypto_encr_free(encr);
	rhp_crypto_integ_free(integ);

	*n_auth_tkt_payload_r = n_auth_tkt_payload;

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_ENC_AUTH_TKT_RX_RTRN,"xxxxLwx",ikemesg,n_payload,resp_vpn,resp_ikesa,"PROTO_IKE_NOTIFY",n_payload->ext.n->get_message_type(n_payload),*n_auth_tkt_payload_r);
	return 0;

error:
	if( n_auth_tkt_payload ){
		rhp_ikev2_payload_n_auth_tkt_free(n_auth_tkt_payload);
	}
	if( enc_p ){
		_rhp_free(enc_p);
	}
	if( icv_p ){
		_rhp_free(icv_p);
	}
	if( encr ){
		rhp_crypto_encr_free(encr);
	}
	if( integ ){
		rhp_crypto_integ_free(integ);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_ENC_AUTH_TKT_RX_ERR,"xxxxLwE",ikemesg,n_payload,resp_vpn,resp_ikesa,"PROTO_IKE_NOTIFY",n_payload->ext.n->get_message_type(n_payload),err);
	return err;
}

int rhp_ikev2_new_payload_n_auth_tkt_tx(u16 mesg_type,u8 auth_tkt_type,
		rhp_ikev2_n_auth_tkt_payload** n_auth_tkt_payload_r)
{
	int err = -EINVAL;
	rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_TX,"LwLwx","PROTO_IKE_NOTIFY",mesg_type,"AUTH_TKT",auth_tkt_type,n_auth_tkt_payload_r);

	n_auth_tkt_payload = _rhp_ikev2_payload_n_auth_tkt_alloc(mesg_type,auth_tkt_type);
	if( n_auth_tkt_payload == NULL ){
		err = -ENOMEM;
		goto error;
	}

	*n_auth_tkt_payload_r = n_auth_tkt_payload;

	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_TX_RTRN,"LwLwx","PROTO_IKE_NOTIFY",mesg_type,"AUTH_TKT",auth_tkt_type,*n_auth_tkt_payload_r);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_N_AUTH_TKT_TX_ERR,"LwLwE","PROTO_IKE_NOTIFY",mesg_type,"AUTH_TKT",auth_tkt_type,err);
	return err;
}
