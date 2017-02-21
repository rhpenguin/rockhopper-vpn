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
#include "rhp_vpn.h"
#include "rhp_ikev2.h"
#include "rhp_http.h"
#include "rhp_nhrp.h"


rhp_mutex_t rhp_ikev1_agg_lock;

extern u8 rhp_proto_ikev1_xauth_vid[8];


struct _rhp_ikev1_agg_ctx {

	u8 tag[4]; // '#IAG'

	struct _rhp_ikev1_agg_ctx* next_hash;

  int my_side;
  u8 my_spi[RHP_PROTO_IKE_SPI_SIZE];

  u64 txn_id;

  rhp_ikev2_mesg* rx_ikemesg;
  rhp_ikev2_mesg* tx_ikemesg;

	rhp_ikev2_payload* rx_id_payload; // Ref to rx_ikemesg. Don't free it.
  int peer_id_type;
  int peer_id_len;
  u8* peer_id; // Ref to rx_id_payload. Don't free it.

	rhp_ikev2_payload* rx_sa_payload; // Ref to rx_ikemesg. Don't free it.

	rhp_ikev2_payload* rx_ke_payload; // Ref to rx_ikemesg. Don't free it.

	rhp_ikev2_payload* rx_nonce_payload; // Ref to rx_ikemesg. Don't free it.

	rhp_ikev2_payload* rx_cr_payload; // Ref to rx_ikemesg. Don't free it.

	rhp_ikev2_payload* rx_my_vid_payload; // Ref to rx_ikemesg. Don't free it.

	unsigned long peer_notified_realm_id;
};
typedef struct _rhp_ikev1_agg_ctx rhp_ikev1_agg_ctx;


static rhp_ikev1_agg_ctx* _rhp_ikev1_agg_ctx_hashtbl[2][RHP_VPN_HASH_TABLE_SIZE];
static u32 _rhp_ikev1_agg_ctx_hashtbl_rnd;


extern int rhp_ikev2_ike_auth_setup_larval_vpn(rhp_vpn* larval_vpn,
		rhp_vpn_realm* rlm,rhp_ikesa* ikesa);

extern int rhp_ikev1_ipc_psk_create_auth_req(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg,
		int peer_id_type,int peer_id_len,u8* peer_id,int exchange_type);

extern int rhp_ikev1_ipc_rsasig_create_sign_req(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg);

extern int rhp_ikev1_ipc_rsasig_create_verify_req(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev1_auth_srch_plds_ctx* s_pld_ctx,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg);

extern int rhp_ikev1_ipc_rsasig_create_verify_and_sign_req(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev1_auth_srch_plds_ctx* s_pld_ctx,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg);

extern int rhp_ikev1_rx_i_comp(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_vpn_realm* rlm,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg,int is_rekeyed);

extern int rhp_ikev1_rx_r_comp(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_vpn_realm* rlm,
		rhp_ikev2_mesg* rx_ikemesg,int is_rekeyed);

extern int rhp_ikev1_rx_r_comp_xauth(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_vpn_realm* rlm,
		rhp_ikev2_mesg* rx_ikemesg);

extern int rhp_ikev1_r_clear_old_vpn(rhp_vpn* new_vpn,rhp_ikesa** new_ikesa,
		int rx_initial_contact,int* is_rekeyed_r);

extern int rhp_ikev1_xauth_r_invoke_task(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_ikemesg);


rhp_ikev1_agg_ctx* _rhp_ikev1_agg_ctx_alloc(int my_side,u8* my_spi)
{
  rhp_ikev1_agg_ctx* agg_ctx;

  agg_ctx = (rhp_ikev1_agg_ctx*)_rhp_malloc(sizeof(rhp_ikev1_agg_ctx));
  if( agg_ctx == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(agg_ctx,0,sizeof(rhp_ikev1_agg_ctx));

  agg_ctx->tag[0] = '#';
  agg_ctx->tag[1] = 'I';
  agg_ctx->tag[2] = 'A';
  agg_ctx->tag[3] = 'G';

  agg_ctx->my_side = my_side;
  memcpy(agg_ctx->my_spi,my_spi,RHP_PROTO_IKE_SPI_SIZE);

  agg_ctx->peer_notified_realm_id = RHP_VPN_REALM_ID_UNKNOWN;

  return agg_ctx;
}

void _rhp_ikev1_agg_ctx_free(rhp_ikev1_agg_ctx* agg_ctx)
{
	if( agg_ctx->rx_ikemesg ){
		rhp_ikev2_unhold_mesg(agg_ctx->rx_ikemesg);
	}

	if( agg_ctx->tx_ikemesg ){
		rhp_ikev2_unhold_mesg(agg_ctx->tx_ikemesg);
	}

	_rhp_free(agg_ctx);

	return;
}

static int _rhp_ikev1_agg_ctx_put(rhp_ikev1_agg_ctx* agg_ctx)
{
  u32 hval;

	RHP_TRC(0,RHPTRCID_IKEV1_AGG_CTX_PUT,"xLdG",agg_ctx,"IKE_SIDE",agg_ctx->my_side,agg_ctx->my_spi);

  RHP_LOCK(&rhp_ikev1_agg_lock);

  hval = _rhp_hash_u32s(agg_ctx->my_spi,RHP_PROTO_IKE_SPI_SIZE,_rhp_ikev1_agg_ctx_hashtbl_rnd);
  hval = hval % RHP_VPN_HASH_TABLE_SIZE;

  agg_ctx->next_hash = _rhp_ikev1_agg_ctx_hashtbl[agg_ctx->my_side][hval];
  _rhp_ikev1_agg_ctx_hashtbl[agg_ctx->my_side][hval] = agg_ctx;

  RHP_UNLOCK(&rhp_ikev1_agg_lock);

	RHP_TRC(0,RHPTRCID_IKEV1_AGG_CTX_PUT_RTRN,"x",agg_ctx);
	return 0;
}

static rhp_ikev1_agg_ctx* _rhp_ikev1_agg_ctx_get(int my_side,u8* my_spi)
{
  int err = -ENOENT;
  u32 hval;
  rhp_ikev1_agg_ctx *agg_ctx,*agg_ctx_p = NULL;

	RHP_TRC(0,RHPTRCID_IKEV1_AGG_CTX_GET,"LdG","IKE_SIDE",my_side,my_spi);

  RHP_LOCK(&rhp_ikev1_agg_lock);

  hval = _rhp_hash_u32s(my_spi,RHP_PROTO_IKE_SPI_SIZE,_rhp_ikev1_agg_ctx_hashtbl_rnd);
  hval = hval % RHP_VPN_HASH_TABLE_SIZE;

  agg_ctx = _rhp_ikev1_agg_ctx_hashtbl[my_side][hval];
  while( agg_ctx ){

    if( agg_ctx->my_side == my_side &&
    	  !memcmp(agg_ctx->my_spi,my_spi,RHP_PROTO_IKE_SPI_SIZE) ){
    	break;
    }

    agg_ctx_p = agg_ctx;
    agg_ctx = agg_ctx->next_hash;
  }

  if( agg_ctx == NULL ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_IKEV1_AGG_CTX_PUT_NO_ENTRY,"x",agg_ctx);
  	goto error;
  }

  if( agg_ctx_p ){
    agg_ctx_p->next_hash = agg_ctx->next_hash;
  }else{
    _rhp_ikev1_agg_ctx_hashtbl[my_side][hval] = agg_ctx->next_hash;
  }

  agg_ctx->next_hash = NULL;

  RHP_UNLOCK(&rhp_ikev1_agg_lock);

	RHP_TRC(0,RHPTRCID_IKEV1_AGG_CTX_GET_RTRN,"x",agg_ctx);
  return agg_ctx;

error:
  RHP_UNLOCK(&rhp_ikev1_agg_lock);

  RHP_TRC(0,RHPTRCID_IKEV1_AGG_CTX_GET_ERR,"xE",agg_ctx,err);
  return NULL;
}

static int _rhp_ikev1_agg_ctx_pending(int my_side,u8* my_spi)
{
  u32 hval;
  rhp_ikev1_agg_ctx *agg_ctx;
  int ret;

	RHP_TRC(0,RHPTRCID_IKEV1_AGG_CTX_PENDING,"LdG","IKE_SIDE",my_side,my_spi);

  RHP_LOCK(&rhp_ikev1_agg_lock);

  hval = _rhp_hash_u32s(my_spi,RHP_PROTO_IKE_SPI_SIZE,_rhp_ikev1_agg_ctx_hashtbl_rnd);
  hval = hval % RHP_VPN_HASH_TABLE_SIZE;

  agg_ctx = _rhp_ikev1_agg_ctx_hashtbl[my_side][hval];
  while( agg_ctx ){

    if( agg_ctx->my_side == my_side &&
    	  !memcmp(agg_ctx->my_spi,my_spi,RHP_PROTO_IKE_SPI_SIZE) ){
    	break;
    }

    agg_ctx = agg_ctx->next_hash;
  }

  if( agg_ctx == NULL ){
  	ret = 0;
  }else{
  	ret = 1;
  }

  RHP_UNLOCK(&rhp_ikev1_agg_lock);

	RHP_TRC(0,RHPTRCID_IKEV1_AGG_CTX_PENDING_RTRN,"xd",agg_ctx,ret);
  return ret;
}


rhp_ikev2_mesg* rhp_ikev1_new_pkt_aggressive_i_1(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_vpn_realm* rlm)
{
	int err = -EINVAL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_ikev2_payload* ikepayload = NULL;
  u8* my_id = NULL;
  int my_id_type = 0;
  int my_id_len = 0;
  int dh_group = rhp_ikesa_v1_top_dhgrp();
  int my_cert_issuer_dn_der_len = 0;
  u8* my_cert_issuer_dn_der = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_AGGRESSIVE_I_1,"xxx",vpn,ikesa,rlm);


  tx_ikemesg = rhp_ikev1_new_mesg_tx(RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE,0,0);
  if( tx_ikemesg == NULL ){
    RHP_BUG("");
    goto error;
  }


  {
    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_SA,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    err = ikepayload->ext.v1_sa->set_def_ikesa_prop(ikepayload,NULL,0,dh_group,
    				ikesa->auth_method,ikesa->v1.lifetime);
    if( err ){
      RHP_BUG("");
      goto error;
    }
  }


  if( ikesa->dh == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  if( ikesa->nonce_i == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  {
    int key_len;
    u8* key = ikesa->dh->get_my_pub_key(ikesa->dh,&key_len);

    if( key == NULL ){
    	err = -EINVAL;
      RHP_BUG("");
      goto error;
    }

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_KE,&ikepayload) ){
    	err = -EINVAL;
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.v1_ke->set_key(ikepayload,key_len,key) ){
    	err = -EINVAL;
      RHP_BUG("");
      goto error;
    }
  }

  {
    int nonce_len = ikesa->nonce_i->get_nonce_len(ikesa->nonce_i);
    u8* nonce = ikesa->nonce_i->get_nonce(ikesa->nonce_i);

    if( nonce == NULL ){
    	err = -EINVAL;
      RHP_BUG("");
      goto error;
    }

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_NONCE,&ikepayload) ){
    	err = -EINVAL;
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.nir->set_nonce(ikepayload,nonce_len,nonce) ){
    	err = -EINVAL;
      RHP_BUG("");
      goto error;
    }
  }

  if( rlm->my_auth.my_auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){

		err = rhp_ikev1_get_my_cert_ca_dn_der(rlm,&my_cert_issuer_dn_der,&my_cert_issuer_dn_der_len);
		if( err ){
			RHP_BUG("");
	  	RHP_UNLOCK(&(rlm->lock));
			err = -ENOMEM;
			goto error;
		}

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_CR,&ikepayload) ){
    	err = -EINVAL;
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    ikepayload->ext.v1_cr->set_cert_encoding(ikepayload,RHP_PROTO_IKEV1_CERT_ENC_X509_CERT_SIG);

    if( my_cert_issuer_dn_der ){

			if( ikepayload->ext.v1_cr->set_ca(ikepayload,my_cert_issuer_dn_der_len,my_cert_issuer_dn_der) ){
				err = -EINVAL;
				RHP_BUG("");
				goto error;
			}
    }
  }


  if( rlm->my_auth.my_id.type ){

  	if( rhp_ikev2_id_value(&(rlm->my_auth.my_id),&my_id,&my_id_len,&my_id_type) ){
  		RHP_BUG("");
  		err = -EINVAL;
  		goto error;
  	}

  	my_id_type = rhp_ikev1_id_type(my_id_type);
  	if( my_id_type < 0 ){
  		RHP_BUG("%d",my_id_type);
  		err = -EINVAL;
  		goto error;
  	}

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_ID,&ikepayload) ){
      RHP_BUG("");
  		err = -EINVAL;
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.v1_id->set_id(ikepayload,my_id_type,my_id_len,my_id) ){
      RHP_BUG("");
  		err = -EINVAL;
      goto error;
    }

  }else{

  	err = -EINVAL;
  	goto error;
  }


  {
    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_VID,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.vid->copy_my_app_vid(ikepayload) ){
      RHP_BUG("");
      goto error;
    }
  }

	_rhp_free(my_id);

	if( my_cert_issuer_dn_der ){
		_rhp_free(my_cert_issuer_dn_der);
	}

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_AGGRESSIVE_I_1_RTRN,"xxx",vpn,ikesa,tx_ikemesg);

  return tx_ikemesg;

error:
  if( tx_ikemesg ){
    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }
	if( my_id ){
		_rhp_free(my_id);
	}
	if( my_cert_issuer_dn_der ){
		_rhp_free(my_cert_issuer_dn_der);
	}
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKEV1_TX_ALLOC_AGGRESSIVE_REQ_ERR,"VP",vpn,ikesa);
  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_AGGRESSIVE_I_1_ERR,"xx",vpn,ikesa);
  return NULL;
}

static int _rhp_ikev1_new_pkt_aggressive_r_2(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_vpn_realm* rlm,rhp_ipcmsg* ipcmsg,rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;
  u8* my_id = NULL;
  int my_id_type = 0;
  int my_id_len = 0;
	int hash_octets_len = 0;
	u8* hash_octets = NULL;
  int my_cert_issuer_dn_der_len = 0;
  u8* my_cert_issuer_dn_der = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_AGGRESSIVE_R_2,"xxxxx",vpn,ikesa,rlm,tx_ikemesg,ipcmsg);

  {
    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_SA,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    err = ikepayload->ext.v1_sa->set_matched_ikesa_prop(ikepayload,&(ikesa->prop.v1),NULL,0);
    if( err ){
      RHP_BUG("");
      goto error;
    }
  }


  {
    int key_len;
    u8* key = ikesa->dh->get_my_pub_key(ikesa->dh,&key_len);

    if( key == NULL ){
      RHP_BUG("");
      goto error;
    }

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_KE,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.v1_ke->set_key(ikepayload,key_len,key) ){
      RHP_BUG("");
      goto error;
    }
  }

  {
    int nonce_len = ikesa->nonce_r->get_nonce_len(ikesa->nonce_r);
    u8* nonce = ikesa->nonce_r->get_nonce(ikesa->nonce_r);

    if( nonce == NULL ){
      RHP_BUG("");
      goto error;
    }

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_NONCE,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.nir->set_nonce(ikepayload,nonce_len,nonce) ){
      RHP_BUG("");
      goto error;
    }
  }


  if( rlm->my_auth.my_id.type ){

  	if( rhp_ikev2_id_value(&(rlm->my_auth.my_id),&my_id,&my_id_len,&my_id_type) ){
  		RHP_BUG("");
  		goto error;
  	}

  	my_id_type = rhp_ikev1_id_type(my_id_type);
  	if( my_id_type < 0 ){
  		RHP_BUG("%d",my_id_type);
  		err = -EINVAL;
  		goto error;
  	}

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_ID,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.v1_id->set_id(ikepayload,my_id_type,my_id_len,my_id) ){
      RHP_BUG("");
      goto error;
    }

  }else{

  	err = -EINVAL;
  	goto error;
  }


  if( rlm->my_auth.my_auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ){

  	err = rhp_ikev1_p1_gen_hash_ir(RHP_IKE_RESPONDER,ikesa,
  					0,NULL,
  					my_id_type,my_id_len,my_id,
  					ikesa->keys.v1.skeyid_len,ikesa->keys.v1.skeyid,
  					&hash_octets,&hash_octets_len);
  	if( err ){
  		goto error;
  	}

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_HASH,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.v1_hash->set_hash(ikepayload,hash_octets_len,hash_octets) ){
      RHP_BUG("");
      goto error;
    }


  }else if( rlm->my_auth.my_auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){

  	rhp_ipcmsg_ikev1_rsasig_sign_rep* rsasig_sign_rep
  		= (rhp_ipcmsg_ikev1_rsasig_sign_rep*)ipcmsg;
  	u8 *sign_octets = NULL, *p;
  	unsigned int i;

  	if( rsasig_sign_rep == NULL ){
  		RHP_BUG("");
  		err = -EINVAL;
  		goto error;
  	}

    sign_octets = (u8*)(rsasig_sign_rep + 1);
    p = sign_octets + rsasig_sign_rep->signed_octets_len;

    {
    	rhp_cert_data* der_data = (rhp_cert_data*)p;
    	int rem = rsasig_sign_rep->cert_chain_len;

  		for( i = 0; i < rsasig_sign_rep->cert_chain_num &&
  								rem > (int)sizeof(rhp_cert_data); i++ ){

  	    if( rhp_ikev2_new_payload_tx(tx_ikemesg,
  	    			RHP_PROTO_IKEV1_PAYLOAD_CERT,&ikepayload) ){
  	      RHP_BUG("");
  	  		err = -EINVAL;
  	      goto error;
  	    }

  	    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

  	    ikepayload->ext.cert->set_cert_encoding(ikepayload,
  	    		RHP_PROTO_IKEV1_CERT_ENC_X509_CERT_SIG);

  	    if( ikepayload->ext.cert->set_cert(ikepayload,
  	    			(der_data->len - sizeof(rhp_cert_data)),(u8*)(der_data + 1)) ){
  	      RHP_BUG("");
  	  		err = -EINVAL;
  	      goto error;
  	    }

  			rem -= (int)sizeof(rhp_cert_data) + der_data->len;
  			der_data = (rhp_cert_data*)(((u8*)(der_data + 1)) + der_data->len);
  		}
    }

    {
      if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_SIG,&ikepayload) ){
        RHP_BUG("");
    		err = -EINVAL;
        goto error;
      }

      tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

      if( ikepayload->ext.v1_sig->set_sig(ikepayload,rsasig_sign_rep->signed_octets_len,sign_octets) ){
        RHP_BUG("");
    		err = -EINVAL;
        goto error;
      }
    }

    {
			err = rhp_ikev1_get_my_cert_ca_dn_der(rlm,&my_cert_issuer_dn_der,&my_cert_issuer_dn_der_len);
			if( err ){
				RHP_BUG("");
				RHP_UNLOCK(&(rlm->lock));
				err = -ENOMEM;
				goto error;
			}

			if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_CR,&ikepayload) ){
				err = -EINVAL;
				RHP_BUG("");
				goto error;
			}

			tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

			ikepayload->ext.v1_cr->set_cert_encoding(ikepayload,RHP_PROTO_IKEV1_CERT_ENC_X509_CERT_SIG);

			if( my_cert_issuer_dn_der ){

				if( ikepayload->ext.v1_cr->set_ca(ikepayload,my_cert_issuer_dn_der_len,my_cert_issuer_dn_der) ){
					err = -EINVAL;
					RHP_BUG("");
					goto error;
				}
			}
    }
  }


  {
    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_VID,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.vid->copy_my_app_vid(ikepayload) ){
      RHP_BUG("");
      goto error;
    }
  }

  if( ikesa->prop.v1.xauth_method ){

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_VID,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.vid->set_vid(ikepayload,8,rhp_proto_ikev1_xauth_vid) ){
      RHP_BUG("");
      goto error;
    }
  }


	_rhp_free(my_id);

	if( hash_octets ){
		_rhp_free(hash_octets);
	}

	if( my_cert_issuer_dn_der ){
		_rhp_free(my_cert_issuer_dn_der);
	}

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_AGGRESSIVE_R_2_RTRN,"xx",ikesa,tx_ikemesg);
  return 0;

error:
	if( my_id ){
		_rhp_free(my_id);
	}
	if( hash_octets ){
		_rhp_free(hash_octets);
	}
	if( my_cert_issuer_dn_der ){
		_rhp_free(my_cert_issuer_dn_der);
	}

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_AGGRESSIVE_R_2_ERR,"xE",ikesa,err);
  return err;
}

static int _rhp_ikev1_new_pkt_aggressive_i_3_psk(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_vpn_realm* rlm,rhp_ipcmsg_ikev1_psk_skeyid_rep* psk_rep,rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;
  u8* skeyid = (u8*)(psk_rep + 1);
	int hash_octets_len = 0;
	u8* hash_octets = NULL;
  u8* my_id = NULL;
  int my_id_type = 0;
  int my_id_len = 0;


  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_AGGRESSIVE_I_3_PSK,"xxxx",vpn,ikesa,psk_rep,tx_ikemesg);

  if( ikesa->v1.tx_initial_contact &&
  		!rhp_gcfg_ikev1_dont_tx_initial_contact ){

  	if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_N,&ikepayload) ){
  		RHP_BUG("");
  		err = -EINVAL;
  		goto error;
  	}

  	tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

  	ikepayload->ext.n->set_protocol_id(ikepayload,RHP_PROTO_IKEV1_PROP_PROTO_ID_ISAKMP);

  	ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKEV1_N_ST_INITIAL_CONTACT);

  	ikepayload->ext.n->v1_set_ikesa_spi(ikepayload,ikesa->init_spi,ikesa->resp_spi);
  }

  {
  	if( rhp_ikev2_id_value(&(rlm->my_auth.my_id),&my_id,&my_id_len,&my_id_type) ){
  		RHP_BUG("");
  		err = -EINVAL;
  		goto error;
  	}

  	my_id_type = rhp_ikev1_id_type(my_id_type);
  	if( my_id_type < 0 ){
  		RHP_BUG("%d",my_id_type);
  		err = -EINVAL;
  		goto error;
  	}

  	err = rhp_ikev1_p1_gen_hash_ir(RHP_IKE_INITIATOR,ikesa,
  					0,NULL,
  					my_id_type,my_id_len,my_id,psk_rep->skeyid_len,skeyid,
  					&hash_octets,&hash_octets_len);
  	if( err ){
  		goto error;
  	}

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_HASH,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.v1_hash->set_hash(ikepayload,hash_octets_len,hash_octets) ){
      RHP_BUG("");
      goto error;
    }
  }

	tx_ikemesg->v1_p1_last_mesg = 1;

	_rhp_free(hash_octets);
	_rhp_free(my_id);

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_AGGRESSIVE_I_3_PSK_RTRN,"xx",ikesa,tx_ikemesg);
  return 0;

error:
	if( hash_octets ){
		_rhp_free(hash_octets);
	}
	if( my_id ){
		_rhp_free(my_id);
	}
	RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_AGGRESSIVE_I_3_PSK_ERR,"xxE",ikesa,tx_ikemesg,err);
	return err;
}

static int _rhp_ikev1_new_pkt_aggressive_i_3_rsasig(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ipcmsg_ikev1_rsasig_sign_rep* rsasig_sign_rep,rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;
	u8 *sign_octets = NULL, *p;
	unsigned int i;

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_AGGRESSIVE_I_3_RSASIG,"xxxx",vpn,ikesa,rsasig_sign_rep,tx_ikemesg);

  sign_octets = (u8*)(rsasig_sign_rep + 1);
  p = sign_octets + rsasig_sign_rep->signed_octets_len;

  if( ikesa->v1.tx_initial_contact &&
  		!rhp_gcfg_ikev1_dont_tx_initial_contact ){

  	if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_N,&ikepayload) ){
  		RHP_BUG("");
  		err = -EINVAL;
  		goto error;
  	}

  	tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

  	ikepayload->ext.n->set_protocol_id(ikepayload,RHP_PROTO_IKEV1_PROP_PROTO_ID_ISAKMP);

  	ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKEV1_N_ST_INITIAL_CONTACT);

  	ikepayload->ext.n->v1_set_ikesa_spi(ikepayload,ikesa->init_spi,ikesa->resp_spi);
  }

  {
  	rhp_cert_data* der_data = (rhp_cert_data*)p;
  	int rem = rsasig_sign_rep->cert_chain_len;

		for( i = 0; i < rsasig_sign_rep->cert_chain_num &&
								rem > (int)sizeof(rhp_cert_data); i++ ){

	    if( rhp_ikev2_new_payload_tx(tx_ikemesg,
	    			RHP_PROTO_IKEV1_PAYLOAD_CERT,&ikepayload) ){
	      RHP_BUG("");
	  		err = -EINVAL;
	      goto error;
	    }

	    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

	    ikepayload->ext.cert->set_cert_encoding(ikepayload,
	    		RHP_PROTO_IKEV1_CERT_ENC_X509_CERT_SIG);

	    if( ikepayload->ext.cert->set_cert(ikepayload,
	    			(der_data->len - sizeof(rhp_cert_data)),(u8*)(der_data + 1)) ){
	      RHP_BUG("");
	  		err = -EINVAL;
	      goto error;
	    }

			rem -= (int)sizeof(rhp_cert_data) + der_data->len;
			der_data = (rhp_cert_data*)(((u8*)(der_data + 1)) + der_data->len);
		}
  }

  {
    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_SIG,&ikepayload) ){
      RHP_BUG("");
  		err = -EINVAL;
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.v1_sig->set_sig(ikepayload,rsasig_sign_rep->signed_octets_len,sign_octets) ){
      RHP_BUG("");
  		err = -EINVAL;
      goto error;
    }
  }

	tx_ikemesg->v1_p1_last_mesg = 1;

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_AGGRESSIVE_I_3_RSASIG_RTRN,"xx",ikesa,tx_ikemesg);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_AGGRESSIVE_I_3_RSASIG_ERR,"xxE",ikesa,tx_ikemesg,err);
	return err;
}


static int _rhp_ikev1_aggressive_ipc_rslv_auth_req(rhp_ikev2_mesg* rx_ikemesg,
		int side,u8* spi,
		int peer_id_type,int peer_id_len,u8* peer_id,unsigned long peer_notified_realm_id,
		int txn_id_flag,rhp_ipcmsg** ipcmsg_r,u64* txn_id_r)
{
  int err = 0;
  int len;
  rhp_ipcmsg_ikev1_rslv_auth_req* rslv_auth_req;
  u64 ipc_txn_id = 0;
  u8* p;

  RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSLV_AUTH_REQ,"xLdGLdpxxdxu",rx_ikemesg,"IKE_SIDE",side,spi,"PROTO_IKE_ID",peer_id_type,peer_id_len,peer_id,ipcmsg_r,txn_id_flag,txn_id_r,peer_notified_realm_id);

  len = sizeof(rhp_ipcmsg_ikev1_rslv_auth_req) + peer_id_len;
  if( peer_id_type == RHP_PROTO_IKE_ID_FQDN ||
  		peer_id_type == RHP_PROTO_IKE_ID_RFC822_ADDR ){
  	len++;
  }


  rslv_auth_req = (rhp_ipcmsg_ikev1_rslv_auth_req*)rhp_ipc_alloc_msg(
  									RHP_IPC_IKEV1_RESOLVE_AUTH_REQUEST,len);
  if( rslv_auth_req == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  p = (u8*)(rslv_auth_req + 1);


  rslv_auth_req->len = len;

  if( txn_id_flag ){

  	ipc_txn_id = rhp_ikesa_new_ipc_txn_id();

  	if( txn_id_r ){
    	*txn_id_r = ipc_txn_id;
    }
  }
  rslv_auth_req->txn_id = ipc_txn_id;

  rslv_auth_req->side = side;
	memcpy(rslv_auth_req->spi,spi,RHP_PROTO_IKE_SPI_SIZE);

	rslv_auth_req->exchange_type = RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE;

	{
		rslv_auth_req->peer_id_type = peer_id_type;
		memcpy(p,peer_id,peer_id_len);
		if( peer_id_type == RHP_PROTO_IKE_ID_FQDN ||
				peer_id_type == RHP_PROTO_IKE_ID_RFC822_ADDR ){
			p[peer_id_len] = '\0';
			p++;
			rslv_auth_req->peer_id_len = peer_id_len + 1;
		}else{
			rslv_auth_req->peer_id_len = peer_id_len;
		}
		p += peer_id_len;
	}

	rslv_auth_req->peer_notified_realm_id = peer_notified_realm_id;


  *ipcmsg_r = (rhp_ipcmsg*)rslv_auth_req;

  RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSLV_AUTH_REQ_RTRN,"xp",rx_ikemesg,rslv_auth_req->len,rslv_auth_req);
  return 0;

error:
  if( rslv_auth_req ){
    _rhp_free_zero(rslv_auth_req,rslv_auth_req->len);
  }
  RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSLV_AUTH_REQ_ERR,"xE",rx_ikemesg,err);
  return err;
}

int _rhp_ikev1_aggressive_check_plds_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_ikev1_agg_ctx* agg_ctx = (rhp_ikev1_agg_ctx*)ctx;
  u8 pld_id = payload->get_payload_id(payload);

  RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_CHECK_PLDS_CB,"xdxxxb",rx_ikemesg,enum_end,payload,payload->ext.v1_id,ctx,pld_id);

  switch( pld_id ){

  case RHP_PROTO_IKEV1_PAYLOAD_SA:

  	agg_ctx->rx_sa_payload = payload;
  	break;

  case RHP_PROTO_IKEV1_PAYLOAD_KE:

  	agg_ctx->rx_ke_payload = payload;
  	break;

  case RHP_PROTO_IKEV1_PAYLOAD_NONCE:

  	agg_ctx->rx_nonce_payload = payload;
  	break;

  case RHP_PROTO_IKEV1_PAYLOAD_CR:

  	agg_ctx->rx_cr_payload = payload;
  	break;

  case RHP_PROTO_IKEV1_PAYLOAD_VID:

  	if( payload->ext.vid == NULL ){
			RHP_BUG("");
			return -EINVAL;
  	}

  	if( payload->ext.vid->is_my_app_id(payload,NULL) ){
    	agg_ctx->rx_my_vid_payload = payload;
  	}

  	break;

  case RHP_PROTO_IKEV1_PAYLOAD_ID:
  {
		if( payload->ext.v1_id == NULL ){
			RHP_BUG("");
			return -EINVAL;
		}

		agg_ctx->peer_id_type = payload->ext.v1_id->get_id_type(payload);
		agg_ctx->peer_id_len = payload->ext.v1_id->get_id_len(payload);

		agg_ctx->peer_id = payload->ext.v1_id->get_id(payload);
		if( agg_ctx->peer_id == NULL ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_CHECK_PLDS_CB_GET_ID_ERR,"x",rx_ikemesg);
			goto error;
		}

		agg_ctx->rx_id_payload = payload;
  }
  	break;

  default:
  	break;
  }
  err = 0;


error:
	if( err ){
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_CHECK_PAYLOADS_ERR,"KbE",rx_ikemesg,pld_id,err);
	}
	RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_CHECK_PLDS_CB_RTRN,"xxxxE",rx_ikemesg,payload,payload->ext.v1_id,ctx,err);
  return err;
}

static int _rhp_ikev1_agg_srch_n_realm_id_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
			rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	int rx_len = 0;
	u8* rx_data = NULL;
	rhp_ikev1_agg_ctx* agg_ctx = (rhp_ikev1_agg_ctx*)ctx;

  RHP_TRC(0,RHPTRCID_IKEV1_AGG_SRCH_N_REALM_ID_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

  rx_len = payload->ext.n->get_data_len(payload);
	rx_data = payload->ext.n->get_data(payload);

	if( rx_len == sizeof(u32) ){

		unsigned long peer_notified_realm_id = ntohl(*((u32*)rx_data));

    RHP_TRC(0,RHPTRCID_IKEV1_AGG_SRCH_N_REALM_ID_CB_DATA,"xu",rx_ikemesg,peer_notified_realm_id);

    if( peer_notified_realm_id &&
    		peer_notified_realm_id <= RHP_VPN_REALM_ID_MAX ){

     	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKE_AUTH_N_REALM_ID_PAYLOAD,"Ku",rx_ikemesg,peer_notified_realm_id);

     	agg_ctx->peer_notified_realm_id = peer_notified_realm_id;

    }else{

    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKE_AUTH_N_INVALID_REALM_ID_PAYLOAD,"Ku",rx_ikemesg,peer_notified_realm_id);
  		RHP_TRC(0,RHPTRCID_IKEV1_AGG_SRCH_N_REALM_ID_CB_BAD_ID,"xxxu",rx_ikemesg,payload,ctx,peer_notified_realm_id);
    }

	}else{

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKE_AUTH_N_INVALID_REALM_ID_PAYLOAD_LEN,"Kd",rx_ikemesg,rx_len);
		RHP_TRC(0,RHPTRCID_IKEV1_AGG_SRCH_N_REALM_ID_CB_BAD_LEN,"xxxd",rx_ikemesg,payload,ctx,rx_len);
	}

  err = 0;

	RHP_TRC(0,RHPTRCID_IKEV1_AGG_SRCH_N_REALM_ID_CB_RTRN,"xxxE",rx_ikemesg,payload,ctx,err);
	return err;
}


static int _rhp_ikev1_rx_aggressive_r_1(rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg,
		rhp_vpn** vpn_i,int* my_ikesa_side_i,u8* my_ikesa_spi_i)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_proto_ike* ikeh = rx_ikemesg->rx_pkt->app.ikeh;
  rhp_ikev1_agg_ctx* agg_ctx = NULL;
  rhp_ipcmsg* rslv_auth_req = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_1,"x",rx_ikemesg);

  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


  if( _rhp_ikev1_agg_ctx_pending(RHP_IKE_INITIATOR,ikeh->init_spi) ){
  	err = RHP_STATUS_IKEV2_MESG_HANDLER_END;
  	goto error;
  }


  agg_ctx = _rhp_ikev1_agg_ctx_alloc(RHP_IKE_INITIATOR,ikeh->init_spi);
  if( agg_ctx == NULL ){
  	err = -ENOMEM;
  	RHP_BUG("");
  	goto error;
  }


  {
  	u8 pld_ids[6] = {	RHP_PROTO_IKEV1_PAYLOAD_SA,
  										RHP_PROTO_IKEV1_PAYLOAD_KE,
  										RHP_PROTO_IKEV1_PAYLOAD_NONCE,
  										RHP_PROTO_IKEV1_PAYLOAD_ID,
  										RHP_PROTO_IKEV1_PAYLOAD_VID,
  										RHP_PROTO_IKE_NO_MORE_PAYLOADS};

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  					rhp_ikev2_mesg_srch_cond_payload_ids,pld_ids,
			  		_rhp_ikev1_aggressive_check_plds_cb,agg_ctx);

    if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
      RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_3_PSK_ENUM_PLDS_ERR,"xd",rx_ikemesg,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_1_CHECK_PAYLOADS_ERR,"KE",rx_ikemesg,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }


    if( agg_ctx->rx_id_payload == NULL 		||
    		agg_ctx->rx_ke_payload == NULL  	||
    		agg_ctx->rx_nonce_payload == NULL ||
    		agg_ctx->rx_sa_payload == NULL ){

      RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_3_PSK_ENUM_PLDS_ERR_2,"xxxxxd",rx_ikemesg,agg_ctx->rx_id_payload,agg_ctx->rx_ke_payload,agg_ctx->rx_nonce_payload,agg_ctx->rx_sa_payload,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_1_CHECK_PAYLOADS_ERR_2,"KE",rx_ikemesg,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }

    err = 0;
  }

  if( agg_ctx->rx_my_vid_payload ){

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  					rhp_ikev2_mesg_srch_cond_n_mesg_id,(void*)((unsigned long)RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_REALM_ID),
  					_rhp_ikev1_agg_srch_n_realm_id_cb,agg_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_1_PARSE_N_REALM_ID_PAYLOAD_ERR,"KE",rx_ikemesg,err);
  		RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_1_REALM_ID_PARSE_ERR,"xE",rx_ikemesg,err);
      err = RHP_STATUS_INVALID_MSG;
    	goto error;
  	}
  }


  err = _rhp_ikev1_aggressive_ipc_rslv_auth_req(rx_ikemesg,
					RHP_IKE_INITIATOR,ikeh->init_spi,
					agg_ctx->peer_id_type,agg_ctx->peer_id_len,agg_ctx->peer_id,
					agg_ctx->peer_notified_realm_id,1,&rslv_auth_req,&(agg_ctx->txn_id));
  if( err ){
  	goto error;
  }

  agg_ctx->rx_ikemesg = rx_ikemesg;
  rhp_ikev2_hold_mesg(rx_ikemesg);
  agg_ctx->tx_ikemesg = tx_ikemesg;
  rhp_ikev2_hold_mesg(tx_ikemesg);

  _rhp_ikev1_agg_ctx_put(agg_ctx);


  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)rslv_auth_req,rslv_auth_req->len,0) < 0 ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  _rhp_free_zero(rslv_auth_req,rslv_auth_req->len);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_1_RTRN,"xx",rx_ikemesg,agg_ctx);

  return RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;

error:

	if( err != RHP_STATUS_IKEV2_MESG_HANDLER_END ){

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_1_ERR,"KE",rx_ikemesg,err);
	}

	if(agg_ctx){
		_rhp_ikev1_agg_ctx_free(agg_ctx);
	}

	if( rslv_auth_req ){
		_rhp_free_zero(rslv_auth_req,rslv_auth_req->len);
	}

  RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_1_ERR,"xxE",rx_ikemesg,agg_ctx,err);
  return err;
}

static int _rhp_ikev1_rx_aggressive_r_1_bh0(rhp_ikev1_agg_ctx* agg_ctx,unsigned long rlm_id)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_ip_addr peer_addr, rx_addr;
  rhp_proto_ike* ikeh = agg_ctx->rx_ikemesg->rx_pkt->app.ikeh;
  rhp_vpn* larval_vpn = NULL;
  rhp_ikesa* ikesa = NULL;
  rhp_ikesa_init_i* init_i = NULL;
  int auth_method = 0, xauth_method = 0;
  unsigned long lifetime = 0;
  rhp_ike_sa_init_srch_plds_ctx s_pld_ctx;
  rhp_ikev1_auth_srch_plds_ctx* s_pld_auth_ctx = NULL;
  rhp_vpn_realm* rlm = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_1_BH0,"xxu",agg_ctx,agg_ctx->rx_ikemesg,rlm_id);

  rhp_ip_addr_reset(&peer_addr);
  rhp_ip_addr_reset(&rx_addr);

  if( agg_ctx->rx_ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE ){

    rhp_ip_addr_set(&peer_addr,AF_INET,
    		(u8*)&(agg_ctx->rx_ikemesg->rx_pkt->l3.iph_v4->src_addr),NULL,32,
    		agg_ctx->rx_ikemesg->rx_pkt->l4.udph->src_port,0);

    rhp_ip_addr_set2(&rx_addr,AF_INET,
    		(u8*)&(agg_ctx->rx_ikemesg->rx_pkt->l3.iph_v4->dst_addr),
    		agg_ctx->rx_ikemesg->rx_pkt->l4.udph->dst_port);

    RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_1_BH0_PEER_ADDR,"xd4WXd",agg_ctx->rx_ikemesg,peer_addr.addr_family,peer_addr.addr.v4,peer_addr.port,peer_addr.netmask.v4,peer_addr.prefixlen);

  }else if( agg_ctx->rx_ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE ){

    rhp_ip_addr_set(&peer_addr,AF_INET6,
    		agg_ctx->rx_ikemesg->rx_pkt->l3.iph_v6->src_addr,NULL,128,
    		agg_ctx->rx_ikemesg->rx_pkt->l4.udph->src_port,0);

    rhp_ip_addr_set2(&rx_addr,AF_INET6,
    		(u8*)&(agg_ctx->rx_ikemesg->rx_pkt->l3.iph_v6->dst_addr),
    		agg_ctx->rx_ikemesg->rx_pkt->l4.udph->dst_port);

    RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_1_BH0_PEER_ADDR_V6,"xd6WXd",agg_ctx->rx_ikemesg,peer_addr.addr_family,peer_addr.addr.v6,peer_addr.port,peer_addr.netmask.v4,peer_addr.prefixlen);

  }else{
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  memset(&s_pld_ctx,0,sizeof(rhp_ike_sa_init_srch_plds_ctx));

	s_pld_auth_ctx = rhp_ikev1_auth_alloc_srch_ctx();
	if( s_pld_auth_ctx == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}


	{
		rlm = rhp_realm_get(rlm_id);
		if( rlm == NULL ){
			RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_1_BH0_NO_REALM,"x",agg_ctx);
			goto error;
		}

		RHP_LOCK(&(rlm->lock));

		if( !_rhp_atomic_read(&(rlm->is_active)) ){

			RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_1_BH0_REALM_NOT_ACTIVE,"x",agg_ctx,rlm);

			RHP_UNLOCK(&(rlm->lock));

			goto error;
		}

		if( rlm->my_auth.my_auth_method != RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG &&
				rlm->my_auth.my_auth_method != RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ){

			err = -EINVAL;
			RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_1_BH0_NO_VALID_AUTH_METHOD_FOUND,"xdE",agg_ctx->rx_ikemesg,rlm->my_auth.my_auth_method,err);

			RHP_UNLOCK(&(rlm->lock));

			goto error;
		}


		if( rlm->my_auth.my_xauth_method == RHP_XAUTH_P1_AUTH_PSK ){
			xauth_method = RHP_PROTO_IKE_AUTHMETHOD_XAUTH_INIT_PSK;
			auth_method = RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY;
		}else if( rlm->my_auth.my_xauth_method == RHP_XAUTH_P1_AUTH_RSASIG ){
			xauth_method = RHP_PROTO_IKE_AUTHMETHOD_XAUTH_INIT_RSASIG;
			auth_method = RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG;
		}else{

			//
			// RHP_XAUTH_P1_AUTH_HYBRID_RSASIG is not needed for a aggressive mode responder.
			//

			auth_method = rlm->my_auth.my_auth_method;
		}

		lifetime = rlm->ikesa.lifetime_hard;

		RHP_UNLOCK(&(rlm->lock));
	}


  {
  	s_pld_ctx.dup_flag = 0;
    s_pld_ctx.resolved_prop.v1.auth_method = auth_method;
    s_pld_ctx.resolved_prop.v1.xauth_method = xauth_method;
    s_pld_ctx.resolved_prop.v1.life_time = lifetime;

  	err = rhp_ikev1_srch_sa_cb(agg_ctx->rx_ikemesg,0,agg_ctx->rx_sa_payload,&s_pld_ctx);
    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_RX_IKEV1_AGGRESSIVE_R_1_BH_ENUM_SA_PLD_ERR,"xxd",agg_ctx->rx_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_1_PARSE_SA_PAYLOAD_ERR,"KE",agg_ctx->rx_ikemesg,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }

    err = 0;
  }

  if( agg_ctx->rx_my_vid_payload ){

  	s_pld_ctx.dup_flag = 0;

  	err = rhp_ikev2_ike_sa_init_srch_my_vid_cb(agg_ctx->rx_ikemesg,0,agg_ctx->rx_my_vid_payload,&s_pld_ctx);
  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
  		RHP_TRC(0,RHPTRCID_RX_IKEV1_AGGRESSIVE_R_1_BH_ENUM_MY_VENDOR_ID_ERR,"xE",agg_ctx->rx_ikemesg,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_1_PARSE_V_PAYLOAD_ERR,"KE",agg_ctx->rx_ikemesg,err);
    	goto error;
  	}
    err = 0;
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rhp_ikev1_srch_nonce_cb(agg_ctx->rx_ikemesg,0,agg_ctx->rx_nonce_payload,&s_pld_ctx);
    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_RHPTRCID_IKEV1_RX_AGGRESSIVE_R_1_BH0_ENUM_NONCE_PLD_ERR,"xd",agg_ctx->rx_ikemesg,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_1_PARSE_NONCE_PAYLOAD_ERR,"KE",agg_ctx->rx_ikemesg,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
    err = 0;
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rhp_ikev1_srch_ke_cb(agg_ctx->rx_ikemesg,0,agg_ctx->rx_ke_payload,&s_pld_ctx);
    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_1_BH0_ENUM_KE_PLD_ERR,"xd",agg_ctx->rx_ikemesg,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_1_PARSE_KE_PAYLOAD_ERR,"KE",agg_ctx->rx_ikemesg,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
    err = 0;
  }

  {
  	s_pld_auth_ctx->dup_flag = 0;

  	err = rhp_ikev1_auth_srch_id_cb(agg_ctx->rx_ikemesg,0,agg_ctx->rx_id_payload,s_pld_auth_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_1_BH0_ENUM_ID_PLD_ERR,"xd",agg_ctx->rx_ikemesg,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_1_PARSE_ID_PAYLOAD_ERR,"KE",agg_ctx->rx_ikemesg,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
  }


  if( auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG &&
  		agg_ctx->rx_cr_payload ){

  	s_pld_ctx.dup_flag = 0;

  	err = rhp_ikev1_srch_cert_req_cb(agg_ctx->rx_ikemesg,0,agg_ctx->rx_cr_payload,&s_pld_ctx);
    if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
      RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_1_BH0_ENUM_CERT_REQ_PLD_ERR,"xd",agg_ctx->rx_ikemesg,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_1_PARSE_CERT_REQ_PAYLOAD_ERR,"KE",agg_ctx->rx_ikemesg,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
    err = 0;
  }



  larval_vpn = rhp_vpn_alloc(NULL,NULL,NULL,NULL,RHP_IKE_RESPONDER); // (xx*)
  if( larval_vpn == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }


  RHP_LOCK(&(larval_vpn->lock));

  _rhp_atomic_set(&(larval_vpn->is_active),1);

  larval_vpn->is_v1 = 1;

  larval_vpn->vpn_realm_id = rlm_id;


  ikesa = rhp_ikesa_v1_aggressive_new_r(&(s_pld_ctx.resolved_prop.v1));
  if( ikesa == NULL ){
  	RHP_BUG("");
    err = -EINVAL;
  	goto error;
  }

  larval_vpn->ikesa_put(larval_vpn,ikesa);


  err = ikesa->dh->set_peer_pub_key(ikesa->dh,s_pld_ctx.peer_dh_pub_key,s_pld_ctx.peer_dh_pub_key_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  err = ikesa->nonce_i->set_nonce(ikesa->nonce_i,s_pld_ctx.nonce,s_pld_ctx.nonce_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  err = rhp_ikev2_id_setup(s_pld_auth_ctx->peer_id_type,s_pld_auth_ctx->peer_id,
  				s_pld_auth_ctx->peer_id_len,&(larval_vpn->peer_id));
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  {
  	rhp_proto_ikev1_sa_payload* sa_payloadh
  		= (rhp_proto_ikev1_sa_payload*)agg_ctx->rx_sa_payload->payloadh;
		int sa_b_len = ntohs(sa_payloadh->len) - 4;

		ikesa->v1.sai_b = (u8*)_rhp_malloc(sa_b_len);
		if( ikesa->v1.sai_b == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		memcpy(ikesa->v1.sai_b,((u8*)sa_payloadh) + 4,sa_b_len);
		ikesa->v1.sai_b_len = sa_b_len;
	}


  larval_vpn->peer_is_rockhopper = s_pld_ctx.peer_is_rockhopper;
  larval_vpn->peer_rockhopper_ver = s_pld_ctx.peer_rockhopper_ver;
  ikesa->peer_is_rockhopper = s_pld_ctx.peer_is_rockhopper;
  ikesa->peer_rockhopper_ver = s_pld_ctx.peer_rockhopper_ver;


 	RHP_LOCK(&(agg_ctx->rx_ikemesg->rx_pkt->rx_ifc->lock));
 	{
 		larval_vpn->set_local_net_info(larval_vpn,agg_ctx->rx_ikemesg->rx_pkt->rx_ifc,
 				rx_addr.addr_family,rx_addr.addr.raw);
  }
	RHP_UNLOCK(&(agg_ctx->rx_ikemesg->rx_pkt->rx_ifc->lock));

  ikesa->set_init_spi(ikesa,ikeh->init_spi);

  larval_vpn->set_peer_addr(larval_vpn,&peer_addr,&peer_addr);

  larval_vpn->origin_peer_port = agg_ctx->rx_ikemesg->rx_pkt->l4.udph->src_port;


  {
		RHP_LOCK(&(rlm->lock));

		if( !_rhp_atomic_read(&(rlm->is_active)) ){
			RHP_UNLOCK(&(rlm->lock));
			RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_1_BH0_REALM_NOT_ACTIVE,"xxx",larval_vpn,ikesa,rlm);
			goto error;
		}

		err = larval_vpn->check_cfg_address(larval_vpn,rlm,agg_ctx->rx_ikemesg->rx_pkt);
		if( err ){

			RHP_UNLOCK(&(rlm->lock));

			RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_1_BH0_CHECK_CFG_ADDR_ERR,"xxxxE",agg_ctx->rx_ikemesg,agg_ctx->rx_ikemesg->rx_pkt,larval_vpn,rlm,err);

			rhp_ikev2_g_statistics_inc(rx_ikev1_req_unknown_if_err_packets);

			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,rlm_id,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_1_IKE_PKT_VIA_UNCONFIGURED_IF,"KVi",agg_ctx->rx_ikemesg,larval_vpn,agg_ctx->rx_ikemesg->rx_pkt->rx_if_index);

			err = RHP_STATUS_INVALID_IKEV2_MESG_CHECK_CFG_ADDR_ERR;
			goto error;
		}

		RHP_UNLOCK(&(rlm->lock));
  }


  init_i = rhp_ikesa_alloc_init_i(ikesa->resp_spi,&peer_addr,agg_ctx->rx_ikemesg);
  if( init_i == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  err = rhp_vpn_ikesa_spi_put(larval_vpn,ikesa->side,ikesa->resp_spi);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }


  rhp_ikesa_init_i_put(init_i,&(ikesa->ike_init_i_hash));
  init_i = NULL;

  rhp_vpn_ikesa_v1_spi_put(&rx_addr,&peer_addr,
  		RHP_IKE_RESPONDER,ikesa->resp_spi,ikesa->init_spi);



  if( auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){

		err = ikesa->dh->compute_key(ikesa->dh);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		err = rhp_ikev1_gen_rsasig_skeyid(larval_vpn,ikesa,
						&(ikesa->keys.v1.skeyid),&(ikesa->keys.v1.skeyid_len));
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

    err = rhp_ikev1_ipc_rsasig_create_sign_req(larval_vpn,ikesa,
    				agg_ctx->rx_ikemesg,agg_ctx->tx_ikemesg);
    if( err ){
    	goto error;
    }

  }else if( auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ){

    err = rhp_ikev1_ipc_psk_create_auth_req(larval_vpn,ikesa,
    				agg_ctx->rx_ikemesg,agg_ctx->tx_ikemesg,0,0,NULL,
    				RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE);
    if( err ){
    	goto error;
    }

  }else{
  	RHP_BUG("%d",auth_method);
  	err = -EINVAL;
  	goto error;
  }

  {
		larval_vpn->connecting = 1;
		rhp_ikesa_half_open_sessions_inc();
  }

  RHP_UNLOCK(&(larval_vpn->lock));

	rhp_realm_unhold(rlm);

	rhp_ikev1_auth_free_srch_ctx(s_pld_auth_ctx);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_1_BH0_RTRN,"xxxx",agg_ctx,agg_ctx->rx_ikemesg,larval_vpn,ikesa);
  return 0;

error:

	if( larval_vpn ){

		rhp_vpn_ref* larval_vpn_ref = rhp_vpn_hold_ref(larval_vpn); // (xx*)

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,larval_vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_1_ERR,"KVPE",agg_ctx->rx_ikemesg,larval_vpn,ikesa,err);

    rhp_vpn_destroy(larval_vpn); // ikesa is also released.

    RHP_UNLOCK(&(larval_vpn->lock));
		rhp_vpn_unhold(larval_vpn_ref); // (xx*)

	}else{

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_1_ERR_2,"KE",agg_ctx->rx_ikemesg,err);
  }

	if( init_i ){
    rhp_ikesa_free_init_i(init_i);
  }

	if( s_pld_auth_ctx ){
		rhp_ikev1_auth_free_srch_ctx(s_pld_auth_ctx);
	}

	if( rlm ){
		rhp_realm_unhold(rlm);
	}

  RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_1_BH0_ERR,"xxE",agg_ctx,agg_ctx->rx_ikemesg,err);
  return err;
}

static int _rhp_ikev1_rx_aggressive_r_1_psk_bh1(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_vpn_realm* rlm,rhp_ipcmsg_ikev1_psk_skeyid_rep* psk_rep,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
  u8* skeyid = (u8*)(psk_rep + 1);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_1_PSK_BH1,"xxxxxxd",vpn,ikesa,rlm,psk_rep,rx_ikemesg,tx_ikemesg,ikesa->v1.tx_initial_contact);

  {
		err = ikesa->dh->compute_key(ikesa->dh);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		err = ikesa->generate_keys_v1(ikesa,psk_rep->skeyid_len,skeyid);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		err = ikesa->encr->set_enc_key(ikesa->encr,ikesa->keys.v1.sk_e,ikesa->keys.v1.sk_e_len);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		err = ikesa->encr->set_dec_key(ikesa->encr,ikesa->keys.v1.sk_e,ikesa->keys.v1.sk_e_len);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
  }


  if( vpn->eap.role == RHP_EAP_DISABLED ){

		if( psk_rep->eap_role == RHP_EAP_AUTHENTICATOR ){

			if( vpn->origin_side != RHP_IKE_RESPONDER || ikesa->side != RHP_IKE_RESPONDER ){
				RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_1_PSK_BH1_INVALID_XAUTH_SIDE_1,"xxxLdLd",psk_rep,vpn,ikesa,"IKE_SIDE",vpn->origin_side,"IKE_SIDE",ikesa->side);
				goto error;
			}

			vpn->eap.role = RHP_EAP_AUTHENTICATOR;
			vpn->eap.eap_method = vpn->eap.peer_id.method = psk_rep->eap_method;

		}else if( psk_rep->eap_role == RHP_EAP_SUPPLICANT ){

			if( vpn->origin_side != RHP_IKE_INITIATOR || ikesa->side != RHP_IKE_INITIATOR ){
				RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_1_PSK_BH1_INVALID_XAUTH_SIDE_2,"xxxLdLd",psk_rep,vpn,ikesa,"IKE_SIDE",vpn->origin_side,"IKE_SIDE",ikesa->side);
				goto error;
			}

		}else if( psk_rep->eap_role == RHP_EAP_DISABLED ){

			vpn->eap.role = RHP_EAP_DISABLED;

		}else{
			RHP_BUG("%d",psk_rep->eap_role);
			goto error;
		}

  }else{

  	if( vpn->eap.role != (int)psk_rep->eap_role ){
  		RHP_BUG("%d,%d",psk_rep->eap_role,vpn->eap.role);
  	}

  	RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_1_PSK_BH1_XAUTH_SIDE_RESOLVED,"xxxLdLd",psk_rep,vpn,ikesa,"EAP_ROLE",vpn->eap.role,"EAP_ROLE",psk_rep->eap_role);
  }


	err = _rhp_ikev1_new_pkt_aggressive_r_2(vpn,ikesa,rlm,(rhp_ipcmsg*)psk_rep,tx_ikemesg);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_PSK_SKEYID_REP_HANDLER_ALLOC_IKEMSG_ERR_2,"xxxxxuE",rx_ikemesg,psk_rep,vpn,ikesa,rlm,rlm->id,err);
    goto error;
  }

  tx_ikemesg->v1_set_retrans_resp = 1;
  tx_ikemesg->v1_dont_enc = 1;

	rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_AGG_2ND_SENT_R);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_1_PSK_BH1_RTRN,"xxxxxx",vpn,ikesa,rlm,psk_rep,rx_ikemesg,tx_ikemesg);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_1_PSK_BH1_ERR,"xxxxxx",vpn,ikesa,rlm,psk_rep,rx_ikemesg,tx_ikemesg,err);
	return err;
}

static int _rhp_ikev1_rx_aggressive_i_2(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_proto_ike* ikeh;
  rhp_ike_sa_init_srch_plds_ctx s_pld_ctx;
  rhp_ikev1_auth_srch_plds_ctx* s_pld_auth_ctx = NULL;
  int auth_method = 0;
  unsigned long lifetime = 0;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_I_2,"xxxx",rx_ikemesg,tx_ikemesg,vpn,ikesa);

  ikeh = rx_ikemesg->rx_pkt->app.ikeh;

  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


	ikesa->timers->quit_lifetime_timer(vpn,ikesa);

  {
		ikesa->timers->quit_retransmit_timer(vpn,ikesa);

		if( ikesa->req_retx_ikemesg ){

			ikesa->set_retrans_request(ikesa,NULL);

			rhp_ikev2_unhold_mesg(ikesa->req_retx_ikemesg);
			ikesa->req_retx_ikemesg = NULL;
		}
  }


  memset(&s_pld_ctx,0,sizeof(rhp_ike_sa_init_srch_plds_ctx));

  s_pld_auth_ctx = rhp_ikev1_auth_alloc_srch_ctx();
  if( s_pld_auth_ctx == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;

  s_pld_auth_ctx->vpn_ref = rhp_vpn_hold_ref(vpn);
  s_pld_auth_ctx->ikesa = ikesa;


  {
  	rhp_vpn_realm* rlm = vpn->rlm;

  	if( rlm == NULL ){
  		RHP_TRC(0,RHPTRCID_RX_IKEV1_AGGRESSIVE_REP_NO_REALM,"xE",rx_ikemesg,err);
    	goto error;
  	}

  	RHP_LOCK(&(rlm->lock));
  	{

  		if( !_rhp_atomic_read(&(rlm->is_active)) ){
  			err = -EINVAL;
    		RHP_TRC(0,RHPTRCID_RX_IKEV1_AGGRESSIVE_REP_REALM_NOT_ACTIVE,"xxE",rlm,rx_ikemesg,err);
  	  	RHP_UNLOCK(&(rlm->lock));
      	goto error;
  		}

  		auth_method = rlm->my_auth.my_auth_method;
  		lifetime = rlm->ikesa.lifetime_hard;
  	}
  	RHP_UNLOCK(&(rlm->lock));
  }


  {
  	s_pld_ctx.dup_flag = 0;
    s_pld_ctx.resolved_prop.v1.auth_method = auth_method;
    s_pld_ctx.resolved_prop.v1.life_time = lifetime;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_SA),
  			rhp_ikev1_srch_sa_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_I_2_ENUM_SA_PLD_ERR,"xxxd",rx_ikemesg,vpn,ikesa,err);
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_I_2_PARSE_SA_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  					rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_NONCE),
  					rhp_ikev1_srch_nonce_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_I_2_ENUM_NIR_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_I_2_PARSE_NONCE_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  					rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_KE),
  					rhp_ikev1_srch_ke_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_I_2_ENUM_KE_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_I_2_PARSE_KE_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
  }


  if( auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){

  	s_pld_ctx.dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  					rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_CR),
  					rhp_ikev1_srch_cert_req_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
      RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_I_2_ENUM_CERET_REQ_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_I_2_PARSE_CERT_REQ_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }

    {
    	s_pld_auth_ctx->dup_flag = 0;

    	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
    					rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_SIG),
    					rhp_ikev1_auth_srch_sign_cb,s_pld_auth_ctx);

      if( err && err != RHP_STATUS_ENUM_OK ){
        RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_I_2_ENUM_HASH_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
      	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_I_2_RSASIG_PARSE_HASH_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
        err = RHP_STATUS_INVALID_MSG;
        goto error;
      }
    }

    {
    	s_pld_auth_ctx->dup_flag = 0;

    	err = rx_ikemesg->search_payloads(rx_ikemesg,1,
      				rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_CERT),
      				rhp_ikev1_auth_srch_cert_cb,s_pld_auth_ctx);

    	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
    		RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_I_2_ENUM_CERT_ERR,"xxxE",rx_ikemesg,vpn,ikesa,err);
    		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_I_2_RSASIG_PARSE_CERT_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
        err = RHP_STATUS_INVALID_MSG;
    		goto error;
    	}
    }

  }else if( auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ){

  	s_pld_auth_ctx->dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  					rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_HASH),
  					rhp_ikev1_auth_srch_hash_cb,s_pld_auth_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_I_2_PSK_ENUM_HASH_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_I_2_PARSE_HASH_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }

  }else{

  	RHP_BUG("%d",auth_method);
  	err = -EINVAL;
  	goto error;
  }


  {
  	s_pld_auth_ctx->dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  					rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_ID),
  					rhp_ikev1_auth_srch_id_cb,s_pld_auth_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_I_2_ENUM_ID_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_I_2_PARSE_ID_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
      err = 0; // This may be a delayed retransmitted response. Just ignored.
      rx_ikemesg->v1_ignored = 1;
      goto error;
    }

    if( vpn->peer_id.type != RHP_PROTO_IKE_ID_ANY ){

			if( rhp_ikev2_id_cmp_by_value(&(vpn->peer_id),
						s_pld_auth_ctx->peer_id_type,s_pld_auth_ctx->peer_id_len,s_pld_auth_ctx->peer_id) ){
				err = RHP_STATUS_INVALID_MSG;
				RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_I_2_ENUM_ID_PLD_ERR_INVALILD_RESP_ID_1,"xxxd",rx_ikemesg,vpn,ikesa,err);
				RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_I_2_ID_PAYLOAD_INVALID_PEER_ID,"KVPE",rx_ikemesg,vpn,ikesa,err);
				goto error;
			}

    }else{

    	// (e.g.) DMVPN: Spoke-to-Spoke tunnel

    	err = rhp_ikev2_id_setup(s_pld_auth_ctx->peer_id_type,s_pld_auth_ctx->peer_id,
    			s_pld_auth_ctx->peer_id_len,&(vpn->peer_id));
    	if( err ){
				RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_I_2_ENUM_ID_PLD_ERR_INVALILD_RESP_ID_2,"xxxd",rx_ikemesg,vpn,ikesa,err);
				RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_I_2_ID_PAYLOAD_INVALID_PEER_ID,"KVPE",rx_ikemesg,vpn,ikesa,err);
    		goto error;
    	}
    }
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  			rhp_ikev2_mesg_search_cond_my_verndor_id,NULL,
  			rhp_ikev2_ike_sa_init_srch_my_vid_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
  		RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_I_2_ENUM_MY_VENDOR_ID_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_I_2_PARSE_V_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
    	goto error;
  	}
  }


  memcpy(&(ikesa->prop.v1),&(s_pld_ctx.resolved_prop.v1),sizeof(rhp_res_ikev1_sa_proposal));

  ikesa->set_resp_spi(ikesa,ikeh->resp_spi);

  vpn->peer_is_rockhopper = s_pld_ctx.peer_is_rockhopper;
  vpn->peer_rockhopper_ver = s_pld_ctx.peer_rockhopper_ver;
  ikesa->peer_is_rockhopper = s_pld_ctx.peer_is_rockhopper;
  ikesa->peer_rockhopper_ver = s_pld_ctx.peer_rockhopper_ver;


  {
  	rhp_ip_addr my_addr;

  	memset(&my_addr,0,sizeof(rhp_ip_addr));
  	my_addr.addr_family = vpn->local.if_info.addr_family;
  	memcpy(my_addr.addr.raw,vpn->local.if_info.addr.raw,16);

  	rhp_vpn_ikesa_v1_spi_put(&my_addr,&(vpn->peer_addr),
  		RHP_IKE_INITIATOR,ikesa->init_spi,ikesa->resp_spi);
  }


  {
  	int prf_alg, encr_alg;

    err = ikesa->dh->set_peer_pub_key(ikesa->dh,s_pld_ctx.peer_dh_pub_key,s_pld_ctx.peer_dh_pub_key_len);
    if( err ){
    	RHP_BUG("%d",err);
    	goto error;
    }

    err = ikesa->nonce_r->set_nonce(ikesa->nonce_r,s_pld_ctx.nonce,s_pld_ctx.nonce_len);
    if( err ){
    	RHP_BUG("%d",err);
    	goto error;
    }

    prf_alg = rhp_ikev1_p1_prf_alg(ikesa->prop.v1.hash_alg);
    if( prf_alg < 0 ){
    	err = -EINVAL;
    	goto error;
    }

    encr_alg = rhp_ikev1_p1_encr_alg(ikesa->prop.v1.enc_alg);
    if( encr_alg < 0 ){
    	err = -EINVAL;
    	goto error;
    }


    ikesa->prf = rhp_crypto_prf_alloc(prf_alg);
    if( ikesa->prf == NULL ){
      RHP_BUG("");
      goto error;
    }

    ikesa->encr = rhp_crypto_encr_alloc(encr_alg,ikesa->prop.v1.key_bits_len);
    if( ikesa->encr == NULL ){
      RHP_BUG("");
      goto error;
    }
  }


  if( auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){

		err = ikesa->dh->compute_key(ikesa->dh);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		err = rhp_ikev1_gen_rsasig_skeyid(vpn,ikesa,
						&(ikesa->keys.v1.skeyid),&(ikesa->keys.v1.skeyid_len));
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}


	  err = rhp_ikev1_ipc_rsasig_create_verify_and_sign_req(vpn,ikesa,s_pld_auth_ctx,
	  				rx_ikemesg,tx_ikemesg);
	  if( err ){
	  	goto error;
	  }


		if( s_pld_auth_ctx->peer_cert_der ){
			vpn->rx_peer_cert = s_pld_auth_ctx->peer_cert_der;
			vpn->rx_peer_cert_len = s_pld_auth_ctx->peer_cert_der_len;
			s_pld_auth_ctx->peer_cert_der = NULL;
			s_pld_auth_ctx->peer_cert_der_len = 0;
	  }

		if( s_pld_auth_ctx->untrust_ca_cert_ders ){
			vpn->rx_untrust_ca_certs = s_pld_auth_ctx->untrust_ca_cert_ders;
			vpn->rx_untrust_ca_certs_len = s_pld_auth_ctx->untrust_ca_cert_ders_len;
			vpn->rx_untrust_ca_certs_num = s_pld_auth_ctx->untrust_ca_cert_ders_num;
			s_pld_auth_ctx->untrust_ca_cert_ders = NULL;
			s_pld_auth_ctx->untrust_ca_cert_ders_len = 0;
			s_pld_auth_ctx->untrust_ca_cert_ders_num = 0;
	  }


  }else if( auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ){

  	{
			ikesa->v1.rx_psk_hash = (u8*)_rhp_malloc(s_pld_auth_ctx->hash_len);
			if( ikesa->v1.rx_psk_hash == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			memcpy(ikesa->v1.rx_psk_hash,s_pld_auth_ctx->hash,s_pld_auth_ctx->hash_len);
			ikesa->v1.rx_psk_hash_len = s_pld_auth_ctx->hash_len;
  	}

    err = rhp_ikev1_ipc_psk_create_auth_req(vpn,ikesa,rx_ikemesg,tx_ikemesg,
    				0,0,NULL,RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE);
    if( err ){
    	goto error;
    }

  }else{
  	RHP_BUG("%d",auth_method);
  	err = -EINVAL;
  	goto error;
  }


  rhp_ikev1_auth_free_srch_ctx(s_pld_auth_ctx);

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_I_2_OK,"KVP",rx_ikemesg,vpn,ikesa);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_I_2_RTRN,"xxx",rx_ikemesg,vpn,ikesa);

  return RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_I_2_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
  if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
  }
  if( s_pld_auth_ctx ){
  	rhp_ikev1_auth_free_srch_ctx(s_pld_auth_ctx);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_I_2_ERR,"xxx",rx_ikemesg,vpn,ikesa);
  return err;
}

static int _rhp_ikev1_rx_aggressive_i_2_psk_bh(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_vpn_realm* rlm,rhp_ipcmsg_ikev1_psk_skeyid_rep* psk_rep,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
	int hash_octets_len = 0;
	u8 *hash_octets = NULL;
	int is_rekeyed = (ikesa->v1.tx_initial_contact ? 0 : 1);
	u8* skeyid = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_I_2_PSK_BH,"xxxxxxd",vpn,ikesa,rlm,psk_rep,rx_ikemesg,tx_ikemesg,ikesa->v1.tx_initial_contact);

	{
  	int peer_id_bin_len;
  	u8* peer_id_bin;
  	rhp_ikev2_payload* peer_id_payload = rx_ikemesg->get_payload(rx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_ID);

  	if( peer_id_payload == NULL ){
  		RHP_BUG("");
  		err = -EINVAL;
  		goto error;
  	}

  	peer_id_bin_len
  		= ntohs(peer_id_payload->payloadh->len) - sizeof(rhp_proto_ike_payload);
  	peer_id_bin = (u8*)(peer_id_payload->payloadh + 1);

  	skeyid = (u8*)(psk_rep + 1);


		err = rhp_ikev1_p1_gen_hash_ir(RHP_IKE_RESPONDER,ikesa,
						peer_id_bin_len,peer_id_bin,
						0,0,NULL,
						psk_rep->skeyid_len,skeyid,
						&hash_octets,&hash_octets_len);

		if( err ){
			goto error;
		}

		if( ikesa->v1.rx_psk_hash_len != hash_octets_len ||
				memcmp(ikesa->v1.rx_psk_hash,hash_octets,hash_octets_len) ){

			err = RHP_STATUS_IKEV1_MAIN_INVALID_HASH_PLD;

			RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_I_2_PSK_INVALID_HASH_PLD_ERR,"xxpp",rx_ikemesg,ikesa,ikesa->v1.rx_psk_hash_len,ikesa->v1.rx_psk_hash,hash_octets_len,hash_octets);
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_I_2_PSK_INVALID_HASH_PAYLOAD_VALUE,"KVPE",rx_ikemesg,vpn,ikesa,err);

			goto error;
		}
	}

  {
		err = ikesa->dh->compute_key(ikesa->dh);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		err = ikesa->generate_keys_v1(ikesa,psk_rep->skeyid_len,skeyid);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		err = ikesa->encr->set_enc_key(ikesa->encr,ikesa->keys.v1.sk_e,ikesa->keys.v1.sk_e_len);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		err = ikesa->encr->set_dec_key(ikesa->encr,ikesa->keys.v1.sk_e,ikesa->keys.v1.sk_e_len);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
  }

	vpn->eap.role = RHP_EAP_DISABLED;


	err = _rhp_ikev1_new_pkt_aggressive_i_3_psk(vpn,ikesa,rlm,psk_rep,tx_ikemesg);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_PSK_SKEYID_REP_HANDLER_INIT_ALLOC_IKEMSG_ERR,"xxxxuE",psk_rep,vpn,ikesa,rlm,rlm->id,err);
    goto error;
  }


  err = rhp_ikev1_rx_i_comp(vpn,ikesa,rlm,rx_ikemesg,tx_ikemesg,is_rekeyed);
  if( err ){
    goto error;
  }


  _rhp_free(hash_octets);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_I_2_PSK_BH_RTRN,"xxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg);
  return 0;

error:
	if( hash_octets ){
		_rhp_free(hash_octets);
	}
  RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_I_2_PSK_BH_ERR,"xxxxE",vpn,ikesa,rx_ikemesg,tx_ikemesg,err);
	return err;
}

static int _rhp_ikev1_rx_aggressive_r_3_psk(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_ikev1_auth_srch_plds_ctx* s_pld_ctx = NULL;
  int is_rekeyed = 0;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_3_PSK,"xxxxd",rx_ikemesg,tx_ikemesg,vpn,ikesa,rx_ikemesg->decrypted);

  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  if( !rx_ikemesg->decrypted ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_3_PSK_RX_MESG_NOT_DECRYPTED,"xxxx",rx_ikemesg,tx_ikemesg,vpn,ikesa);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


	ikesa->timers->quit_lifetime_timer(vpn,ikesa);


	s_pld_ctx = rhp_ikev1_auth_alloc_srch_ctx();
	if( s_pld_ctx == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

  s_pld_ctx->vpn_ref = rhp_vpn_hold_ref(vpn);
  s_pld_ctx->ikesa = ikesa;


  {
  	s_pld_ctx->dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  					rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_HASH),
  					rhp_ikev1_auth_srch_hash_cb,s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_3_PSK_ENUM_HASH_PLD_ERR,"xxxd",rx_ikemesg,vpn,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_3_PSK_PARSE_HASH_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
  }


  {
  	u16 mesg_ids[2] = {	RHP_PROTO_IKEV1_N_ST_INITIAL_CONTACT,
  											RHP_PROTO_IKE_NOTIFY_RESERVED};

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
			  			rhp_ikev2_mesg_srch_cond_n_mesg_ids,mesg_ids,
			  			rhp_ikev1_auth_srch_n_cb,s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
      RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_3_PSK_ENUM_N_PLDS_ERR,"xxxd",rx_ikemesg,vpn,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_3_PSK_PARSE_N_PAYLOADS_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }

    err = 0;
  }

  {
  	int hash_octets_len = 0, peer_id_bin_len;
  	u8 *hash_octets = NULL, *peer_id_bin;
  	rhp_ikev2_payload* peer_id_payload = rx_ikemesg->get_payload(rx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_ID);

  	if( peer_id_payload == NULL ){
  		RHP_BUG("");
  		err = -EINVAL;
  		goto error;
  	}

  	peer_id_bin_len
  		= ntohs(peer_id_payload->payloadh->len) - sizeof(rhp_proto_ike_payload);
  	peer_id_bin = (u8*)(peer_id_payload->payloadh + 1);


  	err = rhp_ikev1_p1_gen_hash_ir(RHP_IKE_INITIATOR,ikesa,
  					peer_id_bin_len,peer_id_bin,
  					0,0,NULL,
						ikesa->keys.v1.skeyid_len,ikesa->keys.v1.skeyid,
						&hash_octets,&hash_octets_len);

  	if( err ){
  		goto error;
  	}

  	if( s_pld_ctx->hash_len != hash_octets_len ||
  			memcmp(s_pld_ctx->hash,hash_octets,hash_octets_len) ){

  		err = RHP_STATUS_IKEV1_MAIN_INVALID_HASH_PLD;

  		RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_3_PSK_INVALID_HASH_PLD_ERR,"xxxpp",rx_ikemesg,vpn,ikesa,s_pld_ctx->hash_len,s_pld_ctx->hash,hash_octets_len,hash_octets);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_3_PSK_INVALID_HASH_PAYLOAD_VALUE,"KVPE",rx_ikemesg,vpn,ikesa,err);

  		_rhp_free(hash_octets);

    	goto error;
  	}

		_rhp_free(hash_octets);
  }


  if( vpn->eap.role == RHP_EAP_DISABLED ){

		err = rhp_ikev1_r_clear_old_vpn(vpn,&ikesa,
						s_pld_ctx->rx_initial_contact,&is_rekeyed);
		if( err ){
			goto error;
		}
  }


  {
  	rhp_vpn_realm* rlm = rhp_realm_get(vpn->vpn_realm_id);
	  if( rlm == NULL ){
			err = -EINVAL;
	    RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_3_PSK_NO_REALM,"xxx",rx_ikemesg,vpn,ikesa);
	    goto error;
	  }

		RHP_LOCK(&(rlm->lock));

		if( !_rhp_atomic_read(&(rlm->is_active)) ){
	    RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_3_PSK_REALM_NOT_ACTIVE,"xxxx",rx_ikemesg,vpn,ikesa,rlm);
			err = -EINVAL;
			RHP_UNLOCK(&(rlm->lock));
		  rhp_realm_unhold(rlm);
			goto error;
		}

		err = rhp_ikev2_ike_auth_setup_larval_vpn(vpn,rlm,ikesa);
		if( err ){
			RHP_UNLOCK(&(rlm->lock));
		  rhp_realm_unhold(rlm);
			goto error;
		}


	  if( vpn->eap.role == RHP_EAP_DISABLED || is_rekeyed ){

			//
			// [CAUTION] err is this func's return value. (*1)
			//
			err = rhp_ikev1_rx_r_comp(vpn,ikesa,rlm,rx_ikemesg,is_rekeyed);
			if( err && err != RHP_STATUS_IKEV2_MESG_HANDLER_END ){
				RHP_UNLOCK(&(rlm->lock));
				rhp_realm_unhold(rlm);
				goto error;
			}

	  }else if( vpn->eap.role == RHP_EAP_AUTHENTICATOR ){

	  	err = rhp_ikev1_rx_r_comp_xauth(vpn,ikesa,rlm,rx_ikemesg);
			if( err ){
				RHP_UNLOCK(&(rlm->lock));
				rhp_realm_unhold(rlm);
				goto error;
			}

			err = rhp_ikev1_xauth_r_invoke_task(vpn,ikesa,rx_ikemesg);
			if( err ){
				RHP_UNLOCK(&(rlm->lock));
				rhp_realm_unhold(rlm);
				goto error;
			}

			err = RHP_STATUS_IKEV2_MESG_HANDLER_END; // (*1)

	  }else{

	  	RHP_BUG("%d,%d",vpn->eap.role,is_rekeyed);
	  }

		RHP_UNLOCK(&(rlm->lock));
	  rhp_realm_unhold(rlm);
  }

  rhp_ikev1_auth_free_srch_ctx(s_pld_ctx);

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_3_PSK_OK,"KVP",rx_ikemesg,vpn,ikesa);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_3_PSK_RTRN,"xxxE",rx_ikemesg,vpn,ikesa,err);
  return err; // (*1)

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_3_PSK_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
  if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
  }

  if( s_pld_ctx ){
  	rhp_ikev1_auth_free_srch_ctx(s_pld_ctx);
  }
  RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_3_PSK_ERR,"xxx#",rx_ikemesg,vpn,ikesa,err);
  return err;
}

static int _rhp_ikev1_rx_aggressive_r_3_rsasig(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_ikev1_auth_srch_plds_ctx* s_pld_ctx = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_3_RSASIG,"xxxxd",rx_ikemesg,tx_ikemesg,vpn,ikesa,rx_ikemesg->decrypted);

  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  if( !rx_ikemesg->decrypted ){
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


	ikesa->timers->quit_lifetime_timer(vpn,ikesa);


	s_pld_ctx = rhp_ikev1_auth_alloc_srch_ctx(s_pld_ctx);
	if( s_pld_ctx == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

  s_pld_ctx->vpn_ref = rhp_vpn_hold_ref(vpn);
  s_pld_ctx->ikesa = ikesa;


  {
  	s_pld_ctx->dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  					rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_SIG),
  					rhp_ikev1_auth_srch_sign_cb,s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_3_RSASIG_ENUM_HASH_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_3_RSASIG_PARSE_HASH_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
  }


  {
  	s_pld_ctx->dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,1,
    				rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_CERT),
    				rhp_ikev1_auth_srch_cert_cb,s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
  		RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_3_RSASIG_ENUM_CERT_ERR,"xxxE",rx_ikemesg,vpn,ikesa,err);
  		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_3_RSASIG_PARSE_CERT_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
  		goto error;
  	}
  }


  {
  	u16 mesg_ids[2] = {	RHP_PROTO_IKEV1_N_ST_INITIAL_CONTACT,
  											RHP_PROTO_IKE_NOTIFY_RESERVED};

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
			  			rhp_ikev2_mesg_srch_cond_n_mesg_ids,mesg_ids,
			  			rhp_ikev1_auth_srch_n_cb,s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
      RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_3_ENUM_N_PLDS_ERR,"xxd",rx_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_3_RSASIG_PARSE_N_PAYLOADS_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }

    err = 0;
  }

  ikesa->v1.rx_initial_contact = s_pld_ctx->rx_initial_contact;



  err = rhp_ikev1_ipc_rsasig_create_verify_req(vpn,ikesa,s_pld_ctx,
  				rx_ikemesg,tx_ikemesg);
  if( err ){
  	goto error;
  }

  if( s_pld_ctx->peer_cert_der ){
		vpn->rx_peer_cert = s_pld_ctx->peer_cert_der;
		vpn->rx_peer_cert_len = s_pld_ctx->peer_cert_der_len;
		s_pld_ctx->peer_cert_der = NULL;
		s_pld_ctx->peer_cert_der_len = 0;
  }

	if( s_pld_ctx->untrust_ca_cert_ders ){
		vpn->rx_untrust_ca_certs = s_pld_ctx->untrust_ca_cert_ders;
		vpn->rx_untrust_ca_certs_len = s_pld_ctx->untrust_ca_cert_ders_len;
		vpn->rx_untrust_ca_certs_num = s_pld_ctx->untrust_ca_cert_ders_num;
		s_pld_ctx->untrust_ca_cert_ders = NULL;
		s_pld_ctx->untrust_ca_cert_ders_len = 0;
		s_pld_ctx->untrust_ca_cert_ders_num = 0;
  }

	rhp_ikev1_auth_free_srch_ctx(s_pld_ctx);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_3_RSASIG_RTRN,"xxxE",rx_ikemesg,vpn,ikesa,err);

  return RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_3_RSASIG_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);

	if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
  }

  if( s_pld_ctx ){
  	rhp_ikev1_auth_free_srch_ctx(s_pld_ctx);
  }
  RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_R_3_RSASIG_ERR,"xxx",rx_ikemesg,vpn,ikesa);
  return err;
}


int rhp_ikev1_rx_aggressive_no_vpn(rhp_ikev2_mesg* rx_ikemesg,
		rhp_ikev2_mesg* tx_ikemesg,rhp_vpn** vpn_i,int* my_ikesa_side_i,u8* my_ikesa_spi_i)
{
	int err = -EINVAL;
	u8 exchange_type = rx_ikemesg->get_exchange_type(rx_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_NO_VPN,"xxLb",rx_ikemesg,tx_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

	if( exchange_type != RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_NO_VPN_NOT_AGGRESSIVE_EXCHG,"xLb",rx_ikemesg,"PROTO_IKE_EXCHG",exchange_type);
		return 0;
	}

	if( *vpn_i || *my_ikesa_side_i != -1 ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

	err = _rhp_ikev1_rx_aggressive_r_1(rx_ikemesg,tx_ikemesg,vpn_i,my_ikesa_side_i,my_ikesa_spi_i);

error:
	if( !err ){
		RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_NO_VPN_RTRN,"xxxLdG",rx_ikemesg,tx_ikemesg,*vpn_i,"IKE_SIDE",*my_ikesa_side_i,my_ikesa_spi_i);
	}else{
		RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_NO_VPN_ERR,"xxE",rx_ikemesg,tx_ikemesg,err);
	}
  return err;
}

int rhp_ikev1_rx_aggressive(rhp_ikev2_mesg* rx_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_ikemesg->get_exchange_type(rx_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE,"xxLdGxLb",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

	if( exchange_type != RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_NOT_AGGRESSIVE_EXCHG,"xxLb",rx_ikemesg,vpn,"PROTO_IKE_EXCHG",exchange_type);
		return 0;
	}


	if( my_ikesa_spi == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

	ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
	if( ikesa == NULL ){
		err = -ENOENT;
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_NO_IKESA,"xxLdG",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
		goto error;
	}

  if( ikesa->state == RHP_IKESA_STAT_V1_AGG_1ST_SENT_I ){

  	err = _rhp_ikev1_rx_aggressive_i_2(vpn,ikesa,rx_ikemesg,tx_ikemesg);

  }else if( ikesa->state == RHP_IKESA_STAT_V1_AGG_2ND_SENT_R ){

  	if( ikesa->prop.v1.xauth_method == RHP_PROTO_IKE_AUTHMETHOD_HYBRID_INIT_RSASIG ){
  		err = -EINVAL;
  		RHP_BUG("");
			goto error;
  	}

  	if( ikesa->prop.v1.auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){

  		err = _rhp_ikev1_rx_aggressive_r_3_rsasig(vpn,ikesa,rx_ikemesg,tx_ikemesg);

  	}else if( ikesa->prop.v1.auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ){

  		err = _rhp_ikev1_rx_aggressive_r_3_psk(vpn,ikesa,rx_ikemesg,tx_ikemesg);
  	}

  }else{
  	RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_BAD_STATE,"xxxLd",rx_ikemesg,vpn,tx_ikemesg,"IKESA_STAT",ikesa->state);
  	err = -EINVAL;
  	goto error;
  }

error:
	RHP_TRC(0,RHPTRCID_IKEV1_RX_AGGRESSIVE_RTRN,"xxxE",rx_ikemesg,vpn,tx_ikemesg,err);
  return err;
}


void rhp_ikev1_aggressive_ipc_rslv_auth_rep_handler(rhp_ipcmsg** ipcmsg_c)
{
  int err = -EINVAL;
  rhp_ipcmsg* ipcmsg = *ipcmsg_c;
  rhp_ipcmsg_ikev1_rslv_auth_rep* rslv_auth_rep;
  rhp_ikev1_agg_ctx* agg_ctx = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSLV_AUTH_REP_HANDLER,"x",ipcmsg);

  if( ipcmsg->len < sizeof(rhp_ipcmsg_ikev1_rslv_auth_rep) ){
    RHP_BUG("%d < %d",ipcmsg->len,sizeof(rhp_ipcmsg_ikev1_rslv_auth_rep));
    goto error;
  }

  rslv_auth_rep = (rhp_ipcmsg_ikev1_rslv_auth_rep*)ipcmsg;


  agg_ctx = _rhp_ikev1_agg_ctx_get(rslv_auth_rep->side,rslv_auth_rep->spi);
  if( agg_ctx == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSLV_AUTH_REP_HANDLER_NO_AGG_CTX,"xLdG",ipcmsg,"IKE_SIDE",rslv_auth_rep->side,rslv_auth_rep->spi);
  	goto error;
  }

  if( agg_ctx->rx_ikemesg == NULL || agg_ctx->tx_ikemesg == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  if( rslv_auth_rep->txn_id != agg_ctx->txn_id ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSLV_AUTH_REP_HANDLER_REALM_BAD_ID,"xxqq",ipcmsg,agg_ctx,rslv_auth_rep->txn_id,agg_ctx->txn_id);
    goto error;
  }

  if( rslv_auth_rep->result == 0 ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSLV_AUTH_REP_HANDLER_RESULT_ERR,"xx",ipcmsg,agg_ctx);
    goto error;
  }


	err = rhp_ikesa_init_i_get(agg_ctx->rx_ikemesg->rx_pkt,NULL);
	if( err != -ENOENT ){ // err == 0 or other error
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSLV_AUTH_REP_HANDLER_IPC_REP_DUP_ERR,"xxxxE",ipcmsg,agg_ctx,agg_ctx->rx_ikemesg,agg_ctx->rx_ikemesg->rx_pkt,err);
    goto error;
	}


  err = _rhp_ikev1_rx_aggressive_r_1_bh0(agg_ctx,rslv_auth_rep->my_realm_id);
  if( err ){
  	goto error;
  }


	RHP_LOG_D(RHP_LOG_SRC_IKEV2,rslv_auth_rep->my_realm_id,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_1_RESOLVE_REALM_OK,"Ku",agg_ctx->rx_ikemesg,rslv_auth_rep->my_realm_id);

  _rhp_ikev1_agg_ctx_free(agg_ctx);

  RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSLV_AUTH_REP_HANDLER_RTRN,"xx",ipcmsg,agg_ctx);
  return;


error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_1_RESOLVE_REALM_ERR,"KE",agg_ctx->rx_ikemesg,err);

  if( agg_ctx ){
    _rhp_ikev1_agg_ctx_free(agg_ctx);
  }

	rhp_ikev2_g_statistics_inc(ikesa_auth_errors);

  RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSLV_AUTH_REP_HANDLER_ERR,"xxE",ipcmsg,agg_ctx,err);
  return;
}

void rhp_ikev1_aggressive_ipc_psk_skeyid_rep_handler(rhp_ipcmsg** ipcmsg_c)
{
  int err = -EINVAL;
  rhp_ipcmsg* ipcmsg = *ipcmsg_c;
  rhp_ipcmsg_ikev1_psk_skeyid_rep* psk_rep;
  rhp_ikesa* ikesa = NULL;
  rhp_vpn_realm* rlm = NULL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_ikev2_mesg* rx_ikemesg = NULL;
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_PSK_SKEYID_REP_HANDLER,"x",ipcmsg);

  if( ipcmsg->len < sizeof(rhp_ipcmsg_ikev1_psk_skeyid_rep) ){
    RHP_BUG("%d < sizeof(rhp_ipcmsg_ikev1_psk_skeyid_rep)(%d)",ipcmsg->len,sizeof(rhp_ipcmsg_ikev1_psk_skeyid_rep));
    goto error;
  }

  psk_rep = (rhp_ipcmsg_ikev1_psk_skeyid_rep*)ipcmsg;

  if( psk_rep->len < sizeof(rhp_ipcmsg_ikev1_psk_skeyid_rep) + psk_rep->skeyid_len ){
    RHP_BUG("%d < sizeof(rhp_ipcmsg_ikev1_psk_skeyid_rep)(%d) + psk_rep->signed_octets_len(%d)",psk_rep->len,sizeof(rhp_ipcmsg_ikev1_psk_skeyid_rep),psk_rep->skeyid_len);
    goto error;
  }

  vpn_ref = rhp_vpn_ikesa_spi_get(psk_rep->side,psk_rep->spi);
  vpn = RHP_VPN_REF(vpn_ref);
  if( vpn == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_PSK_SKEYID_REP_HANDLER_NO_VPN,"xLdG",ipcmsg,"IKE_SIDE",psk_rep->side,psk_rep->spi);
    goto error;
  }

  RHP_LOCK(&(vpn->lock));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_PSK_SKEYID_REP_HANDLER_VPN_NOT_ACTIVE,"xx",ipcmsg,ikesa);
    goto error_l;
  }

  ikesa = vpn->ikesa_get(vpn,psk_rep->side,psk_rep->spi);
  if( ikesa == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_PSK_SKEYID_REP_HANDLER_NO_IKESA,"x",ipcmsg);
    goto error_l;
  }


  tx_ikemesg = ikesa->pend_tx_ikemesg;
 	ikesa->pend_tx_ikemesg = NULL;
  rx_ikemesg = ikesa->pend_rx_ikemesg;
  ikesa->pend_rx_ikemesg = NULL;

  if( tx_ikemesg == NULL || rx_ikemesg == NULL ){
  	RHP_BUG("");
  	goto error_l;
  }

  if( psk_rep->txn_id != ikesa->ipc_txn_id ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_PSK_SKEYID_REP_HANDLER_IKESA_BAD_TXNID,"xxxqq",ipcmsg,vpn,ikesa,psk_rep->txn_id,ikesa->ipc_txn_id);
    goto error_l;
  }

  if( psk_rep->result == 0 ){
  	RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_PSK_SKEYID_REP_HANDLER_RESULT_ERR,"xxx",ipcmsg,vpn,ikesa);
  	goto error_l;
  }



	rlm = rhp_realm_get(psk_rep->my_realm_id);
  if( rlm == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_PSK_SKEYID_REP_HANDLER_NO_REALM,"xx",ipcmsg,ikesa);
    goto error_l;
  }

  RHP_LOCK(&(rlm->lock));

  if( vpn->rlm && rlm != vpn->rlm ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_PSK_SKEYID_REP_HANDLER_INVALID_REALM_ID,"xxuu",ipcmsg,ikesa,psk_rep->my_realm_id,vpn->rlm->id);
    goto error_l2;
  }

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_PSK_SKEYID_REP_HANDLER_REALM_NOT_ACTIVE,"xxxxu",ipcmsg,vpn,ikesa,rlm,rlm->id);
    goto error_l2;
  }


	if( ikesa->side == RHP_IKE_INITIATOR ){

		// Aggressive mode - Rx 2nd message and Tx 3rd message.

		err = _rhp_ikev1_rx_aggressive_i_2_psk_bh(vpn,ikesa,rlm,
						psk_rep,rx_ikemesg,tx_ikemesg);
		if( err ){
			goto error_l2;
		}

	}else{ // RESPONDER

		// Aggressive mode - Rx 1st message and Tx 2nd message.

		err = _rhp_ikev1_rx_aggressive_r_1_psk_bh1(vpn,ikesa,rlm,
						psk_rep,rx_ikemesg,tx_ikemesg);
		if( err ){
			goto error_l2;
		}

		ikesa->busy_flag = 0;
	}

  RHP_UNLOCK(&(rlm->lock));
  rhp_realm_unhold(rlm);
  rlm = NULL;


  rhp_ikev1_call_next_rx_mesg_handlers(rx_ikemesg,vpn,
  		psk_rep->side,psk_rep->spi,tx_ikemesg,RHP_IKEV1_MESG_HANDLER_P1_AGGRESSIVE);


  rhp_ikev2_unhold_mesg(tx_ikemesg);
  rhp_ikev2_unhold_mesg(rx_ikemesg);

  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

  _rhp_free_zero(*ipcmsg_c,(*ipcmsg_c)->len);
  *ipcmsg_c = NULL;

	RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_PSK_SKEYID_REP_HANDLER_RTRN,"xxxx",ipcmsg,vpn,ikesa,rlm);
  return;

error_l2:
	if( rlm ){
		RHP_UNLOCK(&(rlm->lock));
		rhp_realm_unhold(rlm);
	}
error_l:

	if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
	}

	RHP_UNLOCK(&(vpn->lock));

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_SKEYID_ERR,"VE",vpn,err);
  if( vpn ){
    rhp_vpn_unhold(vpn_ref);
  }
  if( tx_ikemesg ){
    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }
  if( rx_ikemesg ){
    rhp_ikev2_unhold_mesg(rx_ikemesg);
  }

  _rhp_free_zero(*ipcmsg_c,(*ipcmsg_c)->len);
  *ipcmsg_c = NULL;

	rhp_ikev2_g_statistics_inc(ikesa_auth_errors);

  RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_PSK_SKEYID_REP_HANDLER_ERR,"xxxxE",ipcmsg,vpn,ikesa,rlm,err);
  return;
}

extern int rhp_ikev1_merge_larval_vpn(rhp_vpn* larval_vpn);

void rhp_ikev1_aggressive_ipc_rsasig_verify_rep_handler(rhp_ipcmsg** ipcmsg_c)
{
  int err = -EINVAL;
  rhp_ipcmsg* ipcmsg = *ipcmsg_c;
  rhp_ipcmsg_ikev1_rsasig_verify_rep* verify_rep;
  rhp_ikesa* ikesa = NULL;
  rhp_vpn_realm* rlm = NULL;
  rhp_ikev2_mesg* rx_ikemesg = NULL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;
  u8* alt_id_p;
  int is_rekeyed = 0;

  RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_VERIFY_REP_HANDLER,"x",ipcmsg);

  if( ipcmsg->len < sizeof(rhp_ipcmsg_ikev1_rsasig_verify_rep) ){
    RHP_BUG("%d < %d",ipcmsg->len,sizeof(rhp_ipcmsg_ikev1_rsasig_verify_rep));
    goto error;
  }

  verify_rep = (rhp_ipcmsg_ikev1_rsasig_verify_rep*)ipcmsg;
  alt_id_p = (u8*)(verify_rep + 1);


  if( verify_rep->len < (sizeof(rhp_ipcmsg_ikev1_rsasig_verify_rep) + verify_rep->alt_peer_id_len) ){
    RHP_BUG("%d < %d(2)",verify_rep->len,(sizeof(rhp_ipcmsg_ikev1_rsasig_verify_rep) + verify_rep->alt_peer_id_len));
    goto error;
  }

  vpn_ref = rhp_vpn_ikesa_spi_get(verify_rep->side,verify_rep->spi);
  vpn = RHP_VPN_REF(vpn_ref);
  if( vpn == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_VERIFY_REP_HANDLER_NO_IKESA,"xLdG",ipcmsg,"IKE_SIDE",verify_rep->side,verify_rep->spi);
  	goto error;
  }


  RHP_LOCK(&(vpn->lock));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
  	RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_VERIFY_REP_HANDLER_IKESA_NOT_ACTIVE,"xx",ipcmsg,vpn);
  	goto error_l_vpn;
  }

  ikesa = vpn->ikesa_get(vpn,verify_rep->side,verify_rep->spi);

  if( ikesa == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_VERIFY_REP_HANDLER_NO_IKESA,"xx",ipcmsg,vpn);
  	goto error_l_vpn;
  }

  rx_ikemesg = ikesa->pend_rx_ikemesg;
  tx_ikemesg = ikesa->pend_tx_ikemesg;
  ikesa->pend_rx_ikemesg = NULL;
  ikesa->pend_tx_ikemesg = NULL;

  if( rx_ikemesg == NULL || tx_ikemesg == NULL ){
  	RHP_BUG("");
  	goto error_l_vpn;
  }

  if( verify_rep->txn_id != ikesa->ipc_txn_id ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_VERIFY_REP_HANDLER_REALM_BAD_ID,"xxxxqq",ipcmsg,vpn,ikesa,rlm,verify_rep->txn_id,ikesa->ipc_txn_id);
    goto error_l_vpn;
  }


  rlm = rhp_realm_get(vpn->vpn_realm_id);
  if( rlm == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_VERIFY_REP_HANDLER_NO_REALM,"xxx",ipcmsg,vpn,ikesa);
    goto error_l_vpn;
  }


  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_VERIFY_REP_HANDLER_REALM_NOT_ACTIVE,"xxxx",ipcmsg,vpn,ikesa,rlm);
    goto error_l_rlm_vpn;
  }

  if( verify_rep->result == 0 ){

    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_VERIFY_REP_HANDLER_RESULT_ERR,"xxxxu",ipcmsg,vpn,ikesa,rlm,rlm->id);

    goto error_l_rlm_vpn;
  }


  if( verify_rep->my_realm_id != rlm->id ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_VERIFY_REP_HANDLER_REALM_BAD_ID_2,"xxxxuu",ipcmsg,vpn,ikesa,rlm,verify_rep->my_realm_id,rlm->id);
    goto error_l_rlm_vpn;
  }

  RHP_UNLOCK(&(rlm->lock));


	if( verify_rep->alt_peer_id_len ){

		if( vpn->peer_id.alt_id ){
			rhp_ikev2_id_clear(vpn->peer_id.alt_id);
			_rhp_free(vpn->peer_id.alt_id);
			vpn->peer_id.alt_id = NULL;
		}

		err = rhp_ikev2_id_alt_setup(verify_rep->alt_peer_id_type,(void*)alt_id_p,
				verify_rep->alt_peer_id_len,&(vpn->peer_id));

		if( err ){
			RHP_BUG("");
	    goto error_l_vpn;
		}
	}

	rhp_ikev2_id_dump("rhp_ikev1_aggressive_ipc_rsasig_verify_rep_handler",&(vpn->peer_id));

  if( vpn->eap.role == RHP_EAP_DISABLED ){

		err = rhp_ikev1_r_clear_old_vpn(vpn,&ikesa,
						ikesa->v1.rx_initial_contact,&is_rekeyed);
		if( err ){
			goto error_l_vpn;
		}
  }


  RHP_LOCK(&(rlm->lock));

	err = rhp_ikev2_ike_auth_setup_larval_vpn(vpn,rlm,ikesa);
	if( err ){
  	goto error_l_rlm_vpn;
	}

  if( vpn->eap.role == RHP_EAP_DISABLED || is_rekeyed ){

		//
		// [CAUTION] err is this func's return value.
		//
		err = rhp_ikev1_rx_r_comp(vpn,ikesa,rlm,rx_ikemesg,is_rekeyed);
		if( err && err != RHP_STATUS_IKEV2_MESG_HANDLER_END ){
			goto error_l_rlm_vpn;
		}

  }else if( vpn->eap.role == RHP_EAP_AUTHENTICATOR ){

  	err = rhp_ikev1_rx_r_comp_xauth(vpn,ikesa,rlm,rx_ikemesg);
		if( err ){
			goto error_l_rlm_vpn;
		}

		err = rhp_ikev1_xauth_r_invoke_task(vpn,ikesa,rx_ikemesg);
		if( err ){
			goto error_l_rlm_vpn;
		}

  }else{

  	RHP_BUG("%d,%d",vpn->eap.role,is_rekeyed);
  }

  RHP_UNLOCK(&(rlm->lock));


	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_3_RSASIG_OK,"KVP",rx_ikemesg,vpn,ikesa);


	rhp_ikev1_call_next_rx_mesg_handlers(rx_ikemesg,vpn,
			verify_rep->side,verify_rep->spi,tx_ikemesg,RHP_IKEV1_MESG_HANDLER_P1_AGGRESSIVE);


  RHP_UNLOCK(&(vpn->lock));


  if( vpn->v1.merge_larval_vpn ){

		rhp_ikev1_merge_larval_vpn(vpn);
	}


  rhp_vpn_unhold(vpn_ref);

  rhp_ikev2_unhold_mesg(rx_ikemesg);
  rhp_ikev2_unhold_mesg(tx_ikemesg);

  rhp_realm_unhold(rlm);

  RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_VERIFY_REP_HANDLER_RTRN,"xxxx",ipcmsg,vpn,ikesa,rlm);
  return;


error_l_rlm_vpn:
  RHP_UNLOCK(&(rlm->lock));
error_l_vpn:
	if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
	}

  RHP_UNLOCK(&(vpn->lock));
error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_RSASIG_VERIFY_ERR,"VE",vpn,err);
	if( vpn ){
    rhp_vpn_unhold(vpn_ref);
  }
	if( rlm ){
		rhp_realm_unhold(rlm);
	}
  if( rx_ikemesg ){
    rhp_ikev2_unhold_mesg(rx_ikemesg);
  }
  if( tx_ikemesg ){
    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }

	rhp_ikev2_g_statistics_inc(ikesa_auth_errors);

  RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_VERIFY_REP_HANDLER_ERR,"xxxxE",ipcmsg,vpn,ikesa,rlm,err);
  return;
}

void rhp_ikev1_aggressive_ipc_rsasig_sign_rep_handler(rhp_ipcmsg** ipcmsg_c)
{
  int err = -EINVAL;
  rhp_ipcmsg* ipcmsg = *ipcmsg_c;
  rhp_ipcmsg_ikev1_rsasig_sign_rep* rsasig_sign_rep;
  rhp_ikesa* ikesa = NULL;
  rhp_vpn_realm* rlm = NULL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_ikev2_mesg* rx_ikemesg = NULL;
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_SIGN_REP_HANDLER,"x",ipcmsg);

  if( ipcmsg->len < sizeof(rhp_ipcmsg_ikev1_rsasig_sign_rep) ){
    RHP_BUG("%d < %d",ipcmsg->len,sizeof(rhp_ipcmsg_ikev1_rsasig_sign_rep));
    goto error;
  }

  rsasig_sign_rep = (rhp_ipcmsg_ikev1_rsasig_sign_rep*)ipcmsg;

  if( rsasig_sign_rep->len < sizeof(rhp_ipcmsg_ikev1_rsasig_sign_rep)
  		+ rsasig_sign_rep->signed_octets_len + rsasig_sign_rep->cert_chain_len ){
    RHP_BUG("%d < %d,%d,%d",rsasig_sign_rep->len,sizeof(rhp_ipcmsg_ikev1_rsasig_sign_rep),rsasig_sign_rep->signed_octets_len,rsasig_sign_rep->cert_chain_len);
    goto error;
  }

  vpn_ref = rhp_vpn_ikesa_spi_get(rsasig_sign_rep->side,rsasig_sign_rep->spi);
  vpn = RHP_VPN_REF(vpn_ref);
  if( vpn == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_SIGN_REP_HANDLER_NO_VPN,"xLdG",ipcmsg,"IKE_SIDE",rsasig_sign_rep->side,rsasig_sign_rep->spi);
    goto error;
  }

  RHP_LOCK(&(vpn->lock));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_SIGN_REP_HANDLER_VPN_NOT_ACTIVE,"xx",ipcmsg,ikesa);
    goto error_l;
  }

  ikesa = vpn->ikesa_get(vpn,rsasig_sign_rep->side,rsasig_sign_rep->spi);
  if( ikesa == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_SIGN_REP_HANDLER_NO_IKESA,"x",ipcmsg);
    goto error_l;
  }


  tx_ikemesg = ikesa->pend_tx_ikemesg;
 	ikesa->pend_tx_ikemesg = NULL;
  rx_ikemesg = ikesa->pend_rx_ikemesg;
  ikesa->pend_rx_ikemesg = NULL;

  if( tx_ikemesg == NULL || rx_ikemesg == NULL ){
  	RHP_BUG("");
  	goto error_l;
  }

  if( rsasig_sign_rep->txn_id != ikesa->ipc_txn_id ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_SIGN_REP_HANDLER_IKESA_BAD_TXNID,"xxxqq",ipcmsg,vpn,ikesa,rsasig_sign_rep->txn_id,ikesa->ipc_txn_id);
    goto error_l;
  }

  if( rsasig_sign_rep->result == 0 ){
  	RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_SIGN_REP_HANDLER_RESULT_ERR,"xxx",ipcmsg,vpn,ikesa);
  	goto error_l;
  }


	rlm = rhp_realm_get(rsasig_sign_rep->my_realm_id);
  if( rlm == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_SIGN_REP_HANDLER_NO_REALM,"xx",ipcmsg,ikesa);
    goto error_l;
  }


  RHP_LOCK(&(rlm->lock));

  if( vpn->rlm && rlm != vpn->rlm ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_SIGN_REP_HANDLER_INVALID_REALM_ID,"xxuu",ipcmsg,ikesa,rsasig_sign_rep->my_realm_id,vpn->rlm->id);
    goto error_l2;
  }

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_SIGN_REP_HANDLER_REALM_NOT_ACTIVE,"xxxxu",ipcmsg,vpn,ikesa,rlm,rlm->id);
    goto error_l2;
  }

  if( rsasig_sign_rep->my_realm_id != rlm->id ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_SIGN_REP_HANDLER_REALM_BAD_ID,"xxxxuu",ipcmsg,vpn,ikesa,rlm,rsasig_sign_rep->my_realm_id,rlm,rlm->id);
    goto error_l2;
  }


  if( vpn->eap.role == RHP_EAP_DISABLED ){

		if( rsasig_sign_rep->eap_role == RHP_EAP_AUTHENTICATOR ){

			if( vpn->origin_side != RHP_IKE_RESPONDER || ikesa->side != RHP_IKE_RESPONDER ){
				RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_SIGN_REP_HANDLER_INVALID_XAUTH_SIDE_1,"xxxLdLd",rsasig_sign_rep,vpn,ikesa,"IKE_SIDE",vpn->origin_side,"IKE_SIDE",ikesa->side);
				goto error_l2;
			}

			vpn->eap.role = RHP_EAP_AUTHENTICATOR;
			vpn->eap.eap_method = vpn->eap.peer_id.method = rsasig_sign_rep->eap_method;

		}else if( rsasig_sign_rep->eap_role == RHP_EAP_SUPPLICANT ){

			if( vpn->origin_side != RHP_IKE_INITIATOR || ikesa->side != RHP_IKE_INITIATOR ){
				RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_SIGN_REP_HANDLER_INVALID_XAUTH_SIDE_2,"xxxLdLd",rsasig_sign_rep,vpn,ikesa,"IKE_SIDE",vpn->origin_side,"IKE_SIDE",ikesa->side);
				goto error_l2;
			}

		}else if( rsasig_sign_rep->eap_role == RHP_EAP_DISABLED ){

			vpn->eap.role = RHP_EAP_DISABLED;

		}else{
			RHP_BUG("%d",rsasig_sign_rep->eap_role);
			goto error_l2;
		}

  }else{

  	if( vpn->eap.role != (int)rsasig_sign_rep->eap_role ){
  		RHP_BUG("%d,%d",rsasig_sign_rep->eap_role,vpn->eap.role);
  	}

  	RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_SIGN_REP_HANDLER_XAUTH_SIDE_RESOLVED,"xxxLdLd",rsasig_sign_rep,vpn,ikesa,"EAP_ROLE",vpn->eap.role,"EAP_ROLE",rsasig_sign_rep->eap_role);
  }


	err = _rhp_ikev1_new_pkt_aggressive_r_2(vpn,ikesa,rlm,(rhp_ipcmsg*)rsasig_sign_rep,tx_ikemesg);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_SIGN_REP_HANDLER_ALLOC_IKEMSG_ERR,"xxxxuE",ipcmsg,vpn,ikesa,rlm,rlm->id,err);
    goto error_l2;
  }

  tx_ikemesg->v1_set_retrans_resp = 1;
  tx_ikemesg->v1_dont_enc = 1;


  RHP_UNLOCK(&(rlm->lock));
  rhp_realm_unhold(rlm);
  rlm = NULL;


  {
		err = ikesa->generate_keys_v1(ikesa,ikesa->keys.v1.skeyid_len,ikesa->keys.v1.skeyid);
		if( err ){
			RHP_BUG("%d",err);
			goto error_l;
		}

		err = ikesa->encr->set_enc_key(ikesa->encr,ikesa->keys.v1.sk_e,ikesa->keys.v1.sk_e_len);
		if( err ){
			RHP_BUG("%d",err);
			goto error_l;
		}

		err = ikesa->encr->set_dec_key(ikesa->encr,ikesa->keys.v1.sk_e,ikesa->keys.v1.sk_e_len);
		if( err ){
			RHP_BUG("%d",err);
			goto error_l;
		}
  }


	rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_AGG_2ND_SENT_R);

  ikesa->busy_flag = 0;


	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_R_2_RSASIG_OK,"KVP",rx_ikemesg,vpn,ikesa);

  rhp_ikev1_call_next_rx_mesg_handlers(rx_ikemesg,vpn,
  		rsasig_sign_rep->side,rsasig_sign_rep->spi,tx_ikemesg,RHP_IKEV1_MESG_HANDLER_P1_AGGRESSIVE);

  rhp_ikev2_unhold_mesg(tx_ikemesg);
  rhp_ikev2_unhold_mesg(rx_ikemesg);

  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

  _rhp_free_zero(*ipcmsg_c,(*ipcmsg_c)->len);
  *ipcmsg_c = NULL;

	RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_SIGN_REP_HANDLER_RTRN,"xxxx",ipcmsg,vpn,ikesa,rlm);
  return;

error_l2:
	if( rlm ){
		RHP_UNLOCK(&(rlm->lock));
		rhp_realm_unhold(rlm);
	}
error_l:

	if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
	}

	RHP_UNLOCK(&(vpn->lock));

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_RSASIG_SIGN_ERR,"VE",vpn,err);
  if( vpn ){
    rhp_vpn_unhold(vpn_ref);
  }
  if( tx_ikemesg ){
    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }
  if( rx_ikemesg ){
    rhp_ikev2_unhold_mesg(rx_ikemesg);
  }

  _rhp_free_zero(*ipcmsg_c,(*ipcmsg_c)->len);
  *ipcmsg_c = NULL;

	rhp_ikev2_g_statistics_inc(ikesa_auth_errors);

  RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_SIGN_REP_HANDLER_ERR,"xxxxE",ipcmsg,vpn,ikesa,rlm,err);
  return;
}

void rhp_ikev1_aggressive_ipc_rsasig_verify_and_sign_rep_handler(rhp_ipcmsg** ipcmsg_c)
{
  int err = -EINVAL;
  rhp_ipcmsg* ipcmsg = *ipcmsg_c;
  rhp_ipcmsg_verify_and_sign_rep* verify_sign_rep;
  rhp_ipcmsg_ikev1_rsasig_verify_rep* in_verify_rep = NULL;
  rhp_ipcmsg_ikev1_rsasig_sign_rep* in_sign_rep = NULL;
  rhp_ikesa* ikesa = NULL;
  rhp_vpn_realm* rlm = NULL;
  rhp_ikev2_mesg* rx_ikemesg = NULL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;
  u8* alt_id_p;
	int is_rekeyed = 0;


  RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER,"x",ipcmsg);

  if( ipcmsg->len < sizeof(rhp_ipcmsg_verify_and_sign_rep) + sizeof(rhp_ipcmsg_ikev1_rsasig_verify_rep) ){
    RHP_BUG("%d < %d, %d",ipcmsg->len,sizeof(rhp_ipcmsg_verify_and_sign_rep),sizeof(rhp_ipcmsg_ikev1_rsasig_verify_rep));
    goto error;
  }

  verify_sign_rep = (rhp_ipcmsg_verify_and_sign_rep*)ipcmsg;

  in_verify_rep = (rhp_ipcmsg_ikev1_rsasig_verify_rep*)(verify_sign_rep + 1);
  alt_id_p = (u8*)(in_verify_rep + 1);

  if( in_verify_rep->len < sizeof(rhp_ipcmsg_ikev1_rsasig_verify_rep) ){
    RHP_BUG("%d < %d",in_verify_rep->len,sizeof(rhp_ipcmsg_ikev1_rsasig_verify_rep));
    goto error;
  }

  if( in_verify_rep->len < (sizeof(rhp_ipcmsg_ikev1_rsasig_verify_rep) + in_verify_rep->alt_peer_id_len) ){
    RHP_BUG("%d < %d, %d(2)",in_verify_rep->len,sizeof(rhp_ipcmsg_ikev1_rsasig_verify_rep),in_verify_rep->alt_peer_id_len);
    goto error;
  }

  if( in_verify_rep->result ){

    if( ipcmsg->len < sizeof(rhp_ipcmsg_verify_and_sign_rep) + in_verify_rep->len + sizeof(rhp_ipcmsg_ikev1_rsasig_sign_rep) ){
      RHP_BUG("%d < %d, %d, %d %d",ipcmsg->len,sizeof(rhp_ipcmsg_verify_and_sign_rep),in_verify_rep->len,sizeof(rhp_ipcmsg_ikev1_rsasig_sign_rep));
      goto error;
    }

    in_sign_rep = (rhp_ipcmsg_ikev1_rsasig_sign_rep*)(((u8*)in_verify_rep) + in_verify_rep->len);

    if( in_verify_rep->side != in_sign_rep->side ||
    		memcmp(in_verify_rep->spi,in_sign_rep->spi,RHP_PROTO_IKE_SPI_SIZE) ){
      RHP_BUG("");
      RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_BAD_VERIFY_SPI,"xLdLdGG",ipcmsg,"IKE_SIDE",in_verify_rep->side,"IKE_SIDE",in_sign_rep->side,in_verify_rep->spi,in_sign_rep->spi);
      goto error;
    }

    if( in_sign_rep->len < sizeof(rhp_ipcmsg_ikev1_rsasig_sign_rep) + in_sign_rep->signed_octets_len  ){
      RHP_BUG(" %d < %d, %d",in_sign_rep->len,sizeof(rhp_ipcmsg_ikev1_rsasig_sign_rep),in_sign_rep->signed_octets_len);
      goto error;
    }
  }


  vpn_ref = rhp_vpn_ikesa_spi_get(in_verify_rep->side,in_verify_rep->spi);
  vpn = RHP_VPN_REF(vpn_ref);
  if( vpn == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_LARVAL_VPN_NOT_FOUND,"xLdG",ipcmsg,"IKE_SIDE",in_verify_rep->side,in_verify_rep->spi);
    goto error;
  }


  RHP_LOCK(&(vpn->lock));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_IKESA_NOT_ACTIVE,"xxx",ipcmsg,vpn);
    goto error_vpn_l;
  }

  ikesa = vpn->ikesa_get(vpn,in_verify_rep->side,in_verify_rep->spi);
  if( ikesa == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_NO_IKESA,"xxLdG",ipcmsg,vpn,"IKE_SIDE",in_verify_rep->side,in_verify_rep->spi);
  	goto error_vpn_l;
  }

  is_rekeyed = (ikesa->v1.tx_initial_contact ? 0 : 1);

  rx_ikemesg = ikesa->pend_rx_ikemesg;
  ikesa->pend_rx_ikemesg = NULL;
  tx_ikemesg = ikesa->pend_tx_ikemesg;
  ikesa->pend_tx_ikemesg = NULL;

  if( rx_ikemesg == NULL || tx_ikemesg == NULL ){
  	RHP_BUG("");
  	goto error_vpn_l;
  }


  if( in_verify_rep->txn_id != ikesa->ipc_txn_id ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_REALM_BAD_ID,"xxxqq",ipcmsg,vpn,ikesa,in_verify_rep->txn_id,ikesa->ipc_txn_id);
    goto error_vpn_l;
  }

  if( !in_verify_rep->result ){
  	RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_VERIFY_RESULT_ERR,"xxx",ipcmsg,vpn,ikesa);
    goto error_vpn_l;
  }


  if( in_sign_rep == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_NO_SIGN_REP,"xxx",ipcmsg,vpn,ikesa);
    goto error_vpn_l;
  }

  if( in_sign_rep->txn_id != ikesa->ipc_txn_id ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_REALM_BAD_ID2,"xxxqq",ipcmsg,vpn,ikesa,in_sign_rep->txn_id,ikesa->ipc_txn_id);
    goto error_vpn_l;
  }

  if( !in_sign_rep->result ){
  	RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_SIGN_RESULT_ERR,"xxx",ipcmsg,vpn,ikesa);
  	goto error_vpn_l;
  }

  if( in_sign_rep->signed_octets_len == 0 ){
  	RHP_BUG("%d",in_sign_rep->signed_octets_len);
  	goto error_vpn_l;
  }

  if( vpn->vpn_realm_id != in_verify_rep->my_realm_id ||
  		in_verify_rep->my_realm_id != in_sign_rep->my_realm_id ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_REALM_BAD_ID_3,"xxxuuu",ipcmsg,vpn,ikesa,vpn->vpn_realm_id,in_sign_rep->my_realm_id,in_verify_rep->my_realm_id);
    goto error_vpn_l;
  }


  rlm = rhp_realm_get(in_verify_rep->my_realm_id);
  if( rlm == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_SIGN_REP_NO_REALM,"xxx",ipcmsg,vpn,ikesa);
    goto error_vpn_l;
  }



	if( in_verify_rep->alt_peer_id_len ){

		if( vpn->peer_id.alt_id ){
			rhp_ikev2_id_clear(vpn->peer_id.alt_id);
			_rhp_free(vpn->peer_id.alt_id);
			vpn->peer_id.alt_id = NULL;
		}

		err = rhp_ikev2_id_alt_setup(in_verify_rep->alt_peer_id_type,(void*)alt_id_p,
				in_verify_rep->alt_peer_id_len,&(vpn->peer_id));

		if( err ){
			RHP_BUG("");
	    goto error_vpn_l;
		}
	}

	rhp_ikev2_id_dump("rhp_ikev1_aggressive_ipc_rsasig_verify_and_sign_rep_handler",&(vpn->peer_id));


  {
		err = ikesa->generate_keys_v1(ikesa,ikesa->keys.v1.skeyid_len,ikesa->keys.v1.skeyid);
		if( err ){
			RHP_BUG("%d",err);
			goto error_vpn_l;
		}

		err = ikesa->encr->set_enc_key(ikesa->encr,ikesa->keys.v1.sk_e,ikesa->keys.v1.sk_e_len);
		if( err ){
			RHP_BUG("%d",err);
			goto error_vpn_l;
		}

		err = ikesa->encr->set_dec_key(ikesa->encr,ikesa->keys.v1.sk_e,ikesa->keys.v1.sk_e_len);
		if( err ){
			RHP_BUG("%d",err);
			goto error_vpn_l;
		}
  }


  RHP_LOCK(&(rlm->lock));

  err = _rhp_ikev1_new_pkt_aggressive_i_3_rsasig(vpn,ikesa,in_sign_rep,tx_ikemesg);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_ALLOC_IKEMSG_ERR,"xxxx",ipcmsg,ikesa,rlm,in_sign_rep);
	  RHP_UNLOCK(&(rlm->lock));
    goto error_vpn_l;
  }


  err = rhp_ikev1_rx_i_comp(vpn,ikesa,rlm,rx_ikemesg,tx_ikemesg,is_rekeyed);
  if( err && err != RHP_STATUS_IKEV2_MESG_HANDLER_END ){
	  RHP_UNLOCK(&(rlm->lock));
  	goto error_vpn_l;
  }

  RHP_UNLOCK(&(rlm->lock));
  rhp_realm_unhold(rlm);
  rlm = NULL;


  RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_I_3_RSASIG_OK,"KVP",rx_ikemesg,vpn,ikesa);

  rhp_ikev1_call_next_rx_mesg_handlers(rx_ikemesg,vpn,
  		in_verify_rep->side,in_verify_rep->spi,tx_ikemesg,RHP_IKEV1_MESG_HANDLER_P1_AGGRESSIVE);

  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

  rhp_ikev2_unhold_mesg(rx_ikemesg);
  rhp_ikev2_unhold_mesg(tx_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_RTRN,"xxx",ipcmsg,vpn,ikesa);
  return;


error_vpn_l:
	if( vpn ){
		if( ikesa ){
			rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_DELETE_WAIT);
			ikesa->timers->schedule_delete(vpn,ikesa,0);
		}
    RHP_UNLOCK(&(vpn->lock));
  }
error:
	if( in_verify_rep && !in_verify_rep->result ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_RSASIG_VERIFY_ERR,"KVE",rx_ikemesg,vpn,err);
	}else{
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_AGGRESSIVE_RSASIG_VERIFY_AND_SIGN_ERR,"KVE",rx_ikemesg,vpn,err);
	}

  if( rlm ){
    rhp_realm_unhold(rlm);
  }

	if( vpn ){
		rhp_vpn_unhold(vpn_ref);
	}

  if( rx_ikemesg ){
  	rhp_ikev2_unhold_mesg(rx_ikemesg);
  }

  if( tx_ikemesg ){
  	rhp_ikev2_unhold_mesg(tx_ikemesg);
  }

	rhp_ikev2_g_statistics_inc(ikesa_auth_errors);

  RHP_TRC(0,IKEV1_AGGRESSIVE_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_ERR,"xxxxxE",ipcmsg,vpn,vpn,ikesa,rlm,err);
  return;
}


int rhp_ikev1_aggressive_init()
{
	RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_INIT,"");

  if( rhp_random_bytes((u8*)&_rhp_ikev1_agg_ctx_hashtbl_rnd,sizeof(_rhp_ikev1_agg_ctx_hashtbl_rnd)) ){
    RHP_BUG("");
    return -EINVAL;
  }

  memset(_rhp_ikev1_agg_ctx_hashtbl,0,sizeof(rhp_ikev1_agg_ctx*)*RHP_VPN_HASH_TABLE_SIZE*2);

  _rhp_mutex_init("IAG",&rhp_ikev1_agg_lock);

  return 0;
}

void rhp_ikev1_aggressive_cleanup()
{
  RHP_TRC(0,RHPTRCID_IKEV1_AGGRESSIVE_CLEANUP,"");

  _rhp_mutex_destroy(&rhp_ikev1_agg_lock);

  return;
}
