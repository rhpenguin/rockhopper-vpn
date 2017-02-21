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

extern u8 rhp_proto_ikev1_xauth_vid[8];


extern int rhp_ikev2_ike_auth_setup_larval_vpn(rhp_vpn* larval_vpn,
		rhp_vpn_realm* rlm,rhp_ikesa* ikesa);

extern int rhp_ikev2_ike_auth_r_setup_nhrp(rhp_vpn* larval_vpn,
		rhp_vpn_realm* rlm,rhp_ikesa* ikesa);

extern void rhp_ikev2_ike_auth_setup_access_point(rhp_vpn* vpn,rhp_vpn_realm* rlm);

extern int rhp_ikev1_xauth_r_invoke_task(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_ikemesg);


rhp_ikev2_mesg* rhp_ikev1_new_pkt_main_i_1(rhp_ikesa* ikesa)
{
	int err = -EINVAL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_MAIN_I_1,"x",ikesa);

  tx_ikemesg = rhp_ikev1_new_mesg_tx(RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION,0,0);
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

    err = ikepayload->ext.v1_sa->set_def_ikesa_prop(ikepayload,NULL,0,0,
    				ikesa->auth_method,ikesa->v1.lifetime);
    if( err ){
      RHP_BUG("");
      goto error;
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

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_MAIN_I_1_RTRN,"xx",ikesa,tx_ikemesg);

  return tx_ikemesg;

error:
  if( tx_ikemesg ){
    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKEV1_TX_ALLOC_MAIN_REQ_ERR,"P",ikesa);
  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_MAIN_I_1_ERR,"x",ikesa);
  return NULL;
}

static int _rhp_ikev1_new_pkt_main_r_2(rhp_ikesa* ikesa,rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_MAIN_R_2,"xx",ikesa,tx_ikemesg);

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

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_MAIN_R_2_RTRN,"xx",ikesa,tx_ikemesg);
  return 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_MAIN_R_2_ERR,"xE",ikesa,err);
  return err;
}

static int _rhp_ikev1_new_pkt_main_i_3(rhp_ikesa* ikesa,rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_MAIN_I_3,"xx",ikesa,tx_ikemesg);

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

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_MAIN_I_3_RTRN,"xx",ikesa,tx_ikemesg);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_MAIN_I_3_ERR,"xx#",ikesa,tx_ikemesg,err);
	return err;
}

static int _rhp_ikev1_new_pkt_main_r_4(rhp_ikesa* ikesa,rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_MAIN_R_4,"xx",ikesa,tx_ikemesg);

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

  if( ikesa->prop.v1.auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){

  	u8 *ders = NULL, *endp;
  	int ders_len = 0;
  	int ders_num = 0;
  	rhp_cert_data* dn_data;
  	int i;

  	rhp_cfg_get_all_ca_dn_ders(&ders,&ders_len,&ders_num);

  	dn_data = (rhp_cert_data*)ders;
  	endp = ders + ders_len;
  	for( i = 0; i < ders_num; i++ ){

  		if( (u8*)dn_data >= endp ){
  			RHP_BUG("");
  			break;
  		}

			if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_CR,&ikepayload) ){
				err = -EINVAL;
				RHP_BUG("");
				goto error;
			}

			tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

			ikepayload->ext.v1_cr->set_cert_encoding(ikepayload,RHP_PROTO_IKEV1_CERT_ENC_X509_CERT_SIG);

			if( ikepayload->ext.v1_cr->set_ca(ikepayload,dn_data->len,(u8*)(dn_data + 1)) ){
				err = -EINVAL;
				RHP_BUG("");
				goto error;
			}

			dn_data = (rhp_cert_data*)(((u8*)(dn_data + 1)) + dn_data->len);
  	}
  }

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_MAIN_R_4_RTRN,"xx",ikesa,tx_ikemesg);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_MAIN_R_4_ERR,"xx#",ikesa,tx_ikemesg,err);
	return err;
}

static int _rhp_ikev1_new_pkt_main_i_5_psk(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_vpn_realm* rlm,
		rhp_ipcmsg_ikev1_psk_skeyid_rep* psk_rep,rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;
  u8* skeyid;
  u8* my_id = NULL;
  int my_id_type = 0;
  int my_id_len = 0;
	int hash_octets_len = 0;
	u8* hash_octets = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_MAIN_I_5_PSK,"xxxxx",vpn,ikesa,rlm,psk_rep,tx_ikemesg);

  skeyid = (u8*)(psk_rep + 1);

  if( rlm->my_auth.my_id.type ){

  	if( rhp_ikev2_id_value(&(rlm->my_auth.my_id),&my_id,&my_id_len,&my_id_type) ){
  		RHP_BUG("");
  		goto error;
  	}

  	my_id_type = rhp_ikev1_id_type(my_id_type); // IKEv2 ==> IKEv1 ID type
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

	_rhp_free(my_id);
	_rhp_free(hash_octets);

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_MAIN_I_5_PSK_RTRN,"xx",ikesa,tx_ikemesg);
  return 0;

error:
	if( my_id ){
		_rhp_free(my_id);
	}
	if( hash_octets ){
		_rhp_free(hash_octets);
	}
	RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_MAIN_I_5_PSK_ERR,"xx#",ikesa,tx_ikemesg,err);
	return err;
}

static int _rhp_ikev1_new_pkt_main_i_5_rsasig(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_vpn_realm* rlm,rhp_ipcmsg_ikev1_rsasig_sign_rep* rsasig_sign_rep,
		rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;
  u8* my_id = NULL;
  int my_id_type = 0;
  int my_id_len = 0;
	u8 *sign_octets = NULL, *p;
	unsigned int i;
	int my_cert_issuer_dn_der_len;
	u8* my_cert_issuer_dn_der = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_MAIN_I_5_RSASIG,"xxxxxp",vpn,ikesa,rlm,rsasig_sign_rep,tx_ikemesg,my_cert_issuer_dn_der_len,my_cert_issuer_dn_der);


  sign_octets = (u8*)(rsasig_sign_rep + 1);
  p = sign_octets + rsasig_sign_rep->signed_octets_len;



	err = rhp_ikev1_get_my_cert_ca_dn_der(rlm,&my_cert_issuer_dn_der,&my_cert_issuer_dn_der_len);
	if( err ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
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

  if( my_cert_issuer_dn_der_len ){

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_CR,&ikepayload) ){
    	err = -EINVAL;
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    ikepayload->ext.v1_cr->set_cert_encoding(ikepayload,RHP_PROTO_IKEV1_CERT_ENC_X509_CERT_SIG);

    if( ikepayload->ext.v1_cr->set_ca(ikepayload,my_cert_issuer_dn_der_len,my_cert_issuer_dn_der) ){
    	err = -EINVAL;
      RHP_BUG("");
      goto error;
    }
  }

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

	_rhp_free(my_id);

  if( my_cert_issuer_dn_der ){
  	_rhp_free(my_cert_issuer_dn_der);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_MAIN_I_5_RSASIG_RTRN,"xx",ikesa,tx_ikemesg);
  return 0;

error:
	if( my_id ){
		_rhp_free(my_id);
	}
  if( my_cert_issuer_dn_der ){
  	_rhp_free(my_cert_issuer_dn_der);
  }
	RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_MAIN_I_5_RSASIG_ERR,"xxE",ikesa,tx_ikemesg,err);
	return err;
}

static int _rhp_ikev1_new_pkt_main_r_6_psk(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_vpn_realm* rlm,
		rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;
  u8* my_id = NULL;
  int my_id_type = 0;
  int my_id_len = 0;
	int hash_octets_len = 0;
	u8* hash_octets = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_MAIN_R_6_PSK,"xxxx",vpn,ikesa,rlm,tx_ikemesg);

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

  {
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
  }

	tx_ikemesg->v1_p1_last_mesg = 1;

	_rhp_free(my_id);
	_rhp_free(hash_octets);

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_MAIN_R_6_PSK_RTRN,"xx",ikesa,tx_ikemesg);
  return 0;

error:
	if( my_id ){
		_rhp_free(my_id);
	}
	if( hash_octets ){
		_rhp_free(hash_octets);
	}
	RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_MAIN_R_6_PSK_ERR,"xx#",ikesa,tx_ikemesg,err);
	return err;
}

static int _rhp_ikev1_new_pkt_main_r_6_rsasig(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_vpn_realm* rlm,rhp_ipcmsg_ikev1_rsasig_sign_rep* rsasig_sign_rep,
		rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;
  u8* my_id = NULL;
  int my_id_type = 0;
  int my_id_len = 0;
	u8 *sign_octets = NULL, *p;
	unsigned int i;

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_MAIN_R_6_RSASIG,"xxxxx",vpn,ikesa,rlm,rsasig_sign_rep,tx_ikemesg);


  sign_octets = (u8*)(rsasig_sign_rep + 1);
  p = sign_octets + rsasig_sign_rep->signed_octets_len;


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

	_rhp_free(my_id);

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_MAIN_R_6_RSASIG_RTRN,"xx",ikesa,tx_ikemesg);
  return 0;

error:
	if( my_id ){
		_rhp_free(my_id);
	}
	RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_MAIN_R_6_RSASIG_ERR,"xx#",ikesa,tx_ikemesg,err);
	return err;
}


int rhp_ikev1_r_clear_old_vpn(rhp_vpn* new_vpn,rhp_ikesa** new_ikesa,
		int rx_initial_contact,int* is_rekeyed_r)
{
	int err = -EINVAL;
  rhp_vpn_ref* old_vpn_ref = NULL;
	rhp_vpn* old_vpn = NULL;
	int is_rekeyed = 0;

	RHP_TRC(0,RHPTRCID_IKEV1_R_CLEAR_OLD_VPN,"xxdx",new_vpn,*new_ikesa,rx_initial_contact,is_rekeyed_r);

	if( new_vpn->eap.role == RHP_EAP_DISABLED ){

		old_vpn_ref = rhp_vpn_get(0,&(new_vpn->peer_id),NULL);
		old_vpn = RHP_VPN_REF(old_vpn_ref);

	}else if( new_vpn->eap.role == RHP_EAP_AUTHENTICATOR ){

		if( !rhp_eap_id_is_null(&(new_vpn->eap.peer_id)) &&
				(new_vpn->eap.eap_method != RHP_PROTO_EAP_TYPE_PRIV_RADIUS ||
				rhp_eap_id_radius_not_null(&(new_vpn->eap.peer_id))) ){

			old_vpn_ref = rhp_vpn_get_by_eap_peer_id(0,&(new_vpn->eap.peer_id));
			old_vpn = RHP_VPN_REF(old_vpn_ref);
		}

		if( old_vpn == NULL &&
				new_vpn->eap.eap_method != RHP_PROTO_EAP_TYPE_PRIV_RADIUS ){

			old_vpn_ref = rhp_vpn_get(0,&(new_vpn->peer_id),&(new_vpn->eap.peer_id));
			old_vpn = RHP_VPN_REF(old_vpn_ref);
		}
	}

	if( old_vpn ){

    int ikesa_side = (*new_ikesa)->side;
    u8 ikesa_spi[RHP_PROTO_IKE_SPI_SIZE];

    memcpy(ikesa_spi,(*new_ikesa)->get_my_spi(*new_ikesa),RHP_PROTO_IKE_SPI_SIZE);

		RHP_UNLOCK(&(new_vpn->lock));


		{
			RHP_LOCK(&(old_vpn->lock));

			if( !rx_initial_contact &&
					!rhp_ip_addr_cmp(&(old_vpn->peer_addr),&(new_vpn->peer_addr)) &&
					old_vpn->local.if_info.addr_family == new_vpn->local.if_info.addr_family &&
					!memcmp(old_vpn->local.if_info.addr.raw,new_vpn->local.if_info.addr.raw,16) ){

				// IKE SA is rekeyed by the same peer.
				RHP_TRC(0,RHPTRCID_IKEV1_R_CLEAR_OLD_VPN_REKEYED,"xxx",new_vpn,*new_ikesa,old_vpn);

				is_rekeyed = 1;

			}else{

				RHP_TRC(0,RHPTRCID_IKEV1_R_CLEAR_OLD_VPN_DESTROY_OLD_VPN,"xxx",new_vpn,*new_ikesa,old_vpn);

				rhp_vpn_destroy(old_vpn);

				is_rekeyed = 0;
			}

			RHP_UNLOCK(&(old_vpn->lock));
		}


		RHP_LOCK(&(new_vpn->lock));

		if( !_rhp_atomic_read(&(new_vpn->is_active)) ){
			RHP_TRC(0,RHPTRCID_IKEV1_R_CLEAR_OLD_VPN_IKESA_NOT_ACTIVE_2,"xx",new_vpn);
			err = -EINVAL;
			goto error;
		}

		*new_ikesa = new_vpn->ikesa_get(new_vpn,ikesa_side,ikesa_spi);
		if( *new_ikesa == NULL ){
			RHP_TRC(0,RHPTRCID_IKEV1_R_CLEAR_OLD_VPN_NO_IKESA_2,"xLdG",new_vpn,"IKE_SIDE",ikesa_side,ikesa_spi);
			err = -EINVAL;
			goto error;
		}

		if( is_rekeyed ){

			new_vpn->v1.merge_larval_vpn = 1;

			// old_vpn->unique_id is immutable.
			memcpy(new_vpn->v1.cur_vpn_unique_id,old_vpn->unique_id,RHP_VPN_UNIQUE_ID_SIZE);
		}

		rhp_vpn_unhold(old_vpn_ref);

	}else{


		RHP_TRC(0,RHPTRCID_IKEV1_R_CLEAR_OLD_VPN_NO_OLD_VPN,"xx",new_vpn,*new_ikesa);
	}

	if( is_rekeyed_r ){
		*is_rekeyed_r = is_rekeyed;
	}

	RHP_TRC(0,RHPTRCID_IKEV1_R_CLEAR_OLD_VPN_RTRN,"xxxddp",new_vpn,*new_ikesa,old_vpn,is_rekeyed,new_vpn->v1.merge_larval_vpn,RHP_VPN_UNIQUE_ID_SIZE,new_vpn->v1.cur_vpn_unique_id);
	return 0;

error:
	if( old_vpn ){
		rhp_vpn_unhold(old_vpn_ref);
	}
	RHP_TRC(0,RHPTRCID_IKEV1_R_CLEAR_OLD_VPN_ERR,"xxxE",new_vpn,*new_ikesa,old_vpn,err);
	return err;
}

static int _rhp_ikev1_auth_search_rlm_cand(rhp_vpn_realm* rlm,void* ctx)
{
	rhp_ikev1_auth_srch_plds_ctx* s_pld_ctx = (rhp_ikev1_auth_srch_plds_ctx*)ctx;
	rhp_cfg_peer* cfg_peer = NULL;

	RHP_LOCK(&(rlm->lock));

	cfg_peer = rlm->get_peer_by_id(rlm,s_pld_ctx->peer_id_tmp);
	if( cfg_peer && (cfg_peer->id.type != RHP_PROTO_IKE_ID_ANY) ){

		s_pld_ctx->peer_notified_realm_id = rlm->id;

		RHP_UNLOCK(&(rlm->lock));

	  RHP_TRC(0,RHPTRCID_IKEV1_AUTH_SEARCH_RLM_CAND_OK,"xxu",s_pld_ctx,rlm,rlm->id);

		return RHP_STATUS_ENUM_OK;
	}

	RHP_UNLOCK(&(rlm->lock));

	return 0;
}


static int _rhp_ikev1_main_ipc_psk_skeyid_req(rhp_ikev2_mesg* ikemesg,
		unsigned long rlm_id,rhp_vpn* vpn,rhp_ikesa* ikesa,
		int mesg_octets_len,u8* mesg_octets,
		int peer_id_type,int peer_id_len,u8* peer_id,int exchange_type,
		rhp_ipcmsg** ipcmsg_r,int txn_id_flag)
{
  int err = 0;
  int len;
  rhp_ipcmsg_ikev1_psk_skeyid_req* psk_req;
  u8* p;

  RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_PSK_SKEYID_REQ,"xuxxLdppx",ikemesg,rlm_id,vpn,ikesa,"PROTO_IKE_ID",peer_id_type,peer_id_len,peer_id,mesg_octets_len,mesg_octets,ipcmsg_r);

  len = sizeof(rhp_ipcmsg_ikev1_psk_skeyid_req) + mesg_octets_len + peer_id_len;
  if( peer_id_type == RHP_PROTO_IKE_ID_FQDN ||
  		peer_id_type == RHP_PROTO_IKE_ID_RFC822_ADDR ){
  	len++; // '\0' terminated.
  }

  psk_req = (rhp_ipcmsg_ikev1_psk_skeyid_req*)rhp_ipc_alloc_msg(RHP_IPC_IKEV1_PSK_SKEYID_REQUEST,len);
  if( psk_req == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  p = (u8*)(psk_req + 1);


  psk_req->len = len;

  if( txn_id_flag ){
    ikesa->ipc_txn_id = rhp_ikesa_new_ipc_txn_id();
  }
  psk_req->txn_id = ikesa->ipc_txn_id;

  psk_req->my_realm_id = rlm_id;
  psk_req->side = ikesa->side;

	if( ikesa->side == RHP_IKE_INITIATOR ){
		memcpy(psk_req->spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
	}else{
		memcpy(psk_req->spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
	}
	psk_req->exchange_type = exchange_type;

  psk_req->prf_method = ikesa->prf->alg;

	psk_req->peer_id_type = peer_id_type;
	psk_req->peer_id_len = peer_id_len;
	memcpy(p,peer_id,peer_id_len);
  if( peer_id_type == RHP_PROTO_IKE_ID_FQDN ||
  		peer_id_type == RHP_PROTO_IKE_ID_RFC822_ADDR ){
  	psk_req->peer_id_len++;
  	p[peer_id_len] = '\0';
  	p += peer_id_len + 1;
  }else{
  	p += peer_id_len;
  }

  psk_req->mesg_octets_len = mesg_octets_len;
  memcpy(p,mesg_octets,mesg_octets_len);
  p += mesg_octets_len;


  *ipcmsg_r = (rhp_ipcmsg*)psk_req;

  RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_PSK_SKEYID_REQ_RTRN,"xuxp",ikemesg,rlm_id,ikesa,psk_req->len,psk_req);
  return 0;

error:
  if( psk_req ){
    _rhp_free_zero(psk_req,psk_req->len);
  }
  RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_PSK_SKEYID_REQ_ERR,"xuxE",ikemesg,rlm_id,ikesa,err);
  return err;
}

int rhp_ikev1_ipc_psk_create_auth_req(rhp_vpn* vpn,rhp_ikesa* ikesa,
			rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg,
			int peer_id_type,int peer_id_len,u8* peer_id,int exchange_type)
{
  int err = -EINVAL;
  u8* mesg_octets = NULL;
  int mesg_octets_len = 0;
  rhp_ipcmsg* psk_req = NULL;
	int peer_id_type_tmp;
	int peer_id_len_tmp;
	u8* peer_id_tmp = NULL;
	unsigned long rlm_id;

  RHP_TRC(0,RHPTRCID_IKEV1_IPC_PSK_CREATE_AUTH_REQ,"xxxxx",rx_ikemesg,tx_ikemesg,vpn,ikesa,vpn->rlm);

  if( vpn->v1.def_realm_id == 0 || vpn->v1.def_realm_id == RHP_VPN_REALM_ID_UNKNOWN ){
  	rlm_id = vpn->vpn_realm_id;
  }else{
  	rlm_id = vpn->v1.def_realm_id;
  }

  err = rhp_ikev1_gen_psk_skeyid_material(vpn,ikesa,&mesg_octets,&mesg_octets_len);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV1_IPC_PSK_CREATE_AUTH_REQ_GET_MESG_OCTETS_ERR,"xxxd",rx_ikemesg,vpn,ikesa,err);
    goto error;
  }

  if( peer_id == NULL ){

  	err = rhp_ikev2_id_value(&(vpn->peer_id),&peer_id_tmp,&peer_id_len_tmp,&peer_id_type_tmp);
  	if( err ){
  		RHP_BUG("%d",err);
  		goto error;
  	}

  	peer_id_type = peer_id_type_tmp;
  	peer_id_len = peer_id_len_tmp;
  	peer_id = peer_id_tmp;
  }


  err = _rhp_ikev1_main_ipc_psk_skeyid_req(rx_ikemesg,
  				rlm_id,vpn,ikesa,mesg_octets_len,mesg_octets,
  				peer_id_type,peer_id_len,peer_id,exchange_type,&psk_req,1);

  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV1_IPC_PSK_CREATE_AUTH_REQ_SING_REQ_ERR,"xxxd",rx_ikemesg,vpn,ikesa,err);
    goto error;
  }

  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)psk_req,psk_req->len,0) < 0 ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  ikesa->pend_rx_ikemesg = rx_ikemesg;
  rhp_ikev2_hold_mesg(rx_ikemesg);

  ikesa->pend_tx_ikemesg = tx_ikemesg;
  rhp_ikev2_hold_mesg(tx_ikemesg);

  ikesa->busy_flag = 1;

  if( peer_id_tmp ){
  	_rhp_free(peer_id_tmp);
  }

  _rhp_free_zero(psk_req,psk_req->len);

  RHP_TRC(0,RHPTRCID_IKEV1_IPC_PSK_CREATE_AUTH_REQ_RTRN,"xxx",rx_ikemesg,vpn,ikesa);
  return 0;

error:
  if( mesg_octets ){
    _rhp_free_zero(mesg_octets,mesg_octets_len);
  }
  if( peer_id_tmp ){
  	_rhp_free(peer_id_tmp);
  }
  if( psk_req ){
  	_rhp_free_zero(psk_req,psk_req->len);
  }
  RHP_TRC(0,RHPTRCID_IKEV1_IPC_PSK_CREATE_AUTH_REQ_ERR,"xxxE",rx_ikemesg,vpn,ikesa,err);
  return err;
}

static int _rhp_ikev1_main_ipc_rsasig_sign_req(rhp_ikev2_mesg* ikemesg,
		unsigned long rlm_id,rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ipcmsg** ipcmsg_r,int txn_id_flag)
{
  int err = 0;
	int mesg_octets_len = 0;
	u8* mesg_octets = NULL;
  int len;
  rhp_ipcmsg_ikev1_rsasig_sign_req* rsasig_sign_req;
  u8* p;

  RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_SIGN_REQ,"xuxxx",ikemesg,rlm_id,vpn,ikesa,ipcmsg_r);


  err = rhp_ikev1_p1_gen_hash_ir_material_part(ikesa->side,
  				ikesa,&mesg_octets,&mesg_octets_len);
  if( err ){
  	RHP_BUG("");
  	goto error;
  }


  len = (int)sizeof(rhp_ipcmsg_ikev1_rsasig_sign_req)
  			+ mesg_octets_len + ikesa->keys.v1.skeyid_len + ikesa->v1.rx_ca_dn_ders_len;

  rsasig_sign_req = (rhp_ipcmsg_ikev1_rsasig_sign_req*)rhp_ipc_alloc_msg(
  										RHP_IPC_IKEV1_SIGN_RSASIG_REQUEST,len);
  if( rsasig_sign_req == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  p = (u8*)(rsasig_sign_req + 1);


  rsasig_sign_req->len = len;

  if( txn_id_flag ){
    ikesa->ipc_txn_id = rhp_ikesa_new_ipc_txn_id();
  }
  rsasig_sign_req->txn_id = ikesa->ipc_txn_id;

  rsasig_sign_req->my_realm_id = rlm_id;
  rsasig_sign_req->side = ikesa->side;

	if( ikesa->side == RHP_IKE_INITIATOR ){
		memcpy(rsasig_sign_req->spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
	}else{
		memcpy(rsasig_sign_req->spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
	}

	rsasig_sign_req->exchange_type = ikesa->v1.p1_exchange_mode;

	rsasig_sign_req->prf_method = ikesa->prf->alg;

	rsasig_sign_req->mesg_octets_len = mesg_octets_len;
	memcpy(p,mesg_octets,mesg_octets_len);
	p += mesg_octets_len;

	rsasig_sign_req->skeyid_len = ikesa->keys.v1.skeyid_len;
	memcpy(p,ikesa->keys.v1.skeyid,ikesa->keys.v1.skeyid_len);
	p += ikesa->keys.v1.skeyid_len;

	rsasig_sign_req->certs_bin_max_size = rhp_gcfg_ca_dn_ders_max_size;
	rsasig_sign_req->ca_dn_ders_len = ikesa->v1.rx_ca_dn_ders_len;
	rsasig_sign_req->ca_dn_ders_num = ikesa->v1.rx_ca_dn_ders_num;
	if( ikesa->v1.rx_ca_dn_ders_len ){
		memcpy(p,ikesa->v1.rx_ca_dn_ders,ikesa->v1.rx_ca_dn_ders_len);
		p += ikesa->v1.rx_ca_dn_ders_len;
	}

	_rhp_free(mesg_octets);

  *ipcmsg_r = (rhp_ipcmsg*)rsasig_sign_req;

  RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_SIGN_REQ_RTRN,"xuxp",ikemesg,rlm_id,ikesa,rsasig_sign_req->len,rsasig_sign_req);
  return 0;

error:
  if( rsasig_sign_req ){
    _rhp_free_zero(rsasig_sign_req,rsasig_sign_req->len);
  }
  if( mesg_octets ){
  	_rhp_free(mesg_octets);
  }
  RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_SIGN_REQ_ERR,"xuxE",ikemesg,rlm_id,ikesa,err);
  return err;
}

int rhp_ikev1_ipc_rsasig_create_sign_req(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = -EINVAL;
  rhp_ipcmsg* rsasig_sign_req = NULL;
	unsigned long rlm_id;

  RHP_TRC(0,RHPTRCID_IKEV1_IPC_RSASIG_CREATE_SIGN_REQ,"xxxxx",rx_ikemesg,tx_ikemesg,vpn,ikesa,vpn->rlm);

	rlm_id = vpn->vpn_realm_id;
  if( !rlm_id ){
  	rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  }

  err = _rhp_ikev1_main_ipc_rsasig_sign_req(rx_ikemesg,rlm_id,
  				vpn,ikesa,&rsasig_sign_req,1);

  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV1_IPC_RSASIG_CREATE_SIGN_REQ_SING_REQ_ERR,"xxxd",rx_ikemesg,vpn,ikesa,err);
    goto error;
  }

  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)rsasig_sign_req,rsasig_sign_req->len,0) < 0 ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  ikesa->pend_rx_ikemesg = rx_ikemesg;
  rhp_ikev2_hold_mesg(rx_ikemesg);

  ikesa->pend_tx_ikemesg = tx_ikemesg;
  rhp_ikev2_hold_mesg(tx_ikemesg);

  ikesa->busy_flag = 1;


  _rhp_free_zero(rsasig_sign_req,rsasig_sign_req->len);

  RHP_TRC(0,RHPTRCID_IKEV1_IPC_RSASIG_CREATE_SIGN_REQ_RTRN,"xxx",rx_ikemesg,vpn,ikesa);
  return 0;

error:
  if( rsasig_sign_req ){
  	_rhp_free_zero(rsasig_sign_req,rsasig_sign_req->len);
  }
  RHP_TRC(0,RHPTRCID_IKEV1_IPC_RSASIG_CREATE_SIGN_REQ_ERR,"xxxE",rx_ikemesg,vpn,ikesa,err);
  return err;
}


static int _rhp_ikev1_main_ipc_rsasig_verify_req(rhp_ikev2_mesg* ikemesg,
		unsigned long rlm_id,rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev1_auth_srch_plds_ctx* s_pld_ctx,
		rhp_ipcmsg** ipcmsg_r,int txn_id_flag)
{
  int err = 0;
	int mesg_octets_len = 0;
	u8* mesg_octets = NULL;
  int len;
  rhp_ipcmsg_ikev1_rsasig_verify_req* rsasig_verify_req;
  u8* p;
  int verify_side = (ikesa->side == RHP_IKE_INITIATOR ? RHP_IKE_RESPONDER : RHP_IKE_INITIATOR);
  int peer_id_type = 0;
  int peer_id_len = 0, peer_id_bin_len = 0;
  u8 *peer_id = NULL, *peer_id_bin = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_REQ,"xuxxxd",ikemesg,rlm_id,vpn,ikesa,ipcmsg_r,s_pld_ctx->peer_id_type);

	if( s_pld_ctx->peer_id ){

		peer_id_type = s_pld_ctx->peer_id_type;
		peer_id_len = s_pld_ctx->peer_id_len;
		peer_id = s_pld_ctx->peer_id;

		peer_id_bin_len = ntohs(s_pld_ctx->peer_id_payload->payloadh->len) - sizeof(rhp_proto_ike_payload);
		peer_id_bin = (u8*)(s_pld_ctx->peer_id_payload->payloadh + 1);

	}else{

		if( rhp_ikev2_id_value(&(vpn->peer_id),&peer_id,&peer_id_len,&peer_id_type) ){
			RHP_BUG("");
			goto error;
		}

		peer_id_type = rhp_ikev1_id_type(peer_id_type); // IKEv2 ==> IKEv1 ID type
		if( peer_id_type < 0 ){
			RHP_BUG("%d",peer_id_type);
			err = -EINVAL;
			goto error;
		}
	}


	err = rhp_ikev1_p1_gen_hash_ir(verify_side,ikesa,
					peer_id_bin_len,peer_id_bin,
					peer_id_type,peer_id_len,peer_id,
					ikesa->keys.v1.skeyid_len,ikesa->keys.v1.skeyid,
					&mesg_octets,&mesg_octets_len);

	if( err ){
		goto error;
	}


  len = (int)sizeof(rhp_ipcmsg_ikev1_rsasig_verify_req) + peer_id_len
  			+ mesg_octets_len + s_pld_ctx->peer_cert_der_len + s_pld_ctx->untrust_ca_cert_ders_len
  			+ s_pld_ctx->sign_octets_len;

  if( peer_id_type == RHP_PROTO_IKE_ID_RFC822_ADDR ||
  		peer_id_type == RHP_PROTO_IKE_ID_FQDN ){
		len++; // + '\0'
	}


  rsasig_verify_req = (rhp_ipcmsg_ikev1_rsasig_verify_req*)rhp_ipc_alloc_msg(
  										RHP_IPC_IKEV1_VERIFY_RSASIG_REQUEST,len);
  if( rsasig_verify_req == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  p = (u8*)(rsasig_verify_req + 1);

  rsasig_verify_req->len = len;

  if( txn_id_flag ){
    ikesa->ipc_txn_id = rhp_ikesa_new_ipc_txn_id();
  }
  rsasig_verify_req->txn_id = ikesa->ipc_txn_id;

  rsasig_verify_req->my_realm_id = rlm_id;
  rsasig_verify_req->peer_notified_realm_id = s_pld_ctx->peer_notified_realm_id;

  rsasig_verify_req->side = ikesa->side;

	if( ikesa->side == RHP_IKE_INITIATOR ){
		memcpy(rsasig_verify_req->spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
	}else{
		memcpy(rsasig_verify_req->spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
	}

	rsasig_verify_req->exchange_type = ikesa->v1.p1_exchange_mode;

	rsasig_verify_req->peer_id_type = peer_id_type;
	rsasig_verify_req->peer_id_len = peer_id_len;
	memcpy(p,peer_id,peer_id_len);
	p += peer_id_len;
	if( peer_id_type == RHP_PROTO_IKE_ID_RFC822_ADDR ||
			peer_id_type == RHP_PROTO_IKE_ID_FQDN ){
		rsasig_verify_req->peer_id_len++;
		*p = '\0';
		p++;
	}

	if( s_pld_ctx->peer_cert_der_len ){

		rsasig_verify_req->peer_cert_bin_len = s_pld_ctx->peer_cert_der_len;

		memcpy(p,s_pld_ctx->peer_cert_der,s_pld_ctx->peer_cert_der_len);
		p += s_pld_ctx->peer_cert_der_len;
	}

	if( s_pld_ctx->untrust_ca_cert_ders_len ){

		rsasig_verify_req->cert_chain_num = s_pld_ctx->untrust_ca_cert_ders_num;
		rsasig_verify_req->cert_chain_bin_len = s_pld_ctx->untrust_ca_cert_ders_len;

		memcpy(p,s_pld_ctx->untrust_ca_cert_ders,s_pld_ctx->untrust_ca_cert_ders_len);
		p += s_pld_ctx->untrust_ca_cert_ders_len;
	}

	rsasig_verify_req->mesg_octets_len = mesg_octets_len;
	memcpy(p,mesg_octets,mesg_octets_len);
	p += mesg_octets_len;

	if( s_pld_ctx->sign_octets_len ){

		rsasig_verify_req->signature_octets_len = s_pld_ctx->sign_octets_len;
		memcpy(p,s_pld_ctx->sign_octets,s_pld_ctx->sign_octets_len);

		p += s_pld_ctx->sign_octets_len;
	}

	_rhp_free(mesg_octets);

	if( s_pld_ctx->peer_id == NULL ){
		_rhp_free(peer_id);
	}

  *ipcmsg_r = (rhp_ipcmsg*)rsasig_verify_req;

  RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_REQ_RTRN,"xuxp",ikemesg,rlm_id,ikesa,rsasig_verify_req->len,rsasig_verify_req);
  return 0;

error:
  if( rsasig_verify_req ){
    _rhp_free_zero(rsasig_verify_req,rsasig_verify_req->len);
  }
  if( mesg_octets ){
  	_rhp_free(mesg_octets);
  }
	if( s_pld_ctx->peer_id == NULL && peer_id ){
		_rhp_free(peer_id);
	}
  RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_REQ_ERR,"xuxE",ikemesg,rlm_id,ikesa,err);
  return err;
}


int rhp_ikev1_hybrid_auth_rsasig_verify_hash(rhp_ikev2_mesg* ikemesg,
		rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev1_auth_srch_plds_ctx* s_pld_ctx)
{
  int err = 0;
	int mesg_octets_len = 0;
	u8* mesg_octets = NULL;
  int verify_side = (ikesa->side == RHP_IKE_INITIATOR ? RHP_IKE_RESPONDER : RHP_IKE_INITIATOR);
  int peer_id_type = 0;
  int peer_id_len = 0, peer_id_bin_len = 0;
  u8 *peer_id = NULL, *peer_id_bin = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_HYBRID_AUTH_RSASIG_VERIFY_HASH,"xxxd",ikemesg,vpn,ikesa,s_pld_ctx->peer_id_type);

  if( s_pld_ctx->hash == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

	if( s_pld_ctx->peer_id ){

		peer_id_type = s_pld_ctx->peer_id_type;
		peer_id_len = s_pld_ctx->peer_id_len;
		peer_id = s_pld_ctx->peer_id;

		peer_id_bin_len = ntohs(s_pld_ctx->peer_id_payload->payloadh->len) - sizeof(rhp_proto_ike_payload);
		peer_id_bin = (u8*)(s_pld_ctx->peer_id_payload->payloadh + 1);

	}else{

		if( rhp_ikev2_id_value(&(vpn->peer_id),&peer_id,&peer_id_len,&peer_id_type) ){
			RHP_BUG("");
			goto error;
		}

		peer_id_type = rhp_ikev1_id_type(peer_id_type); // IKEv2 ==> IKEv1 ID type
		if( peer_id_type < 0 ){
			RHP_BUG("%d",peer_id_type);
			err = -EINVAL;
			goto error;
		}
	}


	err = rhp_ikev1_p1_gen_hash_ir(verify_side,ikesa,
					peer_id_bin_len,peer_id_bin,
					peer_id_type,peer_id_len,peer_id,
					ikesa->keys.v1.skeyid_len,ikesa->keys.v1.skeyid,
					&mesg_octets,&mesg_octets_len);

	if( err ){
		goto error;
	}


	if( mesg_octets_len != s_pld_ctx->hash_len ||
			memcmp(mesg_octets,s_pld_ctx->hash,mesg_octets_len) ){
		err = -EINVAL;
		goto error;
	}

	_rhp_free(mesg_octets);

	if( s_pld_ctx->peer_id == NULL ){
		_rhp_free(peer_id);
	}

  RHP_TRC(0,RHPTRCID_IKEV1_HYBRID_AUTH_RSASIG_VERIFY_HASH_RTRN,"xxx",ikemesg,vpn,ikesa);
  return 0;

error:
  if( mesg_octets ){
  	_rhp_free(mesg_octets);
  }
	if( s_pld_ctx->peer_id == NULL && peer_id ){
		_rhp_free(peer_id);
	}
  RHP_TRC(0,RHPTRCID_IKEV1_HYBRID_AUTH_RSASIG_VERIFY_HASH_ERR,"xxxE",ikemesg,vpn,ikesa,err);
  return err;
}


int rhp_ikev1_ipc_rsasig_create_verify_req(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev1_auth_srch_plds_ctx* s_pld_ctx,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = -EINVAL;
  rhp_ipcmsg* rsasig_verify_req = NULL;
	unsigned long rlm_id;

  RHP_TRC(0,RHPTRCID_IKEV1_IPC_RSASIG_CREATE_VERIFY_REQ,"xxxxxx",rx_ikemesg,tx_ikemesg,vpn,ikesa,s_pld_ctx,vpn->rlm);

	rlm_id = vpn->vpn_realm_id;
  if( !rlm_id ){
  	rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  }

  err = _rhp_ikev1_main_ipc_rsasig_verify_req(rx_ikemesg,rlm_id,
  				vpn,ikesa,s_pld_ctx,&rsasig_verify_req,1);

  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV1_IPC_RSASIG_CREATE_VERIFY_REQ_ERR,"xxxd",rx_ikemesg,vpn,ikesa,err);
    goto error;
  }

  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)rsasig_verify_req,rsasig_verify_req->len,0) < 0 ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  ikesa->pend_rx_ikemesg = rx_ikemesg;
  rhp_ikev2_hold_mesg(rx_ikemesg);

  ikesa->pend_tx_ikemesg = tx_ikemesg;
  rhp_ikev2_hold_mesg(tx_ikemesg);

  ikesa->busy_flag = 1;


  _rhp_free_zero(rsasig_verify_req,rsasig_verify_req->len);

  RHP_TRC(0,RHPTRCID_IKEV1_IPC_RSASIG_CREATE_VERIFY_REQ_RTRN,"xxx",rx_ikemesg,vpn,ikesa);
  return 0;

error:
  if( rsasig_verify_req ){
  	_rhp_free_zero(rsasig_verify_req,rsasig_verify_req->len);
  }
  RHP_TRC(0,RHPTRCID_IKEV1_IPC_RSASIG_CREATE_VERIFY_REQ_ERR,"xxxE",rx_ikemesg,vpn,ikesa,err);
  return err;
}


int rhp_ikev1_ipc_rsasig_create_verify_and_sign_req(rhp_vpn* vpn,rhp_ikesa* ikesa,
			rhp_ikev1_auth_srch_plds_ctx* s_pld_ctx,
			rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = -EINVAL;
  rhp_ipcmsg *in_verify_req = NULL, *in_sign_req = NULL;
  int verify_sign_req_len = 0;
  rhp_ipcmsg_verify_and_sign_req *verify_sign_req = NULL;
	unsigned long rlm_id;

  RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_CREATE_VERIFY_AND_SIGN_REQ,"xxxxxx",rx_ikemesg,tx_ikemesg,vpn,ikesa,s_pld_ctx,vpn->rlm);

	rlm_id = vpn->vpn_realm_id;
  if( !rlm_id ){
  	rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  }

  err = _rhp_ikev1_main_ipc_rsasig_verify_req(rx_ikemesg,rlm_id,
  				vpn,ikesa,s_pld_ctx,&in_verify_req,1);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_CREATE_VERIFY_AND_SIGN_REQ_VERIFY_ERR,"xxxd",rx_ikemesg,vpn,ikesa,err);
    goto error;
  }

  err = _rhp_ikev1_main_ipc_rsasig_sign_req(rx_ikemesg,rlm_id,
  				vpn,ikesa,&in_sign_req,0);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_CREATE_VERIFY_AND_SIGN_REQ_SIGN_ERR,"xxxd",rx_ikemesg,vpn,ikesa,err);
    goto error;
  }

  ((rhp_ipcmsg_ikev1_rsasig_sign_req*)in_sign_req)->txn_id
  		= ((rhp_ipcmsg_ikev1_rsasig_verify_req*)in_verify_req)->txn_id;


  {
  	u8* p;

  	verify_sign_req_len = sizeof(rhp_ipcmsg_verify_and_sign_req)
  												+ in_verify_req->len + in_sign_req->len;

  	verify_sign_req = (rhp_ipcmsg_verify_and_sign_req*)rhp_ipc_alloc_msg(
  										RHP_IPC_IKEV1_VERIFY_AND_SIGN_RSASIG_REQUEST,verify_sign_req_len);
  	if( verify_sign_req == NULL ){
    	err = -EINVAL;
    	RHP_BUG("");
    	goto error;
    }

  	verify_sign_req->len = verify_sign_req_len;

  	verify_sign_req->v1_exchange_type = ikesa->v1.p1_exchange_mode;

  	p = (u8*)(verify_sign_req + 1);

  	memcpy(p,in_verify_req,in_verify_req->len);
  	p += in_verify_req->len;

  	memcpy(p,in_sign_req,in_sign_req->len);
  }


  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)verify_sign_req,verify_sign_req->len,0) < 0 ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  ikesa->pend_rx_ikemesg = rx_ikemesg;
  rhp_ikev2_hold_mesg(rx_ikemesg);

  ikesa->pend_tx_ikemesg = tx_ikemesg;
  rhp_ikev2_hold_mesg(tx_ikemesg);

  ikesa->busy_flag = 1;


  _rhp_free_zero(in_verify_req,in_verify_req->len);
  _rhp_free_zero(in_sign_req,in_sign_req->len);
  _rhp_free_zero(verify_sign_req,verify_sign_req->len);

  RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_CREATE_VERIFY_AND_SIGN_REQ_RTRN,"xxx",rx_ikemesg,vpn,ikesa);
  return 0;

error:
  if( verify_sign_req ){
  	_rhp_free_zero(verify_sign_req,verify_sign_req->len);
  }
  if( in_verify_req ){
  	_rhp_free_zero(in_verify_req,in_verify_req->len);
  }
  if( in_sign_req ){
  	_rhp_free_zero(in_sign_req,in_sign_req->len);
  }
  RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_CREATE_VERIFY_AND_SIGN_REQ_ERR,"xxxE",rx_ikemesg,vpn,ikesa,err);
  return err;
}


static int _rhp_ikev1_rx_main_r_1(rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg,
		rhp_vpn** vpn_i,int* my_ikesa_side_i,u8* my_ikesa_spi_i)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_ikesa* ikesa = NULL;
  rhp_ip_addr peer_addr, rx_addr;
  rhp_proto_ike* ikeh = rx_ikemesg->rx_pkt->app.ikeh;
  rhp_vpn* larval_vpn = NULL;
  rhp_ikesa_init_i* init_i = NULL;
  rhp_ike_sa_init_srch_plds_ctx s_pld_ctx;
  int auth_method = 0, xauth_method = 0;
  unsigned long lifetime = 0;
	unsigned long def_realm_id = 0;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_1,"x",rx_ikemesg);

  rhp_ip_addr_reset(&peer_addr);
  rhp_ip_addr_reset(&rx_addr);

  if( rx_ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE ){

    rhp_ip_addr_set(&peer_addr,AF_INET,
    		(u8*)&(rx_ikemesg->rx_pkt->l3.iph_v4->src_addr),NULL,32,
    		rx_ikemesg->rx_pkt->l4.udph->src_port,0);

    rhp_ip_addr_set2(&rx_addr,AF_INET,
    		(u8*)&(rx_ikemesg->rx_pkt->l3.iph_v4->dst_addr),
    		rx_ikemesg->rx_pkt->l4.udph->dst_port);

    RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_PEER_ADDR,"xd4WXd",rx_ikemesg,peer_addr.addr_family,peer_addr.addr.v4,peer_addr.port,peer_addr.netmask.v4,peer_addr.prefixlen);

  }else if( rx_ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE ){

    rhp_ip_addr_set(&peer_addr,AF_INET6,
    		rx_ikemesg->rx_pkt->l3.iph_v6->src_addr,NULL,128,
    		rx_ikemesg->rx_pkt->l4.udph->src_port,0);

    rhp_ip_addr_set2(&rx_addr,AF_INET6,
    		(u8*)&(rx_ikemesg->rx_pkt->l3.iph_v6->dst_addr),
    		rx_ikemesg->rx_pkt->l4.udph->dst_port);

    RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_PEER_ADDR_V6,"xd6WXd",rx_ikemesg,peer_addr.addr_family,peer_addr.addr.v6,peer_addr.port,peer_addr.netmask.v4,peer_addr.prefixlen);

  }else{
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  memset(&s_pld_ctx,0,sizeof(rhp_ike_sa_init_srch_plds_ctx));

  s_pld_ctx.ikesa = ikesa;


  {
  	rhp_vpn_realm* def_rlm = rhp_ikev1_r_get_def_realm(&rx_addr,&peer_addr);
  	if( def_rlm == NULL ){
  		err = -EINVAL;
  		RHP_TRC(0,RHPTRCID_RX_IKEV1_MAIN_REQ_NO_DEF_IKEV1_REALM,"xE",rx_ikemesg,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_MAIN_REQ_NO_DEF_IKEV1_REALM_FOUND,"K",rx_ikemesg);
    	goto error;
  	}

  	RHP_LOCK(&(def_rlm->lock));
  	{
  		if( !_rhp_atomic_read(&(def_rlm->is_active)) ){
  			err = -EINVAL;
    		RHP_TRC(0,RHPTRCID_RX_IKEV1_MAIN_REQ_DEF_IKEV1_REALM_NOT_ACTIVE,"xE",rx_ikemesg,err);
  	  	RHP_UNLOCK(&(def_rlm->lock));
      	goto error;
  		}

  		if( def_rlm->my_auth.my_auth_method != RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG &&
  				def_rlm->my_auth.my_auth_method != RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ){

  			err = -EINVAL;
    		RHP_TRC(0,RHPTRCID_RX_IKEV1_MAIN_REQ_DEF_IKEV1_REALM_NO_VALID_AUTH_METHOD_FOUND,"xdE",rx_ikemesg,def_rlm->my_auth.my_auth_method,err);

    		RHP_UNLOCK(&(def_rlm->lock));
  	  	rhp_realm_unhold(def_rlm);

  	  	goto error;
  		}

  		if( def_rlm->my_auth.my_xauth_method == RHP_XAUTH_P1_AUTH_PSK ){
  			xauth_method = RHP_PROTO_IKE_AUTHMETHOD_XAUTH_INIT_PSK;
  			auth_method = RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY;
  		}else if( def_rlm->my_auth.my_xauth_method == RHP_XAUTH_P1_AUTH_RSASIG ){
  			xauth_method = RHP_PROTO_IKE_AUTHMETHOD_XAUTH_INIT_RSASIG;
  			auth_method = RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG;
  		}else if( def_rlm->my_auth.my_xauth_method == RHP_XAUTH_P1_AUTH_HYBRID_RSASIG ){
  			xauth_method = RHP_PROTO_IKE_AUTHMETHOD_HYBRID_INIT_RSASIG;
  			auth_method = RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG;
  		}else{
    		auth_method = def_rlm->my_auth.my_auth_method;
  		}

  		lifetime = def_rlm->ikesa.lifetime_hard;
  		def_realm_id = def_rlm->id;
  	}
  	RHP_UNLOCK(&(def_rlm->lock));

  	rhp_realm_unhold(def_rlm);
  }


  {
  	s_pld_ctx.dup_flag = 0;
    s_pld_ctx.resolved_prop.v1.auth_method = auth_method;
    s_pld_ctx.resolved_prop.v1.xauth_method = xauth_method;
    s_pld_ctx.resolved_prop.v1.life_time = lifetime;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_SA),
  			rhp_ikev1_srch_sa_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_RX_IKEV1_MAIN_REQ_ENUM_SA_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_MAIN_REQ_PARSE_SA_PAYLOAD_ERR,"KVPE",rx_ikemesg,NULL,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  			rhp_ikev2_mesg_search_cond_my_verndor_id,NULL,
  			rhp_ikev2_ike_sa_init_srch_my_vid_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
  		RHP_TRC(0,RHPTRCID_RX_IKEV1_MAIN_REQ_ENUM_MY_VENDOR_ID_ERR,"xxE",ikesa,rx_ikemesg,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_MAIN_REQ_PARSE_V_PAYLOAD_ERR,"KVPE",rx_ikemesg,NULL,ikesa,err);
    	goto error;
  	}
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

  larval_vpn->v1.def_realm_id = def_realm_id;


  ikesa = rhp_ikesa_v1_main_new_r(&(s_pld_ctx.resolved_prop.v1));
  if( ikesa == NULL ){
  	RHP_BUG("");
    err = -EINVAL;
  	goto error;
  }

  larval_vpn->ikesa_put(larval_vpn,ikesa);


  larval_vpn->peer_is_rockhopper = s_pld_ctx.peer_is_rockhopper;
  larval_vpn->peer_rockhopper_ver = s_pld_ctx.peer_rockhopper_ver;
  ikesa->peer_is_rockhopper = s_pld_ctx.peer_is_rockhopper;
  ikesa->peer_rockhopper_ver = s_pld_ctx.peer_rockhopper_ver;

 	RHP_LOCK(&(rx_ikemesg->rx_pkt->rx_ifc->lock));
 	{
 		larval_vpn->set_local_net_info(larval_vpn,rx_ikemesg->rx_pkt->rx_ifc,
 				rx_addr.addr_family,rx_addr.addr.raw);
  }
	RHP_UNLOCK(&(rx_ikemesg->rx_pkt->rx_ifc->lock));

  ikesa->set_init_spi(ikesa,ikeh->init_spi);

  larval_vpn->set_peer_addr(larval_vpn,&peer_addr,&peer_addr);

  larval_vpn->origin_peer_port = rx_ikemesg->rx_pkt->l4.udph->src_port;


  init_i = rhp_ikesa_alloc_init_i(ikesa->resp_spi,&peer_addr,rx_ikemesg);
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

  err = _rhp_ikev1_new_pkt_main_r_2(ikesa,tx_ikemesg);
  if( err ){
  	RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_ALLOC_RESP_PKT_ERR,"xxE",rx_ikemesg,ikesa,err);
  	goto error;
  }

  rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_MAIN_2ND_SENT_R);

  rhp_ikesa_init_i_put(init_i,&(ikesa->ike_init_i_hash));
  init_i = NULL;

  rhp_vpn_ikesa_v1_spi_put(&rx_addr,&peer_addr,
  		RHP_IKE_RESPONDER,ikesa->resp_spi,ikesa->init_spi);

  ikesa->timers->start_lifetime_timer(larval_vpn,ikesa,rhp_gcfg_ikesa_lifetime_larval,1);

  {
		larval_vpn->connecting = 1;
		rhp_ikesa_half_open_sessions_inc();
  }

  RHP_LOG_D(RHP_LOG_SRC_IKEV2,(larval_vpn ? larval_vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_R_1_OK,"KVP",rx_ikemesg,larval_vpn,ikesa);

  *vpn_i = larval_vpn;
  *my_ikesa_side_i = ikesa->side;
  memcpy(my_ikesa_spi_i,ikesa->get_my_spi(ikesa),RHP_PROTO_IKE_SPI_SIZE);

  tx_ikemesg->v1_set_retrans_resp = 1;

  RHP_UNLOCK(&(larval_vpn->lock));

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_1_RTRN,"xx",rx_ikemesg,ikesa);
  return 0;

error:
	if( larval_vpn ){

		rhp_vpn_ref* larval_vpn_ref = rhp_vpn_hold_ref(larval_vpn); // (xx*)

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,larval_vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_MAIN_R_1_ERR,"KVPE",rx_ikemesg,larval_vpn,ikesa,err);

    rhp_vpn_destroy(larval_vpn); // ikesa is also released.

    RHP_UNLOCK(&(larval_vpn->lock));
		rhp_vpn_unhold(larval_vpn_ref); // (xx*)

	}else{

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_MAIN_R_1_ERR_2,"KE",rx_ikemesg,err);
  }

	if( init_i ){
    rhp_ikesa_free_init_i(init_i);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_1_ERR,"xxE",rx_ikemesg,ikesa,err);
  return err;
}

static int _rhp_ikev1_rx_main_i_2(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_ikemesg,
		rhp_ikev2_mesg* tx_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_proto_ike* ikeh;
  rhp_ike_sa_init_srch_plds_ctx s_pld_ctx;
  int auth_method = 0, xauth_method = 0;
  unsigned long lifetime = 0;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_2,"xxxx",rx_ikemesg,tx_ikemesg,vpn,ikesa);

  ikeh = rx_ikemesg->rx_pkt->app.ikeh;

  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  {
		ikesa->timers->quit_retransmit_timer(vpn,ikesa);

		if( ikesa->req_retx_ikemesg ){

			ikesa->set_retrans_request(ikesa,NULL);

			rhp_ikev2_unhold_mesg(ikesa->req_retx_ikemesg);
			ikesa->req_retx_ikemesg = NULL;
		}
  }


  {
  	rhp_vpn_realm* rlm = vpn->rlm;

  	if( rlm == NULL ){
  		RHP_TRC(0,RHPTRCID_RX_IKEV1_MAIN_REP_NO_REALM,"xE",rx_ikemesg,err);
    	goto error;
  	}

  	RHP_LOCK(&(rlm->lock));
  	{

  		if( !_rhp_atomic_read(&(rlm->is_active)) ){
  			err = -EINVAL;
    		RHP_TRC(0,RHPTRCID_RX_IKEV1_MAIN_REP_REALM_NOT_ACTIVE,"xxE",rlm,rx_ikemesg,err);
  	  	RHP_UNLOCK(&(rlm->lock));
      	goto error;
  		}


  		if( rlm->my_auth.my_xauth_method == RHP_XAUTH_P1_AUTH_PSK ){
  			xauth_method = RHP_PROTO_IKE_AUTHMETHOD_XAUTH_INIT_PSK;
  			auth_method = RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY;
  		}else if( rlm->my_auth.my_xauth_method == RHP_XAUTH_P1_AUTH_RSASIG ){
  			xauth_method = RHP_PROTO_IKE_AUTHMETHOD_XAUTH_INIT_RSASIG;
  			auth_method = RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG;
  		}else if( rlm->my_auth.my_xauth_method == RHP_XAUTH_P1_AUTH_HYBRID_RSASIG ){
  			xauth_method = RHP_PROTO_IKE_AUTHMETHOD_HYBRID_INIT_RSASIG;
  			auth_method = RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG;
  		}else{
    		auth_method = rlm->my_auth.my_auth_method;
  		}

  		lifetime = rlm->ikesa.lifetime_hard;
  	}
  	RHP_UNLOCK(&(rlm->lock));
  }


  memset(&s_pld_ctx,0,sizeof(rhp_ike_sa_init_srch_plds_ctx));

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;


  {
  	s_pld_ctx.dup_flag = 0;
    s_pld_ctx.resolved_prop.v1.auth_method = auth_method;
    s_pld_ctx.resolved_prop.v1.xauth_method = xauth_method;
    s_pld_ctx.resolved_prop.v1.life_time = lifetime;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_SA),
  			rhp_ikev1_srch_sa_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_2_ENUM_SA_PLD_ERR,"xxxd",rx_ikemesg,vpn,ikesa,err);
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_I_2_PARSE_SA_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  			rhp_ikev2_mesg_search_cond_my_verndor_id,NULL,
  			rhp_ikev2_ike_sa_init_srch_my_vid_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
  		RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_2_ENUM_MY_VENDOR_ID_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_I_2_PARSE_V_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
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
    ikesa->dh = rhp_crypto_dh_alloc(ikesa->prop.v1.dh_group);
    if( ikesa->dh == NULL ){
    	RHP_BUG("");
    	goto error;
    }

    if( ikesa->dh->generate_key(ikesa->dh) ){
    	RHP_BUG("");
    	goto error;
    }

    ikesa->nonce_i = rhp_crypto_nonce_alloc();
    if( ikesa->nonce_i == NULL ){
    	RHP_BUG("");
    	goto error;
    }

    if( ikesa->nonce_i->generate_nonce(ikesa->nonce_i,rhp_gcfg_nonce_size) ){
    	RHP_BUG("");
    	goto error;
    }
  }


  err = _rhp_ikev1_new_pkt_main_i_3(ikesa,tx_ikemesg);
  if( err ){
  	goto error;
  }

  rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_MAIN_3RD_SENT_I);


  {
  	rhp_ip_addr my_addr;

  	memset(&my_addr,0,sizeof(rhp_ip_addr));
  	my_addr.addr_family = vpn->local.if_info.addr_family;
  	memcpy(my_addr.addr.raw,vpn->local.if_info.addr.raw,16);

  	rhp_vpn_ikesa_v1_spi_put(&my_addr,&(vpn->peer_addr),
  		RHP_IKE_INITIATOR,ikesa->init_spi,ikesa->resp_spi);
  }

  tx_ikemesg->v1_start_retx_timer = 1;


	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_I_2_OK,"KVP",rx_ikemesg,vpn,ikesa);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_2_RTRN,"xxx",rx_ikemesg,vpn,ikesa);
  return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_I_2_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
  if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_2_ERR,"xxx",rx_ikemesg,vpn,ikesa);
  return err;
}

static int _rhp_ikev1_rx_main_r_3_rsasig(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_ikemesg,
		rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
	u8* skeyid = NULL;
	int skeyid_len = 0;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_3_RSASIG,"xxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg);

	vpn->eap.role = RHP_EAP_DISABLED;

	err = _rhp_ikev1_new_pkt_main_r_4(ikesa,tx_ikemesg);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_3_RSASIG_NEW_PKT_ERR,"xxxxE",vpn,ikesa,rx_ikemesg,tx_ikemesg,err);
    goto error;
  }


  {
		err = ikesa->dh->compute_key(ikesa->dh);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		err = rhp_ikev1_gen_rsasig_skeyid(vpn,ikesa,&skeyid,&skeyid_len);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		err = ikesa->generate_keys_v1(ikesa,skeyid_len,skeyid);
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

  tx_ikemesg->v1_dont_enc = 1;

	rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_MAIN_4TH_SENT_R);

	_rhp_free_zero(skeyid,skeyid_len);

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_R_3_OK,"KVP",rx_ikemesg,vpn,ikesa);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_3_RSASIG_NEW_PKT_RTRN,"xxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg);
  return 0;

error:
	if( skeyid ){
		_rhp_free_zero(skeyid,skeyid_len);
	}

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_SKEYID_ERR,"VE",vpn,err);

	rhp_ikev2_g_statistics_inc(ikesa_auth_errors);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_3_RSASIG_NEW_PKT_ERR,"xxxxE",vpn,ikesa,rx_ikemesg,tx_ikemesg,err);
  return err;
}

static int _rhp_ikev1_rx_main_r_3(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_ikemesg,
		rhp_ikev2_mesg* tx_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_ike_sa_init_srch_plds_ctx s_pld_ctx;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_3,"xxxx",rx_ikemesg,tx_ikemesg,vpn,ikesa);

  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


  memset(&s_pld_ctx,0,sizeof(rhp_ike_sa_init_srch_plds_ctx));

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;


  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_NONCE),
  			rhp_ikev1_srch_nonce_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_RHPTRCID_IKEV1_RX_MAIN_R_3_ENUM_NIR_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_MAIN_R_3_PARSE_NONCE_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
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
      RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_3_ENUM_KE_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_MAIN_R_3_PARSE_KE_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
  }


  {
  	int prf_alg, encr_alg;

    ikesa->dh = rhp_crypto_dh_alloc(ikesa->prop.v1.dh_group);
    if( ikesa->dh == NULL ){
    	RHP_BUG("");
    	goto error;
    }

    if( ikesa->dh->generate_key(ikesa->dh) ){
    	RHP_BUG("");
    	goto error;
    }

    err = ikesa->dh->set_peer_pub_key(ikesa->dh,s_pld_ctx.peer_dh_pub_key,s_pld_ctx.peer_dh_pub_key_len);
    if( err ){
    	RHP_BUG("%d",err);
    	goto error;
    }


    ikesa->nonce_i = rhp_crypto_nonce_alloc();
    if( ikesa->nonce_i == NULL ){
    	RHP_BUG("");
    	goto error;
    }

    err = ikesa->nonce_i->set_nonce(ikesa->nonce_i,s_pld_ctx.nonce,s_pld_ctx.nonce_len);
    if( err ){
    	RHP_BUG("%d",err);
    	goto error;
    }


    ikesa->nonce_r = rhp_crypto_nonce_alloc();
    if( ikesa->nonce_r == NULL ){
  		err = -EINVAL;
    	RHP_BUG("");
    	goto error;
    }

    if( ikesa->nonce_r->generate_nonce(ikesa->nonce_r,rhp_gcfg_nonce_size) ){
  		err = -EINVAL;
    	RHP_BUG("");
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


  if( ikesa->prop.v1.auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){

		err = _rhp_ikev1_rx_main_r_3_rsasig(vpn,ikesa,rx_ikemesg,tx_ikemesg);
		if( err ){
			goto error;
		}

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_R_3_RSASIG_OK,"KVP",rx_ikemesg,vpn,ikesa);

  }else if( ikesa->prop.v1.auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ){

  	int peer_addr_len = 0, peer_addr_type = 0;
  	u8 peer_addr[16];

    if( rx_ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE ){
    	peer_addr_len = 4;
    	peer_addr_type = RHP_PROTO_IKE_ID_IPV4_ADDR;
    	*((u32*)peer_addr) = rx_ikemesg->rx_pkt->l3.iph_v4->src_addr;
    }else if( rx_ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE ){
    	peer_addr_len = 16;
    	peer_addr_type = RHP_PROTO_IKE_ID_IPV6_ADDR;
    	memcpy(peer_addr,rx_ikemesg->rx_pkt->l3.iph_v6->src_addr,16);
    }

    err = rhp_ikev1_ipc_psk_create_auth_req(vpn,ikesa,rx_ikemesg,tx_ikemesg,
    				peer_addr_type,peer_addr_len,peer_addr,RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION);
    if( err ){
    	goto error;
    }

  	err = RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;

  }else{
  	RHP_BUG("%d",ikesa->prop.v1.auth_method);
  	err = -EINVAL;
  	goto error;
  }

  tx_ikemesg->v1_set_retrans_resp = 1;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_3_RTRN,"xxxE",rx_ikemesg,vpn,ikesa,err);
  return err;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_R_3_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
  if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_3_ERR,"xxx",rx_ikemesg,vpn,ikesa);
  return err;
}

static int _rhp_ikev1_rx_main_i_4(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_ikemesg,
		rhp_ikev2_mesg* tx_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_ike_sa_init_srch_plds_ctx s_pld_ctx;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_4,"xxxx",rx_ikemesg,tx_ikemesg,vpn,ikesa);

  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  {
		ikesa->timers->quit_retransmit_timer(vpn,ikesa);

		if( ikesa->req_retx_ikemesg ){

			ikesa->set_retrans_request(ikesa,NULL);

			rhp_ikev2_unhold_mesg(ikesa->req_retx_ikemesg);
			ikesa->req_retx_ikemesg = NULL;
		}
  }


  memset(&s_pld_ctx,0,sizeof(rhp_ike_sa_init_srch_plds_ctx));

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;


  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  					rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_KE),
  					rhp_ikev1_srch_ke_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_4_ENUM_SA_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_MAIN_I_4_PARSE_KE_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
      err = 0; // This may be a delayed retransmitted response. Just ignored.
      rx_ikemesg->v1_ignored = 1;
      goto error;
    }
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  					rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_NONCE),
  					rhp_ikev1_srch_nonce_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_4_ENUM_NIR_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_MAIN_I_4_PARSE_NONCE_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
      goto error;
    }
  }


  {
  	int prf_alg, encr_alg;

    err = ikesa->dh->set_peer_pub_key(ikesa->dh,s_pld_ctx.peer_dh_pub_key,s_pld_ctx.peer_dh_pub_key_len);
    if( err ){
    	RHP_BUG("%d",err);
    	goto error;
    }


    ikesa->nonce_r = rhp_crypto_nonce_alloc();
    if( ikesa->nonce_r == NULL ){
  		err = -EINVAL;
    	RHP_BUG("");
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


  if( ikesa->prop.v1.auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){

    {
    	s_pld_ctx.dup_flag = 0;

    	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
    					rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_CR),
    					rhp_ikev1_srch_cert_req_cb,&s_pld_ctx);

      if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
        RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_4_ENUM_CERET_REQ_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
      	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_MAIN_I_4_PARSE_CERT_REQ_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
        goto error;
      }
      err = 0;
    }

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


    err = rhp_ikev1_ipc_rsasig_create_sign_req(vpn,ikesa,rx_ikemesg,tx_ikemesg);
    if( err ){
    	goto error;
    }

  }else if( ikesa->prop.v1.auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ){

    err = rhp_ikev1_ipc_psk_create_auth_req(vpn,ikesa,rx_ikemesg,tx_ikemesg,
    				0,0,NULL,RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION);
    if( err ){
    	goto error;
    }

  }else{
  	RHP_BUG("%d",ikesa->prop.v1.auth_method);
  	err = -EINVAL;
  	goto error;
  }


  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_4_RTRN,"xxx",rx_ikemesg,vpn,ikesa);
  return RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;

error:
	if( err ){

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_I_4_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);

		if( ikesa ){
			rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_DELETE_WAIT);
			ikesa->timers->schedule_delete(vpn,ikesa,0);
		}
	}

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_4_ERR,"xxxE",rx_ikemesg,vpn,ikesa,err);
  return err;
}


int rhp_ikev1_rx_i_comp(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_vpn_realm* rlm,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg,int is_rekeyed)
{
	int err = -EINVAL;
	time_t ikesa_lifetime_hard, ikesa_lifetime_soft;

	RHP_TRC(0,RHPTRCID_IKEV1_RX_I_COMP,"xxxxxdpddd",vpn,ikesa,rlm,rx_ikemesg,tx_ikemesg,is_rekeyed,rx_ikemesg->v1_p2_iv_len,rx_ikemesg->v1_p2_rx_last_blk,rlm->v1.dpd_enabled,vpn->v1.peer_dpd_supproted,vpn->ikesa_req_rekeying);

	rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_ESTABLISHED);
  vpn->created_ikesas++;

	if( ikesa->auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){
  	rhp_ikev2_g_statistics_inc(ikesa_auth_rsa_sig);
	}else if( ikesa->auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ){
  	rhp_ikev2_g_statistics_inc(ikesa_auth_psk);
	}


  if( ikesa->prop.v1.life_time &&
  		(time_t)ikesa->prop.v1.life_time > (time_t)rhp_gcfg_ikev1_ikesa_min_lifetime ){

  	ikesa_lifetime_hard = (time_t)ikesa->prop.v1.life_time;

		ikesa_lifetime_soft = ikesa_lifetime_hard - (time_t)rhp_gcfg_ikev1_ikesa_rekey_margin;
		if( (time_t)rlm->ikesa.lifetime_soft < ikesa_lifetime_soft ){
			ikesa_lifetime_soft = (time_t)rlm->ikesa.lifetime_soft;
		}

  }else{

  	ikesa_lifetime_hard = (time_t)rlm->ikesa.lifetime_hard;
		ikesa_lifetime_soft = (time_t)rlm->ikesa.lifetime_soft;
  }


	ikesa->established_time = _rhp_get_time();
	ikesa->expire_hard = ikesa->established_time + ikesa_lifetime_hard;
	ikesa->expire_soft = ikesa->established_time + ikesa_lifetime_soft;


	ikesa->timers->start_lifetime_timer(vpn,ikesa,ikesa_lifetime_soft,1);


	if( rlm->v1.dpd_enabled && vpn->v1.peer_dpd_supproted ){

		ikesa->timers->start_keep_alive_timer(vpn,ikesa,(time_t)rlm->ikesa.keep_alive_interval);

		vpn->v1.dpd_enabled = 1;
	}

	ikesa->timers->start_nat_t_keep_alive_timer(vpn,ikesa,(time_t)rlm->ikesa.nat_t_keep_alive_interval);


  if( !is_rekeyed ){

		rhp_vpn_put(vpn);

		rhp_ikev2_ike_auth_setup_access_point(vpn,rlm);

  	vpn->vpn_conn_lifetime = (time_t)rlm->vpn_conn_lifetime;
		vpn->start_vpn_conn_life_timer(vpn);

		rhp_http_bus_broadcast_async(vpn->vpn_realm_id,1,1,
				rhp_ui_http_vpn_established_serialize,
				rhp_ui_http_vpn_bus_btx_async_cleanup,(void*)rhp_vpn_hold_ref(vpn)); // (*x*)

		vpn->auto_reconnect_retries = 0;


		if( vpn->internal_net_info.static_peer_addr ){

			rhp_vpn_internal_route_update(vpn);
		}

		if( vpn->init_by_peer_addr ){

			if( !rhp_gcfg_dmvpn_connect_shortcut_rate_limit ){

				rhp_vpn_connect_i_pending_clear(vpn->vpn_realm_id,NULL,&(vpn->peer_addr));
			}

		}else{

			rhp_vpn_connect_i_pending_clear(vpn->vpn_realm_id,&(vpn->peer_id),NULL);
		}

  }else{

		rhp_ikev1_detach_old_ikesa(vpn,ikesa);

		vpn->ikesa_req_rekeying = 0;

    RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_6_PSK_IS_REKEY,"xxx",rx_ikemesg,vpn,ikesa);
  }


	vpn->established = 1;

	if( vpn->connecting ){
		vpn->connecting = 0;
		rhp_ikesa_half_open_sessions_dec();
	}

  ikesa->busy_flag = 0;

  {
		if( ikesa->v1.p2_iv_material ){
			RHP_BUG("%d",ikesa->v1.p2_iv_material_len);
		}

		ikesa->v1.p2_iv_material = rx_ikemesg->v1_p2_rx_last_blk;
		ikesa->v1.p2_iv_material_len = rx_ikemesg->v1_p2_iv_len;
		rx_ikemesg->v1_p2_rx_last_blk = NULL;
		rx_ikemesg->v1_p2_iv_len = 0;
  }

  err = 0;

	RHP_TRC(0,RHPTRCID_IKEV1_RX_I_COMP_RTRN,"xxxpE",vpn,ikesa,rx_ikemesg,ikesa->v1.p2_iv_material_len,ikesa->v1.p2_iv_material,err);
	return err;
}

int rhp_ikev1_rx_r_set_p2_iv(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_ikemesg)
{
	RHP_TRC(0,RHPTRCID_IKEV1_RX_R_SET_P2_IV,"xxxpp",vpn,ikesa,rx_ikemesg,rx_ikemesg->v1_p2_iv_len,rx_ikemesg->v1_p2_rx_last_blk,ikesa->v1.p2_iv_material_len,ikesa->v1.p2_iv_material);

	if( rx_ikemesg->v1_p2_rx_last_blk &&
			ikesa->v1.p2_iv_material == NULL ){

		memcpy(ikesa->keys.v1.p1_iv_rx_last_blk,
				rx_ikemesg->v1_p2_rx_last_blk,rx_ikemesg->v1_p2_iv_len);

		ikesa->v1.p2_iv_material = rx_ikemesg->v1_p2_rx_last_blk;
		ikesa->v1.p2_iv_material_len = rx_ikemesg->v1_p2_iv_len;

		rx_ikemesg->v1_p2_rx_last_blk = NULL;
		rx_ikemesg->v1_p2_iv_len = 0;
	}

	RHP_TRC(0,RHPTRCID_IKEV1_RX_R_SET_P2_IV_RTRN,"xxxpp",vpn,ikesa,rx_ikemesg,ikesa->keys.v1.iv_len,ikesa->keys.v1.p1_iv_rx_last_blk,ikesa->v1.p2_iv_material_len,ikesa->v1.p2_iv_material);
	return 0;
}

int rhp_ikev1_rx_r_comp(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_vpn_realm* rlm,
			rhp_ikev2_mesg* rx_ikemesg,int is_rekeyed)
{
	int err = -EINVAL;
  time_t ikesa_lifetime_soft,ikesa_lifetime_hard,keep_alive_interval,nat_t_keep_alive_interval;
  int dpd_enabled;

	RHP_TRC(0,RHPTRCID_IKEV1_RX_R_COMP,"xxxdxdp",vpn,ikesa,rlm,rlm->encap_mode_c,rx_ikemesg,is_rekeyed,rx_ikemesg->v1_p2_iv_len,rx_ikemesg->v1_p2_rx_last_blk);

  if( !is_rekeyed ){

		err = rhp_ikev2_ike_auth_r_setup_nhrp(vpn,rlm,ikesa);
		if( err ){
			goto error;
		}


		if( !rhp_ip_addr_null(&(vpn->cfg_peer->internal_addr)) ){

			rhp_ip_addr_list* peer_addr;

			peer_addr = rhp_ip_dup_addr_list(&(vpn->cfg_peer->internal_addr));
			if( peer_addr == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}
			peer_addr->ip_addr.tag = RHP_IPADDR_TAG_STATIC_PEER_ADDR;

			peer_addr->next = vpn->internal_net_info.peer_addrs;
			vpn->internal_net_info.peer_addrs = peer_addr;

			vpn->internal_net_info.static_peer_addr = 1;
		}


  	rhp_vpn_put(vpn);

  	rhp_ikev2_ike_auth_setup_access_point(vpn,rlm);

		rhp_http_bus_broadcast_async(vpn->vpn_realm_id,1,1,
			rhp_ui_http_vpn_added_serialize,
			rhp_ui_http_vpn_bus_btx_async_cleanup,(void*)rhp_vpn_hold_ref(vpn)); // (*x*)

		RHP_LOG_I(RHP_LOG_SRC_VPNMNG,vpn->vpn_realm_id,RHP_LOG_ID_VPN_ADDED,"IAsNA",&(vpn->peer_id),&(vpn->peer_addr),vpn->peer_fqdn,vpn->unique_id,NULL);

		vpn->vpn_conn_lifetime = (time_t)rlm->vpn_conn_lifetime;
  }

  if( ikesa->prop.v1.life_time &&
  		(time_t)ikesa->prop.v1.life_time > (time_t)rhp_gcfg_ikev1_ikesa_min_lifetime ){

  	ikesa_lifetime_hard = (time_t)ikesa->prop.v1.life_time;

		ikesa_lifetime_soft = ikesa_lifetime_hard - (time_t)rhp_gcfg_ikev1_ikesa_rekey_margin;
		if( (time_t)rlm->ikesa.lifetime_soft < ikesa_lifetime_soft ){
			ikesa_lifetime_soft = (time_t)rlm->ikesa.lifetime_soft;
		}

  }else{

  	ikesa_lifetime_hard = (time_t)rlm->ikesa.lifetime_hard;
		ikesa_lifetime_soft = (time_t)rlm->ikesa.lifetime_soft;
  }

  keep_alive_interval = (time_t)rlm->ikesa.keep_alive_interval;
  nat_t_keep_alive_interval = (time_t)rlm->ikesa.nat_t_keep_alive_interval;
  dpd_enabled = (rlm->v1.dpd_enabled && vpn->v1.peer_dpd_supproted ? 1 : 0);

	vpn->ikesa_move_to_top(vpn,ikesa);


	rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_ESTABLISHED);
  vpn->created_ikesas++;


	if( ikesa->auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){
  	rhp_ikev2_g_statistics_inc(ikesa_auth_rsa_sig);
	}else if( ikesa->auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ){
  	rhp_ikev2_g_statistics_inc(ikesa_auth_psk);
	}


	ikesa->established_time = _rhp_get_time();
	ikesa->expire_hard = ikesa->established_time + ikesa_lifetime_hard;
	ikesa->expire_soft = ikesa->established_time + ikesa_lifetime_soft;


	ikesa->timers->start_lifetime_timer(vpn,ikesa,ikesa_lifetime_soft,1);

	if( dpd_enabled ){

		ikesa->timers->start_keep_alive_timer(vpn,ikesa,keep_alive_interval);

		vpn->v1.dpd_enabled = 1;
	}

	ikesa->timers->start_nat_t_keep_alive_timer(vpn,ikesa,nat_t_keep_alive_interval);


	rhp_ikev1_rx_r_set_p2_iv(vpn,ikesa,rx_ikemesg);


  ikesa->busy_flag = 0;


  if( !is_rekeyed ){

		vpn->auto_reconnect_retries = 0;

		vpn->start_vpn_conn_life_timer(vpn);


		rhp_http_bus_broadcast_async(vpn->vpn_realm_id,1,1,
				rhp_ui_http_vpn_established_serialize,
				rhp_ui_http_vpn_bus_btx_async_cleanup,(void*)rhp_vpn_hold_ref(vpn)); // (*x*)


		if( vpn->internal_net_info.static_peer_addr ){

			rhp_vpn_internal_route_update(vpn);
		}

		err = 0;

  }else{

		err = RHP_STATUS_IKEV2_MESG_HANDLER_END;
  }

	vpn->established = 1;

	if( vpn->connecting ){
		vpn->connecting = 0;
		rhp_ikesa_half_open_sessions_dec();
	}

error:
	RHP_TRC(0,RHPTRCID_IKEV1_RX_R_COMP_RTRN,"xxxppE",vpn,ikesa,rx_ikemesg,ikesa->v1.p2_iv_material_len,ikesa->v1.p2_iv_material,ikesa->keys.v1.iv_len,ikesa->keys.v1.p1_iv_rx_last_blk,err);

	return err;
}

int rhp_ikev1_rx_r_comp_xauth(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_vpn_realm* rlm,
			rhp_ikev2_mesg* rx_ikemesg)
{
	RHP_TRC(0,RHPTRCID_IKEV1_RX_R_COMP_XAUTH,"xxxdxp",vpn,ikesa,rlm,rlm->encap_mode_c,rx_ikemesg,rx_ikemesg->v1_p2_iv_len,rx_ikemesg->v1_p2_rx_last_blk);

	rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_XAUTH_PEND_R);

  ikesa->timers->start_lifetime_timer(vpn,ikesa,(time_t)rlm->ikesa.lifetime_eap_larval,1);

	rhp_ikev1_rx_r_set_p2_iv(vpn,ikesa,rx_ikemesg);

  ikesa->busy_flag = 0;

  // [TODO] IKE SA's rekeying for a XAUTH responder. Currently, it
  //        is expected to be initiated by XAUTH initiator (remote client).
  ikesa->v1.dont_rekey = 1;

	RHP_TRC(0,RHPTRCID_IKEV1_RX_R_COMP_XAUTH_RTRN,"xxxppd",vpn,ikesa,rx_ikemesg,ikesa->v1.p2_iv_material_len,ikesa->v1.p2_iv_material,ikesa->keys.v1.iv_len,ikesa->keys.v1.p1_iv_rx_last_blk,ikesa->v1.dont_rekey);

	return 0;
}

static int _rhp_ikev1_rx_main_r_5_psk(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_ikemesg,
		rhp_ikev2_mesg* tx_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_ikev1_auth_srch_plds_ctx* s_pld_ctx = NULL;
  u8* hash_octets = NULL;
  int hash_octets_len = 0;
  rhp_vpn_realm* rlm = NULL;
  int is_rekeyed = 0;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_PSK,"xxxxd",rx_ikemesg,tx_ikemesg,vpn,ikesa,rx_ikemesg->decrypted);

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
      RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_PSK_ENUM_HASH_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_MAIN_R_5_PSK_PARSE_HASH_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
  }

  {
  	s_pld_ctx->dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_ID),
  			rhp_ikev1_auth_srch_id_cb,s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_PSK_ENUM_ID_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_MAIN_R_5_PSK_PARSE_ID_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
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
      RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_PSK_ENUM_N_PLDS_ERR,"xxd",rx_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_MAIN_R_5_PSK_PARSE_N_PAYLOADS_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }

    err = 0;
  }

  {
  	int peer_id_bin_len
  		= ntohs(s_pld_ctx->peer_id_payload->payloadh->len) - sizeof(rhp_proto_ike_payload);
  	u8* peer_id_bin = (u8*)(s_pld_ctx->peer_id_payload->payloadh + 1);

  	err = rhp_ikev1_p1_gen_hash_ir(RHP_IKE_INITIATOR,ikesa,
  					peer_id_bin_len,peer_id_bin,
  					s_pld_ctx->peer_id_type,s_pld_ctx->peer_id_len,s_pld_ctx->peer_id,
						ikesa->keys.v1.skeyid_len,ikesa->keys.v1.skeyid,
						&hash_octets,&hash_octets_len);

  	if( err ){
  		goto error;
  	}

  	if( s_pld_ctx->hash_len != hash_octets_len ||
  			memcmp(s_pld_ctx->hash,hash_octets,hash_octets_len) ){
  		err = RHP_STATUS_IKEV1_MAIN_INVALID_HASH_PLD;
      RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_PSK_INVALID_HASH_PLD_ERR,"xxpp",rx_ikemesg,ikesa,s_pld_ctx->hash_len,s_pld_ctx->hash,hash_octets_len,hash_octets);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_MAIN_R_5_PSK_INVALID_HASH_PAYLOAD_VALUE,"KVPE",rx_ikemesg,vpn,ikesa,err);
  		goto error;
  	}
  }


  err = rhp_ikev2_id_setup(s_pld_ctx->peer_id_type,
  				s_pld_ctx->peer_id,s_pld_ctx->peer_id_len,&(vpn->peer_id));
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  {
    rlm = rhp_realm_get(vpn->v1.def_realm_id);
		if( rlm == NULL ){
			RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_PSK_NO_REALM,"xx",vpn,ikesa);
			goto error;
		}

		RHP_LOCK(&(rlm->lock));

		if( !_rhp_atomic_read(&(rlm->is_active)) ){
			RHP_UNLOCK(&(rlm->lock));
			RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_PSK_REALM_NOT_ACTIVE,"xxx",vpn,ikesa,rlm);
			goto error;
		}

		err = vpn->check_cfg_address(vpn,rlm,rx_ikemesg->rx_pkt);
		if( err ){

			RHP_UNLOCK(&(rlm->lock));

			RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_PSK_CHECK_CFG_ADDR_ERR,"xxxxE",rx_ikemesg,rx_ikemesg->rx_pkt,vpn,rlm,err);

			rhp_ikev2_g_statistics_inc(rx_ikev1_req_unknown_if_err_packets);

			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->v1.def_realm_id,RHP_LOG_ID_RX_IKEV1_MAIN_R_5_PSK_IKE_PKT_VIA_UNCONFIGURED_IF,"KVi",rx_ikemesg,vpn,rx_ikemesg->rx_pkt->rx_if_index);

			err = RHP_STATUS_INVALID_IKEV2_MESG_CHECK_CFG_ADDR_ERR;
			goto error;
		}

		RHP_UNLOCK(&(rlm->lock));
  }


  if( vpn->eap.role == RHP_EAP_DISABLED ){

		err = rhp_ikev1_r_clear_old_vpn(vpn,&ikesa,
						s_pld_ctx->rx_initial_contact,&is_rekeyed);
		if( err ){
			goto error;
		}
  }


  RHP_LOCK(&(rlm->lock));

  err = _rhp_ikev1_new_pkt_main_r_6_psk(vpn,ikesa,rlm,tx_ikemesg);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_PSK_ALLOC_IKEMSG_ERR,"xx",ikesa,rlm);
	  RHP_UNLOCK(&(rlm->lock));
    goto error;
  }


	err = rhp_ikev2_ike_auth_setup_larval_vpn(vpn,rlm,ikesa);
	if( err ){
		RHP_UNLOCK(&(rlm->lock));
		goto error;
	}


  if( vpn->eap.role == RHP_EAP_DISABLED || is_rekeyed ){

		//
		// [CAUTION] err is this func's return value. (*1)
		//
		err = rhp_ikev1_rx_r_comp(vpn,ikesa,rlm,rx_ikemesg,is_rekeyed);
		if( err && err != RHP_STATUS_IKEV2_MESG_HANDLER_END ){
			RHP_UNLOCK(&(rlm->lock));
			goto error;
		}


  }else if( vpn->eap.role == RHP_EAP_AUTHENTICATOR ){

  	if( ikesa->prop.v1.xauth_method == RHP_PROTO_IKE_AUTHMETHOD_HYBRID_INIT_RSASIG ){
  		err = -EINVAL;
  		RHP_BUG("");
			RHP_UNLOCK(&(rlm->lock));
			goto error;
  	}


  	err = rhp_ikev1_rx_r_comp_xauth(vpn,ikesa,rlm,rx_ikemesg);
		if( err ){
			RHP_UNLOCK(&(rlm->lock));
			goto error;
		}


		err = rhp_ikev1_xauth_r_invoke_task(vpn,ikesa,rx_ikemesg);
		if( err ){
			RHP_UNLOCK(&(rlm->lock));
			goto error;
		}

		err = RHP_STATUS_IKEV2_MESG_HANDLER_END;

  }else{

  	RHP_BUG("%d,%d",vpn->eap.role,is_rekeyed);
  }


  tx_ikemesg->v1_set_retrans_resp = 1;


  RHP_UNLOCK(&(rlm->lock));
  rhp_realm_unhold(rlm);

  _rhp_free(hash_octets);

  rhp_ikev1_auth_free_srch_ctx(s_pld_ctx);

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_R_5_PSK_OK,"KVP",rx_ikemesg,vpn,ikesa);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_PSK_RTRN,"xxxE",rx_ikemesg,vpn,ikesa,err);
  return err; // (*1)

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_R_5_PSK_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
  if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
  }

  if( hash_octets ){
  	_rhp_free(hash_octets);
  }
  if( rlm ){
    rhp_realm_unhold(rlm);
  }
  if( s_pld_ctx ){
  	rhp_ikev1_auth_free_srch_ctx(s_pld_ctx);
  }
  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_PSK_ERR,"xxx",rx_ikemesg,vpn,ikesa);
  return err;
}

static int _rhp_ikev1_rx_main_r_5_rsasig(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_ikemesg,
		rhp_ikev2_mesg* tx_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_ikev1_auth_srch_plds_ctx* s_pld_ctx = NULL;
  rhp_vpn_realm* rlm = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_RSASIG,"xxxxddd",rx_ikemesg,tx_ikemesg,vpn,ikesa,rx_ikemesg->decrypted,ikesa->prop.v1.auth_method,ikesa->prop.v1.xauth_method);

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
  					rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_CR),
  					rhp_ikev1_srch_cert_req_cb_2,s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
      RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_ENUM_CERET_REQ_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_MAIN_R_5_PARSE_CERT_REQ_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
    err = 0;
  }


	if( ikesa->prop.v1.xauth_method != RHP_PROTO_IKE_AUTHMETHOD_HYBRID_INIT_RSASIG ){

		{
			s_pld_ctx->dup_flag = 0;

			err = rx_ikemesg->search_payloads(rx_ikemesg,0,
					rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_SIG),
					rhp_ikev1_auth_srch_sign_cb,s_pld_ctx);

			if( err && err != RHP_STATUS_ENUM_OK ){
				RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_RSASIG_ENUM_SIG_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
				RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_MAIN_R_5_RSASIG_PARSE_SIG_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
				err = RHP_STATUS_INVALID_MSG;
				goto error;
			}
		}

    {
    	s_pld_ctx->dup_flag = 0;

    	err = rx_ikemesg->search_payloads(rx_ikemesg,1,
      		rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_CERT),
      		rhp_ikev1_auth_srch_cert_cb,s_pld_ctx);

    	if( err && err != RHP_STATUS_ENUM_OK ){
    		RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_RSASIG_ENUM_CERT_ERR,"xxxE",rx_ikemesg,vpn,ikesa,err);
    		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_R_5_RSASIG_PARSE_CERT_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
        err = RHP_STATUS_INVALID_MSG;
    		goto error;
    	}
    }

	}else{

		if( ikesa->prop.v1.auth_method != RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){
      RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_RSASIG_HYBRID_RSASIG_NOT_P1_RSASIG,"xxd",rx_ikemesg,ikesa,ikesa->prop.v1.auth_method);
      err = -EINVAL;
      goto error;
		}

  	s_pld_ctx->dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  					rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_HASH),
  					rhp_ikev1_auth_srch_hash_cb,s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_RSASIG_ENUM_HASH_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_MAIN_R_5_HYBRID_AUTH_RSASIG_PARSE_HASH_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
  }


  {
  	s_pld_ctx->dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_ID),
  			rhp_ikev1_auth_srch_id_cb,s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_RSASIG_ENUM_ID_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_MAIN_R_5_RSASIG_PARSE_ID_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
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
      RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_RSASIG_ENUM_N_PLDS_ERR,"xxd",rx_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_MAIN_R_5_RSASIG_PARSE_N_PAYLOADS_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }

    err = 0;
  }

  if( vpn->peer_is_rockhopper ){

  	s_pld_ctx->dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_n_mesg_id,(void*)((unsigned long)RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_REALM_ID),
  			rhp_ikev1_auth_srch_n_realm_id_cb,s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_R_5_RSASIG_PARSE_N_REALM_ID_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
  		RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_RSASIG_REALM_ID_PARSE_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);
      err = RHP_STATUS_INVALID_MSG;
    	goto error;
  	}
  	err = 0;
  }


  err = rhp_ikev2_id_setup(s_pld_ctx->peer_id_type,s_pld_ctx->peer_id,s_pld_ctx->peer_id_len,&(vpn->peer_id));
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }


	if( ikesa->prop.v1.xauth_method == RHP_PROTO_IKE_AUTHMETHOD_HYBRID_INIT_RSASIG ){

		err = rhp_ikev1_hybrid_auth_rsasig_verify_hash(rx_ikemesg,vpn,ikesa,s_pld_ctx);
		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_RSASIG_HYBRID_AUTH_VERIFY_HASH_ERR,"xxxE",rx_ikemesg,vpn,ikesa,err);
			goto error;
		}
	}


  {
    rlm = rhp_realm_get(vpn->v1.def_realm_id);
		if( rlm == NULL ){
			RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_RSASIG_NO_REALM,"xxx",rx_ikemesg,vpn,ikesa);
			goto error;
		}

		RHP_LOCK(&(rlm->lock));

		if( !_rhp_atomic_read(&(rlm->is_active)) ){
			RHP_UNLOCK(&(rlm->lock));
			RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_RSASIG_REALM_NOT_ACTIVE,"xxxx",rx_ikemesg,vpn,ikesa,rlm);
			goto error;
		}

		err = vpn->check_cfg_address(vpn,rlm,rx_ikemesg->rx_pkt);
		if( err ){

			RHP_UNLOCK(&(rlm->lock));

			RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_RSASIG_CHECK_CFG_ADDR_ERR,"xxxxE",rx_ikemesg,rx_ikemesg->rx_pkt,vpn,rlm,err);

			rhp_ikev2_g_statistics_inc(rx_ikev1_req_unknown_if_err_packets);

			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->v1.def_realm_id,RHP_LOG_ID_RX_IKEV1_MAIN_R_5_PSK_IKE_PKT_VIA_UNCONFIGURED_IF,"KVi",rx_ikemesg,vpn,rx_ikemesg->rx_pkt->rx_if_index);

			err = RHP_STATUS_INVALID_IKEV2_MESG_CHECK_CFG_ADDR_ERR;
			goto error;
		}

		RHP_UNLOCK(&(rlm->lock));
  }


  if( !rhp_gcfg_dont_search_cfg_peers_for_realm_id &&
  		s_pld_ctx->peer_notified_realm_id == RHP_VPN_REALM_ID_UNKNOWN ){

  	s_pld_ctx->peer_id_tmp = &(vpn->peer_id);

  	rhp_ikev2_id_dump("auth_req_search_rlm_cand",s_pld_ctx->peer_id_tmp);

  	rhp_realm_enum(0,_rhp_ikev1_auth_search_rlm_cand,(void*)s_pld_ctx);

    RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_RSASIG_SEARCH_RLM_CAND,"xxxu",rx_ikemesg,vpn,ikesa,s_pld_ctx->peer_notified_realm_id);

  	s_pld_ctx->peer_id_tmp = NULL;
  }


  ikesa->v1.rx_initial_contact = s_pld_ctx->rx_initial_contact;


  err = rhp_ikev1_ipc_rsasig_create_verify_and_sign_req(vpn,ikesa,s_pld_ctx,
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

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_RSASIG_RTRN,"xxxE",rx_ikemesg,vpn,ikesa,err);

  return RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_R_5_RSASIG_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);

	if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
  }

  if( rlm ){
    rhp_realm_unhold(rlm);
  }
  if( s_pld_ctx ){
  	rhp_ikev1_auth_free_srch_ctx(s_pld_ctx);
  }
  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_R_5_RSASIG_ERR,"xxx",rx_ikemesg,vpn,ikesa);
  return err;
}

static int _rhp_ikev1_rx_main_i_6_psk(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_ikemesg,
		rhp_ikev2_mesg* tx_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_ikev1_auth_srch_plds_ctx* s_pld_ctx = NULL;
  u8* hash_octets = NULL;
  int hash_octets_len = 0;
  rhp_vpn_realm* rlm = NULL;
  int is_rekeyed = (ikesa->v1.tx_initial_contact ? 0 : 1);


  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_6_PSK,"xxxxddd",rx_ikemesg,tx_ikemesg,vpn,ikesa,rx_ikemesg->decrypted,ikesa->v1.tx_initial_contact,is_rekeyed);

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

  {
		ikesa->timers->quit_retransmit_timer(vpn,ikesa);

		if( ikesa->req_retx_ikemesg ){

			ikesa->set_retrans_request(ikesa,NULL);

			rhp_ikev2_unhold_mesg(ikesa->req_retx_ikemesg);
			ikesa->req_retx_ikemesg = NULL;
		}
  }


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
      RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_6_PSK_ENUM_HASH_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_MAIN_I_6_PSK_PARSE_HASH_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
      err = 0; // This may be a delayed retransmitted response. Just ignored.
      rx_ikemesg->v1_ignored = 1;
      goto error;
    }
  }

  {
  	s_pld_ctx->dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  					rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_ID),
  					rhp_ikev1_auth_srch_id_cb,s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_6_PSK_ENUM_ID_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_MAIN_I_6_PSK_PARSE_ID_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
      goto error;
    }

    //
    // For IKEv1 PSK, only IP-address ID-type is allowed and it
    // is "already" handled by decrypting this IKEv1 mesg itself.
    //
  }


  {
  	int peer_id_bin_len
  		= ntohs(s_pld_ctx->peer_id_payload->payloadh->len) - sizeof(rhp_proto_ike_payload);
  	u8* peer_id_bin = (u8*)(s_pld_ctx->peer_id_payload->payloadh + 1);

  	err = rhp_ikev1_p1_gen_hash_ir(RHP_IKE_RESPONDER,ikesa,
  					peer_id_bin_len,peer_id_bin,
  					s_pld_ctx->peer_id_type,s_pld_ctx->peer_id_len,s_pld_ctx->peer_id,
						ikesa->keys.v1.skeyid_len,ikesa->keys.v1.skeyid,
						&hash_octets,&hash_octets_len);

  	if( err ){
  		goto error;
  	}

  	if( s_pld_ctx->hash_len != hash_octets_len ||
  			memcmp(s_pld_ctx->hash,hash_octets,hash_octets_len) ){
  		err = RHP_STATUS_IKEV1_MAIN_INVALID_HASH_PLD;
      RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_6_PSK_INVALID_HASH_PLD_ERR,"xxpp",rx_ikemesg,ikesa,s_pld_ctx->hash_len,s_pld_ctx->hash,hash_octets_len,hash_octets);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_MAIN_I_6_PSK_INVALID_HASH_PAYLOAD_VALUE,"KVPE",rx_ikemesg,vpn,ikesa,err);
  		goto error;
  	}
  }



  rlm = vpn->rlm;
  if( rlm == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_6_PSK_NO_REALM,"xx",vpn,ikesa);
    goto error;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_6_PSK_REALM_NOT_ACTIVE,"xxx",vpn,ikesa,rlm);
    goto error_l_rlm;
  }


  err = rhp_ikev1_rx_i_comp(vpn,ikesa,rlm,rx_ikemesg,tx_ikemesg,is_rekeyed);
  if( err ){
    goto error_l_rlm;
  }


  RHP_UNLOCK(&(rlm->lock));


  _rhp_free(hash_octets);
  rhp_ikev1_auth_free_srch_ctx(s_pld_ctx);

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_I_6_PSK_OK,"KVP",rx_ikemesg,vpn,ikesa);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_6_PSK_RTRN,"xxxd",rx_ikemesg,vpn,ikesa,is_rekeyed);
  return 0;


error_l_rlm:
  RHP_UNLOCK(&(rlm->lock));
error:
	if( err ){

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_I_6_PSK_ERR,"KVE",rx_ikemesg,vpn,err);

		if( ikesa ){
			rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_DELETE_WAIT);
			ikesa->timers->schedule_delete(vpn,ikesa,0);
		}

		rhp_ikev2_g_statistics_inc(ikesa_auth_errors);
	}

  if( hash_octets ){
  	_rhp_free(hash_octets);
  }
  if( s_pld_ctx ){
  	rhp_ikev1_auth_free_srch_ctx(s_pld_ctx);
  }
  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_6_PSK_ERR,"xxxE",rx_ikemesg,vpn,ikesa,err);
  return err;
}

static int _rhp_ikev1_rx_main_i_6_rsasig(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_ikemesg,
		rhp_ikev2_mesg* tx_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_ikev1_auth_srch_plds_ctx* s_pld_ctx = NULL;
  rhp_vpn_realm* rlm = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_6_RSASIG,"xxxxd",rx_ikemesg,tx_ikemesg,vpn,ikesa,rx_ikemesg->decrypted);

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

  {
		ikesa->timers->quit_retransmit_timer(vpn,ikesa);

		if( ikesa->req_retx_ikemesg ){

			ikesa->set_retrans_request(ikesa,NULL);

			rhp_ikev2_unhold_mesg(ikesa->req_retx_ikemesg);
			ikesa->req_retx_ikemesg = NULL;
		}
  }


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
      RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_6_RSASIG_ENUM_HASH_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_MAIN_I_6_RSASIG_PARSE_HASH_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
  	err = 0;
  }

  {
  	s_pld_ctx->dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  					rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_ID),
  					rhp_ikev1_auth_srch_id_cb,s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_6_RSASIG_ENUM_ID_PLD_ERR,"xxd",rx_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV1_MAIN_I_6_RSASIG_PARSE_ID_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
  	err = 0;


    if( vpn->peer_id.type != RHP_PROTO_IKE_ID_ANY ){

			if( rhp_ikev2_id_cmp_by_value(&(vpn->peer_id),
						s_pld_ctx->peer_id_type,s_pld_ctx->peer_id_len,s_pld_ctx->peer_id) ){
				err = RHP_STATUS_INVALID_MSG;
				RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_6_RSASIG_ENUM_ID_PLD_ERR_INVALILD_RESP_ID_1,"xxxd",rx_ikemesg,vpn,ikesa,err);
				RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_I_6_RSASIG_ID_PAYLOAD_INVALID_PEER_ID,"KVPE",rx_ikemesg,vpn,ikesa,err);
				goto error;
			}

    }else{

    	// (e.g.) DMVPN: Spoke-to-Spoke tunnel

    	err = rhp_ikev2_id_setup(s_pld_ctx->peer_id_type,s_pld_ctx->peer_id,
    			s_pld_ctx->peer_id_len,&(vpn->peer_id));
    	if( err ){
				RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_6_RSASIG_ENUM_ID_PLD_ERR_INVALILD_RESP_ID_2,"xxxd",rx_ikemesg,vpn,ikesa,err);
				RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_I_6_RSASIG_ID_PAYLOAD_INVALID_PEER_ID,"KVPE",rx_ikemesg,vpn,ikesa,err);
				goto error;
    	}
    }
  }

  {
  	s_pld_ctx->dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,1,
    				rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_CERT),
    				rhp_ikev1_auth_srch_cert_cb,s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK ){
  		RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_6_RSASIG_ENUM_CERT_ERR,"xxxE",rx_ikemesg,vpn,ikesa,err);
  		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_I_6_RSASIG_PARSE_CERT_PAYLOAD_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
  		goto error;
  	}
  	err = 0;
  }


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

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_6_RSASIG_RTRN,"xxxE",rx_ikemesg,vpn,ikesa,err);

  return RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_I_6_RSASIG_ERR,"KVPE",rx_ikemesg,vpn,ikesa,err);

	if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
  }

  if( rlm ){
    rhp_realm_unhold(rlm);
  }
  if( s_pld_ctx ){
  	rhp_ikev1_auth_free_srch_ctx(s_pld_ctx);
  }
  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_I_6_RSASIG_ERR,"xxx",rx_ikemesg,vpn,ikesa);
  return err;
}


int rhp_ikev1_rx_main_no_vpn(rhp_ikev2_mesg* rx_ikemesg,
		rhp_ikev2_mesg* tx_ikemesg,rhp_vpn** vpn_i,int* my_ikesa_side_i,u8* my_ikesa_spi_i)
{
	int err = -EINVAL;
	u8 exchange_type = rx_ikemesg->get_exchange_type(rx_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_NO_VPN,"xxLb",rx_ikemesg,tx_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

	if( exchange_type != RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ){
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_NO_VPN_NOT_MAIN_EXCHG,"xLb",rx_ikemesg,"PROTO_IKE_EXCHG",exchange_type);
		return 0;
	}

	if( *vpn_i || *my_ikesa_side_i != -1 ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

	err = _rhp_ikev1_rx_main_r_1(rx_ikemesg,tx_ikemesg,vpn_i,my_ikesa_side_i,my_ikesa_spi_i);

error:
	if( !err ){
		RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_NO_VPN_RTRN,"xxxLdG",rx_ikemesg,tx_ikemesg,*vpn_i,"IKE_SIDE",*my_ikesa_side_i,my_ikesa_spi_i);
	}else{
		RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_NO_VPN_ERR,"xxxE",rx_ikemesg,tx_ikemesg,err);
	}
  return err;
}

int rhp_ikev1_rx_main(rhp_ikev2_mesg* rx_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_ikemesg->get_exchange_type(rx_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN,"xxLdGxLb",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

	if( exchange_type != RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ){
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_NOT_MAIN_EXCHG,"xxLb",rx_ikemesg,vpn,"PROTO_IKE_EXCHG",exchange_type);
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
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_NO_IKESA,"xxLdG",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
		goto error;
	}

  if( ikesa->state == RHP_IKESA_STAT_V1_MAIN_1ST_SENT_I ){

  	err = _rhp_ikev1_rx_main_i_2(vpn,ikesa,rx_ikemesg,tx_ikemesg);

  }else if( ikesa->state == RHP_IKESA_STAT_V1_MAIN_2ND_SENT_R ){

  	err = _rhp_ikev1_rx_main_r_3(vpn,ikesa,rx_ikemesg,tx_ikemesg);

  }else if( ikesa->state == RHP_IKESA_STAT_V1_MAIN_3RD_SENT_I ){

  	err = _rhp_ikev1_rx_main_i_4(vpn,ikesa,rx_ikemesg,tx_ikemesg);

  }else if( ikesa->state == RHP_IKESA_STAT_V1_MAIN_4TH_SENT_R ){

  	if( ikesa->prop.v1.auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){

  		err = _rhp_ikev1_rx_main_r_5_rsasig(vpn,ikesa,rx_ikemesg,tx_ikemesg);

  	}else if( ikesa->prop.v1.auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ){

  		err = _rhp_ikev1_rx_main_r_5_psk(vpn,ikesa,rx_ikemesg,tx_ikemesg);
  	}

  }else if( ikesa->state == RHP_IKESA_STAT_V1_MAIN_5TH_SENT_I ){

  	if( ikesa->prop.v1.auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){

  		err = _rhp_ikev1_rx_main_i_6_rsasig(vpn,ikesa,rx_ikemesg,tx_ikemesg);

  	}else if( ikesa->prop.v1.auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ){

  		err = _rhp_ikev1_rx_main_i_6_psk(vpn,ikesa,rx_ikemesg,tx_ikemesg);
  	}

  }else{

  	err = -EINVAL;
  	goto error;
  }

error:
	RHP_TRC(0,RHPTRCID_IKEV1_RX_MAIN_RTRN,"xxxE",rx_ikemesg,vpn,tx_ikemesg,err);
  return err;
}


void rhp_ikev1_main_ipc_psk_skeyid_rep_handler(rhp_ipcmsg** ipcmsg_c)
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

  RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_PSK_SKEYID_REP_HANDLER,"x",ipcmsg);

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
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_PSK_SKEYID_REP_HANDLER_NO_VPN,"xLdG",ipcmsg,"IKE_SIDE",psk_rep->side,psk_rep->spi);
    goto error;
  }

  RHP_LOCK(&(vpn->lock));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_PSK_SKEYID_REP_HANDLER_VPN_NOT_ACTIVE,"xx",ipcmsg,ikesa);
    goto error_l;
  }

  ikesa = vpn->ikesa_get(vpn,psk_rep->side,psk_rep->spi);
  if( ikesa == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_PSK_SKEYID_REP_HANDLER_NO_IKESA,"x",ipcmsg);
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
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_PSK_SKEYID_REP_HANDLER_IKESA_BAD_TXNID,"xxxqq",ipcmsg,vpn,ikesa,psk_rep->txn_id,ikesa->ipc_txn_id);
    goto error_l;
  }

  if( psk_rep->result == 0 ){
  	RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_PSK_SKEYID_REP_HANDLER_RESULT_ERR,"xxx",ipcmsg,vpn,ikesa);
  	goto error_l;
  }


  if( vpn->eap.role == RHP_EAP_DISABLED ){

		if( psk_rep->eap_role == RHP_EAP_AUTHENTICATOR ){

			if( vpn->origin_side != RHP_IKE_RESPONDER || ikesa->side != RHP_IKE_RESPONDER ){
				RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_PSK_SKEYID_REP_HANDLER_INVALID_XAUTH_SIDE_1,"xxxLdLd",ipcmsg,vpn,ikesa,"IKE_SIDE",vpn->origin_side,"IKE_SIDE",ikesa->side);
				goto error_l;
			}

			vpn->eap.role = RHP_EAP_AUTHENTICATOR;
			vpn->eap.eap_method = vpn->eap.peer_id.method = psk_rep->eap_method;

		}else if( psk_rep->eap_role == RHP_EAP_SUPPLICANT ){

			if( vpn->origin_side != RHP_IKE_INITIATOR || ikesa->side != RHP_IKE_INITIATOR ){
				RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_PSK_SKEYID_REP_HANDLER_INVALID_XAUTH_SIDE_2,"xxxLdLd",ipcmsg,vpn,ikesa,"IKE_SIDE",vpn->origin_side,"IKE_SIDE",ikesa->side);
				goto error_l;
			}

		}else if( psk_rep->eap_role == RHP_EAP_DISABLED ){

			vpn->eap.role = RHP_EAP_DISABLED;

		}else{
			RHP_BUG("%d",psk_rep->eap_role);
			goto error_l;
		}

  }else{

  	if( vpn->eap.role != (int)psk_rep->eap_role ){
  		RHP_BUG("%d,%d",psk_rep->eap_role,vpn->eap.role);
  	}

  	RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_PSK_SKEYID_REP_HANDLER_XAUTH_SIDE_RESOLVED,"xxxLdLd",ipcmsg,vpn,ikesa,"EAP_ROLE",vpn->eap.role,"EAP_ROLE",psk_rep->eap_role);
  }


	rlm = rhp_realm_get(psk_rep->my_realm_id);
  if( rlm == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_PSK_SKEYID_REP_HANDLER_NO_REALM,"xx",ipcmsg,ikesa);
    goto error_l;
  }

  RHP_LOCK(&(rlm->lock));

  if( vpn->rlm && rlm != vpn->rlm ){
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_PSK_SKEYID_REP_HANDLER_INVALID_REALM_ID,"xxuu",ipcmsg,ikesa,psk_rep->my_realm_id,vpn->rlm->id);
    goto error_l2;
  }

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_PSK_SKEYID_REP_HANDLER_REALM_NOT_ACTIVE,"xxxxu",ipcmsg,vpn,ikesa,rlm,rlm->id);
    goto error_l2;
  }


	if( ikesa->side == RHP_IKE_INITIATOR ){

		err = _rhp_ikev1_new_pkt_main_i_5_psk(vpn,ikesa,rlm,psk_rep,tx_ikemesg);

	}else{ // RESPONDER

		err = _rhp_ikev1_new_pkt_main_r_4(ikesa,tx_ikemesg);
	}
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_PSK_SKEYID_REP_HANDLER_ALLOC_IKEMSG_ERR,"xxxxuE",ipcmsg,vpn,ikesa,rlm,rlm->id,err);
    goto error_l2;
  }

  RHP_UNLOCK(&(rlm->lock));
  rhp_realm_unhold(rlm);
  rlm = NULL;


  {
  	u8* skeyid = (u8*)(psk_rep + 1);

		err = ikesa->dh->compute_key(ikesa->dh);
		if( err ){
			RHP_BUG("%d",err);
			goto error_l;
		}

		err = ikesa->generate_keys_v1(ikesa,psk_rep->skeyid_len,skeyid);
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

	if( ikesa->side == RHP_IKE_INITIATOR ){

	  tx_ikemesg->v1_start_retx_timer = 1;

		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_MAIN_5TH_SENT_I);
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_I_4_PSK_OK,"KVP",rx_ikemesg,vpn,ikesa);

	}else{ // RESPONDER

	  tx_ikemesg->v1_dont_enc = 1;

		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_MAIN_4TH_SENT_R);
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_R_3_PSK_OK,"KVP",rx_ikemesg,vpn,ikesa);
	}

  ikesa->busy_flag = 0;


  rhp_ikev1_call_next_rx_mesg_handlers(rx_ikemesg,vpn,
  		psk_rep->side,psk_rep->spi,tx_ikemesg,RHP_IKEV1_MESG_HANDLER_P1_MAIN);

  rhp_ikev2_unhold_mesg(tx_ikemesg);
  rhp_ikev2_unhold_mesg(rx_ikemesg);

  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

  _rhp_free_zero(*ipcmsg_c,(*ipcmsg_c)->len);
  *ipcmsg_c = NULL;

	RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_PSK_SKEYID_REP_HANDLER_RTRN,"xxxx",ipcmsg,vpn,ikesa,rlm);
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
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_SKEYID_ERR,"VE",vpn,err);
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

  RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_PSK_SKEYID_REP_HANDLER_ERR,"xxxxE",ipcmsg,vpn,ikesa,rlm,err);
  return;
}

void rhp_ikev1_main_ipc_rsasig_sign_rep_handler(rhp_ipcmsg** ipcmsg_c)
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

  RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_SIGN_REP_HANDLER,"x",ipcmsg);

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
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_SIGN_REP_HANDLER_NO_VPN,"xLdG",ipcmsg,"IKE_SIDE",rsasig_sign_rep->side,rsasig_sign_rep->spi);
    goto error;
  }

  RHP_LOCK(&(vpn->lock));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_SIGN_REP_HANDLER_VPN_NOT_ACTIVE,"xx",ipcmsg,ikesa);
    goto error_l;
  }

  ikesa = vpn->ikesa_get(vpn,rsasig_sign_rep->side,rsasig_sign_rep->spi);
  if( ikesa == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_SIGN_REP_HANDLER_NO_IKESA,"x",ipcmsg);
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
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_SIGN_REP_HANDLER_IKESA_BAD_TXNID,"xxxqq",ipcmsg,vpn,ikesa,rsasig_sign_rep->txn_id,ikesa->ipc_txn_id);
    goto error_l;
  }

  if( rsasig_sign_rep->result == 0 ){
  	RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_SIGN_REP_HANDLER_RESULT_ERR,"xxx",ipcmsg,vpn,ikesa);
  	goto error_l;
  }


	rlm = rhp_realm_get(rsasig_sign_rep->my_realm_id);
  if( rlm == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_SIGN_REP_HANDLER_NO_REALM,"xx",ipcmsg,ikesa);
    goto error_l;
  }


  RHP_LOCK(&(rlm->lock));

  if( vpn->rlm && rlm != vpn->rlm ){
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_SIGN_REP_HANDLER_INVALID_REALM_ID,"xxuu",ipcmsg,ikesa,rsasig_sign_rep->my_realm_id,vpn->rlm->id);
    goto error_l2;
  }

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_SIGN_REP_HANDLER_REALM_NOT_ACTIVE,"xxxxu",ipcmsg,vpn,ikesa,rlm,rlm->id);
    goto error_l2;
  }

  if( rsasig_sign_rep->my_realm_id != rlm->id ){
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_SIGN_REP_HANDLER_REALM_BAD_ID,"xxxxuu",ipcmsg,vpn,ikesa,rlm,rsasig_sign_rep->my_realm_id,rlm,rlm->id);
    goto error_l2;
  }

	vpn->eap.role = RHP_EAP_DISABLED;


	err = _rhp_ikev1_new_pkt_main_i_5_rsasig(vpn,ikesa,rlm,rsasig_sign_rep,tx_ikemesg);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_SIGN_REP_HANDLER_ALLOC_IKEMSG_ERR,"xxxxuE",ipcmsg,vpn,ikesa,rlm,rlm->id,err);
    goto error_l2;
  }

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


  tx_ikemesg->v1_start_retx_timer = 1;


	rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_MAIN_5TH_SENT_I);
	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_I_4_RSASIG_OK,"KVP",rx_ikemesg,vpn,ikesa);

  ikesa->busy_flag = 0;


  rhp_ikev1_call_next_rx_mesg_handlers(rx_ikemesg,vpn,
  		rsasig_sign_rep->side,rsasig_sign_rep->spi,tx_ikemesg,RHP_IKEV1_MESG_HANDLER_P1_MAIN);

  rhp_ikev2_unhold_mesg(tx_ikemesg);
  rhp_ikev2_unhold_mesg(rx_ikemesg);

  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

  _rhp_free_zero(*ipcmsg_c,(*ipcmsg_c)->len);
  *ipcmsg_c = NULL;

	RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_SIGN_REP_HANDLER_RTRN,"xxxx",ipcmsg,vpn,ikesa,rlm);
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
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_RSASIG_SIGN_ERR,"VE",vpn,err);
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

  RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_SIGN_REP_HANDLER_ERR,"xxxxE",ipcmsg,vpn,ikesa,rlm,err);
  return;
}

extern int rhp_ikev1_merge_larval_vpn(rhp_vpn* larval_vpn);

void rhp_ikev1_main_ipc_rsasig_verify_and_sign_rep_handler(rhp_ipcmsg** ipcmsg_c)
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


  RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER,"x",ipcmsg);

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
      RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_BAD_VERIFY_SPI,"xLdLdGG",ipcmsg,"IKE_SIDE",in_verify_rep->side,"IKE_SIDE",in_sign_rep->side,in_verify_rep->spi,in_sign_rep->spi);
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
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_LARVAL_VPN_NOT_FOUND,"xLdG",ipcmsg,"IKE_SIDE",in_verify_rep->side,in_verify_rep->spi);
    goto error;
  }


  RHP_LOCK(&(vpn->lock));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_IKESA_NOT_ACTIVE,"xxx",ipcmsg,vpn);
    goto error_vpn_l;
  }

  ikesa = vpn->ikesa_get(vpn,in_verify_rep->side,in_verify_rep->spi);
  if( ikesa == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_NO_IKESA,"xxLdG",ipcmsg,vpn,"IKE_SIDE",in_verify_rep->side,in_verify_rep->spi);
  	goto error_vpn_l;
  }

  rx_ikemesg = ikesa->pend_rx_ikemesg;
  ikesa->pend_rx_ikemesg = NULL;
  tx_ikemesg = ikesa->pend_tx_ikemesg;
  ikesa->pend_tx_ikemesg = NULL;

  if( rx_ikemesg == NULL || tx_ikemesg == NULL ){
  	RHP_BUG("");
  	goto error_vpn_l;
  }


  if( in_verify_rep->txn_id != ikesa->ipc_txn_id ){
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_REALM_BAD_ID,"xxxqq",ipcmsg,vpn,ikesa,in_verify_rep->txn_id,ikesa->ipc_txn_id);
    goto error_vpn_l;
  }

  if( !in_verify_rep->result ){
  	RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_VERIFY_RESULT_ERR,"xxx",ipcmsg,vpn,ikesa);
    goto error_vpn_l;
  }


  if( in_sign_rep == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_NO_SIGN_REP,"xxx",ipcmsg,vpn,ikesa);
    goto error_vpn_l;
  }

  if( in_sign_rep->txn_id != ikesa->ipc_txn_id ){
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_REALM_BAD_ID2,"xxxqq",ipcmsg,vpn,ikesa,in_sign_rep->txn_id,ikesa->ipc_txn_id);
    goto error_vpn_l;
  }

  if( !in_sign_rep->result ){
  	RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_SIGN_RESULT_ERR,"xxx",ipcmsg,vpn,ikesa);
  	goto error_vpn_l;
  }

  if( in_sign_rep->signed_octets_len == 0 ){
  	RHP_BUG("%d",in_sign_rep->signed_octets_len);
  	goto error_vpn_l;
  }

  if( in_verify_rep->my_realm_id != in_sign_rep->my_realm_id ){
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_REALM_BAD_ID_3,"xxxuu",ipcmsg,vpn,ikesa,in_sign_rep->my_realm_id,in_verify_rep->my_realm_id);
    goto error_vpn_l;
  }


  rlm = rhp_realm_get(in_verify_rep->my_realm_id);
  if( rlm == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_SIGN_REP_NO_REALM,"xxx",ipcmsg,vpn,ikesa);
    goto error_vpn_l;
  }



  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
	  RHP_UNLOCK(&(rlm->lock));
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_REALM_NOT_ACTIVE,"xxxx",ipcmsg,vpn,ikesa,rlm);
    goto error_vpn_l;
  }

  err = vpn->check_cfg_address(vpn,rlm,rx_ikemesg->rx_pkt); // Here, MOBIKE is NOT processed yet.
  if( err ){

    RHP_UNLOCK(&(rlm->lock));

  	RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_CHECK_CFG_ADDR_ERR,"xxxxE",rx_ikemesg,rx_ikemesg->rx_pkt,vpn,rlm,err);

  	rhp_ikev2_g_statistics_inc(rx_ikev1_req_unknown_if_err_packets);

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,in_verify_rep->my_realm_id,RHP_LOG_ID_RX_IKE_PKT_VIA_UNCONFIGURED_IF,"KVi",rx_ikemesg,vpn,rx_ikemesg->rx_pkt->rx_if_index);

  	err = RHP_STATUS_INVALID_IKEV2_MESG_CHECK_CFG_ADDR_ERR;
    goto error_vpn_l;
  }

  RHP_UNLOCK(&(rlm->lock));


	if( in_verify_rep->alt_peer_id_len ){

		err = rhp_ikev2_id_alt_setup(in_verify_rep->alt_peer_id_type,(void*)alt_id_p,
				in_verify_rep->alt_peer_id_len,&(vpn->peer_id));

		if( err ){
			RHP_BUG("");
	    goto error_vpn_l;
		}
	}


	rhp_ikev2_id_dump("rhp_ikev1_main_ipc_rsasig_verify_and_sign_rep_handler",&(vpn->peer_id));


  if( vpn->eap.role == RHP_EAP_DISABLED ){

		if( in_verify_rep->eap_role == RHP_EAP_AUTHENTICATOR ){

			if( vpn->origin_side != RHP_IKE_RESPONDER || ikesa->side != RHP_IKE_RESPONDER ){
				RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_INVALID_XAUTH_SIDE_1,"xxxLdLd",ipcmsg,vpn,ikesa,"IKE_SIDE",vpn->origin_side,"IKE_SIDE",ikesa->side);
				goto error_vpn_l;
			}

			vpn->eap.role = RHP_EAP_AUTHENTICATOR;
			vpn->eap.eap_method = vpn->eap.peer_id.method = in_verify_rep->eap_method;

		}else if( in_verify_rep->eap_role == RHP_EAP_SUPPLICANT ){

			if( vpn->origin_side != RHP_IKE_INITIATOR || ikesa->side != RHP_IKE_INITIATOR ){
				RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_INVALID_XAUTH_SIDE_2,"xxxLdLd",ipcmsg,vpn,ikesa,"IKE_SIDE",vpn->origin_side,"IKE_SIDE",ikesa->side);
				goto error_vpn_l;
			}

		}else if( in_verify_rep->eap_role == RHP_EAP_DISABLED ){

			vpn->eap.role = RHP_EAP_DISABLED;

		}else{
			RHP_BUG("%d",in_verify_rep->eap_role);
			goto error_vpn_l;
		}

  }else{

  	if( vpn->eap.role != (int)in_verify_rep->eap_role ){
  		RHP_BUG("%d,%d",in_verify_rep->eap_role,vpn->eap.role);
  	}

  	RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_XAUTH_SIDE_RESOLVED,"xxxLdLd",ipcmsg,vpn,ikesa,"EAP_ROLE",vpn->eap.role,"EAP_ROLE",in_verify_rep->eap_role);
  }


  if( vpn->eap.role == RHP_EAP_DISABLED ){

		err = rhp_ikev1_r_clear_old_vpn(vpn,&ikesa,
						ikesa->v1.rx_initial_contact,&is_rekeyed);
		if( err ){
			goto error_vpn_l;
		}
  }


  RHP_LOCK(&(rlm->lock));

  err = _rhp_ikev1_new_pkt_main_r_6_rsasig(vpn,ikesa,rlm,in_sign_rep,tx_ikemesg);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_ALLOC_IKEMSG_ERR,"xxxx",ipcmsg,ikesa,rlm,in_sign_rep);
	  RHP_UNLOCK(&(rlm->lock));
    goto error_vpn_l;
  }


	err = rhp_ikev2_ike_auth_setup_larval_vpn(vpn,rlm,ikesa);
	if( err ){
		RHP_UNLOCK(&(rlm->lock));
		goto error_vpn_l;
	}


  if( vpn->eap.role == RHP_EAP_DISABLED || is_rekeyed ){

		//
		// [CAUTION] err is this func's return value. (*1)
		//
		err = rhp_ikev1_rx_r_comp(vpn,ikesa,rlm,rx_ikemesg,is_rekeyed);
		if( err && err != RHP_STATUS_IKEV2_MESG_HANDLER_END ){
			RHP_UNLOCK(&(rlm->lock));
			goto error_vpn_l;
		}

  }else if( vpn->eap.role == RHP_EAP_AUTHENTICATOR ){

  	err = rhp_ikev1_rx_r_comp_xauth(vpn,ikesa,rlm,rx_ikemesg);
		if( err ){
			RHP_UNLOCK(&(rlm->lock));
			goto error_vpn_l;
		}

		err = rhp_ikev1_xauth_r_invoke_task(vpn,ikesa,rx_ikemesg);
		if( err ){
			RHP_UNLOCK(&(rlm->lock));
			goto error_vpn_l;
		}

  }else{

  	RHP_BUG("%d,%d",vpn->eap.role,is_rekeyed);
  }


  tx_ikemesg->v1_set_retrans_resp = 1;


  RHP_UNLOCK(&(rlm->lock));
  rhp_realm_unhold(rlm);


  RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_R_5_RSASIG_OK,"KVP",rx_ikemesg,vpn,ikesa);


	rhp_ikev1_call_next_rx_mesg_handlers(rx_ikemesg,vpn,
			in_verify_rep->side,in_verify_rep->spi,tx_ikemesg,RHP_IKEV1_MESG_HANDLER_P1_MAIN);


  if( rlm ){
    rhp_realm_unhold(rlm);
  }

  RHP_UNLOCK(&(vpn->lock));


	if( vpn->v1.merge_larval_vpn ){

		rhp_ikev1_merge_larval_vpn(vpn);
	}


  rhp_vpn_unhold(vpn_ref);

  rhp_ikev2_unhold_mesg(rx_ikemesg);
  rhp_ikev2_unhold_mesg(tx_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_RTRN,"xxx",ipcmsg,vpn,ikesa);
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
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_RSASIG_VERIFY_ERR,"KVE",rx_ikemesg,vpn,err);
	}else{
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_RSASIG_VERIFY_AND_SIGN_ERR,"KVE",rx_ikemesg,vpn,err);
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

  RHP_TRC(0,IKEV1_MAIN_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER_ERR,"xxxxxE",ipcmsg,vpn,vpn,ikesa,rlm,err);
  return;
}

void rhp_ikev1_main_ipc_rsasig_verify_rep_handler(rhp_ipcmsg** ipcmsg_c)
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
  int is_rekeyed;

  RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_REP_HANDLER,"x",ipcmsg);

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
  	RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_REP_HANDLER_NO_IKESA,"xLdG",ipcmsg,"IKE_SIDE",verify_rep->side,verify_rep->spi);
  	goto error;
  }


  RHP_LOCK(&(vpn->lock));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
  	RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_REP_HANDLER_IKESA_NOT_ACTIVE,"xx",ipcmsg,vpn);
  	goto error_l_vpn;
  }

  ikesa = vpn->ikesa_get(vpn,verify_rep->side,verify_rep->spi);

  if( ikesa == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_REP_HANDLER_NO_IKESA,"xx",ipcmsg,vpn);
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
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_REP_HANDLER_REALM_BAD_ID,"xxxxqq",ipcmsg,vpn,ikesa,rlm,verify_rep->txn_id,ikesa->ipc_txn_id);
    goto error_l_vpn;
  }

  rlm = vpn->rlm;
  if( rlm == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_REP_HANDLER_NO_REALM,"xxx",ipcmsg,vpn,ikesa);
    goto error_l_vpn;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_REP_HANDLER_REALM_NOT_ACTIVE,"xxxx",ipcmsg,vpn,ikesa,rlm);
    goto error_l_rlm_vpn;
  }

  if( verify_rep->result == 0 ){

    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_REP_HANDLER_RESULT_ERR,"xxxxu",ipcmsg,vpn,ikesa,rlm,rlm->id);

    goto error_l_rlm_vpn;
  }


  if( verify_rep->my_realm_id != rlm->id ){
    RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_REP_HANDLER_REALM_BAD_ID_2,"xxxxuu",ipcmsg,vpn,ikesa,rlm,verify_rep->my_realm_id,rlm->id);
    goto error_l_rlm_vpn;
  }


  is_rekeyed = (ikesa->v1.tx_initial_contact ? 0 : 1);


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
	    goto error_l_rlm_vpn;
		}
	}

	rhp_ikev2_id_dump("rhp_ikev1_main_ipc_rsasig_verify_rep_handler",&(vpn->peer_id));


  err = rhp_ikev1_rx_i_comp(vpn,ikesa,rlm,rx_ikemesg,tx_ikemesg,is_rekeyed);
  if( err ){
  	goto error_l_rlm_vpn;
  }


  RHP_UNLOCK(&(rlm->lock));


	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_I_6_RSASIG_OK,"KVP",rx_ikemesg,vpn,ikesa);


  rhp_ikev1_call_next_rx_mesg_handlers(rx_ikemesg,vpn,
  		verify_rep->side,verify_rep->spi,tx_ikemesg,RHP_IKEV1_MESG_HANDLER_P1_MAIN);

  rhp_ikev2_unhold_mesg(rx_ikemesg);
  rhp_ikev2_unhold_mesg(tx_ikemesg);

  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

  RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_REP_HANDLER_RTRN,"xxxx",ipcmsg,vpn,ikesa,rlm);
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
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_RSASIG_VERIFY_ERR,"VE",vpn,err);
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

  RHP_TRC(0,RHPTRCID_IKEV1_MAIN_IPC_RSASIG_VERIFY_REP_HANDLER_ERR,"xxxxE",ipcmsg,vpn,ikesa,rlm,err);
  return;
}
