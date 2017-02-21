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
#include "rhp_ikev2_mesg.h"
#include "rhp_vpn.h"
#include "rhp_ikev2.h"
#include "rhp_forward.h"
#include "rhp_eap.h"
#include "rhp_eap_sup_impl.h"
#include "rhp_eap_auth_impl.h"
#include "rhp_http.h"
#include "rhp_radius_impl.h"
#include "rhp_nhrp.h"


struct _rhp_ike_auth_srch_plds_ctx {

	u8 tag[4]; // '#ASR'

	rhp_vpn_ref* vpn_ref;
	rhp_ikesa* ikesa;
	rhp_vpn_realm* rlm;

	int dup_flag;

	rhp_ikev2_payload* n_error_payload;
  int n_err;

	rhp_ikev2_payload* id_i_payload;
	rhp_ikev2_payload* id_r_payload;
	rhp_ikev2_payload* auth_payload;

  int peer_auth_octets_len;
  int peer_auth_method;
  u8* peer_auth_octets;


  rhp_ikev2_payload* cert_payload_head;
  int cert_payload_num;

  rhp_ikev2_rx_cert_pld* peer_cert_pld;

  int ca_certs_der_num;
  int ca_certs_hash_url_num;
  rhp_ikev2_rx_cert_pld* ca_cert_plds_head;
  rhp_ikev2_rx_cert_pld* ca_cert_plds_tail;


  rhp_ikev2_payload* certreq_payload_head;
  int certreq_payload_num;

 	int initial_contact;

  int id_i_type; // RHP_PROTO_IKE_ID_PRIVATE_XXX may be assigned. Don't be u8.
  u8 *id_i;
  int id_i_len;
  u8 *id_i_impl;

  int id_r_type; // RHP_PROTO_IKE_ID_PRIVATE_XXX may be assigned. Don't be u8.
  u8 *id_r;
  int id_r_len;
  u8 *id_r_impl;

  int rx_no_nats_allowed_detected;
  int rx_no_nats_allowed;

  u16 notify_error;
  unsigned long notify_error_arg;


  rhp_ikev2_mesg* rx_ikemesg;
  rhp_ikev2_mesg* tx_ikemesg;

  int my_ikesa_side;
  u8 my_ikesa_spi[RHP_PROTO_IKE_SPI_SIZE];

  int my_id_type; // RHP_PROTO_IKE_ID_PRIVATE_XXX may be assigned. Don't be u8.
  int my_id_len;
  u8* my_id_val;

  int cert_urls_num;
  char** cert_urls;

  int eap_used;

  int http_cert_lookup_supported;

  unsigned long peer_notified_realm_id;
  rhp_ikev2_id* peer_id_tmp;

	rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload; // Don't free it. Just a reference.
};
typedef struct _rhp_ike_auth_srch_plds_ctx rhp_ike_auth_srch_plds_ctx;

static rhp_ike_auth_srch_plds_ctx* _rhp_ike_auth_alloc_srch_ctx()
{
	rhp_ike_auth_srch_plds_ctx* s_pld_ctx;

	s_pld_ctx = (rhp_ike_auth_srch_plds_ctx*)_rhp_malloc(sizeof(rhp_ike_auth_srch_plds_ctx));
	if( s_pld_ctx == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(s_pld_ctx,0,sizeof(rhp_ike_auth_srch_plds_ctx));

	s_pld_ctx->tag[0] = '#';
	s_pld_ctx->tag[1] = 'A';
	s_pld_ctx->tag[2] = 'S';
	s_pld_ctx->tag[3] = 'R';

	s_pld_ctx->peer_notified_realm_id = RHP_VPN_REALM_ID_UNKNOWN;

  RHP_TRC(0,RHPTRCID_IKE_AUTH_ALLOC_SRC_CTX,"x",s_pld_ctx);
	return s_pld_ctx;
}

static void _rhp_ike_auth_free_srch_ctx(rhp_ike_auth_srch_plds_ctx* s_pld_ctx)
{
  RHP_TRC(0,RHPTRCID_IKE_AUTH_FREE_SRC_CTX,"x",s_pld_ctx);

	if( s_pld_ctx ){

		rhp_ikev2_rx_cert_pld* rx_cert;

		if( s_pld_ctx->peer_cert_pld ){
			rhp_ikev2_rx_cert_pld_free(s_pld_ctx->peer_cert_pld);
		}


  	rx_cert = s_pld_ctx->ca_cert_plds_head;
		while( rx_cert ){

			rhp_ikev2_rx_cert_pld* rx_cert_nxt = rx_cert->next;

			rhp_ikev2_rx_cert_pld_free(rx_cert);

			rx_cert = rx_cert_nxt;
		}

		if( s_pld_ctx->vpn_ref ){
			rhp_vpn_unhold(s_pld_ctx->vpn_ref);
		}

		if( s_pld_ctx->rlm ){
			rhp_realm_unhold(s_pld_ctx->rlm);
		}

		if( s_pld_ctx->rx_ikemesg ){
			rhp_ikev2_unhold_mesg(s_pld_ctx->rx_ikemesg);
		}

		if( s_pld_ctx->tx_ikemesg ){
			rhp_ikev2_unhold_mesg(s_pld_ctx->tx_ikemesg);
		}

	  if( s_pld_ctx->my_id_val ){
	    _rhp_free_zero(s_pld_ctx->my_id_val,s_pld_ctx->my_id_len);
	  }

	  if( s_pld_ctx->cert_urls ){
	  	_rhp_free(s_pld_ctx->cert_urls);
	  }

	  if( s_pld_ctx->id_i_impl ){
	  	_rhp_free(s_pld_ctx->id_i_impl);
	  }

	  if( s_pld_ctx->id_r_impl ){
	  	_rhp_free(s_pld_ctx->id_r_impl);
	  }

		_rhp_free(s_pld_ctx);
	}

  RHP_TRC(0,RHPTRCID_IKE_AUTH_FREE_SRC_CTX_RTRN,"x",s_pld_ctx);
	return;
}



static int _rhp_ikev2_new_pkt_ike_auth_req(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_vpn_realm* rlm,
		rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ipcmsg *ipcmsg,rhp_ikev2_mesg* tx_req_ikemesg)
{
  rhp_ipcmsg_sign_rep* sign_rep;
  rhp_ikev2_payload* ikepayload = NULL;
  u8* my_id = NULL,*peer_id = NULL;
  int my_id_type = 0, peer_id_type = 0;
  int my_id_len = 0,peer_id_len = 0;
  u8 *auth_octets = NULL,*ca_keys_p = NULL;
  int auth_octets_len = 0,ca_keys_len = 0;
  int auth_method = 0;
  u8* p;
  int eap_sup_enabled = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_AUTH_REQ,"xxxxxx",vpn,ikesa,rlm,rx_resp_ikemesg,rx_resp_ikemesg->rx_pkt,ipcmsg);

  sign_rep = (rhp_ipcmsg_sign_rep*)ipcmsg;
  p = (u8*)(sign_rep + 1);

  tx_req_ikemesg->set_exchange_type(tx_req_ikemesg,RHP_PROTO_IKE_EXCHG_IKE_AUTH);
  tx_req_ikemesg->set_mesg_id(tx_req_ikemesg,1);

  eap_sup_enabled = rhp_eap_sup_impl_is_enabled(rlm,NULL);

  if( rlm->my_auth.my_id.type ){

  	if( rhp_ikev2_id_value(&(rlm->my_auth.my_id),&my_id,&my_id_len,&my_id_type) ){
  		RHP_BUG("");
  		goto error;
  	}

  }else{

  	if( !eap_sup_enabled ||
  			(vpn->my_id.type != RHP_PROTO_IKE_ID_IPV4_ADDR && vpn->my_id.type != RHP_PROTO_IKE_ID_IPV6_ADDR) ){

			RHP_BUG("");
			goto error;

  	}else{

			my_id = (u8*)_rhp_malloc(16);
			if( my_id == NULL ){
				RHP_BUG("");
				goto error;
			}

			if( vpn->my_id.type == RHP_PROTO_IKE_ID_IPV4_ADDR ){
				my_id_len = 4;
			}else if( vpn->my_id.type == RHP_PROTO_IKE_ID_IPV6_ADDR ){
				my_id_len = 16;
			}
			my_id_type = vpn->my_id.type;
			memcpy(my_id,vpn->my_id.addr.addr.raw,my_id_len);
  	}
  }

  if( vpn->peer_id.type != RHP_PROTO_IKE_ID_ANY &&
  		!rhp_ikev2_is_null_auth_id(vpn->peer_id.type) ){

  	if( rhp_ikev2_id_value(&(vpn->peer_id),&peer_id,&peer_id_len,&peer_id_type) ){
			RHP_BUG("");
			goto error;
		}

  }else{

  	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_AUTH_I_NO_PEER_ID,"xxd",ikesa,rlm,vpn->peer_id.type);
  }

  if( my_id || rhp_ikev2_is_null_auth_id(my_id_type) ){

  	if( rhp_ikev2_new_payload_tx(tx_req_ikemesg,RHP_PROTO_IKE_PAYLOAD_ID_I,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_req_ikemesg->put_payload(tx_req_ikemesg,ikepayload);

    if( ikepayload->ext.id->set_id(ikepayload,my_id_type,my_id_len,my_id) ){
      RHP_BUG("");
      goto error;
    }
  }

  if( !eap_sup_enabled ){

		auth_method = (int)sign_rep->auth_method;

		auth_octets = p;
		p += sign_rep->signed_octets_len;
		auth_octets_len = sign_rep->signed_octets_len;

		if( auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){

			rhp_cert_data* cert_data;
			int rem_len;
			int n;

			if( sign_rep->cert_chain_len ){

				cert_data = (rhp_cert_data*)p;
				p += sign_rep->cert_chain_len;
				rem_len = sign_rep->cert_chain_len;

				for( n = 0; n < (int)sign_rep->cert_chain_num; n++ ){

					if( rem_len <= 0 ){
						RHP_BUG("%d",rem_len);
						goto error;
					}

					if( rhp_ikev2_new_payload_tx(tx_req_ikemesg,RHP_PROTO_IKE_PAYLOAD_CERT,&ikepayload) ){
						RHP_BUG("");
						goto error;
					}

					tx_req_ikemesg->put_payload(tx_req_ikemesg,ikepayload);

					if( ikepayload->ext.cert->set_cert(ikepayload,
								(cert_data->len - sizeof(rhp_cert_data)),(u8*)(cert_data + 1)) ){
						RHP_BUG("");
						goto error;
					}

					if( cert_data->type == RHP_CERT_DATA_DER ){

						ikepayload->ext.cert->set_cert_encoding(ikepayload,RHP_PROTO_IKE_CERTENC_X509_CERT_SIG);

					}else if( cert_data->type == RHP_CERT_DATA_HASH_URL ){

						ikepayload->ext.cert->set_cert_encoding(ikepayload,RHP_PROTO_IKE_CERTENC_X509_CERT_HASH_URL);

					}else{
						RHP_BUG("%d",cert_data->type);
						goto error;
					}

					rem_len -= cert_data->len;
					cert_data = (rhp_cert_data*)(((u8*)cert_data) + cert_data->len);

					if( !rlm->my_auth.send_ca_chains ){
						RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_AUTH_I_NOT_TX_CA_CHAINS,"xx",ikesa,rlm);
						break;
					}
				}
			}

		}else if( auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ||
							auth_method == RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH ){

			// Nothing to do...

		}else{
			RHP_BUG("%d",auth_method);
			goto error;
		}
  }

  {
  	if( rhp_ikev2_new_payload_tx(tx_req_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_req_ikemesg->put_payload(tx_req_ikemesg,ikepayload);

    ikepayload->ext.n->set_protocol_id(ikepayload,0);

    ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_INITIAL_CONTACT);
  }


	if( sign_rep->ca_pubkey_dgsts_len ){
    ca_keys_p = p;
    p += sign_rep->ca_pubkey_dgsts_len;
    ca_keys_len = sign_rep->ca_pubkey_dgsts_len;
  }


  if( rhp_gcfg_hash_url_enabled(RHP_IKE_INITIATOR) &&
  		ikesa->peer_http_cert_lookup_supported ){

	 	if( rhp_ikev2_new_payload_tx(tx_req_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
	     RHP_BUG("");
	     goto error;
	 	}

	 	tx_req_ikemesg->put_payload(tx_req_ikemesg,ikepayload);

	 	ikepayload->ext.n->set_protocol_id(ikepayload,0);

	 	ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_HTTP_CERT_LOOKUP_SUPPORTED);
  }


	if( ikesa->peer_is_rockhopper || (ca_keys_len && ca_keys_p) ){

  	if( rhp_ikev2_new_payload_tx(tx_req_ikemesg,RHP_PROTO_IKE_PAYLOAD_CERTREQ,&ikepayload) ){
     RHP_BUG("");
     goto error;
    }

  	tx_req_ikemesg->put_payload(tx_req_ikemesg,ikepayload);

  	ikepayload->ext.certreq->set_cert_encoding(ikepayload,RHP_PROTO_IKE_CERTENC_X509_CERT_SIG);

  	if( ca_keys_len && ca_keys_p ){

  		if( ikepayload->ext.certreq->set_ca_keys(ikepayload,ca_keys_len,ca_keys_p) ){
  			RHP_BUG("");
  			goto error;
  		}
  	}
  }



	if( vpn->auth_ticket.conn_type == RHP_AUTH_TKT_CONN_TYPE_SPOKE2SPOKE ){

		if( vpn->auth_ticket.spk2spk_n_enc_auth_tkt == NULL ){
			RHP_BUG("");
			goto error;
		}

	 	if( rhp_ikev2_new_payload_tx(tx_req_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
	     RHP_BUG("");
	     goto error;
	 	}

	 	tx_req_ikemesg->put_payload(tx_req_ikemesg,ikepayload);

	 	ikepayload->ext.n->set_protocol_id(ikepayload,0);

	 	ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_ENC_AUTH_TICKET);

	 	if( ikepayload->ext.n->set_data(ikepayload,
	 				vpn->auth_ticket.spk2spk_n_enc_auth_tkt_len,vpn->auth_ticket.spk2spk_n_enc_auth_tkt) ){
	     RHP_BUG("");
	 		goto error;
	 	}
	}


  if( rlm->ikesa.send_responder_id && peer_id ){

  	if( rhp_ikev2_new_payload_tx(tx_req_ikemesg,RHP_PROTO_IKE_PAYLOAD_ID_R,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_req_ikemesg->put_payload(tx_req_ikemesg,ikepayload);

    if( ikepayload->ext.id->set_id(ikepayload,peer_id_type,peer_id_len,peer_id) ){
      RHP_BUG("");
      goto error;
    }
  }

  if( !eap_sup_enabled ) {

  	// Size of AUTH depends on auth_method.
  	// (e.g.) For RSA signature with 4096 bits key, the size is 4096bits(512bytes).

    if( rhp_ikev2_new_payload_tx(tx_req_ikemesg,RHP_PROTO_IKE_PAYLOAD_AUTH,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_req_ikemesg->put_payload(tx_req_ikemesg,ikepayload);

    if( ikepayload->ext.auth->set_auth_data(ikepayload,auth_method,auth_octets_len,auth_octets) ){
      RHP_BUG("");
      goto error;
    }
  }


	if( vpn->peer_is_rockhopper && rlm->ikesa.send_realm_id ){

		u32 tx_rlm_id = htonl(rlm->id);

		if( rhp_ikev2_new_payload_tx(tx_req_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_req_ikemesg->put_payload(tx_req_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);

		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_REALM_ID);

    if( ikepayload->ext.n->set_data(ikepayload,sizeof(u32),(u8*)&tx_rlm_id) ){
      RHP_BUG("");
      goto error;
    }

		ikepayload->set_non_critical(ikepayload,1);

	  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_TX_REALM_ID_N_PAYLOAD,"VPd",vpn,ikesa,vpn->peer_is_rockhopper);
	}


  if( my_id ){
    _rhp_free(my_id);
  }
  if( peer_id ){
    _rhp_free(peer_id);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_AUTH_REQ_RTRN,"xxxxx",vpn,ikesa,rx_resp_ikemesg,ipcmsg,tx_req_ikemesg);
  return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKE_AUTH_NEW_REQ_PKT_ERR,"K",rx_resp_ikemesg);
  if( my_id ){
    _rhp_free(my_id);
  }
  if( peer_id ){
    _rhp_free(peer_id);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_AUTH_REQ_ERR,"xxxx",vpn,ikesa,rx_resp_ikemesg,ipcmsg);
  return -EINVAL;
}

static int _rhp_ikev2_new_pkt_ike_auth_sess_resume_req(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_vpn_realm* rlm,
		rhp_vpn_sess_resume_material* material_i,int auth_octets_len,u8*auth_octets,
		int id_i_type,int id_i_len,u8* id_i,
		rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ikev2_mesg* tx_req_ikemesg)
{
  rhp_ikev2_payload* ikepayload = NULL;
  u8 *peer_id = NULL;
  int peer_id_type;
  int peer_id_len = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_AUTH_SESS_RESUME_REQ,"xxxxxxxpdp",vpn,ikesa,rlm,rx_resp_ikemesg,rx_resp_ikemesg->rx_pkt,tx_req_ikemesg,material_i,auth_octets_len,auth_octets,id_i_type,id_i_len,id_i);


  tx_req_ikemesg->set_exchange_type(tx_req_ikemesg,RHP_PROTO_IKE_EXCHG_IKE_AUTH);
  tx_req_ikemesg->set_mesg_id(tx_req_ikemesg,1);


  if( vpn->peer_id.type != RHP_PROTO_IKE_ID_ANY ){

  	if( rhp_ikev2_id_value(&(vpn->peer_id),&peer_id,&peer_id_len,&peer_id_type) ){
			RHP_BUG("");
			goto error;
		}

  }else{

  	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_AUTH_SESS_RESUME_I_NO_PEER_ID,"xxd",ikesa,rlm,vpn->peer_id.type);
  }


  {
  	if( rhp_ikev2_new_payload_tx(tx_req_ikemesg,RHP_PROTO_IKE_PAYLOAD_ID_I,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_req_ikemesg->put_payload(tx_req_ikemesg,ikepayload);

    if( ikepayload->ext.id->set_id(ikepayload,id_i_type,id_i_len,id_i) ){
      RHP_BUG("");
      goto error;
    }
  }


  if( peer_id ){

  	if( rhp_ikev2_new_payload_tx(tx_req_ikemesg,RHP_PROTO_IKE_PAYLOAD_ID_R,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_req_ikemesg->put_payload(tx_req_ikemesg,ikepayload);

    if( ikepayload->ext.id->set_id(ikepayload,peer_id_type,peer_id_len,peer_id) ){
      RHP_BUG("");
      goto error;
    }
  }


  {
    if( rhp_ikev2_new_payload_tx(tx_req_ikemesg,RHP_PROTO_IKE_PAYLOAD_AUTH,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_req_ikemesg->put_payload(tx_req_ikemesg,ikepayload);

    if( ikepayload->ext.auth->set_auth_data(ikepayload,ikesa->auth_method,auth_octets_len,auth_octets) ){
      RHP_BUG("");
      goto error;
    }
  }

  if( peer_id ){
    _rhp_free(peer_id);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_AUTH_SESS_RESUME_REQ_RTRN,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
  return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKE_AUTH_SESS_RESUME_NEW_REQ_PKT_ERR,"K",rx_resp_ikemesg);

	if( peer_id ){
    _rhp_free(peer_id);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_AUTH_SESS_RESUME_REQ_ERR,"xxx",vpn,ikesa,rx_resp_ikemesg);
  return -EINVAL;
}

int rhp_ikev2_new_pkt_ike_auth_error_notify(rhp_ikesa* ikesa,rhp_ikev2_mesg* tx_ikemesg,
		                u8 exchaneg_type,u32 message_id,u16 notify_mesg_type,unsigned long arg0)
{
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_AUTH_ERROR_NOTIFY,"xxdbwx",ikesa,tx_ikemesg,message_id,exchaneg_type,notify_mesg_type,arg0);

  if( exchaneg_type ){
	  tx_ikemesg->set_exchange_type(tx_ikemesg,exchaneg_type);
	  tx_ikemesg->set_mesg_id(tx_ikemesg,message_id);
  }

  {
    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    ikepayload->ext.n->set_protocol_id(ikepayload,0);
    ikepayload->ext.n->set_message_type(ikepayload,notify_mesg_type);

    switch( notify_mesg_type ){

    case RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED:
    	break;

    case RHP_PROTO_IKE_NOTIFY_ERR_NO_PROPOSAL_CHOSEN:
    	break;

    case RHP_PROTO_IKE_NOTIFY_ERR_UNEXPECTED_NAT_DETECTED:
    	break;

    default:
    	RHP_BUG("%d",notify_mesg_type);
    	goto error;
    }
  }

 	tx_ikemesg->tx_flag = RHP_IKEV2_SEND_REQ_FLAG_URGENT;

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_AUTH_ERROR_NOTIFY_RTRN,"xdx",ikesa,message_id,tx_ikemesg);
  return 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_AUTH_ERROR_NOTIFY_ERR,"xd",ikesa,message_id);
  return -EINVAL;
}

static int _rhp_ikev2_new_pkt_ike_auth_rep_impl(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_ikemesg,
		rhp_vpn_realm* rlm,rhp_ikev2_mesg* tx_ikemesg,
		int auth_method,int auth_octets_len,u8 *auth_octets,
		unsigned int cert_chain_len,unsigned int cert_chain_num,u8* cert_data_head)
{
  rhp_ikev2_payload* ikepayload = NULL;
  u8* my_id = NULL;
  int my_id_type;
  int my_id_len;

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_AUTH_REP_IMPL,"xxxxxdpddx",vpn,ikesa,rx_ikemesg,rx_ikemesg->rx_pkt,rlm,auth_method,auth_octets_len,auth_octets,cert_chain_len,cert_chain_num,cert_data_head);

  if( rhp_ikev2_id_value(&(rlm->my_auth.my_id),&my_id,&my_id_len,&my_id_type) ){
    RHP_BUG("");
    goto error;
  }

  {
    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_ID_R,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.id->set_id(ikepayload,my_id_type,my_id_len,my_id) ){
      RHP_BUG("");
      goto error;
    }
  }


  if( auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){

    if( cert_chain_len ){

      int n;
    	rhp_cert_data* cert_data = (rhp_cert_data*)cert_data_head;
      int rem_len = cert_chain_len;

      cert_data_head += cert_chain_len;

      for( n = 0; n < (int)cert_chain_num;n++ ){

        if( rem_len <= 0 ){
          RHP_BUG("%d",rem_len);
          goto error;
        }

        if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_CERT,&ikepayload) ){
          RHP_BUG("");
          goto error;
        }

        tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

        if( ikepayload->ext.cert->set_cert(ikepayload,(cert_data->len - sizeof(rhp_cert_data)),(u8*)(cert_data + 1)) ){
          RHP_BUG("");
          goto error;
        }

				if( cert_data->type == RHP_CERT_DATA_DER ){

					ikepayload->ext.cert->set_cert_encoding(ikepayload,RHP_PROTO_IKE_CERTENC_X509_CERT_SIG);

				}else if( cert_data->type == RHP_CERT_DATA_HASH_URL ){

					ikepayload->ext.cert->set_cert_encoding(ikepayload,RHP_PROTO_IKE_CERTENC_X509_CERT_HASH_URL);

				}else{
					RHP_BUG("%d",cert_data->type);
					goto error;
				}

        rem_len -= cert_data->len;
        cert_data = (rhp_cert_data*)(((u8*)cert_data) + cert_data->len);

        if( !rlm->my_auth.send_ca_chains ){
       	  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_AUTH_R_NOT_TX_CA_CHAINS,"xx",ikesa,rlm);
          break;
        }
      }
    }

  }else if( auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ||
  					auth_method == RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH ){

    // Nothing to do...

  }else{
    RHP_BUG("%d",auth_method);
    goto error;
  }


  {
  	// Size of AUTH depends on auth_method. (ex) For RSA signature with 4096 bits key, the size is 4096bits(512bytes).

  	if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_AUTH,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.auth->set_auth_data(ikepayload,auth_method,auth_octets_len,auth_octets) ){
      RHP_BUG("");
      goto error;
    }
  }

  _rhp_free(my_id);

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_AUTH_REP_IMPL_RTRN,"xxx",ikesa,rlm,tx_ikemesg);
  return 0;

error:
  if( my_id ){
    _rhp_free(my_id);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_AUTH_REP_IMPL_ERR,"xx",ikesa,rlm);
  return -EINVAL;
}

static int _rhp_ikev2_new_pkt_ike_auth_rep(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_ikemesg,
		rhp_vpn_realm* rlm,rhp_ipcmsg *ipcmsg,rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
  rhp_ipcmsg_sign_rep* sign_rep;
  u8 *auth_octets;
  u8 *p, *cert_data_head;

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_AUTH_REP,"xxxxxx",vpn,ikesa,rx_ikemesg,rx_ikemesg->rx_pkt,rlm,ipcmsg);

  sign_rep = (rhp_ipcmsg_sign_rep*)ipcmsg;
  p = (u8*)(sign_rep + 1);

  auth_octets = p;
  p += sign_rep->signed_octets_len;

  cert_data_head = p;
  p += sign_rep->cert_chain_len;

  err = _rhp_ikev2_new_pkt_ike_auth_rep_impl(vpn,ikesa,rx_ikemesg,rlm,tx_ikemesg,
  		(int)sign_rep->auth_method,sign_rep->signed_octets_len,auth_octets,
  		sign_rep->cert_chain_len,sign_rep->cert_chain_num,cert_data_head);

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_AUTH_REP_RTRN,"xxxxE",vpn,ikesa,rlm,tx_ikemesg,err);
  return err;
}

static int _rhp_ikev2_new_pkt_ike_auth_eap_rep(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* eap_pend_rx_ikemesg,
		rhp_vpn_realm* rlm,rhp_ikev2_mesg* tx_ikemesg,int auth_octets_len,u8* auth_octets)
{
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_AUTH_EAP_REP,"xxxxxxxp",vpn,ikesa,rx_ikemesg,rx_ikemesg->rx_pkt,eap_pend_rx_ikemesg,eap_pend_rx_ikemesg->rx_pkt,rlm,auth_octets_len,auth_octets);

  {
    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_AUTH,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.auth->set_auth_data(ikepayload,RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY,auth_octets_len,auth_octets) ){
      RHP_BUG("");
      goto error;
    }
  }

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_AUTH_EAP_REP_RTRN,"xxxxx",ikesa,rlm,rx_ikemesg,eap_pend_rx_ikemesg,tx_ikemesg);
  return 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_AUTH_EAP_REP_ERR,"xxxxxx",ikesa,rlm,rx_ikemesg,eap_pend_rx_ikemesg,tx_ikemesg);
  return -EINVAL;
}

static int _rhp_ikev2_new_pkt_ike_auth_eap_req(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_ikemesg,
		rhp_vpn_realm* rlm,rhp_ikev2_mesg* tx_ikemesg,int auth_octets_len,u8* auth_octets)
{
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_AUTH_EAP_REQ,"xxxxxp",vpn,ikesa,rx_ikemesg,rx_ikemesg->rx_pkt,rlm,auth_octets_len,auth_octets);

  {
    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_AUTH,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.auth->set_auth_data(ikepayload,RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY,auth_octets_len,auth_octets) ){
      RHP_BUG("");
      goto error;
    }
  }

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_AUTH_EAP_REQ_RTRN,"xxxx",ikesa,rlm,rx_ikemesg,tx_ikemesg);
  return 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_IKE_AUTH_EAP_REQ_ERR,"xxxxx",ikesa,rlm,rx_ikemesg,tx_ikemesg);
  return -EINVAL;
}

int rhp_ikev2_ike_auth_ipc_sign_req(rhp_ikev2_mesg* ikemesg,
		unsigned long rlm_id,rhp_ikesa* ikesa,
		int mesg_octets_len,u8* mesg_octets,
		int sk_p_len,u8* sk_p,
		int auth_tkt_session_key_len,u8* auth_tkt_session_key,
		rhp_ipcmsg** ipcmsg_r,int txn_id_flag)
{
  int err = 0;
  int len;
  rhp_ipcmsg_sign_req* sign_req;
  rhp_ikev2_payload* certreq_payload;
  int ca_pubkey_dgsts_len = 0;
  u8* p;
  int my_side;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SIGN_REQ,"xuxppx",ikemesg,rlm_id,ikesa,mesg_octets_len,mesg_octets,sk_p_len,sk_p,ipcmsg_r);
  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_TKT_SESSION_KEY_SIGN_REQ,"xp",ikemesg,auth_tkt_session_key_len,auth_tkt_session_key);

  my_side = (ikemesg->is_initiator(ikemesg) ? RHP_IKE_RESPONDER : RHP_IKE_INITIATOR);

  //
  // TODO : To support multiple CERTREQ requests.
  //
  certreq_payload = ikemesg->get_payload(ikemesg,RHP_PROTO_IKE_PAYLOAD_CERTREQ);

  if( certreq_payload ){

    ca_pubkey_dgsts_len = certreq_payload->ext.certreq->get_ca_keys_len(certreq_payload);
  }

  len = sizeof(rhp_ipcmsg_sign_req) + ca_pubkey_dgsts_len
  		  + mesg_octets_len + sk_p_len + auth_tkt_session_key_len;

  sign_req = (rhp_ipcmsg_sign_req*)rhp_ipc_alloc_msg(RHP_IPC_SIGN_REQUEST,len);
  if( sign_req == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  p = (u8*)(sign_req + 1);

  sign_req->len = len;

  if( txn_id_flag ){
    ikesa->ipc_txn_id = rhp_ikesa_new_ipc_txn_id();
  }
  sign_req->txn_id = ikesa->ipc_txn_id;

  sign_req->my_realm_id = rlm_id;
  sign_req->side = ikesa->side;

  sign_req->http_cert_lookup_supported
  = (rhp_gcfg_hash_url_enabled(my_side) && ikesa->peer_http_cert_lookup_supported);

  {
		sign_req->qcd_enabled = (rhp_gcfg_ikev2_qcd_enabled ? 1 : 0);
		if( ikesa->side == RHP_IKE_INITIATOR ){
			memcpy(sign_req->spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
			memcpy(sign_req->peer_spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
		}else{
			memcpy(sign_req->spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
			memcpy(sign_req->peer_spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
		}
  }

  sign_req->prf_method = ikesa->prf->alg;

  sign_req->mesg_octets_len = mesg_octets_len;

  sign_req->certs_bin_max_size = rhp_gcfg_max_ike_packet_size;

  sign_req->ca_pubkey_dgsts_len = ca_pubkey_dgsts_len;
  if( ca_pubkey_dgsts_len ){
    sign_req->ca_pubkey_dgst_len = RHP_PROTO_IKE_CERTENC_SHA1_DIGEST_LEN;
  }

  memcpy(p,mesg_octets,mesg_octets_len);
  p += mesg_octets_len;

  if( sk_p ){
    memcpy(p, sk_p,sk_p_len);
    p += sk_p_len;
    sign_req->sk_p_len = sk_p_len;
  }

  if( certreq_payload && ca_pubkey_dgsts_len ){
    memcpy(p,certreq_payload->ext.certreq->get_ca_keys(certreq_payload),ca_pubkey_dgsts_len);
    p += ca_pubkey_dgsts_len;
  }

  if( auth_tkt_session_key_len ){
    memcpy(p,auth_tkt_session_key,auth_tkt_session_key_len);
    p += auth_tkt_session_key_len;
  	sign_req->auth_tkt_session_key_len = auth_tkt_session_key_len;
  }

  *ipcmsg_r = (rhp_ipcmsg*)sign_req;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SIGN_REQ_RTRN,"xuxp",ikemesg,rlm_id,ikesa,sign_req->len,sign_req);
  return 0;

error:
  if( sign_req ){
    _rhp_free_zero(sign_req,sign_req->len);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SIGN_REQ_ERR,"xuxE",ikemesg,rlm_id,ikesa,err);
  return err;
}

int rhp_ikev2_ike_auth_ipc_verify_req(unsigned long req_type,
		unsigned long rlm_id,
		rhp_ikesa* ikesa,
    int my_id_type,int my_id_len,u8* my_id_val,
    int peer_id_type,int peer_id_len,u8* peer_id_val,
    int mesg_octets_len,u8* mesg_octets,
    int signature_octets_len,u8* signature_octets,
    rhp_ikev2_rx_cert_pld* peer_cert_pld,
    int cert_chain_num,int cert_chain_bin_len,u8* cert_chain_bin,
    unsigned long peer_notified_realm_id,
    int ikev2_null_auth_sk_px_len,u8* ikev2_null_auth_sk_px,
    int peer_auth_method,
    unsigned long hb2spk_vpn_realm_id,
    int auth_tkt_session_key_len,u8* auth_tkt_session_key,
    rhp_ipcmsg** ipcmsg_r)
{
  int err = -EINVAL;
  rhp_ipcmsg_verify_req* verify_req = NULL;
  int len;
  u8* p;
  u8* peer_cert_bin = NULL;
  int peer_cert_bin_len = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_VERIFY_REQ,"LuuxLdpLdpppxdpupdux","IPC",req_type,rlm_id,ikesa,"PROTO_IKE_ID",my_id_type,my_id_len,my_id_val,"PROTO_IKE_ID",peer_id_type,peer_id_len,peer_id_val,mesg_octets_len,mesg_octets,signature_octets_len,signature_octets,peer_cert_pld,cert_chain_num,cert_chain_bin_len,cert_chain_bin,peer_notified_realm_id,ikev2_null_auth_sk_px_len,ikev2_null_auth_sk_px,peer_auth_method,hb2spk_vpn_realm_id,ipcmsg_r);
  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_TKT_SESSION_KEY_VERIFY_REQ,"xp",ikesa,auth_tkt_session_key_len,auth_tkt_session_key);

  if( peer_cert_pld ){

  	err = rhp_ikev2_rx_cert_pld_peek_der(peer_cert_pld,&peer_cert_bin,&peer_cert_bin_len);
  	if( err ){
  		goto error;
  	}
  }

  len = sizeof(rhp_ipcmsg_verify_req) + my_id_len + peer_id_len + mesg_octets_len
  			+ signature_octets_len + peer_cert_bin_len + cert_chain_bin_len
  			+ ikev2_null_auth_sk_px_len + auth_tkt_session_key_len;


  if( my_id_type == RHP_PROTO_IKE_ID_RFC822_ADDR || my_id_type == RHP_PROTO_IKE_ID_FQDN ){

  	if( my_id_val && my_id_val[my_id_len-1] != '\0' ){
  		len++;
  	}
  }

  if( peer_id_type == RHP_PROTO_IKE_ID_RFC822_ADDR || peer_id_type == RHP_PROTO_IKE_ID_FQDN ){

  	if( peer_id_val && peer_id_val[peer_id_len-1] != '\0' ){
  		len++;
  	}
  }


  verify_req = (rhp_ipcmsg_verify_req*)rhp_ipc_alloc_msg(req_type,len);
  if( verify_req == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  p = (u8*)(verify_req + 1);

  verify_req->len = len;

  ikesa->ipc_txn_id = rhp_ikesa_new_ipc_txn_id();
  verify_req->txn_id = ikesa->ipc_txn_id;

  verify_req->my_realm_id = rlm_id;
  verify_req->side = ikesa->side;
  verify_req->prf_method = ikesa->prf->alg;
  if( ikesa->side == RHP_IKE_INITIATOR ){
    memcpy(verify_req->spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
  }else{
    memcpy(verify_req->spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
  }

  if( my_id_val ){

    verify_req->my_id_type = my_id_type;
    verify_req->my_id_len = my_id_len;
    memcpy(p,my_id_val,my_id_len);
    p += my_id_len;

    if( my_id_type == RHP_PROTO_IKE_ID_RFC822_ADDR || my_id_type == RHP_PROTO_IKE_ID_FQDN ){

    	if( my_id_val[my_id_len-1] != '\0' ){
    		*p = '\0';
    		p++;
    		verify_req->my_id_len++;
    	}
    }
  }

  verify_req->peer_auth_method = peer_auth_method;
  verify_req->peer_id_type = peer_id_type;
  verify_req->peer_id_len = peer_id_len;
  memcpy(p,peer_id_val,peer_id_len);
  p += peer_id_len;

  if( peer_id_type == RHP_PROTO_IKE_ID_RFC822_ADDR || peer_id_type == RHP_PROTO_IKE_ID_FQDN ){

  	if( peer_id_val[peer_id_len-1] != '\0' ){
  		*p = '\0';
  		p++;
  		verify_req->peer_id_len++;
  	}
  }

  if( ikev2_null_auth_sk_px ){
  	verify_req->ikev2_null_auth_sk_px_len = ikev2_null_auth_sk_px_len;
  	memcpy(p,ikev2_null_auth_sk_px,ikev2_null_auth_sk_px_len);
  	p += ikev2_null_auth_sk_px_len;
  }

  if( peer_cert_bin ){
    verify_req->peer_cert_bin_len = peer_cert_bin_len;
    memcpy(p,peer_cert_bin,peer_cert_bin_len);
    p += peer_cert_bin_len;
  }

  if( cert_chain_bin ){
    verify_req->cert_chain_num = cert_chain_num;
    verify_req->cert_chain_bin_len = cert_chain_bin_len;
    memcpy(p,cert_chain_bin,cert_chain_bin_len);
    p += cert_chain_bin_len;
  }

  if( mesg_octets ){
  	verify_req->mesg_octets_len = mesg_octets_len;
  	memcpy(p,mesg_octets,mesg_octets_len);
  	p += mesg_octets_len;
  }

  if( signature_octets ){
  	verify_req->signature_octets_len = signature_octets_len;
  	memcpy(p,signature_octets,signature_octets_len);
  	p += signature_octets_len;
  }

  if( auth_tkt_session_key ){

  	verify_req->auth_tkt_hb2spk_realm_id = hb2spk_vpn_realm_id;

  	verify_req->auth_tkt_session_key_len = auth_tkt_session_key_len;
  	memcpy(p,auth_tkt_session_key,auth_tkt_session_key_len);

  	p += auth_tkt_session_key_len;
  }

  if( rhp_gcfg_ikev2_rx_peer_realm_id_req ){
  	verify_req->peer_notified_realm_id = peer_notified_realm_id;
  }else{
  	verify_req->peer_notified_realm_id = RHP_VPN_REALM_ID_UNKNOWN;
  }


  *ipcmsg_r = (rhp_ipcmsg*)verify_req;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_VERIFY_REQ_RTRN,"Luuxp","IPC",req_type,rlm_id,ikesa,(*ipcmsg_r)->len,*ipcmsg_r);
  return 0;

error:
  if( verify_req ){
    _rhp_free_zero(verify_req,verify_req->len);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_VERIFY_REQ_ERR,"LuuxE","IPC",req_type,rlm_id,ikesa,err);
  return err;
}

static int _rhp_ikev2_ike_auth_ipc_handle_sign_rep(rhp_ipcmsg *ipcmsg)
{
  int err = -EINVAL;
  rhp_ipcmsg_sign_rep* sign_rep;
  rhp_ikesa* ikesa = NULL;
  rhp_vpn_realm* rlm = NULL;
  rhp_ikev2_mesg* tx_req_ikemesg = NULL;
  rhp_ikev2_mesg* rx_resp_ikemesg = NULL;
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;
  time_t lifetime_larval;
  int eap_sup_enabled = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_SIGN_REP,"x",ipcmsg);

  if( ipcmsg->len < sizeof(rhp_ipcmsg_sign_rep) ){
    RHP_BUG("%d < sizeof(rhp_ipcmsg_sign_rep)(%d)",ipcmsg->len,sizeof(rhp_ipcmsg_sign_rep));
    goto error;
  }

  sign_rep = (rhp_ipcmsg_sign_rep*)ipcmsg;

  if( sign_rep->len < sizeof(rhp_ipcmsg_sign_rep) + sign_rep->signed_octets_len ){
    RHP_BUG("%d < sizeof(rhp_ipcmsg_sign_rep)(%d) + sign_rep->signed_octets_len(%d)",sign_rep->len,sizeof(rhp_ipcmsg_sign_rep),sign_rep->signed_octets_len);
    goto error;
  }

  if( sign_rep->result ){

  	if( sign_rep->eap_role == RHP_EAP_SUPPLICANT ){
  		// OK
  	}else if( sign_rep->signed_octets_len == 0 ){
      RHP_BUG("%d",sign_rep->signed_octets_len);
      goto error;
    }
  }

  vpn_ref = rhp_vpn_ikesa_spi_get(sign_rep->side,sign_rep->spi);
  vpn = RHP_VPN_REF(vpn_ref);
  if( vpn == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_SIGN_REP_NO_IKESA,"xLdG",ipcmsg,"IKE_SIDE",sign_rep->side,sign_rep->spi);
    goto error;
  }

  RHP_LOCK(&(vpn->lock));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_SIGN_REP_IKESA_NOT_ACTIVE,"xx",ipcmsg,ikesa);
    goto error_l;
  }

  ikesa = vpn->ikesa_get(vpn,sign_rep->side,sign_rep->spi);
  if( ikesa == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_SIGN_REP_NO_IKESA,"x",ipcmsg);
    goto error_l;
  }


  tx_req_ikemesg = ikesa->pend_tx_ikemesg;
 	ikesa->pend_tx_ikemesg = NULL;
  rx_resp_ikemesg = ikesa->pend_rx_ikemesg;
  ikesa->pend_rx_ikemesg = NULL;

  if( tx_req_ikemesg == NULL || rx_resp_ikemesg == NULL ){
  	RHP_BUG("");
  	goto error_l;
  }

  if( sign_rep->txn_id != ikesa->ipc_txn_id ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_SIGN_REP_IKESA_BAD_TXNID,"xxxqq",ipcmsg,vpn,ikesa,sign_rep->txn_id,ikesa->ipc_txn_id);
    goto error_l;
  }

  rlm = vpn->rlm;
  if( rlm == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_SIGN_REP_NO_REALM,"xx",ipcmsg,ikesa);
    goto error_l;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_SIGN_REP_REALM_NOT_ACTIVE,"xxxxu",ipcmsg,vpn,ikesa,rlm,rlm->id);
    goto error_l2;
  }

  if( sign_rep->my_realm_id != rlm->id ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_SIGN_REP_REALM_BAD_ID,"xxxxuu",ipcmsg,vpn,ikesa,rlm,sign_rep->my_realm_id,rlm,rlm->id);
    goto error_l2;
  }

  if( sign_rep->result == 0 ){
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_SIGN_REP_RESULT_ERR,"xxxxu",ipcmsg,vpn,ikesa,rlm,rlm->id);
  	goto error_l2;
  }


	eap_sup_enabled = rhp_eap_sup_impl_is_enabled(rlm,NULL);

	if( ( eap_sup_enabled && sign_rep->eap_role != RHP_EAP_SUPPLICANT) ||
			(!eap_sup_enabled && sign_rep->eap_role == RHP_EAP_SUPPLICANT) ){

		RHP_BUG("%d,%d",eap_sup_enabled,sign_rep->eap_role);
		goto error_l2;
	}

	if( !eap_sup_enabled ){

		vpn->eap.role = RHP_EAP_DISABLED;

		if( ikesa->eap.pend_mesg_octets_i ){
			_rhp_free(ikesa->eap.pend_mesg_octets_i);
			ikesa->eap.pend_mesg_octets_i = NULL;
		}

  	lifetime_larval = (time_t)rlm->ikesa.lifetime_larval;

	}else{

  	lifetime_larval = (time_t)rlm->ikesa.lifetime_eap_larval;
	}

  ikesa->auth_method = sign_rep->auth_method;

  if( rhp_gcfg_ikev2_qcd_enabled && sign_rep->qcd_enabled ){

  	ikesa->qcd.my_token_enabled = 1;
  	memcpy(ikesa->qcd.my_token,sign_rep->my_qcd_token,RHP_IKEV2_QCD_TOKEN_LEN);

  }else{

  	ikesa->qcd.my_token_enabled = 0;
  }

  err = _rhp_ikev2_new_pkt_ike_auth_req(vpn,ikesa,rlm,ikesa->signed_octets.ikemesg_r_2nd,ipcmsg,tx_req_ikemesg);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_SIGN_REP_ALLOC_IKEMSG_ERR,"xxxxuE",ipcmsg,vpn,ikesa,rlm,rlm->id,err);
    goto error_l2;
  }

  RHP_UNLOCK(&(rlm->lock));


  rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_I_AUTH_SENT);
  ikesa->timers->start_lifetime_timer(vpn,ikesa,lifetime_larval,1);

  ikesa->busy_flag = 0;

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_SIGN_OK,"VP",vpn,ikesa);


  rhp_ikev2_call_next_rx_response_mesg_handlers(rx_resp_ikemesg,vpn,
  		sign_rep->side,sign_rep->spi,tx_req_ikemesg,RHP_IKEV2_MESG_HANDLER_IKESA_AUTH);


  rhp_ikev2_unhold_mesg(tx_req_ikemesg);
  rhp_ikev2_unhold_mesg(rx_resp_ikemesg);

  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_SIGN_REP_RTRN,"xxxx",ipcmsg,vpn,ikesa,rlm);
  return 0;

error_l2:
  RHP_UNLOCK(&(rlm->lock));
error_l:

	if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
	}

	RHP_UNLOCK(&(vpn->lock));

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_SIGN_ERR,"VE",vpn,err);
  if( vpn ){
    rhp_vpn_unhold(vpn_ref);
  }
  if( tx_req_ikemesg ){
    rhp_ikev2_unhold_mesg(tx_req_ikemesg);
  }
  if( rx_resp_ikemesg ){
    rhp_ikev2_unhold_mesg(rx_resp_ikemesg);
  }

	rhp_ikev2_g_statistics_inc(ikesa_auth_errors);

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_SIGN_REP_ERR,"xxxxE",ipcmsg,vpn,ikesa,rlm,err);
  return err;
}

void rhp_ikev2_ike_auth_setup_access_point(rhp_vpn* vpn,rhp_vpn_realm* rlm)
{
	if( rlm->access_point_peer ){

		int eap_sup_enabled = rhp_eap_sup_impl_is_enabled(rlm,NULL);

		if( ((eap_sup_enabled && rlm->my_auth.my_id.type == 0) ||
				 !rhp_ikev2_id_cmp_sub_type_too(&(vpn->my_id),&(rlm->my_auth.my_id))) &&
				!rhp_ikev2_id_cmp_no_alt_id(&(vpn->peer_id),&(rlm->access_point_peer->id) ) ){

			rlm->set_access_point(rlm,vpn);

		  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SETUP_ACCESS_POINT_ID,"xxd",vpn,rlm,eap_sup_enabled);
		  rhp_ikev2_id_dump("vpn->my_id(1)",&(vpn->my_id));
		  rhp_ikev2_id_dump("rlm->my_auth.my_id(1)",&(rlm->my_auth.my_id));
		  rhp_ikev2_id_dump("vpn->peer_id(1)",&(vpn->peer_id));

		}else{

		  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SETUP_ACCESS_POINT_ID_NOT_MATCHED,"xxd",vpn,rlm,eap_sup_enabled);
		  rhp_ikev2_id_dump("vpn->my_id(2)",&(vpn->my_id));
		  rhp_ikev2_id_dump("rlm->my_auth.my_id(2)",&(rlm->my_auth.my_id));
		  rhp_ikev2_id_dump("vpn->peer_id(2)",&(vpn->peer_id));
		  rhp_ikev2_id_dump("rlm->access_point_peer->id(2)",&(rlm->access_point_peer->id));
		}

	}else{

	  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SETUP_ACCESS_POINT_PEER_AC_NOT_SET,"xx",vpn,rlm);
	  rhp_ikev2_id_dump("vpn->my_id(3)",&(vpn->my_id));
	  rhp_ikev2_id_dump("rlm->my_auth.my_id(3)",&(rlm->my_auth.my_id));
	  rhp_ikev2_id_dump("vpn->peer_id(3)",&(vpn->peer_id));
	}

	return;
}

static int _rhp_ikev2_ike_auth_ipc_handle_verify_rep(rhp_ipcmsg *ipcmsg)
{
  int err = -EINVAL;
  rhp_ipcmsg_verify_rep* verify_rep;
  rhp_ikesa* ikesa = NULL;
  rhp_vpn_realm* rlm = NULL;
  rhp_ikev2_mesg* rx_resp_ikemesg = NULL;
  rhp_ikev2_mesg* tx_req_ikemesg = NULL;
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;
  u8* alt_id_p;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_REP,"x",ipcmsg);

  if( ipcmsg->len < sizeof(rhp_ipcmsg_verify_rep) ){
    RHP_BUG("%d < sizeof(rhp_ipcmsg_verify_rep)(%d)",ipcmsg->len,sizeof(rhp_ipcmsg_verify_rep));
    goto error;
  }

  verify_rep = (rhp_ipcmsg_verify_rep*)ipcmsg;
  alt_id_p = (u8*)(verify_rep + 1);

  if( verify_rep->len < sizeof(rhp_ipcmsg_verify_rep) ){
    RHP_BUG("%d < sizeof(rhp_ipcmsg_verify_rep)(%d)",verify_rep->len,sizeof(rhp_ipcmsg_verify_rep));
    goto error;
  }

  if( verify_rep->len < (sizeof(rhp_ipcmsg_verify_rep) + verify_rep->alt_peer_id_len) ){
    RHP_BUG("%d < sizeof(rhp_ipcmsg_verify_rep)(%d)(2)",verify_rep->len,(sizeof(rhp_ipcmsg_verify_rep) + verify_rep->alt_peer_id_len));
    goto error;
  }

  vpn_ref = rhp_vpn_ikesa_spi_get(verify_rep->side,verify_rep->spi);
  vpn = RHP_VPN_REF(vpn_ref);
  if( vpn == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_REP_NO_IKESA,"xLdG",ipcmsg,"IKE_SIDE",verify_rep->side,verify_rep->spi);
  	goto error;
  }

  RHP_LOCK(&(vpn->lock));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_REP_IKESA_NOT_ACTIVE,"xx",ipcmsg,vpn);
  	goto error_l_vpn;
  }

  ikesa = vpn->ikesa_get(vpn,verify_rep->side,verify_rep->spi);

  if( ikesa == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_REP_NO_IKESA,"xx",ipcmsg,vpn);
  	goto error_l_vpn;
  }

  rx_resp_ikemesg = ikesa->pend_rx_ikemesg;
  tx_req_ikemesg = ikesa->pend_tx_ikemesg;
  ikesa->pend_rx_ikemesg = NULL;
  ikesa->pend_tx_ikemesg = NULL;

  if( rx_resp_ikemesg == NULL || tx_req_ikemesg == NULL ){
  	RHP_BUG("");
  	goto error_l_vpn;
  }

  if( verify_rep->txn_id != ikesa->ipc_txn_id ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_REP_REALM_BAD_ID,"xxxxqq",ipcmsg,vpn,ikesa,rlm,verify_rep->txn_id,ikesa->ipc_txn_id);
    goto error_l_vpn;
  }

  rlm = vpn->rlm;
  if( rlm == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_REP_NO_REALM,"xxx",ipcmsg,vpn,ikesa);
    goto error_l_vpn;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_REP_REALM_NOT_ACTIVE,"xxxx",ipcmsg,vpn,ikesa,rlm);
    goto error_l_rlm_vpn;
  }

  if( verify_rep->result == 0 ){

    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_REP_RESULT_ERR,"xxxxu",ipcmsg,vpn,ikesa,rlm,rlm->id);

    goto error_l_rlm_vpn;
  }


  if( verify_rep->my_realm_id != rlm->id ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_REP_REALM_BAD_ID_2,"xxxxuu",ipcmsg,vpn,ikesa,rlm,verify_rep->my_realm_id,rlm->id);
    goto error_l_rlm_vpn;
  }

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

	rhp_ikev2_id_dump("_rhp_ikev2_ike_auth_ipc_handle_verify_rep",&(vpn->peer_id));


  vpn->vpn_conn_lifetime = (time_t)rlm->vpn_conn_lifetime;

	rhp_vpn_put(vpn);


  if( vpn->eap.role == RHP_EAP_DISABLED ){

  	rhp_ikev2_ike_auth_setup_access_point(vpn,rlm);

  	rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_ESTABLISHED);
    vpn->created_ikesas++;

  	if( ikesa->auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){
    	rhp_ikev2_g_statistics_inc(ikesa_auth_rsa_sig);
  	}else if( ikesa->auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ){
    	rhp_ikev2_g_statistics_inc(ikesa_auth_psk);
  	}else if( ikesa->auth_method == RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH ){
    	rhp_ikev2_g_statistics_inc(ikesa_auth_null_auth);
  	}


  	vpn->start_vpn_conn_life_timer(vpn);


  	rhp_http_bus_broadcast_async(vpn->vpn_realm_id,1,1,
  			rhp_ui_http_vpn_established_serialize,
  			rhp_ui_http_vpn_bus_btx_async_cleanup,(void*)rhp_vpn_hold_ref(vpn)); // (*x*)


		if( vpn->init_by_peer_addr ){

			if( !rhp_gcfg_dmvpn_connect_shortcut_rate_limit ){

				rhp_vpn_connect_i_pending_clear(vpn->vpn_realm_id,NULL,&(vpn->peer_addr));
			}

		}else{

			rhp_vpn_connect_i_pending_clear(vpn->vpn_realm_id,&(vpn->peer_id),NULL);
		}

  	ikesa->established_time = _rhp_get_time();
  	ikesa->expire_hard = ikesa->established_time + (time_t)rlm->ikesa.lifetime_hard;
  	ikesa->expire_soft = ikesa->established_time + (time_t)rlm->ikesa.lifetime_soft;


  	ikesa->timers->start_lifetime_timer(vpn,ikesa,(time_t)rlm->ikesa.lifetime_soft,1);
  	ikesa->timers->start_keep_alive_timer(vpn,ikesa,(time_t)rlm->ikesa.keep_alive_interval);
  	ikesa->timers->start_nat_t_keep_alive_timer(vpn,ikesa,(time_t)rlm->ikesa.nat_t_keep_alive_interval);

  	{
			vpn->established = 1;

			if( vpn->connecting ){
				vpn->connecting = 0;
				rhp_ikesa_half_open_sessions_dec();
			}
  	}

  	vpn->auto_reconnect_retries = 0;

		if( vpn->internal_net_info.static_peer_addr ){

			rhp_vpn_internal_route_update(vpn);
		}

  }else{ // EAP

  	ikesa->eap.pend_rx_ikemesg = rx_resp_ikemesg;
 	  rhp_ikev2_hold_mesg(rx_resp_ikemesg);

  	ikesa->timers->start_lifetime_timer(vpn,ikesa,(time_t)rlm->ikesa.lifetime_eap_larval,1);
  }

  ikesa->busy_flag = 0;

  RHP_UNLOCK(&(rlm->lock));

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_RESP_VERIFY_AUTH_OK,"KVP",rx_resp_ikemesg,vpn,ikesa);


  rhp_ikev2_call_next_rx_response_mesg_handlers(rx_resp_ikemesg,vpn,
  		verify_rep->side,verify_rep->spi,tx_req_ikemesg,RHP_IKEV2_MESG_HANDLER_IKESA_AUTH);


  rhp_ikev2_unhold_mesg(rx_resp_ikemesg);
  rhp_ikev2_unhold_mesg(tx_req_ikemesg);

  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_REP_RTRN,"xxxx",ipcmsg,vpn,ikesa,rlm);
  return 0;

error_l_rlm_vpn:
  RHP_UNLOCK(&(rlm->lock));
error_l_vpn:
	if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
	}

  RHP_UNLOCK(&(vpn->lock));
error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_RESP_VERIFY_AUTH_ERR,"KVE",rx_resp_ikemesg,vpn,err);
  if( vpn ){
    rhp_vpn_unhold(vpn_ref);
  }

  if( rx_resp_ikemesg ){
    rhp_ikev2_unhold_mesg(rx_resp_ikemesg);
  }
  if( tx_req_ikemesg ){
    rhp_ikev2_unhold_mesg(tx_req_ikemesg);
  }

	rhp_ikev2_g_statistics_inc(ikesa_auth_errors);

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_REP_ERR,"xxxxE",ipcmsg,vpn,ikesa,rlm,err);
  return err;
}

#ifdef RHP_USE_INITIAL_CONTACT_N_PLD
static int _rhp_ikev2_ike_auth_srch_n_initial_contact_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = 0;
	rhp_ike_auth_srch_plds_ctx* s_pld_ctx = (rhp_ike_auth_srch_plds_ctx*)ctx;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_N_INITIAL_CONTACT_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_N_INITIAL_CONTACT_CB_DUP_ERR,"xx",rx_ikemesg,ctx);
    goto error;
  }

  s_pld_ctx->initial_contact = 1;

  err = 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_N_INITIAL_CONTACT_CB_RTRN,"xxxE",rx_ikemesg,payload,ctx,err);
	return err;
}
#endif

int rhp_ikev2_ike_auth_setup_larval_vpn(rhp_vpn* larval_vpn,
		rhp_vpn_realm* rlm,rhp_ikesa* ikesa)
{
  int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SETUP_LARVAL_VPN,"xxx",larval_vpn,ikesa,rlm);

	err = rhp_ikev2_id_dup(&(larval_vpn->my_id),&(rlm->my_auth.my_id));
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	rhp_ikev2_id_dump("rlm->my_auth.my_id",&(rlm->my_auth.my_id));
	rhp_ikev2_id_dump("larval_vpn->peer_id",&(larval_vpn->peer_id));

	larval_vpn->vpn_realm_id = rlm->id;


	larval_vpn->cfg_peer = rlm->dup_peer_by_id(rlm,&(larval_vpn->peer_id),NULL);
  if( larval_vpn->cfg_peer == NULL ){
  	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,larval_vpn->vpn_realm_id,RHP_LOG_ID_NO_PEER_CFG,"VP",larval_vpn,ikesa);
  	err = -ENOENT;
  	goto error;
  }

  larval_vpn->is_configured_peer = rlm->is_configued_peer(rlm,&(larval_vpn->peer_id));


	if( larval_vpn->rlm && larval_vpn->rlm != rlm ){

		RHP_BUG("0x%lx, 0x%lx",larval_vpn,larval_vpn->rlm);
		err = -EINVAL;
		goto error;

	}else if( larval_vpn->rlm == NULL ){

		larval_vpn->rlm = rlm;
		rhp_realm_hold(rlm);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SETUP_LARVAL_VPN_RTRN,"xxxuxxddbdbbxdddu",larval_vpn,ikesa,rlm,larval_vpn->vpn_realm_id,larval_vpn->rlm,larval_vpn->cfg_peer,larval_vpn->nhrp.role,larval_vpn->nhrp.dmvpn_enabled,larval_vpn->nhrp.dmvpn_shortcut,larval_vpn->vpn_conn_idle_timeout,larval_vpn->auth_ticket.conn_type,rlm->nhrp.auth_tkt_enabled,larval_vpn->cfg_peer,(larval_vpn->cfg_peer ? larval_vpn->cfg_peer->is_access_point : 0),rlm->is_access_point,larval_vpn->gre.key_enabled,larval_vpn->gre.key);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SETUP_LARVAL_VPN_ERR,"xxxE",larval_vpn,ikesa,rlm,err);
	return err;
}

int rhp_ikev2_ike_auth_r_setup_nhrp(rhp_vpn* larval_vpn,
		rhp_vpn_realm* rlm,rhp_ikesa* ikesa)
{
  int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_R_SETUP_NHRP,"xxx",larval_vpn,ikesa,rlm);

	rhp_ikev2_id_dump("rlm->my_auth.my_id",&(rlm->my_auth.my_id));
	rhp_ikev2_id_dump("larval_vpn->peer_id",&(larval_vpn->peer_id));


  larval_vpn->nhrp.role = rlm->nhrp.service;
  larval_vpn->nhrp.dmvpn_enabled = rlm->nhrp.dmvpn_enabled;

  if( rlm->nhrp.key ){

  	larval_vpn->nhrp.key = (u8*)_rhp_malloc(rlm->nhrp.key_len);
  	if( larval_vpn->nhrp.key == NULL ){
  		RHP_BUG("");
  		err = -ENOMEM;
  		goto error;
  	}

  	memcpy(larval_vpn->nhrp.key,rlm->nhrp.key,rlm->nhrp.key_len);
  	larval_vpn->nhrp.key_len = rlm->nhrp.key_len;
  }

  if( larval_vpn->nhrp.dmvpn_enabled ){

  	if( (larval_vpn->cfg_peer == NULL || !larval_vpn->cfg_peer->is_access_point) &&
  			!rlm->is_access_point){

  		larval_vpn->nhrp.dmvpn_shortcut = 1;
  	}

  	larval_vpn->vpn_conn_idle_timeout = rlm->vpn_conn_idle_timeout;
  }

  if( rlm->nhrp.auth_tkt_enabled ){

  	if( (larval_vpn->cfg_peer == NULL || !larval_vpn->cfg_peer->is_access_point) &&
  			!rlm->is_access_point){

  		larval_vpn->auth_ticket.conn_type = RHP_AUTH_TKT_CONN_TYPE_SPOKE2SPOKE;
  	}
  }

  larval_vpn->gre.key_enabled = rlm->gre.key_enabled;
	if( larval_vpn->gre.key_enabled ){
		larval_vpn->gre.key = rlm->gre.key;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_R_SETUP_NHRP_RTRN,"xxxuxxddbdbbxdddup",larval_vpn,ikesa,rlm,larval_vpn->vpn_realm_id,larval_vpn->rlm,larval_vpn->cfg_peer,larval_vpn->nhrp.role,larval_vpn->nhrp.dmvpn_enabled,larval_vpn->nhrp.dmvpn_shortcut,larval_vpn->vpn_conn_idle_timeout,larval_vpn->auth_ticket.conn_type,rlm->nhrp.auth_tkt_enabled,larval_vpn->cfg_peer,(larval_vpn->cfg_peer ? larval_vpn->cfg_peer->is_access_point : 0),rlm->is_access_point,larval_vpn->gre.key_enabled,larval_vpn->gre.key,larval_vpn->nhrp.key_len,larval_vpn->nhrp.key);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_R_SETUP_NHRP_ERR,"xxxE",larval_vpn,ikesa,rlm,err);
	return err;
}


static int _rhp_ikev2_ike_auth_ipc_handle_verify_sign_rep(rhp_ipcmsg *ipcmsg)
{
  int err = -EINVAL;
  rhp_ipcmsg_verify_and_sign_rep* verify_sign_rep;
  rhp_ipcmsg_verify_rep* in_verify_rep = NULL;
  rhp_ipcmsg_sign_rep* in_sign_rep = NULL;
  rhp_ikesa* ikesa = NULL;
  rhp_vpn_realm* rlm = NULL;
  u16 notify_mesg_type = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;
  unsigned long notify_error_arg = 0;
  rhp_ikev2_mesg* rx_req_ikemesg = NULL;
  rhp_ikev2_mesg* tx_resp_ikemesg = NULL;
  rhp_vpn *old_vpn = NULL,*vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;
  void* old_vpn_ref = NULL;
  time_t ikesa_lifetime_soft,ikesa_lifetime_hard,keep_alive_interval,ikesa_lifetime_eap_larval,nat_t_keep_alive_interval;
  u8* alt_id_p;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_SIGN_REP,"x",ipcmsg);

  if( ipcmsg->len < sizeof(rhp_ipcmsg_verify_and_sign_rep) + sizeof(rhp_ipcmsg_verify_rep) ){
    RHP_BUG("%d < sizeof(rhp_ipcmsg_verify_and_sign_rep)(%d) + sizeof(rhp_ipcmsg_verify_rep)(%d)",ipcmsg->len,sizeof(rhp_ipcmsg_verify_and_sign_rep),sizeof(rhp_ipcmsg_verify_rep));
    goto error;
  }

  verify_sign_rep = (rhp_ipcmsg_verify_and_sign_rep*)ipcmsg;

  in_verify_rep = (rhp_ipcmsg_verify_rep*)(verify_sign_rep + 1);
  alt_id_p = (u8*)(in_verify_rep + 1);

  if( in_verify_rep->len < sizeof(rhp_ipcmsg_verify_rep) ){
    RHP_BUG("%d != sizeof(rhp_ipcmsg_verify_rep)(%d)",in_verify_rep->len,sizeof(rhp_ipcmsg_verify_rep));
    goto error;
  }

  if( in_verify_rep->len < (sizeof(rhp_ipcmsg_verify_rep) + in_verify_rep->alt_peer_id_len) ){
    RHP_BUG("%d < sizeof(rhp_ipcmsg_verify_rep)(%d)(2)",in_verify_rep->len,(sizeof(rhp_ipcmsg_verify_rep) + in_verify_rep->alt_peer_id_len));
    goto error;
  }

  if( in_verify_rep->result ){

    if( ipcmsg->len < sizeof(rhp_ipcmsg_verify_and_sign_rep) + in_verify_rep->len + sizeof(rhp_ipcmsg_sign_rep) ){
      RHP_BUG("%d < sizeof(rhp_ipcmsg_verify_and_sign_rep)(%d) + in_verify_rep->len(%d) + sizeof(rhp_ipcmsg_sign_rep)(%d)",ipcmsg->len,sizeof(rhp_ipcmsg_verify_and_sign_rep),in_verify_rep->len,sizeof(rhp_ipcmsg_sign_rep));
      goto error;
    }

    in_sign_rep = (rhp_ipcmsg_sign_rep*)(((u8*)in_verify_rep) + in_verify_rep->len);

    if( in_verify_rep->side != in_sign_rep->side ||
    			memcmp(in_verify_rep->spi,in_sign_rep->spi,RHP_PROTO_IKE_SPI_SIZE) ){
      RHP_BUG("");
      RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_SIGN_REP_BAD_VERIFY_SPI,"xLdLdGG",ipcmsg,"IKE_SIDE",in_verify_rep->side,"IKE_SIDE",in_sign_rep->side,in_verify_rep->spi,in_sign_rep->spi);
      goto error;
    }

    if( in_sign_rep->len < sizeof(rhp_ipcmsg_sign_rep) + in_sign_rep->signed_octets_len  ){
      RHP_BUG(" %d < sizeof(rhp_ipcmsg_sign_rep)(%d) + in_sign_rep->signed_octets_len(%d)",in_sign_rep->len,sizeof(rhp_ipcmsg_sign_rep),in_sign_rep->signed_octets_len);
      goto error;
    }
  }


  vpn_ref = rhp_vpn_ikesa_spi_get(in_verify_rep->side,in_verify_rep->spi);
  vpn = RHP_VPN_REF(vpn_ref);
  if( vpn == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_SIGN_REP_LARVAL_VPN_NOT_FOUND,"xLdG",ipcmsg,"IKE_SIDE",in_verify_rep->side,in_verify_rep->spi);
    goto error;
  }

  RHP_LOCK(&(vpn->lock));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_REP_IKESA_NOT_ACTIVE,"xxx",ipcmsg,vpn);
    goto error_vpn_l;
  }

  ikesa = vpn->ikesa_get(vpn,in_verify_rep->side,in_verify_rep->spi);
  if( ikesa == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_SIGN_REP_NO_IKESA,"xxLdG",ipcmsg,vpn,"IKE_SIDE",in_verify_rep->side,in_verify_rep->spi);
  	goto error_vpn_l;
  }

  rx_req_ikemesg = ikesa->pend_rx_ikemesg;
  ikesa->pend_rx_ikemesg = NULL;
  tx_resp_ikemesg = ikesa->pend_tx_ikemesg;
  ikesa->pend_tx_ikemesg = NULL;

  if( rx_req_ikemesg == NULL || tx_resp_ikemesg == NULL ){
  	RHP_BUG("");
  	goto error_vpn_l;
  }


  if( in_verify_rep->txn_id != ikesa->ipc_txn_id ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_SIGN_REP_REALM_BAD_ID,"xxxqq",ipcmsg,vpn,ikesa,in_verify_rep->txn_id,ikesa->ipc_txn_id);
    goto error_vpn_l;
  }

  if( !in_verify_rep->result ){
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_SIGN_REP_VERIFY_RESULT_ERR,"xxx",ipcmsg,vpn,ikesa);
    goto notify_error_vpn_l;
  }


	if( in_verify_rep->eap_role == RHP_EAP_AUTHENTICATOR &&
			in_verify_rep->eap_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS ){

		RHP_LOCK(&(rhp_eap_radius_cfg_lock));

		if( !rhp_gcfg_eap_radius->enabled ){

			RHP_UNLOCK(&(rhp_eap_radius_cfg_lock));

			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,in_verify_rep->my_realm_id,RHP_LOG_ID_RX_IKE_AUTH_REQ_RADIUS_DISABLED,"KV",rx_req_ikemesg,vpn);

			RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_SIGN_REP_RADIUS_DISABLED,"xxx",ipcmsg,vpn,ikesa);
	  	goto notify_error_vpn_l;
		}

		RHP_UNLOCK(&(rhp_eap_radius_cfg_lock));
	}


  if( in_sign_rep == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_SIGN_REP_NO_SIGN_REP,"xxx",ipcmsg,vpn,ikesa);
    goto notify_error_vpn_l;
  }

  if( in_sign_rep->txn_id != ikesa->ipc_txn_id ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_SIGN_REP_REALM_BAD_ID2,"xxxqq",ipcmsg,vpn,ikesa,in_sign_rep->txn_id,ikesa->ipc_txn_id);
    goto error_vpn_l;
  }

  if( !in_sign_rep->result ){
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_SIGN_REP_SIGN_RESULT_ERR,"xxx",ipcmsg,vpn,ikesa);
  	goto notify_error_vpn_l;
  }

  if( in_sign_rep->signed_octets_len == 0 ){
  	RHP_BUG("%d",in_sign_rep->signed_octets_len);
  	goto notify_error_vpn_l;
  }

  if( in_verify_rep->my_realm_id != in_sign_rep->my_realm_id ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_SIGN_REP_REALM_BAD_ID_3,"xxxuu",ipcmsg,vpn,ikesa,in_sign_rep->my_realm_id,in_verify_rep->my_realm_id);
    goto notify_error_vpn_l;
  }


  rlm = rhp_realm_get(in_verify_rep->my_realm_id);
  if( rlm == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_SING_REP_NO_REALM,"xxx",ipcmsg,vpn,ikesa);
    goto error_vpn_l;
  }



  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
	  RHP_UNLOCK(&(rlm->lock));
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_SIGN_REP_REALM_NOT_ACTIVE,"xxxx",ipcmsg,vpn,ikesa,rlm);
    goto notify_error_vpn_l;
  }

  err = vpn->check_cfg_address(vpn,rlm,rx_req_ikemesg->rx_pkt); // Here, MOBIKE is NOT processed yet.
  if( err ){

    RHP_UNLOCK(&(rlm->lock));

  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_SIGN_REP_CHECK_CFG_ADDR_ERR,"xxxxE",rx_req_ikemesg,rx_req_ikemesg->rx_pkt,vpn,rlm,err);

  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_unknown_if_err_packets);

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,in_verify_rep->my_realm_id,RHP_LOG_ID_RX_IKE_PKT_VIA_UNCONFIGURED_IF,"KVi",rx_req_ikemesg,vpn,rx_req_ikemesg->rx_pkt->rx_if_index);

  	err = RHP_STATUS_INVALID_IKEV2_MESG_CHECK_CFG_ADDR_ERR;
    goto notify_error_vpn_l;
  }

  RHP_UNLOCK(&(rlm->lock));


  if( in_verify_rep->eap_role == RHP_EAP_DISABLED ){

  	//
  	// For inter-op with Win8 VPN clients.
  	//
  	// Even if RSA-Sig is used for an initiator(Win8)'s auth_method, the Win8's VPN
  	// client sends an IDi payload of IPv4/v6 ID-type with the initiator(client)'s
  	// cert. Why??? (Win 8.1 fixed this problem.)
  	// Like Win7, normally, an IDi payload of subjectDN ID-type or subjectAltName's
  	// ID-types(FQDN or E-Mail) is expected when RSA-Sig is used, I think...
    // This may cause some kinds of security concerns.
    //
    // A client behind a NAT may have the same private IP address as other clients.
    // So, the IDi payload of IPv4/v6 ID-type can't be used as the client's ID value.
    // Instead, subjectDN or subjectAltName in a client's cert(a Cert Payload) is
    // used to distinguish the client's ID.
  	//
  	//
  	// Currently, this problem was fixed by Microsoft. (ID Type ==> DN)
  	//
  	//
		if( in_verify_rep->alt_peer_id_len ){

			err = rhp_ikev2_id_alt_setup(in_verify_rep->alt_peer_id_type,(void*)alt_id_p,
					in_verify_rep->alt_peer_id_len,&(vpn->peer_id));

			if( err ){
				RHP_BUG("");
		    goto notify_error_vpn_l;
			}
		}

		rhp_ikev2_id_dump("_rhp_ikev2_ike_auth_ipc_handle_verify_sign_rep",&(vpn->peer_id));


		old_vpn_ref = rhp_vpn_get(in_verify_rep->my_realm_id,&(vpn->peer_id),NULL);
		old_vpn = RHP_VPN_REF(old_vpn_ref);
		if( old_vpn ){

			RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_SIGN_REP_DESTROY_OLD_VPN,"xxxx",ipcmsg,vpn,ikesa,old_vpn);

		  RHP_UNLOCK(&(vpn->lock));


		  {
		  	RHP_LOCK(&(old_vpn->lock));

				rhp_vpn_destroy(old_vpn);

				RHP_UNLOCK(&(old_vpn->lock));
				rhp_vpn_unhold(old_vpn_ref);
				old_vpn = NULL;
		  }


		  RHP_LOCK(&(vpn->lock));

	    if( !_rhp_atomic_read(&(vpn->is_active)) ){
	      RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_SIGN_REP_IKESA_NOT_ACTIVE_2,"xx",ipcmsg,vpn);
	      err = -EINVAL;
	      goto error_vpn_l;
	    }

	    ikesa = vpn->ikesa_get(vpn,in_verify_rep->side,in_verify_rep->spi);

	    if( ikesa == NULL ){
	    	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_SIGN_REP_NO_IKESA_2,"xxLdG",ipcmsg,vpn,"IKE_SIDE",in_verify_rep->side,in_verify_rep->spi);
	      err = -EINVAL;
	    	goto error_vpn_l;
	    }

		}else{

			RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_SIGN_REP_NO_OLD_VPN,"xxx",ipcmsg,vpn,ikesa);
		}
  }



  RHP_LOCK(&(rlm->lock));

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_SIGN_REP_NET_MODE,"xxxxd",ipcmsg,vpn,ikesa,rlm,rlm->encap_mode_c);

  err = rhp_ikev2_ike_auth_setup_larval_vpn(vpn,rlm,ikesa);
	if( err ){
	  RHP_UNLOCK(&(rlm->lock));
		goto notify_error_vpn_l;
	}


	if( !rhp_ip_addr_null(&(vpn->cfg_peer->internal_addr)) ){

		rhp_ip_addr_list* peer_addr;

		peer_addr = rhp_ip_dup_addr_list(&(vpn->cfg_peer->internal_addr));
		if( peer_addr == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
		  RHP_UNLOCK(&(rlm->lock));
			goto notify_error_vpn_l;
		}
		peer_addr->ip_addr.tag = RHP_IPADDR_TAG_STATIC_PEER_ADDR;

		peer_addr->next = vpn->internal_net_info.peer_addrs;
		vpn->internal_net_info.peer_addrs = peer_addr;

		vpn->internal_net_info.static_peer_addr = 1;
	}


  ikesa->auth_method = in_sign_rep->auth_method;

  if( rhp_gcfg_ikev2_qcd_enabled && in_sign_rep->qcd_enabled ){

  	ikesa->qcd.my_token_enabled = 1;
  	memcpy(ikesa->qcd.my_token,in_sign_rep->my_qcd_token,RHP_IKEV2_QCD_TOKEN_LEN);

  }else{

  	ikesa->qcd.my_token_enabled = 0;
  }


  err = _rhp_ikev2_new_pkt_ike_auth_rep(vpn,ikesa,rx_req_ikemesg,
  				rlm,(rhp_ipcmsg*)in_sign_rep,tx_resp_ikemesg);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_SIGN_REP_ALLOC_IKEMSG_ERR,"xxxx",ipcmsg,ikesa,rlm,in_sign_rep);
	  RHP_UNLOCK(&(rlm->lock));
    goto notify_error_vpn_l;
  }

  ikesa_lifetime_soft = (time_t)rlm->ikesa.lifetime_soft;
  ikesa_lifetime_hard =  (time_t)rlm->ikesa.lifetime_hard;
  ikesa_lifetime_eap_larval = (time_t)rlm->ikesa.lifetime_eap_larval;
  keep_alive_interval = (time_t)rlm->ikesa.keep_alive_interval;
  nat_t_keep_alive_interval = (time_t)rlm->ikesa.nat_t_keep_alive_interval;


	if( in_verify_rep->eap_role == RHP_EAP_DISABLED ){

		err = rhp_ikev2_ike_auth_r_setup_nhrp(vpn,rlm,ikesa);
		if( err ){
	    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_SIGN_REP_NHRP_ERR,"xxxx",ipcmsg,ikesa,rlm,in_sign_rep);
		  RHP_UNLOCK(&(rlm->lock));
	    goto notify_error_vpn_l;
		}

		vpn->eap.role = RHP_EAP_DISABLED;
		vpn->eap.eap_method = RHP_PROTO_EAP_TYPE_NONE;

		if( ikesa->eap.pend_mesg_octets_i ){
			_rhp_free(ikesa->eap.pend_mesg_octets_i);
			ikesa->eap.pend_mesg_octets_i = NULL;
		}

		if( ikesa->eap.pend_mesg_octets_r ){
			_rhp_free(ikesa->eap.pend_mesg_octets_r);
			ikesa->eap.pend_mesg_octets_r = NULL;
		}


  	rhp_vpn_put(vpn);


		rhp_ikev2_ike_auth_setup_access_point(vpn,rlm);

		rhp_http_bus_broadcast_async(vpn->vpn_realm_id,1,1,
			rhp_ui_http_vpn_added_serialize,
			rhp_ui_http_vpn_bus_btx_async_cleanup,(void*)rhp_vpn_hold_ref(vpn)); // (*x*)

		RHP_LOG_I(RHP_LOG_SRC_VPNMNG,vpn->vpn_realm_id,RHP_LOG_ID_VPN_ADDED,"IAsNA",&(vpn->peer_id),&(vpn->peer_addr),vpn->peer_fqdn,vpn->unique_id,NULL);
  }

  vpn->vpn_conn_lifetime = (time_t)rlm->vpn_conn_lifetime;

  RHP_UNLOCK(&(rlm->lock));



	if( in_verify_rep->eap_role == RHP_EAP_AUTHENTICATOR ){

		vpn->eap.role = RHP_EAP_AUTHENTICATOR;
		vpn->eap.eap_method = vpn->eap.peer_id.method = in_verify_rep->eap_method;

    ikesa->timers->start_lifetime_timer(vpn,ikesa,ikesa_lifetime_eap_larval,1);

	}else if( in_verify_rep->eap_role == RHP_EAP_SUPPLICANT ){

		RHP_BUG("%d",in_verify_rep->eap_role);
    goto notify_error_vpn_l;

	}else if( in_verify_rep->eap_role == RHP_EAP_DISABLED ){

  	rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_ESTABLISHED);
    vpn->created_ikesas++;

  	if( ikesa->auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){
    	rhp_ikev2_g_statistics_inc(ikesa_auth_rsa_sig);
  	}else if( ikesa->auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ){
    	rhp_ikev2_g_statistics_inc(ikesa_auth_psk);
  	}else if( ikesa->auth_method == RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH ){
    	rhp_ikev2_g_statistics_inc(ikesa_auth_null_auth);
  	}


  	vpn->start_vpn_conn_life_timer(vpn);


  	rhp_http_bus_broadcast_async(vpn->vpn_realm_id,1,1,
  			rhp_ui_http_vpn_established_serialize,
  			rhp_ui_http_vpn_bus_btx_async_cleanup,(void*)rhp_vpn_hold_ref(vpn)); // (*x*)


		ikesa->established_time = _rhp_get_time();
  	ikesa->expire_hard = ikesa->established_time + ikesa_lifetime_hard;
  	ikesa->expire_soft = ikesa->established_time + ikesa_lifetime_soft;

  	{
			vpn->established = 1;

			if( vpn->connecting ){
				vpn->connecting = 0;
				rhp_ikesa_half_open_sessions_dec();
			}
  	}

  	vpn->auto_reconnect_retries = 0;

		ikesa->timers->start_lifetime_timer(vpn,ikesa,ikesa_lifetime_soft,1);
		ikesa->timers->start_keep_alive_timer(vpn,ikesa,keep_alive_interval);
		ikesa->timers->start_nat_t_keep_alive_timer(vpn,ikesa,nat_t_keep_alive_interval);


		if( vpn->internal_net_info.static_peer_addr ){

			rhp_vpn_internal_route_update(vpn);
		}

	}else{
		RHP_BUG("%d",in_verify_rep->eap_role);
  }


  ikesa->busy_flag = 0;

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_RESP_VERIFY_AUTH_AND_SIGN_OK,"KVP",rx_req_ikemesg,vpn,ikesa);


  rhp_ikev2_call_next_rx_request_mesg_handlers(rx_req_ikemesg,vpn,
  		in_verify_rep->side,in_verify_rep->spi,tx_resp_ikemesg,RHP_IKEV2_MESG_HANDLER_IKESA_AUTH);


  rhp_ikev2_unhold_mesg(rx_req_ikemesg);
  rhp_ikev2_unhold_mesg(tx_resp_ikemesg);


  if( rlm ){
    rhp_realm_unhold(rlm);
  }

  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_SIGN_REP_RTRN,"xxx",ipcmsg,vpn,ikesa);
  return 0;


error_vpn_l:
  if( vpn ){
    RHP_UNLOCK(&(vpn->lock));
  }
error:
	if( in_verify_rep && !in_verify_rep->result ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_REQ_VERIFY_AUTH_ERR,"KVE",rx_req_ikemesg,vpn,err);
	}else{
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_REQ_VERIFY_AUTH_AND_SIGN_ERR,"KVE",rx_req_ikemesg,vpn,err);
	}

  if( rlm ){
    rhp_realm_unhold(rlm);
  }

	if( vpn ){
		rhp_vpn_unhold(vpn_ref);
	}

  if( rx_req_ikemesg ){
  	rhp_ikev2_unhold_mesg(rx_req_ikemesg);
  }

  if( tx_resp_ikemesg ){
  	rhp_ikev2_unhold_mesg(tx_resp_ikemesg);
  }

	rhp_ikev2_g_statistics_inc(ikesa_auth_errors);

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_VERIFY_SING_REP_ERR,"xxxxxE",ipcmsg,vpn,vpn,ikesa,rlm,err);
  return err;

notify_error_vpn_l:

	if( vpn && ikesa ){

		err = rhp_ikev2_new_pkt_ike_auth_error_notify(ikesa,tx_resp_ikemesg,0,0,
							notify_mesg_type,notify_error_arg);

		if( err == RHP_STATUS_SUCCESS ){

			rhp_ikev2_call_next_rx_request_mesg_handlers(rx_req_ikemesg,vpn,
							ikesa->side,(ikesa->side == RHP_IKE_INITIATOR ? ikesa->init_spi : ikesa->resp_spi),
							tx_resp_ikemesg,RHP_IKEV2_MESG_HANDLER_END);

			if( in_sign_rep && !in_sign_rep->result ){
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_AUTH_REQ_SIGN_AUTH_ERR_TX_ERR_NOTIFY,"KVPL",rx_req_ikemesg,vpn,ikesa,"PROTO_IKE_NOTIFY",notify_mesg_type);
			}

			if( in_verify_rep && !in_verify_rep->result ){
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_AUTH_REQ_VERIFY_AUTH_ERR_TX_ERR_NOTIFY,"KVPL",rx_req_ikemesg,vpn,ikesa,"PROTO_IKE_NOTIFY",notify_mesg_type);
			}
		}

		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
  	ikesa->timers->schedule_delete(vpn,ikesa,0);
  }

	goto error_vpn_l;
}


int rhp_ikev2_ike_auth_ipc_handle(rhp_ipcmsg *ipcmsg)
{
  int err = -EINVAL;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE,"xLu",ipcmsg,"IPC",ipcmsg->type);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_MAIN ){
    RHP_BUG("");
    return -EPERM;
  }

  switch( ipcmsg->type ){

    case RHP_IPC_SIGN_PSK_REPLY:
    case RHP_IPC_SIGN_RSASIG_REPLY:
      err = _rhp_ikev2_ike_auth_ipc_handle_sign_rep(ipcmsg);
      break;

    case RHP_IPC_VERIFY_PSK_REPLY:
    case RHP_IPC_VERIFY_RSASIG_REPLY:
      err = _rhp_ikev2_ike_auth_ipc_handle_verify_rep(ipcmsg);
      break;

    case RHP_IPC_VERIFY_AND_SIGN_REPLY:
      err = _rhp_ikev2_ike_auth_ipc_handle_verify_sign_rep(ipcmsg);
      break;

    default:
      RHP_BUG("%d",ipcmsg->type);
      goto error;
  }

error:
  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_IPC_HANDLE_RTRN,"xLuE",ipcmsg,"IPC",ipcmsg->type,err);
  return err;
}

int rhp_ikev2_ike_auth_mesg_octets(int side,rhp_ikesa* ikesa,int id_type,u8* id,int id_len,
                                           int* mesg_octets_len_r,u8** mesg_octets_r)
{
  int err = -EINVAL;
  rhp_packet* pkt;
  int pkt_len,prf_len,n_len,mesg_octets_len,id_octets_len;
  u8* p;
  u8* mesg_octets = NULL;
  u8* id_octets = NULL;
  rhp_crypto_nonce* nonce;
  rhp_proto_ike *ikeh;
  u8* nonce_val;
  u8* sk_p;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_MESG_OCTETS,"LdxLdLdpxx","IKE_SIDE",side,ikesa,"IKE_SIDE",ikesa->side,"PROTO_IKE_ID",id_type,id_len,id,mesg_octets_len_r,mesg_octets_r);

  if( rhp_ikev2_is_null_auth_id(id_type) ){
  	id = NULL;
  	id_len = 0;
  	id_type = RHP_PROTO_IKE_ID_NULL_ID;
  }

  if( side == RHP_IKE_INITIATOR ){

  	if( ikesa->side == RHP_IKE_INITIATOR ){
  		pkt = ikesa->signed_octets.ikemesg_i_1st->tx_pkt;
  	}else{
  		pkt = ikesa->signed_octets.ikemesg_i_1st->rx_pkt;
  	}

  	nonce = ikesa->nonce_r;

  }else{

  	if( ikesa->side == RHP_IKE_INITIATOR ){
  		pkt = ikesa->signed_octets.ikemesg_r_2nd->rx_pkt;
  	}else{
  		pkt = ikesa->signed_octets.ikemesg_r_2nd->tx_pkt;
  	}

  	nonce = ikesa->nonce_i;
  }

  if( pkt == NULL || nonce == NULL ){
    RHP_BUG("0x%x,0x%x",pkt,nonce);
    goto error;
  }

  if( *((u32*)pkt->app.raw) == RHP_PROTO_NON_ESP_MARKER ){
  	ikeh = (rhp_proto_ike*)(pkt->app.raw + RHP_PROTO_NON_ESP_MARKER_SZ);
  }else{
  	ikeh = pkt->app.ikeh;
  }

  pkt_len = ntohl(ikeh->len);

  if( ((u8*)ikeh) + pkt_len > pkt->end ){
    RHP_BUG("");
    goto error;
  }

  n_len =  nonce->get_nonce_len(nonce);
  prf_len = ikesa->prf->get_output_len(ikesa->prf);

  if( n_len <= 0 || prf_len <= 0 ){
    RHP_BUG("%d,%d",n_len,prf_len);
    goto error;
  }

  mesg_octets_len = pkt_len + n_len;

  if( id || (id_type == RHP_PROTO_IKE_ID_NULL_ID) ){

  	if( ikesa->key_material.len < 1 || ikesa->key_material.key_octets == NULL ){ // SK_px is needed.
  		RHP_BUG("");
  		err = -EINVAL;
  		goto error;
  	}

    id_octets_len = 4/* IDType | RESERVED | ...*/ + id_len;

    id_octets = (u8*)_rhp_malloc(id_octets_len);
    if( id_octets == NULL ){
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }

    id_octets[0] = (u8)id_type;
    id_octets[1] = 0;
    id_octets[2] = 0;
    id_octets[3] = 0;

    if( id_len ){
    	memcpy(id_octets + 4,id,id_len);
    }

    mesg_octets_len += prf_len;

  }else{

    id_octets_len = 0;
  }

  mesg_octets = (u8*)_rhp_malloc(mesg_octets_len);
  if( mesg_octets == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  p = mesg_octets;
  memcpy(p,ikeh,pkt_len);
  p += pkt_len;
  RHP_TRC_FREQ(0,RHPTRCID_IKEV2_IKE_AUTH_MESG_OCTETS_IKE_PKT,"xpp",ikesa,sizeof(rhp_proto_ike),ikeh,pkt_len,(u8*)ikeh);

  nonce_val = nonce->get_nonce(nonce);
  if( nonce_val == NULL ){
    RHP_BUG("");
    goto error;
  }

  memcpy(p,nonce_val,n_len);
  p += n_len;
  RHP_TRC_FREQ(0,RHPTRCID_IKEV2_IKE_AUTH_MESG_OCTETS_NONCE,"xp",ikesa,n_len,nonce_val);


  if( id || (id_type == RHP_PROTO_IKE_ID_NULL_ID) ){

    if( side == RHP_IKE_INITIATOR ){
      sk_p = ikesa->keys.v2.sk_pi;
    }else{
      sk_p = ikesa->keys.v2.sk_pr;
    }

    err = ikesa->prf->set_key(ikesa->prf,sk_p,ikesa->keys.v2.sk_p_len);
    if( err ){
    	RHP_BUG("%d",err);
      goto error;
    }

    err = ikesa->prf->compute(ikesa->prf,id_octets,id_octets_len,p,prf_len);
    if( err ){
    	RHP_BUG("%d",err);
      goto error;
    }
    RHP_TRC_FREQ(0,RHPTRCID_IKEV2_IKE_AUTH_MESG_OCTETS_ID,"xp",ikesa,prf_len,p);

    _rhp_free_zero(id_octets,id_octets_len);
  }

  *mesg_octets_r = mesg_octets;
  *mesg_octets_len_r = mesg_octets_len;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_MESG_OCTETS_RTRN,"LdxpLd","IKE_SIDE",side,ikesa,mesg_octets_len,mesg_octets,"PROTO_IKE_ID",id_type);
  return 0;

error:
  if( id_octets ){
    _rhp_free(id_octets);
  }
  if( mesg_octets ){
    _rhp_free(mesg_octets);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_MESG_OCTETS_ERR,"LdxLdE","IKE_SIDE",side,ikesa,"PROTO_IKE_ID",id_type,err);
  return err;
}


extern int rhp_auth_supported_prf_method(int prf_method);

static int _rhp_ikev2_ike_auth_sess_resume_sign_auth(rhp_vpn* vpn,rhp_ikesa* ikesa,
		int mesg_octets_len,u8* mesg_octets,int* auth_data_len,u8** auth_data)
{
	int err = -EINVAL;
  rhp_crypto_prf* prf = NULL;
  unsigned int result = 0;
  u8* signed_octets = NULL;
  int signed_octets_len = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SESS_RESUME_SIGN_AUTH,"xxpxx",vpn,ikesa,mesg_octets_len,mesg_octets,auth_data_len,auth_data);

  if( rhp_auth_supported_prf_method(ikesa->prf->alg) ){
    RHP_BUG("%d",ikesa->prf->alg);
    goto error;
  }

  prf  = rhp_crypto_prf_alloc(ikesa->prf->alg);
  if( prf == NULL ){
    RHP_BUG("");
    goto error;
  }


  if( ikesa->side == RHP_IKE_INITIATOR ){

    if( prf->set_key(prf,ikesa->keys.v2.sk_pi,ikesa->keys.v2.sk_p_len) ){
    	RHP_BUG("");
      goto error;
    }

  }else{

  	if( prf->set_key(prf,ikesa->keys.v2.sk_pr,ikesa->keys.v2.sk_p_len) ){
    	RHP_BUG("");
      goto error;
    }
  }


  signed_octets_len = prf->get_output_len(prf);

  signed_octets = (u8*)_rhp_malloc(signed_octets_len);
  if( signed_octets == NULL ){
    RHP_BUG("");
    goto error;
  }

  if( prf->compute(prf,mesg_octets,mesg_octets_len,signed_octets,signed_octets_len) ){
    RHP_BUG("");
    goto error;
  }

  *auth_data_len = signed_octets_len;
  *auth_data = signed_octets;
  result = 1;

  signed_octets = NULL;
  signed_octets_len = 0;

error:
  if( prf ){
    rhp_crypto_prf_free(prf);
  }
  if( signed_octets ){
    _rhp_free_zero(signed_octets,signed_octets_len);
  }

  err = ( result ? 0 : -EINVAL);

  if( result ){
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SESS_RESUME_SIGN_AUTH_RTRN,"xxppd",vpn,ikesa,*auth_data_len,*auth_data,mesg_octets_len,mesg_octets,result);
  }else{
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SESS_RESUME_SIGN_AUTH_ERR,"xxdE",vpn,ikesa,result,err);
  }
  return err;
}

static int _rhp_ikev2_ike_auth_sess_resume_req(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ikev2_mesg* tx_req_ikemesg)
{
  int err = -EINVAL;
  rhp_vpn_sess_resume_material* material_i;
  u8* id_i = NULL;
  int id_i_len = 0;
  int id_i_type = 0;
  u8 *mesg_octets_i = NULL, *auth_i = NULL;
  int mesg_octets_i_len = 0, auth_i_len = 0;
  rhp_vpn_realm* rlm = NULL;
  time_t lifetime_larval;
  int eap_sup_enabled = 0;

  if( !ikesa->gen_by_sess_resume ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  if( ikesa->sess_resume.init.material == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }
  material_i = ikesa->sess_resume.init.material;


  err = rhp_ikev2_id_value(&(material_i->my_id_i),&id_i,&id_i_len,&id_i_type);
  if( err ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }


  ikesa->auth_method = RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY;


  {
		err = rhp_ikev2_ike_auth_mesg_octets(RHP_IKE_INITIATOR,ikesa,
						id_i_type,id_i,id_i_len,&mesg_octets_i_len,&mesg_octets_i);
		if( err ){
			goto error;
		}

		err = _rhp_ikev2_ike_auth_sess_resume_sign_auth(vpn,ikesa,mesg_octets_i_len,mesg_octets_i,&auth_i_len,&auth_i);
		if( err ){
			goto error;
		}
	}


  rlm = vpn->rlm;
  if( rlm == NULL ){
    goto error;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
    RHP_UNLOCK(&(rlm->lock));
    goto error;
  }

	lifetime_larval = (time_t)rlm->ikesa.lifetime_larval;

  eap_sup_enabled = rhp_eap_sup_impl_is_enabled(rlm,NULL);

	err = _rhp_ikev2_new_pkt_ike_auth_sess_resume_req(vpn,ikesa,rlm,
			material_i,auth_i_len,auth_i,
			id_i_type,id_i_len,id_i,ikesa->signed_octets.ikemesg_r_2nd,tx_req_ikemesg);
  if( err ){
    RHP_UNLOCK(&(rlm->lock));
    goto error;
  }

  RHP_UNLOCK(&(rlm->lock));


  if( eap_sup_enabled ){
  	vpn->eap.role = RHP_EAP_SUPPLICANT;
  }else{
  	vpn->eap.role = RHP_EAP_DISABLED;
  }


  rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_I_AUTH_SENT);
  ikesa->timers->start_lifetime_timer(vpn,ikesa,lifetime_larval,1);

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_SESS_RESUME_REQ_OK,"VP",vpn,ikesa);

	_rhp_free(id_i);
	_rhp_free(mesg_octets_i);

	return 0;

error:

	if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
	}

	if( id_i ){
		_rhp_free(id_i);
	}

	if( mesg_octets_i ){
		_rhp_free_zero(mesg_octets_i,mesg_octets_i_len);
	}

	if( auth_i ){
		_rhp_free(auth_i);
	}

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_SESS_RESUME_REQ_ERR,"VE",vpn,err);

	rhp_ikev2_g_statistics_inc(ikesa_auth_sess_resume_errors);

	return err;
}

static int _rhp_ikev2_ike_create_auth_req(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ikev2_mesg* tx_req_ikemesg)
{
  int err = -EINVAL;
  u8* mesg_octets = NULL;
  int mesg_octets_len = 0;
  rhp_ipcmsg* sign_req = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_CREATE_AUTH_REQ,"xxxxx",rx_resp_ikemesg,tx_req_ikemesg,vpn,ikesa,vpn->rlm);


  err = rhp_ikev2_ike_auth_mesg_octets(RHP_IKE_INITIATOR,ikesa,0,NULL,0,&mesg_octets_len,&mesg_octets);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_CREATE_AUTH_REQ_GET_MESG_OCTETS_ERR,"xxxd",rx_resp_ikemesg,vpn,ikesa,err);
    goto error;
  }

  err = rhp_ikev2_ike_auth_ipc_sign_req(rx_resp_ikemesg,
  				vpn->vpn_realm_id,ikesa,mesg_octets_len,mesg_octets,
  				ikesa->keys.v2.sk_p_len,ikesa->keys.v2.sk_pi,0,NULL,&sign_req,1);

  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_CREATE_AUTH_REQ_SING_REQ_ERR,"xxxd",rx_resp_ikemesg,vpn,ikesa,err);
    goto error;
  }

  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)sign_req,sign_req->len,0) < 0 ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  ikesa->pend_rx_ikemesg = rx_resp_ikemesg;
  rhp_ikev2_hold_mesg(rx_resp_ikemesg);

  ikesa->pend_tx_ikemesg = tx_req_ikemesg;
  rhp_ikev2_hold_mesg(tx_req_ikemesg);

  ikesa->busy_flag = 1;

  _rhp_free_zero(sign_req,sign_req->len);

  ikesa->eap.pend_mesg_octets_i_len = mesg_octets_len;
  ikesa->eap.pend_mesg_octets_i = mesg_octets;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_CREATE_AUTH_REQ_RTRN,"xxx",rx_resp_ikemesg,vpn,ikesa);
  return RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;

error:
	if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
	}
  if( mesg_octets ){
    _rhp_free_zero(mesg_octets,mesg_octets_len);
  }
  if( sign_req ){
  	_rhp_free_zero(sign_req,sign_req->len);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_IKE_CREATE_AUTH_REQ_ERR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
  return err;
}

static int _rhp_ikev2_ike_auth_srch_id_sess_resume_ck(rhp_ikev2_mesg* rx_ikemesg,u8 payload_id,
		rhp_ike_auth_srch_plds_ctx* s_pld_ctx,rhp_ikev2_id* id)
{
	int err = -EINVAL;
	rhp_ikev2_sess_resume_tkt_e* sess_res_tkt_e = NULL;
	u8 *tkt_id_i = NULL, *tkt_id_r = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_ID_SESS_RESUME_CK,"xLbxx",rx_ikemesg,"PROTO_IKE_PAYLOAD",payload_id,s_pld_ctx,id);

	if( s_pld_ctx->ikesa->sess_resume.resp.dec_tkt_ipc_rep == NULL ){

		RHP_BUG("");

		err = RHP_STATUS_INVALID_MSG;
		goto error;
	}

	err =  rhp_ikev2_sess_resume_dec_tkt_vals(
					(rhp_ikev2_sess_resume_tkt*)(s_pld_ctx->ikesa->sess_resume.resp.dec_tkt_ipc_rep + 1),
					&sess_res_tkt_e,NULL,&tkt_id_i,NULL,&tkt_id_r,NULL,NULL,NULL);
	if( err ){
	  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_ID_SESS_RESUME_CK_GET_TKT_VALS_ERR,"xE",rx_ikemesg,err);
		goto error;
	}

  if( payload_id == RHP_PROTO_IKE_PAYLOAD_ID_I ){

		// Actually, s_pld_ctx->id_i_type is RHP_PROTO_IKE_ID_PRIVATE_NULL_ID_WITH_ADDR.
  	if( rhp_ikev2_is_null_auth_id(s_pld_ctx->id_i_type) ){

    	if( sess_res_tkt_e->id_i_type != RHP_PROTO_IKE_ID_NULL_ID ||
  				(int)ntohs(sess_res_tkt_e->id_i_len) ){

    	  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_ID_SESS_RESUME_CK_ID_I_NULL_AUTH_ERR,"xLdLdpp",rx_ikemesg,"PROTO_IKE_ID",sess_res_tkt_e->id_i_type,"PROTO_IKE_ID",s_pld_ctx->id_i_type,ntohs(sess_res_tkt_e->id_i_len),tkt_id_i,s_pld_ctx->id_i_len,s_pld_ctx->id_i);
    	  RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_INVALID_SESS_RESUME_ID_I,"KI",rx_ikemesg,id);

  			s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;

  			err = RHP_STATUS_INVALID_MSG;
  			goto error;
  		}

  	}else{

    	if( (int)sess_res_tkt_e->id_i_type != s_pld_ctx->id_i_type ||
  				(int)ntohs(sess_res_tkt_e->id_i_len) != s_pld_ctx->id_i_len ||
  				memcmp(tkt_id_i,s_pld_ctx->id_i,s_pld_ctx->id_i_len) ){

    	  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_ID_SESS_RESUME_CK_ID_I_ERR,"xLdLdpp",rx_ikemesg,"PROTO_IKE_ID",sess_res_tkt_e->id_i_type,"PROTO_IKE_ID",s_pld_ctx->id_i_type,ntohs(sess_res_tkt_e->id_i_len),tkt_id_i,s_pld_ctx->id_i_len,s_pld_ctx->id_i);
    	  RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_INVALID_SESS_RESUME_ID_I,"KI",rx_ikemesg,id);

  			s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;

  			err = RHP_STATUS_INVALID_MSG;
  			goto error;
  		}
  	}


  }else if( payload_id == RHP_PROTO_IKE_PAYLOAD_ID_R ){

		// Actually, s_pld_ctx->id_r_type is RHP_PROTO_IKE_ID_PRIVATE_NULL_ID_WITH_ADDR.
  	if( rhp_ikev2_is_null_auth_id(s_pld_ctx->id_r_type) ){

    	if( sess_res_tkt_e->id_r_type != RHP_PROTO_IKE_ID_NULL_ID ||
  				(int)ntohs(sess_res_tkt_e->id_r_len) ){

    	  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_ID_SESS_RESUME_CK_ID_R_NULL_AUTH_ERR,"xLdLdpp",rx_ikemesg,"PROTO_IKE_ID",sess_res_tkt_e->id_r_type,"PROTO_IKE_ID",s_pld_ctx->id_r_type,ntohs(sess_res_tkt_e->id_r_len),tkt_id_r,s_pld_ctx->id_r_len,s_pld_ctx->id_r);
  			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_INVALID_SESS_RESUME_ID_R,"KI",rx_ikemesg,id);

  			s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;

  			err = RHP_STATUS_INVALID_MSG;
  			goto error;
  		}

  	}else{

    	if( (int)sess_res_tkt_e->id_r_type != s_pld_ctx->id_r_type ||
  				(int)ntohs(sess_res_tkt_e->id_r_len) != s_pld_ctx->id_r_len ||
  				memcmp(tkt_id_r,s_pld_ctx->id_r,s_pld_ctx->id_r_len) ){

    	  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_ID_SESS_RESUME_CK_ID_R_ERR,"xLdLdpp",rx_ikemesg,"PROTO_IKE_ID",sess_res_tkt_e->id_r_type,"PROTO_IKE_ID",s_pld_ctx->id_r_type,ntohs(sess_res_tkt_e->id_r_len),tkt_id_r,s_pld_ctx->id_r_len,s_pld_ctx->id_r);
  			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_INVALID_SESS_RESUME_ID_R,"KI",rx_ikemesg,id);

  			s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;

  			err = RHP_STATUS_INVALID_MSG;
  			goto error;
  		}
  	}


	}else{

		RHP_BUG("%d",payload_id);
  	err = -EINVAL;
  	goto error;
  }

	return 0;

error:
	return err;
}

static int _rhp_ikev2_ike_auth_srch_null_id(rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_payload* payload,
		rhp_vpn* vpn,int* id_len_p,int* id_type_p,u8** id_p,u8** id_impl_p_r)
{
	int err = -EINVAL;
  u8 payload_id = payload->get_payload_id(payload);
  u8* id_impl = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_ID_NULL_ID,"xxxxxxx",rx_ikemesg,payload,vpn,id_len_p,id_type_p,id_p,id_impl_p_r);

	if( *id_len_p || *id_p ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_ID_NULL_ID_BAD_VAL,"xdx",rx_ikemesg,*id_len_p,*id_p);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
	}

	if( rx_ikemesg->rx_pkt == NULL ){
		RHP_BUG("");
    err = -EINVAL;
    goto error;
	}

	id_impl = (u8*)_rhp_malloc(sizeof(rhp_ip_addr));
	if( id_impl == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memset(id_impl,0,sizeof(rhp_ip_addr));

	if( rx_ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE ){

		((rhp_ip_addr*)id_impl)->addr_family = AF_INET;

		if( vpn->origin_side == RHP_IKE_RESPONDER &&
				rx_ikemesg->is_request(rx_ikemesg) ){

			if( payload_id == RHP_PROTO_IKE_PAYLOAD_ID_I ){

				((rhp_ip_addr*)id_impl)->addr.v4 = rx_ikemesg->rx_pkt->l3.iph_v4->src_addr;
				((rhp_ip_addr*)id_impl)->port = rx_ikemesg->rx_pkt->l4.udph->src_port;

			}else if( payload_id == RHP_PROTO_IKE_PAYLOAD_ID_R ){

				((rhp_ip_addr*)id_impl)->addr.v4 = rx_ikemesg->rx_pkt->l3.iph_v4->dst_addr;
				((rhp_ip_addr*)id_impl)->port = rx_ikemesg->rx_pkt->l4.udph->dst_port;

			}else{
				err = RHP_STATUS_INVALID_MSG;
				goto error;
			}

		}else if( vpn->origin_side == RHP_IKE_INITIATOR &&
							rx_ikemesg->is_response(rx_ikemesg) &&
							payload_id == RHP_PROTO_IKE_PAYLOAD_ID_R ){

			((rhp_ip_addr*)id_impl)->addr.v4 = rx_ikemesg->rx_pkt->l3.iph_v4->src_addr;
			((rhp_ip_addr*)id_impl)->port = rx_ikemesg->rx_pkt->l4.udph->src_port;

		}else{
			err = RHP_STATUS_INVALID_MSG;
			goto error;
		}

	}else if( rx_ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE ){

		((rhp_ip_addr*)id_impl)->addr_family = AF_INET6;

		if( rx_ikemesg->is_initiator(rx_ikemesg) && rx_ikemesg->is_request(rx_ikemesg) ){

			if( payload_id == RHP_PROTO_IKE_PAYLOAD_ID_I ){

				memcpy(((rhp_ip_addr*)id_impl)->addr.v6,rx_ikemesg->rx_pkt->l3.iph_v6->src_addr,16);
				((rhp_ip_addr*)id_impl)->port = rx_ikemesg->rx_pkt->l4.udph->src_port;

			}else if( payload_id == RHP_PROTO_IKE_PAYLOAD_ID_R ){

				memcpy(((rhp_ip_addr*)id_impl)->addr.v6,rx_ikemesg->rx_pkt->l3.iph_v6->dst_addr,16);
				((rhp_ip_addr*)id_impl)->port = rx_ikemesg->rx_pkt->l4.udph->dst_port;

			}else{
				err = RHP_STATUS_INVALID_MSG;
				goto error;
			}

		}else if( rx_ikemesg->is_responder(rx_ikemesg) && rx_ikemesg->is_response(rx_ikemesg) &&
							payload_id == RHP_PROTO_IKE_PAYLOAD_ID_R ){

			memcpy(((rhp_ip_addr*)id_impl)->addr.v6,rx_ikemesg->rx_pkt->l3.iph_v6->src_addr,16);
			((rhp_ip_addr*)id_impl)->port = rx_ikemesg->rx_pkt->l4.udph->src_port;

		}else{
			err = RHP_STATUS_INVALID_MSG;
			goto error;
		}

	}else{

		RHP_BUG("%d",rx_ikemesg->rx_pkt->type);
    err = -EINVAL;
    goto error;
	}

	*id_type_p = RHP_PROTO_IKE_ID_PRIVATE_NULL_ID_WITH_ADDR;
	*id_len_p = sizeof(rhp_ip_addr);
	*id_p = id_impl;
	if( id_impl_p_r ){
		*id_impl_p_r = id_impl;
	}

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_ID_NULL_ID_RTRN,"xxxddxx",rx_ikemesg,payload,vpn,*id_type_p,*id_len_p,*id_p,id_impl);
  rhp_ip_addr_dump("*id_p",(rhp_ip_addr*)*id_p);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_ID_NULL_ID_ERR,"xxxE",rx_ikemesg,payload,vpn,err);
	return err;
}

static int _rhp_ikev2_ike_auth_srch_id_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  int err = 0;
  rhp_ike_auth_srch_plds_ctx* s_pld_ctx = (rhp_ike_auth_srch_plds_ctx*)ctx;
  rhp_ikev2_id_payload* id_payload = (rhp_ikev2_id_payload*)payload->ext.id;
  u8 payload_id = payload->get_payload_id(payload);

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_ID_CB,"xdxxx",rx_ikemesg,enum_end,payload,id_payload,ctx);

  if( id_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_ID_CB_DUP_ERR,"xx",rx_ikemesg,payload);
    return RHP_STATUS_INVALID_MSG;
  }

  if( payload_id == RHP_PROTO_IKE_PAYLOAD_ID_I ){

  	rhp_ikev2_id id_i;
	  memset(&id_i,0,sizeof(rhp_ikev2_id));

  	s_pld_ctx->id_i_type = id_payload->get_id_type(payload);
  	s_pld_ctx->id_i_len= id_payload->get_id_len(payload);
  	s_pld_ctx->id_i = id_payload->get_id(payload);

  	if( s_pld_ctx->id_i_type == RHP_PROTO_IKE_ID_NULL_ID ){ // Don't use rhp_ikev2_is_null_auth_id().

  		err = _rhp_ikev2_ike_auth_srch_null_id(rx_ikemesg,payload,RHP_VPN_REF(s_pld_ctx->vpn_ref),
  						&(s_pld_ctx->id_i_len),&(s_pld_ctx->id_i_type),&(s_pld_ctx->id_i),&(s_pld_ctx->id_i_impl));
  		if( err ){
  	    goto error;
  		}

  	}else if( s_pld_ctx->id_i_len == 0 || s_pld_ctx->id_i == NULL ){
	    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_ID_CB_I_BAD_ID,"xxxdx",rx_ikemesg,RHP_VPN_REF(s_pld_ctx->vpn_ref),s_pld_ctx->ikesa,s_pld_ctx->id_i_len,s_pld_ctx->id_i);
	    err = RHP_STATUS_INVALID_MSG;
	    goto error;
	  }


	  {
			err = rhp_ikev2_id_setup(s_pld_ctx->id_i_type,s_pld_ctx->id_i,s_pld_ctx->id_i_len,&id_i);
			if( err ){
				RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_ID_CB_I_BAD_ID2,"xxxdx",rx_ikemesg,RHP_VPN_REF(s_pld_ctx->vpn_ref),s_pld_ctx->ikesa,s_pld_ctx->id_i_len,s_pld_ctx->id_i);
				err = RHP_STATUS_INVALID_MSG;
				goto error;
			}

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_PARSE_ID_I_PAYLOAD,"KI",rx_ikemesg,&id_i);

			if( rhp_gcfg_ikev2_sess_resume_resp_enabled &&
					((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->origin_side == RHP_IKE_RESPONDER &&
					((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->sess_resume.gen_by_sess_resume ){

				err = _rhp_ikev2_ike_auth_srch_id_sess_resume_ck(rx_ikemesg,payload_id,s_pld_ctx,&id_i);
				if( err ){
					goto error;
				}
			}

			rhp_ikev2_id_clear(&id_i);
	  }

		s_pld_ctx->id_i_payload = payload;


	}else if( payload_id == RHP_PROTO_IKE_PAYLOAD_ID_R ){

		rhp_ikev2_id id_r;
	  memset(&id_r,0,sizeof(rhp_ikev2_id));

		s_pld_ctx->id_r_type = id_payload->get_id_type(payload);
		s_pld_ctx->id_r_len= id_payload->get_id_len(payload);
		s_pld_ctx->id_r = id_payload->get_id(payload);

  	if( s_pld_ctx->id_r_type == RHP_PROTO_IKE_ID_NULL_ID ){ // Don't use rhp_ikev2_is_null_auth_id().

  		err = _rhp_ikev2_ike_auth_srch_null_id(rx_ikemesg,payload,RHP_VPN_REF(s_pld_ctx->vpn_ref),
  						&(s_pld_ctx->id_r_len),&(s_pld_ctx->id_r_type),&(s_pld_ctx->id_r),&(s_pld_ctx->id_r_impl));
  		if( err ){
  	    goto error;
  		}

  	}else if( s_pld_ctx->id_r_len == 0 || s_pld_ctx->id_r == NULL ){
	    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_ID_CB_R_BAD_ID,"xxxdx",rx_ikemesg,RHP_VPN_REF(s_pld_ctx->vpn_ref),s_pld_ctx->ikesa,s_pld_ctx->id_r_len,s_pld_ctx->id_r);
	    err = RHP_STATUS_INVALID_MSG;
	    goto error;
	  }


	  {
			err = rhp_ikev2_id_setup(s_pld_ctx->id_r_type,s_pld_ctx->id_r,s_pld_ctx->id_r_len,&id_r);
			if( err ){
				RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_ID_CB_R_BAD_ID2,"xxxdx",rx_ikemesg,RHP_VPN_REF(s_pld_ctx->vpn_ref),s_pld_ctx->ikesa,s_pld_ctx->id_r_len,s_pld_ctx->id_r);
				err = RHP_STATUS_INVALID_MSG;
				goto error;
			}

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_PARSE_ID_R_PAYLOAD,"KI",rx_ikemesg,&id_r);

			if( rhp_gcfg_ikev2_sess_resume_resp_enabled &&
					((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->origin_side == RHP_IKE_RESPONDER &&
					((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->sess_resume.gen_by_sess_resume ){

				err = _rhp_ikev2_ike_auth_srch_id_sess_resume_ck(rx_ikemesg,payload_id,s_pld_ctx,&id_r);
				if( err ){
					goto error;
				}
			}

			rhp_ikev2_id_clear(&id_r);
	  }

		s_pld_ctx->id_r_payload = payload;

	}else{
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_ID_CB_RTRN,"xxE",rx_ikemesg,payload,err);
  return err;
}

static int _rhp_ikev2_ike_auth_srch_auth_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_ikev2_auth_payload* auth_payload = (rhp_ikev2_auth_payload*)payload->ext.id;
  rhp_ike_auth_srch_plds_ctx* s_pld_ctx = (rhp_ike_auth_srch_plds_ctx*)ctx;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_AUTH_CB,"xdxxx",rx_ikemesg,enum_end,payload,auth_payload,ctx);

  if( auth_payload == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_AUTH_CB_DUP_ERR,"xx",rx_ikemesg,payload);
    return RHP_STATUS_INVALID_MSG;
  }

  s_pld_ctx->peer_auth_method = auth_payload->get_auth_method(payload);
  s_pld_ctx->peer_auth_octets_len = auth_payload->get_auth_data_len(payload);
  s_pld_ctx->peer_auth_octets = auth_payload->get_auth_data(payload);

  s_pld_ctx->auth_payload = payload;

 	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_PARSE_AUTH_PAYLOAD,"KLd",rx_ikemesg,"PROTO_IKE_AUTHMETHOD",(int)s_pld_ctx->peer_auth_method,s_pld_ctx->peer_auth_octets_len);


 	if( s_pld_ctx->peer_auth_method != RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG 	 &&
 			s_pld_ctx->peer_auth_method != RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY &&
 			s_pld_ctx->peer_auth_method != RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH ){

	 	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_PARSE_UNSUP_AUTH_METHOD,"KLd",rx_ikemesg,"PROTO_IKE_AUTHMETHOD",(int)s_pld_ctx->peer_auth_method,s_pld_ctx->peer_auth_octets_len);
		s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;

		err = RHP_STATUS_INVALID_MSG;
		goto error;
 	}


	if( (rhp_gcfg_ikev2_sess_resume_resp_enabled || rhp_gcfg_ikev2_sess_resume_init_enabled) &&
			((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->sess_resume.gen_by_sess_resume ){

		if( s_pld_ctx->peer_auth_method != RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ){

		 	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_PARSE_INVALID_SESS_RESUME_AUTH,"KLd",rx_ikemesg,"PROTO_IKE_AUTHMETHOD",(int)s_pld_ctx->peer_auth_method,s_pld_ctx->peer_auth_octets_len);

			s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;

			err = RHP_STATUS_INVALID_MSG;
			goto error;
		}

	}else if( ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->origin_side == RHP_IKE_RESPONDER &&
						rhp_ikev2_is_null_auth_id(s_pld_ctx->id_i_type) &&
						s_pld_ctx->peer_auth_method != RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH ){

	 	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_PARSE_INVALID_NULL_ID_I_AUTH,"KLd",rx_ikemesg,"PROTO_IKE_AUTHMETHOD",(int)s_pld_ctx->peer_auth_method,s_pld_ctx->peer_auth_octets_len);

		s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;

		err = RHP_STATUS_INVALID_MSG;
		goto error;

	}else if( ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->origin_side == RHP_IKE_INITIATOR &&
						rhp_ikev2_is_null_auth_id(s_pld_ctx->id_r_type) &&
						s_pld_ctx->peer_auth_method != RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH ){

	 	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_PARSE_INVALID_NULL_ID_R_AUTH,"KLd",rx_ikemesg,"PROTO_IKE_AUTHMETHOD",(int)s_pld_ctx->peer_auth_method,s_pld_ctx->peer_auth_octets_len);

		s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;

		err = RHP_STATUS_INVALID_MSG;
		goto error;
	}

  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_AUTH_CB_RTRN,"xxE",rx_ikemesg,payload,err);
  return err;
}


static int _rhp_ikev2_ike_auth_srch_cert_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_ike_auth_srch_plds_ctx* s_pld_ctx = (rhp_ike_auth_srch_plds_ctx*)ctx;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_CERT_CB,"xdxu",rx_ikemesg,enum_end,payload,s_pld_ctx->dup_flag);

  if( enum_end ){

  	if( s_pld_ctx->cert_payload_head ){

  	 	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_PARSE_CERT_PAYLOADS,"Kd",rx_ikemesg,s_pld_ctx->cert_payload_num);

  	}else{

  		RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_CERT_CB_NO_CERT_PLD,"xx",rx_ikemesg,s_pld_ctx->ikesa);
  	 	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_NO_CERT_PAYLOAD,"K",rx_ikemesg);
    }

  }else{

  	rhp_ikev2_cert_payload* cert_payload = (rhp_ikev2_cert_payload*)payload->ext.cert;
  	rhp_ikev2_payload* cert_payload_head = NULL;
  	u8 enc;
    int my_side;

  	if( cert_payload == NULL ){
    	RHP_BUG("");
    	return -EINVAL;
    }

    my_side = (rx_ikemesg->is_initiator(rx_ikemesg) ? RHP_IKE_RESPONDER : RHP_IKE_INITIATOR);

	  enc = cert_payload->get_cert_encoding(payload);

	  if( enc == RHP_PROTO_IKE_CERTENC_X509_CERT_SIG ){

	  	// OK..

	  }else if( rhp_gcfg_hash_url_enabled(my_side) &&
	  					enc == RHP_PROTO_IKE_CERTENC_X509_CERT_HASH_URL ){

			int cert_len = cert_payload->get_cert_len(payload);
			u8* p_data = cert_payload->get_cert(payload);

			// Only http is supported.
	  	if( cert_len <= (int)(RHP_IKEV2_CERT_HASH_LEN + RHP_IKEV2_CERT_HASH_URL_MIN_LEN) ||
	  			cert_len >= (int)(RHP_IKEV2_CERT_HASH_LEN + rhp_gcfg_ikev2_hash_url_max_len) ){

		  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_CERT_REQ_CB_HASH_URL_BAD_LEN,"xxxd",rx_ikemesg,RHP_VPN_REF(s_pld_ctx->vpn_ref),s_pld_ctx->ikesa,cert_len);
	  	 	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_HASH_URL_BAD_LENGTH,"Kd",rx_ikemesg,cert_len);

	  	 	goto auth_error_notify;
	  	}

	  	p_data += RHP_IKEV2_CERT_HASH_LEN;
	  	if( p_data[0] != 'h' || p_data[1] != 't' || p_data[2] != 't' || p_data[3] != 'p' ||
	  			p_data[4] != ':' || p_data[5] != '/' || p_data[6] != '/' ){

		  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_CERT_REQ_CB_HASH_URL_UNSUP_PROTO,"xxxp",rx_ikemesg,RHP_VPN_REF(s_pld_ctx->vpn_ref),s_pld_ctx->ikesa,RHP_IKEV2_CERT_HASH_URL_MIN_LEN,p_data);
	  	 	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_HASH_URL_NOT_SUPPORTED_PROTO,"Ka",rx_ikemesg,RHP_IKEV2_CERT_HASH_URL_MIN_LEN,p_data);

	  	 	goto auth_error_notify;
	  	}

	  }else{

  	 	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_NOT_SUPPORTED_CERT_ENCODING,"Kb",rx_ikemesg,enc);

auth_error_notify:
	  	s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;

	  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_CERT_REQ_CB_UNKNOWN_ENCODE,"xxxb",rx_ikemesg,RHP_VPN_REF(s_pld_ctx->vpn_ref),s_pld_ctx->ikesa,enc);

  	 	err = RHP_STATUS_IKEV2_AUTH_FAILED;
	  	goto error;
	  }

  	s_pld_ctx->dup_flag++;

  	if( s_pld_ctx->dup_flag == 1 ){ // Peer's endpoint certificate.

	  	s_pld_ctx->cert_payload_head = payload;

	  	s_pld_ctx->peer_cert_pld = rhp_ikev2_rx_cert_pld_alloc(payload,0);
	  	if( s_pld_ctx->peer_cert_pld == NULL ){
	  		RHP_BUG("");
	  		err = -ENOMEM;
	  		goto error;
	  	}

	  	s_pld_ctx->cert_payload_num++;
	  	payload->list_next = NULL;

	  }else if( s_pld_ctx->dup_flag > rhp_gcfg_max_cert_payloads ){

	    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_CERT_SRCH_CB_TOO_MANY,"xxud",rx_ikemesg,payload,s_pld_ctx->dup_flag,rhp_gcfg_max_cert_payloads);
  	 	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_TOO_MANY_CERT_PAYLOADS,"Kd",rx_ikemesg,s_pld_ctx->dup_flag);

	    goto auth_error_notify;

	  }else{ // SubCAs(Intermediate CAs) certificates.

		  if( enc == RHP_PROTO_IKE_CERTENC_X509_CERT_SIG ){

		  	s_pld_ctx->ca_certs_der_num++;

		  }else if( enc == RHP_PROTO_IKE_CERTENC_X509_CERT_HASH_URL ){

		  	s_pld_ctx->ca_certs_hash_url_num++;

		  }else{
		  	RHP_BUG("");
		  	err = -EINVAL;
  		  goto error;
		  }

	  	{
				cert_payload_head = s_pld_ctx->cert_payload_head;

				if( cert_payload_head->list_next == NULL ){
					cert_payload_head->list_next = payload;
				}else{
					cert_payload_head->list_tail->list_next = payload;
				}
				cert_payload_head->list_tail = payload;
	  	}

	  	{
	  		rhp_ikev2_rx_cert_pld* rx_cert_data = rhp_ikev2_rx_cert_pld_alloc(payload,1);
	  		if( rx_cert_data == NULL ){
	  			RHP_BUG("");
	  		  err = -ENOMEM;
	  		  goto error;
	  		}

	  		if( s_pld_ctx->ca_cert_plds_head == NULL ){
	  			s_pld_ctx->ca_cert_plds_head = rx_cert_data;
	  		}else{
	  			s_pld_ctx->ca_cert_plds_tail->next = rx_cert_data;
	  		}
	  		s_pld_ctx->ca_cert_plds_tail = rx_cert_data;
	  	}

	  	s_pld_ctx->cert_payload_num++;
	  }
  }

  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_CERT_SRCH_CB_RTRN,"xxdddE",rx_ikemesg,payload,s_pld_ctx->dup_flag,s_pld_ctx->cert_payload_num,s_pld_ctx->ca_certs_der_num,s_pld_ctx->ca_certs_hash_url_num,err);
  return err;
}

static int _rhp_ikev2_ike_auth_srch_n_error_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_ike_auth_srch_plds_ctx* s_pld_ctx = (rhp_ike_auth_srch_plds_ctx*)ctx;
  rhp_ikev2_n_payload* n_payload = (rhp_ikev2_n_payload*)payload->ext.n;
  u16 notify_mesg_type;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_N_ERROR_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

  if( n_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  notify_mesg_type = n_payload->get_message_type(payload);

  //
  // TODO : Handling only interested notify-error codes.
  //
  if( notify_mesg_type >= RHP_PROTO_IKE_NOTIFY_ERR_MIN && notify_mesg_type <= RHP_PROTO_IKE_NOTIFY_ERR_MAX ){

    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_N_ERROR_CB_FOUND,"xxLw",rx_ikemesg,payload,"PROTO_IKE_NOTIFY",notify_mesg_type);

    s_pld_ctx->n_error_payload = payload;
    s_pld_ctx->n_err = notify_mesg_type;

    err = RHP_STATUS_ENUM_OK;
    goto error;
  }

  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_N_ERROR_CB_RTRN,"xxE",rx_ikemesg,payload,err);
  return err;
}


int rhp_ikev2_rx_ike_auth_req_search_rlm_cand(rhp_vpn_realm* rlm,void* ctx)
{
	rhp_ike_auth_srch_plds_ctx* s_pld_ctx = (rhp_ike_auth_srch_plds_ctx*)ctx;
	rhp_cfg_peer* cfg_peer = NULL;

	RHP_LOCK(&(rlm->lock));

	cfg_peer = rlm->get_peer_by_id(rlm,s_pld_ctx->peer_id_tmp);
	if( cfg_peer && (cfg_peer->id.type != RHP_PROTO_IKE_ID_ANY) ){

		s_pld_ctx->peer_notified_realm_id = rlm->id;

		RHP_UNLOCK(&(rlm->lock));

	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_SEARCH_RLM_CAND_OK,"xxu",s_pld_ctx,rlm,rlm->id);

		return RHP_STATUS_ENUM_OK;
	}

	RHP_UNLOCK(&(rlm->lock));

	return 0;
}

// Caller must NOT free *spk2spk_session_key_r.
static int _rhp_ikev2_ike_auth_dec_auth_tkt_attrs(
		rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ike_auth_srch_plds_ctx* s_pld_ctx,
		unsigned long* hb2spk_vpn_realm_id_r,
		int* spk2spk_session_key_len_r,u8** spk2spk_session_key_r)
{
	int err = -EINVAL;
	rhp_ikev2_n_auth_tkt_attr* auth_tkt_attr;
	u8* attr_val = NULL;
	int attr_val_len = 0;
	u16 attr_sub_type;
	rhp_ikev2_id init_id;
	unsigned long hb2spk_vpn_realm_id = s_pld_ctx->n_auth_tkt_payload->hb2spk_vpn_realm_id;
	int spk2spk_session_key_len = 0;
	u8* spk2spk_session_key = NULL;

	memset(&init_id,0,sizeof(rhp_ikev2_id));


	{
		auth_tkt_attr
			= s_pld_ctx->n_auth_tkt_payload->get_attr(s_pld_ctx->n_auth_tkt_payload,
					RHP_PROTO_IKEV2_AUTH_TKT_ATTR_INITIATOR_ID,0);
		if( auth_tkt_attr == NULL ){
			err = -EINVAL;
			goto error;
		}

		attr_val = auth_tkt_attr->get_attr_val(auth_tkt_attr,&attr_val_len);
		if( attr_val == NULL ){
			err = -EINVAL;
			goto error;
		}

		attr_sub_type = auth_tkt_attr->get_attr_sub_type(auth_tkt_attr);


		err = rhp_ikev2_id_setup((int)attr_sub_type,attr_val,attr_val_len,&init_id);
		if( err ){
			err = -EINVAL;
			goto error;
		}

		if( rhp_ikev2_id_cmp_by_value(&init_id,s_pld_ctx->id_i_type,s_pld_ctx->id_i_len,s_pld_ctx->id_i) ){
			err = -EINVAL;
			goto error;
		}
	}

	{
		auth_tkt_attr
			= s_pld_ctx->n_auth_tkt_payload->get_attr(s_pld_ctx->n_auth_tkt_payload,
				RHP_PROTO_IKEV2_AUTH_TKT_ATTR_SESSION_KEY,0);
		if( auth_tkt_attr == NULL ){
			err = -EINVAL;
			goto error;
		}

		spk2spk_session_key
			= auth_tkt_attr->get_attr_val(auth_tkt_attr,&spk2spk_session_key_len);
		if( spk2spk_session_key == NULL ){

			s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;

			err = -EINVAL;
			goto error;
		}
	}


	rhp_ikev2_id_clear(&init_id);

	*hb2spk_vpn_realm_id_r = hb2spk_vpn_realm_id;
	*spk2spk_session_key_len_r = spk2spk_session_key_len;
	*spk2spk_session_key_r = spk2spk_session_key;

	return 0;

error:

	rhp_ikev2_id_clear(&init_id);

	return err;
}

static int _rhp_ikev2_rx_ike_auth_req_bh(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,
		rhp_ikev2_mesg* tx_resp_ikemesg,rhp_ike_auth_srch_plds_ctx* s_pld_ctx)
{
  int err = RHP_STATUS_INVALID_MSG;
  u8 *mesg_octets_i = NULL,*mesg_octets_r = NULL;
  int mesg_octets_i_len = 0,mesg_octets_r_len = 0;
  rhp_ipcmsg *in_sign_req = NULL,*in_verify_req = NULL;
  rhp_ipcmsg_verify_and_sign_req* verify_sign_req = NULL;
  int verify_sign_req_len = 0;
  u8* rx_untrust_ca_certs = NULL;
  int rx_untrust_ca_certs_len = 0;
  int rx_untrust_ca_certs_num = s_pld_ctx->ca_certs_der_num + s_pld_ctx->ca_certs_hash_url_num;
	unsigned long hb2spk_vpn_realm_id = RHP_VPN_REALM_ID_UNKNOWN;
	int spk2spk_session_key_len = 0;
	u8* spk2spk_session_key = NULL;


  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_BH,"xxx",rx_req_ikemesg,vpn,ikesa);

  err = rhp_ikev2_id_setup(s_pld_ctx->id_i_type,s_pld_ctx->id_i,s_pld_ctx->id_i_len,&(vpn->peer_id));
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }


  if( !rhp_gcfg_dont_search_cfg_peers_for_realm_id &&
  		s_pld_ctx->peer_notified_realm_id == RHP_VPN_REALM_ID_UNKNOWN ){

  	s_pld_ctx->peer_id_tmp = &(vpn->peer_id);

  	rhp_ikev2_id_dump("auth_req_search_rlm_cand",s_pld_ctx->peer_id_tmp);

  	rhp_realm_enum(0,rhp_ikev2_rx_ike_auth_req_search_rlm_cand,(void*)s_pld_ctx);

    RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_BH_SEARCH_RLM_CAND,"xxxu",rx_req_ikemesg,vpn,ikesa,s_pld_ctx->peer_notified_realm_id);

  	s_pld_ctx->peer_id_tmp = NULL;
  }


  err = rhp_ikev2_ike_auth_mesg_octets(RHP_IKE_INITIATOR,ikesa,
  				s_pld_ctx->id_i_type,s_pld_ctx->id_i,s_pld_ctx->id_i_len,&mesg_octets_i_len,&mesg_octets_i);

	if( err ){
		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_BH_GET_MESG_OCTETS_ERR,"xxxE",rx_req_ikemesg,vpn,ikesa,err);
		goto error;
	}


  if( !s_pld_ctx->eap_used ){

  	ikesa->peer_auth_method = s_pld_ctx->peer_auth_method;

		if( s_pld_ctx->peer_auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){

  		if( s_pld_ctx->ca_cert_plds_head ){

  			err = rhp_ikev2_rx_cert_pld_merge_ders(s_pld_ctx->ca_cert_plds_head,&rx_untrust_ca_certs,&rx_untrust_ca_certs_len);
  			if( err ){
  				RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_BH_MERGED_CERT_DER_ERR,"xxxE",rx_req_ikemesg,vpn,ikesa,err);
  				goto error;
  			}
  		}

			err = rhp_ikev2_ike_auth_ipc_verify_req(RHP_IPC_VERIFY_RSASIG_REQUEST,
																			RHP_VPN_REALM_ID_UNKNOWN,ikesa,
																			s_pld_ctx->id_r_type,s_pld_ctx->id_r_len,s_pld_ctx->id_r,
																			s_pld_ctx->id_i_type,s_pld_ctx->id_i_len,s_pld_ctx->id_i,
																			mesg_octets_i_len,mesg_octets_i,
																			s_pld_ctx->peer_auth_octets_len,s_pld_ctx->peer_auth_octets,
																			s_pld_ctx->peer_cert_pld,
																			rx_untrust_ca_certs_num,rx_untrust_ca_certs_len,rx_untrust_ca_certs,
																			s_pld_ctx->peer_notified_realm_id,
																			0,NULL,
																			s_pld_ctx->peer_auth_method,
																			RHP_VPN_REALM_ID_UNKNOWN,0,NULL,
																			&in_verify_req);

			if( err ){
				RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_BH_VERIFY_REQ_ERR,"xxxE",rx_req_ikemesg,vpn,ikesa,err);
				goto error;
			}

		}else if( s_pld_ctx->peer_auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ||
							s_pld_ctx->peer_auth_method == RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH ){

			if( s_pld_ctx->n_auth_tkt_payload ){

				err = _rhp_ikev2_ike_auth_dec_auth_tkt_attrs(vpn,ikesa,s_pld_ctx,
								&hb2spk_vpn_realm_id,&spk2spk_session_key_len,&spk2spk_session_key);
				if( err ){

					s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;
					goto error;
				}

			  err = rhp_ikev2_auth_vpn_tkt_set_session_key(vpn,
			  				spk2spk_session_key_len,spk2spk_session_key,0,NULL);
				if( err ){

					goto error;
				}
			}


			err = rhp_ikev2_ike_auth_ipc_verify_req(RHP_IPC_VERIFY_PSK_REQUEST,
																					 RHP_VPN_REALM_ID_UNKNOWN,ikesa,
																					 s_pld_ctx->id_r_type,s_pld_ctx->id_r_len,s_pld_ctx->id_r,
																					 s_pld_ctx->id_i_type,s_pld_ctx->id_i_len,s_pld_ctx->id_i,
																					 mesg_octets_i_len,mesg_octets_i,
																					 s_pld_ctx->peer_auth_octets_len,s_pld_ctx->peer_auth_octets,
																					 NULL,0,0,NULL,
																					 s_pld_ctx->peer_notified_realm_id,
																					 (s_pld_ctx->peer_auth_method == RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH ? ikesa->keys.v2.sk_p_len : 0),
																					 (s_pld_ctx->peer_auth_method == RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH ? ikesa->keys.v2.sk_pi : NULL),
																					 s_pld_ctx->peer_auth_method,
																					 hb2spk_vpn_realm_id,spk2spk_session_key_len,spk2spk_session_key,
																					 &in_verify_req);

		 if( err ){
				RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_BH_VERIFY_REQ_ERR2,"xxxE",rx_req_ikemesg,vpn,ikesa,err);
				goto error;
			}

		}else{
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_BH_UNKNOWN_AUTH_METHOD,"xxxd",rx_req_ikemesg,vpn,ikesa,s_pld_ctx->peer_auth_method);
			goto error;
		}

  }else{ // EAP

		err = rhp_ikev2_ike_auth_ipc_verify_req(RHP_IPC_EAP_SUP_VERIFY_REQUEST,
																				 RHP_VPN_REALM_ID_UNKNOWN,ikesa,
																				 s_pld_ctx->id_r_type,s_pld_ctx->id_r_len,s_pld_ctx->id_r,
																				 s_pld_ctx->id_i_type,s_pld_ctx->id_i_len,s_pld_ctx->id_i,
																				 0,NULL,0,NULL,
																				 NULL,0,0,NULL,
																				 s_pld_ctx->peer_notified_realm_id,
																				 0,NULL,0,
																				 RHP_VPN_REALM_ID_UNKNOWN,0,NULL,
																				 &in_verify_req);

		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_BH_IPC_VERIFY_EAP_SUP_REQ_ERR,"xxxE",rx_req_ikemesg,vpn,ikesa,err);
			goto error;
	 	}

	 	ikesa->eap.pend_rx_ikemesg = rx_req_ikemesg;
	 	rhp_ikev2_hold_mesg(rx_req_ikemesg);
  }


  {
    err = rhp_ikev2_ike_auth_mesg_octets(RHP_IKE_RESPONDER,ikesa,0,NULL,0,&mesg_octets_r_len,&mesg_octets_r);
    if( err ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_BH_GET_MESG_OCTETS2,"xxxE",rx_req_ikemesg,vpn,ikesa,err);
      goto error;
    }

    err = rhp_ikev2_ike_auth_ipc_sign_req(rx_req_ikemesg,RHP_VPN_REALM_ID_UNKNOWN,ikesa,
									mesg_octets_r_len,mesg_octets_r,ikesa->keys.v2.sk_p_len,ikesa->keys.v2.sk_pr,
									spk2spk_session_key_len,spk2spk_session_key,&in_sign_req,0);

    if( err ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_BH_SIGN_REQ_ERR,"xxxE",rx_req_ikemesg,vpn,ikesa,err);
      goto error;
    }
  }


  {
  	u8* p;

  	verify_sign_req_len = sizeof(rhp_ipcmsg_verify_and_sign_req) + in_verify_req->len + in_sign_req->len;

  	verify_sign_req = (rhp_ipcmsg_verify_and_sign_req*)rhp_ipc_alloc_msg(RHP_IPC_VERIFY_AND_SIGN_REQUEST,verify_sign_req_len);
  	if( verify_sign_req == NULL ){
    	err = -EINVAL;
    	RHP_BUG("");
    	goto error;
    }

  	verify_sign_req->len = verify_sign_req_len;

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


  ikesa->busy_flag = 1;

  ikesa->pend_rx_ikemesg = rx_req_ikemesg;
  rhp_ikev2_hold_mesg(rx_req_ikemesg);

  ikesa->pend_tx_ikemesg = tx_resp_ikemesg;
  rhp_ikev2_hold_mesg(tx_resp_ikemesg);


  _rhp_free_zero(in_verify_req,in_verify_req->len);
  _rhp_free_zero(in_sign_req,in_sign_req->len);
  _rhp_free_zero(verify_sign_req,verify_sign_req->len);


  if( s_pld_ctx->peer_cert_pld ){

  	err = rhp_ikev2_rx_cert_pld_split_der(s_pld_ctx->peer_cert_pld,&(vpn->rx_peer_cert),&(vpn->rx_peer_cert_len));
  	if( err ){
  		RHP_BUG("%d",err);
  	}

  	rhp_ikev2_rx_cert_pld_split_hash_url(s_pld_ctx->peer_cert_pld,&(vpn->rx_peer_cert_url),
  			&(vpn->rx_peer_cert_hash),&(vpn->rx_peer_cert_hash_len));
  }

  if( rx_untrust_ca_certs ){

  	vpn->rx_untrust_ca_certs = rx_untrust_ca_certs;
  	vpn->rx_untrust_ca_certs_len = rx_untrust_ca_certs_len;
  	rx_untrust_ca_certs = NULL;
  	rx_untrust_ca_certs_len = 0;

  	vpn->rx_untrust_ca_certs_num = s_pld_ctx->ca_certs_der_num + s_pld_ctx->ca_certs_hash_url_num;
  }


  if( s_pld_ctx->eap_used ){

  	ikesa->eap.pend_mesg_octets_i_len = mesg_octets_i_len;
  	ikesa->eap.pend_mesg_octets_i = mesg_octets_i;
  	ikesa->eap.pend_mesg_octets_r_len = mesg_octets_r_len;
  	ikesa->eap.pend_mesg_octets_r = mesg_octets_r;

  }else{

  	_rhp_free(mesg_octets_i);
  	_rhp_free(mesg_octets_r);
  }

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_REQ_OK,"KVP",rx_req_ikemesg,vpn,ikesa);


  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_BH_RTRN,"xxx",rx_req_ikemesg,vpn,ikesa);

  return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_REQ_ERR,"KVPE",rx_req_ikemesg,vpn,ikesa,err);

  if( in_verify_req ){
    _rhp_free_zero(in_verify_req,in_verify_req->len);
  }

  if( in_sign_req ){
    _rhp_free_zero(in_sign_req,in_sign_req->len);
  }

  if( verify_sign_req ){
    _rhp_free_zero(verify_sign_req,verify_sign_req->len);
  }

  if( mesg_octets_i ){
    _rhp_free_zero(mesg_octets_i,mesg_octets_i_len);
  }

  if( mesg_octets_r ){
    _rhp_free_zero(mesg_octets_r,mesg_octets_r_len);
  }

  if( rx_untrust_ca_certs ){
    _rhp_free_zero(rx_untrust_ca_certs,rx_untrust_ca_certs_len);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_BH_ERR,"xxxE",rx_req_ikemesg,vpn,ikesa,err);
  return err;
}

static int _rhp_ikev2_rx_ike_auth_rep_bh(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ikev2_mesg* tx_req_ikemesg,rhp_ike_auth_srch_plds_ctx* s_pld_ctx)
{
  int err = RHP_STATUS_INVALID_MSG;
  u8* mesg_octets_r = NULL;
  int mesg_octets_r_len = 0;
  rhp_ipcmsg* verify_req = NULL;
  u8* rx_untrust_ca_certs = NULL;
  int rx_untrust_ca_certs_len = 0;
  int rx_untrust_ca_certs_num = s_pld_ctx->ca_certs_der_num + s_pld_ctx->ca_certs_hash_url_num;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_BH,"xxx",rx_resp_ikemesg,vpn,ikesa);

  {
  	ikesa->peer_auth_method = s_pld_ctx->peer_auth_method;

  	err = rhp_ikev2_ike_auth_mesg_octets(RHP_IKE_RESPONDER,ikesa,
			    		s_pld_ctx->id_r_type,s_pld_ctx->id_r,s_pld_ctx->id_r_len,&mesg_octets_r_len,&mesg_octets_r);

  	if( err ){
  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_BH_GET_MESG_OCTETS_ERR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
  		goto error;
    }


  	if( s_pld_ctx->peer_auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){

  		if( s_pld_ctx->ca_cert_plds_head ){

  			err = rhp_ikev2_rx_cert_pld_merge_ders(s_pld_ctx->ca_cert_plds_head,&rx_untrust_ca_certs,&rx_untrust_ca_certs_len);
  			if( err ){
  				RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_BH_MERGED_CERT_DER_ERR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
  				goto error;
  			}
  		}

  		err = rhp_ikev2_ike_auth_ipc_verify_req(RHP_IPC_VERIFY_RSASIG_REQUEST,
                                       vpn->vpn_realm_id,ikesa,
                                       s_pld_ctx->my_id_type,s_pld_ctx->my_id_len,s_pld_ctx->my_id_val,
                                       s_pld_ctx->id_r_type,s_pld_ctx->id_r_len,s_pld_ctx->id_r,
                                       mesg_octets_r_len,mesg_octets_r,
                                       s_pld_ctx->peer_auth_octets_len,s_pld_ctx->peer_auth_octets,
                                       s_pld_ctx->peer_cert_pld,
                                       rx_untrust_ca_certs_num,rx_untrust_ca_certs_len,rx_untrust_ca_certs,
                                       RHP_VPN_REALM_ID_UNKNOWN,
                                       0,NULL,
                                       s_pld_ctx->peer_auth_method,
                                       RHP_VPN_REALM_ID_UNKNOWN,0,NULL,
                                       &verify_req);

  		if( err ){
  			RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_BH_VERIFY_REQ_ERR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
  			goto error;
      }

  	}else if( s_pld_ctx->peer_auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ||
  						s_pld_ctx->peer_auth_method == RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH ){

  		if( vpn->auth_ticket.conn_type == RHP_AUTH_TKT_CONN_TYPE_SPOKE2SPOKE &&
  				vpn->auth_ticket.spk2spk_session_key == NULL ){
  			RHP_BUG("");
  			err = -EINVAL;
  			goto error;
  		}

  		err = rhp_ikev2_ike_auth_ipc_verify_req(RHP_IPC_VERIFY_PSK_REQUEST,
  																				 vpn->vpn_realm_id,ikesa,
  	                                       s_pld_ctx->my_id_type,s_pld_ctx->my_id_len,s_pld_ctx->my_id_val,
                                           s_pld_ctx->id_r_type,s_pld_ctx->id_r_len,s_pld_ctx->id_r,
                                           mesg_octets_r_len,mesg_octets_r,
                                           s_pld_ctx->peer_auth_octets_len,s_pld_ctx->peer_auth_octets,
                                           NULL,0,0,NULL,
                                           RHP_VPN_REALM_ID_UNKNOWN,
																					 (s_pld_ctx->peer_auth_method == RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH ? ikesa->keys.v2.sk_p_len : 0),
																					 (s_pld_ctx->peer_auth_method == RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH ? ikesa->keys.v2.sk_pr : NULL),
																					 s_pld_ctx->peer_auth_method,
																					 vpn->vpn_realm_id,
																					 vpn->auth_ticket.spk2spk_session_key_len,vpn->auth_ticket.spk2spk_session_key,
                                           &verify_req);

  		if( err ){
  			RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_BH_VERIFY_REQ_ERR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
  			goto error;
  		}

  	}else{
     err = RHP_STATUS_INVALID_MSG;
  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_BH_UNKNOW_AUTH_METHOD_ERR,"xxd",rx_resp_ikemesg,ikesa,s_pld_ctx->peer_auth_method);
    	goto error;
  	}
  }


  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)verify_req,verify_req->len,0) < 0 ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  ikesa->busy_flag = 1;

  ikesa->pend_rx_ikemesg = rx_resp_ikemesg;
  rhp_ikev2_hold_mesg(rx_resp_ikemesg);

  ikesa->pend_tx_ikemesg = tx_req_ikemesg;
  rhp_ikev2_hold_mesg(tx_req_ikemesg);

  _rhp_free_zero(verify_req,verify_req->len);


  if( s_pld_ctx->peer_cert_pld ){

  	err = rhp_ikev2_rx_cert_pld_split_der(s_pld_ctx->peer_cert_pld,&(vpn->rx_peer_cert),&(vpn->rx_peer_cert_len));
  	if( err ){
  		RHP_BUG("%d",err);
  	}

  	rhp_ikev2_rx_cert_pld_split_hash_url(s_pld_ctx->peer_cert_pld,&(vpn->rx_peer_cert_url),
  			&(vpn->rx_peer_cert_hash),&(vpn->rx_peer_cert_hash_len));
  }

  if( rx_untrust_ca_certs ){

  	vpn->rx_untrust_ca_certs = rx_untrust_ca_certs;
  	vpn->rx_untrust_ca_certs_len = rx_untrust_ca_certs_len;
  	rx_untrust_ca_certs = NULL;
  	rx_untrust_ca_certs_len = 0;

  	vpn->rx_untrust_ca_certs_num = s_pld_ctx->ca_certs_der_num + s_pld_ctx->ca_certs_hash_url_num;
  }


	if( vpn->eap.role == RHP_EAP_SUPPLICANT ){

		ikesa->eap.pend_mesg_octets_r_len = mesg_octets_r_len;
  	ikesa->eap.pend_mesg_octets_r = mesg_octets_r;

	}else{

    _rhp_free_zero(mesg_octets_r,mesg_octets_r_len);
  }


	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_RESP_OK,"KVP",rx_resp_ikemesg,vpn,ikesa);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_BH_RTRN,"xxx",rx_resp_ikemesg,vpn,ikesa);
  return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_RESP_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);

  if( verify_req ){
    _rhp_free_zero(verify_req,verify_req->len);
  }

  if( mesg_octets_r ){
    _rhp_free_zero(mesg_octets_r,mesg_octets_r_len);
  }

  if( rx_untrust_ca_certs ){
    _rhp_free_zero(rx_untrust_ca_certs,rx_untrust_ca_certs_len);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_BH_ERR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
  return err;
}


static int _rhp_ikev2_ike_auth_sess_resume_verify_auth(rhp_vpn* vpn,rhp_ikesa* ikesa,int mesg_octets_len,u8* mesg_octets,
		int peer_auth_octets_len,u8* peer_auth_octets)
{
	int err = -EINVAL;
  rhp_crypto_prf* prf = NULL;
  u8* hashed_key = NULL;
  int hashed_key_len = 0;
  u8* peer_signed_octets = NULL;
  int peer_signed_octets_len = 0;
  int result = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_SESS_RESUME_VERIFY_AUTH,"xxpp",vpn,ikesa,mesg_octets_len,mesg_octets,peer_auth_octets_len,peer_auth_octets);

  if( rhp_auth_supported_prf_method(ikesa->prf->alg) ){
    RHP_BUG("%d",ikesa->prf->alg);
    goto error;
  }

  prf = rhp_crypto_prf_alloc(ikesa->prf->alg);
  if( prf == NULL ){
    RHP_BUG("");
    goto error;
  }


  if( ikesa->side == RHP_IKE_INITIATOR ){

    if( prf->set_key(prf,ikesa->keys.v2.sk_pr,ikesa->keys.v2.sk_p_len) ){
    	RHP_BUG("");
      goto error;
    }

  }else{

  	if( prf->set_key(prf,ikesa->keys.v2.sk_pi,ikesa->keys.v2.sk_p_len) ){
    	RHP_BUG("");
      goto error;
    }
  }


  {
		peer_signed_octets_len = prf->get_output_len(prf);

		peer_signed_octets = (u8*)_rhp_malloc(peer_signed_octets_len);
		if( peer_signed_octets == NULL ){
			RHP_BUG("");
			goto error;
		}

		if( prf->compute(prf,mesg_octets,mesg_octets_len,peer_signed_octets,peer_signed_octets_len) ){
			RHP_BUG("");
			goto error;
		}

		if( peer_signed_octets_len == (int)peer_auth_octets_len &&
				!memcmp(peer_signed_octets,peer_auth_octets,peer_signed_octets_len) ){
			result = 1;
		}else{
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_SESS_RESUME_VERIFY_AUTH_OCTETS_CMP_ERR,"xxpp",vpn,ikesa,peer_signed_octets_len,peer_signed_octets,peer_auth_octets_len,peer_auth_octets);
		}
  }

error:
  if( prf ){
    rhp_crypto_prf_free(prf);
  }
  if( hashed_key ){
    _rhp_free_zero(hashed_key,hashed_key_len);
  }
  if( peer_signed_octets ){
    _rhp_free_zero(peer_signed_octets,peer_signed_octets_len);
  }

  err = ( result ? 0 : RHP_STATUS_IKEV2_SESS_RESUME_AUTH_FAILED );

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_SESS_RESUME_VERIFY_AUTH_RTRN,"xxdE",vpn,ikesa,result,err);
  return err;
}

static int _rhp_ike_auth_req_sess_resume_radius_tkt2attrs(rhp_vpn* vpn,rhp_radius_sess_ressume_tkt* radius_tkt,
		rhp_radius_access_accept_attrs** radius_rx_accept_attrs_r)
{
	int err = -EINVAL;
	rhp_radius_access_accept_attrs* radius_rx_accept_attrs = NULL;
	u64 rx_accept_attrs_mask = _rhp_ntohll(radius_tkt->rx_accept_attrs_mask);
	rhp_split_dns_domain *priv_domain_names_tail = NULL;
	rhp_internal_route_map *priv_internal_route_ipv4_tail = NULL;
	rhp_internal_route_map *priv_internal_route_ipv6_tail = NULL;
	rhp_string_list *priv_realm_roles_tail = NULL;
	rhp_string_list *tunnel_private_group_ids_tail = NULL;

  RHP_TRC(0,RHPTRCID_IKE_AUTH_REQ_SESS_RESUME_RADIUS_TKT2ATTRS,"xxxq",vpn,radius_tkt,radius_rx_accept_attrs_r,rx_accept_attrs_mask);

	radius_rx_accept_attrs = rhp_radius_alloc_access_accept_attrs();
	if( radius_rx_accept_attrs == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	radius_rx_accept_attrs->priv_realm_id = (unsigned long)_rhp_ntohll(radius_tkt->vpn_realm_id_by_radius);

	radius_rx_accept_attrs->session_timeout = ntohl(radius_tkt->session_timeout);
	radius_rx_accept_attrs->framed_mtu = ntohl(radius_tkt->framed_mtu);

	{
		rhp_ip_addr *tmp_addr = NULL, *assigned_addr_v4 = NULL;

		if( RHP_VPN_RADIUS_ATTRS_MASK_0(rx_accept_attrs_mask,RHP_VPN_RADIUS_ATTRS_MASK_FRAMED_IP_V4) ){

			radius_rx_accept_attrs->framed_ipv4.addr_family = AF_INET;
			radius_rx_accept_attrs->framed_ipv4.addr.v4 = radius_tkt->internal_addr_ipv4;

			tmp_addr = &(radius_rx_accept_attrs->framed_ipv4);

		}else if( RHP_VPN_RADIUS_ATTRS_MASK_0(rx_accept_attrs_mask,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_IPV4) ){

			radius_rx_accept_attrs->priv_internal_addr_ipv4.addr_family = AF_INET;
			radius_rx_accept_attrs->priv_internal_addr_ipv4.addr.v4 = radius_tkt->internal_addr_ipv4;
			radius_rx_accept_attrs->priv_internal_addr_ipv4.prefixlen = (int)radius_tkt->internal_addr_ipv4_prefix;

			tmp_addr = &(radius_rx_accept_attrs->priv_internal_addr_ipv4);
		}

		if( tmp_addr && vpn->eap.peer_id.radius.assigned_addr_v4 == NULL ){

			assigned_addr_v4 = (rhp_ip_addr*)_rhp_malloc(sizeof(rhp_ip_addr));
			if( assigned_addr_v4 == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			memcpy(assigned_addr_v4,tmp_addr,sizeof(rhp_ip_addr));

			vpn->eap.peer_id.radius.assigned_addr_v4 = assigned_addr_v4;
		}
	}

	{
		rhp_ip_addr *tmp_addr = NULL, *assigned_addr_v6 = NULL;

		if( RHP_VPN_RADIUS_ATTRS_MASK_0(rx_accept_attrs_mask,RHP_VPN_RADIUS_ATTRS_MASK_FRAMED_IP_V6) ){

			radius_rx_accept_attrs->framed_ipv6.addr_family = AF_INET6;
			memcpy(radius_rx_accept_attrs->framed_ipv6.addr.v6,radius_tkt->internal_addr_ipv6,16);

			tmp_addr = &(radius_rx_accept_attrs->framed_ipv6);

		}else if( RHP_VPN_RADIUS_ATTRS_MASK_0(rx_accept_attrs_mask,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_IPV6) ){

			radius_rx_accept_attrs->priv_internal_addr_ipv6.addr_family = AF_INET6;
			memcpy(radius_rx_accept_attrs->priv_internal_addr_ipv6.addr.v6,radius_tkt->internal_addr_ipv6,16);
			radius_rx_accept_attrs->priv_internal_addr_ipv6.prefixlen = (int)radius_tkt->internal_addr_ipv6_prefix;

			tmp_addr = &(radius_rx_accept_attrs->priv_internal_addr_ipv6);
		}

		if( tmp_addr && vpn->eap.peer_id.radius.assigned_addr_v6 == NULL ){

			assigned_addr_v6 = (rhp_ip_addr*)_rhp_malloc(sizeof(rhp_ip_addr));
			if( assigned_addr_v6 == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			memcpy(assigned_addr_v6,tmp_addr,sizeof(rhp_ip_addr));

			vpn->eap.peer_id.radius.assigned_addr_v6 = assigned_addr_v6;
		}
	}

	if( RHP_VPN_RADIUS_ATTRS_MASK_0(rx_accept_attrs_mask,RHP_VPN_RADIUS_ATTRS_MASK_MS_PRIMARY_DNS_SERVER_V4) ){

		radius_rx_accept_attrs->ms_primary_dns_server_ipv4.addr_family = AF_INET;
		radius_rx_accept_attrs->ms_primary_dns_server_ipv4.addr.v4 = radius_tkt->internal_dns_server_ipv4;

	}else if( RHP_VPN_RADIUS_ATTRS_MASK_0(rx_accept_attrs_mask,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_IPV4) ){

		radius_rx_accept_attrs->priv_internal_dns_server_ipv4.addr_family = AF_INET;
		radius_rx_accept_attrs->priv_internal_dns_server_ipv4.addr.v4 = radius_tkt->internal_dns_server_ipv4;
	}

	if( RHP_VPN_RADIUS_ATTRS_MASK_0(rx_accept_attrs_mask,RHP_VPN_RADIUS_ATTRS_MASK_DNS_IPV6_SERVER) ){

		radius_rx_accept_attrs->dns_server_ipv6.addr_family = AF_INET6;
		memcpy(radius_rx_accept_attrs->dns_server_ipv6.addr.v6,radius_tkt->internal_dns_server_ipv6,16);

	}else if( RHP_VPN_RADIUS_ATTRS_MASK_0(rx_accept_attrs_mask,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_IPV6) ){

		radius_rx_accept_attrs->priv_internal_dns_server_ipv6.addr_family = AF_INET6;
		memcpy(radius_rx_accept_attrs->priv_internal_dns_server_ipv6.addr.v6,radius_tkt->internal_dns_server_ipv6,16);
	}

	if( RHP_VPN_RADIUS_ATTRS_MASK_0(rx_accept_attrs_mask,RHP_VPN_RADIUS_ATTRS_MASK_MS_PRIMARY_NBNS_SERVER_V4) ){

		radius_rx_accept_attrs->ms_primary_nbns_server_ipv4.addr_family = AF_INET;
		radius_rx_accept_attrs->ms_primary_nbns_server_ipv4.addr.v4 = radius_tkt->internal_wins_server_ipv4;
	}

	if( RHP_VPN_RADIUS_ATTRS_MASK_0(rx_accept_attrs_mask,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_GW_V4) ){

		radius_rx_accept_attrs->priv_internal_gateway_ipv4.addr_family = AF_INET;
		radius_rx_accept_attrs->priv_internal_gateway_ipv4.addr.v4 = radius_tkt->internal_gateway_ipv4;
	}

	if( RHP_VPN_RADIUS_ATTRS_MASK_0(rx_accept_attrs_mask,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_GW_V6) ){

		radius_rx_accept_attrs->priv_internal_gateway_ipv6.addr_family = AF_INET6;
		memcpy(radius_rx_accept_attrs->priv_internal_gateway_ipv6.addr.v6,radius_tkt->internal_gateway_ipv6,16);
	}

	{
		int attrs_num = ntohs(radius_tkt->attrs_num), i;
		rhp_radius_sess_resume_tkt_attr* attr = (rhp_radius_sess_resume_tkt_attr*)(radius_tkt + 1);
		u8* endp = ((u8*)radius_tkt) + ntohs(radius_tkt->radius_tkt_len);

		for( i = 0; i < attrs_num; i++){

			int attr_len, attr_type;
			int slen;

			if( ((u8*)attr) + sizeof(rhp_radius_sess_resume_tkt_attr) > endp ){
				err = -EINVAL;
				goto error;
			}

			attr_len = ntohs(attr->len);
			attr_type = ntohs(attr->type);

			if( attr_len <= (int)sizeof(rhp_radius_sess_resume_tkt_attr) ){
				err = -EINVAL;
				goto error;
			}

			if( ((u8*)attr) + attr_len > endp ){
				err = -EINVAL;
				goto error;
			}

			if( attr_type == RHP_SESS_RESUME_RADIUS_ATTR_INTERNAL_DOMAIN_NAME &&
					RHP_VPN_RADIUS_ATTRS_MASK_0(rx_accept_attrs_mask,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_DOMAINS) ){

				rhp_split_dns_domain* priv_domain_name
					= (rhp_split_dns_domain*)_rhp_malloc(sizeof(rhp_split_dns_domain));
				if( priv_domain_name == NULL ){
					RHP_BUG("");
					err = -ENOMEM;
					goto error;
				}
				memset(priv_domain_name,0,sizeof(rhp_split_dns_domain));

				priv_domain_name->tag[0] = '#';
				priv_domain_name->tag[1] = 'C';
				priv_domain_name->tag[2] = 'S';
				priv_domain_name->tag[3] = 'D';

				slen = attr_len - sizeof(rhp_radius_sess_resume_tkt_attr);
				priv_domain_name->name = (char*)_rhp_malloc(slen + 1);
				if( priv_domain_name->name == NULL ){
					_rhp_free(priv_domain_name);
					RHP_BUG("");
					err = -ENOMEM;
					goto error;
				}

				memcpy(priv_domain_name->name,(u8*)(attr + 1),slen);
				priv_domain_name->name[slen] = '\0';

				if( radius_rx_accept_attrs->priv_domain_names == NULL ){
					radius_rx_accept_attrs->priv_domain_names = priv_domain_name;
				}else{
					priv_domain_names_tail->next = priv_domain_name;
				}
				priv_domain_names_tail = priv_domain_name;


			}else if( attr_type == RHP_SESS_RESUME_RADIUS_ATTR_USER_INDEX ){

				char* user_index = NULL;
				slen = attr_len - sizeof(rhp_radius_sess_resume_tkt_attr);

				if( radius_rx_accept_attrs->tunnel_client_auth_id == NULL &&
						RHP_VPN_RADIUS_ATTRS_MASK_0(rx_accept_attrs_mask,RHP_VPN_RADIUS_ATTRS_MASK_TUNNEL_CLIENT_AUTH_ID) ){

					radius_rx_accept_attrs->tunnel_client_auth_id = (char*)_rhp_malloc(slen + 1);
					if( radius_rx_accept_attrs->tunnel_client_auth_id == NULL ){
						RHP_BUG("");
						err = -ENOMEM;
						goto error;
					}

					memcpy(radius_rx_accept_attrs->tunnel_client_auth_id,(u8*)(attr + 1),slen);
					radius_rx_accept_attrs->tunnel_client_auth_id[slen] = '\0';

					user_index = radius_rx_accept_attrs->tunnel_client_auth_id;

				}else if( radius_rx_accept_attrs->priv_user_index == NULL &&
									RHP_VPN_RADIUS_ATTRS_MASK_0(rx_accept_attrs_mask,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_USER_INDEX) ){

					radius_rx_accept_attrs->priv_user_index = (char*)_rhp_malloc(slen + 1);
					if( radius_rx_accept_attrs->priv_user_index == NULL ){
						RHP_BUG("");
						err = -ENOMEM;
						goto error;
					}

					memcpy(radius_rx_accept_attrs->priv_user_index,(u8*)(attr + 1),slen);
					radius_rx_accept_attrs->priv_user_index[slen] = '\0';

					user_index = radius_rx_accept_attrs->priv_user_index;
				}

				if( user_index && vpn->eap.peer_id.radius.user_index == NULL ){

					int idx_len = strlen(user_index);

					vpn->eap.peer_id.radius.user_index = (char*)_rhp_malloc(idx_len + 1);
					if( vpn->eap.peer_id.radius.user_index == NULL ){
						RHP_BUG("");
						err = -ENOMEM;
						goto error;
					}
					memcpy(vpn->eap.peer_id.radius.user_index,user_index,idx_len);
					vpn->eap.peer_id.radius.user_index[idx_len] = '\0';
				}

				if( !rhp_eap_identity_not_protected((int)ntohs(radius_tkt->eap_method)) &&
						vpn->eap.peer_id.radius.user_index == NULL &&
						vpn->eap.peer_id.radius.assigned_addr_v4 == NULL &&
						vpn->eap.peer_id.radius.assigned_addr_v6 == NULL ){

				  if( rhp_random_bytes((u8*)&(vpn->eap.peer_id.radius.salt),sizeof(u32)) ){
				    RHP_BUG("");
				  }

				}else{

					vpn->eap.peer_id.radius.salt = 0;
				}

			}else if( attr_type == RHP_SESS_RESUME_RADIUS_ATTR_INTERNAL_ROUTE_IPV4 &&
								RHP_VPN_RADIUS_ATTRS_MASK_0(rx_accept_attrs_mask,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_RT_MAP_V4) ){

				rhp_internal_route_map* priv_internal_route_ipv4
					= (rhp_internal_route_map*)_rhp_malloc(sizeof(rhp_internal_route_map));
				if( priv_internal_route_ipv4 == NULL ){
					RHP_BUG("");
					err = -ENOMEM;
					goto error;
				}
				memset(priv_internal_route_ipv4,0,sizeof(rhp_internal_route_map));

				priv_internal_route_ipv4->tag[0] = '#';
				priv_internal_route_ipv4->tag[1] = 'I';
				priv_internal_route_ipv4->tag[2] = 'R';
				priv_internal_route_ipv4->tag[3] = 'T';

				priv_internal_route_ipv4->dest_addr.addr_family = AF_INET;
				priv_internal_route_ipv4->dest_addr.addr.v4 = *((u32*)(attr + 1));
				priv_internal_route_ipv4->dest_addr.prefixlen = *(((u8*)(attr + 1)) + 4);

				if( radius_rx_accept_attrs->priv_internal_route_ipv4 == NULL ){
					radius_rx_accept_attrs->priv_internal_route_ipv4 = priv_internal_route_ipv4;
				}else{
					priv_internal_route_ipv4_tail->next = priv_internal_route_ipv4;
				}
				priv_internal_route_ipv4_tail = priv_internal_route_ipv4;


			}else if( attr_type == RHP_SESS_RESUME_RADIUS_ATTR_INTERNAL_ROUTE_IPV6 &&
								RHP_VPN_RADIUS_ATTRS_MASK_0(rx_accept_attrs_mask,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_RT_MAP_V6)){

				rhp_internal_route_map* priv_internal_route_ipv6
					= (rhp_internal_route_map*)_rhp_malloc(sizeof(rhp_internal_route_map));
				if( priv_internal_route_ipv6 == NULL ){
					RHP_BUG("");
					err = -ENOMEM;
					goto error;
				}
				memset(priv_internal_route_ipv6,0,sizeof(rhp_internal_route_map));

				priv_internal_route_ipv6->tag[0] = '#';
				priv_internal_route_ipv6->tag[1] = 'I';
				priv_internal_route_ipv6->tag[2] = 'R';
				priv_internal_route_ipv6->tag[3] = 'T';

				priv_internal_route_ipv6->dest_addr.addr_family = AF_INET6;
				memcpy(priv_internal_route_ipv6->dest_addr.addr.v6,(u8*)(attr + 1),16);
				priv_internal_route_ipv6->dest_addr.prefixlen = *(((u8*)(attr + 1)) + 16);

				if( radius_rx_accept_attrs->priv_internal_route_ipv6 == NULL ){
					radius_rx_accept_attrs->priv_internal_route_ipv6 = priv_internal_route_ipv6;
				}else{
					priv_internal_route_ipv6_tail->next = priv_internal_route_ipv6;
				}
				priv_internal_route_ipv6_tail = priv_internal_route_ipv6;

			}else if( attr_type == RHP_SESS_RESUME_RADIUS_ATTR_PRIV_REALM_ROLE ||
								attr_type == RHP_SESS_RESUME_RADIUS_ATTR_TUNNEL_PRIVATE_GROUP_ID ){

				rhp_string_list* role_string;

				role_string = (rhp_string_list*)_rhp_malloc(sizeof(rhp_string_list));
				if( role_string == NULL ){
					RHP_BUG("");
					err = -ENOMEM;
					goto error;
				}
				memset(role_string,0,sizeof(rhp_string_list));

				slen = attr_len - sizeof(rhp_radius_sess_resume_tkt_attr);
				role_string->string = (char*)_rhp_malloc(slen + 1);
				if( role_string->string == NULL ){
					_rhp_free(role_string);
					RHP_BUG("");
					err = -ENOMEM;
					goto error;
				}

				memcpy(role_string->string,(u8*)(attr + 1),slen);
				role_string->string[slen] = '\0';

				if( attr_type == RHP_SESS_RESUME_RADIUS_ATTR_PRIV_REALM_ROLE ){

					if( radius_rx_accept_attrs->priv_realm_roles == NULL ){
						radius_rx_accept_attrs->priv_realm_roles = role_string;
					}else{
						priv_realm_roles_tail->next = role_string;
					}
					priv_realm_roles_tail = role_string;

				}else if( attr_type == RHP_SESS_RESUME_RADIUS_ATTR_TUNNEL_PRIVATE_GROUP_ID ){

					if( radius_rx_accept_attrs->tunnel_private_group_ids == NULL ){
						radius_rx_accept_attrs->tunnel_private_group_ids = role_string;
					}else{
						tunnel_private_group_ids_tail->next = role_string;
					}
					tunnel_private_group_ids_tail = role_string;
				}
			}

			attr = (rhp_radius_sess_resume_tkt_attr*)(((u8*)attr) + attr_len);
		}
	}



	*radius_rx_accept_attrs_r = radius_rx_accept_attrs;

  RHP_TRC(0,RHPTRCID_IKE_AUTH_REQ_SESS_RESUME_RADIUS_TKT2ATTRS,"xxxqx",vpn,radius_tkt,radius_rx_accept_attrs_r,rx_accept_attrs_mask,*radius_rx_accept_attrs_r);
	radius_rx_accept_attrs->dump(radius_rx_accept_attrs,NULL);

  return 0;

error:
	if( radius_rx_accept_attrs ){
		_rhp_radius_access_accept_attrs_free(radius_rx_accept_attrs);
	}
  RHP_TRC(0,RHPTRCID_IKE_AUTH_REQ_SESS_RESUME_RADIUS_TKT2ATTRS_ERR,"xxxqE",vpn,radius_tkt,radius_rx_accept_attrs_r,rx_accept_attrs_mask);
	return err;
}

static int _rhp_ikev2_rx_ike_auth_req_sess_resume(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,
		rhp_ikev2_mesg* tx_resp_ikemesg,rhp_ike_auth_srch_plds_ctx* s_pld_ctx)
{
  int err = RHP_STATUS_INVALID_MSG;
  u8 *mesg_octets_i = NULL,*mesg_octets_r = NULL,*auth_r = NULL;
  int mesg_octets_i_len = 0,mesg_octets_r_len = 0,auth_r_len = 0;
	rhp_ikev2_sess_resume_tkt_e* sess_res_tkt_e = NULL;
	u8 *sk_d = NULL;
	u8 *id_i = NULL, *alt_id_i = NULL,*id_r = NULL,*alt_id_r = NULL,*eap_id_i = NULL;
	int id_i_len = 0, id_r_len = 0, eap_id_i_len = 0;
  rhp_vpn_realm* rlm = NULL;
  rhp_vpn *old_vpn = NULL;
  void* old_vpn_ref = NULL;
  unsigned long tkt_rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  time_t ikesa_lifetime_soft,ikesa_lifetime_hard,keep_alive_interval,nat_t_keep_alive_interval;
	rhp_ikev2_id tkt_peer_id, tkt_my_id, rx_my_id;
	rhp_radius_sess_ressume_tkt* radius_tkt = NULL;
	rhp_radius_access_accept_attrs* radius_rx_accept_attrs = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_SESS_RESUME,"xxxxd",rx_req_ikemesg,vpn,ikesa,s_pld_ctx,s_pld_ctx->id_r_len);

	memset(&tkt_peer_id,0,sizeof(rhp_ikev2_id));
	memset(&tkt_my_id,0,sizeof(rhp_ikev2_id));
	memset(&rx_my_id,0,sizeof(rhp_ikev2_id));

  {
		if( ikesa->sess_resume.resp.dec_tkt_ipc_rep == NULL ){
			RHP_BUG("");
			err = RHP_STATUS_INVALID_MSG;
			goto error;
		}

		err =  rhp_ikev2_sess_resume_dec_tkt_vals(
					(rhp_ikev2_sess_resume_tkt*)(ikesa->sess_resume.resp.dec_tkt_ipc_rep + 1),
					&sess_res_tkt_e,&sk_d,&id_i,&alt_id_i,&id_r,&alt_id_r,&eap_id_i,(u8**)&radius_tkt);
		if( err ){
			goto error;
		}

		if( sess_res_tkt_e == NULL || sk_d == NULL ){
			RHP_BUG("");
			err = RHP_STATUS_INVALID_MSG;
			goto error;
		}



		id_i_len = ntohs(sess_res_tkt_e->id_i_len);
		id_r_len = ntohs(sess_res_tkt_e->id_r_len);
		if( eap_id_i ){
			eap_id_i_len = ntohs(sess_res_tkt_e->eap_identity_len);
		}

		if( rhp_ikev2_to_null_auth_id(sess_res_tkt_e->id_i_type)
				!= rhp_ikev2_to_null_auth_id(s_pld_ctx->id_i_type) ){
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_SESS_RESUME_ID_I_TYPE_NOT_MATCH_1,"xxxdd",rx_req_ikemesg,vpn,ikesa,s_pld_ctx->id_i_type,sess_res_tkt_e->id_i_type);
			err = RHP_STATUS_INVALID_MSG;
			goto error;
		}

		if( rhp_ikev2_is_null_auth_id(s_pld_ctx->id_i_type) ){

			if( id_i || id_i_len || eap_id_i || eap_id_i_len ){
				RHP_BUG("");
				err = RHP_STATUS_INVALID_MSG;
				goto error;
			}

		}else{

			if( id_i == NULL || !id_i_len ){
				RHP_BUG("");
				err = RHP_STATUS_INVALID_MSG;
				goto error;
			}
		}


		err = rhp_ikev2_id_setup(sess_res_tkt_e->id_i_type,id_i,id_i_len,&tkt_peer_id);
	  if( err ){
	  	RHP_BUG("%d",err);
	  	goto error;
	  }
	  rhp_ikev2_id_dump("tkt_peer_id",&tkt_peer_id);


	  err = rhp_ikev2_id_setup(s_pld_ctx->id_i_type,s_pld_ctx->id_i,s_pld_ctx->id_i_len,&(vpn->peer_id));
	  if( err ){
	  	RHP_BUG("%d",err);
	  	goto error;
	  }
	  rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));


	  if( sess_res_tkt_e->id_i_type != RHP_PROTO_IKE_ID_NULL_ID ){

	  	if( rhp_ikev2_id_cmp(&(vpn->peer_id),&tkt_peer_id) ){
			  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_SESS_RESUME_ID_I_TYPE_NOT_MATCH_2,"xxx",rx_req_ikemesg,vpn,ikesa);
				err = RHP_STATUS_INVALID_MSG;
				goto error;
			}
	  }


		tkt_rlm_id = (unsigned long)_rhp_ntohll(sess_res_tkt_e->vpn_realm_id);
  }



  ikesa->auth_method = RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY;
	ikesa->peer_auth_method = RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY;



	{
		err = rhp_ikev2_ike_auth_mesg_octets(RHP_IKE_INITIATOR,ikesa,
						sess_res_tkt_e->id_i_type,id_i,id_i_len,&mesg_octets_i_len,&mesg_octets_i);
		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_SESS_RESUME_GET_MESG_OCTETS_ERR,"xxxE",rx_req_ikemesg,vpn,ikesa,err);
			goto error;
		}


		err = _rhp_ikev2_ike_auth_sess_resume_verify_auth(vpn,ikesa,mesg_octets_i_len,mesg_octets_i,
				s_pld_ctx->peer_auth_octets_len,s_pld_ctx->peer_auth_octets);
		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_SESS_RESUME_INVALID_AUTH_PLD_VAL,"xxxE",rx_req_ikemesg,vpn,ikesa,err);
			goto error;
		}
	}



  rlm = rhp_realm_get(tkt_rlm_id);
  if( rlm == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_SESS_RESUME_NO_REALM,"xxx",rx_req_ikemesg,vpn,ikesa);
    goto error;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){

  	RHP_UNLOCK(&(rlm->lock));

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_SESS_RESUME_REALM_NOT_ACTIVE,"xxxx",rx_req_ikemesg,vpn,ikesa,rlm);
    goto error;
  }

  err = vpn->check_cfg_address(vpn,rlm,rx_req_ikemesg->rx_pkt); // Here, MOBIKE is NOT processed yet.
  if( err ){

    RHP_UNLOCK(&(rlm->lock));

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_SESS_RESUME_CHECK_CFG_ADDR_ERR,"xxxxE",rx_req_ikemesg,rx_req_ikemesg->rx_pkt,vpn,rlm,err);

  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_unknown_if_err_packets);

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,tkt_rlm_id,RHP_LOG_ID_RX_IKE_PKT_VIA_UNCONFIGURED_IF,"KVi",rx_req_ikemesg,vpn,rx_req_ikemesg->rx_pkt->rx_if_index);

  	err = RHP_STATUS_INVALID_IKEV2_MESG_CHECK_CFG_ADDR_ERR;
    goto error;
  }


	if( s_pld_ctx->id_r_len ){

		int my_id_type = rhp_ikev2_to_null_auth_id(rlm->my_auth.my_id.type);

		if( my_id_type != rhp_ikev2_to_null_auth_id(sess_res_tkt_e->id_r_type) ||
				my_id_type != rhp_ikev2_to_null_auth_id(s_pld_ctx->id_r_type) ){

			RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_SESS_RESUME_ID_R_TYPE_NOT_MATCH_1,"xxxxddd",rx_req_ikemesg,vpn,ikesa,rlm,rlm->my_auth.my_id.type,s_pld_ctx->id_r_type,sess_res_tkt_e->id_r_type);

			RHP_UNLOCK(&(rlm->lock));

			err = RHP_STATUS_INVALID_MSG;
			goto error;
		}

		if( rhp_ikev2_is_null_auth_id(s_pld_ctx->id_r_type) ){

			if( id_r || id_r_len ){

		    RHP_UNLOCK(&(rlm->lock));

				RHP_BUG("");
				err = RHP_STATUS_INVALID_MSG;
				goto error;
			}

		}else{

			if( id_r == NULL || !id_r_len ){

		    RHP_UNLOCK(&(rlm->lock));

				RHP_BUG("");
				err = RHP_STATUS_INVALID_MSG;
				goto error;
			}


			rhp_ikev2_id_dump("rlm->my_auth.my_id",&(rlm->my_auth.my_id));


			err = rhp_ikev2_id_setup(sess_res_tkt_e->id_r_type,id_r,id_r_len,&tkt_my_id);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}
			rhp_ikev2_id_dump("tkt_my_id",&tkt_my_id);

			if( rhp_ikev2_id_cmp(&(rlm->my_auth.my_id),&tkt_my_id) ){

		    RHP_UNLOCK(&(rlm->lock));

			  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_SESS_RESUME_ID_R_TYPE_NOT_MATCH_2,"xxxx",rx_req_ikemesg,vpn,ikesa,rlm);
				err = RHP_STATUS_INVALID_MSG;
				goto error;
			}


		  err = rhp_ikev2_id_setup(s_pld_ctx->id_r_type,s_pld_ctx->id_r,s_pld_ctx->id_r_len,&rx_my_id);
		  if( err ){

		    RHP_UNLOCK(&(rlm->lock));

		  	RHP_BUG("%d",err);
		  	goto error;
		  }
			rhp_ikev2_id_dump("rx_my_id",&rx_my_id);

			if( rhp_ikev2_id_cmp(&rx_my_id,&tkt_my_id) ){

		    RHP_UNLOCK(&(rlm->lock));

				RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_SESS_RESUME_ID_R_TYPE_NOT_MATCH_3,"xxxx",rx_req_ikemesg,vpn,ikesa,rlm);
				err = RHP_STATUS_INVALID_MSG;
				goto error;
			}
		}
	}

  RHP_UNLOCK(&(rlm->lock));



	if( alt_id_i ){

		int alt_id_i_len = ntohs(sess_res_tkt_e->alt_id_i_len);

		err = rhp_ikev2_id_alt_setup(sess_res_tkt_e->alt_id_i_type,alt_id_i,
						alt_id_i_len,&(vpn->peer_id));

		if( err ){
			RHP_BUG("");
		  goto error;
		}
	}

	rhp_ikev2_id_dump("rx_ike_auth_req_sess_resume",&(vpn->peer_id));


	if( eap_id_i ){

		err = rhp_eap_id_setup((int)ntohs(sess_res_tkt_e->eap_i_method),
						eap_id_i_len,eap_id_i,0,&(vpn->eap.peer_id));
		if( err ){
			RHP_BUG("");
			goto error;
		}
	}


	if( ntohs(sess_res_tkt_e->eap_i_method) == RHP_PROTO_EAP_TYPE_PRIV_RADIUS ){

		if( radius_tkt == NULL ){
			err = -EINVAL;
			RHP_BUG("");
			goto error;
		}

		err = _rhp_ike_auth_req_sess_resume_radius_tkt2attrs(vpn,radius_tkt,&radius_rx_accept_attrs);
		if( err ){
			err = -EINVAL;
			RHP_BUG("");
			goto error;
		}
	}


	old_vpn_ref = rhp_vpn_get(tkt_rlm_id,&(vpn->peer_id),NULL);
	old_vpn = RHP_VPN_REF(old_vpn_ref);
	if( old_vpn ){

		int my_side = ikesa->side;
	  u8 my_spi[RHP_PROTO_IKE_SPI_SIZE];
	  memcpy(my_spi,ikesa->get_my_spi(ikesa),RHP_PROTO_IKE_SPI_SIZE);

		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_SESS_RESUME_DESTROY_OLD_VPN,"xxxx",rx_req_ikemesg,vpn,ikesa,old_vpn);

	  RHP_UNLOCK(&(vpn->lock));


	  {
	  	RHP_LOCK(&(old_vpn->lock));

			rhp_vpn_destroy(old_vpn);

			RHP_UNLOCK(&(old_vpn->lock));
			rhp_vpn_unhold(old_vpn_ref);
			old_vpn = NULL;
	  }


	  RHP_LOCK(&(vpn->lock));

    if( !_rhp_atomic_read(&(vpn->is_active)) ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_SESS_RESUME_IKESA_NOT_ACTIVE_2,"xxx",rx_req_ikemesg,vpn);
      err = -EINVAL;
      goto error;
    }

    ikesa = vpn->ikesa_get(vpn,my_side,my_spi);
    if( ikesa == NULL ){
    	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_SESS_RESUME_NO_IKESA_2,"xxLdG",rx_req_ikemesg,vpn,"IKE_SIDE",my_side,my_spi);
      err = -EINVAL;
    	goto error;
    }

	}else{

		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_SESS_RESUME_NO_OLD_VPN,"xxx",rx_req_ikemesg,vpn,ikesa);
	}



  RHP_LOCK(&(rlm->lock));

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_SESS_RESUME_NET_MODE,"xxxxd",rx_req_ikemesg,vpn,ikesa,rlm,rlm->encap_mode_c);

  err = rhp_ikev2_ike_auth_setup_larval_vpn(vpn,rlm,ikesa);
	if( err ){
	  RHP_UNLOCK(&(rlm->lock));
		goto error;
	}

	err = rhp_ikev2_ike_auth_r_setup_nhrp(vpn,rlm,ikesa);
	if( err ){
	  RHP_UNLOCK(&(rlm->lock));
		goto error;
	}

	if( !rhp_ip_addr_null(&(vpn->cfg_peer->internal_addr)) ){

		rhp_ip_addr_list* peer_addr;

		peer_addr = rhp_ip_dup_addr_list(&(vpn->cfg_peer->internal_addr));
		if( peer_addr == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
		  RHP_UNLOCK(&(rlm->lock));
			goto error;
		}
		peer_addr->ip_addr.tag = RHP_IPADDR_TAG_STATIC_PEER_ADDR;

		peer_addr->next = vpn->internal_net_info.peer_addrs;
		vpn->internal_net_info.peer_addrs = peer_addr;

		vpn->internal_net_info.static_peer_addr = 1;
	}


  if( ikesa->qcd.my_token_set_by_sess_resume ){

  	ikesa->qcd.my_token_enabled = 1;
  	// ikesa->qcd.my_token value is already set during SESS_RESUMPTION Exchg.

  }else{

  	ikesa->qcd.my_token_enabled = 0;
  }


	{
		err = rhp_ikev2_ike_auth_mesg_octets(RHP_IKE_RESPONDER,ikesa,
						sess_res_tkt_e->id_r_type,id_r,id_r_len,&mesg_octets_r_len,&mesg_octets_r);
		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_SESS_RESUME_GET_MESG_OCTETS2,"xxxE",rx_req_ikemesg,vpn,ikesa,err);
		  RHP_UNLOCK(&(rlm->lock));
			goto error;
		}

		err = _rhp_ikev2_ike_auth_sess_resume_sign_auth(vpn,ikesa,mesg_octets_r_len,mesg_octets_r,&auth_r_len,&auth_r);
		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_SESS_RESUME_GET_AUTH_R_DATA_ERR,"xxxE",rx_req_ikemesg,vpn,ikesa,err);
		  RHP_UNLOCK(&(rlm->lock));
			goto error;
		}
	}


  err = _rhp_ikev2_new_pkt_ike_auth_rep_impl(vpn,ikesa,rx_req_ikemesg,rlm,tx_resp_ikemesg,
  				RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY,auth_r_len,auth_r,0,0,NULL);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_SESS_RESUME_ALLOC_IKEMSG_ERR,"xxxx",rx_req_ikemesg,vpn,ikesa,rlm);
	  RHP_UNLOCK(&(rlm->lock));
    goto error;
  }

  ikesa_lifetime_soft = (time_t)rlm->ikesa.lifetime_soft;
  ikesa_lifetime_hard =  (time_t)rlm->ikesa.lifetime_hard;
  keep_alive_interval = (time_t)rlm->ikesa.keep_alive_interval;
  nat_t_keep_alive_interval = (time_t)rlm->ikesa.nat_t_keep_alive_interval;

  vpn->vpn_conn_lifetime = (time_t)rlm->vpn_conn_lifetime;

  rhp_vpn_put(vpn);

	rhp_ikev2_ike_auth_setup_access_point(vpn,rlm);

	RHP_UNLOCK(&(rlm->lock));


	{
		rhp_http_bus_broadcast_async(vpn->vpn_realm_id,1,1,
				rhp_ui_http_vpn_added_serialize,
				rhp_ui_http_vpn_bus_btx_async_cleanup,(void*)rhp_vpn_hold_ref(vpn)); // (*x*)

		RHP_LOG_I(RHP_LOG_SRC_VPNMNG,vpn->vpn_realm_id,RHP_LOG_ID_VPN_ADDED,"IAsNA",&(vpn->peer_id),&(vpn->peer_addr),vpn->peer_fqdn,vpn->unique_id,NULL);
	}


	if( eap_id_i ){

		vpn->eap.role = RHP_EAP_AUTHENTICATOR;
		vpn->eap.eap_method = vpn->eap.peer_id.method = (int)ntohs(sess_res_tkt_e->eap_i_method);

		ikesa->eap.state = RHP_IKESA_EAP_STAT_R_COMP;
	}

	if( radius_tkt ){

		vpn->radius.eap_method = (int)ntohs(radius_tkt->eap_method);

		vpn->radius.rx_accept_attrs = radius_rx_accept_attrs;
		radius_rx_accept_attrs = NULL;
	}

	rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_ESTABLISHED);
  vpn->created_ikesas++;

  rhp_ikev2_g_statistics_inc(ikesa_auth_sess_resume);


	vpn->start_vpn_conn_life_timer(vpn);


	rhp_http_bus_broadcast_async(vpn->vpn_realm_id,1,1,
				rhp_ui_http_vpn_established_serialize,
				rhp_ui_http_vpn_bus_btx_async_cleanup,(void*)rhp_vpn_hold_ref(vpn)); // (*x*)


	ikesa->established_time = _rhp_get_time();
	ikesa->expire_hard = ikesa->established_time + ikesa_lifetime_hard;
	ikesa->expire_soft = ikesa->established_time + ikesa_lifetime_soft;

	{
		vpn->established = 1;

		if( vpn->connecting ){
			vpn->connecting = 0;
			rhp_ikesa_half_open_sessions_dec();
		}
	}

	vpn->auto_reconnect_retries = 0;

	ikesa->timers->start_lifetime_timer(vpn,ikesa,ikesa_lifetime_soft,1);
	ikesa->timers->start_keep_alive_timer(vpn,ikesa,keep_alive_interval);
	ikesa->timers->start_nat_t_keep_alive_timer(vpn,ikesa,nat_t_keep_alive_interval);


	if( vpn->internal_net_info.static_peer_addr ){

		rhp_vpn_internal_route_update(vpn);
	}


  if( rlm ){
    rhp_realm_unhold(rlm);
  }

  if( mesg_octets_i ){
    _rhp_free_zero(mesg_octets_i,mesg_octets_i_len);
  }

  if( mesg_octets_r ){
    _rhp_free_zero(mesg_octets_r,mesg_octets_r_len);
  }

  if( auth_r ){
  	_rhp_free(auth_r);
  }

	rhp_ikev2_id_clear(&tkt_peer_id);
	rhp_ikev2_id_clear(&tkt_my_id);
	rhp_ikev2_id_clear(&rx_my_id);

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_REQ_SESS_RESUME_OK,"KVP",rx_req_ikemesg,vpn,ikesa);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_SESS_RESUME_RTRN,"xxx",rx_req_ikemesg,vpn,ikesa);
  return 0;

error:
	rhp_ikev2_g_statistics_inc(ikesa_auth_sess_resume_errors);

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_REQ_SESS_RESUME_ERR,"KVPE",rx_req_ikemesg,vpn,ikesa,err);

  if( rlm ){
    rhp_realm_unhold(rlm);
  }

  if( mesg_octets_i ){
    _rhp_free_zero(mesg_octets_i,mesg_octets_i_len);
  }

  if( mesg_octets_r ){
    _rhp_free_zero(mesg_octets_r,mesg_octets_r_len);
  }

  if( auth_r ){
  	_rhp_free(auth_r);
  }

  if( radius_rx_accept_attrs ){
  	_rhp_radius_access_accept_attrs_free(radius_rx_accept_attrs);
  }

	rhp_ikev2_id_clear(&tkt_peer_id);
	rhp_ikev2_id_clear(&tkt_my_id);
	rhp_ikev2_id_clear(&rx_my_id);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_SESS_RESUME_ERR,"xxxE",rx_req_ikemesg,vpn,ikesa,err);
  return err;
}

static int _rhp_ikev2_rx_ike_auth_rep_sess_resume(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ikev2_mesg* tx_req_ikemesg,rhp_ike_auth_srch_plds_ctx* s_pld_ctx)
{
  int err = RHP_STATUS_INVALID_MSG;
  u8* mesg_octets_r = NULL;
  int mesg_octets_r_len = 0;
  rhp_vpn_realm* rlm = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_SESS_RESUME,"xxx",rx_resp_ikemesg,vpn,ikesa);

  {
  	ikesa->peer_auth_method = s_pld_ctx->peer_auth_method;

  	err = rhp_ikev2_ike_auth_mesg_octets(RHP_IKE_RESPONDER,ikesa,
			    		s_pld_ctx->id_r_type,s_pld_ctx->id_r,s_pld_ctx->id_r_len,&mesg_octets_r_len,&mesg_octets_r);

  	if( err ){
  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_SESS_RESUME_GET_MESG_OCTETS_ERR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
  		goto error;
    }

		err = _rhp_ikev2_ike_auth_sess_resume_verify_auth(vpn,ikesa,mesg_octets_r_len,mesg_octets_r,
				s_pld_ctx->peer_auth_octets_len,s_pld_ctx->peer_auth_octets);
		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_SESS_RESUME_INVALID_AUTH_PLD_VAL,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
			goto error;
		}
	}


  rlm = vpn->rlm;
  if( rlm == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_SESS_RESUME_NO_REALM,"xxx",rx_resp_ikemesg,vpn,ikesa);
    goto error;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_SESS_RESUME_REALM_NOT_ACTIVE,"xxxx",rx_resp_ikemesg,vpn,ikesa,rlm);
    RHP_UNLOCK(&(rlm->lock));
    goto error;
  }


  vpn->vpn_conn_lifetime = (time_t)rlm->vpn_conn_lifetime;

	rhp_vpn_put(vpn);


	rhp_ikev2_ike_auth_setup_access_point(vpn,rlm);

	rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_ESTABLISHED);
  vpn->created_ikesas++;

  if( vpn->eap.role == RHP_EAP_SUPPLICANT ){
  	ikesa->eap.state = RHP_IKESA_EAP_STAT_I_COMP;
  }

	rhp_ikev2_g_statistics_inc(ikesa_auth_sess_resume);


	vpn->start_vpn_conn_life_timer(vpn);


	rhp_http_bus_broadcast_async(vpn->vpn_realm_id,1,1,
			rhp_ui_http_vpn_established_serialize,
			rhp_ui_http_vpn_bus_btx_async_cleanup,(void*)rhp_vpn_hold_ref(vpn)); // (*x*)


	if( vpn->init_by_peer_addr ){
		if( !rhp_gcfg_dmvpn_connect_shortcut_rate_limit ){
			rhp_vpn_connect_i_pending_clear(vpn->vpn_realm_id,NULL,&(vpn->peer_addr));
		}
	}else{
		rhp_vpn_connect_i_pending_clear(vpn->vpn_realm_id,&(vpn->peer_id),NULL);
	}

	ikesa->established_time = _rhp_get_time();
	ikesa->expire_hard = ikesa->established_time + (time_t)rlm->ikesa.lifetime_hard;
	ikesa->expire_soft = ikesa->established_time + (time_t)rlm->ikesa.lifetime_soft;


	ikesa->timers->start_lifetime_timer(vpn,ikesa,(time_t)rlm->ikesa.lifetime_soft,1);
	ikesa->timers->start_keep_alive_timer(vpn,ikesa,(time_t)rlm->ikesa.keep_alive_interval);
	ikesa->timers->start_nat_t_keep_alive_timer(vpn,ikesa,(time_t)rlm->ikesa.nat_t_keep_alive_interval);

	{
		vpn->established = 1;

		if( vpn->connecting ){
			vpn->connecting = 0;
			rhp_ikesa_half_open_sessions_dec();
		}
	}

	vpn->auto_reconnect_retries = 0;

	if( vpn->internal_net_info.static_peer_addr ){

		rhp_vpn_internal_route_update(vpn);
	}

  RHP_UNLOCK(&(rlm->lock));


	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_RESP_SESS_RESUME_OK,"KVP",rx_resp_ikemesg,vpn,ikesa);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_SESS_RESUME_RTRN,"xxx",rx_resp_ikemesg,vpn,ikesa);
  return 0;


error:
	rhp_ikev2_g_statistics_inc(ikesa_auth_sess_resume_errors);

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_RESP_SESS_RESUME_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);

	if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
	}

  if( mesg_octets_r ){
    _rhp_free_zero(mesg_octets_r,mesg_octets_r_len);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_SESS_RESUME_ERR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
  return err;
}


static int _rhp_ike2_auth_eval_hash_url(u8* rx_buf,int rx_buf_len,u8* rx_hash,int rx_hash_len)
{
	int err = -EINVAL;
	u8* md_buf = NULL;
	int md_buf_len = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_EVAL_HASH_URL,"pp",rx_buf_len,rx_buf,rx_hash_len,rx_hash);

	err = rhp_crypto_md(RHP_CRYPTO_MD_SHA1,rx_buf,rx_buf_len,&md_buf,&md_buf_len);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	if( rx_hash_len != md_buf_len ||
			memcmp(rx_hash,md_buf,md_buf_len) ){

	  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_EVAL_HASH_URL_NOT_MATCHED,"pp",rx_buf_len,rx_buf,md_buf_len,md_buf);

		err = RHP_STATUS_IKEV2_HASH_URL_INVALID_CERT_DATA;
		goto error;
	}

	_rhp_free(md_buf);

  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_EVAL_HASH_URL_RTRN,"x",rx_buf);
	return 0;

error:
	if( md_buf ){
		_rhp_free(md_buf);
	}
  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_EVAL_HASH_URL_ERR,"xE",rx_buf,err);
	return err;
}

static void _rhp_ikev2_ike_auth_clear_rx_cert_pld(rhp_ike_auth_srch_plds_ctx* s_pld_ctx)
{
	rhp_ikev2_rx_cert_pld* ca_cert_data;

  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_CLEAR_RX_CERT_PLD,"x",s_pld_ctx);

  if( s_pld_ctx->peer_cert_pld ){

  	if( s_pld_ctx->peer_cert_pld->encoding == RHP_PROTO_IKE_CERTENC_X509_CERT_HASH_URL ){

  		if( s_pld_ctx->peer_cert_pld->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_DER] ){
				_rhp_free(s_pld_ctx->peer_cert_pld->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_DER]);
			}
			s_pld_ctx->peer_cert_pld->val_lens[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_DER] = 0;
			s_pld_ctx->peer_cert_pld->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_DER] = NULL;
		}
  }

	ca_cert_data = s_pld_ctx->ca_cert_plds_head;
	while( ca_cert_data ){

		if( ca_cert_data->encoding == RHP_PROTO_IKE_CERTENC_X509_CERT_HASH_URL ){
			if( ca_cert_data->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_DER] ){
				_rhp_free(ca_cert_data->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_DER]);
			}
			ca_cert_data->val_lens[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_DER] = 0;
			ca_cert_data->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_DER] = NULL;
		}

		ca_cert_data = ca_cert_data->next;
	}

  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_CLEAR_RX_CERT_PLD_RTRN,"x",s_pld_ctx);
}


static void _rhp_ikev2_rx_ike_auth_hash_url_certs_cb_impl(void* cb_ctx,int cb_err,
		int rx_buf_num,int* rx_buf_lens,u8** rx_bufs,int is_req)
{
	int err = -EINVAL;
	rhp_ike_auth_srch_plds_ctx* s_pld_ctx = (rhp_ike_auth_srch_plds_ctx*)cb_ctx;
	rhp_vpn_ref* vpn_ref = s_pld_ctx->vpn_ref;
	rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);
	rhp_ikesa* ikesa = NULL;
	int i;
	u16 notify_mesg_type = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;
	unsigned long notify_error_arg = 0;
	u8* buf = NULL;

	{
		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_HASH_URL_CERTS_CB_IMPL,"xxEdxxd",vpn,cb_ctx,cb_err,rx_buf_num,rx_buf_lens,rx_bufs,is_req);
		_RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
		if( _RHP_TRC_COND(_rhp_trc_user_id(),0) ){
			if( !cb_err && rx_buf_num ){
				for( i = 0; i < rx_buf_num; i++){
					RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_HASH_URL_CERTS_CB_IMPL_RX_DATA,"xp",cb_ctx,rx_buf_lens[i],rx_bufs[i]);
				}
			}
		}
	}

	if( cb_err ){
  	rhp_ikev2_g_statistics_inc(http_clt_get_cert_err);
	}

	s_pld_ctx->vpn_ref = NULL;

	RHP_LOCK(&(vpn->lock));

	if( !_rhp_atomic_read(&(vpn->is_active)) ){
		err = -EINVAL;
		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_HASH_URL_CERTS_CB_IMPL_VPN_NOT_ACTIVE,"xx",vpn,cb_ctx);
		goto error;
  }

	ikesa = vpn->ikesa_get(vpn,s_pld_ctx->my_ikesa_side,s_pld_ctx->my_ikesa_spi);
	if( ikesa == NULL ){
		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_HASH_URL_CERTS_CB_IMPL_NO_IKESA,"xx",vpn,cb_ctx);
		goto error;
	}

	if( ikesa->state == RHP_IKESA_STAT_DELETE 		 ||
			ikesa->state == RHP_IKESA_STAT_DELETE_WAIT ||
			ikesa->state == RHP_IKESA_STAT_DEAD ){
		err = -EINVAL;
		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_HASH_URL_CERTS_CB_IMPL_IKESA_BAD_STAT,"xxx",vpn,ikesa,cb_ctx);
		goto error;
	}

	if( cb_err ){
		err = cb_err;
		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_HASH_URL_CERTS_CB_IMPL_CB_ERR,"xxxE",vpn,ikesa,cb_ctx,cb_err);
		goto error;
	}


	if( s_pld_ctx->cert_urls_num != rx_buf_num ){
		RHP_BUG("%d,%d",rx_buf_num,s_pld_ctx->cert_urls_num);
		err = -EINVAL;
		goto error;
	}

	if( s_pld_ctx->peer_cert_pld == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	i = 0;
  if( s_pld_ctx->peer_cert_pld->encoding == RHP_PROTO_IKE_CERTENC_X509_CERT_HASH_URL ){

  	err = _rhp_ike2_auth_eval_hash_url(rx_bufs[0],rx_buf_lens[0],
  					s_pld_ctx->peer_cert_pld->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_HASH],
  					s_pld_ctx->peer_cert_pld->val_lens[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_HASH]);

  	if( err ){
  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_HASH_URL_CERTS_CB_IMPL_PEER_CERT_URL_EVAL_ERR,"xxxsE",vpn,ikesa,cb_ctx,s_pld_ctx->peer_cert_pld->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_URL],err);
  		goto error;
  	}

  	buf = (u8*)_rhp_malloc(rx_buf_lens[0]);
  	if( buf == NULL ){
  		RHP_BUG("");
  		err = -ENOMEM;
  		goto error;
  	}

  	memcpy(buf,rx_bufs[0],rx_buf_lens[0]);

  	s_pld_ctx->peer_cert_pld->val_lens[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_DER] = rx_buf_lens[0];
  	s_pld_ctx->peer_cert_pld->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_DER] = buf;

  	i++;
  }

  if( s_pld_ctx->ca_certs_hash_url_num ){

  	rhp_ikev2_rx_cert_pld* ca_cert_data = s_pld_ctx->ca_cert_plds_head;

  	while( ca_cert_data ){

  	  if( i >= rx_buf_num ){
  	  	err = -EINVAL;
  	  	RHP_BUG("");
  	  	goto error;
  	  }

  	  if( ca_cert_data->encoding == RHP_PROTO_IKE_CERTENC_X509_CERT_HASH_URL ){

  	  	err = _rhp_ike2_auth_eval_hash_url(rx_bufs[i],rx_buf_lens[i],
  	  					ca_cert_data->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_HASH],
  	  					ca_cert_data->val_lens[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_HASH]);

  	  	if( err ){
  	  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_HASH_URL_CERTS_CB_IMPL_CA_CERT_URL_EVAL_ERR,"xxxsE",vpn,ikesa,cb_ctx,ca_cert_data->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_URL],err);
  	  		goto error;
  	  	}

  	  	buf = (u8*)_rhp_malloc(rx_buf_lens[i]);
  	  	if( buf == NULL ){
  	  		RHP_BUG("");
  	  		err = -ENOMEM;
  	  		goto error;
  	  	}

  	  	memcpy(buf,rx_bufs[i],rx_buf_lens[i]);

  	  	ca_cert_data->val_lens[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_DER] = rx_buf_lens[i];
  	  	ca_cert_data->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_DER] = buf;

  	  	i++;
  	  }

  		ca_cert_data = ca_cert_data->next;
  	}
  }


  if( is_req ){

  	err = _rhp_ikev2_rx_ike_auth_req_bh(vpn,ikesa,s_pld_ctx->rx_ikemesg,s_pld_ctx->tx_ikemesg,s_pld_ctx);
  	if( err ){
  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_HASH_URL_CERTS_CB_IMPL_REQ_BH_ERR,"xxxE",vpn,ikesa,cb_ctx,cb_err);
  		goto error;
  	}

  }else{

  	err = _rhp_ikev2_rx_ike_auth_rep_bh(vpn,ikesa,s_pld_ctx->rx_ikemesg,s_pld_ctx->tx_ikemesg,s_pld_ctx);
  	if( err ){
  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_HASH_URL_CERTS_CB_IMPL_REP_BH_ERR,"xxxE",vpn,ikesa,cb_ctx,cb_err);
  		goto error;
  	}
  }



	RHP_UNLOCK(&(vpn->lock));
	rhp_vpn_unhold(vpn_ref);

	_rhp_ikev2_ike_auth_clear_rx_cert_pld(s_pld_ctx);
	_rhp_ike_auth_free_srch_ctx(s_pld_ctx);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_HASH_URL_CERTS_CB_IMPL_RTRN,"xxx",vpn,ikesa,cb_ctx);
	return;


error:
	if( is_req ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_AUTH_REQ_HASH_URL_GET_CERT_ERR,"KVPE",s_pld_ctx->rx_ikemesg,vpn,ikesa,err);
	}else{
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_AUTH_REP_HASH_URL_GET_CERT_ERR,"KVPE",s_pld_ctx->rx_ikemesg,vpn,ikesa,err);
	}

	if( ikesa ){

		if( is_req ){

			err = rhp_ikev2_new_pkt_ike_auth_error_notify(ikesa,s_pld_ctx->tx_ikemesg,0,0,
								notify_mesg_type,notify_error_arg);

			if( err == RHP_STATUS_SUCCESS ){

				rhp_ikev2_call_next_rx_request_mesg_handlers(s_pld_ctx->rx_ikemesg,vpn,
								ikesa->side,(ikesa->side == RHP_IKE_INITIATOR ? ikesa->init_spi : ikesa->resp_spi),
								s_pld_ctx->tx_ikemesg,RHP_IKEV2_MESG_HANDLER_END);

				RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_AUTH_REQ_HASH_URL_TX_ERR_NOTIFY,"KVPL",s_pld_ctx->rx_ikemesg,vpn,ikesa,"PROTO_IKE_NOTIFY",notify_mesg_type);
			}
		}

		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
	}

	RHP_UNLOCK(&(vpn->lock));
	rhp_vpn_unhold(vpn_ref);

	_rhp_ikev2_ike_auth_clear_rx_cert_pld(s_pld_ctx);
	_rhp_ike_auth_free_srch_ctx(s_pld_ctx);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_HASH_URL_CERTS_CB_IMPL_ERR,"xxxE",vpn,ikesa,cb_ctx,err);
	return;
}

static void _rhp_ikev2_rx_ike_auth_rep_hash_url_certs_cb(void* cb_ctx,int cb_err,int rx_buf_num,int* rx_buf_lens,u8** rx_bufs)
{
	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_HASH_URL_CERTS_CB,"xEdxx",cb_ctx,cb_err,rx_buf_num,rx_buf_lens,rx_bufs);
	_rhp_ikev2_rx_ike_auth_hash_url_certs_cb_impl(cb_ctx,cb_err,rx_buf_num,rx_buf_lens,rx_bufs,0);
}

static void _rhp_ikev2_rx_ike_auth_req_hash_url_certs_cb(void* cb_ctx,int cb_err,int rx_buf_num,int* rx_buf_lens,u8** rx_bufs)
{
	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_HASH_URL_CERTS_CB,"xEdxx",cb_ctx,cb_err,rx_buf_num,rx_buf_lens,rx_bufs);
	_rhp_ikev2_rx_ike_auth_hash_url_certs_cb_impl(cb_ctx,cb_err,rx_buf_num,rx_buf_lens,rx_bufs,1);
}

static int _rhp_ikev2_rx_ike_auth_hash_url_get_certs(rhp_ike_auth_srch_plds_ctx* s_pld_ctx,
		void (*callback)(void* cb_ctx,int err,int rx_buf_num,int* rx_buf_lens,u8** rx_bufs),void* cb_ctx)
{
	int err = -EINVAL;
	rhp_ikev2_rx_cert_pld* cert_data;
	int i;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_HASH_URL_GET_CERTS,"xxYx",RHP_VPN_REF(s_pld_ctx->vpn_ref),s_pld_ctx,callback,cb_ctx);

	s_pld_ctx->cert_urls_num = 0;

  if( s_pld_ctx->peer_cert_pld &&
  		s_pld_ctx->peer_cert_pld->encoding == RHP_PROTO_IKE_CERTENC_X509_CERT_HASH_URL ){

  	s_pld_ctx->cert_urls_num++;
  }

  if( s_pld_ctx->ca_certs_hash_url_num ){

  	s_pld_ctx->cert_urls_num += s_pld_ctx->ca_certs_hash_url_num;
  }

  if( s_pld_ctx->cert_urls_num < 1 ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  s_pld_ctx->cert_urls = (char**)_rhp_malloc(sizeof(char*)*s_pld_ctx->cert_urls_num);
  if( s_pld_ctx->cert_urls == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }
  memset(s_pld_ctx->cert_urls,0,sizeof(char*)*s_pld_ctx->cert_urls_num);

  i = 0;
  if( s_pld_ctx->peer_cert_pld &&
  		s_pld_ctx->peer_cert_pld->encoding == RHP_PROTO_IKE_CERTENC_X509_CERT_HASH_URL ){

  	s_pld_ctx->cert_urls[0] = (char*)s_pld_ctx->peer_cert_pld->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_URL];
  	i++;
  }


  cert_data = s_pld_ctx->ca_cert_plds_head;
  while( cert_data ){

  	if( i >= s_pld_ctx->cert_urls_num ){
  		RHP_BUG("");
  		err = -EINVAL;
  		goto error;
  	}

  	if( cert_data->encoding == RHP_PROTO_IKE_CERTENC_X509_CERT_HASH_URL ){
  		s_pld_ctx->cert_urls[i] = (char*)cert_data->vals[RHP_RX_CERT_PLD_VAL_X509_HASH_URL_URL];
  		i++;
  	}

  	cert_data = cert_data->next;
  }


  err = rhp_http_clt_get(s_pld_ctx->cert_urls_num,s_pld_ctx->cert_urls,
  				rhp_gcfg_ikev2_hash_url_http_timeout,
  				((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->local.if_info.addr_family,
  				callback,cb_ctx,
  				rhp_gcfg_hash_url_match_server_name);

  if( err ){

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_HASH_URL_GET_CERTS_HTTP_CLT_GET_ERR,"xE",s_pld_ctx,err);

  	rhp_ikev2_g_statistics_inc(http_clt_get_cert_err);

  	goto error;
  }

	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_HASH_URL_GET_CERTS_RTRN,"x",s_pld_ctx);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_HASH_URL_GET_CERTS_ERR,"xE",s_pld_ctx,err);
	return err;
}

static int _rhp_ikev2_rx_ike_auth_rep(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ikev2_mesg* tx_req_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_vpn_realm* rlm = NULL;
  rhp_ike_auth_srch_plds_ctx* s_pld_ctx = NULL;
  int null_auth_for_peers = 0, psk_for_peers = 0, rsa_sig_for_peers = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L,"xxx",rx_resp_ikemesg,vpn,ikesa);


  s_pld_ctx = _rhp_ike_auth_alloc_srch_ctx();
  if( s_pld_ctx == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }


  if( rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


  ikesa->timers->quit_lifetime_timer(vpn,ikesa);

  rlm = vpn->rlm;
  if( rlm == NULL ){
    err = -EINVAL;
    RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_NO_REALM,"xxx",rx_resp_ikemesg,vpn,ikesa);
    RHP_BUG("");
    goto error;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
    err = -EINVAL;
    RHP_UNLOCK(&(rlm->lock));
    RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_REALM_NOT_ACTIVE,"xxx",rx_resp_ikemesg,vpn,ikesa);
    goto error;
  }

  if( rlm->my_auth.eap_sup.enabled ){

		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_EAP_SUP_ENABLED_NO_MY_ID,"xxxxd",rx_resp_ikemesg,vpn,ikesa,rlm,rlm->my_auth.eap_sup.method);

  }else{

  	err =  rhp_ikev2_id_value(&(rlm->my_auth.my_id),
  			&(s_pld_ctx->my_id_val),&(s_pld_ctx->my_id_len),&(s_pld_ctx->my_id_type));
  	if( err ){
  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_GET_MY_ID_ERR,"xxxpE",rx_resp_ikemesg,vpn,ikesa,sizeof(rhp_ikev2_id),&(rlm->my_auth.my_id),err);
  		RHP_UNLOCK(&(rlm->lock));
  		goto error;
  	}
  }

	null_auth_for_peers = rlm->null_auth_for_peers;
	psk_for_peers = rlm->psk_for_peers;
	rsa_sig_for_peers = rlm->rsa_sig_for_peers;

  RHP_UNLOCK(&(rlm->lock));



  s_pld_ctx->vpn_ref = rhp_vpn_hold_ref(vpn);
	s_pld_ctx->ikesa = ikesa;

  {
		s_pld_ctx->dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_N),
  			_rhp_ikev2_ike_auth_srch_n_error_cb,s_pld_ctx);

  	if( ( err == 0 || err == RHP_STATUS_ENUM_OK ) && (s_pld_ctx->n_error_payload != NULL ) ){

      RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_RX_N_PEER_ERROR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);

     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_RESP_N_ERR_PAYLOAD,"KVPL",rx_resp_ikemesg,vpn,ikesa,"PROTO_IKE_NOTIFY",s_pld_ctx->n_err);

   	  err = RHP_STATUS_PEER_NOTIFIED_ERROR;
   	  goto error;

  	}else if( err && err != -ENOENT ){
  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_N_ERROR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_RESP_PARSE_N_ERR_PAYLOAD_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
    	goto error;
  	}
  	err = 0;
  }


  {
  	s_pld_ctx->dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_ID_R),
  			_rhp_ikev2_ike_auth_srch_id_cb,s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_ENUM_ID_PLD_ERR,"xxxd",rx_resp_ikemesg,vpn,ikesa,err);
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_RESP_PARSE_ID_R_PAYLOAD_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
      goto error;
    }

    if( vpn->peer_id.type != RHP_PROTO_IKE_ID_ANY ){

    	if( !rhp_ikev2_is_null_auth_id(s_pld_ctx->id_r_type) ){

				if( !rhp_ikev2_is_null_auth_id(vpn->peer_id.type) &&
						rhp_ikev2_id_cmp_by_value(&(vpn->peer_id),s_pld_ctx->id_r_type,s_pld_ctx->id_r_len,s_pld_ctx->id_r) ){
					err = RHP_STATUS_INVALID_MSG;
					RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_ENUM_ID_PLD_ERR_INVALILD_RESP_ID_1,"xxxd",rx_resp_ikemesg,vpn,ikesa,err);
					RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_RESP_ID_R_PAYLOAD_INVALID_PEER_ID,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
					goto error;
				}

    	}else{

    		if( !null_auth_for_peers ){
					err = RHP_STATUS_INVALID_MSG;
					RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_ENUM_ID_PLD_ERR_INVALILD_RESP_ID_2,"xxxd",rx_resp_ikemesg,vpn,ikesa,err);
					RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_RESP_ID_R_PAYLOAD_INVALID_PEER_ID,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
					goto error;
    		}
    	}

    }else{

    	// (e.g.) DMVPN: Spoke-to-Spoke tunnel

    	if( rhp_ikev2_is_null_auth_id(s_pld_ctx->id_r_type) ){

    		if( !null_auth_for_peers ){
					err = RHP_STATUS_INVALID_MSG;
					RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_ENUM_ID_PLD_ERR_INVALILD_RESP_ID_3,"xxxd",rx_resp_ikemesg,vpn,ikesa,err);
					RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_RESP_ID_R_PAYLOAD_INVALID_PEER_ID,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
					goto error;
    		}
    	}

    	err = rhp_ikev2_id_setup(s_pld_ctx->id_r_type,s_pld_ctx->id_r,s_pld_ctx->id_r_len,&(vpn->peer_id));
    	if( err ){
        RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_ENUM_ID_PLD_ERR_INVALILD_RESP_ID_4,"xxxd",rx_resp_ikemesg,vpn,ikesa,err);
       	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_RESP_ID_R_PAYLOAD_INVALID_PEER_ID,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
    		goto error;
    	}
    }
  }

  {
  	s_pld_ctx->dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_AUTH),
  			_rhp_ikev2_ike_auth_srch_auth_cb,s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_ENUM_AUTH_PLD_ERR,"xxxd",rx_resp_ikemesg,vpn,ikesa,err);
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_RESP_AUTH_PAYLOAD_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
      goto error;
    }

		if( (!ikesa->gen_by_sess_resume &&
				 s_pld_ctx->peer_auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY && !psk_for_peers) 	||
				(s_pld_ctx->peer_auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG && !rsa_sig_for_peers) ||
				(s_pld_ctx->peer_auth_method == RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH && !null_auth_for_peers) ){

			err = RHP_STATUS_INVALID_MSG;

			RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_ENUM_AUTH_PLD_NOT_ALLOWED_AUTH_METHOD,"xxxdE",rx_resp_ikemesg,vpn,ikesa,s_pld_ctx->peer_auth_method,err);
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_RESP_AUTH_PAYLOAD_NOT_ALLOWED_AUTH_METHOD_ERR,"KVPLE",rx_resp_ikemesg,vpn,ikesa,"PROTO_IKE_AUTHMETHOD",s_pld_ctx->peer_auth_method,err);
      goto error;
		}
  }

  {
  	s_pld_ctx->dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,1,
    		rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_CERT),
    		_rhp_ikev2_ike_auth_srch_cert_cb,s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_ENUM_CERT_PLD_ERR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
  		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_RESP_CERT_PAYLOAD_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
  		goto error;
  	}

		if( s_pld_ctx->peer_auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG &&
				!s_pld_ctx->cert_payload_num ){

  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_ENUM_CERT_PLD_NO_CERT_PAYLOAD_ERR,"xxx",rx_resp_ikemesg,vpn,ikesa);

			err = RHP_STATUS_INVALID_MSG;
  		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_RESP_NO_CERT_PAYLOAD,"KVP",rx_resp_ikemesg,vpn,ikesa);
			goto error;
		}
  }


  if( s_pld_ctx->peer_auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG &&
  		((s_pld_ctx->peer_cert_pld && s_pld_ctx->peer_cert_pld->encoding == RHP_PROTO_IKE_CERTENC_X509_CERT_HASH_URL) ||
   		  s_pld_ctx->ca_certs_hash_url_num) ){

  	s_pld_ctx->ikesa = NULL;
  	s_pld_ctx->rlm = NULL;

  	s_pld_ctx->rx_ikemesg = rx_resp_ikemesg;
		rhp_ikev2_hold_mesg(rx_resp_ikemesg);

  	s_pld_ctx->tx_ikemesg = tx_req_ikemesg;
		rhp_ikev2_hold_mesg(tx_req_ikemesg);

		s_pld_ctx->my_ikesa_side = ikesa->side;
		memcpy(s_pld_ctx->my_ikesa_spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);


	  ikesa->busy_flag = 1;

  	err = _rhp_ikev2_rx_ike_auth_hash_url_get_certs(s_pld_ctx,
  					_rhp_ikev2_rx_ike_auth_rep_hash_url_certs_cb,(void*)s_pld_ctx);
  	if( err ){
  	  ikesa->busy_flag = 0;
  		goto error;
  	}

  	err = RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;

		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_CERT_DER_NOT_RESOLVED,"xxx",rx_resp_ikemesg,vpn,ikesa);

  }else if( ikesa->gen_by_sess_resume ){

  	err = _rhp_ikev2_rx_ike_auth_rep_sess_resume(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,s_pld_ctx);
  	if( err ){
  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_SESS_RESUME_ERR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
  		goto error;
  	}

  	_rhp_ike_auth_free_srch_ctx(s_pld_ctx);

  }else{

  	err = _rhp_ikev2_rx_ike_auth_rep_bh(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,s_pld_ctx);
  	if( err ){
  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_BH_ERR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
  		goto error;
  	}

  	_rhp_ike_auth_free_srch_ctx(s_pld_ctx);

  	err = RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;
  }


  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_RTRN,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
	return err;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_RESP_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);

  if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
  	ikesa->timers->schedule_delete(vpn,ikesa,0);
  }

  if( s_pld_ctx ){
  	_rhp_ike_auth_free_srch_ctx(s_pld_ctx);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_ERR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
  return err;
}


static int _rhp_ikev2_ike_auth_eap_verify_auth(rhp_vpn* vpn,rhp_ikesa* ikesa,int mesg_octets_len,u8* mesg_octets,
		int eap_sharedkey_len,u8* eap_sharedkey,int peer_auth_octets_len,u8* peer_auth_octets)
{
	int err = -EINVAL;
  rhp_crypto_prf* prf = NULL;
  u8* hashed_key = NULL;
  int hashed_key_len = 0;
  u8* peer_signed_octets = NULL;
  int peer_signed_octets_len = 0;
  int result = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_EAP_VERIFY_AUTH,"xxppp",vpn,ikesa,mesg_octets_len,mesg_octets,eap_sharedkey_len,eap_sharedkey,peer_auth_octets_len,peer_auth_octets);

  if( rhp_auth_supported_prf_method(ikesa->prf->alg) ){
    RHP_BUG("%d",ikesa->prf->alg);
    goto error;
  }

  prf = rhp_crypto_prf_alloc(ikesa->prf->alg);
  if( prf == NULL ){
    RHP_BUG("");
    goto error;
  }

  {
		hashed_key_len = prf->get_output_len(prf);

		hashed_key = (u8*)_rhp_malloc(hashed_key_len);
		if( hashed_key == NULL ){
			RHP_BUG("");
			goto error;
		}

		if( prf->set_key(prf,eap_sharedkey,eap_sharedkey_len) ){
			RHP_BUG("");
			goto error;
		}

		if( prf->compute(prf,(unsigned char*)RHP_PROTO_IKE_AUTH_KEYPAD,strlen(RHP_PROTO_IKE_AUTH_KEYPAD),
					hashed_key,hashed_key_len) ){
			RHP_BUG("");
			goto error;
		}
  }


  if( prf->set_key(prf,hashed_key,hashed_key_len) ){
  	RHP_BUG("");
    goto error;
  }

  {
		peer_signed_octets_len = prf->get_output_len(prf);

		peer_signed_octets = (u8*)_rhp_malloc(peer_signed_octets_len);
		if( peer_signed_octets == NULL ){
			RHP_BUG("");
			goto error;
		}

		if( prf->compute(prf,mesg_octets,mesg_octets_len,peer_signed_octets,peer_signed_octets_len) ){
			RHP_BUG("");
			goto error;
		}

		if( peer_signed_octets_len == (int)peer_auth_octets_len &&
				!memcmp(peer_signed_octets,peer_auth_octets,peer_signed_octets_len) ){
			result = 1;
		}else{
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_EAP_VERIFY_AUTH_OCTETS_CMP_ERR,"xxpp",vpn,ikesa,peer_signed_octets_len,peer_signed_octets,peer_auth_octets_len,peer_auth_octets);
		}
  }

error:
  if( prf ){
    rhp_crypto_prf_free(prf);
  }
  if( hashed_key ){
    _rhp_free_zero(hashed_key,hashed_key_len);
  }
  if( peer_signed_octets ){
    _rhp_free_zero(peer_signed_octets,peer_signed_octets_len);
  }

  err = ( result ? 0 : RHP_STATUS_EAP_PSK_AUTH_FAILED );

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_EAP_VERIFY_AUTH_RTRN,"xxdE",vpn,ikesa,result,err);
  return err;
}

extern int rhp_auth_sign_req_expand_mesg_octets(rhp_crypto_prf* prf,rhp_ikev2_id* my_id,int sk_p_len,u8* sk_p,
    int auth_mesg_octets_part_len,u8* auth_mesg_octets_part,int* auth_mesg_octets_len_r,u8** auth_mesg_octets_r);

static int _rhp_ikev2_ike_auth_eap_sign_auth(rhp_vpn* vpn,rhp_ikesa* ikesa,
		int* mesg_octets_len,u8** mesg_octets,
		int eap_sharedkey_len,u8* eap_sharedkey,
		int* auth_data_len,u8** auth_data)
{
	int err = -EINVAL;
  rhp_crypto_prf* prf = NULL;
  unsigned int result = 0;
  u8* hashed_key = NULL;
  int hashed_key_len = 0;
  u8* signed_octets = NULL;
  int signed_octets_len = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_EAP_SIGN_AUTH,"xxppxx",vpn,ikesa,*mesg_octets_len,*mesg_octets,eap_sharedkey_len,eap_sharedkey,auth_data_len,auth_data);

  if( rhp_auth_supported_prf_method(ikesa->prf->alg) ){
    RHP_BUG("%d",ikesa->prf->alg);
    goto error;
  }

  prf  = rhp_crypto_prf_alloc(ikesa->prf->alg);
  if( prf == NULL ){
    RHP_BUG("");
    goto error;
  }


  {
  	u8* mesg_octets_exp = NULL;
  	int mesg_octets_exp_len = 0;
  	u8* sk_p = ( ikesa->side == RHP_IKE_INITIATOR ? ikesa->keys.v2.sk_pi : ikesa->keys.v2.sk_pr );

  	err = rhp_auth_sign_req_expand_mesg_octets(prf,&(vpn->my_id),ikesa->keys.v2.sk_p_len,sk_p,
  			*mesg_octets_len,*mesg_octets,&mesg_octets_exp_len,&mesg_octets_exp);

  	if( err ){
  		RHP_BUG("%d",err);
  		goto error;
  	}

  	_rhp_free(*mesg_octets);

  	*mesg_octets = mesg_octets_exp;
  	*mesg_octets_len = mesg_octets_exp_len;
  }


  {
    hashed_key_len = prf->get_output_len(prf);

    hashed_key = (u8*)_rhp_malloc(hashed_key_len);
    if( hashed_key == NULL ){
      RHP_BUG("");
      goto error;
    }

    if( prf->set_key(prf,eap_sharedkey,eap_sharedkey_len) ){
      RHP_BUG("");
      goto error;
    }

    if( prf->compute(prf,(unsigned char*)RHP_PROTO_IKE_AUTH_KEYPAD,strlen(RHP_PROTO_IKE_AUTH_KEYPAD),
        hashed_key,hashed_key_len) ){
      RHP_BUG("");
      goto error;
    }
  }

  signed_octets_len = prf->get_output_len(prf);

  signed_octets = (u8*)_rhp_malloc(signed_octets_len);
  if( signed_octets == NULL ){
    RHP_BUG("");
    goto error;
  }

  if( prf->set_key(prf,hashed_key,hashed_key_len) ){
    RHP_BUG("");
    goto error;
  }

  if( prf->compute(prf,*mesg_octets,*mesg_octets_len,signed_octets,signed_octets_len) ){
    RHP_BUG("");
    goto error;
  }

  *auth_data_len = signed_octets_len;
  *auth_data = signed_octets;
  result = 1;

  signed_octets = NULL;
  signed_octets_len = 0;

error:
  if( prf ){
    rhp_crypto_prf_free(prf);
  }
  if( hashed_key ){
    _rhp_free_zero(hashed_key,hashed_key_len);
  }
  if( signed_octets ){
    _rhp_free_zero(signed_octets,signed_octets_len);
  }

  err = ( result ? 0 : -EINVAL);

  if( result ){
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_EAP_SIGN_AUTH_RTRN,"xxppd",vpn,ikesa,*auth_data_len,*auth_data,*mesg_octets_len,*mesg_octets,result);
  }else{
  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_EAP_SIGN_AUTH_ERR,"xxdE",vpn,ikesa,result,err);
  }
  return err;
}

//
// This is called in rhp_ikev2_eap.c after EAP Success message is received.
//
int rhp_ikev2_rx_ike_auth_rep_eap_comp(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ikev2_mesg* tx_req_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  u8 *mesg_octets_i = NULL;
  int mesg_octets_i_len;
  rhp_vpn_realm* rlm = NULL;
  u8 *eap_msk = NULL,*eap_skey_i = NULL;
  int eap_msk_len = 0,eap_skey_i_len = 0;
  int auth_data_len = 0;
  u8* auth_data = NULL;
  time_t ikesa_larval_timeout;


  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_EAP_COMP,"xxx",rx_resp_ikemesg,vpn,ikesa);

  if( rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_BUG("");
  	goto error;
  }


  ikesa->timers->quit_lifetime_timer(vpn,ikesa);


  err = rhp_eap_sup_impl_get_msk(vpn,vpn->eap.impl_ctx,&eap_msk_len,&eap_msk);

  if( err == -ENOENT ){

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_EAP_COMP_NO_MSK,"xxx",rx_resp_ikemesg,vpn,ikesa);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_EAP_SUP_MSK_NOT_AVAILABLE,"KVP",rx_resp_ikemesg,vpn,ikesa);

  	eap_skey_i = ikesa->keys.v2.sk_pi;
  	eap_skey_i_len = ikesa->keys.v2.sk_p_len;

  	err = 0;

  }else if( !err ){

    if( rhp_gcfg_dbg_log_keys_info ){
      RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_DBG_EAP_SUP_MSK_GEN,"KVPp",rx_resp_ikemesg,vpn,ikesa,eap_msk_len,eap_msk);
    }

  	eap_skey_i = eap_msk;
  	eap_skey_i_len = eap_msk_len;

  }else{

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_EAP_COMP_FAIL_TO_GET_MSK,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
  	goto error;
  }


  {
  	mesg_octets_i_len = ikesa->eap.pend_mesg_octets_i_len;
  	mesg_octets_i = ikesa->eap.pend_mesg_octets_i;
  	ikesa->eap.pend_mesg_octets_i_len = 0;
  	ikesa->eap.pend_mesg_octets_i = NULL;

		err = _rhp_ikev2_ike_auth_eap_sign_auth(vpn,ikesa,&mesg_octets_i_len,&mesg_octets_i,
				eap_skey_i_len,eap_skey_i,&auth_data_len,&auth_data);

    if( err ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_EAP_COMP_SIGN_REQ_ERR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
      goto error;
    }
  }


  rlm = vpn->rlm;
  if( rlm == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_EAP_COMP_NO_REALM,"xx",vpn,ikesa);
    goto error;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_EAP_COMP_REALM_NOT_ACTIVE,"xxx",vpn,ikesa,rlm);
    goto error_rlm_l;
  }


  err = _rhp_ikev2_new_pkt_ike_auth_eap_req(vpn,ikesa,
  		rx_resp_ikemesg,rlm,tx_req_ikemesg,auth_data_len,auth_data);

  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_EAP_COMP_ALLOC_IKEMSG_ERR,"xxxE",rx_resp_ikemesg,ikesa,rlm,err);
    goto error_rlm_l;
  }


  ikesa_larval_timeout = (time_t)rlm->ikesa.lifetime_larval;

  RHP_UNLOCK(&(rlm->lock));


	rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_I_AUTH_EAP_SENT);


	ikesa->timers->start_lifetime_timer(vpn,ikesa,ikesa_larval_timeout,1);

  if( eap_msk ){
  	_rhp_free_zero(eap_msk,eap_msk_len);
  }

  _rhp_free_zero(mesg_octets_i,mesg_octets_i_len);
  _rhp_free(auth_data);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_EAP_COMP_RTRN,"xxx",rx_resp_ikemesg,vpn,ikesa);

  return 0;


error_rlm_l:
	RHP_UNLOCK(&(rlm->lock));

error:
	if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
  }

	if( mesg_octets_i ){
    _rhp_free_zero(mesg_octets_i,mesg_octets_i_len);
  }

	if( auth_data ){
    _rhp_free_zero(auth_data,auth_data_len);
  }

  if( eap_msk ){
  	_rhp_free_zero(eap_msk,eap_msk_len);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_EAP_COMP_ERR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
  return err;
}


static int _rhp_ikev2_rx_ike_auth_rep_eap_comp_2(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ikev2_mesg* tx_req_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  u8 *mesg_octets_r = NULL;
  int mesg_octets_r_len = 0;
  rhp_vpn_realm* rlm = NULL;
  rhp_ike_auth_srch_plds_ctx s_pld_ctx;
  u8 *eap_msk = NULL,*eap_skey_r = NULL;
  int eap_msk_len = 0,eap_skey_r_len = 0;
  time_t ikesa_lifetime_soft = 0,ikesa_lifetime_hard = 0,keep_alive_interval = 0,nat_t_keep_alive_interval = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_EAP_COMP_2,"xxx",rx_resp_ikemesg,vpn,ikesa);

  memset(&s_pld_ctx,0,sizeof(rhp_ike_auth_srch_plds_ctx));

  if( rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  ikesa->timers->quit_lifetime_timer(vpn,ikesa);


  {
		rlm = vpn->rlm;
		if( rlm == NULL ){
			err = -EINVAL;
			RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_EAP_COMP_2_NO_REALM,"xxx",rx_resp_ikemesg,vpn,ikesa);
			RHP_BUG("");
			goto error;
		}

		RHP_LOCK(&(rlm->lock));

		if( !_rhp_atomic_read(&(rlm->is_active)) ){
			err = -EINVAL;
			RHP_UNLOCK(&(rlm->lock));
			RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_EAP_COMP_2_REALM_NOT_ACTIVE,"xxx",rx_resp_ikemesg,vpn,ikesa);
			goto error;
		}

		ikesa_lifetime_soft = (time_t)rlm->ikesa.lifetime_soft;
		ikesa_lifetime_hard = (time_t)rlm->ikesa.lifetime_hard;
		keep_alive_interval = (time_t)rlm->ikesa.keep_alive_interval;
		nat_t_keep_alive_interval = (time_t)rlm->ikesa.nat_t_keep_alive_interval;

		RHP_UNLOCK(&(rlm->lock));
  }

  s_pld_ctx.vpn_ref = rhp_vpn_hold_ref(vpn);
  s_pld_ctx.ikesa = ikesa;

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_N),
  			_rhp_ikev2_ike_auth_srch_n_error_cb,&s_pld_ctx);

  	if( ( err == 0 || err == RHP_STATUS_ENUM_OK ) && (s_pld_ctx.n_error_payload != NULL ) ){

      RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_EAP_COMP_2_RX_N_PEER_ERROR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);

     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_RESP_N_ERR_PAYLOAD,"KVPL",rx_resp_ikemesg,vpn,ikesa,"PROTO_IKE_NOTIFY",s_pld_ctx.n_err);

   	  err = RHP_STATUS_PEER_NOTIFIED_ERROR;
   	  goto error;

  	}else if( err && err != -ENOENT ){

  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_EAP_COMP_2_N_ERROR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
    	goto error;
  	}

  	err = 0;
  }


  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_AUTH),
  			_rhp_ikev2_ike_auth_srch_auth_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_EAP_COMP_2_ENUM_AUTH_PLD_ERR,"xxxd",rx_resp_ikemesg,vpn,ikesa,err);
      goto error;
    }

		if( s_pld_ctx.peer_auth_method != RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ){
			err = -EINVAL;
      RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_EAP_COMP_2_AUTH_PLD_METHOD_NOT_PSK,"xxxd",rx_resp_ikemesg,vpn,ikesa,s_pld_ctx.peer_auth_method);
  		goto error;
		}
  }


  err = rhp_eap_sup_impl_get_msk(vpn,vpn->eap.impl_ctx,&eap_msk_len,&eap_msk);

  if( err == -ENOENT ){

  	eap_skey_r = ikesa->keys.v2.sk_pr;
  	eap_skey_r_len = ikesa->keys.v2.sk_p_len;

  	err = 0;

  }else if( !err ){

    if( rhp_gcfg_dbg_log_keys_info ){
      RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_DBG_EAP_SUP_MSK_VRFY,"KVPp",rx_resp_ikemesg,vpn,ikesa,eap_msk_len,eap_msk);
    }

    eap_skey_r = eap_msk;
  	eap_skey_r_len = eap_msk_len;

  }else{
    RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_EAP_COMP_2_FAIL_TO_GET_MSK,"xxx",rx_resp_ikemesg,vpn,ikesa);
    goto error;
  }


  {
  	mesg_octets_r_len = ikesa->eap.pend_mesg_octets_r_len;
  	mesg_octets_r = ikesa->eap.pend_mesg_octets_r;
  	ikesa->eap.pend_mesg_octets_r = NULL;
  	ikesa->eap.pend_mesg_octets_r_len = 0;


		err = _rhp_ikev2_ike_auth_eap_verify_auth(vpn,ikesa,mesg_octets_r_len,mesg_octets_r,
				eap_skey_r_len,eap_skey_r,s_pld_ctx.peer_auth_octets_len,s_pld_ctx.peer_auth_octets);

		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_EAP_COMP_2_VERIFY_AUTH_FAILED,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
			goto error;
		}
  }

  {
		rlm = vpn->rlm;
		if( rlm == NULL ){
			err = -EINVAL;
			RHP_BUG("");
			goto error;
		}

		RHP_LOCK(&(rlm->lock));

		rhp_ikev2_ike_auth_setup_access_point(vpn,rlm);

	  vpn->vpn_conn_lifetime = (time_t)rlm->vpn_conn_lifetime;

		RHP_UNLOCK(&(rlm->lock));
  }

	rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_ESTABLISHED);
  vpn->created_ikesas++;

	rhp_ikev2_g_statistics_inc(ikesa_auth_eap);


	vpn->start_vpn_conn_life_timer(vpn);


	rhp_http_bus_broadcast_async(vpn->vpn_realm_id,1,1,
			rhp_ui_http_vpn_established_serialize,
			rhp_ui_http_vpn_bus_btx_async_cleanup,(void*)rhp_vpn_hold_ref(vpn)); // (*x*)


	if( vpn->init_by_peer_addr ){
		if( !rhp_gcfg_dmvpn_connect_shortcut_rate_limit ){
			rhp_vpn_connect_i_pending_clear(vpn->vpn_realm_id,NULL,&(vpn->peer_addr));
		}
	}else{
		rhp_vpn_connect_i_pending_clear(vpn->vpn_realm_id,&(vpn->peer_id),NULL);
	}

	ikesa->established_time = _rhp_get_time();
	ikesa->expire_hard = ikesa->established_time + ikesa_lifetime_hard;
	ikesa->expire_soft = ikesa->established_time + ikesa_lifetime_soft;


	ikesa->timers->start_lifetime_timer(vpn,ikesa,ikesa_lifetime_soft,1);
	ikesa->timers->start_keep_alive_timer(vpn,ikesa,keep_alive_interval);
	ikesa->timers->start_nat_t_keep_alive_timer(vpn,ikesa,nat_t_keep_alive_interval);

	{
		vpn->established = 1;

		if( vpn->connecting ){
			vpn->connecting = 0;
			rhp_ikesa_half_open_sessions_dec();
		}
	}

	vpn->auto_reconnect_retries = 0;

	if( vpn->internal_net_info.static_peer_addr ){

		rhp_vpn_internal_route_update(vpn);
	}


  _rhp_free_zero(mesg_octets_r,mesg_octets_r_len);


  rx_resp_ikemesg->merged_mesg = ikesa->eap.pend_rx_ikemesg;
  rhp_ikev2_hold_mesg(ikesa->eap.pend_rx_ikemesg);

  rhp_ikev2_unhold_mesg(ikesa->eap.pend_rx_ikemesg);
  ikesa->eap.pend_rx_ikemesg = NULL;

  if( eap_msk ){
  	_rhp_free_zero(eap_msk,eap_msk_len);
  }

  if( s_pld_ctx.vpn_ref ){
  	rhp_vpn_unhold(s_pld_ctx.vpn_ref);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_EAP_COMP_2_RTRN,"xxx",rx_resp_ikemesg,vpn,ikesa);
  return 0;

error:
  if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
  }

  if( s_pld_ctx.vpn_ref ){
  	rhp_vpn_unhold(s_pld_ctx.vpn_ref);
  }

  if( mesg_octets_r ){
    _rhp_free_zero(mesg_octets_r,mesg_octets_r_len);
  }

  if( eap_msk ){
  	_rhp_free_zero(eap_msk,eap_msk_len);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_L_EAP_COMP_2_ERR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
  return err;
}

static int _rhp_ikev2_ike_auth_srch_n_http_cert_lookup_supported_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_ike_auth_srch_plds_ctx* s_pld_ctx = (rhp_ike_auth_srch_plds_ctx*)ctx;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_N_HTTP_CERT_LOOKUP_SUPPORTED_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_N_HTTP_CERT_LOOKUP_SUPPORTED_CB_DUP_ERR,"xx",rx_ikemesg,ctx);
    goto error;
  }

  s_pld_ctx->http_cert_lookup_supported = 1;
  err = 0;

 	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_N_HTTP_CERT_LOOKUP_SUPPORTED_PAYLOAD,"K",rx_ikemesg);

error:
	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_N_HTTP_CERT_LOOKUP_SUPPORTED_CB_RTRN,"xxxE",rx_ikemesg,payload,ctx,err);
	return err;
}

static int _rhp_ikev2_ike_auth_srch_n_realm_id_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	int rx_len = 0;
	u8* rx_data = NULL;
	rhp_ike_auth_srch_plds_ctx* s_pld_ctx = (rhp_ike_auth_srch_plds_ctx*)ctx;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_N_REALM_ID_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_N_REALM_ID_CB_DUP_ERR,"xx",rx_ikemesg,ctx);
    goto error;
  }

  rx_len = payload->ext.n->get_data_len(payload);
	rx_data = payload->ext.n->get_data(payload);

	if( rx_len == sizeof(u32) ){

		unsigned long peer_notified_realm_id = ntohl(*((u32*)rx_data));

    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_N_REALM_ID_CB_DATA,"xu",rx_ikemesg,peer_notified_realm_id);

    if( peer_notified_realm_id &&
    		peer_notified_realm_id <= RHP_VPN_REALM_ID_MAX ){

     	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_N_REALM_ID_PAYLOAD,"Ku",rx_ikemesg,peer_notified_realm_id);

     	s_pld_ctx->peer_notified_realm_id = peer_notified_realm_id;

    }else{

    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_N_INVALID_REALM_ID_PAYLOAD,"Ku",rx_ikemesg,peer_notified_realm_id);
  		RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_N_REALM_ID_CB_BAD_ID,"xxxu",rx_ikemesg,payload,ctx,peer_notified_realm_id);
    }


		if( rhp_gcfg_ikev2_sess_resume_resp_enabled &&
				((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->origin_side == RHP_IKE_RESPONDER &&
				((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->sess_resume.gen_by_sess_resume ){

			rhp_ikev2_sess_resume_tkt_e* sess_res_tkt_e = NULL;

			if( s_pld_ctx->ikesa->sess_resume.resp.dec_tkt_ipc_rep == NULL ){

				RHP_BUG("");

				err = RHP_STATUS_INVALID_MSG;
				goto error;
			}

			err =  rhp_ikev2_sess_resume_dec_tkt_vals(
  					(rhp_ikev2_sess_resume_tkt*)(s_pld_ctx->ikesa->sess_resume.resp.dec_tkt_ipc_rep + 1),
  					&sess_res_tkt_e,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
			if( err ){
				goto error;
			}

			if( _rhp_ntohll(sess_res_tkt_e->vpn_realm_id) != peer_notified_realm_id ){

				s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;

				err = RHP_STATUS_INVALID_MSG;
				goto error;
			}
		}

	}else{

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_N_INVALID_REALM_ID_PAYLOAD_LEN,"Kd",rx_ikemesg,rx_len);
		RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_N_REALM_ID_CB_BAD_LEN,"xxxd",rx_ikemesg,payload,ctx,rx_len);
	}

  err = 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_N_REALM_ID_CB_RTRN,"xxxE",rx_ikemesg,payload,ctx,err);
	return err;
}


static int _rhp_ikev2_ike_auth_srch_cert_req_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_ike_auth_srch_plds_ctx* s_pld_ctx = (rhp_ike_auth_srch_plds_ctx*)ctx;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_CERT_REQ_CB,"xdxu",rx_ikemesg,enum_end,payload,s_pld_ctx->dup_flag);

  if( enum_end ){

  	if( s_pld_ctx->certreq_payload_head ){

  		s_pld_ctx->certreq_payload_num = s_pld_ctx->dup_flag;

  		RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_PARSE_CERTREQ_PAYLOADS,"Kd",rx_ikemesg,s_pld_ctx->certreq_payload_num);

  	}else{
  		RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_CERT_REQ_CB_NO_CERT_REQ_PLD,"xxx",rx_ikemesg,RHP_VPN_REF(s_pld_ctx->vpn_ref),s_pld_ctx->ikesa);
  		RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_NO_CERTREQ_PAYLOAD,"K",rx_ikemesg);
  	}

  }else{

	  rhp_ikev2_certreq_payload* certreq_payload = (rhp_ikev2_certreq_payload*)payload->ext.cert;
	  rhp_ikev2_payload* certreq_payload_head = NULL;
	  u8 enc;

	  if( certreq_payload == NULL ){
	  	RHP_BUG("");
	  	return -EINVAL;
	  }

	  enc = certreq_payload->get_cert_encoding(payload);

	  if( enc != RHP_PROTO_IKE_CERTENC_X509_CERT_SIG ){

	  	s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;

	  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_CERT_REQ_CB_UNKNOWN_ENCODE,"xxxb",rx_ikemesg,RHP_VPN_REF(s_pld_ctx->vpn_ref),s_pld_ctx->ikesa,enc);
  		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_UNSUPPORTED_CERTREQ_ENCODING,"Kb",rx_ikemesg,enc);

  		err = RHP_STATUS_IKEV2_AUTH_FAILED;
	  	goto error;
	  }

	  s_pld_ctx->dup_flag++;

	  if( s_pld_ctx->dup_flag == 1 ){

	  	s_pld_ctx->certreq_payload_head = payload;

	  }else if( s_pld_ctx->dup_flag > rhp_gcfg_max_cert_payloads ){

	    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_CERT_REQ_CB_TOO_MANY,"xxud",rx_ikemesg,payload,s_pld_ctx->dup_flag,rhp_gcfg_max_cert_payloads);
  		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_TOO_MANY_CERTREQ_PAYLOADS,"Kd",rx_ikemesg,s_pld_ctx->dup_flag);

  		err = RHP_STATUS_INVALID_MSG;
	    goto error;

	  }else{

	  	certreq_payload_head = s_pld_ctx->certreq_payload_head;

	  	if( certreq_payload_head->list_next == NULL ){
	  		certreq_payload_head->list_next = payload;
	  	}else{
	  		certreq_payload_head->list_tail->list_next = payload;
	    }
	  	certreq_payload_head->list_tail = payload;
	  }
  }

  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_CERT_REQ_CB_RTRN,"xxuE",rx_ikemesg,payload,s_pld_ctx->dup_flag,err);
  return err;
}

static int _rhp_ikev2_ike_auth_srch_check_childsa_cb(rhp_ikev2_mesg* ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
  rhp_ike_auth_srch_plds_ctx* s_pld_ctx = (rhp_ike_auth_srch_plds_ctx*)ctx;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_SRCH_CHECK_CHILDSA_CB,"xdxx",ikemesg,enum_end,payload,ctx);

 	s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_SRCH_CHECK_CHILDSA_CB_DUP_ERR,"xxx",ikemesg,payload,ctx);
    return RHP_STATUS_INVALID_MSG;
  }

  return 0;
}


int rhp_ikev2_rx_ike_auth_req_impl(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,
		rhp_ikev2_mesg* tx_resp_ikemesg,rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_ike_auth_srch_plds_ctx* s_pld_ctx = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_IMPL,"xxxxd",rx_req_ikemesg,vpn,ikesa,n_auth_tkt_payload,ikesa->gen_by_sess_resume);

  s_pld_ctx = _rhp_ike_auth_alloc_srch_ctx();
  if( s_pld_ctx == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }


  if( rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_BUG("");
  	goto error;
  }


  if( n_auth_tkt_payload == NULL ){

		err = rhp_ikev2_auth_tkt_spk2spk_invoke_dec_tkt_task(vpn,ikesa,
						rx_req_ikemesg,tx_resp_ikemesg,
						&(s_pld_ctx->notify_error),&(s_pld_ctx->notify_error_arg));

		if( err == RHP_STATUS_IKEV2_MESG_HANDLER_PENDING ){

			RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_IMPL_AUTH_TKT_HDL_PENDING,"xxxE",rx_req_ikemesg,vpn,ikesa,err);

			_rhp_ike_auth_free_srch_ctx(s_pld_ctx);

			goto auth_tkt_pending;

		}else if( err ){

			if( s_pld_ctx->notify_error ){
				goto notify_error;
			}

			RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_IMPL_AUTH_TKT_HDL_ERR,"xxxE",rx_req_ikemesg,vpn,ikesa,err);
			goto error;
		}

		//
		// 'err == 0' means that auth_tkt is disabled.
		//

  }else{

  	s_pld_ctx->n_auth_tkt_payload = n_auth_tkt_payload;
  }



  ikesa->timers->quit_lifetime_timer(vpn,ikesa);

  s_pld_ctx->vpn_ref = rhp_vpn_hold_ref(vpn);
	s_pld_ctx->ikesa = ikesa;


  {
		s_pld_ctx->dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_ID_I),
  			_rhp_ikev2_ike_auth_srch_id_cb,s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){

     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_REQ_PARSE_ID_I_PAYLOAD_ERR,"KVPE",rx_req_ikemesg,vpn,ikesa,err);

    	if( s_pld_ctx->notify_error ){
    		goto notify_error;
    	}

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_IMPL_ID_I_ERR,"xxxE",rx_req_ikemesg,vpn,ikesa,err);
    	goto error;
    }
  }

  {
  	s_pld_ctx->dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_ID_R),
  			_rhp_ikev2_ike_auth_srch_id_cb,s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){

     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_REQ_PARSE_ID_R_PAYLOAD_ERR,"KVPE",rx_req_ikemesg,vpn,ikesa,err);

    	if( s_pld_ctx->notify_error ){
    		goto notify_error;
    	}

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_IMPL_ENUM_ID_R_ERR,"xxxd",rx_req_ikemesg,vpn,ikesa,err);
    	goto error;
    }
  }


  {
  	s_pld_ctx->dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_AUTH),
  			_rhp_ikev2_ike_auth_srch_auth_cb,s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){

     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_REQ_PARSE_AUTH_PAYLOAD_ERR,"KVPE",rx_req_ikemesg,vpn,ikesa,err);

    	if( s_pld_ctx->notify_error ){
    		goto notify_error;
    	}

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_IMPL_ENUM_AUTH_ERR,"xxxd",rx_req_ikemesg,vpn,ikesa,err);
    	goto error;
    }

    if( err == -ENOENT ){

    	if( ikesa->gen_by_sess_resume ){

    		s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;
  			err = RHP_STATUS_INVALID_MSG;

      	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_IMPL_ENUM_AUTH_NO_AUTH_PLD_SESS_RESUME_ERR,"xxxE",rx_req_ikemesg,vpn,ikesa,err);
  			goto notify_error;

    	}else if( rhp_ikev2_is_null_auth_id(s_pld_ctx->id_i_type) ){

    		s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;
  			err = RHP_STATUS_INVALID_MSG;

      	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_IMPL_ENUM_AUTH_NO_AUTH_PLD_NULL_ID_I_R_ERR,"xxxddE",rx_req_ikemesg,vpn,ikesa,s_pld_ctx->id_i_type,s_pld_ctx->id_r_type,err);
  			goto notify_error;

    	}else if( s_pld_ctx->n_auth_tkt_payload ){

    		s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;
  			err = RHP_STATUS_INVALID_MSG;

      	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_IMPL_ENUM_AUTH_NO_AUTH_PLD_AUTH_TKT_ERR,"xxxE",rx_req_ikemesg,vpn,ikesa,err);
  			goto notify_error;
    	}

    	s_pld_ctx->eap_used = 1;
    }

		if( s_pld_ctx->n_auth_tkt_payload &&
				s_pld_ctx->peer_auth_method != RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ){

  		s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;
			err = RHP_STATUS_INVALID_MSG;

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_IMPL_ENUM_AUTH_AUTH_PLD_INVALID_AUTH_METHOD_FOR_AUTH_TKT_ERR,"xxxdE",rx_req_ikemesg,vpn,ikesa,s_pld_ctx->peer_auth_method,err);
			goto notify_error;
		}
  }


  {
  	s_pld_ctx->dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,1,
    		rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_CERT),
    		_rhp_ikev2_ike_auth_srch_cert_cb,s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){

  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_IMPL_ENUM_CERT_ERR,"xxxE",rx_req_ikemesg,vpn,ikesa,err);
  		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_REQ_PARSE_CERT_PAYLOAD_ERR,"KVPE",rx_req_ikemesg,vpn,ikesa,err);

  		if( s_pld_ctx->notify_error ){
  			goto notify_error;
  		}

  		goto error;
  	}

  	if( s_pld_ctx->peer_auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG &&
  			( s_pld_ctx->peer_cert_pld == NULL || !s_pld_ctx->cert_payload_num) ){

  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_IMPL_ENUM_CERT_NO_CERT_PAYLOAD_ERR,"xxx",rx_req_ikemesg,vpn,ikesa);

  		s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;
  		err = RHP_STATUS_INVALID_MSG;

  		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_REQ_NO_CERT_PAYLOAD,"KVP",rx_req_ikemesg,vpn,ikesa);

  		goto notify_error;
  	}
  }

  {
  	s_pld_ctx->dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,1,
    		rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_CERTREQ),
    		_rhp_ikev2_ike_auth_srch_cert_req_cb,s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){

    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_REQ_PARSE_CERTREQ_PAYLOAD_ERR,"KVPE",rx_req_ikemesg,vpn,ikesa,err);

  		if( s_pld_ctx->notify_error ){
  			goto notify_error;
  		}

  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_IMPL_ENUM_CERT_REQ_PLD_ERR,"xxxd",rx_req_ikemesg,vpn,ikesa,err);
  		goto error;
  	}
  }

  if( rhp_gcfg_hash_url_enabled(RHP_IKE_RESPONDER) ){

  	s_pld_ctx->dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_n_mesg_id,(void*)((unsigned long)RHP_PROTO_IKE_NOTIFY_ST_HTTP_CERT_LOOKUP_SUPPORTED),
  			_rhp_ikev2_ike_auth_srch_n_http_cert_lookup_supported_cb,s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){

     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_REQ_PARSE_N_HTTP_CERT_LOOKUP_PAYLOAD_ERR,"KVPE",rx_req_ikemesg,vpn,ikesa,err);

  		if( s_pld_ctx->notify_error ){
  			goto notify_error;
  		}

  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_IMPL_HTTP_LOOKUP_SUPPORTED_ERR,"xxxE",vpn,ikesa,rx_req_ikemesg,err);
    	goto error;
  	}

  	ikesa->peer_http_cert_lookup_supported = s_pld_ctx->http_cert_lookup_supported;
  	vpn->peer_http_cert_lookup_supported = s_pld_ctx->http_cert_lookup_supported;
  }


  if( vpn->peer_is_rockhopper ){

  	s_pld_ctx->dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_n_mesg_id,(void*)((unsigned long)RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_REALM_ID),
  			_rhp_ikev2_ike_auth_srch_n_realm_id_cb,s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){

     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_REQ_PARSE_N_REALM_ID_PAYLOAD_ERR,"KVPE",rx_req_ikemesg,vpn,ikesa,err);

  		if( s_pld_ctx->notify_error ){
  			goto notify_error;
  		}

  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_IMPL_REALM_ID_PARSE_ERR,"xxxE",vpn,ikesa,rx_req_ikemesg,err);
    	goto error;
  	}

  	vpn->peer_notified_realm_id = s_pld_ctx->peer_notified_realm_id;
  }



  if( rhp_gcfg_reject_auth_exchg_without_childsa ){

  	s_pld_ctx->dup_flag = 0;

		err = rx_req_ikemesg->search_payloads( rx_req_ikemesg, 0,
				rhp_ikev2_mesg_srch_cond_payload_id,
				(void*) ((unsigned long) RHP_PROTO_IKE_PAYLOAD_SA),
				_rhp_ikev2_ike_auth_srch_check_childsa_cb, s_pld_ctx );

		if(err && err != RHP_STATUS_ENUM_OK){

			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_REQ_NO_SA_PAYLOAD_FOR_CHILDSA,"KE",rx_req_ikemesg,err);

			s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_NO_PROPOSAL_CHOSEN;

			RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_IMPL_NO_CHILDSA_SA_PLD,"xxxE",rx_req_ikemesg,vpn,ikesa,err);
			goto notify_error;
		}


		s_pld_ctx->dup_flag = 0;

		err = rx_req_ikemesg->search_payloads( rx_req_ikemesg, 0,
				rhp_ikev2_mesg_srch_cond_payload_id,
				(void*) ((unsigned long) RHP_PROTO_IKE_PAYLOAD_TS_I),
				_rhp_ikev2_ike_auth_srch_check_childsa_cb, s_pld_ctx );

		if(err && err != RHP_STATUS_ENUM_OK){

			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_REQ_NO_TS_I_PAYLOAD_FOR_CHILDSA,"KE",rx_req_ikemesg,err);

			s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_NO_PROPOSAL_CHOSEN;

			RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_IMPL_NO_CHILDSA_TS_I_PLD,"xxxE",rx_req_ikemesg,vpn,ikesa,err);
			goto notify_error;
		}


		s_pld_ctx->dup_flag = 0;

		err = rx_req_ikemesg->search_payloads( rx_req_ikemesg, 0,
				rhp_ikev2_mesg_srch_cond_payload_id,
				(void*) ((unsigned long) RHP_PROTO_IKE_PAYLOAD_TS_R),
				_rhp_ikev2_ike_auth_srch_check_childsa_cb, s_pld_ctx );

		if(err && err != RHP_STATUS_ENUM_OK){

			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_REQ_NO_TS_R_PAYLOAD_FOR_CHILDSA,"KE",rx_req_ikemesg,err);

			s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_NO_PROPOSAL_CHOSEN;

			RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_IMPL_NO_CHILDSA_TS_R_PLD,"xxxE",rx_req_ikemesg,vpn, ikesa,err);
			goto notify_error;
		}
  }


	if( ikesa->gen_by_sess_resume ){

		err = _rhp_ikev2_rx_ike_auth_req_sess_resume(vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,s_pld_ctx);
		if( err ){

			s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;
			s_pld_ctx->notify_error_arg = 0;

			goto notify_error;
		}

  	_rhp_ike_auth_free_srch_ctx(s_pld_ctx);

	}else if( s_pld_ctx->peer_auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG &&
  					((s_pld_ctx->peer_cert_pld &&
  						s_pld_ctx->peer_cert_pld->encoding == RHP_PROTO_IKE_CERTENC_X509_CERT_HASH_URL) ||
  						s_pld_ctx->ca_certs_hash_url_num) ){

  	s_pld_ctx->ikesa = NULL;
  	s_pld_ctx->rlm = NULL;

  	s_pld_ctx->rx_ikemesg = rx_req_ikemesg;
		rhp_ikev2_hold_mesg(rx_req_ikemesg);

  	s_pld_ctx->tx_ikemesg = tx_resp_ikemesg;
		rhp_ikev2_hold_mesg(tx_resp_ikemesg);

		s_pld_ctx->my_ikesa_side = ikesa->side;
		memcpy(s_pld_ctx->my_ikesa_spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);

	  ikesa->busy_flag = 1;

  	err = _rhp_ikev2_rx_ike_auth_hash_url_get_certs(s_pld_ctx,
  					_rhp_ikev2_rx_ike_auth_req_hash_url_certs_cb,(void*)s_pld_ctx);
  	if( err ){

  		ikesa->busy_flag = 0;

  	  s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;
  	  s_pld_ctx->notify_error_arg = 0;

  	  goto notify_error;
  	}

		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_IMPL_CERT_DER_NOT_RESOLVED,"xxx",rx_req_ikemesg,vpn,ikesa);
		err = RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;

  }else{

  	err = _rhp_ikev2_rx_ike_auth_req_bh(vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,s_pld_ctx);
  	if( err ){

  		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_IMPL_BH_ERR,"xxxE",rx_req_ikemesg,vpn,ikesa,err);

  		if( s_pld_ctx->notify_error ){
  			goto notify_error;
  		}

  		goto error;
  	}

  	_rhp_ike_auth_free_srch_ctx(s_pld_ctx);
		err = RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;
  }


	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_REQ_OK,"KVP",rx_req_ikemesg,vpn,ikesa);

auth_tkt_pending:
  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_IMPL_RTRN,"xxxE",rx_req_ikemesg,vpn,ikesa,err);

  return err;


notify_error:
	err = rhp_ikev2_new_pkt_ike_auth_error_notify(ikesa,tx_resp_ikemesg,0,0,
					s_pld_ctx->notify_error,s_pld_ctx->notify_error_arg);

  if( err ){
  	RHP_BUG("");
  	goto error;
  }

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_AUTH_REQ_TX_ERROR_NOTIFY,"KVPL",rx_req_ikemesg,vpn,ikesa,"PROTO_IKE_NOTIFY",s_pld_ctx->notify_error);

  err = RHP_STATUS_IKEV2_DESTROY_SA_AFTER_TX;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_REQ_ERR,"KVPE",rx_req_ikemesg,vpn,ikesa,err);

  if( ikesa && err != RHP_STATUS_IKEV2_DESTROY_SA_AFTER_TX ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
  }

  if( s_pld_ctx ){
  	_rhp_ike_auth_free_srch_ctx(s_pld_ctx);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_IMPL_ERR,"xxxE",rx_req_ikemesg,vpn,ikesa,err);
  return err;
}

int rhp_ikev2_ike_auth_r_eap_rebind_rlm(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg)
{
	int err = -EINVAL;

	RHP_TRC(0,RHP_IKEV2_AUTH_R_EAP_REBIND_RLM,"xxxuu",vpn,ikesa,rx_req_ikemesg,vpn->eap.rebound_vpn_realm_id,vpn->peer_notified_realm_id);

	if( vpn->eap.rebound_vpn_realm_id ){

		if( vpn->peer_notified_realm_id &&
				vpn->peer_notified_realm_id != RHP_VPN_REALM_ID_UNKNOWN &&
				vpn->peer_notified_realm_id != vpn->eap.rebound_vpn_realm_id ){

			RHP_TRC(0,RHP_IKEV2_AUTH_R_EAP_REBIND_RLM_PEER_NOTIFIED_RLM_ID_NOT_MATCHED_ERR,"xxxuu",rx_req_ikemesg,vpn,ikesa,vpn->eap.rebound_vpn_realm_id,vpn->peer_notified_realm_id);

			if( vpn->eap.eap_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS ){
				RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_AUTH_RADIUS_PEER_NOTIFIED_REALM_NOT_MATCH,"KVuu",rx_req_ikemesg,vpn,vpn->eap.rebound_vpn_realm_id,vpn->peer_notified_realm_id);
			}else{
				RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_AUTH_PEER_NOTIFIED_REALM_NOT_MATCH,"KVuu",rx_req_ikemesg,vpn,vpn->eap.rebound_vpn_realm_id,vpn->peer_notified_realm_id);
			}

			err = RHP_STATUS_INVALID_IKEV2_MESG_NO_REALM;
			goto error;
		}


		if( vpn->vpn_realm_id != vpn->eap.rebound_vpn_realm_id ){

			rhp_vpn_realm* rb_rlm;

			rb_rlm = rhp_realm_get(vpn->eap.rebound_vpn_realm_id);
			if( rb_rlm ){

				RHP_TRC(0,RHP_IKEV2_AUTH_R_EAP_REBIND_RLM_REBIND_RLM_INFO,"xxxxxuu",rx_req_ikemesg,vpn,ikesa,vpn->rlm,rb_rlm,vpn->vpn_realm_id,vpn->eap.rebound_vpn_realm_id);

				RHP_LOCK(&(rb_rlm->lock));

				if( !_rhp_atomic_read(&(rb_rlm->is_active)) ){
					RHP_UNLOCK(&(rb_rlm->lock));
					goto error;
				}

				if( vpn->rlm ){
					rhp_realm_unhold(vpn->rlm);
					vpn->rlm = NULL;
				}

				if( vpn->cfg_peer ){
					rhp_realm_free_peer_cfg(vpn->cfg_peer);
					vpn->cfg_peer = NULL;
				}


				vpn->vpn_realm_id = vpn->eap.rebound_vpn_realm_id;

				vpn->rlm = rb_rlm;
				rhp_realm_hold(rb_rlm);

				vpn->cfg_peer = rb_rlm->dup_peer_by_id(rb_rlm,&(vpn->peer_id),&(vpn->peer_addr));
				if( vpn->cfg_peer == NULL ){
					RHP_UNLOCK(&(rb_rlm->lock));
					goto error;
				}

				RHP_UNLOCK(&(rb_rlm->lock));
				rhp_realm_unhold(rb_rlm);


				{
					int intr_old_flag = vpn->internal_net_info.static_peer_addr;

					if( !rhp_ip_addr_null(&(vpn->cfg_peer->internal_addr)) ){

						rhp_ip_addr_list* peer_addr;

						peer_addr = rhp_ip_dup_addr_list(&(vpn->cfg_peer->internal_addr));
						if( peer_addr == NULL ){
							RHP_BUG("");
							goto error;
						}
						peer_addr->ip_addr.tag = RHP_IPADDR_TAG_STATIC_PEER_ADDR;

						peer_addr->next = vpn->internal_net_info.peer_addrs;
						vpn->internal_net_info.peer_addrs = peer_addr;

						vpn->internal_net_info.static_peer_addr = 1;

					}else{

						vpn->internal_net_info.static_peer_addr = 0;
					}

					if( !intr_old_flag && vpn->internal_net_info.static_peer_addr ){
						rhp_vpn_internal_route_update(vpn);
					}
				}

			}else{

				RHP_TRC(0,RHP_IKEV2_AUTH_R_EAP_REBIND_RLM_REBIND_RLM_NOT_FOUND,"xxxxuud",rx_req_ikemesg,vpn,ikesa,vpn->rlm,vpn->vpn_realm_id,vpn->eap.rebound_vpn_realm_id,vpn->eap.eap_method);

				if( vpn->eap.eap_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS ){
					RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_AUTH_RADIUS_REALM_NOT_FOUND,"KV",rx_req_ikemesg,vpn);
				}else{
					RHP_BUG("");
				}

				err = RHP_STATUS_INVALID_IKEV2_MESG_NO_REALM;
				goto error;
			}
		}

	}else{

		RHP_TRC(0,RHP_IKEV2_AUTH_R_EAP_REBIND_RLM_NOP,"xxx",vpn,ikesa,rx_req_ikemesg);
  }

	RHP_TRC(0,RHP_IKEV2_AUTH_R_EAP_REBIND_RLM_RTRN,"xxxuu",vpn,ikesa,rx_req_ikemesg,vpn->eap.rebound_vpn_realm_id,vpn->peer_notified_realm_id);
  return 0;

error:
	RHP_TRC(0,RHP_IKEV2_AUTH_R_EAP_REBIND_RLM_ERR,"xxxE",vpn,ikesa,rx_req_ikemesg,err);
	return err;
}

static int _rhp_ikev2_rx_ike_auth_req_eap_comp(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,
		rhp_ikev2_mesg* tx_resp_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  u8 *mesg_octets_i = NULL,*mesg_octets_r = NULL;
  int mesg_octets_i_len = 0,mesg_octets_r_len = 0;
  rhp_ike_auth_srch_plds_ctx s_pld_ctx;
  rhp_vpn_realm* rlm = NULL;
  rhp_ikev2_mesg* eap_pend_rx_ikemesg = NULL;
  u8 *eap_msk = NULL,*eap_skey_i = NULL,*eap_skey_r = NULL;
  int eap_msk_len = 0,eap_skey_i_len = 0,eap_skey_r_len = 0;
  int auth_data_len = 0;
  u8* auth_data = NULL;
  time_t ikesa_lifetime_soft = 0,keep_alive_interval = 0,ikesa_lifetime_hard = 0,nat_t_keep_alive_interval = 0;
  rhp_vpn* old_vpn = NULL;
  void* old_vpn_ref = NULL;


  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_EAP_COMP,"xxx",rx_req_ikemesg,vpn,ikesa);

  memset(&s_pld_ctx,0,sizeof(rhp_ike_auth_srch_plds_ctx));

  if( rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_BUG("");
  	goto error;
  }


  eap_pend_rx_ikemesg = ikesa->eap.pend_rx_ikemesg;
  if( eap_pend_rx_ikemesg == NULL ){
  	RHP_BUG("");
  	goto error;
  }


  ikesa->timers->quit_lifetime_timer(vpn,ikesa);

  s_pld_ctx.vpn_ref = rhp_vpn_hold_ref(vpn);
  s_pld_ctx.ikesa = ikesa;


  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_AUTH),
  			_rhp_ikev2_ike_auth_srch_auth_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){

    	if( s_pld_ctx.notify_error ){
      	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_EAP_COMP_ENUM_AUTH_NOTIFY_ERR,"xxxdLd",rx_req_ikemesg,vpn,ikesa,err,"PROTO_IKE_NOTIFY",s_pld_ctx.notify_error);
    		goto notify_error;
    	}

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_EAP_COMP_ENUM_AUTH_ERR,"xxxd",rx_req_ikemesg,vpn,ikesa,err);
    	goto error;
    }

		if( s_pld_ctx.peer_auth_method != RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ){

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_EAP_COMP_ENUM_AUTH_ERR,"xxxLdd",rx_req_ikemesg,vpn,ikesa,"PROTO_IKE_AUTHMETHOD",s_pld_ctx.peer_auth_method,RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY);

			s_pld_ctx.notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;
  		goto notify_error;
		}
  }


  err = rhp_eap_auth_get_msk(vpn,vpn->eap.impl_ctx,&eap_msk_len,&eap_msk);

  if( err == -ENOENT ){

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_EAP_COMP_NO_MSK,"xxx",rx_req_ikemesg,vpn,ikesa);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_EAP_AUTH_MSK_NOT_AVAILABLE,"KVP",rx_req_ikemesg,vpn,ikesa);

  	eap_skey_i = ikesa->keys.v2.sk_pi;
  	eap_skey_i_len = ikesa->keys.v2.sk_p_len;

  	eap_skey_r = ikesa->keys.v2.sk_pr;
  	eap_skey_r_len = ikesa->keys.v2.sk_p_len;

  	err = 0;

  }else if( !err ){

    if( rhp_gcfg_dbg_log_keys_info ){
      RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_DBG_EAP_AUTH_MSK,"KVPp",rx_req_ikemesg,vpn,ikesa,eap_msk_len,eap_msk);
    }

  	eap_skey_i = eap_msk;
  	eap_skey_i_len = eap_msk_len;

  	eap_skey_r = eap_msk;
  	eap_skey_r_len = eap_msk_len;

  }else{

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_EAP_COMP_FAIL_TO_GET_MSK,"xxxE",rx_req_ikemesg,vpn,ikesa,err);

  	s_pld_ctx.notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;
		goto notify_error;
  }


	{
  	ikesa->peer_auth_method = s_pld_ctx.peer_auth_method;

  	mesg_octets_i_len = ikesa->eap.pend_mesg_octets_i_len;
  	mesg_octets_i = ikesa->eap.pend_mesg_octets_i;
  	ikesa->eap.pend_mesg_octets_i_len = 0;
  	ikesa->eap.pend_mesg_octets_i = NULL;

		err = _rhp_ikev2_ike_auth_eap_verify_auth(vpn,ikesa,mesg_octets_i_len,mesg_octets_i,
				eap_skey_i_len,eap_skey_i,s_pld_ctx.peer_auth_octets_len,s_pld_ctx.peer_auth_octets);

		if( err ){

			RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_EAP_COMP_VERIFY_AUTH_FAILED,"xxxE",eap_pend_rx_ikemesg,vpn,ikesa,err);

			s_pld_ctx.notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;
  		goto notify_error;
		}
	}

  {
  	mesg_octets_r_len = ikesa->eap.pend_mesg_octets_r_len;
  	mesg_octets_r = ikesa->eap.pend_mesg_octets_r;
  	ikesa->eap.pend_mesg_octets_r_len = 0;
  	ikesa->eap.pend_mesg_octets_r = NULL;

		err = _rhp_ikev2_ike_auth_eap_sign_auth(vpn,ikesa,&mesg_octets_r_len,&mesg_octets_r,
				eap_skey_r_len,eap_skey_r,&auth_data_len,&auth_data);

    if( err ){

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_EAP_COMP_SIGN_REQ_ERR,"xxxE",eap_pend_rx_ikemesg,vpn,ikesa,err);

    	s_pld_ctx.notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;
  		goto notify_error;
    }
  }


  err = rhp_ikev2_ike_auth_r_eap_rebind_rlm(vpn,ikesa,rx_req_ikemesg);
  if( err ){
		s_pld_ctx.notify_error = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;
		goto notify_error;
  }


  rlm = vpn->rlm;
  if( rlm == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_EAP_COMP_NO_REALM,"xx",vpn,ikesa);
    goto error;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_EAP_COMP_REALM_NOT_ACTIVE,"xxx",vpn,ikesa,rlm);
    err = -EINVAL;
    goto error_rlm_l;
  }


  err = rhp_ikev2_ike_auth_r_setup_nhrp(vpn,rlm,ikesa);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_EAP_COMP_SETUP_NHRP_ERR,"xxxE",rx_req_ikemesg,ikesa,rlm,err);
    goto error_rlm_l;
  }


  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_EAP_COMP_NET_MODE,"xxxx",rx_req_ikemesg,vpn,ikesa,rlm);


  err = _rhp_ikev2_new_pkt_ike_auth_eap_rep(vpn,ikesa,
  		rx_req_ikemesg,eap_pend_rx_ikemesg,rlm,tx_resp_ikemesg,auth_data_len,auth_data);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_EAP_COMP_ALLOC_IKEMSG_ERR,"xxxE",rx_req_ikemesg,ikesa,rlm,err);
    goto error_rlm_l;
  }


  ikesa_lifetime_soft = (time_t)rlm->ikesa.lifetime_soft;
  ikesa_lifetime_hard = (time_t)rlm->ikesa.lifetime_hard;
  keep_alive_interval = (time_t)rlm->ikesa.keep_alive_interval;
  nat_t_keep_alive_interval = (time_t)rlm->ikesa.nat_t_keep_alive_interval;


  if( vpn->eap.eap_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS &&
  		vpn->radius.rx_accept_attrs &&
  		vpn->radius.rx_accept_attrs->session_timeout ){

  	vpn->vpn_conn_lifetime = (time_t)vpn->radius.rx_accept_attrs->session_timeout;
  }

  if( vpn->vpn_conn_lifetime == 0 ){
  	vpn->vpn_conn_lifetime = (time_t)rlm->vpn_conn_lifetime;
  }


	if( !rhp_eap_id_is_null(&(vpn->eap.peer_id)) &&
			(vpn->eap.eap_method != RHP_PROTO_EAP_TYPE_PRIV_RADIUS ||
			rhp_eap_id_radius_not_null(&(vpn->eap.peer_id))) ){

		old_vpn_ref = rhp_vpn_get_by_eap_peer_id(rlm->id,&(vpn->eap.peer_id));
		old_vpn = RHP_VPN_REF(old_vpn_ref);
	}

	if( old_vpn == NULL &&
			vpn->eap.eap_method != RHP_PROTO_EAP_TYPE_PRIV_RADIUS ){

		old_vpn_ref = rhp_vpn_get(rlm->id,&(vpn->peer_id),&(vpn->eap.peer_id));
		old_vpn = RHP_VPN_REF(old_vpn_ref);
	}

	rhp_vpn_put(vpn);

	rhp_ikev2_ike_auth_setup_access_point(vpn,rlm);

  RHP_UNLOCK(&(rlm->lock));



  {
		rhp_http_bus_broadcast_async(vpn->vpn_realm_id,1,1,
			rhp_ui_http_vpn_added_serialize,
			rhp_ui_http_vpn_bus_btx_async_cleanup,(void*)rhp_vpn_hold_ref(vpn)); // (*x*)

		RHP_LOG_I(RHP_LOG_SRC_VPNMNG,vpn->vpn_realm_id,RHP_LOG_ID_VPN_ADDED,"IAsNA",&(vpn->peer_id),&(vpn->peer_addr),vpn->peer_fqdn,vpn->unique_id,NULL);
  }


	if( old_vpn ){

		int my_side = ikesa->side;
	  u8 my_spi[RHP_PROTO_IKE_SPI_SIZE];
	  memcpy(my_spi,ikesa->get_my_spi(ikesa),RHP_PROTO_IKE_SPI_SIZE);

		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_EAP_COMP_DESTROY_OLD_VPN,"xxxxx",rx_req_ikemesg,vpn,ikesa,rlm,old_vpn);

	  RHP_UNLOCK(&(vpn->lock));


	  {
			RHP_LOCK(&(old_vpn->lock));

			rhp_vpn_destroy(old_vpn);

			RHP_UNLOCK(&(old_vpn->lock));
			rhp_vpn_unhold(old_vpn_ref);
			old_vpn_ref = NULL;
			old_vpn = NULL;
	  }


	  RHP_LOCK(&(vpn->lock));

    if( !_rhp_atomic_read(&(vpn->is_active)) ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_EAP_COMP_IKESA_NOT_ACTIVE_2,"xxx",rx_req_ikemesg,vpn);
      err = -EINVAL;
      goto error;
    }

    ikesa = vpn->ikesa_get(vpn,my_side,my_spi);
    if( ikesa == NULL ){
    	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_EAP_COMP_NO_IKESA_2,"xxLdG",rx_req_ikemesg,vpn,"IKE_SIDE",my_side,my_spi);
      err = -EINVAL;
    	goto error;
    }

	}else{

		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_EAP_COMP_NO_OLD_VPN,"xxxx",rx_req_ikemesg,vpn,ikesa,rlm);
	}


	rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_ESTABLISHED);
  vpn->created_ikesas++;

	rhp_ikev2_g_statistics_inc(ikesa_auth_eap);


	vpn->start_vpn_conn_life_timer(vpn);


	rhp_http_bus_broadcast_async(vpn->vpn_realm_id,1,1,
			rhp_ui_http_vpn_established_serialize,
			rhp_ui_http_vpn_bus_btx_async_cleanup,(void*)rhp_vpn_hold_ref(vpn)); // (*x*)


	ikesa->established_time = _rhp_get_time();
	ikesa->expire_hard = ikesa->established_time + ikesa_lifetime_hard;
	ikesa->expire_soft = ikesa->established_time + ikesa_lifetime_soft;

	{
		vpn->established = 1;

		if( vpn->connecting ){
			vpn->connecting = 0;
			rhp_ikesa_half_open_sessions_dec();
		}
	}

	vpn->auto_reconnect_retries = 0;

	ikesa->timers->start_lifetime_timer(vpn,ikesa,ikesa_lifetime_soft,1);
	ikesa->timers->start_keep_alive_timer(vpn,ikesa,keep_alive_interval);
	ikesa->timers->start_nat_t_keep_alive_timer(vpn,ikesa,nat_t_keep_alive_interval);


  if( eap_msk ){
  	_rhp_free_zero(eap_msk,eap_msk_len);
  }

  if( s_pld_ctx.vpn_ref ){
  	rhp_vpn_unhold(s_pld_ctx.vpn_ref);
  }

  _rhp_free_zero(mesg_octets_i,mesg_octets_i_len);
  _rhp_free_zero(mesg_octets_r,mesg_octets_r_len);
  _rhp_free(auth_data);


	rx_req_ikemesg->merged_mesg = ikesa->eap.pend_rx_ikemesg;
  rhp_ikev2_hold_mesg(ikesa->eap.pend_rx_ikemesg);

  rhp_ikev2_unhold_mesg(ikesa->eap.pend_rx_ikemesg);
  ikesa->eap.pend_rx_ikemesg = NULL;


  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_EAP_COMP_RTRN,"xxxx",rx_req_ikemesg,eap_pend_rx_ikemesg,vpn,ikesa);

  return 0;


notify_error:
	err = rhp_ikev2_new_pkt_ike_auth_error_notify(ikesa,tx_resp_ikemesg,0,0,
						s_pld_ctx.notify_error,s_pld_ctx.notify_error_arg);

  if( err ){
  	RHP_BUG("");
  	goto error;
  }

  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_AUTH_REQ_EAP_TX_ERR_NOTIFY,"KVPL",rx_req_ikemesg,vpn,ikesa,"PROTO_IKE_NOTIFY",s_pld_ctx.notify_error);
  err = RHP_STATUS_IKEV2_DESTROY_SA_AFTER_TX;

error:
	if( old_vpn_ref ){
		rhp_vpn_unhold(old_vpn_ref);
	}

	if( ikesa && err != RHP_STATUS_IKEV2_DESTROY_SA_AFTER_TX ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
  }

	if( mesg_octets_i ){
    _rhp_free_zero(mesg_octets_i,mesg_octets_i_len);
  }

	if( mesg_octets_r ){
    _rhp_free_zero(mesg_octets_r,mesg_octets_r_len);
  }

	if( auth_data ){
    _rhp_free_zero(auth_data,auth_data_len);
  }

  if( eap_msk ){
  	_rhp_free_zero(eap_msk,eap_msk_len);
  }

  if( s_pld_ctx.vpn_ref ){
  	rhp_vpn_unhold(s_pld_ctx.vpn_ref);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_L_EAP_COMP_ERR,"xxxxE",rx_req_ikemesg,eap_pend_rx_ikemesg,vpn,ikesa,err);
  return err;

error_rlm_l:
	RHP_UNLOCK(&(rlm->lock));
	goto error;
}

int rhp_ikev2_rx_ike_auth_req(rhp_ikev2_mesg* rx_req_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err = -EINVAL;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_req_ikemesg->get_exchange_type(rx_req_ikemesg);
	u32 mesg_id;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ,"xxLdGxLbb",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_resp_ikemesg,"PROTO_IKE_EXCHG",exchange_type,vpn->auth_ticket.conn_type);


  if( exchange_type != RHP_PROTO_IKE_EXCHG_IKE_AUTH ){
		err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_NOT_IKE_AUTH_EXCHG,"xxLb",rx_req_ikemesg,vpn,"PROTO_IKE_EXCHG",exchange_type);
		goto error;
	}

	if( !RHP_PROTO_IKE_HDR_INITIATOR(rx_req_ikemesg->rx_pkt->app.ikeh->flag) ){
		err = RHP_STATUS_INVALID_MSG;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_INVALID_MESG1,"xx",rx_req_ikemesg,vpn);
		goto error;
  }

  if( !rx_req_ikemesg->decrypted ){
  	err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_NOT_DECRYPTED,"xx",rx_req_ikemesg,vpn);
  	goto error;
  }

	if( my_ikesa_spi == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

	ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
	if( ikesa == NULL ){
		err = -ENOENT;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_NO_IKESA,"xxLdG",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
		goto error;
	}

  if( ikesa->state != RHP_IKESA_STAT_R_IKE_SA_INIT_SENT ){
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_BAD_IKESA_STAT,"xxLdGLd",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state);
  	err = RHP_STATUS_BAD_SA_STATE;
  	goto error;
  }

	mesg_id = rx_req_ikemesg->get_mesg_id(rx_req_ikemesg);

	if( mesg_id == 1 ){

		if( ikesa->eap.state != RHP_IKESA_EAP_STAT_DEFAULT ){
	  	err = RHP_STATUS_BAD_SA_STATE;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_BAD_EAP_STAT1,"xxLdGLd",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"EAP_STAT",ikesa->eap.state);
			goto error;
		}

		err = rhp_ikev2_rx_ike_auth_req_impl(vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,NULL);

	}else{ // EAP

	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_EAP_STAT,"xxLdGLd",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state,"EAP_STAT",ikesa->eap.state);

		if( ikesa->eap.state == RHP_IKESA_EAP_STAT_R_PEND ){

			err = 0;
			goto error;

		}else if( ikesa->eap.state == RHP_IKESA_EAP_STAT_R_COMP ){

			err = _rhp_ikev2_rx_ike_auth_req_eap_comp(vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);

		}else{
	  	err = RHP_STATUS_BAD_SA_STATE;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_BAD_EAP_STAT2,"xxLdGLd",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"EAP_STAT",ikesa->eap.state);
			goto error;
		}
	}

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REQ_RTRN,"xxxE",rx_req_ikemesg,vpn,tx_resp_ikemesg,err);
  return err;
}

int rhp_ikev2_rx_ike_auth_rep(rhp_ikev2_mesg* rx_resp_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err = -EINVAL;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_resp_ikemesg->get_exchange_type(rx_resp_ikemesg);
	u32 mesg_id;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP,"xxLdGxLbb",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_req_ikemesg,"PROTO_IKE_EXCHG",exchange_type,vpn->auth_ticket.conn_type);


	if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ||
			exchange_type == RHP_PROTO_IKE_EXCHG_SESS_RESUME ){

		if( RHP_PROTO_IKE_HDR_INITIATOR(rx_resp_ikemesg->rx_pkt->app.ikeh->flag) ){
			err = RHP_STATUS_INVALID_MSG;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_INVALID_MESG1,"xx",rx_resp_ikemesg,vpn);
			goto error;
	  }

		if( my_ikesa_spi == NULL ){
	    RHP_BUG("");
	    err = -EINVAL;
	    goto error;
	  }

		ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
		if( ikesa == NULL ){
			err = -ENOENT;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_NO_IKESA1,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}

		if( ikesa->state != RHP_IKESA_STAT_I_IKE_SA_INIT_SENT ){
			err = 0;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_BAD_IKESA_STAT1,"xxLdGLd",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state);
			goto error;
		}

		if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ){

		  if( vpn->auth_ticket.conn_type == RHP_AUTH_TKT_CONN_TYPE_SPOKE2SPOKE ){

		  	err = rhp_ikev2_auth_tkt_spk2spk_invoke_get_tkt_task(vpn,ikesa,
		  						rx_resp_ikemesg,tx_req_ikemesg);

		  }else{

		  	err = _rhp_ikev2_ike_create_auth_req(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
		  }

		}else	if( exchange_type == RHP_PROTO_IKE_EXCHG_SESS_RESUME ){

			err = _rhp_ikev2_ike_auth_sess_resume_req(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
		}

	}else if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_AUTH ){

		if( RHP_PROTO_IKE_HDR_INITIATOR(rx_resp_ikemesg->rx_pkt->app.ikeh->flag) ){
			err = RHP_STATUS_INVALID_MSG;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_INVALID_MESG2,"xx",rx_resp_ikemesg,vpn);
			goto error;
	  }

	  if( !rx_resp_ikemesg->decrypted ){
	  	err = 0;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_NOT_DECRYPTED,"xx",rx_resp_ikemesg,vpn);
	  	goto error;
	  }

		if( my_ikesa_spi == NULL ){
	    RHP_BUG("");
	    err = -EINVAL;
	    goto error;
	  }

		ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
		if( ikesa == NULL ){
			err = -ENOENT;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_NO_IKESA2,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}


	  if( ikesa->state == RHP_IKESA_STAT_I_AUTH_SENT ){

			mesg_id = rx_resp_ikemesg->get_mesg_id(rx_resp_ikemesg);

			if( mesg_id == 1 ){

				if( ikesa->eap.state != RHP_IKESA_EAP_STAT_DEFAULT ){
					err = RHP_STATUS_BAD_SA_STATE;
					RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_BAD_EAP_STAT1,"xxLdGLd",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"EAP_STAT",ikesa->eap.state);
					goto error;
				}

				err = _rhp_ikev2_rx_ike_auth_rep(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);

			}else{ // EAP

				RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_EAP_STAT,"xxLdGLd",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state,"EAP_STAT",ikesa->eap.state);

				if( ikesa->eap.state == RHP_IKESA_EAP_STAT_I_PEND ){

					err = 0;
					goto error;

				}else{
					err = RHP_STATUS_BAD_SA_STATE;
					RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_BAD_EAP_STAT2,"xxLdGLd",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"EAP_STAT",ikesa->eap.state);
					goto error;
				}
			}

	  }else if( ikesa->state == RHP_IKESA_STAT_I_AUTH_EAP_SENT ){

			err = _rhp_ikev2_rx_ike_auth_rep_eap_comp_2(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);

	  }else{

	  	err = RHP_STATUS_BAD_SA_STATE;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_BAD_IKESA_STAT2,"xxLdGLd",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state);
	  	goto error;
	  }

	}else{

		err = 0;
		RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_NOT_INTERESTED,"xxx",rx_resp_ikemesg,vpn,tx_req_ikemesg);
	}

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_AUTH_REP_RTRN,"xxxE",rx_resp_ikemesg,vpn,tx_req_ikemesg,err);
  return err;
}

