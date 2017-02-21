/*

	Copyright (C) 2015-2016 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.

	You can redistribute and/or modify this software under the
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/capability.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_packet.h"
#include "rhp_netsock.h"
#include "rhp_timer.h"
#include "rhp_wthreads.h"
#include "rhp_config.h"
#include "rhp_ikev2_mesg.h"
#include "rhp_crypto.h"
#include "rhp_auth_tool.h"
#include "rhp_cert.h"
#include "rhp_http.h"
#include "rhp_ui.h"
#include "rhp_ikev2.h"


extern int rhp_auth_supported_prf_method(int prf_method);


static void _rhp_syspxy_ikev1_ipc_peer_psk_skeyid_req(rhp_ipcmsg* ipcmsg,rhp_ipcmsg** ipcmsg_r)
{
  int err = -EINVAL;
  rhp_ipcmsg_ikev1_psk_skeyid_req* psk_req;
  rhp_ipcmsg_ikev1_psk_skeyid_rep* psk_rep = NULL;
  rhp_vpn_auth_realm* auth_rlm = NULL;
  rhp_ikev2_id peer_id;
  char* id_val = NULL;
  rhp_auth_psk* peer_psk;
  rhp_crypto_prf* prf = NULL;
  unsigned int result = 0;
  u8* auth_key = NULL;
  int auth_key_len = 0;
  u8* peer_skeyid_octets = NULL;
  int peer_skeyid_octets_len = 0;
  u8* mesg_octets = NULL;
  int reply_len = 0;
  unsigned long auth_rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  int eap_role = RHP_EAP_DISABLED;
  int eap_method = RHP_PROTO_EAP_TYPE_NONE;
  u8* p;

  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_PSK_SKEYID_REQ,"xx",ipcmsg,ipcmsg_r);

  memset(&peer_id,0,sizeof(rhp_ikev2_id));

  if( ipcmsg->len < sizeof(rhp_ipcmsg_ikev1_psk_skeyid_req) ){
    RHP_BUG("");
    goto error;
  }

  psk_req = (rhp_ipcmsg_ikev1_psk_skeyid_req*)ipcmsg;

  if( psk_req->peer_id_len == 0 ||
      psk_req->mesg_octets_len == 0 ){
    RHP_BUG("");
    goto error;
  }

  if( psk_req->len != sizeof(rhp_ipcmsg_ikev1_psk_skeyid_req)
  		+ psk_req->peer_id_len + psk_req->mesg_octets_len ){
    RHP_BUG("");
    goto error;
  }

  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_PSK_SKEYID_REQ_PRF_METHOD,"xd",psk_req,psk_req->prf_method);

  if( rhp_auth_supported_prf_method(psk_req->prf_method) ){
    RHP_BUG("%d",psk_req->prf_method);
    goto error;
  }


  p = (u8*)(psk_req + 1);

  if( psk_req->peer_id_len ){

    peer_id.type = psk_req->peer_id_type;

    switch( peer_id.type ){

      case RHP_PROTO_IKE_ID_FQDN:
      case RHP_PROTO_IKE_ID_RFC822_ADDR:

        id_val = (char*)p;
        if( id_val[psk_req->peer_id_len - 1] != '\0' ){
          RHP_BUG("");
          goto failed;
        }
        peer_id.string = id_val;
        p += psk_req->peer_id_len;

        RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_PSK_SKEYID_REQ_PEER_ID,"ds",peer_id.type,peer_id.string);
        break;

      case RHP_PROTO_IKE_ID_IPV4_ADDR:

      	if( psk_req->peer_id_len != 4 ){
      		RHP_BUG("%d",psk_req->peer_id_len);
      		goto failed;
      	}

      	peer_id.addr.addr_family = AF_INET;
      	peer_id.addr.addr.v4 = *((u32*)p);
        p += psk_req->peer_id_len;

        RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_PSK_SKEYID_REQ_PEER_ID_IPV4,"d",peer_id.type);
      	break;

      case RHP_PROTO_IKE_ID_IPV6_ADDR:

      	if( psk_req->peer_id_len != 16 ){
      		RHP_BUG("%d",psk_req->peer_id_len);
      		goto failed;
      	}

      	peer_id.addr.addr_family = AF_INET6;
        memcpy(peer_id.addr.addr.v6,p,16);
        p += psk_req->peer_id_len;

        RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_PSK_SKEYID_REQ_PEER_ID_IPV6,"d",peer_id.type);
      	break;

      default:
        RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_PSK_SKEYID_REQ_PEER_ID_UNKNOWN,"d",peer_id.type);
      	RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_IKEV1_VERIFY_PSK_RX_INVALID_PEER_ID_TYPE,"d",peer_id.type);
        goto failed;
    }
  }

  if( psk_req->my_realm_id != RHP_VPN_REALM_ID_UNKNOWN ){

    auth_rlm = rhp_auth_realm_get(psk_req->my_realm_id);

  }else{

  	auth_rlm = rhp_auth_realm_get_by_role(NULL,
  			RHP_PEER_ID_TYPE_IKEV2,(void*)&peer_id,NULL,1,psk_req->peer_notified_realm_id);
  }

  if( auth_rlm == NULL ){

  	RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_PSK_SKEYID_REQ_RLM_NOT_FOUND,"u",psk_req->my_realm_id);
  	RHP_LOG_E(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_IKEV1_VERIFY_PSK_REALM_NOT_DEFINED,"I",&peer_id);

  	goto failed;
  }

  auth_rlm_id = auth_rlm->id;



  prf = rhp_crypto_prf_alloc(psk_req->prf_method);
  if( prf == NULL ){
    RHP_BUG("");
    goto failed;
  }


  RHP_LOCK(&(auth_rlm->lock));

	{
		rhp_auth_peer* auth_peer
			= auth_rlm->get_peer_by_id(auth_rlm,RHP_PEER_ID_TYPE_IKEV2,(void*)&peer_id);
		if( auth_peer == NULL ){
			RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_PSK_SKEYID_REQ_GET_PEER_BY_ID_ERR,"x",auth_rlm);
			RHP_LOG_DE(RHP_LOG_SRC_AUTH,auth_rlm->id,RHP_LOG_ID_PEER_PSK_NOT_DEFINED,"I",&peer_id);
			goto failed_l;
		}

		peer_psk = auth_peer->peer_psks;
		while( peer_psk ){

			if( peer_psk->key ){
				break;
			}

			peer_psk = peer_psk->next;
		}

		if( peer_psk == NULL ){
			RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_PSK_SKEYID_REQ_PEER_PSK_NULL,"x",auth_rlm);
			RHP_LOG_DE(RHP_LOG_SRC_AUTH,auth_rlm->id,RHP_LOG_ID_IKEV1_NO_PEER_PSK_FOUND,"I",&peer_id);
			goto failed_l;
		}

		auth_key = peer_psk->key;
		auth_key_len = strlen((char*)peer_psk->key);

		if( auth_key_len < 1 ){
			RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_PSK_SKEYID_REQ_PEER_PSK_NULL_2,"xd",auth_rlm,auth_key_len);
			goto failed_l;
		}
	}


  mesg_octets = p;
  p += psk_req->mesg_octets_len;

  if( auth_key == NULL ){
  	RHP_BUG("");
  	goto failed_l;
  }

  if( prf->set_key(prf,auth_key,auth_key_len) ){
    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_PSK_SKEYID_REQ_PRF_SET_KEY_ERR,"xx",auth_rlm,prf);
    goto failed_l;
  }

  peer_skeyid_octets_len = prf->get_output_len(prf);

  peer_skeyid_octets = (u8*)_rhp_malloc(peer_skeyid_octets_len);
  if( peer_skeyid_octets == NULL ){
    RHP_BUG("");
    goto failed_l;
  }

  if( prf->compute(prf,mesg_octets,psk_req->mesg_octets_len,peer_skeyid_octets,peer_skeyid_octets_len) ){
    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_PSK_SKEYID_REQ_PRF_COMPUTE_ERR,"xx",auth_rlm,prf);
    goto failed_l;
  }

  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_PSK_SKEYID_REQ_SIGNED_DATA,"dppp",psk_req->prf_method,auth_key_len,auth_key,psk_req->mesg_octets_len,mesg_octets,peer_skeyid_octets_len,peer_skeyid_octets);

  result = 1;

	eap_role = auth_rlm->xauth.role;
	eap_method = auth_rlm->xauth.method;

failed_l:
  RHP_UNLOCK(&(auth_rlm->lock));
failed:

  reply_len = sizeof(rhp_ipcmsg_ikev1_psk_skeyid_rep) + peer_skeyid_octets_len;

  psk_rep = (rhp_ipcmsg_ikev1_psk_skeyid_rep*)rhp_ipc_alloc_msg(RHP_IPC_IKEV1_PSK_SKEYID_REPLY,reply_len);
  if( psk_rep == NULL ){
    RHP_BUG("");
    goto error;
  }


  psk_rep->len = reply_len;
  psk_rep->txn_id = psk_req->txn_id;
  psk_rep->my_realm_id = auth_rlm_id;
  psk_rep->side = psk_req->side;
  memcpy(psk_rep->spi,psk_req->spi,RHP_PROTO_IKE_SPI_SIZE);
  psk_rep->result = result;
  psk_rep->exchange_type = psk_req->exchange_type;
  psk_rep->eap_role = eap_role;
  psk_rep->eap_method = eap_method;


  if( result ){

  	psk_rep->skeyid_len = peer_skeyid_octets_len;
    memcpy(((u8*)(psk_rep + 1)),peer_skeyid_octets,peer_skeyid_octets_len);

  }else{
    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_PSK_SKEYID_REQ_NG,"x",ipcmsg);
  }

  if( peer_skeyid_octets ){
    _rhp_free_zero(peer_skeyid_octets,peer_skeyid_octets_len);
  }

  if( prf ){
    rhp_crypto_prf_free(prf);
  }

  if( auth_rlm ){
    rhp_auth_realm_unhold(auth_rlm);
  }

  *ipcmsg_r = (rhp_ipcmsg*)psk_rep;

  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_PSK_SKEYID_REQ_RTRN,"xp",ipcmsg,psk_rep->len,psk_rep);
  return;

error:
  if( auth_rlm ){
    rhp_auth_realm_unhold(auth_rlm);
  }
  if( prf ){
    rhp_crypto_prf_free(prf);
  }
  if( peer_skeyid_octets ){
    _rhp_free_zero(peer_skeyid_octets,peer_skeyid_octets_len);
  }

  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_PSK_SKEYID_REQ_ERR,"xd",ipcmsg,err);
  return;
}

static void _rhp_syspxy_ikev1_ipc_psk_skeyid_req_handler(rhp_ipcmsg** ipcmsg)
{
	rhp_ipcmsg* ipcmsg_r = NULL;

	_rhp_syspxy_ikev1_ipc_peer_psk_skeyid_req(*ipcmsg,&ipcmsg_r);

	if( ipcmsg_r ){

	  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipcmsg_r,ipcmsg_r->len,0) < 0 ){
	    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_PSK_SKEYID_REQ_IPC_SEND_ERR,"xxdd",RHP_MY_PROCESS,ipcmsg_r,ipcmsg_r->len,0);
	  }
	  _rhp_free_zero(ipcmsg_r,ipcmsg_r->len);
	}

  _rhp_free_zero(*ipcmsg,(*ipcmsg)->len);
  *ipcmsg = NULL;

  return;
}

static int _rhp_syspxy_ikev1_rsasig_req_ck_cert_req(rhp_cert_store* cert_store,
		u8* certreq_dn_ders,int cert_dns_len,int cert_dns_num)
{
	int err = -EINVAL;
  int local_dns_len = 0, local_dns_num = 0;
  u8* local_dns = NULL;
  rhp_cert_dn** local_cert_dns = NULL;
  rhp_cert_dn** cert_dns = NULL;
  rhp_cert_data* dn_data;
  rhp_cert_dn* cert_dn;
  int i,j, rem = cert_dns_len;
  int found = 0;

  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_RSASIG_REQ_CK_CERT_REQ,"xxdd",cert_store,certreq_dn_ders,cert_dns_len,cert_dns_num);

  err = cert_store->get_ca_dn_ders(cert_store,&local_dns,&local_dns_len,&local_dns_num);
  if( err ){
    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_RSASIG_REQ_CK_CERT_REQ_GET_CA_DN_DERS_ERR,"d",err);
    goto error;
  }

  local_cert_dns = (rhp_cert_dn**)_rhp_malloc(sizeof(rhp_cert_dn*)*(local_dns_num + 1));
  if( local_cert_dns == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
    goto error;
  }
  memset(local_cert_dns,0,sizeof(rhp_cert_dn*)*(local_dns_num + 1));

  cert_dns = (rhp_cert_dn**)_rhp_malloc(sizeof(rhp_cert_dn*)*(cert_dns_num + 1));
  if( cert_dns == NULL ){
  	RHP_BUG("");
  	_rhp_free(local_cert_dns);
  	err = -ENOMEM;
    goto error;
  }
  memset(cert_dns,0,sizeof(rhp_cert_dn*)*(cert_dns_num + 1));


  dn_data = (rhp_cert_data*)local_dns;
  for( i = 0; i < local_dns_num; i++){

  	cert_dn = rhp_cert_dn_alloc_by_DER((u8*)(dn_data + 1),dn_data->len);

  	if( cert_dn == NULL ){
  		RHP_BUG("");
  		err = -EINVAL;
  		goto error;
  	}

  	local_cert_dns[i] = cert_dn;

  	dn_data = (rhp_cert_data*)(((u8*)dn_data) + (int)sizeof(rhp_cert_data) + dn_data->len);
  }

  dn_data = (rhp_cert_data*)certreq_dn_ders;
  for( i = 0; i < cert_dns_num; i++){

  	if( rem < 0 ){
  		RHP_BUG("");
  		err = -EINVAL;
  		goto error;
  	}

  	cert_dn = rhp_cert_dn_alloc_by_DER((u8*)(dn_data + 1),dn_data->len);

  	if( cert_dn == NULL ){
      RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_RSASIG_REQ_CK_CERT_REQ_INVALID_CERT_DN,"dp",err,dn_data->len,(u8*)(dn_data + 1));
  		err = -EINVAL;
  		goto error;
  	}

  	cert_dns[i] = cert_dn;

  	dn_data = (rhp_cert_data*)(((u8*)dn_data) + (int)sizeof(rhp_cert_data) + dn_data->len);
  	rem -= (int)sizeof(rhp_cert_data) + dn_data->len;
  }


  for( i = 0; i < local_dns_num; i++ ){

  	for( j = 0; j < cert_dns_num; j++){

  		if( !local_cert_dns[i]->compare(local_cert_dns[i],cert_dns[j]) ){
  			found++;
  			break;
  		}
  	}
  }

  if( !found ||
  		( rhp_gcfg_strictly_cmp_certreq_ca_dns && found != cert_dns_num ) ){
  	err = -EINVAL;
		goto error;
  }

  err = 0;

error:

	if( local_dns ){
		_rhp_free(local_dns);
	}

	if( local_cert_dns ){

		i = 0;
		cert_dn = local_cert_dns[0];
		while( cert_dn ){
			rhp_cert_dn_free(cert_dn);
			cert_dn = local_cert_dns[i + 1];
		}

		_rhp_free(local_cert_dns);
	}

	if( cert_dns ){

		i = 0;
		cert_dn = cert_dns[0];
		while( cert_dn ){
			rhp_cert_dn_free(cert_dn);
			cert_dn = cert_dns[i + 1];
		}

		_rhp_free(cert_dns);
	}

	RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_RSASIG_REQ_CK_CERT_REQ_RTRN,"xxdE",cert_store,certreq_dn_ders,found,err);
	return err;
}

extern int rhp_auth_ipc_handle_sign_rsasig_req_cb_enum_certs_cb(rhp_cert_store* cert_store,
		int is_user_cert,u8* der,int der_len,rhp_cert_dn* cert_dn,void* ctx);

static  void _rhp_syspxy_ikev1_ipc_rsasig_sign_req_cb(rhp_cert_store* cert_store,int err,rhp_cert_sign_ctx* cb_cert_ctx)
{
  rhp_auth_ipc_sign_rsasig_cb_ctx* cb_ctx = (rhp_auth_ipc_sign_rsasig_cb_ctx*)cb_cert_ctx;
  rhp_ipcmsg_ikev1_rsasig_sign_req* sign_rsasig_req = NULL;
  rhp_vpn_auth_realm* auth_rlm = NULL;
  rhp_ipcmsg_ikev1_rsasig_sign_rep* sign_rsasig_rep = NULL;
  rhp_auth_ipc_sign_rsasig_enum_certs_ctx enum_certs_cb_ctx;
  u8* der_certs = NULL;
  int deny_expired_cert = 1;
  int reply_len = 0;
  int eap_role = RHP_EAP_DISABLED;
  int eap_method = RHP_PROTO_EAP_TYPE_NONE;
  int result = 0;

  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_SIGN_REQ_CB,"xdx",cert_store,err,cb_cert_ctx);

  sign_rsasig_req = (rhp_ipcmsg_ikev1_rsasig_sign_req*)cb_ctx->sign_rsasig_req;

  auth_rlm = cb_ctx->auth_rlm; // (**VV**)

  if( !_rhp_atomic_read(&(cert_store->is_active)) ){
    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_SIGN_REQ_CB_CERTSTORE_NOT_ACTIVE,"x",cert_store);
    goto error;
  }

  if( err ){
    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_SIGN_REQ_CB_GEN_MY_SIG_ERR,"xxE",cert_store,auth_rlm,err);
		RHP_LOG_E(RHP_LOG_SRC_AUTH,auth_rlm->id,RHP_LOG_ID_GENERATE_MY_SIGNATURE_ERR,"E",err);
    goto failed;
  }


  RHP_LOCK(&(auth_rlm->lock));
  {
		if( !_rhp_atomic_read(&(auth_rlm->is_active)) ){
			RHP_UNLOCK(&(auth_rlm->lock));
			RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_SIGN_REQ_CB_REALM_NOT_ACTIVE,"x",auth_rlm);
			goto error;
		}

		deny_expired_cert = !auth_rlm->accept_expired_cert;

		eap_role = auth_rlm->xauth.role;
		eap_method = auth_rlm->xauth.method;
  }
  RHP_UNLOCK(&(auth_rlm->lock));



  {
  	der_certs = (u8*)_rhp_malloc(sign_rsasig_req->certs_bin_max_size);
  	if( der_certs == NULL ){
  		RHP_BUG("");
  		err = -ENOMEM;
  		goto failed;
  	}

    enum_certs_cb_ctx.certs_bin_max_len = sign_rsasig_req->certs_bin_max_size;
    enum_certs_cb_ctx.certs_bin = NULL;
    enum_certs_cb_ctx.certs_bin_len = 0;
    enum_certs_cb_ctx.my_cert = 0;
    enum_certs_cb_ctx.cert_chain_num = 0;
    enum_certs_cb_ctx.certs_bin = der_certs;
    enum_certs_cb_ctx.certs_bin_curp = der_certs;
    enum_certs_cb_ctx.auth_rlm = cb_ctx->auth_rlm;
    enum_certs_cb_ctx.http_cert_lookup_supported = 0;

		err = cert_store->enum_DER_certs(cert_store,deny_expired_cert,1,
				rhp_auth_ipc_handle_sign_rsasig_req_cb_enum_certs_cb,&enum_certs_cb_ctx);

		if( err == RHP_STATUS_ENUM_OK ){
			err = 0;
		}else if( err ){
			RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_SIGN_REQ_CB_FAILED,"dd",err,2);
			RHP_LOG_E(RHP_LOG_SRC_AUTH,auth_rlm->id,RHP_LOG_ID_ENUM_MY_CERT_ERR,"sE",(deny_expired_cert ? "denied" : "ignored"),err);
			goto failed;
		}

		if( enum_certs_cb_ctx.my_cert == 0 ){
			RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_SIGN_REQ_CB_FAILED,"dd",err,3);
			RHP_LOG_E(RHP_LOG_SRC_AUTH,auth_rlm->id,RHP_LOG_ID_GET_NO_MY_CERT_ERR,"");
			goto failed;
		}
  }


  reply_len = sizeof(rhp_ipcmsg_ikev1_rsasig_sign_rep);
  reply_len += cb_ctx->cb_cert_ctx.signed_octets_len;
  reply_len += enum_certs_cb_ctx.certs_bin_len;

  sign_rsasig_rep = (rhp_ipcmsg_ikev1_rsasig_sign_rep*)rhp_ipc_alloc_msg(RHP_IPC_IKEV1_SIGN_RSASIG_REPLY,reply_len);
  if( sign_rsasig_rep == NULL ){
    RHP_BUG("");
    goto failed;
  }

  result = 1;
  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_SIGN_REQ_CB_OK,"x",cb_cert_ctx);


  sign_rsasig_rep->len = reply_len;
  sign_rsasig_rep->txn_id = sign_rsasig_req->txn_id;
  sign_rsasig_rep->my_realm_id = auth_rlm->id;
  sign_rsasig_rep->result = result;
  sign_rsasig_rep->signed_octets_len = cb_ctx->cb_cert_ctx.signed_octets_len;
  sign_rsasig_rep->cert_chain_num = enum_certs_cb_ctx.cert_chain_num;
  sign_rsasig_rep->cert_chain_len = enum_certs_cb_ctx.certs_bin_len;
  sign_rsasig_rep->side = sign_rsasig_req->side;
  sign_rsasig_rep->exchange_type = sign_rsasig_req->exchange_type;
  sign_rsasig_rep->eap_role = eap_role;
  sign_rsasig_rep->eap_method = eap_method;

  memcpy(sign_rsasig_rep->spi,sign_rsasig_req->spi,RHP_PROTO_IKE_SPI_SIZE);

  {
  	u8* p  = (u8*)(sign_rsasig_rep + 1);

  	memcpy(p,cb_ctx->cb_cert_ctx.signed_octets,cb_ctx->cb_cert_ctx.signed_octets_len);
		p = p + cb_ctx->cb_cert_ctx.signed_octets_len;

  	if( der_certs ){
  		memcpy(p,der_certs,enum_certs_cb_ctx.certs_bin_len);
  		p = p + enum_certs_cb_ctx.certs_bin_len;
  	}
  }


tx_error:
  if( cb_ctx->verify_sign_req == NULL ){

    if( rhp_ipc_send(RHP_MY_PROCESS,(void*)sign_rsasig_rep,sign_rsasig_rep->len,0) < 0 ){
      RHP_BUG("");
    }

    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_SIGN_REQ_CB_TX_SIGN_RSASIG_REP,"xp",cb_cert_ctx,sign_rsasig_rep->len,sign_rsasig_rep);

  }else{

    int verify_sign_rep_len = 0;
    rhp_ipcmsg_verify_and_sign_rep* verify_sign_rep = NULL;
    rhp_ipcmsg_ikev1_rsasig_sign_rep* in_sign_rep = sign_rsasig_rep;
    u8* p = NULL;

    verify_sign_rep_len = sizeof(rhp_ipcmsg_verify_and_sign_rep);

    if( cb_ctx->in_verify_rep ){
      verify_sign_rep_len += cb_ctx->in_verify_rep->len;
    }

    if( in_sign_rep ){
      verify_sign_rep_len += in_sign_rep->len;
    }

    verify_sign_rep = (rhp_ipcmsg_verify_and_sign_rep*)rhp_ipc_alloc_msg(RHP_IPC_IKEV1_VERIFY_AND_SIGN_RSASIG_REPLY,verify_sign_rep_len);
    if( verify_sign_rep == NULL ){
      RHP_BUG("");
      goto error;
    }

    verify_sign_rep->len = verify_sign_rep_len;

    p = (u8*)(verify_sign_rep + 1);

    if( cb_ctx->in_verify_rep ){
      memcpy(p,cb_ctx->in_verify_rep,cb_ctx->in_verify_rep->len);
      p += cb_ctx->in_verify_rep->len;
      verify_sign_rep->v1_exchange_type = cb_ctx->exchange_type;
    }

    if( in_sign_rep ){
      memcpy(p,in_sign_rep,in_sign_rep->len);
      p += in_sign_rep->len;
      verify_sign_rep->v1_exchange_type = cb_ctx->exchange_type;
    }

    if( rhp_ipc_send(RHP_MY_PROCESS,(void*)verify_sign_rep,verify_sign_rep->len,0) < 0 ){
      RHP_BUG("");
    }

    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_SIGN_REQ_CB_TX_VERIFY_SIGN_REP,"xp",cb_cert_ctx,verify_sign_rep->len,verify_sign_rep);

    _rhp_free_zero(verify_sign_rep,verify_sign_rep->len);
  }

error:
  if( sign_rsasig_rep ){
    _rhp_free_zero(sign_rsasig_rep,sign_rsasig_rep->len);
  }

  rhp_cert_store_unhold(cert_store);
  rhp_auth_realm_unhold(auth_rlm); // (**VV**)

  if( cb_ctx->cb_cert_ctx.signed_octets ){
    _rhp_free(cb_ctx->cb_cert_ctx.signed_octets);
  }

  if( der_certs ){
    _rhp_free(der_certs);
  }

  if( cb_ctx->verify_sign_req == NULL ){

  	if( cb_ctx->sign_rsasig_req ){
      _rhp_free_zero(cb_ctx->sign_rsasig_req,cb_ctx->sign_rsasig_req->len);
    }

  }else{

  	if( cb_ctx->verify_sign_req ){
      _rhp_free_zero(cb_ctx->verify_sign_req,cb_ctx->verify_sign_req->len);
    }

    if( cb_ctx->in_verify_rep ){
      _rhp_free_zero(cb_ctx->in_verify_rep,cb_ctx->in_verify_rep->len);
    }
  }


  if( cb_ctx->mesg_octets_exp ){
    _rhp_free_zero(cb_ctx->mesg_octets_exp,cb_ctx->mesg_octets_exp_len);
  }

  _rhp_free_zero(cb_ctx,sizeof(rhp_auth_ipc_sign_rsasig_cb_ctx));

  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_SIGN_REQ_CB_RTRN,"x",cb_cert_ctx);
  return;


failed:
	if( sign_rsasig_rep ){
		_rhp_free_zero(sign_rsasig_rep,sign_rsasig_rep->len);
		sign_rsasig_rep = NULL;
	}

  sign_rsasig_rep = (rhp_ipcmsg_ikev1_rsasig_sign_rep*)rhp_ipc_alloc_msg(
  										RHP_IPC_IKEV1_SIGN_RSASIG_REPLY,sizeof(rhp_ipcmsg_ikev1_rsasig_sign_rep));
  if( sign_rsasig_rep == NULL ){
    RHP_BUG("");
    goto error;
  }

  sign_rsasig_rep->len = sizeof(rhp_ipcmsg_ikev1_rsasig_sign_rep);
  sign_rsasig_rep->txn_id = sign_rsasig_req->txn_id;
  sign_rsasig_rep->my_realm_id = auth_rlm->id;
  sign_rsasig_rep->result = 0;
  sign_rsasig_rep->signed_octets_len = 0;
  sign_rsasig_rep->cert_chain_num = 0;
  sign_rsasig_rep->cert_chain_len = 0;
  sign_rsasig_rep->side = sign_rsasig_req->side;
  memcpy(sign_rsasig_rep->spi,sign_rsasig_req->spi,RHP_PROTO_IKE_SPI_SIZE);
  sign_rsasig_rep->exchange_type = sign_rsasig_req->exchange_type;

  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_SIGN_REQ_CB_FAILED,"x",cb_cert_ctx);
	goto tx_error;
}

static int _rhp_syspxy_ikev1_ipc_handle_rsasig_sign_req(rhp_ipcmsg* ipcmsg,
		rhp_ipcmsg** ipcmsg_r,rhp_ipcmsg* verify_sign_req,
		rhp_ipcmsg_ikev1_rsasig_verify_rep* in_verify_rep)
{
  int err = -EINVAL;
  rhp_ipcmsg_ikev1_rsasig_sign_req* sign_rsasig_req;
  rhp_vpn_auth_realm* auth_rlm = NULL;
  rhp_cert_store* cert_store = NULL;
  u8 *mesg_octets = NULL, *mesg_octets_ext = NULL;
  int mesg_octets_len = 0, mesg_octets_ext_len = 0;
  rhp_ipcmsg_ikev1_rsasig_sign_rep* sign_rsasig_rep;
  int reply_len = 0;
  rhp_auth_ipc_sign_rsasig_cb_ctx* cb_ctx;
  u8* certreq_dn_ders = NULL, *p;
  unsigned long auth_rlm_id;

  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSASIG_SIGN_REQ,"xxxx",ipcmsg,ipcmsg_r,verify_sign_req,in_verify_rep);

  if( ipcmsg->len < sizeof(rhp_ipcmsg_ikev1_rsasig_sign_req) ){
    RHP_BUG("");
    goto error;
  }

  sign_rsasig_req = (rhp_ipcmsg_ikev1_rsasig_sign_req*)ipcmsg;

  if( sign_rsasig_req->mesg_octets_len == 0 		||
  		sign_rsasig_req->certs_bin_max_size == 0  ||
      sign_rsasig_req->len != sizeof(rhp_ipcmsg_ikev1_rsasig_sign_req) + sign_rsasig_req->mesg_octets_len
      + sign_rsasig_req->skeyid_len + sign_rsasig_req->ca_dn_ders_len ){
    RHP_BUG("%d, %d, %d, %d, %d, %d, %d, %d",sign_rsasig_req->mesg_octets_len,sign_rsasig_req->certs_bin_max_size,sign_rsasig_req->len,sizeof(rhp_ipcmsg_ikev1_rsasig_sign_req),sign_rsasig_req->mesg_octets_len,sign_rsasig_req->skeyid_len,sign_rsasig_req->ca_dn_ders_len);
    goto error;
  }

  if( rhp_auth_supported_prf_method(sign_rsasig_req->prf_method) ){
    RHP_BUG("%d",sign_rsasig_req->prf_method);
    goto error;
  }


  auth_rlm_id = sign_rsasig_req->my_realm_id;
  if( in_verify_rep &&
  		(auth_rlm_id == 0 || auth_rlm_id == RHP_VPN_REALM_ID_UNKNOWN) ){

  	auth_rlm_id = in_verify_rep->my_realm_id;
  }


  p = (u8*)(sign_rsasig_req + 1);

  mesg_octets = p;
  p += sign_rsasig_req->mesg_octets_len;

  mesg_octets_len = sign_rsasig_req->mesg_octets_len;


  auth_rlm = rhp_auth_realm_get(auth_rlm_id);
  if( auth_rlm == NULL ){
    RHP_BUG("%lu",auth_rlm_id);
    goto failed;
  }

  RHP_LOCK(&(auth_rlm->lock));
  {
    if( auth_rlm->my_auth == NULL ){
    	RHP_BUG("");
			RHP_UNLOCK(&(auth_rlm->lock));
      goto failed;
    }

		cert_store = auth_rlm->my_auth->cert_store;

		if( cert_store ){

			rhp_cert_store_hold(cert_store);

		}else{

			RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSASIG_SIGN_REQ_NO_CERT_STORE,"xuxx",ipcmsg,auth_rlm_id,verify_sign_req,in_verify_rep);

			RHP_LOG_E(RHP_LOG_SRC_AUTH,auth_rlm->id,RHP_LOG_ID_NO_CERT_INFO_LOADED,"");

			RHP_UNLOCK(&(auth_rlm->lock));
			goto failed;
		}


		if( sign_rsasig_req->skeyid_len ){ // Append my id(IDii_b or IDir_b) and gen hash_i/r

			/*
				For RSA-Sig: SKEYID = prf(Ni_b | Nr_b, g^xy)

				HASH_I = prf(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b )
				HASH_R = prf(SKEYID, g^xr | g^xi | CKY-R | CKY-I | SAi_b | IDir_b )


				mesg_octets: g^xi | g^xr | CKY-I | CKY-R | SAi_b for HASH_I.
				             g^xr | g^xi | CKY-R | CKY-I | SAi_b for HASH_R.

				skeyid: SKEYID
			*/

	    u8 *my_id = NULL, *skeyid, *hash_mat;
 	    int my_id_type = 0, skeyid_len = sign_rsasig_req->skeyid_len, hash_mat_len;
	    int my_id_len = 0;
	    rhp_proto_ikev1_id_payload* dmy_hdr;
	    rhp_crypto_prf* prf = NULL;

	    skeyid = p;
	    p += skeyid_len;

	    if( mesg_octets_len < (int)sizeof(rhp_proto_ike_payload) ){
	    	RHP_BUG("");
				RHP_UNLOCK(&(auth_rlm->lock));
				goto failed;
	    }

	    if( !auth_rlm->my_auth->my_id.type ){

	    	RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSASIG_SIGN_REQ_NO_MY_ID,"xuxx",ipcmsg,auth_rlm_id,verify_sign_req,in_verify_rep);

				RHP_LOG_E(RHP_LOG_SRC_AUTH,auth_rlm->id,RHP_LOG_ID_MY_ID_NOT_RESOLVED,"");

				RHP_UNLOCK(&(auth_rlm->lock));
				goto failed;
	    }

	    {
				if( rhp_ikev2_id_value(&(auth_rlm->my_auth->my_id),&my_id,&my_id_len,&my_id_type) ){
					RHP_BUG("");
					RHP_UNLOCK(&(auth_rlm->lock));
					goto failed;
				}

				my_id_type = rhp_ikev1_id_type(my_id_type);
				if( my_id_type < 0 ){
					RHP_BUG("%d",my_id_type);
					_rhp_free(my_id);
					RHP_UNLOCK(&(auth_rlm->lock));
					goto failed;
				}
	    }

	    {
				hash_mat_len
				= mesg_octets_len + (int)(sizeof(rhp_proto_ikev1_id_payload) - sizeof(rhp_proto_ike_payload)) + my_id_len;

				hash_mat = (u8*)_rhp_malloc(hash_mat_len);
				if( hash_mat == NULL ){
					RHP_BUG("%d",hash_mat_len);
					_rhp_free(my_id);
					RHP_UNLOCK(&(auth_rlm->lock));
					goto failed;
				}

				dmy_hdr = (rhp_proto_ikev1_id_payload*)(hash_mat + mesg_octets_len - (int)sizeof(rhp_proto_ike_payload));
				dmy_hdr->id_type = my_id_type;
				dmy_hdr->protocol_id = 0;
				dmy_hdr->port = 0;
				memcpy((dmy_hdr + 1),my_id,my_id_len);

				memcpy(hash_mat,mesg_octets,mesg_octets_len);
	    }

	  	{
				prf = rhp_crypto_prf_alloc(sign_rsasig_req->prf_method);
				if( prf == NULL ){
					RHP_BUG("%d",sign_rsasig_req->prf_method);
					RHP_UNLOCK(&(auth_rlm->lock));
					goto failed;
				}

				mesg_octets_ext_len = prf->get_output_len(prf);

				mesg_octets_ext = (u8*)_rhp_malloc(mesg_octets_ext_len);
				if( mesg_octets_ext == NULL ){
					RHP_BUG("");
					_rhp_free(my_id);
					_rhp_free(hash_mat);
					rhp_crypto_prf_free(prf);
					RHP_UNLOCK(&(auth_rlm->lock));
					goto failed;
				}

				if( prf->set_key(prf,skeyid,skeyid_len) ){
					RHP_BUG("");
					_rhp_free(my_id);
					_rhp_free(hash_mat);
					rhp_crypto_prf_free(prf);
					RHP_UNLOCK(&(auth_rlm->lock));
					goto failed;
				}

				if( prf->compute(prf,hash_mat,hash_mat_len,mesg_octets_ext,mesg_octets_ext_len) ){
					RHP_BUG("");
					_rhp_free(my_id);
					_rhp_free(hash_mat);
					rhp_crypto_prf_free(prf);
					RHP_UNLOCK(&(auth_rlm->lock));
					goto failed;
				}
	  	}

	  	mesg_octets = mesg_octets_ext;
	  	mesg_octets_len = mesg_octets_ext_len;

	  	_rhp_free(my_id);
	  	_rhp_free(hash_mat);
	    rhp_crypto_prf_free(prf);
	  }
  }
  RHP_UNLOCK(&(auth_rlm->lock));


  certreq_dn_ders = p;
  p += sign_rsasig_req->ca_dn_ders_len;

  if( rhp_gcfg_check_certreq_ca_dns && sign_rsasig_req->ca_dn_ders_len ){

  	err = _rhp_syspxy_ikev1_rsasig_req_ck_cert_req(cert_store,
  					certreq_dn_ders,sign_rsasig_req->ca_dn_ders_len,sign_rsasig_req->ca_dn_ders_num);
  	if( err ){

      RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSASIG_SIGN_REQ_MATCHED_CA_KEYS_NOT_FOUND,"Ep",err,sign_rsasig_req->ca_dn_ders_len,certreq_dn_ders);
  		RHP_LOG_DE(RHP_LOG_SRC_AUTH,auth_rlm_id,RHP_LOG_ID_NO_REQUESTED_CA_FOUND,"I",&(auth_rlm->my_auth->my_id));

  		goto failed;
  	}
  }


  cb_ctx = (rhp_auth_ipc_sign_rsasig_cb_ctx*)_rhp_malloc(sizeof(rhp_auth_ipc_sign_rsasig_cb_ctx));
  if( cb_ctx == NULL ){
    RHP_BUG("");
    goto failed;
  }
  memset(cb_ctx,0,sizeof(rhp_auth_ipc_sign_rsasig_cb_ctx));

  cb_ctx->cb_cert_ctx.tag[0] = '#';
  cb_ctx->cb_cert_ctx.tag[1] = 'C';
  cb_ctx->cb_cert_ctx.tag[2] = 'S';
  cb_ctx->cb_cert_ctx.tag[3] = 'C';

  cb_ctx->cb_cert_ctx.sign_op_type = RHP_CERT_SIGN_OP_SIGN_IKEV1;
  cb_ctx->cb_cert_ctx.mesg_octets = mesg_octets;
  cb_ctx->cb_cert_ctx.mesg_octets_len = mesg_octets_len;

  cb_ctx->mesg_octets_exp = mesg_octets_ext;
  cb_ctx->mesg_octets_exp_len = mesg_octets_ext_len;

  if( verify_sign_req ){
  	cb_ctx->exchange_type
  		= ((rhp_ipcmsg_verify_and_sign_req*)verify_sign_req)->v1_exchange_type;
  }else{
  	cb_ctx->exchange_type = sign_rsasig_req->exchange_type;
  }

  cb_ctx->cb_cert_ctx.callback = _rhp_syspxy_ikev1_ipc_rsasig_sign_req_cb;

  cb_ctx->auth_rlm = auth_rlm;
  rhp_auth_realm_hold(auth_rlm);

  cb_ctx->sign_rsasig_req = (rhp_ipcmsg*)sign_rsasig_req;

  cb_ctx->verify_sign_req = verify_sign_req;
  cb_ctx->in_verify_rep = (rhp_ipcmsg*)in_verify_rep;

  err = cert_store->sign(cert_store,(rhp_cert_sign_ctx*)cb_ctx);
  if( err ){
    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSASIG_SIGN_REQ_SIGN_ERR,"d",err);
    goto failed;
  }

  rhp_auth_realm_unhold(auth_rlm);

  *ipcmsg_r = NULL;

  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSASIG_SIGN_REQ_PENDING,"x",ipcmsg);
  return 0;

failed:

  reply_len = sizeof(rhp_ipcmsg_ikev1_rsasig_sign_rep);

  sign_rsasig_rep = (rhp_ipcmsg_ikev1_rsasig_sign_rep*)rhp_ipc_alloc_msg(RHP_IPC_IKEV1_SIGN_RSASIG_REPLY,reply_len);
  if( sign_rsasig_rep == NULL ){
    RHP_BUG("");
    goto error;
  }

  sign_rsasig_rep->len = reply_len;
  sign_rsasig_rep->txn_id = sign_rsasig_req->txn_id;
  sign_rsasig_rep->my_realm_id = auth_rlm_id;
  sign_rsasig_rep->result = 0;

  sign_rsasig_rep->signed_octets_len = 0;
  sign_rsasig_rep->cert_chain_num = 0;
  sign_rsasig_rep->side = sign_rsasig_req->side;
  memcpy(sign_rsasig_rep->spi,sign_rsasig_req->spi,RHP_PROTO_IKE_SPI_SIZE);
  sign_rsasig_rep->exchange_type = sign_rsasig_req->exchange_type;

  if( cert_store ){
    rhp_cert_store_unhold(cert_store);
  }

  if( auth_rlm ){
    rhp_auth_realm_unhold(auth_rlm);
  }

  *ipcmsg_r = (rhp_ipcmsg*)sign_rsasig_rep;

  if( mesg_octets_ext ){
  	_rhp_free(mesg_octets_ext);
  }

  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSASIG_SIGN_REQ_FAILED,"xp",ipcmsg,sign_rsasig_rep->len,sign_rsasig_rep);
  return 0;

error:
  if( cert_store ){
    rhp_cert_store_unhold(cert_store);
  }
  if( auth_rlm ){
    rhp_auth_realm_unhold(auth_rlm);
  }
  if( mesg_octets_ext ){
  	_rhp_free(mesg_octets_ext);
  }

  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSASIG_SIGN_REQ_ERR,"x",ipcmsg);
  return err;
}

static void _rhp_syspxy_ikev1_ipc_rsasig_sign_req_handler(rhp_ipcmsg** ipcmsg)
{
	int err;
	rhp_ipcmsg* ipcmsg_r = NULL;

	err = _rhp_syspxy_ikev1_ipc_handle_rsasig_sign_req(*ipcmsg,&ipcmsg_r,NULL,NULL);

	if( ipcmsg_r ){

	  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipcmsg_r,ipcmsg_r->len,0) < 0 ){
	    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_SIGN_REQ_HANDLER_ERR,"xxdd",RHP_MY_PROCESS,ipcmsg_r,ipcmsg_r->len,0);
	  }
	  _rhp_free_zero(ipcmsg_r,ipcmsg_r->len);
	}

	if( ipcmsg_r || err ){
		_rhp_free_zero(*ipcmsg,(*ipcmsg)->len);
	}
	*ipcmsg = NULL;

  return;
}

static int _rhp_syspxy_ikev1_ipc_rsasig_verify_and_sign_req_cb(rhp_ipcmsg* verify_sign_req,
		rhp_ipcmsg* in_sign_req,rhp_ipcmsg_ikev1_rsasig_verify_rep* in_verify_rep)
{
  int err = -EINVAL;
  rhp_ipcmsg* in_sign_rep = NULL;
  int pending = 0;

  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_VERIFY_AND_SIGN_REQ_CB,"xxxd",verify_sign_req,in_sign_req,in_verify_rep,in_verify_rep->result);

  if( in_verify_rep->result ){

    err = _rhp_syspxy_ikev1_ipc_handle_rsasig_sign_req(in_sign_req,&in_sign_rep,verify_sign_req,in_verify_rep);
    if( err ){
      goto error;
    }

    if( in_sign_rep == NULL ){
      pending = 1;
    }
  }

  if( !pending ){

    int reply_len;
    rhp_ipcmsg_verify_and_sign_rep* verify_sign_rep;
    u8* p;

    reply_len = sizeof(rhp_ipcmsg_verify_and_sign_rep);

    if( in_verify_rep ){
      reply_len += in_verify_rep->len;
    }

    if( in_sign_rep ){
      reply_len += in_sign_rep->len;
    }

    verify_sign_rep = (rhp_ipcmsg_verify_and_sign_rep*)rhp_ipc_alloc_msg(
    										RHP_IPC_IKEV1_VERIFY_AND_SIGN_RSASIG_REPLY,reply_len);
    if( verify_sign_rep == NULL ){
      RHP_BUG("");
      goto error;
    }

    verify_sign_rep->len = reply_len;

    p = (u8*)(verify_sign_rep + 1);

    if( in_verify_rep ){
      memcpy(p,in_verify_rep,in_verify_rep->len);
      p += in_verify_rep->len;
      verify_sign_rep->v1_exchange_type = in_verify_rep->exchange_type;
    }

    if( in_sign_rep ){
      memcpy(p,in_sign_rep,in_sign_rep->len);
      p += in_sign_rep->len;
      verify_sign_rep->v1_exchange_type
      = ((rhp_ipcmsg_verify_and_sign_req*)verify_sign_req)->v1_exchange_type;
    }

    if( in_verify_rep ){
      _rhp_free_zero(in_verify_rep,in_verify_rep->len);
    }

    if( in_sign_rep ){
      _rhp_free_zero(in_sign_rep,in_sign_rep->len);
    }

    if( rhp_ipc_send(RHP_MY_PROCESS,(void*)verify_sign_rep,verify_sign_rep->len,0) < 0 ){
      RHP_BUG("");
    }

    _rhp_free_zero(verify_sign_rep,verify_sign_rep->len);
    _rhp_free_zero(verify_sign_req,verify_sign_req->len);

    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_VERIFY_AND_SIGN_REQ_CB_RTRN,"xxx",verify_sign_req,in_sign_req,in_verify_rep);

  }else{
    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_VERIFY_AND_SIGN_REQ_CB_PENDING,"xxx",verify_sign_req,in_sign_req,in_verify_rep);
  }

  return 0;

error:
  if( in_sign_rep ){
    _rhp_free_zero(in_sign_rep,in_sign_rep->len);
  }
  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_VERIFY_AND_SIGN_REQ_CB_ERR,"xxx",verify_sign_req,in_sign_req,in_verify_rep);
  return err;
}

static void _rhp_syspxy_ikev1_ipc_rsasig_verify_req_cb(rhp_cert_store* cert_store,int auth_err,
    rhp_ikev2_id* subjectname,rhp_ikev2_id* subjectaltname,rhp_cert_sign_verify_ctx* cb_cert_ctx)
{
  rhp_auth_ipc_verify_rsasig_cb_ctx* cb_ctx = (rhp_auth_ipc_verify_rsasig_cb_ctx*)cb_cert_ctx;
  rhp_ipcmsg_ikev1_rsasig_verify_req* verify_rsasig_req = NULL;
  rhp_vpn_auth_realm* auth_rlm = NULL;
  rhp_ipcmsg_ikev1_rsasig_verify_rep* verify_rsasig_rep = NULL;
  int verify_rsasig_rep_len;
  int result = 0;
  unsigned long auth_rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  int go_next = (cb_ctx->verify_sign_req ? 1 : 0);
  int pending = 0;
  u8* subject_val = NULL;
  int subject_val_len = 0;
  int subject_val_id_type;
  int eap_role = RHP_EAP_DISABLED;
  int eap_method = RHP_PROTO_EAP_TYPE_NONE;

  auth_rlm = cb_ctx->auth_rlm;

  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_VERIFY_REQ_CB,"xdxd",cert_store,auth_err,cb_cert_ctx,go_next);
  rhp_ikev2_id_dump("_rhp_syspxy_ikev1_ipc_rsasig_verify_req_cb:subjectname",subjectname);
  rhp_ikev2_id_dump("_rhp_syspxy_ikev1_ipc_rsasig_verify_req_cb:subjectaltname",subjectaltname);


  if( !_rhp_atomic_read(&(cert_store->is_active)) ){
    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_VERIFY_REQ_CB_CERTSTORE_NOT_ACTIVE,"x",cert_store);
    goto error;
  }


  if( subjectname && (rhp_gcfg_ikev2_alt_id_use_dn || subjectaltname == NULL) ){

  	if( rhp_ikev2_id_value(subjectname,&subject_val,&subject_val_len,&subject_val_id_type) ){
  		RHP_BUG("");
  		goto error;
  	}

  }else if( subjectaltname ){

  	if( rhp_ikev2_id_value(subjectaltname,&subject_val,&subject_val_len,&subject_val_id_type) ){
  		RHP_BUG("");
  		goto error;
  	}
  }


  RHP_LOCK(&(auth_rlm->lock));

  if( !_rhp_atomic_read(&(auth_rlm->is_active)) ){
    RHP_UNLOCK(&(auth_rlm->lock));
    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_VERIFY_REQ_CB_REALM_NOT_ACTIVE,"x",auth_rlm);
    goto error;
  }

  cb_ctx->cb_cert_ctx.deny_expired_cert = !auth_rlm->accept_expired_cert;

  auth_rlm_id = auth_rlm->id;

	eap_role = auth_rlm->xauth.role;
	eap_method = auth_rlm->xauth.method;

  RHP_UNLOCK(&(auth_rlm->lock));


  verify_rsasig_req = (rhp_ipcmsg_ikev1_rsasig_verify_req*)cb_ctx->verify_rsasig_req;

  verify_rsasig_rep_len = sizeof(rhp_ipcmsg_ikev1_rsasig_verify_rep) + subject_val_len;

  verify_rsasig_rep = (rhp_ipcmsg_ikev1_rsasig_verify_rep*)rhp_ipc_alloc_msg(
  											RHP_IPC_IKEV1_VERIFY_RSASIG_REPLY,verify_rsasig_rep_len);
  if( verify_rsasig_rep == NULL ){
    RHP_BUG("");
    goto error;
  }

  if( auth_err == 0 ){

  	rhp_auth_peer* peer = auth_rlm->peers;
  	int matched = 0;

  	// Is this user configured to authenticate by PSK ?
  	while( peer ){

  		rhp_ikev2_id_dump("_rhp_syspxy_ikev1_ipc_rsasig_verify_req_cb: auth_rlm->peer.id",&(peer->peer_id.ikev2));

  		switch( peer->peer_id.ikev2.type ){

  		case RHP_PROTO_IKE_ID_ANY:

  			if(  peer->peer_psks == NULL ){
  				matched = 1;
  			}else{

  				if( !rhp_gcfg_auth_method_compared_strictly ){
    				matched = 1;
  					RHP_LOG_I(RHP_LOG_SRC_AUTH,auth_rlm_id,RHP_LOG_ID_ANY_PEERS_PSK_DEFINED_BUT_IGNORED,"I",&(peer->peer_id.ikev2));
  				}else{
						RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_VERIFY_REQ_CB_ANY_PEER_FOUND_BUT_PSK,"x",auth_rlm);
						RHP_LOG_DE(RHP_LOG_SRC_AUTH,auth_rlm_id,RHP_LOG_ID_ANY_PEERS_PSK_DEFINED,"");
  				}
  			}

  			goto out;

  		case RHP_PROTO_IKE_ID_FQDN:
  		case RHP_PROTO_IKE_ID_RFC822_ADDR:

  			if( subjectaltname ){

  				if( !rhp_ikev2_id_cmp(subjectaltname,&(peer->peer_id.ikev2)) ){

  	  			if(  peer->peer_psks == NULL ){
  	  				matched = 1;
  	  			}else{

  	  				if( !rhp_gcfg_auth_method_compared_strictly ){
  	    				matched = 1;
  	    				RHP_LOG_I(RHP_LOG_SRC_AUTH,auth_rlm_id,RHP_LOG_ID_PEER_PSK_DEFINED_BUT_IGNORED,"I",&(peer->peer_id.ikev2));
  	  				}else{
  	  					RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_VERIFY_REQ_CB_PEER_FOUND_BUT_PSK_1,"x",auth_rlm);
  	  					RHP_LOG_DE(RHP_LOG_SRC_AUTH,auth_rlm_id,RHP_LOG_ID_PEER_PSK_DEFINED,"I",&(peer->peer_id.ikev2));
  	  				}
  	  			}

  	  			goto out;
  				}
  			}
  			break;

  		case RHP_PROTO_IKE_ID_DER_ASN1_DN:

  			if( subjectname ){

  				if( !rhp_ikev2_id_cmp(subjectname,&(peer->peer_id.ikev2)) ){

  	  			if( peer->peer_psks == NULL ){
  	  				matched = 1;
  	  			}else{

  	  				if( !rhp_gcfg_auth_method_compared_strictly ){
  	    				matched = 1;
  	    				RHP_LOG_I(RHP_LOG_SRC_AUTH,auth_rlm_id,RHP_LOG_ID_PEER_PSK_DEFINED_BUT_IGNORED,"I",&(peer->peer_id.ikev2));
  	  				}else{
  	  					RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_VERIFY_REQ_CB_PEER_FOUND_BUT_PSK_2,"x",auth_rlm);
  	  					RHP_LOG_DE(RHP_LOG_SRC_AUTH,auth_rlm_id,RHP_LOG_ID_PEER_PSK_DEFINED,"I",&(peer->peer_id.ikev2));
  	  				}
  	  			}

  					goto out;
  				}
  			}
  			break;

  		default:
  			break;
  		}

  		peer = peer->next;
  	}

  	matched = 1; // If no peers are defined, 'ANY' is applied.

out:
  	if( matched ){
  		result = 1;
      RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_VERIFY_REQ_CB_PEER_ID_MATCHED,"x",auth_rlm);
  	}

  }else{

  	RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_VERIFY_REQ_CB_FAILED_TO_VERIFY_PEER_SIG,"x",auth_rlm);
		RHP_LOG_E(RHP_LOG_SRC_AUTH,auth_rlm_id,RHP_LOG_ID_VERIFY_PEER_SIGNATURE_ERR,"IIE",subjectname,subjectaltname,auth_err);

		auth_rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  }

  {
		verify_rsasig_rep->len = verify_rsasig_rep_len;
		verify_rsasig_rep->txn_id = verify_rsasig_req->txn_id;
		verify_rsasig_rep->my_realm_id = auth_rlm_id;
		verify_rsasig_rep->result = result;
		verify_rsasig_rep->side = verify_rsasig_req->side;
		memcpy(verify_rsasig_rep->spi,verify_rsasig_req->spi,RHP_PROTO_IKE_SPI_SIZE);
		verify_rsasig_rep->exchange_type = verify_rsasig_req->exchange_type;

		if( subject_val_len ){

			verify_rsasig_rep->alt_peer_id_len = subject_val_len;
			verify_rsasig_rep->alt_peer_id_type = subject_val_id_type;
			memcpy((verify_rsasig_rep + 1),subject_val,subject_val_len);
		}

		verify_rsasig_rep->eap_role = eap_role;
		verify_rsasig_rep->eap_method = eap_method;
  }

  if( !go_next ){

    if( rhp_ipc_send(RHP_MY_PROCESS,(void*)verify_rsasig_rep,verify_rsasig_rep->len,0) < 0 ){
      RHP_BUG("");
    }

    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_VERIFY_REQ_CB_OK,"x",verify_rsasig_rep);

  }else{

    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_VERIFY_REQ_CB_GO_NEXT,"xd",auth_rlm,result);

  	if( result ){

			if( _rhp_syspxy_ikev1_ipc_rsasig_verify_and_sign_req_cb(cb_ctx->verify_sign_req,
					cb_ctx->in_sign_req,verify_rsasig_rep) ){
				goto error;
			}

			verify_rsasig_rep = NULL;
			pending = 1;

			RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_VERIFY_REQ_CB_PENDING,"xx",verify_rsasig_rep,cb_ctx->verify_sign_req);

  	}else{

  		int reply_len;
      rhp_ipcmsg_verify_and_sign_rep* verify_sign_rep;
      u8* p;

      reply_len = sizeof(rhp_ipcmsg_verify_and_sign_rep);
      reply_len += verify_rsasig_rep->len;

      verify_sign_rep = (rhp_ipcmsg_verify_and_sign_rep*)rhp_ipc_alloc_msg(
      										RHP_IPC_IKEV1_VERIFY_AND_SIGN_RSASIG_REPLY,reply_len);
      if( verify_sign_rep == NULL ){
        RHP_BUG("");
        goto error;
      }

      verify_sign_rep->len = reply_len;
      verify_sign_rep->v1_exchange_type = verify_rsasig_rep->exchange_type;

      p = (u8*)(verify_sign_rep + 1);

      memcpy(p,verify_rsasig_rep,verify_rsasig_rep->len);
      p += verify_rsasig_rep->len;

      if( rhp_ipc_send(RHP_MY_PROCESS,(void*)verify_sign_rep,verify_sign_rep->len,0) < 0 ){
        RHP_BUG("");
      }

      _rhp_free_zero(verify_sign_rep,verify_sign_rep->len);

      RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_VERIFY_REQ_CB_AUTH_FAILED,"xx",verify_rsasig_rep,verify_rsasig_rep);
  	}
  }

error:
  if( verify_rsasig_rep ){
    _rhp_free_zero(verify_rsasig_rep,verify_rsasig_rep->len);
  }
  if( cert_store ){
  	rhp_cert_store_unhold(cert_store);
  }
  if( auth_rlm ){
  	rhp_auth_realm_unhold(auth_rlm);
  }
  if( !go_next ){
    _rhp_free_zero(verify_rsasig_req,verify_rsasig_req->len);
  }else{
    if( !pending ){
      _rhp_free_zero(cb_ctx->verify_sign_req,cb_ctx->verify_sign_req->len);
    }
  }

  if( cb_ctx->cb_cert_ctx.peer_cert ){
  	rhp_cert_free(cb_ctx->cb_cert_ctx.peer_cert);
  }

  _rhp_free_zero(cb_ctx,sizeof(rhp_auth_ipc_verify_rsasig_cb_ctx));

  if( subject_val ){
  	_rhp_free(subject_val);
  }

  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_VERIFY_REQ_CB_RTRN,"xxd",cert_store,cb_cert_ctx,result);
  return;
}

static int _rhp_syspxy_ikev1_ipc_handle_rsasig_verify_req(rhp_ipcmsg *ipcmsg,rhp_ipcmsg** ipcmsg_r,
    rhp_ipcmsg* verify_sign_req,rhp_ipcmsg* in_sign_req)
{
  int err = -EINVAL;
  rhp_ipcmsg_ikev1_rsasig_verify_req* verify_rsasig_req;
  rhp_vpn_auth_realm* auth_rlm = NULL;
  rhp_cert_store* cert_store = NULL;
  char* id_string = NULL;
  rhp_ikev2_id peer_id;
  rhp_ipcmsg_ikev1_rsasig_verify_rep* verify_rsasig_rep;
  int verify_rsasig_rep_len = 0;
  rhp_auth_ipc_verify_rsasig_cb_ctx* cb_ctx;
  u8* peer_cert_bin = NULL;
  u8* cert_chain_bin = NULL;
  u8* mesg_octets = NULL;
  u8* signature = NULL;
  int peer_cert_bin_len = 0;
  int cert_chain_bin_len = 0;
  int mesg_octets_len;
  int signature_octets_len = 0;
  u8* p;
  unsigned long auth_rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  rhp_cert* peer_cert = NULL;
  int deny_expired_cert = 0;
  int xauth_method = 0;

  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSASIG_VERIFY_REQ,"xxxx",ipcmsg,ipcmsg_r,verify_sign_req,in_sign_req);

  memset(&peer_id,0,sizeof(rhp_ikev2_id));

  if( ipcmsg->len < sizeof(rhp_ipcmsg_ikev1_rsasig_verify_req) ){
    RHP_BUG("");
    goto error;
  }

  verify_rsasig_req = (rhp_ipcmsg_ikev1_rsasig_verify_req*)ipcmsg;


  if( verify_rsasig_req->len !=
			sizeof(rhp_ipcmsg_ikev1_rsasig_verify_req)
      + verify_rsasig_req->peer_id_len + verify_rsasig_req->peer_cert_bin_len
      + verify_rsasig_req->cert_chain_bin_len + verify_rsasig_req->mesg_octets_len
      + verify_rsasig_req->signature_octets_len ){
    RHP_BUG("");
    goto error;
  }


  if( verify_rsasig_req->peer_id_len == 0 ){
    RHP_BUG("");
    goto failed;
  }


  if( verify_rsasig_req->mesg_octets_len == 0 ){
    RHP_BUG("");
    goto failed;
  }


  p = (u8*)(verify_rsasig_req + 1);


  if( verify_rsasig_req->peer_id_len  ){

    peer_id.type = verify_rsasig_req->peer_id_type;

    switch( peer_id.type ){

      case RHP_PROTO_IKE_ID_FQDN:
      case RHP_PROTO_IKE_ID_RFC822_ADDR:

        id_string = (char*)p;
        if( id_string[verify_rsasig_req->peer_id_len - 1] != '\0' ){
          RHP_BUG("");
          goto failed;
        }
        peer_id.string = id_string;
        p += verify_rsasig_req->peer_id_len;

        RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSASIG_VERIFY_REQ_PEER_ID,"ds",peer_id.type,peer_id.string);
        break;

      case RHP_PROTO_IKE_ID_DER_ASN1_DN:

        peer_id.dn_der = (u8*)p;
        peer_id.dn_der_len = verify_rsasig_req->peer_id_len;
        p +=  verify_rsasig_req->peer_id_len;

        RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSASIG_VERIFY_REQ_PEER_ID_DN,"dp",peer_id.type,peer_id.dn_der_len,peer_id.dn_der);
        break;

      case RHP_PROTO_IKE_ID_IPV4_ADDR:

      	if( verify_rsasig_req->peer_id_len != 4){
      		RHP_BUG("%d",verify_rsasig_req->peer_id_len);
          goto failed;
      	}

      	peer_id.addr.addr_family = AF_INET;
      	memcpy(peer_id.addr.addr.raw,p,verify_rsasig_req->peer_id_len);
        p +=  verify_rsasig_req->peer_id_len;

        RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSASIG_VERIFY_REQ_PEER_ID_IPV4,"d4",peer_id.type,peer_id.addr.addr.v4);
      	break;

      case RHP_PROTO_IKE_ID_IPV6_ADDR:

      	if( verify_rsasig_req->peer_id_len != 16){
      		RHP_BUG("%d",verify_rsasig_req->peer_id_len);
          goto failed;
      	}

      	peer_id.addr.addr_family = AF_INET6;
      	memcpy(peer_id.addr.addr.raw,p,verify_rsasig_req->peer_id_len);
        p +=  verify_rsasig_req->peer_id_len;

        RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSASIG_VERIFY_REQ_PEER_ID_IPV6,"d6",peer_id.type,peer_id.addr.addr.v6);
      	break;

      default:
        RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSASIG_VERIFY_REQ_PEER_ID_UNKNOWN,"d",peer_id.type);
      	RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_VERIFY_RSASIG_RX_INVALID_PEER_ID_TYPE,"d",peer_id.type);

      	goto failed;
    }
  }

  if( verify_rsasig_req->peer_cert_bin_len ){
  	peer_cert_bin = p;
		peer_cert_bin_len = verify_rsasig_req->peer_cert_bin_len;
		p += peer_cert_bin_len;
  }

  if( verify_rsasig_req->cert_chain_bin_len && verify_rsasig_req->cert_chain_num ){
    cert_chain_bin = p;
    cert_chain_bin_len = verify_rsasig_req->cert_chain_bin_len;
    p +=  cert_chain_bin_len;
  }

  mesg_octets = p;
  mesg_octets_len = verify_rsasig_req->mesg_octets_len;
  p +=  mesg_octets_len;

  if( verify_rsasig_req->signature_octets_len ){
		signature = p;
		signature_octets_len = verify_rsasig_req->signature_octets_len;
		p +=  signature_octets_len;
  }

  if( peer_cert_bin ){

  	peer_cert = rhp_cert_alloc(peer_cert_bin,peer_cert_bin_len);
		if( peer_cert == NULL ){

			RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSASIG_VERIFY_REQ_CERT_ALLOC_ERR,"p",peer_cert_bin_len,peer_cert_bin);
			RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_VERIFY_RSASIG_RX_INVALID_PEER_CERT,"II",NULL,&peer_id);

			goto failed;
		}
  }

  if( verify_rsasig_req->my_realm_id != RHP_VPN_REALM_ID_UNKNOWN ){

    auth_rlm = rhp_auth_realm_get(verify_rsasig_req->my_realm_id);

  }else{

  	auth_rlm = rhp_auth_realm_get_by_role(NULL,
  			RHP_PEER_ID_TYPE_IKEV2,(void*)&peer_id,peer_cert,1,verify_rsasig_req->peer_notified_realm_id);
  }

  if( auth_rlm == NULL ){

    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSASIG_VERIFY_REQ_RLM_NOT_FOUND,"u",verify_rsasig_req->my_realm_id);
  	RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_VERIFY_RSASIG_REALM_NOT_DEFINED,"II",NULL,&peer_id);

  	goto failed;
  }


  RHP_LOCK(&(auth_rlm->lock));
  {

  	if( auth_rlm->xauth.p1_auth_method != RHP_XAUTH_P1_AUTH_HYBRID_RSASIG &&
  			(signature == NULL || peer_cert_bin == NULL || peer_cert == NULL) ){

      RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSASIG_VERIFY_REQ_NOT_RX_PEER_SIGNATURE_OR_PEER_CERT,"udxxxx",verify_rsasig_req->my_realm_id,auth_rlm->xauth.p1_auth_method,auth_rlm,signature,peer_cert_bin,peer_cert);

  		RHP_UNLOCK(&(auth_rlm->lock));

  		goto failed;
  	}

  	xauth_method = auth_rlm->xauth.p1_auth_method;


		cert_store = auth_rlm->my_auth->cert_store;
		if( cert_store ){

			rhp_cert_store_hold(cert_store);

			deny_expired_cert = !auth_rlm->accept_expired_cert;

		}else{

		  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSASIG_VERIFY_REQ_NO_CERT_STORE,"xxxx",ipcmsg,verify_sign_req,in_sign_req,auth_rlm);
	  	RHP_LOG_E(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_VERIFY_RSASIG_NO_MY_CERT_STORE,"II",NULL,&peer_id);

			RHP_UNLOCK(&(auth_rlm->lock));

			goto failed;
		}
  }
  RHP_UNLOCK(&(auth_rlm->lock));



	cb_ctx = (rhp_auth_ipc_verify_rsasig_cb_ctx*)_rhp_malloc(sizeof(rhp_auth_ipc_verify_rsasig_cb_ctx));
	if( cb_ctx == NULL ){
		RHP_BUG("");
		goto failed;
	}
	memset(cb_ctx,0,sizeof(rhp_auth_ipc_verify_rsasig_cb_ctx));

	cb_ctx->cb_cert_ctx.tag[0] = '#';
	cb_ctx->cb_cert_ctx.tag[1] = 'C';
	cb_ctx->cb_cert_ctx.tag[2] = 'S';
	cb_ctx->cb_cert_ctx.tag[3] = 'C';

	cb_ctx->cb_cert_ctx.sign_op_type = RHP_CERT_SIGN_OP_VERIFY_IKEV1;

	cb_ctx->cb_cert_ctx.peer_cert = peer_cert;
	cb_ctx->cb_cert_ctx.cert_chain_bin = cert_chain_bin;
	cb_ctx->cb_cert_ctx.cert_chain_bin_len = cert_chain_bin_len;
	cb_ctx->cb_cert_ctx.signed_octets = mesg_octets;
	cb_ctx->cb_cert_ctx.signed_octets_len = mesg_octets_len;
	cb_ctx->cb_cert_ctx.signature = signature;
	cb_ctx->cb_cert_ctx.signature_len = signature_octets_len;

	cb_ctx->cb_cert_ctx.cert_chain_num = verify_rsasig_req->cert_chain_num;

	cb_ctx->auth_rlm = auth_rlm;
	rhp_auth_realm_hold(auth_rlm);

	cb_ctx->cb_cert_ctx.deny_expired_cert = deny_expired_cert;

	cb_ctx->verify_rsasig_req = (rhp_ipcmsg*)verify_rsasig_req;
	cb_ctx->verify_sign_req = verify_sign_req;
	cb_ctx->in_sign_req = in_sign_req;


  if( xauth_method != RHP_XAUTH_P1_AUTH_HYBRID_RSASIG ){

  	cb_ctx->cb_cert_ctx.callback = _rhp_syspxy_ikev1_ipc_rsasig_verify_req_cb;

		err = cert_store->verify_signature(cert_store,(rhp_cert_sign_verify_ctx*)cb_ctx);
		if( err ){
			RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSASIG_VERIFY_REQ_VERIFY_SIG_ERR,"xx",cert_store,cb_ctx);
			goto failed;
		}

  }else{ // RHP_XAUTH_P1_AUTH_HYBRID_RSASIG

    rhp_cert_store_hold(cert_store);

    _rhp_syspxy_ikev1_ipc_rsasig_verify_req_cb(cert_store,0,NULL,NULL,cb_ctx);

    rhp_cert_store_unhold(cert_store);
  }


  rhp_auth_realm_unhold(auth_rlm);

  *ipcmsg_r = NULL;

  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSASIG_VERIFY_REQ_PENDING,"xd",ipcmsg,deny_expired_cert);
  return 0;

failed:

  verify_rsasig_rep_len = sizeof(rhp_ipcmsg_ikev1_rsasig_verify_rep);

  verify_rsasig_rep = (rhp_ipcmsg_ikev1_rsasig_verify_rep*)rhp_ipc_alloc_msg(RHP_IPC_IKEV1_VERIFY_RSASIG_REPLY,verify_rsasig_rep_len);
  if( verify_rsasig_rep == NULL ){
    RHP_BUG("");
    goto error;
  }

  verify_rsasig_rep->len = verify_rsasig_rep_len;
  verify_rsasig_rep->txn_id = verify_rsasig_req->txn_id;
  verify_rsasig_rep->my_realm_id = auth_rlm_id;
  verify_rsasig_rep->result = 0;
  verify_rsasig_rep->side = verify_rsasig_req->side;
  memcpy(verify_rsasig_rep->spi,verify_rsasig_req->spi,RHP_PROTO_IKE_SPI_SIZE);
	verify_rsasig_rep->exchange_type = verify_rsasig_req->exchange_type;

  if( peer_cert ){
    rhp_cert_free(peer_cert);
  }

  if( cert_store ){
    rhp_cert_store_unhold(cert_store);
  }

  if( auth_rlm ){
    rhp_auth_realm_unhold(auth_rlm);
  }

  *ipcmsg_r = (rhp_ipcmsg*)verify_rsasig_rep;

  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSASIG_VERIFY_REQ_RTRN,"xp",ipcmsg,verify_rsasig_rep->len,verify_rsasig_rep);
  return 0;

error:
  if( cert_store ){
    rhp_cert_store_unhold(cert_store);
  }
  if( auth_rlm ){
    rhp_auth_realm_unhold(auth_rlm);
  }
  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSASIG_VERIFY_REQ_ERR,"x",ipcmsg);
  return err;
}

static void _rhp_syspxy_ikev1_ipc_rsasig_verify_req_handler(rhp_ipcmsg** ipcmsg)
{
	int err;
	rhp_ipcmsg* ipcmsg_r = NULL;

	err = _rhp_syspxy_ikev1_ipc_handle_rsasig_verify_req(*ipcmsg,&ipcmsg_r,NULL,NULL);

	if( ipcmsg_r ){

	  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipcmsg_r,ipcmsg_r->len,0) < 0 ){
	    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_VERIFY_REQ_HANDLER_ERR,"xxdd",RHP_MY_PROCESS,ipcmsg_r,ipcmsg_r->len,0);
	  }
	  _rhp_free_zero(ipcmsg_r,ipcmsg_r->len);
	}

	if( ipcmsg_r || err ){
		_rhp_free_zero(*ipcmsg,(*ipcmsg)->len);
	}
	*ipcmsg = NULL;

	return;
}

static void _rhp_syspxy_ikev1_ipc_handle_rslv_auth_req(rhp_ipcmsg** ipcmsg_c)
{
	rhp_ipcmsg* ipcmsg = *ipcmsg_c;
  rhp_ipcmsg_ikev1_rslv_auth_req* rslv_auth_req;
  rhp_vpn_auth_realm* auth_rlm = NULL;
  char* id_string = NULL;
  rhp_ikev2_id peer_id;
  rhp_ipcmsg_ikev1_rslv_auth_rep* rslv_auth_rep = NULL;
  int rslv_auth_rep_len = 0;
  u8* p;
  unsigned long auth_rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  int result = 0;

  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSLV_AUTH_REQ,"xx",ipcmsg_c,ipcmsg);

  memset(&peer_id,0,sizeof(rhp_ikev2_id));

  if( ipcmsg->len < sizeof(rhp_ipcmsg_ikev1_rslv_auth_req) ){
    RHP_BUG("");
    goto error;
  }

  rslv_auth_req = (rhp_ipcmsg_ikev1_rslv_auth_req*)ipcmsg;


  if( rslv_auth_req->len !=
			sizeof(rhp_ipcmsg_ikev1_rslv_auth_req) + rslv_auth_req->peer_id_len ){
    RHP_BUG("%d,%d,%d",rslv_auth_req->len,sizeof(rhp_ipcmsg_ikev1_rslv_auth_req),rslv_auth_req->peer_id_len);
    goto error;
  }


  if( rslv_auth_req->peer_id_len == 0 ){
    RHP_BUG("");
    goto failed;
  }


  p = (u8*)(rslv_auth_req + 1);


  peer_id.type = rslv_auth_req->peer_id_type;

  switch( peer_id.type ){

  case RHP_PROTO_IKE_ID_FQDN:
  case RHP_PROTO_IKE_ID_RFC822_ADDR:

    id_string = (char*)p;
    if( id_string[rslv_auth_req->peer_id_len - 1] != '\0' ){
      RHP_BUG("");
      goto failed;
    }
    peer_id.string = id_string;
    p += rslv_auth_req->peer_id_len;

    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSLV_AUTH_REQ_PEER_ID,"ds",peer_id.type,peer_id.string);
    break;

  case RHP_PROTO_IKE_ID_DER_ASN1_DN:

    peer_id.dn_der = (u8*)p;
    peer_id.dn_der_len = rslv_auth_req->peer_id_len;
    p +=  rslv_auth_req->peer_id_len;

    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSLV_AUTH_REQ_PEER_ID_DN,"dp",peer_id.type,peer_id.dn_der_len,peer_id.dn_der);
    break;

  case RHP_PROTO_IKE_ID_IPV4_ADDR:

  	if( rslv_auth_req->peer_id_len != 4){
  		RHP_BUG("%d",rslv_auth_req->peer_id_len);
      goto failed;
  	}

  	peer_id.addr.addr_family = AF_INET;
  	memcpy(peer_id.addr.addr.raw,p,rslv_auth_req->peer_id_len);
    p +=  rslv_auth_req->peer_id_len;

    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSLV_AUTH_REQ_PEER_ID_IPV4,"d4",peer_id.type,peer_id.addr.addr.v4);
  	break;

   case RHP_PROTO_IKE_ID_IPV6_ADDR:

   	if( rslv_auth_req->peer_id_len != 16){
   		RHP_BUG("%d",rslv_auth_req->peer_id_len);
       goto failed;
   	}

   	peer_id.addr.addr_family = AF_INET6;
   	memcpy(peer_id.addr.addr.raw,p,rslv_auth_req->peer_id_len);
     p +=  rslv_auth_req->peer_id_len;

    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSLV_AUTH_REQ_PEER_ID_IPV6,"d6",peer_id.type,peer_id.addr.addr.v6);
   	break;

  default:

  	RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSLV_AUTH_REQ_PEER_ID_UNKNOWN,"d",peer_id.type);
    RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_RESOLVE_AUTH_REALM_RX_INVALID_PEER_ID_TYPE,"d",peer_id.type);

    goto failed;
  }


	auth_rlm = rhp_auth_realm_get_by_role(NULL,
			RHP_PEER_ID_TYPE_IKEV2,(void*)&peer_id,NULL,1,rslv_auth_req->peer_notified_realm_id);

  if( auth_rlm == NULL ){

    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSLV_AUTH_REQ_RLM_NOT_FOUND,"x",rslv_auth_req);
  	RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_RESOLVE_AUTH_REALM_NOT_DEFINED,"Iu",&peer_id,rslv_auth_req->peer_notified_realm_id);

  	goto failed;
  }

  auth_rlm_id = auth_rlm->id;
  result = 1;


failed:

  rslv_auth_rep_len = sizeof(rhp_ipcmsg_ikev1_rslv_auth_rep);

  rslv_auth_rep = (rhp_ipcmsg_ikev1_rslv_auth_rep*)rhp_ipc_alloc_msg(
  									RHP_IPC_IKEV1_RESOLVE_AUTH_REPLY,rslv_auth_rep_len);
  if( rslv_auth_rep == NULL ){
    RHP_BUG("");
    goto error;
  }

  rslv_auth_rep->len = rslv_auth_rep_len;
  rslv_auth_rep->txn_id = rslv_auth_req->txn_id;
  rslv_auth_rep->my_realm_id = auth_rlm_id;
  rslv_auth_rep->result = result;
  rslv_auth_rep->side = rslv_auth_req->side;
  memcpy(rslv_auth_rep->spi,rslv_auth_req->spi,RHP_PROTO_IKE_SPI_SIZE);
  rslv_auth_rep->exchange_type = rslv_auth_req->exchange_type;

  if( auth_rlm ){
    rhp_auth_realm_unhold(auth_rlm);
  }


  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)rslv_auth_rep,rslv_auth_rep->len,0) < 0 ){
    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_VERIFY_REQ_HANDLER_ERR,"xxdd",RHP_MY_PROCESS,rslv_auth_rep,rslv_auth_rep->len,0);
  }
  _rhp_free_zero(rslv_auth_rep,rslv_auth_rep->len);

	_rhp_free_zero(ipcmsg,ipcmsg->len);
	*ipcmsg_c = NULL;

  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSLV_AUTH_REQ_RTRN,"x",ipcmsg);
  return;

error:
  if( auth_rlm ){
    rhp_auth_realm_unhold(auth_rlm);
  }
  if( rslv_auth_rep ){
  	_rhp_free_zero(rslv_auth_rep,rslv_auth_rep->len);
  }
  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_HANDLE_RSLV_AUTH_REQ_ERR,"x",ipcmsg);
  return;
}


static int _rhp_syspxy_ikev1_ipc_rsasig_verify_and_sign_req(rhp_ipcmsg *ipcmsg,rhp_ipcmsg** ipcmsg_r)
{
  int err = -EINVAL;
  rhp_ipcmsg_verify_and_sign_req* verify_sign_req;
  rhp_ipcmsg *in_verify_req,*in_sign_req;
  rhp_ipcmsg *in_verify_rep = NULL,*in_sign_rep = NULL;
  int pending = 0;

  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_VERIFY_AND_SIGN_REQ,"xx",ipcmsg,ipcmsg_r);

  if( ipcmsg->len < sizeof(rhp_ipcmsg_verify_and_sign_req) + sizeof(rhp_ipcmsg)*2  ){
    RHP_BUG("");
    goto error;
  }

  verify_sign_req = (rhp_ipcmsg_verify_and_sign_req*)ipcmsg;

  in_verify_req = (rhp_ipcmsg*)(verify_sign_req + 1);

  if( ((u8*)in_verify_req) + in_verify_req->len > ((u8*)ipcmsg) + ipcmsg->len ){
    RHP_BUG("");
    goto error;
  }

  in_sign_req = (rhp_ipcmsg*)(((u8*)in_verify_req) + in_verify_req->len);

  if( ((u8*)in_sign_req) + in_sign_req->len > ((u8*)ipcmsg) + ipcmsg->len ){
    RHP_BUG("");
    goto error;
  }

  if( in_verify_req->type != RHP_IPC_IKEV1_VERIFY_RSASIG_REQUEST ){
    RHP_BUG("%d",in_verify_req->type);
    goto error;
  }


  err = _rhp_syspxy_ikev1_ipc_handle_rsasig_verify_req(in_verify_req,&in_verify_rep,ipcmsg,in_sign_req);
  if( err ){
    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_VERIFY_AND_SIGN_REQ_VERIFY_ERR,"xE",ipcmsg,err);
    goto error;
  }

  if( in_verify_rep == NULL ){
  	pending = 1;
  }


  if( !pending ){

    int reply_len;
    rhp_ipcmsg_verify_and_sign_rep* verify_sign_rep;
    u8* p;

    reply_len = sizeof(rhp_ipcmsg_verify_and_sign_rep);

    if( in_verify_rep ){
      reply_len += in_verify_rep->len;
    }

    if( in_sign_rep && in_sign_rep->len ){
      reply_len += in_sign_rep->len;
    }

    verify_sign_rep = (rhp_ipcmsg_verify_and_sign_rep*)rhp_ipc_alloc_msg(
    										RHP_IPC_IKEV1_VERIFY_AND_SIGN_RSASIG_REPLY,reply_len);
    if( verify_sign_rep == NULL ){
      RHP_BUG("");
      err = -ENOMEM;
      goto error;
    }

    verify_sign_rep->len = reply_len;

    p = (u8*)(verify_sign_rep + 1);

    if( in_verify_rep ){
      memcpy(p,in_verify_rep,in_verify_rep->len);
      p += in_verify_rep->len;
      verify_sign_rep->v1_exchange_type = verify_sign_req->v1_exchange_type;
    }

    if( in_sign_rep ){
      memcpy(p,in_sign_rep,in_sign_rep->len);
      p += in_sign_rep->len;
      verify_sign_rep->v1_exchange_type = verify_sign_req->v1_exchange_type;
    }

    if( in_verify_rep ){
      _rhp_free_zero(in_verify_rep,in_verify_rep->len);
    }

    if( in_sign_rep ){
      _rhp_free_zero(in_sign_rep,in_sign_rep->len);
    }

    *ipcmsg_r = (rhp_ipcmsg*)verify_sign_rep;

    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_VERIFY_AND_SIGN_REQ_RTRN,"xp",ipcmsg,verify_sign_rep->len,verify_sign_rep);

  }else{
    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_VERIFY_AND_SIGN_REQ_PENDING,"x",ipcmsg);
  }

  return 0;

error:
  if( in_verify_rep ){
    _rhp_free_zero(in_verify_rep,in_verify_rep->len);
  }
  if( in_sign_rep ){
    _rhp_free_zero(in_sign_rep,in_sign_rep->len);
  }
  RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_VERIFY_AND_SIGN_REQ_ERR,"x",ipcmsg);
  return err;
}

static void _rhp_syspxy_ikev1_ipc_rsasig_verify_and_sign_req_handler(rhp_ipcmsg** ipcmsg)
{
	int err;
	rhp_ipcmsg* ipcmsg_r = NULL;

	err = _rhp_syspxy_ikev1_ipc_rsasig_verify_and_sign_req(*ipcmsg,&ipcmsg_r);

	if( ipcmsg_r ){

	  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipcmsg_r,ipcmsg_r->len,0) < 0 ){
	    RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_IPC_RSASIG_VERIFY_AND_SIGN_REQ_HANDLER_ERR,"xxdd",RHP_MY_PROCESS,ipcmsg_r,ipcmsg_r->len,0);
	  }
	  _rhp_free_zero(ipcmsg_r,ipcmsg_r->len);
	}


	if( ipcmsg_r || err ){
		_rhp_free_zero(*ipcmsg,(*ipcmsg)->len);
	}
	*ipcmsg = NULL;

  return;
}


int rhp_syspxy_ikev1_auth_init()
{
	int err = -EINVAL;

	// TODO : rhp_prc_ipcmsg_wts_handler should be used for IKEv2's heavy crypto processing.
	err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_IKEV1_PSK_SKEYID_REQUEST,
			_rhp_syspxy_ikev1_ipc_psk_skeyid_req_handler,NULL);
	if( err ){
		RHP_BUG("");
		return err;
	}

	// TODO : rhp_prc_ipcmsg_wts_handler should be used for IKEv2's heavy crypto processing.
	err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_IKEV1_SIGN_RSASIG_REQUEST,
			_rhp_syspxy_ikev1_ipc_rsasig_sign_req_handler,NULL);
	if( err ){
		RHP_BUG("");
		return err;
	}

	// TODO : rhp_prc_ipcmsg_wts_handler should be used for IKEv2's heavy crypto processing.
	err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_IKEV1_VERIFY_RSASIG_REQUEST,
			_rhp_syspxy_ikev1_ipc_rsasig_verify_req_handler,NULL);
	if( err ){
		RHP_BUG("");
		return err;
	}

	// TODO : rhp_prc_ipcmsg_wts_handler should be used for IKEv2's heavy crypto processing.
	err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_IKEV1_VERIFY_AND_SIGN_RSASIG_REQUEST,
			_rhp_syspxy_ikev1_ipc_rsasig_verify_and_sign_req_handler,NULL);
	if( err ){
		RHP_BUG("");
		return err;
	}

	err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_IKEV1_RESOLVE_AUTH_REQUEST,
			_rhp_syspxy_ikev1_ipc_handle_rslv_auth_req,NULL);
	if( err ){
		RHP_BUG("");
		return err;
	}


	RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_INIT,"E",err);

  return 0;
}

int rhp_syspxy_ikev1_auth_cleanup()
{

	RHP_TRC(0,RHPTRCID_SYSPXY_IKEV1_CLEANUP,"");
	return 0;
}
