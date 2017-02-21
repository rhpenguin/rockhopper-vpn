/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
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

extern rhp_mutex_t rhp_auth_lock;
extern rhp_auth_admin_info* rhp_auth_admin_head;

extern int rhp_ikev2_qcd_get_my_token(int my_side,u8* my_ikesa_spi,u8* peer_ikesa_spi,u8* token_r);


int rhp_auth_supported_prf_method(int prf_method)
{
  switch( prf_method ){

    case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_MD5:
    case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA1:
    case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_256:
    case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_384:
    case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_512:
    	break;

    default:
      RHP_BUG("%d",prf_method);
      return -EINVAL;
  }
  return 0;
}


static int _rhp_auth_ipc_handle_auth_cookie_req(rhp_ipcmsg *ipcmsg,rhp_ipcmsg** ipcmsg_r)
{
  int err = -EINVAL;
  rhp_ipcmsg_auth_cookie_req* auth_req = NULL;
  unsigned char* id = NULL;
  unsigned char* nonce = NULL;
  u8* ticket = NULL;
  unsigned int result = 0;
  rhp_ipcmsg_auth_rep* auth_rep;
  rhp_auth_admin_info* admin_info = NULL;
  unsigned long rlm_id = 0;
  int err_rlm_not_matched = 0;
  int is_nobody = 0;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_AUTH_COOKIE_REQ,"xx",ipcmsg,ipcmsg_r);

  if( ipcmsg->len < sizeof(rhp_ipcmsg_auth_cookie_req) ){
    RHP_BUG("");
    goto error;
  }

  auth_req = (rhp_ipcmsg_auth_cookie_req*)ipcmsg;

  if( auth_req->len != sizeof(rhp_ipcmsg_auth_cookie_req)
  		+ auth_req->id_len + auth_req->nonce_len + auth_req->ticket_len ){
    RHP_BUG("");
    goto error;
  }


  if( ((long)auth_req->id_len) < (RHP_AUTH_REQ_MIN_ID_LEN + 1) || auth_req->id_len > RHP_AUTH_REQ_MAX_ID_LEN ){
    RHP_BUG("");
    goto auth_failed;
  }

  id = (unsigned char*)(auth_req + 1);

  if( id[auth_req->id_len - 1] != '\0' ){
    RHP_BUG("");
    goto auth_failed;
  }


  nonce = (unsigned char*)( ((u8*)id) + auth_req->id_len );

  if( nonce[auth_req->nonce_len - 1] != '\0' ){
    RHP_BUG("");
    goto auth_failed;
  }


  ticket = (unsigned char*)( ((u8*)nonce) + auth_req->nonce_len );

  if( auth_req->ticket_len != RHP_HTTP_AUTH_TICKET_SIZE ){
    RHP_BUG("");
    goto auth_failed;
  }


  RHP_LOCK(&(rhp_auth_lock));

  admin_info = rhp_auth_admin_get((char*)id,auth_req->id_len);
  if( admin_info == NULL ){
    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_AUTH_COOKIE_REQ_INVALID_ID_NO_ADM_INFO,"s",id);
    goto auth_failed_l;
  }

  if( admin_info->hashed_key_base64 == NULL ){
    result = 1;
    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_AUTH_COOKIE_REQ_REQ_OK_NO_ADM_PW,"xx",ipcmsg,ipcmsg_r);
    goto auth_no_password;
  }

  {
  	int pad_len = strlen("Rockhopper:");
  	u8 *buf = NULL,*p;
  	int buf_len = (auth_req->id_len - 1) + (auth_req->nonce_len - 1) + pad_len + 1;
  	u8* ticket_tmp = NULL;
  	int ticket_tmp_len = 0;

  	buf = (u8*)_rhp_malloc(buf_len + 1);
  	if( buf == NULL ){
  		RHP_BUG("");
  		err = -ENOMEM;
  		goto auth_failed_l;
  	}
  	p = buf;

  	memcpy(p,"Rockhopper:",pad_len);
  	p += pad_len;
  	memcpy(p,id,(auth_req->id_len - 1));
  	p += (auth_req->id_len - 1);
  	memcpy(p,":",1);
  	p++;
  	memcpy(p,nonce,auth_req->nonce_len); // '\0' included for Debug.


  	err = rhp_crypto_hmac(RHP_CRYPTO_HMAC_SHA1,
  			buf,buf_len,(u8*)(admin_info->hashed_key_base64),strlen(admin_info->hashed_key_base64),&ticket_tmp,&ticket_tmp_len);

  	if( err ){
  		RHP_BUG("");
  		_rhp_free(buf);
  		goto auth_failed_l;
  	}


  	if( ticket_tmp_len != (int)auth_req->ticket_len ||
  			memcmp(ticket_tmp,ticket,auth_req->ticket_len) ){

      RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_AUTH_COOKIE_REQ_NG_TICKET_NOT_MATCH,"sppdss",admin_info->id,auth_req->ticket_len,ticket,ticket_tmp_len,ticket_tmp,buf_len,buf,admin_info->hashed_key_base64);

      _rhp_free(buf);
      _rhp_free(ticket_tmp);
  		goto auth_failed_l;
  	}

		_rhp_free(buf);
    _rhp_free(ticket_tmp);

		result = 1;
    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_AUTH_COOKIE_REQ_TICKET_MATCHED_OK,"spp",admin_info->id,auth_req->ticket_len,ticket,ticket_tmp_len,ticket_tmp);
  }

auth_failed_l:
auth_no_password:
	if( auth_req->vpn_realm_id != (unsigned long)-1 ){

		if( result ){

			if( admin_info->vpn_realm_id && (admin_info->vpn_realm_id != auth_req->vpn_realm_id) ){

				RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_AUTH_COOKIE_REQ_NG_RLM_NOT_MATCH,"suu",admin_info->id,admin_info->vpn_realm_id,auth_req->vpn_realm_id);
				result = 0;
				err_rlm_not_matched = 1;
			}
		}
	}

	if( result ){
		rlm_id = admin_info->vpn_realm_id;
		is_nobody = (unsigned int)(admin_info->is_nobody);
	}else{
		rlm_id = 0;
		RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_AUTH_ADMIN_AUTH_COOKIE_FAILED,"su",id,auth_req->vpn_realm_id);
	}

  RHP_UNLOCK(&(rhp_auth_lock));
auth_failed:

  auth_rep = (rhp_ipcmsg_auth_rep*)rhp_ipc_alloc_msg(RHP_IPC_AUTH_COOKIE_REPLY,sizeof(rhp_ipcmsg_auth_rep) + auth_req->id_len);
  if( auth_rep == NULL ){
    RHP_BUG("");
    goto error;
  }

  auth_rep->len = sizeof(rhp_ipcmsg_auth_rep) + auth_req->id_len;
  auth_rep->txn_id = auth_req->txn_id;
  auth_rep->result = result;
  auth_rep->vpn_realm_id = rlm_id;
  auth_rep->request_user = auth_req->request_user;
  auth_rep->is_nobody = is_nobody;

  if( auth_req->id_len && id ){
    auth_rep->id_len = auth_req->id_len;
    memcpy((u8*)(auth_rep + 1),id,auth_req->id_len);
  }else{
    auth_rep->id_len = 0;
  }

  *ipcmsg_r = (rhp_ipcmsg*)auth_rep;

  if( !result ){
  	if( err_rlm_not_matched ){
    	RHP_LOG_E(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_AUTH_ADMIN_INVALID_REALM,"su",id,auth_req->vpn_realm_id);
  	}else{
    	RHP_LOG_E(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_AUTH_ADMIN_FAILED,"su",id,auth_req->vpn_realm_id);
  	}
  }

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_AUTH_COOKIE_REQ_RTRN,"xudp",ipcmsg,rlm_id,is_nobody,auth_rep->len,auth_rep);
  return 0;

error:
	RHP_LOG_E(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_AUTH_ADMIN_ERR,"suE",id,auth_req->vpn_realm_id,err);

	RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_AUTH_COOKIE_REQ_ERR,"xd",ipcmsg,err);
  return err;
}

static int _rhp_auth_ipc_handle_auth_basic_req(rhp_ipcmsg *ipcmsg,rhp_ipcmsg** ipcmsg_r)
{
  int err = -EINVAL;
  rhp_ipcmsg_auth_basic_req* auth_req = NULL;
  unsigned char* id = NULL;
  unsigned char* password;
  unsigned int result = 0;
  u8* hashed_key = NULL;
  int hashed_key_len = 0;
  rhp_ipcmsg_auth_rep* auth_rep;
  rhp_auth_admin_info* admin_info = NULL;
  unsigned long rlm_id = 0;
  int err_rlm_not_matched = 0;
  int is_nobody = 0;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_AUTH_BASIC_REQ,"xx",ipcmsg,ipcmsg_r);

  if( ipcmsg->len < sizeof(rhp_ipcmsg_auth_basic_req) ){
    RHP_BUG("");
    goto error;
  }

  auth_req = (rhp_ipcmsg_auth_basic_req*)ipcmsg;

  if( auth_req->len != sizeof(rhp_ipcmsg_auth_basic_req) + auth_req->id_len + auth_req->password_len ){
    RHP_BUG("");
    goto error;
  }

  if( ((long)auth_req->id_len) < RHP_AUTH_REQ_MIN_ID_LEN || auth_req->id_len > RHP_AUTH_REQ_MAX_ID_LEN ){
    RHP_BUG("");
    goto auth_failed;
  }

  id = (unsigned char*)(auth_req + 1);

  if( id[auth_req->id_len - 1] != '\0' ){
    RHP_BUG("");
    goto auth_failed;
  }

  if( auth_req->password_len < (RHP_AUTH_REQ_MIN_PW_LEN + 1) /* '\0' only? */ ||
  		 auth_req->password_len > RHP_AUTH_REQ_MAX_PW_LEN ){
    RHP_BUG("");
    goto auth_failed;
  }

  password = (unsigned char*)( ((u8*)id) + auth_req->id_len );

  if( password[auth_req->password_len - 1] != '\0' ){
    RHP_BUG("");
    goto auth_failed;
  }

  RHP_LOCK(&(rhp_auth_lock));

  admin_info = rhp_auth_admin_get((char*)id,auth_req->id_len);
  if( admin_info == NULL ){
    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_AUTH_BASIC_REQ_INVALID_ID_NO_ADM_INFO,"s",id);
    goto auth_failed_l;
  }

  if( admin_info->hashed_key == NULL ){
    result = 1;
    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_AUTH_BASIC_REQ_REQ_OK_NO_ADM_PW,"xx",ipcmsg,ipcmsg_r);
    goto auth_no_password;
  }

  {
  	if( auth_req->password_len <= 1 ){
      RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_AUTH_BASIC_REQ_OK,"s",admin_info->id);
      goto auth_failed_l;
  	}

  	err = _rhp_auth_hashed_auth_key(admin_info->prf,id,auth_req->id_len,password,
  				auth_req->password_len,&hashed_key,&hashed_key_len);

  	if( err ){
  		RHP_BUG("");
  		goto auth_failed_l;
  	}

  	if( admin_info->hashed_key_len != hashed_key_len ||
  			memcmp(admin_info->hashed_key,hashed_key,hashed_key_len) ){

  		RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_AUTH_BASIC_REQ_NG_HASHED_PW_NOT_MATCH,"sspp",admin_info->id,password,hashed_key_len,hashed_key,admin_info->hashed_key_len,admin_info->hashed_key);
  		result = 0;

  	}else{

  		result = 1;
  		RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_AUTH_BASIC_REQ_OK,"s",admin_info->id);
  	}
  }

auth_failed_l:
auth_no_password:

	if( auth_req->vpn_realm_id != (unsigned long)-1 ){

		if( result ){

			if( admin_info->vpn_realm_id && (admin_info->vpn_realm_id != auth_req->vpn_realm_id) ){

				RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_AUTH_BASIC_REQ_NG_RLM_NOT_MATCH,"suu",admin_info->id,admin_info->vpn_realm_id,auth_req->vpn_realm_id);
				result = 0;
				err_rlm_not_matched = 1;
			}
		}
	}

	if( result ){
		rlm_id = admin_info->vpn_realm_id;
		is_nobody = admin_info->is_nobody;
	}else{
		rlm_id = 0;
		RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_AUTH_ADMIN_AUTH_FAILED,"su",id,auth_req->vpn_realm_id);
	}

  RHP_UNLOCK(&(rhp_auth_lock));
auth_failed:

  auth_rep = (rhp_ipcmsg_auth_rep*)rhp_ipc_alloc_msg(RHP_IPC_AUTH_BASIC_REPLY,sizeof(rhp_ipcmsg_auth_rep) + auth_req->id_len);
  if( auth_rep == NULL ){
    RHP_BUG("");
    goto error;
  }

  auth_rep->len = sizeof(rhp_ipcmsg_auth_rep) + auth_req->id_len;
  auth_rep->txn_id = auth_req->txn_id;
  auth_rep->result = result;
  auth_rep->vpn_realm_id = rlm_id;
  auth_rep->request_user = auth_req->request_user;
  auth_rep->is_nobody = is_nobody;

  if( auth_req->id_len && id ){
    auth_rep->id_len = auth_req->id_len;
    memcpy((u8*)(auth_rep + 1),id,auth_req->id_len);
  }else{
    auth_rep->id_len = 0;
  }

  *ipcmsg_r = (rhp_ipcmsg*)auth_rep;

  if( !result ){
  	if( err_rlm_not_matched ){
    	RHP_LOG_E(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_AUTH_ADMIN_INVALID_REALM,"su",id,auth_req->vpn_realm_id);
  	}else{
    	RHP_LOG_E(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_AUTH_ADMIN_FAILED,"su",id,auth_req->vpn_realm_id);
  	}
  }
  if( hashed_key ){
    _rhp_free_zero(hashed_key,hashed_key_len);
  }

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_AUTH_BASIC_REQ_RTRN,"xudp",ipcmsg,rlm_id,is_nobody,auth_rep->len,auth_rep);
  return 0;

error:
	RHP_LOG_E(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_AUTH_ADMIN_ERR,"suE",id,auth_req->vpn_realm_id,err);
  if( hashed_key ){
    _rhp_free_zero(hashed_key,hashed_key_len);
  }
  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_AUTH_BASIC_REQ_ERR,"xd",ipcmsg,err);
  return err;
}

int rhp_auth_sign_req_expand_mesg_octets(rhp_crypto_prf* prf,rhp_ikev2_id* my_id,int sk_p_len,u8* sk_p,
    int auth_mesg_octets_part_len,u8* auth_mesg_octets_part,int* auth_mesg_octets_len_r,u8** auth_mesg_octets_r)
{
  int err = -EINVAL;
  int auth_mesg_octets_len;
  u8* auth_mesg_octets = NULL;
  int id_octets_len;
  u8* id_octets = NULL;
  int prf_len;
  int id_type;
  int id_len;
  u8* id_val = NULL;

  RHP_TRC(0,RHPTRCID_AUTH_SIGN_REQ_EXP_MESG_OCTETS,"xxppxx",prf,my_id,sk_p_len,sk_p,auth_mesg_octets_part_len,auth_mesg_octets_part,auth_mesg_octets_len_r,auth_mesg_octets_r);

  prf_len = prf->get_output_len(prf);
  if( prf_len <= 0 ){
    RHP_BUG("");
    goto error;
  }

  auth_mesg_octets_len = auth_mesg_octets_part_len + prf_len;

  err = rhp_ikev2_id_value(my_id,&id_val,&id_len,&id_type);
  if( err ){
    RHP_TRC(0,RHPTRCID_AUTH_SIGN_REQ_EXP_MESG_OCTETS_ID_ERR,"d",err);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_AUTH_SIGN_REQ_EXP_MESG_OCTETS_ID,"dp",id_type,id_len,id_val);

  auth_mesg_octets = (u8*)_rhp_malloc(auth_mesg_octets_len);
  if( auth_mesg_octets == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
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
  	memcpy(id_octets + 4,id_val,id_len);
  }

  err = prf->set_key(prf,sk_p,sk_p_len);
  if( err ){
    RHP_TRC(0,RHPTRCID_AUTH_SIGN_REQ_EXP_MESG_OCTETS_PRF_SET_KEY_ERR,"d",err);
    goto error;
  }

  memcpy(auth_mesg_octets,auth_mesg_octets_part,auth_mesg_octets_part_len);

  err = prf->compute(prf,id_octets,id_octets_len,(auth_mesg_octets + auth_mesg_octets_part_len),prf_len);
  if( err ){
    RHP_TRC(0,RHPTRCID_AUTH_SIGN_REQ_EXP_MESG_OCTETS_PRF_COMPUTE_ERR,"d",err);
    goto error;
  }

  _rhp_free(id_val);
  _rhp_free_zero(id_octets,id_octets_len);

  *auth_mesg_octets_len_r = auth_mesg_octets_len;
  *auth_mesg_octets_r = auth_mesg_octets;

  RHP_TRC(0,RHPTRCID_AUTH_SIGN_REQ_EXP_MESG_OCTETS_RTRN,"p",*auth_mesg_octets_len_r,*auth_mesg_octets_r);
  return 0;

error:
  if( id_val ){
    _rhp_free(id_val);
  }
  if( auth_mesg_octets ){
    _rhp_free(auth_mesg_octets);
  }
  if( id_octets ){
    _rhp_free(id_octets);
  }
  RHP_TRC(0,RHPTRCID_AUTH_SIGN_REQ_EXP_MESG_OCTETS_ERR,"x",prf);
  return -EINVAL;
}

static int _rhp_auth_ipc_handle_sign_psk_req(rhp_ipcmsg *ipcmsg,
		unsigned long auth_rlm_id,rhp_ipcmsg** ipcmsg_r)
{
  int err = -EINVAL;
  rhp_ipcmsg_sign_req* sign_psk_req;
  rhp_vpn_auth_realm* auth_rlm = NULL;
  rhp_ikev2_id* my_id;
  rhp_auth_psk *my_psk,*my_psk2;
  rhp_crypto_prf* prf = NULL;
  unsigned int result = 0;
  u8* hashed_key_raw = NULL;
  u8* auth_key = NULL;
  int auth_key_len = 0;
  u8* signed_octets = NULL;
  int signed_octets_len = 0;
  u8* mesg_octets = NULL;
  int mesg_octets_len = 0;
  rhp_ipcmsg_sign_rep* sign_psk_rep;
  int reply_len = 0;
  u8* ca_cert_keys = NULL;
  int ca_cert_keys_len = 0,ca_cert_key_len = 0;
  int mesg_octets_exp_len;
  u8* mesg_octets_exp = NULL;
  u8* sk_p = NULL;
  u8* p;
  int eap_role = RHP_EAP_DISABLED;
  int eap_method = RHP_PROTO_EAP_TYPE_NONE;
  int auth_method = RHP_PROTO_IKE_AUTHMETHOD_NONE;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_PSK_REQ,"xux",ipcmsg,auth_rlm_id,ipcmsg_r);

  if( ipcmsg->len < sizeof(rhp_ipcmsg_sign_req) ){
    RHP_BUG("");
    goto error;
  }

  sign_psk_req = (rhp_ipcmsg_sign_req*)ipcmsg;

  if( sign_psk_req->mesg_octets_len == 0 ){
    RHP_BUG("");
    goto error;
  }

  if( sign_psk_req->len != sizeof(rhp_ipcmsg_sign_req) + sign_psk_req->mesg_octets_len
      + sign_psk_req->sk_p_len + sign_psk_req->ca_pubkey_dgsts_len
      + sign_psk_req->auth_tkt_session_key_len ){
    RHP_BUG("");
    goto error;
  }

  p = (u8*)( sign_psk_req + 1 );

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_PSK_REQ_PRF_METHOD,"xdd",sign_psk_req,sign_psk_req->prf_method,sign_psk_req->auth_tkt_session_key_len);

  if( rhp_auth_supported_prf_method(sign_psk_req->prf_method) ){
    RHP_BUG("%d",sign_psk_req->prf_method);
    goto error;
  }

  auth_rlm = rhp_auth_realm_get(auth_rlm_id);
  if( auth_rlm == NULL ){
    RHP_BUG("%lu",auth_rlm_id);
    goto failed;
  }

  prf  = rhp_crypto_prf_alloc(sign_psk_req->prf_method);
  if( prf == NULL ){
    RHP_BUG("");
    goto failed;
  }

  RHP_LOCK(&(auth_rlm->lock));

  if( auth_rlm->my_auth == NULL ){
  	RHP_BUG("");
    RHP_UNLOCK(&(auth_rlm->lock));
    goto failed;
  }


  my_id = &(auth_rlm->my_auth->my_id);

  if( sign_psk_req->auth_tkt_session_key_len ){

  	auth_method = RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY;

  }else{

  	auth_method = auth_rlm->my_auth->auth_method;
  }

  if( auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY &&
  		!sign_psk_req->auth_tkt_session_key_len ){

		my_psk = auth_rlm->my_auth->my_psks;
		my_psk2 = NULL;
		while( my_psk ){

			if( my_psk->prf_method == (char)sign_psk_req->prf_method && my_psk->hashed_key ){
				break;
			}

			if( my_psk2 == NULL && my_psk->key ){
				my_psk2 = my_psk;
			}

			my_psk = my_psk->next;
		}

		if( my_psk == NULL ){
			my_psk = my_psk2;
		}

		if( my_psk == NULL ){
			RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_PSK_REQ_MY_KEY_NOT_FOUND,"x",auth_rlm);
			goto failed_l;
		}

		if( my_psk->prf_method ){

			auth_key = my_psk->hashed_key;
			auth_key_len = my_psk->hashed_key_len;

		}else{

			auth_key_len = prf->get_output_len(prf);

			hashed_key_raw = (u8*)_rhp_malloc(auth_key_len);
			if( hashed_key_raw == NULL ){
				RHP_BUG("");
				goto failed_l;
			}

			if( prf->set_key(prf,my_psk->key,strlen((char*)my_psk->key)) ){
				RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_PSK_REQ_PRF_SET_KEY_ERR,"xx",auth_rlm,prf);
				goto failed_l;
			}

			if( prf->compute(prf,(unsigned char*)RHP_PROTO_IKE_AUTH_KEYPAD,strlen(RHP_PROTO_IKE_AUTH_KEYPAD),
					hashed_key_raw,auth_key_len) ){
				RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_PSK_REQ_PRF_COMPUTE_ERR,"xx",auth_rlm,prf);
				goto failed_l;
			}

			auth_key = hashed_key_raw;
		}
  }


  signed_octets_len = prf->get_output_len(prf);

  signed_octets = (u8*)_rhp_malloc(signed_octets_len);
  if( signed_octets == NULL ){
    RHP_BUG("");
    goto failed_l;
  }

  mesg_octets = p;
  p += sign_psk_req->mesg_octets_len;

  mesg_octets_len = sign_psk_req->mesg_octets_len;


  if( sign_psk_req->sk_p_len ){

    sk_p = p;
    p += sign_psk_req->sk_p_len;

    err = rhp_auth_sign_req_expand_mesg_octets(prf,my_id,sign_psk_req->sk_p_len,sk_p,mesg_octets_len,mesg_octets,
          &mesg_octets_exp_len,&mesg_octets_exp);

    if( err ){
      RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_PSK_REQ_EXP_MESG_OCTETS_ERR,"d",err);
      goto failed_l;
    }

    mesg_octets = mesg_octets_exp;
    mesg_octets_len = mesg_octets_exp_len;
  }


  if( auth_method == RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH ){

  	if( sign_psk_req->sk_p_len < 1 ){
  		RHP_BUG("");
      goto failed_l;
  	}

  	auth_key = sk_p;
  	auth_key_len = sign_psk_req->sk_p_len;

  }else if( auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY &&
  					sign_psk_req->auth_tkt_session_key_len ){

  	auth_key = p;
  	auth_key_len = sign_psk_req->auth_tkt_session_key_len;

  	p += sign_psk_req->auth_tkt_session_key_len;
  }


  if( auth_key == NULL ){
  	RHP_BUG("");
    goto failed_l;
  }

  if( prf->set_key(prf,auth_key,auth_key_len) ){
    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_PSK_REQ_PRF_SET_KEY_ERR,"xx",auth_rlm,prf);
    goto failed_l;
  }

  if( prf->compute(prf,mesg_octets,mesg_octets_len,signed_octets,signed_octets_len) ){
    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_PSK_REQ_PRF_COMPUTE_ERR,"xx",auth_rlm,prf);
    goto failed_l;
  }

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_PSK_REQ_SIGNED_DATA,"dpppd",sign_psk_req->prf_method,auth_key_len,auth_key,mesg_octets_len,mesg_octets,signed_octets_len,signed_octets,sign_psk_req->auth_tkt_session_key_len);

  if( auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY &&
  		sign_psk_req->auth_tkt_session_key_len ){

    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_PSK_REQ_CERT_DGST_NOT_NEEDED_FOR_AUTH_TKT,"xx",sign_psk_req,auth_rlm);

  }else{

    rhp_cert_store* cert_store = auth_rlm->my_auth->cert_store;
    if( cert_store ){

    	rhp_cert_store_hold(cert_store);

    	cert_store->get_ca_public_key_digests(cert_store,&ca_cert_keys,&ca_cert_keys_len,&ca_cert_key_len);

    	rhp_cert_store_unhold(cert_store);

    }else{
      RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_PSK_REQ_NO_CERT_STORE,"x",auth_rlm);
    }
  }

  result = 1;

  if( sign_psk_req->auth_tkt_session_key_len ){
  	eap_role = RHP_EAP_DISABLED;
    eap_method = RHP_PROTO_EAP_TYPE_NONE;
  }else{
		eap_role = auth_rlm->eap.role;
		eap_method = auth_rlm->eap.method;
  }

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_PSK_REQ_OK,"x",ipcmsg);

failed_l:
  RHP_UNLOCK(&(auth_rlm->lock));
failed:

  reply_len = sizeof(rhp_ipcmsg_sign_rep) + signed_octets_len + ca_cert_keys_len;

  sign_psk_rep = (rhp_ipcmsg_sign_rep*)rhp_ipc_alloc_msg(RHP_IPC_SIGN_PSK_REPLY,reply_len);
  if( sign_psk_rep == NULL ){
    RHP_BUG("");
    goto error;
  }

  sign_psk_rep->len = reply_len;
  sign_psk_rep->txn_id = sign_psk_req->txn_id;
  sign_psk_rep->my_realm_id = auth_rlm_id;
  sign_psk_rep->side = sign_psk_req->side;
  memcpy(sign_psk_rep->spi,sign_psk_req->spi,RHP_PROTO_IKE_SPI_SIZE);
  sign_psk_rep->signed_octets_len = signed_octets_len;
  sign_psk_rep->result = result;
  sign_psk_rep->ca_pubkey_dgst_len = ca_cert_key_len;
  sign_psk_rep->ca_pubkey_dgsts_len = ca_cert_keys_len;
  sign_psk_rep->auth_method = auth_method;
  sign_psk_rep->eap_role = eap_role;
  sign_psk_rep->eap_method = eap_method;

  if( result ){

    memcpy(((u8*)(sign_psk_rep + 1)),signed_octets,signed_octets_len);

    if( ca_cert_keys ){
      memcpy(((u8*)(sign_psk_rep + 1)) + signed_octets_len,ca_cert_keys,ca_cert_keys_len);
    }

    {
			sign_psk_rep->qcd_enabled = 0;
			if( sign_psk_req->qcd_enabled ){

				if( rhp_ikev2_qcd_get_my_token(sign_psk_req->side,sign_psk_req->spi,
							sign_psk_req->peer_spi,sign_psk_rep->my_qcd_token) ){

					RHP_BUG("");

				}else{
					sign_psk_rep->qcd_enabled = 1;
				}
			}
    }

  }else{
    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_PSK_REQ_NG,"x",ipcmsg);
  }

  if( signed_octets ){
    _rhp_free_zero(signed_octets,signed_octets_len);
  }

  if( prf ){
    rhp_crypto_prf_free(prf);
  }

  if( hashed_key_raw ){
    _rhp_free_zero(hashed_key_raw,auth_key_len);
  }

  if( auth_rlm ){
    rhp_auth_realm_unhold(auth_rlm);
  }

  if( ca_cert_keys ){
    _rhp_free(ca_cert_keys);
  }

  if( mesg_octets_exp ){
    _rhp_free_zero(mesg_octets_exp,mesg_octets_exp_len);
  }

  *ipcmsg_r = (rhp_ipcmsg*)sign_psk_rep;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_PSK_REQ_RTRN,"xp",ipcmsg,sign_psk_rep->len,sign_psk_rep);
  return 0;

error:
  if( auth_rlm ){
    rhp_auth_realm_unhold(auth_rlm);
  }
  if( prf ){
    rhp_crypto_prf_free(prf);
  }
  if( hashed_key_raw ){
    _rhp_free_zero(hashed_key_raw,auth_key_len);
  }
  if( signed_octets ){
    _rhp_free_zero(signed_octets,signed_octets_len);
  }
  if( ca_cert_keys ){
    _rhp_free(ca_cert_keys);
  }
  if( mesg_octets_exp ){
    _rhp_free_zero(mesg_octets_exp,mesg_octets_exp_len);
  }
  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_PSK_REQ_ERR,"xd",ipcmsg,err);
  return err;
}

static int _rhp_auth_ipc_handle_sign_eap_sup_req(rhp_ipcmsg *ipcmsg,unsigned long auth_rlm_id,rhp_ipcmsg** ipcmsg_r)
{
  int err = -EINVAL;
  rhp_ipcmsg_sign_req* sign_req;
  rhp_vpn_auth_realm* auth_rlm = NULL;
  unsigned int result = 0;
  rhp_ipcmsg_sign_rep* sign_rep;
  int reply_len = 0;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_EAP_SUP_REQ,"xux",ipcmsg,auth_rlm_id,ipcmsg_r);

  if( ipcmsg->len < sizeof(rhp_ipcmsg_sign_req) ){
    RHP_BUG("");
    goto error;
  }

  sign_req = (rhp_ipcmsg_sign_req*)ipcmsg;

  if( sign_req->mesg_octets_len == 0 ){
    RHP_BUG("");
    goto error;
  }

  if( sign_req->len != sizeof(rhp_ipcmsg_sign_req) + sign_req->mesg_octets_len
      + sign_req->sk_p_len + sign_req->ca_pubkey_dgsts_len ){
    RHP_BUG("");
    goto error;
  }

  if( rhp_auth_supported_prf_method(sign_req->prf_method) ){
    RHP_BUG("%d",sign_req->prf_method);
    goto error;
  }

  auth_rlm = rhp_auth_realm_get(auth_rlm_id);
  if( auth_rlm == NULL ){
    RHP_BUG("%lu",auth_rlm_id);
    goto failed;
  }

  RHP_LOCK(&(auth_rlm->lock));

  result = 1;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_EAP_SUP_REQ_OK,"x",ipcmsg);

  RHP_UNLOCK(&(auth_rlm->lock));
failed:

  reply_len = sizeof(rhp_ipcmsg_sign_rep);

  sign_rep = (rhp_ipcmsg_sign_rep*)rhp_ipc_alloc_msg(RHP_IPC_SIGN_PSK_REPLY,reply_len);
  if( sign_rep == NULL ){
    RHP_BUG("");
    goto error;
  }

  sign_rep->len = reply_len;
  sign_rep->txn_id = sign_req->txn_id;
  sign_rep->my_realm_id = auth_rlm_id;
  sign_rep->side = sign_req->side;
  memcpy(sign_rep->spi,sign_req->spi,RHP_PROTO_IKE_SPI_SIZE);
  sign_rep->signed_octets_len = 0;
  sign_rep->result = result;
  sign_rep->eap_role = RHP_EAP_SUPPLICANT;
  sign_rep->ca_pubkey_dgst_len = 0;
  sign_rep->ca_pubkey_dgsts_len = 0;
  sign_rep->auth_method = 0;

  if( result ){

  	sign_rep->qcd_enabled = 0;
    if( sign_req->qcd_enabled ){

    	if( rhp_ikev2_qcd_get_my_token(sign_req->side,sign_req->spi,
    			sign_req->peer_spi,sign_rep->my_qcd_token) ){

    		RHP_BUG("");

    	}else{
    		sign_rep->qcd_enabled = 1;
    	}
    }
  }

  if( auth_rlm ){
    rhp_auth_realm_unhold(auth_rlm);
  }

  *ipcmsg_r = (rhp_ipcmsg*)sign_rep;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_EAP_SUP_REQ_RTRN,"xxdE",ipcmsg,sign_rep,result,err);
  return 0;

error:
  if( auth_rlm ){
    rhp_auth_realm_unhold(auth_rlm);
  }
  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_EAP_SUP_REQ_ERR,"xE",ipcmsg,err);
  return err;
}


static int _rhp_auth_ipc_handle_verify_psk_req(rhp_ipcmsg *ipcmsg,rhp_ipcmsg** ipcmsg_r,
		int* my_auth_method_r,unsigned long* auth_rlm_id_r)
{
  int err = -EINVAL;
  rhp_ipcmsg_verify_req* verify_psk_req;
  rhp_vpn_auth_realm* auth_rlm = NULL;
  rhp_ikev2_id my_id,peer_id;
  char* id_string = NULL;
  rhp_auth_psk *peer_psk,*peer_psk2;
  rhp_crypto_prf* prf = NULL;
  unsigned int result = 0;
  u8* hashed_key_raw = NULL;
  u8* auth_key = NULL;
  int auth_key_len = 0;
  u8* peer_signed_octets = NULL;
  int peer_signed_octets_len = 0;
  u8* mesg_octets = NULL;
  rhp_ipcmsg_verify_rep* verify_psk_rep;
  int reply_len = 0;
  u8* peer_signed_octets_r = NULL;
  unsigned long auth_rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  u8* p;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_PSK_REQ,"xxxx",ipcmsg,ipcmsg_r,my_auth_method_r,auth_rlm_id_r);

  memset(&my_id,0,sizeof(rhp_ikev2_id));
  memset(&peer_id,0,sizeof(rhp_ikev2_id));

  if( ipcmsg->len < sizeof(rhp_ipcmsg_verify_req) ){
    RHP_BUG("");
    goto error;
  }

  verify_psk_req = (rhp_ipcmsg_verify_req*)ipcmsg;

  if( verify_psk_req->peer_id_len == 0 ||
      verify_psk_req->mesg_octets_len == 0 ||
      verify_psk_req->signature_octets_len == 0 ){
    RHP_BUG("");
    goto error;
  }

  if( verify_psk_req->len != sizeof(rhp_ipcmsg_verify_req)
  		+ verify_psk_req->my_id_len + verify_psk_req->peer_id_len
  		+ verify_psk_req->mesg_octets_len + verify_psk_req->signature_octets_len
  		+ verify_psk_req->ikev2_null_auth_sk_px_len + verify_psk_req->auth_tkt_session_key_len ){
    RHP_BUG("");
    goto error;
  }

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_PSK_REQ_PRF_METHOD,"xdd",verify_psk_req,verify_psk_req->prf_method,verify_psk_req->auth_tkt_session_key_len);

  if( rhp_auth_supported_prf_method(verify_psk_req->prf_method) ){
    RHP_BUG("%d",verify_psk_req->prf_method);
    goto error;
  }


  p = (u8*)( verify_psk_req + 1 );

  if( verify_psk_req->my_id_len ){

    my_id.type = verify_psk_req->my_id_type;

    switch( my_id.type ){

      case RHP_PROTO_IKE_ID_FQDN:
      case RHP_PROTO_IKE_ID_RFC822_ADDR:

        id_string = (char*)p;
        if( id_string[verify_psk_req->my_id_len - 1] != '\0' ){
          RHP_BUG("");
          goto failed;
        }
        my_id.string = id_string;
        p += verify_psk_req->my_id_len;

        RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_PSK_REQ_MY_ID,"ds",my_id.type,my_id.string);
        break;

      case RHP_PROTO_IKE_ID_NULL_ID:

      	if( verify_psk_req->my_id_len ){
      		RHP_BUG("%d",verify_psk_req->my_id_len);
      		goto failed;
      	}

      	my_id.type = RHP_PROTO_IKE_ID_NULL_ID;

        RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_PSK_REQ_MY_ID_NULL,"d",my_id.type);
      	break;

      case RHP_PROTO_IKE_ID_PRIVATE_NULL_ID_WITH_ADDR:

      	if( verify_psk_req->my_id_len != sizeof(rhp_ip_addr) ){
      		RHP_BUG("%d",verify_psk_req->my_id_len);
      		goto failed;
      	}

      	memcpy(&(my_id.addr),p,verify_psk_req->my_id_len);
      	p += verify_psk_req->my_id_len;

      	my_id.type = RHP_PROTO_IKE_ID_NULL_ID; // Address value is not interested here.

        RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_PSK_REQ_MY_ID_NULL_WITH_ADDR,"dp",my_id.type,sizeof(rhp_ip_addr),&(my_id.addr));
        rhp_ip_addr_dump("my_id.addr",&(my_id.addr));
        break;

      default:
        RHP_BUG("%d",my_id.type);
        goto failed;
    }
  }

  if( verify_psk_req->peer_id_len ){

    peer_id.type = verify_psk_req->peer_id_type;

    switch( peer_id.type ){

      case RHP_PROTO_IKE_ID_FQDN:
      case RHP_PROTO_IKE_ID_RFC822_ADDR:

        id_string = (char*)p;
        if( id_string[verify_psk_req->peer_id_len - 1] != '\0' ){
          RHP_BUG("");
          goto failed;
        }
        peer_id.string = id_string;
        p += verify_psk_req->peer_id_len;

        RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_PSK_REQ_PEER_ID,"ds",peer_id.type,peer_id.string);
        break;

      case RHP_PROTO_IKE_ID_NULL_ID:

      	if( verify_psk_req->peer_id_len ){
      		RHP_BUG("%d",verify_psk_req->peer_id_len);
      		goto failed;
      	}

      	peer_id.type = RHP_PROTO_IKE_ID_NULL_ID;

        RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_PSK_REQ_PEER_ID_NULL,"d",peer_id.type);
      	break;

      case RHP_PROTO_IKE_ID_PRIVATE_NULL_ID_WITH_ADDR:

      	if( verify_psk_req->peer_id_len != sizeof(rhp_ip_addr) ){
      		RHP_BUG("%d",verify_psk_req->peer_id_len);
      		goto failed;
      	}

      	memcpy(&(peer_id.addr),p,verify_psk_req->peer_id_len);
      	p += verify_psk_req->peer_id_len;

      	peer_id.type = RHP_PROTO_IKE_ID_NULL_ID; // Adddress is not interested here.

        RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_PSK_REQ_PEER_ID_NULL_WITH_ADDR,"dp",peer_id.type,sizeof(rhp_ip_addr),&(peer_id.addr));
        rhp_ip_addr_dump("peer_id.addr",&(peer_id.addr));
        break;

      default:
        RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_PSK_REQ_PEER_ID_UNKNOWN,"d",peer_id.type);
      	RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_VERIFY_PSK_RX_INVALID_PEER_ID_TYPE,"d",peer_id.type);
        goto failed;
    }
  }

  if( verify_psk_req->my_realm_id != RHP_VPN_REALM_ID_UNKNOWN ){

    auth_rlm = rhp_auth_realm_get(verify_psk_req->my_realm_id);

  }else{

  	auth_rlm = rhp_auth_realm_get_by_role((verify_psk_req->my_id_len ? &my_id : NULL),
  			RHP_PEER_ID_TYPE_IKEV2,(void*)&peer_id,NULL,1,verify_psk_req->peer_notified_realm_id);
  }

  if( auth_rlm == NULL ){

  	RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_PSK_REQ_RLM_NOT_FOUND,"u",verify_psk_req->my_realm_id);
  	RHP_LOG_E(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_VERIFY_PSK_REALM_NOT_DEFINED,"II",&my_id,&peer_id);

  	goto failed;
  }

  auth_rlm_id = auth_rlm->id;


	if( verify_psk_req->auth_tkt_session_key_len &&
			verify_psk_req->auth_tkt_hb2spk_realm_id != auth_rlm_id ){

		RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_PSK_REQ_AUTH_TKT_RLM_NOT_MATCHED,"uuu",auth_rlm_id,verify_psk_req->my_realm_id,verify_psk_req->auth_tkt_hb2spk_realm_id);
		RHP_LOG_E(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_VERIFY_PSK_AUTH_TKT_REALM_NOT_MATCHED,"IIuu",&my_id,&peer_id,auth_rlm_id,verify_psk_req->auth_tkt_hb2spk_realm_id);

		goto failed;
	}


  prf  = rhp_crypto_prf_alloc(verify_psk_req->prf_method);
  if( prf == NULL ){
    RHP_BUG("");
    goto failed;
  }


  RHP_LOCK(&(auth_rlm->lock));

  if( verify_psk_req->peer_auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ){

		if( verify_psk_req->auth_tkt_session_key_len ){

			if( !auth_rlm->auth_tkt_enabled ){

				RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_AUTH_TKT_NOT_ALLOWED,"u",verify_psk_req->my_realm_id);
				RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_VERIFY_AUTH_TKT_NOT_ALLOWED,"II",&my_id,&peer_id);

				goto failed_l;

			}

  	}else if( !auth_rlm->psk_for_peers ){

			RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_PSK_NOT_ALLOWED,"u",verify_psk_req->my_realm_id);
			RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_VERIFY_PSK_NOT_ALLOWED,"II",&my_id,&peer_id);

			goto failed_l;
  	}

  }else if( verify_psk_req->peer_auth_method == RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH ){

  	if( !auth_rlm->null_auth_for_peers ){

			RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_NULL_AUTH_NOT_ALLOWED,"u",verify_psk_req->my_realm_id);
			RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_NULL_AUTH_NOT_ALLOWED,"II",&my_id,&peer_id);

			goto failed_l;
		}

  }else{

  	RHP_BUG("%d",verify_psk_req->peer_auth_method);
		goto failed_l;
  }


  if( verify_psk_req->peer_auth_method == RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH ){

  	if( verify_psk_req->ikev2_null_auth_sk_px_len < 1 ){
  		RHP_BUG("");
			goto failed_l;
  	}

		auth_key = p;
		p += verify_psk_req->ikev2_null_auth_sk_px_len;
		auth_key_len = verify_psk_req->ikev2_null_auth_sk_px_len;

  }else{ // PSK

  	if( verify_psk_req->auth_tkt_session_key_len < 1 ){

			rhp_auth_peer* auth_peer
				= auth_rlm->get_peer_by_id(auth_rlm,RHP_PEER_ID_TYPE_IKEV2,(void*)&peer_id);
			if( auth_peer == NULL ){
				RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_PSK_REQ_GET_PEER_BY_ID_ERR,"x",auth_rlm);
				RHP_LOG_DE(RHP_LOG_SRC_AUTH,auth_rlm->id,RHP_LOG_ID_PEER_PSK_NOT_DEFINED,"I",&peer_id);
				goto failed_l;
			}

			peer_psk = auth_peer->peer_psks;
			peer_psk2 = NULL;

			while( peer_psk ){

				if( peer_psk->prf_method == (char)verify_psk_req->prf_method && peer_psk->hashed_key ){
					break;
				}

				if( peer_psk2 == NULL && peer_psk->key ){
					peer_psk2 = peer_psk;
				}

				peer_psk = peer_psk->next;
			}

			if( peer_psk == NULL ){
				peer_psk = peer_psk2;
			}

			if( peer_psk == NULL ){
				RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_PSK_REQ_PEER_PSK_NULL,"x",auth_rlm);
				RHP_LOG_DE(RHP_LOG_SRC_AUTH,auth_rlm->id,RHP_LOG_ID_NO_PEER_PSK_FOUND,"I",&peer_id);
				goto failed_l;
			}

			if( peer_psk->prf_method ){

				auth_key = peer_psk->hashed_key;
				auth_key_len = peer_psk->hashed_key_len;

			}else{

				auth_key_len = prf->get_output_len(prf);

				hashed_key_raw = (u8*)_rhp_malloc(auth_key_len);
				if( hashed_key_raw == NULL ){
					RHP_BUG("");
					goto failed_l;
				}

				if( prf->set_key(prf,peer_psk->key,strlen((char*)peer_psk->key)) ){
					RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_PSK_REQ_PRF_SET_KEY_ERR,"xx",auth_rlm,prf);
					goto failed_l;
				}

				if( prf->compute(prf,(unsigned char*)RHP_PROTO_IKE_AUTH_KEYPAD,strlen(RHP_PROTO_IKE_AUTH_KEYPAD),
						hashed_key_raw,auth_key_len) ){
					RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_PSK_REQ_PRF_COMPUTE_ERR,"xx",auth_rlm,prf);
					goto failed_l;
				}

				auth_key = hashed_key_raw;
			}
  	}
  }


  mesg_octets = p;
  p += verify_psk_req->mesg_octets_len;

  peer_signed_octets_r = p;
  p += verify_psk_req->signature_octets_len;


  if( verify_psk_req->auth_tkt_session_key_len ){
  	auth_key = p;
  	auth_key_len = verify_psk_req->auth_tkt_session_key_len;
  	p += verify_psk_req->auth_tkt_session_key_len;
  }


  if( auth_key == NULL ){
  	RHP_BUG("");
  	goto failed_l;
  }

  if( prf->set_key(prf,auth_key,auth_key_len) ){
    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_PSK_REQ_PRF_SET_KEY_ERR,"xx",auth_rlm,prf);
    goto failed_l;
  }

  peer_signed_octets_len = prf->get_output_len(prf);

  peer_signed_octets = (u8*)_rhp_malloc(peer_signed_octets_len);
  if( peer_signed_octets == NULL ){
    RHP_BUG("");
    goto failed_l;
  }

  if( prf->compute(prf,mesg_octets,verify_psk_req->mesg_octets_len,peer_signed_octets,peer_signed_octets_len) ){
    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_PSK_REQ_PRF_COMPUTE_ERR,"xx",auth_rlm,prf);
    goto failed_l;
  }

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_PSK_REQ_SIGNED_DATA,"dpppd",verify_psk_req->prf_method,auth_key_len,auth_key,verify_psk_req->mesg_octets_len,mesg_octets,peer_signed_octets_len,peer_signed_octets,verify_psk_req->auth_tkt_session_key_len);

  if( peer_signed_octets_len == (int)verify_psk_req->signature_octets_len &&
      !memcmp(peer_signed_octets,peer_signed_octets_r,peer_signed_octets_len) ){

    result = 1;

    if( my_auth_method_r ){
    	*my_auth_method_r = auth_rlm->my_auth->auth_method;
    }

    if( auth_rlm_id_r ){
      *auth_rlm_id_r = auth_rlm_id;
    }

    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_PSK_REQ_OK,"dd",auth_rlm->my_auth->auth_method,auth_rlm_id);

  }else{

  	RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_PSK_REQ_NG,"dd",auth_rlm->my_auth->auth_method,auth_rlm_id);

  	if( !verify_psk_req->auth_tkt_session_key_len ){
  		RHP_LOG_E(RHP_LOG_SRC_AUTH,auth_rlm->id,RHP_LOG_ID_INVALID_PEER_PSK,"I",&peer_id);
  	}else{
  		RHP_LOG_E(RHP_LOG_SRC_AUTH,auth_rlm->id,RHP_LOG_ID_AUTH_TKT_INVALID_PEER_SESSION_KEY,"I",&peer_id);
  	}
  }

failed_l:
  RHP_UNLOCK(&(auth_rlm->lock));
failed:

  reply_len = sizeof(rhp_ipcmsg_verify_rep);

  verify_psk_rep = (rhp_ipcmsg_verify_rep*)rhp_ipc_alloc_msg(RHP_IPC_VERIFY_PSK_REPLY,reply_len);
  if( verify_psk_rep == NULL ){
    RHP_BUG("");
    goto error;
  }

  verify_psk_rep->len = reply_len;
  verify_psk_rep->txn_id = verify_psk_req->txn_id;
  verify_psk_rep->my_realm_id = auth_rlm_id;
  verify_psk_rep->side = verify_psk_req->side;
  memcpy(verify_psk_rep->spi,verify_psk_req->spi,RHP_PROTO_IKE_SPI_SIZE);
  verify_psk_rep->result = result;

  if( !result && my_auth_method_r ){
    *my_auth_method_r = RHP_PROTO_IKE_AUTHMETHOD_NONE; // Dummy!
  }

  if( peer_signed_octets ){
    _rhp_free_zero(peer_signed_octets,peer_signed_octets_len);
  }

  if( prf ){
    rhp_crypto_prf_free(prf);
  }

  if( hashed_key_raw ){
    _rhp_free_zero(hashed_key_raw,auth_key_len);
  }

  if( auth_rlm ){
    rhp_auth_realm_unhold(auth_rlm);
  }

  *ipcmsg_r = (rhp_ipcmsg*)verify_psk_rep;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_PSK_REQ_RTRN,"xp",ipcmsg,verify_psk_rep->len,verify_psk_rep);
  return 0;

error:
  if( auth_rlm ){
    rhp_auth_realm_unhold(auth_rlm);
  }
  if( prf ){
    rhp_crypto_prf_free(prf);
  }
  if( hashed_key_raw ){
    _rhp_free_zero(hashed_key_raw,auth_key_len);
  }
  if( peer_signed_octets ){
    _rhp_free_zero(peer_signed_octets,peer_signed_octets_len);
  }
  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_PSK_REQ_ERR,"xd",ipcmsg,err);
  return err;
}

static int _rhp_auth_ipc_handle_verify_eap_sup_req(rhp_ipcmsg *ipcmsg,
		rhp_ipcmsg** ipcmsg_r,int* my_auth_method_r,unsigned long* auth_rlm_id_r)
{
  int err = -EINVAL;
  rhp_ipcmsg_verify_req* verify_psk_req;
  rhp_vpn_auth_realm* auth_rlm = NULL;
  rhp_ikev2_id my_id,peer_id;
  char* id_string = NULL;
  unsigned int result = 0;
  rhp_ipcmsg_verify_rep* verify_psk_rep;
  int reply_len = 0;
  unsigned long auth_rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  u8* p;
  int eap_method = RHP_PROTO_EAP_TYPE_NONE;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_EAP_SUP_REQ,"xxxx",ipcmsg,ipcmsg_r,my_auth_method_r,auth_rlm_id_r);

  memset(&my_id,0,sizeof(rhp_ikev2_id));
  memset(&peer_id,0,sizeof(rhp_ikev2_id));

  if( ipcmsg->len < sizeof(rhp_ipcmsg_verify_req) ){
    RHP_BUG("");
    goto error;
  }

  verify_psk_req = (rhp_ipcmsg_verify_req*)ipcmsg;

  if( verify_psk_req->peer_id_len == 0 ){
    RHP_BUG("");
    goto error;
  }

  if( verify_psk_req->len != sizeof(rhp_ipcmsg_verify_req) + verify_psk_req->my_id_len
      + verify_psk_req->peer_id_len + verify_psk_req->mesg_octets_len + verify_psk_req->signature_octets_len ){
    RHP_BUG("");
    goto error;
  }

  p = (u8*)( verify_psk_req + 1 );

  if( verify_psk_req->my_id_len ){

    my_id.type = verify_psk_req->my_id_type;

    switch( my_id.type ){

      case RHP_PROTO_IKE_ID_FQDN:
      case RHP_PROTO_IKE_ID_RFC822_ADDR:

        id_string = (char*)p;
        if( id_string[verify_psk_req->my_id_len - 1] != '\0' ){
          RHP_BUG("");
          goto failed;
        }
        my_id.string = id_string;
        p += verify_psk_req->my_id_len;

        RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_EAP_SUP_REQ_MY_ID,"ds",my_id.type,my_id.string);
        break;

      default:
        RHP_BUG("%d",my_id.type);
        goto failed;
    }

    rhp_ikev2_id_dump("verify_psk_req->my_id",&my_id);
  }

  if( verify_psk_req->peer_id_len ){

    peer_id.type = verify_psk_req->peer_id_type;

    switch( peer_id.type ){

      case RHP_PROTO_IKE_ID_FQDN:
      case RHP_PROTO_IKE_ID_RFC822_ADDR:

        id_string = (char*)p;
        if( id_string[verify_psk_req->peer_id_len - 1] != '\0' ){
          RHP_BUG("");
          goto failed;
        }
        peer_id.string = id_string;
        p += verify_psk_req->peer_id_len;

        RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_EAP_SUP_REQ_PEER_ID,"ds",peer_id.type,peer_id.string);
        break;

      case RHP_PROTO_IKE_ID_IPV4_ADDR:

      	if( verify_psk_req->peer_id_len != 4){
      		RHP_BUG("%d",verify_psk_req->peer_id_len);
          goto failed;
      	}

      	peer_id.addr.addr_family = AF_INET;
      	memcpy(peer_id.addr.addr.raw,p,verify_psk_req->peer_id_len);
        break;

      case RHP_PROTO_IKE_ID_IPV6_ADDR:

      	if( verify_psk_req->peer_id_len != 16){
      		RHP_BUG("%d",verify_psk_req->peer_id_len);
          goto failed;
      	}

      	peer_id.addr.addr_family = AF_INET6;
      	memcpy(peer_id.addr.addr.raw,p,verify_psk_req->peer_id_len);
        break;

      default:
        RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_EAP_SUP_REQ_PEER_ID_UNKNOWN,"d",peer_id.type);
      	RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_VERIFY_EAP_SUP_RX_INVALID_PEER_ID_TYPE,"d",peer_id.type);
        goto failed;
    }

    rhp_ikev2_id_dump("verify_psk_req->peer_id",&peer_id);
  }


  if( verify_psk_req->my_realm_id != RHP_VPN_REALM_ID_UNKNOWN ){

    auth_rlm = rhp_auth_realm_get(verify_psk_req->my_realm_id);

  }else{

  	auth_rlm = rhp_auth_realm_get_by_role((verify_psk_req->my_id_len ? &my_id : NULL),
  			RHP_PEER_ID_TYPE_IKEV2,(void*)&peer_id,NULL,0,verify_psk_req->peer_notified_realm_id);

    if( auth_rlm == NULL ){

    	auth_rlm = rhp_auth_realm_get_def_eap_server((verify_psk_req->my_id_len ? &my_id : NULL),
    							verify_psk_req->peer_notified_realm_id);
    	if( auth_rlm ){
      	RHP_LOG_D(RHP_LOG_SRC_AUTH,auth_rlm->id,RHP_LOG_ID_VERIFY_EAP_SUP_DEF_EAP_SERVER_USED,"IIu",&my_id,&peer_id,auth_rlm->id);
    	}else{
      	RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_VERIFY_EAP_SUP_NO_DEF_EAP_SERVER,"II",&my_id,&peer_id);
    	}
  	}
  }

  if( auth_rlm == NULL ){

  	RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_EAP_SUP_REQ_RLM_NOT_FOUND,"u",verify_psk_req->my_realm_id);
  	RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_VERIFY_EAP_SUP_REALM_NOT_DEFINED,"II",&my_id,&peer_id);

  	goto failed;

  }else{

    if( !auth_rlm->eap_for_peers ){

    	RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_EAP_SUP_NOT_ALLOWED,"u",verify_psk_req->my_realm_id);
    	RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_VERIFY_EAP_SUP__NOT_ALLOWED,"II",&my_id,&peer_id);

    	goto failed;
    }

  	RHP_LOG_D(RHP_LOG_SRC_AUTH,auth_rlm->id,RHP_LOG_ID_VERIFY_EAP_SUP_REALM_FOUND,"II",&my_id,&peer_id);
  }


  auth_rlm_id = auth_rlm->id;


  RHP_LOCK(&(auth_rlm->lock));

  if( auth_rlm->eap.role == RHP_EAP_AUTHENTICATOR ){
  	result = 1;
  }

  if( result ){

		if( my_auth_method_r ){
			*my_auth_method_r = auth_rlm->my_auth->auth_method;
		}

		if( auth_rlm_id_r ){
			*auth_rlm_id_r = auth_rlm_id;
		}

		eap_method = auth_rlm->eap.method;
  }

  RHP_UNLOCK(&(auth_rlm->lock));
failed:

  reply_len = sizeof(rhp_ipcmsg_verify_rep);

  verify_psk_rep = (rhp_ipcmsg_verify_rep*)rhp_ipc_alloc_msg(RHP_IPC_EAP_SUP_VERIFY_REPLY,reply_len);
  if( verify_psk_rep == NULL ){
    RHP_BUG("");
    goto error;
  }

  verify_psk_rep->len = reply_len;
  verify_psk_rep->txn_id = verify_psk_req->txn_id;
  verify_psk_rep->my_realm_id = auth_rlm_id;
  verify_psk_rep->side = verify_psk_req->side;
  memcpy(verify_psk_rep->spi,verify_psk_req->spi,RHP_PROTO_IKE_SPI_SIZE);
  verify_psk_rep->result = result;
  verify_psk_rep->eap_role = RHP_EAP_AUTHENTICATOR;
  verify_psk_rep->eap_method = eap_method;


  if( auth_rlm ){
    rhp_auth_realm_unhold(auth_rlm);
  }

  if( !result && my_auth_method_r ){
    *my_auth_method_r = RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY; // Dummy!
  }

  *ipcmsg_r = (rhp_ipcmsg*)verify_psk_rep;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_EAP_SUP_REQ_RTRN,"xxdxdu",ipcmsg,auth_rlm,result,*ipcmsg_r,*my_auth_method_r,*auth_rlm_id_r);
  return 0;

error:
  if( auth_rlm ){
    rhp_auth_realm_unhold(auth_rlm);
  }
  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_EAP_SUP_REQ_ERR,"xxE",ipcmsg,auth_rlm,err);
  return err;
}

static int _rhp_auth_ipc_handle_ca_keys_req(rhp_ipcmsg *ipcmsg,rhp_ipcmsg** ipcmsg_r)
{
  int err = -EINVAL;
  rhp_ipcmsg_ca_keys_req* ca_keys_req;
  rhp_vpn_auth_realm* auth_rlm = NULL;
  rhp_cert_store* cert_store = NULL;
  unsigned int result = 0;
  u8* ca_cert_keys = NULL;
  int ca_cert_keys_len = 0,ca_cert_key_len = 0;
  rhp_ipcmsg_ca_keys_rep* ca_keys_rep;
  int reply_len = 0;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_CA_KEYS_REQ,"xx",ipcmsg,ipcmsg_r);

  if( ipcmsg->len < sizeof(rhp_ipcmsg_ca_keys_req) ){
    RHP_BUG("");
    goto error;
  }

  ca_keys_req = (rhp_ipcmsg_ca_keys_req*)ipcmsg;

  auth_rlm = rhp_auth_realm_get(ca_keys_req->my_realm_id);
  if( auth_rlm == NULL ){
    RHP_BUG("%lu",ca_keys_req->my_realm_id);
    goto failed;
  }

  RHP_LOCK(&(auth_rlm->lock));

  cert_store = auth_rlm->my_auth->cert_store;

  if( cert_store ){
  	rhp_cert_store_hold(cert_store);
  }

  RHP_UNLOCK(&(auth_rlm->lock));

  if( cert_store ){

  	err = cert_store->get_ca_public_key_digests(cert_store,&ca_cert_keys,&ca_cert_keys_len,&ca_cert_key_len);
  	if( err ){
  		RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_CA_KEYS_REQ_GET_PUBKEY_DIG_ERR,"d",err);
  		goto failed;
  	}

  }else{
    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_CA_KEYS_REQ_NO_CERT_STORE,"xxu",ipcmsg,auth_rlm,auth_rlm->id);
  	goto failed;
  }

  result = 1;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_CA_KEYS_REQ_OK,"x",ipcmsg);

failed:

  reply_len = sizeof(rhp_ipcmsg_ca_keys_rep) + ca_cert_keys_len;

  ca_keys_rep = (rhp_ipcmsg_ca_keys_rep*)rhp_ipc_alloc_msg(RHP_IPC_CA_PUBKEY_DIGESTS_REPLY,reply_len);
  if( ca_keys_rep == NULL ){
    RHP_BUG("");
    goto error;
  }

  ca_keys_rep->len = reply_len;
  ca_keys_rep->txn_id = ca_keys_req->txn_id;
  ca_keys_rep->result = result;
  ca_keys_rep->ca_pubkey_dgst_len = ca_cert_key_len;
  ca_keys_rep->ca_pubkey_dgsts_len = ca_cert_keys_len;
  ca_keys_rep->side = ca_keys_req->side;
  memcpy(ca_keys_rep->spi,ca_keys_req->spi,RHP_PROTO_IKE_SPI_SIZE);

  if( result ){

  	if( ca_cert_keys ){
      memcpy((ca_keys_rep + 1),ca_cert_keys,ca_cert_keys_len);
    }

  }else{
    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_CA_KEYS_REQ_NG,"x",ipcmsg);
  }

  if( cert_store ){
    rhp_cert_store_unhold(cert_store);
  }

  if( auth_rlm ){
    rhp_auth_realm_unhold(auth_rlm);
  }

  if( ca_cert_keys ){
    _rhp_free(ca_cert_keys);
  }

  *ipcmsg_r = (rhp_ipcmsg*)ca_keys_rep;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_CA_KEYS_REQ_RTRN,"xp",ipcmsg,ca_keys_rep->len,ca_keys_rep);
  return 0;

error:
  if( ca_cert_keys ){
    _rhp_free(ca_cert_keys);
  }
  if( cert_store ){
    rhp_cert_store_unhold(cert_store);
  }
  if( auth_rlm ){
    rhp_auth_realm_unhold(auth_rlm);
  }
  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_CA_KEYS_REQ_ERR,"xd",ipcmsg,err);
  return err;
}


int rhp_auth_ipc_handle_sign_rsasig_req_cb_enum_certs_cb(rhp_cert_store* cert_store,
		int is_user_cert,u8* der,int der_len,rhp_cert_dn* cert_dn,void* ctx)
{
	int err = -EINVAL;
  rhp_auth_ipc_sign_rsasig_enum_certs_ctx* cb_ctx = (rhp_auth_ipc_sign_rsasig_enum_certs_ctx*)ctx;
  rhp_cert_data* cert_data = (rhp_cert_data*)(cb_ctx->certs_bin_curp);
  rhp_vpn_auth_realm* auth_rlm = cb_ctx->auth_rlm;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_CB_ENUM_CERTS_CB,"xdpxxx",cert_store,is_user_cert,der_len,der,cert_dn,ctx,auth_rlm);

  RHP_LOCK(&(auth_rlm->lock));
  {
  	rhp_cert_url* cert_url = NULL;

  	if( cb_ctx->http_cert_lookup_supported ){

  		cert_url = auth_rlm->my_auth->cert_urls;
			while( cert_url ){

				if( cert_dn && cert_url->cert_dn &&
						!cert_url->cert_dn->compare(cert_url->cert_dn,cert_dn) ){
					break;
				}

				cert_url = cert_url->next;
			}
  	}

  	if( cert_url == NULL ){

  	  if( cb_ctx->certs_bin_len + der_len + (int)sizeof(rhp_cert_data) > cb_ctx->certs_bin_max_len ){
  	    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_CB_ENUM_CERTS_CB_ERR,"xdddd",cert_store,cb_ctx->certs_bin_len,der_len,sizeof(rhp_cert_data),cb_ctx->certs_bin_max_len);
  	    err = -EMSGSIZE;
  	    goto error;
  	  }

  	  cert_data->type = RHP_CERT_DATA_DER;
  		cert_data->len = sizeof(rhp_cert_data) + der_len;
  		memcpy((cert_data + 1),der,der_len);

  	  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_CB_ENUM_CERTS_CB_DER_DATA,"xxp",cert_store,ctx,cert_data->len,cert_data);

  	}else{

  		int url_len = strlen(cert_url->url);
  		u8* cert_hash = NULL;
  		int cert_hash_len = 0;

  	  if( cb_ctx->certs_bin_len + RHP_IKEV2_CERT_HASH_LEN + url_len + (int)sizeof(rhp_cert_data) > cb_ctx->certs_bin_max_len ){
  	    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_CB_ENUM_CERTS_CB_ERR2,"xddddd",cert_store,cb_ctx->certs_bin_len,RHP_IKEV2_CERT_HASH_LEN,url_len,sizeof(rhp_cert_data),cb_ctx->certs_bin_max_len);
  	    err = -EMSGSIZE;
  	    goto error;
  	  }

  	  err = rhp_crypto_md(RHP_CRYPTO_MD_SHA1,der,der_len,&cert_hash,&cert_hash_len);
  	  if( err ){
  	  	RHP_BUG("%d",err);
  	  	goto error;
  	  }

  	  cert_data->type = RHP_CERT_DATA_HASH_URL;
  		cert_data->len = sizeof(rhp_cert_data) + cert_hash_len + url_len;
  		memcpy((cert_data + 1),cert_hash,cert_hash_len);
  		memcpy((((u8*)(cert_data + 1)) + cert_hash_len),cert_url->url,url_len);

  	  _rhp_free(cert_hash);

  	  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_CB_ENUM_CERTS_CB_HASH_URL_DATA,"xxp",cert_store,ctx,cert_data->len,cert_data);
  	}

  	cb_ctx->certs_bin_curp += cert_data->len;
		cb_ctx->certs_bin_len += cert_data->len;
		if( cb_ctx->my_cert == 0 ){
			cb_ctx->my_cert = is_user_cert;
		}
		cb_ctx->cert_chain_num++;

  }
  RHP_UNLOCK(&(auth_rlm->lock));

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_CB_ENUM_CERTS_CB_RTRN,"xxdd",cert_store,ctx,cb_ctx->cert_chain_num,cb_ctx->certs_bin_len);
  return 0;

error:
	RHP_UNLOCK(&(auth_rlm->lock));

	RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_CB_ENUM_CERTS_CB_ERR,"xxE",cert_store,ctx,err);
	return err;
}

static  void _rhp_auth_ipc_handle_sign_rsasig_req_cb(rhp_cert_store* cert_store,int err,rhp_cert_sign_ctx* cb_cert_ctx)
{
  rhp_auth_ipc_sign_rsasig_cb_ctx* cb_ctx = (rhp_auth_ipc_sign_rsasig_cb_ctx*)cb_cert_ctx;
  rhp_ipcmsg_sign_req* sign_rsasig_req = NULL;
  rhp_vpn_auth_realm* auth_rlm = NULL;
  rhp_ipcmsg_sign_rep* sign_rsasig_rep = NULL;
  rhp_auth_ipc_sign_rsasig_enum_certs_ctx enum_certs_cb_ctx;
  u8* ca_cert_keys = NULL;
  int ca_cert_keys_len = 0,ca_cert_key_len = 0;
  u8* der_certs = NULL;
  int deny_expired_cert = 1;
  int reply_len = 0;
  int result = 0;
  int eap_role = 0;
  int eap_method = RHP_PROTO_EAP_TYPE_NONE;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_CB,"xdx",cert_store,err,cb_cert_ctx);

  sign_rsasig_req = (rhp_ipcmsg_sign_req*)cb_ctx->sign_rsasig_req;

  auth_rlm = cb_ctx->auth_rlm; // (**VV**)

  if( !_rhp_atomic_read(&(cert_store->is_active)) ){
    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_CB_CERTSTORE_NOT_ACTIVE,"x",cert_store);
    goto error;
  }

  if( err ){
    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_CB_GEN_MY_SIG_ERR,"xxE",cert_store,auth_rlm,err);
		RHP_LOG_E(RHP_LOG_SRC_AUTH,auth_rlm->id,RHP_LOG_ID_GENERATE_MY_SIGNATURE_ERR,"E",err);
    goto failed;
  }


  RHP_LOCK(&(auth_rlm->lock));
  {
		if( !_rhp_atomic_read(&(auth_rlm->is_active)) ){
			RHP_UNLOCK(&(auth_rlm->lock));
			RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_CB_REALM_NOT_ACTIVE,"x",auth_rlm);
			goto error;
		}

		deny_expired_cert = !auth_rlm->accept_expired_cert;
		eap_role = auth_rlm->eap.role;
		eap_method = auth_rlm->eap.method;
  }
  RHP_UNLOCK(&(auth_rlm->lock));


  {
		err = cert_store->get_ca_public_key_digests(cert_store,&ca_cert_keys,&ca_cert_keys_len,&ca_cert_key_len);
		if( err ){
			RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_CB_GET_PUBKEY_DIG_ERR,"d",err);
			RHP_LOG_E(RHP_LOG_SRC_AUTH,auth_rlm->id,RHP_LOG_ID_GET_CA_CERT_DIGEST_ERR,"E",err);
			goto failed;
		}
  }


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
    enum_certs_cb_ctx.http_cert_lookup_supported = sign_rsasig_req->http_cert_lookup_supported;

		err = cert_store->enum_DER_certs(cert_store,deny_expired_cert,1,
							rhp_auth_ipc_handle_sign_rsasig_req_cb_enum_certs_cb,&enum_certs_cb_ctx);

		if( err == RHP_STATUS_ENUM_OK ){
			err = 0;
		}else if( err ){
			RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_CB_FAILED,"dd",err,2);
			RHP_LOG_E(RHP_LOG_SRC_AUTH,auth_rlm->id,RHP_LOG_ID_ENUM_MY_CERT_ERR,"sE",(deny_expired_cert ? "denied" : "ignored"),err);
			goto failed;
		}

		if( enum_certs_cb_ctx.my_cert == 0 ){
			RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_CB_FAILED,"dd",err,3);
			RHP_LOG_E(RHP_LOG_SRC_AUTH,auth_rlm->id,RHP_LOG_ID_GET_NO_MY_CERT_ERR,"");
			goto failed;
		}
  }


  reply_len = sizeof(rhp_ipcmsg_sign_rep);
  reply_len += cb_ctx->cb_cert_ctx.signed_octets_len;
  reply_len += enum_certs_cb_ctx.certs_bin_len;
  reply_len += ca_cert_keys_len;

  sign_rsasig_rep = (rhp_ipcmsg_sign_rep*)rhp_ipc_alloc_msg(RHP_IPC_SIGN_RSASIG_REPLY,reply_len);
  if( sign_rsasig_rep == NULL ){
    RHP_BUG("");
    goto failed;
  }

  result = 1;
  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_CB_OK,"x",cb_cert_ctx);


  sign_rsasig_rep->len = reply_len;
  sign_rsasig_rep->txn_id = sign_rsasig_req->txn_id;
  sign_rsasig_rep->my_realm_id = auth_rlm->id;
  sign_rsasig_rep->result = result;
  sign_rsasig_rep->signed_octets_len = cb_ctx->cb_cert_ctx.signed_octets_len;
  sign_rsasig_rep->cert_chain_num = enum_certs_cb_ctx.cert_chain_num;
  sign_rsasig_rep->cert_chain_len = enum_certs_cb_ctx.certs_bin_len;
  sign_rsasig_rep->side = sign_rsasig_req->side;
  sign_rsasig_rep->ca_pubkey_dgst_len = ca_cert_key_len;
  sign_rsasig_rep->ca_pubkey_dgsts_len = ca_cert_keys_len;
  sign_rsasig_rep->auth_method = RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG;
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

  	if( ca_cert_keys ){
  		memcpy(p,ca_cert_keys,ca_cert_keys_len);
  		p = p + ca_cert_keys_len;
  	}
  }

  {
		sign_rsasig_rep->qcd_enabled = 0;
		if( sign_rsasig_req->qcd_enabled ){

			if( rhp_ikev2_qcd_get_my_token(sign_rsasig_req->side,sign_rsasig_req->spi,
					sign_rsasig_req->peer_spi,sign_rsasig_rep->my_qcd_token) ){

				RHP_BUG("");

			}else{
				sign_rsasig_rep->qcd_enabled = 1;
			}
		}
  }

tx_error:
  if( cb_ctx->verify_sign_req == NULL ){

    if( rhp_ipc_send(RHP_MY_PROCESS,(void*)sign_rsasig_rep,sign_rsasig_rep->len,0) < 0 ){
      RHP_BUG("");
    }

    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_CB_TX_SIGN_RSASIG_REP,"xp",cb_cert_ctx,sign_rsasig_rep->len,sign_rsasig_rep);

  }else{

    int verify_sign_rep_len = 0;
    rhp_ipcmsg_verify_and_sign_rep* verify_sign_rep = NULL;
    rhp_ipcmsg_sign_rep* in_sign_rep = sign_rsasig_rep;
    u8* p = NULL;

    verify_sign_rep_len = sizeof(rhp_ipcmsg_verify_and_sign_rep);

    if( cb_ctx->in_verify_rep ){
      verify_sign_rep_len += cb_ctx->in_verify_rep->len;
    }

    if( in_sign_rep ){
      verify_sign_rep_len += in_sign_rep->len;
    }

    verify_sign_rep = (rhp_ipcmsg_verify_and_sign_rep*)rhp_ipc_alloc_msg(RHP_IPC_VERIFY_AND_SIGN_REPLY,verify_sign_rep_len);
    if( verify_sign_rep == NULL ){
      RHP_BUG("");
      goto error;
    }

    verify_sign_rep->len = verify_sign_rep_len;

    p = (u8*)(verify_sign_rep + 1);

    if( cb_ctx->in_verify_rep ){
      memcpy(p,cb_ctx->in_verify_rep,cb_ctx->in_verify_rep->len);
      p += cb_ctx->in_verify_rep->len;
    }

    if( in_sign_rep ){
      memcpy(p,in_sign_rep,in_sign_rep->len);
      p += in_sign_rep->len;
    }

    if( rhp_ipc_send(RHP_MY_PROCESS,(void*)verify_sign_rep,verify_sign_rep->len,0) < 0 ){
      RHP_BUG("");
    }

    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_CB_TX_VERIFY_SIGN_REP,"xp",cb_cert_ctx,verify_sign_rep->len,verify_sign_rep);

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

  if( ca_cert_keys ){
    _rhp_free(ca_cert_keys);
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

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_CB_RTRN,"x",cb_cert_ctx);
  return;


failed:
	if( sign_rsasig_rep ){
		_rhp_free_zero(sign_rsasig_rep,sign_rsasig_rep->len);
		sign_rsasig_rep = NULL;
	}

  sign_rsasig_rep = (rhp_ipcmsg_sign_rep*)rhp_ipc_alloc_msg(RHP_IPC_SIGN_RSASIG_REPLY,sizeof(rhp_ipcmsg_sign_rep));
  if( sign_rsasig_rep == NULL ){
    RHP_BUG("");
    goto error;
  }

  sign_rsasig_rep->len = sizeof(rhp_ipcmsg_sign_rep);
  sign_rsasig_rep->txn_id = sign_rsasig_req->txn_id;
  sign_rsasig_rep->my_realm_id = auth_rlm->id;
  sign_rsasig_rep->result = 0;
  sign_rsasig_rep->signed_octets_len = 0;
  sign_rsasig_rep->cert_chain_num = 0;
  sign_rsasig_rep->cert_chain_len = 0;
  sign_rsasig_rep->side = sign_rsasig_req->side;
  sign_rsasig_rep->ca_pubkey_dgst_len = 0;
  sign_rsasig_rep->ca_pubkey_dgsts_len = 0;
  sign_rsasig_rep->auth_method = RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG;
  memcpy(sign_rsasig_rep->spi,sign_rsasig_req->spi,RHP_PROTO_IKE_SPI_SIZE);

	goto tx_error;
}

static int _rhp_auth_ipc_handle_sign_rsasig_req(rhp_ipcmsg* ipcmsg,unsigned long auth_rlm_id,rhp_ipcmsg** ipcmsg_r,
    rhp_ipcmsg* verify_sign_req,rhp_ipcmsg* in_verify_rep)
{
  int err = -EINVAL;
  rhp_ipcmsg_sign_req* sign_rsasig_req;
  rhp_vpn_auth_realm* auth_rlm = NULL;
  rhp_cert_store* cert_store = NULL;
  u8 *mesg_octets = NULL, *mesg_octets_exp = NULL;
  int mesg_octets_len, mesg_octets_exp_len;
  rhp_ipcmsg_sign_rep* sign_rsasig_rep;
  int reply_len = 0;
  rhp_auth_ipc_sign_rsasig_cb_ctx* cb_ctx;
  u8* certreq_pubkey_digests = NULL;
  u8* ca_pubkey_digests = NULL;
  int ca_pubkey_dgsts_len,ca_pubkey_dgst_len;
  u8 *p, *sk_p;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ,"xuxxx",ipcmsg,auth_rlm_id,ipcmsg_r,verify_sign_req,in_verify_rep);

  if( ipcmsg->len < sizeof(rhp_ipcmsg_sign_req) ){
    RHP_BUG("");
    goto error;
  }

  sign_rsasig_req = (rhp_ipcmsg_sign_req*)ipcmsg;

  if( sign_rsasig_req->mesg_octets_len == 0 		||
  		sign_rsasig_req->certs_bin_max_size == 0  ||
      (sign_rsasig_req->ca_pubkey_dgsts_len &&
      (sign_rsasig_req->ca_pubkey_dgsts_len % sign_rsasig_req->ca_pubkey_dgst_len) != 0 ) ||
      sign_rsasig_req->len != sizeof(rhp_ipcmsg_sign_req) + sign_rsasig_req->mesg_octets_len
      + sign_rsasig_req->sk_p_len + sign_rsasig_req->ca_pubkey_dgsts_len  ){
    RHP_BUG("");
    goto error;
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

			RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_NO_CERT_STORE,"xuxx",ipcmsg,auth_rlm_id,verify_sign_req,in_verify_rep);

			RHP_LOG_E(RHP_LOG_SRC_AUTH,auth_rlm->id,RHP_LOG_ID_NO_CERT_INFO_LOADED,"");

			RHP_UNLOCK(&(auth_rlm->lock));
			goto failed;
		}
  }
  RHP_UNLOCK(&(auth_rlm->lock));

  if( sign_rsasig_req->sk_p_len ){

    rhp_crypto_prf* prf = NULL;
    rhp_ikev2_id* my_id = &(auth_rlm->my_auth->my_id);

    prf  = rhp_crypto_prf_alloc(sign_rsasig_req->prf_method);
    if( prf == NULL ){
      RHP_BUG("");
      goto failed;
    }

    sk_p = p;
    p += sign_rsasig_req->sk_p_len;

    err = rhp_auth_sign_req_expand_mesg_octets(prf,my_id,sign_rsasig_req->sk_p_len,sk_p,mesg_octets_len,mesg_octets,
          &mesg_octets_exp_len,&mesg_octets_exp);

    rhp_crypto_prf_free(prf);

    if( err ){
      RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_EXP_MESG_OCTETS_ERR,"d",err);
      goto failed;
    }

    mesg_octets = mesg_octets_exp;
    mesg_octets_len = mesg_octets_exp_len;
  }

  certreq_pubkey_digests = p;
  p += sign_rsasig_req->ca_pubkey_dgsts_len;

  ca_pubkey_dgsts_len = sign_rsasig_req->ca_pubkey_dgsts_len;

  if( rhp_gcfg_check_certreq_ca_digests && sign_rsasig_req->ca_pubkey_dgsts_len ){

    int n1,n2,i,j;
    int found = 0;

    if( sign_rsasig_req->ca_pubkey_dgst_len != RHP_PROTO_IKE_CERTENC_SHA1_DIGEST_LEN ){
    	RHP_BUG("");
    	err = -EINVAL;
      goto failed;
    }

    err = cert_store->get_ca_public_key_digests(cert_store,&ca_pubkey_digests,&ca_pubkey_dgsts_len,&ca_pubkey_dgst_len);
    if( err ){
      RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_GET_PUBKEY_DIG_ERR,"d",err);
      goto failed;
    }

    if( ca_pubkey_dgst_len  != (int)sign_rsasig_req->ca_pubkey_dgst_len ){
      RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_INVALID_CA_PUBKEY_DIGEST_LEN,"du",ca_pubkey_dgst_len,sign_rsasig_req->ca_pubkey_dgst_len);
      goto failed;
    }

    n1 = sign_rsasig_req->ca_pubkey_dgsts_len / sign_rsasig_req->ca_pubkey_dgst_len;
    n2 = ca_pubkey_dgsts_len / ca_pubkey_dgst_len;

    for( i = 0; i < n2; i++ ){

  		u8* p0 = ca_pubkey_digests + (ca_pubkey_dgst_len*i);

    	for( j = 0; j < n1; j++){

    		u8* p1 = certreq_pubkey_digests + (sign_rsasig_req->ca_pubkey_dgst_len*j);

    		if( !memcmp(p0,p1,ca_pubkey_dgst_len) ){
    			found++;
    			break;
    		}
    	}
    }

    if( !found || ( rhp_gcfg_strictly_cmp_certreq_ca_digests && found != n2 ) ){

      RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_MATCHED_CA_KEYS_NOT_FOUND,"dpp",found,sign_rsasig_req->ca_pubkey_dgsts_len,certreq_pubkey_digests,ca_pubkey_dgsts_len,ca_pubkey_digests);
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

  cb_ctx->cb_cert_ctx.sign_op_type = RHP_CERT_SIGN_OP_SIGN;
  cb_ctx->cb_cert_ctx.mesg_octets = mesg_octets;
  cb_ctx->cb_cert_ctx.mesg_octets_len = mesg_octets_len;

  cb_ctx->cb_cert_ctx.callback = _rhp_auth_ipc_handle_sign_rsasig_req_cb;

  cb_ctx->auth_rlm = auth_rlm;
  rhp_auth_realm_hold(auth_rlm);

  cb_ctx->sign_rsasig_req = (rhp_ipcmsg*)sign_rsasig_req;

  cb_ctx->verify_sign_req = verify_sign_req;
  cb_ctx->in_verify_rep = in_verify_rep;

  cb_ctx->mesg_octets_exp = mesg_octets_exp;
  cb_ctx->mesg_octets_exp_len = mesg_octets_exp_len;

  err = cert_store->sign(cert_store,(rhp_cert_sign_ctx*)cb_ctx);
  if( err ){
    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_SIGN_ERR,"d",err);
    goto failed;
  }

  if( ca_pubkey_digests ){
    _rhp_free(ca_pubkey_digests);
  }

  rhp_auth_realm_unhold(auth_rlm);

  *ipcmsg_r = NULL;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_PENDING,"x",ipcmsg);
  return 0;

failed:

  reply_len = sizeof(rhp_ipcmsg_sign_rep);

  sign_rsasig_rep = (rhp_ipcmsg_sign_rep*)rhp_ipc_alloc_msg(RHP_IPC_SIGN_RSASIG_REPLY,reply_len);
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

  if( cert_store ){
    rhp_cert_store_unhold(cert_store);
  }

  if( auth_rlm ){
    rhp_auth_realm_unhold(auth_rlm);
  }

  if( ca_pubkey_digests ){
    _rhp_free(ca_pubkey_digests);
  }

  if( mesg_octets_exp ){
    _rhp_free_zero(mesg_octets_exp,mesg_octets_exp_len);
  }

  *ipcmsg_r = (rhp_ipcmsg*)sign_rsasig_rep;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_ERR_RTRN,"xp",ipcmsg,sign_rsasig_rep->len,sign_rsasig_rep);
  return 0;

error:
  if( cert_store ){
    rhp_cert_store_unhold(cert_store);
  }
  if( auth_rlm ){
    rhp_auth_realm_unhold(auth_rlm);
  }
  if( ca_pubkey_digests ){
    _rhp_free(ca_pubkey_digests);
  }
  if( mesg_octets_exp ){
    _rhp_free_zero(mesg_octets_exp,mesg_octets_exp_len);
  }
  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_RSASIG_REQ_ERR,"x",ipcmsg);
  return err;
}


static int _rhp_auth_ipc_handle_sign_req(rhp_ipcmsg *ipcmsg,rhp_ipcmsg** ipcmsg_r)
{
  int err = -EINVAL;
  rhp_vpn_auth_realm* auth_rlm = NULL;
  rhp_ipcmsg_sign_req* sign_req;
  rhp_ipcmsg_sign_rep* sign_rep;
  int reply_len = 0;
  int auth_method = 0;
  int eap_role = RHP_EAP_DISABLED;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_REQ,"xx",ipcmsg,ipcmsg_r);

  if( ipcmsg->len < sizeof(rhp_ipcmsg_sign_req) ){
    RHP_BUG("");
    goto error;
  }

  sign_req = (rhp_ipcmsg_sign_req*)ipcmsg;

  auth_rlm = rhp_auth_realm_get(sign_req->my_realm_id);
  if( auth_rlm == NULL ){
    RHP_BUG("%lu",sign_req->my_realm_id);
    goto failed;
  }

  RHP_LOCK(&(auth_rlm->lock));

  if( auth_rlm->my_auth == NULL ){
  	RHP_BUG("");
    RHP_UNLOCK(&(auth_rlm->lock));
  	goto failed;
  }

  if( sign_req->auth_tkt_session_key_len ){

  	if( !auth_rlm->auth_tkt_enabled ){
  		RHP_BUG("");
      RHP_UNLOCK(&(auth_rlm->lock));
  		goto failed;
  	}

  	auth_method = RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY;
  	eap_role = RHP_EAP_DISABLED;

  }else{

		auth_method = auth_rlm->my_auth->auth_method;
		eap_role = auth_rlm->eap.role;
  }

  RHP_UNLOCK(&(auth_rlm->lock));


  if( eap_role != RHP_EAP_SUPPLICANT ){

		if( auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){

			err = _rhp_auth_ipc_handle_sign_rsasig_req(ipcmsg,sign_req->my_realm_id,ipcmsg_r,NULL,NULL);
			if( err ){
				_rhp_free_zero(ipcmsg,ipcmsg->len);
			}else{
				 // ipcmsg is held by callback handler. Don't free here.
			}

		}else if( auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ||
							auth_method == RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH ){

			_rhp_auth_ipc_handle_sign_psk_req(ipcmsg,sign_req->my_realm_id,ipcmsg_r);
			_rhp_free_zero(ipcmsg,ipcmsg->len);

		}else{
			RHP_BUG("");
			goto failed;
		}

  }else{ // EAP Supplicant

		_rhp_auth_ipc_handle_sign_eap_sup_req(ipcmsg,sign_req->my_realm_id,ipcmsg_r);
		_rhp_free_zero(ipcmsg,ipcmsg->len);
  }

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_REQ_RTRN,"x",ipcmsg);
  return 0;

failed:

  reply_len = sizeof(rhp_ipcmsg_sign_rep);

  sign_rep = (rhp_ipcmsg_sign_rep*)rhp_ipc_alloc_msg(RHP_IPC_SIGN_PSK_REPLY,reply_len);
  if( sign_rep == NULL ){
    RHP_BUG("");
    goto error;
  }

  sign_rep->len = reply_len;
  sign_rep->txn_id = sign_req->txn_id;
  sign_rep->my_realm_id = sign_req->my_realm_id;
  sign_rep->side = sign_req->side;
  memcpy(sign_rep->spi,sign_req->spi,RHP_PROTO_IKE_SPI_SIZE);
  sign_rep->result = 0;

  if( auth_rlm ){
    rhp_auth_realm_unhold(auth_rlm);
  }

  _rhp_free_zero(ipcmsg,ipcmsg->len);

  *ipcmsg_r = (rhp_ipcmsg*)sign_rep;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_REQ_FAILED_RTRN,"xp",ipcmsg,sign_rep->len,sign_rep);
  return 0;

error:
  if( auth_rlm ){
    rhp_auth_realm_unhold(auth_rlm);
  }
  _rhp_free_zero(ipcmsg,ipcmsg->len);

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_SIGN_REQ_ERR,"x",ipcmsg);
  return err;
}

static int _rhp_auth_ipc_handle_verify_and_sign_req_cb0(rhp_ipcmsg* verify_sign_req,rhp_ipcmsg* in_sign_req,
    rhp_ipcmsg_verify_rep* in_verify_rep,unsigned long auth_rlm_id,int auth_method)
{
  int err = -EINVAL;
  rhp_ipcmsg* in_sign_rep = NULL;
  int pending = 0;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_AND_SING_REQ_CB0,"xxxudd",verify_sign_req,in_sign_req,in_verify_rep,auth_rlm_id,auth_method,in_verify_rep->result);

  if( in_verify_rep->result ){

    if( auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ||
    		auth_method == RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH ){

      err = _rhp_auth_ipc_handle_sign_psk_req(in_sign_req,auth_rlm_id,&in_sign_rep);
      if( err ){
        goto error;
      }

    }else if( auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){

      err = _rhp_auth_ipc_handle_sign_rsasig_req(in_sign_req,auth_rlm_id,&in_sign_rep,verify_sign_req,(rhp_ipcmsg*)in_verify_rep);
      if( err ){
        goto error;
      }

      if( in_sign_rep == NULL ){
        pending = 1;
      }

    }else{
      RHP_BUG("");
      goto error;
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

    verify_sign_rep = (rhp_ipcmsg_verify_and_sign_rep*)rhp_ipc_alloc_msg(RHP_IPC_VERIFY_AND_SIGN_REPLY,reply_len);
    if( verify_sign_rep == NULL ){
      RHP_BUG("");
      goto error;
    }

    verify_sign_rep->len = reply_len;

    p = (u8*)(verify_sign_rep + 1);

    if( in_verify_rep ){
      memcpy(p,in_verify_rep,in_verify_rep->len);
      p += in_verify_rep->len;
    }

    if( in_sign_rep ){
      memcpy(p,in_sign_rep,in_sign_rep->len);
      p += in_sign_rep->len;
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

    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_AND_SING_REQ_CB0_RTRN,"xxx",verify_sign_req,in_sign_req,in_verify_rep);

  }else{
    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_AND_SING_REQ_CB0_PENDING,"xxx",verify_sign_req,in_sign_req,in_verify_rep);
  }

  return 0;

error:
  if( in_sign_rep ){
    _rhp_free_zero(in_sign_rep,in_sign_rep->len);
  }
  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_AND_SING_REQ_CB0_ERR,"xxx",verify_sign_req,in_sign_req,in_verify_rep);
  return err;
}

static  void _rhp_auth_ipc_handle_verify_rsasig_req_cb(rhp_cert_store* cert_store,int auth_err,
    rhp_ikev2_id* subjectname,rhp_ikev2_id* subjectaltname,rhp_cert_sign_verify_ctx* cb_cert_ctx)
{
  rhp_auth_ipc_verify_rsasig_cb_ctx* cb_ctx = (rhp_auth_ipc_verify_rsasig_cb_ctx*)cb_cert_ctx;
  rhp_ipcmsg_verify_req* verify_rsasig_req = NULL;
  rhp_vpn_auth_realm* auth_rlm = NULL;
  rhp_ipcmsg_verify_rep* verify_rsasig_rep = NULL;
  int verify_rsasig_rep_len;
  int result = 0;
  unsigned long auth_rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  int go_next = (cb_ctx->verify_sign_req ? 1 : 0);
  int pending = 0;
  int auth_method = 0;
  u8* subject_val = NULL;
  int subject_val_len = 0;
  int subject_val_id_type;

  auth_rlm = cb_ctx->auth_rlm;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_CB,"xdxd",cert_store,auth_err,cb_cert_ctx,go_next);
  rhp_ikev2_id_dump("_rhp_auth_ipc_handle_verify_rsasig_req_cb:subjectname",subjectname);
  rhp_ikev2_id_dump("_rhp_auth_ipc_handle_verify_rsasig_req_cb:subjectaltname",subjectaltname);


  if( !_rhp_atomic_read(&(cert_store->is_active)) ){
    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_CB_CERTSTORE_NOT_ACTIVE,"x",cert_store);
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
    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_CB_REALM_NOT_ACTIVE,"x",auth_rlm);
    goto error;
  }

  cb_ctx->cb_cert_ctx.deny_expired_cert = !auth_rlm->accept_expired_cert;

  auth_rlm_id = auth_rlm->id;
  auth_method = auth_rlm->my_auth->auth_method;

  RHP_UNLOCK(&(auth_rlm->lock));

  verify_rsasig_req = (rhp_ipcmsg_verify_req*)cb_ctx->verify_rsasig_req;

  verify_rsasig_rep_len = sizeof(rhp_ipcmsg_verify_rep) + subject_val_len;

  verify_rsasig_rep = (rhp_ipcmsg_verify_rep*)rhp_ipc_alloc_msg(RHP_IPC_VERIFY_RSASIG_REPLY,verify_rsasig_rep_len);
  if( verify_rsasig_rep == NULL ){
    RHP_BUG("");
    goto error;
  }

  if( auth_err == 0 ){

  	rhp_auth_peer* peer = auth_rlm->peers;
  	int matched = 0;

  	// Is this user configured to authenticate by PSK ?
  	while( peer ){

  		rhp_ikev2_id_dump("_rhp_auth_ipc_handle_verify_rsasig_req_cb: auth_rlm->peer.id",&(peer->peer_id.ikev2));

  		switch( peer->peer_id.ikev2.type ){

  		case RHP_PROTO_IKE_ID_ANY:

  			if(  peer->peer_psks == NULL ){
  				matched = 1;
  			}else{

  				if(  !rhp_gcfg_auth_method_compared_strictly  ){
    				matched = 1;
  					RHP_LOG_I(RHP_LOG_SRC_AUTH,auth_rlm_id,RHP_LOG_ID_ANY_PEERS_PSK_DEFINED_BUT_IGNORED,"I",&(peer->peer_id.ikev2));
  				}else{
						RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_CB_ANY_PEER_FOUND_BUT_PSK,"x",auth_rlm);
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

  	  				if(  !rhp_gcfg_auth_method_compared_strictly  ){
  	    				matched = 1;
  	    				RHP_LOG_I(RHP_LOG_SRC_AUTH,auth_rlm_id,RHP_LOG_ID_PEER_PSK_DEFINED_BUT_IGNORED,"I",&(peer->peer_id.ikev2));
  	  				}else{
  	  					RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_CB_PEER_FOUND_BUT_PSK_1,"x",auth_rlm);
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

  	  			if(  peer->peer_psks == NULL ){
  	  				matched = 1;
  	  			}else{

  	  				if(  !rhp_gcfg_auth_method_compared_strictly  ){
  	    				matched = 1;
  	    				RHP_LOG_I(RHP_LOG_SRC_AUTH,auth_rlm_id,RHP_LOG_ID_PEER_PSK_DEFINED_BUT_IGNORED,"I",&(peer->peer_id.ikev2));
  	  				}else{
  	  					RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_CB_PEER_FOUND_BUT_PSK_2,"x",auth_rlm);
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
      RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_CB_PEER_ID_MATCHED,"x",auth_rlm);
  	}

  }else{

  	RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_CB_FAILED_TO_VERIFY_PEER_SIG,"x",auth_rlm);
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

		if( subject_val_len ){

			verify_rsasig_rep->alt_peer_id_len = subject_val_len;
			verify_rsasig_rep->alt_peer_id_type = subject_val_id_type;
			memcpy((verify_rsasig_rep + 1),subject_val,subject_val_len);
		}
  }

  if( !go_next ){

    if( rhp_ipc_send(RHP_MY_PROCESS,(void*)verify_rsasig_rep,verify_rsasig_rep->len,0) < 0 ){
      RHP_BUG("");
    }

    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_CB_OK,"x",verify_rsasig_rep);

  }else{

    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_CB_GO_NEXT,"xd",auth_rlm,result);

  	if( result ){

			if( _rhp_auth_ipc_handle_verify_and_sign_req_cb0(cb_ctx->verify_sign_req,
					cb_ctx->in_sign_req,verify_rsasig_rep,auth_rlm_id,auth_method) ){
				goto error;
			}

			verify_rsasig_rep = NULL;
			pending = 1;

			RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_CB_PENDING,"xx",verify_rsasig_rep,cb_ctx->verify_sign_req);

  	}else{

  		int reply_len;
      rhp_ipcmsg_verify_and_sign_rep* verify_sign_rep;
      u8* p;

      reply_len = sizeof(rhp_ipcmsg_verify_and_sign_rep);
      reply_len += verify_rsasig_rep->len;

      verify_sign_rep = (rhp_ipcmsg_verify_and_sign_rep*)rhp_ipc_alloc_msg(RHP_IPC_VERIFY_AND_SIGN_REPLY,reply_len);
      if( verify_sign_rep == NULL ){
        RHP_BUG("");
        goto error;
      }

      verify_sign_rep->len = reply_len;

      p = (u8*)(verify_sign_rep + 1);

      memcpy(p,verify_rsasig_rep,verify_rsasig_rep->len);
      p += verify_rsasig_rep->len;

      if( rhp_ipc_send(RHP_MY_PROCESS,(void*)verify_sign_rep,verify_sign_rep->len,0) < 0 ){
        RHP_BUG("");
      }

      _rhp_free_zero(verify_sign_rep,verify_sign_rep->len);

      RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_CB_AUTH_FAILED,"xx",verify_rsasig_rep,verify_rsasig_rep);
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

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_CB_RTRN,"xxd",cert_store,cb_cert_ctx,result);
  return;
}

static int _rhp_auth_ipc_handle_verify_rsasig_req(rhp_ipcmsg *ipcmsg,rhp_ipcmsg** ipcmsg_r,
    rhp_ipcmsg* verify_sign_req,rhp_ipcmsg* in_sign_req)
{
  int err = -EINVAL;
  rhp_ipcmsg_verify_req* verify_rsasig_req;
  rhp_vpn_auth_realm* auth_rlm = NULL;
  rhp_cert_store* cert_store = NULL;
  char* id_string = NULL;
  rhp_ikev2_id my_id,peer_id;
  rhp_ipcmsg_verify_rep* verify_rsasig_rep;
  int verify_rsasig_rep_len = 0;
  rhp_auth_ipc_verify_rsasig_cb_ctx* cb_ctx;
  u8* peer_cert_bin = NULL;
  u8* cert_chain_bin = NULL;
  u8* mesg_octets = NULL;
  u8* signature = NULL;
  int peer_cert_bin_len;
  int cert_chain_bin_len = 0;
  int mesg_octets_len;
  int signature_octets_len;
  u8* p;
  unsigned long auth_rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  rhp_cert* peer_cert = NULL;
  int deny_expired_cert = 0;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ,"xxxx",ipcmsg,ipcmsg_r,verify_sign_req,in_sign_req);

  memset(&my_id,0,sizeof(rhp_ikev2_id));
  memset(&peer_id,0,sizeof(rhp_ikev2_id));

  if( ipcmsg->len < sizeof(rhp_ipcmsg_verify_req) ){
    RHP_BUG("");
    goto error;
  }

  verify_rsasig_req = (rhp_ipcmsg_verify_req*)ipcmsg;


  if( verify_rsasig_req->len !=
			sizeof(rhp_ipcmsg_verify_req) + verify_rsasig_req->my_id_len
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

  if( verify_rsasig_req->peer_cert_bin_len <= 0 ){
    RHP_BUG("");
    goto failed;
  }

  if( verify_rsasig_req->signature_octets_len == 0 ){
    RHP_BUG("");
    goto failed;
  }

  if( verify_rsasig_req->mesg_octets_len == 0 ){
    RHP_BUG("");
    goto failed;
  }


  p = (u8*)( verify_rsasig_req + 1 );

  if( verify_rsasig_req->my_id_len  ){

    my_id.type = verify_rsasig_req->my_id_type;

    switch( my_id.type ){

      case RHP_PROTO_IKE_ID_FQDN:
      case RHP_PROTO_IKE_ID_RFC822_ADDR:

        id_string = (char*)p;
        if( id_string[verify_rsasig_req->my_id_len - 1] != '\0' ){
          RHP_BUG("");
          goto failed;
        }
        my_id.string = id_string;
        p += verify_rsasig_req->my_id_len;

        RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_MY_ID_FQDN_OR_EMAIL,"ds",my_id.type,my_id.string);
        break;

      case RHP_PROTO_IKE_ID_DER_ASN1_DN:

        my_id.dn_der = (u8*)p;
        my_id.dn_der_len = verify_rsasig_req->my_id_len;
        p +=  verify_rsasig_req->my_id_len;

        RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_MY_ID_DER,"dp",my_id.type,my_id.dn_der_len,my_id.dn_der);
        break;


      case RHP_PROTO_IKE_ID_NULL_ID:

      	if( verify_rsasig_req->my_id_len ){
      		RHP_BUG("%d",verify_rsasig_req->my_id_len);
      		goto failed;
      	}

      	my_id.type = RHP_PROTO_IKE_ID_NULL_ID;

        RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_MY_ID_NULL,"d",my_id.type);
      	break;

      case RHP_PROTO_IKE_ID_PRIVATE_NULL_ID_WITH_ADDR:

      	if( verify_rsasig_req->my_id_len != sizeof(rhp_ip_addr) ){
      		RHP_BUG("%d",verify_rsasig_req->my_id_len);
      		goto failed;
      	}

      	memcpy(&(my_id.addr),p,verify_rsasig_req->my_id_len);
      	p += verify_rsasig_req->my_id_len;

      	my_id.type = RHP_PROTO_IKE_ID_NULL_ID; // Adddress is not interested here.

        RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_MY_ID_NULL_WITH_ADDR,"dp",my_id.type,sizeof(rhp_ip_addr),&(my_id.addr));
        rhp_ip_addr_dump("my_id.addr",&(my_id.addr));
        break;

      default:
        RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_MY_ID_UNKNOWN,"d",my_id.type);
      	RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_VERIFY_RSASIG_RX_INVALID_MY_ID_TYPE,"d",my_id.type);
        goto failed;
    }
  }

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

        RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_PEER_ID,"ds",peer_id.type,peer_id.string);
        break;

      case RHP_PROTO_IKE_ID_DER_ASN1_DN:

        peer_id.dn_der = (u8*)p;
        peer_id.dn_der_len = verify_rsasig_req->peer_id_len;
        p +=  verify_rsasig_req->peer_id_len;

        RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_PEER_ID_DN,"dp",peer_id.type,peer_id.dn_der_len,peer_id.dn_der);
        break;

      case RHP_PROTO_IKE_ID_IPV4_ADDR:

      	//
      	// For inter-op with Win8 VPN clients.
      	//
      	// Even if RSA-Sig is used for an initiator(Win8)'s auth_method, the Win8's VPN
      	// client sends an IDi payload of IPv4/v6 ID-type with the initiator(client)'s
      	// cert. Why???
      	// Like Win7, normally, an IDi payload of DN ID-type or subjectAltName's
      	// ID-types(FQDN or E-Mail) is expected when RSA-Sig is used.
      	// This Win8's behavior may also cause some security concerns.
      	//
      	// ==> Currently, this problem is fixed by Microsoft. (IDi payload ==> DN ID-type).
      	//

      	if( verify_rsasig_req->peer_id_len != 4){
      		RHP_BUG("%d",verify_rsasig_req->peer_id_len);
          goto failed;
      	}

      	peer_id.addr.addr_family = AF_INET;
      	memcpy(peer_id.addr.addr.raw,p,verify_rsasig_req->peer_id_len);
        p +=  verify_rsasig_req->peer_id_len;

        RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_PEER_ID_IPV4,"d4",peer_id.type,peer_id.addr.addr.v4);
      	break;

      case RHP_PROTO_IKE_ID_IPV6_ADDR:

      	if( verify_rsasig_req->peer_id_len != 16){
      		RHP_BUG("%d",verify_rsasig_req->peer_id_len);
          goto failed;
      	}

      	peer_id.addr.addr_family = AF_INET6;
      	memcpy(peer_id.addr.addr.raw,p,verify_rsasig_req->peer_id_len);
        p +=  verify_rsasig_req->peer_id_len;

        RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_PEER_ID_IPV6,"d6",peer_id.type,peer_id.addr.addr.v6);
      	break;


      //
      // [CAUTION]
      //
      //  If peer's id is RHP_PROTO_IKE_ID_NULL, PSK is used for the peer's auth_method (Key is sk_px).
      //  RSA-Sig is never used.
      //
      //
      default:
        RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_PEER_ID_UNKNOWN,"d",peer_id.type);
      	RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_VERIFY_RSASIG_RX_INVALID_PEER_ID_TYPE,"d",peer_id.type);

      	goto failed;
    }
  }

  peer_cert_bin = p;
  peer_cert_bin_len = verify_rsasig_req->peer_cert_bin_len;
  p += peer_cert_bin_len;

  if( verify_rsasig_req->cert_chain_bin_len && verify_rsasig_req->cert_chain_num ){
    cert_chain_bin = p;
    cert_chain_bin_len = verify_rsasig_req->cert_chain_bin_len;
    p +=  cert_chain_bin_len;
  }

  mesg_octets = p;
  mesg_octets_len = verify_rsasig_req->mesg_octets_len;
  p +=  mesg_octets_len;

  signature = p;
  signature_octets_len = verify_rsasig_req->signature_octets_len;
  p +=  signature_octets_len;

  peer_cert = rhp_cert_alloc(peer_cert_bin,peer_cert_bin_len);
  if( peer_cert == NULL ){

    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_CERT_ALLOC_ERR,"p",peer_cert_bin_len,peer_cert_bin);
  	RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_VERIFY_RSASIG_RX_INVALID_PEER_CERT,"II",&my_id,&peer_id);

  	goto failed;
  }

  if( verify_rsasig_req->my_realm_id != RHP_VPN_REALM_ID_UNKNOWN ){

    auth_rlm = rhp_auth_realm_get(verify_rsasig_req->my_realm_id);

  }else{

  	auth_rlm = rhp_auth_realm_get_by_role( (verify_rsasig_req->my_id_len ? &my_id : NULL),
  			RHP_PEER_ID_TYPE_IKEV2,(void*)&peer_id,peer_cert,1,verify_rsasig_req->peer_notified_realm_id);
  }

  if( auth_rlm == NULL ){

    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_RLM_NOT_FOUND,"u",verify_rsasig_req->my_realm_id);
  	RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_VERIFY_RSASIG_REALM_NOT_DEFINED,"II",&my_id,&peer_id);

  	goto failed;
  }

  if( !auth_rlm->rsa_sig_for_peers ){

    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_NOT_ALLOWED,"u",verify_rsasig_req->my_realm_id);
  	RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_VERIFY_RSASIG_NOT_ALLOWED,"II",&my_id,&peer_id);

  	goto failed;
  }



  RHP_LOCK(&(auth_rlm->lock));
  {
		cert_store = auth_rlm->my_auth->cert_store;

		if( cert_store ){

			rhp_cert_store_hold(cert_store);

			deny_expired_cert = !auth_rlm->accept_expired_cert;

		}else{

		  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_NO_CERT_STORE,"xxxx",ipcmsg,verify_sign_req,in_sign_req,auth_rlm);
	  	RHP_LOG_E(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_VERIFY_RSASIG_NO_MY_CERT_STORE,"II",&my_id,&peer_id);

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

  cb_ctx->cb_cert_ctx.sign_op_type = RHP_CERT_SIGN_OP_VERIFY;

  cb_ctx->cb_cert_ctx.peer_cert = peer_cert;
  cb_ctx->cb_cert_ctx.cert_chain_bin = cert_chain_bin;
  cb_ctx->cb_cert_ctx.cert_chain_bin_len = cert_chain_bin_len;
  cb_ctx->cb_cert_ctx.signed_octets = mesg_octets;
  cb_ctx->cb_cert_ctx.signed_octets_len = mesg_octets_len;
  cb_ctx->cb_cert_ctx.signature = signature;
  cb_ctx->cb_cert_ctx.signature_len = signature_octets_len;

  cb_ctx->cb_cert_ctx.cert_chain_num = verify_rsasig_req->cert_chain_num;

  cb_ctx->cb_cert_ctx.callback = _rhp_auth_ipc_handle_verify_rsasig_req_cb;

  cb_ctx->auth_rlm = auth_rlm;
  rhp_auth_realm_hold(auth_rlm);

  cb_ctx->cb_cert_ctx.deny_expired_cert = deny_expired_cert;

  cb_ctx->verify_rsasig_req = (rhp_ipcmsg*)verify_rsasig_req;
  cb_ctx->verify_sign_req = verify_sign_req;
  cb_ctx->in_sign_req = in_sign_req;

  err = cert_store->verify_signature(cert_store,(rhp_cert_sign_verify_ctx*)cb_ctx);
  if( err ){
    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_VERIFY_SIG_ERR,"xx",cert_store,cb_ctx);
    goto failed;
  }

  rhp_auth_realm_unhold(auth_rlm);

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_PENDING,"xd",ipcmsg,deny_expired_cert);
  *ipcmsg_r = NULL;

  return 0;

failed:

  verify_rsasig_rep_len = sizeof(rhp_ipcmsg_verify_rep);

  verify_rsasig_rep = (rhp_ipcmsg_verify_rep*)rhp_ipc_alloc_msg(RHP_IPC_VERIFY_RSASIG_REPLY,verify_rsasig_rep_len);
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

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_RTRN,"xp",ipcmsg,verify_rsasig_rep->len,verify_rsasig_rep);
  return 0;

error:
  if( cert_store ){
    rhp_cert_store_unhold(cert_store);
  }
  if( auth_rlm ){
    rhp_auth_realm_unhold(auth_rlm);
  }
  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_RSASIG_REQ_ERR,"x",ipcmsg);
  return err;
}

static int _rhp_auth_ipc_handle_verify_and_sign_req(rhp_ipcmsg *ipcmsg,rhp_ipcmsg** ipcmsg_r)
{
  int err = -EINVAL;
  rhp_ipcmsg_verify_and_sign_req* verify_sign_req;
  rhp_ipcmsg *in_verify_req,*in_sign_req;
  rhp_ipcmsg *in_verify_rep = NULL,*in_sign_rep = NULL;
  int pending = 0;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_AND_SIGN_REQ,"xx",ipcmsg,ipcmsg_r);

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

  if( in_verify_req->type != RHP_IPC_VERIFY_PSK_REQUEST &&
      in_verify_req->type != RHP_IPC_VERIFY_RSASIG_REQUEST &&
      in_verify_req->type != RHP_IPC_EAP_SUP_VERIFY_REQUEST ){
    RHP_BUG("%d",in_verify_req->type);
    goto error;
  }

  if( in_verify_req->type == RHP_IPC_VERIFY_PSK_REQUEST ){

  	int my_auth_method_psk = 0;
    unsigned long auth_rlm_id_psk;

    err = _rhp_auth_ipc_handle_verify_psk_req(in_verify_req,&in_verify_rep,
    				&my_auth_method_psk,&auth_rlm_id_psk);
    if( err ){
      RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_AND_SIGN_REQ_ERR_1,"x",ipcmsg);
      goto error;
    }

    if( ((rhp_ipcmsg_verify_rep*)in_verify_rep)->result ){

   	  if( my_auth_method_psk == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ||
   	  		my_auth_method_psk == RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH ){

        err = _rhp_auth_ipc_handle_sign_psk_req(in_sign_req,auth_rlm_id_psk,&in_sign_rep);
        if( err ){
          RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_AND_SIGN_REQ_ERR_2,"x",ipcmsg);
          goto error;
        }

      }else if( my_auth_method_psk == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){

        err = _rhp_auth_ipc_handle_sign_rsasig_req(in_sign_req,auth_rlm_id_psk,
        				&in_sign_rep,ipcmsg,in_verify_rep);
        if( err ){
          RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_AND_SIGN_REQ_ERR_3,"x",ipcmsg);
          goto error;
        }

       if( in_sign_rep == NULL ){
         pending = 1;
       }

     }else{
       RHP_BUG("");
    	 err = -EINVAL;
       goto error;
      }
    }

  }else if( in_verify_req->type == RHP_IPC_VERIFY_RSASIG_REQUEST ){

    err = _rhp_auth_ipc_handle_verify_rsasig_req(in_verify_req,&in_verify_rep,ipcmsg,in_sign_req);
    if( err ){
      RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_AND_SIGN_REQ_ERR_4,"x",ipcmsg);
      goto error;
    }

    if( in_verify_rep == NULL ){
    	pending = 1;
    }

  }else if( in_verify_req->type == RHP_IPC_EAP_SUP_VERIFY_REQUEST ){

  	int my_auth_method_eap = 0;
    unsigned long auth_rlm_id_eap;

    err = _rhp_auth_ipc_handle_verify_eap_sup_req(in_verify_req,&in_verify_rep,
    				&my_auth_method_eap,&auth_rlm_id_eap);
    if( err ){
      goto error;
    }

    if( ((rhp_ipcmsg_verify_rep*)in_verify_rep)->result ){

    	if( my_auth_method_eap == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY  ||
    			my_auth_method_eap == RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH ){

        err = _rhp_auth_ipc_handle_sign_psk_req(in_sign_req,auth_rlm_id_eap,&in_sign_rep);
        if( err ){
          goto error;
        }

    	}else if( my_auth_method_eap == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){

        err = _rhp_auth_ipc_handle_sign_rsasig_req(in_sign_req,auth_rlm_id_eap,
        				&in_sign_rep,ipcmsg,in_verify_rep);
        if( err ){
          goto error;
        }

       if( in_sign_rep == NULL ){
         pending = 1;
       }

      }else{
      	RHP_BUG("%d",my_auth_method_eap);
      	err = -EINVAL;
      	goto error;
      }
    }

  }else{
    RHP_BUG("");
    err = -EINVAL;
    goto error;
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

    verify_sign_rep = (rhp_ipcmsg_verify_and_sign_rep*)rhp_ipc_alloc_msg(RHP_IPC_VERIFY_AND_SIGN_REPLY,reply_len);
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
    }

    if( in_sign_rep ){
      memcpy(p,in_sign_rep,in_sign_rep->len);
      p += in_sign_rep->len;
    }

    if( in_verify_rep ){
      _rhp_free_zero(in_verify_rep,in_verify_rep->len);
    }

    if( in_sign_rep ){
      _rhp_free_zero(in_sign_rep,in_sign_rep->len);
    }

    _rhp_free_zero(ipcmsg,ipcmsg->len);

    *ipcmsg_r = (rhp_ipcmsg*)verify_sign_rep;

    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_AND_SIGN_REQ_RTRN,"xp",ipcmsg,verify_sign_rep->len,verify_sign_rep);

  }else{
    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_AND_SIGN_REQ_PENDING,"x",ipcmsg);
  }

  return 0;

error:
  if( in_verify_rep ){
    _rhp_free_zero(in_verify_rep,in_verify_rep->len);
  }
  if( in_sign_rep ){
    _rhp_free_zero(in_sign_rep,in_sign_rep->len);
  }
  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_VERIFY_AND_SIGN_REQ_ERR,"x",ipcmsg);
  return err;
}

rhp_ipcmsg_resolve_my_id_rep* rhp_auth_ipc_alloc_rslv_my_id_rep(unsigned long rlm_id,u64 txn_id,
		int result,int id_type,int id_len,u8* id_value,int my_auth_method,int xauth_method,
		int eap_sup_enabled,int eap_sup_ask_for_user_key,int eap_sup_method,int eap_sup_user_key_cache_enabled,
	  int psk_for_peers,int rsa_sig_for_peers,int eap_for_peers,int null_auth_for_peers,
	  int my_cert_issuer_dn_der_len,u8* my_cert_issuer_dn_der,
	  int untrust_sub_ca_cert_issuer_dn_der_len,u8* untrust_sub_ca_cert_issuer_dn_der)
{
  int reply_len = 0;
  rhp_ipcmsg_resolve_my_id_rep* resolve_my_id_rep;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_ALLOC_RSLV_MY_ID_REP,"uqddpddddddddddpp",rlm_id,txn_id,result,id_type,id_len,id_value,my_auth_method,xauth_method,eap_sup_enabled,eap_sup_ask_for_user_key,eap_sup_method,eap_sup_user_key_cache_enabled,psk_for_peers,rsa_sig_for_peers,eap_for_peers,null_auth_for_peers,my_cert_issuer_dn_der_len,my_cert_issuer_dn_der,untrust_sub_ca_cert_issuer_dn_der_len,untrust_sub_ca_cert_issuer_dn_der);

  if( eap_sup_enabled ){
  	id_len = 0;
  }

  reply_len = sizeof(rhp_ipcmsg_resolve_my_id_rep) + id_len
  						+ my_cert_issuer_dn_der_len + untrust_sub_ca_cert_issuer_dn_der_len;

  resolve_my_id_rep = (rhp_ipcmsg_resolve_my_id_rep*)rhp_ipc_alloc_msg(RHP_IPC_RESOLVE_MY_ID_REPLY,reply_len);
  if( resolve_my_id_rep == NULL ){
    RHP_BUG("");
    return NULL;
  }

  resolve_my_id_rep->len = reply_len;
  resolve_my_id_rep->txn_id = txn_id;
  resolve_my_id_rep->my_realm_id = rlm_id;
  resolve_my_id_rep->result = result;

  if( result ){

  	u8* p;

  	resolve_my_id_rep->my_auth_method = my_auth_method;

  	resolve_my_id_rep->xauth_method = xauth_method;

  	resolve_my_id_rep->eap_sup_enabled = eap_sup_enabled;
  	resolve_my_id_rep->eap_sup_ask_for_user_key = eap_sup_ask_for_user_key;
  	resolve_my_id_rep->eap_sup_user_key_cache_enabled = eap_sup_user_key_cache_enabled;
  	resolve_my_id_rep->eap_sup_method = eap_sup_method;

  	resolve_my_id_rep->psk_for_peers = psk_for_peers;
  	resolve_my_id_rep->rsa_sig_for_peers = rsa_sig_for_peers;
  	resolve_my_id_rep->eap_for_peers = eap_for_peers;
  	resolve_my_id_rep->null_auth_for_peers = null_auth_for_peers;

  	resolve_my_id_rep->my_cert_issuer_dn_der_len = my_cert_issuer_dn_der_len;
  	resolve_my_id_rep->untrust_sub_ca_cert_issuer_dn_der_len = untrust_sub_ca_cert_issuer_dn_der_len;

  	p = (u8*)(resolve_my_id_rep + 1);

    if( id_len || rhp_ikev2_is_null_auth_id(id_type) ){

    	resolve_my_id_rep->my_id_type = id_type;
    	resolve_my_id_rep->my_id_len = id_len;

    	if( id_len ){
      	memcpy(p,id_value,id_len);
      	p += id_len;
      }

    }else{

    	resolve_my_id_rep->my_id_type = RHP_PROTO_IKE_ID_PRIVATE_NOT_RESOLVED;
      resolve_my_id_rep->my_id_len = 0;
    }

    if( my_cert_issuer_dn_der_len ){
    	memcpy(p,my_cert_issuer_dn_der,my_cert_issuer_dn_der_len);
    	p += my_cert_issuer_dn_der_len;
    }

    if( untrust_sub_ca_cert_issuer_dn_der_len ){
    	memcpy(p,untrust_sub_ca_cert_issuer_dn_der,untrust_sub_ca_cert_issuer_dn_der_len);
    	p += untrust_sub_ca_cert_issuer_dn_der_len;
    }
  }

  return resolve_my_id_rep;
}


//
// TODO : Replace the following code with more generic one.
//
int rhp_auth_sup_is_enabled(unsigned long rlm_id,
		int* eap_method_r,int* ask_for_user_key_r,int* user_key_cache_enabled_r)
{
	rhp_vpn_auth_realm *auth_rlm = NULL;

	if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
		RHP_BUG("");
		return 0;
	}

  auth_rlm = rhp_auth_realm_get(rlm_id);
  if( auth_rlm == NULL ){
		RHP_BUG("");
  	return 0;
  }

  RHP_LOCK(&(auth_rlm->lock));
  {

		if( auth_rlm->eap.role == RHP_EAP_SUPPLICANT ){

			*eap_method_r = auth_rlm->eap.method;

			if( auth_rlm->my_auth ){

				*ask_for_user_key_r = ((auth_rlm->my_auth->my_psks && auth_rlm->my_auth->my_psks->key) ? 0 : 1);
				*user_key_cache_enabled_r = auth_rlm->my_auth->eap_sup.user_key_cache_enabled;

			}else{

				*ask_for_user_key_r = 0;
				*user_key_cache_enabled_r = 0;
			}

		  RHP_UNLOCK(&(auth_rlm->lock));
		  rhp_auth_realm_unhold(auth_rlm);

		  RHP_TRC(0,RHPTRCID_AUTH_SUP_IS_ENABLED_ENABLED,"uxddd",rlm_id,auth_rlm,*eap_method_r,*ask_for_user_key_r,*user_key_cache_enabled_r);
			return 1;

		}else{

		  RHP_TRC(0,RHPTRCID_AUTH_SUP_IS_ENABLED_DISABLED,"uxd",rlm_id,auth_rlm,auth_rlm->eap.role);
		}
  }
  RHP_UNLOCK(&(auth_rlm->lock));
  rhp_auth_realm_unhold(auth_rlm);

	return 0;
}


static int _rhp_auth_ipc_handle_resolve_my_id_req(rhp_ipcmsg *ipcmsg,rhp_ipcmsg** ipcmsg_r)
{
  int err = -EINVAL;
  rhp_ipcmsg_resolve_my_id_req* res_my_id_req;
  rhp_vpn_auth_realm* auth_rlm = NULL;
  unsigned int result = 0;
  u8* id_value = NULL;
  int id_len = 0;
  int id_type = RHP_PROTO_IKE_ID_PRIVATE_NOT_RESOLVED;
  int eap_sup_enabled = 0;
  int eap_sup_ask_for_user_key = 0, eap_sup_method = 0, eap_sup_user_key_cache_enabled = 0;
  int psk_for_peers = 0, rsa_sig_for_peers = 0, eap_for_peers = 0, null_auth_for_peers = 0;
  rhp_ipcmsg_resolve_my_id_rep* resolve_my_id_rep;
  int my_auth_method = RHP_PROTO_IKE_AUTHMETHOD_NONE;
  u8 *my_cert_issuer_dn_der = NULL, *untrust_sub_ca_cert_issuer_dn_der = NULL;
  int my_cert_issuer_dn_der_len = 0, untrust_sub_ca_cert_issuer_dn_der_len = 0;
  int xauth_method = RHP_PROTO_IKE_AUTHMETHOD_NONE;


  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_RESOLVE_MY_ID_REQ,"xx",ipcmsg,ipcmsg_r);

  if( ipcmsg->len < sizeof(rhp_ipcmsg_resolve_my_id_req) ){
    RHP_BUG("");
    goto error;
  }

  res_my_id_req = (rhp_ipcmsg_resolve_my_id_req*)ipcmsg;

	eap_sup_enabled = rhp_auth_sup_is_enabled(res_my_id_req->my_realm_id,
											&eap_sup_method,&eap_sup_ask_for_user_key,
											&eap_sup_user_key_cache_enabled);

	auth_rlm =  rhp_auth_realm_get(res_my_id_req->my_realm_id);
  if( auth_rlm == NULL ){
    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_RESOLVE_MY_ID_REQ_NO_REALM,"u",res_my_id_req->my_realm_id);
    goto failed;
  }

  RHP_LOCK(&(auth_rlm->lock));

  if( auth_rlm->my_auth == NULL ){
    RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_RESOLVE_MY_ID_REQ_NO_AUTH_INFO,"xu",auth_rlm,auth_rlm->id);
    goto failed_l;
  }

  if( auth_rlm->my_auth->my_id.type ){

  	if( rhp_ikev2_id_value(&(auth_rlm->my_auth->my_id),&id_value,&id_len,&id_type) ){
  		RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_RESOLVE_MY_ID_REQ_ID_NO_ID,"xp",auth_rlm,sizeof(rhp_ikev2_id),&(auth_rlm->my_auth->my_id));
  		goto failed_l;
  	}

  }else if( !eap_sup_enabled ){

		RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_RESOLVE_MY_ID_REQ_ID_NO_ID_2,"xp",auth_rlm,sizeof(rhp_ikev2_id),&(auth_rlm->my_auth->my_id));
		goto failed_l;
  }

  my_auth_method = auth_rlm->my_auth->auth_method;
  xauth_method = auth_rlm->xauth.p1_auth_method;
  psk_for_peers = auth_rlm->psk_for_peers;
  rsa_sig_for_peers = auth_rlm->rsa_sig_for_peers;
  eap_for_peers = auth_rlm->eap_for_peers;
  null_auth_for_peers = auth_rlm->null_auth_for_peers;


  if( auth_rlm->my_auth->cert_store ){

  	auth_rlm->my_auth->cert_store->get_my_cert_issuer_dn_der(
  			auth_rlm->my_auth->cert_store,&untrust_sub_ca_cert_issuer_dn_der,&untrust_sub_ca_cert_issuer_dn_der_len);

  	auth_rlm->my_auth->cert_store->get_untrust_sub_ca_issuer_dn_der(auth_rlm->my_auth->cert_store,
  			&untrust_sub_ca_cert_issuer_dn_der,&untrust_sub_ca_cert_issuer_dn_der_len);
  }


  result = 1;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_RESOLVE_MY_ID_REQ_ID_FOUND,"dp",id_type,id_len,id_value);

failed_l:
  RHP_UNLOCK(&(auth_rlm->lock));
failed:

  resolve_my_id_rep
  = rhp_auth_ipc_alloc_rslv_my_id_rep(res_my_id_req->my_realm_id,res_my_id_req->txn_id,result,
  		id_type,id_len,id_value,my_auth_method,xauth_method,
  		eap_sup_enabled,eap_sup_ask_for_user_key,eap_sup_method,eap_sup_user_key_cache_enabled,
  		psk_for_peers,rsa_sig_for_peers,eap_for_peers,null_auth_for_peers,
  		my_cert_issuer_dn_der_len,my_cert_issuer_dn_der,
  		untrust_sub_ca_cert_issuer_dn_der_len,untrust_sub_ca_cert_issuer_dn_der);

  if( resolve_my_id_rep == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

  if( id_value ){
    _rhp_free(id_value);
  }

  if( auth_rlm ){
  	rhp_auth_realm_unhold(auth_rlm);
  }

  if( my_cert_issuer_dn_der ){
  	_rhp_free(my_cert_issuer_dn_der);
  }
  if( untrust_sub_ca_cert_issuer_dn_der ){
  	_rhp_free(untrust_sub_ca_cert_issuer_dn_der);
  }


  *ipcmsg_r = (rhp_ipcmsg*)resolve_my_id_rep;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_RESOLVE_MY_ID_REQ_RTRN,"xpu",ipcmsg,resolve_my_id_rep->len,resolve_my_id_rep,result);
  return 0;

error:
  if( id_value ){
    _rhp_free(id_value);
  }
	if( auth_rlm ){
    rhp_auth_realm_unhold(auth_rlm);
	}
  if( my_cert_issuer_dn_der ){
  	_rhp_free(my_cert_issuer_dn_der);
  }
  if( untrust_sub_ca_cert_issuer_dn_der ){
  	_rhp_free(untrust_sub_ca_cert_issuer_dn_der);
  }
  RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_RESOLVE_MY_ID_REQ_ERR,"x",ipcmsg);
  return err;
}

int rhp_auth_ipc_send_ca_pubkey_digests_update()
{
	int err = -EINVAL;
	u8 *digests = NULL, *dns = NULL;
	int digests_len = 0, dns_len = 0, dns_num = 0;
	rhp_ipcmsg_ca_pubkey_digests* ipcmsg = NULL;
	u8* p;

  RHP_TRC(0,RHPTRCID_AUTH_IPC_SEND_CA_PUBKEY_DIGESTS_UPDATE,"");

  rhp_cert_store_all_ca_pubkey_digests(&digests,&digests_len,rhp_gcfg_ca_pubkey_digests_max_size);

  rhp_cert_store_all_ca_dns_der(&dns,&dns_len,&dns_num,rhp_gcfg_ca_dn_ders_max_size);

  if( digests_len < 1 && dns_len < 1 ){
  	err = -ENOENT;
		goto error;
	}


	ipcmsg = (rhp_ipcmsg_ca_pubkey_digests*)rhp_ipc_alloc_msg(
						RHP_IPC_CA_PUBKEY_DIGESTS_UPDATE,sizeof(rhp_ipcmsg_ca_pubkey_digests) + digests_len + dns_len);

	if( ipcmsg == NULL ){
		RHP_BUG("");
		goto error;
	}

	ipcmsg->len = sizeof(rhp_ipcmsg_ca_pubkey_digests) + digests_len + dns_len;
	ipcmsg->pubkey_digest_len = RHP_PROTO_IKE_CERTENC_SHA1_DIGEST_LEN; // SHA-1 MD
	ipcmsg->pubkey_digests_len = digests_len;
	ipcmsg->dn_ders_len = dns_len;
	ipcmsg->dn_ders_num = dns_num;
	p = (u8*)(ipcmsg + 1);
	if( digests_len ){
		memcpy(p,digests,digests_len);
		p += digests_len;
	}
	if( dns_len ){
		memcpy(p,dns,dns_len);
		p += dns_len;
	}


	if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipcmsg,ipcmsg->len,0) < 0 ){
	  goto error;
  }

	if( digests ){
		_rhp_free(digests);
	}
	if( dns ){
		_rhp_free(dns);
	}
	_rhp_free_zero(ipcmsg,ipcmsg->len);

  RHP_TRC(0,RHPTRCID_AUTH_IPC_SEND_CA_PUBKEY_DIGESTS_UPDATE_RTRN,"");
	return 0;

error:
	if( ipcmsg ){
		_rhp_free_zero(ipcmsg,ipcmsg->len);
	}
	if( digests ){
		_rhp_free(digests);
	}
	if( dns ){
		_rhp_free(dns);
	}
  RHP_TRC(0,RHPTRCID_AUTH_IPC_SEND_CA_PUBKEY_DIGESTS_UPDATE_ERR,"E",err);
	return err;
}

int rhp_auth_ipc_handle(rhp_ipcmsg *ipcmsg)
{
  int err = -EINVAL;
  rhp_ipcmsg *ipc_tx_msg = NULL;

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return -EPERM;
  }

  switch( ipcmsg->type ){

    case RHP_IPC_AUTH_BASIC_REQUEST:

      err = _rhp_auth_ipc_handle_auth_basic_req(ipcmsg,&ipc_tx_msg);
      _rhp_free_zero(ipcmsg,ipcmsg->len);
      break;

    case RHP_IPC_AUTH_COOKIE_REQUEST:

      err = _rhp_auth_ipc_handle_auth_cookie_req(ipcmsg,&ipc_tx_msg);
      _rhp_free_zero(ipcmsg,ipcmsg->len);
      break;

    case RHP_IPC_SIGN_REQUEST:

    	// TODO : rhp_prc_ipcmsg_wts_handler should be used for IKEv2's heavy crypto processing.
      err = _rhp_auth_ipc_handle_sign_req(ipcmsg,&ipc_tx_msg);
      break;

    case RHP_IPC_VERIFY_PSK_REQUEST:

    	// TODO : rhp_prc_ipcmsg_wts_handler should be used for IKEv2's heavy crypto processing.
    	err = _rhp_auth_ipc_handle_verify_psk_req(ipcmsg,&ipc_tx_msg,NULL,NULL);
      _rhp_free_zero(ipcmsg,ipcmsg->len);
      break;

    case RHP_IPC_VERIFY_RSASIG_REQUEST:

    	// TODO : rhp_prc_ipcmsg_wts_handler should be used for IKEv2's heavy crypto processing.
      err = _rhp_auth_ipc_handle_verify_rsasig_req(ipcmsg,&ipc_tx_msg,NULL,NULL);
      if( err ){
        _rhp_free_zero(ipcmsg,ipcmsg->len);
      }
      break;

    case RHP_IPC_CA_PUBKEY_DIGESTS_REQUEST:

    	// TODO : rhp_prc_ipcmsg_wts_handler should be used for IKEv2's heavy crypto processing.
      err = _rhp_auth_ipc_handle_ca_keys_req(ipcmsg,&ipc_tx_msg);
      _rhp_free_zero(ipcmsg,ipcmsg->len);
      break;

    case RHP_IPC_RESOLVE_MY_ID_REQUEST:

      err = _rhp_auth_ipc_handle_resolve_my_id_req(ipcmsg,&ipc_tx_msg);
      _rhp_free_zero(ipcmsg,ipcmsg->len);

      if( err ){
         goto error;
      }
      break;

    case RHP_IPC_VERIFY_AND_SIGN_REQUEST:

    	// TODO : rhp_prc_ipcmsg_wts_handler should be used for IKEv2's heavy crypto processing.
    	err = _rhp_auth_ipc_handle_verify_and_sign_req(ipcmsg,&ipc_tx_msg);
      if( err ){
        _rhp_free_zero(ipcmsg,ipcmsg->len);
        goto error;
      }
      break;

    default:
      RHP_BUG("%d,",ipcmsg->type);
      goto error;
  }

  if( ipc_tx_msg ){

    if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipc_tx_msg,ipc_tx_msg->len,0) < 0 ){
      RHP_TRC(0,RHPTRCID_AUTH_IPC_HANDLE_IPC_SEND_ERR,"xxdd",RHP_MY_PROCESS,ipc_tx_msg,ipc_tx_msg->len,0);
    }
    _rhp_free_zero(ipc_tx_msg,ipc_tx_msg->len);
  }

error:
  return err;
}



