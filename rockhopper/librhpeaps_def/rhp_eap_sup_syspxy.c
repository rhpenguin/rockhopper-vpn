/*

	Copyright (C) 2009-2012 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.

 	This library can be distributed under the terms of BSD license.
 	Also see the original wpa_supplicant's README.

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

#include "wpa_supplicant/includes.h"

#include "wpa_supplicant/common.h"
#include "wpa_supplicant/ms_funcs.h"
#include "wpa_supplicant/eap_i.h"

#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_protocol.h"
#include "rhp_packet.h"
#include "rhp_netsock.h"
#include "rhp_wthreads.h"
#include "rhp_process.h"
#include "rhp_config.h"
#include "rhp_vpn.h"
#include "rhp_eap_sup_impl.h"


#define RHP_EAP_SUP_HASH_TABLE_SIZE		11

static rhp_mutex_t _rhp_eap_sup_syspxy_lock;

struct _rhp_eap_sup_sess {

	u8 tag[4]; // '#EPS'

	struct _rhp_eap_sup_sess* next;

	int method_type;
	const struct eap_method* method;
	void* method_ctx;

  unsigned long vpn_realm_id;

  u8 unique_id[RHP_VPN_UNIQUE_ID_SIZE]; // RHP_VPN_UNIQUE_ID_SIZE: 16bytes
  unsigned int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 spi[RHP_PROTO_IKE_SPI_SIZE];

  u64 pend_eap_req_txn_id;
  rhp_ipcmsg* pend_eap_req;

	int tmp_user_id_len;
	u8* tmp_user_id;
	int tmp_user_key_len;
	u8* tmp_user_key;

  time_t created;
};
typedef struct _rhp_eap_sup_sess rhp_eap_sup_sess;

static rhp_eap_sup_sess* _rhp_eap_sup_sess_hashtbl[RHP_EAP_SUP_HASH_TABLE_SIZE];

static u32 _rhp_eap_sup_unique_id_hash(u8* unique_id)
{
  u32 *hval;
  hval = ((u32*)(((u64*)unique_id) + 1)) + 1;
  return  (*hval % RHP_EAP_SUP_HASH_TABLE_SIZE);
}

static rhp_eap_sup_sess* _rhp_eap_sup_alloc(int eap_vendor,int eap_type,unsigned long rlm_id,
		u8* unique_id,int side,u8* spi)
{
	rhp_eap_sup_sess* s_sess = (rhp_eap_sup_sess*)_rhp_malloc(sizeof(rhp_eap_sup_sess));

  RHP_TRC(0,RHPTRCID_EAP_SUP_ALLOC,"dLdupLdG",eap_vendor,"EAP_TYPE",eap_type,rlm_id,RHP_VPN_UNIQUE_ID_SIZE,unique_id,"IKE_SIDE",side,spi);

	if( s_sess == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(s_sess,0,sizeof(rhp_eap_sup_sess));

	s_sess->tag[0] = '#';
	s_sess->tag[1] = 'E';
	s_sess->tag[2] = 'P';
	s_sess->tag[3] = 'S';

	s_sess->method_type = eap_type;

	s_sess->method = eap_peer_get_eap_method(eap_vendor,(EapType)eap_type);
	if( s_sess->method == NULL ){
		RHP_BUG("%d",eap_type);
		_rhp_free(s_sess);
		return NULL;
	}

	s_sess->method_ctx = s_sess->method->init();
	if( s_sess->method_ctx == NULL ){
		RHP_BUG("%d",eap_type);
		_rhp_free(s_sess);
		return NULL;
	}


	s_sess->vpn_realm_id = rlm_id;
	memcpy(s_sess->unique_id,unique_id,RHP_VPN_UNIQUE_ID_SIZE);

	s_sess->side = side;
	memcpy(s_sess->spi,spi,RHP_PROTO_IKE_SPI_SIZE);


	s_sess->created = _rhp_get_time();

  RHP_TRC(0,RHPTRCID_EAP_SUP_ALLOC_RTRN,"dLdupLdGxxx",eap_vendor,"EAP_TYPE",eap_type,rlm_id,RHP_VPN_UNIQUE_ID_SIZE,unique_id,"IKE_SIDE",side,spi,s_sess,s_sess->method,s_sess->method_ctx);
	return s_sess;
}

static int _rhp_eap_sup_delete(rhp_eap_sup_sess* s_sess_d)
{
	int hval;
	rhp_eap_sup_sess *s_sess = NULL,*s_sess_p = NULL;

	RHP_TRC(0,RHPTRCID_EAP_SUP_DELETE,"xup",s_sess_d,s_sess_d->vpn_realm_id,RHP_VPN_UNIQUE_ID_SIZE,s_sess_d->unique_id);

  RHP_LOCK(&_rhp_eap_sup_syspxy_lock);

  hval = _rhp_eap_sup_unique_id_hash(s_sess_d->unique_id);

  s_sess = _rhp_eap_sup_sess_hashtbl[hval];

  while( s_sess ){

    if( s_sess == s_sess_d ){
   	  break;
    }

    s_sess_p = s_sess;
    s_sess = s_sess->next;
  }

  if( s_sess ){

  	if( s_sess_p ){
  		s_sess_p->next = s_sess->next;
  	}else{
  		_rhp_eap_sup_sess_hashtbl[hval] = s_sess->next;
  	}

  	s_sess->method->cleanup(s_sess->method_ctx);

  	if(s_sess->pend_eap_req){
  		_rhp_free_zero(s_sess->pend_eap_req,s_sess->pend_eap_req->len);
  	}

  	if( s_sess->tmp_user_id ){
  		_rhp_free_zero(s_sess->tmp_user_id,s_sess->tmp_user_id_len);
  	}
  	if( s_sess->tmp_user_key ){
  		_rhp_free_zero(s_sess->tmp_user_key,s_sess->tmp_user_key_len);
  	}

  	_rhp_free(s_sess);

  }else{

  	RHP_TRC(0,RHPTRCID_EAP_SUP_DELETE_NOT_FOUND,"x",s_sess_d);

    RHP_UNLOCK(&_rhp_eap_sup_syspxy_lock);
    return -ENOENT;
  }

  RHP_UNLOCK(&_rhp_eap_sup_syspxy_lock);

	RHP_TRC(0,RHPTRCID_EAP_SUP_DELETE_RTRN,"x",s_sess_d);
  return 0;
}

static rhp_eap_sup_sess* _rhp_eap_sup_get(u8* unique_id)
{
	rhp_eap_sup_sess* s_sess = NULL;
  u32 hval;

	RHP_TRC(0,RHPTRCID_EAP_SUP_GET,"p",RHP_VPN_UNIQUE_ID_SIZE,unique_id);

  RHP_LOCK(&_rhp_eap_sup_syspxy_lock);

  hval = _rhp_eap_sup_unique_id_hash(unique_id);

  s_sess = _rhp_eap_sup_sess_hashtbl[hval];

  while( s_sess ){

  	if( !memcmp(unique_id,s_sess->unique_id,RHP_VPN_UNIQUE_ID_SIZE) ){
  		break;
  	}

  	s_sess = s_sess->next;
  }

  RHP_UNLOCK(&_rhp_eap_sup_syspxy_lock);

	RHP_TRC(0,RHPTRCID_EAP_SUP_GET_RTRN,"px",RHP_VPN_UNIQUE_ID_SIZE,unique_id,s_sess);
  return s_sess;
}

static void _rhp_eap_sup_put(rhp_eap_sup_sess* s_sess)
{
  u32 hval;

	RHP_TRC(0,RHPTRCID_EAP_SUP_PUT,"px",RHP_VPN_UNIQUE_ID_SIZE,s_sess->unique_id,s_sess);

  RHP_LOCK(&_rhp_eap_sup_syspxy_lock);

  hval = _rhp_eap_sup_unique_id_hash(s_sess->unique_id);

  s_sess->next = _rhp_eap_sup_sess_hashtbl[hval];
  _rhp_eap_sup_sess_hashtbl[hval] = s_sess;

  RHP_UNLOCK(&_rhp_eap_sup_syspxy_lock);

  return;
}


static int _rhp_eap_sup_get_auth_key(void* ctx,u8** user_name_r, size_t* user_name_len_r,
		u8** key_r, size_t* key_len_r)
{
	int err = -ENOENT;
	rhp_eap_sup_sess* s_sess = (rhp_eap_sup_sess*)ctx;
	u8 *user_id = NULL, *key = NULL;
	size_t user_id_len = 0, key_len = 0;
	rhp_vpn_auth_realm* auth_rlm = NULL;
	u8 *user_id_tmp = NULL, *user_key_tmp = NULL;
	size_t user_id_tmp_len = 0, user_key_tmp_len = 0;

	RHP_TRC(0,RHPTRCID_EAP_SUP_GET_AUTH_KEY,"xxxxx",s_sess,user_name_r,user_name_len_r,key_r,key_len_r);

	auth_rlm = rhp_auth_realm_get(s_sess->vpn_realm_id);
	if( auth_rlm == NULL ){
		RHP_BUG("%d",s_sess->vpn_realm_id);
		err = -ENOENT;
		goto error;
	}

	RHP_LOCK(&(auth_rlm->lock));

	if( auth_rlm->my_auth == NULL || auth_rlm->eap.role != RHP_EAP_SUPPLICANT ){
		RHP_BUG("");
		err = -EINVAL;
		goto error_l;
	}

	if( s_sess->tmp_user_id && s_sess->tmp_user_key ){

		user_id_tmp_len = s_sess->tmp_user_id_len;
		user_id_tmp = s_sess->tmp_user_id;

		user_key_tmp_len = s_sess->tmp_user_key_len;
		user_key_tmp = s_sess->tmp_user_key;

		RHP_TRC(0,RHPTRCID_EAP_SUP_GET_AUTH_KEY_TMP_KEY,"xxxpp",s_sess,auth_rlm,auth_rlm->my_auth,user_id_tmp_len,user_id_tmp,user_key_tmp_len,user_key_tmp);

	}else{

		if( auth_rlm->my_auth->eap_sup.user_key_cache_enabled &&
				auth_rlm->my_auth->eap_sup.cached_user_id &&
				auth_rlm->my_auth->eap_sup.cached_user_key ){

			user_id_tmp_len = auth_rlm->my_auth->eap_sup.cached_user_id_len;
			user_id_tmp = auth_rlm->my_auth->eap_sup.cached_user_id;

			user_key_tmp_len = auth_rlm->my_auth->eap_sup.cached_user_key_len;
			user_key_tmp = auth_rlm->my_auth->eap_sup.cached_user_key;

			RHP_TRC(0,RHPTRCID_EAP_SUP_GET_AUTH_KEY_CACHED_KEY,"xxxpp",s_sess,auth_rlm,auth_rlm->my_auth,user_id_tmp_len,user_id_tmp,user_key_tmp_len,user_key_tmp);
			RHP_LOG_D(RHP_LOG_SRC_AUTH,s_sess->vpn_realm_id,RHP_LOG_ID_EAP_PEER_GET_USER_KEY_CACHED,"a",user_id_tmp_len,user_id_tmp);

		}else if( !rhp_eap_id_is_null(&(auth_rlm->my_auth->my_eap_sup_id)) &&
							auth_rlm->my_auth->my_psks &&
							auth_rlm->my_auth->my_psks->key ){

			user_id_tmp_len = auth_rlm->my_auth->my_eap_sup_id.identity_len;
			user_id_tmp = auth_rlm->my_auth->my_eap_sup_id.identity;

			user_key_tmp_len = strlen((char*)(auth_rlm->my_auth->my_psks->key));
			user_key_tmp = auth_rlm->my_auth->my_psks->key;

			RHP_TRC(0,RHPTRCID_EAP_SUP_GET_AUTH_KEY_CONFIGURED_KEY,"xxxpp",s_sess,auth_rlm,auth_rlm->my_auth,user_id_tmp_len,user_id_tmp,user_key_tmp_len,user_key_tmp);
			RHP_LOG_D(RHP_LOG_SRC_AUTH,s_sess->vpn_realm_id,RHP_LOG_ID_EAP_PEER_GET_USER_KEY_CONFIGURED,"a",user_id_tmp_len,user_id_tmp);

		}else{

			RHP_TRC(0,RHPTRCID_EAP_SUP_GET_AUTH_KEY_NOT_FOUND,"xxx",s_sess,auth_rlm,auth_rlm->my_auth);

			err = -ENOENT;
			goto error_l;
		}
	}

	user_id_len = user_id_tmp_len;
	key_len = user_key_tmp_len;

	user_id = (u8*)_rhp_malloc(user_id_len + 1);
	key = (u8*)_rhp_malloc(key_len + 1);

	if( user_id == NULL || key == NULL ){

		RHP_BUG("");
		err = -ENOMEM;
		goto error_l;
	}

	memcpy(user_id,user_id_tmp,user_id_len);
	user_id[user_id_len] = '\0';
	memcpy(key,user_key_tmp,key_len);
	key[key_len] = '\0';

	RHP_UNLOCK(&(auth_rlm->lock));
	rhp_auth_realm_unhold(auth_rlm);


	*user_name_r = user_id;
	*user_name_len_r = user_id_len;

	if( key_r ){
		*key_r = key;
		*key_len_r = key_len;
	}else{
		_rhp_free_zero(key,key_len);
	}

	RHP_TRC(0,RHPTRCID_EAP_SUP_GET_AUTH_KEY_RTRN,"xx",s_sess,auth_rlm);
	return 0;

error_l:
	RHP_UNLOCK(&(auth_rlm->lock));
	rhp_auth_realm_unhold(auth_rlm);
error:
	if( user_id ){
		_rhp_free_zero(user_id,user_id_len);
	}
	if( key ){
		_rhp_free_zero(key,key_len);
	}

	RHP_LOG_DE(RHP_LOG_SRC_AUTH,s_sess->vpn_realm_id,RHP_LOG_ID_EAP_PEER_GET_USER_KEY_ERR,"E",err);

	RHP_TRC(0,RHPTRCID_EAP_SUP_GET_AUTH_KEY_ERR,"xxE",s_sess,auth_rlm,err);
	return err;
}


static int _rhp_eap_sup_syspxy_set_cached_user_key(unsigned long rlm_id,
		u8* user_id,size_t user_id_len,u8* user_key,size_t user_key_len)
{
	int err = -EINVAL;
	rhp_vpn_auth_realm* auth_rlm = NULL;
	rhp_my_auth* my_auth;

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_SET_CACHED_USER_KEY,"upp",rlm_id,user_id_len,user_id,user_key_len,user_key);

	auth_rlm = rhp_auth_realm_get(rlm_id);
	if( auth_rlm == NULL ){
		RHP_BUG("%d",rlm_id);
		err = -ENOENT;
		goto error;
	}

	RHP_LOCK(&(auth_rlm->lock));

	my_auth = auth_rlm->my_auth;

	if( my_auth == NULL ){
		RHP_BUG("%d",rlm_id);
		err = -ENOENT;
		goto error_l;
	}

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_SET_CACHED_USER_KEY_OLD_INFO,"uxxdpp",rlm_id,auth_rlm,my_auth,my_auth->eap_sup.user_key_cache_enabled,my_auth->eap_sup.cached_user_id_len,my_auth->eap_sup.cached_user_id,my_auth->eap_sup.cached_user_key_len,my_auth->eap_sup.cached_user_key);

	if( !my_auth->eap_sup.user_key_cache_enabled ){
		err = 0;
		goto ignore_l;
	}

	if( my_auth->eap_sup.cached_user_id ){
		_rhp_free_zero(my_auth->eap_sup.cached_user_id,my_auth->eap_sup.cached_user_id_len);
		my_auth->eap_sup.cached_user_id = NULL;
		my_auth->eap_sup.cached_user_id_len = 0;
	}

	if( my_auth->eap_sup.cached_user_key ){
		_rhp_free_zero(my_auth->eap_sup.cached_user_key,my_auth->eap_sup.cached_user_key_len);
		my_auth->eap_sup.cached_user_key = NULL;
		my_auth->eap_sup.cached_user_key_len = 0;
	}

	my_auth->eap_sup.cached_user_id = (u8*)_rhp_malloc(user_id_len);
	my_auth->eap_sup.cached_user_key = (u8*)_rhp_malloc(user_key_len);

	if( my_auth->eap_sup.cached_user_id == NULL || my_auth->eap_sup.cached_user_key == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error_l;
	}

	my_auth->eap_sup.cached_user_id_len = (size_t)user_id_len;
	my_auth->eap_sup.cached_user_key_len = (size_t)user_key_len;
	memcpy(my_auth->eap_sup.cached_user_id,user_id,user_id_len);
	memcpy(my_auth->eap_sup.cached_user_key,user_key,user_key_len);

	RHP_UNLOCK(&(auth_rlm->lock));
	rhp_auth_realm_unhold(auth_rlm);

	{
		rhp_ipcmsg_eap_user_key_cached ipc_msg;
		memset(&ipc_msg,0,sizeof(rhp_ipcmsg_eap_user_key_cached));

		ipc_msg.tag[0] = '#';
		ipc_msg.tag[1] = 'I';
		ipc_msg.tag[2] = 'M';
		ipc_msg.tag[3] = 'S';

		ipc_msg.len = sizeof(rhp_ipcmsg_eap_user_key_cached);
		ipc_msg.type = RHP_IPC_EAP_SUP_USER_KEY_CACHED;
		ipc_msg.vpn_realm_id = rlm_id;

		if( rhp_ipc_send(RHP_MY_PROCESS,(void*)&ipc_msg,ipc_msg.len,0) < 0 ){
			RHP_BUG("");
    }
	}

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_SET_CACHED_USER_KEY_RTRN,"ux",rlm_id,auth_rlm);
	return 0;

error_l:
ignore_l:
	RHP_UNLOCK(&(auth_rlm->lock));
	rhp_auth_realm_unhold(auth_rlm);
error:
	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_SET_CACHED_USER_KEY_ERR,"uxE",rlm_id,auth_rlm,err);
	return err;
}

static void _rhp_eap_sup_syspxy_clear_cached_user_key(unsigned long rlm_id)
{
	rhp_vpn_auth_realm* auth_rlm = NULL;
	rhp_my_auth* my_auth;

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_CLEAR_CACHED_USER_KEY,"u",rlm_id);

	auth_rlm = rhp_auth_realm_get(rlm_id);
	if( auth_rlm == NULL ){
		RHP_BUG("%d",rlm_id);
		goto error;
	}

	RHP_LOCK(&(auth_rlm->lock));

	my_auth = auth_rlm->my_auth;

	if( my_auth == NULL ){
		RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_CLEAR_CACHED_USER_KEY_NO_MY_AUTH,"ux",rlm_id,auth_rlm);
		goto error_l;
	}

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_CLEAR_CACHED_USER_KEY_OLD_INFO,"uxxdpp",rlm_id,auth_rlm,my_auth,my_auth->eap_sup.user_key_cache_enabled,my_auth->eap_sup.cached_user_id_len,my_auth->eap_sup.cached_user_id,my_auth->eap_sup.cached_user_key_len,my_auth->eap_sup.cached_user_key);

	if( my_auth->eap_sup.cached_user_id ){

		RHP_LOG_D(RHP_LOG_SRC_AUTH,rlm_id,RHP_LOG_ID_EAP_PEER_CLEAR_CACHED_USER_KEY,"a",my_auth->eap_sup.cached_user_id_len,my_auth->eap_sup.cached_user_id);

		_rhp_free_zero(my_auth->eap_sup.cached_user_id,my_auth->eap_sup.cached_user_id_len);
		my_auth->eap_sup.cached_user_id = NULL;
		my_auth->eap_sup.cached_user_id_len = 0;
	}

	if( my_auth->eap_sup.cached_user_key ){
		_rhp_free_zero(my_auth->eap_sup.cached_user_key,my_auth->eap_sup.cached_user_key_len);
		my_auth->eap_sup.cached_user_key = NULL;
		my_auth->eap_sup.cached_user_key_len = 0;
	}

error_l:
	RHP_UNLOCK(&(auth_rlm->lock));

error:
	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_CLEAR_CACHED_USER_KEY_RTRN,"ux",rlm_id,auth_rlm);
	return;
}

static int _rhp_eap_sup_syspxy_set_user_key(rhp_eap_sup_sess* s_sess,
		u8* user_id,size_t user_id_len,u8* user_key,size_t user_key_len)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_SET_USER_KEY,"xpp",s_sess,user_id_len,user_id,user_key_len,user_key);

	if( s_sess->tmp_user_id ){
		_rhp_free(s_sess->tmp_user_id);
		s_sess->tmp_user_id = NULL;
		s_sess->tmp_user_id_len = 0;
	}

	if( s_sess->tmp_user_key ){
		_rhp_free(s_sess->tmp_user_key);
		s_sess->tmp_user_key = NULL;
		s_sess->tmp_user_key_len = 0;
	}

	s_sess->tmp_user_id = (u8*)_rhp_malloc(user_id_len);
	s_sess->tmp_user_key = (u8*)_rhp_malloc(user_key_len);

	if( s_sess->tmp_user_id == NULL || s_sess->tmp_user_key == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	s_sess->tmp_user_id_len = (size_t)user_id_len;
	s_sess->tmp_user_key_len = (size_t)user_key_len;
	memcpy(s_sess->tmp_user_id,user_id,user_id_len);
	memcpy(s_sess->tmp_user_key,user_key,user_key_len);

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_SET_USER_KEY_RTRN,"x",s_sess);
	return 0;

error:
	if( s_sess->tmp_user_id ){
		_rhp_free(s_sess->tmp_user_id);
		s_sess->tmp_user_id = NULL;
		s_sess->tmp_user_id_len = 0;
	}
	if( s_sess->tmp_user_key ){
		_rhp_free(s_sess->tmp_user_key);
		s_sess->tmp_user_key = NULL;
		s_sess->tmp_user_key_len = 0;
	}

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_SET_USER_KEY_ERR,"xE",s_sess,err);
	return err;
}

static rhp_eap_sup_sess* _rhp_eap_sup_setup_sess(unsigned long rlm_id,u8* unique_id,
		int my_ikesa_side,u8* my_ikesa_spi)
{
	rhp_eap_sup_sess* s_sess = NULL;
	rhp_vpn_auth_realm* auth_rlm = NULL;

	RHP_TRC(0,RHPTRCID_EAP_SUP_SETUP_SESS,"upLdG",rlm_id,RHP_VPN_UNIQUE_ID_SIZE,unique_id,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);

	auth_rlm = rhp_auth_realm_get(rlm_id);
	if( auth_rlm == NULL ){
		RHP_BUG("%d",rlm_id);
		goto error;
	}

	RHP_LOCK(&(auth_rlm->lock));

	s_sess = _rhp_eap_sup_alloc(auth_rlm->eap.eap_vendor,auth_rlm->eap.method,auth_rlm->id,
						unique_id,my_ikesa_side,my_ikesa_spi);

	if( s_sess == NULL ){

		RHP_BUG("");

		RHP_UNLOCK(&(auth_rlm->lock));
		rhp_auth_realm_unhold(auth_rlm);

		goto error;
	}

	RHP_UNLOCK(&(auth_rlm->lock));
	rhp_auth_realm_unhold(auth_rlm);

  _rhp_eap_sup_put(s_sess);

	RHP_TRC(0,RHPTRCID_EAP_SUP_SETUP_SESS_RTRN,"uxx",rlm_id,unique_id,s_sess);
  return s_sess;

error:
	RHP_TRC(0,RHPTRCID_EAP_SUP_SETUP_SESS_ERR,"ux",rlm_id,unique_id);
	return NULL;
}


static void _rhp_eap_sup_syspxy_req_ipc_handler_impl(rhp_ipcmsg** ipcmsg,int retry_user_key)
{
	int err = -EINVAL;
	rhp_eap_sup_sess* s_sess = NULL;
  struct wpabuf *rx_wbuf = NULL, *tx_wbuf = NULL;
  u8 *eap_msg_rx;
  int eap_msg_rx_len;
  int eap_status = RHP_EAP_STAT_ERROR;
  rhp_ipcmsg* ipcmsg_rep = NULL;
  size_t msk_len = 0;
  u8* msk = NULL;
  struct eap_method_ret eap_proc_ret;
  u8* my_user_id = NULL;
  size_t my_user_id_len = 0;
  unsigned long rlm_id = 0;

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_REQ_IPC_HANDLER_IMPL,"xx",ipcmsg,*ipcmsg);

	memset(&eap_proc_ret,0,sizeof(struct eap_method_ret));

	if( (*ipcmsg)->len < sizeof(rhp_ipcmsg) ){
		RHP_BUG("");
		goto error_no_log;
	}

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_REQ_IPC_HANDLER_IMPL_TYPE,"xLd",*ipcmsg,"IPC",(*ipcmsg)->type);

	if( (*ipcmsg)->type != RHP_IPC_EAP_SUP_HANDLE_REQUEST ){

		RHP_BUG("%d",(*ipcmsg)->type);
		goto error;

	}else{

		rhp_ipcmsg_eap_handle_req* ipc_req = (rhp_ipcmsg_eap_handle_req*)*ipcmsg;

		if( ipc_req->len < sizeof(rhp_ipcmsg_eap_handle_req) ){
			RHP_BUG("%d",ipc_req->len);
			goto error;
		}

  	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_REQ_IPC_HANDLER_IMPL_REQUEST,"xLdudpLdGd",ipc_req,"IPC",ipc_req->type,ipc_req->vpn_realm_id,ipc_req->init_req,RHP_VPN_UNIQUE_ID_SIZE,ipc_req->unique_id,"IKE_SIDE",ipc_req->side,ipc_req->spi,ipc_req->eap_mesg_len);

		if( ipc_req->vpn_realm_id < 1 ){
			RHP_BUG("");
			goto error;
		}

		rlm_id = ipc_req->vpn_realm_id;

		s_sess = _rhp_eap_sup_get(ipc_req->unique_id);
		if( s_sess == NULL ){

			if( retry_user_key ){
				RHP_BUG("");
	    	eap_status = RHP_EAP_STAT_ERROR;
	    	goto error_resp;
			}

	    s_sess = _rhp_eap_sup_setup_sess(ipc_req->vpn_realm_id,
	    		ipc_req->unique_id,ipc_req->side,ipc_req->spi);

	    if( s_sess == NULL ){
	    	eap_status = RHP_EAP_STAT_ERROR;
	    	goto error_resp;
	    }
		}


		eap_msg_rx = (u8*)(ipc_req + 1);
		eap_msg_rx_len = ipc_req->eap_mesg_len;

		if( eap_msg_rx_len < sizeof(rhp_proto_eap) ){
			RHP_BUG("");
			eap_status = RHP_EAP_STAT_ERROR;
    	goto error_resp;
		}

		rx_wbuf = wpabuf_alloc_ext_data(eap_msg_rx,eap_msg_rx_len);
		if( rx_wbuf == NULL ){
			RHP_BUG("");
			eap_status = RHP_EAP_STAT_ERROR;
    	goto error_resp;
		}


		tx_wbuf = s_sess->method->process(s_sess->method_ctx,&eap_proc_ret,rx_wbuf,
							_rhp_eap_sup_get_auth_key,(void*)s_sess);

		if( !s_sess->method->isDone(s_sess->method_ctx) ){

			eap_status = RHP_EAP_STAT_CONTINUE;

			RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_REQ_IPC_HANDLER_IMPL_REQUEST_IS_DONE_CONTINUE,"x",ipc_req);

			if( s_sess->method->newKeyIsRequired(s_sess->method_ctx) ){

				rhp_ipcmsg_eap_user_key_req* ipc_key_req = NULL;
	  	  int ipc_key_req_len = sizeof(rhp_ipcmsg_eap_user_key_req);
				u8 *user_name = NULL, *key = NULL;
				size_t user_name_len = 0, key_len = 0;

				RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_REQ_IPC_HANDLER_IMPL_REQUEST_REQUEST_NEW_KEY,"x",ipc_req);

				err = _rhp_eap_sup_get_auth_key((void*)s_sess,&user_name,&user_name_len,&key,&key_len); // Old invalid id and key.
				if( err ){
					RHP_BUG("");
					eap_status = RHP_EAP_STAT_ERROR;
					goto error_resp;
				}

				ipc_key_req_len += user_name_len;

				ipc_key_req = (rhp_ipcmsg_eap_user_key_req*)rhp_ipc_alloc_msg(RHP_IPC_EAP_SUP_USER_KEY_REQUEST,ipc_key_req_len);
				if(ipc_key_req == NULL){
					RHP_BUG("");
					goto error;
				}
				ipc_key_req->len = ipc_key_req_len;

				ipc_key_req->txn_id = ipc_req->txn_id;
				ipc_key_req->vpn_realm_id = ipc_req->vpn_realm_id;
				memcpy(ipc_key_req->unique_id,ipc_req->unique_id,RHP_VPN_UNIQUE_ID_SIZE);
				ipc_key_req->side = ipc_req->side;
				memcpy(ipc_key_req->spi,ipc_req->spi,RHP_PROTO_IKE_SPI_SIZE);

				ipc_key_req->eap_method = (unsigned int)s_sess->method_type;
				ipc_key_req->user_id_len = user_name_len;

				if(user_name_len){ // Old value
					memcpy((u8*)(ipc_key_req + 1),user_name,user_name_len);
					_rhp_free(user_name);
				}

				if(key_len){ // Old value
					_rhp_free(key);
				}

				ipcmsg_rep = (rhp_ipcmsg*)(ipc_key_req);


				if( s_sess->pend_eap_req ){
					_rhp_free_zero(s_sess->pend_eap_req,s_sess->pend_eap_req->len);
					s_sess->pend_eap_req = NULL;
				}

				s_sess->pend_eap_req_txn_id = ipc_key_req->txn_id;
				s_sess->pend_eap_req = *ipcmsg;
				*ipcmsg = NULL;

				goto req_new_user_key;
			}

		}else{

			RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_REQ_IPC_HANDLER_IMPL_REQUEST_COMPLETED,"x",ipc_req);

			if( s_sess->method->isSuccess(s_sess->method_ctx) ){

				msk = s_sess->method->getKey(s_sess->method_ctx,&msk_len);

				eap_status = RHP_EAP_STAT_COMPLETED;

		  	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_REQ_IPC_HANDLER_IMPL_REQUEST_IS_SUCCESS,"xp",ipc_req,msk_len,msk);

		  	if( s_sess->tmp_user_id && s_sess->tmp_user_key ){

		  		_rhp_eap_sup_syspxy_set_cached_user_key(s_sess->vpn_realm_id,
		  			s_sess->tmp_user_id,s_sess->tmp_user_id_len,s_sess->tmp_user_key,s_sess->tmp_user_key_len);

		  		my_user_id = (u8*)_rhp_malloc(s_sess->tmp_user_id_len + 1);
		  		if( my_user_id ){

		  			memcpy(my_user_id,s_sess->tmp_user_id,s_sess->tmp_user_id_len);
		  			my_user_id[s_sess->tmp_user_id_len] = '\0';

		  			my_user_id_len = s_sess->tmp_user_id_len;
		  		}

		  	}else{

					err = _rhp_eap_sup_get_auth_key((void*)s_sess,&my_user_id,&my_user_id_len,NULL,NULL);
					if( err ){
						RHP_BUG("%d",err); // Ignored..
						err = 0;
					}
		  	}

			}else{

				eap_status = RHP_EAP_STAT_ERROR;

				RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_REQ_IPC_HANDLER_IMPL_REQUEST_IS_ERROR,"x",ipc_req);
			}

			_rhp_eap_sup_delete(s_sess);
			s_sess = NULL;
		}

error_resp:
    {
  	  rhp_ipcmsg_eap_handle_rep* ipc_handle_rep = NULL;
  	  int ipc_rep_len = sizeof(rhp_ipcmsg_eap_handle_rep) + my_user_id_len;
    	int tx_eap_len = (tx_wbuf ? wpabuf_len(tx_wbuf) : 0);
    	u8* p;

    	ipc_rep_len += tx_eap_len + msk_len;

			ipc_handle_rep = (rhp_ipcmsg_eap_handle_rep*)rhp_ipc_alloc_msg(RHP_IPC_EAP_SUP_HANDLE_REPLY,ipc_rep_len);
			if(ipc_handle_rep == NULL){
				RHP_BUG("");
				goto error;
			}
			ipc_handle_rep->len = ipc_rep_len;

			ipc_handle_rep->txn_id = ipc_req->txn_id;
			ipc_handle_rep->vpn_realm_id = ipc_req->vpn_realm_id;
			memcpy(ipc_handle_rep->unique_id,ipc_req->unique_id,RHP_VPN_UNIQUE_ID_SIZE);
			ipc_handle_rep->side = ipc_req->side;
			memcpy(ipc_handle_rep->spi,ipc_req->spi,RHP_PROTO_IKE_SPI_SIZE);
			ipc_handle_rep->status = eap_status;

			ipc_handle_rep->eap_mesg_len = (tx_wbuf ? wpabuf_len(tx_wbuf) : 0);
			ipc_handle_rep->msk_len = msk_len;

			ipc_handle_rep->peer_identity_len = 0;
			ipc_handle_rep->my_identity_len = my_user_id_len;
			ipc_handle_rep->rebound_vpn_realm_id = 0;


			p = (u8*)(ipc_handle_rep + 1);
			if( tx_eap_len ){
				memcpy(p,wpabuf_mhead(tx_wbuf),tx_eap_len);
				p += tx_eap_len;
			}

			if( msk_len ){
				memcpy(p,msk,msk_len);
				p += msk_len;
			}

			if( my_user_id ){
				memcpy(p,my_user_id,my_user_id_len);
				p += my_user_id_len;
			}

			ipcmsg_rep = (rhp_ipcmsg*)(ipc_handle_rep);
    }

req_new_user_key:
  	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_REQ_IPC_HANDLER_IMPL_REQUEST_STAT,"xE",ipc_req,eap_status);
	}


	if( ipcmsg_rep ){

		if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipcmsg_rep,ipcmsg_rep->len,0) < 0 ){
			goto error;
    }

  	_rhp_free_zero(ipcmsg_rep,ipcmsg_rep->len);
  	ipcmsg_rep = NULL;
	}


	if( eap_status != RHP_EAP_STAT_CONTINUE && eap_status != RHP_EAP_STAT_COMPLETED ){
  	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_REQ_IPC_HANDLER_IMPL_STAT,"xxE",ipcmsg,(*ipcmsg),eap_status);
		goto error;
	}

	if( my_user_id ){
		_rhp_free_zero(my_user_id,my_user_id_len);
	}

	if( msk ){
		_rhp_free_zero(msk,msk_len);
	}

	if( tx_wbuf ){
		wpabuf_free(tx_wbuf);
	}

	if( rx_wbuf ){
		wpabuf_unbind_ext_data(rx_wbuf);
		wpabuf_free(rx_wbuf);
	}

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_REQ_IPC_HANDLER_IMPL_RTRN,"xx",ipcmsg,(*ipcmsg));
	return;


error:
	RHP_LOG_DE(RHP_LOG_SRC_AUTH,rlm_id,RHP_LOG_ID_EAP_PEER_FAILED_TO_PROCESS_EAP_MESG,"E",err);

error_no_log:
	if( s_sess ){
		_rhp_eap_sup_delete(s_sess);
	}

	if( ipcmsg_rep ){
		_rhp_free_zero(ipcmsg_rep,ipcmsg_rep->len);
	}

	if( tx_wbuf ){
		wpabuf_free(tx_wbuf);
	}

	if( rx_wbuf ){
		wpabuf_unbind_ext_data(rx_wbuf);
		wpabuf_free(rx_wbuf);
	}

	if( msk ){
		_rhp_free_zero(msk,msk_len);
	}

	if( my_user_id ){
		_rhp_free_zero(my_user_id,my_user_id_len);
	}

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_REQ_IPC_HANDLER_IMPL_ERR,"xx",ipcmsg,(*ipcmsg));
	return;
}

static void _rhp_eap_sup_syspxy_req_ipc_handler(rhp_ipcmsg** ipcmsg)
{
	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_REQ_IPC_HANDLER,"xx",ipcmsg,(*ipcmsg));
	_rhp_eap_sup_syspxy_req_ipc_handler_impl(ipcmsg,0);
}

static void _rhp_eap_sup_syspxy_cancel_ipc_handler(rhp_ipcmsg** ipcmsg)
{
	rhp_eap_sup_sess* s_sess = NULL;

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_CANCEL_IPC_HANDLER,"xx",ipcmsg,*ipcmsg);

	if( (*ipcmsg)->len < sizeof(rhp_ipcmsg) ){
		RHP_BUG("");
		goto error;
	}

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_CANCEL_IPC_HANDLER_TYPE,"xLd",*ipcmsg,"IPC",(*ipcmsg)->type);

	if( (*ipcmsg)->type != RHP_IPC_EAP_SUP_HANDLE_CANCEL ){

		RHP_BUG("%d",(*ipcmsg)->type);
		goto error;

	}else{

		rhp_ipcmsg_eap_handle_cancel* ipc_req = (rhp_ipcmsg_eap_handle_cancel*)*ipcmsg;

		if( ipc_req->len < sizeof(rhp_ipcmsg_eap_handle_cancel) ){
			RHP_BUG("%d",ipc_req->len);
			goto error;
		}

  	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_CANCEL_IPC_HANDLER_CANCEL,"xLdup",ipc_req,"IPC",ipc_req->type,ipc_req->vpn_realm_id,RHP_VPN_UNIQUE_ID_SIZE,ipc_req->unique_id);

		if( ipc_req->vpn_realm_id < 1 ){
			RHP_BUG("");
			goto error;
		}

		s_sess = _rhp_eap_sup_get(ipc_req->unique_id);
		if( s_sess == NULL ){
			RHP_BUG("");
			goto error;
		}

		_rhp_eap_sup_delete(s_sess);
		s_sess = NULL;
	}

error:
	if( s_sess ){
		_rhp_eap_sup_delete(s_sess);
	}

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_CANCEL_IPC_HANDLER_RTRN,"xx",ipcmsg,(*ipcmsg));
	return;
}

static void _rhp_eap_sup_syspxy_user_key_rep_ipc_handler(rhp_ipcmsg** ipcmsg)
{
	rhp_eap_sup_sess* s_sess = NULL;
	rhp_ipcmsg* pend_ipc_req = NULL;
	int is_retry = 1;

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_USER_KEY_REP_IPC_HANDLER,"xx",ipcmsg,*ipcmsg);

	if( (*ipcmsg)->len < sizeof(rhp_ipcmsg) ){
		RHP_BUG("");
		goto error;
	}

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_USER_KEY_REP_IPC_HANDLER_TYPE,"xLd",*ipcmsg,"IPC",(*ipcmsg)->type);

	if( (*ipcmsg)->type != RHP_IPC_EAP_SUP_USER_KEY ){

		RHP_BUG("%d",(*ipcmsg)->type);
		goto error;

	}else{

		rhp_ipcmsg_eap_user_key* ipc_rep = (rhp_ipcmsg_eap_user_key*)*ipcmsg;

		if( ipc_rep->len < sizeof(rhp_ipcmsg_eap_user_key) ){
			RHP_BUG("%d",ipc_rep->len);
			goto error;
		}

  	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_USER_KEY_REP_IPC_HANDLER_REQUEST,"xLdupLdG",ipc_rep,"IPC",ipc_rep->type,ipc_rep->vpn_realm_id,RHP_VPN_UNIQUE_ID_SIZE,ipc_rep->unique_id,"IKE_SIDE",ipc_rep->side,ipc_rep->spi);

		if( ipc_rep->vpn_realm_id < 1 ){
			RHP_BUG("");
			goto error;
		}

		if( ipc_rep->user_id_len == 0 || ipc_rep->user_key_len == 0 ){
			RHP_BUG("");
			goto error;
		}

		s_sess = _rhp_eap_sup_get(ipc_rep->unique_id);
		if( s_sess == NULL ){

			is_retry = 0;

	    s_sess = _rhp_eap_sup_setup_sess(ipc_rep->vpn_realm_id,
	    		ipc_rep->unique_id,ipc_rep->side,ipc_rep->spi);

	    if( s_sess == NULL ){
				RHP_BUG("");
				goto error;
	    }
		}

		{
			u8* p = ((u8*)(ipc_rep + 1));
			u8* p2 = p + ipc_rep->user_id_len;

			if( _rhp_eap_sup_syspxy_set_user_key(s_sess,
					p,(size_t)ipc_rep->user_id_len,p2,(size_t)ipc_rep->user_key_len) ){

				RHP_BUG("");
				goto error;
			}
		}

		if( is_retry ){

			RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_USER_KEY_REP_IPC_HANDLER_IS_RETRY,"xx",ipcmsg,(*ipcmsg));

			if( s_sess->pend_eap_req_txn_id != ipc_rep->txn_id ){
				RHP_BUG("");
				goto error;
			}
			s_sess->pend_eap_req_txn_id = 0;

			pend_ipc_req = s_sess->pend_eap_req;
			s_sess->pend_eap_req = NULL;
			if( pend_ipc_req == NULL ){
				RHP_BUG("");
				goto error;
			}


			_rhp_eap_sup_syspxy_req_ipc_handler_impl(&pend_ipc_req,1);

			if( pend_ipc_req ){
				_rhp_free_zero(pend_ipc_req,pend_ipc_req->len);
			}

		}else{

			RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_USER_KEY_REP_IPC_HANDLER_FIRST_USER_KEY_NOTIFIED,"xx",ipcmsg,(*ipcmsg));
		}
	}

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_USER_KEY_REP_IPC_HANDLER_RTRN,"xx",ipcmsg,(*ipcmsg));
	return;

error:
	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_USER_KEY_REP_IPC_HANDLER_ERR,"xx",ipcmsg,(*ipcmsg));
	return;
}

static void _rhp_eap_sup_syspxy_user_key_clear_cache_ipc_handler(rhp_ipcmsg** ipcmsg)
{
	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_USER_KEY_CLEAR_CACHE_IPC_HANDLER,"xx",ipcmsg,*ipcmsg);

	if( (*ipcmsg)->len < sizeof(rhp_ipcmsg) ){
		RHP_BUG("");
		goto error;
	}

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_USER_KEY_CLEAR_CACHE_IPC_HANDLER_TYPE,"xLd",*ipcmsg,"IPC",(*ipcmsg)->type);

	if( (*ipcmsg)->type != RHP_IPC_EAP_SUP_USER_KEY_CLEAR_CACHE ){

		RHP_BUG("%d",(*ipcmsg)->type);
		goto error;

	}else{

		rhp_ipcmsg_eap_user_key_clear_cache* ipc_req = (rhp_ipcmsg_eap_user_key_clear_cache*)*ipcmsg;

		if( ipc_req->len < sizeof(rhp_ipcmsg_eap_user_key_clear_cache) ){
			RHP_BUG("%d",ipc_req->len);
			goto error;
		}

  	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_USER_KEY_CLEAR_CACHE_IPC_HANDLER_CANCEL,"xLdu",ipc_req,"IPC",ipc_req->type,ipc_req->vpn_realm_id);

		if( ipc_req->vpn_realm_id < 1 ){
			RHP_BUG("");
			goto error;
		}

		_rhp_eap_sup_syspxy_clear_cached_user_key(ipc_req->vpn_realm_id);
	}

error:

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_USER_KEY_CLEAR_CACHE_IPC_HANDLER_RTRN,"xx",ipcmsg,(*ipcmsg));
	return;
}


int rhp_eap_sup_syspxy_init()
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_INIT,"");

	// TODO : rhp_prc_ipcmsg_wts_handler should be used for IKEv2's heavy crypto processing.
	err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_EAP_SUP_HANDLE_REQUEST,
					_rhp_eap_sup_syspxy_req_ipc_handler,NULL);

	if( err ){
		RHP_BUG("");
		return err;
	}

	// TODO : rhp_prc_ipcmsg_wts_handler should be used for IKEv2's heavy crypto processing.
	err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_EAP_SUP_HANDLE_CANCEL,
					_rhp_eap_sup_syspxy_cancel_ipc_handler,NULL);

	if( err ){
		RHP_BUG("");
		return err;
	}

	// TODO : rhp_prc_ipcmsg_wts_handler should be used for IKEv2's heavy crypto processing.
	err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_EAP_SUP_USER_KEY,
					_rhp_eap_sup_syspxy_user_key_rep_ipc_handler,NULL);

	if( err ){
		RHP_BUG("");
		return err;
	}

	// TODO : rhp_prc_ipcmsg_wts_handler should be used for IKEv2's heavy crypto processing.
	err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_EAP_SUP_USER_KEY_CLEAR_CACHE,
					_rhp_eap_sup_syspxy_user_key_clear_cache_ipc_handler,NULL);

	if( err ){
		RHP_BUG("");
		return err;
	}

	if( eap_peer_mschapv2_register() ){
		RHP_BUG("");
		return -EINVAL;
	}

	memset(_rhp_eap_sup_sess_hashtbl,0,sizeof(rhp_eap_sup_sess*)*RHP_EAP_SUP_HASH_TABLE_SIZE);

  _rhp_mutex_init("EPS",&(_rhp_eap_sup_syspxy_lock));

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_INIT_RTRN,"");
	return 0;
}

int rhp_eap_sup_syspxy_cleanup()
{
	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_CLEANUP,"");

	_rhp_mutex_destroy(&(_rhp_eap_sup_syspxy_lock));

	RHP_TRC(0,RHPTRCID_EAP_SUP_SYSPXY_CLEANUP_RTRN,"");
	return 0;
}


