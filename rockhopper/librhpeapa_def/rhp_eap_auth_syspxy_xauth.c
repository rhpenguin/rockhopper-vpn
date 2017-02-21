/*

	Copyright (C) 2015-2016 TETSUHARU HANADA <rhpenguine@gmail.com>
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
#include "rhp_eap_auth_impl.h"
#include "rhp_radius_impl.h"
#include "rhp_eap_auth_priv.h"


static int _rhp_eap_auth_syspxy_xauth_build_req(rhp_eap_auth_sess* a_sess,int* tx_mesg_len_r,u8** tx_mesg_r)
{
	int err = -EINVAL;
	int tx_mesg_len = 0;
	u8* tx_mesg = NULL, *p;

	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_BUILD_REQ,"xxxdd",a_sess,tx_mesg_len_r,tx_mesg_r,a_sess->xauth_state,a_sess->xauth_status);

	if( a_sess->method_type != RHP_PROTO_EAP_TYPE_PRIV_IKEV1_XAUTH_PAP ){
		RHP_BUG("%d",a_sess->method_type);
		err = -EINVAL;
		goto error;
	}


	switch( a_sess->xauth_state ){

	case RHP_XAUTH_AUTH_STAT_DEFAULT:

		tx_mesg_len = (int)sizeof(rhp_proto_ikev1_attribute_payload)
									+ (int)sizeof(rhp_proto_ikev1_attr)*2;

		tx_mesg = (u8*)_rhp_malloc(tx_mesg_len);
		if( tx_mesg == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		memset(tx_mesg,0,tx_mesg_len);
		p = tx_mesg;

		((rhp_proto_ikev1_attribute_payload*)p)->next_payload = 0;
		((rhp_proto_ikev1_attribute_payload*)p)->reserved = 0;
		((rhp_proto_ikev1_attribute_payload*)p)->len = tx_mesg_len;
		((rhp_proto_ikev1_attribute_payload*)p)->type = RHP_PROTO_IKEV1_CFG_REQUEST;
		((rhp_proto_ikev1_attribute_payload*)p)->reserved1 = 0;
		((rhp_proto_ikev1_attribute_payload*)p)->id = 0;
		p += sizeof(rhp_proto_ikev1_attribute_payload);

		// Umm.. TLV format? (AF=0)
		((rhp_proto_ikev1_attr*)p)->attr_type
				= htons(RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_USER_NAME);
		((rhp_proto_ikev1_attr*)p)->len_or_value = 0;
		p += sizeof(rhp_proto_ikev1_attr);

		// Umm.. TLV format? (AF=0)
		((rhp_proto_ikev1_attr*)p)->attr_type
				= htons(RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_USER_PASSWORD);
		((rhp_proto_ikev1_attr*)p)->len_or_value = 0;
		p += sizeof(rhp_proto_ikev1_attr);

		a_sess->xauth_state = RHP_XAUTH_AUTH_STAT_PAP_WAIT_REPLY;

		break;


	case RHP_XAUTH_AUTH_STAT_PAP_WAIT_REPLY:

		tx_mesg_len = (int)sizeof(rhp_proto_ikev1_attribute_payload)
									+ (int)sizeof(rhp_proto_ikev1_attr);

		tx_mesg = (u8*)_rhp_malloc(tx_mesg_len);
		if( tx_mesg == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		memset(tx_mesg,0,tx_mesg_len);
		p = tx_mesg;

		((rhp_proto_ikev1_attribute_payload*)p)->next_payload = 0;
		((rhp_proto_ikev1_attribute_payload*)p)->reserved = 0;
		((rhp_proto_ikev1_attribute_payload*)p)->len = tx_mesg_len;
		((rhp_proto_ikev1_attribute_payload*)p)->type = RHP_PROTO_IKEV1_CFG_SET;
		((rhp_proto_ikev1_attribute_payload*)p)->reserved1 = 0;
		((rhp_proto_ikev1_attribute_payload*)p)->id = 0;
		p += sizeof(rhp_proto_ikev1_attribute_payload);


		((rhp_proto_ikev1_attr*)p)->attr_type
				= RHP_PROTO_IKE_ATTR_SET_AF(htons(RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_STATUS));

		if( a_sess->xauth_status ){

			((rhp_proto_ikev1_attr*)p)->len_or_value = htons(0); // FAILURE

			a_sess->xauth_state = RHP_XAUTH_AUTH_STAT_PAP_WAIT_ACK_FAIL;

		}else{

			((rhp_proto_ikev1_attr*)p)->len_or_value = htons(1); // SUCCESS

			a_sess->xauth_state = RHP_XAUTH_AUTH_STAT_PAP_WAIT_ACK;
		}

		p += sizeof(rhp_proto_ikev1_attr);


		break;

	default:
		RHP_BUG("%d",a_sess->xauth_state);
		err = -EINVAL;
		goto error;
		break;
	}


	*tx_mesg_len_r = tx_mesg_len;
	*tx_mesg_r = tx_mesg;

	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_BUILD_REQ_RTRN,"xxxddp",a_sess,tx_mesg_len_r,tx_mesg_r,a_sess->xauth_state,a_sess->xauth_status,tx_mesg_len,tx_mesg);
	return 0;

error:
	if( tx_mesg ){
		_rhp_free(tx_mesg);
	}
	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_BUILD_REQ_ERR,"xddE",a_sess,a_sess->xauth_state,a_sess->xauth_status,err);
	return err;
}

static int _rhp_eap_auth_syspxy_xauth_check(rhp_eap_auth_sess* a_sess,int rx_mesg_len,u8* rx_mesg)
{
	int err = RHP_STATUS_INVALID_MSG;

	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_CHECK,"xddp",a_sess,a_sess->xauth_state,a_sess->xauth_status,rx_mesg_len,rx_mesg);

	if( a_sess->method_type != RHP_PROTO_EAP_TYPE_PRIV_IKEV1_XAUTH_PAP ){
		RHP_BUG("%d",a_sess->method_type);
		err = -EINVAL;
		goto error;
	}

	if( rx_mesg_len <= (int)sizeof(rhp_proto_ikev1_attribute_payload) ){
		RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_CHECK_INVALID_LEN,"x",a_sess);
		err = RHP_STATUS_INVALID_MSG;
		goto error;
	}

	if( a_sess->xauth_status ){
		RHP_BUG("%d",a_sess->xauth_status);
		err = -EINVAL;
		goto error;
	}

	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_CHECK_OK,"x",a_sess);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_CHECK_NG,"xE",a_sess,err);
	return err;
}



struct _rhp_xauth_pap_auth_ctx {

	int type;
	int user_name_len; 	// '\0' not included.
	u8* user_name;		 	// Not terminated with '\0'.
	int password_len;  	// '\0' not included.
	u8* password;				// Not terminated with '\0'.

	int rx_status;
};

typedef struct _rhp_xauth_pap_auth_ctx	rhp_xauth_pap_auth_ctx;

static int _rhp_eap_auth_syspxy_xauth_pap_auth_cb(rhp_ikev2_payload* payload,
		rhp_ikev1_attr_attr* attr_attr,void* ctx)
{
	int err = -EINVAL;
	rhp_xauth_pap_auth_ctx* rx_user = (rhp_xauth_pap_auth_ctx*)ctx;
	u16 attr_type = attr_attr->get_attr_type(attr_attr);
	int attr_len = attr_attr->get_attr_len(attr_attr);
	u8* attr_val = attr_attr->get_attr(attr_attr);

	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PAP_AUTH_CB,"xxxwpdd",payload,attr_attr,ctx,attr_type,attr_len,attr_val,rx_user->user_name_len,rx_user->password_len);

	if( attr_type == RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_TYPE ){

		if( attr_len != sizeof(u16) ){
			RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PAP_AUTH_CB_INVALID_LEN,"xxxd",payload,attr_attr,ctx,attr_len);
			err = RHP_STATUS_INVALID_MSG;
			goto error;
		}

		rx_user->type = ntohs(*((u16*)attr_val));

	}else if( attr_type == RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_USER_NAME ){

		if( attr_len < 1 ){
			RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PAP_AUTH_CB_INVALID_LEN_2,"xxxd",payload,attr_attr,ctx,attr_len);
			err = RHP_STATUS_INVALID_MSG;
			goto error;
		}

		rx_user->user_name_len = attr_len;
		rx_user->user_name = attr_val;

	}else if( attr_type == RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_USER_PASSWORD ){

		if( attr_len < 1 ){
			RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PAP_AUTH_CB_INVALID_LEN_3,"xxxd",payload,attr_attr,ctx,attr_len);
			err = RHP_STATUS_INVALID_MSG;
			goto error;
		}

		rx_user->password_len = attr_len;
		rx_user->password = attr_val;

	}else if( attr_type == RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_STATUS ){

		rx_user->rx_status = 1;
	}

	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PAP_AUTH_CB_RTRN,"xxxwppd",payload,attr_attr,ctx,attr_type,rx_user->user_name_len,rx_user->user_name,rx_user->password_len,rx_user->password,rx_user->rx_status);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PAP_AUTH_CB_ERR,"xxxE",payload,attr_attr,ctx,err);
	return err;
}

static int _rhp_eap_auth_syspxy_xauth_pap_auth(rhp_eap_auth_sess* a_sess,
		rhp_ikev2_payload* ikepayload,rhp_ikev2_id* my_id,
		unsigned long cur_realm_id,unsigned long peer_notified_realm_id)
{
	int err = -EINVAL;
	rhp_xauth_pap_auth_ctx rx_user;
	rhp_vpn_auth_realm* rb_auth_rlm = NULL;
  rhp_auth_peer* auth_peer;
  rhp_auth_psk *peer_psk;
  rhp_eap_id eap_peer_id;

	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PAP_AUTH,"xxxuu",a_sess,ikepayload,my_id,cur_realm_id,peer_notified_realm_id);

	rhp_ikev2_id_dump("_rhp_eap_auth_syspxy_xauth_pap_auth",my_id);

	memset(&eap_peer_id,0,sizeof(rhp_eap_id));

	rx_user.type = RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_TYPE_GENERIC;
	rx_user.user_name_len = 0;
	rx_user.user_name = NULL;
	rx_user.password_len = 0;
	rx_user.password = NULL;
	rx_user.rx_status = 0;


	err = ikepayload->ext.v1_attr->enum_attr(ikepayload,
			_rhp_eap_auth_syspxy_xauth_pap_auth_cb,&rx_user);
	if( err ){
		RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PAP_AUTH_ENUM_ATTR_ERR,"xxE",a_sess,ikepayload,err);
		goto error;
	}

	if( a_sess->xauth_state == RHP_XAUTH_AUTH_STAT_PAP_WAIT_ACK ||
			a_sess->xauth_state == RHP_XAUTH_AUTH_STAT_PAP_WAIT_ACK_FAIL ){

		if( !rx_user.rx_status ){
			RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PAP_AUTH_RX_ACK_ERR_NO_STATUS_ATTR,"xxddd",a_sess,ikepayload,a_sess->xauth_state,a_sess->xauth_status,rx_user.rx_status);
			err = -ENOENT;
			goto error;
		}

		a_sess->xauth_state = RHP_XAUTH_AUTH_STAT_DONE;

		RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PAP_AUTH_RX_ACK,"xxddd",a_sess,ikepayload,a_sess->xauth_state,a_sess->xauth_status,rx_user.rx_status);
		err = 0;
		goto end;
	}

	if( a_sess->xauth_status ){
		RHP_BUG("%d",a_sess->xauth_status);
		err = -EINVAL;
		goto error;
	}

	if( rx_user.type != RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_TYPE_GENERIC ){
		RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PAP_AUTH_UNSUP_TYPE,"xxd",a_sess,ikepayload,rx_user.type);
		err = -ENOENT;
		goto error;
	}

	if( rx_user.user_name_len < 1 || rx_user.user_name == NULL ){
		RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PAP_AUTH_NO_USERNAME,"xxxd",a_sess,ikepayload,rx_user.user_name,rx_user.user_name_len);
		err = -ENOENT;
		goto error;
	}

	if( rx_user.password_len < 1 || rx_user.password == NULL ){
		RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PAP_AUTH_NO_PASSWORD,"xxxd",a_sess,ikepayload,rx_user.password,rx_user.password_len);
		err = -ENOENT;
		goto error;
	}


	err = rhp_eap_id_setup(a_sess->method_type,
					rx_user.user_name_len,rx_user.user_name,1,&eap_peer_id);
	if( err ){
		RHP_BUG("%d",err);
		err = -ENOENT;
		goto error;
	}


	rb_auth_rlm = rhp_auth_realm_get_by_role(my_id,RHP_PEER_ID_TYPE_EAP,&eap_peer_id,
			NULL,0,peer_notified_realm_id);

	if( rb_auth_rlm == NULL ){

		if( peer_notified_realm_id != 0 &&
				peer_notified_realm_id != RHP_VPN_REALM_ID_UNKNOWN &&
				cur_realm_id != peer_notified_realm_id ){
			err = RHP_STATUS_IKEV1_XAUTH_AUTH_FAILED;
	  	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PAP_AUTH_PEER_NOTIFIEDY_RLM_NOT_MATCHED,"xxuu",ikepayload,my_id,cur_realm_id,peer_notified_realm_id);
			goto error;
		}

		rb_auth_rlm = rhp_auth_realm_get(cur_realm_id);
	}

	if( rb_auth_rlm == NULL ){
		err = RHP_STATUS_IKEV1_XAUTH_AUTH_FAILED;
  	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PAP_AUTH_RLM_NOT_FOUND,"xx",ikepayload,my_id);
		goto error;
	}


  RHP_LOCK(&(rb_auth_rlm->lock));

	if( rb_auth_rlm->xauth.role != RHP_EAP_AUTHENTICATOR ){

  	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PAP_AUTH_NOT_AUTHENTICATOR,"xuLd",rb_auth_rlm,rb_auth_rlm->id,"EAP_ROLE",rb_auth_rlm->xauth.role);

  	RHP_LOG_DE(RHP_LOG_SRC_AUTH,(rb_auth_rlm ? rb_auth_rlm->id : 0),RHP_LOG_ID_XAUTH_NOT_AUTHENTICATOR,"L","EAP_ROLE",rb_auth_rlm->xauth.role);

		err = RHP_STATUS_IKEV1_XAUTH_AUTH_FAILED;
  	goto error;
	}

  auth_peer = rb_auth_rlm->get_peer_by_id(rb_auth_rlm,RHP_PEER_ID_TYPE_EAP,(void*)&eap_peer_id);
  if( auth_peer == NULL ){
		err = RHP_STATUS_IKEV1_XAUTH_AUTH_FAILED;
  	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PAP_AUTH_NO_PEER,"xu",rb_auth_rlm,rb_auth_rlm->id);
  	goto error;
  }


  peer_psk = auth_peer->peer_psks;
  while( peer_psk ){

    if( peer_psk->key ){
  		RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PAP_AUTH_KEY_FOUND,"xxxxs",a_sess,ikepayload,auth_peer,peer_psk,peer_psk->key);
    	break;
    }

    peer_psk = peer_psk->next;
  }

  if( peer_psk == NULL ||
  		strlen((char*)peer_psk->key) != rx_user.password_len ||
  		memcmp(peer_psk->key,rx_user.password,rx_user.password_len) ){

  	int key_err = 1;

  	// For Android's XAUTH Bug... Android may send a password value with Null-terminated.
  	if( rhp_gcfg_ikev1_xauth_allow_null_terminated_password ){

  		if( rx_user.password_len > 1 &&
  				rx_user.password[rx_user.password_len - 1] == 0 && // '\0' terminated... Why?
  				strlen((char*)peer_psk->key) == (rx_user.password_len - 1) &&
  				!memcmp(peer_psk->key,rx_user.password,(rx_user.password_len - 1)) ){

    		RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PAP_AUTH_NULL_TERMINATED_KEY_OK,"xxxsp",a_sess,ikepayload,peer_psk,(peer_psk ? peer_psk->key : NULL),rx_user.password_len,rx_user.password);

  			key_err = 0;
  		}
  	}

  	if( key_err ){

  		RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PAP_AUTH_INVALID_KEY,"xxxsp",a_sess,ikepayload,peer_psk,(peer_psk ? peer_psk->key : NULL),rx_user.password_len,rx_user.password);

			err = RHP_STATUS_IKEV1_XAUTH_AUTH_FAILED;
			goto error;
  	}
  }


  a_sess->rebound_rlm_id = rb_auth_rlm->id;


  if( a_sess->xauth_peer_identity == NULL ){

		a_sess->xauth_peer_identity_len = rx_user.user_name_len;
		a_sess->xauth_peer_identity = (u8*)_rhp_malloc(rx_user.user_name_len + 1);
		if( a_sess->xauth_peer_identity == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		memcpy(a_sess->xauth_peer_identity,rx_user.user_name,rx_user.user_name_len);
		a_sess->xauth_peer_identity[rx_user.user_name_len] = '\0';
  }


	RHP_LOG_D(RHP_LOG_SRC_AUTH,rb_auth_rlm->id,RHP_LOG_ID_XAUTH_PAP_AUTH_OK,"s",eap_peer_id.identity);

  RHP_UNLOCK(&(rb_auth_rlm->lock));
	rhp_auth_realm_unhold(rb_auth_rlm);
	rb_auth_rlm = NULL;

	rhp_eap_id_clear(&eap_peer_id);

end:
	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PAP_AUTH_RTRN,"xx",a_sess,ikepayload);
	return 0;

error:

	if( err == -ENOENT ){
		RHP_LOG_DE(RHP_LOG_SRC_AUTH,(rb_auth_rlm ? rb_auth_rlm->id : 0),RHP_LOG_ID_XAUTH_PAP_AUTH_FAILED,"s","(null)");
	}else{
		RHP_LOG_DE(RHP_LOG_SRC_AUTH,(rb_auth_rlm ? rb_auth_rlm->id : 0),RHP_LOG_ID_XAUTH_PAP_AUTH_FAILED,"s",eap_peer_id.identity);
	}

	if( rb_auth_rlm ){
	  RHP_UNLOCK(&(rb_auth_rlm->lock));
		rhp_auth_realm_unhold(rb_auth_rlm);
	}

	rhp_eap_id_clear(&eap_peer_id);

	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PAP_AUTH_ERR,"xxE",a_sess,ikepayload,err);
	return err;
}

static int _rhp_eap_auth_syspxy_xauth_process(rhp_eap_auth_sess* a_sess,int rx_mesg_len,u8* rx_mesg,
		rhp_ikev2_id* my_id,unsigned long cur_realm_id,unsigned long peer_notified_realm_id)
{
	int err = -EINVAL;
	rhp_ikev2_payload* ikepayload = NULL;

	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PROCESS,"xddpxuu",a_sess,a_sess->xauth_state,a_sess->xauth_status,rx_mesg_len,rx_mesg,my_id,cur_realm_id,peer_notified_realm_id);

	rhp_ikev2_id_dump("_rhp_eap_auth_syspxy_xauth_process",my_id);


	if( a_sess->method_type != RHP_PROTO_EAP_TYPE_PRIV_IKEV1_XAUTH_PAP ){
		RHP_BUG("%d",a_sess->method_type);
		err = -EINVAL;
		goto error;
	}

	if( a_sess->xauth_status ){
		RHP_BUG("%d",a_sess->xauth_status);
		err = -EINVAL;
		goto error;
	}


	if( rx_mesg_len <= (int)sizeof(rhp_proto_ikev1_attribute_payload) ){
		RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PROCESS_INVALID_LEN,"xdd",a_sess,rx_mesg_len,(int)sizeof(rhp_proto_ikev1_attribute_payload));
		err = -EINVAL;
		goto error;
	}


	ikepayload = rhp_ikev2_alloc_payload_raw();
	if( ikepayload == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

  ikepayload->payloadh = (rhp_proto_ike_payload*)rx_mesg;
  ikepayload->payload_id = RHP_PROTO_IKEV1_PAYLOAD_ATTR;
  ikepayload->is_v1 = 1;


  err = rhp_ikev1_attr_payload_parse((rhp_proto_ikev1_attribute_payload*)rx_mesg,rx_mesg_len,ikepayload);
  if( err ){
		RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PROCESS_MESG_PARSE_ERR,"xE",a_sess,err);
  	goto error;
  }


  a_sess->rebound_rlm_id = 0;

  err = _rhp_eap_auth_syspxy_xauth_pap_auth(a_sess,ikepayload,my_id,cur_realm_id,
  				peer_notified_realm_id);
  if( err ){
		RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PROCESS_PAP_AUTH_ERR,"xE",a_sess,err);
  	a_sess->xauth_status = err;
  }


	rhp_ikev2_destroy_payload(ikepayload);

	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PROCESS_RTRN,"xxdd",a_sess,ikepayload,a_sess->xauth_state,a_sess->xauth_status);
	return 0;

error:

	if( ikepayload ){
		rhp_ikev2_destroy_payload(ikepayload);
	}

	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_PROCESS_ERR,"xxddE",a_sess,ikepayload,a_sess->xauth_state,a_sess->xauth_status,err);
	return err;
}

static int _rhp_eap_auth_syspxy_xauth_is_done(rhp_eap_auth_sess* a_sess)
{
	int ret = (a_sess->xauth_state == RHP_XAUTH_AUTH_STAT_DONE);
	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_IS_DONE,"xddd",a_sess,a_sess->xauth_state,a_sess->xauth_status,ret);
	return ret;
}

static int _rhp_eap_auth_syspxy_xauth_is_success(rhp_eap_auth_sess* a_sess)
{
	int ret = (a_sess->xauth_state == RHP_XAUTH_AUTH_STAT_DONE && a_sess->xauth_status == 0);
	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_IS_SUCCESS,"xddd",a_sess,a_sess->xauth_state,a_sess->xauth_status,ret);
	return ret;
}

static u8* _rhp_eap_auth_syspxy_xauth_get_peer_identity(rhp_eap_auth_sess* a_sess,int* peer_identity_len_r)
{
	*peer_identity_len_r = a_sess->xauth_peer_identity_len;
	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_GET_PEER_IDENTITY,"xddp",a_sess,a_sess->xauth_state,a_sess->xauth_status,a_sess->xauth_peer_identity_len,a_sess->xauth_peer_identity);
	return a_sess->xauth_peer_identity;
}

void rhp_eap_auth_syspxy_xauth_ipc_handler(rhp_ipcmsg** ipcmsg)
{
	int err = -EINVAL;
	rhp_eap_auth_sess* a_sess = NULL;
	int tx_mesg_len = 0, rx_mesg_len = 0;
	u8 *tx_mesg = NULL, *rx_mesg = NULL;
  int eap_status = RHP_EAP_STAT_ERROR;
  int ipc_rep_len = sizeof(rhp_ipcmsg_eap_handle_rep);
  rhp_ipcmsg* ipcmsg_rep = NULL;
  unsigned long rebound_vpn_realm_id = 0;
  int peer_identity_len = 0;
  u8* peer_identity = NULL;
  unsigned long auth_rlm_id = 0;
  rhp_ikev2_id my_id; // Don't forget to clear my_id's fields by rhp_ikev2_id_clear().

	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_IPC_HANDLER,"xx",ipcmsg,*ipcmsg);

	memset(&my_id,0,sizeof(rhp_ikev2_id));

	if( (*ipcmsg)->len < sizeof(rhp_ipcmsg) ){
		RHP_BUG("");
		goto error_no_log;
	}

	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_IPC_HANDLER_TYPE,"xLd",*ipcmsg,"IPC",(*ipcmsg)->type);

	switch( (*ipcmsg)->type ){

	case RHP_IPC_XAUTH_AUTH_HANDLE_REQUEST:
	{
		rhp_ipcmsg_eap_handle_req* ipc_req = (rhp_ipcmsg_eap_handle_req*)*ipcmsg;
	  rhp_ipcmsg_eap_handle_rep* ipc_rep = NULL;

		if( ipc_req->len < sizeof(rhp_ipcmsg_eap_handle_req) ){
			RHP_BUG("%d",ipc_req->len);
			goto error;
		}

  	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_IPC_HANDLER_REQUEST,"xLdudpLdGd",ipc_req,"IPC",ipc_req->type,ipc_req->vpn_realm_id,ipc_req->init_req,RHP_VPN_UNIQUE_ID_SIZE,ipc_req->unique_id,"IKE_SIDE",ipc_req->side,ipc_req->spi,ipc_req->eap_mesg_len);

		if( ipc_req->vpn_realm_id < 1 ){
			RHP_BUG("");
			goto error;
		}


		a_sess = rhp_eap_auth_get(ipc_req->unique_id);

		if( !ipc_req->init_req && a_sess == NULL ){

			RHP_BUG("");
			eap_status = RHP_EAP_STAT_ERROR;
			goto error_resp;

		}else if( ipc_req->init_req && a_sess ){

			RHP_BUG("");
			eap_status = RHP_EAP_STAT_ERROR;
			goto error_resp;
		}

		if( a_sess == NULL ){

			{
				rhp_vpn_auth_realm* auth_rlm = NULL;

				auth_rlm = rhp_auth_realm_get(ipc_req->vpn_realm_id);
				if( auth_rlm == NULL ){
					RHP_BUG("%d",ipc_req->vpn_realm_id);
					goto error;
				}

				RHP_LOCK(&(auth_rlm->lock));

				auth_rlm_id = auth_rlm->id;

				a_sess = rhp_eap_auth_alloc(0,auth_rlm->xauth.method,auth_rlm->id,
						ipc_req->unique_id,ipc_req->side,ipc_req->spi);

				if( a_sess == NULL ){

					RHP_BUG("");

					RHP_UNLOCK(&(auth_rlm->lock));
					rhp_auth_realm_unhold(auth_rlm);

					eap_status = RHP_EAP_STAT_ERROR;
					goto error_resp;
				}

				RHP_UNLOCK(&(auth_rlm->lock));
				rhp_auth_realm_unhold(auth_rlm);
			}

	    rhp_eap_auth_put(a_sess);

	    err = _rhp_eap_auth_syspxy_xauth_build_req(a_sess,&tx_mesg_len,&tx_mesg);
	    if( err ){
	    	RHP_BUG("");
				eap_status = RHP_EAP_STAT_ERROR;
	    	goto error_resp;
	    }

	    eap_status = RHP_EAP_STAT_CONTINUE;

		}else{

		  unsigned long cur_auth_rlm_id;

		  {
		  	rhp_vpn_auth_realm* auth_rlm = rhp_auth_realm_get(ipc_req->vpn_realm_id);

		  	if( auth_rlm == NULL ){
					RHP_BUG("%d",ipc_req->vpn_realm_id);
					goto error;
				}

				RHP_LOCK(&(auth_rlm->lock));

				if( rhp_ikev2_id_dup(&my_id,&(auth_rlm->my_auth->my_id)) ){

					RHP_BUG("");

					RHP_UNLOCK(&(auth_rlm->lock));
					rhp_auth_realm_unhold(auth_rlm);

					eap_status = RHP_EAP_STAT_ERROR;
					goto error_resp;
				}

				cur_auth_rlm_id = auth_rlm->id;

				RHP_UNLOCK(&(auth_rlm->lock));
				rhp_auth_realm_unhold(auth_rlm);
		  }

		  rx_mesg = (u8*)(ipc_req + 1);
		  rx_mesg_len = ipc_req->eap_mesg_len;

			if( rx_mesg_len < sizeof(rhp_proto_eap) ){
				RHP_BUG("");
				eap_status = RHP_EAP_STAT_ERROR;
	    	goto error_resp;
			}


			err = _rhp_eap_auth_syspxy_xauth_check(a_sess,rx_mesg_len,rx_mesg);
			if( err ){
		  	RHP_TRC(0,RHPTRCID_AUTH_SYSPXY_XAUTH_IPC_HANDLER_REQUEST_CHECK_ERR,"xE",ipc_req,err);
	    	goto error_resp;
			}


			err = _rhp_eap_auth_syspxy_xauth_process(a_sess,rx_mesg_len,rx_mesg,&my_id,
							ipc_req->vpn_realm_id,ipc_req->peer_notified_realm_id);
			if( err ){
		  	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_IPC_HANDLER_REQUEST_PROCESS_ERR,"xE",ipc_req,err);
	    	goto error_resp;
			}


			if( !_rhp_eap_auth_syspxy_xauth_is_done(a_sess) ){

		    err = _rhp_eap_auth_syspxy_xauth_build_req(a_sess,&tx_mesg_len,&tx_mesg);
		    if( err ){
		    	RHP_BUG("");
					eap_status = RHP_EAP_STAT_ERROR;
		    	goto error_resp;
		    }
			}

			// _rhp_eap_auth_syspxy_xauth_build_req may change the a_sess's EAP State???
			// To just make sure, call _rhp_eap_auth_syspxy_xauth_is_done again here.
			if( !_rhp_eap_auth_syspxy_xauth_is_done(a_sess) ){

				eap_status = RHP_EAP_STAT_CONTINUE;
		  	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_IPC_HANDLER_REQUEST_IS_DONE_CONTINUE,"x",ipc_rep);

			}else{

		  	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_IPC_HANDLER_REQUEST_IS_DONE_COMPLETED,"x",ipc_rep);

				if( _rhp_eap_auth_syspxy_xauth_is_success(a_sess) ){

					peer_identity = _rhp_eap_auth_syspxy_xauth_get_peer_identity(a_sess,&peer_identity_len);
					if( peer_identity_len ){

						char* eap_peer_id;

						{
							eap_peer_id = (char*)_rhp_malloc(peer_identity_len + 1);
							if( eap_peer_id == NULL ){
								RHP_BUG("");
								eap_status = RHP_EAP_STAT_ERROR;
								goto error_resp;
							}

							memcpy(eap_peer_id,peer_identity,peer_identity_len);
							eap_peer_id[peer_identity_len] = '\0';
						}

						if( a_sess->rebound_rlm_id ){

							if( cur_auth_rlm_id != a_sess->rebound_rlm_id ){

								rebound_vpn_realm_id = a_sess->rebound_rlm_id;

								RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_IPC_HANDLER_ACTUAL_REBOUND_RLM_ID_FOUND,"xxsuu",ipc_req,a_sess,eap_peer_id,cur_auth_rlm_id,rebound_vpn_realm_id);
								RHP_LOG_D(RHP_LOG_SRC_AUTH,rebound_vpn_realm_id,RHP_LOG_ID_XAUTH_ACTUAL_REALM_FOUND,"suu",eap_peer_id,cur_auth_rlm_id,rebound_vpn_realm_id);

							}else{

						  	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_IPC_HANDLER_SAME_BOUND_RLM_ID_USED,"xxsu",ipc_req,a_sess,eap_peer_id,cur_auth_rlm_id);
							}

						}else{

					  	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_IPC_HANDLER_NO_REBOUND_RLM_ID,"xxsu",ipc_req,a_sess,eap_peer_id,cur_auth_rlm_id);
						}

						_rhp_free(eap_peer_id);
					}


					eap_status = RHP_EAP_STAT_COMPLETED;

			  	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_IPC_HANDLER_REQUEST_IS_SUCCESS,"xp",ipc_req,peer_identity_len,peer_identity);

				}else{

					eap_status = RHP_EAP_STAT_ERROR;

					RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_IPC_HANDLER_REQUEST_IS_ERROR,"x",ipc_req);
				}

				rhp_eap_auth_delete(a_sess);
				a_sess = NULL;
			}
		}

error_resp:
    {
    	ipc_rep_len += tx_mesg_len + peer_identity_len;

			ipc_rep = (rhp_ipcmsg_eap_handle_rep*)rhp_ipc_alloc_msg(RHP_IPC_XAUTH_AUTH_HANDLE_REPLY,ipc_rep_len);
			if(ipc_rep == NULL){
				RHP_BUG("");
				goto error;
			}
			ipc_rep->len = ipc_rep_len;

			ipc_rep->txn_id = ipc_req->txn_id;
			ipc_rep->vpn_realm_id = ipc_req->vpn_realm_id;
			memcpy(ipc_rep->unique_id,ipc_req->unique_id,RHP_VPN_UNIQUE_ID_SIZE);
			ipc_rep->side = ipc_req->side;
			memcpy(ipc_rep->spi,ipc_req->spi,RHP_PROTO_IKE_SPI_SIZE);
			ipc_rep->status = eap_status;

			ipc_rep->eap_mesg_len = tx_mesg_len;
			ipc_rep->msk_len = 0;
			ipc_rep->peer_identity_len = peer_identity_len;

			ipc_rep->rebound_vpn_realm_id = rebound_vpn_realm_id;

			ipc_rep->is_init_req = ipc_req->is_init_req;

			if( tx_mesg_len ){
				memcpy((u8*)(ipc_rep + 1),tx_mesg,tx_mesg_len);
			}

			if( peer_identity_len ){
				memcpy(((u8*)(ipc_rep + 1)) + tx_mesg_len,peer_identity,peer_identity_len);
			}

			ipcmsg_rep = (rhp_ipcmsg*)(ipc_rep);
    }

  	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_IPC_HANDLER_REQUEST_STAT,"xE",ipc_req,eap_status);
	}
		break;


	case RHP_IPC_XAUTH_AUTH_HANDLE_CANCEL:
	{
		rhp_ipcmsg_eap_handle_cancel* ipc_req = (rhp_ipcmsg_eap_handle_cancel*)*ipcmsg;

		if( ipc_req->len < sizeof(rhp_ipcmsg_eap_handle_cancel) ){
			RHP_BUG("%d",ipc_req->len);
			goto error;
		}

  	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_IPC_HANDLER_CANCEL,"xLdup",ipc_req,"IPC",ipc_req->type,ipc_req->vpn_realm_id,RHP_VPN_UNIQUE_ID_SIZE,ipc_req->unique_id);

		if( ipc_req->vpn_realm_id < 1 ){
			RHP_BUG("");
			goto error;
		}

		a_sess = rhp_eap_auth_get(ipc_req->unique_id);
		if( a_sess == NULL ){
			RHP_BUG("");
			goto error;
		}

		rhp_eap_auth_delete(a_sess);
		a_sess = NULL;
	}
		break;

	default:
		RHP_BUG("%d",(*ipcmsg)->type);
		goto error;
	}


	if( ipcmsg_rep ){

		if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipcmsg_rep,ipcmsg_rep->len,0) < 0 ){
			goto error;
    }

  	_rhp_free_zero(ipcmsg_rep,ipcmsg_rep->len);
  	ipcmsg_rep = NULL;
	}


	if( eap_status != RHP_EAP_STAT_CONTINUE && eap_status != RHP_EAP_STAT_COMPLETED ){
  	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_IPC_HANDLER_STAT,"xxE",ipcmsg,(*ipcmsg),eap_status);
		goto error;
	}

  rhp_ikev2_id_clear(&my_id);


	if( tx_mesg ){
		_rhp_free(tx_mesg);
	}

	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_IPC_HANDLER_RTRN,"xx",ipcmsg,(*ipcmsg));
	return;


error:
	if( (*ipcmsg)->type == RHP_IPC_XAUTH_AUTH_HANDLE_REQUEST ){
		RHP_LOG_DE(RHP_LOG_SRC_AUTH,auth_rlm_id,RHP_LOG_ID_XAUTH_AUTHENTICATOR_FAILED_TO_PROCESS_EAP_MESG,"E",err);
	}

error_no_log:
	if( a_sess ){
		rhp_eap_auth_delete(a_sess);
	}

	if( ipcmsg_rep ){
		_rhp_free_zero(ipcmsg_rep,ipcmsg_rep->len);
	}

	if( tx_mesg ){
		_rhp_free(tx_mesg);
	}

  rhp_ikev2_id_clear(&my_id);

	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_XAUTH_IPC_HANDLER_ERR,"xx",ipcmsg,(*ipcmsg));
	return;
}

