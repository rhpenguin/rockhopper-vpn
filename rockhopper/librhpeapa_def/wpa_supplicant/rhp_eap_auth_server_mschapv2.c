/*
 * hostapd / EAP-MSCHAPv2 (draft-kamath-pppext-eap-mschapv2-00.txt) server
 * Copyright (c) 2004-2007, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include "includes.h"

#include "common.h"
#include "ms_funcs.h"
#include "eap_i.h"


#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_protocol.h"

extern int rhp_gcfg_eap_mschapv2_max_auth_retries;

struct eap_mschapv2_hdr {
	u8 op_code; /* MSCHAPV2_OP_* */
	u8 mschapv2_id; /* must be changed for challenges, but not for
			 * success/failure */
	u8 ms_length[2]; /* Note: misaligned; length - 5 */
	/* followed by data */
} STRUCT_PACKED;

#define MSCHAPV2_OP_CHALLENGE 			1
#define MSCHAPV2_OP_RESPONSE 				2
#define MSCHAPV2_OP_SUCCESS 				3
#define MSCHAPV2_OP_FAILURE 				4
#define MSCHAPV2_OP_CHANGE_PASSWORD 7

#define MSCHAPV2_RESP_LEN 49

#define ERROR_RESTRICTED_LOGON_HOURS 	646
#define ERROR_ACCT_DISABLED 					647
#define ERROR_PASSWD_EXPIRED 					648
#define ERROR_NO_DIALIN_PERMISSION 		649
#define ERROR_AUTHENTICATION_FAILURE 	691
#define ERROR_CHANGING_PASSWORD 			709

#define PASSWD_CHANGE_CHAL_LEN 	16
#define MSCHAPV2_KEY_LEN 				16


#define CHALLENGE_LEN 	16

/*

                 +------+ 0..n
                 |      |(2)            (3)                (4)
                 +--->[RETRY_REQ]----------->[FAILURE_RESP]----->[FAILURE]
                          ^  \                        ^
                          |   \(5)                    |(7)
                          |    \                      |
                          |     \                 +---+
                          |      +---------+     /
                          |                |    /
                       (2)|                V   /
   [DEFAULT]-------->[CHALLENGE]------->[SUCCESS_REQ]----->[SUCCESS_RESP]---->[SUCCESS]
                  (1)             (5)                 (6)                 (8)


  - States: [state-label]

  - Triggers:                         [SRC]    [DST]
   (1) Tx MSCHAP-challenge Req      :  Svr  ==> Peer
   (2) Rx wrong MSCHAP-Resp         :  Peer ==> Svr
   (3) Rx the last wrong MSCHAP-Resp:  Peer ==> Svr
   (4) Tx EAP Failure               :  Svr  ==> Peer
   (5) Rx correct MSCHAP-Resp       :  Peer ==> Svr
       (and Tx MSCHAP-Success)      : (Svr  ==> Peer)
   (6) Rx MSCHAP-Success            :  Peer ==> Svr
   (7) Rx MSCHAP-Failure            :  Peer ==> Svr
   (8) Tx EAP Success               :  Svr  ==> Peer

	- Error handling:
	   [CHALLENGE], [RETRY_REQ] or [SUCCESS_REQ] ==> [FAILURE]


	- Change-Password message NOT supported because this may potentially
	  cause security issues like revealing user id's existence.

*/


struct eap_mschapv2_data {
	u8 auth_challenge[CHALLENGE_LEN];
	int auth_challenge_from_tls;
	u8 *peer_challenge;
	u8 auth_response[20];
	enum { INIT, CHALLENGE, RETRY_REQ, SUCCESS_REQ, FAILURE_RESP,
		SUCCESS_RESP, SUCCESS, FAILURE } state;
	u8 resp_mschapv2_id;
	u8 master_key[16];
	int master_key_valid;
	int retries;
	u8* peer_identity;
	int peer_identity_len;
};

static inline void _eap_mschapv2_state(struct eap_mschapv2_data *data,int new_state)
{
  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_STATE,"xLdLd",data,"LIB_MCHP2_STAT",data->state,"LIB_MCHP2_STAT",new_state);
	RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_STATE,"LL","LIB_MCHP2_STAT",data->state,"LIB_MCHP2_STAT",new_state);
  data->state = new_state;
}

static void * eap_mschapv2_init()
{
	struct eap_mschapv2_data *data;

	data = os_zalloc(sizeof(*data));
	if (data == NULL){
		RHP_BUG("");
		return NULL;
	}

	_eap_mschapv2_state(data,INIT);

  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_INIT,"xLd",data,"LIB_MCHP2_STAT",data->state);

	return data;
}

static void eap_mschapv2_cleanup(void *priv)
{
	struct eap_mschapv2_data *data = priv;

	if (data == NULL){
		RHP_BUG("");
		return;
	}

  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_CLEANUP,"xLd",data,"LIB_MCHP2_STAT",data->state);

	if( data->peer_challenge ){
		os_free(data->peer_challenge);
	}
	if( data->peer_identity ){
		os_free(data->peer_identity);
	}
	os_free(data);

	return;
}

static struct wpabuf * eap_mschapv2_build_challenge(
	struct eap_mschapv2_data *data, u8 id)
{
	struct wpabuf *req;
	struct eap_mschapv2_hdr *ms;
	char *name = "rockhopper"; // TODO: make this configurable
	size_t ms_len;

  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_BUILD_CHALLENGE,"xLdb",data,"LIB_MCHP2_STAT",data->state,id);

	if (!data->auth_challenge_from_tls &&
	    os_get_random(data->auth_challenge, CHALLENGE_LEN)) {

		RHP_BUG("");
		wpa_printf(MSG_ERROR, "EAP-MSCHAPV2: Failed to get random data");

		_eap_mschapv2_state(data,FAILURE);
		return NULL;
	}

	ms_len = sizeof(*ms) + 1 + CHALLENGE_LEN + os_strlen(name);
	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_MSCHAPV2, ms_len, EAP_CODE_REQUEST, id);
	if (req == NULL) {

		RHP_BUG("");
		wpa_printf(MSG_ERROR, "EAP-MSCHAPV2: Failed to allocate memory for request");

		_eap_mschapv2_state(data,FAILURE);
		return NULL;
	}

	ms = wpabuf_put(req, sizeof(*ms));
	ms->op_code = MSCHAPV2_OP_CHALLENGE;
	ms->mschapv2_id = id;
	WPA_PUT_BE16(ms->ms_length, ms_len);

	wpabuf_put_u8(req, CHALLENGE_LEN);
	if (!data->auth_challenge_from_tls){
		wpabuf_put_data(req, data->auth_challenge, CHALLENGE_LEN);
	}else{
		wpabuf_put(req, CHALLENGE_LEN);
	}
	wpa_hexdump(MSG_MSGDUMP, "EAP-MSCHAPV2: Challenge",data->auth_challenge, CHALLENGE_LEN);
	wpabuf_put_data(req, name, os_strlen(name));

	RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_GEN_CHALLENGE_REQ,"b",id);

	RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_BUILD_CHALLENGE_RTRN,"xLdp",data,"LIB_MCHP2_STAT",data->state,wpabuf_len(req),wpabuf_head(req));
	return req;
}

static struct wpabuf * eap_mschapv2_build_success_req(
	struct eap_mschapv2_data *data, u8 id)
{
	struct wpabuf *req;
	struct eap_mschapv2_hdr *ms;
	u8 *msg;
	char *message = "OK";
	size_t ms_len;

  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_BUILD_SUCCESS_REQ,"xLdb",data,"LIB_MCHP2_STAT",data->state,id);

	ms_len = sizeof(*ms) + 2 + 2 * sizeof(data->auth_response) + 1 + 2 + os_strlen(message);

	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_MSCHAPV2, ms_len, EAP_CODE_REQUEST, id);
	if (req == NULL) {

		RHP_BUG("");
		wpa_printf(MSG_ERROR, "EAP-MSCHAPV2: Failed to allocate memory for request");

		_eap_mschapv2_state(data,FAILURE);
		return NULL;
	}

	ms = wpabuf_put(req, sizeof(*ms));
	ms->op_code = MSCHAPV2_OP_SUCCESS;
	ms->mschapv2_id = data->resp_mschapv2_id;
	WPA_PUT_BE16(ms->ms_length, ms_len);
	msg = (u8 *) (ms + 1);

	wpabuf_put_u8(req, 'S');
	wpabuf_put_u8(req, '=');
	wpa_snprintf_hex_uppercase(
		wpabuf_put(req, sizeof(data->auth_response) * 2),
		sizeof(data->auth_response) * 2 + 1,
		data->auth_response, sizeof(data->auth_response));

	wpabuf_put_u8(req, ' ');

	wpabuf_put_u8(req, 'M');
	wpabuf_put_u8(req, '=');
	wpabuf_put_data(req, message, os_strlen(message));

	wpa_hexdump_ascii(MSG_MSGDUMP, "EAP-MSCHAPV2: Success Request Message",msg, ms_len - sizeof(*ms));

	RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_GEN_SUCCESS_REQ,"bs",id,data->peer_identity);

  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_BUILD_SUCCESS_REQ_RTRN,"xLdp",data,"LIB_MCHP2_STAT",data->state,wpabuf_len(req),wpabuf_head(req));
	return req;
}

static struct wpabuf * eap_mschapv2_build_failure_req(
	struct eap_mschapv2_data *data, u8 id)
{
	struct wpabuf *req;
	struct eap_mschapv2_hdr *ms;
	char *message0 = "E=691 R=1 C="; // ERROR_AUTHENTICATION_FAILURE: 691
//char *message1 = " V=3 M=FAILED";
	char *message1 = "";
	size_t ms_len;

  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_BUILD_FAILURE_REQ,"xLdb",data,"LIB_MCHP2_STAT",data->state,id);

	if (!data->auth_challenge_from_tls &&
	    os_get_random(data->auth_challenge, CHALLENGE_LEN)) {

		RHP_BUG("");
		wpa_printf(MSG_ERROR, "EAP-MSCHAPV2: Failed to get random data");

		_eap_mschapv2_state(data,FAILURE);
		return NULL;
	}

	ms_len = sizeof(*ms) + os_strlen(message0) + os_strlen(message1) + 32;
	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_MSCHAPV2, ms_len, EAP_CODE_REQUEST, id);
	if (req == NULL) {

		RHP_BUG("");
		wpa_printf(MSG_ERROR, "EAP-MSCHAPV2: Failed to allocate memory for request");

		_eap_mschapv2_state(data,FAILURE);
		return NULL;
	}

	ms = wpabuf_put(req, sizeof(*ms));
	ms->op_code = MSCHAPV2_OP_FAILURE;
	ms->mschapv2_id = data->resp_mschapv2_id;
	WPA_PUT_BE16(ms->ms_length, ms_len);

	wpabuf_put_data(req, message0, os_strlen(message0));

	wpa_snprintf_hex_uppercase(
		wpabuf_put(req, sizeof(data->auth_challenge) * 2),
		sizeof(data->auth_challenge) * 2 + 1,
		data->auth_challenge, sizeof(data->auth_challenge));

	wpabuf_put_data(req, message1, os_strlen(message1));

	wpa_hexdump_ascii(MSG_MSGDUMP, "EAP-MSCHAPV2: Failure Request Message",(u8 *) message0, os_strlen(message0));

	RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_GEN_FAILURE_REQ,"bs",id,data->peer_identity);

  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_BUILD_FAILURE_REQ_RTRN,"xLdp",data,"LIB_MCHP2_STAT",data->state,wpabuf_len(req),wpabuf_head(req));
	return req;
}

static struct wpabuf * eap_mschapv2_build_eap_failure(
	struct eap_mschapv2_data *data, u8 id)
{
	struct wpabuf *req;

  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_BUILD_EAP_FAILURE,"xLdb",data,"LIB_MCHP2_STAT",data->state,id);

	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_MSCHAPV2, 0, EAP_CODE_FAILURE, id);
	if (req == NULL) {

		RHP_BUG("");
		wpa_printf(MSG_ERROR, "EAP-MSCHAPV2: Failed to allocate memory for request");

		_eap_mschapv2_state(data,FAILURE);
		return NULL;
	}


	_eap_mschapv2_state(data,FAILURE);

	RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_GEN_EAP_FAILURE,"bs",id,data->peer_identity);

	RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_BUILD_EAP_FAILURE_RTRN,"xLdp",data,"LIB_MCHP2_STAT",data->state,wpabuf_len(req),wpabuf_head(req));
	return req;
}

static struct wpabuf * eap_mschapv2_build_eap_success(
	struct eap_mschapv2_data *data, u8 id)
{
	struct wpabuf *req;

  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_BUILD_EAP_SUCCESS,"xLdb",data,"LIB_MCHP2_STAT",data->state,id);

	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_MSCHAPV2, 0, EAP_CODE_SUCCESS, id);
	if (req == NULL) {

		RHP_BUG("");
		wpa_printf(MSG_ERROR, "EAP-MSCHAPV2: Failed to allocate memory for request");

		_eap_mschapv2_state(data,FAILURE);
		return NULL;
	}


	_eap_mschapv2_state(data,SUCCESS);

	RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_GEN_EAP_SUCCESS,"bs",id,data->peer_identity);

	RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_BUILD_EAP_SUCCESS_RTRN,"xLdp",data,"LIB_MCHP2_STAT",data->state,wpabuf_len(req),wpabuf_head(req));
	return req;
}

static struct wpabuf * eap_mschapv2_build_eap_identity_req(
	struct eap_mschapv2_data *data, u8 id)
{
	struct wpabuf *req;

  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_BUILD_EAP_IDENTITY_REQ,"xLdb",data,"LIB_MCHP2_STAT",data->state,id);

	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_IDENTITY, 0, EAP_CODE_REQUEST, id);
	if (req == NULL) {

		RHP_BUG("");
		wpa_printf(MSG_ERROR, "EAP-MSCHAPV2: Failed to allocate memory for request");

		_eap_mschapv2_state(data,FAILURE);
		return NULL;
	}

	RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_GEN_EAP_IDENTITY_REQ,"b",id);

	RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_BUILD_EAP_IDENTITY_REQ_RTRN,"xLdp",data,"LIB_MCHP2_STAT",data->state,wpabuf_len(req),wpabuf_head(req));
	return req;
}

static struct wpabuf * eap_mschapv2_buildReq(void *priv,u8 id)
{
	struct eap_mschapv2_data *data = priv;
	struct wpabuf* ret = NULL;

  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_BUILDREQ,"xLdb",data,"LIB_MCHP2_STAT",data->state,id);

	switch (data->state) {
	case INIT:
		ret = eap_mschapv2_build_eap_identity_req(data, id);
		break;
	case CHALLENGE:
		ret = eap_mschapv2_build_challenge(data, id);
		break;
	case SUCCESS_REQ:
		ret = eap_mschapv2_build_success_req(data, id);
		break;
	case RETRY_REQ:
		ret = eap_mschapv2_build_failure_req(data, id);
		break;
	case SUCCESS_RESP:
		ret = eap_mschapv2_build_eap_success(data, id);
		break;
	case FAILURE_RESP:
		ret = eap_mschapv2_build_eap_failure(data, id);
		break;
	default:
		RHP_BUG("%d",data->state);
		wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: Unknown or invalid state %d in buildReq", data->state);
		goto error;
	}

	{
		rhp_proto_eap* eaphdr;
		u8 eap_type;
		rhp_proto_ms_chapv2* mshdr;

		if( wpabuf_size(ret) >= sizeof(rhp_proto_eap) + sizeof(rhp_proto_ms_chapv2) + 1 ){
			eaphdr = (rhp_proto_eap*)wpabuf_head(ret);
			eap_type = *((u8*)(eaphdr + 1));
			mshdr = (rhp_proto_ms_chapv2*)(((u8*)(eaphdr + 1)) + 1);
			RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_TX_REQ1,"LLbLLb","LIB_MCHP2_STAT",data->state,"EAP_CODE",eaphdr->code,eaphdr->identifier,"EAP_TYPE",eap_type,"MSCHAPV2",mshdr->ms_code,mshdr->ms_identifier);
		}else if( wpabuf_size(ret) >= sizeof(rhp_proto_eap) + 1 ){
			eaphdr = (rhp_proto_eap*)wpabuf_head(ret);
			eap_type = *((u8*)(eaphdr + 1));
			RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_TX_REQ2,"LLbL","LIB_MCHP2_STAT",data->state,"EAP_CODE",eaphdr->code,eaphdr->identifier,"EAP_TYPE",eap_type);
		}else if( wpabuf_size(ret) >= sizeof(rhp_proto_eap) ){
			eaphdr = (rhp_proto_eap*)wpabuf_head(ret);
			RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_TX_REQ3,"LLb","LIB_MCHP2_STAT",data->state,"EAP_CODE",eaphdr->code,eaphdr->identifier);
		}else{
			RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_TX_INVALID_REQ,"L","LIB_MCHP2_STAT",data->state);
		}
	}

	return ret;

error:
	RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_BUILDREQ_ERR,"xLd",data,"LIB_MCHP2_STAT",data->state);
	return NULL;
}


static Boolean eap_mschapv2_check(void *priv,struct wpabuf *respData)
{
	struct eap_mschapv2_data *data = priv;
	struct eap_mschapv2_hdr *resp;
	const u8 *pos;
	size_t len;

  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_CHECK,"xLdp",data,"LIB_MCHP2_STAT",data->state,wpabuf_len(respData),wpabuf_head(respData));

  if( data->state == INIT ){

  	const struct eap_hdr* eap_hdr = NULL;

  	eap_hdr = wpabuf_head(respData);

  	if( eap_hdr->code == EAP_CODE_RESPONSE ){

  		if( (wpabuf_len(respData) < sizeof(struct eap_hdr) + 2) ||
  				*((u8*)(eap_hdr + 1)) != EAP_TYPE_IDENTITY ){

  			RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_CHECK_INVALID_IDENTITY_RESP,"x",data);
  			RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_INVALID_EAP_IDENTITY_RESP,"L","LIB_MCHP2_STAT",data->state);
  			return TRUE;
  		}

  	}else{

			RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_CHECK_INVALID_IDENTITY_RESP_2,"x",data);
			RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_INVALID_EAP_IDENTITY_RESP,"L","LIB_MCHP2_STAT",data->state);
			return TRUE;
  	}

		RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_CHECK_IDENTITY_RESP_OK,"x",data);

  }else{

		pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_MSCHAPV2, respData,&len);
		if (pos == NULL || len < 1) {
			RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_CHECK_INVALID_FRAME,"x",data);
			wpa_printf(MSG_INFO, "EAP-MSCHAPV2: Invalid frame");
			RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_INVALID_EAP_FRAME,"L","LIB_MCHP2_STAT",data->state);
			return TRUE;
		}

		resp = (struct eap_mschapv2_hdr *) pos;
		if ((data->state == CHALLENGE || data->state == RETRY_REQ) &&
				resp->op_code != MSCHAPV2_OP_RESPONSE) {
			RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_CHECK_UNEXPECTED_OP_CODE,"xd",data,(int)resp->op_code);
			wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: Expected Response - ignore op %d", resp->op_code);
			RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_INVALID_MSCHAPV2_CODE,"bL",resp->op_code,"LIB_MCHP2_STAT",data->state);
			return TRUE;
		}

		if (data->state == SUCCESS_REQ &&
				resp->op_code != MSCHAPV2_OP_SUCCESS &&
				resp->op_code != MSCHAPV2_OP_FAILURE) {
			RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_CHECK_UNEXPECTED_OP_CODE_2,"xd",data,(int)resp->op_code);
			wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: Expected Success or Failure - ignore op %d", resp->op_code);
			RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_INVALID_MSCHAPV2_CODE2,"bL",resp->op_code,"LIB_MCHP2_STAT",data->state);
			return TRUE;
		}
  }

  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_CHECK_OK,"x",data);
	return FALSE;
}


static void eap_mschapv2_process_response(
					  struct eap_mschapv2_data *data,
					  struct wpabuf *respData,
					  int (*get_password)(void* ctx,const u8* name,int name_len,u8** password_r),void* ctx)
{
	struct eap_mschapv2_hdr *resp;
	const u8 *pos, *end, *peer_challenge, *nt_response, *name;
	u8 flags;
	size_t len, name_len, i;
	u8 expected[24];
	const u8* user;
	size_t user_len;
	int res;
	u8* password = NULL;
	int password_len;

  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_PROCESS_RESPONSE,"xLdpYx",data,"LIB_MCHP2_STAT",data->state,wpabuf_len(respData),wpabuf_head(respData),get_password,ctx);

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_MSCHAPV2, respData, &len);
	if (pos == NULL || len < 1){
		_eap_mschapv2_state(data,FAILURE_RESP);
	  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_PROCESS_RESPONSE_INVALID_HDR,"xLd",data,"LIB_MCHP2_STAT",data->state);
		return; /* Should not happen - frame already validated */
	}

	end = pos + len;
	resp = (struct eap_mschapv2_hdr *) pos;
	pos = (u8 *) (resp + 1);

	if (len < sizeof(*resp) + 1 + 49 ||
	    resp->op_code != MSCHAPV2_OP_RESPONSE ||
	    pos[0] != 49) {

		_eap_mschapv2_state(data,FAILURE_RESP);

	  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_PROCESS_RESPONSE_INVALID_RESP,"xLd",data,"LIB_MCHP2_STAT",data->state);
		wpa_hexdump_buf(MSG_DEBUG, "EAP-MSCHAPV2: Invalid response",respData);

		return;
	}

	data->resp_mschapv2_id = resp->mschapv2_id;
	pos++;
	peer_challenge = pos;
	pos += 16 + 8;
	nt_response = pos;
	pos += 24;
	flags = *pos++;
	name = pos;
	name_len = end - name;

	if (data->peer_challenge) {
		wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: Using pre-configured Peer-Challenge");
		peer_challenge = data->peer_challenge;
	}
	wpa_hexdump(MSG_MSGDUMP, "EAP-MSCHAPV2: Peer-Challenge",peer_challenge, 16);
	wpa_hexdump(MSG_MSGDUMP, "EAP-MSCHAPV2: NT-Response", nt_response, 24);
	wpa_printf(MSG_MSGDUMP, "EAP-MSCHAPV2: Flags 0x%x", flags);
	wpa_hexdump_ascii(MSG_MSGDUMP, "EAP-MSCHAPV2: Name", name, name_len);


	if( data->peer_identity ){
		os_free(data->peer_identity);
	}
	data->peer_identity = (u8*)os_zalloc(name_len + 1);
	if( data->peer_identity == NULL ){

		_eap_mschapv2_state(data,FAILURE_RESP);

		RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_PROCESS_RESPONSE_ALLOC_NAME_BUF_ERR,"xLdp",data,"LIB_MCHP2_STAT",data->state,name_len,name);
		return;
	}
	memcpy(data->peer_identity,name,name_len);
	data->peer_identity[name_len] = '\0'; // For log output.
	data->peer_identity_len = name_len; // NOT including '\0'.



	// MSCHAPv2 does not include optional domain name in the
	// challenge-response calculation, so remove domain prefix
	// (if present).
	user = name;
	user_len = name_len;
	for (i = 0; i < user_len; i++) {
		if (user[i] == '\\') {
			user_len -= i + 1;
			user += i + 1;
			break;
		}
	}

	password_len = get_password(ctx,name,name_len,&password);
	if( password_len <= 0 ){

		RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_PROCESS_RESPONSE_NO_PASSWORD,"xLd",data,"LIB_MCHP2_STAT",data->state);

	  goto retries;
	}

	wpa_hexdump_ascii(MSG_MSGDUMP, "EAP-MSCHAPV2: User name",user, user_len);


	res = generate_nt_response(data->auth_challenge,
					   peer_challenge,
					   user, user_len,
					   password,password_len,
					   expected);
	if (res) {

		_eap_mschapv2_state(data,FAILURE_RESP);
	  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_PROCESS_RESPONSE_GEN_NT_RESP_ERR,"xLd",data,"LIB_MCHP2_STAT",data->state);
		return;
	}

	if (os_memcmp(nt_response, expected, 24) == 0) {
		const u8 *pw_hash;
		u8 pw_hash_buf[16], pw_hash_hash[16];

		wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: Correct NT-Response");
		_eap_mschapv2_state(data,SUCCESS_REQ);

		// Authenticator response is not really needed yet, but
		// calculate it here so that peer_challenge and username need
		// not be saved.
		nt_password_hash(password,password_len,pw_hash_buf);
		pw_hash = pw_hash_buf;

		generate_authenticator_response_pwhash(
			pw_hash, peer_challenge, data->auth_challenge,
			user, user_len, nt_response,
			data->auth_response);

		hash_nt_password_hash(pw_hash, pw_hash_hash);
		get_master_key(pw_hash_hash, nt_response, data->master_key);
		data->master_key_valid = 1;

		wpa_hexdump_key(MSG_DEBUG, "EAP-MSCHAPV2: Derived Master Key",data->master_key, MSCHAPV2_KEY_LEN);

		RHP_LOG_I(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_PEER_AUTH_SUCCESS,"s",data->peer_identity);

		RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_PROCESS_RESPONSE_SUCCESS,"xLdpp",data,"LIB_MCHP2_STAT",data->state,CHALLENGE_LEN,data->auth_challenge,MSCHAPV2_KEY_LEN,data->master_key);

	} else {

		wpa_hexdump(MSG_MSGDUMP, "EAP-MSCHAPV2: Expected NT-Response", expected, 24);
		wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: Invalid NT-Response");

retries:
		if( data->retries >= rhp_gcfg_eap_mschapv2_max_auth_retries ){

			RHP_LOG_E(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_PEER_AUTH_FAILED,"sd",data->peer_identity,data->retries);

			_eap_mschapv2_state(data,FAILURE_RESP);

		}else{

			if( data->peer_identity && data->peer_identity[0] != '\0' ){
				RHP_LOG_E(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_PEER_AUTH_WAIT_RETRY,"sd",data->peer_identity,data->retries);
			}else{
				RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_PEER_AUTH_WAIT_RETRY,"sd",data->peer_identity,data->retries);
			}

			_eap_mschapv2_state(data,RETRY_REQ);
			data->retries++;
		}

		RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_PROCESS_RESPONSE_FAILURE,"xLdpddpp",data,"LIB_MCHP2_STAT",data->state,CHALLENGE_LEN,data->auth_challenge,data->retries,rhp_gcfg_eap_mschapv2_max_auth_retries,24,expected,24,nt_response);
	}
}


static void eap_mschapv2_process_success_resp(
					      struct eap_mschapv2_data *data,
					      struct wpabuf *respData)
{
	struct eap_mschapv2_hdr *resp;
	const u8 *pos;
	size_t len;

  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_PROCESS_SUCCESS_RESP,"xLdp",data,"LIB_MCHP2_STAT",data->state,wpabuf_len(respData),wpabuf_head(respData));

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_MSCHAPV2, respData,&len);
	if (pos == NULL || len < 1){
		_eap_mschapv2_state(data,FAILURE_RESP);

	  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_PROCESS_SUCCESS_RESP_INVALID_HDR,"xLd",data,"LIB_MCHP2_STAT",data->state);
		return; // Should not happen - frame already validated
	}

	resp = (struct eap_mschapv2_hdr *) pos;

	if (resp->op_code == MSCHAPV2_OP_SUCCESS) {

		wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: Received Success Response - authentication completed successfully");
		_eap_mschapv2_state(data,SUCCESS_RESP);

	  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_PROCESS_SUCCESS_RESP_RX_SUCCESS,"xLd",data,"LIB_MCHP2_STAT",data->state);

	} else {

		wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: Did not receive Success Response - peer rejected authentication");
		_eap_mschapv2_state(data,FAILURE_RESP);

		RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_PROCESS_SUCCESS_RESP_RX_FAILURE,"xLd",data,"LIB_MCHP2_STAT",data->state);
	}
}

static void eap_mschapv2_process_failure_resp(struct eap_mschapv2_data *data)
{
	_eap_mschapv2_state(data,FAILURE_RESP);
	RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_PROCESS_FAILURE_RESP,"xLd",data,"LIB_MCHP2_STAT",data->state);
}


static void eap_mschapv2_process_identity_resp(struct eap_mschapv2_data *data,
		struct wpabuf *respData)
{
	rhp_proto_eap* eaphdr;
	u8 eap_type;
	u8* id_val = NULL;
	int id_len = 0;

  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_PROCESS_IDENTITY_RESP,"xLdx",data,"LIB_MCHP2_STAT",data->state,respData);

	if( wpabuf_size(respData) < sizeof(rhp_proto_eap) + 2 ){
		goto error;
	}

	eaphdr = (rhp_proto_eap*)wpabuf_head(respData);
	eap_type = *((u8*)(eaphdr + 1));

	if( eaphdr->code != EAP_CODE_RESPONSE || eap_type != EAP_TYPE_IDENTITY ){
		goto error;
	}

	id_val = ((u8*)(eaphdr + 1)) + 1;
	id_len = wpabuf_size(respData) - sizeof(rhp_proto_eap) - 1;

	RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_RX_IDENTITY_RESP,"LLba","LIB_MCHP2_STAT",data->state,"EAP_CODE",eaphdr->code,eaphdr->identifier,id_len,id_val);

	_eap_mschapv2_state(data,CHALLENGE);

  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_PROCESS_IDENTITY_RESP_RTRN,"xLdx",data,"LIB_MCHP2_STAT",data->state,respData);
	return;

error:
	_eap_mschapv2_state(data,FAILURE);
	RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_RX_IDENTITY_RESP_ERR,"L","LIB_MCHP2_STAT",data->state);
  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_PROCESS_IDENTITY_RESP_ERR,"xLdx",data,"LIB_MCHP2_STAT",data->state,respData);
	return;
}

static void eap_mschapv2_process(void *priv,
				 struct wpabuf *respData,
				 int (*get_password)(void* ctx,const u8* username,int username_len,u8** password),void* ctx)
{
	struct eap_mschapv2_data *data = priv;

  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_PROCESS,"xLdx",data,"LIB_MCHP2_STAT",data->state,respData);

	if( get_password == NULL ) {
		RHP_BUG("");
		wpa_printf(MSG_INFO, "EAP-MSCHAPV2: Password not configured");
		_eap_mschapv2_state(data,FAILURE);
		return;
	}

	{
		rhp_proto_eap* eaphdr;
		u8 eap_type;
		rhp_proto_ms_chapv2* mshdr;

		if( wpabuf_size(respData) >= sizeof(rhp_proto_eap) + sizeof(rhp_proto_ms_chapv2) + 1 ){
			eaphdr = (rhp_proto_eap*)wpabuf_head(respData);
			eap_type = *((u8*)(eaphdr + 1));
			mshdr = (rhp_proto_ms_chapv2*)(((u8*)(eaphdr + 1)) + 1);
			RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_RX_RESP1,"LLbLLb","LIB_MCHP2_STAT",data->state,"EAP_CODE",eaphdr->code,eaphdr->identifier,"EAP_TYPE",eap_type,"MSCHAPV2",mshdr->ms_code,mshdr->ms_identifier);
		}else if( wpabuf_size(respData) >= sizeof(rhp_proto_eap) + 1 ){
			eaphdr = (rhp_proto_eap*)wpabuf_head(respData);
			eap_type = *((u8*)(eaphdr + 1));
			RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_RX_RESP2,"LLbL","LIB_MCHP2_STAT",data->state,"EAP_CODE",eaphdr->code,eaphdr->identifier,"EAP_TYPE",eap_type);
		}else if( wpabuf_size(respData) >= sizeof(rhp_proto_eap) ){
			eaphdr = (rhp_proto_eap*)wpabuf_head(respData);
			RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_RX_RESP3,"LLb","LIB_MCHP2_STAT",data->state,"EAP_CODE",eaphdr->code,eaphdr->identifier);
		}else{
			RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_SERVER_MSCHAPV2_RX_INVALID_RESP,"L","LIB_MCHP2_STAT",data->state);
		}
	}

	switch (data->state) {
	case INIT:
		eap_mschapv2_process_identity_resp(data, respData);
		break;
	case CHALLENGE:
	case RETRY_REQ:
		eap_mschapv2_process_response(data, respData,get_password,ctx);
		break;
	case SUCCESS_REQ:
		eap_mschapv2_process_success_resp(data, respData);
		break;
	default:
		eap_mschapv2_process_failure_resp(data);
		wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: Unknown state %d in process", data->state);
		break;
	}

  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_PROCESS_RTRN,"xLdx",data,"LIB_MCHP2_STAT",data->state,respData);
}


static Boolean eap_mschapv2_isDone(void *priv)
{
	struct eap_mschapv2_data *data = priv;
	int flag = data->state == SUCCESS || data->state == FAILURE;

  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_IS_DONE,"xLdd",data,"LIB_MCHP2_STAT",data->state,flag);
	return flag;
}

/*

https://msdn.microsoft.com/en-us/library/cc224635.aspx

3.1.5.1 Master Session Key (MSK) Derivation

	Upon successful authentication, Extensible Authentication Protocol Method for Microsoft CHAP derives two 16-byte keys, MasterSendKey and MasterReceiveKey (as specified in [RFC3079], section 3.3).

	MS-MPPE key attributes, defined in [RFC2548] section 2.4.2 and 2.4.3, are defined as follows on an Authenticator:
	 MS-MPPE-Recv-Key      = MasterReceiveKey
	 MS-MPPE-Send-Key      = MasterSendKey

	MS-MPPE keys attributes on a Peer are as populated as follows.
	 MS-MPPE-Recv-Key      = MasterSendKey
	 MS-MPPE-Send-Key      = MasterReceiveKey

	The Master Session Key [RFC3748] is derived from the two keys as follows:
	 MSK = MasterReceiveKey + MasterSendKey + 32 bytes zeroes (padding)

*/
static u8 * eap_mschapv2_getKey(void *priv, size_t *len)
{
	struct eap_mschapv2_data *data = priv;
	u8 *key;

  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_GETKEY,"xLdx",data,"LIB_MCHP2_STAT",data->state,len);

	if (data->state != SUCCESS || !data->master_key_valid){
	  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_GETKEY_BAD_STAT,"xLdd",data,"LIB_MCHP2_STAT",data->state,data->master_key_valid);
		return NULL;
	}

	*len = 2 * MSCHAPV2_KEY_LEN + 32;
	key = os_zalloc(*len);
	if (key == NULL){
		RHP_BUG("");
		return NULL;
	}

	// MSK = server MS-MPPE-Recv-Key + MS-MPPE-Send-Key + 32 bytes zeroes (padding)
	get_asymetric_start_key(data->master_key, key, MSCHAPV2_KEY_LEN, 0, 1);
	get_asymetric_start_key(data->master_key, key + MSCHAPV2_KEY_LEN,MSCHAPV2_KEY_LEN, 1, 1);

	wpa_hexdump_key(MSG_DEBUG, "EAP-MSCHAPV2: Derived key", key, *len);

  RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_GETKEY_RTRN,"xLdp",data,"LIB_MCHP2_STAT",data->state,*len,key);
	return key;
}


static Boolean eap_mschapv2_isSuccess(void *priv)
{
	struct eap_mschapv2_data *data = priv;
	int flag = data->state == SUCCESS;

	RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_IS_SUCCESS,"xLdd",data,"LIB_MCHP2_STAT",data->state,flag);
	return flag;
}


u8 * eap_mschapv2_get_peer_identity(void *priv,size_t *ident_len_r)
{
	struct eap_mschapv2_data *data = priv;
	u8* ident;

	ident = (u8*)os_zalloc(data->peer_identity_len);
	if( ident == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memcpy(ident,data->peer_identity,data->peer_identity_len);
	*ident_len_r = data->peer_identity_len;

	RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_GET_PEER_IDENTITY,"xp",data,*ident_len_r,ident);
	return ident;
}


int eap_server_mschapv2_register(void)
{
	struct eap_method *eap;
	int ret;

	RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_REGISTER,"");

	eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION,
				      EAP_VENDOR_IETF, EAP_TYPE_MSCHAPV2,"MSCHAPV2");

	if (eap == NULL){
		RHP_BUG("");
		return -1;
	}

	eap->init = eap_mschapv2_init;
	eap->cleanup = eap_mschapv2_cleanup;
	eap->buildReq = eap_mschapv2_buildReq;
	eap->check = eap_mschapv2_check;
	eap->process = eap_mschapv2_process;
	eap->isDone = eap_mschapv2_isDone;
	eap->getKey = eap_mschapv2_getKey;
	eap->isSuccess = eap_mschapv2_isSuccess;
	eap->get_peer_identity = eap_mschapv2_get_peer_identity;

	ret = eap_server_method_register(eap);
	if (ret){
		eap_server_method_free(eap);
	}

	RHP_TRC(0,RHPTRCID_EAP_MSCHAPV2_REGISTER_RTRN,"x",ret);
	return ret;
}
