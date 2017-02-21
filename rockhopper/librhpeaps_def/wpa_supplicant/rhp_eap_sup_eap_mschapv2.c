/*
 * EAP peer method: EAP-MSCHAPV2 (draft-kamath-pppext-eap-mschapv2-00.txt)
 * Copyright (c) 2004-2008, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 *
 * This file implements EAP peer part of EAP-MSCHAPV2 method (EAP type 26).
 * draft-kamath-pppext-eap-mschapv2-00.txt defines the Microsoft EAP CHAP
 * Extensions Protocol, Version 2, for mutual authentication and key
 * derivation. This encapsulates MS-CHAP-v2 protocol which is defined in
 * RFC 2759. Use of EAP-MSCHAPV2 derived keys with MPPE cipher is described in
 * RFC 3079.
 */

#include "includes.h"

#include "common.h"
#include "ms_funcs.h"
#include "wpa_ctrl.h"
#include "mschapv2.h"
#include "eap_i.h"
#include "eap_config.h"

#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_protocol.h"

#ifdef _MSC_VER
#pragma pack(push, 1)
#endif /* _MSC_VER */

extern int rhp_gcfg_eap_mschapv2_sup_skip_ms_len_check;


struct eap_mschapv2_hdr {
	u8 op_code; 			/* MSCHAPV2_OP_* */
	u8 mschapv2_id; 	/* usually same as EAP identifier; must be changed
			 	 	 	 	 	 	 	 * for challenges, but not for success/failure */
	u8 ms_length[2]; 	/* Note: misaligned; length - 5 */
	/* followed by data */
} STRUCT_PACKED;

/* Response Data field */
struct ms_response {
	u8 peer_challenge[MSCHAPV2_CHAL_LEN];
	u8 reserved[8];
	u8 nt_response[MSCHAPV2_NT_RESPONSE_LEN];
	u8 flags;
} STRUCT_PACKED;

/* Change-Password Data field */
struct ms_change_password {
	u8 encr_password[516];
	u8 encr_hash[16];
	u8 peer_challenge[MSCHAPV2_CHAL_LEN];
	u8 reserved[8];
	u8 nt_response[MSCHAPV2_NT_RESPONSE_LEN];
	u8 flags[2];
} STRUCT_PACKED;

#ifdef _MSC_VER
#pragma pack(pop)
#endif /* _MSC_VER */

#define MSCHAPV2_OP_CHALLENGE 			1
#define MSCHAPV2_OP_RESPONSE 				2
#define MSCHAPV2_OP_SUCCESS 				3
#define MSCHAPV2_OP_FAILURE 				4
#define MSCHAPV2_OP_CHANGE_PASSWORD 7

#define ERROR_RESTRICTED_LOGON_HOURS 	646
#define ERROR_ACCT_DISABLED 					647
#define ERROR_PASSWD_EXPIRED 					648
#define ERROR_NO_DIALIN_PERMISSION 		649
#define ERROR_AUTHENTICATION_FAILURE 	691
#define ERROR_CHANGING_PASSWORD 			709

#define PASSWD_CHANGE_CHAL_LEN 	16
#define MSCHAPV2_KEY_LEN 				16

/*

        0..n         (4)                     (6)
     +-----------------[CHALLENGE_RETRY_RESP]----------------+
     |                  ^                 \                  |
     |                  |(5)               \(2)              |
     +--->[CHALLENGE_RETRY_WAIT_NEWKEY]     \                |
                        ^                    \               V
                        |                     +------+     [FAILURE_RESP]---------->[FAILURE]
                        |                            |         ^         (7)
                        |                            |         |
                        |            +-------------------------+
                        |           /                |
                        |(4)       /(6)              V
  	[INIT]---------->[CHALLENGE_RESP]---------->[SUCCESS_RESP]---------->[SUCCESS]
     (*0)          (1)                        (2)                      (3)


   (*0) Set username/password

  - States: [state-label]


  - Triggers:                                 [SRC]    [DST]
   (1) Rx MSCHAP-challenge Req and          :  Svr  ==> Peer
       Tx MSCHAP-challenge Resp                Peer ==> Svr
   (2) Rx MSCHAP-Success Req and            :  Svr  ==> Peer
       Tx MSCHAP-Success Resp                  Peer ==> Svr
   (3) Rx EAP Success                       :  Svr  ==> Peer
   (4) Rx MSCHAP-Failure Req(Retry)         :  Svr  ==> Peer
   (5) Set new username/password            :
       and Tx MSCHAP-challenge Resp(Retry)     Peer ==> Svr
   (6) Rx MSCHAP-Failure Req and            :  Svr  ==> Peer
       Tx MSCHAP-Failure Resp                  Peer ==> Svr
   (7) Rx EAP-Failure                       :  Svr  ==> Peer

	- Error handling: (ex.) Rx EAP-Failure (Svr ==> Peer) or
	                        Svr's Auth error in [CHALLENGE_RESP]/[CHALLENGE_RETRY_RESP]

	   [CHALLENGE_RESP], [CHALLENGE_RETRY_RESP] or [SUCCESS_RESP] ==> [FAILURE]

*/

struct eap_mschapv2_data {

	u8 auth_response[MSCHAPV2_AUTH_RESPONSE_LEN];
	int auth_response_valid;

	int prev_error;

	u8 passwd_change_challenge[PASSWD_CHANGE_CHAL_LEN];
	int passwd_change_challenge_valid;
	int passwd_change_version;

	u8 retry_auth_challenge[MSCHAPV2_CHAL_LEN];

	/* Optional challenge values generated in EAP-FAST Phase 1 negotiation
	 */
	u8 *peer_challenge;
	u8 *auth_challenge;

	int phase2;
	u8 master_key[MSCHAPV2_MASTER_KEY_LEN];
	int master_key_valid;
	int success;

	struct wpabuf *prev_challenge;

	struct wpabuf *pend_failure_req;

	enum { INIT, CHALLENGE_RESP, CHALLENGE_RETRY_WAIT_NEWKEY, CHALLENGE_RETRY_RESP,
		SUCCESS_RESP, FAILURE_RESP, SUCCESS, FAILURE } state;

	u8 mschapv2_id;

	int tx_legacy_nack;
};


static inline void _eap_mschapv2_state(struct eap_mschapv2_data *data,int new_state)
{
  RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_STATE,"xLdLd",data,"LIB_S_MCHP2_STAT",data->state,"LIB_S_MCHP2_STAT",new_state);
	RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_PEER_MSCHAPV2_STATE,"LL","LIB_S_MCHP2_STAT",data->state,"LIB_S_MCHP2_STAT",new_state);
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

  RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_INIT,"xLd",data,"LIB_S_MCHP2_STAT",data->state);

	return data;
}


static void eap_mschapv2_cleanup(void *priv)
{
	struct eap_mschapv2_data *data = priv;

  RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_CLEANUP,"x",data);

	if(data->peer_challenge){
		os_free(data->peer_challenge);
	}
	if(data->auth_challenge){
		os_free(data->auth_challenge);
	}
	if(data->prev_challenge){
		wpabuf_free(data->prev_challenge);
	}
	if(data->pend_failure_req){
		wpabuf_free(data->pend_failure_req);
	}
	os_free(data);

  RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_CLEANUP_RTRN,"x",data);
}


static struct wpabuf * eap_mschapv2_challenge_reply(
	struct eap_mschapv2_data *data, u8 id,
	u8 mschapv2_id, const u8 *auth_challenge,
	int (*get_auth_key)(void* ctx,u8** user_name_r, size_t* user_name_len_r,
			u8** password_r, size_t* password_len_r),void* ctx)
{
	struct wpabuf *resp;
	struct eap_mschapv2_hdr *ms;
	u8 *peer_challenge;
	int ms_len;
	struct ms_response *r;
	size_t identity_len, password_len;
	u8 *identity = NULL, *password = NULL;
	int pwhash = 0;

  RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_CHALLENGE_REPLY,"xLdbbxYx",data,"LIB_S_MCHP2_STAT",data->state,id,mschapv2_id,auth_challenge,get_auth_key,ctx);

	wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: Generating Challenge Response");

	if( get_auth_key(ctx,&identity,&identity_len,&password,&password_len) ){
	  RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_CHALLENGE_REPLY_GET_AUTH_KEY_ERR,"x",data);
		return NULL;
	}

	ms_len = sizeof(*ms) + 1 + sizeof(*r) + identity_len;
	resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_MSCHAPV2, ms_len,EAP_CODE_RESPONSE, id);
	if (resp == NULL){
		RHP_BUG("");
		return NULL;
	}

	ms = wpabuf_put(resp, sizeof(*ms));
	ms->op_code = MSCHAPV2_OP_RESPONSE;
	ms->mschapv2_id = mschapv2_id;

	WPA_PUT_BE16(ms->ms_length, ms_len);

	wpabuf_put_u8(resp, sizeof(*r)); /* Value-Size */

	/* Response */
	r = wpabuf_put(resp, sizeof(*r));

	peer_challenge = r->peer_challenge;
	if (data->peer_challenge) {
		wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: peer_challenge generated in Phase 1");
	  RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_CHALLENGE_REPLY_PEER_CHALLENGE_GEN_IN_PHASE1,"x",data);
		peer_challenge = data->peer_challenge;
		os_memset(r->peer_challenge, 0, MSCHAPV2_CHAL_LEN);
	} else if (os_get_random(peer_challenge, MSCHAPV2_CHAL_LEN)) {
		RHP_BUG("");
		wpabuf_free(resp);
		return NULL;
	}
  RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_CHALLENGE_REPLY_KEY_PEER_CHALLENGE,"xp",data,MSCHAPV2_CHAL_LEN,peer_challenge);

	os_memset(r->reserved, 0, 8);

	if (data->auth_challenge) {
		wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: auth_challenge generated in Phase 1");
	  RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_CHALLENGE_REPLY_AUTH_CHALLENGE_GEN_IN_PHASE1,"xx",data,data->auth_challenge);
		auth_challenge = data->auth_challenge;
	}

	if (mschapv2_derive_response(identity, identity_len, password,
				     password_len, pwhash, auth_challenge,
				     peer_challenge, r->nt_response,
				     data->auth_response, data->master_key)) {

		wpa_printf(MSG_ERROR, "EAP-MSCHAPV2: Failed to derive response");
	  RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_CHALLENGE_REPLY_DERIVE_RESP_ERR,"x",data);
		wpabuf_free(resp);
		return NULL;
	}

	data->auth_response_valid = 1;
	data->master_key_valid = 1;

	r->flags = 0; /* reserved, must be zero */


	wpabuf_put_data(resp, identity, identity_len);
	wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: TX identifier %d mschapv2_id %d (response)", id, ms->mschapv2_id);

	RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_PEER_MSCHAPV2_GEN_CHALLENGE_REPLY,"b",id);

	if( identity ){
		_rhp_free(identity);
	}

	if(password){
		_rhp_free_zero(password,password_len);
	}

	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_CHALLENGE_REPLY_RTRN,"xLdp",data,"LIB_S_MCHP2_STAT",data->state,wpabuf_len(resp),wpabuf_head(resp));
	return resp;
}


/**
 * eap_mschapv2_process - Process an EAP-MSCHAPv2 challenge message
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @data: Pointer to private EAP method data from eap_mschapv2_init()
 * @ret: Return values from EAP request validation and processing
 * @req: Pointer to EAP-MSCHAPv2 header from the request
 * @req_len: Length of the EAP-MSCHAPv2 data
 * @id: EAP identifier used in the request
 * Returns: Pointer to allocated EAP response packet (eapRespData) or %NULL if
 * no reply available
 */
static struct wpabuf * eap_mschapv2_challenge(
	struct eap_mschapv2_data *data,
	struct eap_method_ret *ret, const struct eap_mschapv2_hdr *req,
	size_t req_len, u8 id,
	int (*get_auth_key)(void* ctx,u8** user_name_r, size_t* user_name_len_r,
			u8** password_r, size_t* password_len_r),void* ctx)
{
	size_t len, challenge_len;
	const u8 *pos, *challenge;
	struct wpabuf *rep;

	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_CHALLENGE,"xLdxpbYx",data,"LIB_S_MCHP2_STAT",data->state,ret,(int)req_len,req,id,get_auth_key,ctx);

	wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: Received challenge");
	if (req_len < sizeof(*req) + 1) {
		wpa_printf(MSG_INFO, "EAP-MSCHAPV2: Too short challenge data (len %lu)", (unsigned long) req_len);
		RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_PEER_MSCHAPV2_TOO_SHORT_CHALLENGE_DATA,"bu",id,(unsigned long)req_len);
		RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_CHALLENGE_TOO_SHORT_CHALLENGE_DATA,"xfd",data,req_len,sizeof(struct eap_mschapv2_hdr));
		ret->ignore = TRUE;
		return NULL;
	}

	pos = (const u8 *) (req + 1);
	challenge_len = *pos++;
	len = req_len - sizeof(*req) - 1;
	if (challenge_len != MSCHAPV2_CHAL_LEN) {
		wpa_printf(MSG_INFO, "EAP-MSCHAPV2: Invalid challenge length %lu", (unsigned long) challenge_len);
		RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_PEER_MSCHAPV2_INVALID_CHALLENGE_LEN,"bu",id,(unsigned long)challenge_len);
		RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_CHALLENGE_INVALID_CHALLENGE_LEN,"xfd",data,challenge_len,MSCHAPV2_CHAL_LEN);
		ret->ignore = TRUE;
		return NULL;
	}

	if (len < challenge_len) {
		wpa_printf(MSG_INFO, "EAP-MSCHAPV2: Too short challenge packet: len=%lu challenge_len=%lu",
			   (unsigned long) len, (unsigned long) challenge_len);
		RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_PEER_MSCHAPV2_TOO_SHORT_CHALLENGE_PACKET,"bu",id,(unsigned long)len,(unsigned long)challenge_len);
		RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_CHALLENGE_TOO_SHORT_CHALLENGE_PACKET,"xff",data,len,challenge_len);
		ret->ignore = TRUE;
		return NULL;
	}

	challenge = pos;
	pos += challenge_len;
	len -= challenge_len;
	wpa_hexdump_ascii(MSG_DEBUG, "EAP-MSCHAPV2: Authentication Servername",pos, len);

	ret->ignore = FALSE;
	ret->decision = DECISION_FAIL;
	ret->allowNotifications = TRUE;

	rep = eap_mschapv2_challenge_reply(data, id, req->mschapv2_id,challenge,get_auth_key,ctx);
	if( rep ){

		data->mschapv2_id = req->mschapv2_id;

		ret->methodState = METHOD_MAY_CONT;
		_eap_mschapv2_state(data,CHALLENGE_RESP);

		RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_PEER_MSCHAPV2_PROCESS_CHALLENGE_REQ,"b",id);

		RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_CHALLENGE_RTRN,"xLdp",data,"LIB_S_MCHP2_STAT",data->state,wpabuf_len(rep),wpabuf_head(rep));
		return rep;
	}

	ret->methodState = METHOD_DONE;
	_eap_mschapv2_state(data,FAILURE);

	RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_PEER_MSCHAPV2_GEN_CHALLENGE_REPLY_ERR,"b",id);
	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_CHALLENGE_ERR,"xLd",data,"LIB_S_MCHP2_STAT",data->state);
	return NULL;
}


/**
 * eap_mschapv2_process - Process an EAP-MSCHAPv2 success message
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @data: Pointer to private EAP method data from eap_mschapv2_init()
 * @ret: Return values from EAP request validation and processing
 * @req: Pointer to EAP-MSCHAPv2 header from the request
 * @req_len: Length of the EAP-MSCHAPv2 data
 * @id: EAP identifier used in th erequest
 * Returns: Pointer to allocated EAP response packet (eapRespData) or %NULL if
 * no reply available
 */
static struct wpabuf * eap_mschapv2_success(
					    struct eap_mschapv2_data *data,
					    struct eap_method_ret *ret,
					    const struct eap_mschapv2_hdr *req,
					    size_t req_len, u8 id)
{
	struct wpabuf *resp;
	const u8 *pos;
	size_t len;

	wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: Received success");
	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_SUCCESS,"xLdxpb",data,"LIB_S_MCHP2_STAT",data->state,ret,(int)req_len,req,id);

	len = req_len - sizeof(*req);
	pos = (const u8 *) (req + 1);

	if (!data->auth_response_valid ||
	    mschapv2_verify_auth_response(data->auth_response, pos, len)) {

		wpa_printf(MSG_WARNING, "EAP-MSCHAPV2: Invalid authenticator response in success request");

		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		_eap_mschapv2_state(data,FAILURE);

		RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_PEER_MSCHAPV2_INVALID_SUCCESS_REQ,"b",id);

		RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_SUCCESS_INVALID_RESP,"xLd",data,"LIB_S_MCHP2_STAT",data->state);
		return NULL;
	}

	pos += 2 + 2 * MSCHAPV2_AUTH_RESPONSE_LEN;
	len -= 2 + 2 * MSCHAPV2_AUTH_RESPONSE_LEN;

	while (len > 0 && *pos == ' ') {
		pos++;
		len--;
	}

	wpa_hexdump_ascii(MSG_DEBUG, "EAP-MSCHAPV2: Success message",pos, len);
	wpa_printf(MSG_INFO, "EAP-MSCHAPV2: Authentication succeeded");

	/* Note: Only op_code of the EAP-MSCHAPV2 header is included in success
	 * message. */
	resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_MSCHAPV2, 1,EAP_CODE_RESPONSE, id);
	if (resp == NULL) {

		wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: Failed to allocate buffer for success response");
		RHP_BUG("");

		ret->ignore = FALSE;
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		ret->allowNotifications = FALSE;
		_eap_mschapv2_state(data,FAILURE);

		RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_PEER_MSCHAPV2_GEN_SUUCESS_REPLY_ERR,"b",id);
		return NULL;
	}

	wpabuf_put_u8(resp, MSCHAPV2_OP_SUCCESS); /* op_code */

	ret->ignore = FALSE;
	ret->methodState = METHOD_MAY_CONT;
	ret->decision = DECISION_COND_SUCC;
	ret->allowNotifications = FALSE;
	_eap_mschapv2_state(data,SUCCESS_RESP);

	RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_PEER_MSCHAPV2_PROCESS_SUCCESS_REQ,"b",id);

	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_SUCCESS_RTRN,"xLdp",data,"LIB_S_MCHP2_STAT",data->state,wpabuf_len(resp),wpabuf_head(resp));
	return resp;
}

static void eap_mschapv2_eap_success(
					    struct eap_mschapv2_data *data,
					    struct eap_method_ret *ret, const struct eap_hdr* eap_hdr)
{
	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_EAP_SUCCESS,"xLd",data,"LIB_S_MCHP2_STAT",data->state);

	ret->ignore = FALSE;
	ret->methodState = METHOD_DONE;
	ret->decision = DECISION_UNCOND_SUCC;
	ret->allowNotifications = FALSE;
	data->success = 1;

	_eap_mschapv2_state(data,SUCCESS);

	RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_PEER_MSCHAPV2_PROCESS_EAP_SUCCESS,"b",eap_hdr->identifier);

	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_EAP_SUCCESS_RTRN,"xLd",data,"LIB_S_MCHP2_STAT",data->state);
	return;
}


static int eap_mschapv2_failure_txt(
				    struct eap_mschapv2_data *data, char *txt)
{
	char *pos, *msg = "";
	int retry = 1;

	/* For example:
	 * E=691 R=1 C=<32 octets hex challenge> V=3 M=Authentication Failure
	 */

	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_FAILURE_TXT,"xLds",data,"LIB_S_MCHP2_STAT",data->state,txt);

	pos = txt;

	if (pos && os_strncmp(pos, "E=", 2) == 0) {

		pos += 2;
		data->prev_error = atoi(pos);

		wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: error %d",data->prev_error);
		RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_FAILURE_TXT_ERR_CODE,"xd",data,data->prev_error);

		pos = os_strchr(pos, ' ');
		if (pos){
			pos++;
		}
	}

	if (pos && os_strncmp(pos, "R=", 2) == 0) {

		pos += 2;
		retry = atoi(pos);

		wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: retry is %sallowed",retry == 1 ? "" : "not ");
		RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_FAILURE_TXT_RETRY,"xd",data,retry);

		pos = os_strchr(pos, ' ');
		if (pos){
			pos++;
		}

	}

	if (pos && os_strncmp(pos, "C=", 2) == 0) {

		int hex_len;
		char *pos2;
		pos += 2;

		pos2 = os_strchr(pos, ' ');
		if( pos2 ){
			hex_len = pos2 - (char *) pos;
		}else{
			hex_len = os_strlen(pos);
		}

		if( data->prev_error == ERROR_AUTHENTICATION_FAILURE ){

			if (hex_len == MSCHAPV2_CHAL_LEN * 2) {

				if (hexstr2bin(pos, data->retry_auth_challenge,MSCHAPV2_CHAL_LEN)) {

					wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: invalid failure challenge");
					RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_FAILURE_TXT_INVALID_FAILURE_CHALLENGE,"x",data);

					RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_FAILURE_TXT_ERR_1,"x",data);
					return -1;

				} else {

					wpa_hexdump(MSG_DEBUG, "EAP-MSCHAPV2: failure challenge",
					    data->retry_auth_challenge,MSCHAPV2_CHAL_LEN);

					RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_FAILURE_TXT_FAILURE_CHALLENGE,"xp",data,MSCHAPV2_CHAL_LEN,data->retry_auth_challenge);
				}

			} else {

				wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: invalid failure challenge len %d", hex_len);
				RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_FAILURE_TXT_INVALID_FAILURE_CHALLENGE_LEN,"xd",data,hex_len);
			}
		}

		pos = os_strchr(pos, ' ');
		if (pos){
			pos++;
		}

	} else {

		wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: required challenge field was not present in failure message");
		RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_FAILURE_TXT_NO_FAILURE_CHALLENGE,"x",data);

		if( retry == 1 ){
			RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_FAILURE_TXT_ERR_2,"x",data);
			return -1;
		}
	}

	if (pos && os_strncmp(pos, "V=", 2) == 0) {

		pos += 2;
		data->passwd_change_version = atoi(pos);

		wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: password changing protocol version %d", data->passwd_change_version);
		RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_FAILURE_TXT_PASSWORD_CHANGING_PROT_VER,"xd",data,data->passwd_change_version);

		pos = os_strchr(pos, ' ');
		if (pos){
			pos++;
		}
	}

	if (pos && os_strncmp(pos, "M=", 2) == 0) {
		pos += 2;
		msg = pos;
		wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: mesg %s", msg);
		RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_FAILURE_TXT_MESG,"xs",msg);
	}

	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_FAILURE_TXT_RTRN,"xd",data,(retry == 1));
	return (retry == 1);
}


static int eap_mschapv2_copy_failure_req(struct eap_mschapv2_data *data,
					const struct wpabuf *reqData)
{
	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_COPY_FAILURE_REQ,"xp",data,wpabuf_len(reqData),wpabuf_head(reqData));

	/*
	 * Store a copy of the failure_req message, so that it can be processed
	 * again in case retry is allowed after a possible failure.
	 */
	wpabuf_free(data->pend_failure_req);
	data->pend_failure_req = wpabuf_dup(reqData);

	if( data->pend_failure_req == NULL ){
		RHP_BUG("");
		return -1;
	}

	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_COPY_FAILURE_REQ_RTRN,"xxx",data,reqData,data->pend_failure_req);
	return 0;
}


/**
 * eap_mschapv2_process - Process an EAP-MSCHAPv2 failure message
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @data: Pointer to private EAP method data from eap_mschapv2_init()
 * @ret: Return values from EAP request validation and processing
 * @req: Pointer to EAP-MSCHAPv2 header from the request
 * @req_len: Length of the EAP-MSCHAPv2 data
 * @id: EAP identifier used in th erequest
 * Returns: Pointer to allocated EAP response packet (eapRespData) or %NULL if
 * no reply available
 */
static struct wpabuf * eap_mschapv2_failure(
					    struct eap_mschapv2_data *data,
					    struct eap_method_ret *ret,
					    const struct eap_mschapv2_hdr *req,
					    size_t req_len, u8 id,
					    const struct wpabuf *reqData)
{
	struct wpabuf *resp;
	const u8 *msdata = (const u8 *) (req + 1);
	char *buf;
	size_t len = req_len - sizeof(*req);
	int retry = 0;

	wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: Received failure");
	wpa_hexdump_ascii(MSG_DEBUG, "EAP-MSCHAPV2: Failure data",msdata, len);
	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_FAILURE,"xLdxpbp",data,"LIB_S_MCHP2_STAT",data->state,ret,req_len,req,id,(reqData ? wpabuf_len(reqData) : 0),(reqData ? wpabuf_head(reqData) : NULL));

	/*
	 * eap_mschapv2_failure_txt() expects a nul terminated string, so we
	 * must allocate a large enough temporary buffer to create that since
	 * the received message does not include nul termination.
	 */
	buf = os_malloc(len + 1);
	if (buf) {

		os_memcpy(buf, msdata, len);
		buf[len] = '\0';
		retry = eap_mschapv2_failure_txt(data, buf);
		os_free(buf);

		if( retry < 0 ){
			ret->ignore = TRUE;
			RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_FAILURE_ERR_1,"xLdx",data,"LIB_S_MCHP2_STAT",data->state,req);
			return NULL;
		}

		if( retry ){
			RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_PEER_MSCHAPV2_PROCESS_FAILURE_REQ_RETRY_ALLOWED,"b",id);
		}else{
			RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_PEER_MSCHAPV2_PROCESS_FAILURE_REQ_RETRY_NOT_ALLOWED,"b",id);
		}
	}

	if (retry && data->prev_error == ERROR_AUTHENTICATION_FAILURE) {

		/* TODO: could try to retry authentication, e.g, after having
		 * changed the username/password. In this case, EAP MS-CHAP-v2
		 * Failure Response would not be sent here. */

		ret->ignore = FALSE;
		ret->decision = DECISION_FAIL;
		ret->allowNotifications = FALSE;

		if( eap_mschapv2_copy_failure_req(data,reqData) ){

			ret->methodState = METHOD_DONE;
			_eap_mschapv2_state(data,FAILURE);

			RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_PEER_MSCHAPV2_PROCESS_FAILURE_REQ_WAITING_FOR_NEW_KEY_ERR,"b",id);

		}else{

			ret->methodState = METHOD_MAY_CONT;
			_eap_mschapv2_state(data,CHALLENGE_RETRY_WAIT_NEWKEY);

			RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_PEER_MSCHAPV2_PROCESS_FAILURE_REQ_WAITING_FOR_NEW_KEY,"b",id);
		}

		RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_FAILURE_ERR_2,"xLdx",data,"LIB_S_MCHP2_STAT",data->state,req);
		return NULL;
	}

	/* Note: Only op_code of the EAP-MSCHAPV2 header is included in failure
	 * message. */
	resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_MSCHAPV2, 1, EAP_CODE_RESPONSE, id);
	if (resp == NULL){

		RHP_BUG("");

		ret->ignore = FALSE;
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		ret->allowNotifications = FALSE;
		_eap_mschapv2_state(data,FAILURE);

		RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_PEER_MSCHAPV2_GEN_FAILURE_REPLY_ERR,"b",id);

		RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_FAILURE_ERR_3,"xLdx",data,"LIB_S_MCHP2_STAT",data->state,req);
		return NULL;
	}

	wpabuf_put_u8(resp, MSCHAPV2_OP_FAILURE); /* op_code */

	ret->ignore = FALSE;
	ret->methodState = METHOD_MAY_CONT;
	ret->decision = DECISION_FAIL;
	ret->allowNotifications = FALSE;
	_eap_mschapv2_state(data,FAILURE_RESP);

	RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_PEER_MSCHAPV2_PROCESS_FAILURE_REQ,"b",id);

	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_FAILURE_RTRN,"xLdxp",data,"LIB_S_MCHP2_STAT",data->state,req,wpabuf_len(resp),wpabuf_head(resp));
	return resp;
}


static int eap_mschapv2_check_mslen(size_t len,
				    const struct eap_mschapv2_hdr *ms)
{
	size_t ms_len = WPA_GET_BE16(ms->ms_length);

	if (ms_len == len){
		RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_CHECK_MSLEN_OK,"xff",ms,len,ms_len);
		return 0;
	}

	wpa_printf(MSG_INFO, "EAP-MSCHAPV2: Invalid header: len=%lu ms_len=%lu",
			(unsigned long) len, (unsigned long) ms_len);
	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_CHECK_MSLEN_INVALID_HEADER_LEN,"xff",ms,len,ms_len);

	if( rhp_gcfg_eap_mschapv2_sup_skip_ms_len_check ){

		/* Some authentication servers use invalid ms_len,
		 * ignore it for interoperability. */

		wpa_printf(MSG_INFO, "EAP-MSCHAPV2: workaround, ignore invalid ms_len %lu (len %lu)",
			   (unsigned long)ms_len,(unsigned long)len);
		RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_CHECK_MSLEN_INVALID_HEADER_LEN_IGNORED,"xff",ms,len,ms_len);

		return 0;
	}

	return -1;
}


static struct wpabuf * eap_mschapv2_identity_req(struct eap_mschapv2_data *data,
    struct eap_method_ret *ret,const struct wpabuf *reqData,u8 id,
    int (*get_auth_key)(void* ctx,u8** user_name_r, size_t* user_name_len_r,
    		u8** password_r, size_t* password_len_r),void* ctx)
{
	int err = -EINVAL;
	struct wpabuf *rep = NULL;
	u8* user_name = NULL;
	size_t user_name_len = 0;
	u8* p;

	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_IDENTITY_REQ,"xxxbYx",data,ret,reqData,id,get_auth_key,ctx);

	err = get_auth_key(ctx,&user_name,&user_name_len,NULL,NULL);
	if( err ){

		RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_PEER_MSCHAPV2_RX_IDENTITY_REQ_NO_USER_NAME,"b",id);

		RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_PROCESS_RX_IDENTITY_REQ_NO_USER_NAME,"xx",data,reqData);
		goto error;
	}

	rep = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_IDENTITY, user_name_len,EAP_CODE_RESPONSE, id);
	if (rep == NULL){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	p = wpabuf_put(rep,user_name_len);
	memcpy(p,user_name,user_name_len);

	ret->methodState = METHOD_MAY_CONT;

	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_IDENTITY_REQ_RTRN,"xx",data,rep);
	return rep;

error:
	ret->ignore = FALSE;
	ret->methodState = METHOD_DONE;
	ret->decision = DECISION_FAIL;

	_eap_mschapv2_state(data,FAILURE);

	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_IDENTITY_REQ_ERR,"xE",data,err);
	return NULL;
}

static struct wpabuf * eap_mschapv2_legach_nack(struct eap_mschapv2_data *data,
    struct eap_method_ret *ret,const struct wpabuf *reqData,u8 id,void* ctx)
{
	int err = -EINVAL;
	struct wpabuf *rep = NULL;
	u8* p;

	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_LEGACY_NACK,"xxxbxd",data,ret,reqData,id,ctx,data->tx_legacy_nack);

	if( data->tx_legacy_nack ){
		goto error;
	}

	rep = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NAK, 1,EAP_CODE_RESPONSE, id);
	if (rep == NULL){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	p = wpabuf_put(rep,1);
	*p = EAP_TYPE_MSCHAPV2;

	ret->methodState = METHOD_MAY_CONT;

	data->tx_legacy_nack = 1;

	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_LEGACY_NACK_RTRN,"xxd",data,rep,data->tx_legacy_nack);
	return rep;

error:
	ret->ignore = FALSE;
	ret->methodState = METHOD_DONE;
	ret->decision = DECISION_FAIL;

	_eap_mschapv2_state(data,FAILURE);

	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_LEGACY_NACK_ERR,"xdE",data,data->tx_legacy_nack,err);
	return NULL;
}

/**
 * eap_mschapv2_process - Process an EAP-MSCHAPv2 request
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @priv: Pointer to private EAP method data from eap_mschapv2_init()
 * @ret: Return values from EAP request validation and processing
 * @reqData: EAP request to be processed (eapReqData)
 * Returns: Pointer to allocated EAP response packet (eapRespData) or %NULL if
 * no reply available
 */
static struct wpabuf * eap_mschapv2_process(void *priv,
					    struct eap_method_ret *ret,
					    const struct wpabuf *reqData,
					    int (*get_auth_key)(void* ctx,u8** user_name_r, size_t* user_name_len_r,
					    		u8** password_r, size_t* password_len_r),void* ctx)
{
	struct eap_mschapv2_data *data = priv;
	const struct eap_hdr* eap_hdr = NULL;
	const struct eap_mschapv2_hdr *ms = NULL;
	const u8* pos = NULL;
	size_t len = 0;
	u8 id = 0;
	EapType eap_type;
	struct wpabuf *rep = NULL;
	int is_ident_req = 0;

	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_PROCESS,"xLdxpYx",data,"LIB_S_MCHP2_STAT",data->state,reqData,(reqData ? wpabuf_len(reqData) : 0),(reqData ? wpabuf_head(reqData) : NULL),get_auth_key,ctx);

	if( data->state == CHALLENGE_RETRY_WAIT_NEWKEY ){
		reqData = data->pend_failure_req;
		RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_PROCESS_PEND_FAILURE_REQ,"xxp",data,reqData,(reqData ? wpabuf_len(reqData) : 0),(reqData ? wpabuf_head(reqData) : NULL));
	}

	eap_hdr = wpabuf_head(reqData);

	if( eap_hdr->code == EAP_CODE_REQUEST ){

		if( (wpabuf_len(reqData) >= sizeof(struct eap_hdr) + 1) &&
				*((u8*)(eap_hdr + 1)) == EAP_TYPE_IDENTITY ){

			is_ident_req = 1;
		}
	}


	if( !is_ident_req ){

		pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_MSCHAPV2, reqData, &len);
		if ( eap_hdr == NULL || (pos && len < sizeof(*ms) + 1) ) {
			ret->ignore = TRUE;
			RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_PEER_MSCHAPV2_RX_INVALID_EAP_MESG_HDR,"b",eap_hdr->identifier);
			RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_PROCESS_INVALID_HEADER,"xx",data,reqData);
			goto error;
		}

	}else{

		if( data->state != INIT ){

			ret->ignore = FALSE;
			ret->methodState = METHOD_DONE;
			ret->decision = DECISION_FAIL;

			_eap_mschapv2_state(data,FAILURE);

			RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_PEER_MSCHAPV2_RX_INVALID_IDENTITY_REQ,"b",eap_hdr->identifier);

			RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_PROCESS_RX_INVALID_IDENTITY_REQ,"xx",data,reqData);
			goto error;
		}
	}

	if( eap_hdr->code == EAP_CODE_FAILURE ){ // (**)

		ret->ignore = FALSE;
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;

		_eap_mschapv2_state(data,FAILURE);

		RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_PEER_MSCHAPV2_RX_EAP_FAILURE,"b",eap_hdr->identifier);

		RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_PROCESS_CODE_FAILURE,"xx",data,reqData);
		goto error;
	}

	if( pos ){

		ms = (const struct eap_mschapv2_hdr *) pos;

		if (eap_mschapv2_check_mslen(len, ms)) {
			ret->ignore = TRUE;
			RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_PEER_MSCHAPV2_RX_INVALID_MSCHAPV2_HDR,"b",eap_hdr->identifier);
			RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_PROCESS_INVALID_MS_LEN,"xx",data,reqData);
			goto error;
		}
	}

	id = eap_get_id(reqData);
	eap_type = eap_get_type(reqData);
	wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: RX identifier %d mschapv2_id %d", id, (ms ? ms->mschapv2_id : 0));
	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_PROCESS_MSG_ID,"xxbbbb",data,reqData,id,(ms ? ms->mschapv2_id : 0),(ms ? ms->op_code : 0),eap_type);



	switch(data->state){

	case INIT:

		if( is_ident_req ){

			rep = eap_mschapv2_identity_req(data,ret,reqData,id,get_auth_key,ctx);

		}else{

			if( eap_type != EAP_TYPE_MSCHAPV2 ){

				rep = eap_mschapv2_legach_nack(data,ret,reqData,id,ctx);

			}else if( ms == NULL || ms->op_code != MSCHAPV2_OP_CHALLENGE ){

				ret->ignore = TRUE;
				RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_PROCESS_STAT_INIT_INVALID_MS_OP_CODE,"xxxb",data,reqData,ms,(ms ? ms->op_code : 0));
				goto error;

			}else{

				rep = eap_mschapv2_challenge(data, ret, ms, len, id,get_auth_key,ctx);
			}
		}

		break;

	case CHALLENGE_RESP:
	case CHALLENGE_RETRY_RESP:

		if( ms == NULL ){
			ret->ignore = TRUE;
			RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_PROCESS_STAT_CHALLENGE_RESP_OR_RETRY_RESP_NO_MS,"xx",data,reqData);
			goto error;
		}

		if( ms->op_code == MSCHAPV2_OP_SUCCESS ){

			rep = eap_mschapv2_success(data, ret, ms, len, id);

		}else if( ms->op_code == MSCHAPV2_OP_FAILURE ){

			rep = eap_mschapv2_failure(data, ret, ms, len, id, reqData);

		}else{
			ret->ignore = TRUE;
			RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_PROCESS_STAT_CHALLENGE_RESP_OR_RETRY_RESP_UNKNOWN_MS_OP_CODE,"xxb",data,reqData,ms->op_code);
			goto error;
		}

		break;

	case CHALLENGE_RETRY_WAIT_NEWKEY:
		//
		// TODO: this does not seem to be enough when processing two
		// or more failure messages. IAS did not increment mschapv2_id
		// in its own packets, but it seemed to expect the peer to
		// increment this for all packets(?).
		//

		rep = eap_mschapv2_challenge_reply(data, id,
				++(data->mschapv2_id),data->retry_auth_challenge,get_auth_key,ctx);

		if( rep ){

			ret->ignore = FALSE;
			ret->methodState = METHOD_MAY_CONT;
			ret->decision = DECISION_FAIL;
			_eap_mschapv2_state(data,CHALLENGE_RETRY_RESP);

			RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_PEER_MSCHAPV2_PROCESS_FAILURE_REQ_NEW_KEY,"b",id);
			RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_PROCESS_STAT_CHALLENGE_RETRY_WAIT_NEWKEY,"xxx",data,reqData,rep);

		}else{

			ret->ignore = FALSE;
			ret->methodState = METHOD_DONE;
			ret->decision = DECISION_FAIL;
			_eap_mschapv2_state(data,FAILURE);

			RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_PEER_MSCHAPV2_PROCESS_FAILURE_REQ_NEW_KEY_ERR,"b",id);
			RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_PROCESS_STAT_CHALLENGE_RETRY_WAIT_NEWKEY_ERR,"xx",data,reqData);

			goto error;
		}
		break;

	case SUCCESS_RESP:

		if( eap_hdr->code != EAP_CODE_SUCCESS ){
			ret->ignore = TRUE;
			RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_EAP_PEER_MSCHAPV2_RX_INVALID_EAP_MESG_IN_SUCCESS_RESP,"bb",id,eap_hdr->code);
			RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_PROCESS_STAT_SUCCESS_RESP_INVALID_EAP_OP_CODE,"xxb",data,reqData,eap_hdr->code);
			goto error;
		}

		eap_mschapv2_eap_success(data, ret, eap_hdr);

		RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_PROCESS_STAT_SUCCESS_RESP,"xx",data,reqData);
		break;

	case FAILURE_RESP: // ==> Transition to FAILURE by receiving EAP_FAILURE. See above code. (**)
		RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_PROCESS_STAT_FAILURE_RESP,"xx",data,reqData);
		break;

	default:
		ret->ignore = TRUE;
		RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_PROCESS_STAT_UNKNOWN,"xx",data,reqData);
		goto error;
	}

error:
	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_PROCESS_RTRN,"xLdxx",data,"LIB_S_MCHP2_STAT",data->state,reqData,rep);
	return rep;
}


static Boolean eap_mschapv2_isKeyAvailable(void *priv)
{
	struct eap_mschapv2_data *data = priv;
	Boolean flag = (data->success && data->master_key_valid);
	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_IS_KEY_AVAILABLE,"xLdd",data,"LIB_S_MCHP2_STAT",data->state,flag);
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
	int key_len;

	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_GETKEY,"xx",data,len);

	if (!data->master_key_valid || !data->success){
		RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_GETKEY_ERR_1,"xdd",data,data->master_key_valid,data->success);
		return NULL;
	}

	key_len = 2 * MSCHAPV2_KEY_LEN + 32;

	key = os_zalloc(key_len);
	if (key == NULL){
		RHP_BUG("");
		return NULL;
	}

	/* MSK = server MS-MPPE-Recv-Key | MS-MPPE-Send-Key + 32 bytes zeroes (padding),
	 * i.e., peer MS-MPPE-Send-Key | MS-MPPE-Recv-Key + 32 bytes zeroes (padding) */
	get_asymetric_start_key(data->master_key, key, MSCHAPV2_KEY_LEN, 1, 0);
	get_asymetric_start_key(data->master_key, key + MSCHAPV2_KEY_LEN,MSCHAPV2_KEY_LEN, 0, 0);

	wpa_hexdump_key(MSG_DEBUG, "EAP-MSCHAPV2: Derived key",key, key_len);

	*len = key_len;

	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_GETKEY_RTRN,"xLdp",data,"LIB_S_MCHP2_STAT",data->state,(int)*len,key);
	return key;
}

static Boolean eap_mschapv2_isSuccess(void *priv)
{
	struct eap_mschapv2_data *data = priv;
	Boolean flag = (data->state == SUCCESS);
	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_IS_SUCCESS,"xLdd",data,"LIB_S_MCHP2_STAT",data->state,flag);
	return flag;
}

static Boolean eap_mschapv2_isDone(void *priv)
{
	struct eap_mschapv2_data *data = priv;
	Boolean flag = (data->state == SUCCESS || data->state == FAILURE);
	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_IS_DONE,"xLdd",data,"LIB_S_MCHP2_STAT",data->state,flag);
	return flag;
}

Boolean eap_mschapv2_new_key_is_required(void *priv)
{
	struct eap_mschapv2_data *data = priv;
	Boolean flag = (data->state == CHALLENGE_RETRY_WAIT_NEWKEY);
	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_NEW_KEY_IS_REQUIRED,"xLdd",data,"LIB_S_MCHP2_STAT",data->state,flag);
	return flag;
}

/**
 * eap_peer_mschapv2_register - Register EAP-MSCHAPv2 peer method
 * Returns: 0 on success, -1 on failure
 *
 * This function is used to register EAP-MSCHAPv2 peer method into the EAP
 * method list.
 */
int eap_peer_mschapv2_register(void)
{
	struct eap_method *eap;
	int ret;

	eap = eap_peer_method_alloc(EAP_PEER_METHOD_INTERFACE_VERSION,
				    EAP_VENDOR_IETF, EAP_TYPE_MSCHAPV2,
				    "MSCHAPV2");
	if (eap == NULL){
		RHP_BUG("");
		return -1;
	}

	eap->init = eap_mschapv2_init;
	eap->cleanup = eap_mschapv2_cleanup;
	eap->process = eap_mschapv2_process;
	eap->isKeyAvailable = eap_mschapv2_isKeyAvailable;
	eap->getKey = eap_mschapv2_getKey;
	eap->isDone = eap_mschapv2_isDone;
	eap->isSuccess = eap_mschapv2_isSuccess;
	eap->newKeyIsRequired = eap_mschapv2_new_key_is_required;

	ret = eap_peer_method_register(eap);
	if (ret){
		eap_peer_method_free(eap);
	}

	RHP_TRC(0,RHPTRCID_EAP_SUP_MSCHAPV2_REGISTER,"d",ret);
	return ret;
}
