/*

	Copyright (C) 2015-2016 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.

	This library may be distributed, used, and modified under the terms of
	BSD license:

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are
	met:

	1. Redistributions of source code must retain the above copyright
		 notice, this list of conditions and the following disclaimer.

	2. Redistributions in binary form must reproduce the above copyright
		 notice, this list of conditions and the following disclaimer in the
		 documentation and/or other materials provided with the distribution.

	3. Neither the name(s) of the above-listed copyright holder(s) nor the
		 names of its contributors may be used to endorse or promote products
		 derived from this software without specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
	"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
	LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
	A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
	OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
	SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
	LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
	DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
	THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
	OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
#include "rhp_wthreads.h"
#include "rhp_timer.h"
#include "rhp_packet.h"
#include "rhp_netsock.h"
#include "rhp_packet.h"
#include "rhp_config.h"
#include "rhp_crypto.h"
#include "rhp_radius_impl.h"
#include "rhp_radius_priv.h"
#include "rhp_eap_auth_impl.h"


static rhp_mutex_t _rhp_radius_syspxy_lock;


// RHP_RADIUS_SECRET_IDX_XXX
static char* _rhp_radius_syspxy_keys[RHP_RADIUS_SECRET_IDX_MAX + 1] = {NULL,NULL,NULL,NULL}; // 0: primary server 1: secondary server
static int _rhp_radius_syspxy_keys_len[RHP_RADIUS_SECRET_IDX_MAX + 1] = {0,0,0,0};


int rhp_radius_syspxy_set_secret(int index,u8* key,int key_len)
{
  RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_SET_SECRET,"dp",index,key_len,key);

  if( index > RHP_RADIUS_SECRET_IDX_MAX ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
  	RHP_BUG("");
  	return -EPERM;
  }

	RHP_LOCK(&(_rhp_radius_syspxy_lock))

	if( _rhp_radius_syspxy_keys[index] ){
		_rhp_free_zero(_rhp_radius_syspxy_keys[index],_rhp_radius_syspxy_keys_len[index]);
		_rhp_radius_syspxy_keys[index] = NULL;
		_rhp_radius_syspxy_keys_len[index] = 0;
	}

	if( key_len && key ){

		_rhp_radius_syspxy_keys[index] = (char*)_rhp_malloc(key_len + 1);
		if( _rhp_radius_syspxy_keys[index] == NULL ){
			RHP_BUG("");
			RHP_UNLOCK(&(_rhp_radius_syspxy_lock))
			return -ENOMEM;
		}

		memcpy(_rhp_radius_syspxy_keys[index],key,key_len);
		_rhp_radius_syspxy_keys[index][key_len] = '\0';

		_rhp_radius_syspxy_keys_len[index] = key_len;
	}

	RHP_UNLOCK(&(_rhp_radius_syspxy_lock))

  RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_SET_SECRET_RTRN,"dp",index,_rhp_radius_syspxy_keys_len[index],_rhp_radius_syspxy_keys[index]);
	return 0;
}

static int _rhp_radius_syspxy_auth_sign(int secret_index,rhp_proto_radius* tx_radiush,u8** hmac_buf_r,int* hmac_buf_len_r,
		u8** radius_authenticator_r)
{
	int err = -EINVAL;
	u8* hmac_buf = NULL;
	int hmac_buf_len = 0;
	rhp_proto_radius_attr* radius_attr_mesg_auth = NULL;
	int radius_len = ntohs(tx_radiush->len);
	rhp_proto_radius* new_radiush = NULL;
	int acct_mesg_strm_len = 0;
	u8* acct_mesg_strm = NULL;

	if( secret_index > RHP_RADIUS_SECRET_IDX_MAX ){
		RHP_BUG("%d",secret_index);
		return -EINVAL;
	}

  RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_AUTH_SIGN,"xxxxp",tx_radiush,hmac_buf_r,hmac_buf_len_r,radius_authenticator_r,_rhp_radius_syspxy_keys_len[secret_index],_rhp_radius_syspxy_keys[secret_index]);

	if( _rhp_radius_syspxy_keys[secret_index] == NULL ){
		err = RHP_STATUS_RADIUS_NO_SECRET_FOUND;
  	RHP_LOG_E(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_RADIUS_NO_SHARED_SECRET_CONFIGURED,"L","RADIUS_SECRET_IDX",secret_index);
		goto error;
	}


	if( tx_radiush->code == RHP_RADIUS_CODE_ACCESS_REQUEST ){

		new_radiush	= (rhp_proto_radius*)_rhp_malloc(radius_len + 18);
		if( new_radiush == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		memcpy(new_radiush,tx_radiush,radius_len);


		err = rhp_random_bytes(new_radiush->authenticator,RHP_RADIUS_AUTHENTICATOR_LEN);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}


		radius_attr_mesg_auth = (rhp_proto_radius_attr*)(((u8*)new_radiush) + radius_len);
		radius_attr_mesg_auth->len = sizeof(rhp_proto_radius_attr) + RHP_RADIUS_MD5_SIZE;
		radius_attr_mesg_auth->type = RHP_RADIUS_ATTR_TYPE_MESG_AUTH;
		memset((u8*)(radius_attr_mesg_auth + 1),0,RHP_RADIUS_MD5_SIZE);

		new_radiush->len = htons(radius_len + sizeof(rhp_proto_radius_attr) + RHP_RADIUS_MD5_SIZE);


		err = rhp_crypto_hmac(RHP_CRYPTO_HMAC_MD5,
						(u8*)new_radiush,(radius_len + sizeof(rhp_proto_radius_attr) + RHP_RADIUS_MD5_SIZE),
						(u8*)_rhp_radius_syspxy_keys[secret_index],_rhp_radius_syspxy_keys_len[secret_index],
						&hmac_buf,&hmac_buf_len);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}


		*radius_authenticator_r = (u8*)_rhp_malloc(RHP_RADIUS_AUTHENTICATOR_LEN);
		if( *radius_authenticator_r == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
		memcpy(*radius_authenticator_r,new_radiush->authenticator,RHP_RADIUS_AUTHENTICATOR_LEN);

		*hmac_buf_r = hmac_buf;
		*hmac_buf_len_r = hmac_buf_len;

	}else if( tx_radiush->code == RHP_RADIUS_CODE_ACCT_REQUEST ){

		acct_mesg_strm_len = radius_len + _rhp_radius_syspxy_keys_len[secret_index];

		acct_mesg_strm = (u8*)_rhp_malloc(acct_mesg_strm_len);
		if( acct_mesg_strm == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		memset(tx_radiush->authenticator,0,RHP_RADIUS_AUTHENTICATOR_LEN);

		memcpy(acct_mesg_strm,tx_radiush,radius_len);
		memcpy(acct_mesg_strm + radius_len,
				(u8*)_rhp_radius_syspxy_keys[secret_index],_rhp_radius_syspxy_keys_len[secret_index]);

		err = rhp_crypto_md(RHP_CRYPTO_MD_MD5,acct_mesg_strm,acct_mesg_strm_len,&hmac_buf,&hmac_buf_len);
		if( err ){
			goto error;
		}

		*radius_authenticator_r = hmac_buf;

	}else{

		RHP_BUG("%d",tx_radiush->code);
		err = -EINVAL;
		goto error;
	}

	if(new_radiush){
		_rhp_free(new_radiush);
	}

	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_AUTH_SIGN_RTRN,"xpp",tx_radiush,*hmac_buf_len_r,*hmac_buf_r,RHP_RADIUS_AUTHENTICATOR_LEN,*radius_authenticator_r );
	return 0;

error:
	if(new_radiush){
		_rhp_free(new_radiush);
	}
	if(hmac_buf){
		_rhp_free(hmac_buf);
	}
	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_AUTH_SIGN_ERR,"xE",tx_radiush,err);
	return err;
}

static void _rhp_radius_syspxy_ipc_mesg_sign_handler(rhp_ipcmsg** ipcmsg)
{
	int err = -EINVAL;
	rhp_ipcmsg_radius_mesg_sign_req* sign_req = (rhp_ipcmsg_radius_mesg_sign_req*)*ipcmsg;
	rhp_proto_radius* tx_radiush;
	int radius_len;
	u8* hmac_buf = NULL;
	int hmac_buf_len = 0;
	u8* radius_authenticator = NULL;
	rhp_ipcmsg_radius_mesg_sign_rep* ipc_rep = NULL;

	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_IPC_MESG_SIGN_HANDLER,"xx",ipcmsg,sign_req);

	if( sign_req->len <= sizeof(rhp_ipcmsg_radius_mesg_sign_req) ){
		RHP_BUG("%d",sign_req->len);
		err = -EINVAL;
		goto error;
	}

	if( sign_req->type != RHP_IPC_RADIUS_MESG_SIGN_REQUEST ){
		RHP_BUG("%d",sign_req->type);
		err = -EINVAL;
		goto error;
	}

	if( sign_req->mesg_len < sizeof(rhp_proto_radius) + sizeof(rhp_proto_radius_attr) ){
		RHP_BUG("%d",sign_req->mesg_len);
		err = -EINVAL;
		goto error;
	}

	if( sign_req->len < sizeof(rhp_ipcmsg_radius_mesg_sign_req) + sign_req->mesg_len ){
		RHP_BUG("%d, %d, %d",sign_req->len,sizeof(rhp_ipcmsg_radius_mesg_sign_req),sign_req->mesg_len);
		err = -EINVAL;
		goto error;
	}

	if( sign_req->secret_index > RHP_RADIUS_SECRET_IDX_MAX ){
		RHP_BUG("%d",sign_req->secret_index);
		err = -EINVAL;
		goto error;
	}

	tx_radiush = (rhp_proto_radius*)(sign_req + 1);
	radius_len = ntohs(tx_radiush->len);
	if( radius_len != sign_req->mesg_len ){
		RHP_BUG("%d, %d",radius_len,sign_req->mesg_len);
		err = -EINVAL;
		goto error;
	}


	RHP_LOCK(&(_rhp_radius_syspxy_lock));

	err = _rhp_radius_syspxy_auth_sign((int)(sign_req->secret_index),
					tx_radiush,&hmac_buf,&hmac_buf_len,&radius_authenticator);
	if( err ){
		goto error;
	}

	err = 0;

error:
	RHP_UNLOCK(&(_rhp_radius_syspxy_lock));


	{
		ipc_rep = (rhp_ipcmsg_radius_mesg_sign_rep*)rhp_ipc_alloc_msg(RHP_IPC_RADIUS_MESG_SIGN_REPLY,
								sizeof(rhp_ipcmsg_radius_mesg_sign_rep) + RHP_RADIUS_AUTHENTICATOR_LEN + hmac_buf_len);

		if( ipc_rep ){

			if( !err ){

				ipc_rep->len = sizeof(rhp_ipcmsg_radius_mesg_sign_rep) + RHP_RADIUS_AUTHENTICATOR_LEN + hmac_buf_len;

				ipc_rep->authenticator_len = RHP_RADIUS_AUTHENTICATOR_LEN;
				ipc_rep->mesg_hash_len = hmac_buf_len;
				ipc_rep->txn_id = sign_req->txn_id;
				ipc_rep->result = 1;

				memcpy((u8*)(ipc_rep + 1),radius_authenticator,RHP_RADIUS_AUTHENTICATOR_LEN);
				memcpy(((u8*)(ipc_rep + 1) + RHP_RADIUS_AUTHENTICATOR_LEN),hmac_buf,hmac_buf_len);

			}else{

				ipc_rep->len = sizeof(rhp_ipcmsg_radius_mesg_sign_rep);
				ipc_rep->txn_id = sign_req->txn_id;
				ipc_rep->result = 0;
			}

			if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipc_rep,ipc_rep->len,0) < 0 ){
				RHP_BUG("");
		  }

		}else{
			RHP_BUG("");
		}
	}

	if( hmac_buf ){
		_rhp_free(hmac_buf);
	}
	if(radius_authenticator){
		_rhp_free(radius_authenticator);
	}

	if( sign_req ){
		_rhp_free_zero(sign_req,sign_req->len);
		*ipcmsg = NULL;
	}
	if( ipc_rep ){
		_rhp_free_zero(ipc_rep,ipc_rep->len);
	}

	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_IPC_MESG_SIGN_HANDLER_RTRN,"xE",sign_req,err);
	return;
}


static int _rhp_radius_syspxy_parse_mppe_key_attrs(rhp_proto_radius* rx_radiush,
		rhp_proto_radius_attr* radius_attrh,
		rhp_proto_radius_attr_vendor_ms** mppe_send_key_attr_r,
		int* mppe_send_key_attr_len_r,
		rhp_proto_radius_attr_vendor_ms** mppe_recv_key_attr_r,
		int* mppe_recv_key_attr_len_r,unsigned long vpn_realm_id)
{
	int err = -EINVAL;
	rhp_proto_radius_attr_vendor_ms *mppe_send_key_attr = NULL, *mppe_recv_key_attr = NULL;
	int mppe_send_key_attr_len = 0, mppe_recv_key_attr_len = 0;

	if( radius_attrh->len < sizeof(rhp_proto_radius_attr_vendor) ){
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_PARSE_MPPE_KEY_ATTRS_RADIUS_ACCEPT_VENDOR_ATTR_INVALID_LEN_1,"xxbbdd",rx_radiush,radius_attrh,rx_radiush->code,radius_attrh->type,radius_attrh->len,sizeof(rhp_proto_radius_attr_vendor));
		err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
		goto error;
	}

	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_PARSE_MPPE_KEY_ATTRS_RADIUS_ACCEPT_VENDOR_ATTR,"xxbbU",rx_radiush,radius_attrh,rx_radiush->code,radius_attrh->type,((rhp_proto_radius_attr_vendor*)radius_attrh)->vendor_id);

	if( ntohl(((rhp_proto_radius_attr_vendor*)radius_attrh)->vendor_id)
				== RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC_MICROSOFT ){

		if( radius_attrh->len
					> sizeof(rhp_proto_radius_attr_vendor) + sizeof(rhp_proto_radius_attr_vendor_ms) ){

			rhp_proto_radius_attr_vendor_ms* radius_attr_msh
				= (rhp_proto_radius_attr_vendor_ms*)(((rhp_proto_radius_attr_vendor*)radius_attrh) + 1);

			RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_PARSE_MPPE_KEY_ATTRS_RADIUS_ACCEPT_VENDOR_MS_ATTR,"xxbbJb",rx_radiush,radius_attrh,rx_radiush->code,radius_attrh->type,((rhp_proto_radius_attr_vendor*)radius_attrh)->vendor_id,radius_attr_msh->vendor_type);

			if( radius_attr_msh->vendor_type == RHP_RADIUS_VENDOR_MS_ATTR_TYPE_MPPE_SEND_KEY ){

				if( radius_attrh->len <
							sizeof(rhp_proto_radius_attr_vendor) + sizeof(rhp_proto_radius_attr_vendor_ms_mppe_send_key) ){
					err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
					RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_PARSE_MPPE_KEY_ATTRS_RADIUS_ACCEPT_VENDOR_MS_ATTR_INVALID_LEN_1,"xxbbddd",rx_radiush,radius_attrh,rx_radiush->code,radius_attrh->type,radius_attrh->len,sizeof(rhp_proto_radius_attr_vendor),sizeof(rhp_proto_radius_attr_vendor_ms_mppe_send_key));
					goto error;
				}

				mppe_send_key_attr = (rhp_proto_radius_attr_vendor_ms*)radius_attr_msh;
				mppe_send_key_attr_len = radius_attr_msh->vendor_len;

			}else if( radius_attr_msh->vendor_type == RHP_RADIUS_VENDOR_MS_ATTR_TYPE_MPPE_RECV_KEY ){

				if( radius_attrh->len <
							sizeof(rhp_proto_radius_attr_vendor) + sizeof(rhp_proto_radius_attr_vendor_ms_mppe_recv_key) ){
					err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
					RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_PARSE_MPPE_KEY_ATTRS_RADIUS_ACCEPT_VENDOR_MS_ATTR_INVALID_LEN_2,"xxbbddd",rx_radiush,radius_attrh,rx_radiush->code,radius_attrh->type,radius_attrh->len,sizeof(rhp_proto_radius_attr_vendor),sizeof(rhp_proto_radius_attr_vendor_ms_mppe_send_key));
					goto error;
				}

				mppe_recv_key_attr = (rhp_proto_radius_attr_vendor_ms*)radius_attr_msh;
				mppe_recv_key_attr_len = radius_attr_msh->vendor_len;
			}

		}else{

			RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_PARSE_MPPE_KEY_ATTRS_RADIUS_ACCEPT_VENDOR_ATTR_INVALID_LEN_2,"xxbbddd",rx_radiush,radius_attrh,rx_radiush->code,radius_attrh->type,radius_attrh->len,sizeof(rhp_proto_radius_attr_vendor),sizeof(rhp_proto_radius_attr_vendor_ms));
		}
	}


	if( *mppe_send_key_attr_len_r == 0 && mppe_send_key_attr ){
		*mppe_send_key_attr_r = mppe_send_key_attr;
		*mppe_send_key_attr_len_r = mppe_send_key_attr_len;
	  RHP_LOG_D(RHP_LOG_SRC_AUTH,vpn_realm_id,RHP_LOG_ID_RADIUS_SYSPXY_AUTH_PARSE_MS_MPPE_SEND_KEY,"Lbpp","RADIUS_CODE",rx_radiush->code,rx_radiush->id,RHP_RADIUS_AUTHENTICATOR_LEN,rx_radiush->authenticator,mppe_send_key_attr_len,mppe_send_key_attr);
	}

	if( *mppe_recv_key_attr_len_r == 0 && mppe_recv_key_attr ){
		*mppe_recv_key_attr_r = mppe_recv_key_attr;
		*mppe_recv_key_attr_len_r = mppe_recv_key_attr_len;
	  RHP_LOG_D(RHP_LOG_SRC_AUTH,vpn_realm_id,RHP_LOG_ID_RADIUS_SYSPXY_AUTH_PARSE_MS_MPPE_RECV_KEY,"Lbpp","RADIUS_CODE",rx_radiush->code,rx_radiush->id,RHP_RADIUS_AUTHENTICATOR_LEN,rx_radiush->authenticator,mppe_recv_key_attr_len,mppe_recv_key_attr);
	}

	return 0;

error:
	return err;
}

static int _rhp_radius_syspxy_parse_role_string_attrs(rhp_proto_radius* rx_radiush,
		rhp_proto_radius_attr* radius_attrh,rhp_string_list** role_strings_r,
		unsigned long vpn_realm_id,int off_set)
{
	int err = -EINVAL;
	u8* val;
	int val_len;
	rhp_string_list *ret = NULL, *end;

	end = *role_strings_r;
	while( end && end->next != NULL ){ end = end->next; }


	val = ((u8*)(radius_attrh + 1)) + off_set;
	val_len = radius_attrh->len - sizeof(rhp_proto_radius_attr) - off_set;

	if( val_len < 1 ){
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_PARSE_ROLE_STRING_ATTRS_INVALID_ATTR,"xxxd",rx_radiush,radius_attrh,val,val_len);
		err = 0;
		goto ignored;
	}

	if( radius_attrh->type == RHP_RADIUS_ATTR_TYPE_TUNNEL_PRIVATE_GROUP_ID ){

		if( val[0] <= 0x1F ){
			val++;
			val_len--;
		}

		if( val_len < 1 ){
			RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_PARSE_ROLE_STRING_ATTRS_INVALID_ATTR_2,"xxxd",rx_radiush,radius_attrh,val,val_len);
			err = 0;
			goto ignored;
		}
	}

	ret = (rhp_string_list*)_rhp_malloc(sizeof(rhp_string_list));
	if( ret == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memset(ret,0,sizeof(rhp_string_list));

	ret->string = (char*)_rhp_malloc(val_len + 1);
	if( ret->string == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memcpy(ret->string,val,val_len);
	ret->string[val_len] = '\0';

	if( end == NULL ){
		*role_strings_r = ret;
	}else{
		end->next = ret;
	}

  RHP_LOG_D(RHP_LOG_SRC_AUTH,vpn_realm_id,RHP_LOG_ID_RADIUS_SYSPXY_AUTH_PARSE_ROLE_STRING,"LbpLs","RADIUS_CODE",rx_radiush->code,rx_radiush->id,RHP_RADIUS_AUTHENTICATOR_LEN,rx_radiush->authenticator,"RADIUS_ATTR",radius_attrh->type,ret->string);

	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_PARSE_ROLE_STRING_ATTRS,"xxxs",rx_radiush,radius_attrh,ret,ret->string);

ignored:
	return 0;

error:
	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_PARSE_ROLE_STRING_ATTRS_ERR,"xxE",rx_radiush,radius_attrh,err);
	return err;
}

static int _rhp_radius_syspxy_parse_realm_id_attr(rhp_proto_radius* rx_radiush,
		rhp_proto_radius_attr* radius_attrh,unsigned long* rx_vpn_realm_id_r,
		unsigned long vpn_realm_id,int off_set)
{
	int err = -EINVAL, i;
	u8* val;
	int val_len;
	char *tmp = NULL, *endp = NULL;
	unsigned long ret_ulong;

	val = ((u8*)(radius_attrh + 1)) + off_set;
	val_len = radius_attrh->len - sizeof(rhp_proto_radius_attr) - off_set;

	if( val_len < 1 ){
		err = 0;
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_PARSE_REALM_ID_ATTR_INVALID_ATTR,"xxxd",rx_radiush,radius_attrh,val,val_len);
		goto error;
	}

	for(i = 0; i < val_len; i++){
		if( val[i] < '0' || val[i] > '9' ){
	  	goto error;
		}
	}

	tmp = (char*)_rhp_malloc(val_len + 1);
	if( tmp == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	memcpy(tmp,val,val_len);
	tmp[val_len] = '\0';


	ret_ulong = strtoul((char*)tmp,&endp,0);
  if( *endp != '\0' ){
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_PARSE_REALM_ID_ATTR_INVALID_ATTR_2,"xxxd",rx_radiush,radius_attrh,val,val_len);
  	err = -EINVAL;
  	goto error;
  }


	if( ret_ulong != 0 && ret_ulong != RHP_VPN_REALM_ID_UNKNOWN && ret_ulong <= RHP_VPN_REALM_ID_MAX ){
		*rx_vpn_realm_id_r = ret_ulong;
		err = 0;
	  RHP_LOG_D(RHP_LOG_SRC_AUTH,vpn_realm_id,RHP_LOG_ID_RADIUS_SYSPXY_AUTH_PARSE_REALM_ID,"Lbpu","RADIUS_CODE",rx_radiush->code,rx_radiush->id,RHP_RADIUS_AUTHENTICATOR_LEN,rx_radiush->authenticator,ret_ulong);
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_PARSE_REALM_ID_ATTR,"xxuu",rx_radiush,radius_attrh,*rx_vpn_realm_id_r,ret_ulong);
	}else{
		err = -EINVAL;
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_PARSE_REALM_ID_ATTR_INVALID_ATTR_3,"xxu",rx_radiush,radius_attrh,ret_ulong);
		goto error;
	}

error:
	if( tmp ){
		_rhp_free(tmp);
	}
	return err;
}

static int _rhp_radius_syspxy_parse_priv_attr_common(rhp_proto_radius* rx_radiush,
		rhp_proto_radius_attr* radius_attrh,
		unsigned long* rx_vpn_realm_id_r,rhp_string_list** role_strings_r,
		unsigned long vpn_realm_id)
{
	int err = -EINVAL;
	u8* val = NULL;
	int val_len = 0;
	int slen = 0;

	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_PARSE_PRIV_ATTR_COMMON,"xxxxu",rx_radiush,radius_attrh,rx_vpn_realm_id_r,role_strings_r,vpn_realm_id);

	val = (u8*)(radius_attrh + 1);
	val_len = radius_attrh->len - sizeof(rhp_proto_radius_attr);

	if( val_len < 1 ){
		err = 0;
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_PARSE_PRIV_ATTR_COMMON_INVALID_ATTR,"xxxd",rx_radiush,radius_attrh,val,val_len);
		goto error;
	}

	if( val_len > (slen = strlen("REALM_ID:")) &&
			val[0] == 'R' && val[1] == 'E' && val[2] == 'A' && val[3] == 'L' && val[4] == 'M' &&
			val[5] == '_' && val[6] == 'I' && val[7] == 'D' ){

		err = _rhp_radius_syspxy_parse_realm_id_attr(rx_radiush,radius_attrh,rx_vpn_realm_id_r,vpn_realm_id,slen);

	}else if( val_len > (slen = strlen("REALM_ROLE:")) &&
						val[0] == 'R' && val[1] == 'E' && val[2] == 'A' && val[3] == 'L' && val[4] == 'M' &&
						val[5] == '_' && val[6] == 'R' && val[7] == 'O' && val[8] == 'L' && val[9] == 'E' ){

		err = _rhp_radius_syspxy_parse_role_string_attrs(rx_radiush,radius_attrh,role_strings_r,vpn_realm_id,slen);

	}else{

		err = 0;
	}

error:
	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_PARSE_PRIV_ATTR_COMMON_RTRN,"xxxxuuxpE",rx_radiush,radius_attrh,rx_vpn_realm_id_r,role_strings_r,*rx_vpn_realm_id_r,vpn_realm_id,*role_strings_r,(val_len > 0 ? val_len : 0),(val_len > 0 ? val : NULL),err);
	return err;
}


static int _rhp_radius_syspxy_verify_authenticator(int secret_index,rhp_proto_radius* rx_radiush,
		u8* tx_authenticator)
{
	int err = -EINVAL;
	int radius_len = ntohs(rx_radiush->len);
	u8 *auth_buf = NULL, *md_buf = NULL;
	int auth_buf_len = 0, md_buf_len = 0;

	auth_buf_len = radius_len + _rhp_radius_syspxy_keys_len[secret_index];
	auth_buf = (u8*)_rhp_malloc(auth_buf_len);
	if( auth_buf == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memcpy(auth_buf,(u8*)rx_radiush,radius_len);
	memcpy(auth_buf + radius_len,_rhp_radius_syspxy_keys[secret_index],_rhp_radius_syspxy_keys_len[secret_index]);
	memcpy(((rhp_proto_radius*)auth_buf)->authenticator,tx_authenticator,RHP_RADIUS_AUTHENTICATOR_LEN);

	err = rhp_crypto_md(RHP_CRYPTO_MD_MD5,auth_buf,auth_buf_len,&md_buf,&md_buf_len);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	if( md_buf_len != RHP_RADIUS_AUTHENTICATOR_LEN ||
			memcmp(rx_radiush->authenticator,md_buf,md_buf_len) ){

		err = RHP_STATUS_RADIUS_INVALID_AUTHENTICATOR;

		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_AUTH_VERIFY_RADIUS_AUTHENTICATOR_NOT_MATCHED,"xpppp",rx_radiush,radius_len,(u8*)rx_radiush,auth_buf_len,auth_buf,RHP_RADIUS_AUTHENTICATOR_LEN,rx_radiush->authenticator,md_buf_len,md_buf);
		goto error;

	}else{

		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_AUTH_VERIFY_RADIUS_AUTHENTICATOR_OK,"xpppp",rx_radiush,radius_len,(u8*)rx_radiush,auth_buf_len,auth_buf,RHP_RADIUS_AUTHENTICATOR_LEN,rx_radiush->authenticator,md_buf_len,md_buf);
	}

	_rhp_free(auth_buf);
	_rhp_free(md_buf);

	return 0;

error:
	if( auth_buf ){
		_rhp_free(auth_buf);
	}
	if( md_buf ){
		_rhp_free(md_buf);
	}
	return err;
}

static int _rhp_radius_syspxy_verify_mesg_authenticator(
		int secret_index,
		rhp_proto_radius* rx_radiush,u8* tx_authenticator,
		u8* endp,int* verify_ok_r)
{
	int err = -EINVAL;
	int radius_len = ntohs(rx_radiush->len);
	u8 *auth_buf = NULL, *md_buf = NULL;
	int auth_buf_len = 0, md_buf_len = 0;
	rhp_proto_radius_attr* radius_attrh = (rhp_proto_radius_attr*)(rx_radiush + 1);

	while( (u8*)radius_attrh < endp ){

		if( (u8*)(radius_attrh + 1) > endp ){
			RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_AUTH_VERIFY_INVALID_RADIUS_MESG_LEN_3,"xxxx",rx_radiush,radius_attrh,(u8*)(radius_attrh + 1),endp);
			err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
			goto error;
		}

		if( ((u8*)radius_attrh) + radius_attrh->len > endp ){
			err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
			RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_AUTH_VERIFY_INVALID_RADIUS_MESG_LEN_4,"xxxxd",rx_radiush,radius_attrh,((u8*)radius_attrh) + radius_attrh->len,endp,radius_attrh->len);
			goto error;
		}

		if( radius_attrh->len < sizeof(rhp_proto_radius_attr) ){
			err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
			RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_AUTH_VERIFY_INVALID_RADIUS_MESG_LEN_5,"xxdd",rx_radiush,radius_attrh,radius_attrh->len,sizeof(rhp_proto_radius_attr) );
			goto error;
		}


		if( radius_attrh->type == RHP_RADIUS_ATTR_TYPE_MESG_AUTH ){

			int offset;

			if( radius_attrh->len != 18 ){
				err = RHP_STATUS_RADIUS_INVALID_MESG_AUTHENTICATOR_LEN;
				RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_AUTH_VERIFY_INVALID_RADIUS_AUTH_ATTR_LEN,"xxd",rx_radiush,radius_attrh,radius_attrh->len);
				goto error;
			}

			offset = ((u8*)radius_attrh) - (u8*)rx_radiush + sizeof(rhp_proto_radius_attr);

			auth_buf_len = radius_len;
			auth_buf = (u8*)_rhp_malloc(auth_buf_len);
			if( auth_buf == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			memcpy(auth_buf,(u8*)rx_radiush,radius_len);
			memcpy(((rhp_proto_radius*)auth_buf)->authenticator,tx_authenticator,RHP_RADIUS_AUTHENTICATOR_LEN);
			memset((auth_buf + offset),0,(radius_attrh->len - sizeof(rhp_proto_radius_attr)));

			err = rhp_crypto_hmac(RHP_CRYPTO_HMAC_MD5,auth_buf,auth_buf_len,
							(u8*)_rhp_radius_syspxy_keys[secret_index],_rhp_radius_syspxy_keys_len[secret_index],
							&md_buf,&md_buf_len);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			if( md_buf_len != 16 ||
					!memcmp((u8*)(radius_attrh + 1),md_buf,md_buf_len) ){

				*verify_ok_r = 1;

				RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_AUTH_VERIFY_RADIUS_AUTH_ATTR_OK,"xxdbbppppp",rx_radiush,radius_attrh,offset,rx_radiush->code,radius_attrh->type,radius_len,(u8*)rx_radiush,auth_buf_len,auth_buf,16,(u8*)(radius_attrh + 1),md_buf_len,md_buf,radius_attrh->len,(u8*)radius_attrh);

			}else{

				RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_AUTH_VERIFY_INVALID_RADIUS_AUTH_ATTR_NOT_MATCHED,"xxdbbppppp",rx_radiush,radius_attrh,offset,rx_radiush->code,radius_attrh->type,radius_len,(u8*)rx_radiush,auth_buf_len,auth_buf,16,(u8*)(radius_attrh + 1),md_buf_len,md_buf,radius_attrh->len,(u8*)radius_attrh);
			}

			_rhp_free(auth_buf);
			auth_buf = NULL;
			_rhp_free(md_buf);
			md_buf = NULL;

			RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_AUTH_VERIFY_RADIUS_AUTH_ATTR_END,"xxbb",rx_radiush,radius_attrh,rx_radiush->code,radius_attrh->type);
			break;
		}

		radius_attrh = (rhp_proto_radius_attr*)(((u8*)radius_attrh) + radius_attrh->len);
	}

	return 0;

error:
	return err;
}

static int _rhp_radius_syspxy_auth_verify(int secret_index,rhp_proto_radius* rx_radiush,u8* endp,
		u8* tx_authenticator,int* error_notify_r,unsigned long vpn_realm_id)
{
	int err = -EINVAL;
	int radius_len = 0;

	if( secret_index > RHP_RADIUS_SECRET_IDX_MAX ){
		RHP_BUG("%d",secret_index);
		return -EINVAL;
	}

	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_AUTH_VERIFY,"dxxbppu",secret_index,rx_radiush,endp,rx_radiush->code,RHP_RADIUS_AUTHENTICATOR_LEN,tx_authenticator,_rhp_radius_syspxy_keys_len[secret_index],_rhp_radius_syspxy_keys[secret_index],vpn_realm_id);

	if( _rhp_radius_syspxy_keys[secret_index] == NULL ){
  	RHP_LOG_E(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_RADIUS_NO_SHARED_SECRET_CONFIGURED,"L","RADIUS_SECRET_IDX",secret_index);
		err = RHP_STATUS_RADIUS_NO_SECRET_FOUND;
		goto error;
	}

	if( (u8*)(rx_radiush + 1) > endp ){
		err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_AUTH_VERIFY_INVALID_RADIUS_MESG_LEN_1,"xxx",rx_radiush,(u8*)(rx_radiush + 1),endp);
		goto error;
	}

	radius_len = ntohs(rx_radiush->len);
	if( radius_len < (int)sizeof(rhp_proto_radius) ||
			radius_len < rhp_gcfg_radius_min_pkt_len ||
			radius_len > rhp_gcfg_radius_max_pkt_len ||
			((u8*)rx_radiush) + radius_len > endp ){
		err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_AUTH_VERIFY_INVALID_RADIUS_MESG_LEN_2,"xxxd",rx_radiush,((u8*)rx_radiush) + radius_len,endp,radius_len);
		goto error;
	}


	err = _rhp_radius_syspxy_verify_authenticator(secret_index,rx_radiush,tx_authenticator);
	if( err ){
	  RHP_LOG_DE(RHP_LOG_SRC_AUTH,vpn_realm_id,RHP_LOG_ID_RADIUS_SYSPXY_AUTH_VERIFY_AUTHENTICATOR_ERR,"LbppE","RADIUS_CODE",rx_radiush->code,rx_radiush->id,RHP_RADIUS_AUTHENTICATOR_LEN,rx_radiush->authenticator,RHP_RADIUS_AUTHENTICATOR_LEN,tx_authenticator,err);
		goto error;
	}

	if( rx_radiush->code != RHP_RADIUS_CODE_ACCT_RESPONSE ){

		int verify_ok = 0;

		err = _rhp_radius_syspxy_verify_mesg_authenticator(secret_index,rx_radiush,tx_authenticator,endp,&verify_ok);
		if( err ){
			RHP_LOG_DE(RHP_LOG_SRC_AUTH,vpn_realm_id,RHP_LOG_ID_RADIUS_SYSPXY_AUTH_VERIFY_MESG_AUTHENTICATOR_ERR,"LbppE","RADIUS_CODE",rx_radiush->code,rx_radiush->id,RHP_RADIUS_AUTHENTICATOR_LEN,rx_radiush->authenticator,RHP_RADIUS_AUTHENTICATOR_LEN,tx_authenticator,err);
			goto error;
		}

		if( rx_radiush->code != RHP_RADIUS_CODE_ACCESS_REJECT && !verify_ok ){
			err = RHP_STATUS_RADIUS_INVALID_MESG_AUTHENTICATOR;
			goto error;
		}
	}

	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_AUTH_VERIFY_RTRN,"xd",rx_radiush,*error_notify_r);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_AUTH_VERIFY_ERR,"xdE",rx_radiush,*error_notify_r,err);
	return err;
}

static int _rhp_radius_syspxy_parse_access_accept_attrs(
		int secret_index,
		rhp_proto_radius* rx_radiush,u8* endp,
		u8* tx_authenticator,
		u8 priv_attr_type_realm_id,
		int tunnel_private_group_id_enabled,
		u8 priv_attr_type_realm_role,
		u8 priv_attr_type_common,
		rhp_proto_radius_attr_vendor_ms** mppe_send_key_attr_r,
		rhp_proto_radius_attr_vendor_ms** mppe_recv_key_attr_r,
		unsigned long* rx_vpn_realm_id_r,
		rhp_string_list** rx_radius_roles_r,
		unsigned long vpn_realm_id)
{
	int err = -EINVAL;
	int mppe_send_key_attr_len = 0, mppe_recv_key_attr_len = 0;
	rhp_proto_radius_attr* radius_attrh;

	if( secret_index > 1 ){
		RHP_BUG("%d",secret_index);
		return -EINVAL;
	}

	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_PARSE_ACCESS_ACCEPT_ATTRS,"xxbbbbdpxxpu",rx_radiush,endp,rx_radiush->code,priv_attr_type_realm_id,priv_attr_type_realm_role,priv_attr_type_common,tunnel_private_group_id_enabled,RHP_RADIUS_AUTHENTICATOR_LEN,tx_authenticator,mppe_send_key_attr_r,mppe_recv_key_attr_r,_rhp_radius_syspxy_keys_len[secret_index],_rhp_radius_syspxy_keys[secret_index],vpn_realm_id);

	if( (u8*)(rx_radiush + 1) > endp ){
		err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_PARSE_ACCESS_ACCEPT_ATTRS_INVALID_RADIUS_MESG_LEN_1,"xxx",rx_radiush,(u8*)(rx_radiush + 1),endp);
		goto error;
	}

	radius_attrh = (rhp_proto_radius_attr*)(rx_radiush + 1);
	while( (u8*)radius_attrh < endp ){

		if( (u8*)(radius_attrh + 1) > endp ){
			RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_PARSE_ACCESS_ACCEPT_ATTRS_INVALID_RADIUS_MESG_LEN_3,"xxxx",rx_radiush,radius_attrh,(u8*)(radius_attrh + 1),endp);
			err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
			goto error;
		}

		if( ((u8*)radius_attrh) + radius_attrh->len > endp ){
			err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
			RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_PARSE_ACCESS_ACCEPT_ATTRS_INVALID_RADIUS_MESG_LEN_4,"xxxxd",rx_radiush,radius_attrh,((u8*)radius_attrh) + radius_attrh->len,endp,radius_attrh->len);
			goto error;
		}

		if( radius_attrh->len < sizeof(rhp_proto_radius_attr) ){
			err = RHP_STATUS_RADIUS_INVALID_MESG_LEN;
			RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_PARSE_ACCESS_ACCEPT_ATTRS_INVALID_RADIUS_MESG_LEN_5,"xxdd",rx_radiush,radius_attrh,radius_attrh->len,sizeof(rhp_proto_radius_attr) );
			goto error;
		}

		if( radius_attrh->type == RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC ){

			err = _rhp_radius_syspxy_parse_mppe_key_attrs(rx_radiush,radius_attrh,
							mppe_send_key_attr_r,&mppe_send_key_attr_len,mppe_recv_key_attr_r,&mppe_recv_key_attr_len,vpn_realm_id);
			if( err ){
			  RHP_LOG_DE(RHP_LOG_SRC_AUTH,vpn_realm_id,RHP_LOG_ID_RADIUS_SYSPXY_AUTH_PARSE_MS_MPPE_KEY_ATTR_ERR,"LbppE","RADIUS_CODE",rx_radiush->code,rx_radiush->id,RHP_RADIUS_AUTHENTICATOR_LEN,rx_radiush->authenticator,RHP_RADIUS_AUTHENTICATOR_LEN,tx_authenticator,err);
				goto error;
			}

		}else if( priv_attr_type_realm_id && radius_attrh->type == priv_attr_type_realm_id ){

			err = _rhp_radius_syspxy_parse_realm_id_attr(rx_radiush,radius_attrh,rx_vpn_realm_id_r,vpn_realm_id,0);
			if( err ){
			  RHP_LOG_DE(RHP_LOG_SRC_AUTH,vpn_realm_id,RHP_LOG_ID_RADIUS_SYSPXY_AUTH_PARSE_PRIVATE_REALM_ID_ATTR_ERR,"LbppE","RADIUS_CODE",rx_radiush->code,rx_radiush->id,RHP_RADIUS_AUTHENTICATOR_LEN,rx_radiush->authenticator,RHP_RADIUS_AUTHENTICATOR_LEN,tx_authenticator,err);
				goto error;
			}

		}else if( (tunnel_private_group_id_enabled && radius_attrh->type == RHP_RADIUS_ATTR_TYPE_TUNNEL_PRIVATE_GROUP_ID) ||
							(priv_attr_type_realm_role && radius_attrh->type == priv_attr_type_realm_role) ){

			err = _rhp_radius_syspxy_parse_role_string_attrs(rx_radiush,radius_attrh,rx_radius_roles_r,vpn_realm_id,0);
			if( err ){
			  RHP_LOG_DE(RHP_LOG_SRC_AUTH,vpn_realm_id,RHP_LOG_ID_RADIUS_SYSPXY_AUTH_PARSE_PRIVATE_REALM_ROLE_ATTR_ERR,"LbppE","RADIUS_CODE",rx_radiush->code,rx_radiush->id,RHP_RADIUS_AUTHENTICATOR_LEN,rx_radiush->authenticator,RHP_RADIUS_AUTHENTICATOR_LEN,tx_authenticator,err);
				goto error;
			}

		}else if( priv_attr_type_common && radius_attrh->type == priv_attr_type_common ){

			err = _rhp_radius_syspxy_parse_priv_attr_common(rx_radiush,radius_attrh,rx_vpn_realm_id_r,rx_radius_roles_r,vpn_realm_id);
			if( err ){
			  RHP_LOG_DE(RHP_LOG_SRC_AUTH,vpn_realm_id,RHP_LOG_ID_RADIUS_SYSPXY_AUTH_PARSE_PRIVATE_ATTR_COMMON_ERR,"LbppE","RADIUS_CODE",rx_radiush->code,rx_radiush->id,RHP_RADIUS_AUTHENTICATOR_LEN,rx_radiush->authenticator,RHP_RADIUS_AUTHENTICATOR_LEN,tx_authenticator,err);
				goto error;
			}
		}

		radius_attrh = (rhp_proto_radius_attr*)(((u8*)radius_attrh) + radius_attrh->len);
	}

	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_PARSE_ACCESS_ACCEPT_ATTRS_RTRN,"xpp",rx_radiush,mppe_send_key_attr_len,*mppe_send_key_attr_r,mppe_recv_key_attr_len,*mppe_recv_key_attr_r);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_PARSE_ACCESS_ACCEPT_ATTRS_ERR,"xE",rx_radiush,err);
	return err;
}


/*

 - RFC 2548: Microsoft Vendor-specific RADIUS Attributes

2.4.2.  MS-MPPE-Send-Key

   Description

      The MS-MPPE-Send-Key Attribute contains a session key for use by
      the Microsoft Point-to-Point Encryption Protocol (MPPE).  As the
      name implies, this key is intended for encrypting packets sent
      from the NAS to the remote host.  This Attribute is only included
      in Access-Accept packets.

   A summary of the MS-MPPE-Send-Key Attribute format is given below.
   The fields are transmitted left to right.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Vendor-Type  | Vendor-Length |             Salt
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                               String...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Vendor-Type
      16 for MS-MPPE-Send-Key.

   Vendor-Length
      > 4

   Salt
      The Salt field is two octets in length and is used to ensure the
      uniqueness of the keys used to encrypt each of the encrypted
      attributes occurring in a given Access-Accept packet.  The most
      significant bit (leftmost) of the Salt field MUST be set (1).  The
      contents of each Salt field in a given Access-Accept packet MUST
      be unique.

   String
      The plaintext String field consists of three logical sub-fields:
      the Key-Length and Key sub-fields (both of which are required),
      and the optional Padding sub-field.  The Key-Length sub-field is
      one octet in length and contains the length of the unencrypted Key
      sub-field.  The Key sub-field contains the actual encryption key.
      If the combined length (in octets) of the unencrypted Key-Length
      and Key sub-fields is not an even multiple of 16, then the Padding
      sub-field MUST be present.  If it is present, the length of the
      Padding sub-field is variable, between 1 and 15 octets.  The
      String field MUST be encrypted as follows, prior to transmission:

         Construct a plaintext version of the String field by concate-
         nating the Key-Length and Key sub-fields.  If necessary, pad
         the resulting string until its length (in octets) is an even
         multiple of 16.  It is recommended that zero octets (0x00) be
         used for padding.  Call this plaintext P.

         Call the shared secret S, the pseudo-random 128-bit Request
         Authenticator (from the corresponding Access-Request packet) R,
         and the contents of the Salt field A.  Break P into 16 octet
         chunks p(1), p(2)...p(i), where i = len(P)/16.  Call the
         ciphertext blocks c(1), c(2)...c(i) and the final ciphertext C.
         Intermediate values b(1), b(2)...c(i) are required.  Encryption
         is performed in the following manner ('+' indicates
         concatenation):

      b(1) = MD5(S + R + A)    c(1) = p(1) xor b(1)   C = c(1)
      b(2) = MD5(S + c(1))     c(2) = p(2) xor b(2)   C = C + c(2)
                  .                      .
                  .                      .
                  .                      .
      b(i) = MD5(S + c(i-1))   c(i) = p(i) xor b(i)   C = C + c(i)

      The   resulting   encrypted   String   field    will    contain
      c(1)+c(2)+...+c(i).

   On receipt, the process is reversed to yield the plaintext String.

   Implementation Notes
      It is possible that the length of the key returned may be larger
      than needed for the encryption scheme in use.  In this case, the
      RADIUS client is responsible for performing any necessary
      truncation.

      This attribute MAY be used to pass a key from an external (e.g.,
      EAP [15]) server to the RADIUS server.  In this case, it may be
      impossible for the external server to correctly encrypt the key,
      since the RADIUS shared secret might be unavailable.  The external
      server SHOULD, however, return the attribute as defined above; the
      Salt field SHOULD be zero-filled and padding of the String field
      SHOULD be done.  When the RADIUS server receives the attribute
      from the external server, it MUST correctly set the Salt field and
      encrypt the String field before transmitting it to the RADIUS
      client.  If the channel used to communicate the MS-MPPE-Send-Key
      attribute is not secure from eavesdropping, the attribute MUST be
      cryptographically protected.

2.4.3.  MS-MPPE-Recv-Key

   Description

      The MS-MPPE-Recv-Key Attribute contains a session key for use by
      the Microsoft Point-to-Point Encryption Protocol (MPPE).  As the
      name implies, this key is intended for encrypting packets received
      by the NAS from the remote host.  This Attribute is only included
      in Access-Accept packets.

   A summary of the MS-MPPE-Recv-Key Attribute format is given below.
   The fields are transmitted left to right.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Vendor-Type  | Vendor-Length |             Salt
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                               String...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Vendor-Type
      17 for MS-MPPE-Recv-Key.

   Vendor-Length
      > 4

   Salt
      The Salt field is two octets in length and is used to ensure the
      uniqueness of the keys used to encrypt each of the encrypted
      attributes occurring in a given Access-Accept packet.  The most
      significant bit (leftmost) of the Salt field MUST be set (1).  The
      contents of each Salt field in a given Access-Accept packet MUST
      be unique.

   String
      The plaintext String field consists of three logical sub-fields:
      the Key-Length and Key sub-fields (both of which are required),
      and the optional Padding sub-field.  The Key-Length sub-field is
      one octet in length and contains the length of the unencrypted Key
      sub-field.  The Key sub-field contains the actual encryption key.
      If the combined length (in octets) of the unencrypted Key-Length
      and Key sub-fields is not an even multiple of 16, then the Padding
      sub-field MUST be present.  If it is present, the length of the
      Padding sub-field is variable, between 1 and 15 octets.  The
      String field MUST be encrypted as follows, prior to transmission:

         Construct a plaintext version of the String field by
         concatenating the Key-Length and Key sub-fields.  If necessary,
         pad the resulting string until its length (in octets) is an
         even multiple of 16.  It is recommended that zero octets (0x00)
         be used for padding.  Call this plaintext P.

         Call the shared secret S, the pseudo-random 128-bit Request
         Authenticator (from the corresponding Access-Request packet) R,
         and the contents of the Salt field A.  Break P into 16 octet
         chunks p(1), p(2)...p(i), where i = len(P)/16.  Call the
         ciphertext blocks c(1), c(2)...c(i) and the final ciphertext C.
         Intermediate values b(1), b(2)...c(i) are required.  Encryption
         is performed in the following manner ('+' indicates
         concatenation):

         b(1) = MD5(S + R + A)    c(1) = p(1) xor b(1)   C = c(1)
         b(2) = MD5(S + c(1))     c(2) = p(2) xor b(2)   C = C + c(2)
                     .                      .
                     .                      .
                     .                      .
         b(i) = MD5(S + c(i-1))   c(i) = p(i) xor b(i)   C = C + c(i)

         The resulting encrypted String field will contain
         c(1)+c(2)+...+c(i).

      On receipt, the process is reversed to yield the plaintext String.

   Implementation Notes
      It is possible that the length of the key returned may be larger
      than needed for the encryption scheme in use.  In this case, the
      RADIUS client is responsible for performing any necessary
      truncation.

      This attribute MAY be used to pass a key from an external (e.g.,
      EAP [15]) server to the RADIUS server.  In this case, it may be
      impossible for the external server to correctly encrypt the key,
      since the RADIUS shared secret might be unavailable.  The external
      server SHOULD, however, return the attribute as defined above; the
      Salt field SHOULD be zero-filled and padding of the String field
      SHOULD be done.  When the RADIUS server receives the attribute
      from the external server, it MUST correctly set the Salt field and
      encrypt the String field before transmitting it to the RADIUS
      client.  If the channel used to communicate the MS-MPPE-Recv-Key
      attribute is not secure from eavesdropping, the attribute MUST be
      cryptographically protected.
*/

/*

 - EAP-MSCHAPv2 / PEAP

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

/*

 - EAP-TTLSv0 (RFC5281)

8.  Generating Keying Material

   Upon successful conclusion of an EAP-TTLS negotiation, 128 octets of
   keying material are generated and exported for use in securing the
   data connection between client and access point.  The first 64 octets
   of the keying material constitute the MSK, the second 64 octets
   constitute the EMSK.

   The keying material is generated using the TLS PRF function
   [RFC4346], with inputs consisting of the TLS master secret, the
   ASCII-encoded constant string "ttls keying material", the TLS client
   random, and the TLS server random.  The constant string is not null-
   terminated.

      Keying Material = PRF-128(SecurityParameters.master_secret, "ttls
                keying material", SecurityParameters.client_random +
                SecurityParameters.server_random)

      MSK = Keying Material [0..63]

      EMSK = Keying Material [64..127]

   Note that the order of client_random and server_random for EAP-TTLS
   is reversed from that of the TLS protocol [RFC4346].  This ordering
   follows the key derivation method of EAP-TLS [RFC5216].  Altering the
   order of randoms avoids namespace collisions between constant strings
   defined for EAP-TTLS and those defined for the TLS protocol.

   The TTLS server distributes this keying material to the access point
   via the AAA carrier protocol.  When RADIUS is the AAA carrier
   protocol, the MPPE-Recv-Key and MPPE-Send-Key attributes [RFC2548]
   may be used to distribute the first 32 octets and second 32 octets of
   the MSK, respectively.

*/

/*

- EAP-TLS (RFC5216)

2.3.  Key Hierarchy

   Figure 1 illustrates the TLS Key Hierarchy, described in [RFC4346]
   Section 6.3.  The derivation proceeds as follows:

   master_secret = TLS-PRF-48(pre_master_secret, "master secret",
                    client.random || server.random) key_block     =
   TLS-PRF-X(master_secret, "key expansion",
                    server.random || client.random)

   Where:

   TLS-PRF-X =     TLS pseudo-random function defined in [RFC4346],
                   computed to X octets.

   In EAP-TLS, the MSK, EMSK, and Initialization Vector (IV) are derived
   from the TLS master secret via a one-way function.  This ensures that
   the TLS master secret cannot be derived from the MSK, EMSK, or IV
   unless the one-way function (TLS PRF) is broken.  Since the MSK and
   EMSK are derived from the TLS master secret, if the TLS master secret
   is compromised then the MSK and EMSK are also compromised.

   The MSK is divided into two halves, corresponding to the "Peer to
   Authenticator Encryption Key" (Enc-RECV-Key, 32 octets) and
   "Authenticator to Peer Encryption Key" (Enc-SEND-Key, 32 octets).

   The IV is a 64-octet quantity that is a known value; octets 0-31 are
   known as the "Peer to Authenticator IV" or RECV-IV, and octets 32-63
   are known as the "Authenticator to Peer IV", or SEND-IV.

            |                       | pre_master_secret       |
      server|                       |                         | client
      Random|                       V                         | Random
            |     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+     |
            |     |                                     |     |
            +---->|             master_secret           |<----+
            |     |               (TMS)                 |     |
            |     |                                     |     |
            |     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+     |
            |                       |                         |
            V                       V                         V
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                         |
      |                         key_block                       |
      |                   label == "key expansion"              |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |         |         |         |         |         |
        | client  | server  | client  | server  | client  | server
        | MAC     | MAC     | write   | write   | IV      | IV
        |         |         |         |         |         |
        V         V         V         V         V         V

                  Figure 1 - TLS [RFC4346] Key Hierarchy

   EAP-TLS derives exported keying material and parameters as follows:

   Key_Material = TLS-PRF-128(master_secret, "client EAP encryption",
                     client.random || server.random)
   MSK          = Key_Material(0,63)
   EMSK         = Key_Material(64,127)
   IV           = TLS-PRF-64("", "client EAP encryption",
                     client.random || server.random)

   Enc-RECV-Key = MSK(0,31) = Peer to Authenticator Encryption Key
                  (MS-MPPE-Recv-Key in [RFC2548]).  Also known as the
                  PMK in [IEEE-802.11].
   Enc-SEND-Key = MSK(32,63) = Authenticator to Peer Encryption Key
                  (MS-MPPE-Send-Key in [RFC2548])
   RECV-IV      = IV(0,31) = Peer to Authenticator Initialization Vector
   SEND-IV      = IV(32,63) = Authenticator to Peer Initialization
                              Vector
   Session-Id   = 0x0D || client.random || server.random

   Where:

   Key_Material(W,Z) = Octets W through Z inclusive of the key material.
   IV(W,Z)           = Octets W through Z inclusive of the IV.
   MSK(W,Z)          = Octets W through Z inclusive of the MSK.
   EMSK(W,Z)         = Octets W through Z inclusive of the EMSK.
   TLS-PRF-X         = TLS PRF function computed to X octets.
   client.random     = Nonce generated by the TLS client.
   server.random     = Nonce generated by the TLS server.

         |                       | pre_master_secret       |
   server|                       |                         | client
   Random|                       V                         | Random
         |     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+     |
         |     |                                     |     |
         +---->|             master_secret           |<----+
         |     |                                     |     |
         |     |                                     |     |
         |     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+     |
         |                       |                         |
         V                       V                         V
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                         |
   |                        MSK, EMSK                        |
   |               label == "client EAP encryption"          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |             |             |
     | MSK(0,31)   | MSK(32,63)  | EMSK(0,63)
     |             |             |
     |             |             |
     V             V             V

                     Figure 2 - EAP-TLS Key Hierarchy

   The use of these keys is specific to the lower layer, as described in
   Section 2.1 of [KEYFRAME].

*/

/*

 - EAP-AKA (RFC4187)

7.  Key Generation

   This section specifies how keying material is generated.

   On EAP-AKA full authentication, a Master Key (MK) is derived from the
   underlying AKA values (CK and IK keys), and the identity, as follows.

   MK = SHA1(Identity|IK|CK)

   In the formula above, the "|" character denotes concatenation.
   Identity denotes the peer identity string without any terminating
   null characters.  It is the identity from the last AT_IDENTITY
   attribute sent by the peer in this exchange, or, if AT_IDENTITY was
   not used, the identity from the EAP-Response/Identity packet.  The
   identity string is included as-is, without any changes.  As discussed
   in Section 4.1.2.2, relying on EAP-Response/Identity for conveying
   the EAP-AKA peer identity is discouraged, and the server SHOULD use
   the EAP-AKA method-specific identity attributes.  The hash function
   SHA-1 is specified in [SHA-1].

   The Master Key is fed into a Pseudo-Random number Function (PRF),
   which generates separate Transient EAP Keys (TEKs) for protecting
   EAP-AKA packets, as well as a Master Session Key (MSK) for link layer
   security and an Extended Master Session Key (EMSK) for other
   purposes.  On fast re-authentication, the same TEKs MUST be used for
   protecting EAP packets, but a new MSK and a new EMSK MUST be derived
   from the original MK and from new values exchanged in the fast
   re-authentication.

   EAP-AKA requires two TEKs for its own purposes: the authentication
   key K_aut, to be used with the AT_MAC attribute, and the encryption
   key K_encr, to be used with the AT_ENCR_DATA attribute.  The same
   K_aut and K_encr keys are used in full authentication and subsequent
   fast re-authentications.

   Key derivation is based on the random number generation specified in
   NIST Federal Information Processing Standards (FIPS) Publication
   186-2 [PRF].  The pseudo-random number generator is specified in the
   change notice 1 (2001 October 5) of [PRF] (Algorithm 1).  As
   specified in the change notice (page 74), when Algorithm 1 is used as
   a general-purpose pseudo-random number generator, the "mod q" term in
   step 3.3 is omitted.  The function G used in the algorithm is
   constructed via Secure Hash Standard as specified in Appendix 3.3 of
   the standard.  It should be noted that the function G is very similar
   to SHA-1, but the message padding is different.  Please refer to
   [PRF] for full details.  For convenience, the random number algorithm
   with the correct modification is cited in Annex A.

   160-bit XKEY and XVAL values are used, so b = 160.  On each full
   authentication, the Master Key is used as the initial secret seed-key
   XKEY.  The optional user input values (XSEED_j) in step 3.1 are set
   to zero.

   On full authentication, the resulting 320-bit random numbers x_0,
   x_1, ..., x_m-1 are concatenated and partitioned into suitable-sized
   chunks and used as keys in the following order: K_encr (128 bits),
   K_aut (128 bits), Master Session Key (64 bytes), Extended Master
   Session Key (64 bytes).

   On fast re-authentication, the same pseudo-random number generator
   can be used to generate a new Master Session Key and a new Extended
   Master Session Key.  The seed value XKEY' is calculated as follows:

   XKEY' = SHA1(Identity|counter|NONCE_S| MK)

   In the formula above, the Identity denotes the fast re-authentication
   identity, without any terminating null characters, from the
   AT_IDENTITY attribute of the EAP-Response/AKA-Identity packet, or, if
   EAP-Response/AKA-Identity was not used on fast re-authentication, it
   denotes the identity string from the EAP-Response/Identity packet.
   The counter denotes the counter value from the AT_COUNTER attribute
   used in the EAP-Response/AKA-Reauthentication packet.  The counter is
   used in network byte order.  NONCE_S denotes the 16-byte random
   NONCE_S value from the AT_NONCE_S attribute used in the
   EAP-Request/AKA-Reauthentication packet.  The MK is the Master Key
   derived on the preceding full authentication.

   On fast re-authentication, the pseudo-random number generator is run
   with the new seed value XKEY', and the resulting 320-bit random
   numbers x_0, x_1, ..., x_m-1 are concatenated and partitioned into
   64-byte chunks and used as the new 64-byte Master Session Key and the
   new 64-byte Extended Master Session Key.  Note that because K_encr
   and K_aut are not derived on fast re-authentication, the Master
   Session Key and the Extended Master Session key are obtained from the
   beginning of the key stream x_0, x_1, ....

   The first 32 bytes of the MSK can be used as the Pairwise Master Key
   (PMK) for IEEE 802.11i.

   When the RADIUS attributes specified in [RFC2548] are used to
   transport keying material, then the first 32 bytes of the MSK
   correspond to MS-MPPE-RECV-KEY and the second 32 bytes to
   MS-MPPE-SEND-KEY.  In this case, only 64 bytes of keying material
   (the MSK) are used.
*/

/*

 - EAP-SIM (RFC4186)

7.  Key Generation

   This section specifies how keying material is generated.

   On EAP-SIM full authentication, a Master Key (MK) is derived from the
   underlying GSM authentication values (Kc keys), the NONCE_MT, and
   other relevant context as follows.

   MK = SHA1(Identity|n*Kc| NONCE_MT| Version List| Selected Version)

   In the formula above, the "|" character denotes concatenation.
   "Identity" denotes the peer identity string without any terminating
   null characters.  It is the identity from the last AT_IDENTITY
   attribute sent by the peer in this exchange, or, if AT_IDENTITY was
   not used, it is the identity from the EAP-Response/Identity packet.
   The identity string is included as-is, without any changes.  As
   discussed in Section 4.2.2.2, relying on EAP-Response/Identity for
   conveying the EAP-SIM peer identity is discouraged, and the server
   SHOULD use the EAP-SIM method-specific identity attributes.

   The notation n*Kc in the formula above denotes the n Kc values
   concatenated.  The Kc keys are used in the same order as the RAND
   challenges in AT_RAND attribute.  NONCE_MT denotes the NONCE_MT value
   (not the AT_NONCE_MT attribute, but only the nonce value).  The
   Version List includes the 2-byte-supported version numbers from
   AT_VERSION_LIST, in the same order as in the attribute.  The Selected
   Version is the 2-byte selected version from AT_SELECTED_VERSION.
   Network byte order is used, just as in the attributes.  The hash
   function SHA-1 is specified in [SHA-1].  If several EAP/SIM/Start
   roundtrips are used in an EAP-SIM exchange, then the NONCE_MT,
   Version List and Selected version from the last EAP/SIM/Start round
   are used, and the previous EAP/SIM/Start rounds are ignored.

   The Master Key is fed into a Pseudo-Random number Function (PRF)
   which generates separate Transient EAP Keys (TEKs) for protecting
   EAP-SIM packets, as well as a Master Session Key (MSK) for link layer
   security, and an Extended Master Session Key (EMSK) for other
   purposes.  On fast re-authentication, the same TEKs MUST be used for
   protecting EAP packets, but a new MSK and a new EMSK MUST be derived
   from the original MK and from new values exchanged in the fast
   re-authentication.

   EAP-SIM requires two TEKs for its own purposes; the authentication
   key K_aut is to be used with the AT_MAC attribute, and the encryption
   key K_encr is to be used with the AT_ENCR_DATA attribute.  The same
   K_aut and K_encr keys are used in full authentication and subsequent
   fast re-authentications.

   Key derivation is based on the random number generation specified in
   NIST Federal Information Processing Standards (FIPS) Publication
   186-2 [PRF].  The pseudo-random number generator is specified in the
   change notice 1 (2001 October 5) of [PRF] (Algorithm 1).  As
   specified in the change notice (page 74), when Algorithm 1 is used as
   a general-purpose pseudo-random number generator, the "mod q" term in
   step 3.3 is omitted.  The function G used in the algorithm is
   constructed via the Secure Hash Standard, as specified in Appendix
   3.3 of the standard.  It should be noted that the function G is very
   similar to SHA-1, but the message padding is different.  Please refer
   to [PRF] for full details.  For convenience, the random number
   algorithm with the correct modification is cited in Appendix B.

   160-bit XKEY and XVAL values are used, so b = 160.  On each full
   authentication, the Master Key is used as the initial secret seed-key
   XKEY.  The optional user input values (XSEED_j) in step 3.1 are set
   to zero.

   On full authentication, the resulting 320-bit random numbers (x_0,
   x_1, ..., x_m-1) are concatenated and partitioned into suitable-sized
   chunks and used as keys in the following order: K_encr (128 bits),
   K_aut (128 bits), Master Session Key (64 bytes), Extended Master
   Session Key (64 bytes).

   On fast re-authentication, the same pseudo-random number generator
   can be used to generate a new Master Session Key and a new Extended
   Master Session Key.  The seed value XKEY' is calculated as follows:

   XKEY' = SHA1(Identity|counter|NONCE_S| MK)

   In the formula above, the Identity denotes the fast re-authentication
   identity, without any terminating null characters, from the
   AT_IDENTITY attribute of the EAP-Response/SIM/Start packet, or, if

   EAP-Response/SIM/Start was not used on fast re-authentication, it
   denotes the identity string from the EAP-Response/Identity packet.
   The counter denotes the counter value from the AT_COUNTER attribute
   used in the EAP-Response/SIM/Re-authentication packet.  The counter
   is used in network byte order.  NONCE_S denotes the 16-byte NONCE_S
   value from the AT_NONCE_S attribute used in the
   EAP-Request/SIM/Re-authentication packet.  The MK is the Master Key
   derived on the preceding full authentication.

   On fast re-authentication, the pseudo-random number generator is run
   with the new seed value XKEY', and the resulting 320-bit random
   numbers (x_0, x_1, ..., x_m-1) are concatenated and partitioned into
   two 64-byte chunks and used as the new 64-byte Master Session Key and
   the new 64-byte Extended Master Session Key.  Note that because
   K_encr and K_aut are not derived on fast re-authentication, the
   Master Session Key and the Extended Master Session key are obtained
   from the beginning of the key stream (x_0, x_1, ...).

   The first 32 bytes of the MSK can be used as the Pairwise Master Key
   (PMK) for IEEE 802.11i.

   When the RADIUS attributes specified in [RFC2548] are used to
   transport keying material, then the first 32 bytes of the MSK
   correspond to MS-MPPE-RECV-KEY and the second 32 bytes to
   MS-MPPE-SEND-KEY.  In this case, only 64 bytes of keying material
   (the MSK) are used.

   When generating the initial Master Key, the hash function is used as
   a mixing function to combine several session keys (Kc's) generated by
   the GSM authentication procedure and the random number NONCE_MT into
   a single session key.  There are several reasons for this.  The
   current GSM session keys are, at most, 64 bits, so two or more of
   them are needed to generate a longer key.  By using a one-way
   function to combine the keys, we are assured that, even if an
   attacker managed to learn one of the EAP-SIM session keys, it
   wouldn't help him in learning the original GSM Kc's.  In addition,
   since we include the random number NONCE_MT in the calculation, the
   peer is able to verify that the EAP-SIM packets it receives from the
   network are fresh and not replays (also see Section 11).
*/

static int _rhp_radius_syspxy_get_msk(
		int secret_index,
		int eap_method,
		u8* tx_authenticator,
		rhp_proto_radius_attr_vendor_ms* mppe_send_key_attr,
		rhp_proto_radius_attr_vendor_ms* mppe_recv_key_attr,
		u8** msk_r,int* msk_len_r)
{
	int err = -EINVAL;
	u8 *mppe_send_key, *mppe_recv_key;
	size_t mppe_send_key_len, mppe_recv_key_len;
	u8 *mppe_send_key_dec = NULL, *mppe_recv_key_dec = NULL;
	size_t mppe_send_key_dec_len = 0, mppe_recv_key_dec_len = 0;
	u8 *msk = NULL;
	size_t msk_len = 0;

	if( secret_index > RHP_RADIUS_SECRET_IDX_MAX ){
		RHP_BUG("%d",secret_index);
		return -EINVAL;
	}

	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_GET_MSK,"ddpppxxp",eap_method,secret_index,RHP_RADIUS_AUTHENTICATOR_LEN,tx_authenticator,mppe_send_key_attr->vendor_len,mppe_send_key_attr,mppe_recv_key_attr->vendor_len,mppe_recv_key_attr,msk_r,msk_len_r,_rhp_radius_syspxy_keys_len[secret_index],_rhp_radius_syspxy_keys[secret_index]);

	if( _rhp_radius_syspxy_keys[secret_index] == NULL ){
		err = RHP_STATUS_RADIUS_NO_SECRET_FOUND;
  	RHP_LOG_E(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_RADIUS_NO_SHARED_SECRET_CONFIGURED,"L","RADIUS_SECRET_IDX",secret_index);
		goto error;
	}

	mppe_send_key = (u8*)(mppe_send_key_attr + 1);
	mppe_send_key_len = mppe_send_key_attr->vendor_len - sizeof(rhp_proto_radius_attr_vendor_ms);

	mppe_recv_key = (u8*)(mppe_recv_key_attr + 1);
	mppe_recv_key_len = mppe_recv_key_attr->vendor_len - sizeof(rhp_proto_radius_attr_vendor_ms);

	mppe_send_key_dec = rhp_radius_decrypt_ms_key((const u8*)mppe_send_key,mppe_send_key_len,
												(const u8*)tx_authenticator,
												(const u8*)_rhp_radius_syspxy_keys[secret_index],(size_t)_rhp_radius_syspxy_keys_len[secret_index],
												&mppe_send_key_dec_len);
	if( mppe_send_key_dec == NULL ){
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_GET_MSK_DEC_MPPE_SEND_KEY_ERR,"d",eap_method);
		err = RHP_STATUS_RADIUS_GEN_MSK_ERR;
		goto error;
	}

	mppe_recv_key_dec = rhp_radius_decrypt_ms_key((const u8*)mppe_recv_key,mppe_recv_key_len,
												(const u8*)tx_authenticator,
												(const u8*)_rhp_radius_syspxy_keys[secret_index],(size_t)_rhp_radius_syspxy_keys_len[secret_index],
												&mppe_recv_key_dec_len);
	if( mppe_recv_key_dec == NULL ){
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_GET_MSK_DEC_MPPE_RECV_KEY_ERR,"d",eap_method);
		err = RHP_STATUS_RADIUS_GEN_MSK_ERR;
		goto error;
	}

	if(mppe_send_key_dec_len != mppe_recv_key_dec_len){
		err = RHP_STATUS_RADIUS_GEN_MSK_ERR;
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_GET_MSK_BAD_KEY_LEN,"ddd",eap_method,mppe_send_key_dec_len,mppe_recv_key_dec_len);
		goto error;
	}

	if( (eap_method == RHP_PROTO_EAP_TYPE_MS_CHAPV2 ||
			 eap_method == RHP_PROTO_EAP_TYPE_PEAP ||
			 eap_method == RHP_PROTO_EAP_TYPE_PEAPV0_MS_CHAPV2 ) &&
			mppe_send_key_dec_len == RHP_RADIUS_MSCHAPV2_KEY_LEN ){

		msk_len = 64;
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_GET_MSK_FIXED_KEY_LEN,"ddd",eap_method,msk_len,mppe_send_key_dec_len);

	}else{

		msk_len = mppe_recv_key_dec_len + mppe_send_key_dec_len;
	}

	if( msk_len > RHP_RADIUS_MAX_MSK_LEN ){
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_GET_MSK_TOO_LONG_KEY_LEN,"ddd",eap_method,msk_len,RHP_RADIUS_MAX_MSK_LEN);
		goto error;
	}

	msk = (u8*)_rhp_malloc(msk_len);
	if( msk == NULL ){
		RHP_BUG("%d",msk_len);
		goto error;
	}
	memset(msk,0,msk_len); // Zero paddings are included for MS-CHAPv2.

	memcpy(msk,mppe_recv_key_dec,mppe_recv_key_dec_len);
	memcpy((msk + mppe_recv_key_dec_len),mppe_send_key_dec,mppe_send_key_dec_len);

	_rhp_free_zero(mppe_send_key_dec,mppe_send_key_dec_len);
	_rhp_free_zero(mppe_recv_key_dec,mppe_recv_key_dec_len);

	*msk_r = msk;
	*msk_len_r = (int)msk_len;

	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_GET_MSK_RTRN,"dp",eap_method,*msk_len_r,*msk_r);
	return 0;

error:
	if(mppe_send_key_dec){
		_rhp_free_zero(mppe_send_key_dec,mppe_send_key_dec_len);
	}
	if(mppe_recv_key_dec){
		_rhp_free_zero(mppe_recv_key_dec,mppe_recv_key_dec_len);
	}
	if(msk){
		_rhp_free_zero(msk,msk_len);
	}
	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_GET_MSK_ERR,"dE",eap_method,err);
	return err;
}

static int _rhp_radius_syspxy_verify_rx_realm_id(unsigned long rx_vpn_realm_id,
				unsigned long vpn_realm_id,unsigned long peer_notified_realm_id,
				unsigned long* rebound_rlm_id_r,
				rhp_proto_radius* rx_radiush)
{
	int err = -EINVAL;
	rhp_vpn_auth_realm* rb_auth_rlm = NULL;

	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_VERIFY_RX_REALM_ID,"uuuxx",rx_vpn_realm_id,vpn_realm_id,peer_notified_realm_id,rebound_rlm_id_r,rx_radiush);

	if( peer_notified_realm_id &&
			peer_notified_realm_id != RHP_VPN_REALM_ID_UNKNOWN &&
			rx_vpn_realm_id != peer_notified_realm_id ){

		err = RHP_STATUS_RADIUS_RX_REALM_ID_OR_ROLE_NOT_MATCHED;
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_VERIFY_RX_REALM_ID_PEER_NOTIFIED_REALM_ID_NOT_MATCHED,"uuu",rx_vpn_realm_id,vpn_realm_id,peer_notified_realm_id);
		goto error;
	}

	if( vpn_realm_id == rx_vpn_realm_id ){
		err = 0;
		*rebound_rlm_id_r = rx_vpn_realm_id;
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_VERIFY_RX_REALM_ID_RX_SAME_REALM_ID,"uuu",rx_vpn_realm_id,vpn_realm_id,peer_notified_realm_id);
	  RHP_LOG_D(RHP_LOG_SRC_AUTH,vpn_realm_id,RHP_LOG_ID_RADIUS_SYSPXY_VERIFY_REALM_ID_NOT_REBOUND,"Lbpuuu","RADIUS_CODE",rx_radiush->code,rx_radiush->id,RHP_RADIUS_AUTHENTICATOR_LEN,rx_radiush->authenticator,vpn_realm_id,rx_vpn_realm_id,peer_notified_realm_id);
		goto not_rebound;
	}

	rb_auth_rlm = rhp_auth_realm_get(rx_vpn_realm_id);
	if( rb_auth_rlm == NULL ){
		err = RHP_STATUS_RADIUS_RX_REALM_ID_OR_ROLE_NOT_MATCHED;
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_VERIFY_RX_REALM_ID_RX_REALM_NOT_FOUND,"uuux",rx_vpn_realm_id,vpn_realm_id,peer_notified_realm_id,rebound_rlm_id_r);
		goto error;
	}


  RHP_LOCK(&(rb_auth_rlm->lock));

	if( rb_auth_rlm->eap.role != RHP_EAP_AUTHENTICATOR ){
		err = RHP_STATUS_RADIUS_RX_REALM_ID_OR_ROLE_NOT_MATCHED;
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_VERIFY_RX_REALM_ID_RX_REALM_NOT_EAP_AUTHENTICATOR,"uuuxd",rx_vpn_realm_id,vpn_realm_id,peer_notified_realm_id,rb_auth_rlm,rb_auth_rlm->eap.role);
  	goto error;
	}

	if( rb_auth_rlm->eap.method != RHP_PROTO_EAP_TYPE_PRIV_RADIUS ){
		err = RHP_STATUS_RADIUS_RX_REALM_ID_OR_ROLE_NOT_MATCHED;
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_VERIFY_RX_REALM_ID_RX_REALM_RADIUS_DISABLED,"uuuxd",rx_vpn_realm_id,vpn_realm_id,peer_notified_realm_id,rb_auth_rlm,rb_auth_rlm->eap.method);
  	goto error;
	}

	*rebound_rlm_id_r = rb_auth_rlm->id;

  RHP_UNLOCK(&(rb_auth_rlm->lock));
	rhp_auth_realm_unhold(rb_auth_rlm);

  RHP_LOG_D(RHP_LOG_SRC_AUTH,vpn_realm_id,RHP_LOG_ID_RADIUS_SYSPXY_VERIFY_RX_REALM_ID,"Lbpuuuu","RADIUS_CODE",rx_radiush->code,rx_radiush->id,RHP_RADIUS_AUTHENTICATOR_LEN,rx_radiush->authenticator,vpn_realm_id,rx_vpn_realm_id,*rebound_rlm_id_r,peer_notified_realm_id);

	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_VERIFY_RX_REALM_ID_RTRN,"uuuxu",rx_vpn_realm_id,vpn_realm_id,peer_notified_realm_id,rb_auth_rlm,*rebound_rlm_id_r);

not_rebound:
	return 0;

error:
	if( rb_auth_rlm ){
		RHP_UNLOCK(&(rb_auth_rlm->lock));
		rhp_auth_realm_unhold(rb_auth_rlm);
	}

  RHP_LOG_DE(RHP_LOG_SRC_AUTH,vpn_realm_id,RHP_LOG_ID_RADIUS_SYSPXY_VERIFY_RX_REALM_ID_ERR,"LbpuuuE","RADIUS_CODE",rx_radiush->code,rx_radiush->id,RHP_RADIUS_AUTHENTICATOR_LEN,rx_radiush->authenticator,vpn_realm_id,rx_vpn_realm_id,peer_notified_realm_id,err);

  RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_VERIFY_RX_REALM_ID_ERR,"uuuE",rx_vpn_realm_id,vpn_realm_id,peer_notified_realm_id,err);
	return err;
}

static int _rhp_radius_syspxy_verify_rx_realm_roles(rhp_string_list* rx_radius_roles,
		unsigned long vpn_realm_id,unsigned long peer_notified_realm_id,
		unsigned long* rebound_rlm_id_r,
		rhp_proto_radius* rx_radiush)
{
	int err = -EINVAL;
	rhp_vpn_auth_realm* rb_auth_rlm = NULL;
  rhp_ikev2_id my_id; // Don't forget to clear my_id's fields by rhp_ikev2_id_clear().
  rhp_ikev2_id* my_id_p = NULL;
  char* cat_role_strings = NULL;

	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_VERIFY_RX_REALM_ROLES,"xuuxx",rx_radius_roles,vpn_realm_id,peer_notified_realm_id,rebound_rlm_id_r,rx_radiush);

	memset(&my_id,0,sizeof(rhp_ikev2_id));

	if( vpn_realm_id && vpn_realm_id != RHP_VPN_REALM_ID_UNKNOWN ){

		rhp_vpn_auth_realm* cur_auth_rlm = NULL;

		cur_auth_rlm = rhp_auth_realm_get(vpn_realm_id);
		if( cur_auth_rlm == NULL ){
			RHP_BUG("%d",vpn_realm_id);
			goto error;
		}

		RHP_LOCK(&(cur_auth_rlm->lock));

		if( rhp_ikev2_id_dup(&my_id,&(cur_auth_rlm->my_auth->my_id)) ){

			RHP_BUG("");

			RHP_UNLOCK(&(cur_auth_rlm->lock));
			rhp_auth_realm_unhold(cur_auth_rlm);

			goto error;
		}

		RHP_UNLOCK(&(cur_auth_rlm->lock));
		rhp_auth_realm_unhold(cur_auth_rlm);

		my_id_p = &my_id;
	}

	cat_role_strings = _rhp_string_list_cat(rx_radius_roles); // For log.

	rb_auth_rlm = rhp_auth_realm_get_by_role(my_id_p,
									RHP_PEER_ID_TYPE_RADIUS_RX_ROLE,(void*)rx_radius_roles,
									NULL,1,peer_notified_realm_id);

	if( rb_auth_rlm == NULL ){
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_VERIFY_RX_REALM_ROLES_NO_REALM_FOUND,"xuu",rx_radius_roles,vpn_realm_id,peer_notified_realm_id);
		err = RHP_STATUS_RADIUS_RX_REALM_ID_OR_ROLE_NOT_MATCHED;
		goto error;
	}


  RHP_LOCK(&(rb_auth_rlm->lock));

	if( rb_auth_rlm->eap.role != RHP_EAP_AUTHENTICATOR ){
		err = RHP_STATUS_RADIUS_RX_REALM_ID_OR_ROLE_NOT_MATCHED;
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_VERIFY_RX_REALM_ROLES_NOT_EAP_AUTHENTICATOR,"xuuxd",rx_radius_roles,vpn_realm_id,peer_notified_realm_id,rb_auth_rlm,rb_auth_rlm->eap.role);
  	goto error;
	}

	if( rb_auth_rlm->eap.method != RHP_PROTO_EAP_TYPE_PRIV_RADIUS ){
		err = RHP_STATUS_RADIUS_RX_REALM_ID_OR_ROLE_NOT_MATCHED;
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_VERIFY_RX_REALM_ROLES_RADIUS_DISABLED,"xuuxd",rx_radius_roles,vpn_realm_id,peer_notified_realm_id,rb_auth_rlm,rb_auth_rlm->eap.method);
  	goto error;
	}

	*rebound_rlm_id_r = rb_auth_rlm->id;

  RHP_UNLOCK(&(rb_auth_rlm->lock));
	rhp_auth_realm_unhold(rb_auth_rlm);

  RHP_LOG_D(RHP_LOG_SRC_AUTH,vpn_realm_id,RHP_LOG_ID_RADIUS_SYSPXY_VERIFY_RX_VPN_REALM_ROLES,"LbpuuuIs","RADIUS_CODE",rx_radiush->code,rx_radiush->id,RHP_RADIUS_AUTHENTICATOR_LEN,rx_radiush->authenticator,vpn_realm_id,*rebound_rlm_id_r,peer_notified_realm_id,&my_id,cat_role_strings);

  rhp_ikev2_id_clear(&my_id);

	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_VERIFY_RX_REALM_ROLES_RTRN,"xuuxus",rx_radius_roles,vpn_realm_id,peer_notified_realm_id,rb_auth_rlm,*rebound_rlm_id_r,cat_role_strings);
  if( cat_role_strings ){
  	_rhp_free(cat_role_strings);
  }

	return 0;

error:
	if( rb_auth_rlm ){
		RHP_UNLOCK(&(rb_auth_rlm->lock));
		rhp_auth_realm_unhold(rb_auth_rlm);
	}

  RHP_LOG_DE(RHP_LOG_SRC_AUTH,vpn_realm_id,RHP_LOG_ID_RADIUS_SYSPXY_VERIFY_RX_VPN_REALM_ROLES_ERR,"LbpuuIsE","RADIUS_CODE",rx_radiush->code,rx_radiush->id,RHP_RADIUS_AUTHENTICATOR_LEN,rx_radiush->authenticator,vpn_realm_id,peer_notified_realm_id,&my_id,cat_role_strings,err);

  rhp_ikev2_id_clear(&my_id);

	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_VERIFY_RX_REALM_ROLES_ERR,"xuusE",rx_radius_roles,vpn_realm_id,peer_notified_realm_id,cat_role_strings,err);
  if( cat_role_strings ){
  	_rhp_free(cat_role_strings);
  }
	return err;
}

static int _rhp_radius_syspxy_verify_rx_realm_roles_for_not_protected_eap_id(
		rhp_ipcmsg_radius_mesg_auth_req* auth_req,u8* user_name,
		unsigned long vpn_realm_id,unsigned long peer_notified_realm_id,unsigned long* rebound_rlm_id_r,
		rhp_proto_radius* rx_radiush)
{
	int err = -EINVAL;
	rhp_eap_id eap_peer_id;
  rhp_ikev2_id my_id; // Don't forget to clear my_id's fields by rhp_ikev2_id_clear().
  rhp_ikev2_id* my_id_p = NULL;
	rhp_vpn_auth_realm* rb_auth_rlm = NULL;

	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_VERIFY_RX_REALM_ROLES_FOR_NOT_PROTECTED_EAP_ID,"xsuuxxLd",auth_req,user_name,vpn_realm_id,peer_notified_realm_id,rebound_rlm_id_r,rx_radiush,"EAP_TYPE",auth_req->eap_method);

	memset(&eap_peer_id,0,sizeof(rhp_eap_id));
	memset(&my_id,0,sizeof(rhp_ikev2_id));

	if( vpn_realm_id && vpn_realm_id != RHP_VPN_REALM_ID_UNKNOWN ){

		rhp_vpn_auth_realm* cur_auth_rlm = NULL;

		cur_auth_rlm = rhp_auth_realm_get(vpn_realm_id);
		if( cur_auth_rlm == NULL ){
			RHP_BUG("%d",vpn_realm_id);
			goto error;
		}

		RHP_LOCK(&(cur_auth_rlm->lock));

		if( rhp_ikev2_id_dup(&my_id,&(cur_auth_rlm->my_auth->my_id)) ){

			RHP_BUG("");

			RHP_UNLOCK(&(cur_auth_rlm->lock));
			rhp_auth_realm_unhold(cur_auth_rlm);

			goto error;
		}

		RHP_UNLOCK(&(cur_auth_rlm->lock));
		rhp_auth_realm_unhold(cur_auth_rlm);

		my_id_p = &my_id;
	}


	err = rhp_eap_id_setup(auth_req->eap_method,auth_req->user_name_len,user_name,0,&eap_peer_id);
	if( err ){
		RHP_BUG("");
		goto error;
	}

	rb_auth_rlm = rhp_auth_realm_get_by_role(my_id_p,RHP_PEER_ID_TYPE_EAP,
			(void*)&eap_peer_id,NULL,0,peer_notified_realm_id);

	if( rb_auth_rlm == NULL ){

		rb_auth_rlm = rhp_auth_realm_get_def_eap_server(my_id_p,peer_notified_realm_id);
	}

	if( rb_auth_rlm == NULL ){
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_VERIFY_RX_REALM_ROLES_FOR_NOT_PROTECTED_EAP_ID_NO_REALM_FOUND,"xuu",auth_req,vpn_realm_id,peer_notified_realm_id);
		err = RHP_STATUS_RADIUS_RX_REALM_ID_OR_ROLE_NOT_MATCHED;
		goto error;
	}


  RHP_LOCK(&(rb_auth_rlm->lock));

	if( rb_auth_rlm->eap.role != RHP_EAP_AUTHENTICATOR ){
		err = RHP_STATUS_RADIUS_RX_REALM_ID_OR_ROLE_NOT_MATCHED;
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_VERIFY_RX_REALM_ROLES_FOR_NOT_PROTECTED_EAP_ID_NOT_EAP_AUTHENTICATOR,"xuuxd",auth_req,vpn_realm_id,peer_notified_realm_id,rb_auth_rlm,rb_auth_rlm->eap.role);
  	goto error;
	}

	if( rb_auth_rlm->eap.method != RHP_PROTO_EAP_TYPE_PRIV_RADIUS ){
		err = RHP_STATUS_RADIUS_RX_REALM_ID_OR_ROLE_NOT_MATCHED;
		RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_VERIFY_RX_REALM_ROLES_FOR_NOT_PROTECTED_EAP_ID_RADIUS_DISABLED,"xuuxd",auth_req,vpn_realm_id,peer_notified_realm_id,rb_auth_rlm,rb_auth_rlm->eap.method);
  	goto error;
	}

	*rebound_rlm_id_r = rb_auth_rlm->id;

  RHP_UNLOCK(&(rb_auth_rlm->lock));
	rhp_auth_realm_unhold(rb_auth_rlm);

  RHP_LOG_D(RHP_LOG_SRC_AUTH,vpn_realm_id,RHP_LOG_ID_RADIUS_SYSPXY_VERIFY_RX_VPN_REALM_ROLES_FOR_NOT_PROTECTED_EAP_ID,"LbpuuuILs","RADIUS_CODE",rx_radiush->code,rx_radiush->id,RHP_RADIUS_AUTHENTICATOR_LEN,rx_radiush->authenticator,vpn_realm_id,*rebound_rlm_id_r,peer_notified_realm_id,&my_id,"EAP_TYPE",eap_peer_id.method,eap_peer_id.identity);

  rhp_ikev2_id_clear(&my_id);
	rhp_eap_id_clear(&eap_peer_id);

	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_VERIFY_RX_REALM_ROLES_FOR_NOT_PROTECTED_EAP_ID_RTRN,"xsuuxu",auth_req,user_name,vpn_realm_id,peer_notified_realm_id,rb_auth_rlm,*rebound_rlm_id_r);
	return 0;

error:
	if( rb_auth_rlm ){
		RHP_UNLOCK(&(rb_auth_rlm->lock));
		rhp_auth_realm_unhold(rb_auth_rlm);
	}

  RHP_LOG_DE(RHP_LOG_SRC_AUTH,vpn_realm_id,RHP_LOG_ID_RADIUS_SYSPXY_VERIFY_RX_VPN_REALM_ROLES_FOR_NOT_PROTECTED_EAP_ID_ERR,"LbpuuuILsE","RADIUS_CODE",rx_radiush->code,rx_radiush->id,RHP_RADIUS_AUTHENTICATOR_LEN,rx_radiush->authenticator,vpn_realm_id,*rebound_rlm_id_r,peer_notified_realm_id,&my_id,"EAP_TYPE",eap_peer_id.method,eap_peer_id.identity,err);

	rhp_ikev2_id_clear(&my_id);
	rhp_eap_id_clear(&eap_peer_id);

	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_VERIFY_RX_REALM_ROLES_FOR_NOT_PROTECTED_EAP_ID_ERR,"xsuuxE",auth_req,user_name,vpn_realm_id,peer_notified_realm_id,rb_auth_rlm,err);
	return err;
}

static void _rhp_radius_syspxy_ipc_mesg_auth_handler(rhp_ipcmsg** ipcmsg)
{
	int err = -EINVAL;
	rhp_ipcmsg_radius_mesg_auth_req* auth_req = (rhp_ipcmsg_radius_mesg_auth_req*)*ipcmsg;
	u8 *tx_authenticator = NULL;
	rhp_proto_radius* rx_radiush = NULL;
	int radius_len;
	rhp_proto_radius_attr_vendor_ms *mppe_send_key_attr = NULL, *mppe_recv_key_attr = NULL;
	u8* msk = NULL;
	int msk_len = 0;
	unsigned long rx_vpn_realm_id = 0;
	rhp_string_list* rx_radius_roles = NULL;
	unsigned long rebound_rlm_id = 0;
	rhp_ipcmsg_radius_mesg_auth_rep* ipc_rep = NULL;
	int error_notify = 0;
	u8 priv_attr_type_realm_id, priv_attr_type_realm_role, priv_attr_type_common;
	int tunnel_private_group_id_attr_enabled;
	u8* user_name = NULL;


	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_IPC_MESG_AUTH_HANDLER,"xx",ipcmsg,auth_req);

	if( auth_req->len <= sizeof(rhp_ipcmsg_radius_mesg_auth_req) ){
		RHP_BUG("%d",auth_req->len);
		err = -EINVAL;
		goto error;
	}

	if( auth_req->type != RHP_IPC_RADIUS_MESG_AUTH_REQUEST ){
		RHP_BUG("%d",auth_req->type);
		err = -EINVAL;
		goto error;
	}

	if( auth_req->mesg_len < sizeof(rhp_proto_radius) ){
		RHP_BUG("%d",auth_req->mesg_len);
		err = -EINVAL;
		goto error;
	}

	if( auth_req->len < sizeof(rhp_ipcmsg_radius_mesg_auth_req)
				+ auth_req->authenticator_len + auth_req->mesg_len + auth_req->user_name_len ){
		RHP_BUG("%d, %d, %d, %d, %d",auth_req->len,sizeof(rhp_ipcmsg_radius_mesg_auth_req),auth_req->authenticator_len,auth_req->mesg_len,auth_req->user_name_len );
		err = -EINVAL;
		goto error;
	}

	if( auth_req->authenticator_len != RHP_RADIUS_AUTHENTICATOR_LEN ){
		RHP_BUG("%d",auth_req->authenticator_len);
		err = -EINVAL;
		goto error;
	}

	if( auth_req->secret_index > RHP_RADIUS_SECRET_IDX_MAX ){
		RHP_BUG("%d",auth_req->secret_index);
		err = -EINVAL;
		goto error;
	}

	tx_authenticator = (u8*)(auth_req + 1);
	rx_radiush = (rhp_proto_radius*)(tx_authenticator + auth_req->authenticator_len);
	if( auth_req->user_name_len ){
		user_name = ((u8*)rx_radiush) + auth_req->mesg_len;
	}
	radius_len = ntohs(rx_radiush->len);
	if( radius_len != auth_req->mesg_len ){
		RHP_BUG("%d, %d",radius_len,auth_req->mesg_len);
		err = -EINVAL;
		goto error;
	}


	RHP_LOCK(&(_rhp_radius_syspxy_lock));
	{

		err = _rhp_radius_syspxy_auth_verify(
						auth_req->secret_index,
						rx_radiush,(((u8*)auth_req) + auth_req->len),
						tx_authenticator,
						&error_notify,
						auth_req->vpn_realm_id);
		if( err ){
			RHP_UNLOCK(&(_rhp_radius_syspxy_lock));
			RHP_LOG_DE(RHP_LOG_SRC_AUTH,auth_req->vpn_realm_id,RHP_LOG_ID_RADIUS_SYSPXY_AUTH_VERIFY_ERR,"LbppE","RADIUS_CODE",rx_radiush->code,rx_radiush->id,RHP_RADIUS_AUTHENTICATOR_LEN,rx_radiush->authenticator,RHP_RADIUS_AUTHENTICATOR_LEN,tx_authenticator,err);
			goto error;
		}
	}
	RHP_UNLOCK(&(_rhp_radius_syspxy_lock));


	error_notify = 1;


	if( rx_radiush->code == RHP_RADIUS_CODE_ACCESS_ACCEPT ){

		rhp_auth_radius_get_settings(
				&priv_attr_type_realm_id,&priv_attr_type_realm_role,
				&priv_attr_type_common,&tunnel_private_group_id_attr_enabled);


		err = _rhp_radius_syspxy_parse_access_accept_attrs(
						auth_req->secret_index,
						rx_radiush,(((u8*)rx_radiush) + auth_req->mesg_len),
						tx_authenticator,
						priv_attr_type_realm_id,
						tunnel_private_group_id_attr_enabled,
						priv_attr_type_realm_role,
						priv_attr_type_common,
						&mppe_send_key_attr,&mppe_recv_key_attr,
						&rx_vpn_realm_id,
						&rx_radius_roles,
						auth_req->vpn_realm_id);
		if( err ){
			RHP_LOG_DE(RHP_LOG_SRC_AUTH,auth_req->vpn_realm_id,RHP_LOG_ID_RADIUS_SYSPXY_AUTH_PARSE_RX_MESG_ERR,"LbppLE","RADIUS_CODE",rx_radiush->code,rx_radiush->id,RHP_RADIUS_AUTHENTICATOR_LEN,rx_radiush->authenticator,RHP_RADIUS_AUTHENTICATOR_LEN,tx_authenticator,"EAP_TYPE",auth_req->eap_method,err);
			goto error;
		}


		{
			int rlm_id_ok = 0;

			if( rx_vpn_realm_id &&
					rx_vpn_realm_id != RHP_VPN_REALM_ID_UNKNOWN ){

				err = _rhp_radius_syspxy_verify_rx_realm_id(rx_vpn_realm_id,
								auth_req->vpn_realm_id,auth_req->peer_notified_realm_id,&rebound_rlm_id,
								rx_radiush);

				if( err && rx_radius_roles == NULL ){
					goto error;
				}if( !err ){
					rlm_id_ok = 1;
				}
			}

			if( !rlm_id_ok && rx_radius_roles ){

				err = _rhp_radius_syspxy_verify_rx_realm_roles(rx_radius_roles,
								auth_req->vpn_realm_id,auth_req->peer_notified_realm_id,&rebound_rlm_id,
								rx_radiush);
				if( err ){
					goto error;
				}

				rlm_id_ok = 1;
			}

			if( !rlm_id_ok &&
					user_name &&
					rhp_eap_identity_not_protected((int)auth_req->eap_method) ){

				err = _rhp_radius_syspxy_verify_rx_realm_roles_for_not_protected_eap_id(auth_req,
								user_name,auth_req->vpn_realm_id,auth_req->peer_notified_realm_id,&rebound_rlm_id,
								rx_radiush);
				if( err ){
					goto error;
				}

				rlm_id_ok = 1;
			}

			if( auth_req->vpn_realm_id == rebound_rlm_id ){
				rebound_rlm_id = 0;
			}
		}


		RHP_LOCK(&(_rhp_radius_syspxy_lock));
		{

			if( auth_req->eap_method &&
					mppe_send_key_attr && mppe_recv_key_attr ){

				err = _rhp_radius_syspxy_get_msk(
								auth_req->secret_index,
								auth_req->eap_method,
								tx_authenticator,
								mppe_send_key_attr,mppe_recv_key_attr,
								&msk,&msk_len);
				if( err ){
					RHP_UNLOCK(&(_rhp_radius_syspxy_lock));
					RHP_LOG_DE(RHP_LOG_SRC_AUTH,auth_req->vpn_realm_id,RHP_LOG_ID_RADIUS_SYSPXY_AUTH_PARSE_MS_MPPE_KEYS_ERR,"LbppLpp","RADIUS_CODE",rx_radiush->code,rx_radiush->id,RHP_RADIUS_AUTHENTICATOR_LEN,rx_radiush->authenticator,RHP_RADIUS_AUTHENTICATOR_LEN,tx_authenticator,"EAP_TYPE",auth_req->eap_method,mppe_send_key_attr->vendor_len,(u8*)(mppe_send_key_attr + 1),mppe_recv_key_attr->vendor_len,(u8*)(mppe_recv_key_attr + 1));
					goto error;
				}

				RHP_LOG_D(RHP_LOG_SRC_AUTH,auth_req->vpn_realm_id,RHP_LOG_ID_RADIUS_SYSPXY_AUTH_MS_MPPE_KEYS_INFO,"LbppLpp","RADIUS_CODE",rx_radiush->code,rx_radiush->id,RHP_RADIUS_AUTHENTICATOR_LEN,rx_radiush->authenticator,RHP_RADIUS_AUTHENTICATOR_LEN,tx_authenticator,"EAP_TYPE",auth_req->eap_method,mppe_send_key_attr->vendor_len,(u8*)(mppe_send_key_attr + 1),mppe_recv_key_attr->vendor_len,(u8*)(mppe_recv_key_attr + 1));
				if( rhp_gcfg_dbg_log_keys_info ){
					RHP_LOG_D(RHP_LOG_SRC_AUTH,auth_req->vpn_realm_id,RHP_LOG_ID_RADIUS_SYSPXY_AUTH_MSK,"LbppLp","RADIUS_CODE",rx_radiush->code,rx_radiush->id,RHP_RADIUS_AUTHENTICATOR_LEN,rx_radiush->authenticator,RHP_RADIUS_AUTHENTICATOR_LEN,tx_authenticator,"EAP_TYPE",auth_req->eap_method,msk_len,msk);
				}

			}else{

				RHP_LOG_D(RHP_LOG_SRC_AUTH,auth_req->vpn_realm_id,RHP_LOG_ID_RADIUS_SYSPXY_AUTH_MSK_NOT_GENERATED,"LbppL","RADIUS_CODE",rx_radiush->code,rx_radiush->id,RHP_RADIUS_AUTHENTICATOR_LEN,rx_radiush->authenticator,RHP_RADIUS_AUTHENTICATOR_LEN,tx_authenticator,"EAP_TYPE",auth_req->eap_method);
			}
		}
		RHP_UNLOCK(&(_rhp_radius_syspxy_lock));
	}

	err = 0;

error:
	{
		ipc_rep = (rhp_ipcmsg_radius_mesg_auth_rep*)rhp_ipc_alloc_msg(RHP_IPC_RADIUS_MESG_AUTH_REPLY,
							sizeof(rhp_ipcmsg_radius_mesg_auth_rep) + sizeof(rhp_proto_radius) + msk_len);

		if( ipc_rep ){

			ipc_rep->len = sizeof(rhp_ipcmsg_radius_mesg_auth_rep) + sizeof(rhp_proto_radius);
			ipc_rep->txn_id = auth_req->txn_id;
			ipc_rep->mesg_len = sizeof(rhp_proto_radius);
			memcpy((u8*)(ipc_rep + 1),rx_radiush,sizeof(rhp_proto_radius));

			ipc_rep->error = err;
			if( !err ){

				ipc_rep->len += msk_len;

				if( msk_len ){
					ipc_rep->msk_len = msk_len;
					memcpy(((u8*)(ipc_rep + 1)) + ipc_rep->mesg_len,msk,msk_len);
				}

				ipc_rep->rebound_rlm_id = rebound_rlm_id;

			}else{

				ipc_rep->error_notify = error_notify;
			}

			if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipc_rep,ipc_rep->len,0) < 0 ){
				RHP_BUG("");
		  }

		}else{
			RHP_BUG("");
		}
	}

	if( auth_req ){
		_rhp_free_zero(auth_req,auth_req->len);
		*ipcmsg = NULL;
	}
	if( ipc_rep ){
		_rhp_free_zero(ipc_rep,ipc_rep->len);
	}
	if( msk ){
		_rhp_free_zero(msk,msk_len);
	}

	_rhp_string_list_free(rx_radius_roles);

	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_IPC_MESG_AUTH_HANDLER_RTRN,"xE",auth_req,err);
	return;
}


int rhp_radius_syspxy_init()
{
	int err = -EINVAL;

  _rhp_mutex_init("RSL",&(_rhp_radius_syspxy_lock));

	// TODO : rhp_prc_ipcmsg_wts_handler should be used for IKEv2's heavy crypto processing.
	err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_RADIUS_MESG_AUTH_REQUEST,
			_rhp_radius_syspxy_ipc_mesg_auth_handler,NULL);
	if( err ){
		RHP_BUG("");
		return err;
	}

	// TODO : rhp_prc_ipcmsg_wts_handler should be used for IKEv2's heavy crypto processing.
	err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_RADIUS_MESG_SIGN_REQUEST,
			_rhp_radius_syspxy_ipc_mesg_sign_handler,NULL);
	if( err ){
		RHP_BUG("");
		return err;
	}

	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_INIT,"E",err);

  return 0;
}

int rhp_radius_syspxy_cleanup()
{
	_rhp_mutex_destroy(&(_rhp_radius_syspxy_lock));

	RHP_TRC(0,RHPTRCID_RADIUS_SYSPXY_CLEANUP,"");
	return 0;
}
