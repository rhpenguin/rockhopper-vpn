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
#include "rhp_eap_auth_impl.h"
#include "rhp_radius_impl.h"
#include "rhp_eap_auth_priv.h"


static rhp_mutex_t _rhp_eap_auth_syspxy_lock;


static rhp_eap_auth_sess* _rhp_eap_auth_sess_hashtbl[RHP_VPN_HASH_TABLE_SIZE];


rhp_eap_auth_sess* rhp_eap_auth_alloc(int eap_vendor,int eap_type,unsigned long rlm_id,
		u8* unique_id,int side,u8* spi)
{
	rhp_eap_auth_sess* a_sess = (rhp_eap_auth_sess*)_rhp_malloc(sizeof(rhp_eap_auth_sess));

  RHP_TRC(0,RHPTRCID_EAP_AUTH_ALLOC,"dLdupLdG",eap_vendor,"EAP_TYPE",eap_type,rlm_id,RHP_VPN_UNIQUE_ID_SIZE,unique_id,"IKE_SIDE",side,spi);

	if( a_sess == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(a_sess,0,sizeof(rhp_eap_auth_sess));

	a_sess->tag[0] = '#';
	a_sess->tag[1] = 'E';
	a_sess->tag[2] = 'E';
	a_sess->tag[3] = 'S';

	a_sess->vpn_realm_id = rlm_id;

	memcpy(a_sess->unique_id,unique_id,RHP_VPN_UNIQUE_ID_SIZE);

	a_sess->side = side;
	memcpy(a_sess->spi,spi,RHP_PROTO_IKE_SPI_SIZE);

	a_sess->method_type = eap_type;

	if( eap_type < RHP_PROTO_EAP_TYPE_PRIV_MIN ){

		a_sess->method = eap_server_get_eap_method(eap_vendor,(EapType)eap_type);
		if( a_sess->method == NULL ){
			RHP_BUG("%d",eap_type);
			_rhp_free(a_sess);
			return NULL;
		}

		a_sess->method_ctx = a_sess->method->init();
		if( a_sess->method_ctx == NULL ){
			RHP_BUG("%d",eap_type);
			_rhp_free(a_sess);
			return NULL;
		}
	}

	a_sess->xauth_state = RHP_XAUTH_AUTH_STAT_DEFAULT;

	a_sess->eap_req_id = 1;

	a_sess->created = _rhp_get_time();

  RHP_TRC(0,RHPTRCID_EAP_AUTH_ALLOC_RTRN,"dLdupLdGxxx",eap_vendor,"EAP_TYPE",eap_type,rlm_id,RHP_VPN_UNIQUE_ID_SIZE,unique_id,"IKE_SIDE",side,spi,a_sess,a_sess->method,a_sess->method_ctx);
	return a_sess;
}

int rhp_eap_auth_delete(rhp_eap_auth_sess* a_sess_d)
{
	int hval;
	rhp_eap_auth_sess *a_sess = NULL,*a_sess_p = NULL;

	RHP_TRC(0,RHPTRCID_EAP_AUTH_DELETE,"px",RHP_VPN_UNIQUE_ID_SIZE,a_sess_d->unique_id,a_sess_d);

  RHP_LOCK(&_rhp_eap_auth_syspxy_lock);

  hval = rhp_vpn_unique_id_hash(a_sess_d->unique_id);

  a_sess = _rhp_eap_auth_sess_hashtbl[hval];

  while( a_sess ){

    if( a_sess == a_sess_d ){
   	  break;
    }

    a_sess_p = a_sess;
    a_sess = a_sess->next;
  }

  if( a_sess ){

  	if( a_sess_p ){
  		a_sess_p->next = a_sess->next;
  	}else{
  		_rhp_eap_auth_sess_hashtbl[hval] = a_sess->next;
  	}

  	if( a_sess->method ){
  		a_sess->method->cleanup(a_sess->method_ctx);
  	}

  	if( a_sess->key_id ){
  		_rhp_free(a_sess->key_id);
  	}

  	if( a_sess->xauth_peer_identity ){
  		_rhp_free(a_sess->xauth_peer_identity);
  	}

  	_rhp_free(a_sess);

  }else{

  	RHP_TRC(0,RHPTRCID_EAP_AUTH_DELETE_NOT_FOUND,"x",a_sess_d);

    RHP_UNLOCK(&_rhp_eap_auth_syspxy_lock);
    return -ENOENT;
  }

  RHP_UNLOCK(&_rhp_eap_auth_syspxy_lock);

	RHP_TRC(0,RHPTRCID_EAP_AUTH_DELETE_RTRN,"x",a_sess_d);
  return 0;
}

rhp_eap_auth_sess* rhp_eap_auth_get(u8* unique_id)
{
	rhp_eap_auth_sess* a_sess = NULL;
  u32 hval;

	RHP_TRC(0,RHPTRCID_EAP_AUTH_GET,"p",RHP_VPN_UNIQUE_ID_SIZE,unique_id);

  RHP_LOCK(&_rhp_eap_auth_syspxy_lock);

  hval = rhp_vpn_unique_id_hash(unique_id);

  a_sess = _rhp_eap_auth_sess_hashtbl[hval];

  while( a_sess ){

  	if( !memcmp(unique_id,a_sess->unique_id,RHP_VPN_UNIQUE_ID_SIZE) ){
  		break;
  	}

  	a_sess = a_sess->next;
  }

  RHP_UNLOCK(&_rhp_eap_auth_syspxy_lock);

	RHP_TRC(0,RHPTRCID_EAP_AUTH_GET_RTRN,"px",RHP_VPN_UNIQUE_ID_SIZE,unique_id,a_sess);
  return a_sess;
}

void rhp_eap_auth_put(rhp_eap_auth_sess* a_sess)
{
  u32 hval;

	RHP_TRC(0,RHPTRCID_EAP_AUTH_PUT,"px",RHP_VPN_UNIQUE_ID_SIZE,a_sess->unique_id,a_sess);

  RHP_LOCK(&_rhp_eap_auth_syspxy_lock);

  hval = rhp_vpn_unique_id_hash(a_sess->unique_id);

  a_sess->next = _rhp_eap_auth_sess_hashtbl[hval];
  _rhp_eap_auth_sess_hashtbl[hval] = a_sess;

  RHP_UNLOCK(&_rhp_eap_auth_syspxy_lock);

  return;
}


static int _rhp_eap_auth_get_key(void* ctx,const u8* key_id,int key_id_len,u8** key)
{
	int err = -EINVAL;
	rhp_ikev2_id* my_id = (rhp_ikev2_id*)ctx;
	rhp_vpn_auth_realm* rb_auth_rlm = NULL;
  rhp_auth_peer* auth_peer;
  rhp_auth_psk *peer_psk;
  int key_len = 0;
  rhp_eap_id eap_peer_id;
  unsigned long peer_notified_realm_id = my_id->priv;

	RHP_TRC(0,RHPTRCID_EAP_AUTH_GET_KEY,"pxxu",key_id_len,key_id,key,my_id,peer_notified_realm_id);
	rhp_ikev2_id_dump("_rhp_eap_auth_get_key",my_id);

	memset(&eap_peer_id,0,sizeof(rhp_eap_id));


	if( key_id == NULL || key_id_len < 1 ){
  	RHP_TRC(0,RHPTRCID_EAP_AUTH_GET_KEY_NO_KEY_ID,"xxd",my_id,key_id,key_id_len);
		goto error;
	}


	err = rhp_eap_id_setup(RHP_PROTO_EAP_TYPE_MS_CHAPV2,key_id_len,key_id,0,&eap_peer_id);
	if( err ){
		RHP_BUG("");
		goto error;
	}


	rb_auth_rlm = rhp_auth_realm_get_by_role(my_id,RHP_PEER_ID_TYPE_EAP,&eap_peer_id,
			NULL,0,peer_notified_realm_id);

	if( rb_auth_rlm == NULL ){

		rb_auth_rlm = rhp_auth_realm_get_def_eap_server(my_id,peer_notified_realm_id);
	}

	if( rb_auth_rlm == NULL ){
  	RHP_TRC(0,RHPTRCID_EAP_AUTH_GET_KEY_RLM_NOT_FOUND,"xx",my_id,key_id);
		goto error;
	}


  RHP_LOCK(&(rb_auth_rlm->lock));

	if( rb_auth_rlm->eap.role != RHP_EAP_AUTHENTICATOR ){

  	RHP_TRC(0,RHPTRCID_EAP_AUTH_GET_KEY_NOT_AUTHENTICATOR,"xuLd",rb_auth_rlm,rb_auth_rlm->id,"EAP_ROLE",rb_auth_rlm->eap.role);

  	RHP_LOG_DE(RHP_LOG_SRC_AUTH,(rb_auth_rlm ? rb_auth_rlm->id : 0),RHP_LOG_ID_EAP_NOT_AUTHENTICATOR,"L","EAP_ROLE",rb_auth_rlm->eap.role);

  	goto error;
	}

  auth_peer = rb_auth_rlm->get_peer_by_id(rb_auth_rlm,RHP_PEER_ID_TYPE_EAP,(void*)&eap_peer_id);
  if( auth_peer == NULL ){
  	RHP_TRC(0,RHPTRCID_EAP_AUTH_GET_KEY_NO_PEER,"xu",rb_auth_rlm,rb_auth_rlm->id);
  	goto error;
  }


  peer_psk = auth_peer->peer_psks;
  while( peer_psk ){

    if( peer_psk->key ){
    	break;
    }

    peer_psk = peer_psk->next;
  }

  if( peer_psk == NULL ){
  	goto error;
  }

  *key = peer_psk->key;
  key_len = strlen((char*)peer_psk->key); // '\0' NOT included.

  my_id->priv = rb_auth_rlm->id;

	RHP_LOG_D(RHP_LOG_SRC_AUTH,rb_auth_rlm->id,RHP_LOG_ID_EAP_PEER_KEY_FOUND,"s",eap_peer_id.identity);


  RHP_UNLOCK(&(rb_auth_rlm->lock));
	rhp_auth_realm_unhold(rb_auth_rlm);
	rb_auth_rlm = NULL;

	rhp_eap_id_clear(&eap_peer_id);

  RHP_TRC(0,RHPTRCID_EAP_AUTH_GET_KEY_RTRN,"xup",rb_auth_rlm,my_id->priv,key_len,*key);
	return key_len; // '\0' NOT included.

error:

	if( key_id_len < 1 ){
		RHP_LOG_DE(RHP_LOG_SRC_AUTH,(rb_auth_rlm ? rb_auth_rlm->id : 0),RHP_LOG_ID_EAP_NO_PEER_KEY,"s","(null)");
	}else{
		RHP_LOG_DE(RHP_LOG_SRC_AUTH,(rb_auth_rlm ? rb_auth_rlm->id : 0),RHP_LOG_ID_EAP_NO_PEER_KEY,"s",eap_peer_id.identity);
	}

	if( rb_auth_rlm ){
	  RHP_UNLOCK(&(rb_auth_rlm->lock));
		rhp_auth_realm_unhold(rb_auth_rlm);
	}

	rhp_eap_id_clear(&eap_peer_id);

	RHP_TRC(0,RHPTRCID_EAP_AUTH_GET_KEY_ERR,"x",rb_auth_rlm);
	return 0;
}


static void _rhp_eap_auth_syspxy_ipc_handler(rhp_ipcmsg** ipcmsg)
{
	int err = -EINVAL;
	rhp_eap_auth_sess* a_sess = NULL;
  struct wpabuf *rx_wbuf = NULL, *tx_wbuf = NULL;
  u8 *eap_msg_rx;
  int eap_msg_rx_len;
  int eap_status = RHP_EAP_STAT_ERROR;
  int ipc_rep_len = sizeof(rhp_ipcmsg_eap_handle_rep);
  rhp_ipcmsg* ipcmsg_rep = NULL;
  unsigned long rebound_vpn_realm_id = 0;
  size_t msk_len = 0;
  u8* msk = NULL;
  size_t peer_identity_len = 0;
  u8* peer_identity = NULL;
  unsigned long auth_rlm_id = 0;
  rhp_ikev2_id my_id; // Don't forget to clear my_id's fields by rhp_ikev2_id_clear().

	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_IPC_HANDLER,"xx",ipcmsg,*ipcmsg);

	memset(&my_id,0,sizeof(rhp_ikev2_id));

	if( (*ipcmsg)->len < sizeof(rhp_ipcmsg) ){
		RHP_BUG("");
		goto error_no_log;
	}

	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_IPC_HANDLER_TYPE,"xLd",*ipcmsg,"IPC",(*ipcmsg)->type);

	switch( (*ipcmsg)->type ){

	case RHP_IPC_EAP_AUTH_HANDLE_REQUEST:
	{
		rhp_ipcmsg_eap_handle_req* ipc_req = (rhp_ipcmsg_eap_handle_req*)*ipcmsg;
	  rhp_ipcmsg_eap_handle_rep* ipc_rep = NULL;

		if( ipc_req->len < sizeof(rhp_ipcmsg_eap_handle_req) ){
			RHP_BUG("%d",ipc_req->len);
			goto error;
		}

  	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_IPC_HANDLER_REQUEST,"xLdudpLdGd",ipc_req,"IPC",ipc_req->type,ipc_req->vpn_realm_id,ipc_req->init_req,RHP_VPN_UNIQUE_ID_SIZE,ipc_req->unique_id,"IKE_SIDE",ipc_req->side,ipc_req->spi,ipc_req->eap_mesg_len);

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

				a_sess = rhp_eap_auth_alloc(auth_rlm->eap.eap_vendor,auth_rlm->eap.method,auth_rlm->id,
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


	    tx_wbuf = a_sess->method->buildReq(a_sess->method_ctx,a_sess->eap_req_id++);
	    if( tx_wbuf == NULL ){
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


			if( a_sess->method->check(a_sess->method_ctx,rx_wbuf) ){
		  	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_IPC_HANDLER_REQUEST_EAP_CHECK_ERR,"x",ipc_req);
	    	goto error_resp;
			}

			if( ((rhp_proto_eap*)eap_msg_rx)->code == RHP_PROTO_EAP_CODE_RESPONSE &&
					((rhp_proto_eap*)eap_msg_rx)->identifier != (a_sess->eap_req_id - 1)){
		  	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_IPC_HANDLER_REQUEST_EAP_INVALID_IDENTIFIER,"xbb",ipc_req,((rhp_proto_eap*)eap_msg_rx)->identifier,(a_sess->eap_req_id - 1));
				eap_status = RHP_EAP_STAT_ERROR;
	    	goto error_resp;
			}

			{
				my_id.priv = ipc_req->peer_notified_realm_id;

				a_sess->method->process(a_sess->method_ctx,rx_wbuf,_rhp_eap_auth_get_key,&my_id);

				if( my_id.priv && my_id.priv != RHP_VPN_REALM_ID_UNKNOWN ){

					a_sess->rebound_rlm_id = my_id.priv;
					RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_IPC_HANDLER_REBOUND_RLM_ID_FROM_CTX,"xxuu",ipc_req,a_sess,cur_auth_rlm_id,a_sess->rebound_rlm_id);
				}
			}

			if( !a_sess->method->isDone(a_sess->method_ctx) ){

		    tx_wbuf = a_sess->method->buildReq(a_sess->method_ctx,a_sess->eap_req_id++);
		    if( tx_wbuf == NULL ){
		    	RHP_BUG("");
					eap_status = RHP_EAP_STAT_ERROR;
		    	goto error_resp;
		    }
			}

			// method->buildReq() may change the a_sess's EAP State???
			// To just make sure, call method->isDone() again here.
			if( !a_sess->method->isDone(a_sess->method_ctx) ){

				eap_status = RHP_EAP_STAT_CONTINUE;
		  	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_IPC_HANDLER_REQUEST_IS_DONE_CONTINUE,"x",ipc_rep);

			}else{

		  	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_IPC_HANDLER_REQUEST_IS_DONE_COMPLETED,"x",ipc_rep);

				if( a_sess->method->isSuccess(a_sess->method_ctx) ){

					peer_identity = a_sess->method->get_peer_identity(a_sess->method_ctx,&peer_identity_len);
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

								RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_IPC_HANDLER_ACTUAL_REBOUND_RLM_ID_FOUND,"xxsuu",ipc_req,a_sess,eap_peer_id,cur_auth_rlm_id,rebound_vpn_realm_id);
								RHP_LOG_D(RHP_LOG_SRC_AUTH,rebound_vpn_realm_id,RHP_LOG_ID_EAP_SERVER_ACTUAL_REALM_FOUND,"suu",eap_peer_id,cur_auth_rlm_id,rebound_vpn_realm_id);

							}else{

						  	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_IPC_HANDLER_SAME_BOUND_RLM_ID_USED,"xxsu",ipc_req,a_sess,eap_peer_id,cur_auth_rlm_id);
							}

						}else{

					  	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_IPC_HANDLER_NO_REBOUND_RLM_ID,"xxsu",ipc_req,a_sess,eap_peer_id,cur_auth_rlm_id);
						}

						_rhp_free(eap_peer_id);
					}


					msk = a_sess->method->getKey(a_sess->method_ctx,&msk_len);


					eap_status = RHP_EAP_STAT_COMPLETED;

			  	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_IPC_HANDLER_REQUEST_IS_SUCCESS,"xpp",ipc_req,peer_identity_len,peer_identity,msk_len,msk);

				}else{

					eap_status = RHP_EAP_STAT_ERROR;

					RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_IPC_HANDLER_REQUEST_IS_ERROR,"x",ipc_req);
				}

				rhp_eap_auth_delete(a_sess);
				a_sess = NULL;
			}
		}

error_resp:
    {
    	int tx_eap_len = (tx_wbuf ? wpabuf_len(tx_wbuf) : 0);

    	ipc_rep_len += tx_eap_len + msk_len + peer_identity_len;

			ipc_rep = (rhp_ipcmsg_eap_handle_rep*)rhp_ipc_alloc_msg(RHP_IPC_EAP_AUTH_HANDLE_REPLY,ipc_rep_len);
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

			ipc_rep->eap_mesg_len = (tx_wbuf ? wpabuf_len(tx_wbuf) : 0);
			ipc_rep->msk_len = msk_len;
			ipc_rep->peer_identity_len = peer_identity_len;

			ipc_rep->rebound_vpn_realm_id = rebound_vpn_realm_id;

			ipc_rep->is_init_req = ipc_req->is_init_req;

			if( tx_eap_len ){
				memcpy((u8*)(ipc_rep + 1),wpabuf_mhead(tx_wbuf),tx_eap_len);
			}

			if( msk_len ){
				memcpy(((u8*)(ipc_rep + 1)) + tx_eap_len,msk,msk_len);
			}

			if( peer_identity_len ){
				memcpy(((u8*)(ipc_rep + 1)) + tx_eap_len + msk_len,peer_identity,peer_identity_len);
			}

			ipcmsg_rep = (rhp_ipcmsg*)(ipc_rep);
    }

  	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_IPC_HANDLER_REQUEST_STAT,"xE",ipc_req,eap_status);
	}
		break;


	case RHP_IPC_EAP_AUTH_HANDLE_CANCEL:
	{
		rhp_ipcmsg_eap_handle_cancel* ipc_req = (rhp_ipcmsg_eap_handle_cancel*)*ipcmsg;

		if( ipc_req->len < sizeof(rhp_ipcmsg_eap_handle_cancel) ){
			RHP_BUG("%d",ipc_req->len);
			goto error;
		}

  	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_IPC_HANDLER_CANCEL,"xLdup",ipc_req,"IPC",ipc_req->type,ipc_req->vpn_realm_id,RHP_VPN_UNIQUE_ID_SIZE,ipc_req->unique_id);

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
  	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_IPC_HANDLER_STAT,"xxE",ipcmsg,(*ipcmsg),eap_status);
		goto error;
	}

  rhp_ikev2_id_clear(&my_id);

	if( msk ){
		_rhp_free_zero(msk,msk_len);
	}

	if( peer_identity ){
		_rhp_free(peer_identity);
	}

	if( tx_wbuf ){
		wpabuf_free(tx_wbuf);
	}

	if( rx_wbuf ){
		wpabuf_unbind_ext_data(rx_wbuf);
		wpabuf_free(rx_wbuf);
	}

	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_IPC_HANDLER_RTRN,"xx",ipcmsg,(*ipcmsg));
	return;


error:
	if( (*ipcmsg)->type == RHP_IPC_EAP_AUTH_HANDLE_REQUEST ){
		RHP_LOG_DE(RHP_LOG_SRC_AUTH,auth_rlm_id,RHP_LOG_ID_EAP_SERVER_FAILED_TO_PROCESS_EAP_MESG,"E",err);
	}

error_no_log:
	if( a_sess ){
		rhp_eap_auth_delete(a_sess);
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

	if( peer_identity ){
		_rhp_free(peer_identity);
	}

  rhp_ikev2_id_clear(&my_id);

	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_IPC_HANDLER_ERR,"xx",ipcmsg,(*ipcmsg));
	return;
}

extern void rhp_eap_auth_syspxy_xauth_ipc_handler(rhp_ipcmsg** ipcmsg);

int rhp_eap_syspxy_auth_init()
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_INIT,"");

	memset(_rhp_eap_auth_sess_hashtbl,0,sizeof(rhp_eap_auth_sess*)*RHP_VPN_HASH_TABLE_SIZE);

  _rhp_mutex_init("EAS",&(_rhp_eap_auth_syspxy_lock));

	// TODO : rhp_prc_ipcmsg_wts_handler should be used for IKEv2's heavy crypto processing.
	err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_EAP_AUTH_HANDLE_REQUEST,
			_rhp_eap_auth_syspxy_ipc_handler,NULL);

	if( err ){
		RHP_BUG("");
		return err;
	}

	// TODO : rhp_prc_ipcmsg_wts_handler should be used for IKEv2's heavy crypto processing.
	err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_EAP_AUTH_HANDLE_CANCEL,
			_rhp_eap_auth_syspxy_ipc_handler,NULL);

	if( err ){
		RHP_BUG("");
		return err;
	}


	// TODO : rhp_prc_ipcmsg_wts_handler should be used for IKEv2's heavy crypto processing.
	err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_XAUTH_AUTH_HANDLE_REQUEST,
			rhp_eap_auth_syspxy_xauth_ipc_handler,NULL);

	if( err ){
		RHP_BUG("");
		return err;
	}

	// TODO : rhp_prc_ipcmsg_wts_handler should be used for IKEv2's heavy crypto processing.
	err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_XAUTH_AUTH_HANDLE_CANCEL,
			rhp_eap_auth_syspxy_xauth_ipc_handler,NULL);

	if( err ){
		RHP_BUG("");
		return err;
	}

	if( eap_server_mschapv2_register() ){
		RHP_BUG("");
		return -EINVAL;
	}

	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_INIT_RTRN,"");
	return 0;
}

int rhp_eap_syspxy_auth_cleanup()
{
	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_CLEANUP,"");

	_rhp_mutex_destroy(&(_rhp_eap_auth_syspxy_lock));

	RHP_TRC(0,RHPTRCID_EAP_AUTH_SYSPXY_CLEANUP_RTRN,"");
	return 0;
}

