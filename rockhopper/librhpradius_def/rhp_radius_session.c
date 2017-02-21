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
#include "rhp_pcap.h"


rhp_mutex_t rhp_radius_priv_lock;

static u64 _rhp_radius_ipc_txn_id = 0;

static u64 _rhp_radius_new_ipc_txn_id()
{
  u64 new_id;

  RHP_TRC(0,RHPTRCID_RADIUS_NEW_IPC_TXN_ID,"q",_rhp_radius_ipc_txn_id);

  RHP_LOCK(&rhp_radius_priv_lock);

  new_id = ++_rhp_radius_ipc_txn_id;
  if( _rhp_radius_ipc_txn_id == 0 ){
  	_rhp_radius_ipc_txn_id++;
  }

  RHP_UNLOCK(&rhp_radius_priv_lock);

  RHP_TRC(0,RHPTRCID_RADIUS_NEW_IPC_TXN_ID_RTRN,"q",new_id);
  return new_id;
}

struct _rhp_radius_sess_ipc_holder {

	struct _rhp_radius_sess_ipc_holder* next;

	u64 ipc_txn_id;
	rhp_radius_session_ref* radius_sess_ref;
};
typedef struct _rhp_radius_sess_ipc_holder	rhp_radius_sess_ipc_holder;

#define RHP_RADIUS_SESS_HASH_TABLE_SIZE 	1277

static rhp_radius_sess_ipc_holder* _rhp_radius_sess_ipc_holder_htbl[RHP_RADIUS_SESS_HASH_TABLE_SIZE];
u32 _rhp_radius_sess_ipc_holder_htbl_rnd;

static u32 _rhp_radius_sess_ipc_hash(u64 ipc_txn_id)
{
	u32 hval;

  hval = _rhp_hash_u32s((u8*)&ipc_txn_id,sizeof(u64),_rhp_radius_sess_ipc_holder_htbl_rnd);
  hval = hval % RHP_RADIUS_SESS_HASH_TABLE_SIZE;

  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_IPC_HASH,"x",hval);
  return hval;
}

static rhp_radius_session_ref* _rhp_radius_sess_ipc_get(u64 ipc_txn_id)
{
	u32 hval = _rhp_radius_sess_ipc_hash(ipc_txn_id);
	rhp_radius_sess_ipc_holder* hldr = _rhp_radius_sess_ipc_holder_htbl[hval];

  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_IPC_GET,"q",ipc_txn_id);

	while( hldr ){

		if( hldr->ipc_txn_id == ipc_txn_id ){
			break;
		}

		hldr = hldr->next;
	}

	if( hldr ){

		rhp_radius_session_ref* ret_ref
		= rhp_radius_sess_hold_ref(RHP_RADIUS_SESS_REF(hldr->radius_sess_ref));

	  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_IPC_GET_RTRN,"xxxxuxx",ret_ref,hldr->radius_sess_ref,RHP_RADIUS_SESS_REF(hldr->radius_sess_ref),hldr,hval,RHP_RADIUS_SESS_REF(ret_ref)->priv,((rhp_radius_session_priv*)RHP_RADIUS_SESS_REF(ret_ref)->priv)->cb_ctx);
	  return ret_ref;
	}

  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_IPC_GET_NO_ENT,"qu",ipc_txn_id,hval);
	return NULL;
}

static void _rhp_radius_sess_pcap_write(rhp_packet* pkt)
{
	rhp_pcap_write_pkt(pkt);
	return;
}


static int _rhp_radius_sess_ipc_remove(u64 ipc_txn_id)
{
	u32 hval = _rhp_radius_sess_ipc_hash(ipc_txn_id);
	rhp_radius_sess_ipc_holder *hldr = _rhp_radius_sess_ipc_holder_htbl[hval], *hldr_p = NULL;

  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_IPC_REMOVE,"q",ipc_txn_id);

	while( hldr ){

		if( hldr->ipc_txn_id == ipc_txn_id ){
			break;
		}

		hldr_p = hldr;
		hldr = hldr->next;
	}

	if( hldr ){

		if( hldr_p ){
			hldr_p->next = hldr->next;
		}else{
			_rhp_radius_sess_ipc_holder_htbl[hval] = hldr->next;
		}

	  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_IPC_REMOVE_OBJ,"qxuxx",ipc_txn_id,hldr,hval,hldr->radius_sess_ref,RHP_RADIUS_SESS_REF(hldr->radius_sess_ref));

		rhp_radius_sess_unhold(hldr->radius_sess_ref);

		_rhp_free(hldr);

	  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_IPC_REMOVE_RTRN,"qxu",ipc_txn_id,hldr,hval);
		return 0;
	}

  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_IPC_REMOVE_NO_ENT,"qu",ipc_txn_id,hval);
	return -ENOENT;
}


static int _rhp_radius_sess_ipc_put(u64 ipc_txn_id,rhp_radius_session* radius_sess)
{
	u32 hval = _rhp_radius_sess_ipc_hash(ipc_txn_id);
	rhp_radius_sess_ipc_holder* hldr = (rhp_radius_sess_ipc_holder*)_rhp_malloc(sizeof(rhp_radius_sess_ipc_holder));

  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_IPC_PUT,"qxx",ipc_txn_id,radius_sess,hldr);

	if( hldr == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	memset(hldr,0,sizeof(rhp_radius_sess_ipc_holder));

	hldr->ipc_txn_id = ipc_txn_id;
	hldr->radius_sess_ref = rhp_radius_sess_hold_ref(radius_sess);

	hldr->next = _rhp_radius_sess_ipc_holder_htbl[hval];
	_rhp_radius_sess_ipc_holder_htbl[hval] = hldr;

  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_IPC_PUT_RTRN,"qxxx",ipc_txn_id,radius_sess,hldr->radius_sess_ref,hldr);
	return 0;
}


static int _rhp_radius_session_set_nas_addr(rhp_radius_session* radius_sess,rhp_ip_addr* nas_addr)
{
	memcpy(&(radius_sess->nas_addr),nas_addr,sizeof(rhp_ip_addr));
  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SET_NAS_ADDR,"xx",radius_sess,nas_addr);
  rhp_ip_addr_dump("set_nas_addr",&(radius_sess->nas_addr));
  return 0;
}

static void _rhp_radius_session_get_nas_addr(rhp_radius_session* radius_sess,rhp_ip_addr* nas_addr_r)
{
	memcpy(nas_addr_r,&(radius_sess->nas_addr),sizeof(rhp_ip_addr));
  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_GET_NAS_ADDR,"xx",radius_sess,nas_addr_r);
  rhp_ip_addr_dump("get_nas_addr",nas_addr_r);
}

static void _rhp_radius_session_get_server_addr(rhp_radius_session* radius_sess,rhp_ip_addr* server_addr_port_r)
{
	memcpy(server_addr_port_r,&(radius_sess->server_addr_port),sizeof(rhp_ip_addr));
  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_GET_SERVER_ADDR,"xx",radius_sess,server_addr_port_r);
  rhp_ip_addr_dump("get_server_addr",server_addr_port_r);
}

static char* _rhp_radius_session_get_server_fqdn(rhp_radius_session* radius_sess)
{
  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_GET_SERVER_FQDN,"x",radius_sess,radius_sess->server_fqdn);
  return radius_sess->server_fqdn;
}

static int _rhp_radius_session_set_user_name(rhp_radius_session* radius_sess,char* user_name)
{
  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SET_USER_NAME,"xss",radius_sess,user_name,radius_sess->user_name);

	if( radius_sess->user_name ){
		_rhp_free(radius_sess->user_name);
		radius_sess->user_name = NULL;
	}

	if( user_name ){

		int len = strlen(user_name);

		radius_sess->user_name = (char*)_rhp_malloc(len + 1);
		if( radius_sess->user_name == NULL ){
			RHP_BUG("");
			return -ENOMEM;
		}

		memcpy(radius_sess->user_name,user_name,len);
		radius_sess->user_name[len] = '\0';
	}

  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SET_USER_NAME_RTRN,"xs",radius_sess,radius_sess->user_name);
	return 0;
}

static char* _rhp_radius_session_get_user_name(rhp_radius_session* radius_sess)
{
  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_GET_USER_NAME,"xs",radius_sess,radius_sess->user_name);
	return radius_sess->user_name;
}

static int _rhp_radius_session_set_nas_id(rhp_radius_session* radius_sess,char* nas_id)
{
  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SET_NAS_ID,"xss",radius_sess,nas_id,radius_sess->nas_id);

	if( radius_sess->nas_id ){
		_rhp_free(radius_sess->nas_id);
		radius_sess->nas_id = NULL;
	}

	if( nas_id ){

		int len = strlen(nas_id);

		radius_sess->nas_id = (char*)_rhp_malloc(len + 1);
		if( radius_sess->nas_id == NULL ){
			RHP_BUG("");
			return -ENOMEM;
		}

		memcpy(radius_sess->nas_id,nas_id,len);
		radius_sess->nas_id[len] = '\0';
	}

  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SET_NAS_ID_RTRN,"xs",radius_sess,radius_sess->nas_id);
	return 0;
}

static void _rhp_radius_session_include_nas_id_as_ikev2_id(rhp_radius_session* radius_sess,int flag)
{
	radius_sess->inc_nas_id_as_ikev2_id = flag;
	return;
}



static char* _rhp_radius_session_get_nas_id(rhp_radius_session* radius_sess)
{
  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_GET_NAS_ID,"xs",radius_sess,radius_sess->nas_id);
	return radius_sess->nas_id;
}

static int _rhp_radius_session_set_calling_station_id(rhp_radius_session* radius_sess,char* calling_station_id)
{
  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SET_CALLING_STATION_ID,"xss",radius_sess,calling_station_id,radius_sess->calling_station_id);

  if( radius_sess->calling_station_id ){
		_rhp_free(radius_sess->calling_station_id);
		radius_sess->calling_station_id = NULL;
	}

	if( calling_station_id ){

		int len = strlen(calling_station_id);

		radius_sess->calling_station_id = (char*)_rhp_malloc(len + 1);
		if( radius_sess->calling_station_id == NULL ){
			RHP_BUG("");
			return -ENOMEM;
		}

		memcpy(radius_sess->calling_station_id,calling_station_id,len);
		radius_sess->calling_station_id[len] = '\0';
	}

  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SET_CALLING_STATION_ID_RTRN,"xs",radius_sess,radius_sess->calling_station_id);
	return 0;
}

static char* _rhp_radius_session_get_calling_station_id(rhp_radius_session* radius_sess)
{
  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_GET_CALLING_STATION_ID,"xs",radius_sess,radius_sess->calling_station_id);
	return radius_sess->calling_station_id;
}

static int _rhp_radius_session_set_connect_info(rhp_radius_session* radius_sess,char* connect_info)
{
  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SET_CONNECT_INFO_ID,"xss",radius_sess,connect_info,radius_sess->connect_info);

  if( radius_sess->connect_info ){
		_rhp_free(radius_sess->connect_info);
		radius_sess->connect_info = NULL;
	}

	if( connect_info ){

		int len = strlen(connect_info);

		radius_sess->connect_info = (char*)_rhp_malloc(len + 1);
		if( radius_sess->connect_info == NULL ){
			RHP_BUG("");
			return -ENOMEM;
		}

		memcpy(radius_sess->connect_info,connect_info,len);
		radius_sess->connect_info[len] = '\0';
	}

  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SET_CONNECT_INFO_ID_RTRN,"xs",radius_sess,radius_sess->connect_info);
	return 0;
}

static char* _rhp_radius_session_get_connect_info(rhp_radius_session* radius_sess)
{
  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_GET_CONNECT_INFO_ID,"xs",radius_sess,radius_sess->connect_info);
	return radius_sess->connect_info;
}

static void _rhp_radius_session_set_framed_mtu(rhp_radius_session* radius_sess,int framed_mtu)
{
  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SET_FRAMED_MTU,"xdd",radius_sess,radius_sess->framed_mtu,framed_mtu);
	radius_sess->framed_mtu = framed_mtu;
}

static int _rhp_radius_session_get_framed_mtu(rhp_radius_session* radius_sess)
{
  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_GET_FRAMED_MTU,"xd",radius_sess,radius_sess->framed_mtu);
	return radius_sess->framed_mtu;
}

static void _rhp_radius_session_include_nas_port_type(rhp_radius_session* radius_sess,int flag)
{
	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_INCLUDE_NAS_PORT_TYPE,"xdd",radius_sess,radius_sess->inc_nas_port_type,flag);
	radius_sess->inc_nas_port_type = flag;
	return;
}

static int _rhp_radius_session_set_acct_session_id(rhp_radius_session* radius_sess,char* acct_session_id)
{
  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SET_ACCT_SESSION_ID,"xss",radius_sess,acct_session_id,radius_sess->acct_session_id);

  if( radius_sess->acct_session_id ){
		_rhp_free(radius_sess->acct_session_id);
		radius_sess->acct_session_id = NULL;
	}

	if( acct_session_id ){

		int len = strlen(acct_session_id);

		radius_sess->acct_session_id = (char*)_rhp_malloc(len + 1);
		if( radius_sess->acct_session_id == NULL ){
			RHP_BUG("");
			return -ENOMEM;
		}

		memcpy(radius_sess->acct_session_id,acct_session_id,len);
		radius_sess->acct_session_id[len] = '\0';
	}

  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SET_ACCT_SESSION_ID_RTRN,"xs",radius_sess,radius_sess->acct_session_id);
	return 0;
}

static char* _rhp_radius_session_get_acct_session_id(rhp_radius_session* radius_sess)
{
  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_GET_ACCT_SESSION_ID,"xs",radius_sess,radius_sess->acct_session_id);
	return radius_sess->acct_session_id;
}



static void _rhp_radius_session_set_retransmit_interval(rhp_radius_session* radius_sess,time_t interval_secs)
{
	if( interval_secs < 1 ){
		interval_secs = 1;
	}
  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SET_RETRANSMIT_INTERVAL,"xdd",radius_sess,interval_secs,radius_sess->retransmit_interval);
	radius_sess->retransmit_interval = interval_secs;
}

static void _rhp_radius_session_set_retransmit_times(rhp_radius_session* radius_sess,int times)
{
  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SET_RETRANSMIT_TIMES,"xdd",radius_sess,times,radius_sess->retransmit_times);
	radius_sess->retransmit_times = times;
}


static int _rhp_radius_session_get_msk(rhp_radius_session* radius_sess,u8** msk_r,int* msk_len_r)
{
	u8* msk = NULL;
	rhp_radius_session_priv* radius_sess_priv = (rhp_radius_session_priv*)radius_sess->priv;

  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_GET_MSK,"xxxx",radius_sess,radius_sess_priv,msk_r,msk_len_r);

	if( radius_sess_priv->msk ){

		msk = (u8*)_rhp_malloc(radius_sess_priv->msk_len);
		if( msk == NULL ){
			RHP_BUG("");
			return -ENOMEM;
		}

		memcpy(msk,radius_sess_priv->msk,radius_sess_priv->msk_len);

		*msk_r = msk;
		*msk_len_r = radius_sess_priv->msk_len;

	  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_GET_MSK_RTRN,"xxp",radius_sess,radius_sess_priv,*msk_len_r,*msk_r);
		return 0;
	}

  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_GET_MSK_NO_ENT,"xx",radius_sess,radius_sess_priv);
	return -ENOENT;
}

static int _rhp_radius_session_get_eap_method(rhp_radius_session* radius_sess)
{
	rhp_radius_session_priv* radius_sess_priv = (rhp_radius_session_priv*)radius_sess->priv;
  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_GET_EAP_METHOD,"xxd",radius_sess,radius_sess_priv,radius_sess_priv->eap_method);
	return radius_sess_priv->eap_method;
}


static int _rhp_radius_rx_buf_max_size	= 1280;
static int _rhp_radius_rx_max_packets = 4;

extern int rhp_radius_mesg_check(rhp_packet *rx_pkt);

static void _rhp_radius_rx_dispached_task(rhp_packet *rx_pkt)
{
	int err = -EINVAL;
	rhp_radius_session* radius_sess = NULL;
	rhp_radius_mesg* tx_radius_mesg = NULL;
	rhp_radius_session_priv* radius_sess_priv;
	rhp_ipcmsg_radius_mesg_auth_req* auth_req = NULL;
	rhp_proto_radius* rx_radiush;
	u8* req_authenticator;

  RHP_TRC(0,RHPTRCID_RADIUS_RX_DISPATCHED_TASK,"xxxx",rx_pkt,RHP_RADIUS_SESS_REF(rx_pkt->priv),rx_pkt->priv,rx_pkt->app.raw);

  err = rhp_radius_mesg_check(rx_pkt);
  if( err ){
    RHP_TRC(0,RHPTRCID_RADIUS_RX_DISPATCHED_TASK_INVALID_RX_PKT,"x",rx_pkt);
  	goto error;
	}

  rx_radiush = (rhp_proto_radius*)rx_pkt->app.raw;


  radius_sess = RHP_RADIUS_SESS_REF(rx_pkt->priv);

  RHP_LOCK(&(radius_sess->lock));

	radius_sess_priv = (rhp_radius_session_priv*)radius_sess->priv;


	if( !_rhp_atomic_read(&(radius_sess->is_active)) ){
  	err = RHP_STATUS_RADIUS_INVALID_SESSION;
    RHP_TRC(0,RHPTRCID_RADIUS_RX_DISPATCHED_TASK_RADIUS_SESS_NOT_ACTIVE,"xxx",rx_pkt,radius_sess,radius_sess->priv);
    goto error;
  }

  if( radius_sess_priv->tx_access_pkt_ref == NULL ){
  	err = 0;
    RHP_TRC(0,RHPTRCID_RADIUS_RX_DISPATCHED_TASK_RADIUS_SESS_NO_TX_ACCSESS_REQ,"xxx",rx_pkt,radius_sess,radius_sess->priv);
  	goto error;
  }

  if( radius_sess_priv->rx_pend_pkt_ref ){
  	err = 0;
    RHP_TRC(0,RHPTRCID_RADIUS_RX_DISPATCHED_TASK_RADIUS_SESS_RX_PKT_PENDING,"xxxx",rx_pkt,radius_sess,radius_sess->priv,radius_sess_priv->rx_pend_pkt_ref,RHP_PKT_REF(radius_sess_priv->rx_pend_pkt_ref));
  	goto error;
  }

  if( radius_sess_priv->ipc_txn_id ){
  	err = 0;
    RHP_TRC(0,RHPTRCID_RADIUS_RX_DISPATCHED_TASK_RADIUS_SESS_RX_PKT_PENDING_2,"xxxxq",rx_pkt,radius_sess,radius_sess->priv,radius_sess_priv->rx_pend_pkt_ref,RHP_PKT_REF(radius_sess_priv->rx_pend_pkt_ref),radius_sess_priv->ipc_txn_id);
  	goto error;
  }


  tx_radius_mesg = radius_sess_priv->tx_access_req;


  req_authenticator = tx_radius_mesg->get_authenticator(tx_radius_mesg);
  if( req_authenticator == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }


  {
  	char* user_name = NULL;
  	int user_name_len = 0;
  	int auth_req_len = sizeof(rhp_ipcmsg_radius_mesg_auth_req) + RHP_RADIUS_AUTHENTICATOR_LEN + ntohs(rx_radiush->len);
  	u8* p;

		user_name = radius_sess->get_user_name(radius_sess);
		if( user_name ){
			user_name_len = strlen(user_name) + 1;
		}
		auth_req_len += user_name_len;


		auth_req = (rhp_ipcmsg_radius_mesg_auth_req*)rhp_ipc_alloc_msg(RHP_IPC_RADIUS_MESG_AUTH_REQUEST,auth_req_len);
		if( auth_req == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		auth_req->len = auth_req_len;
		auth_req->authenticator_len = RHP_RADIUS_AUTHENTICATOR_LEN;
		auth_req->mesg_len = ntohs(rx_radiush->len);
		auth_req->txn_id = _rhp_radius_new_ipc_txn_id();
		auth_req->eap_method = radius_sess->get_eap_method(radius_sess);
		auth_req->vpn_realm_id = radius_sess->get_realm_id(radius_sess);
		auth_req->peer_notified_realm_id = radius_sess->get_peer_notified_realm_id(radius_sess);
		auth_req->user_name_len = user_name_len;
		auth_req->secret_index = radius_sess->secret_index;


		p = (u8*)(auth_req + 1);

		memcpy(p,req_authenticator,auth_req->authenticator_len);
		p += auth_req->authenticator_len;

		memcpy(p,(u8*)rx_radiush,auth_req->mesg_len);
		p += auth_req->mesg_len;

		if( user_name_len ){
			memcpy(p,user_name,user_name_len);
			p[user_name_len - 1] = '\0';
			p += user_name_len;
		}

		radius_sess_priv->ipc_txn_id = auth_req->txn_id;

    RHP_TRC(0,RHPTRCID_RADIUS_RX_DISPATCHED_TASK_IPC_AUTH_DATA,"xxxqppp",rx_pkt,radius_sess,radius_sess->priv,radius_sess_priv->ipc_txn_id,auth_req->authenticator_len,(u8*)(auth_req + 1),auth_req->mesg_len,((u8*)(auth_req + 1)) + auth_req->authenticator_len,user_name_len,user_name);
  }


  radius_sess_priv->rx_pend_pkt_ref = rhp_pkt_hold_ref(rx_pkt);


  RHP_LOCK(&(rhp_radius_priv_lock));

  err = _rhp_radius_sess_ipc_put(radius_sess_priv->ipc_txn_id,radius_sess);
  if( err ){
    RHP_UNLOCK(&(rhp_radius_priv_lock));
  	RHP_BUG("%d",err);
  	goto error;
  }

  RHP_UNLOCK(&(rhp_radius_priv_lock));


	if( rhp_ipc_send(RHP_MY_PROCESS,(void*)auth_req,auth_req->len,0) < 0 ){
		RHP_BUG("");
  }

	RHP_UNLOCK(&(radius_sess->lock));
	rhp_radius_sess_unhold(radius_sess);

	rhp_pkt_unhold(rx_pkt);

	_rhp_free_zero(auth_req,auth_req->len);

  RHP_TRC(0,RHPTRCID_RADIUS_RX_DISPATCHED_TASK_RTRN,"xx",rx_pkt,radius_sess);
	return;


error:
	if( radius_sess ){

		if( err ){

			if( radius_sess_priv->rx_pend_pkt_ref ){
				rhp_pkt_unhold(radius_sess_priv->rx_pend_pkt_ref);
				radius_sess_priv->rx_pend_pkt_ref = NULL;
			}

			radius_sess_priv->ipc_txn_id = 0;
		}

		RHP_UNLOCK(&(radius_sess->lock));
		rhp_radius_sess_unhold(radius_sess);
	}

	rhp_pkt_unhold(rx_pkt);

	if( auth_req ){
		_rhp_free_zero(auth_req,auth_req->len);
	}

  RHP_TRC(0,RHPTRCID_RADIUS_RX_DISPATCHED_TASK_ERR,"xxE",rx_pkt,radius_sess,err);
	return;
}

static int _rhp_radius_rx_dispatch_pkt(rhp_packet *pkt,rhp_radius_session* radius_sess)
{

	pkt->process_packet = _rhp_radius_rx_dispached_task;
	pkt->priv = rhp_radius_sess_hold_ref(radius_sess);

  RHP_TRC(0,RHPTRCID_RADIUS_RX_DISPATCH_PKT,"xxx",pkt,radius_sess,pkt->priv);

	return rhp_wts_sta_invoke_task(RHP_WTS_DISP_RULE_NETSOCK,RHP_WTS_STA_TASK_NAME_PKT,
			RHP_WTS_DISP_LEVEL_HIGH_2,pkt,pkt);
}

int rhp_radius_session_rx_supported_code(int usage,u8 code)
{
	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RX_SUPPORTED_CODE,"LdLb","RADIUS_USAGE",usage,"RADIUS_CODE",code);

	if( usage == RHP_RADIUS_USAGE_AUTHENTICATION ){

		if( code == RHP_RADIUS_CODE_ACCESS_ACCEPT ||
				code == RHP_RADIUS_CODE_ACCESS_REJECT ||
				code == RHP_RADIUS_CODE_ACCESS_CHALLENGE ){
			return 1;
		}

	}else if( usage == RHP_RADIUS_USAGE_ACCOUNTING ){

		if( code == RHP_RADIUS_CODE_ACCT_RESPONSE ){
			return 1;
		}
	}
	return 0;
}

static int _rhp_radius_session_recv_pkt_v4(struct epoll_event* ep_evt,rhp_epoll_ctx* epoll_ctx,
		rhp_radius_session* radius_sess,rhp_radius_session_priv* radius_sess_priv)
{
  ssize_t rx_len;
	int i, received = 0;

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V4,"xxLdxx",ep_evt,epoll_ctx,"MAIN_EOPLL_EVENT",epoll_ctx->event_type,radius_sess,radius_sess_priv);

  RHP_LOCK(&(rhp_radius_priv_lock));

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V4_SK_IDX,"xxddd",ep_evt,epoll_ctx,radius_sess_priv->sk,_rhp_radius_rx_max_packets,_rhp_radius_rx_buf_max_size);

  for( i = 0; i < _rhp_radius_rx_max_packets; i++ ){

  	rhp_packet* pkt = NULL;
  	struct msghdr msg;
		struct iovec iov[1];
		struct sockaddr_in peer_sin;
		int buf_len = _rhp_radius_rx_buf_max_size;
		rhp_proto_ether* dmy_ethhdr;
		rhp_proto_ip_v4* dmy_iphdr;
		rhp_proto_udp* dmy_udphdr;
		int mesg_len = 0;
		int pkt_offset = 0;
		u8* data_head;

		if( !RHP_PROCESS_IS_ACTIVE() ){
			rx_len = -EINTR;
			RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V4_PROC_NOT_ACTIVE,"xx",ep_evt,epoll_ctx);
			goto error;
		}

		buf_len += sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v4) + sizeof(rhp_proto_udp);
		pkt_offset += sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v4) + sizeof(rhp_proto_udp);

		pkt = rhp_pkt_alloc(buf_len);
		if( pkt == NULL ){
			rx_len = -ENOMEM;
			RHP_BUG("%d",buf_len);
			goto error;
		}

		dmy_ethhdr = (rhp_proto_ether*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ether));
		dmy_iphdr = (rhp_proto_ip_v4*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ip_v4));
		dmy_udphdr = (rhp_proto_udp*)_rhp_pkt_push(pkt,sizeof(rhp_proto_udp));

		data_head = pkt->data + pkt_offset;

		msg.msg_name = &peer_sin;
		msg.msg_namelen = sizeof(peer_sin);
		iov[0].iov_base = data_head;
		iov[0].iov_len  = (buf_len - pkt->len);
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		msg.msg_flags = 0;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;

		rx_len = recvmsg(radius_sess_priv->sk,&msg,MSG_TRUNC | MSG_DONTWAIT);
		if( rx_len < 0 ){

			rx_len = -errno;
			RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V4_INVALID_RX_LEN,"xxE",ep_evt,epoll_ctx,rx_len);

			rhp_pkt_unhold(pkt);
			goto error;
		}

		mesg_len = rx_len;

		if( msg.msg_flags & MSG_TRUNC ){

			RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V4_TRUNC_ERR,"xxdd",ep_evt,epoll_ctx,rx_len,_rhp_radius_rx_buf_max_size);

			if( rx_len <= rhp_gcfg_radius_max_pkt_len ){
				_rhp_radius_rx_buf_max_size = rx_len;
      }

			rhp_pkt_unhold(pkt);
			continue;
		}

		if( rx_len < (int)sizeof(rhp_proto_radius) ){

			RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V4_INVALID_RADIUS_PKT_LEN,"xxd",ep_evt,epoll_ctx,rx_len);

			rhp_pkt_unhold(pkt);
			continue;
		}

		pkt->type = RHP_PKT_IPV4_RADIUS;

		memset(dmy_ethhdr->dst_addr,0,6);
		memset(dmy_ethhdr->src_addr,0,6);
		dmy_ethhdr->protocol = RHP_PROTO_ETH_IP;

		dmy_iphdr->ver = 4;
		dmy_iphdr->ihl = 5;
		dmy_iphdr->tos = 0;
		dmy_iphdr->total_len = htons(mesg_len + sizeof(rhp_proto_ip_v4) + sizeof(rhp_proto_udp));
		dmy_iphdr->id = 0;
		dmy_iphdr->frag = 0;
		dmy_iphdr->ttl = 64;
		dmy_iphdr->protocol = RHP_PROTO_IP_UDP;
		dmy_iphdr->check_sum = 0;

		dmy_iphdr->src_addr = peer_sin.sin_addr.s_addr;
		dmy_iphdr->dst_addr = radius_sess->nas_addr.addr.v4;

		dmy_udphdr->src_port = peer_sin.sin_port;
		dmy_udphdr->dst_port = radius_sess->nas_addr.port;


		dmy_udphdr->len = htons(mesg_len + sizeof(rhp_proto_udp));

		pkt->l2.raw = (u8*)dmy_ethhdr;
		pkt->l3.raw = (u8*)dmy_iphdr;
		pkt->l4.raw = (u8*)dmy_udphdr;

		pkt->app.raw = (u8*)_rhp_pkt_push(pkt,mesg_len);
		if( pkt->app.raw == NULL ){

			RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V4_INVALID_PKT_NO_APP_DATA,"xx",ep_evt,epoll_ctx);

			rhp_pkt_unhold(pkt);
   		continue;
		}

		if( rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_RADIUS] &&
				(!rhp_packet_capture_realm_id || !rhp_packet_capture_realm_id == radius_sess->vpn_realm_id) ){

			_rhp_radius_sess_pcap_write(pkt);
		}

	  if( radius_sess_priv->tx_access_req == NULL ||
	  		radius_sess_priv->tx_access_pkt_ref == NULL ){
			RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V4_INVALID_PKT_NOT_INTERESTED_RESP,"xxdb",ep_evt,epoll_ctx,radius_sess_priv->sk,((rhp_proto_radius*)pkt->app.raw)->id);
			rhp_pkt_unhold(pkt);
   		continue;
	  }

	  if( radius_sess_priv->ipc_txn_id ){
			RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V4_INVALID_PKT_BUSY,"xxdb",ep_evt,epoll_ctx,radius_sess_priv->sk,((rhp_proto_radius*)pkt->app.raw)->id);
			rhp_pkt_unhold(pkt);
   		continue;
	  }

		if( ((rhp_proto_radius*)pkt->app.raw)->id !=
					radius_sess_priv->tx_access_req->get_id(radius_sess_priv->tx_access_req) ){
			RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V4_INVALID_PKT_NOT_INTERESTED_ID,"xxdb",ep_evt,epoll_ctx,radius_sess_priv->sk,((rhp_proto_radius*)pkt->app.raw)->id);
			rhp_pkt_unhold(pkt);
   		continue;
		}

		if( !rhp_radius_session_rx_supported_code(radius_sess->usage,((rhp_proto_radius*)pkt->app.raw)->code) ){
			RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V4_INVALID_PKT_NOT_INTERESTED_CODE,"xxdb",ep_evt,epoll_ctx,radius_sess_priv->sk,((rhp_proto_radius*)pkt->app.raw)->code);
			rhp_pkt_unhold(pkt);
   		continue;
		}

		RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V4_RX_PKT,"xda",pkt,radius_sess_priv->sk,((pkt->l4.raw + ntohs(pkt->l4.udph->len)) - pkt->l2.raw),RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,pkt->l2.raw);


		rx_len = _rhp_radius_rx_dispatch_pkt(pkt,radius_sess);
		if( rx_len ){

			RHP_BUG("%d",rx_len);

			rhp_pkt_unhold(pkt);
			continue;
		}
		received++;
  }

  if( received == 0 ){
  	rx_len = -ENOENT;
  	goto error;
  }

  RHP_UNLOCK(&(rhp_radius_priv_lock));

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V4_RTRN,"xx",ep_evt,epoll_ctx);
	return 0;

error:
	RHP_UNLOCK(&(rhp_radius_priv_lock));

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V4_ERR,"xxE",ep_evt,epoll_ctx,rx_len);
	return rx_len;
}

static int _rhp_radius_session_recv_pkt_v6(struct epoll_event* ep_evt,rhp_epoll_ctx* epoll_ctx,
		rhp_radius_session* radius_sess,rhp_radius_session_priv* radius_sess_priv)
{
  ssize_t rx_len;
	int i, received = 0;

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V6,"xxLd",ep_evt,epoll_ctx,"MAIN_EOPLL_EVENT",epoll_ctx->event_type);

  RHP_LOCK(&(rhp_radius_priv_lock));

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V6_SK_IDX,"xxddd",ep_evt,epoll_ctx,radius_sess_priv->sk,_rhp_radius_rx_max_packets,_rhp_radius_rx_buf_max_size);

  for( i = 0; i < _rhp_radius_rx_max_packets; i++ ){

  	rhp_packet* pkt = NULL;
  	struct msghdr msg;
		struct iovec iov[1];
		struct sockaddr_in6 peer_sin;
		int buf_len = _rhp_radius_rx_buf_max_size;
		rhp_proto_ether* dmy_ethhdr;
		rhp_proto_ip_v6* dmy_ip6hdr;
		rhp_proto_udp* dmy_udphdr;
		int mesg_len = 0;
		int pkt_offset = 0;
		u8* data_head;

		if( !RHP_PROCESS_IS_ACTIVE() ){
			rx_len = -EINTR;
			RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V6_PROC_NOT_ACTIVE,"xx",ep_evt,epoll_ctx);
			goto error;
		}

		buf_len += sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v6) + sizeof(rhp_proto_udp);
		pkt_offset += sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v6) + sizeof(rhp_proto_udp);

		pkt = rhp_pkt_alloc(buf_len);
		if( pkt == NULL ){
			rx_len = -ENOMEM;
			RHP_BUG("%d",buf_len);
			goto error;
		}

		dmy_ethhdr = (rhp_proto_ether*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ether));
		dmy_ip6hdr = (rhp_proto_ip_v6*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ip_v6));
		dmy_udphdr = (rhp_proto_udp*)_rhp_pkt_push(pkt,sizeof(rhp_proto_udp));

		data_head = pkt->data + pkt_offset;

		msg.msg_name = &peer_sin;
		msg.msg_namelen = sizeof(peer_sin);
		iov[0].iov_base = data_head;
		iov[0].iov_len  = (buf_len - pkt->len);
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		msg.msg_flags = 0;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;

		rx_len = recvmsg(radius_sess_priv->sk,&msg,MSG_TRUNC | MSG_DONTWAIT);
		if( rx_len < 0 ){

			rx_len = -errno;
			RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V6_INVALID_RX_LEN,"xxE",ep_evt,epoll_ctx,rx_len);

			rhp_pkt_unhold(pkt);
			goto error;
		}

		mesg_len = rx_len;

		if( msg.msg_flags & MSG_TRUNC ){

			RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V6_TRUNC_ERR,"xxdd",ep_evt,epoll_ctx,rx_len,_rhp_radius_rx_buf_max_size);

			if( rx_len < rhp_gcfg_radius_max_pkt_len ){
				_rhp_radius_rx_buf_max_size = rx_len;
      }

			rhp_pkt_unhold(pkt);
			continue;
		}

		if( rx_len < (int)sizeof(rhp_proto_radius) ){

			RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V6_INVALID_DNS_PKT_LEN,"xxd",ep_evt,epoll_ctx,rx_len);

			rhp_pkt_unhold(pkt);
			continue;
		}

		pkt->type = RHP_PKT_IPV6_DNS;

		memset(dmy_ethhdr->dst_addr,0,6);
		memset(dmy_ethhdr->src_addr,0,6);
		dmy_ethhdr->protocol = RHP_PROTO_ETH_IPV6;

		dmy_ip6hdr->ver = 6;
		dmy_ip6hdr->priority = 0;
		dmy_ip6hdr->flow_label[0] = 0;
		dmy_ip6hdr->flow_label[1] = 0;
		dmy_ip6hdr->flow_label[2] = 0;
		dmy_ip6hdr->next_header = RHP_PROTO_IP_UDP;
		dmy_ip6hdr->hop_limit = 64;
		dmy_ip6hdr->payload_len = htons(mesg_len + sizeof(rhp_proto_udp));

		memcpy(dmy_ip6hdr->src_addr,peer_sin.sin6_addr.s6_addr,16);
		memcpy(dmy_ip6hdr->dst_addr,radius_sess->nas_addr.addr.v6,16);

		dmy_udphdr->src_port = peer_sin.sin6_port;
		dmy_udphdr->dst_port = radius_sess->nas_addr.port;

		dmy_udphdr->len = htons(mesg_len + sizeof(rhp_proto_udp));

		pkt->l2.raw = (u8*)dmy_ethhdr;
		pkt->l3.raw = (u8*)dmy_ip6hdr;
		pkt->l4.raw = (u8*)dmy_udphdr;

		pkt->app.raw = (u8*)_rhp_pkt_push(pkt,mesg_len);
		if( pkt->app.raw == NULL ){

			RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V6_INVALID_PKT_NO_APP_DATA,"xx",ep_evt,epoll_ctx);

			rhp_pkt_unhold(pkt);
   		continue;
		}

		if( rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_RADIUS] &&
				(!rhp_packet_capture_realm_id || !rhp_packet_capture_realm_id == radius_sess->vpn_realm_id) ){

			_rhp_radius_sess_pcap_write(pkt);
		}

	  if( radius_sess_priv->tx_access_req == NULL ||
	  		radius_sess_priv->tx_access_pkt_ref == NULL ){
			RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V6_INVALID_PKT_NOT_INTERESTED_RESP,"xxdb",ep_evt,epoll_ctx,radius_sess_priv->sk,((rhp_proto_radius*)pkt->app.raw)->id);
			rhp_pkt_unhold(pkt);
   		continue;
	  }

	  if( radius_sess_priv->ipc_txn_id ){
			RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V6_INVALID_PKT_BUSY,"xxdb",ep_evt,epoll_ctx,radius_sess_priv->sk,((rhp_proto_radius*)pkt->app.raw)->id);
			rhp_pkt_unhold(pkt);
   		continue;
	  }

		if( ((rhp_proto_radius*)pkt->app.raw)->id !=
					radius_sess_priv->tx_access_req->get_id(radius_sess_priv->tx_access_req) ){
			RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V6_INVALID_PKT_NOT_INTERESTED_ID,"xxdb",ep_evt,epoll_ctx,radius_sess_priv->sk,((rhp_proto_radius*)pkt->app.raw)->id);
			rhp_pkt_unhold(pkt);
   		continue;
		}

		if( !rhp_radius_session_rx_supported_code(radius_sess->usage,((rhp_proto_radius*)pkt->app.raw)->code) ){
			RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V6_INVALID_PKT_NOT_INTERESTED_CODE,"xxdb",ep_evt,epoll_ctx,radius_sess_priv->sk,((rhp_proto_radius*)pkt->app.raw)->code);
			rhp_pkt_unhold(pkt);
   		continue;
		}


		RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V6_RX_PKT,"xda",pkt,radius_sess_priv->sk,((pkt->l4.raw + ntohs(pkt->l4.udph->len)) - pkt->l2.raw),RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,pkt->l2.raw);

		rx_len = _rhp_radius_rx_dispatch_pkt(pkt,radius_sess);
		if( rx_len ){

			RHP_BUG("%d",rx_len);

			rhp_pkt_unhold(pkt);
			continue;
		}

		received++;
  }

  if( received == 0 ){
  	rx_len = -ENOENT;
  	goto error;
  }

  RHP_UNLOCK(&(rhp_radius_priv_lock));

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V6_RTRN,"xx",ep_evt,epoll_ctx);
	return 0;

error:
	RHP_UNLOCK(&(rhp_radius_priv_lock));

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RECV_PKT_V6_ERR,"xxE",ep_evt,epoll_ctx,rx_len);
	return rx_len;
}



static int _rhp_radius_session_epoll_event_cb(struct epoll_event *ep_evt,rhp_epoll_ctx* epoll_ctx)
{
	int err = -EINVAL;
	rhp_radius_session* radius_sess = NULL;
	rhp_radius_session_priv* radius_sess_priv;

	if( epoll_ctx->event_type != RHP_MAIN_EPOLL_EVENT_RADIUS_RX ){
		RHP_BUG("%d",epoll_ctx->event_type);
		return -EINVAL;
	}

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_EPOLL_EVENT_CB,"xxdxx",ep_evt,epoll_ctx,epoll_ctx->event_type,(rhp_radius_session_ref*)RHP_RADIUS_SESS_EPOLL_CTX_SESS_2(epoll_ctx),RHP_RADIUS_SESS_REF((rhp_radius_session_ref*)RHP_RADIUS_SESS_EPOLL_CTX_SESS_2(epoll_ctx)));

	radius_sess = RHP_RADIUS_SESS_REF((rhp_radius_session_ref*)RHP_RADIUS_SESS_EPOLL_CTX_SESS_2(epoll_ctx));
	if( radius_sess == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}


	RHP_LOCK(&(radius_sess->lock));

  radius_sess_priv = (rhp_radius_session_priv*)radius_sess->priv;

  if( !_rhp_atomic_read(&(radius_sess->is_active)) ){
  	err = RHP_STATUS_RADIUS_INVALID_SESSION;
  	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_EPOLL_EVENT_CB_RADIUS_SESS_NOT_ACTIVE,"xxdx",ep_evt,epoll_ctx,epoll_ctx->event_type,radius_sess);
    goto error;
  }

  if( radius_sess->server_addr_port.addr_family == AF_INET ){

  	err = _rhp_radius_session_recv_pkt_v4(ep_evt,epoll_ctx,radius_sess,radius_sess_priv);

  }else if( radius_sess->server_addr_port.addr_family == AF_INET6 ){

  	err = _rhp_radius_session_recv_pkt_v6(ep_evt,epoll_ctx,radius_sess,radius_sess_priv);

  }else{
  	RHP_BUG("%d",radius_sess->server_addr_port.addr_family);
  	err = -EINVAL;
  }
  if( err ){
  	goto error;
  }

	RHP_UNLOCK(&(radius_sess->lock));

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_EPOLL_EVENT_CB_RTRN,"xxdx",ep_evt,epoll_ctx,epoll_ctx->event_type,radius_sess);
	return 0;

error:
	if( radius_sess ){
		RHP_UNLOCK(&(radius_sess->lock));
	}
	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_EPOLL_EVENT_CB_ERR,"xxdxE",ep_evt,epoll_ctx,epoll_ctx->event_type,radius_sess,err);
	return err;
}


static void _rhp_radius_session_close_sk(int* sk)
{
	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_CLOSE_SK,"xd",sk,*sk);

	if( *sk < 0 ){
		RHP_BUG("");
		return;
	}

	close(*sk);
	*sk = -1;

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_CLOSE_SK_RTRN,"xd",sk,*sk);
	return;
}

static int _rhp_radius_session_open_sk(rhp_radius_session* radius_sess)
{
	int err = -EINVAL;
	rhp_radius_session_priv* radius_sess_priv = (rhp_radius_session_priv*)radius_sess->priv;
  int radius_sess_sk = -1;
  union {
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
    unsigned char raw;
  } dst_sin;
  socklen_t dst_sa_len = 0;
  union {
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
    unsigned char raw;
  } my_sin;
  socklen_t my_sin_len;

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_OPEN_SK,"xxs",radius_sess,radius_sess_priv,radius_sess->server_fqdn);
	rhp_ip_addr_dump("radius_sess->server_addr_port",&(radius_sess->server_addr_port));
	rhp_ip_addr_dump("radius_sess->nas_addr",&(radius_sess->nas_addr));


  if( radius_sess_priv->sk >= 0 ){
  	RHP_BUG("%d",radius_sess_priv->sk);
  	return -EINVAL;
  }


  radius_sess_sk = socket(radius_sess->server_addr_port.addr_family,SOCK_DGRAM,0);
  if( radius_sess_sk < 0 ){
    err = -errno;
    RHP_BUG("%d",err);
    goto error;
  }


  //
  // [CAUTION]
  //  O_NONBLOCK is NOT set because MSG_DONTWAIT is set with recvmsg().
  //

  if( !rhp_ip_addr_null(&(radius_sess->nas_addr)) ){

		if( radius_sess->server_addr_port.addr_family == AF_INET ){

			my_sin.v4.sin_family = AF_INET;
			my_sin.v4.sin_port = radius_sess->nas_addr.port;
			my_sin.v4.sin_addr.s_addr = radius_sess->nas_addr.addr.v4;
			my_sin_len = sizeof(struct sockaddr_in);

			RHP_TRC(0,RHPTRCID_RADIUS_SESSION_OPEN_SK_BIND_MY_ADDR_V4,"xxd4Wp",radius_sess,radius_sess_priv,radius_sess_sk,my_sin.v4.sin_addr.s_addr,my_sin.v4.sin_port,sizeof(my_sin),&my_sin);

		}else if( radius_sess->server_addr_port.addr_family == AF_INET6 ){

			my_sin.v6.sin6_family = AF_INET6;
			my_sin.v6.sin6_port = radius_sess->nas_addr.port;
			my_sin.v6.sin6_flowinfo = 0;
			memcpy(my_sin.v6.sin6_addr.s6_addr,radius_sess->nas_addr.addr.v6,16);
			my_sin.v6.sin6_scope_id = 0;
			my_sin_len = sizeof(struct sockaddr_in6);

			RHP_TRC(0,RHPTRCID_RADIUS_SESSION_OPEN_SK_BIND_MY_ADDR_V6,"xxd6Wp",radius_sess,radius_sess_priv,radius_sess_sk,my_sin.v6.sin6_addr.s6_addr,my_sin.v4.sin_port,sizeof(my_sin),&my_sin);
		}


		err = bind(radius_sess_sk,(struct sockaddr*)&my_sin,my_sin_len);
		if( err < 0 ){
			err = -errno;
			RHP_TRC(0,RHPTRCID_RADIUS_SESSION_OPEN_SK_BIND_MY_ADDR_ERR,"xxdE",radius_sess,radius_sess_priv,radius_sess_sk,err);
			goto error;
		}
  }


	if( radius_sess->server_addr_port.addr_family == AF_INET ){

		dst_sin.v4.sin_family = AF_INET;
		dst_sin.v4.sin_port = radius_sess->server_addr_port.port;
		dst_sin.v4.sin_addr.s_addr = radius_sess->server_addr_port.addr.v4;
		dst_sa_len = sizeof(struct sockaddr_in);

		RHP_TRC(0,RHPTRCID_RADIUS_SESSION_OPEN_SK_CONNECT_DST_ADDR_V4,"xxd4Wp",radius_sess,radius_sess_priv,radius_sess_sk,dst_sin.v4.sin_addr.s_addr,dst_sin.v4.sin_port,sizeof(dst_sin),&dst_sin);

	}else if( radius_sess->server_addr_port.addr_family == AF_INET6 ){

		dst_sin.v6.sin6_family = AF_INET6;
		dst_sin.v6.sin6_port = radius_sess->server_addr_port.port;
		dst_sin.v6.sin6_flowinfo = 0;
		memcpy(dst_sin.v6.sin6_addr.s6_addr,radius_sess->server_addr_port.addr.v6,16);
		dst_sin.v6.sin6_scope_id = 0;
		dst_sa_len = sizeof(struct sockaddr_in6);

		RHP_TRC(0,RHPTRCID_RADIUS_SESSION_OPEN_SK_CONNECT_DST_ADDR_V6,"xxd6Wp",radius_sess,radius_sess_priv,radius_sess_sk,dst_sin.v6.sin6_addr.s6_addr,dst_sin.v6.sin6_port,sizeof(dst_sin),&dst_sin);
	}

	err = connect(radius_sess_sk,(struct sockaddr*)&dst_sin,dst_sa_len);
	if( err < 0 ){
		err = -errno;
		RHP_TRC(0,RHPTRCID_RADIUS_SESSION_OPEN_SK_CONNECT_ERR,"xxdE",radius_sess,radius_sess_priv,radius_sess_sk,err);
		goto error;
	}


	if( radius_sess->server_addr_port.addr_family == AF_INET ){

		my_sin.v4.sin_family = AF_INET;
		my_sin_len = sizeof(struct sockaddr_in);

	}else if( radius_sess->server_addr_port.addr_family == AF_INET6 ){

		my_sin.v6.sin6_family = AF_INET6;
		my_sin_len = sizeof(struct sockaddr_in6);
	}

  if( getsockname(radius_sess_sk,(struct sockaddr*)&(my_sin.raw),&my_sin_len) < 0 ){
    err = -errno;
		RHP_TRC(0,RHPTRCID_RADIUS_SESSION_OPEN_SK_GET_SOCK_NAME_ERR,"xxdE",radius_sess,radius_sess_priv,radius_sess_sk,err);
    goto error;
  }

	if( radius_sess->server_addr_port.addr_family == AF_INET ){

		radius_sess->nas_addr.addr_family = AF_INET;
		radius_sess->nas_addr.addr.v4 = my_sin.v4.sin_addr.s_addr;
		radius_sess->nas_addr.port = my_sin.v4.sin_port;

		RHP_TRC(0,RHPTRCID_RADIUS_SESSION_OPEN_SK_BOUND_MY_ADDR_V4,"xxd4W",radius_sess,radius_sess_priv,radius_sess_sk,radius_sess->nas_addr.addr.v4,radius_sess->nas_addr.port);

	}else if( radius_sess->server_addr_port.addr_family == AF_INET6 ){

		radius_sess->nas_addr.addr_family = AF_INET6;
		memcpy(radius_sess->nas_addr.addr.v6,my_sin.v6.sin6_addr.s6_addr,16);
		radius_sess->nas_addr.port = my_sin.v6.sin6_port;

		RHP_TRC(0,RHPTRCID_RADIUS_SESSION_OPEN_SK_BOUND_MY_ADDR_V6,"xxd6W",radius_sess,radius_sess_priv,radius_sess_sk,radius_sess->nas_addr.addr.v6,radius_sess->nas_addr.port);
	}


	radius_sess_priv->epoll_ctx.event_type = RHP_MAIN_EPOLL_EVENT_RADIUS_RX;
  RHP_RADIUS_SESS_EPOLL_CTX_SESS(radius_sess_priv) = (unsigned long)rhp_radius_sess_hold_ref(radius_sess);

	radius_sess_priv->sk = radius_sess_sk;

  RHP_LOG_D(RHP_LOG_SRC_IKEV2,(radius_sess ? radius_sess->vpn_realm_id : 0),RHP_LOG_ID_RADIUS_OPEN_SOCKET,"r",radius_sess);

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_OPEN_SK_RTRN,"xxd",radius_sess,radius_sess_priv,radius_sess_priv->sk);
	return 0;

error:
  RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(radius_sess ? radius_sess->vpn_realm_id : 0),RHP_LOG_ID_RADIUS_OPEN_SOCKET_ERR,"rE",radius_sess,err);

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_OPEN_SK_ERR,"xxdE",radius_sess,radius_sess_priv,radius_sess_priv->sk,err);
	return err;
}


static int _rhp_radius_session_send_access_request_add_attrs(
		rhp_radius_session* radius_sess,rhp_radius_session_priv* radius_sess_priv,
		rhp_radius_mesg* tx_radius_mesg,rhp_radius_mesg_priv* tx_radius_mesg_priv)
{
	int err = -EINVAL;
	rhp_radius_attr* tx_radius_attr = NULL;

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SEND_ACCESS_REQUEST_ADD_ATTRS,"xxxx",radius_sess,radius_sess_priv,tx_radius_mesg,tx_radius_mesg_priv);

	if( radius_sess->connect_info ){

		err = rhp_radius_new_attr_tx(radius_sess,tx_radius_mesg,
						RHP_RADIUS_ATTR_TYPE_CONNECT_INFO,0,&tx_radius_attr);
		if( err ){
			goto error;
		}

		tx_radius_mesg->put_attr_head(tx_radius_mesg,tx_radius_attr);

		err = tx_radius_attr->ext.basic->set_attr_value(tx_radius_attr,
						strlen(radius_sess->connect_info),(u8*)radius_sess->connect_info);
		if( err ){
			goto error;
		}

	  RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_ATTR_CONNECT_INFO_TX,"rLLs",radius_sess,"RADIUS_CODE",(int)tx_radius_mesg->get_code(tx_radius_mesg),"RADIUS_ATTR",(int)tx_radius_attr->get_attr_type(tx_radius_attr),radius_sess->connect_info);
	}


	if( radius_sess->inc_nas_port_type ){

		u32 port_type = htonl(RHP_RADIUS_ATTR_TYPE_NAS_PORT_TYPE_VIRTUAL);

		err = rhp_radius_new_attr_tx(radius_sess,tx_radius_mesg,
						RHP_RADIUS_ATTR_TYPE_NAS_PORT_TYPE,0,&tx_radius_attr);
		if( err ){
			goto error;
		}

		tx_radius_mesg->put_attr_head(tx_radius_mesg,tx_radius_attr);

		err = tx_radius_attr->ext.basic->set_attr_value(tx_radius_attr,
						sizeof(u32),(u8*)&port_type);
		if( err ){
			goto error;
		}

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_ATTR_NAS_PORT_TYPE_TX,"rLLd",radius_sess,"RADIUS_CODE",(int)tx_radius_mesg->get_code(tx_radius_mesg),"RADIUS_ATTR",(int)tx_radius_attr->get_attr_type(tx_radius_attr),RHP_RADIUS_ATTR_TYPE_NAS_PORT_TYPE_VIRTUAL);
	}


	if( radius_sess->framed_mtu ){

		u32 mtu = htonl(radius_sess->framed_mtu);

		err = rhp_radius_new_attr_tx(radius_sess,tx_radius_mesg,
						RHP_RADIUS_ATTR_TYPE_FRAMED_MTU,0,&tx_radius_attr);
		if( err ){
			goto error;
		}

		tx_radius_mesg->put_attr_head(tx_radius_mesg,tx_radius_attr);

		err = tx_radius_attr->ext.basic->set_attr_value(tx_radius_attr,
						sizeof(u32),(u8*)&mtu);
		if( err ){
			goto error;
		}

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_ATTR_FRAMED_MTU_TX,"rLLd",radius_sess,"RADIUS_CODE",(int)tx_radius_mesg->get_code(tx_radius_mesg),"RADIUS_ATTR",(int)tx_radius_attr->get_attr_type(tx_radius_attr),radius_sess->framed_mtu);
	}


	if( radius_sess->calling_station_id ){

		err = rhp_radius_new_attr_tx(radius_sess,tx_radius_mesg,
						RHP_RADIUS_ATTR_TYPE_CALLING_STATION_ID,0,&tx_radius_attr);
		if( err ){
			goto error;
		}

		tx_radius_mesg->put_attr_head(tx_radius_mesg,tx_radius_attr);

		err = tx_radius_attr->ext.basic->set_attr_value(tx_radius_attr,
						strlen(radius_sess->calling_station_id),(u8*)radius_sess->calling_station_id);
		if( err ){
			goto error;
		}

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_ATTR_CALLING_STATION_ID_TX,"rLLs",radius_sess,"RADIUS_CODE",(int)tx_radius_mesg->get_code(tx_radius_mesg),"RADIUS_ATTR",(int)tx_radius_attr->get_attr_type(tx_radius_attr),radius_sess->calling_station_id);
	}


	if( radius_sess->nas_addr.addr_family == AF_INET ){

		err = rhp_radius_new_attr_tx(radius_sess,tx_radius_mesg,
						RHP_RADIUS_ATTR_TYPE_NAS_IP_ADDRESS,0,&tx_radius_attr);
		if( err ){
			goto error;
		}

		tx_radius_mesg->put_attr_head(tx_radius_mesg,tx_radius_attr);

		err = tx_radius_attr->ext.basic->set_attr_value(tx_radius_attr,
						4,(u8*)radius_sess->nas_addr.addr.raw);
		if( err ){
			goto error;
		}

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_ATTR_NAS_IP_ADDRESS_TX,"rLL4",radius_sess,"RADIUS_CODE",(int)tx_radius_mesg->get_code(tx_radius_mesg),"RADIUS_ATTR",(int)tx_radius_attr->get_attr_type(tx_radius_attr),radius_sess->nas_addr.addr.v4);

	}else if( radius_sess->nas_addr.addr_family == AF_INET6 ){

		err = rhp_radius_new_attr_tx(radius_sess,tx_radius_mesg,
						RHP_RADIUS_ATTR_TYPE_NAS_IPV6_ADDRESS,0,&tx_radius_attr);
		if( err ){
			goto error;
		}

		tx_radius_mesg->put_attr_head(tx_radius_mesg,tx_radius_attr);

		err = tx_radius_attr->ext.basic->set_attr_value(tx_radius_attr,
						16,(u8*)radius_sess->nas_addr.addr.raw);
		if( err ){
			goto error;
		}

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_ATTR_NAS_IPV6_ADDRESS_TX,"rLL6",radius_sess,"RADIUS_CODE",(int)tx_radius_mesg->get_code(tx_radius_mesg),"RADIUS_ATTR",(int)tx_radius_attr->get_attr_type(tx_radius_attr),radius_sess->nas_addr.addr.v6);
	}

	if( radius_sess->nas_id ){

		err = rhp_radius_new_attr_tx(radius_sess,tx_radius_mesg,
						RHP_RADIUS_ATTR_TYPE_NAS_ID,0,&tx_radius_attr);
		if( err ){
			goto error;
		}

		tx_radius_mesg->put_attr_head(tx_radius_mesg,tx_radius_attr);

		err = tx_radius_attr->ext.basic->set_attr_value(tx_radius_attr,
						strlen(radius_sess->nas_id),(u8*)radius_sess->nas_id);
		if( err ){
			goto error;
		}

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_ATTR_NAS_ID_TX,"rLLs",radius_sess,"RADIUS_CODE",(int)tx_radius_mesg->get_code(tx_radius_mesg),"RADIUS_ATTR",(int)tx_radius_attr->get_attr_type(tx_radius_attr),radius_sess->nas_id);

	}else if( radius_sess->inc_nas_id_as_ikev2_id &&
						radius_sess->gateway_id.type != RHP_PROTO_IKE_ID_ANY &&
						!rhp_ikev2_is_null_auth_id(radius_sess->gateway_id.type) ){

		char *id_type,*id_str;
		int id_str_len;

		err = rhp_ikev2_id_to_string(&(radius_sess->gateway_id),&id_type,&id_str);
		if( err ){
      RHP_BUG("");
      goto error;
		}
		id_str_len = strlen(id_str);
		if( id_str_len > RHP_RADIUS_ATTR_VAL_MAX_LEN ){
			id_str_len = RHP_RADIUS_ATTR_VAL_MAX_LEN;
		}

		err = rhp_radius_new_attr_tx(radius_sess,tx_radius_mesg,
						RHP_RADIUS_ATTR_TYPE_NAS_ID,0,&tx_radius_attr);
		if( err ){
			_rhp_free(id_type);
			_rhp_free(id_str);
			goto error;
		}

		tx_radius_mesg->put_attr_head(tx_radius_mesg,tx_radius_attr);

		err = tx_radius_attr->ext.basic->set_attr_value(tx_radius_attr,
						id_str_len,(u8*)id_str);
		if( err ){
			_rhp_free(id_type);
			_rhp_free(id_str);
			goto error;
		}

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_ATTR_NAS_ID_TX,"rLLs",radius_sess,"RADIUS_CODE",(int)tx_radius_mesg->get_code(tx_radius_mesg),"RADIUS_ATTR",(int)tx_radius_attr->get_attr_type(tx_radius_attr),id_str);

		_rhp_free(id_type);
		_rhp_free(id_str);
	}


	if( radius_sess->user_name == NULL ){

		rhp_radius_attr* radius_attr_eap
			= tx_radius_mesg->get_attr_eap(tx_radius_mesg,RHP_PROTO_EAP_CODE_RESPONSE,RHP_PROTO_EAP_TYPE_IDENTITY);

		if( radius_attr_eap ){

			rhp_proto_eap_response* eaph;
			int eap_len;

			eaph = (rhp_proto_eap_response*)radius_attr_eap->ext.eap->get_eap_packet(radius_attr_eap,&eap_len);
			if( eaph ){

				eap_len = ntohs(eaph->len);
				if( eap_len >= sizeof(rhp_proto_eap_response) + 1 ){

					eap_len -= sizeof(rhp_proto_eap_response);

					radius_sess->user_name = (char*)_rhp_malloc(eap_len + 1);
					if( radius_sess->user_name == NULL ){
						RHP_BUG("");
						err = -ENOMEM;
					}

					memcpy(radius_sess->user_name,(eaph + 1),eap_len);
					radius_sess->user_name[eap_len] = '\0';
				}
			}
		}
	}

	if( radius_sess->user_name ){

		err = rhp_radius_new_attr_tx(radius_sess,tx_radius_mesg,
						RHP_RADIUS_ATTR_TYPE_USER_NAME,0,&tx_radius_attr);
		if( err ){
			goto error;
		}

		tx_radius_mesg->put_attr_head(tx_radius_mesg,tx_radius_attr);

		err = tx_radius_attr->ext.basic->set_attr_value(tx_radius_attr,
						strlen(radius_sess->user_name),(u8*)radius_sess->user_name);
		if( err ){
			goto error;
		}

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_ATTR_USER_NAME_TX,"rLLs",radius_sess,"RADIUS_CODE",(int)tx_radius_mesg->get_code(tx_radius_mesg),"RADIUS_ATTR",(int)tx_radius_attr->get_attr_type(tx_radius_attr),radius_sess->user_name);
	}


	if( radius_sess->acct_session_id ){

		err = rhp_radius_new_attr_tx(radius_sess,tx_radius_mesg,
				RHP_RADIUS_ATTR_TYPE_ACCT_SESSION_ID,0,&tx_radius_attr);
		if( err ){
			goto error;
		}

		tx_radius_mesg->put_attr(tx_radius_mesg,tx_radius_attr);

		err = tx_radius_attr->ext.basic->set_attr_value(tx_radius_attr,
						strlen(radius_sess->acct_session_id),(u8*)radius_sess->acct_session_id);
		if( err ){
			goto error;
		}

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_ATTR_ACCT_SESSION_ID_TX,"rLLs",radius_sess,"RADIUS_CODE",(int)tx_radius_mesg->get_code(tx_radius_mesg),"RADIUS_ATTR",(int)tx_radius_attr->get_attr_type(tx_radius_attr),radius_sess->acct_session_id);
	}


	if( radius_sess_priv->rx_attr_state ){

		err = rhp_radius_new_attr_tx(radius_sess,tx_radius_mesg,
						RHP_RADIUS_ATTR_TYPE_STATE,0,&tx_radius_attr);
		if( err ){
			goto error;
		}

		tx_radius_mesg->put_attr(tx_radius_mesg,tx_radius_attr);

		err = tx_radius_attr->ext.basic->set_attr_value(tx_radius_attr,
						radius_sess_priv->rx_attr_state_len,radius_sess_priv->rx_attr_state);
		if( err ){
			goto error;
		}

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_ATTR_STATE_TX,"rLLp",radius_sess,"RADIUS_CODE",(int)tx_radius_mesg->get_code(tx_radius_mesg),"RADIUS_ATTR",(int)tx_radius_attr->get_attr_type(tx_radius_attr),radius_sess_priv->rx_attr_state_len,radius_sess_priv->rx_attr_state);
	}

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SEND_ACCESS_REQUEST_ADD_ATTRS_RTRN,"xxxx",radius_sess,radius_sess_priv,tx_radius_mesg,tx_radius_mesg_priv);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SEND_ACCESS_REQUEST_ADD_ATTRS_ERR,"xxxxE",radius_sess,radius_sess_priv,tx_radius_mesg,tx_radius_mesg_priv,err);
	return err;
}

static int _rhp_radius_session_send_acct_request_add_attrs(
		rhp_radius_session* radius_sess,rhp_radius_session_priv* radius_sess_priv,
		rhp_radius_mesg* tx_radius_mesg,rhp_radius_mesg_priv* tx_radius_mesg_priv)
{
	int err = -EINVAL;
	rhp_radius_attr* tx_radius_attr = NULL;

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SEND_ACCT_REQUEST_ADD_ATTRS,"xxxx",radius_sess,radius_sess_priv,tx_radius_mesg,tx_radius_mesg_priv);

	if( radius_sess->connect_info ){

		err = rhp_radius_new_attr_tx(radius_sess,tx_radius_mesg,
						RHP_RADIUS_ATTR_TYPE_CONNECT_INFO,0,&tx_radius_attr);
		if( err ){
			goto error;
		}

		tx_radius_mesg->put_attr_head(tx_radius_mesg,tx_radius_attr);

		err = tx_radius_attr->ext.basic->set_attr_value(tx_radius_attr,
						strlen(radius_sess->connect_info),(u8*)radius_sess->connect_info);
		if( err ){
			goto error;
		}

	  RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_ACCT_ATTR_CONNECT_INFO_TX,"rLLs",radius_sess,"RADIUS_CODE",(int)tx_radius_mesg->get_code(tx_radius_mesg),"RADIUS_ATTR",(int)tx_radius_attr->get_attr_type(tx_radius_attr),radius_sess->connect_info);
	}


	if( radius_sess->inc_nas_port_type ){

		u32 port_type = htonl(RHP_RADIUS_ATTR_TYPE_NAS_PORT_TYPE_VIRTUAL);

		err = rhp_radius_new_attr_tx(radius_sess,tx_radius_mesg,
						RHP_RADIUS_ATTR_TYPE_NAS_PORT_TYPE,0,&tx_radius_attr);
		if( err ){
			goto error;
		}

		tx_radius_mesg->put_attr_head(tx_radius_mesg,tx_radius_attr);

		err = tx_radius_attr->ext.basic->set_attr_value(tx_radius_attr,
						sizeof(u32),(u8*)&port_type);
		if( err ){
			goto error;
		}

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_ACCT_ATTR_NAS_PORT_TYPE_TX,"rLLd",radius_sess,"RADIUS_CODE",(int)tx_radius_mesg->get_code(tx_radius_mesg),"RADIUS_ATTR",(int)tx_radius_attr->get_attr_type(tx_radius_attr),RHP_RADIUS_ATTR_TYPE_NAS_PORT_TYPE_VIRTUAL);
	}


	if( radius_sess->nas_addr.addr_family == AF_INET ){

		err = rhp_radius_new_attr_tx(radius_sess,tx_radius_mesg,
						RHP_RADIUS_ATTR_TYPE_NAS_IP_ADDRESS,0,&tx_radius_attr);
		if( err ){
			goto error;
		}

		tx_radius_mesg->put_attr_head(tx_radius_mesg,tx_radius_attr);

		err = tx_radius_attr->ext.basic->set_attr_value(tx_radius_attr,
						4,(u8*)radius_sess->nas_addr.addr.raw);
		if( err ){
			goto error;
		}

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_ACCT_ATTR_NAS_IP_ADDRESS_TX,"rLL4",radius_sess,"RADIUS_CODE",(int)tx_radius_mesg->get_code(tx_radius_mesg),"RADIUS_ATTR",(int)tx_radius_attr->get_attr_type(tx_radius_attr),radius_sess->nas_addr.addr.v4);

	}else if( radius_sess->nas_addr.addr_family == AF_INET6 ){

		err = rhp_radius_new_attr_tx(radius_sess,tx_radius_mesg,
						RHP_RADIUS_ATTR_TYPE_NAS_IPV6_ADDRESS,0,&tx_radius_attr);
		if( err ){
			goto error;
		}

		tx_radius_mesg->put_attr_head(tx_radius_mesg,tx_radius_attr);

		err = tx_radius_attr->ext.basic->set_attr_value(tx_radius_attr,
						16,(u8*)radius_sess->nas_addr.addr.raw);
		if( err ){
			goto error;
		}

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_ACCT_ATTR_NAS_IPV6_ADDRESS_TX,"rLL6",radius_sess,"RADIUS_CODE",(int)tx_radius_mesg->get_code(tx_radius_mesg),"RADIUS_ATTR",(int)tx_radius_attr->get_attr_type(tx_radius_attr),radius_sess->nas_addr.addr.v6);
	}

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SEND_ACCT_REQUEST_ADD_ATTRS_RTRN,"xxxx",radius_sess,radius_sess_priv,tx_radius_mesg,tx_radius_mesg_priv);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SEND_ACCT_REQUEST_ADD_ATTRS_ERR,"xxxxE",radius_sess,radius_sess_priv,tx_radius_mesg,tx_radius_mesg_priv,err);
	return err;
}

static int _rhp_radius_session_send_message_impl(rhp_radius_session* radius_sess,
		rhp_radius_mesg* tx_radius_mesg)
{
	int err = -EINVAL;
	rhp_radius_session_priv* radius_sess_priv = (rhp_radius_session_priv*)radius_sess->priv;
	rhp_radius_mesg_priv* tx_radius_mesg_priv = (rhp_radius_mesg_priv*)tx_radius_mesg->priv;
  rhp_packet* tx_pkt = NULL;
  int tx_len;
  u8* tx_buf;
  rhp_ipcmsg_radius_mesg_sign_req* sign_req = NULL;
  u8 code = tx_radius_mesg->get_code(tx_radius_mesg);

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SEND_MESSAGE_IMPL,"xxxxxq",radius_sess,tx_radius_mesg,radius_sess_priv,tx_radius_mesg_priv,radius_sess_priv->tx_access_req,radius_sess_priv->ipc_txn_id);

  if( radius_sess_priv->tx_access_req ){
  	err = -EBUSY;
  	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SEND_MESSAGE_IMPL_PEND_1,"xxxxxq",radius_sess,tx_radius_mesg,radius_sess_priv,tx_radius_mesg_priv,radius_sess_priv->tx_access_req,radius_sess_priv->ipc_txn_id);
  	goto error;
  }

  if( radius_sess_priv->ipc_txn_id ){
  	err = -EBUSY;
  	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SEND_MESSAGE_IMPL_PEND_2,"xxxxxq",radius_sess,tx_radius_mesg,radius_sess_priv,tx_radius_mesg_priv,radius_sess_priv->tx_access_req,radius_sess_priv->ipc_txn_id);
  	goto error;
  }

	if( radius_sess_priv->sk == -1 ){

  	struct epoll_event ep_evt;

  	err = _rhp_radius_session_open_sk(radius_sess);
  	if( err ){
  		goto error;
  	}

  	memset(&ep_evt,0,sizeof(struct epoll_event));
		ep_evt.events = EPOLLIN;
		ep_evt.data.ptr = (void*)&(radius_sess_priv->epoll_ctx);

		if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_ADD,radius_sess_priv->sk,&ep_evt) < 0 ){
			int err2 = -errno;
			RHP_BUG("%d",err2);
			goto error;
		}

  }else{

		RHP_TRC(0,RHPTRCID_RADIUS_MAIN_IPC_MESG_SIGN_HANDLER_SK_IS_ALREADY_OPEN,"xxd",radius_sess,radius_sess_priv,radius_sess_priv->sk);
  }


	if( code == RHP_RADIUS_CODE_ACCESS_REQUEST ){

		err = _rhp_radius_session_send_access_request_add_attrs(
						radius_sess,radius_sess_priv,tx_radius_mesg,tx_radius_mesg_priv);
		if( err ){
			goto error;
		}

	}else if( code == RHP_RADIUS_CODE_ACCT_REQUEST ){

		err = _rhp_radius_session_send_acct_request_add_attrs(
						radius_sess,radius_sess_priv,tx_radius_mesg,tx_radius_mesg_priv);
		if( err ){
			goto error;
		}
	}


  err = tx_radius_mesg_priv->serialize(tx_radius_mesg,radius_sess,&tx_pkt);
  if( err ){
  	goto error;
  }

  tx_len = ntohs(tx_pkt->l4.udph->len) - sizeof(rhp_proto_udp);
  tx_buf = tx_pkt->app.raw;

  radius_sess_priv->tx_access_req = tx_radius_mesg;
  rhp_radius_mesg_hold(tx_radius_mesg);
  radius_sess_priv->tx_access_pkt_ref = rhp_pkt_hold_ref(tx_pkt);



  {
		sign_req = (rhp_ipcmsg_radius_mesg_sign_req*)rhp_ipc_alloc_msg(RHP_IPC_RADIUS_MESG_SIGN_REQUEST,
				sizeof(rhp_ipcmsg_radius_mesg_sign_req) + tx_len);
		if( sign_req == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		sign_req->len = sizeof(rhp_ipcmsg_radius_mesg_sign_req) + tx_len;
		sign_req->mesg_len = tx_len;
		sign_req->txn_id = _rhp_radius_new_ipc_txn_id();
		sign_req->secret_index = radius_sess->secret_index;

		memcpy((u8*)(sign_req + 1),tx_buf,tx_len);

		radius_sess_priv->ipc_txn_id = sign_req->txn_id;
  }


  RHP_LOCK(&(rhp_radius_priv_lock));

  err = _rhp_radius_sess_ipc_put(radius_sess_priv->ipc_txn_id,radius_sess);
  if( err ){
    RHP_UNLOCK(&(rhp_radius_priv_lock));
  	RHP_BUG("%d",err);
  	goto error;
  }

  RHP_UNLOCK(&(rhp_radius_priv_lock));


	if( rhp_ipc_send(RHP_MY_PROCESS,(void*)sign_req,sign_req->len,0) < 0 ){
		RHP_BUG("");
  }

	rhp_pkt_unhold(tx_pkt);

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SEND_MESSAGE_IMPL_RTRN,"xx",radius_sess,tx_radius_mesg);
	return 0;

error:
	if( tx_pkt ){
		rhp_pkt_unhold(tx_pkt);
	}
  if( radius_sess_priv->tx_access_req ){

  	rhp_radius_mesg_unhold(radius_sess_priv->tx_access_req);
  	radius_sess_priv->tx_access_req = NULL;

  	rhp_pkt_unhold(radius_sess_priv->tx_access_pkt_ref);
  	radius_sess_priv->tx_access_pkt_ref = NULL;
  }
  if( sign_req ){
  	_rhp_free_zero(sign_req,sign_req->len);
  }

  if( tx_radius_mesg->get_code(tx_radius_mesg) == RHP_RADIUS_CODE_ACCT_REQUEST ){
  	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(radius_sess ? radius_sess->vpn_realm_id : 0),RHP_LOG_ID_RADIUS_TX_ACCESS_REQUEST_ERR,"r",radius_sess);
  }

  RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SEND_MESSAGE_IMPL_ERR,"xxxxE",radius_sess,tx_radius_mesg,radius_sess_priv->tx_access_req,radius_sess_priv->tx_access_pkt_ref,err);
	return err;
}

static void _rhp_radius_session_dns_rslv_cb(void* cb_ctx0,void* cb_ctx1,
		int cb_err,int res_addrs_num,rhp_ip_addr* res_addrs)
{
	int err = -EINVAL;
	rhp_radius_session* radius_sess = RHP_RADIUS_SESS_REF((rhp_radius_session_ref*)cb_ctx0);
	rhp_radius_mesg* tx_radius_mesg	= (rhp_radius_mesg*)cb_ctx1;
	rhp_radius_session_priv* radius_sess_priv = NULL;
	void* cb_ctx = NULL;

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_DNS_RSLV_CB,"xxE",radius_sess,tx_radius_mesg,cb_err);


	RHP_LOCK(&(radius_sess->lock));

	if( !_rhp_atomic_read(&(radius_sess->is_active)) ){
		RHP_UNLOCK(&(radius_sess->lock));
		RHP_TRC(0,RHPTRCID_RADIUS_SESSION_DNS_RSLV_CB_RADIUS_SESS_NOT_ACTIVE,"xxE",radius_sess,tx_radius_mesg,cb_err);
		err = -EINVAL;
		goto error;
	}

	radius_sess_priv = (rhp_radius_session_priv*)radius_sess->priv;
	cb_ctx = radius_sess_priv->cb_ctx;


	if( !cb_err ){

		if( res_addrs_num < 1 ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		radius_sess->server_addr_port.addr_family = res_addrs[0].addr_family;
		memcpy(radius_sess->server_addr_port.addr.raw,res_addrs[0].addr.raw,16);


		if( !rhp_ip_addr_null(&(radius_sess->nas_addr)) &&
				radius_sess->server_addr_port.addr_family != radius_sess->nas_addr.addr_family ){

			RHP_UNLOCK(&(radius_sess->lock));

			err = -EINVAL;
			RHP_BUG("%d, %d",radius_sess->server_addr_port.addr_family,radius_sess->nas_addr.addr_family);
			goto error;
		}

		rhp_ip_addr_dump("dns_rslv_cb",&(radius_sess->server_addr_port));

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_RESOLVE_SERVER_ADDR,"sAr",radius_sess->server_fqdn,&(res_addrs[0]),radius_sess);

		err = _rhp_radius_session_send_message_impl(radius_sess,tx_radius_mesg);
		if( err ){
			RHP_UNLOCK(&(radius_sess->lock));
			goto error;
		}

		err = 0;

	}else{

	  RHP_LOG_DE(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_RESOLVE_SERVER_ADDR_ERR,"srE",radius_sess->server_fqdn,radius_sess,cb_err);
	}


error:
	RHP_UNLOCK(&(radius_sess->lock));


	if( radius_sess_priv && (err || cb_err) ){ // If radius_sess is not active, radius_sess_priv is NULL.

		radius_sess_priv->error_cb(radius_sess,cb_ctx,tx_radius_mesg,
				(cb_err ? (cb_err == -ENOENT ? RHP_STATUS_DNS_RSLV_ERR : cb_err) : err));
	}

	rhp_radius_sess_unhold((rhp_radius_session_ref*)cb_ctx0);
	if( tx_radius_mesg ){
		rhp_radius_mesg_unhold(tx_radius_mesg);
	}

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_DNS_RSLV_CB_RTRN,"xxEE",radius_sess,tx_radius_mesg,cb_err,err);
	return;
}


static int _rhp_radius_session_send_message(rhp_radius_session* radius_sess,
		rhp_radius_mesg* tx_radius_mesg)
{
	int err = -EINVAL;
	rhp_radius_session_priv* radius_sess_priv = (rhp_radius_session_priv*)radius_sess->priv;
	rhp_radius_mesg_priv* tx_radius_mesg_priv = (rhp_radius_mesg_priv*)tx_radius_mesg->priv;

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SEND_MESSAGE,"xxxxxqd",radius_sess,tx_radius_mesg,radius_sess_priv,tx_radius_mesg_priv,radius_sess_priv->tx_access_req,radius_sess_priv->ipc_txn_id,radius_sess_priv->sk);

  if( radius_sess_priv->tx_access_req ){
  	err = -EBUSY;
  	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SEND_MESSAGE_PEND_1,"xxxxxq",radius_sess,tx_radius_mesg,radius_sess_priv,tx_radius_mesg_priv,radius_sess_priv->tx_access_req,radius_sess_priv->ipc_txn_id);
  	goto error;
  }

  if( radius_sess_priv->ipc_txn_id ){
  	err = -EBUSY;
  	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SEND_MESSAGE_PEND_2,"xxxxxq",radius_sess,tx_radius_mesg,radius_sess_priv,tx_radius_mesg_priv,radius_sess_priv->tx_access_req,radius_sess_priv->ipc_txn_id);
  	goto error;
  }

	if( radius_sess_priv->sk == -1 ){

		if( rhp_ip_addr_null(&(radius_sess->server_addr_port)) ){

			if( radius_sess->server_fqdn ){

				rhp_radius_session_ref* radius_sess_ref = NULL;
				int addr_family = AF_UNSPEC;


				radius_sess_ref = rhp_radius_sess_hold_ref(radius_sess);
				rhp_radius_mesg_hold(tx_radius_mesg);


				if( !rhp_ip_addr_null(&(radius_sess->nas_addr)) ){
					addr_family = radius_sess->nas_addr.addr_family;
				}


				err = rhp_dns_resolve(RHP_WTS_DISP_LEVEL_HIGH_2,radius_sess->server_fqdn,addr_family,
						_rhp_radius_session_dns_rslv_cb,radius_sess_ref,tx_radius_mesg);

				if( err ){

					rhp_radius_sess_unhold(radius_sess_ref);
					rhp_radius_mesg_unhold(tx_radius_mesg);

					RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SEND_MESSAGE_DNS_RSLV_ERR,"xxxxsE",radius_sess,tx_radius_mesg,radius_sess_priv,tx_radius_mesg_priv,radius_sess->server_fqdn,err);
					goto error;
				}

				goto pending;
			}

			err = -EINVAL;
			goto error;
		}
	}

	err = _rhp_radius_session_send_message_impl(radius_sess,tx_radius_mesg);
	if( err ){
		goto error;
	}

pending:
	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SEND_MESSAGE_RTRN,"xxxx",radius_sess,tx_radius_mesg,radius_sess_priv,tx_radius_mesg_priv);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SEND_MESSAGE_ERR,"xxxxE",radius_sess,tx_radius_mesg,radius_sess_priv->tx_access_req,radius_sess_priv->tx_access_pkt_ref,err);
	return err;
}

static void _rhp_radius_session_free(rhp_radius_session* radius_sess)
{
	rhp_radius_session_priv* radius_sess_priv = (rhp_radius_session_priv*)radius_sess->priv;

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_FREE,"xx",radius_sess,radius_sess_priv);

	if( radius_sess_priv->tx_access_req ){
		rhp_radius_mesg_hold(radius_sess_priv->tx_access_req);
	}

	if( radius_sess_priv->tx_access_pkt_ref ){
		rhp_pkt_unhold(radius_sess_priv->tx_access_pkt_ref);
	}

	if( radius_sess_priv->rx_pend_pkt_ref ){
		rhp_pkt_unhold(radius_sess_priv->rx_pend_pkt_ref);
	}

	if( rhp_timer_pending(&(radius_sess_priv->retx_timer)) ){
		RHP_BUG("0x%x, 0x%x",radius_sess,radius_sess_priv);
	}

	if( radius_sess_priv->rx_attr_state ){
		_rhp_free_zero(radius_sess_priv->rx_attr_state,radius_sess_priv->rx_attr_state_len);
	}

	if( radius_sess->user_name ){
		_rhp_free(radius_sess->user_name);
	}

	if( radius_sess->nas_id ){
		_rhp_free(radius_sess->nas_id);
	}

	if( radius_sess->calling_station_id ){
		_rhp_free(radius_sess->calling_station_id);
	}

	if( radius_sess->connect_info ){
		_rhp_free(radius_sess->connect_info);
	}

	if( radius_sess->acct_session_id ){
		_rhp_free(radius_sess->acct_session_id);
	}

  if( radius_sess_priv->msk ){
  	_rhp_free_zero(radius_sess_priv->msk,radius_sess_priv->msk_len);
  }

  _rhp_atomic_destroy(&(radius_sess->refcnt));
  _rhp_atomic_destroy(&(radius_sess->is_active));
  _rhp_mutex_destroy(&(radius_sess->lock));

  _rhp_free_zero(radius_sess_priv,sizeof(rhp_radius_session_priv));
  _rhp_free_zero(radius_sess,sizeof(rhp_radius_session));

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_FREE_RTRN,"xx",radius_sess,radius_sess_priv);
  return;
}

void rhp_radius_session_free(rhp_radius_session* radius_sess)
{
	_rhp_radius_session_free(radius_sess);
}



static void _rhp_radius_session_retx_timer(void *ctx,rhp_timer *timer)
{
	int err = -EINVAL;
	rhp_radius_session* radius_sess = RHP_RADIUS_SESS_REF((rhp_radius_session_ref*)ctx);
	rhp_radius_session_priv* radius_sess_priv;
  int tx_len;
  u8* tx_buf;
  rhp_packet* tx_pkt;
  int call_err_cb = 0;
  void* cb_ctx = NULL;
  rhp_radius_mesg* tx_radius_mesg = NULL;

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RETX_TIMER,"xxx",radius_sess,radius_sess->priv,timer);

  RHP_LOCK(&(radius_sess->lock));

  radius_sess_priv = (rhp_radius_session_priv*)radius_sess->priv;

  if( !_rhp_atomic_read(&(radius_sess->is_active)) ){
  	err = RHP_STATUS_RADIUS_INVALID_SESSION;
  	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RETX_TIMER_RADIUS_SESS_NOT_ACTIVE,"xxx",radius_sess,radius_sess->priv,timer);
    goto error;
  }

  if( radius_sess_priv->tx_access_pkt_ref == NULL ){
  	err = 0;
  	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RETX_TIMER_NO_PENDING_REQ_PKT,"xxx",radius_sess,radius_sess->priv,timer);
  	goto error;
  }

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RETX_TIMER_INFO,"xxxddq",radius_sess,radius_sess->priv,timer,radius_sess_priv->retx_counter,radius_sess->retransmit_times,radius_sess_priv->ipc_txn_id);

  call_err_cb = 1;

  if( radius_sess_priv->retx_counter >= radius_sess->retransmit_times ){
  	err = RHP_STATUS_RADIUS_RETX_REQ_ERR;
  	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RETX_TIMER_RETX_MAX_RETRIES_REACHED,"xxx",radius_sess,radius_sess->priv,timer);
  	goto error;
  }

  tx_pkt = RHP_PKT_REF(radius_sess_priv->tx_access_pkt_ref);
  tx_len = ntohs(tx_pkt->l4.udph->len) - sizeof(rhp_proto_udp);
  tx_buf = tx_pkt->app.raw;

  RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_RETRANSMIT_ACCESS_REQUEST,"rRd",radius_sess,radius_sess_priv->tx_access_req,radius_sess_priv->retx_counter,radius_sess->retransmit_times);

  err = send(radius_sess_priv->sk,tx_buf,tx_len,0);
  if( err < 0 ){
  	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RETX_TIMER_RETX_SEND_ERR,"xxxdE",radius_sess,radius_sess->priv,timer,err,-errno);
  	// The packet will be retransmitted later...
  }

  radius_sess_priv->retx_counter++;

  rhp_timer_reset(&(radius_sess_priv->retx_timer));
  rhp_timer_add(&(radius_sess_priv->retx_timer),radius_sess->retransmit_interval);

  err = 0;

  RHP_UNLOCK(&(radius_sess->lock));

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RETX_TIMER_RTRN,"xxx",radius_sess,radius_sess->priv,timer);
	return;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_RETRANSMIT_ACCESS_REQUEST_ERR,"rRddE",radius_sess,radius_sess_priv->tx_access_req,radius_sess_priv->retx_counter,radius_sess->retransmit_times,err);

	{
	  struct epoll_event ep_evt;

		memset(&ep_evt,0,sizeof(struct epoll_event));

		if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_DEL,radius_sess_priv->sk,&ep_evt) < 0 ){

			int err2 = -errno;
			RHP_BUG("%d",err2);

		}else{

			if( RHP_RADIUS_SESS_EPOLL_CTX_SESS(radius_sess_priv) ){
				rhp_radius_sess_unhold((rhp_radius_session*)RHP_RADIUS_SESS_EPOLL_CTX_SESS(radius_sess_priv));
				RHP_RADIUS_SESS_EPOLL_CTX_SESS(radius_sess_priv) = (unsigned long)NULL;
			}
		}

		if( tx_radius_mesg == NULL ){
			tx_radius_mesg = radius_sess_priv->tx_access_req;
			rhp_radius_mesg_hold(tx_radius_mesg);
		}

		rhp_radius_mesg_unhold(radius_sess_priv->tx_access_req);
		radius_sess_priv->tx_access_req = NULL;

		rhp_pkt_unhold(radius_sess_priv->tx_access_pkt_ref);
		radius_sess_priv->tx_access_pkt_ref = NULL;
	}

	cb_ctx = radius_sess_priv->cb_ctx;

	RHP_UNLOCK(&(radius_sess->lock));


	if( err && call_err_cb && _rhp_atomic_read(&(radius_sess->is_active)) ){

		radius_sess_priv->error_cb(radius_sess,cb_ctx,tx_radius_mesg,err);
	}

	rhp_radius_sess_unhold(radius_sess);
	rhp_radius_mesg_unhold(tx_radius_mesg);

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_RETX_TIMER_ERR,"xxxE",radius_sess,radius_sess->priv,timer,err);
	return;
}

static void _rhp_radius_session_set_private_attr_type(rhp_radius_session* radius_sess,
		int rx_attr_type,u8 attr_type_val)
{

	switch( rx_attr_type ){

	case RHP_RADIUS_RX_ATTR_PRIV_REALM_ID:
		radius_sess->priv_attr_type_realm_id = attr_type_val;
		break;
	case RHP_RADIUS_RX_ATTR_PRIV_REALM_ROLE:
		radius_sess->priv_attr_type_realm_role = attr_type_val;
		break;
	case RHP_RADIUS_RX_ATTR_PRIV_USER_INDEX:
		radius_sess->priv_attr_type_user_index = attr_type_val;
		break;
	case RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_ADDR_IPV4:
		radius_sess->priv_attr_type_internal_address_ipv4 = attr_type_val;
		break;
	case RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_ADDR_IPV6:
		radius_sess->priv_attr_type_internal_address_ipv6 = attr_type_val;
		break;
	case RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_DNS_SERVER_IPV4:
		radius_sess->priv_attr_type_internal_dns_server_ipv4 = attr_type_val;
		break;
	case RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_DNS_SERVER_IPV6:
		radius_sess->priv_attr_type_internal_dns_server_ipv6 = attr_type_val;
		break;
	case RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_DOMAIN_NAME:
		radius_sess->priv_attr_type_internal_domain_name = attr_type_val;
		break;
	case RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_ROUTE_IPV4:
		radius_sess->priv_attr_type_internal_route_ipv4 = attr_type_val;
		break;
	case RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_ROUTE_IPV6:
		radius_sess->priv_attr_type_internal_route_ipv6 = attr_type_val;
		break;
	case RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_GATEWAY_IPV4:
		radius_sess->priv_attr_type_internal_gateway_ipv4 = attr_type_val;
		break;
	case RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_GATEWAY_IPV6:
		radius_sess->priv_attr_type_internal_gateway_ipv6 = attr_type_val;
		break;
	case RHP_RADIUS_RX_ATTR_PRIV_COMMON:
		radius_sess->priv_attr_type_common = attr_type_val;
		break;
	}

	return;
}

static unsigned long _rhp_radius_session_get_realm_id(rhp_radius_session* radius_sess)
{
	return radius_sess->vpn_realm_id;
}

static void _rhp_radius_session_set_realm_id(rhp_radius_session* radius_sess,unsigned long vpn_realm_id)
{
	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SET_REALM_ID,"xu",radius_sess,vpn_realm_id);
	radius_sess->vpn_realm_id = vpn_realm_id;
	return;
}

static void _rhp_radius_session_set_peer_notified_realm_id(
		rhp_radius_session* radius_sess,unsigned long peer_notified_realm_id)
{
	radius_sess->peer_notified_realm_id = peer_notified_realm_id;
	return;
}

static unsigned long _rhp_radius_session_get_peer_notified_realm_id(rhp_radius_session* radius_sess)
{
	return radius_sess->peer_notified_realm_id;
}


static int _rhp_radius_session_set_gateway_id(rhp_radius_session* radius_sess,rhp_ikev2_id* gateway_id)
{
	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SET_GATEWAY_ID,"xx",radius_sess,gateway_id);
	if( rhp_ikev2_id_dup(&(radius_sess->gateway_id),gateway_id) ){
		RHP_BUG("");
		return -ENOMEM;
	}
	rhp_ikev2_id_dump("radius_sess_set_gateway_id",&(radius_sess->gateway_id));
	return 0;
}

static rhp_ikev2_id* _rhp_radius_session_get_gateway_id(rhp_radius_session* radius_sess)
{
	return &(radius_sess->gateway_id);
}

static void _rhp_radius_session_set_secret_index(rhp_radius_session* radius_sess,int secret_index)
{
	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_SET_SECRET_INDEX,"xd",radius_sess,secret_index);
	radius_sess->secret_index = secret_index;
	return;
}


static rhp_radius_session* _rhp_radius_session_alloc()
{
	int err = -EINVAL;
	rhp_radius_session* radius_sess;
	rhp_radius_session_priv* radius_sess_priv;

	radius_sess = (rhp_radius_session*)_rhp_malloc(sizeof(rhp_radius_session));
	if( radius_sess == NULL ){
		RHP_BUG("");
		goto error;
	}

	memset(radius_sess,0,sizeof(rhp_radius_session));

	radius_sess_priv = (rhp_radius_session_priv*)_rhp_malloc(sizeof(rhp_radius_session_priv));
	if( radius_sess_priv == NULL ){
		RHP_BUG("");
		_rhp_free(radius_sess);
		radius_sess = NULL;
		goto error;
	}

	memset(radius_sess_priv,0,sizeof(rhp_radius_session_priv));
	radius_sess->priv = radius_sess_priv;

	radius_sess->tag[0] = '#';
	radius_sess->tag[1] = 'R';
	radius_sess->tag[2] = 'D';
	radius_sess->tag[3] = 'S';

	radius_sess_priv->tag[0] = '#';
	radius_sess_priv->tag[1] = 'R';
	radius_sess_priv->tag[2] = 'S';
	radius_sess_priv->tag[3] = 'I';

  _rhp_atomic_init(&(radius_sess->refcnt));
  _rhp_atomic_init(&(radius_sess->is_active));

  _rhp_mutex_init("RDS",&(radius_sess->lock));

  _rhp_atomic_set(&(radius_sess->refcnt),1);

  rhp_timer_init(&(radius_sess_priv->retx_timer),_rhp_radius_session_retx_timer,NULL);


  radius_sess_priv->sk = -1;
  radius_sess_priv->eap_method = RHP_PROTO_EAP_TYPE_NONE;


  radius_sess->set_nas_addr = _rhp_radius_session_set_nas_addr;
  radius_sess->get_nas_addr = _rhp_radius_session_get_nas_addr;
  radius_sess->get_server_addr = _rhp_radius_session_get_server_addr;
  radius_sess->get_server_fqdn = _rhp_radius_session_get_server_fqdn;
  radius_sess->set_user_name = _rhp_radius_session_set_user_name;
  radius_sess->get_user_name = _rhp_radius_session_get_user_name;
  radius_sess->set_nas_id = _rhp_radius_session_set_nas_id;
  radius_sess->include_nas_id_as_ikev2_id = _rhp_radius_session_include_nas_id_as_ikev2_id;
  radius_sess->get_nas_id = _rhp_radius_session_get_nas_id;
  radius_sess->set_calling_station_id = _rhp_radius_session_set_calling_station_id;
  radius_sess->get_calling_station_id = _rhp_radius_session_get_calling_station_id;
  radius_sess->set_connect_info = _rhp_radius_session_set_connect_info;
  radius_sess->get_connect_info = _rhp_radius_session_get_connect_info;
  radius_sess->set_framed_mtu = _rhp_radius_session_set_framed_mtu;
  radius_sess->get_framed_mtu = _rhp_radius_session_get_framed_mtu;
  radius_sess->include_nas_port_type = _rhp_radius_session_include_nas_port_type;
  radius_sess->set_acct_session_id = _rhp_radius_session_set_acct_session_id;
  radius_sess->get_acct_session_id = _rhp_radius_session_get_acct_session_id;
  radius_sess->send_message = _rhp_radius_session_send_message;
  radius_sess->set_retransmit_interval = _rhp_radius_session_set_retransmit_interval;
  radius_sess->set_retransmit_times = _rhp_radius_session_set_retransmit_times;
  radius_sess->get_msk = _rhp_radius_session_get_msk;
  radius_sess->get_eap_method = _rhp_radius_session_get_eap_method;
  radius_sess->set_private_attr_type = _rhp_radius_session_set_private_attr_type;
  radius_sess->set_realm_id = _rhp_radius_session_set_realm_id;
  radius_sess->get_realm_id = _rhp_radius_session_get_realm_id;
  radius_sess->set_gateway_id = _rhp_radius_session_set_gateway_id;
  radius_sess->get_gateway_id = _rhp_radius_session_get_gateway_id;
  radius_sess->set_peer_notified_realm_id = _rhp_radius_session_set_peer_notified_realm_id;
  radius_sess->get_peer_notified_realm_id = _rhp_radius_session_get_peer_notified_realm_id;
  radius_sess->set_secret_index = _rhp_radius_session_set_secret_index;

  radius_sess->retransmit_interval = (time_t)RHP_RADIUS_RETRANSMIT_INTERVAL_DEF;
  radius_sess->retransmit_times = RHP_RADIUS_RETRANSMIT_TIMES_DEF;

  radius_sess->vpn_realm_id = RHP_VPN_REALM_ID_UNKNOWN;
  radius_sess->peer_notified_realm_id = RHP_VPN_REALM_ID_UNKNOWN;
  radius_sess->gateway_id.type = RHP_PROTO_IKE_ID_ANY;

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_ALLOC,"x",radius_sess,radius_sess->priv);
	return radius_sess;

error:
	if( radius_sess ){
		rhp_radius_sess_unhold(radius_sess);
	}
	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_ALLOC_ERR,"E",err);
	return NULL;
}


rhp_radius_session* rhp_radius_session_open(
				int usage, // RHP_RADIUS_USAGE_XXX
				rhp_ip_addr* server_addr_port,
				char* server_fqdn,
				void (*receive_response_cb)(rhp_radius_session* radius_sess,void* cb_ctx,
							rhp_radius_mesg* rx_radius_mesg),
				void (*error_cb)(rhp_radius_session* radius_sess,void* cb_ctx,
						rhp_radius_mesg* tx_radius_mesg,int err),
				void* cb_ctx)
{
	rhp_radius_session* radius_sess;
	rhp_radius_session_priv* radius_sess_priv;
	rhp_ip_addr server_addr_port_dmy;

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_OPEN,"LdxsxYY","RADIUS_USAGE",usage,server_addr_port,server_fqdn,cb_ctx,receive_response_cb,error_cb);
	rhp_ip_addr_dump("server_addr_port",server_addr_port);

	if( (server_addr_port == NULL && server_fqdn == NULL) ||
			receive_response_cb == NULL ||
			error_cb == NULL ){
		RHP_BUG("");
		return NULL;
	}

	if( server_addr_port ){

		if( rhp_ip_addr_null(server_addr_port) && server_fqdn == NULL ){
			RHP_BUG("");
			return NULL;
		}

	}else{

		memset(&server_addr_port_dmy,0,sizeof(rhp_ip_addr));

		server_addr_port = &server_addr_port_dmy;
	}

	if( !server_addr_port->port ){

		if( usage == RHP_RADIUS_USAGE_AUTHENTICATION ){
			server_addr_port->port = htons(RHP_PROTO_PORT_RADIUS);
		}else if( usage == RHP_RADIUS_USAGE_ACCOUNTING ){
			server_addr_port->port = htons(RHP_PROTO_PORT_RADIUS_ACCT);
		}else{
			RHP_BUG("%d",usage);
			return NULL;
		}
	}


	radius_sess = _rhp_radius_session_alloc();
	if( radius_sess == NULL ){
		RHP_BUG("");
		goto error;
	}

	radius_sess->usage = usage;

	radius_sess_priv = (rhp_radius_session_priv*)radius_sess->priv;

	memcpy(&(radius_sess->server_addr_port),server_addr_port,sizeof(rhp_ip_addr));

	if( server_fqdn ){

		radius_sess->server_fqdn = (char*)_rhp_malloc(strlen(server_fqdn) + 1);
		if( radius_sess->server_fqdn == NULL ){
			RHP_BUG("");
			goto error;
		}

		strcpy(radius_sess->server_fqdn,server_fqdn);
	}

	radius_sess_priv->receive_response = receive_response_cb;
	radius_sess_priv->error_cb = error_cb;
	radius_sess_priv->cb_ctx = cb_ctx;


  _rhp_atomic_set(&(radius_sess->is_active),1);

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_OPEN_RTRN,"xx",server_addr_port,radius_sess);
	return radius_sess;

error:
	if( radius_sess ){
		rhp_radius_sess_unhold(radius_sess);
	}
	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_OPEN_ERR,"x",server_addr_port);
	return NULL;
}


int rhp_radius_session_close(rhp_radius_session* radius_sess)
{
	rhp_radius_session_priv* radius_sess_priv = (rhp_radius_session_priv*)radius_sess->priv;
  struct epoll_event ep_evt;

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_CLOSE,"xx",radius_sess,radius_sess_priv);

	if( !_rhp_atomic_read(&(radius_sess->is_active)) ){
		RHP_BUG("");
		return -EINVAL;
	}

  _rhp_atomic_set(&(radius_sess->is_active),0);


	if( !rhp_timer_delete(&(radius_sess_priv->retx_timer)) ){

		rhp_radius_sess_unhold((rhp_radius_session*)(radius_sess_priv->retx_timer.ctx));

	}else{

  	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_CLOSE_TIME_IS_PENDING_OR_DONE_OR_SELFCTX,"xx",radius_sess,radius_sess_priv);
  }

	if( radius_sess_priv->sk != -1 ){

		memset(&ep_evt,0,sizeof(struct epoll_event));

		if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_DEL,radius_sess_priv->sk,&ep_evt) < 0 ){

			int err2 = -errno;
			RHP_BUG("%d",err2);

		}else{

			if( RHP_RADIUS_SESS_EPOLL_CTX_SESS(radius_sess_priv) ){
				rhp_radius_sess_unhold((rhp_radius_session*)RHP_RADIUS_SESS_EPOLL_CTX_SESS(radius_sess_priv));
				RHP_RADIUS_SESS_EPOLL_CTX_SESS(radius_sess_priv) = (unsigned long)NULL;
			}
		}

    _rhp_radius_session_close_sk(&radius_sess_priv->sk);

	}else{

  	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_CLOSE_TIME_TX_REQ_PENDING,"xxx",radius_sess,radius_sess_priv,radius_sess_priv->tx_access_req);
	}

	if( radius_sess_priv->tx_access_req ){
		rhp_radius_mesg_unhold(radius_sess_priv->tx_access_req);
		rhp_pkt_unhold(radius_sess_priv->tx_access_pkt_ref);
		radius_sess_priv->tx_access_req = NULL;
		radius_sess_priv->tx_access_pkt_ref = NULL;
	}

	rhp_radius_sess_unhold(radius_sess);

	RHP_TRC(0,RHPTRCID_RADIUS_SESSION_CLOSE_RTRN,"xx",radius_sess,radius_sess_priv);
  return 0;
}

#ifndef RHP_REFCNT_DEBUG

void rhp_radius_sess_hold(rhp_radius_session* radius_sess)
{
  _rhp_atomic_inc(&(radius_sess->refcnt));
}

rhp_radius_session_ref* rhp_radius_sess_hold_ref(rhp_radius_session* radius_sess)
{
  _rhp_atomic_inc(&(radius_sess->refcnt));
  return radius_sess;
}

void rhp_radius_sess_unhold(rhp_radius_session* radius_sess)
{
#ifdef  RHP_CK_OBJ_TAG_GDB
	radius_sess = RHP_CK_OBJTAG("#RDS",radius_sess);
#endif // RHP_CK_OBJ_TAG_GDB

  if( _rhp_atomic_dec_and_test(&(radius_sess->refcnt)) ){

  	_rhp_radius_session_free(radius_sess);
  }
}

#endif // RHP_REFCNT_DEBUG


static int _rhp_radius_rx_attr_framed_ipv4(rhp_radius_session* radius_sess,
		rhp_radius_session_priv* radius_sess_priv,rhp_radius_mesg* rx_radius_mesg)
{
	int err = -EINVAL;
	rhp_radius_attr* radius_attr_framed_ipv4
		= rx_radius_mesg->get_attr(rx_radius_mesg,RHP_RADIUS_ATTR_TYPE_FRAMED_IP_ADDRESS,NULL);
	rhp_radius_attr* radius_attr_framed_netmask
		= rx_radius_mesg->get_attr(rx_radius_mesg,RHP_RADIUS_ATTR_TYPE_FRAMED_IP_NETMASK,NULL);
	u8* val;
	int val_len = 0;

	if( radius_attr_framed_ipv4 ){

		val = radius_attr_framed_ipv4->ext.basic->get_attr_value(radius_attr_framed_ipv4,&val_len);
		if( val == NULL || val_len != 4 ){
			err = RHP_STATUS_RADIUS_INVALID_ATTR;
			RHP_TRC(0,RHPTRCID_RADIUS_RX_FRAMED_IPV4_INVALID_ATTR,"xxxd",radius_sess,rx_radius_mesg,val,val_len);
			goto error;
		}

		memset(&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->framed_ipv4),0,sizeof(rhp_ip_addr));

		((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->framed_ipv4.addr_family = AF_INET;
		((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->framed_ipv4.addr.v4 = *((u32*)val);

	}else{

		err = -ENOENT;
		goto error;
	}

	if( radius_attr_framed_netmask ){

		val = radius_attr_framed_netmask->ext.basic->get_attr_value(radius_attr_framed_netmask,&val_len);
		if( val == NULL || val_len != 4 ){
			err = RHP_STATUS_RADIUS_INVALID_ATTR;
			RHP_TRC(0,RHPTRCID_RADIUS_RX_FRAMED_IPV4_NETMASK_INVALID_ATTR,"xxxd",radius_sess,rx_radius_mesg,val,val_len);
			goto error;
		}

		((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->framed_ipv4.netmask.v4 = *((u32*)val);
		((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->framed_ipv4.prefixlen
		= rhp_ipv4_netmask_to_prefixlen(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->framed_ipv4.netmask.v4);

	}else{

		((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->framed_ipv4.netmask.v4 = 0;
		((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->framed_ipv4.prefixlen = 0;
	}

	return 0;

error:
	return err;
}

static int _rhp_radius_rx_attr_framed_ipv6(rhp_radius_session* radius_sess,
		rhp_radius_session_priv* radius_sess_priv,rhp_radius_mesg* rx_radius_mesg)
{
	return rhp_radius_rx_basic_attr_to_ipv6(rx_radius_mesg,
			RHP_RADIUS_ATTR_TYPE_FRAMED_IPV6_ADDRESS,
			&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->framed_ipv6));
}

static int _rhp_radius_rx_attr_ms_primary_dns_server_ipv4(rhp_radius_session* radius_sess,
		rhp_radius_session_priv* radius_sess_priv,rhp_radius_mesg* rx_radius_mesg)
{
	int err = -EINVAL;
	rhp_radius_attr* radius_attr
		= rx_radius_mesg->get_attr_vendor_ms(rx_radius_mesg,RHP_RADIUS_VENDOR_MS_ATTR_TYPE_PRIMARY_DNS_SERVER);
	rhp_proto_radius_attr_vendor_ms* val;
	int val_len = 0;

	if( radius_attr ){

		val = radius_attr->ext.ms->get_vendor_attr(radius_attr,&val_len);
		if( val == NULL || val_len != 6 ){
			err = RHP_STATUS_RADIUS_INVALID_ATTR;
			RHP_TRC(0,RHPTRCID_RADIUS_RX_MS_PRIMARY_DNS_SERVER_IPV4_INVALID_ATTR,"xxxd",radius_sess,rx_radius_mesg,val,val_len);
			goto error;
		}

		memset(&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->ms_primary_dns_server_ipv4),
				0,sizeof(rhp_ip_addr));

		((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->ms_primary_dns_server_ipv4.addr_family
		= AF_INET;

		((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->ms_primary_dns_server_ipv4.addr.v4
		= *((u32*)(val + 1));

	}else{

		err = -ENOENT;
		goto error;
	}

	return 0;

error:
	return err;
}

static int _rhp_radius_rx_attr_dns_server_ipv6(rhp_radius_session* radius_sess,
		rhp_radius_session_priv* radius_sess_priv,rhp_radius_mesg* rx_radius_mesg)
{
	return rhp_radius_rx_basic_attr_to_ipv6(rx_radius_mesg,
			RHP_RADIUS_ATTR_TYPE_DNS_IPV6_ADDRESS,&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->dns_server_ipv6));
}

static int _rhp_radius_rx_attr_ms_primary_nbns_server_ipv4(rhp_radius_session* radius_sess,
		rhp_radius_session_priv* radius_sess_priv,rhp_radius_mesg* rx_radius_mesg)
{
	int err = -EINVAL;
	rhp_radius_attr* radius_attr
		= rx_radius_mesg->get_attr_vendor_ms(rx_radius_mesg,RHP_RADIUS_VENDOR_MS_ATTR_TYPE_PRIMARY_NBNS_SERVER);
	rhp_proto_radius_attr_vendor_ms* val;
	int val_len = 0;

	if( radius_attr ){

		val = radius_attr->ext.ms->get_vendor_attr(radius_attr,&val_len);
		if( val == NULL || val_len != 6 ){
			err = RHP_STATUS_RADIUS_INVALID_ATTR;
			RHP_TRC(0,RHPTRCID_RADIUS_RX_MS_PRIMARY_NBNS_SERVER_IPV4_INVALID_ATTR,"xxxd",radius_sess,rx_radius_mesg,val,val_len);
			goto error;
		}

		memset(&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->ms_primary_nbns_server_ipv4),
				0,sizeof(rhp_ip_addr));

		((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->ms_primary_nbns_server_ipv4.addr_family
		= AF_INET;

		((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->ms_primary_nbns_server_ipv4.addr.v4
		= *((u32*)(val + 1));

	}else{

		err = -ENOENT;
		goto error;
	}

	return 0;

error:
	return err;
}

static int _rhp_radius_rx_attr_realm_id_impl(rhp_radius_mesg* rx_radius_mesg,
		u8 attr_type,int is_tunnel_attr,char* priv_attr_string_value_tag,unsigned long* ret_r)
{
	int err = -EINVAL;
	rhp_radius_attr* radius_attr
		= rx_radius_mesg->get_attr(rx_radius_mesg,attr_type,priv_attr_string_value_tag);
	u8* val;
	int val_len = 0, i;
	unsigned long ret_ulong;

	if( radius_attr ){

		char *tmp,*endp;

		val = radius_attr->ext.basic->get_attr_value(radius_attr,&val_len);
		if( val == NULL || val_len < 1 ){
			err = RHP_STATUS_RADIUS_INVALID_ATTR;
			RHP_TRC(0,RHPTRCID_RADIUS_RX_REALM_ID_IMPL_INVALID_ATTR,"xxd",rx_radius_mesg,val,val_len);
			goto error;
		}

		if( is_tunnel_attr ){

			if( val[0] <= 0x1F ){
				val++;
				val_len--;
			}

			if( val_len < 1 ){
				err = RHP_STATUS_RADIUS_INVALID_ATTR;
				RHP_TRC(0,RHPTRCID_RADIUS_RX_REALM_ID_IMPL_INVALID_ATTR_2,"xxd",rx_radius_mesg,val,val_len);
				goto error;
			}
		}

		if( priv_attr_string_value_tag ){

			int slen = strlen(priv_attr_string_value_tag);
			val += slen;
			val_len -= slen;

			if( val_len < 1 ){
				err = RHP_STATUS_RADIUS_INVALID_ATTR;
				RHP_TRC(0,RHPTRCID_RADIUS_RX_REALM_ID_IMPL_INVALID_ATTR_2_1,"xxdds",rx_radius_mesg,val,val_len,slen,priv_attr_string_value_tag);
				goto error;
			}
		}

		for(i = 0; i < val_len; i++){

			if( i > (RHP_VPN_REALM_ID_MAX_CHARS - 1) ){
				err = RHP_STATUS_RADIUS_INVALID_ATTR;
				RHP_TRC(0,RHPTRCID_RADIUS_RX_REALM_ID_IMPL_INVALID_ATTR_3,"xp",rx_radius_mesg,val_len,val);
				goto error;
			}

			if( val[i] < 0x30 || val[i] > 0x39 ){ // '0':0x30, '9': 0x39
				err = RHP_STATUS_RADIUS_INVALID_ATTR;
				RHP_TRC(0,RHPTRCID_RADIUS_RX_REALM_ID_IMPL_INVALID_ATTR_4,"xp",rx_radius_mesg,val_len,val);
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

		ret_ulong = (unsigned int)strtoul(tmp,&endp,0);
		_rhp_free(tmp);
		if( *endp != '\0' ){
			err = RHP_STATUS_RADIUS_INVALID_ATTR;
			RHP_TRC(0,RHPTRCID_RADIUS_RX_REALM_ID_IMPL_INVALID_ATTR_5,"xp",rx_radius_mesg,val_len,val);
			goto error;
		}

		if( ret_ulong == 0 || ret_ulong > RHP_VPN_REALM_ID_MAX ){
			err = RHP_STATUS_RADIUS_INVALID_ATTR;
			RHP_TRC(0,RHPTRCID_RADIUS_RX_REALM_ID_IMPL_INVALID_ATTR_6,"xup",rx_radius_mesg,ret_ulong,val_len,val);
			goto error;
		}

		*ret_r = ret_ulong;

	}else{

		err = -ENOENT;
		goto error;
	}

	return 0;

error:
	return err;
}

static int _rhp_radius_rx_attr_tunnel_private_group_ids(rhp_radius_session* radius_sess,
		rhp_radius_session_priv* radius_sess_priv,rhp_radius_mesg* rx_radius_mesg)
{
	_rhp_string_list_free(
			((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->tunnel_private_group_ids);

	((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->tunnel_private_group_ids = NULL;

	return rhp_radius_rx_basic_attr_to_string_list(rx_radius_mesg,
			RHP_RADIUS_ATTR_TYPE_TUNNEL_PRIVATE_GROUP_ID,1,NULL,
			&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->tunnel_private_group_ids));
}

static int _rhp_radius_rx_attr_tunnel_client_auth_id(rhp_radius_session* radius_sess,
		rhp_radius_session_priv* radius_sess_priv,rhp_radius_mesg* rx_radius_mesg)
{
	return rhp_radius_rx_basic_attr_to_string(rx_radius_mesg,
			RHP_RADIUS_ATTR_TYPE_TUNNEL_CLIENT_AUTH_ID,1,NULL,
			&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->tunnel_client_auth_id));
}

static int _rhp_radius_rx_attr_session_timeout(rhp_radius_session* radius_sess,
		rhp_radius_session_priv* radius_sess_priv,rhp_radius_mesg* rx_radius_mesg)
{
	return rhp_radius_rx_basic_attr_to_u32(rx_radius_mesg,
			RHP_RADIUS_ATTR_TYPE_SESSION_TIMEOUT,
			&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->session_timeout));
}

// Termination-Action for future use.
#if 0
static int _rhp_radius_rx_attr_termination_action_and_state(rhp_radius_session* radius_sess,
		rhp_radius_session_priv* radius_sess_priv,rhp_radius_mesg* rx_radius_mesg)
{
	int err = -EINVAL;

	err = rhp_radius_rx_basic_attr_to_u32(rx_radius_mesg,
					RHP_RADIUS_ATTR_TYPE_TERMINATION_ACTION,
					&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->termination_action));
	if( err ){
		goto error;
	}

	if( ((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->termination_action
			== RHP_RADIUS_ATTR_TYPE_TERMINATION_ACTION_REQUEST ){

		err = rhp_radius_rx_basic_attr_to_bin(rx_radius_mesg,
						RHP_RADIUS_ATTR_TYPE_STATE,
						&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->termination_action_state),
						&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->termination_action_state_len));
		if( err ){
			goto error;
		}
	}

	return 0;

error:
	return err;
}
#endif

static int _rhp_radius_rx_attr_state(rhp_radius_session* radius_sess,
		rhp_radius_session_priv* radius_sess_priv,rhp_radius_mesg* rx_radius_mesg)
{

	if( radius_sess_priv->rx_attr_state ){
		_rhp_free_zero(radius_sess_priv->rx_attr_state,radius_sess_priv->rx_attr_state_len);
		radius_sess_priv->rx_attr_state = NULL;
		radius_sess_priv->rx_attr_state_len = 0;
	}

	return rhp_radius_rx_basic_attr_to_bin(rx_radius_mesg,
					RHP_RADIUS_ATTR_TYPE_STATE,
					&(radius_sess_priv->rx_attr_state),
					&(radius_sess_priv->rx_attr_state_len));
}

static int _rhp_radius_rx_framed_mtu(rhp_radius_session* radius_sess,
		rhp_radius_session_priv* radius_sess_priv,rhp_radius_mesg* rx_radius_mesg)
{
	return rhp_radius_rx_basic_attr_to_u32(rx_radius_mesg,
			RHP_RADIUS_ATTR_TYPE_FRAMED_MTU,
			&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->framed_mtu));
}


static int _rhp_radius_rx_attr_priv_realm_id(rhp_radius_session* radius_sess,
		rhp_radius_session_priv* radius_sess_priv,rhp_radius_mesg* rx_radius_mesg)
{
	int err = -ENOENT;

	if( radius_sess->priv_attr_type_realm_id ){

		err = _rhp_radius_rx_attr_realm_id_impl(rx_radius_mesg,
						radius_sess->priv_attr_type_realm_id,0,NULL,
						&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_realm_id));
	}

	if( err == -ENOENT && radius_sess->priv_attr_type_common ){

		err = _rhp_radius_rx_attr_realm_id_impl(rx_radius_mesg,
						radius_sess->priv_attr_type_common,0,"REALM_ID:",
						&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_realm_id));
	}

	return err;
}

static int _rhp_radius_rx_attr_priv_realm_role(rhp_radius_session* radius_sess,
		rhp_radius_session_priv* radius_sess_priv,rhp_radius_mesg* rx_radius_mesg)
{
	int err = -ENOENT;

	if( radius_sess->priv_attr_type_realm_role ){

		_rhp_string_list_free(
				((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_realm_roles);

		((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_realm_roles = NULL;

		err = rhp_radius_rx_basic_attr_to_string_list(rx_radius_mesg,
				radius_sess->priv_attr_type_realm_role,0,NULL,
				&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_realm_roles));
	}

	if( err == -ENOENT && radius_sess->priv_attr_type_common ){

		_rhp_string_list_free(
				((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_realm_roles);

		((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_realm_roles = NULL;

		err = rhp_radius_rx_basic_attr_to_string_list(rx_radius_mesg,
				radius_sess->priv_attr_type_common,0,"REALM_ROLE:",
				&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_realm_roles));
	}

	return err;
}

static int _rhp_radius_rx_attr_priv_user_index(rhp_radius_session* radius_sess,
		rhp_radius_session_priv* radius_sess_priv,rhp_radius_mesg* rx_radius_mesg)
{
	int err = -ENOENT;

	if( radius_sess->priv_attr_type_realm_id ){

		err = rhp_radius_rx_basic_attr_to_string(rx_radius_mesg,
				radius_sess->priv_attr_type_user_index,0,NULL,
				&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_user_index));
	}

	if( err == -ENOENT && radius_sess->priv_attr_type_common ){

		err = rhp_radius_rx_basic_attr_to_string(rx_radius_mesg,
				radius_sess->priv_attr_type_common,0,"USER_INDEX:",
				&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_user_index));
	}

	return err;
}

static int _rhp_radius_rx_attr_priv_internal_addr_ipv4(rhp_radius_session* radius_sess,
		rhp_radius_session_priv* radius_sess_priv,rhp_radius_mesg* rx_radius_mesg)
{
	int err = -ENOENT;

	if( radius_sess->priv_attr_type_internal_address_ipv4 ){

		err = rhp_radius_rx_basic_attr_str_to_ipv4(rx_radius_mesg,
				radius_sess->priv_attr_type_internal_address_ipv4,NULL,
				&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_internal_addr_ipv4));
	}

	if( err == -ENOENT && radius_sess->priv_attr_type_common ){

		err = rhp_radius_rx_basic_attr_str_to_ipv4(rx_radius_mesg,
				radius_sess->priv_attr_type_common,"IN_IP4:",
				&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_internal_addr_ipv4));
	}

	return err;
}

static int _rhp_radius_rx_attr_priv_internal_addr_ipv6(rhp_radius_session* radius_sess,
		rhp_radius_session_priv* radius_sess_priv,rhp_radius_mesg* rx_radius_mesg)
{
	int err = -ENOENT;

	if( radius_sess->priv_attr_type_internal_address_ipv6 ){

		err = rhp_radius_rx_basic_attr_str_to_ipv6(rx_radius_mesg,
				radius_sess->priv_attr_type_internal_address_ipv6,NULL,
				&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_internal_addr_ipv6));
	}

	if( err == -ENOENT && radius_sess->priv_attr_type_common ){

		err = rhp_radius_rx_basic_attr_str_to_ipv6(rx_radius_mesg,
				radius_sess->priv_attr_type_common,"IN_IP6:",
				&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_internal_addr_ipv6));
	}

	return err;
}

static int _rhp_radius_rx_attr_priv_dns_server_ipv4(rhp_radius_session* radius_sess,
		rhp_radius_session_priv* radius_sess_priv,rhp_radius_mesg* rx_radius_mesg)
{
	int err = -ENOENT;

	if( radius_sess->priv_attr_type_internal_dns_server_ipv4 ){

		err = rhp_radius_rx_basic_attr_str_to_ipv4(rx_radius_mesg,
				radius_sess->priv_attr_type_internal_dns_server_ipv4,NULL,
				&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_internal_dns_server_ipv4));
	}

	if( err == -ENOENT && radius_sess->priv_attr_type_common ){

		err = rhp_radius_rx_basic_attr_str_to_ipv4(rx_radius_mesg,
				radius_sess->priv_attr_type_common,"IN_DNS_IP4:",
				&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_internal_dns_server_ipv4));
	}

	return err;
}

static int _rhp_radius_rx_attr_priv_dns_server_ipv6(rhp_radius_session* radius_sess,
		rhp_radius_session_priv* radius_sess_priv,rhp_radius_mesg* rx_radius_mesg)
{
	int err = -ENOENT;

	if( radius_sess->priv_attr_type_internal_address_ipv6 ){

		err = rhp_radius_rx_basic_attr_str_to_ipv6(rx_radius_mesg,
				radius_sess->priv_attr_type_internal_dns_server_ipv6,NULL,
				&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_internal_dns_server_ipv6));
	}

	if( err == -ENOENT && radius_sess->priv_attr_type_common ){

		err = rhp_radius_rx_basic_attr_str_to_ipv6(rx_radius_mesg,
				radius_sess->priv_attr_type_common,"IN_DNS_IP6:",
				&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_internal_dns_server_ipv6));
	}

	return err;
}

static int _rhp_radius_rx_attr_priv_domain_names(rhp_radius_session* radius_sess,
		rhp_radius_session_priv* radius_sess_priv,rhp_radius_mesg* rx_radius_mesg)
{
	int err = -ENOENT;
	rhp_split_dns_domain* domain
		= ((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_domain_names;

	if( radius_sess->priv_attr_type_internal_domain_name ||
			radius_sess->priv_attr_type_common ){

		while( domain ){
			rhp_split_dns_domain* domain_n = domain->next;
			if( domain->name ){
				_rhp_free(domain->name);
			}
			_rhp_free(domain);
			domain = domain_n;
		}
	}

	if( radius_sess->priv_attr_type_internal_domain_name ){
		((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_domain_names = NULL;

		err = rhp_radius_rx_basic_attr_to_domain_list(rx_radius_mesg,
				radius_sess->priv_attr_type_internal_domain_name,NULL,
				&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_domain_names));
	}

	if( err == -ENOENT && radius_sess->priv_attr_type_common ){

		err = rhp_radius_rx_basic_attr_to_domain_list(rx_radius_mesg,
				radius_sess->priv_attr_type_common,"IN_DOMAIN:",
				&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_domain_names));
	}

	return err;
}

static int _rhp_radius_rx_attr_priv_routes_ipv4(rhp_radius_session* radius_sess,
		rhp_radius_session_priv* radius_sess_priv,rhp_radius_mesg* rx_radius_mesg)
{
	int err = -ENOENT;
	if( radius_sess->priv_attr_type_internal_route_ipv4 ){

		err = rhp_radius_rx_basic_attr_str_to_rt_map_list(rx_radius_mesg,
						radius_sess->priv_attr_type_internal_route_ipv4,AF_INET,NULL,
						&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_internal_route_ipv4));
	}

	if( err == -ENOENT && radius_sess->priv_attr_type_common ){

		err = rhp_radius_rx_basic_attr_str_to_rt_map_list(rx_radius_mesg,
						radius_sess->priv_attr_type_common,AF_INET,"IN_DEST_IP4:",
						&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_internal_route_ipv4));
	}

	return err;
}

static int _rhp_radius_rx_attr_priv_routes_ipv6(rhp_radius_session* radius_sess,
		rhp_radius_session_priv* radius_sess_priv,rhp_radius_mesg* rx_radius_mesg)
{
	int err = -ENOENT;
	if( radius_sess->priv_attr_type_internal_route_ipv6 ){

		err = rhp_radius_rx_basic_attr_str_to_rt_map_list(rx_radius_mesg,
						radius_sess->priv_attr_type_internal_route_ipv6,AF_INET6,NULL,
						&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_internal_route_ipv6));
	}

	if( err == -ENOENT && radius_sess->priv_attr_type_common ){

		err = rhp_radius_rx_basic_attr_str_to_rt_map_list(rx_radius_mesg,
						radius_sess->priv_attr_type_common,AF_INET6,"IN_DEST_IP6:",
						&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_internal_route_ipv6));
	}

	return err;
}

static int _rhp_radius_rx_attr_priv_gateway_ipv4(rhp_radius_session* radius_sess,
		rhp_radius_session_priv* radius_sess_priv,rhp_radius_mesg* rx_radius_mesg)
{
	int err = -ENOENT;
	if( radius_sess->priv_attr_type_internal_gateway_ipv4 ){

		err = rhp_radius_rx_basic_attr_str_to_ipv4(rx_radius_mesg,
				radius_sess->priv_attr_type_internal_gateway_ipv4,NULL,
				&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_internal_gateway_ipv4));
	}

	if( err == -ENOENT && radius_sess->priv_attr_type_common ){

		err = rhp_radius_rx_basic_attr_str_to_ipv4(rx_radius_mesg,
				radius_sess->priv_attr_type_common,"IN_GW_IP4:",
				&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_internal_gateway_ipv4));
	}

	return err;
}

static int _rhp_radius_rx_attr_priv_gateway_ipv6(rhp_radius_session* radius_sess,
		rhp_radius_session_priv* radius_sess_priv,rhp_radius_mesg* rx_radius_mesg)
{
	int err = -ENOENT;
	if( radius_sess->priv_attr_type_internal_gateway_ipv4 ){

		err = rhp_radius_rx_basic_attr_str_to_ipv6(rx_radius_mesg,
				radius_sess->priv_attr_type_internal_gateway_ipv6,NULL,
				&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_internal_gateway_ipv6));
	}

	if( err == -ENOENT && radius_sess->priv_attr_type_common ){

		err = rhp_radius_rx_basic_attr_str_to_ipv6(rx_radius_mesg,
				radius_sess->priv_attr_type_common,"IN_GW_IP6:",
				&(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs->priv_internal_gateway_ipv6));
	}

	return err;
}

void rhp_radius_access_accept_rx_attrs_dump(rhp_radius_access_accept_attrs* rx_accepted_attrs,void* radius_sess_p)
{
	_RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
  if( _RHP_TRC_COND(_rhp_trc_user_id(),0) ){

  	rhp_radius_session* radius_sess = (rhp_radius_session*)radius_sess_p;

		RHP_TRC(0,RHPTRCID_RADIUS_ACCESS_ACCEPTED_RX_ATTRS_DUMP_CFG,"xbbbbbbbbbbbbbbbbbbbbbbbbbbbb",rx_accepted_attrs,rhp_gcfg_eap_radius->enabled,rhp_gcfg_eap_radius->tx_nas_id_as_ikev2_id_enabled,rhp_gcfg_eap_radius->tx_calling_station_id_enabled,rhp_gcfg_eap_radius->tx_nas_port_type_enabled,rhp_gcfg_eap_radius->rx_session_timeout_enabled,rhp_gcfg_eap_radius->rx_term_action_enabled,rhp_gcfg_eap_radius->rx_framed_mtu_enabled,rhp_gcfg_eap_radius->rx_framed_ipv4_enabled,rhp_gcfg_eap_radius->rx_framed_ipv6_enabled,rhp_gcfg_eap_radius->rx_ms_primary_dns_server_v4_enabled,rhp_gcfg_eap_radius->rx_dns_server_v6_enabled,rhp_gcfg_eap_radius->rx_route_v6_info_enabled,rhp_gcfg_eap_radius->rx_ms_primary_nbns_server_v4_enabled,rhp_gcfg_eap_radius->rx_tunnel_private_group_id_enabled,rhp_gcfg_eap_radius->rx_tunnel_client_auth_id_enabled,rhp_gcfg_eap_radius->rx_vpn_realm_id_attr_type,rhp_gcfg_eap_radius->rx_vpn_realm_role_attr_type,rhp_gcfg_eap_radius->rx_user_index_attr_type,rhp_gcfg_eap_radius->rx_internal_dns_v4_attr_type,rhp_gcfg_eap_radius->rx_internal_dns_v6_attr_type,rhp_gcfg_eap_radius->rx_internal_domain_names_attr_type,rhp_gcfg_eap_radius->rx_internal_rt_maps_v4_attr_type,rhp_gcfg_eap_radius->rx_internal_rt_maps_v6_attr_type,rhp_gcfg_eap_radius->rx_internal_gw_v4_attr_type,rhp_gcfg_eap_radius->rx_internal_gw_v6_attr_type,rhp_gcfg_eap_radius->rx_internal_addr_ipv4,rhp_gcfg_eap_radius->rx_internal_addr_ipv6,rhp_gcfg_eap_radius->rx_common_priv_attr);

		if( radius_sess ){
			RHP_TRC(0,RHPTRCID_RADIUS_ACCESS_ACCEPTED_RX_ATTRS_DUMP_CFG_2,"xxbbbbbbbbbbbbbbbbb",rx_accepted_attrs,radius_sess,radius_sess->priv_attr_type_realm_id,radius_sess->priv_attr_type_realm_role,radius_sess->priv_attr_type_user_index,radius_sess->priv_attr_type_internal_address_ipv4,radius_sess->priv_attr_type_internal_address_ipv6,radius_sess->priv_attr_type_internal_dns_server_ipv4,radius_sess->priv_attr_type_internal_dns_server_ipv6,radius_sess->priv_attr_type_internal_domain_name,radius_sess->priv_attr_type_internal_route_ipv4,radius_sess->priv_attr_type_internal_route_ipv6,radius_sess->priv_attr_type_internal_gateway_ipv4,radius_sess->priv_attr_type_internal_gateway_ipv6,radius_sess->priv_attr_type_common);
		}


		if( rx_accepted_attrs == NULL ){

			RHP_TRC(0,RHPTRCID_RADIUS_ACCESS_ACCEPTED_RX_ATTRS_DUMP_NO_ENT,"x",rx_accepted_attrs);

		}else{

			char* tunnel_private_group_ids = _rhp_string_list_cat(rx_accepted_attrs->tunnel_private_group_ids);
			char* priv_realm_roles = _rhp_string_list_cat(rx_accepted_attrs->priv_realm_roles);

			RHP_TRC(0,RHPTRCID_RADIUS_ACCESS_ACCEPTED_RX_ATTRS_DUMP,"xjjussss",rx_accepted_attrs,rx_accepted_attrs->session_timeout,rx_accepted_attrs->framed_mtu,rx_accepted_attrs->priv_realm_id,rx_accepted_attrs->tunnel_client_auth_id,rx_accepted_attrs->priv_user_index,tunnel_private_group_ids,priv_realm_roles);

			if(tunnel_private_group_ids){
				_rhp_free(tunnel_private_group_ids);
			}
			if(priv_realm_roles){
				_rhp_free(priv_realm_roles);
			}

			rhp_ip_addr_dump("framed_ipv4",&(rx_accepted_attrs->framed_ipv4));
			rhp_ip_addr_dump("framed_ipv6",&(rx_accepted_attrs->framed_ipv6));
			rhp_ip_addr_dump("ms_primary_dns_server_ipv4",&(rx_accepted_attrs->ms_primary_dns_server_ipv4));
			rhp_ip_addr_dump("dns_server_ipv6",&(rx_accepted_attrs->dns_server_ipv6));
			rhp_ip_addr_dump("ms_primary_nbns_server_ipv4",&(rx_accepted_attrs->ms_primary_nbns_server_ipv4));
			rhp_ip_addr_dump("priv_internal_addr_ipv4",&(rx_accepted_attrs->priv_internal_addr_ipv4));
			rhp_ip_addr_dump("priv_internal_addr_ipv6",&(rx_accepted_attrs->priv_internal_addr_ipv6));
			rhp_ip_addr_dump("priv_internal_dns_server_ipv4",&(rx_accepted_attrs->priv_internal_dns_server_ipv4));
			rhp_ip_addr_dump("priv_internal_dns_server_ipv6",&(rx_accepted_attrs->priv_internal_dns_server_ipv6));
			rhp_ip_addr_dump("priv_internal_gateway_ipv4",&(rx_accepted_attrs->priv_internal_gateway_ipv4));
			rhp_ip_addr_dump("priv_internal_gateway_ipv6",&(rx_accepted_attrs->priv_internal_gateway_ipv6));


			{
				rhp_split_dns_domain* tmp_dn = rx_accepted_attrs->priv_domain_names;
				while( tmp_dn ){
					RHP_TRC(0,RHPTRCID_RADIUS_ACCESS_ACCEPTED_RX_ATTRS_DUMP_PRIV_DOMAIN_NAME,"xsd",rx_accepted_attrs,tmp_dn->name,tmp_dn->ikev2_cfg);
					tmp_dn = tmp_dn->next;
				}
			}

			{
				rhp_internal_route_map* tmp_rt = rx_accepted_attrs->priv_internal_route_ipv4;
				while( tmp_rt ){
					rhp_ip_addr_dump("priv_internal_route_ipv4",&(tmp_rt->dest_addr));
					tmp_rt = tmp_rt->next;
				}

				tmp_rt = rx_accepted_attrs->priv_internal_route_ipv6;
				while( tmp_rt ){
					rhp_ip_addr_dump("priv_internal_route_ipv6",&(tmp_rt->dest_addr));
					tmp_rt = tmp_rt->next;
				}
			}


			rhp_ip_addr_dump("orig_nas_addr",&(rx_accepted_attrs->orig_nas_addr));
		}
  }
	return;
}


static int _rhp_radius_access_accept_rx_attrs(rhp_radius_session* radius_sess,
		rhp_radius_session_priv* radius_sess_priv,rhp_radius_mesg* rx_radius_mesg)
{
	rhp_radius_access_accept_attrs* rx_accepted_attrs
		= ((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs;

	if( rx_accepted_attrs == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	_rhp_radius_rx_attr_framed_ipv4(radius_sess,
			radius_sess_priv,rx_radius_mesg);

	_rhp_radius_rx_attr_framed_ipv6(radius_sess,
			radius_sess_priv,rx_radius_mesg);

	_rhp_radius_rx_attr_ms_primary_dns_server_ipv4(radius_sess,
			radius_sess_priv,rx_radius_mesg);

	_rhp_radius_rx_attr_dns_server_ipv6(radius_sess,
			radius_sess_priv,rx_radius_mesg);

	_rhp_radius_rx_attr_ms_primary_nbns_server_ipv4(radius_sess,
			radius_sess_priv,rx_radius_mesg);

	_rhp_radius_rx_attr_tunnel_private_group_ids(radius_sess,
			radius_sess_priv,rx_radius_mesg);

	_rhp_radius_rx_attr_tunnel_client_auth_id(radius_sess,
			radius_sess_priv,rx_radius_mesg);

	_rhp_radius_rx_attr_session_timeout(radius_sess,
			radius_sess_priv,rx_radius_mesg);

// Termination-Action for future use.
#if 0

	_rhp_radius_rx_attr_termination_action_and_state(radius_sess,
			radius_sess_priv,rx_radius_mesg);
#endif

	_rhp_radius_rx_framed_mtu(radius_sess,
			radius_sess_priv,rx_radius_mesg);

	_rhp_radius_rx_attr_priv_realm_id(radius_sess,
			radius_sess_priv,rx_radius_mesg);

	_rhp_radius_rx_attr_priv_realm_role(radius_sess,
			radius_sess_priv,rx_radius_mesg);

	_rhp_radius_rx_attr_priv_user_index(radius_sess,
			radius_sess_priv,rx_radius_mesg);

	_rhp_radius_rx_attr_priv_internal_addr_ipv4(radius_sess,
			radius_sess_priv,rx_radius_mesg);

	_rhp_radius_rx_attr_priv_internal_addr_ipv6(radius_sess,
			radius_sess_priv,rx_radius_mesg);

	_rhp_radius_rx_attr_priv_dns_server_ipv4(radius_sess,
			radius_sess_priv,rx_radius_mesg);

	_rhp_radius_rx_attr_priv_dns_server_ipv6(radius_sess,
			radius_sess_priv,rx_radius_mesg);

	_rhp_radius_rx_attr_priv_domain_names(radius_sess,
			radius_sess_priv,rx_radius_mesg);

	_rhp_radius_rx_attr_priv_routes_ipv4(radius_sess,
			radius_sess_priv,rx_radius_mesg);

	_rhp_radius_rx_attr_priv_routes_ipv6(radius_sess,
			radius_sess_priv,rx_radius_mesg);

	_rhp_radius_rx_attr_priv_gateway_ipv4(radius_sess,
			radius_sess_priv,rx_radius_mesg);

	_rhp_radius_rx_attr_priv_gateway_ipv6(radius_sess,
			radius_sess_priv,rx_radius_mesg);


	rhp_radius_access_accept_rx_attrs_dump(((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rx_accept_attrs,radius_sess);
	return 0;
}


static int _rhp_radius_main_log_rx_mesg_cb(rhp_radius_mesg* rx_radius_mesg,rhp_radius_attr* radius_attr,char* nop,void* cb_ctx)
{
	rhp_radius_session* radius_sess = (rhp_radius_session*)cb_ctx;
	u8 attr_type = radius_attr->get_attr_type(radius_attr);
	u32 vendor_id = radius_attr->get_attr_vendor_id(radius_attr);
	u8* val = NULL;
	int val_len = 0;
	char* priv_attr_label = NULL;
	int is_basic_attr = 0;

	if( attr_type == RHP_RADIUS_ATTR_TYPE_EAP ){
		val = (u8*)radius_attr->ext.eap->get_eap_packet(radius_attr,&val_len);
	}else if( attr_type == RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC &&
						vendor_id == RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC_MICROSOFT ){
		val = (u8*)radius_attr->ext.ms->get_vendor_attr(radius_attr,&val_len);
	}else{
		is_basic_attr = 1;
		val = (u8*)radius_attr->ext.basic->get_attr_value(radius_attr,&val_len);
	}

	if( is_basic_attr ){

		RHP_LOCK(&rhp_eap_radius_cfg_lock);
		{
			if( attr_type == rhp_gcfg_eap_radius->rx_vpn_realm_id_attr_type ){
				priv_attr_label = "VPN_REALM_ID";
			}else if( attr_type == rhp_gcfg_eap_radius->rx_vpn_realm_role_attr_type ){
				priv_attr_label = "VPN_REALM_ROLE";
			}else if( attr_type == rhp_gcfg_eap_radius->rx_user_index_attr_type ){
				priv_attr_label = "USER_INDEX";
			}else if( attr_type == rhp_gcfg_eap_radius->rx_internal_dns_v4_attr_type ){
				priv_attr_label = "INTERNAL_DNS_IPV4";
			}else if( attr_type == rhp_gcfg_eap_radius->rx_internal_dns_v6_attr_type ){
				priv_attr_label = "INTERNAL_DNS_IPV6";
			}else if( attr_type == rhp_gcfg_eap_radius->rx_internal_domain_names_attr_type ){
				priv_attr_label = "INTERNAL_DOMAIN_NAME";
			}else if( attr_type == rhp_gcfg_eap_radius->rx_internal_rt_maps_v4_attr_type ){
				priv_attr_label = "INTERNAL_ROUTE_MAP_IPV4";
			}else if( attr_type == rhp_gcfg_eap_radius->rx_internal_rt_maps_v6_attr_type ){
				priv_attr_label = "INTERNAL_ROUTE_MAP_IPV6";
			}else if( attr_type == rhp_gcfg_eap_radius->rx_internal_gw_v4_attr_type ){
				priv_attr_label = "INTERNAL_GATEWAY_IPV4";
			}else if( attr_type == rhp_gcfg_eap_radius->rx_internal_gw_v6_attr_type ){
				priv_attr_label = "INTERNAL_GATEWAY_IPV6";
			}else if( attr_type == rhp_gcfg_eap_radius->rx_internal_addr_ipv4 ){
				priv_attr_label = "INTERNAL_IPV4_ADDRESS";
			}else if( attr_type == rhp_gcfg_eap_radius->rx_internal_addr_ipv6 ){
				priv_attr_label = "INTERNAL_IPV6_ADDRESS";
			}else if( attr_type == rhp_gcfg_eap_radius->rx_common_priv_attr ){
				priv_attr_label = "COMMON";
			}
		}
		RHP_UNLOCK(&rhp_eap_radius_cfg_lock);
	}

	if( priv_attr_label ){

		if(val_len > 64){
			val_len = 64;
		}else if(val_len < 0){
			val_len = 0;
		}
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_RX_ATTR_PRIVATE_ATTR,"rRsba",radius_sess,rx_radius_mesg,priv_attr_label,attr_type,val_len,(val_len ? val : NULL));

	}else{

		switch( attr_type ){

		case RHP_RADIUS_ATTR_TYPE_EAP:
		{
			union {
				u8* raw;
				rhp_proto_eap* eaph;
				rhp_proto_eap_request* eaprh;
			} eaph;
			eaph.raw = val;

			if( eaph.eaph->code == RHP_PROTO_EAP_CODE_REQUEST || eaph.eaph->code == RHP_PROTO_EAP_CODE_RESPONSE ){

				val_len -= sizeof(rhp_proto_eap_request);
				if(val_len > 64){
					val_len = 64;
				}else if(val_len < 0){
					val_len = 0;
				}

				if( eaph.eaprh->type == RHP_PROTO_EAP_TYPE_IDENTITY ){

					RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_RX_ATTR_EAP_IDENTITY,"rRLbWLa",radius_sess,rx_radius_mesg,"EAP_CODE",(int)eaph.eaph->code,eaph.eaph->identifier,eaph.eaph->len,"EAP_TYPE",(int)eaph.eaprh->type,val_len,(val_len > 0 ? (u8*)(eaph.eaprh + 1) : NULL));

				}else{

					RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_RX_ATTR_EAP_REQ,"rRLbWLp",radius_sess,rx_radius_mesg,"EAP_CODE",(int)eaph.eaph->code,eaph.eaph->identifier,eaph.eaph->len,"EAP_TYPE",(int)eaph.eaprh->type,val_len,(val_len > 0 ? (u8*)(eaph.eaprh + 1) : NULL));
				}

			}else if( eaph.eaph->code == RHP_PROTO_EAP_CODE_SUCCESS || eaph.eaph->code == RHP_PROTO_EAP_CODE_FAILURE ){

				RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_RX_ATTR_EAP_SUCCESS_OR_FAILURE,"rRLbW",radius_sess,rx_radius_mesg,"EAP_CODE",(int)eaph.eaph->code,eaph.eaph->identifier,eaph.eaph->len);

			}else{

				RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_RX_ATTR_EAP_UNKNOWN_CODE,"rRLbW",radius_sess,rx_radius_mesg,"EAP_CODE",(int)eaph.eaph->code,eaph.eaph->identifier,eaph.eaph->len);
			}
		}
			break;

		case RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC:

			if( vendor_id == RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC_MICROSOFT ){

				rhp_proto_radius_attr_vendor_ms* msh = (rhp_proto_radius_attr_vendor_ms*)val;

				val_len -= sizeof(rhp_proto_radius_attr_vendor_ms);
				if(val_len > 64){
					val_len = 64;
				}else if(val_len < 0){
					val_len = 0;
				}

				switch(msh->vendor_type){
				case RHP_RADIUS_VENDOR_MS_ATTR_TYPE_PRIMARY_DNS_SERVER:
				case RHP_RADIUS_VENDOR_MS_ATTR_TYPE_SECONDARY_DNS_SERVER:
				case RHP_RADIUS_VENDOR_MS_ATTR_TYPE_PRIMARY_NBNS_SERVER:
				case RHP_RADIUS_VENDOR_MS_ATTR_TYPE_SECONDARY_NBNS_SERVER:
					if( val_len == 4 ){
						RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_RX_ATTR_VENDOR_SPECIFIC_MS_IPV4,"rRL4",radius_sess,rx_radius_mesg,"RADIUS_MS_ATTR",(int)msh->vendor_type,*((u32*)(msh + 1)));
					}else{
						RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_RX_ATTR_VENDOR_SPECIFIC_MS_INVALID_IPV4,"rRLp",radius_sess,rx_radius_mesg,"RADIUS_MS_ATTR",(int)msh->vendor_type,val_len,(val_len > 0 ? (u8*)(msh + 1) : NULL));
					}
					break;
				default:
					RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_RX_ATTR_VENDOR_SPECIFIC_MS,"rRLp",radius_sess,rx_radius_mesg,"RADIUS_MS_ATTR",(int)msh->vendor_type,val_len,(val_len > 0 ? (u8*)(msh + 1) : NULL));
					break;
				}

			}else{

				val_len -= sizeof(rhp_proto_radius_attr_vendor);
				if(val_len > 64){
					val_len = 64;
				}else if(val_len < 0){
					val_len = 0;
				}

				RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_RX_ATTR_VENDOR_SPECIFIC,"rRLp",radius_sess,rx_radius_mesg,"RADIUS_VENDOR",(int)vendor_id,val_len,(val_len > 0 ? (u8*)(((rhp_proto_radius_attr_vendor*)val) + 1) : NULL));
			}
			break;

		case RHP_RADIUS_ATTR_TYPE_NAS_IP_ADDRESS:
		case RHP_RADIUS_ATTR_TYPE_FRAMED_IP_ADDRESS:
		case RHP_RADIUS_ATTR_TYPE_FRAMED_IP_NETMASK:
		{
			if(val_len > 64){
				val_len = 64;
			}else if(val_len < 0){
				val_len = 0;
			}
			if( val_len == 4 ){
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_RX_ATTR_IPV4,"rRL4",radius_sess,rx_radius_mesg,"RADIUS_ATTR",attr_type,*((u32*)val));
			}else{
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_RX_ATTR_INVALID_IPV4,"rRLp",radius_sess,rx_radius_mesg,"RADIUS_ATTR",attr_type,val_len,(val_len ? val : NULL));
			}
		}
			break;
		case RHP_RADIUS_ATTR_TYPE_NAS_IPV6_ADDRESS:
		case RHP_RADIUS_ATTR_TYPE_FRAMED_IPV6_ADDRESS:
		case RHP_RADIUS_ATTR_TYPE_DNS_IPV6_ADDRESS:
		{
			if(val_len > 64){
				val_len = 64;
			}else if(val_len < 0){
				val_len = 0;
			}
			if( val_len == 16 ){
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_RX_ATTR_IPV6,"rRL6",radius_sess,rx_radius_mesg,"RADIUS_ATTR",attr_type,val);
			}else{
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_RX_ATTR_INVALID_IPV6,"rRLp",radius_sess,rx_radius_mesg,"RADIUS_ATTR",attr_type,val_len,(val_len ? val : NULL));
			}
		}
			break;
		case RHP_RADIUS_ATTR_TYPE_USER_NAME:
		case RHP_RADIUS_ATTR_TYPE_NAS_ID:
		case RHP_RADIUS_ATTR_TYPE_CALLED_STATION_ID:
		case RHP_RADIUS_ATTR_TYPE_CALLING_STATION_ID:
		case RHP_RADIUS_ATTR_TYPE_CONNECT_INFO:
		case RHP_RADIUS_ATTR_TYPE_REPLY_MESG:
		case RHP_RADIUS_ATTR_TYPE_TUNNEL_PRIVATE_GROUP_ID:
		case RHP_RADIUS_ATTR_TYPE_TUNNEL_CLIENT_AUTH_ID:
		case RHP_RADIUS_ATTR_TYPE_NAS_PORT_ID:
		{
			if(val_len > 64){
				val_len = 64;
			}else if(val_len < 0){
				val_len = 0;
			}
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_RX_ATTR_STRING,"rRLa",radius_sess,rx_radius_mesg,"RADIUS_ATTR",attr_type,val_len,(val_len ? val : NULL));
		}
			break;
		case RHP_RADIUS_ATTR_TYPE_FRAMED_MTU:
		case RHP_RADIUS_ATTR_TYPE_NAS_PORT_TYPE:
		case RHP_RADIUS_ATTR_TYPE_NAS_PORT:
		case RHP_RADIUS_ATTR_TYPE_SESSION_TIMEOUT:
		case RHP_RADIUS_ATTR_TYPE_TERMINATION_ACTION:
		{
			if(val_len > 64){
				val_len = 64;
			}else if(val_len < 0){
				val_len = 0;
			}
			if( val_len == 4 ){
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_RX_ATTR_UINT32,"rRLj",radius_sess,rx_radius_mesg,"RADIUS_ATTR",attr_type,ntohl(*((u32*)val)));
			}else{
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_RX_ATTR_INVALID_UINT32,"rRLp",radius_sess,rx_radius_mesg,"RADIUS_ATTR",attr_type,val_len,(val_len ? val : NULL));
			}
		}
			break;

		case RHP_RADIUS_ATTR_TYPE_ERROR_CAUSE:
		{
			if(val_len > 64){
				val_len = 64;
			}else if(val_len < 0){
				val_len = 0;
			}
			if( val_len == 4 ){

				u32 err_code = ntohl(*((u32*)val));
				char* err_mesg = NULL;

				switch( err_code ){
				case 201:
					err_mesg = "Residual Session Context Removed";
					break;
				case 202:
					err_mesg = "Invalid EAP Packet (Ignored)";
					break;
				case 401:
					err_mesg = "Unsupported Attribute";
					break;
				case 402:
					err_mesg = "Missing Attribute";
					break;
				case 403:
					err_mesg = "NAS Identification Mismatch";
					break;
				case 404:
					err_mesg = "Invalid Request";
					break;
				case 405:
					err_mesg = "Unsupported Service";
					break;
				case 406:
					err_mesg = "Unsupported Extension";
					break;
				case 407:
					err_mesg = "Invalid Attribute Value";
					break;
				case 501:
					err_mesg = "Administratively Prohibited";
					break;
				case 502:
					err_mesg = "Request Not Routable (Proxy)";
					break;
				case 503:
					err_mesg = "Session Context Not Found";
					break;
				case 504:
					err_mesg = "Session Context Not Removable";
					break;
				case 505:
					err_mesg = "Other Proxy Processing Error";
					break;
				case 506:
					err_mesg = "Resources Unavailable";
					break;
				case 507:
					err_mesg = "Request Initiated";
					break;
				case 508:
					err_mesg = "Multiple Session Selection Unsupported";
					break;
				default:
					err_mesg = "Unknown error code.";
					break;
				}

				RHP_LOG_DE(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_RX_ATTR_ERROR_CAUSE,"rRLjs",radius_sess,rx_radius_mesg,"RADIUS_ATTR",attr_type,err_code,err_mesg);
				RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_ERROR_CAUSE,"xxLdjs",radius_sess,rx_radius_mesg,"RADIUS_ATTR",attr_type,err_code,err_mesg);

			}else{

				RHP_LOG_DE(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_RX_ATTR_INVALID_ERROR_CAUSE,"rRLp",radius_sess,rx_radius_mesg,"RADIUS_ATTR",attr_type,val_len,(val_len ? val : NULL));
				RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_ERROR_CAUSE_UNKOWN,"xxLdp",radius_sess,rx_radius_mesg,"RADIUS_ATTR",attr_type,val_len,(val_len ? val : NULL));
			}
		}
			break;

		case RHP_RADIUS_ATTR_TYPE_MESG_AUTH:
		case RHP_RADIUS_ATTR_TYPE_STATE:
		default:
		{
			if(val_len > 64){
				val_len = 64;
			}else if(val_len < 0){
				val_len = 0;
			}
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_RX_ATTR_BIN,"rRLp",radius_sess,rx_radius_mesg,"RADIUS_ATTR",attr_type,val_len,(val_len ? val : NULL));
		}
			break;
		}
	}

	return 0;
}

static void _rhp_radius_main_log_rx_mesg(rhp_radius_session* radius_sess,rhp_radius_mesg* rx_radius_mesg)
{

	if( rx_radius_mesg == NULL ){
		return;
	}

	if( !rhp_log_debug_level_enabled() ){
		return;
	}

	rx_radius_mesg->enum_attrs(rx_radius_mesg,0,NULL,_rhp_radius_main_log_rx_mesg_cb,radius_sess);

	return;
}


static void _rhp_radius_main_ipc_mesg_auth_handler(int worker_idx,void* wts_ctx)
{
	int err = -EINVAL;
	rhp_ipcmsg_radius_mesg_auth_rep* ipc_rep = (rhp_ipcmsg_radius_mesg_auth_rep*)wts_ctx;
	rhp_radius_session_ref* radius_sess_ref = NULL;
	rhp_radius_session* radius_sess = NULL;
	rhp_radius_session_priv* radius_sess_priv = NULL;
	rhp_radius_mesg* rx_radius_mesg = NULL;
	rhp_packet* rx_pkt = NULL;
  rhp_proto_radius *rx_radiush = NULL, *ipc_rep_radiush = NULL;
	int err_notify = 0;
	void* cb_ctx = NULL;
	u8 code = 0;

	RHP_TRC(0,RHPTRCID_RADIUS_MAIN_IPC_MESG_AUTH_HANDLER,"dx",worker_idx,ipc_rep);

	if( ipc_rep->len < sizeof(rhp_ipcmsg_radius_mesg_auth_rep) ){
		RHP_BUG("%d:%d",ipc_rep->len,sizeof(rhp_ipcmsg_radius_mesg_auth_rep));
		return;
	}

	if( ipc_rep->type != RHP_IPC_RADIUS_MESG_AUTH_REPLY ){
		RHP_BUG("%d",ipc_rep->type);
		return;
	}

	if( ipc_rep->mesg_len < sizeof(rhp_proto_radius) ){
		RHP_BUG("%d",ipc_rep->mesg_len);
		return;
	}

	if( ipc_rep->len < sizeof(rhp_ipcmsg_radius_mesg_auth_rep) + ipc_rep->mesg_len +  ipc_rep->msk_len ){
		RHP_BUG("%d, %d, %d",ipc_rep->len,sizeof(rhp_ipcmsg_radius_mesg_auth_rep),ipc_rep->mesg_len,ipc_rep->msk_len);
		return;
	}

	ipc_rep_radiush = (rhp_proto_radius*)(ipc_rep + 1);


	{
		RHP_LOCK(&(rhp_radius_priv_lock));

		radius_sess_ref = _rhp_radius_sess_ipc_get(ipc_rep->txn_id);
		if( radius_sess_ref == NULL ){
			err = -ENOENT;
			RHP_UNLOCK(&(rhp_radius_priv_lock));
			goto error;
		}
	  radius_sess = RHP_RADIUS_SESS_REF(radius_sess_ref);

		RHP_UNLOCK(&(rhp_radius_priv_lock));
	}


	RHP_LOCK(&(radius_sess->lock));

	radius_sess_priv = (rhp_radius_session_priv*)radius_sess->priv;

	if( !_rhp_atomic_read(&(radius_sess->is_active)) ){
		err = RHP_STATUS_RADIUS_INVALID_SESSION;
		RHP_TRC(0,RHPTRCID_RADIUS_MAIN_IPC_MESG_AUTH_HANDLER_RADIUS_SESS_NOT_ACTIVE,"dxx",worker_idx,ipc_rep,radius_sess);
		goto error;
	}

	if( radius_sess_priv->rx_pend_pkt_ref == NULL ){
		err = -EINVAL;
		RHP_TRC(0,RHPTRCID_RADIUS_MAIN_IPC_MESG_AUTH_HANDLER_RX_PKT_NOT_PENDING,"dxx",worker_idx,ipc_rep,radius_sess);
		goto error;
	}

	if( ipc_rep->error ){

		if( ipc_rep->error_notify ){
			err_notify = 1;
		}

		err = RHP_STATUS_RADIUS_MESG_AUTH_ERR;
		RHP_TRC(0,RHPTRCID_RADIUS_MAIN_IPC_MESG_AUTH_HANDLER_AUTH_FAILED,"dxxxx",worker_idx,ipc_rep,radius_sess,radius_sess_priv->rx_pend_pkt_ref,RHP_PKT_REF(radius_sess_priv->rx_pend_pkt_ref));

		goto error;
	}

	rx_pkt = RHP_PKT_REF(radius_sess_priv->rx_pend_pkt_ref);
	radius_sess_priv->rx_pend_pkt_ref = NULL;


	err = rhp_radius_new_mesg_rx(radius_sess,rx_pkt,&rx_radius_mesg);
	if( err ){
		RHP_TRC(0,RHPTRCID_RADIUS_MAIN_IPC_MESG_AUTH_HANDLER_PARSE_RX_PKT_ERR,"dxxx",worker_idx,ipc_rep,radius_sess,rx_pkt);
		goto error;
	}

	rx_radiush = (rhp_proto_radius*)rx_pkt->app.raw;

	if( (ipc_rep->mesg_len != sizeof(rhp_proto_radius)) ||
			(memcmp(ipc_rep_radiush,rx_radiush,sizeof(rhp_proto_radius))) ){
		err = -EINVAL;
		RHP_TRC(0,RHPTRCID_RADIUS_MAIN_IPC_MESG_AUTH_HANDLER_AUTH_FAILED_2,"dxxxpp",worker_idx,ipc_rep,radius_sess,rx_pkt,ipc_rep->mesg_len,ipc_rep_radiush,sizeof(rhp_proto_radius),rx_radiush);
		goto error;
	}


	if( !rhp_timer_delete(&(radius_sess_priv->retx_timer)) ){

		rhp_radius_sess_unhold(radius_sess);
		err_notify = 1;

	}else{

		RHP_TRC(0,RHPTRCID_RADIUS_MAIN_IPC_MESG_AUTH_HANDLER_TIMER_IS_ALREADY_EXEC,"dxxxx",worker_idx,ipc_rep,radius_sess,rx_pkt,&(radius_sess_priv->retx_timer));

		err = RHP_STATUS_RADIUS_RETX_REQ_ERR;
		goto error;
	}


	code = rx_radius_mesg->get_code(rx_radius_mesg);

	if( code == RHP_RADIUS_CODE_ACCESS_ACCEPT ){

		err = _rhp_radius_access_accept_rx_attrs(radius_sess,
						radius_sess_priv,rx_radius_mesg);
		if( err ){
			goto error;
		}

		((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rebound_rlm_id = ipc_rep->rebound_rlm_id;
		if( ((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rebound_rlm_id == RHP_VPN_REALM_ID_UNKNOWN ){
			((rhp_radius_mesg_priv*)rx_radius_mesg->priv)->rebound_rlm_id = 0;
		}

		if( ipc_rep->msk_len ){

			if( radius_sess_priv->msk ){
				_rhp_free_zero(radius_sess_priv->msk,radius_sess_priv->msk_len);
				radius_sess_priv->msk = NULL;
				radius_sess_priv->msk_len = 0;
			}

			radius_sess_priv->msk = (u8*)_rhp_malloc(ipc_rep->msk_len);
			if( radius_sess_priv->msk == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			memcpy(radius_sess_priv->msk,((u8*)(ipc_rep + 1)) + ipc_rep->mesg_len,ipc_rep->msk_len);
			radius_sess_priv->msk_len = ipc_rep->msk_len;

			RHP_TRC(0,RHPTRCID_RADIUS_MAIN_IPC_MESG_AUTH_HANDLER_MSK,"dxxxp",worker_idx,ipc_rep,radius_sess,rx_pkt,radius_sess_priv->msk_len,radius_sess_priv->msk);

		}else{

			RHP_TRC(0,RHPTRCID_RADIUS_MAIN_IPC_MESG_AUTH_HANDLER_NO_MSK,"dxxx",worker_idx,ipc_rep,radius_sess,rx_pkt);
		}


	}else if( code == RHP_RADIUS_CODE_ACCESS_CHALLENGE ){

		rhp_radius_attr* radius_attr_eap
			= rx_radius_mesg->get_attr_eap(rx_radius_mesg,RHP_PROTO_EAP_CODE_REQUEST,0);

		if( radius_attr_eap ){

			int eap_len = 0;
			rhp_proto_eap* eaph = radius_attr_eap->ext.eap->get_eap_packet(radius_attr_eap,&eap_len);
			if( eaph && eap_len >= sizeof(rhp_proto_eap_request) ){

				radius_sess_priv->eap_method = ((rhp_proto_eap_request*)eaph)->type;

				RHP_TRC(0,RHPTRCID_RADIUS_MAIN_IPC_MESG_AUTH_HANDLER_EAP_REQ_ATTR_EAP_METHOD,"dxxxpd",worker_idx,ipc_rep,radius_sess,rx_pkt,sizeof(rhp_proto_eap_request),eaph,radius_sess_priv->eap_method);

			}else{

				RHP_TRC(0,RHPTRCID_RADIUS_MAIN_IPC_MESG_AUTH_HANDLER_INVALID_EAP_REQ_ATTR,"dxxxxdd",worker_idx,ipc_rep,radius_sess,rx_pkt,eaph,eap_len,sizeof(rhp_proto_eap_request));
			}

		}else{

			RHP_TRC(0,RHPTRCID_RADIUS_MAIN_IPC_MESG_AUTH_HANDLER_NO_EAP_REQ_ATTR,"dxxx",worker_idx,ipc_rep,radius_sess,rx_pkt);
		}

		err = _rhp_radius_rx_attr_state(radius_sess,radius_sess_priv,rx_radius_mesg);
		if( err && err != -ENOENT ){
			goto error;
		}
		err = 0;
	}


	err_notify = 0;

	cb_ctx = radius_sess_priv->cb_ctx;

	{
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_RX_MESG,"rR",radius_sess,rx_radius_mesg);
		_rhp_radius_main_log_rx_mesg(radius_sess,rx_radius_mesg);
	}


  radius_sess_priv->ipc_txn_id = 0;

  if( radius_sess_priv->tx_access_req ){

		rhp_radius_mesg_unhold(radius_sess_priv->tx_access_req);
		rhp_pkt_unhold(radius_sess_priv->tx_access_pkt_ref);

		radius_sess_priv->tx_access_req = NULL;
		radius_sess_priv->tx_access_pkt_ref = NULL;
  }

	RHP_UNLOCK(&(radius_sess->lock));


	radius_sess_priv->receive_response(radius_sess,cb_ctx,rx_radius_mesg);


	{
		RHP_LOCK(&(rhp_radius_priv_lock));
		_rhp_radius_sess_ipc_remove(ipc_rep->txn_id);
		RHP_UNLOCK(&(rhp_radius_priv_lock));
	}

	rhp_pkt_unhold(rx_pkt);
	rhp_radius_mesg_unhold(rx_radius_mesg);

	rhp_radius_sess_unhold(radius_sess_ref);

	_rhp_free_zero(ipc_rep,ipc_rep->len);

	RHP_TRC(0,RHPTRCID_RADIUS_MAIN_IPC_MESG_AUTH_HANDLER_RTRN,"dxxxx",worker_idx,ipc_rep,radius_sess,rx_pkt,cb_ctx);
	return;


error:

	// if radius_sess != NULL, radius_sess is locked here.
	if( rx_radius_mesg ){

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(radius_sess ? radius_sess->vpn_realm_id : 0),RHP_LOG_ID_RADIUS_RX_MESG_AUTH_ERR,"rREE",radius_sess,rx_radius_mesg,err,ipc_rep->error);

	}else{

		u8 radiush_code = 0;
		u8 radiush_id = 0;
		u16 radiush_len = 0;

		if( ipc_rep_radiush ){
			radiush_code = ipc_rep_radiush->code;
			radiush_id = ipc_rep_radiush->id;
			radiush_len = ntohs(ipc_rep_radiush->len);
		}

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(radius_sess ? radius_sess->vpn_realm_id : 0),RHP_LOG_ID_RADIUS_RX_MESG_AUTH_ERR_2,"rbbwEE",radius_sess,radiush_code,radiush_id,radiush_len,err,ipc_rep->error);
	}

	if( radius_sess_ref ){

		void* cb_ctx = radius_sess_priv->cb_ctx;
		rhp_radius_mesg* tx_radius_mesg = radius_sess_priv->tx_access_req;

		rhp_radius_mesg_hold(tx_radius_mesg);

		if( radius_sess_priv->rx_pend_pkt_ref ){
			rhp_pkt_unhold(radius_sess_priv->rx_pend_pkt_ref);
			radius_sess_priv->rx_pend_pkt_ref = NULL;
		}

		if( radius_sess_priv ){
			radius_sess_priv->ipc_txn_id = 0;
		}

		RHP_UNLOCK(&(radius_sess->lock));


		if( err && err_notify &&
				_rhp_atomic_read(&(radius_sess->is_active)) ){

			radius_sess_priv->error_cb(radius_sess,cb_ctx,tx_radius_mesg,err);
		}

	  if( ipc_rep ){

			RHP_LOCK(&(rhp_radius_priv_lock));
			_rhp_radius_sess_ipc_remove(ipc_rep->txn_id);
			RHP_UNLOCK(&(rhp_radius_priv_lock));
		}

		rhp_radius_sess_unhold(radius_sess_ref);
		rhp_radius_mesg_unhold(tx_radius_mesg);
	}

  if( ipc_rep ){
  	_rhp_free_zero(ipc_rep,ipc_rep->len);
  }

  if( rx_pkt ){
  	rhp_pkt_unhold(rx_pkt);
  }

  if( rx_radius_mesg ){
  	rhp_radius_mesg_unhold(rx_radius_mesg);
  }

	RHP_TRC(0,RHPTRCID_RADIUS_MAIN_IPC_MESG_AUTH_HANDLER_ERR,"dxxxxE",worker_idx,ipc_rep,radius_sess,rx_pkt,cb_ctx,err);
	return;
}

static void _rhp_radius_main_ipc_mesg_sign_handler(int worker_idx,void* wts_ctx)
{
	int err = -EINVAL;
	rhp_ipcmsg_radius_mesg_sign_rep* ipc_rep = (rhp_ipcmsg_radius_mesg_sign_rep*)wts_ctx;
	rhp_radius_session_ref* radius_sess_ref = NULL;
	rhp_radius_session* radius_sess = NULL;
	rhp_radius_session_priv* radius_sess_priv = NULL;
	rhp_radius_mesg* tx_radius_mesg = NULL;
	rhp_packet* tx_pkt = NULL;
	u8 *tx_authenticator, *tx_auth_hash;
  rhp_proto_radius* tx_radiush;
	rhp_proto_radius_attr* radius_attr_mesg_auth;
	int tx_len;
	void* cb_ctx = NULL;

	RHP_TRC(0,RHPTRCID_RADIUS_MAIN_IPC_MESG_SIGN_HANDLER,"dx",worker_idx,ipc_rep);

	if( ipc_rep->len < sizeof(rhp_ipcmsg_radius_mesg_sign_rep) ){
		RHP_BUG("%d:%d",ipc_rep->len,sizeof(rhp_ipcmsg_radius_mesg_sign_rep));
		return;
	}

	if( ipc_rep->type != RHP_IPC_RADIUS_MESG_SIGN_REPLY ){
		RHP_BUG("%d",ipc_rep->type);
		return;
	}

	if( ipc_rep->result ){

		if( ipc_rep->authenticator_len != RHP_RADIUS_AUTHENTICATOR_LEN ){
			RHP_BUG("%d",ipc_rep->authenticator_len);
			return;
		}

		if( ipc_rep->mesg_hash_len &&
				ipc_rep->mesg_hash_len < RHP_RADIUS_MD5_SIZE ){
			RHP_BUG("%d",ipc_rep->authenticator_len);
			return;
		}
	}

	if( ipc_rep->len < sizeof(rhp_ipcmsg_radius_mesg_sign_rep)
										 + ipc_rep->authenticator_len + ipc_rep->mesg_hash_len ){
		RHP_BUG("%d, %d, %d, %d",ipc_rep->len,sizeof(rhp_ipcmsg_radius_mesg_sign_rep),ipc_rep->authenticator_len,ipc_rep->mesg_hash_len);
		return;
	}

	{
		RHP_LOCK(&(rhp_radius_priv_lock));

		radius_sess_ref = _rhp_radius_sess_ipc_get(ipc_rep->txn_id);
		if( radius_sess_ref == NULL ){
			err = -ENOENT;
			RHP_UNLOCK(&(rhp_radius_priv_lock));
			goto error;
		}
	  radius_sess = RHP_RADIUS_SESS_REF(radius_sess_ref);

		RHP_UNLOCK(&(rhp_radius_priv_lock));
	}


	RHP_LOCK(&(radius_sess->lock));

	tx_authenticator = (u8*)(ipc_rep + 1);
	tx_auth_hash = tx_authenticator + ipc_rep->authenticator_len;

	radius_sess_priv = (rhp_radius_session_priv*)radius_sess->priv;
	tx_radius_mesg = radius_sess_priv->tx_access_req;

	if( !_rhp_atomic_read(&(radius_sess->is_active)) ){
		err = -EINVAL;
		RHP_TRC(0,RHPTRCID_RADIUS_MAIN_IPC_MESG_SIGN_HANDLER_RADIUS_SESS_NOT_ACTIVE,"dxxx",worker_idx,ipc_rep,radius_sess,radius_sess_priv);
		goto error;
	}

	if( radius_sess_priv->tx_access_pkt_ref == NULL ){
		err = -EINVAL;
		RHP_TRC(0,RHPTRCID_RADIUS_MAIN_IPC_MESG_SIGN_HANDLER_TX_REQ_NOT_PENDING,"dxxx",worker_idx,ipc_rep,radius_sess,radius_sess_priv);
		goto error;
	}


	if( !ipc_rep->result ){
		err = RHP_STATUS_RADIUS_MESG_SIGN_ERR;
		RHP_TRC(0,RHPTRCID_RADIUS_MAIN_IPC_MESG_SIGN_HANDLER_SIGN_FAILED,"dxxx",worker_idx,ipc_rep,radius_sess,radius_sess_priv);
		goto error;
	}

	tx_pkt = RHP_PKT_REF(radius_sess_priv->tx_access_pkt_ref);
	tx_radiush = (rhp_proto_radius*)tx_pkt->app.raw;

	tx_len = ntohs(tx_radiush->len);

	tx_radius_mesg->set_authenticator(tx_radius_mesg,tx_authenticator);
	memcpy(tx_radiush->authenticator,tx_authenticator,ipc_rep->authenticator_len);

	if( tx_radiush->code == RHP_RADIUS_CODE_ACCESS_REQUEST ){

		if( ipc_rep->mesg_hash_len < 1 ){
			RHP_BUG("%d",ipc_rep->mesg_hash_len);
			goto error;
		}

		//
		//
		// [CAUTION] rhp_pkt_realloc() may be called. Don't access pointers of dmy_xxxhs,
		//           and radiush any more. Get a new pointer from pkt.
		//
		//
		radius_attr_mesg_auth
			= (rhp_proto_radius_attr*)rhp_pkt_expand_tail(tx_pkt,sizeof(rhp_proto_radius_attr) + ipc_rep->mesg_hash_len);
		if( radius_attr_mesg_auth == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}


		radius_attr_mesg_auth->len = sizeof(rhp_proto_radius_attr) + ipc_rep->mesg_hash_len;
		radius_attr_mesg_auth->type = RHP_RADIUS_ATTR_TYPE_MESG_AUTH;
		memset((u8*)(radius_attr_mesg_auth + 1),0,sizeof(rhp_proto_radius_attr) + ipc_rep->mesg_hash_len);

		// [CAUTION] rhp_pkt_realloc() may be called. Get a new pointer from pkt.
		tx_len += sizeof(rhp_proto_radius_attr) + ipc_rep->mesg_hash_len;
		tx_radiush = (rhp_proto_radius*)tx_pkt->app.raw;
		tx_radiush->len = htons(tx_len);

		memcpy((u8*)(radius_attr_mesg_auth + 1),tx_auth_hash,ipc_rep->mesg_hash_len);

		((rhp_radius_mesg_priv*)tx_radius_mesg->priv)->tx_mesg_len += tx_len;
	}


	{
		if( tx_pkt->type == RHP_PKT_IPV4_RADIUS ){

			// [CAUTION] rhp_pkt_realloc() may be called. Get a new pointer from pkt.
			tx_pkt->l3.iph_v4->total_len = htons(sizeof(rhp_proto_ip_v4) + sizeof(rhp_proto_udp) + tx_len);
			tx_pkt->l3.iph_v4->src_addr = radius_sess->nas_addr.addr.v4;

		}else if( tx_pkt->type == RHP_PKT_IPV6_RADIUS ){

			// [CAUTION] rhp_pkt_realloc() may be called. Get a new pointer from pkt.
			tx_pkt->l3.iph_v6->payload_len = htons(sizeof(rhp_proto_udp) + tx_len);
			memcpy(tx_pkt->l3.iph_v6->src_addr,radius_sess->nas_addr.addr.v6,16);
		}

		// [CAUTION] rhp_pkt_realloc() may be called. Get a new pointer from pkt.
		tx_pkt->l4.udph->len = htons(sizeof(rhp_proto_udp) + tx_len);
		tx_pkt->l4.udph->src_port = radius_sess->nas_addr.port;
	}

  err = 0;

  radius_sess_priv->retx_counter = 0;
  radius_sess_priv->retx_timer.ctx = rhp_radius_sess_hold_ref(radius_sess);
  rhp_timer_reset(&(radius_sess_priv->retx_timer));
  rhp_timer_add(&(radius_sess_priv->retx_timer),radius_sess->retransmit_interval);

	RHP_TRC(0,RHPTRCID_RADIUS_MAIN_IPC_MESG_SIGN_HANDLER_SIGN_TX_PKT,"dxxxdpa",worker_idx,ipc_rep,radius_sess,radius_sess_priv,radius_sess_priv->sk,tx_len,(u8*)tx_radiush,((tx_pkt->l4.raw + ntohs(tx_pkt->l4.udph->len)) - tx_pkt->l2.raw),RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,tx_pkt->l2.raw);

	if( tx_radius_mesg->get_code(tx_radius_mesg) == RHP_RADIUS_CODE_ACCESS_REQUEST ){
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,radius_sess->vpn_realm_id,RHP_LOG_ID_RADIUS_TX_ACCESS_REQUEST,"rR",radius_sess,tx_radius_mesg);
	}

	if( rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_RADIUS] &&
			(!rhp_packet_capture_realm_id || !rhp_packet_capture_realm_id == radius_sess->vpn_realm_id) ){

		_rhp_radius_sess_pcap_write(tx_pkt);
	}

  err = send(radius_sess_priv->sk,tx_radiush,tx_len,0);
	if( err < 0 ){
		// The packet will be retransmitted later...
		RHP_TRC(0,RHPTRCID_RADIUS_MAIN_IPC_MESG_SIGN_HANDLER_TX_ERR,"dxxxddE",worker_idx,ipc_rep,radius_sess,radius_sess_priv,radius_sess_priv->sk,err,-errno);
	}


  radius_sess_priv->ipc_txn_id = 0;

  cb_ctx = radius_sess_priv->cb_ctx;

	RHP_UNLOCK(&(radius_sess->lock));
	rhp_radius_sess_unhold(radius_sess_ref);

	{
		RHP_LOCK(&(rhp_radius_priv_lock));
		_rhp_radius_sess_ipc_remove(ipc_rep->txn_id);
		RHP_UNLOCK(&(rhp_radius_priv_lock));
	}

	_rhp_free_zero(ipc_rep,ipc_rep->len);

	RHP_TRC(0,RHPTRCID_RADIUS_MAIN_IPC_MESG_SIGN_HANDLER_RTRN,"dxxxxd",worker_idx,ipc_rep,radius_sess,radius_sess_priv,cb_ctx,err);
	return;


error:
	// if radius_sess != NULL, radius_sess is locked here.
	if( tx_radius_mesg &&
			tx_radius_mesg->get_code(tx_radius_mesg) == RHP_RADIUS_CODE_ACCESS_REQUEST ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(radius_sess ? radius_sess->vpn_realm_id : 0),RHP_LOG_ID_RADIUS_TX_ACCESS_REQUEST_SIGN_ERR,"rR",radius_sess,tx_radius_mesg);
	}

	if( radius_sess_ref && radius_sess_priv ){

		cb_ctx = radius_sess_priv->cb_ctx;


	  if( radius_sess_priv->tx_access_req ){

	  	rhp_radius_mesg_unhold(radius_sess_priv->tx_access_req);
	  	radius_sess_priv->tx_access_req = NULL;

	  	rhp_pkt_unhold(radius_sess_priv->tx_access_pkt_ref);
	  	radius_sess_priv->tx_access_pkt_ref = NULL;
	  }

	  radius_sess_priv->ipc_txn_id = 0;

	  if( tx_radius_mesg ){
	  	rhp_radius_mesg_hold(tx_radius_mesg);
	  }

		RHP_UNLOCK(&(radius_sess->lock));


		if( err && _rhp_atomic_read(&(radius_sess->is_active)) ){

			radius_sess_priv->error_cb(radius_sess,cb_ctx,tx_radius_mesg,err);
		}

	  if( ipc_rep ){
			RHP_LOCK(&(rhp_radius_priv_lock));
			_rhp_radius_sess_ipc_remove(ipc_rep->txn_id);
			RHP_UNLOCK(&(rhp_radius_priv_lock));
		}

	  rhp_radius_sess_unhold(radius_sess_ref);
	  if( tx_radius_mesg ){
	  	rhp_radius_mesg_unhold(tx_radius_mesg);
	  }
	}

  if( ipc_rep ){
  	_rhp_free_zero(ipc_rep,ipc_rep->len);
  }

	RHP_TRC(0,RHPTRCID_RADIUS_MAIN_IPC_MESG_SIGN_HANDLER_ERR,"dxxxxE",worker_idx,ipc_rep,radius_sess,radius_sess_priv,cb_ctx,err);
	return;
}


static rhp_prc_ipcmsg_wts_handler _rhp_radius_main_mesg_auth_ipc = {
	wts_type: RHP_WTS_DISP_RULE_AUTHREP,
	wts_disp_priority: RHP_WTS_DISP_LEVEL_HIGH_1,
	wts_disp_wait: 1,
	wts_is_fixed_rule: 0,
	wts_task_handler: _rhp_radius_main_ipc_mesg_auth_handler
};

static rhp_prc_ipcmsg_wts_handler _rhp_radius_main_mesg_sign_ipc = {
	wts_type: RHP_WTS_DISP_RULE_AUTHREP,
	wts_disp_priority: RHP_WTS_DISP_LEVEL_HIGH_1,
	wts_disp_wait: 1,
	wts_is_fixed_rule: 0,
	wts_task_handler: _rhp_radius_main_ipc_mesg_sign_handler
};


extern int rhp_radius_syspxy_set_secret(int index,u8* key,int key_len);

int rhp_radius_impl_set_secret(int index,u8* secret,int secret_len)
{
	int err = -EINVAL;

	if( secret == NULL || secret_len < 1 ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
		RHP_BUG("");
		return -EPERM;
	}

  err = rhp_radius_syspxy_set_secret(index,secret,secret_len);

error:
	RHP_TRC(0,RHPTRCID_RADIUS_IMPL_SET_SECRET,"dpE",index,secret_len,secret,err);
	return err;
}


extern int rhp_radius_syspxy_init();
extern int rhp_radius_syspxy_cleanup();

int rhp_radius_impl_init()
{
	int err = -EINVAL;

  if( RHP_MY_PROCESS->role == RHP_PROCESS_ROLE_MAIN ){

  	_rhp_mutex_init("RGL",&rhp_radius_priv_lock);

  	memset(_rhp_radius_sess_ipc_holder_htbl,0,sizeof(rhp_radius_sess_ipc_holder*)*RHP_RADIUS_SESS_HASH_TABLE_SIZE);

  	if( rhp_random_bytes((u8*)&_rhp_radius_sess_ipc_holder_htbl_rnd,sizeof(_rhp_radius_sess_ipc_holder_htbl_rnd)) ){
  	  RHP_BUG("");
  	  return -EINVAL;
  	}


		err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_RADIUS_MESG_AUTH_REPLY,
						NULL,&_rhp_radius_main_mesg_auth_ipc);
		if( err ){
			RHP_BUG("");
			return err;
		}

		err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_RADIUS_MESG_SIGN_REPLY,
						NULL,&_rhp_radius_main_mesg_sign_ipc);
		if( err ){
			RHP_BUG("");
			return err;
		}


		err = rhp_main_epoll_register(
						RHP_MAIN_EPOLL_EVENT_RADIUS_RX,
						_rhp_radius_session_epoll_event_cb);
		if( err ){
			RHP_BUG("%d",err);
			return err;
		}


  }else if( RHP_MY_PROCESS->role == RHP_PROCESS_ROLE_SYSPXY ){

  	err = rhp_radius_syspxy_init();
  	if( err ){
			RHP_BUG("");
			return err;
		}
  }

	RHP_TRC(0,RHPTRCID_RADIUS_IMPL_INIT,"");

  return 0;
}

int rhp_radius_impl_cleanup()
{
	int err;

  if( RHP_MY_PROCESS->role == RHP_PROCESS_ROLE_SYSPXY ){

  	err = rhp_radius_syspxy_cleanup();
		if( err ){
			RHP_BUG("");
			return err;
		}

  }else{

  	_rhp_mutex_destroy(&rhp_radius_priv_lock);
  }

	RHP_TRC(0,RHPTRCID_RADIUS_IMPL_CLEANUP,"");
  return 0;
}
