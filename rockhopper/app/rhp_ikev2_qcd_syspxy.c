/*

	Copyright (C) 2009-2013 TETSUHARU HANADA <rhpenguine@gmail.com>
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

char* rhp_syspxy_qcd_secret_path = NULL;

#define RHP_IKEV2_QCD_SECRET_LEN	64 // bytes
static u8 _rhp_ikev2_qcd_secret[RHP_IKEV2_QCD_SECRET_LEN];

static rhp_atomic_t _rhp_ikev2_qcd_syspxy_pend_reqs;


int rhp_ikev2_qcd_get_my_token(int my_side,u8* my_ikesa_spi,u8* peer_ikesa_spi,u8* token_r)
{
	int err = -EINVAL;
	u8 buf[RHP_PROTO_IKE_SPI_SIZE*2];
	u8* hmac_buf_r = NULL;
	int hmac_buf_len_r = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_QCD_GET_MY_TOKEN,"LdGGx","IKE_SIDE",my_side,my_ikesa_spi,peer_ikesa_spi,token_r);

	if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
		RHP_BUG("");
		return -EINVAL;
  }

	if( my_side == RHP_IKE_INITIATOR ){
		memcpy(buf,my_ikesa_spi,RHP_PROTO_IKE_SPI_SIZE);
		memcpy(buf + RHP_PROTO_IKE_SPI_SIZE,peer_ikesa_spi,RHP_PROTO_IKE_SPI_SIZE);
	}else{
		memcpy(buf,peer_ikesa_spi,RHP_PROTO_IKE_SPI_SIZE);
		memcpy(buf + RHP_PROTO_IKE_SPI_SIZE,my_ikesa_spi,RHP_PROTO_IKE_SPI_SIZE);
	}


	err = rhp_crypto_hmac(RHP_CRYPTO_HMAC_SHA2_512,
					buf,RHP_PROTO_IKE_SPI_SIZE*2,_rhp_ikev2_qcd_secret,RHP_IKEV2_QCD_SECRET_LEN,
					&hmac_buf_r,&hmac_buf_len_r);

	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	if( hmac_buf_len_r < RHP_IKEV2_QCD_TOKEN_LEN ){
		RHP_BUG("%d");
		err = -EINVAL;
		goto error;
	}

	memcpy(token_r,hmac_buf_r,RHP_IKEV2_QCD_TOKEN_LEN);

	_rhp_free(hmac_buf_r);

  RHP_TRC(0,RHPTRCID_IKEV2_QCD_GET_MY_TOKEN_RTRN,"LdGGp","IKE_SIDE",my_side,my_ikesa_spi,peer_ikesa_spi,RHP_IKEV2_QCD_TOKEN_LEN,token_r);
	return 0;

error:
	if( hmac_buf_r ){
		_rhp_free(hmac_buf_r);
	}
  RHP_TRC(0,RHPTRCID_IKEV2_QCD_GET_MY_TOKEN_RTRN,"LdGGE","IKE_SIDE",my_side,my_ikesa_spi,peer_ikesa_spi,err);
	return err;
}


static void _rhp_ikev2_qcd_syspxy_gen_rep_tkn_req_task(int worker_idx,void *ctx)
{
	int err = -EINVAL;
	rhp_ipcmsg_qcd_gen_rep_tkn_req* ipc_req = (rhp_ipcmsg_qcd_gen_rep_tkn_req*)ctx;
	rhp_ipcmsg_qcd_gen_rep_tkn_rep* ipc_rep = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_QCD_SYSPXY_GEN_REP_TKN_REQ_TASK,"dx",worker_idx,ipc_req);

	if( ipc_req->len < sizeof(rhp_ipcmsg_qcd_gen_rep_tkn_req) ){
		RHP_BUG("%d:%d",ipc_req->len,sizeof(rhp_ipcmsg_qcd_gen_rep_tkn_req));
		goto error;
	}

	if( ipc_req->len < sizeof(rhp_ipcmsg_qcd_gen_rep_tkn_req) + ipc_req->cookie_len ){
		RHP_BUG("%d:%d",ipc_req->len,sizeof(rhp_ipcmsg_qcd_gen_rep_tkn_req) + ipc_req->cookie_len);
		goto error;
	}

	if( ipc_req->type != RHP_IPC_QCD_GEN_REPLY_TOKEN_REQUEST ){
		RHP_BUG("%d",ipc_req->type);
		goto error;
	}

	if( ipc_req->cookie_len < 1 ){
		RHP_BUG("%d",ipc_req->cookie_len);
		goto error;
	}

	{
		ipc_rep
		= (rhp_ipcmsg_qcd_gen_rep_tkn_rep*)rhp_ipc_alloc_msg(RHP_IPC_QCD_GEN_REPLY_TOKEN_REPLY,
				sizeof(rhp_ipcmsg_qcd_gen_rep_tkn_rep) + ipc_req->cookie_len);

		if( ipc_rep == NULL ){
			RHP_BUG("");
			goto error;
		}

		ipc_rep->len = sizeof(rhp_ipcmsg_qcd_gen_rep_tkn_rep) + ipc_req->cookie_len;

		ipc_rep->cookie_len = ipc_req->cookie_len;
		memcpy((u8*)(ipc_rep + 1),(u8*)(ipc_req + 1),ipc_req->cookie_len);
	}


	err = rhp_ikev2_qcd_get_my_token(RHP_IKE_INITIATOR,ipc_req->init_spi,ipc_req->resp_spi,ipc_rep->token);
	if( err ){
		goto error;
	}

	if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipc_rep,ipc_rep->len,0) < 0 ){
		RHP_BUG("");
		goto error;
  }

error:
	if( ipc_req ){
		_rhp_free_zero(ipc_req,ipc_req->len);
	}
	if( ipc_rep ){
		_rhp_free_zero(ipc_rep,ipc_rep->len);
	}

	_rhp_atomic_dec(&_rhp_ikev2_qcd_syspxy_pend_reqs);

  RHP_TRC(0,RHPTRCID_IKEV2_QCD_SYSPXY_GEN_REP_TKN_REQ_TASK_RTRN,"dxE",worker_idx,ipc_req,err);
	return;
}

static void _rhp_ikev2_qcd_syspxy_gen_rep_tkn_req_ipc_handler(rhp_ipcmsg** ipcmsg)
{
	int err = -EINVAL;

  RHP_TRC(0,RHPTRCID_IKEV2_QCD_SYSPXY_GEN_REP_TKN_REQ_IPC_HANDLER,"xxf",ipcmsg,*ipcmsg,_rhp_ikev2_qcd_syspxy_pend_reqs.lock);

	if( _rhp_atomic_read(&_rhp_ikev2_qcd_syspxy_pend_reqs) >= rhp_gcfg_ikev2_qcd_syspxy_max_pend_reqs ){
	  RHP_TRC(0,RHPTRCID_IKEV2_QCD_SYSPXY_GEN_REP_TKN_REQ_IPC_HANDLER_MAX_PEND_REQS,"xx",ipcmsg,*ipcmsg);
		goto ignore;
	}

  if( rhp_wts_dispach_ok(RHP_WTS_DISP_LEVEL_LOW_3,1) ){

    _rhp_atomic_inc(&_rhp_ikev2_qcd_syspxy_pend_reqs);

    // QCD task is dispatched to a MISC worker.
  	err = rhp_wts_add_task(RHP_WTS_DISP_RULE_MISC,RHP_WTS_DISP_LEVEL_LOW_3,NULL,
  			_rhp_ikev2_qcd_syspxy_gen_rep_tkn_req_task,*ipcmsg);

  	if( err ){
      _rhp_atomic_dec(&_rhp_ikev2_qcd_syspxy_pend_reqs);
  		goto ignore;
  	}

    *ipcmsg = NULL;

  }else{

	  RHP_TRC(0,RHPTRCID_IKEV2_QCD_SYSPXY_GEN_REP_TKN_REQ_IPC_HANDLER_MAX_DISP,"xx",ipcmsg,*ipcmsg);
		goto ignore;
  }

  err = 0;

ignore:
	RHP_TRC(0,RHPTRCID_IKEV2_QCD_SYSPXY_GEN_REP_TKN_REQ_IPC_HANDLER_RTRN,"xxE",ipcmsg,*ipcmsg,err);
	return;
}

static void _rhp_ikev2_qcd_syspxy_tkn_req_ipc_handler(rhp_ipcmsg** ipcmsg)
{
	int err = -EINVAL;
	rhp_ipcmsg_qcd_token_req* ipc_req = (rhp_ipcmsg_qcd_token_req*)*ipcmsg;
	rhp_ipcmsg_qcd_token_rep ipc_rep;

	RHP_TRC(0,RHPTRCID_IKEV2_QCD_SYSPXY_TKN_REQ_IPC_HANDLER,"xx",ipcmsg,*ipcmsg);

	if( ipc_req->len < sizeof(rhp_ipcmsg_qcd_token_req) ){
		RHP_BUG("%d:%d",ipc_req->len,sizeof(rhp_ipcmsg_qcd_token_req));
		return;
	}

	if( ipc_req->type != RHP_IPC_QCD_TOKEN_REQUEST ){
		RHP_BUG("%d",ipc_req->type);
		return;
	}

	{
		memset(&ipc_rep,0,sizeof(rhp_ipcmsg_qcd_token_rep));

		ipc_rep.tag[0] = '#';
		ipc_rep.tag[1] = 'I';
		ipc_rep.tag[2] = 'M';
		ipc_rep.tag[3] = 'S';

		ipc_rep.type = RHP_IPC_QCD_TOKEN_REPLY;
		ipc_rep.len = sizeof(rhp_ipcmsg_qcd_token_rep);

		ipc_rep.txn_id = ipc_req->txn_id;
		ipc_rep.my_realm_id = ipc_req->my_realm_id;
		ipc_rep.side = ipc_req->side;
		memcpy(ipc_rep.spi,ipc_req->spi,RHP_PROTO_IKE_SPI_SIZE);
		memcpy(ipc_rep.peer_spi,ipc_req->peer_spi,RHP_PROTO_IKE_SPI_SIZE);

		if( ipc_req->old_ikesa ){

			ipc_rep.old_ikesa = 1;
			ipc_rep.old_side = ipc_req->old_side;
			memcpy(ipc_rep.old_spi,ipc_req->old_spi,RHP_PROTO_IKE_SPI_SIZE);
			memcpy(ipc_rep.old_peer_spi,ipc_req->old_peer_spi,RHP_PROTO_IKE_SPI_SIZE);
		}
	}


	err = rhp_ikev2_qcd_get_my_token(ipc_req->side,ipc_req->spi,ipc_req->peer_spi,ipc_rep.my_token);
	if( err ){
		ipc_rep.result = 0;
	}else{
		ipc_rep.result = 1;
	}

	if( rhp_ipc_send(RHP_MY_PROCESS,(void*)&ipc_rep,ipc_rep.len,0) < 0 ){
		RHP_BUG("");
		goto error;
  }

	err = 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_QCD_SYSPXY_TKN_REQ_IPC_HANDLER_RTRN,"xxE",ipcmsg,*ipcmsg,err);
	return;
}

int rhp_ikev2_qcd_syspxy_init()
{
	int err = -EINVAL;


	if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
		RHP_BUG("");
		return -EINVAL;
  }

	memset(_rhp_ikev2_qcd_secret,0,RHP_IKEV2_QCD_SECRET_LEN);

	err = rhp_file_read_data(rhp_syspxy_qcd_secret_path,RHP_IKEV2_QCD_SECRET_LEN,_rhp_ikev2_qcd_secret);
	if( err ){

		if( unlink(rhp_syspxy_qcd_secret_path) < 0 ){
			RHP_TRC(0,RHPTRCID_IKEV2_QCD_SYSPXY_INIT_UNLINK_QCD_SECRET_FILE_ERR,"sE",rhp_syspxy_qcd_secret_path,-errno);
		}

		err = rhp_random_bytes(_rhp_ikev2_qcd_secret,RHP_IKEV2_QCD_SECRET_LEN);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		err = rhp_file_write(rhp_syspxy_qcd_secret_path,
						_rhp_ikev2_qcd_secret,RHP_IKEV2_QCD_SECRET_LEN,(S_IRUSR | S_IWUSR | S_IXUSR));
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
	}

  if( rhp_gcfg_dbg_log_keys_info ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_QCD_SECRET,"p",RHP_IKEV2_QCD_SECRET_LEN,_rhp_ikev2_qcd_secret);
  }


	{
		err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_QCD_TOKEN_REQUEST,
				_rhp_ikev2_qcd_syspxy_tkn_req_ipc_handler,NULL);

		if( err ){
			RHP_BUG("");
			goto error;
		}

		err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_QCD_GEN_REPLY_TOKEN_REQUEST,
				_rhp_ikev2_qcd_syspxy_gen_rep_tkn_req_ipc_handler,NULL);

		if( err ){
			RHP_BUG("");
			goto error;
		}
	}

  _rhp_atomic_init(&_rhp_ikev2_qcd_syspxy_pend_reqs);
  _rhp_atomic_set(&_rhp_ikev2_qcd_syspxy_pend_reqs,0);

	RHP_TRC(0,RHPTRCID_IKEV2_QCD_SYSPXY_INIT_OK,"");
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_QCD_SYSPXY_INIT_ERR,"E",err);
	return err;
}

int rhp_ikev2_qcd_syspxy_cleanup()
{

	if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
		RHP_BUG("");
		return -EINVAL;
  }

	RHP_TRC(0,RHPTRCID_IKEV2_QCD_SYSPXY_CLEANUP_OK,"");
	return 0;
}
