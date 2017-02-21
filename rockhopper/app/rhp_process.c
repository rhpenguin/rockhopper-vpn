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
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_wthreads.h"

//
// [Linux 2.6]
// 	Current capabilities : /proc/<pid>/status :
// 		CapInh: xxxxxx              Inheritable
// 		CapPrm:	xxxxxx							Permitted
// 		CapEff:	xxxxxx								Effective <=== See this!!!!
// 		CapBnd:	xxxxxx							Bounding Set
//

//
// TODO : Linking with libcap2 for new 64bits capabilities
//

rhp_atomic_t rhp_process_is_active;

int rhp_process_my_role = -1; //  RHP_PROCESS_ROLE_XXX

rhp_process rhp_process_info[RHP_PROCESS_ROLE_MAX+1]; // index :  RHP_PROCESS_ROLE_XXX

int rhp_process_init(uid_t uid,gid_t gid,uid_t syspxy_uid,gid_t syspxy_gid,
		int debug,int core_dump,char* main_user_name,char* syspxy_user_name)
{
  int i;
  int err = 0;
  rhp_process* prc;
  int m2s_p[2];
  int s2m_p[2];

  _rhp_atomic_init(&rhp_process_is_active);

  if( pipe2(m2s_p, O_NONBLOCK) < 0 ){
  	err = -errno;
  	RHP_BUG("%d",err);
  	goto error;
  }

  if( pipe2(s2m_p,O_NONBLOCK) < 0 ){
  	close(m2s_p[0]);
  	close(m2s_p[1]);
  	err = -errno;
  	RHP_BUG("%d",err);
  	goto error;
  }

  for( i = 0; i <= RHP_PROCESS_ROLE_MAX;i++ ){

  	char* user_name;

    prc = &(rhp_process_info[i]);

    memset(prc,0,sizeof(rhp_process));

    prc->tag[0] = '#';
    prc->tag[1] = 'P';
    prc->tag[2] = 'R';
    prc->tag[3] = 'C';


    prc->role = i;
    prc->pid = getpid();

    if( prc->role == RHP_PROCESS_ROLE_SYSPXY ){
      prc->uid = syspxy_uid;
      prc->gid = syspxy_gid;
      user_name = syspxy_user_name;
      prc->ipc_read_pipe = m2s_p[0];
      prc->ipc_write_pipe = s2m_p[1];
    }else{
      prc->uid = uid;
      prc->gid = gid;
      user_name = main_user_name;
      prc->ipc_read_pipe = s2m_p[0];
      prc->ipc_write_pipe = m2s_p[1];
    }

    {
			prc->user_name = (char*)_rhp_malloc(strlen(user_name) + 1);
			if( prc->user_name == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}
			prc->user_name[0] = '\0';
			strcpy(prc->user_name,user_name);
    }


    prc->debug = debug;
    prc->core_dump = core_dump;

    RHP_TRC(0,RHPTRCID_PRC_INIT,"xLu",prc,"PROCESS_ROLE",prc->role);
  }

  rhp_process_my_role = RHP_PROCESS_ROLE_SYSPXY;

  return 0;

error:
	RHP_TRC(0,RHPTRCID_PRC_INIT_ERR,"E",err);
	return err;
}

void rhp_free_caps(rhp_process* prc)
{
  if( prc->caps ){

    RHP_TRC(0,RHPTRCID_PRC_FREE_CAPS,"xLu",prc,"PROCESS_ROLE",prc->role);

    cap_free(prc->caps);
    prc->caps = 0;

  }else{
    RHP_BUG("");
  }
}

int rhp_caps_set(rhp_process* prc,int allowed_caps_num,cap_value_t* allowed_caps)
{
  int err = -EPERM;

  if( RHP_MY_PROCESS->core_dump && RHP_MY_PROCESS->debug ){
    RHP_LINE(" CORE_DUMP enabled. rhp_caps_set() was ignored.");
  	return 0;
  }

  if( prctl(PR_SET_KEEPCAPS,1) < 0 ){
    RHP_BUG("%s,%d",strerror(errno),errno);
    return -EPERM;
  }

  if( (err = setregid(prc->gid,prc->gid)) ){
    RHP_BUG("%s,%d",strerror(errno),errno);
    return -EPERM;
  }

  if( (err = setreuid(prc->uid,prc->uid)) ){
    RHP_BUG("%s,%d",strerror(errno),errno);
    return -EPERM;
  }

  if( ( prc->caps = cap_init() ) == NULL ){
    RHP_BUG("%s,%d",strerror(errno),errno);
    return -EPERM;
  }

  if( cap_clear(prc->caps) == -1 ){
    RHP_BUG("%s,%d",strerror(errno),errno);
    err = -errno;
    goto error;
  }

  if( cap_set_flag(prc->caps,CAP_PERMITTED,allowed_caps_num,allowed_caps,CAP_SET) ){
    RHP_BUG("%s,%d",strerror(errno),errno);
    err = -errno;
    goto error;
  }

  if( cap_set_flag(prc->caps,CAP_EFFECTIVE,allowed_caps_num,allowed_caps,CAP_SET) ){
    RHP_BUG("%s,%d",strerror(errno),errno);
    err = -errno;
    goto error;
  }

  if( cap_set_flag(prc->caps,CAP_INHERITABLE,allowed_caps_num,allowed_caps,CAP_SET) ){
    RHP_BUG("%s,%d",strerror(errno),errno);
    err = -errno;
    goto error;
  }

  if( cap_set_proc(prc->caps) ){
    RHP_BUG("%s,%d",strerror(errno),errno);
    err = -errno;
    goto error;
  }

  RHP_TRC(0,RHPTRCID_PRC_CAPS_SET,"xLu",prc,"PROCESS_ROLE",prc->role);

  return 0;

error:
  rhp_free_caps(prc);
  return err;
}

void rhp_ipc_close(rhp_process* prc)
{
  RHP_TRC(0,RHPTRCID_IPC_CLOSE,"xLudd",prc,"PROCESS_ROLE",prc->role,prc->ipc_read_pipe,prc->ipc_write_pipe);
  if( prc->ipc_read_pipe >= 0 ){
		close(prc->ipc_read_pipe);
		prc->ipc_read_pipe = -1;
  }
  if( prc->ipc_write_pipe >= 0 ){
  	close(prc->ipc_write_pipe);
  	prc->ipc_write_pipe = -1;
  }
}

void rhp_ipc_send_nop(rhp_process* prc,int buflen) // For debug...
{
	rhp_ipcmsg* ipcmsg;
	u8* buf = NULL;
	ssize_t n;
	int i;

  RHP_TRC(0,RHPTRCID_IPC_SEND_NOP,"xd",prc,buflen);

	ipcmsg = (rhp_ipcmsg*)_rhp_malloc(sizeof(rhp_ipcmsg) + buflen);
	if( ipcmsg == NULL ){
		RHP_BUG("");
		return;
	}

	ipcmsg->tag[0] = '#';
	ipcmsg->tag[1] = 'I';
	ipcmsg->tag[2] = 'M';
	ipcmsg->tag[3] = 'S';
	ipcmsg->len = sizeof(rhp_ipcmsg) + buflen;
	ipcmsg->type = RHP_IPC_NOP;

	buf = (u8*)(ipcmsg + 1);
	for( i = 0; i < buflen; i++){
		*(buf + i) = 'X';
	}

	n = rhp_ipc_send(prc,(void*)ipcmsg,ipcmsg->len,0);

  RHP_TRC(0,RHPTRCID_IPC_SEND_NOP_RTRN,"xdd",prc,buflen,n);
	return;
}

ssize_t rhp_ipc_send(rhp_process* prc,void *buf,size_t len,int flags)
{
  ssize_t n = 0;
  int rem = len,cur = 0;
  int cnt = 0;

  RHP_TRC_FREQ(0,RHPTRCID_IPC_SEND,"xLuddpx",prc,"PROCESS_ROLE",prc->role,prc->ipc_read_pipe,prc->ipc_write_pipe,len,buf,flags);
  RHP_TRC(0,RHPTRCID_IPC_MSG_TX,"xuuLd",prc,RHP_PEER_PROCESS->pid,((rhp_ipcmsg*)buf)->len,"IPC",((rhp_ipcmsg*)buf)->type);

  if( prc->ipc_write_pipe < 0 ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  while( rem > 0 ){

  	 n = write(prc->ipc_write_pipe,(((u8*)buf) + cur),rem);
  	 if( n < 0 ){

  		 n = -errno;

  		 if( n != -EINTR ){
  			 break;
  		 }
  	 }

  	 if( !RHP_PROCESS_IS_ACTIVE() ){
  		 n = -EINVAL;
  		 break;
  	 }

  	 rem -= n;
  	 cur += n;
  	 cnt++;
  }

  RHP_TRC(0,RHPTRCID_IPC_SEND_RTRN,"xxdE",prc,buf,cnt,n);
  return n;
}

static void _rhp_ipc_recv_discard(rhp_process* prc,ssize_t len,int flags)
{
	int err = -EINVAL;
  ssize_t n;
  int rem = len;
  u8 discard_buf[128];

  RHP_TRC(0,RHPTRCID_IPC_RECV_DISCARD,"xLdxd",prc,"PROCESS_ROLE",prc->role,flags,len);

	while( rem > 0 ){

		n = read(prc->ipc_read_pipe,discard_buf,128);
		if( n < 0 ){

			err = -errno;

			if( err != -EINTR ){
		    RHP_TRC(0,RHPTRCID_IPC_RECVMSG_READ_HDR_ERROR,"xuE",prc,RHP_PEER_PROCESS->pid,err);
				goto error;
			}
		}

		if( !RHP_PROCESS_IS_ACTIVE() ){
			n = -EINVAL;
			goto error;
		}

		rem -= n;
  }

error:
  RHP_TRC(0,RHPTRCID_IPC_RECV_DISCARD_RTRN,"xE",prc,err);
  return;
}

int rhp_ipc_recvmsg(rhp_process* prc,rhp_ipcmsg **msg,int flags)
{
  int err;
  rhp_ipcmsg msghdr;
  rhp_ipcmsg *retmsg = NULL;
	ssize_t n;
  int rem,cur;
  int cnt;
  u8* rbuf;

  RHP_TRC(0,RHPTRCID_IPC_RECVMSG,"xLdxddd",prc,"PROCESS_ROLE",prc->role,msg,flags,prc->ipc_read_pipe,prc->ipc_write_pipe);

  if( prc->ipc_read_pipe < 0 ){
  	RHP_BUG("");
  	return -EINVAL;
  }

	memset(&msghdr,0,sizeof(rhp_ipcmsg));
	rem = sizeof(rhp_ipcmsg);
	rbuf = (u8*)&msghdr;
	cur = 0;
	cnt = 0;

	while( rem > 0 ){

		n = read(prc->ipc_read_pipe,(rbuf + cur),rem);
		if( n < 0 ){

			err = -errno;

			if( err != -EINTR ){
		    RHP_TRC(0,RHPTRCID_IPC_RECVMSG_READ_HDR_ERROR,"xuE",prc,RHP_PEER_PROCESS->pid,err);
				goto error;
			}

		}else if( n == 0 ){

			RHP_TRC(0,RHPTRCID_IPC_RECVMSG_READ_HDR_PIPE_CLOSED,"xu",prc,RHP_PEER_PROCESS->pid);
			err = -EPIPE;
			goto abort;
		}

		if( !RHP_PROCESS_IS_ACTIVE() ){
			n = -EINVAL;
			goto abort;
		}

		rem -= n;
		cur += n;
		cnt += n;
  }

  RHP_TRC(0,RHPTRCID_IPC_RECVMSG_READ_HDR,"xuuLdp",prc,RHP_PEER_PROCESS->pid,msghdr.len,"IPC",msghdr.type,sizeof(rhp_ipcmsg),&msghdr);

  if( msghdr.len < sizeof(rhp_ipcmsg) ){
    err = -EMSGSIZE;
    RHP_TRC(0,RHPTRCID_IPC_RECVMSG_READ_INVALID_HDR_LEN,"xuuu",prc,RHP_PEER_PROCESS->pid,msghdr.len,sizeof(rhp_ipcmsg));
		goto abort;
  }

  if( msghdr.tag[0] != '#' || msghdr.tag[1] != 'I' || msghdr.tag[2] != 'M' || msghdr.tag[3] != 'S' ){ // magic number : '#IMS'
    RHP_TRC(0,RHPTRCID_IPC_RECVMSG_READ_INVALID_HDR_BAD_MAGIC,"xup",prc,RHP_PEER_PROCESS->pid,sizeof(rhp_ipcmsg),&msghdr);
    RHP_BUG("");
		goto abort;
  }

  retmsg = (rhp_ipcmsg*)_rhp_malloc(msghdr.len);
  if( retmsg == NULL ){

  	err = -ENOMEM;
    RHP_BUG("");

    _rhp_ipc_recv_discard(prc,msghdr.len - sizeof(rhp_ipcmsg),0);
    goto error;
  }

  memcpy(retmsg,&msghdr,sizeof(rhp_ipcmsg));

	rem = msghdr.len - sizeof(rhp_ipcmsg);
	rbuf = (u8*)(retmsg + 1);
	cur = 0;

	while( rem > 0 ){

		n = read(prc->ipc_read_pipe,(rbuf + cur),rem);
		if( n < 0 ){

			err = -errno;

			if( err != -EINTR ){
		    RHP_TRC(0,RHPTRCID_IPC_RECVMSG_READ_BODY_ERROR,"xuE",prc,RHP_PEER_PROCESS->pid,err);
				goto error;
			}

		}else if( n == 0 ){

	    RHP_TRC(0,RHPTRCID_IPC_RECVMSG_READ_BODY_PIPE_CLOSED,"xu",prc,RHP_PEER_PROCESS->pid);
	    err = -EPIPE;
			goto abort;
		}

		if( !RHP_PROCESS_IS_ACTIVE() ){
			n = -EINVAL;
			goto abort;
		}

		rem -= n;
		cur += n;
		cnt += n;
  }

  *msg = retmsg;

  RHP_TRC(0,RHPTRCID_IPC_RECVMSG_RTRN,"xxp",prc,*msg,msghdr.len,*msg);
  return 0;

error:
  if( retmsg ){
    _rhp_free(retmsg);
  }

  RHP_TRC(0,RHPTRCID_IPC_RECVMSG_ERR,"xE",prc,err);
  return err;

abort:
	RHP_BUG("ABORT IPC!");
	if( retmsg ){
		_rhp_free(retmsg);
	}
	rhp_ipc_close(prc);
	RHP_TRC(0,RHPTRCID_IPC_RECVMSG_ABORT_ERR,"xE",prc,err);
	return err;
}


rhp_ipcmsg* rhp_ipc_alloc_msg(unsigned long type,size_t len)
{
  rhp_ipcmsg* ipc_msg = (rhp_ipcmsg*)_rhp_malloc(len);

  if( ipc_msg == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(ipc_msg,0,len);

  ipc_msg->tag[0] = '#';
  ipc_msg->tag[1] = 'I';
  ipc_msg->tag[2] = 'M';
  ipc_msg->tag[3] = 'S';

  ipc_msg->type = type;

  RHP_TRC(0,RHPTRCID_IPC_ALLOC_MSG,"xLdd",ipc_msg,"IPC",type,len);
  return ipc_msg;
}

void rhp_ipc_send_exit()
{
  int err = 0;
  rhp_ipcmsg* ipcmsg;

  RHP_TRC(0,RHPTRCID_IPC_SEND_EXIT,"");

  ipcmsg = (rhp_ipcmsg*)rhp_ipc_alloc_msg(RHP_IPC_EXIT_REQUEST,sizeof(rhp_ipcmsg));

  if( ipcmsg == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  ipcmsg->len = sizeof(rhp_ipcmsg);

  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipcmsg,ipcmsg->len,0) < 0 ){
    err = -EINVAL;
    RHP_TRC(0,RHPTRCID_IPC_SEND_EXIT_SEND_ERR,"E",err);
    goto error;
  }

error:
  if( ipcmsg ){
    _rhp_free_zero(ipcmsg,ipcmsg->len);
  }

  RHP_TRC(0,RHPTRCID_IPC_SEND_EXIT_RTRN,"");
  return;
}


int rhp_ipc_register_handler(rhp_process* prc,unsigned long ipcmsg_type,
		void (*ipcmsg_handler)(struct _rhp_ipcmsg** ipcmsg),rhp_prc_ipcmsg_wts_handler* wts_handler_ctx)
{
	rhp_prc_ipcmsg_handler* hdlr;

  RHP_TRC(0,RHPTRCID_IPC_REGISTER_HANDLER,"xLdLdYx",prc,"PROCESS_ROLE",prc->role,"IPC",ipcmsg_type,ipcmsg_handler,wts_handler_ctx);
  if( wts_handler_ctx ){
    RHP_TRC(0,RHPTRCID_IPC_REGISTER_HANDLER_WTS,"xLdLdxLuLdddY",prc,"PROCESS_ROLE",prc->role,"IPC",ipcmsg_type,wts_handler_ctx,"WTS_DISP_RULE_FLAG",wts_handler_ctx->wts_type,"WTS_DISP_LEVEL_FLAG",wts_handler_ctx->wts_disp_priority,wts_handler_ctx->wts_disp_wait,wts_handler_ctx->wts_is_fixed_rule,wts_handler_ctx->wts_task_handler);
  }


	hdlr = (rhp_prc_ipcmsg_handler*)_rhp_malloc(sizeof(rhp_prc_ipcmsg_handler));
	if( hdlr == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}
	memset(hdlr,0,sizeof(rhp_prc_ipcmsg_handler));

	hdlr->next = NULL;
	hdlr->ipcmsg_type = ipcmsg_type;

	if( ipcmsg_handler ){
		hdlr->ipcmsg_handler = ipcmsg_handler;
	}else if( wts_handler_ctx ){
		hdlr->wts_handler_ctx = wts_handler_ctx;
	}else{
		RHP_BUG("");
	}

	hdlr->next = prc->ipcmsg_handlers;
	prc->ipcmsg_handlers = hdlr;

	return 0;
}

void rhp_ipc_call_handler(rhp_process* prc,rhp_ipcmsg** ipcmsg)
{
	int err = -EINVAL;
	rhp_prc_ipcmsg_handler* hdlr = prc->ipcmsg_handlers;
	int n = 0;

	while( hdlr ){

		if( (*ipcmsg)->type == hdlr->ipcmsg_type ){

			if( hdlr->ipcmsg_handler ){

				hdlr->ipcmsg_handler(ipcmsg);

			}else if( hdlr->wts_handler_ctx ){

				rhp_prc_ipcmsg_wts_handler* wts_handler_ctx = hdlr->wts_handler_ctx;

				if( wts_handler_ctx->wts_task_handler ){

					if( wts_handler_ctx->wts_disp_wait ){

						err = rhp_wts_dispach_check(wts_handler_ctx->wts_disp_priority,
										wts_handler_ctx->wts_is_fixed_rule);

						if( err ){ // Waiting...
							RHP_BUG("%d",err);
							goto ignore;
						}

					}else{

						if( !rhp_wts_dispach_ok(wts_handler_ctx->wts_disp_priority,wts_handler_ctx->wts_is_fixed_rule) ){
							goto ignore;
						}
					}

					err = rhp_wts_add_task(wts_handler_ctx->wts_type,wts_handler_ctx->wts_disp_priority,*ipcmsg,
										wts_handler_ctx->wts_task_handler,*ipcmsg);

					if( err ){
						RHP_BUG("%d",err);
						goto ignore;
					}

					*ipcmsg = NULL;
				}
			}

ignore:
			n++;
			break;
		}

		hdlr = hdlr->next;
	}

	if( n == 0 ){
		RHP_BUG("%d",(*ipcmsg)->type);
	}

	return;
}


