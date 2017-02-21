/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
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
#include <fcntl.h>
#include <libxml/encoding.h>
#include <libxml/xmlwriter.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "rhp_version.h"
#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_protocol.h"
#include "rhp_wthreads.h"
#include "rhp_timer.h"
#include "rhp_config.h"
#include "rhp_crypto.h"
#include "rhp_http.h"
#include "rhp_ui.h"

struct _rhp_http_clt_get_ctx;

struct _rhp_http_clt_get_sess {

	u8 tag[4]; // '#HCS'

	int sk;
  rhp_epoll_ctx sk_epoll_ctx;

	u8* rx_buf;
	int rx_buf_len;
	u8* body_buf; // Just a reference. Don't free this.
	int body_buf_len;

	int url_idx;
	char* url_hostname;
	char* url_port;
	char* url_path;

	struct _rhp_http_clt_get_ctx* get_ctx;
};
typedef struct _rhp_http_clt_get_sess	rhp_http_clt_get_sess;

struct _rhp_http_clt_get_ctx {

	u8 tag[4]; // '#HCG'

	rhp_mutex_t lock;
	rhp_atomic_t refcnt;

	rhp_timer timer;
	time_t timeout;

	int urls_num;
	char** urls;

	rhp_http_clt_get_sess* get_sess_list; // Array[urls_num]
	int completed;

	void (*callback)(void* cb_ctx,int err,int rx_buf_num,int* rx_buf_lens,u8** rx_bufs);
	void* cb_ctx;
	int cb_called;

	int addr_family; // AF_INET or AF_INET6

	struct epoll_event epoll_evt;
};
typedef struct _rhp_http_clt_get_ctx	rhp_http_clt_get_ctx;

static rhp_atomic_t _rhp_http_clt_sk_num;

static void _rhp_http_clt_close_sk(int* sk)
{
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_CLG_CLOSE_SK,"xdf",sk,*sk,_rhp_atomic_read(&_rhp_http_clt_sk_num));

	if( *sk < 0 ){
		RHP_BUG("");
		return;
	}
	_rhp_atomic_dec(&_rhp_http_clt_sk_num);
	close(*sk);
	*sk = -1;
}

long rhp_http_clt_get_open_sk_num()
{
	long n = _rhp_atomic_read(&_rhp_http_clt_sk_num);
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_CLT_OPEN_SK_NUM,"f",n);
	return n;
}


int rhp_http_clt_init()
{
	_rhp_atomic_init(&_rhp_http_clt_sk_num);
	return 0;
}

int rhp_http_clt_cleanup()
{
	_rhp_atomic_destroy(&_rhp_http_clt_sk_num);
	return 0;
}

static void _rhp_http_clt_get_free_ctx(rhp_http_clt_get_ctx* task_ctx);

#ifndef RHP_REFCNT_DEBUG

static void _rhp_http_clt_get_hold(rhp_http_clt_get_ctx* task_ctx)
{
  _rhp_atomic_inc(&(task_ctx->refcnt));
}

static void _rhp_http_clt_get_unhold(rhp_http_clt_get_ctx* task_ctx)
{
	if( _rhp_atomic_dec_and_test(&(task_ctx->refcnt)) ){
		_rhp_http_clt_get_free_ctx((task_ctx);
}

#else // RHP_REFCNT_DEBUG

#define _rhp_http_clt_get_hold(task_ctx)\
{\
	RHP_LINE("#RHP_HTTP_CLT_GET_HOLD 0x%x:vpn->refcnt.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",(task_ctx),(task_ctx)->refcnt.c,rhp_func_trc_current());\
  _rhp_atomic_inc(&((task_ctx)->refcnt));\
}

#define _rhp_http_clt_get_unhold(task_ctx)\
{\
	RHP_LINE("#RHP_HTTP_CLT_GET_UNHOLD 0x%x:vpn->refcnt.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",(task_ctx),(task_ctx)->refcnt.c,rhp_func_trc_current());\
	if( _rhp_atomic_dec_and_test(&((task_ctx)->refcnt)) ){\
  	RHP_LINE("#RHP_HTTP_CLT_GET_UNHOLD_DESTROY 0x%x:vpn->refcnt.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",(task_ctx),(task_ctx)->refcnt.c,rhp_func_trc_current());\
  	_rhp_http_clt_get_free_ctx((task_ctx));\
  }\
}
#endif // RHP_REFCNT_DEBUG

static int _rhp_http_clt_get_sk_epoll_mod(rhp_http_clt_get_sess* hcg_sess,int event_type)
{
	int err = -EINVAL;
	struct epoll_event ep_evt;

  RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_SK_EPOLL_MOD,"xLddsss",hcg_sess,"MAIN_EOPLL_EVENT",event_type,hcg_sess->url_idx,hcg_sess->url_hostname,hcg_sess->url_port,hcg_sess->url_path);

	hcg_sess->sk_epoll_ctx.event_type = event_type;

	memset(&ep_evt,0,sizeof(struct epoll_event));
	ep_evt.events = EPOLLIN | EPOLLONESHOT;
	ep_evt.data.ptr = (void*)&(hcg_sess->sk_epoll_ctx);

	if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_MOD,hcg_sess->sk,&ep_evt) < 0 ){
		err = -errno;
		RHP_BUG("%d",err);
		goto error;
	}

  RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_SK_EPOLL_MOD_RTRN,"xLd",hcg_sess,"MAIN_EOPLL_EVENT",event_type);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_SK_EPOLL_MOD_ERR,"xLdE",hcg_sess,"MAIN_EOPLL_EVENT",event_type,err);
	return err;
}

static void _rhp_http_clt_get_sk_close(rhp_http_clt_get_sess* hcg_sess)
{
  RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_SK_CLOSE,"xddsss",hcg_sess,hcg_sess->sk,hcg_sess->url_idx,hcg_sess->url_hostname,hcg_sess->url_port,hcg_sess->url_path);
	if( hcg_sess->sk != -1 ){

	  struct epoll_event ep_evt;

  	memset(&ep_evt,0,sizeof(struct epoll_event));

    if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_DEL,hcg_sess->sk,&ep_evt) < 0 ){
      RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_SK_CLOSE_EPOLL_ERR,"xE",hcg_sess,-errno);
    }

		_rhp_http_clt_close_sk(&(hcg_sess->sk));
	}
}

static void _rhp_http_clt_get_free_ctx(rhp_http_clt_get_ctx* task_ctx)
{
	int i;

  RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_FREE_CTX,"x",task_ctx);

	if( task_ctx ){

		if( task_ctx->urls ){

			for( i = 0; i < task_ctx->urls_num; i++ ){

				rhp_http_clt_get_sess* hcg_sess = &(task_ctx->get_sess_list[i]);

				if( task_ctx->urls[i] ){
					_rhp_free(task_ctx->urls[i]);
				}

				if( hcg_sess->get_ctx ){
					RHP_BUG("");
				}

				_rhp_http_clt_get_sk_close(hcg_sess);

				if( hcg_sess->rx_buf ){
					_rhp_free(hcg_sess->rx_buf);
				}

				if( hcg_sess->url_hostname ){
					_rhp_free(hcg_sess->url_hostname);
				}

				if( hcg_sess->url_port ){
					_rhp_free(hcg_sess->url_port);
				}

				if( hcg_sess->url_path ){
					_rhp_free(hcg_sess->url_path);
				}
			}

			_rhp_free(task_ctx->get_sess_list);
			_rhp_free(task_ctx->urls);
		}

		if( rhp_timer_pending(&(task_ctx->timer)) ){
			RHP_BUG("");
		}

		_rhp_mutex_destroy(&(task_ctx->lock));
		_rhp_atomic_destroy(&(task_ctx->refcnt));

		_rhp_free(task_ctx);
	}

  RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_FREE_CTX_RTRN,"x",task_ctx);
	return;
}


static void _rhp_http_clt_get_timer_handler(void *ctx,rhp_timer *timer)
{
	int err = -EINVAL;
	rhp_http_clt_get_ctx* task_ctx = (rhp_http_clt_get_ctx*)ctx;
	int i;

  RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_TIMER_HANDLER,"xxd",task_ctx,timer,task_ctx->cb_called);

	RHP_LOCK(&(task_ctx->lock));

	for( i = 0; i < task_ctx->urls_num; i++ ){

		rhp_http_clt_get_sess* hcg_sess = &(task_ctx->get_sess_list[i]);

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_HTTP_CLT_GET_TIMEOUT,"sss",hcg_sess->url_hostname,hcg_sess->url_port,hcg_sess->url_path);

		_rhp_http_clt_get_sk_close(hcg_sess);
	}

	// Can't cancel getaddrinfo()'s blocking invoked by rhp_dns_resolve()...
	// Just wait for the timeout.

	err = -ETIMEDOUT;

	if( !task_ctx->cb_called ){
		task_ctx->callback(task_ctx->cb_ctx,err,0,NULL,NULL);
		task_ctx->cb_called = 1;
	}


	RHP_UNLOCK(&(task_ctx->lock));
	_rhp_http_clt_get_hold(task_ctx);

  RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_TIMER_HANDLER_RTRN,"xx",task_ctx,timer);
	return;
}

static int _rhp_http_clt_send(int sk,u8* tx_buf,int tx_buf_len)
{
  int err = -EINVAL;
  int n = 0;
  int c = 0;

  RHP_TRC(0,RHPTRCID_HTTP_CLT_SEND,"dp",sk,tx_buf_len,tx_buf);

  while( n < tx_buf_len ){

    c = send(sk,(tx_buf + n),(tx_buf_len - n),0);
    if( c < 0 ){

      err = -errno;

      if( err == -EINTR ){
        continue;
      }

      RHP_TRC(0,RHPTRCID_HTTP_CLT_SEND_ERR,"dxE",sk,tx_buf,err);
      return err;
    }
    n += c;
  }

  RHP_TRC(0,RHPTRCID_HTTP_CLT_SEND_RTRN,"dx",sk,tx_buf);
  return 0;
}

#define RHP_HTTP_CLT_GET_REQ_LEN(uri,hostname,useragent)	\
(strlen("GET ") + strlen((uri)) + strlen(" HTTP/1.0") + strlen("\r\n") + \
((hostname) ? (strlen("HOST: ") + strlen((hostname)) + strlen("\r\n")) : 0) + \
((useragent) ? (strlen("User-Agent: ") + strlen((useragent)) + strlen("\r\n")) : 0) + \
 strlen("\r\n"))

static int _rhp_http_clt_get_tx_req(rhp_http_clt_get_ctx* task_ctx,rhp_http_clt_get_sess* hcg_sess)
{
	int err = -EINVAL;
	u8* tx_buf = NULL;
	size_t tx_buf_len = RHP_HTTP_CLT_GET_REQ_LEN(hcg_sess->url_path,hcg_sess->url_hostname,RHP_PRODUCT_NAME) + 1;

  RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_TX_REQ,"xxdsss",task_ctx,hcg_sess,hcg_sess->url_idx,hcg_sess->url_hostname,hcg_sess->url_port,hcg_sess->url_path);

	tx_buf = (u8*)_rhp_malloc(tx_buf_len);
	if( tx_buf == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memset(tx_buf,0,tx_buf_len);

	snprintf((char*)tx_buf,tx_buf_len,"GET %s HTTP/1.0\r\nHOST: %s\r\nUser-Agent: %s\r\n\r\n",
			hcg_sess->url_path,hcg_sess->url_hostname,RHP_PRODUCT_NAME);


	err = _rhp_http_clt_send(hcg_sess->sk,tx_buf,(tx_buf_len - 1));
	if( err ){
		goto error;
	}

	_rhp_free(tx_buf);

  RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_TX_REQ_RTRN,"xx",task_ctx,hcg_sess);
	return 0;

error:
	if( tx_buf ){
		_rhp_free(tx_buf);
	}
  RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_TX_REQ_ERR,"xxE",task_ctx,hcg_sess,err);
	return err;
}

static int _rhp_http_clt_get_sess_connect(rhp_http_clt_get_ctx* task_ctx,rhp_http_clt_get_sess* hcg_sess,
		int addr_family,size_t http_server_addr_len,struct sockaddr *http_server_addr)
{
	int err = -EINVAL;
  int flag;
	struct epoll_event ep_evt;
	long sk_num;

  RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_SESS_CONNECT,"xxLddsssfx",task_ctx,hcg_sess,"AF",addr_family,hcg_sess->url_idx,hcg_sess->url_hostname,hcg_sess->url_port,hcg_sess->url_path,http_server_addr_len,http_server_addr);


  if( (sk_num = _rhp_atomic_read(&_rhp_http_clt_sk_num)) >= rhp_gcfg_http_clt_get_max_reqs ){
	  RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_SESS_CONNECT_MAX_REQS,"xxf",task_ctx,hcg_sess,sk_num);
  	err = RHP_STATUS_HTTP_CLT_MAX_REQS_REACHED;
  	goto error;
  }


	hcg_sess->sk = socket(addr_family,SOCK_STREAM,0);
	if( hcg_sess->sk < 0 ){
		err = -errno;
    RHP_BUG("%d",err);
		goto error;
	}

	_rhp_atomic_inc(&_rhp_http_clt_sk_num);

  if( (flag = fcntl(hcg_sess->sk,F_GETFL)) < 0 ){
    err = -errno;
    RHP_BUG("%d",err);
    goto error;
  }

  if( fcntl(hcg_sess->sk,F_SETFL,flag|O_NONBLOCK) < 0 ){
    err = -errno;
    RHP_BUG("%d",err);
    goto error;
  }

	hcg_sess->sk_epoll_ctx.event_type = RHP_MAIN_EPOLL_HTTP_CLT_GET_CONNECT;
	hcg_sess->sk_epoll_ctx.params[0] = (unsigned long)task_ctx;
	hcg_sess->sk_epoll_ctx.params[1] = (unsigned long)hcg_sess;

	{
		memset(&ep_evt,0,sizeof(struct epoll_event));
		ep_evt.events = EPOLLOUT | EPOLLONESHOT;
		ep_evt.data.ptr = (void*)&(hcg_sess->sk_epoll_ctx);

		if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_ADD,hcg_sess->sk,&ep_evt) < 0 ){
			err = -errno;
			RHP_BUG("%d",err);
			goto error;
		}
  }

	err = connect(hcg_sess->sk,http_server_addr,http_server_addr_len);
	if( err < 0 ){

		err = -errno;
		if( err == -EINPROGRESS ){
			err = 0;
		  RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_SESS_CONNECT_PEND,"xxd",task_ctx,hcg_sess,hcg_sess->sk);
			goto pending;
		}

	  RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_SESS_CONNECT_CONN_ERR,"xxE",task_ctx,hcg_sess,err);
		goto error;

	}else{

	  RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_SESS_CONNECT_DONE,"xxd",task_ctx,hcg_sess,hcg_sess->sk);

		err = _rhp_http_clt_get_tx_req(task_ctx,hcg_sess);
		if( err ){
			goto error;
		}

		err = _rhp_http_clt_get_sk_epoll_mod(hcg_sess,RHP_MAIN_EPOLL_HTTP_CLT_GET_RECV);
		if( err ){
			goto error;
		}
	}

pending:
	RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_SESS_CONNECT_RTRN,"xxd",task_ctx,hcg_sess,hcg_sess->sk);
	return 0;

error:

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_HTTP_CLT_GET_CONN_ERR,"sssE",hcg_sess->url_hostname,hcg_sess->url_port,hcg_sess->url_path,err);
	_rhp_http_clt_get_sk_close(hcg_sess);

  RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_SESS_CONNECT_ERR,"xxE",task_ctx,hcg_sess,err);
	return err;
}

union _rhp_http_clt_sin {
  struct sockaddr_in 	v4;
  struct sockaddr_in6 v6;
  unsigned char raw;
};
typedef union _rhp_http_clt_sin	rhp_http_clt_sin;

static void _rhp_http_clt_set_sin(rhp_ip_addr* ip_addr,rhp_http_clt_get_sess* hcg_sess,rhp_http_clt_sin* my_sin,size_t* my_sin_len)
{
	if( ip_addr->addr_family == AF_INET ){

		my_sin->v4.sin_family = AF_INET;
		my_sin->v4.sin_port = htons(hcg_sess->url_port ? (u16)atoi(hcg_sess->url_port) : 80);
		my_sin->v4.sin_addr.s_addr = ip_addr->addr.v4;
		*my_sin_len = sizeof(struct sockaddr_in);

	}else if( ip_addr->addr_family == AF_INET6 ){

		my_sin->v6.sin6_family = AF_INET6;
		my_sin->v6.sin6_port = htons(hcg_sess->url_port ? (u16)atoi(hcg_sess->url_port) : 80);
		memcpy(my_sin->v6.sin6_addr.s6_addr,ip_addr->addr.v6,16);
		*my_sin_len = sizeof(struct sockaddr_in6);
	}
}

void _rhp_http_clt_get_start_sess_dns_cb(void* cb_ctx0,void* cb_ctx1,int err,
		int res_addrs_num,rhp_ip_addr* res_addrs)
{
	rhp_http_clt_get_ctx* task_ctx = (rhp_http_clt_get_ctx*)cb_ctx0;
	rhp_http_clt_get_sess* hcg_sess = (rhp_http_clt_get_sess*)cb_ctx1;
  size_t my_sin_len = 0;
  rhp_http_clt_sin my_sin;
  int i;
  int addr_family = AF_UNSPEC;

  RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_START_SESS_DNS_CB,"xxEdx",cb_ctx0,cb_ctx1,err,res_addrs_num,res_addrs);

  memset(&my_sin,0,sizeof(rhp_http_clt_sin));

	RHP_LOCK(&(task_ctx->lock));

	if( err ){
		goto error;
	}

	if( task_ctx->cb_called ){
		err = -EINVAL;
		goto error;
	}

	if( hcg_sess->get_ctx == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	for( i = 0; i < res_addrs_num; i++ ){

		if( res_addrs[i].addr_family == task_ctx->addr_family ){

			if( res_addrs[i].addr_family == AF_INET ){

				_rhp_http_clt_set_sin(&(res_addrs[i]),hcg_sess,&my_sin,&my_sin_len);
				addr_family = AF_INET;
				RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_START_SESS_DNS_CB_RES_ADDR,"xx4w",cb_ctx0,cb_ctx1,my_sin.v4.sin_addr.s_addr,my_sin.v4.sin_port);

				break;

			}else if( res_addrs[i].addr_family == AF_INET6 ){

				_rhp_http_clt_set_sin(&(res_addrs[i]),hcg_sess,&my_sin,&my_sin_len);
				addr_family = AF_INET6;
				RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_START_SESS_DNS_CB_RES_ADDR_V6,"xx6w",cb_ctx0,cb_ctx1,my_sin.v6.sin6_addr.s6_addr,my_sin.v6.sin6_port);

				break;
			}
		}
	}

	if( i == res_addrs_num ){

		_rhp_http_clt_set_sin(&(res_addrs[0]),hcg_sess,&my_sin,&my_sin_len);
		addr_family = res_addrs[0].addr_family;

		if( res_addrs[0].addr_family == AF_INET ){
			RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_START_SESS_DNS_CB_RES_ADDR_2,"xx4w",cb_ctx0,cb_ctx1,my_sin.v4.sin_addr.s_addr,my_sin.v4.sin_port);
		}else if( res_addrs[0].addr_family == AF_INET6 ){
			RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_START_SESS_DNS_CB_RES_ADDR_V6_2,"xx6w",cb_ctx0,cb_ctx1,my_sin.v6.sin6_addr.s6_addr,my_sin.v6.sin6_port);
		}
	}

	err = _rhp_http_clt_get_sess_connect(task_ctx,hcg_sess,
					addr_family,my_sin_len,(struct sockaddr*)&(my_sin.raw));
	if( err ){
		goto error;
	}


	RHP_UNLOCK(&(task_ctx->lock));

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_HTTP_CLT_GET_DNS_OK,"sss",hcg_sess->url_hostname,hcg_sess->url_port,hcg_sess->url_path);

  RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_START_SESS_DNS_CB_RTRN,"xx",cb_ctx0,cb_ctx1);
	return;

error:
	if( err != RHP_STATUS_HTTP_CLT_MAX_REQS_REACHED ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_HTTP_CLT_GET_DNS_ERR,"sssE",hcg_sess->url_hostname,hcg_sess->url_port,hcg_sess->url_path,err);
	}

	if( !task_ctx->cb_called ){
		task_ctx->callback(task_ctx->cb_ctx,err,0,NULL,NULL);
		task_ctx->cb_called = 1;
	}

	task_ctx->completed++;

	if( task_ctx->completed == task_ctx->urls_num ){

		if( !rhp_timer_delete(&(task_ctx->timer)) ){
			_rhp_http_clt_get_unhold(task_ctx);
		}
	}

	hcg_sess->get_ctx = NULL;

	RHP_UNLOCK(&(task_ctx->lock));
	_rhp_http_clt_get_unhold(task_ctx);

  RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_START_SESS_DNS_CB_ERR,"xxE",cb_ctx0,cb_ctx1,err);
	return;
}

static int _rhp_http_clt_get_start_sess(rhp_http_clt_get_ctx* task_ctx,rhp_http_clt_get_sess* hcg_sess)
{
	int err = -EINVAL;
	struct addrinfo hints;
	struct in6_addr httpsvr_addr;
	struct addrinfo* res = NULL;
	int addr_family = AF_UNSPEC;
	long sk_num;

  RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_START_SESS,"xxdsss",task_ctx,hcg_sess,hcg_sess->url_idx,hcg_sess->url_hostname,hcg_sess->url_port,hcg_sess->url_path);

  if( (sk_num = _rhp_atomic_read(&_rhp_http_clt_sk_num)) >= rhp_gcfg_http_clt_get_max_reqs ){
    RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_START_SESS_MAX_REQS,"xxf",task_ctx,hcg_sess,sk_num);
  	err = RHP_STATUS_HTTP_CLT_MAX_REQS_REACHED;
  	goto error;
  }

	memset(&hints,0,sizeof(struct addrinfo));
	hints.ai_flags = AI_NUMERICSERV;
	hints.ai_socktype = SOCK_STREAM;

	err = inet_pton(AF_INET,hcg_sess->url_hostname,&httpsvr_addr);
	if( err != 1 ){

		err = inet_pton(AF_INET6,hcg_sess->url_hostname,&httpsvr_addr);
  	if( err != 1 ){

			_rhp_http_clt_get_hold(task_ctx);
			hcg_sess->get_ctx = (void*)task_ctx;

			err = rhp_dns_resolve(RHP_WTS_DISP_LEVEL_HIGH_2,hcg_sess->url_hostname,AF_UNSPEC,
					_rhp_http_clt_get_start_sess_dns_cb,task_ctx,hcg_sess);

			if( err ){
				hcg_sess->get_ctx = NULL;
				_rhp_http_clt_get_unhold(task_ctx);
				goto error;
			}

			RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_START_SESS_DNS_RES_PEND,"xx",task_ctx,hcg_sess);
			goto end;

  	}else{

  		if( rhp_gcfg_ipv6_disabled ){
  			err = RHP_STATUS_IPV6_DISABLED;
  			goto error;
  		}

  		addr_family = AF_INET6;
  	}

	}else{

		addr_family = AF_INET;
	}


	hints.ai_family = AF_UNSPEC;
  hints.ai_flags |= AI_NUMERICHOST; // getaddrinfo() will NOT block.

  err = getaddrinfo(hcg_sess->url_hostname,(hcg_sess->url_port ? hcg_sess->url_port : "80"),
  				&hints,&res);
  if( err ){
		err = -err;
    RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_START_SESS_GEADDRINFO_ERR,"xxE",task_ctx,hcg_sess,err);
		goto error;
	}

	_rhp_http_clt_get_hold(task_ctx);
	hcg_sess->get_ctx = (void*)task_ctx;

	err = _rhp_http_clt_get_sess_connect(task_ctx,hcg_sess,addr_family,res->ai_addrlen,res->ai_addr);
	if( err ){
		hcg_sess->get_ctx = NULL;
		_rhp_http_clt_get_unhold(task_ctx);
		goto error;
	}

end:
	if( res ){
		freeaddrinfo(res);
	}

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_HTTP_CLT_GET_START,"sss",hcg_sess->url_hostname,hcg_sess->url_port,hcg_sess->url_path,err);

	RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_START_SESS_RTRN,"xx",task_ctx,hcg_sess);
	return 0;

error:
	if( err != RHP_STATUS_HTTP_CLT_MAX_REQS_REACHED ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_HTTP_CLT_GET_START_ERR,"sssE",hcg_sess->url_hostname,hcg_sess->url_port,hcg_sess->url_path,err);
	}

	if( res ){
		freeaddrinfo(res);
	}
	RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_START_SESS_ERR,"xxE",task_ctx,hcg_sess,err);
	return err;
}

static void _rhp_http_clt_get_start_task(int worker_index,void *ctx)
{
	int err = -EINVAL;
	rhp_http_clt_get_ctx* task_ctx = (rhp_http_clt_get_ctx*)ctx;
	int i;

	RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_START_TASK,"dx",worker_index,task_ctx);

	RHP_LOCK(&(task_ctx->lock));

	rhp_timer_init(&(task_ctx->timer),_rhp_http_clt_get_timer_handler,(void*)task_ctx);


	_rhp_http_clt_get_hold(task_ctx);

	err = rhp_timer_add(&(task_ctx->timer),task_ctx->timeout);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}


	for( i = 0; i < task_ctx->urls_num; i++ ){

		err = _rhp_http_clt_get_start_sess(task_ctx,&(task_ctx->get_sess_list[i]));
		if( err ){
			task_ctx->completed++;
			RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_START_TASK_START_SESS_ERR,"dxxE",worker_index,task_ctx,&(task_ctx->get_sess_list[i]),err);
		}
	}

	if( task_ctx->completed == task_ctx->urls_num ){

		if( !rhp_timer_delete(&(task_ctx->timer)) ){
			_rhp_http_clt_get_unhold(task_ctx);
		}

		RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_START_TASK_ALL_ERR,"dx",worker_index,task_ctx);

		err = -EINVAL;
		goto error;
	}

	RHP_UNLOCK(&(task_ctx->lock));
	_rhp_http_clt_get_unhold(task_ctx);

	RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_START_TASK_RTRN,"dx",worker_index,task_ctx);
	return;

error:

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_HTTP_CLT_GET_START_TASK_ERR,"E",err);

	if( !task_ctx->cb_called ){
		task_ctx->callback(task_ctx->cb_ctx,err,0,NULL,NULL);
		task_ctx->cb_called = 1;
	}

	RHP_UNLOCK(&(task_ctx->lock));
	_rhp_http_clt_get_unhold(task_ctx);

	RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_START_TASK_ERR,"dxE",worker_index,task_ctx,err);
	return;
}

int rhp_http_clt_get(int urls_num,char** urls,
		time_t timeout /*secs*/,
		int addr_family,
		void (*callback)(void* cb_ctx,int err,int rx_buf_num,int* rx_buf_lens,u8** rx_bufs),void* cb_ctx,
		int (*check_http_server_name)(char* server_name))
{
	int err = -EINVAL;
	rhp_http_clt_get_ctx* task_ctx = NULL;
	int i;

	{
		RHP_TRC(0,RHPTRCID_HTTP_CLT_GET,"dxfLdYx",urls_num,urls,timeout,"AF",addr_family,callback,cb_ctx);
		_RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
	  if( _RHP_TRC_COND(_rhp_trc_user_id(),0) ){
	  	for( i = 0; i < urls_num;i++ ){
	  		RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_URL_DATA,"xs",cb_ctx,urls[i]);
	  	}
	  }
	}

	if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_MAIN ){
		RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

	task_ctx = (rhp_http_clt_get_ctx*)_rhp_malloc(sizeof(rhp_http_clt_get_ctx));
	if( task_ctx == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	memset(task_ctx,0,sizeof(rhp_http_clt_get_ctx));

	task_ctx->tag[0] = '#';
	task_ctx->tag[1] = 'H';
	task_ctx->tag[2] = 'C';
	task_ctx->tag[3] = 'G';

	task_ctx->callback = callback;
	task_ctx->cb_ctx = cb_ctx;
	task_ctx->addr_family = addr_family;


	task_ctx->urls = (char**)_rhp_malloc(sizeof(char*)*urls_num);
	if( task_ctx->urls == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	memset(task_ctx->urls,(long)NULL,sizeof(char*)*urls_num);

	task_ctx->urls_num = urls_num;

	task_ctx->get_sess_list = (rhp_http_clt_get_sess*)_rhp_malloc(sizeof(rhp_http_clt_get_sess)*urls_num);
	if( task_ctx->get_sess_list == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	memset(task_ctx->get_sess_list,0,sizeof(rhp_http_clt_get_sess)*urls_num);

	for( i = 0; i < urls_num; i++ ){

		rhp_http_clt_get_sess* hcg_sess = &(task_ctx->get_sess_list[i]);

		hcg_sess->tag[0] = '#';
		hcg_sess->tag[1] = 'H';
		hcg_sess->tag[2] = 'C';
		hcg_sess->tag[3] = 'S';

		hcg_sess->sk = -1;

		hcg_sess->url_idx = i;
	}


	_rhp_mutex_init("HCG",&(task_ctx->lock));
	_rhp_atomic_init(&(task_ctx->refcnt));

	task_ctx->timeout = timeout;

	for( i = 0; i < urls_num; i++ ){

		int len = strlen(urls[i]) + 1;

		task_ctx->urls[i] = (char*)_rhp_malloc(len);
		if( task_ctx->urls[i] == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		memcpy(task_ctx->urls[i],urls[i],len);

		{
			rhp_http_clt_get_sess* hcg_sess = &(task_ctx->get_sess_list[i]);

			err = rhp_http_url_parse(urls[i],
							&(hcg_sess->url_hostname),
							&(hcg_sess->url_port),
							&(hcg_sess->url_path));

			if( err ){

				RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_HTTP_CLT_GET_RX_INVALID_URL,"sE",urls[i],err);

				goto error;
			}

			if( check_http_server_name &&
					check_http_server_name(hcg_sess->url_hostname) ){

				err = -EINVAL;

				RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_HTTP_CLT_GET_INVALID_SERVER_NAME,"sE",urls[i],err);

				goto error;
			}
		}
	}


	_rhp_http_clt_get_hold(task_ctx);
	err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_2,_rhp_http_clt_get_start_task,(void*)task_ctx);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_RTRN,"x",cb_ctx);
	return 0;

error:
	if( task_ctx ){
		_rhp_http_clt_get_free_ctx(task_ctx);
	}
	RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_ERR,"xE",cb_ctx,err);
	return err;
}


#define RHP_HTTP_CLT_GET_HEAD_1_0	"HTTP/1.0 200"
#define RHP_HTTP_CLT_GET_HEAD_1_1	"HTTP/1.1 200"
static int _rhp_http_clt_get_parse_response(rhp_http_clt_get_ctx* task_ctx,rhp_http_clt_get_sess* hcg_sess)
{
	int err = -EINVAL;
	size_t h_len = strlen(RHP_HTTP_CLT_GET_HEAD_1_0); // 1.1 : same length.
	char *p,*p_end,*ent_head = NULL;
	int i;

	RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_PARSE_RESPONSE,"xxdsssp",task_ctx,hcg_sess,hcg_sess->url_idx,hcg_sess->url_hostname,hcg_sess->url_port,hcg_sess->url_path,hcg_sess->rx_buf_len,hcg_sess->rx_buf);

	if( (size_t)hcg_sess->rx_buf_len <= h_len ){
		err = -EMSGSIZE;
		RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_PARSE_RESPONSE_LEN_ERR,"xxdd",task_ctx,hcg_sess,hcg_sess->rx_buf_len,h_len);
		goto error;
	}

	if( memcmp(hcg_sess->rx_buf,RHP_HTTP_CLT_GET_HEAD_1_0,h_len) &&
			memcmp(hcg_sess->rx_buf,RHP_HTTP_CLT_GET_HEAD_1_1,h_len) ){
		err = -EINVAL;
		RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_PARSE_RESPONSE_ERR_RESP,"xx",task_ctx,hcg_sess);
		goto error;
	}

	p = (char*)hcg_sess->rx_buf;
	p_end = p + hcg_sess->rx_buf_len;

	for( i = 0; i < hcg_sess->rx_buf_len; i++ ){

		if( *p == '\r' ){

			if( p + 3 >= p_end ){
				err = -EMSGSIZE;
				RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_PARSE_RESPONSE_ERR_RESP_INVALID_MESG_1,"xxxx",task_ctx,hcg_sess,(p + 3),p_end);
				goto error;
			}

			if( *(p + 1) == '\n' && *(p + 2) == '\r' && *(p + 3) == '\n' ){

				ent_head = (p + 4);
				break;
			}
		}

		p++;
	}

	if( ent_head == NULL || ent_head >= p_end ){
		err = -EMSGSIZE;
		RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_PARSE_RESPONSE_ERR_RESP_INVALID_MESG_2,"xxxx",task_ctx,hcg_sess,ent_head,p_end);
		goto error;
	}

	hcg_sess->body_buf = (u8*)ent_head;
	hcg_sess->body_buf_len = p_end - ent_head;

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_HTTP_CLT_GET_RESP_DATA,"sssa",hcg_sess->url_hostname,hcg_sess->url_port,hcg_sess->url_path,hcg_sess->rx_buf_len,hcg_sess->rx_buf);
	RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_PARSE_RESPONSE_RTRN,"xx",task_ctx,hcg_sess);
	return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_HTTP_CLT_GET_RESP_ERR,"sssaE",hcg_sess->url_hostname,hcg_sess->url_port,hcg_sess->url_path,((size_t)hcg_sess->rx_buf_len < h_len ? (size_t)hcg_sess->rx_buf_len : h_len),hcg_sess->rx_buf,err);
	RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_PARSE_RESPONSE_ERR,"xxE",task_ctx,hcg_sess,err);
	return err;
}


#define RHP_HTTP_CLT_GET_BUF_LEN	256
static int _rhp_http_clt_get_recv(rhp_http_clt_get_ctx* task_ctx,rhp_http_clt_get_sess* hcg_sess)
{
  int err = 0;
  struct msghdr msg;
  struct iovec iov[1];
  int rx_len = hcg_sess->rx_buf_len;
  u8 *rx_buf = NULL, *p = NULL;
  int rx_buf_tmp_len_rem = 0;
  int completed = 0;

	RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_RECV,"xx",task_ctx,hcg_sess);

  while( 1 ){

  	if( rx_buf == NULL || rx_buf_tmp_len_rem < 1 ){

  		u8* new_buf;

  		new_buf = (u8*)_rhp_malloc(rx_len + RHP_HTTP_CLT_GET_BUF_LEN);
  		if( new_buf == NULL ){

  			RHP_BUG("");

      	if( rx_buf ){
          _rhp_free(rx_buf);
      	}

      	err = -ENOMEM;
      	goto error;
			}

  		if( rx_buf == NULL ){

  			if( hcg_sess->rx_buf ){

  				memcpy(new_buf,hcg_sess->rx_buf,hcg_sess->rx_buf_len);
  				p = new_buf + hcg_sess->rx_buf_len;

    		}else{

    			p = new_buf;
    		}

  		}else{

  			memcpy(new_buf,rx_buf,rx_len);
        p = new_buf + rx_len;

        _rhp_free(rx_buf);
  		}

  		rx_buf = new_buf;

  		rx_buf_tmp_len_rem = RHP_HTTP_CLT_GET_BUF_LEN;

  	}else{

  		p = rx_buf + rx_len;
		}

  	iov[0].iov_base = p;
  	iov[0].iov_len = rx_buf_tmp_len_rem;
  	msg.msg_name = NULL;
  	msg.msg_namelen = 0;
  	msg.msg_iov = iov;
  	msg.msg_iovlen = 1;
  	msg.msg_flags = 0;
  	msg.msg_control = NULL;
  	msg.msg_controllen = 0;

  	err = recvmsg(hcg_sess->sk,&msg,MSG_DONTWAIT);
  	if( err < 0 ){

  		err = -errno;

  		RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_RECV_RECVMSG_ERR,"xxE",task_ctx,hcg_sess,err);

  		if( err == -EINTR ){
  			continue;
  		}else if( err == -EAGAIN ){
  			err = 0;
  			break;
  		}else{
  			goto error;
  		}

  	}else if( err == 0 ){
  		completed = 1;
  		break;
  	}

  	rx_len += err;
  	rx_buf_tmp_len_rem -= err;

  	if( rx_len > rhp_gcfg_http_clt_get_max_rx_length ){
  		err = RHP_STATUS_HTTP_ENT_TOO_LONG;
  		RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_RECV_TOO_LONG_MESG,"xxdd",task_ctx,hcg_sess,rx_len,rhp_gcfg_http_clt_get_max_rx_length);
  		goto error;
  	}
  }


  if( hcg_sess->rx_buf ){
  	_rhp_free(hcg_sess->rx_buf);
  }

  hcg_sess->rx_buf = rx_buf;
  hcg_sess->rx_buf_len = rx_len;
  rx_buf = NULL;
  rx_len = 0;

  if( completed ){

  	err = _rhp_http_clt_get_parse_response(task_ctx,hcg_sess);
  	if( err ){
  		goto error;
  	}

		RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_RECV_COMPLETED_RTRN,"xx",task_ctx,hcg_sess);
  	return RHP_STATUS_HTTP_CLT_DONE;

  }else{

		err = _rhp_http_clt_get_sk_epoll_mod(hcg_sess,RHP_MAIN_EPOLL_HTTP_CLT_GET_RECV);
		if( err ){
			goto error;
		}
  }

	RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_RECV_RTRN,"xx",task_ctx,hcg_sess);
  return 0;

error:

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_HTTP_CLT_GET_RECV_ERR,"E",err);

	if( rx_buf ){
		_rhp_free(rx_buf);
	}

	RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_RECV_ERR,"xxE",task_ctx,hcg_sess,err);
	return err;
}

static int _rhp_http_clt_get_completed(rhp_http_clt_get_ctx* task_ctx,rhp_http_clt_get_sess* hcg_sess)
{
	int err = -EINVAL;
	u8** rx_bufs = NULL;
	int* rx_buf_lens = NULL;
	int i;

	RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_COMPLETED,"xxdsss",task_ctx,hcg_sess,hcg_sess->url_idx,hcg_sess->url_hostname,hcg_sess->url_port,hcg_sess->url_path);

	if( task_ctx->cb_called ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	{
		rx_bufs = (u8**)_rhp_malloc(sizeof(u8*)*task_ctx->urls_num);
		if(rx_bufs == NULL){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		memset(rx_bufs,0,sizeof(u8*)*task_ctx->urls_num);

		rx_buf_lens = (int*)_rhp_malloc(sizeof(int*)*task_ctx->urls_num);
		if(rx_buf_lens == NULL){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		memset(rx_buf_lens,0,sizeof(int*)*task_ctx->urls_num);
	}


	for( i = 0; i < task_ctx->urls_num; i++ ){
		rx_bufs[i] = task_ctx->get_sess_list[i].body_buf;
		rx_buf_lens[i] = task_ctx->get_sess_list[i].body_buf_len;
	}

	task_ctx->callback(task_ctx->cb_ctx,0,task_ctx->urls_num,rx_buf_lens,rx_bufs);
	task_ctx->cb_called = 1;

	_rhp_free(rx_bufs);
	_rhp_free(rx_buf_lens);

	RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_COMPLETED_RTRN,"xx",task_ctx,hcg_sess);
	return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_HTTP_CLT_GET_COMP_ERR,"sssE",hcg_sess->url_hostname,hcg_sess->url_port,hcg_sess->url_path,err);

	if( !task_ctx->cb_called ){
		task_ctx->callback(task_ctx->cb_ctx,err,0,NULL,NULL);
		task_ctx->cb_called = 1;
	}

	if( rx_bufs ){
		_rhp_free(rx_bufs);
	}
	if( rx_buf_lens ){
		_rhp_free(rx_buf_lens);
	}
	RHP_TRC(0,RHPTRCID_HTTP_CLT_GET_COMPLETED_ERR,"xxE",task_ctx,hcg_sess,err);
	return err;
}

static void _rhp_http_clt_main_handle_event_task(int worker_idx,void* ctx)
{
	int err = -EINVAL;
	rhp_epoll_ctx* epoll_ctx = (rhp_epoll_ctx*)ctx;
	rhp_http_clt_get_ctx* task_ctx = (rhp_http_clt_get_ctx*)epoll_ctx->params[0];
	rhp_http_clt_get_sess* hcg_sess = (rhp_http_clt_get_sess*)epoll_ctx->params[1];
	int done_flag = 0;

	RHP_TRC(0,RHPTRCID_HTTP_CLT_MAIN_HANDLE_EVENT_TASK,"dxLdxxdsss",worker_idx,epoll_ctx,"MAIN_EOPLL_EVENT",epoll_ctx->event_type,task_ctx,hcg_sess,hcg_sess->url_idx,hcg_sess->url_hostname,hcg_sess->url_port,hcg_sess->url_path);

	RHP_LOCK(&(task_ctx->lock));

	if( task_ctx->epoll_evt.events & EPOLLERR ){
		RHP_TRC(0,RHPTRCID_HTTP_CLT_MAIN_HANDLE_EVENT_TASK_EPOLL_ERR,"dxxx",worker_idx,epoll_ctx,task_ctx,hcg_sess);
		err = -EINVAL;
		goto error;
	}

	if( task_ctx->cb_called ){
		RHP_TRC(0,RHPTRCID_HTTP_CLT_MAIN_HANDLE_EVENT_TASK_CB_ERR,"dxxx",worker_idx,epoll_ctx,task_ctx,hcg_sess);
		err = -EINVAL;
		goto error;
	}

	if( hcg_sess->get_ctx == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	if( epoll_ctx->event_type == RHP_MAIN_EPOLL_HTTP_CLT_GET_CONNECT ){

		err = _rhp_http_clt_get_tx_req(task_ctx,hcg_sess);
		if( err ){
			goto error;
		}

		err = _rhp_http_clt_get_sk_epoll_mod(hcg_sess,RHP_MAIN_EPOLL_HTTP_CLT_GET_RECV);
		if( err ){
			goto error;
		}

	}else if( epoll_ctx->event_type == RHP_MAIN_EPOLL_HTTP_CLT_GET_RECV ){

		err = _rhp_http_clt_get_recv(task_ctx,hcg_sess);
		if( err && err != RHP_STATUS_HTTP_CLT_DONE ){
			goto error;
		}

	}else{
		RHP_BUG("%d",epoll_ctx->event_type);
		err = -EINVAL;
		goto error;
	}

	if( err == RHP_STATUS_HTTP_CLT_DONE ){

		// (task_ctx->completed + 1): for (*xx*). Incremented lator. (*oo*)
		if( (task_ctx->completed + 1) == task_ctx->urls_num ){

			err = _rhp_http_clt_get_completed(task_ctx,hcg_sess);
			if( err ){
				goto error; // (*xx*)
			}

			if( !rhp_timer_delete(&(task_ctx->timer)) ){
				_rhp_http_clt_get_unhold(task_ctx);
			}

			RHP_TRC(0,RHPTRCID_HTTP_CLT_MAIN_HANDLE_EVENT_TASK_LAST_COMP,"dxxx",worker_idx,epoll_ctx,task_ctx,hcg_sess);
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_HTTP_CLT_GET_LAST_COMP,"sss",hcg_sess->url_hostname,hcg_sess->url_port,hcg_sess->url_path);

		}else{

			RHP_TRC(0,RHPTRCID_HTTP_CLT_MAIN_HANDLE_EVENT_TASK_COMP,"dxxx",worker_idx,epoll_ctx,task_ctx,hcg_sess);
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_HTTP_CLT_GET_COMP,"sss",hcg_sess->url_hostname,hcg_sess->url_port,hcg_sess->url_path);
		}

		task_ctx->completed++; // (*oo*)

		hcg_sess->get_ctx = NULL;
		done_flag = 1;
	}

	RHP_UNLOCK(&(task_ctx->lock));

	if( done_flag ){
		_rhp_http_clt_get_unhold(task_ctx);
	}

	_rhp_http_clt_get_unhold(task_ctx); /* rhp_http_clt_main_handle_event() */

	RHP_TRC(0,RHPTRCID_HTTP_CLT_MAIN_HANDLE_EVENT_TASK,"dxxx",worker_idx,epoll_ctx,task_ctx,hcg_sess);
	return;


error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_HTTP_CLT_GET_HANDLE_ERR,"sssE",hcg_sess->url_hostname,hcg_sess->url_port,hcg_sess->url_path,err);

	if( !task_ctx->cb_called ){
		task_ctx->callback(task_ctx->cb_ctx,err,0,NULL,NULL);
		task_ctx->cb_called = 1;
	}

	task_ctx->completed++;

	if( task_ctx->completed == task_ctx->urls_num ){

		if( !rhp_timer_delete(&(task_ctx->timer)) ){
			_rhp_http_clt_get_unhold(task_ctx);
		}
	}

	_rhp_http_clt_get_sk_close(hcg_sess);

	hcg_sess->get_ctx = NULL;

	RHP_UNLOCK(&(task_ctx->lock));
	_rhp_http_clt_get_unhold(task_ctx);

	_rhp_http_clt_get_unhold(task_ctx); /* rhp_http_clt_main_handle_event() */

	RHP_TRC(0,RHPTRCID_HTTP_CLT_MAIN_HANDLE_EVENT_TASK_ERR,"dxxxE",worker_idx,epoll_ctx,task_ctx,hcg_sess,err);
	return;
}

int rhp_http_clt_main_handle_event(struct epoll_event* epoll_evt)
{
	int err = -EINVAL;
	rhp_epoll_ctx* epoll_ctx = (rhp_epoll_ctx*)epoll_evt->data.ptr;
	rhp_http_clt_get_ctx* task_ctx = (rhp_http_clt_get_ctx*)epoll_ctx->params[0];

	RHP_TRC(0,RHPTRCID_HTTP_CLT_MAIN_HANDLE_EVENT,"xx",epoll_ctx,task_ctx);

	if( epoll_ctx->event_type != RHP_MAIN_EPOLL_HTTP_CLT_GET_CONNECT &&
			epoll_ctx->event_type != RHP_MAIN_EPOLL_HTTP_CLT_GET_RECV ){
		RHP_BUG("");
		return -EINVAL;
	}


	RHP_LOCK(&(task_ctx->lock));

	memcpy(&(task_ctx->epoll_evt),epoll_evt,sizeof(struct epoll_event));

	_rhp_http_clt_get_hold(task_ctx);

	RHP_UNLOCK(&(task_ctx->lock));


	if( (err = rhp_wts_dispach_check(RHP_WTS_DISP_LEVEL_HIGH_2,0)) ){ // Waiting...
		err = -EBUSY;
		_rhp_http_clt_get_unhold(task_ctx);
		RHP_BUG("");
		goto error;
	}

	err = rhp_wts_add_task(RHP_WTS_DISP_RULE_RAND,RHP_WTS_DISP_LEVEL_HIGH_2,NULL,
					_rhp_http_clt_main_handle_event_task,epoll_ctx);

	if( err ){

		RHP_BUG("%d",err);

		_rhp_http_clt_get_unhold(task_ctx);
		goto error;
	}

	RHP_TRC(0,RHPTRCID_HTTP_CLT_MAIN_HANDLE_EVENT_RTRN,"xx",epoll_ctx,task_ctx);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_HTTP_CLT_MAIN_HANDLE_EVENT_ERR,"xxE",epoll_ctx,task_ctx,err);
	return err;
}

