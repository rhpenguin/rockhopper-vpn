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

//
// TODO : Supporting HTTPS.
//

static rhp_http_listen* _rhp_http_servers = NULL;
static rhp_http_conn* _rhp_http_conns_head = NULL;
static rhp_http_conn* _rhp_http_conns_tail = NULL;
static rhp_mutex_t _rhp_http_lock;

static rhp_atomic_t _rhp_http_svr_sk_num;

static u64 _rhp_http_ipc_txn_id = 1;

struct _rhp_http_server_handler {

  u8 tag[4]; // "#HHD"
  struct _rhp_http_server_handler* next;	

  int (*handler)(rhp_http_conn* http_conn,int authorized,void* ctx);
  void* ctx;

  int nobody_allowed;
};
typedef struct _rhp_http_server_handler	rhp_http_server_handler;

// NOT thread safe! handlers are registered when process starts only.
static rhp_http_server_handler* _rhp_http_server_handlers = NULL;
static rhp_http_server_handler* _rhp_http_server_handlers_tail = NULL;

static char* _rhp_http_index_html = "index.html";


static char _rhp_http_auth_cookie_nonce_str[RHP_HTTP_AUTH_COOKIE_NONCE_STR_SIZE];
static char _rhp_http_auth_cookie_nonce_str_old[RHP_HTTP_AUTH_COOKIE_NONCE_STR_SIZE];
static time_t _rhp_http_auth_cookie_nonce_last_updated = 0;

static void _rhp_http_svr_close_sk(int* sk)
{
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SVR_CLOSE_SK,"xdf",sk,*sk,_rhp_atomic_read(&_rhp_http_svr_sk_num));

	if( *sk < 0 ){
		RHP_BUG("");
		return;
	}
	_rhp_atomic_dec(&_rhp_http_svr_sk_num);
	close(*sk);
	*sk = -1;
}

long rhp_http_svr_get_open_sk_num()
{
	long n = _rhp_atomic_read(&_rhp_http_svr_sk_num);
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SVR_OPEN_SK_NUM,"f",n);
	return n;
}

static void _rhp_http_nonce2str(u8* nonce,char* nonce_str_r)
{
	int i,n;
	int buf_len = RHP_HTTP_AUTH_COOKIE_NONCE_STR_SIZE;

	nonce_str_r[0] = '\0';

	n = snprintf(nonce_str_r,RHP_HTTP_AUTH_COOKIE_NONCE_STR_SIZE,"%s","0x");
	buf_len -= n;

	for( i = 0; i < RHP_HTTP_AUTH_COOKIE_NONCE_SIZE; i++){
		n += snprintf((nonce_str_r + n),buf_len,"%02x",nonce[i]);
		buf_len -= n;
	}

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_NONCE2STR,"ps",RHP_HTTP_AUTH_COOKIE_NONCE_SIZE,nonce,nonce_str_r);
	return;
}

static void _rhp_http_update_auth_cookie()
{
	time_t now = _rhp_get_time();
	time_t interval = rhp_gcfg_http_auth_cookie_aging_interval;

	if( interval < (rhp_gcfg_http_bus_read_timeout*3) ){
		interval = (rhp_gcfg_http_bus_read_timeout*3);
	}

	if( _rhp_http_auth_cookie_nonce_last_updated + interval <= now ){

  	u8 nonce[RHP_HTTP_AUTH_COOKIE_NONCE_SIZE];

		strcpy(_rhp_http_auth_cookie_nonce_str_old,_rhp_http_auth_cookie_nonce_str);

  	rhp_random_bytes(nonce,RHP_HTTP_AUTH_COOKIE_NONCE_SIZE);
  	_rhp_http_nonce2str(nonce,_rhp_http_auth_cookie_nonce_str);

	  _rhp_http_auth_cookie_nonce_last_updated = now;

	  RHP_TRC_FREQ(0,RHPTRCID_HTTP_UPDATE_AUTH_COOKIE,"ssd",_rhp_http_auth_cookie_nonce_str,_rhp_http_auth_cookie_nonce_str_old,interval);
	}
}


static int _rhp_http_check_char(char c)
{
  if( c >= '0' && c <= '9' ){
    return 0;	  
  }else if( c >= 'A' && c <= 'Z' ){
    return 0;	  
  }else if( c >= 'a' && c <= 'z' ){
    return 0;	  
  }else if( c == '_'  ){
    return 0;	  
  }else if( c == '-'  ){
    return 0;	  
  }else if( c == '.'  ){
    return 0;	  
  }
  
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_CHECK_CHAR_NG,"b",c);
  return -1;
}

static int _rhp_http_protected_uri(rhp_http_request* http_req)
{
	int fixed_len = strlen("/protected/");

	if( http_req && http_req->uri &&
			(int)strlen(http_req->uri) >= fixed_len &&
			!strncasecmp(http_req->uri,"/protected/",fixed_len) ){
		return 1;
	}

	return 0;
}

// _rhp_http_lock must be acquired.
int rhp_http_auth_request_impl(rhp_http_conn* http_conn,unsigned long rlm_id,int allow_http_basic_auth)
{
  int err = -EINVAL;
  rhp_http_request* http_req = http_conn->http_req;
  rhp_http_header* auth_header = NULL;
  char* basic_auth_method = NULL;
  char* basic_auth_data = NULL;
  char* user_name = NULL;
  char* basic_password = NULL;
  u8* basic_auth_data_decoded = NULL;
  int basic_auth_data_decoded_len = 0;
  rhp_ipcmsg* ipc_req = NULL;
  u64 ipc_txn_id = 0;
	char *p;
  u8* p2;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_AUTH_REQUEST,"xd",http_conn,allow_http_basic_auth);
  
  if( http_req == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  if( http_conn->ipc_txn_id != 0 || http_conn->user_name ){
  	RHP_BUG("");
  	goto error;
  }


  if( http_req->cookie.user_name && http_req->cookie.nonce && http_req->cookie.ticket ){

  	//
  	// Cookie-based Authentication
  	//
  	//  - For Web browser's submit method of <form><input type="file">.
  	//    Handling cookies by JavaScript is easier than manipulating a private HTTP
  	//    Auth header.
  	//  - More secure than HTTP-Basic-like Authentication because user's password
  	//    is NOT included in a HTTP AUTH header.
  	//  - TODO: Replay attack protection??? But, TLS is easier and better, I think.
  	//

  	rhp_ipcmsg_auth_cookie_req* cookie_auth_req;
    int auth_req_len = sizeof(rhp_ipcmsg_auth_cookie_req);
    int uclen = 0;

  	if( strcmp(http_conn->cookie_auth_nonce_str,http_req->cookie.nonce) &&
  			strcmp(http_conn->cookie_auth_nonce_str_old,http_req->cookie.nonce) ){
			RHP_TRC_FREQ(0,RHPTRCID_HTTP_AUTH_REQUEST_COOKIE_AUTH_INVALID_NONCE,"xssss",http_conn,http_req->cookie.user_name,http_conn->cookie_auth_nonce_str,http_conn->cookie_auth_nonce_str_old,http_req->cookie.nonce);
  		err = RHP_STATUS_HTTP_COOKIE_UNAUTHORIZED;
    	goto error;
  	}

  	uclen = strlen(http_req->cookie.user_name);
		if( uclen < RHP_AUTH_REQ_MIN_ID_LEN || uclen > RHP_AUTH_REQ_MAX_ID_LEN ){
			RHP_TRC_FREQ(0,RHPTRCID_HTTP_AUTH_REQUEST_COOKIE_AUTH_INVALID_USER_NAME_LEN,"xds",http_conn,uclen,http_req->cookie.user_name);
			err = RHP_STATUS_HTTP_COOKIE_UNAUTHORIZED;
    	goto error;
		}

  	user_name = (char*)_rhp_malloc(uclen + 1);
  	if( user_name == NULL ){
  		RHP_BUG("");
  		err = -ENOMEM;
  		goto error;
  	}
  	user_name[0] = '\0';

  	strcpy(user_name,http_req->cookie.user_name);

  	auth_req_len += strlen(user_name) + 1;
  	auth_req_len += strlen(http_req->cookie.nonce) + 1;
  	auth_req_len += RHP_HTTP_AUTH_TICKET_SIZE;


  	cookie_auth_req = (rhp_ipcmsg_auth_cookie_req*)rhp_ipc_alloc_msg(RHP_IPC_AUTH_COOKIE_REQUEST,auth_req_len);
		if( cookie_auth_req == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}

		ipc_req = (rhp_ipcmsg*)cookie_auth_req;


		p2 = (u8*)(cookie_auth_req + 1);
		cookie_auth_req->len = auth_req_len;

		cookie_auth_req->txn_id = _rhp_http_ipc_txn_id++;
		if( _rhp_http_ipc_txn_id == 0 ){
			_rhp_http_ipc_txn_id++;
		}

		cookie_auth_req->id_len = strlen(user_name) + 1;
		cookie_auth_req->nonce_len = strlen(http_req->cookie.nonce) + 1;
		cookie_auth_req->ticket_len = RHP_HTTP_AUTH_TICKET_SIZE;
		cookie_auth_req->request_user = RHP_IPC_USER_ADMIN_SERVER_HTTP;
		cookie_auth_req->vpn_realm_id = rlm_id;

		memcpy(p2,user_name,cookie_auth_req->id_len);
		p2 += cookie_auth_req->id_len;

		memcpy(p2,http_req->cookie.nonce,cookie_auth_req->nonce_len);
		p2 += cookie_auth_req->nonce_len;

		memcpy(p2,http_req->cookie.ticket,RHP_HTTP_AUTH_TICKET_SIZE);


		ipc_txn_id = cookie_auth_req->txn_id;

  }else{

  	//
  	// HTTP-Basic-like Authentication
  	//

  	// For command line tool/script on local system.

    int n;
    int i = 1;
    int sp = 0;
    char* token[3] = {NULL,NULL,NULL};
    char* token_ep[3] = {NULL,NULL,NULL};
    int token_len;
    rhp_ipcmsg_auth_basic_req* basic_auth_req = NULL;
    int auth_req_len = sizeof(rhp_ipcmsg_auth_basic_req);

    if( !rhp_ip_is_loopback(&(http_conn->dst_addr)) ){ // Allowed on loopback address.
    	err = -EPERM;
			RHP_TRC_FREQ(0,RHPTRCID_HTTP_AUTH_REQUEST_BASIC_AUTH_NOT_LOOPBACK,"x",http_conn);
    	goto error;
    }

		auth_header = http_req->get_header(http_req,"X-Rhp-Authorization");
		if( auth_header == NULL ){

			if( allow_http_basic_auth ){

				auth_header = http_req->get_header(http_req,"Authorization");
			}

			if( auth_header == NULL ){
				err = RHP_STATUS_HTTP_BASIC_UNAUTHORIZED;
				RHP_TRC_FREQ(0,RHPTRCID_HTTP_AUTH_REQUEST_NO_AUTH_HEADER,"x",http_conn);
				goto error;
			}
		}

		if( auth_header->value == NULL ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC_FREQ(0,RHPTRCID_HTTP_AUTH_REQUEST_NO_AUTH_VALUE,"x",http_conn);
			goto error;
		}

		p = auth_header->value;
		n = strlen(auth_header->value);

		token[0] = auth_header->value;
		while( *p != '\0' && i < 3 && n > 0 ){

			if( *p == ' ' || *p == '\t' ){
				if( sp ){
					goto next;
				}

				token_ep[i-1] = p;
				token[i] = p + 1;
				i++;
				sp = 1;

			}else{
				sp = 0;
			}

	next:
			p++;
			n--;
		}

		if( sp ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC_FREQ(0,RHPTRCID_HTTP_AUTH_REQUEST_INVALID_AUTH_HEADER_1,"x",http_conn);
			goto error;
		}

		if( i != 2 ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC_FREQ(0,RHPTRCID_HTTP_AUTH_REQUEST_INVALID_AUTH_HEADER_2,"x",http_conn);
			goto error;
		}

		if( n != 0 ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC_FREQ(0,RHPTRCID_HTTP_AUTH_REQUEST_INVALID_AUTH_HEADER_3,"x",http_conn);
			goto error;
		}

		if( p[0] != '\0' ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC_FREQ(0,RHPTRCID_HTTP_AUTH_REQUEST_INVALID_AUTH_HEADER_4,"x",http_conn);
			goto error;
		}
		token_ep[1] = &(p[0]);

		token_len = ((u8*)token_ep[0]) - ((u8*)token[0]);
		if( token_len < 1 ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC_FREQ(0,RHPTRCID_HTTP_AUTH_REQUEST_INVALID_AUTH_HEADER_5,"x",http_conn);
			goto error;
		}

		basic_auth_method = (char*)_rhp_malloc(token_len+1);
		if( basic_auth_method == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		memset(basic_auth_method,0,token_len+1);
		memcpy(basic_auth_method,token[0],token_len);

		if( strcasecmp(basic_auth_method,"Basic") ){
			err = RHP_STATUS_HTTP_BASIC_UNAUTHORIZED;
			RHP_TRC_FREQ(0,RHPTRCID_HTTP_AUTH_REQUEST_NOT_BASIC_METHOD,"x",http_conn);
			goto error;
		}

		token_len = ((u8*)token_ep[1]) - ((u8*)token[1]);
		if( token_len < 1 ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC_FREQ(0,RHPTRCID_HTTP_AUTH_REQUEST_INVALID_AUTH_HEADER_6,"x",http_conn);
			goto error;
		}

		basic_auth_data = (char*)_rhp_malloc(token_len+1);
		if( basic_auth_data == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		memset(basic_auth_data,0,token_len+1);
		memcpy(basic_auth_data,token[1],token_len);

		err = rhp_base64_decode((unsigned char*)basic_auth_data,&basic_auth_data_decoded,&basic_auth_data_decoded_len);
		if( err ){
			RHP_TRC_FREQ(0,RHPTRCID_HTTP_AUTH_REQUEST_BASE64_DEC_FAILED,"x",http_conn);
			goto error;
		}

		p = NULL;
		for( i = 0; i < basic_auth_data_decoded_len;i++ ){

			if( basic_auth_data_decoded[i] == ':' ){
				p = (char*)&(basic_auth_data_decoded[i]);
				break;
			}

			if( _rhp_http_check_char(basic_auth_data_decoded[i]) ){
				err = RHP_STATUS_HTTP_BASIC_UNAUTHORIZED;
				RHP_TRC_FREQ(0,RHPTRCID_HTTP_AUTH_REQUEST_INVALID_DEC_CHAR,"x",http_conn);
				goto error;
			}
		}

		if( p == NULL ){
			err = RHP_STATUS_HTTP_BASIC_UNAUTHORIZED;
			RHP_TRC_FREQ(0,RHPTRCID_HTTP_AUTH_REQUEST_NO_DEC_CHARS,"x",http_conn);
			goto error;
		}

		token_len = ((u8*)p) - ((u8*)basic_auth_data_decoded);
		if( token_len < RHP_AUTH_REQ_MIN_ID_LEN || token_len > RHP_AUTH_REQ_MAX_ID_LEN ){
			err = RHP_STATUS_HTTP_BASIC_UNAUTHORIZED;
			RHP_TRC_FREQ(0,RHPTRCID_HTTP_AUTH_REQUEST_DEC_CHARS_TOO_SHORT,"x",http_conn);
			goto error;
		}

		user_name = (char*)_rhp_malloc(token_len + 1);
		if( user_name == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		memset(user_name,0,token_len + 1);
		memcpy(user_name,basic_auth_data_decoded,token_len);


		auth_req_len += token_len + 1;

		token_len = ( ((u8*)basic_auth_data_decoded) + basic_auth_data_decoded_len) - ((u8*)p) - 1;
		if( token_len < RHP_AUTH_REQ_MIN_PW_LEN ){
			err = RHP_STATUS_HTTP_BASIC_UNAUTHORIZED;
			RHP_TRC_FREQ(0,RHPTRCID_HTTP_AUTH_REQUEST_PASSWORD_TOO_SHORT,"x",http_conn);
			goto error;
		}

		if( token_len ){

			basic_password = (char*)_rhp_malloc(token_len+1);
			if( basic_password == NULL ){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}

			memset(basic_password,0,token_len+1);
			memcpy(basic_password,(p+1),token_len);
			auth_req_len += token_len + 1;

		}else{
			auth_req_len += 1; // sizeof('\0')
		}

		basic_auth_req = (rhp_ipcmsg_auth_basic_req*)rhp_ipc_alloc_msg(RHP_IPC_AUTH_BASIC_REQUEST,auth_req_len);
		if( basic_auth_req == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}

		ipc_req = (rhp_ipcmsg*)basic_auth_req;


		p2 = (u8*)(basic_auth_req + 1);
		basic_auth_req->len = auth_req_len;

		basic_auth_req->txn_id = _rhp_http_ipc_txn_id++;
		if( _rhp_http_ipc_txn_id == 0 ){
			_rhp_http_ipc_txn_id++;
		}

		basic_auth_req->id_len = strlen(user_name)+1;
		basic_auth_req->password_len = (basic_password ? (strlen(basic_password)+1) : 1);
		basic_auth_req->request_user = RHP_IPC_USER_ADMIN_SERVER_HTTP;
		basic_auth_req->vpn_realm_id = rlm_id;

		memcpy(p2,user_name,basic_auth_req->id_len);
		if( basic_password ){
			memcpy((p2 + basic_auth_req->id_len),basic_password,basic_auth_req->password_len);
		}else{
			*(p2 + basic_auth_req->id_len) = '\0';
		}

		ipc_txn_id = basic_auth_req->txn_id;
  }
  

  http_conn->ipc_txn_id = ipc_txn_id;
  http_conn->user_name = user_name;
  http_conn->pend_http_auth = 1;
  user_name = NULL;
  
  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipc_req,ipc_req->len,0) < 0 ){
   err = -EINVAL;
   RHP_BUG("");
   goto error;
 }

  err = 0;
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_AUTH_BASIC_OK,"x",http_conn);

error:
  if( basic_auth_method ){
    _rhp_free(basic_auth_method);
  }
  if( basic_auth_data ){
    _rhp_free_zero(basic_auth_data,strlen(basic_auth_data)+1);
  }
  if( user_name ){
    _rhp_free_zero(user_name,strlen(user_name)+1);	  
  }
  if( basic_password ){
    _rhp_free_zero(basic_password,strlen(basic_password)+1);
  }
  if( basic_auth_data_decoded ){
    _rhp_free_zero(basic_auth_data_decoded,basic_auth_data_decoded_len);
  }
  if( ipc_req ){
   _rhp_free_zero(ipc_req,ipc_req->len);
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_AUTH_REQUEST_RTRN,"xE",http_conn,err);
  return err;
}

int rhp_http_auth_request(rhp_http_conn* http_conn,unsigned long rlm_id)
{
	return rhp_http_auth_request_impl(http_conn,rlm_id,0);
}


#define RHP_HTTP_DEFAULT_HANDLER_FBUF_LEN		4096
#define RHP_HTTP_DEFAULT_HANDLER_TXBUF_LEN	(RHP_HTTP_DEFAULT_HANDLER_FBUF_LEN*4)

int rhp_http_fill_response_body_from_file(rhp_http_response* http_res,char* path)
{
	int err = -EINVAL;
	int fd = -1;
  char* mesg_body = NULL;
  long rem_len = 0;
  ssize_t n;

	fd = open(path,O_RDONLY);
	if( fd < 0 ){
	  err = RHP_STATUS_SKIP;
	  RHP_TRC_FREQ(0,RHPTRCID_HTTP_READ_MESG_FROM_FILE_NO_FILE,"xs",http_res,path);
	  goto error;
	}

	mesg_body = (char*)_rhp_malloc(RHP_HTTP_DEFAULT_HANDLER_FBUF_LEN);
	if( mesg_body == NULL ){
	  err = -ENOMEM;
	  RHP_BUG("");
	  goto error;
	}

	RHP_TRC_FREQ(0,RHPTRCID_HTTP_READ_MESG_FROM_FILE_READING_FILE,"xs",http_res,path);

	while( 1 ){

		n = read(fd,mesg_body,RHP_HTTP_DEFAULT_HANDLER_FBUF_LEN);
		if( n < 0 ){

			err = -errno;
	   if( err == -EINTR ){
	  	 err = 0;
	     continue;
	   }

	   RHP_TRC_FREQ(0,RHPTRCID_HTTP_READ_MESG_FROM_FILE_READING_FILE_ERR,"xsE",http_res,path,err);
	   goto error;

		}else if( n == 0 ){
	  	RHP_TRC_FREQ(0,RHPTRCID_HTTP_READ_MESG_FROM_FILE_READING_FILE_END,"xs",http_res,path);
	  	break;
		}

		if( http_res->mesg_body == NULL ){

			http_res->mesg_body = (char*)_rhp_malloc(RHP_HTTP_DEFAULT_HANDLER_TXBUF_LEN);
			if( http_res->mesg_body == NULL ){
				RHP_BUG("");
			}

			rem_len = RHP_HTTP_DEFAULT_HANDLER_TXBUF_LEN;
			http_res->mesg_body_len = 0;
		}

		if( rem_len <= (long)n ){

			char* new_buf = NULL;
			long exp_len = (n > RHP_HTTP_DEFAULT_HANDLER_TXBUF_LEN ? (long)n : RHP_HTTP_DEFAULT_HANDLER_TXBUF_LEN);
			long new_buf_len = http_res->mesg_body_len + exp_len;

			new_buf = (char*)_rhp_malloc(new_buf_len);
			if( new_buf == NULL ){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}

			rem_len = exp_len;

			memcpy(new_buf,http_res->mesg_body,http_res->mesg_body_len);
			_rhp_free(http_res->mesg_body);
			http_res->mesg_body = new_buf;
		}

		memcpy( ((u8*)http_res->mesg_body) + http_res->mesg_body_len,mesg_body,(size_t)n);
		http_res->mesg_body_len += (long)n;
		rem_len -= n;
	}

	return 0;

error:
	return err;
}


static char* _rhp_http_server_cfg_bkup_path = "/tmp/rockhopper.rcfg";

static int _rhp_http_server_rootdir_handler(rhp_http_conn* http_conn,int authorized,void* ctx)
{
  int err = RHP_STATUS_SKIP;
  int ulerr = 0;
  rhp_http_request* http_req = http_conn->http_req;	
  rhp_http_response* http_res = NULL;
  char* filename = NULL;
  char *c,*sfx = NULL;
  int fd = -1;
  char *path = NULL, *path_fixed = NULL;
  ssize_t n;
  char* mesg_body = NULL;
  long rem_len = 0;
  int is_pub_file = 0;
  int allow_http_basic_auth = 0;
  char* event_log_name = NULL;
  int tx_auth_cookie = 0;
  rhp_http_header *req_header = NULL;
  int is_cfg_bkup = 0;
  int is_event_log = 0;
  int is_event_log_txt = 0;
  int is_packet_capture = 0;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER,"xdx",http_conn,authorized,ctx);
  
  if( http_req == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_NO_HTTP_REQ,"x",http_conn);
    return RHP_STATUS_SKIP;	  
  }

  if( http_req->method == NULL || http_req->uri == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_NO_HTTP_REQ_PARAM,"xxx",http_conn,http_req->method,http_req->uri);
    return RHP_STATUS_SKIP;	  
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_PARMS,"xss",http_conn,http_req->method,http_req->uri);
  
  if( !strcmp(http_req->method,"GET") ){

    int fixed_pub_uri_len = strlen("/pub/");
    int url_len = strlen(http_req->uri);

  	if( !strcmp(http_req->uri,"/") ){

  		filename = _rhp_http_index_html;		
  		is_pub_file = 1; // Authentication is NOT required!

  	}else if( !strcasecmp(http_req->uri,"/protected/config/rockhopper.rcfg") ){

  		filename = _rhp_http_server_cfg_bkup_path;
  		is_cfg_bkup = 1;
  		allow_http_basic_auth = 1;
  		tx_auth_cookie = 1;

  	}else if( !strcasecmp(http_req->uri,"/protected/packet_capture/rockhopper.pcap") ){

  		filename = "/tmp/rockhopper.pcap";
  		path_fixed = rhp_packet_capture_file_path;
  		is_packet_capture = 1;
  		allow_http_basic_auth = 1;
  		tx_auth_cookie = 1;

  	}else if( !strcasecmp(http_req->uri,"/protected/log/old_log.xml") ){

  		is_event_log = 1;
  		tx_auth_cookie = 1;

  	}else if( !strcasecmp(http_req->uri,"/protected/log/rockhopper_log.txt") ){

  		is_event_log_txt = 1;
  		tx_auth_cookie = 1;

  	}else if( url_len > fixed_pub_uri_len &&
  						!strncasecmp(http_req->uri,"/pub/",fixed_pub_uri_len) ){

  		is_pub_file = 1; // Authentication is NOT required!
  		filename = &(http_req->uri[1]);

  	}else{

  		err = RHP_STATUS_SKIP;
  		RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_GET_INVALID_URI,"x",http_conn);
  		goto error;
  	}


	  req_header = http_req->get_header(http_req,"Accept");
	  if( req_header && req_header->value ){

	  	if( (strcasestr(req_header->value,"text/html") == NULL) &&
	  			(strcasestr(req_header->value,"text/plain") == NULL) &&
	  			(strcasestr(req_header->value,"text/xml") == NULL) &&
	  			(strcasestr(req_header->value,"text/javascript") == NULL) &&
	  			(strcasestr(req_header->value,"text/css") == NULL) &&
	  			(strcasestr(req_header->value,"text/*") == NULL) &&
	  			(strcasestr(req_header->value,"image/gif") == NULL) &&
	  			(strcasestr(req_header->value,"image/jpeg") == NULL) &&
	  			(strcasestr(req_header->value,"image/png") == NULL) &&
	  			(strcasestr(req_header->value,"application/octet-stream") == NULL) &&
	  			(strcasestr(req_header->value,"*/*") == NULL) ){

	  		RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_INVALID_ACCEPT_HEADER_VALUE,"xxxs",http_conn,http_req,req_header,req_header->value);
	  		err = -ENOENT;
	  		goto error;
	  	}

	  }else{

	    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_NO_ACCEPT_HEADER,"xx",http_conn,http_req);
	  }


  	req_header = http_req->get_header(http_req,"Accept-Charset");
	  if( req_header && req_header->value ){

	  	if( (strcasestr(req_header->value,"utf-8") == NULL) && (strcasestr(req_header->value,"*") == NULL) ){

	  		RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_INVALID_ACCEPT_CHARSET_HEADER_VALUE,"xxxs",http_conn,http_req,req_header,req_header->value);
	      err = -ENOENT;
	      goto error;
	  	}

	  }else{
	    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_NO_ACCEPT_CHARSET_HEADER,"xx",http_conn,http_req);
	  }


		if( !authorized &&
				( !is_pub_file || rhp_gcfg_http_auth_no_pub_files ) ){

		   err = rhp_http_auth_request_impl(http_conn,(unsigned long)-1,allow_http_basic_auth);
		   if( err ){

		  	 if( err == RHP_STATUS_HTTP_BASIC_UNAUTHORIZED && allow_http_basic_auth ){
		  		 err = RHP_STATUS_HTTP_UNAUTHORIZED_BASIC_AUTH_PROMPT;
		  	 }

		  	 RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_AUTH_BASIC_ERR,"x",http_conn);
		  	 goto error;
		   }

		   err = rhp_http_server_conn_timer_restart(http_conn);
		   if( err ){
		  	 RHP_BUG("%d",err);
		  	 goto error;
		   }

		   err = RHP_STATUS_HTTP_REQ_PENDING;

		   RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_GET_GO_PEND,"x",http_conn);
		   goto pending;
		}

		if( http_conn->is_nobody && !is_pub_file ){
			err = -EPERM;
			RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_NOBODY_USER_NOT_ALLOWED,"xs",http_conn,http_req->uri);
	    RHP_LOG_DE(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_HTTP_NOBODY_USER_NOT_ALLOWED_URI,"uss",http_conn->user_realm_id,http_conn->user_name,http_req->uri);
			goto error;
		}

		if( is_event_log || is_event_log_txt ){

	  	int event_log_name_len = strlen(http_conn->user_name) + 64;

	  	event_log_name = (char*)_rhp_malloc( event_log_name_len );
			if( event_log_name == NULL ){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			event_log_name[0] = '\0';

			if( is_event_log ){
				snprintf(event_log_name,event_log_name_len,"/tmp/event_log_%s.xml",http_conn->user_name);
			}else{ // is_event_log_txt
				snprintf(event_log_name,event_log_name_len,"/tmp/event_log_%s.txt",http_conn->user_name);
			}

			filename = event_log_name;
		}

		if( filename == NULL ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		{
			c = filename;
			while( *c != '\0' ){

				if( filename != _rhp_http_index_html ){

					if( *c != '/' && _rhp_http_check_char(*c) ){
						err = RHP_STATUS_SKIP;
						RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_GET_INVALID_CHAR,"x",http_conn);
						goto error;
					}
				}

				if( *c == '.' ){
					sfx = c;
				}

				c++;
			}
	
			if( sfx == NULL || (strlen(filename) - (((u8*)sfx) - ((u8*)filename))) <= 1 ){
				err = RHP_STATUS_SKIP;
				RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_GET_INVALID_FILENAME,"x",http_conn);
				goto error;
			}
			sfx++; // '.'++
		}


	  http_res = rhp_http_res_alloc("200","OK");
	  if( http_res == NULL ){
	  	err = -ENOMEM;
	  	RHP_BUG("");
	  	goto error;
	  }
	
  	if( is_event_log_txt ){
	    err = http_res->put_header(http_res,"Content-Type","application/octet-stream");
  	}else if( !strcasecmp(sfx,"html") ){
	    err = http_res->put_header(http_res,"Content-Type","text/html; charset=utf-8");
	  }else if( !strcasecmp(sfx,"txt") ){
	  	err = http_res->put_header(http_res,"Content-Type","text/plain; charset=utf-8");
	  }else if( !strcasecmp(sfx,"gif") ){
	    err = http_res->put_header(http_res,"Content-Type","image/gif");
	  }else if( !strcasecmp(sfx,"jpeg") ||  !strcasecmp(sfx,"jpg") ){
	    err = http_res->put_header(http_res,"Content-Type","image/jpeg");
	  }else if( !strcasecmp(sfx,"png") ){
	    err = http_res->put_header(http_res,"Content-Type","image/png");
	  }else if( !strcasecmp(sfx,"js") ){
	    err = http_res->put_header(http_res,"Content-Type","text/javascript; charset=utf-8");
	  }else if( !strcasecmp(sfx,"css") ){
	    err = http_res->put_header(http_res,"Content-Type","text/css; charset=utf-8");
	  }else if( !strcasecmp(sfx,"json") ){
	    err = http_res->put_header(http_res,"Content-Type","text/javascript; charset=utf-8");
	  }else if( !strcasecmp(sfx,"xml") ){
	    err = http_res->put_header(http_res,"Content-Type","text/xml; charset=utf-8");
	  }else if( !strcasecmp(sfx,"rcfg") ){

	  	if( !is_cfg_bkup ){
		    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_GET_RCFG_NOT_ALLOWED_1,"xds",http_conn,http_conn->user_realm_id,filename);
	  		err = -EPERM;
	  		goto error;
	  	}

	  	if( http_conn->is_nobody ){
		    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_GET_RCFG_NOT_ALLOWED_2,"xds",http_conn,http_conn->user_realm_id,filename);
	  		err = -EPERM;
	  		goto error;
	  	}

	  	// Config files is NOT allowed for realm admins.
	  	if( http_conn->user_realm_id != 0 ){
		    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_GET_RCFG_NOT_ALLOWED_3,"xds",http_conn,http_conn->user_realm_id,filename);
	  		err = -EPERM;
	  		goto error;
	  	}

	    err = http_res->put_header(http_res,"Content-Type","application/octet-stream");

	  }else if( !strcasecmp(sfx,"pcap") ){

	  	if( !is_packet_capture ){
		    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_GET_PCAP_NOT_ALLOWED_1,"xds",http_conn,http_conn->user_realm_id,filename);
	  		err = -EPERM;
	  		goto error;
	  	}

	  	if( http_conn->is_nobody ){
		    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_GET_PCAP_NOT_ALLOWED_2,"xds",http_conn,http_conn->user_realm_id,filename);
	  		err = -EPERM;
	  		goto error;
	  	}

	  	// Config files is NOT allowed for realm admins.
	  	if( http_conn->user_realm_id != 0 ){
		    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_GET_PCAP_NOT_ALLOWED_3,"xds",http_conn,http_conn->user_realm_id,filename);
	  		err = -EPERM;
	  		goto error;
	  	}

	    err = http_res->put_header(http_res,"Content-Type","application/octet-stream");

	  }else{
	    err = RHP_STATUS_SKIP;
	    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_GET_INVALID_CONTENT_TYPE,"x",http_conn);
	    goto error;
	  }
	
	  if( err ){
	    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_SET_CONTENT_TYPE_ERR,"xE",http_conn,err);
	    goto error;    	
	  }
	
	  if( path_fixed == NULL ){

			path = (char*)_rhp_malloc( strlen(http_conn->root_dir) + strlen(filename) + 2 );
			if( path == NULL ){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			path[0] = '\0';

			sprintf(path,"%s/%s",http_conn->root_dir,filename);

	  }else{

	  	path = path_fixed;
	  }

	  fd = open(path,O_RDONLY);
	  if( fd < 0 ){

	    err = RHP_STATUS_SKIP;

	    if( is_cfg_bkup || is_packet_capture ){
	  		err = -ENOENT;
	  	}

	    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_GET_NO_FILE,"xsd",http_conn,path,is_cfg_bkup);
	    goto error;    	
	  }
	
	  mesg_body = (char*)_rhp_malloc(RHP_HTTP_DEFAULT_HANDLER_FBUF_LEN);
	  if( mesg_body == NULL ){
	    err = -ENOMEM;
	    RHP_BUG("");
	    goto error;
	  }
	
	  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_GET_READING_FILE,"xs",http_conn,path);
	    
	  while( 1 ){
	      
	  	n = read(fd,mesg_body,RHP_HTTP_DEFAULT_HANDLER_FBUF_LEN);    	
	  	if( n < 0 ){
	    	
	  		err = -errno;
	     if( err == -EINTR ){

	    	 err = 0;
	       continue;

	     }else if( is_cfg_bkup || is_packet_capture ){

	    	 err = -ENOENT;
	     }
	
	     RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_GET_READING_FILE_ERR,"xsE",http_conn,path,err);
	     goto error;
	
	  	}else if( n == 0 ){
	    	RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_GET_READING_FILE_END,"xs",http_conn,path);
	    	break;    	  
	  	}
	      
	  	if( http_res->mesg_body == NULL ){
	    	  
	  		http_res->mesg_body = (char*)_rhp_malloc(RHP_HTTP_DEFAULT_HANDLER_TXBUF_LEN);
	  		if( http_res->mesg_body == NULL ){
	  			RHP_BUG("");   	    	
	  		}
	   	    
	  		rem_len = RHP_HTTP_DEFAULT_HANDLER_TXBUF_LEN;
	  		http_res->mesg_body_len = 0;
	  	}
	      
	  	if( rem_len <= (long)n ){
	
	  		char* new_buf = NULL;
	  		long exp_len = (n > RHP_HTTP_DEFAULT_HANDLER_TXBUF_LEN ? (long)n : RHP_HTTP_DEFAULT_HANDLER_TXBUF_LEN);
	  		long new_buf_len = http_res->mesg_body_len + exp_len;
	   	    
	  		new_buf = (char*)_rhp_malloc(new_buf_len);
	  		if( new_buf == NULL ){
	  			err = -ENOMEM;
	  			RHP_BUG("");
	  			goto error;
	  		}
	        
	  		rem_len = exp_len;
	
	  		memcpy(new_buf,http_res->mesg_body,http_res->mesg_body_len);
	  		_rhp_free(http_res->mesg_body);
	  		http_res->mesg_body = new_buf;
	  	}
	      
	  	memcpy( ((u8*)http_res->mesg_body) + http_res->mesg_body_len,mesg_body,(size_t)n);  
	  	http_res->mesg_body_len += (long)n;
	  	rem_len -= n;
	  }
	  
	  if( http_res->mesg_body == NULL ){
	  	err = RHP_STATUS_SKIP;
	  	RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_GET_NO_MESG_BODY,"xx",http_conn,http_res);
	  	goto error;    	
	  }
	    
	  err = rhp_http_tx_server_response(http_conn,http_res,tx_auth_cookie);
	  if( err ){
	  	RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_GET_TX_RESP_FAILED,"xxE",http_conn,http_res,err);
	  	err = RHP_STATUS_ABORT_HTTP_CONN;	  
	  	goto error;   		  
	  }

	  if( event_log_name ){
	  	_rhp_free(event_log_name);
	  }
	
	  if( path_fixed == NULL ){
	  	_rhp_free(path);
	  }
	  _rhp_free(mesg_body);
	  close(fd);	  

    rhp_http_res_free(http_res);

	  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_RTRN,"xxE",http_conn,http_res,ulerr);
	  return RHP_STATUS_CLOSE_HTTP_CONN;
  }
  
pending:
error:
	if( is_cfg_bkup && path ){
		if( unlink(path) < 0 ){
			ulerr = -errno;
		}
	}
  if( http_res ){
    rhp_http_res_free(http_res);	  
  }
  if( fd >= 0 ){
    close(fd);	  
  }
  if( path_fixed == NULL && path ){
    _rhp_free(path);	  
  }
  if( mesg_body ){
    _rhp_free(mesg_body);	  
  }
  if( event_log_name ){
  	_rhp_free(event_log_name);
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ROOT_DIR_HANDLER_ERR,"xEE",http_conn,ulerr,err);
  return err;
}


int rhp_http_create_simple_xml_response(rhp_http_response* http_res,char* contents)
{
	int err = -EINVAL;

  err = http_res->put_header(http_res,"Content-Type","text/xml; charset=utf-8");
  if( err ){
  	RHP_BUG("");
  	goto error;
  }

	http_res->mesg_body_len = strlen("<?xml version=\"1.0\"?>");
	http_res->mesg_body_len += strlen(contents);

	http_res->mesg_body = (char*)_rhp_malloc(http_res->mesg_body_len + 1);
	if( http_res->mesg_body == NULL ){
		RHP_BUG("");
		http_res->mesg_body_len = 0;
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}

	http_res->mesg_body[0] = '\0';
	sprintf(http_res->mesg_body,"%s%s","<?xml version=\"1.0\"?>",contents);

	return 0;

error:
	return err;
}


static int _rhp_http_server_auth_test_handler(rhp_http_conn* http_conn,int authorized,void* ctx)
{
  int err = RHP_STATUS_SKIP;
  rhp_http_request* http_req = http_conn->http_req;
  rhp_http_response* http_res = NULL;
  char tmp[64];
  int bus_sess_exists = 0;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_TEST_HANDLER,"xdx",http_conn,authorized,ctx);

  if( http_req == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_TEST_HANDLER_NO_REQ,"x",http_conn);
    return RHP_STATUS_SKIP;
  }

  if( http_req->method == NULL || http_req->uri == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_TEST_HANDLER_REQ_INVALID_PARMS,"xxx",http_conn,http_req->method,http_req->uri);
    return RHP_STATUS_SKIP;
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_TEST_HANDLER_PARMS,"xss",http_conn,http_req->method,http_req->uri);

  if( !strcmp(http_req->method,"PUT") ){

		if( strcasecmp(http_req->uri,"/protected/authentication") ){
		  err = RHP_STATUS_SKIP;
		  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_TEST_HANDLER_GET_INVALID_URI,"x",http_conn);
		  goto error;
		}

		if( !authorized ){

			err = rhp_http_auth_request(http_conn,(unsigned long)-1);
			if( err){
				RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_TEST_HANDLER_GET_AUTH_BASIC_ERR,"xE",http_conn,err);
				goto error;
			}

			err = rhp_http_server_conn_timer_restart(http_conn);
			if( err ){
	   		 RHP_BUG("%d",err);
	   		 goto error;
			}

			err = RHP_STATUS_HTTP_REQ_PENDING;

		  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_TEST_HANDLER_GET_GO_PEND,"x",http_conn);
		  goto pending;
		}


		{
			rhp_http_bus_session* http_bus_sess = rhp_http_bus_sess_get(-1,http_conn->user_name);
			if( http_bus_sess ){
				rhp_http_bus_sess_unhold(http_bus_sess);
				bus_sess_exists = 1;
			}
		}


	  http_res = rhp_http_res_alloc("200","OK");
	  if( http_res == NULL ){
	    err = -ENOMEM;
	    RHP_BUG("");
	    goto error;
	  }


	  {
			err = http_res->put_header(http_res,"Content-Type","text/xml; charset=utf-8");
			if( err ){
				RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_TEST_HANDLER_GET_PUT_HEADER_ERR,"xE",http_conn,err);
				goto error;
			}

			http_res->mesg_body_len = strlen("<?xml version=\"1.0\"?>");

			http_res->mesg_body_len++; // 'http_bus_is_opened'

			tmp[0] = '\0';
			http_res->mesg_body_len += snprintf(tmp,64,"%lu",http_conn->user_realm_id);

			if( !http_conn->is_nobody ){
				if( http_conn->user_realm_id == 0 ){
					http_res->mesg_body_len += strlen("<rhp_auth_response authority=\"all\" vpn_realm=\"\" http_bus_is_open=\"\"/>");
				}else{
					http_res->mesg_body_len += strlen("<rhp_auth_response authority=\"realm-only\" vpn_realm=\"\" http_bus_is_open=\"\"/>");
				}
			}else{
				http_res->mesg_body_len += strlen("<rhp_auth_response authority=\"nobody\" vpn_realm=\"\" http_bus_is_open=\"\"/>");
			}

			http_res->mesg_body = (char*)_rhp_malloc(http_res->mesg_body_len + 1);
			if( http_res->mesg_body == NULL ){
				RHP_BUG("");
				http_res->mesg_body_len = 0;
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}

			http_res->mesg_body[0] = '\0';

			if( !http_conn->is_nobody ){

				if( http_conn->user_realm_id == 0 ){

					sprintf(http_res->mesg_body,"%s%s%s%d%s",
							"<?xml version=\"1.0\"?><rhp_auth_response authority=\"all\" vpn_realm=\"",
							tmp,
							"\" http_bus_is_open=\"",
							bus_sess_exists,
							"\"/>");

				}else{

					sprintf(http_res->mesg_body,"%s%s%s%d%s",
							"<?xml version=\"1.0\"?><rhp_auth_response authority=\"realm-only\" vpn_realm=\"",
							tmp,
							"\" http_bus_is_open=\"",
							bus_sess_exists,
							"\"/>");
				}

			}else{

				sprintf(http_res->mesg_body,"%s%s%s%d%s",
						"<?xml version=\"1.0\"?><rhp_auth_response authority=\"nobody\" vpn_realm=\"",
						tmp,
						"\" http_bus_is_open=\"",
						bus_sess_exists,
						"\"/>");
			}
	  }


	  err = rhp_http_tx_server_response(http_conn,http_res,1);
	 	if( err ){
	 		RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_TEST_HANDLER_GET_TX_RESP_ERR,"xE",http_conn,err);
	 		err = RHP_STATUS_ABORT_HTTP_CONN;
	 		goto error;
	 	}

    rhp_http_res_free(http_res);

  	RHP_LOG_I(RHP_LOG_SRC_UI,0,RHP_LOG_ID_ADMIN_AUTH_OK,"suAA",http_conn->user_name,http_conn->user_realm_id,&(http_conn->my_addr),&(http_conn->dst_addr));

 		RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_TEST_HANDLER_RTRN,"x",http_conn);
 		return RHP_STATUS_CLOSE_HTTP_CONN;
  }

pending:
error:
  if( http_res ){
    rhp_http_res_free(http_res);
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_TEST_HANDLER_ERR,"x",http_conn);
  return err;
}

// Sync login status. (ex) Sync rhp-auth-nonce between server and browser.
static int _rhp_http_server_sync_handler(rhp_http_conn* http_conn,int authorized,void* ctx)
{
  int err = RHP_STATUS_SKIP;
  rhp_http_request* http_req = http_conn->http_req;
  rhp_http_response* http_res = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_SYNC_HANDLER,"xdx",http_conn,authorized,ctx);

  if( http_req == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_SYNC_HANDLER_NO_REQ,"x",http_conn);
    return RHP_STATUS_SKIP;
  }

  if( http_req->method == NULL || http_req->uri == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_SYNC_HANDLER_REQ_INVALID_PARMS,"xxx",http_conn,http_req->method,http_req->uri);
    return RHP_STATUS_SKIP;
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_SYNC_HANDLER_PARMS,"xss",http_conn,http_req->method,http_req->uri);

  if( !strcmp(http_req->method,"PUT") ){

		if( strcasecmp(http_req->uri,"/sync") ){
		  err = RHP_STATUS_SKIP;
		  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_SYNC_HANDLER_GET_INVALID_URI,"x",http_conn);
		  goto error;
		}

	  http_res = rhp_http_res_alloc("200","OK");
	  if( http_res == NULL ){
	    err = -ENOMEM;
	    RHP_BUG("");
	    goto error;
	  }


	  err = rhp_http_tx_server_response(http_conn,http_res,1); // Set-cookie: rhp-auth-nonce(newest)
	 	if( err ){
	 		RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_SYNC_HANDLER_GET_TX_RESP_ERR,"xE",http_conn,err);
	 		err = RHP_STATUS_ABORT_HTTP_CONN;
	 		goto error;
	 	}

    rhp_http_res_free(http_res);

 		RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_SYNC_HANDLER_RTRN,"x",http_conn);
 		return RHP_STATUS_CLOSE_HTTP_CONN;
  }

error:
  if( http_res ){
    rhp_http_res_free(http_res);
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_SYNC_HANDLER_ERR,"x",http_conn);
  return err;
}

#ifdef RHP_HTTP_SERVER_PING
static int _rhp_http_server_ping_handler(rhp_http_conn* http_conn,int authorized,void* ctx)
{
  int err = RHP_STATUS_SKIP;
  rhp_http_request* http_req = http_conn->http_req;	
  rhp_http_response* http_res = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PING_HANDLER,"xdx",http_conn,authorized,ctx);
  
  if( http_req == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PING_HANDLER_NO_REQ,"x",http_conn);
    return RHP_STATUS_SKIP;	  
  }

  if( http_req->method == NULL || http_req->uri == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PING_HANDLER_REQ_INVALID_PARMS,"xxx",http_conn,http_req->method,http_req->uri);
    return RHP_STATUS_SKIP;	  
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PING_HANDLER_PARMS,"xss",http_conn,http_req->method,http_req->uri);
  
  if( !strcmp(http_req->method,"GET") ){
	  
		if( strcasecmp(http_req->uri,"/protected/ping") ){
		  err = RHP_STATUS_SKIP;
		  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PING_HANDLER_GET_INVALID_URI,"x",http_conn);
		  goto error;
		}
	
		if( !authorized ){
	
			err = rhp_http_auth_basic_request(http_conn,(unsigned long)-1);
			if( err){
				RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PING_HANDLER_GET_AUTH_BASIC_ERR,"xE",http_conn,err);
				goto error;
			}
	
			err = rhp_http_server_conn_timer_restart(http_conn);
			if( err ){
	   		 RHP_BUG("%d",err);
	   		 goto error;
			}
	       
			err = RHP_STATUS_HTTP_REQ_PENDING;
	
		  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PING_HANDLER_GET_GO_PEND,"x",http_conn);
		  goto pending;
		}
		
	  http_res = rhp_http_res_alloc("200","OK");
	  if( http_res == NULL ){
	    err = -ENOMEM;
	    RHP_BUG("");
	    goto error;
	  }
	
	  err = http_res->put_header(http_res,"Content-Type","text/html; charset=utf-8");
	  if( err ){
	  	RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PING_HANDLER_GET_PUT_HEADER_ERR,"xE",http_conn,err);
	  	goto error;    	
	  }
	    
		http_res->mesg_body_len = strlen(RHP_HTTP_PING_RESPONSE_MSG);
		http_res->mesg_body = (char*)_rhp_malloc(http_res->mesg_body_len + 1);
		if( http_res->mesg_body == NULL ){
			RHP_BUG("");
			http_res->mesg_body_len = 0;
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
	  http_res->mesg_body[0] = '\0';
	  strcpy(http_res->mesg_body,RHP_HTTP_PING_RESPONSE_MSG);
	    
	  err = rhp_http_tx_server_response(http_conn,http_res);
	 	if( err ){
	 		RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PING_HANDLER_GET_TX_RESP_ERR,"xE",http_conn,err);
	 		err = RHP_STATUS_ABORT_HTTP_CONN;	  
	 		goto error;   		  
	 	}

    rhp_http_res_free(http_res);

 		RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PING_HANDLER_RTRN,"x",http_conn);
 		return RHP_STATUS_CLOSE_HTTP_CONN;
  }
  
pending:
error:
  if( http_res ){
    rhp_http_res_free(http_res);	  
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PING_HANDLER_ERR,"x",http_conn);
  return err;
}
#endif // RHP_HTTP_SERVER_PING

extern int rhp_http_bus_init();
extern int rhp_http_clt_init();

int rhp_http_server_init()
{
  int err;

  RHP_TRC(0,RHPTRCID_HTTP_INIT,"");
  
  _rhp_mutex_init("HTG",&_rhp_http_lock);

  if( (err = rhp_http_clt_init()) ){
  	RHP_BUG("");
    return err;
  }

  if( (err = rhp_http_bus_init()) ){
  	RHP_BUG("");
    return err;   	  
  }

  rhp_http_server_register_handler(_rhp_http_server_rootdir_handler,NULL,1); // This must be the 1st registered handler.

  rhp_http_server_register_handler(_rhp_http_server_sync_handler,NULL,1);

  rhp_http_server_register_handler(_rhp_http_server_auth_test_handler,NULL,1);


#ifdef RHP_HTTP_SERVER_PING
  rhp_http_server_register_handler(_rhp_http_server_ping_handler,NULL,0);
#endif // RHP_HTTP_SERVER_PING

  {
  	u8 nonce[RHP_HTTP_AUTH_COOKIE_NONCE_SIZE];

  	rhp_random_bytes(nonce,RHP_HTTP_AUTH_COOKIE_NONCE_SIZE);
  	_rhp_http_nonce2str(nonce,_rhp_http_auth_cookie_nonce_str);

  	rhp_random_bytes(nonce,RHP_HTTP_AUTH_COOKIE_NONCE_SIZE);
  	_rhp_http_nonce2str(nonce,_rhp_http_auth_cookie_nonce_str_old);

  	_rhp_http_auth_cookie_nonce_last_updated = _rhp_get_time();
  }
  
  _rhp_atomic_init(&_rhp_http_svr_sk_num);


  RHP_TRC(0,RHPTRCID_HTTP_INIT_RTRN,"");
  return 0;
}

extern void rhp_http_bus_cleanup();
extern int rhp_http_clt_cleanup();

void rhp_http_server_cleanup()
{
  RHP_TRC(0,RHPTRCID_HTTP_CLEANUP,"");
  
  rhp_http_bus_cleanup();

  rhp_http_clt_cleanup();

  _rhp_mutex_destroy(&_rhp_http_lock);
  
	_rhp_atomic_destroy(&_rhp_http_svr_sk_num);

  RHP_TRC(0,RHPTRCID_HTTP_CLEANUP_RTRN,"");
}

static int _rhp_http_req_parse_header(char* header_string,long len,rhp_http_header** header_r)
{
  int err = 0;
  char *p = header_string,*p2 = NULL;
  char* name = NULL;
  char* value = NULL;
  long name_len,value_len;
  rhp_http_header* header = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQ_PARSE_HEADER,"px",( len > 128 ? 128 : len),header_string,header_r);

  while( *p != '\r' && len > 0 ){

  	if( name == NULL && *p == ':' ){

  		name_len = (((u8*)p) - ((u8*)header_string));

  		if( name_len < 1 ){
  			err = RHP_STATUS_INVALID_MSG;
  			goto error;
  		}

  		name = (char*)_rhp_malloc(name_len + 1);
  		if( name == NULL ){
        err = -ENOMEM;
        goto error;
  		}

  		memset(name,0,name_len+1);
  		memcpy(name,header_string,name_len);

  		p2 = (p + 1);
  	}

  	p++;
  	len--;
  }

  if( p2 == NULL || *p != '\r' ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQ_PARSE_HEADER_INVALID_STRING,"x",header_string);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  value_len = (((u8*)p) - ((u8*)p2));

  if( value_len ){

		char* p3 = p2;
		int p3_len = value_len;

		while( p3_len > 0 ){

		  if( *p3 == ' ' || *p3 == '\t' ){
		    p3++;
		    p3_len--;
		    continue;
		  }

		  break;
		}

		value_len = p3_len;
		if( value_len ){

		  value = (char*)_rhp_malloc(value_len+1);
		  if( value == NULL ){
	        err = -ENOMEM;
	        goto error;
		  }

		  memset(value,0,value_len+1);
		  memcpy(value,(p2+1),value_len);
		}

  }else{
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQ_PARSE_HEADER_NO_VALUE,"x",header_string);
  }

  header = (rhp_http_header*)_rhp_malloc(sizeof(rhp_http_header));
  if( header == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  memset(header,0,sizeof(rhp_http_header));
  header->name = name;
  header->value = value;

  *header_r = header;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQ_PARSE_HEADER_RTRN,"xxxsxsd",header_string,*header_r,header->name,header->name,header->value,header->value,(strlen(header->value) + 1));
  return 0;

error:
  if( name ){
    _rhp_free(name);
  }
  if( value ){
    _rhp_free(value);
  }
  if( header ){
    _rhp_free(header);
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQ_PARSE_HEADER_ERR,"xE",header_string,err);
  return err;
}

static int _rhp_http_req_put_header(rhp_http_request* http_req,char* header_string,long len,rhp_http_header** header_r)
{
  int err = 0;
  rhp_http_header* header = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQ_PUT_HEADER,"xpx",http_req,(len > 128 ? 128 : len),header_string,header_r);
  
  err = _rhp_http_req_parse_header(header_string,len,&header);
  if( err ){
  	goto error;
  }

  if( http_req->headers_head == NULL ){
    http_req->headers_head = header;
  }else{
    http_req->headers_tail->next = header;
  }
  http_req->headers_tail = header;

  if( header_r ){
    *header_r = header;	  
  }
  
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQ_PUT_HEADER_RTRN,"xx",http_req,*header_r);
  return 0;	
  
error:
  if( header ){
    _rhp_free(header);	  
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQ_PUT_HEADER_ERR,"xE",http_req,err);
  return err;
}

static rhp_http_header* _rhp_http_req_get_header(rhp_http_request* http_req,char* name)
{
  rhp_http_header* header = http_req->headers_head;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQ_GET_HEADER,"xsx",http_req,name,http_req->headers_head);
  
  while( header ){
	  
    if( !strcasecmp(name,header->name) ){
   	  RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQ_GET_HEADER_RTRN,"xx",http_req,header);
      return header;    	
    }
    
    header = header->next;
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQ_GET_HEADER_ERR,"x",http_req);
  return NULL;	
}

static rhp_http_request* _rhp_http_req_alloc()
{
  rhp_http_request* http_req = NULL;
  
  http_req = (rhp_http_request*)_rhp_malloc(sizeof(rhp_http_request));
  if( http_req == NULL ){
    RHP_BUG("");
    goto error;
  }

  memset(http_req,0,sizeof(rhp_http_request));
  
  http_req->tag[0] = '#';
  http_req->tag[1] = 'H';
  http_req->tag[2] = 'R';
  http_req->tag[3] = 'Q';

  http_req->parsing_stat = RHP_HTTP_REQ_PARSE_INIT;  
  
  http_req->put_header = _rhp_http_req_put_header;  
  http_req->get_header = _rhp_http_req_get_header;  
  
  http_req->content_length = -1;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQ_ALLOC,"x",http_req);
  return http_req;
  
error:
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQ_ALLOC_ERR,"");
  return NULL;
}

static void _rhp_http_header_free(rhp_http_header *header)
{
  if( header->name ){
    _rhp_free(header->name);
  }
  if( header->value ){
    _rhp_free_zero(header->value,strlen(header->value) + 1);
  }
  _rhp_free(header);
  return;
}

void rhp_http_req_free(rhp_http_request* http_req)
{
  rhp_http_header *header1 = NULL,*header2 = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQ_FREE,"x",http_req);
  
  if( http_req->method ){
    _rhp_free(http_req->method);	  
  }

  if( http_req->uri ){
    _rhp_free(http_req->uri);	  
  }

  if( http_req->version ){
    _rhp_free(http_req->version);	  
  }

  if( http_req->xml_doc ){
    xmlFreeDoc((xmlDocPtr)(http_req->xml_doc));
  }
  
  if( http_req->mesg_body ){
    _rhp_free(http_req->mesg_body);	  
  }

  if( http_req->parsing_buf ){
    _rhp_free(http_req->parsing_buf);	  
  }
  
  if( http_req->clt_version ){
  	_rhp_free(http_req->clt_version);
  }

  if( http_req->service_name ){
  	_rhp_free(http_req->service_name);
  }

  header1 = http_req->headers_head;
  while( header1 ){
  	header2 = header1->next;
  	_rhp_http_header_free(header1);
    header1 = header2;
  }

  if( http_req->multipart_form_data ){

  	rhp_http_body_part *body_part1, *body_part2;

  	body_part1 = http_req->multipart_form_data->part_head;
  	while( body_part1 ){

  		body_part2 = body_part1->next;

      header1 = body_part1->headers_head;
      while( header1 ){
      	header2 = header1->next;
      	_rhp_http_header_free(header1);
        header1 = header2;
      }

      if( body_part1->form_name ){
      	_rhp_free(body_part1->form_name);
      }

      if( body_part1->form_filename ){
      	_rhp_free(body_part1->form_filename);
      }

      _rhp_free(body_part1);

  		body_part1 = body_part2;
  	}

  	_rhp_free(http_req->multipart_form_data);
  }

  if( http_req->cookie.user_name ){
  	_rhp_free(http_req->cookie.user_name);
  }

  if( http_req->cookie.nonce ){
  	_rhp_free(http_req->cookie.nonce);
  }

  if( http_req->cookie.ticket ){
  	_rhp_free_zero(http_req->cookie.ticket,RHP_HTTP_AUTH_TICKET_SIZE);
  }

  _rhp_free(http_req);
  
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQ_FREE_RTRN,"x",http_req);
  return;
}

static int _rhp_http_res_put_header(rhp_http_response* http_res,char* name,char* value)
{
  int err = 0;
  rhp_http_header* header = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_RES_PUT_HEADER,"xss",http_res,name,value);
  
  header = (rhp_http_header*)_rhp_malloc(sizeof(rhp_http_header));
  if( header == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  memset(header,0,sizeof(rhp_http_header));
  
  header->name = (char*)_rhp_malloc(strlen(name)+1);
  header->value = (char*)_rhp_malloc(strlen(value)+1);

  if( header->name == NULL || header->value == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  header->name[0] = '\0'; 
  header->value[0] = '\0'; 
  
  strcpy(header->name,name);
  strcpy(header->value,value);

  if( http_res->headers_head == NULL ){
    http_res->headers_head = header;	  
  }else{
    http_res->headers_tail->next = header;	  
  }
  http_res->headers_tail = header;
  
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_RES_PUT_HEADER_RTRN,"xx",http_res,header);
  return 0;	
  
error:
  if( header ){
    if( header->name ){
	  _rhp_free(header->name);	  
	}
	if( header->value ){
	  _rhp_free(header->value);	  
	}
    _rhp_free(header);	  
  }
  
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_RES_PUT_HEADER_ERR,"xE",http_res,err);
  return err;
}

static rhp_http_header* _rhp_http_res_get_header(rhp_http_response* http_res,char* name)
{
  rhp_http_header* header = http_res->headers_head;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_RES_GET_HEADER,"xs",http_res,name);
  
  while( header ){
	  
    if( !strcasecmp(name,header->name) ){
   	  RHP_TRC_FREQ(0,RHPTRCID_HTTP_RES_GET_HEADER_RTRN,"xx",http_res,header);
      return header;    	
    }
    
    header = header->next;
  }
  
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_RES_GET_HEADER_ERR,"x",http_res);
  return NULL;	
}

#define RHP_HTTP_DEF_AUTH_COOKIE_SIZE		(128 + (RHP_HTTP_AUTH_COOKIE_NONCE_SIZE*2) + 1)
static char* _rhp_http_res_gen_auth_cookie(char* nonce,int max_age_secs)
{
	int err = -EINVAL;
	char* set_cookie_str = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_RES_GEN_AUTH_COOKIE,"sd",nonce,max_age_secs);

  set_cookie_str = (char*)_rhp_malloc(RHP_HTTP_DEF_AUTH_COOKIE_SIZE);
  if( set_cookie_str == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }

	set_cookie_str[0] = '\0';
	snprintf(set_cookie_str,RHP_HTTP_DEF_AUTH_COOKIE_SIZE,"rhp-auth-nonce=%s; Max-Age=%d; path=/",nonce,max_age_secs);

	RHP_TRC_FREQ(0,RHPTRCID_HTTP_RES_GEN_AUTH_COOKIE_RTRN,"ss",nonce,set_cookie_str);

	return set_cookie_str;

error:
	if( set_cookie_str ){
		_rhp_free(set_cookie_str);
	}

	RHP_TRC_FREQ(0,RHPTRCID_HTTP_RES_GEN_AUTH_COOKIE_ERR,"sE",nonce,err);
	return NULL;
}


static int _rhp_http_res_set_auth_cookie(rhp_http_response* http_res,char* nonce,int max_age_secs)
{
	int err = -EINVAL;
	char* set_cookie_str = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_RES_SET_AUTH_COOKIE,"xsd",http_res,nonce,max_age_secs);

  set_cookie_str = _rhp_http_res_gen_auth_cookie(nonce,max_age_secs);
  if( set_cookie_str == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }

	err = _rhp_http_res_put_header(http_res,"Set-Cookie",set_cookie_str);
	if( err ){
		goto error;
	}

error:
	if( set_cookie_str ){
		_rhp_free(set_cookie_str);
	}

	RHP_TRC_FREQ(0,RHPTRCID_HTTP_RES_SET_AUTH_COOKIE_RTRN,"xE",http_res,err);
	return err;
}

rhp_http_response* rhp_http_res_alloc(char* status_code,char* reason_phrase)
{
  rhp_http_response* http_res = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_RES_ALLOC,"ss",status_code,reason_phrase);
  
  http_res = (rhp_http_response*)_rhp_malloc(sizeof(rhp_http_response));
  if( http_res == NULL ){
    RHP_BUG("");
    goto error;
  }

  memset(http_res,0,sizeof(rhp_http_response));

  http_res->tag[0] = '#';
  http_res->tag[1] = 'H';
  http_res->tag[2] = 'R';
  http_res->tag[3] = 'S';
  
  if( status_code ){
	  
    http_res->status_code = (char*)_rhp_malloc(strlen(status_code)+1);
    if( http_res->status_code == NULL ){
      RHP_BUG("");
      goto error;    	
    }
    
    http_res->status_code[0] = '\0';
    strcpy(http_res->status_code,status_code);
  }

  if( reason_phrase ){
	  
    http_res->reason_phrase = (char*)_rhp_malloc(strlen(reason_phrase)+1);
    if( http_res->reason_phrase == NULL ){
      RHP_BUG("");
      goto error;    	
    }
    
    http_res->reason_phrase[0] = '\0';
    strcpy(http_res->reason_phrase,reason_phrase);
  }
  
  http_res->put_header = _rhp_http_res_put_header;  
  http_res->get_header = _rhp_http_res_get_header;  
  http_res->set_auth_cookie = _rhp_http_res_set_auth_cookie;
	  
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_RES_ALLOC_RTRN,"x",http_res);
  return http_res;
	  
error:
  if( http_res ){
    rhp_http_res_free(http_res);
  }
  
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_RES_ALLOC_ERR,"");
  return NULL;
}

void rhp_http_res_free(rhp_http_response* http_res)
{
  rhp_http_header *header = NULL,*header_n = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_RES_FREE,"x",http_res);
  
  if( http_res->status_code ){
    _rhp_free(http_res->status_code);	  
  }

  if( http_res->reason_phrase ){
    _rhp_free(http_res->reason_phrase);	  
  }

  if( http_res->mesg_body ){
    _rhp_free(http_res->mesg_body);	  
  }

  header = http_res->headers_head;
  while( header ){
  	header_n = header->next;
  	_rhp_http_header_free(header);
    header = header_n;
  }

  _rhp_free(http_res);
  
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_RES_FREE_RTRN,"x",http_res);
  return;
}

static void _rhp_http_free_server(rhp_http_listen* listen_sk)
{
  rhp_cfg_peer_acl *acl_addr = listen_sk->acl_addrs,*acl_addr2;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_FREE_SERVER,"x",listen_sk);
  
  while( acl_addr ){
    acl_addr2 = acl_addr->next;
    _rhp_free(acl_addr);
    acl_addr = acl_addr2;
  }

  if( listen_sk->root_dir ){
    _rhp_free_zero(listen_sk->root_dir,strlen(listen_sk->root_dir)+1);	  
  }
  
  _rhp_mutex_destroy(&(listen_sk->lock));
  _rhp_atomic_destroy(&(listen_sk->is_active));
  _rhp_atomic_destroy(&(listen_sk->refcnt));
  
  _rhp_free(listen_sk);  

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_FREE_SERVER_RTRN,"x",listen_sk);
}

void rhp_http_svr_hold(rhp_http_listen* listen_sk)
{
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SVR_HOLD,"xd",listen_sk,listen_sk->refcnt.c);
  _rhp_atomic_inc(&(listen_sk->refcnt));
}

void rhp_http_svr_unhold(rhp_http_listen* listen_sk)
{
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SVR_UNHOLD,"xd",listen_sk,listen_sk->refcnt.c);
  if( _rhp_atomic_dec_and_test(&(listen_sk->refcnt)) ){
    _rhp_http_free_server(listen_sk);
  }
}

// Caller must acquire listen_sk->lock
int rhp_http_server_set_client_acls(rhp_http_listen* listen_sk,rhp_cfg_peer_acl* acl_addrs)
{
	int err = -EINVAL;
  rhp_cfg_peer_acl *acl_addr = NULL,*acl_addr2 = NULL,*acl_addrs_tail = NULL;
  rhp_cfg_peer_acl* old_acl_addrs = listen_sk->acl_addrs;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SVR_SET_CLIENT_ACLS,"xux",listen_sk,listen_sk->id,acl_addrs);

  listen_sk->acl_addrs = NULL;

  acl_addr2 = acl_addrs;
  while( acl_addr2 ){

  	acl_addr = (rhp_cfg_peer_acl*)_rhp_malloc(sizeof(rhp_cfg_peer_acl));
		if( acl_addr == NULL ){
		  RHP_BUG("");
		  err = -ENOMEM;
		  goto error;
		}
		memset(acl_addr,0,sizeof(rhp_ip_addr_list));
		memcpy(acl_addr,acl_addr2,sizeof(rhp_cfg_peer_acl));
		acl_addr->next = NULL;

		if( listen_sk->acl_addrs == NULL ){
      listen_sk->acl_addrs = acl_addr;
		}else{
   	  acl_addrs_tail->next = acl_addr;
    }
		acl_addrs_tail = acl_addr;

		acl_addr2 = acl_addr2->next;
  }

  if( old_acl_addrs ){

  	acl_addr2 = old_acl_addrs;
    while( acl_addr2 ){
    	rhp_cfg_peer_acl* acl_n = acl_addr2->next;
    	_rhp_free(acl_addr2);
  		acl_addr2 = acl_n;
    }
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SVR_SET_CLIENT_ACLS_RTRN,"xx",listen_sk,acl_addrs);
  return 0;

error:
	acl_addr2 = listen_sk->acl_addrs;
	while( acl_addr2 ){
		rhp_cfg_peer_acl* acl_n = acl_addr2->next;
		_rhp_free(acl_addr2);
		acl_addr2 = acl_n;
	}

	listen_sk->acl_addrs = old_acl_addrs;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SVR_SET_CLIENT_ACLS_ERR,"xxE",listen_sk,acl_addrs,err);
	return err;
}

int rhp_http_server_open(unsigned long id,rhp_ip_addr* my_addr,
		rhp_cfg_peer_acl* acl_addrs,int max_connection,char* root_dir,
		unsigned long keep_alive_interval,rhp_http_listen** listen_sk_r)
{
  int err = -EINVAL;
  rhp_http_listen* listen_sk = NULL;	
  int sk = -1;
  union {
    struct sockaddr_in 	v4;
    struct sockaddr_in6 v6;
    unsigned char raw;
  } my_sin;
  int my_sin_len;
  int flag;
  struct epoll_event ep_evt;

  if( root_dir == NULL ){
    err = -EINVAL;
    goto error;
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_OPEN,"dxxdsdx",id,my_addr,acl_addrs,max_connection,root_dir,keep_alive_interval,listen_sk_r);
  rhp_ip_addr_dump("rhp_http_server_open.my_addr",my_addr);
  
  listen_sk = (rhp_http_listen*)_rhp_malloc(sizeof(rhp_http_listen));
  if( listen_sk == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }
  memset(listen_sk,0,sizeof(rhp_http_listen));
  
  listen_sk->tag[0] = '#';
  listen_sk->tag[1] = 'H';
  listen_sk->tag[2] = 'T';
  listen_sk->tag[3] = 'L';

  _rhp_mutex_init("HTL",&(listen_sk->lock));
  _rhp_atomic_init(&(listen_sk->is_active));
  _rhp_atomic_init(&(listen_sk->refcnt));
  _rhp_atomic_init(&(listen_sk->cur_conns));
  
  listen_sk->id = id;

  listen_sk->root_dir = (char*)_rhp_malloc(strlen(root_dir)+1);
  if( listen_sk->root_dir == NULL ){
	 RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }
  listen_sk->root_dir[0] = '\0';
  strcpy(listen_sk->root_dir,root_dir);

  listen_sk->sk = -1;

  listen_sk->keep_alive_interval = keep_alive_interval;

  if( listen_sk->keep_alive_interval == 0 ){

    listen_sk->keep_alive_interval = rhp_gcfg_http_rx_timeout;	  

    if( listen_sk->keep_alive_interval < 1 ){
   	  listen_sk->keep_alive_interval = 1;    	
    }
  }
  
  listen_sk->max_conns = max_connection;
  
  memcpy(&(listen_sk->my_addr),my_addr,sizeof(rhp_ip_addr));

	err = rhp_http_server_set_client_acls(listen_sk,acl_addrs);
	if( err ){
		RHP_BUG("");
		goto error;
	}

  sk = socket(my_addr->addr_family,SOCK_STREAM,0);
  if( sk < 0 ){
    err = -errno;
    RHP_BUG("%d",err);
    goto error;
  }

  switch( my_addr->addr_family ){

    case AF_INET:

    	my_sin.v4.sin_family = AF_INET;
			my_sin.v4.sin_port = my_addr->port;
			my_sin.v4.sin_addr.s_addr = my_addr->addr.v4;
			my_sin_len = sizeof(struct sockaddr_in);

			break;

    case AF_INET6:

    	my_sin.v6.sin6_family = AF_INET6;
      my_sin.v6.sin6_port = my_addr->port;
  		my_sin.v6.sin6_flowinfo = 0;
      memcpy(my_sin.v6.sin6_addr.s6_addr,my_addr->addr.v6,16);
  		if( rhp_ipv6_is_linklocal(my_addr->addr.v6) ){
  			my_sin.v6.sin6_scope_id = my_addr->ipv6_scope_id;
  		}else{
  			my_sin.v6.sin6_scope_id = 0;
  		}
      my_sin_len = sizeof(struct sockaddr_in6);

      break;

    default:
      err = -EAFNOSUPPORT;
      RHP_BUG("%d",my_addr->addr_family);
      goto error;
  }

  flag = 1;
  if( setsockopt(sk,SOL_SOCKET,SO_REUSEADDR,(const char *)&flag, sizeof(flag)) < 0 ){
    err = -errno;
    RHP_BUG("%d",err);
    goto error;
  }
  
  if( bind(sk,(struct sockaddr*)&(my_sin.raw),my_sin_len) < 0 ){
    err = -errno;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_OPEN_BIND_ERR,"dxE",id,my_addr,err);
    goto error;
  }

  if( listen(sk,RHP_HTTP_SERVER_LISTEN_Q_NUM) < 0 ){
    err = -errno;
    RHP_BUG("%d",err);
    goto error;
  }

  if( (flag = fcntl(sk,F_GETFL)) < 0 ){
    err = -errno;
    RHP_BUG("%d",err);
    goto error;
  }

  if( fcntl(sk,F_SETFL,flag|O_NONBLOCK) < 0 ){
    err = -errno;
    RHP_BUG("%d",err);
    goto error;
  }

  RHP_LOCK(&(_rhp_http_lock));
  
  listen_sk->sk_epoll_ctx.event_type = RHP_MAIN_EPOLL_HTTP_LISTEN;
  RHP_HTTP_SVR_EPOLL_LISTEN_SK(&(listen_sk->sk_epoll_ctx)) = (unsigned long)listen_sk; // (**2)
  
  memset(&ep_evt,0,sizeof(struct epoll_event));
//ep_evt.events = EPOLLIN | EPOLLERR;
  ep_evt.events = EPOLLIN;
  ep_evt.data.ptr = (void*)&(listen_sk->sk_epoll_ctx); 
  
  if( epoll_ctl(rhp_main_admin_epoll_fd,EPOLL_CTL_ADD,sk,&ep_evt) < 0 ){ 
    RHP_UNLOCK(&(_rhp_http_lock));
    err = -errno;
    RHP_BUG("%d",err);
    goto error;
  }

  rhp_http_svr_hold(listen_sk); // (**2)

  listen_sk->sk = sk;
  
  listen_sk->next = _rhp_http_servers; // (**)
  _rhp_http_servers = listen_sk;

  rhp_http_svr_hold(listen_sk); // (**)

  _rhp_atomic_set(&(listen_sk->is_active),1);

  if( listen_sk_r ){
    rhp_http_svr_hold(listen_sk); // (**3)
    *listen_sk_r = listen_sk; // (**3)	  
  }
  
  RHP_UNLOCK(&(_rhp_http_lock));

	RHP_LOG_D(RHP_LOG_SRC_UI,0,RHP_LOG_ID_HTTP_SERVER_OPEN,"AW",my_addr,my_addr->port);

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_OPEN_RTRN,"dxd",id,listen_sk,sk);
  return 0;
 
error:
  if( sk > 0 ){
    close(sk);
  }
  if( listen_sk ){
    _rhp_http_free_server(listen_sk);	  
  }

	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_HTTP_SERVER_OPEN_ERR,"AWE",my_addr,my_addr->port,err);
  
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_OPEN_ERR,"dE",id,err);
  return err;
}

void rhp_http_server_close(rhp_http_listen* listen_sk)
{
  struct epoll_event ep_evt; // See man 2 epoll_ctl ---BUG REPORT---
  rhp_http_listen *sk1 = NULL,*sk2 = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CLOSE,"xd",listen_sk,listen_sk->sk);
  
  RHP_LOCK(&(listen_sk->lock));
  
  if( !_rhp_atomic_read(&(listen_sk->is_active)) ){
    RHP_BUG("");
    RHP_UNLOCK(&(listen_sk->lock));
    return;
  }
  
  memset(&ep_evt,0,sizeof(struct epoll_event));

  if( epoll_ctl(rhp_main_admin_epoll_fd,EPOLL_CTL_DEL,listen_sk->sk,&ep_evt) < 0 ){
    RHP_BUG("");
  }

  close(listen_sk->sk);

  RHP_HTTP_SVR_EPOLL_LISTEN_SK(&(listen_sk->sk_epoll_ctx)) =  (unsigned long)NULL;

  listen_sk->sk = -1;

  _rhp_atomic_set(&(listen_sk->is_active),0);
  
  RHP_UNLOCK(&(listen_sk->lock));

  RHP_LOCK(&(_rhp_http_lock));

  sk1 = _rhp_http_servers;
  while( sk1 ){
	  
  	if( sk1 == listen_sk ){
  		break;
  	}
	
  	sk2 = sk1;
    sk1 = sk1->next;	  
  }
  
  if( sk1 == NULL ){
    RHP_BUG("");	  
  }else{
	  
  	if( sk2 ){
  		sk2->next = listen_sk->next;	
    }
    
    listen_sk->next = NULL;
    rhp_http_svr_unhold(listen_sk); // _rhp_http_servers
  }
  
  RHP_UNLOCK(&(_rhp_http_lock));
  
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CLOSE_RTRN,"x",listen_sk);
  return;
}

static int _rhp_http_check_acls_ipv4(rhp_http_listen* listen_sk,
		struct sockaddr_in* dst_addr,unsigned long* acl_realm_id_r)
{
  rhp_cfg_peer_acl* acl = listen_sk->acl_addrs;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_CHECK_ACLS_IPV4,"xxx4",listen_sk,acl,dst_addr,dst_addr->sin_addr.s_addr);

  if( dst_addr->sin_addr.s_addr == htonl(0x7F000001)  ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_CHECK_ACLS_IPV4_FROM_LOOPBACK_ADDR,"x4",listen_sk,dst_addr->sin_addr.s_addr);
  	goto found;
  }
  
  if( acl == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_CHECK_ACLS_IPV4_NO_ACL_CONFIG,"x",listen_sk);
    goto found;
  }

  while( acl ){

  	if( acl->addr.addr_family == AF_INET &&
  			( acl->addr.netmask.v4 == 0 ||
         (dst_addr->sin_addr.s_addr & acl->addr.netmask.v4) == acl->addr.addr.v4) ){

  		*acl_realm_id_r = acl->vpn_realm_id;
  		goto found;
  	}

  	acl = acl->next;
  }

	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_ADMIN_REJECTED,"4",dst_addr->sin_addr.s_addr);

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_CHECK_ACLS_IPV4_NOT_MATCHED,"x",listen_sk);
  return -ENOENT;

found:
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_CHECK_ACLS_IPV4_MATCHED,"x",listen_sk);
  return 0;
}

static int _rhp_http_check_acls_ipv6(rhp_http_listen* listen_sk,
		struct sockaddr_in6* dst_addr,unsigned long* acl_realm_id_r)
{
  rhp_cfg_peer_acl* acl = listen_sk->acl_addrs;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_CHECK_ACLS_IPV6,"xxx6",listen_sk,acl,dst_addr,dst_addr->sin6_addr.s6_addr);

  if( rhp_ipv6_is_loopback((u8*)(dst_addr->sin6_addr.s6_addr)) ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_CHECK_ACLS_IPV6_FROM_LOOPBACK_ADDR,"x6",listen_sk,dst_addr->sin6_addr.s6_addr);
  	goto found;
  }

  if( acl == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_CHECK_ACLS_IPV6_NO_ACL_CONFIG,"x",listen_sk);
    goto found;
  }

  while( acl ){

  	if( acl->addr.addr_family == AF_INET6 &&
  			( acl->addr.prefixlen == 0 ||
          rhp_ip_same_subnet_v6(dst_addr->sin6_addr.s6_addr,
          		acl->addr.addr.v6,acl->addr.prefixlen)) ){

  		*acl_realm_id_r = acl->vpn_realm_id;
  		goto found;
  	}

  	acl = acl->next;
  }

	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_ADMIN_REJECTED,"6",dst_addr->sin6_addr.s6_addr);

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_CHECK_ACLS_IPV6_NOT_MATCHED,"x",listen_sk);
  return -ENOENT;

found:
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_CHECK_ACLS_IPV6_MATCHED,"x",listen_sk);
  return 0;
}


static void _rhp_http_free_conn(rhp_http_conn* http_conn)
{
  rhp_http_conn *http_conn_tmp = NULL,*http_conn_tmp2 = NULL;	

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_FREE_CONN,"x",http_conn);
  
  if( http_conn->listen_sk ){
    _rhp_atomic_dec(&(http_conn->listen_sk->cur_conns));
    rhp_http_svr_unhold(http_conn->listen_sk);
  }

  RHP_LOCK(&_rhp_http_lock);

  http_conn_tmp = _rhp_http_conns_head;
  while( http_conn_tmp ){
	  
  	if( http_conn_tmp == http_conn ){
  		break;		
  	}
	
  	http_conn_tmp2 = http_conn_tmp;
		http_conn_tmp = http_conn_tmp->next;
  }
  
  if( http_conn_tmp == NULL ){
    RHP_BUG("");	  
  }else{
	  
  	if( http_conn_tmp2 ){
   	  http_conn_tmp2->next = http_conn->next;	
    }
    
  	if( _rhp_http_conns_head == http_conn ){
   	  _rhp_http_conns_head = http_conn->next;
    }
    
  	if( _rhp_http_conns_tail == http_conn ){
   	  _rhp_http_conns_tail = http_conn_tmp2;
    }
  }
  
  RHP_UNLOCK(&_rhp_http_lock);
  
  if( http_conn->http_req ){
    rhp_http_req_free(http_conn->http_req);
  }
  
  if( http_conn->root_dir ){
    _rhp_free_zero(http_conn->root_dir,strlen(http_conn->root_dir)+1);	  
  }
  
  if( http_conn->user_name ){
    _rhp_free_zero(http_conn->user_name,strlen(http_conn->user_name)+1);	  
  }
  
  _rhp_mutex_destroy(&(http_conn->lock));
  _rhp_atomic_destroy(&(http_conn->is_active));
  _rhp_atomic_destroy(&(http_conn->refcnt));
  
  _rhp_free(http_conn);  
  
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_FREE_CONN_RTRN,"x",http_conn);
}

void rhp_http_conn_hold(rhp_http_conn* http_conn)
{
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_CONN_HOLD,"xd",http_conn,http_conn->refcnt.c);
  _rhp_atomic_inc(&(http_conn->refcnt));
}

void rhp_http_conn_unhold(rhp_http_conn* http_conn)
{
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_CONN_UNHOLD,"xd",http_conn,http_conn->refcnt.c);
  if( _rhp_atomic_dec_and_test(&(http_conn->refcnt)) ){
    _rhp_http_free_conn(http_conn);
  }
}

static void _rhp_http_close_sk(rhp_http_conn* http_conn,int abort_conn)
{

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_CLOSE_SK,"xdd",http_conn,abort_conn,http_conn->sk);
	
  if( http_conn->sk < 0 ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_CLOSE_SK_ALREADY_CLOSED,"x",http_conn);
    return;	  
  }
	
  if( abort_conn ){
    struct linger linger_opt = {1,0};
    setsockopt(http_conn->sk,SOL_SOCKET,SO_LINGER,(char*)&linger_opt,sizeof(struct linger));
  }else{
    shutdown(http_conn->sk,SHUT_RDWR);
  }

  _rhp_http_svr_close_sk(&(http_conn->sk));
  
  _rhp_atomic_set(&(http_conn->is_active),0);
  
  if( http_conn->timer_ctx && http_conn->timer_ctx_free ){
    http_conn->timer_ctx_free(http_conn,http_conn->timer_ctx);	  
  }
  http_conn->timer_ctx = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_CLOSE_SK_RTRN,"x",http_conn);
  return;
}

static void _rhp_http_conn_timer(void *ctx,rhp_timer *timer)
{
  int err = -EINVAL;
  rhp_http_conn* http_conn = (rhp_http_conn*)ctx;	
  int abort_conn = 0;
  int (*callback)(rhp_http_conn* http_conn,void* cb_ctx,rhp_timer *timer) = NULL;
  void* cb_ctx = NULL;
  int call_cb = 0;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_CONN_TIMER,"xx",timer,http_conn);
  
  RHP_LOCK(&(http_conn->lock));
	  
  if( !_rhp_atomic_read(&(http_conn->is_active)) ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_CONN_TIMER_NOT_ACTIVE,"xx",timer,http_conn);
    goto error;
  }

  callback = http_conn->timer_callback;
  ctx = http_conn->timer_ctx;
  http_conn->timer_callback = NULL;
  http_conn->timer_ctx = NULL;

  if( callback == NULL ){
    abort_conn = ( (http_conn->rx_requests < 1) || (http_conn->ipc_txn_id != 0) ) ? 1 : 0;
    _rhp_http_close_sk(http_conn,abort_conn);
  }else{
    call_cb = 1;	  
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_CONN_TIMER_PARMS,"xxxd",timer,http_conn,callback,abort_conn);
  
error:  
  RHP_UNLOCK(&(http_conn->lock));

  if( call_cb && callback ){

    err = callback(http_conn,cb_ctx,timer);

    if( err ){
   	  RHP_LOCK(&(http_conn->lock));
      _rhp_http_close_sk(http_conn,1);
   	  RHP_UNLOCK(&(http_conn->lock));
    }
  }

  rhp_http_conn_unhold(http_conn);
  
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_CONN_TIMER_RTRN,"xx",timer,http_conn);
  
  return;
}


int rhp_http_server_listen_handle_event(struct epoll_event* epoll_evt)
{
  int err = 0;
  rhp_epoll_ctx* epoll_ctx = (rhp_epoll_ctx*)epoll_evt->data.ptr;
  rhp_http_listen* listen_sk = (rhp_http_listen*)RHP_HTTP_SVR_EPOLL_LISTEN_SK(epoll_ctx);
  int sk = -1;
  union {
    struct sockaddr_in 	v4;
    struct sockaddr_in6 v6;
    unsigned char raw;
  } dst_addr;
  socklen_t dst_addr_len;
  rhp_http_conn* http_conn = NULL;
  struct epoll_event ep_evt;
  unsigned long acl_realm_id = 0;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_LISTEN_HANDLE_EVENT,"xx",epoll_evt,listen_sk);
  
  if( listen_sk == NULL ){
    err = -ENOENT;
    RHP_BUG("");
    goto error;
  }

  if( (epoll_evt->events & EPOLLERR) ){
    RHP_BUG("");
    goto error;
  }
  
  RHP_LOCK(&(listen_sk->lock));
  
  if( !_rhp_atomic_read(&(listen_sk->is_active)) ){

    err = -ENOENT;
    RHP_BUG("");

    RHP_UNLOCK(&(listen_sk->lock));
    rhp_http_svr_unhold(listen_sk); // listen_sk->sk_epoll_ctx.params[0]

    goto error;
  }

  switch( listen_sk->my_addr.addr_family ){

    case AF_INET:
   	  dst_addr_len = sizeof(struct sockaddr_in);
      break;

    case AF_INET6:
   	  dst_addr_len = sizeof(struct sockaddr_in6);
      break;

    default:
      RHP_BUG("%d",listen_sk->my_addr.addr_family);
      err = -EAFNOSUPPORT;
      goto error_l;
  }
  
  sk = accept(listen_sk->sk,(struct sockaddr*)&(dst_addr.raw),&dst_addr_len);
  if( sk < 0 ){

  	err = -errno;

  	RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_LISTEN_HANDLE_EVENT_ACCEPT_ERR,"xxE",epoll_evt,listen_sk,err);
  	RHP_BUG("%d",err);

    if( err == -EMFILE || err == -ENFILE ){
    	RHP_BUG("_rhp_http_svr_sk_num : %ld",_rhp_atomic_read(&_rhp_http_svr_sk_num));
    	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_HTTP_SERVER_ACCEPT_ERR_TOO_MANY_SKS,"E",err);
    }

    goto error_l;
  }
  
  _rhp_atomic_inc(&_rhp_http_svr_sk_num);

  if( _rhp_atomic_read(&(listen_sk->cur_conns)) > listen_sk->max_conns ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_LISTEN_HANDLE_EVENT_MAX_CONN,"xxdd",epoll_evt,listen_sk,listen_sk->cur_conns.c,listen_sk->max_conns);
    err = RHP_STATUS_MAX_HTTP_CONNS;	  
    goto error_l;
  }
  
  switch( listen_sk->my_addr.addr_family ){

    case AF_INET:

   	if( _rhp_http_check_acls_ipv4(listen_sk,&(dst_addr.v4),&acl_realm_id) ){

   		RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_LISTEN_HANDLE_EVENT_ACL_ERR,"xx",epoll_evt,listen_sk);
	  
      _rhp_http_svr_close_sk(&sk);

      goto error_l;
    }

   	break;

    case AF_INET6:

    	if( _rhp_http_check_acls_ipv6(listen_sk,&(dst_addr.v6),&acl_realm_id) ){

     		RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_LISTEN_HANDLE_EVENT_ACL_V6_ERR,"xx",epoll_evt,listen_sk);

        _rhp_http_svr_close_sk(&sk);

        goto error_l;
      }

     	break;

    default:
      RHP_BUG("%d",listen_sk->my_addr.addr_family);
      err = -EAFNOSUPPORT;
      goto error_l;
  }
  
  http_conn = (rhp_http_conn*)_rhp_malloc(sizeof(rhp_http_conn));
  if( http_conn == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  memset(http_conn,0,sizeof(rhp_http_conn));
  
  http_conn->tag[0] = '#';
  http_conn->tag[1] = 'H';
  http_conn->tag[2] = 'C';
  http_conn->tag[3] = 'M';

  _rhp_mutex_init("HTL",&(http_conn->lock));
  _rhp_atomic_init(&(http_conn->is_active));
  _rhp_atomic_init(&(http_conn->refcnt));
  
  http_conn->root_dir = (char*)_rhp_malloc(strlen(listen_sk->root_dir)+1);
  if( http_conn->root_dir == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  http_conn->root_dir[0] = '\0';
  strcpy(http_conn->root_dir,listen_sk->root_dir);

  http_conn->sk = -1;
  
  http_conn->keep_alive_interval = listen_sk->keep_alive_interval;
  
  memcpy(&(http_conn->my_addr),&(listen_sk->my_addr),sizeof(rhp_ip_addr));
  http_conn->acl_realm_id = acl_realm_id;

  switch( listen_sk->my_addr.addr_family ){

    case AF_INET:
			http_conn->dst_addr.addr_family = AF_INET;
			http_conn->dst_addr.port = dst_addr.v4.sin_port;
			http_conn->dst_addr.addr.v4 = dst_addr.v4.sin_addr.s_addr;
			break;

    case AF_INET6:
     	http_conn->dst_addr.addr_family = AF_INET6;
     	http_conn->dst_addr.port = dst_addr.v6.sin6_port;
     	memcpy(http_conn->dst_addr.addr.v6,dst_addr.v6.sin6_addr.s6_addr,16);
      break;

    default:
      err = -EAFNOSUPPORT;
      RHP_BUG("%d",listen_sk->my_addr.addr_family);
      goto error;
  }
  
  http_conn->sk_epoll_ctx.event_type = RHP_MAIN_EPOLL_HTTP_SERVER;
  RHP_HTTP_SVR_EPOLL_CONN_SK(&(http_conn->sk_epoll_ctx)) = (unsigned long)http_conn; // (**)
  
  memset(&ep_evt,0,sizeof(struct epoll_event));
//  ep_evt.events = EPOLLIN | EPOLLERR | EPOLLONESHOT;
  ep_evt.events = EPOLLIN | EPOLLONESHOT;
  ep_evt.data.ptr = (void*)&(http_conn->sk_epoll_ctx); 
  
  if( epoll_ctl(rhp_main_admin_epoll_fd,EPOLL_CTL_ADD,sk,&ep_evt) < 0 ){ 
    err = -errno;
    RHP_BUG("%d",err);
    goto error_l;
  }

  rhp_http_conn_hold(http_conn); // (**)
  http_conn->sk = sk;

  http_conn->listen_sk = listen_sk; // (**2)
  rhp_http_svr_hold(listen_sk); // (**2)
  
  _rhp_atomic_set(&(http_conn->is_active),1);
  _rhp_atomic_inc(&(listen_sk->cur_conns));
  
  rhp_timer_init(&(http_conn->conn_timer),_rhp_http_conn_timer,http_conn);
  err = rhp_timer_add(&(http_conn->conn_timer),(time_t)http_conn->keep_alive_interval); // (**3)
  if( err ){
    goto error;	  
  }
  rhp_http_conn_hold(http_conn); // (**3)
  
  RHP_LOCK(&_rhp_http_lock);

  strcpy(http_conn->cookie_auth_nonce_str,_rhp_http_auth_cookie_nonce_str);
  strcpy(http_conn->cookie_auth_nonce_str_old,_rhp_http_auth_cookie_nonce_str_old);

  if( _rhp_http_conns_head ){
    _rhp_http_conns_tail->next = http_conn;
  }else{
    _rhp_http_conns_head = http_conn;	  
  }
  _rhp_http_conns_tail = http_conn;	  
  
  RHP_UNLOCK(&_rhp_http_lock);
  
  RHP_UNLOCK(&(listen_sk->lock));

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_LISTEN_HANDLE_EVENT_RTRN,"xxxx",epoll_evt,listen_sk,http_conn,sk);
  return 0;
  
error_l:
  RHP_UNLOCK(&(listen_sk->lock));
error:

  if( sk > 0 ){
    struct linger linger_opt = {1,0};
    setsockopt(sk,SOL_SOCKET,SO_LINGER,(char*)&linger_opt,sizeof(struct linger));
    _rhp_http_svr_close_sk(&sk);
  }
  
  if( http_conn ){
    _rhp_http_free_conn(http_conn);	  
  }

  if( err == -EMFILE || err == -ENFILE ){
  	rhp_http_server_close(listen_sk); // Umm...
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_LISTEN_HANDLE_EVENT_ERR,"xxE",epoll_evt,listen_sk,err);
  return err;
}

// Caller must aquire http_conn->lock and clear http_conn->timer_ctx.
void rhp_http_server_close_conn(rhp_http_conn* http_conn,int abort_conn)
{
  struct epoll_event ep_evt; // See man 2 epoll_ctl ---BUG REPORT---

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CLOSE_CONN,"xd",http_conn,abort_conn);

  if( http_conn->sk != -1 ){

  	memset(&ep_evt,0,sizeof(struct epoll_event));

  	if( epoll_ctl(rhp_main_admin_epoll_fd,EPOLL_CTL_DEL,http_conn->sk,&ep_evt) < 0 ){
  		RHP_BUG("%s,%d",strerror(errno),errno);
  	}
  }
  
  if( _rhp_atomic_read(&(http_conn->is_active)) ){
	  
    if( http_conn->timer_ctx ){
      RHP_BUG("0x%x , 0x%x",http_conn,http_conn->timer_ctx);    	
    }
    
    _rhp_http_close_sk(http_conn,abort_conn);
  }

  rhp_http_server_conn_timer_stop(http_conn);

  RHP_HTTP_SVR_EPOLL_CONN_SK(&(http_conn->sk_epoll_ctx)) =  (unsigned long)NULL;
  
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CLOSE_CONN_RTRN,"x",http_conn);
}

static int _rhp_http_rx_readline(char** in_buf,long* in_buf_len,char** pend_buf,long* pend_buf_len,
		char** line_r,long* line_len_r)
{
  int err = -EINVAL;
  char* line = NULL;
  char* p = *in_buf;
  char* cr = NULL;
  int found = 0;
  int i;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_RX_READLINE,"xxdxxdxx",in_buf,in_buf_len,*in_buf_len,pend_buf,pend_buf_len,*pend_buf_len,line_r,line_len_r);
  
  for( i = 0; i < *in_buf_len;i++){
    if( *p == '\r' ){
      cr = p;    	
    }else if( *p == '\n' ){
      if( (*pend_buf && (*pend_buf)[(*pend_buf_len)-1] == '\r' && ( p == *in_buf )) || (cr && p == (cr + 1)) ){
   	    found = 1;
        break;	  
      }
    }
    p++;
  }

  if( found ){

		int n = (((u8*)p) - ((u8*)(*in_buf))) + 1;
		int new_buf_len = n + *pend_buf_len;
	  
		line = (char*)_rhp_malloc(new_buf_len + 1);
		if( line == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
		memset(line,0,new_buf_len + 1);

		if( *pend_buf ){
			memcpy(line,*pend_buf,*pend_buf_len);	
		}
		memcpy((line + *pend_buf_len),*in_buf,n);

		*line_r = line;
		*line_len_r = new_buf_len;

		if( *pend_buf ){
			_rhp_free(*pend_buf);
		}
		*pend_buf = NULL;
		*pend_buf_len = 0;
	
		*in_buf_len -= (((u8*)p) - ((u8*)(*in_buf))) + 1;
		*in_buf = (p + 1);

		RHP_TRC_FREQ(0,RHPTRCID_HTTP_RX_READLINE_RTRN,"sdxxdxxd",line,new_buf_len,in_buf,in_buf_len,*in_buf_len,pend_buf,pend_buf_len,*pend_buf_len);
		return 0;
  }

  if( (*in_buf_len + *pend_buf_len) > rhp_gcfg_http_max_header_len ){
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }
  
  line = (char*)_rhp_malloc(*in_buf_len + *pend_buf_len);
  if( line == NULL ){
    err = -ENOMEM;
    goto error;
  }

  if( *pend_buf ){
    memcpy(line,*pend_buf,*pend_buf_len);    
    _rhp_free(*pend_buf);
  }
  
  memcpy((line + *pend_buf_len),*in_buf,*in_buf_len);    

  *pend_buf = line;
  *pend_buf_len += *in_buf_len;
  
  *in_buf_len = 0;
  *in_buf = p;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_RX_READLINE_PEND,"xxdxxd",in_buf,in_buf_len,*in_buf_len,pend_buf,pend_buf_len,*pend_buf_len);
  return RHP_STATUS_HTTP_READLINE_PENDING;
  
error:
  if( line ){
    _rhp_free(line);	  
  }
  
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_RX_READLINE_ERR,"");
  return err;
}

static int _rhp_http_request_parse_reqline(rhp_http_conn* http_conn,rhp_http_request* http_req,char* line,int line_len)
{
  char* p = line;
  int n = line_len;
  char* token[4] = {NULL,NULL,NULL,NULL};
  char* token_ep[4] = {NULL,NULL,NULL,NULL};
  int i = 1;
  int sp = 0;
  int token_len;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQUEST_PARSE_REQLINE,"xxsd",http_conn,http_req,line,line_len);
  
  token[0] = line;
  while( *p != '\0' && i < 4 && n > 0 ){
	  
    if( *p == ' ' ){
      if( sp ){
        return RHP_STATUS_INVALID_MSG;
      }
      token_ep[i-1] = p;
      token[i] = p + 1;
      i++;
      sp = 1;
      
    }else{
      sp = 0;
      if( *p == '\r' ){
        i++;
        break;
      }
    }
    
    p++;
    n--;
  }

  if( sp ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQUEST_PARSE_REQLINE_INVALID_1,"xx",http_conn,http_req);
    return RHP_STATUS_INVALID_MSG;
  }
  
  if( i != 4 ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQUEST_PARSE_REQLINE_INVALID_2,"xx",http_conn,http_req);
    return RHP_STATUS_INVALID_MSG;
  }

  if( n != 2 ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQUEST_PARSE_REQLINE_INVALID_3,"xx",http_conn,http_req);
    return RHP_STATUS_INVALID_MSG;
  }

  if( p[0] != '\r' ||  p[1] != '\n' ||  p[2] != '\0' ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQUEST_PARSE_REQLINE_INVALID_4,"xx",http_conn,http_req);
   return RHP_STATUS_INVALID_MSG;
  }
  token_ep[2] = &(p[0]);

  token_len = ((u8*)token_ep[0]) - ((u8*)token[0]);
  if( token_len < 1 ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQUEST_PARSE_REQLINE_INVALID_5,"xx",http_conn,http_req);
    return RHP_STATUS_INVALID_MSG;
  }

  http_req->method = (char*)_rhp_malloc(token_len+1);
  if( http_req->method == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }
  memset(http_req->method,0,token_len+1);
  memcpy(http_req->method,token[0],token_len);


  token_len = ((u8*)token_ep[1]) - ((u8*)token[1]);
  if( token_len < 1 ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQUEST_PARSE_REQLINE_INVALID_6,"xx",http_conn,http_req);
    return RHP_STATUS_INVALID_MSG;
  }

  if( token_len > rhp_gcfg_http_max_uri ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQUEST_PARSE_REQLINE_INVALID_7,"xx",http_conn,http_req);
    return RHP_STATUS_HTTP_URI_TOO_LONG;
  }
  
  http_req->uri = (char*)_rhp_malloc(token_len+1);
  if( http_req->uri == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }
  memset(http_req->uri,0,token_len+1);
  memcpy(http_req->uri,token[1],token_len);


  token_len = ((u8*)token_ep[2]) - ((u8*)token[2]);
  if( token_len < 1 ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQUEST_PARSE_REQLINE_INVALID_8,"xx",http_conn,http_req);
    return RHP_STATUS_INVALID_MSG;
  }

  http_req->version = (char*)_rhp_malloc(token_len+1);
  if( http_req->version == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }
  memset(http_req->version,0,token_len+1);
  memcpy(http_req->version,token[2],token_len);

  if( strcasecmp(http_req->version,"HTTP/1.0") && strcasecmp(http_req->version,"HTTP/1.1") ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQUEST_PARSE_REQLINE_INVALID_9,"xxs",http_conn,http_req,http_req->version);
    return RHP_STATUS_HTTP_NOT_SUP_VER;	  
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQUEST_PARSE_REQLINE_RTRN,"xx",http_conn,http_req);
  return 0;
}

static int _rhp_http_request_parse_header(rhp_http_conn* http_conn,rhp_http_request* http_req,char* line,int line_len)
{
  int err = -EINVAL;
  rhp_http_header* header = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQUEST_PARSE_HEADER,"xxsd",http_conn,http_req,line,line_len);
  
  err = http_req->put_header(http_req,line,line_len,&header);
  if( err ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQUEST_PARSE_HEADER_PUT_HEADER_FAILED,"xxE",http_conn,http_req,err);
    return err;	  
  }

  if( !strcasecmp(header->name,"Content-Length") ){

	  long cont_len;
	  char* endp = NULL;
	  
	  if( header->value == NULL || *header->value == '\0' ){
		  RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQUEST_PARSE_HEADER_INVALID_CONT_LEN_1,"xx",http_conn,http_req);
		  return RHP_STATUS_INVALID_MSG;		  
	  }
	  
	  cont_len = strtol(header->value,&endp,10);
      
	  if( *endp != '\0' ){
	    RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQUEST_PARSE_HEADER_INVALID_CONT_LEN_2,"xx",http_conn,http_req);
	    return RHP_STATUS_INVALID_MSG;		  
	  }
      
	  if( cont_len < 0 || cont_len == LONG_MAX ){
	    RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQUEST_PARSE_HEADER_INVALID_CONT_LEN_3,"xx",http_conn,http_req);
	    return RHP_STATUS_INVALID_MSG;		  
	  }
      
	  http_req->content_length = cont_len;


  }else if( !strcasecmp(header->name,"Cookie") ){

  	int val_len = strlen(header->value) + 1;
  	char* p = header->value;
  	char* end_p = p + val_len;
  	char* cookie_name = NULL;
  	char* cookie_value = NULL;
  	char* rhp_cookies[5]
  	= {"rhp-auth-name","rhp-auth-nonce","rhp-auth-ticket","rhp-auth-name-init","rhp-auth-ticket-init"};
  	int auth_name_type = 0;
  	int auth_ticket_type = 0;

  	while( p < end_p ){

  		if( *p == ' ' || *p == '\t' ){
  			p++;
  			continue;
  		}

  		if( *p == '=' ){

  			if( cookie_value != NULL ){
  				p++;
  				continue;
  			}

  			if( cookie_name == NULL ){
  		    RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQUEST_PARSE_HEADER_INVALID_COOKIE_1,"xx",http_conn,http_req);
  				goto end;
  			}

  			cookie_value = (p + 1);

  		}else if( *p == ';' || *p == '\0' ){

  			if( cookie_name == NULL || cookie_value == NULL ){
  		    RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQUEST_PARSE_HEADER_INVALID_COOKIE_2,"xx",http_conn,http_req);
  				goto end;
  			}

  			if( p == cookie_value ){
  				p++;
    			cookie_name = NULL;
    			cookie_value = NULL;
  				continue;
  			}

  			{
  				int i,replaced = 0;

  				if( *p != '\0' ){
  					*p = '\0';
  					replaced = 1;
  				}
  				*(cookie_value - 1) = '\0';

  				for( i = 0; i < 5; i++ ){

  					if( !strcasecmp(cookie_name,rhp_cookies[i]) ){
  						break;
  					}
  				}

  				switch( i ){

  				case 0: // rhp-auth-name
  				case 3: // rhp-auth-name-init

parse_auth_name_again:
  					if( http_req->cookie.user_name == NULL ){

  						http_req->cookie.user_name = (char*)_rhp_malloc(strlen(cookie_value) + 1);
  						if( http_req->cookie.user_name == NULL ){
  							RHP_BUG("");
  							goto end;
  						}
  						http_req->cookie.user_name[0] = '\0';

  						strcpy(http_req->cookie.user_name,cookie_value);

  						if( i == 0 ){
  							auth_name_type = 1; // rhp-auth-name
  						}else{
  							auth_name_type = 2; // rhp-auth-name-init
  						}

  					}else if( auth_name_type == 1 ){ // rhp-auth-name

  						_rhp_free(http_req->cookie.user_name);
  						http_req->cookie.user_name = NULL;

  						goto parse_auth_name_again;
  					}
  					break;

  				case 1: // rhp-auth-nonce

  					if( http_req->cookie.nonce == NULL ){

  						http_req->cookie.nonce = (char*)_rhp_malloc(strlen(cookie_value) + 1);
  						if( http_req->cookie.nonce == NULL ){
  							RHP_BUG("");
  							goto end;
  						}
  						http_req->cookie.nonce[0] = '\0';

  						strcpy(http_req->cookie.nonce,cookie_value);
  					}
  					break;

  				case 2: // rhp-auth-ticket
  				case 4: // rhp-auth-ticket-init

parse_auth_ticket_again:
  				if( http_req->cookie.ticket == NULL ){

  					u8* decoded_val = NULL;
  					int decoded_val_len = 0;
  					int cookie_value_len = strlen(cookie_value);
  					char* esc_val = (char*)_rhp_malloc( cookie_value_len + 1);
  					char *dc = cookie_value, *dc_end_p = (dc + cookie_value_len), *esc_val_pt = esc_val;

  					if( esc_val == NULL ){
  						RHP_BUG("");
  						goto end;
  					}

  					while( dc < dc_end_p ){

  						// Base64 uses '+', '/' and/or '=' which are NOT allowed in cookies.
  						// These characters are escaped by browser and must be restored here.

  						if( *dc == '%' ){ // '%' is NOT included into a base64-encoded string.

  							if( dc + 2 >= dc_end_p ){
  	  	  		    RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQUEST_PARSE_HEADER_INVALID_COOKIE_3,"xx",http_conn,http_req);
  	  	  		    _rhp_free(esc_val);
  								goto end;
  							}

  							if( *(dc + 1) == '2' ){

  								if( *(dc + 2) == 'B' || *(dc + 2) == 'b' ){ // '+'
  									*esc_val_pt = '+';
  								}else if( *(dc + 2) == 'F' || *(dc + 2) == 'f' ){ // '/'
  									*esc_val_pt = '/';
  								}else{
  									goto esc_nxt;
  								}

  								esc_val_pt++;
									dc += 3;
									continue;

  							}else if( (*(dc + 1) == '3' && ( *(dc + 2) == 'D' || *(dc + 2) == 'd')) ){ // '='
									*esc_val_pt = '=';
									esc_val_pt++;
									dc += 3;
									continue;
  							}
  						}

esc_nxt:
							*esc_val_pt = *dc;
							esc_val_pt++;
  						dc++;
  					}
  					*esc_val_pt = '\0';


  				  err = rhp_base64_decode((unsigned char*)esc_val,&decoded_val,&decoded_val_len);
  				  if( err ){
  	  		    RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQUEST_PARSE_HEADER_INVALID_COOKIE_4,"xx",http_conn,http_req);
  	  		    _rhp_free(esc_val);
							goto end;
  				  }

	  		    RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQUEST_PARSE_HEADER_COOKIE_RHP_AUTH_TICKET,"xxssp",http_conn,http_req,cookie_value,esc_val,decoded_val_len,decoded_val);

  				  if( decoded_val_len != RHP_HTTP_AUTH_TICKET_SIZE ){
  	  		    RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQUEST_PARSE_HEADER_INVALID_COOKIE_5,"xx",http_conn,http_req);
  				  	_rhp_free_zero(decoded_val,decoded_val_len);
  	  		    _rhp_free(esc_val);
							goto end;
  				  }

	  		    _rhp_free(esc_val);

  				  http_req->cookie.ticket = decoded_val;


						if( i == 2 ){
							auth_ticket_type = 1; // rhp-auth-ticket
						}else{
							auth_ticket_type = 2; // rhp-auth-ticket-init
						}

  				}else if( auth_ticket_type == 1 ){ // rhp-auth-ticket

  			  	_rhp_free_zero(http_req->cookie.ticket,RHP_HTTP_AUTH_TICKET_SIZE);
  					http_req->cookie.ticket = NULL;

  					goto parse_auth_ticket_again;
  				}
  					break;

  				default:
  					break;
  				}

  				if( replaced ){
  					*p = ';';
  				}
  				*(cookie_value - 1) = '=';
  			}

  			cookie_name = NULL;
  			cookie_value = NULL;

  		}else{

  			if( cookie_name == NULL ){
  				cookie_name = p;
  			}
  		}

  		p++;
  	}

    RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQUEST_PARSE_HEADER_COOKIE,"xxssp",http_conn,http_req,http_req->cookie.user_name,http_req->cookie.nonce,RHP_HTTP_AUTH_TICKET_SIZE,http_req->cookie.ticket);
  }
  
end:
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_REQUEST_PARSE_HEADER_RTRN,"xx",http_conn,http_req);
  return 0;
}

static int _rhp_http_rx_request_header(rhp_http_conn* http_conn,rhp_http_request* http_req,
		char* rx_buf,long rx_buf_len,char** next_pt)
{
  int err = -EINVAL;
  char* in_buf = rx_buf;
  long in_buf_len = rx_buf_len;
  char* line = NULL;
  long line_len = 0;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_RX_REQUEST_HEADER,"xxpx",http_conn,http_req,rx_buf_len,rx_buf,next_pt);
  
  if( http_conn->http_req->parsing_stat == RHP_HTTP_REQ_PARSE_INIT ){
    http_conn->http_req->parsing_stat = RHP_HTTP_REQ_PARSE_REQLINE;
  }

  http_conn->rx_requests++;
  
  while( in_buf_len > 0 ){

    err = _rhp_http_rx_readline(&in_buf,&in_buf_len,&(http_req->parsing_buf),&(http_req->parsing_buf_len),&line,&line_len);
    if( err == RHP_STATUS_HTTP_READLINE_PENDING ){
    	
   	  RHP_TRC_FREQ(0,RHPTRCID_HTTP_RX_REQUEST_HEADER_READLINE_PEND,"xx",http_conn,http_req);
    	
      err = 0;
      break;    	
      
    }else if( err ){

      RHP_TRC_FREQ(0,RHPTRCID_HTTP_RX_REQUEST_HEADER_READLINE_ERR,"xxE",http_conn,http_req,err);
      goto error;	
    }

    if( line_len > 1 && line[0] == '\r' && line[1] == '\n' ){

   	  if( http_conn->http_req->parsing_stat != RHP_HTTP_REQ_PARSE_HEADER ){
   	  	RHP_TRC_FREQ(0,RHPTRCID_HTTP_RX_REQUEST_HEADER_INVALID_1,"xx",http_conn,http_req);
        err = RHP_STATUS_INVALID_MSG;
        goto error;
      }

   	  http_conn->http_req->parsing_stat = RHP_HTTP_REQ_PARSE_BODY;
      err = 0;

      break;	
    }

    RHP_TRC_FREQ(0,RHPTRCID_HTTP_RX_REQUEST_HEADER_PARSE_STAT,"xxd",http_conn,http_req,http_conn->http_req->parsing_stat);
    
    switch( http_conn->http_req->parsing_stat ){
	
    case RHP_HTTP_REQ_PARSE_REQLINE:
	  
    	err = _rhp_http_request_parse_reqline(http_conn,http_req,line,line_len);

    	if( err == RHP_STATUS_SUCCESS ){
    		http_conn->http_req->parsing_stat = RHP_HTTP_REQ_PARSE_HEADER;
    	}
    	break;
	
    case RHP_HTTP_REQ_PARSE_HEADER:

    	err = _rhp_http_request_parse_header(http_conn,http_req,line,line_len);
    	break;
	
    default:
    	RHP_BUG("%d",http_conn->http_req->parsing_stat);
    	goto error;
    }

    if( err ){
    	RHP_BUG("%d",err);
    	goto error;	
    }
	
    _rhp_free(line);
    line = NULL;
    line_len = 0;
  }

  if( in_buf_len ){
    *next_pt = in_buf;
  }else{
    *next_pt = NULL;
  }

  if( line ){
    _rhp_free(line);
  }
  
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_RX_REQUEST_HEADER_RTRN,"xxx",http_conn,http_req,*next_pt);
  return 0;

error:
  if( line ){
    _rhp_free(line);	  
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_RX_REQUEST_HEADER_ERR,"xxE",http_conn,http_req,err);
  return err;
}

static int _rhp_http_rx_request_body(rhp_http_conn* http_conn,rhp_http_request* http_req,char* rx_buf,int rx_buf_len)
{
  int err = -EINVAL;
  char* new_buf = NULL;
  int new_buf_len;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_RX_REQUEST_BODY,"xxp",http_conn,http_req,rx_buf_len,rx_buf);
  
  if( http_conn->http_req->parsing_stat == RHP_HTTP_REQ_PARSE_COMPLETE ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_RX_REQUEST_BODY_COMPLETED,"xx",http_conn,http_req);
    return 0;
  }

  new_buf_len = http_req->mesg_body_len + rx_buf_len;

  if( new_buf_len > rhp_gcfg_http_max_content_length ){

    err = RHP_STATUS_HTTP_ENT_TOO_LONG;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_RX_REQUEST_BODY_TOO_LONG,"xxdd",http_conn,http_req,new_buf_len,rhp_gcfg_http_max_content_length);

  	RHP_LOG_DE(RHP_LOG_SRC_UI,0,RHP_LOG_ID_RX_HTTP_MESG_TOO_LONG,"sdd",http_req->uri,new_buf_len,rhp_gcfg_http_max_content_length);

    goto error;
  }
  
  if( http_req->content_length >= 0 && new_buf_len > http_req->content_length ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_RX_REQUEST_BODY_INVALID_1,"xx",http_conn,http_req);
    goto error;
  }
  
  new_buf = (char*)_rhp_malloc(new_buf_len);
  if( new_buf == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  memset(new_buf,0,new_buf_len);
  
  if( http_req->mesg_body ){
    memcpy(new_buf,http_req->mesg_body,http_req->mesg_body_len);
    _rhp_free(http_req->mesg_body);
  }
  memcpy(new_buf+http_req->mesg_body_len,rx_buf,rx_buf_len);

  http_req->mesg_body = new_buf;
  http_req->mesg_body_len = new_buf_len;

  if( http_req->content_length >= 0 && new_buf_len == http_req->content_length ){
    http_conn->http_req->parsing_stat = RHP_HTTP_REQ_PARSE_COMPLETE;	  
  }
  
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_RX_REQUEST_BODY_RTRN,"xxp",http_conn,http_req,new_buf_len,new_buf);
  return 0;

error:
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_RX_REQUEST_BODY_ERR,"xxE",http_conn,http_req,err);
  return err;
}

// NOT thread safe! Call this api when process starts only.
int rhp_http_server_register_handler(int (*handler)(rhp_http_conn* http_con,int authorized,void* ctx),void* ctx,
		int nobody_allowed)
{
  rhp_http_server_handler* handler_entry = (rhp_http_server_handler*)_rhp_malloc(sizeof(rhp_http_server_handler));

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ADD_HANDLER,"Yxd",handler,ctx,nobody_allowed);
  
  if( handler_entry == NULL ){
    RHP_BUG("");
    return -ENOMEM;	  
  }
  memset(handler_entry,0,sizeof(rhp_http_server_handler));
	  
  handler_entry->tag[0] = '#';
  handler_entry->tag[1] = 'H';
  handler_entry->tag[2] = 'H';
  handler_entry->tag[3] = 'D';

  handler_entry->handler = handler;
  handler_entry->ctx = ctx;
  handler_entry->nobody_allowed = nobody_allowed;
	  
  if( _rhp_http_server_handlers == NULL ){
  	_rhp_http_server_handlers = handler_entry;	  
  }else{
  	_rhp_http_server_handlers_tail->next = handler_entry;	  
  }
  _rhp_http_server_handlers_tail = handler_entry;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_ADD_HANDLER_RTRN,"xYx",handler_entry,handler,ctx);
  return 0;	
}

static int _rhp_http_call_request_handlers(rhp_http_conn* http_conn,int authorized)
{
  int err = -EINVAL;
  rhp_http_server_handler* handler_entry;	

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_CALL_REQUEST_HANDLERS,"xd",http_conn,authorized);
  
  handler_entry = _rhp_http_server_handlers;
  err = RHP_STATUS_SKIP;

  while( handler_entry ){

  	if( http_conn->http_req == NULL ){
  		RHP_BUG("");
  		err = -EINVAL;
  		goto error;
  	}

    RHP_TRC_FREQ(0,RHPTRCID_HTTP_CALL_REQUEST_HANDLERS_CALL_HANDLER,"xxYx",http_conn,handler_entry,handler_entry->handler,handler_entry->ctx);

    if( !handler_entry->nobody_allowed && http_conn->is_nobody ){
    	goto next;
    }

    err = handler_entry->handler(http_conn,authorized,handler_entry->ctx);

    RHP_TRC_FREQ(0,RHPTRCID_HTTP_CALL_REQUEST_HANDLERS_CALL_HANDLER_RTRN,"xxE",http_conn,handler_entry,err);
	
		if( err == RHP_STATUS_SUCCESS ){
		  break;
		}else if( err == RHP_STATUS_ABORT_HTTP_CONN ){
		  break;	
		}else if( err == RHP_STATUS_HTTP_REQ_PENDING ){
		  break;	
		}else if( err == RHP_STATUS_HTTP_BASIC_UNAUTHORIZED ||
							err == RHP_STATUS_HTTP_UNAUTHORIZED_BASIC_AUTH_PROMPT ||
							err == RHP_STATUS_HTTP_COOKIE_UNAUTHORIZED ){

			if( authorized ){
        RHP_BUG("");
        err = -EINVAL;
        goto error;
			}
		
			err = rhp_http_tx_server_unauth_error_response(http_conn,err);
			if( err ){
				RHP_TRC_FREQ(0,RHPTRCID_HTTP_CALL_REQUEST_HANDLERS_TX_SERVER_UNAUTH_RESP_ERR,"xE",http_conn,err);
				goto error;	  
			}

			err = RHP_STATUS_CLOSE_HTTP_CONN;

			RHP_TRC_FREQ(0,RHPTRCID_HTTP_CALL_REQUEST_HANDLERS_UNAUTHORIXED,"x",http_conn);
			goto error;

		}if( err && err != RHP_STATUS_SKIP ){
      RHP_TRC_FREQ(0,RHPTRCID_HTTP_CALL_REQUEST_HANDLERS_HANDLER_ERR,"xE",http_conn,err);
      goto error;
    }

next:
    handler_entry = handler_entry->next;
  }

  if( err == RHP_STATUS_SKIP ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_CALL_REQUEST_HANDLERS_SKIP_ERR,"x",http_conn);
    err = -ENOENT;
  }
  
error:
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_CALL_REQUEST_HANDLERS_RTRN,"xE",http_conn,err);
  return err;	
}

static char* _rhp_http_gen_date_header_str()
{
  time_t n;
  char* val = NULL;
  int val_len = 256;
  int c;
  
  val = (char*)_rhp_malloc(val_len);
  if( val == NULL ){
    RHP_BUG("");
    return NULL;
  }
  memset(val,0,val_len);
  
  n = _rhp_get_realtime();
  c = sprintf(val,"Data: ");
  c += strftime((val + c),(val_len - c),"%a, %d %b %Y %H:%M:%S GMT",gmtime(&n));
  sprintf((val + c),"\r\n");

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_GEN_DATE_HADER_STR,"s",val);
  return val;	
}

static char* _rhp_http_gen_content_length_header_str(long mesg_body_len)
{
	int val_len = 256;
  char* val = NULL;
  
  if( mesg_body_len < 1 || mesg_body_len >= LONG_MAX ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_GEN_CONTENT_LENGTH_HEADER_STR_ERR,"d",mesg_body_len);
    return NULL;	  
  }
  
  val = (char*)_rhp_malloc(val_len);
  if( val == NULL ){
    RHP_BUG("");
    return NULL;
  }
  memset(val,0,val_len);
  
  sprintf(val,"Content-Length: %ld\r\n",mesg_body_len);
  
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_GEN_CONTENT_LENGTH_HEADER_STR,"ds",mesg_body_len,val);
  return val;	
}

static int _rhp_http_send(rhp_http_conn* http_conn,u8* tx_buf,int tx_buf_len)
{
  int err = -EINVAL;
  int n = 0;
  int c = 0;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SEND,"xp",http_conn,(tx_buf_len > 1024 ? 1024 : tx_buf_len),tx_buf);
  
  while( n < tx_buf_len ){
		
    c = send(http_conn->sk,(tx_buf + n),(tx_buf_len - n),0);  

    if( c < 0 ){
      err = -errno;
      if( err == -EINTR ){
        continue;    	  
      }
      
      RHP_TRC_FREQ(0,RHPTRCID_HTTP_SEND_ERR,"xE",http_conn,err);
      return err;
    }
    n += c;
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SEND_RTRN,"x",http_conn);
  return 0;	
}

// http_conn->lock must be acquired.
int rhp_http_tx_server_response(rhp_http_conn* http_conn,rhp_http_response* http_res,int tx_auth_cookie)
{
  int err = 0;
  int tx_header_buf_len;
  char* tx_header_buf = NULL;
  char* cont_len_header = NULL;
  char* date_header = NULL;
  int c = 0;
  rhp_http_header* header = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_TX_SERVER_RESPONSE,"xx",http_conn,http_res);
  
  if( tx_auth_cookie ){

  	err = http_res->set_auth_cookie(http_res,http_conn->cookie_auth_nonce_str,rhp_gcfg_http_auth_cookie_max_age);
		if( err ){
			RHP_TRC_FREQ(0,RHPTRCID_HTTP_TX_SERVER_RESPONSE_PUT_HEADER_SET_COOKIE_ERR,"x",http_conn);
			goto error;
		}
  }

  tx_header_buf_len = strlen(RHP_HTTP_VERSION) + strlen(http_res->status_code) + strlen(http_res->reason_phrase) + 6/* SP*2 + CRLF + CRLF */;
  tx_header_buf_len += strlen("Server: "RHP_HTTP_SERVER_NAME" "RHP_VERSION_STR"\r\n");
  
  if( http_res->mesg_body ){

  	if( http_res->mesg_body_len < 1 ){
      err = -EINVAL;
      RHP_BUG("");
      goto error;
  	}
	  
    cont_len_header = _rhp_http_gen_content_length_header_str(http_res->mesg_body_len);
    if( cont_len_header == NULL ){
      err = -ENOMEM;
      RHP_BUG("");
      goto error;    	
    }
    
    tx_header_buf_len += strlen(cont_len_header);
  }
  

  date_header = _rhp_http_gen_date_header_str();
  if( date_header == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  tx_header_buf_len += strlen(date_header);	  

  header = http_res->headers_head;
  while( header ){
    tx_header_buf_len += strlen(header->name);
    if( header->value ){
      tx_header_buf_len += strlen(header->value);
    }
    tx_header_buf_len += 4; /*: + SP + CRLF*/
    header = header->next;
  }

  
  tx_header_buf = (char*)_rhp_malloc(tx_header_buf_len + 32);
  if( tx_header_buf == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  memset(tx_header_buf,0,tx_header_buf_len);
  
  c += sprintf(tx_header_buf,"%s %s %s\r\n",RHP_HTTP_VERSION,http_res->status_code,http_res->reason_phrase);
  c += sprintf(tx_header_buf+c,"%s",date_header);
  c += sprintf(tx_header_buf+c,"Server: %s\r\n",RHP_HTTP_SERVER_NAME" "RHP_VERSION_STR);

  header = http_res->headers_head;
  while( header ){

  	if( header->value ){
  		c += sprintf(tx_header_buf+c,"%s: %s\r\n",header->name,header->value);
  	}else{
      c += sprintf(tx_header_buf+c,"%s: \r\n",header->name);
  	}

  	header = header->next;
  }
  
  if( http_res->mesg_body ){

    c += sprintf(tx_header_buf+c,"%s",cont_len_header);
  }


  c += sprintf(tx_header_buf+c,"%s","\r\n");
  
  err = _rhp_http_send(http_conn,(u8*)tx_header_buf,tx_header_buf_len);
  if( err ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_TX_SERVER_RESPONSE_SEND_HEADER_ERR,"xxE",http_conn,http_res,err);
    goto error;	  
  }

  if( http_res->mesg_body ){

    err = _rhp_http_send(http_conn,(u8*)http_res->mesg_body,http_res->mesg_body_len);
    if( err ){
      RHP_TRC_FREQ(0,RHPTRCID_HTTP_TX_SERVER_RESPONSE_SEND_BODY_ERR,"xxE",http_conn,http_res,err);
      goto error;	  
    }
  }
  
error:
  if( cont_len_header ){
    _rhp_free(cont_len_header);	  
  }
  
  if( date_header ){
    _rhp_free(date_header);	  
  }
  
  if( tx_header_buf ){
    _rhp_free(tx_header_buf);	  
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_TX_SERVER_RESPONSE_RTRN,"xxE",http_conn,http_res,err);
  return err;	
}

// http_conn->lock must be acquired.
int rhp_http_tx_server_unauth_error_response(rhp_http_conn* http_conn, int conn_err)
{
  int err = 0;
  rhp_http_response* http_res = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_TX_SERVER_UNAUTH_ERROR_RESPONSE,"xE",http_conn,conn_err);
  

  if( conn_err == RHP_STATUS_HTTP_UNAUTHORIZED_BASIC_AUTH_PROMPT ){

		http_res = rhp_http_res_alloc("401","Authorization Required");
		if( http_res == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}

		err = http_res->put_header(http_res,"WWW-Authenticate","Basic realm=\"Rockhopper\"");
		if( err ){
			RHP_TRC_FREQ(0,RHPTRCID_HTTP_TX_SERVER_UNAUTH_ERROR_RESPONSE_PUT_HEADER_WWW_AUTHENTICATE_ERR,"x",http_conn);
			goto error;
		}

  }else if( conn_err == RHP_STATUS_HTTP_COOKIE_UNAUTHORIZED ){

		http_res = rhp_http_res_alloc("403","Forbidden");
		if( http_res == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}

  }else{

		http_res = rhp_http_res_alloc("403","Forbidden");
		if( http_res == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
  }


  err = http_res->put_header(http_res,"Content-Type","text/html; charset=utf-8");
  if( err ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_TX_SERVER_UNAUTH_ERROR_RESPONSE_PUT_HEADER_ERR_1,"x",http_conn);
    goto error;    	
  }

  http_res->mesg_body_len = strlen(RHP_HTTP_UNAUTHORIZED_ERR_MSG);
  http_res->mesg_body = (char*)_rhp_malloc(http_res->mesg_body_len + 1);
  if( http_res->mesg_body == NULL ){
  	RHP_BUG("");
  	http_res->mesg_body_len = 0;
  	err = -ENOMEM;
  	goto error;
  }
  http_res->mesg_body[0] = '\0';
  strcpy(http_res->mesg_body,RHP_HTTP_UNAUTHORIZED_ERR_MSG);
	  
  err = rhp_http_tx_server_response(http_conn,http_res,1);
  if( err ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_TX_SERVER_UNAUTH_ERROR_RESPONSE_TX_SERVER_RESP_ERR,"xE",http_conn,err);
    err = RHP_STATUS_ABORT_HTTP_CONN;	  
    goto error;   		  
  }

  err = 0;

error:  
  if( http_res ){
    rhp_http_res_free(http_res);	  
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_TX_SERVER_UNAUTH_ERROR_RESPONSE_RTRN,"xE",http_conn,err);
  return err;
}

// http_conn->lock must be acquired.
int rhp_http_tx_server_error_response(rhp_http_conn* http_conn,char* status_code,char* reason_phrase,char* mesg_body,int tx_auth_cookie)
{
  int err = 0;
  int tx_buf_len;
  char* tx_buf = NULL;
  long cont_len = 0;
  char* cont_len_header = NULL;
  char* date_header = NULL;
  int c = 0;
  char* set_auth_cookie_str = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_TX_SERVER_ERROR_RESPONSE,"xsss",http_conn,status_code,reason_phrase,mesg_body);
  
  tx_buf_len = strlen(RHP_HTTP_VERSION) + strlen(status_code) + strlen(reason_phrase) + 6/* SP*2 + CRLF + CRLF */;
  tx_buf_len += strlen("Server: "RHP_HTTP_SERVER_NAME" "RHP_VERSION_STR"\r\n");
  
  {
		set_auth_cookie_str = _rhp_http_res_gen_auth_cookie(http_conn->cookie_auth_nonce_str,rhp_gcfg_http_auth_cookie_max_age);
		if( set_auth_cookie_str == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		tx_buf_len += strlen("Set-Cookie: ") + strlen(set_auth_cookie_str) + strlen("\r\n");
  }

  if( mesg_body ){

    cont_len = strlen(mesg_body);
    cont_len_header = _rhp_http_gen_content_length_header_str(cont_len);
    if( cont_len_header == NULL ){
      err = -ENOMEM;
      goto error;    	
    }
	
    tx_buf_len += strlen("Content-Type: text/html; charset=utf-8\r\n");
    tx_buf_len += strlen(cont_len_header);
    tx_buf_len += cont_len;
  }
  

  date_header = _rhp_http_gen_date_header_str();
  if( date_header == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  tx_buf_len += strlen(date_header);	  
  
  tx_buf = (char*)_rhp_malloc(tx_buf_len+32);
  if( tx_buf == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  memset(tx_buf,0,tx_buf_len);
  
  c += sprintf(tx_buf,"%s %s %s\r\n",RHP_HTTP_VERSION,status_code,reason_phrase);
  c += sprintf(tx_buf+c,"%s",date_header);
  c += sprintf(tx_buf+c,"Server: %s\r\n",RHP_HTTP_SERVER_NAME" "RHP_VERSION_STR);
  c += sprintf(tx_buf+c,"Set-Cookie: %s\r\n",set_auth_cookie_str);

  if( mesg_body ){
    c += sprintf(tx_buf+c,"%s","Content-Type: text/html; charset=utf-8\r\n");
    c += sprintf(tx_buf+c,"%s",cont_len_header);
  }


  c += sprintf(tx_buf+c,"%s","\r\n");
  
  if( mesg_body ){
    c += sprintf(tx_buf+c,"%s",mesg_body);
  }

  err = _rhp_http_send(http_conn,(u8*)tx_buf,tx_buf_len);
  if( err ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_TX_SERVER_ERROR_RESPONSE_SEND_ERR,"xE",http_conn,err);
    goto error;	  
  }
  
  err = 0;
  
error:
  if( cont_len_header ){
    _rhp_free(cont_len_header);	  
  }
  
  if( date_header ){
    _rhp_free(date_header);	  
  }

  if( tx_buf ){
    _rhp_free(tx_buf);	  
  }

  if( set_auth_cookie_str ){
  	_rhp_free(set_auth_cookie_str);
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_TX_SERVER_ERROR_RESPONSE_RTRN,"xE",http_conn,err);
  return err;	
}

// http_conn->lock must be acquired.
// close_flag :  0 : gracefully close connection , 1 : abort connection
int rhp_http_tx_server_def_error_response(rhp_http_conn* http_conn,int err,int* close_flag,int tx_auth_cookie)
{
  int err2 = -EINVAL;	

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_TX_DEF_ERROR_RESPONSE,"xEx",http_conn,err,close_flag);
  
  if( err == RHP_STATUS_INVALID_MSG ){
  	err2 = rhp_http_tx_server_error_response(http_conn,"400","Bad Request",NULL,tx_auth_cookie);
    *close_flag = 0;
  }else if( err == RHP_STATUS_HTTP_NOT_SUP_VER ){
  	err2 = rhp_http_tx_server_error_response(http_conn,"505","HTTP Version not supported",NULL,tx_auth_cookie);
    *close_flag = 0;
  }else if( err == RHP_STATUS_HTTP_URI_TOO_LONG ){
  	err2 = rhp_http_tx_server_error_response(http_conn,"414","Request-URI Too Large",NULL,tx_auth_cookie);
    *close_flag = 0;
  }else if( err == RHP_STATUS_HTTP_ENT_TOO_LONG ){
  	err2 = rhp_http_tx_server_error_response(http_conn,"413","Request Entiry Too Large",NULL,tx_auth_cookie);
    *close_flag = 0;
  }else if( err == RHP_STATUS_HTTP_BASIC_UNAUTHORIZED ||
  					err == RHP_STATUS_HTTP_UNAUTHORIZED_BASIC_AUTH_PROMPT ||
  					err == RHP_STATUS_HTTP_COOKIE_UNAUTHORIZED ){
    *close_flag = 0; // Instead, rhp_http_tx_server_unauth_error_response()
  }else if( err == RHP_STATUS_HTTP_URI_GONE){
  	err2 = rhp_http_tx_server_error_response(http_conn,"410","Gone",RHP_HTTP_NOT_FOUND_ERR_MSG,tx_auth_cookie);
    *close_flag = 0;
  }else if( err == RHP_STATUS_HTTP_NOT_FOUND){
  	err2 = rhp_http_tx_server_error_response(http_conn,"404","Not Found",RHP_HTTP_NOT_FOUND_ERR_MSG,tx_auth_cookie);
    *close_flag = 0;
  }else if( err == -ENOENT || err == RHP_STATUS_NO_IP  ){
    err2 = rhp_http_tx_server_error_response(http_conn,"404","Not Found",RHP_HTTP_NOT_FOUND_ERR_MSG,tx_auth_cookie);
    *close_flag = 0;
  }else if( err == -EPERM ){
    err2 = rhp_http_tx_server_error_response(http_conn,"403","Forbidden",RHP_HTTP_NOT_FOUND_ERR_MSG,tx_auth_cookie);
    *close_flag = 0;
  }else if( err == -EEXIST || err == -EBUSY ){
    err2 = rhp_http_tx_server_error_response(http_conn,"409","Conflict",RHP_HTTP_NOT_FOUND_ERR_MSG,tx_auth_cookie);
    *close_flag = 0;
  }else{
     RHP_BUG("");	  
     err2 = rhp_http_tx_server_error_response(http_conn,"500","Internal Server Error",NULL,tx_auth_cookie);
     *close_flag = 0;
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_TX_DEF_ERROR_RESPONSE_RTRN,"xddd",http_conn,err,*close_flag,err2);
  return err2;	
}

static rhp_http_header* _rhp_http_multipart_form_data_get_header(rhp_http_body_part* http_bpart,char* name)
{
  rhp_http_header* header = http_bpart->headers_head;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_MULTIPART_FORM_DATA_GET_HEADER,"xsx",http_bpart,name,http_bpart->headers_head);

  while( header ){

    if( !strcasecmp(name,header->name) ){
   	  RHP_TRC_FREQ(0,RHPTRCID_HTTP_MULTIPART_FORM_DATA_GET_HEADER_RTRN,"xxs",http_bpart,header,header->value);
      return header;
    }

    header = header->next;
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_MULTIPART_FORM_DATA_GET_HEADER_NO_ENT,"x",http_bpart);
  return NULL;
}

static rhp_http_body_part* _rhp_http_multipart_form_data_get_body_part(rhp_http_body_multipart_form_data* multipart_form_data,char* form_name)
{
	rhp_http_body_part* part = multipart_form_data->part_head;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_MULTIPART_FORM_DATA_GET_BODY_PART,"xsx",multipart_form_data,form_name, multipart_form_data->part_head);

  while( part ){

    if( part->form_name && !strcasecmp(form_name,part->form_name) ){
   	  RHP_TRC_FREQ(0,RHPTRCID_HTTP_MULTIPART_FORM_DATA_GET_BODY_PART_RTRN,"xxp",multipart_form_data,part,(part->data_len > 128 ? 128 : part->data_len),part->data);
      return part;
    }

    part = part->next;
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_MULTIPART_FORM_DATA_GET_BODY_PART_NO_ENT,"x",multipart_form_data);
  return NULL;
}


static int _rhp_http_server_parse_multipart_form_data(rhp_http_request* http_req)
{
	int err = -EINVAL;
  rhp_http_header* req_header = NULL;
  u8 *p,*p2,*end_p;
  int p_len;
  char* boundary_str = NULL;
  int boundary_str_len;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PARSE_MULTIPART_FORM_DATA,"x",http_req);

  if( http_req->mesg_body == NULL ){
    err = -ENOENT;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PARSE_MULTIPART_FORM_DATA_NO_MESGBODY,"x",http_req);
    goto error;
  }

  if( strcmp(http_req->method,"POST") ){
    err = -ENOENT;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PARSE_MULTIPART_FORM_DATA_NOT_POST_METHOD,"x",http_req);
    goto error;
  }

  req_header = http_req->get_header(http_req,"Content-Type");
  if( req_header == NULL || req_header->value == NULL ){
    err = -ENOENT;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PARSE_MULTIPART_FORM_DATA_NO_CONTENT_TYPE,"x",http_req);
    goto error;
  }

  if( (strcasestr(req_header->value,"multipart/form-data") == NULL) ){
    err = -ENOENT;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PARSE_MULTIPART_FORM_DATA_NOT_MULTIPART,"xs",http_req,req_header->value);
    goto error;
  }

  p = (u8*)strcasestr(req_header->value,"boundary=");
  if( p == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PARSE_MULTIPART_FORM_DATA_NO_BOUNDARY_MARKER,"x",http_req);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


  {
		http_req->multipart_form_data
		= (rhp_http_body_multipart_form_data*)_rhp_malloc(sizeof(rhp_http_body_multipart_form_data));

		if( http_req->multipart_form_data == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		memset(http_req->multipart_form_data,0,sizeof(rhp_http_body_multipart_form_data));

		http_req->multipart_form_data->tag[0] = '#';
		http_req->multipart_form_data->tag[1] = 'H';
		http_req->multipart_form_data->tag[2] = 'M';
		http_req->multipart_form_data->tag[3] = 'P';

		http_req->multipart_form_data->get_body_part = _rhp_http_multipart_form_data_get_body_part;
  }

  {
    end_p = (u8*)(req_header->value) + strlen(req_header->value);

    p += strlen("boundary=");
		p2 = p;
		while( p2 < end_p ){

			if( *p2 == ' ' || *p2 == '\t' ){
				break;
			}

			p2++;
		}

		if( p == p2 ){
	    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PARSE_MULTIPART_FORM_DATA_PARSE_BOUNDARY_MARKER_ERR,"x",http_req);
			err = RHP_STATUS_INVALID_MSG;
			goto error;
		}

		boundary_str_len = p2 - p;
		boundary_str = (char*)_rhp_malloc(boundary_str_len + 16);
		if( boundary_str == NULL ){
			err = -ENOMEM;
			goto error;
		}

		boundary_str[0] = '-';
		boundary_str[1] = '-';
		memcpy(&(boundary_str[2]),p,(boundary_str_len));
		boundary_str[boundary_str_len + 2] = '\r';
		boundary_str[boundary_str_len + 3] = '\n';
		boundary_str[boundary_str_len + 4] = '\0';

		boundary_str_len += 4;
  }

  {
		u8* part_p = NULL;
		rhp_http_body_part* part = NULL;
		int end_ok = 0;

		p = (u8*)(http_req->mesg_body);
		p_len = http_req->mesg_body_len;
		end_p = p + p_len;

		while( p < end_p ){

			part_p = rhp_bin_pattern(p,(end_p - p),(u8*)boundary_str,boundary_str_len);
			if( part_p == NULL ){

				boundary_str[boundary_str_len  - 2] = '-';
				boundary_str[boundary_str_len  - 1] = '-';
				boundary_str[boundary_str_len] = '\r';
				boundary_str[boundary_str_len + 1] = '\n';
				boundary_str[boundary_str_len + 2] = '\0';

				boundary_str_len += 2;

				part_p = rhp_bin_pattern(p,(end_p - p),(u8*)boundary_str,boundary_str_len);
				if( part_p == NULL ){
			    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PARSE_MULTIPART_FORM_DATA_PARSE_NOT_TERMINATED_1,"x",http_req);
					err = RHP_STATUS_INVALID_MSG;
					goto error;
				}

				if( http_req->multipart_form_data->part_tail ){
					rhp_http_body_part* part_tail = http_req->multipart_form_data->part_tail;
					part_tail->part_len = part_p - (u8*)part_tail->part_head;
				}

				end_ok = 1;
				break;
			}

			part = (rhp_http_body_part*)_rhp_malloc(sizeof(rhp_http_body_part));
			if( part == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}
			memset(part,0,sizeof(rhp_http_body_part));

			part->tag[0] = '#';
			part->tag[1] = 'H';
			part->tag[2] = 'B';
			part->tag[3] = 'P';

			part->get_header = _rhp_http_multipart_form_data_get_header;

			part->part_head = (char*)part_p + boundary_str_len;

			if( http_req->multipart_form_data->part_tail ){
				rhp_http_body_part* part_pre = http_req->multipart_form_data->part_tail;
				part_pre->part_len = (u8*)part_p - ((u8*)part_pre->part_head);
			}

			if( http_req->multipart_form_data->part_head == NULL ){
				http_req->multipart_form_data->part_head = part;
			}else{
				http_req->multipart_form_data->part_tail->next = part;
			}
			http_req->multipart_form_data->part_tail = part;

			http_req->multipart_form_data->part_num++;

			p = part_p + boundary_str_len;
		}

		if( !end_ok ){
	    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PARSE_MULTIPART_FORM_DATA_PARSE_NOT_TERMINATED_2,"x",http_req);
			err = RHP_STATUS_INVALID_MSG;
			goto error;
		}


		part = http_req->multipart_form_data->part_head;
		while( part ){

			if( part->part_len ){

				part->data = rhp_bin_pattern((u8*)(part->part_head),part->part_len,(u8*)"\r\n\r\n",4);
				if( part->data ){

					part->data += 4;
					part->data_len = ((u8*)(part->part_head) + part->part_len) - part->data - 2; // 2: end of data marker '\r\n'.
				}

			}else{
				RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PARSE_MULTIPART_FORM_DATA_PARSE_PART_HEADER_ERR,"x",http_req);
				err = RHP_STATUS_INVALID_MSG;
				goto error;
			}

			{
				p = (u8*)(part->part_head);
				p_len = (part->data - p) - 2;

				while( p < (part->data - 2) ){

					rhp_http_header* header = NULL;
					int dh_len;

					p2 = rhp_bin_pattern(p,p_len,(u8*)"\r\n",2);
					if( p2 == NULL ){
						RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PARSE_MULTIPART_FORM_DATA_PARSE_PART_DATA_ERR,"x",http_req);
						err = RHP_STATUS_INVALID_MSG;
						goto error;
					}else if( p == p2 ){
						break;
					}
					dh_len = p2 - p;

					err = _rhp_http_req_parse_header((char*)p,p_len,&header);
					if( err ){
						RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PARSE_MULTIPART_FORM_DATA_PARSE_PART_HEADER_ERR2,"x",http_req);
						goto error;
					}

					if( part->headers_head == NULL ){
						part->headers_head = header;
					}else{
						part->headers_tail->next = header;
					}
					part->headers_tail = header;

					p_len -= dh_len;
					p += dh_len + 2;
				}
			}

			{
				int i, n_len;
				char* form_values[2] = {"name=","filename="};
				rhp_http_header* disp_header = part->get_header(part,"Content-Disposition");

				if( disp_header == NULL ){
					err = RHP_STATUS_INVALID_MSG;
					RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PARSE_MULTIPART_FORM_DATA_NO_CONTENT_DISPOSITION,"x",http_req);
					goto error;
				}

				for( i = 0; i < 2; i++ ){

					char* value;
					int v_len;
					int fmn_len;

					n_len = 0;
					v_len = strlen(disp_header->value);
					fmn_len = strlen(form_values[i]);

					p = rhp_bin_pattern((u8*)(disp_header->value),v_len,(u8*)form_values[i],fmn_len);
					if( p == NULL ){
						continue;
					}

					p2 = p;
					v_len -= (p - (u8*)(disp_header->value));
					while( v_len ){

						if( *p2 == ';' || *p2 == '\r' ){
							break;
						}

						p2++;
						v_len--;
						n_len++;
					}

					if( n_len < 2 ){ // "value" : 2*'"'
						err = RHP_STATUS_INVALID_MSG;
						RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PARSE_MULTIPART_FORM_DATA_PARSE_CONTENT_DISPOSITION_ATTR_ERR,"xs",http_req,form_values[i]);
						goto error;
					}
					n_len -= (fmn_len + 2);

					value = (char*)_rhp_malloc(n_len + 1);
					if( value == NULL ){
						RHP_BUG("");
						err = -ENOMEM;
						goto error;
					}
					memcpy(value,(p + fmn_len + 1),n_len);
					value[n_len] = '\0';

					if( i == 0 ){
						part->form_name = value;
					}else if( i == 1 ){
						part->form_filename = value;
					}
				}
			}

			part = part->next;
		}
  }

	_rhp_free(boundary_str);

	RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PARSE_MULTIPART_FORM_DATA_RTRN,"x",http_req);
  return 0;

error:
	if( boundary_str ){
		_rhp_free(boundary_str);
	}
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_PARSE_MULTIPART_FORM_DATA_ERR,"xE",http_req,err);
	return err;
}


extern void rhp_ui_http_lower_err_handle(rhp_http_conn* http_conn,rhp_http_request* http_req);

#define RHP_HTTP_RX_BUF_LEN	4096

int rhp_http_server_conn_handle_event(struct epoll_event* epoll_evt)
{
  int err = 0;
  struct msghdr msg;
  struct iovec iov[1];
  rhp_epoll_ctx* epoll_ctx = (rhp_epoll_ctx*)epoll_evt->data.ptr;
  rhp_http_conn* http_conn = (rhp_http_conn*)RHP_HTTP_SVR_EPOLL_CONN_SK(epoll_ctx);
  int rx_len = 0;
  char* rx_buf = NULL;
  char* rx_buf_tmp = NULL;
  int rx_buf_tmp_len = 0;
  int rx_buf_tmp_len_rem = 0;
  char* next_pt = NULL;
  int close_flag = -1; // -1 : NOT close connection , 0 : gracefully close connection , 1 : abort connection
  char cookie_auth_nonce_str[RHP_HTTP_AUTH_COOKIE_NONCE_STR_SIZE];
  char cookie_auth_nonce_str_old[RHP_HTTP_AUTH_COOKIE_NONCE_STR_SIZE];

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT,"xx",epoll_evt,http_conn);

  RHP_LOCK(&_rhp_http_lock);
  {
  	_rhp_http_update_auth_cookie();

  	cookie_auth_nonce_str[0] = '\0';
  	cookie_auth_nonce_str_old[0] = '\0';
  	strcpy(cookie_auth_nonce_str,_rhp_http_auth_cookie_nonce_str);
  	strcpy(cookie_auth_nonce_str_old,_rhp_http_auth_cookie_nonce_str_old);
  }
  RHP_UNLOCK(&_rhp_http_lock);


  RHP_LOCK(&(http_conn->lock));

  http_conn->cookie_auth_nonce_str[0] = '\0';
  http_conn->cookie_auth_nonce_str_old[0] = '\0';
  strcpy(http_conn->cookie_auth_nonce_str,cookie_auth_nonce_str);
  strcpy(http_conn->cookie_auth_nonce_str_old,cookie_auth_nonce_str_old);

  if( (epoll_evt->events & EPOLLERR) ||
  		!_rhp_atomic_read(&(http_conn->is_active)) || !_rhp_atomic_read(&(http_conn->listen_sk->is_active)) ){

    rhp_http_server_close_conn(http_conn,0);

    RHP_UNLOCK(&(http_conn->lock));
    rhp_http_conn_unhold(http_conn); // http_conn->sk_epoll_ctx.params[0]

    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_NOT_ACTIVE,"xx",epoll_evt,http_conn);
    return -EINVAL;
  }


  if( http_conn->ipc_txn_id != 0 ){
  	err = -EBUSY;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_IPC_PENDING,"xxYx",epoll_evt,http_conn,http_conn->ipc_callback,http_conn->ipc_cb_ctx);
  	goto error;
  }


  while( 1 ){

  	if( rx_buf == NULL || rx_buf_tmp_len_rem < 1 ){

  		char* new_buf;

  		new_buf = (char*)_rhp_malloc(rx_len + RHP_HTTP_RX_BUF_LEN);
  		if( new_buf == NULL ){

  			RHP_BUG("");

      	if( rx_buf ){
          _rhp_free(rx_buf);
      	}

      	err = -ENOMEM;
      	goto error;
			}

  		if( rx_buf ){
  			memcpy(new_buf,rx_buf,rx_len);
        _rhp_free(rx_buf);
  		}

  		rx_buf = new_buf;
  		rx_buf_tmp_len_rem = RHP_HTTP_RX_BUF_LEN;
		}

  	iov[0].iov_base = rx_buf + rx_len;
  	iov[0].iov_len = rx_buf_tmp_len_rem;
  	msg.msg_name = NULL;
  	msg.msg_namelen = 0;
  	msg.msg_iov = iov;
  	msg.msg_iovlen = 1;
  	msg.msg_flags = 0;
  	msg.msg_control = NULL;
  	msg.msg_controllen = 0;

  	err = recvmsg(http_conn->sk,&msg,MSG_DONTWAIT);
  	if( err < 0 ){

  		err = -errno;
  		RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_RECVMSG_ERR,"xxdE",epoll_evt,http_conn,http_conn->sk,err);

  		if( err == -EINTR ){
  			continue;
  		}else if( err == -EAGAIN ){
  			err = 0;
  			RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_RECVMSG_EAGAIN,"xxd",epoll_evt,http_conn,http_conn->sk);
  			break;
  		}else{
  			goto error;
  		}

  	}else if( err == 0 ){
  		RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_RECVMSG_RTRN,"xxddd",epoll_evt,http_conn,http_conn->sk,rx_len,rx_buf_tmp_len_rem);
  		break;
  	}

  	rx_len += err;
  	rx_buf_tmp_len_rem -= err;
  }

  rx_buf_tmp = rx_buf;
  rx_buf_tmp_len = rx_len;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_RECVMSG_COMPLETE,"xxdp",epoll_evt,http_conn,http_conn->sk,rx_buf_tmp_len,rx_buf_tmp);

  if( http_conn->http_req == NULL ){

  	if( rx_len == 0 ){

  		RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_RX_LEN_CLOSED,"xxd",epoll_evt,http_conn,http_conn->sk);

     rhp_http_server_close_conn(http_conn,0);
     err = RHP_STATUS_CLOSE_HTTP_CONN;
     goto closed;
  	}

    http_conn->http_req = _rhp_http_req_alloc();
    if( http_conn->http_req == NULL ){
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }
  }

  if( rhp_http_server_conn_timer_stop(http_conn) ){

    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_STOP_TIMER_ERR,"xxd",epoll_evt,http_conn,http_conn->sk);

    err = RHP_STATUS_CLOSE_HTTP_CONN;
    goto closed;
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_REQ_PARMS,"xxxd",epoll_evt,http_conn,http_conn->http_req,http_conn->http_req->parsing_stat);

  switch( http_conn->http_req->parsing_stat ){

  case RHP_HTTP_REQ_PARSE_INIT:
  case RHP_HTTP_REQ_PARSE_REQLINE:
  case RHP_HTTP_REQ_PARSE_HEADER:

		if( rx_buf_tmp_len == 0 ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_INVALID_1,"xx",epoll_evt,http_conn);
			goto error;
		}

		err = _rhp_http_rx_request_header(http_conn,http_conn->http_req,rx_buf_tmp,rx_buf_tmp_len,&next_pt);
		if( err ){
		  RHP_BUG("%d",err);
		  goto error;
		}

		if( http_conn->http_req->parsing_stat == RHP_HTTP_REQ_PARSE_BODY ){

		  if( next_pt == NULL  ){

		  	if( http_conn->http_req->content_length > 0 ){
		  		break;
		  	}

		    http_conn->http_req->parsing_stat = RHP_HTTP_REQ_PARSE_COMPLETE;

		  }else{

		    if( next_pt >= (char*)(rx_buf + rx_len) ){
		      err = RHP_STATUS_INVALID_MSG;
		      RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_INVALID_2,"xx",epoll_evt,http_conn);
		  	  goto error;
		    }

		    rx_buf_tmp = next_pt;
		    rx_buf_tmp_len = (rx_buf + rx_len) - next_pt;

		    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_GO_PARSE_BODY,"xxp",epoll_evt,http_conn,rx_buf_tmp_len,rx_buf_tmp);
		    goto parse_body;
		  }
		}

		break;

  case RHP_HTTP_REQ_PARSE_BODY:

parse_body:
    if( rx_buf_tmp_len == 0 ){
    	http_conn->http_req->parsing_stat = RHP_HTTP_REQ_PARSE_COMPLETE;
    }

  	err = _rhp_http_rx_request_body(http_conn,http_conn->http_req,rx_buf_tmp,rx_buf_tmp_len);

  	RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_RX_REQ_BODY,"xxE",epoll_evt,http_conn,err);
  	break;

  case RHP_HTTP_REQ_PARSE_COMPLETE:
  default:
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  if( err ){
  	RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_MESG_ERR,"xxE",epoll_evt,http_conn,err);
  	goto error;
  }

  if( http_conn->http_req->parsing_stat == RHP_HTTP_REQ_PARSE_COMPLETE ){

		if( http_conn->http_req == NULL ){
	      RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_INVALID_3,"xx",epoll_evt,http_conn);
		  err = RHP_STATUS_INVALID_MSG;
		  goto abort;
		}

    if( http_conn->http_req->content_length >= 0 &&
    			http_conn->http_req->mesg_body_len != http_conn->http_req->content_length ){
    	err = RHP_STATUS_INVALID_MSG;
    	RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_INVALID_4,"xx",epoll_evt,http_conn);
    	goto error;
    }


    err = _rhp_http_server_parse_multipart_form_data(http_conn->http_req);
    if( err && err != -ENOENT ){
    	RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_PARSE_MULTIPART_FORM_DATA_ERR,"xxxE",epoll_evt,http_conn,http_conn->http_req,err);
    	goto error;
    }
    err = 0;


    err = _rhp_http_call_request_handlers(http_conn,http_conn->authorized);

    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_CALL_REQ_HANDLERS,"xxE",epoll_evt,http_conn,err);

    if( err == RHP_STATUS_HTTP_REQ_PENDING ){

      RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_GO_PEND,"xxd",epoll_evt,http_conn,rx_len);

     if( rx_len == 0 ){
        http_conn->pending_rx_closed = 1;
      }

     goto pending;
    }

    if( http_conn->http_req ){
      rhp_http_req_free(http_conn->http_req);
      http_conn->http_req = NULL;
    }

    if( err == RHP_STATUS_ABORT_HTTP_CONN ){
      RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_ABORT,"xx",epoll_evt,http_conn);
      goto abort;
    }else if( err < 0 || (err && err != RHP_STATUS_CLOSE_HTTP_CONN) ){
      RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_CALLBACK_ERR,"xxE",epoll_evt,http_conn,err);
      goto error;
    }
  }

  if( rx_len == 0 || err == RHP_STATUS_CLOSE_HTTP_CONN ){

  	RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_GO_CLOSED,"xxdE",epoll_evt,http_conn,rx_len,err);

  	rhp_http_server_close_conn(http_conn,0);
  	err = 0;
  	goto closed;
  }

rx_next:
  err = rhp_http_server_conn_rx_restart(http_conn);
  if( err ){
  	RHP_BUG("%d",err);
  	goto abort;
  }

  err = rhp_http_server_conn_timer_restart(http_conn);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

pending:
	if( rx_buf ){
		_rhp_free(rx_buf);
	}

  RHP_UNLOCK(&(http_conn->lock));

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_RTRN,"xx",epoll_evt,http_conn);
  return 0;

error:
	{
		int tx_auth_cookie = _rhp_http_protected_uri(http_conn->http_req);

		if( rhp_http_tx_server_def_error_response(http_conn,err,&close_flag,tx_auth_cookie) ){
abort:
    	close_flag = 1;
		}
	}

	if( http_conn->http_req ){
		rhp_ui_http_lower_err_handle(http_conn,http_conn->http_req);
	}

  if( close_flag >= 0 ){ // -1 : NOT close connection , 0 : gracefully close connection , 1 : abort connection
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_CALL_CLOSE_CONN,"xxd",epoll_evt,http_conn,close_flag);
    rhp_http_server_close_conn(http_conn,close_flag);
  }else{
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_GO_RX_NEXT,"xx",epoll_evt,http_conn);
    goto rx_next;
  }

closed:
  RHP_UNLOCK(&(http_conn->lock));
  rhp_http_conn_unhold(http_conn); // http_conn->sk_epoll_ctx.params[0]
  if( rx_buf ){
    _rhp_free(rx_buf);
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_HANDLE_EVENT_ERR,"xxE",epoll_evt,http_conn,err);
  return err;
}

// http_conn->lock must be aquired.
int rhp_http_server_conn_rx_restart(rhp_http_conn* http_conn)
{
  int err = 0;
  struct epoll_event ep_evt;
  memset(&ep_evt,0,sizeof(struct epoll_event));
//  ep_evt.events = EPOLLIN | EPOLLERR | EPOLLONESHOT;
  ep_evt.events = EPOLLIN | EPOLLONESHOT;
  ep_evt.data.ptr = (void*)&(http_conn->sk_epoll_ctx);

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_RX_RESTART,"x",http_conn);

  if( epoll_ctl(rhp_main_admin_epoll_fd,EPOLL_CTL_MOD,http_conn->sk,&ep_evt) < 0 ){
  	err = -errno;
  	RHP_BUG("%d",err);
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_RX_RESTART_RTRN,"xE",http_conn,err);
  return err;
}

// http_conn->lock must be aquired.
int rhp_http_server_conn_timer_stop(rhp_http_conn* http_conn)
{
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_TIMER_STOP,"x",http_conn);

  if( rhp_timer_delete(&(http_conn->conn_timer)) ){
    return -EINVAL;
  }
  rhp_http_conn_unhold(http_conn);

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_TIMER_STOP_RTRN,"x",http_conn);
  return 0;
}

// http_conn->lock must be aquired.
int rhp_http_server_conn_timer_restart(rhp_http_conn* http_conn)
{
  int err;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_TIMER_RESTART,"x",http_conn);

  rhp_timer_reset(&(http_conn->conn_timer));
  err = rhp_timer_add(&(http_conn->conn_timer),(time_t)http_conn->keep_alive_interval); // (**)
  if( err ){
  	RHP_BUG("%d",err);
  	return err;
  }
  rhp_http_conn_hold(http_conn); // (**)

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CONN_TIMER_RESTART_RTRN,"x",http_conn);
  return 0;
}


// _rhp_http_lock must be acquired.
int rhp_http_ipc_cfg_request(rhp_http_conn* http_conn,
		int data_len,u8* data,int (*ipc_callback)(rhp_http_conn* http_conn,int data_len,u8* data,void* ipc_cb_ctx),void* ipc_cb_ctx)
{
  int err = -EINVAL;
  rhp_ipcmsg_syspxy_cfg_req* cfg_req = NULL;
  int cfg_req_len = sizeof(rhp_ipcmsg_syspxy_cfg_req) + data_len;
  u8* p;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_IPC_CFG_REQUEST,"x",http_conn);

  if( http_conn->http_req == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  if( http_conn->ipc_txn_id != 0 ){
  	RHP_BUG("");
  	goto error;
  }

  if( http_conn->user_name == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  cfg_req_len += strlen(http_conn->user_name) + 1;


  cfg_req = (rhp_ipcmsg_syspxy_cfg_req*)rhp_ipc_alloc_msg(RHP_IPC_SYSPXY_CFG_REQUEST,cfg_req_len);
  if( cfg_req == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  p = (u8*)(cfg_req + 1);
  cfg_req->len = cfg_req_len;

  cfg_req->txn_id = _rhp_http_ipc_txn_id++;
  if( _rhp_http_ipc_txn_id == 0 ){
    _rhp_http_ipc_txn_id++;
  }

  cfg_req->opr_user_name_len = strlen(http_conn->user_name) + 1;
  cfg_req->request_user = RHP_IPC_USER_ADMIN_SERVER_HTTP;

  memcpy(p,http_conn->user_name,cfg_req->opr_user_name_len);
  p += cfg_req->opr_user_name_len;

  memcpy(p,data,data_len);


  http_conn->ipc_txn_id = cfg_req->txn_id;
  http_conn->ipc_callback = ipc_callback;
  http_conn->ipc_cb_ctx = ipc_cb_ctx;


  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)cfg_req,cfg_req->len,0) < 0 ){
   err = -EINVAL;
   RHP_BUG("");
   goto error;
 }

  err = 0;
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_IPC_CFG_TX_OK,"x",http_conn);

error:
  if( cfg_req ){
   _rhp_free_zero(cfg_req,cfg_req->len);
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_IPC_CFG_REQUEST_RTRN,"xE",http_conn,err);
  return err;
}

// _rhp_http_lock must be acquired.
int rhp_http_ipc_cfg_request_async(rhp_http_conn* http_conn,int data_len,u8* data,u64 http_bus_session_id)
{
  int err = -EINVAL;
  rhp_ipcmsg_syspxy_cfg_req* cfg_req = NULL;
  int cfg_req_len = sizeof(rhp_ipcmsg_syspxy_cfg_req) + data_len;
  u8* p;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_IPC_CFG_REQUEST_ASYNC,"x",http_conn);

  if( http_conn->http_req == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  if( http_conn->ipc_txn_id != 0 ){
  	RHP_BUG("");
  	goto error;
  }

  if( http_conn->user_name == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  cfg_req_len += strlen(http_conn->user_name) + 1;


  cfg_req = (rhp_ipcmsg_syspxy_cfg_req*)rhp_ipc_alloc_msg(RHP_IPC_SYSPXY_CFG_REQUEST,cfg_req_len);
  if( cfg_req == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  p = (u8*)(cfg_req + 1);
  cfg_req->len = cfg_req_len;

  cfg_req->txn_id = _rhp_http_ipc_txn_id++;
  if( _rhp_http_ipc_txn_id == 0 ){
    _rhp_http_ipc_txn_id++;
  }

  cfg_req->opr_user_name_len = strlen(http_conn->user_name) + 1;
  cfg_req->request_user = RHP_IPC_USER_ADMIN_SERVER_HTTP;
  cfg_req->http_bus_session_id = http_bus_session_id;

  memcpy(p,http_conn->user_name,cfg_req->opr_user_name_len);
  p += cfg_req->opr_user_name_len;

  memcpy(p,data,data_len);


  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)cfg_req,cfg_req->len,0) < 0 ){
   err = -EINVAL;
   RHP_BUG("");
   goto error;
 }

  err = 0;
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_IPC_CFG_REQUEST_ASYNC_IPC_TX_OK,"x",http_conn);

error:
  if( cfg_req ){
   _rhp_free_zero(cfg_req,cfg_req->len);
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_IPC_CFG_REQUEST_ASYNC_RTRN,"xE",http_conn,err);
  return err;
}


int rhp_http_server_cfg_ipc_handle(rhp_ipcmsg* ipcmsg)
{
  int err = -EINVAL;
  rhp_ipcmsg_syspxy_cfg_rep* cfg_rep = (rhp_ipcmsg_syspxy_cfg_rep*)ipcmsg;
  rhp_http_conn* http_conn = NULL;
  char* user_name = NULL;
  int close_flag = -1; // 0 : gracefully close connection , 1 : abort connection
  u8* data = NULL;
  int data_len = 0;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CFG_IPC_HANDLE,"x",ipcmsg);

  if( cfg_rep->request_user != RHP_IPC_USER_ADMIN_SERVER_HTTP ){
    RHP_BUG("");
    goto error;
  }

  if( cfg_rep->opr_user_name_len <= 1 ){
    RHP_BUG("");
    goto error;
  }

  user_name = (char*)(cfg_rep + 1);

  if( user_name[cfg_rep->opr_user_name_len-1] != '\0' ){
    RHP_BUG("");
    goto error;
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CFG_IPC_HANDLE_PARMS,"xs",ipcmsg,user_name);

  data = ((u8*)user_name) + cfg_rep->opr_user_name_len;
  data_len = cfg_rep->len - sizeof(rhp_ipcmsg_syspxy_cfg_rep) - cfg_rep->opr_user_name_len;


  if( cfg_rep->http_bus_session_id ){

  	err = rhp_http_bus_cfg_async_ipc_handle(cfg_rep->http_bus_session_id,cfg_rep,
  			user_name,data_len,(data_len > 0 ? data : NULL));

  	goto out;
  }


	RHP_LOCK(&_rhp_http_lock);

	http_conn = _rhp_http_conns_head;
	while( http_conn ){

		if( http_conn->ipc_txn_id &&
			http_conn->ipc_txn_id == cfg_rep->txn_id &&
			http_conn->user_name &&
			!strcasecmp(user_name,http_conn->user_name) ){
			break;
		}

		http_conn = http_conn->next;
	}

	if( http_conn == NULL ){

		RHP_UNLOCK(&_rhp_http_lock);

		RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CFG_IPC_HANDLE_NO_HTTP_CONN,"x",ipcmsg);
		goto error;
	}
	rhp_http_conn_hold(http_conn); // (**1)

	RHP_UNLOCK(&_rhp_http_lock);


	RHP_LOCK(&(http_conn->lock));

	if( !_rhp_atomic_read(&(http_conn->is_active)) ){
		RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CFG_IPC_HANDLE_HTTP_CONN_NOT_ACTIVE,"xx",ipcmsg,http_conn);
		goto error;
	}

	if( rhp_http_server_conn_timer_stop(http_conn) ){
		RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CFG_IPC_HANDLE_HTTP_CONN_TIMER_STOP_ERR,"xx",ipcmsg,http_conn);
		err = RHP_STATUS_CLOSE_HTTP_CONN;
		goto closed;
	}

	http_conn->ipc_txn_id = 0;

	if( http_conn->ipc_callback ){

		err = http_conn->ipc_callback(http_conn,data_len,data,http_conn->ipc_cb_ctx);

		http_conn->ipc_cb_ctx = NULL;
		http_conn->ipc_callback = NULL;

	}else{
		RHP_BUG("");
		goto abort;
	}


	if( err == RHP_STATUS_HTTP_REQ_PENDING ){
		RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CFG_IPC_HANDLE_AUTH_OK_GO_PENDING,"xx",ipcmsg,http_conn);
		goto pending;
	}

	if( http_conn->http_req ){
		rhp_http_req_free(http_conn->http_req);
		http_conn->http_req = NULL;
	}

	if( err == RHP_STATUS_ABORT_HTTP_CONN ){
		RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CFG_IPC_HANDLE_AUTH_OK_ABORT_CONN,"xx",ipcmsg,http_conn);
		goto abort;
	}else if( err < 0 || (err && err != RHP_STATUS_CLOSE_HTTP_CONN) ){
		RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CFG_IPC_HANDLE_AUTH_OK_BUT_ERR,"xxE",ipcmsg,http_conn,err);
		goto error;
	}else{
		RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CFG_IPC_HANDLE_AUTH_OK_NO_ERR,"xxE",ipcmsg,http_conn,err);
	}

	if( http_conn->pending_rx_closed || err == RHP_STATUS_CLOSE_HTTP_CONN ){

		RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CFG_IPC_HANDLE_GO_CLOSED,"xxdE",ipcmsg,http_conn,http_conn->pending_rx_closed,err);

		rhp_http_server_close_conn(http_conn,0);
		err = 0;

		goto closed;
	}

	err = rhp_http_server_conn_rx_restart(http_conn);
	if( err ){
		RHP_BUG("%d",err);
		goto abort;
	}

	err = rhp_http_server_conn_timer_restart(http_conn);
	if( err ){
		RHP_BUG("%d",err);
		goto abort;
	}

pending:
	RHP_UNLOCK(&(http_conn->lock));
	rhp_http_conn_unhold(http_conn); // (**1)

	RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CFG_IPC_HANDLE_RTRN,"xx",ipcmsg,http_conn);
	return 0;

error:
  if( http_conn ){

  	int tx_auth_cookie = _rhp_http_protected_uri(http_conn->http_req);

  	if( rhp_http_tx_server_def_error_response(http_conn,err,&close_flag,tx_auth_cookie) ){
abort:
      close_flag = 1;
    }

   	RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CFG_IPC_HANDLE_CLOSED,"xxd",ipcmsg,http_conn,close_flag);
    rhp_http_server_close_conn(http_conn,close_flag);

closed:
    RHP_UNLOCK(&(http_conn->lock));

    rhp_http_conn_unhold(http_conn); // (**1)
    rhp_http_conn_unhold(http_conn); // http_conn->sk_epoll_ctx.params[0]
  }

out:
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_CFG_IPC_HANDLE_ERR,"xxE",ipcmsg,http_conn,err);
  return err;
}

int rhp_http_server_auth_ipc_handle(rhp_ipcmsg* ipcmsg)
{
  int err = -EINVAL;
  rhp_ipcmsg_auth_rep* auth_rep = (rhp_ipcmsg_auth_rep*)ipcmsg;
  rhp_http_conn* http_conn = NULL;
  char* user_name = NULL;
  int close_flag = -1; // 0 : gracefully close connection , 1 : abort connection
  char cookie_auth_nonce_str[RHP_HTTP_AUTH_COOKIE_NONCE_STR_SIZE];

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_IPC_HANDLE,"x",ipcmsg);

  if( auth_rep->request_user != RHP_IPC_USER_ADMIN_SERVER_HTTP ){
    RHP_BUG("");
    goto error;
  }

  if( auth_rep->id_len <= 1 ){
    RHP_BUG("");
    goto error;
  }

  user_name = (char*)(auth_rep + 1);

  if( user_name[auth_rep->id_len-1] != '\0' ){
    RHP_BUG("");
    goto error;
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_IPC_HANDLE_PARMS,"xs",ipcmsg,user_name);

  RHP_LOCK(&_rhp_http_lock);

  http_conn = _rhp_http_conns_head;
  while( http_conn ){

    if( http_conn->ipc_txn_id &&
    	http_conn->ipc_txn_id == auth_rep->txn_id &&
   		http_conn->user_name &&
    	!strcasecmp(user_name,http_conn->user_name) ){
      break;
    }

    http_conn = http_conn->next;
  }

  if( http_conn == NULL ){

    RHP_UNLOCK(&_rhp_http_lock);

    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_IPC_HANDLE_NO_HTTP_CONN,"x",ipcmsg);
    goto error;
  }
  rhp_http_conn_hold(http_conn); // (**1)

  {
		_rhp_http_update_auth_cookie();

		cookie_auth_nonce_str[0] = '\0';
		strcpy(cookie_auth_nonce_str,_rhp_http_auth_cookie_nonce_str);
  }

  RHP_UNLOCK(&_rhp_http_lock);


  RHP_LOCK(&(http_conn->lock));

  if( !_rhp_atomic_read(&(http_conn->is_active)) ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_IPC_HANDLE_HTTP_CONN_NOT_ACTIVE,"xx",ipcmsg,http_conn);
    goto error;
  }

  {
		http_conn->cookie_auth_nonce_str[0] = '\0';
		strcpy(http_conn->cookie_auth_nonce_str,cookie_auth_nonce_str);
  }

  if( rhp_http_server_conn_timer_stop(http_conn) ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_IPC_HANDLE_HTTP_CONN_TIMER_STOP_ERR,"xx",ipcmsg,http_conn);
    err = RHP_STATUS_CLOSE_HTTP_CONN;
    goto closed;
  }

  http_conn->ipc_txn_id = 0;

  if( auth_rep->result ){

    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_IPC_HANDLE_AUTH_OK,"xxu",ipcmsg,http_conn,http_conn->acl_realm_id);

    if( auth_rep->vpn_realm_id && http_conn->acl_realm_id &&
    		auth_rep->vpn_realm_id != http_conn->acl_realm_id ){

    	RHP_LOG_DE(RHP_LOG_SRC_UI,0,RHP_LOG_ID_ADMIN_INVALID_REALM,"su",http_conn->user_name,http_conn->user_realm_id);

    	RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_IPC_HANDLE_AUTH_OK_BUT_RLM_ACL_NG,"xxuu",ipcmsg,http_conn,auth_rep->vpn_realm_id,http_conn->acl_realm_id);
    	goto auth_ng;
    }

    if( auth_rep->is_nobody ){

    	if( !rhp_gcfg_webmng_allow_nobody_admin ){

    		RHP_LOG_DE(RHP_LOG_SRC_UI,0,RHP_LOG_ID_ADMIN_NOBODY_USER_NOT_ALLOWED,"su",http_conn->user_name,http_conn->user_realm_id);

    		RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_IPC_HANDLE_AUTH_OK_BUT_NOBODY_USER_NG,"xxuu",ipcmsg,http_conn,auth_rep->vpn_realm_id,http_conn->acl_realm_id);
    		goto auth_ng;

    	}else if( !rhp_ip_is_loopback(&(http_conn->dst_addr)) ){

    		RHP_LOG_DE(RHP_LOG_SRC_UI,0,RHP_LOG_ID_ADMIN_NOBODY_USER_ALLOWED_ONLY_FROM_LOOPBACK,"suA",http_conn->user_name,http_conn->user_realm_id,&(http_conn->dst_addr));

    		RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_IPC_HANDLE_AUTH_OK_BUT_NOBODY_USER_NOT_LOOPBACK_NG,"xxuu",ipcmsg,http_conn,auth_rep->vpn_realm_id,http_conn->acl_realm_id);
    		goto auth_ng;
    	}

    	RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_IPC_HANDLE_AUTH_NOBODY_USER_OK,"xxuud",ipcmsg,http_conn,auth_rep->vpn_realm_id,http_conn->acl_realm_id,rhp_gcfg_webmng_allow_nobody_admin);
    }

    http_conn->authorized = 1;
    http_conn->user_realm_id = auth_rep->vpn_realm_id;
    http_conn->is_nobody = auth_rep->is_nobody;

    err = _rhp_http_call_request_handlers(http_conn,http_conn->authorized);

    if( err == RHP_STATUS_HTTP_REQ_PENDING ){
      RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_IPC_HANDLE_AUTH_OK_GO_PENDING,"xx",ipcmsg,http_conn);
      goto pending;
    }

    if( http_conn->http_req ){
      rhp_http_req_free(http_conn->http_req);
      http_conn->http_req = NULL;
    }

    if( err == RHP_STATUS_ABORT_HTTP_CONN ){
      RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_IPC_HANDLE_AUTH_OK_ABORT_CONN,"xx",ipcmsg,http_conn);
      goto abort;
    }else if( err < 0 || (err && err != RHP_STATUS_CLOSE_HTTP_CONN) ){
      RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_IPC_HANDLE_AUTH_OK_BUT_ERR,"xxE",ipcmsg,http_conn,err);
      goto error;
    }else{
      RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_IPC_HANDLE_AUTH_OK_NO_ERR,"xxE",ipcmsg,http_conn,err);
    }

  }else{

  	int conn_err;

auth_ng:
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_IPC_HANDLE_AUTH_NG,"xx",ipcmsg,http_conn);

    conn_err
    = (auth_rep->type == RHP_IPC_AUTH_COOKIE_REPLY ? RHP_STATUS_HTTP_COOKIE_UNAUTHORIZED : RHP_STATUS_HTTP_BASIC_UNAUTHORIZED);

    err = rhp_http_tx_server_unauth_error_response(http_conn,conn_err);
    if( err ){
      goto error;
    }

    err = RHP_STATUS_CLOSE_HTTP_CONN;
  }

  if( http_conn->pending_rx_closed || err == RHP_STATUS_CLOSE_HTTP_CONN ){

    RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_IPC_HANDLE_GO_CLOSED,"xxdE",ipcmsg,http_conn,http_conn->pending_rx_closed,err);

    rhp_http_server_close_conn(http_conn,0);
    err = 0;

    goto closed;
  }

  err = rhp_http_server_conn_rx_restart(http_conn);
  if( err ){
  	RHP_BUG("%d",err);
  	goto abort;
  }

  err = rhp_http_server_conn_timer_restart(http_conn);
  if( err ){
  	RHP_BUG("%d",err);
  	goto abort;
  }

pending:
  RHP_UNLOCK(&(http_conn->lock));
  rhp_http_conn_unhold(http_conn); // (**1)

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_IPC_HANDLE_RTRN,"xx",ipcmsg,http_conn);
  return 0;

error:
  if( http_conn ){
		int tx_auth_cookie = _rhp_http_protected_uri(http_conn->http_req);

  	if( rhp_http_tx_server_def_error_response(http_conn,err,&close_flag,tx_auth_cookie) ){
abort:
      close_flag = 1;
    }

   	RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_IPC_HANDLE_CLOSED,"xxd",ipcmsg,http_conn,close_flag);
    rhp_http_server_close_conn(http_conn,close_flag);

closed:
    RHP_UNLOCK(&(http_conn->lock));

    rhp_http_conn_unhold(http_conn); // (**1)
    rhp_http_conn_unhold(http_conn); // http_conn->sk_epoll_ctx.params[0]
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_SERVER_AUTH_IPC_HANDLE_ERR,"xxE",ipcmsg,http_conn,err);
  return err;
}


