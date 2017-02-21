/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifndef _RHP_HTTP_H_
#define _RHP_HTTP_H_

#define RHP_HTTP_VERSION "HTTP/1.0"
#define RHP_HTTP_SERVER_NAME RHP_PRODUCT_NAME

#define RHP_HTTP_BUS_VERSION "1.0"

/*******************

	HTTP URL API

********************/

extern int rhp_http_url_parse(char* url,char** hostname_r,char** port_r,char** path_r);


/**************************

 HTTP 1.1 Protocol APIs

**************************/

#define RHP_HTTP_SERVER_LISTEN_Q_NUM	5

struct _rhp_http_listen {

  unsigned char tag[4]; // "#HTL"

  struct _rhp_http_listen* next;
  struct _rhp_http_listen* cfg_next;

  rhp_mutex_t lock;

  rhp_atomic_t refcnt;
  rhp_atomic_t is_active;

  unsigned long id;

  int sk;  // FD for listening socket. -1 : Not specified.

  rhp_ip_addr my_addr;
  rhp_cfg_peer_acl* acl_addrs;

  rhp_atomic_t cur_conns;
  int max_conns;

  rhp_epoll_ctx sk_epoll_ctx;

  char* root_dir;
  unsigned long keep_alive_interval;
};
typedef struct _rhp_http_listen  rhp_http_listen;

#define RHP_HTTP_SVR_EPOLL_LISTEN_SK(epoll_ctx) ((epoll_ctx)->params[0])

extern int rhp_http_server_set_client_acls(rhp_http_listen* listen_sk,rhp_cfg_peer_acl* acl_addrs);

struct _rhp_http_header {

  struct _rhp_http_header* next;

  char* name;
  char* value;
};
typedef struct _rhp_http_header  rhp_http_header;


struct _rhp_http_body_part {

	u8 tag[4]; // '#HBP'

  struct _rhp_http_body_part* next;

  int part_len;
  char* part_head; // Don't free. Reference to rhp_http_request->mesg_body.

  rhp_http_header* headers_head;
  rhp_http_header* headers_tail;
  rhp_http_header* (*get_header)(struct _rhp_http_body_part* http_bpart,char* name);

  char* form_name;
  char* form_filename;

  int data_len;
  u8* data; // Don't free! Reference to rhp_http_request->mesg_body.
};
typedef struct _rhp_http_body_part  rhp_http_body_part;


struct _rhp_http_body_multipart_form_data {

	unsigned char tag[4]; // '#HMP'

	int part_num;
	rhp_http_body_part* part_head;
	rhp_http_body_part* part_tail;

	rhp_http_body_part* (*get_body_part)(struct _rhp_http_body_multipart_form_data* multipart_form_data,char* form_name);
};
typedef struct _rhp_http_body_multipart_form_data  rhp_http_body_multipart_form_data;


struct _rhp_http_request {

  unsigned char tag[4]; // "#HRQ"

  char* method;
  char* uri;
  char* version;

  long content_length;
  u64 session_id;

  rhp_http_header* headers_head;
  rhp_http_header* headers_tail;
  int (*put_header)(struct _rhp_http_request* http_req,char* header,long len,rhp_http_header** header_r);
  rhp_http_header* (*get_header)(struct _rhp_http_request* http_req,char* name);

  long mesg_body_len;
  char* mesg_body;

  rhp_http_body_multipart_form_data* multipart_form_data;

  struct {
  	char* user_name;
  	char* nonce;
#define RHP_HTTP_AUTH_TICKET_SIZE		20
  	u8* ticket; // HMAC-SHA-1
  } cookie;

  // members for http_bus I/O.
  char* clt_version;
  char* service_name;
  void* xml_doc; // xmlDocPtr
  void* xml_root_node; // xmlDocPtr , Don't free!

#define RHP_HTTP_REQ_PARSE_INIT						0
#define RHP_HTTP_REQ_PARSE_REQLINE				1
#define RHP_HTTP_REQ_PARSE_HEADER					2
#define RHP_HTTP_REQ_PARSE_BODY						3
#define RHP_HTTP_REQ_PARSE_COMPLETE				4
  int parsing_stat;

  long parsing_buf_len;
  char* parsing_buf;
};
typedef struct _rhp_http_request  rhp_http_request;


struct _rhp_http_response {

  unsigned char tag[4]; // "#HRS"

  char* status_code;
  char* reason_phrase;

  rhp_http_header* headers_head;
  rhp_http_header* headers_tail;
  int (*put_header)(struct _rhp_http_response* http_res,char* name,char* value);
  rhp_http_header* (*get_header)(struct _rhp_http_response* http_res,char* name);

  int tx_auth_cookie;
  int (*set_auth_cookie)(struct _rhp_http_response* http_res,char* nonce,int max_age_secs);

  int mesg_body_len;
  char* mesg_body;
};
typedef struct _rhp_http_response  rhp_http_response;


struct _rhp_http_conn {

  unsigned char tag[4]; // "#HCN"

  struct _rhp_http_conn* next;

  rhp_mutex_t lock;

  rhp_atomic_t refcnt;
  rhp_atomic_t is_active;

  int sk;  // FD for accepted socket. -1 : Not specified.

  u64 unique_id;

  rhp_epoll_ctx sk_epoll_ctx;

  rhp_ip_addr my_addr;
  rhp_ip_addr dst_addr;
  unsigned long acl_realm_id;

  rhp_timer conn_timer;

  rhp_http_listen* listen_sk;

  rhp_http_request* http_req;

  int rx_requests;

  char* root_dir;
  unsigned long keep_alive_interval;

  u64 ipc_txn_id;

  void* ipc_cb_ctx;
  int (*ipc_callback)(struct _rhp_http_conn* http_conn,int data_len,u8* data,void* ipc_cb_ctx);

  int pending_rx_closed;

  int authorized;
  char* user_name;
  unsigned long user_realm_id; // User's realm ID

  int pend_http_auth;

#define RHP_HTTP_AUTH_COOKIE_NONCE_SIZE	24
#define RHP_HTTP_AUTH_COOKIE_NONCE_STR_SIZE		(RHP_HTTP_AUTH_COOKIE_NONCE_SIZE*2 + 3)
  char cookie_auth_nonce_str[RHP_HTTP_AUTH_COOKIE_NONCE_STR_SIZE];
  char cookie_auth_nonce_str_old[RHP_HTTP_AUTH_COOKIE_NONCE_STR_SIZE];

  int (*timer_callback)(struct _rhp_http_conn* http_conn,void* cb_ctx,rhp_timer *timer);
  void* timer_ctx;
  void (*timer_ctx_free)(struct _rhp_http_conn* http_conn,void* cb_ctx); // Caller acquires http_conn->lock.

  int is_nobody;
};
typedef struct _rhp_http_conn  rhp_http_conn;

#define RHP_HTTP_SVR_EPOLL_CONN_SK(epoll_ctx) ((epoll_ctx)->params[0])


extern int rhp_http_server_init();
extern void rhp_http_server_cleanup();

extern void rhp_http_svr_hold(rhp_http_listen* listen_sk);
extern void rhp_http_svr_unhold(rhp_http_listen* listen_sk);

extern void rhp_http_conn_hold(rhp_http_conn* http_conn);
extern void rhp_http_conn_unhold(rhp_http_conn* http_conn);

extern int rhp_http_server_open(unsigned long id,rhp_ip_addr* my_addr,rhp_cfg_peer_acl* acl_addrs,int max_connection,char* root_dir,
		unsigned long keep_alive_interval,rhp_http_listen** listen_sk_r);
extern void rhp_http_server_close(rhp_http_listen* listen_sk);
extern int rhp_http_server_listen_handle_event(struct epoll_event* epoll_evt);

extern int rhp_http_server_conn_handle_event(struct epoll_event* epoll_evt);

// NOT thread safe! Call this api when process starts only.
extern int rhp_http_server_register_handler(int (*handler)(rhp_http_conn* http_conn,int authorized,void* ctx),void* ctx,int nobody_allowed);
extern void rhp_http_req_free(rhp_http_request* http_req);

#define RHP_HTTP_UNAUTHORIZED_ERR_MSG 	"<html><title>Authorization Required</title><body><h1>Authorization Required</h1></body></html>"
#define RHP_HTTP_NOT_FOUND_ERR_MSG 		"<html><title>Not Found</title><body><h1>Not Found</h1></body></html>"
#define RHP_HTTP_PING_RESPONSE_MSG 		"<html><title>Ping Response</title><body><h1>Ping Response OK</h1></body></html>"

extern int rhp_http_tx_server_response(rhp_http_conn* http_conn,rhp_http_response* http_res,int tx_auth_cookie);
extern int rhp_http_tx_server_unauth_error_response(rhp_http_conn* http_conn,int conn_err);
extern int rhp_http_tx_server_error_response(rhp_http_conn* http_conn,char* status_code,char* reason_phrase,char* mesg_body,int tx_auth_cookie);
extern int rhp_http_tx_server_def_error_response(rhp_http_conn* http_conn,int err,int* close_flag,int tx_auth_cookie);

extern int rhp_http_server_conn_rx_restart(rhp_http_conn* http_conn);
extern int rhp_http_server_conn_timer_stop(rhp_http_conn* http_conn);
extern int rhp_http_server_conn_timer_restart(rhp_http_conn* http_conn);
extern void rhp_http_server_close_conn(rhp_http_conn* http_conn,int abort_conn);

extern rhp_http_response* rhp_http_res_alloc(char* status_code,char* reason_phrase);
extern void rhp_http_res_free(rhp_http_response* http_res);

extern int rhp_http_auth_request(rhp_http_conn* http_conn,unsigned long rlm_id);
extern int rhp_http_auth_request_impl(rhp_http_conn* http_conn,unsigned long rlm_id,int http_basic_auth);

extern int rhp_http_server_auth_ipc_handle(rhp_ipcmsg* ipcmsg);
extern int rhp_http_server_cfg_ipc_handle(rhp_ipcmsg* ipcmsg);

extern int rhp_http_ipc_cfg_request(rhp_http_conn* http_conn,
		int data_len,u8* data,int (*ipc_callback)(rhp_http_conn* http_conn,int data_len,u8* data,void* ipc_cb_ctx),void* ipc_cb_ctx);
extern int rhp_http_ipc_cfg_request_async(rhp_http_conn* http_conn,int data_len,u8* data,u64 http_bus_session_id);

extern int rhp_http_fill_response_body_from_file(rhp_http_response* http_res,char* path);
extern int rhp_http_create_simple_xml_response(rhp_http_response* http_res,char* xml_contents);



/******************

  HTTP Bus APIs

*******************/

struct _rhp_http_bus_session {

  u8 tag[4]; // '#HBS'
  struct _rhp_http_bus_session* hash_next;

  struct _rhp_http_bus_session* list_next;
  struct _rhp_http_bus_session* list_prev;

#define RHP_HTTP_BUS_SESS_ID_STR		32
  char session_id_str[RHP_HTTP_BUS_SESS_ID_STR];
  u64 session_id;
  char* user_name;
  unsigned long user_realm_id;  // User's realm ID

  rhp_ip_addr my_addr;
  rhp_ip_addr dst_addr;
  unsigned long acl_realm_id;
  int is_nobody;

  rhp_mutex_t lock;

  rhp_atomic_t refcnt;
  rhp_atomic_t is_active;

  rhp_http_conn* http_conn_read;

  int bus_read_rec_num;
  int bus_read_xml_writer_len;
  void* bus_read_xml_writer;     // xmlTextWriterPtr
  void* bus_read_xml_writer_buf; // xmlBufferPtr

  rhp_timer session_timer;

  void* ipc_bus_cb_ctx;
  int (*ipc_bus_callback)(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,struct _rhp_http_bus_session* http_bus_sess,
  		rhp_http_request* http_req,int data_len,u8* data,void* ipc_bus_cb_ctx);

  u64 resp_serial_no;

  void* cfg_save_cb_ctx;
  void (*cfg_save_cb_ctx_free)(void* cb_ctx);

  void* cfg_restore_cb_ctx;
  void (*cfg_restore_cb_ctx_free)(void* cb_ctx);
};
typedef struct _rhp_http_bus_session rhp_http_bus_session;

extern void rhp_http_bus_sess_hold(rhp_http_bus_session* http_bus_sess);
extern void rhp_http_bus_sess_unhold(rhp_http_bus_session* http_bus_sess);

extern rhp_http_bus_session* rhp_http_bus_sess_get(u64 session_id,char* user_name);


extern int rhp_http_bus_serialize_mesg_with_one_record(rhp_http_bus_session* http_bus_sess,
		int (*serialize)(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx),void* ctx,
		char** res_xml,int* res_xml_len);


#define RHP_HTTP_BUS_SERVICE_NAME_MAX			64

// NOT thread safe! Call this api when process starts only.
extern int rhp_http_bus_register_request_handler(char* service_name,
		int (*handler)(rhp_http_conn* http_conn,rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx),void* ctx,
		int nobody_allowed);

extern int rhp_http_bus_send_async(u64 session_id,char* user_name,unsigned long rlm_id,int critical,int nobody_allowed,
        int (*serialize)(void* http_bus_sess,void* ctx,void* writer,int idx),void* ctx);

// Without acquiring (rhp_http_bus_session*)http_bus_sess->lock...
extern int rhp_http_bus_send_async_unlocked(void* http_bus_sess,unsigned long rlm_id,int critical,int nobody_allowed,
        int (*serialize)(void* http_bus_sess,void* ctx,void* writer,int idx),void* ctx);

#define RHP_HTTP_BUS_BTX_ALL_REALMS		0xFFFFFFFF
extern int rhp_http_bus_broadcast_async(unsigned long rlm_id,int critical,int nobody_allowed,
        int (*serialize)(void* http_bus_sess,void* ctx,void* writer,int idx),
        void (*cleanup)(void* ctx),void* ctx);

extern int rhp_http_bus_send_response(rhp_http_conn* http_conn,rhp_http_bus_session* http_bus_sess,
		int (*serialize)(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx),void* ctx);

extern int rhp_http_bus_ipc_cfg_request(rhp_http_conn* http_conn,rhp_http_bus_session* http_bus_sess,
		int data_len,u8* data,
		int (*ipc_bus_callback)(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,rhp_http_bus_session* http_bus_sess,
				rhp_http_request* http_req,int data_len,u8* data,void* ipc_bus_cb_ctx),void* ipc_bus_cb_ctx);


extern int rhp_http_bus_cfg_async_ipc_handle(u64 session_id,rhp_ipcmsg_syspxy_cfg_rep* cfg_rep,
		char* user_name,int data_len,u8* data);

extern int rhp_http_bus_ipc_cfg_request_async(rhp_http_conn* http_conn,
		u64 http_bus_session_id,int data_len,u8* data);


extern int rhp_http_bus_check_session_id(char* session_id_str);



/*********************************************

  UI's serialization handlers (for responses)

	- http_bus_sess_d : rhp_http_bus_session*
  - ctx : rhp_vpn*
  - writer : xmlTextWriterPtr

**********************************************/

extern void rhp_ui_http_vpn_bus_btx_async_cleanup(void* ctx);
extern int rhp_ui_http_vpn_close_serialize(void* http_bus_sess_d,void* ctx,void* writer,int idx);
extern int rhp_ui_http_vpn_established_serialize(void* http_bus_sess_d,void* ctx,void* writer,int idx);
extern int rhp_ui_http_vpn_added_serialize(void* http_bus_sess_d,void* ctx,void* writer,int idx);
extern int rhp_ui_http_vpn_deleted_serialize(void* http_bus_sess_d,void* ctx,void* writer,int idx);

extern int rhp_ui_http_vpn_mobike_i_rt_check_start_serialize(void* http_bus_sess_d,
		void* ctx,void* writer,int idx);
extern int rhp_ui_http_vpn_mobike_i_rt_check_finished_serialize(void* http_bus_sess_d,
		void* ctx,void* writer,int idx);
extern int rhp_ui_http_vpn_mobike_r_net_outage_finished_serialize(void* http_bus_sess_d,
		void* ctx,void* writer,int idx);
extern int rhp_ui_http_vpn_mobike_r_net_outage_detected_serialize(void* http_bus_sess_d,
		void* ctx,void* writer,int idx);



/******************

  HTTP GET API

*******************/

extern int rhp_http_clt_get(int urls_num,char** urls,time_t timeout /*secs*/,
		int addr_family, // AF_INET or AF_INET6
		void (*callback)(void* cb_ctx,int err,int rx_buf_num,int* rx_buf_lens,u8** rx_bufs),void* cb_ctx,
		int (*check_http_server_name)(char* server_name));


#endif // _RHP_HTTP_H_
