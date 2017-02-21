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

/*

 << Rockhopper HTTP Bus Protocol Overview >>

	Each session for HTTP Bus protocol needs two TCP connections. One is
	for "read" operation and the other is for "write" operation. These TCP connections
	may be closed and reconnected anytime, if the session does NOT expire yet.

	Only one session is assigned for each user. In other words, one user is bound to
	only one session. In this case, "user" means one who is authenticated by
	rhp_http_auth_request()[rhp_http.c].


  +----------+                        +--------------------+
 	|	         |=====[Read channel]==== |                    |
	| <client> |					              |  <Rockhopper>      |<===>[Rockhopper components]
	|(Browser, |=====[Write channel]====|  (HTTP Bus server) |
  |    etc.) |                        |                    |
  +----------+                        +--------------------+


	 - Open operation

	     <client>                      <Rockhopper(HTTP Bus server)>
               ====[POST request]===>
                                     [Send response with a new session_id]
               <===[POST response]===

	 - Read operation

	     <client>                     <Rockhopper(HTTP Bus server)>
      (Polling)====[GET request]===>
                                    [Pending the connection for a while]
                                                                          <Rockhopper other components>
                                                       [Messages]<========(Async)
                                    [Send response with messages]
               <===[GET response]===

      (Polling)====[GET request]===>
      ...(repeated)...


			*Rockhopper components may broadcast their messages to multiple clients at the same time, if needed.


	 - Write operation

	     <client>                     <Rockhopper(HTTP Bus server)>
               ====[PUT request]===>
                                                  [Message]======>
                                                                  <Rockhopper other components>
               <===[PUT response]<===[Send response soon]<========(Sync)

	 - Close operation

	     <client>                         <Rockhopper(HTTP Bus server)>
               ====[DELETE request]===>
                                        [Send response]
               <===[DELETE response]===



	[Open]
	 - Method : POST
	 - URI : /bus/open
	 - Body :  Request: None , Response: See (*2)

	[Read]
	 - Method : GET
	 - URI : /bus/read/<session_id>  (ex) /bus/read/1234 (Decimal)
	 - Body : Request: None, Response: See (*1)

	[Write]
	 - Method : PUT
	 - URI : /bus/write/<session_id>  (ex) /bus/write/1234 (Decimal)
	 - Body : See (*1)

	[Close]
	 - Method : DELETE
	 - URI : /bus/close/<session_id>  (ex) /bus/close/1234 (Decimal)
	 - Body : None


 - (*1)

	 [XML message : Request(Client ==> Server)]

	 <?xml version="1.0"?>

		 <rhp_http_bus_request version="1.0" service="service_id">
			 ...
		 </rhp_http_bus_request>

	------

	 [XML message : Response(Server ==> Client)]

	 <?xml version="1.0"?>

		 <rhp_http_bus_response version="1.0">

			 <rhp_http_bus_record index="0" service="service_id" ... />

			 <rhp_http_bus_record index="1" service="service_id" ... >
				 ...
			 </rhp_http_bus_record>

			 ...

		 </rhp_http_bus_response>

		 -- A rhp_http_bus_response message may contain multiple rhp_http_bus_records.

	------


 - (*2)

	 [XML message : /bus/open Response(Server ==> Client)]

		<?xml version="1.0"?>
		<rhp_http_bus_response version="1.0">
			<rhp_http_bus_record index="0" service="new_session" session_id="1234"/>
		</rhp_http_bus_response>

 */

#define RHP_HTTP_BUS_UNKNOWN		0
#define RHP_HTTP_BUS_OPEN				1
#define RHP_HTTP_BUS_READ				2
#define RHP_HTTP_BUS_WRITE			3
#define RHP_HTTP_BUS_CLOSE			4
#define RHP_HTTP_BUS_KEEPALIVE	5

static rhp_mutex_t _rhp_http_bus_lock;

struct _rhp_http_bus_req_handler {

  u8 tag[4]; // "#HBH"
  struct _rhp_http_bus_req_handler* next;

  char service_name[RHP_HTTP_BUS_SERVICE_NAME_MAX];
  int (*handler)(rhp_http_conn* http_conn,rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx);
  void* ctx;

  int nobody_allowed;
};
typedef struct _rhp_http_bus_req_handler rhp_http_bus_req_handler;

// NOT thread safe! handlers are registered when process starts only.
static rhp_http_bus_req_handler* _rhp_http_bus_req_handlers = NULL;
static rhp_http_bus_req_handler* _rhp_http_bus_req_handlers_tail = NULL;


static u64 _rhp_http_bus_sess_idx = 1;

#define RHP_HTTP_BUS_HASH_SIZE	257
static rhp_http_bus_session* _rhp_http_bus_sess_hashtbl[RHP_HTTP_BUS_HASH_SIZE];
static rhp_http_bus_session* _rhp_http_bus_sess_list = NULL;
static rhp_atomic_t _rhp_http_bus_sess_num;


int _rhp_http_bus_xml_writer_start(rhp_http_bus_session* http_bus_sess,void** writer_r,void** buf_r,int* len_r)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;
  xmlTextWriterPtr writer = NULL;
  xmlBufferPtr buf;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_XML_WRITER_START,"xxxx",http_bus_sess,writer_r,buf_r,len_r);

  buf = xmlBufferCreate();
  if( buf == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  writer = xmlNewTextWriterMemory(buf,0);
  if (writer == NULL) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  n = xmlTextWriterStartDocument(writer,NULL,NULL,NULL); // 1.0,UTF-8,standalone
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterStartElement(writer,(xmlChar*)"rhp_http_bus_response");
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute(writer,(xmlChar*)"version",(xmlChar*)RHP_HTTP_BUS_VERSION);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"serial_no","%llu",http_bus_sess->resp_serial_no);
  http_bus_sess->resp_serial_no++;
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  *writer_r = writer;
  *buf_r = buf;
  *len_r = n2;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_XML_WRITER_START_RTRN,"xxp",http_bus_sess,*writer_r,*len_r,*buf_r);
  return 0;

error:
  if( writer ){
    xmlFreeTextWriter(writer);
  }

  if( buf ){
    xmlBufferFree(buf);
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_XML_WRITER_START_ERR,"x",http_bus_sess);
  return err;
}

int _rhp_http_bus_xml_writer_end(rhp_http_bus_session* http_bus_sess,
		void* writer_i,void* buf_i,int len,char** res_xml,int* res_xml_len)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = len;
  xmlTextWriterPtr writer = (xmlTextWriterPtr)writer_i;
  xmlBufferPtr buf = (xmlBufferPtr)buf_i;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_XML_WRITER_END,"xxxdxx",http_bus_sess,writer_i,buf_i,len,res_xml,res_xml_len);

  n = xmlTextWriterEndDocument(writer);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterFlush(writer);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  xmlFreeTextWriter(writer);
  writer = NULL;


  *res_xml = (char*)_rhp_malloc(n2);
  if( *res_xml == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  memcpy((*res_xml),buf->content,n2);
  *res_xml_len = n2;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_XML_WRITER_END_OK,"xp",http_bus_sess,*res_xml_len,*res_xml);

  err = 0;

error:
	if( writer ){
	  xmlFreeTextWriter(writer);
	}
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_XML_WRITER_END_RTRN,"xE",http_bus_sess,err);
  return err;
}


int rhp_http_bus_serialize_mesg_with_one_record(rhp_http_bus_session* http_bus_sess,
		int (*serialize)(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx),void* ctx,
		char** res_xml,int* res_xml_len)
{
  int err = -EINVAL;
  int n = 0;
  void* writer = NULL;
  void* buf = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SERIALIZE_MESG_WITH_ONE_RECORD,"xYxxx",http_bus_sess,serialize,ctx,res_xml,res_xml_len);

  if( serialize == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SERIALIZE_MESG_WITH_ONE_RECORD_NO_SERIALIZE_METHOD_IGNORED,"x",http_bus_sess);
    err = 0;
    goto end; // Ignored.
  }

  err = _rhp_http_bus_xml_writer_start(http_bus_sess,&writer,&buf,&n);
  if( err ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SERIALIZE_MESG_WITH_ONE_RECORD_WRITER_START_ERR,"x",http_bus_sess);
    goto error;
  }

  n = serialize(http_bus_sess,ctx,writer,0);
 	if(n < 0){
 		err = n;
 	  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SERIALIZE_MESG_WITH_ONE_RECORD_SERIALIZE_ERR,"xE",http_bus_sess,err);
	  goto error;
 	}

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SERIALIZE_MESG_WITH_ONE_RECORD_SERIALIZE,"xd",http_bus_sess,n);

  err =  _rhp_http_bus_xml_writer_end(http_bus_sess,writer,buf,n,res_xml,res_xml_len);
  writer = NULL;
  if( err ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SERIALIZE_MESG_WITH_ONE_RECORD_WRITER_END_ERR,"xE",http_bus_sess,err);
    goto error;
  }

error:
end:
  if( writer ){
    xmlFreeTextWriter(writer);
  }
  if( buf ){
    xmlBufferFree(buf);
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SERIALIZE_MESG_WITH_ONE_RECORD_RTRN,"xE",http_bus_sess,err);
  return err;
}


static u32 _rhp_http_bus_hash(u64 session_id)
{
  u32 hash = ((u32*)&session_id)[0];
  return hash % RHP_HTTP_BUS_HASH_SIZE;
}

static void _rhp_http_bus_sess_free(rhp_http_bus_session* http_bus_sess)
{

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SESS_FREE,"x",http_bus_sess);

  if( http_bus_sess->cfg_save_cb_ctx && http_bus_sess->cfg_save_cb_ctx_free ){
  	http_bus_sess->cfg_save_cb_ctx_free(http_bus_sess->cfg_save_cb_ctx);
  }

  if( http_bus_sess->cfg_restore_cb_ctx && http_bus_sess->cfg_restore_cb_ctx_free ){
  	http_bus_sess->cfg_restore_cb_ctx_free(http_bus_sess->cfg_restore_cb_ctx);
  }

  if( http_bus_sess->http_conn_read ){
    rhp_http_conn_unhold(http_bus_sess->http_conn_read);
  }

  if( http_bus_sess->user_name ){
    _rhp_free_zero(http_bus_sess->user_name,strlen(http_bus_sess->user_name)+1);
  }

  if( http_bus_sess->bus_read_xml_writer ){
    xmlFreeTextWriter(http_bus_sess->bus_read_xml_writer);
  }

  if( http_bus_sess->bus_read_xml_writer_buf ){
    xmlBufferFree(http_bus_sess->bus_read_xml_writer_buf);
  }

  _rhp_mutex_destroy(&(http_bus_sess->lock));
  _rhp_atomic_destroy(&(http_bus_sess->is_active));
  _rhp_atomic_destroy(&(http_bus_sess->refcnt));

  _rhp_free(http_bus_sess);

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SESS_FREE_RTRN,"x",http_bus_sess);
}

static int _rhp_http_bus_sess_delete(rhp_http_bus_session* http_bus_sess)
{
  rhp_http_bus_session *tmp = NULL,*tmp2 = NULL;
  u32 hash = _rhp_http_bus_hash(http_bus_sess->session_id);

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SESS_DELETE,"xq",http_bus_sess,http_bus_sess->session_id);

  RHP_LOCK(&_rhp_http_bus_lock);

  tmp = _rhp_http_bus_sess_hashtbl[hash];
  while( tmp ){

  	if( http_bus_sess == tmp ){
      break;
  	}

  	tmp2 = tmp;
    tmp = tmp->hash_next;
  }

  RHP_UNLOCK(&_rhp_http_bus_lock);

  if( tmp ){

    if( tmp2 == NULL ){
   	  _rhp_http_bus_sess_hashtbl[hash] = http_bus_sess->hash_next;
    }else{
      tmp2->hash_next = http_bus_sess->hash_next;
    }

    if( http_bus_sess->list_prev == NULL ){
   	  _rhp_http_bus_sess_list = http_bus_sess->list_next;
   	  if( _rhp_http_bus_sess_list ){
   	  	_rhp_http_bus_sess_list->list_prev = NULL;
   	  }
    }else{
   	  http_bus_sess->list_prev->list_next = http_bus_sess->list_next;
   	  if( http_bus_sess->list_next ){
   	  	http_bus_sess->list_next->list_prev = http_bus_sess->list_prev;
   	  }
    }

    http_bus_sess->hash_next = NULL;
    http_bus_sess->list_next = NULL;
    http_bus_sess->list_prev = NULL;

    rhp_http_bus_sess_unhold(http_bus_sess);
    _rhp_atomic_dec(&_rhp_http_bus_sess_num);

    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SESS_DELETE_RTRN,"x",http_bus_sess);
    return 0;

  }else{
  	RHP_BUG("");
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SESS_DELETE_ERR,"x",http_bus_sess);
  return -ENOENT;
}

static void _rhp_http_bus_sess_timer(void* ctx,rhp_timer *timer)
{
  int err = -EINVAL;
  rhp_http_bus_session* http_bus_sess = (rhp_http_bus_session*)ctx;
  rhp_http_response* http_res = NULL;
  rhp_http_conn* http_conn = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SESS_TIMER,"xx",timer,http_bus_sess);

  RHP_LOCK(&(http_bus_sess->lock));

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SESS_TIMER_RECORD_NUM,"xxd",timer,http_bus_sess,http_bus_sess->bus_read_rec_num);

  if( !_rhp_atomic_read(&(http_bus_sess->is_active)) ){
  	err = -ENOENT;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SESS_TIMER_NOT_ACTIVE,"xx",timer,http_bus_sess);
    goto error;
  }

  http_conn = http_bus_sess->http_conn_read;
  if( http_conn == NULL ){ // Idle timeout.
  	err = RHP_STATUS_CLOSE_HTTP_CONN;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SESS_TIMER_IDLE_TIMEOUT,"xx",timer,http_bus_sess);
    goto error;
  }
  rhp_http_conn_hold(http_conn); // (**4)

  RHP_UNLOCK(&(http_bus_sess->lock));


  RHP_LOCK(&(http_conn->lock));

  if( !_rhp_atomic_read(&(http_conn->is_active)) ){ // Idle timeout.
    err = RHP_STATUS_CLOSE_HTTP_CONN;
    goto error;
  }

  RHP_LOCK(&(http_bus_sess->lock));

  if( !_rhp_atomic_read(&(http_bus_sess->is_active)) ){
  	err = -ENOENT;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SESS_TIMER_NOT_ACTIVE,"xx",timer,http_bus_sess);
    goto error;
  }

  //
  // Handling for /bus/read/session.
  //

  http_res = rhp_http_res_alloc("200","OK");
  if( http_res == NULL ){
    err = -ENOMEM;
	  RHP_BUG("");
    goto error;
  }

  err = http_res->put_header(http_res,"Content-Type","text/xml; charset=utf-8");
  if( err ){
		RHP_BUG("");
    goto error;
  }

  if( http_bus_sess->bus_read_rec_num ){

    err = _rhp_http_bus_xml_writer_end(http_bus_sess,http_bus_sess->bus_read_xml_writer,
    		http_bus_sess->bus_read_xml_writer_buf,http_bus_sess->bus_read_xml_writer_len,
    		&http_res->mesg_body,&http_res->mesg_body_len);

    http_bus_sess->bus_read_xml_writer = NULL;

    if( err ){
      RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SESS_TIMER_WRITER_END_ERR,"xxE",timer,http_bus_sess,err);
      err = RHP_STATUS_ABORT_HTTP_CONN;
      goto error;
    }

    xmlFreeTextWriter(http_bus_sess->bus_read_xml_writer);
    xmlBufferFree(http_bus_sess->bus_read_xml_writer_buf);

    http_bus_sess->bus_read_xml_writer_len = 0;
    http_bus_sess->bus_read_xml_writer = NULL;
    http_bus_sess->bus_read_xml_writer_buf = NULL;
    http_bus_sess->bus_read_rec_num = 0;

  }else{

			http_res->mesg_body_len = strlen("<?xml version=\"1.0\"?><rhp_http_bus_response version=\"");
			http_res->mesg_body_len += strlen(RHP_HTTP_BUS_VERSION);
			http_res->mesg_body_len += strlen("\"/>");

			http_res->mesg_body = (char*)_rhp_malloc(http_res->mesg_body_len + 1);
			if( http_res->mesg_body == NULL ){
				RHP_BUG("");
				http_res->mesg_body_len = 0;
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}

			http_res->mesg_body[0] = '\0';
		  sprintf(http_res->mesg_body,"%s%s%s",
		  		"<?xml version=\"1.0\"?><rhp_http_bus_response version=\"",
		  		RHP_HTTP_BUS_VERSION,
		  		"\"/>");
  }

	err = rhp_http_tx_server_response(http_conn,http_res,1);
	if( err ){
		RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SESS_TIMER_TX_SERVER_RESP_ERR,"xxE",timer,http_bus_sess,err);
		err = RHP_STATUS_ABORT_HTTP_CONN;
		goto error;
	}

	rhp_http_res_free(http_res);
	http_res = NULL;

  if( http_conn->http_req ){
    rhp_http_req_free(http_conn->http_req);
    http_conn->http_req = NULL;
  }

  if( http_bus_sess->http_conn_read ){
    rhp_http_conn_unhold(http_bus_sess->http_conn_read); // (**_rhp_http_bus_read**)
    http_bus_sess->http_conn_read = NULL;
  }

  rhp_timer_reset(&(http_bus_sess->session_timer));

  err = rhp_timer_add(&(http_bus_sess->session_timer),(time_t)rhp_gcfg_http_bus_idle_timeout);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }
  rhp_http_bus_sess_hold(http_bus_sess);

/*
  err = rhp_http_server_conn_rx_restart(http_conn);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  err = rhp_http_server_conn_timer_restart(http_conn);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }
*/

	rhp_http_server_close_conn(http_conn,0); // (**5**)


  RHP_UNLOCK(&(http_bus_sess->lock));
  RHP_UNLOCK(&(http_conn->lock));

  rhp_http_conn_unhold(http_conn); // (**4)
  rhp_http_bus_sess_unhold(http_bus_sess);

  rhp_http_conn_unhold(http_conn); // http_conn->sk_epoll_ctx.params[0] , (**5**)

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SESS_TIMER_RTRN,"xx",timer,http_bus_sess);
  return;

error:
	if( http_res ){
		rhp_http_res_free(http_res);
	}

  if( http_conn ){
    rhp_http_server_close_conn(http_conn,0); // (**6)**)
  }

  _rhp_atomic_set(&(http_bus_sess->is_active),0);

  if( http_bus_sess->http_conn_read ){
    rhp_http_server_close_conn(http_bus_sess->http_conn_read,0);
    rhp_http_conn_unhold(http_bus_sess->http_conn_read);
    http_bus_sess->http_conn_read = NULL;
  }

  RHP_UNLOCK(&(http_bus_sess->lock));
  if( http_conn ){
    RHP_UNLOCK(&(http_conn->lock));
    rhp_http_conn_unhold(http_conn); // (**6**)
  }

  _rhp_http_bus_sess_delete(http_bus_sess);

  rhp_http_bus_sess_unhold(http_bus_sess);

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SESS_TIMER_ERR,"xx",timer,http_bus_sess);
  return;
}

static rhp_http_bus_session* _rhp_http_bus_sess_alloc(char* user_name)
{
  rhp_http_bus_session* http_bus_sess = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SESS_ALLOC,"s",user_name);

  if( user_name == NULL ){
    RHP_BUG("");
    return NULL;
  }

  http_bus_sess = (rhp_http_bus_session*)_rhp_malloc(sizeof(rhp_http_bus_session));
  if( http_bus_sess == NULL ){
    RHP_BUG("");
    goto error;
  }
  memset(http_bus_sess,0,sizeof(rhp_http_bus_session));

  http_bus_sess->tag[0] = '#';
  http_bus_sess->tag[1] = 'H';
  http_bus_sess->tag[2] = 'B';
  http_bus_sess->tag[3] = 'S';

  _rhp_mutex_init("HTL",&(http_bus_sess->lock));
  _rhp_atomic_init(&(http_bus_sess->is_active));
  _rhp_atomic_init(&(http_bus_sess->refcnt));

  http_bus_sess->user_name = (char*)_rhp_malloc(strlen(user_name)+1);
  if( http_bus_sess->user_name == NULL ){
    RHP_BUG("");
    goto error;
  }
  http_bus_sess->user_name[0] = '\0';
  strcpy(http_bus_sess->user_name,user_name);

  rhp_timer_init(&(http_bus_sess->session_timer),_rhp_http_bus_sess_timer,http_bus_sess);

  RHP_LOCK(&_rhp_http_bus_lock);
  {

  	http_bus_sess->session_id = _rhp_http_bus_sess_idx++;

  	if( _rhp_http_bus_sess_idx == (u64)(-1) ){
  		_rhp_http_bus_sess_idx += 2;
  	}
  }
  RHP_UNLOCK(&_rhp_http_bus_lock);

  http_bus_sess->session_id_str[0] = '\0';
  sprintf(http_bus_sess->session_id_str,"%llu",http_bus_sess->session_id);

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SESS_ALLOC_RTRN,"x",http_bus_sess);
  return http_bus_sess;

error:
  if( http_bus_sess ){
    _rhp_http_bus_sess_free(http_bus_sess);
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SESS_ALLOC_ERR,"");
  return NULL;
}

void rhp_http_bus_sess_hold(rhp_http_bus_session* http_bus_sess)
{
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SESS_HOLD,"xd",http_bus_sess,http_bus_sess->refcnt.c);
  _rhp_atomic_inc(&(http_bus_sess->refcnt));
}

void rhp_http_bus_sess_unhold(rhp_http_bus_session* http_bus_sess)
{
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SESS_UNHOLD,"xd",http_bus_sess,http_bus_sess->refcnt.c);

  if( _rhp_atomic_dec_and_test(&(http_bus_sess->refcnt)) ){

  	if( http_bus_sess->user_realm_id == 0 ){

  		rhp_ui_log_main_log_ctl(0);
  	}

  	_rhp_http_bus_sess_free(http_bus_sess);
  }
}

static rhp_http_bus_session* _rhp_http_bus_sess_get(u64 session_id,char* user_name)
{
  rhp_http_bus_session*	http_bus_sess = NULL;
  u32 hash = _rhp_http_bus_hash(session_id);

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SESS_GET,"qs",session_id,user_name);

  RHP_LOCK(&_rhp_http_bus_lock);

  if( (session_id != (u64)-1) ){

    http_bus_sess = _rhp_http_bus_sess_hashtbl[hash];
    while( http_bus_sess ){

	  if( (http_bus_sess->session_id == session_id) &&
		  user_name && !strcasecmp(http_bus_sess->user_name,user_name) ){
        break;
	  }

      http_bus_sess = http_bus_sess->hash_next;
    }

  }else{

    http_bus_sess = _rhp_http_bus_sess_list;

    while( http_bus_sess ){

  	  if( user_name && !strcasecmp(http_bus_sess->user_name,user_name) ){
  	  	break;
  	  }

      http_bus_sess = http_bus_sess->list_next;
    }
  }

  if( http_bus_sess ){
    rhp_http_bus_sess_hold(http_bus_sess);
  }

  RHP_UNLOCK(&_rhp_http_bus_lock);

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SESS_GET_RTRN,"qx",session_id,http_bus_sess);
  return http_bus_sess;
}

rhp_http_bus_session* rhp_http_bus_sess_get(u64 session_id,char* user_name)
{
	return _rhp_http_bus_sess_get(session_id,user_name);
}


static void _rhp_http_bus_sess_put(rhp_http_bus_session* http_bus_sess)
{
  u32 hash = _rhp_http_bus_hash(http_bus_sess->session_id);

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SESS_PUT,"xq",http_bus_sess,http_bus_sess->session_id);

  http_bus_sess->hash_next = NULL;
  http_bus_sess->list_next = NULL;
  http_bus_sess->list_prev = NULL;

  RHP_LOCK(&_rhp_http_bus_lock);

  if( _rhp_http_bus_sess_hashtbl[hash] ){
    http_bus_sess->hash_next = _rhp_http_bus_sess_hashtbl[hash];
  }
  _rhp_http_bus_sess_hashtbl[hash] = http_bus_sess;

  if( _rhp_http_bus_sess_list ){
    http_bus_sess->list_next = _rhp_http_bus_sess_list;
    _rhp_http_bus_sess_list->list_prev = http_bus_sess;
  }
  _rhp_http_bus_sess_list = http_bus_sess;

  rhp_http_bus_sess_hold(http_bus_sess);
  _rhp_atomic_inc(&_rhp_http_bus_sess_num);

  RHP_UNLOCK(&_rhp_http_bus_lock);

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_SESS_PUT_RTRN,"x",http_bus_sess);
}


int rhp_http_bus_check_session_id(char* session_id_str)
{
  char* c = session_id_str;
  int i = 0;

  while( *c != '\0' ){

    if( *c < '0' || *c > '9' ){
   	  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_CHECK_SESSION_ID_INVAL_1,"s",session_id_str);
      return -1;
    }

    if( i > 20 ){ // u64_max
   	  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_CHECK_SESSION_ID_INVAL_2,"s",session_id_str);
      return -1;
    }

    i++;
    c++;
  }

  if( i < 1 ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_CHECK_SESSION_ID_INVAL_3,"s",session_id_str);
    return -1;
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_CHECK_SESSION_ID_OK,"s",session_id_str);
  return 0;
}

static int _rhp_http_bus_open_serialize(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_OPEN_SERIALIZE,"xxxd",http_bus_sess,ctx,writer,idx);

  n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"http_bus");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"open");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_OPEN_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_OPEN_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}


static int _rhp_http_bus_open(rhp_http_conn* http_conn)
{
  int err = -EINVAL;
  rhp_http_bus_session* http_bus_sess = NULL;
  rhp_http_request* http_req = http_conn->http_req;
  rhp_http_response* http_res = NULL;
  rhp_http_header* req_header = NULL;
  int new_sess = 0;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_OPEN,"x",http_conn);

  if( http_req == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_OPEN_NO_REQ_ERR,"x",http_conn);
    return -ENOENT;
  }

  if( _rhp_atomic_read(&_rhp_http_bus_sess_num) > rhp_gcfg_http_bus_max_session ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_OPEN_MAX_SESS_ERR,"xdd",http_conn,_rhp_http_bus_sess_num.c,rhp_gcfg_http_bus_max_session);
    return -ENOENT;
  }

  req_header = http_req->get_header(http_req,"Accept");

  if( req_header && req_header->value ){

  	if( (strcasestr(req_header->value,"text/xml") == NULL) &&
  			(strcasestr(req_header->value,"text/*") == NULL) &&
  			(strcasestr(req_header->value,"*/*") == NULL) ){
  		RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_OPEN_INVALID_ACCEPT_HEADER_VALUE,"xxxs",http_conn,http_req,req_header,req_header->value);
  		return -ENOENT;
  	}

  }else{
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_OPEN_NO_ACCEPT_HEADER,"xx",http_conn,http_req);
  }

  req_header = http_req->get_header(http_req,"Accept-Charset");

  if( req_header && req_header->value ){

  	if( (strcasestr(req_header->value,"utf-8") == NULL) &&
  			(strcasestr(req_header->value,"*") == NULL) ){
      RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_OPEN_INVALID_ACCEPT_CHARSET_HEADER_VALUE,"xxxs",http_conn,http_req,req_header,req_header->value);
      return -ENOENT;
  	}

  }else{

    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_OPEN_NO_ACCEPT_CHARSET_HEADER,"xx",http_conn,http_req);
  }

  http_bus_sess = _rhp_http_bus_sess_get(-1,http_conn->user_name); // (*)
  if( http_bus_sess == NULL ){

    http_bus_sess = _rhp_http_bus_sess_alloc(http_conn->user_name);
    if( http_bus_sess == NULL ){
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }

    rhp_http_bus_sess_hold(http_bus_sess); // (*)

    http_bus_sess->user_realm_id = http_conn->user_realm_id;
    new_sess = 1;

  }else{

    RHP_LOCK(&(http_bus_sess->lock));

    if( http_bus_sess->user_realm_id != http_conn->user_realm_id ){
      RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_OPEN_INVALID_RLM_ID,"xxuu",http_conn,http_res,http_bus_sess->user_realm_id,http_conn->user_realm_id);
      err = -EPERM;
      goto error;
    }

    if( !rhp_timer_delete(&(http_bus_sess->session_timer)) ){
      rhp_http_bus_sess_unhold(http_bus_sess); // (**)
    }

    rhp_timer_reset(&(http_bus_sess->session_timer));
  }


  memcpy(&(http_bus_sess->my_addr),&(http_conn->my_addr),sizeof(rhp_ip_addr));
  memcpy(&(http_bus_sess->dst_addr),&(http_conn->dst_addr),sizeof(rhp_ip_addr));
  http_bus_sess->acl_realm_id = http_conn->acl_realm_id;

  http_bus_sess->is_nobody = http_conn->is_nobody;


  http_res = rhp_http_res_alloc("200","OK");
  if( http_res == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  err = http_res->put_header(http_res,"Content-Type","text/xml; charset=utf-8");
  if( err ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_OPEN_PUT_HEADER_ERR,"xxE",http_conn,http_res,err);
    goto error;
  }

  err = rhp_http_bus_serialize_mesg_with_one_record(http_bus_sess,_rhp_http_bus_open_serialize,NULL,
		  &(http_res->mesg_body),&http_res->mesg_body_len);

  if( err ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_OPEN_SERIALIZE_MESG_ERR,"xE",http_conn,err);
    goto error;
  }

  err = rhp_http_tx_server_response(http_conn,http_res,1);
  if( err ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_OPEN_TX_RESP_ERR,"xxE",http_conn,http_res,err);
    err = RHP_STATUS_ABORT_HTTP_CONN;
    goto error;
  }

  err = rhp_timer_add(&(http_bus_sess->session_timer),(time_t)rhp_gcfg_http_bus_idle_timeout); // (**)
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }
  rhp_http_bus_sess_hold(http_bus_sess); // (**)

  if( new_sess ){

    _rhp_atomic_set(&(http_bus_sess->is_active),1);
    _rhp_http_bus_sess_put(http_bus_sess);

  }else{

    RHP_UNLOCK(&(http_bus_sess->lock));
  }

  rhp_http_res_free(http_res);

  rhp_http_bus_sess_unhold(http_bus_sess); // (*)

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_OPEN_RTRN,"xx",http_conn,http_bus_sess);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
  if( !new_sess && http_bus_sess ){
    RHP_UNLOCK(&(http_bus_sess->lock));
  }
  if( http_res ){
    rhp_http_res_free(http_res);
  }
  if( http_bus_sess ){
    rhp_http_bus_sess_unhold(http_bus_sess);
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_OPEN_ERR,"xE",http_conn,err);
  return err;
}

static int _rhp_http_bus_close(rhp_http_conn* http_conn)
{
  int err = -EINVAL;
  rhp_http_request* http_req = http_conn->http_req;
  rhp_http_bus_session* http_bus_sess = NULL;
  rhp_http_response* http_res = NULL;
  rhp_http_conn* http_conn_read = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_CLOSE,"x",http_conn);

  if( http_req == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_CLOSE_NO_REQ_ERR,"x",http_conn);
    return -ENOENT;
  }

  http_bus_sess = _rhp_http_bus_sess_get(http_req->session_id,http_conn->user_name); // (**)
  if( http_bus_sess == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_CLOSE_NO_SESS_ERR,"xqs",http_conn,http_req->session_id,http_conn->user_name);
    return -ENOENT;
  }

  RHP_LOCK(&(http_bus_sess->lock));

  if( _rhp_atomic_read(&(http_bus_sess->is_active)) == 0 ){
    err = -ENOENT;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_CLOSE_NOT_ACTIVE,"xx",http_conn,http_bus_sess);
    goto error;
  }

  if( http_bus_sess->user_realm_id != http_conn->user_realm_id ){
    err = -EPERM;
    goto error;
  }

  if( rhp_ip_addr_cmp_ip_only(&(http_bus_sess->my_addr),&(http_conn->my_addr)) ){
    err = RHP_STATUS_HTTP_URI_GONE;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_CLOSE_MYADDR_NOT_MATCHED,"xx",http_conn,http_bus_sess);
    goto error;
  }

  if( rhp_ip_addr_cmp_ip_only(&(http_bus_sess->dst_addr),&(http_conn->dst_addr)) ){
    err = RHP_STATUS_HTTP_URI_GONE;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_CLOSE_DSTADDR_NOT_MATCHED,"xx",http_conn,http_bus_sess);
    goto error;
  }


  _rhp_atomic_set(&(http_bus_sess->is_active),0);

  {
		http_res = rhp_http_res_alloc("200","OK");

		if( http_res ){

			err = rhp_http_tx_server_response(http_conn,http_res,1);
			if( err ){
				RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_CLOSE_TX_RESP_ERR,"xxE",http_conn,http_bus_sess,err);
				err = RHP_STATUS_ABORT_HTTP_CONN;
			}

		}else{
			RHP_BUG("");
			err = -ENOMEM;
		}
  }


  if( !rhp_timer_delete(&(http_bus_sess->session_timer)) ){
    rhp_http_bus_sess_unhold(http_bus_sess);
  }


  http_conn_read = http_bus_sess->http_conn_read;
  if( http_conn_read ){
    rhp_http_conn_hold(http_conn_read);
    http_bus_sess->http_conn_read = NULL;
  }

  RHP_UNLOCK(&(http_bus_sess->lock));

  _rhp_http_bus_sess_delete(http_bus_sess);


  if( http_conn_read ){

    RHP_LOCK(&(http_conn_read->lock));

    rhp_http_server_close_conn(http_conn_read,0); // (**7**)

    RHP_UNLOCK(&(http_conn_read->lock));

    rhp_http_conn_unhold(http_conn_read); // (**7**)
  }

  rhp_http_res_free(http_res);

  rhp_http_bus_sess_unhold(http_bus_sess); // (**)

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_CLOSE_RTRN,"xx",http_conn,http_bus_sess);
  return RHP_STATUS_CLOSE_HTTP_CONN;;

error:
  if( http_res ){
    rhp_http_res_free(http_res);
  }
  if( http_bus_sess ){
    RHP_UNLOCK(&(http_bus_sess->lock));
    rhp_http_bus_sess_unhold(http_bus_sess); // (**)
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_CLOSE_ERR,"xxE",http_conn,http_bus_sess,err);
  return err;
}

static int _rhp_http_bus_read(rhp_http_conn* http_conn)
{
  int err = -EINVAL;
  rhp_http_request* http_req = http_conn->http_req;
  rhp_http_bus_session* http_bus_sess = NULL;
  rhp_http_response* http_res = NULL;
  rhp_http_header* req_header = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_READ,"x",http_conn);

  if( http_req == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_READ_NO_REQ_ERR,"x",http_conn);
    return -ENOENT;
  }

  req_header = http_req->get_header(http_req,"Accept");
  if( req_header && req_header->value ){

  	if( (strcasestr(req_header->value,"text/xml") == NULL) &&
  			(strcasestr(req_header->value,"text/*") == NULL) &&
  			(strcasestr(req_header->value,"*/*") == NULL) ){
  		RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_READ_INVALID_ACCEPT_HEADER_VALUE,"xxxs",http_conn,http_req,req_header,req_header->value);
      return -ENOENT;
  	}

  }else{
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_READ_NO_ACCEPT_HEADER,"xx",http_conn,http_req);
  }

  req_header = http_req->get_header(http_req,"Accept-Charset");
  if( req_header && req_header->value ){

  	if( (strcasestr(req_header->value,"utf-8") == NULL) &&
  			(strcasestr(req_header->value,"*") == NULL) ){
  		RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_READ_INVALID_ACCEPT_CHARSET_HEADER_VALUE,"xxxs",http_conn,http_req,req_header,req_header->value);
      return -ENOENT;
  	}

  }else{
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_READ_NO_ACCEPT_CHARSET_HEADER,"xx",http_conn,http_req);
  }

  http_bus_sess = _rhp_http_bus_sess_get(http_req->session_id,http_conn->user_name); // (**)
  if( http_bus_sess == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_READ_NO_SESS_ERR,"xqs",http_conn,http_req->session_id,http_conn->user_name);
    return RHP_STATUS_HTTP_URI_GONE;
  }

  RHP_LOCK(&(http_bus_sess->lock));

  if( _rhp_atomic_read(&(http_bus_sess->is_active)) == 0 ){
    err = RHP_STATUS_HTTP_URI_GONE;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_READ_NOT_ACTIVE,"xx",http_conn,http_bus_sess);
    goto error;
  }

  if( http_bus_sess->user_realm_id != http_conn->user_realm_id ){
    err = -EPERM;
    goto error;
  }

  if( rhp_ip_addr_cmp_ip_only(&(http_bus_sess->my_addr),&(http_conn->my_addr)) ){
    err = RHP_STATUS_HTTP_URI_GONE;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_READ_MYADDR_NOT_MATCHED,"xx",http_conn,http_bus_sess);
    goto error;
  }

  if( rhp_ip_addr_cmp_ip_only(&(http_bus_sess->dst_addr),&(http_conn->dst_addr)) ){
    err = RHP_STATUS_HTTP_URI_GONE;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_READ_DSTADDR_NOT_MATCHED,"xx",http_conn,http_bus_sess);
    goto error;
  }

  if( http_bus_sess->http_conn_read == http_conn ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_READ_ONLY_ONE_CONN_ALLOWED,"xx",http_conn,http_bus_sess);
    goto error;
  }

  if( http_bus_sess->http_conn_read ){

    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_READ_CLOSE_OLD_HTTP_CONN,"xxx",http_conn,http_bus_sess,http_bus_sess->http_conn_read);

    rhp_http_conn_unhold(http_bus_sess->http_conn_read); // (**_rhp_http_bus_read**)

  	rhp_http_server_close_conn(http_bus_sess->http_conn_read,1);
    rhp_http_conn_unhold(http_bus_sess->http_conn_read); // http_conn->sk_epoll_ctx.params[0]

    http_bus_sess->http_conn_read = NULL;
  }

  if( rhp_timer_delete(&(http_bus_sess->session_timer)) ){
    err = -ENOENT;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_READ_DEL_TIMER_FAILED,"xx",http_conn,http_bus_sess);
    goto error;
  }
  rhp_http_bus_sess_unhold(http_bus_sess);

  if( http_bus_sess->bus_read_rec_num ){

    http_res = rhp_http_res_alloc("200","OK");
    if( http_res == NULL ){
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }

    err = http_res->put_header(http_res,"Content-Type","text/xml; charset=utf-8");
    if( err ){
      RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_READ_PUT_HEADER_FAILED,"xxxE",http_conn,http_bus_sess,http_res,err);
      goto error;
    }

    err = _rhp_http_bus_xml_writer_end(http_bus_sess,http_bus_sess->bus_read_xml_writer,
    		http_bus_sess->bus_read_xml_writer_buf,http_bus_sess->bus_read_xml_writer_len,
    		&http_res->mesg_body,&http_res->mesg_body_len);

    http_bus_sess->bus_read_xml_writer = NULL;

    if( err ){
      RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_READ_WRITER_END_ERR,"xxE",http_conn,http_bus_sess,err);
      err = RHP_STATUS_ABORT_HTTP_CONN;
      goto error;
    }

    err = rhp_http_tx_server_response(http_conn,http_res,1);
    if( err ){
      RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_READ_TX_RESP_ERR,"xxE",http_conn,http_bus_sess,err);
      err = RHP_STATUS_ABORT_HTTP_CONN;
      goto error;
    }

    xmlFreeTextWriter(http_bus_sess->bus_read_xml_writer);
    xmlBufferFree(http_bus_sess->bus_read_xml_writer_buf);

    http_bus_sess->bus_read_xml_writer_len = 0;
    http_bus_sess->bus_read_xml_writer = NULL;
    http_bus_sess->bus_read_xml_writer_buf = NULL;
    http_bus_sess->bus_read_rec_num = 0;

  }else{

    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_READ_NO_RECORD,"xx",http_conn,http_bus_sess);

    http_bus_sess->http_conn_read = http_conn;
    rhp_http_conn_hold(http_conn); // (**_rhp_http_bus_read**)

    rhp_timer_reset(&(http_bus_sess->session_timer));

    err = rhp_timer_add(&(http_bus_sess->session_timer),(time_t)rhp_gcfg_http_bus_read_timeout);
    if( err ){
      RHP_BUG("%d",err);
      goto error;
    }
    rhp_http_bus_sess_hold(http_bus_sess);

    err = RHP_STATUS_HTTP_REQ_PENDING;

    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_READ_NO_RECORD_GO_PEND,"xx",http_conn,http_bus_sess);
    goto pending;
  }

  rhp_timer_reset(&(http_bus_sess->session_timer));

  err = rhp_timer_add(&(http_bus_sess->session_timer),(time_t)rhp_gcfg_http_bus_idle_timeout);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }
  rhp_http_bus_sess_hold(http_bus_sess);

  RHP_UNLOCK(&(http_bus_sess->lock));

  if( http_res ){
    rhp_http_res_free(http_res);
  }

  rhp_http_bus_sess_unhold(http_bus_sess); // (**)

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_READ_RTRN,"xx",http_conn,http_bus_sess);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
  if( http_res ){
    rhp_http_res_free(http_res);
  }

pending:
  if( http_bus_sess ){
    RHP_UNLOCK(&(http_bus_sess->lock));
    rhp_http_bus_sess_unhold(http_bus_sess); // (**)
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_READ_ERR,"xxE",http_conn,http_bus_sess,err);
  return err;
}

// NOT thread safe! Call this api when process starts only.
int rhp_http_bus_register_request_handler(char* service_name,
	int (*handler)(rhp_http_conn* http_conn,rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx),void* ctx,
	int nobody_allowed)
{
  rhp_http_bus_req_handler* handler_entry
  = (rhp_http_bus_req_handler*)_rhp_malloc(sizeof(rhp_http_bus_req_handler));

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_ADD_REQUEST_HANDLER,"sYxd",service_name,handler,ctx,nobody_allowed);

  if( handler_entry == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }
  memset(handler_entry,0,sizeof(rhp_http_bus_req_handler));

  handler_entry->tag[0] = '#';
  handler_entry->tag[1] = 'H';
  handler_entry->tag[2] = 'B';
  handler_entry->tag[3] = 'H';

  handler_entry->service_name[0] = '\0';
  strcpy(handler_entry->service_name,service_name);

  handler_entry->handler = handler;
  handler_entry->ctx = ctx;
  handler_entry->nobody_allowed = nobody_allowed;

  if( _rhp_http_bus_req_handlers == NULL ){
	_rhp_http_bus_req_handlers = handler_entry;
  }else{
    _rhp_http_bus_req_handlers_tail->next = handler_entry;
  }
  _rhp_http_bus_req_handlers_tail = handler_entry;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_ADD_REQUEST_HANDLER_RTRN,"sYx",service_name,handler,ctx);
  return 0;
}


static int _rhp_http_bus_call_request_handler(rhp_http_conn* http_conn,rhp_http_bus_session* http_bus_sess,
		rhp_http_request* http_req)
{
  int err = -ENOENT;
  rhp_http_bus_req_handler* handler_entry;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_CALL_REQUEST_HANDLER,"xxx",http_conn,http_bus_sess,http_req);

  handler_entry = _rhp_http_bus_req_handlers;

  while( handler_entry ){

  	if( !handler_entry->nobody_allowed && http_conn->is_nobody ){
  		goto next;
  	}

  	if( !strcmp(handler_entry->service_name,http_req->service_name) ){

  		err = handler_entry->handler(http_conn,http_bus_sess,http_req,handler_entry->ctx);

  		break;
  	}

next:
  	handler_entry = handler_entry->next;
  }

  if( handler_entry ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_CALL_REQUEST_HANDLER_RTRN,"xxxxYxE",http_conn,http_bus_sess,http_req,handler_entry,handler_entry->handler,handler_entry->ctx,err);
  }else{
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_CALL_REQUEST_HANDLER_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  }
  return err;
}


static int _rhp_http_bus_ipc_cfg_callback(rhp_http_conn* http_conn,int data_len,u8* data,void* ipc_cb_ctx)
{
  int err = -EINVAL;
  rhp_http_request* http_req = http_conn->http_req;
  rhp_http_bus_session* http_bus_sess = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_IPC_CFG_CALLBACK,"x",http_conn);

  if( http_req == NULL || http_req->mesg_body_len < 1 ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_IPC_CFG_CALLBACK_NO_REQ_OR_NO_BODY_ERR,"xx",http_conn,http_req);
    return -ENOENT;
  }

  http_bus_sess = _rhp_http_bus_sess_get(http_req->session_id,http_conn->user_name); // (**)
  if( http_bus_sess == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_IPC_CFG_CALLBACK_NO_SESS_ERR,"xqs",http_conn,http_req->session_id,http_conn->user_name);
    return -ENOENT;
  }

  RHP_LOCK(&(http_bus_sess->lock));

  if( _rhp_atomic_read(&(http_bus_sess->is_active)) == 0 ){
    err = -ENOENT;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_IPC_CFG_CALLBACK_NOT_ACTIVE,"xx",http_conn,http_bus_sess);
    goto error;
  }

  if( http_bus_sess->ipc_bus_callback ){

    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_IPC_CFG_CALLBACK_CALL_HANDER,"xxYx",http_conn,http_bus_sess,http_bus_sess->ipc_bus_callback,http_bus_sess->ipc_bus_cb_ctx);

  	err = http_bus_sess->ipc_bus_callback(http_req->xml_doc,http_req->xml_root_node,
  			http_conn,http_bus_sess,http_req,data_len,data,http_bus_sess->ipc_bus_cb_ctx);

  	http_bus_sess->ipc_bus_callback = NULL;
  	http_bus_sess->ipc_bus_cb_ctx = NULL;

  }else{
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  if( err == RHP_STATUS_HTTP_REQ_PENDING ){

    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_IPC_CFG_CALLBACK_GO_PEND,"xx",http_conn,http_bus_sess);
    goto pending;

  }else if( err ){

  	RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_IPC_CFG_CALLBACK_CALL_REQ_HANDLER_ERR,"xxE",http_conn,http_bus_sess,err);
    goto error;
  }

  RHP_UNLOCK(&(http_bus_sess->lock));
  rhp_http_bus_sess_unhold(http_bus_sess); // (**)

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_IPC_CFG_CALLBACK_RTRN,"xx",http_conn,http_bus_sess);
  return RHP_STATUS_SUCCESS;

error:
  if( http_bus_sess ){
    RHP_UNLOCK(&(http_bus_sess->lock));
    rhp_http_bus_sess_unhold(http_bus_sess); // (**)
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_IPC_CFG_CALLBACK_ERR_1,"xxE",http_conn,http_bus_sess,err);
  return err;

pending:
  RHP_UNLOCK(&(http_bus_sess->lock));
  rhp_http_bus_sess_unhold(http_bus_sess); // (**)

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_IPC_CFG_CALLBACK_PENDING,"xxE",http_conn,http_bus_sess,err);
  return err;
}

extern int rhp_ui_http_cfg_bkup_save_bh(rhp_http_bus_session* http_bus_sess,rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt);
extern int rhp_ui_http_upload_cert_file_bh(rhp_http_bus_session* http_bus_sess,rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt);

int rhp_http_bus_cfg_async_ipc_handle(u64 session_id,rhp_ipcmsg_syspxy_cfg_rep* cfg_rep,char* user_name,int data_len,u8* data)
{
  int err = -EINVAL;
  rhp_http_bus_session* http_bus_sess = NULL;
  rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt = (rhp_ipcmsg_syspxy_cfg_sub*)data;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_CFG_ASYNC_IPC_HANDLE,"qspdx",session_id,user_name,cfg_rep->len,cfg_rep,data_len,data);

  if( data_len < (int)sizeof(rhp_ipcmsg_syspxy_cfg_sub) && (int)cfg_sub_dt->len != data_len ){
		err = -EINVAL;
		RHP_BUG("%d, %d, %d",cfg_sub_dt->len,data_len,sizeof(rhp_ipcmsg_syspxy_cfg_sub));
		goto error;
	}

  http_bus_sess = _rhp_http_bus_sess_get(session_id,user_name); // (**)
  if( http_bus_sess == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_CFG_ASYNC_IPC_HANDLE_NO_SESS_ERR,"qs",session_id,user_name);
    return -ENOENT;
  }


  RHP_LOCK(&(http_bus_sess->lock));

  if( _rhp_atomic_read(&(http_bus_sess->is_active)) == 0 ){
    err = -ENOENT;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_CFG_ASYNC_IPC_HANDLE_NOT_ACTIVE,"qsx",session_id,user_name,http_bus_sess);
    goto error;
  }


  switch( cfg_sub_dt->cfg_type ){

  case RHP_IPC_SYSPXY_CFG_BKUP_SAVE:

  	err = rhp_ui_http_cfg_bkup_save_bh(http_bus_sess,cfg_sub_dt);
  	if( err ){
  		goto error;
  	}
  	break;


    case RHP_IPC_SYSPXY_CFG_UPLOAD_CERT_FILE:

    	err = rhp_ui_http_upload_cert_file_bh(http_bus_sess,cfg_sub_dt);
    	if( err ){
    		goto error;
    	}
    	break;

  default:
  	RHP_BUG("%d",cfg_sub_dt->cfg_type);
  	err = -EINVAL;
  	goto error;
  }


  RHP_UNLOCK(&(http_bus_sess->lock));
  rhp_http_bus_sess_unhold(http_bus_sess); // (**)

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_CFG_ASYNC_IPC_HANDLE_RTRN,"qsx",session_id,user_name,http_bus_sess);
  return RHP_STATUS_SUCCESS;

error:
  if( http_bus_sess ){
    RHP_UNLOCK(&(http_bus_sess->lock));
    rhp_http_bus_sess_unhold(http_bus_sess); // (**)
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_CFG_ASYNC_IPC_HANDLE_ERR,"qsxE",session_id,user_name,http_bus_sess,err);
  return err;
}


int rhp_http_bus_ipc_cfg_request(rhp_http_conn* http_conn,rhp_http_bus_session* http_bus_sess,
		int data_len,u8* data,
		int (*ipc_bus_callback)(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,rhp_http_bus_session* http_bus_sess,
				rhp_http_request* http_req,int data_len,u8* data,void* ipc_bus_cb_ctx),void* ipc_bus_cb_ctx)
{
	int err = -EINVAL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_IPC_CFG_REQUEST,"xxpYx",http_conn,http_bus_sess,data_len,data,ipc_bus_callback,ipc_bus_cb_ctx);

	http_bus_sess->ipc_bus_cb_ctx = ipc_bus_cb_ctx;
	http_bus_sess->ipc_bus_callback = ipc_bus_callback;

	err = rhp_http_ipc_cfg_request(http_conn,data_len,data,_rhp_http_bus_ipc_cfg_callback,NULL);
	if( err ){
		RHP_BUG("");
		goto error;
	}

  err = rhp_http_server_conn_timer_restart(http_conn);
  if( err ){
	  RHP_BUG("%d",err);
	  goto error;
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_IPC_CFG_REQUEST_RTRN,"xxxYx",http_conn,http_bus_sess,data,ipc_bus_callback,ipc_bus_cb_ctx);
  return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_IPC_CFG_REQUEST_ERR,"xxxYxE",http_conn,http_bus_sess,data,ipc_bus_callback,ipc_bus_cb_ctx,err);
	return err;
}


int rhp_http_bus_ipc_cfg_request_async(rhp_http_conn* http_conn,u64 session_id,int data_len,u8* data)
{
	int err = -EINVAL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_IPC_CFG_REQUEST_ASYNC,"xqp",http_conn,session_id,data_len,data);

	err = rhp_http_ipc_cfg_request_async(http_conn,data_len,data,session_id);
	if( err ){
		RHP_BUG("");
		goto error;
	}

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_IPC_CFG_REQUEST_ASYNC_RTRN,"xqx",http_conn,session_id,data);
  return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_IPC_CFG_REQUEST_ASYNC_ERR,"xqxE",http_conn,session_id,data,err);
	return err;
}

static int _rhp_http_bus_write(rhp_http_conn* http_conn)
{
  int err = -EINVAL;
  rhp_http_request* http_req = http_conn->http_req;
  rhp_http_bus_session* http_bus_sess = NULL;
  rhp_http_header* req_header = NULL;
  xmlDocPtr doc = NULL;
  xmlNodePtr root_node = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE,"x",http_conn);

  if( http_req == NULL || http_req->mesg_body_len < 1 ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_NO_REQ_OR_NO_BODY_ERR,"xx",http_conn,http_req);
    return -ENOENT;
  }

  req_header = http_req->get_header(http_req,"Accept");
  if( req_header && req_header->value ){

  	if( (strcasestr(req_header->value,"text/xml") == NULL) &&
  			(strcasestr(req_header->value,"text/*") == NULL) &&
  			(strcasestr(req_header->value,"*/*") == NULL)){

  		RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_INVALID_ACCEPT_HEADER_VALUE,"xxxs",http_conn,http_req,req_header,req_header->value);
      return -ENOENT;
  	}

  }else{
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_NO_ACCEPT_HEADER,"xx",http_conn,http_req);
  }

  req_header = http_req->get_header(http_req,"Accept-Charset");
  if( req_header && req_header->value ){

  	if( (strcasestr(req_header->value,"utf-8") == NULL) &&
  			(strcasestr(req_header->value,"*") == NULL) ){
  		RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_INVALID_ACCEPT_CHARSET_HEADER_VALUE,"xxxs",http_conn,http_req,req_header,req_header->value);
      return -ENOENT;
  	}

  }else{
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_NO_ACCEPT_CHARSET_HEADER,"xx",http_conn,http_req);
  }

  req_header = http_req->get_header(http_req,"Content-Type");
  if( req_header == NULL || req_header->value == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_NO_CONTENT_TYPE_HEADER_ERR,"xx",http_conn,http_req);
    return -ENOENT;
  }

  if( (strcasestr(req_header->value,"text/xml") == NULL) ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_INVALID_CONTENT_TYPE_HEADER_VALUE_1,"xxxs",http_conn,http_req,req_header,req_header->value);
    return -ENOENT;
  }

  if( (strcasestr(req_header->value,"charset=utf-8") == NULL) ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_INVALID_CONTENT_TYPE_HEADER_VALUE_2,"xxxs",http_conn,http_req,req_header,req_header->value);
    return -ENOENT;
  }

  http_bus_sess = _rhp_http_bus_sess_get(http_req->session_id,http_conn->user_name); // (**)
  if( http_bus_sess == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_NO_SESS_ERR,"xqs",http_conn,http_req->session_id,http_conn->user_name);
    return RHP_STATUS_HTTP_URI_GONE;
  }

  RHP_LOCK(&(http_bus_sess->lock));

  if( _rhp_atomic_read(&(http_bus_sess->is_active)) == 0 ){
    err = RHP_STATUS_HTTP_URI_GONE;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_NOT_ACTIVE,"xx",http_conn,http_bus_sess);
    goto error;
  }

  if( http_bus_sess->user_realm_id != http_conn->user_realm_id ){
    err = -EPERM;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_INVALID_RLM_ID,"xxuu",http_conn,http_bus_sess,http_bus_sess->user_realm_id,http_conn->user_realm_id);
    goto error;
  }

  if( http_bus_sess->ipc_bus_callback ){
  	err = -EBUSY;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_IPC_PENDING,"xxYx",http_conn,http_bus_sess,http_bus_sess->ipc_bus_callback,http_bus_sess->ipc_bus_cb_ctx);
  	goto error;
  }

  if( rhp_ip_addr_cmp_ip_only(&(http_bus_sess->my_addr),&(http_conn->my_addr)) ){
    err = RHP_STATUS_HTTP_URI_GONE;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_MYADDR_NOT_MATCHED,"xx",http_conn,http_bus_sess);
    goto error;
  }

  if( rhp_ip_addr_cmp_ip_only(&(http_bus_sess->dst_addr),&(http_conn->dst_addr)) ){
    err = RHP_STATUS_HTTP_URI_GONE;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_DSTADDR_NOT_MATCHED,"xx",http_conn,http_bus_sess);
    goto error;
  }

  doc = xmlParseMemory(http_req->mesg_body,http_req->mesg_body_len);
  if( doc == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_INVALID_MESG_1,"xx",http_conn,http_bus_sess);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  http_req->xml_doc = doc;

  root_node = xmlDocGetRootElement(doc);
  if( root_node == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_INVALID_MESG_2,"xx",http_conn,http_bus_sess);
    goto error;
  }

  http_req->xml_root_node = root_node;

  if( xmlStrcmp(root_node->name,(const xmlChar*)"rhp_http_bus_request") ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_INVALID_MESG_3,"xx",http_conn,http_bus_sess);
    goto error;
  }

  http_req->clt_version = (char*)rhp_xml_get_prop(root_node,(const xmlChar*)"version");
  if( http_req->clt_version == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_INVALID_MESG_4,"xx",http_conn,http_bus_sess);
    goto error;
  }

  if( strcasecmp(http_req->clt_version,RHP_HTTP_BUS_VERSION) ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_INVALID_MESG_5,"xx",http_conn,http_bus_sess);
    goto error;
  }

  http_req->service_name = (char*)rhp_xml_get_prop(root_node,(const xmlChar*)"service");
  if( http_req->service_name == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_INVALID_MESG_6,"xx",http_conn,http_bus_sess);
    goto error;
  }

  if( (strlen(http_req->service_name) + 1) > RHP_HTTP_BUS_SERVICE_NAME_MAX ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_INVALID_MESG_7,"xx",http_conn,http_bus_sess);
    goto error;
  }

  err = _rhp_http_bus_call_request_handler(http_conn,http_bus_sess,http_req);

  if( err == RHP_STATUS_HTTP_REQ_PENDING ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_GO_PEND,"xx",http_conn,http_bus_sess);
    goto pending;
  }else if( err ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_CALL_REQ_HANDLER_ERR,"xxE",http_conn,http_bus_sess,err);
    goto error;
  }

  RHP_UNLOCK(&(http_bus_sess->lock));
  rhp_http_bus_sess_unhold(http_bus_sess); // (**)

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_RTRN,"xx",http_conn,http_bus_sess);
  return RHP_STATUS_SUCCESS;

error:
  if( http_bus_sess ){
    RHP_UNLOCK(&(http_bus_sess->lock));
    rhp_http_bus_sess_unhold(http_bus_sess); // (**)
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_ERR_1,"xxE",http_conn,http_bus_sess,err);
  return err;

pending:
  RHP_UNLOCK(&(http_bus_sess->lock));
  rhp_http_bus_sess_unhold(http_bus_sess); // (**)

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_WRITE_PENDING,"xxE",http_conn,http_bus_sess,err);
  return err;
}

static int _rhp_http_bus_keepalive(rhp_http_conn* http_conn)
{
  int err = -EINVAL;
  rhp_http_request* http_req = http_conn->http_req;
  rhp_http_bus_session* http_bus_sess = NULL;
  rhp_http_response* http_res = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_KEEPALIVE,"x",http_conn);

  http_bus_sess = _rhp_http_bus_sess_get(http_req->session_id,http_conn->user_name); // (**)
  if( http_bus_sess == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_KEEPALIVE_NO_SESS_ERR,"xqs",http_conn,http_req->session_id,http_conn->user_name);
    return -ENOENT;
  }

  RHP_LOCK(&(http_bus_sess->lock));

  if( _rhp_atomic_read(&(http_bus_sess->is_active)) == 0 ){
    err = -ENOENT;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_KEEPALIVE_NOT_ACTIVE,"xx",http_conn,http_bus_sess);
    goto error;
  }

  if( http_bus_sess->user_realm_id != http_conn->user_realm_id ){
    err = -EPERM;
    goto error;
  }

  if(rhp_ip_addr_cmp_ip_only(&(http_bus_sess->my_addr),&(http_conn->my_addr)) ){
    err = RHP_STATUS_HTTP_URI_GONE;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_KEEPALIVE_MYADDR_NOT_MATCHED,"xx",http_conn,http_bus_sess);
    goto error;
  }

  if(rhp_ip_addr_cmp_ip_only(&(http_bus_sess->dst_addr),&(http_conn->dst_addr)) ){
    err = RHP_STATUS_HTTP_URI_GONE;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_KEEPALIVE_DSTADDR_NOT_MATCHED,"xx",http_conn,http_bus_sess);
    goto error;
  }

  http_res = rhp_http_res_alloc("200","OK");
  if( http_res == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  err = rhp_http_tx_server_response(http_conn,http_res,1);
  if( err ){
    err = RHP_STATUS_ABORT_HTTP_CONN;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_KEEPALIVE_TX_RESP_ERR,"xxE",http_conn,http_bus_sess,err);
    goto error;
  }

  RHP_UNLOCK(&(http_bus_sess->lock));

  rhp_http_res_free(http_res);

  rhp_http_bus_sess_unhold(http_bus_sess); // (**)

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_KEEPALIVE_RTRN,"xx",http_conn,http_bus_sess);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
  if( http_res ){
    rhp_http_res_free(http_res);
  }
  if( http_bus_sess ){
    RHP_UNLOCK(&(http_bus_sess->lock));
    rhp_http_bus_sess_unhold(http_bus_sess); // (**)
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_KEEPALIVE_ERR,"xxE",http_conn,http_bus_sess,err);
  return err;
}

// http_bus_sess->lock must be acquired.
int rhp_http_bus_send_async_unlocked(void* http_bus_sess_d,unsigned long rlm_id,int critical,int nobody_allowed,
        int (*serialize)(void* http_bus_sess,void* ctx,void* writer,int idx),void* ctx)
{
  int err = -EINVAL;
  int n = 0;
  rhp_http_bus_session* http_bus_sess = (rhp_http_bus_session*)http_bus_sess_d;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_TX_RESPONSE_ASYNC_UNLOCKED,"xuddYxdd",http_bus_sess,rlm_id,critical,nobody_allowed,serialize,ctx,http_bus_sess->bus_read_rec_num,http_bus_sess->bus_read_xml_writer_len);

  if( serialize == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_TX_RESPONSE_ASYNC_UNLOCKED_NO_SERIALIZE_METHOD,"xYx",http_bus_sess,serialize,ctx);
    return 0;
  }

  if( !_rhp_atomic_read(&(http_bus_sess->is_active)) ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_TX_RESPONSE_ASYNC_UNLOCKED_SESS_NOT_ACTIVE,"x",http_bus_sess);
    return 0;
  }


  if( http_bus_sess->user_realm_id != 0 &&
  		http_bus_sess->user_realm_id != rlm_id ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_TX_RESPONSE_ASYNC_UNLOCKED_SESS_NOT_PERMITTED,"xuu",http_bus_sess,http_bus_sess->user_realm_id,rlm_id);
  	return 0;
  }

  if( http_bus_sess->is_nobody && !nobody_allowed ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_TX_RESPONSE_ASYNC_UNLOCKED_SESS_NOBODY_USER_NOT_PERMITTED,"xuu",http_bus_sess,http_bus_sess->user_realm_id,rlm_id);
  	return 0;
  }

  if( !critical ){

    if( http_bus_sess->bus_read_xml_writer_len > rhp_gcfg_http_bus_max_async_non_critical_mesg_bytes ){
      RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_TX_RESPONSE_ASYNC_UNLOCKED_SESS_NOT_CRITICAL_SO_IGNORED,"xdd",http_bus_sess,http_bus_sess->bus_read_xml_writer_len,rhp_gcfg_http_bus_max_async_non_critical_mesg_bytes);
    	return 0;
    }
  }


  if( http_bus_sess->bus_read_xml_writer_len > rhp_gcfg_http_bus_max_async_mesg_bytes ){
    err = RHP_STATUS_HTTP_BUS_MESG_TOO_BIG;
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_TX_RESPONSE_ASYNC_UNLOCKED_MESG_TOO_BIG,"xdd",http_bus_sess,http_bus_sess->bus_read_xml_writer_len,rhp_gcfg_http_bus_max_async_mesg_bytes);
    goto error;
  }


  if( http_bus_sess->bus_read_xml_writer == NULL ){

    err = _rhp_http_bus_xml_writer_start(http_bus_sess,&(http_bus_sess->bus_read_xml_writer),
    		&(http_bus_sess->bus_read_xml_writer_buf),&(http_bus_sess->bus_read_xml_writer_len));

    if( err ){
      RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_TX_RESPONSE_ASYNC_UNLOCKED_WRITER_START_ERR,"xE",http_bus_sess,err);
      goto error;
    }

  }else{
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_TX_RESPONSE_ASYNC_UNLOCKED_WRITER_EXISTS,"xx",http_bus_sess,http_bus_sess->bus_read_xml_writer);
  }

	n = serialize(http_bus_sess,ctx,http_bus_sess->bus_read_xml_writer,http_bus_sess->bus_read_rec_num);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}


  http_bus_sess->bus_read_xml_writer_len += n;
  http_bus_sess->bus_read_rec_num++;

  if( http_bus_sess->http_conn_read ){

    rhp_timer_update(&(http_bus_sess->session_timer),0);

  }else{

  	// Wait for next bus_read request from client...
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_TX_RESPONSE_ASYNC_UNLOCKED_NO_HTTP_CONN_READ,"x",http_bus_sess);
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_TX_RESPONSE_ASYNC_UNLOCKED_RTRN,"xxdd",http_bus_sess,http_bus_sess->bus_read_xml_writer,http_bus_sess->bus_read_rec_num,http_bus_sess->bus_read_xml_writer_len);
  return 0;

error:
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_TX_RESPONSE_ASYNC_UNLOCKED_ERR,"xE",http_bus_sess,err);
  return err;
}

//
// [CAUTION]
//
//  Don't call with http_bus_sess->lock locked. For instance don't call in the same context with _rhp_http_bus_handler().
//
int rhp_http_bus_send_async(u64 session_id,char* user_name,unsigned long rlm_id,int critical,int nobody_allowed,
        int (*serialize)(void* http_bus_sess,void* ctx,void* writer,int idx),void* ctx)
{
  int err;
  rhp_http_bus_session* http_bus_sess = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_TX_RESPONSE_ASYNC,"qsuddYx",session_id,user_name,rlm_id,critical,nobody_allowed,serialize,ctx);

  http_bus_sess = _rhp_http_bus_sess_get(session_id,user_name); // (*)

  if( http_bus_sess == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_TX_RESPONSE_ASYNC_SESS_NOT_ACTIVE,"x",http_bus_sess);
    return 0;
  }

  RHP_LOCK(&(http_bus_sess->lock));

  err = rhp_http_bus_send_async_unlocked(http_bus_sess,rlm_id,critical,nobody_allowed,serialize,ctx);

  RHP_UNLOCK(&(http_bus_sess->lock));

  rhp_http_bus_sess_unhold(http_bus_sess); // (*)

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_TX_RESPONSE_ASYNC_RTRN,"qsudYxxE",session_id,user_name,rlm_id,critical,serialize,ctx,http_bus_sess,err);
  return err;
}


struct _rhp_http_bus_tx_async_ctx {

	u8 tag[4]; // '#HAY'
	struct _rhp_http_bus_tx_async_ctx* next;

	unsigned long rlm_id;
	int critical;
	int nobody_allowed;

	int (*serialize)(void* http_bus_sess,void* ctx,void* writer,int idx);
  void (*cleanup)(void* ctx);
  void* ctx;
};
typedef struct _rhp_http_bus_tx_async_ctx		rhp_http_bus_tx_async_ctx;

rhp_http_bus_tx_async_ctx* _rhp_http_bus_alloc_tx_async_ctx(
		unsigned long rlm_id,int critical,int nobody_allowed,
		int (*serialize)(void* http_bus_sess,void* ctx,void* writer,int idx),
		void (*cleanup)(void* ctx),void* ctx)
{
	rhp_http_bus_tx_async_ctx* tx_ctx
	= (rhp_http_bus_tx_async_ctx*)_rhp_malloc(sizeof(rhp_http_bus_tx_async_ctx));

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_ALLOC_TX_ASYNC_CTX,"udYYx",rlm_id,critical,serialize,cleanup,ctx);

	if( tx_ctx == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(tx_ctx,0,sizeof(rhp_http_bus_tx_async_ctx));

	tx_ctx->tag[0] = '#';
	tx_ctx->tag[1] = 'H';
	tx_ctx->tag[2] = 'A';
	tx_ctx->tag[3] = 'Y';

	tx_ctx->rlm_id = rlm_id;
	tx_ctx->nobody_allowed = nobody_allowed;
	tx_ctx->critical = critical;
	tx_ctx->serialize = serialize;
	tx_ctx->cleanup = cleanup;
	tx_ctx->ctx = ctx;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_ALLOC_TX_ASYNC_CTX_RTRN,"xYx",tx_ctx,serialize,ctx);
	return tx_ctx;
}

void _rhp_http_bus_free_tx_async_ctx(rhp_http_bus_tx_async_ctx* tx_ctx)
{
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_FREE_TX_ASYNC_CTX,"xYx",tx_ctx,tx_ctx->serialize,tx_ctx->ctx);
	_rhp_free(tx_ctx);
}

static void _rhp_http_bus_btx_async_task(int worker_index,void *ctx)
{
  int err = -EINVAL;
  rhp_http_bus_tx_async_ctx* tx_ctx = (rhp_http_bus_tx_async_ctx*)ctx;
  rhp_http_bus_session* http_bus_sess = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_BROADCAST_ASYNC_TASK,"dx",worker_index,ctx);

  RHP_LOCK(&_rhp_http_bus_lock);

  http_bus_sess = _rhp_http_bus_sess_list;

  while( http_bus_sess ){

  	if( tx_ctx->rlm_id == RHP_HTTP_BUS_BTX_ALL_REALMS ||
  			http_bus_sess->user_realm_id == 0 ||
  			http_bus_sess->user_realm_id == tx_ctx->rlm_id ){

			RHP_LOCK(&(http_bus_sess->lock));

			err = rhp_http_bus_send_async_unlocked(http_bus_sess,
					tx_ctx->rlm_id,tx_ctx->critical,tx_ctx->nobody_allowed,tx_ctx->serialize,tx_ctx->ctx);

			if( err ){
				RHP_BUG("%d",err);
			}

			RHP_UNLOCK(&(http_bus_sess->lock));
  	}

    http_bus_sess = http_bus_sess->list_next;
  }

  RHP_UNLOCK(&_rhp_http_bus_lock);

  if( tx_ctx->cleanup ){
  	tx_ctx->cleanup(tx_ctx->ctx);
  }

	_rhp_http_bus_free_tx_async_ctx(tx_ctx);

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_BROADCAST_ASYNC_TASK_RTRN,"dx",worker_index,ctx);
  return;
}

//
// [CAUTION] serialize() callback will be executed in a different contenxt(thread) and
//           ctx object will be freed by cleanup() callback. Don't use ctx object allocated
//           in local stack.
//
int rhp_http_bus_broadcast_async(unsigned long rlm_id,int critical,int nobody_allowed,
        int (*serialize)(void* http_bus_sess,void* ctx,void* writer,int idx),
        void (*cleanup)(void* ctx),void* ctx)
{
  int err = -EINVAL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_BROADCAST_ASYNC,"uddYYxx",rlm_id,critical,nobody_allowed,serialize,cleanup,ctx,_rhp_http_bus_sess_list);

  {
		void* tx_ctx = _rhp_http_bus_alloc_tx_async_ctx(rlm_id,critical,nobody_allowed,serialize,cleanup,ctx);

		if( tx_ctx == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		err = rhp_wts_sta_invoke_task(RHP_WTS_DISP_RULE_SAME_WORKER,
				RHP_WTS_STA_TASK_NAME_HBUS_ASYNC_TX,RHP_WTS_DISP_LEVEL_HIGH_1,tx_ctx,tx_ctx);

		if( err ){
			_rhp_http_bus_free_tx_async_ctx(tx_ctx);
		  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_BROADCAST_ASYNC_INV_TASK_ERR,"uYxE",rlm_id,serialize,ctx,err);
			goto error;
		}
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_BROADCAST_ASYNC_RTRN,"udYYxx",rlm_id,critical,serialize,cleanup,ctx,_rhp_http_bus_sess_list);
  return 0;

error:
	if( cleanup ){
		cleanup(ctx);
	}
	RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_BROADCAST_ASYNC_ERR,"udYYxxE",rlm_id,critical,serialize,cleanup,ctx,_rhp_http_bus_sess_list,err);
	return err;
}

// http_conn->lock ==> http_bus_sess->lock must be acquired.
int rhp_http_bus_send_response(rhp_http_conn* http_conn,rhp_http_bus_session* http_bus_sess,
		int (*serialize)(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx),void* ctx)
{
  int err = -EINVAL;
  rhp_http_response* http_res = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_TX_RESPONSE,"xxYx",http_conn,http_bus_sess,serialize,ctx);

  if( !_rhp_atomic_read(&(http_bus_sess->is_active)) ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_TX_RESPONSE_SESS_NOT_ACTIVE,"xx",http_conn,http_bus_sess);
    return 0;
  }

  http_res = rhp_http_res_alloc("200","OK");
  if( http_res == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  err = http_res->put_header(http_res,"Content-Type","text/xml; charset=utf-8");
  if( err ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_TX_RESPONSE_PUT_HEADER_ERR,"xxE",http_conn,http_bus_sess,err);
    goto error;
  }

  err = rhp_http_bus_serialize_mesg_with_one_record(http_bus_sess,serialize,ctx,
		  &(http_res->mesg_body),&http_res->mesg_body_len);

  if( err ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_TX_RESPONSE_SERIALIZE_MESG_ERR,"xxE",http_conn,http_bus_sess,err);
    goto error;
  }

  err = rhp_http_tx_server_response(http_conn,http_res,1);
  if( err ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_TX_RESPONSE_TX_RESP_ERR,"xxE",http_conn,http_bus_sess,err);
    err = RHP_STATUS_ABORT_HTTP_CONN;
    goto error;
  }

  err = 0;

error:
  if( http_res ){
    rhp_http_res_free(http_res);
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_TX_RESPONSE_RTRN,"xxE",http_conn,http_bus_sess,err);
  return err;
}

static int _rhp_http_bus_handler(rhp_http_conn* http_conn,int authorized,void* ctx)
{
  int err = RHP_STATUS_SKIP;
  rhp_http_request* http_req = http_conn->http_req;
  size_t fixed_uri_len = 0;
  int opr = RHP_HTTP_BUS_UNKNOWN;
  char* session_id_str = NULL;
  u64 session_id = 0;
  char* endp;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_HANDLER,"xdxx",http_conn,authorized,ctx,http_req);

  if( http_req == NULL ){
  	RHP_BUG("");
  	return RHP_STATUS_SKIP;
  }

  if( http_req->method == NULL || http_req->uri == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_HANDLER_INVALID_REQ_PARMS_1,"xxxx",http_conn,http_req,http_req->method,http_req->uri);
    return RHP_STATUS_SKIP;
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_HANDLER_REQ_PARMS,"xxxx",http_conn,http_req,http_req->method,http_req->uri);

  fixed_uri_len = strlen("/protected/bus/");

  if( strlen(http_req->uri) < fixed_uri_len ||
	  strncasecmp(http_req->uri,"/protected/bus/",fixed_uri_len) ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_HANDLER_NOT_INTERESTED_URI,"xxd",http_conn,http_req,fixed_uri_len);
    return RHP_STATUS_SKIP;
  }

  if( !strcmp(http_req->method,"POST") ){

  	if( !strcasecmp(http_req->uri,"/protected/bus/open") ){

  		fixed_uri_len = strlen("/protected/bus/open");
  		opr = RHP_HTTP_BUS_OPEN;

  	}else{
      RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_HANDLER_INVALID_REQ_PARMS_3,"xx",http_conn,http_req);
  	  err = -ENOENT;
  	  goto error;
  	}

  }else if( !strcmp(http_req->method,"GET") ){

    fixed_uri_len = strlen("/protected/bus/read/");

    if( strlen((char*)http_req->uri) <= fixed_uri_len ||
	    strncasecmp((char*)http_req->uri,"/protected/bus/read/",fixed_uri_len) ){
      RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_HANDLER_INVALID_REQ_PARMS_4,"xxd",http_conn,http_req,fixed_uri_len);
  	  err = -ENOENT;
  	  goto error;
    }

    opr = RHP_HTTP_BUS_READ;

  }else if( !strcmp(http_req->method,"PUT") ){

  	if( ( strlen((char*)http_req->uri) > (fixed_uri_len = strlen("/protected/bus/write/")) ) &&
  			!strncasecmp((char*)http_req->uri,"/protected/bus/write/",fixed_uri_len) ){
      	opr = RHP_HTTP_BUS_WRITE;
  	}else if( ( strlen((char*)http_req->uri) > (fixed_uri_len = strlen("/protected/bus/keepalive/")) ) &&
  	    !strncasecmp((char*)http_req->uri,"/protected/bus/keepalive/",fixed_uri_len) ){
      opr = RHP_HTTP_BUS_KEEPALIVE;
  	}else{
     RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_HANDLER_INVALID_REQ_PARMS_5,"xx",http_conn,http_req);
  	  err = -ENOENT;
  	  goto error;
  	}

  }else if( !strcmp(http_req->method,"DELETE") ){

    fixed_uri_len = strlen("/protected/bus/close/");

    if( strlen((char*)http_req->uri) <= fixed_uri_len ||
	    strncasecmp((char*)http_req->uri,"/protected/bus/close/",fixed_uri_len) ){
      RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_HANDLER_INVALID_REQ_PARMS_6,"xxd",http_conn,http_req,fixed_uri_len);
  	  err = -ENOENT;
  	  goto error;
    }

    opr = RHP_HTTP_BUS_CLOSE;

  }else{
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_HANDLER_INVALID_REQ_PARMS_7,"xx",http_conn,http_req);
    err = -ENOENT;
    goto error;
  }

  if( opr == RHP_HTTP_BUS_UNKNOWN ){
    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_HANDLER_INVALID_REQ_PARMS_8,"xxd",http_conn,http_req,opr);
    err = -ENOENT;
    goto error;
  }

  if( opr != RHP_HTTP_BUS_OPEN ){

    session_id_str = (char*)(((u8*)http_req->uri) + fixed_uri_len);

    if( rhp_http_bus_check_session_id(session_id_str) ){
    	err = -ENOENT;
     RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_HANDLER_INVALID_REQ_PARMS_9,"xxs",http_conn,http_req,session_id_str);
     goto error;
    }

    session_id = strtoull((char*)session_id_str,&endp,0);

    if( (session_id == ULLONG_MAX && errno == ERANGE) || *endp != '\0' ){
    	err = -ENOENT;
     RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_HANDLER_INVALID_REQ_PARMS_10,"xxs",http_conn,http_req,session_id_str);
     goto error;
    }
  }

  if( !authorized ){

    err = rhp_http_auth_request(http_conn,(unsigned long)-1);
    if( err ){
      RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_HANDLER_AUTH_BASIC_ERR,"xxE",http_conn,http_req,err);
      goto error;
    }

    err = rhp_http_server_conn_timer_restart(http_conn);
    if( err ){
  	  RHP_BUG("%d",err);
  	  goto error;
    }

    err = RHP_STATUS_HTTP_REQ_PENDING;

    RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_HANDLER_GO_AUTH_PEND,"xx",http_conn,http_req);
    goto pending;
  }

  if( !http_conn->authorized || http_conn->user_name == NULL ){
    RHP_BUG("");
    err = RHP_STATUS_ABORT_HTTP_CONN;
    goto error;
  }

  http_req->session_id = session_id;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_HANDLER_OPR,"xxd",http_conn,http_req,opr);

  switch( opr ){

  case RHP_HTTP_BUS_OPEN:
  	err = _rhp_http_bus_open(http_conn);
  	break;

  case RHP_HTTP_BUS_READ:
  	err = _rhp_http_bus_read(http_conn);
  	break;

  case RHP_HTTP_BUS_WRITE:
  	err = _rhp_http_bus_write(http_conn);
  	break;

  case RHP_HTTP_BUS_CLOSE:
  	err = _rhp_http_bus_close(http_conn);
  	break;

  case RHP_HTTP_BUS_KEEPALIVE:
  	err = _rhp_http_bus_keepalive(http_conn);
  	break;

  default:
  	RHP_BUG("%d",opr);
  	err = RHP_STATUS_ABORT_HTTP_CONN;
  	goto error;
  }

  if( err == RHP_STATUS_HTTP_REQ_PENDING ){

  	RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_HANDLER_GO_PEND,"xx",http_conn,http_req);
    goto pending;

  }else if( err ){

  	RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_HANDLER_OPR_ERR,"xxE",http_conn,http_req,err);
    goto error;
  }

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_HANDLER_RTRN,"xx",http_conn,http_req);
  return RHP_STATUS_SUCCESS;

pending:
error:
  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_HANDLER_ERR,"xxE",http_conn,http_req,err);
  return err;
}


struct _rhp_http_bus_astx_task {

  unsigned char tag[4]; // "#HBT"

  rhp_mutex_t lock;

	int tx_q_num;
	rhp_http_bus_tx_async_ctx* head;
	rhp_http_bus_tx_async_ctx* tail;
};
typedef struct _rhp_http_bus_astx_task		rhp_http_bus_astx_task;

static rhp_http_bus_astx_task* _rhp_http_bus_astx_task_lst;


static void _rhp_http_bus_async_btx_task_handler(int worker_index,void* task_ctx_d)
{
	rhp_http_bus_astx_task* astx_task = &(_rhp_http_bus_astx_task_lst[worker_index]);
	rhp_http_bus_tx_async_ctx* tx_ctx = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_ASYNC_BTX_TASK_HANDLER,"dxx",worker_index,task_ctx_d,astx_task);

  while( 1 ){

  	RHP_LOCK(&(astx_task->lock));

  	tx_ctx = astx_task->head;
		if( tx_ctx == NULL ){

			RHP_UNLOCK(&(astx_task->lock));
			goto end;
		}

		if( astx_task->tail == tx_ctx ){
			astx_task->tail = tx_ctx->next;
		}
		astx_task->head = tx_ctx->next;

		tx_ctx->next = NULL;

	  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_ASYNC_BTX_TASK_HANDLER_EXEC,"xxd",astx_task,tx_ctx,astx_task->tx_q_num);

	  astx_task->tx_q_num--;

		RHP_UNLOCK(&(astx_task->lock));

		_rhp_http_bus_btx_async_task(worker_index,(void*)tx_ctx);
  }

end:

	RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_ASYNC_BTX_TASK_HANDLER_RTRN,"x",astx_task);
  return;
}

//
// *****[CAUTION]*******
//
//    All callback functions except task_handler()  DON'T call RHP_BUG("") or rhp_log_write()!
//    These apis may internally call rhp_wts_sta_invoke_task(), so the call will be deadlock!
//
// *****[CAUTION]*******
//
static int _rhp_http_bus_async_btx_task_do_exec(int worker_index,void* task_ctx_d)
{
	rhp_http_bus_astx_task* astx_task = &(_rhp_http_bus_astx_task_lst[worker_index]);
	int flag = 0;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_ASYNC_BTX_TASK_DO_EXEC,"dxx",worker_index,task_ctx_d,astx_task);

  RHP_LOCK(&(astx_task->lock));

  flag = ( astx_task->head != NULL );

  RHP_UNLOCK(&(astx_task->lock));

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_ASYNC_BTX_TASK_DO_EXEC_RTRN,"xd",astx_task,flag);
  return flag;
}

//
// *****[CAUTION]*******
//
//    All callback functions except task_handler()  DON'T call RHP_BUG("") or rhp_log_write()!
//    These apis may internally call rhp_wts_sta_invoke_task(), so the call will be deadlock!
//
// *****[CAUTION]*******
//
static int _rhp_http_bus_async_btx_task_add_ctx(int worker_index,void* task_ctx_d,void* ctx)
{
	rhp_http_bus_astx_task* astx_task = &(_rhp_http_bus_astx_task_lst[worker_index]);
	rhp_http_bus_tx_async_ctx* tx_ctx = (rhp_http_bus_tx_async_ctx*)ctx;

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_ASYNC_BTX_TASK_ADD_CTX,"dxxx",worker_index,task_ctx_d,astx_task,tx_ctx);

  RHP_LOCK(&(astx_task->lock));

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_ASYNC_BTX_TASK_ADD_CTX_Q,"xd",astx_task,astx_task->tx_q_num);

  tx_ctx->next = NULL;

  if( astx_task->tail ){
  	astx_task->tail->next = tx_ctx;
  }else{
  	astx_task->head = tx_ctx;
  }
	astx_task->tail = tx_ctx;

  astx_task->tx_q_num++;

  RHP_UNLOCK(&(astx_task->lock));

  RHP_TRC_FREQ(0,RHPTRCID_HTTP_BUS_ASYNC_BTX_TASK_ADD_CTX_RTRN,"x",astx_task);
  return 0;
}



int rhp_http_bus_init()
{
	int err = -EINVAL;
	int workers_num = rhp_wts_get_workers_num();
	int i;

	RHP_TRC(0,RHPTRCID_HTTP_BUS_INIT,"");

  _rhp_mutex_init("HTG",&_rhp_http_bus_lock);
  memset(_rhp_http_bus_sess_hashtbl,0,RHP_HTTP_BUS_HASH_SIZE);
  _rhp_atomic_init(&_rhp_http_bus_sess_num);


	{
  	_rhp_http_bus_astx_task_lst = (rhp_http_bus_astx_task*)_rhp_malloc(sizeof(rhp_http_bus_astx_task)*workers_num);
  	if( _rhp_http_bus_astx_task_lst == NULL ){
  		err = -ENOMEM;
			RHP_BUG("%d",err);
			goto error;
		}

		for( i = 0; i < workers_num ; i++ ){

	  	rhp_http_bus_astx_task* tx_task = &(_rhp_http_bus_astx_task_lst[i]);

			memset(tx_task,0,sizeof(rhp_http_bus_astx_task));

			tx_task->tag[0] = '#';
			tx_task->tag[1] = 'H';
			tx_task->tag[2] = 'B';
			tx_task->tag[3] = 'T';

			_rhp_mutex_init("HBT",&(tx_task->lock));
		}


		err = rhp_wts_sta_register_task(RHP_WTS_STA_TASK_NAME_HBUS_ASYNC_TX,
				RHP_WTS_DISP_LEVEL_HIGH_1,
				_rhp_http_bus_async_btx_task_handler,
				_rhp_http_bus_async_btx_task_do_exec,
				_rhp_http_bus_async_btx_task_add_ctx,NULL);

		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
	}


  rhp_http_server_register_handler(_rhp_http_bus_handler,NULL,1);

  RHP_TRC(0,RHPTRCID_HTTP_BUS_INIT_RTRN,"");
  return 0;

error:
	RHP_TRC(0,RHPTRCID_HTTP_BUS_INIT_ERR,"E",err);
	return err;
}

void rhp_http_bus_cleanup()
{
  RHP_TRC(0,RHPTRCID_HTTP_BUS_CLEANUP,"");

  _rhp_mutex_destroy(&_rhp_http_bus_lock);

  RHP_TRC(0,RHPTRCID_HTTP_BUS_CLEANUP_RTRN,"");
}

