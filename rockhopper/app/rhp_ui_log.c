/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.

	You can redistribute and/or modify this software under the
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


//
// Access operations to the Log DB file(SQLite) is processed by only the particular
// single thread, the worker thread for RHP_WTS_DISP_RULE_MISC.
// So, no lock is required.
//


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
#include <byteswap.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <libxml/encoding.h>
#include <libxml/xmlwriter.h>
#include "sqlite3.h"


#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_protocol.h"
#include "rhp_packet.h"
#include "rhp_netsock.h"
#include "rhp_config.h"
#include "rhp_vpn.h"
#include "rhp_ikev2_mesg.h"
#include "rhp_ikev2.h"
#include "rhp_http.h"
#include "rhp_wthreads.h"
#include "rhp_event.h"
#include "rhp_ui.h"
#include "rhp_dns_pxy.h"
#include "rhp_tuntap.h"
#include "rhp_forward.h"

struct _rhp_ui_log_write_ctx {

	u8 tag[4]; // '#LWX'

	unsigned long event_source;
	unsigned long vpn_realm_id;
	unsigned long level;
	unsigned long log_id;
	struct timeval timestamp;
	char* log_content;
	int log_content_len;
};
typedef struct _rhp_ui_log_write_ctx	rhp_ui_log_write_ctx;

struct _rhp_ui_log_db_ctx {
	u8 tag[4]; // '#UDC'
	struct _rhp_ui_log_db_ctx* next;

#define RHP_UI_LOG_DB_WRITE				1
#define RHP_UI_LOG_DB_GET_NUM			2
#define RHP_UI_LOG_DB_SAVE				3
#define RHP_UI_LOG_DB_RESET				4
	int action;
	void* ctx[6];
};
typedef struct _rhp_ui_log_db_ctx		rhp_ui_log_db_ctx;


static 	sqlite3* _rhp_ui_log_db = NULL;
static sqlite3_stmt* _rhp_ui_log_cmd_insert = NULL;
static sqlite3_stmt* _rhp_ui_log_cmd_update_rec_num = NULL;
static sqlite3_stmt* _rhp_ui_log_cmd_get_rec_num = NULL;
static sqlite3_stmt* _rhp_ui_log_cmd_get_oldest_recs = NULL;
static sqlite3_stmt* _rhp_ui_log_cmd_del_oldest_rec = NULL;
static sqlite3_stmt* _rhp_ui_log_cmd_del_all_recs = NULL;
static sqlite3_stmt* _rhp_ui_log_cmd_enum_all_recs = NULL;
static sqlite3_stmt* _rhp_ui_log_cmd_enum_limit_recs_all_realms = NULL;
static sqlite3_stmt* _rhp_ui_log_cmd_enum_limit_recs_one_realm = NULL;



static long _rhp_ui_log_db_record_num = -1;

static rhp_atomic_t _rhp_ui_log_pending_records;
u64 rhp_ui_log_statistics_dropped_log_records = 0;
rhp_mutex_t rhp_ui_log_statistics_lock;

#define RHP_LOG_TOOL_SQL_INSERT_EVENT\
		"insert into event_log(timestamp,event_source,realm_id, level,event_id,message) values(?,?,?,?,?,?);"

#define RHP_LOG_TOOL_OLDEST_DEL_NUM		5

// ... limit N : N == RHP_LOG_TOOL_OLDEST_DEL_NUM
#define RHP_LOG_TOOL_SQL_GET_OLDEST_RECS\
		"select timestamp from event_log order by timestamp asc limit 5;"

#define RHP_LOG_TOOL_SQL_DEL_OLDEST_REC\
		"delete from event_log where timestamp = ?;"

#define RHP_LOG_TOOL_SQL_DEL_ALL_RECS\
		"delete from event_log;"

#define RHP_LOG_TOOL_SQL_UPDATE_REC_NUM\
		"update event_log_meta set record_num = ? where id=0;"

#define RHP_LOG_TOOL_SQL_GET_REC_NUM\
		"select record_num from event_log_meta where id=0;"

#define RHP_LOG_TOOL_SQL_ENUM_ALL_RECS\
		"select * from event_log order by timestamp desc;"

#define RHP_LOG_TOOL_SQL_ENUM_LIMIT_RECS_ALL_REALMS\
		"select * from event_log order by timestamp desc limit ?;"

#define RHP_LOG_TOOL_SQL_ENUM_LIMIT_RECS_ONE_REALM\
		"select * from event_log where realm_id=? order by timestamp desc limit ?;"

static int _rhp_ui_log_active = 0;

static int _rhp_ui_log_write_xml_record(void* writer,int idx,u64 session_id,
		unsigned long event_source,unsigned long vpn_realm_id,unsigned long level,
		unsigned long log_id,int log_content_len,char* log_content)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;

  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_WRITE_XML_RECORD,"xdLuuLuLup",writer,idx,"LOG_SRC",event_source,vpn_realm_id,"LOG_LV",level,"LOG_ID",log_id,log_content_len,log_content);

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

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"log_record");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",session_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",vpn_realm_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"log_event_source","%lu",event_source);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"log_level","%lu",level);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"log_id","%lu",log_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  if( log_content_len ){

  	n = xmlTextWriterWriteCDATA((xmlTextWriterPtr)writer,(xmlChar*)log_content);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
  }

  n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_WRITE_XML_RECORD_RTRN,"xd",writer,n2);
  return n2;

error:
	RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_WRITE_XML_RECORD_ERR,"xE",writer,err);
  return err;
}

static int _rhp_ui_log_write_main_http_serialize(void* http_bus_sess_d,void* ctx_d,void* writer,int idx)
{
	rhp_http_bus_session* http_bus_sess = (rhp_http_bus_session*) http_bus_sess_d;
	rhp_ui_log_write_ctx* ctx = (rhp_ui_log_write_ctx*)ctx_d;
  int err = -EINVAL;
  int n2 = 0;

  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_WRITE_MAIN_SERIALIZE,"xxdxLuuLuLup",http_bus_sess,writer,idx,ctx_d,"LOG_SRC",ctx->event_source,ctx->vpn_realm_id,"LOG_LV",ctx->level,"LOG_ID",ctx->log_id,ctx->log_content_len,ctx->log_content);

  n2 = _rhp_ui_log_write_xml_record(writer,idx,http_bus_sess->session_id,
  		ctx->event_source,ctx->vpn_realm_id,ctx->level,ctx->log_id,ctx->log_content_len,ctx->log_content);
  if( n2 < 0 ){
  	err = n2;
  	goto error;
  }

  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_WRITE_MAIN_SERIALIZE_RTRN,"xxd",http_bus_sess,ctx,n2);
  return n2;

error:
	RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_WRITE_MAIN_SERIALIZE_ERR,"xxE",http_bus_sess,ctx,err);
  return err;
}

static void _rhp_ui_log_write_main_cleanup(void* ctx_d)
{
	rhp_ui_log_write_ctx* ctx = (rhp_ui_log_write_ctx*)ctx_d;

	if( ctx->log_content ){
		_rhp_free(ctx->log_content);
	}
	_rhp_free(ctx);

	RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_WRITE_MAIN_CLEANUP,"x",ctx);
}

static rhp_ui_log_write_ctx* _rhp_ui_log_write_main_alloc_ctx(unsigned long event_source,unsigned long vpn_realm_id,
		unsigned long level,unsigned long log_id,struct timeval* timestamp,char* log_content,int log_content_len)
{
	rhp_ui_log_write_ctx* ctx = NULL;

	ctx = (rhp_ui_log_write_ctx*)_rhp_malloc(sizeof(rhp_ui_log_write_ctx));
	if( ctx == NULL ){
		RHP_BUG("");
		return NULL;
	}

	ctx->tag[0] = '#';
	ctx->tag[1] = 'L';
	ctx->tag[2] = 'W';
	ctx->tag[3] = 'X';
	ctx->event_source = event_source;
	ctx->level = level;
	ctx->log_id = log_id;
	ctx->vpn_realm_id = vpn_realm_id;
	memcpy(&(ctx->timestamp),timestamp,sizeof(struct timeval));

	if( log_content ){

		ctx->log_content = (char*)_rhp_malloc(log_content_len);
		if(  ctx->log_content == NULL ){
			RHP_BUG("");
			_rhp_free(ctx);
			return NULL;
		}

		memcpy(ctx->log_content,log_content,log_content_len);
		ctx->log_content_len = log_content_len;

	}else{

		ctx->log_content = NULL;
		ctx->log_content_len = 0;
	}

	RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_WRITE_MAIN_ALLOC_CTX,"uuuux",event_source,vpn_realm_id,level,log_id,ctx);
	return ctx;
}

static void _rhp_ui_log_write_main(unsigned long event_source,unsigned long vpn_realm_id,
		unsigned long level,unsigned long log_id,struct timeval* timestamp,char* log_content,int log_content_len)
{
	int err;
	rhp_ui_log_write_ctx* ctx = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_WRITE_MAIN,"uuuupp",event_source,vpn_realm_id,level,log_id,sizeof(struct timeval),timestamp,log_content_len,log_content);

  if( log_content[log_content_len - 1] != '\0' ){
  	RHP_BUG("log_content NOT Null-terminated.");
  	return;
  }

  ctx = _rhp_ui_log_write_main_alloc_ctx(event_source,vpn_realm_id,
  		level,log_id,timestamp,log_content,log_content_len);
  if( ctx == NULL ){
  	err = -ENOMEM;
  	goto error;
  }

	err = rhp_http_bus_broadcast_async(vpn_realm_id,0,0,
			_rhp_ui_log_write_main_http_serialize,
			_rhp_ui_log_write_main_cleanup,(void*)ctx);

error:
  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_WRITE_MAIN_RTRN,"uuuuE",event_source,vpn_realm_id,level,log_id,err);
	return;
}


static int _rhp_ui_log_write_syspxy_serialize(void* http_bus_sess_d,void* ctx_d,void* writer,int idx)
{
	rhp_http_bus_session* http_bus_sess = (rhp_http_bus_session*) http_bus_sess_d;
	rhp_ipcmsg_syspxy_log_record* rec = (rhp_ipcmsg_syspxy_log_record*)ctx_d;
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;

  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_WRITE_SYSPXY_SERIALIZE,"xxdxLuuLuLup",http_bus_sess,writer,idx,rec,"LOG_SRC",rec->event_source,rec->vpn_realm_id,"LOG_LV",rec->level,"LOG_ID",rec->log_id,rec->log_content_len,(rec + 1));

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

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"log_record");
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

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",rec->vpn_realm_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"log_event_source","%lu",rec->event_source);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"log_level","%lu",rec->level);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"log_id","%lu",rec->log_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  if( rec->log_content_len ){

  	n = xmlTextWriterWriteCDATA((xmlTextWriterPtr)writer,(xmlChar*)(rec + 1));
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
  }

  n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_WRITE_SYSPXY_SERIALIZE_RTRN,"xxd",http_bus_sess,rec,n2);
  return n2;

error:
	RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_WRITE_SYSPXY_SERIALIZE_ERR,"xxE",http_bus_sess,rec,err);
  return err;
}

static void _rhp_ui_log_write_syspxy_cleanup(void* ctx_d)
{
	rhp_ipcmsg_syspxy_log_record* ipcmsg = (rhp_ipcmsg_syspxy_log_record*)ctx_d;

	_rhp_free(ipcmsg);

	RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_WRITE_SYSPXY_CLEANUP,"x",ipcmsg);
}

int rhp_ui_log_syspxy_ipc_handle(rhp_ipcmsg* ipcmsg)
{
	int err = 0;
	rhp_ipcmsg_syspxy_log_record* rec = (rhp_ipcmsg_syspxy_log_record*)ipcmsg;
	rhp_ui_log_db_ctx* ctx = NULL;

	RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_SYSPXY_IPC_HANDLE,"xp",ipcmsg,ipcmsg->len,ipcmsg);

	ctx = (rhp_ui_log_db_ctx*)_rhp_malloc(sizeof(rhp_ui_log_db_ctx));
	if( ctx ){

		rhp_ui_log_write_ctx* ctx2 = NULL;

		memset(ctx,0,sizeof(rhp_ui_log_db_ctx));

		ctx->tag[0] = '#';
		ctx->tag[1] = 'U';
		ctx->tag[2] = 'D';
		ctx->tag[3] = 'C';

	  ctx2 = _rhp_ui_log_write_main_alloc_ctx(rec->event_source,rec->vpn_realm_id,
	  		rec->level,rec->log_id,&(rec->timestamp),
	  		(rec->log_content_len ? (char*)(rec + 1) : NULL),rec->log_content_len);

	  if( ctx2 == NULL ){

	  	RHP_BUG("");
	  	_rhp_free(ctx);

	  }else{

	  	ctx->action = RHP_UI_LOG_DB_WRITE;
	  	ctx->ctx[0] = (void*)ctx2;

			err = rhp_wts_sta_invoke_task(RHP_WTS_DISP_RULE_MISC,
					RHP_WTS_STA_TASK_NAME_EVENT_LOG,RHP_WTS_DISP_LEVEL_HIGH_2,ctx,ctx);

			if( err ){
				RHP_BUG("%d",err);
				_rhp_ui_log_write_main_cleanup(ctx2);
  	  	_rhp_free(ctx);
			}
	  }

	}else{
		RHP_BUG("");
	}


	err = rhp_http_bus_broadcast_async(rec->vpn_realm_id,0,0,
			_rhp_ui_log_write_syspxy_serialize,
			_rhp_ui_log_write_syspxy_cleanup,(void*)rec);

	RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_SYSPXY_IPC_HANDLE_RTRN,"xE",ipcmsg,err);
	return 0;
}

static void _rhp_ui_log_write_syspxy(unsigned long event_source,unsigned long vpn_realm_id,
		unsigned long level,unsigned long log_id,struct timeval* timestamp,char* log_content,int log_content_len)
{
	rhp_ipcmsg_syspxy_log_record* rec = NULL;
	int tot_len = sizeof(rhp_ipcmsg_syspxy_log_record) + log_content_len;
	u8* p;

  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_WRITE_SYSPXY,"uuuupp",event_source,vpn_realm_id,level,log_id,sizeof(struct timeval),timestamp,log_content_len,log_content);

	rec = (rhp_ipcmsg_syspxy_log_record*)rhp_ipc_alloc_msg(RHP_IPC_SYSPXY_LOG_RECORD,tot_len);

	if( rec == NULL ){
    RHP_BUG("");
    goto error;
  }

	rec->len = tot_len;
	rec->event_source = event_source;
	rec->vpn_realm_id = vpn_realm_id;
	rec->level = level;
	rec->log_id = log_id;
	memcpy(&(rec->timestamp),timestamp,sizeof(struct timeval));
	rec->log_content_len = log_content_len;


  p = (u8*)(rec + 1);
  memcpy(p,log_content,log_content_len);

  if( rhp_ipc_send(RHP_MY_PROCESS,(void*)rec,rec->len,0) < 0 ){
    RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_WRITE_SYSPXY_IPC_SEND_ERR,"xxd",RHP_MY_PROCESS,rec,rec->len);
  }

error:
	if(rec){
		_rhp_free(rec);
	}
  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_WRITE_SYSPXY_RTRN,"uuuuE",event_source,vpn_realm_id,level,log_id);
  return;
}


static __thread int _rhp_ui_logging = 0;

void rhp_ui_log_write(unsigned long event_source,unsigned long vpn_realm_id,
		unsigned long level,unsigned long log_id,struct timeval* timestamp,char* log_content,int log_content_len,
		int misc_log)
{
	int err = -EINVAL;
	long pnum = 0;

	if( misc_log ){
		rhp_trace_write_disable(rhp_gcfg_disabled_trace_write_for_misc_events);
	}

  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_WRITE,"uuuupsddd",event_source,vpn_realm_id,level,log_id,sizeof(struct timeval),timestamp,log_content,log_content_len,_rhp_ui_logging,_rhp_ui_log_active);

  if( _rhp_ui_logging ){ // Avoid recursive calls.
  	return;
  }

  _rhp_ui_logging = 1;

	if( !_rhp_ui_log_active ){
		_rhp_ui_logging = 0;
		return;
	}

  if( RHP_MY_PROCESS->role == RHP_PROCESS_ROLE_MAIN ){

  	rhp_ui_log_db_ctx* ctx = NULL;

  	if( (pnum = _rhp_atomic_read(&_rhp_ui_log_pending_records)) > rhp_gcfg_log_pending_records_max ){

  		RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_WRITE_SKIP,"uuuufd",event_source,vpn_realm_id,level,log_id,pnum,rhp_gcfg_log_pending_records_max);

  		RHP_LOCK(&rhp_ui_log_statistics_lock);
  		rhp_ui_log_statistics_dropped_log_records++;
  		RHP_UNLOCK(&rhp_ui_log_statistics_lock);

  		goto skip;
  	}

  	_rhp_ui_log_write_main(event_source,vpn_realm_id,level,log_id,timestamp,log_content,log_content_len);


  	ctx = (rhp_ui_log_db_ctx*)_rhp_malloc(sizeof(rhp_ui_log_db_ctx));
  	if( ctx ){

  		rhp_ui_log_write_ctx* ctx2 = NULL;

  		memset(ctx,0,sizeof(rhp_ui_log_db_ctx));

  		ctx->tag[0] = '#';
  		ctx->tag[1] = 'U';
  		ctx->tag[2] = 'D';
  		ctx->tag[3] = 'C';

  	  ctx2 = _rhp_ui_log_write_main_alloc_ctx(event_source,vpn_realm_id,
  	  		level,log_id,timestamp,log_content,log_content_len);

  	  if( ctx2 == NULL ){

  	  	RHP_BUG("");
  	  	_rhp_free(ctx);

  	  }else{

  	  	ctx->action = RHP_UI_LOG_DB_WRITE;
  	  	ctx->ctx[0] = (void*)ctx2;

  			err = rhp_wts_sta_invoke_task(RHP_WTS_DISP_RULE_MISC,
  					RHP_WTS_STA_TASK_NAME_EVENT_LOG,RHP_WTS_DISP_LEVEL_HIGH_2,ctx,ctx);

  			if( err ){

  				RHP_BUG("%d",err);
  				_rhp_ui_log_write_main_cleanup(ctx2);
    	  	_rhp_free(ctx);

      		RHP_LOCK(&rhp_ui_log_statistics_lock);
      		rhp_ui_log_statistics_dropped_log_records++;
      		RHP_UNLOCK(&rhp_ui_log_statistics_lock);

  			}else{
  				_rhp_atomic_inc(&_rhp_ui_log_pending_records);
  			}
  	  }

  	}else{
  		RHP_BUG("");
  	}

  }else if( RHP_MY_PROCESS->role == RHP_PROCESS_ROLE_SYSPXY ){

  	_rhp_ui_log_write_syspxy(event_source,vpn_realm_id,level,log_id,timestamp,log_content,log_content_len);

  }else{

  	RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_WRITE_ERR,"uuuupp",event_source,vpn_realm_id,level,log_id,sizeof(struct timeval),timestamp,log_content_len,log_content);
  }

skip:
  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_WRITE_RTRN,"uuuuf",event_source,vpn_realm_id,level,log_id,pnum);
	_rhp_ui_logging = 0;

	if( misc_log ){
		rhp_trace_write_enable(rhp_gcfg_disabled_trace_write_for_misc_events);
	}

	return;
}

int rhp_ui_log_get_record_num(RHP_LOG_GET_RECORD_NUM_CB callback,void* ctx_cb)
{
	int err = -EINVAL;
	rhp_ui_log_db_ctx* ctx = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_GET_RECORD_NUM,"Yx",callback,ctx_cb);

	if( !_rhp_ui_log_active ){
		RHP_BUG("");
  	err = -EINVAL;
  	goto error;
	}

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_MAIN ){
		RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

	ctx = (rhp_ui_log_db_ctx*)_rhp_malloc(sizeof(rhp_ui_log_db_ctx));
	if( ctx == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memset(ctx,0,sizeof(rhp_ui_log_db_ctx));

	ctx->tag[0] = '#';
	ctx->tag[1] = 'U';
	ctx->tag[2] = 'D';
	ctx->tag[3] = 'C';

	ctx->action = RHP_UI_LOG_DB_GET_NUM;
	ctx->ctx[0] = (void*)callback;
	ctx->ctx[1] = ctx_cb;

	err = rhp_wts_sta_invoke_task(RHP_WTS_DISP_RULE_MISC,
			RHP_WTS_STA_TASK_NAME_EVENT_LOG,RHP_WTS_DISP_LEVEL_HIGH_2,ctx,ctx);

	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_GET_RECORD_NUM_RTRN,"Yx",callback,ctx_cb);
	return 0;

error:
	if( ctx ){
		_rhp_free(ctx);
	}
  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_GET_RECORD_NUM_ERR,"YxE",callback,ctx_cb,err);
	return err;
}

int rhp_ui_log_reset(RHP_LOG_RESET_CB callback,void* ctx_cb)
{
	int err = -EINVAL;
	rhp_ui_log_db_ctx* ctx = NULL;

  RHP_TRC(0,RHPTRCID_UI_LOG_RESET,"Yx",callback,ctx_cb);

	if( !_rhp_ui_log_active ){
		RHP_BUG("");
  	return -EINVAL;
	}

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_MAIN ){
		RHP_BUG("");
  	return -EINVAL;
  }

	ctx = (rhp_ui_log_db_ctx*)_rhp_malloc(sizeof(rhp_ui_log_db_ctx));
	if( ctx == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memset(ctx,0,sizeof(rhp_ui_log_db_ctx));

	ctx->tag[0] = '#';
	ctx->tag[1] = 'U';
	ctx->tag[2] = 'D';
	ctx->tag[3] = 'C';

	ctx->action = RHP_UI_LOG_DB_RESET;
	ctx->ctx[0] = (void*)callback;
	ctx->ctx[1] = ctx_cb;

	err = rhp_wts_sta_invoke_task(RHP_WTS_DISP_RULE_MISC,
			RHP_WTS_STA_TASK_NAME_EVENT_LOG,RHP_WTS_DISP_LEVEL_HIGH_2,ctx,ctx);

	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

  RHP_TRC(0,RHPTRCID_UI_LOG_RESET_RTRN,"Yx",callback,ctx_cb);
	return 0;

error:
	if( ctx ){
		_rhp_free(ctx);
	}
  RHP_TRC(0,RHPTRCID_UI_LOG_RESET_ERR,"YxE",callback,ctx_cb,err);
	return err;
}

int rhp_ui_log_save(int file_type,char* file_name,unsigned long vpn_realm_id,int limit_num,RHP_LOG_SAVE_CB callback,void* ctx_cb)
{
	int err = -EINVAL;
	rhp_ui_log_db_ctx* ctx = NULL;
	char* file_name_dp = NULL;

  RHP_TRC(0,RHPTRCID_UI_LOG_SAVE,"dsudYx",file_type,file_name,vpn_realm_id,limit_num,callback,ctx_cb);

	if( !_rhp_ui_log_active ){
		RHP_BUG("");
  	return -EINVAL;
	}

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_MAIN ){
		RHP_BUG("");
  	return -EINVAL;
  }

	ctx = (rhp_ui_log_db_ctx*)_rhp_malloc(sizeof(rhp_ui_log_db_ctx));
	if( ctx == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	file_name_dp = (char*)_rhp_malloc(strlen(file_name) + 1);
	if( file_name_dp == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	file_name_dp[0] = '\0';
	strcpy(file_name_dp,file_name);

	memset(ctx,0,sizeof(rhp_ui_log_db_ctx));

	ctx->tag[0] = '#';
	ctx->tag[1] = 'U';
	ctx->tag[2] = 'D';
	ctx->tag[3] = 'C';

	ctx->action = RHP_UI_LOG_DB_SAVE;
	ctx->ctx[0] = (void*)callback;
	ctx->ctx[1] = ctx_cb;
	ctx->ctx[2] = (void*)file_type;
	ctx->ctx[3] = (void*)file_name_dp;
	ctx->ctx[4] = (void*)vpn_realm_id;
	ctx->ctx[5] = (void*)limit_num;


	err = rhp_wts_sta_invoke_task(RHP_WTS_DISP_RULE_MISC,
			RHP_WTS_STA_TASK_NAME_EVENT_LOG,RHP_WTS_DISP_LEVEL_HIGH_2,ctx,ctx);

	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

  RHP_TRC(0,RHPTRCID_UI_LOG_SAVE_RTRN,"dsYx",file_type,file_name,callback,ctx_cb);
	return 0;

error:
	if( ctx ){
		_rhp_free(ctx);
	}
	if( file_name_dp ){
		_rhp_free(file_name_dp);
	}
  RHP_TRC(0,RHPTRCID_UI_LOG_SAVE_ERR,"dsYxE",file_type,file_name,callback,ctx_cb,err);
	return err;
}

static int _rhp_ui_log_enum_oldest_recs(char** result,int result_num)
{
	int serr = SQLITE_DONE;
	char* result_tmp;
	int i;

	sqlite3_reset(_rhp_ui_log_cmd_get_oldest_recs);

	i = 0;
	while( (serr = sqlite3_step(_rhp_ui_log_cmd_get_oldest_recs)) == SQLITE_ROW && i < result_num ){

		result_tmp = (char*)sqlite3_column_text(_rhp_ui_log_cmd_get_oldest_recs,0);
		if( result_tmp ){

			result[i] = (char*)_rhp_malloc(strlen(result_tmp) + 1);
			if( result[i] == NULL ){
				return -ENOMEM;
			}

			result[i][0] = '\0';
			strcpy(result[i],result_tmp);
		}

		RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_ENUM_OLDEST_RECS_TIMESTAMP,"ds",i,result[i]);

	  i++;
	}

	if(serr != SQLITE_DONE){
		RHP_BUG("%d, %s",serr,sqlite3_errmsg(_rhp_ui_log_db));
		return -EINVAL;
	}

	return 0;
}

#define RHP_LOG_TOOL_SQL_DBG_DEL_REC\
		"delete from event_log where timestamp = ?;"

static int _rhp_ui_log_del_oldest_rec(char* time_stamp)
{
	int serr;
	int err = 0;

	sqlite3_exec(_rhp_ui_log_db, "begin;", NULL, NULL, NULL);

	sqlite3_reset(_rhp_ui_log_cmd_del_oldest_rec);
	sqlite3_bind_text(_rhp_ui_log_cmd_del_oldest_rec,1,time_stamp,strlen(time_stamp),SQLITE_TRANSIENT);

	serr = sqlite3_step(_rhp_ui_log_cmd_del_oldest_rec);
	if (serr != SQLITE_DONE){

		RHP_BUG("%d, %s",serr,sqlite3_errmsg(_rhp_ui_log_db));
		err = -EINVAL;

		sqlite3_exec(_rhp_ui_log_db, "rollback;", NULL, NULL, NULL);
		goto error;

	}else{

		sqlite3_reset(_rhp_ui_log_cmd_update_rec_num);
		sqlite3_bind_int64(_rhp_ui_log_cmd_update_rec_num, 1,(_rhp_ui_log_db_record_num - 1));

		serr = sqlite3_step(_rhp_ui_log_cmd_update_rec_num);
		if (serr != SQLITE_DONE){

			RHP_BUG("%d, %s",err,sqlite3_errmsg(_rhp_ui_log_db));
			err = -EINVAL;

			sqlite3_exec(_rhp_ui_log_db, "rollback;", NULL, NULL, NULL);
			goto error;

		}else{

			_rhp_ui_log_db_record_num--;

			RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_DEL_OLDEST_REC_TIMESTAMP,"sd",time_stamp,_rhp_ui_log_db_record_num);
		}
	}

	sqlite3_exec(_rhp_ui_log_db, "commit;", NULL, NULL, NULL);

error:
	return err;
}

static int _rhp_ui_log_db_clear_oldest_recs()
{
	int err = -EINVAL;
  long max_recs = (rhp_gcfg_max_event_log_records > RHP_LOG_TOOL_OLDEST_DEL_NUM) ? rhp_gcfg_max_event_log_records : RHP_LOG_TOOL_OLDEST_DEL_NUM*2;

	while( _rhp_ui_log_db_record_num >= max_recs ){

		char* del_recs[RHP_LOG_TOOL_OLDEST_DEL_NUM];
		int i;

	  RHP_TRC(0,RHPTRCID_UI_LOG_DB_CLEAR_OLDEST_RECS_CUR_NUM,"dd",_rhp_ui_log_db_record_num,max_recs);

		memset(del_recs,0,sizeof(char*)*RHP_LOG_TOOL_OLDEST_DEL_NUM);

		err = _rhp_ui_log_enum_oldest_recs(del_recs,RHP_LOG_TOOL_OLDEST_DEL_NUM);
		if( !err ){

			for( i = 0; i < RHP_LOG_TOOL_OLDEST_DEL_NUM; i++){

				err = _rhp_ui_log_del_oldest_rec(del_recs[i]);
				if( err ){
					RHP_BUG("%d",err);
					break;
				}
			}
		}

		for( i = 0; i < RHP_LOG_TOOL_OLDEST_DEL_NUM; i++){
			if( del_recs[i] ){
				_rhp_free(del_recs[i]);
			}
		}

		if( err ){
			RHP_BUG("%d",err);
			break;
		}
	}

	return err;
}

static int _rhp_ui_log_db_write(rhp_ui_log_db_ctx* ctx)
{
	int err = -EINVAL;
	int serr = SQLITE_OK;
	rhp_ui_log_write_ctx* ctx2 = (rhp_ui_log_write_ctx*)(ctx->ctx[0]);
  struct tm ts;
  char buf0[64];

  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_DB_WRITE,"xd",ctx,_rhp_ui_log_db_record_num);

	if( ctx2 == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}


	buf0[0] = '\0';
  localtime_r(&(ctx2->timestamp.tv_sec),&ts);

  snprintf(buf0,64,
  		"%d-%02d-%02d %02d:%02d:%02d.%06ld",
  		ts.tm_year + 1900,ts.tm_mon + 1, ts.tm_mday, ts.tm_hour, ts.tm_min, ts.tm_sec,
  		ctx2->timestamp.tv_usec);


  _rhp_ui_log_db_clear_oldest_recs();


	sqlite3_exec(_rhp_ui_log_db, "begin;", NULL, NULL, NULL);

	sqlite3_reset(_rhp_ui_log_cmd_insert);
	sqlite3_bind_text(_rhp_ui_log_cmd_insert,1,buf0,strlen(buf0),SQLITE_TRANSIENT);
	sqlite3_bind_int(_rhp_ui_log_cmd_insert, 2, ctx2->event_source);
	sqlite3_bind_int(_rhp_ui_log_cmd_insert, 3, ctx2->vpn_realm_id);
	sqlite3_bind_int(_rhp_ui_log_cmd_insert, 4, ctx2->level);
	sqlite3_bind_int(_rhp_ui_log_cmd_insert, 5, ctx2->log_id);
	sqlite3_bind_text(_rhp_ui_log_cmd_insert,6,ctx2->log_content,(ctx2->log_content_len - 1),SQLITE_TRANSIENT);

	serr = sqlite3_step(_rhp_ui_log_cmd_insert);
	if(serr != SQLITE_DONE){

		RHP_BUG("%d, %s",err,sqlite3_errmsg(_rhp_ui_log_db));

		sqlite3_exec(_rhp_ui_log_db, "rollback;", NULL, NULL, NULL);
		goto error;

	}else{

		sqlite3_reset(_rhp_ui_log_cmd_update_rec_num);
		sqlite3_bind_int64(_rhp_ui_log_cmd_update_rec_num, 1,(_rhp_ui_log_db_record_num + 1));

		serr = sqlite3_step(_rhp_ui_log_cmd_update_rec_num);
		if (serr != SQLITE_DONE){

			RHP_BUG("%d, %s",err,sqlite3_errmsg(_rhp_ui_log_db));

			sqlite3_exec(_rhp_ui_log_db, "rollback;", NULL, NULL, NULL);
			goto error;

		}else{

			_rhp_ui_log_db_record_num++;
		}
	}

	sqlite3_exec(_rhp_ui_log_db, "commit;", NULL, NULL, NULL);

	if( ctx2 ){
		_rhp_ui_log_write_main_cleanup(ctx2);
	}

	_rhp_atomic_dec(&_rhp_ui_log_pending_records);

  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_DB_WRITE_RTRN,"xxdLd",ctx,ctx2,_rhp_ui_log_db_record_num,"SQLITE3_ERR",serr);
	return 0;

error:
	if( ctx2 ){
		_rhp_ui_log_write_main_cleanup(ctx2);
	}

	_rhp_atomic_dec(&_rhp_ui_log_pending_records);

	RHP_LOCK(&rhp_ui_log_statistics_lock);
	rhp_ui_log_statistics_dropped_log_records++;
	RHP_UNLOCK(&rhp_ui_log_statistics_lock);

	RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_DB_WRITE_ERR,"xxLdE",ctx,ctx2,"SQLITE3_ERR",serr,err);
	return err;
}

static int _rhp_ui_log_db_get_num(rhp_ui_log_db_ctx* ctx,long* num_r)
{
	int err = -EINVAL;
	int serr = SQLITE_OK;
	long num = -1;
	RHP_LOG_GET_RECORD_NUM_CB cb;

  RHP_TRC(0,RHPTRCID_UI_LOG_DB_GET_NUM,"xx",ctx,num_r);

	sqlite3_reset(_rhp_ui_log_cmd_get_rec_num);

	while( (serr = sqlite3_step(_rhp_ui_log_cmd_get_rec_num)) == SQLITE_ROW ){
			num = sqlite3_column_int64(_rhp_ui_log_cmd_get_rec_num,0);
	}

	if( serr != SQLITE_DONE ){
		RHP_BUG("%d, %s",err,sqlite3_errmsg(_rhp_ui_log_db));
		num = -1;
		err = -EINVAL;
	}

	if( num_r ){
		*num_r = num;
	}

	if( ctx ){

		void* cb_ctx = ctx->ctx[1];
		cb = (RHP_LOG_GET_RECORD_NUM_CB)(ctx->ctx[0]);

		if( cb ){
			cb(num,cb_ctx);
		}
	}

  RHP_TRC(0,RHPTRCID_UI_LOG_DB_GET_NUM_RTRN,"xdLd",ctx,num,"SQLITE3_ERR",serr);
	return 0;
}


char* rhp_event_log_convert_cmd_path = NULL;

static int _rhp_ui_log_db_save_convert_txt(rhp_ui_log_db_ctx* ctx)
{
	int err = -EINVAL;
	rhp_cmd_tlv_list tlvlst;

  RHP_TRC(0,RHPTRCID_UI_LOG_DB_SAVE_CONVERT_TXT,"xss",ctx,rhp_event_log_convert_cmd_path,(char*)ctx->ctx[3]);

  memset(&tlvlst,0,sizeof(rhp_cmd_tlv_list));

  if( rhp_event_log_convert_cmd_path == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_EVENT_LOG_CONVERT_SRC_XML_FILE",
			(strlen((char*)ctx->ctx[3]) + 1),(char*)ctx->ctx[3]);
	if( err ){
		RHP_BUG("");
		goto error;
	}

	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_EVENT_LOG_CONVERT_DST_TXT_FILE",
			(strlen((char*)ctx->ctx[3]) + 1),(char*)ctx->ctx[3]);
	if( err ){
		RHP_BUG("");
		goto error;
	}

	err = rhp_cmd_exec(rhp_event_log_convert_cmd_path,&tlvlst,1);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	rhp_cmd_tlv_clear(&tlvlst);

  RHP_TRC(0,RHPTRCID_UI_LOG_DB_SAVE_CONVERT_TXT_RTRN,"x",ctx);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_UI_LOG_DB_SAVE_CONVERT_TXT_ERR,"xE",ctx,err);
	return err;
}

static int _rhp_ui_log_db_save(rhp_ui_log_db_ctx* ctx)
{
	int err = -EINVAL,serr = SQLITE_OK;
	xmlTextWriterPtr writer = NULL;
	int idx;
	int n,n2 = 0;
	RHP_LOG_SAVE_CB cb = (RHP_LOG_SAVE_CB)(ctx->ctx[0]);
	void* ctx_cb = (void*)ctx->ctx[1];
	int file_type = (int)ctx->ctx[2];
	char* file_name = (char*)ctx->ctx[3];
	unsigned long rlm_id = (unsigned long)ctx->ctx[4];
  int limit_num = (unsigned long)ctx->ctx[5];

  RHP_TRC(0,RHPTRCID_UI_LOG_DB_SAVE,"xYxdsudd",ctx,cb,ctx_cb,file_type,file_name,rlm_id,limit_num,_rhp_ui_log_db_record_num);

	if( file_type != RHP_LOG_SAVE_TYPE_XML && file_type != RHP_LOG_SAVE_TYPE_TXT ){
		RHP_BUG("%d",file_type);
		return -EINVAL;
	}

	writer = xmlNewTextWriterFilename(file_name,0);
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

  if( limit_num ){

		if( rlm_id == 0 ){

			sqlite3_reset(_rhp_ui_log_cmd_enum_limit_recs_all_realms);
			sqlite3_bind_int(_rhp_ui_log_cmd_enum_limit_recs_all_realms,1,limit_num);

			idx = 0;
			while( (serr = sqlite3_step(_rhp_ui_log_cmd_enum_limit_recs_all_realms)) == SQLITE_ROW ){

				char* mesg = (char*)sqlite3_column_text(_rhp_ui_log_cmd_enum_limit_recs_all_realms,5);

				n = _rhp_ui_log_write_xml_record(writer,idx,0,
							sqlite3_column_int(_rhp_ui_log_cmd_enum_limit_recs_all_realms,1),
							sqlite3_column_int(_rhp_ui_log_cmd_enum_limit_recs_all_realms,2),
							sqlite3_column_int(_rhp_ui_log_cmd_enum_limit_recs_all_realms,3),
							sqlite3_column_int(_rhp_ui_log_cmd_enum_limit_recs_all_realms,4),
							strlen(mesg) + 1,mesg);

				if( n < 0 ){
					err = n;
					RHP_BUG("%d",err);
					goto error;
				}else{
					n2 += n;
				}

				idx++;
			}

		}else{

			sqlite3_reset(_rhp_ui_log_cmd_enum_limit_recs_one_realm);
			sqlite3_bind_int(_rhp_ui_log_cmd_enum_limit_recs_one_realm,1,rlm_id);
			sqlite3_bind_int(_rhp_ui_log_cmd_enum_limit_recs_one_realm,2,limit_num);

			idx = 0;
			while( (serr = sqlite3_step(_rhp_ui_log_cmd_enum_limit_recs_one_realm)) == SQLITE_ROW ){

				char* mesg = (char*)sqlite3_column_text(_rhp_ui_log_cmd_enum_limit_recs_one_realm,5);

				n = _rhp_ui_log_write_xml_record(writer,idx,0,
							sqlite3_column_int(_rhp_ui_log_cmd_enum_limit_recs_one_realm,1),
							sqlite3_column_int(_rhp_ui_log_cmd_enum_limit_recs_one_realm,2),
							sqlite3_column_int(_rhp_ui_log_cmd_enum_limit_recs_one_realm,3),
							sqlite3_column_int(_rhp_ui_log_cmd_enum_limit_recs_one_realm,4),
							strlen(mesg) + 1,mesg);

				if( n < 0 ){
					err = n;
					RHP_BUG("%d",err);
					goto error;
				}else{
					n2 += n;
				}

				idx++;
			}
		}

  }else{

		sqlite3_reset(_rhp_ui_log_cmd_enum_all_recs);

		idx = 0;
		while( (serr = sqlite3_step(_rhp_ui_log_cmd_enum_all_recs)) == SQLITE_ROW ){

			char* mesg = (char*)sqlite3_column_text(_rhp_ui_log_cmd_enum_all_recs,5);
			unsigned long rec_rlm_id = (unsigned long)sqlite3_column_int(_rhp_ui_log_cmd_enum_all_recs,2);

			if( mesg && (rlm_id == 0 || rlm_id == rec_rlm_id) ){

				n = _rhp_ui_log_write_xml_record(writer,idx,0,
						sqlite3_column_int(_rhp_ui_log_cmd_enum_all_recs,1),
						rec_rlm_id,
						sqlite3_column_int(_rhp_ui_log_cmd_enum_all_recs,3),
						sqlite3_column_int(_rhp_ui_log_cmd_enum_all_recs,4),
						strlen(mesg) + 1,mesg);

				if( n < 0 ){
					err = n;
					RHP_BUG("%d",err);
					goto error;
				}else{
					n2 += n;
				}
			}

			idx++;
		}
  }


	n = xmlTextWriterEndDocument(writer);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  xmlFreeTextWriter(writer);
  writer = NULL;


	if(serr != SQLITE_DONE){
		RHP_BUG("%d, %s",serr,sqlite3_errmsg(_rhp_ui_log_db));
		err = -EINVAL;
		goto error;
	}

	if( file_type == RHP_LOG_SAVE_TYPE_TXT ){

		err = _rhp_ui_log_db_save_convert_txt(ctx);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
	}

  if( cb ){
  	cb(0,ctx_cb);
  }

  if( file_name ){
  	_rhp_free(file_name);
  }

  RHP_TRC(0,RHPTRCID_UI_LOG_DB_SAVE_RTRN,"xLdE",ctx,"SQLITE3_ERR",serr,err);
	return 0;

error:
	if( writer ){
		xmlFreeTextWriter(writer);
	}

  if( cb ){
  	cb(err,ctx_cb);
  }

  if( file_name ){
  	_rhp_free(file_name);
  }

	RHP_TRC(0,RHPTRCID_UI_LOG_DB_SAVE_ERR,"xE",ctx,err);
	return err;
}

static int _rhp_ui_log_db_reset(rhp_ui_log_db_ctx* ctx)
{
	int err = 0,serr = SQLITE_OK;
  RHP_LOG_RESET_CB cb = ctx->ctx[0];
	void* ctx_cb = ctx->ctx[1];

  RHP_TRC(0,RHPTRCID_UI_LOG_DB_RESET,"xYxd",ctx,cb,ctx_cb,_rhp_ui_log_db_record_num);

  sqlite3_exec(_rhp_ui_log_db, "begin;", NULL, NULL, NULL);

	sqlite3_reset(_rhp_ui_log_cmd_del_all_recs);

	serr = sqlite3_step(_rhp_ui_log_cmd_del_all_recs);
	if( serr != SQLITE_DONE ){

		RHP_BUG("%d, %s",err,sqlite3_errmsg(_rhp_ui_log_db));

		sqlite3_exec(_rhp_ui_log_db, "rollback;", NULL, NULL, NULL);
		goto error;

	}else{

		_rhp_ui_log_db_record_num = 0;

		sqlite3_reset(_rhp_ui_log_cmd_update_rec_num);
		sqlite3_bind_int64(_rhp_ui_log_cmd_update_rec_num, 1,_rhp_ui_log_db_record_num);

		serr = sqlite3_step(_rhp_ui_log_cmd_update_rec_num);
		if (serr != SQLITE_DONE){

			RHP_BUG("%d, %s",err,sqlite3_errmsg(_rhp_ui_log_db));

			sqlite3_exec(_rhp_ui_log_db, "rollback;", NULL, NULL, NULL);
			goto error;
		}
	}

	sqlite3_exec(_rhp_ui_log_db, "commit;", NULL, NULL, NULL);


	if( err == -ENOENT ){
		err = 0;
	}

error:
	if( cb ){
		cb(err,ctx_cb);
	}

  RHP_TRC(0,RHPTRCID_UI_LOG_DB_RESET_RTRN,"xdLdE",ctx,_rhp_ui_log_db_record_num,"SQLITE3_ERR",serr,err);
	return err;
}


static int _rhp_ui_log_db_first_called = 0;

static void _rhp_ui_log_db_task(int worker_index,void* ctx_d)
{
	int err = -EINVAL;
	rhp_ui_log_db_ctx* ctx = (rhp_ui_log_db_ctx*)ctx_d;

  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_DB_TASK,"dxdxxxxxxd",worker_index,ctx,ctx->action,ctx->ctx[0],ctx->ctx[1],ctx->ctx[2],ctx->ctx[3],ctx->ctx[4],ctx->ctx[5],_rhp_ui_log_db_record_num);

  if( !_rhp_ui_log_db_first_called ){

  	err = _rhp_ui_log_db_get_num(NULL,&_rhp_ui_log_db_record_num);
  	if( err ){
  		RHP_BUG("%d",err);
  		goto error;
  	}

    RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_DB_TASK_FST_CALLED,"dxd",worker_index,ctx_d,_rhp_ui_log_db_record_num);

  	_rhp_ui_log_db_first_called = 1;
  }


  switch( ctx->action ){

  case RHP_UI_LOG_DB_WRITE:

    if( _rhp_ui_log_db_record_num < 0 ){
    	RHP_BUG("%d",_rhp_ui_log_db_record_num);
    	err = -EINVAL;
    	goto error;
    }

  	_rhp_ui_log_db_write(ctx);
  	break;

  case RHP_UI_LOG_DB_GET_NUM:

    if( _rhp_ui_log_db_record_num < 0 ){
    	RHP_BUG("%d",_rhp_ui_log_db_record_num);
    	err = -EINVAL;
    	goto error;
    }

  	_rhp_ui_log_db_get_num(ctx,NULL);
  	break;

  case RHP_UI_LOG_DB_SAVE:

  	_rhp_ui_log_db_save(ctx);
  	break;

  case RHP_UI_LOG_DB_RESET:

  	_rhp_ui_log_db_reset(ctx);
  	break;

  default:
  	RHP_BUG("%d",ctx->action);
  	err = -EINVAL;
  	goto error;
  }

  err = 0;

error:
  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_DB_TASK_RTRN,"dxE",worker_index,ctx,err);
  return;
}

struct _rhp_ui_log_db_task {

  unsigned char tag[4]; // "#ELC"

  rhp_mutex_t lock;

	int q_num;
	rhp_ui_log_db_ctx* head;
	rhp_ui_log_db_ctx* tail;
};
typedef struct _rhp_ui_log_db_task		rhp_ui_log_db_task;

static rhp_ui_log_db_task* _rhp_ui_log_db_task_lst;


static void _rhp_ui_log_db_task_handler(int worker_index,void* task_ctx_d)
{
	rhp_ui_log_db_task* log_task = &(_rhp_ui_log_db_task_lst[worker_index]);
	rhp_ui_log_db_ctx* log_ctx = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_DB_TASK_HANDLER,"dxx",worker_index,task_ctx_d,log_task);

  while( 1 ){

  	RHP_LOCK(&(log_task->lock));

  	log_ctx = log_task->head;
		if( log_ctx == NULL ){

			RHP_UNLOCK(&(log_task->lock));
			goto end;
		}

		if( log_task->tail == log_ctx ){
			log_task->tail = log_ctx->next;
		}
		log_task->head = log_ctx->next;

		log_ctx->next = NULL;

	  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_DB_TASK_HANDLER_EXEC,"xxd",log_task,log_ctx,log_task->q_num);

	  log_task->q_num--;

		RHP_UNLOCK(&(log_task->lock));

		_rhp_ui_log_db_task(worker_index,(void*)log_ctx);
		_rhp_free(log_ctx);
  }

end:
	RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_DB_TASK_HANDLER_RTRN,"x",log_task);
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
static int _rhp_ui_log_db_task_do_exec(int worker_index,void* task_ctx_d)
{
	rhp_ui_log_db_task* log_task = &(_rhp_ui_log_db_task_lst[worker_index]);
	int flag = 0;

  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_DB_TASK_DO_EXEC,"dxx",worker_index,task_ctx_d,log_task);

  RHP_LOCK(&(log_task->lock));

  flag = ( log_task->head != NULL );

  RHP_UNLOCK(&(log_task->lock));

  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_DB_TASK_DO_EXEC_RTRN,"xd",log_task,flag);
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
static int _rhp_ui_log_db_task_add_ctx(int worker_index,void* task_ctx_d,void* ctx)
{
	rhp_ui_log_db_task* log_task = &(_rhp_ui_log_db_task_lst[worker_index]);
	rhp_ui_log_db_ctx* log_ctx = (rhp_ui_log_db_ctx*)ctx;

  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_DB_TASK_ADD_CTX,"dxxx",worker_index,task_ctx_d,log_task,log_ctx);

  RHP_LOCK(&(log_task->lock));

  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_DB_TASK_ADD_CTX_Q,"xd",log_task,log_task->q_num);

  log_ctx->next = NULL;

  if( log_task->tail ){
  	log_task->tail->next = log_ctx;
  }else{
  	log_task->head = log_ctx;
  }
	log_task->tail = log_ctx;

  log_task->q_num++;

  RHP_UNLOCK(&(log_task->lock));

  RHP_TRC_FREQ(0,RHPTRCID_UI_LOG_DB_TASK_ADD_CTX_RTRN,"x",log_task);
  return 0;
}

extern char* rhp_main_log_file_path;

int rhp_ui_log_init()
{
	int err = -EINVAL;
	int workers_num = rhp_wts_get_workers_num();
	int i;

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_MAIN ){
  	_rhp_ui_log_active = 1;
  	return 0;
  }

	if( rhp_main_log_file_path == NULL ){

		RHP_BUG("");

		rhp_gcfg_log_disabled = 1;
	  rhp_log_disable(rhp_gcfg_log_disabled);

	  return 0;
	}

	err = sqlite3_open_v2(rhp_main_log_file_path,&_rhp_ui_log_db,
			(SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX),NULL);
	if( err != SQLITE_OK ){
		RHP_BUG("%d",err);
		err = -EINVAL;
		goto error;
	}

	sqlite3_prepare(_rhp_ui_log_db,
				RHP_LOG_TOOL_SQL_INSERT_EVENT, strlen(RHP_LOG_TOOL_SQL_INSERT_EVENT),
				&_rhp_ui_log_cmd_insert, NULL);

	sqlite3_prepare(_rhp_ui_log_db,
				RHP_LOG_TOOL_SQL_UPDATE_REC_NUM, strlen(RHP_LOG_TOOL_SQL_UPDATE_REC_NUM),
				&_rhp_ui_log_cmd_update_rec_num, NULL);

	sqlite3_prepare(_rhp_ui_log_db,
			RHP_LOG_TOOL_SQL_GET_REC_NUM, strlen(RHP_LOG_TOOL_SQL_GET_REC_NUM),
				&_rhp_ui_log_cmd_get_rec_num, NULL);

	sqlite3_prepare(_rhp_ui_log_db,
			RHP_LOG_TOOL_SQL_GET_OLDEST_RECS, strlen(RHP_LOG_TOOL_SQL_GET_OLDEST_RECS),
				&_rhp_ui_log_cmd_get_oldest_recs, NULL);

	sqlite3_prepare(_rhp_ui_log_db,
			RHP_LOG_TOOL_SQL_DEL_OLDEST_REC, strlen(RHP_LOG_TOOL_SQL_DEL_OLDEST_REC),
				&_rhp_ui_log_cmd_del_oldest_rec, NULL);

	sqlite3_prepare(_rhp_ui_log_db,
			RHP_LOG_TOOL_SQL_DEL_ALL_RECS, strlen(RHP_LOG_TOOL_SQL_DEL_ALL_RECS),
				&_rhp_ui_log_cmd_del_all_recs, NULL);

	sqlite3_prepare(_rhp_ui_log_db,
			RHP_LOG_TOOL_SQL_ENUM_ALL_RECS, strlen(RHP_LOG_TOOL_SQL_ENUM_ALL_RECS),
				&_rhp_ui_log_cmd_enum_all_recs, NULL);

	sqlite3_prepare(_rhp_ui_log_db,
			RHP_LOG_TOOL_SQL_ENUM_LIMIT_RECS_ALL_REALMS, strlen(RHP_LOG_TOOL_SQL_ENUM_LIMIT_RECS_ALL_REALMS),
				&_rhp_ui_log_cmd_enum_limit_recs_all_realms, NULL);

	sqlite3_prepare(_rhp_ui_log_db,
			RHP_LOG_TOOL_SQL_ENUM_LIMIT_RECS_ONE_REALM, strlen(RHP_LOG_TOOL_SQL_ENUM_LIMIT_RECS_ONE_REALM),
				&_rhp_ui_log_cmd_enum_limit_recs_one_realm, NULL);


	{
  	_rhp_ui_log_db_task_lst = (rhp_ui_log_db_task*)_rhp_malloc(sizeof(rhp_ui_log_db_task)*workers_num);
  	if( _rhp_ui_log_db_task_lst == NULL ){
  		err = -ENOMEM;
			RHP_BUG("%d",err);
			goto error;
		}

		for( i = 0; i < workers_num ; i++ ){

	  	rhp_ui_log_db_task* log_task = &(_rhp_ui_log_db_task_lst[i]);

			memset(log_task,0,sizeof(rhp_ui_log_db_task));

			log_task->tag[0] = '#';
			log_task->tag[1] = 'E';
			log_task->tag[2] = 'L';
			log_task->tag[3] = 'C';

			_rhp_mutex_init("LGT",&(log_task->lock));
		}


		err = rhp_wts_sta_register_task(RHP_WTS_STA_TASK_NAME_EVENT_LOG,
				RHP_WTS_DISP_LEVEL_HIGH_2,
				_rhp_ui_log_db_task_handler,
				_rhp_ui_log_db_task_do_exec,
				_rhp_ui_log_db_task_add_ctx,NULL);

		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
	}

	_rhp_atomic_init(&_rhp_ui_log_pending_records);
  _rhp_mutex_init("ULL",&rhp_ui_log_statistics_lock);

	_rhp_ui_log_active = 1;
	return 0;

error:
	if( _rhp_ui_log_cmd_insert ){
		sqlite3_finalize(_rhp_ui_log_cmd_insert);
	}
	if( _rhp_ui_log_db ){
		sqlite3_close(_rhp_ui_log_db);
	}
	return err;
}

int rhp_ui_log_main_log_ctl(int flag)
{
	RHP_TRC(0,RHPTRCID_UI_LOG_MAIN_LOG_CTL,"dd",flag,rhp_gcfg_log_level_debug);

	if( !rhp_gcfg_log_level_debug ){

		rhp_log_enable_debug_level(flag);

		{
			rhp_ipcmsg_syspxy_log_ctrl log_ctrl;

			log_ctrl.tag[0] = '#';
			log_ctrl.tag[1] = 'I';
			log_ctrl.tag[2] = 'M';
			log_ctrl.tag[3] = 'S';

			log_ctrl.type = RHP_IPC_SYSPXY_LOG_CTRL;
			log_ctrl.len = sizeof(rhp_ipcmsg_syspxy_log_ctrl);

			log_ctrl.debug_flag = flag;

			if( rhp_ipc_send(RHP_MY_PROCESS,(void*)&log_ctrl,log_ctrl.len,0) < 0 ){
				RHP_BUG("");
			}
		}
  }


	RHP_TRC(0,RHPTRCID_UI_LOG_MAIN_LOG_CTL_RTRN,"dd",flag,rhp_gcfg_log_level_debug);
	return 0;
}

int rhp_ui_log_cleanup()
{

	if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_MAIN ){
		_rhp_ui_log_active = 0;
  	return 0;
  }

	if( _rhp_ui_log_cmd_insert ){
		sqlite3_finalize(_rhp_ui_log_cmd_insert);
	}

	if( _rhp_ui_log_cmd_update_rec_num ){
		sqlite3_finalize(_rhp_ui_log_cmd_update_rec_num);
	}

	if( _rhp_ui_log_cmd_get_rec_num ){
		sqlite3_finalize(_rhp_ui_log_cmd_get_rec_num);
	}

	if( _rhp_ui_log_cmd_get_oldest_recs ){
		sqlite3_finalize(_rhp_ui_log_cmd_get_oldest_recs);
	}

	if( _rhp_ui_log_cmd_del_oldest_rec ){
		sqlite3_finalize(_rhp_ui_log_cmd_del_oldest_rec);
	}

	if( _rhp_ui_log_cmd_del_all_recs ){
		sqlite3_finalize(_rhp_ui_log_cmd_del_all_recs);
	}

	if( _rhp_ui_log_cmd_enum_all_recs ){
		sqlite3_finalize(_rhp_ui_log_cmd_enum_all_recs);
	}

	if( _rhp_ui_log_cmd_enum_limit_recs_all_realms ){
		sqlite3_finalize(_rhp_ui_log_cmd_enum_limit_recs_all_realms);
	}

	if( _rhp_ui_log_cmd_enum_limit_recs_one_realm ){
		sqlite3_finalize(_rhp_ui_log_cmd_enum_limit_recs_one_realm);
	}

	if( _rhp_ui_log_db ){
		sqlite3_close(_rhp_ui_log_db);
	}

	_rhp_ui_log_active = 0;
	return 0;
}
