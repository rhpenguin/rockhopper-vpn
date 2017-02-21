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
#include <signal.h>
#include <pwd.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/unistd.h>
#include <time.h>
#include <execinfo.h>

#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_version.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_config.h"
#include "rhp_netmng.h"
#include "rhp_protocol.h"
#include "rhp_packet.h"
#include "rhp_vpn.h"
#include "rhp_ikev2.h"

#ifdef RHP_MEMORY_DBG

rhp_mutex_t rhp_memory_dbg_lock;

struct _rhp_mem_blk {

	u8 tag[4]; // #MEM

	struct _rhp_mem_blk* hash_prev;
	struct _rhp_mem_blk* hash_next;
	struct _rhp_mem_blk* lst_next;

	size_t size;
	time_t time;

	void* cur;
#define RHP_DBG_MEM_CALLER_REC_NUM		8
	void* owner[RHP_DBG_MEM_CALLER_REC_NUM];

	void* old_cur;
	void* old_owner[RHP_DBG_MEM_CALLER_REC_NUM];

#define RHP_DBG_MEM_FILE_SIZE	32
	char file_name[RHP_DBG_MEM_FILE_SIZE];
	int file_line;

	int from_pool;
	unsigned long flag;

	pid_t thread_id;
};
typedef struct _rhp_mem_blk		rhp_mem_blk;

#define RHP_MEMORY_RECORD_HASH_SIZE		1277

static rhp_mem_blk* _rhp_mem_blk_hash_tbl[RHP_MEMORY_RECORD_HASH_SIZE];


#define RHP_MEMORY_DBUG_BLK_SIZE				512
#define RHP_MEMORY_DBUG_BLK_POOL_NUM		30000

static rhp_mem_blk* _rhp_mem_record_pool_head = NULL;
static rhp_mem_blk* _rhp_mem_record_pool_tail = NULL;
static int _rhp_mem_record_pool_num = 0;
static unsigned long _rhp_mem_record_newly_alloc = 0;
static unsigned long _rhp_mem_alloc_big_record = 0;

static time_t _rhp_mem_dbg_startup_time;

static int _rhp_mem_dbg_started = 0;

void rhp_memory_dbg_init()
{
	int i;

	_rhp_mem_dbg_startup_time = _rhp_get_time();

	memset(_rhp_mem_blk_hash_tbl,0,sizeof(rhp_mem_blk*)*RHP_MEMORY_RECORD_HASH_SIZE);

  _rhp_mutex_init("MEM",&(rhp_memory_dbg_lock));

  for( i = 0; i < RHP_MEMORY_DBUG_BLK_POOL_NUM; i++){

  	rhp_mem_blk* rec = (rhp_mem_blk*)malloc(sizeof(rhp_mem_blk) + RHP_MEMORY_DBUG_BLK_SIZE);
  	if( rec == NULL ){
  		break;
  	}

  	memset(rec,0,sizeof(rhp_mem_blk));
  	memset((rec + 1),0x77,RHP_MEMORY_DBUG_BLK_SIZE);

  	rec->tag[0] = '$';
  	rec->tag[1] = '$';
  	rec->tag[2] = '$';
  	rec->tag[3] = '$';

  	rec->from_pool = 1;

  	if( _rhp_mem_record_pool_head == NULL ){
  		_rhp_mem_record_pool_head = rec;
    	_rhp_mem_record_pool_tail = rec;
  	}else{
  		_rhp_mem_record_pool_tail->lst_next = rec;
  		_rhp_mem_record_pool_tail = rec;
  	}

  	_rhp_mem_record_pool_num++;
  }

  RHP_LINE("rhp_memory_dbg_init : _rhp_mem_record_pool_num: %d",_rhp_mem_record_pool_num);

  return;
}

void rhp_memory_dbg_start()
{
  _rhp_mem_dbg_started = 1;
  RHP_LINE("rhp_memory_dbg_start : %d",_rhp_mem_dbg_started);
}


void* _rhp_malloc_dbg(size_t size,const char* file,int line)
{
	void* ptr;
	rhp_mem_blk* rec;
	unsigned long hval;
	int no_more_pool = 0;

	if( !_rhp_mem_dbg_started ){

		ptr = malloc(size);

		RHP_TRC(0,RHPTRCID_MALLOC_PRE_DBUG,"xdsd",ptr,size,file,line);
		return ptr;
	}

	if( size <= RHP_MEMORY_DBUG_BLK_SIZE ){

	 	pthread_mutex_lock(&(rhp_memory_dbg_lock.mutex));
	 	{

	 		if( !_rhp_mem_record_pool_num ){
	 		  pthread_mutex_unlock(&(rhp_memory_dbg_lock.mutex));
	 		  no_more_pool = 1;
	 		 _rhp_mem_record_newly_alloc++;
	 		 goto new_buffer;
	 		}

	 		rec = _rhp_mem_record_pool_head;
	 		_rhp_mem_record_pool_head = rec->lst_next;
	 		if( _rhp_mem_record_pool_head == NULL  ){
	 			_rhp_mem_record_pool_tail = NULL;
	 		}

	 		rec->lst_next = NULL;

	 		_rhp_mem_record_pool_num--;
	 	}
	  pthread_mutex_unlock(&(rhp_memory_dbg_lock.mutex));

	}else{

		_rhp_mem_alloc_big_record++;

new_buffer:
		rec = (rhp_mem_blk*)malloc(sizeof(rhp_mem_blk) + size);
		if( rec == NULL ){
			RHP_BUG("NO MEMORY!");
			return NULL;
		}

		rec->from_pool = 0;
		rec->lst_next = NULL;
	}


	rec->tag[0] = '#';
	rec->tag[1] = 'M';
	rec->tag[2] = 'E';
	rec->tag[3] = 'D';

	rec->thread_id = gettid();

	ptr = (void*)(rec + 1);

	rec->size = size;
	rec->time = _rhp_get_time();
	rec->hash_prev = NULL;
	rec->hash_next = NULL;
	rec->cur = NULL;

#ifdef RHP_DBG_FUNC_TRC
	rec->cur = rhp_func_trc_call_stack[rhp_func_trc_call_stack_idx];

	{
		int i;

		for( i = 1; i <= RHP_DBG_MEM_CALLER_REC_NUM; i++ ){

			if( rhp_func_trc_call_stack_idx > i ){
				rec->owner[i - 1] = rhp_func_trc_call_stack[rhp_func_trc_call_stack_idx - i];
			}else{
				rec->owner[i - 1] = NULL;
			}
		}
	}
#else
	memset(rec->owner,0,sizeof(void*)*RHP_DBG_MEM_CALLER_REC_NUM);
#endif // RHP_DBG_FUNC_TRC

	rec->file_name[0] = '\0';
	snprintf(rec->file_name,RHP_DBG_MEM_FILE_SIZE,"%s",file);
	rec->file_line = line;


	hval = ((unsigned long)ptr) % RHP_MEMORY_RECORD_HASH_SIZE;

 	pthread_mutex_lock(&(rhp_memory_dbg_lock.mutex));
 	{

 		if( _rhp_mem_blk_hash_tbl[hval] ){
			_rhp_mem_blk_hash_tbl[hval]->hash_prev = rec;
			rec->hash_next = _rhp_mem_blk_hash_tbl[hval];
		}

		_rhp_mem_blk_hash_tbl[hval] = rec;

 	}
  pthread_mutex_unlock(&(rhp_memory_dbg_lock.mutex));

	if( rhp_mem_initialized ){
		rec->flag = 1;
		rhp_mem_statistics_alloc(size);
	}else{
		rec->flag = 0;
	}

	RHP_TRC(0,RHPTRCID_MALLOC,"xddsdxdYYYYYYYYYYYYYYYY",ptr,size,no_more_pool,file,line,rec,rec->from_pool,rec->owner[0],rec->owner[1],rec->owner[2],rec->owner[3],rec->owner[4],rec->owner[5],rec->owner[6],rec->owner[7],rec->old_owner[0],rec->old_owner[1],rec->old_owner[2],rec->old_owner[3],rec->old_owner[4],rec->old_owner[5],rec->old_owner[6],rec->old_owner[7]);
	return ptr;
}


static __thread void* _rhp_free_dbg_buf0[512];

static char* _rhp_dbg_bt()
{
	int a;
	int n = backtrace(_rhp_free_dbg_buf0,sizeof(_rhp_free_dbg_buf0)/sizeof(void*));
	char** bt_str = backtrace_symbols(_rhp_free_dbg_buf0,n);
	char* pbuf = (char*)malloc(1024);
	int pbuf_len = 1024;
	char* pbuf_c = pbuf;

	if( bt_str == NULL ){
		RHP_BUG("");
		goto error;
	}

	if( pbuf == NULL ){
		RHP_BUG("");
		goto error;
	}

	memset( pbuf, '\0', 1024 );

	for(a = 0; a < n; a++){

		int ln = strlen( bt_str[a]) + 5 ;
		if(pbuf_c + ln > pbuf + pbuf_len){

			char* pbuf_tmp = (char*) malloc( pbuf_len * 2 );
			if(pbuf_tmp == NULL){
				RHP_BUG( "" );
				goto error;
			}
			memset( pbuf_tmp, '\0', pbuf_len * 2 );

			pbuf_c = pbuf_tmp + (pbuf_c - pbuf);

			memcpy( pbuf_tmp, pbuf, pbuf_len );
			free( pbuf );

			pbuf_len = pbuf_len * 2;
			pbuf = pbuf_tmp;
		}

		memcpy( pbuf_c, bt_str[a], (ln - 4) );
		pbuf_c += (ln - 4);
		*pbuf_c = '<';
		pbuf_c++;
		*pbuf_c = 'b';
		pbuf_c++;
		*pbuf_c = 'r';
		pbuf_c++;
		*pbuf_c = '>';
		pbuf_c++;
	}

	free( bt_str );

	RHP_BUG("%s",pbuf);
	return pbuf;

error:
	if( bt_str ){
		free(bt_str);
	}
	if( pbuf ){
		free(pbuf);
	}
	RHP_BUG("");
	return NULL;
}


void _rhp_free_dbg(void *ptr,const char* file,int line)
{
	rhp_mem_blk* rec = NULL;
	unsigned long hval;
	void *cur = NULL, *caller[RHP_DBG_MEM_CALLER_REC_NUM];
	int i;

	if( !_rhp_mem_dbg_started ){
		RHP_TRC(0,RHPTRCID_FREE_PRE_DBUG,"xsd",ptr,file,line);
		free(ptr);
		return;
	}

	RHP_TRC(0,RHPTRCID_FREE,"xsdx",ptr,file,line,(((u8*)ptr) - sizeof(rhp_mem_blk)));

#ifdef RHP_DBG_FUNC_TRC
	cur = rhp_func_trc_call_stack[rhp_func_trc_call_stack_idx];

	for( i = 1; i <= RHP_DBG_MEM_CALLER_REC_NUM; i++ ){

		if( rhp_func_trc_call_stack_idx > i ){
			caller[i - 1] = rhp_func_trc_call_stack[rhp_func_trc_call_stack_idx - i];
		}else{
			caller[i - 1] = NULL;
		}
	}
#else
	memset(caller,0,sizeof(void*)*RHP_DBG_MEM_CALLER_REC_NUM);
#endif // RHP_DBG_FUNC_TRC


	if( ptr == NULL ){

		RHP_BUG("0x%x, 0x%x",caller,cur);
    RHP_TRC(0,RHPTRCID_FREE_DBG_FREE_NULL_ADDRESS,"YY",caller,cur);

		RHP_LOG_DE(RHP_LOG_SRC_UI,0,RHP_LOG_ID_MEMDBG_FREE_NULL_PT,"xx",caller,cur); // See add2line
		return;
	}

	rec = (rhp_mem_blk*)(((u8*)ptr) - sizeof(rhp_mem_blk));

	if( rec->tag[0] != '#' || rec->tag[1] != 'M' || rec->tag[2] != 'E' || rec->tag[3] != 'D' ){

		RHP_BUG("");
		RHP_TRC(0,RHPTRCID_FREE_DBG_FREE_INVALID_BUFFER,"xddYYYYYYYYYYYYYYYYYYYYYYYYdpp",ptr,rec->size,rec->from_pool,caller[0],caller[1],caller[2],caller[3],caller[4],caller[5],caller[6],caller[7],rec->owner[0],rec->owner[1],rec->owner[2],rec->owner[3],rec->owner[4],rec->owner[5],rec->owner[6],rec->owner[7],rec->old_owner[0],rec->old_owner[1],rec->old_owner[2],rec->old_owner[3],rec->old_owner[4],rec->old_owner[5],rec->old_owner[6],rec->old_owner[7],rec->size,sizeof(rhp_mem_blk),rec,(RHP_MEMORY_DBUG_BLK_SIZE/2),(u8*)(rec + 1));

		if( rec->from_pool &&  rec->cur == NULL ){

			RHP_LOG_DE(RHP_LOG_SRC_UI,0,RHP_LOG_ID_MEMDBG_FREE_MAY_DUP_PT,"xddxxxxxxxxxxxx",ptr,rec->size,rec->from_pool,caller[0],caller[1],caller[2],caller[3],rec->owner[0],rec->owner[1],rec->owner[2],rec->owner[3],rec->old_owner[0],rec->old_owner[1],rec->old_owner[2],rec->old_owner[3]); // See add2line

		}else if( rec->tag[0] != '%' || rec->tag[1] != '%' || rec->tag[2] != '%' || rec->tag[3] != '%' ){

			RHP_LOG_DE(RHP_LOG_SRC_UI,0,RHP_LOG_ID_MEMDBG_FREE_MAY_DUP_PT2,"xddxxxxxxxxxxxx",ptr,rec->size,rec->from_pool,caller[0],caller[1],caller[2],caller[3],rec->owner[0],rec->owner[1],rec->owner[2],rec->owner[3],rec->old_owner[0],rec->old_owner[1],rec->old_owner[2],rec->old_owner[3]); // See add2line

		}else{

			RHP_LOG_DE(RHP_LOG_SRC_UI,0,RHP_LOG_ID_MEMDBG_FREE_INVALID_PT,"xddxxxxxxxxxxxx",ptr,rec->size,rec->from_pool,caller[0],caller[1],caller[2],caller[3],rec->owner[0],rec->owner[1],rec->owner[2],rec->owner[3],rec->old_owner[0],rec->old_owner[1],rec->old_owner[2],rec->old_owner[3]); // See add2line
		}

		return;
	}

	if( rec->from_pool && rec->cur == NULL ){

		RHP_BUG("");
		RHP_TRC(0,RHPTRCID_FREE_DBG_FREE_DUPLICATED_FREE,"xddYYYYYYYYYYYYYYYYYYYYYYYYdpp",ptr,rec->size,rec->from_pool,caller[0],caller[1],caller[2],caller[3],caller[4],caller[5],caller[6],caller[7],rec->owner[0],rec->owner[1],rec->owner[2],rec->owner[3],rec->owner[4],rec->owner[5],rec->owner[6],rec->owner[7],rec->old_owner[0],rec->old_owner[1],rec->old_owner[2],rec->old_owner[3],rec->old_owner[4],rec->old_owner[5],rec->old_owner[6],rec->old_owner[7],rec->size,sizeof(rhp_mem_blk),rec,(RHP_MEMORY_DBUG_BLK_SIZE/2),(u8*)(rec + 1));

		RHP_LOG_DE(RHP_LOG_SRC_UI,0,RHP_LOG_ID_MEMDBG_FREE_DUP_PT,"xddxxxxxxxxxxxx",ptr,rec->size,rec->from_pool,caller[0],caller[1],caller[2],caller[3],rec->owner[0],rec->owner[1],rec->owner[2],rec->owner[3],rec->old_owner[0],rec->old_owner[1],rec->old_owner[2],rec->old_owner[3]); // See add2line

		return;
	}

	RHP_TRC(0,RHPTRCID_FREE_BUF_HEAD,"xxpp",rec,ptr,sizeof(rhp_mem_blk),rec,( rec->size > 4 ? 4 : rec->size ),ptr);

	if( rec->flag ){
		rhp_mem_statistics_free(rec->size);
	}

	rec->tag[0] = '%';
	rec->tag[1] = '%';
	rec->tag[2] = '%';
	rec->tag[3] = '%';

	rec->old_cur = rec->cur;
	rec->cur = NULL;

	for( i = 0; i < RHP_DBG_MEM_CALLER_REC_NUM; i++ ){
		rec->old_owner[i] = rec->owner[i];
		rec->owner[i] = NULL;
	}

	if( !rec->from_pool ){
		memset((rec + 1),0x33,rec->size);
	}else{
		memset((rec + 1),0x33,RHP_MEMORY_DBUG_BLK_SIZE);
	}

	hval = ((unsigned long)ptr) % RHP_MEMORY_RECORD_HASH_SIZE;

 	pthread_mutex_lock(&(rhp_memory_dbg_lock.mutex));
 	{

 		if( rec->hash_prev == NULL ){

 			_rhp_mem_blk_hash_tbl[hval] = rec->hash_next;
 			if( rec->hash_next ){
 				rec->hash_next->hash_prev = NULL;
 			}

		}else{

			rec->hash_prev->hash_next = rec->hash_next;
			if( rec->hash_next ){
				rec->hash_next->hash_prev = rec->hash_prev;
			}
		}

 		rec->hash_next = NULL;
 		rec->hash_prev = NULL;

 		if( !rec->from_pool ){

 			RHP_TRC(0,RHPTRCID_FREE_NOT_FROM_POOL,"xx",rec,ptr);
 			free(rec);

 		}else{

 			rec->lst_next = NULL;

 	  	if( _rhp_mem_record_pool_head == NULL ){
 	  		_rhp_mem_record_pool_head = rec;
 	    	_rhp_mem_record_pool_tail = rec;
 	  	}else{
 	  		_rhp_mem_record_pool_tail->lst_next = rec;
 	  		_rhp_mem_record_pool_tail = rec;
 	  	}

 	  	_rhp_mem_record_pool_num++;
 		}
 	}
  pthread_mutex_unlock(&(rhp_memory_dbg_lock.mutex));

  return;
}

void _rhp_free_zero_dbg(void *ptr,size_t size,const char* file,int line)
{

	//
	// Copied code from _rhp_free(). TRC IDs are different.
	//

	rhp_mem_blk* rec = NULL;
	unsigned long hval;
	void *cur = NULL, *caller[RHP_DBG_MEM_CALLER_REC_NUM];
	int i;

	if( !_rhp_mem_dbg_started ){
		RHP_TRC(0,RHPTRCID_FREE_ZERO_PRE_DBUG,"xsd",ptr,file,line);
		free(ptr);
		return;
	}

	RHP_TRC(0,RHPTRCID_FREE_ZERO,"xdsddx",ptr,size,file,line,(((u8*)ptr) - sizeof(rhp_mem_blk)));

#ifdef RHP_DBG_FUNC_TRC
	cur = rhp_func_trc_call_stack[rhp_func_trc_call_stack_idx];

	for( i = 1; i <= RHP_DBG_MEM_CALLER_REC_NUM; i++ ){

		if( rhp_func_trc_call_stack_idx > i ){
			caller[i - 1] = rhp_func_trc_call_stack[rhp_func_trc_call_stack_idx - i];
		}else{
			caller[i - 1] = NULL;
		}
	}
#else
	memset(caller,0,sizeof(void*)*RHP_DBG_MEM_CALLER_REC_NUM);
#endif // RHP_DBG_FUNC_TRC


	if( ptr == NULL ){

		RHP_BUG("");
		RHP_TRC(0,RHPTRCID_FREE_DBG_FREE_NULL_ADDRESS_2,"YY",caller,cur);

		RHP_LOG_DE(RHP_LOG_SRC_UI,0,RHP_LOG_ID_MEMDBG_FREE_NULL_PT,"xx",caller,cur); // See add2line

		return;
	}

	rec = (rhp_mem_blk*)(((u8*)ptr) - sizeof(rhp_mem_blk));

	if( rec->tag[0] != '#' || rec->tag[1] != 'M' || rec->tag[2] != 'E' || rec->tag[3] != 'D' ){

		RHP_BUG("");
		RHP_TRC(0,RHPTRCID_FREE_ZERO_DBG_FREE_INVALID_BUFFER_2,"xddYYYYYYYYYYYYYYYYYYYYYYYYdpp",ptr,rec->size,rec->from_pool,caller[0],caller[1],caller[2],caller[3],caller[4],caller[5],caller[6],caller[7],rec->owner[0],rec->owner[1],rec->owner[2],rec->owner[3],rec->owner[4],rec->owner[5],rec->owner[6],rec->owner[7],rec->old_owner[0],rec->old_owner[1],rec->old_owner[2],rec->old_owner[3],rec->old_owner[4],rec->old_owner[5],rec->old_owner[6],rec->old_owner[7],rec->size,sizeof(rhp_mem_blk),rec,(RHP_MEMORY_DBUG_BLK_SIZE/2),(u8*)(rec + 1));

		if( rec->from_pool &&  rec->cur == NULL ){

			RHP_LOG_DE(RHP_LOG_SRC_UI,0,RHP_LOG_ID_MEMDBG_FREE_MAY_DUP_PT,"xddxxxxxxxxxxxx",ptr,rec->size,rec->from_pool,caller[0],caller[1],caller[2],caller[3],rec->owner[0],rec->owner[1],rec->owner[2],rec->owner[3],rec->old_owner[0],rec->old_owner[1],rec->old_owner[2],rec->old_owner[3]); // See add2line

		}else if( rec->tag[0] != '%' || rec->tag[1] != '%' || rec->tag[2] != '%' || rec->tag[3] != '%' ){

			RHP_LOG_DE(RHP_LOG_SRC_UI,0,RHP_LOG_ID_MEMDBG_FREE_MAY_DUP_PT2,"xddxxxxxxxxxxxx",ptr,rec->size,rec->from_pool,caller[0],caller[1],caller[2],caller[3],rec->owner[0],rec->owner[1],rec->owner[2],rec->owner[3],rec->old_owner[0],rec->old_owner[1],rec->old_owner[2],rec->old_owner[3]); // See add2line

		}else{

			RHP_LOG_DE(RHP_LOG_SRC_UI,0,RHP_LOG_ID_MEMDBG_FREE_INVALID_PT,"xddxxxxxxxxxxxx",ptr,rec->size,rec->from_pool,caller[0],caller[1],caller[2],caller[3],rec->owner[0],rec->owner[1],rec->owner[2],rec->owner[3],rec->old_owner[0],rec->old_owner[1],rec->old_owner[2],rec->old_owner[3]); // See add2line
		}

		return;
	}

	if( rec->from_pool && rec->cur == NULL ){

		RHP_BUG("");
		RHP_TRC(0,RHPTRCID_FREE_ZERO_DBG_FREE_DUPLICATED_FREE_2,"xddYYYYYYYYYYYYYYYYYYYYYYYYdpp",ptr,rec->size,rec->from_pool,caller[0],caller[1],caller[2],caller[3],caller[4],caller[5],caller[6],caller[7],rec->owner[0],rec->owner[1],rec->owner[2],rec->owner[3],rec->owner[4],rec->owner[5],rec->owner[6],rec->owner[7],rec->old_owner[0],rec->old_owner[1],rec->old_owner[2],rec->old_owner[3],rec->old_owner[4],rec->old_owner[5],rec->old_owner[6],rec->old_owner[7],rec->size,sizeof(rhp_mem_blk),rec,(RHP_MEMORY_DBUG_BLK_SIZE/2),(u8*)(rec + 1));

		RHP_LOG_DE(RHP_LOG_SRC_UI,0,RHP_LOG_ID_MEMDBG_FREE_DUP_PT,"xddxxxxxxxxxxxx",ptr,rec->size,rec->from_pool,caller[0],caller[1],caller[2],caller[3],rec->owner[0],rec->owner[1],rec->owner[2],rec->owner[3],rec->old_owner[0],rec->old_owner[1],rec->old_owner[2],rec->old_owner[3]); // See add2line

		return;
	}

	if( rec->size < size ){

		RHP_BUG("");
		RHP_TRC(0,RHPTRCID_FREE_ZERO_DBG_FREE_INVALID_SIZE_2,"xdddYYYYYYYYYYYYYYYYYYYYYYYYdppp",ptr,rec->size,size,rec->from_pool,caller[0],caller[1],caller[2],caller[3],caller[4],caller[5],caller[6],caller[7],rec->owner[0],rec->owner[1],rec->owner[2],rec->owner[3],rec->owner[4],rec->owner[5],rec->owner[6],rec->owner[7],rec->old_owner[0],rec->old_owner[1],rec->old_owner[2],rec->old_owner[3],rec->old_owner[4],rec->old_owner[5],rec->old_owner[6],rec->old_owner[7],rec->size,sizeof(rhp_mem_blk),rec,rec->size,(u8*)(rec + 1),size,ptr);

		RHP_LOG_DE(RHP_LOG_SRC_UI,0,RHP_LOG_ID_MEMDBG_FREE_ZERO_INVALID_SIZE,"xdddxxxxxxxxxxxx",ptr,rec->size,size,rec->from_pool,caller[0],caller[1],caller[2],caller[3],rec->owner[0],rec->owner[1],rec->owner[2],rec->owner[3],rec->old_owner[0],rec->old_owner[1],rec->old_owner[2],rec->old_owner[3]); // See add2line
	}

	RHP_TRC(0,RHPTRCID_FREE_ZERO_BUF_HEAD,"xxpp",rec,ptr,sizeof(rhp_mem_blk),rec,( rec->size > 4 ? 4 : rec->size ),ptr);

	if( rec->flag ){
		rhp_mem_statistics_free(rec->size);
	}

	rec->tag[0] = '%';
	rec->tag[1] = '%';
	rec->tag[2] = '%';
	rec->tag[3] = '%';

	rec->old_cur = rec->cur;
	rec->cur = NULL;

	for( i = 0; i < RHP_DBG_MEM_CALLER_REC_NUM; i++ ){
		rec->old_owner[i] = rec->owner[i];
		rec->owner[i] = NULL;
	}

	if( !rec->from_pool ){
		memset((rec + 1),0x33,rec->size);
	}else{
		memset((rec + 1),0x33,RHP_MEMORY_DBUG_BLK_SIZE);
	}


	hval = ((unsigned long)ptr) % RHP_MEMORY_RECORD_HASH_SIZE;

 	pthread_mutex_lock(&(rhp_memory_dbg_lock.mutex));
 	{

 		if( rec->hash_prev == NULL ){

 			_rhp_mem_blk_hash_tbl[hval] = rec->hash_next;
 			if( rec->hash_next ){
 				rec->hash_next->hash_prev = NULL;
 			}

		}else{

			rec->hash_prev->hash_next = rec->hash_next;
			if( rec->hash_next ){
				rec->hash_next->hash_prev = rec->hash_prev;
			}
		}

 		rec->hash_next = NULL;
 		rec->hash_prev = NULL;

 		if( !rec->from_pool ){

 			RHP_TRC(0,RHPTRCID_FREE_ZERO_NOT_FROM_POOL_2,"xx",rec,ptr);
 			free(rec);

 		}else{

 			rec->lst_next = NULL;

 	  	if( _rhp_mem_record_pool_head == NULL ){
 	  		_rhp_mem_record_pool_head = rec;
 	  	}else{
 	  		_rhp_mem_record_pool_tail->lst_next = rec;
 	  	}
	    _rhp_mem_record_pool_tail = rec;

 	  	_rhp_mem_record_pool_num++;
 		}
 	}
  pthread_mutex_unlock(&(rhp_memory_dbg_lock.mutex));

  return;
}



#define RHP_MEMORY_DBG_TRC_SIZE		128

void rhp_memory_dbg_leak_print(int start_time,int elapsing_time)
{
	int i;
	rhp_mem_blk* rec;
	u64 not_freed_bytes = 0;

 	pthread_mutex_lock(&(rhp_memory_dbg_lock.mutex));
 	{
 		RHP_TRCF(RHPTRCID_MEM_DBG_LEAK_PRINT,"ddddd",_rhp_mem_record_pool_num,_rhp_mem_record_newly_alloc,_rhp_mem_alloc_big_record,start_time,elapsing_time);

 		for( i = 0; i < RHP_MEMORY_RECORD_HASH_SIZE; i++ ){

 			rec = _rhp_mem_blk_hash_tbl[i];

 			while( rec ){

 				int dump_len = rec->size;
 				time_t now = _rhp_get_time();

 				if( start_time < 1 && elapsing_time < 1 ){
 					goto write_rec;
 				}

 				if( rec->time <= (_rhp_mem_dbg_startup_time + start_time) ){
 					goto next;
 				}

 				if( (int)(now - rec->time) > elapsing_time ){

write_rec:
 					if( rec->size > RHP_MEMORY_DBG_TRC_SIZE ){
 						dump_len = RHP_MEMORY_DBG_TRC_SIZE;
 					}

 					RHP_TRCF(RHPTRCID_MEM_DBG_NOT_FREED_ADDRESS,"xdsdfddYYYYYYYYYYYYYYYYp",(rec + 1),rec->size,rec->file_name,rec->file_line,rec->thread_id,(u32)(now - rec->time),(u32)(rec->time),rec->owner[0],rec->owner[1],rec->owner[2],rec->owner[3],rec->owner[4],rec->owner[5],rec->owner[6],rec->owner[7],rec->old_owner[0],rec->old_owner[1],rec->old_owner[2],rec->old_owner[3],rec->old_owner[4],rec->old_owner[5],rec->old_owner[6],rec->old_owner[7],dump_len,(rec + 1));
 					not_freed_bytes += rec->size;
 				}

next:
 				rec = rec->hash_next;
 			}
 		}

 	}
  pthread_mutex_unlock(&(rhp_memory_dbg_lock.mutex));

  RHP_TRCF(RHPTRCID_MEM_DBG_LEAK_PRINT_END,"q",not_freed_bytes);

  return;
}

#endif // RHP_MEMORY_DBG


void rhp_pkt_udp_csum_test(rhp_packet* pkt)
{
  rhp_proto_ether* ethh = pkt->l2.eth;

  if( ethh == NULL ){
  	RHP_BUG("");
  	return;
  }

	if( ethh->protocol == RHP_PROTO_ETH_IP ){

		rhp_proto_ip_v4* iph = (rhp_proto_ip_v4*)(ethh + 1);

		if( iph->protocol == RHP_PROTO_IP_UDP ){

			rhp_proto_udp* udph = (rhp_proto_udp*)( ((u8*)iph) + iph->ihl*4 );
			u16 ip_org_csum = iph->check_sum;
			u16 udp_org_csum = udph->check_sum;
			u16 ip_test_csum = _rhp_proto_ip_v4_set_csum(iph);
			u16 udp_test_csum = _rhp_proto_ip_v4_udp_set_csum(iph->src_addr,iph->dst_addr,udph);

			RHP_TRC(0,RHPTRCID_TEST_UDP_CKSUM,"ppwwww",sizeof(rhp_proto_ip_v4),iph,sizeof(rhp_proto_udp),udph,ip_org_csum,udp_org_csum,ip_test_csum,udp_test_csum);

//				iph->check_sum = ip_org_csum;
//				udph->check_sum = udp_org_csum;
		}
	}
}

void _rhp_dbg_time_bomb(void* ctx)
{
	_rhp_panic();
}



#ifdef RHP_REFCNT_DEBUG
#ifdef RHP_REFCNT_DEBUG_X

void* rhp_refcnt_dbg_get(void* obj_or_ref)
{
	u8* tag = (u8*)obj_or_ref;

	if( obj_or_ref == NULL ){
		return NULL;
	}

	if( (tag[0] == '#' && tag[1] == 'V' && tag[2] == 'P' && tag[3] == 'N') || // struct rhp_vpn*
			(tag[0] == '#' && tag[1] == 'R' && tag[2] == 'P' && tag[3] == 'K') || // struct rhp_packet*
			(tag[0] == '#' && tag[1] == 'R' && tag[2] == 'D' && tag[3] == 'S') ){ // struct rhp_radius_session*

		return (void*)obj_or_ref;

	}else if( tag[0] == '#' && tag[1] == 'R' && tag[2] == 'F' && tag[3] == 'D'){

		return (void*)(((rhp_refcnt_dbg*)obj_or_ref)->obj);
	}

	RHP_BUG("");
	return NULL;
}


rhp_mutex_t rhp_refcnt_dbg_lock;
static rhp_refcnt_dbg* _rhp_refcnt_dbg_head = NULL;

rhp_refcnt_dbg* rhp_refcnt_dbg_alloc(void* obj,const char* file,int line)
{
	rhp_refcnt_dbg* dref = (rhp_refcnt_dbg*)_rhp_malloc(sizeof(rhp_refcnt_dbg));

	if( dref ){

		memset(dref,0,sizeof(rhp_refcnt_dbg));

		dref->tag[0] = '#';
		dref->tag[1] = 'R';
		dref->tag[2] = 'F';
		dref->tag[3] = 'D';

		dref->obj = obj;

		strncpy(dref->file,file,RHP_REFCNT_DBG_FILE_LEN);
		dref->line = line;

		dref->thread_id = gettid();

#ifdef RHP_DBG_FUNC_TRC
		dref->cur = rhp_func_trc_call_stack[rhp_func_trc_call_stack_idx];

	{
		int i;

		for( i = 1; i <= RHP_REFCNT_CALLER_NUM; i++ ){

			if( rhp_func_trc_call_stack_idx > i ){
				dref->owner[i - 1] = rhp_func_trc_call_stack[rhp_func_trc_call_stack_idx - i];
			}else{
				dref->owner[i - 1] = NULL;
			}
		}
	}
#endif // RHP_DBG_FUNC_TRC

		RHP_LOCK(&rhp_refcnt_dbg_lock);
		dref->next = _rhp_refcnt_dbg_head;
		_rhp_refcnt_dbg_head = dref;
		RHP_UNLOCK(&rhp_refcnt_dbg_lock);

	}else{
		RHP_BUG("");
	}

	return dref;
}

void* rhp_refcnt_dbg_free(void* obj_or_ref)
{
	u8* tag = (u8*)obj_or_ref;

	if( tag[0] == '#' && tag[1] == 'R' && tag[2] == 'F' && tag[3] == 'D' ){

		void* obj = (rhp_vpn*)((rhp_refcnt_dbg*)obj_or_ref)->obj;
		rhp_refcnt_dbg* dref = (rhp_refcnt_dbg*)obj_or_ref;
		rhp_refcnt_dbg *dref_tmp = NULL,*dref_tmp_pre = NULL;


		RHP_LOCK(&rhp_refcnt_dbg_lock);

		dref_tmp = _rhp_refcnt_dbg_head;

		while( dref_tmp ){

			if( dref_tmp == dref ){

				if( dref_tmp_pre ){
					dref_tmp_pre->next = dref_tmp->next;
				}else{
					_rhp_refcnt_dbg_head = dref_tmp->next;
				}

				break;
			}

			dref_tmp_pre = dref_tmp;
			dref_tmp = dref_tmp->next;
		}
		RHP_UNLOCK(&rhp_refcnt_dbg_lock);

		_rhp_free(obj_or_ref);

		return obj;

	}else if( tag[0] == '#' &&
				((tag[1] >= 'A' && tag[1] <= 'Z') || (tag[1] >= 'a' && tag[1] <= 'z')) &&
				((tag[2] >= 'A' && tag[2] <= 'Z') || (tag[2] >= 'a' && tag[2] <= 'z')) &&
				((tag[3] >= 'A' && tag[3] <= 'Z') || (tag[3] >= 'a' && tag[3] <= 'z')) ){

		return obj_or_ref;
	}

	RHP_BUG("0x0x",obj_or_ref);
	return NULL;
}

void rhp_refcnt_dbg_print()
{
	rhp_refcnt_dbg* dref;

	RHP_LOCK(&rhp_refcnt_dbg_lock);

	dref = _rhp_refcnt_dbg_head;

	while( dref ){

		void* obj = rhp_refcnt_dbg_get(dref);

		if( obj == NULL ){

			RHP_BUG("");

		}else{

			u8* tag = (u8*)obj;

			if( tag[0] == '#' && tag[1] == 'V' && tag[2] == 'P' && tag[3] == 'N'){ // struct rhp_vpn*

				RHP_TRCF(RHPTRCID_VPN_REF_DBG_PRINT,"sxxfsddYYYYYYYY"," rhp_vpn* ",dref,dref->obj,dref->thread_id,dref->file,dref->line,((rhp_vpn*)(dref->obj))->refcnt.c,dref->owner[0],dref->owner[1],dref->owner[2],dref->owner[3],dref->owner[4],dref->owner[5],dref->owner[6],dref->owner[7]);

			}else if( tag[0] == '#' && tag[1] == 'R' && tag[2] == 'P' && tag[3] == 'K' ){ // struct rhp_packet*

				RHP_TRCF(RHPTRCID_VPN_REF_DBG_PRINT,"sxxfsddYYYYYYYY"," rhp_packet* ",dref,dref->obj,dref->thread_id,dref->file,dref->line,((rhp_packet*)(dref->obj))->refcnt.c,dref->owner[0],dref->owner[1],dref->owner[2],dref->owner[3],dref->owner[4],dref->owner[5],dref->owner[6],dref->owner[7]);

			}else{

				char tag_str[5];

				tag_str[0] = tag[0];
				tag_str[1] = tag[1];
				tag_str[2] = tag[2];
				tag_str[3] = tag[3];
				tag_str[4] = '\0';

				if( tag_str[0] == '#' &&
						((tag_str[1] >= 'A' && tag_str[1] <= 'Z') || (tag_str[1] >= 'a' && tag_str[1] <= 'z')) &&
						((tag_str[2] >= 'A' && tag_str[2] <= 'Z') || (tag_str[2] >= 'a' && tag_str[2] <= 'z')) &&
						((tag_str[3] >= 'A' && tag_str[3] <= 'Z') || (tag_str[3] >= 'a' && tag_str[3] <= 'z')) ){

					RHP_TRCF(RHPTRCID_VPN_REF_DBG_PRINT,"sxxfsddYYYYYYYY",tag_str,dref,dref->obj,dref->thread_id,dref->file,dref->line,((rhp_packet*)(dref->obj))->refcnt.c,dref->owner[0],dref->owner[1],dref->owner[2],dref->owner[3],dref->owner[4],dref->owner[5],dref->owner[6],dref->owner[7]);

				}else{

					RHP_TRCF(RHPTRCID_VPN_REF_DBG_PRINT,"sxxfsddYYYYYYYY"," unknown* ",dref,dref->obj,dref->thread_id,dref->file,dref->line,((rhp_packet*)(dref->obj))->refcnt.c,dref->owner[0],dref->owner[1],dref->owner[2],dref->owner[3],dref->owner[4],dref->owner[5],dref->owner[6],dref->owner[7]);
				}
			}
		}

		dref = dref->next;
	}

	RHP_UNLOCK(&rhp_refcnt_dbg_lock);

	return;
}


int rhp_refcnt_dbg_init()
{
  _rhp_mutex_init("RFD",&(rhp_refcnt_dbg_lock));
  return 0;
}

int rhp_refcnt_dbg_cleanup()
{
	_rhp_mutex_destroy(&(rhp_refcnt_dbg_lock));
  return 0;
}

#endif // RHP_REFCNT_DEBUG_X
#endif // RHP_REFCNT_DEBUG


#ifdef RHP_IKEV2_INTEG_ERR_DBG

struct _rhp_ikev2_dbg_integ_err_ctx {
	u16 notify_mesg_type;
};
typedef struct _rhp_ikev2_dbg_integ_err_ctx	rhp_ikev2_dbg_integ_err_ctx;

static int rhp_ikev2_dbg_tx_integ_error_rep_plds_cb(rhp_ikev2_mesg* tx_ikemesg,void* ctx)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;
  rhp_ikev2_dbg_integ_err_ctx* plds_cb_ctx = (rhp_ikev2_dbg_integ_err_ctx*)ctx;

  if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
    RHP_BUG("");
    goto error;
  }

  tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

  ikepayload->ext.n->set_protocol_id(ikepayload,0);
  ikepayload->ext.n->set_message_type(ikepayload,plds_cb_ctx->notify_mesg_type);

  return 0;

error:
	return err;
}

int rhp_ikev2_dbg_tx_integ_err_notify(rhp_packet* rx_pkt,u16 notify_mesg_type)
{
  int err = -EINVAL;
  rhp_proto_ip_v4* iph_i;
  rhp_proto_udp* udph_i;
  rhp_proto_ike* ikeh_i;
  rhp_ifc_entry* rx_ifc;
  rhp_ikev2_dbg_integ_err_ctx pld_cb_ctx;
  int i;

  RHP_TRC(0,RHPTRCID_IKEV2_DBG_TX_INTEG_ERR_NOTIFY,"xLw",rx_pkt,"PROTO_IKE_NOTIFY",notify_mesg_type);

  if( rx_pkt->type != RHP_PKT_IPV4_IKE ){
  	RHP_BUG("");
  	// TODO: IPv6 Support.
  	return -EINVAL;
  }

  iph_i = rx_pkt->l3.iph_v4;
  udph_i = rx_pkt->l4.udph;
  ikeh_i = rx_pkt->app.ikeh;
  rx_ifc = rx_pkt->rx_ifc;

  memset(&pld_cb_ctx,0,sizeof(rhp_ikev2_dbg_integ_err_ctx));
  pld_cb_ctx.notify_mesg_type = notify_mesg_type;

  for( i = 0; i < 10; i++ ){

  	err = rhp_ikev2_tx_plain_error_rep_v4(iph_i,udph_i,ikeh_i,rx_ifc,
				rhp_ikev2_dbg_tx_integ_error_rep_plds_cb,(void*)&pld_cb_ctx);

		if( err ){
			goto error;
		}
  }

  RHP_TRC(0,RHPTRCID_IKEV2_DBG_TX_INTEG_ERR_NOTIFY_RTRN,"x",rx_pkt);
  return 0;

error:

  RHP_TRC(0,RHPTRCID_IKEV2_DBG_TX_INTEG_ERR_NOTIFY_ERR,"xE",rx_pkt,err);
  return err;
}

int rhp_ikev2_dbg_rx_integ_err_notify(rhp_packet* rx_pkt)
{
  RHP_TRC(0,RHPTRCID_IKEV2_DBG_RX_INTEG_ERR_NOTIFY,"x",rx_pkt);

  RHP_TRC(0,RHPTRCID_IKEV2_DBG_RX_INTEG_ERR_NOTIFY_RTRN,"x",rx_pkt);
	return 0;
}

#else // RHP_IKEV2_INTEG_ERR_DBG

int rhp_ikev2_dbg_tx_integ_err_notify(rhp_packet* rx_pkt,u16 notify_mesg_type)
{
	return 0;
}

int rhp_ikev2_dbg_rx_integ_err_notify(rhp_packet* rx_pkt)
{
	return 0;
}

#endif // RHP_IKEV2_INTEG_ERR_DBG

