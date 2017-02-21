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
#include <sched.h>
#include <sys/capability.h>
#include <linux/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_wthreads.h"
#include "rhp_config.h"

//
// TODO : Control allocatable task(resource) numbers by VPN realm priorities.
//

//
// TODO : Dispatching rule(policy) by VPN realms. (Example policy : A task worker is reserved for a vpn realm ONLY.)
//

static rhp_mutex_t _rhp_wts_lock;

struct _rhp_wts_ctrl_task_ctx {

  void *task_ctx;
  rhp_atomic_t refcnt;

  void (*ctx_destructor)(void* ctx);
};
typedef struct _rhp_wts_ctrl_task_ctx	rhp_wts_ctrl_task_ctx;

struct _rhp_wts_task {

  unsigned char tag[4]; // "#WTT"

  struct _rhp_wts_task* next;
  struct _rhp_wts_task* add_ctrl_task_next;

  rhp_wts_ctrl_task_ctx* ctrl_task_ctx;
  void* task_ctx;
  void (*task_handler)(int worker_index,void *task_ctx);

  int stationed;
  int sta_task_name;
  int (*do_exec)(int worker_index,void* task_ctx);
  int (*add_ctx)(int worker_index,void* task_ctx,void* ctx);
};
typedef struct _rhp_wts_task  rhp_wts_task;


struct _rhp_wts_worker_q {
  rhp_wts_task* task_lst_head;
  rhp_wts_task* task_lst_tail;
};
typedef struct _rhp_wts_worker_q rhp_wts_worker_q;

rhp_wts_worker_statistics* rhp_wts_worker_statistics_tbl;


struct _rhp_wts_worker {

  unsigned char tag[4]; // "#WTW"

  rhp_wts_worker_q task_q[RHP_WTS_DISP_LEVEL_MAX + 1];

  rhp_wts_task* sta_task[RHP_WTS_STA_TASK_NAME_MAX + 1][RHP_WTS_DISP_LEVEL_MAX + 1];

  int idx;

  rhp_thread_t thread;
  rhp_cond_t evt;
  rhp_mutex_t lock;

  int is_misc_worker;

  int yield_limit;
};
typedef struct _rhp_wts_worker  rhp_wts_worker;

#define RHP_WTS_Q_HEAD(worker,level) 		((worker)->task_q[(level)].task_lst_head)
#define RHP_WTS_Q_TAIL(worker,level) 			((worker)->task_q[(level)].task_lst_tail)
#define RHP_WTS_STA(worker,task_name,level) 					((worker)->sta_task[(task_name)][(level)])

static int _rhp_gcfg_wts_workers = 0;
// "+2" : Including rhp_wts_fixed_worker(RHP_WTS_DISP_RULE_MISC) and
//        rhp_wts_fixed_blocking_worker(RHP_WTS_DISP_RULE_MISC_BLOCKING).
#define RHP_WTS_ALL_WORKERS_NUM	(_rhp_gcfg_wts_workers + 2)

struct _rhp_wts_disp_rule {

  unsigned char tag[4]; // "#WTR"

  unsigned long type; /* RHP_WTS_DISP_RULE_XXX */
  u32 (*disp_hash)(void *key_seed,int* err);
};
typedef struct _rhp_wts_disp_rule  rhp_wts_disp_rule;

static rhp_wts_worker* rhp_wts_worker_list = NULL;
static rhp_wts_worker rhp_wts_fixed_worker;
static rhp_wts_worker rhp_wts_fixed_blocking_worker;

#ifdef RHP_EVENT_FUNCTION
static rhp_wts_worker rhp_wts_event_worker;
#endif // RHP_EVENT_FUNCTION

static rhp_wts_disp_rule* rhp_wts_disp_rule_list = NULL;

static rhp_atomic_t _rhp_wts_cur_tasks;
static rhp_atomic_t _rhp_wts_cur_tasks_lower_priority;
static volatile int _rhp_wts_disp_waiting = 0;
static rhp_cond_t _rhp_wts_max_check_evt;

static rhp_wts_task* _rhp_wts_task_pool = NULL;
static long _rhp_wts_task_pool_num = 0;

static __thread long _rhp_wts_worker_id_tls = -1;


static void _rhp_wts_free_task(rhp_wts_task* task)
{
	if( task->ctrl_task_ctx ){
		_rhp_free(task->ctrl_task_ctx);
	}
	_rhp_free(task);
}

int rhp_wts_dispach_ok(int disp_priority,int is_fixed_rule)
{
  int ret;

  if( disp_priority < RHP_WTS_DISP_LEVEL_HIGH_1 ){
  	RHP_TRC_FREQ(0,RHPTRCID_WTS_DISP_1,"",1);
  	ret = 1;
  	goto end;
  }

  if( disp_priority == RHP_WTS_DISP_LEVEL_HIGH_1 ){

  	ret = ( _rhp_atomic_read(&_rhp_wts_cur_tasks) <= rhp_gcfg_wts_max_worker_tasks );

  	RHP_TRC_FREQ(0,RHPTRCID_WTS_DISP_2,"dd",_rhp_wts_cur_tasks.c,rhp_gcfg_wts_max_worker_tasks);

  }else{

    if( !is_fixed_rule ){
      ret = ( _rhp_atomic_read(&_rhp_wts_cur_tasks_lower_priority) <= rhp_gcfg_wts_max_worker_tasks_low_priority );
    }else{
      ret = ( _rhp_atomic_read(&_rhp_wts_cur_tasks_lower_priority) <= rhp_gcfg_wts_max_worker_tasks_low_priority/3 );
    }

  	RHP_TRC_FREQ(0,RHPTRCID_WTS_DISP_3,"dd",_rhp_wts_cur_tasks_lower_priority.c,rhp_gcfg_wts_max_worker_tasks_low_priority);
  }

end:

	RHP_TRC_FREQ(0,RHPTRCID_WTS_DISP,"Lddd","WTS_DISP_LEVEL_FLAG",disp_priority,is_fixed_rule,ret);
  return ret;
}

int rhp_wts_dispach_check(int disp_priority,int is_fixed_rule)
{
  int err;

  RHP_LOCK(&_rhp_wts_lock);

  while( !rhp_wts_dispach_ok(disp_priority,is_fixed_rule) ){

    _rhp_wts_disp_waiting++;

    if( (err = _rhp_wait_event(&_rhp_wts_max_check_evt,&_rhp_wts_lock,0) ) ){
      _rhp_wts_disp_waiting--;
      RHP_TRC_FREQ(0,RHPTRCID_WTS_DISP_CHECK_ERR,"E",err);
      goto error;
    }

    _rhp_wts_disp_waiting--;
  }

  err = 0;

error:
  RHP_UNLOCK(&_rhp_wts_lock);

  RHP_TRC_FREQ(0,RHPTRCID_WTS_DISP_CHECK,"LddE","WTS_DISP_LEVEL_FLAG",disp_priority,is_fixed_rule,err);
  return err;
}

static void _rhp_wts_dispach_restart()
{
  int flag = 0;
  if( _rhp_wts_disp_waiting && rhp_wts_dispach_ok(0,0) ){
    RHP_EVT_NOTIFY_ALL(&_rhp_wts_max_check_evt);
    flag = 1;
  }
  RHP_TRC_FREQ(0,RHPTRCID_WTS_DISP_RESTAT,"d",flag);
}

int rhp_wts_register_disp_rule(unsigned long type/*RHP_WTS_DISP_RULE_XXX*/,u32 (*disp_hash)(void *key_seed,int* err))
{
  if( type > RHP_WTS_DISP_RULE_MAX ){
    RHP_BUG("%d",type);
    return -EINVAL;
  }

  if( rhp_wts_disp_rule_list[type].tag[0] ){
    RHP_BUG("%d",type);
    return -EEXIST;
  }

  rhp_wts_disp_rule_list[type].tag[0] = '#';
  rhp_wts_disp_rule_list[type].tag[1] = 'W';
  rhp_wts_disp_rule_list[type].tag[2] = 'T';
  rhp_wts_disp_rule_list[type].tag[3] = 'R';

  rhp_wts_disp_rule_list[type].type = type;
  rhp_wts_disp_rule_list[type].disp_hash = disp_hash;

  RHP_TRC_FREQ(0,RHPTRCID_WTS_DISP_RULE,"LuY","WTS_DISP_RULE_FLAG",type,disp_hash);
  return 0;
}

static rhp_wts_task* _rhp_wts_alloc_task_raw()
{
  rhp_wts_task* task = (rhp_wts_task*)_rhp_malloc(sizeof(rhp_wts_task));
  if( task == NULL ){
    RHP_BUG("");
    return NULL;
  }
  memset(task,0,sizeof(rhp_wts_task));

  task->tag[0] = '#';
  task->tag[1] = 'W';
  task->tag[2] = 'T';
  task->tag[3] = 'T';

  return task;
}

static rhp_wts_task* _rhp_wts_alloc_task(int disp_priority)
{
  rhp_wts_task *task,*task2;
  int i;

  task = _rhp_wts_alloc_task_raw();

  if( task == NULL ){

    RHP_LOCK(&_rhp_wts_lock);

  	if( (_rhp_wts_task_pool != NULL ) && (disp_priority <= RHP_WTS_DISP_LEVEL_HIGH_1) ){

			task = _rhp_wts_task_pool;
			_rhp_wts_task_pool = task->next;

			_rhp_wts_task_pool_num--;
			task->next = NULL;

			RHP_TRC_FREQ(0,RHPTRCID_WTS_ALLOC_TASK_FROM_POOL,"dd",_rhp_wts_task_pool_num,rhp_gcfg_wts_max_task_pool_num);

		  if( _rhp_wts_task_pool_num <= rhp_gcfg_wts_max_task_pool_num/10*5 ){

		    RHP_TRC_FREQ(0,RHPTRCID_WTS_ALLOC_TASK_REALLOC_POOL,"dd",_rhp_wts_task_pool_num,rhp_gcfg_wts_max_task_pool_num);

		    for( i = _rhp_wts_task_pool_num; i < rhp_gcfg_wts_max_task_pool_num; i++){

		      task2 = _rhp_wts_alloc_task_raw();
		      if( task2 == NULL ){
		      	break;
		      }

		      if( task == NULL ){

		        task = task2;

		      }else{

		        task2->next = _rhp_wts_task_pool;
		        _rhp_wts_task_pool = task2;

		        _rhp_wts_task_pool_num++;
		      }
		    }
		  }

			RHP_UNLOCK(&_rhp_wts_lock);
  	}
  }

  RHP_TRC_FREQ(0,RHPTRCID_WTS_ALLOC_TASK,"xLddd",task,"WTS_DISP_LEVEL_FLAG",disp_priority,_rhp_wts_task_pool_num,rhp_gcfg_wts_max_task_pool_num);

  return task;
}

//
// *****[CAUTION]*******
//
//    All callback functions except task_handler() DON'T call RHP_BUG("") or rhp_log_write()!
//    These trace/log apis may internally call rhp_wts_sta_invoke_task(), so the call will be
//    deadlock!
//
// *****[CAUTION]*******
//
//
// [CAUTION]
//  rhp_wts_fixed_blocking_worker is NOT applied for this STA task.
//
int rhp_wts_sta_register_task(int task_name,int disp_priority,void (*task_handler)(int worker_index,void *ctx),
		int (*do_exec)(int worker_index,void* ctx),int (*add_ctx)(int worker_index,void* task_ctx,void* ctx),void* task_ctx)
{
	int err = -EINVAL;
	int i;

  RHP_TRC_FREQ(0,RHPTRCID_WTS_STA_REGISTER_TASK,"LdLdYYx","WTS_DISP_TASK_NAME",task_name,"WTS_DISP_LEVEL_FLAG",disp_priority,task_handler,do_exec,task_ctx);

  if( !RHP_PROCESS_IS_ACTIVE() ){
    RHP_TRC_FREQ(0,RHPTRCID_WTS_REGISTER_STA_TASK_NOT_ACTIVE,"");
    return -EINVAL;
  }

  if( task_handler == NULL || do_exec == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  for( i = 0; i <= _rhp_gcfg_wts_workers; i++){

  	rhp_wts_worker* worker;
    rhp_wts_task* task;

    if( i == _rhp_gcfg_wts_workers ){
    	worker = &rhp_wts_fixed_worker;
    }else{
    	worker = &(rhp_wts_worker_list[i]);
    }

    RHP_LOCK(&(worker->lock));

  	task = worker->sta_task[task_name][disp_priority];

  	if( task ){

  		RHP_BUG("");

  		RHP_UNLOCK(&(worker->lock));

  		err = -EINVAL;
    	goto error;
  	}

  	task = _rhp_wts_alloc_task(disp_priority);
  	if( task == NULL ){

  		RHP_BUG("");

  		RHP_UNLOCK(&(worker->lock));

  		err = -ENOMEM;
  	  goto error;
  	}

  	task->sta_task_name = task_name;
  	task->stationed = 1;
  	task->task_ctx = task_ctx;
  	task->do_exec = do_exec;
  	task->task_handler = task_handler;
  	task->add_ctx = add_ctx;

  	worker->sta_task[task_name][disp_priority] = task;

  	RHP_UNLOCK(&(worker->lock));
  }


  RHP_TRC_FREQ(0,RHPTRCID_WTS_STA_REGISTER_TASK_RTRN,"LdLdYYx","WTS_DISP_TASK_NAME",task_name,"WTS_DISP_LEVEL_FLAG",disp_priority,task_handler,do_exec,task_ctx);
  return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_WTS_STA_REGISTER_TASK_ERR,"LdLdYYx","WTS_DISP_TASK_NAME",task_name,"WTS_DISP_LEVEL_FLAG",disp_priority,task_handler,do_exec,task_ctx);
	return err;
}

static rhp_wts_worker* _rhp_wts_select_worker(unsigned long type/*RHP_WTS_DISP_RULE_XXX*/,void *key_seed)
{
  int err = 0;
  rhp_wts_disp_rule *drule;
  u32 hash;
  rhp_wts_worker* worker = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_WTS_SELECT_WORKER,"Ldx","WTS_DISP_RULE_FLAG",type,key_seed);

  if( type == RHP_WTS_DISP_RULE_MISC ){

    worker = &rhp_wts_fixed_worker;

  }else if( type == RHP_WTS_DISP_RULE_MISC_BLOCKING ){

    worker = &rhp_wts_fixed_blocking_worker;

#ifdef RHP_EVENT_FUNCTION
  }else if( type == RHP_WTS_DISP_RULE_EVENT ){

    worker = &rhp_wts_event_worker;
#endif // RHP_EVENT_FUNCTION

  }else if( type == RHP_WTS_DISP_RULE_SAME_WORKER || type == RHP_WTS_DISP_RULE_RAND ){

  	if( type == RHP_WTS_DISP_RULE_SAME_WORKER &&
  			_rhp_wts_worker_id_tls >= 0 && _rhp_wts_worker_id_tls < _rhp_gcfg_wts_workers ){

  		worker = &(rhp_wts_worker_list[_rhp_wts_worker_id_tls]);

  	}else{

  		unsigned int seed = _rhp_get_time();

  		hash = (u32)rand_r(&seed);
  		hash = hash % _rhp_gcfg_wts_workers;

  		worker = &(rhp_wts_worker_list[hash]);
  	}

  }else{

    if( type > RHP_WTS_DISP_RULE_MAX ){
      RHP_BUG("%d",type);
      goto error;
    }

    if( rhp_wts_disp_rule_list[type].tag[0] == 0 ){
      RHP_BUG("%d",type);
      goto error;
    }

    drule = &(rhp_wts_disp_rule_list[type]);

    if( drule->disp_hash == NULL ){
      RHP_BUG("%d",type);
      goto error;
    }

    hash = drule->disp_hash(key_seed,&err);
    if( err ){
      RHP_BUG("%d,err:%d",type,err);
      goto error;
    }
    hash = hash % _rhp_gcfg_wts_workers;

    worker = &(rhp_wts_worker_list[hash]);
  }

error:

	RHP_TRC_FREQ(0,RHPTRCID_WTS_SELECT_WORKER_RTRN,"Ldxx","WTS_DISP_RULE_FLAG",type,key_seed,worker);
	return worker;
}

//
// *****[CAUTION]*******
//
//    All callback functions except task_handler() DON'T call RHP_BUG("") or rhp_log_write()!
//    These trace/log apis may internally call rhp_wts_sta_invoke_task(), so the call will be
//    deadlock! Also see rhp_wts_sta_register_task().
//
// *****[CAUTION]*******
//
int rhp_wts_sta_invoke_task(unsigned long type/*RHP_WTS_DISP_RULE_XXX*/,
		int task_name,int disp_priority,void *key_seed,void* ctx)
{
  rhp_wts_task *task = NULL;
  int err = 0;
  rhp_wts_worker *worker;
  int notify_flag = 0;

  RHP_TRC_FREQ(0,RHPTRCID_WTS_INVOKE_STA_TASK,"LuLdLdxx","WTS_DISP_RULE_FLAG",type,"WTS_DISP_TASK_NAME",task_name,"WTS_DISP_LEVEL_FLAG",disp_priority,key_seed,ctx);

  if( !RHP_PROCESS_IS_ACTIVE() ){
    RHP_TRC_FREQ(0,RHPTRCID_WTS_ADD_TASK_NOT_ACTIVE,"");
    err = -EINVAL;
    goto error;
  }

  worker = _rhp_wts_select_worker(type,key_seed);
  if( worker == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_WTS_ADD_TASK_NO_WORKER_FOUND,"");
    err = -EINVAL;
    goto error;
  }

  RHP_LOCK(&(worker->lock));

  task = worker->sta_task[task_name][disp_priority];

  if( task ){

		notify_flag = ( !(task->do_exec(worker->idx,task->task_ctx)) ? 1 : 0 );

		if( ctx && worker->sta_task[task_name][disp_priority]->add_ctx ){

			err = worker->sta_task[task_name][disp_priority]->add_ctx(worker->idx,task->task_ctx,ctx);
			if( err ){
			  RHP_TRC_FREQ(0,RHPTRCID_WTS_INVOKE_STA_TASK_ADD_CTX_ERR,"LuLdLdxxE","WTS_DISP_RULE_FLAG",type,"WTS_DISP_TASK_NAME",task_name,"WTS_DISP_LEVEL_FLAG",disp_priority,key_seed,ctx,err);
				goto error_l;
			}
		}

		if( notify_flag ){

			if( (err = RHP_EVT_NOTIFY(&(worker->evt))) ){
				err = -err;
			  RHP_TRC_FREQ(0,RHPTRCID_WTS_INVOKE_STA_TASK_NOTIFY_ERR,"LuLdLdxxE","WTS_DISP_RULE_FLAG",type,"WTS_DISP_TASK_NAME",task_name,"WTS_DISP_LEVEL_FLAG",disp_priority,key_seed,ctx,err);
				goto error_l;
			}
		}

  }else{
	  RHP_TRC_FREQ(0,RHPTRCID_WTS_INVOKE_STA_TASK_NOT_DEFINED,"LuLdLdxx","WTS_DISP_RULE_FLAG",type,"WTS_DISP_TASK_NAME",task_name,"WTS_DISP_LEVEL_FLAG",disp_priority,key_seed,ctx);
	  RHP_BUG("");
  }

  RHP_UNLOCK(&(worker->lock));

  RHP_TRC_FREQ(0,RHPTRCID_WTS_INVOKE_STA_TASK_RTRN,"LuLdLdxx","WTS_DISP_RULE_FLAG",type,"WTS_DISP_TASK_NAME",task_name,"WTS_DISP_LEVEL_FLAG",disp_priority,key_seed,ctx);
  return 0;

error_l:
	RHP_UNLOCK(&(worker->lock));
error:
  RHP_TRC_FREQ(0,RHPTRCID_WTS_INVOKE_STA_TASK_ERR,"LuLdLdxxE","WTS_DISP_RULE_FLAG",type,"WTS_DISP_TASK_NAME",task_name,"WTS_DISP_LEVEL_FLAG",disp_priority,key_seed,ctx,err);
	return err;
}


int rhp_wts_add_task(unsigned long type/*RHP_WTS_DISP_RULE_XXX*/,int disp_priority,
                     void *key_seed,void (*task_handler)(int worker_index,void *ctx),void* task_ctx)
{
  rhp_wts_task *task = NULL;
  int err = 0;
  rhp_wts_worker *worker;
  int notify_flag = 0;
  u32 hash = 0;
  rhp_wts_task **lst_h,**lst_t;

  RHP_TRC_FREQ(0,RHPTRCID_WTS_ADD_TASK,"LuLdxYx","WTS_DISP_RULE_FLAG",type,"WTS_DISP_LEVEL_FLAG",disp_priority,key_seed,task_handler,task_ctx);

  if( !RHP_PROCESS_IS_ACTIVE() ){
    RHP_TRC_FREQ(0,RHPTRCID_WTS_ADD_TASK_NOT_ACTIVE,"");
    return -EINVAL;
  }

  worker = _rhp_wts_select_worker(type,key_seed);
  if( worker == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  task = _rhp_wts_alloc_task(disp_priority);
  if( task == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  task->task_ctx = task_ctx;
  task->task_handler = task_handler;


  RHP_LOCK(&(worker->lock));

  notify_flag = ( RHP_WTS_Q_HEAD(worker,disp_priority) == NULL );
  lst_h = &(RHP_WTS_Q_HEAD(worker,disp_priority));
  lst_t = &(RHP_WTS_Q_TAIL(worker,disp_priority));

  if( (*lst_h) == NULL ){
    (*lst_h) = task;
  }else{
    (*lst_t)->next = task;
  }
  (*lst_t) = task;

  if( notify_flag ){

    if( (err = RHP_EVT_NOTIFY(&(worker->evt))) ){
      RHP_UNLOCK(&(worker->lock));
      err = -err;
      RHP_BUG("%d",err);
      goto error;
    }
  }

  _rhp_atomic_inc(&_rhp_wts_cur_tasks);
  if( disp_priority > RHP_WTS_DISP_LEVEL_HIGH_1 ){
    _rhp_atomic_inc(&_rhp_wts_cur_tasks_lower_priority);
  }

  RHP_UNLOCK(&(worker->lock));

  RHP_TRC_FREQ(0,RHPTRCID_WTS_ADD_TASK_RTRN,"LuLdxud","WTS_DISP_RULE_FLAG",type,"WTS_DISP_LEVEL_FLAG",disp_priority,task,hash,notify_flag);
  return 0;

error:
  if( task ){
    _rhp_wts_free_task(task);;
  }
  RHP_TRC_FREQ(0,RHPTRCID_WTS_ADD_TASK_ERR,"LuLdE","WTS_DISP_RULE_FLAG",type,"WTS_DISP_LEVEL_FLAG",disp_priority,err);
  return err;
}

int rhp_wts_switch_ctx(int disp_priority,void (*task)(int worker_index,void *ctx),void* ctx)
{
	return rhp_wts_add_task(RHP_WTS_DISP_RULE_SAME_WORKER,disp_priority,NULL,task,ctx);
}

//
// [CAUTION]
//  rhp_wts_fixed_worker and rhp_wts_fixed_blocking_worker is NOT applied for this ctrl task.
//
int rhp_wts_add_ctrl_task(void (*task_handler)(int worker_index,void *ctx),void (*ctx_destructor)(void* ctx),void* task_ctx)
{
  rhp_wts_task* task = NULL;
  rhp_wts_task* tasks_head = NULL;
  rhp_wts_task* tasks_tail = NULL;
  int err = 0;
  rhp_wts_worker *worker;
  int notify_flag = 0;
  rhp_wts_task **lst_h,**lst_t;
  rhp_wts_ctrl_task_ctx* ctrl_task_ctx = NULL;
  int i;

  RHP_TRC_FREQ(0,RHPTRCID_WTS_ADD_CTRL_TASK,"YYx",task_handler,ctx_destructor,task_ctx);

  if( !RHP_PROCESS_IS_ACTIVE() ){
    RHP_TRC_FREQ(0,RHPTRCID_ADD_CTRL_TASK_NOT_ACTIVE,"");
    return -EINVAL;
  }


  {
  	ctrl_task_ctx = (rhp_wts_ctrl_task_ctx*)_rhp_malloc(sizeof(rhp_wts_ctrl_task_ctx));
  	if( ctrl_task_ctx == NULL ){
  		RHP_BUG("");
  		err = -ENOMEM;
  		goto error;
  	}
  	memset(ctrl_task_ctx,0,sizeof(rhp_wts_ctrl_task_ctx));

  	_rhp_atomic_init(&(ctrl_task_ctx->refcnt));
  	_rhp_atomic_set(&(ctrl_task_ctx->refcnt),0);

  	ctrl_task_ctx->task_ctx = task_ctx;
  	ctrl_task_ctx->ctx_destructor = ctx_destructor;
  }


  for( i = 0; i < _rhp_gcfg_wts_workers; i++){

	  task = _rhp_wts_alloc_task(RHP_WTS_DISP_LEVEL_CTRL);
	  if( task == NULL ){
	    err = -ENOMEM;
	    RHP_BUG("");
	    goto error;
	  }

		task->ctrl_task_ctx = ctrl_task_ctx;
		_rhp_atomic_inc(&(task->ctrl_task_ctx->refcnt));

	  task->task_handler = task_handler;

	  if( tasks_head == NULL ){
	  	tasks_head = task;
	  }else{
	  	tasks_tail->add_ctrl_task_next = task;
	  }
  	tasks_tail = task;
  }

  task = tasks_head;
  for( i = 0; i < _rhp_gcfg_wts_workers; i++){

  	rhp_wts_task* task_nxt = task->add_ctrl_task_next;
  	tasks_head = task_nxt;

  	worker = &(rhp_wts_worker_list[i]);

  	RHP_LOCK(&(worker->lock));

	  notify_flag = ( RHP_WTS_Q_HEAD(worker,RHP_WTS_DISP_LEVEL_CTRL) == NULL );
	  lst_h = &(RHP_WTS_Q_HEAD(worker,RHP_WTS_DISP_LEVEL_CTRL));
	  lst_t = &(RHP_WTS_Q_TAIL(worker,RHP_WTS_DISP_LEVEL_CTRL));

	  if( (*lst_h) == NULL ){
	    (*lst_h) = task;
	  }else{
	    (*lst_t)->next = task;
	  }
	  (*lst_t) = task;

	  if( notify_flag ){

	    if( (err = RHP_EVT_NOTIFY(&(worker->evt))) ){
	    	RHP_UNLOCK(&(worker->lock));
	    	err = -err;
	      RHP_BUG("%d",err);
	      goto error;
	    }
	  }

	  _rhp_atomic_inc(&_rhp_wts_cur_tasks);

	  RHP_UNLOCK(&(worker->lock));

	  task = task_nxt;
  }

  RHP_TRC_FREQ(0,RHPTRCID_WTS_ADD_CTRL_TASK_RTRN,"xd",task,notify_flag);
  return 0;

error:
	task = tasks_head;
  while( task ){
  	rhp_wts_task* task_nxt = task->add_ctrl_task_next;
    _rhp_wts_free_task(task);
	  task = task_nxt;
  }

  RHP_TRC_FREQ(0,RHPTRCID_WTS_ADD_CTRL_TASK_ERR,"E",err);
  return err;
}


static rhp_wts_task* _rhp_wts_get_task(rhp_wts_worker *worker,int* disp_priority)
{
  rhp_wts_task* task = NULL;
  rhp_wts_task **lst_h = NULL,**lst_t = NULL;
  int i = 0,j = 0;

  for( i = 0; i <= RHP_WTS_DISP_LEVEL_MAX; i++ ){

  	rhp_wts_task* sta_task;

  	if( RHP_WTS_Q_HEAD(worker,i) ){

  		lst_h = &(RHP_WTS_Q_HEAD(worker,i));
    	lst_t = &(RHP_WTS_Q_TAIL(worker,i));

    	task  = (*lst_h);

    	if( (*lst_h) == (*lst_t) ){
    		(*lst_t) = (*lst_t)->next;
    	}
    	(*lst_h) = (*lst_h)->next;

    	*disp_priority = i;
    	break;
    }

  	for( j = 0; j <= RHP_WTS_STA_TASK_NAME_MAX ; j++  ){

  		sta_task = RHP_WTS_STA(worker,j,i);

			if( sta_task ){

				if( sta_task->do_exec(worker->idx,sta_task->task_ctx) ){

					task = sta_task;
					*disp_priority = i;
					break;
				}
			}
  	}
  }

  if( task ){
  	RHP_TRC_FREQ(0,RHPTRCID_WTS_GET_TASK,"xdLdxdY",worker,worker->idx,"WTS_DISP_LEVEL_FLAG",*disp_priority,task,task->stationed,task->task_handler);
  }else{
  	RHP_TRC_FREQ(0,RHPTRCID_WTS_GET_TASK_NO_TASK,"xd",worker,worker->idx);
  }
  return task;
}


extern void rhp_vpn_unique_ids_init_tls();
extern void rhp_esp_impl_init_tls(); // TODO : Supporting a case without default ESP impl...(NO SYMBOL for this!)


static void* _rhp_wts_worker_run(void* arg)
{
  rhp_wts_worker *worker = (rhp_wts_worker*)arg;
  int err;
  rhp_wts_task* task = NULL;
  int c = 0;
  int disp_priority = 0;

  RHP_TRC(0,RHPTRCID_WTS_WORKER_RUN,"x",worker);

  err = rhp_sig_clear();
  if( err ){
  	RHP_BUG("%",err);
  	return NULL;
  }

  rhp_trace_tid = gettid();
  _rhp_wts_worker_id_tls = worker->idx;

  rhp_vpn_unique_ids_init_tls();
  rhp_esp_impl_init_tls();

  RHP_TRC(0,RHPTRCID_WTS_WORKER_RUN_START,"xdd",worker,worker->idx,worker->is_misc_worker);

  while( 1 ){

restart:
    RHP_LOCK(&(worker->lock));

    while( task == NULL ){

    	disp_priority = 0;

      if( (task = _rhp_wts_get_task(worker,&disp_priority) ) ){
        break;
      }

      if( !RHP_PROCESS_IS_ACTIVE() ){
        RHP_UNLOCK(&(worker->lock));
        RHP_TRC_FREQ(0,RHPTRCID_WTS_WORKER_RUN_NOT_ACTIVE,"");
        goto out;
      }

      c = 0;
      if( (err = _rhp_wait_event(&(worker->evt),&(worker->lock),0) ) ){
        RHP_UNLOCK(&(worker->lock));
        goto restart;
      }
    }

    RHP_UNLOCK(&(worker->lock));

    if( task->task_handler ){

    	void* ctx = ( task->ctrl_task_ctx ? task->ctrl_task_ctx->task_ctx : task->task_ctx );

      RHP_TRC_FREQ(0,RHPTRCID_WTS_WORKER_RUN_EXEC_START,"LdxddxYx","WTS_DISP_LEVEL_FLAG",disp_priority,worker,worker->idx,worker->is_misc_worker,task,task->task_handler,ctx);

      task->task_handler(worker->idx,ctx);

      RHP_TRC_FREQ(0,RHPTRCID_WTS_WORKER_RUN_EXEC_END,"LdxddxYx","WTS_DISP_LEVEL_FLAG",disp_priority,worker,worker->idx,worker->is_misc_worker,task,task->task_handler,ctx);

    	rhp_wts_worker_statistics_tbl[worker->idx].exec_tasks_counter++;

    	if( task->ctrl_task_ctx ){

    		if( _rhp_atomic_dec_and_test(&(task->ctrl_task_ctx->refcnt)) ){

    			RHP_TRC_FREQ(0,RHPTRCID_WTS_WORKER_RUN_EXEC_CTX_DESTRUCTOR,"xdxYx",worker,worker->idx,task,task->ctrl_task_ctx->ctx_destructor,task->ctrl_task_ctx->task_ctx);

    			if( task->ctrl_task_ctx->ctx_destructor ){
    				task->ctrl_task_ctx->ctx_destructor(task->ctrl_task_ctx->task_ctx);
    			}

    		}else{

    			task->ctrl_task_ctx = NULL;
    		}
    	}

    }else{
      RHP_BUG("0x%x , %d",task,worker->idx);
    }

    if( !task->stationed ){
    	_rhp_wts_free_task(task);
    }

    task = NULL;


    RHP_LOCK(&_rhp_wts_lock);

    _rhp_atomic_dec(&_rhp_wts_cur_tasks);
    if( disp_priority > RHP_WTS_DISP_LEVEL_HIGH_1 ){
      _rhp_atomic_dec(&_rhp_wts_cur_tasks_lower_priority);
    }

    _rhp_wts_dispach_restart();

    RHP_UNLOCK(&_rhp_wts_lock);

    if( worker->yield_limit && ++c > worker->yield_limit ){
      c = 0;
      sched_yield();
    }
  }

out:
	RHP_TRC(0,RHPTRCID_WTS_WORKER_RUN_RTRN,"");
	return NULL;
}

static int _rhp_wts_worker_init(rhp_wts_worker* worker,int idx)
{
  int err = 0;

  worker->tag[0] = '#';
  worker->tag[1] = 'W';
  worker->tag[2] = 'T';
  worker->tag[3] = 'W';

  worker->idx = idx;

  _rhp_cond_init(&(worker->evt));
  _rhp_mutex_init("WWK",&(worker->lock));
  worker->yield_limit = rhp_gcfg_wts_worker_yield_limit;

  if( ( err = _rhp_thread_create(&(worker->thread),_rhp_wts_worker_run,worker)) ){
    err = -err;
    RHP_BUG("%d",err);
    goto error;
  }

error:
	RHP_TRC(0,RHPTRCID_WTS_WORKER_INIT,"xdE",worker,idx,err);
	return err;
}

int rhp_wts_get_workers_num()
{
	RHP_TRC_FREQ(0,RHPTRCID_WTS_GET_WORKERS_NUM,"d",RHP_WTS_ALL_WORKERS_NUM);

	return RHP_WTS_ALL_WORKERS_NUM;
}

long rhp_wts_is_worker()
{
	long idx = _rhp_wts_worker_id_tls;
	return ( idx >= 0 ? idx : -1);
}

int rhp_wts_get_statistics(rhp_wts_worker_statistics** tables_r,int* tables_num_r)
{
	rhp_wts_worker_statistics* tables = NULL;
	int n = rhp_wts_get_workers_num();
	int i;

	if( _rhp_wts_worker_id_tls >= 0 ){
		RHP_BUG(""); // Sorry! This func MUST NOT be called in wts's context.
		return -EINVAL;
	}

	tables = (rhp_wts_worker_statistics*)_rhp_malloc(sizeof(rhp_wts_worker_statistics)*n);
	if( tables == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	for( i = 0; i < (n - 2); i++ ){

		RHP_LOCK(&(rhp_wts_worker_list[i].lock));

		memcpy(&(tables[i]),&(rhp_wts_worker_statistics_tbl[i]),sizeof(rhp_wts_worker_statistics));

		RHP_UNLOCK(&(rhp_wts_worker_list[i].lock))
	}

	{
		RHP_LOCK(&(rhp_wts_fixed_worker.lock));

		memcpy(&(tables[n - 2]),&(rhp_wts_worker_statistics_tbl[n - 2]),sizeof(rhp_wts_worker_statistics));

		RHP_UNLOCK(&(rhp_wts_fixed_worker.lock))
	}

	{
		RHP_LOCK(&(rhp_wts_fixed_blocking_worker.lock));

		memcpy(&(tables[n - 1]),&(rhp_wts_worker_statistics_tbl[n - 1]),sizeof(rhp_wts_worker_statistics));

		RHP_UNLOCK(&(rhp_wts_fixed_blocking_worker.lock))
	}


	*tables_r = tables;
	*tables_num_r = n;

	return 0;
}

int rhp_wts_clear_statistics()
{
	int n = rhp_wts_get_workers_num();
	int i;

	if( _rhp_wts_worker_id_tls >= 0 ){
		RHP_BUG(""); // Sorry! This func MUST NOT be called in wts's context.
		return -EINVAL;
	}

	for( i = 0; i < (n - 2); i++ ){

		RHP_LOCK(&(rhp_wts_worker_list[i].lock));

		memset(&(rhp_wts_worker_statistics_tbl[i]),0,
				sizeof(rhp_wts_worker_statistics) - sizeof(rhp_wts_worker_statistics_dont_clear));

		RHP_UNLOCK(&(rhp_wts_worker_list[i].lock))
	}

	{
		RHP_LOCK(&(rhp_wts_fixed_worker.lock));

		memset(&(rhp_wts_worker_statistics_tbl[n - 2]),0,
				sizeof(rhp_wts_worker_statistics) - sizeof(rhp_wts_worker_statistics_dont_clear));

		RHP_UNLOCK(&(rhp_wts_fixed_worker.lock))
	}

	{
		RHP_LOCK(&(rhp_wts_fixed_blocking_worker.lock));

		memset(&(rhp_wts_worker_statistics_tbl[n - 1]),0,
				sizeof(rhp_wts_worker_statistics) - sizeof(rhp_wts_worker_statistics_dont_clear));

		RHP_UNLOCK(&(rhp_wts_fixed_blocking_worker.lock))
	}

	return 0;
}

int rhp_wts_init(int workers_num)
{
  int err = 0;
  int i;
  rhp_wts_task* task;

  _rhp_gcfg_wts_workers = workers_num;
  if(workers_num < 1 ){
    _rhp_gcfg_wts_workers = 1;
  }

  _rhp_mutex_init("WTS",&_rhp_wts_lock);

  _rhp_cond_init(&_rhp_wts_max_check_evt);
  _rhp_atomic_init(&_rhp_wts_cur_tasks);
  _rhp_atomic_init(&_rhp_wts_cur_tasks_lower_priority);

  for( i = 0; i < rhp_gcfg_wts_max_task_pool_num;i++){

    task = _rhp_wts_alloc_task_raw();
    if( task == NULL ){
    	RHP_BUG("%d , %d",i,rhp_gcfg_wts_max_task_pool_num);
    	break;
    }

    task->next = _rhp_wts_task_pool;
    _rhp_wts_task_pool = task;

	 _rhp_wts_task_pool_num++;
  }

  rhp_wts_worker_list = (rhp_wts_worker*)_rhp_malloc(sizeof(rhp_wts_worker)*_rhp_gcfg_wts_workers);
  if( rhp_wts_worker_list == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  memset(rhp_wts_worker_list,0,sizeof(rhp_wts_worker)*_rhp_gcfg_wts_workers);


  rhp_wts_worker_statistics_tbl = (rhp_wts_worker_statistics*)_rhp_malloc(sizeof(rhp_wts_worker_statistics)*RHP_WTS_ALL_WORKERS_NUM);
  if( rhp_wts_worker_statistics_tbl == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  memset(rhp_wts_worker_statistics_tbl,0,sizeof(rhp_wts_worker_statistics)*RHP_WTS_ALL_WORKERS_NUM);


  rhp_wts_disp_rule_list
      = (rhp_wts_disp_rule*)_rhp_malloc(sizeof(rhp_wts_disp_rule)*(RHP_WTS_DISP_RULE_MAX+1));
  if( rhp_wts_disp_rule_list == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  memset(rhp_wts_disp_rule_list,0,sizeof(rhp_wts_disp_rule)*(RHP_WTS_DISP_RULE_MAX+1));

  for( i = 0; i < _rhp_gcfg_wts_workers; i++ ){

    err = _rhp_wts_worker_init(&(rhp_wts_worker_list[i]),i);
    if( err ){
      RHP_BUG("");
      goto error;
    }
  }

  {
    memset(&rhp_wts_fixed_worker,0,sizeof(rhp_wts_worker));

    rhp_wts_fixed_worker.is_misc_worker = 1;

    err = _rhp_wts_worker_init(&rhp_wts_fixed_worker,i);
    if( err ){
      RHP_BUG("");
      goto error;
    }
  }

  {
    memset(&rhp_wts_fixed_blocking_worker,0,sizeof(rhp_wts_worker));

    rhp_wts_fixed_blocking_worker.is_misc_worker = 1;

    err = _rhp_wts_worker_init(&rhp_wts_fixed_blocking_worker,i + 1);
    if( err ){
      RHP_BUG("");
      goto error;
    }
  }

#ifdef RHP_EVENT_FUNCTION
  {
    memset(&rhp_wts_event_worker,0,sizeof(rhp_wts_worker));

    err = _rhp_wts_worker_init(&rhp_wts_event_worker,RHP_WTS_DISP_RULE_EVENT);
    if( err ){
      RHP_BUG("");
      goto error;
    }
  }
#endif // RHP_EVENT_FUNCTION

error:

	RHP_TRC(0,RHPTRCID_WTS_INIT,"ddE",_rhp_gcfg_wts_workers,rhp_gcfg_wts_max_task_pool_num,err);

  return err;
}

