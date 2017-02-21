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
#include "rhp_timer.h"
#include "rhp_config.h"

static rhp_mutex_t  _rhp_timer_lock;
static rhp_cond_t   _rhp_timer_evt;
static rhp_thread_t _rhp_timer_thread;

//
// Simple Heap Priority Qing
//
static rhp_timer **_rhp_timer_q = NULL;
static int _rhp_timer_q_maxnum = 0;
static int _rhp_timer_q_curnum = 0;


static inline void _rhp_timer_q_up(rhp_timer *timer,int to_top)
{
  int parent_idx,last_idx;
  rhp_timer *last;

  parent_idx = ((timer->q_idx-1)/2);
  last_idx = timer->q_idx;
  last = _rhp_timer_q[last_idx];

  while( last_idx > 0 && 
  			 ( _rhp_timespec_gt(&(_rhp_timer_q[parent_idx]->executed_time),&(last->executed_time)) || to_top) ){

  	_rhp_timer_q[last_idx] = _rhp_timer_q[parent_idx];
    _rhp_timer_q[last_idx]->q_idx = last_idx;

    last_idx = parent_idx;
    parent_idx = (parent_idx-1)/2;
  }

  _rhp_timer_q[last_idx] = last;
  _rhp_timer_q[last_idx]->q_idx = last_idx;
  
  return;
}

static inline void _rhp_timer_q_down(rhp_timer *timer)
{
  int smaller,left,right;
  rhp_timer *root = _rhp_timer_q[timer->q_idx];
  int idx = timer->q_idx;
  int last_idx = _rhp_timer_q_curnum/2;

#ifdef RHP_TIMER_DEBUG  
  {
  	struct timespec now,diff;
		clock_gettime(CLOCK_MONOTONIC,&now);
		_rhp_timespec_sub(&(timer->executed_time),&now,&diff);
 		RHP_TRCSTR(0,"idx : %d _rhp_timer_q_down(C) : timer : timer:0x%x q_idx:%d  executed_time:%ld.%ld (%ld.%ld) ctx:0x%x timer_handler:##FUNC_ADDR_START##0x%x##FUNC_ADDR_END## ",idx,timer,timer->q_idx,timer->executed_time.tv_sec,timer->executed_time.tv_nsec,diff.tv_sec,diff.tv_nsec,timer->ctx,timer->timer_handler);
  }
#endif // RHP_TIMER_DEBUG  
  
  while( idx < last_idx ){

    left = idx*2 + 1;
    right = left + 1;

    if( right >= _rhp_timer_q_curnum ||
    		_rhp_timespec_lt(&(_rhp_timer_q[left]->executed_time),&(_rhp_timer_q[right]->executed_time)) ){
    	smaller = left;
    }else{
    	smaller = right;
    }

    if( _rhp_timespec_lt(&(root->executed_time),&(_rhp_timer_q[smaller]->executed_time)) ){
      break;
    }

    _rhp_timer_q[idx] = _rhp_timer_q[smaller];
    _rhp_timer_q[idx]->q_idx = idx;
    idx = smaller;
  }
  
  _rhp_timer_q[idx] = root;
  _rhp_timer_q[idx]->q_idx = idx;
  
#ifdef RHP_TIMER_DEBUG  
  {
  	struct timespec now,diff;
		clock_gettime(CLOCK_MONOTONIC,&now);
		_rhp_timespec_sub(&(timer->executed_time),&now,&diff);
 		RHP_TRCSTR(0," idx:%d _rhp_timer_q_down(R) : timer : timer:0x%x q_idx:%d  executed_time:%ld.%ld (%ld.%ld) ctx:0x%x timer_handler:##FUNC_ADDR_START##0x%x##FUNC_ADDR_END## ",idx,timer,timer->q_idx,timer->executed_time.tv_sec,timer->executed_time.tv_nsec,diff.tv_sec,diff.tv_nsec,timer->ctx,timer->timer_handler);
  }
#endif // RHP_TIMER_DEBUG  

  return;
}

static inline int _rhp_timer_q_put(rhp_timer *timer)
{
  int err = 0;

  if( _rhp_timer_q_curnum >= _rhp_timer_q_maxnum ){

    int newmax = _rhp_timer_q_maxnum*2;

    RHP_TRC(0,RHPTRCID_TIMER_Q_PUT_EXPAND,"xd",timer,_rhp_timer_q_curnum);

    rhp_timer **newq = (rhp_timer**)_rhp_malloc(sizeof(rhp_timer*)*newmax);

    if( newq == NULL ){
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }
    memset(newq,0,sizeof(rhp_timer*)*newmax);

    memcpy(newq,_rhp_timer_q,sizeof(rhp_timer*)*_rhp_timer_q_maxnum);

    _rhp_free(_rhp_timer_q);

    _rhp_timer_q = newq;
    _rhp_timer_q_maxnum = newmax;
  }

  timer->q_idx = _rhp_timer_q_curnum;
  _rhp_timer_q[_rhp_timer_q_curnum] = timer;

  _rhp_timer_q_up(timer,0);

  _rhp_timer_q_curnum++;

error:
  RHP_TRC(0,RHPTRCID_TIMER_Q_PUT_RTRN,"xd",timer,err);
  return err;
}


static inline int _rhp_timer_q_empty()
{
	RHP_TRC_FREQ(0,RHPTRCID_TIMER_Q_EMPTY,"d",_rhp_timer_q_curnum);
  return (_rhp_timer_q_curnum == 0);
}

static inline rhp_timer* _rhp_timer_q_get()
{
  rhp_timer* r = _rhp_timer_q[0];

  if( _rhp_timer_q_empty() ){
    RHP_TRC(0,RHPTRCID_TIMER_Q_GET_EMPTY,"");
    return NULL;
  }
  
  _rhp_timer_q[0] = _rhp_timer_q[--_rhp_timer_q_curnum];
  _rhp_timer_q[0]->q_idx = 0;  

#ifdef RHP_TIMER_DEBUG  
  {
		int a = 0;
  	struct timespec now,diff;
		clock_gettime(CLOCK_MONOTONIC,&now);
		_rhp_timespec_sub(&(_rhp_timer_q[a]->executed_time),&now,&diff);
 		RHP_TRCSTR(0,"_rhp_timer_q_get : _rhp_timer_q[%d] : timer:0x%x q_idx:%d  executed_time:%ld.%ld (%ld.%ld) ctx:0x%x timer_handler:##FUNC_ADDR_START##0x%x##FUNC_ADDR_END## ",a,_rhp_timer_q[a],_rhp_timer_q[a]->q_idx,_rhp_timer_q[a]->executed_time.tv_sec,_rhp_timer_q[a]->executed_time.tv_nsec,diff.tv_sec,diff.tv_nsec,_rhp_timer_q[a]->ctx,_rhp_timer_q[a]->timer_handler);
  }
#endif // RHP_TIMER_DEBUG  
  
  _rhp_timer_q_down(_rhp_timer_q[0]);
  r->q_idx = -1;

  RHP_TRC(0,RHPTRCID_TIMER_Q_GET,"xYx",r,r->timer_handler,r->ctx);
  
  return r;
}

static inline rhp_timer* _rhp_timer_q_peek()
{
  if( _rhp_timer_q_empty() ){
  	RHP_TRC_FREQ(0,RHPTRCID_TIMER_Q_PEEK_EMPTY,"");
    return NULL;
  }

  RHP_TRC_FREQ(0,RHPTRCID_TIMER_Q_PEEK,"x",_rhp_timer_q[0]);
  return _rhp_timer_q[0];
}

static inline int _rhp_timer_q_update(rhp_timer *timer,struct timespec* new_executed_time,int to_top)
{
	struct timespec old_time;
	_rhp_timespec_copy(&old_time,&(timer->executed_time));


  if( timer->q_idx < 0 || timer->q_idx >= _rhp_timer_q_curnum ){
    RHP_BUG("%d < 0 or %d >= %d",timer->q_idx,timer->q_idx,_rhp_timer_q_curnum);
    return -EINVAL;
  }

  _rhp_timespec_copy(&(_rhp_timer_q[timer->q_idx]->executed_time),new_executed_time);

  if( _rhp_timespec_gt(&old_time,new_executed_time) || to_top ){
    _rhp_timer_q_up(timer,to_top);
  }else{
    _rhp_timer_q_down(timer);
  }
  
  RHP_TRC(0,RHPTRCID_TIMER_Q_UPDATE,"d",0);
  
  return 0;
}

static int _rhp_timer_reschedule()
{
  RHP_TRC(0,RHPTRCID_TIMER_RESCHEDULE_TIMER,"");
  return RHP_EVT_NOTIFY(&_rhp_timer_evt);
}


static void* _rhp_timer_run(void* arg)
{
  int err;
  rhp_timer *timer;
  struct timespec waiting;
  struct timespec now;
  struct timespec const_polling;

  RHP_TRC(0,RHPTRCID_TIMER_TIMER_RUN,"");

  _rhp_timespec_clear(&waiting);
  const_polling.tv_sec = RHP_TIMER_POLLING;
  const_polling.tv_nsec = 0;
  
  err = rhp_sig_clear();
  if( err ){
  	RHP_BUG("%",err);
  	return NULL;
  }
  
  rhp_trace_tid = gettid();

  RHP_TRC(0,RHPTRCID_TIMER_TIMER_RUN_START,"u",rhp_trace_tid);

  while( 1 ){

restart:
		timer = NULL;

		RHP_LOCK_FREQ(&_rhp_timer_lock);

		while( timer == NULL ){

			timer = _rhp_timer_q_peek();

			if( timer ){

				clock_gettime(CLOCK_MONOTONIC,&now);

				if( _rhp_timespec_gteq(&now,&(timer->executed_time)) ){

					_rhp_timer_q_get();
					break;

				}else{

					_RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
				  if( _RHP_TRC_COND(_rhp_trc_user_id(),0) ){
				  	struct timespec diff;
				  	_rhp_timespec_sub(&(timer->executed_time),&now,&diff);
				  	RHP_TRC_FREQ(0,RHPTRCID_TIMER_TIMER_RUN_NOT_TIMEDOUT_YET,"uuuuuu",now.tv_sec,now.tv_nsec,timer->executed_time.tv_sec,timer->executed_time.tv_nsec,diff.tv_sec,diff.tv_nsec);
				  }
				}

				_rhp_timespec_sub(&(timer->executed_time),&now,&waiting);
/*
		  	if( waiting < 2 ){
		  		waiting = 2; 	// UGLY!!!!  Error of less than 2 seconds sometimes occurs
												// in pthread_cond_timedwait()/_rhp_wait_event() on VMware Workstation.
		  	}
*/


				if( _rhp_timespec_gt(&waiting,&const_polling) ){
					RHP_TRC_FREQ(0,RHPTRCID_TIMER_TIMER_RUN_POLLING1,"uud",waiting.tv_sec,waiting.tv_nsec,RHP_TIMER_POLLING);
					_rhp_timespec_copy(&waiting,&const_polling);
				}
			
			}else{
				RHP_TRC_FREQ(0,RHPTRCID_TIMER_TIMER_RUN_POLLING2,"uud",waiting.tv_sec,waiting.tv_nsec,RHP_TIMER_POLLING);
				_rhp_timespec_copy(&waiting,&const_polling);
			}

			if( !RHP_PROCESS_IS_ACTIVE() ){
				RHP_UNLOCK_FREQ(&_rhp_timer_lock);
				RHP_TRC(0,RHPTRCID_NOT_ACTIVE,"s","_rhp_timer_run");
				goto out;
			}

			timer = NULL;

			RHP_TRC_FREQ(0,RHPTRCID_TIMER_TIMER_RUN_WAIT,"uu",waiting.tv_sec,waiting.tv_nsec);

			if( (err = _rhp_wait_event_ex(&_rhp_timer_evt,&_rhp_timer_lock,&waiting) ) ){

				RHP_TRC_FREQ(0,RHPTRCID_TIMER_TIMER_RUN_WAIT_ERR,"uuE",waiting.tv_sec,waiting.tv_nsec,-err);

				if( err != ETIMEDOUT ){
					RHP_UNLOCK_FREQ(&_rhp_timer_lock);
					goto restart;
				}
			}
		}
    
		timer->status = RHP_TIMER_STAT_EXEC;

		RHP_UNLOCK_FREQ(&_rhp_timer_lock);
    
		if( timer->oneshot_handler ){

			RHP_TRC(0,RHPTRCID_TIMER_TIMER_RUN_ONESHOT,"uxYx",rhp_trace_tid,timer,timer->oneshot_handler,timer->ctx);

			timer->oneshot_handler(timer->ctx);
			_rhp_free(timer);

		}else if( timer->timer_handler ){

			RHP_TRC(0,RHPTRCID_TIMER_TIMER_RUN_CALLBACK,"uxYx",rhp_trace_tid,timer,timer->timer_handler,timer->ctx);

			timer->timer_handler(timer->ctx,timer);

			RHP_LOCK_FREQ(&_rhp_timer_lock);

			if( timer->status == RHP_TIMER_STAT_EXEC ){
				timer->status = RHP_TIMER_STAT_DONE;
			}

			RHP_UNLOCK_FREQ(&_rhp_timer_lock);
		
		}else{
			RHP_BUG("0x%x",timer);
		}
  }

out:

  RHP_LINE("");
  return NULL;
}

int rhp_timer_start()
{
  int err = 0;

  if( rhp_gcfg_timer_max_qsize < RHP_TIMER_Q_MIN ){
    rhp_gcfg_timer_max_qsize = RHP_TIMER_Q_MIN;
  }

  RHP_TRC(0,RHPTRCID_TIMER_START,"d",rhp_gcfg_timer_max_qsize);

  _rhp_timer_q = (rhp_timer**)_rhp_malloc(sizeof(rhp_timer*)*rhp_gcfg_timer_max_qsize);
  if( _rhp_timer_q == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

  _rhp_timer_q_maxnum = rhp_gcfg_timer_max_qsize;

  _rhp_cond_init(&_rhp_timer_evt);
  _rhp_mutex_init("TMR",&_rhp_timer_lock);

  if( ( err = _rhp_thread_create(&_rhp_timer_thread,_rhp_timer_run,NULL)) ){
    err = -err;
    RHP_BUG("");
    goto error;
  }

  RHP_TRC(0,RHPTRCID_TIMER_START_RTRN,"d",0);
  return 0;
  
error:
  if( _rhp_timer_q ){
    _rhp_free(_rhp_timer_q);
    _rhp_timer_q_maxnum = 0;
  }

  RHP_TRC(0,RHPTRCID_TIMER_START_RTRN,"d",err);
  return err;
}


void rhp_timer_init(rhp_timer *timer,void (*timer_handler)(void *ctx,rhp_timer *timer),void *ctx)
{
  timer->tag[0] = '#';
  timer->tag[1] = 'T';
  timer->tag[2] = 'M';
  timer->tag[3] = 'R';

  RHP_TRC(0,RHPTRCID_TIMER_INIT,"xYx",timer,timer_handler,ctx);
  
  timer->q_idx = -1;
  _rhp_timespec_clear(&(timer->executed_time));
  timer->status = RHP_TIMER_STAT_INIT;

  timer->ctx = ctx;
  timer->timer_handler = timer_handler;

  return;
}

void rhp_timer_reset(rhp_timer *timer)
{
  RHP_TRC(0,RHPTRCID_TIMER_RESET,"xYx",timer,timer->timer_handler,timer->ctx);

  timer->q_idx = -1;
  _rhp_timespec_clear(&(timer->executed_time));
  timer->status = RHP_TIMER_STAT_INIT;

  return;
}

int rhp_timer_pending(rhp_timer *timer)
{
  int pending = 0;

  RHP_LOCK(&_rhp_timer_lock);
  
  if( timer->status == RHP_TIMER_STAT_WAITING || timer->status == RHP_TIMER_STAT_EXEC ){
    pending = 1;    
  }
  RHP_UNLOCK(&_rhp_timer_lock);

  RHP_TRC(0,RHPTRCID_TIMER_PENDING,"xYxdLd",timer,timer->timer_handler,timer->ctx,pending,"TIMER_STAT",timer->status);
  return pending;
}

int rhp_timer_add_with_ctx(rhp_timer *timer,time_t sec/*0:Exec immediately!*/,void* new_ctx)
{
	struct timespec diff;

  RHP_TRC(0,RHPTRCID_TIMER_ADD_WITH_CTX,"xux",timer,sec,new_ctx);

	_rhp_timespec_clear(&diff);

	diff.tv_sec = sec;

	return rhp_timer_add_ex(timer,(sec ? &diff : NULL),new_ctx);
}

int rhp_timer_add(rhp_timer *timer,time_t sec/*0:Exec immediately!*/)
{
	return rhp_timer_add_with_ctx(timer,sec,NULL);
}

int rhp_timer_add_msec_with_ctx(rhp_timer *timer,long msecs/*0:Exec immediately!*/,void* new_ctx)
{
	struct timespec diff;

  RHP_TRC(0,RHPTRCID_TIMER_ADD_MSEC_WITH_CTX,"xfx",timer,msecs,new_ctx);

	_rhp_timespec_clear(&diff);

	if( msecs >= 1000 ){
		RHP_BUG("%ld",msecs);
		return -EINVAL;
	}

	diff.tv_nsec = msecs*1000000;

	return rhp_timer_add_ex(timer,(msecs ? &diff : NULL),new_ctx);
}

int rhp_timer_add_msec(rhp_timer *timer,long msecs/*0:Exec immediately!*/)
{
	return rhp_timer_add_msec_with_ctx(timer,msecs,NULL);
}

int rhp_timer_add_ex(rhp_timer *timer,struct timespec* diff_sec_nano/*NULL:Exec immediately!*/,void* new_ctx)
{
  int err = 0;

  RHP_TRC(0,RHPTRCID_TIMER_ADD_EX,"xYxxxuuLd",timer,timer->timer_handler,timer->ctx,new_ctx,diff_sec_nano,(diff_sec_nano ? diff_sec_nano->tv_sec : 0),(diff_sec_nano ? diff_sec_nano->tv_nsec : 0),"TIMER_STAT",timer->status);

  RHP_LOCK(&_rhp_timer_lock);

#ifdef RHP_TIMER_DEBUG  
  {
  	int a;
  	struct timespec now,diff;
		clock_gettime(CLOCK_MONOTONIC,&now);

  	for( a = 0; a < _rhp_timer_q_curnum; a++ ){

    	_rhp_timespec_sub(&(_rhp_timer_q[a]->executed_time),&now,&diff);

  		RHP_TRCSTR(0,"(C)_rhp_timer_q[%d] : timer:0x%x q_idx:%d  executed_time:%ld.%ld (%ld.%ld) ctx:0x%x timer_handler:##FUNC_ADDR_START##0x%x##FUNC_ADDR_END## ",a,_rhp_timer_q[a],_rhp_timer_q[a]->q_idx,_rhp_timer_q[a]->executed_time.tv_sec,_rhp_timer_q[a]->executed_time.tv_nsec,diff.tv_sec,diff.tv_nsec,_rhp_timer_q[a]->ctx,_rhp_timer_q[a]->timer_handler);

  		if( _rhp_timer_q[a] == timer ){
    		RHP_BUG("TIMER DUP! _rhp_timer_q[%d] : timer:0x%x q_idx:%d  executed_time:%ld.%ld (%ld.%ld) ctx:0x%x timer_handler:##FUNC_ADDR_START##0x%x##FUNC_ADDR_END## ",a,_rhp_timer_q[a],_rhp_timer_q[a]->q_idx,_rhp_timer_q[a]->executed_time.tv_sec,_rhp_timer_q[a]->executed_time.tv_nsec,diff.tv_sec,diff.tv_nsec,_rhp_timer_q[a]->ctx,_rhp_timer_q[a]->timer_handler);
  		}
  	}
  }
#endif // RHP_TIMER_DEBUG  
  
  if( timer->status == RHP_TIMER_STAT_WAITING || 
  		timer->status == RHP_TIMER_STAT_EXEC 		||
      timer->status == RHP_TIMER_STAT_DELETED ){
    err = -EINVAL;
    RHP_BUG("0x%x , %d",timer,timer->status);
    goto error;
  }
  
  {
  	struct timespec now;
		clock_gettime(CLOCK_MONOTONIC,&now);

		if( diff_sec_nano ){
			_rhp_timespec_add(&now,diff_sec_nano,&(timer->executed_time));
		}else{
			_rhp_timespec_copy(&(timer->executed_time),&now);
		}
  }

  err = _rhp_timer_q_put(timer);

  timer->status = RHP_TIMER_STAT_WAITING;

  if( _rhp_timer_q_peek() == timer ){
    _rhp_timer_reschedule();
  }

#ifdef RHP_TIMER_DEBUG  
  {
  	int a;
  	struct timespec now,diff;
		clock_gettime(CLOCK_MONOTONIC,&now);

  	for( a = 0; a < _rhp_timer_q_curnum; a++ ){
    	_rhp_timespec_sub(&(_rhp_timer_q[a]->executed_time),&now,&diff);
  		RHP_TRCSTR(0,"(R)_rhp_timer_q[%d] : timer:0x%x q_idx:%d  executed_time:%ld.%ld (%ld.%ld) ctx:0x%x timer_handler:##FUNC_ADDR_START##0x%x##FUNC_ADDR_END## ",a,_rhp_timer_q[a],_rhp_timer_q[a]->q_idx,_rhp_timer_q[a]->executed_time.tv_sec,_rhp_timer_q[a]->executed_time.tv_nsec,diff.tv_sec,diff.tv_nsec,_rhp_timer_q[a]->ctx,_rhp_timer_q[a]->timer_handler);
  	}
  }
#endif // RHP_TIMER_DEBUG  

  if( new_ctx ){
  	timer->ctx = new_ctx;
  }

error:
  RHP_UNLOCK(&_rhp_timer_lock);
  RHP_TRC(0,RHPTRCID_TIMER_ADD_EX_RTRN,"xE",timer,err);
  return err;
}


static int _rhp_timer_update(rhp_timer *timer,struct timespec* diff_sec_nano)
{
  int err = 0;
  struct timespec new_executed_time;

  RHP_TRC(0,RHPTRCID_TIMER_UPDATE_STATIC,"xYxxuuLd",timer,timer->timer_handler,timer->ctx,diff_sec_nano,(diff_sec_nano ? diff_sec_nano->tv_sec : 0),(diff_sec_nano ? diff_sec_nano->tv_nsec : 0),"TIMER_STAT",timer->status);

  _rhp_timespec_clear(&new_executed_time);
  
  if( timer->status != RHP_TIMER_STAT_WAITING ){
    err = -ENOENT;
    RHP_TRC(0,RHPTRCID_TIMER_UPDATE_STATIC_EXEC_STAT_OR_INVALID_STAT,"xYxLd",timer,timer->timer_handler,timer->ctx,"TIMER_STAT",timer->status);
    goto error;
  }
  
  {
  	struct timespec now;
		clock_gettime(CLOCK_MONOTONIC,&now);

		if( diff_sec_nano ){
			_rhp_timespec_add(&now,diff_sec_nano,&new_executed_time);
		}else{
			_rhp_timespec_copy(&new_executed_time,&now);
		}
  }

  if( (err = _rhp_timer_q_update(timer,&new_executed_time,0)) ){
    RHP_BUG("0x%x , %d",timer,err);
    goto error;
  }

  if( _rhp_timer_q_peek() == timer ){
    _rhp_timer_reschedule();
  }
  
error:
	RHP_TRC(0,RHPTRCID_TIMER_UPDATE_STATIC_RTRN,"xE",timer,err);
	return err;
}

int rhp_timer_update(rhp_timer *timer,time_t sec/*0:Exec immediately!*/)
{
	struct timespec diff;

  RHP_TRC(0,RHPTRCID_TIMER_UPDATE,"xu",timer,sec);

	_rhp_timespec_clear(&diff);

	diff.tv_sec = sec;

	return rhp_timer_update_ex(timer,(sec ? &diff : NULL));
}

int rhp_timer_update_msec(rhp_timer *timer,long msecs/*0:Exec immediately!*/)
{
	struct timespec diff;

  RHP_TRC(0,RHPTRCID_TIMER_UPDATE_MSEC,"xf",timer,msecs);

	_rhp_timespec_clear(&diff);

	if( msecs >= 1000 ){
		RHP_BUG("%ld",msecs);
		return -EINVAL;
	}

	diff.tv_nsec = msecs*1000000;

	return rhp_timer_update_ex(timer,(msecs ? &diff : NULL));
}

int rhp_timer_update_ex(rhp_timer *timer,struct timespec* diff_sec_nano/*NULL:Exec immediately!*/)
{
  int err = 0;

  RHP_TRC(0,RHPTRCID_TIMER_UPDATE,"xYxxuu",timer,timer->timer_handler,timer->ctx,diff_sec_nano,(diff_sec_nano ? diff_sec_nano->tv_sec : 0),(diff_sec_nano ? diff_sec_nano->tv_nsec : 0));

  RHP_LOCK(&_rhp_timer_lock);

#ifdef RHP_TIMER_DEBUG  
  {
  	int a;
  	struct timespec now,diff;
		clock_gettime(CLOCK_MONOTONIC,&now);

  	for( a = 0; a < _rhp_timer_q_curnum; a++ ){
    	_rhp_timespec_sub(&(_rhp_timer_q[a]->executed_time),&now,&diff);
  		RHP_TRCSTR(0,"(C)_rhp_timer_q[%d] : timer:0x%x q_idx:%d  executed_time:%ld.%ld (%ld.%ld) ctx:0x%x timer_handler:##FUNC_ADDR_START##0x%x##FUNC_ADDR_END## ",a,_rhp_timer_q[a],_rhp_timer_q[a]->q_idx,_rhp_timer_q[a]->executed_time.tv_sec,_rhp_timer_q[a]->executed_time.tv_nsec,diff.tv_sec,diff.tv_nsec,_rhp_timer_q[a]->ctx,_rhp_timer_q[a]->timer_handler);
  	}
  }
#endif // RHP_TIMER_DEBUG  
  
  err = _rhp_timer_update(timer,diff_sec_nano);

#ifdef RHP_TIMER_DEBUG  
  {
  	int a;
  	struct timespec now,diff;
		clock_gettime(CLOCK_MONOTONIC,&now);

  	for( a = 0; a < _rhp_timer_q_curnum; a++ ){
    	_rhp_timespec_sub(&(_rhp_timer_q[a]->executed_time),&now,&diff);
  		RHP_TRCSTR(0,"(R)_rhp_timer_q[%d] : timer:0x%x q_idx:%d  executed_time:%ld.%ld (%ld.%ld) ctx:0x%x timer_handler:##FUNC_ADDR_START##0x%x##FUNC_ADDR_END## ",a,_rhp_timer_q[a],_rhp_timer_q[a]->q_idx,_rhp_timer_q[a]->executed_time.tv_sec,_rhp_timer_q[a]->executed_time.tv_nsec,diff.tv_sec,diff.tv_nsec,_rhp_timer_q[a]->ctx,_rhp_timer_q[a]->timer_handler);
  	}
  }
#endif // RHP_TIMER_DEBUG  
  
  RHP_UNLOCK(&_rhp_timer_lock);

  RHP_TRC(0,RHPTRCID_TIMER_UPDATE_RTRN,"xE",timer,err);
  return err;
}

int rhp_timer_delete(rhp_timer *timer)
{
  int err = 0;
  rhp_timer *tmp;

  RHP_TRC(0,RHPTRCID_TIMER_DELETE,"xYx",timer,timer->timer_handler,timer->ctx);

  RHP_LOCK(&_rhp_timer_lock);

#ifdef RHP_TIMER_DEBUG  
  {
  	int a;
  	struct timespec now,diff;
		clock_gettime(CLOCK_MONOTONIC,&now);

  	for( a = 0; a < _rhp_timer_q_curnum; a++ ){
    	_rhp_timespec_sub(&(_rhp_timer_q[a]->executed_time),&now,&diff);
  		RHP_TRCSTR(0,"(C)_rhp_timer_q[%d] : timer:0x%x q_idx:%d  executed_time:%ld.%ld (%ld.%ld) ctx:0x%x timer_handler:##FUNC_ADDR_START##0x%x##FUNC_ADDR_END## ",a,_rhp_timer_q[a],_rhp_timer_q[a]->q_idx,_rhp_timer_q[a]->executed_time.tv_sec,_rhp_timer_q[a]->executed_time.tv_nsec,diff.tv_sec,diff.tv_nsec,_rhp_timer_q[a]->ctx,_rhp_timer_q[a]->timer_handler);
  	}
  }
#endif // RHP_TIMER_DEBUG  
  
  if( timer->status != RHP_TIMER_STAT_WAITING ){
    err = -ENOENT;
    RHP_TRC(0,RHPTRCID_TIMER_DELETE_NOT_WAITING,"xLd",timer,"TIMER_STAT",timer->status);
    goto error;
  }

  if( _rhp_timer_q[0] == NULL ){
  	RHP_BUG("_rhp_timer_q[0] == NULL");
  }

  if( _rhp_timer_q[0] && _rhp_timer_q[0] != timer ){

  	struct timespec ctmp;

  	ctmp.tv_sec = _rhp_timer_q[0]->executed_time.tv_sec;
  	ctmp.tv_nsec = _rhp_timer_q[0]->executed_time.tv_nsec - 1;

		if( (err = _rhp_timer_q_update(timer,&ctmp,1) ) ){
      RHP_BUG("0x%x , %d",timer,err);
      goto error;
    }
  }

#ifdef RHP_TIMER_DEBUG  
  {
  	int a;
  	struct timespec now,diff;
		clock_gettime(CLOCK_MONOTONIC,&now);

  	for( a = 0; a < _rhp_timer_q_curnum; a++ ){
    	_rhp_timespec_sub(&(_rhp_timer_q[a]->executed_time),&now,&diff);
  		RHP_TRCSTR(0,"(M)_rhp_timer_q[%d] : timer:0x%x q_idx:%d  executed_time:%ld.%ld (%ld.%ld) ctx:0x%x timer_handler:##FUNC_ADDR_START##0x%x##FUNC_ADDR_END## ",a,_rhp_timer_q[a],_rhp_timer_q[a]->q_idx,_rhp_timer_q[a]->executed_time.tv_sec,_rhp_timer_q[a]->executed_time.tv_nsec,diff.tv_sec,diff.tv_nsec,_rhp_timer_q[a]->ctx,_rhp_timer_q[a]->timer_handler);
  	}
  }
#endif // RHP_TIMER_DEBUG  
  
  if( (tmp = _rhp_timer_q_get()) != timer ){
    RHP_BUG("0x%x,0x%x",timer,tmp);
  }
  
  timer->status = RHP_TIMER_STAT_DELETED;

#ifdef RHP_TIMER_DEBUG  
  {
  	int a;
  	struct timespec now,diff;
		clock_gettime(CLOCK_MONOTONIC,&now);

  	for( a = 0; a < _rhp_timer_q_curnum; a++  ){
    	_rhp_timespec_sub(&(_rhp_timer_q[a]->executed_time),&now,&diff);
  		RHP_TRCSTR(0,"(R)_rhp_timer_q[%d] : timer:0x%x q_idx:%d  executed_time:%ld.%ld (%ld.%ld) ctx:0x%x timer_handler:##FUNC_ADDR_START##0x%x##FUNC_ADDR_END## ",a,_rhp_timer_q[a],_rhp_timer_q[a]->q_idx,_rhp_timer_q[a]->executed_time.tv_sec,_rhp_timer_q[a]->executed_time.tv_nsec,diff.tv_sec,diff.tv_nsec,_rhp_timer_q[a]->ctx,_rhp_timer_q[a]->timer_handler);
  	}
  }
#endif // RHP_TIMER_DEBUG  

error:
  RHP_UNLOCK(&_rhp_timer_lock);
  RHP_TRC(0,RHPTRCID_TIMER_DELETE_RTRN,"xE",timer,err);
  return err;
}

int rhp_timer_oneshot(void (*handler)(void *ctx),void *ctx,time_t sec/*0:Exec immediately!*/)
{
	struct timespec diff;

  RHP_TRC(0,RHPTRCID_TIMER_ONESHOT,"Yxu",handler,ctx,sec);

	_rhp_timespec_clear(&diff);

	diff.tv_sec = sec;

	return rhp_timer_oneshot_ex(handler,ctx,(sec ? &diff : NULL));
}

int rhp_timer_oneshot_msec(void (*handler)(void *ctx),void *ctx,long msecs/*0:Exec immediately!*/)
{
	struct timespec diff;

  RHP_TRC(0,RHPTRCID_TIMER_ONESHOT_MSEC,"Yxf",handler,ctx,msecs);

	_rhp_timespec_clear(&diff);

	if( msecs >= 1000 ){
		RHP_BUG("%ld",msecs);
		return -EINVAL;
	}

	diff.tv_nsec = msecs*1000000;

	return rhp_timer_oneshot_ex(handler,ctx,(msecs ? &diff : NULL));
}

int rhp_timer_oneshot_ex(void (*handler)(void *ctx),void *ctx,struct timespec* diff_sec_nano/*NULL:Exec immediately!*/)
{
  rhp_timer *timer = (rhp_timer*)_rhp_malloc(sizeof(rhp_timer));

  RHP_TRC(0,RHPTRCID_TIMER_ONESHOT_EX,"Yxxuu",handler,ctx,diff_sec_nano,(diff_sec_nano ? diff_sec_nano->tv_sec : 0),(diff_sec_nano ? diff_sec_nano->tv_nsec : 0));

  if( timer == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  rhp_timer_init(timer,NULL,ctx);
  
  timer->oneshot_handler = handler;

  return rhp_timer_add_ex(timer,diff_sec_nano,NULL);
}

