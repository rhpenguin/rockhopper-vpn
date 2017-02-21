/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifndef _RHP_TIMER_H_
#define _RHP_TIMER_H_

#define RHP_TIMER_Q_MAX_DEFAULT   16000

#define RHP_TIMER_Q_MIN    		32
#define RHP_TIMER_POLLING		10 // (sec)

struct _rhp_timer {

  unsigned char tag[4]; // '#TMR'
  int q_idx;

  struct timespec executed_time;

#define RHP_TIMER_STAT_INIT       	0
#define RHP_TIMER_STAT_WAITING			1
#define RHP_TIMER_STAT_EXEC			   	2
#define RHP_TIMER_STAT_DONE       	3
#define RHP_TIMER_STAT_DELETED    	4
  int status;

  void *ctx;
  void (*timer_handler)(void *ctx,struct _rhp_timer *timer);
  void (*oneshot_handler)(void *ctx);
};
typedef struct _rhp_timer rhp_timer;

extern int rhp_timer_start();

extern void rhp_timer_init(rhp_timer *timer,void (*timer_handler)(void *ctx,rhp_timer *timer),void *ctx);
extern void rhp_timer_reset(rhp_timer *timer);

extern int rhp_timer_add(rhp_timer *timer,time_t diff_secs/*0:Exec immediately!*/);
extern int rhp_timer_add_msec(rhp_timer *timer,long diff_msecs/*0:Exec immediately!*/); // diff_msecs : 0 - 999 (msecs)
extern int rhp_timer_add_with_ctx(rhp_timer *timer,time_t diff_secs/*0:Exec immediately!*/,void* new_ctx);
extern int rhp_timer_add_msec_with_ctx(rhp_timer *timer,long diff_msecs/*0:Exec immediately!*/,void* new_ctx); // diff_msecs : 0 - 999 (msecs)
extern int rhp_timer_add_ex(rhp_timer *timer,struct timespec* diff_secs_and_nanosecs/*NULL:Exec immediately!*/,void* new_ctx);

extern int rhp_timer_update(rhp_timer *timer,time_t diff_secs/*0:Exec immediately!*/);
extern int rhp_timer_update_msec(rhp_timer *timer,long diff_msecs/*0:Exec immediately!*/); // diff_msecs : 0 - 999 (msecs)
extern int rhp_timer_update_ex(rhp_timer *timer,struct timespec* diff_secs_and_nanosecs/*NULL:Exec immediately!*/);

extern int rhp_timer_delete(rhp_timer *timer);
extern int rhp_timer_pending(rhp_timer *timer);

extern int rhp_timer_oneshot(void (*handler)(void *ctx),void *ctx,time_t sec/*0:Exec immediately!*/);
extern int rhp_timer_oneshot_msec(void (*handler)(void *ctx),void *ctx,long msecs/*0:Exec immediately!*/); // diff_msecs : 0 - 999 (msecs)
extern int rhp_timer_oneshot_ex(void (*handler)(void *ctx),void *ctx,struct timespec* diff_sec_nano/*NULL:Exec immediately!*/);

#endif // _RHP_TIMER_H_
