/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifndef _RHP_MISC_H_
#define _RHP_MISC_H_

#include <values.h>

#include "rhp_err.h"
#include "rhp_log.h"


#include "rhp_misc2.h"


/*

  Build Flags for debug. ( gcc -DRHP_XXX_ ):

   - RHP_WRITE_DEBUG_LOG: Write bug trace to event log.

   - RHP_DBG_FUNC_TRC: Enable function call trace.
                       Addictional gcc's options, '-finstrument-functions' and
                       -gN (ex:-g3), are required. And, '-O0' is better.

   - RHP_MUTEX_DEBUG: Enable mutex's debug trace.

   - RHP_REFCNT_DEBUG and RHP_REFCNT_DEBUG_X: Enable reference counter's debug trace.

   - RHP_MEMORY_DBG: Enable memory alloc/free's debug trace.
                     Run 'make' with -DRHP_DBG_FUNC_TRC, '-O0', '-finstrument-functions'
                     and -gN (ex:-g3). All libraries using _rhp_malloc()/_rhp_free
                     must be built with these flags and options. By enabling this
                     flag, you can get trace records about where/when a memory area
                     was allocated or freed and possiblities of duplicate memory frees.

                     Also, by using the following tool, you can get a list
                     of not-freed memory addresses as trace records. This info is
                     helpful to find memory leaks.

                     [ Usage ]
											% rockhopper.pl memory_dbg -admin <admin_id> -password <password>
                      [-elapsing_time <seconds>(>0)]
                      [-start_time <seconds>(>0)]
                      [-port <admin_port>]

   - RHP_PKT_DEBUG: Trace detailed packet's debug info.

   - RHP_TIMER_DEBUG: Trace detailed timer's debug info.

   - RHP_CK_OBJ_TAG and RHP_CK_OBJ_TAG_GDB: Check (struct)object->tag value by using RHP_CK_OBJTAG
   	 	 	 	 	 	 	 	 	 	    	 	 	 	 	 	      macro.
   	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	    If the field is broken, trap signal by GDB and/or
   	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	    write a bug trace record.

	 - RHP_IKEV2_INTEG_ERR_DBG: When a local peer fails to verify a received request, it sends an error
	                            notification response (IKEv2) to trigger the remote peer's debug
	                            reaction.

  	                            - Mesg Type: PRIV_RHP_DBG_IKE_INTEG_ERR(59400)

                              A Rx handler for the response is rhp_ikev2_dbg_rx_integ_err_notify().
                              [rhp_dbg.c]


   - When enabling these flags (except RHP_TIMER_DEBUG and RHP_IKEV2_INTEG_ERR_DBG)
     by installer script, run it like this:

     % cd rockhopper-x.y.z

			 % ./debug_tools/install_dbg_no_optmz.sh
			 or
			 % ./installer/install_uninstall.pl install_dbg no_optmz

		 or

			 % ./debug_tools/install_dbg_all.sh
			 or
			 % ./installer/install_uninstall.pl install_dbg all







	 - RHP_PKT_DBG_PRINT_PKT_DATA: Write IKEv2 pkt data to files for ikev2_dmy_cliet.app.

   - RHP_PKT_DBG_IKEV2_RETRANS_TEST / RHP_PKT_DBG_IKEV2_RETRANS_FRAG_TEST: For IKEv2 retrans test.

   - RHP_PKT_DBG_IKEV2_BAD_COOKIE_TEST: For bad cookies test. (COOKIE)

   - RHP_PKT_DBG_IKEV2_BAD_TKT_TEST: For bad tickets test. (Session Resumption)

   - RHP_SESS_RESUME_DEBUG_1: Always start Session Resume exchange after rx a peer's ticket.
                              The ticket will be never updated.

*/

/****************************

  Private constants (Global)

*****************************/

#define RHP_IKE_INITIATOR 		0
#define RHP_IKE_RESPONDER 		1

#define RHP_DIR_INBOUND			0
#define RHP_DIR_OUTBOUND		1

#define RHP_EAP_DISABLED				0
#define RHP_EAP_SUPPLICANT			1
#define RHP_EAP_AUTHENTICATOR		2

#define RHP_VPN_UNIQUE_ID_SIZE		16

#define RHP_NET_CACHE_AGING_TASK_MAX_NSEC		10000000


/*******************

     Debug

********************/

#define _rhp_panic()\
{\
	RHP_TRCSTRF("PANIC!");\
	sleep(1);\
	exit(-1);\
}

extern void _rhp_dbg_time_bomb(void* ctx);
#define _rhp_panic_time_bomb(sec)\
{\
	RHP_TRCSTRF("PANIC! TIME BOMB: %d(secs)",(sec));\
	rhp_timer_oneshot(_rhp_dbg_time_bomb,NULL,(sec));\
}


/**************************************

 Utils for time() / struct timespec.

***************************************/

#include <time.h>

static inline void _rhp_timespec_clear( struct timespec* t )
{
	t->tv_sec = 0;
	t->tv_nsec = 0;
}

static inline void _rhp_timespec_copy( struct timespec* to,
		struct timespec* from )
{
	to->tv_sec = from->tv_sec;
	to->tv_nsec = from->tv_nsec;
}

// a > b
static inline int _rhp_timespec_gt( struct timespec* a, struct timespec* b )
{
	if(a->tv_sec == b->tv_sec){
		return (a->tv_nsec > b->tv_nsec);
	}else{
		return (a->tv_sec > b->tv_sec);
	}
}

// a < b
static inline int _rhp_timespec_lt( struct timespec* a, struct timespec* b )
{
	return _rhp_timespec_gt( b, a );
}

// a >= b
static inline int _rhp_timespec_gteq( struct timespec* a, struct timespec* b )
{
	if(a->tv_sec == b->tv_sec){
		return (a->tv_nsec >= b->tv_nsec);
	}else{
		return (a->tv_sec >= b->tv_sec);
	}
}

// a <= b
static inline int _rhp_timespec_lteq( struct timespec* a, struct timespec* b )
{
	return _rhp_timespec_gteq( b, a );
}

// res = a + b
static inline void _rhp_timespec_add( struct timespec* a, struct timespec* b,
		struct timespec* res )
{
	res->tv_sec = a->tv_sec + b->tv_sec;
	res->tv_nsec = a->tv_nsec + b->tv_nsec;
	if(res->tv_nsec >= 1000000000){
		++(res->tv_sec);
		res->tv_nsec -= 1000000000;
	}
}

// res = a - b
static inline void _rhp_timespec_sub( struct timespec* a, struct timespec* b,
		struct timespec* res )
{
	res->tv_sec = a->tv_sec - b->tv_sec;
	res->tv_nsec = a->tv_nsec - b->tv_nsec;
	if( res->tv_sec && res->tv_nsec < 0){
		--(res->tv_sec);
		res->tv_nsec += 1000000000;
	}

	if(res->tv_sec < 0 || res->tv_nsec < 0){
		RHP_TRCSTRF("[%ld , %ld], [%ld , %ld], [%ld , %ld]",a->tv_sec,a->tv_nsec,b->tv_sec,b->tv_nsec,res->tv_sec,res->tv_nsec);
	}
}


// For human-readable time since the Epoch.
static inline time_t _rhp_get_realtime()
{
	struct timespec now;
	clock_gettime(CLOCK_REALTIME_COARSE,&now); // > 1ms(resolution)
	return now.tv_sec;
}

static inline time_t _rhp_get_time()
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC_COARSE,&now); // > 1ms(resolution)
	return now.tv_sec;
}



/***************************

   Pthread API wrappers

 ****************************/

#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>

//_syscall0(pid_t,gettid) pid_t gettid(void);
static inline pid_t gettid(void)
{
  return (pid_t)syscall(SYS_gettid);
}



#include <pthread.h>

typedef pthread_cond_t    rhp_cond_t;

struct _rhp_mutex_t {
  pthread_mutex_t mutex;
  volatile long locked;
#define RHP_MUTEX_DBG_FLAG_IGNORED			0x1
#define RHP_MUTEX_DBG_FLAG_INITILIZED 	0x2
  unsigned int debug_flag;
  char tag[4];
};
typedef struct _rhp_mutex_t  rhp_mutex_t;

typedef pthread_t         rhp_thread_t;

#ifndef RHP_MUTEX_DEBUG

static inline void RHP_LOCK(rhp_mutex_t* lock)
{
  pthread_mutex_lock(&(lock->mutex));
  lock->locked = 1;
}

static inline void RHP_UNLOCK(rhp_mutex_t* lock)
{
  pthread_mutex_unlock(&(lock->mutex));
  lock->locked = 0;
}

static inline void RHP_LOCK_FREQ(rhp_mutex_t* lock)
{
  pthread_mutex_lock(&(lock->mutex));
  lock->locked = 1;
}

static inline void RHP_UNLOCK_FREQ(rhp_mutex_t* lock)
{
  pthread_mutex_unlock(&(lock->mutex));
  lock->locked = 0;
}

#else // RHP_MUTEX_DEBUG

#define RHP_LOCK(lock)\
{\
  if( !((lock)->debug_flag & RHP_MUTEX_DBG_FLAG_INITILIZED) ){\
  	RHP_LINE("#LOCK [IN]0x%x NOT INITIALIZED!!!",(lock));\
  	_rhp_panic();\
 	}\
  if( !((lock)->debug_flag & RHP_MUTEX_DBG_FLAG_IGNORED) ){\
  	RHP_LINE("#LOCK [IN]0x%x[%s](locked:%d)",(lock),(lock)->tag,(lock)->locked);\
 	}\
 	pthread_mutex_lock(&((lock)->mutex));\
 	(lock)->locked = 1;\
  if( !((lock)->debug_flag & RHP_MUTEX_DBG_FLAG_IGNORED) ){\
  	RHP_LINE("#LOCK [OUT]0x%x[%s](locked:%d)",(lock),(lock)->tag,(lock)->locked);\
  }\
}
#define RHP_UNLOCK(lock)\
{\
  if( !((lock)->debug_flag & RHP_MUTEX_DBG_FLAG_INITILIZED) ){\
    RHP_LINE("#UNLOCK [IN]0x%x NOT INITIALIZED!!!",(lock));\
  	_rhp_panic();\
 	}\
  if( !((lock)->debug_flag & RHP_MUTEX_DBG_FLAG_IGNORED) ){\
  	RHP_LINE("#UNLOCK [IN]0x%x[%s](locked:%d)",(lock),(lock)->tag,(lock)->locked);\
  }\
  (lock)->locked = 0;\
  pthread_mutex_unlock(&((lock)->mutex));\
  if( !((lock)->debug_flag & RHP_MUTEX_DBG_FLAG_IGNORED) ){\
  	RHP_LINE("#UNLOCK [OUT]0x%x[%s](locked:%d)",(lock),(lock)->tag,(lock)->locked);\
  }\
}
#define RHP_LOCK_FREQ(lock)\
{\
  if( !((lock)->debug_flag & RHP_MUTEX_DBG_FLAG_INITILIZED) ){\
  	RHP_LINE("#LOCK [IN]0x%x NOT INITIALIZED!!!",(lock));\
  	_rhp_panic();\
 	}\
  if( _RHP_TRC_COND(_rhp_trc_user_freq_id(),0) && !((lock)->debug_flag & RHP_MUTEX_DBG_FLAG_IGNORED) ){\
  	RHP_LINE("#LOCK [IN]0x%x[%s](locked:%d)",(lock),(lock)->tag,(lock)->locked);\
 	}\
 	pthread_mutex_lock(&((lock)->mutex));\
 	(lock)->locked = 1;\
 	if( _RHP_TRC_COND(_rhp_trc_user_freq_id(),0) && !((lock)->debug_flag & RHP_MUTEX_DBG_FLAG_IGNORED) ){\
 		RHP_LINE("#LOCK [OUT]0x%x[%s](locked:%d)",(lock),(lock)->tag,(lock)->locked);\
	}\
}
#define RHP_UNLOCK_FREQ(lock)\
{\
  if( !((lock)->debug_flag & RHP_MUTEX_DBG_FLAG_INITILIZED) ){\
    RHP_LINE("#UNLOCK [IN]0x%x NOT INITIALIZED!!!",(lock));\
  	_rhp_panic();\
 	}\
  if( _RHP_TRC_COND(_rhp_trc_user_freq_id(),0) && !((lock)->debug_flag & RHP_MUTEX_DBG_FLAG_IGNORED) ){\
    RHP_LINE("#UNLOCK [IN]0x%x[%s](locked:%d)",(lock),(lock)->tag,(lock)->locked);\
	}\
  (lock)->locked = 0;\
  pthread_mutex_unlock(&((lock)->mutex));\
  if( _RHP_TRC_COND(_rhp_trc_user_freq_id(),0) && !((lock)->debug_flag & RHP_MUTEX_DBG_FLAG_IGNORED) ){\
    RHP_LINE("#UNLOCK [OUT]0x%x[%s](locked:%d)",(lock),(lock)->tag,(lock)->locked);\
	}\
}

#endif // RHP_MUTEX_DEBUG

#define RHP_EVT_NOTIFY_ALL(evt)   pthread_cond_broadcast((evt))
#define RHP_EVT_NOTIFY(evt)       pthread_cond_signal((evt))


// Wait for (sec) seconds.
static inline int _rhp_wait_event(rhp_cond_t *evt,rhp_mutex_t *lock,time_t diff_sec)
{
  if( diff_sec == 0 ){
    return pthread_cond_wait(evt,&(lock->mutex));
  }else{
    struct timespec t = {(time(NULL)+diff_sec),0};
    return pthread_cond_timedwait(evt,&(lock->mutex),&t);
  }
}

// Wait for (time) seconds + nano-seconds.
static inline int _rhp_wait_event_ex(rhp_cond_t *evt,rhp_mutex_t *lock,struct timespec* diff)
{
  if( diff == NULL ){
    return pthread_cond_wait(evt,&(lock->mutex));
  }else{
    struct timespec now, res;
		clock_gettime(CLOCK_REALTIME,&now);
		_rhp_timespec_add(&now,diff,&res);
    return pthread_cond_timedwait(evt,&(lock->mutex),&res);
  }
}

static inline int _rhp_thread_create(rhp_thread_t *thread,void *(*function)(void *),void *arg)
{
  pthread_attr_t atr;

  pthread_attr_init(&atr);
  pthread_attr_setdetachstate(&atr,PTHREAD_CREATE_DETACHED);

  return pthread_create(thread,NULL,function,arg);
}

static inline void _rhp_thread_exit(void* value)
{
  pthread_exit(value);
}

static inline int _rhp_thread_join(rhp_thread_t thread,void **value_ptr)
{
  return pthread_join(thread,value_ptr);
}

static inline int _rhp_cond_init(rhp_cond_t *evt)
{
  return pthread_cond_init(evt,NULL);
}

static inline int _rhp_cond_destroy(rhp_cond_t *evt)
{
  return pthread_cond_destroy(evt);
}

static inline int _rhp_mutex_init(char* tag,rhp_mutex_t *mutex)
{
  mutex->tag[0] = tag[0];
  mutex->tag[1] = tag[1];
  mutex->tag[2] = tag[2];
  mutex->tag[3] = '\0';
  mutex->locked = 0;
  mutex->debug_flag = RHP_MUTEX_DBG_FLAG_INITILIZED;
#ifdef RHP_MUTEX_DEBUG
  RHP_LINE("#LOCK_INIT 0x%x[%s](locked:%d)",(mutex),(mutex)->tag,(mutex)->locked);
#endif // RHP_MUTEX_DEBUG
  return pthread_mutex_init(&(mutex->mutex),NULL);
}

static inline int _rhp_mutex_destroy(rhp_mutex_t *mutex)
{
#ifdef RHP_MUTEX_DEBUG
  RHP_LINE("#LOCK_DESTROY 0x%x[%s](locked:%d)",(mutex),(mutex)->tag,(mutex)->locked);
#endif // RHP_MUTEX_DEBUG
  return pthread_mutex_destroy(&(mutex->mutex));
}

struct _rhp_atomic_t {
  rhp_mutex_t lock;
  volatile long c;
};
typedef struct _rhp_atomic_t  rhp_atomic_t;

static inline int _rhp_atomic_init(rhp_atomic_t* val)
{
	int ret;
  val->c = 0;
  ret = _rhp_mutex_init("ATM",&(val->lock));
  val->lock.debug_flag |= RHP_MUTEX_DBG_FLAG_IGNORED;
  return ret;
}

static inline void _rhp_atomic_destroy(rhp_atomic_t* val)
{
  _rhp_mutex_destroy(&(val->lock));
}

/*
#define _rhp_atomic_read(val) ({\
  long __ret2__;\
	RHP_LINE("#_rhp_atomic_read: 0x%x",(val));\
  RHP_LOCK(&((val)->lock));\
  __ret2__ = (val)->c;\
  RHP_UNLOCK(&((val)->lock));\
  __ret2__;\
})\
*/
static inline long _rhp_atomic_read(rhp_atomic_t* val)
{
  long r;
  RHP_LOCK(&(val->lock));
  r = val->c;
  RHP_UNLOCK(&(val->lock));
  return r;
}

static inline void _rhp_atomic_set(rhp_atomic_t* val,long c)
{
  RHP_LOCK(&(val->lock));
  val->c = c;
  RHP_UNLOCK(&(val->lock));
}

static inline void _rhp_atomic_inc(rhp_atomic_t* val)
{
  RHP_LOCK(&(val->lock));
  val->c++;
  RHP_UNLOCK(&(val->lock));
}

static inline long _rhp_atomic_inc_and_read(rhp_atomic_t* val)
{
	long r;
  RHP_LOCK(&(val->lock));
  r = ++val->c;
  RHP_UNLOCK(&(val->lock));
  return r;
}

static inline void _rhp_atomic_dec(rhp_atomic_t* val)
{
  RHP_LOCK(&(val->lock));
  val->c--;
  RHP_UNLOCK(&(val->lock));
}

static inline int _rhp_atomic_dec_and_test(rhp_atomic_t* val)
{
  int r = 0;
  RHP_LOCK(&(val->lock));
  if( --val->c == 0 ){r = 1;}
  RHP_UNLOCK(&(val->lock));
  return r;
}



struct _rhp_atomic_flag_t {
  rhp_mutex_t lock;
  volatile long c;
  volatile int flag;
};
typedef struct _rhp_atomic_flag_t  rhp_atomic_flag_t;

static inline int _rhp_atomic_flag_init(rhp_atomic_flag_t* val)
{
	int ret;
  val->c = 0;
  val->flag = 0;
  ret = _rhp_mutex_init("ATM",&(val->lock));
  val->lock.debug_flag |= RHP_MUTEX_DBG_FLAG_IGNORED;
  return ret;
}

static inline void _rhp_atomic_flag_destroy(rhp_atomic_flag_t* val)
{
  _rhp_mutex_destroy(&(val->lock));
}

static inline int _rhp_atomic_flag_inc(rhp_atomic_flag_t* val,long upper_threshold)
{
	long f;
  RHP_LOCK(&(val->lock));
  if( ++val->c >= upper_threshold && !val->flag ){
  	val->flag = 1;
  }
  f = val->flag;
  RHP_UNLOCK(&(val->lock));
  return f;
}

static inline long _rhp_atomic_flag_read_cnt(rhp_atomic_flag_t* val)
{
	long r;
  RHP_LOCK(&(val->lock));
  r = val->c;
  RHP_UNLOCK(&(val->lock));
  return r;
}

static inline int _rhp_atomic_flag_inc_and_test(rhp_atomic_flag_t* val,long upper_threshold,int* flag)
{
	long f,t = 0;
  RHP_LOCK(&(val->lock));
  if( ++val->c >= upper_threshold && !val->flag ){
  	val->flag = 1;
  	t = 1;
  }
  f = val->flag;
  RHP_UNLOCK(&(val->lock));
  if( flag ){
  	*flag = f;
  }
  return t;
}

static inline int _rhp_atomic_flag_dec(rhp_atomic_flag_t* val,long lower_threshold)
{
  int f;
  RHP_LOCK(&(val->lock));
  if( --val->c <= lower_threshold && val->flag ){
  	val->flag = 0;
  }
	f = val->flag;
  RHP_UNLOCK(&(val->lock));
  return f;
}

static inline int _rhp_atomic_flag_dec_and_test(rhp_atomic_flag_t* val,long lower_threshold,int* flag)
{
  int f,t = 0;
  RHP_LOCK(&(val->lock));
  if( --val->c <= lower_threshold && val->flag ){
  	val->flag = 0;
  	t = 1;
  }
	f = val->flag;
  RHP_UNLOCK(&(val->lock));
  if( flag ){
  	*flag = f;
  }
  return t;
}


/*************************

  Memory API wrappers

***************************/

//#include "rhp_misc2.h"


/************************

    Hash Functions

*************************/

#include "rhp_jhash.h"

static inline u32 _rhp_hash_ipv4_1(u32 ip,u32 rnd/*random*/)
{
  return jhash_1word(ip,rnd);
}

static inline u32 _rhp_hash_ipv4_2(u32 src_ip,u32 dst_ip,u32 rnd/*random*/)
{
  return jhash_2words(src_ip,dst_ip,rnd);
}

static inline u32 _rhp_hash_ipv4_2_ext(u32 src_ip,u32 dst_ip,u32 ext,u32 rnd/*random*/)
{
  return jhash_3words(src_ip,dst_ip,ext,rnd);
}

static inline u32 _rhp_hash_ipv4_udp(u32 src_ip,u16 src_port,u32 dst_ip,u16 dst_port,u32 rnd/*random*/)
{
  return jhash_3words(src_ip,dst_ip,((((u32)src_port) << 16) | ((u32)dst_port)),rnd);
}

static inline u32 _rhp_hash_ipv4_udp_src(u32 src_ip,u16 src_port,u32 rnd/*random*/)
{
  return jhash_2words(src_ip,(u32)src_port,rnd);
}



static inline u32 _rhp_hash_ipv6_1(u8* ip,u32 rnd/*random*/)
{
  return jhash2((u32*)ip,4,rnd);
}

static inline u32 _rhp_hash_ipv6_2(u8* src_ip,u8* dst_ip,u32 rnd/*random*/)
{
  return jhash2_2((u32*)src_ip,4,(u32*)dst_ip,4,rnd);
}

// ext: 16 bytes
static inline u32 _rhp_hash_ipv6_2_ext(u8* src_ip,u8* dst_ip,u8* ext,u32 rnd/*random*/)
{
  return jhash2_3((u32*)src_ip,4,(u32*)dst_ip,4,(u32*)ext,4,rnd);
}

static inline u32 _rhp_hash_ipv6_udp(u8* src_ip,u16 src_port,u8* dst_ip,u16 dst_port,u32 rnd/*random*/)
{
	u32 p = ((((u32)src_port) << 16) | ((u32)dst_port));
  return jhash2_3((u32*)src_ip,4,(u32*)dst_ip,4,&p,1,rnd);
}

static inline u32 _rhp_hash_ipv6_udp_src(u8* src_ip,u16 src_port,u32 rnd/*random*/)
{
	u32 p = (u32)src_port;
  return jhash2_2((u32*)src_ip,4,&p,1,rnd);
}


static inline u32 _rhp_hash_u32s(u8* key/*32bits aligned*/,u32 key_len,u32 rnd/*random*/)
{
  return jhash2((u32*)key,(key_len >> 2),rnd);
}

static inline u32 _rhp_hash_bytes(const void *key, u32 len, u32 rnd)
{
  return jhash(key,len,rnd);
}

static inline u32 _rhp_hash_bytes_2(const void *key1, u32 len1,const void *key2, u32 len2, u32 rnd)
{
  return (jhash(key1,len1,rnd) ^  jhash(key2,len2,rnd));
}

static inline u32 _rhp_hash_u32(u32 key,u32 rnd)
{
  return jhash_1word(key,rnd);
}

static inline u32 _rhp_hash_2u32(u32 key0,u32 key1,u32 rnd)
{
  return jhash_2words(key0,key1,rnd);
}


/******************************

  Network Interface Table

*******************************/

#define RHP_IFNAMSIZ  32 // (cf.) net/if.h: #define IF_NAMESIZE	16
struct _rhp_if_entry {

  char if_name[RHP_IFNAMSIZ];
  u8 mac[6];
  u16 mac_reserved0; // 32b boundary.
  int if_index;
  unsigned int if_flags; // IFF_UP etc...
  unsigned int mtu; // bytes

  int addr_family; // AF_INET or AF_INET6

  union {
    u32 v4;
    u8  v6[16];
    u8  raw[16];
  } addr;

  int prefixlen;

  //
  // IFA_F_XXX (include/uapi/linux/if_addr.h)
  //
  // Actually, #define IFA_F_TEMPORARY IFA_F_SECONDARY in if_addr.h.
#define RHP_IFA_F_TEMPORARY(if_addr_flags)		((if_addr_flags) & IFA_F_TEMPORARY)
#define RHP_IFA_F_SECONDARY(if_addr_flags)		((if_addr_flags) & IFA_F_SECONDARY)
#define RHP_IFA_F_NODAD(if_addr_flags)				((if_addr_flags) & IFA_F_NODAD)
#define RHP_IFA_F_OPTIMISTIC(if_addr_flags)		((if_addr_flags) & IFA_F_OPTIMISTIC)
#define RHP_IFA_F_DADFAILED(if_addr_flags)		((if_addr_flags) & IFA_F_DADFAILED)
#define RHP_IFA_F_HOMEADDRESS(if_addr_flags)	((if_addr_flags) & IFA_F_HOMEADDRESS)
#define RHP_IFA_F_DEPRECATED(if_addr_flags)		((if_addr_flags) & IFA_F_DEPRECATED)
#define RHP_IFA_F_TENTATIVE(if_addr_flags)		((if_addr_flags) & IFA_F_TENTATIVE)
#define RHP_IFA_F_PERMANENT(if_addr_flags)		((if_addr_flags) & IFA_F_PERMANENT)
  unsigned int if_addr_flags;
};
typedef struct _rhp_if_entry  rhp_if_entry;


extern void rhp_if_entry_dump(char* label,rhp_if_entry* if_ent);
extern int rhp_if_entry_cmp(rhp_if_entry* if_ent0,rhp_if_entry* if_ent1);


/******************************

  Network address Table

*******************************/

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

struct _rhp_ip_addr {

  int addr_family; // AF_INET or AF_INET6

  union {
    u32 v4;
    u8  v6[16];
    u8  raw[16];
  } addr;

  union {
    u32 v4;
    u8  v6[16];
    u8  raw[16];
  } netmask;

  int prefixlen;

  u16 port;
  u16 reserved;

  u32 ipv6_scope_id; // if_index

#define RHP_IPADDR_TAG_NONE									0
#define RHP_IPADDR_TAG_IKEV2_CFG_ASSIGNED		1 // For remote config server (responder)
#define RHP_IPADDR_TAG_STATIC_PEER_ADDR			2
#define RHP_IPADDR_TAG_INVALID_ADDR					3
#define RHP_IPADDR_TAG_IKEV2_EXCHG					4
  int tag;

  unsigned long priv;
};
typedef struct _rhp_ip_addr  rhp_ip_addr;


extern rhp_ip_addr* rhp_ipv6_loopback_addr;
extern rhp_ip_addr* rhp_ipv6_all_node_multicast_addr;
extern rhp_ip_addr* rhp_ipv6_all_router_multicast_addr;
extern rhp_ip_addr* rhp_ipv6_mld2_multicast_addr;


extern void rhp_ip_addr_dump(char* label,rhp_ip_addr* addr);

extern void rhp_ip_addr_set(rhp_ip_addr* ipaddr,int addr_family,u8* addr,u8* netmask,int prefixlen,
		u16 port,u32 ipv6_scope_id);
extern void rhp_ip_addr_set2(rhp_ip_addr* ipaddr,int addr_family,u8* addr,u16 port);
extern void rhp_ip_addr_reset(rhp_ip_addr* ipaddr);


extern u32 rhp_ipv4_prefixlen_to_netmask(int prefix_len);
extern void rhp_ipv6_prefixlen_to_netmask(int prefix_len,u8* mask_r);
extern int rhp_ipv4_netmask_to_prefixlen(u32 netmask);
extern int rhp_ipv6_netmask_to_prefixlen(u8* netmask);
extern int rhp_ip_addr_null(rhp_ip_addr* addr);
extern int rhp_ipv6_addr_null(u8* addr);
extern int rhp_netmask_null(rhp_ip_addr* addr);
extern int rhp_ip_same_subnet(rhp_ip_addr* subnet_addr,int addr_family,u8* addr);
extern int rhp_ip_same_subnet2(int addr_family,u8* addr0,u8* addr1,int prefixlen);
extern int rhp_ip_same_subnet_v4(u32 addr0,u32 addr1,int prefixlen);
extern int rhp_ip_same_subnet_v6(u8* addr0,u8* addr1,int prefixlen);
extern void rhp_ip_gen_multicast_mac(int addr_family,u8* ip,u8* mac_r);
extern int rhp_ip_subnet_broadcast(rhp_ip_addr* subnet_addr,int addr_family,u8* addr);
extern int rhp_ip_multicast(int addr_family,u8* addr);
extern int rhp_ip_is_loopback(rhp_ip_addr* addr);
extern int rhp_ipv4_is_loopback(u32 addr);
extern int rhp_ipv6_is_loopback(u8* addr);
extern int rhp_ipv4_is_linklocal(u32 addr);
extern int rhp_ipv6_is_linklocal(u8* addr);
extern int rhp_ipv6_is_linklocal_all_types(u8* addr);
extern int rhp_ip_is_linklocal(int addr_family,u8* addr);
extern int rhp_ipv4_valid_peer_addrs(u32 addr0,u32 addr1);
extern int rhp_ipv6_valid_peer_addrs(u8* addr0,u8* addr1);
extern int rhp_ip_valid_peer_addrs(int addr_family,u8* addr0,u8* addr1);
extern void rhp_ipv6_gen_solicited_node_multicast(u8* ipv6,u8* maddr_r);
extern int rhp_ipv6_is_solicited_node_multicast(u8* ipv6);
extern int rhp_ip_network_addr(int addr_family,u8* addr,int prefix_len,
		rhp_ip_addr* network_addr_r);


// Comparison between objects (including a port number, netmask, and prefixlen).
extern int rhp_ip_addr_cmp(rhp_ip_addr* addr0,rhp_ip_addr* addr1);
// -1 : not matched , 0 : equal , 1 : addr0 < addr1 , 2 : addr0 > addr1
extern int rhp_ip_addr_cmp_ip_only(rhp_ip_addr* addr0,rhp_ip_addr* addr1);
// -1 : not matched , 0 : equal , 1 : addr0 < addr1 , 2 : addr0 > addr1
extern int rhp_ip_addr_cmp_value(rhp_ip_addr* addr0,int addr1_len,u8* addr1);
extern int rhp_ip_addr_gt_ip(rhp_ip_addr* addr0,rhp_ip_addr* addr1);
extern int rhp_ip_addr_lt_ip(rhp_ip_addr* addr0,rhp_ip_addr* addr1);
extern int rhp_ip_addr_gt_ipv4(rhp_ip_addr* addr0,u32 addr1);
extern int rhp_ip_addr_gt_ipv6(rhp_ip_addr* addr0,u8* addr1);
extern int rhp_ip_addr_gt_iphdr(rhp_ip_addr* addr0,int addr_family,u8* iphdr,int src_or_dst/* 0: Src, 1: Dst */);
extern int rhp_ip_addr_lt_ipv4(rhp_ip_addr* addr0,u32 addr1);
extern int rhp_ip_addr_lt_ipv6(rhp_ip_addr* addr0,u8* addr1);
extern int rhp_ip_addr_lt_iphdr(rhp_ip_addr* addr0,int addr_family,u8* iphdr,int src_or_dst/* 0: Src, 1: Dst */);
extern int rhp_ip_addr_gteq_ip(rhp_ip_addr* addr0,rhp_ip_addr* addr1);
extern int rhp_ip_addr_lteq_ip(rhp_ip_addr* addr0,rhp_ip_addr* addr1);
extern int rhp_ip_addr_eq_ip(rhp_ip_addr* addr0,rhp_ip_addr* addr1);


extern int rhp_ip_addr_longest_match(rhp_ip_addr* addr0,rhp_ip_addr* addr1,int max_prefix_len);

extern int rhp_ipv6_addr_cmp_prefix(u8* addr0,u8* addr1,int prefix_len);
extern int rhp_ipv6_is_same_addr(u8* addr0,u8* addr1);

extern void rhp_ipv4_subnet_addr_range(u32 subnet_addr,u32 subnet_mask,u32* start_r,u32* end_r);
extern void rhp_ipv4_subnet_addr_range2(u32 subnet_addr,int prefix_len,u32* start_r,u32* end_r);
extern void rhp_ipv6_subnet_addr_range(u8* subnet_addr,int prefix_len,u8* start_r,u8* end_r);

static inline int _rhp_mac_addr_null(u8* mac)
{
	if( mac == NULL ){
		return 1;
	}
	if( mac[0] || mac[1] || mac[2] || mac[3] || mac[4] || mac[5] ){
		return 0;
	}
	return 1;
}

extern int rhp_str_to_mac(char* str,u8* mac_r);

// -1 : error, 0: tiebreaker, 1: src_addr0 wins and 2: src_addr1 wins.
extern int rhp_ipv4_cmp_src_addr(
		rhp_ip_addr* src_addr0,rhp_ip_addr* src_addr1,rhp_ip_addr* dest_addr);

// -1 : error, 0: tiebreaker, 1: src_addr0 wins and 2: src_addr1 wins.
extern int rhp_ipv6_cmp_src_addr(rhp_ip_addr* src_addr0,unsigned int src_addr0_flag,
		rhp_ip_addr* src_addr1,unsigned int src_addr1_flag,
		rhp_ip_addr* dest_addr);

extern char* rhp_ipv6_string(u8* addr);
extern char* rhp_ipv6_string2(u8* addr,char* str_r); // str_r: char[INET6_ADDRSTRLEN + 1];
extern char* rhp_ip_port_string(rhp_ip_addr* ip_addr);

// addr_family: AF_UNSPEC, AF_INET or AF_INET6
extern int rhp_ip_str2addr(int addr_family,char* ip_addr_str,rhp_ip_addr* ip_r);



struct _rhp_ip_addr_list {
	rhp_ip_addr ip_addr;
	struct _rhp_ip_addr_list* next;
};
typedef struct _rhp_ip_addr_list  rhp_ip_addr_list;

static inline void rhp_ip_addr_list_free(rhp_ip_addr_list* addrs_head)
{
	rhp_ip_addr_list *addrl = addrs_head, *addrl_n;
	while( addrl ){
		addrl_n = addrl->next;
		_rhp_free(addrl);
		addrl = addrl_n;
	}
	return;
}

static inline rhp_ip_addr_list* rhp_ip_addr_list_included(
		rhp_ip_addr_list* addrs_head,rhp_ip_addr* addr,int cmp_ip_only)
{
	rhp_ip_addr_list *addrl = addrs_head;

	while( addrl ){

		if( cmp_ip_only ){

			if( !rhp_ip_addr_cmp_ip_only(&(addrl->ip_addr),addr) ){
				return addrl;
			}

		}else{

			if( !rhp_ip_addr_cmp(&(addrl->ip_addr),addr) ){
				return addrl;
			}
		}

		addrl = addrl->next;
	}
	return NULL;
}

extern rhp_ip_addr_list* rhp_ip_dup_addr_list(rhp_ip_addr* ipaddr);

extern rhp_ip_addr* rhp_ip_search_addr_list(rhp_ip_addr_list* addr_lst,
		int (*filter)(rhp_ip_addr* ipaddr,void* ctx),void* ctx);

extern int rhp_ip_search_addr_list_cb_addr_family_no_linklocal(rhp_ip_addr* ipaddr,
		void* ctx); // ctx: AF_INET or AF_INET6
extern int rhp_ip_search_addr_list_cb_addr_family(rhp_ip_addr* ipaddr,
		void* ctx); // ctx: AF_INET or AF_INET6

extern int rhp_ip_search_addr_list_cb_addr_tag(rhp_ip_addr* ipaddr,
		void* ctx); // ctx: RHP_IPADDR_TAG_XXX

extern int rhp_ip_search_addr_list_cb_addr_ipv4_tag(rhp_ip_addr* ipaddr,
		void* ctx); // ctx: RHP_IPADDR_TAG_XXX
extern int rhp_ip_search_addr_list_cb_addr_ipv6_tag(rhp_ip_addr* ipaddr,
		void* ctx); // ctx: RHP_IPADDR_TAG_XXX

extern int rhp_ip_search_addr_list_cb_v6_linklocal(rhp_ip_addr* ipaddr,void* ctx);



#include <byteswap.h>

#ifdef RHP_BIG_ENDIAN
#define _rhp_htonll(v)	((v))
#define _rhp_ntohll(v)	((v))
#else	// RHP_BIG_ENDIAN
#define _rhp_htonll(v)	bswap_64((v))
#define _rhp_ntohll(v)	bswap_64((v))
#endif // RHP_BIG_ENDIAN


/******************************

  Network Route Map Table

*******************************/

struct _rhp_rt_map_entry {

#define RHP_RTMAP_TYPE_UNKNOWN					0
#define RHP_RTMAP_TYPE_DEFAULT					1
#define RHP_RTMAP_TYPE_STATIC						2
#define RHP_RTMAP_TYPE_DYNAMIC					3
#define RHP_RTMAP_TYPE_DYNAMIC_DEFAULT	4
#define RHP_RTMAP_TYPE_DEFAULT_INTERNAL					5
#define RHP_RTMAP_TYPE_STATIC_INTERNAL					6
#define RHP_RTMAP_TYPE_DYNAMIC_INTERNAL					7
#define RHP_RTMAP_TYPE_DYNAMIC_DEFAULT_INTERNAL	8
#define RHP_RTMAP_TYPE_NHRP_CACHE								9
  int type;

  int rtm_type; // rtnetlink.h: RTN_XXX, struct rtmsg->rtm_type

  int addr_family; // AF_INET or AF_INET6

  char oif_name[RHP_IFNAMSIZ];
  int oif_index;

  rhp_ip_addr dest_network;

  rhp_ip_addr gateway_addr;

  int metric;
};
typedef struct _rhp_rt_map_entry  rhp_rt_map_entry;


static inline int rhp_rtmap_entry_cmp(rhp_rt_map_entry* rtmap0,rhp_rt_map_entry* rtmap1)
{
	if( rtmap0 == NULL || rtmap1 == NULL ){
		return -1;
	}
	return memcmp(rtmap0,rtmap1,sizeof(rhp_rt_map_entry));
}

extern void rhp_rtmap_entry_dump(char* label,rhp_rt_map_entry* rtmap_ent);


/**************************

         IKEv2 ID

***************************/

#include "rhp_protocol.h"
#include "rhp_cert.h"

struct _rhp_ikev2_id {

  int type; // RHP_PROTO_IKE_ID_XXX, > sizeof(u8)
  int cert_sub_type; // RHP_PROTO_IKE_ID_XXX, > sizeof(u8)

  char* string;

  int dn_der_len;
  u8* dn_der;

  rhp_ip_addr addr;

  char* conn_name_for_null_id;

  struct _rhp_ikev2_id* alt_id;

  unsigned long priv;
};
typedef struct _rhp_ikev2_id  rhp_ikev2_id;

extern void rhp_ikev2_id_dump(char* label,rhp_ikev2_id* id);

extern void rhp_ikev2_id_clear(rhp_ikev2_id* id);
extern int rhp_ikev2_id_dup(rhp_ikev2_id* id_to,rhp_ikev2_id* id_from);
extern int rhp_ikev2_id_setup(int type,void* val,int val_len,rhp_ikev2_id* id_to);
extern int rhp_ikev2_id_setup_ex(int type,void* val0,int val0_len,void* val1,int val1_len,rhp_ikev2_id* id_to);
extern int rhp_ikev2_id_hash(rhp_ikev2_id* id,u32 rnd,u32* hval_r);
extern int rhp_ikev2_id_value(rhp_ikev2_id* id,u8** value_r,int* len_r,int* id_type_r);
extern int rhp_ikev2_id_value_str(rhp_ikev2_id* id,u8** value_r,int* len_r,int* id_type_r);
extern int rhp_ikev2_id_cmp(rhp_ikev2_id* id0,rhp_ikev2_id* id1);
extern int rhp_ikev2_id_cmp_no_alt_id(rhp_ikev2_id* id0,rhp_ikev2_id* id1);
extern int rhp_ikev2_id_cmp_by_value(rhp_ikev2_id* id0,int id1_type,int id1_len,u8* id1);
extern int rhp_ikev2_id_cmp_sub_type_too(rhp_ikev2_id* id0,rhp_ikev2_id* id1);
extern int rhp_ikev2_id_cmp_sub_type_too_by_value(rhp_ikev2_id* id0,int id1_type,int id1_len,u8* id1);
extern int rhp_ikev2_id_to_string(rhp_ikev2_id* id,char** id_type_r,char** id_str_r);
extern int rhp_ikev2_id_alt_setup(int type,void* val,int val_len,rhp_ikev2_id* id_to);
extern int rhp_ikev2_is_null_auth_id(int id_type);
extern int rhp_ikev2_id_is_null_auth_id(rhp_ikev2_id* id);
extern int rhp_ikev2_to_null_auth_id(int id_type);

struct _rhp_eap_id {

	int method; // RHP_PROTO_EAP_TYPE_XXX. In case of RHP_PROTO_EAP_TYPE_PRIV_RADIUS,
							// see vpn->radius.eap_method for actual method type (if any).

	int identity_len; // NOT including the last '\0'.
	u8* identity; 		 // '\0' terminated.

	struct {

		int eap_method; // Not RHP_PROTO_EAP_TYPE_PRIV_RADIUS.

		char* user_index; // by RADIUS server

		rhp_ip_addr* assigned_addr_v4; // by RADIUS server
		rhp_ip_addr* assigned_addr_v6; // by RADIUS server

		u32 salt; // For internal user only. Don't ref it.

	} radius;

	int for_xauth;
};
typedef struct _rhp_eap_id	rhp_eap_id;

extern void rhp_eap_id_dump(char* label,rhp_eap_id* eap_id);

extern int rhp_eap_id_hash(rhp_eap_id* eap_peer_id,u32 rnd,u32* hval_r);
extern void rhp_eap_id_clear(rhp_eap_id* eap_id);
extern int rhp_eap_id_cmp(rhp_eap_id* eap_id0,rhp_eap_id* eap_id1);
extern int rhp_eap_id_is_null(rhp_eap_id* eap_id);
extern int rhp_eap_id_setup(int method, // RHP_PROTO_EAP_TYPE_XXX
		int identity_len, // NOT including the last '\0'
		u8* identity,		 	// NOT '\0' terminated.
		int for_xauth,
		rhp_eap_id* eap_id_r);
extern int rhp_eap_id_dup(rhp_eap_id* id_to,rhp_eap_id* id_from);
extern int rhp_eap_id_to_string(rhp_eap_id* eap_id,char** eap_id_method_r,char** eap_id_str_r);
extern int rhp_eap_id_radius_not_null(rhp_eap_id* id);


/***********************

       Debug APIs

************************/

static inline void _rhp_print_dump(char* d,int len)
{
  int i,j;
  char* mc = d;
  printf("addr : 0x%lx , len : %d\n",(unsigned long)d,len);
  printf("*0 *1 *2 *3 *4 *5 *6 *7 *8 *9 *A *B *C *D *E *F     0123456789ABCDEF\n");
  for( i = 0;i < len; i++ ){
    int pd;
    if( i && (i % 16) == 0 ){
      printf("    ");
      for( j = 0;j < 16; j++ ){
        if( *mc >= 33 && *mc <= 126 ){printf("%c",*mc);
        }else{printf(".");}
        mc++;
      }
      printf("\n");
    }

    pd = ((*(int *)d) & 0x000000FF);

    if( pd <= 0x0F ){printf("0");}
    printf("%x ",pd);
    d++;
  }

  {
    int k,k2;
    if( (i % 16) == 0 ){
      k = 0;
      k2 = 16;
    }else{
      k = 16 - (i % 16);
      k2 = (i % 16);
    }
    for( i = 0; i < k;i++ ){printf("   ");}
    printf("    ");
    for( j = 0;j < k2; j++ ){
      if( *mc >= 33 && *mc <= 126 ){
        printf("%c",*mc);
      }else{printf(".");
      }
      mc++;
    }
  }

  printf("\n");
}


/********************

     Misc Utils

*********************/

extern int rhp_string_prefix_search(u8* bytes,int len/*'\0' NOT included.*/,char* pattern);
extern int rhp_string_suffix_search(u8* bytes,int len/*'\0' NOT included.*/,char* pattern);

extern u8* rhp_bin_pattern(u8* buf,int buf_len,u8* pattern,int pattern_len);

extern int rhp_bin2str_dump(int bin_len,u8* bin,int scale,int* res_len_r,char** res_r);


//
// a , b must be 'unsigned long'.
//
#define RHP_AFTER(a,b)		   ((long)(b) - (long)(a) < 0))
#define RHP_BEFORE(a,b)      RHP_AFTER(b,a)
#define RHP_AFTER_EQ(a,b)    ((long)(a) - (long)(b) >= 0))
#define RHP_BEFORE_EQ(a,b)   RHP_AFTER_EQ(b,a)



#ifdef RHP_LIBXML2

/**************************

  XML Utils / File Utils

***************************/

#include <libxml/xmlmemory.h>
#include <libxml/encoding.h>
#include <libxml/parser.h>
#include <libxml/xmlwriter.h>

#define RHP_XML_DT_LONG	        0  // long
#define RHP_XML_DT_ULONG	      1  // unsigned long
#define RHP_XML_DT_LONGLONG     2  // long long
#define RHP_XML_DT_ULONGLONG   	3  // unsigned long long
#define RHP_XML_DT_IPV4         4  // u8[4] (Network byte order)
#define RHP_XML_DT_IPV6         5  // rhp_ip_addr (allocated by caller)
#define RHP_XML_DT_PORT         6  //  u16 (Network byte order)
#define RHP_XML_DT_STRING       7  // char*
#define RHP_XML_DT_IPV4_SUBNET  8  // rhp_ip_addr
#define RHP_XML_DT_IPV6_SUBNET  9  // rhp_ip_addr
#define RHP_XML_DT_BASE64       10 // u8*
#define RHP_XML_DT_DN_DER       11 // u8* (DER encoded bytes)
#define RHP_XML_DT_INT 	        12 // int
#define RHP_XML_DT_UINT 	      13 // unsigned int
#define RHP_XML_DT_DOUBLE 	    14 // double
extern int rhp_xml_str2val(xmlChar* str,int data_type,void* retval,int* retval_len,void* def_val,int def_val_len);

extern int rhp_xml_strcasecmp(xmlChar* str1,xmlChar* str2);

extern int rhp_xml_enum_tags(xmlNodePtr parent_node,xmlChar* tag,
                              int (*callback)(xmlNodePtr node,void* ctx),void* ctx,int enum_all);

extern int rhp_xml_write_node(xmlNodePtr node,xmlTextWriterPtr writer,
		int* len,int recursively,
		int (*node_filter_callback)(xmlNodePtr node,void* ctx),
		int (*attr_filter_callback)(xmlNodePtr node,xmlAttrPtr attr,char** new_prop_val,void* ctx),void* ctx);

extern int rhp_xml_write_node_start(xmlNodePtr node,xmlTextWriterPtr writer,int* len,
		int (*attr_filter_callback)(xmlNodePtr node,xmlAttrPtr attr,char** new_prop_val,void* ctx),void* ctx);

extern int rhp_xml_write_node_end(xmlNodePtr node,xmlTextWriterPtr writer,int* len);


extern xmlNodePtr rhp_xml_get_child(xmlNodePtr parent_node,xmlChar* tag);
extern int rhp_xml_set_prop(xmlNodePtr cur_node,xmlChar* name,xmlChar* value);
extern void rhp_xml_delete_child(xmlNodePtr parent_node,xmlChar* tag);
extern int rhp_xml_replace_child(xmlNodePtr cur_parent_node,xmlNodePtr new_parent_node,xmlChar* elm_tag,int clear_flag);
extern int rhp_xml_get_text_or_cdata_content(xmlNodePtr node,xmlChar** content_r,int* content_len_r);

extern xmlChar* rhp_xml_get_prop(xmlNodePtr node,const xmlChar* prop_name);
extern xmlChar* rhp_xml_get_prop_static(xmlNodePtr node,const xmlChar* prop_name);
extern int rhp_xml_check_enable(xmlNodePtr node,const xmlChar* prop_name,int* flag_r);

extern xmlChar* rhp_xml_search_prop_in_children(xmlNodePtr parent_node,xmlChar* elm_tag,xmlChar* prop_name,xmlNodePtr* node_r);
extern int rhp_xml_prop_update_in_children(xmlNodePtr cur_parent_node,xmlNodePtr new_parent_node,xmlChar* elm_tag,xmlChar* prop_name);
extern xmlNodePtr rhp_xml_search_prop_value_in_children(xmlNodePtr parent_node,xmlChar* elm_tag,xmlChar* prop_name,xmlChar* prop_val);
extern xmlNodePtr rhp_xml_search_prop_value_in_children2(xmlNodePtr parent_node,xmlChar* elm_tag,
		xmlChar* prop_name,xmlChar* prop_val,xmlChar* prop_name2,xmlChar* prop_val2);

extern void rhp_xml_doc_dump(char* label,xmlDocPtr doc);

#endif // RHP_LIBXML2


/*******************

	File Utils

********************/

extern int rhp_file_copy(char* src_file_path_name,char* dst_file_path_name,mode_t dst_mode);
extern int rhp_file_read_line(int fd,char** line_r);
extern int rhp_file_write(char* file_path,u8* buf,int buf_len,mode_t fmode);
extern int rhp_file_exists(char* file_path_name);
extern int rhp_file_read_data(char* file_path_name,int buf_len,u8* buf);


/*******************

	  VPN UID

********************/

extern int rhp_str_to_vpn_unique_id(char* str,u8* unique_id_r);



/********************

   Exec cmd Utils

*********************/

struct _rhp_cmd_tlv {

	u8 tag[4]; // '#CTV'

	struct _rhp_cmd_tlv* next;

	char* name;

#define RHP_CMD_TLV_LONG										1
#define RHP_CMD_TLV_ULONG										2
#define RHP_CMD_TLV_IPV4										3 // rhp_ip_addr
#define RHP_CMD_TLV_IPV6										4 // rhp_ip_addr
#define RHP_CMD_TLV_PORT										5
#define RHP_CMD_TLV_STRING									6
#define RHP_CMD_TLV_IPV4_SUBNET_PREFIX			7 // rhp_ip_addr
#define RHP_CMD_TLV_IPV6_SUBNET_PREFIX			8 // rhp_ip_addr
#define RHP_CMD_TLV_IPV4_SUBNET_MASK				9 // rhp_ip_addr
#define RHP_CMD_TLV_INT											10
#define RHP_CMD_TLV_UINT										11
	int type;

	unsigned long value_len;
	void* value;
};
typedef struct _rhp_cmd_tlv		rhp_cmd_tlv;

struct _rhp_cmd_tlv_list {
	rhp_cmd_tlv* head;
	rhp_cmd_tlv* tail;
};
typedef struct _rhp_cmd_tlv_list		rhp_cmd_tlv_list;

extern int rhp_cmd_exec_init();
extern int rhp_cmd_exec_cleanup();
extern int rhp_cmd_tlv_add(rhp_cmd_tlv_list* list,int type,char* name,unsigned long value_len,void* value);
extern void rhp_cmd_tlv_clear(rhp_cmd_tlv_list* list);
extern int rhp_cmd_exec(char* cmd,rhp_cmd_tlv_list* envs,int sync_flag);
extern void rhp_cmd_exec_sync(pid_t pid,int exit_status);


/*******************

     CRC32

********************/

extern u_int32_t rhp_crc32(u_int32_t crc, const void *buf, size_t size);



/**********************

	DNS resolution Utils

***********************/

extern int rhp_dns_resolve(int disp_priority,char* peer_fqdn,
		int addr_family, // AF_INET, AF_INET6 or AF_UNSPEC(both IPv4 and IPv6)
		void (*callback)(void* cb_ctx0,void* cb_ctx1,int err,int res_addrs_num,rhp_ip_addr* res_addrs),
		void* cb_ctx0,void* cb_ctx1);


/**********************

   EUI64 I/F ID

***********************/

struct _rhp_eui64_id {
	u8 id[8];
	int gen_by_global_id;
};
typedef struct _rhp_eui64_id	rhp_eui64_id;

// if_id: MAC address(48bits) or NULL.
// id_r: 64bits
extern int rhp_eui64_id_gen(u8* if_id,rhp_eui64_id* id_r);
extern void rhp_eui64_id_clear(rhp_eui64_id* id);




/**********************

	   String list

***********************/

struct _rhp_string_list {

	struct _rhp_string_list* next;

	char* string;
};
typedef struct _rhp_string_list	rhp_string_list;

static inline void _rhp_string_list_free(rhp_string_list* list_head)
{
	rhp_string_list* p0 = list_head;
	while( p0 ){

		rhp_string_list* p1 = p0->next;

//		RHP_LINE("_rhp_string_list_free() p0:0x%x,p0->string:0x%x, p1:0x%x",p0,p0->string,p1);

		if( p0->string ){
			_rhp_free(p0->string);
		}
		_rhp_free(p0);
		p0 = p1;
	}
}

static inline char* _rhp_string_list_cat(rhp_string_list* list_head)
{
	rhp_string_list *p0 = list_head, *p1;
	int len = 0, n = 0;
	char *ret = NULL, *p;

	while( p0 ){

		p1 = p0->next;

		if( p0->string ){
			len += strlen(p0->string);
			n++;
		}
		p0 = p1;
	}

	ret = (char*)_rhp_malloc(len + n + 1);
	if( ret == NULL ){
		RHP_BUG("");
		return NULL;
	}
	p = ret;

	p0 = list_head;
	while( p0 ){

		p1 = p0->next;

		if( p0->string ){
			int sn = strlen(p0->string);
			memcpy(p,p0->string,sn);
			p[sn] = ' ';
			p += (sn + 1);
		}
		p0 = p1;
	}
	*p = '\0';

	return ret;
}




/**********************

	  Packet Capture

***********************/

#define RHP_PKT_CAP_FLAG_ESP_PLAIN		0
#define RHP_PKT_CAP_FLAG_ESP_CIPHER		1
#define RHP_PKT_CAP_FLAG_IKEV2_PLAIN	2
#define RHP_PKT_CAP_FLAG_IKEV2_CIPHER	3
#define RHP_PKT_CAP_FLAG_VIF					4
#define RHP_PKT_CAP_FLAG_RADIUS				5
#define RHP_PKT_CAP_FLAG_ESP_PLAIN_NOT_CHECKED	6
#define RHP_PKT_CAP_FLAG_MAX					6
extern u8 rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_MAX + 1];

extern unsigned long rhp_packet_capture_realm_id;


#endif // _RHP_MISC_H_

