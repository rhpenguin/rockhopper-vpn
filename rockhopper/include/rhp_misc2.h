#ifndef _RHP_MISC2_H_
#define _RHP_MISC2_H_


#include "rhp_trace.h"

/*************************

  Private data types

**************************/

#ifndef RHP_TYPES_DONT_DEF
typedef u_int64_t u64;
typedef u_int32_t u32;
typedef u_int16_t u16;
typedef u_int8_t   u8;
#endif //RHP_TYPES_DONT_DEF
#define RHP_TRUE    	1
#define RHP_FALSE   	0


/*******************************

  Debug Trace

********************************/

#ifndef RHP_TRC_FMT_A_MAC

#define RHP_TRC_FMT_A_MAC												0
#define RHP_TRC_FMT_A_IPV4											1
#define RHP_TRC_FMT_A_UDP												2
#define RHP_TRC_FMT_A_ESP												3
#define RHP_TRC_FMT_A_IKEV2											4
#define RHP_TRC_FMT_A_IKEV2_PLAIN								5
#define RHP_TRC_FMT_A_MAC_IPV4_ESP							6
#define RHP_TRC_FMT_A_MAC_IPV4_IKEV2						7
#define RHP_TRC_FMT_A_MAC_IPV4_IKEV2_PLAIN			8
#define RHP_TRC_FMT_A_FROM_MAC_RAW							9
#define RHP_TRC_FMT_A_IKEV2_PLAIN_PAYLOADS			10 // NOT including [E]'s header, IV, and ICV fields.
#define RHP_TRC_FMT_A_MAC_IPV4_NAT_T_KEEPALIVE	11
#define RHP_TRC_FMT_A_IKEV2_UDP_SK							12
#define RHP_TRC_FMT_A_IKEV2_NAT_T_UDP_SK				13
#define RHP_TRC_FMT_A_ESP_RAW_SK								14
#define RHP_TRC_FMT_A_IPV6								  		15
#define RHP_TRC_FMT_A_MAC_IPV6_ESP							16
#define RHP_TRC_FMT_A_MAC_IPV6_IKEV2						17
#define RHP_TRC_FMT_A_MAC_IPV6_IKEV2_PLAIN			18
#define RHP_TRC_FMT_A_MAC_IPV6_NAT_T_KEEPALIVE	19
#define RHP_TRC_FMT_A_GRE_NHRP									20

#endif // RHP_TRC_FMT_A_MAC

//
//
//  void rhp_trace(unsigned char userid,unsigned long record_id, /*char* format,(top of va_args)*/...);
//
//  format (extention)  :
//
//   'u' : unsigned long data. For user land app.
//   'U' : unsigned long data. For user land app.(BE(swapped))
//   'j' : 4B data. For user land app.
//   'J' : 4B data. For user land app.(BE(swapped))
//   'k' : 4B data(HEX). For user land app.
//   'K' : 4B data(HEX). For user land app.(BE(swapped))
//   'x' : unsigned long data(HEX). (long, address) For user land app.
//   'X' : unsigned long data(HEX). (long, address) For user land app.(BE(swapped))
//   'F' : unsigned long data. (unsigned long) For user land app.
//
//	 'Y' : A symbol like a function pointer. unsigned long data. (address) For user land app.
//	 'E' : Error code. 4B data. For user land app.
//	 'L' : Dummy symbol to append a label for "%?m[...]" format or %?B[...] format. For user land app.
//        (ex) 	rhp_trace(RHP_TRC_USER_MAIN,12,"Lb","LABEL",val);//Len of 'val' is 1B. ==> Formatted as "%bm[LABEL]".
//					rhp_trace(RHP_TRC_USER_MAIN,12,"Lw","LABEL",val);//Len of 'val' is 2B. ==> Formatted as "%wm[LABEL]".
//					rhp_trace(RHP_TRC_USER_MAIN,12,"Ld","LABEL",val);//Len of 'val' is 4B. ==> Formatted as "%dm[LABEL]".
//					rhp_trace(RHP_TRC_USER_MAIN,12,"Lq","LABEL",val);//Len of 'val' is 8B. ==> Formatted as "%qm[LABEL]".
//					rhp_trace(RHP_TRC_USER_MAIN,12,"LW","LABEL",val);//Len of 'val' is 2B. ==> Formatted as "%wm[LABEL]".
//					rhp_trace(RHP_TRC_USER_MAIN,12,"LD","LABEL",val);//Len of 'val' is 4B. ==> Formatted as "%dm[LABEL]".
//					rhp_trace(RHP_TRC_USER_MAIN,12,"LQ","LABEL",val);//Len of 'val' is 8B. ==> Formatted as "%qm[LABEL]".
//					rhp_trace(RHP_TRC_USER_MAIN,12,"LB","LABEL",1,&val); //'val' is u8(Len of 'val' is 1B). ==> Formatted as "%bB[LABEL]".
//					rhp_trace(RHP_TRC_USER_MAIN,12,"LB","LABEL",2,&val); //'val' is u16(Len of 'val' is 2B). ==> Formatted as "%wB[LABEL]".
//					rhp_trace(RHP_TRC_USER_MAIN,12,"LB","LABEL",4,&val); //'val' is u32(Len of 'val' is 4B). ==> Formatted as "%dB[LABEL]".
//					rhp_trace(RHP_TRC_USER_MAIN,12,"LB","LABEL",8,&val); //'val' is u64(Len of 'val' is 8B). ==> Formatted as "%qB[LABEL]".
//	 'a' : pointer. (Network Protocol data) For user land app.
//        (ex) rhp_trace(1,12,"a",32,RHP_TRC_FMT_A_XXX,8,12,buf);// Len of 'buf' is 32B , Len of IV is 8B and Len of ICV is 12B.
//	 'G' : IKE SPI (8bytes) For user land app.
//	 'H' : ESP SPI (4bytes) For user land app.
//	 't' : time_t (System time. e.g. by clock_gettime(CLOCK_MONOTONIC_COARSE,&time).) For user land app.
//   'T' : time_t (Since epoc-time. e.g. by clock_gettime(CLOCK_REALTIME_COARSE,&time).) For user land app.
//
//


#define RHP_TRC_USER_COMMON   			1
#define RHP_TRC_USER_SYSPXY   			2
#define RHP_TRC_USER_MAIN     			3
// #define RHP_TRC_USER_FUNCTRC			4 // Reserved. (ex) For __cyg_profile_func_enter()/exit() hooks.
// #define RHP_TRC_USER_TRACE_FILE	5 // Reserved. (ex) For libSegFault.so.
#define RHP_TRC_USER_MAIN_FREQ     	6 // For frequent trace records... (ex) timer, polling in a short time.
#define RHP_TRC_USER_SYSPXY_FREQ   	7 // For frequent trace records... (ex) timer, polling in a short time.


extern int rhp_process_my_role; //  RHP_PROCESS_ROLE_XXX

#define _rhp_trc_user_id() ({\
  int __ret2__;\
  if( rhp_process_my_role == 1 ){\
    __ret2__ = RHP_TRC_USER_MAIN;\
  }else if( rhp_process_my_role == 0 ){\
	__ret2__ = RHP_TRC_USER_SYSPXY;\
  }else{\
    __ret2__ = RHP_TRC_USER_COMMON;\
  }\
  __ret2__;\
})

#define _rhp_trc_user_freq_id() ({\
  int __ret2__;\
  if( rhp_process_my_role == 1 ){\
    __ret2__ = RHP_TRC_USER_MAIN_FREQ;\
  }else if( rhp_process_my_role == 0 ){\
	__ret2__ = RHP_TRC_USER_SYSPXY_FREQ;\
  }else{\
    __ret2__ = RHP_TRC_USER_COMMON;\
  }\
  __ret2__;\
})

#define RHP_TRC(filter_mask,record_id,...)    	_RHP_TRC(_rhp_trc_user_id(),(filter_mask),(record_id),__VA_ARGS__)
#define RHP_TRCSTR(filter_mask,...)           	_RHP_TRCSTR(_rhp_trc_user_id(),(filter_mask), __VA_ARGS__)
#define RHP_TRCF(record_id,...)               	_RHP_TRCF(_rhp_trc_user_id(),(record_id),__VA_ARGS__)
#define RHP_TRCSTRF(...)                      	_RHP_TRCSTRF(_rhp_trc_user_id(),__VA_ARGS__)

#ifdef RHP_WRITE_DEBUG_LOG
#define RHP_BUG(...)\
do{\
  	RHP_LOG_D(RHP_LOG_SRC_NONE,0,RHP_LOG_ID_BUG_TRC,"sd",__FILE__,__LINE__);\
		_RHP_BUG(_rhp_trc_user_id(),__VA_ARGS__);\
}while(0)
#else
#define RHP_BUG(...)                          	_RHP_BUG(_rhp_trc_user_id(),__VA_ARGS__)
#endif // RHP_WRITE_DEBUG_LOG

#define RHP_LINE(...)                         			_RHP_LINE(_rhp_trc_user_id(),__VA_ARGS__)
#define RHP_LINEF(...)                         			_RHP_LINEF(_rhp_trc_user_id(),__VA_ARGS__)
#define RHP_BINDUMP(filter_mask,str,len,addr) 			_RHP_TRC(_rhp_trc_user_id(),(filter_mask),4,"sp",(str),(len),(addr))
#define RHP_TRC_FREQ(filter_mask,record_id,...)  		_RHP_TRC(_rhp_trc_user_freq_id(),(filter_mask),(record_id),__VA_ARGS__)
#define RHP_BINDUMP_FREQ(filter_mask,str,len,addr) 	_RHP_TRC(_rhp_trc_user_freq_id(),(filter_mask),4,"sp",(str),(len),(addr))

#define RHP_TRC_FUNC_RECORD_ID_ENTER			1
#define RHP_TRC_FUNC_RECORD_ID_EXIT				2
#define RHP_TRC_FUNC_ENTER(func_addr,idx)	_RHP_TRC(RHP_TRC_USER_FUNCTRC,0,RHP_TRC_FUNC_RECORD_ID_ENTER,"xd",(func_addr),(idx))
#define RHP_TRC_FUNC_EXIT(func_addr,idx)	_RHP_TRC(RHP_TRC_USER_FUNCTRC,0,RHP_TRC_FUNC_RECORD_ID_EXIT,"xd",(func_addr),(idx))

#define RHP_TRC_FUNC_CUR_LINE(label,obj1,obj2,obj3)\
{\
	RHP_LINE(" >>>>> ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##  : [ %s ] : (1) 0x%x : (2) 0x%x : (3) 0x%x ",rhp_func_trc_current(),label,obj1,obj2,obj3);\
}



#ifdef RHP_DBG_FUNC_TRC

#define RHP_DBG_FUNC_TRC_CALL_STACK_MAX		2048

extern __thread void* rhp_func_trc_call_stack[RHP_DBG_FUNC_TRC_CALL_STACK_MAX];
extern __thread int rhp_func_trc_call_stack_idx;

#endif // RHP_DBG_FUNC_TRC

extern void* rhp_func_trc_current();


extern int rhp_ui_log_main_log_ctl(int flag);



/*************************

  Memory API wrappers

***************************/

extern void rhp_mem_statistics_init();
extern void rhp_mem_statistics_alloc(size_t size);
extern void rhp_mem_statistics_free(size_t size);
extern int rhp_mem_statistics_get(u_int64_t* alloc_size_r,u_int64_t* free_size_r);
extern int rhp_mem_initialized;

#ifndef RHP_MEMORY_DBG

struct _rhp_mem_ctx {
	size_t size;
	unsigned long flag;
};
typedef struct _rhp_mem_ctx rhp_mem_ctx;

static inline void* _rhp_malloc(size_t size)
{
	rhp_mem_ctx* ctx;

	if( size == 0 ){
		RHP_TRCSTRF("_rhp_malloc() size-zero error!");
		return NULL;
	}

	ctx = malloc(size + sizeof(rhp_mem_ctx));
	if( ctx ){

		ctx->size = size;

		if( rhp_mem_initialized ){
			ctx->flag = 1;
			rhp_mem_statistics_alloc(size);
		}else{
			ctx->flag = 0;
		}
	}

	return (void*)(ctx + 1);
}

static inline void _rhp_free(void *ptr)
{
  if( ptr ){

  	rhp_mem_ctx* ctx = (rhp_mem_ctx*)(((unsigned char*)ptr) - sizeof(rhp_mem_ctx));

  	if( (((unsigned char*)ptr)[0] == '#') ){ // Marker for duplicated free()... '#' ==> '%'
  		((unsigned char*)ptr)[0] = '%';
  	}

  	if( ctx->flag ){
  		rhp_mem_statistics_free(ctx->size);
  	}

  	free(ctx);

  }else{
		RHP_TRCSTRF("_rhp_free() null addr error!");
  }
}

static inline void _rhp_free_zero(void *ptr,size_t size)
{
  if( ptr ){

  	rhp_mem_ctx* ctx = (rhp_mem_ctx*)(((unsigned char*)ptr) - sizeof(rhp_mem_ctx));

  	size = ( ctx->size < size ? ctx->size : size );

  	if( size > 4 && (((unsigned char*)ptr)[0] == '#') ){
  		((unsigned char*)ptr)[0] = '%';
  		memset((((unsigned char*)ptr) + 4),0,(size - 4));
  	}else{
  		memset(ptr,0,size);
  	}

  	if( ctx->flag ){
  		rhp_mem_statistics_free(ctx->size);
  	}

  	free(ctx);

  }else{
		RHP_TRCSTRF("_rhp_free_zero() null addr error!");
  }
}

#else // RHP_MEMORY_DBG

extern void* _rhp_malloc_dbg(size_t size,const char* file,int line);
extern void _rhp_free_dbg(void *ptr,const char* file,int line);
extern void _rhp_free_zero_dbg(void *ptr,size_t size,const char* file,int line);

#define _rhp_malloc(size)						_rhp_malloc_dbg((size),__FILE__,__LINE__)
#define _rhp_free(ptr)							_rhp_free_dbg((ptr),__FILE__,__LINE__)
#define _rhp_free_zero(ptr,size)		_rhp_free_zero_dbg((ptr),(size),__FILE__,__LINE__)

extern void rhp_memory_dbg_leak_print(int start_time,int elapsing_time);


#endif //  RHP_MEMORY_DBG



#ifdef RHP_CK_OBJ_TAG
#define RHP_CK_OBJTAG(tag,obj)({\
  void* __ret3__;\
  if( obj != NULL && ( (tag)[0] != ((char*)(obj))[0] || (tag)[1] != ((char*)(obj))[1] ||\
  		(tag)[2] != ((char*)(obj))[2] || (tag)[3] != ((char*)(obj))[3] ) ){\
  	RHP_BUG("obj: 0x%lx, %c%c%c%c != %c%c%c%c",(unsigned long)(obj),(tag)[0],(tag)[1],(tag)[2],(tag)[3],((char*)(obj))[0],((char*)(obj))[1],((char*)(obj))[2],((char*)(obj))[3]);\
  	_rhp_panic();\
  }\
  __ret3__ = (obj);\
  __ret3__;\
})
#endif // RHP_CK_OBJ_TAG

#ifdef RHP_CK_OBJ_TAG_GDB
#include "signal.h"
#define RHP_CK_OBJTAG(tag,obj)({\
  void* __ret3__;\
  if( obj != NULL && ( (tag)[0] != ((char*)(obj))[0] || (tag)[1] != ((char*)(obj))[1] ||\
  		(tag)[2] != ((char*)(obj))[2] || (tag)[3] != ((char*)(obj))[3] ) ){\
  	RHP_BUG("obj: 0x%lx, %c%c%c%c != %c%c%c%c",(unsigned long)(obj),(tag)[0],(tag)[1],(tag)[2],(tag)[3],((char*)(obj))[0],((char*)(obj))[1],((char*)(obj))[2],((char*)(obj))[3]);\
		printf("RHP_CK_OBJTAG ERROR! : %c%c%c%c\n",(tag)[0],(tag)[1],(tag)[2],(tag)[3]);\
  	raise(SIGTRAP);\
	}\
  __ret3__ = (obj);\
  __ret3__;\
})
#endif // RHP_CK_OBJ_TAG

#ifndef RHP_CK_OBJTAG
#define RHP_CK_OBJTAG(tag,obj) ((obj))
#endif // RHP_CK_OBJTAG




#ifdef RHP_REFCNT_DEBUG
#ifdef RHP_REFCNT_DEBUG_X

struct _rhp_refcnt_dbg {

	unsigned char tag[4]; // '#RFD'

	struct _rhp_refcnt_dbg* next;

	void* obj;

#define RHP_REFCNT_DBG_FILE_LEN	128
	char file[RHP_REFCNT_DBG_FILE_LEN];
	int line;

	void* cur;
#define RHP_REFCNT_CALLER_NUM		8
	void* owner[RHP_REFCNT_CALLER_NUM];

	pid_t thread_id;
};
typedef struct _rhp_refcnt_dbg	rhp_refcnt_dbg;

extern rhp_refcnt_dbg* rhp_refcnt_dbg_alloc(void* obj,const char* file,int line);
extern void* rhp_refcnt_dbg_free(void* obj_or_ref);

extern void rhp_refcnt_dbg_print();
extern void* rhp_refcnt_dbg_get(void* obj_or_ref);

#define RHP_REFCNT_OBJ(obj_or_ref)		rhp_refcnt_dbg_get((obj_or_ref))

extern int rhp_refcnt_dbg_init();
extern int rhp_refcnt_dbg_cleanup();


#endif // RHP_REFCNT_DEBUG_X
#endif // RHP_REFCNT_DEBUG



// This must be less than INT_MAX and
// less than (IF_NAMESIZE(net/if.h) - strlen("rhpvif"))(Decimal).
#define RHP_VPN_REALM_ID_MAX				32767
#define RHP_VPN_REALM_ID_MAX_CHARS	5
#define RHP_VPN_REALM_ID_UNKNOWN  ((unsigned long)-1)

#endif // _RHP_MISC2_H_
