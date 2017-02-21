/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifdef RHP_EVENT_FUNCTION  

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


static unsigned long _rhp_event_ctx_terminator_impl = 0xF1F2F3F4;
void* RHP_EVT_CTX_END = &_rhp_event_ctx_terminator_impl;

static rhp_event_record* _rhp_event_record_pool = NULL;
static long _rhp_event_record_pool_num = 0;


static void _rhp_event_vpn(rhp_event_record* evt_rec);

static RHP_EVENT_CALLBACK _rhp_event_callback[RHP_EVENT_TYPE_MAX+1] = {
  _rhp_event_vpn,		
};

static rhp_event_record* _rhp_event_alloc_raw()
{
  rhp_event_record* evt_rec;

  evt_rec = (rhp_event_record*)_rhp_malloc(sizeof(rhp_event_record));
  if( evt_rec == NULL ){
    RHP_BUG("");
    return NULL;
  }
  
  memset(evt_rec,0,sizeof(rhp_event_record));

  evt_rec->tag[0] = '#';
  evt_rec->tag[1] = 'E';
  evt_rec->tag[2] = 'V';
  evt_rec->tag[3] = 'T';
  
  return evt_rec;
}

static rhp_event_record* _rhp_event_alloc()
{
  rhp_event_record *evt_rec,*evt_rec2;
  int i;

  evt_rec = _rhp_event_alloc_raw();
  
  if( evt_rec == NULL && (_rhp_event_record_pool != NULL) ){

    evt_rec = _rhp_event_record_pool;
    _rhp_event_record_pool = evt_rec->next_list;
	  
    _rhp_event_record_pool_num--;	  
    evt_rec->next_list = NULL;
  }
  
  if( _rhp_event_record_pool_num <= rhp_gcfg_event_max_record_pool_num/10*7 ){

    for( i = _rhp_event_record_pool_num; i < rhp_gcfg_event_max_record_pool_num;i++){
		  
      evt_rec2 = _rhp_event_alloc_raw();
      if( evt_rec2 == NULL ){
	    break;    	
	   }
      
      if( evt_rec == NULL ){
    	  
        evt_rec = evt_rec2;
    	  
      }else{
      
        evt_rec2->next_list = _rhp_event_record_pool;
        _rhp_event_record_pool = evt_rec2;    	
		 
        _rhp_event_record_pool_num++;
      }
    }
  }
  
  return evt_rec;
}

static void _rhp_event_task(void *ctx)
{
  rhp_event_record* evt_rec = (rhp_event_record*)ctx;
  RHP_EVENT_CALLBACK req_callback = NULL;
 
  if( evt_rec->event_type > RHP_EVENT_TYPE_MAX ){
    RHP_BUG("%d",evt_rec->event_type);
    return;
  }
  
  req_callback = _rhp_event_callback[evt_rec->event_type];
  if( req_callback == NULL ){
    RHP_BUG("%d",evt_rec->event_type);
  }else{
    req_callback(evt_rec);
  }
  
  if( evt_rec->complete_callback ){
    evt_rec->complete_callback(evt_rec);	  
  }

  _rhp_free_zero(evt_rec,sizeof(rhp_event_record));
  
  return;
}

int rhp_event(u32 event_type,u32 event_code,u32 event_sub_code,int disp_priority,
		RHP_EVENT_CALLBACK complete_callback,.../*,RHP_EVT_CTX_END*/)
{
  int err;	
  va_list args;
  rhp_event_record* evt_rec;
  int i;

  if( !rhp_wts_dispach_ok(disp_priority,0) ){
    return -EBUSY;	  
  }
  
  evt_rec = _rhp_event_alloc();
  if( evt_rec ){
    RHP_BUG("");
    return -ENOMEM;
  }

  evt_rec->event_type = event_type;
  evt_rec->event_code = event_code;
  evt_rec->event_sub_code = event_sub_code;

  evt_rec->ctx_num = 0;
  evt_rec->complete_callback = complete_callback;
  
  va_start(args,complete_callback);
    
  for( i = 0; i <= RHP_EVT_MAX_CONTEXTS;i++ ){
	  
  	void* ctx = va_arg(args,void*);
	
  	if( ctx == RHP_EVT_CTX_END ){
      break;		
  	}

  	if( i >= RHP_EVT_MAX_CONTEXTS && ctx != RHP_EVT_CTX_END ){
      va_end(args);
      RHP_BUG("");
      _rhp_free(evt_rec);	  
      return -EINVAL;
  	}
	  
    evt_rec->ctx[i] = ctx;
    evt_rec->ctx_num++;
  }
    
  va_end(args);
  
  err = rhp_wts_add_task(RHP_WTS_DISP_RULE_EVENT,disp_priority,NULL,_rhp_event_task,evt_rec);
  if( err ){
     _rhp_free(evt_rec);	  
    return err;	  
  }
  
  return 0;
}

static void _rhp_event_vpn(rhp_event_record* evt_rec)
{
  // TODO : NOT IMPLEMENTED YET.	
	
  //
  // TODO : Check realm_vpn_id for the operation!	
  //
	
  //
  // TODO : Send event to admin without realm_vpn_id(super user) too , if needed.
  //
}

int rhp_event_init()
{
  int err = -EINVAL;
  int i;
  rhp_event_record* evt_rec;

  for( i = 0; i < rhp_gcfg_event_max_record_pool_num;i++){
	  
    evt_rec = _rhp_event_alloc_raw();
    if( evt_rec == NULL ){
      break;    	
    }
    
    evt_rec->next_list = _rhp_event_record_pool;
	 _rhp_event_record_pool = evt_rec;    	
	 
	 _rhp_event_record_pool_num++;
  }
  
  return 0;
}

#endif // RHP_EVENT_FUNCTION  
