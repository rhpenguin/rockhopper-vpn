/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifndef _RHP_EVENT_H_
#define _RHP_EVENT_H_

#include "rhp_wthreads.h"

#ifdef RHP_EVENT_FUNCTION  

#define RHP_EVT_MAX_CONTEXTS	10

struct _rhp_event_record {

  u8 tag[4]; // '#EVT'
  
  struct _rhp_event_record* next_list;

  u32 event_type;
  u32 event_code;
  u32 event_sub_code;

  void (*complete_callback)(struct _rhp_event_record* evt_rec);
  
  int ctx_num;
  void* ctx[RHP_EVT_MAX_CONTEXTS];  
};
typedef struct _rhp_event_record rhp_event_record;

typedef void (*RHP_EVENT_CALLBACK)(rhp_event_record* evt_rec);



#define RHP_EVENT_TYPE_VPN	0
#define RHP_EVENT_TYPE_MAX 	0

extern void* RHP_EVT_CTX_END;
extern int rhp_event(u32 event_type,u32 event_code,u32 event_sub_code,int disp_priority,RHP_EVENT_CALLBACK complete_callback,.../*,RHP_EVT_CTX_END*/);

#define RHP_EVT_VPN_A(code,sub_code,.../*,RHP_EVT_CTX_END*/) (rhp_event(RHP_EVENT_TYPE_VPN,(code),(sub_code),RHP_WTS_DISP_LEVEL_ADMIN,__VA_ARGS__))
#define RHP_EVT_VPN_H(code,sub_code,.../*,RHP_EVT_CTX_END*/) (rhp_event(RHP_EVENT_TYPE_VPN,(code),(sub_code),RHP_WTS_DISP_LEVEL_HIGH,__VA_ARGS__))
#define RHP_EVT_VPN_L(code,sub_code,.../*,RHP_EVT_CTX_END*/) (rhp_event(RHP_EVENT_TYPE_VPN,(code),(sub_code),RHP_WTS_DISP_LEVEL_LOW,__VA_ARGS__))

#endif // RHP_EVENT_FUNCTION  

#endif // _RHP_EVENT_H_
