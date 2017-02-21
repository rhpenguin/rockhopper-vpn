/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifndef _RHP_UI_H_
#define _RHP_UI_H_

#define RHP_AUTH_REQ_MIN_ID_LEN	4
#define RHP_AUTH_REQ_MAX_ID_LEN	32

#define RHP_AUTH_REQ_MIN_PW_LEN 	0
#define RHP_AUTH_REQ_MAX_PW_LEN 	256

#define RHP_UI_TYPE_HTTP	0
#define RHP_UI_TYPE_MAX		0

struct _rhp_ui_ctx {

  int ui_type; // RHP_UI_TYPE_XXX
	
  char user_name[RHP_AUTH_REQ_MAX_ID_LEN];
  
  unsigned long vpn_realm_id;

  struct {
	  
    u64 http_bus_sess_id;
    
  } http; 
};
typedef struct _rhp_ui_ctx	rhp_ui_ctx;


extern int rhp_admin_servers_start();
extern int rhp_admin_servers_stop();
extern int rhp_admin_servers_retry_start();

#define RHP_UI_MAX_ADMIN_SERVER_ENTRY_POINTS		8
  
#endif // _RHP_UI_H_
