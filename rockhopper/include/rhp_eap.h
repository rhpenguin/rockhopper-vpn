/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifndef _RHP_EAP_H_
#define _RHP_EAP_H_

#include "rhp_err.h"
#include "rhp_vpn.h"
#include "rhp_ikesa.h"
#include "rhp_ikev2_mesg.h"



#define RHP_EAP_STAT_NONE							RHP_STATUS_EAP_STAT_NONE
#define RHP_EAP_STAT_PENDING					RHP_STATUS_EAP_STAT_PENDING
#define RHP_EAP_STAT_CONTINUE					RHP_STATUS_EAP_STAT_CONTINUE
#define RHP_EAP_STAT_COMPLETED				RHP_STATUS_EAP_STAT_COMPLETED
#define RHP_EAP_STAT_NOT_SUPPORTED		RHP_STATUS_EAP_STAT_NOT_SUPPORTED
#define RHP_EAP_STAT_ERROR						RHP_STATUS_EAP_STAT_ERROR


// For IKEv2
extern void rhp_eap_recv_callback(rhp_vpn* vpn,int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* rx_ikemesg,
		rhp_ikev2_mesg* tx_ikemesg,int eap_stat/*RHP_EAP_STAT_XXX*/);



// For IKEv1
extern void rhp_xauth_recv_callback(rhp_vpn* vpn,int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* rx_ikemesg,
		rhp_ikev2_mesg* tx_ikemesg,int eap_stat/*RHP_EAP_STAT_XXX*/,int is_init_req);

extern int rhp_ikev1_xauth_r_invoke_task(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_ikemesg);



extern int rhp_eap_sup_ask_for_user_key(rhp_vpn* vpn,int my_ikesa_side,u8* my_ikesa_spi,
		int eap_method, // RHP_PROTO_EAP_TYPE_XXX
		u8* user_id,int user_id_len,
		RHP_EAP_SUP_ASK_FOR_USER_KEY_CB callback,void* ctx);


extern int rhp_eap_identity_not_protected(int eap_method);

#endif // _RHP_EAP_H_
