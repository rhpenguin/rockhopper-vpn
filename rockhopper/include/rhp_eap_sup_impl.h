/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/

//
// librhpeaps.so
//

#ifndef _RHP_EAP_SUP_IMPL_H_
#define _RHP_EAP_SUP_IMPL_H_

#include "rhp_eap.h"

extern int rhp_eap_sup_impl_init();
extern int rhp_eap_sup_impl_cleanup();


struct _rhp_eap_sup_info {

	int eap_method; // RHP_PROTO_EAP_TYPE_XXX

	int ask_for_user_key;

	int user_key_cache_enabled;

	int user_key_is_cached;

	unsigned long priv[4];
};
typedef struct _rhp_eap_sup_info rhp_eap_sup_info;

extern int rhp_eap_sup_impl_is_enabled(rhp_vpn_realm* rlm,rhp_eap_sup_info* info_r);

extern int rhp_eap_sup_impl_clear_user_key_cache(rhp_vpn_realm* rlm);


extern void* rhp_eap_sup_impl_vpn_init(int method,rhp_vpn* vpn,rhp_vpn_realm* rlm,rhp_ikesa* ikesa,
		u8* eap_user_id,int eap_user_id_len,u8* eap_user_key,int eap_user_key_len);

extern void rhp_eap_sup_impl_vpn_cleanup(rhp_vpn* vpn,void* impl_ctx);

extern int rhp_eap_sup_impl_recv(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_payload* rx_eap_pld,rhp_ikev2_mesg* tx_ikemesg,void* impl_ctx);

extern int rhp_eap_sup_impl_get_msk(rhp_vpn* vpn,void* impl_ctx,int* msk_len_r,u8** msk_r);

extern int rhp_eap_sup_get_my_identity(rhp_vpn* vpn,void* impl_ctx,int* ident_len_r,u8** ident_r);

extern char* rhp_eap_sup_impl_method2str(int method);
extern int rhp_eap_sup_impl_str2method(char* method_name);

#endif // _RHP_EAP_SUP_IMPL_H_
