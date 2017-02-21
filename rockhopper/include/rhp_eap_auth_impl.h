/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/

//
// librhpeapa.so
//

#ifndef _RHP_EAP_AUTH_IMPL_H_
#define _RHP_EAP_AUTH_IMPL_H_

#include "rhp_eap.h"

extern int rhp_eap_auth_impl_init();
extern int rhp_eap_auth_impl_cleanup();

// method: RHP_EAP_METHOD_XXX
extern void* rhp_eap_auth_impl_vpn_init(int method,rhp_vpn* vpn,rhp_vpn_realm* rlm,rhp_ikesa* ikesa);

extern void rhp_eap_auth_impl_vpn_cleanup(rhp_vpn* vpn,void* impl_ctx);

extern int rhp_eap_auth_impl_init_req(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg,void* impl_ctx);

extern int rhp_eap_auth_impl_recv(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_payload* rx_eap_pld,rhp_ikev2_mesg* tx_ikemesg,void* impl_ctx);

extern int rhp_eap_auth_get_msk(rhp_vpn* vpn,void* impl_ctx,int* msk_len_r,u8** msk_r);

extern int rhp_eap_auth_get_peer_identity(rhp_vpn* vpn,void* impl_ctx,int* ident_len_r,u8** ident_r);

extern char* rhp_eap_auth_impl_method2str(int method);
extern int rhp_eap_auth_impl_str2method(char* method_name);

extern int rhp_eap_auth_impl_method_is_supported(int method);

extern int rhp_eap_auth_impl_radius_set_secret(int index,u8* secret,int secret_len);

#endif // _RHP_EAP_AUTH_IMPL_H_
