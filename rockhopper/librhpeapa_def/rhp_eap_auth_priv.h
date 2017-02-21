/*

	Copyright (C) 2015-2016 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.

	You can redistribute and/or modify this software under the
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/

#ifndef _RHP_EAP_AUTH_PRIV_H_
#define _RHP_EAP_AUTH_PRIV_H_


struct _rhp_eap_auth_impl_ctx_comm {
	// RHP_PROTO_EAP_TYPE_XXX
	int method; // Don't move this. (rhp_eap_auth_impl_ctx and rhp_eap_auth_impl_radius_ctx)
};
typedef struct _rhp_eap_auth_impl_ctx_comm	rhp_eap_auth_impl_ctx_comm;


struct _rhp_eap_auth_impl_ctx {

	// RHP_PROTO_EAP_TYPE_XXX
	int method; // Don't move this. (rhp_eap_auth_impl_ctx_comm)

	u8 tag[4]; // '#EAA'

	rhp_vpn_ref* vpn_ref;

	int is_completed;

	rhp_ikev2_mesg* rx_ikemesg;
	rhp_ikev2_mesg* tx_ikemesg;

	// MS-CHAPv2: MSK = server MS-MPPE-Recv-Key + MS-MPPE-Send-Key + 32 bytes zeroes (padding)
	u8 msk[64];

	int peer_identity_len;
	u8* peer_identity;
};
typedef struct _rhp_eap_auth_impl_ctx	rhp_eap_auth_impl_ctx;


struct _rhp_eap_auth_impl_radius_ctx {

	// RHP_PROTO_EAP_TYPE_XXX
	int method; // Don't move this. (rhp_eap_auth_impl_ctx_comm)

	u8 tag[4]; // '#ERA'

	int eap_method;

	rhp_vpn_ref* vpn_ref;

	int is_completed;

	rhp_ikev2_mesg* rx_ikemesg;
	rhp_ikev2_payload* rx_eap_pld; // Just referecne. Don't free it.

	rhp_ikev2_mesg* tx_ikemesg;

	int msk_len;
	u8* msk;

	int peer_identity_len;
	u8* peer_identity;

	rhp_radius_session* radius_sess;

	int my_ikesa_side;
	u8 my_ikesa_spi[RHP_PROTO_IKE_SPI_SIZE];

	int secondary_server_configured;
	int tx_secondary_server;

	int rx_mesg_num;
};
typedef struct _rhp_eap_auth_impl_radius_ctx	rhp_eap_auth_impl_radius_ctx;


extern void* rhp_eap_auth_impl_vpn_init_for_radius(rhp_vpn* vpn,rhp_vpn_realm* rlm,rhp_ikesa* ikesa);
extern void rhp_eap_auth_impl_vpn_cleanup_for_radius(rhp_vpn* vpn,void* impl_ctx);

extern int rhp_eap_auth_impl_init_req_for_radius(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg,void* impl_ctx);

extern int rhp_eap_auth_impl_recv_for_radius(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_payload* rx_eap_pld,rhp_ikev2_mesg* tx_ikemesg,void* impl_ctx);

extern int rhp_eap_auth_get_msk_for_radius(rhp_vpn* vpn,void* impl_ctx,int* msk_len_r,u8** msk_r);
extern int rhp_eap_auth_get_peer_identity_for_radius(rhp_vpn* vpn,void* impl_ctx,int* ident_len_r,u8** ident_r);



struct _rhp_eap_auth_sess {

	u8 tag[4]; // '#EES'

	struct _rhp_eap_auth_sess* next;

	int method_type;

	// For WPA supplicant (EAP)
	const struct eap_method* method;
	void* method_ctx;

  unsigned long vpn_realm_id;

  u8 unique_id[RHP_VPN_UNIQUE_ID_SIZE]; // RHP_VPN_UNIQUE_ID_SIZE: 16bytes
  unsigned int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 spi[RHP_PROTO_IKE_SPI_SIZE];

  u8 eap_req_id;

  int key_id_len;
  char* key_id; // '\0' terminated.

  time_t created;

  unsigned long rebound_rlm_id;


#define RHP_XAUTH_AUTH_STAT_DEFAULT					0
#define RHP_XAUTH_AUTH_STAT_DONE						1

#define RHP_XAUTH_AUTH_STAT_PAP_WAIT_REPLY			10
#define RHP_XAUTH_AUTH_STAT_PAP_WAIT_ACK				11 // SUCCESS
#define RHP_XAUTH_AUTH_STAT_PAP_WAIT_ACK_FAIL		12 // FAILURE
  int xauth_state;

  int xauth_status; // 0: OK, 1 or error: FAILURE

  int xauth_peer_identity_len;
  u8* xauth_peer_identity;
};
typedef struct _rhp_eap_auth_sess rhp_eap_auth_sess;


extern rhp_eap_auth_sess* rhp_eap_auth_alloc(int eap_vendor,int eap_type,unsigned long rlm_id,
		u8* unique_id,int side,u8* spi);

extern int rhp_eap_auth_delete(rhp_eap_auth_sess* a_sess_d);

extern rhp_eap_auth_sess* rhp_eap_auth_get(u8* unique_id);

extern void rhp_eap_auth_put(rhp_eap_auth_sess* a_sess);





#endif // _RHP_EAP_AUTH_PRIV_H_
