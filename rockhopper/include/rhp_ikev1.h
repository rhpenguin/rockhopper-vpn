/*

	Copyright (C) 2015-2016 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.

	You can redistribute and/or modify this software under the
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifndef _RHP_IKEV1_H_
#define _RHP_IKEV1_H_

struct _rhp_ifc_entry;
struct _rhp_packet;
struct _rhp_vpn;
struct _rhp_ikesa;
struct _rhp_ikesa_timers;
struct _rhp_ikev2_mesg;
struct _rhp_ikev2_payload;
struct _rhp_childsa;
struct _rhp_http_bus_session;
struct _rhp_vpn_realm;
struct _rhp_cfg_if;


/****************************

  IKEv1 Message handlers

*****************************/

typedef int (*RHP_IKEV1_MESG_HANDLER_TX)(struct _rhp_ikev2_mesg* tx_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,int req_initiator/*RHP_IKEV1_MESG_HANDLER_XXXX*/);

typedef int (*RHP_IKEV1_MESG_HANDLER_RX)(struct _rhp_ikev2_mesg* rx_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_ikemesg);

typedef int (*RHP_IKEV1_MESG_HANDLER_RX_NO_VPN)(struct _rhp_ikev2_mesg* rx_ikemesg,
		struct _rhp_ikev2_mesg* tx_ikemesg,struct _rhp_vpn** vpn_i_r,int* my_ikesa_side_i_r,u8* my_ikesa_spi_i_r);

struct _rhp_ikev1_message_handler {

	u8 tag[4]; // "#IMH"

	struct _rhp_ikev1_message_handler* next;

#define RHP_IKEV1_MESG_HANDLER_START							0
#define RHP_IKEV1_MESG_HANDLER_END								1
#define RHP_IKEV1_MESG_HANDLER_P1_MAIN						10
#define RHP_IKEV1_MESG_HANDLER_P1_AGGRESSIVE			20
#define RHP_IKEV1_MESG_HANDLER_XAUTH							30
#define RHP_IKEV1_MESG_HANDLER_MODE_CFG						40
#define RHP_IKEV1_MESG_HANDLER_RHP_INTERNAL_NET		50
#define RHP_IKEV1_MESG_HANDLER_P2_QUICK						60
#define RHP_IKEV1_MESG_HANDLER_NAT_T							70
#define RHP_IKEV1_MESG_HANDLER_DELETE_SA					100
#define RHP_IKEV1_MESG_HANDLER_DPD								1000
	int type;

	// 'vpn' is already locked by caller.
	RHP_IKEV1_MESG_HANDLER_TX send_mesg;

	// 'vpn' is already locked by caller.
	RHP_IKEV1_MESG_HANDLER_RX_NO_VPN recv_mesg_no_vpn;
	RHP_IKEV1_MESG_HANDLER_RX recv_mesg;
};
typedef struct _rhp_ikev1_message_handler		rhp_ikev1_message_handler;

extern int rhp_ikev1_register_message_handler(int handler_type,
		RHP_IKEV1_MESG_HANDLER_TX send_mesg,
		RHP_IKEV1_MESG_HANDLER_RX_NO_VPN recv_mesg_no_vpn,
		RHP_IKEV1_MESG_HANDLER_RX recv_mesg);

extern void rhp_ikev1_call_next_tx_mesg_handlers(struct _rhp_ikev2_mesg* tx_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,int pending_caller/*RHP_IKEV1_MESG_HANDLER_XXXX*/,
		int req_initiator/*RHP_IKEV1_MESG_HANDLER_XXXX*/);

extern void rhp_ikev1_call_next_rx_mesg_handlers(struct _rhp_ikev2_mesg* rx_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_ikemesg,
		int pending_caller_type/*RHP_IKEV1_MESG_HANDLER_XXXX*/);


extern int rhp_ikev1_send_mesg(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,
		struct _rhp_ikev2_mesg* tx_ikemesg,int req_initiator);

extern int rhp_ikev1_retransmit_mesg(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa);


extern int rhp_ikev1_recv_ipv4(struct _rhp_packet* pkt);
extern int rhp_ikev1_recv_ipv6(struct _rhp_packet* pkt);

extern int rhp_ikev1_p1_prf_alg(int hash_alg);
extern int rhp_ikev1_p1_encr_alg(int ikev1_alg);
extern int rhp_ikev1_id_type(int ikev2_id_type);
extern int rhp_ikev1_p2_encr_alg(int ikev1_trans_id);
extern int rhp_ikev1_p2_integ_alg(int ikev1_auth_alg);


extern struct _rhp_ikesa* rhp_ikev1_tx_get_established_ikesa(struct _rhp_vpn* vpn);


extern int rhp_ikev1_connect_i_try_secondary(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,
		struct _rhp_vpn_realm* rlm,rhp_ip_addr* secondary_peer_addr,struct _rhp_cfg_if* cfg_if,
		struct _rhp_ikev2_mesg** new_1st_mesg_r);

extern int rhp_ikev1_rekey_create_ikesa(struct _rhp_vpn* vpn,
		struct _rhp_vpn_realm* rlm,struct _rhp_ikesa* old_ikesa,
		struct _rhp_ikesa** new_ikesa_r,struct _rhp_ikev2_mesg** ikemesg_r);

extern int rhp_ikev1_rekey_create_childsa(struct _rhp_vpn* vpn,struct _rhp_vpn_realm* rlm,
		struct _rhp_childsa* old_childsa,struct _rhp_ikev2_mesg** ikemesg_r);


extern int rhp_ikev1_detach_old_ikesa(struct _rhp_vpn* vpn,struct _rhp_ikesa* new_ikesa);


extern u8* rhp_ikev1_mesg_gen_iv(struct _rhp_ikesa* ikesa,u32 mesg_id,int* iv_len_r);



extern int rhp_ikev1_tx_info_mesg_hash_add(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,
		struct _rhp_ikev2_mesg* tx_ikemesg,
		int (*enum_pld_cb)(struct _rhp_ikev2_mesg* ikemesg,int enum_end,
				struct _rhp_ikev2_payload* payload,void* pkt_for_hash_c)); // pkt_for_hash_c : rhp_packet

extern int rhp_ikev1_rx_info_mesg_hash_verify(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,
		struct _rhp_ikev2_mesg* rx_ikemesg,u8 pld_id);


extern int rhp_ikev1_gen_rsasig_skeyid(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,
		u8** skeyid_r,int* skeyid_len_r);

extern int rhp_ikev1_gen_psk_skeyid_material(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,
		u8** skeyid_mat_r,int* skeyid_mat_len_r);


extern int rhp_ikev1_p1_gen_hash_ir_material_part(int for_side,struct _rhp_ikesa* ikesa,
		u8** mesg_octets_r,int* mesg_octets_len_r);

extern int rhp_ikev1_p1_gen_hash_ir(
		int for_side,struct _rhp_ikesa* ikesa,
		int idix_b_bin_len,u8* idix_b_bin, // idix_b: idii_b or idir_b
		int idix_b_type,int idix_b_len,u8* idix_b, // idix_b: idii_b or idir_b
		int skeyid_len,u8* skeyid,u8** hash_octets_r,int* hash_octets_len_r);

extern int rhp_ikev1_get_my_cert_ca_dn_der(struct _rhp_vpn_realm* rlm,
		u8** my_cert_issuer_dn_der_r,int* my_cert_issuer_dn_der_len_r);


extern int rhp_ikesa_v1_top_dhgrp();


extern struct _rhp_vpn_realm* rhp_ikev1_r_get_def_realm(rhp_ip_addr* rx_addr,
		rhp_ip_addr* peer_addr);


//
// RHP_IKEV1_MESG_HANDLER_P1_MAIN
//

extern struct _rhp_ikev2_mesg* rhp_ikev1_new_pkt_main_i_1(struct _rhp_ikesa* ikesa);

extern int rhp_ikev1_rx_main_no_vpn(struct _rhp_ikev2_mesg* rx_req_ikemesg,
		struct _rhp_ikev2_mesg* tx_resp_ikemesg,struct _rhp_vpn** vpn_i,
		int* my_ikesa_side_i,u8* my_ikesa_spi_i);

extern int rhp_ikev1_rx_main(struct _rhp_ikev2_mesg* rx_resp_ikemesg,
		struct _rhp_vpn* vpn,int my_ikesa_side,u8* my_ikesa_spi,
		struct _rhp_ikev2_mesg* tx_req_ikemesg);


//
// RHP_IKEV1_MESG_HANDLER_P1_AGGRESSIVE
//

extern struct _rhp_ikev2_mesg* rhp_ikev1_new_pkt_aggressive_i_1(struct _rhp_vpn* vpn,
		struct _rhp_ikesa* ikesa,struct _rhp_vpn_realm* rlm);

extern int rhp_ikev1_rx_aggressive_no_vpn(struct _rhp_ikev2_mesg* rx_req_ikemesg,
		struct _rhp_ikev2_mesg* tx_resp_ikemesg,struct _rhp_vpn** vpn_i,
		int* my_ikesa_side_i,u8* my_ikesa_spi_i);

extern int rhp_ikev1_rx_aggressive(struct _rhp_ikev2_mesg* rx_resp_ikemesg,
		struct _rhp_vpn* vpn,int my_ikesa_side,u8* my_ikesa_spi,
		struct _rhp_ikev2_mesg* tx_req_ikemesg);


//
// RHP_IKEV1_MESG_HANDLER_XAUTH
//

extern int rhp_ikev1_rx_xauth(struct _rhp_ikev2_mesg* rx_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_ikemesg);


//
// RHP_IKEV1_MESG_HANDLER_P2_QUICK
//

extern int rhp_ikev1_rx_quick(struct _rhp_ikev2_mesg* rx_resp_ikemesg,
		struct _rhp_vpn* vpn,int my_ikesa_side,u8* my_ikesa_spi,
		struct _rhp_ikev2_mesg* tx_req_ikemesg);


//
// RHP_IKEV1_MESG_HANDLER_DELETE_SA
//

extern int rhp_ikev1_rx_delete_sa(struct _rhp_ikev2_mesg* rx_resp_ikemesg,
		struct _rhp_vpn* vpn,int my_ikesa_side,u8* my_ikesa_spi,
		struct _rhp_ikev2_mesg* tx_req_ikemesg);

extern struct _rhp_ikev2_mesg* rhp_ikev1_new_pkt_delete_ikesa(struct _rhp_vpn* vpn,
		struct _rhp_ikesa* ikesa);

extern struct _rhp_ikev2_mesg* rhp_ikev1_new_pkt_delete_ipsecsa(struct _rhp_vpn* vpn,
		struct _rhp_ikesa* ikesa,struct _rhp_childsa* childsa);



//
// RHP_IKEV1_MESG_HANDLER_NAT_T
//

extern int rhp_ikev1_rx_nat_t(struct _rhp_ikev2_mesg* rx_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_ikemesg);

extern int rhp_ikev1_tx_nat_t_req(struct _rhp_ikev2_mesg* tx_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,int req_initiator);



//
// RHP_IKEV1_MESG_HANDLER_DPD
//

extern struct _rhp_ikev2_mesg* rhp_ikev1_new_pkt_dpd_r_u_there(struct _rhp_vpn* vpn,
		struct _rhp_ikesa* ikesa,u32* dpd_seq_r);

extern int rhp_ikev1_rx_dpd(struct _rhp_ikev2_mesg* rx_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_ikemesg);

extern int rhp_ikev1_tx_dpd_req(struct _rhp_ikev2_mesg* tx_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,int req_initiator);


//
// RHP_IKEV1_MESG_HANDLER_RHP_INTERNAL_NET
//

extern int rhp_ikev1_rx_internal_net(struct _rhp_ikev2_mesg* rx_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_ikemesg);



//
// RHP_IKEV1_MESG_HANDLER_MODE_CFG
//

extern int rhp_ikev1_rx_mode_cfg(struct _rhp_ikev2_mesg* rx_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_ikemesg);




struct _rhp_ikev1_auth_srch_plds_ctx {

	u8 tag[4]; // '#ASR'

	void* vpn_ref; // rhp_vpn_ref
	struct _rhp_ikesa* ikesa;

	int dup_flag;

	struct _rhp_ikev2_payload* peer_sig_payload; // Ref to rx_ikemesg. Don't free it.
  int sign_octets_len;
  u8* sign_octets; // Ref to peer_sign_payload. Don't free it.


  int peer_cert_der_len;
  u8* peer_cert_der;

  int untrust_ca_cert_ders_num;
  int untrust_ca_cert_ders_len;
  u8* untrust_ca_cert_ders;

  struct _rhp_ikev2_payload* peer_hash_payload; // Ref to rx_ikemesg. Don't free it.
  int hash_len;
  u8* hash; // Ref to peer_hash_payload. Don't free it.

  struct _rhp_ikev2_payload* peer_id_payload; // Ref to rx_ikemesg. Don't free it.
  int peer_id_type;
  int peer_id_len;
  u8* peer_id; // Ref to peer_id_payload. Don't free it.

  int rx_initial_contact;

  struct _rhp_ikev2_mesg* rx_ikemesg;
  struct _rhp_ikev2_mesg* tx_ikemesg;

  int my_ikesa_side;
  u8 my_ikesa_spi[RHP_PROTO_IKE_SPI_SIZE];

  unsigned long peer_notified_realm_id;
  rhp_ikev2_id* peer_id_tmp;

  struct _rhp_ikev2_payload* n_error_payload;
  int n_err;
};
typedef struct _rhp_ikev1_auth_srch_plds_ctx rhp_ikev1_auth_srch_plds_ctx;

extern rhp_ikev1_auth_srch_plds_ctx* rhp_ikev1_auth_alloc_srch_ctx();
extern void rhp_ikev1_auth_free_srch_ctx(rhp_ikev1_auth_srch_plds_ctx* s_pld_ctx);



// ctx: rhp_ike_sa_init_srch_plds_ctx*
// ctx->vpn may be NULL.
extern int rhp_ikev1_srch_sa_cb(struct _rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		struct _rhp_ikev2_payload* payload,void* ctx);

// ctx: rhp_ike_sa_init_srch_plds_ctx*
// ctx->vpn may be NULL.
extern int rhp_ikev1_srch_ke_cb(struct _rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		struct _rhp_ikev2_payload* payload,void* ctx);

// ctx: rhp_ike_sa_init_srch_plds_ctx*
// ctx->vpn may be NULL.
extern int rhp_ikev1_srch_nonce_cb(struct _rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		struct _rhp_ikev2_payload* payload,void* ctx);

// ctx: rhp_ike_sa_init_srch_plds_ctx*
// ctx->vpn may be NULL.
extern int rhp_ikev1_srch_cert_req_cb(struct _rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		struct _rhp_ikev2_payload* payload,void* ctx);

extern int rhp_ikev1_srch_cert_req_cb_2(struct _rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		struct _rhp_ikev2_payload* payload,void* ctx);


// ctx: rhp_ikev1_auth_srch_plds_ctx*
// ctx->vpn may be NULL.
extern int rhp_ikev1_auth_srch_hash_cb(struct _rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		struct _rhp_ikev2_payload* payload,void* ctx);

// ctx: rhp_ikev1_auth_srch_plds_ctx*
// ctx->vpn may be NULL.
extern int rhp_ikev1_auth_srch_id_cb(struct _rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		struct _rhp_ikev2_payload* payload,void* ctx);

// ctx: rhp_ikev1_auth_srch_plds_ctx*
// ctx->vpn may be NULL.
extern int rhp_ikev1_auth_srch_sign_cb(struct _rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		struct _rhp_ikev2_payload* payload,void* ctx);

// ctx: rhp_ikev1_auth_srch_plds_ctx*
// ctx->vpn may be NULL.
extern int rhp_ikev1_auth_srch_n_realm_id_cb(struct _rhp_ikev2_mesg* rx_ikemesg,int enum_end,
			struct _rhp_ikev2_payload* payload,void* ctx);

// ctx: rhp_ikev1_auth_srch_plds_ctx*
// ctx->vpn may be NULL.
extern int rhp_ikev1_auth_srch_cert_cb(struct _rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		struct _rhp_ikev2_payload* payload,void* ctx);

// ctx: rhp_ikev1_auth_srch_plds_ctx*
// ctx->vpn may be NULL.
extern int rhp_ikev1_auth_srch_n_cb(struct _rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		struct _rhp_ikev2_payload* payload,void* ctx);

// ctx: rhp_ikev1_auth_srch_plds_ctx*
// ctx->vpn may be NULL.
extern int rhp_ikev1_auth_srch_n_error_cb(struct _rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		struct _rhp_ikev2_payload* payload,void* ctx);

extern int rhp_ikev1_new_pkt_error_notify_rep(struct _rhp_ikesa* ikesa,
		struct _rhp_ikev2_mesg* tx_ikemesg,u16 notify_mesg_type,unsigned long arg0);

#endif // _RHP_IKEV1_H_
