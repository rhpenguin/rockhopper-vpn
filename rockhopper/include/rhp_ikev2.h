/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifndef _RHP_IKEV2_H_
#define _RHP_IKEV2_H_

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
struct _rhp_ikev2_sess_resume_tkt;
struct _rhp_ikev2_sess_resume_tkt_e;
struct _rhp_ikev2_tx_new_req;
struct _rhp_ikev2_n_auth_tkt_payload;

#include "rhp_ikev1.h"

#define RHP_IKEV2_SEND_REQ_FLAG_RESEVED					1
#define RHP_IKEV2_SEND_REQ_FLAG_BUSY_SKIP				2
#define RHP_IKEV2_SEND_REQ_FLAG_URGENT					4
#define RHP_IKEV2_SEND_REQ_FLAG_V1_COMMIT_BIT		8
extern void rhp_ikev2_send_request(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,
		struct _rhp_ikev2_mesg* ikemesg,int req_initiator/*RHP_IKEV2_MESG_HANDLER_XXXX*/);

extern int rhp_ikev2_retransmit_req(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa);

extern void rhp_ikesa_set_retrans_reply(struct _rhp_ikesa* ikesa,rhp_packet* pkt);
extern void rhp_ikesa_set_retrans_request(struct _rhp_ikesa* ikesa,rhp_packet* pkt);


extern int rhp_ikev2_recv_ipv4(rhp_packet* pkt);
extern int rhp_ikev2_recv_ipv6(rhp_packet* pkt);

extern int rhp_ikev2_create_child_sa_dyn_create(struct _rhp_vpn* vpn);

extern int rhp_ikev2_new_pkt_ike_auth_error_notify(struct _rhp_ikesa* ikesa,
		struct _rhp_ikev2_mesg* tx_ikemesg,u8 exchaneg_type,u32 message_id,
		u16 notify_mesg_type,unsigned long arg0);

extern int rhp_ikev2_tx_plain_error_rep_v4(
		rhp_proto_ip_v4* rx_req_iph,rhp_proto_udp* rx_req_udph,rhp_proto_ike* rx_req_ikeh,
		struct _rhp_ifc_entry *rx_req_ifc,
		int (*add_payloads_callback)(struct _rhp_ikev2_mesg* tx_ikemesg,void* ctx),void* ctx);

extern int rhp_ikev2_tx_plain_error_rep_v6(
		rhp_proto_ip_v6* rx_req_ip6h,rhp_proto_udp* rx_req_udph,rhp_proto_ike* rx_req_ikeh,
		struct _rhp_ifc_entry *rx_req_ifc,
		int (*add_payloads_callback)(struct _rhp_ikev2_mesg* tx_ikemesg,void* ctx),void* ctx);

extern int rhp_ikev2_dbg_tx_integ_err_notify(struct _rhp_packet* rx_pkt,u16 notify_mesg_type);
extern int rhp_ikev2_dbg_rx_integ_err_notify(struct _rhp_packet* rx_pkt);


extern int rhp_ikev2_pkt_rebuild_header(struct _rhp_packet* pkt,
		int addr_family,u8* src_addr,u8* dst_addr,u16 src_port,u16 dst_port);


extern int rhp_ikev2_check_tx_addr(struct _rhp_vpn* vpn,
		struct _rhp_ikesa* tx_ikesa,struct _rhp_ifc_entry* tx_ifc);


/****************************

  IKEv2 Message handlers

*****************************/

typedef int (*RHP_IKEV2_MESG_HANDLER_TX_REQ)(struct _rhp_ikev2_mesg* tx_req_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,int req_initiator/*RHP_IKEV2_MESG_HANDLER_XXXX*/);

typedef int (*RHP_IKEV2_MESG_HANDLER_RX_REQ)(struct _rhp_ikev2_mesg* rx_req_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_ikemesg);

typedef int (*RHP_IKEV2_MESG_HANDLER_RX_REQ_NO_VPN)(struct _rhp_ikev2_mesg* rx_req_ikemesg,
		struct _rhp_ikev2_mesg* tx_ikemesg,struct _rhp_vpn** vpn_i_r,int* my_ikesa_side_i_r,u8* my_ikesa_spi_i_r);

typedef int (*RHP_IKEV2_MESG_HANDLER_RX_RESP)(struct _rhp_ikev2_mesg* rx_resp_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_ikemesg);

struct _rhp_ikev2_message_handler {

	u8 tag[4]; // "#IMH"

	struct _rhp_ikev2_message_handler* next;

#define RHP_IKEV2_MESG_HANDLER_START								0
#define RHP_IKEV2_MESG_HANDLER_END									1
#define RHP_IKEV2_MESG_HANDLER_IKESA_INIT						10
#define RHP_IKEV2_MESG_HANDLER_SESS_RESUME					11 // IKE_SESSION_RESUME exchange
#define RHP_IKEV2_MESG_HANDLER_NAT_T								20
#define RHP_IKEV2_MESG_HANDLER_IKESA_AUTH						30
//
// EAP suspends other message handlings during IKE_AUTH Exchanges
// by returning RHP_STATUS_IKEV2_MESG_HANDLER_END.
#define RHP_IKEV2_MESG_HANDLER_EAP									40
#define RHP_IKEV2_MESG_HANDLER_CONFIG								50
#define RHP_IKEV2_MESG_HANDLER_RHP_INTERNAL_NET			60
#define RHP_IKEV2_MESG_HANDLER_CREATE_CHILDSA				70
#define RHP_IKEV2_MESG_HANDLER_KEEP_ALIVE						80
//
// [CAUTION]
//  An old IKE SA is scheduled to be deleted by this Rekey handler.
//  Handlers called after this handler get the ikesa in DELETED
//  state or can't get the ikesa (it might be already freed or it might expire).
//  A new rekeyed ikesa is available by using ikemesg->rekeyed_ikesa_my_side
//  and ikemesg->rekeyed_ikesa_my_spi.
#define RHP_IKEV2_MESG_HANDLER_REKEY								90
#define RHP_IKEV2_MESG_HANDLER_MOBIKE								100
#define RHP_IKEV2_MESG_HANDLER_SESS_RESUME_TKT			110 // IKE_SESSION_RESUME's ticket exchange
#define RHP_IKEV2_MESG_HANDLER_AUTH_TKT_HUB2SPOKE		120	// Auth Ticket: For Hub-to-Spoke connection.
#define RHP_IKEV2_MESG_HANDLER_QCD									200
#define RHP_IKEV2_MESG_HANDLER_INFORMATIONAL				1000
#define RHP_IKEV2_MESG_HANDLER_DELETE_SA						1001
#define RHP_IKEV2_MESG_HANDLER_TX_NEW_REQ						15000 // This must be the last entry.
	int type;

	// 'vpn' is already locked by caller.
	RHP_IKEV2_MESG_HANDLER_TX_REQ send_request_mesg;

	// 'vpn' is already locked by caller.
	RHP_IKEV2_MESG_HANDLER_RX_REQ_NO_VPN recv_request_mesg_no_vpn;
	RHP_IKEV2_MESG_HANDLER_RX_REQ recv_request_mesg;
	RHP_IKEV2_MESG_HANDLER_RX_RESP recv_response_mesg;
};
typedef struct _rhp_ikev2_message_handler		rhp_ikev2_message_handler;

extern int rhp_ikev2_register_message_handler(int handler_type,
		RHP_IKEV2_MESG_HANDLER_TX_REQ send_request_mesg,
		RHP_IKEV2_MESG_HANDLER_RX_REQ_NO_VPN recv_request_mesg_no_vpn,
		RHP_IKEV2_MESG_HANDLER_RX_REQ recv_request_mesg,
		RHP_IKEV2_MESG_HANDLER_RX_RESP recv_response_mesg);

extern void rhp_ikev2_call_next_tx_request_mesg_handlers(struct _rhp_ikev2_mesg* tx_req_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,int pending_caller/*RHP_IKEV2_MESG_HANDLER_XXXX*/,
		int req_initiator/*RHP_IKEV2_MESG_HANDLER_XXXX*/);

extern void rhp_ikev2_call_next_rx_request_mesg_handlers(struct _rhp_ikev2_mesg* rx_req_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_resp_ikemesg,
		int pending_caller_type/*RHP_IKEV2_MESG_HANDLER_XXXX*/);

extern void rhp_ikev2_call_next_rx_response_mesg_handlers(struct _rhp_ikev2_mesg* rx_resp_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_next_req_ikemesg,
		int pending_caller/*RHP_IKEV2_MESG_HANDLER_XXXX*/);


//
// RHP_IKEV2_MESG_HANDLER_IKESA_INIT
//

extern struct _rhp_ikev2_mesg* rhp_ikev2_new_pkt_ike_sa_init_req(struct _rhp_ikesa* ikesa,
		u16 dhgrp_id,int cookie_len,u8* cookie);

int rhp_ikev2_rx_ike_sa_init_req_no_vpn(struct _rhp_ikev2_mesg* rx_req_ikemesg,
		struct _rhp_ikev2_mesg* tx_resp_ikemesg,struct _rhp_vpn** vpn_i,int* my_ikesa_side_i,u8* my_ikesa_spi_i);

int rhp_ikev2_rx_ike_sa_init_rep(struct _rhp_ikev2_mesg* rx_resp_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_req_ikemesg);

extern int rhp_ikev2_ike_sa_init_i_try_secondary(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,
		rhp_ip_addr* secondary_peer_addr,struct _rhp_cfg_if* cfg_if,struct _rhp_ikev2_mesg** new_1st_mesg_r);

extern int rhp_ikev2_ike_sa_init_disp_cookie_handler(struct _rhp_packet* pkt_i);

extern int rhp_ikev2_ike_sa_init_tx_error_rep(struct _rhp_ikev2_mesg* rx_ikemesg,u16 notify_mesg_type,unsigned long arg0);


struct _rhp_ike_sa_init_srch_plds_ctx {

	struct _rhp_vpn* vpn;
	struct _rhp_ikesa* ikesa;

	int dup_flag;

  struct _rhp_ikev2_payload* n_error_payload;
  int n_err;
  struct _rhp_ikev2_payload* n_cookie_payload;
  struct _rhp_ikev2_payload* n_invalid_ke_payload;

  struct _rhp_ikev2_payload* sa_payload;
  struct _rhp_ikev2_payload* nir_payload;
  struct _rhp_ikev2_payload* ke_payload;
  struct _rhp_ikev2_payload* my_v_payload;

  struct _rhp_ikev2_payload* v1_hash_payload;
  struct _rhp_ikev2_payload* v1_id_payload;

  union {
  	rhp_res_sa_proposal v2;
  	rhp_res_ikev1_sa_proposal v1;
  } resolved_prop;

  int nonce_len;
  u8* nonce;

	u16 dhgrp;
  int peer_dh_pub_key_len;
  u8* peer_dh_pub_key;

  int prf_key_len;

  struct _rhp_ikev2_payload* certreq_payload_head;
  int certreq_payload_num;

  int http_cert_lookup_supported;

  int frag_supported;

  int peer_is_rockhopper;
  u8 peer_rockhopper_ver;

  u16 notify_error;
  unsigned long notify_error_arg;
};
typedef struct _rhp_ike_sa_init_srch_plds_ctx		rhp_ike_sa_init_srch_plds_ctx;

extern int rhp_ikev2_ike_sa_init_srch_nir_cb(struct _rhp_ikev2_mesg* rx_ikemesg,
		int enum_end,struct _rhp_ikev2_payload* payload,void* ctx);

extern int rhp_ikev2_ike_sa_init_srch_my_vid_cb(struct _rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		struct _rhp_ikev2_payload* payload,void* ctx);

extern int rhp_ikev2_ike_sa_init_srch_n_frag_supported_cb(struct _rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		struct _rhp_ikev2_payload* payload,void* ctx);

extern int rhp_ikev2_ike_sa_init_srch_n_cookie_cb(struct _rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		struct _rhp_ikev2_payload* payload,void* ctx);

extern int rhp_ikev2_ike_sa_init_srch_n_http_cert_lookup_supported_cb(struct _rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		struct _rhp_ikev2_payload* payload,void* ctx);


#define RHP_IKEV2_COOKIE_LEN					24 // SHA-1(20bytes) + ver(4bytes)



//
// RHP_IKEV2_MESG_HANDLER_SESS_RESUME
//
struct _rhp_vpn_sess_resume_material;

extern struct _rhp_ikev2_mesg* rhp_ikev2_new_pkt_sess_resume_req(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,
		struct _rhp_vpn_sess_resume_material* sess_resume_material_i,int cookie_len,u8* cookie);

extern int rhp_ikev2_sess_resume_dec_tkt_vals(struct _rhp_ikev2_sess_resume_tkt* sess_res_tkt,
		struct _rhp_ikev2_sess_resume_tkt_e** sess_res_tkt_e_r,u8** sk_d_r,u8** id_i_r,u8** alt_id_i_r,u8** id_r_r,
		u8** alt_id_r_r,u8** eap_id_i_r,u8** sess_res_radius_tkt_r);  // Just refereces. Don't free.

extern int rhp_ikev2_rx_sess_resume_req_no_vpn(struct _rhp_ikev2_mesg* rx_req_ikemesg,
		struct _rhp_ikev2_mesg* tx_resp_ikemesg,struct _rhp_vpn** vpn_i,int* my_ikesa_side_i,u8* my_ikesa_spi_i);

extern int rhp_ikev2_rx_sess_resume_rep(struct _rhp_ikev2_mesg* rx_resp_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_req_ikemesg);



//
// RHP_IKEV2_MESG_HANDLER_SESS_RESUME_TKT
//

extern int rhp_ikev2_rx_sess_resume_tkt_req(struct _rhp_ikev2_mesg* rx_req_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_resp_ikemesg);

extern int rhp_ikev2_rx_sess_resume_tkt_rep(struct _rhp_ikev2_mesg* rx_resp_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_req_ikemesg);


//
// RHP_IKEV2_MESG_HANDLER_IKESA_AUTH
//

extern int rhp_ikev2_rx_ike_auth_req(struct _rhp_ikev2_mesg* rx_req_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_resp_ikemesg);

extern int rhp_ikev2_rx_ike_auth_rep(struct _rhp_ikev2_mesg* rx_resp_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_req_ikemesg);


extern int rhp_ikev2_ike_auth_mesg_octets(
		int side,struct _rhp_ikesa* ikesa,int id_type,u8* id,int id_len,
    int* mesg_octets_len_r,u8** mesg_octets_r);

extern int rhp_ikev2_ike_auth_ipc_sign_req(struct _rhp_ikev2_mesg* ikemesg,
		unsigned long rlm_id,struct _rhp_ikesa* ikesa,
		int mesg_octets_len,u8* mesg_octets,int sk_p_len,u8* sk_p,int auth_tkt_session_key_len,u8* auth_tkt_session_key,
		struct _rhp_ipcmsg** ipcmsg_r,int txn_id_flag);

extern int rhp_ikev2_rx_ike_auth_req_impl(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,struct _rhp_ikev2_mesg* rx_req_ikemesg,
		struct _rhp_ikev2_mesg* tx_resp_ikemesg,struct _rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload);


//
// RHP_IKEV2_MESG_HANDLER_EAP
//

extern int rhp_ikev2_rx_ike_eap_req(struct _rhp_ikev2_mesg* rx_req_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_resp_ikemesg);

extern int rhp_ikev2_rx_ike_eap_rep(struct _rhp_ikev2_mesg* rx_resp_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_req_ikemesg);


//
// RHP_IKEV2_MESG_HANDLER_CREATE_CHILDSA
//

extern int rhp_ikev2_rx_create_child_sa_req(struct _rhp_ikev2_mesg* rx_req_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_resp_ikemesg);

extern int rhp_ikev2_rx_create_child_sa_rep(struct _rhp_ikev2_mesg* rx_resp_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_req_ikemesg);


//
// RHP_IKEV2_MESG_HANDLER_REKEY
//

extern int rhp_ikev2_rekey_create_childsa(struct _rhp_vpn* vpn,struct _rhp_vpn_realm* rlm,
		struct _rhp_childsa* old_childsa,int by_ipv6_autoconf,struct _rhp_ikev2_mesg** ikemesg_r);

extern int rhp_ikev2_rekey_create_ikesa(struct _rhp_vpn* vpn,struct _rhp_vpn_realm* rlm,
		struct _rhp_ikesa* old_ikesa,struct _rhp_ikev2_mesg** ikemesg_r);

extern int rhp_ikev2_rx_rekey_req(struct _rhp_ikev2_mesg* rx_req_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_resp_ikemesg);

extern int rhp_ikev2_rx_rekey_rep(struct _rhp_ikev2_mesg* rx_resp_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_req_ikemesg);


//
// RHP_IKEV2_MESG_HANDLER_NAT_T
//

extern int rhp_ikev2_tx_nat_t_req(struct _rhp_ikev2_mesg* tx_req_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,int req_initiator);

extern int rhp_ikev2_rx_nat_t_req(struct _rhp_ikev2_mesg* rx_req_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_resp_ikemesg);

extern int rhp_ikev2_rx_nat_t_rep(struct _rhp_ikev2_mesg* rx_resp_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_req_ikemesg);

extern int rhp_ikev2_nat_t_rx_from_unknown_peer(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,struct _rhp_packet* rx_pkt,rhp_proto_ike* ikeh);

extern int rhp_ikev2_nat_t_change_peer_addr_port(struct _rhp_vpn* vpn,
		int addr_family,u8* new_ip_addr,u16 new_port,u16 peer_tx_dest_port,int checked);

extern int rhp_ikev2_nat_t_send_keep_alive(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa);

// Don't use this API for IKE_SA_INIT exchg.
extern int rhp_ikev2_nat_t_new_pkt_req(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,
		struct _rhp_ikev2_mesg* rx_req_ikemesg,struct _rhp_ikev2_mesg* tx_ikemesg);

extern int rhp_ikev2_nat_t_peer_dst_hash(struct _rhp_ikesa* ikesa,struct _rhp_ikev2_payload* n_dst_payload,
		int dst_addr_len,u8* dst_addr,u8** hash_r,int* hash_len_r);

extern int rhp_ikev2_nat_t_dst_check(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,
		struct _rhp_ikev2_payload* n_dst_payload,int dst_addr_len,u8* dst_addr);


//
// RHP_IKEV2_MESG_HANDLER_RHP_INTERNAL_NET
//

extern int rhp_ikev2_rx_internal_net_req(struct _rhp_ikev2_mesg* rx_req_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_resp_ikemesg);

extern int rhp_ikev2_rx_internal_net_rep(struct _rhp_ikev2_mesg* rx_resp_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_req_ikemesg);


//
// RHP_IKEV2_MESG_HANDLER_INFORMATIONAL
//

extern int rhp_ikev2_rx_info_req(struct _rhp_ikev2_mesg* rx_req_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_resp_ikemesg);

extern int rhp_ikev2_rx_info_rep(struct _rhp_ikev2_mesg* rx_resp_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_req_ikemesg);


//
// RHP_IKEV2_MESG_HANDLER_DELETE_SA
//

extern int rhp_ikev2_rx_delete_sa_req(struct _rhp_ikev2_mesg* rx_req_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_resp_ikemesg);

extern int rhp_ikev2_rx_delete_sa_rep(struct _rhp_ikev2_mesg* rx_resp_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_req_ikemesg);


//
// RHP_IKEV2_MESG_HANDLER_CONFIG
//

extern int rhp_ikev2_tx_cfg_req(struct _rhp_ikev2_mesg* tx_req_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,int req_initiator);

extern int rhp_ikev2_rx_cfg_req(struct _rhp_ikev2_mesg* rx_req_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_resp_ikemesg);

extern int rhp_ikev2_rx_cfg_rep(struct _rhp_ikev2_mesg* rx_resp_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_req_ikemesg);


//
// RHP_IKEV2_MESG_HANDLER_QCD (Quick Crash Detection)
//

extern int rhp_ikev2_rx_qcd_req(struct _rhp_ikev2_mesg* rx_req_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_resp_ikemesg);

extern int rhp_ikev2_rx_qcd_rep(struct _rhp_ikev2_mesg* rx_resp_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_req_ikemesg);

extern int rhp_ikev2_qcd_rx_invalid_ikesa_spi_req(struct _rhp_packet* rx_pkt);
extern int rhp_ikev2_qcd_rx_invalid_ikesa_spi_resp(struct _rhp_packet* rx_pkt,struct _rhp_vpn* vpn);

extern int rhp_ikev2_qcd_get_my_token(int my_side,u8* my_ikesa_spi,u8* peer_ikesa_spi,u8* token_r);

extern long rhp_ikev2_qcd_pend_req_num();


//
// RHP_IKEV2_MESG_HANDLER_MOBIKE
//

extern int rhp_ikev2_rx_mobike_req(struct _rhp_ikev2_mesg* rx_req_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_resp_ikemesg);

extern int rhp_ikev2_rx_mobike_rep(struct _rhp_ikev2_mesg* rx_resp_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_req_ikemesg);

extern int rhp_ikev2_mobike_pending(struct _rhp_vpn* vpn);
extern int rhp_ikev2_mobike_ka_pending(struct _rhp_vpn* vpn);

extern int rhp_ikev2_mobike_i_rx_probe_pkt(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,struct _rhp_packet* pkt);
extern int rhp_ikev2_mobike_i_start_routability_check(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,int wait_conv_interval);
extern int rhp_ikev2_mobike_i_rt_invoke_waiting_timer(struct _rhp_vpn* vpn);

extern int rhp_ikev2_mobike_rx_resp_rt_ck_addrs(struct _rhp_packet* rx_pkt,struct _rhp_vpn* vpn);


//
// RHP_IKEV2_MESG_HANDLER_TX_NEW_REQ
//

extern int rhp_ikev2_rx_tx_new_req_req(struct _rhp_ikev2_mesg* rx_req_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_resp_ikemesg);

extern int rhp_ikev2_rx_tx_new_req_rep(struct _rhp_ikev2_mesg* rx_resp_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_req_ikemesg);


extern struct _rhp_ikev2_mesg* rhp_ikev2_tx_new_req_get(struct _rhp_vpn* vpn,int my_side,u8* my_spi);

extern void rhp_ikev2_tx_new_req_free_ctx(struct _rhp_ikev2_tx_new_req* tx_new_req);
extern void rhp_ikev2_tx_new_req_free_ctx_vpn(struct _rhp_vpn* vpn,struct _rhp_ikev2_tx_new_req* tx_new_req);



//
// RHP_IKEV2_MESG_HANDLER_AUTH_TKT_HUB2SPOKE
//

extern int rhp_ikev2_rx_auth_tkt_hb2spk_req(struct _rhp_ikev2_mesg* rx_req_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_resp_ikemesg);

extern int rhp_ikev2_rx_auth_tkt_hb2spk_rep(struct _rhp_ikev2_mesg* rx_resp_ikemesg,struct _rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,struct _rhp_ikev2_mesg* tx_req_ikemesg);


extern int rhp_ikev2_auth_tkt_hb2spk_tx_tkt_req(struct _rhp_vpn_realm* tx_rlm,
		rhp_ip_addr* shortcut_resp_pub_addr,rhp_ip_addr* shortcut_resp_itnl_addr,
		rhp_ikev2_id* shortcut_resp_id,
		void (*rx_resp_cb)(struct _rhp_vpn* rx_hb2spk_vpn,int my_ikesa_side,u8* my_ikesa_spi,
				int cb_err,struct _rhp_ikev2_mesg* rx_resp_ikemesg,struct _rhp_vpn* spk2spk_vpn),
				struct _rhp_vpn* spk2spk_vpn);


//
// A VPN Realm for vpn is not resolved yet.
//
extern int rhp_ikev2_auth_tkt_spk2spk_invoke_dec_tkt_task(
		struct _rhp_vpn* spk2spk_vpn,struct _rhp_ikesa* ikesa,struct _rhp_ikev2_mesg* rx_req_ikemesg,
		struct _rhp_ikev2_mesg* tx_resp_ikemesg,u16* notify_error_r,unsigned long* notify_error_arg_r);

extern int rhp_ikev2_auth_tkt_spk2spk_invoke_get_tkt_task(
		struct _rhp_vpn* spk2spk_vpn,struct _rhp_ikesa* ikesa,
		struct _rhp_ikev2_mesg* rx_resp_ikemesg,struct _rhp_ikev2_mesg* tx_req_ikemesg);


extern int rhp_ikev2_auth_vpn_tkt_set_session_key(struct _rhp_vpn* spk2spk_vpn,
		int session_key_len,u8* session_key,int n_enc_auth_tkt_len,u8* n_enc_auth_tkt);




//
// IKEv2 global statistics
//

struct _rhp_ikev2_global_statistics_dont_clear {
	u64 ikesa_initiator_num;
	u64 ikesa_responder_num;
	u64 childsa_initiator_num;
	u64 childsa_responder_num;
	u64 ikesa_half_open_num;
	u64 qcd_pend_req_packets;
	u64 ikev2_alloc_rx_messages;
	u64 ikev2_alloc_tx_messages;
	unsigned long vpn_num;
};
typedef struct _rhp_ikev2_global_statistics_dont_clear rhp_ikev2_global_statistics_dont_clear;

// Only error or special case's statistics(for performance).
struct _rhp_ikev2_global_statistics {

	u64 rx_ikev2_invalid_packets;
	u64 rx_ikev2_err_packets;

	u64 rx_ikev2_acl_err_packets;

	u64 rx_ikev2_resp_verify_err_packets;
	u64 rx_ikev2_resp_unknown_if_err_packets;
	u64 rx_ikev2_resp_no_ikesa_err_packets;
	u64 rx_ikev2_resp_bad_ikesa_state_packets;
	u64 rx_ikev2_resp_no_req_err_packets;
	u64 rx_ikev2_resp_invalid_seq_packets;
	u64 rx_ikev2_resp_invalid_exchg_type_packets;
	u64 rx_ikev2_resp_not_encrypted_packets;
	u64 rx_ikev2_resp_integ_err_packets;
	u64 rx_ikev2_resp_invalid_len_packets;
	u64 rx_ikev2_resp_invalid_spi_packets;
	u64 rx_ikev2_resp_parse_err_packets;
	u64 rx_ikev2_resp_unsup_ver_packets;
	u64 rx_ikev2_resp_err_packets;
	u64 rx_ikev2_resp_process_err_packets;

	u64 rx_ikev2_resp_frag_packets;
	u64 rx_ikev2_resp_invalid_frag_packets;
	u64 rx_ikev2_resp_too_many_frag_packets;
	u64 rx_ikev2_resp_too_long_frag_packets;
	u64 rx_ikev2_resp_rx_dup_frag_packets;

	u64 rx_ikev2_resp_from_unknown_peer_packets;
	u64 rx_ikev2_req_apply_cookie_packets;

	u64 tx_ikev2_resp_rate_limited_err_packets;
	u64 tx_ikev2_resp_retransmit_packets;
	u64 tx_ikev2_resp_cookie_packets;

	u64 rx_ikev2_req_verify_err_packets;
	u64 rx_ikev2_req_new_ike_sa_init_packets;
	u64 rx_ikev2_req_no_ikesa_err_packets;
	u64 rx_ikev2_req_unknown_if_err_packets;
	u64 rx_ikev2_req_invalid_exchg_type_packets;
	u64 rx_ikev2_req_bad_ikesa_state_packets;
	u64 rx_ikev2_req_busy_err_packets;
	u64 rx_ikev2_req_invalid_seq_packets;
	u64 rx_ikev2_req_not_encrypted_packets;
	u64 rx_ikev2_req_integ_err_packets;
	u64 rx_ikev2_req_invalid_len_packets;
	u64 rx_ikev2_req_invalid_spi_packets;
	u64 rx_ikev2_req_parse_err_packets;
	u64 rx_ikev2_req_unsup_ver_packets;
	u64 rx_ikev2_req_err_packets;
	u64 rx_ikev2_req_process_err_packets;

	u64 rx_ikev2_req_frag_packets;
	u64 rx_ikev2_req_invalid_frag_packets;
	u64 rx_ikev2_req_too_many_frag_packets;
	u64 rx_ikev2_req_too_long_frag_packets;
	u64 rx_ikev2_req_rx_dup_frag_packets;
	u64 rx_ikev2_req_rx_frag_timedout;

	u64 rx_ikev2_req_from_unknown_peer_packets;

	u64 tx_ikev2_req_process_err_packets;
	u64 tx_ikev2_req_no_ikesa_err_packets;
	u64 tx_ikev2_req_queued_packets;
	u64 tx_ikev2_req_no_if_err_packets;
	u64 tx_ikev2_req_err_packets;
	u64 tx_ikev2_req_retransmit_packets;
	u64 tx_ikev2_req_retransmit_errors;
	u64 tx_ikev2_req_alloc_packet_err;

	u64 tx_ikev2_resp_no_if_err_packets;
	u64 tx_ikev2_resp_process_err_packets;
	u64 tx_ikev2_resp_err_packets;

	u64 ikesa_established_as_initiator;
	u64 ikesa_negotiated_as_initiator;
	u64 ikesa_deleted_as_initiator;
	u64 ikesa_established_as_responder;
	u64 ikesa_negotiated_as_responder;
	u64 ikesa_deleted_as_responder;
	u64 ikesa_responder_exchg_started;

	u64 ikesa_auth_errors;
	u64 ikesa_auth_rsa_sig;
	u64 ikesa_auth_psk;
	u64 ikesa_auth_null_auth;
	u64 ikesa_auth_eap;
	u64 ikesa_auth_sess_resume;
	u64 ikesa_auth_sess_resume_errors;

	u64 childsa_established_as_initiator;
	u64 childsa_negotiated_as_initiator;
	u64 childsa_deleted_as_initiator;
	u64 childsa_established_as_responder;
	u64 childsa_negotiated_as_responder;
	u64 childsa_deleted_as_responder;

	u64 vpn_allocated;
	u64 vpn_deleted;

	u64 qcd_rx_req_packets;
	u64 qcd_rx_req_err_packets;
	u64 qcd_rx_req_ignored_packets;
	u64 qcd_tx_err_resp_packets;
	u64 qcd_rx_err_resp_packets;
	u64 qcd_rx_err_resp_ignored_packets;
	u64 qcd_rx_err_resp_cleared_ikesas;
	u64 qcd_rx_err_resp_bad_tokens;
	u64 qcd_rx_err_resp_no_ikesa;

	u64 max_vpn_sessions_reached;
	u64 max_ikesa_half_open_sessions_reached;
	u64 max_cookie_half_open_sessions_reached;
	u64 max_cookie_half_open_sessions_per_sec_reached;

	u64 http_clt_get_cert_err;

	u64 mobike_init_tx_update_sa_addr_times;
	u64 mobike_init_exec_rt_check_times;
	u64 mobike_init_net_outage_times;
	u64 mobike_init_nat_t_addr_changed_times;
	u64 mobike_init_tx_probe_packets;
	u64 mobike_resp_rx_update_sa_addr_times;
	u64 mobike_resp_net_outage_times;



	u64 rx_ikev1_invalid_packets;
	u64 rx_ikev1_err_packets;

	u64 rx_ikev1_acl_err_packets;

	u64 rx_ikev1_verify_err_packets;
	u64 rx_ikev1_no_ikesa_err_packets;
	u64 rx_ikev1_unknown_if_err_packets;
	u64 rx_ikev1_invalid_exchg_type_packets;
	u64 rx_ikev1_bad_ikesa_state_packets;
	u64 rx_ikev1_busy_err_packets;
	u64 rx_ikev1_invalid_seq_packets;
	u64 rx_ikev1_not_encrypted_packets;
	u64 rx_ikev1_integ_err_packets;
	u64 rx_ikev1_invalid_len_packets;
	u64 rx_ikev1_invalid_spi_packets;
	u64 rx_ikev1_parse_err_packets;
	u64 rx_ikev1_unsup_ver_packets;
	u64 rx_ikev1_process_err_packets;

	u64 rx_ikev1_new_main_mode_packets;
	u64 rx_ikev1_new_aggressive_mode_packets;

	u64 rx_ikev1_from_unknown_peer_packets;

	u64 tx_ikev1_process_err_packets;
	u64 tx_ikev1_no_ikesa_err_packets;
	u64 tx_ikev1_no_if_err_packets;
	u64 tx_ikev1_err_packets;
	u64 tx_ikev1_alloc_packet_err;
	u64 tx_ikev1_retransmit_packets;
	u64 tx_ikev1_retransmit_errors;

	u64 rx_ikev1_req_unknown_if_err_packets;

	u64 tx_ikev1_resp_rate_limited_err_packets;
	u64 tx_ikev1_resp_retransmit_packets;

	// The followings MUST NOT be cleared by rhp_ikev2_clear_statistics()
	// and MUST be the tail of this structure.
	rhp_ikev2_global_statistics_dont_clear dc;
};
typedef struct _rhp_ikev2_global_statistics	rhp_ikev2_global_statistics;

extern rhp_mutex_t rhp_ikev2_lock_statistics;
extern rhp_ikev2_global_statistics rhp_ikev2_statistics_global_tbl;

#define rhp_ikev2_g_statistics_inc(value_name) {\
	RHP_LOCK(&rhp_ikev2_lock_statistics);\
	(rhp_ikev2_statistics_global_tbl.value_name)++;\
	RHP_UNLOCK(&rhp_ikev2_lock_statistics);\
}\

#define rhp_ikev2_g_statistics_dec(value_name) {\
	RHP_LOCK(&rhp_ikev2_lock_statistics);\
	(rhp_ikev2_statistics_global_tbl.value_name)--;\
	RHP_UNLOCK(&rhp_ikev2_lock_statistics);\
}\

extern void rhp_ikev2_get_statistics(rhp_ikev2_global_statistics* table);
extern void rhp_ikev2_clear_statistics();


#endif // _RHP_IKEV2_H_


