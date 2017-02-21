/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/



#ifndef _RHP_VPN_H_
#define _RHP_VPN_H_

#include "rhp_ikesa.h"
#include "rhp_ikev2_mesg.h"
#include "rhp_ui.h"

struct _rhp_vpn;
struct _rhp_radius_access_accept_attrs;
struct _rhp_nhrp_addr_map;
struct _rhp_nhrp_mesg;
struct _rhp_auth_tkt_pending_req;

struct _rhp_ikesa_timers {

  unsigned char tag[4]; // "#VIT"

  int my_side;
  u8 my_spi[RHP_PROTO_IKE_SPI_SIZE];

  rhp_timer lifetime_timer;
  int (*start_lifetime_timer)(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,time_t secs,int sec_randomized);
  int (*quit_lifetime_timer)(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa);


  rhp_timer keep_alive_timer;
  u64 last_rx_encrypted_packets;
  u64 last_rx_esp_packets;
  int keep_alive_forced;
  int (*start_keep_alive_timer)(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,time_t interval);
  int (*quit_keep_alive_timer)(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa);


  rhp_timer nat_t_keep_alive_timer;
  int (*start_nat_t_keep_alive_timer)(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,time_t interval);
  int (*quit_nat_t_keep_alive_timer)(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa);


  rhp_timer retx_timer;
  int retx_counter;
  int retx_mobike_resp_counter;
  int (*start_retransmit_timer)(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,int dont_wait);
  int (*quit_retransmit_timer)(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa);


  rhp_timer frag_rx_req_timer;
  int (*start_frag_rx_req_timer)(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,time_t interval);
  int (*quit_frag_rx_req_timer)(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa);


  int (*schedule_delete)(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,int defered_sec);
};
typedef struct _rhp_ikesa_timers rhp_ikesa_timers;


struct _rhp_childsa_timers {

  unsigned char tag[4]; // "#VCT"

  struct _rhp_childsa_timers* next;

  u32 spi_inb;
  u32 spi_outb;

  rhp_timer lifetime_timer;

  int (*start_lifetime_timer)(struct _rhp_vpn* vpn,struct _rhp_childsa* childsa,time_t secs,int sec_randomized);
  int (*quit_lifetime_timer)(struct _rhp_vpn* vpn,struct _rhp_childsa* childsa);

  int (*schedule_delete)(struct _rhp_vpn* vpn,struct _rhp_childsa* childsa,int defered_sec);
};
typedef struct _rhp_childsa_timers rhp_childsa_timers;


struct _rhp_vpn_sess_resume_material {

	u8 tag[4]; // '#SRM'

	int my_side_i;
	u8 my_spi_i[RHP_PROTO_IKE_SPI_SIZE];
	rhp_ikev2_id my_id_i;
	struct _rhp_res_sa_proposal* old_sa_prop_i;
  int old_sk_d_i_len;
  u8* old_sk_d_i;
  rhp_eap_id my_eap_id_i;

  int peer_tkt_r_len;
  u8* peer_tkt_r;
  time_t peer_tkt_r_expire_time; // (secs) 0: Unknown.
};
typedef struct _rhp_vpn_sess_resume_material	rhp_vpn_sess_resume_material;


struct _rhp_vpn_reconnect_info {

	unsigned char tag[4]; // "#VRC"

	unsigned long rlm_id;

	rhp_ikev2_id peer_id;

	rhp_ip_addr peer_addr;

	char* peer_fqdn;
	rhp_ip_addr peer_fqdn_addr_primary;
	rhp_ip_addr peer_fqdn_addr_secondary;

	u16 peer_port;
	u16 reserved;

	unsigned long retries;

	rhp_vpn_sess_resume_material* sess_resume_material_i;
};
typedef struct _rhp_vpn_reconnect_info rhp_vpn_reconnect_info;


struct _rhp_vpn_mobike_cookie2 {

	struct _rhp_vpn_mobike_cookie2* next;

	int mesg_id_valid;
	u32 mesg_id;

#define RHP_IKEV2_MOBIKE_COOKIE2_LEN	64
	u8 cookie2[RHP_IKEV2_MOBIKE_COOKIE2_LEN];

#define RHP_IKEV2_MOBIKE_COOKIE2_SA_ADDR									1
#define RHP_IKEV2_MOBIKE_COOKIE2_NAT_GW_REFLEXIVE_ADDR		2
	int gen_type;

	rhp_ikev2_mesg* tx_ikemesg;
};
typedef struct _rhp_vpn_mobike_cookie2	rhp_vpn_mobike_cookie2;

extern void rhp_ikev2_mobike_free_tx_cookie2(rhp_vpn_mobike_cookie2* tx_cookie2);


struct _rhp_mobike_path_map {

	rhp_if_entry my_if_info;
	rhp_ip_addr peer_addr;

#define RHP_MOBIKE_PEER_CFG					1
#define RHP_MOBIKE_PEER_ADDITIONAL	2
	int peer_type;

	rhp_packet_ref* rx_probe_pend_pkt_ref;	// IKEv2 Response mesg

	int result; // 0: NG, 1: OK
};
typedef struct _rhp_mobike_path_map	rhp_mobike_path_map;

extern void rhp_ikev2_mobike_free_path_maps(struct _rhp_vpn* vpn);


struct _rhp_ikev2_tx_new_req {

	u8 tag[4]; // '#TNR'

	struct _rhp_ikev2_tx_new_req* next;

	int my_side;
	u8 my_spi[RHP_PROTO_IKE_SPI_SIZE];

	rhp_ikev2_mesg* tx_ikemesg;

	int retries;
};
typedef struct _rhp_ikev2_tx_new_req	rhp_ikev2_tx_new_req;




typedef void (*RHP_EAP_SUP_ASK_FOR_USER_KEY_CB)(void* ctx,struct _rhp_vpn* vpn,int my_ikesa_side,
		u8* my_ikesa_spi,int eap_method,
		u8* user_id,int user_id_len,u8* user_key,int user_key_len);

struct _rhp_vpn {

  unsigned char tag[4]; // "#VPN"

  struct _rhp_vpn* next_hash;
  struct _rhp_vpn* next_hash_eap_id;
  struct _rhp_vpn* next_hash_unique_id;
//struct _rhp_vpn* next_hash_dummy_peer_mac;
  struct _rhp_vpn* next_hash_peer_addr;
  struct _rhp_vpn* pre_list;
  struct _rhp_vpn* next_list;

  rhp_mutex_t lock;

  rhp_atomic_t refcnt;
  rhp_atomic_t is_active;

  u8 unique_id[RHP_VPN_UNIQUE_ID_SIZE]; // RHP_VPN_UNIQUE_ID_SIZE: See rhp_misc.h

  rhp_ikev2_id my_id;
  rhp_ikev2_id peer_id;

  char* peer_fqdn;

  unsigned long vpn_realm_id;
  struct _rhp_vpn_realm* rlm;
  struct _rhp_cfg_peer* cfg_peer; // Reference is held in rlm.


  rhp_ip_addr peer_addr;
  rhp_ip_addr origin_peer_addr;

  void (*set_peer_addr)(struct _rhp_vpn* vpn,rhp_ip_addr* addr,rhp_ip_addr* origin_addr);

  struct {
  	rhp_if_entry if_info;
  	u16 port;
  	u16 port_nat_t;
  } local;

  void (*set_local_net_info)(struct _rhp_vpn* vpn,rhp_ifc_entry* ifc,int addr_family,u8* addr);

  int auto_reconnect;
  int exec_auto_reconnect;
  int auto_reconnect_retries;
  rhp_vpn_reconnect_info* reconnect_info;

  u8 connecting;
  u8 ikesa_req_rekeying;
  u8 childsa_req_rekeying;
  u8 established;
  u8 deleting; // Deleted by user or UI.
  u8 is_initiated_by_user; // As Initiator, of course.
  u8 peer_is_remote_client;
  u8 is_remote_client;

  time_t created;

  int ikesa_num; // TODO : Deny new IKE SAs if acceptable num reaches.
  rhp_ikesa* ikesa_list_head;

  rhp_ikesa* (*ikesa_get)(struct _rhp_vpn* vpn,int my_side,u8* spi);
  void (*ikesa_put)(struct _rhp_vpn* vpn,rhp_ikesa* ikesa);
  rhp_ikesa* (*ikesa_delete)(struct _rhp_vpn* vpn,int my_side,u8* spi);
  void (*ikesa_move_to_top)(struct _rhp_vpn* vpn,rhp_ikesa* ikesa);

  int rx_peer_cert_len;
  u8* rx_peer_cert; // Binary form (DER) without a rhp_cert_data header.
  char* rx_peer_cert_url;
  int rx_peer_cert_hash_len;
  u8* rx_peer_cert_hash;

  int rx_untrust_ca_certs_len;
  int rx_untrust_ca_certs_num;
  u8* rx_untrust_ca_certs; // rhp_cert_data + cert_data | rhp_cert_data + cert_data | ...

  int childsa_num; // TODO : Deny new Child SAs if acceptable num reaches.
  rhp_childsa* childsa_list_head;

  unsigned long created_ikesas;
  unsigned long created_childsas;


  rhp_childsa_ts* last_my_tss;
  rhp_childsa_ts* last_peer_tss;

  rhp_childsa_ts* ipv6_autoconf_my_tss;
  rhp_childsa_ts* ipv6_autoconf_peer_tss;

  rhp_childsa* (*childsa_get)(struct _rhp_vpn* vpn,int direction,u32 spi);
  void (*childsa_put)(struct _rhp_vpn* vpn,rhp_childsa* childsa);
  rhp_childsa* (*childsa_delete)(struct _rhp_vpn* vpn,int direction,u32 spi);
  void (*childsa_move_to_top)(struct _rhp_vpn* vpn,rhp_childsa* childsa);

  int (*childsa_established)(struct _rhp_vpn* vpn);


  int (*check_cfg_address)(struct _rhp_vpn* vpn,struct _rhp_vpn_realm* rlm,
  		struct _rhp_packet* pkt);

#define RHP_VPN_TX_IKEMESG_Q_URG				0
#define RHP_VPN_TX_IKEMESG_Q_NORMAL			1
#define RHP_VPN_TX_IKEMESG_Q_NUM				2
  struct _rhp_ikemesg_q req_tx_ikemesg_q[RHP_VPN_TX_IKEMESG_Q_NUM];

  rhp_ui_ctx ui_info;

  // TODO : Implement detailed statistics, if needed.
  struct {

    u64 tx_esp_packets;
    u64 tx_esp_bytes;

    u64 rx_esp_packets;
    u64 rx_esp_bytes;

  } statistics;

  int peer_is_rockhopper;
  int peer_rockhopper_ver;

  int is_configured_peer; // This peer is configured with a Peer ID. NOT any.

  int origin_side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER

  u16 origin_peer_port; // Peer's port used for IKE_SA_INIT exchg.
  u8 init_by_peer_addr;
  u8 reserved1;

  struct {

  	int encap_mode_c; // RHP_VPN_ENCAP__XXX

  	int static_peer_addr;
  	rhp_ip_addr_list* peer_addrs;

	  u8 exchg_peer_mac[6];			// aligned: exchg_peer_mac[0-5]
	  u8 peer_addrs_notified; 	// aligned: exchg_peer_mac[6]
	  u8 fwd_any_dns_queries;	 	// aligned: exchg_peer_mac[7]

	  u8 dummy_peer_mac[6]; // aligned: dummy_peer_mac[0-5]

	  // For remote client.
#define RHP_IKEV2_CFG_CP_ADDR_NONE			0
#define RHP_IKEV2_CFG_CP_ADDR_REQUESTED	1
#define RHP_IKEV2_CFG_CP_ADDR_ASSIGNED	2
	  u8 peer_addr_v4_cp; // aligned: dummy_peer_mac[6]
	  u8 peer_addr_v6_cp; // aligned: dummy_peer_mac[7]

	  u8 exec_ipv6_autoconf;
	  u8 peer_exec_ipv6_autoconf;
	  u8 ipv6_autoconf_narrow_ts_i;
	  u8 reserved0;

  	rhp_ip_addr_list* ipv6_autoconf_old_addrs;

  } internal_net_info;

  struct {

  	//
  	// !exec_nat_t && !use_nat_t_port : Neither Ikev2 nor ESP(NOT UDP-encup) uses NAT-T port.
  	//
  	// !exec_nat_t && use_nat_t_port : Only IKEv2 uses NAT-T port. (e.g. MOBIKE).
  	//
  	// exec_nat_t && use_nat_t_port : Both IKEv2 and ESP(UDP-encup) use NAT-T port.
  	//
  	// exec_nat_t && !use_nat_t_port : Both IKEv2 and ESP(UDP-encup) use NAT-T port.
  	//
    int exec_nat_t;
    int use_nat_t_port;
    int always_use_nat_t_port; // config

#define RHP_IKESA_BEHIND_A_NAT_LOCAL 	0x1
#define RHP_IKESA_BEHIND_A_NAT_PEER 	0x2
    unsigned int behind_a_nat;

    time_t last_addr_changed;

    int rx_udp_encap_from_remote_peer;

  } nat_t_info;

  // This is also used for IKEv1/XAUTH.
  struct {

  	int role; 	// RHP_EAP_XXXX
  	int eap_method; // RHP_PROTO_EAP_TYPE_XXX. In case of RHP_PROTO_EAP_TYPE_PRIV_RADIUS,
  									// see vpn->radius.eap_method for actual method type.

  	void* impl_ctx;

  	unsigned long rebound_vpn_realm_id; // For EAP server(Authenticator)

  	// For EAP server(Authenticator).
  	rhp_eap_id peer_id;


  	// For EAP peer(Supplicant).
  	RHP_EAP_SUP_ASK_FOR_USER_KEY_CB ask_for_user_key_cb;
  	void* ask_usrkey_cb_ctx;
  	u64 ask_usr_key_ipc_txn_id;
  	unsigned long ask_usr_key_ui_txn_id;

  	rhp_eap_id my_id;

  } eap;

  struct {

  	int eap_method; // RHP_PROTO_EAP_TYPE_XXX. Not RHP_PROTO_EAP_TYPE_PRIV_RADIUS!

  	//
  	// eap.rebound_vpn_realm_id is used for a User's VPN Realm ID attribute.
  	//

  	struct _rhp_radius_access_accept_attrs* rx_accept_attrs;


#define RHP_VPN_RADIUS_ATTRS_MASK_SET_0(mask,mask_bit) 	((mask) |= (0x8000000000000000ULL >> mask_bit))
#define RHP_VPN_RADIUS_ATTRS_MASK_SET(vpn,mask_bit) 		RHP_VPN_RADIUS_ATTRS_MASK_SET_0((vpn)->radius.rx_accept_attrs_mask,mask_bit)
#define RHP_VPN_RADIUS_ATTRS_MASK_0(mask,mask_bit) 			((mask) & (0x8000000000000000ULL >> mask_bit))
#define RHP_VPN_RADIUS_ATTRS_MASK(vpn,mask_bit) 				RHP_VPN_RADIUS_ATTRS_MASK_0((vpn)->radius.rx_accept_attrs_mask,mask_bit)

#define RHP_VPN_RADIUS_ATTRS_MASK_FRAMED_IP_V4							0
#define RHP_VPN_RADIUS_ATTRS_MASK_FRAMED_IP_V6							1
#define RHP_VPN_RADIUS_ATTRS_MASK_MS_PRIMARY_DNS_SERVER_V4	2
#define RHP_VPN_RADIUS_ATTRS_MASK_DNS_IPV6_SERVER						3
#define RHP_VPN_RADIUS_ATTRS_MASK_MS_PRIMARY_NBNS_SERVER_V4	4
#define RHP_VPN_RADIUS_ATTRS_MASK_TUNNEL_CLIENT_AUTH_ID			5
#define RHP_VPN_RADIUS_ATTRS_MASK_PRIV_USER_INDEX						6
#define RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_IPV4						7
#define RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_IPV6						8
#define RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_DNS_V4					9
#define RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_DNS_V6					10
#define RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_DOMAINS					11
#define RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_RT_MAP_V4				12
#define RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_RT_MAP_V6				13
#define RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_GW_V4						14
#define RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_GW_V6						15
  	u64 rx_accept_attrs_mask;

  	u8 acct_enabled;
  	u8 acct_tx_start_notify;
  	u8 reserved0;
  	u8 reserved1;

  	int acct_term_cause; // RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_XXX

  } radius;


  u8 exec_mobike;
  u8 mobike_disabled;
  u16 reserved2;

  union {

  	// Initiator
  	struct {

  		// Peer's additional addrs.
  		int additional_addrs_num;
  		rhp_ip_addr_list* additional_addrs;

  		int rt_ck_pending; // routability check flag

  		int cand_path_maps_num;
  		int cand_path_maps_cur_idx;
  		int cand_path_maps_retries;
  		int cand_path_maps_active;
  		rhp_mobike_path_map* cand_path_maps;

  		int cand_path_maps_num_result;
  		rhp_mobike_path_map* cand_path_maps_result; // Don't access pmap->rx_probe_pend_pkt_ref (pointer).

  		rhp_packet_ref* tx_probe_pkt_ref; // IKEv2 Request mesg and fragments(if any).

  		rhp_vpn_mobike_cookie2* rt_ck_cookie2_head;

  		int nat_t_src_hash_rx_times;
  		u8 rx_nat_t_src_hash[RHP_IKEV2_NAT_T_HASH_LEN];

  		int rt_ck_waiting;
  		time_t rt_ck_hold_start_time;
  		rhp_timer rt_ck_waiting_timer;

  		unsigned long nat_t_addr_changed_times;

  	} init;

  	// Responder
  	struct {

  		int rt_ck_pending; // routability check flag
  		rhp_ip_addr rt_ck_pend_peer_addr;
  		rhp_if_entry rt_ck_pend_local_if_info;

  		rhp_vpn_mobike_cookie2* rt_ck_cookie2_head;

  		int keepalive_pending;

  	} resp;

  } mobike;

  unsigned long mobike_exec_rt_ck_times;


	struct {

  	u8 exec_sess_resume;
  	u8 gen_by_sess_resume;
  	u8 tkt_req_pending;
  	u8 auth_method_i_org; // For responder.
  	u8 auth_method_r_org; // For responder.
  	u8 reserved0;
  	u8 reserved1;
  	u8 reserved2;

  	rhp_vpn_sess_resume_material* material; // For initiator.

  } sess_resume;

  void (*sess_resume_clear)(struct _rhp_vpn* vpn);
  rhp_vpn_sess_resume_material* (*sess_resume_get_material_i)(struct _rhp_vpn* vpn);
  void (*sess_resume_set_material_i)(struct _rhp_vpn* vpn,rhp_vpn_sess_resume_material* material_i);


  struct {

  	rhp_ikev2_tx_new_req* req_head;

  	rhp_timer task;

  } ikev2_tx_new_req;


  time_t vpn_conn_lifetime;
  rhp_timer vpn_conn_timer;
  int (*start_vpn_conn_life_timer)(struct _rhp_vpn* vpn);
  int (*quit_vpn_conn_life_timer)(struct _rhp_vpn* vpn);

#define RHP_VPN_CONN_IDLE_TIMEOUT_RANDOM_RANGE		30
  time_t vpn_conn_idle_timeout;
  rhp_timer vpn_conn_idle_timer;
  int (*start_vpn_conn_idle_timer)(struct _rhp_vpn* vpn);
  int (*quit_vpn_conn_idle_timer)(struct _rhp_vpn* vpn);

  struct {

  	int key_enabled;
  	u32 key;

  } gre;

  struct {

  	u8 role; // RHP_NHRP_SERVICE_XXX
  	u8 dmvpn_enabled;

  	// For NHC
  	u8 nhc_update_addr_pending;
  	u8 nhc_update_addr_forcedly;

  	int nhc_pending_purge_reqs;

  	rhp_timer nhc_registration_timer;

  	struct _rhp_nhrp_addr_map* nhc_addr_maps_head;

  	// For NHS
  	int nhs_next_hop_addrs_num;
  	rhp_ip_addr_list* nhs_next_hop_addrs;

  	struct {
  		struct _rhp_nhrp_mesg* head;
  		struct _rhp_nhrp_mesg* tail;
  	} pend_resolution_req_q;

  	u8 dmvpn_shortcut;
  	u8 reserved0;
  	u16 reserved1;

		int key_len;
		u8* key;

  } nhrp;

	int (*start_nhc_registration_timer)(struct _rhp_vpn* vpn,time_t next_interval);
	int (*quit_nhc_registration_timer)(struct _rhp_vpn* vpn);


  struct {

#define RHP_AUTH_TKT_CONN_TYPE_DISABLED			0
#define RHP_AUTH_TKT_CONN_TYPE_HUB2SPOKE		1
#define RHP_AUTH_TKT_CONN_TYPE_SPOKE2SPOKE	2
  	u8 conn_type;
  	u16 reserved1;

  	struct _rhp_auth_tkt_pending_req* hb2spk_pend_req_q_head;
  	struct _rhp_auth_tkt_pending_req* hb2spk_pend_req_q_tail;

		rhp_ip_addr spk2spk_resp_pub_addr;
		rhp_ip_addr spk2spk_resp_itnl_addr;
		rhp_ikev2_id spk2spk_resp_id;

		int spk2spk_session_key_len;
		u8* spk2spk_session_key;

		int spk2spk_n_enc_auth_tkt_len;
		u8* spk2spk_n_enc_auth_tkt;

  } auth_ticket;


  u8 peer_http_cert_lookup_supported;
  u8 exec_ikev2_frag;
  u8 exec_rekey_ipv6_autoconf;
  u8 reserved3;

  int route_updated;

  int create_child_sa_failed;

#define RHP_VPN_TS_EXT_FLG_NARROW_CP								0x01
#define RHP_VPN_TS_EXT_FLG_IPV6_ALLOW_RA						0x02
#define RHP_VPN_TS_EXT_FLG_IPV6_ALLOW_AUTOCONFIG		0x04
  unsigned int ts_extended_flag;


  unsigned long peer_notified_realm_id;

  int is_v1;

  struct {

  	unsigned long def_realm_id;

  	u8 peer_nat_t_supproted;
  	u8 peer_dpd_supproted;
#define RHP_IKEV1_ITNL_ADDR_FLAG_TX		0x01
#define RHP_IKEV1_ITNL_ADDR_FLAG_RX		0x02
  	u8 internal_addr_flag;
  	u8 commit_bit_enabled; // P2

    u8 cur_vpn_unique_id[RHP_VPN_UNIQUE_ID_SIZE];

  	u8 merge_larval_vpn;
  	u8 dpd_enabled;
  	u16 reserved0;

  	// [0]: IPv4, [1]: IPv6
  	rhp_ip_addr* rx_mode_cfg_internal_addrs;

  } v1;

  rhp_childsa* (*v1_ipsecsa_get_by_mesg_id)(struct _rhp_vpn* vpn,rhp_ikesa* ikesa,u32 mesg_id);


  void (*dump)(char* label,struct _rhp_vpn* vpn);
};
typedef struct _rhp_vpn rhp_vpn;


struct _rhp_vpn_list {

	struct _rhp_vpn_list* next;

	rhp_vpn_ref* vpn_ref;
};
typedef struct _rhp_vpn_list	rhp_vpn_list;

extern rhp_vpn_list* rhp_vpn_list_alloc(rhp_vpn* vpn);
extern void rhp_vpn_list_free(rhp_vpn_list* vpn_lst_head);


struct _rhp_internal_address {

	u8 tag[4]; // '#INA'

	struct _rhp_internal_address* hash_peer_id_next;
	struct _rhp_internal_address* hash_eap_peer_id_next;
	struct _rhp_internal_address* hash_addr_v4_next;
	struct _rhp_internal_address* hash_addr_v6_next;

	struct _rhp_internal_address* lst_prev;
	struct _rhp_internal_address* lst_next;

	unsigned long vpn_realm_id;

	rhp_ikev2_id peer_id;

	rhp_eap_id eap_peer_id;

	rhp_ip_addr assigned_addr_v4;
	rhp_ip_addr assigned_addr_v6;

	time_t expire;
};
typedef struct _rhp_internal_address		rhp_internal_address;


#ifndef RHP_HASH_SIZE_DBG
#define RHP_VPN_HASH_TABLE_SIZE   1277
#else // RHP_HASH_SIZE_DBG
#define RHP_VPN_HASH_TABLE_SIZE   3
#endif // RHP_HASH_SIZE_DBG


extern rhp_vpn* rhp_vpn_alloc(rhp_ikev2_id* my_id,rhp_ikev2_id* peer_id,
		rhp_vpn_realm* rlm,rhp_ip_addr* peer_ip,int origin_side);

//
// [CAUTION]
// This API internally acqures rlm->lock. So, don't call this API with the lock acquired.
//
extern void rhp_vpn_destroy(rhp_vpn* vpn);


#ifndef RHP_REFCNT_DEBUG

typedef struct _rhp_vpn	rhp_vpn_ref;

extern void rhp_vpn_hold(rhp_vpn* vpn);
extern rhp_vpn_ref* rhp_vpn_hold_ref(rhp_vpn* vpn);
extern void rhp_vpn_unhold(void* vpn);

#define RHP_VPN_REF(vpn) ((rhp_vpn*)(vpn))

#else // RHP_REFCNT_DEBUG

#ifndef RHP_REFCNT_DEBUG_X

typedef struct _rhp_vpn	rhp_vpn_ref;

extern void rhp_vpn_free(rhp_vpn* vpn);

#define rhp_vpn_hold(vpn)\
{\
	RHP_LINE("#RHP_VPN_HOLD 0x%x:vpn->refcnt.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",(vpn),(vpn)->refcnt.c,rhp_func_trc_current());\
  _rhp_atomic_inc(&((vpn)->refcnt));\
}
#define rhp_vpn_hold_ref(vpn)\
({\
	rhp_vpn_ref* __ret3__ = (rhp_vpn_ref*)(vpn);\
	RHP_LINE("#RHP_VPN_HOLD REF 0x%x:vpn->refcnt.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",(vpn),(vpn)->refcnt.c,rhp_func_trc_current());\
  _rhp_atomic_inc(&((vpn)->refcnt));\
	__ret3__;\
})
#define rhp_vpn_unhold(vpn_t)\
{\
	rhp_vpn* __vpn__ = (rhp_vpn*)(vpn_t);\
	RHP_LINE("#RHP_VPN_UNHOLD 0x%x:vpn->refcnt.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",__vpn__,__vpn__->refcnt.c,rhp_func_trc_current());\
	if( _rhp_atomic_dec_and_test(&(__vpn__->refcnt)) ){\
  	RHP_LINE("#RHP_VPN_UNHOLD_DESTROY 0x%x:vpn->refcnt.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",__vpn__,__vpn__->refcnt.c,rhp_func_trc_current());\
  	rhp_vpn_free(__vpn__);\
  }\
}
#define RHP_VPN_REF(vpn) ((rhp_vpn*)(vpn))

#else // RHP_REFCNT_DEBUG_X

/*

  To debug a rhp_vpn object's refcnt, use rhp_vpn_hold_ref() and rhp_vpn_unhold().
  rhp_vpn_hold_ref() returns a rhp_vpn_ref object which records where the rhp_vpn
  object is held by rhp_vpn_hold_ref(). To unhold the object, use rhp_vpn_unhold()
  as usual. To get a rhp_vpn object from a rhp_vpn_ref object, use RHP_VPN_REF().


  rhp_vpn* vpn = xxx.
  rhp_vpn_ref* vpn_ref = rhp_vpn_hold_ref(vpn);
  ...
  ...
  rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);
  ...
  ...
  rhp_vpn_unhold(vpn_ref);


	To get unheld rhp_vpn objects' records, run 'rockhopper.pl memory_dbg ... ' command.

*/

typedef struct _rhp_refcnt_dbg	rhp_vpn_ref;

extern void rhp_vpn_free(rhp_vpn* vpn);

#define rhp_vpn_hold(vpn)\
{\
	RHP_LINE("#RHP_VPN_HOLD 0x%x:vpn->refcnt.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",(vpn),(vpn)->refcnt.c,rhp_func_trc_current());\
  _rhp_atomic_inc(&((vpn)->refcnt));\
}
#define rhp_vpn_hold_ref(vpn)\
({\
	rhp_vpn_ref* __ret3__;\
  _rhp_atomic_inc(&((vpn)->refcnt));\
  __ret3__ = (rhp_vpn_ref*)rhp_refcnt_dbg_alloc((vpn),__FILE__,__LINE__);\
	RHP_LINE("#RHP_VPN_HOLD REF 0x%x(ref:0x%x):vpn->refcnt.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",(vpn),__ret3__,(vpn)->refcnt.c,rhp_func_trc_current());\
	__ret3__;\
})
#define rhp_vpn_unhold(vpn_or_vpn_ref)\
{\
	rhp_vpn* __vpn__ = (rhp_vpn*)rhp_refcnt_dbg_free((vpn_or_vpn_ref));\
	RHP_LINE("#RHP_VPN_UNHOLD 0x%x(ref:0x%x):vpn->refcnt.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",__vpn__,(vpn_or_vpn_ref),__vpn__->refcnt.c,rhp_func_trc_current());\
	if( _rhp_atomic_dec_and_test(&(__vpn__->refcnt)) ){\
  	RHP_LINE("#RHP_VPN_UNHOLD_DESTROY 0x%x(ref:0x%x):vpn->refcnt.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",__vpn__,(vpn_or_vpn_ref),__vpn__->refcnt.c,rhp_func_trc_current());\
  	rhp_vpn_free(__vpn__);\
  }\
}


#define RHP_VPN_REF(vpn_or_vpn_ref) ((rhp_vpn*)RHP_REFCNT_OBJ((vpn_or_vpn_ref)))

#endif // RHP_REFCNT_DEBUG_X
#endif // RHP_REFCNT_DEBUG



struct _rhp_auth_tkt_pending_req {

	u8 tag[4]; // '#ATR'

	struct _rhp_auth_tkt_pending_req* next;

	int hb2spk_my_side;
	u8 hb2spk_my_spi[RHP_PROTO_IKE_SPI_SIZE];
	u32 hb2spk_message_id;

	struct _rhp_vpn_ref* spk2spk_vpn_ref;
	void (*rx_resp_cb)(struct _rhp_vpn* rx_hb2spk_vpn,int hb2spk_my_ikesa_side,u8* hb2spk_my_ikesa_spi,
			int cb_err,struct _rhp_ikev2_mesg* rx_resp_ikemesg,struct _rhp_vpn* spk2spk_vpn);

	int hb2spk_is_tx_pending;

	struct _rhp_ikev2_mesg* hb2spk_tx_req_ikemesg;
};
typedef struct _rhp_auth_tkt_pending_req	rhp_auth_tkt_pending_req;

extern void rhp_ikev2_auth_tkt_pending_req_free(rhp_auth_tkt_pending_req* auth_tkt_req);




extern rhp_vpn_ref* rhp_vpn_get_unlocked(unsigned long rlm_id,rhp_ikev2_id* peer_id,
		rhp_eap_id* eap_peer_id,int no_alt_id);
extern rhp_vpn_ref* rhp_vpn_get(unsigned long rlm_id,rhp_ikev2_id* peer_id,rhp_eap_id* eap_peer_id);
extern rhp_vpn_ref* rhp_vpn_get_no_alt_id(unsigned long rlm_id,rhp_ikev2_id* peer_id,rhp_eap_id* eap_peer_id);
extern void rhp_vpn_put(rhp_vpn* vpn);
extern int rhp_vpn_delete_no_lock(rhp_vpn* vpn);
extern int rhp_vpn_delete(rhp_vpn* vpn);
extern int rhp_vpn_enum(unsigned long rlm_id,int (*callback)(rhp_vpn* vpn,void* ctx),void* ctx);

extern rhp_vpn_ref* rhp_vpn_get_by_eap_peer_id_unlocked(unsigned long rlm_id,rhp_eap_id* eap_peer_id);
extern rhp_vpn_ref* rhp_vpn_get_by_eap_peer_id(unsigned long rlm_id,rhp_eap_id* eap_peer_id);

/*
extern rhp_vpn_ref* rhp_vpn_get_by_dummy_peer_mac_no_lock(u8* dummy_peer_mac);
extern rhp_vpn_ref* rhp_vpn_get_by_dummy_peer_mac(u8* dummy_peer_mac);
*/

extern int rhp_vpn_put_by_peer_internal_addr(rhp_ip_addr* peer_internal_ip,rhp_vpn* vpn);
extern int rhp_vpn_delete_by_peer_internal_addr(rhp_ip_addr* peer_internal_ip,rhp_vpn* vpn);
extern rhp_vpn_ref* rhp_vpn_get_by_peer_internal_addr(unsigned long rlm_id,rhp_ip_addr* peer_internal_ip);
extern rhp_vpn_ref* rhp_vpn_get_by_peer_internal_addr_no_lock(unsigned long rlm_id,rhp_ip_addr* peer_internal_ip);

extern int rhp_vpn_put_by_peer_internal_mac(u8* mac,rhp_vpn* vpn);
extern int rhp_vpn_delete_by_peer_internal_mac(u8* mac,rhp_vpn* vpn);
extern rhp_vpn_ref* rhp_vpn_get_by_peer_internal_mac_no_lock(unsigned long rlm_id,u8* mac);
extern rhp_vpn_ref* rhp_vpn_get_by_peer_internal_mac(unsigned long rlm_id,u8* mac);


extern int rhp_vpn_get_by_peer_addr_impl(unsigned long rlm_id,int addr_family,u8* peer_address,
		rhp_vpn_list** vpn_lst_head_r);

extern int rhp_vpn_update_by_peer_addr(rhp_vpn* vpn,int new_addr_family,u8* new_peer_addr);

//
// Get a head of vpn lists if multiple and redundant vpns
// (destinated to the same address) exist.
//
extern rhp_vpn_ref* rhp_vpn_get_by_peer_addr(unsigned long rlm_id,
					rhp_ip_addr* peer_addr0,rhp_ip_addr* peer_addr1);



//
// peer_proto_addr is compared with NRHP registration cache.
//
extern rhp_vpn_ref* rhp_vpn_get_by_nhrp_peer_nbma_proto_addrs(unsigned long rlm_id,
		rhp_ip_addr* peer_nbma_addr,rhp_ip_addr* peer_proto_addr);


// [CAUTION] Don't call this API within ANY locked scope!
extern rhp_vpn_ref* rhp_vpn_get_by_peer_fqdn(unsigned long rlm_id,char* peer_fqdn);

extern int rhp_vpn_ikesa_spi_put(rhp_vpn* vpn,int my_side,u8* spi);
extern int rhp_vpn_ikesa_spi_delete(rhp_vpn* vpn,int my_side,u8* spi);
extern rhp_vpn_ref* rhp_vpn_ikesa_spi_get(int my_side,u8* spi);
extern rhp_vpn_ref* rhp_vpn_ikesa_spi_get_by_peer_id(unsigned long rlm_id,rhp_ikev2_id* peer_id,int no_alt_id);

extern int rhp_vpn_ikesa_v1_spi_delete(rhp_ip_addr* my_addr,rhp_ip_addr* peer_addr,
		int my_side,u8* my_spi,u8* peer_spi);
extern int rhp_vpn_ikesa_v1_spi_get(rhp_ip_addr* my_addr,rhp_ip_addr* peer_addr,
		u8* my_spi,u8* peer_spi,int* my_side_r);
extern int rhp_vpn_ikesa_v1_spi_put(rhp_ip_addr* my_addr,rhp_ip_addr* peer_addr,
		int my_side,u8* my_spi,u8* peer_spi);

extern int rhp_vpn_inb_childsa_put(rhp_vpn* vpn,u32 inb_spi);
extern int rhp_vpn_inb_childsa_delete(u32 inb_spi);
extern rhp_vpn_ref* rhp_vpn_inb_childsa_get(u32 inb_spi);

extern rhp_ikesa_timers* rhp_ikesa_new_timers(int my_side,u8* spi);
extern rhp_ikesa_timers* rhp_ikesa_v1_new_timers(int my_side,u8* spi);
extern void rhp_ikesa_timers_free(rhp_vpn* vpn,int my_side,u8* spi);

extern rhp_childsa_timers* rhp_childsa_new_timers(u32 spi_inb,u32 spi_outb);
extern rhp_childsa_timers* rhp_ipsecsa_v1_new_timers(u32 spi_inb,u32 spi_outb);
extern void rhp_childsa_timers_free(rhp_vpn* vpn,int direction,u32 spi);

extern time_t rhp_vpn_lifetime_random(int lifetime_secs);


extern void rhp_vpn_gen_unique_id(u8* unique_id_r);
extern int rhp_vpn_gen_or_add_local_mac(u8* added_mac,u8* mac_addr_r);
extern void rhp_vpn_clear_local_mac(u8* mac_addr);


extern void rhp_vpn_sess_resume_clear(rhp_vpn_sess_resume_material* material);


struct _rhp_vpn_conn_args {

	rhp_ikev2_id* peer_id;
	rhp_ip_addr* peer_addr;

	char* peer_fqdn;
	rhp_ip_addr* peer_fqdn_addr_primary;
	rhp_ip_addr* peer_fqdn_addr_secondary;

	u16 peer_port;

	int eap_sup_method;

	int eap_sup_user_id_len;
	u8* eap_sup_user_id;

	int eap_sup_user_key_len;
	u8* eap_sup_user_key;

	struct _rhp_nhrp_mesg* pend_nhrp_resolution_req;
	unsigned long nhrp_rx_vpn_realm_id;
	u8 nhrp_dmvpn_shortcut; // DMVPN: Spoke-to-Spoke connection
	u8 mobike_disabled;
	u8 auth_tkt_conn_type;

	u8 ikev1_init_mode;

	rhp_ip_addr* nhrp_peer_proto_addr;

	rhp_ui_ctx* ui_info;
};
typedef struct _rhp_vpn_conn_args rhp_vpn_conn_args;

struct _rhp_vpn_reconn_args {

	int auto_reconnect;
	int exec_auto_reconnect;
	int auto_reconnect_retries;

	rhp_vpn_sess_resume_material* sess_resume_material_i;
};
typedef struct _rhp_vpn_reconn_args rhp_vpn_reconn_args;

extern int rhp_vpn_connect_i(
		unsigned long rlm_id,
		rhp_vpn_conn_args* conn_args,
		rhp_vpn_reconn_args* reconn_args,
		int is_initiated_by_user);


extern int rhp_vpn_close_impl(rhp_vpn* vpn);

extern int rhp_vpn_close(unsigned long rlm_id,rhp_ikev2_id* peer_id,rhp_ip_addr* peer_addr,
		char* peer_fqdn,u8* vpn_unique_id,rhp_ui_ctx* ui_info);


extern rhp_vpn_ref* rhp_vpn_get_in_valid_rlm_cfg(unsigned long rlm_id,rhp_ikev2_id* peer_id);

extern u32 rhp_vpn_unique_id_hash(u8* unique_id);
extern rhp_vpn_ref* rhp_vpn_get_by_unique_id_unlocked(u8* unique_id);
extern rhp_vpn_ref* rhp_vpn_get_by_unique_id(u8* unique_id);

extern int rhp_vpn_enum_unique_ids(unsigned long rlm_id,
		u8** unique_ids_r,int* unique_ids_num_r,int* free_by_caller_r);
extern int rhp_vpn_enum_unique_ids2(unsigned long rlm_id,int no_tls_cache,
		u8** unique_ids_r,int* unique_ids_num_r,int* free_by_caller_r);
extern int rhp_vpn_clear_unique_ids_tls_cache(unsigned long rlm_id);

extern int rhp_vpn_internal_route_update_impl(rhp_vpn* vpn,time_t conv_interval);
extern int rhp_vpn_internal_route_update(rhp_vpn* vpn);
extern int rhp_vpn_internal_route_delete(rhp_vpn* vpn,rhp_vpn_realm* rlm);

extern rhp_ip_addr* rhp_vpn_internal_route_get_gw_addr(int addr_family,
		rhp_vpn_realm* rlm,rhp_vpn* vpn,rhp_route_map* rtmap);


extern int rhp_vpn_cleanup_by_realm_id(unsigned long rlm_id,int only_dormant);


extern int rhp_vpn_internal_address_assign(rhp_vpn* vpn,rhp_vpn_realm* rlm,
		rhp_ip_addr* cur_addr_v4,rhp_ip_addr* cur_addr_v6,
		rhp_ip_addr* new_addr_v4,rhp_ip_addr* new_addr_v6);
extern int rhp_vpn_internal_address_free(rhp_vpn* vpn,int dont_hold);
extern int rhp_vpn_internal_address_enum(unsigned long rlm_id,
		int (*callback)(rhp_internal_address* intr_addr,void* ctx),void* ctx);
extern void rhp_vpn_internal_address_clear_cache(unsigned long vpn_realm_id);

extern int rhp_vpn_internal_address_get(rhp_vpn* vpn,rhp_ip_addr_list** addrs_head_r);
extern int rhp_vpn_internal_address_is_assigned(rhp_vpn* vpn,rhp_ip_addr* addr);

extern int rhp_vpn_internal_addr_pool_v6_included(rhp_vpn_realm* rlm,rhp_ip_addr* addr);


extern int rhp_vpn_start_reconnect(rhp_vpn* vpn);


extern void rhp_vpn_ikev2_cfg_split_dns_clear(rhp_vpn_realm* rlm,rhp_vpn* vpn);
extern void rhp_vpn_ikev2_cfg_internal_routes_clear(rhp_vpn_realm* rlm,rhp_vpn* vpn);

extern rhp_vpn_ref* rhp_vpn_get_access_point_peer(unsigned long rlm_id);

extern int rhp_vpn_forcedly_close_conns(unsigned long rlm_id);


// AOC: Always On Connection
#define RHP_VPN_AOC_TIMER_INIT_INTERVAL		10 // (sec)
extern int rhp_vpn_aoc_put(rhp_vpn_realm* rlm); 	 // Call this before rhp_realm_put()!!!
extern void rhp_vpn_aoc_delete(u64 vpn_aoc_objid); // Don't call within a scope where rlm->lock or vpn->lock is acquired.
extern void rhp_vpn_aoc_start();
extern void rhp_vpn_aoc_update();
extern void rhp_vpn_aoc_stop();




extern int rhp_ui_http_vpn_added_serialize(void* http_bus_sess,void* ctx,void* writer,int idx);
extern void rhp_ui_http_vpn_bus_btx_async_cleanup(void* ctx);
extern int rhp_ui_http_vpn_deleted_serialize(void* http_bus_sess,void* ctx,void* writer,int idx);
extern void rhp_ui_http_vpn_bus_btx_async_cleanup(void* ctx);


extern rhp_atomic_t rhp_vpn_fwd_any_dns_queries;


extern int rhp_vpn_max_sessions_reached();
extern int rhp_ikesa_max_half_open_sessions_reached();



extern int rhp_vpn_connect_i_pending(unsigned long rlm_id,rhp_ikev2_id* peer_id,rhp_ip_addr* peer_addr);
extern int rhp_vpn_connect_i_pending_put(unsigned long rlm_id,rhp_ikev2_id* peer_id,rhp_ip_addr* peer_addr);
extern int rhp_vpn_connect_i_pending_clear(unsigned long rlm_id,rhp_ikev2_id* peer_id,rhp_ip_addr* peer_addr);






#endif // _RHP_VPN_H_
