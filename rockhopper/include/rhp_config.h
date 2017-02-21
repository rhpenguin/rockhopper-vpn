/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifndef _RHP_CONFIG_H_
#define _RHP_CONFIG_H_

#include "rhp_protocol.h"
#include "rhp_cert.h"

struct _rhp_packet;
struct _rhp_ikev2_mesg;

struct _rhp_vpn;
#ifndef rhp_vpn_ref
#ifdef RHP_REFCNT_DEBUG_X
typedef struct _rhp_refcnt_dbg	rhp_vpn_ref;
#else // RHP_REFCNT_DEBUG_X
typedef struct _rhp_vpn	rhp_vpn_ref;
#endif // RHP_REFCNT_DEBUG_X
#endif // rhp_vpn_ref

struct _rhp_ifc_entry;
struct _rhp_rt_map_entry;

/*************************************************

 Immutable global config params.

 [CAUTION]
 When configs are changed , please restart service.

**************************************************/
extern int rhp_gcfg_main_epoll_events;
extern int rhp_gcfg_timer_max_qsize;
extern int rhp_gcfg_wts_max_worker_tasks;
extern int rhp_gcfg_wts_max_worker_tasks_low_priority;
extern int rhp_gcfg_wts_syspxy_workers;
extern int rhp_gcfg_wts_main_workers;
extern int rhp_gcfg_wts_worker_yield_limit;
extern int rhp_gcfg_wts_max_task_pool_num;

extern int rhp_gcfg_ike_port;
extern int rhp_gcfg_ike_port_nat_t;
extern int rhp_gcfg_socket_path_mtu_discover;
extern int rhp_gcfg_pmtu_err_max_size; // Don't be an odd number!
extern int rhp_gcfg_min_pmtu;
extern int rhp_gcfg_netsock_max_recv_packets;
extern int rhp_gcfg_netsock_rx_esp_pkt_upper_limit;
extern int rhp_gcfg_tuntap_rx_pkt_upper_limit;
extern int rhp_gcfg_max_ike_packet_size;
extern int rhp_gcfg_max_packet_default_size;
extern int rhp_gcfg_max_packet_size;
extern int rhp_gcfg_recover_packet_default_size_num;
extern int rhp_gcfg_packet_buffer_pool_max_num;
extern int rhp_gcfg_packet_buffer_pool_init_num;
extern int rhp_gcfg_def_vif_mtu;

extern int rhp_gcfg_max_cert_payloads;
extern int rhp_gcfg_nonce_size;
extern int rhp_gcfg_ikev1_min_nonce_size;

extern int rhp_gcfg_ike_retry_times;
extern int rhp_gcfg_ike_init_retry_times;
extern int rhp_gcfg_ike_retry_init_interval;
extern int rhp_gcfg_ike_retry_max_interval;

extern int rhp_gcfg_http_max_connections;
extern int rhp_gcfg_http_rx_timeout;
extern int rhp_gcfg_http_max_uri;
extern int rhp_gcfg_http_max_header_len;
extern int rhp_gcfg_http_max_content_length;
extern int rhp_gcfg_http_default_port;
extern int rhp_gcfg_http_auth_no_pub_files;
extern int rhp_gcfg_http_bus_read_timeout;
extern int rhp_gcfg_http_bus_idle_timeout;
extern int rhp_gcfg_http_bus_max_session;
extern int rhp_gcfg_http_bus_max_async_mesg_bytes;
extern int rhp_gcfg_http_bus_max_async_non_critical_mesg_bytes;
extern int rhp_gcfg_http_auth_cookie_max_age; // secs
extern int rhp_gcfg_http_auth_cookie_aging_interval; // secs

extern int rhp_gcfg_keep_alive_interval;
extern int rhp_gcfg_nat_t_keep_alive_interval;
extern int rhp_gcfg_nat_t_keep_alive_packets;
extern int rhp_gcfg_always_exec_keep_alive;

extern int rhp_gcfg_ikesa_lifetime_larval;
extern int rhp_gcfg_ikesa_lifetime_eap_larval;
extern int rhp_gcfg_ikesa_lifetime_soft;
extern int rhp_gcfg_ikesa_lifetime_hard;
extern int rhp_gcfg_ikesa_lifetime_deleted;

extern int rhp_gcfg_childsa_lifetime_larval;
extern int rhp_gcfg_childsa_lifetime_soft;
extern int rhp_gcfg_childsa_lifetime_hard;
extern int rhp_gcfg_childsa_lifetime_deleted;
extern int rhp_gcfg_childsa_anti_replay;
extern int rhp_gcfg_childsa_anti_replay_win_size;
extern int rhp_gcfg_childsa_tfc_padding;
extern int rhp_gcfg_childsa_pfs;
extern int rhp_gcfg_childsa_resp_not_rekeying;

extern u64 rhp_gcfg_childsa_max_seq_esn;
extern u32 rhp_gcfg_childsa_max_seq_non_esn;

extern int rhp_gcfg_ikesa_cookie;
extern int rhp_gcfg_ikesa_cookie_max_open_req_per_sec;
extern int rhp_gcfg_ikesa_cookie_max_half_open_sessions;
extern int rhp_gcfg_ikesa_cookie_refresh_interval;
extern int rhp_gcfg_ikesa_cookie_max_pend_packets;

extern int rhp_gcfg_ikesa_resp_not_rekeying;

extern int rhp_gcfg_net_event_convergence_interval;

extern int rhp_gcfg_vpn_auto_reconnect_interval_1;
extern int rhp_gcfg_vpn_auto_reconnect_interval_2;
extern int rhp_gcfg_vpn_auto_reconnect_max_retries;

extern int rhp_gcfg_vpn_max_half_open_sessions;
extern int rhp_gcfg_vpn_max_sessions;

extern int rhp_gcfg_event_max_record_pool_num;

extern int rhp_gcfg_mac_cache_aging_interval;
extern int rhp_gcfg_mac_cache_hold_time;
extern int rhp_gcfg_mac_cache_max_entries;
extern int rhp_gcfg_proxy_arp_cache;

extern u32 rhp_gcfg_dummy_mac_min_idx;
extern u32 rhp_gcfg_dummy_mac_max_idx;
extern u32 rhp_gcfg_dummy_mac_oui;

extern int rhp_gcfg_arp_resolve_timeout; // secs
extern int rhp_gcfg_arp_resolve_retry_times;
extern int rhp_gcfg_neigh_resolve_max_addrs;
extern int rhp_gcfg_neigh_resolve_max_q_pkts;

extern int rhp_gcfg_wts_pkt_task_max_q_packets;
extern int rhp_gcfg_wts_pkt_task_yield_limit;

extern int rhp_gcfg_childsa_dbg_gen_spi;
extern int rhp_gcfg_ikesa_dbg_gen_spi;

extern int rhp_gcfg_dbg_tx_ikev2_pkt_lost_rate; // 0--100
extern int rhp_gcfg_dbg_tx_esp_pkt_lost_rate; // 0--100
extern int rhp_gcfg_dbg_tx_ikev2_pkt_cons_drop;
extern int rhp_gcfg_dbg_tx_esp_pkt_cons_drop;

extern int rhp_gcfg_dns_pxy_trans_tbl_timeout; // (sec)
extern int rhp_gcfg_dns_pxy_trans_tbl_timeout2; // (sec)
extern int rhp_gcfg_dns_pxy_trans_tbl_max_num;
extern int rhp_gcfg_dns_pxy_fixed_internal_port;
extern int rhp_gcfg_dns_pxy_fwd_any_queries_to_vpn;
extern int rhp_gcfg_dns_pxy_fwd_any_queries_to_vpn_non_rockhopper;
extern int rhp_gcfg_dns_pxy_fwd_max_sockets;

extern int rhp_gcfg_internal_address_aging_interval; // (sec)

extern int rhp_gcfg_vpn_always_on_connect_poll_interval; // (sec)

extern int rhp_gcfg_behind_a_nat_dont_change_addr_port;
extern int rhp_gcfg_peer_addr_change_min_interval;
extern int rhp_gcfg_nat_dont_change_addr_port_by_esp;
extern int rhp_gcfg_nat_dont_change_addr_port_by_ikev1;

extern int rhp_gcfg_bridge_static_cache_garp_num;

extern int rhp_gcfg_dns_pxy_convergence_interval;
extern int rhp_gcfg_dns_pxy_retry_interval;

extern int rhp_gcfg_strict_peer_addr_port_check;

extern int rhp_gcfg_log_level_debug;
extern int rhp_gcfg_max_event_log_records;

extern int rhp_gcfg_auth_method_compared_strictly;
extern int rhp_gcfg_randomize_sa_lifetime;

extern int rhp_gcfg_stun_max_attr_size;

extern int rhp_gcfg_ikesa_remote_cfg_narrow_ts_i;

extern int rhp_gcfg_ca_pubkey_digests_max_size;
extern int rhp_gcfg_responder_tx_all_cas_certreq;
extern int rhp_gcfg_check_certreq_ca_digests;
extern int rhp_gcfg_strictly_cmp_certreq_ca_digests;

extern int rhp_gcfg_delete_ikesa_if_no_childsa_exists;
extern int rhp_gcfg_reject_auth_exchg_without_childsa;

extern int rhp_gcfg_eap_mschapv2_max_auth_retries;

extern int rhp_gcfg_ikesa_crl_check_all;

extern int rhp_gcfg_net_event_init_convergence_interval;

extern int rhp_gcfg_dbg_log_keys_info;

extern int rhp_gcfg_dbg_direct_file_trace;
extern long rhp_gcfg_dbg_f_trace_max_size;
extern char* rhp_gcfg_dbg_f_trace_main_path;
extern char* rhp_gcfg_dbg_f_trace_syspxy_path;

extern int rhp_gcfg_trace_pkt_full_dump;

extern int rhp_gcfg_ikev2_alt_id_use_dn;

extern int rhp_gcfg_forcedly_close_vpns_wait_secs;

extern int rhp_gcfg_log_disabled;

extern int rhp_gcfg_check_pkt_routing_loop;

// This is NOT configured by rhp_gcfg_vpn_params[] table.
extern int rhp_gcfg_webmng_allow_nobody_admin;
extern int rhp_gcfg_webmng_auto_reconnect_nobody_admin;

extern int rhp_gcfg_eap_mschapv2_sup_skip_ms_len_check;

extern int rhp_gcfg_ikev2_qcd_enabled;
extern int rhp_gcfg_ikev2_qcd_min_token_len;
extern int rhp_gcfg_ikev2_qcd_max_token_len;
extern int rhp_gcfg_ikev2_qcd_max_rx_packets_per_sec;
extern int rhp_gcfg_ikev2_qcd_max_rx_err_per_sec;
extern int rhp_gcfg_ikev2_qcd_max_pend_packets;
extern int rhp_gcfg_ikev2_qcd_syspxy_max_pend_reqs;
extern int rhp_gcfg_ikev2_qcd_enabled_time; // secs after boot/reboot.

extern int rhp_gcfg_ike_retransmit_reps_limit_per_sec;

extern int rhp_gcfg_ikev2_mobike_rt_check_convergence_interval; // (secs)
extern int rhp_gcfg_ikev2_mobike_rt_check_interval_msec; // (msecs)
extern int rhp_gcfg_ikev2_mobike_rt_check_retry_interval_msec; // (msecs)
extern int rhp_gcfg_ikev2_mobike_rt_check_max_retries;
extern int rhp_gcfg_ikev2_mobike_resp_keep_alive_interval; // (secs)
extern int rhp_gcfg_ikev2_mobike_resp_keep_alive_retry_interval; // (secs)
extern int rhp_gcfg_ikev2_mobike_resp_keep_alive_max_retries;
extern int rhp_gcfg_ikev2_mobike_rt_check_on_nat_t_port;
extern int rhp_gcfg_ikev2_mobike_dynamically_disable_nat_t;
extern int rhp_gcfg_ikev2_mobike_watch_nat_gw_reflexive_addr;
extern int rhp_gcfg_ikev2_mobike_init_rt_check_hold_time;
extern int rhp_gcfg_ikev2_mobike_init_rt_check_hold_ka_interval;
extern int rhp_gcfg_ikev2_mobike_init_rt_check_hold_ka_max_retries;

extern int rhp_gcfg_http_clt_get_max_rx_length;
extern int rhp_gcfg_http_clt_get_max_reqs;

extern int rhp_gcfg_ikev2_hash_url_http_timeout; // (secs)

extern int rhp_gcfg_ikev2_rx_if_strictly_check;

extern int rhp_gcfg_ikev2_dont_tx_general_err_resp;

extern int rhp_gcfg_esp_rx_udp_encap_only_when_exec_nat_t;

extern int rhp_gcfg_log_pending_records_max;

extern int rhp_gcfg_ikev2_hash_url_max_len;

extern int rhp_gcfg_dns_resolve_max_tasks;

extern int rhp_gcfg_ikev2_rx_peer_realm_id_req;

extern int rhp_gcfg_forward_critical_pkt_preferentially;

extern int rhp_gcfg_flood_pkts_if_no_accesspoint_exists;

extern int rhp_gcfg_dont_search_cfg_peers_for_realm_id;

extern int rhp_gcfg_peek_rx_packet_size;

extern int rhp_gcfg_ipv6_disabled;
extern int rhp_gcfg_ikev2_mobike_additional_addr_check_dnat;


extern int rhp_gcfg_ipv6_nd_resolve_timeout;
extern int rhp_gcfg_ipv6_nd_resolve_retry_times;

extern int rhp_gcfg_arp_reprobe_min_interval; // secs
extern int rhp_gcfg_ipv6_nd_reprobe_min_interval; // secs

extern int rhp_gcfg_ipv6_rlm_lladdr_first_wait_secs; // secs
extern int rhp_gcfg_ipv6_rlm_lladdr_dad_first_interval; // secs
extern int rhp_gcfg_ipv6_rlm_lladdr_dad_retry_interval;  // secs
extern int rhp_gcfg_ipv6_rlm_lladdr_dad_retransmits; // times
extern int rhp_gcfg_ipv6_rlm_lladdr_max_gen_retries; // times

extern int rhp_gcfg_proxy_ipv6_nd_cache;

extern int rhp_gcfg_bridge_static_cache_unsolicited_nd_adv_num;

extern int rhp_gcfg_ipv6_drop_router_adv;

extern int rhp_gcfg_ikev2_enable_fragmentation;
extern int rhp_gcfg_ikev2_max_fragments;
extern int rhp_gcfg_ikev2_frag_max_packet_size; // bytes
extern int rhp_gcfg_ikev2_frag_size_v4; // bytes
extern int rhp_gcfg_ikev2_frag_size_v6; // bytes
extern int rhp_gcfg_ikev2_frag_use_min_size;
extern int rhp_gcfg_ikev2_frag_min_size_v4; // bytes
extern int rhp_gcfg_ikev2_frag_min_size_v6; // bytes
extern int rhp_gcfg_ikev2_frag_rx_timeout; // secs

extern int rhp_gcfg_esp_dont_match_selectors;

extern int rhp_gcfg_v4_icmp_is_critical;

extern int rhp_gcfg_v6_deny_remote_client_nd_pkts_over_ipip;

extern int rhp_gcfg_v6_allow_ra_tss_type;

extern int rhp_gcfg_udp_encap_for_v6_after_rx_rockhopper_also;
extern int rhp_gcfg_enable_childsa_outb_after_n_secs;

extern int rhp_gcfg_eap_client_use_ikev2_random_addr_id;

extern int rhp_gcfg_ikev2_sess_resume_init_enabled;
extern int rhp_gcfg_ikev2_sess_resume_resp_enabled;
extern int rhp_gcfg_ikev2_sess_resume_key_update_interval; // secs
extern int rhp_gcfg_ikev2_sess_resume_key_update_interval_min; // secs
extern int rhp_gcfg_ikev2_sess_resume_ticket_lifetime; // secs
extern int rhp_gcfg_ikev2_sess_resume_resp_tkt_revocation;
extern double rhp_gcfg_ikev2_sess_resume_tkt_rvk_bfltr_false_ratio;
extern int rhp_gcfg_ikev2_sess_resume_tkt_rvk_bfltr_max_tkts;

extern int rhp_gcfg_ikev2_tx_new_req_retry_interval; // secs

extern int rhp_gcfg_ikev2_rekey_ikesa_delete_deferred_init;
extern int rhp_gcfg_ikev2_rekey_ikesa_delete_deferred_resp;

extern int rhp_gcfg_ikev2_rekey_childsa_delete_deferred_init;
extern int rhp_gcfg_ikev2_rekey_childsa_delete_deferred_resp;

extern int rhp_gcfg_def_eap_server_if_only_single_rlm_defined;

extern int rhp_gcfg_ikev2_max_create_child_sa_failure;

extern int rhp_gcfg_ikev_other_auth_disabled_if_null_auth_enabled;

extern int rhp_gcfg_disabled_trace_write_for_misc_events;

extern int rhp_gcfg_v6_allow_auto_tss_type;

extern int rhp_gcfg_ikev2_itnl_net_convergence_interval;
extern int rhp_gcfg_ikev2_itnl_net_convergence_max_wait_times;

extern int rhp_gcfg_bridge_tx_garp_for_vpn_peers;
extern int rhp_gcfg_bridge_tx_unsol_nd_adv_for_vpn_peers;

extern int rhp_gcfg_ikev2_cfg_rmt_clt_req_old_addr;

extern int rhp_gcfg_ikev2_cfg_v6_internal_addr_def_prefix_len;

extern int rhp_gcfg_radius_min_pkt_len;
extern int rhp_gcfg_radius_max_pkt_len;
extern int rhp_gcfg_radius_mschapv2_eap_identity_not_protected;
extern int rhp_gcfg_radius_secondary_server_hold_time;

extern int rhp_gcfg_radius_acct_max_sessions;
extern int rhp_gcfg_radius_acct_max_queued_tx_messages;

extern int rhp_gcfg_ip_routing_disabled;

extern int rhp_gcfg_ip_routing_cache_max_entries_v4;
extern int rhp_gcfg_ip_routing_cache_max_entries_v6;
extern int rhp_gcfg_ip_routing_cache_hold_time;
extern int rhp_gcfg_ip_routing_cache_aging_interval;
extern int rhp_gcfg_ip_routing_cache_hash_size;

extern int rhp_gcfg_ip_routing_max_entries_v4;
extern int rhp_gcfg_ip_routing_max_entries_v6;
extern int rhp_gcfg_ip_routing_hash_bucket_init_size;
extern int rhp_gcfg_ip_routing_hash_bucket_max_size;
extern double rhp_gcfg_ip_routing_hash_bucket_max_occupancy_ratio;

extern int rhp_gcfg_mac_cache_hash_size;
extern int rhp_gcfg_neigh_cache_hash_size;

extern int rhp_gcfg_nhrp_default_hop_count;
extern int rhp_gcfg_nhrp_cache_hold_time; // (secs)
extern int rhp_gcfg_nhrp_cache_update_interval; // (secs)
extern int rhp_gcfg_nhrp_cache_update_interval_error; // (secs)

extern int rhp_gcfg_nhrp_cache_hash_size;
extern int rhp_gcfg_nhrp_cache_aging_interval;

extern int rhp_gcfg_nhrp_cache_max_entries;

extern int rhp_gcfg_nhrp_max_request_sessions;
extern int rhp_gcfg_nhrp_registration_req_tx_margin_time;
extern int rhp_gcfg_nhrp_request_session_timeout;
extern int rhp_gcfg_nhrp_request_session_timeout_max;
extern int rhp_gcfg_nhrp_request_session_retry_times;

extern int rhp_gcfg_internal_net_max_peer_addrs;

extern int rhp_gcfg_nhrp_traffic_indication_rate_limit; // (secs)
extern int rhp_gcfg_nhrp_traffic_indication_orig_pkt_len;
extern int rhp_gcfg_nhrp_strictly_check_addr_uniqueness;
extern int rhp_gcfg_nhrp_registration_req_cie_prefix_len;
extern int rhp_gcfg_nhrp_registration_req_cie_prefix_len_v6;
extern int rhp_gcfg_nhrp_cie_mtu;

extern int rhp_gcfg_ip_routing_cache_dst_addr_only;
extern int rhp_gcfg_ip_routing_coarse_tick_interval; // (secs)

extern int rhp_gcfg_dmvpn_vpn_conn_idle_timeout; // (secs)
extern int rhp_gcfg_dmvpn_connect_shortcut_wait_random_range; // (secs)
extern int rhp_gcfg_dmvpn_connect_shortcut_rate_limit; // (secs)
extern int rhp_gcfg_dmvpn_dont_handle_traffic_indication;
extern int rhp_gcfg_dmvpn_only_tx_resolution_rep_via_nhs;
extern int rhp_gcfg_dmvpn_tx_resolution_rep_via_nhs;

extern int rhp_gcfg_ikev2_auth_tkt_shortcut_session_key_len;
extern int rhp_gcfg_ikev2_auth_tkt_shortcut_session_key_min_len;
extern int rhp_gcfg_ikev2_auth_tkt_shortcut_session_key_max_len;
extern int rhp_gcfg_ikev2_auth_tkt_lifetime; // (secs)

extern int rhp_gcfg_packet_capture_timer_check_interval; // (secs)

extern int rhp_gcfg_ikev1_enabled;
extern int rhp_gcfg_def_ikev1_if_only_single_rlm_defined;

extern int rhp_gcfg_ikev1_nat_t_disabled;
extern int rhp_gcfg_ikev1_dpd_enabled;
extern int rhp_gcfg_ikev1_commit_bit_enabled;

extern int rhp_gcfg_ikev1_dont_tx_initial_contact;

extern int rhp_gcfg_ikev1_ikesa_lifetime_deleted;
extern int rhp_gcfg_ikev1_ipsecsa_lifetime_deleted;
extern int rhp_gcfg_ikev1_tx_redundant_delete_sa_mesg; // (pkts)

extern int rhp_gcfg_ikev1_retx_pkts_num;

extern int rhp_gcfg_ikev1_ikesa_min_lifetime;
extern int rhp_gcfg_ikev1_ikesa_rekey_margin;
extern int rhp_gcfg_ikev1_ipsecsa_min_lifetime;
extern int rhp_gcfg_ikev1_ipsecsa_rekey_margin;
extern int rhp_gcfg_ikev1_ipsecsa_tx_responder_lifetime;
extern int rhp_gcfg_ikev1_ipsecsa_gre_strictly_match_ts;

extern int rhp_gcfg_ca_dn_ders_max_size;

extern int rhp_gcfg_check_certreq_ca_dns;
extern int rhp_gcfg_strictly_cmp_certreq_ca_dns;

extern int rhp_gcfg_ikev1_xauth_tx_error_margin; // (secs)

extern unsigned long rhp_gcfg_ikev1_mode_cfg_addr_expiry; // (secs)
extern int rhp_gcfg_ikev1_mode_cfg_tx_subnets;

extern int rhp_gcfg_ikev1_main_mode_enabled;
extern int rhp_gcfg_ikev1_aggressive_mode_enabled;

extern int rhp_gcfg_ikev1_xauth_allow_null_terminated_password;

// **************************************************


extern rhp_atomic_t rhp_dns_pxy_users;


struct _rhp_gcfg_param {
	int type;
	char* val_name;
	void* val_p;
};
typedef struct _rhp_gcfg_param	rhp_gcfg_param;

extern rhp_gcfg_param rhp_gcfg_vpn_params[];
extern rhp_gcfg_param rhp_gcfg_ikesa_params[];
extern rhp_gcfg_param rhp_gcfg_childsa_params[];



extern rhp_mutex_t rhp_cfg_lock;


struct _rhp_cfg_transform {

  char tag[4]; // "#TRS"

  struct _rhp_cfg_transform* next;

  int priority;

  u8 type;
  u16 id;
  int key_bits_len; // For ENCR
};
typedef struct _rhp_cfg_transform rhp_cfg_transform;

struct _rhp_cfg_ikesa {

	char tag[4]; // "#CIK"

  u8 protocol_id;
  rhp_cfg_transform* encr_trans_list;
  rhp_cfg_transform* prf_trans_list;
  rhp_cfg_transform* integ_trans_list;
  rhp_cfg_transform* dh_trans_list;

  unsigned long cb[4];

//  void (*dump)(struct _rhp_cfg_ikesa* cfg_ikesa);
};
typedef struct _rhp_cfg_ikesa rhp_cfg_ikesa;

struct _rhp_cfg_childsa {

	char tag[4]; // "#CCH"

  u8 protocol_id;
  rhp_cfg_transform* encr_trans_list;
  rhp_cfg_transform* integ_trans_list;
  rhp_cfg_transform* esn_trans;

  unsigned long cb[4];

//  void (*dump)(struct _rhp_cfg_childsa* cfg_childsa);
};
typedef struct _rhp_cfg_childsa rhp_cfg_childsa;



struct _rhp_cfg_ikev1_transform {

  char tag[4]; // "#TRS"

  struct _rhp_cfg_ikev1_transform* next;

  int priority;

  int enc_alg;		// P1
  int hash_alg;		// P1
  int dh_group;		// P1/P2

  int trans_id;		// P2
  int auth_alg;		// P2
  int esn;				// P2

  int key_bits_len; // For ENC
};
typedef struct _rhp_cfg_ikev1_transform rhp_cfg_ikev1_transform;

struct _rhp_cfg_ikev1_ikesa {

	char tag[4]; // "#CIK"

	rhp_cfg_ikev1_transform* trans_list;

  unsigned long cb[4];

//  void (*dump)(struct _rhp_cfg_ikev1_ikesa* cfg_ikesa);
};
typedef struct _rhp_cfg_ikev1_ikesa rhp_cfg_ikev1_ikesa;

struct _rhp_cfg_ikev1_ipsecsa {

	char tag[4]; // "#CCH"

  u8 protocol_id;
  rhp_cfg_ikev1_transform* trans_list;

  unsigned long cb[4];

//  void (*dump)(struct _rhp_cfg_ikev1_ipsecsa* cfg_ipsecsa);
};
typedef struct _rhp_cfg_ikev1_ipsecsa rhp_cfg_ikev1_ipsecsa;



struct _rhp_cert_dn;

struct _rhp_ifc_entry;

struct _rhp_cfg_if {

  char tag[4]; // "#CFI"

  struct _rhp_cfg_if* next;

  char* if_name;
  int priority;

  int advertising;

  int addr_family; // AF_INET, AF_INET6, or AF_UNSPEC(IPv4 and IPv6)
  int is_by_def_route;

#define RHP_MOBIKE_R_MAX_ADDITIONAL_ADDRS		32

// This must be >= 2 and <= RHP_MOBIKE_R_MAX_ADDITIONAL_ADDRS.
#define RHP_MOBIKE_DST_NAT_ADDRS_NUM	2
  int mobike_dnat_addrs_num_v4;
  int mobike_dnat_addrs_num_v6;
  rhp_ip_addr mobike_dnat_addr_v4[RHP_MOBIKE_DST_NAT_ADDRS_NUM];
  rhp_ip_addr mobike_dnat_addr_v6[RHP_MOBIKE_DST_NAT_ADDRS_NUM];

  struct _rhp_ifc_entry* ifc;
};
typedef struct _rhp_cfg_if  rhp_cfg_if;

struct _rhp_cfg_internal_if {

	char tag[4]; // "#CVI"

#define RHP_VIRTUAL_IF_NAME					"rhpvif"
#define RHP_VIRTUAL_IF_NAME_LEN			6	// strlen("rhpvif")
#define RHP_VIRTUAL_NULL_IF_NAME		"rhpvif_null"
#define RHP_VIRTUAL_DMY_IF_NAME			"rhpvif_dmy"
  char* if_name;

#define RHP_VIF_ADDR_STATIC			0
#define RHP_VIF_ADDR_IKEV2CFG		1
#define RHP_VIF_ADDR_DHCP				2
#define RHP_VIF_ADDR_NONE				3
  int addrs_type;
  rhp_ip_addr_list* addrs; // IPv4 address and IPv6 address

  rhp_ip_addr gw_addr; // IPv4
  rhp_ip_addr gw_addr_v6;

  rhp_ip_addr sys_def_gw_addr; // IPv4
  rhp_ip_addr sys_def_gw_addr_v6;

  int fixed_mtu;
  int default_mtu;

  struct _rhp_ifc_entry* ifc;

  char* bridge_name;
  rhp_ip_addr_list* bridge_addrs; // Maybe, more than two addresses..
  int bridge_def_mtu; // For PMTUD.

  int ikev2_config_ipv6_auto;
};
typedef struct _rhp_cfg_internal_if  rhp_cfg_internal_if;

struct _rhp_traffic_selector {

  char tag[4]; // "#TRS"

  struct _rhp_traffic_selector* next;

  unsigned long priority;

#define RHP_CFG_IKEV1_TS_IPV4_ADDR_RANGE		1000 // > 255 (sizeof(u8))
#define RHP_CFG_IKEV1_TS_IPV6_ADDR_RANGE		1001
  int ts_type; // RHP_PROTO_IKE_TS_XXX (u8)

  int ts_is_subnet;
  union {

  	rhp_ip_addr subnet;

  	struct {
      rhp_ip_addr start; // Starting address.
      rhp_ip_addr end;   // Ending address.
    } range;

    struct {
      rhp_ip_addr start; // Starting address.
      rhp_ip_addr end;   // Ending address.
    } raw;

  } addr;

  u16 start_port; // Starting port.
  u16 end_port;   // Ending port.

  u8 protocol;
  u8 for_fragmented;
  u16 reserved0;

  u8 icmp_start_type;
  u8 icmp_end_type;
  u8 icmp_start_code;
  u8 icmp_end_code;
};
typedef struct _rhp_traffic_selector rhp_traffic_selector;

extern int rhp_cfg_is_any_traffic_selector(rhp_traffic_selector* cfg_ts);


struct _rhp_cfg_peer {

  char tag[4]; // "#CFP"

  struct _rhp_cfg_peer* next;

  rhp_ikev2_id id;

  char* primary_tx_if_name;
  char* secondary_tx_if_name;

  rhp_ip_addr primary_addr;
  char* primary_addr_fqdn;
  rhp_ip_addr secondary_addr;

  rhp_ip_addr internal_addr;
  rhp_ip_addr internal_addr_v6;

  int is_access_point;

  int always_on_connection;
  u64 vpn_aoc_objid;

  int swap_tss; // 1: enable, 0: disable

  int my_tss_num;
  rhp_traffic_selector* my_tss;

  int peer_tss_num;
  rhp_traffic_selector* peer_tss;

	rhp_ip_addr mobike_additional_addr_cache;

	rhp_ip_addr ikev2_cfg_rmt_clt_old_addr_v4;
	rhp_ip_addr ikev2_cfg_rmt_clt_old_addr_v6;

	int v6_udp_encap_disabled;


#define RHP_IKEV1_INITIATOR_DISABLED					0
#define RHP_IKEV1_INITIATOR_MODE_MAIN					1
#define RHP_IKEV1_INITIATOR_MODE_AGGRESSIVE		2
  u8 ikev1_init_mode;
  u8 ikev1_commit_bit_enabled;
  u16 reserved0;
};
typedef struct _rhp_cfg_peer  rhp_cfg_peer;


struct _rhp_ext_traffic_selector {

  char tag[4]; // "#CET"

  struct _rhp_ext_traffic_selector* next;

  unsigned long priority;

  u16 ether_type;
  u8 reserved0;
  u8 reserved1;
};
typedef struct _rhp_ext_traffic_selector  rhp_ext_traffic_selector;

struct _rhp_split_dns_domain {

	char tag[4]; // "#CSD"

	struct _rhp_split_dns_domain* next;

	char* name;

  int ikev2_cfg;
};
typedef struct _rhp_split_dns_domain  rhp_split_dns_domain;

static inline void _rhp_split_dns_domain_free(rhp_split_dns_domain* domains)
{
	rhp_split_dns_domain* domain = domains;
	while( domain ){
		rhp_split_dns_domain* domain_n = domain->next;
		_rhp_free(domain->name);
		_rhp_free(domain);
		domain = domain_n;
	}
}

struct _rhp_route_map {

	char tag[4]; // "#RMP"

	struct _rhp_route_map* next;

	rhp_ip_addr dest_addr;

	rhp_ip_addr gateway_addr;
	char* tx_interface;

	unsigned int metric;

  rhp_ikev2_id gateway_peer_id;

  int ikev2_cfg;
};
typedef struct _rhp_route_map		rhp_route_map;

extern void rhp_rtmap_dump(char* label,rhp_route_map* rtmap);


struct _rhp_internal_route_map {

	char tag[4]; // "#IRT"

	struct _rhp_internal_route_map* next;

	rhp_ip_addr dest_addr;
};
typedef struct _rhp_internal_route_map		rhp_internal_route_map;

static inline void _rhp_internal_route_map_free(rhp_internal_route_map* rtmaps)
{
	rhp_internal_route_map *rtmap,*rtmap_n;

	rtmap = rtmaps;
	while( rtmap ){

		rtmap_n = rtmap->next;

		_rhp_free(rtmap);

		rtmap = rtmap_n;
	}
}

struct _rhp_internal_address_pool {

	char tag[4]; // "#IAP"

	struct _rhp_internal_address_pool* next;

	rhp_ip_addr start;
	rhp_ip_addr end;

	rhp_ip_addr last;

	rhp_ip_addr netmask;
};
typedef struct _rhp_internal_address_pool	rhp_internal_address_pool;

struct _rhp_internal_peer_address {

	char tag[4]; // "#IPA"

	struct _rhp_internal_peer_address* next;

  rhp_ikev2_id peer_id;

	rhp_ip_addr peer_address;
};
typedef struct _rhp_internal_peer_address	rhp_internal_peer_address;


struct _rhp_vpn_realm {

  char tag[4]; // "#VRM"

  struct _rhp_vpn_realm* next;

  rhp_mutex_t lock;

  rhp_atomic_t refcnt;
  rhp_atomic_t is_active;

  int disabled;

  time_t realm_created_time;
  time_t realm_updated_time;
  time_t sess_resume_policy_index;

// This must be less than INT_MAX and
// less than (IF_NAMESIZE(net/if.h) - strlen("rhpvif"))(Decimal).
// See rhp_misc2.h (RHP_VPN_REALM_ID_UNKNOWN and RHP_VPN_REALM_ID_MAX).
  unsigned long id;

  char* name;
  char* mode_label;
  char* description;
  int is_not_ready;

#define RHP_VPN_ENCAP_ETHERIP		1
#define RHP_VPN_ENCAP_IPIP			2
#define RHP_VPN_ENCAP_GRE				4
#define RHP_VPN_ENCAP_ANY				(RHP_VPN_ENCAP_ETHERIP | RHP_VPN_ENCAP_IPIP | RHP_VPN_ENCAP_GRE)
  int encap_mode_c;

  rhp_cfg_if* my_interfaces;
  int my_interfaces_any;
  int my_interface_use_def_route;


  rhp_cfg_internal_if* internal_ifc;

  int (*get_internal_if_subnet_addr)(struct _rhp_vpn_realm* rlm,int addr_family,rhp_ip_addr* subnet_addr_r);


  int is_access_point;
  int is_mesh_node;

  rhp_cfg_peer* peers;
  rhp_cfg_peer* access_point_peer; // Only a reference. Don't free!

  rhp_vpn_ref* access_point_peer_vpn_ref;
  void (*set_access_point)(struct _rhp_vpn_realm*rlm,struct _rhp_vpn* vpn);

  struct {

    rhp_ikev2_id my_id;
    int my_auth_method;

    int http_cert_lookup;

    int send_ca_chains;

    struct {
			int enabled;
			int method;	// RHP_PROTO_EAP_TYPE_XXX
			int ask_for_user_key;
			int user_key_cache_enabled;
			int user_key_cached;
    } eap_sup;

    int my_cert_issuer_dn_der_len;
    u8* my_cert_issuer_dn_der;

    int untrust_sub_ca_cert_issuer_dn_der_len;
    u8* untrust_sub_ca_cert_issuer_dn_der;

    int my_xauth_method; // RHP_XAUTH_P1_AUTH_XXX

  } my_auth;


#define RHP_CFG_LIFETIME_MIN_REKEY_DIFF  			30	// (secs)
#define RHP_CFG_IKESA_LIFETIME_MIN						180	// (secs)
#define RHP_CFG_CHILDSA_LIFETIME_MIN					120	// (secs)
#define RHP_CFG_LIFETIME_RANDOM_RANGE    			30	// (secs)
#define RHP_CFG_CLEANUP_DUP_SA_MARGIN					2		// (secs)
#define RHP_CFG_LIFETIME_DEFERRED_REKEY				60 	// (secs)
#define RHP_CFG_LIFETIME_DEFERRED_REKEY_RANDOM_RANGE	10 	// (secs)
  struct {

    unsigned long lifetime_larval; 			// secs
    unsigned long lifetime_eap_larval; 	// secs
    unsigned long lifetime_soft; 		// secs
    unsigned long lifetime_hard; 		// secs
    unsigned long lifetime_deleted; // secs

    int resp_not_rekeying;

    int nat_t;

    int use_nat_t_port;

    int delete_no_childsa;

#define RHP_CFG_NAT_T_KEEP_ALIVE_MIN_INTERVAL  	5
    unsigned long nat_t_keep_alive_interval; 	// secs

#define RHP_CFG_KEEP_ALIVE_MIN_INTERVAL  	10
#define RHP_CFG_KEEP_ALIVE_RANDOM_RANGE		10
    unsigned long keep_alive_interval; 	// secs

    int send_realm_id; // For initiator. This is ignored when EAP is configured.

    int send_responder_id; // Tx IDr in AUTH req. (For initiator)

  } ikesa;


#define RHP_CFG_VPN_CONN_LIFE_TIME_MIN  			30	// (secs)
  unsigned long vpn_conn_lifetime; // (secs)  0: Disabled.

#define RHP_CFG_VPN_CONN_IDLE_TIME_MIN  			30	// (secs)
  unsigned long vpn_conn_idle_timeout; // (secs)  0: Disabled.


  struct {

    unsigned long lifetime_larval; 	// secs
    unsigned long lifetime_soft; 		// secs
    unsigned long lifetime_hard; 		// secs
    unsigned long lifetime_deleted; // secs

    int anti_replay;
    int anti_replay_win_size;

    int out_of_order_drop;

#define RHP_CFG_TFC_PADDING_MAX_SIZE		64
#define RHP_CFG_TFC_PADDING_MIN_SIZE		16
    int tfc_padding;
    int tfc_padding_max_size;

#define RHP_CFG_DUMMY_TRAFFIC_RATE_PER_PACKETS		10
#define RHP_CFG_DUMMY_TRAFFIC_INTERVAL						30
#define RHP_CFG_DUMMY_TRAFFIC_MIN_INTERVAL				5
    int dummy_traffic;
    unsigned long dummy_traffic_rate_per_packets;
    unsigned long dummy_traffic_interval; // secs

    int pfs;

    int resp_not_rekeying;

    int apply_ts_to_eoip; // 0 : disabled , 1 : enabled.
    int apply_ts_to_gre; // 0 : disabled , 1 : enabled.

    int exec_pmtud;

    rhp_ip_addr v6_aux_lladdr;

    int v6_enable_udp_encap_after_rx;

    int v6_udp_encap_disabled;

    int exact_match_ts;

    int dont_fwd_pkts_between_vpn_conns;

    int gre_auto_gen_ts;
    int gre_ts_allow_nat_reflexive_addr;

  } childsa;

  struct {

  	int etss_num;
  	rhp_ext_traffic_selector* etss;

  } ext_tss;

  struct{

  	int static_internal_server_addr;
  	rhp_ip_addr internal_server_addr;

  	int static_internal_server_addr_v6;
  	rhp_ip_addr internal_server_addr_v6;

  	rhp_split_dns_domain* domains;

  } split_dns;


  rhp_route_map* route_maps;
  rhp_ip_addr ext_internal_gateway_addr;
  rhp_ip_addr ext_internal_gateway_addr_v6;


#define RHP_IKEV2_CONFIG_SERVER		1
#define RHP_IKEV2_CONFIG_CLIENT		2
	int config_service;

  struct {

  	rhp_internal_route_map* rt_maps;
  	rhp_internal_route_map* rt_maps_v6;

  	int addr_hold_hours;
  	rhp_internal_address_pool* addr_pools;
  	rhp_internal_peer_address* peer_addrs;
  	rhp_internal_address_pool* addr_pools_v6;
  	rhp_internal_peer_address* peer_addrs_v6;

  	rhp_ip_addr dns_server_addr;
  	rhp_ip_addr dns_server_addr_v6;
  	rhp_split_dns_domain* domains;

  	rhp_ip_addr gw_addr;
  	rhp_ip_addr gw_addr_v6;

  	rhp_ip_addr wins_server_addr;
  	rhp_ip_addr wins_server_addr_v6;

#define RHP_IKEV2_CFG_NARROW_TS_I_NON_ROCKHOPPER		0
#define RHP_IKEV2_CFG_NARROW_TS_I_ALL								1
#define RHP_IKEV2_CFG_NARROW_TS_I_DONT							2
#define RHP_IKEV2_CFG_NARROW_TS_I_UNDEF							3
  	int narrow_ts_i; 	// 0 : Do narrow Traffic Selectors(TSi). However, if a remote peer is Rockhopper, don't narrow.
  										// 1 : Do narrow Traffic Selectors(TSi) for all remote peers.
  										// 2 : Don't narrow Traffic Selectors(TSi).

  	rhp_ip_addr internal_netmask;
  	rhp_ip_addr internal_netmask_v6;

  	int allow_v6_ra; // Add TSs for IPv6 router adv/sol. (For Windows)

  	int reject_non_clients;

  	int dont_fwd_pkts_between_clients;
  	int dont_fwd_pkts_between_clients_except_v6_auto;

  	int disable_non_ip;

  	int reject_client_ts;

  	int allow_ipv6_autoconf;

  } config_server;


  struct {

  	int enabled;

  	int resp_routability_check;

  	unsigned long resp_ka_interval; // (secs), Keep-Alive
  	unsigned long resp_ka_interval_null_auth; // (secs)
#define RHP_IKEV2_CFG_MOBIKE_KA_RANGE		60 	// (secs)
  	unsigned long resp_ka_retx_interval; 		// (secs)
  	int resp_ka_retx_retries;

  	unsigned long init_hold_time;
  	unsigned long init_hold_ka_interval; // (secs)
  	int init_hold_ka_max_retries;

  	int init_cache_additional_addr;

  } mobike;


  int psk_for_peers;
  int rsa_sig_for_peers;
  int eap_for_peers;
  int null_auth_for_peers;

  int (*null_auth_configured)(struct _rhp_vpn_realm* rlm);


  struct {

#define RHP_NHRP_SERVICE_NONE			0
#define RHP_NHRP_SERVICE_SERVER 	1
#define RHP_NHRP_SERVICE_CLIENT 	2
		u8 service;
		u8 dmvpn_enabled;
		u8 auth_tkt_enabled; // Spoke-to-Spoke Auth
		u8 reserved0;

		int key_len;
		u8* key;

  } nhrp;


  struct {

  	int key_enabled;
  	u32 key;

  } gre;


  struct {

  	u8 dpd_enabled;
  	u8 reserved0;
  	u16 reserved1;

    unsigned long ikesa_lifetime_deleted; 	// secs
    unsigned long ipsecsa_lifetime_deleted; // secs

  } v1;

  rhp_cfg_if* (*get_my_interface)(struct _rhp_vpn_realm* rlm,char* if_name,int addr_family);
  rhp_cfg_if* (*get_next_my_interface)(struct _rhp_vpn_realm* rlm,
  		char* cur_if_name,rhp_ip_addr* peer_addr);
  rhp_cfg_if* (*get_next_my_interface_def_route)(struct _rhp_vpn_realm* rlm,
  		char* cur_if_name,rhp_ip_addr* peer_addr);

  // ret: 1 (checked_if_index >= current_if_index)
  int (*my_interface_cmp_priority)(struct _rhp_vpn_realm* rlm,
  		int current_if_index,int checked_if_index,rhp_ip_addr* peer_addr);

  rhp_cfg_internal_if* (*get_internal_if)(struct _rhp_vpn_realm* rlm);

  rhp_cfg_peer* (*get_peer_by_primary_addr)(struct _rhp_vpn_realm* rlm,rhp_ip_addr* addr);
  rhp_cfg_peer* (*get_peer_by_id)(struct _rhp_vpn_realm* rlm,rhp_ikev2_id* peer_id);
  rhp_cfg_peer* (*dup_peer_by_id)(struct _rhp_vpn_realm* rlm,
  		rhp_ikev2_id* peer_id,rhp_ip_addr* peer_ip);


  int (*enum_route_map_by_peerid)(struct _rhp_vpn_realm* rlm,rhp_ikev2_id* peer_id,
  		int (*callback)(struct _rhp_vpn_realm* rlm,rhp_ikev2_id* peer_id,
  				rhp_route_map* rtmap,void* ctx),void* ctx);

  int (*enum_route_map_by_ikev2_cfg)(struct _rhp_vpn_realm* rlm,
  		int (*callback)(struct _rhp_vpn_realm* rlm,rhp_route_map* rtmap,void* ctx),void* ctx);

  int (*is_configued_peer)(struct _rhp_vpn_realm* rlm,rhp_ikev2_id* peer_id);


  int (*rtmap_put_ikev2_cfg)(struct _rhp_vpn_realm* rlm,rhp_ip_addr* dest_addr,
  			rhp_ip_addr* gateway_addr,char* tx_interface);
  void (*rtmap_delete)(struct _rhp_vpn_realm*rlm,rhp_route_map* rtmap);

  void (*destructor)(struct _rhp_vpn_realm* rlm);

  unsigned long apdx[4];

  struct {

  	struct {

  		u64 rx_from_vpn_pkts;
  		u64 rx_from_vpn_err_pkts;

  		u64 rx_from_vpn_ipip_pkts;
  		u64 rx_from_vpn_ipip_subnet_broadcast_pkts;
  		u64 rx_from_vpn_ipip_same_subnet_pkts;
  		u64 rx_from_vpn_ipip_fwd_nexthop_pkts;
  		u64 rx_from_vpn_ipip_fwd_thisnode_pkts;
  		u64 rx_from_vpn_ipip_fwd_err_pkts;
  		u64 rx_from_vpn_ipip_broadcast_pkts; // Multicast included.

  		u64 tx_to_vpn_flooding_pkts;
  		u64 tx_from_vpn_flooding_pkts;

  	} bridge;

  	struct {

  		u64 rx_esp_packets;
  		u64 rx_esp_err_packets;
  		u64 rx_esp_anti_replay_err_packets;
  		u64 rx_esp_decrypt_err_packets;
  		u64 tx_esp_ts_err_packets;
  		u64 tx_esp_integ_err_packets;
  		u64 tx_esp_invalid_packets;
  		u64 rx_esp_unknown_proto_packets;
  		u64 rx_esp_no_childsa_err_packets;

  		u64 tx_esp_packets;
  		u64 tx_esp_err_packets;
  		u64 tx_esp_encrypt_err_packets;
  		u64 rx_esp_ts_err_packets;
  		u64 rx_esp_integ_err_packets;
  		u64 rx_esp_invalid_packets;
  		u64 tx_esp_no_childsa_err_packets;

  		u64 rx_esp_src_changed_packets;

  	} esp;

  } statistics;
};
typedef struct _rhp_vpn_realm rhp_vpn_realm;


struct _rhp_res_sa_proposal {

  u8 number; // Proposal #
  u8 protocol_id; // Protocol ID
  u8 spi_len; // SPI Size
  u8 spi[RHP_PROTO_SPI_MAX_SIZE];

  u16 reserved0;
  u16 encr_id;
  int encr_key_bits;
  int encr_priority;

  u16 prf_id;
  int prf_priority;

  u16 integ_id;
  int integ_priority;

  u16 dhgrp_id;
  int dhgrp_priority;

  u16 esn; // 0 : disable , 1 : enable
  int esn_priority;

  int pfs; // 0 : disable , 1 : enable
};
typedef struct _rhp_res_sa_proposal rhp_res_sa_proposal;

extern void rhp_cfg_dump_res_sa_prop(rhp_res_sa_proposal* res_prop);


struct _rhp_res_ikev1_sa_proposal {

  u8 number; // Proposal #
  u8 protocol_id; // Protocol ID
  u8 spi_len; // SPI Size
  u8 trans_number;
  u8 spi[RHP_PROTO_SPI_MAX_SIZE];

  int cfg_priority;

  int enc_alg;							// P1
  int hash_alg;							// P1
  int auth_method;					// P1
  int dh_group;							// P1/P2
  unsigned long life_time;	// P1/P2

  int xauth_method;		// P1

  unsigned long life_bytes; // P2
  int trans_id; 	// P2
  int encap_mode;	// P2
  int auth_alg;		// P2
  int esn;				// P2

  int key_bits_len; // For ENCR

  unsigned long rx_life_time;	// P2
};
typedef struct _rhp_res_ikev1_sa_proposal rhp_res_ikev1_sa_proposal;

extern void rhp_cfg_dump_res_ikev1_sa_prop(rhp_res_ikev1_sa_proposal* res_prop);


extern int rhp_cfg_init();

extern int rhp_cfg_global_load(char* conf_xml_path);
extern int rhp_cfg_init_load(char* conf_xml_path);

extern int rhp_realms_setup_vif();
extern int rhp_realms_setup_route(unsigned long rlm_id);
extern int rhp_realms_flush_route(unsigned long rlm_id);


extern int rhp_cfg_ipc_handle(rhp_ipcmsg *ipcmsg);

extern int rhp_cfg_transform_str2id(int trans_type,char* trans_name);
extern int rhp_cfg_transform_type_str2id(char* trans_name);

extern rhp_vpn_realm* rhp_realm_alloc();

extern int rhp_realm_put(rhp_vpn_realm* rlm);
extern rhp_vpn_realm* rhp_realm_get(unsigned long id);
extern void rhp_realm_delete(rhp_vpn_realm* rlm);
extern rhp_vpn_realm* rhp_realm_delete_by_id(unsigned long rlm_id);


extern int rhp_realm_enum(unsigned long rlm_id,int (*callback)(rhp_vpn_realm* rlm,void* ctx),void* ctx);
extern rhp_vpn_realm* rhp_realm_search_by_split_dns(int addr_family,char* domain_name);


extern void rhp_realm_hold(rhp_vpn_realm* rlm);
extern void rhp_realm_unhold(rhp_vpn_realm* rlm);


extern rhp_cfg_ikesa* rhp_cfg_parse_ikesa_security(xmlNodePtr node);
extern rhp_cfg_childsa* rhp_cfg_parse_childsa_security(xmlNodePtr node);
extern void rhp_cfg_free_ikesa_security(rhp_cfg_ikesa* cfg_ikesa);
extern void rhp_cfg_free_childsa_security(rhp_cfg_childsa* cfg_childsa);
extern int rhp_cfg_add_transform_list(xmlNodePtr node,int trans_type,rhp_cfg_transform** trans_list_head);
extern rhp_cfg_ikesa* rhp_cfg_get_ikesa_security();
extern rhp_cfg_childsa* rhp_cfg_get_childsa_security();
extern rhp_cfg_ikesa* rhp_cfg_default_ikesa_security();
extern rhp_cfg_childsa* rhp_cfg_default_childsa_security();

extern rhp_cfg_ikev1_ipsecsa* rhp_cfg_parse_ikev1_ipsecsa_security(xmlNodePtr node);
extern rhp_cfg_ikev1_ikesa* rhp_cfg_parse_ikev1_ikesa_security(xmlNodePtr node);
extern void rhp_cfg_free_ikev1_ikesa_security(rhp_cfg_ikev1_ikesa* cfg_ikesa);
extern void rhp_cfg_free_ikev1_ipsecsa_security(rhp_cfg_ikev1_ipsecsa* cfg_ipsecsa);
extern rhp_cfg_ikev1_ikesa* rhp_cfg_ikev1_get_ikesa_security();
extern rhp_cfg_ikev1_ipsecsa* rhp_cfg_ikev1_get_ipsecsa_security();
extern rhp_cfg_ikev1_ikesa* rhp_cfg_ikev1_default_ikesa_security();
extern rhp_cfg_ikev1_ipsecsa* rhp_cfg_ikev1_default_ipsecsa_security();


struct _rhp_ikev2_proposal;
struct _rhp_res_sa_proposal;
extern int rhp_cfg_match_ikesa_proposal(struct _rhp_ikev2_proposal* prop,struct _rhp_res_sa_proposal* res_prop);
extern int rhp_cfg_match_childsa_proposal(struct _rhp_ikev2_proposal* prop,struct _rhp_res_sa_proposal* res_prop,int pfs);

struct _rhp_ikev1_proposal;
struct _rhp_res_sa_ikev1_proposal;
extern int rhp_cfg_match_ikev1_ikesa_proposal(struct _rhp_ikev1_proposal* prop,struct _rhp_res_ikev1_sa_proposal* res_prop);
extern int rhp_cfg_match_ikev1_ipsecsa_proposal(struct _rhp_ikev1_proposal* prop,struct _rhp_res_ikev1_sa_proposal* res_prop);


extern int rhp_cfg_parse_ikev2_id(xmlNodePtr node,const xmlChar* id_type_attrname,const xmlChar* id_attrname,rhp_ikev2_id* id);


extern void rhp_cfg_realm_free_ext_traffic_selectors(rhp_ext_traffic_selector* etss);
extern int rhp_cfg_realm_dup_ext_traffic_selectors(rhp_vpn_realm* rlm,rhp_ext_traffic_selector** etss_r);

extern int rhp_cfg_get_all_ca_pubkey_digests(u8** digests_r,int* digests_len_r,int* digest_len_r);

extern int rhp_cfg_get_all_ca_dn_ders(u8** ders_r,int* ders_len_r,int* ders_num_r);


extern void rhp_realm_free_peer_cfg(rhp_cfg_peer* peers);
extern void rhp_realm_free(rhp_vpn_realm* rlm);

struct _rhp_ikev2_traffic_selector;
extern void rhp_cfg_traffic_selectors_dump_impl(char* label,rhp_traffic_selector* cfg_tss,struct _rhp_ikev2_traffic_selector* tss,int only_head);
extern void rhp_cfg_traffic_selectors_dump(char* label,rhp_traffic_selector* cfg_tss,struct _rhp_ikev2_traffic_selector* tss);

extern void rhp_realm_rtmap_free(rhp_route_map* rtmap);

extern void rhp_realm_setup_ifc(rhp_vpn_realm* rlm,struct _rhp_ifc_entry* ifc,
		int is_def_route,int def_route_addr_family);

extern int rhp_realm_open_ifc_socket(struct _rhp_ifc_entry* ifc,int retried);
extern void rhp_realm_close_ifc_socket_if_no_users(struct _rhp_ifc_entry* ifc);

extern int rhp_realm_cfg_svr_narrow_ts_i(rhp_vpn_realm* rlm,struct _rhp_vpn* vpn);

extern rhp_vpn_realm* rhp_realm_get_def_ikev1(rhp_ikev2_id* peer_id,rhp_ip_addr* peer_addr);



struct _rhp_vpn_realm_disabled {

	struct _rhp_vpn_realm_disabled* next;

	unsigned long id;
  char* name;
  char* mode_label;
  char* description;

  time_t created_time;
  time_t updated_time;
};
typedef struct _rhp_vpn_realm_disabled rhp_vpn_realm_disabled;

extern int rhp_realm_disabled_exists(unsigned long rlm_id);
extern int rhp_realm_disabled_put(unsigned long rlm_id,char* name,char* mode_label,char* description,time_t created_time,time_t updated_time);
extern int rhp_realm_disabled_delete(unsigned long rlm_id);
extern int rhp_realm_disabled_enum(unsigned long rlm_id,
		int (*callback)(rhp_vpn_realm_disabled* rlm_disabled,void* ctx),void* ctx);



struct _rhp_cfg_peer_acl {

  u8 tag[4]; // '#PAC'

  struct _rhp_cfg_peer_acl* next;

  int priority;
  rhp_ip_addr addr;

  int any;

  unsigned long vpn_realm_id;
};
typedef struct _rhp_cfg_peer_acl  rhp_cfg_peer_acl;

extern void rhp_cfg_free_peer_acls(rhp_cfg_peer_acl* cfg_peer_acls_head);

extern int rhp_cfg_check_peer_acls(struct _rhp_packet* pkt);
extern rhp_cfg_peer_acl* rhp_cfg_peer_acl_list;


struct _rhp_cfg_admin_service {

  u8 tag[4]; // '#ASV'

  struct _rhp_cfg_admin_service* next;

  unsigned long id;

  rhp_ip_addr addr;
  rhp_ip_addr addr_v6;
  rhp_cfg_peer_acl* client_acls;

#define RHP_CFG_ADMIN_SERVICE_PROTO_HTTP	0
#define RHP_CFG_ADMIN_SERVICE_PROTO_HTTPS	1
  int protocol;
  unsigned long keep_alive_interval;
  int max_conns;

  char* root_dir;

  int nobody_allowed_tmp;
  int nobody_auto_reconnect_tmp;
};
typedef struct _rhp_cfg_admin_service	rhp_cfg_admin_service;

struct _rhp_http_listen;

extern rhp_cfg_admin_service* rhp_cfg_admin_services;
extern struct _rhp_http_listen* rhp_cfg_admin_services_listen_sks;

extern void rhp_cfg_free_admin_services(rhp_cfg_admin_service* cfg_admin_services_head);


struct _rhp_cfg_firewall {

  u8 tag[4]; // '#RFW'

  struct _rhp_cfg_firewall* next;

  int priority;

  char* traffic;
  char* action;
  char* interface;
  char* filter_pos;
};
typedef struct _rhp_cfg_firewall	rhp_cfg_firewall;

extern rhp_cfg_firewall* rhp_cfg_firewall_rules;

extern void rhp_cfg_free_firewall_rules(rhp_cfg_firewall* cfg_firewall_head);
extern int rhp_cfg_apply_firewall_rules(rhp_cfg_firewall* cfg_firewall_head,
		rhp_cfg_admin_service* cfg_admin_service_head);



struct _rhp_gcfg_hash_url_http_svr {

	u8 tag[4]; // '#HRH'

	struct _rhp_gcfg_hash_url_http_svr* next;

#define RHP_G_HASH_URL_HTTP_SUFFIX	1
#define RHP_G_HASH_URL_HTTP_EXACT		2
	int type;

	char* server_name;
};
typedef struct _rhp_gcfg_hash_url_http_svr rhp_gcfg_hash_url_http_svr;

struct _rhp_gcfg_hash_url {

	u8 tag[4]; // '#HRL'

	int init_enabled;
	int resp_enabled;

	rhp_gcfg_hash_url_http_svr* http_svrs_head;
	rhp_gcfg_hash_url_http_svr* http_svrs_tail;
};
typedef struct _rhp_gcfg_hash_url	rhp_gcfg_hash_url;

extern rhp_mutex_t rhp_gcfg_hash_url_lock;
extern rhp_gcfg_hash_url* rhp_global_cfg_hash_url;

extern void rhp_gcfg_free_hash_url(rhp_gcfg_hash_url* cfg_hash_url);
extern int rhp_gcfg_hash_url_enabled(int side); // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
extern int rhp_gcfg_hash_url_match_server_name(char* server_name);


//
// - EAP-RADIUS config (Main process)
//
//  Referenced with rhp_eap_radius_cfg_lock acquired.
//
extern rhp_mutex_t rhp_eap_radius_cfg_lock;

struct _rhp_eap_radius_gcfg {

	u8 tag[4]; // '#RDC'

	u8 enabled;
	u8 tx_nas_id_as_ikev2_id_enabled;
	u8 tx_calling_station_id_enabled;
	u8 tx_nas_port_type_enabled;
	u8 rx_session_timeout_enabled;
	u8 rx_term_action_enabled;
	u8 rx_framed_mtu_enabled;
	u8 rx_framed_ipv4_enabled;
	u8 rx_framed_ipv6_enabled;
	u8 rx_ms_primary_dns_server_v4_enabled;
	u8 rx_dns_server_v6_enabled;
	u8 rx_route_v6_info_enabled;
	u8 rx_ms_primary_nbns_server_v4_enabled; // (WINS)
	u8 rx_tunnel_private_group_id_enabled;
	u8 rx_tunnel_client_auth_id_enabled;
	u8 rx_vpn_realm_id_attr_type; // (> 0)
	u8 rx_vpn_realm_role_attr_type; // (> 0)
	u8 rx_user_index_attr_type; // (> 0)
	u8 rx_internal_dns_v4_attr_type; // (> 0)
	u8 rx_internal_dns_v6_attr_type; // (> 0)
	u8 rx_internal_domain_names_attr_type; // (> 0)
	u8 rx_internal_rt_maps_v4_attr_type; // (> 0)
	u8 rx_internal_rt_maps_v6_attr_type; // (> 0)
	u8 rx_internal_gw_v4_attr_type; // (> 0)
	u8 rx_internal_gw_v6_attr_type; // (> 0)
	u8 rx_internal_addr_ipv4; // (> 0)
	u8 rx_internal_addr_ipv6; // (> 0)
	u8 rx_common_priv_attr; // (> 0)
	u8 reserved1;
	u8 reserved2;

	rhp_ip_addr server_addr_port;
	char* server_fqdn;

	rhp_ip_addr server_secondary_addr_port;
	char* server_secondary_fqdn;

	rhp_ip_addr nas_addr;

	rhp_ip_addr nas_secondary_addr;

	char* nas_id;
	char* connect_info;
	int tx_framed_mtu; // (bytes)

#define RHP_RADIUS_RETRANSMIT_INTERVAL_DEF	3
	time_t retransmit_interval; // (secs)

#define RHP_RADIUS_RETRANSMIT_TIMES_DEF		3
	int retransmit_times; // (times)

#define RHP_RADIUS_MAX_SESSIONS_DEF				256
	int max_sessions;
};
typedef struct _rhp_eap_radius_gcfg rhp_eap_radius_gcfg;

struct _rhp_radius_acct_gcfg {

	u8 tag[4]; // '#RDA'

	u8 enabled;
	u8 tx_nas_id_as_ikev2_id_enabled;
	u8 reserved0;
	u8 reserved1;

	rhp_ip_addr server_addr_port;
	char* server_fqdn;

	rhp_ip_addr server_secondary_addr_port;
	char* server_secondary_fqdn;

	rhp_ip_addr nas_addr;

	rhp_ip_addr nas_secondary_addr;

	char* nas_id;
	char* connect_info;

	time_t retransmit_interval; // (secs)

	int retransmit_times; // (times)
};
typedef struct _rhp_radius_acct_gcfg rhp_radius_acct_gcfg;

extern rhp_eap_radius_gcfg* rhp_gcfg_eap_radius;
extern rhp_radius_acct_gcfg* rhp_gcfg_radius_acct;

extern rhp_eap_radius_gcfg* rhp_gcfg_alloc_eap_radius();
extern void rhp_gcfg_free_eap_radius(rhp_eap_radius_gcfg* cfg_eap_radius);

extern rhp_radius_acct_gcfg* rhp_gcfg_alloc_radius_acct();
extern void rhp_gcfg_free_radius_acct(rhp_radius_acct_gcfg* cfg_radius_acct);

extern int rhp_eap_radius_rx_attr_enabled(u8 rx_attr_type,unsigned long vendor_id,u8 vendor_type);



extern rhp_vpn_realm* rhp_cfg_parse_realm(xmlNodePtr realm_node);
extern rhp_cfg_admin_service* rhp_cfg_parse_admin_service(xmlNodePtr node);
extern rhp_cfg_peer_acl* rhp_cfg_parse_peer_acl(xmlNodePtr node);
extern rhp_cfg_firewall* rhp_cfg_parse_firewall_rule(xmlNodePtr node);
extern rhp_gcfg_hash_url* rhp_gcfg_parse_hash_url(xmlNodePtr node);
extern int rhp_gcfg_parse_eap_radius(xmlNodePtr node,rhp_eap_radius_gcfg* cfg_eap_radius);
extern int rhp_gcfg_parse_radius_acct(xmlNodePtr node,rhp_radius_acct_gcfg* cfg_radius_acct);


//
// This structure is also used for EAP-MSCHAPv2 to store a
// user's password.
//
struct _rhp_auth_psk  {

  u8 tag[4]; // "#APK"

  struct _rhp_auth_psk* next;

  int prf_method; // RHP_PROTO_IKE_TRANSFORM_ID_PRF_XXX

  int hashed_key_len;
  u8* hashed_key;

  unsigned char* key;
};
typedef struct _rhp_auth_psk  rhp_auth_psk; // PEM file


struct _rhp_crypto_prf;

struct _rhp_auth_admin_info {

  u8 tag[4]; // "#ADI"

  struct _rhp_auth_admin_info* next_list;

  unsigned char* id;
  int is_nobody;

  int prf_method; // RHP_PROTO_IKE_TRANSFORM_ID_PRF_XXX
  struct _rhp_crypto_prf* prf;

  int hashed_key_len;
  u8* hashed_key;
  char* hashed_key_base64;

  unsigned long vpn_realm_id;
};
typedef struct _rhp_auth_admin_info  rhp_auth_admin_info;

extern rhp_auth_admin_info* rhp_auth_admin_get(char* admin_id,unsigned int admin_id_len);

extern int rhp_auth_admin_replace_key(rhp_auth_admin_info* admin_info,char* new_key);



struct _rhp_auth_role {

  u8 tag[4]; // "#ARL"

  struct _rhp_auth_role* next;

#define RHP_ROLE_TYPE_FQDN                  	1
#define RHP_ROLE_TYPE_EMAIL                 	2
#define RHP_ROLE_TYPE_SUBJECT		        			3
#define RHP_ROLE_TYPE_SUBJECTALTNAME_FQDN   	4
#define RHP_ROLE_TYPE_SUBJECTALTNAME_EMAIL  	5
#define RHP_ROLE_TYPE_EAP_PREFIX_SEARCH				6
#define RHP_ROLE_TYPE_EAP_SUFFIX_SEARCH				7
#define RHP_ROLE_TYPE_ANY											8
#define RHP_ROLE_TYPE_RADIUS_ATTRIBUTE				9
  int match_type;

  char* string;
  struct _rhp_cert_dn* cert_dn;
};
typedef struct _rhp_auth_role  rhp_auth_role;



extern int rhp_cfg_parse_eap_id(xmlNodePtr node,const xmlChar* id_type_attrname,const xmlChar* id_attrname,rhp_eap_id* id);
extern int rhp_cfg_parse_eap_method(xmlNodePtr node,const xmlChar* attrname,int* method_r);


struct _rhp_auth_peer {

  u8 tag[4]; // "#APR"

  struct _rhp_auth_peer* next;

#define RHP_PEER_ID_TYPE_IKEV2						1
#define RHP_PEER_ID_TYPE_EAP							2
#define RHP_PEER_ID_TYPE_RADIUS_RX_ROLE		3
  int peer_id_type;

  union {
  	rhp_ikev2_id ikev2;
  	rhp_eap_id eap;
  } peer_id;

  rhp_auth_psk* peer_psks;
};
typedef struct _rhp_auth_peer  rhp_auth_peer;


struct _rhp_cert_dn;

struct _rhp_cert_url {

	struct _rhp_cert_url* next;

	int is_my_cert;

	char* cert_dn_str;
	char* url;

	struct _rhp_cert_dn* cert_dn;
};
typedef struct _rhp_cert_url	rhp_cert_url;


struct _rhp_my_auth {

  u8 tag[4]; // "#MAU"

  int auth_method; // RHP_PROTO_IKE_AUTHMETHOD_XXX
  								 // RHP_PROTO_IKE_AUTHMETHOD_XAUTH_INIT_XXX or RHP_PROTO_IKE_AUTHMETHOD_HYBRID_INIT_XXX

  rhp_ikev2_id my_id;

  // If this is enabled, auth_method may be RHP_PROTO_IKE_AUTHMETHOD_NONE.
  rhp_eap_id my_eap_sup_id; // EAP Peer(supplicant) ID

  struct {

  	int user_key_cache_enabled;

		int cached_user_id_len;
  	u8* cached_user_id;
		int cached_user_key_len;
  	u8* cached_user_key;

  } eap_sup;

  rhp_auth_psk* my_psks;

  rhp_cert_store* cert_store;
  rhp_cert_store* cert_store_tmp;

  rhp_cert_url* cert_urls;


  // Just a placeholder for a uploaded RSA priv_key file.
  //
  //  When a password string on <form/> and <input/> tags is submitted,
  //  Firefox shows a prompt dialog to save it into the browser's cache.
  //  As a workaround, it is submitted on a config_update_my_key_info
  //  message.
  //
  unsigned char* rsa_priv_key_pw;
};
typedef struct _rhp_my_auth	rhp_my_auth;


struct _rhp_vpn_auth_realm {

  char tag[4]; // "#VRA"

  struct _rhp_vpn_auth_realm* next;

  rhp_mutex_t lock;

  rhp_atomic_t refcnt;
  rhp_atomic_t is_active;

  int disabled;

  unsigned long id;

  char* name;

  rhp_auth_role* roles; // rlm->roles is immutable. No lock needed.

  rhp_auth_peer* peers;

  rhp_my_auth* my_auth;

  char* my_cert_store_password;
  int accept_expired_cert;

  struct {

		int role; // RHP_EAP_XXX
		int method; // RHP_PROTO_EAP_TYPE_XXX

		int eap_vendor; // EAP_VENDOR_XXX, default: 0(EAP_VENDOR_IETF)

		int is_default_eap_server;

  } eap;

  struct {

		int role; // RHP_EAP_XXX
		int method; // RHP_PROTO_EAP_TYPE_XXX

#define RHP_XAUTH_P1_AUTH_NONE						0
#define RHP_XAUTH_P1_AUTH_PSK							1
#define RHP_XAUTH_P1_AUTH_RSASIG					2
#define RHP_XAUTH_P1_AUTH_HYBRID_RSASIG		3
		int p1_auth_method;

  } xauth;

  int psk_for_peers;
  int rsa_sig_for_peers;
  int eap_for_peers;
  int null_auth_for_peers;

  u8 auth_tkt_enabled;
  u8 reserved0;
  u16 reserved1;

  int just_updated;

  // id_type : RHP_PEER_ID_TYPE_XXX
  rhp_auth_peer* (*get_peer_by_id)(struct _rhp_vpn_auth_realm* auth_rlm,int id_type,void* id);

  // id_type : RHP_PEER_ID_TYPE_XXX
  int (*delete_auth_peer)(struct _rhp_vpn_auth_realm* auth_rlm,int id_type,void* id);

  int (*replace_auth_peer)(struct _rhp_vpn_auth_realm* auth_rlm,rhp_auth_peer* auth_peer);

  void (*destructor)(struct _rhp_vpn_auth_realm* rlm);

  unsigned long apdx[4];
};
typedef struct _rhp_vpn_auth_realm  rhp_vpn_auth_realm;


extern int rhp_auth_init_load(char* conf_xml_path);

extern rhp_vpn_auth_realm* rhp_auth_realm_get(unsigned long id);
extern rhp_vpn_auth_realm* rhp_auth_realm_get_by_role(rhp_ikev2_id* my_id,int peer_id_type,void* peer_id,rhp_cert* cert,
			int also_any,unsigned long peer_notified_realm_id);
extern rhp_vpn_auth_realm* rhp_auth_realm_get_def_eap_server(rhp_ikev2_id* my_id,unsigned long peer_notified_realm_id);
extern void rhp_auth_realm_delete(rhp_vpn_auth_realm* auth_rlm);
extern rhp_vpn_auth_realm* rhp_auth_realm_delete_by_id(unsigned long rlm_id);
extern int rhp_auth_realm_put(rhp_vpn_auth_realm* auth_rlm);

extern void rhp_auth_realm_hold(rhp_vpn_auth_realm* auth_rlm);
extern void rhp_auth_realm_unhold(rhp_vpn_auth_realm* auth_rlm);

extern int rhp_auth_policy_permitted_if_entry(unsigned long rlm_id,rhp_if_entry* if_ent);
extern int rhp_auth_policy_permitted_addr(unsigned long rlm_id,rhp_ip_addr* addr,unsigned long* metric_base,unsigned long* matric_max);

extern rhp_vpn_auth_realm* rhp_auth_parse_auth_realm(xmlNodePtr realm_node);
extern rhp_my_auth* rhp_auth_parse_auth_my_auth(xmlNodePtr node,unsigned long rlm_id);
extern rhp_auth_peer* rhp_auth_parse_auth_peer(xmlNodePtr node);
extern rhp_auth_admin_info* rhp_auth_parse_admin(xmlNodePtr node,void* ctx,char** admin_hashed_key);
extern rhp_cert_url* rhp_auth_parse_realm_cert_urls(xmlNodePtr node,unsigned long rlm_id);

extern int rhp_auth_setup_cert_urls(rhp_cert_store* cert_store,rhp_my_auth* my_auth,unsigned long rlm_id);
extern void rhp_auth_free_cert_urls(rhp_cert_url* cert_url_lst_head);

extern int rhp_auth_admin_delete(char* id);
extern int rhp_auth_admin_replace(rhp_auth_admin_info* new_admin_info);

extern void rhp_auth_free_auth_peer(rhp_auth_peer* cfg_auth_peer);
extern void rhp_auth_free_my_auth(rhp_my_auth* my_auth);


extern int rhp_auth_sup_is_enabled(unsigned long rlm_id,
		int* eap_method_r,int* ask_for_user_key_r,int* user_key_cache_enabled_r);

extern void rhp_auth_eap_cfg_reset(rhp_vpn_auth_realm* auth_rlm,rhp_my_auth* my_auth);


extern int rhp_cfg_save_config(char* config_file_path,void* cfg_doc);


extern int rhp_auth_realm_disabled_exists(unsigned long rlm_id);
extern int rhp_auth_realm_disabled_put(unsigned long rlm_id);
extern int rhp_auth_realm_disabled_delete(unsigned long rlm_id);


extern void rhp_auth_radius_get_settings(
		u8* priv_attr_type_realm_id_r,
		u8* priv_attr_type_realm_role_r,
		u8* priv_attr_type_common_r,
		int* tunnel_private_group_id_attr_enabled_r);

extern void rhp_auth_radius_set_settings(
		u8* priv_attr_type_realm_id_p,
		u8* priv_attr_type_realm_role_p,
		u8* priv_attr_type_common_p,
		int* tunnel_private_group_id_attr_enabled_p);





extern char* rhp_packet_capture_file_path;


#endif // _RHP_CONFIG_H
