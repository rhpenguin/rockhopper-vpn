/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifndef _RHP_ESP_H_
#define _RHP_ESP_H_

#include "rhp_vpn.h"

extern int rhp_esp_send(rhp_vpn* tx_vpn,rhp_packet* pkt);
extern int rhp_esp_recv(rhp_packet* pkt);

extern int rhp_esp_add_childsa_to_impl(rhp_vpn* vpn,rhp_childsa* childsa);
extern int rhp_esp_delete_childsa_to_impl(rhp_vpn* vpn,rhp_childsa* childsa);

#include "rhp_esp_impl.h"

extern void rhp_esp_send_callback(int err,rhp_packet* pkt,rhp_vpn* tx_vpn,u32 spi_outb,void* pend_ctx);
extern void rhp_esp_recv_callback(int err,rhp_packet* pkt,rhp_vpn* rx_vpn,u32 spi_inb,u8 next_header,void* pend_ctx);

extern int rhp_esp_rx_update_anti_replay(rhp_vpn* vpn,rhp_childsa* childsa,u32 rx_seq);

extern u32 rhp_esp_rx_get_esn_seqh(rhp_vpn* vpn,rhp_childsa* childsa,u32 rx_seq);

extern int rhp_esp_match_selectors_ether(rhp_ext_traffic_selector* etss_head,rhp_proto_ether* ethh);
extern int rhp_esp_match_selectors_gre(rhp_ext_traffic_selector* etss_head,rhp_proto_gre* greh,int greh_len);

extern int rhp_esp_match_selectors_ipv4(int direction/*RHP_DIR_XXX*/,rhp_childsa_ts* my_tss,rhp_childsa_ts* peer_tss,
		rhp_if_entry* my_eoip_addr,rhp_ip_addr* peer_eoip_addr,rhp_proto_ip_v4* iph,u8* end);
extern int rhp_esp_match_selectors_ipv6(int direction/*RHP_DIR_XXX*/,rhp_childsa_ts* my_tss,rhp_childsa_ts* peer_tss,
		rhp_if_entry* my_eoip_addr,rhp_ip_addr* peer_eoip_addr,rhp_proto_ip_v6* iph,u8* end,int deny_addr_rslv_pkt /* IPv6 ND */);

extern int rhp_esp_match_selectors_non_ipip(int direction,u8 protocol,
		rhp_childsa_ts* my_tss,rhp_childsa_ts* peer_tss,rhp_if_entry* my_if_addr,rhp_ip_addr* peer_addr);


extern int rhp_esp_tx_handle_pmtud_v4(rhp_packet* rx_pkt,rhp_proto_ip_v4* iph,int pmtu_cache);
extern int rhp_esp_tx_handle_pmtud_v6(rhp_packet* rx_pkt,rhp_proto_ip_v6* ip6h,int pmtu_cache);

extern int rhp_esp_tcp_mss_overwrite_v4(rhp_proto_ip_v4* iph,u8* end,int pmtu_cache);
extern int rhp_esp_tcp_mss_overwrite_v6(rhp_proto_ip_v6* ip6h,u8* end,int pmtu_cache);

extern int rhp_esp_is_v6_linklocal_icmp_pkt(rhp_packet* rx_pkt);


struct _rhp_esp_global_statistics_dont_clear {
	u64 dns_pxy_activated_v4;
	u64 dns_pxy_deactivated_v4;
	u64 dns_pxy_activated_v6;
	u64 dns_pxy_deactivated_v6;
};
typedef struct _rhp_esp_global_statistics_dont_clear	rhp_esp_global_statistics_dont_clear;

// Only error or special case's statistics(for performance).
struct _rhp_esp_global_statistics {

	u64 rx_esp_no_vpn_err_packets;
	u64 rx_esp_no_childsa_err_packets;
	u64 rx_esp_anti_replay_err_packets;
	u64 rx_esp_decrypt_err_packets;
	u64 tx_esp_ts_err_packets;
	u64 tx_esp_integ_err_packets;
	u64 tx_esp_invalid_packets;
	u64 rx_esp_unknown_proto_packets;
	u64 rx_esp_invalid_nat_t_packets;
	u64 rx_esp_err_packets;

	u64 rx_esp_src_changed_packets;

	u64 tx_esp_no_childsa_err_packets;
	u64 tx_esp_encrypt_err_packets;
	u64 rx_esp_ts_err_packets;
	u64 rx_esp_integ_err_packets;
	u64 rx_esp_invalid_packets;
	u64 tx_esp_err_packets;

	u64 dns_pxy_drop_queries;
	u64 dns_pxy_max_pending_queries_reached;
	u64 dns_pxy_gc_drop_queries;
	u64 dns_pxy_fwd_queries_to_inet;
	u64 dns_pxy_fwd_queries_to_vpn;
	u64 dns_pxy_rx_answers_from_inet;
	u64 dns_pxy_rx_answers_from_vpn;
	u64 dns_pxy_rx_unknown_txnid_answers;
	u64 dns_pxy_no_internal_nameserver_v4;
	u64 dns_pxy_no_internal_nameserver_v6;
	u64 dns_pxy_no_valid_src_addr_v4;
	u64 dns_pxy_no_valid_src_addr_v6;


	// The followings MUST NOT be cleared by rhp_esp_clear_statistics()
	// and MUST be the tail of this structure.
	rhp_esp_global_statistics_dont_clear dc;
};
typedef struct _rhp_esp_global_statistics	rhp_esp_global_statistics;

rhp_mutex_t rhp_esp_lock_statistics;
rhp_esp_global_statistics rhp_esp_statistics_global_tbl;

#define rhp_esp_g_statistics_inc(value_name) {\
	RHP_LOCK(&rhp_esp_lock_statistics);\
	(rhp_esp_statistics_global_tbl.value_name)++;\
	RHP_UNLOCK(&rhp_esp_lock_statistics);\
}\

#define rhp_esp_g_statistics_dec(value_name) {\
	RHP_LOCK(&rhp_esp_lock_statistics);\
	(rhp_esp_statistics_global_tbl.value_name)--;\
	RHP_UNLOCK(&rhp_esp_lock_statistics);\
}\


extern void rhp_esp_get_statistics(rhp_esp_global_statistics* table);
extern void rhp_esp_clear_statistics();


#endif // _RHP_ESP_H_

