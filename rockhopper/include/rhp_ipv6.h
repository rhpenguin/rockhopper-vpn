/*

	Copyright (C) 2009-2014 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifndef _RHP_IPV6_H_
#define _RHP_IPV6_H_

struct _rhp_ifc_entry;
struct _rhp_packet;


extern int rhp_ipv6_rlm_lladdr_start_alloc(unsigned long rlm_id,struct _rhp_ifc_entry* v_ifc,
		int try_fixed_lladdr);

extern int rhp_ipv6_rlm_lladdr_rx(struct _rhp_ifc_entry* v_ifc,struct _rhp_packet* pkt);

// Caller does NOT acquire rlm->lock and vifc->lock(rlm->internal_ifc->ifc).
extern int rhp_ipv6_rlm_lladdr_get(rhp_vpn_realm* rlm,u8* lladdr_r,u8* llmac_r);

// Caller must acquire v_ifc->lock.
extern int rhp_ipv6_v_ifc_lladdr_get(rhp_ifc_entry* v_ifc,u8* lladdr_r,u8* llmac_r);


extern int rhp_ipv6_icmp6_parse_rx_pkt(rhp_packet* pkt,
		rhp_proto_ether** eth_r,
		rhp_proto_ip_v6** ip6h_r,
		rhp_proto_icmp6** icmp6h_r);

extern int rhp_ipv6_nd_parse_adv_pkt(rhp_packet* pkt,
		rhp_proto_ether* eth,
		rhp_proto_ip_v6* ip6h,
		rhp_proto_icmp6* icmp6h,
		u8** target_lladdr_r /*Just reference. Don't free it!*/,
		u8** target_mac_r /*Just reference. Don't free it!*/ );

extern int rhp_ipv6_nd_parse_solicit_pkt(rhp_packet* pkt,
		rhp_proto_ether* eth,
		rhp_proto_ip_v6* ip6h,
		rhp_proto_icmp6* icmp6h,
		u8** target_addr_r /*Just reference. Don't free it!*/,
		u8** src_addr_r /*Just reference. Don't free it!*/,
		u8** src_mac_r /*Just reference. Don't free it!*/ );


extern rhp_packet* rhp_ipv6_nd_new_solicitation_pkt(u8* sender_mac,u8* target_ipv6,
		u8* src_ipv6,int target_lladdr);

extern rhp_packet* rhp_ipv6_nd_new_adv_pkt(u8* sender_mac,u8* target_ipv6,
		u8* src_mac,u8* dst_mac,u8* src_ipv6,u8* dst_ipv6,int solicited);

extern rhp_packet* rhp_ipv6_new_mld1_report(u8* sender_mac,
		u8* src_ipv6,u8* mc_addr_ipv6);

extern rhp_packet* rhp_ipv6_new_mld2_report(u8* sender_mac,
		u8* src_ipv6,u8* mc_addr_ipv6);


extern int rhp_ipv6_is_nd_packet(rhp_packet* rx_pkt,u8* icmp6_type_r);



#endif // _RHP_IPV6_H
