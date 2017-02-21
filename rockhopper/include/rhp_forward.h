/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifndef _RHP_FORWARD_H_
#define _RHP_FORWARD_H_

/**********************

     Bridging APIs

***********************/

struct _rhp_bridge_cache {

	char tag[4]; // '#SWC'

	struct _rhp_bridge_cache* next_hash;

	struct _rhp_bridge_cache* pre_list;
	struct _rhp_bridge_cache* next_list;

	unsigned long vpn_realm_id;
	u8 dest_mac[6];

#define RHP_BRIDGE_SIDE_TUNTAP		0
#define RHP_BRIDGE_SIDE_VPN				1
	int side;

	rhp_vpn_ref* vpn_ref;

	u64 last_used_cnt;
	time_t last_checked_time;

#define RHP_BRIDGE_SCACHE_DUMMY							1
#define RHP_BRIDGE_SCACHE_IKEV2_EXCHG				2
#define RHP_BRIDGE_SCACHE_V6_DUMMY_LL_ADDR	3
#define RHP_BRIDGE_SCACHE_IKEV2_CFG					4
	int static_cache;
};
typedef struct _rhp_bridge_cache	rhp_bridge_cache;


struct _rhp_bridge_neigh_cache {

	char tag[4]; // '#SAC'

	struct _rhp_bridge_neigh_cache* next_hash_tgt_ip;
	struct _rhp_bridge_neigh_cache* next_hash_tgt_mac;

	struct _rhp_bridge_neigh_cache* pre_list;
	struct _rhp_bridge_neigh_cache* next_list;

	int addr_family; // AF_INET or AF_INET6

	unsigned long vpn_realm_id;
	u8 target_mac[6];
	rhp_ip_addr target_ip;

	int side; // RHP_BRIDGE_SIDE_XXX

	rhp_vpn_ref* vpn_ref;

	u64 last_used_cnt;
	time_t last_checked_time;

	int stale;
	time_t last_probed_time;

	int static_cache; // RHP_BRIDGE_SCACHE_XXX

	int tgt_mac_cached;

	u64 last_tx_nhrp_trf_indication_tick;
};
typedef struct _rhp_bridge_neigh_cache	rhp_bridge_neigh_cache;


struct _rhp_neigh_rslv_ctx {

  unsigned char tag[4]; // '#NER'

  struct _rhp_neigh_rslv_ctx* next_hash;

	int addr_family; // AF_INET or AF_INET6

  rhp_timer timer;

  unsigned long vpn_realm_id;

  int pkt_q_num;
  rhp_packet_q pkt_q;

  // 'rx_vpn' is just a vpn triggering an address resolution
  // process and used to retransmit the request packet.
  // Packets from other VPN connections may be queued(pkt_q)
  // at the same time.
	rhp_vpn_ref* rx_vpn_ref;
  int rx_if_index;
  rhp_ifc_entry *rx_ifc;

  u8 sender_mac[6];
  u8 target_mac[6];

  rhp_ip_addr target_ip;
  rhp_ip_addr sender_ip;

  time_t created_time;

  int retries;
};
typedef struct _rhp_neigh_rslv_ctx rhp_neigh_rslv_ctx;



struct _rhp_bridge_cache_global_statistics_dont_clear {

	struct {
		unsigned long cache_num;
	} bridge;

	struct {
		unsigned long cache_num;
		unsigned long resolving_addrs;
	} neigh;

	struct {
		u64 pxy_arp_queued_num;
	} arp;

	struct {
		u64 pxy_nd_queued_num;
	} v6_neigh;
};
typedef struct _rhp_bridge_cache_global_statistics_dont_clear rhp_bridge_cache_global_statistics_dont_clear;

struct _rhp_bridge_cache_global_statistics {

	struct {
		u64 referenced;
		u64 static_dmy_cached_found;
		u64 static_exchg_cached_found;
		u64 dyn_cached_found;
		u64 cached_not_found;
		u64 rx_to_vpn_err_pkts;
		u64 rx_from_vpn_err_pkts;
		u64 rx_from_vpn_ipip_fwd_err_pkts;
		u64 tx_from_vpn_flooding_pkts;
		u64 tx_to_vpn_flooding_pkts;
	} bridge;

	struct {
		u64 referenced;
		u64 static_dmy_cached_found;
		u64 static_exchg_cached_found;
		u64 static_v6_dmy_linklocal_cached_found;
		u64 static_ikev2_cfg_cached_found;
		u64 dyn_cached_found;
		u64 cached_not_found;
	} neigh_cache;

	struct {
		u64 pxy_arp_reply;
		u64 pxy_arp_tx_req;
		u64 pxy_arp_tx_req_retried;
		u64 pxy_arp_req_rslv_err;
		u64 pxy_arp_queued_packets;
	} arp;

	struct { // sol: solicitation
		u64 pxy_nd_tx_sol;
		u64 pxy_nd_queued_packets;
		u64 pxy_nd_tx_sol_retried;
		u64 pxy_nd_sol_rslv_err;
		u64 pxy_nd_adv;
	} v6_neigh;

	// The followings MUST NOT be cleared by rhp_bridge_clear_statistics()
	// and MUST be the tail of this structure.
	rhp_bridge_cache_global_statistics_dont_clear dc;
};
typedef struct _rhp_bridge_cache_global_statistics	rhp_bridge_cache_global_statistics;

extern void rhp_bridge_get_statistics(rhp_bridge_cache_global_statistics* table);
extern void rhp_bridge_clear_statistics();


extern int rhp_bridge_pkt_to_vpn(rhp_packet* pkt);
extern int rhp_bridge_pkt_from_vpn(rhp_packet* pkt,rhp_vpn* rx_vpn);
extern int rhp_bridge_pkt_from_vpn_ipv4_arp_rslv(unsigned long vpn_realm_id,
		rhp_vpn* rx_vpn,rhp_vpn_realm* rx_rlm,rhp_packet* tx_pkt,int dmvpn_enabled);
extern int rhp_bridge_pkt_from_vpn_ipv6_nd_rslv(unsigned long vpn_realm_id,
		rhp_vpn* rx_vpn,rhp_vpn_realm* rx_rlm,rhp_packet* tx_pkt,int dmvpn_enabled);

extern int rhp_bridge_static_cache_create(unsigned long vpn_realm_id,
		u8* peer_mac,int side,int static_by);
extern int rhp_bridge_static_cache_delete(unsigned long vpn_realm_id,u8* peer_mac);

extern int rhp_bridge_static_cache_reset_for_vpn(unsigned long rlm_id,rhp_vpn* vpn,
		u8* peer_mac,rhp_ip_addr_list* peer_addrs,int static_by);
extern int rhp_bridge_static_neigh_cache_update_for_vpn(rhp_vpn* vpn,
		rhp_ip_addr* old_peer_addr,rhp_ip_addr* new_peer_addr,u8* new_peer_mac,int static_by);


extern int rhp_bridge_cache_cleanup_by_realm_id(unsigned long vpn_realm_id);
extern int rhp_bridge_cache_cleanup_by_vpn(rhp_vpn* vpn);

// If 'vpn' is NULL , flush all cache entries.
extern void rhp_bridge_cache_flush(rhp_vpn* vpn,unsigned long rlm_id);
extern void rhp_bridge_cache_flush_by_vpn(rhp_vpn* vpn);


extern int rhp_bridge_static_neigh_cache_create(unsigned long vpn_realm_id,
		u8* peer_mac,rhp_ip_addr* peer_addr,int side,int static_by);
extern int rhp_bridge_static_neigh_cache_delete(unsigned long vpn_realm_id,
		rhp_ip_addr* peer_addr,rhp_vpn* vpn,u8* old_target_mac);


extern int rhp_bridge_enum(unsigned long rlm_id,
		int (*callback)(rhp_bridge_cache* br_c,void* ctx),void* ctx);
extern int rhp_bridge_arp_enum(unsigned long rlm_id,
		int (*callback0)(rhp_bridge_neigh_cache* br_c_n,void* ctx0),void* ctx0,
		int (*callback1)(rhp_neigh_rslv_ctx* rslv_ctx,void* ctx1),void* ctx1);
extern int rhp_bridge_nd_enum(unsigned long rlm_id,
		int (*callback0)(rhp_bridge_neigh_cache* br_c_n,void* ctx0),void* ctx0,
		int (*callback1)(rhp_neigh_rslv_ctx* rslv_ctx,void* ctx1),void* ctx1);



extern int rhp_encap_send(rhp_vpn* tx_vpn,rhp_packet* pkt);



/**********************

   IP Bridging APIs

***********************/

extern int rhp_ip_bridge_send(rhp_vpn* tx_vpn,rhp_packet* pkt);
extern int rhp_ip_bridge_send_flooding(unsigned long rlm_id,rhp_packet* pkt,rhp_vpn* rx_vpn,
		int dont_fwd_pkts_btwn_clts);
extern int rhp_ip_bridge_send_access_point(rhp_vpn_realm* tx_rlm,rhp_packet* pkt);

extern int rhp_ip_bridge_recv(rhp_packet* pkt,rhp_vpn* rx_vpn,u8 protocol);



/**********************

   GRE Bridging APIs

***********************/

extern int rhp_gre_send(rhp_vpn* tx_vpn,rhp_packet* pkt);
extern int rhp_gre_send_flooding(unsigned long rlm_id,rhp_packet* pkt,
		rhp_vpn* rx_vpn/* For split-horizon*/,int dont_fwd_pkts_btwn_clts);
extern int rhp_gre_send_access_point(rhp_vpn_realm* tx_rlm,rhp_packet* pkt);

extern int rhp_gre_check_header(rhp_proto_gre* greh);

extern int rhp_gre_recv(rhp_packet* pkt,rhp_vpn* rx_vpn);



/**********************

   IP Routing APIs

***********************/

struct _rhp_ip_routing_entry {

	u8 tag[4]; // '#IRE'

	struct _rhp_ip_routing_entry* next;

#define RHP_IP_RT_ENT_TYPE_SYSTEM		0 // by RT_NETLINK
#define RHP_IP_RT_ENT_TYPE_NHRP			1
	int type;

	rhp_rt_map_entry info;

	unsigned long out_realm_id;

	time_t created_time;

	time_t hold_time;  // NHRP

	rhp_vpn_ref* tx_vpn_ref; // NHRP

	u64 used;
};
typedef struct _rhp_ip_routing_entry	rhp_ip_routing_entry;


struct _rhp_ip_routing_bkt {

	u8 tag[4]; // '#IRB'

	struct _rhp_ip_routing_bkt* next;

	int prefix_len;
	union {
		u8 raw[16];
		u32 v4;
		u8 v6[16];
	} netmask;

	unsigned int bkt_size;
	unsigned int entries_num;

	time_t created;

	rhp_ip_routing_entry** entries_hash_tbl;

	int rehashed;
};
typedef struct _rhp_ip_routing_bkt	rhp_ip_routing_bkt;


struct _rhp_ip_route_cache {

	u8 tag[4]; // '#ICR'

	struct _rhp_ip_route_cache* next_hash;

	struct _rhp_ip_route_cache* pre_list;
	struct _rhp_ip_route_cache* next_list;

	int type; // RHP_IP_RT_ENT_TYPE_XXX

	int addr_family;

	union {
		u8 raw[16];
		u32 v4;
		u8 v6[16];
	} src_addr;

	union {
		u8 raw[16];
		u32 v4;
		u8 v6[16];
	} dst_addr;

	union {
		u8 raw[16];
		u32 v4;
		u8 v6[16];
	} nexthop_addr;

	rhp_vpn_ref* src_vpn_ref; // For RHP_IP_RT_ENT_TYPE_SYSTEM.
	rhp_vpn_ref* tx_vpn_ref; 	// For RHP_IP_RT_ENT_TYPE_NHRP.

	unsigned long gen_marker; // For RHP_IP_RT_ENT_TYPE_NHRP.

	unsigned long out_realm_id;

	time_t created;
	time_t last_checked_time;

	u64 last_tx_nhrp_trf_indication_tick;

	unsigned long used_cnt;
};
typedef struct _rhp_ip_route_cache	rhp_ip_route_cache;


extern int rhp_ip_routing_v4(u32 src_addr,u32 dst_addr,rhp_vpn* src_vpn,
		u32* next_hop_addr_r,unsigned long* out_realm_id_r,int* tx_nhrp_trf_indication_r);
extern int rhp_ip_routing_v6(u8* src_addr,u8* dst_addr,rhp_vpn* src_vpn,
		u8* next_hop_addr_r,unsigned long* out_realm_id_r,int* tx_nhrp_trf_indication_r);

extern int rhp_ip_routing_slow_v4(u32 src_addr,u32 dst_addr,
		u32* next_hop_addr_r,unsigned long* out_realm_id_r,rhp_ip_addr* dst_network_r);

//
// [CAUTION]
//
//  Before calling this function, check dst_addr is linklocal address on the same subnet.
extern int rhp_ip_routing_slow_v6(u8* src_addr,u8* dst_addr,
		u8* next_hop_addr_r,unsigned long* out_realm_id_r,rhp_ip_addr* dst_network_r);


//
// [CAUTION]
// This may internally acquire tx_vpn->lock.
//
extern int rhp_ip_routing_nhrp_v4(u32 src_addr,u32 dst_addr,unsigned long tx_realm_id,
		rhp_vpn_ref** tx_vpn_ref_r);

//
// [CAUTION]
// This may internally acquire tx_vpn->lock.
//
extern int rhp_ip_routing_nhrp_v6(u8* src_addr,u8* dst_addr,unsigned long tx_realm_id,
		rhp_vpn_ref** tx_vpn_ref_r);

extern int rhp_ip_routing_nhrp_add_cache(rhp_ip_addr* dest_network,
		rhp_ip_addr* gateway_addr,unsigned long out_realm_id,int oif_index,
		rhp_vpn* tx_vpn,time_t hold_time,int metric);

extern int rhp_ip_routing_nhrp_flush_cache_by_vpn(rhp_vpn* tx_vpn);
extern int rhp_ip_routing_nhrp_aging_cache(int* schedule_again_r);



extern void rhp_ip_routing_cache_flush(int addr_family);
extern int rhp_ip_routing_cache_flush_by_vpn(rhp_vpn* vpn);
extern int rhp_ip_routing_invoke_flush_task(rhp_vpn* vpn);

extern int rhp_ip_routing_enum(int addr_family,
		int (*callback)(int addr_family,rhp_ip_routing_bkt* ip_rt_bkt,rhp_ip_routing_entry* ip_rt_ent,void* ctx),void* ctx);

extern int rhp_ip_routing_cache_enum(int addr_family,
		int (*callback)(int addr_family,rhp_ip_route_cache* ip_rt_c,void* ctx),void* ctx);



#endif // _RHP_FORWARD_H_
