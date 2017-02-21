/*

	Copyright (C) 2015-2016 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.

	You can redistribute and/or modify this software under the
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifndef _RHP_NHRP_H_
#define _RHP_NHRP_H_

struct _rhp_nhrp_mesg;

extern rhp_mutex_t rhp_nhrp_lock;


struct _rhp_nhrp_cie {

	u8 tag[4]; // '#CIE'

	struct _rhp_nhrp_cie* next;

	u8 code;
	u8 prefix_len;
	u16 reserved0;
	u8 (*get_code)(struct _rhp_nhrp_cie* nhrp_cie);

	u8 (*get_prefix_len)(struct _rhp_nhrp_cie* nhrp_cie);
	int (*set_prefix_len)(struct _rhp_nhrp_cie* nhrp_cie,u8 prefix_len);

	u16 mtu;
	u16 hold_time;
	u16 (*get_mtu)(struct _rhp_nhrp_cie* nhrp_cie);
	int (*set_mtu)(struct _rhp_nhrp_cie* nhrp_cie,u16 mtu);
	u16 (*get_hold_time)(struct _rhp_nhrp_cie* nhrp_cie);
	int (*set_hold_time)(struct _rhp_nhrp_cie* nhrp_cie,u16 hold_time);

	rhp_ip_addr clt_nbma_addr;
	int (*set_clt_nbma_addr)(struct _rhp_nhrp_cie* nhrp_cie,int addr_family,u8* clt_nbma_addr);
	int (*get_clt_nbma_addr)(struct _rhp_nhrp_cie* nhrp_cie,rhp_ip_addr* clt_nbma_addr_r);

	rhp_ip_addr clt_protocol_addr;
	int (*set_clt_protocol_addr)(struct _rhp_nhrp_cie* nhrp_cie,int addr_family,u8* clt_protocol_addr);
	int (*get_clt_protocol_addr)(struct _rhp_nhrp_cie* nhrp_cie,rhp_ip_addr* clt_protocol_addr_r);

	rhp_proto_nhrp_clt_info_entry* nhrp_cieh;
};
typedef struct _rhp_nhrp_cie	rhp_nhrp_cie;


struct _rhp_nhrp_ext {

	u8 tag[4]; // '#NHT'

	struct _rhp_nhrp_ext* next;

	int type;
	int (*get_type)(struct _rhp_nhrp_ext* nhrp_ext);

	u8 compulsory_flag;
	u8 reserved0;
	u16 reserved1;
	int (*is_compulsory)(struct _rhp_nhrp_ext* nhrp_ext);

	rhp_nhrp_cie* cie_list_head;
	rhp_nhrp_cie* cie_list_tail;
	int (*add_cie)(struct _rhp_nhrp_ext* nhrp_ext,rhp_nhrp_cie* nhrp_cie);
	int (*enum_cie)(struct _rhp_nhrp_ext* nhrp_ext,
			int (*callback)(struct _rhp_nhrp_ext* nhrp_ext,rhp_nhrp_cie* nhrp_cie,void* ctx),void* ctx);

	//
	// [CAUTION]
	//  In case of Cisco's auth ext, cast it to rhp_proto_nhrp_cisco_auth_ext.
	//
	rhp_proto_nhrp_ext* nhrp_exth;

	int ext_auth_key_len;
	u8* ext_auth_key;
};
typedef struct _rhp_nhrp_ext	rhp_nhrp_ext;


struct _rhp_nhrp_m_mandatory {

	u8 tag[4]; // '#NHM'

	u32 request_id;
	u32 (*get_request_id)(struct _rhp_nhrp_mesg* nhrp_mesg);

	int dont_update_req_id;
	void (*dont_update_request_id)(struct _rhp_nhrp_mesg* nhrp_mesg,int flag);

	u16 flags;
	u16 reserved0;
	int (*set_flags)(struct _rhp_nhrp_mesg* nhrp_mesg,u16 flag_bits); // flag_bit: RHP_PROTO_NHRP_XXX_FLAG_YYY
	u16 (*get_flags)(struct _rhp_nhrp_mesg* nhrp_mesg);

	rhp_ip_addr src_nbma_addr;
	int (*set_src_nbma_addr)(struct _rhp_nhrp_mesg* nhrp_mesg,int addr_family,u8* src_nbma_addr);
	int (*get_src_nbma_addr)(struct _rhp_nhrp_mesg* nhrp_mesg,rhp_ip_addr* src_nbma_addr_r);

	rhp_ip_addr src_protocol_addr;
	int (*set_src_protocol_addr)(struct _rhp_nhrp_mesg* nhrp_mesg,int addr_family,u8* src_protocol_addr);
	int (*get_src_protocol_addr)(struct _rhp_nhrp_mesg* nhrp_mesg,rhp_ip_addr* src_protocol_addr_r);

	rhp_ip_addr dst_protocol_addr;
	int (*set_dst_protocol_addr)(struct _rhp_nhrp_mesg* nhrp_mesg,int addr_family,u8* dst_protocol_addr);
	int (*get_dst_protocol_addr)(struct _rhp_nhrp_mesg* nhrp_mesg,rhp_ip_addr* dst_protocol_addr_r);


	rhp_nhrp_cie* cie_list_head;
	rhp_nhrp_cie* cie_list_tail;
	int (*add_cie)(struct _rhp_nhrp_mesg* nhrp_mesg,rhp_nhrp_cie* nhrp_cie);
	int (*enum_cie)(struct _rhp_nhrp_mesg* nhrp_mesg,
			int (*callback)(struct _rhp_nhrp_mesg* nhrp_mesg,rhp_nhrp_cie* nhrp_cie,void* ctx),void* ctx);

	rhp_proto_nhrp_mandatory* nhrp_mandatoryh;
};
typedef struct _rhp_nhrp_m_mandatory	rhp_nhrp_m_mandatory;


struct _rhp_nhrp_m_error_indication {

	u8 tag[4]; // '#NHE'

	u16 error_code;
	u16 reserved0;
	void (*set_error_code)(struct _rhp_nhrp_mesg* nhrp_mesg,u16 error_code);
	u16 (*get_error_code)(struct _rhp_nhrp_mesg* nhrp_mesg);


	int error_org_mesg_len;
	u8* error_org_mesg;
	u8* (*get_error_org_mesg)(struct _rhp_nhrp_mesg* nhrp_mesg,int* error_org_mesg_len_r);
	int (*set_error_org_mesg)(struct _rhp_nhrp_mesg* nhrp_mesg,int error_org_mesg_len,u8* error_org_mesg);


	rhp_ip_addr src_nbma_addr;
	int (*set_src_nbma_addr)(struct _rhp_nhrp_mesg* nhrp_mesg,int addr_family,u8* src_nbma_addr);
	int (*get_src_nbma_addr)(struct _rhp_nhrp_mesg* nhrp_mesg,rhp_ip_addr* src_nbma_addr_r);

	rhp_ip_addr src_protocol_addr;
	int (*set_src_protocol_addr)(struct _rhp_nhrp_mesg* nhrp_mesg,int addr_family,u8* src_protocol_addr);
	int (*get_src_protocol_addr)(struct _rhp_nhrp_mesg* nhrp_mesg,rhp_ip_addr* src_protocol_addr_r);

	rhp_ip_addr dst_protocol_addr;
	int (*set_dst_protocol_addr)(struct _rhp_nhrp_mesg* nhrp_mesg,int addr_family,u8* dst_protocol_addr);
	int (*get_dst_protocol_addr)(struct _rhp_nhrp_mesg* nhrp_mesg,rhp_ip_addr* dst_protocol_addr_r);

	rhp_proto_nhrp_error* nhrp_errorh;
};
typedef struct _rhp_nhrp_m_error_indication	rhp_nhrp_m_error_indication;


struct _rhp_nhrp_m_traffic_indication {

	u8 tag[4]; // '#NHT'

	u16 traffic_code;
	u16 reserved0;
	void (*set_traffic_code)(struct _rhp_nhrp_mesg* nhrp_mesg,u16 traffic_code);
	u16 (*get_traffic_code)(struct _rhp_nhrp_mesg* nhrp_mesg);


	int traffic_org_mesg_len;
	u8* traffic_org_mesg;
	u8* (*get_traffic_org_mesg)(struct _rhp_nhrp_mesg* nhrp_mesg,int* traffic_org_mesg_len_r);
	int (*set_traffic_org_mesg)(struct _rhp_nhrp_mesg* nhrp_mesg,int traffic_org_mesg_len,u8* traffic_org_mesg);

	int (*get_org_mesg_addrs)(struct _rhp_nhrp_mesg* nhrp_mesg,
				rhp_ip_addr* org_src_addr_r,rhp_ip_addr* org_dst_addr_r);


	rhp_ip_addr src_nbma_addr;
	int (*set_src_nbma_addr)(struct _rhp_nhrp_mesg* nhrp_mesg,int addr_family,u8* src_nbma_addr);
	int (*get_src_nbma_addr)(struct _rhp_nhrp_mesg* nhrp_mesg,rhp_ip_addr* src_nbma_addr_r);

	rhp_ip_addr src_protocol_addr;
	int (*set_src_protocol_addr)(struct _rhp_nhrp_mesg* nhrp_mesg,int addr_family,u8* src_protocol_addr);
	int (*get_src_protocol_addr)(struct _rhp_nhrp_mesg* nhrp_mesg,rhp_ip_addr* src_protocol_addr_r);

	rhp_ip_addr dst_protocol_addr;
	int (*set_dst_protocol_addr)(struct _rhp_nhrp_mesg* nhrp_mesg,int addr_family,u8* dst_protocol_addr);
	int (*get_dst_protocol_addr)(struct _rhp_nhrp_mesg* nhrp_mesg,rhp_ip_addr* dst_protocol_addr_r);


	rhp_proto_nhrp_traffic_indication* nhrp_traffich;
};
typedef struct _rhp_nhrp_m_traffic_indication	rhp_nhrp_m_traffic_indication;


struct _rhp_nhrp_mesg {

	u8 tag[4]; // '#NHR'

	struct _rhp_nhrp_mesg* next;

  rhp_atomic_t refcnt;

	//
	// f_xxx: For fixed_header.
	// m_xxx: For mandatory_header.
	//

	u16 f_addr_family;
	u8 f_packet_type;
	u8 f_hop_count;
	// Return: Network Byte Order, RHP_PROTO_NHRP_ADDR_FAMILY_XXX
	u16 (*get_addr_family)(struct _rhp_nhrp_mesg* nhrp_mesg);
	u8 (*get_packet_type)(struct _rhp_nhrp_mesg* nhrp_mesg);


	u8 exec_dec_hop_count;
	u8 rx_hop_count;
	u16 reserved1;
	void (*dec_hop_count)(struct _rhp_nhrp_mesg* nhrp_mesg);


	union {
		u8* raw;
		rhp_nhrp_m_mandatory* mandatory;
		rhp_nhrp_m_error_indication* error;
		rhp_nhrp_m_traffic_indication* traffic;
	} m;


	rhp_nhrp_ext* ext_list_head;
	rhp_nhrp_ext* ext_list_tail;
	int (*add_extension)(struct _rhp_nhrp_mesg* nhrp_mesg,rhp_nhrp_ext* nhrp_ext);
	int (*enum_extension)(struct _rhp_nhrp_mesg* nhrp_mesg,
			int (*callback)(struct _rhp_nhrp_mesg* nhrp_mesg,rhp_nhrp_ext* nhrp_ext,void* ctx),void* ctx);
	rhp_nhrp_ext* (*get_extension)(struct _rhp_nhrp_mesg* nhrp_mesg,int type);
	rhp_nhrp_ext* (*remove_extension)(struct _rhp_nhrp_mesg* nhrp_mesg,int type);

	int (*ext_auth_check_key)(struct _rhp_nhrp_mesg* nhrp_mesg,int key_len,u8* key);


  int (*serialize)(struct _rhp_nhrp_mesg* nhrp_mesg,rhp_vpn* tx_vpn,int max_mesg_len,
  		rhp_packet** pkt_r);


  rhp_ip_addr rx_nbma_src_addr;
  int (*get_rx_nbma_src_addr)(struct _rhp_nhrp_mesg* nhrp_mesg,rhp_ip_addr* rx_nbma_src_addr_r);

  rhp_ip_addr rx_nbma_dst_addr;
  int (*get_rx_nbma_dst_addr)(struct _rhp_nhrp_mesg* nhrp_mesg,rhp_ip_addr* rx_nbma_dst_addr_r);


  rhp_packet_ref* rx_pkt_ref;
	rhp_proto_nhrp* nhrph;

  rhp_packet_ref* tx_pkt_ref;

  rhp_vpn_ref* rx_vpn_ref;
  rhp_vpn_ref* tx_vpn_ref;

  rhp_ip_addr resolution_rep_dst_network;
  rhp_ip_addr resolution_rep_my_itnl_addr;
};
typedef struct _rhp_nhrp_mesg	rhp_nhrp_mesg;


extern rhp_nhrp_mesg* rhp_nhrp_mesg_alloc(
		u16 f_addr_family, // Network Byte Order, RHP_PROTO_NHRP_ADDR_FAMILY_XXX
		u8 f_packet_type);
extern rhp_nhrp_mesg* rhp_nhrp_mesg_dup(rhp_nhrp_mesg* nhrp_mesg);

extern rhp_nhrp_cie* rhp_nhrp_cie_alloc(u8 code);
extern void rhp_nhrp_cie_free(rhp_nhrp_cie* nhrp_cie);

extern rhp_nhrp_ext* rhp_nhrp_ext_alloc(int type,int compulsory_flag);
extern void rhp_nhrp_ext_free(rhp_nhrp_ext* nhrp_ext);

extern rhp_nhrp_mesg* rhp_nhrp_mesg_new_tx(
		u16 f_addr_family, // Network Byte Order, RHP_PROTO_NHRP_ADDR_FAMILY_XXX
		u8 f_packet_type);
extern int rhp_nhrp_mesg_new_rx(rhp_packet* rx_pkt,rhp_nhrp_mesg** nhrp_mesg_r);

extern void rhp_nhrp_mesg_hold(rhp_nhrp_mesg* nhrp_mesg);
extern void rhp_nhrp_mesg_unhold(rhp_nhrp_mesg* nhrp_mesg);

// For NHC
extern int rhp_nhrp_tx_registration_req(rhp_vpn* tx_vpn);

// For NHC
extern int rhp_nhrp_tx_purge_req(rhp_vpn* tx_vpn,rhp_ip_addr* purged_addr);

// For NHS
extern int rhp_nhrp_tx_traffic_indication(rhp_vpn* tx_vpn,rhp_packet* rx_pkt_d);
extern int rhp_nhrp_invoke_tx_traffic_indication_task(rhp_vpn* tx_vpn,rhp_packet* rx_pkt);


// For NHC
extern int rhp_nhrp_invoke_update_addr_task(rhp_vpn* vpn,int forcedly,int conv_time);

extern int rhp_rx_nhrp_from_vpn(unsigned long vpn_realm_id,rhp_vpn* rx_vpn,rhp_packet* pkt);

extern u32 rhp_nhrp_tx_next_request_id();


extern int rhp_nhrp_tx_queued_resolution_rep(rhp_vpn* tx_vpn);



struct _rhp_nhrp_cache {

	u8 tag[4]; // '#NRC'

	struct _rhp_nhrp_cache* next_hash;

	struct _rhp_nhrp_cache* pre_list;
	struct _rhp_nhrp_cache* next_list;

	rhp_ip_addr protocol_addr; 	// Internal address
	rhp_ip_addr nbma_addr;			// Public address
	rhp_ip_addr nat_addr;				// Public address (Reflexive address)

	unsigned long vpn_realm_id;

	rhp_vpn_ref* vpn_ref;
	u8 vpn_dummy_mac[6];

	u8 static_cache;
	u8 uniqueness;
	u8 authoritative; // Created by NRHP Registration from a remote peer.
	u8 reserved0;

	int rx_hold_time;
	int rx_mtu;

  time_t created_time;
};
typedef struct _rhp_nhrp_cache	rhp_nhrp_cache;

extern void rhp_nhrp_cache_dump(char* tag,rhp_nhrp_cache* nhrp_c);

//
// [CAUTION]
//
//   Caller must NOT acquire rhp_bridge_lock, rlm->lock and (rhp_ifc_entry*)v_ifc->lock.
//
extern int rhp_nhrp_cache_get(
		int addr_family,u8* protocol_addr,unsigned long ll_proto_addr_rlm_id,
		unsigned long* peer_rlm_id_r,rhp_ip_addr* peer_nbma_addr_r,u8* vpn_dummy_per_mac_r);

//
// [CAUTION]
//
//   Caller must NOT acquire rhp_bridge_lock, rlm->lock and (rhp_ifc_entry*)v_ifc->lock.
//
extern rhp_vpn* rhp_nhrp_cache_get_vpn(
		int addr_family,u8* protocol_addr,unsigned long rlm_id);

extern int rhp_nhrp_cache_get_peer_dummy_mac(
		int addr_family,u8* protocol_addr,unsigned long ll_proto_addr_rlm_id,
		u8* vpn_dummy_per_mac_r);


extern int rhp_nhrp_cache_enum(unsigned long rlm_id,int src_proto_addr_family,
		int (*callback)(rhp_nhrp_cache* nhrp_c,void* ctx),void* ctx);

extern int rhp_nhrp_cache_flush_by_vpn(rhp_vpn* vpn);
extern int rhp_nhrp_cache_invoke_flush_task(rhp_vpn* vpn);


struct _rhp_nhrp_req_session {

  unsigned char tag[4]; // '#NRS'

  struct _rhp_nhrp_req_session* next_hash;

  rhp_atomic_t refcnt;
  rhp_timer timer;

  int pkt_q_num;
  rhp_packet_q pkt_q;

  u32 tx_request_id;

  unsigned long vpn_realm_id;
  u8 vpn_uid[RHP_VPN_UNIQUE_ID_SIZE];

	int request_type; // RHP_PROTO_NHRP_PKT_XXX_REQ

  rhp_ip_addr target_protocol_ip;
  rhp_ip_addr src_nbma_ip; // For RHP_PROTO_NHRP_PKT_REGISTRATION_REQ.

  time_t created_time;

  int retries;

  int done;
};
typedef struct _rhp_nhrp_req_session rhp_nhrp_req_session;



struct _rhp_nhrp_addr_map {

	struct _rhp_nhrp_addr_map* next;

	int nbma_addr_family;
	union {
		u32 v4;
		u8 v6[16];
		u8 raw[16];
	} nbma_addr;

	int proto_addr_family;
	union {
		u32 v4;
		u8 v6[16];
		u8 raw[16];
	} proto_addr;

	int nat_nbma_addr_family;
	union {
		u32 v4;
		u8 v6[16];
		u8 raw[16];
	} nat_nbma_addr;

	int flag;
};
typedef struct _rhp_nhrp_addr_map rhp_nhrp_addr_map;

extern void rhp_nhrp_addr_map_dump(char* label,rhp_nhrp_addr_map* nhrp_addr_map);



struct _rhp_nhrp_cache_global_statistics_dont_clear {

	unsigned long cache_num;

	unsigned long request_sessions;
	unsigned long request_session_queued_num;
};
typedef struct _rhp_nhrp_cache_global_statistics_dont_clear rhp_nhrp_cache_global_statistics_dont_clear;

struct _rhp_nhrp_cache_global_statistics {

	u64 referenced;
	u64 cached_not_found;

	u64 tx_request;
	u64 tx_request_retried;
	u64 tx_request_err;

	// The followings MUST NOT be cleared by rhp_nhrp_clear_statistics()
	// and MUST be the tail of this structure.
	rhp_nhrp_cache_global_statistics_dont_clear dc;
};
typedef struct _rhp_nhrp_cache_global_statistics	rhp_nhrp_cache_global_statistics;

extern void rhp_nhrp_get_statistics(rhp_nhrp_cache_global_statistics* table);
extern void rhp_nhrp_clear_statistics();

#endif // _RHP_NHRP_H_
