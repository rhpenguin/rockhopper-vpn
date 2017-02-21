/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifndef _RHP_CHILDSA_H_
#define _RHP_CHILDSA_H_

#include "rhp_timer.h"
#include "rhp_crypto.h"

struct rhp_packet;
struct _rhp_ikesa;
struct _rhp_ifc_entry;
struct _rhp_ikev2_traffic_selector;
struct _rhp_vpn;
struct _rhp_childsa_timers;
struct _rhp_ikev2_payload;


//
// LW and simple version of TS. Don't include pointer vals!
//
struct _rhp_childsa_ts {

  u8 tag[4]; // '#CST'

  struct _rhp_childsa_ts* next;

  u8 is_v1;

  // ts_type: IKEv2(RHP_PROTO_IKE_TS_IPVx_XXXX), id_type: IKEv1(RHP_PROTO_IKEV1_ID_IPVx_XXXX)
  u8 ts_or_id_type;

  u8 protocol;

#define RHP_CHILDSA_TS_NONE					0
#define RHP_CHILDSA_TS_IS_PENDING		1
#define RHP_CHILDSA_TS_NOT_USED			2
  u8 flag;

  u16 start_port;
  u16 end_port;

  u8 icmp_start_type;
  u8 icmp_end_type;
  u8 icmp_start_code;
  u8 icmp_end_code;

  rhp_ip_addr start_addr;
  rhp_ip_addr end_addr;

  // For IKEv1
  int v1_prefix_len;
  u8 ts_or_id_type_org;
  u8 reserved0;
  u16 reserved1;
};
typedef struct _rhp_childsa_ts rhp_childsa_ts;

extern int rhp_childsa_ts_dup(rhp_childsa_ts* from,rhp_childsa_ts* to);
extern int rhp_childsa_ts_addr_included(rhp_childsa_ts* ts,rhp_ip_addr* addr);
extern int rhp_childsa_ts_replace_addrs(rhp_childsa_ts* ts,rhp_ip_addr* start_addr,rhp_ip_addr* end_addr);

extern void rhp_childsa_ts_dump(char* tag,rhp_childsa_ts* ts);

extern int rhp_childsa_ts_cmp(rhp_childsa_ts* ts0, rhp_childsa_ts* ts1);
extern int rhp_childsa_ts_is_any(rhp_childsa_ts* ts);
extern int rhp_childsa_ts_cmp_same_or_any(rhp_childsa_ts* ts,rhp_childsa_ts* tss_head);


//
// [CAUTION]
//   Don't ref rhp_vpn obj from rhp_childsa (for IKEv1 SA mngt).
//
struct _rhp_childsa {

  unsigned char tag[4]; // "#CSA"

  struct _rhp_childsa* next_vpn_list;

  int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u32 spi_inb;
  u32 spi_outb;


  struct {
    int side;
    u8 init_spi[RHP_PROTO_IKE_SPI_SIZE];
    u8 resp_spi[RHP_PROTO_IKE_SPI_SIZE];
  } parent_ikesa;


#define RHP_CHILDSA_GEN_IKE_AUTH					1
#define RHP_CHILDSA_GEN_CREATE_CHILD_SA		2
#define RHP_CHILDSA_GEN_REKEY							3
#define RHP_CHILDSA_GEN_IKEV1							4
#define RHP_CHILDSA_GEN_IKEV1_REKEY				5
  int gen_type;
  u32 gen_message_id;

  int rekeyed_gen;


  struct _rhp_childsa_timers* timers;


#define RHP_CHILDSA_STAT_DEFAULT  				0

#define RHP_CHILDSA_STAT_LARVAL   				1
#define RHP_CHILDSA_STAT_MATURE   				2
#define RHP_CHILDSA_STAT_REKEYING 				3
#define RHP_CHILDSA_STAT_DELETE	  				4 // Start deleting Child SA and sending D payloads.
#define RHP_CHILDSA_STAT_DELETE_WAIT	  	5 // Actually destroy Child SA's resource.
#define RHP_CHILDSA_STAT_DEAD     				6

// IKEv1: Quick mode
#define RHP_IPSECSA_STAT_V1_1ST_SENT_I			100
#define RHP_IPSECSA_STAT_V1_WAIT_COMMIT_I		101 // If commit-bit enabled.
#define RHP_IPSECSA_STAT_V1_2ND_SENT_R			102
#define RHP_IPSECSA_STAT_V1_MATURE   				103
#define RHP_IPSECSA_STAT_V1_REKEYING 				104
#define RHP_IPSECSA_STAT_V1_DELETE	  			105 // Start deleting IPsec SA and sending D payloads.
#define RHP_IPSECSA_STAT_V1_DELETE_WAIT	  	106 // Actually destroy IPsec SA's resource.
#define RHP_IPSECSA_STAT_V1_DEAD     				107
  int state;


#define RHP_CHILDSA_MODE_TRANSPORT		0
#define RHP_CHILDSA_MODE_TUNNEL				1
  int ipsec_mode;

  rhp_childsa_ts* my_tss;
  rhp_childsa_ts* peer_tss;

  int (*set_traffic_selectors)(struct _rhp_childsa* childsa,
		  struct _rhp_ikev2_traffic_selector* my_tss,struct _rhp_ikev2_traffic_selector* peer_tss,struct _rhp_vpn* vpn);

  int (*set_traffic_selector_v1)(struct _rhp_childsa* childsa,
  		rhp_childsa_ts* my_csa_ts,rhp_childsa_ts* peer_csa_ts,
  		rhp_childsa_ts* my_csa_ts_gre,rhp_childsa_ts* peer_csa_ts_gre);

  union{
		rhp_res_sa_proposal v2;
		rhp_res_ikev1_sa_proposal v1;
  } prop;

  rhp_crypto_integ*  integ_inb;
  rhp_crypto_integ*  integ_outb;

  rhp_crypto_encr*   encr;


  // For rekeyed Child SA.
  rhp_crypto_dh*     rekey_dh;
  rhp_crypto_nonce*  rekey_nonce_i;
  rhp_crypto_nonce*  rekey_nonce_r;

  int collision_detected;

  int (*generate_inb_spi)(struct _rhp_childsa* childsa);
  void (*set_outb_spi)(struct _rhp_childsa* childsa,u32 spi);

  int anti_replay; 	// 0 : disable , 1 : enable
  int esn; 					// 0 : disable , 1 : enable
  int tfc_padding; 	// 0 : disable , 1 : enable
	int out_of_order_drop; // 0 : disable , 1 : enable

  struct {
		int len;
    u8* key_octets; // IKEv2: [enc_key | integ_outb_key | dec_key | integ_inb_key]
    								// IKEv1: [enc_key | integ_outb_key | padding | dec_key | integ_inb_key | padding]
  } key_material;

  struct {

    int integ_key_len;
    u8* integ_outb_key; // Pointer to key_material.key_octets
    u8* integ_inb_key; // Pointer to key_material.key_octets

    int encr_key_len;
    u8* encr_enc_key; // Pointer to key_material.key_octets
    u8* encr_dec_key; // Pointer to key_material.key_octets

  } keys;

  int (*setup_sec_params)(struct _rhp_ikesa* ikesa,struct _rhp_childsa* childsa); // For IKEv1/v2.
  int (*setup_sec_params2)(struct _rhp_ikesa* ikesa,struct _rhp_childsa* childsa); // For IKEv2.


  u64 tx_seq;

  struct {

  	union {

			struct {
				u64 t;
				u64 b;
			} esn;

			struct {
				u32 last;
			} non_esn;

		} rx_seq;

		rhp_crypto_bn* window_mask; // Window size must be less maximum positive number of signed int.

		u64 out_of_order_seq_last;

  } rx_anti_replay;

  int exec_pmtud;
  unsigned int pmtu_default;
  unsigned int pmtu_cache;

  time_t created_time;
  time_t established_time;
	time_t expire_hard;
	time_t expire_soft;

  int delete_ikesa_too;

  int gre_ts_auto_generated;

  void* impl_ctx;
  void* (*get_esp_impl_ctx)(struct _rhp_childsa* childsa);


  struct {

    int addr_family; // e.g. For a traffic selector.

    int trans_id; // RHP_PROTO_IKEV1_TF_ESP_XXX
    int auth_id; 	// RHP_PROTO_IKEV1_P2_ATTR_AUTH_XXX

    rhp_crypto_dh*     dh; // For PFS.
    rhp_crypto_nonce*  nonce_i;
    rhp_crypto_nonce*  nonce_r;

    u8 dont_rekey;
  	u8 reserved0;
    u16 reserved1;

  } v1;


  // TODO : Implement detailed statistics, if needed.
  struct {

    u64 tx_esp_packets; // Packets encrypted by this node.

    u64 rx_esp_packets; // Packets encrypted by remote peer.

  } statistics;


  u64 last_tx_esp_packets;
  u64 last_rx_esp_packets;


  void (*dump)(struct _rhp_childsa* childsa);

  void (*destructor)(struct _rhp_childsa* childsa);
};
typedef struct _rhp_childsa		rhp_childsa;

extern void rhp_childsa_set_state(rhp_childsa* childsa,int new_state);

extern int rhp_childsa_init();
extern int rhp_childsa_cleanup();

extern rhp_childsa* rhp_childsa_alloc(int side,int is_v1);
extern rhp_childsa* rhp_childsa_alloc2_i(struct _rhp_vpn* vpn,int pfs);
extern rhp_childsa* rhp_childsa_alloc2_r(rhp_res_sa_proposal* res_prop,struct _rhp_vpn_realm* rlm);

extern void rhp_childsa_destroy(struct _rhp_vpn* vpn,rhp_childsa* childsa);

extern int rhp_childsa_dup_traffic_selectors(rhp_childsa* childsa,rhp_childsa_ts** my_tss_r,rhp_childsa_ts** peer_tss_r);
extern void rhp_childsa_free_traffic_selectors(rhp_childsa_ts* my_tss,rhp_childsa_ts* peer_tss);


struct _rhp_ikev2_traffic_selector;
extern int rhp_childsa_search_traffic_selectors(rhp_traffic_selector* cfg_ts,struct _rhp_ikev2_traffic_selector* tss,
		struct _rhp_ikev2_traffic_selector** res_tss);

extern int rhp_childsa_ts_included_cfg(rhp_traffic_selector* cfg_ts,struct _rhp_ikev2_traffic_selector* ts);
extern int rhp_childsa_ts_included(rhp_childsa_ts* ts_cmp, rhp_childsa_ts* ts);

extern int rhp_childsa_check_traffic_selectors_cfg(rhp_traffic_selector* cfg_tss,struct _rhp_ikev2_traffic_selector* tss);

extern int rhp_childsa_is_any_traffic_selector(struct _rhp_ikev2_traffic_selector* ts);

extern int rhp_childsa_exact_match_traffic_selector_cfg(rhp_traffic_selector* cfg_ts,struct _rhp_ikev2_traffic_selector* ts);

extern int rhp_childsa_exact_match_traffic_selectors_cfg(int cfg_tss_num,rhp_traffic_selector* cfg_tss,
		int tss_num,struct _rhp_ikev2_traffic_selector* tss);


extern int rhp_childsa_is_ikev1_any_traffic_selector(struct _rhp_ikev2_payload* id_payload);

extern int rhp_childsa_ikev1_match_traffic_selector_cfg(
		struct _rhp_traffic_selector* cfg_ts,struct _rhp_ikev2_payload* id_payload);

extern int rhp_childsa_ikev1_match_traffic_selectors_cfg(int cfg_tss_num,struct _rhp_traffic_selector* cfg_tss,
		struct _rhp_ikev2_payload* id_payload,rhp_ip_addr* gre_addr);




extern void rhp_childsa_calc_pmtu(struct _rhp_vpn* vpn,rhp_vpn_realm* rlm,rhp_childsa* childsa);


#endif // _RHP_CHILDSA_H_

