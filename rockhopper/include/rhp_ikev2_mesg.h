/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/



#ifndef _RHP_IKEV2_MESG_H_
#define _RHP_IKEV2_MESG_H_

struct _rhp_ikesa;
struct _rhp_childsa;
struct _rhp_ikev2_payload;
struct _rhp_vpn;

#include "rhp_ikev1_mesg.h"

/*********************

    IKE Message

*********************/

struct _rhp_ikev2_mesg {

  unsigned char tag[4]; // "#IKM"

  struct _rhp_ikev2_mesg* next;

  rhp_packet* tx_pkt;
  rhp_packet* rx_pkt;

  struct _rhp_ikev2_mesg*	merged_mesg; // For read-only purpose!

  rhp_proto_ike* tx_ikeh;
  int tx_mesg_len;

  rhp_atomic_t refcnt;

  int decrypted;

  u8* (*get_init_spi)(struct _rhp_ikev2_mesg* ikemesg);
  u8* (*get_resp_spi)(struct _rhp_ikev2_mesg* ikemesg);

  void (*set_init_spi)(struct _rhp_ikev2_mesg* ikemesg,u8* spi);
  void (*set_resp_spi)(struct _rhp_ikev2_mesg* ikemesg,u8* spi);

  u8 (*get_next_payload)(struct _rhp_ikev2_mesg* ikemesg);

  u8 (*get_major_ver)(struct _rhp_ikev2_mesg* ikemesg);

  u8 (*get_minor_ver)(struct _rhp_ikev2_mesg* ikemesg);

  u8 (*get_exchange_type)(struct _rhp_ikev2_mesg* ikemesg);
  void (*set_exchange_type)(struct _rhp_ikev2_mesg* ikemesg,u8 exchage_type);

  int (*is_initiator)(struct _rhp_ikev2_mesg* ikemesg);
  int (*is_responder)(struct _rhp_ikev2_mesg* ikemesg);

  int (*is_request)(struct _rhp_ikev2_mesg* ikemesg);
  int (*is_response)(struct _rhp_ikev2_mesg* ikemesg);

  u32 (*get_mesg_id)(struct _rhp_ikev2_mesg* ikemesg);
  void (*set_mesg_id)(struct _rhp_ikev2_mesg* ikemesg,u32 mesg_id);

  u32 (*get_len)(struct _rhp_ikev2_mesg* ikemesg);

  void (*dump_payloads)(struct _rhp_ikev2_mesg* ikemesg);

  int (*rx_get_init_addr)(struct _rhp_ikev2_mesg* ikemesg,rhp_ip_addr* addr);
  int (*rx_get_resp_addr)(struct _rhp_ikev2_mesg* ikemesg,rhp_ip_addr* addr);

  int (*rx_get_src_addr)(struct _rhp_ikev2_mesg* ikemesg,rhp_ip_addr* addr);
  int (*rx_get_dst_addr)(struct _rhp_ikev2_mesg* ikemesg,rhp_ip_addr* addr);

  struct _rhp_ikev2_payload* payload_list_head;
  struct _rhp_ikev2_payload* payload_list_tail;

  void (*put_payload)(struct _rhp_ikev2_mesg* ikemesg,struct _rhp_ikev2_payload* payload); // Add to list tail.
  void (*put_payload_head)(struct _rhp_ikev2_mesg* ikemesg,struct _rhp_ikev2_payload* payload); // Add to list head.

  int (*search_payloads)(struct _rhp_ikev2_mesg* ikemesg,int notify_enum_end,
  		int (*condition)(struct _rhp_ikev2_mesg* ikemesg,struct _rhp_ikev2_payload* payload,void* cond_ctx),void* cond_ctx,
  		int (*action)(struct _rhp_ikev2_mesg* ikemesg,int enum_end,struct _rhp_ikev2_payload* payload,void* cb_ctx),void* cb_ctx);

  struct _rhp_ikev2_payload* (*get_payload)(struct _rhp_ikev2_mesg* ikemesg,u8 paylod_id);

  int (*serialize)(struct _rhp_ikev2_mesg* ikemesg,struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,
  		rhp_packet** pkt_r);
  int (*serialize_v1)(struct _rhp_ikev2_mesg* ikemesg,struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,
  		rhp_packet** pkt_r);

  int (*decrypt)(rhp_packet* pkt,struct _rhp_ikesa* ikesa,u8* next_payload_r);
  int (*decrypt_v1)(rhp_packet* pkt,struct _rhp_ikesa* ikesa,
  			u8* next_payload_r,int* rx_last_blk_len_r,u8** rx_last_blk_r);

  int (*v1_commit_bit_enabled)(struct _rhp_ikev2_mesg* ikemesg);


  int ikesa_my_side;
  u8 ikesa_my_spi[RHP_PROTO_IKE_SPI_SIZE];

  struct {
    int new_ikesa_my_side;
    u8 new_ikesa_my_spi[RHP_PROTO_IKE_SPI_SIZE];
  } ikesa_rekey;

  u32 childsa_spi_inb;

  int tx_ikesa_fixed;
  int tx_from_nat_t_port;


  rhp_ip_addr* fixed_src_addr;
  rhp_ip_addr* fixed_dst_addr;
  int fixed_tx_if_index;


  unsigned long tx_flag; // mask for RHP_IKEV2_SEND_REQ_FLAG_XXXs

  void (*packet_serialized)(struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,
  		struct _rhp_ikev2_mesg* tx_ikemesg,rhp_packet* serialized_pkt);


  int for_rekey_req; 		// 1 : for Child SA Rekey or IKE SA Rekey
  int for_ikesa_rekey;	// 1 : for IKE SA Rekey
  int rekeyed_ikesa_my_side;
  u8 rekeyed_ikesa_my_spi[RHP_PROTO_IKE_SPI_SIZE];

  rhp_ip_addr rx_cp_internal_addrs[2]; // [0]: IPv4, [1]: IPv6

  int ikev2_keep_alive;

  int mobike_update_sa_addr;
  int mobike_probe_req;

  int add_nat_t_info;
  int nat_t_detected;
  int nat_t_behind_a_nat; // mask for RHP_IKESA_BEHIND_A_NAT_XXX

  int put_n_payload_err;

  void* auth_tkt_pending_req; // struct rhp_auth_tkt_pending_req (rhp_vpn.h)


  u8 is_v1;
  u8 v1_set_retrans_resp;
  u8 v1_dont_enc;
  u8 v1_start_retx_timer;
  u8 v1_p1_last_mesg;
  u8 v1_src_changed;
  u8 v1_tx_redundant_pkts; // For Delete SA mesg.
  u8 v1_ignored;

  u16 v1_dont_nat_t_port; // Network Byte order
  u16 reserved1;

  int v1_p2_iv_len;
  u8* v1_p2_rx_last_blk;

  rhp_proto_ikev1_sa_payload* v1_sa_b; // Just a reference. Don't free.


  int activated;
};
typedef struct _rhp_ikev2_mesg  rhp_ikev2_mesg;

extern rhp_ikev2_mesg* rhp_ikev2_new_mesg_tx(u8 exchange_type,u32 message_id/*For response*/,u8 flag);

extern int rhp_ikev2_new_mesg_rx(rhp_packet* pkt,rhp_proto_ike** ikeh,
		struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,rhp_ikev2_mesg** ikemesg,
		struct _rhp_ikev2_payload** n_cookie_payload,struct _rhp_ikev2_payload** nir_payload_r,rhp_ikev2_mesg** ikemesg_err_r);

extern int rhp_ikev2_check_mesg(rhp_packet* pkt);

extern int rhp_ikev2_mesg_rx_integ_check(struct _rhp_packet* pkt,struct _rhp_ikesa* ikesa);

extern void rhp_ikev2_hold_mesg(rhp_ikev2_mesg* ikemesg);
extern void rhp_ikev2_unhold_mesg(rhp_ikev2_mesg* ikemesg);

extern int rhp_ikev2_mesg_srch_cond_payload_id(rhp_ikev2_mesg* ikemesg,struct _rhp_ikev2_payload* payload,void* cond_ctx);
extern int rhp_ikev2_mesg_srch_cond_payload_ids(rhp_ikev2_mesg* ikemesg,struct _rhp_ikev2_payload* payload,void* cond_ctx);

extern int rhp_ikev2_mesg_srch_cond_n_mesg_id(rhp_ikev2_mesg* ikemesg,struct _rhp_ikev2_payload* payload,void* cond_ctx);
extern int rhp_ikev2_mesg_srch_cond_n_mesg_ids(rhp_ikev2_mesg* ikemesg,struct _rhp_ikev2_payload* payload,void* cond_ctx);

extern int rhp_ikev2_mesg_search_cond_my_verndor_id(rhp_ikev2_mesg* ikemesg,struct _rhp_ikev2_payload* payload,void* cond_ctx);

extern int rhp_ikev2_rx_verify_frag(rhp_packet* pkt,struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,
		rhp_proto_ike* ikeh,int* rx_frag_completed_r);

extern void rhp_ikev2_sync_frag_headers(rhp_packet* pkt);



struct _rhp_ikemesg_q {
	rhp_ikev2_mesg* head;
	rhp_ikev2_mesg* tail;
};
typedef struct _rhp_ikemesg_q  rhp_ikemesg_q;

extern void rhp_ikemesg_q_init(rhp_ikemesg_q* ikemesg_q);
extern void rhp_ikemesg_q_enq(rhp_ikemesg_q* ikemesg_q,rhp_ikev2_mesg* ikemesg);
extern void rhp_ikemesg_q_enq_head(rhp_ikemesg_q* ikemesg_q,rhp_ikev2_mesg* ikemesg);
extern rhp_ikev2_mesg* rhp_ikemesg_q_peek(rhp_ikemesg_q* ikemesg_q);
extern rhp_ikev2_mesg* rhp_ikemesg_q_deq(rhp_ikemesg_q* ikemesg_q);
extern int rhp_ikemesg_q_remove(rhp_ikemesg_q* ikemesg_q,rhp_ikev2_mesg* ikemesg);


/*************************************

  Security Association Payload

**************************************/

struct _rhp_ikev2_transform {

  struct _rhp_ikev2_transform* next;

  rhp_proto_ike_transform* transh;

  u8 reserved0;
  u8 type;
  u16 id;
  int key_bits_len; // For ENCR
};
typedef struct _rhp_ikev2_transform rhp_ikev2_transform;

struct _rhp_ikev2_proposal {

  struct _rhp_ikev2_proposal* next;

  rhp_proto_ike_proposal* proph;

  int trans_num;
  int (*get_trans_num)(struct _rhp_ikev2_proposal* prop);

  rhp_ikev2_transform* trans_list_head;
  rhp_ikev2_transform* trans_list_tail;
  void (*put_trans)(struct _rhp_ikev2_proposal* prop,rhp_ikev2_transform* trans); // Add to list tail.
  int (*enum_trans)(struct _rhp_ikev2_proposal* prop,
        int (*callback)(struct _rhp_ikev2_proposal* prop,rhp_ikev2_transform* trans,void* ctx),void* ctx);
  int (*alloc_and_put_trans)(struct _rhp_ikev2_proposal* prop,u8 type,u16 id,int key_bits_len);

  u8 protocol_id;
  u8 reserved0;
  u16 reserved1;
  u8 (*get_protocol_id)(struct _rhp_ikev2_proposal* prop);

  u8 proposal_number;
  u8 reserved2;
  u16 reserved3;
  u8 (*get_proposal_number)(struct _rhp_ikev2_proposal* prop);

  int spi_len;
  u8  spi[RHP_PROTO_SPI_MAX_SIZE];
  int (*get_spi)(struct _rhp_ikev2_proposal* prop,u8* spi,int* spi_len);
};
typedef struct _rhp_ikev2_proposal  rhp_ikev2_proposal;

struct _rhp_res_sa_proposal;

struct _rhp_ikev2_sa_payload {

  rhp_ikev2_proposal* prop_list_head;
  rhp_ikev2_proposal* prop_list_tail;
  void (*put_prop)(struct _rhp_ikev2_payload* payload,rhp_ikev2_proposal* prop); // Add to list tail.
  int (*enum_props)(struct _rhp_ikev2_payload* payload,
        int (*callback)(struct _rhp_ikev2_payload* payload,rhp_ikev2_proposal* prop,void* ctx),void* ctx);

  int (*get_matched_ikesa_prop)(struct _rhp_ikev2_payload* payload,struct _rhp_res_sa_proposal* res_prop);
  int (*get_matched_childsa_prop)(struct _rhp_ikev2_payload* payload,struct _rhp_res_sa_proposal* res_prop);

  int (*set_def_ikesa_prop)(struct _rhp_ikev2_payload* payload,u8* spi,int spi_len,u16 rekey_dhgrp_id);
  int (*copy_ikesa_prop)(struct _rhp_ikev2_payload* payload,u8* spi,int spi_len,struct _rhp_ikesa* old_ikesa);

  int (*set_def_childsa_prop)(struct _rhp_ikev2_payload* payload,u8* spi,int spi_len,u16 rekey_pfs_dhgrp_id);
  int (*copy_childsa_prop)(struct _rhp_ikev2_payload* payload,u8* spi,int spi_len,
  		struct _rhp_childsa* old_childs,u16 rekey_pfs_dhgrp_id);

  int (*set_matched_ikesa_prop)(struct _rhp_ikev2_payload* payload,struct _rhp_res_sa_proposal* prop,u8* spi,int spi_len);
  int (*set_matched_childsa_prop)(struct _rhp_ikev2_payload* payload,struct _rhp_res_sa_proposal* prop,u32 spi);

  int is_for_ikesa;
  int (*rx_payload_is_for_ikesa)(struct _rhp_ikev2_payload* payload);
};
typedef struct _rhp_ikev2_sa_payload  rhp_ikev2_sa_payload;


/*******************************

  Key Exchange Payload

*******************************/

struct _rhp_ikev2_ke_payload {

  u16 (*get_dhgrp)(struct _rhp_ikev2_payload* payload);

  int (*get_key_len)(struct _rhp_ikev2_payload* payload);
  u8* (*get_key)(struct _rhp_ikev2_payload* payload);

  u16 dhgrp;
  u16 reserved0;
  int key_len;
  u8* key;
  int (*set_key)(struct _rhp_ikev2_payload* payload,u16 dhgrp,int key_len,u8* key);
};
typedef struct _rhp_ikev2_ke_payload  rhp_ikev2_ke_payload;


/*********************

  Nonce Payload

*********************/

struct _rhp_ikev2_nir_payload {

  int (*get_nonce_len)(struct _rhp_ikev2_payload* payload);
  u8* (*get_nonce)(struct _rhp_ikev2_payload* payload);

  int nonce_len;
  u8* nonce;
  int (*set_nonce)(struct _rhp_ikev2_payload* payload,int nonce_len,u8* nonce);
};
typedef struct _rhp_ikev2_nir_payload  rhp_ikev2_nir_payload;


/**************************

  Vendor ID Payload

**************************/

#define RHP_MY_VENDOR_ID   			"Please enjoy Rockhopper VPN!"
#define RHP_MY_VENDOR_ID_VER		1


struct _rhp_ikev2_vid_payload {

  int (*get_vid_len)(struct _rhp_ikev2_payload* payload);
  u8* (*get_vid)(struct _rhp_ikev2_payload* payload);

  int vid_len;
  u8* vid;
  int (*set_vid)(struct _rhp_ikev2_payload* payload,int vid_len,u8* vid);

  int (*copy_my_app_vid)(struct _rhp_ikev2_payload* payload);
  int (*is_my_app_id)(struct _rhp_ikev2_payload* payload,u8* ver_r);
};
typedef struct _rhp_ikev2_vid_payload  rhp_ikev2_vid_payload;


/*****************************

  Identification Payload

*****************************/

struct _rhp_ikev2_id_payload {

  u8 (*get_id_type)(struct _rhp_ikev2_payload* payload);

  int (*get_id_len)(struct _rhp_ikev2_payload* payload);
  u8* (*get_id)(struct _rhp_ikev2_payload* payload);

  u8 id_type;
  u8 reserved0;
  u16 reserved1;
  int id_len;
  u8* id;
  int (*set_id)(struct _rhp_ikev2_payload* payload,int id_type,int id_len,u8* id);

  int (*is_initiator)(struct _rhp_ikev2_payload* payload);
};
typedef struct _rhp_ikev2_id_payload  rhp_ikev2_id_payload;


/*******************************

  Authentication payload

*******************************/

struct _rhp_ikev2_auth_payload {

  u8 (*get_auth_method)(struct _rhp_ikev2_payload* payload);

  u8 auth_method;
  u8 reserved0;
  u16 reserved1;
  int auth_data_len;
  u8* auth_data;
  int (*set_auth_data)(struct _rhp_ikev2_payload* payload,u8 auth_method,int auth_data_len,u8* auth_data);

  int (*get_auth_data_len)(struct _rhp_ikev2_payload* payload);
  u8* (*get_auth_data)(struct _rhp_ikev2_payload* payload);
};
typedef struct _rhp_ikev2_auth_payload  rhp_ikev2_auth_payload;


/**********************

   Notify Payload

***********************/

struct _rhp_ikev2_n_auth_tkt_attr {

	struct _rhp_ikev2_n_auth_tkt_attr* next;

	u16 tkt_attr_type;
	u16 tkt_attr_sub_type;

	u16 (*get_attr_type)(struct _rhp_ikev2_n_auth_tkt_attr* tkt_attr);

	void (*set_attr_sub_type)(struct _rhp_ikev2_n_auth_tkt_attr* tkt_attr,u16 attr_sub_type);
	u16 (*get_attr_sub_type)(struct _rhp_ikev2_n_auth_tkt_attr* tkt_attr);

	int tkt_attr_len;
	u8* tkt_attr_val;
	u8* (*get_attr_val)(struct _rhp_ikev2_n_auth_tkt_attr* tkt_attr,int *val_len_r);
	int (*set_attr_val)(struct _rhp_ikev2_n_auth_tkt_attr* tkt_attr,int len,u8* val);
};
typedef struct _rhp_ikev2_n_auth_tkt_attr	rhp_ikev2_n_auth_tkt_attr;

struct _rhp_ikev2_n_auth_tkt_payload {

	u8 auth_tkt_type;
  u8 reserved0;
  u16 mesg_type;
  u16 (*get_mesg_type)(struct _rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload);
  u8 (*get_auth_tkt_type)(struct _rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload);

  rhp_ikev2_n_auth_tkt_attr* attr_head;
  rhp_ikev2_n_auth_tkt_attr* attr_tail;
  int (*add_attr)(struct _rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload,
  		rhp_ikev2_n_auth_tkt_attr* auth_tkt_attr);
  rhp_ikev2_n_auth_tkt_attr* (*get_attr)(struct _rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload,
  		u16 tkt_attr_type,u16 tkt_attr_sub_type);

  int (*serialize)(rhp_ikev2_mesg* tx_ikemesg,
  		struct _rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload,struct _rhp_vpn* resp_vpn,
  		struct _rhp_ikesa* resp_ikesa,struct _rhp_ikev2_payload** n_payload_r);

  unsigned long hb2spk_vpn_realm_id;
};
typedef struct _rhp_ikev2_n_auth_tkt_payload	rhp_ikev2_n_auth_tkt_payload;

extern rhp_ikev2_n_auth_tkt_attr* rhp_ikev2_payload_n_auth_tkt_attr_alloc(u16 tkt_attr_type);
extern void rhp_ikev2_payload_n_auth_tkt_attr_free(rhp_ikev2_n_auth_tkt_attr* tkt_attr);

extern void rhp_ikev2_payload_n_auth_tkt_free(rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload);

extern int rhp_ikev2_new_payload_n_auth_tkt_rx(struct _rhp_ikev2_mesg* ikemesg,struct _rhp_ikev2_payload* n_payload,
		rhp_ikev2_n_auth_tkt_payload** n_auth_tkt_payload_r);

extern int rhp_ikev2_new_payload_n_enc_auth_tkt_rx(struct _rhp_ikev2_mesg* ikemesg,struct _rhp_ikev2_payload* n_payload,
		struct _rhp_vpn* resp_vpn,rhp_ikev2_n_auth_tkt_payload** n_auth_tkt_payload_r);

extern int rhp_ikev2_new_payload_n_auth_tkt_tx(u16 mesg_type,u8 auth_tkt_type,
		rhp_ikev2_n_auth_tkt_payload** n_auth_tkt_payload_r);


struct _rhp_tkt_auth_srch_plds_ctx {

	int dup_flag;

	struct _rhp_vpn* vpn;
	struct _rhp_ikesa* ikesa;

	int peer_enabled;

	struct _rhp_ikev2_payload* n_auth_tkt_payload;
	struct _rhp_ikev2_payload* n_enc_auth_tkt_payload;
};
typedef struct _rhp_tkt_auth_srch_plds_ctx		rhp_tkt_auth_srch_plds_ctx;

extern void rhp_ikev2_auth_tkt_srch_clear_ctx(rhp_tkt_auth_srch_plds_ctx* s_pld_ctx);

extern int rhp_ikev2_auth_tkt_srch_n_cb(struct _rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		struct _rhp_ikev2_payload* payload,void* ctx);




struct _rhp_ikev2_n_payload {

  struct _rhp_ikev2_n_payload* next;

  u8 protocol_id;
  u8 reserved0;
  u16 reserved1;
  u8 (*get_protocol_id)(struct _rhp_ikev2_payload* payload);
  void (*set_protocol_id)(struct _rhp_ikev2_payload* payload,u8 protocol_id);

  // For Child SA/IKEv1 IPsec SA.
  int spi_len;
  u32 spi;
  int (*get_spi_len)(struct _rhp_ikev2_payload* payload);
  u32 (*get_spi)(struct _rhp_ikev2_payload* payload);
  void (*set_spi)(struct _rhp_ikev2_payload* payload,u32 spi);

  u16 message_type;
  u16 reserved4;
  u16 (*get_message_type)(struct _rhp_ikev2_payload* payload);
  void (*set_message_type)(struct _rhp_ikev2_payload* payload,u16 message_type);

  int data_len;
  u8* data;
  int (*get_data_len)(struct _rhp_ikev2_payload* payload);
  u8* (*get_data)(struct _rhp_ikev2_payload* payload);
  int (*set_data)(struct _rhp_ikev2_payload* payload,int data_len,u8* data);
  int (*set_data2)(struct _rhp_ikev2_payload* payload,int data0_len,u8* data0,int data1_len,u8* data1);

  // For IKEv1 IKE SA.
  u8 v1_ikesa_spi[16]; // Iint/Resp cookies.
  u8* (*v1_get_ikesa_spi)(struct _rhp_ikev2_payload* payload);
  int (*v1_set_ikesa_spi)(struct _rhp_ikev2_payload* payload,u8* init_cookie,u8* resp_cookie);
};
typedef struct _rhp_ikev2_n_payload  rhp_ikev2_n_payload;

#define RHP_IKEV2_NAT_T_HASH_LEN	20


/************************************

  Certificate Request Payload

************************************/

struct _rhp_ikev2_certreq_payload {

  int (*get_ca_keys_num)(struct _rhp_ikev2_payload* payload);
  int (*get_ca_key_len)(struct _rhp_ikev2_payload* payload);

  int (*get_ca_keys_len)(struct _rhp_ikev2_payload* payload);
  u8* (*get_ca_keys)(struct _rhp_ikev2_payload* payload);

  u8 cert_encoding;
  void (*set_cert_encoding)(struct _rhp_ikev2_payload* payload,u8 cert_encoding);
  u8 (*get_cert_encoding)(struct _rhp_ikev2_payload* payload);

  int ca_keys_len;
  u8* ca_keys;
  int (*set_ca_keys)(struct _rhp_ikev2_payload* payload,int ca_keys_len,u8* ca_keys);
};
typedef struct _rhp_ikev2_certreq_payload  rhp_ikev2_certreq_payload;



/****************************

  Certificate Payload

****************************/

struct _rhp_ikev2_cert_payload {

  u8 cert_encoding;
  void (*set_cert_encoding)(struct _rhp_ikev2_payload* payload,u8 cert_encoding);
  u8 (*get_cert_encoding)(struct _rhp_ikev2_payload* payload);

  int cert_len;
  u8* cert;
  int (*set_cert)(struct _rhp_ikev2_payload* payload,int cert_len,u8* cert);
  int (*get_cert_len)(struct _rhp_ikev2_payload* payload);
  u8* (*get_cert)(struct _rhp_ikev2_payload* payload);
};
typedef struct _rhp_ikev2_cert_payload  rhp_ikev2_cert_payload;

#define RHP_IKEV2_CERT_HASH_LEN						20
#define RHP_IKEV2_CERT_HASH_URL_MIN_LEN		(strlen("http://x"))

struct _rhp_ikev2_rx_cert_pld {

	struct _rhp_ikev2_rx_cert_pld* next;

	int is_ca_cert;

	int encoding; // RHP_PROTO_IKE_CERTENC_XXX
	int len; // val_lens[0] + val_lens[1] + ...

	//
	// - RHP_PROTO_IKE_CERTENC_X509_CERT_SIG
	//   - vals[0] : Raw DER data
	//
	// - RHP_PROTO_IKE_CERTENC_X509_CERT_HASH_URL
	//   - vals[0] : SHA1-HASH(20bytes)
	//   - vals[1] : URL + '\0'
	//   - vals[2] : (Result) Received raw DER data by HTTP-CLIENT-GET.
	//
	//
#define RHP_RX_CERT_PLD_VAL_NUM		5
#define RHP_RX_CERT_PLD_VAL_X509_SIG_DER					0
#define RHP_RX_CERT_PLD_VAL_X509_HASH_URL_HASH		0
#define RHP_RX_CERT_PLD_VAL_X509_HASH_URL_URL			1
#define RHP_RX_CERT_PLD_VAL_X509_HASH_URL_DER			2
	int val_lens[RHP_RX_CERT_PLD_VAL_NUM];
	u8* vals[RHP_RX_CERT_PLD_VAL_NUM];
};
typedef struct _rhp_ikev2_rx_cert_pld	rhp_ikev2_rx_cert_pld;

extern rhp_ikev2_rx_cert_pld* rhp_ikev2_rx_cert_pld_alloc(struct _rhp_ikev2_payload* payload,int is_ca_cert);
extern void rhp_ikev2_rx_cert_pld_free(rhp_ikev2_rx_cert_pld* cert_data);
extern int rhp_ikev2_rx_cert_pld_merge_ders(rhp_ikev2_rx_cert_pld* cert_data,u8** merged_buf_r,int* merged_buf_len_r);
extern int rhp_ikev2_rx_cert_pld_peek_der(rhp_ikev2_rx_cert_pld* cert_data,u8** buf_r,int* buf_len_r);
extern int rhp_ikev2_rx_cert_pld_split_der(rhp_ikev2_rx_cert_pld* cert_data,u8** buf_r,int* buf_len_r);

extern int rhp_ikev2_rx_cert_pld_split_hash_url(rhp_ikev2_rx_cert_pld* cert_data,char** url_r,u8** hash_r,int* hash_len_r);


/****************************

  Traffic Selector Payload

****************************/

struct _rhp_ikev2_traffic_selector {

  struct _rhp_ikev2_traffic_selector* next;

  // If this value is set by put_ts_rx(), it is just a reference.
  // Don't free it. [tsh_is_ref == 1]
  rhp_proto_ike_ts_selector* tsh;
  int tsh_is_ref;

  u8 ts_type;
  void (*set_ts_type)(struct _rhp_ikev2_traffic_selector* ts,u8 ts_type);
  u8 (*get_ts_type)(struct _rhp_ikev2_traffic_selector* ts);

  u8 protocol;
  u8 is_pending;
  u8 apdx_ts_ignored;
  u8 reserved1;
  void (*set_protocol)(struct _rhp_ikev2_traffic_selector* ts,u8 protocol);
  u8 (*get_protocol)(struct _rhp_ikev2_traffic_selector* ts);

  u16 start_port;
  u16 end_port;
  void (*set_start_port)(struct _rhp_ikev2_traffic_selector* ts,u16 start_port);
  u16 (*get_start_port)(struct _rhp_ikev2_traffic_selector* ts);
  void (*set_end_port)(struct _rhp_ikev2_traffic_selector* ts,u16 end_port);
  u16 (*get_end_port)(struct _rhp_ikev2_traffic_selector* ts);

  u8 icmp_start_type;
  u8 icmp_end_type;
  void (*set_icmp_start_type)(struct _rhp_ikev2_traffic_selector* ts,u8 start_type);
  u8 (*get_icmp_start_type)(struct _rhp_ikev2_traffic_selector* ts);
  void (*set_icmp_end_type)(struct _rhp_ikev2_traffic_selector* ts,u8 end_type);
  u8 (*get_icmp_end_type)(struct _rhp_ikev2_traffic_selector* ts);

  u8 icmp_start_code;
  u8 icmp_end_code;
  void (*set_icmp_start_code)(struct _rhp_ikev2_traffic_selector* ts,u8 start_code);
  u8 (*get_icmp_start_code)(struct _rhp_ikev2_traffic_selector* ts);
  void (*set_icmp_end_code)(struct _rhp_ikev2_traffic_selector* ts,u8 end_code);
  u8 (*get_icmp_end_code)(struct _rhp_ikev2_traffic_selector* ts);

  rhp_ip_addr start_addr;
  void (*set_start_addr)(struct _rhp_ikev2_traffic_selector* ts,rhp_ip_addr* start_addr);
  int (*get_start_addr)(struct _rhp_ikev2_traffic_selector* ts,rhp_ip_addr* start_addr_r);

  rhp_ip_addr end_addr;
  void (*set_end_addr)(struct _rhp_ikev2_traffic_selector* ts,rhp_ip_addr* end_addr);
  int (*get_end_addr)(struct _rhp_ikev2_traffic_selector* ts,rhp_ip_addr* end_addr_r);

  int (*addr_is_included)(struct _rhp_ikev2_traffic_selector* ts,rhp_ip_addr* addr);
  int (*replace_start_addr)(struct _rhp_ikev2_traffic_selector* ts,rhp_ip_addr* addr);
  int (*replace_end_addr)(struct _rhp_ikev2_traffic_selector* ts,rhp_ip_addr* addr);

  void (*dump)(struct _rhp_ikev2_traffic_selector* ts_head,char* label);
  void (*dump2log)(struct _rhp_ikev2_traffic_selector* ts_head,char* label,unsigned long rlm_id);
};
typedef struct _rhp_ikev2_traffic_selector rhp_ikev2_traffic_selector;

struct _rhp_vpn_realm;
struct _rhp_cfg_peer;
struct _rhp_traffic_selector;
struct _rhp_childsa_ts;

struct _rhp_ikev2_ts_payload {

  u8 (*get_ts_num)(struct _rhp_ikev2_payload* payload);

  u8 tss_num;
  rhp_ikev2_traffic_selector* tss_head;
  rhp_ikev2_traffic_selector* tss_tail;
  int (*alloc_and_put_ts)(struct _rhp_ikev2_payload* payload,u8 ts_type,u8 protocol,u16 start_port,u16 end_port,
		  u8 icmp_start_type,u8 icmp_end_type,u8 icmp_start_code,u8 icmp_end_code,
		  rhp_ip_addr* start_addr,rhp_ip_addr* end_addr);

  int (*put_ts_rx)(struct _rhp_ikev2_payload* payload,rhp_proto_ike_ts_selector* tsh);

  // For responder
  int (*get_matched_tss)(struct _rhp_ikev2_payload* payload,struct _rhp_vpn_realm* rlm,struct _rhp_cfg_peer* cfg_peer,
  		rhp_ikev2_traffic_selector** res_tss);

  // For initiator
  int (*check_tss)(struct _rhp_ikev2_payload* payload,struct _rhp_vpn_realm* rlm,struct _rhp_cfg_peer* cfg_peer,
  			struct _rhp_childsa_ts* extended_tss,rhp_ikev2_traffic_selector** res_tss);

  int (*set_i_tss)(struct _rhp_ikev2_payload* payload,struct _rhp_vpn_realm* rlm,struct _rhp_cfg_peer* cfg_peer,
  		rhp_ip_addr_list* cp_internal_addrs,rhp_ikev2_traffic_selector* apdx_tss);

  void (*set_matched_r_tss)(struct _rhp_ikev2_payload* payload,rhp_ikev2_traffic_selector* res_tss); // res_tss is eaten.

  int (*set_tss)(struct _rhp_ikev2_payload* payload,struct _rhp_childsa_ts* tss);

  // 'payload' (i.e. this object) is a rx payload from a peer.
  int (*reconfirm_tss)(struct _rhp_ikev2_payload* payload,struct _rhp_ikev2_payload* tx_payload);
};
typedef struct _rhp_ikev2_ts_payload  rhp_ikev2_ts_payload;

extern int rhp_ikev2_alloc_ts(u8 ts_type,rhp_ikev2_traffic_selector** ts_r);
extern int rhp_ikev2_ts_tx_dup(rhp_ikev2_traffic_selector* from,rhp_ikev2_traffic_selector** to_r);
extern void rhp_ikev2_ts_payload_free_ts(rhp_ikev2_traffic_selector* ts);
extern void rhp_ikev2_ts_payload_free_tss(rhp_ikev2_traffic_selector* tss);

extern int rhp_ikev2_dup_ts(rhp_ikev2_traffic_selector* ts,rhp_ikev2_traffic_selector** ts_r);
extern int rhp_ikev2_dup_tss(rhp_ikev2_traffic_selector* tss_head,
		rhp_ikev2_traffic_selector** tss_head_r,
		int (*eval)(rhp_ikev2_traffic_selector* ts,void* cb_ctx),void* ctx);

extern int rhp_ikev2_ts_cmp_ts2tsh(rhp_ikev2_traffic_selector* ts, rhp_proto_ike_ts_selector* tsh);
extern int rhp_ikev2_ts_cmp_ts2ts(rhp_ikev2_traffic_selector* ts0, rhp_ikev2_traffic_selector* ts1);
extern int rhp_ikev2_ts_cmp_ts2cfg(rhp_ikev2_traffic_selector* ts, struct _rhp_traffic_selector* cfg_ts);
extern int rhp_ikev2_ts_cmp(rhp_ikev2_traffic_selector* ts0, rhp_ikev2_traffic_selector* ts1);

extern int rhp_ikev2_ts_is_included(rhp_ikev2_traffic_selector* tss_head,rhp_ikev2_traffic_selector* ts);
extern int rhp_ikev2_ts_is_any(rhp_ikev2_traffic_selector* ts);

extern int rhp_ikev2_ts_payload_addr_is_included(rhp_ikev2_traffic_selector* ts,rhp_ip_addr* addr);
extern int rhp_ikev2_ts_payload_cfg_addr_is_included(struct _rhp_traffic_selector* cfg_ts,rhp_ip_addr* addr);

extern int rhp_ikev2_ts_cmp_ts2tss_same_or_any(rhp_ikev2_traffic_selector* ts,rhp_ikev2_traffic_selector* tss_head);
extern int rhp_ikev2_ts_cmp_ts2cfg_tss_same_or_any(rhp_ikev2_traffic_selector* ts,rhp_traffic_selector* cfg_tss_head);

extern int rhp_ikev2_ts_payload_ts2childsa_ts(rhp_ikev2_traffic_selector* ts,struct _rhp_childsa_ts* csa_ts);


/**********************

   Delete Payload

***********************/

struct _rhp_ikev2_d_payload {

  struct _rhp_ikev2_d_payload* next;

  u8 protocol_id;
  u8 reserved0;
  u16 reserved1;
  u8 (*get_protocol_id)(struct _rhp_ikev2_payload* payload);
  void (*set_protocol_id)(struct _rhp_ikev2_payload* payload,u8 protocol_id);

  // For Child SA/IKEv1 IPsec SA
  int spi_len;
  int (*get_spi_len)(struct _rhp_ikev2_payload* payload);

  // For Child SA/IKEv1 IPsec SA
  int spis_num;
  int (*get_spis_num)(struct _rhp_ikev2_payload* payload);

  // For Child SA/IKEv1 IPsec SA.
  int spis_len;
  u32* spis;
  int (*get_spis_len)(struct _rhp_ikev2_payload* payload);
  u32* (*get_spis)(struct _rhp_ikev2_payload* payload);
  int (*set_spi)(struct _rhp_ikev2_payload* payload,u32 spi);

  // For IKEv1 IKE SA.
  u8 v1_ikesa_spi[16]; // Iint/Resp cookies.
  u8* (*v1_get_ikesa_spi)(struct _rhp_ikev2_payload* payload);
  int (*v1_set_ikesa_spi)(struct _rhp_ikev2_payload* payload,u8* init_cookie,u8* resp_cookie);
};
typedef struct _rhp_ikev2_d_payload  rhp_ikev2_d_payload;


/**********************

   Configuration Payload

***********************/

struct _rhp_ikev2_cp_attr {

	struct _rhp_ikev2_cp_attr* next;

	rhp_proto_ike_cfg_attr* cp_attrh;

	u16 attr_type;
	void (*set_attr_type)(struct _rhp_ikev2_cp_attr* cp_attr,u16 attr_type);
	u16 (*get_attr_type)(struct _rhp_ikev2_cp_attr* cp_attr);

	int attr_len;
	u8* attr_val;

	int (*get_attr_len)(struct _rhp_ikev2_cp_attr* cp_attr);
	u8* (*get_attr)(struct _rhp_ikev2_cp_attr* cp_attr);
	int (*set_attr)(struct _rhp_ikev2_cp_attr* cp_attr,int attr_len,u8* attr_val);
};
typedef struct _rhp_ikev2_cp_attr		rhp_ikev2_cp_attr;

struct _rhp_ikev2_cp_payload {

  u8 cfg_type;
  u8 reserved0;
  u16 reserved1;
  u8 (*get_cfg_type)(struct _rhp_ikev2_payload* payload);
  void (*set_cfg_type)(struct _rhp_ikev2_payload* payload,u8 cfg_type);

  int attr_num;
  rhp_ikev2_cp_attr* cp_attr_head;
  rhp_ikev2_cp_attr* cp_attr_tail;

  struct {
		rhp_ip_addr internal_addr_v4;
		rhp_ip_addr internal_addr_v6;
	} cp_attr_ext;

	int (*put_attr_rx)(struct _rhp_ikev2_payload* payload,rhp_proto_ike_cfg_attr* cp_attr); // Add to list tail.
  int (*enum_attr)(struct _rhp_ikev2_payload* payload,
        int (*callback)(struct _rhp_ikev2_payload* payload,rhp_ikev2_cp_attr* cp_attr,void* ctx),void* ctx);
  int (*alloc_and_put_attr)(struct _rhp_ikev2_payload* payload,u16 attr_type,int attr_len,u8* attr_val);
  rhp_ip_addr* (*get_attr_internal_addr_v4)(struct _rhp_ikev2_payload* payload);
  rhp_ip_addr* (*get_attr_internal_addr_v6)(struct _rhp_ikev2_payload* payload);
};
typedef struct _rhp_ikev2_cp_payload  rhp_ikev2_cp_payload;


#define RHP_IKEV2_CFG_IPV6_RA_TSS_NUM	5

extern rhp_ikev2_traffic_selector* rhp_ikev2_cfg_my_v6_ra_tss;
extern rhp_ikev2_traffic_selector* rhp_ikev2_cfg_peer_v6_ra_tss;

#define RHP_IKEV2_CFG_IPV6_RA_TSS_RA								0 // Only RA/RS
#define RHP_IKEV2_CFG_IPV6_RA_TSS_ICMPV6						1
#define RHP_IKEV2_CFG_IPV6_RA_TSS_ICMPV6_ADDR_ANY		2 // Any src/dst addresses
#define RHP_IKEV2_CFG_IPV6_RA_TSS_RA_ADDR_ANY				3 // Only RA/RS, Any src/dst addresses
extern int rhp_ikev2_cfg_alloc_v6_ra_tss(int type);


#define RHP_IKEV2_CFG_IPV6_AUTO_TSS_NUM		6

extern rhp_ikev2_traffic_selector* rhp_ikev2_cfg_my_v6_auto_tss;
extern rhp_ikev2_traffic_selector* rhp_ikev2_cfg_peer_v6_auto_tss;

#define RHP_IKEV2_CFG_IPV6_AUTO_TSS_ICMPV6						0
#define RHP_IKEV2_CFG_IPV6_AUTO_TSS_ICMPV6_ADDR_ANY		1 // Any src/dst addresses
extern int rhp_ikev2_cfg_alloc_v6_auto_tss(int type);


/**********************

   EAP Payload

***********************/

struct _rhp_ikev2_eap_payload {

	int tx_eap_mesg_len;
	u8* tx_eap_mesg;

	u8 (*get_code)(struct _rhp_ikev2_payload* payload);
	u8 (*get_identifier)(struct _rhp_ikev2_payload* payload);
	u8 (*get_type)(struct _rhp_ikev2_payload* payload);

	int (*set_eap_message)(struct _rhp_ikev2_payload* payload,u8* eap_mesg,int eap_mesg_len);
	u8* (*get_eap_message)(struct _rhp_ikev2_payload* payload,int* eap_mesg_len_r);
};
typedef struct _rhp_ikev2_eap_payload  rhp_ikev2_eap_payload;



/**********************

   STUN Payload (RHP)

***********************/

struct _rhp_stun_mesg;

struct _rhp_ikev2_stun_payload {

	// Primitive
	struct _rhp_stun_mesg* stun_mesg;
	struct _rhp_stun_mesg* (*get_stun_mesg)(struct _rhp_ikev2_payload* payload);
	void (*set_stun_mesg)(struct _rhp_ikev2_payload* payload,struct _rhp_stun_mesg* stun_mesg);
	struct _rhp_stun_mesg* (*unset_stun_mesg)(struct _rhp_ikev2_payload* payload);


	// Bind
	int (*bind_alloc_tx_req)(struct _rhp_ikev2_payload* payload);
	int (*bind_alloc_tx_resp)(struct _rhp_ikev2_payload* payload, rhp_ikev2_mesg* rx_req_ikemesg);

	int (*bind_rx_resp_mapped_addr)(struct _rhp_ikev2_payload* payload, rhp_ip_addr** mapped_addr_r);

};
typedef struct _rhp_ikev2_stun_payload  rhp_ikev2_stun_payload;



/*******************************

  Generic Payload Header

********************************/

struct _rhp_ikev2_payload {

  unsigned char tag[4]; // "#IKP"

  struct _rhp_ikev2_payload* next; // For rhp_ikev2_mesg.
  struct _rhp_ikev2_payload* list_next; // For temporary use.
  struct _rhp_ikev2_payload* list_tail; // For temporary use.

  struct _rhp_ikev2_mesg* ikemesg;

  rhp_proto_ike_payload* payloadh;

  u8 payload_id;
  u8 is_v1;
  u16 reserved1;
  u8 (*get_payload_id)(struct _rhp_ikev2_payload* ikepayload);

  u8  (*get_next_payload)(struct _rhp_ikev2_payload* ikepayload);

  u16 (*get_len_rx)(struct _rhp_ikev2_payload* ikepayload);

  int non_critical;
  void (*set_non_critical)(struct _rhp_ikev2_payload* ikepayload,int flag);

  union {
    u8* raw;
    rhp_ikev2_sa_payload* sa;
    rhp_ikev2_ke_payload* ke;
    rhp_ikev2_nir_payload* nir;
    rhp_ikev2_vid_payload* vid;
    rhp_ikev2_id_payload* id;
    rhp_ikev2_auth_payload* auth;
    rhp_ikev2_n_payload* n;
    rhp_ikev2_certreq_payload* certreq;
    rhp_ikev2_cert_payload* cert;
    rhp_ikev2_ts_payload* ts;
    rhp_ikev2_d_payload* d;
    rhp_ikev2_cp_payload* cp;
    rhp_ikev2_eap_payload* eap;
    rhp_ikev2_stun_payload* stun;

    rhp_ikev1_sa_payload* v1_sa;
    rhp_ikev1_ke_payload* v1_ke;
    rhp_ikev1_id_payload* v1_id;
    rhp_ikev1_cr_payload* v1_cr; // CertReq
    rhp_ikev1_hash_payload* v1_hash;
    rhp_ikev1_sig_payload* v1_sig;
    rhp_ikev1_nat_d_payload* v1_nat_d;
    rhp_ikev1_nat_oa_payload* v1_nat_oa;
    rhp_ikev1_attr_payload* v1_attr;
  } ext;

  int (*ext_serialize)(struct _rhp_ikev2_payload* ikepayload,rhp_packet* pkt);

  void (*ext_destructor)(struct _rhp_ikev2_payload* ikepayload);

  void (*ext_dump)(struct _rhp_ikev2_payload* ikepayload);

};
typedef struct _rhp_ikev2_payload rhp_ikev2_payload;

extern int rhp_ikev2_new_payload_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                    rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload** ikepayload);

extern int rhp_ikev2_new_payload_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload** ikepayload);

extern rhp_ikev2_payload* rhp_ikev2_alloc_payload_raw();
extern void rhp_ikev2_destroy_payload(rhp_ikev2_payload* ikepayload);





/*********************************************************

 Create_Child_SA Exchange (AUTH/REKEY/CREATE_CHILDSA)

*********************************************************/

struct _rhp_childsa_srch_plds_ctx {

	struct _rhp_vpn* vpn;
	struct _rhp_ikesa* ikesa;
	rhp_vpn_realm* rlm;
	struct _rhp_childsa* childsa;

	int dup_flag;

 	rhp_ikev2_payload* sa_payload;
 	rhp_ikev2_payload* ts_i_payload;
 	rhp_ikev2_payload* ts_r_payload;

 	union {
 		rhp_res_sa_proposal v2;
 		rhp_res_ikev1_sa_proposal v1;
 	} resolved_prop;

  struct _rhp_ikev2_traffic_selector* res_tss_i;
  struct _rhp_ikev2_traffic_selector* res_tss_r;

 	u8 use_trans_port_mode;
 	u8 esp_tfc_padding_not_supported;
 	u8 use_etherip_encap;
 	u8 rekey_ipv6_autoconf;
 	u8 use_gre_encap;
 	u8 v1_connected;
 	u8 reservied0;
 	u8 reservied1;

 	rhp_ip_addr* res_cp_internal_addr_v4;
 	rhp_ip_addr* res_cp_internal_addr_v6;

 	u16 notify_error;
 	unsigned long notify_error_arg;
  u8 notify_proto;
  u32 notify_spi;


  rhp_ikev2_payload* n_error_payload;

  rhp_ikev2_payload* n_rekey_sa_payload;

  rhp_ikev2_payload* ke_payload;
  rhp_ikev2_payload* nir_payload;

  rhp_ikev2_payload* v1_hash_payload;

  rhp_ip_addr v1_nat_oa_i;
  rhp_ip_addr v1_nat_oa_r;

 	u32 rekey_outb_spi;

  int nonce_len;
  u8* nonce;
  int prf_key_len;

  u16 dhgrp;
  int peer_dh_pub_key_len;
  u8* peer_dh_pub_key;

  int v1_addr_family;
};
typedef struct _rhp_childsa_srch_plds_ctx		rhp_childsa_srch_plds_ctx;


extern int rhp_ikev2_create_child_sa_add_v6_ext_ts(rhp_childsa_srch_plds_ctx* s_pld_ctx,
		rhp_ikev2_traffic_selector* my_tss_ext,rhp_ikev2_traffic_selector* peer_tss_ext,
		rhp_ikev2_traffic_selector* my_tss_ext2,rhp_ikev2_traffic_selector* peer_tss_ext2,
		int mark_pending);

extern int rhp_ikev2_create_child_sa_add_v6_accept_ra_ts(rhp_childsa_srch_plds_ctx* s_pld_ctx);

extern int rhp_ikev2_create_child_sa_add_v6_auto_ts(rhp_childsa_srch_plds_ctx* s_pld_ctx,int mark_pending);

extern int rhp_ikev2_create_child_sa_mod_tss_cp(rhp_ikev2_mesg* tx_resp_ikemesg,
		rhp_childsa_srch_plds_ctx* s_pld_ctx,unsigned int ts_extended_flag_0);

extern int rhp_ikev2_create_child_sa_purge_af_tss(rhp_ikev2_mesg* tx_resp_ikemesg,
		rhp_childsa_srch_plds_ctx* s_pld_ctx,u8 purged_ts_type,unsigned int* ts_extended_flag_r);


extern int rhp_ikev2_create_child_sa_srch_childsa_ke_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx);

extern int rhp_ikev2_create_child_sa_srch_childsa_nir_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx);

extern int rhp_ikev2_create_child_sa_rep_srch_ts_i_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx);

extern int rhp_ikev2_create_child_sa_rep_srch_ts_r_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx);

extern int rhp_ikev2_create_child_sa_req_srch_ts_i_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx);

extern int rhp_ikev2_create_child_sa_req_srch_ts_r_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx);

extern int rhp_ikev2_create_child_sa_srch_sa_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx);


extern int rhp_ikev2_rx_create_child_sa_req_encap_mode(struct _rhp_vpn* vpn,struct _rhp_vpn_realm* rlm,
		struct _rhp_childsa_srch_plds_ctx* s_pld_ctx,int* encap_mode_c_r);

extern int rhp_ikev2_rx_create_child_sa_rep_encap_mode(struct _rhp_vpn* vpn,struct _rhp_vpn_realm* rlm,
		struct _rhp_childsa_srch_plds_ctx* s_pld_ctx,int* encap_mode_c_r);


extern void rhp_childsa_cleanup_dup_childsa_handler2(void *ctx);

extern int rhp_childsa_detect_exchg_collision(struct _rhp_vpn* vpn);



struct _rhp_delete_srch_plds_ctx {

	int ikesa_dup_flag;
	int childsa_dup_flag;

	struct _rhp_vpn* vpn;
	struct _rhp_ikesa* ikesa;
	struct _rhp_vpn_realm* rlm;

	struct _rhp_ikev2_payload* delete_ikepayload;

	int ikesa_my_side;
	u8* ikesa_my_spi;

  int childsa_outb_spis_num;
  u32* childsa_outb_spis;
};
typedef struct _rhp_delete_srch_plds_ctx		rhp_delete_srch_plds_ctx;



struct _rhp_nat_t_srch_plds_ctx {

	int dup_flag;

	struct _rhp_vpn* vpn;
	struct _rhp_ikesa* ikesa;
	struct _rhp_vpn_realm* rlm;

  int n_nat_t_src_num;
  int n_nat_t_dst_num;
  int exec_nat_t;
  unsigned int behind_a_nat;

  int peer_not_behind_a_nat;

  u16 notify_error;
  unsigned long notify_error_arg;
};
typedef struct _rhp_nat_t_srch_plds_ctx		rhp_nat_t_srch_plds_ctx;



struct _rhp_intr_net_srch_plds_ctx {

	int dup_flag;

	struct _rhp_vpn* vpn;
	struct _rhp_ikesa* ikesa;

  rhp_ip_addr_list* peer_addrs;
  int peer_addrs_num;

  u8 peer_mac[6];

  int peer_is_access_point;
  int peer_is_mesh_node;
};
typedef struct _rhp_intr_net_srch_plds_ctx		rhp_intr_net_srch_plds_ctx;



struct _rhp_cp_req_srch_pld_ctx {

	int dup_flag;

	int peer_is_rockhopper;

	rhp_ikev2_payload* cp_payload;

	int internal_addr_flag;
	rhp_ip_addr internal_addr;

	int internal_netmask_flag;
	int internal_subnet_flag;
	int internal_dns_flag;
	int internal_gateway_flag;
	int internal_wins_flag;

	int internal_addr_v6_flag;
	rhp_ip_addr internal_addr_v6;

	int internal_subnet_v6_flag;
	int internal_dns_v6_flag;
	int internal_gateway_v6_flag;
	int internal_wins_v6_flag;

	int internal_dns_sfx_flag;
	int app_ver_flag;
#define RHP_IKE_CFG_ATTR_APP_VER_MAX_LEN		128

	int supported_attrs;

	int ipv6_autoconf_flag;

	int v1_rx_attrs;

  u16 notify_error;
  unsigned long notify_error_arg;
};
typedef struct _rhp_cp_req_srch_pld_ctx		rhp_cp_req_srch_pld_ctx;

#endif // _RHP_IKEV2_MESG_H_

