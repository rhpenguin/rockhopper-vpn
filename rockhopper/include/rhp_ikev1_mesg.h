/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/



#ifndef _RHP_IKEV1_MESG_H_
#define _RHP_IKEV1_MESG_H_

struct _rhp_packet;
struct _rhp_vpn;
struct _rhp_ikesa;
struct _rhp_childsa;
struct _rhp_ikev2_payload;
struct _rhp_vpn;
struct _rhp_ikev2_mesg;
struct _rhp_ikev2_payload;
struct _rhp_vpn_realm;
struct _rhp_cfg_peer;
struct _rhp_childsa_ts;

extern struct _rhp_ikev2_mesg* rhp_ikev1_new_mesg_tx(u8 exchange_type,u32 message_id/*For response*/,u8 flag);

extern int rhp_ikev1_new_mesg_rx(struct _rhp_packet* pkt,struct _rhp_vpn* vpn,struct _rhp_ikesa* ikesa,
		struct _rhp_ikev2_mesg** ikemesg_r,
		struct _rhp_ikev2_mesg** ikemesg_err_r);



/*************************************

  Security Association Payload

**************************************/

struct _rhp_ikev1_transform {

  struct _rhp_ikev1_transform* next;

  rhp_proto_ikev1_transform_payload* transh;

  u8 trans_number;
  u8 trans_id;
  u16 reserved0;
  
  int enc_alg;							// P1
  int hash_alg;							// P1
  int auth_method;					// P1
  int dh_group;							// P1/P2
  unsigned long life_time;	// P1/P2
  
  unsigned long life_bytes; // P2
  int encap_mode;	// P2
  int auth_alg;		// P2
  int esn;				// P2
    
  int key_bits_len; // For ENC
};
typedef struct _rhp_ikev1_transform rhp_ikev1_transform;

struct _rhp_ikev1_proposal {

  struct _rhp_ikev1_proposal* next;

  rhp_proto_ikev1_proposal_payload* proph;

  int trans_num;
  int (*get_trans_num)(struct _rhp_ikev1_proposal* prop);

  rhp_ikev1_transform* trans_list_head;
  rhp_ikev1_transform* trans_list_tail;
  void (*put_trans)(struct _rhp_ikev1_proposal* prop,rhp_ikev1_transform* trans); // Add to list tail.
  int (*enum_trans)(struct _rhp_ikev1_proposal* prop,
        int (*callback)(struct _rhp_ikev1_proposal* prop,rhp_ikev1_transform* trans,void* ctx),void* ctx);
  int (*alloc_and_put_trans)(struct _rhp_ikev1_proposal* prop,
  			u8 trans_number,u8 trans_id,rhp_ikev1_transform** trans_r);

  u8 protocol_id;
  u8 reserved0;
  u16 reserved1;
  u8 (*get_protocol_id)(struct _rhp_ikev1_proposal* prop);

  u8 proposal_number;
  u8 reserved2;
  u16 reserved3;
  u8 (*get_proposal_number)(struct _rhp_ikev1_proposal* prop);

  int spi_len;
  u8  spi[RHP_PROTO_SPI_MAX_SIZE];
  int (*get_spi)(struct _rhp_ikev1_proposal* prop,u8* spi,int* spi_len);
};
typedef struct _rhp_ikev1_proposal  rhp_ikev1_proposal;

struct _rhp_res_ikev1_sa_proposal;

struct _rhp_ikev1_sa_payload {

  rhp_ikev1_proposal* prop_list_head;
  rhp_ikev1_proposal* prop_list_tail;
  void (*put_prop)(struct _rhp_ikev2_payload* payload,rhp_ikev1_proposal* prop); // Add to list tail.
  int (*enum_props)(struct _rhp_ikev2_payload* payload,
        int (*callback)(struct _rhp_ikev2_payload* payload,rhp_ikev1_proposal* prop,void* ctx),void* ctx);

  int (*get_matched_ikesa_prop)(struct _rhp_ikev2_payload* payload,struct _rhp_res_ikev1_sa_proposal* res_prop);
  int (*get_matched_ipsecsa_prop)(struct _rhp_ikev2_payload* payload,struct _rhp_res_ikev1_sa_proposal* res_prop);

  int (*set_def_ikesa_prop)(struct _rhp_ikev2_payload* payload,u8* spi,int spi_len,u16 dhgrp_id,
  			int auth_method,unsigned long lifetime);
  int (*copy_ikesa_prop)(struct _rhp_ikev2_payload* payload,u8* spi,int spi_len,struct _rhp_ikesa* old_ikesa);

  int (*set_def_ipsecsa_prop)(struct _rhp_ikev2_payload* payload,u32 spi,
  			u16 pfs_dhgrp_id,int encap_mode,unsigned long lifetime);
  int (*copy_ipsecsa_prop)(struct _rhp_ikev2_payload* payload,u32 spi,
  			struct _rhp_childsa* old_childs,u16 rekey_pfs_dhgrp_id);

  int (*set_matched_ikesa_prop)(struct _rhp_ikev2_payload* payload,struct _rhp_res_ikev1_sa_proposal* prop,u8* spi,int spi_len);
  int (*set_matched_ipsecsa_prop)(struct _rhp_ikev2_payload* payload,struct _rhp_res_ikev1_sa_proposal* prop,u32 spi);

  int is_for_ikesa;
  int (*rx_payload_is_for_ikesa)(struct _rhp_ikev2_payload* payload);

  rhp_proto_ikev1_sa_payload* sa_b;
};
typedef struct _rhp_ikev1_sa_payload  rhp_ikev1_sa_payload;



/*******************************

  Key Exchange Payload

*******************************/

struct _rhp_ikev1_ke_payload {

  int (*get_key_len)(struct _rhp_ikev2_payload* payload);
  u8* (*get_key)(struct _rhp_ikev2_payload* payload);

  int key_len;
  u8* key;
  int (*set_key)(struct _rhp_ikev2_payload* payload,int key_len,u8* key);
};
typedef struct _rhp_ikev1_ke_payload  rhp_ikev1_ke_payload;



/*****************************

  Identification Payload

*****************************/

struct _rhp_ikev1_id_payload {

  u8 (*get_id_type)(struct _rhp_ikev2_payload* payload);

  u8 (*get_protocol_id)(struct _rhp_ikev2_payload* payload);

  u16 (*get_port)(struct _rhp_ikev2_payload* payload);

  int (*get_id_len)(struct _rhp_ikev2_payload* payload);
  u8* (*get_id)(struct _rhp_ikev2_payload* payload);


  int (*set_i_ts)(struct _rhp_ikev2_payload* payload,struct _rhp_vpn_realm* rlm,
  			int side,int addr_family,struct _rhp_cfg_peer* cfg_peer,rhp_ip_addr* cp_internal_addr,
  			rhp_ip_addr* gre_addr,struct _rhp_childsa_ts** csa_ts_r);

  // For responder
  int (*get_matched_ts)(struct _rhp_ikev2_payload* payload,int side,
  		struct _rhp_vpn_realm* rlm,struct _rhp_cfg_peer* cfg_peer,rhp_ip_addr* gre_addr);

  // For initiator
  int (*check_ts)(struct _rhp_ikev2_payload* payload,int side,
  		struct _rhp_childsa* childsa);

  struct _rhp_childsa_ts* (*to_csa_ts)(struct _rhp_ikev2_payload* payload);

  int (*set_csa_ts)(struct _rhp_ikev2_payload* payload,struct _rhp_childsa_ts* csa_ts);


  u8 id_type;
  u8 protocol_id;
  u16 port;

  int id_len;
  u8* id;
  int (*set_id)(struct _rhp_ikev2_payload* payload,int id_type,int id_len,u8* id);

  int gre_ts_auto_generated;
};
typedef struct _rhp_ikev1_id_payload  rhp_ikev1_id_payload;


//extern int rhp_ikev1_id_type_to_v2_ts_type(int v1_id_type);



/****************************

    Certificate Payload

****************************/
//
// Use rhp_ikev2_cert_payload
//


/****************************

 Certificate Request Payload

****************************/

struct _rhp_ikev1_cr_payload {

  u8 cert_encoding;
  void (*set_cert_encoding)(struct _rhp_ikev2_payload* payload,u8 cert_encoding);
  u8 (*get_cert_encoding)(struct _rhp_ikev2_payload* payload);

  int ca_len;
  u8* ca;
  int (*set_ca)(struct _rhp_ikev2_payload* payload,int ca_dn_len,u8* ca_dn);
  int (*get_ca_len)(struct _rhp_ikev2_payload* payload);
  u8* (*get_ca)(struct _rhp_ikev2_payload* payload);
};
typedef struct _rhp_ikev1_cr_payload  rhp_ikev1_cr_payload;



/*******************************

          Hash Payload

*******************************/

struct _rhp_ikev1_hash_payload {

  int (*get_hash_len)(struct _rhp_ikev2_payload* payload);
  u8* (*get_hash)(struct _rhp_ikev2_payload* payload);

  int hash_len;
  u8* hash;
  int (*set_hash)(struct _rhp_ikev2_payload* payload,int hash_len,u8* hash);
};
typedef struct _rhp_ikev1_hash_payload  rhp_ikev1_hash_payload;



/*******************************

       Signature Payload

*******************************/

struct _rhp_ikev1_sig_payload {

  int (*get_sig_len)(struct _rhp_ikev2_payload* payload);
  u8* (*get_sig)(struct _rhp_ikev2_payload* payload);

  int sig_len;
  u8* sig;
  int (*set_sig)(struct _rhp_ikev2_payload* payload,int sig_len,u8* sig);
};
typedef struct _rhp_ikev1_sig_payload  rhp_ikev1_sig_payload;



/*********************

    Nonce Payload

*********************/
//
// Use rhp_ikev2_nir_payload
//



/*********************

 Notification Payload

*********************/
//
// Use rhp_ikev2_n_payload
//



/*********************

    Delete Payload

*********************/
//
// Use rhp_ikev2_d_payload
//


/*********************

  Vendor ID Payload

*********************/
//
// Use rhp_ikev2_v_payload
//


/*******************************

         NAT-D Payload

*******************************/

struct _rhp_ikev1_nat_d_payload {

  int (*get_hash_len)(struct _rhp_ikev2_payload* payload);
  u8* (*get_hash)(struct _rhp_ikev2_payload* payload);

  int hash_len;
  u8* hash;
  int (*set_hash)(struct _rhp_ikev2_payload* payload,int hash_len,u8* hash);
};
typedef struct _rhp_ikev1_nat_d_payload  rhp_ikev1_nat_d_payload;


/*******************************

        NAT-OA Payload

*******************************/

struct _rhp_ikev1_nat_oa_payload {

  int (*get_orig_addr_family)(struct _rhp_ikev2_payload* payload);
  u8* (*get_orig_addr)(struct _rhp_ikev2_payload* payload);

  int addr_family;
  u8 addr[16];
  int (*set_orig_addr)(struct _rhp_ikev2_payload* payload,int addr_family,u8* addr);
};
typedef struct _rhp_ikev1_nat_oa_payload  rhp_ikev1_nat_oa_payload;


/**********************

  Attribute Payload

***********************/

struct _rhp_ikev1_attr_attr {

	struct _rhp_ikev1_attr_attr* next;

	rhp_proto_ikev1_attr* attr_attrh;

	u16 attr_type;
	void (*set_attr_type)(struct _rhp_ikev1_attr_attr* attr_attr,u16 attr_type);
	u16 (*get_attr_type)(struct _rhp_ikev1_attr_attr* attr_attr);

	int attr_len;
	u8* attr_val;

	int (*get_attr_len)(struct _rhp_ikev1_attr_attr* attr_attr);
	u8* (*get_attr)(struct _rhp_ikev1_attr_attr* attr_attr);
	int (*set_attr)(struct _rhp_ikev1_attr_attr* attr_attr,int attr_len,u8* attr_val);
};
typedef struct _rhp_ikev1_attr_attr		rhp_ikev1_attr_attr;

struct _rhp_ikev1_attr_payload {

  u8 type;
  u8 reserved0;
  u16 reserved1;
  u8 (*get_type)(struct _rhp_ikev2_payload* payload);
  void (*set_type)(struct _rhp_ikev2_payload* payload,u8 cfg_type);

  int attr_num;
  rhp_ikev1_attr_attr* attr_attr_head;
  rhp_ikev1_attr_attr* attr_attr_tail;

  struct {
		rhp_ip_addr internal_addr_v4;
		rhp_ip_addr internal_addr_v6;
	} attr_attr_ext;

	int (*put_attr_rx)(struct _rhp_ikev2_payload* payload,rhp_proto_ikev1_attr* attr_attr); // Add to list tail.
  int (*enum_attr)(struct _rhp_ikev2_payload* payload,
        int (*callback)(struct _rhp_ikev2_payload* payload,rhp_ikev1_attr_attr* attr_attr,void* ctx),void* ctx);
  int (*alloc_and_put_attr)(struct _rhp_ikev2_payload* payload,u16 attr_type,int attr_len,u8* attr_val);
  rhp_ip_addr* (*get_attr_internal_addr_v4)(struct _rhp_ikev2_payload* payload);
  rhp_ip_addr* (*get_attr_internal_addr_v6)(struct _rhp_ikev2_payload* payload);
};
typedef struct _rhp_ikev1_attr_payload  rhp_ikev1_attr_payload;


struct _rhp_proto_ikev1_attribute_payload;

extern int rhp_ikev1_attr_payload_parse(
		struct _rhp_proto_ikev1_attribute_payload* attr_payloadh,int payload_len,struct _rhp_ikev2_payload* payload);


#endif // _RHP_IKEV1_MESG_H_
