/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifndef _RHP_IKESA_H_
#define _RHP_IKESA_H_

#include "rhp_timer.h"

/*

 - Initial Exchange

             [DEFAULT]<---------------------+
               |    |                        \
               |    |rcv IKE_SA_INIT(R)       \
 snd           |    |snd IKE_SA_INIT           \
 IKE_SA_INIT(R)|    +-----------+               \
               |                |                \
               V                V               [DEAD]
 [I_IKE_SA_INIT_SENT]   [R_IKE_SA_INIT_SENT]       \
 rcv         |            rcv IKE_AUTH(R)|          \
  IKE_SA_INIT|            snd IKE_AUTH   |           \
 snd         |                           |            \
  IKE_AUTH(R)|                           |             \
             V      rcv_IKE_AUTH         V     clear    \
      [I_AUTH_SENT]-------------->[ESTABLISHED]------>[DELETED]<---{ERROR!}
                                    |                      ^
                rcv CREATE_CHILD_SA |                      | rcv DELETE
                snd CREATE_CHILD_SA |                      | snd DELETE
                                    V                      |
                                   [REKEYING]--------------+



             [DEFAULT]<---------------------+
               |    |                        \
               |    |rcv IKE_SA_INIT(R)       \
 snd           |    |snd IKE_SA_INIT           \
 IKE_SA_INIT(R)|    +-----------+               \
               |                |                \
               V                V                 \
 [I_IKE_SA_INIT_SENT]   [R_IKE_SA_INIT_SENT]     [DEAD]
 rcv         |            rcv IKE_AUTH(R)|          \
  IKE_SA_INIT|            snd EAP(R)     |           \
 snd         |                           |            \
  IKE_AUTH(R)|                           |             +
             V                           V             |
      [I_AUTH_SENT]                  [R_EAP_SENT]      |
 rcv EAP(R)  |                          |     ^ \      |
 snd EAP     |                   rcv EAP|     |  \     |
             V              snd IKE_AUTH|     |   \    |
      [I_EAP_SENT]                      |     |    +   |
           / ^   \   rcv IKE_AUTH       |     |    |   |
          /  |    +---------------+     |     +----+   |
         /   |                     \    |   rcv EAP    |
        +----+                      +   |   snd EAP(R) |
    rcv EAP(R)                      |   |              |
    snd EAP                         V   V      clear   |
                                  [ESTABLISHED]----->[DELETED]<---{ERROR!}
                                    |                      ^
                rcv CREATE_CHILD_SA |                      | rcv DELETE
                snd CREATE_CHILD_SA |                      | snd DELETE
                                    V                      |
                                   [REKEYING]--------------+


 - Rekey Exchange

                               [DEFAULT]<-----------------------------------+
                                 |    |                                     |
                                 |    |rcv CREATE_CHILD_SA[IKE SA REKEY](R) |
 snd                             |    |snd CREATE_CHILD_SA[IKE SA REKEY]    |
 CREATE_CHILD_SA[IKE SA REKEY](R)|    |                                     |
                                 |    |                                     |
                                 V    |                                  [DEAD]
                      [I_REKEY_SENT]  |                                     |
                             rcv |    |                                     |
    CREATE_CHILD_SA[IKE SA REKEY]|    |                                     |
                                 |    |                                     |
                                 |    |                                     |
                                 V    V   clear                             |
                               [ESTABLISHED]-------------------------->[DELETED]<---{ERROR!}
                                    |                                     ^
                rcv CREATE_CHILD_SA |                                     | rcv DELETE
                snd CREATE_CHILD_SA |                                     | snd DELETE
                                    V                                     |
                                   [REKEYING]-----------------------------+

  (R) : request
  [STATE] : state
  snd : send
  rcv : receive

*/

#include "rhp_crypto.h"
#include "rhp_childsa.h"

struct _rhp_ifc_entry;
struct _rhp_vpn_realm;
struct _rhp_cfg_peer;
struct _rhp_ikev2_mesg;
struct _rhp_http_bus_session;
struct _rhp_vpn;
struct _rhp_ikesa_timers;
struct _rhp_ikev2_payload;
struct _rhp_ipcmsg_sess_resume_dec_rep;
struct _rhp_vpn_sess_resume_material;
struct _rhp_ikesa;

//
// 'P2 Session' means Quick mode exchange or Informational exchange.
//
struct _rhp_ikev1_p2_session {

	struct _rhp_ikev1_p2_session* next;

	u32 mesg_id;

	u8 exchange_type;
	u8 clear_aftr_proc;
	u16 reserved1;

  int iv_len;
  u8* dec_iv;
  u8* iv_last_rx_blk;

  u32 dpd_seq;
};
typedef struct _rhp_ikev1_p2_session	rhp_ikev1_p2_session;

extern rhp_ikev1_p2_session* rhp_ikev1_p2_session_alloc(u8 clear_aftr_proc);
extern void rhp_ikev1_p2_session_free(rhp_ikev1_p2_session* p2_sess);

extern rhp_ikev1_p2_session* rhp_ikev1_p2_session_get(struct _rhp_ikesa* ikesa,u32 mesg_id,u8 exchange_type);
extern int rhp_ikev1_p2_session_tx_put(struct _rhp_ikesa* ikesa,u32 mesg_id,u8 exchange_type,u32 dpd_seq,u8 clear_aftr_proc);
extern int rhp_ikev1_p2_session_rx_put(struct _rhp_ikesa* ikesa,struct _rhp_ikev2_mesg* rx_ikemesg,u8 clear_aftr_proc);
extern int rhp_ikev1_p2_session_clear(struct _rhp_ikesa* ikesa,u32 mesg_id,u8 exchange_type,u32 dpd_seq);




//
// [CAUTION]
//   Don't ref rhp_vpn obj from rhp_ikesa (for IKEv1 SA mngt).
//
struct _rhp_ikesa {

  unsigned char tag[4]; // "#ISA"

  struct _rhp_ikesa* next_vpn_list;
  struct _rhp_ikesa* next_ike_sa_init_i;

  u8 init_spi[RHP_PROTO_IKE_SPI_SIZE];
  u8 resp_spi[RHP_PROTO_IKE_SPI_SIZE];

  struct _rhp_ikesa_timers* timers;

  u8* (*get_my_spi)(struct _rhp_ikesa* ikesa);

  int rekeyed_gen;

  u32 gen_message_id;
  u32 rekey_ikesa_message_id;

  struct {
    int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
    u8 init_spi[RHP_PROTO_IKE_SPI_SIZE];
    u8 resp_spi[RHP_PROTO_IKE_SPI_SIZE];
  } parent_ikesa;

  int (*generate_init_spi)(struct _rhp_ikesa* ikesa);
  int (*generate_resp_spi)(struct _rhp_ikesa* ikesa);
  void (*set_init_spi)(struct _rhp_ikesa* ikesa,u8* spi);
  void (*set_resp_spi)(struct _rhp_ikesa* ikesa,u8* spi);


  int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER

#define RHP_IKESA_DYING_INTERVAL								1


#define RHP_IKESA_STAT_DEFAULT              		0

#define RHP_IKESA_STAT_I_IKE_SA_INIT_SENT   		1
#define RHP_IKESA_STAT_I_AUTH_SENT          		2
#define RHP_IKESA_STAT_I_AUTH_EAP_SENT          3	// Initiator sent AUTH payload after receiving EAP-Success.
#define RHP_IKESA_STAT_R_IKE_SA_INIT_SENT   		4
#define RHP_IKESA_STAT_ESTABLISHED          		5
#define RHP_IKESA_STAT_REKEYING	          			6
#define RHP_IKESA_STAT_DELETE				          	7	 // Start deleting IKE SA and sending D payloads.
#define RHP_IKESA_STAT_DELETE_WAIT		        	8  // Destroy IKE SA resource actually.
#define RHP_IKESA_STAT_I_REKEY_SENT							9  // Initial state for a new IKE SA.
#define RHP_IKESA_STAT_DEAD                 		10

#define RHP_IKESA_STAT_V1_MAIN_1ST_SENT_I				101
#define RHP_IKESA_STAT_V1_MAIN_3RD_SENT_I				102
#define RHP_IKESA_STAT_V1_MAIN_5TH_SENT_I				103
#define RHP_IKESA_STAT_V1_MAIN_2ND_SENT_R				104
#define RHP_IKESA_STAT_V1_MAIN_4TH_SENT_R				105

#define RHP_IKESA_STAT_V1_AGG_1ST_SENT_I				106
#define RHP_IKESA_STAT_V1_AGG_WAIT_COMMIT_I			107 // If commit-bit enabled. [TODO] Currently, not supported.
#define RHP_IKESA_STAT_V1_AGG_2ND_SENT_R				108

#define RHP_IKESA_STAT_V1_ESTABLISHED						109
#define RHP_IKESA_STAT_V1_REKEYING							110
#define RHP_IKESA_STAT_V1_DELETE				        111	// Start deleting IKE SA and sending D payloads.
#define RHP_IKESA_STAT_V1_DELETE_WAIT		        112 // Destroy IKE SA resource actually.
#define RHP_IKESA_STAT_V1_DEAD                 	113

#define RHP_IKESA_STAT_V1_XAUTH_PEND_I					114
#define RHP_IKESA_STAT_V1_XAUTH_PEND_R					115
  int state;


  int auth_method; 			// RHP_PROTO_IKE_AUTHMETHOD_XXX
  int peer_auth_method; // RHP_PROTO_IKE_AUTHMETHOD_XXX

  u32 ike_init_i_hash;
  struct {
    struct _rhp_ikev2_mesg* ikemesg_i_1st;
    struct _rhp_ikev2_mesg* ikemesg_r_2nd;
  } signed_octets;

  union {
  	rhp_res_sa_proposal v2;
  	rhp_res_ikev1_sa_proposal v1;
  } prop;

  rhp_crypto_nonce*  nonce_i;
  rhp_crypto_nonce*  nonce_r;
  rhp_crypto_dh*     dh;
  rhp_crypto_prf*    prf;
  rhp_crypto_integ*  integ_i;
  rhp_crypto_integ*  integ_r;
  rhp_crypto_encr*   encr;

  u8 padcnt;
  u8 reserved0;
  u16 reserved1;

  struct {
    int len;
    u8* key_octets; // v2: [sk_d | sk_ai | sk_ar | sk_ei | sk_er | sk_pi | sk_pr | sk_dmvpn_a | sk_dmvpn_e]
  } key_material;

  union {

  	struct {

  		int sk_d_len;
			u8* sk_d; // Pointer to key_material.octets

			int sk_a_len;
			u8* sk_ai; // Pointer to key_material.key_octets
			u8* sk_ar; // Pointer to key_material.key_octets

			int sk_e_len;
			u8* sk_ei; // Pointer to key_material.key_octets
			u8* sk_er; // Pointer to key_material.key_octets

			int sk_p_len;
			u8* sk_pi; // Pointer to key_material.key_octets
			u8* sk_pr; // Pointer to key_material.key_octets

			int sk_dmvpn_a_len;
			u8* sk_dmvpn_a; // Pointer to key_material.key_octets

			int sk_dmvpn_e_len;
			u8* sk_dmvpn_e; // Pointer to key_material.key_octets

  	} v2;

  	struct {

  		int iv_len;

  		u8* p1_iv_dec;
  		u8* p1_iv_rx_last_blk;

  		int skeyid_len;
  		u8* skeyid;

  		int skeyid_d_len;
  		u8* skeyid_d;

  		int skeyid_a_len;
  		u8* skeyid_a;

  		int skeyid_e_len;
  		u8* skeyid_e;

  		int sk_e_len;
  		u8* sk_e;

  	} v1;

  } keys;

  int (*generate_keys)(struct _rhp_ikesa* ikesa);
  int (*generate_new_keys)(struct _rhp_ikesa* old_ikesa,struct _rhp_ikesa* new_ikesa);

  int (*generate_keys_v1)(struct _rhp_ikesa* ikesa,int skeyid_len,u8* skeyid);

  struct {

    int cookie_len;
    u8* cookie;

#define RHP_IKESA_MAX_COOKIE_RETRIES	3
    int cookie_retry;

  } cookies;


  u32 req_message_id;

  rhp_packet* req_retx_pkt;
  void (*set_retrans_request)(struct _rhp_ikesa* ikesa,rhp_packet* pkt);

  struct _rhp_ikev2_mesg* req_retx_ikemesg;


  rhp_packet* rep_retx_pkt;
  void (*set_retrans_reply)(struct _rhp_ikesa* ikesa,rhp_packet* pkt);

  time_t rep_retx_last_time;
  unsigned long rep_retx_cnt;


  struct {

  	int req_pkts_num;
		rhp_packet_q req_pkts;

		int rep_pkts_num;
		rhp_packet_q rep_pkts;

  } rx_frag;

	void (*reset_req_frag_pkts_q)(struct _rhp_ikesa* ikesa);
	void (*reset_rep_frag_pkts_q)(struct _rhp_ikesa* ikesa);


  u64 ipc_txn_id;

  int busy_flag;

  int collision_detected;

  struct _rhp_ikev2_mesg* pend_rx_ikemesg;
  struct _rhp_ikev2_mesg* pend_tx_ikemesg;

	time_t created_time;
	time_t established_time;
	time_t expire_hard;
	time_t expire_soft;

  int peer_http_cert_lookup_supported;

  struct {
  	u32 req_mesg_id;
  } keep_alive;

  struct {

#define RHP_IKESA_EAP_STAT_DEFAULT	      0
#define RHP_IKESA_EAP_STAT_I_PEND         1
#define RHP_IKESA_EAP_STAT_R_PEND        	2
#define RHP_IKESA_EAP_STAT_I_COMP        	3
#define RHP_IKESA_EAP_STAT_R_COMP       	4
  	int state;

  	struct _rhp_ikev2_mesg* pend_rx_ikemesg; // 3rd or 4th IKEv2 message.

  	int pend_mesg_octets_i_len;
		u8* pend_mesg_octets_i;
		int pend_mesg_octets_r_len;
		u8* pend_mesg_octets_r;

  } eap;

  struct {

  	int my_token_enabled;
  	u8 my_token[RHP_IKEV2_QCD_TOKEN_LEN];
  	int my_token_set_by_sess_resume;

  	int peer_token_len;
  	u8* peer_token;

#define RHP_IKEV2_QCD_PEND_RX_REQ								1
#define RHP_IKEV2_QCD_PEND_RX_RESP							2
#define RHP_IKEV2_QCD_PEND_RX_RESP_SESS_RESUME	3
  	int pend_pos;
  	u64 ipc_txn_id;
    struct _rhp_ikev2_mesg* pend_rx_ikemesg;
    struct _rhp_ikev2_mesg* pend_tx_ikemesg;

  } qcd;


  int gen_by_sess_resume;

  struct {

  	struct {

			u64 ipc_txn_id;
			struct _rhp_ikev2_mesg* pend_rx_ikemesg;
			struct _rhp_ikev2_mesg* pend_tx_ikemesg;

			rhp_ipcmsg_sess_resume_dec_rep* dec_tkt_ipc_rep;

  	} resp;

  	struct {

  		// Don't free. Just a reference to 'vpn->sess_resume.material'.
  		struct _rhp_vpn_sess_resume_material* material;

  	} init;

  } sess_resume;


  int peer_is_rockhopper;
  int peer_rockhopper_ver;

  int tried_secondary_peer;


  struct {

  	// RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION or RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE
  	u8 p1_exchange_mode;
  	u8 commit_bit_enabled;
  	u8 tx_initial_contact;
  	u8 rx_initial_contact;
  	u8 dont_rekey;
  	u8 nat_t_d_done;
  	u16 reserved1;

  	struct _rhp_ikev2_mesg* tx_ikemesg;

    int enc_alg;
    int hash_alg;

    unsigned long lifetime; // (secs)

    int sai_b_len;
    u8* sai_b;

  	rhp_ikev1_p2_session* p2_sessions;

  	int p2_iv_material_len;
		u8* p2_iv_material;

		int rep_retx_pkts_num;
		rhp_packet_q rep_retx_pkts;

		u32 dpd_seq;

		// Rx Cert_Req payload's data from a remote peer.
	  //   An array of rhp_cert_data(s). Each rhp_cert_data object includes a trusted CA's DN.
	  //   rhp_cert_data->type == RHP_CERT_DATA_CA_DN.
	  //   rhp_cert_data->len NOT including the header structure(i.e. sizeof(rhp_cert_data)).
		int rx_ca_dn_ders_num;
	  int rx_ca_dn_ders_len;
	  u8* rx_ca_dn_ders;

	  int rx_psk_hash_len;
	  u8* rx_psk_hash;

	  rhp_packet_ref* mode_cfg_pending_pkt_ref;

	  time_t keep_alive_interval;
	  time_t nat_t_keep_alive_interval;

  } v1;



  struct {

  	u64 rx_packets;
  	u64 rx_encrypted_packets;

  	u64 rx_keep_alive_reply_packets;

  } statistics;


  void (*dump)(struct _rhp_ikesa* ikesa);

  void (*destructor)(struct _rhp_ikesa* ikesa);
};
typedef struct _rhp_ikesa rhp_ikesa;

extern void rhp_ikesa_set_state(rhp_ikesa* ikesa,int new_state);


extern rhp_ikesa* rhp_ikesa_new_i(rhp_vpn_realm* rlm,rhp_cfg_peer* cfg_peer,u16 dhgrp_id);
extern rhp_ikesa* rhp_ikesa_new_r(rhp_res_sa_proposal* res_prop);
extern int rhp_ikesa_r_init_params_bh(rhp_ikesa* ikesa,rhp_res_sa_proposal* res_prop);

extern rhp_ikesa* rhp_ikesa_v1_main_new_i(rhp_vpn_realm* rlm,rhp_cfg_peer* cfg_peer);
extern rhp_ikesa* rhp_ikesa_v1_main_new_r(rhp_res_ikev1_sa_proposal* res_prop);

extern rhp_ikesa* rhp_ikesa_v1_aggressive_new_i(rhp_vpn_realm* rlm,rhp_cfg_peer* cfg_peer,u16 dhgrp_id);
extern rhp_ikesa* rhp_ikesa_v1_aggressive_new_r(rhp_res_ikev1_sa_proposal* res_prop);


extern void rhp_ikesa_destroy(struct _rhp_vpn* vpn,rhp_ikesa* ikesa);

extern int rhp_ikesa_init();
extern int rhp_ikesa_cleanup();

struct _rhp_ikesa_init_i {

  unsigned char tag[4]; // "#III"

  struct _rhp_ikesa_init_i* next_hash;

  u8 my_resp_spi[RHP_PROTO_IKE_SPI_SIZE];

  rhp_ip_addr peer_addr;

  int ike_sa_init_i_len;
  u8* ike_sa_init_i;
  u32 ike_init_i_hash;
};
typedef struct _rhp_ikesa_init_i rhp_ikesa_init_i;

extern rhp_ikesa_init_i* rhp_ikesa_alloc_init_i(u8* my_resp_spi,rhp_ip_addr* peer_addr,struct _rhp_ikev2_mesg* rx_ikemesg);
extern void rhp_ikesa_free_init_i(rhp_ikesa_init_i* init_i);

extern int rhp_ikesa_init_i_get(rhp_packet* pkt_i,u8* my_resp_spi);
extern void rhp_ikesa_init_i_put(rhp_ikesa_init_i* init_i,u32* hval_r);
extern rhp_ikesa_init_i* rhp_ikesa_init_i_delete(u8* my_resp_spi,u32 hval);

extern int rhp_ikesa_crypto_setup_r(rhp_ikesa* ikesa);
extern int rhp_ikesa_crypto_setup_new_r(rhp_ikesa* old_ikesa,rhp_ikesa* new_ikesa);


extern u64 rhp_ikesa_new_ipc_txn_id();

static inline int _rhp_ikesa_negotiating(rhp_ikesa* ikesa)
{
	    // V2
  if( ikesa->state == RHP_IKESA_STAT_DEFAULT ||
	    ikesa->state == RHP_IKESA_STAT_I_IKE_SA_INIT_SENT ||
	    ikesa->state == RHP_IKESA_STAT_I_AUTH_SENT ||
	    ikesa->state == RHP_IKESA_STAT_R_IKE_SA_INIT_SENT ||
	    ikesa->state == RHP_IKESA_STAT_I_REKEY_SENT ||
	    // V1
	    ikesa->state == RHP_IKESA_STAT_V1_MAIN_1ST_SENT_I ||
	    ikesa->state == RHP_IKESA_STAT_V1_MAIN_3RD_SENT_I ||
	    ikesa->state == RHP_IKESA_STAT_V1_MAIN_5TH_SENT_I ||
	    ikesa->state == RHP_IKESA_STAT_V1_MAIN_2ND_SENT_R ||
	    ikesa->state == RHP_IKESA_STAT_V1_MAIN_4TH_SENT_R ||
	    ikesa->state == RHP_IKESA_STAT_V1_AGG_1ST_SENT_I  ||
	    ikesa->state == RHP_IKESA_STAT_V1_AGG_WAIT_COMMIT_I ||
	    ikesa->state == RHP_IKESA_STAT_V1_AGG_2ND_SENT_R ){
    return 1;
  }
  return 0;
}


extern void rhp_ikesa_half_open_sessions_inc();
extern void rhp_ikesa_half_open_sessions_dec();
extern void rhp_ikesa_open_req_per_sec_update();
extern int rhp_ikesa_cookie_active(int inc_statistics);


extern int rhp_ikesa_pkt_hash(rhp_packet* pkt,u32* hval_r,u8** head_r,int* len_r);
// hval_r: 20 bytes (SHA_DIGEST_LENGTH)
extern int rhp_ikesa_pkt_hash_v1(rhp_packet* pkt,u8** hval_r,int* hval_len_r,u8** head_r,int* len_r);


#endif // _RHP_IKESA_H_


