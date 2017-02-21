/*

 Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
 All rights reserved.

 You can redistribute and/or modify this software under the
 LESSER GPL version 2.1.
 See also LICENSE.txt and LICENSE_LGPL2.1.txt.

 */

#ifndef _RHP_PROCESS_H_
#define _RHP_PROCESS_H_

#include "rhp_protocol.h"

extern rhp_atomic_t rhp_process_is_active;
#define RHP_PROCESS_IS_ACTIVE()  (_rhp_atomic_read(&rhp_process_is_active))

#define RHP_PROCESS_ROLE_SYSPXY         	0
#define RHP_PROCESS_ROLE_MAIN             1
#define RHP_PROCESS_ROLE_MAX              1

extern int rhp_process_my_role; //  RHP_PROCESS_ROLE_XXX

extern int rhp_debug_flag;
extern char* rhp_main_conf_path;
extern char* rhp_syspxy_conf_path;

/*************************

      Process Table

 *************************/

struct _rhp_ipcmsg;

struct _rhp_prc_ipcmsg_wts_handler {

	// See rhp_wthreads.h

	/* key_seed is also struct _rhp_ipcmsg* ipcmsg. */

	unsigned long wts_type; // RHP_WTS_DISP_RULE_XXX
	int wts_disp_priority;	// RHP_WTS_DISP_LEVEL_XXX
	int wts_disp_wait;			// Use rhp_wts_dispach_check() or NOT.
	int wts_is_fixed_rule;	// Used for rhp_wts_dispach_ok().
	void (*wts_task_handler)(int worker_index,void* ipcmsg); /* ipcmsg: struct _rhp_ipcmsg*. This must be freed in this handler. */
};
typedef struct _rhp_prc_ipcmsg_wts_handler rhp_prc_ipcmsg_wts_handler;

struct _rhp_prc_ipcmsg_handler {

	struct _rhp_prc_ipcmsg_handler* next;

	unsigned long ipcmsg_type;

	void (*ipcmsg_handler)(struct _rhp_ipcmsg** ipcmsg);

	rhp_prc_ipcmsg_wts_handler* wts_handler_ctx;
};
typedef struct _rhp_prc_ipcmsg_handler	rhp_prc_ipcmsg_handler;



struct _rhp_process {

  unsigned char tag[4]; // "#PRC"

  int role; // RHP_PROCESS_ROLE_XXX

  pid_t pid;
  uid_t uid;
  gid_t gid;

  char* user_name;

  int core_dump;
  int debug;
  cap_t caps;

  int ipc_read_pipe;
  int ipc_write_pipe;

  rhp_thread_t sig_th;

  rhp_prc_ipcmsg_handler* ipcmsg_handlers;
};
typedef struct _rhp_process rhp_process;

extern rhp_process rhp_process_info[RHP_PROCESS_ROLE_MAX + 1]; // index :  RHP_PROCESS_ROLE_XXX
#define RHP_MY_PROCESS     (&(rhp_process_info[rhp_process_my_role]))
#define RHP_PEER_PROCESS   (&(rhp_process_info[(rhp_process_my_role == RHP_PROCESS_ROLE_SYSPXY \
? RHP_PROCESS_ROLE_MAIN : RHP_PROCESS_ROLE_SYSPXY )]))

extern int rhp_sig_clear();



//
// For users like ext libraries which need to handle IPC messages between a main process
// and a syspxy process. (ex. EAP libraries)
//
extern int rhp_ipc_register_handler(rhp_process* prc,unsigned long ipcmsg_type,
		void (*ipcmsg_handler)(struct _rhp_ipcmsg** ipcmsg),rhp_prc_ipcmsg_wts_handler* wts_handler_ctx);

extern void rhp_ipc_call_handler(rhp_process* prc,struct _rhp_ipcmsg** ipcmsg);




/*******************************************************

      IPC APIs (between MAIN and SYS_PROXY)

 ********************************************************/

struct _rhp_ipcmsg {

  unsigned char tag[4]; // "#IMS"

  unsigned int len;

#define RHP_IPC_RESERVED                        0
#define RHP_IPC_EXIT_REQUEST                    1
#define RHP_IPC_NOP															2

#define RHP_IPC_NETMNG_REGISTER        					10
#define RHP_IPC_NETMNG_UPDATE_IF       					11
#define RHP_IPC_NETMNG_UPDATE_ADDR							12
#define RHP_IPC_NETMNG_DELETE_IF       					13
#define RHP_IPC_NETMNG_DELETE_ADDR							14
#define RHP_IPC_NETMNG_VIF_CREATE  	  					15
#define RHP_IPC_NETMNG_VIF_DELETE  	  					16
#define RHP_IPC_NETMNG_VIF_UPDATE  	  					17
#define RHP_IPC_NETMNG_ROUTE_UPDATE							18
#define RHP_IPC_NETMNG_ROUTE_DELETE							19
#define RHP_IPC_NETMNG_DNSPXY_RDIR_START				20
#define RHP_IPC_NETMNG_DNSPXY_RDIR_END					21
#define RHP_IPC_NETMNG_BRIDGE_ADD								22
#define RHP_IPC_NETMNG_BRIDGE_DELETE						23
#define RHP_IPC_NETMNG_ROUTEMAP_UPDATED					24
#define RHP_IPC_NETMNG_ROUTEMAP_DELETED					25
#define RHP_IPC_NETMNG_VIF_EXEC_IPV6_AUTOCONF  	26

#define RHP_IPC_AUTH_BASIC_REQUEST           		100
#define RHP_IPC_AUTH_BASIC_REPLY             		101
#define RHP_IPC_AUTH_COOKIE_REQUEST           	102
#define RHP_IPC_AUTH_COOKIE_REPLY             	103

#define RHP_IPC_SIGN_REQUEST           					200
#define RHP_IPC_SIGN_PSK_REPLY         					201
#define RHP_IPC_SIGN_RSASIG_REPLY      					202 // Signature , my cert and chain.
#define RHP_IPC_VERIFY_PSK_REQUEST     					203
#define RHP_IPC_VERIFY_PSK_REPLY       					204
#define RHP_IPC_VERIFY_RSASIG_REQUEST 					205 // Signature , peer cert and chain.
#define RHP_IPC_VERIFY_RSASIG_REPLY    					206
#define RHP_IPC_CA_PUBKEY_DIGESTS_REQUEST				207
#define RHP_IPC_CA_PUBKEY_DIGESTS_REPLY         208
#define RHP_IPC_RESOLVE_MY_ID_REQUEST  					209
#define RHP_IPC_RESOLVE_MY_ID_REPLY    					210
#define RHP_IPC_VERIFY_AND_SIGN_REQUEST					211
#define RHP_IPC_VERIFY_AND_SIGN_REPLY  					212
#define RHP_IPC_EAP_SUP_VERIFY_REQUEST					213
#define RHP_IPC_EAP_SUP_VERIFY_REPLY						214
#define RHP_IPC_QCD_TOKEN_REQUEST								215
#define RHP_IPC_QCD_TOKEN_REPLY									216
#define RHP_IPC_QCD_GEN_REPLY_TOKEN_REQUEST			217
#define RHP_IPC_QCD_GEN_REPLY_TOKEN_REPLY				218
#define RHP_IPC_SESS_RESUME_ENC_REQUEST					219
#define RHP_IPC_SESS_RESUME_ENC_REPLY						220
#define RHP_IPC_SESS_RESUME_DEC_REQUEST					221
#define RHP_IPC_SESS_RESUME_DEC_REPLY						222

// IKEv1
#define RHP_IPC_IKEV1_PSK_SKEYID_REQUEST			260
#define RHP_IPC_IKEV1_PSK_SKEYID_REPLY				261
#define RHP_IPC_IKEV1_SIGN_RSASIG_REQUEST			262
#define RHP_IPC_IKEV1_SIGN_RSASIG_REPLY				263
#define RHP_IPC_IKEV1_VERIFY_RSASIG_REQUEST		264
#define RHP_IPC_IKEV1_VERIFY_RSASIG_REPLY			265
#define RHP_IPC_IKEV1_VERIFY_AND_SIGN_RSASIG_REQUEST		266
#define RHP_IPC_IKEV1_VERIFY_AND_SIGN_RSASIG_REPLY			267
#define RHP_IPC_IKEV1_RESOLVE_AUTH_REQUEST		268 // For aggressive mode.
#define RHP_IPC_IKEV1_RESOLVE_AUTH_REPLY			269


#define RHP_IPC_SYSPXY_CFG_REQUEST 					 		300
#define RHP_IPC_SYSPXY_CFG_REPLY				  			301
#define RHP_IPC_CA_PUBKEY_DIGESTS_UPDATE				302

#define RHP_IPC_SYSPXY_MEMORY_DBG        				400

#define RHP_IPC_SYSPXY_LOG_RECORD								500
#define RHP_IPC_SYSPXY_LOG_CTRL									501

// librhpeapa.so and librhpeaps.so
#define RHP_IPC_EAP_AUTH_HANDLE_REQUEST						600
#define RHP_IPC_EAP_AUTH_HANDLE_REPLY							601
#define RHP_IPC_EAP_AUTH_HANDLE_CANCEL						602
#define RHP_IPC_EAP_SUP_HANDLE_REQUEST						603
#define RHP_IPC_EAP_SUP_HANDLE_REPLY							604
#define RHP_IPC_EAP_SUP_HANDLE_CANCEL							605
#define RHP_IPC_EAP_SUP_USER_KEY_REQUEST					606
#define RHP_IPC_EAP_SUP_USER_KEY									607
#define RHP_IPC_EAP_SUP_USER_KEY_CACHED						608
#define RHP_IPC_EAP_SUP_USER_KEY_CLEAR_CACHE			609

#define RHP_IPC_XAUTH_AUTH_HANDLE_REQUEST					650
#define RHP_IPC_XAUTH_AUTH_HANDLE_REPLY						651
#define RHP_IPC_XAUTH_AUTH_HANDLE_CANCEL					652


#define RHP_IPC_FIREWALL_RULES_APPLY						700

// librhpradius.so
#define RHP_IPC_RADIUS_MESG_AUTH_REQUEST				800
#define RHP_IPC_RADIUS_MESG_AUTH_REPLY					801
#define RHP_IPC_RADIUS_MESG_SIGN_REQUEST				802
#define RHP_IPC_RADIUS_MESG_SIGN_REPLY					803

  unsigned long type;
};
typedef struct _rhp_ipcmsg rhp_ipcmsg;

#define RHP_IPC_USER_ADMIN_SERVER_HTTP		1

struct _rhp_ipcmsg_nm_request {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
};
typedef struct _rhp_ipcmsg_nm_request rhp_ipcmsg_nm_request;

struct _rhp_ipcmsg_nm_update_if {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  rhp_if_entry info;
};
typedef struct _rhp_ipcmsg_nm_update_if rhp_ipcmsg_nm_update_if;
typedef struct _rhp_ipcmsg_nm_update_if rhp_ipcmsg_nm_update_addr;
typedef struct _rhp_ipcmsg_nm_update_if rhp_ipcmsg_nm_delete_addr;
typedef struct _rhp_ipcmsg_nm_update_if rhp_ipcmsg_nm_config;

struct _rhp_ipcmsg_nm_delete_if {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  char if_name[RHP_IFNAMSIZ];
};
typedef struct _rhp_ipcmsg_nm_delete_if rhp_ipcmsg_nm_delete_if;

struct _rhp_ipcmsg_vif_create {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  unsigned long vpn_realm_id;
  unsigned int interface_type; // RHP_VIF_TYPE_XXX
  rhp_if_entry info_v4; // IPv4
  rhp_if_entry info_v6;	// IPv6
  unsigned int exec_up_down;
  unsigned int v6_disable; 	// 1: disable
#define RHP_IPC_VIF_V6_AUTOCONF_DISABLE				0
#define RHP_IPC_VIF_V6_AUTOCONF_ENABLE				1
#define RHP_IPC_VIF_V6_AUTOCONF_ENABLE_ADDR		2
  unsigned int v6_autoconf; // 0: disable, 1: enable
};
typedef struct _rhp_ipcmsg_vif_create rhp_ipcmsg_vif_create;

struct _rhp_ipcmsg_vif_update {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  unsigned long vpn_realm_id;
  unsigned int interface_type; // RHP_VIF_TYPE_XXX
#define RHP_IPC_VIF_UPDATE_MTU		1
#define RHP_IPC_VIF_UPDATE_ADDR		2
#define RHP_IPC_VIF_DELETE_ADDR		4
  unsigned int updated_flag;
  rhp_if_entry if_info;
};
typedef struct _rhp_ipcmsg_vif_update rhp_ipcmsg_vif_update;

struct _rhp_ipcmsg_vif_delete {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  unsigned long vpn_realm_id;
  unsigned int interface_type; // RHP_VIF_TYPE_XXX
  char if_name[RHP_IFNAMSIZ];
};
typedef struct _rhp_ipcmsg_vif_delete rhp_ipcmsg_vif_delete;

struct _rhp_ipcmsg_nm_route_update {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  unsigned long vpn_realm_id;
  char if_name[RHP_IFNAMSIZ];
  rhp_ip_addr dest_addr;
  rhp_ip_addr nexthop_addr;
  unsigned int metric;
};
typedef struct _rhp_ipcmsg_nm_route_update rhp_ipcmsg_nm_route_update;

struct _rhp_ipcmsg_nm_route_delete {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  unsigned long vpn_realm_id;
  char if_name[RHP_IFNAMSIZ];
  rhp_ip_addr dest_addr;
  rhp_ip_addr nexthop_addr;
};
typedef struct _rhp_ipcmsg_nm_route_delete rhp_ipcmsg_nm_route_delete;

struct _rhp_ipcmsg_nm_route_map_updated {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  rhp_rt_map_entry info;
};
typedef struct _rhp_ipcmsg_nm_route_map_updated rhp_ipcmsg_nm_route_map_updated;
typedef struct _rhp_ipcmsg_nm_route_map_updated rhp_ipcmsg_nm_route_map_deleted;


struct _rhp_ipcmsg_netmng_dns_pxy_rdir {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u16 reserved;
  u16 internal_port;
  rhp_ip_addr inet_name_server_addr;
};
typedef struct _rhp_ipcmsg_netmng_dns_pxy_rdir rhp_ipcmsg_netmng_dns_pxy_rdir;

struct _rhp_ipcmsg_netmng_bridge_ctrl {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u16 reserved;
  char bridge_name[RHP_IFNAMSIZ];
  char vif_name[RHP_IFNAMSIZ];
};
typedef struct _rhp_ipcmsg_netmng_bridge_ctrl rhp_ipcmsg_netmng_bridge_ctrl;


struct _rhp_ipcmsg_auth_comm {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
};
typedef struct _rhp_ipcmsg_auth_comm rhp_ipcmsg_auth_comm;

struct _rhp_ipcmsg_auth_basic_req {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long request_user; // RHP_IPC_REQ_USER_XXXX
  unsigned int id_len;
  unsigned int password_len;
  unsigned long vpn_realm_id;
  /* followed by id and password */
};
typedef struct _rhp_ipcmsg_auth_basic_req	rhp_ipcmsg_auth_basic_req;

struct _rhp_ipcmsg_auth_rep {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long request_user; // RHP_IPC_REQ_USER_XXXX
  unsigned int id_len;
  unsigned long vpn_realm_id;
  unsigned int is_nobody; // Only limited operations allowed by UI.
  unsigned int result; //  1 : Success , 0 : Failed
/* followed by id */
};
typedef struct _rhp_ipcmsg_auth_rep rhp_ipcmsg_auth_rep;

struct _rhp_ipcmsg_auth_cookie_req {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long request_user; // RHP_IPC_REQ_USER_XXXX
  unsigned int id_len;
  unsigned int nonce_len;
  unsigned int ticket_len;
  unsigned long vpn_realm_id;
  /* followed by id, nonce, and ticket */
};
typedef struct _rhp_ipcmsg_auth_cookie_req	rhp_ipcmsg_auth_cookie_req;



struct _rhp_ipcmsg_sign_req {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long my_realm_id;
  unsigned int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 spi[RHP_PROTO_IKE_SPI_SIZE];
  unsigned int prf_method; // RHP_PROTO_IKE_TRANSFORM_ID_PRF_XXXX
  unsigned int mesg_octets_len;
  unsigned int sk_p_len;
  unsigned int certs_bin_max_size;
  unsigned int ca_pubkey_dgst_len; 	// CA pubkey digest len (SHA-1 MD: 20bytes)
  unsigned int ca_pubkey_dgsts_len; // CA pubkey digests len
  unsigned int http_cert_lookup_supported;
  unsigned int qcd_enabled;
  u8 peer_spi[RHP_PROTO_IKE_SPI_SIZE];
  unsigned int auth_tkt_session_key_len;
  /* followed by mesg_octets, sk_p, CA keys_octets, and/or auth_tkt_session_key */
};
typedef struct _rhp_ipcmsg_sign_req rhp_ipcmsg_sign_req;

struct _rhp_ipcmsg_sign_rep {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned int auth_method; // RHP_PROTO_IKE_AUTHMETHOD_XXX
  unsigned long my_realm_id;
  unsigned int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 spi[RHP_PROTO_IKE_SPI_SIZE];
  unsigned int eap_role; // RHP_EAP_XXX
  unsigned int eap_method; // RHP_PROTO_EAP_TYPE_XXX
  unsigned int result; //  1 : Success , 0 : Failed
  unsigned int signed_octets_len;
  unsigned int cert_chain_num;
  unsigned int cert_chain_len;
  unsigned int ca_pubkey_dgst_len; // CA pubkey digest len (SHA-1 MD: 20bytes)
  unsigned int ca_pubkey_dgsts_len; // CA pubkey digests len
#define RHP_IKEV2_QCD_TOKEN_LEN		64 // bytes
  unsigned int qcd_enabled;
  unsigned char my_qcd_token[RHP_IKEV2_QCD_TOKEN_LEN];
/* followed by signed_octets , my_cert(rhp_cert_data) , chain(rhp_cert_data(s)),
   CA key_octets and qcd_token(if any) */
};
typedef struct _rhp_ipcmsg_sign_rep rhp_ipcmsg_sign_rep;

struct _rhp_ipcmsg_verify_req {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long my_realm_id; // If NOT specified , 0xFFFFFFFF
  unsigned int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 spi[RHP_PROTO_IKE_SPI_SIZE];
  unsigned int prf_method; // RHP_PROTO_IKE_TRANSFORM_ID_PRF_XXXX
  unsigned int eap_requested;
  unsigned int my_id_type; // RHP_PROTO_IKE_ID_XXX
  unsigned int my_id_len;
  unsigned int peer_id_type; // RHP_PROTO_IKE_ID_XXX
  unsigned int peer_id_len;
  unsigned int peer_auth_method;
  unsigned int peer_cert_bin_len;
  unsigned int cert_chain_num;
  unsigned int cert_chain_bin_len;
  unsigned int mesg_octets_len;
  unsigned int signature_octets_len;
  unsigned long peer_notified_realm_id; // If NOT specified , 0xFFFFFFFF
  unsigned int ikev2_null_auth_sk_px_len;
  unsigned long auth_tkt_hb2spk_realm_id;
  unsigned int auth_tkt_session_key_len;
/* followed by my id,  peer id , sk_px, peer cert, cert chains,
   mesg_octets, signature octets and/or auth_tkt_session_key */
};
typedef struct _rhp_ipcmsg_verify_req rhp_ipcmsg_verify_req;

struct _rhp_ipcmsg_verify_rep {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long my_realm_id;
  unsigned int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 spi[RHP_PROTO_IKE_SPI_SIZE];
  unsigned int result; //  1 : Success , 0 : Failed
  unsigned int eap_role; // RHP_EAP_XXX
  unsigned int eap_method; // RHP_PROTO_EAP_TYPE_XXX
  unsigned int alt_peer_id_len;
  unsigned int alt_peer_id_type; // sizeof(u8)
  /* Followed by alt_peer_id_value(ex: Cert's DN or subjectAltName) */
};
typedef struct _rhp_ipcmsg_verify_rep rhp_ipcmsg_verify_rep;

struct _rhp_ipcmsg_ca_keys_req {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long my_realm_id;
  unsigned int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 spi[RHP_PROTO_IKE_SPI_SIZE];
};
typedef struct _rhp_ipcmsg_ca_keys_req rhp_ipcmsg_ca_keys_req;

struct _rhp_ipcmsg_ca_keys_rep {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long my_realm_id;
  unsigned int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 spi[RHP_PROTO_IKE_SPI_SIZE];
  unsigned int result; //  1 : Success , 0 : Failed
  unsigned int ca_pubkey_dgst_len; // CA pubkey digest len (SHA-1 MD: 20bytes)
  unsigned int ca_pubkey_dgsts_len; // CA pubkey digests len
/* followed by keyts_octets */
};
typedef struct _rhp_ipcmsg_ca_keys_rep rhp_ipcmsg_ca_keys_rep;

struct _rhp_ipcmsg_resolve_my_id_req {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long my_realm_id;
};
typedef struct _rhp_ipcmsg_resolve_my_id_req rhp_ipcmsg_resolve_my_id_req;

struct _rhp_ipcmsg_resolve_my_id_rep {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long my_realm_id;
  unsigned int result; //  1 : Success , 0 : Failed
  unsigned int my_id_type; // RHP_PROTO_IKE_ID_XXX
  unsigned int my_id_len;
  unsigned int my_auth_method;
  unsigned int eap_sup_enabled;
  unsigned int eap_sup_method; // RHP_PROTO_EAP_TYPE_XXX
  unsigned int eap_sup_ask_for_user_key;
  unsigned int eap_sup_user_key_cache_enabled;
  unsigned int psk_for_peers;
  unsigned int rsa_sig_for_peers;
  unsigned int eap_for_peers;
  unsigned int null_auth_for_peers;
  unsigned int xauth_method;
  unsigned int my_cert_issuer_dn_der_len;
  unsigned int untrust_sub_ca_cert_issuer_dn_der_len;
  /* followed by my id, my cert's issuer DN DER and
   * untrust sub CA cert's issuer DN DER.*/
};
typedef struct _rhp_ipcmsg_resolve_my_id_rep rhp_ipcmsg_resolve_my_id_rep;

extern rhp_ipcmsg_resolve_my_id_rep* rhp_auth_ipc_alloc_rslv_my_id_rep(unsigned long rlm_id,u64 txn_id,
		int result,int id_type,int id_len,u8* id_value,int my_auth_method,int my_xauth_method,
		int eap_sup_enabled,int eap_sup_ask_for_user_key,int eap_sup_method,int eap_sup_user_key_cache_enabled,
	  int psk_for_peers,int rsa_sig_for_peers,int eap_for_peers,int null_auth_for_peers,
	  int my_cert_issuer_dn_der_len,u8* my_cert_issuer_dn_der,
	  int untrust_sub_ca_cert_issuer_dn_der_len,u8* untrust_sub_ca_cert_issuer_dn_der);


struct _rhp_ipcmsg_verify_and_sign_req {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  // RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION or RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE
  unsigned int v1_exchange_type;
/* followed by rhp_ipcmsg_verify_req and rhp_ipcmsg_sign_req  */
};
typedef struct _rhp_ipcmsg_verify_and_sign_req rhp_ipcmsg_verify_and_sign_req;

struct _rhp_ipcmsg_verify_and_sign_rep {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  // RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION or RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE
  unsigned int v1_exchange_type;
/* followed by rhp_ipcmsg_verify_rep and rhp_ipcmsg_sign_rep  */
};
typedef struct _rhp_ipcmsg_verify_and_sign_rep rhp_ipcmsg_verify_and_sign_rep;

struct __rhp_ipcmsg_syspxy_cfg_sub {

#define RHP_IPC_SYSPXY_CFG_NONE										0
#define RHP_IPC_SYSPXY_CFG_GET										1
#define RHP_IPC_SYSPXY_CFG_CREATE_REALM						2
#define RHP_IPC_SYSPXY_CFG_UPDATE_REALM						3
#define RHP_IPC_SYSPXY_CFG_DELETE_REALM						4
#define RHP_IPC_SYSPXY_CFG_GET_KEY_INFO						5
#define RHP_IPC_SYSPXY_CFG_UPDATE_KEY_INFO				6
#define RHP_IPC_SYSPXY_CFG_DELETE_KEY_INFO				7
#define RHP_IPC_SYSPXY_CFG_UPDATE_CERT						8
#define RHP_IPC_SYSPXY_CFG_DELETE_CERT						9
#define RHP_IPC_SYSPXY_CFG_UPDATE_ADMIN						10
#define RHP_IPC_SYSPXY_CFG_DELETE_ADMIN						11
#define RHP_IPC_SYSPXY_CFG_GET_PRINTED_CERTS			12
#define RHP_IPC_SYSPXY_CFG_ENUM_ADMIN							13
#define RHP_IPC_SYSPXY_CFG_BKUP_SAVE							14
#define RHP_IPC_SYSPXY_CFG_UPLOAD_CERT_FILE				15
#define RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE				16
#define RHP_IPC_SYSPXY_CFG_RSRC_STATISTICS				17
#define RHP_IPC_SYSPXY_CFG_ENABLE_REALM						18
#define RHP_IPC_SYSPXY_CFG_DISABLE_REALM					19
#define RHP_IPC_SYSPXY_CFG_RESET_QCD_KEY					20
#define RHP_IPC_SYSPXY_CFG_RESET_SESS_RESUME_KEY	21
#define RHP_IPC_SYSPXY_CFG_UPDATE_RADIUS_MNG			22
  unsigned int cfg_type;
  unsigned long len;
  unsigned long target_rlm_id;
  unsigned int result;
  unsigned int config_updated;
  unsigned long priv[4];
};
typedef struct __rhp_ipcmsg_syspxy_cfg_sub rhp_ipcmsg_syspxy_cfg_sub;

#define RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE_PKCS12							0x01
#define RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE_MY_CERT_PEM					0x02
#define RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE_MY_PRIVKEY_PEM			0x04
#define RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE_CA_PEM							0x08
#define RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE_CRL_PEM							0x10

#define RHP_IPC_SYSPXY_CFG_GET_PRINTED_CERTS_MY_CERT						0
#define RHP_IPC_SYSPXY_CFG_GET_PRINTED_CERTS_CA_CERTS						1
#define RHP_IPC_SYSPXY_CFG_GET_PRINTED_CERTS_CRL								2



struct _rhp_ipcmsg_syspxy_cfg_req {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long request_user; // RHP_IPC_REQ_USER_XXXX
  u64 http_bus_session_id;
  unsigned int opr_user_name_len;
  /* followed by opr_user_name */
};
typedef struct _rhp_ipcmsg_syspxy_cfg_req rhp_ipcmsg_syspxy_cfg_req;

struct _rhp_ipcmsg_syspxy_cfg_rep {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long request_user; // RHP_IPC_REQ_USER_XXXX
  u64 http_bus_session_id;
  unsigned int opr_user_name_len;
  /* followed by opr_user_name */
};
typedef struct _rhp_ipcmsg_syspxy_cfg_rep rhp_ipcmsg_syspxy_cfg_rep;

struct _rhp_ipcmsg_ca_pubkey_digests {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  unsigned int pubkey_digest_len;
  unsigned int pubkey_digests_len;
  unsigned int dn_ders_len;
  unsigned int dn_ders_num;
  /* followed by CA pubkey digests and CA DN DERs */
  /* CA DN DERs: An array of rhp_cert_data(s) [rhp_cert.h]. */
  /*             Each rhp_cert_data object includes a trusted CA's DN. */
	/*             rhp_cert_data->type == RHP_CERT_DATA_CA_DN. */
	/*             rhp_cert_data->len NOT including the header structure (i.e. sizeof(rhp_cert_data)). */
};
typedef struct _rhp_ipcmsg_ca_pubkey_digests	rhp_ipcmsg_ca_pubkey_digests;

extern int rhp_auth_ipc_send_ca_pubkey_digests_update();


struct _rhp_ipcmsg_syspxy_mem_dbg {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  unsigned int start_time;
  unsigned int elapsing_time;
};
typedef struct _rhp_ipcmsg_syspxy_mem_dbg rhp_ipcmsg_syspxy_mem_dbg;



struct _rhp_ipcmsg_syspxy_log_ctrl {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  unsigned int debug_flag;
};
typedef struct _rhp_ipcmsg_syspxy_log_ctrl rhp_ipcmsg_syspxy_log_ctrl;

struct _rhp_ipcmsg_syspxy_log_record {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
	unsigned long event_source;
	unsigned long vpn_realm_id;
	unsigned long level;
	unsigned long log_id;
	struct timeval timestamp;
	unsigned int log_content_len;
	/* log_content... */
};
typedef struct _rhp_ipcmsg_syspxy_log_record rhp_ipcmsg_syspxy_log_record;



// Header : rhp_ipcmsg_auth_comm
struct _rhp_ipcmsg_eap_handle_req {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long vpn_realm_id;
  u8 unique_id[16]; // RHP_VPN_UNIQUE_ID_SIZE: 16bytes
  unsigned int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 spi[RHP_PROTO_IKE_SPI_SIZE];
  unsigned int init_req; // For Responder(Authenticator)
  unsigned int eap_mesg_len;
  unsigned int eap_method;
  unsigned long peer_notified_realm_id;
  unsigned int is_init_req;
  /* EAP Message or IKEv1 Attribute payload */
};
typedef struct _rhp_ipcmsg_eap_handle_req	rhp_ipcmsg_eap_handle_req;

// Header : rhp_ipcmsg_auth_comm
struct _rhp_ipcmsg_eap_handle_rep {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long vpn_realm_id;
  unsigned long rebound_vpn_realm_id; // For Responder(Authenticator)
  u8 unique_id[16]; // RHP_VPN_UNIQUE_ID_SIZE: 16bytes
  unsigned int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 spi[RHP_PROTO_IKE_SPI_SIZE];
  unsigned int status; // RHP_EAP_STAT_XXX
  unsigned int eap_mesg_len;
  unsigned int msk_len;
  unsigned int peer_identity_len; // For Responder(Authenticator)
  unsigned int my_identity_len; 	// For Initiator(Supplicant)
  unsigned int is_init_req;
  /* EAP Message, MSK(if any) and Peer Identity or My Identity(if any) */
};
typedef struct _rhp_ipcmsg_eap_handle_rep	rhp_ipcmsg_eap_handle_rep;

struct _rhp_ipcmsg_eap_handle_cancel {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  unsigned long vpn_realm_id;
  u8 unique_id[16]; // RHP_VPN_UNIQUE_ID_SIZE: 16bytes
};
typedef struct _rhp_ipcmsg_eap_handle_cancel	rhp_ipcmsg_eap_handle_cancel;

// Header : rhp_ipcmsg_auth_comm
struct _rhp_ipcmsg_eap_user_key_req {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long vpn_realm_id;
  u8 unique_id[16]; // RHP_VPN_UNIQUE_ID_SIZE: 16bytes
  unsigned int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 spi[RHP_PROTO_IKE_SPI_SIZE];
  unsigned int eap_method;
  unsigned int user_id_len; 	// \0 NOT included
  /* User ID (if any) */
};
typedef struct _rhp_ipcmsg_eap_user_key_req	rhp_ipcmsg_eap_user_key_req;

// Header : rhp_ipcmsg_auth_comm
struct _rhp_ipcmsg_eap_user_key {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long vpn_realm_id;
  u8 unique_id[16]; // RHP_VPN_UNIQUE_ID_SIZE: 16bytes
  unsigned int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 spi[RHP_PROTO_IKE_SPI_SIZE];
  unsigned int eap_method;
  unsigned int user_id_len; 	// \0 NOT included
  unsigned int user_key_len; 	// \0 NOT included
  /* User ID and key (if any) */
};
typedef struct _rhp_ipcmsg_eap_user_key	rhp_ipcmsg_eap_user_key;

struct _rhp_ipcmsg_eap_user_key_cached {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  unsigned long vpn_realm_id;
};
typedef struct _rhp_ipcmsg_eap_user_key_cached	rhp_ipcmsg_eap_user_key_cached;

struct _rhp_ipcmsg_eap_user_key_clear_cache {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  unsigned long vpn_realm_id;
};
typedef struct _rhp_ipcmsg_eap_user_key_clear_cache	rhp_ipcmsg_eap_user_key_clear_cache;



struct _rhp_ipcmsg_qcd_token_req {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long my_realm_id;
  unsigned int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 spi[RHP_PROTO_IKE_SPI_SIZE];
  u8 peer_spi[RHP_PROTO_IKE_SPI_SIZE];
  unsigned int old_ikesa;
  unsigned int old_side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 old_spi[RHP_PROTO_IKE_SPI_SIZE];
  u8 old_peer_spi[RHP_PROTO_IKE_SPI_SIZE];
};
typedef struct _rhp_ipcmsg_qcd_token_req rhp_ipcmsg_qcd_token_req;

struct _rhp_ipcmsg_qcd_token_rep {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long my_realm_id;
  unsigned int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 spi[RHP_PROTO_IKE_SPI_SIZE];
  u8 peer_spi[RHP_PROTO_IKE_SPI_SIZE];
  unsigned int old_ikesa;
  unsigned int old_side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 old_spi[RHP_PROTO_IKE_SPI_SIZE];
  u8 old_peer_spi[RHP_PROTO_IKE_SPI_SIZE];
  unsigned int result;
  u8 my_token[RHP_IKEV2_QCD_TOKEN_LEN];
};
typedef struct _rhp_ipcmsg_qcd_token_rep rhp_ipcmsg_qcd_token_rep;

struct _rhp_ipcmsg_qcd_gen_rep_tkn_req {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u8 init_spi[RHP_PROTO_IKE_SPI_SIZE];
  u8 resp_spi[RHP_PROTO_IKE_SPI_SIZE];
  unsigned int cookie_len;
  /* cookie data */
};
typedef struct _rhp_ipcmsg_qcd_gen_rep_tkn_req rhp_ipcmsg_qcd_gen_rep_tkn_req;

struct _rhp_ipcmsg_qcd_gen_rep_tkn_rep {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  unsigned int cookie_len;
  u8 token[RHP_IKEV2_QCD_TOKEN_LEN];
  /* cookie data */
};
typedef struct _rhp_ipcmsg_qcd_gen_rep_tkn_rep rhp_ipcmsg_qcd_gen_rep_tkn_rep;



struct _rhp_ipcmsg_sess_resume_enc_req {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long my_realm_id;
  unsigned int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 spi[RHP_PROTO_IKE_SPI_SIZE];
  u8 peer_spi[RHP_PROTO_IKE_SPI_SIZE];
  unsigned int old_ikesa; // For Rekey exchg
  unsigned int old_side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 old_spi[RHP_PROTO_IKE_SPI_SIZE];
  u8 old_peer_spi[RHP_PROTO_IKE_SPI_SIZE];
  int64_t expired_time; // secs
  unsigned int qcd_enabled;
  unsigned int tkt_len;
  unsigned int radius_tkt_len;
  unsigned char my_qcd_token[RHP_IKEV2_QCD_TOKEN_LEN];
  unsigned int result; // For rhp_ipcmsg_sess_resume_enc_rep and rhp_ipcmsg_sess_resume_dec_rep.
  /* ticket data (rhp_sess_resume_tkt: rhp_protocol.h), if any. */
  /* ticket data (rhp_radius_sess_ressume_tkt: rhp_protocol.h), if any. */
};
typedef struct _rhp_ipcmsg_sess_resume_enc_req rhp_ipcmsg_sess_resume_enc_req;
typedef struct _rhp_ipcmsg_sess_resume_enc_req rhp_ipcmsg_sess_resume_enc_rep;
typedef struct _rhp_ipcmsg_sess_resume_enc_req rhp_ipcmsg_sess_resume_dec_req;
typedef struct _rhp_ipcmsg_sess_resume_enc_req rhp_ipcmsg_sess_resume_dec_rep;



// Header : rhp_ipcmsg_auth_comm
struct _rhp_ipcmsg_radius_mesg_auth_req {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned int authenticator_len;
  unsigned int mesg_len;
  unsigned int secret_index;
  unsigned int eap_method;
  unsigned long vpn_realm_id;
  unsigned long peer_notified_realm_id;
  unsigned int user_name_len;
  /* Tx RADIUS header's Authenticator value (16 bytes) */
  /* Rx RADIUS Mesg data (rhp_proto_radius*) */
  /* user_name(eap_peerid_i) (if any) */
};
typedef struct _rhp_ipcmsg_radius_mesg_auth_req rhp_ipcmsg_radius_mesg_auth_req;

// Header : rhp_ipcmsg_auth_comm
struct _rhp_ipcmsg_radius_mesg_auth_rep {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  int error; // 0: Success, !0: error code
  unsigned int error_notify;
  unsigned int mesg_len;
  unsigned int msk_len;
  unsigned long rebound_rlm_id;
  /* Rx RADIUS header data (rhp_proto_radius*) */
  /* MSK (Pre-shared-key) value (if any) */
};
typedef struct _rhp_ipcmsg_radius_mesg_auth_rep rhp_ipcmsg_radius_mesg_auth_rep;

// Header : rhp_ipcmsg_auth_comm
struct _rhp_ipcmsg_radius_mesg_sign_req {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned int mesg_len;
  unsigned int secret_index;
  /* Tx RADIUS Mesg data (rhp_proto_radius*) */
};
typedef struct _rhp_ipcmsg_radius_mesg_sign_req rhp_ipcmsg_radius_mesg_sign_req;

// Header : rhp_ipcmsg_auth_comm
struct _rhp_ipcmsg_radius_mesg_sign_rep {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned int result;
  unsigned int authenticator_len;
  unsigned int mesg_hash_len;
  /* Tx RADIUS header's Authenticator value (16 bytes) */
  /* MD5 Hash value (16 bytes) */
};
typedef struct _rhp_ipcmsg_radius_mesg_sign_rep rhp_ipcmsg_radius_mesg_sign_rep;



struct _rhp_ipcmsg_ikev1_psk_skeyid_req {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long my_realm_id; // If NOT specified , 0xFFFFFFFF
  unsigned int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 spi[RHP_PROTO_IKE_SPI_SIZE];
  // RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION or RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE
  unsigned int exchange_type;
  unsigned int prf_method; // RHP_PROTO_IKE_TRANSFORM_ID_PRF_XXXX (IKEv2)
  unsigned int peer_id_type; // RHP_PROTO_IKE_ID_XXX
  unsigned int peer_id_len;
  unsigned int mesg_octets_len;
  unsigned long peer_notified_realm_id; // If NOT specified , 0xFFFFFFFF
  /* followed by peer id and mesg_octets (Ni_b | Nr_b). */
};
typedef struct _rhp_ipcmsg_ikev1_psk_skeyid_req rhp_ipcmsg_ikev1_psk_skeyid_req;

struct _rhp_ipcmsg_ikev1_psk_skeyid_rep {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long my_realm_id;
  unsigned int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 spi[RHP_PROTO_IKE_SPI_SIZE];
  // RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION or RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE
  unsigned int exchange_type;
  unsigned int result; //  1 : Success , 0 : Failed
  unsigned int skeyid_len;
  unsigned int eap_role; // RHP_EAP_XXX
  unsigned int eap_method; // RHP_PROTO_EAP_TYPE_XXX
  /* Followed by SKEYID octets. */
};
typedef struct _rhp_ipcmsg_ikev1_psk_skeyid_rep rhp_ipcmsg_ikev1_psk_skeyid_rep;


struct _rhp_ipcmsg_ikev1_rsasig_sign_req {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long my_realm_id;
  unsigned int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 spi[RHP_PROTO_IKE_SPI_SIZE];
  // RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION or RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE
  unsigned int exchange_type;
  unsigned int prf_method; // RHP_PROTO_IKE_TRANSFORM_ID_PRF_XXXX (IKEv2)
  unsigned int mesg_octets_len; // If skeyid_len is zero, this is HASH_I/R value itself.
  unsigned int skeyid_len; // If this is specified, my_id is appended at the tail of
                           // mesg_octets and HASH_I/R is calculated before SIG_I/R is
  												 // generated.
  unsigned int certs_bin_max_size;
  unsigned int ca_dn_ders_len; // Len of CA DERs.
  unsigned int ca_dn_ders_num; // Num of CA Ders.
  /* followed by mesg_octets, skeyid(if any) and/or CA DN DERs */
  // CA DN DERs: An array of rhp_cert_data(s). Each rhp_cert_data object includes a trusted CA's DN.
  //             rhp_cert_data->type == RHP_CERT_DATA_CA_DN.
  //             rhp_cert_data->len NOT including the header structure(i.e. sizeof(rhp_cert_data)).
};
typedef struct _rhp_ipcmsg_ikev1_rsasig_sign_req rhp_ipcmsg_ikev1_rsasig_sign_req;

struct _rhp_ipcmsg_ikev1_rsasig_sign_rep {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long my_realm_id;
  unsigned int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 spi[RHP_PROTO_IKE_SPI_SIZE];
  // RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION or RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE
  unsigned int exchange_type;
  unsigned int result; //  1 : Success , 0 : Failed
  unsigned int signed_octets_len;
  unsigned int cert_chain_num;
  unsigned int cert_chain_len;
  unsigned int eap_role; // RHP_EAP_XXX
  unsigned int eap_method; // RHP_PROTO_EAP_TYPE_XXX
/* followed by signed_octets , my_cert(rhp_cert_data)
   and/or chain(rhp_cert_data(s)) */
};
typedef struct _rhp_ipcmsg_ikev1_rsasig_sign_rep rhp_ipcmsg_ikev1_rsasig_sign_rep;

struct _rhp_ipcmsg_ikev1_rsasig_verify_req {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long my_realm_id; // If NOT specified , 0xFFFFFFFF
  unsigned int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 spi[RHP_PROTO_IKE_SPI_SIZE];
  // RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION or RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE
  unsigned int exchange_type;
  unsigned int peer_id_type; // RHP_PROTO_IKE_ID_XXX
  unsigned int peer_id_len;
  unsigned int peer_cert_bin_len;
  unsigned int cert_chain_num;
  unsigned int cert_chain_bin_len;
  unsigned int mesg_octets_len;
  unsigned int signature_octets_len;
  unsigned long peer_notified_realm_id; // If NOT specified , 0xFFFFFFFF
  /* followed by peer id , peer cert, cert chains,
   	 mesg_octets and/or signature octets. */
};
typedef struct _rhp_ipcmsg_ikev1_rsasig_verify_req rhp_ipcmsg_ikev1_rsasig_verify_req;

struct _rhp_ipcmsg_ikev1_rsasig_verify_rep {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long my_realm_id;
  unsigned int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 spi[RHP_PROTO_IKE_SPI_SIZE];
  // RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION or RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE
  unsigned int exchange_type;
  unsigned int result; //  1 : Success , 0 : Failed
  unsigned int alt_peer_id_len;
  unsigned int alt_peer_id_type; // sizeof(u8)
  unsigned int eap_role; // RHP_EAP_XXX
  unsigned int eap_method; // RHP_PROTO_EAP_TYPE_XXX
  /* Followed by alt_peer_id_value(ex: Cert's DN or subjectAltName) */
};
typedef struct _rhp_ipcmsg_ikev1_rsasig_verify_rep rhp_ipcmsg_ikev1_rsasig_verify_rep;

struct _rhp_ipcmsg_ikev1_rslv_auth_req {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 spi[RHP_PROTO_IKE_SPI_SIZE];
  // RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION or RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE
  unsigned int exchange_type;
  unsigned int peer_id_type; // RHP_PROTO_IKE_ID_XXX
  unsigned int peer_id_len;
  unsigned long peer_notified_realm_id; // If NOT specified , 0xFFFFFFFF
  /* followed by peer id. */
};
typedef struct _rhp_ipcmsg_ikev1_rslv_auth_req rhp_ipcmsg_ikev1_rslv_auth_req;

struct _rhp_ipcmsg_ikev1_rslv_auth_rep {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  u64 txn_id;
  unsigned long my_realm_id;
  unsigned int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
  u8 spi[RHP_PROTO_IKE_SPI_SIZE];
  // RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION or RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE
  unsigned int exchange_type;
  unsigned int result; //  1 : Success , 0 : Failed
};
typedef struct _rhp_ipcmsg_ikev1_rslv_auth_rep rhp_ipcmsg_ikev1_rslv_auth_rep;




struct _rhp_ipcmsg_fw_rule {
  unsigned int len;
  unsigned int traffic_len;
  unsigned int action_len;
  unsigned int if_len;
  unsigned int filter_pos_len;
  unsigned int arg0_len;
  unsigned int arg1_len;
  /* Option strings or values */
};
typedef struct _rhp_ipcmsg_fw_rule	rhp_ipcmsg_fw_rule;

struct _rhp_ipcmsg_fw_rules {
  unsigned char tag[4]; // "#IMS"
  unsigned int len;
  unsigned long type; // RHP_IPC_XXX
  unsigned int rules_num;
  /* rhp_ipcmsg_fw_rule(s) */
};
typedef struct _rhp_ipcmsg_fw_rules	rhp_ipcmsg_fw_rules;



extern void rhp_ipc_close( rhp_process* prc );
extern ssize_t rhp_ipc_send( rhp_process* prc, void *buf, size_t len, int flags );
extern int rhp_ipc_recvmsg( rhp_process* prc, rhp_ipcmsg **msg, int flags );
extern rhp_ipcmsg* rhp_ipc_alloc_msg( unsigned long type, size_t len );
extern void rhp_ipc_send_nop(rhp_process* prc,int buflen);

extern void rhp_ipc_send_exit();


/***************************

 Process Capabilities

 ****************************/
extern int rhp_caps_set( rhp_process* prc, int allowed_caps_num, cap_value_t* allowed_caps );
extern void rhp_free_caps( rhp_process* prc );

/***************************

 Process Handling

 ****************************/
extern int rhp_process_init( uid_t uid, gid_t gid, uid_t syspxy_uid, gid_t syspxy_gid, int debug, int core_dump,
    char* main_user_name,char* syspxy_user_name );
extern void rhp_syspxy_run();
extern void rhp_main_run();

#define RHP_SYSPXY_EPOLL_NETLINK  	 0
#define RHP_SYSPXY_EPOLL_IPC         1

#define RHP_MAIN_EPOLL_IPC        							0
#define RHP_MAIN_EPOLL_NETSOCK    							1
#define RHP_MAIN_EPOLL_TUNDEV     							2
#define RHP_MAIN_EPOLL_HTTP_LISTEN 							3
#define RHP_MAIN_EPOLL_HTTP_SERVER 							4
#define RHP_MAIN_EPOLL_DNSPXY_RSLVR							5
#define RHP_MAIN_EPOLL_DNSPXY_PROTECTED_V4		  6
#define RHP_MAIN_EPOLL_DNSPXY_INET_V4						7
#define RHP_MAIN_EPOLL_HTTP_CLT_GET_CONNECT			8
#define RHP_MAIN_EPOLL_HTTP_CLT_GET_RECV				9
#define RHP_MAIN_EPOLL_DNSPXY_PROTECTED_V6		  10
#define RHP_MAIN_EPOLL_DNSPXY_INET_V6						11
#define RHP_MAIN_EPOLL_EVENT_CB_START						12 // [CAUTION] If changing it, check also rhp_main_epoll_register().
#define RHP_MAIN_EPOLL_EVENT_RADIUS_RX					RHP_MAIN_EPOLL_EVENT_CB_START
#define RHP_MAIN_EPOLL_EVENT_CB_RESERVED_1			13
#define RHP_MAIN_EPOLL_EVENT_CB_RESERVED_2			14
#define RHP_MAIN_EPOLL_EVENT_CB_RESERVED_3			15
#define RHP_MAIN_EPOLL_EVENT_CB_RESERVED_4			16
#define RHP_MAIN_EPOLL_EVENT_CB_RESERVED_5			17
#define RHP_MAIN_EPOLL_EVENT_CB_RESERVED_6			18
#define RHP_MAIN_EPOLL_EVENT_CB_RESERVED_7			19 // See RHP_MAIN_EPOLL_EVENT_CALLBACKS_MAX

#define RHP_MAIN_EPOLL_EVENT_CALLBACKS_MAX	8


#define RHP_SYSPXY_EPOLL_MAX      256
#define RHP_MAIN_EPOLL_MAX        4096
#define RHP_EPOLL_POLLTIME   			(10*1000)

extern int rhp_main_net_epoll_fd;
extern int rhp_main_admin_epoll_fd;

struct epoll_event;

struct _rhp_epoll_ctx {
	int event_type; // RHP_MAIN_EPOLL_XXX
	unsigned long params[6];
};
typedef struct _rhp_epoll_ctx rhp_epoll_ctx;

extern int rhp_auth_ipc_handle(rhp_ipcmsg *ipcmsg);

extern int rhp_ikev2_ike_auth_ipc_handle(rhp_ipcmsg *ipcmsg);

typedef int (*RHP_EPOLL_EVENT_CB)(struct epoll_event *ep_evt,rhp_epoll_ctx* epoll_ctx);

extern int rhp_main_epoll_register(
		int event_type, // RHP_MAIN_EPOLL_XXX (>= RHP_MAIN_EPOLL_EVENT_CB_START)
		RHP_EPOLL_EVENT_CB event_cb);






/***************************

 	 	RSA-Sig IPC structures

 ****************************/

struct _rhp_vpn_auth_realm;

struct _rhp_auth_ipc_sign_rsasig_cb_ctx {

  rhp_cert_sign_ctx cb_cert_ctx;

  struct _rhp_vpn_auth_realm* auth_rlm;
  rhp_ipcmsg* sign_rsasig_req;

  rhp_ipcmsg* verify_sign_req;
  rhp_ipcmsg* in_verify_rep;

  u8* mesg_octets_exp;
  int mesg_octets_exp_len;

  // RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION or RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE
  int exchange_type;
};
typedef struct _rhp_auth_ipc_sign_rsasig_cb_ctx rhp_auth_ipc_sign_rsasig_cb_ctx;

struct _rhp_auth_ipc_sign_rsasig_enum_certs_ctx {
  u8* certs_bin;
  u8* certs_bin_curp;
  int certs_bin_len;
  int certs_bin_max_len;
  int my_cert;
  int cert_chain_num;
  int http_cert_lookup_supported;

  struct _rhp_vpn_auth_realm* auth_rlm;
};
typedef struct _rhp_auth_ipc_sign_rsasig_enum_certs_ctx   rhp_auth_ipc_sign_rsasig_enum_certs_ctx;


struct _rhp_auth_ipc_verify_rsasig_cb_ctx {

  rhp_cert_sign_verify_ctx cb_cert_ctx;

  struct _rhp_vpn_auth_realm* auth_rlm;
  rhp_ipcmsg* verify_rsasig_req;

  rhp_ipcmsg* verify_sign_req;
  rhp_ipcmsg* in_sign_req;
};
typedef struct _rhp_auth_ipc_verify_rsasig_cb_ctx rhp_auth_ipc_verify_rsasig_cb_ctx;



#endif // _RHP_PROCESS_H_
