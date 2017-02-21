/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


//
// librhpcert.so
//

#ifndef _RHP_CERT_H_
#define _RHP_CERT_H_

extern int rhp_cert_init();
extern int rhp_cert_start();
extern void rhp_cert_cleanup();

struct _rhp_cert_store;


struct _rhp_cert_data {

#define RHP_CERT_DATA_DER				1
#define RHP_CERT_DATA_HASH_URL	2	// For IKEv2
#define RHP_CERT_DATA_CA_DN			3 // For IKEv1 CertReq
	unsigned int type;

	unsigned int len;
  /* followed by cert DERed octets, Hash and URL or DERed CA's DN. */
};
typedef struct _rhp_cert_data  rhp_cert_data;


struct _rhp_cert_dn {

  u8 tag[4];  // "#CTN"

  void* ctx;
  int ctx_shared;

  int (*DER_encode)(struct _rhp_cert_dn* cert_dn,u8** der,int* der_len);

  int (*contains_rdns)(struct _rhp_cert_dn* cert_dn,struct _rhp_cert_dn* rdns);

  int (*compare)(struct _rhp_cert_dn* cert_dn0,struct _rhp_cert_dn* cert_dn1);

  char* (*to_text)(struct _rhp_cert_dn* cert_dn);

  void (*destructor)(struct _rhp_cert_dn* cert_dn);
};
typedef struct _rhp_cert_dn  rhp_cert_dn;

extern rhp_cert_dn* rhp_cert_dn_alloc_by_DER(u8* der,int der_len);
extern rhp_cert_dn* rhp_cert_dn_alloc_by_text(char* dn/*Don't be const string!*/);
extern void rhp_cert_dn_free(rhp_cert_dn* cert_dn);


struct _rhp_cert {

  u8 tag[4];  // "#CRT"

  void* ctx;
  
  rhp_cert_dn* (*get_cert_dn)(struct _rhp_cert* cert);

  int (*get_cert_subjectaltname)(struct _rhp_cert* cert,char** altname,int* altname_len,int* altname_type);
  
  void (*destructor)(struct _rhp_cert* cert);
};
typedef struct _rhp_cert  rhp_cert;

extern rhp_cert* rhp_cert_alloc(u8* der,int der_len);
extern void rhp_cert_free(rhp_cert* cert);


// A common header for rhp_cert_sign_ctx and rhp_cert_sign_verify_ctx.
struct _rhp_cert_ext_op {
  u8 tag[4]; // "#CSC"

#define RHP_CERT_SIGN_OP_SIGN       			1
#define RHP_CERT_SIGN_OP_VERIFY     			2
#define RHP_CERT_SIGN_OP_SIGN_IKEV1 			3
#define RHP_CERT_SIGN_OP_VERIFY_IKEV1     4
  int sign_op_type; // RHP_CERT_SIGN_OP_XXX
};
typedef struct _rhp_cert_ext_op  rhp_cert_ext_op;


struct _rhp_cert_sign_ctx {

	// [COMMON-START] See rhp_cert_ext_op.
  u8 tag[4]; // "#CSC"
  int sign_op_type; // RHP_CERT_SIGN_OP_SIGN
  // [COMMON-END]

  // [IN]
  u8* mesg_octets;
  int mesg_octets_len;

  // [OUT]
  u8* signed_octets;
  int signed_octets_len;
  
  void (*callback)(struct _rhp_cert_store* cert_store,int err,struct _rhp_cert_sign_ctx* cb_ctx);
  
  unsigned long priv[4];
};
typedef struct _rhp_cert_sign_ctx rhp_cert_sign_ctx;


struct _rhp_ikev2_id;

struct _rhp_cert_sign_verify_ctx {

	// [COMMON-START] See rhp_cert_ext_op.
  u8 tag[4]; // "#CSC"
  int sign_op_type; // RHP_CERT_SIGN_OP_VERIFY
  // [COMMON-END]
  
  // [IN]
  rhp_cert* peer_cert;
  
  // [IN]
  int cert_chain_num;
  int cert_chain_bin_len;
  // Each DER-encoded certificate in 'cert_der_bin' is cupsulated into a rhp_cert_bin structure.
  u8* cert_chain_bin;
  
  // [IN]
  u8* signed_octets;
  int signed_octets_len;

  // [IN]
  int signature_len;
  u8* signature;

  // [IN]
  int deny_expired_cert;
  
  void (*callback)(struct _rhp_cert_store* cert_store,int err,
  		struct _rhp_ikev2_id* subjectname,struct _rhp_ikev2_id* subjectaltname,struct _rhp_cert_sign_verify_ctx* cb_ctx);
  
  unsigned long priv[4];
};
typedef struct _rhp_cert_sign_verify_ctx  rhp_cert_sign_verify_ctx;


struct _rhp_cert_store {

  u8 tag[4];  // "#CTS"
  
  struct _rhp_cert_store* next;

  char* cert_store_path;

  rhp_mutex_t lock;

  rhp_atomic_t refcnt;
  rhp_atomic_t is_active;

  int imcomplete;

  void* ctx;

  int (*get_ca_public_key_digests)(struct _rhp_cert_store* cert_store,u8** digests,int* digests_len,int* digest_len);
  
  // dns_r: An array of rhp_cert_data(s). Each rhp_cert_data object includes a trusted CA's DN.
  //        rhp_cert_data->type == RHP_CERT_DATA_CA_DN.
  //        rhp_cert_data->len NOT including the header structure(i.e. sizeof(rhp_cert_data)).
  int (*get_ca_dn_ders)(struct _rhp_cert_store* cert_store,u8** dns_r,int* dns_len_r,int* dns_num_r);

  int (*get_my_cert_issuer_dn_der)(struct _rhp_cert_store* cert_store,u8** dn_r,int* dn_len_r);
  int (*get_untrust_sub_ca_issuer_dn_der)(struct _rhp_cert_store* cert_store,u8** dn_r,int* dn_len_r);


  // Enum my_cert and untrust sub CA certs.
  // Each DER-encoded certificate in 'cert_der_bin' is cupsulated into a rhp_cert_bin structure.
  int (*enum_DER_certs)(struct _rhp_cert_store* cert_store,int deny_expired_cert,int enum_dn_also,
        int (*callback)(struct _rhp_cert_store* cert_store,int is_my_cert,u8* der,int der_len,rhp_cert_dn* cert_dn,void* cb_ctx),
        void* cb_ctx);

  int (*sign)(struct _rhp_cert_store* cert_store,rhp_cert_sign_ctx* cb_ctx);

  int (*verify_signature)(struct _rhp_cert_store* cert_store,rhp_cert_sign_verify_ctx* cb_ctx);

  int (*get_my_cert_dn_der)(struct _rhp_cert_store* cert_store,u8** outb,int* outb_len);

  char* (*get_my_cert_dn_text)(struct _rhp_cert_store* cert_store);
  char* (*get_my_cert_serialno_text)(struct _rhp_cert_store* cert_store);
  
  // Multivalued name NOT supported.
  int (*get_my_cert_subjectaltname)(struct _rhp_cert_store* cert_store,char** altname,int* altname_len,int* altname_type); 
  
  int (*get_my_cert_printed_text)(struct _rhp_cert_store* cert_store,u8** out,int* out_len);

  int (*get_ca_certs_printed_text)(struct _rhp_cert_store* cert_store,u8** out,int* out_len);

  int (*get_crls_printed_text)(struct _rhp_cert_store* cert_store,u8** out,int* out_len);

  int (*get_my_and_intermediate_ca_certs_printed_text)(struct _rhp_cert_store* cert_store,u8** out,int* out_len);

  void (*destructor)(struct _rhp_cert_store* cert_store);
};
typedef struct _rhp_cert_store  rhp_cert_store;

extern rhp_cert_store* rhp_cert_store_alloc(char* cert_store_path,unsigned long auth_realm_id,char* password);
extern void rhp_cert_store_destroy(rhp_cert_store* cert_store);
extern void rhp_cert_store_clear_resources(char* cert_store_path,unsigned long auth_realm_id);

extern void rhp_cert_store_hold(rhp_cert_store* cert_store);
extern void rhp_cert_store_unhold(rhp_cert_store* cert_store);


extern int rhp_cert_update(unsigned long auth_realm_id,int my_cert_cont_len,u8* my_cert_cont,
		int my_privkey_cont_len,u8* my_privkey_cont,int certs_cont_len,u8* certs_cont,char* password,
		char* cert_store_path,rhp_cert_store** cert_store_r);

extern int rhp_cert_update2(unsigned long auth_realm_id,char* password,
		char* cert_store_path,rhp_cert_store** cert_store_r);


extern int rhp_cert_delete(unsigned long auth_realm_id,char* cert_store_path,rhp_cert_store* cert_store);


extern void rhp_cert_X509_pem_print(rhp_cert* cert);
extern void rhp_cert_X509_NAME_pem_print(rhp_cert_dn* cert_dn);
extern void rhp_cert_X509_print(rhp_cert* cert);
extern void rhp_cert_X509_NAME_print(rhp_cert_dn* cert_dn);


extern int rhp_cert_store_all_ca_pubkey_digests(u8** digests_r,int* digests_len_r,int max_digests_len);

// dns_r: An array of rhp_cert_data(s). Each rhp_cert_data object includes a trusted CA's DN.
//        rhp_cert_data->type == RHP_CERT_DATA_CA_DN.
//        rhp_cert_data->len NOT including the header structure(i.e. sizeof(rhp_cert_data)).
extern int rhp_cert_store_all_ca_dns_der(u8** dns_r,int* dns_len_r,int* dns_num_r,int max_dns_len);


// If certs_num > 1, each DER-encoded certificate in 'cert_der_bin' is cupsulated into a rhp_cert_bin structure.
extern int rhp_cert_get_certs_printed_text(u8* certs_der_bin,int certs_der_bin_len,int certs_num,u8** out,int* out_len);

#endif // _RHP_CERT_H_


