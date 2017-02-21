/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


//
// librhpcrypto.so
//

#ifndef _RHP_CRYPTO_H_
#define _RHP_CRYPTO_H_

extern int rhp_crypto_init();
extern void rhp_crypto_cleanup();


/***********
    PRNG
************/

// Gen cryptographically strong pseudo-random bytes.
extern int rhp_random_bytes(u8* buf,int buf_len);


/***********
     MD
************/

#define RHP_CRYPTO_MD_MD5			1
#define RHP_CRYPTO_MD_SHA1		2
extern int rhp_crypto_md(int alg,u8* buf,int buf_len,u8** md_buf_r,int* md_buf_len_r);


/***********
     HMAC
************/

#define RHP_CRYPTO_HMAC_MD5						1
#define RHP_CRYPTO_HMAC_SHA1					2
#define RHP_CRYPTO_HMAC_SHA2_256			3
#define RHP_CRYPTO_HMAC_SHA2_384			4
#define RHP_CRYPTO_HMAC_SHA2_512			5
extern int rhp_crypto_hmac(int alg,u8* buf,int buf_len,u8* key,int key_len,u8** hmac_buf_r,int* hmac_buf_len_r);


/***************
    BASE64
****************/

// text NOT includes '\n'.
extern int rhp_base64_encode(u8* bin,int bin_len,unsigned char** res_text);

// text is terminated with '\n' but NOT decoded. res_bin_len NOT includes padding('=') length.
extern int rhp_base64_decode(unsigned char* text,u8** res_bin,int* res_bin_len);


/***************

     Nonce

****************/

struct _rhp_crypto_nonce {

  void* ctx;

  int nonce_len;
  u8* nonce;
  int (*set_nonce)(struct _rhp_crypto_nonce* nonce,u8* nonce_buf,int nonce_buf_len);
  int (*generate_nonce)(struct _rhp_crypto_nonce* nonce,int nonce_len);

  int (*get_nonce_len)(struct _rhp_crypto_nonce* nonce);
  int (*copy_nonce)(struct _rhp_crypto_nonce* nonce,u8* nonce_buf,int nonce_buf_len);
  u8* (*get_nonce)(struct _rhp_crypto_nonce* nonce);
};
typedef struct _rhp_crypto_nonce rhp_crypto_nonce;

extern rhp_crypto_nonce* rhp_crypto_nonce_alloc();
extern void rhp_crypto_nonce_free(rhp_crypto_nonce* nonce);
extern int rhp_crypto_nonce_cmp(rhp_crypto_nonce* nonce0,rhp_crypto_nonce* nonce1);
extern int rhp_crypto_nonce_cmp_val(rhp_crypto_nonce* nonce0,int nonce1_len,u8* nonce1);


/***************

      D-H

****************/

struct _rhp_crypto_dh {

  int grp; // RHP_PROTO_IKE_TRANSFORM_ID_DH_XXX

  void* ctx;

  int (*generate_key)(struct _rhp_crypto_dh* dh);
  int (*compute_key)(struct _rhp_crypto_dh* dh);

  u8* my_pub_key;
  int my_pub_key_len;
  u8* (*get_my_pub_key)(struct _rhp_crypto_dh* dh,int* key_len_r);

  u8* peer_pub_key;
  int peer_pub_key_len;
  int (*set_peer_pub_key)(struct _rhp_crypto_dh* dh,u8* pub_key_buf,int pub_key_buf_len);
  u8* (*get_peer_pub_key)(struct _rhp_crypto_dh* dh,int* key_len_r);

  u8* shared_key;
  int shared_key_len;
  u8* (*get_shared_key)(struct _rhp_crypto_dh* dh,int* key_len_r);

  int (*reset)(struct _rhp_crypto_dh* dh);
};
typedef struct _rhp_crypto_dh  rhp_crypto_dh;

extern rhp_crypto_dh* rhp_crypto_dh_alloc(int dhgrp);
extern void rhp_crypto_dh_free(rhp_crypto_dh* dh);


/***************

      PRF

****************/

struct _rhp_crypto_prf {

  int alg; // RHP_PROTO_IKE_TRANSFORM_ID_PRF_XXX

  void* ctx;

  int (*get_output_len)(struct _rhp_crypto_prf* prf);

  /*
   RFC5996(2.13 Generating Keying Material) says that:
     "It is assumed that PRFs accept keys of any length, but have a
     preferred key size.  The preferred key size MUST be used as the
     length of SK_d, SK_pi, and SK_pr (see Section 2.14).  For PRFs based
     on the HMAC construction, the preferred key size is equal to the
     length of the output of the underlying hash function.  Other types of
     PRFs MUST specify their preferred key size."
	*/
  int (*get_key_len)(struct _rhp_crypto_prf* prf); // preferred key size

  u8* key;
  int key_len;
  int (*set_key)(struct _rhp_crypto_prf* prf,u8* key,int key_len);

  int (*compute)(struct _rhp_crypto_prf* prf,u8* data,int data_len,u8* outb,int outb_len);
};
typedef struct _rhp_crypto_prf rhp_crypto_prf;

extern rhp_crypto_prf* rhp_crypto_prf_alloc(int alg);
extern void rhp_crypto_prf_free(rhp_crypto_prf* prf);

extern int rhp_crypto_prf_key_len(int alg);


/***************

     Integ

****************/

struct _rhp_crypto_integ {

  int alg; // RHP_PROTO_IKE_TRANSFORM_ID_AUTH_XXX

  void* ctx;

  int (*get_output_len)(struct _rhp_crypto_integ* integ);
  int (*get_key_len)(struct _rhp_crypto_integ* integ);

  u8* key;
  int key_len;
  int (*set_key)(struct _rhp_crypto_integ* integ,u8* key,int key_len);

  int (*compute)(struct _rhp_crypto_integ* integ,u8* data,int data_len,u8* outb,int outb_len);
};
typedef struct _rhp_crypto_integ rhp_crypto_integ;

extern rhp_crypto_integ* rhp_crypto_integ_alloc(int alg);
extern void rhp_crypto_integ_free(rhp_crypto_integ* integ);


/***************

     Encr

****************/


struct _rhp_crypto_encr {

  int alg; // RHP_PROTO_IKE_TRANSFORM_ID_ENCR_XXX
  int alg_key_bits;

  void* ctx_enc;
  void* ctx_dec;

  int (*get_iv_len)(struct _rhp_crypto_encr* encr);
  int (*get_block_len)(struct _rhp_crypto_encr* encr);
  int (*get_block_aligned_len)(struct _rhp_crypto_encr* encr,int data_len);

  int key_len;
  int (*get_key_len)(struct _rhp_crypto_encr* encr); // bytes

  u8* enc_key;
  int (*set_enc_key)(struct _rhp_crypto_encr* encr,u8* key,int key_len);

  u8* dec_key;
  int (*set_dec_key)(struct _rhp_crypto_encr* encr,u8* key,int key_len);

  int (*encrypt)(struct _rhp_crypto_encr* encr,
  			u8* plain_txt,int plain_txt_len,u8* outb,int outb_len);

  int (*decrypt)(struct _rhp_crypto_encr* encr,
  		u8* cipher_txt,int cipher_txt_len,u8* outb,int outb_len,u8* iv);

  u8* enc_iv;
  int (*update_enc_iv)(struct _rhp_crypto_encr* encr,u8* enc_iv,int enc_iv_len);
  u8* (*get_enc_iv)(struct _rhp_crypto_encr* encr);
};
typedef struct _rhp_crypto_encr rhp_crypto_encr;

extern rhp_crypto_encr* rhp_crypto_encr_alloc(int alg,int key_bits_len);
extern void rhp_crypto_encr_free(rhp_crypto_encr* encr);

#define RHP_CRYPTO_MAX_IV_SIZE	32 // AES-CBC : 16B(128b)


/***************

  Hash (IKEv1)

****************/

struct _rhp_crypto_hash {

  int alg; // RHP_PROTO_IKEV1_P1_ATTR_HASH_XXX

  void* ctx;

  int (*get_output_len)(struct _rhp_crypto_hash* hash);

  int (*compute)(struct _rhp_crypto_hash* hash,u8* data,int data_len,u8* outb,int outb_len);
};
typedef struct _rhp_crypto_hash rhp_crypto_hash;

extern rhp_crypto_hash* rhp_crypto_hash_alloc(int alg);
extern void rhp_crypto_hash_free(rhp_crypto_hash* hash);


/************************************

     RSA Signature Sign/Verify

************************************/

struct _rhp_crypto_rsasig {

  void* ctx_sign;
  void* ctx_verify;

  int priv_key_len;
  u8* priv_key;
  int (*set_priv_key)(struct _rhp_crypto_rsasig* rsasig,u8* priv_key,int priv_key_len);

  int pub_key_len;
  u8* pub_key;
  int (*set_pub_key)(struct _rhp_crypto_rsasig* rsasig,u8* pub_key,int pub_key_len);

  //
  // RSASSA-PKCS1-v1_5 signature scheme (e.g. IKEv2)
  //
  // - signature: SHA1 value (20 bytes) [OUT]
  //
  int (*sign)(struct _rhp_crypto_rsasig* rsasig,
  		u8* mesg_octets,int mesg_octets_len,u8** signature,int* signature_len);

  //
  // RSASSA-PKCS1-v1_5 signature scheme (e.g. IKEv2)
  //
  // - signature: SHA1 value (20 bytes)	[IN]
  //
  int (*verify)(struct _rhp_crypto_rsasig* rsasig,
  		u8* signed_octets,int signed_octets_len,u8* signature,int signature_len);


  //
  // Private key encryption in PKCS #1 format. (IKEv1)
  //
  // - mesg_octets: HASH_I or HASH_R 					[IN]
  // - signature: Encrypted HASH_I or HASH_R 	[OUT]
  //
  int (*sign_ikev1)(struct _rhp_crypto_rsasig* rsasig,
  		u8* mesg_octets,int mesg_octets_len,u8** signature,int* signature_len);

  //
  // Private key decryption in PKCS #1 format. (IKEv1)
  //
  // - mesg_octets: HASH_I or HASH_R					[IN]
  // - signature: Encrypted HASH_I or HASH_R	[OUT]
  //
  int (*verify_ikev1)(struct _rhp_crypto_rsasig* rsasig,
  		u8* mesg_octets,int mesg_octets_len,u8* signature,int signature_len);
};
typedef struct _rhp_crypto_rsasig  rhp_crypto_rsasig;

extern rhp_crypto_rsasig* rhp_crypto_rsasig_alloc();
extern void rhp_crypto_rsasig_free(rhp_crypto_rsasig* rsasig);


/***************

      PRF+

****************/

extern int rhp_crypto_prf_plus(rhp_crypto_prf* prf,u8* k,int k_len,u8* s,int s_len,u8* outb,int outb_len);


/***************

    Big Number

****************/

struct _rhp_crypto_bn {

	void* ctx;

	int (*set_bit)(struct _rhp_crypto_bn* bn,int idx); // idx starts from 0.
	int (*clear_bit)(struct _rhp_crypto_bn* bn,int idx);

	int (*bit_is_set)(struct _rhp_crypto_bn* bn, int idx);

	int (*left_shift)(struct _rhp_crypto_bn* bn,int n);
	int (*right_shift)(struct _rhp_crypto_bn* bn,int n);

	int bits_len;
	int (*get_bits_len)(struct _rhp_crypto_bn* bn);
};
typedef struct _rhp_crypto_bn	rhp_crypto_bn;

extern rhp_crypto_bn* rhp_crypto_bn_alloc(int bits_len);
extern void rhp_crypto_bn_free(rhp_crypto_bn* bn);


#endif // _RHP_CRYPTO_H_
