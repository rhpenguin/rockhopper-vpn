/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	This library may be distributed, used, and modified under the terms of
	BSD license:

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are
	met:

	1. Redistributions of source code must retain the above copyright
		 notice, this list of conditions and the following disclaimer.

	2. Redistributions in binary form must reproduce the above copyright
		 notice, this list of conditions and the following disclaimer in the
		 documentation and/or other materials provided with the distribution.

	3. Neither the name(s) of the above-listed copyright holder(s) nor the
		 names of its contributors may be used to endorse or promote products
		 derived from this software without specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
	"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
	LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
	A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
	OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
	SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
	LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
	DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
	THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
	OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/


#ifdef RHP_OPENSSL

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>


#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_crypto.h"
#include "rhp_protocol.h"

static u8 rhp_crypto_dh_grp2_prime[] = {
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xC9,0x0F,0xDA,0xA2,0x21,0x68,0xC2,0x34,
  0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
  0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,
  0x02,0x0B,0xBE,0xA6,0x3B,0x13,0x9B,0x22,
  0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
  0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,
  0x30,0x2B,0x0A,0x6D,0xF2,0x5F,0x14,0x37,
  0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,
  0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,
  0xF4,0x4C,0x42,0xE9,0xA6,0x37,0xED,0x6B,
  0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
  0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,
  0xAE,0x9F,0x24,0x11,0x7C,0x4B,0x1F,0xE6,
  0x49,0x28,0x66,0x51,0xEC,0xE6,0x53,0x81,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};

static u8 rhp_crypto_dh_grp5_prime[] = {
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xC9,0x0F,0xDA,0xA2,0x21,0x68,0xC2,0x34,
  0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
  0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,
  0x02,0x0B,0xBE,0xA6,0x3B,0x13,0x9B,0x22,
  0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
  0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,
  0x30,0x2B,0x0A,0x6D,0xF2,0x5F,0x14,0x37,
  0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,
  0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,
  0xF4,0x4C,0x42,0xE9,0xA6,0x37,0xED,0x6B,
  0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
  0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,
  0xAE,0x9F,0x24,0x11,0x7C,0x4B,0x1F,0xE6,
  0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D,
  0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,
  0x98,0xDA,0x48,0x36,0x1C,0x55,0xD3,0x9A,
  0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
  0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96,
  0x1C,0x62,0xF3,0x56,0x20,0x85,0x52,0xBB,
  0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D,
  0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,
  0xF1,0x74,0x6C,0x08,0xCA,0x23,0x73,0x27,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
};

static u8 rhp_crypto_dh_grp14_prime[] = {
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xC9,0x0F,0xDA,0xA2,0x21,0x68,0xC2,0x34,
  0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
  0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,
  0x02,0x0B,0xBE,0xA6,0x3B,0x13,0x9B,0x22,
  0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
  0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,
  0x30,0x2B,0x0A,0x6D,0xF2,0x5F,0x14,0x37,
  0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,
  0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,
  0xF4,0x4C,0x42,0xE9,0xA6,0x37,0xED,0x6B,
  0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
  0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,
  0xAE,0x9F,0x24,0x11,0x7C,0x4B,0x1F,0xE6,
  0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D,
  0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,
  0x98,0xDA,0x48,0x36,0x1C,0x55,0xD3,0x9A,
  0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
  0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96,
  0x1C,0x62,0xF3,0x56,0x20,0x85,0x52,0xBB,
  0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D,
  0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,
  0xF1,0x74,0x6C,0x08,0xCA,0x18,0x21,0x7C,
  0x32,0x90,0x5E,0x46,0x2E,0x36,0xCE,0x3B,
  0xE3,0x9E,0x77,0x2C,0x18,0x0E,0x86,0x03,
  0x9B,0x27,0x83,0xA2,0xEC,0x07,0xA2,0x8F,
  0xB5,0xC5,0x5D,0xF0,0x6F,0x4C,0x52,0xC9,
  0xDE,0x2B,0xCB,0xF6,0x95,0x58,0x17,0x18,
  0x39,0x95,0x49,0x7C,0xEA,0x95,0x6A,0xE5,
  0x15,0xD2,0x26,0x18,0x98,0xFA,0x05,0x10,
  0x15,0x72,0x8E,0x5A,0x8A,0xAC,0xAA,0x68,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};

static void _rhp_crypto_dh_dump(rhp_crypto_dh* dh,BIGNUM* peer_pub_key,char* label)
{
  DH* dh_ctx = (DH*)dh->ctx;
  u8* g_bin = NULL;
  u8* p_bin = NULL;
  u8* peer_pub_key_bin = NULL;
  u8* my_priv_key_bin = NULL;
  u8* my_pub_key_bin = NULL;
  int impl_key_len;
  int g_bin_len = 0;
  int p_bin_len = 0;
  int peer_pub_key_bin_len = 0;
  int my_priv_key_bin_len = 0;
  int my_pub_key_bin_len = 0;


  const BIGNUM *member_p, *member_g, *member_pub_key, *member_priv_key;

  DH_get0_pqg(dh_ctx, &member_p, NULL, &member_g);
  DH_get0_key(dh_ctx, &member_pub_key, &member_priv_key);


  _RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
  if( _RHP_TRC_COND(_rhp_trc_user_id(),0) ){

		p_bin = (u8*)_rhp_malloc(BN_num_bytes(member_p));
		g_bin = (u8*)_rhp_malloc(BN_num_bytes(member_g));
		if( peer_pub_key ){
			peer_pub_key_bin = (u8*)_rhp_malloc(BN_num_bytes(peer_pub_key));
			memset(peer_pub_key_bin,0,BN_num_bytes(peer_pub_key));
		}
		if( member_priv_key ){
			my_priv_key_bin = (u8*)_rhp_malloc(BN_num_bytes(member_priv_key));
			memset(my_priv_key_bin,0,BN_num_bytes(member_priv_key));
		}
		if( member_pub_key ){
			my_pub_key_bin = (u8*)_rhp_malloc(BN_num_bytes(member_pub_key));
			memset(my_pub_key_bin,0,BN_num_bytes(member_pub_key));
		}


		if( p_bin ){
			BN_bn2bin(member_p,p_bin);
			p_bin_len = BN_num_bytes(member_p);
		}

		if( g_bin ){
			BN_bn2bin(member_g,g_bin);
			g_bin_len = BN_num_bytes(member_g);
		}

		if( peer_pub_key_bin ){
			BN_bn2bin(peer_pub_key,peer_pub_key_bin);
			peer_pub_key_bin_len = BN_num_bytes(peer_pub_key);
		}

		if( my_priv_key_bin ){
			BN_bn2bin(member_priv_key,my_priv_key_bin);
			my_priv_key_bin_len = BN_num_bytes(member_priv_key);
		}

		if( my_pub_key_bin ){
			BN_bn2bin(member_pub_key,my_pub_key_bin);
			my_pub_key_bin_len = BN_num_bytes(member_pub_key);
		}


		impl_key_len = DH_size(dh_ctx); // get Diffie-Hellman prime size

		RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_DH_CTX_DUMP,"sxxdppppp",label,dh,dh_ctx,impl_key_len,g_bin_len,g_bin,p_bin_len,p_bin,peer_pub_key_bin_len,peer_pub_key_bin,my_priv_key_bin_len,my_priv_key_bin,my_pub_key_bin_len,my_pub_key_bin);

		if( g_bin ){
			_rhp_free(g_bin);
		}
		if( p_bin ){
			_rhp_free(p_bin);
		}
		if( peer_pub_key_bin ){
			_rhp_free(peer_pub_key_bin);
		}
		if( my_priv_key_bin ){
			_rhp_free(my_priv_key_bin);
		}
		if( my_pub_key_bin ){
			_rhp_free(my_pub_key_bin);
		}
  }
}

static int _rhp_crypto_openssl_dh_get_dh_prime(int grp,u8** prime,int* prime_len)
{
  switch( grp ){

  case RHP_PROTO_IKE_TRANSFORM_ID_DH_1:
    return -ENOENT;

  case RHP_PROTO_IKE_TRANSFORM_ID_DH_2:
    *prime = rhp_crypto_dh_grp2_prime;
    *prime_len = RHP_PROTO_IKE_DH_GRP2_PRIME_SZ;
    break;

  case RHP_PROTO_IKE_TRANSFORM_ID_DH_5:
    *prime = rhp_crypto_dh_grp5_prime;
    *prime_len = RHP_PROTO_IKE_DH_GRP5_PRIME_SZ;
    break;

  case RHP_PROTO_IKE_TRANSFORM_ID_DH_14:
    *prime = rhp_crypto_dh_grp14_prime;
    *prime_len = RHP_PROTO_IKE_DH_GRP14_PRIME_SZ;
    break;

  case RHP_PROTO_IKE_TRANSFORM_ID_DH_15:
  case RHP_PROTO_IKE_TRANSFORM_ID_DH_16:
  case RHP_PROTO_IKE_TRANSFORM_ID_DH_17:
  case RHP_PROTO_IKE_TRANSFORM_ID_DH_18:
  default:
    RHP_BUG("%d",grp);
    return -ENOENT;
  }

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_CH_GET_DH_PRIME,"dp",grp,*prime_len,*prime);
  return 0;
}


static int _rhp_crypto_openssl_dh_compute_key(rhp_crypto_dh* dh)
{
  int err = 0;
  BIGNUM* peer_pub = NULL;
  DH* dh_ctx = (DH*)dh->ctx;
  int bin_len;
  int key_len = DH_size(dh_ctx); // get Diffie-Hellman prime size

  if( dh->peer_pub_key == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  peer_pub = BN_bin2bn(dh->peer_pub_key,dh->peer_pub_key_len,NULL);
  if( peer_pub == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

//_rhp_crypto_dh_dump(dh,peer_pub,"_rhp_crypto_openssl_dh_compute_key(1)");

  dh->shared_key_len = 0;
  dh->shared_key = (u8*)_rhp_malloc(key_len);
  if( dh->shared_key == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  memset(dh->shared_key,0,key_len);

//_rhp_crypto_dh_dump(dh,peer_pub,"_rhp_crypto_openssl_dh_compute_key(2)");

  if( (bin_len = DH_compute_key(dh->shared_key,peer_pub,dh_ctx)) < 0 ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  if( key_len < bin_len ){

  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;

  }else if( key_len != bin_len ){

    // bin_len may be less than key_len.

  	u8* tmp_buf = (u8*)_rhp_malloc(key_len);

  	if( tmp_buf == NULL ){
  		RHP_BUG("");
    	err = -ENOMEM;
    	goto error;
  	}
  	memset(tmp_buf,0,key_len);

    // Prepend zero bits if bin_len is less than key_len.
  	memcpy((tmp_buf + key_len - bin_len),dh->shared_key,bin_len);

  	_rhp_free(dh->shared_key);
  	dh->shared_key = tmp_buf;
  }

  _rhp_crypto_dh_dump(dh,peer_pub,"_rhp_crypto_openssl_dh_compute_key(3)");

  dh->shared_key_len = key_len;

error:
  if( peer_pub ){
    BN_free(peer_pub);
  }

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_DH_COMPUTE_KEY,"xppdd",dh,dh->shared_key_len,dh->shared_key,dh->peer_pub_key_len,dh->peer_pub_key,err,dh->grp);
  return err;
}


static u8* _rhp_crypto_openssl_dh_get_my_pub_key(rhp_crypto_dh* dh,int* my_put_key_len_r)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_DH_GET_MY_PUB_KEY,"xxdp",dh,dh->my_pub_key,dh->grp,dh->my_pub_key_len,dh->my_pub_key);
  *my_put_key_len_r = dh->my_pub_key_len;
  return dh->my_pub_key;
}

static int _rhp_crypto_openssl_dh_set_peer_pub_key(rhp_crypto_dh* dh,u8* peer_pub_key,int peer_pub_key_len)
{
  dh->peer_pub_key = (u8*)_rhp_malloc(peer_pub_key_len);

  if( dh->peer_pub_key == NULL ){
  	RHP_BUG("");
    return -ENOMEM;
  }

  dh->peer_pub_key_len = peer_pub_key_len;
  memcpy(dh->peer_pub_key,peer_pub_key,peer_pub_key_len);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_DH_SET_PEER_PUB_KEY,"xpd",dh,dh->peer_pub_key_len,dh->peer_pub_key,dh->grp);
  return 0;
}

static u8* _rhp_crypto_openssl_dh_get_peer_pub_key(rhp_crypto_dh* dh,int* peer_pub_key_len_r)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_DH_GET_PEER_PUB_KEY,"xxdp",dh,dh->peer_pub_key,dh->grp,dh->peer_pub_key_len,dh->peer_pub_key);
  *peer_pub_key_len_r = dh->peer_pub_key_len;
  return dh->peer_pub_key;
}


static u8* _rhp_crypto_openssl_dh_get_shared_key(rhp_crypto_dh* dh,int* shared_key_len_r)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_DH_COPY_SHARED_KEY,"xpd",dh,dh->shared_key_len,dh->shared_key,dh->grp);
  *shared_key_len_r = dh->shared_key_len;
  return dh->shared_key;
}

static int _rhp_crypto_openssl_dh_generate_key(rhp_crypto_dh* dh)
{
  int err = 0;
  DH* dh_ctx = (DH*)dh->ctx;
  int key_len = DH_size(dh_ctx); // get Diffie-Hellman prime size
  int bin_len;

  const BIGNUM *member_pub_key, *member_priv_key;


//_rhp_crypto_dh_dump(dh,NULL,"_rhp_crypto_openssl_dh_generate_key(1)");

  if( DH_generate_key(dh_ctx) != 1 ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

//_rhp_crypto_dh_dump(dh,NULL,"_rhp_crypto_openssl_dh_generate_key(2)");

  DH_get0_key(dh_ctx, &member_pub_key, &member_priv_key);
  // bin_len may be less than key_len.
  bin_len = BN_num_bytes(member_pub_key);
  if( key_len < bin_len ){
     RHP_BUG("");
     err = -EINVAL;
     goto error;
  }


  dh->my_pub_key_len = 0;
  dh->my_pub_key = (u8*)_rhp_malloc(key_len);
  if( dh->my_pub_key == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  memset(dh->my_pub_key,0,key_len);

  /*
    RFC5996(3.4. Key Exchange Payload) says that:
     "A Key Exchange payload is constructed by copying one's Diffie-Hellman
     public value into the "Key Exchange Data" portion of the payload.
     The length of the Diffie-Hellman public value for modular
     exponentiation group (MODP) groups MUST be equal to the length of the
     prime modulus over which the exponentiation was performed, prepending
     zero bits to the value if necessary."
  */
  // Prepend zero bits if bin_len is less than key_len.
  if( BN_bn2bin(member_pub_key,(dh->my_pub_key + key_len - bin_len)) < 0 ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  dh->my_pub_key_len = key_len;

  _rhp_crypto_dh_dump(dh,NULL,"_rhp_crypto_openssl_dh_generate_key(3)");

/*
  if( key_len != bin_len ){
  	RHP_LOG_I(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_OPENSSL_DH_GENERATE_KEY_KEY_LEN,"ddp",key_len,bin_len,dh->my_pub_key_len,dh->my_pub_key);
  }
*/

error:
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_DH_GENERATE_KEY,"xpdd",dh,dh->my_pub_key_len,dh->my_pub_key,err,dh->grp);
  return err;
}

static int _rhp_crypto_openssl_nonce_set_nonce(rhp_crypto_nonce* nonce,u8* nonce_buf,int nonce_buf_len)
{
  if( nonce->nonce ){
    RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_NONCE_SET_NONCE_FREE_OLD,"");
    _rhp_free(nonce->nonce);
  }

  nonce->nonce = (u8*)_rhp_malloc(nonce_buf_len);
  if( nonce->nonce == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }
  memcpy(nonce->nonce,nonce_buf,nonce_buf_len);
  nonce->nonce_len = nonce_buf_len;

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_NONCE_SET_NONCE,"xp",nonce,nonce_buf_len,nonce_buf);
  return 0;
}

static int _rhp_crypto_openssl_nonce_generate_nonce(rhp_crypto_nonce* nonce,int nonce_len)
{
  if( nonce->nonce ){
    RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_NONCE_GENERATE_NONCE_FREE_OLD,"");
    _rhp_free(nonce->nonce);
  }

  nonce->nonce = (u8*)_rhp_malloc(nonce_len);
  if( nonce->nonce == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  if( RAND_bytes(nonce->nonce,nonce_len) != 1 ){
    _rhp_free(nonce->nonce);
    nonce->nonce = NULL;
    RHP_BUG("");
    return -EINVAL;
  }
  nonce->nonce_len = nonce_len;

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_NONCE_GENERATE_NONCE,"xp",nonce,nonce_len,nonce->nonce);
  return 0;
}

static int _rhp_crypto_openssl_nonce_get_nonce_len(rhp_crypto_nonce* nonce)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_NONCE_GET_NONCE_LEN,"xd",nonce,nonce->nonce_len);
  return nonce->nonce_len;
}

static int _rhp_crypto_openssl_nonce_copy_nonce(rhp_crypto_nonce* nonce,u8* nonce_buf,int nonce_buf_len)
{
  if( nonce->nonce == NULL ){
    RHP_BUG("");
    return -ENOENT;
  }

  if( nonce->nonce_len > nonce_buf_len ){
    RHP_BUG("");
    return -EINVAL;
  }

  memcpy(nonce_buf,nonce->nonce,nonce->nonce_len);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_NONCE_COPY_NONCE,"xp",nonce,nonce_buf_len,nonce_buf);
  return 0;
}

static u8* _rhp_crypto_openssl_nonce_get_nonce(rhp_crypto_nonce* nonce)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_NONCE_GET_NONCE,"xp",nonce,nonce->nonce_len,nonce->nonce);
  return nonce->nonce;
}

int rhp_crypto_nonce_cmp(rhp_crypto_nonce* nonce0,rhp_crypto_nonce* nonce1)
{
  u8 *n0_buf,*n1_buf;
  int n0_len,n1_len,i;

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_NONCE_CMP,"xx",nonce0,nonce1);

  n0_buf = nonce0->get_nonce(nonce0);
  n1_buf = nonce1->get_nonce(nonce1);

  if( n0_buf == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_NONCE_CMP_RTRN_1,"xx",nonce0,nonce1);
    return -1;
  }else if( n1_buf == NULL ){
    RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_NONCE_CMP_RTRN_2,"xx",nonce0,nonce1);
    return 1;
  }

  n0_len = nonce0->get_nonce_len(nonce0);
  n1_len = nonce1->get_nonce_len(nonce1);

  if( n0_len < n1_len ){
    RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_NONCE_CMP_RTRN_3,"xx",nonce0,nonce1);
    return -1;
  }else if( n0_len > n1_len ){
    RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_NONCE_CMP_RTRN_4,"xx",nonce0,nonce1);
    return 1;
  }

  for( i = 0; i < n0_len;i++ ){
     if( n0_buf[i] < n1_buf[i] ){
       RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_NONCE_CMP_RTRN_5,"xx",nonce0,nonce1);
        return -1;
     }else if( n0_buf[i] > n1_buf[i] ){
       RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_NONCE_CMP_RTRN_6,"xx",nonce0,nonce1);
        return 1;
     }
  }

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_NONCE_CMP_RTRN_7,"xx",nonce0,nonce1);
  return 0;
}

int rhp_crypto_nonce_cmp_val(rhp_crypto_nonce* nonce0,int nonce1_len,u8* nonce1)
{
  u8 *n0_buf;
  int n0_len,i;

  n0_buf = nonce0->get_nonce(nonce0);

  if( n0_buf == NULL ){
    return -1;
  }

  n0_len = nonce0->get_nonce_len(nonce0);

  if( n0_len < nonce1_len ){
    return -1;
  }

  for( i = 0; i < n0_len;i++ ){
     if( n0_buf[i] < nonce1[i] ){
        return -1;
     }else if( n0_buf[i] > nonce1[i] ){
        return 1;
     }
  }

  return 0;
}


static int _rhp_crypto_openssl_prf_hmac_sha1_get_output_len(rhp_crypto_prf* prf)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA1_GET_OUTPUT_LEN,"xd",prf,SHA_DIGEST_LENGTH);
  return SHA_DIGEST_LENGTH;
}

static int _rhp_crypto_openssl_prf_hmac_sha1_get_key_len(rhp_crypto_prf* prf)
{
  /*
   RFC5996(2.13 Generating Keying Material) says that:
     "It is assumed that PRFs accept keys of any length, but have a
     preferred key size.  The preferred key size MUST be used as the
     length of SK_d, SK_pi, and SK_pr (see Section 2.14).  For PRFs based
     on the HMAC construction, the preferred key size is equal to the
     length of the output of the underlying hash function.  Other types of
     PRFs MUST specify their preferred key size."
	*/

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA1_GET_KEY_LEN,"xd",prf,SHA_DIGEST_LENGTH);
  return SHA_DIGEST_LENGTH; // preferred key size for IKEv2 IKE SA's keying material.
}

static int _rhp_crypto_openssl_prf_hmac_sha1_set_key(rhp_crypto_prf* prf,u8* key,int key_len)
{
  if( prf->key ){
    RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA1_SET_KEY_FREE_OLD,"xp",prf,prf->key_len,prf->key);
    _rhp_free(prf->key);
  }

  prf->key = (u8*)_rhp_malloc(key_len);
  if( prf->key == NULL ){
    return -ENOMEM;
  }
  memcpy(prf->key,key,key_len);
  prf->key_len = key_len;

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA1_SET_KEY,"xp",prf,prf->key_len,prf->key);
  return 0;
}

static int _rhp_crypto_openssl_prf_hmac_sha1_compute(rhp_crypto_prf* prf,u8* data,int data_len,u8* outb,int outb_len)
{
  unsigned int olen;

  if( prf->key == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( outb_len < SHA_DIGEST_LENGTH ){
    RHP_BUG("");
    return -EINVAL;
  }

  HMAC(EVP_sha1(),prf->key,prf->key_len,data,data_len,outb,&olen);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA1_COMPUTE,"xpp",prf,data_len,data,outb_len,outb);
  return 0;
}

static rhp_crypto_prf* _rhp_crypto_openssl_prf_hmac_sha1_alloc()
{
  rhp_crypto_prf* prf = (rhp_crypto_prf*)_rhp_malloc(sizeof(rhp_crypto_prf));

  if( prf == NULL ){
    RHP_BUG("");
    return NULL;
  }

  prf->alg = RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA1;
  prf->ctx = NULL;
  prf->key = NULL;

  prf->get_output_len = _rhp_crypto_openssl_prf_hmac_sha1_get_output_len;
  prf->get_key_len = _rhp_crypto_openssl_prf_hmac_sha1_get_key_len;
  prf->set_key = _rhp_crypto_openssl_prf_hmac_sha1_set_key;
  prf->compute = _rhp_crypto_openssl_prf_hmac_sha1_compute;

  RHP_TRC(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA1_ALLOC,"x",prf);
  return prf;
}

static void _rhp_crypto_openssl_prf_hmac_sha1_free(rhp_crypto_prf* prf)
{
  if( prf->key ){
    _rhp_free_zero(prf->key,prf->key_len);
  }
  _rhp_free(prf);
  RHP_TRC(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA1_FREE,"x",prf);
}



static int _rhp_crypto_openssl_prf_hmac_sha2_256_get_output_len(rhp_crypto_prf* prf)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA2_256_GET_OUTPUT_LEN,"xd",prf,SHA256_DIGEST_LENGTH);
  return SHA256_DIGEST_LENGTH;
}

static int _rhp_crypto_openssl_prf_hmac_sha2_256_get_key_len(rhp_crypto_prf* prf)
{
  /*
   RFC5996(2.13 Generating Keying Material) says that:
     "It is assumed that PRFs accept keys of any length, but have a
     preferred key size.  The preferred key size MUST be used as the
     length of SK_d, SK_pi, and SK_pr (see Section 2.14).  For PRFs based
     on the HMAC construction, the preferred key size is equal to the
     length of the output of the underlying hash function.  Other types of
     PRFs MUST specify their preferred key size."
	*/

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA2_256_GET_KEY_LEN,"xd",prf,SHA256_DIGEST_LENGTH);
  return SHA256_DIGEST_LENGTH;// preferred key size for IKEv2 IKE SA's keying material.
}

static int _rhp_crypto_openssl_prf_hmac_sha2_256_set_key(rhp_crypto_prf* prf,u8* key,int key_len)
{
  if( prf->key ){
    RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA2_256_SET_KEY_FREE_OLD,"xp",prf,prf->key_len,prf->key);
    _rhp_free(prf->key);
  }

  prf->key = (u8*)_rhp_malloc(key_len);
  if( prf->key == NULL ){
    return -ENOMEM;
  }
  memcpy(prf->key,key,key_len);
  prf->key_len = key_len;

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA2_256_SET_KEY,"xp",prf,prf->key_len,prf->key);
  return 0;
}

static int _rhp_crypto_openssl_prf_hmac_sha2_256_compute(rhp_crypto_prf* prf,u8* data,int data_len,u8* outb,int outb_len)
{
  unsigned int olen;

  if( prf->key == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( outb_len < SHA256_DIGEST_LENGTH ){
    RHP_BUG("");
    return -EINVAL;
  }

  HMAC(EVP_sha256(),prf->key,prf->key_len,data,data_len,outb,&olen);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA2_256_COMPUTE,"xpp",prf,data_len,data,outb_len,outb);
  return 0;
}

static rhp_crypto_prf* _rhp_crypto_openssl_prf_hmac_sha2_256_alloc()
{
  rhp_crypto_prf* prf = (rhp_crypto_prf*)_rhp_malloc(sizeof(rhp_crypto_prf));

  if( prf == NULL ){
    RHP_BUG("");
    return NULL;
  }

  prf->alg = RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_256;
  prf->ctx = NULL;
  prf->key = NULL;

  prf->get_output_len = _rhp_crypto_openssl_prf_hmac_sha2_256_get_output_len;
  prf->get_key_len = _rhp_crypto_openssl_prf_hmac_sha2_256_get_key_len;
  prf->set_key = _rhp_crypto_openssl_prf_hmac_sha2_256_set_key;
  prf->compute = _rhp_crypto_openssl_prf_hmac_sha2_256_compute;

  RHP_TRC(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA2_256_ALLOC,"x",prf);
  return prf;
}

static void _rhp_crypto_openssl_prf_hmac_sha2_256_free(rhp_crypto_prf* prf)
{
  if( prf->key ){
    _rhp_free_zero(prf->key,prf->key_len);
  }
  _rhp_free(prf);
  RHP_TRC(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA2_256_FREE,"x",prf);
}



static int _rhp_crypto_openssl_prf_hmac_sha2_384_get_output_len(rhp_crypto_prf* prf)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA2_384_GET_OUTPUT_LEN,"xd",prf,SHA384_DIGEST_LENGTH);
  return SHA384_DIGEST_LENGTH;
}

static int _rhp_crypto_openssl_prf_hmac_sha2_384_get_key_len(rhp_crypto_prf* prf)
{
  /*
   RFC5996(2.13 Generating Keying Material) says that:
     "It is assumed that PRFs accept keys of any length, but have a
     preferred key size.  The preferred key size MUST be used as the
     length of SK_d, SK_pi, and SK_pr (see Section 2.14).  For PRFs based
     on the HMAC construction, the preferred key size is equal to the
     length of the output of the underlying hash function.  Other types of
     PRFs MUST specify their preferred key size."
	*/

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA2_384_GET_KEY_LEN,"xd",prf,SHA384_DIGEST_LENGTH);
  return SHA384_DIGEST_LENGTH;// preferred key size for IKEv2 IKE SA's keying material.
}

static int _rhp_crypto_openssl_prf_hmac_sha2_384_set_key(rhp_crypto_prf* prf,u8* key,int key_len)
{
  if( prf->key ){
    RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA2_384_SET_KEY_FREE_OLD,"xp",prf,prf->key_len,prf->key);
    _rhp_free(prf->key);
  }

  prf->key = (u8*)_rhp_malloc(key_len);
  if( prf->key == NULL ){
    return -ENOMEM;
  }
  memcpy(prf->key,key,key_len);
  prf->key_len = key_len;

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA2_384_SET_KEY,"xp",prf,prf->key_len,prf->key);
  return 0;
}

static int _rhp_crypto_openssl_prf_hmac_sha2_384_compute(rhp_crypto_prf* prf,u8* data,int data_len,u8* outb,int outb_len)
{
  unsigned int olen;

  if( prf->key == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( outb_len < SHA384_DIGEST_LENGTH ){
    RHP_BUG("");
    return -EINVAL;
  }

  HMAC(EVP_sha384(),prf->key,prf->key_len,data,data_len,outb,&olen);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA2_384_COMPUTE,"xpp",prf,data_len,data,outb_len,outb);
  return 0;
}

static rhp_crypto_prf* _rhp_crypto_openssl_prf_hmac_sha2_384_alloc()
{
  rhp_crypto_prf* prf = (rhp_crypto_prf*)_rhp_malloc(sizeof(rhp_crypto_prf));

  if( prf == NULL ){
    RHP_BUG("");
    return NULL;
  }

  prf->alg = RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_384;
  prf->ctx = NULL;
  prf->key = NULL;

  prf->get_output_len = _rhp_crypto_openssl_prf_hmac_sha2_384_get_output_len;
  prf->get_key_len = _rhp_crypto_openssl_prf_hmac_sha2_384_get_key_len;
  prf->set_key = _rhp_crypto_openssl_prf_hmac_sha2_384_set_key;
  prf->compute = _rhp_crypto_openssl_prf_hmac_sha2_384_compute;

  RHP_TRC(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA2_384_ALLOC,"x",prf);
  return prf;
}

static void _rhp_crypto_openssl_prf_hmac_sha2_384_free(rhp_crypto_prf* prf)
{
  if( prf->key ){
    _rhp_free_zero(prf->key,prf->key_len);
  }
  _rhp_free(prf);
  RHP_TRC(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA2_384_FREE,"x",prf);
}



static int _rhp_crypto_openssl_prf_hmac_sha2_512_get_output_len(rhp_crypto_prf* prf)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA2_512_GET_OUTPUT_LEN,"xd",prf,SHA512_DIGEST_LENGTH);
  return SHA512_DIGEST_LENGTH;
}

static int _rhp_crypto_openssl_prf_hmac_sha2_512_get_key_len(rhp_crypto_prf* prf)
{
  /*
   RFC5996(2.13 Generating Keying Material) says that:
     "It is assumed that PRFs accept keys of any length, but have a
     preferred key size.  The preferred key size MUST be used as the
     length of SK_d, SK_pi, and SK_pr (see Section 2.14).  For PRFs based
     on the HMAC construction, the preferred key size is equal to the
     length of the output of the underlying hash function.  Other types of
     PRFs MUST specify their preferred key size."
	*/

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA2_512_GET_KEY_LEN,"xd",prf,SHA512_DIGEST_LENGTH);
  return SHA512_DIGEST_LENGTH;// preferred key size for IKEv2 IKE SA's keying material.
}

static int _rhp_crypto_openssl_prf_hmac_sha2_512_set_key(rhp_crypto_prf* prf,u8* key,int key_len)
{
  if( prf->key ){
    RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA2_512_SET_KEY_FREE_OLD,"xp",prf,prf->key_len,prf->key);
    _rhp_free(prf->key);
  }

  prf->key = (u8*)_rhp_malloc(key_len);
  if( prf->key == NULL ){
    return -ENOMEM;
  }
  memcpy(prf->key,key,key_len);
  prf->key_len = key_len;

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA2_512_SET_KEY,"xp",prf,prf->key_len,prf->key);
  return 0;
}

static int _rhp_crypto_openssl_prf_hmac_sha2_512_compute(rhp_crypto_prf* prf,u8* data,int data_len,u8* outb,int outb_len)
{
  unsigned int olen;

  if( prf->key == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( outb_len < SHA512_DIGEST_LENGTH ){
    RHP_BUG("");
    return -EINVAL;
  }

  HMAC(EVP_sha512(),prf->key,prf->key_len,data,data_len,outb,&olen);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA2_512_COMPUTE,"xpp",prf,data_len,data,outb_len,outb);
  return 0;
}

static rhp_crypto_prf* _rhp_crypto_openssl_prf_hmac_sha2_512_alloc()
{
  rhp_crypto_prf* prf = (rhp_crypto_prf*)_rhp_malloc(sizeof(rhp_crypto_prf));

  if( prf == NULL ){
    RHP_BUG("");
    return NULL;
  }

  prf->alg = RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_512;
  prf->ctx = NULL;
  prf->key = NULL;

  prf->get_output_len = _rhp_crypto_openssl_prf_hmac_sha2_512_get_output_len;
  prf->get_key_len = _rhp_crypto_openssl_prf_hmac_sha2_512_get_key_len;
  prf->set_key = _rhp_crypto_openssl_prf_hmac_sha2_512_set_key;
  prf->compute = _rhp_crypto_openssl_prf_hmac_sha2_512_compute;

  RHP_TRC(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA2_512_ALLOC,"x",prf);
  return prf;
}

static void _rhp_crypto_openssl_prf_hmac_sha2_512_free(rhp_crypto_prf* prf)
{
  if( prf->key ){
    _rhp_free_zero(prf->key,prf->key_len);
  }
  _rhp_free(prf);
  RHP_TRC(0,RHPTRCID_OPENSSL_PRF_HMAC_SHA2_512_FREE,"x",prf);
}



static int _rhp_crypto_openssl_prf_hmac_md5_get_output_len(rhp_crypto_prf* prf)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_HMAC_MD5_GET_OUTPUT_LEN,"xd",prf,MD5_DIGEST_LENGTH);
  return MD5_DIGEST_LENGTH;
}

static int _rhp_crypto_openssl_prf_hmac_md5_get_key_len(rhp_crypto_prf* prf)
{
  /*
   RFC5996(2.13 Generating Keying Material) says that:
     "It is assumed that PRFs accept keys of any length, but have a
     preferred key size.  The preferred key size MUST be used as the
     length of SK_d, SK_pi, and SK_pr (see Section 2.14).  For PRFs based
     on the HMAC construction, the preferred key size is equal to the
     length of the output of the underlying hash function.  Other types of
     PRFs MUST specify their preferred key size."
	*/

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_HMAC_MD5_GET_KEY_LEN,"xd",prf,MD5_DIGEST_LENGTH);
  return MD5_DIGEST_LENGTH; // preferred key size for IKEv2 IKE SA's keying material.
}

static int _rhp_crypto_openssl_prf_hmac_md5_set_key(rhp_crypto_prf* prf,u8* key,int key_len)
{
  if( prf->key ){
    RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_HMAC_MD5_SET_KEY_FREE_OLD,"xp",prf,prf->key_len,prf->key);
    _rhp_free(prf->key);
  }

  prf->key = (u8*)_rhp_malloc(key_len);
  if( prf->key == NULL ){
    return -ENOMEM;
  }
  memcpy(prf->key,key,key_len);
  prf->key_len = key_len;

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_HMAC_MD5_SET_KEY,"xp",prf,prf->key_len,prf->key);
  return 0;
}

static int _rhp_crypto_openssl_prf_hmac_md5_compute(rhp_crypto_prf* prf,u8* data,int data_len,u8* outb,int outb_len)
{
  unsigned int olen;

  if( prf->key == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( outb_len < MD5_DIGEST_LENGTH ){
    RHP_BUG("");
    return -EINVAL;
  }

  HMAC(EVP_md5(),prf->key,prf->key_len,data,data_len,outb,&olen);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_HMAC_MD5_COMPUTE,"xpp",prf,data_len,data,outb_len,outb);
  return 0;
}

static rhp_crypto_prf* _rhp_crypto_openssl_prf_hmac_md5_alloc()
{
  rhp_crypto_prf* prf = (rhp_crypto_prf*)_rhp_malloc(sizeof(rhp_crypto_prf));

  if( prf == NULL ){
    RHP_BUG("");
    return NULL;
  }

  prf->alg = RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_MD5;
  prf->ctx = NULL;
  prf->key = NULL;

  prf->get_output_len = _rhp_crypto_openssl_prf_hmac_md5_get_output_len;
  prf->get_key_len = _rhp_crypto_openssl_prf_hmac_md5_get_key_len;
  prf->set_key = _rhp_crypto_openssl_prf_hmac_md5_set_key;
  prf->compute = _rhp_crypto_openssl_prf_hmac_md5_compute;

  RHP_TRC(0,RHPTRCID_OPENSSL_PRF_HMAC_MD5_ALLOC,"x",prf);
  return prf;
}

static void _rhp_crypto_openssl_prf_hmac_md5_free(rhp_crypto_prf* prf)
{
  if( prf->key ){
    _rhp_free_zero(prf->key,prf->key_len);
  }
  _rhp_free(prf);
  RHP_TRC(0,RHPTRCID_OPENSSL_PRF_HMAC_MD5_FREE,"x",prf);
}



static int _rhp_crypto_openssl_integ_hmac_sha1_96_get_output_len(rhp_crypto_integ* integ)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA1_96_GET_OUTPUT_LEN,"xd",integ,12);
  return 12; // 96bits
}

static int _rhp_crypto_openssl_integ_hmac_sha1_96_get_key_len(rhp_crypto_integ* integ)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA1_96_GET_KEY_LEN,"xd",integ,SHA_DIGEST_LENGTH);
  return SHA_DIGEST_LENGTH;
}

static int _rhp_crypto_openssl_integ_hmac_sha1_96_set_key(rhp_crypto_integ* integ,u8* key,int key_len)
{

  if( integ->key ){
    RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA1_96_SET_KEY_FREE_OLD,"xp",integ,integ->key_len,integ->key);
    _rhp_free(integ->key);
  }

  integ->key = (u8*)_rhp_malloc(key_len);
  if( integ->key == NULL ){
	RHP_BUG("");
    return -ENOMEM;
  }
  memcpy(integ->key,key,key_len);
  integ->key_len = key_len;

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA1_96_SET_KEY,"xp",integ,integ->key_len,integ->key);
  return 0;
}

static int _rhp_crypto_openssl_integ_hmac_sha1_96_compute(rhp_crypto_integ* integ,u8* data,int data_len,u8* outb,int outb_len)
{
  unsigned int olen;
  u8 obuf[SHA_DIGEST_LENGTH];

  if( integ->key == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( outb_len < 12 ){
    RHP_BUG("");
    return -EINVAL;
  }

  HMAC(EVP_sha1(),integ->key,integ->key_len,data,data_len,obuf,&olen);
  memcpy(outb,obuf,12);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA1_96_COMPUTE,"xppp",integ,integ->key_len,integ->key,data_len,data,outb_len,outb);
  return 0;
}

static rhp_crypto_integ* _rhp_crypto_openssl_integ_hmac_sha1_96_alloc()
{
  rhp_crypto_integ* integ = (rhp_crypto_integ*)_rhp_malloc(sizeof(rhp_crypto_integ));

  if( integ == NULL ){
    RHP_BUG("");
    return NULL;
  }

  integ->alg = RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA1;
  integ->ctx = NULL;
  integ->key = NULL;

  integ->get_output_len = _rhp_crypto_openssl_integ_hmac_sha1_96_get_output_len;
  integ->get_key_len = _rhp_crypto_openssl_integ_hmac_sha1_96_get_key_len;
  integ->set_key = _rhp_crypto_openssl_integ_hmac_sha1_96_set_key;
  integ->compute = _rhp_crypto_openssl_integ_hmac_sha1_96_compute;

  RHP_TRC(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA1_96_ALLOC,"x",integ);
  return integ;
}

static void _rhp_crypto_openssl_integ_hmac_sha1_96_free(rhp_crypto_integ* integ)
{
  if( integ->key ){
    _rhp_free_zero(integ->key,integ->key_len);
  }
  _rhp_free(integ);
  RHP_TRC(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA1_96_FREE,"x",integ);
}



static int _rhp_crypto_openssl_integ_hmac_sha2_256_128_get_output_len(rhp_crypto_integ* integ)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA2_256_128_GET_OUTPUT_LEN,"xd",integ,16);
  return 16; // 128bits
}

static int _rhp_crypto_openssl_integ_hmac_sha2_256_128_get_key_len(rhp_crypto_integ* integ)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA2_256_128_GET_KEY_LEN,"xd",integ,SHA_DIGEST_LENGTH);
  return SHA256_DIGEST_LENGTH;
}

static int _rhp_crypto_openssl_integ_hmac_sha2_256_128_set_key(rhp_crypto_integ* integ,u8* key,int key_len)
{
  if( integ->key ){
    RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA2_256_128_SET_KEY_FREE_OLD,"xp",integ,integ->key_len,integ->key);
    _rhp_free(integ->key);
  }

  integ->key = (u8*)_rhp_malloc(key_len);
  if( integ->key == NULL ){
	RHP_BUG("");
    return -ENOMEM;
  }
  memcpy(integ->key,key,key_len);
  integ->key_len = key_len;

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA2_256_128_SET_KEY,"xp",integ,integ->key_len,integ->key);
  return 0;
}

static int _rhp_crypto_openssl_integ_hmac_sha2_256_128_compute(rhp_crypto_integ* integ,u8* data,int data_len,u8* outb,int outb_len)
{
  unsigned int olen;
  u8 obuf[SHA256_DIGEST_LENGTH];

  if( integ->key == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( outb_len < 16 ){
    RHP_BUG("");
    return -EINVAL;
  }

  HMAC(EVP_sha256(),integ->key,integ->key_len,data,data_len,obuf,&olen);
  memcpy(outb,obuf,16);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA2_256_128_COMPUTE,"xppp",integ,integ->key_len,integ->key,data_len,data,outb_len,outb);
  return 0;
}

static rhp_crypto_integ* _rhp_crypto_openssl_integ_hmac_sha2_256_128_alloc()
{
  rhp_crypto_integ* integ = (rhp_crypto_integ*)_rhp_malloc(sizeof(rhp_crypto_integ));

  if( integ == NULL ){
    RHP_BUG("");
    return NULL;
  }

  integ->alg = RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_256_128;
  integ->ctx = NULL;
  integ->key = NULL;

  integ->get_output_len = _rhp_crypto_openssl_integ_hmac_sha2_256_128_get_output_len;
  integ->get_key_len = _rhp_crypto_openssl_integ_hmac_sha2_256_128_get_key_len;
  integ->set_key = _rhp_crypto_openssl_integ_hmac_sha2_256_128_set_key;
  integ->compute = _rhp_crypto_openssl_integ_hmac_sha2_256_128_compute;

  RHP_TRC(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA2_256_128_ALLOC,"x",integ);
  return integ;
}

static void _rhp_crypto_openssl_integ_hmac_sha2_256_128_free(rhp_crypto_integ* integ)
{
  if( integ->key ){
    _rhp_free_zero(integ->key,integ->key_len);
  }
  _rhp_free(integ);
  RHP_TRC(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA2_256_128_FREE,"x",integ);
}



static int _rhp_crypto_openssl_integ_hmac_sha2_384_192_get_output_len(rhp_crypto_integ* integ)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA2_384_192_GET_OUTPUT_LEN,"xd",integ,24);
  return 24; // 192bits
}

static int _rhp_crypto_openssl_integ_hmac_sha2_384_192_get_key_len(rhp_crypto_integ* integ)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA2_384_192_GET_KEY_LEN,"xd",integ,SHA_DIGEST_LENGTH);
  return SHA384_DIGEST_LENGTH;
}

static int _rhp_crypto_openssl_integ_hmac_sha2_384_192_set_key(rhp_crypto_integ* integ,u8* key,int key_len)
{
  if( integ->key ){
    RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA2_384_192_SET_KEY_FREE_OLD,"xp",integ,integ->key_len,integ->key);
    _rhp_free(integ->key);
  }

  integ->key = (u8*)_rhp_malloc(key_len);
  if( integ->key == NULL ){
	RHP_BUG("");
    return -ENOMEM;
  }
  memcpy(integ->key,key,key_len);
  integ->key_len = key_len;

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA2_384_192_SET_KEY,"xp",integ,integ->key_len,integ->key);
  return 0;
}

static int _rhp_crypto_openssl_integ_hmac_sha2_384_192_compute(rhp_crypto_integ* integ,u8* data,int data_len,u8* outb,int outb_len)
{
  unsigned int olen;
  u8 obuf[SHA384_DIGEST_LENGTH];

  if( integ->key == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( outb_len < 24 ){
    RHP_BUG("");
    return -EINVAL;
  }

  HMAC(EVP_sha384(),integ->key,integ->key_len,data,data_len,obuf,&olen);
  memcpy(outb,obuf,24);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA2_384_192_COMPUTE,"xppp",integ,integ->key_len,integ->key,data_len,data,outb_len,outb);
  return 0;
}

static rhp_crypto_integ* _rhp_crypto_openssl_integ_hmac_sha2_384_192_alloc()
{
  rhp_crypto_integ* integ = (rhp_crypto_integ*)_rhp_malloc(sizeof(rhp_crypto_integ));

  if( integ == NULL ){
    RHP_BUG("");
    return NULL;
  }

  integ->alg = RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_384_192;
  integ->ctx = NULL;
  integ->key = NULL;

  integ->get_output_len = _rhp_crypto_openssl_integ_hmac_sha2_384_192_get_output_len;
  integ->get_key_len = _rhp_crypto_openssl_integ_hmac_sha2_384_192_get_key_len;
  integ->set_key = _rhp_crypto_openssl_integ_hmac_sha2_384_192_set_key;
  integ->compute = _rhp_crypto_openssl_integ_hmac_sha2_384_192_compute;

  RHP_TRC(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA2_384_192_ALLOC,"x",integ);
  return integ;
}

static void _rhp_crypto_openssl_integ_hmac_sha2_384_192_free(rhp_crypto_integ* integ)
{
  if( integ->key ){
    _rhp_free_zero(integ->key,integ->key_len);
  }
  _rhp_free(integ);
  RHP_TRC(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA2_384_192_FREE,"x",integ);
}



static int _rhp_crypto_openssl_integ_hmac_sha2_512_256_get_output_len(rhp_crypto_integ* integ)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA2_512_256_GET_OUTPUT_LEN,"xd",integ,32);
  return 32; // 256bits
}

static int _rhp_crypto_openssl_integ_hmac_sha2_512_256_get_key_len(rhp_crypto_integ* integ)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA2_512_256_GET_KEY_LEN,"xd",integ,SHA_DIGEST_LENGTH);
  return SHA512_DIGEST_LENGTH;
}

static int _rhp_crypto_openssl_integ_hmac_sha2_512_256_set_key(rhp_crypto_integ* integ,u8* key,int key_len)
{
  if( integ->key ){
    RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA2_512_256_SET_KEY_FREE_OLD,"xp",integ,integ->key_len,integ->key);
    _rhp_free(integ->key);
  }

  integ->key = (u8*)_rhp_malloc(key_len);
  if( integ->key == NULL ){
	RHP_BUG("");
    return -ENOMEM;
  }
  memcpy(integ->key,key,key_len);
  integ->key_len = key_len;

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA2_512_256_SET_KEY,"xp",integ,integ->key_len,integ->key);
  return 0;
}

static int _rhp_crypto_openssl_integ_hmac_sha2_512_256_compute(rhp_crypto_integ* integ,u8* data,int data_len,u8* outb,int outb_len)
{
  unsigned int olen;
  u8 obuf[SHA512_DIGEST_LENGTH];

  if( integ->key == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( outb_len < 32 ){
    RHP_BUG("");
    return -EINVAL;
  }

  HMAC(EVP_sha512(),integ->key,integ->key_len,data,data_len,obuf,&olen);
  memcpy(outb,obuf,32);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA2_512_256_COMPUTE,"xppp",integ,integ->key_len,integ->key,data_len,data,outb_len,outb);
  return 0;
}

static rhp_crypto_integ* _rhp_crypto_openssl_integ_hmac_sha2_512_256_alloc()
{
  rhp_crypto_integ* integ = (rhp_crypto_integ*)_rhp_malloc(sizeof(rhp_crypto_integ));

  if( integ == NULL ){
    RHP_BUG("");
    return NULL;
  }

  integ->alg = RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_512_256;
  integ->ctx = NULL;
  integ->key = NULL;

  integ->get_output_len = _rhp_crypto_openssl_integ_hmac_sha2_512_256_get_output_len;
  integ->get_key_len = _rhp_crypto_openssl_integ_hmac_sha2_512_256_get_key_len;
  integ->set_key = _rhp_crypto_openssl_integ_hmac_sha2_512_256_set_key;
  integ->compute = _rhp_crypto_openssl_integ_hmac_sha2_512_256_compute;

  RHP_TRC(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA2_512_256_ALLOC,"x",integ);
  return integ;
}

static void _rhp_crypto_openssl_integ_hmac_sha2_512_256_free(rhp_crypto_integ* integ)
{
  if( integ->key ){
    _rhp_free_zero(integ->key,integ->key_len);
  }
  _rhp_free(integ);
  RHP_TRC(0,RHPTRCID_OPENSSL_INTEG_HMAC_SHA2_512_256_FREE,"x",integ);
}



static int _rhp_crypto_openssl_integ_hmac_md5_96_get_output_len(rhp_crypto_integ* integ)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_INTEG_HMAC_MD5_96_GET_OUTPUT_LEN,"xd",integ,12);
  return 12; // 96bits
}

static int _rhp_crypto_openssl_integ_hmac_md5_96_get_key_len(rhp_crypto_integ* integ)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_INTEG_HMAC_MD5_96_GET_KEY_LEN,"xd",integ,SHA_DIGEST_LENGTH);
  return MD5_DIGEST_LENGTH;
}

static int _rhp_crypto_openssl_integ_hmac_md5_96_set_key(rhp_crypto_integ* integ,u8* key,int key_len)
{

  if( integ->key ){
    RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_INTEG_HMAC_MD5_96_SET_KEY_FREE_OLD,"xp",integ,integ->key_len,integ->key);
    _rhp_free(integ->key);
  }

  integ->key = (u8*)_rhp_malloc(key_len);
  if( integ->key == NULL ){
  	RHP_BUG("");
  	return -ENOMEM;
  }
  memcpy(integ->key,key,key_len);
  integ->key_len = key_len;

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_INTEG_HMAC_MD5_96_SET_KEY,"xp",integ,integ->key_len,integ->key);
  return 0;
}

static int _rhp_crypto_openssl_integ_hmac_md5_96_compute(rhp_crypto_integ* integ,u8* data,int data_len,u8* outb,int outb_len)
{
  unsigned int olen;
  u8 obuf[MD5_DIGEST_LENGTH];

  if( integ->key == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( outb_len < 12 ){
    RHP_BUG("");
    return -EINVAL;
  }

  HMAC(EVP_md5(),integ->key,integ->key_len,data,data_len,obuf,&olen);
  memcpy(outb,obuf,12);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_INTEG_HMAC_MD5_96_COMPUTE,"xppp",integ,integ->key_len,integ->key,data_len,data,outb_len,outb);
  return 0;
}

static rhp_crypto_integ* _rhp_crypto_openssl_integ_hmac_md5_96_alloc()
{
  rhp_crypto_integ* integ = (rhp_crypto_integ*)_rhp_malloc(sizeof(rhp_crypto_integ));

  if( integ == NULL ){
    RHP_BUG("");
    return NULL;
  }

  integ->alg = RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_MD5;
  integ->ctx = NULL;
  integ->key = NULL;

  integ->get_output_len = _rhp_crypto_openssl_integ_hmac_md5_96_get_output_len;
  integ->get_key_len = _rhp_crypto_openssl_integ_hmac_md5_96_get_key_len;
  integ->set_key = _rhp_crypto_openssl_integ_hmac_md5_96_set_key;
  integ->compute = _rhp_crypto_openssl_integ_hmac_md5_96_compute;

  RHP_TRC(0,RHPTRCID_OPENSSL_INTEG_HMAC_MD5_96_ALLOC,"x",integ);
  return integ;
}

static void _rhp_crypto_openssl_integ_hmac_md5_96_free(rhp_crypto_integ* integ)
{
  if( integ->key ){
    _rhp_free_zero(integ->key,integ->key_len);
  }

  _rhp_free(integ);

  RHP_TRC(0,RHPTRCID_OPENSSL_INTEG_HMAC_MD5_96_FREE,"x",integ);
  return;
}


static int _rhp_crypto_openssl_encr_aes_cbc_get_iv_len(rhp_crypto_encr* encr)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_ENCR_AES_CBC_GET_IV_LEN,"xd",encr,AES_BLOCK_SIZE);
  return AES_BLOCK_SIZE;
}

static int _rhp_crypto_openssl_encr_aes_cbc_get_block_len(rhp_crypto_encr* encr)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_ENCR_AES_CBC_GET_BLOCK_LEN,"xd",encr,AES_BLOCK_SIZE);
  return AES_BLOCK_SIZE;
}

static int _rhp_crypto_openssl_encr_aes_cbc_get_block_aligned_len(rhp_crypto_encr* encr,int data_len)
{
  int ret = (data_len+(AES_BLOCK_SIZE-1)) & ~(AES_BLOCK_SIZE-1);
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_ENCR_AES_CBC_GET_BLOCK_ALIGNED_LEN,"xd",encr,ret);
  return ret;
}

static int _rhp_crypto_openssl_encr_aes_cbc_get_key_len(rhp_crypto_encr* encr)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_ENCR_AES_CBC_GET_KEY_LEN,"xd",encr,encr->key_len);
  return encr->key_len;
}

static int _rhp_crypto_openssl_encr_aes_cbc_set_enc_key(rhp_crypto_encr* encr,u8* key,int key_len)
{
  if( key_len != encr->key_len ){
    RHP_BUG(" %d != %d ",key_len,encr->key_len);
    return -EINVAL;
  }

  if( encr->enc_key == NULL ){

    encr->enc_key = (u8*)_rhp_malloc(key_len);

    if( encr->enc_key == NULL ){
      RHP_BUG("");
      return -ENOMEM;
    }
  }
  memcpy(encr->enc_key,key,key_len);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_ENCR_AES_CBC_SET_ENC_KEY,"xp",encr,key_len,key);
  return 0;
}

static int _rhp_crypto_openssl_encr_aes_cbc_set_dec_key(rhp_crypto_encr* encr,u8* key,int key_len)
{
  if( key_len != encr->key_len ){
    RHP_BUG(" %d != %d ",key_len,encr->key_len);
    return -EINVAL;
  }

  if( encr->dec_key == NULL ){

    encr->dec_key = (u8*)_rhp_malloc(key_len);

    if( encr->dec_key == NULL ){
      RHP_BUG("");
      return -ENOMEM;
    }
  }
  memcpy(encr->dec_key,key,key_len);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_ENCR_AES_CBC_SET_DEC_KEY,"xp",encr,key_len,key);
  return 0;
}

static int _rhp_crypto_openssl_encr_aes_cbc_encrypt(rhp_crypto_encr* encr,u8* plain_txt,int plain_txt_len,
    u8* outb,int outb_len)
{
  EVP_CIPHER_CTX *ctx;
  const EVP_CIPHER* type;
  int olen;
  int iv_len = encr->get_iv_len(encr);

  if( encr->enc_key == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( outb_len != plain_txt_len ){
    RHP_BUG("");
    return -EINVAL;
  }

  switch( encr->key_len ){
    case 16: // 128bits
      type = EVP_aes_128_cbc();
      break;
    case 24: // 192bits
      type = EVP_aes_192_cbc();
      break;
    case 32: // 256bits
      type = EVP_aes_256_cbc();
      break;
    default:
      RHP_BUG("");
      return -EINVAL;
  }

  ctx = EVP_CIPHER_CTX_new();

  if( EVP_EncryptInit_ex(ctx,type,NULL,encr->enc_key,encr->enc_iv) == 0 ){
    RHP_BUG("");
    goto error;
  }

  EVP_CIPHER_CTX_set_padding(ctx,0);

  if( EVP_EncryptUpdate(ctx,outb,&olen,plain_txt,plain_txt_len) == 0 ){
    RHP_BUG("");
    goto error;
  }

  if( EVP_EncryptFinal_ex(ctx,NULL,&olen) == 0 ){
    RHP_BUG("");
    goto error;
  }

  EVP_CIPHER_CTX_free(ctx);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_ENCR_AES_CBC_ENCRYPT,"xpppp",encr,encr->key_len,encr->enc_key,iv_len,encr->enc_iv,plain_txt_len,plain_txt,outb_len,outb);
  return 0;

error:
  EVP_CIPHER_CTX_free(ctx);
  return -EINVAL;
}

static int _rhp_crypto_openssl_encr_aes_cbc_decrypt(rhp_crypto_encr* encr,u8* cipher_txt,int cipher_txt_len,
    u8* outb,int outb_len,u8* iv)
{
  EVP_CIPHER_CTX *ctx;
  const EVP_CIPHER* type;
  int olen;
  int iv_len = encr->get_iv_len(encr);

  if( encr->dec_key == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( outb_len != cipher_txt_len ){
    RHP_BUG("");
    return -EINVAL;
  }

  switch( encr->key_len ){
    case 16: // 128bits
      type = EVP_aes_128_cbc();
      break;
    case 24: // 192bits
      type = EVP_aes_192_cbc();
      break;
    case 32: // 256bits
      type = EVP_aes_256_cbc();
      break;
    default:
      RHP_BUG("");
      return -EINVAL;
  }

  ctx = EVP_CIPHER_CTX_new();

  if( EVP_DecryptInit(ctx,type,encr->dec_key,iv) == 0 ){
    RHP_BUG("");
    goto error;
  }

  EVP_CIPHER_CTX_set_padding(ctx,0);

  if( EVP_DecryptUpdate(ctx,outb,&olen,cipher_txt,cipher_txt_len) == 0 ){
    RHP_BUG("");
    goto error;
  }

  if( EVP_DecryptFinal_ex(ctx,NULL,&olen) == 0 ){
    RHP_BUG("");
    goto error;
  }

  EVP_CIPHER_CTX_free(ctx);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_ENCR_AES_CBC_DECRYPT,"xppppp",encr,encr->key_len,encr->dec_key,iv_len,iv,cipher_txt_len,cipher_txt,outb_len,outb,AES_BLOCK_SIZE,iv);
  return 0;

error:
  EVP_CIPHER_CTX_free(ctx);
  return -EINVAL;
}

static int _rhp_crypto_openssl_encr_aes_cbc_update_enc_iv(rhp_crypto_encr* encr,u8* enc_iv,int enc_iv_len)
{
  if( enc_iv_len != AES_BLOCK_SIZE ){
    RHP_BUG("");
    return -EINVAL;
  }

  memcpy(encr->enc_iv,enc_iv,enc_iv_len);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_ENCR_AES_CBC_UPDATE_ENC_IV,"xp",encr,enc_iv_len,enc_iv);
  return 0;
}

static u8* _rhp_crypto_openssl_encr_aes_cbc_get_enc_iv(rhp_crypto_encr* encr)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_ENCR_AES_CBC_GET_ENC_IV,"xp",encr,AES_BLOCK_SIZE,encr->enc_iv);
  return encr->enc_iv;
}


static rhp_crypto_encr* _rhp_crypto_openssl_encr_aes_cbc_alloc(int key_bits_len)
{
  rhp_crypto_encr* encr = (rhp_crypto_encr*)_rhp_malloc(sizeof(rhp_crypto_encr));

  if( encr == NULL ){
    RHP_BUG("");
    return NULL;
  }

  encr->enc_iv = (u8*)_rhp_malloc(AES_BLOCK_SIZE);
  if( encr->enc_iv == NULL ){
    _rhp_free(encr);
    RHP_BUG("");
    return NULL;
  }

  if( rhp_random_bytes(encr->enc_iv,AES_BLOCK_SIZE) ){
    _rhp_free(encr->enc_iv);
    _rhp_free(encr);
    RHP_BUG("");
    return NULL;
  }

  encr->alg = RHP_PROTO_IKE_TRANSFORM_ID_ENCR_AES_CBC;

  encr->ctx_enc = NULL;
  encr->ctx_dec = NULL;
  encr->enc_key = NULL;
  encr->dec_key = NULL;
  encr->key_len = key_bits_len / 8;
  encr->alg_key_bits = key_bits_len;

  encr->get_iv_len = _rhp_crypto_openssl_encr_aes_cbc_get_iv_len;
  encr->get_block_len = _rhp_crypto_openssl_encr_aes_cbc_get_block_len;
  encr->get_block_aligned_len = _rhp_crypto_openssl_encr_aes_cbc_get_block_aligned_len;

  encr->get_key_len = _rhp_crypto_openssl_encr_aes_cbc_get_key_len;
  encr->set_enc_key = _rhp_crypto_openssl_encr_aes_cbc_set_enc_key;
  encr->set_dec_key = _rhp_crypto_openssl_encr_aes_cbc_set_dec_key;
  encr->encrypt = _rhp_crypto_openssl_encr_aes_cbc_encrypt;
  encr->decrypt = _rhp_crypto_openssl_encr_aes_cbc_decrypt;
  encr->update_enc_iv = _rhp_crypto_openssl_encr_aes_cbc_update_enc_iv;
  encr->get_enc_iv = _rhp_crypto_openssl_encr_aes_cbc_get_enc_iv;

  RHP_TRC(0,RHPTRCID_OPENSSL_ENCR_AES_CBC_ALLOC,"x",encr);
  return encr;
}

static void _rhp_crypto_openssl_encr_aes_cbc_free(rhp_crypto_encr* encr)
{
  if( encr->enc_iv ){
    _rhp_free(encr->enc_iv);
  }
  if( encr->enc_key ){
    _rhp_free_zero(encr->enc_key,encr->key_len);
  }
  if( encr->dec_key ){
    _rhp_free_zero(encr->dec_key,encr->key_len);
  }
  _rhp_free(encr);
  RHP_TRC(0,RHPTRCID_OPENSSL_ENCR_AES_CBC_FREE,"x",encr);

  return;
}


#define	RHP_DES_BLOCK_SIZE				8
#define	RHP_3DES_KEY_LEN					24

static int _rhp_crypto_openssl_encr_3des_cbc_get_iv_len(rhp_crypto_encr* encr)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_ENCR_3DES_CBC_GET_IV_LEN,"xd",encr,RHP_DES_BLOCK_SIZE);
  return RHP_DES_BLOCK_SIZE;
}

static int _rhp_crypto_openssl_encr_3des_cbc_get_block_len(rhp_crypto_encr* encr)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_ENCR_3DES_CBC_GET_BLOCK_LEN,"xd",encr,RHP_DES_BLOCK_SIZE);
  return RHP_DES_BLOCK_SIZE;
}

static int _rhp_crypto_openssl_encr_3des_cbc_get_block_aligned_len(rhp_crypto_encr* encr,int data_len)
{
  int ret = (data_len+(RHP_DES_BLOCK_SIZE-1)) & ~(RHP_DES_BLOCK_SIZE-1);
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_ENCR_3DES_CBC_GET_BLOCK_ALIGNED_LEN,"xd",encr,ret);
  return ret;
}

static int _rhp_crypto_openssl_encr_3des_cbc_get_key_len(rhp_crypto_encr* encr)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_ENCR_3DES_CBC_GET_KEY_LEN,"xd",encr,encr->key_len);
  return encr->key_len;
}

static int _rhp_crypto_openssl_encr_3des_cbc_set_enc_key(rhp_crypto_encr* encr,u8* key,int key_len)
{
  if( key_len != encr->key_len ){
    RHP_BUG(" %d != %d ",key_len,encr->key_len);
    return -EINVAL;
  }

  if( encr->enc_key == NULL ){

    encr->enc_key = (u8*)_rhp_malloc(key_len);

    if( encr->enc_key == NULL ){
      RHP_BUG("");
      return -ENOMEM;
    }
  }
  memcpy(encr->enc_key,key,key_len);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_ENCR_3DES_CBC_SET_ENC_KEY,"xp",encr,key_len,key);
  return 0;
}

static int _rhp_crypto_openssl_encr_3des_cbc_set_dec_key(rhp_crypto_encr* encr,u8* key,int key_len)
{
  if( key_len != encr->key_len ){
    RHP_BUG(" %d != %d ",key_len,encr->key_len);
    return -EINVAL;
  }

  if( encr->dec_key == NULL ){

    encr->dec_key = (u8*)_rhp_malloc(key_len);

    if( encr->dec_key == NULL ){
      RHP_BUG("");
      return -ENOMEM;
    }
  }
  memcpy(encr->dec_key,key,key_len);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_ENCR_3DES_CBC_SET_DEC_KEY,"xp",encr,key_len,key);
  return 0;
}

static int _rhp_crypto_openssl_encr_3des_cbc_encrypt(rhp_crypto_encr* encr,u8* plain_txt,int plain_txt_len,
    u8* outb,int outb_len)
{
  EVP_CIPHER_CTX *ctx;
  const EVP_CIPHER* type = EVP_des_ede3_cbc();
  int olen;
  int iv_len = encr->get_iv_len(encr);

  if( encr->enc_key == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( outb_len != plain_txt_len ){
    RHP_BUG("");
    return -EINVAL;
  }

  ctx = EVP_CIPHER_CTX_new();

  if( EVP_EncryptInit_ex(ctx,type,NULL,encr->enc_key,encr->enc_iv) == 0 ){
    RHP_BUG("");
    goto error;
  }

  EVP_CIPHER_CTX_set_padding(ctx,0);

  if( EVP_EncryptUpdate(ctx,outb,&olen,plain_txt,plain_txt_len) == 0 ){
    RHP_BUG("");
    goto error;
  }

  if( EVP_EncryptFinal_ex(ctx,NULL,&olen) == 0 ){
    RHP_BUG("");
    goto error;
  }

  EVP_CIPHER_CTX_free(ctx);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_ENCR_3DES_CBC_ENCRYPT,"xpppp",encr,encr->key_len,encr->enc_key,iv_len,encr->enc_iv,plain_txt_len,plain_txt,outb_len,outb);
  return 0;

error:
  EVP_CIPHER_CTX_free(ctx);
  return -EINVAL;
}

static int _rhp_crypto_openssl_encr_3des_cbc_decrypt(rhp_crypto_encr* encr,u8* cipher_txt,int cipher_txt_len,
    u8* outb,int outb_len,u8* iv)
{
  EVP_CIPHER_CTX *ctx;
  const EVP_CIPHER* type = EVP_des_ede3_cbc();
  int olen;
  int iv_len = encr->get_iv_len(encr);

  if( encr->dec_key == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( outb_len != cipher_txt_len ){
    RHP_BUG("");
    return -EINVAL;
  }

  ctx = EVP_CIPHER_CTX_new();

  if( EVP_DecryptInit(ctx,type,encr->dec_key,iv) == 0 ){
    RHP_BUG("");
    goto error;
  }

  EVP_CIPHER_CTX_set_padding(ctx,0);

  if( EVP_DecryptUpdate(ctx,outb,&olen,cipher_txt,cipher_txt_len) == 0 ){
    RHP_BUG("");
    goto error;
  }

  if( EVP_DecryptFinal_ex(ctx,NULL,&olen) == 0 ){
    RHP_BUG("");
    goto error;
  }

  EVP_CIPHER_CTX_free(ctx);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_ENCR_3DES_CBC_DECRYPT,"xppppp",encr,encr->key_len,encr->dec_key,iv_len,iv,cipher_txt_len,cipher_txt,outb_len,outb,RHP_DES_BLOCK_SIZE,iv);
  return 0;

error:
  EVP_CIPHER_CTX_free(ctx);
  return -EINVAL;
}

static int _rhp_crypto_openssl_encr_3des_cbc_update_enc_iv(rhp_crypto_encr* encr,u8* enc_iv,int enc_iv_len)
{
  if( enc_iv_len != RHP_DES_BLOCK_SIZE ){
    RHP_BUG("");
    return -EINVAL;
  }

  memcpy(encr->enc_iv,enc_iv,enc_iv_len);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_ENCR_3DES_CBC_UPDATE_ENC_IV,"xp",encr,enc_iv_len,enc_iv);
  return 0;
}

static u8* _rhp_crypto_openssl_encr_3des_cbc_get_enc_iv(rhp_crypto_encr* encr)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_ENCR_3DES_CBC_GET_ENC_IV,"xp",encr,RHP_DES_BLOCK_SIZE,encr->enc_iv);
  return encr->enc_iv;
}


static rhp_crypto_encr* _rhp_crypto_openssl_encr_3des_cbc_alloc()
{
  rhp_crypto_encr* encr = (rhp_crypto_encr*)_rhp_malloc(sizeof(rhp_crypto_encr));

  if( encr == NULL ){
    RHP_BUG("");
    return NULL;
  }

  encr->enc_iv = (u8*)_rhp_malloc(RHP_DES_BLOCK_SIZE);
  if( encr->enc_iv == NULL ){
    _rhp_free(encr);
    RHP_BUG("");
    return NULL;
  }

  if( rhp_random_bytes(encr->enc_iv,RHP_DES_BLOCK_SIZE) ){
    _rhp_free(encr->enc_iv);
    _rhp_free(encr);
    RHP_BUG("");
    return NULL;
  }

  encr->alg = RHP_PROTO_IKE_TRANSFORM_ID_ENCR_3DES;

  encr->ctx_enc = NULL;
  encr->ctx_dec = NULL;
  encr->enc_key = NULL;
  encr->dec_key = NULL;
  encr->key_len = RHP_3DES_KEY_LEN;
  encr->alg_key_bits = 0;

  encr->get_iv_len = _rhp_crypto_openssl_encr_3des_cbc_get_iv_len;
  encr->get_block_len = _rhp_crypto_openssl_encr_3des_cbc_get_block_len;
  encr->get_block_aligned_len = _rhp_crypto_openssl_encr_3des_cbc_get_block_aligned_len;

  encr->get_key_len = _rhp_crypto_openssl_encr_3des_cbc_get_key_len;
  encr->set_enc_key = _rhp_crypto_openssl_encr_3des_cbc_set_enc_key;
  encr->set_dec_key = _rhp_crypto_openssl_encr_3des_cbc_set_dec_key;
  encr->encrypt = _rhp_crypto_openssl_encr_3des_cbc_encrypt;
  encr->decrypt = _rhp_crypto_openssl_encr_3des_cbc_decrypt;
  encr->update_enc_iv = _rhp_crypto_openssl_encr_3des_cbc_update_enc_iv;
  encr->get_enc_iv = _rhp_crypto_openssl_encr_3des_cbc_get_enc_iv;

  RHP_TRC(0,RHPTRCID_OPENSSL_ENCR_3DES_CBC_ALLOC,"x",encr);
  return encr;
}

static void _rhp_crypto_openssl_encr_3des_cbc_free(rhp_crypto_encr* encr)
{
  if( encr->enc_iv ){
    _rhp_free(encr->enc_iv);
  }
  if( encr->enc_key ){
    _rhp_free_zero(encr->enc_key,encr->key_len);
  }
  if( encr->dec_key ){
    _rhp_free_zero(encr->dec_key,encr->key_len);
  }
  _rhp_free(encr);
  RHP_TRC(0,RHPTRCID_OPENSSL_ENCR_3DES_CBC_FREE,"x",encr);
}


static int _rhp_crypto_dh_alloc(rhp_crypto_dh* dh)
{
  int err = -EINVAL;
  u8* prime;
  int prime_len;
  DH* dh_ctx = NULL;

  dh_ctx = DH_new();
  if( dh_ctx == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }
  dh->ctx = (void*)dh_ctx;

  if( _rhp_crypto_openssl_dh_get_dh_prime(dh->grp,&prime,&prime_len) ){
    RHP_BUG("");
    goto error;
  }

  BIGNUM *p, *g;
  p = BN_bin2bn(prime,prime_len,NULL);
  g = BN_new();
  if (p == NULL || g == NULL) {
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }
  if (!BN_set_word(g, RHP_PROTO_IKE_DH_GENERATOR)) {
    RHP_BUG("");
    goto error;
  }

  if (!DH_set0_pqg(dh_ctx, p, NULL, g)){
    RHP_BUG("");
    goto error;
  }

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_DH_ALLOC_IMPL,"xd",dh,dh->grp);
  return 0;

error:
  if( dh_ctx ){
    DH_free(dh_ctx);
  }
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_DH_ALLOC_IMPL_ERR,"xd",dh,err);
  return err;
}

static void _rhp_crypto_dh_free(rhp_crypto_dh* dh)
{
  if( dh->my_pub_key ){
    _rhp_free(dh->my_pub_key);
    dh->my_pub_key = NULL;
    dh->my_pub_key_len = 0;
  }
  if( dh->shared_key ){
    _rhp_free_zero(dh->shared_key,dh->shared_key_len);
    dh->shared_key = NULL;
    dh->shared_key_len = 0;
  }
  if( dh->peer_pub_key ){
    _rhp_free(dh->peer_pub_key);
    dh->peer_pub_key = NULL;
    dh->peer_pub_key_len = 0;
  }
  if( dh->ctx ){
    DH_free(dh->ctx);
    dh->ctx = NULL;
  }
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_DH_FREE_IMPL,"x",dh);
}

static int _rhp_crypto_openssl_dh_reset(rhp_crypto_dh* dh)
{
  int err;
  _rhp_crypto_dh_free(dh);
  err = _rhp_crypto_dh_alloc(dh);
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_DH_RESET,"xdd",dh,err,dh->grp);
  return err;
}

rhp_crypto_dh* rhp_crypto_dh_alloc(int dhgrp)
{
  rhp_crypto_dh* dh = NULL;

  dh = (rhp_crypto_dh*)_rhp_malloc(sizeof(rhp_crypto_dh));
  if( dh == NULL ){
    RHP_BUG("");
    return NULL;
  }
  memset(dh,0,sizeof(rhp_crypto_dh));

  dh->grp = dhgrp;

  dh->generate_key = _rhp_crypto_openssl_dh_generate_key;
  dh->compute_key = _rhp_crypto_openssl_dh_compute_key;
  dh->get_shared_key = _rhp_crypto_openssl_dh_get_shared_key;
  dh->get_my_pub_key = _rhp_crypto_openssl_dh_get_my_pub_key;
  dh->set_peer_pub_key = _rhp_crypto_openssl_dh_set_peer_pub_key;
  dh->get_peer_pub_key = _rhp_crypto_openssl_dh_get_peer_pub_key;
  dh->reset = _rhp_crypto_openssl_dh_reset;

  if( _rhp_crypto_dh_alloc(dh) ){
  	RHP_BUG("");
    goto error;
  }

  RHP_TRC(0,RHPTRCID_OPENSSL_DH_ALLOC,"xd",dh,dh->grp);
  return dh;

error:
  if( dh ){
    _rhp_free(dh);
  }
  return NULL;
}

void rhp_crypto_dh_free(rhp_crypto_dh* dh)
{
	if( dh == NULL ){
		return;
	}
  _rhp_crypto_dh_free(dh);
  _rhp_free_zero(dh,sizeof(rhp_crypto_dh));
  RHP_TRC(0,RHPTRCID_OPENSSL_DH_FREE,"x",dh);
  return;
}

rhp_crypto_nonce* rhp_crypto_nonce_alloc()
{
  rhp_crypto_nonce* nonce;

  nonce = (rhp_crypto_nonce*)_rhp_malloc(sizeof(rhp_crypto_nonce));
  if( nonce == NULL ){
    RHP_BUG("");
    return NULL;
  }
  memset(nonce,0,sizeof(rhp_crypto_nonce));

  nonce->set_nonce = _rhp_crypto_openssl_nonce_set_nonce;
  nonce->generate_nonce = _rhp_crypto_openssl_nonce_generate_nonce;
  nonce->get_nonce_len = _rhp_crypto_openssl_nonce_get_nonce_len;
  nonce->copy_nonce = _rhp_crypto_openssl_nonce_copy_nonce;
  nonce->get_nonce = _rhp_crypto_openssl_nonce_get_nonce;

  RHP_TRC(0,RHPTRCID_OPENSSL_NONCE_ALLOC,"x",nonce);
  return nonce;
}

void rhp_crypto_nonce_free(rhp_crypto_nonce* nonce)
{
	if( nonce == NULL ){
		return;
	}
  if( nonce->nonce ){
    _rhp_free(nonce->nonce);
  }
  _rhp_free(nonce);

  RHP_TRC(0,RHPTRCID_OPENSSL_NONCE_FREE,"x",nonce);

  return;
}

static int _rhp_crypto_openssl_rsasig_set_priv_key(rhp_crypto_rsasig* rsasig,u8* priv_key,int priv_key_len)
{
  rsasig->priv_key = (u8*)_rhp_malloc(priv_key_len);
  if( rsasig->priv_key == NULL ){
	RHP_BUG("");
    return -ENOMEM;
  }
  memcpy(rsasig->priv_key,priv_key,priv_key_len);
  rsasig->priv_key_len = priv_key_len;

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_RSASIG_SET_PRIV_KEY,"xp",rsasig,priv_key_len,priv_key);
  return 0;
}

static int _rhp_crypto_openssl_rsasig_set_pub_key(rhp_crypto_rsasig* rsasig,u8* pub_key,int pub_key_len)
{
  rsasig->pub_key = (u8*)_rhp_malloc(pub_key_len);
  if( rsasig->pub_key == NULL ){
	RHP_BUG("");
    return -ENOMEM;
  }
  memcpy(rsasig->pub_key,pub_key,pub_key_len);
  rsasig->pub_key_len = pub_key_len;
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_RSASIG_SET_PUB_KEY,"xp",rsasig,pub_key_len,pub_key);
  return 0;
}

static int _rhp_crypto_openssl_rsasig_sign(rhp_crypto_rsasig* rsasig,u8* mesg_octets,int mesg_octets_len,
		u8** signed_octets,int* signed_octets_len)
{
  int err = -EINVAL;
  EVP_MD_CTX *md_ctx;
  md_ctx = EVP_MD_CTX_new();
  u8* next;
  u8* outb = NULL;
  unsigned int outb_len;
  EVP_PKEY* priv_key = NULL;

  if( rsasig->priv_key == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  next = rsasig->priv_key;
  priv_key = d2i_PrivateKey(EVP_PKEY_RSA,NULL,(const unsigned char**)&next,rsasig->priv_key_len);
  if( priv_key == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( EVP_SignInit_ex(md_ctx,EVP_sha1(),NULL) != 1 ){
    EVP_PKEY_free(priv_key);
    return -EINVAL;
  }

  outb_len = EVP_PKEY_size(priv_key);

  outb = (u8*)_rhp_malloc(outb_len);
  if( outb == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  if( EVP_SignUpdate(md_ctx,mesg_octets,mesg_octets_len) != 1 ){
	RHP_BUG("");
    goto error;
  }

  if( EVP_SignFinal(md_ctx,outb,&outb_len,priv_key) != 1 ){
	RHP_BUG("");
    goto error;
  }

  EVP_PKEY_free(priv_key);
  EVP_MD_CTX_free(md_ctx);

  *signed_octets = outb;
  *signed_octets_len = outb_len;

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_RSASIG_SIGN_OK,"xpp",rsasig,mesg_octets_len,mesg_octets,outb_len,outb);
  return 0;

error:
  if( outb ){
    _rhp_free(outb);
  }
  if( priv_key ){
    EVP_PKEY_free(priv_key);
  }
  EVP_MD_CTX_free(md_ctx);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_RSASIG_SIGN_ERR,"xpE",rsasig,mesg_octets_len,mesg_octets,err);
  return err;
}

static int _rhp_crypto_openssl_rsasig_verify(rhp_crypto_rsasig* rsasig,u8* signed_octets,int signed_octets_len,u8* sig,int sig_len)
{
  int err = -EINVAL;
  u8* next;
  EVP_MD_CTX *md_ctx;
  md_ctx = EVP_MD_CTX_new();
  EVP_PKEY* pub_key = NULL;

  if( rsasig->pub_key == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  next = rsasig->pub_key;
  pub_key = d2i_PublicKey(EVP_PKEY_RSA,NULL,(const unsigned char**)&next,rsasig->pub_key_len);
  if( pub_key == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( EVP_VerifyInit(md_ctx,EVP_sha1()) != 1 ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( EVP_VerifyUpdate(md_ctx,signed_octets,signed_octets_len) != 1 ){
    RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_RSASIG_VERIFY_NG1,"xpp",rsasig,signed_octets_len,signed_octets,sig_len,sig);
    goto error;
  }

  if( EVP_VerifyFinal(md_ctx,sig,sig_len,pub_key) != 1 ){
    RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_RSASIG_VERIFY_NG2,"xpp",rsasig,signed_octets_len,signed_octets,sig_len,sig);
    goto error;
  }

  EVP_PKEY_free(pub_key);
  EVP_MD_CTX_free(md_ctx);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_RSASIG_VERIFY_OK,"xpp",rsasig,signed_octets_len,signed_octets,sig_len,sig);
  return 0;

error:
  if( pub_key ){
    EVP_PKEY_free(pub_key);
  }
  EVP_MD_CTX_free(md_ctx);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_RSASIG_VERIFY_ERR,"xppE",rsasig,signed_octets_len,signed_octets,sig_len,sig,err);
  return err;
}

static int _rhp_crypto_openssl_rsasig_sign_ikev1(rhp_crypto_rsasig* rsasig,
		u8* mesg_octets,int mesg_octets_len,u8** signature,int* signature_len)
{
  int err = -EINVAL;
  EVP_MD_CTX *md_ctx;
  md_ctx = EVP_MD_CTX_new();
  u8* next;
  u8* outb = NULL;
  unsigned int outb_len, sig_len;
  EVP_PKEY* priv_key = NULL;

  if( rsasig->priv_key == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  next = rsasig->priv_key;
  priv_key = d2i_PrivateKey(EVP_PKEY_RSA,NULL,(const unsigned char**)&next,rsasig->priv_key_len);
  if( priv_key == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( EVP_SignInit(md_ctx,EVP_sha1()) != 1 ){
    EVP_PKEY_free(priv_key);
    return -EINVAL;
  }


  outb_len = RSA_size(EVP_PKEY_get0(priv_key));

  outb = (u8*)_rhp_malloc(outb_len);
  if( outb == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  sig_len = RSA_private_encrypt(mesg_octets_len,mesg_octets,
							outb,EVP_PKEY_get0(priv_key),RSA_PKCS1_PADDING);
	if( sig_len == 0 || sig_len != outb_len ){
		err = -EINVAL;
		RHP_BUG("");
	  goto error;
	}

  EVP_PKEY_free(priv_key);
  EVP_MD_CTX_free(md_ctx);

  *signature = outb;
  *signature_len = outb_len;

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_RSASIG_SIGN_IKEV1_OK,"xpp",rsasig,mesg_octets_len,mesg_octets,outb_len,outb);
  return 0;

error:
  if( outb ){
    _rhp_free(outb);
  }
  if( priv_key ){
    EVP_PKEY_free(priv_key);
  }
  EVP_MD_CTX_free(md_ctx);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_RSASIG_SIGN_IKEV1_ERR,"xpE",rsasig,mesg_octets_len,mesg_octets,err);
  return err;
}

static int _rhp_crypto_openssl_rsasig_verify_ikev1(rhp_crypto_rsasig* rsasig,
		u8* mesg_octets,int mesg_octets_len,u8* signature,int signature_len)
{
  int err = -EINVAL;
  u8* next;
  EVP_PKEY* pub_key = NULL;
  u8* outb = NULL;
  unsigned int outb_len, sig_len2;

  if( rsasig->pub_key == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  next = rsasig->pub_key;
  // EVP_PKEY *d2i_PublicKey(int type, EVP_PKEY **a, const unsigned char **pp, long length);
  // pub_key is EVP_PKEY*
  pub_key = d2i_PublicKey(EVP_PKEY_RSA,NULL,(const unsigned char**)&next,rsasig->pub_key_len);
  if( pub_key == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }


  outb_len = BN_num_bytes(EVP_PKEY_get0(pub_key));

  outb = (u8*)_rhp_malloc(outb_len);
  if( outb == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }


  sig_len2 = RSA_public_decrypt(signature_len,signature,outb,EVP_PKEY_get0(pub_key),RSA_PKCS1_PADDING);
	if( sig_len2 == 0 ) {
		err = -EINVAL;
		RHP_BUG("");
	  goto error;
	}

	if( sig_len2 != mesg_octets_len ||
			memcmp(mesg_octets,outb,mesg_octets_len) ){
	  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_RSASIG_VERIFY_IKEV1_SIG_NOT_MATCH,"xppd",rsasig,mesg_octets_len,mesg_octets,sig_len2,outb,outb_len);
		err = -EINVAL;
	  goto error;
	}


  EVP_PKEY_free(pub_key);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_RSASIG_VERIFY_IKEV1_OK,"xppd",rsasig,mesg_octets_len,mesg_octets,signature_len,signature,outb_len);
  return 0;

error:
	if( outb ){
		_rhp_free(outb);
	}
  if( pub_key ){
    EVP_PKEY_free(pub_key);
  }

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_RSASIG_VERIFY_IKEV1_ERR,"xppdE",rsasig,mesg_octets_len,mesg_octets,signature_len,signature,outb_len,err);
  return err;
}


// This MUST generate cryptographically strong random bytes.
int rhp_random_bytes(u8* buf,int buf_len)
{
  if( RAND_bytes(buf,buf_len) != 1 ){
    RHP_BUG("");
    return -1;
  }

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_RANDOM_BYTES,"p",buf_len,buf);
  return 0;
}


static int _rhp_md_bytes_md5(u8* buf,int buf_len,u8** md_buf,int* md_buf_len)
{
  *md_buf = (u8*)_rhp_malloc(MD5_DIGEST_LENGTH);
  if( *md_buf == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  MD5(buf,buf_len,*md_buf);

  *md_buf_len = MD5_DIGEST_LENGTH;

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_MD_BYTES_MD5,"pp",buf_len,buf,*md_buf_len,*md_buf);
  return 0;
}

static int _rhp_md_bytes_sha1(u8* buf,int buf_len,u8** md_buf,int* md_buf_len)
{
  *md_buf = (u8*)_rhp_malloc(SHA_DIGEST_LENGTH);
  if( *md_buf == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  SHA1(buf,buf_len,*md_buf);

  *md_buf_len = SHA_DIGEST_LENGTH;

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_MD_BYTES_SHA1,"pp",buf_len,buf,*md_buf_len,*md_buf);
  return 0;
}


int rhp_crypto_md(int alg,u8* buf,int buf_len,u8** md_buf,int* md_buf_len)
{
	switch( alg ){

	case RHP_CRYPTO_MD_MD5:

		return _rhp_md_bytes_md5(buf,buf_len,md_buf,md_buf_len);

	case RHP_CRYPTO_MD_SHA1:

		return _rhp_md_bytes_sha1(buf,buf_len,md_buf,md_buf_len);

	default:
    RHP_BUG("%d",alg);
    break;
	}

	return -EINVAL;
}


static int _rhp_hmac_bytes_md5(u8* buf,int buf_len,u8* key,int key_len,u8** md_buf,int* md_buf_len)
{
  *md_buf = (u8*)_rhp_malloc(MD5_DIGEST_LENGTH);
  if( *md_buf == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  HMAC(EVP_md5(),key,key_len,buf,buf_len,*md_buf,(unsigned int*)md_buf_len);

  return 0;
}

static int _rhp_hmac_bytes_sha1(u8* buf,int buf_len,u8* key,int key_len,u8** md_buf,int* md_buf_len)
{
  *md_buf = (u8*)_rhp_malloc(SHA_DIGEST_LENGTH);
  if( *md_buf == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  HMAC(EVP_sha1(),key,key_len,buf,buf_len,*md_buf,(unsigned int*)md_buf_len);

  return 0;
}

static int _rhp_hmac_bytes_sha2_256(u8* buf,int buf_len,u8* key,int key_len,u8** md_buf,int* md_buf_len)
{
  *md_buf = (u8*)_rhp_malloc(SHA256_DIGEST_LENGTH);
  if( *md_buf == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  HMAC(EVP_sha256(),key,key_len,buf,buf_len,*md_buf,(unsigned int*)md_buf_len);

  return 0;
}

static int _rhp_hmac_bytes_sha2_384(u8* buf,int buf_len,u8* key,int key_len,u8** md_buf,int* md_buf_len)
{
  *md_buf = (u8*)_rhp_malloc(SHA384_DIGEST_LENGTH);
  if( *md_buf == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  HMAC(EVP_sha384(),key,key_len,buf,buf_len,*md_buf,(unsigned int*)md_buf_len);

  return 0;
}

static int _rhp_hmac_bytes_sha2_512(u8* buf,int buf_len,u8* key,int key_len,u8** md_buf,int* md_buf_len)
{
  *md_buf = (u8*)_rhp_malloc(SHA512_DIGEST_LENGTH);
  if( *md_buf == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  HMAC(EVP_sha512(),key,key_len,buf,buf_len,*md_buf,(unsigned int*)md_buf_len);

  return 0;
}

int rhp_crypto_hmac(int alg,u8* buf,int buf_len,u8* key,int key_len,u8** md_buf,int* md_buf_len)
{
	switch( alg ){

	case RHP_CRYPTO_HMAC_MD5:

		return _rhp_hmac_bytes_md5(buf,buf_len,key,key_len,md_buf,md_buf_len);

	case RHP_CRYPTO_HMAC_SHA1:

		return _rhp_hmac_bytes_sha1(buf,buf_len,key,key_len,md_buf,md_buf_len);

	case RHP_CRYPTO_HMAC_SHA2_256:

		return _rhp_hmac_bytes_sha2_256(buf,buf_len,key,key_len,md_buf,md_buf_len);

	case RHP_CRYPTO_HMAC_SHA2_384:

		return _rhp_hmac_bytes_sha2_384(buf,buf_len,key,key_len,md_buf,md_buf_len);

	case RHP_CRYPTO_HMAC_SHA2_512:

		return _rhp_hmac_bytes_sha2_512(buf,buf_len,key,key_len,md_buf,md_buf_len);

	default:
    RHP_BUG("%d",alg);
    break;
	}

	return -EINVAL;
}


rhp_crypto_prf* rhp_crypto_prf_alloc(int alg)
{
  switch( alg ){

    case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA1:

      return _rhp_crypto_openssl_prf_hmac_sha1_alloc();

    case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_MD5:

      return _rhp_crypto_openssl_prf_hmac_md5_alloc();

    case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_256:

      return _rhp_crypto_openssl_prf_hmac_sha2_256_alloc();

    case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_384:

      return _rhp_crypto_openssl_prf_hmac_sha2_384_alloc();

    case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_512:

      return _rhp_crypto_openssl_prf_hmac_sha2_512_alloc();

    default:
      RHP_BUG("%d",alg);
      return NULL;
  }
}

void rhp_crypto_prf_free(rhp_crypto_prf* prf)
{

	if( prf == NULL ){
		return;
	}

  switch( prf->alg ){

    case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA1:

      _rhp_crypto_openssl_prf_hmac_sha1_free(prf);
      return;

    case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_MD5:

      _rhp_crypto_openssl_prf_hmac_md5_free(prf);
      return;

    case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_256:

    	_rhp_crypto_openssl_prf_hmac_sha2_256_free(prf);
      return;

    case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_384:

    	_rhp_crypto_openssl_prf_hmac_sha2_384_free(prf);
      return;

    case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_512:

    	_rhp_crypto_openssl_prf_hmac_sha2_512_free(prf);
      return;

    default:
      RHP_BUG("prf:0x%x , %d",prf,prf->alg);
      return;
  }
}

rhp_crypto_integ* rhp_crypto_integ_alloc(int alg)
{
  switch( alg ){

    case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA1_96:

      return _rhp_crypto_openssl_integ_hmac_sha1_96_alloc();

    case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_MD5_96:

      return _rhp_crypto_openssl_integ_hmac_md5_96_alloc();

    case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_256_128:

      return _rhp_crypto_openssl_integ_hmac_sha2_256_128_alloc();

    case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_384_192:

      return _rhp_crypto_openssl_integ_hmac_sha2_384_192_alloc();

    case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_512_256:

      return _rhp_crypto_openssl_integ_hmac_sha2_512_256_alloc();

    default:
      RHP_BUG("%d",alg);
      return NULL;
  }
}

void rhp_crypto_integ_free(rhp_crypto_integ* integ)
{
	if( integ == NULL ){
		return;
	}
  switch( integ->alg ){

    case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA1_96:

      _rhp_crypto_openssl_integ_hmac_sha1_96_free(integ);
      return;

    case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_MD5_96:

      _rhp_crypto_openssl_integ_hmac_md5_96_free(integ);
      return;

    case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_256_128:

      _rhp_crypto_openssl_integ_hmac_sha2_256_128_free(integ);
      return;

    case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_384_192:

      _rhp_crypto_openssl_integ_hmac_sha2_384_192_free(integ);
      return;

    case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_512_256:

      _rhp_crypto_openssl_integ_hmac_sha2_512_256_free(integ);
      return;

    default:
      RHP_BUG("integ:0x%x , %d",integ,integ->alg);
      return;
  }
}


rhp_crypto_encr* rhp_crypto_encr_alloc(int alg,int key_bits_len)
{
  switch( alg ){

    case RHP_PROTO_IKE_TRANSFORM_ID_ENCR_AES_CBC:

      return _rhp_crypto_openssl_encr_aes_cbc_alloc(key_bits_len);

    case RHP_PROTO_IKE_TRANSFORM_ID_ENCR_3DES:

      return _rhp_crypto_openssl_encr_3des_cbc_alloc();

    default:
      RHP_BUG("%d",alg);
      return NULL;
  }
}

void rhp_crypto_encr_free(rhp_crypto_encr* encr)
{
	if( encr == NULL ){
		return;
	}
  switch( encr->alg ){

    case RHP_PROTO_IKE_TRANSFORM_ID_ENCR_AES_CBC:

      _rhp_crypto_openssl_encr_aes_cbc_free(encr);
      return;

    case RHP_PROTO_IKE_TRANSFORM_ID_ENCR_3DES:

      _rhp_crypto_openssl_encr_3des_cbc_free(encr);
      return;

    default:
      RHP_BUG("encr:0x%x , %d",encr,encr->alg);
      return;
  }
}




int rhp_crypto_prf_key_len(int alg)
{
  switch( alg ){
    case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_MD5:
      return MD5_DIGEST_LENGTH;
    case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA1:
      return SHA_DIGEST_LENGTH;
    case RHP_PROTO_IKE_TRANSFORM_ID_PRF_AES128_CBC:
      return AES_BLOCK_SIZE;
    case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_256:
      return SHA256_DIGEST_LENGTH;
    case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_384:
      return SHA384_DIGEST_LENGTH;
    case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_512:
      return SHA512_DIGEST_LENGTH;
    default:
      RHP_BUG("%d",alg);
      return -EINVAL;
  }
}


int rhp_crypto_prf_plus(rhp_crypto_prf* prf,u8* k,int k_len,u8* s,int s_len,u8* outb_r,int outb_r_len)
{
  int err = 0;
  int prf_len = prf->get_output_len(prf);
  int output_buf_len;
  int n,i;
  u8 idx = 0x01;
  u8 *tmp = NULL,*tmp2 = NULL;
  u8 *pt0,*pt1,*op;
  int pt0_len;
  int padlen;

  if( outb_r_len < prf_len ){
    RHP_BUG("%d < %d",outb_r_len,prf_len);
    return -EINVAL;
  }

  padlen = (prf_len - (outb_r_len % prf_len));

  if( padlen != prf_len ){

    output_buf_len = outb_r_len + padlen;

    tmp2 = (u8*)_rhp_malloc(output_buf_len);

    if( tmp2 == NULL ){
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }

  }else{

    output_buf_len = outb_r_len;
  }

  n = output_buf_len / prf_len;

  if( n > 0xFF ){
    RHP_BUG("%d,%d,%d",outb_r_len,output_buf_len,prf_len);
    err = -EINVAL;
    goto error;
  }

  tmp = (u8*)_rhp_malloc(prf_len + s_len + sizeof(idx));
  if( tmp == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

  pt0 = &(tmp[prf_len]);
  pt1 = &(pt0[s_len]);

  pt0_len = s_len + sizeof(idx);

  if( tmp2 ){
    op = tmp2;
  }else{
    op = outb_r;
  }

  memcpy(pt0,s,s_len);

  err = prf->set_key(prf,k,k_len);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  for( i = 0; i < n ; i++ ){

    *pt1 = idx;

    if( (err = prf->compute(prf,pt0,pt0_len,op,prf_len)) ){
      goto error;
    }

    if( i == 0 ){
      pt0_len += prf_len;
      pt0 = tmp;
    }

    memcpy(pt0,op,prf_len);
    op += prf_len;

    idx++;
  }

  if( tmp2 ){
    memcpy(outb_r,tmp2,outb_r_len);
  }

  err = 0;

error:
  if( tmp ){
    _rhp_free(tmp);
  }
  if( tmp2 ){
    _rhp_free(tmp2);
  }

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_PRF_PLUS,"xpppd",prf,k_len,k,s_len,s,outb_r_len,outb_r,err);
  return err;
}

int rhp_base64_encode(u8* bin,int bin_len,unsigned char** res_text)
{
  int output_len = (((bin_len + 2) / 3) * 4) + 1;
  unsigned char* output = NULL;

  output = (unsigned char*)_rhp_malloc(output_len);
  if( output == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  output_len = EVP_EncodeBlock(output,bin,bin_len);

  if( output_len < 1 ){
    _rhp_free(output);
    RHP_BUG("%d",output_len);
    return -EINVAL;
  }

  output[output_len] = '\0';

  *res_text = output;

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_BASE64_ENCODE,"ps",bin_len,bin,*res_text);
  return 0;
}

int rhp_base64_decode(unsigned char* text,u8** res_bin,int* res_bin_len)
{
  int output_len = (((strlen((char *)text) + 3) / 4) * 3);
  u8* output = NULL;
  int padlen = 0;
  int i;
  int text_len = strlen((char*)text);

  for( i = text_len - 1;i >= 0;i-- ){
    if( text[i] == '=' ){
      padlen++;
    }else{
      break;
    }
  }

  if( (text_len - padlen) < 1 ){
	RHP_BUG("%d,%d",text_len,padlen);
    return -EINVAL;
  }

  output = (unsigned char*)_rhp_malloc(output_len);
  if( output == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  output_len = EVP_DecodeBlock(output,text,text_len);

  if( output_len < 1 ){
    _rhp_free(output);
    RHP_BUG("%d",output_len);
    return -EINVAL;
  }

  *res_bin = output;
  *res_bin_len = output_len - padlen;

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_BASE64_DECODE,"sp",text,*res_bin_len,*res_bin);
  return 0;
}


rhp_crypto_rsasig* rhp_crypto_rsasig_alloc()
{
  rhp_crypto_rsasig* rsasig = NULL;

  rsasig = (rhp_crypto_rsasig*)_rhp_malloc(sizeof(rhp_crypto_rsasig));
  if( rsasig == NULL ){
	RHP_BUG("");
    goto error;
  }
  memset(rsasig,0,sizeof(rhp_crypto_rsasig));

  rsasig->set_priv_key = _rhp_crypto_openssl_rsasig_set_priv_key;
  rsasig->set_pub_key = _rhp_crypto_openssl_rsasig_set_pub_key;
  rsasig->sign = _rhp_crypto_openssl_rsasig_sign;
  rsasig->verify = _rhp_crypto_openssl_rsasig_verify;
  rsasig->sign_ikev1 = _rhp_crypto_openssl_rsasig_sign_ikev1;
  rsasig->verify_ikev1 = _rhp_crypto_openssl_rsasig_verify_ikev1;

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_RSASIG_ALLOC,"x",rsasig);
  return rsasig;

error:
  if( rsasig ){
    _rhp_free(rsasig);
  }
  RHP_TRC(0,RHPTRCID_OPENSSL_RSASIG_ALLOC_ERR,"");
  return NULL;
}

void rhp_crypto_rsasig_free(rhp_crypto_rsasig* rsasig)
{
	if( rsasig == NULL ){
		return;
	}

  if( rsasig->pub_key ){
    _rhp_free(rsasig->pub_key);
  }
  if( rsasig->priv_key ){
    _rhp_free_zero(rsasig->priv_key,rsasig->priv_key_len);
  }
  _rhp_free_zero(rsasig,sizeof(rhp_crypto_rsasig));
  RHP_TRC(0,RHPTRCID_OPENSSL_RSASIG_FREE,"x",rsasig);
}



static int _rhp_crypto_bn_set_bit(rhp_crypto_bn* bn,int idx)
{
	int err;

	err = BN_set_bit((BIGNUM*)bn->ctx,idx);
	if( !err ){
		RHP_BUG("");
		return -EINVAL;
	}

	return 0;
}

static int _rhp_crypto_bn_clear_bit(rhp_crypto_bn* bn,int idx)
{
	int err;

	err = BN_clear_bit((BIGNUM*)bn->ctx,idx);
	if( !err ){
		RHP_BUG("");
		return -EINVAL;
	}

	return 0;
}

static int _rhp_crypto_bn_bit_is_set(rhp_crypto_bn* bn, int idx)
{
	int flag;

	flag = BN_is_bit_set((BIGNUM*)bn->ctx,idx);

	return flag;
}

static int _rhp_crypto_bn_left_shift(rhp_crypto_bn* bn,int n)
{
	int err;
	BIGNUM* bn_ctx_r;

	bn_ctx_r = BN_new();
	if( bn_ctx_r == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	err = BN_lshift(bn_ctx_r,(BIGNUM*)bn->ctx,n);
	if( !err ){
		RHP_BUG("");
		BN_free(bn_ctx_r);
		return -EINVAL;
	}

	BN_free((BIGNUM*)bn->ctx);
	bn->ctx = bn_ctx_r;

	return 0;
}

static int _rhp_crypto_bn_right_shift(rhp_crypto_bn* bn,int n)
{
	int err;
	BIGNUM* bn_ctx_r;

	bn_ctx_r = BN_new();
	if( bn_ctx_r == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	err = BN_rshift(bn_ctx_r,(BIGNUM*)bn->ctx,n);
	if( !err ){
		RHP_BUG("");
		BN_free(bn_ctx_r);
		return -EINVAL;
	}

	BN_free((BIGNUM*)bn->ctx);
	bn->ctx = bn_ctx_r;

	return 0;
}

static int _rhp_crypto_bn_get_bits_len(rhp_crypto_bn* bn)
{
	return bn->bits_len;
}

rhp_crypto_bn* rhp_crypto_bn_alloc(int bits_len)
{
	rhp_crypto_bn* bn;
	BIGNUM* bn_ctx;

	if( bits_len < 1 ){
		RHP_BUG("");
		return NULL;
	}

	bn = (rhp_crypto_bn*)_rhp_malloc(sizeof(rhp_crypto_bn));
	if( bn == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(bn,0,sizeof(rhp_crypto_bn));

	bn_ctx = BN_new();
	if( bn_ctx == NULL ){
		RHP_BUG("");
		_rhp_free(bn);
		return NULL;
	}

	bn->bits_len = bits_len;
	bn->ctx = bn_ctx;

	bn->set_bit = _rhp_crypto_bn_set_bit;
	bn->clear_bit = _rhp_crypto_bn_clear_bit;
	bn->bit_is_set = _rhp_crypto_bn_bit_is_set;
	bn->left_shift = _rhp_crypto_bn_left_shift;
	bn->right_shift = _rhp_crypto_bn_right_shift;
	bn->get_bits_len = _rhp_crypto_bn_get_bits_len;

  RHP_TRC(0,RHPTRCID_OPENSSL_BN_ALLOC,"x",bn);
	return bn;
}

void rhp_crypto_bn_free(rhp_crypto_bn* bn)
{
	if( bn == NULL ){
		return;
	}

	BN_free((BIGNUM*)bn->ctx);
	_rhp_free(bn);

  RHP_TRC(0,RHPTRCID_OPENSSL_BN_FREE,"x",bn);
	return;
}




static int _rhp_crypto_hash_md5_get_output_len(rhp_crypto_hash* hash)
{
	return MD5_DIGEST_LENGTH;
}

static int _rhp_crypto_hash_md5_compute(rhp_crypto_hash* hash,u8* data,int data_len,u8* outb,int outb_len)
{

	if( outb_len < MD5_DIGEST_LENGTH ){
		RHP_BUG("%d",outb_len);
		return -EINVAL;
	}

  MD5(data,data_len,outb);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_HASH_MD5,"p",MD5_DIGEST_LENGTH,outb);
  return 0;
}

static rhp_crypto_hash* _rhp_crypto_hash_md5_alloc()
{
	rhp_crypto_hash* hash = (rhp_crypto_hash*)_rhp_malloc(sizeof(rhp_crypto_hash));

	if( hash == NULL ){
		RHP_BUG("");
		return NULL;
	}

	hash->get_output_len = _rhp_crypto_hash_md5_get_output_len;
	hash->compute = _rhp_crypto_hash_md5_compute;

	return hash;
}

static void _rhp_crypto_hash_md5_free(rhp_crypto_hash* hash)
{
	_rhp_free(hash);
	return;
}


static int _rhp_crypto_hash_sha1_get_output_len(rhp_crypto_hash* hash)
{
	return SHA_DIGEST_LENGTH;
}

static int _rhp_crypto_hash_sha1_compute(rhp_crypto_hash* hash,u8* data,int data_len,u8* outb,int outb_len)
{

	if( outb_len < SHA_DIGEST_LENGTH ){
		RHP_BUG("%d",outb_len);
		return -EINVAL;
	}

  SHA1(data,data_len,outb);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_HASH_SHA1,"xppd",hash,data_len,data,SHA_DIGEST_LENGTH,outb,outb_len);
  return 0;
}

static rhp_crypto_hash* _rhp_crypto_hash_sha1_alloc()
{
	rhp_crypto_hash* hash = (rhp_crypto_hash*)_rhp_malloc(sizeof(rhp_crypto_hash));

	if( hash == NULL ){
		RHP_BUG("");
		return NULL;
	}

	hash->get_output_len = _rhp_crypto_hash_sha1_get_output_len;
	hash->compute = _rhp_crypto_hash_sha1_compute;

	return hash;
}

static void _rhp_crypto_hash_sha1_free(rhp_crypto_hash* hash)
{
	_rhp_free(hash);
	return;
}


static int _rhp_crypto_hash_sha2_256_get_output_len(rhp_crypto_hash* hash)
{
	return SHA256_DIGEST_LENGTH;
}

static int _rhp_crypto_hash_sha2_256_compute(rhp_crypto_hash* hash,u8* data,int data_len,u8* outb,int outb_len)
{

	if( outb_len < SHA256_DIGEST_LENGTH ){
		RHP_BUG("%d",outb_len);
		return -EINVAL;
	}

  SHA256(data,data_len,outb);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_HASH_SHA2_256,"p",SHA256_DIGEST_LENGTH,outb);
  return 0;
}

static rhp_crypto_hash* _rhp_crypto_hash_sha2_256_alloc()
{
	rhp_crypto_hash* hash = (rhp_crypto_hash*)_rhp_malloc(sizeof(rhp_crypto_hash));

	if( hash == NULL ){
		RHP_BUG("");
		return NULL;
	}

	hash->get_output_len = _rhp_crypto_hash_sha2_256_get_output_len;
	hash->compute = _rhp_crypto_hash_sha2_256_compute;

	return hash;
}

static void _rhp_crypto_hash_sha2_256_free(rhp_crypto_hash* hash)
{
	_rhp_free(hash);
	return;
}


static int _rhp_crypto_hash_sha2_384_get_output_len(rhp_crypto_hash* hash)
{
	return SHA384_DIGEST_LENGTH;
}

static int _rhp_crypto_hash_sha2_384_compute(rhp_crypto_hash* hash,u8* data,int data_len,u8* outb,int outb_len)
{

	if( outb_len < SHA384_DIGEST_LENGTH ){
		RHP_BUG("%d",outb_len);
		return -EINVAL;
	}

  SHA384(data,data_len,outb);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_HASH_SHA2_384,"p",SHA384_DIGEST_LENGTH,outb);
  return 0;
}

static rhp_crypto_hash* _rhp_crypto_hash_sha2_384_alloc()
{
	rhp_crypto_hash* hash = (rhp_crypto_hash*)_rhp_malloc(sizeof(rhp_crypto_hash));

	if( hash == NULL ){
		RHP_BUG("");
		return NULL;
	}

	hash->get_output_len = _rhp_crypto_hash_sha2_384_get_output_len;
	hash->compute = _rhp_crypto_hash_sha2_384_compute;

	return hash;
}

static void _rhp_crypto_hash_sha2_384_free(rhp_crypto_hash* hash)
{
	_rhp_free(hash);
	return;
}


static int _rhp_crypto_hash_sha2_512_get_output_len(rhp_crypto_hash* hash)
{
	return SHA512_DIGEST_LENGTH;
}

static int _rhp_crypto_hash_sha2_512_compute(rhp_crypto_hash* hash,u8* data,int data_len,u8* outb,int outb_len)
{

	if( outb_len < SHA512_DIGEST_LENGTH ){
		RHP_BUG("%d",outb_len);
		return -EINVAL;
	}

  SHA512(data,data_len,outb);

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_HASH_SHA2_512,"p",SHA512_DIGEST_LENGTH,outb);
  return 0;
}

static rhp_crypto_hash* _rhp_crypto_hash_sha2_512_alloc()
{
	rhp_crypto_hash* hash = (rhp_crypto_hash*)_rhp_malloc(sizeof(rhp_crypto_hash));

	if( hash == NULL ){
		RHP_BUG("");
		return NULL;
	}

	hash->get_output_len = _rhp_crypto_hash_sha2_512_get_output_len;
	hash->compute = _rhp_crypto_hash_sha2_512_compute;

	return hash;
}

static void _rhp_crypto_hash_sha2_512_free(rhp_crypto_hash* hash)
{
	_rhp_free(hash);
	return;
}


rhp_crypto_hash* rhp_crypto_hash_alloc(int alg)
{
	rhp_crypto_hash* hash;

	switch( alg ){
	case RHP_PROTO_IKEV1_P1_ATTR_HASH_MD5:
		hash = _rhp_crypto_hash_md5_alloc();
		break;
	case RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA1:
		hash = _rhp_crypto_hash_sha1_alloc();
		break;
	case RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA2_256:
		hash = _rhp_crypto_hash_sha2_256_alloc();
		break;
	case RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA2_384:
		hash = _rhp_crypto_hash_sha2_384_alloc();
		break;
	case RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA2_512:
		hash = _rhp_crypto_hash_sha2_512_alloc();
		break;
	default:
    RHP_BUG("%d",alg);
    return NULL;
	}

	if( hash ){
		hash->alg = alg;
	}

	return hash;
}

void rhp_crypto_hash_free(rhp_crypto_hash* hash)
{
	switch( hash->alg ){
	case RHP_PROTO_IKEV1_P1_ATTR_HASH_MD5:
		return _rhp_crypto_hash_md5_free(hash);
	case RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA1:
		return _rhp_crypto_hash_sha1_free(hash);
	case RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA2_256:
		return _rhp_crypto_hash_sha2_256_free(hash);
	case RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA2_384:
		return _rhp_crypto_hash_sha2_384_free(hash);
	case RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA2_512:
		return _rhp_crypto_hash_sha2_512_free(hash);
	default:
    RHP_BUG("%d",hash->alg);
    return;
	}
}


static rhp_mutex_t* _rhp_openssl_g_locks = NULL;

struct CRYPTO_dynlock_value {
	u8 tag[4]; // "#SMX"
	rhp_mutex_t lock;
};

unsigned long _rhp_openssl_threads_set_id_cb(void)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_THREADS_SET_ID_CB,"");
	return gettid();
}

void _rhp_openssl_threads_set_locking_cb(int mode,int type,const char *file,int line)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_THREADS_SET_LOCKING_CB,"LBsd","OPENSSL_LOCK",4,&mode,file,line);

	if( mode & CRYPTO_LOCK ){
		RHP_LOCK(&(_rhp_openssl_g_locks[type]));
	}else{
		RHP_UNLOCK(&(_rhp_openssl_g_locks[type]));
	}
	return;
}

struct CRYPTO_dynlock_value* _rhp_openssl_threads_dyn_create_cb(const char *file,int line)
{
	struct CRYPTO_dynlock_value* dynlock = (struct CRYPTO_dynlock_value*)_rhp_malloc(sizeof(struct CRYPTO_dynlock_value));

	if( dynlock == NULL ){
		RHP_BUG("");
		return NULL;
	}

	dynlock->tag[0] = '#';
	dynlock->tag[1] = 'S';
	dynlock->tag[2] = 'M';
	dynlock->tag[3] = 'X';

	_rhp_mutex_init("SSD",&(dynlock->lock));

  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_THREADS_DYN_CREATE_CB,"xsd",dynlock,dynlock,file,line);

	return dynlock;
}

void _rhp_openssl_threads_dyn_lock_cb(int mode,struct CRYPTO_dynlock_value* dynlock,const char *file,int line)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_THREADS_DYN_LOCK_CB,"LBxsd","OPENSSL_LOCK",4,&mode,dynlock,file,line);

	if( mode & CRYPTO_LOCK ){
		RHP_LOCK(&(dynlock->lock));
	}else{
		RHP_UNLOCK(&(dynlock->lock));
	}
	return;
}

void _rhp_openssl_threads_dyn_destroy_cb(struct CRYPTO_dynlock_value* dynlock,const char *file,int line)
{
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_THREADS_SET_ID_CB,"xsd",dynlock,file,line);

	_rhp_mutex_destroy(&(dynlock->lock));
	_rhp_free(dynlock);
	return;
}

static int _rhp_openssl_threads_init()
{
	int i;

	_rhp_openssl_g_locks = (rhp_mutex_t*)_rhp_malloc(sizeof(rhp_mutex_t)*CRYPTO_num_locks());
	if( _rhp_openssl_g_locks == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	for( i = 0; i < CRYPTO_num_locks();i++){
		_rhp_mutex_init("SSG",&(_rhp_openssl_g_locks[i]));
		RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_THREADS_INIT_MUTEX_INIT,"dx",i,&(_rhp_openssl_g_locks[i]));
	}

	// TODO : CRYPTO_THREADID_set_callback() is better for recent OpenSSL(0.9.9~).
	CRYPTO_set_id_callback(_rhp_openssl_threads_set_id_cb);
	CRYPTO_set_locking_callback(_rhp_openssl_threads_set_locking_cb);
	CRYPTO_set_dynlock_create_callback(_rhp_openssl_threads_dyn_create_cb);
	CRYPTO_set_dynlock_lock_callback(_rhp_openssl_threads_dyn_lock_cb);
	CRYPTO_set_dynlock_destroy_callback(_rhp_openssl_threads_dyn_destroy_cb);

	RHP_TRC(0,RHPTRCID_OPENSSL_THREADS_INIT,"xd",_rhp_openssl_g_locks,CRYPTO_num_locks());
	return 0;
}

static int _rhp_openssl_threads_cleanup()
{
	int i;

	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);
	CRYPTO_set_dynlock_create_callback(NULL);
	CRYPTO_set_dynlock_lock_callback(NULL);
	CRYPTO_set_dynlock_destroy_callback(NULL);

	for( i = 0; i < CRYPTO_num_locks();i++){
		_rhp_mutex_destroy(&(_rhp_openssl_g_locks[i]));
		RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_THREADS_CLEANUP_MUTEX_DESTROY,"dx",i,&(_rhp_openssl_g_locks[i]));
	}

	_rhp_free(_rhp_openssl_g_locks);

	RHP_TRC(0,RHPTRCID_OPENSSL_THREADS_CLEANUP,"");
	return 0;
}

int rhp_crypto_init()
{
	int err = -EINVAL;

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	err = _rhp_openssl_threads_init();
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	RHP_TRC(0,RHPTRCID_OPENSSL_CRYPTO_INIT,"");
	return 0;

error:
	return err;
}

void rhp_crypto_cleanup()
{
	_rhp_openssl_threads_cleanup();
  RHP_TRC_FREQ(0,RHPTRCID_OPENSSL_CRYPTO_CLEANUP,"");
}

#endif /* RHP_OPENSSL */
