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

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/capability.h>
#include <unistd.h>
#include <sys/resource.h>
#include <fcntl.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/pem2.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
//#include <openssl/store.h>


#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_crypto.h"
#include "rhp_protocol.h"
#include "rhp_cert.h"
#include "rhp_wthreads.h"
#include "rhp_process.h"

extern int rhp_gcfg_ikesa_crl_check_all;


/*
  Files :

  The following PEM files are created for each VPN realm.

  1. <cert_store_path>/my_cert_<realm_id>.pem :
    - PEM format/X.509v3
    - This file may include an end entity certificate and some intermediate CA certificates(if any).
      These CA certificates may be sent with the end entity certificate and peer will treate these
      as 'untrusted' ones in the chain.

    [my_cert_<realm_id>.pem]

      -----BEGIN CERTIFICATE-----
      MIICmTCCAgKgAwIBAgIBAzANBgkqhkiG9w0BAQUFADBTMQswCQYDVQQGEwJKUDER
      ... (end entity certificate : First) ...
      YXXXXXOdZM/MgpD3Jrpe9dTmQdnFN7X8jeW0qZyu2TQa71LuxmF2voE3Fmf7n23I
      -----END CERTIFICATE-----
      -----BEGIN CERTIFICATE-----
      BBBBBTCCAgKgAwIBAgIBAzANBgkqhkiG9w0BAQUFADBTMQswCQYDVQQGEwJKUDER
      ... (intermediate CA certificate : Second) ...
      YDDDDDDDDD/MgpD3Jrpe9dTmQdnFN7X8jeW0qZyu2TQa71LuxmF2voE3Fmf7n23I
      -----END CERTIFICATE-----
      -----BEGIN CERTIFICATE-----
      CCCCCCCAgKgAwIBAgIBAzANBgkqhkiG9w0BAQUFADBTMQswCQYDVQQGEwJKUDER
      ... (intermediate CA certificate : Last) ...
      KKKKKKKKM/MgpD3Jrpe9dTmQdnFN7X8jeW0qZyu2TQa71LuxmF2voE3Fmf7n23I
      -----END CERTIFICATE-----
      (EOF)

  2. <cert_store_path>/my_priv_key_<realm_id>.pem :
    - PEM format/PKCS#1
    - This file includes a public key and a private key for RSA signature.

    [my_priv_key_<realm_id>.pem]

      -----BEGIN RSA PRIVATE KEY-----
      Proc-Type: 4,ENCRYPTED
      DEK-Info: DES-EDE3-CBC,54AB06F83A1598E4

      eV1NUqxaykStV+EQyKIe/2S/uEmmnKIlqVvet78X8bhwTMulUevL5/XhBxbnv4Q7
      ...
      LnGRy3Ds4giYFH7G16hkJzyVAQlay15JrVfAupjQUXkFjO0eO+bGug==
      -----END RSA PRIVATE KEY-----
      (EOF)

  3. <cert_store_path>/ca_certs_<realm_id>.pem :
    - PEM format/X.509v3
    - This file may include a root CA certificate and some intermediate CA certificates(if any).
      Peer should keep the same root CA certificate too. And certificates for intermediate CAs
      are treated as 'trusted' ones in the chain.

    [ca_certs_<realm_id>.pem]

      -----BEGIN CERTIFICATE-----
      BBBBBTCCAgKgAwIBAgIBAzANBgkqhkiG9w0BAQUFADBTMQswCQYDVQQGEwJKUDER
      ... (intermediate CA certificate : First) ...
      YDDDDDDDDD/MgpD3Jrpe9dTmQdnFN7X8jeW0qZyu2TQa71LuxmF2voE3Fmf7n23I
      -----END CERTIFICATE-----
      -----BEGIN CERTIFICATE-----
      CCCCCCCAgKgAwIBAgIBAzANBgkqhkiG9w0BAQUFADBTMQswCQYDVQQGEwJKUDER
      ... (intermediate CA certificate : Second) ...
      KKKKKKKKM/MgpD3Jrpe9dTmQdnFN7X8jeW0qZyu2TQa71LuxmF2voE3Fmf7n23I
      -----END CERTIFICATE-----
      -----BEGIN CERTIFICATE-----
      MIIClzCCAgCgAwIBAgIBADANBgkqhkiG9w0BAQUFADBTMQswCQYDVQQGEwJKUDER
      ... (root CA certificate : Last) ...
      5ft0HnPTHKFhzc3VQsVvLxsBXwtSuRwhShPMb2J281WJ375WYuNrNQIN5w==
      -----END CERTIFICATE-----
      (EOF)


  4. <cert_store_path>/crls_<realm_id>.pem :
    - PEM format/X.509v3 CRL
    - This file may include multiple CRLs.

    [crls_<realm_id>.pem]

      -----BEGIN X509 CRL-----
      MIICATCB6jANBgkqhkiG9w0BAQUFADCBkDELMAkGA1UEBhMCSlAxETAPBgNVBAgT
       ...
      5xQgwjlfJu/a3dLv9FOVB4gWwv4k3igR4f08UqWa/16Y2cqURA==
      -----END X509 CRL-----
      -----BEGIN X509 CRL-----
      NJJCATCB6jANBgkqhkiG9w0BAQUFADCBkDELMAkGA1UEBhMCSlAxETAPBgNVBAgT
       ...
      4dAswjlfJu/a3dLv9FOVB4gWwv4k3igR4f08UqWa/16Y2cqURA==
      -----END X509 CRL-----
      (EOF)


*/

static rhp_mutex_t _rhp_cert_store_g_lock;
static rhp_cert_store* _rhp_cert_store_list = NULL;


struct _rhp_cert_store_openssl_ctx {

#define RHP_CERT_STORE_OPENSSL_MAX_PATH   256
  char my_cert_file[RHP_CERT_STORE_OPENSSL_MAX_PATH];
  char private_key_file[RHP_CERT_STORE_OPENSSL_MAX_PATH];
  char ca_certs_file[RHP_CERT_STORE_OPENSSL_MAX_PATH];
  char crls_file[RHP_CERT_STORE_OPENSSL_MAX_PATH];

  unsigned long auth_realm_id;

	//
	// Why do we need to use X509_STORE? Why isn't the 'trusted_ca_crts' enough?
	//  ANS) To use _rhp_cert_store_openssl_cert_verify_cb() for expired certs.
	//
  rhp_cert_store* cert_store;

  EVP_PKEY* pkey_ctx;
  X509_STORE* store_ctx;

  X509* my_crt;
  STACK_OF(X509)* untrust_ca_crts;

  X509* root_ca_crt; // Just a reference. Don't free it!
  STACK_OF(X509)* trusted_ca_crts;

  STACK_OF(X509_CRL)* crls_list;

  int ca_pubkey_digests_cache_len;
  u8* ca_pubkey_digests_cache;

  int ca_dns_cache_len;
  int ca_dns_cache_num;
  u8* ca_dns_cache; // Trusted CA's DNs (Array of rhp_cert_data(s)). Type is RHP_CERT_DATA_CA_DN.

  int my_crt_issuer_dn_cache_len;
  u8* my_crt_issuer_dn_cache;

  int untrust_ca_issuer_dn_cache_len;
  u8* untrust_ca_issuer_dn_cache;
};
typedef struct _rhp_cert_store_openssl_ctx  rhp_cert_store_openssl_ctx;


struct _rhp_cert_openssl_ctx {

  X509* cert_impl;

  rhp_cert_dn* cert_dn;

  char* altname;
  int altname_len;
  int altname_type;
};
typedef struct _rhp_cert_openssl_ctx  rhp_cert_openssl_ctx;

__thread int _rhp_cert_deny_expired_cert = 0; // TLS
__thread int _rhp_cert_expired_cert = 0;

#ifdef RHP_OPENSSL_TEST
void rhp_ikev2_id_clear(rhp_ikev2_id* id)
{
  if( id->string ){
    _rhp_free(id->string);
    id->string = NULL;
  }
  if( id->dn_der ){
    _rhp_free(id->dn_der);
    id->dn_der = NULL;
    id->dn_der_len = 0;
  }

  return;
}
#endif // RHP_OPENSSL_TEST


static char* _rhp_X509_NAME_oneline2(X509_NAME* dn)
{
	BIO* mb = BIO_new(BIO_s_mem());
	char* ret = NULL;
	int n;

	RHP_TRC(0,RHPTRCID_OPENSSL_CERT_X509_NAME_ONELINE2,"x",dn);

	if( X509_NAME_print_ex(mb,dn,0,XN_FLAG_ONELINE) < 0 ){
		RHP_TRC(0,RHPTRCID_OPENSSL_CERT_X509_NAME_ONELINE2_NO_DN,"x",dn);
		goto error;
	}

	n = BIO_pending(mb);
	if( n < 1 ){
		RHP_TRC(0,RHPTRCID_OPENSSL_CERT_X509_NAME_ONELINE2_NO_DN_2,"x",dn);
		goto error;
	}

	ret = (char*)_rhp_malloc(n + 1);
	if( ret == NULL ){
		RHP_BUG("");
		goto error;
	}

	BIO_read(mb,ret,n);
	ret[n] = '\0';

error:
	BIO_free(mb);

	RHP_TRC(0,RHPTRCID_OPENSSL_CERT_X509_NAME_ONELINE2_RTRN,"xxs",dn,ret,ret);
	return ret;
}

static char* _rhp_X509_NAME_oneline(X509* cert)
{
	return _rhp_X509_NAME_oneline2(X509_get_subject_name(cert));
}

static char* _rhp_X509_CRL_ISSUER_oneline(X509_CRL* crl)
{
	return _rhp_X509_NAME_oneline2(X509_CRL_get_issuer(crl));
}

static char* _rhp_X509_SERIALNO_text(X509* cert)
{
	BIO* mb = BIO_new(BIO_s_mem());
	char* ret = NULL;
	int n;

	RHP_TRC(0,RHPTRCID_OPENSSL_CERT_X509_SERIALNO_TEXT,"x",cert);

	if( i2a_ASN1_INTEGER(mb,X509_get_serialNumber(cert)) < 0 ){
		RHP_TRC(0,RHPTRCID_OPENSSL_CERT_X509_SERIALNO_TEXT_NO_DN,"x",cert);
		goto error;
	}

	n = BIO_pending(mb);
	if( n < 1 ){
		RHP_TRC(0,RHPTRCID_OPENSSL_CERT_X509_SERIALNO_TEXT_NO_DN_2,"x",cert);
		goto error;
	}

	ret = (char*)_rhp_malloc(n + 1);
	if( ret == NULL ){
		RHP_BUG("");
		goto error;
	}

	BIO_read(mb,ret,n);
	ret[n] = '\0';

error:
	BIO_free(mb);

	RHP_TRC(0,RHPTRCID_OPENSSL_CERT_X509_SERIALNO_TEXT_RTRN,"xxs",cert,ret,ret);
	return ret;
}

static int _rhp_X509_Info_text(X509* cert,char** dn_txt_r,char** srn_txt_r)
{
	char *dn_txt = NULL,*srn_txt = NULL;

  dn_txt = _rhp_X509_NAME_oneline(cert);
  if( dn_txt == NULL ){
  	return -EINVAL;
  }

  srn_txt = _rhp_X509_SERIALNO_text(cert);
  if( srn_txt == NULL ){
  	_rhp_free(dn_txt);
  	return -EINVAL;
  }

  *dn_txt_r = dn_txt;
  *srn_txt_r = srn_txt;

  return 0;
}

void _rhp_cert_printf_dn(X509* cert)
{
	char* dn_txt = _rhp_X509_NAME_oneline(cert);
	if( dn_txt ){
		printf("DN: %s\n",dn_txt);
		_rhp_free(dn_txt);
	}
}


static void _rhp_cert_store_put(rhp_cert_store* cert_store)
{
  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_PUT,"x",cert_store);

	RHP_LOCK(&_rhp_cert_store_g_lock);

	cert_store->next = _rhp_cert_store_list;
	_rhp_cert_store_list = cert_store;

	rhp_cert_store_hold(cert_store);

	RHP_UNLOCK(&_rhp_cert_store_g_lock);

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_PUT_RTRN,"x",cert_store);
	return;
}

static void _rhp_cert_store_delete(rhp_cert_store* cert_store)
{
	rhp_cert_store *tmp,*tmp1 = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_DELETE,"x",cert_store);

  RHP_LOCK(&_rhp_cert_store_g_lock);

	tmp = _rhp_cert_store_list;
	while( tmp ){

		if( tmp == cert_store ){

			if( tmp1 ){
				tmp1->next = tmp->next;
			}else{
				_rhp_cert_store_list = tmp->next;
			}

			tmp->next = NULL;
			rhp_cert_store_unhold(cert_store);

			break;
		}

		tmp1 = tmp;
		tmp = tmp->next;
	}

	RHP_UNLOCK(&_rhp_cert_store_g_lock);

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_DELETE_RTRN,"x",cert_store);
  return;
}


int rhp_cert_store_all_ca_pubkey_digests(u8** digests_r,int* digests_len_r,int max_digests_len)
{
	int err = -EINVAL;
	rhp_cert_store *cert_store;
	u8* digests_tmp = NULL;
	int digests_tmp_len = 0;
	int digest_len;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_ALL_CA_PUBKEY_DIGESTS,"xxd",digests_r,digests_len_r,max_digests_len);

	RHP_LOCK(&_rhp_cert_store_g_lock);

	cert_store = _rhp_cert_store_list;
	while( cert_store ){

		u8* digests;
		int digests_len;
		int i;

		err = cert_store->get_ca_public_key_digests(cert_store,&digests,&digests_len,&digest_len);
		if( err ){
			// cert_store may be NOT ready. Go next.
			goto next;
		}

		for( i = 0; i < digests_len/digest_len; i++ ){

			int rem = digests_tmp_len;
			u8* p = digests_tmp;
			int found = 0;

			while( rem > 0 ){

				if( !memcmp(digests + digest_len*i,p,digest_len) ){
					found = 1;
					break;
				}

				rem -= digest_len;
				p += digest_len;
			}

			if( !found ){

				u8* new_buf;

				if( max_digests_len &&
						digests_tmp_len + digest_len > max_digests_len ){
					err = 0;
					RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_ALL_CA_PUBKEY_DIGESTS_MAX_SIZE_REACHED,"ddd",digests_tmp_len,digest_len,max_digests_len);
					goto max_size_reached;
				}

				new_buf = (u8*)_rhp_malloc(digests_tmp_len + digest_len);
				if( new_buf == NULL ){
					RHP_BUG("");
					goto error;
				}

				if( digests_tmp ){

					memcpy(new_buf,digests_tmp,digests_tmp_len);
					memcpy(new_buf + digests_tmp_len,digests + digest_len*i,digest_len);

					_rhp_free(digests_tmp);

				}else{

					memcpy(new_buf,digests + digest_len*i,digest_len);
				}

				digests_tmp = new_buf;
				digests_tmp_len += digest_len;
			}
	}

		_rhp_free(digests);

next:
		cert_store = cert_store->next;
	}

max_size_reached:
	 RHP_UNLOCK(&_rhp_cert_store_g_lock);

	 if( digests_tmp == NULL ){
		 err = -ENOENT;
		 goto error_2;
	 }

	 *digests_r = digests_tmp;
	 *digests_len_r = digests_tmp_len;

	 RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_ALL_CA_PUBKEY_DIGESTS_RTRN,"xp",digests_r,*digests_len_r,*digests_r);
	 return 0;

error:
	RHP_UNLOCK(&_rhp_cert_store_g_lock);
error_2:

	if( digests_tmp ){
		_rhp_free(digests_tmp);
	}

	RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_ALL_CA_PUBKEY_DIGESTS_ERR,"xE",digests_r,err);
	return err;
}


int rhp_cert_store_all_ca_dns_der(u8** dns_r,int* dns_len_r,int* dns_num_r,int max_dns_len)
{
	int err = -EINVAL;
	rhp_cert_store *cert_store;
	u8* dns_tmp = NULL;
	int dns_tmp_len = 0, dns_tmp_len2 = 0;
	int dns_tmp_num = 0;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_ALL_CA_DNS_DER,"xxxd",dns_r,dns_len_r,dns_num_r,max_dns_len);

	RHP_LOCK(&_rhp_cert_store_g_lock);

	cert_store = _rhp_cert_store_list;
	while( cert_store ){

		u8* dns;
		int dns_len;
		int dns_num;
		int i;
		rhp_cert_data* dn_header;

		err = cert_store->get_ca_dn_ders(cert_store,&dns,&dns_len,&dns_num);
		if( err ){
			// cert_store may be NOT ready. Go next.
			goto next;
		}

		dn_header = (rhp_cert_data*)dns;
		for( i = 0; i < dns_num; i++ ){

			int found = 0;
			int rem = dns_tmp_len;
			rhp_cert_data* dn_header_tmp = (rhp_cert_data*)dns_tmp;

			while( rem > 0 ){

				if( dn_header->len == dn_header_tmp->len &&
						!memcmp((dn_header + 1),(dn_header_tmp + 1),dn_header->len) ){
					found = 1;
					break;
				}

				rem -= (int)sizeof(rhp_cert_data) + dn_header_tmp->len;
				dn_header_tmp = (rhp_cert_data*)(((u8*)(dn_header_tmp + 1)) + dn_header_tmp->len);
			}

			if( !found ){

				u8* new_buf;

				if( max_dns_len &&
						dns_tmp_len2 + dn_header->len > max_dns_len ){
					err = 0;
					RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_ALL_CA_DNS_DER_MAX_SIZE_REACHED,"ddd",dns_tmp_len2,dn_header->len,max_dns_len);
					goto max_size_reached;
				}

				new_buf = (u8*)_rhp_malloc(dns_tmp_len + (int)sizeof(rhp_cert_data) + dn_header->len);
				if( new_buf == NULL ){
					RHP_BUG("");
					goto error;
				}

				if( dns_tmp ){

					memcpy(new_buf,dns_tmp,dns_tmp_len);
					memcpy(new_buf + dns_tmp_len,dn_header,(int)sizeof(rhp_cert_data) + dn_header->len);

					_rhp_free(dns_tmp);

				}else{

					memcpy(new_buf,dn_header,(int)sizeof(rhp_cert_data) + dn_header->len);
				}

				dns_tmp = new_buf;
				dns_tmp_len += (int)sizeof(rhp_cert_data) + dn_header->len;
				dns_tmp_len2 += dn_header->len;
				dns_tmp_num++;
			}

			dn_header = (rhp_cert_data*)(((u8*)(dn_header + 1)) + dn_header->len);
		}

		_rhp_free(dns);

next:
		cert_store = cert_store->next;
	}

max_size_reached:
	RHP_UNLOCK(&_rhp_cert_store_g_lock);

	if( dns_tmp == NULL ){
		err = -ENOENT;
		goto error_2;
	}

	*dns_r = dns_tmp;
	*dns_len_r = dns_tmp_len;
	*dns_num_r = dns_tmp_num;


	RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_ALL_CA_DNS_DER_RTRN,"xpd",dns_r,*dns_len_r,*dns_r,*dns_num_r);
	return 0;

error:
	RHP_UNLOCK(&_rhp_cert_store_g_lock);
error_2:

	if( dns_tmp ){
		_rhp_free(dns_tmp);
	}

	RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_ALL_CA_DNS_DER_ERR,"xE",dns_r,err);
	return err;
}


static int _rhp_cert_store_verify_cert(rhp_cert_store_openssl_ctx* cert_store_ctx,
		X509_STORE* store_ctx,X509* verified_cert,STACK_OF(X509)* verified_untrust_ca_crts,
		int deny_expired_cert)
{
  int err = -EINVAL;
  X509_STORE_CTX* store_verify_ctx = NULL;
	X509_VERIFY_PARAM* v_param = NULL;
  int old_deny_expired = _rhp_cert_deny_expired_cert;
	char *dn_log_txt = NULL,*srn_log_txt = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_VERIFY_CERT,"xxxxd",cert_store_ctx,store_ctx,verified_cert,verified_untrust_ca_crts,deny_expired_cert);

  _rhp_cert_deny_expired_cert = deny_expired_cert;
  _rhp_cert_expired_cert = 0;

	_rhp_X509_Info_text(verified_cert,&dn_log_txt,&srn_log_txt);


  store_verify_ctx = X509_STORE_CTX_new();

  if( store_verify_ctx == NULL){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }

  if( sk_X509_num(verified_untrust_ca_crts) < 1 ){
  	verified_untrust_ca_crts = NULL;
  }

	// store_ctx, verified_cert and verified_untrust_ca_crts are just references
  // for 'store_verify_ctx'. X509_STORE_CTX_free() doesn't free them.
    if( !X509_STORE_CTX_init(store_verify_ctx,store_ctx,verified_cert,verified_untrust_ca_crts) ){
  	RHP_BUG("");
  	goto error;
  }


	if( cert_store_ctx->crls_list && sk_X509_CRL_num(cert_store_ctx->crls_list) ){

  	unsigned long vrfy_flag
  	= (rhp_gcfg_ikesa_crl_check_all ? X509_V_FLAG_CRL_CHECK_ALL : X509_V_FLAG_CRL_CHECK);

  	if( verified_untrust_ca_crts == NULL ){
  		vrfy_flag = X509_V_FLAG_CRL_CHECK;
  	}

  	vrfy_flag |= X509_VERIFY_PARAM_get_flags(X509_STORE_get0_param(store_ctx));


  	RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_CERT_VERIFY_CHECK_CRL,"uss",cert_store_ctx->auth_realm_id,dn_log_txt,srn_log_txt);
		RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_VERIFY_CERT_VERIFY_CRL_ALSO,"xxxssu",store_verify_ctx,cert_store_ctx->crls_list,v_param,dn_log_txt,srn_log_txt,vrfy_flag);


  	v_param = X509_VERIFY_PARAM_new();
		if( v_param == NULL ){
			RHP_BUG("");
			err = -EINVAL;
	  	goto error;
		}

		X509_VERIFY_PARAM_inherit(v_param,X509_STORE_CTX_get0_param(store_verify_ctx));

		if( !X509_VERIFY_PARAM_set_flags(v_param, vrfy_flag) ){
			RHP_BUG("");
			err = -EINVAL;
	  	goto error;
		}

	  // 'v_param' is linked(NOT duplicated!) to 'store_verify_ctx->param'.
		// It will be freed by X509_STORE_CTX_free().
		X509_STORE_CTX_set0_param(store_verify_ctx, v_param);

		// crls_list is just a reference for 'store_verify_ctx'. X509_STORE_CTX_free() doesn't free it.
		X509_STORE_CTX_set0_crls(store_verify_ctx,cert_store_ctx->crls_list);

	}else{

		RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_VERIFY_CERT_VERIFY_NO_CRL,"x",store_verify_ctx);
	}


  if( X509_verify_cert(store_verify_ctx) <= 0 ){

		char *err_dn_txt = NULL,*err_srn_txt = NULL;
  	int v_err = X509_STORE_CTX_get_error(store_verify_ctx);
  	int n_dpth =  X509_STORE_CTX_get_error_depth(store_verify_ctx);
  	X509* err_cert = X509_STORE_CTX_get_current_cert(store_verify_ctx);
  	const char* v_err_txt = X509_verify_cert_error_string(v_err);

  	if( err_cert ){
    	_rhp_X509_Info_text(verified_cert,&err_dn_txt,&err_srn_txt);
  	}

    if( _rhp_cert_expired_cert && deny_expired_cert ){

    	_rhp_cert_expired_cert = 0;

      RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_VERIFY_CERT_VERIFY_NG_EXPIRED_1,"xuss",store_verify_ctx,cert_store_ctx->auth_realm_id,dn_log_txt,srn_log_txt);

      RHP_LOG_E(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_CERT_EXPIRED,"uss",cert_store_ctx->auth_realm_id,dn_log_txt,srn_log_txt);
    }

  	RHP_LOG_E(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_CERT_VERIFY_ERR,"usLdss",cert_store_ctx->auth_realm_id,v_err_txt,"OPNSSL_CRT_ERR",v_err,n_dpth,err_dn_txt,err_srn_txt);

    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_VERIFY_CERT_VERIFY_NG,"xLddxsss",store_verify_ctx,"OPNSSL_CRT_ERR",v_err,n_dpth,err_cert,v_err_txt,err_dn_txt,err_srn_txt);

  	if( err_dn_txt ){
  		_rhp_free(err_dn_txt);
  	}
  	if( err_srn_txt ){
  		_rhp_free(err_srn_txt);
  	}

    err = RHP_STATUS_INVALID_CERT;
    goto error;
  }


  if( _rhp_cert_expired_cert ){

    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_VERIFY_CERT_VERIFY_NG_EXPIRED_2,"xuss",store_verify_ctx,cert_store_ctx->auth_realm_id,dn_log_txt,srn_log_txt);

  	_rhp_cert_expired_cert = 0;

    if( deny_expired_cert ){

    	RHP_LOG_E(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_CERT_EXPIRED,"uss",cert_store_ctx->auth_realm_id,dn_log_txt,srn_log_txt);

    	err = RHP_STATUS_CERT_EXPIRED;
    	goto error;

    }else{

    	RHP_LOG_W(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_CERT_EXPIRED_BUG_IGNORED,"uss",cert_store_ctx->auth_realm_id,dn_log_txt,srn_log_txt);
    }
  }


  // 'v_param' is linked store_verify_ctx->param. This is also freed here.
  X509_STORE_CTX_free(store_verify_ctx);

  _rhp_cert_deny_expired_cert = old_deny_expired;


	RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_CERT_VERIFY_OK,"uss",cert_store_ctx->auth_realm_id,dn_log_txt,srn_log_txt);

	if( dn_log_txt ){
		_rhp_free(dn_log_txt);
	}
	if( srn_log_txt ){
		_rhp_free(srn_log_txt);
	}

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_VERIFY_CERT_RTRN,"xx",store_ctx,verified_cert);
  return 0;

error:
  if( store_verify_ctx  ){
    // 'v_param' is linked store_verify_ctx->param. This is also freed here.
    X509_STORE_CTX_free(store_verify_ctx);
  }
  _rhp_cert_deny_expired_cert = old_deny_expired;

	if( dn_log_txt ){
		_rhp_free(dn_log_txt);
	}
	if( srn_log_txt ){
		_rhp_free(srn_log_txt);
	}

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_VERIFY_CERT_ERR,"xxE",store_ctx,verified_cert,err);
  return err;
}

static int _rhp_cert_store_openssl_load_certs_ders(u8* der_bin,int der_bin_len,int der_num,
    STACK_OF(X509)* certs_list,X509** first_cert,X509** last_cert)
{
	int err = -EINVAL;
  int i = 0;
  rhp_cert_data* cert_der;
  int rem;

  RHP_TRC(0,RHPTRCID_OPENSSL_LOAD_CERTS_DERS,"pdxxx",der_bin_len,der_bin,der_num,certs_list,first_cert,last_cert);

  if( der_bin_len <= (int)sizeof(rhp_cert_data) ){
    RHP_BUG("");
    goto error;
  }

  if( first_cert ){
    *first_cert = NULL;
  }

  if( last_cert ){
    *last_cert = NULL;
  }

  cert_der = (rhp_cert_data*)der_bin;
  rem = der_bin_len;

  for( i = 0; i < der_num; i++ ){

  	int cert_len = cert_der->len;
  	X509* cert;
  	u8* next = (u8*)(cert_der + 1);

  	cert =  d2i_X509(NULL,(const unsigned char**)&next,cert_len);
  	if( cert == NULL ){
   	  RHP_TRC(0,RHPTRCID_OPENSSL_LOAD_CERTS_DERS_PARSE_NG,"x",der_bin);
   	  err = RHP_STATUS_X509_CERT_PARSE_DER_ERR;
      goto error;
    }

    sk_X509_push(certs_list,cert);

    rem -= cert_len;
    if( rem < 0 ){
      RHP_BUG("");
      goto error;
    }

    if( first_cert && *first_cert == NULL  ){
      *first_cert = cert;
      RHP_TRC(0,RHPTRCID_OPENSSL_LOAD_CERTS_DERS_FIRST,"xx",der_bin,cert);
     }

    if( last_cert ){
      *last_cert = cert;
      RHP_TRC(0,RHPTRCID_OPENSSL_LOAD_CERTS_DERS_LAST,"xx",der_bin,cert);
    }

    RHP_TRC(0,RHPTRCID_OPENSSL_LOAD_CERTS_DERS_PARSED,"xx",der_bin,cert);

    {
    	char *dn_txt = NULL,*srn_txt = NULL;
    	_rhp_X509_Info_text(cert,&dn_txt,&srn_txt);
    	RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_LOADED_X509_CERT_DER,"dss",(i + 1),dn_txt,srn_txt);
    	if(dn_txt){_rhp_free(dn_txt);}
    	if(srn_txt){_rhp_free(srn_txt);}
    }

    cert_der = (rhp_cert_data*)((u8*)cert_der) + cert_len;
  }

  if( sk_X509_num(certs_list) == 0 ){
    RHP_TRC(0,RHPTRCID_OPENSSL_LOAD_CERTS_DERS_NO_CERT_LIST_ERR,"x",der_bin);
    err = -ENOENT;
    goto error;
  }

  RHP_TRC(0,RHPTRCID_OPENSSL_LOAD_CERTS_DERS_RTRN,"x",der_bin);
  return 0;

error:
  if( first_cert ){
    *first_cert = NULL;
  }
  if( last_cert ){
    *last_cert = NULL;
  }

  RHP_TRC(0,RHPTRCID_OPENSSL_LOAD_CERTS_DERS_ERR,"x",der_bin);
  return err;
}

static int _rhp_cert_store_openssl_load_certs_pem(BIO* bio_ctx,
		STACK_OF(X509)* certs_list,X509** first_cert,X509** last_cert,int dont_push_stk)
{
	int err = -EINVAL;
  STACK_OF(X509_INFO) *certs_info_list = NULL;
  int n,n2 = 0,i;


  RHP_TRC(0,RHPTRCID_OPENSSL_LOAD_CERTS_PEM,"xxxxd",bio_ctx,certs_list,first_cert,last_cert,dont_push_stk);

  if( first_cert ){
    *first_cert = NULL;
  }

  if( last_cert ){
    *last_cert = NULL;
  }

  certs_info_list = PEM_X509_INFO_read_bio(bio_ctx,NULL,NULL,NULL);
  if( certs_info_list == NULL ){
  	err = -EINVAL;
    RHP_TRC(0,RHPTRCID_OPENSSL_LOAD_CERTS_PEM_PEM_X509_INFO_READ_BIO_ERR,"x",bio_ctx);
    goto error;
  }

  i = 1;
  while( (n = sk_X509_INFO_num(certs_info_list)) ){

    X509_INFO* tmp_cert_info = sk_X509_INFO_shift(certs_info_list);

    if( tmp_cert_info->x509 != NULL ){

    	int flag = 1;

      if( first_cert && *first_cert == NULL ){

      	*first_cert = tmp_cert_info->x509;
        RHP_TRC(0,RHPTRCID_OPENSSL_LOAD_CERTS_PEM_FIRST,"xxx",bio_ctx,tmp_cert_info,tmp_cert_info->x509);

      }else if( last_cert && (n == 1) ){

      	*last_cert = tmp_cert_info->x509;
        RHP_TRC(0,RHPTRCID_OPENSSL_LOAD_CERTS_PEM_LAST,"xxx",bio_ctx,tmp_cert_info,tmp_cert_info->x509);

      }else{
        flag = 0;
      }

      if( !dont_push_stk || !flag ){

      	sk_X509_push(certs_list,tmp_cert_info->x509);
        RHP_TRC(0,RHPTRCID_OPENSSL_LOAD_CERTS_PEM_PUSHED_LIST,"xxx",bio_ctx,tmp_cert_info,tmp_cert_info->x509);
      }

      n2++;

      RHP_TRC(0,RHPTRCID_OPENSSL_LOAD_CERTS_PEM_PARSED,"xxxd",bio_ctx,tmp_cert_info,tmp_cert_info->x509,n2);

      {
      	char *dn_txt = NULL,*srn_txt = NULL;
      	_rhp_X509_Info_text(tmp_cert_info->x509,&dn_txt,&srn_txt);
      	RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_LOADED_X509_CERT_PEM,"dss",i++,dn_txt,srn_txt);
      	if(dn_txt){_rhp_free(dn_txt);}
      	if(srn_txt){_rhp_free(srn_txt);}
      }

      tmp_cert_info->x509 = NULL; // Maybe, deref the x509 pointer.

    }else{
      RHP_TRC(0,RHPTRCID_OPENSSL_LOAD_CERTS_PEM_PARSED_NULL_CERT,"xx",bio_ctx,tmp_cert_info);
    }

    X509_INFO_free(tmp_cert_info);
  }

  if( n2 == 0 ){
    RHP_TRC(0,RHPTRCID_OPENSSL_LOAD_CERTS_PEM_NO_CERTS_LIST,"x",bio_ctx);
    err = -ENOENT;
    goto error;
  }

  sk_X509_INFO_free(certs_info_list);

  RHP_TRC(0,RHPTRCID_OPENSSL_LOAD_CERTS_PEM_RTRN,"x",bio_ctx);
  return 0;

error:
  if( certs_info_list ){
    sk_X509_INFO_free(certs_info_list);
  }
  if( first_cert ){
    *first_cert = NULL;
  }
  if( last_cert ){
    *last_cert = NULL;
  }

  RHP_TRC(0,RHPTRCID_OPENSSL_LOAD_CERTS_PEM_ERR,"xE",bio_ctx,err);
  return err;
}


static int _rhp_cert_store_openssl_load_crls_pem(BIO* bio_ctx,STACK_OF(X509_CRL)* crls_list)
{
	int err = -EINVAL;
  STACK_OF(X509_INFO) *crls_info_list = NULL;
  int i,crls_num = 0;

  RHP_TRC(0,RHPTRCID_OPENSSL_LOAD_CRLS_PEM,"xx",bio_ctx,crls_list);

  crls_info_list = PEM_X509_INFO_read_bio(bio_ctx,NULL,NULL,NULL);
  if( crls_info_list == NULL ){
    RHP_TRC(0,RHPTRCID_OPENSSL_LOAD_CRLS_PEM_PEM_X509_INFO_READ_BIO_ERR,"x",bio_ctx);
    goto error;
  }

  crls_num = sk_X509_INFO_num(crls_info_list);

  for( i = 0; i < crls_num; i++ ){

  	X509_INFO *tmp_crl_info = sk_X509_INFO_value(crls_info_list, i);

  	if(tmp_crl_info->crl){

  		if (!sk_X509_CRL_push(crls_list, tmp_crl_info->crl)){
  	    RHP_TRC(0,RHPTRCID_OPENSSL_LOAD_CRLS_PEM_PUSH_CRL_ERR,"x",bio_ctx);
  	    goto error;
  		}

      {
      	char *issr_txt = _rhp_X509_CRL_ISSUER_oneline(tmp_crl_info->crl);
      	RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_LOADED_X509_CRL_PEM,"ds",(i + 1),issr_txt);
      	if(issr_txt){_rhp_free(issr_txt);}
      }

  		tmp_crl_info->crl = NULL;// Maybe, deref the crl's pointer.
  	}
  }

  if( sk_X509_CRL_num(crls_list) == 0 ){
    RHP_TRC(0,RHPTRCID_OPENSSL_LOAD_CRLS_PEM_NO_CERTS_LIST,"x",bio_ctx);
    err = -ENOENT;
    goto error;
  }

  sk_X509_INFO_free(crls_info_list);

  RHP_TRC(0,RHPTRCID_OPENSSL_LOAD_CRLS_PEM_RTRN,"xd",bio_ctx,crls_num);
  return 0;

error:
  if( crls_info_list ){
    sk_X509_INFO_free(crls_info_list);
  }

  RHP_TRC(0,RHPTRCID_OPENSSL_LOAD_CRLS_PEM_ERR,"xE",bio_ctx,err);
  return err;
}

static int _rhp_cert_store_openssl_get_ca_public_key_digests(rhp_cert_store* cert_store,u8** digests,
    int* digests_len,int* digest_len)
{
  int err = -EINVAL;
  rhp_cert_store_openssl_ctx* cert_store_ctx = NULL;
  X509* cert = NULL;
  int i;
  u8* outb = NULL;
  int n = 0;
  int tot_len = 0;

  RHP_TRC(0,RHPTRCID_OPENSSL_GET_PUBLIC_KEY_DIGESTS,"xxx",cert_store,digests,digests_len,digest_len);

  RHP_LOCK(&(cert_store->lock));

  if( !_rhp_atomic_read(&(cert_store->is_active)) ){
    RHP_TRC(0,RHPTRCID_OPENSSL_GET_PUBLIC_KEY_DIGESTS_NOT_ACTIVE,"x",cert_store);
    goto error;
  }

  cert_store_ctx = (rhp_cert_store_openssl_ctx*)cert_store->ctx;

  if( cert_store_ctx == NULL ){
    RHP_BUG("");
    goto error;
  }

  if( cert_store_ctx->ca_pubkey_digests_cache ){

cache:
    outb = (u8*)_rhp_malloc(cert_store_ctx->ca_pubkey_digests_cache_len);
    if( outb == NULL ){
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }

    tot_len = cert_store_ctx->ca_pubkey_digests_cache_len;
    memcpy(outb,cert_store_ctx->ca_pubkey_digests_cache,tot_len);

    RHP_TRC(0,RHPTRCID_OPENSSL_GET_PUBLIC_KEY_DIGESTS_OUTB,"xp",cert_store,tot_len,outb);

  }else{

    n = sk_X509_num(cert_store_ctx->trusted_ca_crts);

    if( n > 0 ){

      RHP_TRC(0,RHPTRCID_OPENSSL_GET_PUBLIC_KEY_DIGESTS_CA_CERTS_NUM,"xd",cert_store,n);

    	cert_store_ctx->ca_pubkey_digests_cache = (u8*)_rhp_malloc(SHA_DIGEST_LENGTH*n);

			if( cert_store_ctx->ca_pubkey_digests_cache == NULL ){
				cert_store_ctx->ca_pubkey_digests_cache_len = 0;
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}

    }else{

      RHP_TRC(0,RHPTRCID_OPENSSL_GET_PUBLIC_KEY_DIGESTS_NO_CERTS,"xd",cert_store,n);

    	err = -ENOENT;
    	goto error;
    }

    //
    // [RFC5996 3.7.]
    //
    // The Certification Authority value is a concatenated list of SHA-1 hashes
    // of the public keys of trusted Certification Authorities (CAs).  Each
    // is encoded as the SHA-1 hash of the Subject Public Key Info element
    // (see section 4.1.2.7 of [PKIX]) from each Trust Anchor certificate.
    //
    for( i = 0; i < n; i++ ){

      u8* tmp_buf;
  	  X509_PUBKEY* cert_pub_key;
  	  unsigned char *bstr = NULL,*bstr_p;
  	  int bstr_len;

  	  cert = sk_X509_value(cert_store_ctx->trusted_ca_crts,i);

      cert_pub_key = X509_get_X509_PUBKEY(cert);
      if( cert_pub_key == NULL ){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
      }

      bstr_len = i2d_X509_PUBKEY(cert_pub_key,NULL);
      if( bstr_len < 1 ){
      	err = -EINVAL;
      	RHP_BUG("");
      	goto error;
      }

      bstr = (unsigned char*)_rhp_malloc(bstr_len);
      if( bstr == NULL ){
      	RHP_BUG("");
      	err = -ENOMEM;
      	goto error;
      }
      bstr_p = bstr;

      i2d_X509_PUBKEY(cert_pub_key,&bstr_p);

      tmp_buf = cert_store_ctx->ca_pubkey_digests_cache + ( i*SHA_DIGEST_LENGTH );

  		SHA1(bstr,bstr_len,tmp_buf);

      cert_store_ctx->ca_pubkey_digests_cache_len += SHA_DIGEST_LENGTH;

      RHP_TRC(0,RHPTRCID_OPENSSL_GET_PUBLIC_KEY_DIGESTS_EACH,"xxdxpp",cert_store,cert_store_ctx,i,cert_pub_key,SHA_DIGEST_LENGTH,tmp_buf,bstr_len,bstr);

      _rhp_free(bstr);
    }

    goto cache;
  }

  RHP_UNLOCK(&(cert_store->lock));

  *digest_len = SHA_DIGEST_LENGTH;
  *digests_len = tot_len;
  *digests = outb;

  RHP_TRC(0,RHPTRCID_OPENSSL_GET_PUBLIC_KEY_DIGESTS_RTRN,"xddp",cert_store,n,*digest_len,*digests_len,outb);
  return 0;

error:
	if( cert_store_ctx ){
		if( cert_store_ctx->ca_pubkey_digests_cache ){
			_rhp_free(cert_store_ctx->ca_pubkey_digests_cache);
		}
		cert_store_ctx->ca_pubkey_digests_cache = NULL;
		cert_store_ctx->ca_pubkey_digests_cache_len = 0;
	}

	RHP_UNLOCK(&(cert_store->lock));

	if( outb ){
    _rhp_free(outb);
  }

  RHP_TRC(0,RHPTRCID_OPENSSL_GET_PUBLIC_KEY_DIGESTS_ERR,"xdE",cert_store,n,err);
  return err;
}

//
// To get DNs of all trusted chained CAs (including sub (intermediate) CAs).
//
// dns_r: An array of rhp_cert_data(s). rhp_cert_data->type == RHP_CERT_DATA_CA_DN.
//
static int _rhp_cert_store_openssl_get_ca_dn_ders(rhp_cert_store* cert_store,u8** dns_r,
    int* dns_len_r,int* dns_num_r)
{
  int err = -EINVAL;
  rhp_cert_store_openssl_ctx* cert_store_ctx = NULL;
  X509* cert = NULL;
  int i;
  u8* outb = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_GET_CA_DNS_DER,"xxxx",cert_store,dns_r,dns_len_r,dns_num_r);

  RHP_LOCK(&(cert_store->lock));

  if( !_rhp_atomic_read(&(cert_store->is_active)) ){
  	err = -EINVAL;
    RHP_TRC(0,RHPTRCID_OPENSSL_GET_CA_DNS_DER_NOT_ACTIVE,"x",cert_store);
    goto error;
  }

  cert_store_ctx = (rhp_cert_store_openssl_ctx*)cert_store->ctx;
  if( cert_store_ctx == NULL ){
  	err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  if( cert_store_ctx->ca_dns_cache ){

cache:
    outb = (u8*)_rhp_malloc(cert_store_ctx->ca_dns_cache_len);
    if( outb == NULL ){
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }

    memcpy(outb,cert_store_ctx->ca_dns_cache,cert_store_ctx->ca_dns_cache_len);

    RHP_TRC(0,RHPTRCID_OPENSSL_GET_CA_DNS_DER_OUTB,"xp",cert_store,cert_store_ctx->ca_dns_cache_len,outb);

  }else{

  	int tmp_buf_len = 0;
  	u8* tmp_buf = NULL;
    int n = 0;

    if( cert_store_ctx->trusted_ca_crts == NULL ){
      RHP_TRC(0,RHPTRCID_OPENSSL_GET_CA_DNS_DER_NO_CERT_LOADED,"x",cert_store);
    	err = -ENOENT;
    	goto error;
    }

    n = sk_X509_num(cert_store_ctx->trusted_ca_crts);
    if( n < 1 ){
      RHP_TRC(0,RHPTRCID_OPENSSL_GET_CA_DNS_DER_NO_CERTS,"xd",cert_store,n);
    	err = -ENOENT;
    	goto error;
    }

    for( i = 0; i < n; i++ ){

	    X509_NAME* dn;
	    u8 *dn_der = NULL, *new_buf = NULL;
	    rhp_cert_data* new_dn_head;
	    int dn_der_len, new_buf_len = 0;

  	  cert = sk_X509_value(cert_store_ctx->trusted_ca_crts,i);

	    dn = X509_get_subject_name(cert); // dn: Just a reference. Don't free it.
	    if( dn == NULL ){
	      err = -ENOENT;
	      goto error;
	    }

	    dn_der_len = i2d_X509_NAME(dn,NULL);
	    if( dn_der_len < 0 ){
	    	err = -EINVAL;
	    	goto error;
	    }

	    dn_der = (u8*)_rhp_malloc(dn_der_len);
	    if( dn_der == NULL ){
	    	RHP_BUG("");
	    	err = -ENOMEM;
	    	goto error;
	    }

	    i2d_X509_NAME(dn,&dn_der);
	    dn_der = (dn_der - dn_der_len);


	    new_buf_len = tmp_buf_len + (int)sizeof(rhp_cert_data) + dn_der_len;
	    new_buf = (u8*)_rhp_malloc(new_buf_len);
	    if( new_buf == NULL ){
	    	RHP_BUG("");
		    _rhp_free(dn_der);
	    	err = -ENOMEM;
	    	goto error;
	    }

	    if( tmp_buf_len ){

	    	memcpy(new_buf,tmp_buf,tmp_buf_len);
		    _rhp_free(tmp_buf);

		    new_dn_head = (rhp_cert_data*)(new_buf + tmp_buf_len);

	    }else{

	    	new_dn_head = (rhp_cert_data*)new_buf;
	    }

	    new_dn_head->type = RHP_CERT_DATA_CA_DN;
	    new_dn_head->len = dn_der_len;
	    memcpy((new_dn_head + 1),dn_der,dn_der_len);

	    tmp_buf = new_buf;
	    tmp_buf_len = new_buf_len;

	    _rhp_free(dn_der);
    }

    cert_store_ctx->ca_dns_cache = tmp_buf;
    cert_store_ctx->ca_dns_cache_len = tmp_buf_len;
    cert_store_ctx->ca_dns_cache_num = n;

    goto cache;
  }

  RHP_UNLOCK(&(cert_store->lock));

  *dns_num_r = cert_store_ctx->ca_dns_cache_num;
  *dns_len_r = cert_store_ctx->ca_dns_cache_len;
  *dns_r = outb;

  RHP_TRC(0,RHPTRCID_OPENSSL_GET_CA_DNS_DER_RTRN,"xddp",cert_store,*dns_num_r,*dns_len_r,*dns_len_r,*dns_r);
  return 0;

error:
	if( cert_store_ctx ){
		if( cert_store_ctx->ca_dns_cache ){
			_rhp_free(cert_store_ctx->ca_dns_cache);
		}
		cert_store_ctx->ca_dns_cache = NULL;
		cert_store_ctx->ca_dns_cache_len = 0;
		cert_store_ctx->ca_dns_cache_num = 0;
	}

	RHP_UNLOCK(&(cert_store->lock));

	if( outb ){
    _rhp_free(outb);
  }

  RHP_TRC(0,RHPTRCID_OPENSSL_GET_CA_DNS_DER_ERR,"xE",cert_store,err);
  return err;
}

static int _rhp_cert_store_openssl_get_my_cert_issuer_dn_der(rhp_cert_store* cert_store,u8** dn_r,
    int* dn_len_r)
{
  int err = -EINVAL;
  rhp_cert_store_openssl_ctx* cert_store_ctx = NULL;
  u8* outb = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_GET_MY_CERT_ISSUER_DN_DER,"xxx",cert_store,dn_r,dn_len_r);

  RHP_LOCK(&(cert_store->lock));

  if( !_rhp_atomic_read(&(cert_store->is_active)) ){
  	err = -EINVAL;
    RHP_TRC(0,RHPTRCID_OPENSSL_GET_MY_CERT_ISSUER_DN_DER_NOT_ACTIVE,"x",cert_store);
    goto error;
  }

  cert_store_ctx = (rhp_cert_store_openssl_ctx*)cert_store->ctx;
  if( cert_store_ctx == NULL ){
  	err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  if( cert_store_ctx->my_crt_issuer_dn_cache ){

cache:
    outb = (u8*)_rhp_malloc(cert_store_ctx->my_crt_issuer_dn_cache_len);
    if( outb == NULL ){
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }

    memcpy(outb,cert_store_ctx->my_crt_issuer_dn_cache,cert_store_ctx->my_crt_issuer_dn_cache_len);

    RHP_TRC(0,RHPTRCID_OPENSSL_GET_MY_CERT_ISSUER_DN_DER_OUTB,"xp",cert_store,cert_store_ctx->my_crt_issuer_dn_cache_len,outb);

  }else{

    X509_NAME* dn;
    u8 *dn_der = NULL;
    int dn_der_len;

    if( cert_store_ctx->my_crt == NULL ){
      RHP_TRC(0,RHPTRCID_OPENSSL_GET_MY_CERT_ISSUER_DN_DER_NOT_MY_CERT_LOADED,"x",cert_store);
      err = -ENOENT;
      goto error;
    }

    dn = X509_get_issuer_name(cert_store_ctx->my_crt); // dn: Just a reference. Don't free it.
    if( dn == NULL ){
      err = -ENOENT;
      RHP_TRC(0,RHPTRCID_OPENSSL_GET_MY_CERT_ISSUER_DN_DER_NO_ISSUER_NAME_FOUND,"x",cert_store);
      goto error;
    }

    dn_der_len = i2d_X509_NAME(dn,NULL);
    if( dn_der_len < 0 ){
      RHP_TRC(0,RHPTRCID_OPENSSL_GET_MY_CERT_ISSUER_DN_DER_INVALID_ISSUER_NAME,"x",cert_store);
    	err = -EINVAL;
    	goto error;
    }

    dn_der = (u8*)_rhp_malloc(dn_der_len);
    if( dn_der == NULL ){
    	RHP_BUG("");
    	err = -ENOMEM;
    	goto error;
    }

    i2d_X509_NAME(dn,&dn_der);
    dn_der = (dn_der - dn_der_len);

    cert_store_ctx->my_crt_issuer_dn_cache = dn_der;
    cert_store_ctx->my_crt_issuer_dn_cache_len = dn_der_len;

    goto cache;
  }

  RHP_UNLOCK(&(cert_store->lock));

  *dn_len_r = cert_store_ctx->my_crt_issuer_dn_cache_len;
  *dn_r = outb;

  RHP_TRC(0,RHPTRCID_OPENSSL_GET_MY_CERT_ISSUER_DN_DER_RTRN,"xdp",cert_store,*dn_len_r,*dn_len_r,*dn_r);
  return 0;

error:
	if( cert_store_ctx ){
		if( cert_store_ctx->my_crt_issuer_dn_cache ){
			_rhp_free(cert_store_ctx->my_crt_issuer_dn_cache);
		}
		cert_store_ctx->my_crt_issuer_dn_cache = NULL;
		cert_store_ctx->my_crt_issuer_dn_cache_len = 0;
	}

	RHP_UNLOCK(&(cert_store->lock));

	if( outb ){
    _rhp_free(outb);
  }

  RHP_TRC(0,RHPTRCID_OPENSSL_GET_MY_CERT_ISSUER_DN_DER_ERR,"xE",cert_store,err);
  return err;
}

static int _rhp_cert_store_openssl_get_untrust_sub_ca_issuer_dn_der(rhp_cert_store* cert_store,u8** dn_r,
    int* dn_len_r)
{
  int err = -EINVAL;
  rhp_cert_store_openssl_ctx* cert_store_ctx = NULL;
  X509* cert = NULL;
  u8* outb = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_GET_UNTRUST_SUB_CA_ISSUER_DN_DER,"xxx",cert_store,dn_r,dn_len_r);

  RHP_LOCK(&(cert_store->lock));

  if( !_rhp_atomic_read(&(cert_store->is_active)) ){
  	err = -EINVAL;
    RHP_TRC(0,RHPTRCID_OPENSSL_GET_UNTRUST_SUB_CA_ISSUER_DN_DER_NOT_ACTIVE,"x",cert_store);
    goto error;
  }

  cert_store_ctx = (rhp_cert_store_openssl_ctx*)cert_store->ctx;
  if( cert_store_ctx == NULL ){
  	err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  if( cert_store_ctx->untrust_ca_issuer_dn_cache ){

cache:
    outb = (u8*)_rhp_malloc(cert_store_ctx->untrust_ca_issuer_dn_cache_len);
    if( outb == NULL ){
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }

    memcpy(outb,cert_store_ctx->untrust_ca_issuer_dn_cache,cert_store_ctx->untrust_ca_issuer_dn_cache_len);

    RHP_TRC(0,RHPTRCID_OPENSSL_GET_UNTRUST_SUB_CA_ISSUER_DN_DER_OUTB,"xp",cert_store,cert_store_ctx->untrust_ca_issuer_dn_cache_len,outb);

  }else{

    int n = 0;
    X509_NAME* dn;
    u8 *dn_der = NULL;
    int dn_der_len;

    if( cert_store_ctx->untrust_ca_crts == NULL ){
      RHP_TRC(0,RHPTRCID_OPENSSL_GET_UNTRUST_SUB_CA_ISSUER_DN_DER_NO_CERT_LOADED,"x",cert_store);
    	err = -ENOENT;
    	goto error;
    }

    n = sk_X509_num(cert_store_ctx->untrust_ca_crts);
    if( n < 1 ){
      RHP_TRC(0,RHPTRCID_OPENSSL_GET_UNTRUST_SUB_CA_ISSUER_DN_DER_NO_CERTS,"xd",cert_store,n);
    	err = -ENOENT;
    	goto error;
    }

	  cert = sk_X509_value(cert_store_ctx->untrust_ca_crts,(n - 1));

    dn = X509_get_issuer_name(cert); // dn: Just a reference. Don't free it.
    if( dn == NULL ){
      RHP_TRC(0,RHPTRCID_OPENSSL_GET_UNTRUST_SUB_CA_ISSUER_DN_DER_NO_ISSUER_NAME,"xx",cert_store,cert);
      err = -ENOENT;
      goto error;
    }

    dn_der_len = i2d_X509_NAME(dn,NULL);
    if( dn_der_len < 0 ){
      RHP_TRC(0,RHPTRCID_OPENSSL_GET_UNTRUST_SUB_CA_ISSUER_DN_DER_INVALID_ISSUER_NAME,"xxx",cert_store,cert,dn);
    	err = -EINVAL;
    	goto error;
    }

    dn_der = (u8*)_rhp_malloc(dn_der_len);
    if( dn_der == NULL ){
    	RHP_BUG("");
    	err = -ENOMEM;
    	goto error;
    }

    i2d_X509_NAME(dn,&dn_der);
    dn_der = (dn_der - dn_der_len);

    cert_store_ctx->untrust_ca_issuer_dn_cache = dn_der;
    cert_store_ctx->untrust_ca_issuer_dn_cache_len = dn_der_len;

    goto cache;
  }

  RHP_UNLOCK(&(cert_store->lock));

  *dn_len_r = cert_store_ctx->untrust_ca_issuer_dn_cache_len;
  *dn_r = outb;

  RHP_TRC(0,RHPTRCID_OPENSSL_GET_UNTRUST_SUB_CA_ISSUER_DN_DER_RTRN,"xp",cert_store,*dn_len_r,*dn_r);
  return 0;

error:
	if( cert_store_ctx ){
		if( cert_store_ctx->untrust_ca_issuer_dn_cache ){
			_rhp_free(cert_store_ctx->untrust_ca_issuer_dn_cache);
		}
		cert_store_ctx->untrust_ca_issuer_dn_cache = NULL;
		cert_store_ctx->untrust_ca_issuer_dn_cache_len = 0;
	}

	RHP_UNLOCK(&(cert_store->lock));

	if( outb ){
    _rhp_free(outb);
  }

  RHP_TRC(0,RHPTRCID_OPENSSL_GET_UNTRUST_SUB_CA_ISSUER_DN_DER_ERR,"xE",cert_store,err);
  return err;
}


static rhp_cert_dn* _rhp_cert_dn_alloc(X509_NAME* name,int ctx_shared);

static int _rhp_cert_store_openssl_enum_DER_certs(rhp_cert_store* cert_store,
		int deny_expired_cert,
		int enum_dn_also,
    int (*callback)(struct _rhp_cert_store* cert_store,
    		int is_my_cert,u8* der,int dar_len,rhp_cert_dn* cert_dn,void* ct_ctx),
    void* cb_ctx)
{
  int err = -EINVAL;
  rhp_cert_store_openssl_ctx* cert_store_ctx = NULL;
  X509* cert = NULL;
  int i;
  u8 *outb = NULL,*next;
  int n = 0,len = 0;
  rhp_cert_dn* cert_dn = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_ENUM_DER_CERTS,"xddxx",cert_store,deny_expired_cert,enum_dn_also,callback,cb_ctx);

  RHP_LOCK(&(cert_store->lock));

  if( !_rhp_atomic_read(&(cert_store->is_active)) ){
    RHP_TRC(0,RHPTRCID_OPENSSL_ENUM_DER_CERTS_NOT_ACITVE,"x",cert_store);
    goto error;
  }

  cert_store_ctx = (rhp_cert_store_openssl_ctx*)cert_store->ctx;

  if( cert_store_ctx->my_crt == NULL ){
    RHP_TRC(0,RHPTRCID_OPENSSL_ENUM_DER_CERTS_NO_MY_CERT,"x",cert_store);
  	err = -ENOENT;
  	goto error;
  }

  n = sk_X509_num(cert_store_ctx->untrust_ca_crts);

  {
    err =  _rhp_cert_store_verify_cert(cert_store_ctx,cert_store_ctx->store_ctx,
    		cert_store_ctx->my_crt,cert_store_ctx->untrust_ca_crts,deny_expired_cert);
    if( err ){
      RHP_TRC(0,RHPTRCID_OPENSSL_ENUM_DER_CERTS_CERT_VERIFY_ERR,"xxE",cert_store,cert,err);
      goto error;
    }

    RHP_TRC(0,RHPTRCID_OPENSSL_ENUM_DER_CERTS_CERT_VERIFY_OK,"xx",cert_store,cert);
  }

  for( i = 0; i < (n + 1); i++ ){

    int is_my_cert = 0;

    if( i == 0 ){

    	cert = cert_store_ctx->my_crt;
    	is_my_cert = 1;

    }else{

    	cert = sk_X509_value(cert_store_ctx->untrust_ca_crts,(i - 1));
    }


    if( enum_dn_also ){

      X509_NAME* dn;

      dn = X509_get_subject_name(cert); // dn is just a reference.
      if( dn == NULL ){
        RHP_BUG("");
         err = -ENOENT;
        goto error;
      }

      cert_dn = _rhp_cert_dn_alloc(dn,1);
      if( cert_dn == NULL ){
      	RHP_BUG("");
      	err = -ENOMEM;
      	goto error;
      }
    }


    len = i2d_X509(cert,NULL);

    outb = next = (u8*)_rhp_malloc(len);
    if( outb == NULL ){
      err = -ENOENT;
      RHP_BUG("");
      goto error;
    }

    i2d_X509(cert,&next);

    RHP_TRC(0,RHPTRCID_OPENSSL_ENUM_DER_CERTS_CERT_CB_ENUM,"xdxp",cert_store,i,cert,len,outb);

    {
			err = callback(cert_store,is_my_cert,outb,len,cert_dn,cb_ctx);

			_rhp_free(outb);
			outb = NULL;

			if( cert_dn ){
				rhp_cert_dn_free(cert_dn);
				cert_dn = NULL;
			}

			if( err == RHP_STATUS_ENUM_OK ){
				err = 0;
				RHP_TRC(0,RHPTRCID_OPENSSL_ENUM_DER_CERTS_CERT_CB_ENUM_OK,"xE",cert_store,err);
				goto end;
			}else if( err ){
				RHP_TRC(0,RHPTRCID_OPENSSL_ENUM_DER_CERTS_CERT_CB_ERR,"xE",cert_store,err);
				goto error;
			}
    }
  }

end:
  RHP_UNLOCK(&(cert_store->lock));

  if( outb ){
    _rhp_free(outb);
  }

  if( cert_dn ){
  	rhp_cert_dn_free(cert_dn);
  }

  RHP_TRC(0,RHPTRCID_OPENSSL_ENUM_DER_CERTS_RTRN,"x",cert_store);
  return 0;

error:
  RHP_UNLOCK(&(cert_store->lock));

  if( outb ){
    _rhp_free(outb);
  }

  if( cert_dn ){
  	rhp_cert_dn_free(cert_dn);
  }

  RHP_TRC(0,RHPTRCID_OPENSSL_ENUM_DER_CERTS_ERR,"xE",cert_store,err);
  return err;
}

static void _rhp_cert_store_openssl_sign_cb(int worker_idx,void *ctx)
{
  int err = -EINVAL;
  rhp_cert_sign_ctx* cb_ctx = (rhp_cert_sign_ctx*)ctx;
  rhp_cert_store* cert_store = (rhp_cert_store*)cb_ctx->priv[0];
  rhp_cert_store_openssl_ctx* cert_store_ctx = NULL;
  u8* priv_key = NULL;
  int priv_key_len = 0;
  rhp_crypto_rsasig* rsasig = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_SIGN_CB,"dxd",worker_idx,ctx,cb_ctx->sign_op_type);

  if( !_rhp_atomic_read(&(cert_store->is_active)) ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_SIGN_CB_NOT_ACTIVE,"x",ctx);
    goto error;
  }

  RHP_LOCK(&(cert_store->lock));

  cert_store_ctx = (rhp_cert_store_openssl_ctx*)cert_store->ctx;

  priv_key_len = i2d_PrivateKey(cert_store_ctx->pkey_ctx,NULL);

  priv_key = (u8*)_rhp_malloc(priv_key_len);
  if( priv_key == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error_l;
  }

  i2d_PrivateKey(cert_store_ctx->pkey_ctx,&priv_key);
  priv_key = (priv_key - priv_key_len);

  RHP_UNLOCK(&(cert_store->lock));

  rsasig = rhp_crypto_rsasig_alloc();
  if( rsasig == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  err = rsasig->set_priv_key(rsasig,priv_key,priv_key_len);
  if( err ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_SIGN_CB_RSASIG_SET_PRIV_KEY_ERR,"xE",ctx,err);
    goto error;
  }

  if( cb_ctx->sign_op_type == RHP_CERT_SIGN_OP_SIGN ){

  	err = rsasig->sign(rsasig,cb_ctx->mesg_octets,cb_ctx->mesg_octets_len,
  									&(cb_ctx->signed_octets),&(cb_ctx->signed_octets_len));

  }else if( cb_ctx->sign_op_type == RHP_CERT_SIGN_OP_SIGN_IKEV1 ){

  	err = rsasig->sign_ikev1(rsasig,cb_ctx->mesg_octets,cb_ctx->mesg_octets_len,
  									&(cb_ctx->signed_octets),&(cb_ctx->signed_octets_len));

  }else{
  	RHP_BUG("%d",cb_ctx->sign_op_type);
  	err = -EINVAL;
  }
  if( err ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_SIGN_CB_RSASIG_SIGN_ERR,"xE",ctx,err);
    goto error;
  }

  cb_ctx->callback(cert_store,0,cb_ctx);

  _rhp_free_zero(priv_key,priv_key_len);
  rhp_crypto_rsasig_free(rsasig);

  rhp_cert_store_unhold(cert_store);

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_SIGN_CB_RTRN,"x",ctx);
  return;

error_l:
  RHP_UNLOCK(&(cert_store->lock));
error:

  cb_ctx->callback(cert_store,err,cb_ctx);

  if( priv_key ){
    _rhp_free_zero(priv_key,priv_key_len);
  }
  if( rsasig ){
    rhp_crypto_rsasig_free(rsasig);
  }
  rhp_cert_store_unhold(cert_store);

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_SIGN_CB_ERR,"x",ctx);
  return;
}

static int _rhp_cert_store_openssl_sign(rhp_cert_store* cert_store,rhp_cert_sign_ctx* cb_ctx)
{
  int err = -EINVAL;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_SIGN,"xxd",cert_store,cb_ctx,cb_ctx->sign_op_type);

  if( cb_ctx->mesg_octets == NULL || cb_ctx->mesg_octets_len == 0 ||
       cb_ctx->callback == NULL ){
	RHP_BUG(" 0x%x , 0x%x , 0x%x",cb_ctx->mesg_octets,cb_ctx->mesg_octets_len,cb_ctx->callback);
    goto error;
  }

  if( !rhp_wts_dispach_ok(RHP_WTS_DISP_LEVEL_HIGH_2,0) ){
    RHP_BUG("");
    goto error;
  }

  RHP_LOCK(&(cert_store->lock));

  if( !_rhp_atomic_read(&(cert_store->is_active)) ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_SIGN_NOT_ACITVE,"x",cert_store);
    goto error_l;
  }

  cb_ctx->priv[0] = (unsigned long)cert_store;
  rhp_cert_store_hold(cert_store);

  RHP_UNLOCK(&(cert_store->lock));

  err = rhp_wts_add_task(RHP_WTS_DISP_RULE_CERTOPR,
  				RHP_WTS_DISP_LEVEL_HIGH_2,cb_ctx,_rhp_cert_store_openssl_sign_cb,cb_ctx);
  if( err ){
    rhp_cert_store_unhold(cert_store);
    RHP_BUG("%d",err);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_SIGN_RTRN,"x",cert_store);
  return 0;

error_l:
  RHP_UNLOCK(&(cert_store->lock));
error:

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_SIGN_ERR,"xE",cert_store,err);
  return err;
}

static int _rhp_cert_openssl_get_cert_subjectaltname_impl(X509* cert_impl,char** altname_r,
    int* altname_len_r,int* altname_type_r)
{
  int err = -EINVAL;
  GENERAL_NAMES* gen_names = NULL;
  GENERAL_NAME* gen_name = NULL;
  ASN1_IA5STRING* ia5 = NULL;
  int i;
  char* altname = NULL;
  int altname_type;
  int gen_names_num = 0;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_CERT_SUBJECTNAME_IMPL,"xxxx",cert_impl,altname_r,altname_len_r,altname_type_r);

  gen_names = X509_get_ext_d2i(cert_impl,NID_subject_alt_name,NULL,NULL);
  if( gen_names == NULL ){
    err = -ENOENT;
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_CERT_SUBJECTNAME_IMPL_NO_SUBJECTALT,"x",cert_impl);
    goto error;
  }

  gen_names_num = sk_GENERAL_NAME_num(gen_names);

  if( gen_names_num ){

    for(i = gen_names_num - 1; i >= 0 ; i--){

      gen_name = sk_GENERAL_NAME_value(gen_names,i);

      if( gen_name->type == GEN_EMAIL || gen_name->type == GEN_DNS ){

        ia5 = gen_name->d.ia5;

        if( gen_name->type == GEN_EMAIL ){
          altname_type = RHP_PROTO_IKE_ID_RFC822_ADDR;
        }else if( gen_name->type == GEN_DNS ){
          altname_type = RHP_PROTO_IKE_ID_FQDN;
        }

        break;
      }

      RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_CERT_SUBJECTNAME_IMPL_ENUM,"xddxd",cert_impl,i,gen_names_num,gen_name,gen_name->type);

      gen_name = NULL;
    }

  }else{
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_CERT_SUBJECTNAME_IMPL_NUM_ZERO,"x",cert_impl);
  }

  if( ia5 == NULL || ia5->length == 0 ){
    err = -ENOENT;
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_CERT_SUBJECTNAME_IMPL_SUBJECTALT_NOT_FOUND,"x",cert_impl);
    goto error;
  }

  altname = (char*)_rhp_malloc(ia5->length + 1);
  if( altname == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  memcpy(altname,ia5->data,ia5->length);
  altname[ia5->length] = '\0';

  *altname_r = altname;
  *altname_len_r = ia5->length + 1;
  *altname_type_r = altname_type;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_CERT_SUBJECTNAME_IMPL_SUBJECTALT_RTRN,"xLdp",cert_impl,"PROTO_IKE_ID",*altname_type_r,*altname_len_r,*altname_r);
  return 0;

error:
  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_CERT_SUBJECTNAME_IMPL_SUBJECTALT_ERR,"xE",cert_impl,err);
  return err;
}

static int _rhp_cert_store_openssl_certs_printed_text(STACK_OF(X509)* certs,u8** out_r,int* out_len_r)
{
  int err = -EINVAL;
  X509* cert = NULL;
  int i, n = 0;
	BIO *mem = NULL;
	unsigned char* tmp = NULL;
	int tmp_len = 0;
	u8* out = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERTS_PRINTED_TEXT,"xxx",certs,out_r,out_len_r);


  n = sk_X509_num(certs);

  if( n < 1 ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERTS_PRINTED_TEXT_NO_CA_CERTS,"x",certs);
    err = -ENOENT;
    goto error;
  }

	mem = BIO_new(BIO_s_mem());
	if ( mem == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
    goto error;
	}

  for( i = 0; i < n ; i++ ){

		cert = sk_X509_value(certs,i);

    err = X509_print_ex(mem,cert,0,0);
		if( !err ){
				err = -EINVAL;
				RHP_TRC(0,RHPTRCID_OPENSSL_CERTS_PRINTED_TEXT_X509_PRINT_EX_ERR,"x",certs);
				goto error;
		}
  }

	tmp_len = BIO_get_mem_data(mem, (char **)&tmp);
	RHP_TRC(0,RHPTRCID_OPENSSL_CERTS_PRINTED_TEXT_DUMP,"xp",certs,tmp_len,tmp);

	BIO_set_close(mem, BIO_NOCLOSE);
	BIO_free(mem);
	mem = NULL;

	out = (u8*)_rhp_malloc(tmp_len + 1);
	if( out == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memcpy(out,tmp,tmp_len);
	OPENSSL_free(tmp);

	out[tmp_len] = '\0';

	*out_r = out;
	*out_len_r = tmp_len + 1;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERTS_PRINTED_TEXT_RTRN,"xp",certs,*out_len_r,*out_r);
  return 0;

error:

  if( mem ){
  	BIO_free(mem);
  }

  if( tmp ){
  	OPENSSL_free(tmp);
  }

  RHP_TRC(0,RHPTRCID_OPENSSL_CERTS_PRINTED_TEXT_ERR,"xE",certs,err);
  return err;
}

static int _rhp_cert_store_openssl_a_cert_printed_text(X509* cert,u8** out_r,int* out_len_r)
{
  int err = -EINVAL;
	BIO *mem = NULL;
	unsigned char* tmp = NULL;
	int tmp_len = 0;
	u8* out = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_CERT_PRINTED_TEXT,"xxx",cert,out_r,out_len_r);

	mem = BIO_new(BIO_s_mem());
	if ( mem == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
    goto error_l;
	}

	err = X509_print_ex(mem,cert,0,0);
	if( !err ){
		err = -EINVAL;
	  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_CERT_PRINTED_TEXT_X509_PRINT_EX_ERR,"x",cert);
		goto error_l;
	}

	tmp_len = BIO_get_mem_data(mem, (char **)&tmp);
  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_CERT_PRINTED_TEXT_DUMP,"xp",cert,tmp_len,tmp);

	BIO_set_close(mem, BIO_NOCLOSE);
	BIO_free(mem);
	mem = NULL;

	out = (u8*)_rhp_malloc(tmp_len + 1);
	if( out == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error_l;
	}

	memcpy(out,tmp,tmp_len);
	OPENSSL_free(tmp);

	out[tmp_len] = '\0';

	*out_r = out;
	*out_len_r = tmp_len + 1;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_CERT_PRINTED_TEXT_RTRN,"xp",cert,*out_len_r,*out_r);
  return 0;

error_l:
  if( mem ){
  	BIO_free(mem);
  }

  if( tmp ){
  	OPENSSL_free(tmp);
  }

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_CERT_PRINTED_TEXT_ERR,"xE",cert,err);
  return err;
}


int rhp_cert_get_certs_printed_text(u8* certs_der_bin,int certs_der_bin_len,int certs_num,u8** out_r,int* out_len_r)
{
	int err = -EINVAL;
  STACK_OF(X509)* certs_chain = NULL;
  X509* cert = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_GET_CERTS_PRINTED_TEXT,"pdxx",certs_der_bin_len,certs_der_bin,certs_num,out_r,out_len_r);

  certs_chain = sk_X509_new_null();
  if( certs_chain == NULL ){
    RHP_BUG("");
  	err = -EINVAL;
    goto error;
  }

  if( certs_num > 1 ){

  	err = _rhp_cert_store_openssl_load_certs_ders(certs_der_bin,certs_der_bin_len,
  							certs_num,certs_chain,NULL,NULL);

		if( err ){
			RHP_TRC(0,RHPTRCID_OPENSSL_CERT_GET_CERTS_PRINTED_TEXT_LOAD_DERS_ERR,"xE",certs_der_bin,err);
			goto error;
		}

	  err = _rhp_cert_store_openssl_certs_printed_text(certs_chain,out_r,out_len_r);
	  if( err ){
	    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_GET_CERTS_PRINTED_TEXT_X509_PRINT_ERR,"xE",certs_der_bin,err);
	  	goto error;
	  }

		sk_X509_free(certs_chain);

  }else{

    u8* next = certs_der_bin;

    cert = d2i_X509(NULL,(const unsigned char**)&next,certs_der_bin_len);
    if( cert == NULL ){
			RHP_TRC(0,RHPTRCID_OPENSSL_CERT_GET_CERTS_PRINTED_TEXT_LOAD_DERS_ERR_2,"x",certs_der_bin);
    	err = -EINVAL;
      goto error;
    }

  	err = _rhp_cert_store_openssl_a_cert_printed_text(cert,out_r,out_len_r);
  	if( err ){
	    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_GET_CERTS_PRINTED_TEXT_X509_PRINT_ERR_2,"xE",certs_der_bin,err);
	  	goto error;
	  }

    X509_free(cert);
  }


  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_GET_CERTS_PRINTED_TEXT_RTRN,"xp",certs_der_bin,*out_len_r,*out_r);
  return 0;

error:
	if( certs_chain ){
		sk_X509_free(certs_chain);
	}

	if( cert ){
    X509_free(cert);
	}

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_GET_CERTS_PRINTED_TEXT_ERR,"xE",certs_der_bin,err);
	return err;
}


static void _rhp_cert_store_openssl_verify_cb(int worker_idx,void *ctx)
{
  int err = -EINVAL;
  rhp_cert_sign_verify_ctx* cb_ctx = (rhp_cert_sign_verify_ctx*)ctx;
  rhp_cert_store* cert_store = (rhp_cert_store*)cb_ctx->priv[0];
  rhp_cert_store_openssl_ctx* cert_store_ctx = NULL;
  rhp_crypto_rsasig* rsasig = NULL;
  rhp_cert* peer_cert = NULL;
  u8* pub_key = NULL;
  int pub_key_len = 0;
  STACK_OF(X509)* peer_cert_chain = NULL;
  EVP_PKEY* pub_key_ctx = NULL;
  rhp_ikev2_id subjectname,subjectaltname;
  rhp_ikev2_id *subjectname_p = NULL,*subjectaltname_p = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_VERIFY_CB,"dxd",worker_idx,ctx,cb_ctx->sign_op_type);

  memset(&subjectname,0,sizeof(rhp_ikev2_id));
  memset(&subjectaltname,0,sizeof(rhp_ikev2_id));

  RHP_LOCK(&(cert_store->lock));

  if( !_rhp_atomic_read(&(cert_store->is_active)) ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_VERIFY_CB_NOT_ACTIVE,"xx",ctx,cert_store);
    err = -EINVAL;
    goto error_l;
  }

  cert_store_ctx = (rhp_cert_store_openssl_ctx*)cert_store->ctx;

  if( cb_ctx->cert_chain_bin ){

    peer_cert_chain = sk_X509_new_null();
    if( peer_cert_chain == NULL ){
      RHP_BUG("");
    	err = -EINVAL;
      goto error_l;
    }

    if( (err = _rhp_cert_store_openssl_load_certs_ders(cb_ctx->cert_chain_bin,
                  cb_ctx->cert_chain_bin_len,cb_ctx->cert_chain_num,peer_cert_chain,NULL,NULL) ) ){
      RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_VERIFY_CB_LOAD_CERTS_DERS_ERR,"xxE",ctx,cert_store,err);
      goto error_l;
    }
  }

  peer_cert = cb_ctx->peer_cert;
  if( peer_cert == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
    goto error_l;
  }

  err = _rhp_cert_store_verify_cert(cert_store_ctx,cert_store_ctx->store_ctx,
                                    ((rhp_cert_openssl_ctx*)peer_cert->ctx)->cert_impl,peer_cert_chain,
                                    cb_ctx->deny_expired_cert);
  if( err ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_VERIFY_CB_VERIFY_CERT_ERR,"xxE",ctx,cert_store,err);
    goto error_l;
  }

  RHP_UNLOCK(&(cert_store->lock));


  pub_key_ctx = X509_get_pubkey(((rhp_cert_openssl_ctx*)peer_cert->ctx)->cert_impl);
  if( pub_key_ctx == NULL ){
  	err = -EINVAL;
  	RHP_BUG("");
    goto error;
  }

  pub_key_len = i2d_PublicKey(pub_key_ctx,NULL);

  pub_key = (u8*)_rhp_malloc(pub_key_len);
  if( pub_key == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  i2d_PublicKey(pub_key_ctx,&pub_key);
  pub_key = (pub_key - pub_key_len);

  rsasig = rhp_crypto_rsasig_alloc();
  if( rsasig == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error_l;
  }

  err = rsasig->set_pub_key(rsasig,pub_key,pub_key_len);
  if( err ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_VERIFY_CB_RSASIG_SET_PUB_KEY_ERR,"xxE",ctx,cert_store,err);
    goto error;
  }

  if( cb_ctx->sign_op_type == RHP_CERT_SIGN_OP_VERIFY ){

  	err = rsasig->verify(rsasig,cb_ctx->signed_octets,cb_ctx->signed_octets_len,
  									cb_ctx->signature,cb_ctx->signature_len);

  }else if( cb_ctx->sign_op_type == RHP_CERT_SIGN_OP_VERIFY_IKEV1 ){

  	err = rsasig->verify_ikev1(rsasig,cb_ctx->signed_octets,cb_ctx->signed_octets_len,
  									cb_ctx->signature,cb_ctx->signature_len);

  }else{
  	RHP_BUG("");
  	err = -EINVAL;
  }
  if( err ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_VERIFY_CB_RSASIG_VERIFY_ERR,"xxE",ctx,cert_store,err);
    goto error;
  }

  {
    X509_NAME* dn;
    u8* dn_der = NULL;
    int dn_der_len;

    dn = X509_get_subject_name(((rhp_cert_openssl_ctx*)peer_cert->ctx)->cert_impl); // dn: Just a reference. Don't free it.
    if( dn == NULL ){
      err = -ENOENT;
      goto error;
    }

    dn_der_len = i2d_X509_NAME(dn,NULL);
    if( dn_der_len < 0 ){
    	err = -EINVAL;
    	goto error;
    }

    dn_der = (u8*)_rhp_malloc(dn_der_len);
    if( dn_der == NULL ){
    	RHP_BUG("");
    	err = -ENOMEM;
    	goto error;
    }

    i2d_X509_NAME(dn,&dn_der);
    dn_der = (dn_der - dn_der_len);

    err = rhp_ikev2_id_setup(RHP_PROTO_IKE_ID_DER_ASN1_DN,dn_der,dn_der_len,&subjectname);
    _rhp_free(dn_der);

    if( err ){
			goto error;
		}

    subjectname_p = &subjectname;
  }

  {
  	char* altname = NULL;
  	int altname_len = 0;
  	int altname_type = -1;

  	err = _rhp_cert_openssl_get_cert_subjectaltname_impl(((rhp_cert_openssl_ctx*)peer_cert->ctx)->cert_impl,
  			&altname,&altname_len,&altname_type);

  	if( !err ){

			err = rhp_ikev2_id_setup(altname_type,altname,altname_len,&subjectaltname);
			_rhp_free(altname);

			if( err ){
				goto error;
			}

			subjectaltname_p = &subjectaltname;
  	}
  }

  cb_ctx->callback(cert_store,0,subjectname_p,subjectaltname_p,cb_ctx);

   EVP_PKEY_free(pub_key_ctx);
  _rhp_free_zero(pub_key,pub_key_len);
  rhp_crypto_rsasig_free(rsasig);
  if( peer_cert_chain ){
    sk_X509_free(peer_cert_chain);
  }

  rhp_ikev2_id_clear(&subjectname);
  rhp_ikev2_id_clear(&subjectaltname);

  rhp_cert_store_unhold(cert_store);

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_VERIFY_CB_RTRN,"xx",ctx,cert_store);
  return;

error_l:
  RHP_UNLOCK(&(cert_store->lock));
error:

	if( !err ){
		err = -EINVAL;
		RHP_BUG("");
	}

  cb_ctx->callback(cert_store,err,NULL,NULL,cb_ctx);

  if( pub_key ){
    _rhp_free_zero(pub_key,pub_key_len);
  }
  if( rsasig ){
    rhp_crypto_rsasig_free(rsasig);
  }
  if( peer_cert_chain ){
    sk_X509_free(peer_cert_chain);
  }
  if( pub_key_ctx ){
    EVP_PKEY_free(pub_key_ctx);
  }
  rhp_cert_store_unhold(cert_store);

  rhp_ikev2_id_clear(&subjectname);
  rhp_ikev2_id_clear(&subjectaltname);

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_VERIFY_CB_ERR,"xx",ctx,cert_store);
  return;
}

static int _rhp_cert_store_openssl_verify_signature(rhp_cert_store* cert_store,rhp_cert_sign_verify_ctx* cb_ctx)
{
  int err = -EINVAL;
  rhp_cert_store_openssl_ctx* cert_store_ctx = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_VERIFY_SIGNATURE,"xxxd",cert_store,cb_ctx,cert_store->ctx,cb_ctx->sign_op_type);

  if( cb_ctx->peer_cert == NULL ||
      cb_ctx->signed_octets == NULL || cb_ctx->signed_octets_len == 0 ||
      cb_ctx->signature == NULL || cb_ctx->signature_len == 0 ||
      cb_ctx->callback == NULL ){
  	RHP_BUG("0x%x,0x%x,0x%x,0x%x,0x%x,0x%x",cb_ctx->peer_cert,cb_ctx->signed_octets,cb_ctx->signed_octets_len,cb_ctx->signature,cb_ctx->signature_len,cb_ctx->callback);
    goto error;
  }

  if( !rhp_wts_dispach_ok(RHP_WTS_DISP_LEVEL_HIGH_2,0) ){
    RHP_BUG("");
    goto error;
  }

  RHP_LOCK(&(cert_store->lock));

  if( !_rhp_atomic_read(&(cert_store->is_active)) ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_VERIFY_SIGNATURE_NOT_ACTIVE,"x",cert_store);
    goto error_l;
  }

  cert_store_ctx = (rhp_cert_store_openssl_ctx*)cert_store->ctx;

  if( cert_store_ctx->store_ctx == NULL ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_VERIFY_SIGNATURE_NO_CERT_STORE_MAYBE_NO_CA_CERTS,"xxx",cert_store,cb_ctx,cert_store_ctx);
    goto error_l;
  }

  cb_ctx->priv[0] = (unsigned long)cert_store;
  rhp_cert_store_hold(cert_store);

  RHP_UNLOCK(&(cert_store->lock));

  err = rhp_wts_add_task(RHP_WTS_DISP_RULE_CERTOPR,RHP_WTS_DISP_LEVEL_HIGH_2,
  				cb_ctx,_rhp_cert_store_openssl_verify_cb,cb_ctx);
  if( err ){
    rhp_cert_store_unhold(cert_store);
    RHP_BUG("%d",err);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_VERIFY_SIGNATURE_RTRN,"x",cert_store);
  return 0;

error_l:
  RHP_UNLOCK(&(cert_store->lock));
error:

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_VERIFY_SIGNATURE_ERR,"xE",cert_store,err);
  return err;
}


static char* _rhp_cert_store_openssl_get_my_cert_serialno_text(rhp_cert_store* cert_store)
{
  int err = -EINVAL;
  rhp_cert_store_openssl_ctx* cert_store_ctx;
  char* ret;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_SERIALNO_TEXT,"x",cert_store);

  RHP_LOCK(&(cert_store->lock));

  if( !_rhp_atomic_read(&(cert_store->is_active)) ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_SERIALNO_TEXT_NOT_ACTIVE,"x",cert_store);
    goto error_l;
  }

  cert_store_ctx = (rhp_cert_store_openssl_ctx*)cert_store->ctx;

  if( cert_store_ctx->my_crt == NULL ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_SERIALNO_TEXT_NO_MY_CERT,"x",cert_store);
    err = -ENOENT;
    goto error_l;
  }

	ret = _rhp_X509_SERIALNO_text(cert_store_ctx->my_crt);
	if( ret == NULL ){
    err = -ENOENT;
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_SERIALNO_TEXT_NO_SERIALNO,"x",cert_store);
    goto error_l;
	}

  RHP_UNLOCK(&(cert_store->lock));

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_SERIALNO_TEXT_RTRN,"xs",cert_store,ret);
  return ret;

error_l:
  RHP_UNLOCK(&(cert_store->lock));

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_SERIALNO_TEXT_ERR,"xE",cert_store,err);
  return NULL;
}

static char* _rhp_cert_store_openssl_get_my_cert_dn_text(rhp_cert_store* cert_store)
{
  int err = -EINVAL;
  rhp_cert_store_openssl_ctx* cert_store_ctx;
  char* ret;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_DN_TEXT,"x",cert_store);

  RHP_LOCK(&(cert_store->lock));

  if( !_rhp_atomic_read(&(cert_store->is_active)) ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_DN_TEXT_NOT_ACTIVE,"x",cert_store);
    goto error_l;
  }

  cert_store_ctx = (rhp_cert_store_openssl_ctx*)cert_store->ctx;

  if( cert_store_ctx->my_crt == NULL ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_DN_TEXT_NO_MY_CERT,"x",cert_store);
    err = -ENOENT;
    goto error_l;
  }

	ret = _rhp_X509_NAME_oneline(cert_store_ctx->my_crt);
	if( ret == NULL ){
    err = -ENOENT;
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_DN_TEXT_NO_SUBJECTNAME_2,"x",cert_store);
    goto error_l;
	}

  RHP_UNLOCK(&(cert_store->lock));

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_DN_TEXT_RTRN,"xs",cert_store,ret);
  return ret;

error_l:
  RHP_UNLOCK(&(cert_store->lock));

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_DN_TEXT_ERR,"xE",cert_store,err);
  return NULL;
}


static int _rhp_cert_store_openssl_get_my_cert_dn_der(rhp_cert_store* cert_store,u8** outb,int* outb_len)
{
  int err = -EINVAL;
  rhp_cert_store_openssl_ctx* cert_store_ctx;
  X509_NAME* dn = NULL;
  u8* dn_der = NULL;
  int dn_der_len = 0;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_DN_DER,"xxx",cert_store,outb,outb_len);

  RHP_LOCK(&(cert_store->lock));

  if( !_rhp_atomic_read(&(cert_store->is_active)) ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_DN_DER_NOT_ACTIVE,"x",cert_store);
    goto error_l;
  }

  cert_store_ctx = (rhp_cert_store_openssl_ctx*)cert_store->ctx;

  if( cert_store_ctx->my_crt == NULL ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_DN_DER_NO_MY_CERT,"x",cert_store);
    err = -ENOENT;
    goto error_l;
  }

  dn = X509_get_subject_name(cert_store_ctx->my_crt); // dn: Just a reference. Don't free it.
  if( dn == NULL ){
    err = -ENOENT;
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_DN_DER_NO_SUBJECTNAME,"x",cert_store);
    goto error_l;
  }

  dn_der_len = i2d_X509_NAME(dn,NULL);
  if( dn_der_len < 0 ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_DN_DER_PARSE_ERR,"xx",cert_store,dn);
    goto error_l;
  }

  dn_der = (u8*)_rhp_malloc(dn_der_len);
  if( dn_der == NULL ){
  	RHP_BUG("");
  	goto error_l;
  }

  i2d_X509_NAME(dn,&dn_der);
  dn_der = (dn_der - dn_der_len);

  RHP_UNLOCK(&(cert_store->lock));

  *outb = dn_der;
  *outb_len = dn_der_len;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_DN_DER_RTRN,"xxp",cert_store,dn,dn_der_len,dn_der);
  return 0;

error_l:
  RHP_UNLOCK(&(cert_store->lock));

  if( dn_der ){
		_rhp_free(dn_der);
	}

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_DN_DER_ERR,"xE",cert_store,err);
  return err;
}

static int _rhp_cert_store_openssl_get_my_cert_subjectaltname(rhp_cert_store* cert_store,char** altname_r,
    int* altname_len_r,int* altname_type_r)
{
  int err = -EINVAL;
  rhp_cert_store_openssl_ctx* cert_store_ctx = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_SUBJECTNAME,"xxxx",cert_store,altname_r,altname_len_r,altname_type_r);

  RHP_LOCK(&(cert_store->lock));

  if( !_rhp_atomic_read(&(cert_store->is_active)) ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_SUBJECTNAME_NOT_ACITVE,"x",cert_store);
    goto error_l;
  }

  cert_store_ctx = (rhp_cert_store_openssl_ctx*)cert_store->ctx;

  if( cert_store_ctx->my_crt == NULL ){
  	err = -ENOENT;
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_SUBJECTNAME_NO_MY_CERT,"x",cert_store);
    goto error_l;
  }

  err = _rhp_cert_openssl_get_cert_subjectaltname_impl(cert_store_ctx->my_crt,
  		altname_r,altname_len_r,altname_type_r);

  if( err ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_SUBJECTNAME_IMPL_ERR,"xE",cert_store,err);
    goto error_l;
  }

  RHP_UNLOCK(&(cert_store->lock));

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_SUBJECTNAME_RTRN,"x",cert_store);
  return 0;

error_l:
  RHP_UNLOCK(&(cert_store->lock));

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_SUBJECTNAME_ERR,"xE",cert_store,err);
  return err;
}


static int _rhp_cert_store_openssl_get_my_cert_printed_text(rhp_cert_store* cert_store,u8** out_r,
    int* out_len_r)
{
  int err = -EINVAL;
  rhp_cert_store_openssl_ctx* cert_store_ctx = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_PRINTED_TEXT,"xxx",cert_store,out_r,out_len_r);

  RHP_LOCK(&(cert_store->lock));

  if( !_rhp_atomic_read(&(cert_store->is_active)) ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_PRINTED_TEXT_NOT_ACITVE,"x",cert_store);
    goto error_l;
  }

  cert_store_ctx = (rhp_cert_store_openssl_ctx*)cert_store->ctx;

  if( cert_store_ctx->my_crt == NULL ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_PRINTED_TEXT_NO_MY_CERT,"x",cert_store);
    err = -ENOENT;
    goto error_l;
  }

  err = _rhp_cert_store_openssl_a_cert_printed_text(cert_store_ctx->my_crt,out_r,out_len_r);
  if( err ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_PRINTED_TEXT_PRINT_ERR,"x",cert_store);
    goto error_l;
  }

  RHP_UNLOCK(&(cert_store->lock));

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_PRINTED_TEXT_RTRN,"xp",cert_store,*out_len_r,*out_r);
  return 0;

error_l:
  RHP_UNLOCK(&(cert_store->lock));

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_GET_MY_CERT_PRINTED_TEXT_ERR,"xE",cert_store,err);
  return err;
}


static int _rhp_cert_store_openssl_get_ca_certs_printed_text(rhp_cert_store* cert_store,u8** out_r,
    int* out_len_r)
{
  int err = -EINVAL;
  rhp_cert_store_openssl_ctx* cert_store_ctx = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_GET_CA_CERTS_PRINTED_TEXT,"xxx",cert_store,out_r,out_len_r);

  RHP_LOCK(&(cert_store->lock));

  if( !_rhp_atomic_read(&(cert_store->is_active)) ){
    RHP_TRC(0,RHPTRCID_OPENSSL_GET_CA_CERTS_PRINTED_TEXT_NOT_ACITVE,"x",cert_store);
    goto error;
  }

  cert_store_ctx = (rhp_cert_store_openssl_ctx*)cert_store->ctx;

  err = _rhp_cert_store_openssl_certs_printed_text(cert_store_ctx->trusted_ca_crts,out_r,out_len_r);
  if( err ){
    RHP_TRC(0,RHPTRCID_OPENSSL_GET_CA_CERTS_PRINTED_TEXT_X509_PRINT_ERR,"x",cert_store);
    goto error;
  }

	RHP_UNLOCK(&(cert_store->lock));

  RHP_TRC(0,RHPTRCID_OPENSSL_GET_CA_CERTS_PRINTED_TEXT_RTRN,"xxp",cert_store,cert_store_ctx,*out_len_r,*out_r);
  return 0;

error:
  RHP_UNLOCK(&(cert_store->lock));

  RHP_TRC(0,RHPTRCID_OPENSSL_GET_CA_CERTS_PRINTED_TEXT_ERR,"xxE",cert_store,cert_store_ctx,err);
  return err;
}


static int _rhp_cert_store_openssl_get_crls_printed_text(rhp_cert_store* cert_store,u8** out_r,
    int* out_len_r)
{
  int err = -EINVAL;
  rhp_cert_store_openssl_ctx* cert_store_ctx = NULL;
  X509_CRL* crl = NULL;
  int i, n = 0;
	BIO *mem = NULL;
	unsigned char* tmp = NULL;
	int tmp_len = 0;
	u8* out = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_GET_CRLS_PRINTED_TEXT,"xxx",cert_store,out_r,out_len_r);

  RHP_LOCK(&(cert_store->lock));

  if( !_rhp_atomic_read(&(cert_store->is_active)) ){
    RHP_TRC(0,RHPTRCID_OPENSSL_GET_CRLS_PRINTED_TEXT_NOT_ACITVE,"x",cert_store);
    goto error;
  }

  cert_store_ctx = (rhp_cert_store_openssl_ctx*)cert_store->ctx;

  if( cert_store_ctx->crls_file == NULL ){
    RHP_TRC(0,RHPTRCID_OPENSSL_GET_CRLS_PRINTED_TEXT_NO_CA_CERTS,"x",cert_store);
    err = -ENOENT;
    goto error;
  }

  n = sk_X509_CRL_num(cert_store_ctx->crls_list);

  if( n < 1 ){
    RHP_TRC(0,RHPTRCID_OPENSSL_GET_CRLS_PRINTED_TEXT_NO_CA_CERTS_2,"x",cert_store);
    err = -ENOENT;
    goto error;
  }

	mem = BIO_new(BIO_s_mem());
	if ( mem == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
    goto error;
	}

  for( i = 0; i < n ; i++ ){

		crl = sk_X509_CRL_value(cert_store_ctx->crls_list,i);

    err = X509_CRL_print(mem,crl);
		if( !err ){
				err = -EINVAL;
				RHP_TRC(0,RHPTRCID_OPENSSL_GET_CRLS_PRINTED_TEXT_X509_PRINT_EX_ERR,"x",cert_store);
				goto error;
		}
  }

	tmp_len = BIO_get_mem_data(mem, (char **)&tmp);
	RHP_TRC(0,RHPTRCID_OPENSSL_GET_CRLS_PRINTED_TEXT_DUMP,"xp",cert_store,tmp_len,tmp);

	BIO_set_close(mem, BIO_NOCLOSE);
	BIO_free(mem);
	mem = NULL;

	out = (u8*)_rhp_malloc(tmp_len + 1);
	if( out == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memcpy(out,tmp,tmp_len);
	OPENSSL_free(tmp);

	out[tmp_len] = '\0';

	*out_r = out;
	*out_len_r = tmp_len + 1;

	RHP_UNLOCK(&(cert_store->lock));

  RHP_TRC(0,RHPTRCID_OPENSSL_GET_CRLS_PRINTED_TEXT_RTRN,"xp",cert_store,*out_len_r,*out_r);
  return 0;

error:
  RHP_UNLOCK(&(cert_store->lock));

  if( mem ){
  	BIO_free(mem);
  }

  if( tmp ){
  	OPENSSL_free(tmp);
  }

  RHP_TRC(0,RHPTRCID_OPENSSL_GET_CRLS_PRINTED_TEXT_ERR,"xE",cert_store,err);
  return err;
}

static int _rhp_cert_store_openssl_get_my_and_intermediate_ca_certs_printed_text(rhp_cert_store* cert_store,u8** out_r,
    int* out_len_r)
{
  int err = -EINVAL;
  rhp_cert_store_openssl_ctx* cert_store_ctx = NULL;
  X509* cert = NULL;
  int i, n = 0;
	BIO *mem = NULL;
	unsigned char* tmp = NULL;
	int tmp_len = 0;
	u8* out = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_GET_MY_AND_INTERMEDIATE_CA_CERTS_PRINTED_TEXT_PRINTED_TEXT,"xxx",cert_store,out_r,out_len_r);

  RHP_LOCK(&(cert_store->lock));

  if( !_rhp_atomic_read(&(cert_store->is_active)) ){
    RHP_TRC(0,RHPTRCID_OPENSSL_GET_MY_AND_INTERMEDIATE_CA_CERTS_PRINTED_TEXT_PRINTED_TEXT_NOT_ACITVE,"x",cert_store);
    goto error;
  }

  cert_store_ctx = (rhp_cert_store_openssl_ctx*)cert_store->ctx;

  if( cert_store_ctx->my_crt == NULL ){
    RHP_TRC(0,RHPTRCID_OPENSSL_GET_MY_AND_INTERMEDIATE_CA_CERTS_PRINTED_TEXT_PRINTED_TEXT_NO_CA_CERTS,"x",cert_store);
    err = -ENOENT;
    goto error;
  }

	mem = BIO_new(BIO_s_mem());
	if ( mem == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
    goto error;
	}

  n = sk_X509_num(cert_store_ctx->untrust_ca_crts);

  for( i = 0; i < (n + 1) ; i++ ){

  	if( i == 0 ){
  		cert = cert_store_ctx->my_crt;
  	}else{
  		cert = sk_X509_value(cert_store_ctx->untrust_ca_crts,(i - 1));
  	}

    err = X509_print_ex(mem,cert,0,0);
		if( !err ){
				err = -EINVAL;
				RHP_TRC(0,RHPTRCID_OPENSSL_GET_MY_AND_INTERMEDIATE_CA_CERTS_PRINTED_TEXT_PRINTED_TEXT_X509_PRINT_EX_ERR,"x",cert_store);
				goto error;
		}
  }

	tmp_len = BIO_get_mem_data(mem, (char **)&tmp);
	RHP_TRC(0,RHPTRCID_OPENSSL_GET_MY_AND_INTERMEDIATE_CA_CERTS_PRINTED_TEXT_PRINTED_TEXT_DUMP,"xp",cert_store,tmp_len,tmp);

	BIO_set_close(mem, BIO_NOCLOSE);
	BIO_free(mem);
	mem = NULL;

	out = (u8*)_rhp_malloc(tmp_len + 1);
	if( out == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memcpy(out,tmp,tmp_len);
	OPENSSL_free(tmp);

	out[tmp_len] = '\0';

	*out_r = out;
	*out_len_r = tmp_len + 1;

	RHP_UNLOCK(&(cert_store->lock));

  RHP_TRC(0,RHPTRCID_OPENSSL_GET_MY_AND_INTERMEDIATE_CA_CERTS_PRINTED_TEXT_PRINTED_TEXT_RTRN,"xp",cert_store,*out_len_r,*out_r);
  return 0;

error:
  RHP_UNLOCK(&(cert_store->lock));

  if( mem ){
  	BIO_free(mem);
  }

  if( tmp ){
  	OPENSSL_free(tmp);
  }

  RHP_TRC(0,RHPTRCID_OPENSSL_GET_MY_AND_INTERMEDIATE_CA_CERTS_PRINTED_TEXT_PRINTED_TEXT_ERR,"xE",cert_store,err);
  return err;
}


static int _rhp_cert_store_openssl_cert_verify_cb(int ok,X509_STORE_CTX* store)
{
  // TODO Write warning log for being expiring certificate , if any.

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_VERIFY_CB_FROM_LIB,"dxLd",ok,store,"OPNSSL_CRT_ERR",X509_STORE_CTX_get_error(store));

  if( X509_STORE_CTX_get_error(store) == X509_V_ERR_CERT_HAS_EXPIRED ){

  	if( !_rhp_cert_deny_expired_cert ){
      ok = 1;
    }

  	_rhp_cert_expired_cert = 1;

  	RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_VERIFY_CB_FROM_LIB_EXPIRED,"xdd",store,_rhp_cert_deny_expired_cert,ok);
  }

  return ok;
}

rhp_cert_store* rhp_cert_store_alloc(char* cert_store_path,unsigned long auth_realm_id,char* password)
{
	int err = -EINVAL;
  rhp_cert_store* cert_store = NULL;
  FILE* fp = NULL;
  rhp_cert_store_openssl_ctx* cert_store_ctx = NULL;
  EVP_PKEY* pkey = NULL;
  X509_STORE* store = NULL;
  STACK_OF(X509)* untrust_ca_certs_list = NULL;
  STACK_OF(X509)* trust_ca_certs_list = NULL;
  STACK_OF(X509_CRL)* crls_list = NULL;
  char* tmp_path = NULL;
  BIO* bio_ctx = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_ALLOC,"sus",cert_store_path,auth_realm_id,password);

  tmp_path = (char*)_rhp_malloc(strlen(cert_store_path) + RHP_CERT_STORE_OPENSSL_MAX_PATH + 2 );
  if( tmp_path == NULL ){
    RHP_BUG("");
    goto error;
  }

  cert_store = (rhp_cert_store*)_rhp_malloc(sizeof(rhp_cert_store));
  if( cert_store == NULL ){
    RHP_BUG("");
    goto error;
  }
  memset(cert_store,0,sizeof(rhp_cert_store));

  cert_store_ctx = (rhp_cert_store_openssl_ctx*)_rhp_malloc(sizeof(rhp_cert_store_openssl_ctx));
  if( cert_store_ctx == NULL ){
    RHP_BUG("");
    goto error;
  }
  memset(cert_store_ctx,0,sizeof(rhp_cert_store_openssl_ctx));

  cert_store->tag[0] = '#';
  cert_store->tag[1] = 'C';
  cert_store->tag[2] = 'T';
  cert_store->tag[3] = 'S';


  cert_store->cert_store_path = (char*)_rhp_malloc(strlen(cert_store_path)+1);
  if( cert_store->cert_store_path == NULL ){
    RHP_BUG("");
    goto error;
  }
  cert_store->cert_store_path[0] = '\0';
  strcpy(cert_store->cert_store_path,cert_store_path);


  cert_store_ctx->my_cert_file[0] = '\0';
  sprintf(cert_store_ctx->my_cert_file,"/my_cert_%lu.pem",auth_realm_id);
  cert_store_ctx->private_key_file[0] = '\0';
  sprintf(cert_store_ctx->private_key_file,"/my_priv_key_%lu.pem",auth_realm_id);
  cert_store_ctx->ca_certs_file[0] = '\0';
  sprintf(cert_store_ctx->ca_certs_file,"/ca_certs_%lu.pem",auth_realm_id);
  cert_store_ctx->crls_file[0] = '\0';
  sprintf(cert_store_ctx->crls_file,"/crl_%lu.pem",auth_realm_id);



  tmp_path[0] = '\0';
  strcpy(tmp_path,cert_store_path);
  strcat(tmp_path,cert_store_ctx->private_key_file);

  if( !(fp = fopen(tmp_path,"r")) ){

  	RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_ALLOC_PRIV_KEY_PATH_NOT_FOUND,"s",tmp_path);
  	cert_store->imcomplete++;

  	RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_LOAD_PRIV_KEY_NOT_FOUND,"us",auth_realm_id,cert_store_ctx->private_key_file);

  }else{

  	if( password ){
  		pkey = PEM_read_PrivateKey(fp,NULL,NULL,password);
  	}else{
  		pkey = PEM_read_PrivateKey(fp,NULL,NULL,"");
  	}
  	fclose(fp);

  	if( pkey == NULL ){

  		RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_ALLOC_READ_PRIVKEY_ERR,"ss",tmp_path,password);
  		cert_store->imcomplete++;

    	RHP_LOG_E(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_LOAD_PRIV_KEY_LOAD_ERR,"us",auth_realm_id,cert_store_ctx->private_key_file);

  	}else{

    	RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_PRIV_KEY_LOADED,"us",auth_realm_id,cert_store_ctx->private_key_file);
  	}
  }



  tmp_path[0] = '\0';
  strcpy(tmp_path,cert_store_path);
  strcat(tmp_path,cert_store_ctx->my_cert_file);

  bio_ctx = BIO_new_file(tmp_path, "r");
  if( bio_ctx == NULL ){

  	RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_ALLOC_MY_CERT_PATH_BIO_ERR,"s",tmp_path);
  	cert_store->imcomplete++;

  	RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_LOAD_MY_CERT_NOT_FOUND,"us",auth_realm_id,cert_store_ctx->my_cert_file);

  }else{

  	untrust_ca_certs_list = sk_X509_new_null();
    if( untrust_ca_certs_list == NULL ){
    	RHP_BUG("");
      goto error;
    }

		if( (err = _rhp_cert_store_openssl_load_certs_pem(bio_ctx,untrust_ca_certs_list,&(cert_store_ctx->my_crt),NULL,1)) ){

			RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_ALLOC_MY_CERT_PATH_LOAD_ERR,"s",tmp_path);

			RHP_LOG_E(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_LOAD_MY_CERT_LOAD_ERR,"usE",auth_realm_id,cert_store_ctx->my_cert_file,err);
			goto error;
		}

		BIO_free(bio_ctx);
		bio_ctx = NULL;
  }



  tmp_path[0] = '\0';
  strcpy(tmp_path,cert_store_path);
  strcat(tmp_path,cert_store_ctx->ca_certs_file);

  bio_ctx =  BIO_new_file(tmp_path, "r");
  if( bio_ctx == NULL ){

  	RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_ALLOC_CA_CERTS_PATH_BIO_ERR,"s",tmp_path);
  	cert_store->imcomplete++;

  	RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_LOAD_CA_CERTS_NOT_FOUND,"us",auth_realm_id,cert_store_ctx->ca_certs_file);

  }else{

  	trust_ca_certs_list = sk_X509_new_null();
		if( trust_ca_certs_list == NULL ){
			RHP_BUG("");
			goto error;
		}

		//
		// Why do we have to use X509_STORE?
		//  ANS) To use _rhp_cert_store_openssl_cert_verify_cb() for expired certs.
		//
		store = X509_STORE_new();
		if( store == NULL ){
			RHP_BUG("");
			goto error;
		}

		X509_STORE_set_verify_cb_func(store,_rhp_cert_store_openssl_cert_verify_cb);

		if( X509_STORE_load_locations(store,tmp_path,NULL) != 1 ){

			RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_LOAD_LOCATIONS_ERR,"s",tmp_path);

			RHP_LOG_E(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_LOAD_CA_CERTS_LOAD_ERR,"us",auth_realm_id,cert_store_ctx->ca_certs_file);
			goto error;
		}

		if( (err = _rhp_cert_store_openssl_load_certs_pem(bio_ctx,trust_ca_certs_list,
				NULL,&(cert_store_ctx->root_ca_crt),0)) ){

			RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_ALLOC_CA_CERTS_PATH_LOAD_ERR,"s",tmp_path);

			RHP_LOG_E(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_LOAD_CA_CERTS_LOAD_ERR_2,"usE",auth_realm_id,cert_store_ctx->ca_certs_file,err);
			goto error;
		}

		BIO_free(bio_ctx);
		bio_ctx = NULL;
  }



  tmp_path[0] = '\0';
  strcpy(tmp_path,cert_store_path);
  strcat(tmp_path,cert_store_ctx->crls_file);

  bio_ctx = BIO_new_file(tmp_path, "r");
  if( bio_ctx == NULL ){

  	RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_ALLOC_CRLS_PATH_BIO_ERR_OR_NOT_FOUND,"s",tmp_path);

  	RHP_LOG_D(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_LOAD_CRL_NOT_FOUND,"us",auth_realm_id,cert_store_ctx->crls_file);

  }else{

    crls_list = sk_X509_CRL_new_null();
    if( crls_list == NULL ){
    	RHP_BUG("");
      goto error;
    }

		err = _rhp_cert_store_openssl_load_crls_pem(bio_ctx,crls_list);
		if( err ){

			RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_ALLOC_CRLS_PATH_LOAD_ERR,"s",tmp_path);

			RHP_LOG_E(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_LOAD_CRL_LOAD_ERR,"usE",auth_realm_id,cert_store_ctx->crls_file,err);
			goto error;
		}

		BIO_free(bio_ctx);
		bio_ctx = NULL;
  }


  cert_store_ctx->auth_realm_id = auth_realm_id;

  cert_store_ctx->pkey_ctx = (void*)pkey;
  cert_store_ctx->store_ctx = (void*)store;

  cert_store_ctx->untrust_ca_crts = untrust_ca_certs_list;
  cert_store_ctx->trusted_ca_crts = trust_ca_certs_list;
  cert_store_ctx->crls_list = crls_list;

  cert_store->ctx = (void*)cert_store_ctx;

  cert_store->get_ca_public_key_digests = _rhp_cert_store_openssl_get_ca_public_key_digests;
  cert_store->get_ca_dn_ders = _rhp_cert_store_openssl_get_ca_dn_ders;
  cert_store->get_my_cert_issuer_dn_der = _rhp_cert_store_openssl_get_my_cert_issuer_dn_der;
  cert_store->get_untrust_sub_ca_issuer_dn_der = _rhp_cert_store_openssl_get_untrust_sub_ca_issuer_dn_der;
  cert_store->enum_DER_certs = _rhp_cert_store_openssl_enum_DER_certs;
  cert_store->sign = _rhp_cert_store_openssl_sign;
  cert_store->verify_signature = _rhp_cert_store_openssl_verify_signature;
  cert_store->get_my_cert_dn_der = _rhp_cert_store_openssl_get_my_cert_dn_der;
  cert_store->get_my_cert_dn_text = _rhp_cert_store_openssl_get_my_cert_dn_text;
  cert_store->get_my_cert_serialno_text = _rhp_cert_store_openssl_get_my_cert_serialno_text;
  cert_store->get_my_cert_subjectaltname = _rhp_cert_store_openssl_get_my_cert_subjectaltname;
  cert_store->get_my_cert_printed_text = _rhp_cert_store_openssl_get_my_cert_printed_text;
  cert_store->get_ca_certs_printed_text = _rhp_cert_store_openssl_get_ca_certs_printed_text;
  cert_store->get_crls_printed_text = _rhp_cert_store_openssl_get_crls_printed_text;
  cert_store->get_my_and_intermediate_ca_certs_printed_text = _rhp_cert_store_openssl_get_my_and_intermediate_ca_certs_printed_text;

  _rhp_atomic_init(&(cert_store->refcnt));
  _rhp_atomic_init(&(cert_store->is_active));

  _rhp_mutex_init("CRT",&(cert_store->lock));

  _rhp_atomic_set(&(cert_store->refcnt),1);
  _rhp_atomic_set(&(cert_store->is_active),1);

  _rhp_free(tmp_path);

  _rhp_cert_store_put(cert_store);

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_ALLOC_RTRN,"xd",cert_store,cert_store->imcomplete);
  return cert_store;

error:
  if( tmp_path ){
    _rhp_free(tmp_path);
  }
  if( pkey ){
    EVP_PKEY_free(pkey);
  }
  if( store ){
    X509_STORE_free(store);
  }
  if( bio_ctx ){
	BIO_free(bio_ctx);
  }
  if( untrust_ca_certs_list ){
  	sk_X509_free(untrust_ca_certs_list);
  }
  if( trust_ca_certs_list ){
  	sk_X509_free(trust_ca_certs_list);
  }
  if( crls_list ){
  	sk_X509_CRL_free(crls_list);
  }
  if( cert_store ){
    if( cert_store->cert_store_path ){
      _rhp_free(cert_store->cert_store_path);
    }
    _rhp_free(cert_store);
  }

	RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_ALLOC_CERT_STORE_ERR,"uE",auth_realm_id,err);

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_ALLOC_ERR,"x",cert_store);
  return NULL;
}


void rhp_cert_store_clear_resources(char* cert_store_path,unsigned long auth_realm_id)
{
	int err = -EINVAL;
  char* tmp_path = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_CLEAR_RESOURCES,"su",cert_store_path,auth_realm_id);

  tmp_path = (char*)_rhp_malloc(strlen(cert_store_path) + RHP_CERT_STORE_OPENSSL_MAX_PATH + 2 );
  if( tmp_path == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

  {
  	tmp_path[0] = '\0';
		sprintf(tmp_path,"%s/my_priv_key_%lu.pem",cert_store_path,auth_realm_id);

		if( (err = unlink(tmp_path)) ){
			RHP_BUG("%d",-errno);
		}
  }

  {
  	tmp_path[0] = '\0';
		sprintf(tmp_path,"%s/my_priv_key_%lu.old",cert_store_path,auth_realm_id);

		unlink(tmp_path);
  }

  {
  	tmp_path[0] = '\0';
		sprintf(tmp_path,"%s/my_cert_%lu.pem",cert_store_path,auth_realm_id);

		if( (err = unlink(tmp_path)) ){
			RHP_BUG("%d",-errno);
		}
  }

  {
  	tmp_path[0] = '\0';
		sprintf(tmp_path,"%s/my_cert_%lu.old",cert_store_path,auth_realm_id);

		if( (err = unlink(tmp_path)) ){
			RHP_BUG("%d",-errno);
		}
  }

  {
  	tmp_path[0] = '\0';
		sprintf(tmp_path,"%s/ca_certs_%lu.pem",cert_store_path,auth_realm_id);

		if( (err = unlink(tmp_path)) ){
			RHP_BUG("%d",-errno);
		}
  }

  {
  	tmp_path[0] = '\0';
		sprintf(tmp_path,"%s/ca_certs_%lu.old",cert_store_path,auth_realm_id);

		if( (err = unlink(tmp_path)) ){
			RHP_BUG("%d",-errno);
		}
  }

  {
  	tmp_path[0] = '\0';
		sprintf(tmp_path,"%s/crl_%lu.pem",cert_store_path,auth_realm_id);

		if( (err = unlink(tmp_path)) ){
			RHP_BUG("%d",-errno);
		}
  }

  {
  	tmp_path[0] = '\0';
		sprintf(tmp_path,"%s/crl_%lu.old",cert_store_path,auth_realm_id);

		if( (err = unlink(tmp_path)) ){
			RHP_BUG("%d",-errno);
		}
  }

  _rhp_free(tmp_path);

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_CLEAR_RESOURCES_RTRN,"su",cert_store_path,auth_realm_id);
  return;

error:
  if( tmp_path ){
    _rhp_free(tmp_path);
  }

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_CLEAR_RESOURCES_ERR,"suE",cert_store_path,auth_realm_id,err);
  return;
}

void rhp_cert_store_destroy(rhp_cert_store* cert_store)
{
  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_DESTROY,"xd",cert_store,cert_store->is_active.c);

  _rhp_cert_store_delete(cert_store);

  _rhp_atomic_set(&(cert_store->is_active),0);
}

static void _rhp_cert_store_free(rhp_cert_store* cert_store)
{
  rhp_cert_store_openssl_ctx* cert_store_ctx = (rhp_cert_store_openssl_ctx*)cert_store->ctx;
  unsigned long auth_realm_id = 0;

  if( cert_store_ctx ){

  	auth_realm_id = cert_store_ctx->auth_realm_id;

    if( cert_store_ctx->pkey_ctx ){
      EVP_PKEY_free(cert_store_ctx->pkey_ctx);
    }

    if( cert_store_ctx->store_ctx ){
      X509_STORE_free(cert_store_ctx->store_ctx);
    }

    if( cert_store_ctx->my_crt ){
    	X509_free(cert_store_ctx->my_crt);
    }

    if( cert_store_ctx->trusted_ca_crts ){
    	sk_X509_pop_free(cert_store_ctx->trusted_ca_crts, X509_free);
    }

    if( cert_store_ctx->untrust_ca_crts ){
    	sk_X509_pop_free(cert_store_ctx->untrust_ca_crts, X509_free);
    }

    if( cert_store_ctx->crls_list ){
    	sk_X509_CRL_pop_free(cert_store_ctx->crls_list, X509_CRL_free);
    }

    if( cert_store_ctx->ca_pubkey_digests_cache ){
      _rhp_free(cert_store_ctx->ca_pubkey_digests_cache);
    }

    if( cert_store_ctx->ca_dns_cache ){
      _rhp_free(cert_store_ctx->ca_dns_cache);
    }

    if( cert_store_ctx->my_crt_issuer_dn_cache ){
      _rhp_free(cert_store_ctx->my_crt_issuer_dn_cache);
    }

    _rhp_free(cert_store_ctx);
  }
  if( cert_store->cert_store_path ){
    _rhp_free(cert_store->cert_store_path);
  }
  _rhp_free(cert_store);

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_FREE,"xu",cert_store,auth_realm_id);
}

void rhp_cert_store_hold(rhp_cert_store* cert_store)
{
  _rhp_atomic_inc(&(cert_store->refcnt));
  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_HOLD,"xd",cert_store,cert_store->refcnt.c);
}

void rhp_cert_store_unhold(rhp_cert_store* cert_store)
{
  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_STORE_UNHOLD,"xd",cert_store,cert_store->refcnt.c);

  if( _rhp_atomic_dec_and_test(&(cert_store->refcnt)) ){

    if( cert_store->destructor ){
      cert_store->destructor(cert_store);
    }

    _rhp_cert_store_free(cert_store);
  }
}

static u32 _rhp_cert_store_disp_hash(void *key_seed,int* err)
{
  rhp_cert_ext_op* sign = (rhp_cert_ext_op*)key_seed;
  volatile int n,i;
  u32 hash = 0;
  u32* p;

  switch( sign->sign_op_type ){

    case RHP_CERT_SIGN_OP_SIGN:
    case RHP_CERT_SIGN_OP_SIGN_IKEV1:
    {
    	rhp_cert_sign_ctx* sign_ctx = (rhp_cert_sign_ctx*)sign;

      if( sign_ctx->mesg_octets_len < (int)sizeof(u32) ){
        *err = -EINVAL;
        RHP_BUG("");
        goto error;
      }

      RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DISP_HASH_OP_SIGN_MESG_OCTETS,"xp",key_seed,sign_ctx->mesg_octets_len,sign_ctx->mesg_octets);

      n = sign_ctx->mesg_octets_len / sizeof(u32);
      p = (u32*)sign_ctx->mesg_octets;
      for(i = 0; i < n; i++){
        hash ^= *p;
        p++;
      }

      RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DISP_HASH_OP_SIGN,"xdxp",key_seed,sign->sign_op_type,hash,sign_ctx->mesg_octets_len,sign_ctx->mesg_octets);
    }
      return hash;

    case RHP_CERT_SIGN_OP_VERIFY:
    case RHP_CERT_SIGN_OP_VERIFY_IKEV1:
    {
    	rhp_cert_sign_verify_ctx* verify_ctx = (rhp_cert_sign_verify_ctx*)sign;

      if( verify_ctx->signed_octets_len < (int)sizeof(u32) ){
        *err = -EINVAL;
        RHP_BUG("");
        goto error;
      }

      RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DISP_HASH_OP_VERIFY_SIGNED_OCTETS,"xp",key_seed,verify_ctx->signed_octets_len,verify_ctx->signed_octets);

      n = verify_ctx->signed_octets_len / sizeof(u32);
      p = (u32*)verify_ctx->signed_octets;
      for(i = 0; i < n; i++){
        hash ^= *p;
        p++;
      }

      RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DISP_HASH_OP_VERIFY,"xdx",key_seed,sign->sign_op_type,hash);
    }
      return hash;

    default:
      RHP_BUG("%d",sign->sign_op_type);
      *err = -EINVAL;
      break;
  }

error:
  return 0;
}

static int _rhp_cert_dn_openssl_DER_encode(rhp_cert_dn* cert_dn,u8** der,int* der_len)
{
  X509_NAME* name = (X509_NAME*)cert_dn->ctx;
  u8* p = NULL;
  int p_len = 0;

  p_len = i2d_X509_NAME(name,NULL);
  if( p_len < 0 ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DER_ENCODE_PARSE_ERR,"xxx",cert_dn,der,der_len);
    return -EINVAL;
  }

  p = (u8*)_rhp_malloc(p_len);
  if( p == NULL ){
  	RHP_BUG("");
  	return -ENOMEM;
  }

  i2d_X509_NAME(name,&p);

  *der = (p - p_len);
  *der_len = p_len;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DER_ENCODE,"xp",cert_dn,*der_len,*der);
  return 0;
}

static int _rhp_cert_dn_openssl_cmp_rdn(X509_NAME_ENTRY *rdn0,X509_NAME_ENTRY *rdn1)
{
  ASN1_STRING *rdn0_value, *rdn1_value;
  ASN1_OBJECT *rdn0_object, *rdn1_object;

  rdn0_value = X509_NAME_ENTRY_get_data(rdn0);
  rdn1_value = X509_NAME_ENTRY_get_data(rdn1);
  if (rdn0_value == NULL || rdn1_value == NULL)
      return -1;

  rdn0_object = X509_NAME_ENTRY_get_object(rdn0);
  rdn1_object = X509_NAME_ENTRY_get_object(rdn1);
  if (rdn0_object == NULL || rdn1_object == NULL)
      return -1;

  if( rdn0_value->type != rdn1_value->type ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_CMP_RDN_NOT_MATCHED1,"xdxd",rdn0,rdn0_value->type,rdn1,rdn1_value->type);
    return -1;
  }

  if( ASN1_STRING_type(rdn0_value) != V_ASN1_TELETEXSTRING &&
      ASN1_STRING_type(rdn0_value) != V_ASN1_PRINTABLESTRING &&
      ASN1_STRING_type(rdn0_value) != V_ASN1_UNIVERSALSTRING &&
      ASN1_STRING_type(rdn0_value) != V_ASN1_UTF8STRING &&
      ASN1_STRING_type(rdn0_value) != V_ASN1_BMPSTRING &&
      ASN1_STRING_type(rdn0_value) != V_ASN1_IA5STRING ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_CMP_RDN_NOT_MATCHED2,"xd",rdn0,ASN1_STRING_type(rdn0_value));
    return -1;
  }

  if( ASN1_STRING_type(rdn1_value) != V_ASN1_TELETEXSTRING &&
      ASN1_STRING_type(rdn1_value) != V_ASN1_PRINTABLESTRING &&
      ASN1_STRING_type(rdn1_value) != V_ASN1_UNIVERSALSTRING &&
      ASN1_STRING_type(rdn1_value) != V_ASN1_UTF8STRING &&
      ASN1_STRING_type(rdn1_value) != V_ASN1_BMPSTRING &&
      ASN1_STRING_type(rdn1_value) != V_ASN1_IA5STRING ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_CMP_RDN_NOT_MATCHED3,"xd",rdn1,ASN1_STRING_type(rdn1_value));
    return -1;
  }

// TODO
//  if( rdn0->set != rdn1->set ){
//    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_CMP_RDN_NOT_MATCHED4,"xdxd",rdn0,rdn0->set,rdn1,rdn1->set);
//    return -1;
//  }

  if( ASN1_STRING_length(rdn0_value) != ASN1_STRING_length(rdn1_value)){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_CMP_RDN_NOT_MATCHED5,"xdxd",rdn0,ASN1_STRING_length(rdn0_value),rdn1,ASN1_STRING_length(rdn1_value));
    return -1;
  }

  if( memcmp(ASN1_STRING_get0_data(rdn0_value),ASN1_STRING_get0_data(rdn1_value),ASN1_STRING_length(rdn0_value)) ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_CMP_RDN_NOT_MATCHED6,"xpxp",rdn0,ASN1_STRING_length(rdn0_value),ASN1_STRING_get0_data(rdn0_value),rdn1,ASN1_STRING_length(rdn1_value),ASN1_STRING_get0_data(rdn1_value));
    return -1;
  }

  if( OBJ_cmp(rdn0_object,rdn1_object) ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_CMP_RDN_NOT_MATCHED7,"xx",rdn0,rdn1);
    return -1;
  }

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_CMP_RDN_MATCHED,"xx",rdn0,rdn1);
  return 0;
}

static int _rhp_cert_dn_openssl_contains_rdns(rhp_cert_dn* cert_dn,rhp_cert_dn* rdns)
{
  X509_NAME* name0 = (X509_NAME*)cert_dn->ctx;
  X509_NAME* name1 = (X509_NAME*)rdns->ctx;
  X509_NAME_ENTRY *rdn0 = NULL,*rdn1 = NULL;
  int i;
  int rdn0_num = 0,rdn1_num = 0;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_CONTAINS_RDNS,"xx",cert_dn,rdns);

  rdn0_num = X509_NAME_entry_count(name0);
  rdn1_num = X509_NAME_entry_count(name1);


  if( rdn0_num < 1 || rdn1_num < 1 ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_CONTAINS_RDNS_NOT_MATCHED1,"xdd",cert_dn,rdn0_num,rdn1_num);
    return -1;
  }

  if( rdn0_num < rdn1_num ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_CONTAINS_RDNS_NOT_MATCHED2,"xdd",cert_dn,rdn0_num,rdn1_num);
    return -1;
  }

  for( i = 0; i < rdn1_num; i++ ){

    rdn0 = X509_NAME_get_entry(name0,i);
    rdn1 = X509_NAME_get_entry(name1,i);

    if( _rhp_cert_dn_openssl_cmp_rdn(rdn0,rdn1) ){
      break;
    }
  }

  if( i == rdn1_num ){
  	RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_CONTAINS_RDNS_MATCHED,"x",cert_dn);
    return 0;
  }

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_CONTAINS_RDNS_NOT_MATCHED3,"x",cert_dn);
  return -1;
}

static int _rhp_cert_dn_openssl_compare(rhp_cert_dn* cert_dn0,struct _rhp_cert_dn* cert_dn1)
{
  int ret;
  X509_NAME* name0 = (X509_NAME*)cert_dn0->ctx;
  X509_NAME* name1 = (X509_NAME*)cert_dn1->ctx;

  ret = X509_NAME_cmp(name0,name1);

	_RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
  if( _RHP_TRC_COND(_rhp_trc_user_id(),0) ){

  	char *str0 = cert_dn0->to_text(cert_dn0);
  	char *str1 = cert_dn1->to_text(cert_dn1);

  	RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_COMPARE,"xxssd",cert_dn0,cert_dn1,str0,str1,ret);
  	if(str0){
  		_rhp_free(str0);
  	}
  	if(str1){
  		_rhp_free(str1);
  	}
  }
  return ret;
}

static void _rhp_cert_dn_openssl_destructor(rhp_cert_dn* cert_dn)
{
  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_DESTRUCTOR,"x",cert_dn);
  return;
}

static char* _rhp_cert_dn_openssl_to_text(rhp_cert_dn* cert_dn)
{
  char* ret = _rhp_X509_NAME_oneline2((X509_NAME*)cert_dn->ctx);
  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_TO_TEXT,"xxxs",cert_dn,cert_dn->ctx,ret,ret);
  return ret;
}

static rhp_cert_dn* _rhp_cert_dn_alloc(X509_NAME* name,int ctx_shared)
{
  rhp_cert_dn* cert_dn = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_ALLOC,"xd",name,ctx_shared);

  cert_dn = (rhp_cert_dn*)_rhp_malloc(sizeof(rhp_cert_dn));
  if( cert_dn == NULL ){
	RHP_BUG("");
    return NULL;
  }

  memset(cert_dn,0,sizeof(rhp_cert_dn));

  cert_dn->tag[0] = '#';
  cert_dn->tag[1] = 'C';
  cert_dn->tag[2] = 'T';
  cert_dn->tag[3] = 'N';

  cert_dn->ctx = (void*)name;
  cert_dn->DER_encode = _rhp_cert_dn_openssl_DER_encode;
  cert_dn->contains_rdns = _rhp_cert_dn_openssl_contains_rdns;
  cert_dn->compare = _rhp_cert_dn_openssl_compare;
  cert_dn->to_text = _rhp_cert_dn_openssl_to_text;
  cert_dn->destructor = _rhp_cert_dn_openssl_destructor;
  cert_dn->ctx_shared = ctx_shared;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_ALLOC_RTRN,"xx",name,cert_dn);
  return cert_dn;
}


rhp_cert_dn* rhp_cert_dn_alloc_by_DER(u8* der,int der_len)
{
  rhp_cert_dn* cert_dn = NULL;
  X509_NAME* name = NULL;
  unsigned char* p = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_ALLOC_BY_DER,"p",der_len,der);

  p = der;
  if( !d2i_X509_NAME(&name,(const unsigned char**)&p,der_len) ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_ALLOC_BY_DER_PARSE_ERR,"x",der);
    goto error;
  }

  cert_dn = _rhp_cert_dn_alloc(name,0);
  if( cert_dn == NULL ){
    RHP_BUG("");
    goto error;
  }

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_ALLOC_BY_DER_RTRN,"xx",der,cert_dn);
  return cert_dn;

error:
  if( name ){
    X509_NAME_free(name);
  }
  if( cert_dn ){
    _rhp_free(cert_dn);
  }
  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_ALLOC_BY_DER_ERR,"x",der);
  return NULL;
}

struct _rhp_cert_dn_rdn_tmp {
  struct _rhp_cert_dn_rdn_tmp* next;
  char* type_start;
  char* type_end;
  char* value_start;
  char* value_end;
};
typedef struct _rhp_cert_dn_rdn_tmp rhp_cert_dn_rdn_tmp;

#define RHP_CERT_DN_SEARCH_RDN_TYPE     0
#define RHP_CERT_DN_PARSE_RDN_TYPE      1
#define RHP_CERT_DN_SEARCH_RDN_VALUE    2
#define RHP_CERT_DN_PARSE_RDN_VALUE     3

// Only basic format is supported. Such as Multivalued RDN('+') , Hex format('#')
// or OID format is NOT supported. And supported encoding is UTF8 only.
rhp_cert_dn* rhp_cert_dn_alloc_by_text(char* dn/*Don't be const string!*/)
{
  char *p,*sp_p = NULL;
  rhp_cert_dn_rdn_tmp *rdns_head = NULL,*rdns_tail = NULL;
  rhp_cert_dn_rdn_tmp* rdn_p = NULL;
  int esc = 0;
  int state = RHP_CERT_DN_SEARCH_RDN_TYPE;
  X509_NAME* name = NULL;
  rhp_cert_dn* cert_dn = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_ALLOC_BY_TEXT,"s",dn);

  p = dn;
  while( *p != '\0' ){

    if( *p == ' ' || *p == '\r' ){

      if( state == RHP_CERT_DN_SEARCH_RDN_TYPE ){

        p++;

      }else if( state == RHP_CERT_DN_PARSE_RDN_TYPE ){

        if( sp_p == NULL ){
          sp_p = p;
        }
        p++;

      }else if( state == RHP_CERT_DN_SEARCH_RDN_VALUE ){

        p++;

      }else if( state == RHP_CERT_DN_PARSE_RDN_VALUE ){

        if( sp_p == NULL ){
          sp_p = p;
        }
        p++;

      }else{
   	    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_ALLOC_BY_TEXT_ERR1,"s",dn);
        goto error;
      }

    }else if( *p == '=' ){

      if( esc ){

        if( state == RHP_CERT_DN_PARSE_RDN_TYPE ){
          esc = 0;
          p++;
        }else if( state == RHP_CERT_DN_PARSE_RDN_VALUE ){
          esc = 0;
          p++;
        }else{
   	      RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_ALLOC_BY_TEXT_ERR2,"s",dn);
          goto error;
        }

      }else{

        if( state == RHP_CERT_DN_PARSE_RDN_TYPE ){

          if( sp_p ){
            rdn_p->type_end = sp_p - 1;
          }else{
            rdn_p->type_end = p - 1;
          }
          sp_p = NULL;
          state = RHP_CERT_DN_SEARCH_RDN_VALUE;
          p++;

        }else{
   	      RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_ALLOC_BY_TEXT_ERR3,"s",dn);
          goto error;
        }
      }

    }else if( (*p == ',') ||  (*p == ';') || (*p == '/') ){

      if( esc ){

        if( state == RHP_CERT_DN_PARSE_RDN_TYPE ){
          esc = 0;
          p++;
        }else if( state == RHP_CERT_DN_PARSE_RDN_VALUE ){
          esc = 0;
          p++;
        }else{
       	  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_ALLOC_BY_TEXT_ERR4,"s",dn);
          goto error;
        }

      }else{

        if( state == RHP_CERT_DN_PARSE_RDN_VALUE ){

          if( sp_p ){
            rdn_p->value_end = sp_p - 1;
          }else{
            rdn_p->value_end = p - 1;
          }
          sp_p = NULL;
          state = RHP_CERT_DN_SEARCH_RDN_TYPE;

          if( rdns_head == NULL ){
            rdns_head = rdn_p;
            rdns_tail = rdn_p;
          }else{
            rdns_tail->next = rdn_p;
            rdns_tail = rdn_p;
          }
          rdn_p = NULL;

          p++;

        }else{
       	  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_ALLOC_BY_TEXT_ERR5,"s",dn);
          goto error;
        }
      }

    }else if( *p == '\\' ){

      if( esc ){

        if( state == RHP_CERT_DN_PARSE_RDN_TYPE ){
          esc = 0;
          p++;
        }else if( state == RHP_CERT_DN_PARSE_RDN_VALUE ){
          esc = 0;
          p++;
        }else{
       	  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_ALLOC_BY_TEXT_ERR6,"s",dn);
          goto error;
        }

      }else{

        if( state == RHP_CERT_DN_PARSE_RDN_TYPE ){
          esc = 1;
          p++;
        }else if( state == RHP_CERT_DN_PARSE_RDN_VALUE ){
          esc = 1;
          p++;
        }else{
       	  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_ALLOC_BY_TEXT_ERR7,"s",dn);
          goto error;
        }
      }

    }else{

      if( esc ){
       	RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_ALLOC_BY_TEXT_ERR8,"s",dn);
        goto error;
      }

      if( state == RHP_CERT_DN_SEARCH_RDN_TYPE ){

        rdn_p = (rhp_cert_dn_rdn_tmp*)_rhp_malloc(sizeof(rhp_cert_dn_rdn_tmp));
        if( rdn_p == NULL ){
          RHP_BUG("");
          goto error;
        }
        memset(rdn_p,0,sizeof(rhp_cert_dn_rdn_tmp));

        rdn_p->type_start = p;
        state = RHP_CERT_DN_PARSE_RDN_TYPE;
        p++;

      }else if( state == RHP_CERT_DN_PARSE_RDN_TYPE  ){

        sp_p = NULL;
        p++;

      }else if( state == RHP_CERT_DN_SEARCH_RDN_VALUE  ){

        rdn_p->value_start = p;
        state = RHP_CERT_DN_PARSE_RDN_VALUE;
        p++;

      }else if( state == RHP_CERT_DN_PARSE_RDN_VALUE  ){

        sp_p = NULL;
        p++;

      }else{
     	RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_ALLOC_BY_TEXT_ERR9,"s",dn);
        goto error;
      }
    }
  }

  if( rdn_p ){

    if( state != RHP_CERT_DN_PARSE_RDN_VALUE ){
      RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_ALLOC_BY_TEXT_ERR10,"s",dn);
      goto error;
    }

    if( sp_p ){
      rdn_p->value_end = sp_p - 1;
    }else{
      rdn_p->value_end = p - 1;
    }

    if( rdns_head == NULL ){
      rdns_head = rdn_p;
      rdns_tail = rdn_p;
    }else{
      rdns_tail->next = rdn_p;
      rdns_tail = rdn_p;
    }
    rdn_p = NULL;
  }

  if( rdns_head == NULL ){
   	RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_ALLOC_BY_TEXT_ERR11,"s",dn);
    goto error;
  }

  name = X509_NAME_new();
  if (name == NULL){
	RHP_BUG("");
    goto error;
  }

  rdn_p = rdns_head;
  while( rdn_p ){

    char t,v;
    rhp_cert_dn_rdn_tmp* rdn2_p = rdn_p->next;

    t = *(rdn_p->type_end+1);
    v = *(rdn_p->value_end+1);

    *(rdn_p->type_end+1) = '\0';
    *(rdn_p->value_end+1) = '\0';

    if( !X509_NAME_add_entry_by_txt(name, (const char*)rdn_p->type_start,
    		MBSTRING_UTF8,(const unsigned char*)rdn_p->value_start, -1, -1, 0) ){

    	*(rdn_p->type_end+1) = t;
     *(rdn_p->value_end+1) = v;

     while( rdn_p ){
    	 rdn2_p = rdn_p->next;
    	 _rhp_free(rdn_p);
    	 rdn_p = rdn2_p;
     }
     rdns_head = NULL;

     RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_ALLOC_BY_TEXT_ERR12,"s",dn);
     goto error2;
    }

    *(rdn_p->type_end+1) = t;
    *(rdn_p->value_end+1) = v;

    _rhp_free(rdn_p);
    rdn_p = rdn2_p;
  }

  rdns_head = NULL;

  cert_dn = _rhp_cert_dn_alloc(name,0);
  if( cert_dn == NULL ){
    RHP_BUG("");
    goto error;
  }

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_ALLOC_BY_TEXT_RTRN,"sx",dn,cert_dn);
  return cert_dn;

error:
  rdn_p = rdns_head;
  while( rdn_p ){
    rhp_cert_dn_rdn_tmp* rdn2_p = rdn_p->next;
    _rhp_free(rdn_p);
    rdn_p = rdn2_p;
  }
error2:
  if( name ){
    X509_NAME_free(name);
  }
  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_ALLOC_BY_TEXT_ERR,"s",dn);
  return NULL;
}

void rhp_cert_dn_free(rhp_cert_dn* cert_dn)
{
  if( cert_dn->destructor ){
    cert_dn->destructor(cert_dn);
  }

  if( !cert_dn->ctx_shared && cert_dn->ctx ){
    X509_NAME_free((X509_NAME*)cert_dn->ctx);
  }
  _rhp_free(cert_dn);
  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DN_FREE,"x",cert_dn);
}

static rhp_cert_dn* _rhp_cert_openssl_get_cert_dn(rhp_cert* cert)
{
  rhp_cert_openssl_ctx* cert_ctx = (rhp_cert_openssl_ctx*)cert->ctx;
  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_GET_CERT_DN,"xx",cert,cert_ctx->cert_dn);
  return cert_ctx->cert_dn;
}

static int _rhp_cert_openssl_get_cert_subjectaltname(rhp_cert* cert,char** altname,int* altname_len,int* altname_type)
{
  rhp_cert_openssl_ctx* cert_ctx = (rhp_cert_openssl_ctx*)cert->ctx;

  if( cert_ctx->altname == NULL ){
	RHP_TRC(0,RHPTRCID_OPENSSL_CERT_GET_SUBJECTNAME_NO_SUBJECTNAME,"x",cert);
    return -ENOENT;
  }

  *altname = cert_ctx->altname;
  *altname_len = cert_ctx->altname_len;
  *altname_type = cert_ctx->altname_type;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_GET_SUBJECTNAME,"xdds",cert,*altname_type,*altname_len,*altname);
  return 0;
}

static void _rhp_cert_openssl_destructor(rhp_cert* cert)
{
  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DESTRUCTOR,"x",cert);
  return;
}

rhp_cert* rhp_cert_alloc(u8* der,int der_len)
{
  rhp_cert* cert = NULL;
  rhp_cert_openssl_ctx* cert_ctx = NULL;
  u8* next = NULL;
  X509_NAME* dn = NULL;
  int err;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_ALLOC,"p",der_len,der);

  cert = (rhp_cert*)_rhp_malloc(sizeof(rhp_cert));
  if( cert == NULL ){
  	RHP_BUG("");
    goto error;
  }
  memset(cert,0,sizeof(rhp_cert));

  cert_ctx = (rhp_cert_openssl_ctx*)_rhp_malloc(sizeof(rhp_cert_openssl_ctx));
  if( cert_ctx == NULL ){
	RHP_BUG("");
    goto error;
  }
  memset(cert_ctx,0,sizeof(rhp_cert_openssl_ctx));

  cert->ctx = (void*)cert_ctx;

  cert->tag[0] = '#';
  cert->tag[1] = 'C';
  cert->tag[2] = 'R';
  cert->tag[3] = 'T';

  next = der;
  cert_ctx->cert_impl = d2i_X509(NULL,(const unsigned char**)&next,der_len);
  if( cert_ctx->cert_impl == NULL ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_ALLOC_PARSE_ERR,"x",der);
    goto error;
  }

  dn = X509_get_subject_name(cert_ctx->cert_impl);
  if( dn ){
    cert_ctx->cert_dn = _rhp_cert_dn_alloc(dn,1);
    if( cert_ctx->cert_dn == NULL ){
      goto error;
    }
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_ALLOC_SUBJECTNAME,"xxx",der,cert,cert_ctx->cert_dn);
  }else{
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_ALLOC_NO_SUBJECTNAME,"xx",der,cert);
  }

  err = _rhp_cert_openssl_get_cert_subjectaltname_impl(cert_ctx->cert_impl,&(cert_ctx->altname),
        &(cert_ctx->altname_len),&(cert_ctx->altname_type));

  if( err == -ENOENT ){
    err = 0;
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_ALLOC_NO_SUBJECTALTNAME,"xx",der,cert);
  }else if( err ){
    RHP_TRC(0,RHPTRCID_OPENSSL_CERT_ALLOC_GET_SUBJECTALTNAME_ERR,"xxE",der,cert,err);
    goto error;
  }

  cert->get_cert_dn = _rhp_cert_openssl_get_cert_dn;
  cert->get_cert_subjectaltname = _rhp_cert_openssl_get_cert_subjectaltname;
  cert->destructor = _rhp_cert_openssl_destructor;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_ALLOC_RTRN,"xx",der,cert);
  return cert;

error:
  if( cert ){
    rhp_cert_free(cert);
  }
  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_ALLOC_ERR,"x",der);
  return NULL;
}

void rhp_cert_free(rhp_cert* cert)
{
  rhp_cert_openssl_ctx* cert_ctx = (rhp_cert_openssl_ctx*)cert->ctx;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_FREE,"xx",cert,cert_ctx);

  if( cert->destructor ){
    cert->destructor(cert);
  }

  if( cert_ctx ){
    if( cert_ctx->cert_dn ){
      cert_ctx->cert_dn->ctx = NULL;
      rhp_cert_dn_free(cert_ctx->cert_dn);
    }
    if( cert_ctx->cert_impl ){
      X509_free(cert_ctx->cert_impl);
    }
    if( cert_ctx->altname ){
      _rhp_free(cert_ctx->altname);
    }
    _rhp_free(cert_ctx);
  }
  _rhp_free(cert);

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_FREE_RTRN,"xx",cert,cert_ctx);
}


void rhp_cert_X509_pem_print(rhp_cert* cert)
{
  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_X509_PEM_PRINT,"x",cert);
	PEM_ASN1_write((int (*)())i2d_X509,PEM_STRING_X509,stdout,(char*)cert->ctx, NULL,NULL,0,NULL,NULL);
}

void rhp_cert_X509_NAME_pem_print(rhp_cert_dn* cert_dn)
{
  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_X509_NAME_PEM_PRINT,"x",cert_dn);
	PEM_ASN1_write((int (*)())i2d_X509_NAME,PEM_STRING_X509,stdout,(char*)cert_dn->ctx, NULL,NULL,0,NULL,NULL);
}

void rhp_cert_X509_print(rhp_cert* cert)
{
  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_X509_PRINT,"x",cert);
	X509_print_ex_fp(stdout,cert->ctx,0,0);
}

void rhp_cert_X509_NAME_print(rhp_cert_dn* cert_dn)
{
  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_X509_NAME_PRINT,"x",cert_dn);
	X509_NAME_print_ex_fp(stdout,cert_dn->ctx,0,0);
}


static int _rhp_cert_recover_file(char* cert_store_file_path)
{
	int err = -EINVAL;
	char* sfx_p = NULL;
	int path_len = 0,wk_path_len = 0;
	int i;
	char* wk_file_path = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_RECOVER_FILE,"s",cert_store_file_path);

	path_len = strlen(cert_store_file_path) + 1;
	sfx_p = (cert_store_file_path + path_len - 1);

	for( i = path_len; i > 0; i--){
		if( *sfx_p == '.' ){
			break;
		}
		sfx_p--;
	}

	wk_path_len = path_len + strlen(".old");

	wk_file_path = (char*)_rhp_malloc(wk_path_len);
	if( wk_file_path == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}
	memset(wk_file_path,'\0',wk_path_len);
	memcpy(wk_file_path,cert_store_file_path,(sfx_p - cert_store_file_path));
	memcpy((wk_file_path + (sfx_p - cert_store_file_path)),".old",strlen(".old"));

	if( rename(wk_file_path,cert_store_file_path) < 0 ){
		err = -errno;
	  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_RECOVER_FILE_RENAME_ERR,"ssE",wk_file_path,cert_store_file_path,err);
		goto error;
	}

	_rhp_free(wk_file_path);

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_RECOVER_FILE_RTRN,"s",cert_store_file_path);
	return 0;

error:
	if( wk_file_path ){
		_rhp_free(wk_file_path);
	}
  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_RECOVER_FILE_ERR,"sE",cert_store_file_path,err);
	return err;
}

static int _rhp_cert_rename_file(char* config_file_path,int also_tmp)
{
	int err = -EINVAL;
	char* sfx_p = NULL;
	int path_len = 0,wk_path_len = 0;
	int i;
	char* wk_file_path = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_RENAME_FILE,"sd",config_file_path,also_tmp);

	path_len = strlen(config_file_path) + 1;
	sfx_p = (config_file_path + path_len - 1);

	for( i = path_len; i > 0; i--){
		if( *sfx_p == '.' ){
			break;
		}
		sfx_p--;
	}

	wk_path_len = path_len + strlen(".old");

	wk_file_path = (char*)_rhp_malloc(wk_path_len);
	if( wk_file_path == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}
	memset(wk_file_path,'\0',wk_path_len);
	memcpy(wk_file_path,config_file_path,(sfx_p - config_file_path));

	memcpy((wk_file_path + (sfx_p - config_file_path)),".old",strlen(".old"));

	if( rename(config_file_path,wk_file_path) < 0 ){

		err = -errno;
	  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_RENAME_FILE_RENAME_ERR,"ssE",config_file_path,wk_file_path,err);

	  if( err != -ENOENT ){
	  	RHP_BUG("");
			goto error;
		}
	}

	if( also_tmp ){

		memcpy((wk_file_path + (sfx_p - config_file_path)),".tmp",strlen(".tmp"));

		if( rename(wk_file_path,config_file_path) < 0 ){
			err = -errno;
		  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_RENAME_FILE_RENAME_ERR2,"ssE",config_file_path,wk_file_path,err);
			goto error;
		}
	}

	_rhp_free(wk_file_path);
  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_RENAME_RTRN,"s",config_file_path);
	return 0;

error:
	if( wk_file_path ){
		_rhp_free(wk_file_path);
	}
  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_RENAME_ERR,"sE",config_file_path,err);
	return err;
}

static int _rhp_cert_write_tmp_file(char* cert_store_file_path,int cont_len,u8* cont)
{
	int err = -EINVAL;
	int fd = -1;
	u8* pt = cont;
	int n = cont_len;
	char* sfx_p;
	int path_len = 0,wk_path_len = 0;
	int i;
	char* wk_file_path = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_WRITE_TMP_FILE,"sp",cert_store_file_path,cont_len,cont);

	path_len = strlen(cert_store_file_path) + 1;
	sfx_p = (cert_store_file_path + path_len - 1);

	for( i = path_len; i > 0; i--){
		if( *sfx_p == '.' ){
			break;
		}
		sfx_p--;
	}

	wk_path_len = path_len + strlen(".tmp");

	wk_file_path = (char*)_rhp_malloc(wk_path_len);
	if( wk_file_path == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}
	memset(wk_file_path,'\0',wk_path_len);
	memcpy(wk_file_path,cert_store_file_path,(sfx_p - cert_store_file_path));
	memcpy((wk_file_path + (sfx_p - cert_store_file_path)),".tmp",strlen(".tmp"));


	fd = open(wk_file_path,(O_WRONLY | O_CREAT | O_TRUNC),S_IRWXU);
	if( fd < 0 ){
		err = -errno;
		RHP_BUG("%d",err);
	  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_WRITE_TMP_FILE_OPEN_ERR,"ssE",cert_store_file_path,wk_file_path,err);
		goto error;
	}

	while( n > 0 ){

		int c = write(fd,pt,n);
		if( c < 0 ){
			err = -errno;
			RHP_BUG("%d",err);
		  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_WRITE_TMP_FILE_WRITE_ERR,"ssE",cert_store_file_path,wk_file_path,err);
			goto error;
		}

		n -= c;
		pt += c;
	}

	close(fd);
	_rhp_free(wk_file_path);

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_WRITE_TMP_FILE_RTRN,"sx",cert_store_file_path,cont);
	return 0;

error:
	if( fd > -1 ){
		close(fd);
	}
	if( wk_file_path ){
		_rhp_free(wk_file_path);
	}
  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_WRITE_TMP_FILE_ERR,"sxE",cert_store_file_path,cont,err);
	return err;
}

#define RHP_CERT_UPADTE_MY_CERT						1
#define RHP_CERT_UPADTE_MY_PRIVATE_KEY		2
#define RHP_CERT_UPADTE_CA_CERTS					4
#define RHP_CERT_UPADTE_CRL								8

static int _rhp_cert_update_impl(unsigned long auth_realm_id,u8 flag,
		int my_cert_cont_len,u8* my_cert_cont,
		int my_privkey_cont_len,u8* my_privkey_cont,
		int certs_cont_len,u8* certs_cont,
		char* password,
		char* cert_store_path,rhp_cert_store** cert_store_r)
{
	int err = -EINVAL;
	char* path = NULL;
	int cert_store_path_len = strlen(cert_store_path);
	rhp_cert_store* new_cert_store = NULL;

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_UPDATE,"ubpppssx",auth_realm_id,flag,my_cert_cont_len,my_cert_cont,my_privkey_cont_len,my_privkey_cont,certs_cont_len,certs_cont,password,cert_store_path,cert_store_r);

	path = (char*)_rhp_malloc(cert_store_path_len + RHP_CERT_STORE_OPENSSL_MAX_PATH + 2);
	if( path == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error_no_rcv;
	}

	path[0] = '\0';
	strcpy(path,cert_store_path);

	if( my_cert_cont ){

		sprintf((path + cert_store_path_len),"/my_cert_%lu.pem",auth_realm_id);

		err = _rhp_cert_write_tmp_file(path,my_cert_cont_len,my_cert_cont);
		if( err ){
			RHP_BUG("%d",err);
			goto error_no_rcv;
		}
	}

	if( my_privkey_cont ){

		sprintf((path + cert_store_path_len),"/my_priv_key_%lu.pem",auth_realm_id);

		err = _rhp_cert_write_tmp_file(path,my_privkey_cont_len,my_privkey_cont);
		if( err ){
			RHP_BUG("%d",err);
			goto error_no_rcv;
		}
	}

	if( certs_cont ){

	  sprintf((path + cert_store_path_len),"/ca_certs_%lu.pem",auth_realm_id);

		err = _rhp_cert_write_tmp_file(path,certs_cont_len,certs_cont);
		if( err ){
			RHP_BUG("%d",err);
			goto error_no_rcv;
		}
	}



	if( (flag & RHP_CERT_UPADTE_MY_CERT) || my_cert_cont ){

		sprintf((path + cert_store_path_len),"/my_cert_%lu.pem",auth_realm_id);

		err = _rhp_cert_rename_file(path,1);
		if( err ){
			RHP_BUG("%d",err);
			goto error_no_rcv;
		}
	}

	if( (flag & RHP_CERT_UPADTE_MY_PRIVATE_KEY) || my_privkey_cont ){

		sprintf((path + cert_store_path_len),"/my_priv_key_%lu.pem",auth_realm_id);

		err = _rhp_cert_rename_file(path,1);
		if( err ){

			RHP_BUG("%d",err);

			{
				sprintf((path + cert_store_path_len),"/my_cert_%lu.pem",auth_realm_id);
				_rhp_cert_recover_file(path);
			}

			goto error_no_rcv;
		}
	}

	if( (flag & RHP_CERT_UPADTE_CA_CERTS) || certs_cont ){

	  sprintf((path + cert_store_path_len),"/ca_certs_%lu.pem",auth_realm_id);

		err = _rhp_cert_rename_file(path,1);
		if( err  && err != -ENOENT ){

			RHP_BUG("%d",err);

			{
				sprintf((path + cert_store_path_len),"/my_cert_%lu.pem",auth_realm_id);
				_rhp_cert_recover_file(path);
				sprintf((path + cert_store_path_len),"/my_priv_key_%lu.pem",auth_realm_id);
				_rhp_cert_recover_file(path);
			}

			goto error_no_rcv;
		}
		err = 0;
	}

	if( flag & RHP_CERT_UPADTE_CRL ){

	  sprintf((path + cert_store_path_len),"/crl_%lu.pem",auth_realm_id);

		err = _rhp_cert_rename_file(path,1);
		if( err  && err != -ENOENT ){

			RHP_BUG("%d",err);

			{
				sprintf((path + cert_store_path_len),"/my_cert_%lu.pem",auth_realm_id);
				_rhp_cert_recover_file(path);
				sprintf((path + cert_store_path_len),"/my_priv_key_%lu.pem",auth_realm_id);
				_rhp_cert_recover_file(path);
				sprintf((path + cert_store_path_len),"/ca_certs_%lu.pem",auth_realm_id);
				_rhp_cert_recover_file(path);
			}

			goto error_no_rcv;
		}
		err = 0;
	}


	 new_cert_store = rhp_cert_store_alloc(cert_store_path,auth_realm_id,password);
	 if( new_cert_store == NULL ){
		  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_UPDATE_FAIL_TO_ALLOC_CERT_STORE,"uxxx",auth_realm_id,my_cert_cont,my_privkey_cont,certs_cont);
		 err = -EINVAL;
		 goto error;
	 }

	 if( cert_store_r ){

		 if( *cert_store_r ){
			 rhp_cert_store_destroy(*cert_store_r);
		 }

		 *cert_store_r = new_cert_store;

	 }else{

			rhp_cert_store_destroy(new_cert_store);
			new_cert_store = NULL;
	 }

	_rhp_free(path);

	RHP_TRC(0,RHPTRCID_OPENSSL_CERT_UPDATE_RTRN,"uxxxx",auth_realm_id,my_cert_cont,my_privkey_cont,certs_cont,new_cert_store);
	return 0;

error:
	if( path ){
		sprintf((path + cert_store_path_len),"/my_cert_%lu.pem",auth_realm_id);
		_rhp_cert_recover_file(path);
		sprintf((path + cert_store_path_len),"/my_priv_key_%lu.pem",auth_realm_id);
		_rhp_cert_recover_file(path);
	  sprintf((path + cert_store_path_len),"/ca_certs_%lu.pem",auth_realm_id);
		_rhp_cert_recover_file(path);
	  sprintf((path + cert_store_path_len),"/crl_%lu.pem",auth_realm_id);
		_rhp_cert_recover_file(path);
	}
error_no_rcv:
	if( path ){
		_rhp_free(path);
	}
	if( new_cert_store ){
		rhp_cert_store_destroy(new_cert_store);
	}

	RHP_LOG_DE(RHP_LOG_SRC_AUTH,0,RHP_LOG_ID_UPDATE_CERT_STORE_ERR,"uE",auth_realm_id,err);

	RHP_TRC(0,RHPTRCID_OPENSSL_CERT_UPDATE_ERR,"uxxxE",auth_realm_id,my_cert_cont,my_privkey_cont,certs_cont,err);
	return err;
}

int rhp_cert_update(unsigned long auth_realm_id,int my_cert_cont_len,u8* my_cert_cont,
		int my_privkey_cont_len,u8* my_privkey_cont,int certs_cont_len,u8* certs_cont,char* password,
		char* cert_store_path,rhp_cert_store** cert_store_r)
{
	return _rhp_cert_update_impl(auth_realm_id,0,
			my_cert_cont_len,my_cert_cont,
			my_privkey_cont_len,my_privkey_cont,
			certs_cont_len,certs_cont,password,
			cert_store_path,cert_store_r);
}

int rhp_cert_update2(unsigned long auth_realm_id,
		char* password,
		char* cert_store_path,rhp_cert_store** cert_store_r)
{
	int err = -EINVAL;
	u8 flag = 0;
	char* path = NULL;
	int cert_store_path_len = strlen(cert_store_path);

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_UPDATE2,"ussx",auth_realm_id,password,cert_store_path,cert_store_r);

	path = (char*)_rhp_malloc(cert_store_path_len + RHP_CERT_STORE_OPENSSL_MAX_PATH + 2);
	if( path == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	path[0] = '\0';
	strcpy(path,cert_store_path);

	{
		sprintf((path + cert_store_path_len),"/my_cert_%lu.tmp",auth_realm_id);

		if( !rhp_file_exists(path) ){
			flag |= RHP_CERT_UPADTE_MY_CERT;
		}
	}

	{
		sprintf((path + cert_store_path_len),"/my_priv_key_%lu.tmp",auth_realm_id);

		if( !rhp_file_exists(path) ){
			flag |= RHP_CERT_UPADTE_MY_PRIVATE_KEY;
		}
	}

	{
	  sprintf((path + cert_store_path_len),"/ca_certs_%lu.tmp",auth_realm_id);

		if( !rhp_file_exists(path) ){
			flag |= RHP_CERT_UPADTE_CA_CERTS;
		}
	}

	{
	  sprintf((path + cert_store_path_len),"/crl_%lu.tmp",auth_realm_id);

		if( !rhp_file_exists(path) ){
			flag |= RHP_CERT_UPADTE_CRL;
		}
	}

	err = _rhp_cert_update_impl(auth_realm_id,flag,
			0,NULL,
			0,NULL,
			0,NULL,
			password,
			cert_store_path,cert_store_r);

	if( err ){
		goto error;
	}

	_rhp_free(path);

	RHP_TRC(0,RHPTRCID_OPENSSL_CERT_UPDATE2_RTRN,"ussbx",auth_realm_id,password,cert_store_path,flag,*cert_store_r);
	return 0;

error:
	if( path ){
		_rhp_free(path);
	}
  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_UPDATE2_ERR,"ussxbE",auth_realm_id,password,cert_store_path,cert_store_r,flag,err);
	return err;
}

int rhp_cert_delete(unsigned long auth_realm_id,char* cert_store_path,rhp_cert_store* cert_store)
{
	int err = -EINVAL;
	char* path = NULL;
	int cert_store_path_len = strlen(cert_store_path);

	RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DELETE,"usx",auth_realm_id,cert_store_path,cert_store);

	path = (char*)_rhp_malloc(cert_store_path_len + RHP_CERT_STORE_OPENSSL_MAX_PATH + 2);
	if( path == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	path[0] = '\0';
	strcpy(path,cert_store_path);

	sprintf((path + cert_store_path_len),"/my_cert_%lu.pem",auth_realm_id);
	err = _rhp_cert_rename_file(path,0);
	if( err ){
		RHP_BUG("%d",err);
	}

	sprintf((path + cert_store_path_len),"/my_priv_key_%lu.pem",auth_realm_id);
	err = _rhp_cert_rename_file(path,0);
	if( err ){
		RHP_BUG("%d",err);
	}

  sprintf((path + cert_store_path_len),"/ca_certs_%lu.pem",auth_realm_id);
	err = _rhp_cert_rename_file(path,0);
	if( err ){
		RHP_BUG("%d",err);
	}

  sprintf((path + cert_store_path_len),"/crl_%lu.pem",auth_realm_id);
	err = _rhp_cert_rename_file(path,0);
	if( err ){
		RHP_BUG("%d",err);
	}


	if( cert_store ){
		rhp_cert_store_destroy(cert_store);
	}

	_rhp_free(path);

	RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DELETE_RTRN,"usxE",auth_realm_id,cert_store_path,cert_store,err);
	return 0;

error:
	if( path ){
		_rhp_free(path);
	}
	RHP_TRC(0,RHPTRCID_OPENSSL_CERT_DELETE_ERR,"usxE",auth_realm_id,cert_store_path,cert_store,err);
	return err;
}

int rhp_cert_start()
{
  int err = -EINVAL;

  if( (err = rhp_wts_register_disp_rule(RHP_WTS_DISP_RULE_CERTOPR,_rhp_cert_store_disp_hash)) ){
    RHP_BUG("");
    goto error;
  }

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_START,"");
  return 0;

error:
  return err;
}

int rhp_cert_init()
{
  _rhp_mutex_init("CSR",&_rhp_cert_store_g_lock);

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_INIT,"");
  return 0;
}

void rhp_cert_cleanup()
{
  _rhp_mutex_destroy(&_rhp_cert_store_g_lock);

  RHP_TRC(0,RHPTRCID_OPENSSL_CERT_CLEANUP,"");
}

#endif /* RHP_OPENSSL */



