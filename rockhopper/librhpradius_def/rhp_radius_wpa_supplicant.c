
/*

This library(librhpradius.so) includes modified source code imported
from wpa_supplicant-2.5.

This library is distributed under the BSD licence. Please read the
following original Copyright notice and visit the wpa_supplicant
project's Web site (http://hostap.epitest.fi/wpa_supplicant/) to
get more detailed information.

*/

/*
 * wpa_supplicant and hostapd
 *
 * Copyright (c) 2002-2009, 2011-2014, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <asm/types.h>
#include <sys/capability.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <linux/errqueue.h>

#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <openssl/des.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/dh.h>

#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_protocol.h"
#include "rhp_timer.h"
#include "rhp_packet.h"
#include "rhp_netsock.h"
#include "rhp_packet.h"
#include "rhp_config.h"
#include "rhp_crypto.h"
#include "rhp_radius_impl.h"
#include "rhp_radius_priv.h"

static int openssl_digest_vector(const EVP_MD *type, int non_fips,
				 size_t num_elem, const u8 *addr[],
				 const size_t *len, u8 *mac)
{
	EVP_MD_CTX *ctx;
	size_t i;
	unsigned int mac_len;

	RHP_TRC(0,RHPTRCID_RADIUS_OPENSSL_DIGEST_VECTOR,"xddddx",type,EVP_MD_type(type),non_fips,num_elem,len,mac);

	ctx = EVP_MD_CTX_new();
#ifdef CONFIG_FIPS
#ifdef OPENSSL_FIPS
	if (non_fips)
		EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
#endif /* OPENSSL_FIPS */
#endif /* CONFIG_FIPS */
	if (!EVP_DigestInit_ex(ctx, type, NULL)) {
//		wpa_printf(MSG_ERROR, "OpenSSL: EVP_DigestInit_ex failed: %s",
//			   ERR_error_string(ERR_get_error(), NULL));
		RHP_BUG("");
		return -1;
	}
	for (i = 0; i < num_elem; i++) {
		if (!EVP_DigestUpdate(ctx, addr[i], len[i])) {
//			wpa_printf(MSG_ERROR, "OpenSSL: EVP_DigestUpdate "
//				   "failed: %s",
//				   ERR_error_string(ERR_get_error(), NULL));
			RHP_BUG("");
			return -1;
		}
	}
	if (!EVP_DigestFinal_ex(ctx, mac, &mac_len)) {
//		wpa_printf(MSG_ERROR, "OpenSSL: EVP_DigestFinal failed: %s",
//			   ERR_error_string(ERR_get_error(), NULL));
		RHP_BUG("");
		return -1;
	}

	EVP_MD_CTX_free(ctx);

	RHP_TRC(0,RHPTRCID_RADIUS_OPENSSL_DIGEST_VECTOR_RTRN,"p",*len,mac);
	return 0;
}

static int _md5_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
	return openssl_digest_vector(EVP_md5(), 0, num_elem, addr, len, mac);
}

u8* rhp_radius_decrypt_ms_key(const u8 *key, size_t len,
			   const u8 *req_authenticator,
			   const u8 *secret, size_t secret_len, size_t *reslen)
{
	u8 *plain, *ppos, *res;
	const u8 *pos;
	size_t left, plen;
	u8 hash[RHP_RADIUS_MD5_SIZE];
	int i, first = 1;
	const u8 *addr[3];
	size_t elen[3];

	RHP_TRC(0,RHPTRCID_RADIUS_DECRYPT_MS_KEY,"pppx",len,key,RHP_RADIUS_AUTHENTICATOR_LEN,req_authenticator,secret_len,secret,reslen);

	// key: 16-bit salt followed by encrypted key info

	if (len < 2 + 16) {
		RHP_TRC(0,RHPTRCID_RADIUS_DECRYPT_MS_KEY_INVALID_KEY_LEN_1,"d",len);
		return NULL;
	}

	pos = key + 2;
	left = len - 2;
	if (left % 16) {
		RHP_TRC(0,RHPTRCID_RADIUS_DECRYPT_MS_KEY_INVALID_KEY_LEN_2,"d",len);
		return NULL;
	}

	plen = left;
	ppos = plain = _rhp_malloc(plen);
	if (plain == NULL){
		return NULL;
	}
	plain[0] = 0;

	while (left > 0) {

		// b(1) = MD5(Secret + Request-Authenticator + Salt)
		// b(i) = MD5(Secret + c(i - 1)) for i > 1

		addr[0] = secret;
		elen[0] = secret_len;
		if (first) {
			addr[1] = req_authenticator;
			elen[1] = RHP_RADIUS_MD5_SIZE;
			addr[2] = key;
			elen[2] = 2; // Salt
		} else {
			addr[1] = pos - RHP_RADIUS_MD5_SIZE;
			elen[1] = RHP_RADIUS_MD5_SIZE;
		}
		_md5_vector(first ? 3 : 2, addr, elen, hash);
		first = 0;

		for (i = 0; i < RHP_RADIUS_MD5_SIZE; i++)
			*ppos++ = *pos++ ^ hash[i];
		left -= RHP_RADIUS_MD5_SIZE;
	}

	if (plain[0] == 0 || plain[0] > plen - 1) {
		_rhp_free(plain);
		RHP_BUG("");
		return NULL;
	}

	res = _rhp_malloc(plain[0]);
	if (res == NULL) {
		_rhp_free(plain);
		RHP_BUG("");
		return NULL;
	}
	memcpy(res, plain + 1, plain[0]);
	if (reslen){
		*reslen = plain[0];
	}
	_rhp_free(plain);

	RHP_TRC(0,RHPTRCID_RADIUS_DECRYPT_MS_KEY_RTRN,"xp",key,*reslen,res);
	return res;
}




/*
static u8 * decrypt_ms_key(const u8 *key, size_t len,
			   const u8 *req_authenticator,
			   const u8 *secret, size_t secret_len, size_t *reslen)
{
	u8 *plain, *ppos, *res;
	const u8 *pos;
	size_t left, plen;
	u8 hash[MD5_MAC_LEN];
	int i, first = 1;
	const u8 *addr[3];
	size_t elen[3];

	// key: 16-bit salt followed by encrypted key info

	if (len < 2 + 16) {
		wpa_printf(MSG_DEBUG, "RADIUS: %s: Len is too small: %d",
			   __func__, (int) len);
		return NULL;
	}

	pos = key + 2;
	left = len - 2;
	if (left % 16) {
		wpa_printf(MSG_INFO, "RADIUS: Invalid ms key len %lu",
			   (unsigned long) left);
		return NULL;
	}

	plen = left;
	ppos = plain = os_malloc(plen);
	if (plain == NULL)
		return NULL;
	plain[0] = 0;

	while (left > 0) {
		// b(1) = MD5(Secret + Request-Authenticator + Salt)
		// b(i) = MD5(Secret + c(i - 1)) for i > 1

		addr[0] = secret;
		elen[0] = secret_len;
		if (first) {
			addr[1] = req_authenticator;
			elen[1] = MD5_MAC_LEN;
			addr[2] = key;
			elen[2] = 2; // Salt
		} else {
			addr[1] = pos - MD5_MAC_LEN;
			elen[1] = MD5_MAC_LEN;
		}
		md5_vector(first ? 3 : 2, addr, elen, hash);
		first = 0;

		for (i = 0; i < MD5_MAC_LEN; i++)
			*ppos++ = *pos++ ^ hash[i];
		left -= MD5_MAC_LEN;
	}

	if (plain[0] == 0 || plain[0] > plen - 1) {
		wpa_printf(MSG_INFO, "RADIUS: Failed to decrypt MPPE key");
		os_free(plain);
		return NULL;
	}

	res = os_malloc(plain[0]);
	if (res == NULL) {
		os_free(plain);
		return NULL;
	}
	os_memcpy(res, plain + 1, plain[0]);
	if (reslen)
		*reslen = plain[0];
	os_free(plain);
	return res;
}
*/

/*
static void encrypt_ms_key(const u8 *key, size_t key_len, u16 salt,
			   const u8 *req_authenticator,
			   const u8 *secret, size_t secret_len,
			   u8 *ebuf, size_t *elen)
{
	int i, len, first = 1;
	u8 hash[MD5_MAC_LEN], saltbuf[2], *pos;
	const u8 *addr[3];
	size_t _len[3];

	WPA_PUT_BE16(saltbuf, salt);

	len = 1 + key_len;
	if (len & 0x0f) {
		len = (len & 0xf0) + 16;
	}
	os_memset(ebuf, 0, len);
	ebuf[0] = key_len;
	os_memcpy(ebuf + 1, key, key_len);

	*elen = len;

	pos = ebuf;
	while (len > 0) {
		// b(1) = MD5(Secret + Request-Authenticator + Salt)
		// b(i) = MD5(Secret + c(i - 1)) for i > 1
		addr[0] = secret;
		_len[0] = secret_len;
		if (first) {
			addr[1] = req_authenticator;
			_len[1] = MD5_MAC_LEN;
			addr[2] = saltbuf;
			_len[2] = sizeof(saltbuf);
		} else {
			addr[1] = pos - MD5_MAC_LEN;
			_len[1] = MD5_MAC_LEN;
		}
		md5_vector(first ? 3 : 2, addr, _len, hash);
		first = 0;

		for (i = 0; i < MD5_MAC_LEN; i++)
			*pos++ ^= hash[i];

		len -= MD5_MAC_LEN;
	}
}
*/

/*

struct radius_ms_mppe_keys {
	u8 *send;
	size_t send_len;
	u8 *recv;
	size_t recv_len;
};

struct radius_ms_mppe_keys *
radius_msg_get_ms_keys(struct radius_msg *msg, struct radius_msg *sent_msg,
		       const u8 *secret, size_t secret_len)
{
	u8 *key;
	size_t keylen;
	struct radius_ms_mppe_keys *keys;

	if (msg == NULL || sent_msg == NULL)
		return NULL;

	keys = os_zalloc(sizeof(*keys));
	if (keys == NULL)
		return NULL;

	key = radius_msg_get_vendor_attr(msg, RADIUS_VENDOR_ID_MICROSOFT,
					 RADIUS_VENDOR_ATTR_MS_MPPE_SEND_KEY,
					 &keylen);
	if (key) {
		keys->send = decrypt_ms_key(key, keylen,
					    sent_msg->hdr->authenticator,
					    secret, secret_len,
					    &keys->send_len);
		if (!keys->send) {
			wpa_printf(MSG_DEBUG,
				   "RADIUS: Failed to decrypt send key");
		}
		os_free(key);
	}

	key = radius_msg_get_vendor_attr(msg, RADIUS_VENDOR_ID_MICROSOFT,
					 RADIUS_VENDOR_ATTR_MS_MPPE_RECV_KEY,
					 &keylen);
	if (key) {
		keys->recv = decrypt_ms_key(key, keylen,
					    sent_msg->hdr->authenticator,
					    secret, secret_len,
					    &keys->recv_len);
		if (!keys->recv) {
			wpa_printf(MSG_DEBUG,
				   "RADIUS: Failed to decrypt recv key");
		}
		os_free(key);
	}

	return keys;
}


struct radius_ms_mppe_keys *
radius_msg_get_cisco_keys(struct radius_msg *msg, struct radius_msg *sent_msg,
			  const u8 *secret, size_t secret_len)
{
	u8 *key;
	size_t keylen;
	struct radius_ms_mppe_keys *keys;

	if (msg == NULL || sent_msg == NULL)
		return NULL;

	keys = os_zalloc(sizeof(*keys));
	if (keys == NULL)
		return NULL;

	key = radius_msg_get_vendor_attr(msg, RADIUS_VENDOR_ID_CISCO,
					 RADIUS_CISCO_AV_PAIR, &keylen);
	if (key && keylen == 51 &&
	    os_memcmp(key, "leap:session-key=", 17) == 0) {
		keys->recv = decrypt_ms_key(key + 17, keylen - 17,
					    sent_msg->hdr->authenticator,
					    secret, secret_len,
					    &keys->recv_len);
	}
	os_free(key);

	return keys;
}
*/
