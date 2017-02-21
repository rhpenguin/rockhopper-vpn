/*

	Copyright (C) 2015-2016 TETSUHARU HANADA <rhpenguine@gmail.com>
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

#ifndef _RHP_RADIUS_PRIV_H_
#define _RHP_RADIUS_PRIV_H_


#define RHP_RADIUS_MD5_SIZE						16
#define RHP_RADIUS_MSCHAPV2_KEY_LEN		16
#define RHP_RADIUS_MAX_MSK_LEN				128


extern u8* rhp_radius_decrypt_ms_key(const u8 *key, size_t len,
	   const u8 *req_authenticator,const u8 *secret, size_t secret_len, size_t *reslen);




extern rhp_mutex_t rhp_radius_priv_lock;

struct _rhp_radius_session_priv {

	u8 tag[4]; // '#RSI'

	int sk;

#define	RHP_RADIUS_SESS_EPOLL_CTX_SESS(radius_sess_priv) 	((radius_sess_priv)->epoll_ctx.params[0])
#define	RHP_RADIUS_SESS_EPOLL_CTX_SESS_2(epoll_ctx) 			((epoll_ctx)->params[0])
	rhp_epoll_ctx epoll_ctx;

	u8 tx_mesg_id;
	u8 reserved0;
	u16 reserved1;

	int rx_attr_state_len;
	u8* rx_attr_state;

	int msk_len;
	u8* msk;

	int eap_method; // RHP_PROTO_EAP_TYPE_XXX

	int retx_counter;
	rhp_timer retx_timer;

	rhp_radius_mesg* tx_access_req; // A request packet on the fly.
	rhp_packet_ref* tx_access_pkt_ref; // For retransmission.

	rhp_packet_ref* rx_pend_pkt_ref;

	u64 ipc_txn_id;

	void* cb_ctx;

	void (*receive_response)(rhp_radius_session* radius_sess,void* cb_ctx,
				struct _rhp_radius_mesg* radius_mesg);
	void (*error_cb)(rhp_radius_session* radius_sess,void* cb_ctx,rhp_radius_mesg* tx_radius_mesg,int err);
};
typedef struct _rhp_radius_session_priv	rhp_radius_session_priv;



struct _rhp_radius_attr_priv {

	u8 tag[4]; // '#RAI'

	rhp_proto_radius_attr* radius_attrh;


	int eap_attrh_rx_defrag_len;
	rhp_proto_eap* eap_attrh_rx_defrag;


  int (*ext_serialize)(struct _rhp_radius_attr* radius_attr,rhp_packet* pkt);

  void (*ext_destructor)(struct _rhp_radius_attr* radius_attr);
};
typedef struct _rhp_radius_attr_priv	rhp_radius_attr_priv;



struct _rhp_radius_mesg_priv {

	u8 tag[4]; // '#RMI'

	rhp_packet_ref* tx_pkt_ref;
	rhp_packet_ref* rx_pkt_ref;

  rhp_proto_radius* tx_radiush;
  u16 tx_mesg_len;
  u8 is_term_req;

  int (*serialize)(struct _rhp_radius_mesg* radius_mesg,rhp_radius_session* radius_sess,
  		rhp_packet** pkt_r);

	rhp_radius_access_accept_attrs* rx_accept_attrs;

	unsigned long rebound_rlm_id;
};
typedef struct _rhp_radius_mesg_priv	rhp_radius_mesg_priv;

extern int rhp_radius_new_mesg_rx(rhp_radius_session* radius_sess,rhp_packet* pkt,rhp_radius_mesg** radius_mesg_r);



extern int rhp_radius_rx_basic_attr_to_ipv4(rhp_radius_mesg* rx_radius_mesg,
		u8 attr_type,rhp_ip_addr* addr_r);

extern int rhp_radius_rx_basic_attr_to_ipv6(rhp_radius_mesg* rx_radius_mesg,
		u8 attr_type,rhp_ip_addr* addr_r);

extern int rhp_radius_rx_basic_attr_to_ip_list(rhp_radius_mesg* rx_radius_mesg,
		u8 attr_type,int addr_family,rhp_ip_addr_list** addr_list_r);

extern int rhp_radius_rx_basic_attr_to_u32(rhp_radius_mesg* rx_radius_mesg,
		u8 attr_type,u32* ret_r);

extern int rhp_radius_rx_basic_attr_to_string(rhp_radius_mesg* rx_radius_mesg,
		u8 attr_type,int is_tunnel_attr,char* priv_attr_string_value_tag,char** ret_r);

extern int rhp_radius_rx_basic_attr_to_string_list(rhp_radius_mesg* rx_radius_mesg,
		u8 attr_type,int is_tunnel_attr,char* priv_attr_string_value_tag,rhp_string_list** ret_head_r);

extern int rhp_radius_rx_basic_attr_to_domain_list(rhp_radius_mesg* rx_radius_mesg,
		u8 attr_type,char* priv_attr_string_value_tag,rhp_split_dns_domain** ret_head_r);

extern int rhp_radius_rx_basic_attr_to_bin(rhp_radius_mesg* rx_radius_mesg,
		u8 attr_type,u8** ret_r,int* ret_len_r);

extern int rhp_radius_rx_basic_attr_str_to_ipv4_impl(rhp_radius_mesg* rx_radius_mesg,
		rhp_radius_attr* radius_attr,char* priv_attr_string_value_tag,rhp_ip_addr* addr_r);

extern int rhp_radius_rx_basic_attr_str_to_ipv4(rhp_radius_mesg* rx_radius_mesg,
		u8 attr_type,char* priv_attr_string_value_tag,rhp_ip_addr* addr_r);

extern int rhp_radius_rx_basic_attr_str_to_ipv6_impl(rhp_radius_mesg* rx_radius_mesg,
		rhp_radius_attr* radius_attr,char* priv_attr_string_value_tag,rhp_ip_addr* addr_r);

extern int rhp_radius_rx_basic_attr_str_to_ipv6(rhp_radius_mesg* rx_radius_mesg,
		u8 attr_type,char* priv_attr_string_value_tag,rhp_ip_addr* addr_r);

extern int rhp_radius_rx_basic_attr_str_to_rt_map_list(rhp_radius_mesg* rx_radius_mesg,
		u8 attr_type,int addr_family,char* priv_attr_string_value_tag,rhp_internal_route_map** ret_head_r);



extern int rhp_radius_session_rx_supported_code(int usage,u8 code);



#define RHP_RADIUS_PKT_DEFAULT_SIZE		1024


#endif // _RHP_RADIUS_PRIV_H_
