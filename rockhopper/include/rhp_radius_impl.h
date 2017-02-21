/*

	Copyright (C) 2015-2016 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.

	You can redistribute and/or modify this software under the
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/

//
// librhpradius.so
//

#ifndef _RHP_RADIUS_IMPL_H_
#define _RHP_RADIUS_IMPL_H_

struct _rhp_radius_mesg;
struct _rhp_radius_attr;


extern int rhp_radius_impl_init();
extern int rhp_radius_impl_cleanup();


#define RHP_RADIUS_SECRET_IDX_PRIMARY					0
#define RHP_RADIUS_SECRET_IDX_SECONDARY				1
#define RHP_RADIUS_SECRET_IDX_ACCT_PRIMARY		2
#define RHP_RADIUS_SECRET_IDX_ACCT_SECONDARY	3
#define RHP_RADIUS_SECRET_IDX_MAX							3
extern int rhp_radius_impl_set_secret(int index,u8* secret,int secret_len);


struct _rhp_radius_session {

	u8 tag[4]; // '#RDS'

  rhp_mutex_t lock;

  rhp_atomic_t refcnt;
  rhp_atomic_t is_active;

  int usage; // RHP_RADIUS_USAGE_XXX

	rhp_ip_addr nas_addr; // nas: NAS (i.e. rockhopper gateway/concentrator)
	int (*set_nas_addr)(struct _rhp_radius_session* radius_sess,rhp_ip_addr* nas_addr);
	void (*get_nas_addr)(struct _rhp_radius_session* radius_sess,rhp_ip_addr* nas_addr_r);

	rhp_ip_addr server_addr_port; // server: RADIUS server
	void (*get_server_addr)(struct _rhp_radius_session* radius_sess,rhp_ip_addr* server_addr_port_r);

	char* server_fqdn;
	char* (*get_server_fqdn)(struct _rhp_radius_session* radius_sess);

	unsigned long vpn_realm_id;
	void (*set_realm_id)(struct _rhp_radius_session* radius_sess,unsigned long vpn_realm_id);
	unsigned long (*get_realm_id)(struct _rhp_radius_session* radius_sess);

	unsigned long peer_notified_realm_id;
	void (*set_peer_notified_realm_id)(struct _rhp_radius_session* radius_sess,
			unsigned long peer_notified_realm_id);
	unsigned long (*get_peer_notified_realm_id)(struct _rhp_radius_session* radius_sess);

	int secret_index;
	void (*set_secret_index)(struct _rhp_radius_session* radius_sess,int secret_index);

	rhp_ikev2_id gateway_id;
	int (*set_gateway_id)(struct _rhp_radius_session* radius_sess,rhp_ikev2_id* gateway_id);
	rhp_ikev2_id* (*get_gateway_id)(struct _rhp_radius_session* radius_sess); // Don't free return value.


  int (*get_msk)(struct _rhp_radius_session* radius_sess,u8** msk_r,int* msk_len_r);

  // Ret: RHP_PROTO_EAP_TYPE_XXX
  int (*get_eap_method)(struct _rhp_radius_session* radius_sess);


	time_t retransmit_interval;
	void (*set_retransmit_interval)(struct _rhp_radius_session* radius_sess,time_t interval_secs);

	int retransmit_times;
	void (*set_retransmit_times)(struct _rhp_radius_session* radius_sess,int times);


	char* user_name;
	int (*set_user_name)(struct _rhp_radius_session* radius_sess,char* user_name);
	char* (*get_user_name)(struct _rhp_radius_session* radius_sess);

	char* nas_id;
	int (*set_nas_id)(struct _rhp_radius_session* radius_sess,char* nas_id);
	char* (*get_nas_id)(struct _rhp_radius_session* radius_sess);
	int inc_nas_id_as_ikev2_id;
	void (*include_nas_id_as_ikev2_id)(struct _rhp_radius_session* radius_sess,int flag);

	char* calling_station_id;
	int (*set_calling_station_id)(struct _rhp_radius_session* radius_sess,char* calling_station_id);
	char* (*get_calling_station_id)(struct _rhp_radius_session* radius_sess);

	char* connect_info;
	int (*set_connect_info)(struct _rhp_radius_session* radius_sess,char* connect_info);
	char* (*get_connect_info)(struct _rhp_radius_session* radius_sess);

	int framed_mtu;
	void (*set_framed_mtu)(struct _rhp_radius_session* radius_sess,int framed_mtu);
	int (*get_framed_mtu)(struct _rhp_radius_session* radius_sess);

	int inc_nas_port_type; // "Virtual"
	void (*include_nas_port_type)(struct _rhp_radius_session* radius_sess,int flag);

	char* acct_session_id;
	int (*set_acct_session_id)(struct _rhp_radius_session* radius_sess,char* acct_session_id);
	char* (*get_acct_session_id)(struct _rhp_radius_session* radius_sess);


	int (*send_message)(struct _rhp_radius_session* radius_sess,
				struct _rhp_radius_mesg* tx_radius_mesg);


	u8 priv_attr_type_realm_id;
	u8 priv_attr_type_realm_role;
	u8 priv_attr_type_user_index;
	u8 priv_attr_type_internal_address_ipv4;
	u8 priv_attr_type_internal_address_ipv6;
	u8 priv_attr_type_internal_dns_server_ipv4;
	u8 priv_attr_type_internal_dns_server_ipv6;
	u8 priv_attr_type_internal_domain_name;
	u8 priv_attr_type_internal_route_ipv4;
	u8 priv_attr_type_internal_route_ipv6;
	u8 priv_attr_type_internal_gateway_ipv4;
	u8 priv_attr_type_internal_gateway_ipv6;
	u8 priv_attr_type_common;
	u8 reserved0;
	u8 reserved1;
	u8 reserved2;

#define RHP_RADIUS_RX_ATTR_PRIV_REALM_ID									11
#define RHP_RADIUS_RX_ATTR_PRIV_REALM_ROLE								12
#define RHP_RADIUS_RX_ATTR_PRIV_USER_INDEX								13
#define RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_ADDR_IPV4				14
#define RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_ADDR_IPV6				15
#define RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_DNS_SERVER_IPV4	16
#define RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_DNS_SERVER_IPV6	17
#define RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_DOMAIN_NAME			18
#define RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_ROUTE_IPV4				19
#define RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_ROUTE_IPV6				20
#define RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_GATEWAY_IPV4			21
#define RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_GATEWAY_IPV6			22
#define RHP_RADIUS_RX_ATTR_PRIV_COMMON										23
	// rx_attr_type: RHP_RADIUS_RX_ATTR_PRIV_XXX
	void (*set_private_attr_type)(struct _rhp_radius_session* radius_sess,int rx_attr_type,u8 attr_type_val);

	void* priv;
};
typedef struct _rhp_radius_session	rhp_radius_session;

//
// [CAUTION] When callbacks are called, radius_sess is already held but not LOCKed.
//
#define RHP_RADIUS_USAGE_AUTHENTICATION		0
#define RHP_RADIUS_USAGE_ACCOUNTING				1
extern rhp_radius_session* rhp_radius_session_open(
					int usage, // RHP_RADIUS_USAGE_XXX
					rhp_ip_addr* server_addr_port,
					char* server_fqdn,
					void (*receive_response_cb)(rhp_radius_session* radius_sess,void* cb_ctx,
							struct _rhp_radius_mesg* rx_radius_mesg),
					void (*error_cb)(rhp_radius_session* radius_sess,void* cb_ctx,
							struct _rhp_radius_mesg* tx_radius_mesg,int err),
					void* cb_ctx);


extern int rhp_radius_session_close(rhp_radius_session* radius_sess);



#ifndef RHP_REFCNT_DEBUG

typedef struct _rhp_radius_session	rhp_radius_session_ref;

extern void rhp_radius_sess_hold(rhp_radius_session* radius_sess);
extern rhp_radius_session_ref* rhp_radius_sess_hold_ref(rhp_radius_session* radius_sess);
extern void rhp_radius_sess_unhold(rhp_radius_session* radius_sess);

#define RHP_RADIUS_SESS_REF(radius_sess) ((rhp_radius_session*)(radius_sess))

#else // RHP_REFCNT_DEBUG
#ifndef RHP_REFCNT_DEBUG_X

typedef struct _rhp_radius_session	rhp_radius_session_ref;

extern void rhp_radius_session_free(rhp_radius_session* radius_sess);

#define rhp_radius_sess_hold(radius_sess)\
{\
	RHP_LINE("#RHP_RADIUS_SESS_HOLD 0x%x:radius_sess->refcnt.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",(radius_sess),(radius_sess)->refcnt.c,rhp_func_trc_current());\
  _rhp_atomic_inc(&((radius_sess)->refcnt));\
}
#define rhp_radius_sess_hold_ref(radius_sess)\
({\
	rhp_radius_session_ref* __ret3__ = (rhp_radius_session_ref*)(radius_sess);\
	RHP_LINE("#RHP_RADIUS_SESS_HOLD REF 0x%x:radius_sess->refcnt.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",(radius_sess),(radius_sess)->refcnt.c,rhp_func_trc_current());\
  _rhp_atomic_inc(&((radius_sess)->refcnt));\
	__ret3__;\
})
#define rhp_radius_sess_unhold(radius_sess_t)\
{\
	rhp_radius_session* __radius_sess__ = (rhp_radius_session*)(radius_sess_t);\
	RHP_LINE("#RHP_RADIUS_SESS_UNHOLD 0x%x:radius_sess->refcnt.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",__radius_sess__,__radius_sess__->refcnt.c,rhp_func_trc_current());\
	if( _rhp_atomic_dec_and_test(&(__radius_sess__->refcnt)) ){\
  	RHP_LINE("#RHP_RADIUS_SESS_UNHOLD_DESTROY 0x%x:radius_sess->refcnt.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",__radius_sess__,__radius_sess__->refcnt.c,rhp_func_trc_current());\
  	rhp_radius_session_free(__radius_sess__);\
  }\
}

#define RHP_RADIUS_SESS_REF(radius_sess) ((rhp_radius_session*)(radius_sess))


#else // RHP_REFCNT_DEBUG_X

/*

  To debug a rhp_radius_session object's refcnt, use rhp_radius_sess_hold_ref() and rhp_radius_sess_unhold().
  rhp_radius_sess_hold_ref() returns a rhp_radius_sess_ref object which records where the rhp_radius_session
  object is held by rhp_radius_sess_hold_ref(). To unhold the object, use rhp_radius_sess_unhold()
  as usual. To get a rhp_radius_session object from a rhp_radius_session_ref object, use RHP_RADIUS_SESS_REF().


  rhp_radius_session* radius_sess = xxx.
  rhp_radius_session_ref* radius_sess_ref = rhp_radius_sess_hold_ref(radius_sess);
  ...
  ...
  rhp_radius_session* radius_sess = RHP_RADIUS_SESS_REF(radius_sess_ref);
  ...
  ...
  rhp_radius_sess_unhold(radius_sess_ref);


	To get unheld rhp_radius_session objects' records, run 'rockhopper.pl memory_dbg ... ' command.

*/

typedef struct _rhp_refcnt_dbg	rhp_radius_session_ref;

extern void rhp_radius_session_free(rhp_radius_session* radius_sess);

#define rhp_radius_sess_hold(radius_sess)\
{\
	RHP_LINE("#RHP_RADIUS_SESS_HOLD 0x%x:radius_sess->refcnt.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",(radius_sess),(radius_sess)->refcnt.c,rhp_func_trc_current());\
  _rhp_atomic_inc(&((radius_sess)->refcnt));\
}
#define rhp_radius_sess_hold_ref(radius_sess)\
({\
	rhp_radius_session_ref* __ret3__;\
  _rhp_atomic_inc(&((radius_sess)->refcnt));\
  __ret3__ = (rhp_radius_session_ref*)rhp_refcnt_dbg_alloc((radius_sess),__FILE__,__LINE__);\
	RHP_LINE("#RHP_RADIUS_SESS_HOLD REF 0x%x(ref:0x%x):radius_sess->refcnt.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",(radius_sess),__ret3__,(radius_sess)->refcnt.c,rhp_func_trc_current());\
	__ret3__;\
})
#define rhp_radius_sess_unhold(radius_sess_or_radius_sess_ref)\
{\
	rhp_radius_session* __radius_sess__ = (rhp_radius_session*)rhp_refcnt_dbg_free((radius_sess_or_radius_sess_ref));\
	RHP_LINE("#RHP_RADIUS_SESS_UNHOLD 0x%x(ref:0x%x):radius_sess->refcnt.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",__radius_sess__,(radius_sess_or_radius_sess_ref),__radius_sess__->refcnt.c,rhp_func_trc_current());\
	if( _rhp_atomic_dec_and_test(&(__radius_sess__->refcnt)) ){\
  	RHP_LINE("#RHP_RADIUS_SESS_UNHOLD_DESTROY 0x%x(ref:0x%x):radius_sess->refcnt.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",__radius_sess__,(radius_sess_or_radius_sess_ref),__radius_sess__->refcnt.c,rhp_func_trc_current());\
  	rhp_radius_session_free(__radius_sess__);\
  }\
}


#define RHP_RADIUS_SESS_REF(radius_sess_or_radius_sess_ref) ((rhp_radius_session*)RHP_REFCNT_OBJ((radius_sess_or_radius_sess_ref)))

#endif // RHP_REFCNT_DEBUG_X
#endif // RHP_REFCNT_DEBUG



struct _rhp_radius_attr_basic {

	u8 attr_value_len;
	u8 reserved0;
	u16 reserved1;
	u8* attr_value;

	int (*set_attr_value)(struct _rhp_radius_attr* radius_attr,u8 attr_value_len,u8* attr_value);
	u8* (*get_attr_value)(struct _rhp_radius_attr* radius_attr,
			int* attr_val_len_r); // Caller must NOT free the return value.

	void* priv;
};
typedef struct _rhp_radius_attr_basic rhp_radius_attr_basic;


struct _rhp_radius_attr_eap {

	u16 eap_packet_len;
	u16 reserved0;
	rhp_proto_eap* eap_packet;

	u8 (*get_eap_code)(struct _rhp_radius_attr* radius_attr);
	u8 (*get_eap_type)(struct _rhp_radius_attr* radius_attr);

	int (*set_eap_packet)(struct _rhp_radius_attr* radius_attr,u8 packet_len,rhp_proto_eap* packet);
	rhp_proto_eap* (*get_eap_packet)(struct _rhp_radius_attr* radius_attr,
			int* packet_len_r); // Caller must NOT free the return value.

	void* priv;
};
typedef struct _rhp_radius_attr_eap rhp_radius_attr_eap;


struct _rhp_radius_attr_vendor_ms {

	u8 vendor_attr_len;
	u8 reserved0;
	u16 reserved1;
	rhp_proto_radius_attr_vendor_ms* vendor_attr;

	u8 (*get_vendor_type)(struct _rhp_radius_attr* radius_attr);

	int (*set_vendor_attr)(struct _rhp_radius_attr* radius_attr,
			rhp_proto_radius_attr_vendor_ms* vendor_attr,int vendor_attr_len);

	rhp_proto_radius_attr_vendor_ms* (*get_vendor_attr)(struct _rhp_radius_attr* radius_attr,
			int* vendor_attr_len_r); // Caller must NOT free the return value.

	void* priv;
};
typedef struct _rhp_radius_attr_vendor_ms rhp_radius_attr_vendor_ms;


struct _rhp_radius_attr {

	u8 tag[4]; // '#RDA'

	struct _rhp_radius_attr* next;

	struct _rhp_radius_mesg* radius_mesg;

	u8 attr_type;
	u8 reserved0;
	u16 reserved1;
  u8 (*get_attr_type)(struct _rhp_radius_attr* radius_attr);

  u32 vendor_id;
  u32 (*get_attr_vendor_id)(struct _rhp_radius_attr* radius_attr);

	union {
		u8* raw;
		rhp_radius_attr_basic* basic;
		rhp_radius_attr_eap* eap;
		rhp_radius_attr_vendor_ms* ms;
	} ext;

	void* priv;
};
typedef struct _rhp_radius_attr	rhp_radius_attr;


extern void rhp_radius_attr_destroy(rhp_radius_attr* radius_attr);

extern int rhp_radius_new_attr_tx(rhp_radius_session* radius_sess,struct _rhp_radius_mesg* radius_mesg,
		u8 attr_type,u32 vendor_id,rhp_radius_attr** radius_attr_r);

extern int rhp_radius_new_attr_rx(rhp_radius_session* radius_sess,struct _rhp_radius_mesg* radius_mesg,
		rhp_proto_radius_attr* radius_attrh,int radius_attr_len,rhp_radius_attr** radius_attr_r);



struct _rhp_radius_access_accept_attrs {

	u8 tag[4]; // '#RAA'

	rhp_ip_addr framed_ipv4;
	rhp_ip_addr framed_ipv6;

	rhp_ip_addr ms_primary_dns_server_ipv4;
	rhp_ip_addr dns_server_ipv6;

	rhp_ip_addr ms_primary_nbns_server_ipv4;

	u32 session_timeout;

// Termination-Action for future use.
#if 0
	// RHP_RADIUS_ATTR_TYPE_TERMINATION_ACTION_DEFAULT or RHP_RADIUS_ATTR_TYPE_TERMINATION_ACTION_REQUEST
	u32 termination_action;
	int termination_action_state_len;
	u8* termination_action_state;
#endif

	u32 framed_mtu;


	unsigned long priv_realm_id;

	rhp_string_list* tunnel_private_group_ids;
	rhp_string_list* priv_realm_roles;


	char* tunnel_client_auth_id;
	char* priv_user_index;


	rhp_ip_addr priv_internal_addr_ipv4;
	rhp_ip_addr priv_internal_addr_ipv6;

	rhp_ip_addr priv_internal_dns_server_ipv4;
	rhp_ip_addr priv_internal_dns_server_ipv6;
	rhp_split_dns_domain* priv_domain_names;

	rhp_internal_route_map* priv_internal_route_ipv4;
	rhp_internal_route_map* priv_internal_route_ipv6;

	rhp_ip_addr priv_internal_gateway_ipv4;
	rhp_ip_addr priv_internal_gateway_ipv6;


	rhp_ip_addr orig_nas_addr; // Not rx attribute.

	void (*dump)(struct _rhp_radius_access_accept_attrs* access_accepted_attrs,void* radius_sess_p);
};
typedef struct _rhp_radius_access_accept_attrs	rhp_radius_access_accept_attrs;


extern void rhp_radius_access_accept_rx_attrs_dump(
		rhp_radius_access_accept_attrs* rx_accepted_attrs,void* radius_sess_p);

static inline rhp_radius_access_accept_attrs* rhp_radius_alloc_access_accept_attrs()
{
	rhp_radius_access_accept_attrs* rx_accept_attrs
	= (rhp_radius_access_accept_attrs*)_rhp_malloc(sizeof(rhp_radius_access_accept_attrs));
	if( rx_accept_attrs == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(rx_accept_attrs,0,sizeof(rhp_radius_access_accept_attrs));

	rx_accept_attrs->tag[0] = '#';
	rx_accept_attrs->tag[1] = 'R';
	rx_accept_attrs->tag[2] = 'A';
	rx_accept_attrs->tag[3] = 'A';

	rx_accept_attrs->dump = rhp_radius_access_accept_rx_attrs_dump;

	rx_accept_attrs->priv_realm_id = RHP_VPN_REALM_ID_UNKNOWN;

// Termination-Action for future use.
#if 0
	rx_accept_attrs->termination_action
		= RHP_RADIUS_ATTR_TYPE_TERMINATION_ACTION_DEFAULT;
#endif

	return rx_accept_attrs;
}

static inline void _rhp_radius_access_accept_attrs_free(rhp_radius_access_accept_attrs* rx_accept_attrs)
{

//	RHP_LINE("_rhp_radius_access_accept_attrs_free() rx_accept_attrs:0x%x, tunnel_private_group_ids:0x%x",rx_accept_attrs,rx_accept_attrs->tunnel_private_group_ids);

// Termination-Action for future use.
#if 0
	if( rx_accept_attrs->termination_action_state ){
		_rhp_free_zero(rx_accept_attrs->termination_action_state,
				rx_accept_attrs->termination_action_state_len);
	}
#endif

	if( rx_accept_attrs->tunnel_private_group_ids ){
		_rhp_string_list_free(rx_accept_attrs->tunnel_private_group_ids);
	}

	if( rx_accept_attrs->priv_realm_roles ){
		_rhp_string_list_free(rx_accept_attrs->priv_realm_roles);
	}

	if( rx_accept_attrs->tunnel_client_auth_id ){
		_rhp_free(rx_accept_attrs->tunnel_client_auth_id);
	}

	if( rx_accept_attrs->priv_user_index ){
		_rhp_free(rx_accept_attrs->priv_user_index);
	}

	_rhp_split_dns_domain_free(rx_accept_attrs->priv_domain_names);

	_rhp_internal_route_map_free(rx_accept_attrs->priv_internal_route_ipv4);
	_rhp_internal_route_map_free(rx_accept_attrs->priv_internal_route_ipv6);

	_rhp_free(rx_accept_attrs);

	return;
}



struct _rhp_radius_mesg {

	u8 tag[4]; // '#RMG'

	struct _rhp_radius_mesg* next;

  rhp_atomic_t refcnt;

  u8 (*get_code)(struct _rhp_radius_mesg* radius_mesg);
  void (*set_code)(struct _rhp_radius_mesg* radius_mesg,u8 code);

  u8 (*get_id)(struct _rhp_radius_mesg* radius_mesg);
  void (*set_id)(struct _rhp_radius_mesg* radius_mesg,u8 id);

  u16 (*get_len)(struct _rhp_radius_mesg* radius_mesg);

  u8* (*get_authenticator)(struct _rhp_radius_mesg* radius_mesg);
  void (*set_authenticator)(struct _rhp_radius_mesg* radius_mesg,u8* authenticator);

  void (*set_termination_request)(struct _rhp_radius_mesg* radius_mesg,int flag);

  int attr_num;
  rhp_radius_attr* attr_head;
  rhp_radius_attr* attr_tail;

  void (*put_attr)(struct _rhp_radius_mesg* radius_mesg,rhp_radius_attr* radius_attr);
  void (*put_attr_head)(struct _rhp_radius_mesg* radius_mesg,rhp_radius_attr* radius_attr);

  rhp_radius_attr* (*get_attr)(struct _rhp_radius_mesg* radius_mesg,u8 type,char* priv_attr_string_value_tag);

  int (*enum_attrs)(struct _rhp_radius_mesg* radius_mesg,u8 type,char* priv_attr_string_value_tag,
  		int (*callback)(struct _rhp_radius_mesg* radius_mesg,rhp_radius_attr* radius_attr,
  				char* priv_attr_string_value_tag,void* cb_ctx),void* ctx);

  rhp_radius_attr* (*get_attr_eap)(struct _rhp_radius_mesg* radius_mesg,u8 eap_code,u8 eap_type);

  rhp_radius_attr* (*get_attr_vendor_ms)(struct _rhp_radius_mesg* radius_mesg,u8 vendor_type);


  // For one-time-use purpose.
  rhp_radius_access_accept_attrs* (*get_access_accept_attributes)(struct _rhp_radius_mesg* radius_mesg);

  unsigned long (*get_realm_id_by_access_accept_attrs)(struct _rhp_radius_mesg* radius_mesg);

  void (*get_src_addr_port)(struct _rhp_radius_mesg* radius_mesg,rhp_ip_addr* addr_port_r);
  void (*get_dst_addr_port)(struct _rhp_radius_mesg* radius_mesg,rhp_ip_addr* addr_port_r);

	void* priv;
};
typedef struct _rhp_radius_mesg	rhp_radius_mesg;


extern rhp_radius_mesg* rhp_radius_new_mesg_tx(u8 code,u8 id);



#ifndef RHP_REFCNT_DEBUG

extern void rhp_radius_mesg_hold(rhp_radius_mesg* radius_mesg);
extern void rhp_radius_mesg_unhold(rhp_radius_mesg* radius_mesg);

#else // RHP_REFCNT_DEBUG

extern void rhp_radius_free_mesg(rhp_radius_mesg* radius_mesg);

#define rhp_radius_mesg_hold(radius_mesg)\
{\
	RHP_LINE("#RHP_RADIUS_MESG_HOLD 0x%x:radius_mesg->refcnt.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",(radius_mesg),(radius_mesg)->refcnt.c,rhp_func_trc_current());\
  _rhp_atomic_inc(&((radius_mesg)->refcnt));\
}
#define rhp_radius_mesg_unhold(radius_mesg_t)\
{\
	rhp_radius_mesg* __radius_mesg__ = (rhp_radius_mesg*)(radius_mesg_t);\
	RHP_LINE("#RHP_RADIUS_MESG_UNHOLD 0x%x:radius_mesg->refcnt.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",__radius_mesg__,__radius_mesg__->refcnt.c,rhp_func_trc_current());\
	if( _rhp_atomic_dec_and_test(&(__radius_mesg__->refcnt)) ){\
  	RHP_LINE("#RHP_RADIUS_MESG_UNHOLD_DESTROY 0x%x:radius_mesg->refcnt.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",__radius_mesg__,__radius_mesg__->refcnt.c,rhp_func_trc_current());\
  	rhp_radius_free_mesg(__radius_mesg__);\
  }\
}

#endif // RHP_REFCNT_DEBUG



#endif // _RHP_RADIUS_IMPL_H_
