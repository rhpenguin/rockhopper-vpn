/*

	Copyright (C) 2009-2012 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifndef _RHP_STUN_H_
#define _RHP_STUN_H_



/*******************************

  Primitive API

********************************/

struct _rhp_stun_attr {

	unsigned char tag[4]; // "#AST"

	struct _rhp_stun_attr* next;

	rhp_proto_stun_attr* rx_attr;

	u16 tx_attr_type;
	u16 tx_attr_len;
	u8* tx_attr_val;

	u16 (*get_attr_type)(struct _rhp_stun_attr* stun_attr);
	int (*get_attr_len)(struct _rhp_stun_attr* stun_attr);
	u8* (*get_attr_val)(struct _rhp_stun_attr* stun_attr, int* attr_len_r);
};
typedef struct _rhp_stun_attr  rhp_stun_attr;


struct _rhp_stun_mesg {

	unsigned char tag[4]; // "#STM"

  int  len;
  u8* head;

  rhp_proto_stun* rx_header;

  rhp_proto_stun tx_header;

  u8 (*get_mesg_class)(struct _rhp_stun_mesg* stun_mesg);
  u16 (*get_mesg_method)(struct _rhp_stun_mesg* stun_mesg);
  u8* (*get_mesg_txnid)(struct _rhp_stun_mesg* stun_mesg);
  int (*get_mesg_len)(struct _rhp_stun_mesg* stun_mesg);


  int attr_num;
  rhp_stun_attr* attr_lst_head;
  rhp_stun_attr* attr_lst_tail;

  int tx_attrs_len;

  int (*enum_attrs)(struct _rhp_stun_mesg* stun_mesg, u16 attr_type,
  		int (*callback)(struct _rhp_stun_mesg* stun_mesg,rhp_stun_attr* attr,void* cb_ctx),void* ctx);

  rhp_stun_attr* (*get_attr)(struct _rhp_stun_mesg* stun_mesg, u16 attr_type);
  rhp_ip_addr* (*get_attr_mapped_addr)(struct _rhp_stun_mesg* stun_mesg);


  int (*put_attr)(struct _rhp_stun_mesg* stun_mesg,u16 attr_type, int attr_len, u8* attr_val);
  int (*put_attr_mapped_addr)(struct _rhp_stun_mesg* stun_mesg,rhp_ip_addr* mapped_addr,int xored);


  int (*serialize)(struct _rhp_stun_mesg* stun_mesg,int fingerprint,u8** buf_r, int* buf_len_r);
  int (*serialize_short_term_cred)(struct _rhp_stun_mesg* stun_mesg,u8* username,u8* sterm_key,int fingerprint,u8** buf_r, int* buf_len_r);
};
typedef struct _rhp_stun_mesg  rhp_stun_mesg;



extern int rhp_stun_mesg_new_rx(u8* rx_buf, int rx_buf_len, int fingerprint_flag,rhp_stun_mesg** stun_mesg_r);

extern int rhp_stun_mesg_new_rx_short_term_cred(u8* rx_buf, int rx_buf_len,int fingerprint_flag,
		u8* (*get_key)(u8* username, void* cb_get_key_ctx),void* get_key_ctx,
		rhp_stun_mesg** stun_mesg_r);

extern int rhp_stun_mesg_new_rx_long_term_cred(u8* rx_buf, int rx_buf_len,int fingerprint_flag,
		int (*is_valid_nonce)(u8* realm, u8* username, u8* nonce, void* cb_vl_n_ctx),void* vl_n_ctx,
		void (*callback)(int err,rhp_stun_mesg* stun_mesg,void* cb_ctx),void* ctx);


extern rhp_stun_mesg* rhp_stun_mesg_new_tx(u8 class, u16 method, u8* txn_id);

extern void rhp_stun_mesg_free(rhp_stun_mesg* stun_mesg);


extern int rhp_stun_mesg_attr_xor_addr(rhp_ip_addr* addr,u8* txn_id);

extern int rhp_stun_rx_mesg_is_stun(u8* rx_buf, int rx_buf_len,int fingerprint_flag,
		rhp_proto_stun** header_r,rhp_proto_stun_attr** attr_top_r);



/*******************************

     Bind

********************************/

extern int rhp_stun_bind_tx_new_req_mesg(rhp_stun_mesg** stun_req_r);

extern int rhp_stun_bind_tx_new_resp_mesg(rhp_stun_mesg* rx_stun_req, rhp_ip_addr* mapped_addr, rhp_stun_mesg** tx_stun_resp_r);

extern int rhp_stun_bind_resp_attr_mapped_addr(rhp_stun_mesg* rx_stun_resp,rhp_ip_addr** mapped_addr_r);

#endif // _RHP_STUN_H_

