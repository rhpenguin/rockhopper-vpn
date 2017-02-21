/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.

	You can redistribute and/or modify this software under the
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

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

#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_protocol.h"
#include "rhp_packet.h"
#include "rhp_netsock.h"
#include "rhp_wthreads.h"
#include "rhp_packet.h"
#include "rhp_config.h"
#include "rhp_crypto.h"
#include "rhp_stun.h"

u16 _rhp_stun_mesg_attr_get_attr_type(rhp_stun_attr* stun_attr)
{
	u16 attr_type;

	if( stun_attr->rx_attr ){
		attr_type = ntohs(stun_attr->rx_attr->attr_type);
	}else{
		attr_type = stun_attr->tx_attr_type;
	}

	RHP_TRC(0,RHPTRCID_STUN_MESG_ATTR_GET_ATTR_TYPE,"xLw",stun_attr,"STUN_ATTR_TYPE",attr_type);
	return attr_type;
}

int _rhp_stun_mesg_attr_get_attr_len(rhp_stun_attr* stun_attr)
{
	int ret;
	if( stun_attr->rx_attr ){
		ret = ntohs(stun_attr->rx_attr->attr_len);
	}else{
		ret = stun_attr->tx_attr_len;
	}

	RHP_TRC(0,RHPTRCID_STUN_MESG_ATTR_GET_ATTR_LEN,"xd",stun_attr,ret);
	return ret;
}

u8* _rhp_stun_mesg_attr_get_attr_val(rhp_stun_attr* stun_attr,int* attr_len_r)
{
	u8* ret = NULL;
	int ret_len = 0;

	if( stun_attr->rx_attr ){

		ret_len = _rhp_stun_mesg_attr_get_attr_len(stun_attr);

		if( ret_len ){
			ret = (u8*)(stun_attr->rx_attr + 1);
		}

	}else{

		ret_len = stun_attr->tx_attr_len;
		ret = stun_attr->tx_attr_val;
	}

	if( attr_len_r ){
		*attr_len_r = ret_len;
	}

	RHP_TRC(0,RHPTRCID_STUN_MESG_ATTR_GET_ATTR_VAL,"xp",stun_attr,ret_len,ret);
	return ret;
}

static rhp_stun_attr* _rhp_stun_mesg_attr_alloc_raw()
{
	rhp_stun_attr* attr = (rhp_stun_attr*)_rhp_malloc(sizeof(rhp_stun_attr));

	if( attr == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(attr,0,sizeof(rhp_stun_attr));

	attr->tag[0] = '#';
	attr->tag[1] = 'A';
	attr->tag[2] = 'S';
	attr->tag[3] = 'T';

	attr->get_attr_type = _rhp_stun_mesg_attr_get_attr_type;
	attr->get_attr_len = _rhp_stun_mesg_attr_get_attr_len;
	attr->get_attr_val = _rhp_stun_mesg_attr_get_attr_val;

	RHP_TRC(0,RHPTRCID_STUN_MESG_ATTR_ALLOC_RAW,"x",attr);
	return attr;
}

static u8 _rhp_stun_mesg_get_mesg_class(rhp_stun_mesg* stun_mesg)
{
	rhp_proto_stun* header;
	u8 ret;

	if( stun_mesg->rx_header ){
		header = stun_mesg->rx_header;
	}else{
		header = &(stun_mesg->tx_header);
	}

	ret = _rhp_proto_stun_mesg_class(header->mesg_type);

	RHP_TRC(0,RHPTRCID_STUN_MESG_GET_MESG_CLASS,"xLb",stun_mesg,"STUN_CLASS",ret);
	return ret;
}

static u16 _rhp_stun_mesg_get_mesg_method(rhp_stun_mesg* stun_mesg)
{
	rhp_proto_stun* header;
	u16 ret;

	if( stun_mesg->rx_header ){
		header = stun_mesg->rx_header;
	}else{
		header = &(stun_mesg->tx_header);
	}

	ret = _rhp_proto_stun_mesg_method(header->mesg_type);

	RHP_TRC(0,RHPTRCID_STUN_MESG_GET_MESG_METHOD,"xLw",stun_mesg,"STUN_METHOD",ret);
	return ret;
}

static u8* _rhp_stun_mesg_get_mesg_txnid(rhp_stun_mesg* stun_mesg)
{
	rhp_proto_stun* header;

	if( stun_mesg->rx_header ){
		header = stun_mesg->rx_header;
	}else{
		header = &(stun_mesg->tx_header);
	}

	RHP_TRC(0,RHPTRCID_STUN_MESG_GET_MESG_TXNID,"xp",stun_mesg,RHP_PROTO_STUN_TXN_ID_SIZE,&(header->txn_id[0]));
	return &(header->txn_id[0]);
}

static int _rhp_stun_mesg_get_mesg_len(rhp_stun_mesg* stun_mesg)
{
	rhp_proto_stun* header;

	if( stun_mesg->rx_header ){
		header = stun_mesg->rx_header;
	}else{
		header = &(stun_mesg->tx_header);
	}

	RHP_TRC(0,RHPTRCID_STUN_MESG_GET_MESG_LEN,"xW",stun_mesg,header->mesg_len);
	return (int)ntohs(header->mesg_len);
}


static int _rhp_stun_mesg_enum_attrs(rhp_stun_mesg* stun_mesg, u16 attr_type,
  		int (*callback)(rhp_stun_mesg* stun_mesg,rhp_stun_attr* attr,void* cb_ctx),void* ctx)
{
	int err = -EINVAL;
	rhp_stun_attr* attr = stun_mesg->attr_lst_head;
	int n = 0;

	RHP_TRC(0,RHPTRCID_STUN_MESG_ENUM_ATTRS,"xLwYx",stun_mesg,"STUN_ATTR_TYPE",attr_type,callback,ctx);

	while( attr ){

		if( !attr_type || (attr->get_attr_type(attr) == attr_type) ){

			err = callback(stun_mesg,attr,ctx);
			if( err ){

				if( err == RHP_STATUS_ENUM_OK ){
					RHP_TRC(0,RHPTRCID_STUN_MESG_ENUM_ATTRS_RTRN_ENUM_OK,"xLwYx",stun_mesg,"STUN_ATTR_TYPE",attr_type,callback,ctx);
					return 0;
				}

				RHP_TRC(0,RHPTRCID_STUN_MESG_ENUM_ATTRS_ERR,"xLwYxE",stun_mesg,"STUN_ATTR_TYPE",attr_type,callback,ctx,err);
				return err;
			}

			n++;
		}

		attr = attr->next;
	}

	if( n == 0 ){

		err = -ENOENT;

		RHP_TRC(0,RHPTRCID_STUN_MESG_ENUM_ATTRS_ERR_NO_ENT,"xLwYxE",stun_mesg,"STUN_ATTR_TYPE",attr_type,callback,ctx,err);
		return err;
	}

	RHP_TRC(0,RHPTRCID_STUN_MESG_ENUM_ATTRS_RTRN,"xLwYxd",stun_mesg,"STUN_ATTR_TYPE",attr_type,callback,ctx,n);
	return 0;
}


static rhp_stun_attr* _rhp_stun_mesg_get_attr(rhp_stun_mesg* stun_mesg, u16 attr_type)
{
	rhp_stun_attr* attr = stun_mesg->attr_lst_head;

	while( attr ){

		if( attr->get_attr_type(attr) == attr_type ){

			RHP_TRC(0,RHPTRCID_STUN_MESG_GET_ATTR,"xLwx",stun_mesg,"STUN_ATTR_TYPE",attr_type,attr);
			return attr;
		}

		attr = attr->next;
	}

	RHP_TRC(0,RHPTRCID_STUN_MESG_GET_ATTR_ERR_NO_ENT,"xLw",stun_mesg,"STUN_ATTR_TYPE",attr_type);
	return NULL;
}


int rhp_stun_mesg_attr_xor_addr(rhp_ip_addr* addr,u8* txn_id)
{
	int err = -EINVAL;

	rhp_ip_addr_dump("rhp_stun_mesg_attr_xor_addr CALL",addr);

	if( addr->addr_family == AF_INET ){

		addr->addr.v4 = htonl(ntohl(addr->addr.v4) ^ RHP_PROTO_STUN_MAGIC_COOKIE);

	}else if( addr->addr_family == AF_INET6 ){

		int i;

		if( txn_id == NULL ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		addr->addr.v6[0] ^= 0x21;
		addr->addr.v6[1] ^= 0x12;
		addr->addr.v6[2] ^= 0xa4;
		addr->addr.v6[3] ^= 0x42;

		for( i = 3; i < 16; i++ ){
			addr->addr.v6[i] ^= txn_id[i];
		}

	}else{
		err = -EINVAL;
		goto error;
	}

	addr->port = htons(ntohs(addr->port) ^ (RHP_PROTO_STUN_MAGIC_COOKIE >> 16));

	rhp_ip_addr_dump("rhp_stun_mesg_attr_xor_addr RTRN",addr);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_STUN_MESG_ATTR_XOR_ADDR_ERR,"E",err);
	return err;
}

static rhp_ip_addr* _rhp_stun_mesg_get_attr_mapped_addr(rhp_stun_mesg* stun_mesg)
{
	int err = -EINVAL;
	rhp_stun_attr* attr;
	rhp_ip_addr* mapped_addr = NULL;
	u16 attr_type;
	int attr_len;

	RHP_TRC(0,RHPTRCID_STUN_MESG_GET_ATTR_MAPPED_ADDR,"x",stun_mesg);

	attr = _rhp_stun_mesg_get_attr(stun_mesg,RHP_PROTO_STUN_ATTR_XOR_MAPPED_ADDRESS);
	if( attr == NULL ){

		attr = _rhp_stun_mesg_get_attr(stun_mesg,RHP_PROTO_STUN_ATTR_MAPPED_ADDRESS);
		attr_type = RHP_PROTO_STUN_ATTR_MAPPED_ADDRESS;

	}else{

		attr_type = RHP_PROTO_STUN_ATTR_XOR_MAPPED_ADDRESS;
	}

	if( attr == NULL ){
		RHP_TRC(0,RHPTRCID_STUN_MESG_GET_ATTR_MAPPED_ADDR_NOT_FOUND,"x",stun_mesg);
		goto error;
	}

	mapped_addr = (rhp_ip_addr*)_rhp_malloc(sizeof(rhp_ip_addr));
	if( mapped_addr == NULL ){
		RHP_BUG("");
		goto error;
	}

	memset(mapped_addr,0,sizeof(rhp_ip_addr));

	{
		rhp_proto_stun_attr_mapped_addr_v* attr_val;

		attr_val = (rhp_proto_stun_attr_mapped_addr_v*)attr->get_attr_val(attr,&attr_len);
		if( attr_val == NULL ){
			RHP_BUG("");
			goto error;
		}

		if( attr_len != sizeof(rhp_proto_stun_attr_mapped_addr_v) + 4 &&
				attr_len != sizeof(rhp_proto_stun_attr_mapped_addr_v) + 16 ){

			RHP_TRC(0,RHPTRCID_STUN_MESG_GET_ATTR_MAPPED_ADDR_BAD_LENGTH,"xd",stun_mesg,attr_len);
			goto error;
		}

		mapped_addr->port = ntohs(attr_val->port);

		if( attr_val->addr_family == RHP_PROTO_STUN_AF_IPV4 ){

			mapped_addr->addr_family = AF_INET;
			mapped_addr->addr.v4 = ntohl(*((u32*)(attr_val + 1)));

		}else if( attr_val->addr_family == RHP_PROTO_STUN_AF_IPV6 ){

			mapped_addr->addr_family = AF_INET6;
			memcpy(mapped_addr->addr.v6,(u8*)(attr_val + 1),16);
		}
	}


	if( attr->get_attr_type(attr) == RHP_PROTO_STUN_ATTR_XOR_MAPPED_ADDRESS ){

		u8* txn_id = stun_mesg->get_mesg_txnid(stun_mesg);

		err = rhp_stun_mesg_attr_xor_addr(mapped_addr,txn_id);
		if( err ){
			goto error;
		}
	}

	RHP_TRC(0,RHPTRCID_STUN_MESG_GET_ATTR_MAPPED_ADDR_RTRN,"xx",stun_mesg,mapped_addr);
	rhp_ip_addr_dump("_rhp_stun_mesg_get_attr_mapped_addr",mapped_addr);
	return mapped_addr;

error:
	if( mapped_addr ){
		_rhp_free(mapped_addr);
	}
	RHP_TRC(0,RHPTRCID_STUN_MESG_GET_ATTR_MAPPED_ADDR_ERR,"xE",stun_mesg,err);
	return NULL;
}

static void _rhp_mesg_put_attr_raw(rhp_stun_mesg* stun_mesg, rhp_stun_attr* attr)
{
	RHP_TRC(0,RHPTRCID_STUN_MESG_PUT_ATTR_RAW,"xx",stun_mesg,attr);

	if( stun_mesg->attr_lst_head == NULL ){
		stun_mesg->attr_lst_head = attr;
	}else{
		stun_mesg->attr_lst_tail->next = attr;
	}
	stun_mesg->attr_lst_tail = attr;

	stun_mesg->attr_num++;

	stun_mesg->tx_attrs_len += sizeof(rhp_proto_stun_attr) + attr->tx_attr_len;

	RHP_TRC(0,RHPTRCID_STUN_MESG_PUT_ATTR_RAW_RTRN,"xxddd",stun_mesg,attr,attr->tx_attr_len,stun_mesg->attr_num,stun_mesg->tx_attrs_len);
}

static int _rhp_stun_mesg_put_attr(rhp_stun_mesg* stun_mesg,u16 attr_type, int attr_len, u8* attr_val)
{
	rhp_stun_attr* attr = _rhp_stun_mesg_attr_alloc_raw();

	RHP_TRC(0,RHPTRCID_STUN_MESG_PUT_ATTR,"xLwp",stun_mesg,"STUN_ATTR_TYPE",attr_type,attr_len,attr_val);

	if( attr == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	attr->tx_attr_type = attr_type;

	if( attr_len ){

		attr->tx_attr_val = (u8*)_rhp_malloc(attr_len);
		if( attr->tx_attr_val == NULL ){
			RHP_BUG("");
			return -ENOMEM;
		}

		memcpy(attr->tx_attr_val,attr_val,attr_len);
		attr->tx_attr_len = attr_len;
	}

	_rhp_mesg_put_attr_raw(stun_mesg,attr);

	RHP_TRC(0,RHPTRCID_STUN_MESG_PUT_ATTR_RTRN,"xLwx",stun_mesg,"STUN_ATTR_TYPE",attr_type,attr_val);
	return 0;
}


static int _rhp_stun_mesg_put_attr_mapped_addr(rhp_stun_mesg* stun_mesg,rhp_ip_addr* mapped_addr,int xored)
{
	int err = -EINVAL;
	u8 attr_buf[sizeof(rhp_proto_stun_attr_xor_mapped_addr_v) + 16];
	rhp_proto_stun_attr_xor_mapped_addr_v* stun_attr = (rhp_proto_stun_attr_xor_mapped_addr_v*)attr_buf;
	int attr_len = sizeof(rhp_proto_stun_attr_xor_mapped_addr_v);

	memset(stun_attr,0,sizeof(rhp_proto_stun_attr_xor_mapped_addr_v) + 16);

	stun_attr->x_port = htons(ntohs(mapped_addr->port) ^ (RHP_PROTO_STUN_MAGIC_COOKIE >> 16));

	if( mapped_addr->addr_family == AF_INET ){

		stun_attr->addr_family = RHP_PROTO_STUN_AF_IPV4;

		*((u32*)(stun_attr + 1)) = mapped_addr->addr.v4;

		attr_len += 4;

	}else if( mapped_addr->addr_family == AF_INET6 ){

		stun_attr->addr_family = RHP_PROTO_STUN_AF_IPV6;

		memcpy((u8*)(stun_attr + 1),mapped_addr->addr.v6,16);

		attr_len += 16;

	}else{
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	err = _rhp_stun_mesg_put_attr(stun_mesg,
			(xored ? RHP_PROTO_STUN_ATTR_XOR_MAPPED_ADDRESS : RHP_PROTO_STUN_ATTR_MAPPED_ADDRESS),
			attr_len,attr_buf);
	if( err ){
		goto error;
	}

	return 0;

error:
	return err;
}


static int _rhp_stun_mesg_serialize_prm(rhp_stun_mesg* stun_mesg,int fingerprint, u8** buf_r, int* buf_len_r)
{
	int err = -EINVAL;
	int mesg_len = sizeof(rhp_proto_stun);
	u8* mesg_buf = NULL;
	rhp_proto_stun* stun_header;
	rhp_proto_stun_attr* stun_attr;
  rhp_stun_attr* attr;

	RHP_TRC(0,RHPTRCID_STUN_MESG_SERIALIZE_PRM,"xdxx",stun_mesg,fingerprint,buf_r,buf_len_r);

	mesg_len += stun_mesg->tx_attrs_len;

	if( fingerprint ){

		mesg_len += sizeof(rhp_proto_stun_attr_fingerprint);
	}


	mesg_buf = (u8*)_rhp_malloc(mesg_len);
	if( mesg_buf == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}


	stun_header = (rhp_proto_stun*)mesg_buf;
	stun_attr = (rhp_proto_stun_attr*)(stun_header + 1);

  attr = stun_mesg->attr_lst_head;
  while( attr ){

  	int stun_attr_len;
  	int padlen = 0;
  	int i;

  	stun_attr->attr_type = htons(attr->get_attr_type(attr));

  	stun_attr_len = attr->get_attr_len(attr);
  	stun_attr->attr_len = htons(stun_attr_len);

  	if( stun_attr_len ){

  		memcpy((u8*)(stun_attr + 1),attr->get_attr_val(attr,NULL),stun_attr_len);

  		padlen = stun_attr_len % 4;
  		if( padlen ){
  			padlen = 4 - padlen;
  		}
  	}

  	for( i = 0; i < padlen; i++ ){
  		*(((u8*)(stun_attr + 1)) + stun_attr_len + i) = 0;
  	}

  	stun_attr = (rhp_proto_stun_attr*)(((u8*)(stun_attr + 1)) + stun_attr_len + padlen);

  	attr = attr->next;
  }

  memcpy(stun_header,&(stun_mesg->tx_header),sizeof(rhp_proto_stun));

  stun_header->mesg_len = htons(mesg_len - sizeof(rhp_proto_stun));


	*buf_r = mesg_buf;
	*buf_len_r = mesg_len;

	RHP_TRC(0,RHPTRCID_STUN_MESG_SERIALIZE_PRM_RTRN,"xdp",stun_mesg,fingerprint,*buf_len_r,*buf_r);
	return 0;

error:
	if( mesg_buf ){
		_rhp_free(mesg_buf);
	}
	RHP_TRC(0,RHPTRCID_STUN_MESG_SERIALIZE_PRM_ERR,"xE",stun_mesg,err);
	return  err;
}


static u32 _rhp_stun_mesg_attr_fingerprint(u8 *buf, int len)
{
	u32 ret = (u32)rhp_crc32(0, buf, (unsigned int)len) ^ RHP_PROTO_STUN_ATTR_FINGERPRINT_MASK;

	RHP_TRC(0,RHPTRCID_STUN_MESG_ATTR_FINGERPRINT,"uxp",ret,ret,len,buf);
	return ret;
}

static void _rhp_stun_mesg_set_attr_fingerprint(int mesg_len,u8* mesg_buf)
{
	int fp_buf_len = mesg_len - sizeof(rhp_proto_stun_attr_fingerprint);
	rhp_proto_stun_attr_fingerprint* stun_attr_fp
	= (rhp_proto_stun_attr_fingerprint*)(mesg_buf + mesg_len - sizeof(rhp_proto_stun_attr_fingerprint));

	RHP_TRC(0,RHPTRCID_STUN_MESG_SET_ATTR_FINGERPRINT,"p",mesg_len,mesg_buf);

	stun_attr_fp->attr_type = htons(RHP_PROTO_STUN_ATTR_FINGERPRINT);
	stun_attr_fp->attr_len = sizeof(rhp_proto_stun_attr_fingerprint) - sizeof(rhp_proto_stun_attr);

	stun_attr_fp->crc32 = htonl(_rhp_stun_mesg_attr_fingerprint(mesg_buf, fp_buf_len));

	// No padding bytes needed for fingerprint attr.

	RHP_TRC(0,RHPTRCID_STUN_MESG_SET_ATTR_FINGERPRINT_RTRN,"pp",sizeof(rhp_proto_stun_attr_fingerprint),stun_attr_fp,mesg_len,mesg_buf);
	return;
}

static int _rhp_stun_mesg_serialize(rhp_stun_mesg* stun_mesg,int fingerprint, u8** buf_r, int* buf_len_r)
{
	int err = -EINVAL;
	int mesg_len = sizeof(rhp_proto_stun);
	u8* mesg_buf = NULL;

	RHP_TRC(0,RHPTRCID_STUN_MESG_SERIALIZE,"xdxx",stun_mesg,fingerprint,buf_r,buf_len_r);

  err = _rhp_stun_mesg_serialize_prm(stun_mesg,fingerprint,&mesg_buf,&mesg_len);
  if( err ){
  	goto error;
  }

	if( fingerprint ){

		_rhp_stun_mesg_set_attr_fingerprint(mesg_len,mesg_buf);
	}


	*buf_r = mesg_buf;
	*buf_len_r = mesg_len;

	RHP_TRC(0,RHPTRCID_STUN_MESG_SERIALIZE_RTRN,"xp",stun_mesg,*buf_len_r,*buf_r);
	return 0;

error:
	if( mesg_buf ){
		_rhp_free(mesg_buf);
	}
	RHP_TRC(0,RHPTRCID_STUN_MESG_SERIALIZE_ERR,"xE",stun_mesg,err);
	return  err;
}

static int _rhp_stun_mesg_serialize_short_term_cred(rhp_stun_mesg* stun_mesg,
		u8* username,u8* sterm_key,int fingerprint,u8** buf_r, int* buf_len_r)
{
	int err = -EINVAL;
	static u8 hmac[RHP_PROTO_STUN_ATTR_MESG_INTEG_SIZE]; // Dummy
	int mesg_len = sizeof(rhp_proto_stun);
	u8* mesg_buf = NULL;
	rhp_proto_stun* header;
	u8* hmac_buf = NULL;
	int hmac_buf_len = 0;

	RHP_TRC(0,RHPTRCID_STUN_MESG_SERIALIZE_SHORT_TERM_CRED,"xssdxx",stun_mesg,username,sterm_key,fingerprint,buf_r,buf_len_r);

	err = stun_mesg->put_attr(stun_mesg,RHP_PROTO_STUN_ATTR_USERNAME,strlen((char*)username) + 1,username);
	if( err ){
		RHP_BUG("");
		goto error;
	}

	err = stun_mesg->put_attr(stun_mesg,RHP_PROTO_STUN_ATTR_MESSAGE_INTEGRITY,
			RHP_PROTO_STUN_ATTR_MESG_INTEG_SIZE,hmac);
	if( err ){
		RHP_BUG("");
		goto error;
	}


  err = _rhp_stun_mesg_serialize_prm(stun_mesg,fingerprint,&mesg_buf,&mesg_len);
  if( err ){
  	RHP_BUG("");
  	goto error;
  }

  header = (rhp_proto_stun*)mesg_buf;


	{
		int orig_mesg_len = ntohs(header->mesg_len);
		int hmac_in_len = mesg_len - sizeof(rhp_proto_stun_attr_mesg_integ);
		int tmp_mesg_len =  orig_mesg_len;
		rhp_proto_stun_attr_mesg_integ* stun_attr_integ;

		stun_attr_integ = (rhp_proto_stun_attr_mesg_integ*)(mesg_buf + mesg_len - sizeof(rhp_proto_stun_attr_mesg_integ));

		if( fingerprint ){

			hmac_in_len -= sizeof(rhp_proto_stun_attr_fingerprint);
			tmp_mesg_len -= sizeof(rhp_proto_stun_attr_fingerprint);

			stun_attr_integ = (rhp_proto_stun_attr_mesg_integ*)(((u8*)stun_attr_integ) - sizeof(rhp_proto_stun_attr_fingerprint));
		}

		header->mesg_len = htons(tmp_mesg_len);

		err = rhp_crypto_hmac(RHP_CRYPTO_HMAC_SHA1,(u8*)header,hmac_in_len,
				sterm_key,strlen((char*)sterm_key),&hmac_buf,&hmac_buf_len);

		header->mesg_len = htons(orig_mesg_len);

		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		if( hmac_buf_len != RHP_PROTO_STUN_ATTR_MESG_INTEG_SIZE ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		memcpy(&(stun_attr_integ->hmac[0]),hmac_buf,hmac_buf_len);
	}


	if( fingerprint ){

		_rhp_stun_mesg_set_attr_fingerprint(mesg_len,mesg_buf);
	}


	_rhp_free(hmac_buf);

	*buf_r = mesg_buf;
	*buf_len_r = mesg_len;

	RHP_TRC(0,RHPTRCID_STUN_MESG_SERIALIZE_SHORT_TERM_CRED_RTRN,"xp",stun_mesg,*buf_len_r,*buf_r);
	return 0;

error:
	if( mesg_buf ){
		_rhp_free(mesg_buf);
	}
	if( hmac_buf ){
		_rhp_free(hmac_buf);
	}
	RHP_TRC(0,RHPTRCID_STUN_MESG_SERIALIZE_SHORT_TERM_CRED_ERR,"xE",stun_mesg,err);
	return err;
}


static rhp_stun_mesg* _rhp_stun_mesg_alloc_raw()
{
	rhp_stun_mesg* stun_mesg = (rhp_stun_mesg*)_rhp_malloc(sizeof(rhp_stun_mesg));

	if( stun_mesg == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(stun_mesg,0,sizeof(rhp_stun_mesg));

	stun_mesg->tag[0] = '#';
	stun_mesg->tag[1] = 'S';
	stun_mesg->tag[2] = 'T';
	stun_mesg->tag[3] = 'M';

	stun_mesg->get_mesg_class = _rhp_stun_mesg_get_mesg_class;
	stun_mesg->get_mesg_method = _rhp_stun_mesg_get_mesg_method;
	stun_mesg->get_mesg_txnid = _rhp_stun_mesg_get_mesg_txnid;
	stun_mesg->get_mesg_len = _rhp_stun_mesg_get_mesg_len ;
	stun_mesg->enum_attrs = _rhp_stun_mesg_enum_attrs;
	stun_mesg->get_attr = _rhp_stun_mesg_get_attr;
	stun_mesg->get_attr_mapped_addr = _rhp_stun_mesg_get_attr_mapped_addr;
	stun_mesg->put_attr = _rhp_stun_mesg_put_attr;
	stun_mesg->put_attr_mapped_addr = _rhp_stun_mesg_put_attr_mapped_addr;
	stun_mesg->serialize = _rhp_stun_mesg_serialize;
	stun_mesg->serialize_short_term_cred = _rhp_stun_mesg_serialize_short_term_cred;

  RHP_TRC(0,RHPTRCID_STUN_MESG_ALLOC_RAW,"x",stun_mesg);
	return stun_mesg;
}


void rhp_stun_mesg_free(rhp_stun_mesg* stun_mesg)
{
  RHP_TRC(0,RHPTRCID_STUN_MESG_FREE,"x",stun_mesg);

	if( stun_mesg == NULL ){
		RHP_BUG("");
		return;
	}

	{
		rhp_stun_attr* attr = stun_mesg->attr_lst_head;

		while( attr ){

			rhp_stun_attr* attr2 = attr->next;

			if( attr->tx_attr_val ){
				_rhp_free(attr->tx_attr_val);
			}

			_rhp_free(attr);

			attr = attr2;
		}
	}

	if( stun_mesg->head ){
		_rhp_free(stun_mesg->head);
	}

	_rhp_free(stun_mesg);

	RHP_TRC(0,RHPTRCID_STUN_MESG_FREE_RTRN,"x",stun_mesg);
	return;
}


static rhp_proto_stun_attr* _rhp_stun_mesg_rx_seek_attr(u8* rx_buf, int rx_buf_len,u16 attr_type)
{
	u8 *p, *endp;
	rhp_proto_stun* header = (rhp_proto_stun*)rx_buf;
	rhp_proto_stun_attr* stun_attr_r = NULL;

	RHP_TRC(0,RHPTRCID_STUN_MESG_RX_SEEK_ATTR,"xdLw",rx_buf,rx_buf_len,"STUN_ATTR_TYPE",attr_type);

	p = (u8*)(header + 1);
	endp = rx_buf + rx_buf_len;

	while( p < endp ){

		rhp_proto_stun_attr* stun_attr;
		int attr_len;
		int padlen;

		if( p + sizeof(rhp_proto_stun_attr) > endp ){
			RHP_TRC(0,RHPTRCID_STUN_MESG_RX_SEEK_ATTR_INVALID_MESG_1,"x",rx_buf);
			break;
		}

		stun_attr = (rhp_proto_stun_attr*)p;

		attr_len = ntohs(stun_attr->attr_len);

		padlen = attr_len % 4;
		if( padlen ){
			padlen = 4 - padlen;
		}else{
			padlen = 0;
		}

		if( ((u8*)(stun_attr + 1))  + attr_len + padlen > endp ){
			// Invalid STUN message
			RHP_TRC(0,RHPTRCID_STUN_MESG_RX_SEEK_ATTR_INVALID_MESG_2,"x",rx_buf);
			break;
		}

		if( ntohs(stun_attr->attr_type) == attr_type ){

			stun_attr_r = (rhp_proto_stun_attr*)p;
			break;
		}

		p += sizeof(rhp_proto_stun_attr) + attr_len + padlen;
	}

	if( stun_attr_r ){
		RHP_TRC(0,RHPTRCID_STUN_MESG_RX_SEEK_ATTR_INVALID_MESG_RTRN,"xp",rx_buf,sizeof(rhp_proto_stun_attr),stun_attr_r);
	}else{
		RHP_TRC(0,RHPTRCID_STUN_MESG_RX_SEEK_ATTR_INVALID_MESG_ERR_NOT_FOUND,"x",rx_buf);
	}
	return stun_attr_r;
}

// Return 0 if Success.
static int _rhp_stun_rx_mesg_is_stun(u8* rx_buf, int rx_buf_len,int fingerprint_flag,
		rhp_proto_stun** header_r,rhp_proto_stun_attr** attr_top_r,
		rhp_proto_stun_attr_mesg_integ** attr_integ_r,rhp_proto_stun_attr_username** attr_uname_r)
{
	int err = -EINVAL;
	rhp_proto_stun* header;
	u16 mesg_type;
	u16 mesg_len;
	u8* endp = rx_buf + rx_buf_len;

	RHP_TRC(0,RHPTRCID_STUN_RX_MESG_IS_STUN,"pdxxxx",rx_buf_len,rx_buf,fingerprint_flag,header_r,attr_top_r,attr_integ_r,attr_uname_r);

	if( rx_buf_len < (int)sizeof(rhp_proto_stun) ){
		err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
		goto error;
	}

	header = (rhp_proto_stun*)rx_buf;

	mesg_type = ntohs(header->mesg_type);
	mesg_len = ntohs(header->mesg_len);

	if( mesg_len & 0x0003 ){
		err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH_FORMAT;
		goto error;
	}

	if( mesg_len != rx_buf_len - (int)sizeof(rhp_proto_stun) ){
		err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
		goto error;
	}

	if( ntohl(header->magic_cookie) != RHP_PROTO_STUN_MAGIC_COOKIE ){
		err = RHP_STATUS_INVALID_STUN_MESG_BAD_MAGIC_COOKIE;
		goto error;
	}

	if( mesg_type & 0xc000 ){
		err = RHP_STATUS_INVALID_STUN_MESG_BAD_START_BITS;
		goto error;
	}

	if( fingerprint_flag ){

		rhp_proto_stun_attr_fingerprint* attr_fp
		= (rhp_proto_stun_attr_fingerprint*)_rhp_stun_mesg_rx_seek_attr(rx_buf,rx_buf_len,
				RHP_PROTO_STUN_ATTR_FINGERPRINT);

		if( attr_fp == NULL ){

			err = RHP_STATUS_INVALID_STUN_MESG_NO_FINGERPRINT;
			goto error;

		}else{

			u32 fp;
			int fp_buf_len = ((u8*)attr_fp) - ((u8*)header);
			int attr_len;

			if( (((u8*)attr_fp) + (int)sizeof(rhp_proto_stun_attr_fingerprint)) != endp ){
				err = RHP_STATUS_INVALID_STUN_MESG_BAD_POS;
				goto error;
			}

			attr_len = ntohs(attr_fp->attr_len);

			if( attr_len != ((int)sizeof(rhp_proto_stun_attr_fingerprint) - (int)sizeof(rhp_proto_stun_attr)) ){
				err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
				goto error;
			}

			fp = _rhp_stun_mesg_attr_fingerprint((u8*)header, fp_buf_len);

			if( fp != ntohl(attr_fp->crc32) ){

				RHP_TRC(0,RHPTRCID_STUN_RX_MESG_IS_STUN_INVALID_FINGERPRINT,"xxxp",rx_buf,fp,ntohl(attr_fp->crc32),(attr_len + sizeof(rhp_proto_stun_attr)),attr_fp);

				err = RHP_STATUS_INVALID_STUN_MESG_INVALID_FINGERPRINT;
				goto error;
			}
		}
	}

	if( attr_integ_r ){

		rhp_proto_stun_attr_mesg_integ* attr_integ
		= (rhp_proto_stun_attr_mesg_integ*)_rhp_stun_mesg_rx_seek_attr(rx_buf,rx_buf_len,
				RHP_PROTO_STUN_ATTR_MESSAGE_INTEGRITY);

		if( attr_integ ){

			int attr_len;

			if( (((u8*)attr_integ) + (int)sizeof(rhp_proto_stun_attr_mesg_integ)) > endp ){
				err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
				goto error;
			}

			if( fingerprint_flag ){

				if( (((u8*)attr_integ) + (int)sizeof(rhp_proto_stun_attr_mesg_integ)
						+ (int)sizeof(rhp_proto_stun_attr_fingerprint)) != endp ){

					err = RHP_STATUS_INVALID_STUN_MESG_BAD_POS;
					goto error;
				}

			}else{

				if( (((u8*)attr_integ) + (int)sizeof(rhp_proto_stun_attr_mesg_integ)) != endp ){
					err = RHP_STATUS_INVALID_STUN_MESG_BAD_POS;
					goto error;
				}
			}

			attr_len = (int)ntohs(attr_integ->attr_len);

			if( attr_len != ((int)sizeof(rhp_proto_stun_attr_mesg_integ) - (int)sizeof(rhp_proto_stun_attr)) ){
				err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
				goto error;
			}

			*attr_integ_r = attr_integ;

			RHP_TRC(0,RHPTRCID_STUN_RX_MESG_IS_STUN_ATTR_MESG_INTEG,"xp",rx_buf,(attr_len + sizeof(rhp_proto_stun_attr)),*attr_integ_r);
		}
	}

	if( attr_uname_r ){

		rhp_proto_stun_attr_username* attr_uname
		= (rhp_proto_stun_attr_username*)_rhp_stun_mesg_rx_seek_attr(rx_buf,rx_buf_len,
				RHP_PROTO_STUN_ATTR_USERNAME);

		if( attr_uname ){

			int attr_len;

			if( (((u8*)attr_uname) + (int)sizeof(rhp_proto_stun_attr_username)) > endp ){
				err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
				goto error;
			}

			attr_len = ntohs(attr_uname->attr_len);

			if( attr_len < 1 || attr_len > 513 ){
				err = RHP_STATUS_INVALID_STUN_MESG_ATTR_BAD_LENGTH;
				goto error;
			}

			*attr_uname_r = attr_uname;

			RHP_TRC(0,RHPTRCID_STUN_RX_MESG_IS_STUN_ATTR_UNAME,"xp",rx_buf,(attr_len + sizeof(rhp_proto_stun_attr)),*attr_uname_r);
		}
	}

	if( header_r ){

		*header_r = header;

		RHP_TRC(0,RHPTRCID_STUN_RX_MESG_IS_STUN_HEADER,"xp",rx_buf,sizeof(rhp_proto_stun),*header_r);
	}

	if( attr_top_r ){

		if( mesg_len ){

			*attr_top_r = (rhp_proto_stun_attr*)(header + 1);

			RHP_TRC(0,RHPTRCID_STUN_RX_MESG_IS_STUN_ATTR_TOP,"xp",rx_buf,sizeof(rhp_proto_stun_attr),*attr_top_r);

		}else{
			*attr_top_r = NULL;
		}
	}

	RHP_TRC(0,RHPTRCID_STUN_RX_MESG_IS_STUN_RTRN,"x",rx_buf);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_STUN_RX_MESG_IS_STUN_ERR,"xE",rx_buf,err);
	return err;
}

// Return 0 if Success.
int rhp_stun_rx_mesg_is_stun(u8* rx_buf, int rx_buf_len,int fingerprint_flag,
		rhp_proto_stun** header_r,rhp_proto_stun_attr** attr_top_r)
{
	return _rhp_stun_rx_mesg_is_stun(rx_buf,rx_buf_len,fingerprint_flag,header_r,attr_top_r,NULL,NULL);
}


static int _rhp_stun_mesg_check_attr(rhp_proto_stun_attr* stun_attr,u16 attr_type,int attr_len)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_STUN_MESG_CHECK_ATTR,"Lwp","STUN_ATTR_TYPE",attr_type,(attr_len + sizeof(rhp_proto_stun_attr)),stun_attr);

	switch( attr_type ){

	case RHP_PROTO_STUN_ATTR_MAPPED_ADDRESS:
	case RHP_PROTO_STUN_ATTR_XOR_MAPPED_ADDRESS:
	case RHP_PROTO_STUN_ATTR_ALTERNATE_SERVER:
	case RHP_PROTO_STUN_ATTR_XOR_PEER_ADDRESS	:
	case RHP_PROTO_STUN_ATTR_XOR_RELAYED_ADDRESS:
	{
		rhp_proto_stun_attr_mapped_addr* mapped_addr = (rhp_proto_stun_attr_mapped_addr*)stun_attr;

		if( attr_len + (int)sizeof(rhp_proto_stun_attr) < (int)sizeof(rhp_proto_stun_attr_mapped_addr) ){
			err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
			goto error;
		}

		if( mapped_addr->attr_val.addr_family == RHP_PROTO_STUN_AF_IPV4 ){

			if( attr_len + (int)sizeof(rhp_proto_stun_attr) != (int)sizeof(rhp_proto_stun_attr_mapped_addr) + 4 ){
				err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
				goto error;
			}

		}else 	if( mapped_addr->attr_val.addr_family == RHP_PROTO_STUN_AF_IPV6 ){

			if( attr_len + (int)sizeof(rhp_proto_stun_attr) != (int)sizeof(rhp_proto_stun_attr_mapped_addr) + 16 ){
				err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
				goto error;
			}

		}else{
			err = RHP_STATUS_INVALID_STUN_MESG_BAD_ADDR_FAMILY;
			goto error;
		}
	}
		break;

	case RHP_PROTO_STUN_ATTR_USERNAME:

		if( attr_len + (int)sizeof(rhp_proto_stun_attr) < (int)sizeof(rhp_proto_stun_attr_username) ){
			err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
			goto error;
		}

		if( attr_len < 1 || attr_len > 513 ){
			err = RHP_STATUS_INVALID_STUN_MESG_ATTR_BAD_LENGTH;
			goto error;
		}

		break;

	case RHP_PROTO_STUN_ATTR_REALM:

		if( attr_len + (int)sizeof(rhp_proto_stun_attr) < (int)sizeof(rhp_proto_stun_attr_realm) ){
			err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
			goto error;
		}

		if( attr_len < 1 || attr_len > 763 ){
			err = RHP_STATUS_INVALID_STUN_MESG_ATTR_BAD_LENGTH;
			goto error;
		}

		break;

	case RHP_PROTO_STUN_ATTR_SOFTWARE	:

		if( attr_len + (int)sizeof(rhp_proto_stun_attr) < (int)sizeof(rhp_proto_stun_attr_software) ){
			err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
			goto error;
		}

		if( attr_len < 1 || attr_len > 763 ){
			err = RHP_STATUS_INVALID_STUN_MESG_ATTR_BAD_LENGTH;
			goto error;
		}

		break;

	case RHP_PROTO_STUN_ATTR_MESSAGE_INTEGRITY:

		if( attr_len + (int)sizeof(rhp_proto_stun_attr) != (int)sizeof(rhp_proto_stun_attr_mesg_integ) ){
			err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
			goto error;
		}

		break;

	case RHP_PROTO_STUN_ATTR_ERROR_CODE:

		if( attr_len + (int)sizeof(rhp_proto_stun_attr) < (int)sizeof(rhp_proto_stun_attr_error_code) ){
			err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
			goto error;
		}

		if( attr_len - (int)sizeof(rhp_proto_stun_attr_error_code) > 763 ){
			err = RHP_STATUS_INVALID_STUN_MESG_ATTR_BAD_LENGTH;
			goto error;
		}

		break;

	case RHP_PROTO_STUN_ATTR_UNKNOWN_ATTRIBUTES:

		if( attr_len + (int)sizeof(rhp_proto_stun_attr) < (int)sizeof(rhp_proto_stun_attr_unknown_attrs) ){
			err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
			goto error;
		}

		if( attr_len < 2 || (attr_len & 0x0000001) ){
			err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
			goto error;
		}

		break;

	case RHP_PROTO_STUN_ATTR_NONCE:

		if( attr_len + (int)sizeof(rhp_proto_stun_attr) < (int)sizeof(rhp_proto_stun_attr_nonce) ){
			err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
			goto error;
		}

		if( attr_len < 1 || attr_len > 763 ){
			err = RHP_STATUS_INVALID_STUN_MESG_ATTR_BAD_LENGTH;
			goto error;
		}

		break;

	case RHP_PROTO_STUN_ATTR_FINGERPRINT	:

		if( attr_len + (int)sizeof(rhp_proto_stun_attr) != (int)sizeof(rhp_proto_stun_attr_fingerprint) ){
			err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
			goto error;
		}

		break;

	case RHP_PROTO_STUN_ATTR_CHANNEL_NUMBER	:

		if( attr_len + (int)sizeof(rhp_proto_stun_attr) != (int)sizeof(rhp_proto_stun_attr_channel_num) ){
			err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
			goto error;
		}

		break;

	case RHP_PROTO_STUN_ATTR_LIFETIME:

		if( attr_len + (int)sizeof(rhp_proto_stun_attr) != (int)sizeof(rhp_proto_stun_attr_lifetime) ){
			err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
			goto error;
		}

		break;

	case RHP_PROTO_STUN_ATTR_DATA:

		if( attr_len + (int)sizeof(rhp_proto_stun_attr) < (int)sizeof(rhp_proto_stun_attr_data) ){
			err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
			goto error;
		}

		if( attr_len < 1 ){
			err = RHP_STATUS_INVALID_STUN_MESG_ATTR_BAD_LENGTH;
			goto error;
		}

		break;

	case RHP_PROTO_STUN_ATTR_EVEN_PORT:

		if( attr_len + (int)sizeof(rhp_proto_stun_attr) != (int)sizeof(rhp_proto_stun_attr_even_port) ){
			err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
			goto error;
		}

		break;

	case RHP_PROTO_STUN_ATTR_REQUESTED_TRANSPORT:

		if( attr_len + (int)sizeof(rhp_proto_stun_attr) != (int)sizeof(rhp_proto_stun_attr_req_transport) ){
			err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
			goto error;
		}

		break;

	case RHP_PROTO_STUN_ATTR_DONT_FRAGMENT:

		if( attr_len + (int)sizeof(rhp_proto_stun_attr) != (int)sizeof(rhp_proto_stun_attr_dont_frag) ){
			err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
			goto error;
		}

		break;

	case RHP_PROTO_STUN_ATTR_RESERVATION_TOKEN:

		if( attr_len + (int)sizeof(rhp_proto_stun_attr) != (int)sizeof(rhp_proto_stun_attr_rsrv_token) ){
			err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
			goto error;
		}

		break;

	default:

		if( attr_len > rhp_gcfg_stun_max_attr_size ){
			err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
			goto error;
		}

		break;
	}

	RHP_TRC(0,RHPTRCID_STUN_MESG_CHECK_ATTR_RTRN,"Lwx","STUN_ATTR_TYPE",attr_type,stun_attr);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_STUN_MESG_CHECK_ATTR_ERR,"LwxE","STUN_ATTR_TYPE",attr_type,stun_attr,err);
	return err;
}

static int _rhp_stun_mesg_parse_attrs(rhp_stun_mesg* stun_mesg, rhp_proto_stun_attr* stun_attr_top)
{
	int err = -EINVAL;
	u8 *p, *endp;

	RHP_TRC(0,RHPTRCID_STUN_MESG_PARSE_ATTRS,"xx",stun_mesg,stun_attr_top);

	p = (u8*)stun_attr_top;
	endp = stun_mesg->head + stun_mesg->len;

	while( p < endp ){

		rhp_proto_stun_attr* stun_attr;
		int attr_len;
		int padlen;
		u16 attr_type;

		if( p + sizeof(rhp_proto_stun_attr) > endp ){
			err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
			goto error;
		}

		stun_attr = (rhp_proto_stun_attr*)p;

		attr_len = ntohs(stun_attr->attr_len);

		padlen = attr_len % 4;
		if( padlen ){
			padlen = 4 - padlen;
		}else{
			padlen = 0;
		}

		if( ((u8*)(stun_attr + 1))  + attr_len + padlen > endp ){
			err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
			goto error;
		}

		attr_type = ntohs(stun_attr->attr_type);

		err = _rhp_stun_mesg_check_attr(stun_attr,attr_type,attr_len);
		if( err ){
			goto error;
		}

		{
			rhp_stun_attr* attr = _rhp_stun_mesg_attr_alloc_raw();

			if( attr == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			attr->rx_attr = stun_attr;

			_rhp_mesg_put_attr_raw(stun_mesg,attr);
		}

		p += sizeof(rhp_proto_stun_attr) + attr_len + padlen;
	}

	if( p != endp ){
		err = RHP_STATUS_INVALID_STUN_MESG_BAD_LENGTH;
		goto error;
	}

	RHP_TRC(0,RHPTRCID_STUN_MESG_PARSE_ATTRS_RTRN,"xx",stun_mesg,stun_attr_top);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_STUN_MESG_PARSE_ATTRS_ERR,"xxE",stun_mesg,stun_attr_top,err);
	return err;
}


static int _rhp_stun_mesg_new_rx(u8* rx_buf, int rx_buf_len,
		rhp_proto_stun_attr* stun_attr_top,rhp_stun_mesg** stun_mesg_r)
{
	int err = -EINVAL;
	rhp_stun_mesg* stun_mesg = NULL;

	RHP_TRC(0,RHPTRCID_STUN_MESG_NEW_RX_IMPL,"pxx",rx_buf_len,rx_buf,stun_attr_top,stun_mesg_r);

	stun_mesg = _rhp_stun_mesg_alloc_raw();
	if( stun_mesg == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	stun_mesg->head = (u8*)_rhp_malloc(rx_buf_len);
	if( stun_mesg->head == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memcpy(stun_mesg->head,rx_buf,rx_buf_len);
	stun_mesg->len = rx_buf_len;


	if( stun_attr_top ){

		err = _rhp_stun_mesg_parse_attrs(stun_mesg,stun_attr_top);
		if( err ){
			goto error;
		}
	}

	*stun_mesg_r = stun_mesg;

	RHP_TRC(0,RHPTRCID_STUN_MESG_NEW_RX_IMPL_RTRN,"xx",rx_buf,*stun_mesg_r);
	return 0;

error:
	if( stun_mesg ){
		rhp_stun_mesg_free(stun_mesg);
	}
	RHP_TRC(0,RHPTRCID_STUN_MESG_NEW_RX_IMPL_ERR,"xE",rx_buf,err);
	return err;
}


int rhp_stun_mesg_new_rx(u8* rx_buf, int rx_buf_len, int fingerprint_flag,rhp_stun_mesg** stun_mesg_r)
{
	int err = -EINVAL;
	rhp_proto_stun* header;
	rhp_proto_stun_attr* stun_attr;
	rhp_stun_mesg* stun_mesg = NULL;

	RHP_TRC(0,RHPTRCID_STUN_MESG_NEW_RX,"pdx",rx_buf_len,rx_buf,fingerprint_flag,stun_mesg_r);

	err = _rhp_stun_rx_mesg_is_stun(rx_buf,rx_buf_len,fingerprint_flag,&header,&stun_attr,NULL,NULL);
	if( err ){
		goto error;
	}

	err = _rhp_stun_mesg_new_rx(rx_buf,rx_buf_len,stun_attr,&stun_mesg);
	if( err ){
		goto error;
	}

	*stun_mesg_r = stun_mesg;

	RHP_TRC(0,RHPTRCID_STUN_MESG_NEW_RX_RTRN,"xx",rx_buf,*stun_mesg_r);
	return 0;

error:
	if( stun_mesg ){
		rhp_stun_mesg_free(stun_mesg);
	}
	RHP_TRC(0,RHPTRCID_STUN_MESG_NEW_RX_ERR,"xE",rx_buf,err);
	return err;
}

int rhp_stun_mesg_new_rx_short_term_cred(u8* rx_buf, int rx_buf_len,int fingerprint_flag,
		u8* (*get_key)(u8* username, void* cb_get_key_ctx),void* get_key_ctx,
		rhp_stun_mesg** stun_mesg_r)
{
	int err = -EINVAL;
	rhp_proto_stun* header;
	rhp_proto_stun_attr* stun_attr;
	rhp_proto_stun_attr_mesg_integ* stun_attr_integ = NULL;
	rhp_proto_stun_attr_username* stun_attr_uname = NULL;
	rhp_stun_mesg* stun_mesg = NULL;
	u8* uname = NULL;
	u8* sterm_key;
	u8* hmac_buf = NULL;
	int hmac_buf_len = 0;

	RHP_TRC(0,RHPTRCID_STUN_MESG_NEW_RX_SHORT_TERM_CRED,"pdYxx",rx_buf_len,rx_buf,fingerprint_flag,get_key,get_key_ctx,stun_mesg_r);

	err = _rhp_stun_rx_mesg_is_stun(rx_buf,rx_buf_len,fingerprint_flag,
			&header,&stun_attr,&stun_attr_integ,&stun_attr_uname);
	if( err ){
		goto error;
	}

	if( stun_attr_integ == NULL ){
		err = RHP_STATUS_INVALID_STUN_MESG_ATTR_INTEG_REQUIRED;
		goto error;
	}

	if( stun_attr_uname == NULL ){
		err = RHP_STATUS_INVALID_STUN_MESG_ATTR_UNAME_REQUIRED;
		goto error;
	}

	{
		int attr_len = ntohs(stun_attr_uname->attr_len);

		uname = (u8*)_rhp_malloc(attr_len + 1);
		if( uname == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		memcpy(uname,(u8*)(stun_attr_uname + 1),attr_len);
		uname[attr_len] = '\0';
	}


	sterm_key = get_key(uname,get_key_ctx);
	if( sterm_key == NULL ){
		err = RHP_STATUS_INVALID_STUN_MESG_NO_STERM_CRED;
		goto error;
	}


	{
		int orig_mesg_len = ntohs(header->mesg_len);
		int hmac_in_len = ((u8*)stun_attr_integ) - ((u8*)header);
		int tmp_mesg_len =  hmac_in_len + sizeof(rhp_proto_stun_attr_mesg_integ);

		header->mesg_len = htons(tmp_mesg_len);

		err = rhp_crypto_hmac(RHP_CRYPTO_HMAC_SHA1,(u8*)header,hmac_in_len,
				sterm_key,strlen((char*)sterm_key),&hmac_buf,&hmac_buf_len);

		header->mesg_len = htons(orig_mesg_len);

		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		if( (hmac_buf_len != RHP_PROTO_STUN_ATTR_MESG_INTEG_SIZE) ||
				memcmp(hmac_buf,&(stun_attr_integ->hmac[0]),hmac_buf_len)  ){

			RHP_TRC(0,RHPTRCID_STUN_MESG_NEW_RX_SHORT_TERM_CRED_INVALID_HMAC,"xpp",rx_buf,hmac_buf_len,hmac_buf,RHP_PROTO_STUN_ATTR_MESG_INTEG_SIZE,&(stun_attr_integ->hmac[0]));

			err = RHP_STATUS_INVALID_STUN_MESG_BAD_INTEG;
			goto error;
		}
	}


	err = _rhp_stun_mesg_new_rx(rx_buf,rx_buf_len,stun_attr,&stun_mesg);
	if( err ){
		goto error;
	}

	_rhp_free(uname);
	_rhp_free(hmac_buf);

	*stun_mesg_r = stun_mesg;

	RHP_TRC(0,RHPTRCID_STUN_MESG_NEW_RX_SHORT_TERM_CRED_RTRN,"xx",rx_buf,*stun_mesg_r);
	return 0;

error:
	if( stun_mesg ){
		rhp_stun_mesg_free(stun_mesg);
	}
	if( uname ){
		_rhp_free(uname);
	}
	if( hmac_buf ){
		_rhp_free(hmac_buf);
	}
	RHP_TRC(0,RHPTRCID_STUN_MESG_NEW_RX_SHORT_TERM_CRED_ERR,"xE",rx_buf,err);
	return err;
}

int rhp_stun_mesg_new_rx_long_term_cred(u8* rx_buf, int rx_buf_len,int fingerprint_flag,
		int (*is_valid_nonce)(u8* realm, u8* username, u8* nonce, void* cb_vl_n_ctx),void* vl_n_ctx,
		void (*callback)(int err,rhp_stun_mesg* stun_mesg,void* cb_ctx),void* ctx)
{
	// TODO : NOT implemented yet.
	return -EINVAL;
}


rhp_stun_mesg* rhp_stun_mesg_new_tx(	u8 class, u16 method, u8* txn_id)
{
	rhp_stun_mesg* stun_mesg = NULL;

	if( txn_id == NULL ){

		RHP_TRC(0,RHPTRCID_STUN_MESG_NEW_TX_TXNID_NULL,"LbLw","STUN_CLASS",class,"STUN_METHOD",method);

		if( (class == RHP_PROTO_STUN_CLASS_RESP) || (class == RHP_PROTO_STUN_CLASS_ERROR) ){
			RHP_BUG("%d",class);
			goto error;
		}

	}else{

		RHP_TRC(0,RHPTRCID_STUN_MESG_NEW_TX,"LbLwp","STUN_CLASS",class,"STUN_METHOD",method,RHP_PROTO_STUN_TXN_ID_SIZE,txn_id);
	}

	stun_mesg = _rhp_stun_mesg_alloc_raw();
	if( stun_mesg == NULL ){
		RHP_BUG("");
		goto error;
	}

	stun_mesg->tx_header.magic_cookie = htonl(RHP_PROTO_STUN_MAGIC_COOKIE);
	stun_mesg->tx_header.mesg_type = _rhp_proto_stun_mesg_type(class,method);

	if( (class == RHP_PROTO_STUN_CLASS_REQ) || (class == RHP_PROTO_STUN_CLASS_INDICATION) ){

		if( rhp_random_bytes(&(stun_mesg->tx_header.txn_id[0]),RHP_PROTO_STUN_TXN_ID_SIZE) ){
			RHP_BUG("");
			goto error;
		}

	}else{

		memcpy(&(stun_mesg->tx_header.txn_id[0]),txn_id,RHP_PROTO_STUN_TXN_ID_SIZE);
	}

	RHP_TRC(0,RHPTRCID_STUN_MESG_NEW_TX_RTRN,"LbLwxx","STUN_CLASS",class,"STUN_METHOD",method,txn_id,stun_mesg);
	return stun_mesg;

error:
	if( stun_mesg ){
		rhp_stun_mesg_free(stun_mesg);
	}
	RHP_TRC(0,RHPTRCID_STUN_MESG_NEW_TX_ERR,"LbLwxx","STUN_CLASS",class,"STUN_METHOD",method,txn_id);
	return NULL;
}


