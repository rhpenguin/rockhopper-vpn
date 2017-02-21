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
#include "rhp_wthreads.h"
#include "rhp_timer.h"
#include "rhp_packet.h"
#include "rhp_netsock.h"
#include "rhp_packet.h"
#include "rhp_config.h"
#include "rhp_crypto.h"
#include "rhp_radius_impl.h"
#include "rhp_radius_priv.h"


struct _rhp_radius_enum_attr_ctx {
	void* list_head;
	void* list_tail;
	unsigned long priv[4];
};
typedef struct _rhp_radius_enum_attr_ctx	rhp_radius_enum_attr_ctx;


int rhp_radius_rx_basic_attr_to_ipv4(rhp_radius_mesg* rx_radius_mesg,
		u8 attr_type,rhp_ip_addr* addr_r)
{
	int err = -EINVAL;
	rhp_radius_attr* radius_attr
		= rx_radius_mesg->get_attr(rx_radius_mesg,attr_type,NULL);
	u8* val = NULL;
	int val_len = 0;

	if( radius_attr ){

		val = radius_attr->ext.basic->get_attr_value(radius_attr,&val_len);
		if( val == NULL || val_len != 4 ){
			err = RHP_STATUS_RADIUS_INVALID_ATTR;
			RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_IPV4_INVALID_ATTR,"xxd",rx_radius_mesg,val,val_len);
			goto error;
		}

		memset(addr_r,0,sizeof(rhp_ip_addr));

		addr_r->addr_family = AF_INET;
		addr_r->addr.v4 = *((u32*)val);

	}else{

		err = -ENOENT;
		goto error;
	}

	RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_IPV4,"xLbxxp",rx_radius_mesg,"RADIUS_ATTR",attr_type,radius_attr,addr_r,val_len,val);
	rhp_ip_addr_dump("*addr_r",addr_r);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_IPV4_ERR,"xLbxxpE",rx_radius_mesg,"RADIUS_ATTR",attr_type,radius_attr,addr_r,val_len,val,err);
	return err;
}

int rhp_radius_rx_basic_attr_to_ipv6(rhp_radius_mesg* rx_radius_mesg,
		u8 attr_type,rhp_ip_addr* addr_r)
{
	int err = -EINVAL;
	rhp_radius_attr* radius_attr
		= rx_radius_mesg->get_attr(rx_radius_mesg,attr_type,NULL);
	u8* val = NULL;
	int val_len = 0;

	if( radius_attr ){

		val = radius_attr->ext.basic->get_attr_value(radius_attr,&val_len);
		if( val == NULL || val_len != 16 ){
			err = RHP_STATUS_RADIUS_INVALID_ATTR;
			RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_IPV6_INVALID_ATTR,"xxd",rx_radius_mesg,val,val_len);
			goto error;
		}

		memset(addr_r,0,sizeof(rhp_ip_addr));

		addr_r->addr_family = AF_INET6;
		memcpy(addr_r->addr.v6,val,16);

	}else{

		err = -ENOENT;
		goto error;
	}

	RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_IPV6,"xLbxxp",rx_radius_mesg,"RADIUS_ATTR",attr_type,radius_attr,addr_r,val_len,val);
	rhp_ip_addr_dump("*addr_r",addr_r);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_IPV6_ERR,"xLbxxpE",rx_radius_mesg,"RADIUS_ATTR",attr_type,radius_attr,addr_r,val_len,val,err);
	return err;
}

int rhp_radius_rx_basic_attr_to_ip_list(rhp_radius_mesg* rx_radius_mesg,
		u8 attr_type,int addr_family,rhp_ip_addr_list** addr_list_r)
{
/*
	int err = -ENOMEM;
	rhp_ip_addr_list* addr_list = NULL;

	addr_list = (rhp_ip_addr_list*)_rhp_malloc(sizeof(rhp_ip_addr_list));
	if( addr_list == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	memset(addr_list,0,sizeof(rhp_ip_addr_list));

	if( addr_family == AF_INET ){

		err = _rhp_radius_rx_basic_attr_ipv4(radius_sess,radius_sess_priv,rx_radius_mesg,
					attr_type,&(addr_list->ip_addr));

	}else if( addr_family == AF_INET ){

		err = _rhp_radius_rx_basic_attr_ipv6(radius_sess,radius_sess_priv,rx_radius_mesg,
					attr_type,&(addr_list->ip_addr));

	}else{
		RHP_BUG("%d",addr_family);
		err = -EINVAL;
	}

	if( err ){
		goto error;
	}

	*addr_list_r = addr_list;

	return 0;

error:
	if( addr_list ){
		_rhp_free(addr_list);
	}
	return err;
*/
	RHP_BUG("");
	return -EINVAL;
}

int rhp_radius_rx_basic_attr_to_u32(rhp_radius_mesg* rx_radius_mesg,
		u8 attr_type,u32* ret_r)
{
	int err = -EINVAL;
	rhp_radius_attr* radius_attr
		= rx_radius_mesg->get_attr(rx_radius_mesg,attr_type,NULL);
	u8* val = NULL;
	int val_len = 0;

	if( radius_attr ){

		val = radius_attr->ext.basic->get_attr_value(radius_attr,&val_len);
		if( val == NULL || val_len != 4 ){
			err = RHP_STATUS_RADIUS_INVALID_ATTR;
			RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_U32_INVALID_ATTR,"xxd",rx_radius_mesg,val,val_len);
			goto error;
		}

		*ret_r = ntohl(*((u32*)val));

	}else{

		err = -ENOENT;
		goto error;
	}

	RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_U32,"xLbxxjp",rx_radius_mesg,"RADIUS_ATTR",attr_type,radius_attr,ret_r,*ret_r,val_len,val);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_U32_ERR,"xLbxxpE",rx_radius_mesg,"RADIUS_ATTR",attr_type,radius_attr,ret_r,val_len,val,err);
	return err;
}

int rhp_radius_rx_basic_attr_to_string(rhp_radius_mesg* rx_radius_mesg,
		u8 attr_type,int is_tunnel_attr,char* priv_attr_string_value_tag,char** ret_r)
{
	int err = -EINVAL;
	rhp_radius_attr* radius_attr
		= rx_radius_mesg->get_attr(rx_radius_mesg,attr_type,priv_attr_string_value_tag);
	char* val = NULL;
	int val_len = 0;
	char* ret = NULL;

	if( radius_attr ){

		val = (char*)radius_attr->ext.basic->get_attr_value(radius_attr,&val_len);
		if( val == NULL || val_len < 1 ){
			err = RHP_STATUS_RADIUS_INVALID_ATTR;
			RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_STRING_INVALID_ATTR,"xxd",rx_radius_mesg,val,val_len);
			goto error;
		}

		if( is_tunnel_attr ){

			if( val[0] <= 0x1F ){
				val++;
				val_len--;
			}

			if( val_len < 1 ){
				err = RHP_STATUS_RADIUS_INVALID_ATTR;
				RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_STRING_INVALID_ATTR_2,"xxd",rx_radius_mesg,val,val_len);
				goto error;
			}
		}

		if( priv_attr_string_value_tag ){

			int slen = strlen(priv_attr_string_value_tag);

			val += slen;
			val_len -= slen;

			if( val_len < 1 ){
				err = RHP_STATUS_RADIUS_INVALID_ATTR;
				RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_STRING_INVALID_ATTR_3,"xxdsd",rx_radius_mesg,val,val_len,priv_attr_string_value_tag,slen);
				goto error;
			}
		}

		ret = (char*)_rhp_malloc(val_len + 1);
		if( ret == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		memcpy(ret,val,val_len);
		ret[val_len] = '\0';

		if( *ret_r ){
			_rhp_free(*ret_r);
			*ret_r = NULL;
		}

		*ret_r = ret;

	}else{

		err = -ENOENT;
		goto error;
	}

	RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_STRING,"xLbxxsps",rx_radius_mesg,"RADIUS_ATTR",attr_type,radius_attr,ret_r,*ret_r,val_len,val,priv_attr_string_value_tag);
	return 0;

error:
	if( ret ){
		_rhp_free(ret);
	}
	RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_STRING_ERR,"xLbxxpsE",rx_radius_mesg,"RADIUS_ATTR",attr_type,radius_attr,ret_r,val_len,val,priv_attr_string_value_tag,err);
	return err;
}

static int _rhp_radius_rx_basic_attr_string_list_cb(rhp_radius_mesg* rx_radius_mesg,
		rhp_radius_attr* radius_attr,char* priv_attr_string_value_tag,void* cb_ctx)
{
	int err = -EINVAL;
	union {
		void* raw;
		rhp_string_list* str_lst;
		rhp_split_dns_domain* domain;
	} ret;
	rhp_radius_enum_attr_ctx* ctx = (rhp_radius_enum_attr_ctx*)cb_ctx;
	char* val = NULL;
	int val_len = 0;
	int is_tunnel_attr = (int)ctx->priv[0];
	int is_dns_domain = (int)ctx->priv[1];
	int ret_len = (is_dns_domain ? sizeof(rhp_split_dns_domain) : sizeof(rhp_string_list));

	val = (char*)radius_attr->ext.basic->get_attr_value(radius_attr,&val_len);
	if( val == NULL || val_len < 1 ){
		err = RHP_STATUS_RADIUS_INVALID_ATTR;
		RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_STRING_LIST_CB_INVALID_ATTR,"xxd",rx_radius_mesg,val,val_len);
		goto error;
	}

	if( is_tunnel_attr ){

		if( val[0] <= 0x1F ){
			val++;
			val_len--;
		}

		if( val_len < 1 ){
			err = RHP_STATUS_RADIUS_INVALID_ATTR;
			RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_STRING_LIST_CB_INVALID_ATTR_2,"xxd",rx_radius_mesg,val,val_len);
			goto error;
		}
	}

	if( priv_attr_string_value_tag ){

		int slen = strlen(priv_attr_string_value_tag);

		val += slen;
		val_len -= slen;

		if( val_len < 1 ){
			err = RHP_STATUS_RADIUS_INVALID_ATTR;
			RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_STRING_LIST_CB_INVALID_ATTR_3,"xxdsd",rx_radius_mesg,val,val_len,priv_attr_string_value_tag,slen);
			goto error;
		}
	}


	ret.raw = _rhp_malloc(ret_len);
	if( ret.raw == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	memset(ret.raw,0,ret_len);

	if( is_dns_domain ){

		ret.domain->tag[0] = '#';
		ret.domain->tag[1] = 'C';
		ret.domain->tag[2] = 'S';
		ret.domain->tag[3] = 'D';

		ret.domain->name = (char*)_rhp_malloc(val_len + 1);
		if( ret.domain->name == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		memcpy(ret.domain->name,val,val_len);
		ret.domain->name[val_len] = '\0';

	}else{

		ret.str_lst->string = (char*)_rhp_malloc(val_len + 1);
		if( ret.str_lst->string == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		memcpy(ret.str_lst->string,val,val_len);
		ret.str_lst->string[val_len] = '\0';
	}

	if( ctx->list_head == NULL ){
		ctx->list_head = ret.raw;
	}else{
		if( is_dns_domain ){
			((rhp_split_dns_domain*)ctx->list_tail)->next = ret.raw;
		}else{
			((rhp_string_list*)ctx->list_tail)->next = ret.raw;
		}
	}
	ctx->list_tail = ret.raw;

	if( is_dns_domain ){
		RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_STRING_LIST_CB_DNS_DOMAIN,"xLbxxsdps",rx_radius_mesg,"RADIUS_ATTR",radius_attr->get_attr_type(radius_attr),radius_attr,ret.domain,ret.domain->name,ret.domain->ikev2_cfg,val_len,val,priv_attr_string_value_tag);
	}else{
		RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_STRING_LIST_CB,"xLbxxsps",rx_radius_mesg,"RADIUS_ATTR",radius_attr->get_attr_type(radius_attr),radius_attr,ret.str_lst,ret.str_lst->string,val_len,val,priv_attr_string_value_tag);
	}
	return 0;

error:
	if( is_dns_domain ){
		_rhp_split_dns_domain_free(ret.domain);
	}else{
		_rhp_string_list_free(ret.str_lst);
	}
	RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_STRING_LIST_CB_ERR,"xLbxpsE",rx_radius_mesg,"RADIUS_ATTR",(radius_attr ? radius_attr->get_attr_type(radius_attr) : 0),radius_attr,val_len,val,priv_attr_string_value_tag,err);
	return err;
}

int rhp_radius_rx_basic_attr_to_string_list(rhp_radius_mesg* rx_radius_mesg,
		u8 attr_type,int is_tunnel_attr,char* priv_attr_string_value_tag,rhp_string_list** ret_head_r)
{
	int err = -EINVAL;
	rhp_radius_enum_attr_ctx ctx;

	memset(&ctx,0,sizeof(rhp_radius_enum_attr_ctx));

	ctx.priv[0] = (unsigned long)is_tunnel_attr;
	ctx.priv[1] = (unsigned long)0;

	err = rx_radius_mesg->enum_attrs(rx_radius_mesg,attr_type,priv_attr_string_value_tag,
					_rhp_radius_rx_basic_attr_string_list_cb,&ctx);
	if( err ){
		goto error;
	}

	if( *ret_head_r ){
		_rhp_string_list_free(*ret_head_r);
		*ret_head_r = NULL;
	}

	*ret_head_r = (rhp_string_list*)ctx.list_head;

	RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_STRING_LIST,"xLbsx",rx_radius_mesg,"RADIUS_ATTR",attr_type,priv_attr_string_value_tag,*ret_head_r);
	return 0;

error:
	_rhp_string_list_free(ctx.list_head);
	RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_STRING_LIST_ERR,"xLbxsE",rx_radius_mesg,"RADIUS_ATTR",attr_type,ret_head_r,priv_attr_string_value_tag,err);
	return err;
}

int rhp_radius_rx_basic_attr_to_domain_list(rhp_radius_mesg* rx_radius_mesg,
		u8 attr_type,char* priv_attr_string_value_tag,rhp_split_dns_domain** ret_head_r)
{
	int err = -EINVAL;
	rhp_radius_enum_attr_ctx ctx;

	memset(&ctx,0,sizeof(rhp_radius_enum_attr_ctx));

	ctx.priv[0] = 0;
	ctx.priv[1] = (unsigned long)1;

	err = rx_radius_mesg->enum_attrs(rx_radius_mesg,attr_type,priv_attr_string_value_tag,
					_rhp_radius_rx_basic_attr_string_list_cb,&ctx);
	if( err ){
		goto error;
	}

	if( *ret_head_r ){
		_rhp_split_dns_domain_free(*ret_head_r);
		*ret_head_r = NULL;
	}

	*ret_head_r = (rhp_split_dns_domain*)ctx.list_head;

	RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_DOMAIN_LIST,"xLbsx",rx_radius_mesg,"RADIUS_ATTR",attr_type,priv_attr_string_value_tag,*ret_head_r);
	return 0;

error:
	_rhp_split_dns_domain_free(ctx.list_head);
	RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_DOMAIN_LIST_ERR,"xLbxsE",rx_radius_mesg,"RADIUS_ATTR",attr_type,ret_head_r,priv_attr_string_value_tag,err);
	return err;
}

int rhp_radius_rx_basic_attr_to_bin(rhp_radius_mesg* rx_radius_mesg,
		u8 attr_type,u8** ret_r,int* ret_len_r)
{
	int err = -EINVAL;
	rhp_radius_attr* radius_attr
		= rx_radius_mesg->get_attr(rx_radius_mesg,attr_type,NULL);
	u8* val = NULL;
	int val_len = 0;
	u8* ret = NULL;

	if( radius_attr ){

		val = radius_attr->ext.basic->get_attr_value(radius_attr,&val_len);
		if( val == NULL || val_len < 1 ){
			err = RHP_STATUS_RADIUS_INVALID_ATTR;
			RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_BIN_INVALID_ATTR,"xxd",rx_radius_mesg,val,val_len);
			goto error;
		}

		ret = (u8*)_rhp_malloc(val_len);
		if( ret == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		memcpy(ret,val,val_len);

		*ret_r = ret;
		*ret_len_r = val_len;

	}else{

		err = -ENOENT;
		goto error;
	}

	RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_BIN,"xLbxpp",rx_radius_mesg,"RADIUS_ATTR",attr_type,radius_attr,*ret_len_r,*ret_r,val_len,val);
	return 0;

error:
	if( ret ){
		_rhp_free(ret);
	}
	RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_BIN_ERR,"xLbxxxpE",rx_radius_mesg,"RADIUS_ATTR",attr_type,radius_attr,ret_len_r,ret_r,val_len,val,err);
	return err;
}

int rhp_radius_rx_basic_attr_str_to_ipv4_impl(rhp_radius_mesg* rx_radius_mesg,
		rhp_radius_attr* radius_attr,char* priv_attr_string_value_tag,rhp_ip_addr* addr_r)
{
	int err = -EINVAL;
	char *val = NULL, *p = NULL;
	int val_len = 0, i, pn = 0;
	rhp_ip_addr addr;
  char* endp;

	if( radius_attr ){

		val = (char*)radius_attr->ext.basic->get_attr_value(radius_attr,&val_len);
		if( val == NULL || val_len < 8 ){
			err = RHP_STATUS_RADIUS_INVALID_ATTR;
			RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_IPV4_STR_INVALID_ATTR,"xxd",rx_radius_mesg,val,val_len);
			goto error;
		}

		if( priv_attr_string_value_tag ){

			int slen = strlen(priv_attr_string_value_tag);

			val += slen;
			val_len -= slen;

			if( val_len < 1 ){
				err = RHP_STATUS_RADIUS_INVALID_ATTR;
				RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_IPV4_STR_INVALID_ATTR_2,"xxdsd",rx_radius_mesg,val,val_len,priv_attr_string_value_tag,slen);
				goto error;
			}
		}

		memset(&addr,0,sizeof(rhp_ip_addr));
		addr.addr_family = AF_INET;

		for( i = 0; i < val_len; i++ ){

			if( i > 17 ){
				err = RHP_STATUS_RADIUS_INVALID_ATTR;
				RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_IPV4_STR_INVALID_ATTR_3,"xp",rx_radius_mesg,val_len,val);
				goto error;
			}

			// '.': 0x2e, '/': 0x2f, '0':0x30, '9':0x39
			if( pn > 3 || (val[i] == 0x2f && p) ||
					(val[i] != 0x2e && val[i] != 0x2f && val[i] < 0x30) ||
					val[i] > 0x39 ){
				err = RHP_STATUS_RADIUS_INVALID_ATTR;
				RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_IPV4_STR_INVALID_ATTR_4,"xp",rx_radius_mesg,val_len,val);
				goto error;
			}

			if( val[i] == 0x2f ){

				p = &(val[i]);

				if( i < 7 ){
					err = RHP_STATUS_RADIUS_INVALID_ATTR;
					RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_IPV4_STR_INVALID_ATTR_5,"xp",rx_radius_mesg,val_len,val);
					goto error;
				}

				if( ((val + val_len) - p) > 3  ){
					err = RHP_STATUS_RADIUS_INVALID_ATTR;
					RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_IPV4_STR_INVALID_ATTR_6,"xp",rx_radius_mesg,val_len,val);
					goto error;
				}

			}else if( val[i] == 0x2e ){
				pn++;
			}
		}

    if( p ){

    	char tmp[3] = {'\0','\0','\0'};

    	memcpy(tmp,(p + 1),((val + val_len) - p - 1));

      *p = '\0';

      if( rhp_ip_str2addr(AF_INET,val,&addr) ){
        *p = '/';
				err = RHP_STATUS_RADIUS_INVALID_ATTR;
				RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_IPV4_STR_INVALID_ATTR_7,"xp",rx_radius_mesg,val_len,val);
				goto error;
      }

      *p = '/';

      addr.prefixlen = (u8)strtol(tmp,&endp,10);
      if( *endp != '\0' ){
				err = RHP_STATUS_RADIUS_INVALID_ATTR;
				RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_IPV4_STR_INVALID_ATTR_8,"xp",rx_radius_mesg,val_len,val);
				goto error;
      }

      if( addr.prefixlen < 0 || addr.prefixlen > 32 ){
				err = RHP_STATUS_RADIUS_INVALID_ATTR;
				RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_IPV4_STR_INVALID_ATTR_9,"xp",rx_radius_mesg,val_len,val);
				goto error;
      }

      addr.netmask.v4 = rhp_ipv4_prefixlen_to_netmask(addr.prefixlen);

    }else{

    	char v4addr_tmp[16];

			if( i > 15 ){
				err = RHP_STATUS_RADIUS_INVALID_ATTR;
				RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_IPV4_STR_INVALID_ATTR_10,"xp",rx_radius_mesg,val_len,val);
				goto error;
			}

			memcpy(v4addr_tmp,val,val_len);
			v4addr_tmp[val_len] = '\0';

      if( rhp_ip_str2addr(AF_INET,v4addr_tmp,&addr) ){
				err = RHP_STATUS_RADIUS_INVALID_ATTR;
				RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_IPV4_STR_INVALID_ATTR_11,"xp",rx_radius_mesg,val_len,val);
				goto error;
      }
    }

		memcpy(addr_r,&addr,sizeof(rhp_ip_addr));

	}else{

		err = -ENOENT;
		goto error;
	}

	RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_STR_IPV4_IMPL,"xLbxxps",rx_radius_mesg,"RADIUS_ATTR",radius_attr->get_attr_type(radius_attr),radius_attr,addr_r,val_len,val,priv_attr_string_value_tag);
	rhp_ip_addr_dump("*addr_r",addr_r);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_STR_IPV4_IMPL_ERR,"xLbxxpsE",rx_radius_mesg,"RADIUS_ATTR",(radius_attr ? radius_attr->get_attr_type(radius_attr) : 0),radius_attr,addr_r,val_len,val,priv_attr_string_value_tag,err);
	return err;
}

int rhp_radius_rx_basic_attr_str_to_ipv4(rhp_radius_mesg* rx_radius_mesg,
		u8 attr_type,char* priv_attr_string_value_tag,rhp_ip_addr* addr_r)
{
	int err = -ENOENT;
	rhp_radius_attr* radius_attr
		= rx_radius_mesg->get_attr(rx_radius_mesg,attr_type,priv_attr_string_value_tag);

	if( radius_attr ){

		err = rhp_radius_rx_basic_attr_str_to_ipv4_impl(rx_radius_mesg,
					radius_attr,priv_attr_string_value_tag,addr_r);
	}

	RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_STR_IPV4,"xLbxsE",rx_radius_mesg,"RADIUS_ATTR",attr_type,addr_r,priv_attr_string_value_tag,err);
	return err;
}

int rhp_radius_rx_basic_attr_str_to_ipv6_impl(rhp_radius_mesg* rx_radius_mesg,
		rhp_radius_attr* radius_attr,char* priv_attr_string_value_tag,rhp_ip_addr* addr_r)
{
	int err = -EINVAL;
	char *val = NULL, *p = NULL;
	int val_len = 0, i, pn = 0;
	rhp_ip_addr addr;
  char* endp;

	if( radius_attr ){

		val = (char*)radius_attr->ext.basic->get_attr_value(radius_attr,&val_len);
		if( val == NULL || val_len < 2 ){
			err = RHP_STATUS_RADIUS_INVALID_ATTR;
			RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_IPV6_STR_INVALID_ATTR,"xxd",rx_radius_mesg,val,val_len);
			goto error;
		}

		if( priv_attr_string_value_tag ){

			int slen = strlen(priv_attr_string_value_tag);

			val += slen;
			val_len -= slen;

			if( val_len < 1 ){
				err = RHP_STATUS_RADIUS_INVALID_ATTR;
				RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_IPV6_STR_INVALID_ATTR_2,"xxdsd",rx_radius_mesg,val,val_len,priv_attr_string_value_tag,slen);
				goto error;
			}
		}

		memset(&addr,0,sizeof(rhp_ip_addr));
		addr.addr_family = AF_INET6;

		for( i = 0; i < val_len; i++ ){

			if( i > 41 ){
				err = RHP_STATUS_RADIUS_INVALID_ATTR;
				RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_IPV6_STR_INVALID_ATTR_3,"xp",rx_radius_mesg,val_len,val);
				goto error;
			}

			// ':': 0x3a, '/': 0x2f, '0':0x30, '9':0x39, 'a':0x61 , 'z':0x7a , 'A':0x41 , 'Z':0x5a

			if( pn > 7 || (val[i] == 0x2f && p) ||
					!( val[i] == 0x3a ||
						 val[i] == 0x2f ||
						 (val[i] >= 0x30 && val[i] <= 0x39) ||
						 (val[i] >= 0x61 && val[i] <= 0x7a) ||
						 (val[i] >= 0x41 && val[i] <= 0x5a) ) ){
				err = RHP_STATUS_RADIUS_INVALID_ATTR;
				RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_IPV6_STR_INVALID_ATTR_4,"xp",rx_radius_mesg,val_len,val);
				goto error;
			}

			if( val[i] == 0x2f ){

				p = &(val[i]);

				if( i < 2 ){
					err = RHP_STATUS_RADIUS_INVALID_ATTR;
					RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_IPV6_STR_INVALID_ATTR_5,"xp",rx_radius_mesg,val_len,val);
					goto error;
				}

				if( ((val + val_len) - p) > 3  ){
					err = RHP_STATUS_RADIUS_INVALID_ATTR;
					RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_IPV6_STR_INVALID_ATTR_6,"xp",rx_radius_mesg,val_len,val);
					goto error;
				}

			}else if( val[i] == 0x2e ){
				pn++;
			}
		}

    if( p ){

    	char tmp[3] = {'\0','\0','\0'};

    	memcpy(tmp,(p + 1),((val + val_len) - p - 1));

      *p = '\0';

      if( rhp_ip_str2addr(AF_INET6,val,&addr) ){
        *p = '/';
				err = RHP_STATUS_RADIUS_INVALID_ATTR;
				RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_IPV6_STR_INVALID_ATTR_7,"xp",rx_radius_mesg,val_len,val);
				goto error;
      }

      *p = '/';

      addr.prefixlen = (u8)strtol(tmp,&endp,10);
      if( *endp != '\0' ){
				err = RHP_STATUS_RADIUS_INVALID_ATTR;
				RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_IPV6_STR_INVALID_ATTR_8,"xp",rx_radius_mesg,val_len,val);
				goto error;
      }

      if( addr.prefixlen < 0 || addr.prefixlen > 128 ){
				err = RHP_STATUS_RADIUS_INVALID_ATTR;
				RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_IPV6_STR_INVALID_ATTR_9,"xp",rx_radius_mesg,val_len,val);
				goto error;
      }

      rhp_ipv6_prefixlen_to_netmask(addr.prefixlen,addr.netmask.v6);

    }else{

    	char v6addr_tmp[39];

			if( i > 38 ){
				err = RHP_STATUS_RADIUS_INVALID_ATTR;
				RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_IPV6_STR_INVALID_ATTR_10,"xp",rx_radius_mesg,val_len,val);
				goto error;
			}

			memcpy(v6addr_tmp,val,val_len);
			v6addr_tmp[val_len] = '\0';

      if( rhp_ip_str2addr(AF_INET6,v6addr_tmp,&addr) ){
				err = RHP_STATUS_RADIUS_INVALID_ATTR;
				RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_IPV6_STR_INVALID_ATTR_11,"xp",rx_radius_mesg,val_len,val);
				goto error;
      }
    }

		memcpy(addr_r,&addr,sizeof(rhp_ip_addr));

	}else{

		err = -ENOENT;
		goto error;
	}

	RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_STR_IPV6_IMPL,"xLbxxps",rx_radius_mesg,"RADIUS_ATTR",radius_attr->get_attr_type(radius_attr),radius_attr,addr_r,val_len,val,priv_attr_string_value_tag);
	rhp_ip_addr_dump("*addr_r",addr_r);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_STR_IPV6_IMPL_ERR,"xLbxxpsE",rx_radius_mesg,"RADIUS_ATTR",(radius_attr ? radius_attr->get_attr_type(radius_attr) : 0),radius_attr,addr_r,val_len,val,priv_attr_string_value_tag,err);
	return err;
}

int rhp_radius_rx_basic_attr_str_to_ipv6(rhp_radius_mesg* rx_radius_mesg,
		u8 attr_type,char* priv_attr_string_value_tag,rhp_ip_addr* addr_r)
{
	int err = -ENOENT;
	rhp_radius_attr* radius_attr
		= rx_radius_mesg->get_attr(rx_radius_mesg,attr_type,priv_attr_string_value_tag);

	if( radius_attr ){
		err = rhp_radius_rx_basic_attr_str_to_ipv6_impl(rx_radius_mesg,
					radius_attr,priv_attr_string_value_tag,addr_r);
	}

	RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_STR_IPV6,"xLbxsE",rx_radius_mesg,"RADIUS_ATTR",attr_type,addr_r,priv_attr_string_value_tag,err);
	return err;
}

static int _rhp_radius_rx_basic_attr_rt_map_str_list_cb(rhp_radius_mesg* rx_radius_mesg,
		rhp_radius_attr* radius_attr,char* priv_attr_string_value_tag,void* cb_ctx)
{
	int err = -EINVAL;
	rhp_internal_route_map* ret = NULL;
	rhp_radius_enum_attr_ctx* ctx = (rhp_radius_enum_attr_ctx*)cb_ctx;
	u8* val = NULL;
	int val_len = 0;

	val = radius_attr->ext.basic->get_attr_value(radius_attr,&val_len);
	if( val == NULL || val_len < 1 ){
		err = RHP_STATUS_RADIUS_INVALID_ATTR;
		RHP_TRC(0,RHPTRCID_RADIUS_RX_BASIC_ATTR_IP_STR_LIST_CB_INVALID_ATTR,"xxd",rx_radius_mesg,val,val_len);
		goto error;
	}

	ret = (rhp_internal_route_map*)_rhp_malloc(sizeof(rhp_internal_route_map));
	if( ret == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memset(ret,0,sizeof(rhp_ip_addr_list));
	ret->tag[0] = '#';
	ret->tag[0] = 'I';
	ret->tag[0] = 'R';
	ret->tag[0] = 'T';


	if( ctx->priv[0] == AF_INET ){

		err = rhp_radius_rx_basic_attr_str_to_ipv4_impl(rx_radius_mesg,
						radius_attr,priv_attr_string_value_tag,&(ret->dest_addr));

	}else if( ctx->priv[0] == AF_INET6 ){

		err = rhp_radius_rx_basic_attr_str_to_ipv6_impl(rx_radius_mesg,
						radius_attr,priv_attr_string_value_tag,&(ret->dest_addr));

	}else{
		RHP_BUG("%d",ctx->priv[0]);
		err = -ENOMEM;
		goto error;
	}

	if( ctx->list_head == NULL ){
		ctx->list_head = ret;
	}else{
		((rhp_internal_route_map*)ctx->list_tail)->next = ret;
	}
	ctx->list_tail = ret;

	RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_STR_RT_MAP_LIST_CB,"xLbxxp",rx_radius_mesg,"RADIUS_ATTR",radius_attr->get_attr_type(radius_attr),radius_attr,ret,val_len,val);
	rhp_ip_addr_dump("*ret->dest_addr",&(ret->dest_addr));
	return 0;

error:
	if( ret ){
		_rhp_free(ret);
	}
	RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_STR_RT_MAP_LIST_CB_ERR,"xLbxxpE",rx_radius_mesg,"RADIUS_ATTR",radius_attr->get_attr_type(radius_attr),radius_attr,ret,val_len,val,err);
	return err;
}

int rhp_radius_rx_basic_attr_str_to_rt_map_list(rhp_radius_mesg* rx_radius_mesg,
		u8 attr_type,int addr_family,char* priv_attr_string_value_tag,rhp_internal_route_map** ret_head_r)
{
	int err = -EINVAL;
	rhp_radius_enum_attr_ctx ctx;
	rhp_internal_route_map *tmp, *tmp_n;

	memset(&ctx,0,sizeof(rhp_radius_enum_attr_ctx));

	ctx.priv[0] = (unsigned long)addr_family;

	err = rx_radius_mesg->enum_attrs(rx_radius_mesg,attr_type,priv_attr_string_value_tag,
			_rhp_radius_rx_basic_attr_rt_map_str_list_cb,&ctx);
	if( err ){
		goto error;
	}

	if( *ret_head_r ){
		tmp = *ret_head_r;
		while( tmp ){
			tmp_n = tmp->next;
			_rhp_free(tmp);
			tmp = tmp_n;
		}
	}

	*ret_head_r = (rhp_internal_route_map*)ctx.list_head;

	RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_STR_RT_MAP_LIST,"xLbLdxx",rx_radius_mesg,"RADIUS_ATTR",attr_type,"AF",addr_family,ret_head_r,*ret_head_r);
	return 0;

error:
	{
		tmp = (rhp_internal_route_map*)ctx.list_head;
		while( tmp ){
			tmp_n = tmp->next;
			_rhp_free(tmp);
			tmp = tmp_n;
		}
	}
	RHP_TRC(0,RHPTRCID_RADIUS_RX_ATTR_PARSE_STR_RT_MAP_LIST_ERR,"xLbLdxE",rx_radius_mesg,"RADIUS_ATTR",attr_type,"AF",addr_family,ret_head_r,err);
	return err;
}


