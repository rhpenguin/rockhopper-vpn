/*

	Copyright (C) 2015-2016 TETSUHARU HANADA <rhpenguine@gmail.com>
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
#include "rhp_config.h"
#include "rhp_vpn.h"
#include "rhp_ikev2.h"
#include "rhp_ikev2_mesg.h"
#include "rhp_forward.h"
#include "rhp_eoip.h"
#include "rhp_esp.h"
#include "rhp_nhrp.h"


static u8 _rhp_nhrp_cie_get_code(rhp_nhrp_cie* nhrp_cie)
{
  RHP_TRC(0,RHPTRCID_NHRP_CIE_GET_CODE,"xb",nhrp_cie,nhrp_cie->code);
	return nhrp_cie->code;
}

static u8 _rhp_nhrp_cie_get_prefix_len(rhp_nhrp_cie* nhrp_cie)
{
  RHP_TRC(0,RHPTRCID_NHRP_CIE_GET_PREFIX_LEN,"xb",nhrp_cie,nhrp_cie->prefix_len);
	return nhrp_cie->prefix_len;
}

static int _rhp_nhrp_cie_set_prefix_len(rhp_nhrp_cie* nhrp_cie,u8 prefix_len)
{
  RHP_TRC(0,RHPTRCID_NHRP_CIE_SET_PREFIX_LEN,"xb",nhrp_cie,prefix_len);
	nhrp_cie->prefix_len = prefix_len;
	return 0;
}

static u16 _rhp_nhrp_cie_get_mtu(rhp_nhrp_cie* nhrp_cie)
{
  RHP_TRC(0,RHPTRCID_NHRP_CIE_GET_MTU,"xw",nhrp_cie,nhrp_cie->mtu);
	return nhrp_cie->mtu;
}

static int _rhp_nhrp_cie_set_mtu(rhp_nhrp_cie* nhrp_cie,u16 mtu)
{
  RHP_TRC(0,RHPTRCID_NHRP_CIE_SET_MTU,"xw",nhrp_cie,mtu);
	nhrp_cie->mtu = mtu;
	return 0;
}

static u16 _rhp_nhrp_cie_get_hold_time(rhp_nhrp_cie* nhrp_cie)
{
  RHP_TRC(0,RHPTRCID_NHRP_CIE_GET_HOLD_TIME,"xw",nhrp_cie,nhrp_cie->hold_time);
	return nhrp_cie->hold_time;
}

static int _rhp_nhrp_cie_set_hold_time(rhp_nhrp_cie* nhrp_cie,u16 hold_time)
{
  RHP_TRC(0,RHPTRCID_NHRP_CIE_SET_HOLD_TIME,"xw",nhrp_cie,hold_time);
	nhrp_cie->hold_time = hold_time;
	return 0;
}

static int _rhp_nhrp_cie_set_clt_nbma_addr(rhp_nhrp_cie* nhrp_cie,int addr_family,u8* clt_nbma_addr)
{
	int addr_len;

	if( addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_NHRP_CIE_SET_CLT_NBMA_ADDR_V4,"xLd4",nhrp_cie,"AF",addr_family,*((u32*)clt_nbma_addr));
		addr_len = 4;
	}else if( addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_NHRP_CIE_SET_CLT_NBMA_ADDR_V6,"xLd6",nhrp_cie,"AF",addr_family,clt_nbma_addr);
		addr_len = 16;
	}else{
		RHP_BUG("%d",addr_family);
		return -EINVAL;
	}

	memset(&(nhrp_cie->clt_nbma_addr),0,sizeof(rhp_ip_addr));

	nhrp_cie->clt_nbma_addr.addr_family = addr_family;
	memcpy(nhrp_cie->clt_nbma_addr.addr.raw,clt_nbma_addr,addr_len);

	rhp_ip_addr_dump("nhrp_cie->clt_nbma_addr",&(nhrp_cie->clt_nbma_addr));
	return 0;
}

static int _rhp_nhrp_cie_get_clt_nbma_addr(rhp_nhrp_cie* nhrp_cie,rhp_ip_addr* clt_nbma_addr_r)
{
	memcpy(clt_nbma_addr_r,&(nhrp_cie->clt_nbma_addr),sizeof(rhp_ip_addr));
	RHP_TRC(0,RHPTRCID_NHRP_CIE_GET_CLT_NBMA_ADDR,"xx",nhrp_cie,clt_nbma_addr_r);
	rhp_ip_addr_dump("clt_nbma_addr_r",clt_nbma_addr_r);
	return 0;
}

static int _rhp_nhrp_cie_set_clt_protocol_addr(rhp_nhrp_cie* nhrp_cie,int addr_family,u8* clt_protocol_addr)
{
	int addr_len;

	if( addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_NHRP_CIE_SET_CLT_PROTOCOL_ADDR_V4,"xLd4",nhrp_cie,"AF",addr_family,*((u32*)clt_protocol_addr));
		addr_len = 4;
	}else if( addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_NHRP_CIE_SET_CLT_PROTOCOL_ADDR_V6,"xLd6",nhrp_cie,"AF",addr_family,clt_protocol_addr);
		addr_len = 16;
	}else{
		RHP_BUG("%d",addr_family);
		return -EINVAL;
	}

	memset(&(nhrp_cie->clt_protocol_addr),0,sizeof(rhp_ip_addr));

	nhrp_cie->clt_protocol_addr.addr_family = addr_family;
	memcpy(nhrp_cie->clt_protocol_addr.addr.raw,clt_protocol_addr,addr_len);

	rhp_ip_addr_dump("nhrp_cie->clt_protocol_addr",&(nhrp_cie->clt_protocol_addr));
	return 0;
}

static int _rhp_nhrp_cie_get_clt_protocol_addr(rhp_nhrp_cie* nhrp_cie,rhp_ip_addr* clt_protocol_addr_r)
{
	memcpy(clt_protocol_addr_r,&(nhrp_cie->clt_protocol_addr),sizeof(rhp_ip_addr));
	RHP_TRC(0,RHPTRCID_NHRP_CIE_GET_CLT_PROTOCOL_ADDR,"xx",nhrp_cie,clt_protocol_addr_r);
	rhp_ip_addr_dump("clt_protocol_addr_r",clt_protocol_addr_r);
	return 0;
}

void rhp_nhrp_cie_free(rhp_nhrp_cie* nhrp_cie)
{
	RHP_TRC(0,RHPTRCID_NHRP_CIE_FREE,"x",nhrp_cie);
	_rhp_free(nhrp_cie);
	return;
}

rhp_nhrp_cie* rhp_nhrp_cie_alloc(u8 code)
{
	rhp_nhrp_cie* nhrp_cie = (rhp_nhrp_cie*)_rhp_malloc(sizeof(rhp_nhrp_cie));

	if( nhrp_cie == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(nhrp_cie,0,sizeof(rhp_nhrp_cie));

	nhrp_cie->tag[0] = '#';
	nhrp_cie->tag[1] = 'C';
	nhrp_cie->tag[2] = 'I';
	nhrp_cie->tag[3] = 'E';

	nhrp_cie->code = code;

	nhrp_cie->get_code = _rhp_nhrp_cie_get_code;
	nhrp_cie->get_prefix_len = _rhp_nhrp_cie_get_prefix_len;
	nhrp_cie->set_prefix_len = _rhp_nhrp_cie_set_prefix_len;
	nhrp_cie->get_mtu = _rhp_nhrp_cie_get_mtu;
	nhrp_cie->set_mtu = _rhp_nhrp_cie_set_mtu;
	nhrp_cie->get_hold_time = _rhp_nhrp_cie_get_hold_time;
	nhrp_cie->set_hold_time = _rhp_nhrp_cie_set_hold_time;
	nhrp_cie->set_clt_nbma_addr = _rhp_nhrp_cie_set_clt_nbma_addr;
	nhrp_cie->get_clt_nbma_addr = _rhp_nhrp_cie_get_clt_nbma_addr;
	nhrp_cie->set_clt_protocol_addr = _rhp_nhrp_cie_set_clt_protocol_addr;
	nhrp_cie->get_clt_protocol_addr = _rhp_nhrp_cie_get_clt_protocol_addr;

	RHP_TRC(0,RHPTRCID_NHRP_CIE_ALLOC,"xb",nhrp_cie,code);
	return nhrp_cie;
}


static int _rhp_nhrp_ext_get_type(rhp_nhrp_ext* nhrp_ext)
{
	RHP_TRC(0,RHPTRCID_NHRP_EXT_GET_TYPE,"xd",nhrp_ext,nhrp_ext->type);
	return nhrp_ext->type;
}

static int _rhp_nhrp_ext_add_cie(rhp_nhrp_ext* nhrp_ext,rhp_nhrp_cie* nhrp_cie)
{
	if( nhrp_ext->cie_list_head == NULL ){
		nhrp_ext->cie_list_head = nhrp_cie;
	}else{
		nhrp_ext->cie_list_tail->next = nhrp_cie;
	}
	nhrp_ext->cie_list_tail = nhrp_cie;

	RHP_TRC(0,RHPTRCID_NHRP_EXT_ADD_CIE,"xxxxx",nhrp_ext,nhrp_cie,nhrp_cie->next,nhrp_ext->cie_list_head,nhrp_ext->cie_list_tail);
	return 0;
}

static int _rhp_nhrp_ext_enum_cie(rhp_nhrp_ext* nhrp_ext,
		int (*callback)(rhp_nhrp_ext* nhrp_ext,rhp_nhrp_cie* nhrp_cie,void* ctx),void* ctx)
{
	rhp_nhrp_cie* nhrp_cie = nhrp_ext->cie_list_head;
	int n = 0;

	RHP_TRC(0,RHPTRCID_NHRP_EXT_ENUM_CIE,"xYxx",nhrp_ext,callback,ctx,nhrp_ext->cie_list_head);

	while( nhrp_cie ){

		int err = callback(nhrp_ext,nhrp_cie,ctx);
		if( err ){
			RHP_TRC(0,RHPTRCID_NHRP_EXT_ENUM_CIE_CB_ERR,"xYxxE",nhrp_ext,callback,ctx,nhrp_cie,err);
			return err;
		}
		n++;

		nhrp_cie = nhrp_cie->next;
	}

	if( n < 1 ){
		RHP_TRC(0,RHPTRCID_NHRP_EXT_ENUM_CIE_NO_ENT,"xYx",nhrp_ext,callback,ctx);
		return -ENOENT;
	}

	RHP_TRC(0,RHPTRCID_NHRP_EXT_ENUM_CIE_RTRN,"xYxd",nhrp_ext,callback,ctx,n);
	return 0;
}

static int _rhp_nhrp_ext_is_compulsory(rhp_nhrp_ext* nhrp_ext)
{
	RHP_TRC(0,RHPTRCID_NHRP_EXT_IS_COMPULSORY,"xd",nhrp_ext,nhrp_ext->compulsory_flag);
	return nhrp_ext->compulsory_flag;
}

void rhp_nhrp_ext_free(rhp_nhrp_ext* nhrp_ext)
{
	rhp_nhrp_cie* nhrp_cie = nhrp_ext->cie_list_head;

	RHP_TRC(0,RHPTRCID_NHRP_EXT_FREE,"xx",nhrp_ext,nhrp_ext->cie_list_head);

	while( nhrp_cie ){

		rhp_nhrp_cie* nhrp_cie_n = nhrp_cie->next;

		rhp_nhrp_cie_free(nhrp_cie);

		nhrp_cie = nhrp_cie_n;
	}

	if( nhrp_ext->ext_auth_key ){
		_rhp_free(nhrp_ext->ext_auth_key);
	}

	_rhp_free(nhrp_ext);

	RHP_TRC(0,RHPTRCID_NHRP_EXT_FREE_RTRN,"x",nhrp_ext);
	return;
}

rhp_nhrp_ext* rhp_nhrp_ext_alloc(int type,int compulsory_flag)
{
	rhp_nhrp_ext* nhrp_ext = (rhp_nhrp_ext*)_rhp_malloc(sizeof(rhp_nhrp_ext));

	if( nhrp_ext == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(nhrp_ext,0,sizeof(rhp_nhrp_ext));

	nhrp_ext->tag[0] = '#';
	nhrp_ext->tag[1] = 'N';
	nhrp_ext->tag[2] = 'H';
	nhrp_ext->tag[3] = 'T';

	nhrp_ext->type = type;
	nhrp_ext->compulsory_flag = compulsory_flag;

	nhrp_ext->get_type = _rhp_nhrp_ext_get_type;
	nhrp_ext->add_cie = _rhp_nhrp_ext_add_cie;
	nhrp_ext->enum_cie = _rhp_nhrp_ext_enum_cie;
	nhrp_ext->is_compulsory = _rhp_nhrp_ext_is_compulsory;

	RHP_TRC(0,RHPTRCID_NHRP_EXT_ALLOC,"xdd",nhrp_ext,type,compulsory_flag);
	return nhrp_ext;
}


static u16 _rhp_nhrp_mesg_get_addr_family(rhp_nhrp_mesg* nhrp_mesg)
{
	RHP_TRC(0,RHPTRCID_NHRP_MESG_GET_ADDR_FAMILY,"xw",nhrp_mesg,nhrp_mesg->f_addr_family);
	return nhrp_mesg->f_addr_family;
}

static u8 _rhp_nhrp_mesg_get_packet_type(rhp_nhrp_mesg* nhrp_mesg)
{
	RHP_TRC(0,RHPTRCID_NHRP_MESG_GET_PACKET_TYPE,"xb",nhrp_mesg,nhrp_mesg->f_packet_type);
	return nhrp_mesg->f_packet_type;
}

static void _rhp_nhrp_mesg_dec_hop_count(rhp_nhrp_mesg* nhrp_mesg)
{
	RHP_TRC(0,RHPTRCID_NHRP_MESG_DEC_HOP_COUNT,"x",nhrp_mesg);
	nhrp_mesg->exec_dec_hop_count = 1;
	return;
}

static int _rhp_nhrp_mesg_get_rx_nbma_src_addr(rhp_nhrp_mesg* nhrp_mesg,rhp_ip_addr* rx_nbma_src_addr_r)
{
	rhp_packet* rx_pkt = RHP_PKT_REF(nhrp_mesg->rx_pkt_ref);

	if( rx_pkt ){

		if( rx_pkt->nhrp.nbma_addr_family == AF_INET ){

			rx_nbma_src_addr_r->addr_family = AF_INET;
			rx_nbma_src_addr_r->addr.v4 = *((u32*)rx_pkt->nhrp.nbma_src_addr);

		}else if( rx_pkt->nhrp.nbma_addr_family == AF_INET6 ){

			rx_nbma_src_addr_r->addr_family = AF_INET6;
			memcpy(rx_nbma_src_addr_r->addr.v6,rx_pkt->nhrp.nbma_src_addr,16);

		}else{
			RHP_TRC(0,RHPTRCID_NHRP_MESG_GET_RX_NBMA_SRC_ADDR_NO_ENT,"xxd",nhrp_mesg,rx_pkt,rx_pkt->nhrp.nbma_addr_family);
			return -ENOENT;
		}

	}else{

		if( nhrp_mesg->rx_nbma_src_addr.addr_family != AF_INET &&
				nhrp_mesg->rx_nbma_src_addr.addr_family != AF_INET6 ){
			RHP_TRC(0,RHPTRCID_NHRP_MESG_GET_RX_NBMA_SRC_ADDR_NO_ENT_2,"xd",nhrp_mesg,nhrp_mesg->rx_nbma_src_addr.addr_family);
			return -ENOENT;
		}

		memcpy(rx_nbma_src_addr_r,&(nhrp_mesg->rx_nbma_src_addr),sizeof(rhp_ip_addr));
	}

	RHP_TRC(0,RHPTRCID_NHRP_MESG_GET_RX_NBMA_SRC_ADDR,"xxx",nhrp_mesg,rx_pkt,rx_nbma_src_addr_r);
	rhp_ip_addr_dump("rx_nbma_src_addr_r",rx_nbma_src_addr_r);
	return 0;
}

static int _rhp_nhrp_mesg_get_rx_nbma_dst_addr(rhp_nhrp_mesg* nhrp_mesg,rhp_ip_addr* rx_nbma_dst_addr_r)
{
	rhp_packet* rx_pkt = RHP_PKT_REF(nhrp_mesg->rx_pkt_ref);

	if( rx_pkt ){

		if( rx_pkt->nhrp.nbma_addr_family == AF_INET ){

			rx_nbma_dst_addr_r->addr_family = AF_INET;
			rx_nbma_dst_addr_r->addr.v4 = *((u32*)rx_pkt->nhrp.nbma_dst_addr);

		}else if( rx_pkt->nhrp.nbma_addr_family == AF_INET6 ){

			rx_nbma_dst_addr_r->addr_family = AF_INET6;
			memcpy(rx_nbma_dst_addr_r->addr.v6,rx_pkt->nhrp.nbma_dst_addr,16);

		}else{
			RHP_TRC(0,RHPTRCID_NHRP_MESG_GET_RX_NBMA_SRC_ADDR_NO_ENT,"xxd",nhrp_mesg,rx_pkt,rx_pkt->nhrp.nbma_addr_family);
			return -ENOENT;
		}

	}else{

		if( nhrp_mesg->rx_nbma_dst_addr.addr_family != AF_INET &&
				nhrp_mesg->rx_nbma_dst_addr.addr_family != AF_INET6 ){
			RHP_TRC(0,RHPTRCID_NHRP_MESG_GET_RX_NBMA_SRC_ADDR_NO_ENT_2,"xd",nhrp_mesg,nhrp_mesg->rx_nbma_dst_addr.addr_family);
			return -ENOENT;
		}

		memcpy(rx_nbma_dst_addr_r,&(nhrp_mesg->rx_nbma_dst_addr),sizeof(rhp_ip_addr));
	}

	RHP_TRC(0,RHPTRCID_NHRP_MESG_GET_RX_NBMA_DST_ADDR,"xxx",nhrp_mesg,rx_pkt,rx_nbma_dst_addr_r);
	rhp_ip_addr_dump("rx_nbma_dst_addr_r",rx_nbma_dst_addr_r);
	return 0;
}


static u32 _rhp_nhrp_m_mandatory_get_request_id(rhp_nhrp_mesg* nhrp_mesg)
{
	RHP_TRC(0,RHPTRCID_NHRP_M_MANDATORY_GET_REQUEST_ID,"xj",nhrp_mesg,nhrp_mesg->m.mandatory->request_id);
	return nhrp_mesg->m.mandatory->request_id;
}

static void _rhp_nhrp_m_mandatory_dont_update_request_id(rhp_nhrp_mesg* nhrp_mesg,int flag)
{
	RHP_TRC(0,RHPTRCID_NHRP_M_MANDATORY_DONT_UPDATE_REQUEST_ID,"xdj",nhrp_mesg,flag,nhrp_mesg->m.mandatory->request_id);
	nhrp_mesg->m.mandatory->dont_update_req_id = flag;
	return;
}

static int _rhp_nhrp_m_mandatory_set_flags(rhp_nhrp_mesg* nhrp_mesg,u16 flag_bits) // flag_bit: RHP_PROTO_NHRP_XXX_FLAG_YYY
{
	nhrp_mesg->m.mandatory->flags |= flag_bits;
	RHP_TRC(0,RHPTRCID_NHRP_M_MANDATORY_SET_FLAGS,"xww",nhrp_mesg,flag_bits,nhrp_mesg->m.mandatory->flags);
	return 0;
}

static u16 _rhp_nhrp_m_mandatory_get_flags(rhp_nhrp_mesg* nhrp_mesg)
{
	RHP_TRC(0,RHPTRCID_NHRP_M_MANDATORY_GET_FLAGS,"xw",nhrp_mesg,nhrp_mesg->m.mandatory->flags);
	return nhrp_mesg->m.mandatory->flags;
}

static int _rhp_nhrp_m_mandatory_set_src_nbma_addr(rhp_nhrp_mesg* nhrp_mesg,int addr_family,u8* src_nbma_addr)
{
	int addr_len;

	if( addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_NHRP_M_MANDATORY_SET_SRC_NBMA_ADDR_V4,"xLd4",nhrp_mesg,"AF",addr_family,*((u32*)src_nbma_addr));
		addr_len = 4;
	}else if( addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_NHRP_M_MANDATORY_SET_SRC_NBMA_ADDR_V6,"xLd6",nhrp_mesg,"AF",addr_family,src_nbma_addr);
		addr_len = 16;
	}else{
		RHP_BUG("%d",addr_family);
		return -EINVAL;
	}

	memset(&(nhrp_mesg->m.mandatory->src_nbma_addr),0,sizeof(rhp_ip_addr));

	nhrp_mesg->m.mandatory->src_nbma_addr.addr_family = addr_family;
	memcpy(nhrp_mesg->m.mandatory->src_nbma_addr.addr.raw,src_nbma_addr,addr_len);

	RHP_TRC(0,RHPTRCID_NHRP_M_MANDATORY_SET_SRC_NBMA_ADDR_RTRN,"xLdx",nhrp_mesg,"AF",addr_family,src_nbma_addr);
	rhp_ip_addr_dump("nhrp_mesg->m.mandatory->src_nbma_addr",&(nhrp_mesg->m.mandatory->src_nbma_addr));
	return 0;
}

static int _rhp_nhrp_m_mandatory_get_src_nbma_addr(rhp_nhrp_mesg* nhrp_mesg,rhp_ip_addr* src_nbma_addr_r)
{
	RHP_TRC(0,RHPTRCID_NHRP_M_MANDATORY_GET_SRC_NBMA_ADDR,"xx",nhrp_mesg,src_nbma_addr_r);
	memcpy(src_nbma_addr_r,&(nhrp_mesg->m.mandatory->src_nbma_addr),sizeof(rhp_ip_addr));
	rhp_ip_addr_dump("src_nbma_addr_r",src_nbma_addr_r);
	return 0;
}

static int _rhp_nhrp_m_mandatory_set_src_protocol_addr(rhp_nhrp_mesg* nhrp_mesg,int addr_family,u8* src_protocol_addr)
{
	int addr_len;

	if( addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_NHRP_M_MANDATORY_SET_SRC_PROTOCOL_ADDR_V4,"xLd4",nhrp_mesg,"AF",addr_family,*((u32*)src_protocol_addr));
		addr_len = 4;
	}else if( addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_NHRP_M_MANDATORY_SET_SRC_PROTOCOL_ADDR_V6,"xLd6",nhrp_mesg,"AF",addr_family,src_protocol_addr);
		addr_len = 16;
	}else{
		RHP_BUG("%d",addr_family);
		return -EINVAL;
	}

	memset(&(nhrp_mesg->m.mandatory->src_protocol_addr),0,sizeof(rhp_ip_addr));

	nhrp_mesg->m.mandatory->src_protocol_addr.addr_family = addr_family;
	memcpy(nhrp_mesg->m.mandatory->src_protocol_addr.addr.raw,src_protocol_addr,addr_len);

	RHP_TRC(0,RHPTRCID_NHRP_M_MANDATORY_SET_SRC_PROTOCOL_ADDR_RTRN,"xLdx",nhrp_mesg,"AF",addr_family,src_protocol_addr);
	rhp_ip_addr_dump("nhrp_mesg->m.mandatory->src_protocol_addr",&(nhrp_mesg->m.mandatory->src_protocol_addr));
	return 0;
}

static int _rhp_nhrp_m_mandatory_get_src_protocol_addr(rhp_nhrp_mesg* nhrp_mesg,rhp_ip_addr* src_protocol_addr_r)
{
	RHP_TRC(0,RHPTRCID_NHRP_M_MANDATORY_GET_SRC_PROTOCOL_ADDR,"xx",nhrp_mesg,src_protocol_addr_r);
	memcpy(src_protocol_addr_r,&(nhrp_mesg->m.mandatory->src_protocol_addr),sizeof(rhp_ip_addr));
	rhp_ip_addr_dump("src_protocol_addr_r",src_protocol_addr_r);
	return 0;
}

static int _rhp_nhrp_m_mandatory_set_dst_protocol_addr(rhp_nhrp_mesg* nhrp_mesg,int addr_family,u8* dst_protocol_addr)
{
	int addr_len;

	if( addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_NHRP_M_MANDATORY_SET_DST_PROTOCOL_ADDR_V4,"xLd4",nhrp_mesg,"AF",addr_family,*((u32*)dst_protocol_addr));
		addr_len = 4;
	}else if( addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_NHRP_M_MANDATORY_SET_DST_PROTOCOL_ADDR_V6,"xLd6",nhrp_mesg,"AF",addr_family,dst_protocol_addr);
		addr_len = 16;
	}else{
		RHP_BUG("%d",addr_family);
		return -EINVAL;
	}

	memset(&(nhrp_mesg->m.mandatory->dst_protocol_addr),0,sizeof(rhp_ip_addr));

	nhrp_mesg->m.mandatory->dst_protocol_addr.addr_family = addr_family;
	memcpy(nhrp_mesg->m.mandatory->dst_protocol_addr.addr.raw,dst_protocol_addr,addr_len);

	RHP_TRC(0,RHPTRCID_NHRP_M_MANDATORY_SET_DST_PROTOCOL_ADDR_RTRN,"xLdx",nhrp_mesg,"AF",addr_family,dst_protocol_addr);
	rhp_ip_addr_dump("nhrp_mesg->m.mandatory->dst_protocol_addr",&(nhrp_mesg->m.mandatory->dst_protocol_addr));
	return 0;
}

static int _rhp_nhrp_m_mandatory_get_dst_protocol_addr(rhp_nhrp_mesg* nhrp_mesg,rhp_ip_addr* dst_protocol_addr_r)
{
	RHP_TRC(0,RHPTRCID_NHRP_M_MANDATORY_GET_DST_PROTOCOL_ADDR,"xx",nhrp_mesg,dst_protocol_addr_r);
	memcpy(dst_protocol_addr_r,&(nhrp_mesg->m.mandatory->dst_protocol_addr),sizeof(rhp_ip_addr));
	rhp_ip_addr_dump("dst_protocol_addr_r",dst_protocol_addr_r);
	return 0;
}

static int _rhp_nhrp_m_mandatory_add_cie(rhp_nhrp_mesg* nhrp_mesg,rhp_nhrp_cie* nhrp_cie)
{
	RHP_TRC(0,RHPTRCID_NHRP_M_MANDATORY_ADD_CIE,"xxxx",nhrp_mesg,nhrp_cie,nhrp_mesg->m.mandatory->cie_list_head,nhrp_mesg->m.mandatory->cie_list_tail);

	if( nhrp_mesg->m.mandatory->cie_list_head == NULL ){
		nhrp_mesg->m.mandatory->cie_list_head = nhrp_cie;
	}else{
		nhrp_mesg->m.mandatory->cie_list_tail->next = nhrp_cie;
	}
	nhrp_mesg->m.mandatory->cie_list_tail = nhrp_cie;

	RHP_TRC(0,RHPTRCID_NHRP_M_MANDATORY_ADD_CIE_RTRN,"xxxx",nhrp_mesg,nhrp_cie,nhrp_mesg->m.mandatory->cie_list_head,nhrp_mesg->m.mandatory->cie_list_tail);
	return 0;
}

static int _rhp_nhrp_m_mandatory_enum_cie(rhp_nhrp_mesg* nhrp_mesg,
					int (*callback)(struct _rhp_nhrp_mesg* nhrp_mesg,rhp_nhrp_cie* nhrp_cie,void* ctx),void* ctx)
{
	rhp_nhrp_cie* nhrp_cie = nhrp_mesg->m.mandatory->cie_list_head;
	int n = 0;

	RHP_TRC(0,RHPTRCID_NHRP_M_MANDATORY_ENUM_CIE,"xYx",nhrp_mesg,callback,ctx);

	while( nhrp_cie ){

		int err = callback(nhrp_mesg,nhrp_cie,ctx);
		if( err ){
			RHP_TRC(0,RHPTRCID_NHRP_M_MANDATORY_ENUM_CIE_CB_ERR,"xYxE",nhrp_mesg,callback,ctx,err);
			return err;
		}
		n++;

		nhrp_cie = nhrp_cie->next;
	}

	if( n < 1 ){
		RHP_TRC(0,RHPTRCID_NHRP_M_MANDATORY_ENUM_CIE_NO_ENT,"xYx",nhrp_mesg,callback,ctx);
		return -ENOENT;
	}

	RHP_TRC(0,RHPTRCID_NHRP_M_MANDATORY_ENUM_CIE_RTRN,"xYxd",nhrp_mesg,callback,ctx,n);
	return 0;
}

static void _rhp_nhrp_mesg_m_mandatory_free(rhp_nhrp_m_mandatory* nhrp_m_mandatory)
{
	rhp_nhrp_cie* nhrp_cie = nhrp_m_mandatory->cie_list_head;

	RHP_TRC(0,RHPTRCID_NHRP_M_MANDATORY_FREE,"xx",nhrp_m_mandatory,nhrp_m_mandatory->cie_list_head);

	while(nhrp_cie){

		rhp_nhrp_cie* nhrp_cie_n = nhrp_cie->next;

		rhp_nhrp_cie_free(nhrp_cie);

		nhrp_cie = nhrp_cie_n;
	}

	_rhp_free(nhrp_m_mandatory);

	RHP_TRC(0,RHPTRCID_NHRP_M_MANDATORY_FREE_RTRN,"x",nhrp_m_mandatory);
	return;
}

static rhp_nhrp_m_mandatory* _rhp_nhrp_mesg_m_mandatory_alloc()
{
	rhp_nhrp_m_mandatory* nhrp_m_mandatory
		= (rhp_nhrp_m_mandatory*)_rhp_malloc(sizeof(rhp_nhrp_m_mandatory));

	if( nhrp_m_mandatory == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(nhrp_m_mandatory,0,sizeof(rhp_nhrp_m_mandatory));

	nhrp_m_mandatory->tag[0] = '#';
	nhrp_m_mandatory->tag[1] = 'N';
	nhrp_m_mandatory->tag[2] = 'H';
	nhrp_m_mandatory->tag[3] = 'M';

	nhrp_m_mandatory->get_request_id = _rhp_nhrp_m_mandatory_get_request_id;
	nhrp_m_mandatory->dont_update_request_id = _rhp_nhrp_m_mandatory_dont_update_request_id;
	nhrp_m_mandatory->set_flags = _rhp_nhrp_m_mandatory_set_flags;
	nhrp_m_mandatory->get_flags = _rhp_nhrp_m_mandatory_get_flags;
	nhrp_m_mandatory->set_src_nbma_addr = _rhp_nhrp_m_mandatory_set_src_nbma_addr;
	nhrp_m_mandatory->get_src_nbma_addr = _rhp_nhrp_m_mandatory_get_src_nbma_addr;
	nhrp_m_mandatory->set_src_protocol_addr = _rhp_nhrp_m_mandatory_set_src_protocol_addr;
	nhrp_m_mandatory->get_src_protocol_addr = _rhp_nhrp_m_mandatory_get_src_protocol_addr;
	nhrp_m_mandatory->set_dst_protocol_addr = _rhp_nhrp_m_mandatory_set_dst_protocol_addr;
	nhrp_m_mandatory->get_dst_protocol_addr = _rhp_nhrp_m_mandatory_get_dst_protocol_addr;
	nhrp_m_mandatory->add_cie = _rhp_nhrp_m_mandatory_add_cie;
	nhrp_m_mandatory->enum_cie = _rhp_nhrp_m_mandatory_enum_cie;

	RHP_TRC(0,RHPTRCID_NHRP_M_MANDATORY_ALLOC,"x",nhrp_m_mandatory);
	return nhrp_m_mandatory;
}


static int _rhp_nhrp_mesg_add_extension(rhp_nhrp_mesg* nhrp_mesg,rhp_nhrp_ext* nhrp_ext)
{
	RHP_TRC(0,RHPTRCID_NHRP_MESG_ADD_EXTENSION,"xxxx",nhrp_mesg,nhrp_ext,nhrp_mesg->ext_list_head,nhrp_mesg->ext_list_tail);

	if( nhrp_mesg->ext_list_head == NULL ){
		nhrp_mesg->ext_list_head = nhrp_ext;
	}else{
		nhrp_mesg->ext_list_tail->next = nhrp_ext;
	}
	nhrp_mesg->ext_list_tail = nhrp_ext;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_ADD_EXTENSION_RTRN,"xxxx",nhrp_mesg,nhrp_ext,nhrp_mesg->ext_list_head,nhrp_mesg->ext_list_tail);
	return 0;
}

static int _rhp_nhrp_mesg_enum_extension(rhp_nhrp_mesg* nhrp_mesg,
					int (*callback)(struct _rhp_nhrp_mesg* nhrp_mesg,rhp_nhrp_ext* nhrp_ext,void* ctx),void* ctx)
{
	rhp_nhrp_ext* nhrp_ext = nhrp_mesg->ext_list_head;
	int n = 0;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_ENUM_EXTENSION,"xYxx",nhrp_mesg,callback,ctx,nhrp_mesg->ext_list_head);

	while( nhrp_ext ){

		int err = callback(nhrp_mesg,nhrp_ext,ctx);
		if( err ){
			return err;
		}
		n++;

		nhrp_ext = nhrp_ext->next;
	}

	if( n < 1 ){
		RHP_TRC(0,RHPTRCID_NHRP_MESG_ENUM_EXTENSION_NO_ENT,"xYx",nhrp_mesg,callback,ctx);
		return -ENOENT;
	}

	RHP_TRC(0,RHPTRCID_NHRP_MESG_ENUM_EXTENSION_RTRN,"xYxd",nhrp_mesg,callback,ctx,n);
	return 0;
}


static int _rhp_nhrp_mesg_ext_auth_check_key(rhp_nhrp_mesg* nhrp_mesg,int key_len,u8* key)
{
	rhp_nhrp_ext* nhrp_ext = nhrp_mesg->ext_list_head;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_EXT_AUTH_CHECK_KEY,"xxp",nhrp_mesg,nhrp_mesg->ext_list_head,key_len,key);

	while( nhrp_ext ){

		if( nhrp_ext->get_type(nhrp_ext) == RHP_PROTO_NHRP_EXT_TYPE_AUTHENTICATION ){

			RHP_TRC(0,RHPTRCID_NHRP_MESG_EXT_AUTH_CHECK_KEY_RX_KEY,"xxpp",nhrp_mesg,nhrp_ext,nhrp_ext->ext_auth_key_len,nhrp_ext->ext_auth_key,key_len,key);

			if( key == NULL ){

				RHP_TRC(0,RHPTRCID_NHRP_MESG_EXT_AUTH_CHECK_KEY_LOCAL_KEY_NULL,"xx",nhrp_mesg,nhrp_ext);
				return -EINVAL;
			}

			if( nhrp_ext->ext_auth_key == NULL ){

				RHP_TRC(0,RHPTRCID_NHRP_MESG_EXT_AUTH_CHECK_KEY_RX_KEY_VAL_NULL,"xx",nhrp_mesg,nhrp_ext);
				return -EINVAL;
			}

			if( nhrp_ext->ext_auth_key_len == key_len &&
					!memcmp(nhrp_ext->ext_auth_key,key,key_len) ){

				RHP_TRC(0,RHPTRCID_NHRP_MESG_EXT_AUTH_CHECK_KEY_OK,"xx",nhrp_mesg,nhrp_ext);
				return 0;
			}

			RHP_TRC(0,RHPTRCID_NHRP_MESG_EXT_AUTH_CHECK_KEY_RX_INVALID_KEY,"xx",nhrp_mesg,nhrp_ext);
			return -EINVAL;
		}

		nhrp_ext = nhrp_ext->next;
	}

	if( key == NULL && nhrp_ext == NULL ){
		RHP_TRC(0,RHPTRCID_NHRP_MESG_EXT_AUTH_CHECK_KEY_KEY_NOT_CONFIGURED_OK,"xx",nhrp_mesg,nhrp_ext);
		return 0;
	}

	RHP_TRC(0,RHPTRCID_NHRP_MESG_EXT_AUTH_CHECK_KEY_ERR,"x",nhrp_mesg);
	return -EINVAL;
}

static rhp_nhrp_ext* _rhp_nhrp_mesg_get_extension(rhp_nhrp_mesg* nhrp_mesg,int type)
{
	rhp_nhrp_ext *nhrp_ext = nhrp_mesg->ext_list_head;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_GET_EXTENSION,"xd",nhrp_mesg,type);

	while( nhrp_ext ){

		if( nhrp_ext->type == type ){
			RHP_TRC(0,RHPTRCID_NHRP_MESG_GET_EXTENSION_RTRN,"xdx",nhrp_mesg,type,nhrp_ext);
			return nhrp_ext;
		}

		nhrp_ext = nhrp_ext->next;
	}

	RHP_TRC(0,RHPTRCID_NHRP_MESG_GET_EXTENSION_NO_ENT,"xd",nhrp_mesg,type);
	return NULL;
}

static rhp_nhrp_ext* _rhp_nhrp_mesg_remove_extension(rhp_nhrp_mesg* nhrp_mesg,int type)
{
	rhp_nhrp_ext *nhrp_ext = nhrp_mesg->ext_list_head, *nhrp_ext_p = NULL;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_REMOVE_EXTENSION,"xdx",nhrp_mesg,type,nhrp_mesg->ext_list_head);

	while( nhrp_ext ){

		if( nhrp_ext->type == type ){
			break;
		}

		nhrp_ext_p = nhrp_ext;
		nhrp_ext = nhrp_ext->next;
	}

	if( nhrp_ext == NULL ){
		RHP_TRC(0,RHPTRCID_NHRP_MESG_REMOVE_EXTENSION_NO_ENT,"xdx",nhrp_mesg,type,nhrp_mesg->ext_list_head);
		return NULL;
	}

	if( nhrp_ext_p ){

		nhrp_ext_p->next = nhrp_ext->next;

		if( nhrp_ext == nhrp_mesg->ext_list_tail ){
			nhrp_mesg->ext_list_tail = nhrp_ext_p;
		}

	}else{

		nhrp_mesg->ext_list_head = nhrp_ext->next;

		if( nhrp_ext == nhrp_mesg->ext_list_tail ){
			nhrp_mesg->ext_list_tail = nhrp_ext->next;
		}
	}


	nhrp_ext->next = NULL;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_REMOVE_EXTENSION_RTRN,"xdxxxx",nhrp_mesg,type,nhrp_mesg->ext_list_head,nhrp_mesg->ext_list_tail,nhrp_ext,nhrp_ext_p);
	return nhrp_ext;
}

static rhp_packet* _rhp_nhrp_mesg_alloc_tx_pkt(rhp_vpn* tx_vpn,int buf_len)
{
	rhp_packet* pkt = NULL;
  rhp_proto_ether* dmy_ethh;
  rhp_proto_gre* greh;
  rhp_proto_nhrp* nhrph;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_ALLOC_TX_PKT,"xd",tx_vpn,buf_len);

	pkt = rhp_pkt_alloc(buf_len);
	if( pkt == NULL ){
		RHP_BUG("");
		goto error;
	}

	pkt->type = RHP_PKT_GRE_NHRP;

	{
		dmy_ethh = (rhp_proto_ether*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ether));
		if( dmy_ethh == NULL ){
			RHP_BUG("");
			goto error;
		}
		dmy_ethh->protocol = RHP_PROTO_ETH_NHRP;

		pkt->l2.eth = dmy_ethh;
	}

	{
		greh = (rhp_proto_gre*)_rhp_pkt_push(pkt,sizeof(rhp_proto_gre));
		if( greh == NULL ){
			RHP_BUG("");
			goto error;
		}

  	greh->check_sum_flag = 0;
  	greh->reserved_flag0 = 0;
  	greh->seq_flag = 0;
  	greh->reserved_flag1 = 0;
  	greh->reserved_flag2 = 0;

		greh->ver = 0;
		greh->protocol_type = RHP_PROTO_ETH_NHRP;

		if( tx_vpn->gre.key_enabled ){

			u8* greh_key = (u8*)_rhp_pkt_push(pkt,sizeof(u32));
			if( greh_key == NULL ){
				RHP_BUG("");
				goto error;
			}

			greh->key_flag = 1;
			*((u32*)greh_key) = htonl(tx_vpn->gre.key);

		}else{

	  	greh->key_flag = 0;
		}

		pkt->l3.nhrp_greh = greh;
	}

	{
		nhrph = (rhp_proto_nhrp*)_rhp_pkt_push(pkt,sizeof(rhp_proto_nhrp));
		if( nhrph == NULL ){
			RHP_BUG("");
			goto error;
		}

		pkt->l4.nhrph = nhrph;
	}

	RHP_TRC(0,RHPTRCID_NHRP_MESG_ALLOC_TX_PKT_RTRN,"dxxxx",buf_len,pkt,pkt->l2.eth,pkt->l3.nhrp_greh,pkt->l4.nhrph);
	return pkt;

error:
	if( pkt ){
		rhp_pkt_unhold(pkt);
	}
	RHP_TRC(0,RHPTRCID_NHRP_MESG_ALLOC_TX_PKT_ERR,"d",buf_len);
	return NULL;
}

static int _rhp_nhrp_mesg_serialize_build_f_header(rhp_nhrp_mesg* nhrp_mesg,
		rhp_vpn* tx_vpn,rhp_packet* tx_pkt,int* nhrp_mesg_len_r)
{
	int err = -EINVAL;
	rhp_proto_nhrp* nhrph = tx_pkt->l4.nhrph;
	rhp_ip_addr src_nbma_addr, src_proto_addr, dst_proto_addr;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_SERIALIZE_BUILD_F_HEADER,"xxxxd",nhrp_mesg,tx_vpn,tx_pkt,nhrp_mesg_len_r,nhrp_mesg->f_packet_type);

	memset(&src_nbma_addr,0,sizeof(rhp_ip_addr));
	memset(&src_proto_addr,0,sizeof(rhp_ip_addr));
	memset(&dst_proto_addr,0,sizeof(rhp_ip_addr));

	{
		nhrph->fixed.address_family_no = nhrp_mesg->f_addr_family;
		memset(nhrph->fixed.ptotocol_type_snap,0,5);

		if( nhrp_mesg->rx_hop_count && nhrp_mesg->exec_dec_hop_count ){
			nhrph->fixed.hop_count = --nhrp_mesg->rx_hop_count;
		}else{
			nhrph->fixed.hop_count = nhrp_mesg->f_hop_count;
		}

		nhrph->fixed.len = 0;
		nhrph->fixed.check_sum = 0;
		nhrph->fixed.extension_offset = 0;
		nhrph->fixed.version = RHP_PROTO_NHRP_VERSION;

		nhrph->fixed.packet_type = nhrp_mesg->f_packet_type;

		nhrph->fixed.src_nbma_addr_type_reserved = 0;
		nhrph->fixed.src_nbma_addr_type_flag = 0;

		nhrph->fixed.src_nbma_saddr_type_reserved = 0;
		nhrph->fixed.src_nbma_saddr_type_flag = 0;
		nhrph->fixed.src_nbma_saddr_type_len = 0;
	}


	switch( nhrp_mesg->f_packet_type ){

	case RHP_PROTO_NHRP_PKT_RESOLUTION_REQ:
	case RHP_PROTO_NHRP_PKT_RESOLUTION_REP:
	case RHP_PROTO_NHRP_PKT_REGISTRATION_REQ:
	case RHP_PROTO_NHRP_PKT_REGISTRATION_REP:
	case RHP_PROTO_NHRP_PKT_PURGE_REQ:
	case RHP_PROTO_NHRP_PKT_PURGE_REP:

		err = nhrp_mesg->m.mandatory->get_src_nbma_addr(nhrp_mesg,&src_nbma_addr);
		if( err ){
			goto error;
		}

		err = nhrp_mesg->m.mandatory->get_src_protocol_addr(nhrp_mesg,&src_proto_addr);
		if( err ){
			goto error;
		}

		err = nhrp_mesg->m.mandatory->get_dst_protocol_addr(nhrp_mesg,&dst_proto_addr);
		if( err ){
			goto error;
		}

		break;

	case RHP_PROTO_NHRP_PKT_ERROR_INDICATION:

		err = nhrp_mesg->m.error->get_src_nbma_addr(nhrp_mesg,&src_nbma_addr);
		if( err ){
			goto error;
		}

		err = nhrp_mesg->m.error->get_src_protocol_addr(nhrp_mesg,&src_proto_addr);
		if( err ){
			goto error;
		}

		err = nhrp_mesg->m.error->get_dst_protocol_addr(nhrp_mesg,&dst_proto_addr);
		if( err ){
			goto error;
		}

		break;

	case RHP_PROTO_NHRP_PKT_TRAFFIC_INDICATION:

		err = nhrp_mesg->m.traffic->get_src_nbma_addr(nhrp_mesg,&src_nbma_addr);
		if( err ){
			goto error;
		}

		err = nhrp_mesg->m.traffic->get_src_protocol_addr(nhrp_mesg,&src_proto_addr);
		if( err ){
			goto error;
		}

		err = nhrp_mesg->m.traffic->get_dst_protocol_addr(nhrp_mesg,&dst_proto_addr);
		if( err ){
			goto error;
		}

		break;

	default:
		err = RHP_STATUS_NHRP_NOT_SUPPORTED_ATTR;
		goto error;
	}


	if( src_nbma_addr.addr_family == AF_INET ){
		nhrph->fixed.src_nbma_addr_type_len = RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN;
	}else if( src_nbma_addr.addr_family == AF_INET6 ){
		nhrph->fixed.src_nbma_addr_type_len = RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN;
	}else{
		nhrph->fixed.src_nbma_addr_type_len = 0;
	}

	if( src_proto_addr.addr_family == AF_INET || dst_proto_addr.addr_family == AF_INET ){
		nhrph->fixed.protocol_type = RHP_PROTO_ETH_IP;
	}else if( src_proto_addr.addr_family == AF_INET6 || dst_proto_addr.addr_family == AF_INET6 ){
		nhrph->fixed.protocol_type = RHP_PROTO_ETH_IPV6;
	}else{
		nhrph->fixed.protocol_type = 0;
	}

	*nhrp_mesg_len_r += sizeof(rhp_proto_nhrp_fixed);

	RHP_TRC(0,RHPTRCID_NHRP_MESG_SERIALIZE_BUILD_F_HEADER_RTRN,"xxxd",nhrp_mesg,tx_vpn,tx_pkt,*nhrp_mesg_len_r);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_MESG_SERIALIZE_BUILD_F_HEADER_ERR,"xxxE",nhrp_mesg,tx_vpn,tx_pkt,err);
	return err;
}

static int _rhp_nhrp_mesg_serialize_cie(rhp_nhrp_mesg* nhrp_mesg,
		rhp_vpn* tx_vpn,rhp_packet* tx_pkt,rhp_nhrp_cie* nhrp_cie,
		int* nhrp_mesg_len_r)
{
	int err = -EINVAL;
	rhp_proto_nhrp_clt_info_entry* nhrp_cieh;
	rhp_ip_addr clt_nbma_addr;
	rhp_ip_addr clt_protocol_addr;
	int addr_len;
	u8* addr_p;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_SERIALIZE_CIE,"xxxxxd",nhrp_mesg,tx_vpn,tx_pkt,nhrp_cie,nhrp_mesg_len_r,nhrp_mesg->f_packet_type);

	memset(&clt_nbma_addr,0,sizeof(rhp_ip_addr));
	memset(&clt_protocol_addr,0,sizeof(rhp_ip_addr));


	nhrp_cieh
		= (rhp_proto_nhrp_clt_info_entry*)_rhp_pkt_push(tx_pkt,sizeof(rhp_proto_nhrp_clt_info_entry));
	if( nhrp_cieh == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	nhrp_cieh->code = nhrp_cie->code;
	nhrp_cieh->prefix_len = nhrp_cie->prefix_len;
	nhrp_cieh->unused = 0;
	nhrp_cieh->mtu = htons(nhrp_cie->mtu);
	nhrp_cieh->hold_time = htons(nhrp_cie->hold_time);
	nhrp_cieh->preference = 0;
	nhrp_cieh->clt_nbma_saddr_type_len = 0;


	err = nhrp_cie->get_clt_nbma_addr(nhrp_cie,&clt_nbma_addr);
	if( err ){
		goto error;
	}

	err = nhrp_cie->get_clt_protocol_addr(nhrp_cie,&clt_protocol_addr);
	if( err ){
		goto error;
	}

	{
		if( clt_nbma_addr.addr_family == AF_INET ){
			addr_len =
			nhrp_cieh->clt_nbma_addr_type_len = RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN;
		}else if( clt_nbma_addr.addr_family == AF_INET6 ){
			addr_len =
			nhrp_cieh->clt_nbma_addr_type_len = RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN;
		}else{
			addr_len = nhrp_cieh->clt_nbma_addr_type_len = 0;
		}

		if( addr_len ){

			addr_p = _rhp_pkt_push(tx_pkt,addr_len);
			if( addr_p == NULL ){
				RHP_BUG("");
				err = -EINVAL;
				goto error;
			}

			memcpy(addr_p,clt_nbma_addr.addr.raw,addr_len);
			*nhrp_mesg_len_r += addr_len;
		}
	}

	{
		if( clt_protocol_addr.addr_family == AF_INET ){
			addr_len =
			nhrp_cieh->clt_protocol_addr_len = RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN;
		}else if( clt_protocol_addr.addr_family == AF_INET6 ){
			addr_len =
			nhrp_cieh->clt_protocol_addr_len = RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN;
		}else{
			addr_len = nhrp_cieh->clt_protocol_addr_len = 0;
		}

		if( addr_len ){

			addr_p = _rhp_pkt_push(tx_pkt,addr_len);
			if( addr_p == NULL ){
				RHP_BUG("");
				err = -EINVAL;
				goto error;
			}

			memcpy(addr_p,clt_protocol_addr.addr.raw,addr_len);
			*nhrp_mesg_len_r += addr_len;
		}
	}

	*nhrp_mesg_len_r += sizeof(rhp_proto_nhrp_clt_info_entry);

	RHP_TRC(0,RHPTRCID_NHRP_MESG_SERIALIZE_CIE_RTRN,"xxxxd",nhrp_mesg,tx_vpn,tx_pkt,nhrp_cie,*nhrp_mesg_len_r);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_MESG_SERIALIZE_CIE_ERR,"xxxxE",nhrp_mesg,tx_vpn,tx_pkt,nhrp_cie,err);
	return err;
}

static int _rhp_nhrp_mesg_serialize_build_m_header(rhp_nhrp_mesg* nhrp_mesg,
		rhp_vpn* tx_vpn,rhp_packet* tx_pkt,int* nhrp_mesg_len_r)
{
	int err = -EINVAL;
	rhp_proto_nhrp* nhrph = tx_pkt->l4.nhrph;
	rhp_ip_addr src_nbma_addr, src_proto_addr, dst_proto_addr;
	u8* addr_p;
	int offset = 0;
	u32 tx_request_id;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_SERIALIZE_BUILD_M_HEADER,"xxxxdx",nhrp_mesg,tx_vpn,tx_pkt,nhrp_mesg_len_r,nhrp_mesg->f_packet_type,nhrp_mesg->m.mandatory->cie_list_head);

	memset(&src_nbma_addr,0,sizeof(rhp_ip_addr));
	memset(&src_proto_addr,0,sizeof(rhp_ip_addr));
	memset(&dst_proto_addr,0,sizeof(rhp_ip_addr));


	switch( nhrp_mesg->f_packet_type ){

	case RHP_PROTO_NHRP_PKT_RESOLUTION_REQ:
	case RHP_PROTO_NHRP_PKT_RESOLUTION_REP:
	case RHP_PROTO_NHRP_PKT_REGISTRATION_REQ:
	case RHP_PROTO_NHRP_PKT_REGISTRATION_REP:
	case RHP_PROTO_NHRP_PKT_PURGE_REQ:
	case RHP_PROTO_NHRP_PKT_PURGE_REP:

		if( !nhrp_mesg->m.mandatory->dont_update_req_id ){
			tx_request_id = rhp_nhrp_tx_next_request_id();
		}else{
			tx_request_id = nhrp_mesg->m.mandatory->request_id;
		}

		nhrph->m.mandatory.flags = nhrp_mesg->m.mandatory->get_flags(nhrp_mesg);
		nhrph->m.mandatory.request_id = htonl(tx_request_id);

		nhrp_mesg->m.mandatory->request_id = tx_request_id;

		err = nhrp_mesg->m.mandatory->get_src_nbma_addr(nhrp_mesg,&src_nbma_addr);
		if( err ){
			goto error;
		}

		err = nhrp_mesg->m.mandatory->get_src_protocol_addr(nhrp_mesg,&src_proto_addr);
		if( err ){
			goto error;
		}

		err = nhrp_mesg->m.mandatory->get_dst_protocol_addr(nhrp_mesg,&dst_proto_addr);
		if( err ){
			goto error;
		}

		{
			int addr_len;

			if( src_nbma_addr.addr_family == AF_INET ){
				addr_len = RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN;
			}else if( src_nbma_addr.addr_family == AF_INET6 ){
				addr_len = RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN;
			}else{
				addr_len = 0;
			}

			if( addr_len ){

				addr_p = _rhp_pkt_push(tx_pkt,addr_len);
				if( addr_p == NULL ){
					err = -EINVAL;
					RHP_BUG("");
					goto error;
				}

				memcpy(addr_p,src_nbma_addr.addr.raw,addr_len);
				*nhrp_mesg_len_r += addr_len;
			}
		}

		{
			if( src_proto_addr.addr_family == AF_INET ){
				nhrph->m.mandatory.src_protocol_len = RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN;
			}else if( src_proto_addr.addr_family == AF_INET6 ){
				nhrph->m.mandatory.src_protocol_len = RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN;
			}else{
				nhrph->m.mandatory.src_protocol_len = 0;
			}

			if( nhrph->m.mandatory.src_protocol_len ){

				addr_p = _rhp_pkt_push(tx_pkt,(int)nhrph->m.mandatory.src_protocol_len);
				if( addr_p == NULL ){
					err = -EINVAL;
					RHP_BUG("");
					goto error;
				}

				memcpy(addr_p,src_proto_addr.addr.raw,nhrph->m.mandatory.src_protocol_len);
				*nhrp_mesg_len_r += (int)nhrph->m.mandatory.src_protocol_len;
			}
		}

		{
			if( dst_proto_addr.addr_family == AF_INET ){
				nhrph->m.mandatory.dst_protocol_len = RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN;
			}else if( dst_proto_addr.addr_family == AF_INET6 ){
				nhrph->m.mandatory.dst_protocol_len = RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN;
			}else{
				nhrph->m.mandatory.dst_protocol_len = 0;
			}

			if( nhrph->m.mandatory.dst_protocol_len ){

				addr_p = _rhp_pkt_push(tx_pkt,(int)nhrph->m.mandatory.dst_protocol_len);
				if( addr_p == NULL ){
					err = -EINVAL;
					RHP_BUG("");
					goto error;
				}

				memcpy(addr_p,dst_proto_addr.addr.raw,nhrph->m.mandatory.dst_protocol_len);
				*nhrp_mesg_len_r += (int)nhrph->m.mandatory.dst_protocol_len;
			}
		}

		{
			rhp_nhrp_cie* nhrp_cie = nhrp_mesg->m.mandatory->cie_list_head;

			while( nhrp_cie ){

				err = _rhp_nhrp_mesg_serialize_cie(nhrp_mesg,tx_vpn,tx_pkt,nhrp_cie,nhrp_mesg_len_r);
				if( err ){
					goto error;
				}

				nhrp_cie = nhrp_cie->next;
			}
		}

		*nhrp_mesg_len_r += sizeof(rhp_proto_nhrp_mandatory);

		break;


	case RHP_PROTO_NHRP_PKT_ERROR_INDICATION:

		nhrph->m.error.error_code = htons(nhrp_mesg->m.error->get_error_code(nhrp_mesg));
		nhrph->m.error.error_offset = 0;

		offset = sizeof(rhp_proto_nhrp_fixed) + sizeof(rhp_proto_nhrp_error);

		err = nhrp_mesg->m.error->get_src_nbma_addr(nhrp_mesg,&src_nbma_addr);
		if( err ){
			goto error;
		}

		err = nhrp_mesg->m.error->get_src_protocol_addr(nhrp_mesg,&src_proto_addr);
		if( err ){
			goto error;
		}

		err = nhrp_mesg->m.error->get_dst_protocol_addr(nhrp_mesg,&dst_proto_addr);
		if( err ){
			goto error;
		}

		{
			int addr_len;

			if( src_nbma_addr.addr_family == AF_INET ){
				addr_len = RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN;
			}else if( src_nbma_addr.addr_family == AF_INET6 ){
				addr_len = RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN;
			}else{
				addr_len = 0;
			}

			if( addr_len ){

				addr_p = _rhp_pkt_push(tx_pkt,addr_len);
				if( addr_p == NULL ){
					err = -EINVAL;
					RHP_BUG("");
					goto error;
				}

				memcpy(addr_p,src_nbma_addr.addr.raw,addr_len);
				*nhrp_mesg_len_r += addr_len;
				offset += addr_len;
			}
		}

		{
			if( src_proto_addr.addr_family == AF_INET ){
				nhrph->m.error.src_protocol_len = RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN;
			}else if( src_proto_addr.addr_family == AF_INET6 ){
				nhrph->m.error.src_protocol_len = RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN;
			}else{
				nhrph->m.error.src_protocol_len = 0;
			}

			if( nhrph->m.error.src_protocol_len ){

				addr_p = _rhp_pkt_push(tx_pkt,(int)nhrph->m.error.src_protocol_len);
				if( addr_p == NULL ){
					err = -EINVAL;
					RHP_BUG("");
					goto error;
				}

				memcpy(addr_p,src_proto_addr.addr.raw,nhrph->m.error.src_protocol_len);
				*nhrp_mesg_len_r += (int)nhrph->m.error.src_protocol_len;
				offset += (int)nhrph->m.error.src_protocol_len;
			}
		}

		{
			if( dst_proto_addr.addr_family == AF_INET ){
				nhrph->m.error.dst_protocol_len = RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN;
			}else if( dst_proto_addr.addr_family == AF_INET6 ){
				nhrph->m.error.dst_protocol_len = RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN;
			}else{
				nhrph->m.error.dst_protocol_len = 0;
			}

			if( nhrph->m.error.dst_protocol_len ){

				addr_p = _rhp_pkt_push(tx_pkt,(int)nhrph->m.error.dst_protocol_len);
				if( addr_p == NULL ){
					err = -EINVAL;
					RHP_BUG("");
					goto error;
				}

				memcpy(addr_p,dst_proto_addr.addr.raw,nhrph->m.error.dst_protocol_len);
				*nhrp_mesg_len_r += (int)nhrph->m.error.dst_protocol_len;
				offset += (int)nhrph->m.error.dst_protocol_len;
			}
		}

		{
			int error_cont_len = 0;
			u8* error_cont = nhrp_mesg->m.error->get_error_org_mesg(nhrp_mesg,&error_cont_len);

			if( error_cont ){

				addr_p = _rhp_pkt_push(tx_pkt,error_cont_len);
				if( addr_p == NULL ){
					err = -EINVAL;
					RHP_BUG("");
					goto error;
				}

				memcpy(addr_p,error_cont,error_cont_len);
				*nhrp_mesg_len_r += error_cont_len;
			}
		}

		nhrph->m.error.error_offset = ntohs((u16)offset);

		*nhrp_mesg_len_r += sizeof(rhp_proto_nhrp_error);

		break;


	case RHP_PROTO_NHRP_PKT_TRAFFIC_INDICATION:

		nhrph->m.traffic.traffic_code = htons(nhrp_mesg->m.traffic->get_traffic_code(nhrp_mesg));

		err = nhrp_mesg->m.traffic->get_src_nbma_addr(nhrp_mesg,&src_nbma_addr);
		if( err ){
			goto error;
		}

		err = nhrp_mesg->m.traffic->get_src_protocol_addr(nhrp_mesg,&src_proto_addr);
		if( err ){
			goto error;
		}

		err = nhrp_mesg->m.traffic->get_dst_protocol_addr(nhrp_mesg,&dst_proto_addr);
		if( err ){
			goto error;
		}

		{
			int addr_len;

			if( src_nbma_addr.addr_family == AF_INET ){
				addr_len = RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN;
			}else if( src_nbma_addr.addr_family == AF_INET6 ){
				addr_len = RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN;
			}else{
				addr_len = 0;
			}

			if( addr_len ){

				addr_p = _rhp_pkt_push(tx_pkt,addr_len);
				if( addr_p == NULL ){
					err = -EINVAL;
					RHP_BUG("");
					goto error;
				}

				memcpy(addr_p,src_nbma_addr.addr.raw,addr_len);
				*nhrp_mesg_len_r += addr_len;
			}
		}

		{
			if( src_proto_addr.addr_family == AF_INET ){
				nhrph->m.traffic.src_protocol_len = RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN;
			}else if( src_proto_addr.addr_family == AF_INET6 ){
				nhrph->m.traffic.src_protocol_len = RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN;
			}else{
				nhrph->m.traffic.src_protocol_len = 0;
			}

			if( nhrph->m.traffic.src_protocol_len ){

				addr_p = _rhp_pkt_push(tx_pkt,(int)nhrph->m.traffic.src_protocol_len);
				if( addr_p == NULL ){
					err = -EINVAL;
					RHP_BUG("");
					goto error;
				}

				memcpy(addr_p,src_proto_addr.addr.raw,nhrph->m.traffic.src_protocol_len);
				*nhrp_mesg_len_r += (int)nhrph->m.traffic.src_protocol_len;
			}
		}

		{
			if( dst_proto_addr.addr_family == AF_INET ){
				nhrph->m.traffic.dst_protocol_len = RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN;
			}else if( dst_proto_addr.addr_family == AF_INET6 ){
				nhrph->m.traffic.dst_protocol_len = RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN;
			}else{
				nhrph->m.traffic.dst_protocol_len = 0;
			}

			if( nhrph->m.traffic.dst_protocol_len ){

				addr_p = _rhp_pkt_push(tx_pkt,(int)nhrph->m.traffic.dst_protocol_len);
				if( addr_p == NULL ){
					err = -EINVAL;
					RHP_BUG("");
					goto error;
				}

				memcpy(addr_p,dst_proto_addr.addr.raw,nhrph->m.traffic.dst_protocol_len);
				*nhrp_mesg_len_r += (int)nhrph->m.traffic.dst_protocol_len;
			}
		}

		{
			int traffic_cont_len = 0;
			u8* traffic_cont = nhrp_mesg->m.traffic->get_traffic_org_mesg(nhrp_mesg,&traffic_cont_len);

			if( traffic_cont ){

				addr_p = _rhp_pkt_push(tx_pkt,traffic_cont_len);
				if( addr_p == NULL ){
					err = -EINVAL;
					RHP_BUG("");
					goto error;
				}

				memcpy(addr_p,traffic_cont,traffic_cont_len);
				*nhrp_mesg_len_r += traffic_cont_len;
			}
		}

		*nhrp_mesg_len_r += sizeof(rhp_proto_nhrp_traffic_indication);

		break;

	default:
		err = RHP_STATUS_NHRP_NOT_SUPPORTED_ATTR;
		goto error;
	}

	RHP_TRC(0,RHPTRCID_NHRP_MESG_SERIALIZE_BUILD_M_HEADER_RTRN,"xxxd",nhrp_mesg,tx_vpn,tx_pkt,*nhrp_mesg_len_r);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_MESG_SERIALIZE_BUILD_M_HEADER_ERR,"xxxE",nhrp_mesg,tx_vpn,tx_pkt,err);
	return err;
}

static int _rhp_nhrp_mesg_serialize_extensions(rhp_nhrp_mesg* nhrp_mesg,
		rhp_vpn* tx_vpn,rhp_packet* tx_pkt,int* nhrp_mesg_len_r)
{
	int err = -EINVAL;
	rhp_nhrp_ext* nhrp_ext = nhrp_mesg->ext_list_head;
	u8* tail_pre = tx_pkt->tail;
	int n = 0, end_ext_flag = 0;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_SERIALIZE_EXTENSIONS,"xxxxx",nhrp_mesg,tx_vpn,tx_pkt,nhrp_mesg_len_r,nhrp_mesg->ext_list_head);

	while( nhrp_ext ){

		u8* p0 = tx_pkt->tail;
		rhp_proto_nhrp_ext* nhrp_exth;

		nhrp_exth = (rhp_proto_nhrp_ext*)_rhp_pkt_push(tx_pkt,sizeof(rhp_proto_nhrp_ext));
		if( nhrp_exth == NULL ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		nhrp_exth->len = 0;
		nhrp_exth->type = htons((u16)nhrp_ext->type);

		if( nhrp_ext->compulsory_flag ){
			nhrp_exth->type |= (u16)RHP_PROTO_NHRP_EXT_FLAG_COMPULSORY;
		}

		if( nhrp_ext->type == RHP_PROTO_NHRP_EXT_TYPE_END ){
			end_ext_flag = 1;
		}

		*nhrp_mesg_len_r += sizeof(rhp_proto_nhrp_ext);

		if( nhrp_ext->cie_list_head ){

			rhp_nhrp_cie* nhrp_cie = nhrp_ext->cie_list_head;
			int pl = *nhrp_mesg_len_r;

			while( nhrp_cie ){

				err = _rhp_nhrp_mesg_serialize_cie(nhrp_mesg,tx_vpn,tx_pkt,nhrp_cie,nhrp_mesg_len_r);
				if( err ){
					goto error;
				}

				nhrp_cie = nhrp_cie->next;
			}

			nhrp_exth->len = htons((u16)(*nhrp_mesg_len_r - pl));

		}else if( nhrp_ext->ext_auth_key ){

			int ext_auth_len = (int)sizeof(rhp_proto_nhrp_ext_auth) + nhrp_ext->ext_auth_key_len;
			rhp_proto_nhrp_ext_auth* nhrp_ext_authh
				= (rhp_proto_nhrp_ext_auth*)_rhp_pkt_push(tx_pkt,ext_auth_len);
			if( nhrp_ext_authh == NULL ){
				RHP_BUG("");
				err = -EINVAL;
				goto error;
			}

			if( nhrp_ext->type != RHP_PROTO_NHRP_EXT_TYPE_AUTHENTICATION ){
				RHP_BUG("");
				err = -EINVAL;
				goto error;
			}

			nhrp_ext_authh->reserved = 0;
			nhrp_ext_authh->spi = htons(0x0001);

			memcpy((nhrp_ext_authh + 1),nhrp_ext->ext_auth_key,nhrp_ext->ext_auth_key_len);

			nhrp_exth->len = htons((u16)ext_auth_len);
			*nhrp_mesg_len_r += ext_auth_len;
		}

		RHP_TRC(0,RHPTRCID_NHRP_MESG_SERIALIZE_EXTENSIONS_ADD_EXT,"xxxxxxddwbxxdp",nhrp_mesg,tx_vpn,tx_pkt,nhrp_ext,nhrp_ext->next,nhrp_ext->cie_list_head,n,*nhrp_mesg_len_r,nhrp_ext->type,nhrp_ext->compulsory_flag,p0,tx_pkt->tail,(int)(tx_pkt->tail - p0),nhrp_ext->ext_auth_key_len,nhrp_ext->ext_auth_key);

		n++;
		nhrp_ext = nhrp_ext->next;
	}

	if( n ){

		u8* p0 = tx_pkt->tail;

		if( !end_ext_flag ){

			rhp_proto_nhrp_ext* nhrp_ext_endh
				= (rhp_proto_nhrp_ext*)_rhp_pkt_push(tx_pkt,sizeof(rhp_proto_nhrp_ext));
			if( nhrp_ext_endh == NULL ){
				RHP_BUG("");
				err = -EINVAL;
				goto error;
			}

			nhrp_ext_endh->type = htons(RHP_PROTO_NHRP_EXT_TYPE_END);
			nhrp_ext_endh->len = 0;

			*nhrp_mesg_len_r += sizeof(rhp_proto_nhrp_ext);
		}

		tx_pkt->l4.nhrph->fixed.extension_offset = htons((u16)(tail_pre - (u8*)tx_pkt->l4.nhrph));

		RHP_TRC(0,RHPTRCID_NHRP_MESG_SERIALIZE_EXTENSIONS_ADD_EXT_2,"xxxddxxd",nhrp_mesg,tx_vpn,tx_pkt,n,*nhrp_mesg_len_r,p0,tx_pkt->tail,(int)(tx_pkt->tail - p0));

	}else{

		tx_pkt->l4.nhrph->fixed.extension_offset = 0;
	}

	RHP_TRC(0,RHPTRCID_NHRP_MESG_SERIALIZE_EXTENSIONS_RTRN,"xxxdd",nhrp_mesg,tx_vpn,tx_pkt,*nhrp_mesg_len_r,n);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_MESG_SERIALIZE_EXTENSIONS_ERR,"xxxE",nhrp_mesg,tx_vpn,tx_pkt,err);
	return err;
}

static int _rhp_nhrp_mesg_serialize(rhp_nhrp_mesg* nhrp_mesg,rhp_vpn* tx_vpn,
		int mesg_max_len,rhp_packet** pkt_r)
{
	int err = -EINVAL;
	rhp_packet* tx_pkt = NULL;
	int nhrp_mesg_len = 0;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_SERIALIZE,"xxdx",nhrp_mesg,tx_vpn,mesg_max_len,pkt_r);

	if( !mesg_max_len ){

		rhp_childsa* cur_childsa = tx_vpn->childsa_list_head;
		while( cur_childsa ){

			// Newer one is adopted.
			if( cur_childsa->state == RHP_CHILDSA_STAT_MATURE 		||	// IKEv2
					cur_childsa->state == RHP_CHILDSA_STAT_REKEYING 	||	// IKEv2
					cur_childsa->state == RHP_IPSECSA_STAT_V1_MATURE 	||
					cur_childsa->state == RHP_IPSECSA_STAT_V1_REKEYING ){
				break;
			}

			cur_childsa = cur_childsa->next_vpn_list;
		}

		if( cur_childsa == NULL ){
			err = RHP_STATUS_ESP_NO_CHILDSA;
			goto error;
		}

		mesg_max_len = cur_childsa->pmtu_default;
	}


	tx_pkt = _rhp_nhrp_mesg_alloc_tx_pkt(tx_vpn,mesg_max_len);
	if( tx_pkt == NULL ){
		err = -ENOMEM;
		goto error;
	}

	err = _rhp_nhrp_mesg_serialize_build_f_header(nhrp_mesg,tx_vpn,tx_pkt,&nhrp_mesg_len);
	if( err ){
		goto error;
	}


	switch( nhrp_mesg->f_packet_type ){

	case RHP_PROTO_NHRP_PKT_RESOLUTION_REQ:
	case RHP_PROTO_NHRP_PKT_RESOLUTION_REP:
	case RHP_PROTO_NHRP_PKT_REGISTRATION_REQ:
	case RHP_PROTO_NHRP_PKT_REGISTRATION_REP:
	case RHP_PROTO_NHRP_PKT_PURGE_REQ:
	case RHP_PROTO_NHRP_PKT_PURGE_REP:

		err = _rhp_nhrp_mesg_serialize_build_m_header(nhrp_mesg,tx_vpn,tx_pkt,&nhrp_mesg_len);
		if( err ){
			goto error;
		}

		break;

	case RHP_PROTO_NHRP_PKT_ERROR_INDICATION:
	case RHP_PROTO_NHRP_PKT_TRAFFIC_INDICATION:

		err = _rhp_nhrp_mesg_serialize_build_m_header(nhrp_mesg,tx_vpn,tx_pkt,&nhrp_mesg_len);
		if( err ){
			goto error;
		}

		break;

	default:
		RHP_BUG("%d",nhrp_mesg->f_packet_type);
		err = -EINVAL;
		goto error;
	}

	{
		rhp_nhrp_ext* nhrp_ext_auth;

		nhrp_ext_auth = nhrp_mesg->remove_extension(nhrp_mesg,RHP_PROTO_NHRP_EXT_TYPE_AUTHENTICATION);
		if( nhrp_ext_auth ){
			rhp_nhrp_ext_free(nhrp_ext_auth);
		}

		if( tx_vpn->nhrp.key ){


			nhrp_ext_auth = rhp_nhrp_ext_alloc(RHP_PROTO_NHRP_EXT_TYPE_AUTHENTICATION,1);
			if( nhrp_ext_auth == NULL ){
				err = -ENOMEM;
				goto error;
			}

			nhrp_ext_auth->ext_auth_key = (u8*)_rhp_malloc(tx_vpn->nhrp.key_len);
			if( nhrp_ext_auth->ext_auth_key == NULL ){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}

			memcpy(nhrp_ext_auth->ext_auth_key,tx_vpn->nhrp.key,tx_vpn->nhrp.key_len);
			nhrp_ext_auth->ext_auth_key_len = tx_vpn->nhrp.key_len;


			err = nhrp_mesg->add_extension(nhrp_mesg,nhrp_ext_auth);
			if( err ){
				rhp_nhrp_ext_free(nhrp_ext_auth);
				goto error;
			}
		}
	}


	err = _rhp_nhrp_mesg_serialize_extensions(nhrp_mesg,tx_vpn,tx_pkt,&nhrp_mesg_len);
	if( err ){
		goto error;
	}


	tx_pkt->l4.nhrph->fixed.len = htons((u16)nhrp_mesg_len);
	_rhp_proto_nhrp_set_csum(tx_pkt->l4.nhrph);

	*pkt_r = tx_pkt;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_SERIALIZE_RTRN,"xxxx",nhrp_mesg,tx_vpn,pkt_r,*pkt_r);
	return 0;

error:
	if( tx_pkt ){
		rhp_pkt_unhold(tx_pkt);
	}
	RHP_TRC(0,RHPTRCID_NHRP_MESG_SERIALIZE_ERR,"xxE",nhrp_mesg,tx_vpn,err);
	return err;
}


static void _rhp_nhrp_m_error_set_error_code(rhp_nhrp_mesg* nhrp_mesg,u16 error_code)
{
	nhrp_mesg->m.error->error_code = error_code;
	RHP_TRC(0,RHPTRCID_NHRP_M_ERROR_SET_ERROR_CODE,"xw",nhrp_mesg,error_code);
	return;
}

static u16 _rhp_nhrp_m_error_get_error_code(rhp_nhrp_mesg* nhrp_mesg)
{
	RHP_TRC(0,RHPTRCID_NHRP_M_ERROR_GET_ERROR_CODE,"xw",nhrp_mesg,nhrp_mesg->m.error->error_code);
	return nhrp_mesg->m.error->error_code;
}

static u8* _rhp_nhrp_m_error_get_error_org_mesg(rhp_nhrp_mesg* nhrp_mesg,int* error_org_mesg_len_r)
{
	*error_org_mesg_len_r = nhrp_mesg->m.error->error_org_mesg_len;
	RHP_TRC(0,RHPTRCID_NHRP_M_ERROR_GET_ERROR_ORG_MESG,"xp",nhrp_mesg,*error_org_mesg_len_r,nhrp_mesg->m.error->error_org_mesg);
	return nhrp_mesg->m.error->error_org_mesg;
}

static int _rhp_nhrp_m_error_set_error_org_mesg(rhp_nhrp_mesg* nhrp_mesg,int error_org_mesg_len,u8* error_org_mesg)
{
	RHP_TRC(0,RHPTRCID_NHRP_M_ERROR_SET_ERROR_ORG_MESG,"xp",nhrp_mesg,error_org_mesg_len,error_org_mesg);

	if( nhrp_mesg->m.error->error_org_mesg ){
		_rhp_free(nhrp_mesg->m.error->error_org_mesg);
		nhrp_mesg->m.error->error_org_mesg_len = 0;
	}

	nhrp_mesg->m.error->error_org_mesg = (u8*)_rhp_malloc(error_org_mesg_len);
	if( nhrp_mesg->m.error->error_org_mesg == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	memcpy(nhrp_mesg->m.error->error_org_mesg,error_org_mesg,error_org_mesg_len);
	nhrp_mesg->m.error->error_org_mesg_len = error_org_mesg_len;

	RHP_TRC(0,RHPTRCID_NHRP_M_ERROR_SET_ERROR_ORG_MESG_RTRN,"xp",nhrp_mesg,error_org_mesg_len,nhrp_mesg->m.error->error_org_mesg);
	return 0;
}

static int _rhp_nhrp_m_error_set_src_nbma_addr(rhp_nhrp_mesg* nhrp_mesg,int addr_family,u8* src_nbma_addr)
{
	int addr_len;

	if( addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_NHRP_M_ERROR_SET_SRC_NBMA_ADDR_V4,"xLd4",nhrp_mesg,"AF",addr_family,*((u32*)src_nbma_addr));
		addr_len = 4;
	}else if( addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_NHRP_M_ERROR_SET_SRC_NBMA_ADDR_V6,"xLd6",nhrp_mesg,"AF",addr_family,src_nbma_addr);
		addr_len = 16;
	}else{
		RHP_BUG("%d",addr_family);
		return -EINVAL;
	}

	memset(&(nhrp_mesg->m.error->src_nbma_addr),0,sizeof(rhp_ip_addr));

	nhrp_mesg->m.error->src_nbma_addr.addr_family = addr_family;
	memcpy(nhrp_mesg->m.error->src_nbma_addr.addr.raw,src_nbma_addr,addr_len);

	RHP_TRC(0,RHPTRCID_NHRP_M_ERROR_SET_SRC_NBMA_ADDR_RTRN,"x",nhrp_mesg);
	rhp_ip_addr_dump("nhrp_mesg->m.error->src_nbma_addr",&(nhrp_mesg->m.error->src_nbma_addr));
	return 0;
}

static int _rhp_nhrp_m_error_get_src_nbma_addr(rhp_nhrp_mesg* nhrp_mesg,rhp_ip_addr* src_nbma_addr_r)
{
	memcpy(src_nbma_addr_r,&(nhrp_mesg->m.error->src_nbma_addr),sizeof(rhp_ip_addr));
	RHP_TRC(0,RHPTRCID_NHRP_M_ERROR_GET_SRC_NBMA_ADDR,"xx",nhrp_mesg,src_nbma_addr_r);
	rhp_ip_addr_dump("src_nbma_addr_r",src_nbma_addr_r);
	return 0;
}

static int _rhp_nhrp_m_error_set_src_protocol_addr(rhp_nhrp_mesg* nhrp_mesg,int addr_family,u8* src_protocol_addr)
{
	int addr_len;

	if( addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_NHRP_M_ERROR_SET_SRC_PROTOCOL_ADDR_V4,"xLd4",nhrp_mesg,"AF",addr_family,*((u32*)src_protocol_addr));
		addr_len = 4;
	}else if( addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_NHRP_M_ERROR_SET_SRC_PROTOCOL_ADDR_V6,"xLd6",nhrp_mesg,"AF",addr_family,src_protocol_addr);
		addr_len = 16;
	}else{
		RHP_BUG("%d",addr_family);
		return -EINVAL;
	}

	memset(&(nhrp_mesg->m.error->src_protocol_addr),0,sizeof(rhp_ip_addr));

	nhrp_mesg->m.error->src_protocol_addr.addr_family = addr_family;
	memcpy(nhrp_mesg->m.error->src_protocol_addr.addr.raw,src_protocol_addr,addr_len);

	RHP_TRC(0,RHPTRCID_NHRP_M_ERROR_SET_SRC_PROTOCOL_ADDR_RTRN,"x",nhrp_mesg);
	rhp_ip_addr_dump("nhrp_mesg->m.error->src_protocol_addr",&(nhrp_mesg->m.error->src_protocol_addr));
	return 0;
}

static int _rhp_nhrp_m_error_get_src_protocol_addr(rhp_nhrp_mesg* nhrp_mesg,rhp_ip_addr* src_protocol_addr_r)
{
	memcpy(src_protocol_addr_r,&(nhrp_mesg->m.error->src_protocol_addr),sizeof(rhp_ip_addr));
	RHP_TRC(0,RHPTRCID_NHRP_M_ERROR_GET_SRC_PROTOCOL_ADDR,"xx",nhrp_mesg,src_protocol_addr_r);
	rhp_ip_addr_dump("src_protocol_addr_r",src_protocol_addr_r);
	return 0;
}

static int _rhp_nhrp_m_error_set_dst_protocol_addr(rhp_nhrp_mesg* nhrp_mesg,int addr_family,u8* dst_protocol_addr)
{
	int addr_len;

	if( addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_NHRP_M_ERROR_SET_DST_PROTOCOL_ADDR_V4,"xLd4",nhrp_mesg,"AF",addr_family,*((u32*)dst_protocol_addr));
		addr_len = 4;
	}else if( addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_NHRP_M_ERROR_SET_DST_PROTOCOL_ADDR_V6,"xLd6",nhrp_mesg,"AF",addr_family,dst_protocol_addr);
		addr_len = 16;
	}else{
		RHP_BUG("%d",addr_family);
		return -EINVAL;
	}

	memset(&(nhrp_mesg->m.error->dst_protocol_addr),0,sizeof(rhp_ip_addr));

	nhrp_mesg->m.error->dst_protocol_addr.addr_family = addr_family;
	memcpy(nhrp_mesg->m.error->dst_protocol_addr.addr.raw,dst_protocol_addr,addr_len);

	RHP_TRC(0,RHPTRCID_NHRP_M_ERROR_SET_DST_PROTOCOL_ADDR_RTRN,"x",nhrp_mesg);
	rhp_ip_addr_dump("nhrp_mesg->m.error->dst_protocol_addr",&(nhrp_mesg->m.error->dst_protocol_addr));
	return 0;
}

static int _rhp_nhrp_m_error_get_dst_protocol_addr(rhp_nhrp_mesg* nhrp_mesg,rhp_ip_addr* dst_protocol_addr_r)
{
	memcpy(dst_protocol_addr_r,&(nhrp_mesg->m.error->dst_protocol_addr),sizeof(rhp_ip_addr));
	RHP_TRC(0,RHPTRCID_NHRP_M_ERROR_GET_DST_PROTOCOL_ADDR,"xx",nhrp_mesg,dst_protocol_addr_r);
	rhp_ip_addr_dump("dst_protocol_addr_r",dst_protocol_addr_r);
	return 0;
}

static void _rhp_nhrp_mesg_m_error_indication_free(rhp_nhrp_m_error_indication* nhrp_m_error)
{
	RHP_TRC(0,RHPTRCID_NHRP_M_ERROR_INDICATION_FREE,"xx",nhrp_m_error,nhrp_m_error->error_org_mesg);

	if( nhrp_m_error->error_org_mesg ){
		_rhp_free(nhrp_m_error->error_org_mesg);
	}

	_rhp_free(nhrp_m_error);

	RHP_TRC(0,RHPTRCID_NHRP_M_ERROR_INDICATION_FREE_RTRN,"x",nhrp_m_error);
	return;
}

static rhp_nhrp_m_error_indication* _rhp_nhrp_mesg_m_error_indication_alloc()
{
	rhp_nhrp_m_error_indication* nhrp_m_error
		= (rhp_nhrp_m_error_indication*)_rhp_malloc(sizeof(rhp_nhrp_m_error_indication));

	if( nhrp_m_error == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(nhrp_m_error,0,sizeof(rhp_nhrp_m_error_indication));

	nhrp_m_error->tag[0] = '#';
	nhrp_m_error->tag[1] = 'N';
	nhrp_m_error->tag[2] = 'H';
	nhrp_m_error->tag[3] = 'E';

	nhrp_m_error->set_error_code = _rhp_nhrp_m_error_set_error_code;
	nhrp_m_error->get_error_code = _rhp_nhrp_m_error_get_error_code;
	nhrp_m_error->get_error_org_mesg = _rhp_nhrp_m_error_get_error_org_mesg;
	nhrp_m_error->set_error_org_mesg = _rhp_nhrp_m_error_set_error_org_mesg;
	nhrp_m_error->set_src_nbma_addr = _rhp_nhrp_m_error_set_src_nbma_addr;
	nhrp_m_error->get_src_nbma_addr = _rhp_nhrp_m_error_get_src_nbma_addr;
	nhrp_m_error->set_src_protocol_addr = _rhp_nhrp_m_error_set_src_protocol_addr;
	nhrp_m_error->get_src_protocol_addr = _rhp_nhrp_m_error_get_src_protocol_addr;
	nhrp_m_error->set_dst_protocol_addr = _rhp_nhrp_m_error_set_dst_protocol_addr;
	nhrp_m_error->get_dst_protocol_addr = _rhp_nhrp_m_error_get_dst_protocol_addr;

	RHP_TRC(0,RHPTRCID_NHRP_M_ERROR_INDICATION_ALLOC,"x",nhrp_m_error);

	return nhrp_m_error;
}


static void _rhp_nhrp_m_traffic_set_traffic_code(rhp_nhrp_mesg* nhrp_mesg,u16 traffic_code)
{
	nhrp_mesg->m.traffic->traffic_code = traffic_code;
	RHP_TRC(0,RHPTRCID_NHRP_M_TRAFFIC_SET_TRAFFIC_CODE,"xw",nhrp_mesg,traffic_code);
	return;
}

static u16 _rhp_nhrp_m_traffic_get_traffic_code(rhp_nhrp_mesg* nhrp_mesg)
{
	RHP_TRC(0,RHPTRCID_NHRP_M_TRAFFIC_GET_TRAFFIC_CODE,"xw",nhrp_mesg,nhrp_mesg->m.traffic->traffic_code);
	return nhrp_mesg->m.traffic->traffic_code;
}

static u8* _rhp_nhrp_m_traffic_get_traffic_org_mesg(rhp_nhrp_mesg* nhrp_mesg,int* traffic_org_mesg_len_r)
{
	*traffic_org_mesg_len_r = nhrp_mesg->m.traffic->traffic_org_mesg_len;
	RHP_TRC(0,RHPTRCID_NHRP_M_TRAFFIC_GET_TRAFFIC_ORG_MESG,"xp",nhrp_mesg,*traffic_org_mesg_len_r,nhrp_mesg->m.traffic->traffic_org_mesg);
	return nhrp_mesg->m.traffic->traffic_org_mesg;
}

static int _rhp_nhrp_m_traffic_set_traffic_org_mesg(rhp_nhrp_mesg* nhrp_mesg,int traffic_org_mesg_len,u8* traffic_org_mesg)
{
	RHP_TRC(0,RHPTRCID_NHRP_M_TRAFFIC_SET_TRAFFIC_ORG_MESG,"xp",nhrp_mesg,traffic_org_mesg_len,traffic_org_mesg);

	if( nhrp_mesg->m.traffic->traffic_org_mesg ){
		_rhp_free(nhrp_mesg->m.traffic->traffic_org_mesg);
		nhrp_mesg->m.traffic->traffic_org_mesg_len = 0;
	}

	nhrp_mesg->m.traffic->traffic_org_mesg = (u8*)_rhp_malloc(traffic_org_mesg_len);
	if( nhrp_mesg->m.traffic->traffic_org_mesg == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	memcpy(nhrp_mesg->m.traffic->traffic_org_mesg,traffic_org_mesg,traffic_org_mesg_len);
	nhrp_mesg->m.traffic->traffic_org_mesg_len = traffic_org_mesg_len;

	RHP_TRC(0,RHPTRCID_NHRP_M_TRAFFIC_SET_TRAFFIC_ORG_MESG_RTRN,"xp",nhrp_mesg,traffic_org_mesg_len,nhrp_mesg->m.traffic->traffic_org_mesg);
	return 0;
}

static int _rhp_nhrp_m_traffic_get_org_mesg_addrs(rhp_nhrp_mesg* nhrp_mesg,
		rhp_ip_addr* org_src_addr_r,rhp_ip_addr* org_dst_addr_r)
{
	u8 ver;

	if( nhrp_mesg->m.traffic->traffic_org_mesg == NULL ||
			nhrp_mesg->m.traffic->traffic_org_mesg_len < (int)sizeof(rhp_proto_ip_v4) ){
		RHP_BUG("");
		return -EINVAL;
	}

	ver = ((rhp_proto_ip_v4*)nhrp_mesg->m.traffic->traffic_org_mesg)->ver;

	if( ver == 4 ){

		if( org_src_addr_r ){
			org_src_addr_r->addr_family = AF_INET;
			org_src_addr_r->addr.v4 = ((rhp_proto_ip_v4*)nhrp_mesg->m.traffic->traffic_org_mesg)->src_addr;
		}
		if( org_dst_addr_r ){
			org_dst_addr_r->addr_family = AF_INET;
			org_dst_addr_r->addr.v4 = ((rhp_proto_ip_v4*)nhrp_mesg->m.traffic->traffic_org_mesg)->dst_addr;
		}

	}else if( ver == 6 && nhrp_mesg->m.traffic->traffic_org_mesg_len >= (int)sizeof(rhp_proto_ip_v6) ){

		if( org_src_addr_r ){
			org_src_addr_r->addr_family = AF_INET6;
			memcpy(org_src_addr_r->addr.v6,((rhp_proto_ip_v6*)nhrp_mesg->m.traffic->traffic_org_mesg)->src_addr,16);
		}
		if( org_dst_addr_r ){
			org_dst_addr_r->addr_family = AF_INET6;
			memcpy(org_dst_addr_r->addr.v6,((rhp_proto_ip_v6*)nhrp_mesg->m.traffic->traffic_org_mesg)->dst_addr,16);
		}

	}else{
		RHP_BUG("%d",ver);
		return -EINVAL;
	}

	RHP_TRC(0,RHPTRCID_NHRP_M_TRAFFIC_GET_ORG_MESG_DST_ADDR,"xp",nhrp_mesg,nhrp_mesg->m.traffic->traffic_org_mesg_len,nhrp_mesg->m.traffic->traffic_org_mesg);
	rhp_ip_addr_dump("org_src_addr_r",org_src_addr_r);
	rhp_ip_addr_dump("org_dst_addr_r",org_dst_addr_r);
	return 0;
}


static int _rhp_nhrp_m_traffic_set_src_nbma_addr(rhp_nhrp_mesg* nhrp_mesg,int addr_family,u8* src_nbma_addr)
{
	int addr_len;

	if( addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_NHRP_M_TRAFFIC_SET_SRC_NBMA_ADDR_V4,"xLd4",nhrp_mesg,"AF",addr_family,*((u32*)src_nbma_addr));
		addr_len = 4;
	}else if( addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_NHRP_M_TRAFFIC_SET_SRC_NBMA_ADDR_V6,"xLd6",nhrp_mesg,"AF",addr_family,src_nbma_addr);
		addr_len = 16;
	}else{
		RHP_BUG("%d",addr_family);
		return -EINVAL;
	}

	memset(&(nhrp_mesg->m.traffic->src_nbma_addr),0,sizeof(rhp_ip_addr));

	nhrp_mesg->m.traffic->src_nbma_addr.addr_family = addr_family;
	memcpy(nhrp_mesg->m.traffic->src_nbma_addr.addr.raw,src_nbma_addr,addr_len);

	RHP_TRC(0,RHPTRCID_NHRP_M_TRAFFIC_SET_SRC_NBMA_ADDR_RTRN,"x",nhrp_mesg);
	rhp_ip_addr_dump("nhrp_mesg->m.traffic->src_nbma_addr",&(nhrp_mesg->m.traffic->src_nbma_addr));
	return 0;
}

static int _rhp_nhrp_m_traffic_get_src_nbma_addr(rhp_nhrp_mesg* nhrp_mesg,rhp_ip_addr* src_nbma_addr_r)
{
	memcpy(src_nbma_addr_r,&(nhrp_mesg->m.traffic->src_nbma_addr),sizeof(rhp_ip_addr));
	RHP_TRC(0,RHPTRCID_NHRP_M_TRAFFIC_GET_SRC_NBMA_ADDR,"xx",nhrp_mesg,src_nbma_addr_r);
	rhp_ip_addr_dump("src_nbma_addr_r",src_nbma_addr_r);
	return 0;
}

static int _rhp_nhrp_m_traffic_set_src_protocol_addr(rhp_nhrp_mesg* nhrp_mesg,int addr_family,u8* src_protocol_addr)
{
	int addr_len;

	if( addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_NHRP_M_TRAFFIC_SET_SRC_PROTOCOL_ADDR_V4,"xLd4",nhrp_mesg,"AF",addr_family,*((u32*)src_protocol_addr));
		addr_len = 4;
	}else if( addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_NHRP_M_TRAFFIC_SET_SRC_PROTOCOL_ADDR_V6,"xLd6",nhrp_mesg,"AF",addr_family,src_protocol_addr);
		addr_len = 16;
	}else{
		RHP_BUG("%d",addr_family);
		return -EINVAL;
	}

	memset(&(nhrp_mesg->m.traffic->src_protocol_addr),0,sizeof(rhp_ip_addr));

	nhrp_mesg->m.traffic->src_protocol_addr.addr_family = addr_family;
	memcpy(nhrp_mesg->m.traffic->src_protocol_addr.addr.raw,src_protocol_addr,addr_len);

	RHP_TRC(0,RHPTRCID_NHRP_M_TRAFFIC_SET_SRC_PROTOCOL_ADDR_RTRN,"x",nhrp_mesg);
	rhp_ip_addr_dump("nhrp_mesg->m.traffic->src_protocol_addr",&(nhrp_mesg->m.traffic->src_protocol_addr));
	return 0;
}

static int _rhp_nhrp_m_traffic_get_src_protocol_addr(rhp_nhrp_mesg* nhrp_mesg,rhp_ip_addr* src_protocol_addr_r)
{
	memcpy(src_protocol_addr_r,&(nhrp_mesg->m.traffic->src_protocol_addr),sizeof(rhp_ip_addr));
	RHP_TRC(0,RHPTRCID_NHRP_M_TRAFFIC_GET_SRC_PROTOCOL_ADDR,"xx",nhrp_mesg,src_protocol_addr_r);
	rhp_ip_addr_dump("src_protocol_addr_r",src_protocol_addr_r);
	return 0;
}

static int _rhp_nhrp_m_traffic_set_dst_protocol_addr(rhp_nhrp_mesg* nhrp_mesg,int addr_family,u8* dst_protocol_addr)
{
	int addr_len;

	if( addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_NHRP_M_TRAFFIC_SET_DST_PROTOCOL_ADDR_V4,"xLd4",nhrp_mesg,"AF",addr_family,*((u32*)dst_protocol_addr));
		addr_len = 4;
	}else if( addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_NHRP_M_TRAFFIC_SET_DST_PROTOCOL_ADDR_V6,"xLd6",nhrp_mesg,"AF",addr_family,dst_protocol_addr);
		addr_len = 16;
	}else{
		RHP_BUG("%d",addr_family);
		return -EINVAL;
	}

	memset(&(nhrp_mesg->m.traffic->dst_protocol_addr),0,sizeof(rhp_ip_addr));

	nhrp_mesg->m.traffic->dst_protocol_addr.addr_family = addr_family;
	memcpy(nhrp_mesg->m.traffic->dst_protocol_addr.addr.raw,dst_protocol_addr,addr_len);

	RHP_TRC(0,RHPTRCID_NHRP_M_TRAFFIC_SET_DST_PROTOCOL_ADDR_RTRN,"x",nhrp_mesg);
	rhp_ip_addr_dump("nhrp_mesg->m.traffic->dst_protocol_addr",&(nhrp_mesg->m.traffic->dst_protocol_addr));
	return 0;
}

static int _rhp_nhrp_m_traffic_get_dst_protocol_addr(rhp_nhrp_mesg* nhrp_mesg,rhp_ip_addr* dst_protocol_addr_r)
{
	memcpy(dst_protocol_addr_r,&(nhrp_mesg->m.traffic->dst_protocol_addr),sizeof(rhp_ip_addr));
	RHP_TRC(0,RHPTRCID_NHRP_M_TRAFFIC_GET_DST_PROTOCOL_ADDR,"xx",nhrp_mesg,dst_protocol_addr_r);
	rhp_ip_addr_dump("dst_protocol_addr_r",dst_protocol_addr_r);
	return 0;
}

static void _rhp_nhrp_mesg_m_traffic_indication_free(rhp_nhrp_m_traffic_indication* nhrp_m_traffic)
{
	RHP_TRC(0,RHPTRCID_NHRP_M_TRAFFIC_INDICATION_FREE,"xx",nhrp_m_traffic,nhrp_m_traffic->traffic_org_mesg);

	if( nhrp_m_traffic->traffic_org_mesg ){
		_rhp_free(nhrp_m_traffic->traffic_org_mesg);
	}

	_rhp_free(nhrp_m_traffic);

	RHP_TRC(0,RHPTRCID_NHRP_M_TRAFFIC_INDICATION_FREE_RTRN,"x",nhrp_m_traffic);
	return;
}

static rhp_nhrp_m_traffic_indication* _rhp_nhrp_mesg_m_traffic_indication_alloc()
{
	rhp_nhrp_m_traffic_indication* nhrp_m_traffic
		= (rhp_nhrp_m_traffic_indication*)_rhp_malloc(sizeof(rhp_nhrp_m_traffic_indication));

	if( nhrp_m_traffic == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(nhrp_m_traffic,0,sizeof(rhp_nhrp_m_traffic_indication));

	nhrp_m_traffic->tag[0] = '#';
	nhrp_m_traffic->tag[1] = 'N';
	nhrp_m_traffic->tag[2] = 'H';
	nhrp_m_traffic->tag[3] = 'T';

	nhrp_m_traffic->set_traffic_code = _rhp_nhrp_m_traffic_set_traffic_code;
	nhrp_m_traffic->get_traffic_code = _rhp_nhrp_m_traffic_get_traffic_code;
	nhrp_m_traffic->get_traffic_org_mesg = _rhp_nhrp_m_traffic_get_traffic_org_mesg;
	nhrp_m_traffic->set_traffic_org_mesg = _rhp_nhrp_m_traffic_set_traffic_org_mesg;
	nhrp_m_traffic->get_org_mesg_addrs = _rhp_nhrp_m_traffic_get_org_mesg_addrs;
	nhrp_m_traffic->set_src_nbma_addr = _rhp_nhrp_m_traffic_set_src_nbma_addr;
	nhrp_m_traffic->get_src_nbma_addr = _rhp_nhrp_m_traffic_get_src_nbma_addr;
	nhrp_m_traffic->set_src_protocol_addr = _rhp_nhrp_m_traffic_set_src_protocol_addr;
	nhrp_m_traffic->get_src_protocol_addr = _rhp_nhrp_m_traffic_get_src_protocol_addr;
	nhrp_m_traffic->set_dst_protocol_addr = _rhp_nhrp_m_traffic_set_dst_protocol_addr;
	nhrp_m_traffic->get_dst_protocol_addr = _rhp_nhrp_m_traffic_get_dst_protocol_addr;

	RHP_TRC(0,RHPTRCID_NHRP_M_TRAFFIC_INDICATION_ALLOC,"x",nhrp_m_traffic);
	return nhrp_m_traffic;
}


static void _rhp_nhrp_mesg_free(rhp_nhrp_mesg* nhrp_mesg)
{

	RHP_TRC(0,RHPTRCID_NHRP_MESG_FREE,"xxxxx",nhrp_mesg,nhrp_mesg->m.raw,nhrp_mesg->rx_pkt_ref,RHP_PKT_REF(nhrp_mesg->rx_pkt_ref),nhrp_mesg->ext_list_head);

  if( nhrp_mesg->rx_pkt_ref ){
    rhp_pkt_unhold(nhrp_mesg->rx_pkt_ref);
  }

  if( nhrp_mesg->tx_pkt_ref ){
    rhp_pkt_unhold(nhrp_mesg->tx_pkt_ref);
  }

  if( nhrp_mesg->m.raw ){

  	switch( nhrp_mesg->f_packet_type ){

		case RHP_PROTO_NHRP_PKT_RESOLUTION_REQ:
		case RHP_PROTO_NHRP_PKT_RESOLUTION_REP:
		case RHP_PROTO_NHRP_PKT_REGISTRATION_REQ:
		case RHP_PROTO_NHRP_PKT_REGISTRATION_REP:
		case RHP_PROTO_NHRP_PKT_PURGE_REQ:
		case RHP_PROTO_NHRP_PKT_PURGE_REP:

			_rhp_nhrp_mesg_m_mandatory_free(nhrp_mesg->m.mandatory);
			break;

		case RHP_PROTO_NHRP_PKT_ERROR_INDICATION:

			_rhp_nhrp_mesg_m_error_indication_free(nhrp_mesg->m.error);
			break;

		case RHP_PROTO_NHRP_PKT_TRAFFIC_INDICATION:

			_rhp_nhrp_mesg_m_traffic_indication_free(nhrp_mesg->m.traffic);
			break;

		default:
			if( nhrp_mesg->m.raw ){
				RHP_BUG("0x%x",(unsigned long)nhrp_mesg->m.raw);
			}
			break;
		}
  }

  {
  	rhp_nhrp_ext* nhrp_ext = nhrp_mesg->ext_list_head;
  	while( nhrp_ext ){

  		rhp_nhrp_ext* nhrp_ext_n = nhrp_ext->next;

  		rhp_nhrp_ext_free(nhrp_ext);

  		nhrp_ext = nhrp_ext_n;
  	}
  }


  if( nhrp_mesg->rx_vpn_ref ){
  	rhp_vpn_unhold(nhrp_mesg->rx_vpn_ref);
  }
  if( nhrp_mesg->tx_vpn_ref ){
  	rhp_vpn_unhold(nhrp_mesg->tx_vpn_ref);
  }

  _rhp_atomic_destroy(&(nhrp_mesg->refcnt));

	_rhp_free(nhrp_mesg);

	RHP_TRC(0,RHPTRCID_NHRP_MESG_FREE_RTRN,"x",nhrp_mesg);
	return;
}

void rhp_nhrp_mesg_hold(rhp_nhrp_mesg* nhrp_mesg)
{
  RHP_TRC(0,RHPTRCID_NHRP_MESG_HOLD,"x",nhrp_mesg);

  _rhp_atomic_inc(&(nhrp_mesg->refcnt));

  RHP_TRC(0,RHPTRCID_NHRP_MESG_HOLD_RTRN,"xd",nhrp_mesg,_rhp_atomic_read(&(nhrp_mesg->refcnt)));

  return;
}

void rhp_nhrp_mesg_unhold(rhp_nhrp_mesg* nhrp_mesg)
{
  RHP_TRC(0,RHPTRCID_NHRP_MESG_UNHOLD,"x",nhrp_mesg);

  if( _rhp_atomic_dec_and_test(&(nhrp_mesg->refcnt)) ){

  	_rhp_nhrp_mesg_free(nhrp_mesg);

  	RHP_TRC(0,RHPTRCID_NHRP_MESG_UNHOLD_FREE_RTRN,"x",nhrp_mesg);

  }else{

  	RHP_TRC(0,RHPTRCID_NHRP_MESG_UNHOLD_RTRN,"xd",nhrp_mesg,_rhp_atomic_read(&(nhrp_mesg->refcnt)));
  }

  return;
}


rhp_nhrp_mesg* rhp_nhrp_mesg_alloc(u16 f_addr_family,u8 f_packet_type)
{
	rhp_nhrp_mesg* nhrp_mesg = (rhp_nhrp_mesg*)_rhp_malloc(sizeof(rhp_nhrp_mesg));

  RHP_TRC(0,RHPTRCID_NHRP_MESG_ALLOC,"Wb",f_addr_family,f_packet_type);

	if( nhrp_mesg == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(nhrp_mesg,0,sizeof(rhp_nhrp_mesg));

	nhrp_mesg->tag[0] = '#';
	nhrp_mesg->tag[1] = 'N';
	nhrp_mesg->tag[2] = 'H';
	nhrp_mesg->tag[3] = 'R';

	nhrp_mesg->f_addr_family = f_addr_family;
	nhrp_mesg->f_packet_type = f_packet_type;
	nhrp_mesg->f_hop_count = (u8)rhp_gcfg_nhrp_default_hop_count;


	switch( f_packet_type ){

	case RHP_PROTO_NHRP_PKT_RESOLUTION_REQ:
	case RHP_PROTO_NHRP_PKT_RESOLUTION_REP:
	case RHP_PROTO_NHRP_PKT_REGISTRATION_REQ:
	case RHP_PROTO_NHRP_PKT_REGISTRATION_REP:
	case RHP_PROTO_NHRP_PKT_PURGE_REQ:
	case RHP_PROTO_NHRP_PKT_PURGE_REP:

		nhrp_mesg->m.mandatory = _rhp_nhrp_mesg_m_mandatory_alloc();
		break;

	case RHP_PROTO_NHRP_PKT_ERROR_INDICATION:

		nhrp_mesg->m.error = _rhp_nhrp_mesg_m_error_indication_alloc();
		break;

	case RHP_PROTO_NHRP_PKT_TRAFFIC_INDICATION:

		nhrp_mesg->m.traffic = _rhp_nhrp_mesg_m_traffic_indication_alloc();
		break;

	default:
		RHP_BUG("%d",f_packet_type);
		_rhp_free(nhrp_mesg);
		return NULL;
	}

	if( nhrp_mesg->m.raw == NULL ){
		RHP_BUG("");
		_rhp_free(nhrp_mesg);
		return NULL;
	}


	nhrp_mesg->get_addr_family = _rhp_nhrp_mesg_get_addr_family;
	nhrp_mesg->get_packet_type = _rhp_nhrp_mesg_get_packet_type;
	nhrp_mesg->dec_hop_count = _rhp_nhrp_mesg_dec_hop_count;
	nhrp_mesg->get_rx_nbma_src_addr = _rhp_nhrp_mesg_get_rx_nbma_src_addr;
	nhrp_mesg->get_rx_nbma_dst_addr = _rhp_nhrp_mesg_get_rx_nbma_dst_addr;
	nhrp_mesg->add_extension = _rhp_nhrp_mesg_add_extension;
	nhrp_mesg->get_extension = _rhp_nhrp_mesg_get_extension;
	nhrp_mesg->remove_extension = _rhp_nhrp_mesg_remove_extension;
	nhrp_mesg->enum_extension = _rhp_nhrp_mesg_enum_extension;
	nhrp_mesg->ext_auth_check_key = _rhp_nhrp_mesg_ext_auth_check_key;
	nhrp_mesg->serialize = _rhp_nhrp_mesg_serialize;

  _rhp_atomic_init(&(nhrp_mesg->refcnt));
  _rhp_atomic_set(&(nhrp_mesg->refcnt),1);

  RHP_TRC(0,RHPTRCID_NHRP_MESG_ALLOC_RTRN,"Wbx",f_addr_family,f_packet_type,nhrp_mesg);
	return nhrp_mesg;
}

static int _rhp_nhrp_mesg_rx_parse_fixed_header(rhp_packet* rx_pkt,
		rhp_proto_nhrp* nhrph,rhp_proto_nhrp_fixed* nhrp_fixedh,
		rhp_nhrp_mesg** nhrp_mesg_r)
{
	int err = -EINVAL;
	rhp_nhrp_mesg* nhrp_mesg = NULL;

  RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_FIXED_HEADER,"xxxxp",rx_pkt,nhrph,nhrp_fixedh,nhrp_mesg_r,((((u8*)nhrp_fixedh) + sizeof(rhp_proto_nhrp_fixed)) <= rx_pkt->end ? sizeof(rhp_proto_nhrp_fixed) : 0),(u8*)nhrp_fixedh);

	if( nhrp_fixedh->address_family_no != RHP_PROTO_NHRP_ADDR_FAMILY_IPV4 &&
			nhrp_fixedh->address_family_no != RHP_PROTO_NHRP_ADDR_FAMILY_IPV6 ){
		err = RHP_STATUS_NHRP_NOT_SUPPORTED_ATTR;
	  RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_FIXED_HEADER_UNSUP_ADDR_FAMILY,"xW",rx_pkt,nhrp_fixedh->address_family_no);
		goto error;
	}

	if( nhrp_fixedh->version != RHP_PROTO_NHRP_VERSION ){
		err = RHP_STATUS_NHRP_NOT_SUPPORTED_ATTR;
	  RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_FIXED_HEADER_UNSUP_VER,"xb",rx_pkt,nhrp_fixedh->version);
		goto error;
	}

	if( nhrp_fixedh->protocol_type != RHP_PROTO_ETH_IP &&
			nhrp_fixedh->protocol_type != RHP_PROTO_ETH_IPV6 ){
		err = RHP_STATUS_NHRP_NOT_SUPPORTED_ATTR;
	  RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_FIXED_HEADER_UNSUP_PROTO_TYPE,"xW",rx_pkt,nhrp_fixedh->protocol_type);
		goto error;
	}

	if( nhrp_fixedh->packet_type != RHP_PROTO_NHRP_PKT_RESOLUTION_REQ &&
			nhrp_fixedh->packet_type != RHP_PROTO_NHRP_PKT_RESOLUTION_REP &&
			nhrp_fixedh->packet_type != RHP_PROTO_NHRP_PKT_REGISTRATION_REQ &&
			nhrp_fixedh->packet_type != RHP_PROTO_NHRP_PKT_REGISTRATION_REP &&
			nhrp_fixedh->packet_type != RHP_PROTO_NHRP_PKT_PURGE_REQ &&
			nhrp_fixedh->packet_type != RHP_PROTO_NHRP_PKT_PURGE_REP &&
			nhrp_fixedh->packet_type != RHP_PROTO_NHRP_PKT_ERROR_INDICATION &&
			nhrp_fixedh->packet_type != RHP_PROTO_NHRP_PKT_TRAFFIC_INDICATION ){
		err = RHP_STATUS_NHRP_NOT_SUPPORTED_ATTR;
	  RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_FIXED_HEADER_UNSUP_PACKET_TYPE,"xb",rx_pkt,nhrp_fixedh->packet_type);
		goto error;
	}

	if( nhrp_fixedh->src_nbma_addr_type_flag ){
		err = RHP_STATUS_NHRP_NOT_SUPPORTED_ATTR;
	  RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_FIXED_HEADER_UNSUP_SRC_NBMA_ADDR_TYPE_FLAG,"xb",rx_pkt,nhrp_fixedh->src_nbma_addr_type_flag);
		goto error;
	}

	if( nhrp_fixedh->src_nbma_addr_type_len &&
			nhrp_fixedh->src_nbma_addr_type_len != RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN &&
			nhrp_fixedh->src_nbma_addr_type_len != RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN ){
		err = RHP_STATUS_NHRP_NOT_SUPPORTED_ATTR;
	  RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_FIXED_HEADER_UNSUP_SRC_NBMA_ADDR_TYPE,"xb",rx_pkt,nhrp_fixedh->src_nbma_addr_type_len);
		goto error;
	}

	{
		u16 csum_o = nhrp_fixedh->check_sum;
		u16 csum = _rhp_proto_nhrp_set_csum(nhrph);

		if( csum_o != csum ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
		  RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_FIXED_HEADER_CSUM_ERR,"xWW",rx_pkt,csum_o,csum);
			goto error;
		}
	}


	nhrp_mesg = rhp_nhrp_mesg_alloc(nhrp_fixedh->address_family_no,nhrp_fixedh->packet_type);
	if( nhrp_mesg == NULL ){
		RHP_BUG("");
		goto error;
	}

	nhrp_mesg->rx_hop_count = nhrp_fixedh->hop_count;

	nhrp_mesg->nhrph = nhrph;
	nhrp_mesg->rx_pkt_ref = rhp_pkt_hold_ref(rx_pkt);

	*nhrp_mesg_r = nhrp_mesg;

  RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_FIXED_HEADER_RTRN,"xxxbxx",rx_pkt,nhrp_mesg,*nhrp_mesg_r,nhrp_mesg->rx_hop_count,nhrp_mesg->nhrph,nhrp_mesg->rx_pkt_ref);
	return 0;

error:
	if( nhrp_mesg ){
		rhp_nhrp_mesg_unhold(nhrp_mesg);
	}
  RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_FIXED_HEADER_ERR,"xE",rx_pkt,err);
	return err;
}

static int _rhp_nhrp_mesg_rx_parse_cie(rhp_packet* rx_pkt,
		rhp_proto_nhrp_fixed* nhrp_fixedh,rhp_nhrp_mesg* nhrp_mesg,
		rhp_proto_nhrp_clt_info_entry* nhrp_cieh,rhp_nhrp_cie* nhrp_cie,u8* endp)
{
	int err = -EINVAL;
	u8* addr_p;
	int addr_family, addr_len;
	int cie_len = sizeof(rhp_proto_nhrp_clt_info_entry);

  RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_CIE,"xxxxxx",rx_pkt,nhrp_fixedh,nhrp_mesg,nhrp_cieh,nhrp_cie,endp);

	if( nhrp_cieh->clt_nbma_addr_type_len ){

		if( nhrp_fixedh->address_family_no == RHP_PROTO_NHRP_ADDR_FAMILY_IPV4 ){

			if( nhrp_cieh->clt_nbma_addr_type_len != RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN ){

				err = RHP_STATUS_NHRP_NOT_SUPPORTED_ATTR;
			  RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_CIE_UNSUP_CLT_ADDR_V4,"xxWb",rx_pkt,nhrp_mesg,nhrp_fixedh->address_family_no,nhrp_cieh->clt_nbma_addr_type_len);
				goto error;
			}

			addr_family = AF_INET;
			addr_len = 4;

		}else if( nhrp_fixedh->address_family_no == RHP_PROTO_NHRP_ADDR_FAMILY_IPV6 ){

			if( nhrp_cieh->clt_nbma_addr_type_len != RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN ){

				err = RHP_STATUS_NHRP_NOT_SUPPORTED_ATTR;
			  RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_CIE_UNSUP_CLT_ADDR_V6,"xxWb",rx_pkt,nhrp_mesg,nhrp_fixedh->address_family_no,nhrp_cieh->clt_nbma_addr_type_len);
				goto error;
			}

			addr_family = AF_INET6;
			addr_len = 16;

		}else{

			err = RHP_STATUS_NHRP_NOT_SUPPORTED_ATTR;
		  RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_CIE_UNSUP_CLT_ADDR,"xxWb",rx_pkt,nhrp_mesg,nhrp_fixedh->address_family_no,nhrp_cieh->clt_nbma_addr_type_len);
			goto error;
		}

		if( ((u8*)nhrp_cieh) + cie_len + addr_len > endp ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
		  RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_CIE_INVALID_PKT_1,"xxddx",rx_pkt,nhrp_mesg,nhrp_cieh,cie_len,addr_len,endp);
			goto error;
		}

		addr_p = (u8*)_rhp_pkt_pull(rx_pkt,addr_len);
		if( addr_p == NULL ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_CIE_INVALID_PKT_2,"xd",rx_pkt,addr_len);
			goto error;
		}

		err = nhrp_cie->set_clt_nbma_addr(nhrp_cie,addr_family,addr_p);
		if( err ){
			goto error;
		}

		cie_len += addr_len;
	}

	if( nhrp_cieh->clt_nbma_saddr_type_len ){

		if( nhrp_fixedh->address_family_no == RHP_PROTO_NHRP_ADDR_FAMILY_IPV4 &&
				nhrp_cieh->clt_nbma_saddr_type_len == RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN ){

			addr_family = AF_INET;
			addr_len = 4;

		}else if( nhrp_fixedh->address_family_no == RHP_PROTO_NHRP_ADDR_FAMILY_IPV6 &&
							nhrp_cieh->clt_nbma_saddr_type_len == RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN ){

			addr_family = AF_INET6;
			addr_len = 16;

		}else{
			err = RHP_STATUS_NHRP_NOT_SUPPORTED_ATTR;
		  RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_CIE_UNSUP_CLT_SADDR,"xxWb",rx_pkt,nhrp_mesg,nhrp_fixedh->address_family_no,nhrp_cieh->clt_nbma_saddr_type_len);
			goto error;
		}

		// Not Used.

		if( ((u8*)nhrp_cieh) + cie_len + addr_len > endp ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
		  RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_CIE_INVALID_PKT_3,"xxddx",rx_pkt,nhrp_mesg,nhrp_cieh,cie_len,addr_len,endp);
			goto error;
		}

		addr_p = (u8*)_rhp_pkt_pull(rx_pkt,addr_len);
		if( addr_p == NULL ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
		  RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_CIE_INVALID_PKT_4,"xd",rx_pkt,addr_len);
			goto error;
		}

		cie_len += addr_len;
	}


	if( nhrp_cieh->clt_protocol_addr_len ){

		if( nhrp_fixedh->protocol_type == RHP_PROTO_ETH_IP &&
				nhrp_cieh->clt_protocol_addr_len == RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN ){

			addr_family = AF_INET;
			addr_len = 4;

		}else if( nhrp_fixedh->protocol_type == RHP_PROTO_ETH_IPV6 &&
							nhrp_cieh->clt_protocol_addr_len == RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN ){

			addr_family = AF_INET6;
			addr_len = 16;

		}else{
			err = RHP_STATUS_NHRP_NOT_SUPPORTED_ATTR;
		  RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_CIE_UNSUP_CLT_PROTOCOL_ADDR,"xxWb",rx_pkt,nhrp_mesg,nhrp_fixedh->protocol_type,nhrp_cieh->clt_protocol_addr_len);
			goto error;
		}

		if( ((u8*)nhrp_cieh) + cie_len + addr_len > endp ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
		  RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_CIE_INVALID_PKT_5,"xxddx",rx_pkt,nhrp_mesg,nhrp_cieh,cie_len,addr_len,endp);
			goto error;
		}

		addr_p = (u8*)_rhp_pkt_pull(rx_pkt,addr_len);
		if( addr_p == NULL ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
		  RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_CIE_INVALID_PKT_6,"xd",rx_pkt,addr_len);
			goto error;
		}

		err = nhrp_cie->set_clt_protocol_addr(nhrp_cie,addr_family,addr_p);
		if( err ){
			goto error;
		}

		cie_len += addr_len;
	}

	err = nhrp_cie->set_prefix_len(nhrp_cie,nhrp_cieh->prefix_len);
	if( err ){
		goto error;
	}

	err = nhrp_cie->set_hold_time(nhrp_cie,ntohs(nhrp_cieh->hold_time));
	if( err ){
		goto error;
	}

	err = nhrp_cie->set_mtu(nhrp_cie,ntohs(nhrp_cieh->mtu));
	if( err ){
		goto error;
	}

	nhrp_cie->nhrp_cieh = nhrp_cieh;

  RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_CIE_RTRN,"xx",rx_pkt,nhrp_cie->nhrp_cieh);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_CIE_ERR,"xE",rx_pkt,err);
	return err;
}

static int _rhp_nhrp_mesg_rx_parse_m_cies(rhp_packet* rx_pkt,
		rhp_proto_nhrp_fixed* nhrp_fixedh,rhp_nhrp_mesg* nhrp_mesg,u8* endp)
{
	int err = -EINVAL;
	u8* cur = rx_pkt->data;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_CIES,"xxxxx",rx_pkt,nhrp_fixedh,nhrp_mesg,endp,cur);

	while( cur < endp ){

		rhp_proto_nhrp_clt_info_entry* nhrp_cieh;
		rhp_nhrp_cie* nhrp_cie;

		if( cur + sizeof(rhp_proto_nhrp_clt_info_entry) > endp ){
			break;
		}

		nhrp_cieh = (rhp_proto_nhrp_clt_info_entry*)cur;

		nhrp_cie = rhp_nhrp_cie_alloc(nhrp_cieh->code);
		if( nhrp_cie == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		if( nhrp_fixedh->packet_type == RHP_PROTO_NHRP_PKT_RESOLUTION_REQ ||
				nhrp_fixedh->packet_type == RHP_PROTO_NHRP_PKT_RESOLUTION_REP ||
				nhrp_fixedh->packet_type == RHP_PROTO_NHRP_PKT_REGISTRATION_REQ ||
				nhrp_fixedh->packet_type == RHP_PROTO_NHRP_PKT_REGISTRATION_REP ||
				nhrp_fixedh->packet_type == RHP_PROTO_NHRP_PKT_PURGE_REQ 			||
				nhrp_fixedh->packet_type == RHP_PROTO_NHRP_PKT_PURGE_REP ){

			err = nhrp_mesg->m.mandatory->add_cie(nhrp_mesg,nhrp_cie);
			if( err ){
				rhp_nhrp_cie_free(nhrp_cie);
				goto error;
			}
/*
		}else if( nhrp_fixedh->packet_type == RHP_PROTO_NHRP_PKT_ERROR_INDICATION ){
			// TODO: Not Implemented yet.
		}else if( nhrp_fixedh->packet_type == RHP_PROTO_NHRP_PKT_TRAFFIC_INDICATION ){
			// TODO: Not Implemented yet.
*/
		}else{
			err = RHP_STATUS_NHRP_NOT_SUPPORTED_ATTR;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_CIES_UNSUP_PKT_TYPE,"xxxb",rx_pkt,nhrp_fixedh,nhrp_mesg,nhrp_fixedh->packet_type);
			goto error;
		}


		if( _rhp_pkt_pull(rx_pkt,sizeof(rhp_proto_nhrp_clt_info_entry)) == NULL ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_CIES_INVALID_LEN,"xxxb",rx_pkt,nhrp_fixedh,nhrp_mesg,nhrp_fixedh->packet_type);
			goto error;
		}


		err = _rhp_nhrp_mesg_rx_parse_cie(rx_pkt,nhrp_fixedh,nhrp_mesg,nhrp_cieh,nhrp_cie,endp);
		if( err ){
			goto error;
		}

		cur = rx_pkt->data;
	}

	if( endp != rx_pkt->data ){
		RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_CIES_INVALID_LEN_2,"xxxbxx",rx_pkt,nhrp_fixedh,nhrp_mesg,nhrp_fixedh->packet_type,endp,rx_pkt->data);
		err = RHP_STATUS_NHRP_INVALID_PKT;
		goto error;
	}

	RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_CIES_RTRN,"xx",rx_pkt,nhrp_mesg);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_CIES_ERR,"xxE",rx_pkt,nhrp_mesg,err);
	return err;
}


static int _rhp_nhrp_mesg_rx_parse_m_header_mandatory(rhp_packet* rx_pkt,
		rhp_nhrp_mesg* nhrp_mesg,rhp_proto_nhrp_fixed* nhrp_fixedh,rhp_proto_nhrp_mandatory* mandatory)
{
	int err = -EINVAL;
	u8* addr_p;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_MANDATORY,"xxxx",rx_pkt,nhrp_mesg,nhrp_fixedh,mandatory);


	nhrp_mesg->m.mandatory->request_id = ntohl(mandatory->request_id);
	nhrp_mesg->m.mandatory->flags = mandatory->flags;

	if( nhrp_fixedh->address_family_no == RHP_PROTO_NHRP_ADDR_FAMILY_IPV4 ){

		if( nhrp_fixedh->src_nbma_addr_type_len == RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN ){

			addr_p = (u8*)_rhp_pkt_pull(rx_pkt,4);
			if( addr_p == NULL ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_MANDATORY_INVALID_LEN_2,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
				goto error;
			}

			err = nhrp_mesg->m.mandatory->set_src_nbma_addr(nhrp_mesg,AF_INET,addr_p);
			if( err ){
				goto error;
			}

		}else if( nhrp_fixedh->src_nbma_addr_type_len ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_MANDATORY_INVALID_LEN_3,"xxxb",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_fixedh->src_nbma_addr_type_len);
			goto error;
		}

		if( nhrp_fixedh->src_nbma_saddr_type_len == RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN ){

			// Not used.

			addr_p = (u8*)_rhp_pkt_pull(rx_pkt,4);
			if( addr_p == NULL ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_MANDATORY_INVALID_LEN_4,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
				goto error;
			}

		}else if( nhrp_fixedh->src_nbma_saddr_type_len ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_MANDATORY_INVALID_LEN_5,"xxxb",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_fixedh->src_nbma_saddr_type_len);
			goto error;
		}

	}else if( nhrp_fixedh->address_family_no == RHP_PROTO_NHRP_ADDR_FAMILY_IPV6 ){

		if( nhrp_fixedh->src_nbma_addr_type_len == RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN ){

			addr_p = (u8*)_rhp_pkt_pull(rx_pkt,16);
			if( addr_p == NULL ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_MANDATORY_INVALID_LEN_6,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
				goto error;
			}

			err = nhrp_mesg->m.mandatory->set_src_nbma_addr(nhrp_mesg,AF_INET6,addr_p);
			if( err ){
				goto error;
			}

		}else if( nhrp_fixedh->src_nbma_addr_type_len ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_MANDATORY_INVALID_LEN_7,"xxxb",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_fixedh->src_nbma_addr_type_len);
			goto error;
		}

		if( nhrp_fixedh->src_nbma_saddr_type_len == RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN ){

			// Not used.

			addr_p = (u8*)_rhp_pkt_pull(rx_pkt,16);
			if( addr_p == NULL ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_MANDATORY_INVALID_LEN_8,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
				goto error;
			}

		}else if( nhrp_fixedh->src_nbma_saddr_type_len ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_MANDATORY_INVALID_LEN_9,"xxxb",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_fixedh->src_nbma_saddr_type_len);
			goto error;
		}

	}else{
		err = RHP_STATUS_NHRP_NOT_SUPPORTED_ATTR;
		RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_MANDATORY_UNSUP_ADDR_FAMILY,"xxxW",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_fixedh->address_family_no);
		goto error;
	}


	if( nhrp_fixedh->protocol_type == RHP_PROTO_ETH_IP ){

		if( mandatory->src_protocol_len == RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN ){

			addr_p = (u8*)_rhp_pkt_pull(rx_pkt,4);
			if( addr_p == NULL ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_MANDATORY_INVALID_LEN_10,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
				goto error;
			}

			err = nhrp_mesg->m.mandatory->set_src_protocol_addr(nhrp_mesg,AF_INET,addr_p);
			if( err ){
				goto error;
			}

		}else if( mandatory->src_protocol_len ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_MANDATORY_INVALID_LEN_11,"xxxb",rx_pkt,nhrp_mesg,nhrp_fixedh,mandatory->src_protocol_len);
			goto error;
		}

		if( mandatory->dst_protocol_len == RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN ){

			addr_p = (u8*)_rhp_pkt_pull(rx_pkt,4);
			if( addr_p == NULL ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_MANDATORY_INVALID_LEN_12,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
				goto error;
			}

			err = nhrp_mesg->m.mandatory->set_dst_protocol_addr(nhrp_mesg,AF_INET,addr_p);
			if( err ){
				goto error;
			}

		}else if( mandatory->dst_protocol_len ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_MANDATORY_INVALID_LEN_13,"xxxb",rx_pkt,nhrp_mesg,nhrp_fixedh,mandatory->dst_protocol_len);
			goto error;
		}

	}else if( nhrp_fixedh->protocol_type == RHP_PROTO_ETH_IPV6 ){

		if( mandatory->src_protocol_len == RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN ){

			addr_p = (u8*)_rhp_pkt_pull(rx_pkt,16);
			if( addr_p == NULL ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_MANDATORY_INVALID_LEN_14,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
				goto error;
			}

			err = nhrp_mesg->m.mandatory->set_src_protocol_addr(nhrp_mesg,AF_INET6,addr_p);
			if( err ){
				goto error;
			}

		}else if( mandatory->src_protocol_len ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_MANDATORY_INVALID_LEN_15,"xxxb",rx_pkt,nhrp_mesg,nhrp_fixedh,mandatory->src_protocol_len);
			goto error;
		}

		if( mandatory->dst_protocol_len == RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN ){

			addr_p = (u8*)_rhp_pkt_pull(rx_pkt,16);
			if( addr_p == NULL ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_MANDATORY_INVALID_LEN_16,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
				goto error;
			}

			err = nhrp_mesg->m.mandatory->set_dst_protocol_addr(nhrp_mesg,AF_INET6,addr_p);
			if( err ){
				goto error;
			}

		}else if( mandatory->dst_protocol_len ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_MANDATORY_INVALID_LEN_17,"xxxb",rx_pkt,nhrp_mesg,nhrp_fixedh,mandatory->dst_protocol_len);
			goto error;
		}

	}else{
		err = RHP_STATUS_NHRP_NOT_SUPPORTED_ATTR;
		RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_MANDATORY_UNSUP_PROTO_TYPE,"xxxW",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_fixedh->protocol_type);
		goto error;
	}


	{
		int ext_offset = (int)ntohs(nhrp_fixedh->extension_offset);
		u8* endp = ((u8*)nhrp_fixedh) + (ext_offset ? ext_offset : ntohs(nhrp_fixedh->len));

		err = _rhp_nhrp_mesg_rx_parse_m_cies(rx_pkt,nhrp_fixedh,nhrp_mesg,endp);
		if( err ){
			goto error;
		}
	}

	nhrp_mesg->m.mandatory->nhrp_mandatoryh = mandatory;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_MANDATORY_RTRN,"xx",rx_pkt,nhrp_mesg);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_MANDATORY_ERR,"xxE",rx_pkt,nhrp_mesg,err);
	return err;
}

static int _rhp_nhrp_mesg_rx_parse_m_header_error(rhp_packet* rx_pkt,
		rhp_nhrp_mesg* nhrp_mesg,rhp_proto_nhrp_fixed* nhrp_fixedh,rhp_proto_nhrp_error* nhrp_errorh)
{
	int err = -EINVAL;
	int nhrp_errorh_len = sizeof(rhp_proto_nhrp_error);
	u8* addr_p;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_ERROR,"xxxx",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_errorh);

	nhrp_mesg->m.error->error_code = ntohs(nhrp_errorh->error_code);

	if( nhrp_fixedh->address_family_no == RHP_PROTO_NHRP_ADDR_FAMILY_IPV4 ){

		if( nhrp_fixedh->src_nbma_addr_type_len == RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN ){

			addr_p = (u8*)_rhp_pkt_pull(rx_pkt,4);
			if( addr_p == NULL ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_ERROR_INVALID_LEN_2,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
				goto error;
			}

			err = nhrp_mesg->m.error->set_src_nbma_addr(nhrp_mesg,AF_INET,addr_p);
			if( err ){
				goto error;
			}

			nhrp_errorh_len += 4;

		}else if( nhrp_fixedh->src_nbma_addr_type_len ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_ERROR_INVALID_LEN_3,"xxxb",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_fixedh->src_nbma_addr_type_len);
			goto error;
		}

		if( nhrp_fixedh->src_nbma_saddr_type_len == RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN ){

			// Not used.

			addr_p = (u8*)_rhp_pkt_pull(rx_pkt,4);
			if( addr_p == NULL ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_ERROR_INVALID_LEN_4,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
				goto error;
			}

			nhrp_errorh_len += 4;

		}else if( nhrp_fixedh->src_nbma_saddr_type_len ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_ERROR_INVALID_LEN_5,"xxxb",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_fixedh->src_nbma_addr_type_len);
			goto error;
		}

	}else if( nhrp_fixedh->address_family_no == RHP_PROTO_NHRP_ADDR_FAMILY_IPV6 ){

		if( nhrp_fixedh->src_nbma_addr_type_len == RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN ){

			addr_p = (u8*)_rhp_pkt_pull(rx_pkt,16);
			if( addr_p == NULL ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_ERROR_INVALID_LEN_6,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
				goto error;
			}

			err = nhrp_mesg->m.error->set_src_nbma_addr(nhrp_mesg,AF_INET6,addr_p);
			if( err ){
				goto error;
			}

			nhrp_errorh_len += 16;


		}else if( nhrp_fixedh->src_nbma_addr_type_len ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_ERROR_INVALID_LEN_7,"xxxb",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_fixedh->src_nbma_addr_type_len);
			goto error;
		}

		if( nhrp_fixedh->src_nbma_saddr_type_len == RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN ){

			// Not used.

			addr_p = (u8*)_rhp_pkt_pull(rx_pkt,16);
			if( addr_p == NULL ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_ERROR_INVALID_LEN_8,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
				goto error;
			}

			nhrp_errorh_len += 16;

		}else if( nhrp_fixedh->src_nbma_saddr_type_len ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_ERROR_INVALID_LEN_9,"xxxb",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_fixedh->src_nbma_saddr_type_len);
			goto error;
		}

	}else{
		err = RHP_STATUS_NHRP_NOT_SUPPORTED_ATTR;
		RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_ERROR_UNSUP_ADDR_FAMILY,"xxxW",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_fixedh->address_family_no);
		goto error;
	}


	if( nhrp_fixedh->protocol_type == RHP_PROTO_ETH_IP ){

		if( nhrp_errorh->src_protocol_len == RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN ){

			addr_p = (u8*)_rhp_pkt_pull(rx_pkt,4);
			if( addr_p == NULL ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_ERROR_INVALID_LEN_10,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
				goto error;
			}

			err = nhrp_mesg->m.error->set_src_protocol_addr(nhrp_mesg,AF_INET,addr_p);
			if( err ){
				goto error;
			}

			nhrp_errorh_len += 4;

		}else if( nhrp_errorh->src_protocol_len ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_ERROR_INVALID_LEN_11,"xxxb",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_errorh->src_protocol_len);
			goto error;
		}

		if( nhrp_errorh->dst_protocol_len == RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN ){

			addr_p = (u8*)_rhp_pkt_pull(rx_pkt,4);
			if( addr_p == NULL ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_ERROR_INVALID_LEN_12,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
				goto error;
			}

			err = nhrp_mesg->m.error->set_dst_protocol_addr(nhrp_mesg,AF_INET,addr_p);
			if( err ){
				goto error;
			}

			nhrp_errorh_len += 4;

		}else if( nhrp_errorh->dst_protocol_len ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_ERROR_INVALID_LEN_13,"xxxb",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_errorh->dst_protocol_len);
			goto error;
		}

	}else if( nhrp_fixedh->protocol_type == RHP_PROTO_ETH_IPV6 ){

		if( nhrp_errorh->src_protocol_len == RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN ){

			addr_p = (u8*)_rhp_pkt_pull(rx_pkt,16);
			if( addr_p == NULL ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_ERROR_INVALID_LEN_14,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
				goto error;
			}

			err = nhrp_mesg->m.error->set_src_protocol_addr(nhrp_mesg,AF_INET6,addr_p);
			if( err ){
				goto error;
			}

			nhrp_errorh_len += 16;

		}else if( nhrp_errorh->src_protocol_len ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_ERROR_INVALID_LEN_15,"xxxb",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_errorh->src_protocol_len);
			goto error;
		}

		if( nhrp_errorh->dst_protocol_len == RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN ){

			addr_p = (u8*)_rhp_pkt_pull(rx_pkt,16);
			if( addr_p == NULL ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_ERROR_INVALID_LEN_16,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
				goto error;
			}

			err = nhrp_mesg->m.error->set_dst_protocol_addr(nhrp_mesg,AF_INET6,addr_p);
			if( err ){
				goto error;
			}

			nhrp_errorh_len += 16;

		}else if( nhrp_errorh->dst_protocol_len ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_ERROR_INVALID_LEN_17,"xxxb",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_errorh->dst_protocol_len);
			goto error;
		}

	}else{
		err = RHP_STATUS_NHRP_NOT_SUPPORTED_ATTR;
		RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_ERROR_UNSUP_PROTO_TYPE,"xxxW",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_fixedh->protocol_type);
		goto error;
	}


	{
		u8* endp = ((u8*)nhrp_fixedh) + (int)ntohs(nhrp_fixedh->len);
		u8* error_cont_p = ((u8*)nhrp_errorh) + nhrp_errorh_len;
		int error_cont_len = endp - error_cont_p;

		if( error_cont_len > 0 ){

			err = nhrp_mesg->m.error->set_error_org_mesg(nhrp_mesg,error_cont_len,error_cont_p);
			if( err ){
				goto error;
			}
		}
	}

	nhrp_mesg->m.error->nhrp_errorh = nhrp_errorh;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_ERROR_RTRN,"xx",rx_pkt,nhrp_mesg);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_ERROR_ERR,"xxE",rx_pkt,nhrp_mesg,err);
	return err;
}

static int _rhp_nhrp_mesg_rx_parse_m_header_traffic(rhp_packet* rx_pkt,
		rhp_nhrp_mesg* nhrp_mesg,rhp_proto_nhrp_fixed* nhrp_fixedh,
		rhp_proto_nhrp_traffic_indication* nhrp_traffich)
{
	int err = -EINVAL;
	int nhrp_traffich_len = sizeof(rhp_proto_nhrp_traffic_indication);
	u8* addr_p;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC,"xxxx",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_traffich);

	nhrp_mesg->m.traffic->traffic_code = ntohs(nhrp_traffich->traffic_code);

	if( nhrp_fixedh->address_family_no == RHP_PROTO_NHRP_ADDR_FAMILY_IPV4 ){

		if( nhrp_fixedh->src_nbma_addr_type_len == RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN ){

			addr_p = (u8*)_rhp_pkt_pull(rx_pkt,4);
			if( addr_p == NULL ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_INVALID_LEN_2,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
				goto error;
			}

			err = nhrp_mesg->m.traffic->set_src_nbma_addr(nhrp_mesg,AF_INET,addr_p);
			if( err ){
				goto error;
			}

			nhrp_traffich_len += 4;

		}else if( nhrp_fixedh->src_nbma_addr_type_len ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_INVALID_LEN_3,"xxxb",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_fixedh->src_nbma_addr_type_len);
			goto error;
		}

		if( nhrp_fixedh->src_nbma_saddr_type_len == RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN ){

			// Not used.

			addr_p = (u8*)_rhp_pkt_pull(rx_pkt,4);
			if( addr_p == NULL ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_INVALID_LEN_4,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
				goto error;
			}

			nhrp_traffich_len += 4;

		}else if( nhrp_fixedh->src_nbma_saddr_type_len ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_INVALID_LEN_5,"xxxb",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_fixedh->src_nbma_addr_type_len);
			goto error;
		}

	}else if( nhrp_fixedh->address_family_no == RHP_PROTO_NHRP_ADDR_FAMILY_IPV6 ){

		if( nhrp_fixedh->src_nbma_addr_type_len == RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN ){

			addr_p = (u8*)_rhp_pkt_pull(rx_pkt,16);
			if( addr_p == NULL ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_INVALID_LEN_6,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
				goto error;
			}

			err = nhrp_mesg->m.traffic->set_src_nbma_addr(nhrp_mesg,AF_INET6,addr_p);
			if( err ){
				goto error;
			}

			nhrp_traffich_len += 16;


		}else if( nhrp_fixedh->src_nbma_addr_type_len ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_INVALID_LEN_7,"xxxb",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_fixedh->src_nbma_addr_type_len);
			goto error;
		}

		if( nhrp_fixedh->src_nbma_saddr_type_len == RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN ){

			// Not used.

			addr_p = (u8*)_rhp_pkt_pull(rx_pkt,16);
			if( addr_p == NULL ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_INVALID_LEN_8,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
				goto error;
			}

			nhrp_traffich_len += 16;

		}else if( nhrp_fixedh->src_nbma_saddr_type_len ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_INVALID_LEN_9,"xxxb",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_fixedh->src_nbma_saddr_type_len);
			goto error;
		}

	}else{
		err = RHP_STATUS_NHRP_NOT_SUPPORTED_ATTR;
		RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_UNSUP_ADDR_FAMILY,"xxxW",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_fixedh->address_family_no);
		goto error;
	}


	if( nhrp_fixedh->protocol_type == RHP_PROTO_ETH_IP ){

		if( nhrp_traffich->src_protocol_len == RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN ){

			addr_p = (u8*)_rhp_pkt_pull(rx_pkt,4);
			if( addr_p == NULL ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_INVALID_LEN_10,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
				goto error;
			}

			err = nhrp_mesg->m.traffic->set_src_protocol_addr(nhrp_mesg,AF_INET,addr_p);
			if( err ){
				goto error;
			}

			nhrp_traffich_len += 4;

		}else if( nhrp_traffich->src_protocol_len ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_INVALID_LEN_11,"xxxb",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_traffich->src_protocol_len);
			goto error;
		}

		if( nhrp_traffich->dst_protocol_len == RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN ){

			addr_p = (u8*)_rhp_pkt_pull(rx_pkt,4);
			if( addr_p == NULL ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_INVALID_LEN_12,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
				goto error;
			}

			err = nhrp_mesg->m.traffic->set_dst_protocol_addr(nhrp_mesg,AF_INET,addr_p);
			if( err ){
				goto error;
			}

			nhrp_traffich_len += 4;

		}else if( nhrp_traffich->dst_protocol_len ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_INVALID_LEN_13,"xxxb",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_traffich->src_protocol_len);
			goto error;
		}

	}else if( nhrp_fixedh->protocol_type == RHP_PROTO_ETH_IPV6 ){

		if( nhrp_traffich->src_protocol_len == RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN ){

			addr_p = (u8*)_rhp_pkt_pull(rx_pkt,16);
			if( addr_p == NULL ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_INVALID_LEN_14,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
				goto error;
			}

			err = nhrp_mesg->m.traffic->set_src_protocol_addr(nhrp_mesg,AF_INET6,addr_p);
			if( err ){
				goto error;
			}

			nhrp_traffich_len += 16;

		}else if( nhrp_traffich->src_protocol_len ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_INVALID_LEN_15,"xxxb",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_traffich->src_protocol_len);
			goto error;
		}

		if( nhrp_traffich->dst_protocol_len == RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN ){

			addr_p = (u8*)_rhp_pkt_pull(rx_pkt,16);
			if( addr_p == NULL ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_INVALID_LEN_16,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
				goto error;
			}

			err = nhrp_mesg->m.traffic->set_dst_protocol_addr(nhrp_mesg,AF_INET6,addr_p);
			if( err ){
				goto error;
			}

			nhrp_traffich_len += 16;

		}else if( nhrp_traffich->dst_protocol_len ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_INVALID_LEN_17,"xxxb",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_traffich->dst_protocol_len);
			goto error;
		}

	}else{
		err = RHP_STATUS_NHRP_NOT_SUPPORTED_ATTR;
		RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_UNSUP_PROTO_TYPE,"xxxW",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_fixedh->protocol_type);
		goto error;
	}

	{
		int ext_offset = ntohs(nhrp_fixedh->extension_offset);
		u8* endp, *traffic_cont_p = ((u8*)nhrp_traffich) + nhrp_traffich_len;
		int traffic_cont_len;

		if( ext_offset ){

			endp = ((u8*)nhrp_fixedh) + ext_offset;
			if( endp > ((u8*)nhrp_fixedh) + (int)ntohs(nhrp_fixedh->len) ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_ERROR_CONT_TOO_SHORT_1,"xxxxWd",rx_pkt,nhrp_mesg,endp,nhrp_fixedh,nhrp_fixedh->len,ext_offset);
				goto error;
			}

		}else{

			endp = ((u8*)nhrp_fixedh) + (int)ntohs(nhrp_fixedh->len);
		}

		traffic_cont_len = endp - traffic_cont_p;
		if( traffic_cont_len < 0 ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		if( traffic_cont_len > 0 ){

			u8 ver;
			rhp_ip_addr src_addr, dst_addr;

			memset(&src_addr,0,sizeof(rhp_ip_addr));
			memset(&dst_addr,0,sizeof(rhp_ip_addr));

			if( _rhp_pkt_pull(rx_pkt,traffic_cont_len) == NULL ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_ERROR_CONT_TOO_SHORT_2,"xxd",rx_pkt,nhrp_mesg,traffic_cont_len);
				goto error;
			}

			if( traffic_cont_len < (int)sizeof(rhp_proto_ip_v4) ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_ERROR_CONT_TOO_SHORT_3,"xxd",rx_pkt,nhrp_mesg,traffic_cont_len);
				goto error;
			}

			ver = ((rhp_proto_ip_v4*)traffic_cont_p)->ver;

			if( ver == 4 ){

				src_addr.addr_family = AF_INET;
				src_addr.addr.v4 = ((rhp_proto_ip_v4*)traffic_cont_p)->src_addr;

				dst_addr.addr_family = AF_INET;
				dst_addr.addr.v4 = ((rhp_proto_ip_v4*)traffic_cont_p)->dst_addr;

				if( src_addr.addr.v4 == dst_addr.addr.v4 ){
					err = RHP_STATUS_NHRP_INVALID_PKT;
					goto error;
				}

				if( src_addr.addr.v4 == 0xFFFFFFFF || dst_addr.addr.v4 == 0xFFFFFFFF ){
					err = RHP_STATUS_NHRP_INVALID_PKT;
					goto error;
				}

			}else if( ver == 6 ){

				if( traffic_cont_len < (int)sizeof(rhp_proto_ip_v6) ){
					err = RHP_STATUS_NHRP_INVALID_PKT;
					RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_ERROR_CONT_TOO_SHORT_V6,"xxd",rx_pkt,nhrp_mesg,traffic_cont_len);
					goto error;
				}

				src_addr.addr_family = AF_INET6;
				memcpy(src_addr.addr.v6,((rhp_proto_ip_v6*)traffic_cont_p)->src_addr,16);

				dst_addr.addr_family = AF_INET6;
				memcpy(dst_addr.addr.v6,((rhp_proto_ip_v6*)traffic_cont_p)->dst_addr,16);

				if( rhp_ipv6_is_same_addr(src_addr.addr.v6,dst_addr.addr.v6) ){
					err = RHP_STATUS_NHRP_INVALID_PKT;
					goto error;
				}

			}else{
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_ERROR_CONT_TOO_SHORT,"xxbd",rx_pkt,nhrp_mesg,((rhp_proto_ip_v4*)traffic_cont_p)->ver,traffic_cont_len);
				goto error;
			}

			if( rhp_ip_addr_null(&src_addr) || rhp_ip_addr_null(&dst_addr) ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				goto error;
			}

			if( rhp_ip_is_loopback(&src_addr) || rhp_ip_is_loopback(&dst_addr) ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				goto error;
			}

			if( rhp_ip_multicast(src_addr.addr_family,src_addr.addr.raw) ||
					rhp_ip_multicast(dst_addr.addr_family,dst_addr.addr.raw) ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				goto error;
			}

			err = nhrp_mesg->m.traffic->set_traffic_org_mesg(nhrp_mesg,traffic_cont_len,traffic_cont_p);
			if( err ){
				goto error;
			}

		}else{
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_NO_ERROR_CONT,"xx",rx_pkt,nhrp_mesg);
			goto error;
		}
	}

	nhrp_mesg->m.traffic->nhrp_traffich = nhrp_traffich;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_RTRN,"xx",rx_pkt,nhrp_mesg);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_M_HEADER_TRAFFIC_ERR,"xxE",rx_pkt,nhrp_mesg,err);
	return err;
}

static int _rhp_nhrp_mesg_rx_parse_mandatory_header(rhp_packet* rx_pkt,
		rhp_nhrp_mesg* nhrp_mesg,rhp_proto_nhrp_fixed* nhrp_fixedh)
{
	int err = -EINVAL;
	union {
		u8* raw;
		rhp_proto_nhrp_mandatory* mandatory;
		rhp_proto_nhrp_error* error;
		rhp_proto_nhrp_traffic_indication* traffic;
	} nhrp_m_hdr;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_MANDATORY_HEADER,"xxpp",rx_pkt,nhrp_mesg,((((u8*)nhrp_fixedh) + sizeof(rhp_proto_nhrp_fixed)) <= rx_pkt->end ? sizeof(rhp_proto_nhrp_fixed) : 0),(u8*)nhrp_fixedh,((((u8*)(nhrp_fixedh + 1)) + sizeof(rhp_proto_nhrp_mandatory)) <= rx_pkt->end ? sizeof(rhp_proto_nhrp_mandatory) : 0),(u8*)(nhrp_fixedh + 1 ));

	//
	// rhp_proto_nhrp_mandatory, rhp_proto_nhrp_error and rhp_proto_nhrp_traffic_indication
	// are the same size.
	//
	nhrp_m_hdr.raw = (u8*)_rhp_pkt_pull(rx_pkt,sizeof(rhp_proto_nhrp_mandatory));
	if( nhrp_m_hdr.raw == NULL ){
		err = RHP_STATUS_NHRP_INVALID_PKT;
		RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_MANDATORY_HEADER_INVALID_LEN_1,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
		goto error;
	}


	if( nhrp_fixedh->packet_type == RHP_PROTO_NHRP_PKT_RESOLUTION_REQ 	||
			nhrp_fixedh->packet_type == RHP_PROTO_NHRP_PKT_RESOLUTION_REP 	||
			nhrp_fixedh->packet_type == RHP_PROTO_NHRP_PKT_REGISTRATION_REQ ||
			nhrp_fixedh->packet_type == RHP_PROTO_NHRP_PKT_REGISTRATION_REP ||
			nhrp_fixedh->packet_type == RHP_PROTO_NHRP_PKT_PURGE_REQ 				||
			nhrp_fixedh->packet_type == RHP_PROTO_NHRP_PKT_PURGE_REP ){

		err = _rhp_nhrp_mesg_rx_parse_m_header_mandatory(rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_m_hdr.mandatory);
		if( err ){
			goto error;
		}

	}else if( nhrp_fixedh->packet_type == RHP_PROTO_NHRP_PKT_ERROR_INDICATION ){

		err = _rhp_nhrp_mesg_rx_parse_m_header_error(rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_m_hdr.error);
		if( err ){
			goto error;
		}

	}else if( nhrp_fixedh->packet_type == RHP_PROTO_NHRP_PKT_TRAFFIC_INDICATION ){

		err = _rhp_nhrp_mesg_rx_parse_m_header_traffic(rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_m_hdr.traffic);
		if( err ){
			goto error;
		}

	}else{
		RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_MANDATORY_HEADER_UNSUP_PKT_TYPE,"xxxb",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_fixedh->packet_type);
		err = RHP_STATUS_NHRP_NOT_SUPPORTED_ATTR;
		goto error;
	}

	RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_MANDATORY_HEADER_RTRN,"xxx",rx_pkt,nhrp_mesg,nhrp_fixedh);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_MANDATORY_HEADER_ERR,"xxE",rx_pkt,nhrp_mesg,err);
	return err;
}


static int _rhp_nhrp_mesg_rx_parse_extension_cies(rhp_packet* rx_pkt,
		rhp_proto_nhrp_fixed* nhrp_fixedh,rhp_nhrp_mesg* nhrp_mesg,
		rhp_proto_nhrp_ext* nhrp_exth,rhp_nhrp_ext* nhrp_ext)
{
	int err = -EINVAL;
	u8* cur = rx_pkt->data;
	u8* endp = ((u8*)nhrp_exth) + sizeof(rhp_proto_nhrp_ext) + ntohs(nhrp_exth->len);

	RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_EXTENSION_CIES,"xxxxxxx",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_exth,nhrp_ext,cur,endp);

	while( cur < endp ){

		rhp_proto_nhrp_clt_info_entry* nhrp_cieh;
		rhp_nhrp_cie* nhrp_cie;

		if( cur + (int)sizeof(rhp_proto_nhrp_clt_info_entry) > endp ){
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_EXTENSION_CIES_INVALID_LEN_1,"xxxxxxx",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_exth,nhrp_ext,cur,endp);
			break;
		}

		nhrp_cieh = (rhp_proto_nhrp_clt_info_entry*)cur;

		nhrp_cie = rhp_nhrp_cie_alloc(nhrp_cieh->code);
		if( nhrp_cie == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}


		err = nhrp_ext->add_cie(nhrp_ext,nhrp_cie);
		if( err ){
			goto error;
		}


		if( _rhp_pkt_pull(rx_pkt,sizeof(rhp_proto_nhrp_clt_info_entry)) == NULL ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_EXTENSION_CIES_INVALID_LEN_2,"xxxxxxx",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_exth,nhrp_ext,cur,endp);
			goto error;
		}


		err = _rhp_nhrp_mesg_rx_parse_cie(rx_pkt,nhrp_fixedh,nhrp_mesg,nhrp_cieh,nhrp_cie,endp);
		if( err ){
			goto error;
		}


		cur = rx_pkt->data;
	}

	if( endp != rx_pkt->data ){
		err = RHP_STATUS_NHRP_INVALID_PKT;
		RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_EXTENSION_CIES_INVALID_LEN_3,"xxxxxxxx",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_exth,nhrp_ext,cur,endp,rx_pkt->data);
		goto error;
	}

	RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_EXTENSION_CIES_RTRN,"xx",rx_pkt,nhrp_mesg);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_EXTENSION_CIES_ERR,"xxE",rx_pkt,nhrp_mesg,err);
	return err;
}

static int _rhp_nhrp_mesg_rx_parse_extensions(rhp_packet* rx_pkt,
		rhp_nhrp_mesg* nhrp_mesg,rhp_proto_nhrp_fixed* nhrp_fixedh)
{
	int err = -EINVAL;
	u8 *cur, *endp;
	int nhrp_len = ntohs(nhrp_fixedh->len);

	endp = ((u8*)nhrp_fixedh) + nhrp_len;
	cur = rx_pkt->data;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_EXTENSIONS,"xxxdxxW",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_len,endp,cur,nhrp_fixedh->extension_offset);

	while( cur < endp ){

		rhp_proto_nhrp_ext* nhrp_exth;
		rhp_nhrp_ext* nhrp_ext;
		int ext_len = 0;

		if( cur + (int)sizeof(rhp_proto_nhrp_ext) > endp ){
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_EXTENSIONS_INVALID_LEN_1,"xxxdxx",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_len,endp,cur);
			break;
		}

		if( _rhp_pkt_pull(rx_pkt,sizeof(rhp_proto_nhrp_ext)) == NULL ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_EXTENSIONS_INVALID_LEN_2,"xxxdxx",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_len,endp,cur);
			goto error;
		}

		nhrp_exth = (rhp_proto_nhrp_ext*)cur;
		ext_len = ntohs(nhrp_exth->len);

		nhrp_ext = rhp_nhrp_ext_alloc(ntohs(RHP_PROTO_NHRP_EXT_TYPE(nhrp_exth->type)),0);
		if( nhrp_ext == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		err = nhrp_mesg->add_extension(nhrp_mesg,nhrp_ext);
		if( err ){
			goto error;
		}


		nhrp_ext->compulsory_flag = RHP_PROTO_NHRP_EXT_FLAG_IS_COMPULSORY(nhrp_ext->type);


		if( nhrp_ext->type == RHP_PROTO_NHRP_EXT_TYPE_END ){

			if( ext_len ){
				err = RHP_STATUS_NHRP_INVALID_PKT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_EXTENSIONS_INVALID_LEN_4,"xxxdxxd",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_len,endp,cur,ext_len);
				goto error;
			}

			break;

		}else if( nhrp_ext->type == RHP_PROTO_NHRP_EXT_TYPE_RESPONDER_ADDRESS ||
							nhrp_ext->type == RHP_PROTO_NHRP_EXT_TYPE_FORWARD_TRANSIT_NHS_RECORD ||
							nhrp_ext->type == RHP_PROTO_NHRP_EXT_TYPE_REVERSE_TRANSIT_NHS_RECORD ||
							nhrp_ext->type == RHP_PROTO_NHRP_EXT_TYPE_NAT_ADDRESS ){

			if( cur + (int)sizeof(rhp_proto_nhrp_ext) + ext_len > endp ){
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_EXTENSIONS_INVALID_LEN_5,"xxxdxxd",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_len,endp,cur,ext_len);
				break;
			}

			if( ext_len ){

				err = _rhp_nhrp_mesg_rx_parse_extension_cies(rx_pkt,nhrp_fixedh,nhrp_mesg,
								nhrp_exth,nhrp_ext);
				if( err ){
					goto error;
				}
			}

		}else if( nhrp_ext->type == RHP_PROTO_NHRP_EXT_TYPE_AUTHENTICATION ){

			if( cur + (int)sizeof(rhp_proto_nhrp_ext) + ext_len > endp ){
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_EXTENSIONS_INVALID_LEN_10,"xxxdxxd",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_len,endp,cur,ext_len);
				break;
			}

			if( ext_len ){

				if( _rhp_pkt_pull(rx_pkt,ext_len) == NULL ){
					err = RHP_STATUS_NHRP_INVALID_PKT;
					RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_EXTENSIONS_INVALID_LEN_10_2,"xxxdxxd",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_len,endp,cur,ext_len);
					goto error;
				}

				if( ext_len > (int)sizeof(rhp_proto_nhrp_ext_auth) ){

					nhrp_ext->ext_auth_key_len = ext_len - (int)sizeof(rhp_proto_nhrp_ext_auth);
					nhrp_ext->ext_auth_key = (u8*)_rhp_malloc(nhrp_ext->ext_auth_key_len);
					if( nhrp_ext->ext_auth_key == NULL ){
						RHP_BUG("");
						err = -ENOMEM;
						goto error;
					}

					memcpy(nhrp_ext->ext_auth_key,
							((u8*)nhrp_exth) + (int)(sizeof(rhp_proto_nhrp_ext) + sizeof(rhp_proto_nhrp_ext_auth)),
							nhrp_ext->ext_auth_key_len);
				}
			}

			RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_EXTENSIONS_AUTHENTICATION,"xxpp",rx_pkt,nhrp_mesg,ext_len + (int)sizeof(rhp_proto_nhrp_ext),nhrp_exth,nhrp_ext->ext_auth_key_len,nhrp_ext->ext_auth_key);

		}else{

			if( cur + (int)sizeof(rhp_proto_nhrp_ext) + ext_len > endp ){
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_EXTENSIONS_INVALID_LEN_7,"xxxdxxd",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_len,endp,cur,ext_len);
				break;
			}

			if( ext_len ){

				if( _rhp_pkt_pull(rx_pkt,ext_len) == NULL ){
					err = RHP_STATUS_NHRP_INVALID_PKT;
					RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_EXTENSIONS_INVALID_LEN_8,"xxxdxxd",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_len,endp,cur,ext_len);
					goto error;
				}
			}

			if( nhrp_ext->compulsory_flag ){
				err = RHP_STATUS_NHRP_UNSUP_COMPULSORY_EXT;
				RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_EXTENSIONS_UNSUP_EXT_TYPE,"xxxdxxdd",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_len,endp,cur,ext_len,nhrp_ext->type);
				goto error;
			}
		}

		nhrp_ext->nhrp_exth = nhrp_exth;

		cur = rx_pkt->data;
	}

	if( endp != rx_pkt->data ){
		err = RHP_STATUS_NHRP_INVALID_PKT;
		RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_EXTENSIONS_INVALID_LEN_9,"xxxdxxx",rx_pkt,nhrp_mesg,nhrp_fixedh,nhrp_len,endp,cur,rx_pkt->data);
		goto error;
	}

	RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_EXTENSIONS_RTRN,"xx",rx_pkt,nhrp_mesg);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_MESG_RX_PARSE_EXTENSIONS_ERR,"xxE",rx_pkt,nhrp_mesg,err);
	return err;
}


int rhp_nhrp_mesg_new_rx(rhp_packet* rx_pkt,rhp_nhrp_mesg** nhrp_mesg_r)
{
	int err = -EINVAL;
	rhp_proto_nhrp* nhrph = rx_pkt->l4.nhrph;
	rhp_proto_nhrp_fixed* nhrp_fixedh;
	rhp_nhrp_mesg* nhrp_mesg = NULL;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_NEW_RX,"xxp",rx_pkt,nhrp_mesg_r,((((u8*)nhrph) + sizeof(rhp_proto_nhrp)) <= rx_pkt->end ? sizeof(rhp_proto_nhrp) : 0),(u8*)nhrph);

	if( rx_pkt->type != RHP_PKT_GRE_NHRP ){
		RHP_BUG("%d",rx_pkt->type);
		return -EINVAL;
	}

	if( nhrph == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}


	if( rx_pkt->data < rx_pkt->l4.raw ){

		if( _rhp_pkt_pull(rx_pkt,(rx_pkt->l4.raw - rx_pkt->data)) == NULL ){
			err = RHP_STATUS_NHRP_INVALID_PKT;
			RHP_TRC(0,RHPTRCID_NHRP_MESG_NEW_RX_INVALID_LEN_1,"xxxxx",rx_pkt,nhrp_mesg_r,nhrph,rx_pkt->l4.raw,rx_pkt->data);
			goto error;
		}
	}


	nhrp_fixedh = (rhp_proto_nhrp_fixed*)_rhp_pkt_pull(rx_pkt,sizeof(rhp_proto_nhrp_fixed));
	if( nhrp_fixedh == NULL ){
		err = RHP_STATUS_NHRP_INVALID_PKT;
		RHP_TRC(0,RHPTRCID_NHRP_MESG_NEW_RX_INVALID_LEN_2,"xxxxx",rx_pkt,nhrp_mesg_r,nhrph,rx_pkt->l4.raw,rx_pkt->data);
		goto error;
	}


	err = _rhp_nhrp_mesg_rx_parse_fixed_header(rx_pkt,nhrph,nhrp_fixedh,&nhrp_mesg);
	if( err ){
		goto error;
	}


	err = _rhp_nhrp_mesg_rx_parse_mandatory_header(rx_pkt,nhrp_mesg,nhrp_fixedh);
	if( err ){
		goto error;
	}


	if( nhrp_fixedh->extension_offset ){

		if( nhrp_fixedh->packet_type == RHP_PROTO_NHRP_PKT_RESOLUTION_REQ 	||
				nhrp_fixedh->packet_type == RHP_PROTO_NHRP_PKT_RESOLUTION_REP 	||
				nhrp_fixedh->packet_type == RHP_PROTO_NHRP_PKT_REGISTRATION_REQ ||
				nhrp_fixedh->packet_type == RHP_PROTO_NHRP_PKT_REGISTRATION_REP ||
				nhrp_fixedh->packet_type == RHP_PROTO_NHRP_PKT_PURGE_REQ 				||
				nhrp_fixedh->packet_type == RHP_PROTO_NHRP_PKT_PURGE_REP 				||
				nhrp_fixedh->packet_type == RHP_PROTO_NHRP_PKT_TRAFFIC_INDICATION ){

			err = _rhp_nhrp_mesg_rx_parse_extensions(rx_pkt,nhrp_mesg,nhrp_fixedh);
			if( err ){
				goto error;
			}
		}
	}

	*nhrp_mesg_r = nhrp_mesg;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_NEW_RX_RTRN,"xxxx",rx_pkt,nhrp_mesg_r,nhrph,*nhrp_mesg_r);
	return 0;

error:
	if( nhrp_mesg ){
		rhp_nhrp_mesg_unhold(nhrp_mesg);
	}
	RHP_TRC(0,RHPTRCID_NHRP_MESG_NEW_RX_ERR,"xxxE",rx_pkt,nhrp_mesg_r,nhrph,err);
	return err;
}

rhp_nhrp_mesg* rhp_nhrp_mesg_new_tx(u16 f_addr_family,u8 f_packet_type)
{
	rhp_nhrp_mesg* nhrp_mesg = NULL;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_NEW_TX,"Wb",f_addr_family,f_packet_type);

	nhrp_mesg = rhp_nhrp_mesg_alloc(f_addr_family,f_packet_type);
	if( nhrp_mesg == NULL ){
		RHP_BUG("");
		goto error;
	}

	RHP_TRC(0,RHPTRCID_NHRP_MESG_NEW_TX_RTRN,"Wbx",f_addr_family,f_packet_type,nhrp_mesg);
	return nhrp_mesg;

error:
	RHP_TRC(0,RHPTRCID_NHRP_MESG_NEW_TX_ERR,"Wb",f_addr_family,f_packet_type);
	return NULL;
}


static rhp_nhrp_cie* _rhp_nhrp_mesg_dup_cie(rhp_nhrp_cie* nhrp_cie)
{
	rhp_nhrp_cie* nhrp_cie_d;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_DUP_CIE,"x",nhrp_cie);

	nhrp_cie_d = rhp_nhrp_cie_alloc(nhrp_cie->get_code(nhrp_cie));
	if( nhrp_cie_d == NULL ){
		RHP_BUG("");
		goto error;
	}

	nhrp_cie_d->prefix_len = nhrp_cie->prefix_len;
	nhrp_cie_d->mtu = nhrp_cie->mtu;
	nhrp_cie_d->hold_time = nhrp_cie->hold_time;
	memcpy(&(nhrp_cie_d->clt_nbma_addr),&(nhrp_cie->clt_nbma_addr),sizeof(rhp_ip_addr));
	memcpy(&(nhrp_cie_d->clt_protocol_addr),&(nhrp_cie->clt_protocol_addr),sizeof(rhp_ip_addr));

	RHP_TRC(0,RHPTRCID_NHRP_MESG_DUP_CIE_RTRN,"xx",nhrp_cie,nhrp_cie_d);
	return nhrp_cie_d;

error:
	if( nhrp_cie_d ){
		rhp_nhrp_cie_free(nhrp_cie_d);
	}
	RHP_TRC(0,RHPTRCID_NHRP_MESG_DUP_CIE_ERR,"x",nhrp_cie);
	return NULL;
}

static rhp_nhrp_ext* _rhp_nhrp_mesg_dup_ext(rhp_nhrp_ext* nhrp_ext)
{
	int err = -EINVAL;
	rhp_nhrp_ext* nhrp_ext_d
		= rhp_nhrp_ext_alloc(nhrp_ext->get_type(nhrp_ext),nhrp_ext->is_compulsory(nhrp_ext));
	rhp_nhrp_cie* nhrp_cie = nhrp_ext->cie_list_head;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_DUP_EXT,"xx",nhrp_ext,nhrp_ext->cie_list_head);

	nhrp_ext_d->compulsory_flag = nhrp_ext->compulsory_flag;

	while( nhrp_cie ){

		rhp_nhrp_cie* nhrp_cie_d = _rhp_nhrp_mesg_dup_cie(nhrp_cie);

		if( nhrp_cie_d == NULL ){
			RHP_BUG("");
			goto error;
		}

		err = nhrp_ext_d->add_cie(nhrp_ext_d,nhrp_cie_d);
		if( err ){
			rhp_nhrp_cie_free(nhrp_cie_d);
			goto error;
		}

		nhrp_cie = nhrp_cie->next;
	}


	if( nhrp_ext->ext_auth_key ){

		nhrp_ext_d->ext_auth_key = (u8*)_rhp_malloc(nhrp_ext->ext_auth_key_len);
		if( nhrp_ext_d->ext_auth_key == NULL ){
			RHP_BUG("");
			goto error;
		}

		memcpy(nhrp_ext_d->ext_auth_key,nhrp_ext->ext_auth_key,nhrp_ext->ext_auth_key_len);

		nhrp_ext_d->ext_auth_key_len = nhrp_ext->ext_auth_key_len;
	}


	RHP_TRC(0,RHPTRCID_NHRP_MESG_DUP_EXT_RTRN,"xx",nhrp_ext,nhrp_ext_d);
	return nhrp_ext_d;

error:
	if( nhrp_ext_d ){
		rhp_nhrp_ext_free(nhrp_ext_d);
	}
	RHP_TRC(0,RHPTRCID_NHRP_MESG_DUP_EXT_ERR,"x",nhrp_ext);
	return NULL;
}

static int _rhp_nhrp_mesg_dup_m_mandatory(rhp_nhrp_mesg* nhrp_mesg_d,
		rhp_nhrp_m_mandatory* nhrp_m_mandatory)
{
	int err = -EINVAL;
	rhp_nhrp_cie* nhrp_cie = nhrp_m_mandatory->cie_list_head;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_DUP_M_MANDATORY,"xxx",nhrp_mesg_d,nhrp_m_mandatory,nhrp_m_mandatory->cie_list_head);

	if( nhrp_mesg_d->m.mandatory == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	nhrp_mesg_d->m.mandatory->request_id = nhrp_m_mandatory->request_id;
	nhrp_mesg_d->m.mandatory->flags = nhrp_m_mandatory->flags;

	memcpy(&(nhrp_mesg_d->m.mandatory->src_nbma_addr),&(nhrp_m_mandatory->src_nbma_addr),sizeof(rhp_ip_addr));
	memcpy(&(nhrp_mesg_d->m.mandatory->src_protocol_addr),&(nhrp_m_mandatory->src_protocol_addr),sizeof(rhp_ip_addr));
	memcpy(&(nhrp_mesg_d->m.mandatory->dst_protocol_addr),&(nhrp_m_mandatory->dst_protocol_addr),sizeof(rhp_ip_addr));

	while( nhrp_cie ){

		rhp_nhrp_cie* nhrp_cie_d = _rhp_nhrp_mesg_dup_cie(nhrp_cie);

		if( nhrp_cie_d == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		err = nhrp_mesg_d->m.mandatory->add_cie(nhrp_mesg_d,nhrp_cie_d);
		if( err ){
			rhp_nhrp_cie_free(nhrp_cie_d);
			goto error;
		}

		nhrp_cie = nhrp_cie->next;
	}

	RHP_TRC(0,RHPTRCID_NHRP_MESG_DUP_M_MANDATORY_RTRN,"xxxx",nhrp_mesg_d,nhrp_m_mandatory,nhrp_mesg_d->m.mandatory,nhrp_mesg_d->m.mandatory->cie_list_head);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_MESG_DUP_M_MANDATORY_ERR,"xxx",nhrp_mesg_d,nhrp_mesg_d->m.mandatory,nhrp_m_mandatory);
	return err;
}

static int _rhp_nhrp_mesg_dup_m_error_indication(
		rhp_nhrp_mesg* nhrp_mesg_d,rhp_nhrp_m_error_indication* nhrp_m_error)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_DUP_M_ERROR_INDICATION,"xx",nhrp_mesg_d,nhrp_m_error);

	if( nhrp_mesg_d->m.error == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	nhrp_mesg_d->m.error->error_code = nhrp_m_error->error_code;

	if( nhrp_m_error->error_org_mesg_len ){

		err = nhrp_mesg_d->m.error->set_error_org_mesg(nhrp_mesg_d,
					nhrp_m_error->error_org_mesg_len,nhrp_mesg_d->m.error->error_org_mesg);
		if( err ){
			goto error;
		}
	}

	memcpy(&(nhrp_mesg_d->m.error->src_nbma_addr),&(nhrp_m_error->src_nbma_addr),sizeof(rhp_ip_addr));
	memcpy(&(nhrp_mesg_d->m.error->src_protocol_addr),&(nhrp_m_error->src_protocol_addr),sizeof(rhp_ip_addr));
	memcpy(&(nhrp_mesg_d->m.error->dst_protocol_addr),&(nhrp_m_error->dst_protocol_addr),sizeof(rhp_ip_addr));

	RHP_TRC(0,RHPTRCID_NHRP_MESG_DUP_M_ERROR_INDICATION_RTRN,"xxx",nhrp_mesg_d,nhrp_m_error,nhrp_mesg_d->m.error);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_MESG_DUP_M_ERROR_INDICATION_ERR,"xxx",nhrp_mesg_d,nhrp_mesg_d->m.error,nhrp_m_error);
	return err;
}

static int _rhp_nhrp_mesg_dup_m_traffic_indication(
		rhp_nhrp_mesg* nhrp_mesg_d,rhp_nhrp_m_traffic_indication* nhrp_m_traffic)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_NHRP_MESG_DUP_M_TRAFFIC_INDICATION,"xx",nhrp_mesg_d,nhrp_m_traffic);

	if( nhrp_mesg_d->m.traffic == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	nhrp_mesg_d->m.traffic->traffic_code = nhrp_m_traffic->traffic_code;

	if( nhrp_m_traffic->traffic_org_mesg_len ){

		err = nhrp_mesg_d->m.traffic->set_traffic_org_mesg(nhrp_mesg_d,
					nhrp_m_traffic->traffic_org_mesg_len,nhrp_mesg_d->m.traffic->traffic_org_mesg);
		if( err ){
			goto error;
		}
	}

	memcpy(&(nhrp_mesg_d->m.traffic->src_nbma_addr),&(nhrp_m_traffic->src_nbma_addr),sizeof(rhp_ip_addr));
	memcpy(&(nhrp_mesg_d->m.traffic->src_protocol_addr),&(nhrp_m_traffic->src_protocol_addr),sizeof(rhp_ip_addr));
	memcpy(&(nhrp_mesg_d->m.traffic->dst_protocol_addr),&(nhrp_m_traffic->dst_protocol_addr),sizeof(rhp_ip_addr));

	RHP_TRC(0,RHPTRCID_NHRP_MESG_DUP_M_TRAFFIC_INDICATION_RTRN,"xxx",nhrp_mesg_d,nhrp_m_traffic,nhrp_mesg_d->m.traffic);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_NHRP_MESG_DUP_M_TRAFFIC_INDICATION_ERR,"xxx",nhrp_mesg_d,nhrp_mesg_d->m.traffic,nhrp_m_traffic);
	return err;
}

rhp_nhrp_mesg* rhp_nhrp_mesg_dup(rhp_nhrp_mesg* nhrp_mesg)
{
	int err = -EINVAL;
	rhp_nhrp_ext* nhrp_ext = nhrp_mesg->ext_list_head;
	rhp_nhrp_mesg* nhrp_mesg_d
		= rhp_nhrp_mesg_alloc(nhrp_mesg->get_addr_family(nhrp_mesg),nhrp_mesg->get_packet_type(nhrp_mesg));

	RHP_TRC(0,RHPTRCID_NHRP_MESG_DUP,"xxxx",nhrp_mesg,nhrp_mesg->m.raw,nhrp_mesg->ext_list_head,nhrp_mesg_d);

	if( nhrp_mesg_d == NULL ){
		RHP_BUG("");
		goto error;
	}

	nhrp_mesg_d->f_hop_count = nhrp_mesg->f_hop_count;
	nhrp_mesg_d->exec_dec_hop_count = nhrp_mesg->exec_dec_hop_count;
	nhrp_mesg_d->rx_hop_count = nhrp_mesg->rx_hop_count;


	nhrp_mesg->get_rx_nbma_src_addr(nhrp_mesg,&(nhrp_mesg_d->rx_nbma_src_addr));
	nhrp_mesg->get_rx_nbma_dst_addr(nhrp_mesg,&(nhrp_mesg_d->rx_nbma_dst_addr));


	if( nhrp_mesg->m.raw ){

		switch( nhrp_mesg_d->f_packet_type ){

		case RHP_PROTO_NHRP_PKT_RESOLUTION_REQ:
		case RHP_PROTO_NHRP_PKT_RESOLUTION_REP:
		case RHP_PROTO_NHRP_PKT_REGISTRATION_REQ:
		case RHP_PROTO_NHRP_PKT_REGISTRATION_REP:
		case RHP_PROTO_NHRP_PKT_PURGE_REQ:
		case RHP_PROTO_NHRP_PKT_PURGE_REP:

			err = _rhp_nhrp_mesg_dup_m_mandatory(nhrp_mesg_d,nhrp_mesg->m.mandatory);
			break;

		case RHP_PROTO_NHRP_PKT_ERROR_INDICATION:

			err	= _rhp_nhrp_mesg_dup_m_error_indication(nhrp_mesg_d,nhrp_mesg->m.error);
			break;

		case RHP_PROTO_NHRP_PKT_TRAFFIC_INDICATION:

			err = _rhp_nhrp_mesg_dup_m_traffic_indication(nhrp_mesg_d,nhrp_mesg->m.traffic);
			break;

		default:
			RHP_BUG("%d",nhrp_mesg_d->f_packet_type);
			goto error;
		}

		if( err ){
			RHP_BUG("%d",err);
			rhp_nhrp_mesg_unhold(nhrp_mesg_d);
			return NULL;
		}
	}

	while( nhrp_ext ){

		rhp_nhrp_ext* nhrp_ext_d;

		if( nhrp_ext->type == RHP_PROTO_NHRP_EXT_TYPE_END ){
			RHP_TRC(0,RHPTRCID_NHRP_MESG_DUP_EXT_TYPE_END_IGNORED,"xx",nhrp_mesg,nhrp_ext);
			goto next;
		}

		nhrp_ext_d = _rhp_nhrp_mesg_dup_ext(nhrp_ext);
		if( nhrp_ext_d == NULL ){
			RHP_BUG("");
			goto error;
		}

		err = nhrp_mesg_d->add_extension(nhrp_mesg_d,nhrp_ext_d);
		if( err ){
			goto error;
		}

next:
		nhrp_ext = nhrp_ext->next;
	}

	RHP_TRC(0,RHPTRCID_NHRP_MESG_DUP_RTRN,"xxxx",nhrp_mesg,nhrp_mesg_d,nhrp_mesg_d->m.raw,nhrp_mesg_d->ext_list_head);
	return nhrp_mesg_d;


error:
	if( nhrp_mesg_d ){
		rhp_nhrp_mesg_unhold(nhrp_mesg_d);
	}
	RHP_TRC(0,RHPTRCID_NHRP_MESG_DUP_ERR,"x",nhrp_mesg);
	return NULL;
}

