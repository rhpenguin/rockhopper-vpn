/*

	Copyright (C) 2009-2014 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.

	You can redistribute and/or modify this software under the
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


// sudo su
// echo "1" > /sys/devices/virtual/net/br0/bridge/multicast_snooping (0 or 1)
// echo "1" > /sys/devices/virtual/net/br0/bridge/multicast_querier (0 or 1)
// echo "30" > /sys/devices/virtual/net/br0/bridge/multicast_querier_interval (secs)

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
#include "rhp_tuntap.h"
#include "rhp_esp.h"
#include "rhp_ipv6.h"


struct _rhp_v6_rlm_lladdr_ctx {

	u8 tag[4]; // '#6LA'

	unsigned long rlm_id;

	rhp_timer retx_timer;

	rhp_packet_ref* dad_probe_pkt_ref;
	rhp_packet_ref* dad_mld2_pkt_ref;

  int retries;
};
typedef struct _rhp_v6_rlm_lladdr_ctx	rhp_v6_rlm_lladdr_ctx;


static int _rhp_ipv6_gen_dmy_lladdr(u8* v6_lladdr_r)
{
	int retries = 0;
	u8 v6_lladdr[16];

	RHP_TRC(0,RHPTRCID_IPV6_GEN_DMY_LLADDR,"6",v6_lladdr_r);

	v6_lladdr[0] = 0xFE;
	v6_lladdr[1] = 0x80;
	v6_lladdr[2] = 0;
	v6_lladdr[3] = 0;
	v6_lladdr[4] = 0;
	v6_lladdr[5] = 0;
	v6_lladdr[6] = 0;
	v6_lladdr[7] = 0;

retry:
	if( retries >= 1000 ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( rhp_random_bytes((v6_lladdr + 8),8) ){
		retries++;
		goto retry;
	}

	if( *((u64*)(v6_lladdr + 8)) == 0 ){
		retries++;
		goto retry;
	}

	memcpy(v6_lladdr_r,v6_lladdr,16);

	RHP_TRC(0,RHPTRCID_IPV6_GEN_DMY_LLADDR_RTRN,"6",v6_lladdr_r);
	return 0;
}

int rhp_ipv6_icmp6_parse_rx_pkt(rhp_packet* pkt,
		rhp_proto_ether** eth_r,
		rhp_proto_ip_v6** ip6h_r,
		rhp_proto_icmp6** icmp6h_r)
{
	rhp_proto_ether* eth = pkt->l2.eth;
	rhp_proto_ip_v6* ip6h;
	rhp_proto_icmp6* icmp6h;
	u8 proto = RHP_PROTO_IP_IPV6_ICMP;
	int pld_len = 0;

	RHP_TRC_FREQ(0,RHPTRCID_IPV6_ICMP6_PARSE_RX_PKT,"xxxx",pkt,eth_r,ip6h_r,icmp6h_r);
	rhp_pkt_trace_dump("_rhp_ipv6_icmp6_parse_rx_pkt",pkt);

	if( pkt->tail == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( eth == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}


	if( RHP_PROTO_ETHER_MULTICAST_SRC(pkt->l2.eth) ){  // Including Broadcast address
		RHP_TRC(0,RHPTRCID_IPV6_ICMP6_PARSE_RX_PKT_SRC_MAC_MULTICAST,"xM",pkt,eth->src_addr);
		return RHP_STATUS_IPV6_PKT_NOT_INTERESTED;
	}


	if( eth->protocol != RHP_PROTO_ETH_IPV6 ){
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_ICMP6_PARSE_RX_PKT_ETH_NOT_IPV6,"xW",pkt,eth->protocol);
		return RHP_STATUS_IPV6_PKT_NOT_INTERESTED;
	}


	ip6h = (rhp_proto_ip_v6*)(eth + 1);

	if( ((u8*)ip6h) + sizeof(rhp_proto_ip_v6) > pkt->tail ){
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_ICMP6_PARSE_RX_PKT_BAD_IPV6_LEN,"x",pkt);
		return -EINVAL;
	}

	if( ip6h->ver != 6 ){
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_ICMP6_PARSE_RX_PKT_NOT_IPV6,"xd",pkt,ip6h->ver);
		return RHP_STATUS_IPV6_PKT_NOT_INTERESTED;
	}

	if( rhp_ipv6_addr_null(ip6h->dst_addr) ||
			rhp_ip_multicast(AF_INET6,ip6h->src_addr) ){
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_ICMP6_PARSE_RX_PKT_BAD_IPV6_ADDR,"x66",pkt,ip6h->src_addr,ip6h->dst_addr);
		return -EINVAL;
	}


	pld_len = ntohs(ip6h->payload_len);
	if( pld_len < (int)sizeof(rhp_proto_icmp6) ||
			((u8*)(ip6h + 1)) + pld_len > pkt->tail ){
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_ICMP6_PARSE_RX_PKT_BAD_ICMP6_LEN,"xd",pkt,pld_len);
		return -EINVAL;
	}

	icmp6h = (rhp_proto_icmp6*)rhp_proto_ip_v6_upper_layer(ip6h,pkt->end,1,&proto,NULL);
	if( icmp6h == NULL || ((u8*)(icmp6h + 1)) > pkt->tail ){
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_ICMP6_PARSE_RX_PKT_NO_ICMP6_DATA,"x",pkt);
		return -EINVAL;
	}

	pld_len -= ((u8*)icmp6h) - ((u8*)(ip6h + 1));
	if( pld_len <= 0 ){
		return -EINVAL;
	}

	{
		u16 csum = icmp6h->check_sum, csum2;

		if( (csum2 = _rhp_proto_icmpv6_set_csum(ip6h->src_addr,ip6h->dst_addr,
					icmp6h,pld_len)) != csum ){

			icmp6h->check_sum = csum;

			RHP_TRC_FREQ(0,RHPTRCID_IPV6_ICMP6_PARSE_RX_PKT_BAD_ICMP6_CHECKSUM,"xww",pkt,csum,csum2);
			return -EINVAL;
		}
	}

	*eth_r = eth;
	*ip6h_r = ip6h;
	*icmp6h_r = icmp6h;

	RHP_TRC_FREQ(0,RHPTRCID_IPV6_ICMP6_PARSE_RX_PKT_RTRN,"xppp",pkt,sizeof(rhp_proto_ether),*eth_r,sizeof(rhp_proto_ip_v6),*ip6h_r,sizeof(rhp_proto_icmp6),*icmp6h_r);
	return 0;
}

int rhp_ipv6_nd_parse_adv_pkt(rhp_packet* pkt,
		rhp_proto_ether* eth,
		rhp_proto_ip_v6* ip6h,
		rhp_proto_icmp6* icmp6h,
		u8** target_addr_r /*Just reference. Don't free it!*/,
		u8** target_mac_r /*Just reference. Don't free it!*/ )
{
	int pld_len;
	rhp_proto_icmp6_nd_adv* nd_advh = (rhp_proto_icmp6_nd_adv*)icmp6h;

	RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_ADV,"xpppxx",pkt,sizeof(rhp_proto_ether),eth,sizeof(rhp_proto_ip_v6),ip6h,sizeof(rhp_proto_icmp6),icmp6h,target_addr_r,target_mac_r);
	rhp_pkt_trace_dump("_rhp_ipv6_nd_parse_adv",pkt);

	pld_len = (int)ntohs(ip6h->payload_len);

	if( pld_len < (int)sizeof(rhp_proto_icmp6_nd_adv) ||
			((u8*)(ip6h + 1)) + pld_len > pkt->tail ||
			((u8*)nd_advh) + sizeof(rhp_proto_icmp6_nd_adv) > pkt->tail ){

		RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_ADV_BAD_IPV6_PLD_LEN,"xd",pkt,pld_len);
		return -EINVAL;
	}

	if( icmp6h->type != RHP_PROTO_ICMP6_TYPE_NEIGHBOR_ADV ||
			icmp6h->code != 0 ){
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_ADV_BAD_TYPE_OR_CODE,"xbb",pkt,icmp6h->type,icmp6h->code);
		return -EINVAL;
	}

	if( ip6h->hop_limit != 255 ){
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_ADV_BAD_HOP_LIMIT,"xb",pkt,ip6h->hop_limit);
		return -EINVAL;
	}


	if( rhp_ip_multicast(AF_INET6,nd_advh->target_addr) ||
			rhp_ipv6_addr_null(nd_advh->target_addr) ){
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_ADV_BAD_MC_TGT_ADDR,"x6",pkt,nd_advh->target_addr);
		return -EINVAL;
	}

	if( rhp_ip_multicast(AF_INET6,ip6h->dst_addr) && nd_advh->solicited ){
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_ADV_BAD_SOLICITED_FLAG,"x6d",pkt,ip6h->dst_addr,nd_advh->solicited);
		return -EINVAL;
	}

	if( target_addr_r ){

		*target_addr_r = nd_advh->target_addr;
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_ADV_OPT_TGT_ADDR,"x6",pkt,*target_addr_r);
	}

	if( pld_len > (int)sizeof(rhp_proto_icmp6_nd_adv) ){

		u8* opt = (u8*)(nd_advh + 1);
		pld_len -= (int)sizeof(rhp_proto_icmp6_nd_adv);

		while( pld_len > 0 && opt < pkt->tail ){

			if( opt + 2 >= pkt->tail ){
				RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_ADV_BAD_OPT_LEN,"x",pkt);
				return -EINVAL;
			}

			if( opt[1] == 0 ){ // opt[1]: Opt's Length
				RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_ADV_BAD_OPT_LEN_ZERO,"xbb",pkt,opt[0],opt[1]);
				return -EINVAL;
			}

			if( opt + opt[1] > pkt->tail ){
				RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_ADV_BAD_OPT_LEN2,"xbb",pkt,opt[0],opt[1]);
				return -EINVAL;
			}

			if( opt[0] == RHP_PROTO_ICMP6_ND_OPT_LINK_ADDR_TGT ){ // opt[0]: type

				if( opt[1] != 1 ){ // 1*8 bytes
					RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_ADV_BAD_OPT_LINK_ADDR_TGT_LEN,"xbb",pkt,opt[0],opt[1]);
					return -EINVAL;
				}

				if( _rhp_mac_addr_null(((rhp_proto_icmp6_nd_opt_link_addr*)opt)->mac) ){
					RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_ADV_BAD_OPT_LINK_ADDR_TGT_NULL_ADDR,"xbb",pkt,opt[0],opt[1]);
					return -EINVAL;
				}

				if( target_mac_r ){

					*target_mac_r = ((rhp_proto_icmp6_nd_opt_link_addr*)opt)->mac;
					RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_ADV_OPT_LINK_ADDR_TGT_MAC,"xM",pkt,*target_mac_r);
				}
			}

			pld_len -= opt[1]*8;
			opt += opt[1];
		}

		if( pld_len != 0 ){
			RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_ADV_BAD_PLD_LEN,"xd",pkt,pld_len);
			return -EINVAL;
		}
	}

	RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_ADV_RTRN,"x",pkt);
	return 0;
}

int rhp_ipv6_nd_parse_solicit_pkt(rhp_packet* pkt,
		rhp_proto_ether* eth,
		rhp_proto_ip_v6* ip6h,
		rhp_proto_icmp6* icmp6h,
		u8** target_addr_r /*Just reference. Don't free it!*/,
		u8** src_addr_r /*Just reference. Don't free it!*/,
		u8** src_mac_r /*Just reference. Don't free it!*/ )
{
	int pld_len;
	rhp_proto_icmp6_nd_solict* nd_solh = (rhp_proto_icmp6_nd_solict*)icmp6h;

	RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_SOLICITATION,"xpppxx",pkt,sizeof(rhp_proto_ether),eth,sizeof(rhp_proto_ip_v6),ip6h,sizeof(rhp_proto_icmp6),icmp6h,target_addr_r,src_mac_r);
	rhp_pkt_trace_dump("rhp_ipv6_nd_parse_solicit",pkt);

	pld_len = (int)ntohs(ip6h->payload_len);

	if( pld_len < (int)sizeof(rhp_proto_icmp6_nd_solict) ||
			((u8*)(ip6h + 1)) + pld_len > pkt->tail ||
			((u8*)nd_solh) + sizeof(rhp_proto_icmp6_nd_solict) > pkt->tail ){

		RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_SOLICITATION_BAD_IPV6_PLD_LEN,"xd",pkt,pld_len);
		return -EINVAL;
	}

	if( icmp6h->type != RHP_PROTO_ICMP6_TYPE_NEIGHBOR_SOLICIT || icmp6h->code != 0 ){
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_SOLICITATION_BAD_TYPE_OR_CODE,"xbb",pkt,icmp6h->type,icmp6h->code);
		return -EINVAL;
	}

	if( ip6h->hop_limit != 255 ){
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_SOLICITATION_BAD_HOP_LIMIT,"xb",pkt,ip6h->hop_limit);
		return -EINVAL;
	}


	if( rhp_ip_multicast(AF_INET6,nd_solh->target_addr) ||
			rhp_ipv6_addr_null(nd_solh->target_addr) ){
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_SOLICITATION_BAD_MC_TGT_ADDR,"x6",pkt,nd_solh->target_addr);
		return -EINVAL;
	}

	if( rhp_ipv6_addr_null(ip6h->src_addr) ){

		if( !rhp_ipv6_is_solicited_node_multicast(ip6h->dst_addr) ){
			RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_SOLICITATION_BAD_SOL_NODE_DST_ADDR,"x6",pkt,ip6h->dst_addr);
			return -EINVAL;
		}
	}


	if( target_addr_r ){

		*target_addr_r = nd_solh->target_addr;
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_SOLICITATION_OPT_LINK_ADDR_TGT_ADDR,"x6",pkt,*target_addr_r);
	}

	if( src_addr_r ){

		*src_addr_r = ip6h->src_addr;
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_SOLICITATION_SRC_IPV6_ADDR,"x6",pkt,*src_addr_r);
	}

	if( pld_len > (int)sizeof(rhp_proto_icmp6_nd_solict) ){

		u8* opt = (u8*)(nd_solh + 1);
		pld_len -= (int)sizeof(rhp_proto_icmp6_nd_solict);

		while( pld_len > 0 && opt < pkt->tail ){

			if( opt + 2 >= pkt->tail ){
				RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_SOLICITATION_BAD_OPT_LEN,"x",pkt);
				return -EINVAL;
			}

			if( opt[1] == 0 ){ // opt[1]: Opt's Length
				RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_SOLICITATION_BAD_OPT_LEN_ZERO,"xbb",pkt,opt[0],opt[1]);
				return -EINVAL;
			}

			if( opt + opt[1] > pkt->tail ){
				RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_SOLICITATION_BAD_OPT_LEN2,"xbb",pkt,opt[0],opt[1]);
				return -EINVAL;
			}

			if( opt[0] == RHP_PROTO_ICMP6_ND_OPT_LINK_ADDR_SRC ){ // opt[0]: type

				if( rhp_ipv6_addr_null(ip6h->src_addr) ){
					RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_SOLICITATION_BAD_OPT_LINK_ADDR_SRC_FOR_UNSPEC_SRC_ADDR,"xbb",pkt,opt[0],opt[1]);
					return -EINVAL;
				}

				if( opt[1] != 1 ){ // 1*8 bytes
					RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_SOLICITATION_BAD_OPT_LINK_ADDR_SRC_LEN,"xbb",pkt,opt[0],opt[1]);
					return -EINVAL;
				}

				if( _rhp_mac_addr_null(((rhp_proto_icmp6_nd_opt_link_addr*)opt)->mac) ){
					RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_SOLICITATION_BAD_OPT_LINK_ADDR_SRC_NULL_ADDR,"xbb",pkt,opt[0],opt[1]);
					return -EINVAL;
				}

				if( src_mac_r ){

					*src_mac_r = ((rhp_proto_icmp6_nd_opt_link_addr*)opt)->mac;
					RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_SOLICITATION_OPT_LINK_ADDR_SRC_MAC,"xM",pkt,*src_mac_r);
				}
			}

			pld_len -= opt[1]*8;
			opt += opt[1];
		}

		if( pld_len != 0 ){
			RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_SOLICITATION_BAD_PLD_LEN,"xd",pkt,pld_len);
			return -EINVAL;
		}
	}

	RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_PARSE_SOLICITATION_RTRN,"x",pkt);
	return 0;
}

rhp_packet* rhp_ipv6_nd_new_solicitation_pkt(u8* sender_mac,u8* target_ipv6,
		u8* src_ipv6,int target_lladdr)
{
	rhp_packet* pkt = NULL;
	rhp_proto_ether* eth;
	rhp_proto_ip_v6 *ip6h;
	rhp_proto_icmp6_nd_solict *ndh;
	rhp_proto_icmp6_nd_opt_link_addr* nd_opt_lladdr = NULL;
	int pld_len
	= sizeof(rhp_proto_icmp6_nd_solict)
  	+ (target_lladdr ? sizeof(rhp_proto_icmp6_nd_opt_link_addr) : 0);

	RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_NEW_SOLICITATION,"M66d",sender_mac,target_ipv6,src_ipv6,target_lladdr);

	if( _rhp_mac_addr_null(sender_mac) ){
		RHP_BUG("");
		return NULL;
	}

	if( rhp_ipv6_addr_null(target_ipv6) ){
		RHP_BUG("");
		return NULL;
	}

	pkt = rhp_pkt_alloc( sizeof(rhp_proto_ether)
											+ sizeof(rhp_proto_ip_v6)
											+ sizeof(rhp_proto_icmp6_nd_solict)
											+ (target_lladdr ? sizeof(rhp_proto_icmp6_nd_opt_link_addr) : 0));
	if( pkt == NULL ){
		RHP_BUG("");
		return NULL;
	}

	pkt->type = RHP_PKT_PLAIN_ETHER_TAP;

	eth = (rhp_proto_ether*)_rhp_pkt_push(pkt,(int)sizeof(rhp_proto_ether));
	ip6h = (rhp_proto_ip_v6*)_rhp_pkt_push(pkt,(int)sizeof(rhp_proto_ip_v6));
	ndh = (rhp_proto_icmp6_nd_solict*)_rhp_pkt_push(pkt,(int)sizeof(rhp_proto_icmp6_nd_solict));
	if( target_lladdr ){
		nd_opt_lladdr
		= (rhp_proto_icmp6_nd_opt_link_addr*)_rhp_pkt_push(pkt,(int)sizeof(rhp_proto_icmp6_nd_opt_link_addr));
	}

	pkt->l2.eth = eth;
	pkt->l3.raw = (u8*)ip6h;
	pkt->l4.raw = (u8*)ndh;


	rhp_ipv6_gen_solicited_node_multicast(target_ipv6,ip6h->dst_addr);


	rhp_ip_gen_multicast_mac(AF_INET6,ip6h->dst_addr,eth->dst_addr);


	memcpy(eth->src_addr,sender_mac,6);
	eth->protocol = RHP_PROTO_ETH_IPV6;

	ip6h->ver = 6;
	ip6h->priority = 0;
	ip6h->flow_label[0] = 0;
	ip6h->flow_label[1] = 0;
	ip6h->flow_label[2] = 0;
	ip6h->next_header = RHP_PROTO_IP_IPV6_ICMP;
	ip6h->hop_limit = 255;
	ip6h->payload_len = htons((u16)pld_len);

	if( src_ipv6 == NULL ){
		memset(ip6h->src_addr,0,16);
	}else{
		memcpy(ip6h->src_addr,src_ipv6,16);
	}

	ndh->type = RHP_PROTO_ICMP6_TYPE_NEIGHBOR_SOLICIT;
	ndh->code = 0;
	ndh->check_sum = 0;
	ndh->reserved = 0;
	memcpy(ndh->target_addr,target_ipv6,16);

	if( target_lladdr ){
		nd_opt_lladdr->type = RHP_PROTO_ICMP6_ND_OPT_LINK_ADDR_SRC;
		nd_opt_lladdr->len = 1;
		memcpy(nd_opt_lladdr->mac,sender_mac,6);
	}

	_rhp_proto_icmpv6_set_csum(ip6h->src_addr,ip6h->dst_addr,
			(rhp_proto_icmp6*)ndh,pld_len);

	rhp_pkt_trace_dump("rhp_ipv6_nd_new_solicitation",pkt);

	RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_NEW_SOLICITATION_RTRN,"x",pkt);
	return pkt;
}

rhp_packet* rhp_ipv6_nd_new_adv_pkt(u8* sender_mac,u8* target_ipv6,
		u8* src_mac,u8* dst_mac,u8* src_ipv6,u8* dst_ipv6,int solicited)
{
	rhp_packet* pkt = NULL;
	rhp_proto_ether* eth;
	rhp_proto_ip_v6 *ip6h;
	rhp_proto_icmp6_nd_adv *ndh;
	rhp_proto_icmp6_nd_opt_link_addr* nd_opt_lladdr = NULL;
	int pld_len
	= sizeof(rhp_proto_icmp6_nd_adv) + sizeof(rhp_proto_icmp6_nd_opt_link_addr);

	RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_NEW_ADV,"M6M66d",sender_mac,target_ipv6,dst_mac,src_ipv6,dst_ipv6,solicited);

	if( _rhp_mac_addr_null(sender_mac) ){
		RHP_BUG("");
		return NULL;
	}

	if( rhp_ipv6_addr_null(target_ipv6) ){
		RHP_BUG("");
		return NULL;
	}

	pkt = rhp_pkt_alloc( sizeof(rhp_proto_ether)
											+ sizeof(rhp_proto_ip_v6)
											+ sizeof(rhp_proto_icmp6_nd_adv)
											+ sizeof(rhp_proto_icmp6_nd_opt_link_addr));
	if( pkt == NULL ){
		RHP_BUG("");
		return NULL;
	}

	pkt->type = RHP_PKT_PLAIN_ETHER_TAP;

	eth = (rhp_proto_ether*)_rhp_pkt_push(pkt,(int)sizeof(rhp_proto_ether));
	ip6h = (rhp_proto_ip_v6*)_rhp_pkt_push(pkt,(int)sizeof(rhp_proto_ip_v6));
	ndh = (rhp_proto_icmp6_nd_adv*)_rhp_pkt_push(pkt,(int)sizeof(rhp_proto_icmp6_nd_adv));
	nd_opt_lladdr
	= (rhp_proto_icmp6_nd_opt_link_addr*)_rhp_pkt_push(pkt,(int)sizeof(rhp_proto_icmp6_nd_opt_link_addr));

	pkt->l2.eth = eth;
	pkt->l3.raw = (u8*)ip6h;
	pkt->l4.raw = (u8*)ndh;

	if( src_mac ){
		memcpy(eth->src_addr,src_mac,6);
	}else{
		memcpy(eth->src_addr,sender_mac,6);
	}
	eth->protocol = RHP_PROTO_ETH_IPV6;

	if( dst_ipv6 == NULL || rhp_ipv6_addr_null(dst_ipv6) ){
		dst_ipv6 = rhp_ipv6_all_node_multicast_addr->addr.v6;
		rhp_ip_gen_multicast_mac(AF_INET6,dst_ipv6,eth->dst_addr);
	}else if( dst_mac ){
		memcpy(eth->dst_addr,dst_mac,6);
	}

	ip6h->ver = 6;
	ip6h->priority = 0;
	ip6h->flow_label[0] = 0;
	ip6h->flow_label[1] = 0;
	ip6h->flow_label[2] = 0;
	ip6h->next_header = RHP_PROTO_IP_IPV6_ICMP;
	ip6h->hop_limit = 255;
	ip6h->payload_len = htons((u16)pld_len);

	memcpy(ip6h->src_addr,src_ipv6,16);
	memcpy(ip6h->dst_addr,dst_ipv6,16);


	ndh->type = RHP_PROTO_ICMP6_TYPE_NEIGHBOR_ADV;
	ndh->code = 0;
	ndh->check_sum = 0;
	ndh->override = 1;
	ndh->solicited = solicited;
	ndh->router = 0;
	ndh->reserved = 0;
	memcpy(ndh->target_addr,target_ipv6,16);


	nd_opt_lladdr->type = RHP_PROTO_ICMP6_ND_OPT_LINK_ADDR_TGT;
	nd_opt_lladdr->len = 1;
	memcpy(nd_opt_lladdr->mac,sender_mac,6);


	_rhp_proto_icmpv6_set_csum(ip6h->src_addr,ip6h->dst_addr,
			(rhp_proto_icmp6*)ndh,pld_len);

	rhp_pkt_trace_dump("rhp_ipv6_nd_new_adv",pkt);

	RHP_TRC_FREQ(0,RHPTRCID_IPV6_ND_NEW_ADV_RTRN,"x",pkt);
	return pkt;
}

static rhp_packet* _rhp_ipv6_dad_new_solicitation(u8* sender_mac,u8* target_ipv6)
{
	return rhp_ipv6_nd_new_solicitation_pkt(sender_mac,target_ipv6,NULL,0);
}

rhp_packet* rhp_ipv6_new_mld2_report(u8* sender_mac,
		u8* src_ipv6,u8* mc_addr_ipv6)
{
	rhp_packet* pkt = NULL;
	rhp_proto_ether* eth;
	rhp_proto_ip_v6 *ip6h;
	rhp_proto_ip_v6_exthdr *h_b_hh; // 8bytes
	rhp_proto_icmp6_mld2_report *mld2h;
	rhp_proto_icmp6_mld2_mc_addr_rec* mld2_rech;
	int pld_len = 8 // Hop-By-Hop opt
								+ sizeof(rhp_proto_icmp6_mld2_report)
								+ sizeof(rhp_proto_icmp6_mld2_mc_addr_rec);

	RHP_TRC_FREQ(0,RHPTRCID_IPV6_NEW_MLD2_REPORT,"M66",sender_mac,src_ipv6,mc_addr_ipv6);

	if( _rhp_mac_addr_null(sender_mac) ){
		RHP_BUG("");
		return NULL;
	}

	if( src_ipv6 && rhp_ipv6_addr_null(src_ipv6) ){
		RHP_BUG("");
		return NULL;
	}

	if( rhp_ipv6_addr_null(mc_addr_ipv6) ){
		RHP_BUG("");
		return NULL;
	}

	pkt = rhp_pkt_alloc( sizeof(rhp_proto_ether)
											+ sizeof(rhp_proto_ip_v6) + 8
											+ sizeof(rhp_proto_icmp6_mld2_report)
											+ sizeof(rhp_proto_icmp6_mld2_mc_addr_rec));
	if( pkt == NULL ){
		RHP_BUG("");
		return NULL;
	}

	pkt->type = RHP_PKT_PLAIN_ETHER_TAP;

	eth = (rhp_proto_ether*)_rhp_pkt_push(pkt,(int)sizeof(rhp_proto_ether));

	ip6h = (rhp_proto_ip_v6*)_rhp_pkt_push(pkt,(int)sizeof(rhp_proto_ip_v6));
	h_b_hh = (rhp_proto_ip_v6_exthdr*)_rhp_pkt_push(pkt,8);
	mld2h = (rhp_proto_icmp6_mld2_report*)_rhp_pkt_push(pkt,
						(int)sizeof(rhp_proto_icmp6_mld2_report));
	mld2_rech = (rhp_proto_icmp6_mld2_mc_addr_rec*)_rhp_pkt_push(pkt,
						(int)sizeof(rhp_proto_icmp6_mld2_mc_addr_rec));

	pkt->l2.eth = eth;
	pkt->l3.raw = (u8*)ip6h;
	pkt->l4.raw = (u8*)mld2h;

	// Hop-By-Hop opt
	h_b_hh->next_header = RHP_PROTO_IP_IPV6_ICMP;
	h_b_hh->len = 0;
	((u8*)h_b_hh)[2] = 0x05; // Router Alert
	((u8*)h_b_hh)[3] = 0x02; // Len: 2bytes
	((u8*)h_b_hh)[4] = 0; // MLD
	((u8*)h_b_hh)[5] = 0; // MLD
	((u8*)h_b_hh)[6] = 0x01; // PadN
	((u8*)h_b_hh)[7] = 0;		 // PadN's Len


	memcpy(eth->src_addr,sender_mac,6);
	eth->protocol = RHP_PROTO_ETH_IPV6;

	ip6h->ver = 6;
	ip6h->priority = 0;
	ip6h->flow_label[0] = 0;
	ip6h->flow_label[1] = 0;
	ip6h->flow_label[2] = 0;
	ip6h->next_header = RHP_PROTO_IP_IPV6_HOP_BY_HOP;
	ip6h->hop_limit = 1;
	ip6h->payload_len = htons((u16)pld_len);
	if( src_ipv6 ){
		memcpy(ip6h->src_addr,src_ipv6,16);
	}else{
		memset(ip6h->src_addr,0,16);
	}

	memcpy(ip6h->dst_addr,rhp_ipv6_mld2_multicast_addr->addr.v6,16);

	rhp_ip_gen_multicast_mac(AF_INET6,ip6h->dst_addr,eth->dst_addr);


	mld2h->type = RHP_PROTO_ICMP6_TYPE_MLD2_LISTENER_REPORT;
	mld2h->code = 0;
	mld2h->check_sum = 0;
	mld2h->reserved = 0;
	mld2h->mc_addr_rec_num = htons(0x01);

	mld2_rech->type = RHP_PROTO_ICMP6_MLD2_MC_ADDR_REC_TO_EXCLUDE;
	mld2_rech->aux_len = 0;
	mld2_rech->src_addr_num = 0;
	memcpy(mld2_rech->mc_addr,mc_addr_ipv6,16);

	_rhp_proto_icmpv6_set_csum(ip6h->src_addr,ip6h->dst_addr,
			(rhp_proto_icmp6*)mld2h,(pld_len - 8));

	rhp_pkt_trace_dump("_rhp_ipv6_new_mld2_report",pkt);

	RHP_TRC_FREQ(0,RHPTRCID_IPV6_NEW_MLD2_REPORT_RTRN,"x",pkt);
	return pkt;
}

rhp_packet* rhp_ipv6_new_mld1_report(u8* sender_mac,
		u8* src_ipv6,u8* mc_addr_ipv6)
{
	rhp_packet* pkt = NULL;
	rhp_proto_ether* eth;
	rhp_proto_ip_v6 *ip6h;
	rhp_proto_ip_v6_exthdr *h_b_hh; // 8bytes
	rhp_proto_icmp6_mld1_report *mld1h;

	RHP_TRC_FREQ(0,RHPTRCID_IPV6_NEW_MLD1_REPORT,"M66",sender_mac,src_ipv6,mc_addr_ipv6);

	if( _rhp_mac_addr_null(sender_mac) ){
		RHP_BUG("");
		return NULL;
	}

	if( src_ipv6 && rhp_ipv6_addr_null(src_ipv6) ){
		RHP_BUG("");
		return NULL;
	}

	if( rhp_ipv6_addr_null(mc_addr_ipv6) ){
		RHP_BUG("");
		return NULL;
	}

	pkt = rhp_pkt_alloc( sizeof(rhp_proto_ether)
											+ sizeof(rhp_proto_ip_v6) + 8
											+ sizeof(rhp_proto_icmp6_mld1_report));
	if( pkt == NULL ){
		RHP_BUG("");
		return NULL;
	}

	pkt->type = RHP_PKT_PLAIN_ETHER_TAP;

	eth = (rhp_proto_ether*)_rhp_pkt_push(pkt,(int)sizeof(rhp_proto_ether));

	ip6h = (rhp_proto_ip_v6*)_rhp_pkt_push(pkt,(int)sizeof(rhp_proto_ip_v6));
	h_b_hh = (rhp_proto_ip_v6_exthdr*)_rhp_pkt_push(pkt,8);
	mld1h = (rhp_proto_icmp6_mld1_report*)_rhp_pkt_push(pkt,
						(int)sizeof(rhp_proto_icmp6_mld1_report));

	pkt->l2.eth = eth;
	pkt->l3.raw = (u8*)ip6h;
	pkt->l4.raw = (u8*)mld1h;

	// Hop-By-Hop opt
	h_b_hh->next_header = RHP_PROTO_IP_IPV6_ICMP;
	h_b_hh->len = 0;
	((u8*)h_b_hh)[2] = 0x05; // Router Alert
	((u8*)h_b_hh)[3] = 0x02; // Len: 2bytes
	((u8*)h_b_hh)[4] = 0; // MLD
	((u8*)h_b_hh)[5] = 0; // MLD
	((u8*)h_b_hh)[6] = 0x01; // PadN
	((u8*)h_b_hh)[7] = 0;		 // PadN's Len


	memcpy(eth->src_addr,sender_mac,6);
	eth->protocol = RHP_PROTO_ETH_IPV6;

	ip6h->ver = 6;
	ip6h->priority = 0;
	ip6h->flow_label[0] = 0;
	ip6h->flow_label[1] = 0;
	ip6h->flow_label[2] = 0;
	ip6h->next_header = RHP_PROTO_IP_IPV6_HOP_BY_HOP;
	ip6h->hop_limit = 1;
	ip6h->payload_len = htons(8 // Hop-By-Hop opt
														+ sizeof(rhp_proto_icmp6_mld1_report));
	if( src_ipv6 ){
		memcpy(ip6h->src_addr,src_ipv6,16);
	}else{
		memset(ip6h->src_addr,0,16);
	}

	memcpy(ip6h->dst_addr,mc_addr_ipv6,16);


	rhp_ip_gen_multicast_mac(AF_INET6,ip6h->dst_addr,eth->dst_addr);


	mld1h->type = RHP_PROTO_ICMP6_TYPE_MLD_LISTENER_REPORT;
	mld1h->code = 0;
	mld1h->check_sum = 0;
	mld1h->reserved = 0;
	mld1h->max_resp_delay = 0;

	memcpy(mld1h->mc_addr,mc_addr_ipv6,16);

	_rhp_proto_icmpv6_set_csum(ip6h->src_addr,ip6h->dst_addr,
			(rhp_proto_icmp6*)mld1h,sizeof(rhp_proto_icmp6_mld1_report));

	rhp_pkt_trace_dump("_rhp_ipv6_new_mld1_report",pkt);

	RHP_TRC_FREQ(0,RHPTRCID_IPV6_NEW_MLD1_REPORT_RTRN,"x",pkt);
	return pkt;
}

static rhp_packet* _rhp_ipv6_new_mld1_done(u8* sender_mac,
		u8* src_ipv6,u8* mc_addr_ipv6)
{
	rhp_packet* pkt = NULL;
	rhp_proto_ether* eth;
	rhp_proto_ip_v6* ip6h;
	rhp_proto_ip_v6_exthdr* h_b_hh; // 8bytes
	rhp_proto_icmp6_mld1* mld1h;

	RHP_TRC_FREQ(0,RHPTRCID_IPV6_DAD_NEW_MLD1_DONE,"M66",sender_mac,src_ipv6,mc_addr_ipv6);

	if( _rhp_mac_addr_null(sender_mac) ){
		RHP_BUG("");
		return NULL;
	}

	if( src_ipv6 && rhp_ipv6_addr_null(src_ipv6) ){
		RHP_BUG("");
		return NULL;
	}

	if( rhp_ipv6_addr_null(mc_addr_ipv6) ){
		RHP_BUG("");
		return NULL;
	}

	pkt = rhp_pkt_alloc( sizeof(rhp_proto_ether)
											+ sizeof(rhp_proto_ip_v6) + 8
											+ sizeof(rhp_proto_icmp6_mld2_report)
											+ sizeof(rhp_proto_icmp6_mld2_mc_addr_rec));
	if( pkt == NULL ){
		RHP_BUG("");
		return NULL;
	}

	pkt->type = RHP_PKT_PLAIN_ETHER_TAP;

	eth = (rhp_proto_ether*)_rhp_pkt_push(pkt,(int)sizeof(rhp_proto_ether));

	ip6h = (rhp_proto_ip_v6*)_rhp_pkt_push(pkt,(int)sizeof(rhp_proto_ip_v6));
	h_b_hh = (rhp_proto_ip_v6_exthdr*)_rhp_pkt_push(pkt,8);
	mld1h = (rhp_proto_icmp6_mld1*)_rhp_pkt_push(pkt,
						(int)sizeof(rhp_proto_icmp6_mld1));

	pkt->l2.eth = eth;
	pkt->l3.raw = (u8*)ip6h;
	pkt->l4.raw = (u8*)mld1h;

	// Hop-By-Hop opt
	h_b_hh->next_header = RHP_PROTO_IP_IPV6_ICMP;
	h_b_hh->len = 0;
	((u8*)h_b_hh)[2] = 0x05; // Router Alert
	((u8*)h_b_hh)[3] = 0x02; // Len: 2bytes
	((u8*)h_b_hh)[4] = 0; // MLD
	((u8*)h_b_hh)[5] = 0; // MLD
	((u8*)h_b_hh)[6] = 0x01; // PadN
	((u8*)h_b_hh)[7] = 0;		 // PadN's Len


	memcpy(eth->src_addr,sender_mac,6);
	eth->protocol = RHP_PROTO_ETH_IPV6;

	ip6h->ver = 6;
	ip6h->priority = 0;
	ip6h->flow_label[0] = 0;
	ip6h->flow_label[1] = 0;
	ip6h->flow_label[2] = 0;
	ip6h->next_header = RHP_PROTO_IP_IPV6_HOP_BY_HOP;
	ip6h->hop_limit = 1;
	ip6h->payload_len = htons(8 // Hop-By-Hop opt
														+ sizeof(rhp_proto_icmp6_mld1));
	if( src_ipv6 ){
		memcpy(ip6h->src_addr,src_ipv6,16);
	}else{
		memset(ip6h->src_addr,0,16);
	}

	memcpy(ip6h->dst_addr,rhp_ipv6_all_router_multicast_addr->addr.v6,16);


	rhp_ip_gen_multicast_mac(AF_INET6,ip6h->dst_addr,eth->dst_addr);


	mld1h->type = RHP_PROTO_ICMP6_TYPE_MLD_LISTENER_DONE;
	mld1h->code = 0;
	mld1h->check_sum = 0;
	mld1h->reserved = 0;
	mld1h->max_resp_delay = 0;
	memcpy(mld1h->mc_addr,mc_addr_ipv6,16);

	_rhp_proto_icmpv6_set_csum(ip6h->src_addr,ip6h->dst_addr,
			(rhp_proto_icmp6*)mld1h,sizeof(rhp_proto_icmp6_mld1));

	rhp_pkt_trace_dump("_rhp_ipv6_new_mld1_done",pkt);

	RHP_TRC_FREQ(0,RHPTRCID_IPV6_DAD_NEW_MLD1_DONE_RTRN,"x",pkt);
	return pkt;
}


static void _rhp_ipv6_rlm_lladdr_free_ctx(rhp_v6_rlm_lladdr_ctx* v6r_lladdr,rhp_ifc_entry* v_ifc)
{
	RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_FREE_CTX,"xxu",v6r_lladdr,v_ifc,v_ifc->tuntap_vpn_realm_id);

	if( v6r_lladdr->dad_probe_pkt_ref ){
		rhp_pkt_unhold(v6r_lladdr->dad_probe_pkt_ref);
	}

	if( v6r_lladdr->dad_mld2_pkt_ref ){
		rhp_pkt_unhold(v6r_lladdr->dad_mld2_pkt_ref);
	}


	// Actually, this v6r_lladdr ctx is freed in the timer
	// handler(_rhp_ipv6_rlm_lladdr_timer).
	if( !rhp_timer_delete(&(v6r_lladdr->retx_timer)) ){
		RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_FREE_CTX_TIMER_DELETED,"xx",v6r_lladdr);
	}

	rhp_ifc_unhold(v_ifc); // (**XX**)[_rhp_ipv6_rlm_lladdr_alloc_ctx()]

	_rhp_free(v6r_lladdr);

	RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_FREE_CTX_RTRN,"xx",v6r_lladdr,v_ifc);
	return;
}

static void _rhp_ipv6_rlm_lladdr_timer(void* arg,rhp_timer* timer)
{
	int err = -EINVAL;
	rhp_ifc_entry* v_ifc = (rhp_ifc_entry*)arg;
	rhp_v6_rlm_lladdr_ctx* v6r_lladdr = NULL;
	rhp_packet *mld2_rep_pkt_d = NULL;

	RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_TIMER,"xx",v_ifc,timer);

	RHP_LOCK(&(v_ifc->lock));

	RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_TIMER_V_IFC_CTX_DUMP,"xxLd6Mddxd",v_ifc,timer,"V6LLADDR_STAT",v_ifc->v6_aux_lladdr.state,v_ifc->v6_aux_lladdr.lladdr.addr.v6,v_ifc->v6_aux_lladdr.mac,v_ifc->v6_aux_lladdr.fixed_lladdr,v_ifc->v6_aux_lladdr.gen_retries,v_ifc->v6_aux_lladdr.ctx,rhp_gcfg_ipv6_rlm_lladdr_dad_retransmits);

  if( !_rhp_atomic_read(&(v_ifc->is_active)) ){
  	RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_TIMER_V_IFC_NOT_ACTIVE,"xx",v_ifc,timer);
  	goto error;
	}

  if( v_ifc->v6_aux_lladdr.state != RHP_V6_LINK_LOCAL_ADDR_DAD_PROBING ){
  	RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_TIMER_BAD_STATE,"xxLd",v_ifc,timer,"V6LLADDR_STAT",v_ifc->v6_aux_lladdr.state);
  	goto error;
	}

  v6r_lladdr = (rhp_v6_rlm_lladdr_ctx*)v_ifc->v6_aux_lladdr.ctx;
  if( v6r_lladdr == NULL ){
  	RHP_BUG("");
  	goto error;
  }


  if( rhp_gcfg_ipv6_rlm_lladdr_dad_retransmits &&
  		v6r_lladdr->retries < rhp_gcfg_ipv6_rlm_lladdr_dad_retransmits ){

		rhp_packet *nd_sol_pkt_d = NULL;

    RHP_UNLOCK(&(v_ifc->lock));


    nd_sol_pkt_d = rhp_pkt_dup(RHP_PKT_REF(v6r_lladdr->dad_probe_pkt_ref));
		mld2_rep_pkt_d = rhp_pkt_dup(RHP_PKT_REF(v6r_lladdr->dad_mld2_pkt_ref));

  	if( mld2_rep_pkt_d ){

  	  rhp_tuntap_write(v_ifc,mld2_rep_pkt_d);
  		rhp_pkt_unhold(mld2_rep_pkt_d);

  	}else{
  		RHP_BUG("");
  	}

  	if( nd_sol_pkt_d ){

  	  rhp_tuntap_write(v_ifc,nd_sol_pkt_d);
  		rhp_pkt_unhold(nd_sol_pkt_d);

  	}else{
  		RHP_BUG("");
  	}


		v6r_lladdr->retries++;

		rhp_timer_reset(&(v6r_lladdr->retx_timer));
		rhp_timer_add(&(v6r_lladdr->retx_timer),(time_t)rhp_gcfg_ipv6_rlm_lladdr_dad_retry_interval);


  }else{

  	v_ifc->v6_aux_lladdr.state = RHP_V6_LINK_LOCAL_ADDR_AVAILABLE;

  	rhp_ipv6_gen_solicited_node_multicast(v_ifc->v6_aux_lladdr.lladdr.addr.v6,
  			v_ifc->v6_aux_lladdr.lladdr_sol_node_mc);

  	err = rhp_bridge_static_neigh_cache_create(
  					v_ifc->tuntap_vpn_realm_id,
  					v_ifc->v6_aux_lladdr.mac,&(v_ifc->v6_aux_lladdr.lladdr),
  					RHP_BRIDGE_SIDE_TUNTAP,RHP_BRIDGE_SCACHE_V6_DUMMY_LL_ADDR);
  	if( err ){
  		RHP_BUG("%d",err);
  	}

		mld2_rep_pkt_d = rhp_pkt_dup(RHP_PKT_REF(v6r_lladdr->dad_mld2_pkt_ref));
  	if( mld2_rep_pkt_d ){
  		memcpy(mld2_rep_pkt_d->l3.iph_v6->src_addr,v_ifc->v6_aux_lladdr.lladdr.addr.v6,16);
  	}else{
  		RHP_BUG("");
  	}

    RHP_UNLOCK(&(v_ifc->lock));


  	if( mld2_rep_pkt_d ){

  	  rhp_tuntap_write(v_ifc,mld2_rep_pkt_d); // v_ifc->lock is NOT needed.
  		rhp_pkt_unhold(mld2_rep_pkt_d);
  	}

  	RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_TIMER_DONE,"xx",v_ifc,timer);


/*
//  [For Debug] FROM
  	{
  	  rhp_packet* mld1_done_pkt = _rhp_ipv6_new_mld1_done(
  	  								v_ifc->v6_aux_lladdr.mac,
  	  								v_ifc->v6_aux_lladdr.addr.v6,
  	  								RHP_PKT_REF(v6r_lladdr->dad_probe_pkt_ref)->l3.iph_v6->dst_addr);

  	  if( mld1_done_pkt == NULL ){
  	  	RHP_BUG("");
  	  }else{
  	  	rhp_tuntap_write(v_ifc,mld1_done_pkt);
  	  	rhp_pkt_unhold(mld1_done_pkt);
  	  }
  	}
//  [For Debug] TO
*/

  	_rhp_ipv6_rlm_lladdr_free_ctx(v6r_lladdr,v_ifc); // v_ifc->ref is also decremented.
  	v_ifc->v6_aux_lladdr.ctx = NULL;
  }

	RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_TIMER_RTRN,"xx",v_ifc,timer);
  return;

error:
	v_ifc->v6_aux_lladdr.state = RHP_V6_LINK_LOCAL_ADDR_ERR;
	v_ifc->v6_aux_lladdr.ctx = NULL;

	RHP_UNLOCK(&(v_ifc->lock));

	if( v6r_lladdr ){
		_rhp_ipv6_rlm_lladdr_free_ctx(v6r_lladdr,v_ifc); // v_ifc->ref is also decremented.
	}

	RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_TIMER_ERR,"xx",v_ifc,timer);
	return;
}

static rhp_v6_rlm_lladdr_ctx* _rhp_ipv6_rlm_lladdr_alloc_ctx(rhp_ifc_entry* v_ifc)
{
	rhp_v6_rlm_lladdr_ctx* v6r_lladdr = NULL;

	RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_ALLOC_CTX,"x",v_ifc);

	v6r_lladdr
	= (rhp_v6_rlm_lladdr_ctx*)_rhp_malloc(sizeof(rhp_v6_rlm_lladdr_ctx));

	if(v6r_lladdr == NULL){
		RHP_BUG("");
		goto error;
	}
	memset(v6r_lladdr,0,sizeof(rhp_v6_rlm_lladdr_ctx));

	v6r_lladdr->tag[0] = '#';
	v6r_lladdr->tag[1] = '6';
	v6r_lladdr->tag[2] = 'L';
	v6r_lladdr->tag[3] = 'A';

	rhp_timer_init(&(v6r_lladdr->retx_timer),_rhp_ipv6_rlm_lladdr_timer,v_ifc);
	rhp_ifc_hold(v_ifc); // (**XX**)[_rhp_ipv6_rlm_lladdr_free_ctx()]

	RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_ALLOC_CTX,"xx",v_ifc,v6r_lladdr);
	return v6r_lladdr;

error:
	RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_ALLOC_CTX_ERR,"x",v_ifc);
	return NULL;
}

static void _rhp_ipv6_rlm_lladdr_alloc_handler(void* ctx)
{
	int err;
	rhp_vpn_realm* rlm = NULL;
	rhp_ifc_entry* v_ifc = (rhp_ifc_entry*)ctx;
	rhp_v6_rlm_lladdr_ctx* v6r_lladdr = NULL;
	rhp_packet *nd_sol_pkt = NULL,*mld2_rep_pkt = NULL;
	rhp_ip_addr fixed_v6r_lladdr;

	RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_ALLOC_HANDLER,"xu",v_ifc,v_ifc->tuntap_vpn_realm_id);

	memset(&fixed_v6r_lladdr,0,sizeof(rhp_ip_addr));

	rlm = rhp_realm_get(v_ifc->tuntap_vpn_realm_id);
	if( rlm == NULL ){
		RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_ALLOC_HANDLER_NO_RLM,"xu",v_ifc,v_ifc->tuntap_vpn_realm_id);
		err = -ENOENT;
		goto error;
	}


	RHP_LOCK(&(rlm->lock));

	if( rlm->childsa.v6_aux_lladdr.addr_family == AF_INET6 &&
			!rhp_ip_addr_null(&(rlm->childsa.v6_aux_lladdr)) ){

		memcpy(&fixed_v6r_lladdr,&(rlm->childsa.v6_aux_lladdr),sizeof(rhp_ip_addr));
	}

	RHP_UNLOCK(&(rlm->lock));


	RHP_LOCK(&(v_ifc->lock));

	RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_ALLOC_HANDLER_V_IFC_CTX_DUMP,"xLd6Mddxd",v_ifc,"V6LLADDR_STAT",v_ifc->v6_aux_lladdr.state,v_ifc->v6_aux_lladdr.lladdr.addr.v6,v_ifc->v6_aux_lladdr.mac,v_ifc->v6_aux_lladdr.fixed_lladdr,v_ifc->v6_aux_lladdr.gen_retries,v_ifc->v6_aux_lladdr.ctx,rhp_gcfg_ipv6_rlm_lladdr_dad_retransmits);

  if( !_rhp_atomic_read(&(v_ifc->is_active)) ){
  	RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_ALLOC_HANDLER_V_IFC_NOT_ACTIVE,"xu",v_ifc,v_ifc->tuntap_vpn_realm_id);
  	goto error;
	}

  if( v_ifc->v6_aux_lladdr.state != RHP_V6_LINK_LOCAL_ADDR_DAD_PROBING ){
  	RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_ALLOC_HANDLER_V_IFC_BAD_STATE,"xuLd",v_ifc,v_ifc->tuntap_vpn_realm_id,"V6LLADDR_STAT",v_ifc->v6_aux_lladdr.state);
  	goto error;
  }

  if( v_ifc->v6_aux_lladdr.ctx != NULL ){
  	RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_ALLOC_HANDLER_V_IFC_CTX_BUSY,"xux",v_ifc,v_ifc->tuntap_vpn_realm_id,v_ifc->v6_aux_lladdr.ctx);
  	goto error;
  }

  v6r_lladdr = _rhp_ipv6_rlm_lladdr_alloc_ctx(v_ifc);
  if( v6r_lladdr == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  if( v_ifc->v6_aux_lladdr.fixed_lladdr &&
  		!rhp_ip_addr_null(&fixed_v6r_lladdr) ){

  	memcpy(&(v_ifc->v6_aux_lladdr.lladdr),&fixed_v6r_lladdr,sizeof(rhp_ip_addr));
  	RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_ALLOC_HANDLER_V_IFC_FIXED_LLADDR,"xu6",v_ifc,v_ifc->tuntap_vpn_realm_id,v_ifc->v6_aux_lladdr.lladdr.addr.v6);

  }else{

  	err = _rhp_ipv6_gen_dmy_lladdr(v_ifc->v6_aux_lladdr.lladdr.addr.v6);
		if( err ){
			RHP_BUG("");
			goto error;
		}
  }

  v_ifc->v6_aux_lladdr.fixed_lladdr = 0;


  nd_sol_pkt = _rhp_ipv6_dad_new_solicitation(
  							v_ifc->v6_aux_lladdr.mac,v_ifc->v6_aux_lladdr.lladdr.addr.v6);
  if( nd_sol_pkt == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  nd_sol_pkt->v6_rlm_lladdr = 1;

  mld2_rep_pkt = rhp_ipv6_new_mld2_report(
  								v_ifc->v6_aux_lladdr.mac,NULL,nd_sol_pkt->l3.iph_v6->dst_addr);
  if( mld2_rep_pkt == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  mld2_rep_pkt->v6_rlm_lladdr = 1;


  v6r_lladdr->dad_probe_pkt_ref = rhp_pkt_hold_ref(nd_sol_pkt);
  v6r_lladdr->dad_mld2_pkt_ref = rhp_pkt_hold_ref(mld2_rep_pkt);

  v_ifc->v6_aux_lladdr.ctx = (void*)v6r_lladdr;

  RHP_UNLOCK(&(v_ifc->lock));


  {
		rhp_packet *nd_sol_pkt_d = rhp_pkt_dup(nd_sol_pkt);
		rhp_packet *mld2_rep_pkt_d = rhp_pkt_dup(mld2_rep_pkt);

		if( mld2_rep_pkt_d ){

			rhp_tuntap_write(v_ifc,mld2_rep_pkt_d);
			rhp_pkt_unhold(mld2_rep_pkt_d);
		}

		if( nd_sol_pkt_d ){

			rhp_tuntap_write(v_ifc,nd_sol_pkt_d);
			rhp_pkt_unhold(nd_sol_pkt_d);
		}
  }

	rhp_timer_reset(&(v6r_lladdr->retx_timer));
	rhp_timer_add(&(v6r_lladdr->retx_timer),(time_t)rhp_gcfg_ipv6_rlm_lladdr_dad_first_interval);


	rhp_pkt_unhold(nd_sol_pkt);
	nd_sol_pkt = NULL;
	rhp_pkt_unhold(mld2_rep_pkt);
	mld2_rep_pkt = NULL;

	if( rlm ){
		rhp_realm_unhold(rlm);
	}

  rhp_ifc_unhold(v_ifc);

	RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_ALLOC_HANDLER_RTRN,"x",v_ifc);
	return;

error:
	if( v6r_lladdr ){
		_rhp_ipv6_rlm_lladdr_free_ctx(v6r_lladdr,v_ifc);
		v_ifc->v6_aux_lladdr.ctx = NULL;
	}

  RHP_UNLOCK(&(v_ifc->lock));

  if( nd_sol_pkt ){
  	rhp_pkt_unhold(nd_sol_pkt);
  }

  if( mld2_rep_pkt ){
  	rhp_pkt_unhold(mld2_rep_pkt);
  }

  if( rlm ){
    rhp_realm_unhold(rlm);
  }

	rhp_ifc_unhold(v_ifc);

	RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_ALLOC_HANDLER_ERR,"xx",v_ifc,rlm);
	return;
}

int rhp_ipv6_rlm_lladdr_start_alloc(unsigned long rlm_id,rhp_ifc_entry* v_ifc,
		int try_fixed_lladdr)
{
	int err;

	RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_START_ALLOC,"uxd",rlm_id,v_ifc,try_fixed_lladdr);

	if( rhp_gcfg_ipv6_disabled ){
		RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_START_ALLOC_IPV6_DISABLED,"uxd",rlm_id,v_ifc,try_fixed_lladdr);
		return -EINVAL;
	}

	rhp_ifc_hold(v_ifc);

	err = rhp_timer_oneshot(_rhp_ipv6_rlm_lladdr_alloc_handler,
					(void*)v_ifc,(time_t)rhp_gcfg_ipv6_rlm_lladdr_first_wait_secs);
	if( err ){
		rhp_ifc_unhold(v_ifc);
		RHP_BUG("%d",err);
		return err;
	}

	memset(&(v_ifc->v6_aux_lladdr.lladdr),0,sizeof(rhp_ip_addr));
  v_ifc->v6_aux_lladdr.lladdr.addr_family = AF_INET6;
	v_ifc->v6_aux_lladdr.state = RHP_V6_LINK_LOCAL_ADDR_DAD_PROBING;
	v_ifc->v6_aux_lladdr.fixed_lladdr = try_fixed_lladdr;
	v_ifc->v6_aux_lladdr.ctx = NULL;

	RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_START_ALLOC_RTRN,"u",rlm_id,v_ifc);
	return 0;
}

int rhp_ipv6_rlm_lladdr_rx(rhp_ifc_entry* v_ifc,rhp_packet* pkt)
{
	int err;
	rhp_proto_ether* eth = NULL;
	rhp_proto_ip_v6* ip6h = NULL;
	rhp_proto_icmp6* icmp6h = NULL;
	rhp_v6_rlm_lladdr_ctx* v6r_lladdr;
	u8* target_lladdr = NULL;

	RHP_TRC_FREQ(0,RHPTRCID_IPV6_RLM_LLADDR_RX,"xuxd",v_ifc,v_ifc->tuntap_vpn_realm_id,pkt,pkt->v6_rlm_lladdr);

	if( rhp_gcfg_ipv6_disabled ){
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_RLM_LLADDR_RX_IPV6_DISABLED,"xux",v_ifc,v_ifc->tuntap_vpn_realm_id,pkt);
		return 0;
	}

	if( pkt->v6_rlm_lladdr ){
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_RLM_LLADDR_RX_OWN_PKT,"xux",v_ifc,v_ifc->tuntap_vpn_realm_id,pkt);
		goto ignored;
	}

	err = rhp_ipv6_icmp6_parse_rx_pkt(pkt,&eth,&ip6h,&icmp6h);
	if( err ){
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_RLM_LLADDR_RX_PARSE_ICMP6_ERR,"xuxE",v_ifc,v_ifc->tuntap_vpn_realm_id,pkt,err);
		goto ignored;
	}


	RHP_LOCK(&(v_ifc->lock));

	RHP_TRC(0,RHPTRCID_IPV6_RLM_LLADDR_RX_V_IFC_CTX_DUMP,"xLd6Mddxdb",v_ifc,"V6LLADDR_STAT",v_ifc->v6_aux_lladdr.state,v_ifc->v6_aux_lladdr.lladdr.addr.v6,v_ifc->v6_aux_lladdr.mac,v_ifc->v6_aux_lladdr.fixed_lladdr,v_ifc->v6_aux_lladdr.gen_retries,v_ifc->v6_aux_lladdr.ctx,rhp_gcfg_ipv6_rlm_lladdr_dad_retransmits,icmp6h->type);

	if( rhp_ipv6_is_same_addr(ip6h->src_addr,v_ifc->v6_aux_lladdr.lladdr.addr.v6)  ){
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_RLM_LLADDR_RX_OWN_PKT2,"xuxxdE",v_ifc,v_ifc->tuntap_vpn_realm_id,pkt,v_ifc->v6_aux_lladdr.ctx,v_ifc->v6_aux_lladdr.state,err);
		goto end;
	}

	switch( icmp6h->type ){

	case RHP_PROTO_ICMP6_TYPE_NEIGHBOR_ADV:

		if( v_ifc->v6_aux_lladdr.ctx == NULL ||
				v_ifc->v6_aux_lladdr.state != RHP_V6_LINK_LOCAL_ADDR_DAD_PROBING ){

			RHP_TRC_FREQ(0,RHPTRCID_IPV6_RLM_LLADDR_RX_NOT_PROBING_STATE,"xuxxdE",v_ifc,v_ifc->tuntap_vpn_realm_id,pkt,v_ifc->v6_aux_lladdr.ctx,v_ifc->v6_aux_lladdr.state,err);
			goto end;
		}


		err = rhp_ipv6_nd_parse_adv_pkt(pkt,eth,ip6h,icmp6h,&target_lladdr,NULL);
		if( err ){
			RHP_TRC_FREQ(0,RHPTRCID_IPV6_RLM_LLADDR_RX_PARSE_ND_ADV_ERR,"xuxE",v_ifc,v_ifc->tuntap_vpn_realm_id,pkt,err);
			goto end;
		}

		if( target_lladdr &&
				rhp_ipv6_is_same_addr(target_lladdr,v_ifc->v6_aux_lladdr.lladdr.addr.v6) ){

		  v6r_lladdr = (rhp_v6_rlm_lladdr_ctx*)v_ifc->v6_aux_lladdr.ctx;

		  if( !rhp_timer_delete(&(v6r_lladdr->retx_timer)) ){

		  	v_ifc->v6_aux_lladdr.state = RHP_V6_LINK_LOCAL_ADDR_ERR;

		  	_rhp_ipv6_rlm_lladdr_free_ctx(v6r_lladdr,v_ifc); // v_ifc->ref is also decremented.
		  	v_ifc->v6_aux_lladdr.ctx = NULL;

		  	if( v_ifc->v6_aux_lladdr.gen_retries <= rhp_gcfg_ipv6_rlm_lladdr_max_gen_retries ){

					RHP_TRC_FREQ(0,RHPTRCID_IPV6_RLM_LLADDR_RX_RETRY,"xux",v_ifc,v_ifc->tuntap_vpn_realm_id,pkt);

		  		v_ifc->v6_aux_lladdr.gen_retries++;

		  		err = rhp_ipv6_rlm_lladdr_start_alloc(v_ifc->tuntap_vpn_realm_id,v_ifc,0);
		  		if( err ){
		  			RHP_BUG("");
		  		}

		  	}else{

					RHP_TRC_FREQ(0,RHPTRCID_IPV6_RLM_LLADDR_RX_RETRY_ERR,"xuxdd",v_ifc,v_ifc->tuntap_vpn_realm_id,pkt,v_ifc->v6_aux_lladdr.gen_retries,rhp_gcfg_ipv6_rlm_lladdr_max_gen_retries);
		  	}

		  }else{
				RHP_TRC_FREQ(0,RHPTRCID_IPV6_RLM_LLADDR_RX_TIMER_EXPIRED,"xux",v_ifc,v_ifc->tuntap_vpn_realm_id,pkt);
			}
		}

		break;

	default:
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_RLM_LLADDR_RX_NOT_INTERESTED,"xuxb",v_ifc,v_ifc->tuntap_vpn_realm_id,pkt,icmp6h->type);
		goto end;
	}

end:
	RHP_UNLOCK(&(v_ifc->lock));

ignored:
	RHP_TRC_FREQ(0,RHPTRCID_IPV6_RLM_LLADDR_RX_RTRN,"xux",v_ifc,v_ifc->tuntap_vpn_realm_id,pkt);
	return 0;
}

int rhp_ipv6_is_nd_packet(rhp_packet* pkt,u8* icmp6_type_r)
{
	rhp_proto_ether* eth = pkt->l2.eth;
	rhp_proto_ip_v6* ip6h;
	rhp_proto_icmp6* icmp6h;
	u8 proto = RHP_PROTO_IP_IPV6_ICMP;
	int pld_len = 0;

	RHP_TRC_FREQ(0,RHPTRCID_IPV6_IS_ND_PACKET,"x",pkt);

	if( pkt->tail == NULL ){
		RHP_BUG("");
		return 0;
	}

	if( eth == NULL ){
		RHP_BUG("");
		return 0;
	}

	if( eth->protocol != RHP_PROTO_ETH_IPV6 ){
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_IS_ND_PACKET_ETH_NOT_IPV6,"xW",pkt,eth->protocol);
		return 0;
	}


	ip6h = (rhp_proto_ip_v6*)(eth + 1);

	if( ((u8*)ip6h) + sizeof(rhp_proto_ip_v6) > pkt->tail ){
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_IS_ND_PACKET_BAD_IPV6_LEN,"x",pkt);
		return 0;
	}

	if( ip6h->ver != 6 ){
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_IS_ND_PACKET_NOT_IPV6,"xd",pkt,ip6h->ver);
		return 0;
	}

	pld_len = ntohs(ip6h->payload_len);
	if( pld_len < (int)sizeof(rhp_proto_icmp6) ||
			((u8*)(ip6h + 1)) + pld_len > pkt->tail ){
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_IS_ND_PACKET_BAD_ICMP6_LEN,"xd",pkt,pld_len);
		return 0;
	}

	icmp6h = (rhp_proto_icmp6*)rhp_proto_ip_v6_upper_layer(ip6h,pkt->end,1,&proto,NULL);
	if( icmp6h == NULL || ((u8*)(icmp6h + 1)) > pkt->tail ){
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_IS_ND_PACKET_NO_ICMP6_DATA,"x",pkt);
		return 0;
	}

	pld_len -= ((u8*)icmp6h) - ((u8*)(ip6h + 1));
	if( pld_len <= 0 ){
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_IS_ND_PACKET_NO_ICMP6_PLD_DATA,"x",pkt);
		return 0;
	}

	if( icmp6h->type == RHP_PROTO_ICMP6_TYPE_NEIGHBOR_SOLICIT ||
			icmp6h->type == RHP_PROTO_ICMP6_TYPE_NEIGHBOR_ADV ||
			icmp6h->type == RHP_PROTO_ICMP6_TYPE_MLD_LISTENER_QUERY ){

		if( icmp6_type_r ){
			*icmp6_type_r = icmp6h->type;
		}

		RHP_TRC_FREQ(0,RHPTRCID_IPV6_IS_ND_PACKET_FOUND,"x",pkt);
		return 1;
	}

	RHP_TRC_FREQ(0,RHPTRCID_IPV6_IS_ND_PACKET_NOT_INTERESTED,"x",pkt);
	return 0;
}

// Caller does NOT acquire rlm->lock and vifc->lock(rlm->internal_ifc->ifc).
int rhp_ipv6_rlm_lladdr_get(rhp_vpn_realm* rlm,u8* lladdr_r,u8* llmac_r)
{
	int err = -EINVAL;
	rhp_ifc_entry* v_ifc = NULL;

	RHP_TRC_FREQ(0,RHPTRCID_IPV6_RLM_LLADDR_GET,"xux",rlm,rlm->id,llmac_r);

	RHP_LOCK(&(rlm->lock));
	{
		v_ifc = rlm->internal_ifc->ifc;
		if( v_ifc == NULL ){

			err = -EINVAL;
			RHP_TRC_FREQ(0,RHPTRCID_IPV6_RLM_LLADDR_GET_NO_VIFC,"xu",rlm,rlm->id);

			RHP_UNLOCK(&(rlm->lock));
			goto error;
		}

		rhp_ifc_hold(v_ifc);
	}
	RHP_UNLOCK(&(rlm->lock));


	RHP_LOCK(&(v_ifc->lock));
	{
		if( v_ifc->v6_aux_lladdr.state != RHP_V6_LINK_LOCAL_ADDR_AVAILABLE ){

			err = -EINVAL;
			RHP_TRC_FREQ(0,RHPTRCID_IPV6_RLM_LLADDR_GET_NO_V6_AUX_MAC,"xu",rlm,rlm->id);

			RHP_UNLOCK(&(v_ifc->lock));
			rhp_ifc_unhold(v_ifc);

			goto error;
		}

		memcpy(lladdr_r,v_ifc->v6_aux_lladdr.lladdr.addr.v6,16);
		memcpy(llmac_r,v_ifc->v6_aux_lladdr.mac,6);
	}
	RHP_UNLOCK(&(v_ifc->lock));
	rhp_ifc_unhold(v_ifc);

	RHP_TRC_FREQ(0,RHPTRCID_IPV6_RLM_LLADDR_GET_RTRN,"xuM",rlm,rlm->id,llmac_r);
	return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_IPV6_RLM_LLADDR_GET_ERR,"xuE",rlm,rlm->id,err);
	return err;
}

// Caller must acquire v_ifc->lock.
int rhp_ipv6_v_ifc_lladdr_get(rhp_ifc_entry* v_ifc,u8* lladdr_r,u8* llmac_r)
{
	int err = -EINVAL;

	RHP_TRC_FREQ(0,RHPTRCID_IPV6_V_IFC_LLADDR_GET,"xuxx",v_ifc,v_ifc->tuntap_vpn_realm_id,lladdr_r,llmac_r);

	if( v_ifc->v6_aux_lladdr.state != RHP_V6_LINK_LOCAL_ADDR_AVAILABLE ){

		err = -EINVAL;
		RHP_TRC_FREQ(0,RHPTRCID_IPV6_V_IFC_LLADDR_GET_NO_V6_AUX_MAC,"xu",v_ifc,v_ifc->tuntap_vpn_realm_id);

		goto error;
	}

	memcpy(lladdr_r,v_ifc->v6_aux_lladdr.lladdr.addr.v6,16);
	memcpy(llmac_r,v_ifc->v6_aux_lladdr.mac,6);

	RHP_TRC_FREQ(0,RHPTRCID_IPV6_V_IFC_LLADDR_GET_RTRN,"xu6M",v_ifc,v_ifc->tuntap_vpn_realm_id,lladdr_r,llmac_r);
	return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_IPV6_V_IFC_LLADDR_GET_ERR,"xuE",v_ifc,v_ifc->tuntap_vpn_realm_id,err);
	return err;
}

