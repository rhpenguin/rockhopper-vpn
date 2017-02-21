/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/

//
// TODO : RHP_PKT_PLAIN_IPV4_ESP_DUMMY (TFC Dummy packets) support...
//

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
#include "rhp_esp.h"
#include "rhp_eoip.h"
#include "rhp_forward.h"
#include "rhp_timer.h"
#include "rhp_tuntap.h"
#include "rhp_ikev2.h"
#include "rhp_pcap.h"

//
// TODO : Supporting ESP dummy packets for TFC.
//


void rhp_esp_get_statistics(rhp_esp_global_statistics* table)
{
	RHP_LOCK(&rhp_esp_lock_statistics);
	memcpy(table,&rhp_esp_statistics_global_tbl,sizeof(rhp_esp_global_statistics));
	RHP_UNLOCK(&rhp_esp_lock_statistics);
}

void rhp_esp_clear_statistics()
{
	RHP_LOCK(&rhp_esp_lock_statistics);

	memset(&rhp_esp_statistics_global_tbl,0,
			sizeof(rhp_esp_global_statistics) - sizeof(rhp_esp_global_statistics_dont_clear));

	RHP_UNLOCK(&rhp_esp_lock_statistics);
}


static inline void _rhp_esp_tx_pcap_write(rhp_vpn* tx_vpn,rhp_packet* pkt)
{
	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_PCAP_WRITE,"xxLdd",tx_vpn,pkt,"PKT",pkt->type,pkt->encap_mode);

	if( pkt->encap_mode == RHP_VPN_ENCAP_GRE ||
			pkt->encap_mode == RHP_VPN_ENCAP_ETHERIP ){

		int addr_family;
		struct {
			rhp_proto_ether ethh;
			union {
				rhp_proto_ip_v4 v4;
				rhp_proto_ip_v6 v6;
			} iph;
		} dmy_hdr;
		int dmy_hdr_len;

		memcpy(dmy_hdr.ethh.src_addr,tx_vpn->local.if_info.mac,6);
		memset(dmy_hdr.ethh.dst_addr,0,6);

		addr_family = tx_vpn->local.if_info.addr_family;
		if( addr_family == AF_INET ){

			dmy_hdr_len = (int)(sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v4));

			dmy_hdr.ethh.protocol = RHP_PROTO_ETH_IP;

			dmy_hdr.iph.v4.ver = 4;
			dmy_hdr.iph.v4.ihl = 5;
			dmy_hdr.iph.v4.tos = 0;
			dmy_hdr.iph.v4.total_len = htons((int)sizeof(rhp_proto_ip_v4) + pkt->len);
			dmy_hdr.iph.v4.id = 0;
			dmy_hdr.iph.v4.frag = 0;
			dmy_hdr.iph.v4.ttl = 64;
			if( pkt->encap_mode == RHP_VPN_ENCAP_GRE ){
				dmy_hdr.iph.v4.protocol = RHP_PROTO_IP_GRE;
			}else if( pkt->encap_mode == RHP_VPN_ENCAP_ETHERIP ){
				dmy_hdr.iph.v4.protocol = RHP_PROTO_IP_ETHERIP;
			}
			dmy_hdr.iph.v4.check_sum = 0;
			dmy_hdr.iph.v4.src_addr = tx_vpn->local.if_info.addr.v4;
			dmy_hdr.iph.v4.dst_addr = tx_vpn->peer_addr.addr.v4;

		}else if( addr_family == AF_INET6 ){

			dmy_hdr_len = (int)(sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v6));

			dmy_hdr.ethh.protocol = RHP_PROTO_ETH_IPV6;

			dmy_hdr.iph.v6.ver = 6;
			dmy_hdr.iph.v6.priority = 0;
			dmy_hdr.iph.v6.flow_label[0] = 0;
			dmy_hdr.iph.v6.flow_label[1] = 0;
			dmy_hdr.iph.v6.flow_label[2] = 0;
			if( pkt->encap_mode == RHP_VPN_ENCAP_GRE ){
				dmy_hdr.iph.v6.next_header = RHP_PROTO_IP_GRE;
			}else if( pkt->encap_mode == RHP_VPN_ENCAP_ETHERIP ){
				dmy_hdr.iph.v6.next_header = RHP_PROTO_IP_ETHERIP;
			}
			dmy_hdr.iph.v6.hop_limit = 64;
			dmy_hdr.iph.v6.payload_len = htons(pkt->len);
			memcpy(dmy_hdr.iph.v6.src_addr,tx_vpn->local.if_info.addr.v6,16);
			memcpy(dmy_hdr.iph.v6.dst_addr,tx_vpn->peer_addr.addr.v6,16);

		}else{
			RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_PCAP_WRITE_ERR_1,"xx",tx_vpn,pkt);
			goto error;
		}

		rhp_pcap_write(pkt->len,pkt->data,dmy_hdr_len,(u8*)&dmy_hdr);

	}else if( pkt->encap_mode == RHP_VPN_ENCAP_IPIP ){

		rhp_proto_ether ethh;

		memcpy(ethh.src_addr,tx_vpn->local.if_info.mac,6);
		memset(ethh.dst_addr,0,6);

		if( ((rhp_proto_ip_v4*)pkt->data)->ver == 4 ){
			ethh.protocol = RHP_PROTO_ETH_IP;
		}else if( ((rhp_proto_ip_v4*)pkt->data)->ver == 6 ){
			ethh.protocol = RHP_PROTO_ETH_IPV6;
		}else{
			RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_PCAP_WRITE_ERR_2,"xx",tx_vpn,pkt);
			goto error;
		}

		rhp_pcap_write(pkt->len,pkt->data,(int)sizeof(rhp_proto_ether),(u8*)&ethh);

	}else{
		RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_PCAP_WRITE_ERR_3,"xx",tx_vpn,pkt);
		goto error;
	}

error:
	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_PCAP_WRITE_RTRN,"xx",tx_vpn,pkt);
	return;
}

static inline void _rhp_esp_rx_pcap_write(rhp_vpn* rx_vpn,rhp_packet* pkt,u8 next_header)
{
	u8* p;
	int pkt_len;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_PCAP_WRITE,"xxbd",rx_vpn,pkt,next_header,pkt->pcaped);

	if( pkt->pcaped ){
		return;
	}

	if( next_header == RHP_PROTO_IP_IP ||
			next_header == RHP_PROTO_IP_IPV6 ){

		rhp_proto_ether ethh;

		memset(ethh.src_addr,0,6);
		memcpy(ethh.dst_addr,rx_vpn->local.if_info.mac,6);

		if( next_header == RHP_PROTO_IP_IP ){
			ethh.protocol = RHP_PROTO_ETH_IP;
		}else if( next_header == RHP_PROTO_IP_IPV6 ){
			ethh.protocol = RHP_PROTO_ETH_IPV6;
		}

		pkt_len = pkt->len;
		p = pkt->data;

		rhp_pcap_write(pkt_len,p,(int)sizeof(rhp_proto_ether),(u8*)&ethh);

	}else if( next_header == RHP_PROTO_IP_GRE ||
						next_header == RHP_PROTO_IP_ETHERIP ){

		int addr_family;
		struct {
			rhp_proto_ether ethh;
			union {
				rhp_proto_ip_v4 v4;
				rhp_proto_ip_v6 v6;
			} iph;
		} dmy_hdr;
		int dmy_hdr_len;

		memset(dmy_hdr.ethh.src_addr,0,6);
		memcpy(dmy_hdr.ethh.dst_addr,rx_vpn->local.if_info.mac,6);

		pkt_len = pkt->len;
		p = pkt->data;

		addr_family = rx_vpn->local.if_info.addr_family;
		if( addr_family == AF_INET ){

			dmy_hdr_len = (int)(sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v4));

			dmy_hdr.ethh.protocol = RHP_PROTO_ETH_IP;

			dmy_hdr.iph.v4.ver = 4;
			dmy_hdr.iph.v4.ihl = 5;
			dmy_hdr.iph.v4.tos = 0;
			dmy_hdr.iph.v4.total_len = htons((int)sizeof(rhp_proto_ip_v4) + pkt_len);
			dmy_hdr.iph.v4.id = 0;
			dmy_hdr.iph.v4.frag = 0;
			dmy_hdr.iph.v4.ttl = 64;
			if( next_header == RHP_PROTO_IP_GRE ){
				dmy_hdr.iph.v4.protocol = RHP_PROTO_IP_GRE;
			}else if( next_header == RHP_PROTO_IP_ETHERIP ){
				dmy_hdr.iph.v4.protocol = RHP_PROTO_IP_ETHERIP;
			}
			dmy_hdr.iph.v4.check_sum = 0;
			dmy_hdr.iph.v4.src_addr = rx_vpn->peer_addr.addr.v4;
			dmy_hdr.iph.v4.dst_addr = rx_vpn->local.if_info.addr.v4;

		}else if( addr_family == AF_INET6 ){

			dmy_hdr_len = (int)(sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v6));

			dmy_hdr.ethh.protocol = RHP_PROTO_ETH_IPV6;

			dmy_hdr.iph.v6.ver = 6;
			dmy_hdr.iph.v6.priority = 0;
			dmy_hdr.iph.v6.flow_label[0] = 0;
			dmy_hdr.iph.v6.flow_label[1] = 0;
			dmy_hdr.iph.v6.flow_label[2] = 0;
			if( next_header == RHP_PROTO_IP_GRE ){
				dmy_hdr.iph.v6.next_header = RHP_PROTO_IP_GRE;
			}else if( next_header == RHP_PROTO_IP_ETHERIP ){
				dmy_hdr.iph.v6.next_header = RHP_PROTO_IP_ETHERIP;
			}
			dmy_hdr.iph.v6.hop_limit = 64;
			dmy_hdr.iph.v6.payload_len = htons(pkt_len);
			memcpy(dmy_hdr.iph.v6.src_addr,rx_vpn->peer_addr.addr.v6,16);
			memcpy(dmy_hdr.iph.v6.dst_addr,rx_vpn->local.if_info.addr.v6,16);

		}else{
			RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_PCAP_WRITE_ERR_1,"xxb",rx_vpn,pkt,next_header);
			goto error;
		}

		rhp_pcap_write(pkt_len,p,dmy_hdr_len,(u8*)&dmy_hdr);

	}else{
		RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_PCAP_WRITE_ERR_2,"xxb",rx_vpn,pkt,next_header);
		goto error;
	}

error:
	RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_PCAP_WRITE_RTRN,"xxb",rx_vpn,pkt,next_header);
	return;
}


static u32 _rhp_esp_tx_disp_hash_rnd = 0;

static u32 _rhp_esp_tx_disp_hash(void *key_seed,int* err)
{
	u32 spi_outb = ((rhp_packet*)key_seed)->esp_tx_spi_outb;
	u32 hval;

	hval = _rhp_hash_u32(spi_outb,_rhp_esp_tx_disp_hash_rnd);
	*err = 0;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_DISP_HASH,"xxux",key_seed,err,hval,hval);
	return hval;
}

int rhp_esp_init()
{
  int err = 0;

  if( rhp_random_bytes((u8*)&_rhp_esp_tx_disp_hash_rnd,sizeof(_rhp_esp_tx_disp_hash_rnd)) ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  err = rhp_wts_register_disp_rule(RHP_WTS_DISP_RULE_ESP_TX,_rhp_esp_tx_disp_hash);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

  err = rhp_esp_impl_init();
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

  _rhp_mutex_init("EST",&(rhp_esp_lock_statistics));

  memset(&rhp_esp_statistics_global_tbl,0,sizeof(rhp_esp_global_statistics));

error:
	RHP_TRC(0,RHPTRCID_ESP_INIT,"E",err);
	return err;
}

int rhp_esp_cleanup()
{
	rhp_esp_impl_cleanup();

  _rhp_mutex_destroy(&(rhp_esp_lock_statistics));

	RHP_TRC(0,RHPTRCID_ESP_CLEANUP,"");
	return 0;
}


static rhp_packet* _rhp_esp_new_icmp_pmtud_err_v4_pkt(rhp_packet* rx_pkt,
		rhp_proto_ip_v4* rx_iph,u32 this_addr,int pmtu_size)
{
	rhp_packet* icmp_err_pkt;
	int pkt_len = sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v4)
								+ sizeof(rhp_proto_icmp) + sizeof(rhp_proto_icmp_frag_needed);
	int tot_len,new_tot_len;
	rhp_proto_ether* ethh;
	rhp_proto_ip_v4* iph;
	rhp_proto_icmp* icmph;
	rhp_proto_icmp_frag_needed* fragh;
	int pld_len;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_NEW_ICMP_PMTUD_ERR_V4_PKT,"xd4",rx_pkt,pmtu_size,this_addr);
	rhp_pkt_trace_dump("_rhp_esp_new_icmp_pmtud_err_v4_pkt.rx_pkt",rx_pkt);


	tot_len = ntohs(rx_iph->total_len);

	if( rx_pkt->len <= (int)(sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v4)) ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_NEW_ICMP_PMTUD_ERR_V4_PKT_IGNORE_1,"x",rx_pkt);
		return NULL;
	}

	// Including broadcast addresss
	if( RHP_PROTO_ETHER_MULTICAST_DST(rx_pkt->l2.eth) ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_NEW_ICMP_PMTUD_ERR_V4_PKT_IGNORE_2,"x",rx_pkt);
		return NULL;
	}

	// Including broadcast addresss
	if( RHP_PROTO_ETHER_MULTICAST_SRC(rx_pkt->l2.eth) ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_NEW_ICMP_PMTUD_ERR_V4_PKT_IGNORE_3,"x",rx_pkt);
		return NULL;
	}

	if( (rx_iph->dst_addr == 0xFFFFFFFF) || (rx_iph->src_addr == 0xFFFFFFFF) ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_NEW_ICMP_PMTUD_ERR_V4_PKT_IGNORE_4,"x",rx_pkt);
		return NULL;
	}

	if( rhp_ip_multicast(AF_INET,(u8*)&(rx_iph->dst_addr)) ||
			rhp_ip_multicast(AF_INET,(u8*)&(rx_iph->src_addr)) ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_NEW_ICMP_PMTUD_ERR_V4_PKT_IGNORE_5,"x",rx_pkt);
		return NULL;
	}


	if( rx_iph->protocol == RHP_PROTO_IP_ICMP ){

		rhp_proto_icmp* rx_icmph;

		if( tot_len < (int)(sizeof(rhp_proto_ip_v4) + sizeof(rhp_proto_icmp)) ){
			RHP_TRC_FREQ(0,RHPTRCID_ESP_NEW_ICMP_PMTUD_ERR_V4_PKT_IGNORE_6,"x",rx_pkt);
			return NULL;
		}

		rx_icmph = (rhp_proto_icmp*)(((u8*)rx_iph) + rx_iph->ihl*4);

		if( (u8*)rx_icmph >= rx_pkt->end ){
			RHP_TRC_FREQ(0,RHPTRCID_ESP_NEW_ICMP_PMTUD_ERR_V4_PKT_IGNORE_7,"x",rx_pkt);
			return NULL;
		}

		if( rx_icmph->type != RHP_PROTO_ICMP_TYPE_ECHO_REQUEST ) {
			RHP_TRC_FREQ(0,RHPTRCID_ESP_NEW_ICMP_PMTUD_ERR_V4_PKT_IGNORE_8,"x",rx_pkt);
			return NULL;
		}
	}


	if( tot_len > rhp_gcfg_pmtu_err_max_size ){
		pld_len = rhp_gcfg_pmtu_err_max_size;
	}else{
		pld_len = tot_len;
	}


	pkt_len += pld_len;
	new_tot_len = sizeof(rhp_proto_ip_v4) + sizeof(rhp_proto_icmp)
							  + sizeof(rhp_proto_icmp_frag_needed) + pld_len;


	icmp_err_pkt = rhp_pkt_alloc(pkt_len);
	if( icmp_err_pkt == NULL ){
		RHP_BUG("");
		return NULL;
	}

	icmp_err_pkt->type = RHP_PKT_PLAIN_ETHER_TAP;

	ethh = (rhp_proto_ether*)_rhp_pkt_push(icmp_err_pkt,sizeof(rhp_proto_ether));
	iph = (rhp_proto_ip_v4*)_rhp_pkt_push(icmp_err_pkt,sizeof(rhp_proto_ip_v4));
	icmph = (rhp_proto_icmp*)_rhp_pkt_push(icmp_err_pkt,sizeof(rhp_proto_icmp));
	fragh = (rhp_proto_icmp_frag_needed*)_rhp_pkt_push(icmp_err_pkt,sizeof(rhp_proto_icmp_frag_needed));

	ethh->protocol = rx_pkt->l2.eth->protocol;
	memcpy(ethh->dst_addr,rx_pkt->l2.eth->src_addr,6);
	memcpy(ethh->src_addr,rx_pkt->l2.eth->dst_addr,6);

	iph->ver = 4;
	iph->ihl = 5;
	iph->tos = 0;
	iph->total_len = htons(new_tot_len);
	iph->frag = 0;
	iph->ttl = 64;
	iph->protocol = RHP_PROTO_IP_ICMP;
	iph->check_sum = 0;
	iph->src_addr = this_addr;
	iph->dst_addr = rx_iph->src_addr;

	rhp_random_bytes((u8*)&(iph->id),sizeof(u16));

	icmph->type = RHP_PROTO_ICMP_TYPE_DEST_UNREACH;
	icmph->code = RHP_PROTO_ICMP_FRAG_NEEDED;
	icmph->check_sum = 0;

	fragh->mtu = htons((u16)pmtu_size);
	fragh->reserved = 0;

	memcpy((u8*)(fragh + 1),(u8*)rx_iph,pld_len);

	_rhp_proto_icmp_set_csum(icmph,(sizeof(rhp_proto_icmp) + sizeof(rhp_proto_icmp_frag_needed) + pld_len));
	_rhp_proto_ip_v4_set_csum(iph);

	icmp_err_pkt->l2.raw = (u8*)ethh;
	icmp_err_pkt->l3.raw = (u8*)iph;

	if( rx_pkt->esp_rx_vpn_ref ){
		icmp_err_pkt->esp_tx_vpn_ref = rhp_vpn_hold_ref(RHP_VPN_REF(rx_pkt->esp_rx_vpn_ref));
	}

	if( rx_pkt->rx_ifc ){
		icmp_err_pkt->tx_ifc = rx_pkt->rx_ifc;
		rhp_ifc_hold(icmp_err_pkt->tx_ifc);
	}

	rhp_pkt_trace_dump("_rhp_esp_new_icmp_pmtud_err_v4_pkt.icmp_err_pkt",icmp_err_pkt);
	RHP_TRC_FREQ(0,RHPTRCID_ESP_NEW_ICMP_PMTUD_ERR_V4_PKT_RTRN,"xxa",rx_pkt,icmp_err_pkt,(sizeof(new_tot_len) + new_tot_len),RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,ethh);

	return icmp_err_pkt;
}

static rhp_packet* _rhp_esp_new_icmp_pmtud_err_v6_pkt(rhp_packet* rx_pkt,
		rhp_proto_ip_v6* rx_ip6h,u8* this_addr,int pmtu_size)
{
	rhp_packet* icmp6_err_pkt;
	int pkt_len = sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v6)
								+ sizeof(rhp_proto_icmp6_pkt_too_big);
	int tot_len,new_tot_len;
	u8 proto = RHP_PROTO_IP_IPV6_ICMP;
	rhp_proto_icmp6* rx_icmp6h;
	rhp_proto_ether* ethh;
	rhp_proto_ip_v6* ip6h;
	rhp_proto_icmp6_pkt_too_big* icmp6h;
	int pld_len;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_NEW_ICMP_PMTUD_ERR_V6_PKT,"xd6",rx_pkt,pmtu_size,this_addr);
	rhp_pkt_trace_dump("_rhp_esp_new_icmp_pmtud_err_v6_pkt.rx_pkt",rx_pkt);


	tot_len = (int)sizeof(rhp_proto_ip_v6) + (int)ntohs(rx_ip6h->payload_len);

	if( rx_pkt->len <= (int)(sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v6)) ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_NEW_ICMP_PMTUD_ERR_V6_PKT_IGNORE_1,"x",rx_pkt);
		return NULL;
	}

	// Including broadcast addresss
	if( RHP_PROTO_ETHER_MULTICAST_DST(rx_pkt->l2.eth) ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_NEW_ICMP_PMTUD_ERR_V6_PKT_IGNORE_2,"x",rx_pkt);
		return NULL;
	}

	// Including broadcast addresss
	if( RHP_PROTO_ETHER_MULTICAST_SRC(rx_pkt->l2.eth) ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_NEW_ICMP_PMTUD_ERR_V6_PKT_IGNORE_3,"x",rx_pkt);
		return NULL;
	}

	if( rhp_ip_multicast(AF_INET6,rx_ip6h->dst_addr) ||
			rhp_ip_multicast(AF_INET6,rx_ip6h->src_addr) ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_NEW_ICMP_PMTUD_ERR_V6_PKT_IGNORE_5,"x",rx_pkt);
		return NULL;
	}


	rx_icmp6h = (rhp_proto_icmp6*)rhp_proto_ip_v6_upper_layer(rx_ip6h,rx_pkt->end,1,&proto,NULL);
	if( rx_icmp6h ){

		if( tot_len < (int)(sizeof(rhp_proto_ip_v6) + sizeof(rhp_proto_icmp6)) ){
			RHP_TRC_FREQ(0,RHPTRCID_ESP_NEW_ICMP_PMTUD_ERR_V6_PKT_IGNORE_6,"x",rx_pkt);
			return NULL;
		}

		if( rx_icmp6h->type != RHP_PROTO_ICMP6_TYPE_ECHO_REQUEST ) {
			RHP_TRC_FREQ(0,RHPTRCID_ESP_NEW_ICMP_PMTUD_ERR_V6_PKT_IGNORE_8,"x",rx_pkt);
			return NULL;
		}
	}


	if( tot_len > rhp_gcfg_pmtu_err_max_size ){
		pld_len = rhp_gcfg_pmtu_err_max_size;
	}else{
		pld_len = tot_len;
	}


	pkt_len += pld_len;
	new_tot_len = sizeof(rhp_proto_ip_v6) + sizeof(rhp_proto_icmp6_pkt_too_big)
							  + pld_len;


	icmp6_err_pkt = rhp_pkt_alloc(pkt_len);
	if( icmp6_err_pkt == NULL ){
		RHP_BUG("");
		return NULL;
	}

	icmp6_err_pkt->type = RHP_PKT_PLAIN_ETHER_TAP;

	ethh = (rhp_proto_ether*)_rhp_pkt_push(icmp6_err_pkt,sizeof(rhp_proto_ether));
	ip6h = (rhp_proto_ip_v6*)_rhp_pkt_push(icmp6_err_pkt,sizeof(rhp_proto_ip_v6));
	icmp6h = (rhp_proto_icmp6_pkt_too_big*)_rhp_pkt_push(icmp6_err_pkt,sizeof(rhp_proto_icmp6_pkt_too_big));

	ethh->protocol = rx_pkt->l2.eth->protocol;
	memcpy(ethh->dst_addr,rx_pkt->l2.eth->src_addr,6);
	memcpy(ethh->src_addr,rx_pkt->l2.eth->dst_addr,6);


	ip6h->ver = 6;
	ip6h->priority = 0;
	ip6h->flow_label[0] = 0;
	ip6h->flow_label[1] = 0;
	ip6h->flow_label[2] = 0;
	ip6h->next_header = RHP_PROTO_IP_IPV6_ICMP;
	ip6h->hop_limit = 64;
	ip6h->payload_len = htons(new_tot_len - sizeof(rhp_proto_ip_v6));
	memcpy(ip6h->src_addr,this_addr,16);
	memcpy(ip6h->dst_addr,rx_ip6h->src_addr,16);


	icmp6h->type = RHP_PROTO_ICMP6_TYPE_PKT_TOO_BIG;
	icmp6h->code = 0;
	icmp6h->check_sum = 0;

	icmp6h->mtu = htonl((u32)pmtu_size);

	memcpy((u8*)(icmp6h + 1),(u8*)rx_ip6h,pld_len);

	_rhp_proto_icmpv6_set_csum(ip6h->src_addr,ip6h->dst_addr,
			(rhp_proto_icmp6*)icmp6h,sizeof(rhp_proto_icmp6_pkt_too_big) + pld_len);


	icmp6_err_pkt->l2.raw = (u8*)ethh;
	icmp6_err_pkt->l3.raw = (u8*)ip6h;

	if( rx_pkt->esp_rx_vpn_ref ){
		icmp6_err_pkt->esp_tx_vpn_ref = rhp_vpn_hold_ref(RHP_VPN_REF(rx_pkt->esp_rx_vpn_ref));
	}

	if( rx_pkt->rx_ifc ){
		icmp6_err_pkt->tx_ifc = rx_pkt->rx_ifc;
		rhp_ifc_hold(icmp6_err_pkt->tx_ifc);
	}

	rhp_pkt_trace_dump("_rhp_esp_new_icmp_pmtud_err_v6_pkt.icmp_err_pkt",icmp6_err_pkt);
	RHP_TRC_FREQ(0,RHPTRCID_ESP_NEW_ICMP_PMTUD_ERR_V6_PKT_RTRN,"xxa",rx_pkt,icmp6_err_pkt,(sizeof(new_tot_len) + new_tot_len),RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,ethh);

	return icmp6_err_pkt;
}

static void _rhp_esp_tx_icmp_err_dispatched_task(rhp_packet* pkt_icmpd_err_pkt)
{
	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_ICMP_ERR_DISPATCHED_TASK,"x",pkt_icmpd_err_pkt);

	rhp_ifc_entry* v_ifc = pkt_icmpd_err_pkt->tx_ifc;

	if( v_ifc && !memcmp(v_ifc->if_name,RHP_VIRTUAL_IF_NAME,RHP_VIRTUAL_IF_NAME_LEN) ){

		rhp_tuntap_write(v_ifc,pkt_icmpd_err_pkt);

	}else if( pkt_icmpd_err_pkt->esp_tx_vpn_ref ){

		rhp_vpn* tx_vpn = RHP_VPN_REF(pkt_icmpd_err_pkt->esp_tx_vpn_ref);

		rhp_encap_send(tx_vpn,pkt_icmpd_err_pkt);

	}else{

		RHP_BUG("");
	}

	rhp_pkt_unhold(pkt_icmpd_err_pkt); // pkt_icmpd_err_pkt->tx_ifc etc. will be released.

	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_ICMP_ERR_DISPATCHED_TASK_RTRN,"x",pkt_icmpd_err_pkt);
	return;
}

static int _rhp_esp_tx_dispatch_pmtud_err_packet(rhp_packet* pkt)
{
	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_DISPATCH_PACKET,"x",pkt);

	pkt->process_packet = _rhp_esp_tx_icmp_err_dispatched_task;

	return rhp_wts_sta_invoke_task(RHP_WTS_DISP_RULE_SAME_WORKER,
			RHP_WTS_STA_TASK_NAME_PKT,RHP_WTS_DISP_LEVEL_LOW_2,pkt,pkt);
}

static int _rhp_esp_tcp_mss_overwrite(int addr_family,u8* iph,u8* end,
		rhp_proto_tcp* tcph,int tcp_seg_len,int pmtu_cache)
{
	int tcp_hdr_len;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_MSS_OVERWRITE,"Ldxxxddpp","AF",addr_family,iph,end,tcph,tcp_seg_len,pmtu_cache,(addr_family == AF_INET ? sizeof(rhp_proto_ip_v4) : sizeof(rhp_proto_ip_v6)),iph,sizeof(rhp_proto_tcp),tcph);

	if( (u8*)tcph >= end ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_MSS_OVERWRITE_INVALID_PKT,"xxx",iph,tcph,end);
		goto error;
	}

	// 4 bytes: MSS option
	if( tcph->syn && (tcp_hdr_len = tcph->doff*4) >= (int)(sizeof(rhp_proto_tcp) + 4) ){

		u8* opt_p = (u8*)(tcph + 1);
		u8* endp = (u8*)((u8*)tcph) + tcp_hdr_len;

		while( opt_p < endp ){

			if( *opt_p == RHP_PROTO_TCP_OPT_EOP ){

				break;

			}else if( *opt_p == RHP_PROTO_TCP_OPT_NOP ){

				opt_p++;

			}else if( *opt_p == RHP_PROTO_TCP_OPT_MSS ){

				u16 mss,tun_mss;

				if( endp - opt_p < 4 ){
					RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_MSS_OVERWRITE_MSS_OPT_IGNORE_1,"xx",iph,end);
					goto error;
				}

				mss = ntohs(*((u16*)&(opt_p[2])));

				if( addr_family == AF_INET ){

					tun_mss = (u16)(pmtu_cache - (int)(sizeof(rhp_proto_ip_v4) + sizeof(rhp_proto_tcp)));

				}else if( addr_family == AF_INET6 ){

					tun_mss = (u16)(pmtu_cache - (int)(sizeof(rhp_proto_ip_v6) + sizeof(rhp_proto_tcp)));

				}else{

					goto error;
				}

				if( mss > tun_mss ){

					if( ((u8*)tcph) + tcp_seg_len > end ){
						RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_MSS_OVERWRITE_MSS_OPT_INVALID_PKT,"xx",iph,end);
						goto error;
					}

					if( tcp_seg_len < tcp_hdr_len ){
						RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_MSS_OVERWRITE_MSS_OPT_IGNORE_2,"xx",iph,end);
						goto error;
					}

					*((u16*)&(opt_p[2])) = htons(tun_mss);

					if( addr_family == AF_INET ){

						_rhp_proto_ip_v4_tcp_set_csum(
								((rhp_proto_ip_v4*)iph)->src_addr,
								((rhp_proto_ip_v4*)iph)->dst_addr,tcph,tcp_seg_len);

					}else if( addr_family == AF_INET6 ){

						_rhp_proto_ip_v6_tcp_set_csum(
								((rhp_proto_ip_v6*)iph)->src_addr,
								((rhp_proto_ip_v6*)iph)->dst_addr,tcph,tcp_seg_len);
					}

					RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_MSS_OVERWRITE_EXEC_OVERWRITE,"xxww",iph,end,mss,tun_mss);
				}

				break;

			}else{

				if( (endp - opt_p >= 2) && opt_p[1] > 0 ){

					opt_p += opt_p[1];

				}else{ // We don't know this TCP option's format.

					RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_MSS_OVERWRITE_IGNORE_2,"xxxx",iph,end,endp,opt_p);
					goto error;
				}
			}
		}

	}else{

		RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_MSS_OVERWRITE_IGNORE_1,"xx",iph,end);
	}

error:
	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_MSS_OVERWRITE_RTRN,"xxp",iph,end,sizeof(rhp_proto_tcp),tcph);
	return 0; // Error NOT retured.
}

int rhp_esp_tcp_mss_overwrite_v4(rhp_proto_ip_v4* iph,u8* end,int pmtu_cache)
{
	int err;
	int ihl = iph->ihl*4;
	rhp_proto_tcp* tcph = (rhp_proto_tcp*)(((u8*)iph)  + ihl);
	int tcp_seg_len = htons(iph->total_len) - ihl;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_MSS_OVERWRITE_V4,"xxddpp",iph,end,pmtu_cache,tcp_seg_len,sizeof(rhp_proto_ip_v4),iph,sizeof(rhp_proto_tcp),tcph);

	err = _rhp_esp_tcp_mss_overwrite(AF_INET,(u8*)iph,end,tcph,tcp_seg_len,pmtu_cache);

	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_MSS_OVERWRITE_V4_RTRN,"xE",iph,err);
	return err;
}

int rhp_esp_tcp_mss_overwrite_v6(rhp_proto_ip_v6* ip6h,u8* end,int pmtu_cache)
{
	int err = -EINVAL;
	int tcp_seg_len;
	rhp_proto_tcp* tcph;
	u8 proto = RHP_PROTO_IP_TCP;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_MSS_OVERWRITE_V6,"xxdp",ip6h,end,pmtu_cache,sizeof(rhp_proto_ip_v6),ip6h);

	tcph = (rhp_proto_tcp*)rhp_proto_ip_v6_upper_layer(ip6h,end,1,&proto,NULL);
	if( tcph == NULL || ((u8*)(tcph + 1)) >= end ){
		err = 0;  // Error NOT retured.
		goto error;
	}

	tcp_seg_len = (int)htons(ip6h->payload_len) - (int)(((u8*)tcph) - ((u8*)(ip6h + 1)));
	if( tcp_seg_len <= 0 || (((u8*)tcph) + tcp_seg_len) >= end ){
		err = 0;  // Error NOT retured.
		goto error;
	}

	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_MSS_OVERWRITE_V6_TCP,"xdp",tcph,tcp_seg_len,sizeof(rhp_proto_tcp),tcph);

	err = _rhp_esp_tcp_mss_overwrite(AF_INET6,(u8*)ip6h,end,tcph,tcp_seg_len,pmtu_cache);

error:
	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_MSS_OVERWRITE_V6_RTRN,"xE",ip6h,err);
	return err;
}

int rhp_esp_tx_handle_pmtud_v4(rhp_packet* rx_pkt,rhp_proto_ip_v4* iph,int pmtu_cache)
{
	int err = -EINVAL;
	int pkt_len = rx_pkt->len;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_HANDLE_PMTUD,"xddx",rx_pkt,pmtu_cache,pkt_len,rx_pkt->rx_ifc);

	if( ((u8*)(iph + 1) >= rx_pkt->end) ){
		err = -EINVAL;
		goto drop;
	}

	if( iph->protocol == RHP_PROTO_IP_TCP ){

		err = rhp_esp_tcp_mss_overwrite_v4(iph,rx_pkt->end,pmtu_cache);
		if( err ){
			goto drop;
		}
	}

	if( (pkt_len > pmtu_cache) && RHP_PROTO_IP_FRAG_DF(iph->frag) ){

		rhp_packet* pkt_icmpd_err;
		rhp_ifc_entry* ifc = rx_pkt->rx_ifc;
		u32 this_addr = 0;
		int this_prefix_len = 0;

		if( ifc == NULL ){
			RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_HANDLE_PMTUD_NO_RX_IF,"x",rx_pkt);
			goto skip;
		}

		RHP_LOCK(&(ifc->lock));
		{
			rhp_ifc_addr* ifc_addr = ifc->select_src_addr(ifc,AF_INET,(u8*)&(iph->src_addr),0);
			if( ifc_addr ){
				this_addr = ifc_addr->addr.addr.v4;
				this_prefix_len = ifc_addr->addr.prefixlen;
			}
		}
		RHP_UNLOCK(&(ifc->lock));

		if( this_addr && this_prefix_len &&
				iph->src_addr != this_addr &&
				!rhp_ip_same_subnet_v4(iph->dst_addr,iph->src_addr,this_prefix_len) ){

			pkt_icmpd_err = _rhp_esp_new_icmp_pmtud_err_v4_pkt(rx_pkt,iph,this_addr,pmtu_cache);
			if( pkt_icmpd_err == NULL ){

				RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_HANDLE_PMTUD_TX_ICMP_ERR_PKT_FAILED,"xE",rx_pkt,err);

			}else{

				err = _rhp_esp_tx_dispatch_pmtud_err_packet(pkt_icmpd_err);
				if( err ){
					RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_HANDLE_PMTUD_DISP_PACKET_ERR,"xxE",rx_pkt,pkt_icmpd_err,err);
					rhp_pkt_unhold(pkt_icmpd_err); // pkt_icmpd_err_pkt-> tx_ifc will be released.
				}
			}

			RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_HANDLE_PMTUD_TX_ICMP_ERR_PKT,"xxE",rx_pkt,pkt_icmpd_err,err);

			err = RHP_STATUS_PMTUD_ERROR;
			goto drop;
		}
	}

skip:
	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_HANDLE_PMTUD_RTRN,"x",rx_pkt);
	return 0;

drop:
	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_HANDLE_PMTUD_DROP,"x",rx_pkt);
	return err;
}

int rhp_esp_tx_handle_pmtud_v6(rhp_packet* rx_pkt,rhp_proto_ip_v6* ip6h,int pmtu_cache)
{
	int err = -EINVAL;
	int pkt_len = rx_pkt->len;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_HANDLE_PMTUD_V6,"xddx",rx_pkt,pmtu_cache,pkt_len,rx_pkt->rx_ifc);

	if( ((u8*)(ip6h + 1) >= rx_pkt->end) ){
		err = -EINVAL;
		goto drop;
	}

	err = rhp_esp_tcp_mss_overwrite_v6(ip6h,rx_pkt->end,pmtu_cache);
	if( err ){
		goto drop;
	}

	if( pkt_len > pmtu_cache ){

		rhp_packet* pkt_icmpd_err;
		rhp_ifc_entry* ifc = rx_pkt->rx_ifc;
		u8 this_addr_v6[16];
		int this_prefix_v6_len = 0;

		if( ifc == NULL ){
			RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_HANDLE_PMTUD_V6_NO_RX_IF,"x",rx_pkt);
			goto skip;
		}

		RHP_LOCK(&(ifc->lock));
		{
			rhp_ifc_addr* ifc_addr = ifc->select_src_addr(ifc,AF_INET6,ip6h->src_addr,0);
			if( ifc_addr ){
				memcpy(this_addr_v6,ifc_addr->addr.addr.v6,16);
				this_prefix_v6_len = ifc_addr->addr.prefixlen;
			}else{
				memset(this_addr_v6,0,16);
			}
		}
		RHP_UNLOCK(&(ifc->lock));

		if( !rhp_ipv6_addr_null(this_addr_v6) && this_prefix_v6_len &&
				!rhp_ipv6_is_same_addr(ip6h->src_addr,this_addr_v6) &&
				!rhp_ip_same_subnet_v6(ip6h->dst_addr,ip6h->src_addr,this_prefix_v6_len) ){

			pkt_icmpd_err = _rhp_esp_new_icmp_pmtud_err_v6_pkt(rx_pkt,ip6h,this_addr_v6,pmtu_cache);
			if( pkt_icmpd_err == NULL ){

				RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_HANDLE_PMTUD_V6_TX_ICMP_ERR_PKT_FAILED,"xE",rx_pkt,err);

			}else{

				err = _rhp_esp_tx_dispatch_pmtud_err_packet(pkt_icmpd_err);

				if( err ){
					RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_HANDLE_PMTUD_V6_DISP_PACKET_ERR,"xxE",rx_pkt,pkt_icmpd_err,err);
					rhp_pkt_unhold(pkt_icmpd_err); // pkt_icmpd_err_pkt-> tx_ifc will be released.
				}
			}

			RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_HANDLE_PMTUD_V6_TX_ICMP_ERR_PKT,"xxE",rx_pkt,pkt_icmpd_err,err);

			err = RHP_STATUS_PMTUD_ERROR;
			goto drop;
		}
	}

skip:
	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_HANDLE_PMTUD_V6_RTRN,"x",rx_pkt);
	return 0;

drop:
	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_HANDLE_PMTUD_V6_DROP,"x",rx_pkt);
	return err;
}


void rhp_esp_tx_dispatched_task(rhp_packet* pkt)
{
	int err;
	rhp_vpn_ref* tx_vpn_ref = pkt->esp_tx_vpn_ref;
	rhp_vpn* tx_vpn = RHP_VPN_REF(tx_vpn_ref);
	rhp_vpn_realm* rlm = NULL;
	u32 spi_outb = pkt->esp_tx_spi_outb;
	int pkt_tx_len = pkt->len;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_DISPATCHED_TASK,"xxxd",pkt,tx_vpn_ref,tx_vpn,pkt_tx_len);

	pkt->esp_tx_vpn_ref = NULL;

	if( tx_vpn == NULL ){
		RHP_BUG("");
		goto error;
	}


	RHP_LOCK(&(tx_vpn->lock));

	if( !_rhp_atomic_read(&(tx_vpn->is_active)) ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_DISPATCHED_TASK_VPN_NOT_ACTIVE,"xx",pkt,tx_vpn);
		goto error_l;
  }

	rlm = tx_vpn->rlm;
	if( rlm == NULL ){
  	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_DISPATCHED_TASK_NO_RLM,"xx",pkt,tx_vpn);
		goto error_l;
	}
	rhp_realm_hold(rlm);


	if( rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_ESP_PLAIN] &&
			(!rhp_packet_capture_realm_id || (tx_vpn && rhp_packet_capture_realm_id == tx_vpn->vpn_realm_id)) ){

		_rhp_esp_tx_pcap_write(tx_vpn,pkt);
	}


	RHP_UNLOCK(&(tx_vpn->lock));

	rhp_pkt_hold(pkt);


	// pend_ctx is currently not used.
	err = rhp_esp_impl_enc_packet(pkt,tx_vpn,rlm,spi_outb,(void*)1);
	if( err == RHP_STATUS_ESP_IMPL_PENDING ){

		//
		// Pending... ESP impl will call rhp_esp_send_callback() later...
		//

		//
		// pkt and tx_vpn must be held by rhp_xxx_unhold() in rhp_esp_impl_enc_packet();
		//

		RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_DISPATCHED_TASK_IMPL_OUTBOUND_PACKET_PENDING,"xxxH",pkt,tx_vpn,rlm,spi_outb);

		rhp_pkt_pending(pkt);

	}else if( err ){

  	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_DISPATCHED_TASK_IMPL_OUTBOUND_PACKET_ERR,"xxxHE",pkt,tx_vpn,rlm,spi_outb,err);

  	rhp_pkt_unhold(pkt);

		switch(err){

		case RHP_STATUS_SELECTOR_NOT_MATCHED:
			RHP_LOCK(&(rlm->lock));
			rlm->statistics.esp.tx_esp_ts_err_packets++;
			RHP_UNLOCK(&(rlm->lock));

	  	rhp_esp_g_statistics_inc(tx_esp_ts_err_packets);
			break;

		case RHP_STATUS_ESP_ENCRYPT_ERR:
			RHP_LOCK(&(rlm->lock));
			rlm->statistics.esp.tx_esp_encrypt_err_packets++;
			RHP_UNLOCK(&(rlm->lock));

	  	rhp_esp_g_statistics_inc(tx_esp_encrypt_err_packets);
			break;

		case RHP_STATUS_ESP_INTEG_ERR:
			RHP_LOCK(&(rlm->lock));
			rlm->statistics.esp.tx_esp_integ_err_packets++;
			RHP_UNLOCK(&(rlm->lock));

	  	rhp_esp_g_statistics_inc(tx_esp_integ_err_packets);
			break;

		case RHP_STATUS_ESP_INVALID_PKT:
			RHP_LOCK(&(rlm->lock));
			rlm->statistics.esp.tx_esp_invalid_packets++;
			RHP_UNLOCK(&(rlm->lock));

	  	rhp_esp_g_statistics_inc(tx_esp_invalid_packets);
			break;

		case RHP_STATUS_ESP_NO_CHILDSA:
			RHP_LOCK(&(rlm->lock));
			rlm->statistics.esp.rx_esp_no_childsa_err_packets++;
			RHP_UNLOCK(&(rlm->lock));

	  	rhp_esp_g_statistics_inc(rx_esp_no_childsa_err_packets);
			break;

		default:
			break;
		}

  	goto error;

	}else{

  	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_DISPATCHED_TASK_IMPL_OUTBOUND_PACKET_OK,"xxxH",pkt,tx_vpn,rlm,spi_outb);

  	rhp_pkt_unhold(pkt);

		err = rhp_netsock_send(pkt->tx_ifc,pkt);
		if( err < 0 ){

			// Write trace...
			err = 0;

		}else{

			RHP_LOCK(&(tx_vpn->lock));
			{
				rhp_childsa* outb_childsa;

				tx_vpn->statistics.tx_esp_packets++;
				tx_vpn->statistics.tx_esp_bytes += pkt_tx_len;

				outb_childsa = tx_vpn->childsa_get(tx_vpn,RHP_DIR_OUTBOUND,spi_outb);
				if( outb_childsa ){
					outb_childsa->statistics.tx_esp_packets++;
				}
			}
			RHP_UNLOCK(&(tx_vpn->lock));
		}
	}


	RHP_LOCK(&(rlm->lock));
	rlm->statistics.esp.tx_esp_packets++;
	RHP_UNLOCK(&(rlm->lock));

	rhp_realm_unhold(rlm);
	rhp_vpn_unhold(tx_vpn_ref);
	rhp_pkt_unhold(pkt);

	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_DISPATCHED_TASK_RTRN,"xxx",pkt,tx_vpn,rlm);
  return;


error_l:
  RHP_UNLOCK(&(tx_vpn->lock));
error:
	if( rlm ){
		RHP_LOCK(&(rlm->lock));
		rlm->statistics.esp.tx_esp_err_packets++;
		RHP_UNLOCK(&(rlm->lock));
		rhp_realm_unhold(rlm);
	}
	if( tx_vpn ){
		rhp_vpn_unhold(tx_vpn_ref);
	}
	if( pkt ){
		rhp_pkt_unhold(pkt);
	}

	rhp_esp_g_statistics_inc(tx_esp_err_packets);

	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_DISPATCHED_TASK_ERR,"xxx",pkt,tx_vpn,rlm);
	return;
}

static int _rhp_esp_tx_dispatch_packet(rhp_packet* pkt)
{
	int disp_pri;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_DISPATCH_PACKET,"x",pkt);

	if( rhp_gcfg_forward_critical_pkt_preferentially &&
			rhp_is_critical_pkt(pkt) ){
		disp_pri = RHP_WTS_DISP_LEVEL_HIGH_2;
	}else{
		disp_pri = RHP_WTS_DISP_LEVEL_LOW_1;
	}

	pkt->process_packet = rhp_esp_tx_dispatched_task;

	return rhp_wts_sta_invoke_task(RHP_WTS_DISP_RULE_ESP_TX,
			RHP_WTS_STA_TASK_NAME_PKT,disp_pri,pkt,pkt);
}


static int _rhp_esp_tx_get_inner_iphdr(rhp_packet* pkt,
		u16* proto_r/*RHP_PROTO_ETH_IP or RHP_PROTO_ETH_IPV6*/,
		u8** iphdr_r /*rhp_proto_ip_v4 or rhp_proto_ip_v6. Don't free it!*/)
{
	int err = -EINVAL;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_GET_INTER_IPHDR,"x",pkt);

  switch( pkt->type ){

  case RHP_PKT_PLAIN_ETHER_TAP:
  case RHP_PKT_PLAIN_IPV4_TUNNEL:
  case RHP_PKT_PLAIN_IPV4_ESP_DUMMY:
  case RHP_PKT_PLAIN_IPV6_TUNNEL:
  case RHP_PKT_PLAIN_IPV6_ESP_DUMMY:
  	break;

  default:
  	err = -EINVAL;
		RHP_BUG("%d",pkt->type);
		goto error;
	}

  if( pkt->l2.raw == NULL || pkt->l3.raw == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  if( pkt->type == RHP_PKT_PLAIN_ETHER_TAP ){

  	if( pkt->encap_mode == RHP_VPN_ENCAP_IPIP 	 ||
  			pkt->encap_mode == RHP_VPN_ENCAP_ETHERIP ||
  			pkt->encap_mode == RHP_VPN_ENCAP_GRE ){

  		if( pkt->l2.eth->protocol == RHP_PROTO_ETH_IP ){

  			*proto_r = RHP_PROTO_ETH_IP;
  			*iphdr_r = (u8*)(pkt->l3.iph_v4);

  		}else	if( pkt->l2.eth->protocol == RHP_PROTO_ETH_IPV6 ){

  			*proto_r = RHP_PROTO_ETH_IPV6;
  			*iphdr_r = (u8*)(pkt->l3.iph_v6);

  		}else{
  			RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_GET_INTER_IPHDR_NOT_IP_PKT,"xd",pkt,pkt->l2.eth->protocol);
  	  	err = -EINVAL;
  	  	goto error;
  		}

  	}else{
  		RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_GET_INTER_IPHDR_UNKNOWN_ENCAP_MODE,"xd",pkt,pkt->encap_mode);
	  	err = -EINVAL;
	  	goto error;
  	}

  }else if( pkt->type == RHP_PKT_PLAIN_IPV4_TUNNEL ){

		*proto_r = RHP_PROTO_ETH_IP;
		*iphdr_r = (u8*)(pkt->l3.iph_v4);

  }else if( pkt->type == RHP_PKT_PLAIN_IPV6_TUNNEL ){

		*proto_r = RHP_PROTO_ETH_IPV6;
		*iphdr_r = (u8*)(pkt->l3.iph_v6);

  }else if( pkt->type == RHP_PKT_PLAIN_IPV4_ESP_DUMMY ||
  					pkt->type == RHP_PKT_PLAIN_IPV6_ESP_DUMMY ){

  	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_GET_INTER_IPHDR_ESP_DUMMY_IGNORED,"x",pkt);

  	// TODO: Supporting dummy esp packets
  	err = -EINVAL;
  	goto error;

  }else{
  	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_GET_INTER_IPHDR_UNKNOWN_PKT_TYPE,"xd",pkt,pkt->type);
  	err = -EINVAL;
  	goto error;
  }

	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_GET_INTER_IPHDR_RTRN,"x",pkt);
  return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_ESP_TX_GET_INTER_IPHDR_ERR,"xE",pkt,err);
	return err;
}


//
// For a peer, like Win7/8, which creates and deletes Child SAs dynamically.
//
static int _rhp_esp_dyn_create_childsa(rhp_vpn* tx_vpn,rhp_packet* pkt)
{
	int err = -EINVAL;
	u16 proto = 0;
	u8* iph = NULL;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_DYN_CREATE_CHILDSA,"xx",tx_vpn,pkt);

	if( tx_vpn->deleting ){
		err = 0;
		RHP_TRC_FREQ(0,RHPTRCID_ESP_DYN_CREATE_CHILDSA_VPN_DELETING,"xx",tx_vpn,pkt);
		goto error;
	}

	if( tx_vpn->last_my_tss == NULL || tx_vpn->last_peer_tss == NULL ){
		err = -EINVAL;
		RHP_TRC_FREQ(0,RHPTRCID_ESP_DYN_CREATE_CHILDSA_LAST_TSS_NULL,"xxxx",tx_vpn,pkt,tx_vpn->last_my_tss,tx_vpn->last_peer_tss);
		goto error;
	}

	err = _rhp_esp_tx_get_inner_iphdr(pkt,&proto,&iph);
	if( err ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_DYN_CREATE_CHILDSA_NO_IP_HEADER,"xx",tx_vpn,pkt);
		goto error;
	}

	if( proto == RHP_PROTO_ETH_IP ){

		if( rhp_esp_match_selectors_ipv4(RHP_DIR_OUTBOUND,
					tx_vpn->last_my_tss,tx_vpn->last_peer_tss,NULL,NULL,(rhp_proto_ip_v4*)iph,pkt->end) ){

			err = RHP_STATUS_SELECTOR_NOT_MATCHED;
			RHP_TRC_FREQ(0,RHPTRCID_ESP_DYN_CREATE_CHILDSA_SELECTOR_NOT_MATCHED,"xx",tx_vpn,pkt);
			goto error;
		}

	}else if( proto == RHP_PROTO_ETH_IPV6 ){

		if( rhp_esp_match_selectors_ipv6(RHP_DIR_OUTBOUND,
					tx_vpn->last_my_tss,tx_vpn->last_peer_tss,NULL,NULL,(rhp_proto_ip_v6*)iph,pkt->end,0) ){

			err = RHP_STATUS_SELECTOR_NOT_MATCHED;
			RHP_TRC_FREQ(0,RHPTRCID_ESP_DYN_CREATE_CHILDSA_SELECTOR_NOT_MATCHED_V6,"xx",tx_vpn,pkt);
			goto error;
		}

	}else{

		err = RHP_STATUS_SELECTOR_NOT_MATCHED;
		RHP_TRC_FREQ(0,RHPTRCID_ESP_DYN_CREATE_CHILDSA_NOT_IP_PKT,"xxW",tx_vpn,pkt,proto);
		goto error;
	}


	err = rhp_ikev2_create_child_sa_dyn_create(tx_vpn);

error:
	RHP_TRC_FREQ(0,RHPTRCID_ESP_DYN_CREATE_CHILDSA_RTRN,"xxE",tx_vpn,pkt,err);
	return err;
}


int rhp_esp_send(rhp_vpn* tx_vpn,rhp_packet* pkt)
{
	int err = -EINVAL;
	rhp_childsa* cur_childsa;
	u32 spi_outb;
	int childsa_negotiating = 0;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_SEND_l,"xx",pkt,tx_vpn);

	if( tx_vpn == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	RHP_LOCK(&(tx_vpn->lock));

	if( !_rhp_atomic_read(&(tx_vpn->is_active)) ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_SEND_l_VPN_NOT_ACTIVE,"xx",pkt,tx_vpn);
		err = -EINVAL;
		goto error_l;
  }


	if( rhp_ikev2_mobike_pending(tx_vpn) ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_SEND_l_VPN_MOBIKE_RT_CK_PENDING,"xx",pkt,tx_vpn);
		err = RHP_STATUS_IKEV2_MOBIKE_RT_CK_PENDING;
		goto error_l;
	}

	if( rhp_ikev2_mobike_ka_pending(tx_vpn) ){
		// Only trace!
		RHP_TRC_FREQ(0,RHPTRCID_ESP_SEND_l_VPN_MOBIKE_KA_PENDING,"xx",pkt,tx_vpn);
	}


	cur_childsa = tx_vpn->childsa_list_head;
  while( cur_childsa ){

  	RHP_TRC_FREQ(0,RHPTRCID_ESP_SEND_l_CHILDSA,"xxxLd",pkt,tx_vpn,cur_childsa,"CHILDSA_STAT",cur_childsa->state);

  	// Newer one is adopted.
  	if( cur_childsa->state == RHP_CHILDSA_STAT_MATURE 		|| // IKEv2
  			cur_childsa->state == RHP_CHILDSA_STAT_REKEYING 	|| // IKEv2
  			cur_childsa->state == RHP_IPSECSA_STAT_V1_MATURE 	||
  			cur_childsa->state == RHP_IPSECSA_STAT_V1_REKEYING ){

  		break;

  	}else if( cur_childsa->state == RHP_CHILDSA_STAT_LARVAL 					|| // IKEv2
  						cur_childsa->state == RHP_IPSECSA_STAT_V1_1ST_SENT_I 		||
  						cur_childsa->state == RHP_IPSECSA_STAT_V1_WAIT_COMMIT_I ||
  						cur_childsa->state == RHP_IPSECSA_STAT_V1_2ND_SENT_R ){

  		childsa_negotiating++;
  	}

  	cur_childsa = cur_childsa->next_vpn_list;
  }

  if( cur_childsa == NULL ){

  	RHP_TRC_FREQ(0,RHPTRCID_ESP_SEND_l_NO_CHILDSA,"xx",pkt,tx_vpn);

  	if( tx_vpn->ikesa_num && !childsa_negotiating ){

  		_rhp_esp_dyn_create_childsa(tx_vpn,pkt);
  	}

  	if( tx_vpn->rlm ){
    	RHP_LOCK(&(tx_vpn->rlm->lock));
    	tx_vpn->rlm->statistics.esp.tx_esp_no_childsa_err_packets++;
    	RHP_UNLOCK(&(tx_vpn->rlm->lock));
  	}

  	rhp_esp_g_statistics_inc(tx_esp_no_childsa_err_packets);

  	err = -ENOENT;
  	goto error_l;
  }

	RHP_TRC_FREQ(0,RHPTRCID_ESP_SEND_l_CUR_CHILDSA,"xxxddq",pkt,tx_vpn,cur_childsa,cur_childsa->anti_replay,cur_childsa->esn,cur_childsa->tx_seq);


	if( pkt->encap_mode == RHP_VPN_ENCAP_IPIP ){

  	if( tx_vpn->internal_net_info.encap_mode_c != RHP_VPN_ENCAP_IPIP ){
			err = RHP_STATUS_IPSEC_MODE_NOT_MATCHED;
			goto error_l;
  	}

		if( cur_childsa->ipsec_mode != RHP_CHILDSA_MODE_TUNNEL ){
			err = RHP_STATUS_IPSEC_MODE_NOT_MATCHED;
			goto error_l;
		}

	}else if( pkt->encap_mode == RHP_VPN_ENCAP_ETHERIP ){

  	if( tx_vpn->internal_net_info.encap_mode_c != RHP_VPN_ENCAP_ETHERIP ){
			err = RHP_STATUS_IPSEC_MODE_NOT_MATCHED;
			goto error_l;
  	}

		if( cur_childsa->ipsec_mode != RHP_CHILDSA_MODE_TRANSPORT ){
			err = RHP_STATUS_IPSEC_MODE_NOT_MATCHED;
			goto error_l;
		}

	}else if( pkt->encap_mode == RHP_VPN_ENCAP_GRE ){

  	if( tx_vpn->internal_net_info.encap_mode_c != RHP_VPN_ENCAP_GRE ){
			err = RHP_STATUS_IPSEC_MODE_NOT_MATCHED;
			goto error_l;
  	}

		if( cur_childsa->ipsec_mode != RHP_CHILDSA_MODE_TRANSPORT ){
			err = RHP_STATUS_IPSEC_MODE_NOT_MATCHED;
			goto error_l;
		}

	}else{
		RHP_BUG("");
		err = -EINVAL;
		goto error_l;
	}

  spi_outb = cur_childsa->spi_outb;

	if( cur_childsa->anti_replay ){

		if( cur_childsa->esn ){

			if( cur_childsa->tx_seq == 0 ){
				err = RHP_STATUS_DROP_PKT;
		  	RHP_TRC_FREQ(0,RHPTRCID_ESP_SEND_l_ESN_TX_SEQ_ZERO,"xx",pkt,tx_vpn);
		  	goto error_l;
			}

		}else{

			if( (cur_childsa->tx_seq & 0x00000000FFFFFFFFULL) == 0 ){
				err = RHP_STATUS_DROP_PKT;
		  	RHP_TRC_FREQ(0,RHPTRCID_ESP_SEND_l_NON_ESN_TX_SEQ_ZERO,"xx",pkt,tx_vpn);
		  	goto error_l;
			}
		}

	  if( (cur_childsa->state == RHP_CHILDSA_STAT_MATURE ||
	  		 cur_childsa->state == RHP_IPSECSA_STAT_V1_MATURE) &&
	  		((cur_childsa->esn && cur_childsa->tx_seq >= rhp_gcfg_childsa_max_seq_esn) ||
				(!cur_childsa->esn && cur_childsa->tx_seq >= rhp_gcfg_childsa_max_seq_non_esn) ) ){

	  	// Start rekeying!
	  	cur_childsa->timers->quit_lifetime_timer(tx_vpn,cur_childsa);
	  	cur_childsa->timers->start_lifetime_timer(tx_vpn,cur_childsa,0,0); // Exec immediately!
	  }
	}

	{
	 	rhp_ifc_entry* tx_ifc = rhp_ifc_get_by_if_idx(tx_vpn->local.if_info.if_index);  // (***)
	 	if( tx_ifc == NULL ){

	 		RHP_BUG("");
    	err = -EINVAL;
    	goto error_l;

	 	}else{

	 		pkt->tx_ifc = tx_ifc;
		  rhp_ifc_hold(pkt->tx_ifc);

		  rhp_ifc_unhold(tx_ifc);
	 	}
	}

	pkt->esp_tx_spi_outb = spi_outb;
	pkt->esp_tx_vpn_ref = rhp_vpn_hold_ref(tx_vpn);

	RHP_UNLOCK(&(tx_vpn->lock));

	rhp_pkt_hold(pkt);

	err = _rhp_esp_tx_dispatch_packet(pkt);
	if( err ){

		RHP_TRC_FREQ(0,RHPTRCID_ESP_SEND_DISP_PACKET_ERR,"xxE",tx_vpn,pkt,err);

		rhp_vpn_unhold(pkt->esp_tx_vpn_ref);
		pkt->esp_tx_vpn_ref = NULL;
		rhp_pkt_unhold(pkt);

		goto error;
	}

	return 0;

error_l:
	RHP_UNLOCK(&(tx_vpn->lock));
error:

	if( tx_vpn->rlm ){
		RHP_LOCK(&(tx_vpn->rlm->lock));
		tx_vpn->rlm->statistics.esp.tx_esp_err_packets++;
		RHP_UNLOCK(&(tx_vpn->rlm->lock));
	}

	rhp_esp_g_statistics_inc(tx_esp_err_packets);

	return err;
}

/*

 [RFC2401]

Appendix C -- Sequence Space Window Code Example

   This appendix contains a routine that implements a bitmask check for
   a 32 packet window.  It was provided by James Hughes
   (jim_hughes@stortek.com) and Harry Varnis (hgv@anubis.network.com)
   and is intended as an implementation example.  Note that this code
   both checks for a replay and updates the window.  Thus the algorithm,
   as shown, should only be called AFTER the packet has been
   authenticated.  Implementers might wish to consider splitting the
   code to do the check for replays before computing the ICV.  If the
   packet is not a replay, the code would then compute the ICV, (discard
   any bad packets), and if the packet is OK, update the window.

  #include <stdio.h>
  #include <stdlib.h>
  typedef unsigned long u_long;

  enum {
    ReplayWindowSize = 32
  };

  u_long bitmap = 0;        // session state - must be 32 bits
  u_long lastSeq = 0;       // session state

  // Returns 0 if packet disallowed, 1 if packet permitted
  int ChkReplayWindow(u_long seq);

  int ChkReplayWindow(u_long seq)
  {

    u_long diff;

    if (seq == 0) return 0; // first == 0 or wrapped

    if (seq > lastSeq) {  // new larger sequence number

        diff = seq - lastSeq;

        if (diff < ReplayWindowSize) {  // In window
            bitmap <<= diff;
            bitmap |= 1;          // set bit for this packet
        } else bitmap = 1;      // This packet has a "way larger"

        lastSeq = seq;
        return 1;                       // larger is good
    }

    diff = lastSeq - seq;

    if (diff >= ReplayWindowSize) return 0;    // too old or wrapped

    if (bitmap & ((u_long)1 << diff)) return 0;  // already seen

    bitmap |= ((u_long)1 << diff);  // mark as seen

    return 1;                            // out of order but good
  }

  char string_buffer[512];
  #define STRING_BUFFER_SIZE sizeof(string_buffer)

  int main()
  {

    int result;
    u_long last, current, bits;

    printf("Input initial state (bits in hex, last msgnum):\n");

    if (!fgets(string_buffer, STRING_BUFFER_SIZE, stdin)) exit(0);

    sscanf(string_buffer, "%lx %lu", &bits, &last);

    if (last != 0) bits |= 1;

    bitmap = bits;
    lastSeq = last;

    printf("bits:%08lx last:%lu\n", bitmap, lastSeq);
    printf("Input value to test (current):\n");

    while (1) {

        if (!fgets(string_buffer, STRING_BUFFER_SIZE, stdin)) break;

        sscanf(string_buffer, "%lu", &current);
        result = ChkReplayWindow(current);

        printf("%-3s", result ? "OK" : "BAD");
        printf(" bits:%08lx last:%lu\n", bitmap, lastSeq);
    }

    return 0;
  }

*/
static int _rhp_esp_rx_anti_replay_non_esn(rhp_packet* pkt,rhp_proto_esp* esph,rhp_vpn* vpn,rhp_childsa* childsa)
{
  u64 diff;
  u32 w;
	u32 seq,lastseq;
	rhp_crypto_bn* win_mask = childsa->rx_anti_replay.window_mask;

	w = win_mask->get_bits_len(win_mask);
	lastseq = childsa->rx_anti_replay.rx_seq.non_esn.last;
	seq = ntohl(esph->seq);

	RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_ANTI_REPLAY_NON_ESN,"xxxxUuu",pkt,esph,vpn,childsa,esph->seq,lastseq,w);

  if( seq == 0 ){
  	RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_ANTI_REPLAY_NON_ESN_SEQ_ZERO_OR_WRAPPED,"xxx",pkt,esph,childsa);
  	goto reject; // first == 0 or wrapped
  }

  if( seq > lastseq ) {  // new larger sequence number
  	RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_ANTI_REPLAY_NON_ESN_OK_NEW_LARGER_SEQ,"xxx",pkt,esph,childsa);
  	return 0;
  }

  diff = lastseq - seq;

  if( diff >= w ){
  	RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_ANTI_REPLAY_NON_ESN_TOO_OLD_OR_WRAPPED,"xxxdu",pkt,esph,childsa,diff,w);
  	goto reject;    // too old or wrapped
  }

	if( win_mask->bit_is_set(win_mask,diff) ){
  	RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_ANTI_REPLAY_NON_ESN_ALREADY_SEEN,"xxx",pkt,esph,childsa);
  	goto reject;  // already seen
  }

	pkt->esp_seq = (u64)seq;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_ANTI_REPLAY_NON_ESN_OK,"xxx",pkt,esph,childsa);
  return 0; // out of order but good

reject:
	return -EINVAL;
}

/*

 [RFC4303]

Appendix A: Extended (64-bit) Sequence Numbers

A1.  Overview

   This appendix describes an extended sequence number (ESN) scheme for
   use with IPsec (ESP and AH) that employs a 64-bit sequence number,
   but in which only the low-order 32 bits are transmitted as part of
   each packet.  It covers both the window scheme used to detect
   replayed packets and the determination of the high-order bits of the
   sequence number that are used both for replay rejection and for
   computation of the ICV.  It also discusses a mechanism for handling
   loss of synchronization relative to the (not transmitted) high-order
   bits.

A2.  Anti-Replay Window

   The receiver will maintain an anti-replay window of size W.  This
   window will limit how far out of order a packet can be, relative to
   the packet with the highest sequence number that has been
   authenticated so far.  (No requirement is established for minimum or
   recommended sizes for this window, beyond the 32- and 64-packet
   values already established for 32-bit sequence number windows.
   However, it is suggested that an implementer scale these values
   consistent with the interface speed supported by an implementation
   that makes use of the ESN option.  Also, the algorithm described
   below assumes that the window is no greater than 2^31 packets in
   width.)  All 2^32 sequence numbers associated with any fixed value
   for the high-order 32 bits (Seqh) will hereafter be called a sequence
   number subspace.  The following table lists pertinent variables and
   their definitions.

        Var.   Size
        Name  (bits)            Meaning
        ----  ------  ---------------------------
        W        32        Size of window
        T         64        Highest sequence number authenticated so far,
                               upper bound of window
        Tl        32        Lower 32 bits of T
        Th       32        Upper 32 bits of T
        B         64        Lower bound of window
        Bl        32        Lower 32 bits of B
        Bh       32        Upper 32 bits of B
        Seq      64        Sequence Number of received packet
        Seql     32        Lower 32 bits of Seq
        Seqh    32        Upper 32 bits of Seq

   When performing the anti-replay check, or when determining which
   high-order bits to use to authenticate an incoming packet, there are
   two cases:

     + Case A: Tl >= (W - 1). In this case, the window is within one
                              sequence number subspace.  (See Figure 1)
     + Case B: Tl < (W - 1).  In this case, the window spans two
                              sequence number subspaces.  (See Figure 2)

   In the figures below, the bottom line ("----") shows two consecutive
   sequence number subspaces, with zeros indicating the beginning of
   each subspace.  The two shorter lines above it show the higher-order
   bits that apply.  The "====" represents the window.  The "****"
   represents future sequence numbers, i.e., those beyond the current
   highest sequence number authenticated (ThTl).

        Th+1                                       *********
        Th                      =======*****

              --0--------+-----+-----0--------+-----------0--
                                 Bl        Tl                        Bl
                                                                      (Bl+2^32) mod 2^32

                            Figure 1 -- Case A


        Th                                          ====**************
        Th-1                                  ===

              --0-----------------+--0--+--------------+--0--
                                                Bl        Tl                        Bl
                                                                                     (Bl+2^32) mod 2^32

                            Figure 2 -- Case B

A2.1.  Managing and Using the Anti-Replay Window

   The anti-replay window can be thought of as a string of bits where
   `W' defines the length of the string.  W = T - B + 1 and cannot
   exceed 2^32 - 1 in value.  The bottom-most bit corresponds to B and
   the top-most bit corresponds to T, and each sequence number from Bl
   through Tl is represented by a corresponding bit.  The value of the
   bit indicates whether or not a packet with that sequence number has
   been received and authenticated, so that replays can be detected and
   rejected.

   When a packet with a 64-bit sequence number (Seq) greater than T is
   received and validated,

      + B is increased by (Seq - T)
      + (Seq - T) bits are dropped from the low end of the window
      + (Seq - T) bits are added to the high end of the window
      + The top bit is set to indicate that a packet with that sequence
        number has been received and authenticated
      + The new bits between T and the top bit are set to indicate that
        no packets with those sequence numbers have been received yet.
      + T is set to the new sequence number

   In checking for replayed packets,

      + Under Case A: If Seql >= Bl (where Bl = Tl - W + 1) AND Seql <=
        Tl, then check the corresponding bit in the window to see if
        this Seql has already been seen.  If yes, reject the packet.  If
        no, perform integrity check (see Appendix A2.2. below for
        determination of Seqh).

      + Under Case B: If Seql >= Bl (where Bl = Tl - W + 1) OR Seql <=
        Tl, then check the corresponding bit in the window to see if
        this Seql has already been seen.  If yes, reject the packet.  If
        no, perform integrity check (see Appendix A2.2. below for
        determination of Seqh).

A2.2.  Determining the Higher-Order Bits (Seqh) of the Sequence Number

   Because only `Seql' will be transmitted with the packet, the receiver
   must deduce and track the sequence number subspace into which each
   packet falls, i.e., determine the value of Seqh.  The following
   equations define how to select Seqh under "normal" conditions; see
   Section A3 for a discussion of how to recover from extreme packet
   loss.

      + Under Case A (Figure 1):
        If Seql >= Bl (where Bl = Tl - W + 1), then Seqh = Th
        If Seql <  Bl (where Bl = Tl - W + 1), then Seqh = Th + 1

      + Under Case B (Figure 2):
        If Seql >= Bl (where Bl = Tl - W + 1), then Seqh = Th - 1
        If Seql <  Bl (where Bl = Tl - W + 1), then Seqh = Th

A2.3.  Pseudo-Code Example

   The following pseudo-code illustrates the above algorithms for anti-
   replay and integrity checks.  The values for `Seql', `Tl', `Th' and
   `W' are 32-bit unsigned integers.  Arithmetic is mod 2^32.

        If (Tl >= W - 1)                            Case A
            If (Seql >= Tl - W + 1)
                Seqh = Th
                If (Seql <= Tl)
                    If (pass replay check)
                        If (pass integrity check)
                            Set bit corresponding to Seql
                            Pass the packet on
                        Else reject packet
                    Else reject packet
                Else
                    If (pass integrity check)
                        Tl = Seql (shift bits)
                        Set bit corresponding to Seql
                        Pass the packet on
                    Else reject packet
            Else
                Seqh = Th + 1
                If (pass integrity check)
                    Tl = Seql (shift bits)
                    Th = Th + 1
                    Set bit corresponding to Seql
                    Pass the packet on
                Else reject packet
        Else                                            Case B
            If (Seql >= Tl - W + 1)
                Seqh = Th - 1
                If (pass replay check)
                    If (pass integrity check)
                        Set the bit corresponding to Seql
                        Pass packet on
                    Else reject packet
                Else reject packet
            Else
                Seqh = Th
                If (Seql <= Tl)
                    If (pass replay check)
                        If (pass integrity check)
                            Set the bit corresponding to Seql
                            Pass packet on
                        Else reject packet
                    Else reject packet
                Else
                    If (pass integrity check)
                        Tl = Seql (shift bits)
                        Set the bit corresponding to Seql
                        Pass packet on
                    Else reject packet

A3.  Handling Loss of Synchronization due to Significant Packet Loss

   If there is an undetected packet loss of 2^32 or more consecutive
   packets on a single SA, then the transmitter and receiver will lose
   synchronization of the high-order bits, i.e., the equations in
   Section A2.2. will fail to yield the correct value.  Unless this
   problem is detected and addressed, subsequent packets on this SA will
   fail authentication checks and be discarded.  The following procedure
   SHOULD be implemented by any IPsec (ESP or AH) implementation that
   supports the ESN option.

   Note that this sort of extended traffic loss is likely to be detected
   at higher layers in most cases, before IPsec would have to invoke the
   sort of re-synchronization mechanism described in A3.1 and A3.2. If
   any significant fraction of the traffic on the SA in question is TCP,
   the source would fail to receive ACKs and would stop sending long
   before 2^32 packets had been lost.  Also, for any bi-directional
   application, even ones operating above UDP, such an extended outage
   would likely result in triggering some form of timeout.  However, a
   unidirectional application, operating over UDP, might lack feedback
   that would cause automatic detection of a loss of this magnitude,
   hence the motivation to develop a recovery method for this case.
   Note that the above observations apply to SAs between security
   gateways, or between hosts, or between host and security gateways.

   The solution we've chosen was selected to:

     + minimize the impact on normal traffic processing

     + avoid creating an opportunity for a new denial of service attack
       such as might occur by allowing an attacker to force diversion of
       resources to a re-synchronization process

     + limit the recovery mechanism to the receiver -- because anti-
       replay is a service only for the receiver, and the transmitter
       generally is not aware of whether the receiver is using sequence
       numbers in support of this optional service, it is preferable for
       recovery mechanisms to be local to the receiver.  This also
       allows for backward compatibility.

A3.1.  Triggering Re-synchronization

   For each SA, the receiver records the number of consecutive packets
   that fail authentication.  This count is used to trigger the re-
   synchronization process, which should be performed in the background
   or using a separate processor.  Receipt of a valid packet on the SA
   resets the counter to zero.  The value used to trigger the re-
   synchronization process is a local parameter.  There is no
   requirement to support distinct trigger values for different SAs,
   although an implementer may choose to do so.

A3.2.  Re-synchronization Process

   When the above trigger point is reached, a "bad" packet is selected
   for which authentication is retried using successively larger values
   for the upper half of the sequence number (Seqh).  These values are
   generated by incrementing by one for each retry.  The number of
   retries should be limited, in case this is a packet from the "past"
   or a bogus packet.  The limit value is a local parameter.  (Because
   the Seqh value is implicitly placed after the ESP (or AH) payload, it
   may be possible to optimize this procedure by executing the integrity
   algorithm over the packet up to the endpoint of the payload, then
   compute different candidate ICVs by varying the value of Seqh.)
   Successful authentication of a packet via this procedure resets the
   consecutive failure count and sets the value of T to that of the
   received packet.

   This solution requires support only on the part of the receiver,
   thereby allowing for backward compatibility.  Also, because re-
   synchronization efforts would either occur in the background or
   utilize an additional processor, this solution does not impact
   traffic processing and a denial of service attack cannot divert
   resources away from traffic processing.

 */

//
// TODO : Re-sync seq no Process support. See above A3.2.
//
// TODO : RFC 6479
//
static int _rhp_esp_rx_anti_replay_esn(rhp_packet* pkt,rhp_proto_esp* esph,rhp_vpn* vpn,rhp_childsa* childsa)
{
	u32 tl,bl,seql,th;
	u32 w;
	u64 diff;
	rhp_crypto_bn* win_mask = childsa->rx_anti_replay.window_mask;

	w = win_mask->get_bits_len(win_mask);
	tl = (u32)(childsa->rx_anti_replay.rx_seq.esn.t & 0x00000000FFFFFFFFULL);
	th = (u32)((childsa->rx_anti_replay.rx_seq.esn.t >> 32) & 0x00000000FFFFFFFFULL);
	bl = (u32)(childsa->rx_anti_replay.rx_seq.esn.b & 0x00000000FFFFFFFFULL);
	seql = ntohl(esph->seq);

	RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_ANTI_REPLAY_ESN,"xxxxuuuuuqq",pkt,esph,vpn,childsa,w,tl,th,bl,seql,childsa->rx_anti_replay.rx_seq.esn.t,childsa->rx_anti_replay.rx_seq.esn.b);

	if( (th == 0) ||  (tl >= (w-1)) ){ // Case A

		if( seql >= bl ){

			if( seql <= tl ){

				diff = seql - bl;

				if( !win_mask->bit_is_set(win_mask,diff) ){
					RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_ANTI_REPLAY_ESN_CASE_A_NEW_PKT_IN_WIN,"xxxu",pkt,esph,childsa,diff);
				}else{
					RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_ANTI_REPLAY_ESN_CASE_A_ALREADY_SEEN,"xxxu",pkt,esph,childsa,diff);
					goto reject;
				}

			}else{

				RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_ANTI_REPLAY_ESN_CASE_A_OVER,"xxx",pkt,esph,childsa);
			}

			pkt->esp_seq = ((((u64)th) << 32) & 0xFFFFFFFF00000000ULL) | ((((u64)seql) << 32) & 0x00000000FFFFFFFFULL);

		}else{

			RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_ANTI_REPLAY_ESN_CASE_A_WRAPPED,"xxx",pkt,esph,childsa);

			pkt->esp_seq = ((((u64)(th + 1)) << 32) & 0xFFFFFFFF00000000ULL) | ((((u64)seql) << 32) & 0x00000000FFFFFFFFULL);
		}

	}else{ // Case B

		if( seql >= bl ){

			diff = seql - bl;

			if( !win_mask->bit_is_set(win_mask,diff) ){
				RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_ANTI_REPLAY_ESN_CASE_B_NEW_PKT_IN_WIN,"xxxu",pkt,esph,childsa,diff);
			}else{
				RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_ANTI_REPLAY_ESN_CASE_B_ALREADY_SEEN,"xxxu",pkt,esph,childsa,diff);
				goto reject;
			}

			pkt->esp_seq = ((((u64)(th - 1)) << 32) & 0xFFFFFFFF00000000ULL) | ((((u64)seql) << 32) & 0x00000000FFFFFFFFULL);

		}else{

			if( seql < tl ){

				diff = seql + ((u32)0xFFFFFFFF) - bl + 1;

				if( !win_mask->bit_is_set(win_mask,diff) ){
					RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_ANTI_REPLAY_ESN_CASE_B_OVER_NEW_PKT_IN_WIN,"xxxu",pkt,esph,childsa,diff);
				}else{
					RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_ANTI_REPLAY_ESN_CASE_B_OVER_ALREADY_SEEN,"xxxu",pkt,esph,childsa,diff);
					goto reject;
				}

			}else{

				RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_ANTI_REPLAY_ESN_CASE_B_OVER_WRAPPED,"xxx",pkt,esph,childsa);
			}

			pkt->esp_seq = ((((u64)th) << 32) & 0xFFFFFFFF00000000ULL) | ((((u64)seql) << 32) & 0x00000000FFFFFFFFULL);
		}
	}

	RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_ANTI_REPLAY_ESN_OK,"xxxuuuuq",pkt,esph,childsa,w,tl,bl,seql,pkt->esp_seq);
	return 0;

reject:
	return -EINVAL;
}

static int _rhp_esp_rx_anti_replay(rhp_packet* pkt,rhp_proto_esp* esph,rhp_vpn* vpn,rhp_childsa* childsa)
{
	int err = -EINVAL;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_ANTI_REPLAY,"xxxxd",pkt,esph,vpn,childsa,childsa->anti_replay);

	if( !childsa->anti_replay ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_ANTI_REPLAY_DISABLED,"xxx",pkt,esph,childsa);
		return 0;
	}

	if( !childsa->esn ){
		err = _rhp_esp_rx_anti_replay_non_esn(pkt,esph,vpn,childsa);
	}else{
		err = _rhp_esp_rx_anti_replay_esn(pkt,esph,vpn,childsa);
	}

	if( pkt->esp_seq <= childsa->rx_anti_replay.out_of_order_seq_last ){

		if( childsa->out_of_order_drop ){
			err = -EINVAL;
		}

	}else{

		childsa->rx_anti_replay.out_of_order_seq_last = pkt->esp_seq;
	}

	RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_ANTI_REPLAY_RTRN,"xxxE",pkt,esph,childsa,err);
	return err;
}

static int _rhp_esp_anti_replay_win_shift(rhp_crypto_bn* win_mask,u32 win_size,u64 diff)
{
	if( diff > (u64)win_size ){
		diff = (u64)win_size;
	}

	return win_mask->right_shift(win_mask,diff);
}

static int _rhp_esp_rx_update_anti_replay_non_esn(rhp_vpn* vpn,rhp_childsa* childsa,u32 rx_seq)
{
	int err = -EINVAL;
  u64 diff;
  u32 w;
	u32 lastseq;
	rhp_crypto_bn* win_mask = childsa->rx_anti_replay.window_mask;

	w = win_mask->get_bits_len(win_mask);
	lastseq = childsa->rx_anti_replay.rx_seq.non_esn.last;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_UPDATE_ANTI_REPLAY_NON_ESN,"xxuuu",vpn,childsa,rx_seq,lastseq,w);

  if( rx_seq > lastseq ){

  	RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_UPDATE_ANTI_REPLAY_NON_ESN_NEW_PKT,"xx",vpn,childsa);

    diff = rx_seq - lastseq;

		if( _rhp_esp_anti_replay_win_shift(win_mask,w,diff) ){
			err = -EINVAL;
			RHP_BUG("");
 			goto error;
		}

		if( win_mask->set_bit(win_mask,(w-1)) ){
			err = -EINVAL;
			RHP_BUG("");
			goto error;
		}

		childsa->rx_anti_replay.rx_seq.non_esn.last = rx_seq;

  }else{

  	RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_UPDATE_ANTI_REPLAY_NON_ESN_PKT_IN_WIN,"xx",vpn,childsa);

		diff = lastseq - rx_seq;

		if( win_mask->set_bit(win_mask,(w-1)) ){
			err = -EINVAL;
			RHP_BUG("");
			goto error;
		}
  }

	RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_UPDATE_ANTI_REPLAY_NON_ESN_RTNR,"xxuu",vpn,childsa,rx_seq,lastseq);
  return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_UPDATE_ANTI_REPLAY_NON_ESN_ERR,"xxE",vpn,childsa,err);
	return err;
}

static int _rhp_esp_rx_update_anti_replay_esn(rhp_vpn* vpn,rhp_childsa* childsa,u32 rx_seq)
{
	int err = -EINVAL;
	u32 tl,th,bl,bh,seql,seqh;
	u32 w;
	u64 diff;
	rhp_crypto_bn* win_mask = childsa->rx_anti_replay.window_mask;

	w = win_mask->get_bits_len(win_mask);
	tl = (u32)(childsa->rx_anti_replay.rx_seq.esn.t & 0x00000000FFFFFFFFULL);
	th = (u32)((childsa->rx_anti_replay.rx_seq.esn.t >> 32) & 0x00000000FFFFFFFFULL);
	bl = (u32)(childsa->rx_anti_replay.rx_seq.esn.b & 0x00000000FFFFFFFFULL);
	bh = (u32)((childsa->rx_anti_replay.rx_seq.esn.b >> 32) & 0x00000000FFFFFFFFULL);
	seql = rx_seq;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_UPDATE_ANTI_REPLAY_ESN,"xxuuuuuuuqq",vpn,childsa,rx_seq,w,tl,th,bl,bh,seql,childsa->rx_anti_replay.rx_seq.esn.t,childsa->rx_anti_replay.rx_seq.esn.b);

  if( (th == 0) ||  (tl >= (w - 1)) ){ // Case A

  	if( seql >= bl ){

			seqh = th;

			if( seql <= tl ){

				diff = seql - bl;

				if( win_mask->set_bit(win_mask,diff) ){
					err = -EINVAL;
					RHP_BUG("");
					goto error;
				}

				RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_UPDATE_ANTI_REPLAY_ESN_CASE_A_PKT_IN_WIN,"xxuuuuuuud",vpn,childsa,rx_seq,w,tl,th,bl,bh,seql,diff);

			}else{

				int win_idx;
				childsa->rx_anti_replay.rx_seq.esn.t = ( (((u64)seqh) << 32) & 0xFFFFFFFF00000000ULL)  |  (((u64)seql) & 0x00000000FFFFFFFFULL);

				diff = seql - tl;

				if( childsa->rx_anti_replay.rx_seq.esn.t > w ){

					if( _rhp_esp_anti_replay_win_shift(win_mask,w,diff) ){
						err = -EINVAL;
						RHP_BUG("");
						goto error;
					}

					childsa->rx_anti_replay.rx_seq.esn.b = (childsa->rx_anti_replay.rx_seq.esn.t - w) + 1;
					win_idx = (w-1);

				}else{

					win_idx = (int)(childsa->rx_anti_replay.rx_seq.esn.t) - 1;
				}

				if( win_mask->set_bit(win_mask,win_idx) ){
					err = -EINVAL;
					RHP_BUG("");
					goto error;
				}

				RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_UPDATE_ANTI_REPLAY_ESN_CASE_A_NEW_PKT,"xxuuuuuuuudqq",vpn,childsa,rx_seq,w,tl,th,bl,bh,seql,diff,win_idx,childsa->rx_anti_replay.rx_seq.esn.b,childsa->rx_anti_replay.rx_seq.esn.t);
			}

		}else{

			u64 seq;

			seqh = th + 1;
			seq = ( (((u64)bh) << 32) & 0xFFFFFFFF00000000ULL)  |  (((u64)bl) & 0x00000000FFFFFFFFULL);

			tl = seql;
			th = th + 1;

			diff = seq - childsa->rx_anti_replay.rx_seq.esn.t;

			childsa->rx_anti_replay.rx_seq.esn.t = ( (((u64)th) << 32) & 0xFFFFFFFF00000000ULL)  |  (((u64)tl) & 0x00000000FFFFFFFFULL);
			childsa->rx_anti_replay.rx_seq.esn.b = (childsa->rx_anti_replay.rx_seq.esn.t - w) + 1;

			if( _rhp_esp_anti_replay_win_shift(win_mask,w,diff) ){
				err = -EINVAL;
				RHP_BUG("");
				goto error;
			}

			if( win_mask->set_bit(win_mask,(w-1)) ){
				err = -EINVAL;
				RHP_BUG("");
				goto error;
			}

			RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_UPDATE_ANTI_REPLAY_ESN_CASE_A_WRAPPED,"xxuuuuuuuuqq",vpn,childsa,rx_seq,w,tl,th,bl,bh,seql,diff,childsa->rx_anti_replay.rx_seq.esn.b,childsa->rx_anti_replay.rx_seq.esn.t);
		}

  }else{ // Case B

    if( seql >= bl ){

			diff = seql - bl;

			if( win_mask->set_bit(win_mask,diff) ){
				err = -EINVAL;
				RHP_BUG("");
				goto error;
			}

			RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_UPDATE_ANTI_REPLAY_ESN_CASE_B_IN_WIN,"xxuuuuuuuuqq",vpn,childsa,rx_seq,w,tl,th,bl,bh,seql,diff,childsa->rx_anti_replay.rx_seq.esn.b,childsa->rx_anti_replay.rx_seq.esn.t);

    }else{

    	seqh = th;

    	if( seql <= tl ){

				diff = seql + ((u32)0xFFFFFFFF) - bl + 1;

				if( win_mask->set_bit(win_mask,diff) ){
					err = -EINVAL;
					RHP_BUG("");
					goto error;
				}

				RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_UPDATE_ANTI_REPLAY_ESN_CASE_B_WRAPPED_IN_WIN,"xxuuuuuuuuqq",vpn,childsa,rx_seq,w,tl,th,bl,bh,seql,diff,childsa->rx_anti_replay.rx_seq.esn.b,childsa->rx_anti_replay.rx_seq.esn.t);

    	}else{

				childsa->rx_anti_replay.rx_seq.esn.t = ( (((u64)seqh) << 32) & 0xFFFFFFFF00000000ULL)  |  (((u64)seql) & 0x00000000FFFFFFFFULL);
				childsa->rx_anti_replay.rx_seq.esn.b = (childsa->rx_anti_replay.rx_seq.esn.t - w) + 1;

				diff = seql - tl;
				if( _rhp_esp_anti_replay_win_shift(win_mask,w,diff) ){
					err = -EINVAL;
					RHP_BUG("");
					goto error;
				}

				if( win_mask->set_bit(win_mask,(w-1)) ){
					err = -EINVAL;
					RHP_BUG("");
					goto error;
				}

				RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_UPDATE_ANTI_REPLAY_ESN_CASE_B_WRAPPED_NEW_PKT,"xxuuuuuuuuqq",vpn,childsa,rx_seq,w,tl,th,bl,bh,seql,diff,childsa->rx_anti_replay.rx_seq.esn.b,childsa->rx_anti_replay.rx_seq.esn.t);
    	}
    }
  }

	RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_UPDATE_ANTI_REPLAY_ESN_RTRN,"xxqq",vpn,childsa,childsa->rx_anti_replay.rx_seq.esn.t,childsa->rx_anti_replay.rx_seq.esn.b);
  return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_UPDATE_ANTI_REPLAY_ESN_ERR,"xxE",vpn,childsa,err);
	return err;
}

int rhp_esp_rx_update_anti_replay(rhp_vpn* vpn,rhp_childsa* childsa,u32 rx_seq)
{
	int err = -EINVAL;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_UPDATE_ANTI_REPLAY,"xxud",vpn,childsa,rx_seq,childsa->anti_replay);

	if( !childsa->anti_replay ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_UPDATE_ANTI_REPLAY_DISABLED,"xx",vpn,childsa);
		return 0;
	}

	if( !childsa->esn ){
		err = _rhp_esp_rx_update_anti_replay_non_esn(vpn,childsa,rx_seq);
	}else{
		err = _rhp_esp_rx_update_anti_replay_esn(vpn,childsa,rx_seq);
	}

	RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_UPDATE_ANTI_REPLAY_RTRN,"xxE",vpn,childsa,err);
	return err;
}

u32 rhp_esp_rx_get_esn_seqh(rhp_vpn* vpn,rhp_childsa* childsa,u32 rx_seq)
{
	u32 seqh,w,tl,th,bl;
	rhp_crypto_bn* win_mask = childsa->rx_anti_replay.window_mask;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_GET_ESN_SEQH,"xxudd",vpn,childsa,rx_seq,childsa->anti_replay,childsa->esn);

	if( !childsa->anti_replay ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_GET_ESN_SEQH_ANTI_REPLAY_DISABLED,"xx",vpn,childsa);
		return 0;
	}

	if( !childsa->esn ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_GET_ESN_SEQH_ESN_DISABLED,"xx",vpn,childsa);
		return 0;
	}

	w = win_mask->get_bits_len(win_mask);
	tl = (u32)(childsa->rx_anti_replay.rx_seq.esn.t & 0x00000000FFFFFFFFULL);
	th = (u32)((childsa->rx_anti_replay.rx_seq.esn.t >> 32) & 0x00000000FFFFFFFFULL);
	bl = (u32)(childsa->rx_anti_replay.rx_seq.esn.b & 0x00000000FFFFFFFFULL);

	RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_GET_ESN_SEQH_CHILDSA_VALS,"xxuqq",vpn,childsa,w,childsa->rx_anti_replay.rx_seq.esn.t,childsa->rx_anti_replay.rx_seq.esn.b);

  if( tl >= (w - 1) ){ // Case A

  	if( rx_seq >= bl ){
  		seqh = th;
  		RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_GET_ESN_SEQH_CASE_A_IN_WIN,"xxuuuu",vpn,childsa,w,tl,th,bl,seqh);
  	}else{
  		seqh = th + 1;
  		RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_GET_ESN_SEQH_CASE_A_WRAPPED,"xxuuuu",vpn,childsa,w,tl,th,bl,seqh);
  	}

  }else{	// Case B

  	if( rx_seq >= bl && th ){
  		seqh = th - 1;
  		RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_GET_ESN_SEQH_CASE_B_WRAPPED,"xxuuuu",vpn,childsa,w,tl,th,bl,seqh);
		}else{
      seqh = th;
  		RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_GET_ESN_SEQH_CASE_B_NEW,"xxuuuu",vpn,childsa,w,tl,th,bl,seqh);
		}
  }

	RHP_TRC_FREQ(0,RHPTRCID_ESP_RX_GET_ESN_SEQH_RTRN,"xxu",vpn,childsa,seqh);
  return seqh;
}


struct _rhp_esp_rx_impl_cb {
	int src_changed;
	int addr_family;
	u8 src_addr[16];
	u16 src_port;
	u16 dst_port;
};
typedef struct _rhp_esp_rx_impl_cb	rhp_esp_rx_impl_cb;

int rhp_esp_recv(rhp_packet* pkt)
{
	int err = -EINVAL;
	union {
		rhp_proto_ip_v4* v4;
		rhp_proto_ip_v6* v6;
		u8* raw;
	} iph;
	rhp_proto_udp* udph = NULL;
	rhp_proto_esp* esph = NULL;
	u32 spi_inb = 0;
	rhp_vpn* vpn = NULL;
	rhp_vpn_ref* vpn_ref = NULL;
	rhp_childsa* inb_childsa = NULL;
	rhp_vpn_realm* rlm = NULL;
	int pld_len = 0;
	u8 next_header = (u8)-1;
	int addr_family;
	rhp_esp_rx_impl_cb* pend_ctx = NULL;
	int rx_udp_encap_from_remote_peer_p;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV,"xLd",pkt,"PKT",pkt->type);

	pend_ctx = (rhp_esp_rx_impl_cb*)_rhp_malloc(sizeof(rhp_esp_rx_impl_cb));
	if(pend_ctx == NULL){
		err = -ENOMEM;
		goto drop;
	}
	memset(pend_ctx,0,sizeof(rhp_esp_rx_impl_cb));

	iph.raw = pkt->l3.raw;

	if( pkt->type == RHP_PKT_IPV4_ESP_NAT_T ){

		udph = pkt->l4.udph;
		esph = pkt->app.esph;

		pld_len = ntohs(iph.v4->total_len) - (iph.v4->ihl << 2) - sizeof(rhp_proto_udp);
		addr_family = AF_INET;

	}else	if( pkt->type == RHP_PKT_IPV6_ESP_NAT_T ){

		udph = pkt->l4.udph;
		esph = pkt->app.esph;

		pld_len = ntohs(iph.v6->payload_len) - sizeof(rhp_proto_udp);
		addr_family = AF_INET6;

	}else if( pkt->type == RHP_PKT_IPV4_ESP ){

		esph = pkt->app.esph;
		pld_len = ntohs(iph.v4->total_len) - (iph.v4->ihl << 2);
		addr_family = AF_INET;

	}else if( pkt->type == RHP_PKT_IPV6_ESP ){

		esph = pkt->app.esph;
		pld_len = ntohs(iph.v6->payload_len);
		addr_family = AF_INET6;

	}else{
		RHP_BUG("");
		goto drop;
	}

	if( pld_len < (int)sizeof(rhp_proto_esp) ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_BAD_PLD_LEN,"xdd",pkt,pld_len,(int)sizeof(rhp_proto_esp));
		err = RHP_STATUS_BAD_PACKET;
		goto drop;
	}

	spi_inb = esph->spi;
	pkt->esp_rx_spi_inb = spi_inb;

	vpn_ref = rhp_vpn_inb_childsa_get(spi_inb);
	vpn = RHP_VPN_REF(vpn_ref);
	if( vpn == NULL ){

		err = -ENOENT;
		RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_NO_CHILDSA,"xH",pkt,spi_inb);

		rhp_esp_g_statistics_inc(rx_esp_no_vpn_err_packets);

		goto drop;
	}

	RHP_LOCK(&(vpn->lock));

	if( !_rhp_atomic_read(&(vpn->is_active)) ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_VPN_NOT_ACTIVE,"xxH",pkt,vpn,spi_inb);
		goto drop_l;
  }

	rx_udp_encap_from_remote_peer_p = vpn->nat_t_info.rx_udp_encap_from_remote_peer;

	{

	  //
	  // TODO: Supporting addr change like IPv4 NAT => IPv6 NAT and IPv6 NAT => IPv4 NAT.
	  //

		if( vpn->local.if_info.addr_family != addr_family ){

			rhp_esp_g_statistics_inc(rx_esp_src_changed_packets);

			RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_VPN_ADDR_FAMILY_NOT_MATCHED,"xxHLdLd",pkt,vpn,spi_inb,"AF",vpn->local.if_info.addr_family,"AF",addr_family);
			goto drop_l;
		}

		if( vpn->peer_addr.addr_family != addr_family ){

			rhp_esp_g_statistics_inc(rx_esp_src_changed_packets);

			RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_VPN_ADDR_FAMILY_NOT_MATCHED_2,"xxHLdLd",pkt,vpn,spi_inb,"AF",addr_family,"AF",vpn->peer_addr.addr_family);
			goto drop_l;
		}
	}


	rlm = vpn->rlm;
	if( rlm == NULL ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_RLM_NOT_ACTIVE,"xxH",pkt,vpn,spi_inb);
		goto drop_l;
	}
	rhp_realm_hold(rlm);


  //
  // TODO: Supporting addr change like IPv4 NAT => IPv6 NAT and IPv6 NAT => IPv4 NAT.
  //
	if( (addr_family == vpn->peer_addr.addr_family) &&
			((addr_family == AF_INET && iph.v4->src_addr != vpn->peer_addr.addr.v4) ||
			 (addr_family == AF_INET6 && !rhp_ipv6_is_same_addr(iph.v6->src_addr,vpn->peer_addr.addr.v6)) ||
			 (udph && udph->src_port != vpn->peer_addr.port)) ){

		rhp_esp_g_statistics_inc(rx_esp_src_changed_packets);

		if( udph ){

			if( !rhp_gcfg_nat_dont_change_addr_port_by_esp &&
					!vpn->exec_mobike ){

				pend_ctx->src_changed = 1;
				pend_ctx->addr_family = addr_family;
				pend_ctx->src_port = pkt->l4.udph->src_port;
				pend_ctx->dst_port = pkt->l4.udph->dst_port;

				if( addr_family == AF_INET ){

					RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_SRC_CHANGED,"xxH4W4W",pkt,vpn,spi_inb,iph.v4->src_addr,udph->src_port,vpn->peer_addr.addr.v4,vpn->peer_addr.port);

					*((u32*)pend_ctx->src_addr) = pkt->l3.iph_v4->src_addr;

				}else if( addr_family == AF_INET6 ){

					RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_SRC_CHANGED_V6,"xxH6W6W",pkt,vpn,spi_inb,iph.v6->src_addr,udph->src_port,vpn->peer_addr.addr.v6,vpn->peer_addr.port);

					memcpy(pend_ctx->src_addr,pkt->l3.iph_v6->src_addr,16);
				}

			}else{

				if( addr_family == AF_INET ){
					RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_SRC_CHANGED_DROP1,"xxH4W4W",pkt,vpn,spi_inb,iph.v4->src_addr,udph->src_port,vpn->peer_addr.addr.v4,vpn->peer_addr.port);
				}else if( addr_family == AF_INET ){
					RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_SRC_CHANGED_DROP1_V6,"xxH6W6W",pkt,vpn,spi_inb,iph.v6->src_addr,udph->src_port,vpn->peer_addr.addr.v6,vpn->peer_addr.port);
				}

				goto drop_l;
			}

		}else{

			if( addr_family == AF_INET ){
				RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_SRC_CHANGED_DROP2,"xxH44",pkt,vpn,spi_inb,iph.v4->src_addr,vpn->peer_addr.addr.v4);
			}else if( addr_family == AF_INET6 ){
				RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_SRC_CHANGED_DROP2_V6,"xxH44",pkt,vpn,spi_inb,iph.v6->src_addr,vpn->peer_addr.addr.v6);
			}

			goto drop_l;
		}
	}


	if( pkt->type == RHP_PKT_IPV4_ESP_NAT_T ||
			pkt->type == RHP_PKT_IPV6_ESP_NAT_T ){

		if( !vpn->nat_t_info.exec_nat_t && rhp_gcfg_esp_rx_udp_encap_only_when_exec_nat_t ){

			RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_NAT_T_NOT_ACTIVATED,"xxH",pkt,vpn,spi_inb);

			rhp_esp_g_statistics_inc(rx_esp_invalid_nat_t_packets);

			goto drop_l;
		}
	}


	pkt->esp_rx_vpn_ref = rhp_vpn_hold_ref(vpn);

	inb_childsa = vpn->childsa_get(vpn,RHP_DIR_INBOUND,spi_inb);
  if( inb_childsa == NULL ){

  	RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_NO_CHILD_SA,"xxH",pkt,vpn,spi_inb);

		RHP_LOCK(&(rlm->lock));
		rlm->statistics.esp.rx_esp_no_childsa_err_packets++;
		RHP_UNLOCK(&(rlm->lock));

		rhp_esp_g_statistics_inc(rx_esp_no_childsa_err_packets);

		goto drop_l;
  }

	RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_FOUND_CHILD_SA,"xxHx",pkt,vpn,spi_inb,inb_childsa);


	if( inb_childsa->anti_replay ){

		err =  _rhp_esp_rx_anti_replay(pkt,esph,vpn,inb_childsa);
		if( err ){
			RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_RX_ANTI_REPLAY_FAILED,"xxHxE",pkt,vpn,spi_inb,inb_childsa,err);

			RHP_LOCK(&(rlm->lock));
			rlm->statistics.esp.rx_esp_anti_replay_err_packets++;
			RHP_UNLOCK(&(rlm->lock));

			rhp_esp_g_statistics_inc(rx_esp_anti_replay_err_packets);

			goto drop_l;
		}
	}

	RHP_UNLOCK(&(vpn->lock));


	rhp_pkt_hold(pkt);

	err = rhp_esp_impl_dec_packet(pkt,vpn,rlm,spi_inb,&next_header,(void*)pend_ctx);
	if( err == RHP_STATUS_ESP_IMPL_PENDING ){

		//
		// Pending... ESP impl will call rhp_esp_recv_callback() later...
		//

		//
		// rhp_esp_impl_dec_packet() must call rhp_pkt_hold() for the pending the packet.
		//

		RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_IMPL_INBOUND_PACKET_PENDING,"xxHx",pkt,vpn,spi_inb,inb_childsa);

		rhp_pkt_pending(pkt);
		pend_ctx = NULL; // This will be freed later.

	}else if( err ){

		RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_IMPL_INBOUND_PACKET_ERR,"xxHxE",pkt,vpn,spi_inb,inb_childsa,err);

		rhp_pkt_unhold(pkt);

		switch(err){

		case RHP_STATUS_SELECTOR_NOT_MATCHED:
			if( rlm ){
				RHP_LOCK(&(rlm->lock));
				rlm->statistics.esp.rx_esp_ts_err_packets++;
				RHP_UNLOCK(&(rlm->lock));
			}

			rhp_esp_g_statistics_inc(rx_esp_ts_err_packets);
			break;

		case RHP_STATUS_ESP_DECRYPT_ERR:
			if( rlm ){
				RHP_LOCK(&(rlm->lock));
				rlm->statistics.esp.rx_esp_decrypt_err_packets++;
				RHP_UNLOCK(&(rlm->lock));
			}

			rhp_esp_g_statistics_inc(rx_esp_decrypt_err_packets);
			break;

		case RHP_STATUS_ESP_INTEG_ERR:
			if( rlm ){
				RHP_LOCK(&(rlm->lock));
				rlm->statistics.esp.rx_esp_integ_err_packets++;
				RHP_UNLOCK(&(rlm->lock));
			}

			rhp_esp_g_statistics_inc(rx_esp_integ_err_packets);
			break;

		case RHP_STATUS_ESP_INVALID_PKT:
			if( rlm ){
				RHP_LOCK(&(rlm->lock));
				rlm->statistics.esp.rx_esp_invalid_packets++;
				RHP_UNLOCK(&(rlm->lock));
			}

			rhp_esp_g_statistics_inc(rx_esp_invalid_packets);
			break;

		case RHP_STATUS_ESP_NO_CHILDSA:
			if( rlm ){
				RHP_LOCK(&(rlm->lock));
				rlm->statistics.esp.rx_esp_no_childsa_err_packets++;
				RHP_UNLOCK(&(rlm->lock));
			}

			rhp_esp_g_statistics_inc(rx_esp_no_childsa_err_packets);
			break;

		case RHP_STATUS_ESP_RX_DUMMY_PKT:
		default:
			break;
		}

		goto drop;

	}else{

		// OK

		RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_IMPL_INBOUND_PACKET_OK,"xxHxb",pkt,vpn,spi_inb,inb_childsa,next_header);

		if( !rx_udp_encap_from_remote_peer_p && vpn->nat_t_info.rx_udp_encap_from_remote_peer ){
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_FIRST_UDP_ENCAP_ESP_PACKET,"V",vpn);
		}

		rhp_pkt_unhold(pkt);

		if( pend_ctx->src_changed ){

			RHP_LOCK(&(vpn->lock));
			{
				if( rlm ){
					RHP_LOCK(&(rlm->lock));
					rlm->statistics.esp.rx_esp_src_changed_packets++;
					RHP_UNLOCK(&(rlm->lock));
				}

				err = rhp_ikev2_nat_t_change_peer_addr_port(vpn,pend_ctx->addr_family,
						pend_ctx->src_addr,pend_ctx->src_port,pend_ctx->dst_port,0);
				if( err ){
					RHP_UNLOCK(&(vpn->lock));
					goto drop;
				}
			}
			RHP_UNLOCK(&(vpn->lock));
		}


		if( rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_ESP_PLAIN] &&
				(!rhp_packet_capture_realm_id || (vpn && rhp_packet_capture_realm_id == vpn->vpn_realm_id)) ){

			_rhp_esp_rx_pcap_write(vpn,pkt,next_header);
		}


		if( next_header == RHP_PROTO_IP_ETHERIP ){

			err = rhp_eoip_recv(pkt,vpn);
			if( err ){
				RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_EOIP_RECV_FAILED,"xxHxE",pkt,vpn,spi_inb,inb_childsa,err);
				goto drop;
			}

		}else if( next_header == RHP_PROTO_IP_IP || next_header == RHP_PROTO_IP_IPV6 ){

			err = rhp_ip_bridge_recv(pkt,vpn,next_header);
			if( err ){
				RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_IP_FWD_PKT_FROM_VPN_FAILED,"xxHxE",pkt,vpn,spi_inb,inb_childsa,err);
				goto drop;
			}

		}else if( next_header == RHP_PROTO_IP_GRE ){

			err = rhp_gre_recv(pkt,vpn);
			if( err ){
				RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_GRE_RECV_FAILED,"xxHxE",pkt,vpn,spi_inb,inb_childsa,err);
				goto drop;
			}

		}else if( next_header == RHP_PROTO_IP_NO_NEXT_HDR ){

			// Do nothing...
			RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_ESP_DUMMY,"xxHx",pkt,vpn,spi_inb,inb_childsa);

		}else{

			RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_UNKNOWN_PROTO,"xxHx",pkt,vpn,spi_inb,inb_childsa);

			RHP_LOCK(&(rlm->lock));
			rlm->statistics.esp.rx_esp_unknown_proto_packets++;
			RHP_UNLOCK(&(rlm->lock));

			rhp_esp_g_statistics_inc(rx_esp_unknown_proto_packets);

			goto drop;
		}
	}

	RHP_LOCK(&(rlm->lock));
	rlm->statistics.esp.rx_esp_packets++;
	RHP_UNLOCK(&(rlm->lock));


	RHP_LOCK(&(vpn->lock));
	vpn->statistics.rx_esp_packets++;
	vpn->statistics.rx_esp_bytes += pkt->len;

	inb_childsa = vpn->childsa_get(vpn,RHP_DIR_INBOUND,spi_inb);
  if( inb_childsa ){
  	inb_childsa->statistics.rx_esp_packets++;
  }
	RHP_UNLOCK(&(vpn->lock));


	rhp_realm_unhold(rlm);
	rhp_vpn_unhold(vpn_ref);

	if( pend_ctx ){
		_rhp_free(pend_ctx);
	}

	RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_RTRN,"xxHx",pkt,vpn,spi_inb,inb_childsa);
	return 0;

drop_l:
	RHP_UNLOCK(&(vpn->lock));
drop:
	if( vpn ){
		rhp_vpn_unhold(vpn_ref);
	}
	if( rlm ){

		RHP_LOCK(&(rlm->lock));
		rlm->statistics.esp.rx_esp_err_packets++;
		RHP_UNLOCK(&(rlm->lock));

		rhp_realm_unhold(rlm);
	}

	if( pend_ctx ){
		_rhp_free(pend_ctx);
	}

	rhp_esp_g_statistics_inc(rx_esp_err_packets);

	RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_RTRN,"xxHxE",pkt,vpn,spi_inb,inb_childsa,err);
	return -EINVAL;
}

//
// TODO : Updating statistics
//
// TODO: Currently, pend_ctx is not used. If the variable is used,
//       don't forget to free it.
//
void rhp_esp_send_callback(int err,rhp_packet* pkt,rhp_vpn* tx_vpn,u32 spi_outb,void* pend_ctx)
{
	int pkt_tx_len = pkt->len;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_SEND_CALLBACK,"Exxxxx",err,pkt,tx_vpn,spi_outb,pend_ctx);

	if( !err ){

		err = rhp_netsock_send(pkt->tx_ifc,pkt);
		if( err < 0 ){
			RHP_TRC_FREQ(0,RHPTRCID_ESP_SEND_CALLBACK_ERR,"xE",pkt,err);
		}else{

			rhp_childsa* outb_childsa;

			RHP_TRC_FREQ(0,RHPTRCID_ESP_SEND_CALLBACK_RTRN,"x",pkt);

			RHP_LOCK(&(tx_vpn->lock));
			tx_vpn->statistics.tx_esp_packets++;
			tx_vpn->statistics.tx_esp_bytes += pkt_tx_len;

			outb_childsa = tx_vpn->childsa_get(tx_vpn,RHP_DIR_OUTBOUND,spi_outb);
			if( outb_childsa ){
				outb_childsa->statistics.tx_esp_packets++;
			}

			RHP_UNLOCK(&(tx_vpn->lock));
		}
	}

	rhp_pkt_unhold(pkt);
	return;
}

//
// TODO : Updating statistics
//
void rhp_esp_recv_callback(int err,rhp_packet* pkt,
			rhp_vpn* rx_vpn,u32 spi_inb,u8 next_header,void* pend_ctx_b)
{
	rhp_esp_rx_impl_cb* pend_ctx = (rhp_esp_rx_impl_cb*)pend_ctx_b;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_CALLBACK,"Exbx",err,pkt,next_header,pend_ctx);

	if( pend_ctx_b == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	if( !err ){

		RHP_LOCK(&(rx_vpn->lock));

		if( pkt->type == RHP_PKT_IPV4_ESP_NAT_T ||
				pkt->type == RHP_PKT_IPV6_ESP_NAT_T ){

			if( pkt->l3.raw == NULL ){
				RHP_BUG("");
				RHP_UNLOCK(&(rx_vpn->lock));
				goto error;
			}

			if( pend_ctx->src_changed ){

				err = rhp_ikev2_nat_t_change_peer_addr_port(rx_vpn,pend_ctx->addr_family,
								pend_ctx->src_addr,pend_ctx->src_port,pend_ctx->dst_port,0);
				if( err ){
					RHP_UNLOCK(&(rx_vpn->lock));
					goto error;
				}

			}else{

				RHP_UNLOCK(&(rx_vpn->lock));

				RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_CALLBACK_NAT_T_CHANGE_PEER_ADDR_DROP_PKT,"x",pkt);
				goto error;
			}
		}

		{
			rhp_childsa* inb_childsa;

			rx_vpn->statistics.rx_esp_packets++;
			rx_vpn->statistics.rx_esp_bytes += pkt->len;

			inb_childsa = rx_vpn->childsa_get(rx_vpn,RHP_DIR_INBOUND,spi_inb);
			if( inb_childsa ){
				inb_childsa->statistics.rx_esp_packets++;
			}
		}

		RHP_UNLOCK(&(rx_vpn->lock));



		if( next_header == RHP_PROTO_IP_ETHERIP ){

			err = rhp_eoip_recv(pkt,rx_vpn);
			if( err ){
				RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_CALLBACK_EOIP_RECV,"xbE",pkt,next_header,err);
				goto error;
			}

		}else if( next_header == RHP_PROTO_IP_IP || next_header == RHP_PROTO_IP_IPV6  ){

			err = rhp_ip_bridge_recv(pkt,rx_vpn,next_header);
			if( err ){
				RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_CALLBACK_IP_FWD_PKT_FROM_VPN_ERR,"xbE",pkt,next_header,err);
				goto error;
			}

		}else if( next_header == RHP_PROTO_IP_GRE ){

			err = rhp_gre_recv(pkt,rx_vpn);
			if( err ){
				RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_CALLBACK_GRE_RECV,"xbE",pkt,next_header,err);
				goto error;
			}

		}else if( next_header == RHP_PROTO_IP_NO_NEXT_HDR ){

			// Do nothing...
			RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_CALLBACK_ESP_DUMMY,"xb",pkt,next_header);

		}else{
			RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_CALLBACK_UNKNOWN_PROTO,"xb",pkt,next_header);
			goto error;
		}

		RHP_LOCK(&(rx_vpn->lock));
		{
			rx_vpn->statistics.rx_esp_packets++;
			rx_vpn->statistics.rx_esp_bytes += pkt->len;
		}
		RHP_UNLOCK(&(rx_vpn->lock));
	}


error:

	rhp_pkt_unhold(pkt);

	if( pend_ctx ){
		_rhp_free(pend_ctx);
	}

	RHP_TRC_FREQ(0,RHPTRCID_ESP_RECV_CALLBACK_RTRN,"xb",pkt,next_header);
	return;
}


struct _rhp_esp_to_impl_ctx {

	u8 tag[4]; // "#EPL"

	rhp_vpn_ref* vpn_ref;
	rhp_vpn_realm* rlm;
	u32 spi_inb;
	u32 spi_outb;

	void* impl_ctx;
};
typedef struct _rhp_esp_to_impl_ctx	rhp_esp_to_impl_ctx;

static void _rhp_esp_add_childsa_to_impl_handler(int worker_idx,void *handler_ctx)
{
	rhp_esp_to_impl_ctx* ctx = (rhp_esp_to_impl_ctx*)handler_ctx;
	rhp_vpn_ref* vpn_ref = ctx->vpn_ref;
	rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);
	rhp_vpn_realm* rlm = ctx->rlm;
	rhp_childsa* childsa;
	void* impl_ctx = NULL;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_ADD_CHILDSA_TO_IMPL_HANDLER,"dxxx",worker_idx,ctx,vpn,rlm);

	if( !_rhp_atomic_read(&(vpn->is_active)) ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_ADD_CHILDSA_TO_IMPL_HANDLER_VPN_NOT_ACTIVE,"xxx",ctx,vpn,rlm);
		goto error;
  }

	if( !_rhp_atomic_read(&(rlm->is_active)) ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_ADD_CHILDSA_TO_IMPL_HANDLER_RLM_NOT_ACTIVE,"xxx",ctx,vpn,rlm);
		goto error;
  }

	impl_ctx = rhp_esp_impl_childsa_init(vpn,rlm,ctx->spi_inb,ctx->spi_outb);
	if( impl_ctx == NULL ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_ADD_CHILDSA_TO_IMPL_HANDLER_IMPL_CTX_FAILED,"xxx",ctx,vpn,rlm);
		goto error;
	}


	RHP_LOCK(&(vpn->lock));

	if( !_rhp_atomic_read(&(vpn->is_active)) ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_ADD_CHILDSA_TO_IMPL_HANDLER_VPN_NOT_ACTIVE_2,"xxx",ctx,vpn,rlm);
		goto error_l;
  }

	childsa = vpn->childsa_get(vpn,RHP_DIR_INBOUND,ctx->spi_inb);
	if( childsa == NULL ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_ADD_CHILDSA_TO_IMPL_HANDLER_NO_CHILDSA,"xxxH",ctx,vpn,rlm,ctx->spi_inb);
		goto error_l;
	}

	childsa->impl_ctx = impl_ctx;

	RHP_UNLOCK(&(vpn->lock));

	rhp_realm_unhold(rlm);
	rhp_vpn_unhold(vpn_ref);

	_rhp_free(ctx);

	RHP_TRC_FREQ(0,RHPTRCID_ESP_ADD_CHILDSA_TO_IMPL_HANDLER_RTRN,"xxx",ctx,vpn,rlm);
	return;

error_l:
	RHP_UNLOCK(&(vpn->lock));
error:
	rhp_realm_unhold(rlm);
	rhp_vpn_unhold(vpn_ref);
	_rhp_free(ctx);

	if( impl_ctx ){
		rhp_esp_impl_childsa_cleanup(impl_ctx);
	}

	RHP_TRC_FREQ(0,RHPTRCID_ESP_ADD_CHILDSA_TO_IMPL_HANDLER_ERR,"xxx",ctx,vpn,rlm);
	return;
}

int rhp_esp_add_childsa_to_impl(rhp_vpn* vpn,rhp_childsa* childsa)
{
	int err;
	rhp_esp_to_impl_ctx* ctx = (rhp_esp_to_impl_ctx*)_rhp_malloc(sizeof(rhp_esp_to_impl_ctx));

	RHP_TRC_FREQ(0,RHPTRCID_ESP_ADD_CHILDSA_TO_IMPL,"xxx",vpn,childsa,ctx);

	if( ctx == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	ctx->tag[0] = '#';
	ctx->tag[1] = 'E';
	ctx->tag[2] = 'P';
	ctx->tag[3] = 'L';

	ctx->vpn_ref = rhp_vpn_hold_ref(vpn);

	ctx->rlm = vpn->rlm;
	rhp_realm_hold(ctx->rlm);

	ctx->spi_inb = childsa->spi_inb;
	ctx->spi_outb = childsa->spi_outb;

	err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_1,_rhp_esp_add_childsa_to_impl_handler,ctx);
	if( err ){

		RHP_BUG("%d",err);

		rhp_realm_unhold(ctx->rlm);
		rhp_vpn_unhold(ctx->vpn_ref);
		goto error;
	}

	RHP_TRC_FREQ(0,RHPTRCID_ESP_ADD_CHILDSA_TO_IMPL_RTRN,"xxx",vpn,childsa,ctx);
	return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_ESP_ADD_CHILDSA_TO_IMPL_ERR,"xxxE",vpn,childsa,ctx,err);
	return err;
}

static void _rhp_esp_delete_childsa_to_impl_handler(int worker_idx,void *handler_ctx)
{
	rhp_esp_impl_childsa_cleanup(handler_ctx);
	return;
}

int rhp_esp_delete_childsa_to_impl(rhp_vpn* vpn,rhp_childsa* childsa)
{
	int err;
	void* ctx = NULL;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_DELETE_CHILDSA_TO_IMPL,"xxx",vpn,childsa,childsa->impl_ctx);

	if( childsa->impl_ctx == NULL ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_DELETE_CHILDSA_TO_IMPL_CTX_IS_NULL,"xxxLd",vpn,childsa,childsa->impl_ctx,"CHILDSA_STAT",childsa->state);
		err = -EINVAL;
		goto error;
	}

	ctx = childsa->impl_ctx;
	childsa->impl_ctx = NULL;

	err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_1,_rhp_esp_delete_childsa_to_impl_handler,ctx);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	RHP_TRC_FREQ(0,RHPTRCID_ESP_DELETE_CHILDSA_TO_IMPL_RTRN,"xxx",vpn,childsa,ctx);
	return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_ESP_DELETE_CHILDSA_TO_IMPL_ERR,"xxxE",vpn,childsa,ctx,err);
	return err;
}

int rhp_esp_match_selectors_ether(rhp_ext_traffic_selector* etss_head,rhp_proto_ether* ethh)
{
	rhp_ext_traffic_selector* etss = etss_head;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_ETHER,"xx",etss_head,ethh);

	if( etss == NULL ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_ETHER_MATCHED_ANY,"xx",etss_head,ethh);
		return 0;
	}

	while( etss ){

		RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_ETHER_HEAD,"xxxWW",etss_head,ethh,etss,etss->ether_type,ethh->protocol);

		if( etss->ether_type == 0 || etss->ether_type == ethh->protocol ){
			RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_ETHER_MATCHED,"xx",etss_head,ethh);
			return 0;
		}

		etss = etss->next;
	}

	RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_ETHER_NOT_MATCHED,"xx",etss_head,ethh);
	return -1;
}

int rhp_esp_match_selectors_gre(rhp_ext_traffic_selector* etss_head,rhp_proto_gre* greh,int greh_len)
{
	rhp_ext_traffic_selector* etss = etss_head;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_GRE,"xxd",etss_head,greh,greh_len);

	if( etss == NULL ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_GRE_MATCHED_ANY,"xx",etss_head,greh);
		return 0;
	}

	while( etss ){

		RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_GRE_HEAD,"xxxWW",etss_head,greh,etss,etss->ether_type,greh->protocol_type);

		if( etss->ether_type == 0 || etss->ether_type == greh->protocol_type ){
			RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_GRE_MATCHED,"xx",etss_head,greh);
			return 0;
		}

		etss = etss->next;
	}

	RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_GRE_NOT_MATCHED,"xx",etss_head,greh);
	return -1;
}


static int _rhp_esp_match_selectors(int direction,rhp_childsa_ts* my_tss,
		rhp_childsa_ts* peer_tss, rhp_if_entry* my_eoip_if_addr,
		rhp_ip_addr* peer_eoip_addr, int addr_family, u8* iph, u8* end,
		int deny_addr_rslv_pkt /* IPv6 ND */)
{
	rhp_childsa_ts *src_ts, *dst_ts, *tmp_ts;
	int ip_data_len = -1;
	rhp_ip_addr my_eoip_addr;
	rhp_ip_addr *src_eoip_addr = NULL, *dst_eoip_addr = NULL;
	union {
		rhp_proto_ip_v4* v4;
		rhp_proto_ip_v6* v6;
		u8* raw;
	} l3_hdr;
	union {
		rhp_proto_udp* 		udph;
		rhp_proto_tcp* 		tcph;
		rhp_proto_sctp* 	sctph;
		rhp_proto_icmp* 	icmph;
		rhp_proto_icmp6* 	icmp6h;
		u8* raw;
	} l4_hdr;
	u8 protocol = 0;
	int ipv6_frag = 0;
	int i;

	if( addr_family == AF_INET ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_V4,"Ldxxxxxxdp","IPSEC_DIR",direction,my_tss,peer_tss,iph,my_eoip_if_addr,peer_eoip_addr,end,deny_addr_rslv_pkt,sizeof(rhp_proto_ip_v4),iph);
	}else if( addr_family == AF_INET6 ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_V6,"Ldxxxxxxdp","IPSEC_DIR",direction,my_tss,peer_tss,iph,my_eoip_if_addr,peer_eoip_addr,end,deny_addr_rslv_pkt,sizeof(rhp_proto_ip_v6),iph);
	}else{
		RHP_BUG("%d",addr_family);
		return -1;
	}
	rhp_if_entry_dump("rhp_esp_match_selectors.my_eoip_addr",my_eoip_if_addr);
	rhp_ip_addr_dump("rhp_esp_match_selectors.peer_eoip_addr",peer_eoip_addr);

	l3_hdr.raw = iph;
	l4_hdr.raw = NULL;

	if((my_tss == NULL) || (peer_tss == NULL)){
		RHP_TRC_FREQ( 0, RHPTRCID_ESP_MATCH_SELECTORS_ANY_TSS, "x", iph );
		goto matched;
	}

	if(direction == RHP_DIR_INBOUND){
		src_ts = peer_tss;
		dst_ts = my_tss;
	}else{
		src_ts = my_tss;
		dst_ts = peer_tss;
	}

	if(my_eoip_if_addr && peer_eoip_addr){ // EoIP/GRE -- ANY-ANY Traffic Selector

		my_eoip_addr.addr_family = my_eoip_if_addr->addr_family;
		memcpy(my_eoip_addr.addr.raw,my_eoip_if_addr->addr.raw,16);

		if(direction == RHP_DIR_INBOUND){
			src_eoip_addr = peer_eoip_addr;
			dst_eoip_addr = &my_eoip_addr;
		}else{
			src_eoip_addr = &my_eoip_addr;
			dst_eoip_addr = peer_eoip_addr;
		}

		if( !src_ts->flag && !dst_ts->flag &&
				(src_ts->next == NULL) && (dst_ts->next == NULL) &&
				((src_ts->protocol == RHP_PROTO_IP_ETHERIP || src_ts->protocol == RHP_PROTO_IP_GRE) || (src_ts->protocol == 0)) &&
				((dst_ts->protocol == RHP_PROTO_IP_ETHERIP || dst_ts->protocol == RHP_PROTO_IP_GRE) || (dst_ts->protocol == 0)) &&
				!rhp_ip_addr_cmp_ip_only(src_eoip_addr,&(src_ts->start_addr)) &&
				!rhp_ip_addr_cmp_ip_only(dst_eoip_addr,&(dst_ts->start_addr)) ){

			RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_EOIP_ANY_TSS,"x",iph);
			goto matched;
		}

		rhp_ip_addr_dump("rhp_esp_match_selectors.src_ts",&(src_ts->start_addr));
		rhp_ip_addr_dump("rhp_esp_match_selectors.dst_ts",&(dst_ts->start_addr));
	}

	if( addr_family == AF_INET ){

		l4_hdr.raw = iph + (l3_hdr.v4->ihl * 4);
		ip_data_len = ntohs( l3_hdr.v4->total_len ) - (l3_hdr.v4->ihl * 4);
		protocol = l3_hdr.v4->protocol;

	}else if( addr_family == AF_INET6 ){

		ipv6_frag = rhp_proto_ip_v6_frag( l3_hdr.v6, end, &protocol,&(l4_hdr.raw) );
		if(!ipv6_frag){

			l4_hdr.raw = rhp_proto_ip_v6_upper_layer( l3_hdr.v6, end, 0, NULL, &protocol);
		}

		if(l4_hdr.raw){
			ip_data_len = ntohs( l3_hdr.v6->payload_len ) - (l4_hdr.raw - ((u8*)(l3_hdr.v6 + 1)));
		}else{
			ip_data_len = ntohs( l3_hdr.v6->payload_len );
		}

	}else{

		RHP_BUG( "" );
		goto not_matched;
	}

	_RHP_TRC_FLG_UPDATE( _rhp_trc_user_id() );
	if(_RHP_TRC_COND(_rhp_trc_user_id(),0)){

		if( addr_family == AF_INET ){

			if(!RHP_PROTO_IP_FRAG_OFFSET(l3_hdr.v4->frag)){

				if(l4_hdr.raw){

					switch(protocol){
					case RHP_PROTO_IP_UDP:
					case RHP_PROTO_IP_UDPLITE:
						RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_UDP,"x44sbWW",iph,l3_hdr.v4->src_addr,l3_hdr.v4->dst_addr,"UDP",l3_hdr.v4->protocol,l4_hdr.udph->src_port,l4_hdr.udph->dst_port);
						break;
					case RHP_PROTO_IP_TCP:
						RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_TCP,"x44sbWW",iph,l3_hdr.v4->src_addr,l3_hdr.v4->dst_addr,"TCP",l3_hdr.v4->protocol,l4_hdr.tcph->src_port,l4_hdr.tcph->dst_port);
						break;
					case RHP_PROTO_IP_ICMP:
						RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_ICMP,"x44sbbb",iph,l3_hdr.v4->src_addr,l3_hdr.v4->dst_addr,"ICMP",l3_hdr.v4->protocol,l4_hdr.icmph->type,l4_hdr.icmph->code);
						break;
					case RHP_PROTO_IP_SCTP:
						RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_SCTP,"x44sbWW",iph,l3_hdr.v4->src_addr,l3_hdr.v4->dst_addr,"SCTP",l3_hdr.v4->protocol,l4_hdr.sctph->src_port,l4_hdr.sctph->dst_port);
						break;
					default:
						RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_UNKNOWN_1,"x44sb",iph,l3_hdr.v4->src_addr,l3_hdr.v4->dst_addr,"UNKNOWN",l3_hdr.v4->protocol);
						break;
					}

				}else{
					RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_UNKNOWN_2,"x44sb",iph,l3_hdr.v4->src_addr,l3_hdr.v4->dst_addr,"UNKNOWN",l3_hdr.v4->protocol);
				}

			}else{
				RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_FRAGMENT,"x44sb",iph,l3_hdr.v4->src_addr,l3_hdr.v4->dst_addr,"FRAG",l3_hdr.v4->protocol);
			}

		}else if( addr_family == AF_INET6 ){

			if(!ipv6_frag){

				if(l4_hdr.raw){

					switch(protocol){
					case RHP_PROTO_IP_UDP:
					case RHP_PROTO_IP_UDPLITE:
						RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_UDP_V6,"x66sbWW",iph,l3_hdr.v6->src_addr,l3_hdr.v6->dst_addr,"UDP",l3_hdr.v6->next_header, l4_hdr.udph->src_port,l4_hdr.udph->dst_port);
						break;
					case RHP_PROTO_IP_TCP:
						RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_TCP_V6,"x66sbWW",iph,l3_hdr.v6->src_addr,l3_hdr.v6->dst_addr,"TCP",l3_hdr.v6->next_header, l4_hdr.tcph->src_port,l4_hdr.tcph->dst_port);
						break;
					case RHP_PROTO_IP_IPV6_ICMP:
						RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_ICMP_V6,"x66sbbb",iph,l3_hdr.v6->src_addr,l3_hdr.v6->dst_addr,"ICMPV6",l3_hdr.v6->next_header,l4_hdr.icmp6h->type,l4_hdr.icmp6h->code);
						break;
					case RHP_PROTO_IP_SCTP:
						RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_SCTP_V6,"x66sbWW",iph,l3_hdr.v6->src_addr,l3_hdr.v6->dst_addr,"SCTP",l3_hdr.v6->next_header,l4_hdr.sctph->src_port,l4_hdr.sctph->dst_port);
						break;
					default:
						RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_UNKNOWN_V6_1,"x66sb",iph,l3_hdr.v6->src_addr,l3_hdr.v6->dst_addr,"UNKNOWN",l3_hdr.v6->next_header);
						break;
					}

				}else{
					RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_UNKNOWN_V6_2,"x66sb",iph,l3_hdr.v6->src_addr,l3_hdr.v6->dst_addr,"UNKNOWN",l3_hdr.v6->next_header);
				}

			}else{
				RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_FRAGMENT_V6,"x66sb",iph,l3_hdr.v6->src_addr,l3_hdr.v6->dst_addr,"FRAG",l3_hdr.v6->next_header);
			}
		}
	}

	for( i = 0; i < 2; i++ ){

		int src_or_dst;
		u16 port;

		if( i == 0 ){
			tmp_ts = src_ts;
			src_or_dst = 0;
		}else if( i == 1 ){
			tmp_ts = dst_ts;
			src_or_dst = 1;
		}

		while( tmp_ts ){

			if( tmp_ts->flag ){
				goto next;
			}

			if( (addr_family == AF_INET &&
					((tmp_ts->is_v1 && (tmp_ts->ts_or_id_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR_SUBNET || tmp_ts->ts_or_id_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR_RANGE)) ||
					 tmp_ts->ts_or_id_type == RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE)) ||
					(addr_family == AF_INET6 &&
					((tmp_ts->is_v1 && (tmp_ts->ts_or_id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR_SUBNET || tmp_ts->ts_or_id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR_RANGE)) ||
					 tmp_ts->ts_or_id_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE)) ){

				if(addr_family == AF_INET){

					if(i == 0){
						RHP_TRC_FREQ( 0, RHPTRCID_SELECTOR_IPV4_SRC,"xdbbWWbbbb44",tmp_ts,tmp_ts->is_v1,tmp_ts->ts_or_id_type,tmp_ts->protocol,tmp_ts->start_port,tmp_ts->end_port,tmp_ts->icmp_start_type,tmp_ts->icmp_end_type,tmp_ts->icmp_start_code,tmp_ts->icmp_end_code, tmp_ts->start_addr.addr.v4,tmp_ts->end_addr.addr.v4);
					}else if(i == 1){
						RHP_TRC_FREQ( 0, RHPTRCID_SELECTOR_IPV4_DST,"xdbbWWbbbb44",tmp_ts,tmp_ts->is_v1,tmp_ts->ts_or_id_type,tmp_ts->protocol,tmp_ts->start_port,tmp_ts->end_port,tmp_ts->icmp_start_type,tmp_ts->icmp_end_type,tmp_ts->icmp_start_code,tmp_ts->icmp_end_code, tmp_ts->start_addr.addr.v4,tmp_ts->end_addr.addr.v4);
					}

				}else if(addr_family == AF_INET6){

					if(i == 0){
						RHP_TRC_FREQ( 0, RHPTRCID_SELECTOR_IPV6_SRC,"xdbbWWbbbb66",tmp_ts,tmp_ts->is_v1,tmp_ts->ts_or_id_type,tmp_ts->protocol,tmp_ts->start_port,tmp_ts->end_port,tmp_ts->icmp_start_type,tmp_ts->icmp_end_type,tmp_ts->icmp_start_code,tmp_ts->icmp_end_code,tmp_ts->start_addr.addr.v6,tmp_ts->end_addr.addr.v6);
					}else if(i == 1){
						RHP_TRC_FREQ( 0, RHPTRCID_SELECTOR_IPV6_DST,"xdbbWWbbbb66",tmp_ts,tmp_ts->is_v1,tmp_ts->ts_or_id_type,tmp_ts->protocol,tmp_ts->start_port,tmp_ts->end_port,tmp_ts->icmp_start_type,tmp_ts->icmp_end_type,tmp_ts->icmp_start_code,tmp_ts->icmp_end_code,tmp_ts->start_addr.addr.v6,tmp_ts->end_addr.addr.v6);
					}
				}

				if(tmp_ts->protocol != 0 && tmp_ts->protocol != protocol){
					goto next;
				}

				if( !rhp_ip_addr_gt_iphdr( &(tmp_ts->start_addr), addr_family, iph, src_or_dst ) ||
						!rhp_ip_addr_lt_iphdr( &(tmp_ts->end_addr), addr_family, iph, src_or_dst )){

					goto next;
				}

			}else{

				goto next;
			}

			if(tmp_ts->protocol){

				if(ip_data_len <= 0){
					goto next;
				}

				if( tmp_ts->protocol == RHP_PROTO_IP_UDP || // UDP
						tmp_ts->protocol == RHP_PROTO_IP_UDPLITE){ // UDPLite

					if( (addr_family == AF_INET && RHP_PROTO_IP_FRAG_OFFSET(l3_hdr.v4->frag)) ||
					    (addr_family == AF_INET6 && ipv6_frag ) ||
					    l4_hdr.raw == NULL ||
					    ip_data_len < (int)sizeof(rhp_proto_udp) ){

						if( ((ntohs(tmp_ts->start_port) == 0xFFFF) && (ntohs(tmp_ts->end_port) == 0)) || // OPAQUE
								((ntohs(tmp_ts->start_port) == 0) && (ntohs(tmp_ts->end_port) == 0xFFFF)) ){ // ANY
							// OK!
						}else{
							goto next;
						}

					}else{

						if( i == 0 ){
							port = ntohs(l4_hdr.udph->src_port);
						}else if( i == 1 ){
							port = ntohs(l4_hdr.udph->dst_port);
						}

						if( ntohs(tmp_ts->start_port) > port ||
								ntohs(tmp_ts->end_port) < port ){
							goto next;
						}
					}

				}else if( tmp_ts->protocol == RHP_PROTO_IP_TCP ){ // TCP

					if( (addr_family == AF_INET && RHP_PROTO_IP_FRAG_OFFSET(l3_hdr.v4->frag)) ||
							(addr_family == AF_INET6 && ipv6_frag ) ||
							l4_hdr.raw == NULL ||
							ip_data_len < (int)sizeof(rhp_proto_tcp) ){

						if( ((ntohs(tmp_ts->start_port) == 0xFFFF) && (ntohs(tmp_ts->end_port) == 0)) || // OPAQUE
								((ntohs(tmp_ts->start_port) == 0) && (ntohs(tmp_ts->end_port) == 0xFFFF)) ){ // ANY
							// OK!
						}else{
							goto next;
						}

					}else{

						if( i == 0 ){
							port = ntohs(l4_hdr.tcph->src_port);
						}else if( i == 1 ){
							port = ntohs(l4_hdr.tcph->dst_port);
						}

						if( ntohs(tmp_ts->start_port) > port ||
								ntohs(tmp_ts->end_port) < port ){
							goto next;
							}
					}

				}else if( tmp_ts->protocol == RHP_PROTO_IP_SCTP ){ // SCTP

					if( (addr_family == AF_INET && RHP_PROTO_IP_FRAG_OFFSET(l3_hdr.v4->frag)) ||
							(addr_family == AF_INET6 && ipv6_frag ) ||
							l4_hdr.raw == NULL ||
							ip_data_len < (int)sizeof(rhp_proto_sctp) ){

						if( ((ntohs(tmp_ts->start_port) == 0xFFFF) && (ntohs(tmp_ts->end_port) == 0)) || // OPAQUE
								((ntohs(tmp_ts->start_port) == 0) && (ntohs(tmp_ts->end_port) == 0xFFFF)) ){ // ANY
							// OK!
						}else{
							goto next;
						}

					}else{

						if( i == 0 ){
							port = ntohs(l4_hdr.sctph->src_port);
						}else if( i == 1 ){
							port = ntohs(l4_hdr.sctph->dst_port);
						}

						if( ntohs(tmp_ts->start_port) > port ||
								ntohs(tmp_ts->end_port) < port ){
							goto next;
						}
					}

				}else if( tmp_ts->protocol == RHP_PROTO_IP_ICMP ){ // ICMP

					if( addr_family != AF_INET ){
						goto next;
					}

					if( RHP_PROTO_IP_FRAG_OFFSET(l3_hdr.v4->frag) ||
							l4_hdr.raw == NULL ||
							ip_data_len < (int)sizeof(rhp_proto_icmp) ){

						if( (tmp_ts->icmp_start_type == 255 && tmp_ts->icmp_end_type == 0 &&
								 tmp_ts->icmp_start_code == 255 && tmp_ts->icmp_end_code == 0) ||
								(tmp_ts->icmp_start_type == 0 && tmp_ts->icmp_end_type == 0xFF &&
								 tmp_ts->icmp_start_code == 0 && tmp_ts->icmp_end_code == 0xFF) ){ // ANY
							// OK!
						}else{
							goto next;
						}

					}else{

						if( tmp_ts->icmp_start_type > l4_hdr.icmph->type ||
								tmp_ts->icmp_end_type < l4_hdr.icmph->type ){
							goto next;
						}

						if( tmp_ts->icmp_start_code > l4_hdr.icmph->code ||
								tmp_ts->icmp_end_code < l4_hdr.icmph->code ){
							goto next;
						}
					}

				}else if( tmp_ts->protocol == RHP_PROTO_IP_IPV6_ICMP ){ // ICMPv6

					if( addr_family != AF_INET6 ){
						goto next;
					}

					if( ipv6_frag ||
							l4_hdr.raw == NULL ||
							ip_data_len < (int)sizeof(rhp_proto_icmp6) ){

						if( (tmp_ts->icmp_start_type == 255 && tmp_ts->icmp_end_type == 0 &&
								 tmp_ts->icmp_start_code == 255 && tmp_ts->icmp_end_code == 0) ||
								(tmp_ts->icmp_start_type == 0 && tmp_ts->icmp_end_type == 0xFF &&
								 tmp_ts->icmp_start_code == 0 && tmp_ts->icmp_end_code == 0xFF) ){ // ANY
							// OK!
						}else{
							goto next;
						}

					}else{

						if( tmp_ts->icmp_start_type > l4_hdr.icmp6h->type ||
								tmp_ts->icmp_end_type < l4_hdr.icmp6h->type ){
							goto next;
						}

						if( tmp_ts->icmp_start_code > l4_hdr.icmp6h->code ||
								tmp_ts->icmp_end_code < l4_hdr.icmp6h->code ){
							goto next;
						}
					}
				}
			}

			break;

next:
			tmp_ts = tmp_ts->next;
		}

		if(tmp_ts == NULL){

			if(i == 0){
				RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_IP_SRC_NOT_MATCHED,"Ldxxx","IPSEC_DIR",direction,my_tss,peer_tss,iph);
			}else if(i == 1){
				RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_IP_DST_NOT_MATCHED,"Ldxxx","IPSEC_DIR",direction,my_tss,peer_tss,iph);
			}

			goto not_matched;
		}
	}


matched:
	if( deny_addr_rslv_pkt &&
			addr_family == AF_INET6 &&
			!ipv6_frag &&
			l4_hdr.raw &&
			protocol == RHP_PROTO_IP_IPV6_ICMP &&
			ip_data_len >= (int)sizeof(rhp_proto_icmp6) &&
			( l4_hdr.icmp6h->type == RHP_PROTO_ICMP6_TYPE_NEIGHBOR_SOLICIT ||
				l4_hdr.icmp6h->type == RHP_PROTO_ICMP6_TYPE_NEIGHBOR_ADV ) ){

		RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_DENY_ADDR_RSLV_PKT,"Ldx","IPSEC_DIR",direction,iph);
		goto not_matched;
	}

	RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_MATCHED,"Ldxxxdxbdd","IPSEC_DIR",direction,my_tss,peer_tss,iph,ipv6_frag,l4_hdr.raw,protocol,ip_data_len,rhp_gcfg_v6_deny_remote_client_nd_pkts_over_ipip);
	return 0;

not_matched:
	RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_NOT_MATCHED,"Ldxxxd","IPSEC_DIR",direction,my_tss,peer_tss,iph,ip_data_len);
	return -1;
}

int rhp_esp_match_selectors_non_ipip(int direction,u8 protocol,
		rhp_childsa_ts* my_tss,rhp_childsa_ts* peer_tss,
		rhp_if_entry* my_if_addr,rhp_ip_addr* peer_addr)
{
	rhp_childsa_ts *src_ts, *dst_ts, *tmp_ts;
	rhp_ip_addr my_addr;
	rhp_ip_addr *src_addr = NULL, *dst_addr = NULL;
	int i;

	if( peer_addr->addr_family == AF_INET ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_NON_IPIP_V4,"Ldbxxxx","IPSEC_DIR",direction,protocol,my_tss,peer_tss,my_if_addr,peer_addr);
	}else if( peer_addr->addr_family == AF_INET6 ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_NON_IPIP_V6,"Ldbxxxx","IPSEC_DIR",direction,protocol,my_tss,peer_tss,my_if_addr,peer_addr);
	}else{
		RHP_BUG("%d",peer_addr->addr_family);
		return -1;
	}
	rhp_if_entry_dump("_rhp_esp_match_selectors_non_ipip.my_addr",my_if_addr);
	rhp_ip_addr_dump("_rhp_esp_match_selectors_non_ipip.peer_addr",peer_addr);


	if((my_tss == NULL) || (peer_tss == NULL)){
		RHP_TRC_FREQ( 0, RHPTRCID_ESP_MATCH_SELECTORS_NON_IPIP_ANY_TSS,"xx",my_tss,peer_tss);
		goto matched;
	}

	my_addr.addr_family = my_if_addr->addr_family;
	memcpy(my_addr.addr.raw,my_if_addr->addr.raw,16);

	if( direction == RHP_DIR_INBOUND ){

		src_ts = peer_tss;
		dst_ts = my_tss;

		src_addr = peer_addr;
		dst_addr = &my_addr;

	}else{

		src_ts = my_tss;
		dst_ts = peer_tss;

		src_addr = &my_addr;
		dst_addr = peer_addr;
	}


	for( i = 0; i < 2; i++ ){

		int src_or_dst;

		if( i == 0 ){
			tmp_ts = src_ts;
			src_or_dst = 0;
		}else if( i == 1 ){
			tmp_ts = dst_ts;
			src_or_dst = 1;
		}

		while( tmp_ts ){

			int addr_cmp_flag = 0;

			if( tmp_ts->flag ){
				goto next;
			}

			if( (peer_addr->addr_family == AF_INET &&
					((tmp_ts->is_v1 && (tmp_ts->ts_or_id_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR_SUBNET || tmp_ts->ts_or_id_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR_RANGE)) ||
					 tmp_ts->ts_or_id_type == RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE)) ||
					(peer_addr->addr_family == AF_INET6 &&
					((tmp_ts->is_v1 && (tmp_ts->ts_or_id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR_SUBNET || tmp_ts->ts_or_id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR_RANGE)) ||
					 tmp_ts->ts_or_id_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE)) ){

				if(peer_addr->addr_family == AF_INET){

					if(i == 0){
						RHP_TRC_FREQ( 0, RHPTRCID_SELECTOR_IPV4_SRC,"xdbbWWbbbb44",tmp_ts,tmp_ts->is_v1,tmp_ts->ts_or_id_type,tmp_ts->protocol,tmp_ts->start_port,tmp_ts->end_port,tmp_ts->icmp_start_type,tmp_ts->icmp_end_type,tmp_ts->icmp_start_code,tmp_ts->icmp_end_code, tmp_ts->start_addr.addr.v4,tmp_ts->end_addr.addr.v4);
					}else if(i == 1){
						RHP_TRC_FREQ( 0, RHPTRCID_SELECTOR_IPV4_DST,"xdbbWWbbbb44",tmp_ts,tmp_ts->is_v1,tmp_ts->ts_or_id_type,tmp_ts->protocol,tmp_ts->start_port,tmp_ts->end_port,tmp_ts->icmp_start_type,tmp_ts->icmp_end_type,tmp_ts->icmp_start_code,tmp_ts->icmp_end_code, tmp_ts->start_addr.addr.v4,tmp_ts->end_addr.addr.v4);
					}

				}else if(peer_addr->addr_family == AF_INET6){

					if(i == 0){
						RHP_TRC_FREQ( 0, RHPTRCID_SELECTOR_IPV6_SRC,"xdbbWWbbbb66",tmp_ts,tmp_ts->is_v1,tmp_ts->ts_or_id_type,tmp_ts->protocol,tmp_ts->start_port,tmp_ts->end_port,tmp_ts->icmp_start_type,tmp_ts->icmp_end_type,tmp_ts->icmp_start_code,tmp_ts->icmp_end_code,tmp_ts->start_addr.addr.v6,tmp_ts->end_addr.addr.v6);
					}else if(i == 1){
						RHP_TRC_FREQ( 0, RHPTRCID_SELECTOR_IPV6_DST,"xdbbWWbbbb66",tmp_ts,tmp_ts->is_v1,tmp_ts->ts_or_id_type,tmp_ts->protocol,tmp_ts->start_port,tmp_ts->end_port,tmp_ts->icmp_start_type,tmp_ts->icmp_end_type,tmp_ts->icmp_start_code,tmp_ts->icmp_end_code,tmp_ts->start_addr.addr.v6,tmp_ts->end_addr.addr.v6);
					}
				}

				if( tmp_ts->protocol != 0 && tmp_ts->protocol != protocol ){
					goto next;
				}

				if( peer_addr->addr_family == AF_INET ){
					addr_cmp_flag = rhp_ip_addr_gt_ipv4(&(tmp_ts->start_addr),(src_or_dst ? dst_addr->addr.v4 : src_addr->addr.v4));
				}else if( peer_addr->addr_family == AF_INET6 ){
					addr_cmp_flag = rhp_ip_addr_gt_ipv6(&(tmp_ts->start_addr),(src_or_dst ? dst_addr->addr.v6 : src_addr->addr.v6));
				}

				if( !addr_cmp_flag ){
					goto next;
				}

				if( peer_addr->addr_family == AF_INET ){
					addr_cmp_flag = rhp_ip_addr_lt_ipv4(&(tmp_ts->end_addr),(src_or_dst ? dst_addr->addr.v4 : src_addr->addr.v4));
				}else if( peer_addr->addr_family == AF_INET6 ){
					addr_cmp_flag = rhp_ip_addr_lt_ipv6(&(tmp_ts->end_addr),(src_or_dst ? dst_addr->addr.v6 : src_addr->addr.v6));
				}

				if( !addr_cmp_flag ){
					goto next;
				}

			}else{

				goto next;
			}

			break;

next:
			tmp_ts = tmp_ts->next;
		}

		if( tmp_ts == NULL ){

			if(i == 0){
				RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_NON_IPIP_IP_SRC_NOT_MATCHED,"Ldxxb","IPSEC_DIR",direction,my_tss,peer_tss,protocol);
			}else if(i == 1){
				RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_NON_IPIP_IP_DST_NOT_MATCHED,"Ldxxb","IPSEC_DIR",direction,my_tss,peer_tss,protocol);
			}

			goto not_matched;
		}
	}


matched:
	RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_NON_IPIP_MATCHED,"Ldxx","IPSEC_DIR",direction,my_tss,peer_tss);
	return 0;

not_matched:
	RHP_TRC_FREQ(0,RHPTRCID_ESP_MATCH_SELECTORS_NON_IPIP_NOT_MATCHED,"Ldxx","IPSEC_DIR",direction,my_tss,peer_tss);
	return -1;
}

int rhp_esp_match_selectors_ipv4(int direction/*RHP_DIR_XXX*/,rhp_childsa_ts* my_tss,rhp_childsa_ts* peer_tss,
		rhp_if_entry* my_eoip_addr,rhp_ip_addr* peer_eoip_addr,rhp_proto_ip_v4* iph,u8* end)
{
	return _rhp_esp_match_selectors(direction,my_tss,peer_tss,
			my_eoip_addr,peer_eoip_addr,AF_INET,(u8*)iph,end,0);
}

int rhp_esp_match_selectors_ipv6(int direction/*RHP_DIR_XXX*/,rhp_childsa_ts* my_tss,rhp_childsa_ts* peer_tss,
		rhp_if_entry* my_eoip_addr,rhp_ip_addr* peer_eoip_addr,rhp_proto_ip_v6* ip6h,u8* end,
		int deny_addr_rslv_pkt /* IPv6 ND */)
{
	return _rhp_esp_match_selectors(direction,my_tss,peer_tss,
			my_eoip_addr,peer_eoip_addr,AF_INET6,(u8*)ip6h,end,deny_addr_rslv_pkt);
}


int rhp_esp_is_v6_linklocal_icmp_pkt(rhp_packet* rx_pkt)
{
	u8 proto = RHP_PROTO_IP_IPV6_ICMP;
	rhp_proto_icmp6* rx_icmp6h;

	if( rx_pkt->l2.raw == NULL ||
			rx_pkt->l2.eth->protocol != RHP_PROTO_ETH_IPV6 ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IS_V6_LINKLOCAL_ICMP_PKT_NOT_V6_PKT,"x",rx_pkt);
		return 0;
	}

	if( rx_pkt->l3.raw == NULL ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IS_V6_LINKLOCAL_ICMP_PKT_NOT_V6_PKT_2,"x",rx_pkt);
		return 0;
	}

	if( !rhp_ipv6_is_linklocal_all_types(rx_pkt->l3.iph_v6->dst_addr) ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IS_V6_LINKLOCAL_ICMP_PKT_DST_NOT_LINKLOCAL,"x",rx_pkt);
		return 0;
	}

	rx_icmp6h = (rhp_proto_icmp6*)rhp_proto_ip_v6_upper_layer(
								rx_pkt->l3.iph_v6,rx_pkt->end,1,&proto,NULL);
	if( rx_icmp6h == NULL ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IS_V6_LINKLOCAL_ICMP_PKT_NOT_ICMP,"x",rx_pkt);
		return 0;
	}

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IS_V6_LINKLOCAL_ICMP_PKT,"x66b",rx_pkt,rx_pkt->l3.iph_v6->src_addr,rx_pkt->l3.iph_v6->dst_addr,rx_pkt->l3.iph_v6->next_header);
	return 1;
}
