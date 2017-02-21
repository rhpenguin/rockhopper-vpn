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
#include "rhp_process.h"
#include "rhp_config.h"
#include "rhp_vpn.h"
#include "rhp_esp.h"
#include "rhp_eoip.h"
#include "rhp_forward.h"
#include "rhp_ikev1.h"
#include "rhp_pcap.h"



#define RHP_ESP_IMPL_HASH_TABLE_SIZE	1277

struct _rhp_esp_impl_tls_cache {

	u8 tag[4]; // "#EST"

	struct _rhp_esp_impl_tls_cache* hash_next;

	u8 vpn_unique_id[RHP_VPN_UNIQUE_ID_SIZE];
	unsigned long vpn_realm_id;

	u32 spi_inb; // Inbound SPI is always unique!
  u32 spi_outb;

  rhp_ip_addr peer_addr_port;
  int peer_addr_v6_cp_assigned;

  struct {
  	rhp_if_entry addr;
  	u16 port;
  } local;

  int ipsec_mode; 	// RHP_CHILDSA_MODE_XXX
  int encap_mode_c; // RHP_VPN_ENCAP_XXX

  int apply_ts_to_eoip;
  int apply_ts_to_gre;
  rhp_childsa_ts* my_tss;
  rhp_childsa_ts* peer_tss;

	rhp_ext_traffic_selector* etss;

	int udp_encap;
	int v6_enable_udp_encap_after_rx;
	int v6_udp_encap_disabled;

	int esn;
  u64 tx_seq;

  rhp_crypto_integ* integ_inb;
  rhp_crypto_integ* integ_outb;

  rhp_crypto_encr* encr;

  int tfc_padding;
  int tfc_padding_max_size;

  int exec_pmtud;
  int pmtu_default;
  int pmtu_cache;

  time_t tfc_pad_last_updated;
  int tfc_pad_len;

  int rx_udp_encap_from_remote_peer;
};
typedef struct _rhp_esp_impl_tls_cache		rhp_esp_impl_tls_cache;

struct _rhp_esp_impl_tls_cache_ctx {

	u8 tag[4]; // "#ESC"

	u8 vpn_unique_id[RHP_VPN_UNIQUE_ID_SIZE];
	u32 spi_inb;
};
typedef struct _rhp_esp_impl_tls_cache_ctx	rhp_esp_impl_tls_cache_ctx;

static __thread rhp_esp_impl_tls_cache** _rhp_esp_impl_tls_cache_hashtbl = NULL;

static inline void _rhp_esp_impl_dump_tls_cache(rhp_esp_impl_tls_cache* tls_cache)
{
	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_DUMP_TLS,"xxxpuHHwwLdddxxxddqxxxdddddddddd",_rhp_esp_impl_tls_cache_hashtbl,tls_cache,tls_cache->hash_next,RHP_VPN_UNIQUE_ID_SIZE,tls_cache->vpn_unique_id,tls_cache->vpn_realm_id,tls_cache->spi_inb,tls_cache->spi_outb,tls_cache->peer_addr_port,tls_cache->local.port,"CHILDSA_MODE",tls_cache->ipsec_mode,tls_cache->apply_ts_to_eoip,tls_cache->apply_ts_to_gre,tls_cache->my_tss,tls_cache->peer_tss,tls_cache->etss,tls_cache->udp_encap,tls_cache->esn,tls_cache->tx_seq,tls_cache->integ_inb,tls_cache->integ_outb,tls_cache->encr,tls_cache->tfc_padding,tls_cache->tfc_padding_max_size,tls_cache->pmtu_default,tls_cache->exec_pmtud,tls_cache->pmtu_cache,tls_cache->v6_enable_udp_encap_after_rx,tls_cache->peer_addr_v6_cp_assigned,tls_cache->tfc_pad_len,tls_cache->rx_udp_encap_from_remote_peer,tls_cache->v6_udp_encap_disabled);

	rhp_if_entry_dump("_rhp_esp_impl_dump_tls_cache",&tls_cache->local.addr);
	rhp_ip_addr_dump("_rhp_esp_impl_dump_tls_cache",&tls_cache->peer_addr_port);
	return;
}

static inline void _rhp_esp_impl_rx_pcap_write(rhp_esp_impl_tls_cache* tls_cache,
		rhp_packet* pkt,u8 next_header)
{
	u8* p;
	int pkt_len;
	rhp_vpn_ref* vpn_ref = NULL;
	rhp_vpn* rx_vpn = NULL;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_PCAP_WRITE,"xxb",tls_cache,pkt,next_header);

	vpn_ref = rhp_vpn_get_by_unique_id(tls_cache->vpn_unique_id);
	rx_vpn = RHP_VPN_REF(vpn_ref);

	if( rx_vpn == NULL ){
		goto error;
	}

	if( rhp_packet_capture_realm_id &&
			rhp_packet_capture_realm_id != rx_vpn->vpn_realm_id ){
		goto error;
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
		pkt->pcaped = 1;

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
			dmy_hdr.iph.v4.id = htons(0xd0ba); // Dummy Marker
			dmy_hdr.iph.v4.frag = 0;
			dmy_hdr.iph.v4.ttl = 64;
			if( next_header == RHP_PROTO_IP_GRE ){
				dmy_hdr.iph.v4.protocol = RHP_PROTO_IP_GRE;
			}else if( next_header == RHP_PROTO_IP_ETHERIP ){
				dmy_hdr.iph.v4.protocol = RHP_PROTO_IP_ETHERIP;
			}
			dmy_hdr.iph.v4.check_sum = 0;
			dmy_hdr.iph.v4.src_addr = rx_vpn->local.if_info.addr.v4;
			dmy_hdr.iph.v4.dst_addr = rx_vpn->peer_addr.addr.v4;

		}else if( addr_family == AF_INET6 ){

			dmy_hdr_len = (int)(sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v6));

			dmy_hdr.ethh.protocol = RHP_PROTO_ETH_IPV6;

			dmy_hdr.iph.v6.ver = 6;
			dmy_hdr.iph.v6.priority = 0;
			dmy_hdr.iph.v6.flow_label[0] = 0xba; // Dummy Marker
			dmy_hdr.iph.v6.flow_label[1] = 0xd0; // Dummy Marker
			dmy_hdr.iph.v6.flow_label[2] = 0;
			if( next_header == RHP_PROTO_IP_GRE ){
				dmy_hdr.iph.v6.next_header = RHP_PROTO_IP_GRE;
			}else if( next_header == RHP_PROTO_IP_ETHERIP ){
				dmy_hdr.iph.v6.next_header = RHP_PROTO_IP_ETHERIP;
			}
			dmy_hdr.iph.v6.hop_limit = 64;
			dmy_hdr.iph.v6.payload_len = htons(pkt_len);
			memcpy(dmy_hdr.iph.v6.src_addr,rx_vpn->local.if_info.addr.v6,16);
			memcpy(dmy_hdr.iph.v6.dst_addr,rx_vpn->peer_addr.addr.v6,16);

		}else{
			RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_PCAP_WRITE_ERR_1,"xxb",rx_vpn,pkt,next_header);
			goto error;
		}

		rhp_pcap_write(pkt_len,p,dmy_hdr_len,(u8*)&dmy_hdr);
		pkt->pcaped = 1;

	}else{
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_PCAP_WRITE_ERR_2,"xxb",tls_cache,pkt,next_header);
		goto error;
	}

error:
	if( rx_vpn ){
		rhp_vpn_unhold(vpn_ref);
	}
	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_PCAP_WRITE_RTRN,"xxxb",tls_cache,pkt,rx_vpn,next_header);
	return;
}



void rhp_esp_impl_init_tls()
{
	_rhp_esp_impl_tls_cache_hashtbl
	= (rhp_esp_impl_tls_cache**)_rhp_malloc(sizeof(rhp_esp_impl_tls_cache*)*RHP_ESP_IMPL_HASH_TABLE_SIZE);

	if( _rhp_esp_impl_tls_cache_hashtbl ){
		memset(_rhp_esp_impl_tls_cache_hashtbl,0,sizeof(rhp_esp_impl_tls_cache*)*RHP_ESP_IMPL_HASH_TABLE_SIZE);
	}

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_INIT_TLS,"x",_rhp_esp_impl_tls_cache_hashtbl);
	return;
}

static void _rhp_esp_impl_tls_cache_free(rhp_esp_impl_tls_cache* tls_cache)
{
	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TLS_CACHE_FREE,"x",tls_cache);

	if( tls_cache == NULL ){
		return;
	}

	rhp_cfg_realm_free_ext_traffic_selectors(tls_cache->etss);
  rhp_childsa_free_traffic_selectors(tls_cache->my_tss,tls_cache->peer_tss);

  if( tls_cache->integ_inb ){
  	rhp_crypto_integ_free(tls_cache->integ_inb);
  }

  if( tls_cache->integ_outb ){
  	rhp_crypto_integ_free(tls_cache->integ_outb);
  }

  if( tls_cache->encr ){
  	rhp_crypto_encr_free(tls_cache->encr);
  }

  _rhp_free_zero(tls_cache,sizeof(rhp_esp_impl_tls_cache));

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TLS_CACHE_FREE_RTRN,"x",tls_cache);
  return;
}

static rhp_esp_impl_tls_cache* _rhp_esp_impl_tls_cache_alloc(rhp_vpn* vpn,rhp_childsa* childsa,
		rhp_esp_impl_tls_cache* tls_cache_r/* If tls_cache_r is NOT NULL , params are shallow-copied. */)
{
	int err;
	rhp_esp_impl_tls_cache* tls_cache = NULL;
	rhp_vpn_realm* rlm;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TLS_CACHE_ALLOC,"xxx",vpn,childsa,tls_cache_r);

	if( _rhp_esp_impl_tls_cache_hashtbl == NULL ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TLS_CACHE_ALLOC_NOT_ENOUGH_MEMORY,"xxx",vpn,childsa,tls_cache_r);
		return NULL;
	}

	if( tls_cache_r == NULL ){

		tls_cache = (rhp_esp_impl_tls_cache*)_rhp_malloc(sizeof(rhp_esp_impl_tls_cache));
		if( tls_cache == NULL ){
			RHP_BUG("");
			return NULL;
		}

	}else{

		tls_cache = tls_cache_r;
	}

	memset(tls_cache,0,sizeof(rhp_esp_impl_tls_cache));

	tls_cache->tag[0] = '#';
	tls_cache->tag[1] = 'E';
	tls_cache->tag[2] = 'S';
	tls_cache->tag[3] = 'T';

	memcpy(tls_cache->vpn_unique_id,vpn->unique_id,RHP_VPN_UNIQUE_ID_SIZE);
	tls_cache->vpn_realm_id = vpn->vpn_realm_id;

	tls_cache->encap_mode_c = vpn->internal_net_info.encap_mode_c;

	tls_cache->spi_inb = childsa->spi_inb;
	tls_cache->spi_outb = childsa->spi_outb;

  memcpy(&(tls_cache->peer_addr_port),&(vpn->peer_addr),sizeof(rhp_ip_addr));

  memcpy(&(tls_cache->local.addr),&(vpn->local.if_info),sizeof(rhp_if_entry));
  tls_cache->local.port = vpn->local.port;

  tls_cache->peer_addr_v6_cp_assigned
  	= (vpn->internal_net_info.peer_addr_v6_cp == RHP_IKEV2_CFG_CP_ADDR_ASSIGNED ? 1 : 0);

  if( vpn->cfg_peer ){
  	tls_cache->v6_udp_encap_disabled = vpn->cfg_peer->v6_udp_encap_disabled;
  }else{
  	tls_cache->v6_udp_encap_disabled = 0;
  }

  {
	  rlm = vpn->rlm;

	  if( rlm == NULL ){
	  	RHP_BUG("");
	  	goto error;
	  }

		RHP_LOCK(&(rlm->lock));

		if( !_rhp_atomic_read(&(rlm->is_active)) ){
			RHP_UNLOCK(&(rlm->lock));
			goto error;
		}

	  tls_cache->apply_ts_to_eoip = rlm->childsa.apply_ts_to_eoip;
	  tls_cache->apply_ts_to_gre = rlm->childsa.apply_ts_to_gre;

		if( tls_cache_r == NULL ){

		  err = rhp_cfg_realm_dup_ext_traffic_selectors(rlm,&(tls_cache->etss));
		  if( err ){
		  	RHP_BUG("%d",err);
		  	RHP_UNLOCK(&(rlm->lock));
		  	goto error;
		  }

		}else{

			tls_cache->etss = rlm->ext_tss.etss;
		}

	  tls_cache->tfc_padding_max_size = rlm->childsa.tfc_padding_max_size;

	  if( rhp_gcfg_udp_encap_for_v6_after_rx_rockhopper_also ||
	  		!(vpn->peer_is_rockhopper) ){

	  	tls_cache->v6_enable_udp_encap_after_rx = rlm->childsa.v6_enable_udp_encap_after_rx;
	  }

	  if( !tls_cache->v6_udp_encap_disabled ){
	  	tls_cache->v6_udp_encap_disabled = rlm->childsa.v6_udp_encap_disabled;
	  }

	  RHP_UNLOCK(&(rlm->lock));
	}

  tls_cache->ipsec_mode = childsa->ipsec_mode;
  tls_cache->tfc_padding = childsa->tfc_padding;

  tls_cache->exec_pmtud = childsa->exec_pmtud;
  tls_cache->pmtu_cache = childsa->pmtu_cache;
  tls_cache->pmtu_default = childsa->pmtu_default;

  if( vpn->nat_t_info.exec_nat_t || vpn->nat_t_info.always_use_nat_t_port ){
  	tls_cache->udp_encap = 1;
  }else{
  	tls_cache->udp_encap = 0;
  }

	if( tls_cache_r == NULL ){

	  err = rhp_childsa_dup_traffic_selectors(childsa,&(tls_cache->my_tss),&(tls_cache->peer_tss));
	  if( err ){
	  	RHP_BUG("%d",err);
	  	RHP_UNLOCK(&(rlm->lock));
	  	goto error;
	  }

	}else{

		tls_cache->my_tss = childsa->my_tss;
		tls_cache->peer_tss = childsa->peer_tss;
	}

  tls_cache->esn = childsa->esn;

	if( tls_cache_r == NULL ){

		if( vpn->is_v1 ){

			int integ_id = rhp_ikev1_p2_integ_alg(childsa->prop.v1.auth_alg);
			int encr_id = rhp_ikev1_p2_encr_alg(childsa->prop.v1.trans_id);

			tls_cache->integ_inb = rhp_crypto_integ_alloc(integ_id);
			tls_cache->integ_outb = rhp_crypto_integ_alloc(integ_id);
			tls_cache->encr = rhp_crypto_encr_alloc(encr_id,childsa->prop.v1.key_bits_len);

		}else{

			tls_cache->integ_inb = rhp_crypto_integ_alloc(childsa->prop.v2.integ_id);
			tls_cache->integ_outb = rhp_crypto_integ_alloc(childsa->prop.v2.integ_id);
			tls_cache->encr = rhp_crypto_encr_alloc(childsa->prop.v2.encr_id,childsa->prop.v2.encr_key_bits);
		}

		if( tls_cache->integ_inb == NULL ){
	  	RHP_BUG("");
	  	goto error;
	  }

	  if( tls_cache->integ_outb == NULL ){
	  	RHP_BUG("");
	  	goto error;
	  }

	  if( tls_cache->encr == NULL ){
	  	RHP_BUG("");
	  	goto error;
	  }

	  err = tls_cache->encr->set_enc_key(tls_cache->encr,childsa->keys.encr_enc_key,
	  				childsa->keys.encr_key_len);
	  if( err ){
	    RHP_BUG("%d",err);
	    goto error;
	  }

	  err = tls_cache->encr->set_dec_key(tls_cache->encr,
	  				childsa->keys.encr_dec_key,childsa->keys.encr_key_len);
	  if( err ){
	    RHP_BUG("%d",err);
	    goto error;
	  }

	  err = tls_cache->integ_inb->set_key(tls_cache->integ_inb,
	  				childsa->keys.integ_inb_key,childsa->keys.integ_key_len);
	  if( err ){
	    RHP_BUG("%d",err);
	    goto error;
	  }

	  err = tls_cache->integ_outb->set_key(tls_cache->integ_outb,
	  				childsa->keys.integ_outb_key,childsa->keys.integ_key_len);
	  if( err ){
	    RHP_BUG("%d",err);
	    goto error;
	  }

	}else{

	  tls_cache->integ_inb = childsa->integ_inb;
	  tls_cache->integ_outb = childsa->integ_outb;
	  tls_cache->encr = childsa->encr;
	}

	_rhp_esp_impl_dump_tls_cache(tls_cache);
	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TLS_CACHE_ALLOC_RTRN,"xx",vpn,childsa);

	return tls_cache;

error:
	if( tls_cache_r == NULL && tls_cache ){
		_rhp_esp_impl_tls_cache_free(tls_cache);
	}

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TLS_CACHE_ALLOC_ERR,"xx",vpn,childsa);
	return NULL;
}

static int _rhp_esp_impl_tls_hash(u8* vpn_unique_id,u32 spi_inb)
{
	return (spi_inb % RHP_ESP_IMPL_HASH_TABLE_SIZE);
}

static void _rhp_esp_impl_tls_cache_put(u8* vpn_unique_id,u32 spi_inb,rhp_esp_impl_tls_cache* tls_cache)
{
	int hval;
	rhp_esp_impl_tls_cache* tls_cache_h;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TLS_CACHE_PUT,"pHx",RHP_VPN_UNIQUE_ID_SIZE,vpn_unique_id,spi_inb,tls_cache);

	if( _rhp_esp_impl_tls_cache_hashtbl == NULL ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TLS_CACHE_PUT_NOT_ENOUGH_MEMORY,"pHx",RHP_VPN_UNIQUE_ID_SIZE,vpn_unique_id,spi_inb,tls_cache);
		return;
	}

	hval = _rhp_esp_impl_tls_hash(vpn_unique_id,spi_inb);
	tls_cache_h = _rhp_esp_impl_tls_cache_hashtbl[hval];

	tls_cache->hash_next = tls_cache_h;
	_rhp_esp_impl_tls_cache_hashtbl[hval] = tls_cache;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TLS_CACHE_PUT_RETURN,"pHx",RHP_VPN_UNIQUE_ID_SIZE,vpn_unique_id,spi_inb,tls_cache);
	return;
}

static void _rhp_esp_impl_tls_cache_clear(u8* vpn_unique_id,u32 spi_inb)
{
	int hval;
	rhp_esp_impl_tls_cache *tls_cache,*tls_cache_p = NULL;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TLS_CACHE_CLEAR,"pH",RHP_VPN_UNIQUE_ID_SIZE,vpn_unique_id,spi_inb);

	if( _rhp_esp_impl_tls_cache_hashtbl == NULL ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TLS_CACHE_CLEAR_NOT_ENOUGH_MEMORY,"pH",RHP_VPN_UNIQUE_ID_SIZE,vpn_unique_id,spi_inb);
		return;
	}

	hval = _rhp_esp_impl_tls_hash(vpn_unique_id,spi_inb);

	tls_cache = _rhp_esp_impl_tls_cache_hashtbl[hval];

	while( tls_cache ){

		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TLS_CACHE_CLEAR_CACHED_ENTRY,"xppHH",tls_cache,RHP_VPN_UNIQUE_ID_SIZE,tls_cache->vpn_unique_id,RHP_VPN_UNIQUE_ID_SIZE,vpn_unique_id,tls_cache->spi_inb,spi_inb);

		if( (tls_cache->spi_inb == spi_inb) &&
				!memcmp(tls_cache->vpn_unique_id,vpn_unique_id,RHP_VPN_UNIQUE_ID_SIZE) ){
			break;
		}

		tls_cache_p = tls_cache;
		tls_cache = tls_cache->hash_next;
	}

	if( tls_cache == NULL ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TLS_CACHE_CLEAR_NO_ENT,"pH",RHP_VPN_UNIQUE_ID_SIZE,vpn_unique_id,spi_inb);
		return;
	}

	if( tls_cache_p ){
		tls_cache_p->hash_next = tls_cache->hash_next;
	}else{
		_rhp_esp_impl_tls_cache_hashtbl[hval] = tls_cache->hash_next;
	}

	_rhp_esp_impl_tls_cache_free(tls_cache);

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TLS_CACHE_CLEAR_RTRN,"xpH",tls_cache,RHP_VPN_UNIQUE_ID_SIZE,vpn_unique_id,spi_inb);
	return;
}

static rhp_esp_impl_tls_cache* _rhp_esp_impl_tls_cache_get(u8* vpn_unique_id,u32 spi_inb)
{
	int hval;
	rhp_esp_impl_tls_cache* tls_cache;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TLS_CACHE_GET,"pu",RHP_VPN_UNIQUE_ID_SIZE,vpn_unique_id,spi_inb);

	if( _rhp_esp_impl_tls_cache_hashtbl == NULL ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TLS_CACHE_GET_NOT_ENOUGH_MEMORY,"pH",RHP_VPN_UNIQUE_ID_SIZE,vpn_unique_id,spi_inb);
		return NULL;
	}

	hval = _rhp_esp_impl_tls_hash(vpn_unique_id,spi_inb);
	tls_cache = _rhp_esp_impl_tls_cache_hashtbl[hval];

	while( tls_cache ){

		if( tls_cache->spi_inb == spi_inb && !memcmp(tls_cache->vpn_unique_id,vpn_unique_id,RHP_VPN_UNIQUE_ID_SIZE) ){
			RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TLS_CACHE_GET_RTRN,"pHx",RHP_VPN_UNIQUE_ID_SIZE,vpn_unique_id,spi_inb,tls_cache);
			return tls_cache;
		}

		tls_cache = tls_cache->hash_next;
	}

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TLS_CACHE_GET_NO_ENT,"pH",RHP_VPN_UNIQUE_ID_SIZE,vpn_unique_id,spi_inb);
	return NULL;
}

static void _rhp_esp_impl_clear_params_tls_cache_task(int worker_idx,void* ctx)
{
	rhp_esp_impl_tls_cache_ctx* tls_ctx = (rhp_esp_impl_tls_cache_ctx*)ctx;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_CLEAR_PARAMS_TLS_CACHE_TASK,"dx",worker_idx,tls_ctx);

	_rhp_esp_impl_tls_cache_clear(tls_ctx->vpn_unique_id,tls_ctx->spi_inb);

	return;
}

static void _rhp_esp_impl_tls_cache_ctx_destructor(void* ctx)
{
	_rhp_free(ctx);
	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TLS_CACHE_CTX_DESTRUCTOR,"x",ctx);
}

static int _rhp_esp_impl_clear_params_tls_cache(u8* vpn_unique_id,u32 spi_inb)
{
	int err;
	rhp_esp_impl_tls_cache_ctx* tls_ctx = (rhp_esp_impl_tls_cache_ctx*)_rhp_malloc(sizeof(rhp_esp_impl_tls_cache_ctx));

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_CLEAR_PARAMS_TLS_CACHE,"pH",RHP_VPN_UNIQUE_ID_SIZE,vpn_unique_id,spi_inb);

	if( tls_ctx == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	tls_ctx->tag[0] = '#';
	tls_ctx->tag[1] = 'E';
	tls_ctx->tag[2] = 'S';
	tls_ctx->tag[3] = 'C';

	memcpy(tls_ctx->vpn_unique_id,vpn_unique_id,RHP_VPN_UNIQUE_ID_SIZE);
	tls_ctx->spi_inb = spi_inb;

	err = rhp_wts_add_ctrl_task(_rhp_esp_impl_clear_params_tls_cache_task,
			_rhp_esp_impl_tls_cache_ctx_destructor,(void*)tls_ctx);

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_CLEAR_PARAMS_TLS_CACHE_RTRN,"pHE",RHP_VPN_UNIQUE_ID_SIZE,vpn_unique_id,spi_inb,err);
	return err;
}

static int _rhp_esp_impl_sync_tls_cache_tx(rhp_vpn* vpn,rhp_childsa* childsa,rhp_esp_impl_tls_cache* tls_cache,rhp_packet* pkt,int shallow_copied)
{
	int err = -EINVAL;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_SYNC_TLS_CACHE_TX,"xxxuxqqpHdd",vpn,childsa,tls_cache,vpn->vpn_realm_id,pkt,childsa->tx_seq,pkt->dmy_pkt_esp_tx_seq,RHP_VPN_UNIQUE_ID_SIZE,tls_cache->vpn_unique_id,tls_cache->spi_inb,shallow_copied,tls_cache->udp_encap);

	if( pkt->dmy_pkt_esp_tx_seq == 0 ){
		childsa->tx_seq++;
	}else if( pkt->dmy_pkt_esp_tx_seq > childsa->tx_seq ){
		childsa->tx_seq = pkt->dmy_pkt_esp_tx_seq;
	}

	if( !shallow_copied ){

		int iv_len = tls_cache->encr->get_iv_len(tls_cache->encr);
		u8* iv = tls_cache->encr->get_enc_iv(tls_cache->encr);

		if( iv_len < 0 || iv == NULL ){
			RHP_BUG("%d",iv_len);
			goto error;
		}

		err = childsa->encr->update_enc_iv(childsa->encr,iv,iv_len);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
	}

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_SYNC_TLS_CACHE_TX_RTRN,"xxxqd",vpn,childsa,tls_cache,childsa->tx_seq,tls_cache->udp_encap);
	return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_SYNC_TLS_CACHE_TX_ERR,"xxxqdE",vpn,childsa,tls_cache,childsa->tx_seq,tls_cache->udp_encap,err);
	return err;
}

static int _rhp_esp_impl_sync_tls_cache_rx(rhp_vpn* vpn,rhp_childsa* childsa,rhp_esp_impl_tls_cache* tls_cache,int shallow_copied)
{
	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_SYNC_TLS_CACHE_RX,"xxxHdpdd",vpn,childsa,tls_cache,tls_cache->spi_inb,tls_cache->vpn_realm_id,RHP_VPN_UNIQUE_ID_SIZE,tls_cache->vpn_unique_id,shallow_copied,tls_cache->udp_encap);

	if( !vpn->nat_t_info.rx_udp_encap_from_remote_peer && tls_cache->rx_udp_encap_from_remote_peer ){

		vpn->nat_t_info.rx_udp_encap_from_remote_peer = 1;
	}

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_SYNC_TLS_CACHE_RX_RTRN,"xxxd",vpn,childsa,tls_cache,tls_cache->udp_encap);
	return 0;
}

static int _rhp_esp_impl_tfc_padding_proto_etherip(rhp_proto_etherip* etheriph,rhp_proto_ether* ethh,int pkt_len)
{
	u16 ether_type = ethh->protocol;

	if( ether_type == RHP_PROTO_ETH_IP 		||
			ether_type == RHP_PROTO_ETH_IPV6 	||
			ether_type == RHP_PROTO_ETH_ARP ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TFC_PADDING_PROTO_ETHERIP_MATCHED,"xxd",etheriph,ethh,pkt_len);
		return 1;
	}

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TFC_PADDING_PROTO_ETHERIP_NOT_MATCHED,"xxd",etheriph,ethh,pkt_len);
	return 0;
}


static int _rhp_esp_impl_tfc_padding_proto(rhp_packet* pkt)
{
	int ret;

	if( pkt->type == RHP_PKT_PLAIN_ETHER_TAP ){

		rhp_proto_etherip* etheriph;
		rhp_proto_ether* ethh;

		if( pkt->len < (int)sizeof(rhp_proto_etherip) + (int)sizeof(rhp_proto_ether) ){
			return 0;
		}

		etheriph = (rhp_proto_etherip*)pkt->data;
		ethh = (rhp_proto_ether*)(etheriph + 1);

		ret = _rhp_esp_impl_tfc_padding_proto_etherip(etheriph,ethh,pkt->len);

		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TFC_PADDING_PROTO_PLAIN_ETHER_TAP,"x",pkt);
		return ret;

	}else if( pkt->type == RHP_PKT_PLAIN_IPV4_TUNNEL ||
						pkt->type == RHP_PKT_PLAIN_IPV6_TUNNEL ){

		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TFC_PADDING_PROTO_PLAIN_IP_TUNNEL,"x",pkt);
		return 1;
  }

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TFC_PADDING_PROTO_NOT_MATCHED,"x",pkt);
	return 0;
}

static inline int _rhp_esp_impl_do_udp_encap(rhp_packet* pkt,int addr_family,rhp_esp_impl_tls_cache* tls_cache)
{
	if( tls_cache->udp_encap &&
			( addr_family == AF_INET ||
			  (!tls_cache->v6_udp_encap_disabled &&
			  (!tls_cache->v6_enable_udp_encap_after_rx ||
				 tls_cache->rx_udp_encap_from_remote_peer )) ) ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_DO_UDP_ENCAP_DONT,"xLdxdddd",pkt,"AF",addr_family,tls_cache,tls_cache->udp_encap,tls_cache->v6_udp_encap_disabled,tls_cache->v6_enable_udp_encap_after_rx,tls_cache->rx_udp_encap_from_remote_peer);
		return 1;
	}
	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_DO_UDP_ENCAP_DO,"xLdxdddd",pkt,"AF",addr_family,tls_cache,tls_cache->udp_encap,tls_cache->v6_udp_encap_disabled,tls_cache->v6_enable_udp_encap_after_rx,tls_cache->rx_udp_encap_from_remote_peer);
	return 0;
}

static int _rhp_esp_impl_tx_exec_encap(rhp_packet* pkt,int addr_family,u8 esp_nxt_hdr,
		rhp_esp_impl_tls_cache* tls_cache)
{
	int err = -EINVAL;
	int exp_head_len,exp_tail_len,integ_checked_len;
	int iv_len,icv_len,tfc_pad_len = 0,aligned_len,
			pad_len = 0,pld_data_len,block_len;
	u8 *tfc_pad_p = NULL,*pad_p,*icv_p,*iv_p = NULL,*pld_data_p,
			*plain_head_p = NULL,*icv_out_p = NULL,*encr_iv;
	rhp_proto_ether* dmy_ethh;
	union {
		rhp_proto_ip_v4* v4;
		rhp_proto_ip_v6* v6;
		u8* raw;
	} dmy_iph;
  rhp_proto_udp* dmy_udph = NULL;
	rhp_proto_esp* esph = NULL;
	u8* pkt_p;
	int do_udp_encap;
	int i;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TX_EXEC_ENCAP,"xLdbxqd",pkt,"AF",addr_family,esp_nxt_hdr,tls_cache,pkt->dmy_pkt_esp_tx_seq);


	do_udp_encap = _rhp_esp_impl_do_udp_encap(pkt,addr_family,tls_cache);


	pld_data_len = pkt->len;
	if( pld_data_len < 1 ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TX_EXEC_ENCAP_INVALD_PKT,"xxd",pkt,tls_cache,pld_data_len);
		return RHP_STATUS_ESP_INVALID_PKT;
	}


	iv_len = tls_cache->encr->get_iv_len(tls_cache->encr);
	if( iv_len < 0 ){
		RHP_BUG("%d",iv_len);
		err = -EINVAL;
		goto error;
	}

	block_len = tls_cache->encr->get_block_len(tls_cache->encr);
	if( block_len < 0 ){
		RHP_BUG("%d",block_len);
		err = -EINVAL;
		goto error;
	}

	icv_len = tls_cache->integ_outb->get_output_len(tls_cache->integ_outb);
	if( icv_len < 0 ){
		RHP_BUG("%d",icv_len);
		err = -EINVAL;
		goto error;
	}

	if( icv_len < (int)sizeof(u32) ){ // For buffer of ESN higher bits...
		RHP_BUG("%d",icv_len);
		err = -EINVAL;
		goto error;
	}

	exp_head_len = sizeof(rhp_proto_ether) + sizeof(rhp_proto_esp) + iv_len;
	if( addr_family == AF_INET ){
		exp_head_len += sizeof(rhp_proto_ip_v4);
	}else if( addr_family == AF_INET6 ){
		exp_head_len += sizeof(rhp_proto_ip_v6);
	}

	if( do_udp_encap ){
		exp_head_len += sizeof(rhp_proto_udp);
	}

	exp_tail_len = icv_len;


	if( tls_cache->tfc_padding &&
			_rhp_esp_impl_tfc_padding_proto(pkt) ){

		time_t now = _rhp_get_time();

		if( now != tls_cache->tfc_pad_last_updated ){

			u32 rnd;
			rhp_random_bytes((u8*)&rnd,sizeof(u32));

			tfc_pad_len = (rnd % tls_cache->tfc_padding_max_size);
			tls_cache->tfc_pad_last_updated = now;
			tls_cache->tfc_pad_len = tfc_pad_len;

		}else{

			tfc_pad_len = tls_cache->tfc_pad_len;
		}

		aligned_len = tls_cache->encr->get_block_aligned_len(tls_cache->encr,
										(pld_data_len + tfc_pad_len) + (sizeof(u8)*2));

		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TX_EXEC_ENCAP_TFC_PADDING,"xxd",pkt,tls_cache,tfc_pad_len);

		if( aligned_len + (exp_head_len - (int)sizeof(rhp_proto_ether))
				+ exp_tail_len > tls_cache->pmtu_cache ){
			RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TX_EXEC_ENCAP_TFC_PADDING_EXC_PMTU,"xxddddd",pkt,tls_cache,tls_cache->pmtu_cache,aligned_len,exp_head_len,sizeof(rhp_proto_ether),exp_tail_len);
			goto no_tfc_padding;
		}

	}else{

no_tfc_padding:
		tfc_pad_len = 0;
		aligned_len = tls_cache->encr->get_block_aligned_len(tls_cache->encr,
										pld_data_len + (sizeof(u8)*2));

		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TX_EXEC_ENCAP_TFC_NO_PADDING,"xx",pkt,tls_cache);
	}


	// Including Nxthdr and PadLen fields
	pad_len = aligned_len - pld_data_len - tfc_pad_len;
	exp_tail_len += pad_len + tfc_pad_len;

	integ_checked_len = sizeof(rhp_proto_esp) + iv_len + aligned_len;

	{
		//
		// [CAUTION]
		// 	See RHP_PKT_HEADER_ROOM (rhp_packet.h)
		//
		dmy_ethh = (rhp_proto_ether*)rhp_pkt_expand_head(pkt,exp_head_len);
		if( dmy_ethh == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		if( rhp_pkt_expand_tail(pkt,exp_tail_len) == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		pkt_p = ((u8*)dmy_ethh) + sizeof(rhp_proto_ether);

	  dmy_iph.raw = pkt_p;
	  if( addr_family == AF_INET ){
	  	pkt_p += sizeof(rhp_proto_ip_v4);
	  }else if( addr_family == AF_INET6 ){
	  	pkt_p += sizeof(rhp_proto_ip_v6);
	  }

	  if( do_udp_encap ){

	  	dmy_udph = (rhp_proto_udp*)pkt_p;
			pkt_p += sizeof(rhp_proto_udp);
	  }


	  esph = (rhp_proto_esp*)pkt_p;
		pkt_p += sizeof(rhp_proto_esp);

		if( iv_len ){

		  iv_p = (u8*)pkt_p;
			pkt_p += iv_len;
		}

		pld_data_p = (u8*)pkt_p;
		pkt_p += aligned_len;

	  icv_p = (u8*)pkt_p;
		pkt_p += icv_len;
	}

	{
		u8* p;

		plain_head_p = (u8*)_rhp_malloc(aligned_len);
		if( plain_head_p == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		p = plain_head_p;
		p += pld_data_len;

	  if( tfc_pad_len ){

	  	tfc_pad_p = (u8*)p;
	  	if( tfc_pad_p == NULL ){
	    	RHP_BUG("");
	  		err = -EINVAL;
	  		goto error;
	    }
			p += tfc_pad_len;
	  }

	  pad_p = (u8*)p;
		if( pad_p == NULL ){
	  	RHP_BUG("");
			err = -EINVAL;
			goto error;
	  }
		p += pad_len;
	}

	{
		memcpy(dmy_ethh->src_addr,tls_cache->local.addr.mac,6);
		memset(dmy_ethh->dst_addr,0,6);

		if( addr_family == AF_INET ){
			dmy_ethh->protocol = RHP_PROTO_ETH_IP;
		}else if( addr_family == AF_INET6 ){
			dmy_ethh->protocol = RHP_PROTO_ETH_IPV6;
		}
	}

	if( addr_family == AF_INET ){

		dmy_iph.v4->ver = 4;
	  dmy_iph.v4->ihl = 5;
	  dmy_iph.v4->tos = 0;
	  dmy_iph.v4->total_len = 0;
	  dmy_iph.v4->id = 0;
	  dmy_iph.v4->frag = 0;
	  dmy_iph.v4->ttl = 64;
	  dmy_iph.v4->check_sum = 0;

	  dmy_iph.v4->src_addr = tls_cache->local.addr.addr.v4;
	  dmy_iph.v4->dst_addr = tls_cache->peer_addr_port.addr.v4;

	}else if( addr_family == AF_INET6 ){

		dmy_iph.v6->ver = 6;
		dmy_iph.v6->priority = 0;
		dmy_iph.v6->flow_label[0] = 0;
		dmy_iph.v6->flow_label[1] = 0;
		dmy_iph.v6->flow_label[2] = 0;
		dmy_iph.v6->hop_limit = 64;
		dmy_iph.v6->payload_len = 0;

		memcpy(dmy_iph.v6->src_addr,tls_cache->local.addr.addr.v6,16);
		memcpy(dmy_iph.v6->dst_addr,tls_cache->peer_addr_port.addr.v6,16);
	}

	if( do_udp_encap ){

  	if( addr_family == AF_INET ){

  		dmy_iph.v4->protocol = RHP_PROTO_IP_UDP;

  	}else if( addr_family == AF_INET6 ){

  		dmy_iph.v6->next_header = RHP_PROTO_IP_UDP;
  	}

  	dmy_udph->len = 0;
	  dmy_udph->check_sum = 0;
	  dmy_udph->src_port = tls_cache->local.port;
	  dmy_udph->dst_port = tls_cache->peer_addr_port.port;

		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TX_EXEC_ENCAP_UDP_ENCAP,"xx",pkt,tls_cache);

  }else{

  	if( addr_family == AF_INET ){

  		dmy_iph.v4->protocol = RHP_PROTO_IP_ESP;

  	}else if( addr_family == AF_INET6 ){

  		dmy_iph.v6->next_header = RHP_PROTO_IP_ESP;
  	}

		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TX_EXEC_ENCAP_NO_UDP_ENCAP,"xx",pkt,tls_cache);
  }

  {
	  esph->spi = tls_cache->spi_outb;

	  if( pkt->dmy_pkt_esp_tx_seq ){

			RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TX_EXEC_ENCAP_TEST_DMY_PKT_TX_SEQ,"xxq",pkt,tls_cache,pkt->dmy_pkt_esp_tx_seq);
	  	esph->seq = htonl((u32)pkt->dmy_pkt_esp_tx_seq);

	  }else{

	  	esph->seq = htonl((u32)tls_cache->tx_seq);
	  }

	  if( iv_len ){

	  	encr_iv = tls_cache->encr->get_enc_iv(tls_cache->encr);
		  if( encr_iv == NULL ){
		  	RHP_BUG("");
		  	goto error;
		  }

		  memcpy(iv_p,encr_iv,iv_len);
	  }
  }

  {
  	u8* pad_nxt_hdr_p;

  	memcpy(plain_head_p,pld_data_p,pld_data_len);

	  if( tfc_pad_len ){

	  	u8 tfc_val = 0;

	  	for( i = 0; i < tfc_pad_len;i++){
	  		tfc_pad_p[i] = tfc_val++;
	  	}
	  }

	  {
	  	int pad_len_a = pad_len - 2; // -2 : Nxthdr + PadLen

	  	for( i = 0; i < pad_len_a; i++){
	  		pad_p[i] = (u8)(i + 1);
	  	}

	  	*((u8*)(pad_p + pad_len_a)) = pad_len_a;
	  }

	  pad_nxt_hdr_p = (u8*)(pad_p + (pad_len - 1));
	  if( pkt->type == RHP_PKT_PLAIN_ETHER_TAP ){

	  	if( tls_cache->ipsec_mode == RHP_CHILDSA_MODE_TUNNEL ){

    		*pad_nxt_hdr_p = esp_nxt_hdr;

	  	}else{

	  		if( tls_cache->encap_mode_c == RHP_VPN_ENCAP_ETHERIP ){

	  			*pad_nxt_hdr_p = RHP_PROTO_IP_ETHERIP;

	  		}else if( tls_cache->encap_mode_c == RHP_VPN_ENCAP_GRE ){

	  			*pad_nxt_hdr_p = RHP_PROTO_IP_GRE;

	  		}else{
	  	  	RHP_BUG("%d",tls_cache->encap_mode_c);
	  	  	goto error;
	  		}
	  	}

	  }else if( pkt->type == RHP_PKT_GRE_NHRP ){

	  	*pad_nxt_hdr_p = RHP_PROTO_IP_GRE;

	  }else if( pkt->type == RHP_PKT_PLAIN_IPV4_TUNNEL ){

	  	*pad_nxt_hdr_p = RHP_PROTO_IP_IP;

	  }else if( pkt->type == RHP_PKT_PLAIN_IPV6_TUNNEL ){

	  	*pad_nxt_hdr_p = RHP_PROTO_IP_IPV6;

	  }else if( pkt->type == RHP_PKT_PLAIN_IPV4_ESP_DUMMY ||
	  					pkt->type == RHP_PKT_PLAIN_IPV6_ESP_DUMMY ){

	  	*pad_nxt_hdr_p = RHP_PROTO_IP_NO_NEXT_HDR;

	  }else{
	  	RHP_BUG("%d",pkt->type);
	  	goto error;
	  }
  }

  err = tls_cache->encr->encrypt(tls_cache->encr,
  				plain_head_p,aligned_len,pld_data_p,aligned_len);
  if( err ){
  	RHP_BUG("");
    err = RHP_STATUS_ESP_ENCRYPT_ERR;
    goto error;
  }

  if( tls_cache->esn ){

	  if( pkt->dmy_pkt_esp_tx_seq ){

  		*((u32*)(pld_data_p + aligned_len))
  		= htonl((((u32)(pkt->dmy_pkt_esp_tx_seq >> 32)) & 0xFFFFFFFF));

	  }else{

	  	*((u32*)(pld_data_p + aligned_len))
	  	= htonl((((u32)(tls_cache->tx_seq >> 32)) & 0xFFFFFFFF));
  	}

  	integ_checked_len += sizeof(u32);
  }


  icv_out_p = (u8*)_rhp_malloc(icv_len);
  if( icv_out_p == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }

  err = tls_cache->integ_outb->compute(tls_cache->integ_outb,
  				(u8*)esph,integ_checked_len,icv_out_p,icv_len);
  if( err ){
    RHP_BUG("");
    err = RHP_STATUS_ESP_INTEG_ERR;
    goto error;
  }

  memcpy(icv_p,icv_out_p,icv_len);

  if( block_len < iv_len ){
    RHP_BUG("");
    goto error;
  }

  err = tls_cache->encr->update_enc_iv(tls_cache->encr,(icv_p - iv_len),iv_len);
  if( err ){
    RHP_BUG("");
    err = RHP_STATUS_ESP_INTEG_ERR;
    goto error;
  }

  if( do_udp_encap ){

  	if( addr_family == AF_INET ){

  		dmy_iph.v4->total_len = htons(sizeof(rhp_proto_ip_v4) + sizeof(rhp_proto_udp)
  											 	 	 	+ sizeof(rhp_proto_esp) + iv_len + aligned_len + icv_len);

    	pkt->type = RHP_PKT_IPV4_ESP_NAT_T;

  	}else if( addr_family == AF_INET6 ){

  		dmy_iph.v6->payload_len = htons(sizeof(rhp_proto_udp)
  											 	 	 	 	+ sizeof(rhp_proto_esp) + iv_len + aligned_len + icv_len);

    	pkt->type = RHP_PKT_IPV6_ESP_NAT_T;
  	}

  	dmy_udph->len = htons(sizeof(rhp_proto_udp) + sizeof(rhp_proto_esp)
  									+ iv_len + aligned_len + icv_len);

  }else{

  	if( addr_family == AF_INET ){

  		dmy_iph.v4->total_len = htons(sizeof(rhp_proto_ip_v4) + sizeof(rhp_proto_esp)
  												 	 	+ iv_len + aligned_len + icv_len);

    	pkt->type = RHP_PKT_IPV4_ESP;

  	}else if( addr_family == AF_INET6 ){

  		dmy_iph.v6->payload_len = htons(sizeof(rhp_proto_esp)
  															+ iv_len + aligned_len + icv_len);

    	pkt->type = RHP_PKT_IPV6_ESP;
  	}

  }

  _rhp_free_zero(plain_head_p,aligned_len); // Zero clear for encrypted packets....
  _rhp_free(icv_out_p);

  pkt->l2.raw = (u8*)dmy_ethh;
  pkt->l3.raw = dmy_iph.raw;
  pkt->l4.raw = (u8*)dmy_udph;
  pkt->app.esph = esph;

	rhp_pkt_trace_dump("_rhp_esp_impl_tx_exec_encap(1)",pkt);
	if( addr_family == AF_INET ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TX_EXEC_ENCAP_RTRN,"xxa",pkt,tls_cache,pkt->len,RHP_TRC_FMT_A_MAC_IPV4_ESP,iv_len,icv_len,pkt->data);
	}else if( addr_family == AF_INET6 ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TX_EXEC_ENCAP_V6_RTRN,"xxa",pkt,tls_cache,pkt->len,RHP_TRC_FMT_A_MAC_IPV6_ESP,iv_len,icv_len,pkt->data);
	}

	return 0;

error:
	if( plain_head_p ){
		_rhp_free(plain_head_p);
	}
	if( icv_out_p ){
		_rhp_free(icv_out_p);
	}

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TX_EXEC_ENCAP_ERR,"xxE",pkt,tls_cache,err);
	return err;
}

static int _rhp_esp_impl_tx_encap(rhp_packet* pkt,rhp_esp_impl_tls_cache* tls_cache)
{
	int err = -EINVAL;
	int encap_addr_family = AF_UNSPEC;
	union {
		rhp_proto_ip_v4* v4;
		rhp_proto_ip_v6* v6;
		u8* raw;
	} encap_iph;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TX_ENCAP,"xxddLd",pkt,tls_cache,tls_cache->apply_ts_to_eoip,tls_cache->apply_ts_to_gre,"VPN_ENCAP",pkt->encap_mode);
	rhp_pkt_trace_dump("_rhp_esp_impl_tx_encap(1)",pkt);

	encap_iph.raw = NULL;

  switch( pkt->type ){

  case RHP_PKT_PLAIN_ETHER_TAP:
  case RHP_PKT_PLAIN_IPV4_TUNNEL:
  case RHP_PKT_PLAIN_IPV4_ESP_DUMMY:
  case RHP_PKT_PLAIN_IPV6_TUNNEL:
  case RHP_PKT_PLAIN_IPV6_ESP_DUMMY:
  case RHP_PKT_GRE_NHRP:
  	break;

  default:
		RHP_BUG("%d",pkt->type);
		goto error;
	}

  if( pkt->l2.raw == NULL || pkt->l3.raw == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  //
  // Matching selectors...
  //
  if( pkt->type == RHP_PKT_PLAIN_ETHER_TAP ||
  		pkt->type == RHP_PKT_GRE_NHRP ){

  	if( !rhp_gcfg_esp_dont_match_selectors ){

  		int matched = 0;

			if( rhp_esp_match_selectors_ether(tls_cache->etss,pkt->l2.eth) ){
				err = RHP_STATUS_SELECTOR_NOT_MATCHED;
				goto error;
			}

			if( pkt->encap_mode == RHP_VPN_ENCAP_ETHERIP ){

				// Transport mode
				if( !rhp_esp_match_selectors_non_ipip(RHP_DIR_OUTBOUND,RHP_PROTO_IP_ETHERIP,
								tls_cache->my_tss,tls_cache->peer_tss,
								&(tls_cache->local.addr),&(tls_cache->peer_addr_port)) ){

					matched = 1;
				}

			}else if( pkt->encap_mode == RHP_VPN_ENCAP_GRE ){

				// Transport mode
				if( !rhp_esp_match_selectors_non_ipip(RHP_DIR_OUTBOUND,RHP_PROTO_IP_GRE,
								tls_cache->my_tss,tls_cache->peer_tss,
								&(tls_cache->local.addr),&(tls_cache->peer_addr_port)) ){

					matched = 1;
				}
			}

			if( !matched &&
					(pkt->encap_mode == RHP_VPN_ENCAP_IPIP || // Tunnel mode
						// For a packet encapsulate in EtherIP/GRE.
					 (pkt->encap_mode == RHP_VPN_ENCAP_ETHERIP && tls_cache->apply_ts_to_eoip) ||
					 (pkt->encap_mode == RHP_VPN_ENCAP_GRE && tls_cache->apply_ts_to_gre)) ){

				if( pkt->l2.eth->protocol == RHP_PROTO_ETH_IP ){

					encap_iph.v4 = pkt->l3.iph_v4;
					encap_addr_family = AF_INET;

					if( !rhp_esp_match_selectors_ipv4(RHP_DIR_OUTBOUND,tls_cache->my_tss,tls_cache->peer_tss,
								&(tls_cache->local.addr),&(tls_cache->peer_addr_port),encap_iph.v4,pkt->end) ){

						matched = 1;
					}

				}else if( pkt->l2.eth->protocol == RHP_PROTO_ETH_IPV6 ){

					encap_iph.v6 = pkt->l3.iph_v6;
					encap_addr_family = AF_INET6;

					if( !rhp_esp_match_selectors_ipv6(RHP_DIR_OUTBOUND,tls_cache->my_tss,tls_cache->peer_tss,
								&(tls_cache->local.addr),&(tls_cache->peer_addr_port),encap_iph.v6,pkt->end,0) ){

						matched = 1;
					}
				}
			}

			if(!matched ){
				err = RHP_STATUS_SELECTOR_NOT_MATCHED;
				goto error;
			}
  	}

  }else if( pkt->type == RHP_PKT_PLAIN_IPV4_TUNNEL ){

  	if( !rhp_gcfg_esp_dont_match_selectors ){

			encap_iph.v4 = pkt->l3.iph_v4;
			encap_addr_family = AF_INET;

			if( rhp_esp_match_selectors_ipv4(RHP_DIR_OUTBOUND,
						tls_cache->my_tss,tls_cache->peer_tss,NULL,NULL,encap_iph.v4,pkt->end) ){

				err = RHP_STATUS_SELECTOR_NOT_MATCHED;
				goto error;
			}
  	}

  }else if( pkt->type == RHP_PKT_PLAIN_IPV6_TUNNEL ){

  	if( !rhp_gcfg_esp_dont_match_selectors ){

			encap_iph.v6 = pkt->l3.iph_v6;
			encap_addr_family = AF_INET6;

			if( rhp_esp_match_selectors_ipv6(RHP_DIR_OUTBOUND,
						tls_cache->my_tss,tls_cache->peer_tss,NULL,NULL,encap_iph.v6,pkt->end,0) ){

				err = RHP_STATUS_SELECTOR_NOT_MATCHED;
				goto error;
			}
  	}

  }else if( pkt->type == RHP_PKT_PLAIN_IPV4_ESP_DUMMY ){
  	// Do nothing...
  }


	if( encap_iph.raw && tls_cache->exec_pmtud ){

		if( encap_addr_family == AF_INET ){

			err = rhp_esp_tx_handle_pmtud_v4(pkt,encap_iph.v4,tls_cache->pmtu_cache);

		}else if( encap_addr_family == AF_INET6 ){

			err = rhp_esp_tx_handle_pmtud_v6(pkt,encap_iph.v6,tls_cache->pmtu_cache);

		}else{

			err = 0;
		}

		if( err ){
			goto error;
		}
	}


  if( tls_cache->local.addr.addr_family == AF_INET ||
  		tls_cache->local.addr.addr_family == AF_INET6 ){

  	u8 esp_nxt_hdr;
		if( encap_addr_family == AF_INET ){
  		esp_nxt_hdr = RHP_PROTO_IP_IP;
		}else if( encap_addr_family == AF_INET6 ){
  		esp_nxt_hdr = RHP_PROTO_IP_IPV6;
		}else{
  		esp_nxt_hdr = RHP_PROTO_IP_NO_NEXT_HDR;
  	}

  	err = _rhp_esp_impl_tx_exec_encap(pkt,tls_cache->local.addr.addr_family,
  					esp_nxt_hdr,tls_cache);
  	if( err ){
  		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TX_ENCAP_EXEC_ENC_ERR,"xxE",pkt,tls_cache,err);
  		goto error;
  	}

  }else{
  	RHP_BUG("%d",tls_cache->local.addr.addr_family);
  	err = -EINVAL;
  	goto error;
  }

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TX_ENCAP_RTRN,"xx",pkt,tls_cache);
  return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TX_ENCAP_ERR,"xxE",pkt,tls_cache,err);
	return err;
}

static int _rhp_esp_impl_tx_encap_locked(rhp_packet* pkt,rhp_vpn* vpn,rhp_childsa* childsa)
{
	int err;
	rhp_esp_impl_tls_cache tls_cache_dmy;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TX_ENCAP_LOCKED,"xxx",pkt,vpn,childsa);

	if( _rhp_esp_impl_tls_cache_alloc(vpn,childsa,&tls_cache_dmy) == NULL ){
		err = -EINVAL;
		RHP_BUG("");
		goto error;
	}

	tls_cache_dmy.tx_seq = childsa->tx_seq;

	tls_cache_dmy.pmtu_cache = childsa->pmtu_cache;

	if( !tls_cache_dmy.rx_udp_encap_from_remote_peer ){
		tls_cache_dmy.rx_udp_encap_from_remote_peer = vpn->nat_t_info.rx_udp_encap_from_remote_peer;
	}

	err = _rhp_esp_impl_tx_encap(pkt,&tls_cache_dmy);
	if( err ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TX_ENCAP_LOCKED_TX_ENCAP_ERR,"xxxE",pkt,vpn,childsa,err);
		goto error;
	}

	err = _rhp_esp_impl_sync_tls_cache_tx(vpn,childsa,&tls_cache_dmy,pkt,1);
	if( err ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TX_ENCAP_LOCKED_SYNC_TLS_CACHE_ERR,"xxxE",pkt,vpn,childsa,err);
		goto error;
	}

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TX_ENCAP_LOCKED_RTRN,"xxx",pkt,vpn,childsa);
	return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_TX_ENCAP_LOCKED_ERR,"xxxE",pkt,vpn,childsa,err);
	return err;
}

// EtherIP
static int _rhp_esp_impl_rx_decap_etherip(rhp_esp_impl_tls_cache* tls_cache,
		rhp_packet* pkt,u8* dec_out_p,int dec_data_len,u8 pad_len)
{
	int err = -EINVAL;
	rhp_proto_etherip* ethiph;
	rhp_proto_ether* ethh;
	int diff;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_ETHERIP,"xxpb",tls_cache,pkt,dec_data_len,dec_out_p,pad_len);
	rhp_pkt_trace_dump("_rhp_esp_impl_rx_decap_etherip(1)",pkt);

	dec_data_len -= 2 + pad_len;

	if( dec_data_len <= (int)(sizeof(rhp_proto_etherip) + sizeof(rhp_proto_ether)) ){
		err = RHP_STATUS_ESP_INVALID_PKT;
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_ETHERIP_TOO_SHORT_ETH_HDR,"xxdd",tls_cache,pkt,dec_data_len,pad_len,(int)(sizeof(rhp_proto_etherip) + sizeof(rhp_proto_ether)));
		goto error;
	}

	ethiph = (rhp_proto_etherip*)dec_out_p;
	ethh = (rhp_proto_ether*)(ethiph + 1);

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_ETHERIP_PKT,"xxa",pkt,tls_cache,(dec_data_len - sizeof(rhp_proto_etherip)),RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,ethh);

	if( rhp_eoip_check_header(ethiph) ){
		err = RHP_STATUS_ESP_INVALID_PKT;
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_ETHERIP_BAD_EOIP_HDR,"xxp",tls_cache,pkt,sizeof(rhp_proto_etherip),ethiph);
		goto error;
	}

	if( _rhp_esp_impl_tfc_padding_proto_etherip(ethiph,ethh,dec_data_len) ){

		// TFC Padding...

		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_ETHERIP_TFC_PADDING,"xx",tls_cache,pkt);

		if( ethh->protocol == RHP_PROTO_ETH_IP ){

			rhp_proto_ip_v4* iph;
			int ip_data_len;

			if( dec_data_len < (int)(sizeof(rhp_proto_etherip)
												 + sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v4)) ){

				err = RHP_STATUS_ESP_INVALID_PKT;
				RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_ETHERIP_TOO_SHORT_IPV4_HDR,"xxdd",tls_cache,pkt,pkt->len,(int)sizeof(rhp_proto_ip_v4));
				goto error;
			}

			iph = (rhp_proto_ip_v4*)(ethh + 1);
			ip_data_len = ntohs(iph->total_len);

			if( dec_data_len < (int)(sizeof(rhp_proto_etherip)
												 + sizeof(rhp_proto_ether)) + ip_data_len ){

				err = RHP_STATUS_ESP_INVALID_PKT;
				RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_ETHERIP_TOO_SHORT_IPV4_DATA,"xxdd",tls_cache,pkt,pkt->len,(int)sizeof(rhp_proto_ip_v4));
				goto error;
			}

			dec_data_len = (int)(sizeof(rhp_proto_etherip) + sizeof(rhp_proto_ether)) + ip_data_len;

		}else	if( ethh->protocol == RHP_PROTO_ETH_ARP ){

			if( dec_data_len < (int)(sizeof(rhp_proto_etherip)
												 + sizeof(rhp_proto_ether) + sizeof(rhp_proto_arp)) ){

				err = RHP_STATUS_ESP_INVALID_PKT;
				RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_ETHERIP_TOO_SHORT_ARP_PKT,"xxdd",tls_cache,pkt,dec_data_len,(int)sizeof(rhp_proto_arp));
				goto error;
			}

			dec_data_len = (int)(sizeof(rhp_proto_etherip) + sizeof(rhp_proto_ether) + sizeof(rhp_proto_arp));

		}else if( ethh->protocol == RHP_PROTO_ETH_IPV6 ){

			rhp_proto_ip_v6* ip6h;
			int ip_data_len;

			if( dec_data_len < (int)(sizeof(rhp_proto_etherip)
												 + sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v6)) ){

				err = RHP_STATUS_ESP_INVALID_PKT;
				RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_ETHERIP_TOO_SHORT_IPV6_HDR,"xxdd",tls_cache,pkt,pkt->len,(int)sizeof(rhp_proto_ip_v6));
				goto error;
			}

			ip6h = (rhp_proto_ip_v6*)(ethh + 1);
			ip_data_len = ntohs(ip6h->payload_len) + sizeof(rhp_proto_ip_v6);

			if( dec_data_len < (int)(sizeof(rhp_proto_etherip)
												 + sizeof(rhp_proto_ether)) + ip_data_len ){

				err = RHP_STATUS_ESP_INVALID_PKT;
				RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_ETHERIP_TOO_SHORT_IPV6_DATA,"xxdd",tls_cache,pkt,pkt->len,(int)sizeof(rhp_proto_ip_v4));
				goto error;
			}

			dec_data_len = (int)(sizeof(rhp_proto_etherip) + sizeof(rhp_proto_ether)) + ip_data_len;
		}
	}

	diff = (pkt->tail - (u8*)pkt->app.esph) - dec_data_len;

	memcpy(pkt->app.raw,dec_out_p,dec_data_len);
	pkt->data = pkt->app.raw;
	pkt->len = dec_data_len;
	pkt->tail = pkt->app.raw + dec_data_len;

	rhp_pkt_trace_dump("_rhp_esp_impl_rx_decap_etherip(2)",pkt);
	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_ETHERIP_RTRN,"xxd",tls_cache,pkt,diff);

	return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_ETHERIP_ERR,"xxE",tls_cache,pkt,err);
	return err;
}

// IPv4/v6
static int _rhp_esp_impl_rx_decap_ip_ip(rhp_esp_impl_tls_cache* tls_cache,
		rhp_packet* pkt,int addr_family,u8* dec_out_p,int dec_data_len,u8 pad_len)
{
	int err = -EINVAL;
	union {
		rhp_proto_ip_v4* v4;
		rhp_proto_ip_v6* v6;
		u8* raw;
	} iph;
	int diff;
	int ip_data_len;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_IP_IP,"xxLdpb",tls_cache,pkt,"AF",addr_family,dec_data_len,dec_out_p,pad_len);
	rhp_pkt_trace_dump("_rhp_esp_impl_rx_decap_ip_ip(1)",pkt);

	dec_data_len -= 2 + pad_len;

	if( (addr_family == AF_INET && dec_data_len < (int)sizeof(rhp_proto_ip_v4)) ||
			(addr_family == AF_INET6 && dec_data_len < (int)sizeof(rhp_proto_ip_v6)) ){
		err = RHP_STATUS_ESP_INVALID_PKT;
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_IP_IP_TOO_SHORT_IP_HDR,"xxdd",tls_cache,pkt,dec_data_len,(int)sizeof(rhp_proto_ip_v4));
		goto error;
	}

	iph.raw = dec_out_p;
	if( addr_family == AF_INET ){
		ip_data_len = ntohs(iph.v4->total_len);
	}else if( addr_family == AF_INET6 ){
		ip_data_len = ntohs(iph.v6->payload_len) + sizeof(rhp_proto_ip_v6);
	}else{
		RHP_BUG("");
		err = RHP_STATUS_ESP_INVALID_PKT;
		goto error;
	}

	if( ip_data_len > dec_data_len ){
		err = RHP_STATUS_ESP_INVALID_PKT;
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_IP_IP_INVALID_IP_DATA_LEN,"xxdd",tls_cache,pkt,ip_data_len,dec_data_len);
		goto error;
	}

	if( (addr_family == AF_INET && iph.v4->ver != 4) ||
			(addr_family == AF_INET6 && iph.v6->ver != 6) ){
		err = RHP_STATUS_ESP_INVALID_PKT;
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_IP_IP_BAD_IP_VER,"xxddb",tls_cache,pkt,ip_data_len,dec_data_len,iph.raw);
		goto error;
	}

	dec_data_len = ip_data_len;

	diff = (pkt->tail - (u8*)pkt->app.esph) - dec_data_len;

	memcpy(pkt->app.raw,dec_out_p,dec_data_len);
	pkt->data = pkt->app.raw;
	pkt->len = dec_data_len;
	pkt->tail = pkt->app.raw + dec_data_len;

	rhp_pkt_trace_dump("_rhp_esp_impl_rx_decap_ip_ip(2)",pkt);
	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_IP_IP_RTRN,"xxd",tls_cache,pkt,diff);

	return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_IP_IP_ERR,"xxE",tls_cache,pkt,err);
	return err;
}

// GRE
static int _rhp_esp_impl_rx_decap_gre(rhp_esp_impl_tls_cache* tls_cache,
		rhp_packet* pkt,u8* dec_out_p,int dec_data_len,u8 pad_len,
		int nbma_addr_family,u8* src_nbma_addr,u8* dst_nbma_addr)
{
	int err = -EINVAL;
	rhp_proto_gre* greh;
	int diff;
	int greh_len;

	if( nbma_addr_family == AF_INET ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_GRE_V4,"xxpbLd44",tls_cache,pkt,dec_data_len,dec_out_p,pad_len,"AF",nbma_addr_family,*((u32*)src_nbma_addr),*((u32*)dst_nbma_addr));
	}else if( nbma_addr_family == AF_INET6 ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_GRE_V6,"xxpbLd66",tls_cache,pkt,dec_data_len,dec_out_p,pad_len,"AF",nbma_addr_family,src_nbma_addr,dst_nbma_addr);
	}else{
		RHP_BUG("%d",nbma_addr_family);
	}
	rhp_pkt_trace_dump("_rhp_esp_impl_rx_decap_gre(1)",pkt);

	dec_data_len -= 2 + pad_len;

	if( dec_data_len <= (int)sizeof(rhp_proto_gre) ){
		err = RHP_STATUS_ESP_INVALID_PKT;
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_GRE_TOO_SHORT_ETH_HDR,"xxd",tls_cache,pkt,dec_data_len,pad_len,sizeof(rhp_proto_gre));
		goto error;
	}


	greh = (rhp_proto_gre*)dec_out_p;


	if( greh->check_sum_flag ){
		greh_len = (int)sizeof(rhp_proto_gre_csum);
	}else{
		greh_len = (int)sizeof(rhp_proto_gre);
	}

	if( greh->key_flag ){
		greh_len += (int)sizeof(u32);
	}

	if( greh->seq_flag ){
		greh_len += (int)sizeof(u32);
	}

	if( dec_data_len <= greh_len ){
		err = RHP_STATUS_ESP_INVALID_PKT;
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_GRE_TOO_SHORT_ETH_HDR_2,"xxddp",tls_cache,pkt,dec_data_len,pad_len,greh_len,sizeof(rhp_proto_gre),greh);
		goto error;
	}


	if( rhp_gre_check_header(greh) ){
		err = RHP_STATUS_ESP_INVALID_PKT;
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_GRE_BAD_HDR,"xxp",tls_cache,pkt,greh_len,greh);
		goto error;
	}


	if( greh->protocol_type != RHP_PROTO_ETH_IP &&
			greh->protocol_type != RHP_PROTO_ETH_IPV6 &&
			greh->protocol_type != RHP_PROTO_ETH_NHRP ){
		err = RHP_STATUS_ESP_INVALID_PKT;
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_GRE_UNSUP_PROTO,"xxWp",tls_cache,pkt,greh->protocol_type,greh_len,greh);
		goto error;
	}


	{

		// TFC Padding...

		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_GRE_TFC_PADDING,"xx",tls_cache,pkt);

		if( greh->protocol_type == RHP_PROTO_ETH_IP ){

			rhp_proto_ip_v4* iph;
			int ip_data_len;

			if( dec_data_len < greh_len + (int)sizeof(rhp_proto_ip_v4) ){

				err = RHP_STATUS_ESP_INVALID_PKT;
				RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_GRE_TOO_SHORT_IPV4_HDR,"xxdd",tls_cache,pkt,pkt->len,(int)sizeof(rhp_proto_ip_v4));
				goto error;
			}

			iph = (rhp_proto_ip_v4*)(((u8*)greh) + greh_len);
			ip_data_len = ntohs(iph->total_len);

			if( dec_data_len < greh_len + ip_data_len ){

				err = RHP_STATUS_ESP_INVALID_PKT;
				RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_GRE_TOO_SHORT_IPV4_DATA,"xxdddddpp",tls_cache,pkt,pkt->len,(int)sizeof(rhp_proto_ip_v4),dec_data_len,greh_len,ip_data_len,sizeof(rhp_proto_gre),greh,sizeof(rhp_proto_ip_v4),iph);
				goto error;
			}

			dec_data_len = greh_len + ip_data_len;


		}else	if( greh->protocol_type == RHP_PROTO_ETH_NHRP ){

			rhp_proto_nhrp* nhrph;
			int nhrp_len;

			if( dec_data_len < greh_len + (int)sizeof(rhp_proto_nhrp) ){
				err = RHP_STATUS_ESP_INVALID_PKT;
				RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_GRE_TOO_SHORT_NHRP_HDR,"xxdd",tls_cache,pkt,dec_data_len,(int)sizeof(rhp_proto_nhrp));
				goto error;
			}

			nhrph = (rhp_proto_nhrp*)(((u8*)greh) + greh_len);

			nhrp_len = ntohs(nhrph->fixed.len);

			if( dec_data_len < greh_len + nhrp_len ){

				err = RHP_STATUS_ESP_INVALID_PKT;
				RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_GRE_TOO_SHORT_GRE_DATA,"xxdd",tls_cache,pkt,pkt->len,(int)sizeof(rhp_proto_nhrp));
				goto error;
			}


			if( nbma_addr_family == AF_INET ){

				pkt->nhrp.nbma_addr_family = AF_INET;
				pkt->nhrp.nbma_src_addr = (u8*)_rhp_malloc(4);
				pkt->nhrp.nbma_dst_addr = (u8*)_rhp_malloc(4);

				if( pkt->nhrp.nbma_src_addr == NULL || pkt->nhrp.nbma_dst_addr == NULL ){
					RHP_BUG("");
					err = -ENOMEM;
					goto error;
				}

				memcpy(pkt->nhrp.nbma_src_addr,src_nbma_addr,4);
				memcpy(pkt->nhrp.nbma_dst_addr,dst_nbma_addr,4);

			}else if( nbma_addr_family == AF_INET6 ){

				pkt->nhrp.nbma_addr_family = AF_INET6;
				pkt->nhrp.nbma_src_addr = (u8*)_rhp_malloc(16);
				pkt->nhrp.nbma_dst_addr = (u8*)_rhp_malloc(16);

				if( pkt->nhrp.nbma_src_addr == NULL || pkt->nhrp.nbma_dst_addr == NULL ){
					RHP_BUG("");
					err = -ENOMEM;
					goto error;
				}

				memcpy(pkt->nhrp.nbma_src_addr,src_nbma_addr,16);
				memcpy(pkt->nhrp.nbma_dst_addr,dst_nbma_addr,16);
			}


			dec_data_len = greh_len + nhrp_len;


		}else if( greh->protocol_type == RHP_PROTO_ETH_IPV6 ){

			rhp_proto_ip_v6* ip6h;
			int ip_data_len;

			if( dec_data_len < greh_len + (int)sizeof(rhp_proto_ip_v6) ){
				err = RHP_STATUS_ESP_INVALID_PKT;
				RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_GRE_TOO_SHORT_IPV6_HDR,"xxdd",tls_cache,pkt,pkt->len,(int)sizeof(rhp_proto_ip_v6));
				goto error;
			}

			ip6h = (rhp_proto_ip_v6*)(((u8*)greh) + greh_len);
			ip_data_len = ntohs(ip6h->payload_len) + sizeof(rhp_proto_ip_v6);

			if( dec_data_len < greh_len + ip_data_len ){
				err = RHP_STATUS_ESP_INVALID_PKT;
				RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_GRE_TOO_SHORT_IPV4_DATA,"xxdddddpp",tls_cache,pkt,pkt->len,(int)sizeof(rhp_proto_ip_v6),dec_data_len,greh_len,ip_data_len,sizeof(rhp_proto_gre),greh,sizeof(rhp_proto_ip_v6),ip6h);
				goto error;
			}

			dec_data_len = greh_len + ip_data_len;
		}
	}

	diff = (pkt->tail - (u8*)pkt->app.esph) - dec_data_len;

	memcpy(pkt->app.raw,dec_out_p,dec_data_len);
	pkt->data = pkt->app.raw;
	pkt->len = dec_data_len;
	pkt->tail = pkt->app.raw + dec_data_len;

	rhp_pkt_trace_dump("_rhp_esp_impl_rx_decap_gre(2)",pkt);
	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_GRE_RTRN,"xxd",tls_cache,pkt,diff);

	return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_GRE_ERR,"xxE",tls_cache,pkt,err);
	return err;
}

static int _rhp_esp_impl_rx_exec_decap(rhp_packet* pkt,
		rhp_esp_impl_tls_cache* tls_cache,u32 seqh,u8* next_header_r)
{
	int err = -EINVAL;
	int addr_family = AF_UNSPEC;
	union {
		rhp_proto_ip_v4* v4;
		rhp_proto_ip_v6* v6;
		u8* raw;
	} iph;
	rhp_proto_esp* esph = NULL;
	int ip_data_len,pld_data_len,iv_len,block_len,icv_len,
			integ_checked_len,dec_data_len;
	u8 *icv_p,*icv_out_p = NULL,*icv_rx_p = NULL;
	u8 *iv_p,*dec_p,*dec_out_p = NULL;
	u8 pad_len,next_header;
	int udp_encap = 0, udp_encap_pkt = 0;;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_EXEC_DECAP,"xxuxx",pkt,tls_cache,seqh,seqh,next_header_r);
#ifdef RHP_PKT_DEBUG
	rhp_pkt_trace_dump("_rhp_esp_impl_rx_exec_decap(1)",pkt);
#endif // RHP_PKT_DEBUG

	iph.raw = pkt->l3.raw;

	if( pkt->type == RHP_PKT_IPV4_ESP ){
		addr_family = AF_INET;
	}else if( pkt->type == RHP_PKT_IPV4_ESP_NAT_T ){
		addr_family = AF_INET;
		udp_encap_pkt = 1;
	}else if( pkt->type == RHP_PKT_IPV6_ESP ){
		addr_family = AF_INET6;
	}else if( pkt->type == RHP_PKT_IPV6_ESP_NAT_T ){
		addr_family = AF_INET6;
		udp_encap_pkt = 1;
	}else{
		RHP_BUG("");
		goto error;
	}

	esph = pkt->app.esph;

	if( addr_family == AF_INET ){
		ip_data_len = ntohs(iph.v4->total_len) - (iph.v4->ihl*4);
	}else if( addr_family == AF_INET6 ){
		ip_data_len = ntohs(iph.v6->payload_len);
	}

	pld_data_len = pkt->len;

	if( pld_data_len < 1 ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_EXEC_DECAP_BAD_PKT_1,"xxd",pkt,tls_cache,pld_data_len);
		return RHP_STATUS_ESP_INVALID_PKT;
	}

	iv_len = tls_cache->encr->get_iv_len(tls_cache->encr);
	if( iv_len < 0 ){
		RHP_BUG("%d",iv_len);
		err = -EINVAL;
		goto error;
	}

	block_len = tls_cache->encr->get_block_len(tls_cache->encr);
	if( block_len < 0 ){
		RHP_BUG("%d",block_len);
		err = -EINVAL;
		goto error;
	}

	icv_len = tls_cache->integ_inb->get_output_len(tls_cache->integ_inb);
	if( icv_len < 0 ){
		RHP_BUG("%d",icv_len);
		err = -EINVAL;
		goto error;
	}

	if( icv_len < (int)sizeof(u32) ){ // For buffer of ESN higher bits...
		RHP_BUG("%d",icv_len);
		err = -EINVAL;
		goto error;
	}

	if( addr_family == AF_INET ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_EXEC_DECAP_ESP_PKT,"xxa",pkt,tls_cache,pkt->len,RHP_TRC_FMT_A_MAC_IPV4_ESP,iv_len,icv_len,pkt->data);
	}else if( addr_family == AF_INET6 ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_EXEC_DECAP_ESP_PKT_V6,"xxa",pkt,tls_cache,pkt->len,RHP_TRC_FMT_A_MAC_IPV6_ESP,iv_len,icv_len,pkt->data);
	}

	if( pkt->type == RHP_PKT_IPV4_ESP ||
			pkt->type == RHP_PKT_IPV6_ESP ){

		if( ip_data_len < (int)sizeof(rhp_proto_esp) + iv_len + block_len + icv_len ){

			err = RHP_STATUS_ESP_INVALID_PKT;
			RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_EXEC_DECAP_BAD_PKT_2,"xxdddddd",pkt,tls_cache,ip_data_len,(int)sizeof(rhp_proto_esp),iv_len,block_len,icv_len,(int)sizeof(rhp_proto_esp) + iv_len + block_len + icv_len);
			goto error;
		}

	  dec_data_len = ip_data_len - sizeof(rhp_proto_esp) - iv_len - icv_len;

	}else if( pkt->type == RHP_PKT_IPV4_ESP_NAT_T ||
						pkt->type == RHP_PKT_IPV6_ESP_NAT_T ){

		udp_encap = 1;

		if( ip_data_len < (int)(sizeof(rhp_proto_udp) + sizeof(rhp_proto_esp))
											+ iv_len + block_len + icv_len ){

			err = RHP_STATUS_ESP_INVALID_PKT;
			RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_EXEC_DECAP_BAD_PKT_3,"xxddddddd",pkt,tls_cache,ip_data_len,(int)sizeof(rhp_proto_udp),(int)sizeof(rhp_proto_esp),iv_len,block_len,icv_len,(int)(sizeof(rhp_proto_udp) + sizeof(rhp_proto_esp)) + iv_len + block_len + icv_len);
			goto error;
		}

	  dec_data_len = ip_data_len - sizeof(rhp_proto_udp) - sizeof(rhp_proto_esp) - iv_len - icv_len;

	}else{
		RHP_BUG("");
		goto error;
	}

	if( dec_data_len % block_len ){
		err = RHP_STATUS_ESP_INVALID_PKT;
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_EXEC_DECAP_BAD_PKT_4,"xxdd",pkt,tls_cache,dec_data_len,block_len);
		goto error;
	}

	icv_p = pkt->tail - icv_len;
	if( icv_p <= ((u8*)(esph + 1)) + iv_len ){
		err = RHP_STATUS_ESP_INVALID_PKT;
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_EXEC_DECAP_BAD_PKT_5,"xxxxd",pkt,tls_cache,icv_p,(esph + 1),iv_len);
		goto error;
	}

	integ_checked_len = ip_data_len - icv_len;
	if( udp_encap ){
		integ_checked_len -= sizeof(rhp_proto_udp);
	}

	if( tls_cache->esn ){
  	integ_checked_len += sizeof(u32);
  }


  icv_out_p = (u8*)_rhp_malloc(icv_len);
  if( icv_out_p == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }

  icv_rx_p = (u8*)_rhp_malloc(icv_len);
  if( icv_rx_p == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }
  memcpy(icv_rx_p,icv_p,icv_len);

  if( tls_cache->esn ){
  	*((u32*)icv_p) = htonl(seqh);
  }

  err = tls_cache->integ_inb->compute(tls_cache->integ_inb,(u8*)esph,
  				integ_checked_len,icv_out_p,icv_len);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  if( memcmp(icv_out_p,icv_rx_p,icv_len) ){
		err = RHP_STATUS_ESP_INTEG_ERR;
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_EXEC_DECAP_BAD_PKT_ICV_ERR,"xxpp",pkt,tls_cache,icv_len,icv_out_p,icv_len,icv_rx_p);
		goto error;
  }

  dec_p = ((u8*)(esph + 1)) + iv_len;
  iv_p = (u8*)(esph + 1);

  dec_out_p = (u8*)_rhp_malloc(dec_data_len);
  if( dec_out_p == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }

  err = tls_cache->encr->decrypt(tls_cache->encr,dec_p,
  				dec_data_len,dec_out_p,dec_data_len,iv_p);
  if( err ){
  	err = RHP_STATUS_ESP_DECRYPT_ERR;
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_EXEC_DECAP_BAD_PKT_DECRYPTO_ERR,"xx",pkt,tls_cache);
    goto error;
  }

#ifdef RHP_PKT_DEBUG
	rhp_pkt_trace_dump("_rhp_esp_impl_rx_exec_decap(2)",pkt);
#endif // RHP_PKT_DEBUG

  pad_len = *((u8*)(dec_out_p + (dec_data_len - 2)));
  next_header = *((u8*)(dec_out_p + (dec_data_len - 1)));

  if( pad_len > (dec_data_len - 2) ){
		err = RHP_STATUS_ESP_INVALID_PKT;
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_EXEC_DECAP_BAD_PKT_6,"xxdd",pkt,tls_cache,pad_len,(dec_data_len - 2));
		goto error;
  }

  if( next_header == RHP_PROTO_IP_ETHERIP ){

  	err = _rhp_esp_impl_rx_decap_etherip(tls_cache,pkt,
  					dec_out_p,dec_data_len,pad_len);
  	if( err ){
  		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_EXEC_DECAP_RX_DECAP_ETHERIP_ERR,"xxE",pkt,tls_cache,err);
  		goto error;
  	}

  }else if( next_header == RHP_PROTO_IP_IP || next_header == RHP_PROTO_IP_IPV6 ){

  	err = _rhp_esp_impl_rx_decap_ip_ip(tls_cache,pkt,
  					(next_header == RHP_PROTO_IP_IP ? AF_INET : AF_INET6),dec_out_p,dec_data_len,pad_len);
  	if( err ){
  		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_EXEC_DECAP_RX_DECAP_IP_IP_ERR,"xxE",pkt,tls_cache,err);
  		goto error;
  	}

  }else if( next_header == RHP_PROTO_IP_GRE ){

  	u8* src_nbma_addr;
  	u8* dst_nbma_addr;

  	if( addr_family == AF_INET ){
  		src_nbma_addr = (u8*)&(iph.v4->src_addr);
  		dst_nbma_addr = (u8*)&(iph.v4->dst_addr);
  	}else if( addr_family == AF_INET6 ){
  		src_nbma_addr = iph.v6->src_addr;
  		dst_nbma_addr = iph.v6->dst_addr;
  	}else{
  		src_nbma_addr = NULL;
  		dst_nbma_addr = NULL;
  	}

    err = _rhp_esp_impl_rx_decap_gre(tls_cache,pkt,
    					dec_out_p,dec_data_len,pad_len,addr_family,src_nbma_addr,dst_nbma_addr);
    if( err ){
    	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_EXEC_DECAP_RX_DECAP_GRE_ERR,"xxE",pkt,tls_cache,err);
    	goto error;
    }

  }else if( next_header == RHP_PROTO_IP_NO_NEXT_HDR ){ // Dummy packets for TFC

  	// Do nothing...
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_EXEC_DECAP_RX_DECAP_ESP_DUMMY,"xx",pkt,tls_cache);

  }else{
		err = RHP_STATUS_ESP_INVALID_PKT;
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_RX_IPV4_DECAP_IP_IPV6_ERR,"xxE",pkt,tls_cache,err);
		goto error;
  }


	if( icv_out_p ){
		_rhp_free(icv_out_p);
	}

	if( icv_rx_p ){
		_rhp_free(icv_rx_p);
	}

	if( dec_out_p ){
		_rhp_free(dec_out_p);
	}

	*next_header_r = next_header;

#ifdef RHP_PKT_DEBUG
	rhp_pkt_trace_dump("_rhp_esp_impl_rx_exec_decap(3)",pkt);
#endif // RHP_PKT_DEBUG

	if( udp_encap_pkt ){
		tls_cache->rx_udp_encap_from_remote_peer = 1;
	}

  RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_EXEC_DECAP_RTRN,"xxb",pkt,tls_cache,*next_header_r);
	return 0;


error:

	if( icv_out_p ){
		_rhp_free(icv_out_p);
	}

	if( icv_rx_p ){
		_rhp_free(icv_rx_p);
	}

	if( dec_out_p ){
		_rhp_free(dec_out_p);
	}

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_EXEC_DECAP_ERR,"xxE",pkt,tls_cache,err);
	return err;
}

static int _rhp_esp_impl_rx_decap(rhp_packet* pkt,rhp_esp_impl_tls_cache* tls_cache,u32 seqh,u8* next_header_r)
{
	int err = -EINVAL;
	int addr_family = AF_UNSPEC;
	union {
		rhp_proto_ip_v4* v4;
		rhp_proto_ip_v6* v6;
		u8* raw;
	} decap_iph;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP,"xxuxx",pkt,tls_cache,seqh,seqh,next_header_r);
	rhp_pkt_trace_dump("_rhp_esp_impl_rx_decap(1)",pkt);

	decap_iph.raw = NULL;

  switch( pkt->type ){

  case RHP_PKT_IPV4_ESP:
  case RHP_PKT_IPV4_ESP_NAT_T:
  case RHP_PKT_IPV6_ESP:
  case RHP_PKT_IPV6_ESP_NAT_T:
  	break;

  default:
		RHP_BUG("%d",pkt->type);
		goto error;
	}

  if( tls_cache->local.addr.addr_family == AF_INET ||
  		tls_cache->local.addr.addr_family == AF_INET6 ){

  	err = _rhp_esp_impl_rx_exec_decap(pkt,tls_cache,seqh,next_header_r);
  	if( err ){
  		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_EXEC_DECAP_ERR,"xxE",pkt,tls_cache,err);
  		goto error;
  	}

  }else{
  	RHP_BUG("%d",tls_cache->local.addr.addr_family);
  	err = -EINVAL;
  	goto error;
  }


  if( rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_ESP_PLAIN_NOT_CHECKED] ){

		_rhp_esp_impl_rx_pcap_write(tls_cache,pkt,*next_header_r);
	}


  //
  // Matching selectors...
  //
  if( *next_header_r == RHP_PROTO_IP_ETHERIP ){

  	rhp_proto_etherip* ethiph = (rhp_proto_etherip*)pkt->app.raw;
  	rhp_proto_ether* ethh = (rhp_proto_ether*)(ethiph + 1);

  	if( tls_cache->encap_mode_c != RHP_VPN_ENCAP_ETHERIP ){
  		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_ETHERIP_NOT_ENCAP_ETHERIP,"xx",pkt,tls_cache);
  		err = RHP_STATUS_SELECTOR_NOT_MATCHED;
  		goto error;
  	}

  	if( tls_cache->ipsec_mode != RHP_CHILDSA_MODE_TRANSPORT ){
  		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_ETHERIP_NOT_TRANSPORT_MODE,"xx",pkt,tls_cache);
  		err = RHP_STATUS_SELECTOR_NOT_MATCHED;
  		goto error;
  	}

  	if( !rhp_gcfg_esp_dont_match_selectors ){

  		int matched = 0;

			if( rhp_esp_match_selectors_ether(tls_cache->etss,ethh) ){

				RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_ETHERIP_ETHER_SELECTOR_NOT_MATCHED,"xx",pkt,tls_cache);
				err = RHP_STATUS_SELECTOR_NOT_MATCHED;
				goto error;
			}

			if( ethh->protocol == RHP_PROTO_ETH_IP ){
				addr_family = AF_INET;
				decap_iph.v4 = (rhp_proto_ip_v4*)(ethh + 1);
			}else if( ethh->protocol == RHP_PROTO_ETH_IPV6 ){
				addr_family = AF_INET6;
				decap_iph.v6 = (rhp_proto_ip_v6*)(ethh + 1);
			}


			// Transport mode
			if( !rhp_esp_match_selectors_non_ipip(RHP_DIR_INBOUND,RHP_PROTO_IP_ETHERIP,
							tls_cache->my_tss,tls_cache->peer_tss,
							&(tls_cache->local.addr),&(tls_cache->peer_addr_port)) ){

				matched = 1;

			}else{
				RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_ETHERIP_NON_IPIP_SELECTOR_NOT_MATCHED,"xx",pkt,tls_cache);
			}


			// For a packet encapsulate in EtherIP
			if( !matched && tls_cache->apply_ts_to_eoip ){

				if( ethh->protocol == RHP_PROTO_ETH_IP ){

					if( !rhp_esp_match_selectors_ipv4(RHP_DIR_INBOUND,tls_cache->my_tss,tls_cache->peer_tss,
							&(tls_cache->local.addr),&(tls_cache->peer_addr_port),decap_iph.v4,pkt->end) ){

						matched = 1;

					}else{
						RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_ETHERIP_IPV4_SELECTOR_NOT_MATCHED,"xx",pkt,tls_cache);
					}

				}else if( ethh->protocol == RHP_PROTO_ETH_IPV6 ){

					if( !rhp_esp_match_selectors_ipv6(RHP_DIR_INBOUND,tls_cache->my_tss,tls_cache->peer_tss,
							&(tls_cache->local.addr),&(tls_cache->peer_addr_port),decap_iph.v6,pkt->end,0) ){

						matched = 1;

					}else{
						RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_ETHERIP_IPV6_SELECTOR_NOT_MATCHED,"xx",pkt,tls_cache);
					}
				}
			}

			if( !matched ){
				err = RHP_STATUS_SELECTOR_NOT_MATCHED;
				goto error;
			}
  	}

  }else if( *next_header_r == RHP_PROTO_IP_IP ||
  					*next_header_r == RHP_PROTO_IP_IPV6 ){

  	if( tls_cache->encap_mode_c != RHP_VPN_ENCAP_IPIP ){
  		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_IP_IP_IPV4_NOT_ENCAP_IPIP,"xx",pkt,tls_cache);
  		err = RHP_STATUS_SELECTOR_NOT_MATCHED;
  		goto error;
  	}

  	if( tls_cache->ipsec_mode != RHP_CHILDSA_MODE_TUNNEL ){
  		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_IP_IP_IPV4_NOT_TUNNEL_MODE,"xx",pkt,tls_cache);
  		err = RHP_STATUS_SELECTOR_NOT_MATCHED;
  		goto error;
  	}

		if( !rhp_gcfg_esp_dont_match_selectors ){

			if( *next_header_r == RHP_PROTO_IP_IP ){

				addr_family = AF_INET;
				decap_iph.v4 = (rhp_proto_ip_v4*)pkt->app.raw;

				if( rhp_esp_match_selectors_ipv4(RHP_DIR_INBOUND,
							tls_cache->my_tss,tls_cache->peer_tss,NULL,NULL,decap_iph.v4,pkt->end) ){

					RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_IP_IP_IPV4_SELECTOR_NOT_MATCHED,"xx",pkt,tls_cache);
					err = RHP_STATUS_SELECTOR_NOT_MATCHED;
					goto error;
				}

			}else if( *next_header_r == RHP_PROTO_IP_IPV6 ){

				addr_family = AF_INET6;
				decap_iph.v6 = (rhp_proto_ip_v6*)pkt->app.raw;

				if( rhp_esp_match_selectors_ipv6(RHP_DIR_INBOUND,
							tls_cache->my_tss,tls_cache->peer_tss,NULL,NULL,decap_iph.v6,pkt->end,
							(rhp_gcfg_v6_deny_remote_client_nd_pkts_over_ipip && tls_cache->peer_addr_v6_cp_assigned ? 1 : 0)) ){

					RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_IP_IP_IPV6_SELECTOR_NOT_MATCHED,"xx",pkt,tls_cache);
					err = RHP_STATUS_SELECTOR_NOT_MATCHED;
					goto error;
				}
			}
		}

  }else if( *next_header_r == RHP_PROTO_IP_GRE ){

    rhp_proto_gre* greh = (rhp_proto_gre*)pkt->app.raw;
    int greh_len;

    if( tls_cache->encap_mode_c != RHP_VPN_ENCAP_GRE ){
    	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_GRE_NOT_ENCAP_GRE,"xx",pkt,tls_cache);
    	err = RHP_STATUS_SELECTOR_NOT_MATCHED;
    	goto error;
    }

    if( tls_cache->ipsec_mode != RHP_CHILDSA_MODE_TRANSPORT ){
    	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_GRE_NOT_TRANSPORT_MODE,"xx",pkt,tls_cache);
    	err = RHP_STATUS_SELECTOR_NOT_MATCHED;
   		goto error;
   	}

    if( !rhp_gcfg_esp_dont_match_selectors ){

    	int matched = 0;

			if( greh->check_sum_flag ){
				greh_len = (int)sizeof(rhp_proto_gre_csum);
			}else{
				greh_len = (int)sizeof(rhp_proto_gre);
			}

			if( greh->key_flag ){
				greh_len += (int)sizeof(u32);
			}

			if( greh->seq_flag ){
				greh_len += (int)sizeof(u32);
			}

			if( rhp_esp_match_selectors_gre(tls_cache->etss,greh,greh_len) ){
				RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_GRE_SELECTOR_NOT_MATCHED,"xx",pkt,tls_cache);
				err = RHP_STATUS_SELECTOR_NOT_MATCHED;
				goto error;
			}


			if( greh->protocol_type == RHP_PROTO_ETH_IP ){
				addr_family = AF_INET;
				decap_iph.v4 = (rhp_proto_ip_v4*)(((u8*)greh) + greh_len);
			}else if( greh->protocol_type == RHP_PROTO_ETH_IPV6 ){
				addr_family = AF_INET6;
				decap_iph.v6 = (rhp_proto_ip_v6*)(((u8*)greh) + greh_len);
			}else if( greh->protocol_type != RHP_PROTO_ETH_NHRP ){
				RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_GRE_RX_UNSUP_ETHER_TYPE,"xxW",pkt,tls_cache,greh->protocol_type);
			}


			// Transport mode
			if( !rhp_esp_match_selectors_non_ipip(RHP_DIR_INBOUND,RHP_PROTO_IP_GRE,
							tls_cache->my_tss,tls_cache->peer_tss,
							&(tls_cache->local.addr),&(tls_cache->peer_addr_port)) ){

				matched = 1;

			}else{
				RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_GRE_NON_IPIP_SELECTOR_NOT_MATCHED,"xx",pkt,tls_cache);
			}


			// For a packet encapsulate in GRE
			if( !matched && tls_cache->apply_ts_to_gre ){

				if( greh->protocol_type == RHP_PROTO_ETH_IP ){

					if( !rhp_esp_match_selectors_ipv4(RHP_DIR_INBOUND,tls_cache->my_tss,tls_cache->peer_tss,
							&(tls_cache->local.addr),&(tls_cache->peer_addr_port),decap_iph.v4,pkt->end) ){

						matched = 1;

					}else{
						RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_GRE_IPV4_SELECTOR_NOT_MATCHED,"xx",pkt,tls_cache);
					}

				}else if( greh->protocol_type == RHP_PROTO_ETH_IPV6 ){

					if( !rhp_esp_match_selectors_ipv6(RHP_DIR_INBOUND,tls_cache->my_tss,tls_cache->peer_tss,
							&(tls_cache->local.addr),&(tls_cache->peer_addr_port),decap_iph.v6,pkt->end,0) ){

						matched = 1;

					}else{
						RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_GRE_IPV6_SELECTOR_NOT_MATCHED,"xx",pkt,tls_cache);
					}
				}
			}

			if( !matched ){
				err = RHP_STATUS_SELECTOR_NOT_MATCHED;
				goto error;
			}
    }

  }else if( *next_header_r == RHP_PROTO_IP_NO_NEXT_HDR ){

  	// Do nothing...
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_ESP_DUMMY,"xx",pkt,tls_cache);

		err = RHP_STATUS_ESP_RX_DUMMY_PKT;
		goto error;

  }else{

  	// Do nothing...
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_UNKNOW_INTERNAL_PKT,"xxb",pkt,tls_cache,*next_header_r);

		err = RHP_STATUS_SELECTOR_NOT_MATCHED;
		goto error;
  }


  if( tls_cache->exec_pmtud &&
  		addr_family != AF_UNSPEC && decap_iph.raw ){

  	if( addr_family == AF_INET ){

  		err = rhp_esp_tcp_mss_overwrite_v4(decap_iph.v4,pkt->end,tls_cache->pmtu_cache);

  	}else if( addr_family == AF_INET6 ){

  		err = rhp_esp_tcp_mss_overwrite_v6(decap_iph.v6,pkt->end,tls_cache->pmtu_cache);

  	}else{
  		err = 0;
  	}

  	if( err ){
			err = RHP_STATUS_ESP_INVALID_PKT;
			goto error;
		}
  }

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_RTRN,"xxxdd",pkt,tls_cache,decap_iph.raw,addr_family,tls_cache->exec_pmtud);
  return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_ERR,"xxE",pkt,tls_cache,err);
	return err;
}

static int _rhp_esp_impl_rx_decap_locked(rhp_packet* pkt,rhp_vpn* vpn,rhp_childsa* childsa,u32 seqh,u8* next_header_r)
{
	int err;
	rhp_esp_impl_tls_cache tls_cache_dmy;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_LOCKED,"xxxux",pkt,vpn,childsa,seqh,next_header_r);

	if( _rhp_esp_impl_tls_cache_alloc(vpn,childsa,&tls_cache_dmy) == NULL ){
		err = -EINVAL;
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_LOCKED_ALLOC_TLS_CACHE_ERR,"xxx",pkt,vpn,childsa);
		goto error;
	}

	tls_cache_dmy.pmtu_cache = childsa->pmtu_cache;

	err = _rhp_esp_impl_rx_decap(pkt,&tls_cache_dmy,seqh,next_header_r);
	if( err ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_LOCKED_DECAP_ERR,"xxxE",pkt,vpn,childsa,err);
		goto error;
	}

	err = _rhp_esp_impl_sync_tls_cache_rx(vpn,childsa,&tls_cache_dmy,1);
	if( err ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_LOCKED_SYNC_TLS_CACHE_ERR,"xxxE",pkt,vpn,childsa,err);
		goto error;
	}

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_LOCKED_RTRN,"xxxE",pkt,vpn,childsa);
	return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_RX_DECAP_LOCKED__ERR,"xxxE",pkt,vpn,childsa,err);
	return err;
}


int rhp_esp_impl_init()
{
	RHP_TRC(0,RHPTRCID_ESP_IMPL_INIT,"");
	return 0;
}

void rhp_esp_impl_cleanup()
{
	RHP_TRC(0,RHPTRCID_ESP_IMPL_CLEANUP,"");
	return;
}

struct _rhp_esp_impl_childsa_ctx {

	u8 tag[4]; // "#EIX"

	u8 vpn_unique_id[RHP_VPN_UNIQUE_ID_SIZE];
	u32 spi_inb;
	u32 spi_outb;
};
typedef struct _rhp_esp_impl_childsa_ctx	rhp_esp_impl_childsa_ctx;

void* rhp_esp_impl_childsa_init(rhp_vpn* vpn,rhp_vpn_realm* rlm,u32 spi_inb,u32 spi_outb)
{
	rhp_esp_impl_childsa_ctx* impl_ctx = NULL;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_CHILDSA_INIT,"xxHH",vpn,rlm,spi_inb,spi_outb);

	RHP_LOCK(&(vpn->lock));

	if( !_rhp_atomic_read(&(vpn->is_active)) ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_CHILDSA_INIT_VPN_NOT_ACTIVE,"xxHH",vpn,rlm,spi_inb,spi_outb);
		goto error_l;
  }

	impl_ctx = (rhp_esp_impl_childsa_ctx*)_rhp_malloc(sizeof(rhp_esp_impl_childsa_ctx));
	if( impl_ctx == NULL ){
		RHP_BUG("");
		goto error_l;
	}

	impl_ctx->tag[0] = '#';
	impl_ctx->tag[1] = 'E';
	impl_ctx->tag[2] = 'I';
	impl_ctx->tag[3] = 'X';

	memcpy(impl_ctx->vpn_unique_id,vpn->unique_id,RHP_VPN_UNIQUE_ID_SIZE);
	impl_ctx->spi_inb = spi_inb;
	impl_ctx->spi_outb = spi_outb;

	RHP_UNLOCK(&(vpn->lock));

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_CHILDSA_INIT_RTRN,"xxHHx",vpn,rlm,spi_inb,spi_outb,impl_ctx);
	return impl_ctx;

error_l:
	RHP_UNLOCK(&(vpn->lock));

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_CHILDSA_INIT_ERR,"xxHH",vpn,rlm,spi_inb,spi_outb);
	return NULL;
}

void rhp_esp_impl_childsa_cleanup(void* impl_ctx)
{
	int err;
	rhp_esp_impl_childsa_ctx* ctx = (rhp_esp_impl_childsa_ctx*)impl_ctx;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_CHILDSA_CLEANUP,"xpHH",impl_ctx,RHP_VPN_UNIQUE_ID_SIZE,ctx->vpn_unique_id,ctx->spi_inb,ctx->spi_outb);

  err = _rhp_esp_impl_clear_params_tls_cache(ctx->vpn_unique_id,ctx->spi_inb);
	if( err ){
  	RHP_BUG("%d",err);
  }

	_rhp_free(impl_ctx);

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_CHILDSA_CLEANUP_RTRN,"x",impl_ctx);
  return;
}

static void _rhp_esp_impl_sync_tx_addr_port(rhp_vpn* vpn,rhp_esp_impl_tls_cache* tls_cache)
{
	tls_cache->peer_addr_port.addr_family = vpn->peer_addr.addr_family;
  tls_cache->local.addr.addr_family = vpn->local.if_info.addr_family;

	if( vpn->peer_addr.addr_family == AF_INET ){

  	tls_cache->peer_addr_port.addr.v4 = vpn->peer_addr.addr.v4;
  	tls_cache->peer_addr_port.port = vpn->peer_addr.port;

  	tls_cache->local.addr.addr.v4 = vpn->local.if_info.addr.v4;
  	tls_cache->local.addr.if_index = vpn->local.if_info.if_index;

  }else if( vpn->peer_addr.addr_family == AF_INET6 ){

  	memcpy(tls_cache->peer_addr_port.addr.v6,vpn->peer_addr.addr.v6,16);
  	tls_cache->peer_addr_port.port = vpn->peer_addr.port;

  	memcpy(tls_cache->local.addr.addr.v6,vpn->local.if_info.addr.v6,16);
  	tls_cache->local.addr.if_index = vpn->local.if_info.if_index;
  }


  if( vpn->nat_t_info.exec_nat_t || vpn->nat_t_info.always_use_nat_t_port ){
  	tls_cache->udp_encap = 1;
		tls_cache->local.port = vpn->local.port_nat_t;
  }else{
  	tls_cache->udp_encap = 0;
  	tls_cache->local.port = vpn->local.port;
  }

  return;
}

int rhp_esp_impl_enc_packet(rhp_packet* pkt,rhp_vpn* vpn,rhp_vpn_realm* rlm,u32 spi_outb,void* pend_ctx)
{
	int err = -EINVAL;
	rhp_childsa* childsa = NULL;
	rhp_esp_impl_tls_cache* tls_cache = NULL;
	rhp_esp_impl_childsa_ctx* impl_ctx = NULL;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_ENC_PACKET,"xxxHxp",pkt,vpn,rlm,spi_outb,pend_ctx,pkt->len,pkt->data);

	RHP_LOCK(&(vpn->lock));

	if( !_rhp_atomic_read(&(vpn->is_active)) ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_ENC_PACKET_VPN_NOT_ACTIVE,"xxx",pkt,vpn,rlm);
		goto error_l;
  }

	childsa = vpn->childsa_get(vpn,RHP_DIR_OUTBOUND,spi_outb);
	if( childsa == NULL ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_ENC_PACKET_NO_CHILDSA,"xxx",pkt,vpn,rlm);
		err = RHP_STATUS_ESP_NO_CHILDSA;
		goto error_l;
	}

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_ENC_PACKET_CHILDSA,"xxxx",pkt,vpn,rlm,childsa);

	if( rhp_gcfg_enable_childsa_outb_after_n_secs ){

		time_t now = _rhp_get_time();
		time_t ts;

		if( (ts = now - childsa->created_time) < rhp_gcfg_enable_childsa_outb_after_n_secs ){
			RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_ENC_PACKET_CHILDSA_PENDING,"xxxdd",pkt,vpn,rlm,rhp_gcfg_enable_childsa_outb_after_n_secs,ts);
			err = RHP_STATUS_ESP_NO_CHILDSA;
			goto error_l;
		}
	}

	impl_ctx = (rhp_esp_impl_childsa_ctx*)childsa->get_esp_impl_ctx(childsa);
	if( impl_ctx == NULL ){
		RHP_BUG("");
		goto error_l;
	}

  tls_cache = _rhp_esp_impl_tls_cache_get(vpn->unique_id,impl_ctx->spi_inb);
  if( tls_cache == NULL ){

  	tls_cache = _rhp_esp_impl_tls_cache_alloc(vpn,childsa,NULL);

  	if( tls_cache == NULL ){

  		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_ENC_PACKET_FAIL_TO_ALLOC_TLS_CACHE,"xxxx",pkt,vpn,rlm,childsa);

  		err = _rhp_esp_impl_tx_encap_locked(pkt,vpn,childsa);
  		if( err ){
    		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_ENC_PACKET_TX_ENCAP_ERR,"xxxxE",pkt,vpn,rlm,childsa,err);
  			goto error_l;
  		}

  		goto locked_path_end;
  	}

  	_rhp_esp_impl_tls_cache_put(vpn->unique_id,impl_ctx->spi_inb,tls_cache); // Search by SPI for inbound.
  }


  tls_cache->tx_seq = childsa->tx_seq;

  tls_cache->pmtu_cache = childsa->pmtu_cache;

  if( !tls_cache->rx_udp_encap_from_remote_peer && vpn->nat_t_info.rx_udp_encap_from_remote_peer ){
  	tls_cache->rx_udp_encap_from_remote_peer = 1;
  }

  _rhp_esp_impl_sync_tx_addr_port(vpn,tls_cache);

  RHP_UNLOCK(&(vpn->lock));


	err = _rhp_esp_impl_tx_encap(pkt,tls_cache);
	if( err != RHP_STATUS_SUCCESS ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_ENC_PACKET_TX_ENCAP_ERR,"xxxxE",pkt,vpn,rlm,childsa,err);
		goto error;
	}


	RHP_LOCK(&(vpn->lock));

	childsa = vpn->childsa_get(vpn,RHP_DIR_OUTBOUND,spi_outb);
	if( childsa == NULL ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_ENC_PACKET_NO_CHILDSA_2,"xxx",pkt,vpn,rlm);
		err = RHP_STATUS_ESP_NO_CHILDSA;
		goto error_l;
	}

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_ENC_PACKET_CHILDSA_2,"xxxx",pkt,vpn,rlm,childsa);

	err = _rhp_esp_impl_sync_tls_cache_tx(vpn,childsa,tls_cache,pkt,0);
	if( err ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_ENC_PACKET_SYNC_TLS_CACHE_ERR,"xxxxE",pkt,vpn,rlm,childsa,err);
		goto error_l;
	}

locked_path_end:
	RHP_UNLOCK(&(vpn->lock));


	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_ENC_PACKET_RTRN,"xxxx",pkt,vpn,rlm,childsa);
	return 0;

error_l:
	RHP_UNLOCK(&(vpn->lock));
error:

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_ENC_PACKET_ERR,"xxxxE",pkt,vpn,rlm,childsa,err);
	return err;
}

int rhp_esp_impl_dec_packet(rhp_packet* pkt,rhp_vpn* vpn,rhp_vpn_realm* rlm,u32 spi_inb,u8* next_header_r,void* pend_ctx)
{
	int err = -EINVAL;
	rhp_childsa* childsa = NULL;
	rhp_esp_impl_tls_cache* tls_cache = NULL;
	rhp_esp_impl_childsa_ctx* impl_ctx = NULL;
	u32 rx_seq,seqh;

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_DEC_PACKET,"xxxHxxp",pkt,vpn,rlm,spi_inb,next_header_r,pend_ctx,pkt->len,pkt->data);

	RHP_LOCK(&(vpn->lock));

	if( !_rhp_atomic_read(&(vpn->is_active)) ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_DEC_PACKET_VPN_NOT_ACTIVE,"xxx",pkt,vpn,rlm);
		goto error_l;
  }

	childsa = vpn->childsa_get(vpn,RHP_DIR_INBOUND,spi_inb);
	if( childsa == NULL ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_DEC_PACKET_NO_CHILDSA,"xxx",pkt,vpn,rlm);
		err = RHP_STATUS_ESP_NO_CHILDSA;
		goto error_l;
	}

	impl_ctx = (rhp_esp_impl_childsa_ctx*)childsa->get_esp_impl_ctx(childsa);
	if( impl_ctx == NULL ){
		RHP_BUG("");
		goto error_l;
	}

	rx_seq = ntohl(pkt->app.esph->seq);

	seqh = rhp_esp_rx_get_esn_seqh(vpn,childsa,rx_seq);

  tls_cache = _rhp_esp_impl_tls_cache_get(vpn->unique_id,impl_ctx->spi_inb);
  if( tls_cache == NULL ){

  	tls_cache = _rhp_esp_impl_tls_cache_alloc(vpn,childsa,NULL);

  	if( tls_cache == NULL ){

  		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_DEC_PACKET_FAIL_TO_ALLOC_TLS_CACHE,"xxxxx",pkt,vpn,rlm,childsa,impl_ctx);

  		err = _rhp_esp_impl_rx_decap_locked(pkt,vpn,childsa,seqh,next_header_r);
  		if( err ){
    		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_DEC_PACKET_DECAP_LOCKED_ERR,"xxxxE",pkt,vpn,rlm,childsa,err);
  			goto error_l;
  		}

  		err = rhp_esp_rx_update_anti_replay(vpn,childsa,rx_seq);
  		if( err ){
    		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_DEC_PACKET_ANTI_REPLAY_ERR_1,"xxxxE",pkt,vpn,rlm,childsa,err);
  			goto error_l;
  		}

  		goto locked_path_end;
  	}

  	_rhp_esp_impl_tls_cache_put(vpn->unique_id,impl_ctx->spi_inb,tls_cache); // Search by SPI for inbound.
  }


  if( vpn->nat_t_info.exec_nat_t || vpn->nat_t_info.always_use_nat_t_port ){
  	tls_cache->udp_encap = 1;
  }else{
  	tls_cache->udp_encap = 0;
  }

	tls_cache->pmtu_cache = childsa->pmtu_cache;

  RHP_UNLOCK(&(vpn->lock));


	err = _rhp_esp_impl_rx_decap(pkt,tls_cache,seqh,next_header_r);
	if( err != RHP_STATUS_SUCCESS ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_DEC_PACKET_DECAP_ERR,"xxxxE",pkt,vpn,rlm,childsa,err);
		goto error;
	}


	RHP_LOCK(&(vpn->lock));

	if( !_rhp_atomic_read(&(vpn->is_active)) ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_DEC_PACKET_VPN_NOT_ACTIVE_2,"xxxx",pkt,vpn,rlm,childsa);
		goto error_l;
  }

	childsa = vpn->childsa_get(vpn,RHP_DIR_INBOUND,spi_inb);
	if( childsa == NULL ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_DEC_PACKET_NO_CHILDSA_2,"xxxx",pkt,vpn,rlm,childsa);
		err = RHP_STATUS_ESP_NO_CHILDSA;
		goto error_l;
	}

	err = _rhp_esp_impl_sync_tls_cache_rx(vpn,childsa,tls_cache,0);
	if( err ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_DEC_PACKET_SYNC_TLS_CACHE_ERR,"xxxxE",pkt,vpn,rlm,childsa,err);
		goto error_l;
	}

	err = rhp_esp_rx_update_anti_replay(vpn,childsa,rx_seq);
	if( err ){
		RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_DEC_PACKET_ANTI_REPLAY_ERR_2,"xxxxE",pkt,vpn,rlm,childsa,err);
		goto error_l;
	}

locked_path_end:
	RHP_UNLOCK(&(vpn->lock));

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_DEC_PACKET_RTRN,"xxxx",pkt,vpn,rlm,childsa);
	return 0;

error_l:
	RHP_UNLOCK(&(vpn->lock));
error:

	RHP_TRC_FREQ(0,RHPTRCID_ESP_IMPL_DEC_PACKET_ERR,"xxxxE",pkt,vpn,rlm,childsa,err);
	return err;
}


