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



static rhp_proto_gre* _rhp_gre_build_header(rhp_vpn* tx_vpn,rhp_packet* pkt)
{
	rhp_proto_gre* greh;

  RHP_TRC_FREQ(0,RHPTRCID_GRE_BUILD_HEADER,"x",pkt);

  if( pkt->type == RHP_PKT_GRE_NHRP ){

  	if( _rhp_pkt_pull(pkt,sizeof(rhp_proto_ether)) == NULL ){
  		RHP_BUG("");
  		return NULL;
  	}

  	//
  	// GRE's header already exists.
  	//

    RHP_TRC_FREQ(0,RHPTRCID_GRE_BUILD_HEADER_NHRP,"xa",pkt,(pkt->tail - (u8*)pkt->l3.nhrp_greh > 0 ? pkt->tail - (u8*)pkt->l3.nhrp_greh : 0),RHP_TRC_FMT_A_GRE_NHRP,0,0,(u8*)pkt->l3.nhrp_greh);

  	pkt->encap_mode = RHP_VPN_ENCAP_GRE;

    greh = pkt->l3.nhrp_greh;

  }else if( pkt->l2.eth->protocol == RHP_PROTO_ETH_IP ||
  					pkt->l2.eth->protocol == RHP_PROTO_ETH_IPV6 ){

  	if( _rhp_pkt_pull(pkt,sizeof(rhp_proto_ether)) == NULL ){
  		RHP_BUG("");
  		return NULL;
  	}

  	greh = (rhp_proto_gre*)rhp_pkt_expand_head(pkt,
  					sizeof(rhp_proto_gre) + (tx_vpn->gre.key_enabled ? sizeof(u32) : 0));
  	if( greh == NULL ){
  		RHP_BUG("");
  		return NULL;
  	}


  	greh->check_sum_flag = 0;
  	greh->reserved_flag0 = 0;
  	if( tx_vpn->gre.key_enabled ){
  		greh->key_flag = 1;
  	}else{
  		greh->key_flag = 0;
  	}
  	greh->seq_flag = 0;
  	greh->reserved_flag1 = 0;
  	greh->reserved_flag2 = 0;

  	greh->ver = 0;
  	greh->protocol_type = pkt->l2.eth->protocol;

  	if( tx_vpn->gre.key_enabled ){
  		*((u32*)(greh + 1)) = htonl(tx_vpn->gre.key);
  	}

  	pkt->encap_mode = RHP_VPN_ENCAP_GRE;

  	// Don't change pkt->l2.eth->protocol.

  }else{
    RHP_TRC_FREQ(0,RHPTRCID_GRE_BUILD_HEADER_NOT_SUP_PROTO,"xW",pkt,pkt->l2.eth->protocol);
  	return NULL;
  }

  RHP_TRC_FREQ(0,RHPTRCID_GRE_BUILD_HEADER_RTRN,"xxp",pkt,greh,(sizeof(rhp_proto_gre) + 32),pkt->data);

	return greh;
}

int rhp_gre_send(rhp_vpn* tx_vpn,rhp_packet* pkt)
{
	rhp_proto_gre* greh;

  RHP_TRC_FREQ(0,RHPTRCID_GRE_SEND,"xxxd",tx_vpn,pkt,pkt->l2.eth,pkt->type);

  if( tx_vpn == NULL || pkt->l2.eth == NULL ){
  	RHP_BUG("");
  	return 0;
  }

	greh = _rhp_gre_build_header(tx_vpn,pkt);
	if( greh == NULL ){
		return -EINVAL;
	}

	rhp_pkt_trace_dump("rhp_gre_send(2)",pkt);

	rhp_esp_send(tx_vpn,pkt);

  RHP_TRC_FREQ(0,RHPTRCID_GRE_SEND_RTRN,"xx",tx_vpn,pkt);
	return 0;
}

// rx_vpn may be NULL.
int rhp_gre_send_flooding(unsigned long rlm_id,rhp_packet* pkt,
		rhp_vpn* rx_vpn/* For split-horizon*/,int dont_fwd_pkts_btwn_clts)
{
	int err;
	rhp_proto_gre* greh;
	u8* unique_ids = NULL;
	int unique_ids_num = 0;
	int free_by_caller = 0;
	rhp_vpn* tx_vpn = NULL;
	void* tx_vpn_ref = NULL;
	int i;
	int n_no_gre = 0;

  RHP_TRC_FREQ(0,RHPTRCID_GRE_SEND_FLOODING,"uxxdd",rlm_id,pkt,rx_vpn,dont_fwd_pkts_btwn_clts,(rx_vpn ? rx_vpn->peer_is_remote_client : -1));

	err = rhp_vpn_enum_unique_ids(rlm_id,&unique_ids,&unique_ids_num,&free_by_caller);
	if( err ){

		rhp_esp_g_statistics_inc(tx_esp_no_childsa_err_packets);

		RHP_TRC_FREQ(0,RHPTRCID_GRE_SEND_FLOODING_ENUM_UNIQ_ID_FAILED,"uxxE",rlm_id,pkt,rx_vpn,err);
		return err;
	}

	for( i = 0; i < unique_ids_num; i++){

		u8* unq_id = unique_ids + (RHP_VPN_UNIQUE_ID_SIZE*i);

		tx_vpn_ref = rhp_vpn_get_by_unique_id(unq_id);
		tx_vpn = RHP_VPN_REF(tx_vpn_ref);

	  RHP_TRC_FREQ(0,RHPTRCID_GRE_SEND_FLOODING_TX_VPN,"xp",tx_vpn,RHP_VPN_UNIQUE_ID_SIZE,unq_id);

		if( tx_vpn ){

			rhp_packet* pkt_d = NULL;

			if( tx_vpn == rx_vpn ){
				goto next;
			}

			if( dont_fwd_pkts_btwn_clts &&
					tx_vpn->peer_is_remote_client &&
					(rx_vpn && rx_vpn->peer_is_remote_client) ){
				goto next;
			}

			RHP_LOCK(&(tx_vpn->lock));
			{
				if( tx_vpn->internal_net_info.encap_mode_c != RHP_VPN_ENCAP_GRE ){
					RHP_UNLOCK(&(tx_vpn->lock));
					n_no_gre++;
					goto next;
				}
			}
			RHP_UNLOCK(&(tx_vpn->lock));

			pkt_d = rhp_pkt_dup(pkt);
			if( pkt_d ){

				greh = _rhp_gre_build_header(tx_vpn,pkt_d);
				if( greh == NULL ){
					goto next;
				}

				pkt_d->rx_if_index = pkt->rx_if_index;
				pkt_d->rx_ifc = pkt->rx_ifc;
				if( pkt_d->rx_ifc ){
					rhp_ifc_hold(pkt_d->rx_ifc);
				}

				rhp_esp_send(tx_vpn,pkt_d);

			}else{
				RHP_BUG("");
			}

next:
			rhp_vpn_unhold(tx_vpn_ref);
			if( pkt_d ){
				rhp_pkt_unhold(pkt_d);
			}
		}
	}

	if( free_by_caller ){
		_rhp_free(unique_ids);
	}

	if( n_no_gre ){
		goto no_gre;
	}

  RHP_TRC_FREQ(0,RHPTRCID_GRE_SEND_FLOODING_RTRN,"uxx",rlm_id,pkt,rx_vpn);
	return 0;

no_gre:
	RHP_TRC_FREQ(0,RHPTRCID_GRE_SEND_FLOODING_ERR_NO_GRE_ENCAP,"uxxd",rlm_id,pkt,rx_vpn,n_no_gre);
	return RHP_STATUS_NO_GRE_ENCAP;
}

int rhp_gre_send_access_point(rhp_vpn_realm* tx_rlm,rhp_packet* pkt)
{
	int err = -EINVAL;
	rhp_proto_gre* greh;
  rhp_vpn* tx_vpn = NULL;
  rhp_vpn_ref* tx_vpn_ref = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_GRE_SEND_ACCESS_POINT,"xxx",tx_rlm,pkt,tx_rlm->access_point_peer_vpn_ref);

  RHP_LOCK(&(tx_rlm->lock));
  {

  	if( !_rhp_atomic_read(&(tx_rlm->is_active)) ){
			RHP_TRC_FREQ(0,RHPTRCID_GRE_SEND_ACCESS_POINT_RLM_NOT_ACTIVE,"xx",tx_rlm,pkt);
			goto error_l;
		}

		if( tx_rlm->access_point_peer_vpn_ref ){
			tx_vpn = RHP_VPN_REF(tx_rlm->access_point_peer_vpn_ref);
			tx_vpn_ref = rhp_vpn_hold_ref(tx_vpn);
		}
  }
  RHP_UNLOCK(&(tx_rlm->lock));


  if( tx_vpn ){

  	RHP_LOCK(&(tx_vpn->lock));
  	{
  		if( tx_vpn->internal_net_info.encap_mode_c != RHP_VPN_ENCAP_GRE ){

  			RHP_UNLOCK(&(tx_vpn->lock));
  			rhp_vpn_unhold(tx_vpn_ref);

  			goto no_gre;
  		}
  	}
  	RHP_UNLOCK(&(tx_vpn->lock));

		greh = _rhp_gre_build_header(tx_vpn,pkt);
		if( greh ){

			rhp_esp_send(tx_vpn,pkt);

		}else{

			// RHP_BUG() in _rhp_gre_build_header().
		}

		rhp_vpn_unhold(tx_vpn_ref);

  }else{

  	rhp_esp_g_statistics_inc(tx_esp_no_childsa_err_packets);

  	RHP_TRC_FREQ(0,RHPTRCID_GRE_SEND_ACCESS_POINT_NO_PEER_VPN,"xx",tx_rlm,pkt);

  	goto no_tx_vpn;
  }

  RHP_TRC_FREQ(0,RHPTRCID_GRE_SEND_ACCESS_POINT_RTRN,"xx",tx_rlm,pkt);
	return 0;

no_gre:
	RHP_TRC_FREQ(0,RHPTRCID_GRE_SEND_ACCESS_POINT_NO_GRE_ENCAP,"xx",tx_rlm,pkt);
	return RHP_STATUS_NO_GRE_ENCAP;

no_tx_vpn:
	RHP_TRC_FREQ(0,RHPTRCID_GRE_SEND_ACCESS_POINT_NO_TX_VPN,"xx",tx_rlm,pkt);
	return RHP_STATUS_TX_ACCESS_POINT_NO_VPN;

error_l:
	RHP_UNLOCK(&(tx_rlm->lock));
  RHP_TRC_FREQ(0,RHPTRCID_GRE_SEND_ACCESS_POINT_ERR,"xxE",tx_rlm,pkt,err);
	return err;
}

int rhp_gre_check_header(rhp_proto_gre* greh)
{
	if( greh->ver != RHP_PROTO_GRE_VERSION ){
		RHP_TRC_FREQ(0,RHPTRCID_GRE_CHECK_HEADER_BAD_HDR,"p",sizeof(rhp_proto_gre),greh);
		return -1;
	}

	RHP_TRC_FREQ(0,RHPTRCID_GRE_CHECK_HEADER_OK,"p",sizeof(rhp_proto_gre),greh);
	return 0;
}

int rhp_gre_recv(rhp_packet* pkt,rhp_vpn* rx_vpn)
{
	int err = -EINVAL;
	rhp_proto_ether* ethh;
	int gre_len = (int)sizeof(rhp_proto_gre);
	u32 vpn_realm_id;
	rhp_vpn_realm* rx_rlm = NULL;
	u16 greh_protocol_type;
	int dmvpn_enabled = 0;

	RHP_TRC_FREQ(0,RHPTRCID_GRE_RECV,"xxdk",pkt,rx_vpn,rx_vpn->gre.key_enabled,rx_vpn->gre.key);
	rhp_pkt_trace_dump("rhp_gre_recv(1)",pkt);

	if( pkt->len < (int)sizeof(rhp_proto_gre) ){
		err = RHP_STATUS_BAD_PACKET;
		RHP_TRC_FREQ(0,RHPTRCID_GRE_RECV_PKT_TOO_SHORT,"xxdd",pkt,rx_vpn,pkt->len,(int)sizeof(rhp_proto_etherip) + (int)sizeof(rhp_proto_ether));
		goto error;
	}

	if( _rhp_pkt_try_pull(pkt,sizeof(rhp_proto_gre)) ){
		err = RHP_STATUS_BAD_PACKET;
		RHP_TRC_FREQ(0,RHPTRCID_GRE_RECV_BAD_PKT_1,"xx",pkt,rx_vpn);
		goto error;
	}

	{
		rhp_proto_gre* greh;
		u8 *greh_p;

		greh = (rhp_proto_gre*)pkt->data;
		greh_p = (u8*)(greh + 1);


		if( rhp_gre_check_header(greh) ){
			err = RHP_STATUS_BAD_PACKET;
			RHP_TRC_FREQ(0,RHPTRCID_GRE_RECV_BAD_HEADER,"xx",pkt,rx_vpn);
			goto error;
		}


		if( greh->check_sum_flag ){

			if( _rhp_pkt_try_pull(pkt,sizeof(rhp_proto_gre_csum)) ){
				err = RHP_STATUS_BAD_PACKET;
				RHP_TRC_FREQ(0,RHPTRCID_GRE_RECV_BAD_PKT_CSUM_1,"xx",pkt,rx_vpn);
				goto error;
			}

			gre_len = (int)sizeof(rhp_proto_gre_csum); // Including a GRE common header.
			greh_p = ((u8*)greh) + (int)sizeof(rhp_proto_gre_csum);
		}


		if( (rx_vpn->gre.key_enabled && !greh->key_flag) ||
				(!rx_vpn->gre.key_enabled && greh->key_flag) ){

			err = RHP_STATUS_BAD_PACKET;
			RHP_TRC_FREQ(0,RHPTRCID_GRE_RECV_BAD_PKT_KEY_0,"xxddp",pkt,rx_vpn,rx_vpn->gre.key_enabled,greh->key_flag,gre_len,greh);
			goto error;
		}

		if( greh->key_flag ){

			if( _rhp_pkt_try_pull(pkt,gre_len + (int)sizeof(u32)) ){
				err = RHP_STATUS_BAD_PACKET;
				RHP_TRC_FREQ(0,RHPTRCID_GRE_RECV_BAD_PKT_KEY_1,"xx",pkt,rx_vpn);
				goto error;
			}

			gre_len += (int)sizeof(u32);

			if( *((u32*)greh_p) != htonl(rx_vpn->gre.key) ){
				err = RHP_STATUS_BAD_PACKET;
				RHP_TRC_FREQ(0,RHPTRCID_GRE_RECV_BAD_PKT_KEY_2,"xxpUU",pkt,rx_vpn,gre_len,greh,*((u32*)greh_p),rx_vpn->gre.key);
				goto error;
			}

			greh_p += (int)sizeof(u32);
		}

		if( greh->seq_flag ){

			if( _rhp_pkt_try_pull(pkt,gre_len + (int)sizeof(u32)) ){
				err = RHP_STATUS_BAD_PACKET;
				RHP_TRC_FREQ(0,RHPTRCID_GRE_RECV_BAD_PKT_SEQ_1,"xx",pkt,rx_vpn);
				goto error;
			}

			gre_len += (int)sizeof(u32);
			greh_p += (int)sizeof(u32);
		}


		if( greh->protocol_type == RHP_PROTO_ETH_IP ||
				greh->protocol_type == RHP_PROTO_ETH_IPV6 ){

			// Remove GRE header.
			if( _rhp_pkt_pull(pkt,gre_len) == NULL ){
				err = RHP_STATUS_BAD_PACKET;
				RHP_TRC_FREQ(0,RHPTRCID_GRE_RECV_BAD_PKT_2,"xx",pkt,rx_vpn);
				goto error;
			}

		}else if( greh->protocol_type == RHP_PROTO_ETH_NHRP ){

			// Nothing to do.

		}else{

			err = RHP_STATUS_BAD_PACKET;
			RHP_TRC_FREQ(0,RHPTRCID_GRE_RECV_UNSUP_PKT_1,"xxWp",pkt,rx_vpn,greh->protocol_type,sizeof(rhp_proto_gre),(u8*)greh);
			goto error;
		}

		greh_protocol_type = greh->protocol_type;
	}


	{
		ethh = (rhp_proto_ether*)rhp_pkt_expand_head(pkt,sizeof(rhp_proto_ether));
		if( ethh == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}


		RHP_LOCK(&(rx_vpn->lock));
		{
			if( rx_vpn->internal_net_info.encap_mode_c != RHP_VPN_ENCAP_GRE ){

				err = -EINVAL;
				RHP_TRC_FREQ(0,RHPTRCID_GRE_RECV_NOT_ENCAP_GRE_1,"xxLd",pkt,rx_vpn,"VPN_ENCAP",rx_vpn->internal_net_info.encap_mode_c);

				RHP_UNLOCK(&(rx_vpn->lock));
				goto error;
			}

			memcpy(ethh->src_addr,rx_vpn->internal_net_info.dummy_peer_mac,6);

			vpn_realm_id = rx_vpn->vpn_realm_id;

			dmvpn_enabled = rx_vpn->nhrp.dmvpn_enabled;

			rx_rlm = rx_vpn->rlm;
			if( rx_rlm == NULL ){

				err = -EINVAL;
				RHP_TRC_FREQ(0,RHPTRCID_GRE_RECV_NOT_ENCAP_GRE_NO_RLM,"xx",pkt,rx_vpn);

				RHP_UNLOCK(&(rx_vpn->lock));
				goto error;
			}

			rhp_realm_hold(rx_vpn->rlm);
		}
		RHP_UNLOCK(&(rx_vpn->lock));

		ethh->protocol = greh_protocol_type;
	}


	if( ethh->protocol == RHP_PROTO_ETH_IP ){

		pkt->type = RHP_PKT_PLAIN_ETHER_TAP;
		pkt->l2.eth = ethh;
		pkt->l3.raw = (u8*)(ethh + 1);
		pkt->l4.raw = NULL;

		rhp_pkt_trace_dump("rhp_gre_recv(v4)",pkt);

		err = rhp_bridge_pkt_from_vpn_ipv4_arp_rslv(vpn_realm_id,
						rx_vpn,rx_rlm,pkt,dmvpn_enabled);
		if( err ){
			RHP_TRC_FREQ(0,RHPTRCID_GRE_RECV_ARP_RSLV_ERR,"xxE",pkt,rx_vpn,err);
			goto error;
		}

	}else if( ethh->protocol == RHP_PROTO_ETH_IPV6 ){

		pkt->type = RHP_PKT_PLAIN_ETHER_TAP;
		pkt->l2.eth = ethh;
		pkt->l3.raw = (u8*)(ethh + 1);;
		pkt->l4.raw = NULL;

		rhp_pkt_trace_dump("rhp_gre_recv(v6)",pkt);

		err = rhp_bridge_pkt_from_vpn_ipv6_nd_rslv(vpn_realm_id,
						rx_vpn,rx_rlm,pkt,dmvpn_enabled);
		if( err ){
			RHP_TRC_FREQ(0,RHPTRCID_GRE_RECV_IPV6_ND_RSLV_ERR,"xxE",pkt,rx_vpn,err);
			goto error;
		}

	}else if( ethh->protocol == RHP_PROTO_ETH_NHRP ){

		pkt->type = RHP_PKT_GRE_NHRP;

		pkt->l3.nhrp_greh = (rhp_proto_gre*)(ethh + 1);
		pkt->l4.nhrph = (rhp_proto_nhrp*)(((u8*)pkt->l3.nhrp_greh) + gre_len);


		err = rhp_rx_nhrp_from_vpn(vpn_realm_id,rx_vpn,pkt);
		if( err ){
			RHP_TRC_FREQ(0,RHPTRCID_GRE_RECV_NHRP_FROM_VPN_ERR,"xxE",pkt,rx_vpn,err);
			goto error;
		}

	}else{

		err = RHP_STATUS_BAD_PACKET;
		RHP_TRC_FREQ(0,RHPTRCID_GRE_RECV_UNSUP_PKT_2,"xxWp",pkt,rx_vpn,greh_protocol_type,sizeof(rhp_proto_ether),(u8*)ethh);
		goto error;
	}

	if( rx_rlm ){
		rhp_realm_unhold(rx_rlm);
	}

	RHP_TRC_FREQ(0,RHPTRCID_GRE_RECV_RTRN,"xxx",pkt,rx_vpn,rx_rlm);
	return 0;

error:

	if( rx_rlm ){
		rhp_realm_unhold(rx_rlm);
	}

	RHP_TRC_FREQ(0,RHPTRCID_GRE_RECV_ERR,"xxE",pkt,rx_vpn,err);
	return err;
}


