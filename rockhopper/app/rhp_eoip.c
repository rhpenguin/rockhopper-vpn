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
#include "rhp_config.h"
#include "rhp_vpn.h"
#include "rhp_ikev2.h"
#include "rhp_ikev2_mesg.h"
#include "rhp_forward.h"
#include "rhp_eoip.h"
#include "rhp_esp.h"

//
// TODO : If a mac address collision between peers occurs, we should consider
// mac address translation from vpn->internal_net.peer_mac to vpn->internal_net.dummy_mac
// before/after bridging packets.
//

static rhp_proto_etherip* _rhp_eoip_build_header(rhp_packet* pkt)
{
	rhp_proto_etherip* ethiph;

  RHP_TRC_FREQ(0,RHPTRCID_EOIP_BUILD_HEADER,"x",pkt);

	ethiph = (rhp_proto_etherip*)rhp_pkt_expand_head(pkt,sizeof(rhp_proto_etherip));
	if( ethiph == NULL ){
		RHP_BUG("");
		return NULL;
	}

	ethiph->ver = RHP_PROTO_ETHERIP_VER;
	ethiph->reserved = RHP_PROTO_ETHERIP_RESERVED;
	ethiph->reserved1 = RHP_PROTO_ETHERIP_RESERVED;

	pkt->encap_mode = RHP_VPN_ENCAP_ETHERIP;

	// Don't change pkt->l2.eth->protocol.

  RHP_TRC_FREQ(0,RHPTRCID_EOIP_BUILD_HEADER_RTRN,"xp",pkt,(sizeof(rhp_proto_etherip) + 32),pkt->data);

	return ethiph;
}

int rhp_eoip_send(rhp_vpn* tx_vpn,rhp_packet* pkt)
{
	rhp_proto_etherip* ethiph;

  RHP_TRC_FREQ(0,RHPTRCID_EOIP_SEND,"xx",tx_vpn,pkt);

  if( tx_vpn == NULL ){
  	RHP_BUG("");
  	return 0;
  }

	ethiph = _rhp_eoip_build_header(pkt);
	if( ethiph == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	rhp_pkt_trace_dump("rhp_eoip_send(2)",pkt);

	rhp_esp_send(tx_vpn,pkt);

  RHP_TRC_FREQ(0,RHPTRCID_EOIP_SEND_RTRN,"xx",tx_vpn,pkt);
	return 0;
}

// rx_vpn may be NULL.
int rhp_eoip_send_flooding(unsigned long rlm_id,rhp_packet* pkt,
		rhp_vpn* rx_vpn/* For split-horizon*/,int dont_fwd_pkts_btwn_clts)
{
	int err;
	rhp_proto_etherip* ethiph;
	u8* unique_ids = NULL;
	int unique_ids_num = 0;
	int free_by_caller = 0;
	rhp_vpn* tx_vpn = NULL;
	void* tx_vpn_ref = NULL;
	int i;
	int n_no_etherip = 0;

  RHP_TRC_FREQ(0,RHPTRCID_EOIP_SEND_FLOODING,"uxxdd",rlm_id,pkt,rx_vpn,dont_fwd_pkts_btwn_clts,(rx_vpn ? rx_vpn->peer_is_remote_client : -1));

	err = rhp_vpn_enum_unique_ids(rlm_id,&unique_ids,&unique_ids_num,&free_by_caller);
	if( err ){

		rhp_esp_g_statistics_inc(tx_esp_no_childsa_err_packets);

		RHP_TRC_FREQ(0,RHPTRCID_EOIP_SEND_FLOODING_ENUM_UNIQ_ID_FAILED,"uxxE",rlm_id,pkt,rx_vpn,err);
		return err;
	}

	for( i = 0; i < unique_ids_num; i++){

		u8* unq_id = unique_ids + (RHP_VPN_UNIQUE_ID_SIZE*i);

		tx_vpn_ref = rhp_vpn_get_by_unique_id(unq_id);
		tx_vpn = RHP_VPN_REF(tx_vpn_ref);

	  RHP_TRC_FREQ(0,RHPTRCID_EOIP_SEND_FLOODING_TX_VPN,"xp",tx_vpn,RHP_VPN_UNIQUE_ID_SIZE,unq_id);

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
				if( tx_vpn->internal_net_info.encap_mode_c != RHP_VPN_ENCAP_ETHERIP ){
					RHP_UNLOCK(&(tx_vpn->lock));
					n_no_etherip++;
					goto next;
				}
			}
			RHP_UNLOCK(&(tx_vpn->lock));

			pkt_d = rhp_pkt_dup(pkt);
			if( pkt_d ){

				ethiph = _rhp_eoip_build_header(pkt_d);
				if( ethiph == NULL ){
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

	if( n_no_etherip ){
		goto no_etherip;
	}

  RHP_TRC_FREQ(0,RHPTRCID_EOIP_SEND_FLOODING_RTRN,"uxx",rlm_id,pkt,rx_vpn);
	return 0;

no_etherip:
	RHP_TRC_FREQ(0,RHPTRCID_EOIP_SEND_FLOODING_ERR_NO_ETHERIP_ENCAP,"uxxd",rlm_id,pkt,rx_vpn,n_no_etherip);
	return RHP_STATUS_NO_ETHERIP_ENCAP;
}

int rhp_eoip_send_access_point(rhp_vpn_realm* tx_rlm,rhp_packet* pkt)
{
	int err = -EINVAL;
	rhp_proto_etherip* ethiph;
  rhp_vpn* tx_vpn = NULL;
  rhp_vpn_ref* tx_vpn_ref = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_EOIP_SEND_ACCESS_POINT,"xxx",tx_rlm,pkt,tx_rlm->access_point_peer_vpn_ref);

  RHP_LOCK(&(tx_rlm->lock));
  {

  	if( !_rhp_atomic_read(&(tx_rlm->is_active)) ){
			RHP_TRC_FREQ(0,RHPTRCID_EOIP_SEND_ACCESS_POINT_RLM_NOT_ACTIVE,"xx",tx_rlm,pkt);
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
  		if( tx_vpn->internal_net_info.encap_mode_c != RHP_VPN_ENCAP_ETHERIP ){

  			RHP_UNLOCK(&(tx_vpn->lock));
  			rhp_vpn_unhold(tx_vpn_ref);

  			goto no_etherip;
  		}
  	}
  	RHP_UNLOCK(&(tx_vpn->lock));

		ethiph = _rhp_eoip_build_header(pkt);
		if( ethiph ){
			rhp_esp_send(tx_vpn,pkt);
		}else{
			// RHP_BUG() in _rhp_eoip_build_header().
		}

		rhp_vpn_unhold(tx_vpn_ref);

  }else{

  	rhp_esp_g_statistics_inc(tx_esp_no_childsa_err_packets);

  	RHP_TRC_FREQ(0,RHPTRCID_EOIP_SEND_ACCESS_POINT_NO_PEER_VPN,"xx",tx_rlm,pkt);
  }

  RHP_TRC_FREQ(0,RHPTRCID_EOIP_SEND_ACCESS_POINT_RTRN,"xx",tx_rlm,pkt);
	return 0;

no_etherip:
	RHP_TRC_FREQ(0,RHPTRCID_EOIP_SEND_ACCESS_POINT_NO_ETHERIP_ENCAP,"xx",tx_rlm,pkt);
	return RHP_STATUS_NO_ETHERIP_ENCAP;

error_l:
	RHP_UNLOCK(&(tx_rlm->lock));
  RHP_TRC_FREQ(0,RHPTRCID_EOIP_SEND_ACCESS_POINT_ERR,"xxE",tx_rlm,pkt,err);
	return err;
}

int rhp_eoip_check_header(rhp_proto_etherip* ethiph)
{
	if( ethiph->ver != RHP_PROTO_ETHERIP_VER ||
			ethiph->reserved != RHP_PROTO_ETHERIP_RESERVED ||
			ethiph->reserved1 != RHP_PROTO_ETHERIP_RESERVED ){

		RHP_TRC_FREQ(0,RHPTRCID_EOIP_CHECK_HEADER_BAD_HDR,"p",sizeof(rhp_proto_etherip),ethiph);
		return -1;
	}

	RHP_TRC_FREQ(0,RHPTRCID_EOIP_CHECK_HEADER_OK,"p",sizeof(rhp_proto_etherip),ethiph);
	return 0;
}

int rhp_eoip_recv(rhp_packet* pkt,rhp_vpn* rx_vpn)
{
	int err = -EINVAL;
	rhp_proto_etherip* ethiph;
	rhp_proto_ether* ethh;

	RHP_TRC_FREQ(0,RHPTRCID_EOIP_RECV,"xx",pkt,rx_vpn);
	rhp_pkt_trace_dump("rhp_eoip_recv(1)",pkt);

	if( pkt->len < (int)sizeof(rhp_proto_etherip) + (int)sizeof(rhp_proto_ether) ){
		err = RHP_STATUS_BAD_PACKET;
		RHP_TRC_FREQ(0,RHPTRCID_EOIP_RECV_PKT_TOO_SHORT,"xxdd",pkt,rx_vpn,pkt->len,(int)sizeof(rhp_proto_etherip) + (int)sizeof(rhp_proto_ether));
		goto error;
	}

	ethiph = (rhp_proto_etherip*)_rhp_pkt_pull(pkt,sizeof(rhp_proto_etherip));
	if( ethiph == NULL ){
		err = RHP_STATUS_BAD_PACKET;
		RHP_TRC_FREQ(0,RHPTRCID_EOIP_RECV_BAD_PKT_1,"xx",pkt,rx_vpn);
		goto error;
	}

	if( rhp_eoip_check_header(ethiph) ){
		err = RHP_STATUS_BAD_PACKET;
		RHP_TRC_FREQ(0,RHPTRCID_EOIP_RECV_BAD_HEADER,"xx",pkt,rx_vpn);
		goto error;
	}


	if( _rhp_pkt_try_pull(pkt,sizeof(rhp_proto_ether)) ){
		err = RHP_STATUS_BAD_PACKET;
		RHP_TRC_FREQ(0,RHPTRCID_EOIP_RECV_BAD_PKT_2,"xx",pkt,rx_vpn);
		goto error;
	}

	ethh = (rhp_proto_ether*)pkt->data;

	pkt->type = RHP_PKT_PLAIN_ETHER_TAP;
	pkt->l2.eth = ethh;
	pkt->l3.raw = (u8*)(ethh + 1);
	pkt->l4.raw = NULL;

	rhp_pkt_trace_dump("rhp_eoip_recv(2)",pkt);

	err = rhp_bridge_pkt_from_vpn(pkt,rx_vpn);
	if( err ){
		RHP_TRC_FREQ(0,RHPTRCID_EOIP_RECV_FAIL_TO_BRIDGE_PKT_FROM_VPN,"xxE",pkt,rx_vpn,err);
		goto error;
	}

	RHP_TRC_FREQ(0,RHPTRCID_EOIP_RECV_RTRN,"xx",pkt,rx_vpn);
	return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_EOIP_RECV_ERR,"xxE",pkt,rx_vpn,err);
	return err;
}



