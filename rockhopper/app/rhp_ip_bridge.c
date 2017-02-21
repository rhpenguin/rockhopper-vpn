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
#include "rhp_esp.h"


static u8* _rhp_ip_bridge_build_header(rhp_packet* pkt)
{
	u8* data;

  RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_BUILD_HEADER,"xd",pkt,pkt->len);

	if( pkt->l2.eth->protocol != RHP_PROTO_ETH_IP &&
			pkt->l2.eth->protocol != RHP_PROTO_ETH_IPV6 ){
	  RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_BUILD_HEADER_ERR,"xW",pkt,pkt->l2.eth->protocol);
		return NULL;
	}

	data = _rhp_pkt_pull(pkt,sizeof(rhp_proto_ether));
	if( data == NULL ){
		RHP_BUG("");
		return NULL;
	}

	pkt->encap_mode = RHP_VPN_ENCAP_IPIP;

  RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_BUILD_HEADER_RTRN,"xdp",pkt,pkt->len,pkt->len,pkt->data);

  return data;
}

int rhp_ip_bridge_send(rhp_vpn* tx_vpn,rhp_packet* pkt)
{
	int err = -EINVAL;
	u8* data;

  RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_SEND,"xx",tx_vpn,pkt);
	rhp_pkt_trace_dump("rhp_ip_bridge_send(1)",pkt);

  if( tx_vpn == NULL ){
  	RHP_BUG("");
  	return 0;
  }

	if( rhp_gcfg_ipv6_disabled && pkt->l2.eth->protocol == RHP_PROTO_ETH_IPV6 ){
	  RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_SEND_IPV6_DISABLED,"xx",tx_vpn,pkt);
		return 0;
	}


	data = _rhp_ip_bridge_build_header(pkt);
	if( data == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	rhp_pkt_trace_dump("rhp_ip_bridge_send(2)",pkt);

	rhp_esp_send(tx_vpn,pkt);

  RHP_TRC_FREQ(0,RHPTRCID_RHPTRCID_IP_BRIDGE_SEND_RTRN,"xx",tx_vpn,pkt);
	return 0;
}

// rx_vpn may be NULL.
int rhp_ip_bridge_send_flooding(unsigned long rlm_id,rhp_packet* pkt,rhp_vpn* rx_vpn,
		int dont_fwd_pkts_btwn_clts)
{
	int err;
	u8* data;
	u8* unique_ids;
	int unique_ids_num;
	int free_by_caller = 0;
	rhp_vpn* tx_vpn = NULL;
	void* tx_vpn_ref = NULL;
	int i;
	int n_no_ipip = 0;

  RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_SEND_FLOODING,"uxxdd",rlm_id,pkt,rx_vpn,dont_fwd_pkts_btwn_clts,(rx_vpn ? rx_vpn->peer_is_remote_client : -1));
	rhp_pkt_trace_dump("rhp_ip_bridge_send_flooding(1)",pkt);

	if( rhp_gcfg_ipv6_disabled && pkt->l2.eth->protocol == RHP_PROTO_ETH_IPV6 ){
	  RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_SEND_FLOODING_IPV6_DISABLED,"xx",tx_vpn,pkt);
		return 0;
	}

	err = rhp_vpn_enum_unique_ids(rlm_id,&unique_ids,&unique_ids_num,&free_by_caller);
	if( err ){

  	rhp_esp_g_statistics_inc(tx_esp_no_childsa_err_packets);

  	RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_SEND_FLOODING_ENUM_UNIQ_ID_FAILED,"uxxE",rlm_id,pkt,rx_vpn,err);
		return err;
	}

	for( i = 0; i < unique_ids_num; i++){

		u8* unq_id = unique_ids + (RHP_VPN_UNIQUE_ID_SIZE*i);

		tx_vpn_ref = rhp_vpn_get_by_unique_id(unq_id);
		tx_vpn = RHP_VPN_REF(tx_vpn_ref);

	  RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_SEND_FLOODING_TX_VPN,"xp",tx_vpn,RHP_VPN_UNIQUE_ID_SIZE,unq_id);

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
				if( tx_vpn->internal_net_info.encap_mode_c != RHP_VPN_ENCAP_IPIP ){
					RHP_UNLOCK(&(tx_vpn->lock));
					n_no_ipip++;
					goto next;
				}
			}
			RHP_UNLOCK(&(tx_vpn->lock));

			pkt_d = rhp_pkt_dup(pkt);
			if( pkt_d ){

				rhp_pkt_trace_dump("rhp_ip_bridge_send_flooding(2)",pkt);

				data = _rhp_ip_bridge_build_header(pkt_d);
				if( data == NULL ){
					goto next;
				}

				pkt_d->rx_if_index = pkt->rx_if_index;
				pkt_d->rx_ifc = pkt->rx_ifc;
				if( pkt_d->rx_ifc ){
					rhp_ifc_hold(pkt_d->rx_ifc);
				}

				rhp_pkt_trace_dump("rhp_ip_bridge_send_flooding(3)",pkt);

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

	if( n_no_ipip ){
		goto no_ipip;
	}

  RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_SEND_FLOODING_RTRN,"uxx",rlm_id,pkt,rx_vpn);
	return 0;

no_ipip:
	RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_SEND_FLOODING_NO_IPIP_ENCAP,"uxxd",rlm_id,pkt,rx_vpn,n_no_ipip);
	return RHP_STATUS_NO_IPIP_ENCAP;
}

int rhp_ip_bridge_send_access_point(rhp_vpn_realm* tx_rlm,rhp_packet* pkt)
{
	int err = -EINVAL;
	u8* data;
  rhp_vpn_ref* tx_vpn_ref = NULL;
  rhp_vpn* tx_vpn = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_SEND_ACCESS_POINT,"xx",tx_rlm,pkt);
	rhp_pkt_trace_dump("rhp_ip_bridge_send_access_point(1)",pkt);

	if( rhp_gcfg_ipv6_disabled && pkt->l2.eth->protocol == RHP_PROTO_ETH_IPV6 ){
	  RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_SEND_ACCESS_POINT_IPV6_DISABLED,"xx",tx_rlm,pkt);
		return 0;
	}


  RHP_LOCK(&(tx_rlm->lock));
  {

		if( !_rhp_atomic_read(&(tx_rlm->is_active)) ){
			RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_SEND_ACCESS_POINT_RLM_NOT_ACTIVE,"xx",tx_rlm,pkt);
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
  		if( tx_vpn->internal_net_info.encap_mode_c != RHP_VPN_ENCAP_IPIP ){

  			RHP_UNLOCK(&(tx_vpn->lock));
  			rhp_vpn_unhold(tx_vpn_ref);

  			goto no_ipip;
  		}
  	}
  	RHP_UNLOCK(&(tx_vpn->lock));

		data = _rhp_ip_bridge_build_header(pkt);
		if( data ){

			rhp_pkt_trace_dump("rhp_ip_bridge_send_access_point(2)",pkt);

			rhp_esp_send(tx_vpn,pkt);

		}else{
			// RHP_BUG() in _rhp_eoip_build_header().
		}

		rhp_vpn_unhold(tx_vpn_ref);

  }else{

  	rhp_esp_g_statistics_inc(tx_esp_no_childsa_err_packets);

    RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_SEND_ACCESS_POINT_NO_PEER_VPN,"xxx",tx_rlm,pkt,tx_vpn);
  }

  RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_SEND_ACCESS_POINT_RTRN,"xxx",tx_rlm,pkt,tx_vpn);
	return 0;


no_ipip:
	RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_SEND_ACCESS_POINT_NO_IPIP_ENCAP,"xxx",tx_rlm,pkt,tx_vpn);
	return RHP_STATUS_NO_IPIP_ENCAP;


error_l:
	RHP_UNLOCK(&(tx_rlm->lock));
error:
	RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_SEND_ACCESS_POINT_ERR,"xxxE",tx_rlm,pkt,tx_vpn,err);
	return err;
}

int rhp_ip_bridge_recv(rhp_packet* pkt,rhp_vpn* rx_vpn,u8 protocol)
{
	int err = -EINVAL;
	rhp_proto_ether* ethh;
	u32 vpn_realm_id;
	u8* data;
	rhp_vpn_realm* rx_rlm = NULL;

	RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_RECV,"xxb",pkt,rx_vpn,protocol);
	rhp_pkt_trace_dump("rhp_ip_bridge_recv(1)",pkt);

	if( protocol != RHP_PROTO_IP_IP &&
			protocol != RHP_PROTO_IP_IPV6 ){
		err = -EINVAL;
		RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_RECV_NOT_IP_IP,"xxb",pkt,rx_vpn,protocol);
		goto error;
	}

	if( rhp_gcfg_ipv6_disabled && protocol == RHP_PROTO_IP_IPV6 ){
		err = -EINVAL;
		RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_RECV_IPV6_DISABLED,"xxb",pkt,rx_vpn,protocol);
		goto error;
	}

	data = pkt->data;

	ethh = (rhp_proto_ether*)rhp_pkt_expand_head(pkt,sizeof(rhp_proto_ether));
	if( ethh == NULL ){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}

	RHP_LOCK(&(rx_vpn->lock));
	{
		if( rx_vpn->internal_net_info.encap_mode_c != RHP_VPN_ENCAP_IPIP ){

			err = -EINVAL;
			RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_RECV_NOT_ENCAP_IP_IP,"xxLd",pkt,rx_vpn,"VPN_ENCAP",rx_vpn->internal_net_info.encap_mode_c);

			RHP_UNLOCK(&(rx_vpn->lock));
			goto error;
		}

		memcpy(ethh->src_addr,rx_vpn->internal_net_info.dummy_peer_mac,6);

		vpn_realm_id = rx_vpn->vpn_realm_id;

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


	pkt->type = RHP_PKT_PLAIN_ETHER_TAP;
	pkt->l2.eth = ethh;
	pkt->l3.raw = data;
	pkt->l4.raw = NULL;

	if( protocol == RHP_PROTO_IP_IP ){

		ethh->protocol = RHP_PROTO_ETH_IP;

		rhp_pkt_trace_dump("rhp_ip_bridge_recv(v4)",pkt);

		err = rhp_bridge_pkt_from_vpn_ipv4_arp_rslv(vpn_realm_id,rx_vpn,rx_rlm,pkt,0);
		if( err ){
			RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_RECV_ARP_RSLV_ERR,"xxE",pkt,rx_vpn,err);
			goto error;
		}

	}else if( protocol == RHP_PROTO_IP_IPV6 ){

		ethh->protocol = RHP_PROTO_ETH_IPV6;

		rhp_pkt_trace_dump("rhp_ip_bridge_recv(v6)",pkt);

		err = rhp_bridge_pkt_from_vpn_ipv6_nd_rslv(vpn_realm_id,rx_vpn,rx_rlm,pkt,0);
		if( err ){
			RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_RECV_IPV6_ND_RSLV_ERR,"xxE",pkt,rx_vpn,err);
			goto error;
		}

	}else{
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	if( rx_rlm ){
		rhp_realm_unhold(rx_rlm);
	}

	RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_RECV_RTRN,"xx",pkt,rx_vpn);
	return 0;

error:

	if( rx_rlm ){
		rhp_realm_unhold(rx_rlm);
	}

	RHP_TRC_FREQ(0,RHPTRCID_IP_BRIDGE_RECV_ERR,"xxE",pkt,rx_vpn,err);
	return err;
}


int rhp_ip_bridge_init()
{
	RHP_TRC(0,RHPTRCID_IP_BRIDGE_INIT,"");
  return 0;
}

int rhp_ip_bridge_cleanup()
{
	RHP_TRC(0,RHPTRCID_IP_BRIDGE_CLEANUP,"");
  return 0;
}
