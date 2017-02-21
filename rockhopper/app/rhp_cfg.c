/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/capability.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_packet.h"
#include "rhp_netsock.h"
#include "rhp_timer.h"
#include "rhp_wthreads.h"
#include "rhp_config.h"
#include "rhp_ikev2_mesg.h"
#include "rhp_http.h"
#include "rhp_dns_pxy.h"
#include "rhp_vpn.h"
#include "rhp_eap_auth_impl.h"
#include "rhp_eap_sup_impl.h"

static inline void _rhp_cfg_trc_dump_realm(rhp_vpn_realm* rlm)
{
  rhp_cfg_if* my_interfaces;
  rhp_cfg_peer* peers;

  RHP_TRC(0,RHPTRCID_REALM_DUMP,"xdsxddxdxxxxxxp",rlm,rlm->id,rlm->name,rlm->next,rlm->refcnt.c,rlm->is_active.c,rlm->my_interfaces,rlm->my_interfaces_any,rlm->internal_ifc,rlm->peers,rlm->apdx[0],rlm->apdx[1],rlm->apdx[2],rlm->apdx[3],sizeof(rhp_vpn_realm),rlm);

  if( rlm->internal_ifc ){

  	RHP_TRC(0,RHPTRCID_REALM_DUMP_TUNIF,"xsxp",rlm->internal_ifc,rlm->internal_ifc->if_name,rlm->internal_ifc->ifc,sizeof(rhp_cfg_if),rlm->internal_ifc);

  	if( rlm->internal_ifc->ifc ){

  		rlm->internal_ifc->ifc->dump_lock("dump_realm_internal_ifc",rlm->internal_ifc->ifc);
    }
  }

  my_interfaces = rlm->my_interfaces;

  while( my_interfaces ){

  	RHP_TRC(0,RHPTRCID_REALM_DUMP_MYIFC,"xsdxp",my_interfaces,my_interfaces->if_name,my_interfaces->priority,my_interfaces->ifc,sizeof(rhp_cfg_if),my_interfaces);

  	if( my_interfaces->ifc ){

  		my_interfaces->ifc->dump_lock("dump_realm_my_interfaces",my_interfaces->ifc);
    }

  	my_interfaces = my_interfaces->next;
  }

  peers = rlm->peers;
  while( peers ){

    switch( peers->id.type ){

    case RHP_PROTO_IKE_ID_ANY:

    	RHP_TRC(0,RHPTRCID_REALM_DUMP_PEER_ANY,"xdp",peers,peers->id.type,sizeof(rhp_cfg_peer),peers);
    	break;

    case RHP_PROTO_IKE_ID_FQDN:
    case RHP_PROTO_IKE_ID_RFC822_ADDR:
    case RHP_PROTO_IKE_ID_DER_ASN1_DN:

    	if( peers->primary_addr.addr_family == AF_UNSPEC ){
    		RHP_TRC(0,RHPTRCID_REALM_DUMP_PEER_UNSPEC_STR,"xdsLdp",peers,peers->id.type,peers->id.string,"AF",peers->primary_addr.addr_family,sizeof(rhp_cfg_peer),peers);
    	}else if( peers->primary_addr.addr_family == AF_INET ){
    		RHP_TRC(0,RHPTRCID_REALM_DUMP_PEER_INET_STR,"xdsLd4W4Wp",peers,peers->id.type,peers->id.string,"AF",peers->primary_addr.addr_family,peers->primary_addr.addr.v4,peers->primary_addr.port,peers->secondary_addr.addr.v4,peers->secondary_addr.port,sizeof(rhp_cfg_peer),peers);
    	}else if( peers->primary_addr.addr_family == AF_INET6 ){
    		RHP_TRC(0,RHPTRCID_REALM_DUMP_PEER_INET6_STR,"xdsLd6W6Wp",peers,peers->id.type,peers->id.string,"AF",peers->primary_addr.addr_family,peers->primary_addr.addr.v6,peers->primary_addr.port,peers->secondary_addr.addr.v6,peers->secondary_addr.port,sizeof(rhp_cfg_peer),peers);
    	}else{
    		RHP_BUG("%d",peers->primary_addr.addr_family);
    	}
    	break;

     case RHP_PROTO_IKE_ID_IPV4_ADDR:
     case RHP_PROTO_IKE_ID_IPV6_ADDR:
    	 break;

     case RHP_PROTO_IKE_ID_DER_ASN1_GN:
     case RHP_PROTO_IKE_ID_KEY_ID:
     default:
    	 RHP_BUG("%d",peers->id.type);
    	 break;
    }

    peers = peers->next;
  }
}

static void  _rhp_cfg_trc_dump_ikesa(rhp_cfg_ikesa* cfg_ikesa)
{
  rhp_cfg_transform* cfg_trans;

  RHP_TRC(0,RHPTRCID_CFG_IKESA_DUMP,"xbxxxx",cfg_ikesa,cfg_ikesa->protocol_id,cfg_ikesa->encr_trans_list,cfg_ikesa->prf_trans_list,cfg_ikesa->integ_trans_list,cfg_ikesa->dh_trans_list);

  cfg_trans = cfg_ikesa->encr_trans_list;
  while( cfg_trans ){
    RHP_TRC(0,RHPTRCID_CFG_IKESA_DUMP_ENCR,"xdbwd",cfg_trans,cfg_trans->priority,cfg_trans->type,cfg_trans->id,cfg_trans->key_bits_len);
    cfg_trans = cfg_trans->next;
  }

  cfg_trans = cfg_ikesa->prf_trans_list;
  while( cfg_trans ){
    RHP_TRC(0,RHPTRCID_CFG_IKESA_DUMP_PRF,"xdbw",cfg_trans,cfg_trans->priority,cfg_trans->type,cfg_trans->id);
    cfg_trans = cfg_trans->next;
  }

  cfg_trans = cfg_ikesa->integ_trans_list;
  while( cfg_trans ){
    RHP_TRC(0,RHPTRCID_CFG_IKESA_DUMP_INTEG,"xdbw",cfg_trans,cfg_trans->priority,cfg_trans->type,cfg_trans->id);
    cfg_trans = cfg_trans->next;
  }

  cfg_trans = cfg_ikesa->dh_trans_list;
  while( cfg_trans ){
    RHP_TRC(0,RHPTRCID_CFG_IKESA_DUMP_DH,"xdbw",cfg_trans,cfg_trans->priority,cfg_trans->type,cfg_trans->id);
    cfg_trans = cfg_trans->next;
  }

  return;
}

static void _rhp_cfg_trc_dump_childsa(rhp_cfg_childsa* cfg_childsa)
{
  rhp_cfg_transform* cfg_trans;

  RHP_TRC(0,RHPTRCID_CHILDSA_DUMP,"xbxxxx",cfg_childsa,cfg_childsa->protocol_id,cfg_childsa->encr_trans_list,cfg_childsa->integ_trans_list,cfg_childsa->esn_trans);

  cfg_trans = cfg_childsa->encr_trans_list;
  while( cfg_trans ){
    RHP_TRC(0,RHPTRCID_CHILDSA_DUMP_ENCR,"xdbwd",cfg_trans,cfg_trans->priority,cfg_trans->type,cfg_trans->id,cfg_trans->key_bits_len);
    cfg_trans = cfg_trans->next;
  }

  cfg_trans = cfg_childsa->integ_trans_list;
  while( cfg_trans ){
    RHP_TRC(0,RHPTRCID_CHILDSA_DUMP_INTEG,"xdbw",cfg_trans,cfg_trans->priority,cfg_trans->type,cfg_trans->id);
    cfg_trans = cfg_trans->next;
  }

  cfg_trans = cfg_childsa->esn_trans;
  while( cfg_trans ){
    RHP_TRC(0,RHPTRCID_CHILDSA_DUMP_ESN,"xdbw",cfg_trans,cfg_trans->priority,cfg_trans->type,cfg_trans->id);
    cfg_trans = cfg_trans->next;
  }
}


static void  _rhp_cfg_trc_dump_ikev1_ipsecsa(rhp_cfg_ikev1_ipsecsa* cfg_ipsecsa)
{
  rhp_cfg_ikev1_transform* cfg_trans;

  RHP_TRC(0,RHPTRCID_CFG_IKEKV1_IPSECA_DUMP,"xxb",cfg_ipsecsa,cfg_ipsecsa->trans_list,cfg_ipsecsa->protocol_id);

  cfg_trans = cfg_ipsecsa->trans_list;
  while( cfg_trans ){
    RHP_TRC(0,RHPTRCID_CFG_IKEKV1_IPSECSA_TRANS_DUMP,"xxddddddd",cfg_trans,cfg_trans->next,cfg_trans->priority,cfg_trans->enc_alg,cfg_trans->hash_alg,cfg_trans->dh_group,cfg_trans->trans_id,cfg_trans->auth_alg,cfg_trans->esn,cfg_trans->key_bits_len);
    cfg_trans = cfg_trans->next;
  }

  return;
}

static void  _rhp_cfg_trc_dump_ikev1_ikesa(rhp_cfg_ikev1_ikesa* cfg_ikesa)
{
  rhp_cfg_ikev1_transform* cfg_trans;

  RHP_TRC(0,RHPTRCID_CFG_IKEKV1_IKESA_DUMP,"xx",cfg_ikesa,cfg_ikesa->trans_list);

  cfg_trans = cfg_ikesa->trans_list;
  while( cfg_trans ){
    RHP_TRC(0,RHPTRCID_CFG_IKEKV1_IKESA_TRANS_DUMP,"xxddddddd",cfg_trans,cfg_trans->next,cfg_trans->priority,cfg_trans->enc_alg,cfg_trans->hash_alg,cfg_trans->dh_group,cfg_trans->trans_id,cfg_trans->auth_alg,cfg_trans->esn,cfg_trans->key_bits_len);
    cfg_trans = cfg_trans->next;
  }

  return;
}


void rhp_cfg_traffic_selectors_dump_impl(char* label,rhp_traffic_selector* cfg_tss,rhp_ikev2_traffic_selector* tss,int only_head)
{
	_RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
  if( _RHP_TRC_COND(_rhp_trc_user_id(),0) ){

  	rhp_ikev2_traffic_selector* dump_ts = tss;
    rhp_traffic_selector* dump_cfg_ts = cfg_tss;
    rhp_ip_addr start_addr,end_addr;

    while( dump_ts ){

    	u32 protocol = dump_ts->get_protocol(dump_ts);
    	u32 start_port = ntohs(dump_ts->get_start_port(dump_ts));
    	u32 end_port = ntohs(dump_ts->get_end_port(dump_ts));
    	u8 icmp_start_type = dump_ts->get_icmp_start_type(dump_ts);
    	u8 icmp_start_code = dump_ts->get_icmp_start_code(dump_ts);
    	u8 icmp_end_type = dump_ts->get_icmp_end_type(dump_ts);
    	u8 icmp_end_code = dump_ts->get_icmp_end_code(dump_ts);

			dump_ts->get_start_addr(dump_ts,&start_addr);
			dump_ts->get_end_addr(dump_ts,&end_addr);

			if( start_addr.addr_family == AF_INET ){

				RHP_TRC(0,RHPTRCID_CFG_TRAFFIC_SELECTORS_TS_PLD,"sxuuubbbb44",label,dump_ts,protocol,start_port,end_port,icmp_start_type,icmp_start_code,icmp_end_type,icmp_end_code,start_addr.addr.v4,end_addr.addr.v4);

			}else if( start_addr.addr_family == AF_INET6 ){

				RHP_TRC(0,RHPTRCID_CFG_TRAFFIC_SELECTORS_TS_PLD_V6,"sxuuubbbb66",label,dump_ts,protocol,start_port,end_port,icmp_start_type,icmp_start_code,icmp_end_type,icmp_end_code,start_addr.addr.v6,end_addr.addr.v6);

			}else{

				RHP_TRC(0,RHPTRCID_CFG_TRAFFIC_SELECTORS_TS_PLD_UNKNOWN_ADDR_FAMILY,"sLdxuuubbbbpp",label,"AF",start_addr.addr_family,dump_ts,protocol,start_port,end_port,icmp_start_type,icmp_start_code,icmp_end_type,icmp_end_code,16,start_addr.addr.raw,16,end_addr.addr.raw);
			}

			if( only_head ){
				break;
			}

			dump_ts = dump_ts->next;
    }

    while( dump_cfg_ts ){

    	u32 protocol = dump_cfg_ts->protocol;
    	u32 start_port = ntohs(dump_cfg_ts->start_port);
    	u32 end_port = ntohs(dump_cfg_ts->end_port);
    	u8 icmp_start_type = dump_cfg_ts->icmp_start_type;
    	u8 icmp_start_code = dump_cfg_ts->icmp_start_code;
    	u8 icmp_end_type = dump_cfg_ts->icmp_end_type;
    	u8 icmp_end_code = dump_cfg_ts->icmp_end_code;

    	if( dump_cfg_ts->ts_type == RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE ){

    		u32 start_ipv4;
      	u32 end_ipv4;

      	if( dump_cfg_ts->ts_is_subnet ){

  				rhp_ipv4_subnet_addr_range(dump_cfg_ts->addr.subnet.addr.v4,
  						dump_cfg_ts->addr.subnet.netmask.v4,&start_ipv4,&end_ipv4);

    	  }else {
    	  	start_ipv4 = dump_cfg_ts->addr.range.start.addr.v4;
    	  	end_ipv4 = dump_cfg_ts->addr.range.end.addr.v4;
    	  }

        RHP_TRC(0,RHPTRCID_CFG_TRAFFIC_SELECTORS_TS_CFG,"sxuuubbbb44",label,dump_cfg_ts,protocol,start_port,end_port,icmp_start_type,icmp_start_code,icmp_end_type,icmp_end_code,start_ipv4,end_ipv4);

    	}else if( dump_cfg_ts->ts_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){

    		u8 start_ipv6[16];
      	u8 end_ipv6[16];

      	if( dump_cfg_ts->ts_is_subnet ){
      		rhp_ipv6_subnet_addr_range(dump_cfg_ts->addr.subnet.addr.v6,dump_cfg_ts->addr.subnet.prefixlen,start_ipv6,end_ipv6);
    	  }else {
    	  	memcpy(start_ipv6,dump_cfg_ts->addr.range.start.addr.v6,16);
    	  	memcpy(end_ipv6,dump_cfg_ts->addr.range.end.addr.v6,16);
    	  }

        RHP_TRC(0,RHPTRCID_CFG_TRAFFIC_SELECTORS_TS_CFG_V6,"sxuuubbbb66",label,dump_cfg_ts,protocol,start_port,end_port,icmp_start_type,icmp_start_code,icmp_end_type,icmp_end_code,start_ipv6,end_ipv6);

    	}else{

        RHP_TRC(0,RHPTRCID_CFG_TRAFFIC_SELECTORS_TS_CFG_UNKNOWN_ADDR_FAMILY,"sxuuubbbbddppp",label,dump_cfg_ts,protocol,start_port,end_port,icmp_start_type,icmp_start_code,icmp_end_type,icmp_end_code,dump_cfg_ts->ts_is_subnet,dump_cfg_ts->addr.subnet.prefixlen,16,dump_cfg_ts->addr.subnet.addr.raw,16,dump_cfg_ts->addr.range.start.addr.raw,16,dump_cfg_ts->addr.range.end.addr.raw);
    	}

    	if( only_head ){
    		break;
    	}

      dump_cfg_ts = dump_cfg_ts->next;
    }
  }
}

void rhp_cfg_traffic_selectors_dump(char* label,rhp_traffic_selector* cfg_tss,rhp_ikev2_traffic_selector* tss)
{
	rhp_cfg_traffic_selectors_dump_impl(label,cfg_tss,tss,0);
}

rhp_mutex_t rhp_cfg_lock;
rhp_vpn_realm* rhp_realm_list_head = NULL;

extern char* rhp_home_dir;

extern char* rhp_cfg_bkup_cmd_path;

extern char* rhp_event_log_convert_cmd_path;
char* rhp_main_log_file_path = NULL;

char* rhp_packet_capture_file_path = NULL;


int rhp_gcfg_main_epoll_events = RHP_MAIN_EPOLL_MAX;

int rhp_gcfg_timer_max_qsize = RHP_TIMER_Q_MAX_DEFAULT;

int rhp_gcfg_wts_max_worker_tasks = RHP_WTS_MAX_TASKS;
int rhp_gcfg_wts_max_worker_tasks_low_priority = RHP_WTS_MAX_TASKS_LOW_PRIORITY;
int rhp_gcfg_wts_syspxy_workers = RHP_WTS_SYSPXY_WORKERS_NUM;
int rhp_gcfg_wts_main_workers = RHP_WTS_MAIN_WORKERS_NUM;
int rhp_gcfg_wts_worker_yield_limit = RHP_WTS_YIELD_LIMIT;
int rhp_gcfg_wts_max_task_pool_num = 500;

int rhp_gcfg_wts_pkt_task_max_q_packets = 2048;
int rhp_gcfg_wts_pkt_task_yield_limit = 32;

int rhp_gcfg_ike_port = RHP_PROTO_PORT_IKE;
int rhp_gcfg_ike_port_nat_t = RHP_PROTO_PORT_IKE_NATT;

int rhp_gcfg_socket_path_mtu_discover = 0;
int rhp_gcfg_pmtu_err_max_size = 512;  // Don't be an odd number!
int rhp_gcfg_min_pmtu = 576;
int rhp_gcfg_netsock_rx_esp_pkt_upper_limit = 16;
int rhp_gcfg_tuntap_rx_pkt_upper_limit = 16;
int rhp_gcfg_max_packet_default_size = 3840;// If RSA signature with a 4096 bits(512bytes) key length is specified
																						// in certificates, the packet size of IKE_AUTH may be more than 3K bytes.
																						// This value is based on the size( + (sizeof(rhp_proto_ether)
																						// + sizeof(rhp_proto_ip_v4) + sizeof(rhp_proto_udp))). TOO BIG!!!
																						// Of course, smaller size than this size is OK but a peer have to
																						// retransmit the IKE_AUTH Req packet.
																						// See _rhp_netsock_recv_ipv4() - trunc packet - [rhp_netsock.c].
int rhp_gcfg_max_ike_packet_size = 8192;
int rhp_gcfg_max_packet_size = 8192;
int rhp_gcfg_recover_packet_default_size_num = 1024;
int rhp_gcfg_packet_buffer_pool_max_num = 1000;
int rhp_gcfg_packet_buffer_pool_init_num = 1000;
int rhp_gcfg_def_vif_mtu = 1492;

int rhp_gcfg_max_cert_payloads = 32;
int rhp_gcfg_nonce_size = 64;
int rhp_gcfg_ikev1_min_nonce_size = 8;

int rhp_gcfg_ike_retry_times = 4;
int rhp_gcfg_ike_init_retry_times = 3;
int rhp_gcfg_ike_retry_init_interval = 2;
int rhp_gcfg_ike_retry_max_interval = 60;

int rhp_gcfg_http_max_connections = 100;
int rhp_gcfg_http_rx_timeout = 600; // secs
int rhp_gcfg_http_max_uri = 4096; // bytes
int rhp_gcfg_http_max_header_len = 8192; // bytes
int rhp_gcfg_http_max_content_length = (32*1024*1024); // bytes
int rhp_gcfg_http_default_port = 32501;
int rhp_gcfg_http_auth_no_pub_files = 0;
int rhp_gcfg_http_auth_cookie_max_age = 3600; // secs
int rhp_gcfg_http_auth_cookie_aging_interval = 180; // secs

int rhp_gcfg_http_bus_read_timeout = 30;
int rhp_gcfg_http_bus_idle_timeout = 1200;
int rhp_gcfg_http_bus_max_session = 30;
int rhp_gcfg_http_bus_max_async_mesg_bytes = (1000*1000); // Bytes
int rhp_gcfg_http_bus_max_async_non_critical_mesg_bytes = (600*1000); // Bytes


int rhp_gcfg_ikesa_lifetime_larval = 60;
int rhp_gcfg_ikesa_lifetime_eap_larval = 180;
//int rhp_gcfg_ikesa_lifetime_soft = 10980;
//int rhp_gcfg_ikesa_lifetime_hard = 20100;
int rhp_gcfg_ikesa_lifetime_soft = 28800;
int rhp_gcfg_ikesa_lifetime_hard = 43200;
int rhp_gcfg_ikesa_lifetime_deleted = 30;

int rhp_gcfg_keep_alive_interval = 90;
int rhp_gcfg_nat_t_keep_alive_interval = 20; // RFC3948's default
int rhp_gcfg_nat_t_keep_alive_packets = 3;
int rhp_gcfg_always_exec_keep_alive = 0;

int rhp_gcfg_childsa_lifetime_larval = 60;
int rhp_gcfg_childsa_lifetime_soft = 3600;
int rhp_gcfg_childsa_lifetime_hard = 3720;
int rhp_gcfg_childsa_lifetime_deleted = 30;

int rhp_gcfg_childsa_anti_replay = 1;
int rhp_gcfg_childsa_anti_replay_win_size = 64;
int rhp_gcfg_childsa_tfc_padding = 0;
int rhp_gcfg_childsa_pfs = 0;
int rhp_gcfg_childsa_resp_not_rekeying = 0;

u64 rhp_gcfg_childsa_max_seq_esn = 0xFFFFFFFFFFFFF000ULL;
u32 rhp_gcfg_childsa_max_seq_non_esn = 0xFFFFF000UL;

int rhp_gcfg_ikesa_cookie = 1;
int rhp_gcfg_ikesa_cookie_max_open_req_per_sec = 100;
int rhp_gcfg_ikesa_cookie_max_half_open_sessions = 300;
int rhp_gcfg_ikesa_cookie_refresh_interval = 300; // (secs)
int rhp_gcfg_ikesa_cookie_max_pend_packets = 250;


int rhp_gcfg_ikesa_resp_not_rekeying = 0;

int rhp_gcfg_ikesa_crl_check_all = 1;


int rhp_gcfg_net_event_convergence_interval = 3; // (secs)

int rhp_gcfg_vpn_auto_reconnect_interval_1 = 5;
int rhp_gcfg_vpn_auto_reconnect_interval_2 = 5;
int rhp_gcfg_vpn_auto_reconnect_max_retries = 3;

int rhp_gcfg_vpn_max_half_open_sessions = 3000;
int rhp_gcfg_vpn_max_sessions = 5000;

int rhp_gcfg_event_max_record_pool_num = 200;

int rhp_gcfg_mac_cache_aging_interval = 600; // (secs)
int rhp_gcfg_mac_cache_hold_time = 1200; // (secs)
int rhp_gcfg_mac_cache_max_entries = 5000; // For both MAC cache and ARP/ND cache.
int rhp_gcfg_proxy_arp_cache = 1;

u32 rhp_gcfg_dummy_mac_min_idx = 0;
u32 rhp_gcfg_dummy_mac_max_idx = 0x00FFFFFE;
u32 rhp_gcfg_dummy_mac_oui = 0x0002FFEF;

int rhp_gcfg_arp_resolve_timeout = 2;
int rhp_gcfg_arp_resolve_retry_times = 3;

int rhp_gcfg_dns_pxy_trans_tbl_timeout = 30; // (sec)
int rhp_gcfg_dns_pxy_trans_tbl_timeout2 = 10; // (sec)
int rhp_gcfg_dns_pxy_trans_tbl_max_num = 4096;
int rhp_gcfg_dns_pxy_fixed_internal_port = 0;
int rhp_gcfg_dns_pxy_convergence_interval = 3;
int rhp_gcfg_dns_pxy_retry_interval = 60;
int rhp_gcfg_dns_pxy_fwd_any_queries_to_vpn = 0;
int rhp_gcfg_dns_pxy_fwd_any_queries_to_vpn_non_rockhopper = 1;
int rhp_gcfg_dns_pxy_fwd_max_sockets = 256;


int rhp_gcfg_internal_address_aging_interval = 300; // (sec)

int rhp_gcfg_vpn_always_on_connect_poll_interval = 120; // (sec)

// 0 : Allowed.
// 1 : Allowed for original responder.
// 2 : NOT Allowed.
int rhp_gcfg_behind_a_nat_dont_change_addr_port = 1;
int rhp_gcfg_peer_addr_change_min_interval = 10; // (sec)
int rhp_gcfg_nat_dont_change_addr_port_by_esp = 0;

int rhp_gcfg_ikesa_dbg_gen_spi = 0;
int rhp_gcfg_childsa_dbg_gen_spi = 0;

int rhp_gcfg_bridge_static_cache_garp_num = 2;

int rhp_gcfg_strict_peer_addr_port_check = 1;

int rhp_gcfg_log_level_debug = 0;
int rhp_gcfg_max_event_log_records = 5000;
int rhp_gcfg_log_disabled = 0;

int rhp_gcfg_auth_method_compared_strictly = 0;
int rhp_gcfg_randomize_sa_lifetime = 1;

int rhp_gcfg_stun_max_attr_size = 2048;

int rhp_gcfg_ikesa_remote_cfg_narrow_ts_i = 0;

int rhp_gcfg_ca_pubkey_digests_max_size = 400; // bytes, 24 pubkey digests(SHA-1 MD*20)
int rhp_gcfg_responder_tx_all_cas_certreq = 1;
int rhp_gcfg_check_certreq_ca_digests = 1;
int rhp_gcfg_strictly_cmp_certreq_ca_digests = 0;

int rhp_gcfg_delete_ikesa_if_no_childsa_exists = 0;
int rhp_gcfg_reject_auth_exchg_without_childsa = 1;

int rhp_gcfg_eap_mschapv2_max_auth_retries = 2;

int rhp_gcfg_dbg_tx_ikev2_pkt_lost_rate = 0;
int rhp_gcfg_dbg_tx_esp_pkt_lost_rate = 0;
int rhp_gcfg_dbg_tx_ikev2_pkt_cons_drop = 2;
int rhp_gcfg_dbg_tx_esp_pkt_cons_drop = 2;
int rhp_gcfg_dbg_log_keys_info = 0;

int rhp_gcfg_dbg_direct_file_trace = 0;
char* rhp_gcfg_dbg_f_trace_main_path = NULL;
char* rhp_gcfg_dbg_f_trace_syspxy_path = NULL;
long rhp_gcfg_dbg_f_trace_max_size = RHP_TRC_F_DEF_MAX_FILE_SIZE;

int rhp_gcfg_trace_pkt_full_dump = 0;

int rhp_gcfg_net_event_init_convergence_interval = 60;

int rhp_gcfg_ikev2_alt_id_use_dn = 0;

int rhp_gcfg_forcedly_close_vpns_wait_secs = 3; //secs

// This is NOT configured by rhp_gcfg_vpn_params[] table.
int rhp_gcfg_webmng_allow_nobody_admin = 1;
int rhp_gcfg_webmng_auto_reconnect_nobody_admin = 1;

int rhp_gcfg_check_pkt_routing_loop = 1;

int rhp_gcfg_eap_mschapv2_sup_skip_ms_len_check = 0;

int rhp_gcfg_ikev2_qcd_enabled = 1;
int rhp_gcfg_ikev2_qcd_min_token_len = 16;  // [RFC6290]
int rhp_gcfg_ikev2_qcd_max_token_len = 128; // [RFC6290]
int rhp_gcfg_ikev2_qcd_max_rx_packets_per_sec = 1000;
int rhp_gcfg_ikev2_qcd_max_rx_err_per_sec = 500;
int rhp_gcfg_ikev2_qcd_max_pend_packets = 250;
int rhp_gcfg_ikev2_qcd_syspxy_max_pend_reqs = 100;
int rhp_gcfg_ikev2_qcd_enabled_time = 0; // secs after boot/reboot.

int rhp_gcfg_ike_retransmit_reps_limit_per_sec = 128;

int rhp_gcfg_ikev2_mobike_rt_check_convergence_interval = 3; // (secs)
int rhp_gcfg_ikev2_mobike_rt_check_interval_msec = 30; // (msecs)
int rhp_gcfg_ikev2_mobike_rt_check_retry_interval_msec = 600; // (msec)
int rhp_gcfg_ikev2_mobike_rt_check_max_retries = 5;
int rhp_gcfg_ikev2_mobike_resp_keep_alive_interval = 600; // (secs)
int rhp_gcfg_ikev2_mobike_resp_keep_alive_retry_interval = 300; // (secs)
int rhp_gcfg_ikev2_mobike_resp_keep_alive_max_retries = 12;
int rhp_gcfg_ikev2_mobike_rt_check_on_nat_t_port = 1;
int rhp_gcfg_ikev2_mobike_dynamically_disable_nat_t = 1;
int rhp_gcfg_ikev2_mobike_watch_nat_gw_reflexive_addr = 1;
int rhp_gcfg_ikev2_mobike_init_rt_check_hold_time = 1800; // (secs)
int rhp_gcfg_ikev2_mobike_init_rt_check_hold_ka_interval = 60; //(secs)
int rhp_gcfg_ikev2_mobike_init_rt_check_hold_ka_max_retries = 0;

int rhp_gcfg_http_clt_get_max_rx_length = (32*1024*1024); // bytes;
int rhp_gcfg_http_clt_get_max_reqs = 300;

int rhp_gcfg_ikev2_hash_url_http_timeout = 60; // (secs)

int rhp_gcfg_ikev2_rx_if_strictly_check = 1;

int rhp_gcfg_ikev2_dont_tx_general_err_resp = 0;

int rhp_gcfg_esp_rx_udp_encap_only_when_exec_nat_t = 0;

int rhp_gcfg_log_pending_records_max = 15000;

int rhp_gcfg_ikev2_hash_url_max_len = 1024;

int rhp_gcfg_dns_resolve_max_tasks = 256;

int rhp_gcfg_ikev2_rx_peer_realm_id_req = 1;

int rhp_gcfg_forward_critical_pkt_preferentially = 1;

int rhp_gcfg_flood_pkts_if_no_accesspoint_exists = 1;

int rhp_gcfg_dont_search_cfg_peers_for_realm_id = 0;

int rhp_gcfg_peek_rx_packet_size = 0;

int rhp_gcfg_ipv6_disabled = 0;
int rhp_gcfg_ikev2_mobike_additional_addr_check_dnat = 1;

int rhp_gcfg_neigh_resolve_max_addrs = 8192;
int rhp_gcfg_neigh_resolve_max_q_pkts = 4096;

int rhp_gcfg_ipv6_nd_resolve_timeout = 2;
int rhp_gcfg_ipv6_nd_resolve_retry_times = 3;

int rhp_gcfg_arp_reprobe_min_interval = 30; // (secs)
int rhp_gcfg_ipv6_nd_reprobe_min_interval = 30; // secs

int rhp_gcfg_ipv6_rlm_lladdr_first_wait_secs = 3; // secs
int rhp_gcfg_ipv6_rlm_lladdr_dad_first_interval = 5; // secs
int rhp_gcfg_ipv6_rlm_lladdr_dad_retry_interval = 1;  // secs
int rhp_gcfg_ipv6_rlm_lladdr_dad_retransmits = 1; // times
int rhp_gcfg_ipv6_rlm_lladdr_max_gen_retries = 10; // times

int rhp_gcfg_proxy_ipv6_nd_cache = 1;

int rhp_gcfg_bridge_static_cache_unsolicited_nd_adv_num = 2;

int rhp_gcfg_ipv6_drop_router_adv = 0;

int rhp_gcfg_ikev2_enable_fragmentation = 0;
int rhp_gcfg_ikev2_max_fragments = 64;
int rhp_gcfg_ikev2_frag_max_packet_size = 32768; // bytes
int rhp_gcfg_ikev2_frag_size_v4 = 0; // bytes. [0:A link's MTU is used by default.]
int rhp_gcfg_ikev2_frag_size_v6 = 0; // bytes. [0:A link's MTU is used by default.]
int rhp_gcfg_ikev2_frag_min_size_v4 = 548; // bytes. [576 - sizeof(ipv4_hdr) - sizeof(udp_hdr)]
int rhp_gcfg_ikev2_frag_min_size_v6 = 1232; // bytes. [1280  - sizeof(ipv6_hdr) - sizeof(udp_hdr)]
int rhp_gcfg_ikev2_frag_use_min_size = 0;
int rhp_gcfg_ikev2_frag_rx_timeout = 60; // secs

int rhp_gcfg_esp_dont_match_selectors = 0; // For debug purpose...

int rhp_gcfg_v4_icmp_is_critical = 0;

int rhp_gcfg_v6_deny_remote_client_nd_pkts_over_ipip = 1;

// See #define RHP_IKEV2_CFG_IPV6_RA_TSS_XXX
int rhp_gcfg_v6_allow_ra_tss_type = 1;

int rhp_gcfg_udp_encap_for_v6_after_rx_rockhopper_also = 0;
int rhp_gcfg_enable_childsa_outb_after_n_secs = 0;

int rhp_gcfg_eap_client_use_ikev2_random_addr_id = 1;


int rhp_gcfg_ikev2_sess_resume_init_enabled = 1;
int rhp_gcfg_ikev2_sess_resume_resp_enabled = 0;

// Actual valid secs are this value x 2.
//int rhp_gcfg_ikev2_sess_resume_key_update_interval = 21600; // secs.
int rhp_gcfg_ikev2_sess_resume_key_update_interval = 43600; // secs.
int rhp_gcfg_ikev2_sess_resume_key_update_interval_min = 180; // secs.

// This must be more than RHP_IKEV2_SESS_RESUME_TKT_LIFETIME_MARGIN secs.
//int rhp_gcfg_ikev2_sess_resume_ticket_lifetime = 20100; // secs (eq rhp_gcfg_ikesa_lifetime_hard)
int rhp_gcfg_ikev2_sess_resume_ticket_lifetime = 43200; // secs (eq rhp_gcfg_ikesa_lifetime_hard)

int rhp_gcfg_ikev2_sess_resume_resp_tkt_revocation = 0;
double rhp_gcfg_ikev2_sess_resume_tkt_rvk_bfltr_false_ratio = 0.0001;
int rhp_gcfg_ikev2_sess_resume_tkt_rvk_bfltr_max_tkts = 110000;


int rhp_gcfg_ikev2_tx_new_req_retry_interval = 5; // (secs)

int rhp_gcfg_ikev2_rekey_ikesa_delete_deferred_init = 5;
int rhp_gcfg_ikev2_rekey_ikesa_delete_deferred_resp = 30;

int rhp_gcfg_ikev2_rekey_childsa_delete_deferred_init = 10;
int rhp_gcfg_ikev2_rekey_childsa_delete_deferred_resp = 30;

int rhp_gcfg_def_eap_server_if_only_single_rlm_defined = 1;

int rhp_gcfg_ikev2_max_create_child_sa_failure = 5;

int rhp_gcfg_ikev_other_auth_disabled_if_null_auth_enabled = 1;

int rhp_gcfg_disabled_trace_write_for_misc_events = 1;

int rhp_gcfg_ikev2_mobike_resp_null_auth_keep_alive_interval = 60;


// See #define RHP_IKEV2_CFG_IPV6_AUTO_TSS_XXX
int rhp_gcfg_v6_allow_auto_tss_type = 0;

int rhp_gcfg_ikev2_itnl_net_convergence_interval = 5; // (secs)
int rhp_gcfg_ikev2_itnl_net_convergence_max_wait_times = 4; //

int rhp_gcfg_bridge_tx_garp_for_vpn_peers = 1;
int rhp_gcfg_bridge_tx_unsol_nd_adv_for_vpn_peers = 1;

int rhp_gcfg_ikev2_cfg_rmt_clt_req_old_addr = 0;

int rhp_gcfg_ikev2_cfg_v6_internal_addr_def_prefix_len = 64;


int rhp_gcfg_radius_min_pkt_len = RHP_RADIUS_PKT_LEN_MIN;
int rhp_gcfg_radius_max_pkt_len = RHP_RADIUS_PKT_LEN_MAX;
int rhp_gcfg_radius_mschapv2_eap_identity_not_protected = 1;
int rhp_gcfg_radius_secondary_server_hold_time = 1200; // (secs)

int rhp_gcfg_radius_acct_max_sessions = 8;
int rhp_gcfg_radius_acct_max_queued_tx_messages = 1024; // Per rhp_radius_acct_handle.

int rhp_gcfg_ip_routing_disabled = 0;

int rhp_gcfg_ip_routing_cache_max_entries_v4 = 5000;
int rhp_gcfg_ip_routing_cache_max_entries_v6 = 5000;
int rhp_gcfg_ip_routing_cache_hold_time = 7200; // secs
int rhp_gcfg_ip_routing_cache_aging_interval = 600; // secs
int rhp_gcfg_ip_routing_cache_hash_size = 1277;

int rhp_gcfg_ip_routing_max_entries_v4 = 5000;
int rhp_gcfg_ip_routing_max_entries_v6 = 5000;
int rhp_gcfg_ip_routing_hash_bucket_init_size = 131;
int rhp_gcfg_ip_routing_hash_bucket_max_size = 16411;
double rhp_gcfg_ip_routing_hash_bucket_max_occupancy_ratio = 0.7;

int rhp_gcfg_mac_cache_hash_size = 1277;
int rhp_gcfg_neigh_cache_hash_size = 1277;


int rhp_gcfg_nhrp_default_hop_count = 255;
int rhp_gcfg_nhrp_cache_hold_time = 7200; // secs
int rhp_gcfg_nhrp_cache_update_interval = 3600; // secs
int rhp_gcfg_nhrp_cache_update_interval_error = 60; // secs

int rhp_gcfg_nhrp_cache_hash_size	= 1277;
int rhp_gcfg_nhrp_cache_aging_interval = 600; // secs
int rhp_gcfg_nhrp_cache_max_entries = 5000;

int rhp_gcfg_nhrp_max_request_sessions = 5000;
int rhp_gcfg_nhrp_registration_req_tx_margin_time = 5; // secs
int rhp_gcfg_nhrp_request_session_timeout = 10; // secs
int rhp_gcfg_nhrp_request_session_timeout_max = 60; // secs
int rhp_gcfg_nhrp_request_session_retry_times = 5;

int rhp_gcfg_internal_net_max_peer_addrs = 16;

int rhp_gcfg_nhrp_traffic_indication_rate_limit = 60; // secs
int rhp_gcfg_nhrp_traffic_indication_orig_pkt_len = 64;
int rhp_gcfg_nhrp_strictly_check_addr_uniqueness = 0;
int rhp_gcfg_nhrp_registration_req_cie_prefix_len = 32;
int rhp_gcfg_nhrp_registration_req_cie_prefix_len_v6 = 128;
int rhp_gcfg_nhrp_cie_mtu = 17916;

int rhp_gcfg_ip_routing_cache_dst_addr_only = 1;
int rhp_gcfg_ip_routing_coarse_tick_interval = 30; // (secs)

int rhp_gcfg_dmvpn_vpn_conn_idle_timeout = 600; // (secs)
int rhp_gcfg_dmvpn_connect_shortcut_wait_random_range = 10; // (secs)
int rhp_gcfg_dmvpn_connect_shortcut_rate_limit = 60; // (secs)
int rhp_gcfg_dmvpn_dont_handle_traffic_indication = 0;
int rhp_gcfg_dmvpn_only_tx_resolution_rep_via_nhs = 0;
int rhp_gcfg_dmvpn_tx_resolution_rep_via_nhs = 0;

int rhp_gcfg_ikev2_auth_tkt_shortcut_session_key_len = 64;
int rhp_gcfg_ikev2_auth_tkt_shortcut_session_key_min_len = 16;
int rhp_gcfg_ikev2_auth_tkt_shortcut_session_key_max_len = 256;
int rhp_gcfg_ikev2_auth_tkt_lifetime = 300; // (secs);

int rhp_gcfg_packet_capture_timer_check_interval = 10; // (secs)

int rhp_gcfg_ikev1_enabled = 0;
int rhp_gcfg_def_ikev1_if_only_single_rlm_defined = 1;

int rhp_gcfg_ikev1_nat_t_disabled = 0;

int rhp_gcfg_nat_dont_change_addr_port_by_ikev1 = 0;

int rhp_gcfg_ikev1_dpd_enabled = 1;
int rhp_gcfg_ikev1_commit_bit_enabled = 1;

int rhp_gcfg_ikev1_ikesa_lifetime_deleted = 1; 	// (secs)
int rhp_gcfg_ikev1_ipsecsa_lifetime_deleted = 1;	// (secs)

int rhp_gcfg_ikev1_tx_redundant_delete_sa_mesg = 2; // (pkts)

int rhp_gcfg_ikev1_retx_pkts_num = 3;

int rhp_gcfg_ikev1_ikesa_min_lifetime = 180; // (secs)
int rhp_gcfg_ikev1_ikesa_rekey_margin = 60; // (secs)
int rhp_gcfg_ikev1_ipsecsa_min_lifetime = 120; // (secs)
int rhp_gcfg_ikev1_ipsecsa_rekey_margin = 60; // (secs)
int rhp_gcfg_ikev1_ipsecsa_tx_responder_lifetime = 1;

int rhp_gcfg_ca_dn_ders_max_size = 2048; // bytes

int rhp_gcfg_check_certreq_ca_dns = 1;
int rhp_gcfg_strictly_cmp_certreq_ca_dns = 0;

int rhp_gcfg_ikev1_xauth_tx_error_margin = 5; // (secs)

unsigned long rhp_gcfg_ikev1_mode_cfg_addr_expiry = 0xFFFFFFFF;
int rhp_gcfg_ikev1_mode_cfg_tx_subnets = 1;

int rhp_gcfg_ikev1_main_mode_enabled = 1;
int rhp_gcfg_ikev1_aggressive_mode_enabled = 0;

int rhp_gcfg_ikev1_ipsecsa_gre_strictly_match_ts = 0;

int rhp_gcfg_ikev1_dont_tx_initial_contact = 0;

int rhp_gcfg_ikev1_xauth_allow_null_terminated_password = 1;

// **************************************************

//
//  Referenced with rhp_eap_radius_cfg_lock acquired.
//

rhp_mutex_t rhp_eap_radius_cfg_lock;

rhp_eap_radius_gcfg* rhp_gcfg_eap_radius = NULL;
rhp_radius_acct_gcfg* rhp_gcfg_radius_acct = NULL;

// **************************************************


//
// [CAUTION]
//
//  VPN's global cfg params are valid for both Main process and Protected process.
//
rhp_gcfg_param rhp_gcfg_vpn_params[] = {
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"tuntap_rx_pkt_upper_limit",
				val_p: 				(void*)&(rhp_gcfg_tuntap_rx_pkt_upper_limit),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"netsock_rx_esp_pkt_upper_limit",
				val_p: 				(void*)&(rhp_gcfg_netsock_rx_esp_pkt_upper_limit),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"max_packet_default_size",
				val_p: 				(void*)&(rhp_gcfg_max_packet_default_size),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"max_packet_size",
				val_p: 				(void*)&(rhp_gcfg_max_packet_size),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"default_vif_mtu",
				val_p: 				(void*)&(rhp_gcfg_def_vif_mtu),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"packet_buffer_pool_max_num",
				val_p: 				(void*)&(rhp_gcfg_packet_buffer_pool_max_num),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"packet_buffer_pool_init_num",
				val_p: 				(void*)&(rhp_gcfg_packet_buffer_pool_init_num),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"socket_path_mtu_discover",
				val_p: 				(void*)&(rhp_gcfg_socket_path_mtu_discover),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"pmtu_err_max_size",
				val_p: 				(void*)&(rhp_gcfg_pmtu_err_max_size),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"min_pmtu",
				val_p: 				(void*)&(rhp_gcfg_min_pmtu),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"net_event_convergence_interval",
				val_p: 				(void*)&(rhp_gcfg_net_event_convergence_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"auto_reconnect_interval_1",
				val_p: 				(void*)&(rhp_gcfg_vpn_auto_reconnect_interval_1),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"auto_reconnect_interval_2",
				val_p: 				(void*)&(rhp_gcfg_vpn_auto_reconnect_interval_2),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"auto_reconnect_max_retries",
				val_p: 				(void*)&(rhp_gcfg_vpn_auto_reconnect_max_retries),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"max_half_open_sessions",
				val_p: 				(void*)&(rhp_gcfg_vpn_max_half_open_sessions),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"max_sessions",
				val_p: 				(void*)&(rhp_gcfg_vpn_max_sessions),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"mac_cache_aging_interval",
				val_p: 				(void*)&(rhp_gcfg_mac_cache_aging_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"mac_cache_hold_time",
				val_p: 				(void*)&(rhp_gcfg_mac_cache_hold_time),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"mac_cache_max_entries",
				val_p: 				(void*)&(rhp_gcfg_mac_cache_max_entries),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"proxy_arp_cache",
				val_p: 				(void*)&(rhp_gcfg_proxy_arp_cache),
		},
		{
				type: 					RHP_XML_DT_UINT,
				val_name: 	"dummy_mac_min_idx",
				val_p: 				(void*)&(rhp_gcfg_dummy_mac_min_idx),
		},
		{
				type: 					RHP_XML_DT_UINT,
				val_name: 	"dummy_mac_max_idx",
				val_p: 				(void*)&(rhp_gcfg_dummy_mac_max_idx),
		},
		{
				type: 					RHP_XML_DT_UINT,
				val_name: 	"dummy_mac_oui",
				val_p: 				(void*)&(rhp_gcfg_dummy_mac_oui),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"timer_max_qsize",
				val_p: 				(void*)&(rhp_gcfg_timer_max_qsize),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"wts_max_worker_tasks",
				val_p: 				(void*)&(rhp_gcfg_wts_max_worker_tasks),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"wts_max_worker_tasks_low_priority",
				val_p: 				(void*)&(rhp_gcfg_wts_max_worker_tasks_low_priority),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"wts_syspxy_workers",
				val_p: 				(void*)&(rhp_gcfg_wts_syspxy_workers),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"wts_main_workers",
				val_p: 				(void*)&(rhp_gcfg_wts_main_workers),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"wts_worker_yield_limit",
				val_p: 				(void*)&(rhp_gcfg_wts_worker_yield_limit),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"wts_max_task_pool_num",
				val_p: 				(void*)&(rhp_gcfg_wts_max_task_pool_num),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"wts_pkt_task_max_q_packets",
				val_p: 				(void*)&(rhp_gcfg_wts_pkt_task_max_q_packets),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"wts_pkt_task_yield_limit",
				val_p: 				(void*)&(rhp_gcfg_wts_pkt_task_yield_limit),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"http_max_connections",
				val_p: 				(void*)&(rhp_gcfg_http_max_connections),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"http_rx_timeout",
				val_p: 				(void*)&(rhp_gcfg_http_rx_timeout),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"http_max_uri",
				val_p: 				(void*)&(rhp_gcfg_http_max_uri),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"http_max_header_len",
				val_p: 				(void*)&(rhp_gcfg_http_max_header_len),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"http_max_content_length",
				val_p: 				(void*)&(rhp_gcfg_http_max_content_length),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"http_default_port",
				val_p: 				(void*)&(rhp_gcfg_http_default_port),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"http_auth_no_pub_files",
				val_p: 				(void*)&(rhp_gcfg_http_auth_no_pub_files),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"http_bus_read_timeout",
				val_p: 				(void*)&(rhp_gcfg_http_bus_read_timeout),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"http_bus_idle_timeout",
				val_p: 				(void*)&(rhp_gcfg_http_bus_idle_timeout),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"http_bus_max_session",
				val_p: 				(void*)&(rhp_gcfg_http_bus_max_session),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"http_bus_max_async_mesg_bytes",
				val_p: 				(void*)&(rhp_gcfg_http_bus_max_async_mesg_bytes),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"http_bus_max_async_non_critical_mesg_bytes",
				val_p: 				(void*)&(rhp_gcfg_http_bus_max_async_non_critical_mesg_bytes),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"arp_resolve_timeout",
				val_p: 				(void*)&(rhp_gcfg_arp_resolve_timeout),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"arp_resolve_retry_times",
				val_p: 				(void*)&(rhp_gcfg_arp_resolve_retry_times),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"neigh_resolve_max_q_pkts",
				val_p: 				(void*)&(rhp_gcfg_neigh_resolve_max_q_pkts),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"neigh_resolve_max_addrs",
				val_p: 				(void*)&(rhp_gcfg_neigh_resolve_max_addrs),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"arp_reprobe_min_interval",
				val_p: 				(void*)&(rhp_gcfg_arp_reprobe_min_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ipv6_nd_resolve_timeout",
				val_p: 				(void*)&(rhp_gcfg_ipv6_nd_resolve_timeout),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ipv6_nd_resolve_retry_times",
				val_p: 				(void*)&(rhp_gcfg_ipv6_nd_resolve_retry_times),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ipv6_nd_reprobe_min_interval",
				val_p: 				(void*)&(rhp_gcfg_ipv6_nd_reprobe_min_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dns_pxy_trans_tbl_timeout",
				val_p: 				(void*)&(rhp_gcfg_dns_pxy_trans_tbl_timeout),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dns_pxy_trans_tbl_timeout2",
				val_p: 				(void*)&(rhp_gcfg_dns_pxy_trans_tbl_timeout2),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dns_pxy_trans_tbl_max_num",
				val_p: 				(void*)&(rhp_gcfg_dns_pxy_trans_tbl_max_num),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dns_pxy_fixed_internal_port",
				val_p: 				(void*)&(rhp_gcfg_dns_pxy_fixed_internal_port),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dns_pxy_convergence_interval",
				val_p: 				(void*)&(rhp_gcfg_dns_pxy_convergence_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dns_pxy_retry_interval",
				val_p: 				(void*)&(rhp_gcfg_dns_pxy_retry_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dns_pxy_fwd_any_queries_to_vpn",
				val_p: 				(void*)&(rhp_gcfg_dns_pxy_fwd_any_queries_to_vpn),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dns_pxy_fwd_any_queries_to_vpn_non_rockhopper",
				val_p: 				(void*)&(rhp_gcfg_dns_pxy_fwd_any_queries_to_vpn_non_rockhopper),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dns_pxy_fwd_max_sockets",
				val_p: 				(void*)&(rhp_gcfg_dns_pxy_fwd_max_sockets),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"internal_address_aging_interval",
				val_p: 				(void*)&(rhp_gcfg_internal_address_aging_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"vpn_always_on_connect_poll_interval",
				val_p: 				(void*)&(rhp_gcfg_vpn_always_on_connect_poll_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"recover_packet_default_size_num",
				val_p: 				(void*)&(rhp_gcfg_recover_packet_default_size_num),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"behind_a_nat_dont_change_addr_port",
				val_p: 				(void*)&(rhp_gcfg_behind_a_nat_dont_change_addr_port),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"nat_dont_change_addr_port_by_esp",
				val_p: 				(void*)&(rhp_gcfg_nat_dont_change_addr_port_by_esp),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"nat_dont_change_addr_port_by_ikev1",
				val_p: 				(void*)&(rhp_gcfg_nat_dont_change_addr_port_by_ikev1),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"peer_addr_change_min_interval",
				val_p: 				(void*)&(rhp_gcfg_peer_addr_change_min_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"bridge_static_cache_garp_num",
				val_p: 				(void*)&(rhp_gcfg_bridge_static_cache_garp_num),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"log_level_debug",
				val_p: 				(void*)&(rhp_gcfg_log_level_debug),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"log_max_event_records",
				val_p: 				(void*)&(rhp_gcfg_max_event_log_records),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"randomize_sa_lifetime",
				val_p: 				(void*)&(rhp_gcfg_randomize_sa_lifetime),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"stun_max_attr_size",
				val_p: 				(void*)&(rhp_gcfg_stun_max_attr_size),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"http_auth_cookie_max_age",
				val_p: 				(void*)&(rhp_gcfg_http_auth_cookie_max_age),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"http_auth_cookie_aging_interval",
				val_p: 				(void*)&(rhp_gcfg_http_auth_cookie_aging_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dbg_tx_ikev2_pkt_lost_rate",
				val_p: 				(void*)&(rhp_gcfg_dbg_tx_ikev2_pkt_lost_rate),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dbg_tx_esp_pkt_lost_rate",
				val_p: 				(void*)&(rhp_gcfg_dbg_tx_esp_pkt_lost_rate),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dbg_tx_ikev2_pkt_cons_drop",
				val_p: 				(void*)&(rhp_gcfg_dbg_tx_ikev2_pkt_cons_drop),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dbg_tx_esp_pkt_cons_drop",
				val_p: 				(void*)&(rhp_gcfg_dbg_tx_esp_pkt_cons_drop),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dbg_log_keys_info",
				val_p: 				(void*)&(rhp_gcfg_dbg_log_keys_info),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dbg_use_trace_file",
				val_p: 				(void*)&(rhp_gcfg_dbg_direct_file_trace),
		},
		{
				type: 					RHP_XML_DT_LONG,
				val_name: 	"dbg_trace_file_max_bytes",
				val_p: 				(void*)&(rhp_gcfg_dbg_f_trace_max_size),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dbg_ikesa_gen_spi",
				val_p: 				(void*)&(rhp_gcfg_ikesa_dbg_gen_spi),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dbg_childsa_gen_spi",
				val_p: 				(void*)&(rhp_gcfg_childsa_dbg_gen_spi),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"trace_pkt_full_dump",
				val_p: 				(void*)&(rhp_gcfg_trace_pkt_full_dump),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"net_event_init_convergence_interval",
				val_p: 				(void*)&(rhp_gcfg_net_event_init_convergence_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_alt_id_use_dn",
				val_p: 				(void*)&(rhp_gcfg_ikev2_alt_id_use_dn),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"forcedly_close_vpns_wait_secs",
				val_p: 				(void*)&(rhp_gcfg_forcedly_close_vpns_wait_secs),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"check_pkt_routing_loop",
				val_p: 				(void*)&(rhp_gcfg_check_pkt_routing_loop),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"eap_mschapv2_max_auth_retries",
				val_p: 				(void*)&(rhp_gcfg_eap_mschapv2_max_auth_retries),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"auth_method_cmp_strictly",
				val_p: 				(void*)&(rhp_gcfg_auth_method_compared_strictly),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"crl_check_all",
				val_p: 				(void*)&(rhp_gcfg_ikesa_crl_check_all),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ca_pubkey_digests_max_size",
				val_p: 				(void*)&(rhp_gcfg_ca_pubkey_digests_max_size),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"check_certreq_ca_digests",
				val_p: 				(void*)&(rhp_gcfg_check_certreq_ca_digests),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"certreq_ca_digests_cmp_strictly",
				val_p: 				(void*)&(rhp_gcfg_strictly_cmp_certreq_ca_digests),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"qcd_syspxy_max_pend_reqs",
				val_p: 				(void*)&(rhp_gcfg_ikev2_qcd_syspxy_max_pend_reqs),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"log_disabled",
				val_p: 				(void*)&(rhp_gcfg_log_disabled),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"http_clt_get_max_rx_length",
				val_p: 				(void*)&(rhp_gcfg_http_clt_get_max_rx_length),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"http_clt_get_max_reqs",
				val_p: 				(void*)&(rhp_gcfg_http_clt_get_max_reqs),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"esp_rx_udp_encap_only_when_exec_nat_t",
				val_p: 				(void*)&(rhp_gcfg_esp_rx_udp_encap_only_when_exec_nat_t),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dns_resolve_max_tasks",
				val_p: 				(void*)&(rhp_gcfg_dns_resolve_max_tasks),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"log_pending_records_max",
				val_p: 				(void*)&(rhp_gcfg_log_pending_records_max),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"forward_critical_pkt_preferentially",
				val_p: 				(void*)&(rhp_gcfg_forward_critical_pkt_preferentially),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"flood_pkts_if_no_accesspoint_exists",
				val_p: 				(void*)&(rhp_gcfg_flood_pkts_if_no_accesspoint_exists),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dont_search_cfg_peers_for_realm_id",
				val_p: 				(void*)&(rhp_gcfg_dont_search_cfg_peers_for_realm_id),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"peek_rx_packet_size",
				val_p: 				(void*)&(rhp_gcfg_peek_rx_packet_size),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ipv6_disabled",
				val_p: 				(void*)&(rhp_gcfg_ipv6_disabled),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ipv6_rlm_lladdr_init_wait_secs",
				val_p: 				(void*)&(rhp_gcfg_ipv6_rlm_lladdr_first_wait_secs),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ipv6_rlm_lladdr_dad_first_interval",
				val_p: 				(void*)&(rhp_gcfg_ipv6_rlm_lladdr_dad_first_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ipv6_rlm_lladdr_dad_retry_interval",
				val_p: 				(void*)&(rhp_gcfg_ipv6_rlm_lladdr_dad_retry_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ipv6_rlm_lladdr_dad_retransmits",
				val_p: 				(void*)&(rhp_gcfg_ipv6_rlm_lladdr_dad_retransmits),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ipv6_rlm_lladdr_max_gen_retries",
				val_p: 				(void*)&(rhp_gcfg_ipv6_rlm_lladdr_max_gen_retries),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"proxy_ipv6_nd_cache",
				val_p: 				(void*)&(rhp_gcfg_proxy_ipv6_nd_cache),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ipv6_drop_router_adv",
				val_p: 				(void*)&(rhp_gcfg_ipv6_drop_router_adv),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"bridge_static_cache_unsolicited_nd_adv_num",
				val_p: 				(void*)&(rhp_gcfg_bridge_static_cache_unsolicited_nd_adv_num),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"v6_deny_remote_client_nd_pkts_over_ipip",
				val_p: 				(void*)&(rhp_gcfg_v6_deny_remote_client_nd_pkts_over_ipip),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"v6_allow_ra_tss_type",
				val_p: 				(void*)&(rhp_gcfg_v6_allow_ra_tss_type),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"udp_encap_for_v6_after_rx_rockhopper_also",
				val_p: 				(void*)&(rhp_gcfg_udp_encap_for_v6_after_rx_rockhopper_also),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"enable_childsa_outb_after_n_secs",
				val_p: 				(void*)&(rhp_gcfg_enable_childsa_outb_after_n_secs),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_sess_resume_init_enabled",
				val_p: 				(void*)&(rhp_gcfg_ikev2_sess_resume_init_enabled),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_sess_resume_resp_enabled",
				val_p: 				(void*)&(rhp_gcfg_ikev2_sess_resume_resp_enabled),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_sess_resume_key_update_interval",
				val_p: 				(void*)&(rhp_gcfg_ikev2_sess_resume_key_update_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_sess_resume_key_update_interval_min",
				val_p: 				(void*)&(rhp_gcfg_ikev2_sess_resume_key_update_interval_min),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_sess_resume_ticket_lifetime",
				val_p: 				(void*)&(rhp_gcfg_ikev2_sess_resume_ticket_lifetime),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_sess_resume_resp_tkt_revocation",
				val_p: 				(void*)&(rhp_gcfg_ikev2_sess_resume_resp_tkt_revocation),
		},
		{
				type: 					RHP_XML_DT_DOUBLE,
				val_name: 	"ikev2_sess_resume_tkt_rvk_bfltr_false_ratio",
				val_p: 				(void*)&(rhp_gcfg_ikev2_sess_resume_tkt_rvk_bfltr_false_ratio),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_sess_resume_tkt_rvk_bfltr_max_tkts",
				val_p: 				(void*)&(rhp_gcfg_ikev2_sess_resume_tkt_rvk_bfltr_max_tkts),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"def_eap_server_if_only_single_rlm_defined",
				val_p: 				(void*)&(rhp_gcfg_def_eap_server_if_only_single_rlm_defined),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev_other_auth_disabled_if_null_auth_enabled",
				val_p: 				(void*)&(rhp_gcfg_ikev_other_auth_disabled_if_null_auth_enabled),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"disabled_trace_write_for_misc_events",
				val_p: 				(void*)&(rhp_gcfg_disabled_trace_write_for_misc_events),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"v6_allow_auto_tss_type",
				val_p: 				(void*)&(rhp_gcfg_v6_allow_auto_tss_type),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_itnl_net_convergence_interval",
				val_p: 				(void*)&(rhp_gcfg_ikev2_itnl_net_convergence_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_itnl_net_convergence_max_wait_times",
				val_p: 				(void*)&(rhp_gcfg_ikev2_itnl_net_convergence_max_wait_times),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"bridge_tx_garp_for_vpn_peers",
				val_p: 				(void*)&(rhp_gcfg_bridge_tx_garp_for_vpn_peers),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"bridge_tx_unsol_nd_adv_for_vpn_peers",
				val_p: 				(void*)&(rhp_gcfg_bridge_tx_unsol_nd_adv_for_vpn_peers),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"radius_min_pkt_len",
				val_p: 				(void*)&(rhp_gcfg_radius_min_pkt_len),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"radius_max_pkt_len",
				val_p: 				(void*)&(rhp_gcfg_radius_max_pkt_len),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"radius_secondary_server_hold_time",
				val_p: 				(void*)&(rhp_gcfg_radius_secondary_server_hold_time),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"radius_mschapv2_eap_identity_not_protected",
				val_p: 				(void*)&(rhp_gcfg_radius_mschapv2_eap_identity_not_protected),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"radius_acct_max_sessions",
				val_p: 				(void*)&(rhp_gcfg_radius_acct_max_sessions),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"radius_acct_max_queued_tx_messages",
				val_p: 				(void*)&(rhp_gcfg_radius_acct_max_queued_tx_messages),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ip_routing_disabled",
				val_p: 				(void*)&(rhp_gcfg_ip_routing_disabled),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ip_routing_cache_max_entries_v4",
				val_p: 				(void*)&(rhp_gcfg_ip_routing_cache_max_entries_v4),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ip_routing_cache_max_entries_v6",
				val_p: 				(void*)&(rhp_gcfg_ip_routing_cache_max_entries_v6),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ip_routing_cache_hold_time",
				val_p: 				(void*)&(rhp_gcfg_ip_routing_cache_hold_time),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ip_routing_cache_aging_interval",
				val_p: 				(void*)&(rhp_gcfg_ip_routing_cache_aging_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ip_routing_cache_hash_size",
				val_p: 				(void*)&(rhp_gcfg_ip_routing_cache_hash_size),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"mac_cache_hash_size",
				val_p: 				(void*)&(rhp_gcfg_mac_cache_hash_size),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"neigh_cache_hash_size",
				val_p: 				(void*)&(rhp_gcfg_neigh_cache_hash_size),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ip_routing_max_entries_v4",
				val_p: 				(void*)&(rhp_gcfg_ip_routing_max_entries_v4),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ip_routing_max_entries_v6",
				val_p: 				(void*)&(rhp_gcfg_ip_routing_max_entries_v6),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ip_routing_hash_bucket_init_size",
				val_p: 				(void*)&(rhp_gcfg_ip_routing_hash_bucket_init_size),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ip_routing_hash_bucket_max_size",
				val_p: 				(void*)&(rhp_gcfg_ip_routing_hash_bucket_max_size),
		},
		{
				type: 					RHP_XML_DT_DOUBLE,
				val_name: 	"ip_routing_hash_bucket_max_occupancy_ratio",
				val_p: 				(void*)&(rhp_gcfg_ip_routing_hash_bucket_max_occupancy_ratio),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ip_routing_cache_dst_addr_only",
				val_p: 				(void*)&(rhp_gcfg_ip_routing_cache_dst_addr_only),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ip_routing_coarse_tick_interval",
				val_p: 				(void*)&(rhp_gcfg_ip_routing_coarse_tick_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"nhrp_default_hop_count",
				val_p: 				(void*)&(rhp_gcfg_nhrp_default_hop_count),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"nhrp_cache_hold_time",
				val_p: 				(void*)&(rhp_gcfg_nhrp_cache_hold_time),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"nhrp_cache_update_interval",
				val_p: 				(void*)&(rhp_gcfg_nhrp_cache_update_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"nhrp_cache_update_interval_error",
				val_p: 				(void*)&(rhp_gcfg_nhrp_cache_update_interval_error),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"nhrp_cache_hash_size",
				val_p: 				(void*)&(rhp_gcfg_nhrp_cache_hash_size),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"nhrp_cache_aging_interval",
				val_p: 				(void*)&(rhp_gcfg_nhrp_cache_aging_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"nhrp_cache_max_entries",
				val_p: 				(void*)&(rhp_gcfg_nhrp_cache_max_entries),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"nhrp_max_request_sessions",
				val_p: 				(void*)&(rhp_gcfg_nhrp_max_request_sessions),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"nhrp_registration_req_tx_margin_time",
				val_p: 				(void*)&(rhp_gcfg_nhrp_registration_req_tx_margin_time),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"nhrp_request_session_timeout",
				val_p: 				(void*)&(rhp_gcfg_nhrp_request_session_timeout),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"nhrp_request_session_timeout_max",
				val_p: 				(void*)&(rhp_gcfg_nhrp_request_session_timeout_max),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"nhrp_request_session_retry_times",
				val_p: 				(void*)&(rhp_gcfg_nhrp_request_session_retry_times),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"internal_net_max_peer_addrs",
				val_p: 				(void*)&(rhp_gcfg_internal_net_max_peer_addrs),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"nhrp_traffic_indication_rate_limit",
				val_p: 				(void*)&(rhp_gcfg_nhrp_traffic_indication_rate_limit),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"nhrp_traffic_indication_orig_pkt_len",
				val_p: 				(void*)&(rhp_gcfg_nhrp_traffic_indication_orig_pkt_len),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"nhrp_strictly_check_addr_uniqueness",
				val_p: 				(void*)&(rhp_gcfg_nhrp_strictly_check_addr_uniqueness),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"nhrp_registration_req_cie_prefix_len",
				val_p: 				(void*)&(rhp_gcfg_nhrp_registration_req_cie_prefix_len),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"nhrp_registration_req_cie_prefix_len_v6",
				val_p: 				(void*)&(rhp_gcfg_nhrp_registration_req_cie_prefix_len_v6),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"nhrp_cie_mtu",
				val_p: 				(void*)&(rhp_gcfg_nhrp_cie_mtu),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dmvpn_vpn_conn_idle_timeout",
				val_p: 				(void*)&(rhp_gcfg_dmvpn_vpn_conn_idle_timeout),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dmvpn_connect_shortcut_wait_random_range",
				val_p: 				(void*)&(rhp_gcfg_dmvpn_connect_shortcut_wait_random_range),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dmvpn_connect_shortcut_rate_limit",
				val_p: 				(void*)&(rhp_gcfg_dmvpn_connect_shortcut_rate_limit),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dmvpn_dont_handle_traffic_indication",
				val_p: 				(void*)&(rhp_gcfg_dmvpn_dont_handle_traffic_indication),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dmvpn_only_tx_resolution_rep_via_nhs",
				val_p: 				(void*)&(rhp_gcfg_dmvpn_only_tx_resolution_rep_via_nhs),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dmvpn_tx_resolution_rep_via_nhs",
				val_p: 				(void*)&(rhp_gcfg_dmvpn_tx_resolution_rep_via_nhs),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"packet_capture_timer_check_interval",
				val_p: 				(void*)&(rhp_gcfg_packet_capture_timer_check_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev1_enabled",
				val_p: 				(void*)&(rhp_gcfg_ikev1_enabled),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev1_main_mode_enabled",
				val_p: 				(void*)&(rhp_gcfg_ikev1_main_mode_enabled),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev1_aggressive_mode_enabled",
				val_p: 				(void*)&(rhp_gcfg_ikev1_aggressive_mode_enabled),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"def_ikev1_if_only_single_rlm_defined",
				val_p: 				(void*)&(rhp_gcfg_def_ikev1_if_only_single_rlm_defined),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev1_nat_t_disabled",
				val_p: 				(void*)&(rhp_gcfg_ikev1_nat_t_disabled),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ca_dn_ders_max_size",
				val_p: 				(void*)&(rhp_gcfg_ca_dn_ders_max_size),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"check_certreq_ca_dns",
				val_p: 				(void*)&(rhp_gcfg_check_certreq_ca_dns),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"strictly_cmp_certreq_ca_dns",
				val_p: 				(void*)&(rhp_gcfg_strictly_cmp_certreq_ca_dns),
		},
		{-1,NULL,NULL},
};

//
// [CAUTION]
//
//  IKE SA's global cfg params are valid only for Main process.
//
rhp_gcfg_param rhp_gcfg_ikesa_params[] = {
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ike_port",
				val_p: 				(void*)&(rhp_gcfg_ike_port),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ike_nat_t_port",
				val_p: 				(void*)&(rhp_gcfg_ike_port_nat_t),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"max_ike_packet_size",
				val_p: 				(void*)&(rhp_gcfg_max_ike_packet_size),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"retransmit_times",
				val_p: 				(void*)&(rhp_gcfg_ike_retry_times),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"init_retransmit_times",
				val_p: 				(void*)&(rhp_gcfg_ike_init_retry_times),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"retransmit_init_interval",
				val_p: 				(void*)&(rhp_gcfg_ike_retry_init_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"retransmit_max_interval",
				val_p: 				(void*)&(rhp_gcfg_ike_retry_max_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"lifetime_larval",
				val_p: 				(void*)&(rhp_gcfg_ikesa_lifetime_larval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"lifetime_eap_larval",
				val_p: 				(void*)&(rhp_gcfg_ikesa_lifetime_eap_larval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"lifetime_soft",
				val_p: 				(void*)&(rhp_gcfg_ikesa_lifetime_soft),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"lifetime_hard",
				val_p: 				(void*)&(rhp_gcfg_ikesa_lifetime_hard),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"lifetime_deleted",
				val_p: 				(void*)&(rhp_gcfg_ikesa_lifetime_deleted),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"keep_alive_interval",
				val_p: 				(void*)&(rhp_gcfg_keep_alive_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"always_exec_keep_alive",
				val_p: 				(void*)&(rhp_gcfg_always_exec_keep_alive),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"nat_t_keep_alive_interval",
				val_p: 				(void*)&(rhp_gcfg_nat_t_keep_alive_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"nat_t_keep_alive_packets",
				val_p: 				(void*)&(rhp_gcfg_nat_t_keep_alive_packets),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"cookie",
				val_p: 				(void*)&(rhp_gcfg_ikesa_cookie),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"cookies_max_open_req_per_sec",
				val_p: 				(void*)&(rhp_gcfg_ikesa_cookie_max_open_req_per_sec),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"cookies_max_half_open_sessions",
				val_p: 				(void*)&(rhp_gcfg_ikesa_cookie_max_half_open_sessions),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"cookies_refresh_interval",
				val_p: 				(void*)&(rhp_gcfg_ikesa_cookie_refresh_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"cookies_max_pend_packets",
				val_p: 				(void*)&(rhp_gcfg_ikesa_cookie_max_pend_packets),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"resp_not_rekeying",
				val_p: 				(void*)&(rhp_gcfg_ikesa_resp_not_rekeying),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"max_cert_payloads",
				val_p: 				(void*)&(rhp_gcfg_max_cert_payloads),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"nonce_size",
				val_p: 				(void*)&(rhp_gcfg_nonce_size),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev1_min_nonce_size",
				val_p: 				(void*)&(rhp_gcfg_ikev1_min_nonce_size),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"strict_peer_addr_port_check",
				val_p: 				(void*)&(rhp_gcfg_strict_peer_addr_port_check),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"remote_cfg_narrow_ts_i",
				val_p: 				(void*)&(rhp_gcfg_ikesa_remote_cfg_narrow_ts_i),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"responder_tx_certreq",
				val_p: 				(void*)&(rhp_gcfg_responder_tx_all_cas_certreq),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"delete_ikesa_if_no_childsa_exists",
				val_p: 				(void*)&(rhp_gcfg_delete_ikesa_if_no_childsa_exists),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"qcd_enabled",
				val_p: 				(void*)&(rhp_gcfg_ikev2_qcd_enabled),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"qcd_min_token_len",
				val_p: 				(void*)&(rhp_gcfg_ikev2_qcd_min_token_len),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"qcd_max_token_len",
				val_p: 				(void*)&(rhp_gcfg_ikev2_qcd_max_token_len),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"qcd_max_packets_per_sec",
				val_p: 				(void*)&(rhp_gcfg_ikev2_qcd_max_rx_packets_per_sec),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"qcd_max_rx_err_per_sec",
				val_p: 				(void*)&(rhp_gcfg_ikev2_qcd_max_rx_err_per_sec),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"qcd_max_pend_packets",
				val_p: 				(void*)&(rhp_gcfg_ikev2_qcd_max_pend_packets),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"qcd_enabled_time",
				val_p: 				(void*)&(rhp_gcfg_ikev2_qcd_enabled_time),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ike_retransmit_reps_limit_per_sec",
				val_p: 				(void*)&(rhp_gcfg_ike_retransmit_reps_limit_per_sec),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"mobike_rt_check_convergence_interval",
				val_p: 				(void*)&(rhp_gcfg_ikev2_mobike_rt_check_convergence_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"mobike_rt_check_interval_msec",
				val_p: 				(void*)&(rhp_gcfg_ikev2_mobike_rt_check_interval_msec),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"mobike_rt_check_retry_interval_msec",
				val_p: 				(void*)&(rhp_gcfg_ikev2_mobike_rt_check_retry_interval_msec),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"mobike_rt_check_max_retries",
				val_p: 				(void*)&(rhp_gcfg_ikev2_mobike_rt_check_max_retries),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"mobike_resp_keep_alive_interval",
				val_p: 				(void*)&(rhp_gcfg_ikev2_mobike_resp_keep_alive_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"mobike_resp_keep_alive_retry_interval",
				val_p: 				(void*)&(rhp_gcfg_ikev2_mobike_resp_keep_alive_retry_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"mobike_resp_keep_alive_max_retries",
				val_p: 				(void*)&(rhp_gcfg_ikev2_mobike_resp_keep_alive_max_retries),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"mobike_rt_check_on_nat_t_port",
				val_p: 				(void*)&(rhp_gcfg_ikev2_mobike_rt_check_on_nat_t_port),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"mobike_dynamically_disable_nat_t",
				val_p: 				(void*)&(rhp_gcfg_ikev2_mobike_dynamically_disable_nat_t),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"mobike_watch_nat_gw_reflexive_addr",
				val_p: 				(void*)&(rhp_gcfg_ikev2_mobike_watch_nat_gw_reflexive_addr),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"mobike_init_rt_check_hold_time",
				val_p: 				(void*)&(rhp_gcfg_ikev2_mobike_init_rt_check_hold_time),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"mobike_init_rt_check_hold_ka_interval",
				val_p: 				(void*)&(rhp_gcfg_ikev2_mobike_init_rt_check_hold_ka_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"mobike_init_rt_check_hold_ka_max_retries",
				val_p: 				(void*)&(rhp_gcfg_ikev2_mobike_init_rt_check_hold_ka_max_retries),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"mobike_additional_addr_check_dnat",
				val_p: 				(void*)&(rhp_gcfg_ikev2_mobike_additional_addr_check_dnat),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"reject_auth_exchg_without_childsa",
				val_p: 				(void*)&(rhp_gcfg_reject_auth_exchg_without_childsa),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_hash_url_http_timeout",
				val_p: 				(void*)&(rhp_gcfg_ikev2_hash_url_http_timeout),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_rx_if_strictly_check",
				val_p: 				(void*)&(rhp_gcfg_ikev2_rx_if_strictly_check),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_hash_url_max_len",
				val_p: 				(void*)&(rhp_gcfg_ikev2_hash_url_max_len),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"dont_tx_general_err_resp",
				val_p: 				(void*)&(rhp_gcfg_ikev2_dont_tx_general_err_resp),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_enable_fragmentation",
				val_p: 				(void*)&(rhp_gcfg_ikev2_enable_fragmentation),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_max_fragments",
				val_p: 				(void*)&(rhp_gcfg_ikev2_max_fragments),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_frag_max_packet_size",
				val_p: 				(void*)&(rhp_gcfg_ikev2_frag_max_packet_size),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_frag_size_v4",
				val_p: 				(void*)&(rhp_gcfg_ikev2_frag_size_v4),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_frag_size_v6",
				val_p: 				(void*)&(rhp_gcfg_ikev2_frag_size_v6),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_frag_min_size_v4",
				val_p: 				(void*)&(rhp_gcfg_ikev2_frag_min_size_v4),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_frag_min_size_v6",
				val_p: 				(void*)&(rhp_gcfg_ikev2_frag_min_size_v6),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_frag_use_min_size",
				val_p: 				(void*)&(rhp_gcfg_ikev2_frag_use_min_size),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_frag_rx_timeout",
				val_p: 				(void*)&(rhp_gcfg_ikev2_frag_rx_timeout),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_rx_peer_realm_id",
				val_p: 				(void*)&(rhp_gcfg_ikev2_rx_peer_realm_id_req),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"eap_client_use_ikev2_random_addr_id",
				val_p: 				(void*)&(rhp_gcfg_eap_client_use_ikev2_random_addr_id),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_tx_new_req_retry_interval",
				val_p: 				(void*)&(rhp_gcfg_ikev2_tx_new_req_retry_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_rekey_ikesa_delete_deferred_init",
				val_p: 				(void*)&(rhp_gcfg_ikev2_rekey_ikesa_delete_deferred_init),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_rekey_ikesa_delete_deferred_resp",
				val_p: 				(void*)&(rhp_gcfg_ikev2_rekey_ikesa_delete_deferred_resp),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_mobike_resp_null_auth_keep_alive_interval",
				val_p: 				(void*)&(rhp_gcfg_ikev2_mobike_resp_null_auth_keep_alive_interval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_cfg_rmt_clt_req_old_addr",
				val_p: 				(void*)&(rhp_gcfg_ikev2_cfg_rmt_clt_req_old_addr),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_cfg_v6_internal_addr_def_prefix_len",
				val_p: 				(void*)&(rhp_gcfg_ikev2_cfg_v6_internal_addr_def_prefix_len),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_auth_tkt_shortcut_session_key_len",
				val_p: 				(void*)&(rhp_gcfg_ikev2_auth_tkt_shortcut_session_key_len),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_auth_tkt_shortcut_session_key_min_len",
				val_p: 				(void*)&(rhp_gcfg_ikev2_auth_tkt_shortcut_session_key_min_len),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_auth_tkt_shortcut_session_key_max_len",
				val_p: 				(void*)&(rhp_gcfg_ikev2_auth_tkt_shortcut_session_key_max_len),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev2_auth_tkt_lifetime",
				val_p: 				(void*)&(rhp_gcfg_ikev2_auth_tkt_lifetime),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev1_dpd_enabled",
				val_p: 				(void*)&(rhp_gcfg_ikev1_dpd_enabled),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev1_lifetime_deleted",
				val_p: 				(void*)&(rhp_gcfg_ikev1_ikesa_lifetime_deleted),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev1_tx_redundant_delete_sa_mesg",
				val_p: 				(void*)&(rhp_gcfg_ikev1_tx_redundant_delete_sa_mesg),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev1_retx_pkts_num",
				val_p: 				(void*)&(rhp_gcfg_ikev1_retx_pkts_num),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev1_dont_tx_initial_contact",
				val_p: 				(void*)&(rhp_gcfg_ikev1_dont_tx_initial_contact),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev1_ikesa_min_lifetime",
				val_p: 				(void*)&(rhp_gcfg_ikev1_ikesa_min_lifetime),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev1_ikesa_rekey_margin",
				val_p: 				(void*)&(rhp_gcfg_ikev1_ikesa_rekey_margin),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev1_xauth_allow_null_terminated_password",
				val_p: 				(void*)&(rhp_gcfg_ikev1_xauth_allow_null_terminated_password),
		},
		{-1,NULL,NULL},
};


//
// [CAUTION]
//
//  Child SA's global cfg params are valid only for Main process.
//
rhp_gcfg_param rhp_gcfg_childsa_params[] = {
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"lifetime_larval",
				val_p: 				(void*)&(rhp_gcfg_childsa_lifetime_larval),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"lifetime_soft",
				val_p: 				(void*)&(rhp_gcfg_childsa_lifetime_soft),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"lifetime_hard",
				val_p: 				(void*)&(rhp_gcfg_childsa_lifetime_hard),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"lifetime_deleted",
				val_p: 				(void*)&(rhp_gcfg_childsa_lifetime_deleted),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"anti_replay",
				val_p: 				(void*)&(rhp_gcfg_childsa_anti_replay),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"anti_replay_win_size",
				val_p: 				(void*)&(rhp_gcfg_childsa_anti_replay_win_size),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"tfc_padding",
				val_p: 				(void*)&(rhp_gcfg_childsa_tfc_padding),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"pfs",
				val_p: 				(void*)&(rhp_gcfg_childsa_pfs),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"resp_not_rekeying",
				val_p: 				(void*)&(rhp_gcfg_childsa_resp_not_rekeying),
		},
		{
				type: 					RHP_XML_DT_ULONGLONG,
				val_name: 	"max_seq_esn",
				val_p: 				(void*)&(rhp_gcfg_childsa_max_seq_esn),
		},
		{
				type: 					RHP_XML_DT_UINT,
				val_name: 	"max_seq_non_esn",
				val_p: 				(void*)&(rhp_gcfg_childsa_max_seq_non_esn),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"esp_dont_match_selectors",
				val_p: 				(void*)&(rhp_gcfg_esp_dont_match_selectors),
		},
		{
				type: 					RHP_XML_DT_UINT,
				val_name: 	"v4_icmp_is_critical",
				val_p: 				(void*)&(rhp_gcfg_v4_icmp_is_critical),
		},

		{
				type: 					RHP_XML_DT_UINT,
				val_name: 	"ikev2_rekey_childsa_delete_deferred_init",
				val_p: 				(void*)&(rhp_gcfg_ikev2_rekey_childsa_delete_deferred_init),
		},
		{
				type: 					RHP_XML_DT_UINT,
				val_name: 	"ikev2_rekey_childsa_delete_deferred_resp",
				val_p: 				(void*)&(rhp_gcfg_ikev2_rekey_childsa_delete_deferred_resp),
		},
		{
				type: 					RHP_XML_DT_UINT,
				val_name: 	"ikev2_max_create_child_sa_failure",
				val_p: 				(void*)&(rhp_gcfg_ikev2_max_create_child_sa_failure),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev1_lifetime_deleted",
				val_p: 				(void*)&(rhp_gcfg_ikev1_ipsecsa_lifetime_deleted),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev1_ipsecsa_min_lifetime",
				val_p: 				(void*)&(rhp_gcfg_ikev1_ipsecsa_min_lifetime),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev1_ipsecsa_rekey_margin",
				val_p: 				(void*)&(rhp_gcfg_ikev1_ipsecsa_rekey_margin),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev1_ipsecsa_tx_responder_lifetime",
				val_p: 				(void*)&(rhp_gcfg_ikev1_ipsecsa_tx_responder_lifetime),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev1_xauth_tx_error_margin",
				val_p: 				(void*)&(rhp_gcfg_ikev1_xauth_tx_error_margin),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev1_commit_bit_enabled",
				val_p: 				(void*)&(rhp_gcfg_ikev1_commit_bit_enabled),
		},
		{
				type: 					RHP_XML_DT_INT,
				val_name: 	"ikev1_mode_cfg_tx_subnets",
				val_p: 				(void*)&(rhp_gcfg_ikev1_mode_cfg_tx_subnets),
		},
		{
				type: 					RHP_XML_DT_ULONG,
				val_name: 	"ikev1_mode_cfg_addr_expiry",
				val_p: 				(void*)&(rhp_gcfg_ikev1_mode_cfg_addr_expiry),
		},
		{
				type: 					RHP_XML_DT_ULONG,
				val_name: 	"ikev1_ipsecsa_gre_strictly_match_ts",
				val_p: 				(void*)&(rhp_gcfg_ikev1_ipsecsa_gre_strictly_match_ts),
		},
		{-1,NULL,NULL},
};


rhp_cfg_ikesa* rhp_ikesa_config = NULL;
rhp_cfg_childsa* rhp_childsa_config = NULL;

rhp_cfg_ikev1_ikesa* rhp_ikev1_ikesa_config = NULL;
rhp_cfg_ikev1_ipsecsa* rhp_ikev1_ipsecsa_config = NULL;


rhp_cfg_peer_acl* rhp_cfg_peer_acl_list = NULL;


rhp_cfg_admin_service* rhp_cfg_admin_services = NULL;
rhp_http_listen* rhp_cfg_admin_services_listen_sks = NULL;

rhp_cfg_firewall* rhp_cfg_firewall_rules = NULL;

rhp_mutex_t rhp_gcfg_hash_url_lock;
rhp_gcfg_hash_url* rhp_global_cfg_hash_url = NULL;


static rhp_cfg_transform _rhp_cfg_ikesa_security_def_encr[] = {
  {
    next:           &(_rhp_cfg_ikesa_security_def_encr[1]),
    priority: 10,
    type:           RHP_PROTO_IKE_TRANSFORM_TYPE_ENCR,
    id:             RHP_PROTO_IKE_TRANSFORM_ID_ENCR_AES_CBC,
    key_bits_len:   256,
  },
  {
    next:           &(_rhp_cfg_ikesa_security_def_encr[2]),
    priority: 20,
    type:           RHP_PROTO_IKE_TRANSFORM_TYPE_ENCR,
    id:             RHP_PROTO_IKE_TRANSFORM_ID_ENCR_AES_CBC,
    key_bits_len:   192,
  },
  {
    next:           &(_rhp_cfg_ikesa_security_def_encr[3]),
    priority: 30,
    type:           RHP_PROTO_IKE_TRANSFORM_TYPE_ENCR,
    id:             RHP_PROTO_IKE_TRANSFORM_ID_ENCR_AES_CBC,
    key_bits_len:   128,
  },
  {
    next:           NULL,
    priority: 40,
    type:           RHP_PROTO_IKE_TRANSFORM_TYPE_ENCR,
    id:             RHP_PROTO_IKE_TRANSFORM_ID_ENCR_3DES,
    key_bits_len:   0,
  },
};

static rhp_cfg_transform _rhp_cfg_ikesa_security_def_prf[] = {
	{
	  next:           &(_rhp_cfg_ikesa_security_def_prf[1]),
	  priority: 10,
	  type:           RHP_PROTO_IKE_TRANSFORM_TYPE_PRF,
	  id:             RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_512,
	},
	{
	  next:           &(_rhp_cfg_ikesa_security_def_prf[2]),
	  priority: 20,
	  type:           RHP_PROTO_IKE_TRANSFORM_TYPE_PRF,
	  id:             RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_384,
	},
	{
	  next:           &(_rhp_cfg_ikesa_security_def_prf[3]),
	  priority: 30,
	  type:           RHP_PROTO_IKE_TRANSFORM_TYPE_PRF,
	  id:             RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_256,
	},
  {
//    next:           &(_rhp_cfg_ikesa_security_def_prf[4]),
    next:           NULL,
    priority: 40,
    type:           RHP_PROTO_IKE_TRANSFORM_TYPE_PRF,
    id:             RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA1,
  },
/*
  {
    next:           NULL,
    priority: 50,
    type:           RHP_PROTO_IKE_TRANSFORM_TYPE_PRF,
    id:             RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_MD5,
  },
*/
};

static rhp_cfg_transform _rhp_cfg_ikesa_security_def_integ[] = {
	{
	  next:           &(_rhp_cfg_ikesa_security_def_integ[1]),
	  priority: 10,
	  type:           RHP_PROTO_IKE_TRANSFORM_TYPE_INTEG,
	  id:             RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_512_256,
	},
	{
	  next:           &(_rhp_cfg_ikesa_security_def_integ[2]),
	  priority: 20,
	  type:           RHP_PROTO_IKE_TRANSFORM_TYPE_INTEG,
	  id:             RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_384_192,
	},
	{
	  next:           &(_rhp_cfg_ikesa_security_def_integ[3]),
	  priority: 30,
	  type:           RHP_PROTO_IKE_TRANSFORM_TYPE_INTEG,
	  id:             RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_256_128,
	},
  {
//    next:           &(_rhp_cfg_ikesa_security_def_integ[4]),
    next:           NULL,
    priority: 40,
    type:           RHP_PROTO_IKE_TRANSFORM_TYPE_INTEG,
    id:             RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA1_96,
  },
/*
  {
    next:           NULL,
    priority: 50,
    type:           RHP_PROTO_IKE_TRANSFORM_TYPE_INTEG,
    id:             RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_MD5_96,
  },
*/
};

static rhp_cfg_transform _rhp_cfg_ikesa_security_def_dh[] = {
  {
    next:           &(_rhp_cfg_ikesa_security_def_dh[1]),
    priority: 10,
    type:           RHP_PROTO_IKE_TRANSFORM_TYPE_DH,
    id:             RHP_PROTO_IKE_TRANSFORM_ID_DH_14,
  },
  {
    next:           &(_rhp_cfg_ikesa_security_def_dh[2]),
    priority: 20,
    type:           RHP_PROTO_IKE_TRANSFORM_TYPE_DH,
    id:             RHP_PROTO_IKE_TRANSFORM_ID_DH_5,
  },
  {
    next:           NULL,
    priority: 30,
    type:           RHP_PROTO_IKE_TRANSFORM_TYPE_DH,
    id:             RHP_PROTO_IKE_TRANSFORM_ID_DH_2,
  },
};

static rhp_cfg_transform _rhp_cfg_childsa_security_def_esn[] = {
  {
  	next:           &(_rhp_cfg_childsa_security_def_esn[1]),
    priority: 10,
    type:           RHP_PROTO_IKE_TRANSFORM_TYPE_ESN,
    id:             RHP_PROTO_IKE_TRANSFORM_ESN_ENABLE,
  },
  {
    next:           NULL,
    priority: 20,
    type:           RHP_PROTO_IKE_TRANSFORM_TYPE_ESN,
    id:             RHP_PROTO_IKE_TRANSFORM_ESN_DISABLE,
  },
};


static rhp_cfg_ikesa _rhp_ikesa_config_def  = {
  protocol_id       : RHP_PROTO_IKE_PROTOID_IKE,
  encr_trans_list   : _rhp_cfg_ikesa_security_def_encr,
  prf_trans_list    : _rhp_cfg_ikesa_security_def_prf,
  integ_trans_list  : _rhp_cfg_ikesa_security_def_integ,
  dh_trans_list     : _rhp_cfg_ikesa_security_def_dh,
};

static rhp_cfg_childsa _rhp_childsa_config_def  = {
  protocol_id     : RHP_PROTO_IKE_PROTOID_ESP,
  encr_trans_list : _rhp_cfg_ikesa_security_def_encr,
  integ_trans_list: _rhp_cfg_ikesa_security_def_integ,
  esn_trans       : _rhp_cfg_childsa_security_def_esn,
};


static rhp_cfg_ikev1_transform _rhp_cfg_ikev1_ikesa_security_def[] = {
		{
	  	next:     &(_rhp_cfg_ikev1_ikesa_security_def[1]),
	    priority: 10,
	    enc_alg:  RHP_PROTO_IKEV1_P1_ATTR_ENC_AES_CBC,
	    hash_alg: RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA2_256,
	    dh_group: RHP_PROTO_IKEV1_ATTR_GROUP_MODP_2048,
	    key_bits_len: 256,
	  },
	  {
	  	next:     &(_rhp_cfg_ikev1_ikesa_security_def[2]),
	    priority: 10,
	    enc_alg:  RHP_PROTO_IKEV1_P1_ATTR_ENC_AES_CBC,
	    hash_alg: RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA2_256,
	    dh_group: RHP_PROTO_IKEV1_ATTR_GROUP_MODP_2048,
	    key_bits_len: 128,
	  },
	  {
	  	next:     &(_rhp_cfg_ikev1_ikesa_security_def[3]),
	    priority: 10,
	    enc_alg:  RHP_PROTO_IKEV1_P1_ATTR_ENC_AES_CBC,
	    hash_alg: RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA1,
	    dh_group: RHP_PROTO_IKEV1_ATTR_GROUP_MODP_2048,
	    key_bits_len: 256,
	  },
	  {
	  	next:     &(_rhp_cfg_ikev1_ikesa_security_def[4]),
	    priority: 20,
	    enc_alg:  RHP_PROTO_IKEV1_P1_ATTR_ENC_AES_CBC,
	    hash_alg: RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA1,
	    dh_group: RHP_PROTO_IKEV1_ATTR_GROUP_MODP_2048,
	    key_bits_len: 128,
	  },
	  {
		  next:     &(_rhp_cfg_ikev1_ikesa_security_def[5]),
	    priority: 30,
	    enc_alg:  RHP_PROTO_IKEV1_P1_ATTR_ENC_AES_CBC,
	    hash_alg: RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA2_256,
	    dh_group: RHP_PROTO_IKEV1_ATTR_GROUP_MODP_1536,
	    key_bits_len: 256,
	  },
	  {
		  next:     &(_rhp_cfg_ikev1_ikesa_security_def[6]),
	    priority: 30,
	    enc_alg:  RHP_PROTO_IKEV1_P1_ATTR_ENC_AES_CBC,
	    hash_alg: RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA1,
	    dh_group: RHP_PROTO_IKEV1_ATTR_GROUP_MODP_1536,
	    key_bits_len: 256,
	  },
	  {
		  next:     &(_rhp_cfg_ikev1_ikesa_security_def[7]),
	    priority: 40,
	    enc_alg:  RHP_PROTO_IKEV1_P1_ATTR_ENC_AES_CBC,
	    hash_alg: RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA2_256,
	    dh_group: RHP_PROTO_IKEV1_ATTR_GROUP_MODP_1536,
	    key_bits_len: 128,
	  },
	  {
		  next:     &(_rhp_cfg_ikev1_ikesa_security_def[8]),
	    priority: 40,
	    enc_alg:  RHP_PROTO_IKEV1_P1_ATTR_ENC_AES_CBC,
	    hash_alg: RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA1,
	    dh_group: RHP_PROTO_IKEV1_ATTR_GROUP_MODP_1536,
	    key_bits_len: 128,
	  },

	  //
	  // For Android
	  //
	  {
		  next:     &(_rhp_cfg_ikev1_ikesa_security_def[9]),
	    priority: 40,
	    enc_alg:  RHP_PROTO_IKEV1_P1_ATTR_ENC_AES_CBC,
	    hash_alg: RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA2_256,
	    dh_group: RHP_PROTO_IKEV1_ATTR_GROUP_MODP_1024, // Umm...
	    key_bits_len: 256,
	  },

	  {
			next:     &(_rhp_cfg_ikev1_ikesa_security_def[10]),
	    priority: 50,
	    enc_alg:  RHP_PROTO_IKEV1_P1_ATTR_ENC_3DES_CBC,
	    hash_alg: RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA1,
	    dh_group: RHP_PROTO_IKEV1_ATTR_GROUP_MODP_2048,
	    key_bits_len: 0,
	  },
	  {
			next:     NULL,
	    priority: 60,
	    enc_alg:  RHP_PROTO_IKEV1_P1_ATTR_ENC_3DES_CBC,
	    hash_alg: RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA1,
	    dh_group: RHP_PROTO_IKEV1_ATTR_GROUP_MODP_1536,
	    key_bits_len: 0,
	  },
};

static rhp_cfg_ikev1_transform _rhp_cfg_ikev1_ipsecsa_security_def[] = {
	  {
	  	next:     &(_rhp_cfg_ikev1_ipsecsa_security_def[1]),
	    priority: 10,
	    dh_group : 0,
	    trans_id: RHP_PROTO_IKEV1_TF_ESP_AES_CBC,
	    auth_alg: RHP_PROTO_IKEV1_P2_ATTR_AUTH_HMAC_SHA1,
	    esn: 0,
	    key_bits_len: 256,
	  },
	  {
		  next:     &(_rhp_cfg_ikev1_ipsecsa_security_def[2]),
	    priority: 20,
	    dh_group : 0,
	    trans_id: RHP_PROTO_IKEV1_TF_ESP_AES_CBC,
	    auth_alg: RHP_PROTO_IKEV1_P2_ATTR_AUTH_HMAC_SHA1,
	    esn: 0,
	    key_bits_len: 128,
	  },
	  {
			next:     NULL,
	    priority: 30,
	    dh_group : 0,
	    trans_id: RHP_PROTO_IKEV1_TF_ESP_3DES,
	    auth_alg: RHP_PROTO_IKEV1_P2_ATTR_AUTH_HMAC_SHA1,
	    esn: 0,
	    key_bits_len: 0,
	  },
};

static rhp_cfg_ikev1_ikesa _rhp_ikev1_ikesa_config_def  = {
  trans_list   : _rhp_cfg_ikev1_ikesa_security_def,
};

static rhp_cfg_ikev1_ipsecsa _rhp_ikev1_ipsecsa_config_def  = {
  protocol_id     : RHP_PROTO_IKEV1_PROP_PROTO_ID_ESP,
  trans_list : _rhp_cfg_ikev1_ipsecsa_security_def,
};


static u8* _rhp_ca_pubkey_digests_cache = NULL;
static int _rhp_ca_pubkey_digests_cache_len = 0;
static int _rhp_ca_pubkey_digest_len = 0;

static u8* _rhp_ca_dn_ders_cache = NULL;
static int _rhp_ca_dn_ders_cache_len = 0;
static int _rhp_ca_dn_ders_cache_num = 0;


int rhp_cfg_transform_str2id(int trans_type,char* trans_name)
{
  switch( trans_type ){

    case RHP_PROTO_IKE_TRANSFORM_TYPE_ENCR:

      if( !strcasecmp(trans_name,"3des-cbc") ){
        return RHP_PROTO_IKE_TRANSFORM_ID_ENCR_3DES;
      }else if( !strcasecmp(trans_name,"aes-cbc") ){
        return RHP_PROTO_IKE_TRANSFORM_ID_ENCR_AES_CBC;
      }else if( !strcasecmp(trans_name,"null") ){
        return RHP_PROTO_IKE_TRANSFORM_ID_ENCR_NULL;
      }
      break;

    case RHP_PROTO_IKE_TRANSFORM_TYPE_PRF:

      if( !strcasecmp(trans_name,"hmac-md5") ){
        return RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_MD5;
      }else if( !strcasecmp(trans_name,"hmac-sha1") ){
        return RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA1;
      }else if( !strcasecmp(trans_name,"aes128-cbc") ){
        return RHP_PROTO_IKE_TRANSFORM_ID_PRF_AES128_CBC;
      }else if( !strcasecmp(trans_name,"hmac-sha2-256") ){
        return RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_256;
      }else if( !strcasecmp(trans_name,"hmac-sha2-384") ){
        return RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_384;
      }else if( !strcasecmp(trans_name,"hmac-sha2-512") ){
        return RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_512;
      }
      break;

    case RHP_PROTO_IKE_TRANSFORM_TYPE_INTEG:

      if( !strcasecmp(trans_name,"hmac-md5-96") ){
        return RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_MD5_96;
      }else if( !strcasecmp(trans_name,"hmac-sha1-96") ){
        return RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA1_96;
      }else if( !strcasecmp(trans_name,"aes-xcbc-96") ){
        return RHP_PROTO_IKE_TRANSFORM_ID_AUTH_AES_XCBC_96;
      }else if( !strcasecmp(trans_name,"hmac-sha2-256-128") ){
        return RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_256_128;
      }else if( !strcasecmp(trans_name,"hmac-sha2-384-192") ){
        return RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_384_192;
      }else if( !strcasecmp(trans_name,"hmac-sha2-512-256") ){
        return RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_512_256;
      }
      break;

    case RHP_PROTO_IKE_TRANSFORM_TYPE_DH:

      if( !strcasecmp(trans_name,"group14") ){
        return RHP_PROTO_IKE_TRANSFORM_ID_DH_14;
      }else if( !strcasecmp(trans_name,"group5") ){
        return RHP_PROTO_IKE_TRANSFORM_ID_DH_5;
      }else if( !strcasecmp(trans_name,"group2") ){
        return RHP_PROTO_IKE_TRANSFORM_ID_DH_2;
      }
      break;

    case RHP_PROTO_IKE_TRANSFORM_TYPE_ESN:

      if( !strcasecmp(trans_name,"esn_disable") ){
        return RHP_PROTO_IKE_TRANSFORM_ESN_DISABLE;
      }else if( !strcasecmp(trans_name,"esn_enable") ){
        return RHP_PROTO_IKE_TRANSFORM_ESN_ENABLE;
      }
      break;

    default:
      RHP_BUG("%d",trans_type);
      break;
  }
  return -1;
}

int rhp_cfg_transform_type_str2id(char* trans_name)
{
  if( !strcasecmp(trans_name,"encr") ){
    return RHP_PROTO_IKE_TRANSFORM_TYPE_ENCR;
  }else if( !strcasecmp(trans_name,"prf") ){
    return RHP_PROTO_IKE_TRANSFORM_TYPE_PRF;
  }else if( !strcasecmp(trans_name,"integ") ){
    return RHP_PROTO_IKE_TRANSFORM_TYPE_INTEG;
  }else if( !strcasecmp(trans_name,"dh") ){
    return RHP_PROTO_IKE_TRANSFORM_TYPE_DH;
  }else if( !strcasecmp(trans_name,"esn") ){
    return RHP_PROTO_IKE_TRANSFORM_TYPE_ESN;
  }
  RHP_BUG("%s",trans_name);
  return -1;
}


int rhp_cfg_ikev1_ikesa_attr_type_str2id(char* attr_type_name)
{

  if( !strcasecmp(attr_type_name,"encryption") ){
    return RHP_PROTO_IKEV1_P1_ATTR_TYPE_ENCRYPTION;
  }else if( !strcasecmp(attr_type_name,"hash") ){
    return RHP_PROTO_IKEV1_P1_ATTR_TYPE_HASH;
  }else if( !strcasecmp(attr_type_name,"group_desc") ){
    return RHP_PROTO_IKEV1_P1_ATTR_TYPE_GROUP_DESC;
  }

  RHP_BUG("%s",attr_type_name);
  return -1;
}

int rhp_cfg_ikev1_transform_id_str2id(char* attr_type_name)
{

  if( !strcasecmp(attr_type_name,"3des-cbc") ){
    return RHP_PROTO_IKEV1_TF_ESP_3DES;
  }else if( !strcasecmp(attr_type_name,"aes-cbc") ){
    return RHP_PROTO_IKEV1_TF_ESP_AES_CBC;
  }else if( !strcasecmp(attr_type_name,"esp-3des-cbc") ){
    return RHP_PROTO_IKEV1_TF_ESP_3DES;
  }else if( !strcasecmp(attr_type_name,"esp-aes-cbc") ){
    return RHP_PROTO_IKEV1_TF_ESP_AES_CBC;
  }else if( !strcasecmp(attr_type_name,"esp-null") ){
    return RHP_PROTO_IKEV1_TF_ESP_NULL;
  }else if( !strcasecmp(attr_type_name,"isakmp") ){
    return RHP_PROTO_IKEV1_TF_ISAKMP_KEY_IKE;
  }

  RHP_BUG("%s",attr_type_name);
  return -1;
}

int rhp_cfg_ikev1_ipsecsa_attr_type_str2id(char* attr_type_name)
{

  if( !strcasecmp(attr_type_name,"auth") ){
    return RHP_PROTO_IKEV1_P2_ATTR_TYPE_AUTH;
  }else if( !strcasecmp(attr_type_name,"esn") ){
    return RHP_PROTO_IKEV1_P2_ATTR_TYPE_ESN;
  }else if( !strcasecmp(attr_type_name,"group_desc") ){
    return RHP_PROTO_IKEV1_P2_ATTR_TYPE_GROUP_DESC;
  }

  RHP_BUG("%s",attr_type_name);
  return -1;
}

int rhp_cfg_ikev1_ikesa_attr_value_str2id(int attr_type,char* attr_val_name)
{
  switch( attr_type ){

    case RHP_PROTO_IKEV1_P1_ATTR_TYPE_ENCRYPTION:

      if( !strcasecmp(attr_val_name,"3des-cbc") ){
        return RHP_PROTO_IKEV1_P1_ATTR_ENC_3DES_CBC;
      }else if( !strcasecmp(attr_val_name,"aes-cbc") ){
        return RHP_PROTO_IKEV1_P1_ATTR_ENC_AES_CBC;
      }
      break;

    case RHP_PROTO_IKEV1_P1_ATTR_TYPE_HASH:

      if( !strcasecmp(attr_val_name,"md5") ){
        return RHP_PROTO_IKEV1_P1_ATTR_HASH_MD5;
      }else if( !strcasecmp(attr_val_name,"sha1") ){
        return RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA1;
      }else if( !strcasecmp(attr_val_name,"sha2-256") ){
        return RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA2_256;
      }else if( !strcasecmp(attr_val_name,"sha2-384") ){
        return RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA2_384;
      }else if( !strcasecmp(attr_val_name,"sha2-512") ){
        return RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA2_512;
      }
      break;

    case RHP_PROTO_IKEV1_P1_ATTR_TYPE_GROUP_DESC:

      if( !strcasecmp(attr_val_name,"group14") ){
        return RHP_PROTO_IKEV1_ATTR_GROUP_MODP_2048;
      }else if( !strcasecmp(attr_val_name,"group5") ){
        return RHP_PROTO_IKEV1_ATTR_GROUP_MODP_1536;
      }else if( !strcasecmp(attr_val_name,"group2") ){
        return RHP_PROTO_IKEV1_ATTR_GROUP_MODP_1024;
      }
      break;

    default:
      RHP_BUG("%d",attr_type);
      break;
  }
  return -1;
}

int rhp_cfg_ikev1_ipsecsa_attr_value_str2id(int attr_type,char* attr_val_name)
{
  switch( attr_type ){

    case RHP_PROTO_IKEV1_P2_ATTR_TYPE_AUTH:

      if( !strcasecmp(attr_val_name,"hmac-md5-96") ){
        return RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_MD5_96;
      }else if( !strcasecmp(attr_val_name,"hmac-sha1-96") ){
        return RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA1_96;
      }else if( !strcasecmp(attr_val_name,"aes-xcbc-96") ){
        return RHP_PROTO_IKE_TRANSFORM_ID_AUTH_AES_XCBC_96;
      }else if( !strcasecmp(attr_val_name,"hmac-sha2-256-128") ){
        return RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_256_128;
      }else if( !strcasecmp(attr_val_name,"hmac-sha2-384-192") ){
        return RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_384_192;
      }else if( !strcasecmp(attr_val_name,"hmac-sha2-512-256") ){
        return RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_512_256;
      }
      RHP_BUG("%d,%s",attr_type,attr_val_name);
      break;

    case RHP_PROTO_IKEV1_P2_ATTR_TYPE_ESN:

      if( !strcasecmp(attr_val_name,"enable") ){
        return RHP_PROTO_IKEV1_P2_ATTR_ESN_ENABLE;
      }else if( !strcasecmp(attr_val_name,"disable") ){
        return RHP_PROTO_IKEV1_P2_ATTR_ESN_DISABLE;
      }
      RHP_BUG("%d,%s",attr_type,attr_val_name);
      break;

    case RHP_PROTO_IKEV1_P2_ATTR_TYPE_GROUP_DESC:

      if( !strcasecmp(attr_val_name,"group14") ){
        return RHP_PROTO_IKEV1_ATTR_GROUP_MODP_2048;
      }else if( !strcasecmp(attr_val_name,"group5") ){
        return RHP_PROTO_IKEV1_ATTR_GROUP_MODP_1536;
      }else if( !strcasecmp(attr_val_name,"group2") ){
        return RHP_PROTO_IKEV1_ATTR_GROUP_MODP_1024;
      }
      RHP_BUG("%d,%s",attr_type,attr_val_name);
      break;

    default:
      RHP_BUG("%d",attr_type);
      break;
  }
  return -1;
}


int rhp_cfg_ipc_handle(rhp_ipcmsg *ipcmsg)
{
  int err = 0;
  rhp_vpn_realm* rlm = NULL;
  u8* p;

  RHP_TRC(0,RHPTRCID_CFG_IPC_HANDLE,"xLdp",ipcmsg,"IPC",ipcmsg->type,ipcmsg->len,ipcmsg);

  switch( ipcmsg->type ){

  case RHP_IPC_RESOLVE_MY_ID_REPLY:
  {
    rhp_ipcmsg_resolve_my_id_rep* my_id_rep = (rhp_ipcmsg_resolve_my_id_rep*)ipcmsg;

    if( ipcmsg->len < sizeof(rhp_ipcmsg_resolve_my_id_rep) ){
      RHP_BUG("%d",ipcmsg->len);
      goto error;
    }

    RHP_TRC(0,RHPTRCID_CFG_IPC_HANDLE_RESOLVE_MY_ID_REPLY_PARAMS,"xudddddddddddd",ipcmsg,my_id_rep->my_realm_id,my_id_rep->result,my_id_rep->my_id_type,my_id_rep->eap_sup_enabled,my_id_rep->eap_sup_method,my_id_rep->eap_sup_ask_for_user_key,my_id_rep->eap_sup_user_key_cache_enabled,my_id_rep->psk_for_peers,my_id_rep->rsa_sig_for_peers,my_id_rep->eap_for_peers,my_id_rep->null_auth_for_peers,my_id_rep->my_cert_issuer_dn_der_len,my_id_rep->untrust_sub_ca_cert_issuer_dn_der_len);

    if( !my_id_rep->result ){
      RHP_TRC(0,RHPTRCID_CFG_IPC_HANDLE_RESOLVE_MY_ID_REPLY_RESULT_ERR,"xd",ipcmsg,my_id_rep->result);
      err = -EINVAL;
      goto error;
    }

    p = (u8*)(my_id_rep + 1);

    if( ( my_id_rep->my_id_len &&
    			(my_id_rep->my_id_type == RHP_PROTO_IKE_ID_FQDN 			 ||
    			 my_id_rep->my_id_type == RHP_PROTO_IKE_ID_RFC822_ADDR ||
    			 my_id_rep->my_id_type == RHP_PROTO_IKE_ID_IPV4_ADDR ||
    			 my_id_rep->my_id_type == RHP_PROTO_IKE_ID_IPV6_ADDR ||
           my_id_rep->my_id_type == RHP_PROTO_IKE_ID_DER_ASN1_DN) )  ||
        rhp_ikev2_is_null_auth_id(my_id_rep->my_id_type) 						 ||
    		my_id_rep->eap_sup_enabled ){


			rlm = rhp_realm_get(my_id_rep->my_realm_id);
			if( rlm == NULL ){
				RHP_BUG("%d",my_id_rep->my_realm_id);
				err = -ENOENT;
				goto error;
			}


			RHP_LOCK(&(rlm->lock));
			{

				rhp_ikev2_id_clear(&(rlm->my_auth.my_id));
				rlm->my_auth.my_auth_method = RHP_PROTO_IKE_AUTHMETHOD_NONE;

				if( my_id_rep->my_id_len || rhp_ikev2_is_null_auth_id(my_id_rep->my_id_type) ){

					err = rhp_ikev2_id_setup(my_id_rep->my_id_type,
									(my_id_rep->my_id_len ? (void*)p : NULL),
									my_id_rep->my_id_len,&(rlm->my_auth.my_id));
					if( err ){

						RHP_BUG("%d",rlm->id);

						RHP_UNLOCK(&(rlm->lock));
						rhp_realm_unhold(rlm);

						goto error;
					}
					p += my_id_rep->my_id_len;

					rlm->my_auth.my_auth_method = my_id_rep->my_auth_method;

					rlm->my_auth.my_xauth_method = my_id_rep->xauth_method;

					RHP_LOG_I(RHP_LOG_SRC_AUTHCFG,rlm->id,RHP_LOG_ID_MY_VPN_ID,"uIdd",rlm->id,&(rlm->my_auth.my_id),rlm->my_auth.my_auth_method,rlm->my_auth.my_xauth_method);
				}

				if( my_id_rep->eap_sup_enabled ){

					char* mth_str = rhp_eap_sup_impl_method2str(my_id_rep->eap_sup_method);

					RHP_LOG_I(RHP_LOG_SRC_AUTHCFG,rlm->id,RHP_LOG_ID_MY_VPN_ID_EAP_SUP_ENABLED,"us",rlm->id,mth_str);

					if( mth_str ){
						_rhp_free(mth_str);
					}
				}

				rlm->my_auth.eap_sup.enabled = my_id_rep->eap_sup_enabled;
				rlm->my_auth.eap_sup.method = my_id_rep->eap_sup_method;
				rlm->my_auth.eap_sup.ask_for_user_key = my_id_rep->eap_sup_ask_for_user_key;
				rlm->my_auth.eap_sup.user_key_cache_enabled = my_id_rep->eap_sup_user_key_cache_enabled;

				rlm->psk_for_peers = my_id_rep->psk_for_peers;
				rlm->rsa_sig_for_peers = my_id_rep->rsa_sig_for_peers;
				rlm->eap_for_peers = my_id_rep->eap_for_peers;
				rlm->null_auth_for_peers = my_id_rep->null_auth_for_peers;

				{
					if( rlm->my_auth.my_cert_issuer_dn_der ){
						_rhp_free(rlm->my_auth.my_cert_issuer_dn_der);
						rlm->my_auth.my_cert_issuer_dn_der_len = 0;
						rlm->my_auth.my_cert_issuer_dn_der = NULL;
					}

					if( my_id_rep->my_cert_issuer_dn_der_len ){

						rlm->my_auth.my_cert_issuer_dn_der = (u8*)_rhp_malloc(my_id_rep->my_cert_issuer_dn_der_len);
						if( rlm->my_auth.my_cert_issuer_dn_der == NULL ){

							RHP_BUG("%d",rlm->id);

							RHP_UNLOCK(&(rlm->lock));
							rhp_realm_unhold(rlm);

							err = -ENOMEM;
							goto error;
						}

						memcpy(rlm->my_auth.my_cert_issuer_dn_der,p,
								my_id_rep->my_cert_issuer_dn_der_len);

						rlm->my_auth.my_cert_issuer_dn_der_len = my_id_rep->my_cert_issuer_dn_der_len;

						p += my_id_rep->my_cert_issuer_dn_der_len;
					}
				}

				{
					if( rlm->my_auth.untrust_sub_ca_cert_issuer_dn_der ){
						_rhp_free(rlm->my_auth.untrust_sub_ca_cert_issuer_dn_der);
						rlm->my_auth.untrust_sub_ca_cert_issuer_dn_der_len = 0;
						rlm->my_auth.untrust_sub_ca_cert_issuer_dn_der = NULL;
					}

					if( my_id_rep->untrust_sub_ca_cert_issuer_dn_der_len ){

						rlm->my_auth.untrust_sub_ca_cert_issuer_dn_der
							= (u8*)_rhp_malloc(my_id_rep->untrust_sub_ca_cert_issuer_dn_der_len);

						if( rlm->my_auth.untrust_sub_ca_cert_issuer_dn_der == NULL ){

							RHP_BUG("%d",rlm->id);

							RHP_UNLOCK(&(rlm->lock));
							rhp_realm_unhold(rlm);

							err = -ENOMEM;
							goto error;
						}

						memcpy(rlm->my_auth.untrust_sub_ca_cert_issuer_dn_der,
								p,my_id_rep->untrust_sub_ca_cert_issuer_dn_der_len);

						rlm->my_auth.untrust_sub_ca_cert_issuer_dn_der_len
							= my_id_rep->untrust_sub_ca_cert_issuer_dn_der_len;

						p += my_id_rep->untrust_sub_ca_cert_issuer_dn_der_len;
					}
				}
			}
			RHP_UNLOCK(&(rlm->lock));


			err = rhp_vpn_cleanup_by_realm_id(my_id_rep->my_realm_id,0);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}


	    RHP_TRC(0,RHPTRCID_CFG_IPC_HANDLE_RESOLVE_MY_ID_REPLAY_OK,"xxddddddddddpp",ipcmsg,rlm,rlm->my_auth.my_auth_method,rlm->my_auth.my_xauth_method,rlm->my_auth.eap_sup.enabled,rlm->my_auth.eap_sup.method,rlm->my_auth.eap_sup.ask_for_user_key,rlm->my_auth.eap_sup.user_key_cache_enabled,rlm->psk_for_peers,rlm->rsa_sig_for_peers,rlm->eap_for_peers,rlm->null_auth_for_peers,rlm->my_auth.my_cert_issuer_dn_der_len,rlm->my_auth.my_cert_issuer_dn_der,rlm->my_auth.untrust_sub_ca_cert_issuer_dn_der_len,rlm->my_auth.untrust_sub_ca_cert_issuer_dn_der);
	    rhp_ikev2_id_dump("rlm->my_auth.my_id",&(rlm->my_auth.my_id));

			rhp_realm_unhold(rlm);

    }else{

	    RHP_TRC(0,RHPTRCID_CFG_IPC_HANDLE_RESOLVE_MY_ID_REPLAY_ID_NOT_RESOLVED,"x",ipcmsg);

	    RHP_LOG_DE(RHP_LOG_SRC_AUTHCFG,my_id_rep->my_realm_id,RHP_LOG_ID_MY_VPN_ID_RESOLVE_ERR,"u",my_id_rep->my_realm_id);
    }
  }
    break;


  case RHP_IPC_CA_PUBKEY_DIGESTS_UPDATE:

    {
    	rhp_ipcmsg_ca_pubkey_digests* pubkeys_dgsts = (rhp_ipcmsg_ca_pubkey_digests*)ipcmsg;

      if( ipcmsg->len < sizeof(rhp_ipcmsg_ca_pubkey_digests) ){
        RHP_BUG("%d",ipcmsg->len);
        goto error;
      }

      RHP_LOCK(&rhp_cfg_lock);

      p = (u8*)(pubkeys_dgsts + 1);
      {

				if( _rhp_ca_pubkey_digests_cache ){
					_rhp_free(_rhp_ca_pubkey_digests_cache);
				}
				_rhp_ca_pubkey_digests_cache = NULL;
				_rhp_ca_pubkey_digests_cache_len =0;
				_rhp_ca_pubkey_digest_len = 0;

				if( pubkeys_dgsts->pubkey_digests_len ){

					_rhp_ca_pubkey_digests_cache = (u8*)_rhp_malloc(pubkeys_dgsts->pubkey_digests_len);
					if( _rhp_ca_pubkey_digests_cache == NULL ){
						RHP_BUG("");
						RHP_UNLOCK(&rhp_cfg_lock);
						goto error;
					}

					memcpy(_rhp_ca_pubkey_digests_cache,p,pubkeys_dgsts->pubkey_digests_len);
					_rhp_ca_pubkey_digests_cache_len = pubkeys_dgsts->pubkey_digests_len;
					_rhp_ca_pubkey_digest_len = pubkeys_dgsts->pubkey_digest_len;
					p += pubkeys_dgsts->pubkey_digests_len;

					RHP_TRC(0,RHPTRCID_CFG_IPC_HANDLE_UPDATED_ALL_CA_PUBKEY_DIGESTS,"xpd",ipcmsg,_rhp_ca_pubkey_digests_cache_len,_rhp_ca_pubkey_digests_cache,_rhp_ca_pubkey_digest_len);

				}else{

					RHP_TRC(0,RHPTRCID_CFG_IPC_HANDLE_NO_CA_PUBKEY_DIGESTS,"x",ipcmsg);
				}
      }

      {

      	if( _rhp_ca_dn_ders_cache ){
					_rhp_free(_rhp_ca_dn_ders_cache);
				}
				_rhp_ca_dn_ders_cache = NULL;
				_rhp_ca_dn_ders_cache_len =0;
				_rhp_ca_dn_ders_cache = 0;

				if( pubkeys_dgsts->dn_ders_len ){

					_rhp_ca_dn_ders_cache = (u8*)_rhp_malloc(pubkeys_dgsts->dn_ders_len);
					if( _rhp_ca_dn_ders_cache == NULL ){
						RHP_BUG("");
						RHP_UNLOCK(&rhp_cfg_lock);
						goto error;
					}

					memcpy(_rhp_ca_dn_ders_cache,p,pubkeys_dgsts->dn_ders_len);
					_rhp_ca_dn_ders_cache_len = pubkeys_dgsts->dn_ders_len;
					_rhp_ca_dn_ders_cache_num = pubkeys_dgsts->dn_ders_num;
					p += pubkeys_dgsts->dn_ders_len;

					RHP_TRC(0,RHPTRCID_CFG_IPC_HANDLE_UPDATED_ALL_CA_PUBKEY_DIGESTS_CA_DN_DERS,"xpd",ipcmsg,_rhp_ca_dn_ders_cache_len,_rhp_ca_dn_ders_cache,_rhp_ca_dn_ders_cache_num);

				}else{

					RHP_TRC(0,RHPTRCID_CFG_IPC_HANDLE_CA_PUBKEY_DIGESTS_NO_CA_DN_DERS,"x",ipcmsg);
				}
      }

      RHP_UNLOCK(&rhp_cfg_lock);
    }
    break;

  default:
    RHP_BUG("%d",ipcmsg->type);
    goto error;
}

error:
  if( ipcmsg ){
    _rhp_free_zero(ipcmsg,ipcmsg->len);
  }

  RHP_TRC(0,RHPTRCID_CFG_IPC_HANDLE_RTRN,"x",ipcmsg);
  return err;
}

int rhp_cfg_get_all_ca_pubkey_digests(u8** digests_r,int* digests_len_r,int* digest_len_r)
{
	int err = -EINVAL;
	u8* digests = NULL;

  RHP_TRC(0,RHPTRCID_CFG_GET_ALL_CA_PUBKEY_DIGESTS,"xxx",digests_r,digests_len_r,digest_len_r);

  RHP_LOCK(&rhp_cfg_lock);

  if( _rhp_ca_pubkey_digests_cache == NULL ){
  	err = -ENOENT;
  	goto error;
  }

  digests = (u8*)_rhp_malloc(_rhp_ca_pubkey_digests_cache_len);
  if( digests == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }

  memcpy(digests,_rhp_ca_pubkey_digests_cache,_rhp_ca_pubkey_digests_cache_len);

  *digests_r = digests;
  *digests_len_r = _rhp_ca_pubkey_digests_cache_len;
  *digest_len_r = _rhp_ca_pubkey_digest_len;

  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_CFG_GET_ALL_CA_PUBKEY_DIGESTS_RTRN,"pd",*digests_len_r,*digests_r,*digest_len_r);
  return 0;

error:
  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_CFG_GET_ALL_CA_PUBKEY_DIGESTS_ERR,"xE",digests_r,err);
  return err;
}

int rhp_cfg_get_all_ca_dn_ders(u8** ders_r,int* ders_len_r,int* ders_num_r)
{
	int err = -EINVAL;
	u8* ders = NULL;

  RHP_TRC(0,RHPTRCID_CFG_GET_ALL_CA_DN_DERS,"xxx",ders_r,ders_len_r,ders_num_r);

  RHP_LOCK(&rhp_cfg_lock);

  if( _rhp_ca_dn_ders_cache == NULL ){
  	err = -ENOENT;
  	goto error;
  }

  ders = (u8*)_rhp_malloc(_rhp_ca_dn_ders_cache_len);
  if( ders == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }

  memcpy(ders,_rhp_ca_dn_ders_cache,_rhp_ca_dn_ders_cache_len);

  *ders_r = ders;
  *ders_len_r = _rhp_ca_dn_ders_cache_len;
  *ders_num_r = _rhp_ca_dn_ders_cache_num;

  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_CFG_GET_ALL_CA_DN_DERS_RTRN,"pd",*ders_len_r,*ders_r,*ders_num_r);
  return 0;

error:
  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_CFG_GET_ALL_CA_DN_DERS_ERR,"xE",ders_r,err);
  return err;
}


int rhp_cfg_parse_ikev2_id(xmlNodePtr node,
		const xmlChar* id_type_attrname,const xmlChar* id_attrname,rhp_ikev2_id* id)
{
	int err = -EINVAL;
  int ret_len;

  RHP_TRC(0,RHPTRCID_CFG_PARSE_IKEV2_ID,"xss",node,id_type_attrname,id_attrname);

  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,id_type_attrname),(xmlChar*)"fqdn") ){
    id->type = RHP_PROTO_IKE_ID_FQDN;
  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,id_type_attrname),(xmlChar*)"email") ){
    id->type = RHP_PROTO_IKE_ID_RFC822_ADDR;
  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,id_type_attrname),(xmlChar*)"dn") ){
    id->type = RHP_PROTO_IKE_ID_DER_ASN1_DN;
  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,id_type_attrname),(xmlChar*)"subjectaltname") ){
    id->type = RHP_PROTO_IKE_ID_PRIVATE_SUBJECTALTNAME;
  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,id_type_attrname),(xmlChar*)"cert_auto") ){
    id->type = RHP_PROTO_IKE_ID_PRIVATE_CERT_AUTO;
  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,id_type_attrname),(xmlChar*)"any") ){
    id->type = RHP_PROTO_IKE_ID_ANY;
  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,id_type_attrname),(xmlChar*)"ipv4") ){
    id->type = RHP_PROTO_IKE_ID_IPV4_ADDR;
  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,id_type_attrname),(xmlChar*)"ipv6") ){
    id->type = RHP_PROTO_IKE_ID_IPV6_ADDR;
  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,id_type_attrname),(xmlChar*)"null-id") ){
    id->type = RHP_PROTO_IKE_ID_NULL_ID;
  }else{
  	err = -ENOENT;
    RHP_TRC(0,RHPTRCID_CFG_PARSE_IKEV2_ID_NO_PROP,"xss",node,id_type_attrname,id_attrname);
    goto error;
  }

  if( id->type == RHP_PROTO_IKE_ID_DER_ASN1_DN ){

    if( rhp_xml_str2val(rhp_xml_get_prop_static(node,id_attrname),
    			RHP_XML_DT_DN_DER,&(id->dn_der),&ret_len,NULL,0) ){
    	RHP_BUG("");
    }else{
      id->dn_der_len = ret_len;
    }

  }else if( id->type == RHP_PROTO_IKE_ID_PRIVATE_SUBJECTALTNAME ||
            id->type == RHP_PROTO_IKE_ID_PRIVATE_CERT_AUTO ||
            id->type == RHP_PROTO_IKE_ID_ANY ){

    // Nothing to do here.

  }else if( id->type == RHP_PROTO_IKE_ID_IPV4_ADDR ){

  	id->addr.addr_family = AF_INET;
  	if( rhp_xml_str2val(rhp_xml_get_prop_static(node,id_attrname),
  				RHP_XML_DT_IPV4,&(id->addr.addr.v4),&ret_len,NULL,0) ){
    	RHP_BUG("");
    }

  }else if( id->type == RHP_PROTO_IKE_ID_IPV6_ADDR ){

  	id->addr.addr_family = AF_INET6;
  	if( rhp_xml_str2val(rhp_xml_get_prop_static(node,id_attrname),
  				RHP_XML_DT_IPV6,&(id->addr),&ret_len,NULL,0) ){
    	RHP_BUG("");
    }

  }else if( id->type == RHP_PROTO_IKE_ID_NULL_ID ){

    err = rhp_xml_str2val(rhp_xml_get_prop_static(node,id_attrname),RHP_XML_DT_STRING,
    			&(id->conn_name_for_null_id),&ret_len,NULL,0);
    if( err && err != -ENOENT ){
    	RHP_BUG("");
      goto error;
    }
  	err = 0;

  }else{

    if( !rhp_xml_str2val(rhp_xml_get_prop_static(node,id_attrname),
    			RHP_XML_DT_STRING,&(id->string),&ret_len,NULL,0) ){

      if( id->type != RHP_PROTO_IKE_ID_FQDN &&
      		id->type != RHP_PROTO_IKE_ID_RFC822_ADDR ){
        RHP_BUG("");
        goto error;
      }

    }else{
    	RHP_BUG("");
    }
  }

  return 0;

error:
  return err;
}

int rhp_cfg_parse_eap_id(xmlNodePtr node,
		const xmlChar* id_type_attrname,const xmlChar* id_attrname,rhp_eap_id* eap_id)
{
	int err = -EINVAL;

  RHP_TRC(0,RHPTRCID_CFG_PARSE_EAP_ID,"xss",node,id_type_attrname,id_attrname);

  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,id_type_attrname),(xmlChar*)"mschapv2") ){

  	eap_id->method = RHP_PROTO_EAP_TYPE_MS_CHAPV2;

    if( rhp_xml_str2val(rhp_xml_get_prop_static(node,id_attrname),
    			RHP_XML_DT_STRING,&(eap_id->identity),&(eap_id->identity_len),NULL,0) ){
    	err = -ENOENT;
      RHP_TRC(0,RHPTRCID_CFG_PARSE_EAP_ID_NO_ID,"xss",node,id_type_attrname,id_attrname);
      goto error;
    }
    eap_id->identity_len--; // '\0' not included.

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,id_type_attrname),(xmlChar*)"xauth") ){

    	eap_id->method = RHP_PROTO_EAP_TYPE_PRIV_IKEV1_XAUTH_PAP;

      if( rhp_xml_str2val(rhp_xml_get_prop_static(node,id_attrname),
      			RHP_XML_DT_STRING,&(eap_id->identity),&(eap_id->identity_len),NULL,0) ){
      	err = -ENOENT;
        RHP_TRC(0,RHPTRCID_CFG_PARSE_EAP_ID_XAUTH_NO_ID,"xss",node,id_type_attrname,id_attrname);
        goto error;
      }
      eap_id->identity_len--; // '\0' not included.
      eap_id->for_xauth = 1;

  }else{
  	err = -ENOENT;
    RHP_TRC(0,RHPTRCID_CFG_PARSE_EAP_ID_NO_PROP,"xss",node,id_type_attrname,id_attrname);
    goto error;
  }

  return 0;

error:
  return err;
}

int rhp_cfg_parse_eap_method(xmlNodePtr node,const xmlChar* attrname,int* method_r)
{
	int err = -EINVAL;
  int ret_len;

  RHP_TRC(0,RHPTRCID_CFG_PARSE_EAP_METHOD,"xs",node,attrname);

  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,attrname),(xmlChar*)"mschapv2") ){

  	*method_r = RHP_PROTO_EAP_TYPE_MS_CHAPV2;

  }else{
  	err = -ENOENT;
    RHP_TRC(0,RHPTRCID_CFG_PARSE_EAP_METHOD_NO_PROP,"xs",node,attrname);
    goto error;
  }

  return 0;

error:
  return err;
}


int rhp_cfg_is_any_traffic_selector(rhp_traffic_selector* cfg_ts)
{

	if( cfg_ts->protocol ){
	  RHP_TRC(0,RHPTRCID_CFG_IS_ANY_TRAFFIC_SELECTOR_PROTO,"x",cfg_ts);
		return 0;
	}

	if( cfg_ts->start_port != 0 ){
	  RHP_TRC(0,RHPTRCID_CFG_IS_ANY_TRAFFIC_SELECTOR_START_PORT,"x",cfg_ts);
		return 0;
	}

	if( cfg_ts->end_port != 0xFFFF ){
	  RHP_TRC(0,RHPTRCID_CFG_IS_ANY_TRAFFIC_SELECTOR_END_PORT,"x",cfg_ts);
		return 0;
	}

	if( cfg_ts->ts_is_subnet ){
	  RHP_TRC(0,RHPTRCID_CFG_IS_ANY_TRAFFIC_SELECTOR_IS_SUBNET,"x",cfg_ts);
		return 0;
	}

	if( cfg_ts->ts_type == RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE ){

		if( cfg_ts->addr.range.start.addr.v4 != 0 ){
		  RHP_TRC(0,RHPTRCID_CFG_IS_ANY_TRAFFIC_SELECTOR_START_ADDR,"x",cfg_ts);
			return 0;
		}

		if( cfg_ts->addr.range.end.addr.v4 != 0xFFFFFFFF ){
		  RHP_TRC(0,RHPTRCID_CFG_IS_ANY_TRAFFIC_SELECTOR_END_ADDR,"x",cfg_ts);
			return 0;
		}

	}else if( cfg_ts->ts_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){

		u64* b = (u64*)cfg_ts->addr.range.start.addr.v6;

		if( b[0] || b[1] ){
		  RHP_TRC(0,RHPTRCID_CFG_IS_ANY_TRAFFIC_SELECTOR_START_ADDR_V6,"x",cfg_ts);
			return 0;
		}

		b = (u64*)cfg_ts->addr.range.end.addr.v6;
		if( b[0] != 0xFFFFFFFFFFFFFFFFUL || b[1] != 0xFFFFFFFFFFFFFFFFUL ){
		  RHP_TRC(0,RHPTRCID_CFG_IS_ANY_TRAFFIC_SELECTOR_END_ADDR_V6,"x",cfg_ts);
			return 0;
		}
	}

  RHP_TRC(0,RHPTRCID_CFG_IS_ANY_TRAFFIC_SELECTOR_FOUND,"x",cfg_ts);
	return 1;
}

#define RHP_CFG_MAX_TRAFFIC_SELECTORS		255

static int _rhp_cfg_parse_each_traffic_selector(xmlNodePtr node, void* ctx)
{
	int err;
	rhp_cfg_peer* cfg_peer = (rhp_cfg_peer*) ctx;
	xmlNodePtr child_node = NULL;
	rhp_traffic_selector *cfg_ts = NULL, *cfg_ts_c = NULL, *cfg_ts_p = NULL;
	int ret_len;
	rhp_traffic_selector **cfg_ts_list = NULL;
	int *cfg_ts_list_num = NULL;
	int is_v1 = 0;

	if((!xmlStrcmp( node->name, (xmlChar*) "my_traffic_selector" ))){
		cfg_ts_list = &(cfg_peer->my_tss);
		cfg_ts_list_num = &cfg_peer->my_tss_num;
	}else{
		cfg_ts_list = &(cfg_peer->peer_tss);
		cfg_ts_list_num = &cfg_peer->peer_tss_num;
	}

	if(*cfg_ts_list_num > RHP_CFG_MAX_TRAFFIC_SELECTORS){
		err = -EINVAL;
		RHP_BUG( "" );
		goto error;
	}

	cfg_ts = (rhp_traffic_selector*) _rhp_malloc( sizeof(rhp_traffic_selector) );
	if(cfg_ts == NULL){
		err = -ENOMEM;
		RHP_BUG( "" );
		goto error;
	}
	memset( cfg_ts, 0, sizeof(rhp_traffic_selector) );

	cfg_ts->tag[0] = '#';
	cfg_ts->tag[1] = 'T';
	cfg_ts->tag[2] = 'R';
	cfg_ts->tag[3] = 'S';

	if(rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"priority"),
			RHP_XML_DT_ULONG, &(cfg_ts->priority), &ret_len, NULL, 0 )){
		cfg_ts->priority = INT_MAX;
	}

	rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"is_v1"),
  		RHP_XML_DT_INT,&is_v1,&ret_len,NULL,0);


	if( rhp_xml_get_child(node,(xmlChar*)"address_v6") ){

		cfg_ts->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;

	}else{

		cfg_ts->ts_type = RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE;
	}


	cfg_ts->protocol = 0;

	child_node = rhp_xml_get_child( node, (xmlChar*) "protocol" );
	if(child_node){

		xmlChar* id = rhp_xml_get_prop( child_node, (xmlChar*) "id" );

		if(id){

			if(!rhp_xml_strcasecmp( id, (xmlChar*) "icmp" )){

				if( cfg_ts->ts_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){
					cfg_ts->protocol = RHP_PROTO_IP_IPV6_ICMP;
				}else{
					cfg_ts->protocol = RHP_PROTO_IP_ICMP;
				}

			}else if(!rhp_xml_strcasecmp( id, (xmlChar*) "icmp_fragments" )){

				if( cfg_ts->ts_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){
					cfg_ts->protocol = RHP_PROTO_IP_IPV6_ICMP;
				}else{
					cfg_ts->protocol = RHP_PROTO_IP_ICMP;
				}
				cfg_ts->for_fragmented = 1;

			}else if(!rhp_xml_strcasecmp( id, (xmlChar*) "tcp" )){
				cfg_ts->protocol = RHP_PROTO_IP_TCP;
			}else if(!rhp_xml_strcasecmp( id, (xmlChar*) "tcp_fragments" )){
				cfg_ts->protocol = RHP_PROTO_IP_TCP;
				cfg_ts->for_fragmented = 1;
			}else if(!rhp_xml_strcasecmp( id, (xmlChar*) "udp" )){
				cfg_ts->protocol = RHP_PROTO_IP_UDP;
			}else if(!rhp_xml_strcasecmp( id, (xmlChar*) "udp_fragments" )){
				cfg_ts->protocol = RHP_PROTO_IP_UDP;
				cfg_ts->for_fragmented = 1;
			}else if(!rhp_xml_strcasecmp( id, (xmlChar*) "gre" )){
				cfg_ts->protocol = RHP_PROTO_IP_GRE;
			}else if(!rhp_xml_strcasecmp( id, (xmlChar*) "esp" )){
				cfg_ts->protocol = RHP_PROTO_IP_ESP;
			}else if(!rhp_xml_strcasecmp( id, (xmlChar*) "ah" )){
				cfg_ts->protocol = RHP_PROTO_IP_AH;
			}else if(!rhp_xml_strcasecmp( id, (xmlChar*) "etherip" )){
				cfg_ts->protocol = RHP_PROTO_IP_ETHERIP;
			}else if(!rhp_xml_strcasecmp( id, (xmlChar*) "ipcomp" )){
				cfg_ts->protocol = RHP_PROTO_IP_IPCOMP;
			}else if(!rhp_xml_strcasecmp( id, (xmlChar*) "sctp" )){
				cfg_ts->protocol = RHP_PROTO_IP_SCTP;
			}else if(!rhp_xml_strcasecmp( id, (xmlChar*) "sctp_fragments" )){
				cfg_ts->protocol = RHP_PROTO_IP_SCTP;
				cfg_ts->for_fragmented = 1;
			}else if(!rhp_xml_strcasecmp( id, (xmlChar*) "udplite" )){
				cfg_ts->protocol = RHP_PROTO_IP_UDPLITE;
			}else if(!rhp_xml_strcasecmp( id, (xmlChar*) "l2tp" )){
				cfg_ts->protocol = RHP_PROTO_IP_L2TP;
			}else if(rhp_xml_strcasecmp( id, (xmlChar*) "any" )){
				err = rhp_xml_str2val( id, RHP_XML_DT_UINT, &(cfg_ts->protocol),
						&ret_len, NULL, 0 );
				if(err){
					_rhp_free( id );
					RHP_BUG( "" );
					goto error;
				}
			}

			_rhp_free( id );

		}else{
			// "any"
		}
	}

	cfg_ts->start_port = 0;
	cfg_ts->end_port = 65535;
	cfg_ts->icmp_start_type = 0;
	cfg_ts->icmp_end_type = 255;
	cfg_ts->icmp_start_code = 0;
	cfg_ts->icmp_end_code = 255;

	if( cfg_ts->protocol == RHP_PROTO_IP_ICMP ||
			cfg_ts->protocol == RHP_PROTO_IP_IPV6_ICMP ){ // ICMP

		if( cfg_ts->for_fragmented ){
			cfg_ts->icmp_start_type = 255;
			cfg_ts->icmp_end_type = 0;
			cfg_ts->icmp_start_code = 255;
			cfg_ts->icmp_end_code = 0;
		}

		child_node = rhp_xml_get_child( node, (xmlChar*) "icmp" );

		if(child_node){

			xmlChar *start = NULL, *end = NULL;

			if(cfg_ts->for_fragmented){
				// Ignore...
			}else{

				start = rhp_xml_get_prop( child_node, (xmlChar*) "start_type" );
				end = rhp_xml_get_prop( child_node, (xmlChar*) "end_type" );

				if(start){
					if(rhp_xml_strcasecmp( start, (xmlChar*) "any" )){
						err = rhp_xml_str2val( start, RHP_XML_DT_UINT,
								&(cfg_ts->icmp_start_type), &ret_len, NULL, 0 );
						if(err){
							_rhp_free( start );
							RHP_BUG( "" );
							goto error;
						}
					}
					_rhp_free( start );
				}

				cfg_ts->icmp_end_type = 255;
				if(end){
					if(rhp_xml_strcasecmp( end, (xmlChar*) "any" )){
						err = rhp_xml_str2val( end, RHP_XML_DT_UINT,
								&(cfg_ts->icmp_end_type), &ret_len, NULL, 0 );
						if(err){
							_rhp_free( end );
							RHP_BUG( "" );
							goto error;
						}
					}
					_rhp_free( end );
				}

				if(cfg_ts->icmp_start_type > cfg_ts->icmp_end_type){
					RHP_BUG( "" );
					goto error;
				}

				start = rhp_xml_get_prop( child_node, (xmlChar*) "start_code" );
				end = rhp_xml_get_prop( child_node, (xmlChar*) "end_code" );

				if(start){
					if(rhp_xml_strcasecmp( start, (xmlChar*) "any" )){
						err = rhp_xml_str2val( start, RHP_XML_DT_UINT,
								&(cfg_ts->icmp_start_code), &ret_len, NULL, 0 );
						if(err){
							_rhp_free( start );
							RHP_BUG( "" );
							goto error;
						}
					}
					_rhp_free( start );
				}

				cfg_ts->icmp_end_code = 255;
				if(end){
					if(rhp_xml_strcasecmp( end, (xmlChar*) "any" )){
						err = rhp_xml_str2val( end, RHP_XML_DT_UINT,
								&(cfg_ts->icmp_end_code), &ret_len, NULL, 0 );
						if(err){
							_rhp_free( end );
							RHP_BUG( "" );
							goto error;
						}
					}
					_rhp_free( end );
				}

				if(cfg_ts->icmp_start_code > cfg_ts->icmp_end_code){
					RHP_BUG( "" );
					goto error;
				}
			}
		}

	}else if(	cfg_ts->protocol == RHP_PROTO_IP_UDP 	|| // UDP
						cfg_ts->protocol == RHP_PROTO_IP_TCP 	|| // TCP
						cfg_ts->protocol == RHP_PROTO_IP_SCTP || // SCTP
						cfg_ts->protocol == RHP_PROTO_IP_UDPLITE){	// UDPLite

		if(cfg_ts->for_fragmented){
			cfg_ts->start_port = 65535;
			cfg_ts->end_port = 0;
		}

		child_node = rhp_xml_get_child( node, (xmlChar*) "port" );

		if(child_node){

			xmlChar *start = NULL, *end = NULL;

			if(cfg_ts->for_fragmented){
				// Ignore...
			}else{

				start = rhp_xml_get_prop( child_node, (xmlChar*) "start" );
				end = rhp_xml_get_prop( child_node, (xmlChar*) "end" );

				if(start){

					if(rhp_xml_strcasecmp( start, (xmlChar*) "any" )){

						err = rhp_xml_str2val( start, RHP_XML_DT_PORT,
								&(cfg_ts->start_port), &ret_len, NULL, 0 );
						if(err){
							_rhp_free( start );
							RHP_BUG( "" );
							goto error;
						}
						_rhp_free( start );
					}

					if(end){

						if(rhp_xml_strcasecmp( end, (xmlChar*) "any" )){

							err = rhp_xml_str2val( end, RHP_XML_DT_PORT, &(cfg_ts->end_port),
									&ret_len, NULL, 0 );
							if(err){
								_rhp_free( end );
								RHP_BUG( "" );
								goto error;
							}
						}
						_rhp_free( end );
					}
				}

				if(ntohs( cfg_ts->start_port ) > ntohs( cfg_ts->end_port )){
					RHP_BUG( "" );
					goto error;
				}
			}
		}
	}

	if( cfg_ts->ts_type == RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE ){

		cfg_ts->addr.raw.start.addr_family = AF_INET;
		cfg_ts->addr.raw.end.addr_family = AF_INET;
		cfg_ts->ts_is_subnet = 0;
		cfg_ts->addr.range.start.addr.v4 = 0;
		cfg_ts->addr.range.end.addr.v4 = 0xFFFFFFFF;

		child_node = rhp_xml_get_child( node, (xmlChar*) "address_v4" );

	}else if( cfg_ts->ts_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){

		cfg_ts->addr.raw.start.addr_family = AF_INET6;
		cfg_ts->addr.raw.end.addr_family = AF_INET6;
		cfg_ts->ts_is_subnet = 0;
		memset(cfg_ts->addr.range.start.addr.v6,0,16);
		memset(cfg_ts->addr.range.end.addr.v6,0xFF,16);

		child_node = rhp_xml_get_child( node, (xmlChar*) "address_v6" );
	}

	if( child_node ){

		xmlChar *start = NULL, *end = NULL, *subnet = NULL;

		subnet = rhp_xml_get_prop( child_node, (xmlChar*) "subnet" );
		start = rhp_xml_get_prop( child_node, (xmlChar*) "start" );
		end = rhp_xml_get_prop( child_node, (xmlChar*) "end" );

		if( subnet ){

			rhp_ip_addr* subnet_tmp = NULL;

			cfg_ts->ts_is_subnet = 1;

			if(rhp_xml_strcasecmp( subnet, (xmlChar*) "any" )){

				if( cfg_ts->ts_type == RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE ){

					err = rhp_xml_str2val( subnet, RHP_XML_DT_IPV4_SUBNET, &subnet_tmp,
							&ret_len, NULL, 0 );

				}else if( cfg_ts->ts_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){

					err = rhp_xml_str2val( subnet, RHP_XML_DT_IPV6_SUBNET, &subnet_tmp,
							&ret_len, NULL, 0 );
				}
				if(err){
					_rhp_free( subnet );
					RHP_BUG( "" );
					goto error;
				}

				memcpy( &(cfg_ts->addr.subnet), subnet_tmp, sizeof(rhp_ip_addr) );

				_rhp_free( subnet_tmp );
			}

			_rhp_free( subnet );

		}else{

			if( start ){

				if(rhp_xml_strcasecmp( start, (xmlChar*) "any" )){

					if( cfg_ts->ts_type == RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE ){

						err = rhp_xml_str2val( start, RHP_XML_DT_IPV4,
								&(cfg_ts->addr.range.start.addr.v4), &ret_len, NULL, 0 );

					}else if( cfg_ts->ts_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){

						err = rhp_xml_str2val( start, RHP_XML_DT_IPV6,
										&(cfg_ts->addr.range.start), &ret_len, NULL, 0 );
					}
					if(err){
						_rhp_free( start );
						RHP_BUG( "" );
						goto error;
					}
				}
				_rhp_free( start );
			}

			if( end ){

				if(rhp_xml_strcasecmp( start, (xmlChar*) "any" )){

					if( cfg_ts->ts_type == RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE ){

						err = rhp_xml_str2val( end, RHP_XML_DT_IPV4,
								&(cfg_ts->addr.range.end.addr.v4), &ret_len, NULL, 0 );

					}else if( cfg_ts->ts_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){

						err = rhp_xml_str2val( end, RHP_XML_DT_IPV6,
										&(cfg_ts->addr.range.end), &ret_len, NULL, 0 );
					}
					if(err){
						_rhp_free( end );
						RHP_BUG( "" );
						goto error;
					}
				}
				_rhp_free( end );
			}

			if( rhp_ip_addr_eq_ip(&(cfg_ts->addr.range.start),&(cfg_ts->addr.range.end)) ){

				if( rhp_ip_addr_gt_ip(&(cfg_ts->addr.range.end),&(cfg_ts->addr.range.start)) ){
					RHP_BUG( "" );
					goto error;
				}
			}
		}
	}

	if( is_v1 ){

		if( cfg_ts->ts_type == RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE ){

			cfg_ts->ts_type = RHP_CFG_IKEV1_TS_IPV4_ADDR_RANGE;

		}else if( cfg_ts->ts_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){

			cfg_ts->ts_type = RHP_CFG_IKEV1_TS_IPV6_ADDR_RANGE;
		}
	}

	{
		cfg_ts_c = *cfg_ts_list;

		while(cfg_ts_c){
			if(cfg_ts_c->priority > cfg_ts->priority){
				break;
			}
			cfg_ts_p = cfg_ts_c;
			cfg_ts_c = cfg_ts_c->next;
		}

		if(cfg_ts_p == NULL){
			cfg_ts->next = *cfg_ts_list;
			*cfg_ts_list = cfg_ts;
		}else{
			cfg_ts->next = cfg_ts_p->next;
			cfg_ts_p->next = cfg_ts;
		}

		(*cfg_ts_list_num)++;
	}

	return 0;

	error: if(cfg_ts){
		_rhp_free( cfg_ts );
	}
	return err;
}

static int _rhp_cfg_alloc_any_traffic_selector_proto(int addr_family,
		rhp_traffic_selector **cfg_ts_list,int *cfg_ts_list_num,u8 protocol)
{
  int err;
  rhp_traffic_selector *cfg_ts = NULL,*cfg_ts_c = NULL,*cfg_ts_p = NULL;

  if( *cfg_ts_list_num > RHP_CFG_MAX_TRAFFIC_SELECTORS ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  cfg_ts = (rhp_traffic_selector*)_rhp_malloc(sizeof(rhp_traffic_selector));
  if( cfg_ts == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  memset(cfg_ts,0,sizeof(rhp_traffic_selector));

  cfg_ts->tag[0] = '#';
  cfg_ts->tag[1] = 'T';
  cfg_ts->tag[2] = 'R';
  cfg_ts->tag[3] = 'S';

  if( addr_family == AF_INET ){

  	cfg_ts->ts_type = RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE;
    cfg_ts->addr.range.end.addr.v4 = 0xFFFFFFFF;

  }else if( addr_family == AF_INET6 ){

  	cfg_ts->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
    memset(cfg_ts->addr.range.end.addr.v6,0xFF,16);

  }else{
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  cfg_ts->addr.raw.start.addr_family = addr_family;
  cfg_ts->addr.raw.end.addr_family = addr_family;

  cfg_ts->priority = INT_MAX;

  cfg_ts->protocol = protocol;

  cfg_ts->end_port = 0xFFFF;

  cfg_ts->icmp_end_type = 0xFF;
  cfg_ts->icmp_end_code = 0xFF;

  cfg_ts->ts_is_subnet = 0;


  cfg_ts_c = *cfg_ts_list;

  while( cfg_ts_c ){

  	if( protocol ){
  		if( cfg_ts_c->priority >= cfg_ts->priority ){
  			break;
  		}
  	}

 		if( cfg_ts_c->priority > cfg_ts->priority ){
 			break;
  	}

 		cfg_ts_p = cfg_ts_c;
 		cfg_ts_c = cfg_ts_c->next;
  }

  if( cfg_ts_p == NULL ){
  	cfg_ts->next = *cfg_ts_list;
  	*cfg_ts_list = cfg_ts;
  }else{
    cfg_ts->next = cfg_ts_p->next;
    cfg_ts_p->next = cfg_ts;
  }

  (*cfg_ts_list_num)++;

  return 0;

error:
  if( cfg_ts ){
    _rhp_free(cfg_ts);
  }
  return err;
}

static int _rhp_cfg_alloc_any_traffic_selector(rhp_traffic_selector **cfg_ts_list,
		int *cfg_ts_list_num)
{
	int err;

	err = _rhp_cfg_alloc_any_traffic_selector_proto(AF_INET,cfg_ts_list,cfg_ts_list_num,0);
	if( err ){
		goto error;
	}

	if( !rhp_gcfg_ipv6_disabled ){

		err = _rhp_cfg_alloc_any_traffic_selector_proto(AF_INET6,cfg_ts_list,cfg_ts_list_num,0);
		if( err ){
			goto error;
		}
	}

	return 0;

error:
	return err;
}

static int _rhp_cfg_parse_peer_traffic_selectors(xmlNodePtr node,void* ctx)
{
  int err;
  rhp_cfg_peer* cfg_peer = (rhp_cfg_peer*)ctx;

  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"swap"),(xmlChar*)"enable") ){
  	cfg_peer->swap_tss = 1;
  }else{
  	cfg_peer->swap_tss = 0;
  }

  err = rhp_xml_enum_tags(node,(xmlChar*)"my_traffic_selector",_rhp_cfg_parse_each_traffic_selector,cfg_peer,1);
  if( err == -ENOENT ){
  	cfg_peer->my_tss_num = 0;
  	cfg_peer->my_tss = NULL;
  	err = 0;
  }else if( err == RHP_STATUS_ENUM_OK ){
  	err = 0;
  }else if( err ){
    RHP_BUG("%d",err);
    goto error;
  }


  err = rhp_xml_enum_tags(node,(xmlChar*)"peer_traffic_selector",_rhp_cfg_parse_each_traffic_selector,cfg_peer,1);
  if( err == -ENOENT ){
  	cfg_peer->peer_tss_num = 0;
  	cfg_peer->peer_tss = NULL;
  	err = 0;
  }else if( err == RHP_STATUS_ENUM_OK ){
  	err = 0;
  }else if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( cfg_peer->swap_tss ){

    int tss_num;
    rhp_traffic_selector* tss;

  	tss_num = cfg_peer->peer_tss_num;
  	tss = cfg_peer->peer_tss;

  	cfg_peer->peer_tss_num = cfg_peer->my_tss_num;
  	cfg_peer->peer_tss = cfg_peer->my_tss;

  	cfg_peer->my_tss_num = tss_num;
  	cfg_peer->my_tss = tss;
  }

  rhp_cfg_traffic_selectors_dump("_rhp_cfg_parse_peer_traffic_selectors.my_tss",cfg_peer->my_tss,NULL);
  rhp_cfg_traffic_selectors_dump("_rhp_cfg_parse_peer_traffic_selectors.peer_tss",cfg_peer->peer_tss,NULL);
  return 0;

error:
  return err;
}

static int _rhp_cfg_parse_ext_traffic_selector(xmlNodePtr node,void* ctx)
{
  int err;
  rhp_vpn_realm* rlm = (rhp_vpn_realm*)ctx;
  xmlNodePtr child_node = NULL;
  rhp_ext_traffic_selector *cfg_ts = NULL,*cfg_ts_c = NULL,*cfg_ts_p = NULL;
  int ret_len;
  rhp_ext_traffic_selector **cfg_ts_list = NULL;
  int *cfg_ts_list_num = NULL;

  if( (!xmlStrcmp(node->name,(xmlChar*)"ext_traffic_selector")) ){
    cfg_ts_list = &(rlm->ext_tss.etss);
    cfg_ts_list_num = &rlm->ext_tss.etss_num;
  }

  cfg_ts = (rhp_ext_traffic_selector*)_rhp_malloc(sizeof(rhp_ext_traffic_selector));
  if( cfg_ts == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  memset(cfg_ts,0,sizeof(rhp_ext_traffic_selector));

  cfg_ts->tag[0] = '#';
  cfg_ts->tag[1] = 'C';
  cfg_ts->tag[2] = 'E';
  cfg_ts->tag[3] = 'T';

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"priority"),RHP_XML_DT_ULONG,&(cfg_ts->priority),&ret_len,NULL,0) ){
    cfg_ts->priority = INT_MAX;
  }

  cfg_ts->ether_type = 0;

  child_node = rhp_xml_get_child(node,(xmlChar*)"protocol");

  if( child_node ){

  	xmlChar* id = NULL;
  	id = rhp_xml_get_prop(child_node,(xmlChar*)"id");

  	if( id ){

  		if( !rhp_xml_strcasecmp(id,(xmlChar*)"ipv4") ){

  			cfg_ts->ether_type = RHP_PROTO_ETH_IP;

  		}else if( !rhp_xml_strcasecmp(id,(xmlChar*)"ipv6") ){

  			cfg_ts->ether_type = RHP_PROTO_ETH_IPV6;

  		}else if( !rhp_xml_strcasecmp(id,(xmlChar*)"arp") ){

				cfg_ts->ether_type = RHP_PROTO_ETH_ARP;

			}else if( !rhp_xml_strcasecmp(id,(xmlChar*)"rarp") ){

				cfg_ts->ether_type = RHP_PROTO_ETH_RARP;

/*
			}else if( !rhp_xml_strcasecmp(id,(xmlChar*)"802.1q") ){

				cfg_ts->ether_type = RHP_PROTO_ETH_8021Q;
*/
			}else if( rhp_xml_strcasecmp(id,(xmlChar*)"any") ){

				err = rhp_xml_str2val(id,RHP_XML_DT_UINT,&(cfg_ts->ether_type),&ret_len,NULL,0);
				if( err ){
		  		_rhp_free(id);
					RHP_BUG("%d",err);
					goto error;
				}
	    }

  		_rhp_free(id);

  	}else{
  		// ANY
  		cfg_ts->ether_type = 0;
  	}
  }

  cfg_ts_c = *cfg_ts_list;

  while( cfg_ts_c ){

    if( cfg_ts_c->priority > cfg_ts->priority ){
      break;
    }

    cfg_ts_p = cfg_ts_c;
    cfg_ts_c = cfg_ts_c->next;
  }

  if( cfg_ts_p == NULL ){
  	cfg_ts->next = *cfg_ts_list;
  	*cfg_ts_list = cfg_ts;
  }else{
    cfg_ts->next = cfg_ts_p->next;
    cfg_ts_p->next = cfg_ts;
  }

  (*cfg_ts_list_num)++;

  return 0;

error:
  if( cfg_ts ){
    _rhp_free(cfg_ts);
  }
  return err;
}


static int _rhp_cfg_parse_ext_traffic_selectors(xmlNodePtr node,void* ctx)
{
  int err;
  rhp_vpn_realm* rlm = (rhp_vpn_realm*)ctx;

  err = rhp_xml_enum_tags(node,(xmlChar*)"ext_traffic_selector",_rhp_cfg_parse_ext_traffic_selector,rlm,1);
  if( err == -ENOENT ){
  	rlm->ext_tss.etss_num = 0;
  	rlm->ext_tss.etss = NULL;
  	err = 0;
  }else if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

  return 0;

error:
  return err;
}



static int _rhp_cfg_parse_peer_secondary(xmlNodePtr node,void* ctx)
{
  int err;
  rhp_cfg_peer* cfg_peer = (rhp_cfg_peer*)ctx;
  int ret_len;
  u16 dmy_port;

  dmy_port = rhp_gcfg_ike_port; // LOCK not needed. Don't ntohs().

  if( cfg_peer->primary_addr.addr_family != AF_UNSPEC ){

    err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"address_v4"),
    				RHP_XML_DT_IPV4,&(cfg_peer->secondary_addr.addr.v4),&ret_len,NULL,0);
    if( !err ){

      cfg_peer->secondary_addr.addr_family = AF_INET;

    }else if( err == -ENOENT ){

      err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"address_v6"),
      				RHP_XML_DT_IPV6,&(cfg_peer->secondary_addr),&ret_len,NULL,0);
      if( err ){
        RHP_BUG("");
        goto error;
      }

      cfg_peer->secondary_addr.addr_family = AF_INET6;

    }else{
      RHP_BUG("");
      goto error;
    }

    err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"port"),
    				RHP_XML_DT_PORT,&(cfg_peer->secondary_addr.port),&ret_len,&dmy_port,sizeof(dmy_port));
    if( err ){
      RHP_BUG("");
      goto error;
    }

  }else{

  	rhp_ip_addr_reset(&(cfg_peer->secondary_addr));
    cfg_peer->secondary_addr.port = htons(dmy_port);
  }

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"source_interface"),
  				RHP_XML_DT_STRING,&(cfg_peer->secondary_tx_if_name),&ret_len,NULL,0);
  if( err && err != -ENOENT ){
    RHP_BUG("");
    goto error;
  }
  err = 0;

  return 0;

error:
  return err;
}

static int _rhp_cfg_parse_peer_service(xmlNodePtr node,void* ctx)
{
  rhp_cfg_peer* cfg_peer = (rhp_cfg_peer*)ctx;

  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"name"),(xmlChar*)"access_point") ){

  	cfg_peer->is_access_point = 1;
  }

  return 0;
}

//
// TODO : Fixed Path MTU setting for each peer.
//
static int _rhp_cfg_parse_peer(xmlNodePtr node,void* ctx)
{
  int err;
  rhp_vpn_realm* rlm = (rhp_vpn_realm*)ctx;
  rhp_cfg_peer* cfg_peer = NULL;
  rhp_cfg_peer *cfg_peer_p = NULL,*cfg_peer_c = NULL;
  int ret_len, flag;
  u16 dmy_port;

  dmy_port = rhp_gcfg_ike_port; // LOCK not needed. Don't ntohs().

  cfg_peer = (rhp_cfg_peer*)_rhp_malloc(sizeof(rhp_cfg_peer));
  if( cfg_peer == NULL ){
    return -ENOMEM;
  }
  memset(cfg_peer,0,sizeof(rhp_cfg_peer));

  cfg_peer->tag[0] = '#';
  cfg_peer->tag[1] = 'C';
  cfg_peer->tag[2] = 'F';
  cfg_peer->tag[3] = 'P';

  err = rhp_cfg_parse_ikev2_id(node,(const xmlChar*)"id_type",(const xmlChar*)"id",&(cfg_peer->id));
  if( err == -ENOENT ){

  	cfg_peer->id.type = RHP_PROTO_IKE_ID_ANY;

  }else if( err ){

  	RHP_BUG("");
    goto error;
  }
  err = 0;

  if( cfg_peer->id.type != RHP_PROTO_IKE_ID_FQDN &&
      cfg_peer->id.type != RHP_PROTO_IKE_ID_RFC822_ADDR &&
      cfg_peer->id.type != RHP_PROTO_IKE_ID_IPV4_ADDR &&
      cfg_peer->id.type != RHP_PROTO_IKE_ID_IPV6_ADDR &&
      cfg_peer->id.type != RHP_PROTO_IKE_ID_DER_ASN1_DN &&
      cfg_peer->id.type != RHP_PROTO_IKE_ID_NULL_ID &&
      cfg_peer->id.type != RHP_PROTO_IKE_ID_ANY ){
    RHP_BUG("");
    goto error;
  }

  {
  	rhp_ip_addr_reset(&(cfg_peer->primary_addr));

  	err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"address_v4"),RHP_XML_DT_IPV4,
				&(cfg_peer->primary_addr.addr.v4),&ret_len,NULL,0);

		if( !err ){

			cfg_peer->primary_addr.addr_family = AF_INET;

		}else if( err == -ENOENT ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"address_v6"),
							RHP_XML_DT_IPV6,&(cfg_peer->primary_addr),&ret_len,NULL,0);

			if( err == -ENOENT ){

				err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"address_fqdn"),
								RHP_XML_DT_STRING,&(cfg_peer->primary_addr_fqdn),&ret_len,NULL,0);

				if( err && err != -ENOENT ){
					RHP_BUG("");
					goto error;
				}
				err = 0;

			}else if( err ){
				RHP_BUG("");
				goto error;
			}else{
				cfg_peer->primary_addr.addr_family = AF_INET6;
			}

		}else{
			RHP_BUG("");
			goto error;
		}
  }

  if( (cfg_peer->id.type != RHP_PROTO_IKE_ID_ANY) ||
  		 !rhp_ip_addr_null(&(cfg_peer->primary_addr)) ||
  		 cfg_peer->primary_addr_fqdn ){

    err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"port"),RHP_XML_DT_PORT,
    		&(cfg_peer->primary_addr.port),&ret_len,&dmy_port,sizeof(dmy_port));

    if( err ){
      RHP_BUG("");
      goto error;
    }

  	err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"internal_address_v4"),RHP_XML_DT_IPV4,
  		&(cfg_peer->internal_addr.addr.v4),&ret_len,NULL,0);
		if( err && err != -ENOENT ){
			RHP_BUG("");
			goto error;
		}
		cfg_peer->internal_addr.addr_family = AF_INET;
		err = 0;

  	err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"internal_address_v6"),
  					RHP_XML_DT_IPV6,&(cfg_peer->internal_addr_v6),&ret_len,NULL,0);
		if( err && err != -ENOENT ){
			RHP_BUG("");
			goto error;
		}
		cfg_peer->internal_addr_v6.addr_family = AF_INET6;
		err = 0;


		err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"source_interface"),
						RHP_XML_DT_STRING,&(cfg_peer->primary_tx_if_name),&ret_len,NULL,0);

		if( err && err != -ENOENT ){
			RHP_BUG("");
			goto error;
		}
		err = 0;
  }


	cfg_peer->ikev1_init_mode = RHP_IKEV1_INITIATOR_DISABLED;
	cfg_peer->ikev1_commit_bit_enabled = 0;

	cfg_peer->always_on_connection = 0;


	if( !rhp_ip_addr_null(&(cfg_peer->primary_addr)) ||
			cfg_peer->primary_addr_fqdn ){

		int ikev1_init_enabled = 0;

		err = rhp_xml_enum_tags(node,(xmlChar*)"secondary",_rhp_cfg_parse_peer_secondary,cfg_peer,0);
		if( err == -ENOENT ){

			rhp_ip_addr_reset(&(cfg_peer->secondary_addr));
			cfg_peer->secondary_addr.port = htons(dmy_port);

			err = 0;

		}else if( err ){
			RHP_BUG("");
			goto error;
		}

	  rhp_xml_check_enable(node,(const xmlChar*)"ikev1",&ikev1_init_enabled);
	  if( ikev1_init_enabled ){

		  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"ikev1_mode"),(xmlChar*)"main") ){

		  	cfg_peer->ikev1_init_mode = RHP_IKEV1_INITIATOR_MODE_MAIN;

		  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"ikev1_mode"),(xmlChar*)"aggressive") ){

		  	cfg_peer->ikev1_init_mode = RHP_IKEV1_INITIATOR_MODE_AGGRESSIVE;
		  }

			{
				flag = cfg_peer->ikev1_commit_bit_enabled;
				rhp_xml_check_enable(node,(const xmlChar*)"ikev1_commit_bit",&flag);
				cfg_peer->ikev1_commit_bit_enabled = flag;
			}
	  }

	  rhp_xml_check_enable(node,(const xmlChar*)"always_on_connection",&(cfg_peer->always_on_connection));
	}


  err = rhp_xml_enum_tags(node,(xmlChar*)"peer_service",_rhp_cfg_parse_peer_service,cfg_peer,1);
  if( err && err != -ENOENT ){
    RHP_BUG("");
    goto error;
  }
  err = 0;


  err = rhp_xml_enum_tags(node,(xmlChar*)"traffic_selectors",
  				_rhp_cfg_parse_peer_traffic_selectors,cfg_peer,0);
  if( err == -ENOENT ){
    cfg_peer->my_tss = NULL;
    cfg_peer->peer_tss = NULL;
    err = 0;
  }else if( err ){
    RHP_BUG("");
    goto error;
  }

	if( cfg_peer->my_tss == NULL ){

		err = _rhp_cfg_alloc_any_traffic_selector(&(cfg_peer->my_tss),&cfg_peer->my_tss_num);
		if( err ){
			RHP_BUG("");
			goto error;
		}
	}

	if( cfg_peer->peer_tss == NULL ){

		err = _rhp_cfg_alloc_any_traffic_selector(&(cfg_peer->peer_tss),&cfg_peer->peer_tss_num);
		if( err ){
			RHP_BUG("");
			goto error;
		}
	}


  if( rlm->is_access_point && cfg_peer->is_access_point ){
    RHP_BUG("");
    goto error;
  }

  if( cfg_peer->is_access_point && (rlm->access_point_peer != NULL) ){
    RHP_BUG("");
    goto error;
  }

  if( cfg_peer->id.type == RHP_PROTO_IKE_ID_ANY ){

    cfg_peer_c = rlm->peers;

    while( cfg_peer_c ){
    	cfg_peer_p = cfg_peer_c;
    	cfg_peer_c = cfg_peer_c->next;
    }

    if( cfg_peer_p == NULL ){
    	rlm->peers = cfg_peer;
    }else{
    	cfg_peer_p->next = cfg_peer;
    }

  }else{

  	cfg_peer->next = rlm->peers;
    rlm->peers = cfg_peer;
  }

  if( cfg_peer->is_access_point ){
  	rlm->access_point_peer = cfg_peer;
  }


  {
		cfg_peer->v6_udp_encap_disabled = 0;

		rhp_xml_check_enable(node,(const xmlChar*)"v6_udp_encapsulation_disabled",
				&(cfg_peer->v6_udp_encap_disabled));
  }


  if( rhp_ikev2_is_null_auth_id(cfg_peer->id.type) &&
  		rhp_ip_addr_null(&(cfg_peer->primary_addr)) &&
  		cfg_peer->primary_addr_fqdn == NULL ){

		RHP_LOG_W(RHP_LOG_SRC_CFG,rlm->id,RHP_LOG_ID_REMOTE_PEER_ADDRESS_NOT_SPECIFIED_FOR_NULL_ID,"I",&(cfg_peer->id));
  }

  return 0;

error:
  if( cfg_peer ){
    _rhp_free(cfg_peer);
  }

  return -EINVAL;
}

static int _rhp_create_def_rlm_peer(rhp_vpn_realm* rlm)
{
  int err = -EINVAL;
  rhp_cfg_peer* cfg_peer = NULL;
  rhp_cfg_peer *cfg_peer_p = NULL,*cfg_peer_c = NULL;
  u32 dmy_addr = 0;
  u16 dmy_port;

  dmy_port = rhp_gcfg_ike_port; // LOCK not needed. Don't ntohs().

  cfg_peer = (rhp_cfg_peer*)_rhp_malloc(sizeof(rhp_cfg_peer));
  if( cfg_peer == NULL ){
  	RHP_BUG("");
    return -ENOMEM;
  }
  memset(cfg_peer,0,sizeof(rhp_cfg_peer));

  cfg_peer->tag[0] = '#';
  cfg_peer->tag[1] = 'C';
  cfg_peer->tag[2] = 'F';
  cfg_peer->tag[3] = 'P';

  cfg_peer->id.type = RHP_PROTO_IKE_ID_ANY;

  cfg_peer->primary_addr.addr_family = AF_INET;
  cfg_peer->internal_addr.addr_family = AF_INET;
  cfg_peer->primary_addr.port = htons(dmy_port);

  cfg_peer->secondary_addr.addr.v4 = dmy_addr;
  cfg_peer->secondary_addr.port = htons(dmy_port);
  cfg_peer->secondary_addr.addr_family = AF_INET;

  err = _rhp_cfg_alloc_any_traffic_selector(&(cfg_peer->my_tss),&cfg_peer->my_tss_num);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  err = _rhp_cfg_alloc_any_traffic_selector(&(cfg_peer->peer_tss),&cfg_peer->peer_tss_num);
  	if( err ){
  		RHP_BUG("");
  		goto error;
    }

    cfg_peer_c = rlm->peers;

    while( cfg_peer_c ){
    	cfg_peer_p = cfg_peer_c;
    	cfg_peer_c = cfg_peer_c->next;
    }

    if( cfg_peer_p == NULL ){
    	rlm->peers = cfg_peer;
    }else{
    	cfg_peer_p->next = cfg_peer;
    }

  return 0;

error:
  if( cfg_peer ){
    _rhp_free(cfg_peer);
  }
  return -EINVAL;
}

static int _rhp_cfg_parse_peers(xmlNodePtr node,void* ctx)
{
  return rhp_xml_enum_tags(node,(xmlChar*)"peer",_rhp_cfg_parse_peer,ctx,1);
}


static int _rhp_cfg_parse_split_dns_domain(xmlNodePtr node,void* ctx)
{
  int err;
  rhp_vpn_realm* rlm = (rhp_vpn_realm*)ctx;
  int ret_len;
  rhp_split_dns_domain *domain = NULL,*domain_p = NULL;

  domain = (rhp_split_dns_domain*)_rhp_malloc(sizeof(rhp_split_dns_domain));
  if( domain == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }

  memset(domain,0,sizeof(rhp_split_dns_domain));

  domain->tag[0] = '#';
  domain->tag[1] = 'C';
  domain->tag[2] = 'S';
  domain->tag[3] = 'D';

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"match"),RHP_XML_DT_STRING,&(domain->name),&ret_len,NULL,0);
  if( err ){
    RHP_BUG("");
    goto error;
  }
  err = 0;

	RHP_TRC(0,RHPTRCID_CFG_PARSE_SPLIT_DNS_DOMAIN,"xs",domain,domain->name);

  domain_p = rlm->split_dns.domains;
  while( domain_p ){

  	if( domain_p->next == NULL ){
  		break;
  	}

  	domain_p = domain_p->next;
  }

  if( domain_p == NULL ){
  	rlm->split_dns.domains = domain;
  }else{
  	domain_p->next = domain;
  }

  return 0;

error:
	return err;
}

static int _rhp_cfg_parse_split_dns(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
  rhp_vpn_realm* rlm = (rhp_vpn_realm*)ctx;
  int ret_len;

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"internal_dns_server_address_v4"),RHP_XML_DT_IPV4,
  		&(rlm->split_dns.internal_server_addr.addr.v4),&ret_len,NULL,0);

  if( err && err != -ENOENT ){

    RHP_BUG("%d",err);
    goto error;

  }else if( err == 0 ){

  	rlm->split_dns.internal_server_addr.addr_family = AF_INET;
  	rlm->split_dns.static_internal_server_addr = 1;

  	rhp_ip_addr_dump("rlm->split_dns.internal_server_addr",&(rlm->split_dns.internal_server_addr));
  }
  err = 0;


  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,
  				(const xmlChar*)"internal_dns_server_address_v6"),RHP_XML_DT_IPV6,
  				&(rlm->split_dns.internal_server_addr_v6),&ret_len,NULL,0);

  if( err && err != -ENOENT ){

    RHP_BUG("%d",err);
    goto error;

  }else if( err == 0 ){

  	rlm->split_dns.internal_server_addr_v6.addr_family = AF_INET6;
  	rlm->split_dns.static_internal_server_addr_v6 = 1;

    rhp_ip_addr_dump("rlm->split_dns.internal_server_addr_v6",&(rlm->split_dns.internal_server_addr_v6));
  }
  err = 0;


  return rhp_xml_enum_tags(node,(xmlChar*)"domain",_rhp_cfg_parse_split_dns_domain,ctx,1);

error:
	return err;
}


static int _rhp_cfg_parse_route_map(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
  rhp_vpn_realm* rlm = (rhp_vpn_realm*)ctx;
  rhp_route_map* rtmap = NULL;
  rhp_route_map* rtmap_tail = NULL;
  int vn = 0;
  int ret_len;

  rtmap = (rhp_route_map*)_rhp_malloc(sizeof(rhp_route_map));
  if( rtmap == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }

  memset(rtmap,0,sizeof(rhp_route_map));

  rtmap->tag[0] = '#';
  rtmap->tag[1] = 'R';
  rtmap->tag[2] = 'M';
  rtmap->tag[3] = 'P';

  {
		rhp_ip_addr* ip_addr = NULL;

		err = rhp_xml_str2val(rhp_xml_get_prop_static(node,
						(const xmlChar*)"destination_v4"),RHP_XML_DT_IPV4_SUBNET,&ip_addr,&ret_len,NULL,0);

		if( err == -ENOENT ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,
							(const xmlChar*)"destination_v6"),RHP_XML_DT_IPV6_SUBNET,&ip_addr,&ret_len,NULL,0);
		}
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		memcpy(&(rtmap->dest_addr),ip_addr,sizeof(rhp_ip_addr));
		_rhp_free(ip_addr);


	  err = rhp_cfg_parse_ikev2_id(node,(const xmlChar*)"gateway_peer_id_type",
	  				(const xmlChar*)"gateway_peer_id",&(rtmap->gateway_peer_id));
	  if( err == -ENOENT ){

	  	int addr_family = AF_INET;
	  	xmlChar* gw_addr = rhp_xml_get_prop(node,(const xmlChar*)"gateway_addr_v4");

	  	if( gw_addr == NULL ){

	  		gw_addr = rhp_xml_get_prop(node,(const xmlChar*)"gateway_addr_v6");
	  		if( gw_addr ){
	  			addr_family = AF_INET6;
	  		}
	  	}

	  	if( gw_addr ){

	  		if( !xmlStrcmp(gw_addr,(xmlChar*)"null")){

	  			rtmap->tx_interface = (char*)_rhp_malloc(strlen(RHP_VIRTUAL_NULL_IF_NAME) + 1);
	  			if( rtmap->tx_interface == NULL ){
	  	  		_rhp_free(gw_addr);
	  				RHP_BUG("");
	  				err = -ENOMEM;
	  				goto error;
	  			}

	  			rtmap->tx_interface[0] = '\0';
	  			strcpy(rtmap->tx_interface,RHP_VIRTUAL_NULL_IF_NAME);

	  			vn++;

	  		}else{

	  			if( addr_family == AF_INET ){

	  				u32 ipv4;

						err = rhp_xml_str2val(gw_addr,RHP_XML_DT_IPV4,&ipv4,&ret_len,NULL,0);
						if( err ){
							_rhp_free(gw_addr);
							RHP_BUG("");
							goto error;
						}

						rtmap->gateway_addr.addr_family = AF_INET;
						rtmap->gateway_addr.addr.v4 = ipv4;

						vn++;

	  			}else if( addr_family == AF_INET6 ){

	  				rhp_ip_addr ipv6;

						err = rhp_xml_str2val(gw_addr,RHP_XML_DT_IPV6,&ipv6,&ret_len,NULL,0);
						if( err ){
							_rhp_free(gw_addr);
							RHP_BUG("");
							goto error;
						}

						rtmap->gateway_addr.addr_family = AF_INET6;
						memcpy(rtmap->gateway_addr.addr.v6,ipv6.addr.v6,16);

						vn++;
	  			}
	  		}

	  		_rhp_free(gw_addr);

	  	}else{

					err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"interface"),
									RHP_XML_DT_STRING,&(rtmap->tx_interface),&ret_len,NULL,0);
					if( err ){
	  				RHP_BUG("");
	  				goto error;
					}

					vn++;
	  	}

		}else if( err ){

			RHP_BUG("%d",err);
			goto error;

		}else{

		  if( rtmap->gateway_peer_id.type != RHP_PROTO_IKE_ID_FQDN &&
		  		rtmap->gateway_peer_id.type != RHP_PROTO_IKE_ID_RFC822_ADDR &&
		  		rtmap->gateway_peer_id.type != RHP_PROTO_IKE_ID_DER_ASN1_DN ){
		    RHP_BUG("%d",rtmap->gateway_peer_id.type);
		    goto error;
		  }

			vn++;
		}

		err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"metric"),
						RHP_XML_DT_UINT,&(rtmap->metric),&ret_len,NULL,0);
		if( err ){
			err = 0;
			rtmap->metric = 0;
		}
  }

  if( vn == 0 ){
  	err = -EINVAL;
  	RHP_BUG("");
  	goto error;
  }

  rtmap_tail = rlm->route_maps;
  while( rtmap_tail ){
  	if( rtmap_tail->next == NULL ){
  		break;
  	}
  	rtmap_tail = rtmap_tail->next;
  }

  if( rtmap_tail == NULL ){
  	rlm->route_maps = rtmap;
  }else{
  	rtmap_tail->next = rtmap;
  }

	RHP_TRC(0,RHPTRCID_CFG_PARSE_ROUTE_MAP,"xus",rtmap,rtmap->metric,rtmap->tx_interface);
	rhp_ip_addr_dump("rtmap->dest_addr",&(rtmap->dest_addr));
	rhp_ip_addr_dump("rtmap->gateway_addr",&(rtmap->gateway_addr));
	rhp_ikev2_id_dump("rtmap->gateway_peer_id",&(rtmap->gateway_peer_id));

  return 0;

error:
	if( rtmap ){
		if( rtmap->tx_interface ){
			_rhp_free(rtmap->tx_interface);
		}
		_rhp_free(rtmap);
	}

	return err;
}

static int _rhp_cfg_parse_route_maps(xmlNodePtr node,void* ctx)
{
  return rhp_xml_enum_tags(node,(xmlChar*)"route_map",_rhp_cfg_parse_route_map,ctx,1);
}

rhp_cfg_peer_acl* rhp_cfg_parse_peer_acl(xmlNodePtr node)
{
  rhp_cfg_peer_acl *cfg_peer_acl = NULL;
  int ret_len;

  cfg_peer_acl = (rhp_cfg_peer_acl*)_rhp_malloc(sizeof(rhp_cfg_peer_acl));
  if( cfg_peer_acl == NULL ){
  	RHP_BUG("");
    return NULL;
  }
  memset(cfg_peer_acl,0,sizeof(rhp_cfg_peer_acl));

  cfg_peer_acl->tag[0] = '#';
  cfg_peer_acl->tag[1] = 'P';
  cfg_peer_acl->tag[2] = 'A';
  cfg_peer_acl->tag[3] = 'C';

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"priority"),RHP_XML_DT_INT,&(cfg_peer_acl->priority),&ret_len,NULL,0) ){
    cfg_peer_acl->priority = INT_MAX;
  }

  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"type"),(xmlChar*)"ipv4_subnet") ){

    rhp_ip_addr* ipv4_subnet = NULL;

    if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"match"),RHP_XML_DT_IPV4_SUBNET,&ipv4_subnet,&ret_len,NULL,0) ){
      RHP_BUG("");
      goto error;
    }
    memcpy(&(cfg_peer_acl->addr),ipv4_subnet,sizeof(rhp_ip_addr));
    _rhp_free(ipv4_subnet);

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"type"),(xmlChar*)"ipv4") ){

    if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"match"),RHP_XML_DT_IPV4,&(cfg_peer_acl->addr.addr.v4),&ret_len,NULL,0) ){
      RHP_BUG("");
      goto error;
    }
    cfg_peer_acl->addr.prefixlen = 32;
    cfg_peer_acl->addr.netmask.v4 = 0xFFFFFFFF;
    cfg_peer_acl->addr.addr_family = AF_INET;

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"type"),(xmlChar*)"ipv6_subnet") ){

      rhp_ip_addr* ipv6_subnet = NULL;

      if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"match"),
      			RHP_XML_DT_IPV6_SUBNET,&ipv6_subnet,&ret_len,NULL,0) ){
        RHP_BUG("");
        goto error;
      }
      memcpy(&(cfg_peer_acl->addr),ipv6_subnet,sizeof(rhp_ip_addr));
      _rhp_free(ipv6_subnet);

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"type"),
    						(xmlChar*)"ipv6") ){

    if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"match"),
      			RHP_XML_DT_IPV6,&(cfg_peer_acl->addr),&ret_len,NULL,0) ){
      RHP_BUG("");
      goto error;
    }
    cfg_peer_acl->addr.prefixlen = 128;
    ((u64*)cfg_peer_acl->addr.netmask.v6)[0] = 0xFFFFFFFFFFFFFFFFUL;
    ((u64*)cfg_peer_acl->addr.netmask.v6)[1] = 0xFFFFFFFFFFFFFFFFUL;
    cfg_peer_acl->addr.addr_family = AF_INET6;

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"type"),
  						(xmlChar*)"any") ){

  	cfg_peer_acl->any = 1;

  }else{
    RHP_BUG("");
    goto error;
  }

  return cfg_peer_acl;

error:
  if( cfg_peer_acl ){
    _rhp_free(cfg_peer_acl);
  }
  return NULL;
}

void rhp_cfg_free_peer_acls(rhp_cfg_peer_acl* cfg_peer_acls_head)
{
	rhp_cfg_peer_acl* cfg_peer_acl = cfg_peer_acls_head;

	while( cfg_peer_acl ){
		rhp_cfg_peer_acl* cfg_peer_acl_n = cfg_peer_acl->next;
		_rhp_free(cfg_peer_acl);
		cfg_peer_acl = cfg_peer_acl_n;
	}
}

static int _rhp_cfg_parse_peer_acl(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
  rhp_cfg_peer_acl *cfg_peer_acl = NULL;
  rhp_cfg_peer_acl *cfg_peer_acl_p = NULL,*cfg_peer_acl_c = NULL;

  cfg_peer_acl = rhp_cfg_parse_peer_acl(node);
  if( cfg_peer_acl == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  cfg_peer_acl_c = rhp_cfg_peer_acl_list;

  while( cfg_peer_acl_c ){

    if( cfg_peer_acl_c->priority > cfg_peer_acl->priority ){
      break;
    }

    cfg_peer_acl_p = cfg_peer_acl_c;
    cfg_peer_acl_c = cfg_peer_acl_c->next;
  }

  if( cfg_peer_acl_p == NULL ){
  	cfg_peer_acl->next = rhp_cfg_peer_acl_list;
    rhp_cfg_peer_acl_list = cfg_peer_acl;
  }else{
    cfg_peer_acl->next = cfg_peer_acl_p->next;
    cfg_peer_acl_p->next = cfg_peer_acl;
  }

  return 0;

error:
  if( cfg_peer_acl ){
    _rhp_free(cfg_peer_acl);
  }
  return -EINVAL;
}

static int _rhp_cfg_parse_peer_acls(xmlNodePtr node,void* ctx)
{
  return rhp_xml_enum_tags(node,(xmlChar*)"peer_acl",_rhp_cfg_parse_peer_acl,ctx,1);
}

static int _rhp_cfg_parse_admin_service_acl(xmlNodePtr node,void* ctx)
{
  rhp_cfg_admin_service* cfg_admin_srv = (rhp_cfg_admin_service*)ctx;
  rhp_cfg_peer_acl *cfg_peer_acl = NULL;
  rhp_cfg_peer_acl *cfg_peer_acl_p = NULL,*cfg_peer_acl_c = NULL;
  int ret_len;

  cfg_peer_acl = (rhp_cfg_peer_acl*)_rhp_malloc(sizeof(rhp_cfg_peer_acl));
  if( cfg_peer_acl == NULL ){
	RHP_BUG("");
    return -ENOMEM;
  }
  memset(cfg_peer_acl,0,sizeof(rhp_cfg_peer_acl));

  cfg_peer_acl->tag[0] = '#';
  cfg_peer_acl->tag[1] = 'P';
  cfg_peer_acl->tag[2] = 'A';
  cfg_peer_acl->tag[3] = 'C';

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"priority"),
  			RHP_XML_DT_INT,&(cfg_peer_acl->priority),&ret_len,NULL,0) ){
    cfg_peer_acl->priority = INT_MAX;
  }

  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,
  			(const xmlChar*)"type"),(xmlChar*)"ipv4_subnet") ){

    rhp_ip_addr* ipv4_subnet = NULL;

    if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"match"),
    			RHP_XML_DT_IPV4_SUBNET,&ipv4_subnet,&ret_len,NULL,0) ){
      RHP_BUG("");
      goto error;
    }
    memcpy(&(cfg_peer_acl->addr),ipv4_subnet,sizeof(rhp_ip_addr));
    _rhp_free(ipv4_subnet);

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,
  						(const xmlChar*)"type"),(xmlChar*)"ipv4") ){

    if( rhp_xml_str2val(rhp_xml_get_prop_static(node,
    			(const xmlChar*)"match"),RHP_XML_DT_IPV4,&(cfg_peer_acl->addr.addr.v4),&ret_len,NULL,0) ){
      RHP_BUG("");
      goto error;
    }
    cfg_peer_acl->addr.addr_family = AF_INET;
    cfg_peer_acl->addr.prefixlen = 32;
    cfg_peer_acl->addr.netmask.v4 = 0xFFFFFFFF;

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,
    			(const xmlChar*)"type"),(xmlChar*)"ipv6_subnet") ){

    rhp_ip_addr* ipv6_subnet = NULL;

    if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"match"),
    		RHP_XML_DT_IPV6_SUBNET,&ipv6_subnet,&ret_len,NULL,0) ){
      RHP_BUG("");
      goto error;
    }
    memcpy(&(cfg_peer_acl->addr),ipv6_subnet,sizeof(rhp_ip_addr));
    _rhp_free(ipv6_subnet);

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,
  						(const xmlChar*)"type"),(xmlChar*)"ipv6") ){

    if( rhp_xml_str2val(rhp_xml_get_prop_static(node,
    			(const xmlChar*)"match"),RHP_XML_DT_IPV6,&(cfg_peer_acl->addr),&ret_len,NULL,0) ){
      RHP_BUG("");
      goto error;
    }
    cfg_peer_acl->addr.addr_family = AF_INET6;
    cfg_peer_acl->addr.prefixlen = 128;
    memset(cfg_peer_acl->addr.netmask.v6,0xFF,16);

  }else{
    RHP_BUG("");
    goto error;
  }

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"vpn_realm"),
  			RHP_XML_DT_ULONG,&(cfg_peer_acl->vpn_realm_id),&ret_len,NULL,0) ){
    cfg_peer_acl->vpn_realm_id = 0;
  }

  cfg_peer_acl_c = cfg_admin_srv->client_acls;

  while( cfg_peer_acl_c ){
    if( cfg_peer_acl_c->priority > cfg_peer_acl->priority ){
      break;
    }
    cfg_peer_acl_p = cfg_peer_acl_c;
    cfg_peer_acl_c = cfg_peer_acl_c->next;
  }

  if( cfg_peer_acl_p == NULL ){
  	cfg_peer_acl->next = cfg_admin_srv->client_acls;
    cfg_admin_srv->client_acls = cfg_peer_acl;
  }else{
    cfg_peer_acl->next = cfg_peer_acl_p->next;
    cfg_peer_acl_p->next = cfg_peer_acl;
  }

  return 0;

error:
  if( cfg_peer_acl ){
    _rhp_free(cfg_peer_acl);
  }
  return -EINVAL;
}

void rhp_cfg_free_admin_services(rhp_cfg_admin_service* cfg_admin_srv_head)
{
	rhp_cfg_admin_service* cfg_admin_srv = cfg_admin_srv_head;

	while( cfg_admin_srv ){

		rhp_cfg_admin_service* cfg_admin_srv_n = cfg_admin_srv->next;

	  if( cfg_admin_srv ){
	  	if( cfg_admin_srv->client_acls ){
	  		rhp_cfg_free_peer_acls(cfg_admin_srv->client_acls);
	  	}
	    _rhp_free(cfg_admin_srv);
	  }

		cfg_admin_srv = cfg_admin_srv_n;
	}
}

rhp_cfg_admin_service* rhp_cfg_parse_admin_service(xmlNodePtr node)
{
  int err = -EINVAL;
  rhp_cfg_admin_service *cfg_admin_srv = NULL;
  int ret_len;
  u32 dmy_addr = 0x7F000001;
  u16 dmy_port = 0;

  cfg_admin_srv = (rhp_cfg_admin_service*)_rhp_malloc(sizeof(rhp_cfg_admin_service));
  if( cfg_admin_srv == NULL ){
  	RHP_BUG("");
  	return NULL;
  }
  memset(cfg_admin_srv,0,sizeof(rhp_cfg_admin_service));

  cfg_admin_srv->tag[0] = '#';
  cfg_admin_srv->tag[1] = 'A';
  cfg_admin_srv->tag[2] = 'S';
  cfg_admin_srv->tag[3] = 'V';

  cfg_admin_srv->addr.addr_family = AF_INET;
  cfg_admin_srv->addr.netmask.v4 = 0xFFFFFFFF;
  cfg_admin_srv->addr.prefixlen = 32;

  memcpy(&(cfg_admin_srv->addr_v6),rhp_ipv6_loopback_addr,sizeof(rhp_ip_addr));


  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,
  				(const xmlChar*)"id"),RHP_XML_DT_ULONG,&(cfg_admin_srv->id),&ret_len,NULL,0);
  if( err ){
  	RHP_BUG("");
    goto error;
  }

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,
  				(const xmlChar*)"address_v4"),RHP_XML_DT_IPV4,&(cfg_admin_srv->addr.addr.v4),&ret_len,&dmy_addr,sizeof(dmy_addr));
  if( err ){
  	RHP_BUG("");
    goto error;
  }

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,
  				(const xmlChar*)"address_v6"),RHP_XML_DT_IPV6,&(cfg_admin_srv->addr_v6),&ret_len,NULL,0);
  if( err && err != -ENOENT ){
  	RHP_BUG("");
    goto error;
  }
  err = 0;

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,
  				(const xmlChar*)"port"),RHP_XML_DT_PORT,&(cfg_admin_srv->addr.port),&ret_len,&dmy_port,sizeof(dmy_port));
  if( err ){
  	RHP_BUG("");
    goto error;
  }

  if( !rhp_ip_addr_null(&(cfg_admin_srv->addr_v6)) ){
  	cfg_admin_srv->addr_v6.port = cfg_admin_srv->addr.port;
  }


  if( cfg_admin_srv->addr.addr.v4 == 0 || cfg_admin_srv->addr.port == 0 ){
  	RHP_BUG("");
    goto error;
  }

  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"protocol"),(xmlChar*)"http") ){
    cfg_admin_srv->protocol = RHP_CFG_ADMIN_SERVICE_PROTO_HTTP;
  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"protocol"),(xmlChar*)"https") ){
//  cfg_admin_srv->protocol = RHP_CFG_ADMIN_SERVICE_PROTO_HTTPS;
  	RHP_BUG("");
    goto error;
  }else{
  	RHP_BUG("");
    goto error;
  }

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"root_dir"),RHP_XML_DT_STRING,&(cfg_admin_srv->root_dir),&ret_len,".",0);
  if( err ){
  	RHP_BUG("");
    goto error;
  }

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"timeout"),RHP_XML_DT_INT,&(cfg_admin_srv->keep_alive_interval),&ret_len,NULL,0);
  if( err && err != -ENOENT ){
  	RHP_BUG("");
    goto error;
  }

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"max_connections"),RHP_XML_DT_INT,&(cfg_admin_srv->max_conns),&ret_len,NULL,0);
  if( err && err != -ENOENT ){
  	RHP_BUG("");
    goto error;
  }

  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"nobody_allowed"),(xmlChar*)"disable") ){
  	cfg_admin_srv->nobody_allowed_tmp = 0;
  }else{
  	cfg_admin_srv->nobody_allowed_tmp = 1;
  }

  if( cfg_admin_srv->nobody_allowed_tmp ){

  	if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"nobody_auto_reconnect"),(xmlChar*)"disable") ){
  		cfg_admin_srv->nobody_auto_reconnect_tmp = 0;
  	}else{
  		cfg_admin_srv->nobody_auto_reconnect_tmp = 1;
  	}

  }else{
		cfg_admin_srv->nobody_auto_reconnect_tmp = 0;
  }

  if( cfg_admin_srv->keep_alive_interval < 1 ){
    cfg_admin_srv->keep_alive_interval = rhp_gcfg_http_rx_timeout;
    if( cfg_admin_srv->keep_alive_interval < 1 ){
      cfg_admin_srv->keep_alive_interval = 1;
    }
  }

  if( cfg_admin_srv->max_conns < 1 ){
    cfg_admin_srv->max_conns = rhp_gcfg_http_rx_timeout;
    if( cfg_admin_srv->max_conns < 1 ){
      cfg_admin_srv->max_conns = 1;
    }
  }

  err = rhp_xml_enum_tags(node,(xmlChar*)"client_acl",_rhp_cfg_parse_admin_service_acl,cfg_admin_srv,1);
  if( err == -ENOENT ){
    cfg_admin_srv->client_acls = NULL;
    err = 0;
  }else if( err ){
    RHP_BUG("");
    goto error;
  }

  return cfg_admin_srv;

error:
  if( cfg_admin_srv ){
  	rhp_cfg_free_admin_services(cfg_admin_srv);
  }
  return NULL;
}

static int _rhp_cfg_parse_admin_service(xmlNodePtr node,void* ctx)
{
  int err = -EINVAL;
  rhp_cfg_admin_service *cfg_admin_srv = NULL;
  rhp_cfg_admin_service *cfg_admin_srv_p = NULL,*cfg_admin_srv_c = NULL;

  cfg_admin_srv = rhp_cfg_parse_admin_service(node);
  if( cfg_admin_srv == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

	if( cfg_admin_srv->protocol == RHP_CFG_ADMIN_SERVICE_PROTO_HTTP ){

		if( cfg_admin_srv->nobody_allowed_tmp ){
  		RHP_LOG_D(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_ADMIN_NOBODY_USER_CFG_ALLOWED,"dd",cfg_admin_srv->nobody_allowed_tmp,cfg_admin_srv->nobody_auto_reconnect_tmp);
		}

		rhp_gcfg_webmng_allow_nobody_admin = cfg_admin_srv->nobody_allowed_tmp;
		rhp_gcfg_webmng_auto_reconnect_nobody_admin = cfg_admin_srv->nobody_auto_reconnect_tmp;
	}

  cfg_admin_srv_c = rhp_cfg_admin_services;
  while( cfg_admin_srv_c ){
    cfg_admin_srv_p = cfg_admin_srv_c;
    cfg_admin_srv_c = cfg_admin_srv_c->next;
  }

  if( cfg_admin_srv_p == NULL ){
    rhp_cfg_admin_services = cfg_admin_srv;
  }else{
    cfg_admin_srv_p->next = cfg_admin_srv;
  }

  return 0;

error:
	if( cfg_admin_srv ){
		rhp_cfg_free_admin_services(cfg_admin_srv);
	}
  return -EINVAL;
}

static int _rhp_cfg_parse_admin_services(xmlNodePtr node,void* ctx)
{
  return rhp_xml_enum_tags(node,(xmlChar*)"admin_service",_rhp_cfg_parse_admin_service,ctx,1);
}


rhp_cfg_firewall* rhp_cfg_parse_firewall_rule(xmlNodePtr node)
{
	int err = -EINVAL;
	rhp_cfg_firewall* cfg_fw = NULL;
	int ret_len;

	cfg_fw = (rhp_cfg_firewall*)_rhp_malloc(sizeof(rhp_cfg_firewall));
	if( cfg_fw == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(cfg_fw,0,sizeof(rhp_cfg_firewall));

	cfg_fw->tag[0] = '#';
	cfg_fw->tag[1] = 'R';
	cfg_fw->tag[2] = 'F';
	cfg_fw->tag[3] = 'W';

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"priority"),RHP_XML_DT_INT,&(cfg_fw->priority),&ret_len,NULL,0);
  if( err ){
  	RHP_BUG("");
    goto error;
  }

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"traffic"),RHP_XML_DT_STRING,&(cfg_fw->traffic),&ret_len,NULL,0);
  if( err ){
  	RHP_BUG("");
    goto error;
  }

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"action"),RHP_XML_DT_STRING,&(cfg_fw->action),&ret_len,NULL,0);
  if( err ){
  	RHP_BUG("");
    goto error;
  }

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"interface"),RHP_XML_DT_STRING,&(cfg_fw->interface),&ret_len,NULL,0);
  if( err ){
  	RHP_BUG("");
    goto error;
  }

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"filter_pos"),RHP_XML_DT_STRING,&(cfg_fw->filter_pos),&ret_len,NULL,0);
  if( err ){
  	RHP_BUG("");
    goto error;
  }

  return cfg_fw;

error:
	if( cfg_fw ){
		rhp_cfg_free_firewall_rules(cfg_fw);
	}
	return NULL;
}

void rhp_cfg_free_firewall_rules(rhp_cfg_firewall* cfg_firewall_head)
{
	rhp_cfg_firewall* cfg_fw = cfg_firewall_head;

	while( cfg_fw ){

		rhp_cfg_firewall* cfg_fw_n = cfg_fw->next;

		if( cfg_fw->traffic ){
			_rhp_free(cfg_fw->traffic);
		}
		if( cfg_fw->action ){
			_rhp_free(cfg_fw->action);
		}
		if( cfg_fw->interface ){
			_rhp_free(cfg_fw->interface);
		}
		if( cfg_fw->filter_pos ){
			_rhp_free(cfg_fw->filter_pos);
		}

		_rhp_free(cfg_fw);

		cfg_fw = cfg_fw_n;
	}

	return;
}

static int _rhp_cfg_parse_firewall_rule(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
	rhp_cfg_firewall* cfg_fw = NULL;
	rhp_cfg_firewall *cfg_fw_p = NULL,*cfg_fw_c = NULL;

	cfg_fw = rhp_cfg_parse_firewall_rule(node);
  if( cfg_fw == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  cfg_fw_c = rhp_cfg_firewall_rules;

  while( cfg_fw_c ){

  	if( cfg_fw_c->priority > cfg_fw->priority ){
      break;
    }

  	cfg_fw_p = cfg_fw_c;
    cfg_fw_c = cfg_fw_c->next;
  }

  if( cfg_fw_p == NULL ){
  	cfg_fw->next = rhp_cfg_firewall_rules;
  	rhp_cfg_firewall_rules = cfg_fw;
  }else{
  	cfg_fw->next = cfg_fw_p->next;
  	cfg_fw_p->next = cfg_fw;
  }

  return 0;

error:
  if( cfg_fw ){
    _rhp_free(cfg_fw);
  }
  return -EINVAL;
}

static int _rhp_cfg_parse_firewall(xmlNodePtr node,void* ctx)
{
  return rhp_xml_enum_tags(node,(xmlChar*)"firewall_rule",_rhp_cfg_parse_firewall_rule,ctx,1);
}

static int _rhp_cfg_add_firewall_ipc_rule(int* buf_len,u8** buf_head,int* cur_len,u8** cur_p,
		rhp_cfg_firewall* cfg_fw,int arg0_len,u8* arg0,int arg1_len,u8* arg1)
{
	int len = sizeof(rhp_ipcmsg_fw_rule);
	rhp_ipcmsg_fw_rule* ipc_fw_rule;
	u8* p;

	RHP_TRC(0,RHPTRCID_CFG_ADD_FIREWALL_IPC_RULE,"dxdxxsssspp",*buf_len,*buf_head,*cur_len,*cur_p,cfg_fw,cfg_fw->traffic,cfg_fw->action,cfg_fw->interface,cfg_fw->filter_pos,arg0_len,arg0,arg1_len,arg1);

	len += (cfg_fw->traffic ? strlen(cfg_fw->traffic) : 0) + 1;
	len += (cfg_fw->action ? strlen(cfg_fw->action) : 0) + 1;
	len += (cfg_fw->interface ? strlen(cfg_fw->interface) : 0) + 1;
	len += (cfg_fw->filter_pos ? strlen(cfg_fw->filter_pos) : 0) + 1;
	len += arg0_len;
	len += arg1_len;

	if( *buf_len - *cur_len - len < 0 ){

		int tmp_len = *buf_len + len*3;
		u8* tmp = (u8*)_rhp_malloc(tmp_len);

		if( tmp == NULL ){
			RHP_BUG("");
			return -ENOMEM;
		}

		memcpy(tmp,*buf_head,*buf_len);
		_rhp_free(*buf_head);

		*buf_head = tmp;
		*buf_len = tmp_len;
		*cur_p = *buf_head + *cur_len;
	}

	ipc_fw_rule = (rhp_ipcmsg_fw_rule*)*cur_p;

	ipc_fw_rule->len = len;
	ipc_fw_rule->traffic_len = (cfg_fw->traffic ? strlen(cfg_fw->traffic) : 0) + 1;
	ipc_fw_rule->action_len = (cfg_fw->action ? strlen(cfg_fw->action) : 0) + 1;
	ipc_fw_rule->if_len = (cfg_fw->interface ? strlen(cfg_fw->interface) : 0) + 1;
	ipc_fw_rule->filter_pos_len = (cfg_fw->filter_pos ? strlen(cfg_fw->filter_pos) : 0) + 1;
	ipc_fw_rule->arg0_len = arg0_len;
	ipc_fw_rule->arg1_len = arg1_len;

	p = (u8*)(ipc_fw_rule + 1);

	p[ipc_fw_rule->traffic_len-1] = '\0';
	if( ipc_fw_rule->traffic_len > 1 ){
		strcpy((char*)p,cfg_fw->traffic);
	}
	p += ipc_fw_rule->traffic_len;

	p[ipc_fw_rule->action_len-1] = '\0';
	if( ipc_fw_rule->action_len > 1 ){
		strcpy((char*)p,cfg_fw->action);
	}
	p += ipc_fw_rule->action_len;

	p[ipc_fw_rule->if_len-1] = '\0';
	if( ipc_fw_rule->if_len > 1 ){
		strcpy((char*)p,cfg_fw->interface);
	}
	p += ipc_fw_rule->if_len;

	p[ipc_fw_rule->filter_pos_len-1] = '\0';
	if( ipc_fw_rule->filter_pos_len > 1 ){
		strcpy((char*)p,cfg_fw->filter_pos);
	}
	p += ipc_fw_rule->filter_pos_len;

	if( arg0_len ){
		memcpy(p,arg0,arg0_len);
		p += arg0_len;
	}

	if( arg1_len ){
		memcpy(p,arg1,arg1_len);
		p += arg1_len;
	}


	*cur_len += (p - *cur_p);
	*cur_p = p;

	RHP_TRC(0,RHPTRCID_CFG_ADD_FIREWALL_IPC_RULE_RTRN,"p",*buf_len,*buf_head);

	return 0;
}

int _rhp_cfg_add_firewall_ipc_admin_svc_rules(int* buf_len,u8** buf_head,int* cur_len,u8** cur_p,
		rhp_cfg_firewall* cfg_fw,rhp_cfg_admin_service* cfg_admin_service_head,unsigned int* rules_num)
{
	int err = -EINVAL;
  rhp_cfg_admin_service *cfg_admin_srv = cfg_admin_service_head;

	RHP_TRC(0,RHPTRCID_CFG_ADD_FIREWALL_IPC_ADMIN_SVC_RULES_LOOPBACK,"dxdxxxd",*buf_len,*buf_head,*cur_len,*cur_p,cfg_fw,cfg_admin_service_head,*rules_num);

  while( cfg_admin_srv ){

  	rhp_ip_addr_dump("is_loopback?",&(cfg_admin_srv->addr));

  	if( !rhp_ip_is_loopback(&(cfg_admin_srv->addr)) ){

  		rhp_cfg_peer_acl* client_acl = cfg_admin_srv->client_acls;
  		while( client_acl ){

  	  	rhp_ip_addr_dump("arg0",&(cfg_admin_srv->addr));
  	  	rhp_ip_addr_dump("arg1",&(client_acl->addr));

  			err = _rhp_cfg_add_firewall_ipc_rule(buf_len,buf_head,cur_len,cur_p,cfg_fw,
  					sizeof(rhp_ip_addr),(u8*)&(cfg_admin_srv->addr),
  					sizeof(rhp_ip_addr),(u8*)&(client_acl->addr));

  			if( err ){
  				goto error;
  			}

  			(*rules_num)++;

  			client_acl = client_acl->next;
  		}

  	}else{
  		RHP_TRC(0,RHPTRCID_CFG_ADD_FIREWALL_IPC_ADMIN_SVC_RULES_LOOPBACK,"");
  	}

  	cfg_admin_srv = cfg_admin_srv->next;
  }

  return 0;

error:
	RHP_TRC(0,RHPTRCID_CFG_ADD_FIREWALL_IPC_ADMIN_SVC_RULES_ERR,"E",err);
	return err;
}

int rhp_cfg_apply_firewall_rules(rhp_cfg_firewall* cfg_firewall_head,
		rhp_cfg_admin_service* cfg_admin_service_head)
{
	int err = -EINVAL;
	rhp_cfg_firewall* cfg_fw;
	u8 *cur_p,*buf = NULL;
	int cur_len,buf_len;
	unsigned int rules_num = 0;

	RHP_TRC(0,RHPTRCID_CFG_APPLY_FIREWALL_RULES,"xx",cfg_firewall_head,cfg_admin_service_head);

	buf = (u8*)rhp_ipc_alloc_msg(RHP_IPC_FIREWALL_RULES_APPLY,sizeof(rhp_ipcmsg_fw_rules));
	if( buf == NULL ){
		RHP_BUG("");
		goto error;
	}

	buf_len = sizeof(rhp_ipcmsg_fw_rules);
	cur_p = (u8*)(buf + sizeof(rhp_ipcmsg_fw_rules));
	cur_len = sizeof(rhp_ipcmsg_fw_rules);

	cfg_fw = cfg_firewall_head;
	while( cfg_fw ){

		int arg0_len = 0,arg1_len = 0;
		u8 *arg0 = NULL,*arg1 = NULL;

		if( !strcasecmp(cfg_fw->traffic,"web-mng") ){

			err = _rhp_cfg_add_firewall_ipc_admin_svc_rules(&buf_len,&buf,&cur_len,&cur_p,cfg_fw,cfg_admin_service_head,&rules_num);
			if( err ){
				goto error;
			}

		}else{

			err = _rhp_cfg_add_firewall_ipc_rule(&buf_len,&buf,&cur_len,&cur_p,cfg_fw,arg0_len,arg0,arg1_len,arg1);
			if( err ){
				goto error;
			}

			rules_num++;
		}

		cfg_fw = cfg_fw->next;
	}

	{
		rhp_ipcmsg_fw_rules* ipc_fw_rules = (rhp_ipcmsg_fw_rules*)buf;

		ipc_fw_rules->rules_num = rules_num;
		ipc_fw_rules->len = (cur_p - buf);

		if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipc_fw_rules,ipc_fw_rules->len,0) < 0 ){
			RHP_BUG("");
		}
	}

	_rhp_free(buf);

	RHP_TRC(0,RHPTRCID_CFG_APPLY_FIREWALL_RULES_RTRN,"xx",cfg_firewall_head,cfg_admin_service_head);
	return 0;

error:
	if( buf ){
		_rhp_free(buf);
	}
	RHP_TRC(0,RHPTRCID_CFG_APPLY_FIREWALL_RULES_ERR,"xxE",cfg_firewall_head,cfg_admin_service_head,err);
	return err;
}



void _rhp_gcfg_free_hash_url_http_svr(rhp_gcfg_hash_url_http_svr* http_svr)
{
	if( http_svr->server_name ){
		_rhp_free(http_svr->server_name);
	}
	_rhp_free(http_svr);
}

static int _rhp_gcfg_parse_hash_url_http_svr(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
	rhp_gcfg_hash_url* cfg_hash_url = (rhp_gcfg_hash_url*)ctx;
	rhp_gcfg_hash_url_http_svr* http_svr;
	int ret_len;

	http_svr = (rhp_gcfg_hash_url_http_svr*)_rhp_malloc(sizeof(rhp_gcfg_hash_url_http_svr));
	if( http_svr == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memset(http_svr,0,sizeof(rhp_gcfg_hash_url_http_svr));
	http_svr->tag[0] = '#';
	http_svr->tag[1] = 'H';
	http_svr->tag[2] = 'R';
	http_svr->tag[3] = 'H';


	if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"type"),(xmlChar*)"exact") ){
		http_svr->type = RHP_G_HASH_URL_HTTP_EXACT;
	}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"type"),(xmlChar*)"suffix") ){
		http_svr->type = RHP_G_HASH_URL_HTTP_SUFFIX;
	}else{
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"server_name"),RHP_XML_DT_STRING,
  		&(http_svr->server_name),&ret_len,NULL,0);

  if( err ){
  	RHP_BUG("");
    goto error;
  }

  if( cfg_hash_url->http_svrs_head == NULL ){
  	cfg_hash_url->http_svrs_head = http_svr;
  }else{
  	cfg_hash_url->http_svrs_tail->next = http_svr;
  }
	cfg_hash_url->http_svrs_tail = http_svr;

	return 0;

error:
	if( http_svr ){
		_rhp_gcfg_free_hash_url_http_svr(http_svr);
	}
	return err;
}

rhp_gcfg_hash_url* _rhp_gcfg_malloc_hash_url()
{
	rhp_gcfg_hash_url* cfg_hash_url = NULL;

	cfg_hash_url = (rhp_gcfg_hash_url*)_rhp_malloc(sizeof(rhp_gcfg_hash_url));
	if( cfg_hash_url == NULL ){
		RHP_BUG("");
		goto error;
	}

	memset(cfg_hash_url,0,sizeof(rhp_gcfg_hash_url));

	cfg_hash_url->tag[0] = '#';
	cfg_hash_url->tag[1] = 'H';
	cfg_hash_url->tag[2] = 'R';
	cfg_hash_url->tag[3] = 'L';

	cfg_hash_url->init_enabled = 1;
	cfg_hash_url->resp_enabled = 0;

	return cfg_hash_url;

error:
	return NULL;
}

rhp_gcfg_hash_url* rhp_gcfg_parse_hash_url(xmlNodePtr node)
{
	int err = -EINVAL;
	rhp_gcfg_hash_url* cfg_hash_url = NULL;

	cfg_hash_url = _rhp_gcfg_malloc_hash_url();
	if( cfg_hash_url == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

  rhp_xml_check_enable(node,(xmlChar*)"initiator_enabled",&(cfg_hash_url->init_enabled));
  rhp_xml_check_enable(node,(xmlChar*)"responder_enabled",&(cfg_hash_url->resp_enabled));


  err = rhp_xml_enum_tags(node,(xmlChar*)"http_server",_rhp_gcfg_parse_hash_url_http_svr,(void*)cfg_hash_url,1);
  if( err && err != -ENOENT ){
  	RHP_BUG("");
  	goto error;
  }

  return cfg_hash_url;

error:
	if( cfg_hash_url ){
		rhp_gcfg_free_hash_url(cfg_hash_url);
	}
  return NULL;
}

static int _rhp_gcfg_parse_hash_url(xmlNodePtr node,void* ctx)
{
	if( rhp_global_cfg_hash_url == NULL ){
		rhp_global_cfg_hash_url = rhp_gcfg_parse_hash_url(node);
	}
	return 0;
}

void rhp_gcfg_free_hash_url(rhp_gcfg_hash_url* cfg_hash_url)
{
	rhp_gcfg_hash_url_http_svr *http_svr = cfg_hash_url->http_svrs_head, *http_svr_n = NULL;

	while( http_svr ){

		http_svr_n = http_svr->next;

		_rhp_gcfg_free_hash_url_http_svr(http_svr);

		http_svr = http_svr_n;
	}

	_rhp_free(cfg_hash_url);

	return;
}

int rhp_gcfg_hash_url_enabled(int side)
{
	int ret = 0;

  RHP_TRC(0,RHPTRCID_GCFG_HASH_URL_ENABLED,"Ldx","IKE_SIDE",side,rhp_global_cfg_hash_url);

	RHP_LOCK(&rhp_gcfg_hash_url_lock);

	if( rhp_global_cfg_hash_url ){

		if( side == RHP_IKE_INITIATOR ){
			ret = rhp_global_cfg_hash_url->init_enabled;
		}else{
			ret = rhp_global_cfg_hash_url->resp_enabled;
		}
	}

	RHP_UNLOCK(&rhp_gcfg_hash_url_lock);

  RHP_TRC(0,RHPTRCID_GCFG_HASH_URL_ENABLED_RTRN,"Ldd","IKE_SIDE",side,ret);
	return ret;
}

int rhp_gcfg_hash_url_match_server_name(char* server_name)
{
	int ret = -1;
	rhp_gcfg_hash_url_http_svr* http_svr;

  RHP_TRC(0,RHPTRCID_GCFG_HASH_URL_MATCH_SERVER_NAME,"sx",server_name,rhp_global_cfg_hash_url);

	RHP_LOCK(&rhp_gcfg_hash_url_lock);

	if( rhp_global_cfg_hash_url == NULL || rhp_global_cfg_hash_url->http_svrs_head == NULL ){
		ret = 0;
		goto end;
	}

	http_svr = rhp_global_cfg_hash_url->http_svrs_head;
	while( http_svr ){

		if( http_svr->type == RHP_G_HASH_URL_HTTP_SUFFIX ){

			ret = rhp_string_suffix_search((u8*)server_name,strlen(server_name),http_svr->server_name);

			if( !ret ){
				RHP_TRC(0,RHPTRCID_GCFG_HASH_URL_MATCH_SERVER_NAME_SFX,"sxs",server_name,http_svr,http_svr->server_name);
				goto end;
			}

		}else if( http_svr->type == RHP_G_HASH_URL_HTTP_EXACT ){

			if( !strcmp(server_name,http_svr->server_name) ){
				RHP_TRC(0,RHPTRCID_GCFG_HASH_URL_MATCH_SERVER_NAME_EXACT,"sxs",server_name,http_svr,http_svr->server_name);
				ret = 0;
				goto end;
			}
		}


		http_svr = http_svr->next;
	}

end:
	RHP_UNLOCK(&rhp_gcfg_hash_url_lock);

  RHP_TRC(0,RHPTRCID_GCFG_HASH_URL_MATCH_SERVER_NAME_RTRN,"sd",server_name,ret);
	return ret;
}


rhp_eap_radius_gcfg* rhp_gcfg_alloc_eap_radius()
{
	rhp_eap_radius_gcfg* cfg_eap_radius = NULL;

	cfg_eap_radius = (rhp_eap_radius_gcfg*)_rhp_malloc(sizeof(rhp_eap_radius_gcfg));
	if( cfg_eap_radius == NULL ){
		RHP_BUG("");
		goto error;
	}
	memset(cfg_eap_radius,0,sizeof(rhp_eap_radius_gcfg));

	cfg_eap_radius->tag[0] = '#';
	cfg_eap_radius->tag[1] = 'R';
	cfg_eap_radius->tag[2] = 'D';
	cfg_eap_radius->tag[3] = 'C';

	cfg_eap_radius->enabled = 0;

	cfg_eap_radius->nas_addr.addr_family = AF_UNSPEC;
	cfg_eap_radius->server_addr_port.addr_family = AF_UNSPEC;

	cfg_eap_radius->retransmit_interval = RHP_RADIUS_RETRANSMIT_INTERVAL_DEF;
	cfg_eap_radius->retransmit_times = RHP_RADIUS_RETRANSMIT_TIMES_DEF;
	cfg_eap_radius->max_sessions = RHP_RADIUS_MAX_SESSIONS_DEF;

	cfg_eap_radius->tx_calling_station_id_enabled = 1;
	cfg_eap_radius->tx_nas_port_type_enabled = 1;

  RHP_TRC(0,RHPTRCID_GCFG_ALLOC_EAP_RADIUS_OK,"x",cfg_eap_radius);
	return cfg_eap_radius;

error:
	RHP_TRC(0,RHPTRCID_GCFG_ALLOC_EAP_RADIUS_ERR,"");
	return NULL;
}

void rhp_gcfg_free_eap_radius(rhp_eap_radius_gcfg* cfg_eap_radius)
{
  RHP_TRC(0,RHPTRCID_GCFG_FREE_EAP_RADIUS,"x",cfg_eap_radius);

	if( cfg_eap_radius->nas_id ){
		_rhp_free(cfg_eap_radius->nas_id);
	}

	if( cfg_eap_radius->connect_info ){
		_rhp_free(cfg_eap_radius->connect_info);
	}

	if( cfg_eap_radius->server_fqdn ){
		_rhp_free(cfg_eap_radius->server_fqdn);
	}

	if( cfg_eap_radius->server_secondary_fqdn ){
		_rhp_free(cfg_eap_radius->server_secondary_fqdn);
	}

	_rhp_free(cfg_eap_radius);

  RHP_TRC(0,RHPTRCID_GCFG_FREE_EAP_RADIUS_RTRN,"x",cfg_eap_radius);
	return;
}


rhp_radius_acct_gcfg* rhp_gcfg_alloc_radius_acct()
{
	rhp_radius_acct_gcfg* cfg_radius_acct = NULL;

	cfg_radius_acct = (rhp_radius_acct_gcfg*)_rhp_malloc(sizeof(rhp_radius_acct_gcfg));
	if( cfg_radius_acct == NULL ){
		RHP_BUG("");
		goto error;
	}
	memset(cfg_radius_acct,0,sizeof(rhp_radius_acct_gcfg));

	cfg_radius_acct->tag[0] = '#';
	cfg_radius_acct->tag[1] = 'R';
	cfg_radius_acct->tag[2] = 'D';
	cfg_radius_acct->tag[3] = 'A';

	cfg_radius_acct->enabled = 0;

	cfg_radius_acct->nas_addr.addr_family = AF_UNSPEC;
	cfg_radius_acct->server_addr_port.addr_family = AF_UNSPEC;

	cfg_radius_acct->retransmit_interval = RHP_RADIUS_RETRANSMIT_INTERVAL_DEF;
	cfg_radius_acct->retransmit_times = RHP_RADIUS_RETRANSMIT_TIMES_DEF;

  RHP_TRC(0,RHPTRCID_GCFG_ALLOC_RADIUS_ACCT_OK,"x",cfg_radius_acct);
	return cfg_radius_acct;

error:
	RHP_TRC(0,RHPTRCID_GCFG_ALLOC_RADIUS_ACCT_ERR,"");
	return NULL;
}

void rhp_gcfg_free_radius_acct(rhp_radius_acct_gcfg* cfg_radius_acct)
{
  RHP_TRC(0,RHPTRCID_GCFG_FREE_RADIUS_ACCT,"x",cfg_radius_acct);

	if( cfg_radius_acct->nas_id ){
		_rhp_free(cfg_radius_acct->nas_id);
	}

	if( cfg_radius_acct->connect_info ){
		_rhp_free(cfg_radius_acct->connect_info);
	}

	if( cfg_radius_acct->server_fqdn ){
		_rhp_free(cfg_radius_acct->server_fqdn);
	}

	if( cfg_radius_acct->server_secondary_fqdn ){
		_rhp_free(cfg_radius_acct->server_secondary_fqdn);
	}

	_rhp_free(cfg_radius_acct);

  RHP_TRC(0,RHPTRCID_GCFG_FREE_RADIUS_ACCT_RTRN,"x",cfg_radius_acct);
	return;
}


static int _rhp_gcfg_parse_eap_radius_setting(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
	rhp_eap_radius_gcfg* cfg_eap_radius = (rhp_eap_radius_gcfg*)ctx;
	int ret_len, flag;

  RHP_TRC(0,RHPTRCID_GCFG_PARSE_EAP_RADIUS_SETTING,"xx",node,cfg_eap_radius);

	if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"type"),(xmlChar*)"sending_attribute") ){

		flag = 0;

		if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"NAS-Identifier") ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"value"),RHP_XML_DT_STRING,
					&(cfg_eap_radius->nas_id),&ret_len,NULL,0);
			if( err ){
				RHP_BUG("");
				goto error;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"Connect-Info") ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"value"),RHP_XML_DT_STRING,
					&(cfg_eap_radius->connect_info),&ret_len,NULL,0);
			if( err ){
				RHP_BUG("");
				goto error;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"Framed-MTU") ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"value"),RHP_XML_DT_INT,
					&(cfg_eap_radius->tx_framed_mtu),&ret_len,NULL,0);
			if( err ){
				RHP_BUG("");
				goto error;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"NAS-Identifier-IKEv2-ID") ){

			rhp_xml_check_enable(node,(xmlChar*)"value",&flag);
			cfg_eap_radius->tx_nas_id_as_ikev2_id_enabled = flag;

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"Calling-Station-Id") ){

			rhp_xml_check_enable(node,(xmlChar*)"value",&flag);
			cfg_eap_radius->tx_calling_station_id_enabled = flag;

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"NAS-Port-Type") ){

			rhp_xml_check_enable(node,(xmlChar*)"value",&flag);
			cfg_eap_radius->tx_nas_port_type_enabled = flag;
		}



	}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"type"),(xmlChar*)"received_attribute") ){

		flag = 0;
		rhp_xml_check_enable(node,(xmlChar*)"value",&flag);

		if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"Session-Timeout") ){

			cfg_eap_radius->rx_session_timeout_enabled = flag;

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"Termination-Action") ){

			cfg_eap_radius->rx_term_action_enabled = flag;

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"Framed-IP-Address") ){

			cfg_eap_radius->rx_framed_ipv4_enabled = flag;

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"Framed-IPv6-Address") ){

			cfg_eap_radius->rx_framed_ipv6_enabled = flag;

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"MS-Primary-DNS-Server") ){

			cfg_eap_radius->rx_ms_primary_dns_server_v4_enabled = flag;

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"DNS-Server-IPv6-Address") ){

			cfg_eap_radius->rx_dns_server_v6_enabled = flag;

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"Route-IPv6-Information") ){

			cfg_eap_radius->rx_route_v6_info_enabled = flag;

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"MS-Primary-NBNS-Server") ){

			cfg_eap_radius->rx_ms_primary_nbns_server_v4_enabled = flag;

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"Tunnel-Private-Group-ID") ){

			cfg_eap_radius->rx_tunnel_private_group_id_enabled = flag;

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"Tunnel-Client-Auth-ID") ){

			cfg_eap_radius->rx_tunnel_client_auth_id_enabled = flag;
		}


	}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"type"),(xmlChar*)"received_private_attribute") ){

		int tmp_val;

		if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"vpn_realm_id_attr_type") ){

			tmp_val = 0;
			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"value"),RHP_XML_DT_INT,
							&tmp_val,&ret_len,NULL,0);
			if( err ){
				RHP_BUG("");
				goto error;
			}

			if( tmp_val > 255 ){
				cfg_eap_radius->rx_vpn_realm_id_attr_type = 0;
				RHP_BUG("");
			}else{
				cfg_eap_radius->rx_vpn_realm_id_attr_type = (u8)tmp_val;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"vpn_realm_role_attr_type") ){

			tmp_val = 0;
				err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"value"),RHP_XML_DT_INT,
								&tmp_val,&ret_len,NULL,0);
				if( err ){
					RHP_BUG("");
					goto error;
				}

				if( tmp_val > 255 ){
					cfg_eap_radius->rx_vpn_realm_role_attr_type = 0;
					RHP_BUG("");
				}else{
					cfg_eap_radius->rx_vpn_realm_role_attr_type = (u8)tmp_val;
				}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"user_index_attr_type") ){

			tmp_val = 0;
			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"value"),RHP_XML_DT_INT,
							&tmp_val,&ret_len,NULL,0);
			if( err ){
				RHP_BUG("");
				goto error;
			}

			if( tmp_val > 255 ){
				cfg_eap_radius->rx_user_index_attr_type = 0;
				RHP_BUG("");
			}else{
				cfg_eap_radius->rx_user_index_attr_type = (u8)tmp_val;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"internal_dns_v4_attr_type") ){

			tmp_val = 0;
			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"value"),RHP_XML_DT_INT,
							&tmp_val,&ret_len,NULL,0);
			if( err ){
				RHP_BUG("");
				goto error;
			}

			if( tmp_val > 255 ){
				cfg_eap_radius->rx_internal_dns_v4_attr_type = 0;
				RHP_BUG("");
			}else{
				cfg_eap_radius->rx_internal_dns_v4_attr_type = (u8)tmp_val;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"internal_dns_v6_attr_type") ){

			tmp_val = 0;
			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"value"),RHP_XML_DT_INT,
							&tmp_val,&ret_len,NULL,0);
			if( err ){
				RHP_BUG("");
				goto error;
			}

			if( tmp_val > 255 ){
				cfg_eap_radius->rx_internal_dns_v6_attr_type = 0;
				RHP_BUG("");
			}else{
				cfg_eap_radius->rx_internal_dns_v6_attr_type = (u8)tmp_val;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"internal_domain_names_attr_type") ){

			tmp_val = 0;
			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"value"),RHP_XML_DT_INT,
							&tmp_val,&ret_len,NULL,0);
			if( err ){
				RHP_BUG("");
				goto error;
			}

			if( tmp_val > 255 ){
				cfg_eap_radius->rx_internal_domain_names_attr_type = 0;
				RHP_BUG("");
			}else{
				cfg_eap_radius->rx_internal_domain_names_attr_type = (u8)tmp_val;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"internal_rt_maps_v4_attr_type") ){

			tmp_val = 0;
			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"value"),RHP_XML_DT_INT,
							&tmp_val,&ret_len,NULL,0);
			if( err ){
				RHP_BUG("");
				goto error;
			}

			if( tmp_val > 255 ){
				cfg_eap_radius->rx_internal_rt_maps_v4_attr_type = 0;
				RHP_BUG("");
			}else{
				cfg_eap_radius->rx_internal_rt_maps_v4_attr_type = (u8)tmp_val;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"internal_rt_maps_v6_attr_type") ){

			tmp_val = 0;
			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"value"),RHP_XML_DT_INT,
							&tmp_val,&ret_len,NULL,0);
			if( err ){
				RHP_BUG("");
				goto error;
			}

			if( tmp_val > 255 ){
				cfg_eap_radius->rx_internal_rt_maps_v6_attr_type = 0;
				RHP_BUG("");
			}else{
				cfg_eap_radius->rx_internal_rt_maps_v6_attr_type = (u8)tmp_val;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"internal_gw_v4_attr_type") ){

			tmp_val = 0;
			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"value"),RHP_XML_DT_INT,
							&tmp_val,&ret_len,NULL,0);
			if( err ){
				RHP_BUG("");
				goto error;
			}

			if( tmp_val > 255 ){
				cfg_eap_radius->rx_internal_gw_v4_attr_type = 0;
				RHP_BUG("");
			}else{
				cfg_eap_radius->rx_internal_gw_v4_attr_type = (u8)tmp_val;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"internal_gw_v6_attr_type") ){

			tmp_val = 0;
			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"value"),RHP_XML_DT_INT,
							&tmp_val,&ret_len,NULL,0);
			if( err ){
				RHP_BUG("");
				goto error;
			}

			if( tmp_val > 255 ){
				cfg_eap_radius->rx_internal_gw_v6_attr_type = 0;
				RHP_BUG("");
			}else{
				cfg_eap_radius->rx_internal_gw_v6_attr_type = (u8)tmp_val;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"internal_ipv4_attr_type") ){

			tmp_val = 0;
			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"value"),RHP_XML_DT_INT,
							&tmp_val,&ret_len,NULL,0);
			if( err ){
				RHP_BUG("");
				goto error;
			}

			if( tmp_val > 255 ){
				cfg_eap_radius->rx_internal_addr_ipv4 = 0;
				RHP_BUG("");
			}else{
				cfg_eap_radius->rx_internal_addr_ipv4 = (u8)tmp_val;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"internal_ipv6_attr_type") ){

			tmp_val = 0;
			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"value"),RHP_XML_DT_INT,
							&tmp_val,&ret_len,NULL,0);
			if( err ){
				RHP_BUG("");
				goto error;
			}

			if( tmp_val > 255 ){
				cfg_eap_radius->rx_internal_addr_ipv6 = 0;
				RHP_BUG("");
			}else{
				cfg_eap_radius->rx_internal_addr_ipv6 = (u8)tmp_val;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"common_attr_type") ){

			tmp_val = 0;
			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"value"),RHP_XML_DT_INT,
							&tmp_val,&ret_len,NULL,0);
			if( err ){
				RHP_BUG("");
				goto error;
			}

			if( tmp_val > 255 ){
				cfg_eap_radius->rx_common_priv_attr = 0;
				RHP_BUG("");
			}else{
				cfg_eap_radius->rx_common_priv_attr = (u8)tmp_val;
			}
		}

	}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"type"),(xmlChar*)"setting") ){

		if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"retransmit_interval") ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"value"),RHP_XML_DT_INT,
							&(cfg_eap_radius->retransmit_interval),&ret_len,NULL,0);
			if( err ){
				RHP_BUG("");
				goto error;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"retransmit_times") ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"value"),RHP_XML_DT_INT,
							&(cfg_eap_radius->retransmit_times),&ret_len,NULL,0);
			if( err ){
				RHP_BUG("");
				goto error;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"max_sessions") ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"value"),RHP_XML_DT_INT,
							&(cfg_eap_radius->max_sessions),&ret_len,NULL,0);
			if( err ){
				RHP_BUG("");
				goto error;
			}
		}
	}

  RHP_TRC(0,RHPTRCID_GCFG_PARSE_EAP_RADIUS_SETTING_RTRN,"xx",node,cfg_eap_radius);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_GCFG_PARSE_EAP_RADIUS_SETTING_ERR,"xxE",node,cfg_eap_radius,err);
	return err;
}

int rhp_gcfg_parse_eap_radius(xmlNodePtr node,rhp_eap_radius_gcfg* cfg_eap_radius)
{
	int err = -EINVAL;
	int ret_len, flag;

  RHP_TRC(0,RHPTRCID_GCFG_PARSE_EAP_RADIUS,"xx",node,cfg_eap_radius);

  flag = 0;
  rhp_xml_check_enable(node,(xmlChar*)"enabled",&flag);
  cfg_eap_radius->enabled = flag;

  if( cfg_eap_radius->enabled ){

		if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"address_type"),
					(xmlChar*)"ipv4") ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"server_address"),
							RHP_XML_DT_IPV4,&(cfg_eap_radius->server_addr_port.addr.v4),&ret_len,NULL,0);
			if( err == -ENOENT ){
				err = 0;
			}else if(err){
				RHP_BUG("");
				goto error;
			}else{
				cfg_eap_radius->server_addr_port.addr_family = AF_INET;
			}

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"source_address"),
							RHP_XML_DT_IPV4,&(cfg_eap_radius->nas_addr.addr.v4),&ret_len,NULL,0);
			if( err == -ENOENT ){
				err = 0;
			}else if(err){
				RHP_BUG("");
				goto error;
			}else{
				cfg_eap_radius->nas_addr.addr_family = AF_INET;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"address_type"),
								(xmlChar*)"ipv6") ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"server_address"),
							RHP_XML_DT_IPV6,&(cfg_eap_radius->server_addr_port),&ret_len,NULL,0);
			if( err == -ENOENT ){
				err = 0;
			}else if(err){
				RHP_BUG("");
				goto error;
			}else{
				cfg_eap_radius->server_addr_port.addr_family = AF_INET6;
			}

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"source_address"),
							RHP_XML_DT_IPV6,&(cfg_eap_radius->nas_addr),&ret_len,NULL,0);
			if( err == -ENOENT ){
				err = 0;
			}else if(err){
				RHP_BUG("");
				goto error;
			}else{
				cfg_eap_radius->nas_addr.addr_family = AF_INET6;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"address_type"),
								(xmlChar*)"fqdn") ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"server_address"),
					RHP_XML_DT_STRING,&(cfg_eap_radius->server_fqdn),&ret_len,NULL,0);
			if( err == -ENOENT ){
				err = 0;
			}else if(err){
				RHP_BUG("");
				goto error;
			}else{
				cfg_eap_radius->server_addr_port.addr_family = AF_UNSPEC;
			}

			if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"source_ip_version"),
								(xmlChar*)"ipv4") ){

				err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"source_address"),
								RHP_XML_DT_IPV4,&(cfg_eap_radius->nas_addr.addr.v4),&ret_len,NULL,0);
				if( err == -ENOENT ){
					err = 0;
				}else if(err){
					RHP_BUG("");
					goto error;
				}else{
					cfg_eap_radius->nas_addr.addr_family = AF_INET;
				}

			}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"source_ip_version"),
									(xmlChar*)"ipv6") ){

				err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"source_address"),
								RHP_XML_DT_IPV6,&(cfg_eap_radius->nas_addr),&ret_len,NULL,0);
				if( err == -ENOENT ){
					err = 0;
				}else if(err){
					RHP_BUG("");
					goto error;
				}else{
					cfg_eap_radius->nas_addr.addr_family = AF_INET6;
				}

			}else{

				cfg_eap_radius->nas_addr.addr_family = AF_UNSPEC;
			}

		}else{

			cfg_eap_radius->server_addr_port.addr_family = AF_UNSPEC;
		}

		{
			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"server_port"),
					RHP_XML_DT_PORT,&(cfg_eap_radius->server_addr_port.port),&ret_len,NULL,0);
			if( err == -ENOENT ){
				cfg_eap_radius->server_addr_port.port = htons(RHP_PROTO_PORT_RADIUS);
			}else if(err){
				RHP_BUG("");
				goto error;
			}
		}

		rhp_ip_addr_dump("cfg_eap_radius->server_addr_port",&(cfg_eap_radius->server_addr_port));
		rhp_ip_addr_dump("cfg_eap_radius->nas_addr",&(cfg_eap_radius->nas_addr));


		if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"server_secondary_address_type"),
					(xmlChar*)"ipv4") ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"server_secondary_address"),
							RHP_XML_DT_IPV4,&(cfg_eap_radius->server_secondary_addr_port.addr.v4),&ret_len,NULL,0);
			if( err == -ENOENT ){
				err = 0;
			}else if(err){
				RHP_BUG("");
				goto error;
			}else{
				cfg_eap_radius->server_secondary_addr_port.addr_family = AF_INET;
			}

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"source_secondary_address"),
							RHP_XML_DT_IPV4,&(cfg_eap_radius->nas_secondary_addr.addr.v4),&ret_len,NULL,0);
			if( err == -ENOENT ){
				err = 0;
			}else if(err){
				RHP_BUG("");
				goto error;
			}else{
				cfg_eap_radius->nas_secondary_addr.addr_family = AF_INET;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"server_secondary_address_type"),
								(xmlChar*)"ipv6") ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"server_secondary_address"),
							RHP_XML_DT_IPV6,&(cfg_eap_radius->server_secondary_addr_port),&ret_len,NULL,0);
			if( err == -ENOENT ){
				err = 0;
			}else if(err){
				RHP_BUG("");
				goto error;
			}else{
				cfg_eap_radius->server_secondary_addr_port.addr_family = AF_INET6;
			}

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"source_secondary_address"),
							RHP_XML_DT_IPV6,&(cfg_eap_radius->nas_secondary_addr),&ret_len,NULL,0);
			if( err == -ENOENT ){
				err = 0;
			}else if(err){
				RHP_BUG("");
				goto error;
			}else{
				cfg_eap_radius->nas_secondary_addr.addr_family = AF_INET6;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"server_secondary_address_type"),
								(xmlChar*)"fqdn") ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"server_secondary_address"),
					RHP_XML_DT_STRING,&(cfg_eap_radius->server_secondary_fqdn),&ret_len,NULL,0);
			if( err == -ENOENT ){
				err = 0;
			}else if(err){
				RHP_BUG("");
				goto error;
			}else{
				cfg_eap_radius->server_secondary_addr_port.addr_family = AF_UNSPEC;
			}

			if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"source_secondary_ip_version"),
								(xmlChar*)"ipv4") ){

				err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"source_secondary_address"),
								RHP_XML_DT_IPV4,&(cfg_eap_radius->nas_secondary_addr.addr.v4),&ret_len,NULL,0);
				if( err == -ENOENT ){
					err = 0;
				}else if(err){
					RHP_BUG("");
					goto error;
				}else{
					cfg_eap_radius->nas_secondary_addr.addr_family = AF_INET;
				}

			}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"source_secondary_ip_version"),
									(xmlChar*)"ipv6") ){

				err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"source_secondary_address"),
								RHP_XML_DT_IPV6,&(cfg_eap_radius->nas_secondary_addr),&ret_len,NULL,0);
				if( err == -ENOENT ){
					err = 0;
				}else if(err){
					RHP_BUG("");
					goto error;
				}else{
					cfg_eap_radius->nas_secondary_addr.addr_family = AF_INET6;
				}

			}else{

				cfg_eap_radius->nas_secondary_addr.addr_family = AF_UNSPEC;
			}

		}else{

			cfg_eap_radius->server_secondary_addr_port.addr_family = AF_UNSPEC;
		}

		{
			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"server_secondary_port"),
					RHP_XML_DT_PORT,&(cfg_eap_radius->server_secondary_addr_port.port),&ret_len,NULL,0);
			if( err == -ENOENT ){
				cfg_eap_radius->server_secondary_addr_port.port = htons(RHP_PROTO_PORT_RADIUS);
			}else if(err){
				RHP_BUG("");
				goto error;
			}
		}

		rhp_ip_addr_dump("cfg_eap_radius->server_secondary_addr_port",&(cfg_eap_radius->server_secondary_addr_port));
		rhp_ip_addr_dump("cfg_eap_radius->nas_secondary_addr",&(cfg_eap_radius->nas_secondary_addr));



		err = rhp_xml_enum_tags(node,(xmlChar*)"radius_setting",
						_rhp_gcfg_parse_eap_radius_setting,(void*)cfg_eap_radius,1);
		if( err && err != -ENOENT ){
			RHP_BUG("");
			goto error;
		}
  }

  if( cfg_eap_radius->enabled &&
  		cfg_eap_radius->server_addr_port.addr_family == AF_UNSPEC &&
  		cfg_eap_radius->server_fqdn == NULL ){

  	RHP_BUG("%d, %d, %s",cfg_eap_radius->enabled,cfg_eap_radius->server_addr_port.addr_family,cfg_eap_radius->server_fqdn);

  	cfg_eap_radius->enabled = 0;
  }

  RHP_TRC(0,RHPTRCID_GCFG_PARSE_EAP_RADIUS_RTRN,"xx",node,cfg_eap_radius);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_GCFG_PARSE_EAP_RADIUS_ERR,"xxE",node,cfg_eap_radius,err);
  return err;
}


static int _rhp_gcfg_parse_radius_acct_setting(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
	rhp_radius_acct_gcfg* cfg_radius_acct = (rhp_radius_acct_gcfg*)ctx;
	int ret_len, flag;

  RHP_TRC(0,RHPTRCID_GCFG_PARSE_RADIUS_ACCT_SETTING,"xx",node,cfg_radius_acct);

	if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"type"),(xmlChar*)"sending_attribute") ){

		if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"NAS-Identifier") ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"value"),RHP_XML_DT_STRING,
					&(cfg_radius_acct->nas_id),&ret_len,NULL,0);
			if( err ){
				RHP_BUG("");
				goto error;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"Connect-Info") ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"value"),RHP_XML_DT_STRING,
					&(cfg_radius_acct->connect_info),&ret_len,NULL,0);
			if( err ){
				RHP_BUG("");
				goto error;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"NAS-Identifier-IKEv2-ID") ){

			flag = 0;
			rhp_xml_check_enable(node,(xmlChar*)"value",(int*)&flag);
			cfg_radius_acct->tx_nas_id_as_ikev2_id_enabled = flag;
		}

	}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"type"),(xmlChar*)"setting") ){

		if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"retransmit_interval") ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"value"),RHP_XML_DT_INT,
							&(cfg_radius_acct->retransmit_interval),&ret_len,NULL,0);
			if( err ){
				RHP_BUG("");
				goto error;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),(xmlChar*)"retransmit_times") ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"value"),RHP_XML_DT_INT,
							&(cfg_radius_acct->retransmit_times),&ret_len,NULL,0);
			if( err ){
				RHP_BUG("");
				goto error;
			}
		}
	}

  RHP_TRC(0,RHPTRCID_GCFG_PARSE_RADIUS_ACCT_SETTING_RTRN,"xx",node,cfg_radius_acct);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_GCFG_PARSE_RADIUS_ACCT_SETTING_ERR,"xxE",node,cfg_radius_acct,err);
	return err;
}

int rhp_gcfg_parse_radius_acct(xmlNodePtr node,rhp_radius_acct_gcfg* cfg_radius_acct)
{
	int err = -EINVAL;
	int ret_len, flag;

  RHP_TRC(0,RHPTRCID_GCFG_PARSE_RADIUS_ACCT,"xx",node,cfg_radius_acct);

  flag = 0;
  rhp_xml_check_enable(node,(xmlChar*)"enabled",&flag);
  cfg_radius_acct->enabled = flag;

  if( cfg_radius_acct->enabled ){

		if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"address_type"),
					(xmlChar*)"ipv4") ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"server_address"),
							RHP_XML_DT_IPV4,&(cfg_radius_acct->server_addr_port.addr.v4),&ret_len,NULL,0);
			if( err == -ENOENT ){
				err = 0;
			}else if(err){
				RHP_BUG("");
				goto error;
			}else{
				cfg_radius_acct->server_addr_port.addr_family = AF_INET;
			}

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"source_address"),
							RHP_XML_DT_IPV4,&(cfg_radius_acct->nas_addr.addr.v4),&ret_len,NULL,0);
			if( err == -ENOENT ){
				err = 0;
			}else if(err){
				RHP_BUG("");
				goto error;
			}else{
				cfg_radius_acct->nas_addr.addr_family = AF_INET;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"address_type"),
								(xmlChar*)"ipv6") ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"server_address"),
							RHP_XML_DT_IPV6,&(cfg_radius_acct->server_addr_port),&ret_len,NULL,0);
			if( err == -ENOENT ){
				err = 0;
			}else if(err){
				RHP_BUG("");
				goto error;
			}else{
				cfg_radius_acct->server_addr_port.addr_family = AF_INET6;
			}

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"source_address"),
							RHP_XML_DT_IPV6,&(cfg_radius_acct->nas_addr),&ret_len,NULL,0);
			if( err == -ENOENT ){
				err = 0;
			}else if(err){
				RHP_BUG("");
				goto error;
			}else{
				cfg_radius_acct->nas_addr.addr_family = AF_INET6;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"address_type"),
								(xmlChar*)"fqdn") ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"server_address"),
					RHP_XML_DT_STRING,&(cfg_radius_acct->server_fqdn),&ret_len,NULL,0);
			if( err == -ENOENT ){
				err = 0;
			}else if(err){
				RHP_BUG("");
				goto error;
			}else{
				cfg_radius_acct->server_addr_port.addr_family = AF_UNSPEC;
			}

			if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"source_ip_version"),
								(xmlChar*)"ipv4") ){

				err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"source_address"),
								RHP_XML_DT_IPV4,&(cfg_radius_acct->nas_addr.addr.v4),&ret_len,NULL,0);
				if( err == -ENOENT ){
					err = 0;
				}else if(err){
					RHP_BUG("");
					goto error;
				}else{
					cfg_radius_acct->nas_addr.addr_family = AF_INET;
				}

			}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"source_ip_version"),
									(xmlChar*)"ipv6") ){

				err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"source_address"),
								RHP_XML_DT_IPV6,&(cfg_radius_acct->nas_addr),&ret_len,NULL,0);
				if( err == -ENOENT ){
					err = 0;
				}else if(err){
					RHP_BUG("");
					goto error;
				}else{
					cfg_radius_acct->nas_addr.addr_family = AF_INET6;
				}

			}else{

				cfg_radius_acct->nas_addr.addr_family = AF_UNSPEC;
			}

		}else{

			cfg_radius_acct->server_addr_port.addr_family = AF_UNSPEC;
		}

		{
			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"server_port"),
					RHP_XML_DT_PORT,&(cfg_radius_acct->server_addr_port.port),&ret_len,NULL,0);
			if( err == -ENOENT ){
				cfg_radius_acct->server_addr_port.port = htons(RHP_PROTO_PORT_RADIUS_ACCT);
			}else if(err){
				RHP_BUG("");
				goto error;
			}
		}

		rhp_ip_addr_dump("cfg_radius_acct->server_addr_port",&(cfg_radius_acct->server_addr_port));
		rhp_ip_addr_dump("cfg_radius_acct->nas_addr",&(cfg_radius_acct->nas_addr));


		if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"server_secondary_address_type"),
					(xmlChar*)"ipv4") ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"server_secondary_address"),
							RHP_XML_DT_IPV4,&(cfg_radius_acct->server_secondary_addr_port.addr.v4),&ret_len,NULL,0);
			if( err == -ENOENT ){
				err = 0;
			}else if(err){
				RHP_BUG("");
				goto error;
			}else{
				cfg_radius_acct->server_secondary_addr_port.addr_family = AF_INET;
			}

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"source_secondary_address"),
							RHP_XML_DT_IPV4,&(cfg_radius_acct->nas_secondary_addr.addr.v4),&ret_len,NULL,0);
			if( err == -ENOENT ){
				err = 0;
			}else if(err){
				RHP_BUG("");
				goto error;
			}else{
				cfg_radius_acct->nas_secondary_addr.addr_family = AF_INET;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"server_secondary_address_type"),
								(xmlChar*)"ipv6") ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"server_secondary_address"),
							RHP_XML_DT_IPV6,&(cfg_radius_acct->server_secondary_addr_port),&ret_len,NULL,0);
			if( err == -ENOENT ){
				err = 0;
			}else if(err){
				RHP_BUG("");
				goto error;
			}else{
				cfg_radius_acct->server_secondary_addr_port.addr_family = AF_INET6;
			}

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"source_secondary_address"),
							RHP_XML_DT_IPV6,&(cfg_radius_acct->nas_secondary_addr),&ret_len,NULL,0);
			if( err == -ENOENT ){
				err = 0;
			}else if(err){
				RHP_BUG("");
				goto error;
			}else{
				cfg_radius_acct->nas_secondary_addr.addr_family = AF_INET6;
			}

		}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"server_secondary_address_type"),
								(xmlChar*)"fqdn") ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"server_secondary_address"),
					RHP_XML_DT_STRING,&(cfg_radius_acct->server_secondary_fqdn),&ret_len,NULL,0);
			if( err == -ENOENT ){
				err = 0;
			}else if(err){
				RHP_BUG("");
				goto error;
			}else{
				cfg_radius_acct->server_secondary_addr_port.addr_family = AF_UNSPEC;
			}

			if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"source_secondary_ip_version"),
								(xmlChar*)"ipv4") ){

				err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"source_secondary_address"),
								RHP_XML_DT_IPV4,&(cfg_radius_acct->nas_secondary_addr.addr.v4),&ret_len,NULL,0);
				if( err == -ENOENT ){
					err = 0;
				}else if(err){
					RHP_BUG("");
					goto error;
				}else{
					cfg_radius_acct->nas_secondary_addr.addr_family = AF_INET;
				}

			}else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"source_secondary_ip_version"),
									(xmlChar*)"ipv6") ){

				err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"source_secondary_address"),
								RHP_XML_DT_IPV6,&(cfg_radius_acct->nas_secondary_addr),&ret_len,NULL,0);
				if( err == -ENOENT ){
					err = 0;
				}else if(err){
					RHP_BUG("");
					goto error;
				}else{
					cfg_radius_acct->nas_secondary_addr.addr_family = AF_INET6;
				}

			}else{

				cfg_radius_acct->nas_secondary_addr.addr_family = AF_UNSPEC;
			}

		}else{

			cfg_radius_acct->server_secondary_addr_port.addr_family = AF_UNSPEC;
		}

		{
			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"server_secondary_port"),
					RHP_XML_DT_PORT,&(cfg_radius_acct->server_secondary_addr_port.port),&ret_len,NULL,0);
			if( err == -ENOENT ){
				cfg_radius_acct->server_secondary_addr_port.port = htons(RHP_PROTO_PORT_RADIUS_ACCT);
			}else if(err){
				RHP_BUG("");
				goto error;
			}
		}

		rhp_ip_addr_dump("cfg_radius_acct->server_secondary_addr_port",&(cfg_radius_acct->server_secondary_addr_port));
		rhp_ip_addr_dump("cfg_radius_acct->nas_secondary_addr",&(cfg_radius_acct->nas_secondary_addr));


		err = rhp_xml_enum_tags(node,(xmlChar*)"radius_setting",
						_rhp_gcfg_parse_radius_acct_setting,(void*)cfg_radius_acct,1);
		if( err && err != -ENOENT ){
			RHP_BUG("");
			goto error;
		}
  }


  if( cfg_radius_acct->enabled &&
  		cfg_radius_acct->server_addr_port.addr_family == AF_UNSPEC &&
  		cfg_radius_acct->server_fqdn == NULL ){

  	RHP_BUG("%d, %d, %s",cfg_radius_acct->enabled,cfg_radius_acct->server_addr_port.addr_family,cfg_radius_acct->server_fqdn);

  	cfg_radius_acct->enabled = 0;
  }

  RHP_TRC(0,RHPTRCID_GCFG_PARSE_RADIUS_ACCT_RTRN,"xx",node,cfg_radius_acct);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_GCFG_PARSE_RADIUS_ACCT_ERR,"xxE",node,cfg_radius_acct,err);
  return err;
}


static int _rhp_gcfg_parse_eap_radius(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
	rhp_eap_radius_gcfg* cfg_radius_acct = rhp_gcfg_alloc_eap_radius();

	if( cfg_radius_acct ){

		err = rhp_gcfg_parse_eap_radius(node,cfg_radius_acct);
		if( err ){
			rhp_gcfg_free_eap_radius(cfg_radius_acct);
			return err;
		}

		rhp_gcfg_eap_radius = cfg_radius_acct;

	}else{
		RHP_BUG("");
		return -ENOMEM;
	}

	return 0;
}


static int _rhp_gcfg_parse_radius_acct(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
	rhp_radius_acct_gcfg* cfg_radius_acct = rhp_gcfg_alloc_radius_acct();

	if( cfg_radius_acct ){

		err = rhp_gcfg_parse_radius_acct(node,cfg_radius_acct);
		if( err ){
			rhp_gcfg_free_radius_acct(cfg_radius_acct);
			return err;
		}

		rhp_gcfg_radius_acct = cfg_radius_acct;

	}else{
		RHP_BUG("");
		return -ENOMEM;
	}

	return 0;
}


static int _rhp_cfg_parse_my_interface(xmlNodePtr node,void* ctx)
{
  rhp_vpn_realm* rlm = (rhp_vpn_realm*)ctx;
  rhp_cfg_if* cfg_if = NULL;
  rhp_cfg_if *cfg_if_p = NULL,*cfg_if_c;
  int ret_len;
  int i;

  cfg_if = (rhp_cfg_if*)_rhp_malloc(sizeof(rhp_cfg_if));
  if( cfg_if == NULL ){
  	RHP_BUG("");
    return -ENOMEM;
  }
  memset(cfg_if,0,sizeof(rhp_cfg_if));

  cfg_if->tag[0] = '#';
  cfg_if->tag[1] = 'C';
  cfg_if->tag[2] = 'F';
  cfg_if->tag[3] = 'I';

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),RHP_XML_DT_STRING,&(cfg_if->if_name),&ret_len,NULL,0) ){
  	RHP_BUG("");
    goto error;
  }

  if( ret_len > (RHP_IFNAMSIZ + 1) ){
  	RHP_BUG("");
    goto error;
  }

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"priority"),RHP_XML_DT_INT,&(cfg_if->priority),&ret_len,NULL,0) ){
    cfg_if->priority = INT_MAX;
  }

  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"advertising"),(xmlChar*)"enable") ){
    cfg_if->advertising = 1;
  }else{
    cfg_if->advertising = 0;
  }


  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,
  			(xmlChar*)"ip_version"),(xmlChar*)"ipv4") ){
    cfg_if->addr_family = AF_INET;
  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"ip_version"),
  						(xmlChar*)"ipv6") ){
    cfg_if->addr_family = AF_INET6;
  }else{
    cfg_if->addr_family = AF_UNSPEC; // IPv4 and/or IPv6...
  }


  {
  	int dst_nat_idx = 0;

		for( i = 0; i < RHP_MOBIKE_DST_NAT_ADDRS_NUM; i++ ){
			cfg_if->mobike_dnat_addr_v4[i].addr_family = AF_UNSPEC;
			cfg_if->mobike_dnat_addr_v6[i].addr_family = AF_UNSPEC;
		}

		if( !rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"dest_nat_addr_v4"),
					RHP_XML_DT_IPV4,
					&(cfg_if->mobike_dnat_addr_v4[dst_nat_idx].addr.v4),&ret_len,NULL,0) ){

			cfg_if->mobike_dnat_addr_v4[dst_nat_idx].addr_family = AF_INET;
			dst_nat_idx++;

			if( !rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"dest_nat_addr2_v4"),
						RHP_XML_DT_IPV4,
						&(cfg_if->mobike_dnat_addr_v4[dst_nat_idx].addr.v4),&ret_len,NULL,0) ){

				cfg_if->mobike_dnat_addr_v4[dst_nat_idx].addr_family = AF_INET;
				dst_nat_idx++;
			}
		}
		cfg_if->mobike_dnat_addrs_num_v4 = dst_nat_idx;


		dst_nat_idx = 0;
		if( !rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"dest_nat_addr_v6"),
				RHP_XML_DT_IPV6,
				&(cfg_if->mobike_dnat_addr_v6[dst_nat_idx]),&ret_len,NULL,0) ){

			cfg_if->mobike_dnat_addr_v6[dst_nat_idx].addr_family = AF_INET6;
			dst_nat_idx++;

			if( !rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"dest_nat_addr2_v6"),
						RHP_XML_DT_IPV6,
						&(cfg_if->mobike_dnat_addr_v6[dst_nat_idx]),&ret_len,NULL,0) ){

				cfg_if->mobike_dnat_addr_v6[dst_nat_idx].addr_family = AF_INET6;
				dst_nat_idx++;
			}
		}
		cfg_if->mobike_dnat_addrs_num_v6 = dst_nat_idx;
  }


  cfg_if_c = rlm->my_interfaces;
  while( cfg_if_c ){

    if( cfg_if_c->priority > cfg_if->priority ){
      break;
    }

    cfg_if_p = cfg_if_c;
    cfg_if_c = cfg_if_c->next;
  }

  if( cfg_if_p == NULL ){
  	cfg_if->next = rlm->my_interfaces;
  	rlm->my_interfaces = cfg_if;
  }else{
    cfg_if->next = cfg_if_p->next;
    cfg_if_p->next = cfg_if;
  }

  return 0;

error:
  if( cfg_if ){
    if( cfg_if->if_name ){
      _rhp_free(cfg_if->if_name);
    }
    _rhp_free(cfg_if);
  }
  return -EINVAL;
}


static int _rhp_cfg_parse_my_interfaces(xmlNodePtr node,void* ctx)
{
	rhp_vpn_realm* rlm = (rhp_vpn_realm*)ctx;

	if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"use_default_route"),(xmlChar*)"enable") ){
		rlm->my_interface_use_def_route = 1;
  }else{
  	rlm->my_interface_use_def_route = 0;
  }

	if( rlm->my_interface_use_def_route ){
    rlm->my_interfaces = NULL; // Later set based on route maps.
		return 0;
	}

  return rhp_xml_enum_tags(node,(xmlChar*)"my_interface",_rhp_cfg_parse_my_interface,ctx,1);
}


static int _rhp_cfg_parse_rlm_ikesa(xmlNodePtr node,void* ctx)
{
  rhp_vpn_realm* rlm = (rhp_vpn_realm*)ctx;
  int ret_len, flag;

  {
		rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"keep_alive_interval"),RHP_XML_DT_ULONG,&(rlm->ikesa.keep_alive_interval),&ret_len,NULL,0);

		if( rlm->ikesa.keep_alive_interval < RHP_CFG_KEEP_ALIVE_MIN_INTERVAL ){
			rlm->ikesa.keep_alive_interval = RHP_CFG_KEEP_ALIVE_MIN_INTERVAL;
		}
  }

  {
		rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"nat_t_keep_alive_interval"),RHP_XML_DT_ULONG,&(rlm->ikesa.nat_t_keep_alive_interval),&ret_len,NULL,0);

		if( rlm->ikesa.nat_t_keep_alive_interval &&
				rlm->ikesa.nat_t_keep_alive_interval < RHP_CFG_NAT_T_KEEP_ALIVE_MIN_INTERVAL ){
			rlm->ikesa.nat_t_keep_alive_interval = RHP_CFG_NAT_T_KEEP_ALIVE_MIN_INTERVAL;
		}
  }

  {
		rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"lifetime_soft"),RHP_XML_DT_ULONG,&(rlm->ikesa.lifetime_soft),&ret_len,NULL,0);
		rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"lifetime_hard"),RHP_XML_DT_ULONG,&(rlm->ikesa.lifetime_hard),&ret_len,NULL,0);

		if( rlm->ikesa.lifetime_soft < RHP_CFG_IKESA_LIFETIME_MIN ){
			rlm->ikesa.lifetime_soft = RHP_CFG_IKESA_LIFETIME_MIN;
		}

		if( (rlm->ikesa.lifetime_soft + RHP_CFG_LIFETIME_MIN_REKEY_DIFF) > rlm->ikesa.lifetime_hard ){
			rlm->ikesa.lifetime_hard = rlm->ikesa.lifetime_soft + RHP_CFG_LIFETIME_MIN_REKEY_DIFF;
		}
  }

  {
		rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"vpn_conn_lifetime"),RHP_XML_DT_ULONG,&(rlm->vpn_conn_lifetime),&ret_len,NULL,0);

		if( rlm->vpn_conn_lifetime &&
				rlm->vpn_conn_lifetime < RHP_CFG_VPN_CONN_LIFE_TIME_MIN ){
			rlm->vpn_conn_lifetime = RHP_CFG_VPN_CONN_LIFE_TIME_MIN;
		}
  }

  {
		rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"vpn_conn_idle_timeout"),RHP_XML_DT_ULONG,&(rlm->vpn_conn_idle_timeout),&ret_len,NULL,0);

		if( rlm->vpn_conn_idle_timeout &&
				rlm->vpn_conn_idle_timeout < RHP_CFG_VPN_CONN_IDLE_TIME_MIN ){
			rlm->vpn_conn_idle_timeout = RHP_CFG_VPN_CONN_IDLE_TIME_MIN;
		}
  }

  {
  	xmlChar* rmt_cfg_narrow_ts_i = rhp_xml_get_prop_static(node,(const xmlChar*)"remote_cfg_narrow_ts_i");

		if( rmt_cfg_narrow_ts_i ){

  		if( !strcmp((char*)rmt_cfg_narrow_ts_i,"enable") ){

				rlm->config_server.narrow_ts_i = RHP_IKEV2_CFG_NARROW_TS_I_ALL;

			}else if( !strcmp((char*)rmt_cfg_narrow_ts_i,"enable_for_non_rockhopper") ){

				rlm->config_server.narrow_ts_i = RHP_IKEV2_CFG_NARROW_TS_I_NON_ROCKHOPPER;

			}else if( !strcmp((char*)rmt_cfg_narrow_ts_i,"disable") ){

				rlm->config_server.narrow_ts_i = RHP_IKEV2_CFG_NARROW_TS_I_DONT;
			}
  	}


		rlm->config_server.internal_netmask.addr_family = AF_INET;
		rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"remote_cfg_internal_netmask_v4"),
				RHP_XML_DT_IPV4,&(rlm->config_server.internal_netmask.netmask.v4),&ret_len,NULL,0);
		rlm->config_server.internal_netmask.prefixlen = rhp_ipv4_netmask_to_prefixlen(rlm->config_server.internal_netmask.netmask.v4);


		rlm->config_server.internal_netmask_v6.addr_family = AF_INET6;
		rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"remote_cfg_internal_prefixlen_v6"),
				RHP_XML_DT_INT,&(rlm->config_server.internal_netmask_v6.prefixlen),&ret_len,NULL,0);
		rhp_ipv6_prefixlen_to_netmask(rlm->config_server.internal_netmask_v6.prefixlen,rlm->config_server.internal_netmask_v6.netmask.v6);


		rlm->config_server.wins_server_addr.addr_family = AF_INET;
		rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"remote_cfg_wins_server_v4"),
				RHP_XML_DT_IPV4,&(rlm->config_server.wins_server_addr.addr.v4),&ret_len,NULL,0);


		rlm->config_server.wins_server_addr_v6.addr_family = AF_INET6;
		rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"remote_cfg_wins_server_v6"),
				RHP_XML_DT_IPV6,&(rlm->config_server.wins_server_addr_v6),&ret_len,NULL,0);
  }

  rhp_xml_check_enable(node,(const xmlChar*)"responder_not_rekeying",&(rlm->ikesa.resp_not_rekeying));

  rhp_xml_check_enable(node,(const xmlChar*)"nat_t",&(rlm->ikesa.nat_t));

  rhp_xml_check_enable(node,(const xmlChar*)"use_nat_t_port",&(rlm->ikesa.use_nat_t_port));

  rhp_xml_check_enable(node,(const xmlChar*)"http_cert_lookup",&(rlm->my_auth.http_cert_lookup));

  rhp_xml_check_enable(node,(const xmlChar*)"send_ca_chains",&(rlm->my_auth.send_ca_chains));

  rhp_xml_check_enable(node,(const xmlChar*)"delete_ikesa_if_no_childsa_exists",&(rlm->ikesa.delete_no_childsa));

  rhp_xml_check_enable(node,(const xmlChar*)"send_realm_id",&(rlm->ikesa.send_realm_id));

  rhp_xml_check_enable(node,(const xmlChar*)"initiator_sends_responder_id",&(rlm->ikesa.send_responder_id));


  {
		rhp_xml_check_enable(node,(const xmlChar*)"mobike",&(rlm->mobike.enabled));

		rhp_xml_check_enable(node,(const xmlChar*)"mobike_resp_routability_check",&(rlm->mobike.resp_routability_check));

		rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"mobike_resp_keep_alive_interval"),RHP_XML_DT_ULONG,&(rlm->mobike.resp_ka_interval),&ret_len,NULL,0);
		if( rlm->mobike.resp_ka_interval < RHP_CFG_KEEP_ALIVE_MIN_INTERVAL ){
			rlm->mobike.resp_ka_interval = RHP_CFG_KEEP_ALIVE_MIN_INTERVAL;
		}

		rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"mobike_resp_null_auth_keep_alive_interval"),RHP_XML_DT_ULONG,&(rlm->mobike.resp_ka_interval_null_auth),&ret_len,NULL,0);
		if( rlm->mobike.resp_ka_interval_null_auth < RHP_CFG_KEEP_ALIVE_MIN_INTERVAL ){
			rlm->mobike.resp_ka_interval_null_auth = RHP_CFG_KEEP_ALIVE_MIN_INTERVAL;
		}


		rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"mobike_resp_keep_alive_retry_interval"),RHP_XML_DT_ULONG,&(rlm->mobike.resp_ka_retx_interval),&ret_len,NULL,0);
		if( rlm->mobike.resp_ka_retx_interval < (unsigned long)rhp_gcfg_ike_retry_init_interval ){
			rlm->mobike.resp_ka_retx_interval = (unsigned long)rhp_gcfg_ike_retry_init_interval;
		}

		rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"mobike_resp_keep_alive_max_retries"),RHP_XML_DT_ULONG,&(rlm->mobike.resp_ka_retx_retries),&ret_len,NULL,0);


		rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"mobike_init_hold_time"),RHP_XML_DT_ULONG,&(rlm->mobike.init_hold_time),&ret_len,NULL,0);

		rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"mobike_init_keep_alive_interval"),RHP_XML_DT_ULONG,&(rlm->mobike.init_hold_ka_interval),&ret_len,NULL,0);
		if( rlm->mobike.init_hold_ka_interval < RHP_CFG_KEEP_ALIVE_MIN_INTERVAL ){
			rlm->mobike.init_hold_ka_interval = RHP_CFG_KEEP_ALIVE_MIN_INTERVAL;
		}

		rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"mobike_init_keep_alive_max_retries"),RHP_XML_DT_ULONG,&(rlm->mobike.init_hold_ka_max_retries),&ret_len,NULL,0);


		rhp_xml_check_enable(node,(const xmlChar*)"mobike_init_cache_additional_address",&(rlm->mobike.init_cache_additional_addr));
  }


  {
  	flag = rlm->v1.dpd_enabled;
  	rhp_xml_check_enable(node,(const xmlChar*)"v1_dpd",&flag);
  	rlm->v1.dpd_enabled = flag;
  }

  return 0;
}


static int _rhp_cfg_parse_rlm_childsa(xmlNodePtr node,void* ctx)
{
  rhp_vpn_realm* rlm = (rhp_vpn_realm*)ctx;
  int ret_len;

  rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"lifetime_soft"),RHP_XML_DT_ULONG,&(rlm->childsa.lifetime_soft),&ret_len,NULL,0);
  rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"lifetime_hard"),RHP_XML_DT_ULONG,&(rlm->childsa.lifetime_hard),&ret_len,NULL,0);

  if( rlm->childsa.lifetime_soft < RHP_CFG_CHILDSA_LIFETIME_MIN ){
  	rlm->childsa.lifetime_soft = RHP_CFG_CHILDSA_LIFETIME_MIN;
  }

  if( (rlm->childsa.lifetime_soft + RHP_CFG_LIFETIME_MIN_REKEY_DIFF) > rlm->childsa.lifetime_hard ){
  	rlm->childsa.lifetime_hard = rlm->childsa.lifetime_soft + RHP_CFG_LIFETIME_MIN_REKEY_DIFF;
  }

  rhp_xml_check_enable(node,(xmlChar*)"pfs",&(rlm->childsa.pfs));

  {
  	rhp_xml_check_enable(node,(xmlChar*)"tfc_padding",&(rlm->childsa.tfc_padding));

  	rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"tfc_padding_max_size"),RHP_XML_DT_INT,&(rlm->childsa.tfc_padding_max_size),&ret_len,NULL,0);

  	if( rlm->childsa.tfc_padding_max_size < RHP_CFG_TFC_PADDING_MIN_SIZE ){
  		rlm->childsa.tfc_padding_max_size = RHP_CFG_TFC_PADDING_MIN_SIZE;
  	}
  }

  {
  	rhp_xml_check_enable(node,(xmlChar*)"dummy_traffic",&(rlm->childsa.dummy_traffic));

  	rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"dummy_traffic_rate_per_packets"),RHP_XML_DT_ULONG,&(rlm->childsa.dummy_traffic_rate_per_packets),&ret_len,NULL,0);

    if( rlm->childsa.dummy_traffic_rate_per_packets < 1 ){
    	rlm->childsa.dummy_traffic_rate_per_packets = 1;
    }

  	rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"dummy_traffic_interval"),RHP_XML_DT_ULONG,&(rlm->childsa.dummy_traffic_interval),&ret_len,NULL,0);

    if( rlm->childsa.dummy_traffic_interval < RHP_CFG_DUMMY_TRAFFIC_MIN_INTERVAL ){
    	rlm->childsa.dummy_traffic_interval = RHP_CFG_DUMMY_TRAFFIC_MIN_INTERVAL;
    }
  }

  rhp_xml_check_enable(node,(xmlChar*)"responder_not_rekeying",&(rlm->childsa.resp_not_rekeying));

  rhp_xml_check_enable(node,(xmlChar*)"apply_traffic_selector_to_eoip",&(rlm->childsa.apply_ts_to_eoip));
  rhp_xml_check_enable(node,(xmlChar*)"apply_traffic_selector_to_gre",&(rlm->childsa.apply_ts_to_gre));

  rhp_xml_check_enable(node,(xmlChar*)"anti_replay",&(rlm->childsa.anti_replay));

  rhp_xml_check_enable(node,(xmlChar*)"enable_udp_encapsulation_for_ipv6_after_rx",&(rlm->childsa.v6_enable_udp_encap_after_rx));

  rhp_xml_check_enable(node,(xmlChar*)"disable_v6_udp_encapsulation",&(rlm->childsa.v6_udp_encap_disabled));

	rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"anti_replay_win_size"),
			RHP_XML_DT_INT,&(rlm->childsa.anti_replay_win_size),&ret_len,NULL,0);

  rhp_xml_check_enable(node,(xmlChar*)"out_of_order_drop",&(rlm->childsa.out_of_order_drop));

  rhp_xml_check_enable(node,(xmlChar*)"adjust_path_mtu",&(rlm->childsa.exec_pmtud));

  rhp_xml_check_enable(node,(xmlChar*)"exact_match_ts",&(rlm->childsa.exact_match_ts));

  rhp_xml_check_enable(node,(xmlChar*)"dont_fwd_pkts_between_vpn_conns",&(rlm->childsa.dont_fwd_pkts_between_vpn_conns));

  rhp_xml_check_enable(node,(xmlChar*)"gre_auto_generate_ts",&(rlm->childsa.gre_auto_gen_ts));
  rhp_xml_check_enable(node,(xmlChar*)"gre_ts_allow_nat_reflexive_addr",&(rlm->childsa.gre_ts_allow_nat_reflexive_addr));

  rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"v6_aux_link_local_addr"),
				RHP_XML_DT_IPV6,&(rlm->childsa.v6_aux_lladdr),&ret_len,NULL,0);

  return 0;
}


static int _rhp_cfg_parse_config_server_internal_address_pool(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
  rhp_vpn_realm* rlm = (rhp_vpn_realm*)ctx;
	rhp_internal_address_pool* addr_pool = NULL;
  int ret_len;

	addr_pool = (rhp_internal_address_pool*)_rhp_malloc(sizeof(rhp_internal_address_pool));
	if( addr_pool == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memset(addr_pool,0,sizeof(rhp_internal_address_pool));

	addr_pool->tag[0] = '#';
	addr_pool->tag[1] = 'I';
	addr_pool->tag[2] = 'A';
	addr_pool->tag[3] = 'P';


  if( rhp_xml_get_prop_static(node,(const xmlChar*)"subnet_address_v4") ){

    rhp_ip_addr* ret_ipv4;

	  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"subnet_address_v4"),
	  			RHP_XML_DT_IPV4_SUBNET,&ret_ipv4,&ret_len,NULL,0) ){
	  	RHP_BUG("");
	    goto error;
	  }


		addr_pool->start.addr_family = AF_INET;
		addr_pool->end.addr_family = AF_INET;

		rhp_ipv4_subnet_addr_range(ret_ipv4->addr.v4,
				ret_ipv4->netmask.v4,&(addr_pool->start.addr.v4),&(addr_pool->end.addr.v4));


		addr_pool->netmask.addr_family = AF_INET;
		addr_pool->netmask.addr.v4 = ret_ipv4->netmask.v4;
		addr_pool->netmask.prefixlen = ret_ipv4->prefixlen;

		addr_pool->last.addr_family = AF_INET;
		addr_pool->last.addr.v4 = ret_ipv4->addr.v4;

		_rhp_free(ret_ipv4);

	}else if( rhp_xml_get_prop_static(node,(const xmlChar*)"start_address_v4") &&
						rhp_xml_get_prop_static(node,(const xmlChar*)"end_address_v4")  ){

    u32 ret_start_ipv4,ret_end_ipv4;

	  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"start_address_v4"),
	  			RHP_XML_DT_IPV4,&ret_start_ipv4,&ret_len,NULL,0) ){
	  	RHP_BUG("");
	    goto error;
	  }

	  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"end_address_v4"),
	  			RHP_XML_DT_IPV4,&ret_end_ipv4,&ret_len,NULL,0) ){
	  	RHP_BUG("");
	    goto error;
	  }

		addr_pool->start.addr_family = AF_INET;
		addr_pool->start.addr.v4 = ret_start_ipv4;

		addr_pool->end.addr_family = AF_INET;
		addr_pool->end.addr.v4 = ret_end_ipv4;

		if( rhp_ip_addr_lt_ip(&(addr_pool->start),&(addr_pool->end)) ){
			err = -EINVAL;
		  RHP_LOG_E(RHP_LOG_SRC_CFG,rlm->id,RHP_LOG_ID_REMOTE_CFG_SVR_ADDR_POOL_BAD_END_ADDR,"AA",&(addr_pool->start),&(addr_pool->end));
			RHP_BUG("");
			goto error;
		}

		addr_pool->last.addr_family = AF_INET;
		addr_pool->last.addr.v4 = ntohl(ret_start_ipv4) - 1;
		addr_pool->last.addr.v4 = htonl(addr_pool->last.addr.v4);

	}else if( rhp_xml_get_prop_static(node,(const xmlChar*)"subnet_address_v6") ){

	    rhp_ip_addr* ret_ipv6;

		  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"subnet_address_v6"),
		  			RHP_XML_DT_IPV6_SUBNET,&ret_ipv6,&ret_len,NULL,0) ){
		  	RHP_BUG("");
		    goto error;
		  }

		  if( ret_ipv6->prefixlen < 64 ){
				err = -EINVAL;
			  RHP_LOG_E(RHP_LOG_SRC_CFG,rlm->id,RHP_LOG_ID_REMOTE_CFG_SVR_ADDR_POOL_BAD_PREFIX_LEN,"A",&ret_ipv6);
				RHP_BUG("");
				goto error;
		  }

		  rhp_ipv6_subnet_addr_range(ret_ipv6->addr.v6,ret_ipv6->prefixlen,
		  		addr_pool->start.addr.v6,addr_pool->end.addr.v6);

			addr_pool->start.addr_family = AF_INET6;
			addr_pool->end.addr_family = AF_INET6;

			addr_pool->netmask.addr_family = AF_INET6;
			memcpy(addr_pool->netmask.addr.v6,ret_ipv6->netmask.v6,16);
			addr_pool->netmask.prefixlen = ret_ipv6->prefixlen;

			addr_pool->last.addr_family = AF_INET6;
			memcpy(addr_pool->last.addr.v6,ret_ipv6->addr.v6,16);

			_rhp_free(ret_ipv6);

	}else if( rhp_xml_get_prop_static(node,(const xmlChar*)"start_address_v6") &&
						rhp_xml_get_prop_static(node,(const xmlChar*)"end_address_v6")  ){

		rhp_ip_addr ret_start_ipv6,ret_end_ipv6;
		u64 s,e;

		memset(&ret_start_ipv6,0,sizeof(rhp_ip_addr));
		memset(&ret_end_ipv6,0,sizeof(rhp_ip_addr));

	  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"start_address_v6"),
	  			RHP_XML_DT_IPV6,&ret_start_ipv6,&ret_len,NULL,0) ){
	  	RHP_BUG("");
	    goto error;
	  }

	  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"end_address_v6"),
	  			RHP_XML_DT_IPV6,&ret_end_ipv6,&ret_len,NULL,0) ){
	  	RHP_BUG("");
	    goto error;
	  }

		memcpy(&(addr_pool->start),&ret_start_ipv6,sizeof(rhp_ip_addr));
		s = _rhp_ntohll(((u64*)addr_pool->start.addr.v6)[1]);
		memcpy(&(addr_pool->end),&ret_end_ipv6,sizeof(rhp_ip_addr));
		e = _rhp_ntohll(((u64*)addr_pool->end.addr.v6)[1]);

		if( s > e ||
				rhp_ip_addr_lt_ip(&(addr_pool->start),&(addr_pool->end)) ){
			err = -EINVAL;
		  RHP_LOG_E(RHP_LOG_SRC_CFG,rlm->id,RHP_LOG_ID_REMOTE_CFG_SVR_ADDR_POOL_BAD_END_ADDR,"AA",&(addr_pool->start),&(addr_pool->end));
			RHP_BUG("");
			goto error;
		}

		addr_pool->last.addr_family = AF_INET6;
		memcpy(addr_pool->last.addr.v6,ret_start_ipv6.addr.v6,16);
		((u64*)addr_pool->last.addr.v6)[1] = _rhp_htonll(s - 1);

	}else{
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}


  {
  	rhp_internal_address_pool* addr_pool_tail;

  	if( addr_pool->start.addr_family == AF_INET ){
  		addr_pool_tail = rlm->config_server.addr_pools;
  	}else if( addr_pool->start.addr_family == AF_INET6 ){
  		addr_pool_tail = rlm->config_server.addr_pools_v6;
  	}else{
  		RHP_BUG("");
  		err = -EINVAL;
  		goto error;
  	}

  	while( addr_pool_tail ){

  		if( addr_pool_tail->next == NULL ){
  			break;
  		}

  		addr_pool_tail = addr_pool_tail->next;
  	}

  	if( addr_pool_tail ){

  		addr_pool_tail->next = addr_pool;

  	}else{

	  	if( addr_pool->start.addr_family == AF_INET ){
	  		rlm->config_server.addr_pools = addr_pool;
	  	}else if( addr_pool->start.addr_family == AF_INET6 ){
	  		rlm->config_server.addr_pools_v6 = addr_pool;
	  	}
		}
	}

  return 0;

error:
	if( addr_pool ){
		_rhp_free(addr_pool);
	}
	return err;
}


static int _rhp_cfg_parse_config_server_internal_peer(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
  rhp_vpn_realm* rlm = (rhp_vpn_realm*)ctx;
  rhp_internal_peer_address* peer_addr = NULL;
  rhp_ip_addr *ret_ipv4,*ret_ipv6;
  int ret_len;

  peer_addr = (rhp_internal_peer_address*)_rhp_malloc(sizeof(rhp_internal_peer_address));
	if( peer_addr == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memset(peer_addr,0,sizeof(rhp_internal_peer_address));

	peer_addr->tag[0] = '#';
	peer_addr->tag[1] = 'I';
	peer_addr->tag[2] = 'P';
	peer_addr->tag[3] = 'A';


  if( rhp_cfg_parse_ikev2_id(node,(const xmlChar*)"id_type",(const xmlChar*)"id",
  			&(peer_addr->peer_id)) ){
    RHP_BUG("");
    goto error;
  }

  if( peer_addr->peer_id.type != RHP_PROTO_IKE_ID_FQDN &&
  		peer_addr->peer_id.type != RHP_PROTO_IKE_ID_RFC822_ADDR &&
  		peer_addr->peer_id.type != RHP_PROTO_IKE_ID_DER_ASN1_DN ){
    RHP_BUG("");
    goto error;
  }

  {
		err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"internal_address_v4"),
						RHP_XML_DT_IPV4_SUBNET,&ret_ipv4,&ret_len,NULL,0);
		if( !err ){

			memcpy(&(peer_addr->peer_address),ret_ipv4,sizeof(rhp_ip_addr));

			if( rlm->config_server.peer_addrs ){
				peer_addr->next = rlm->config_server.peer_addrs;
				rlm->config_server.peer_addrs = peer_addr;
			}else{
				rlm->config_server.peer_addrs = peer_addr;
			}

			_rhp_free(ret_ipv4);

		}else if( err == -ENOENT ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"internal_address_v6"),
							RHP_XML_DT_IPV6_SUBNET,&ret_ipv6,&ret_len,NULL,0);
			if( err ){
				RHP_BUG("");
				goto error;
			}

			memcpy(&(peer_addr->peer_address),ret_ipv6,sizeof(rhp_ip_addr));

			if( rlm->config_server.peer_addrs_v6 ){
				peer_addr->next = rlm->config_server.peer_addrs_v6;
				rlm->config_server.peer_addrs_v6 = peer_addr;
			}else{
				rlm->config_server.peer_addrs_v6 = peer_addr;
			}

			_rhp_free(ret_ipv6);

		}else{
			RHP_BUG("%d",err);
			goto error;
		}
  }

	return 0;

error:
	if( peer_addr ){
		_rhp_free(peer_addr);
	}
	return err;
}


static int _rhp_cfg_parse_config_server_internal_address(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
  int ret_len;
  rhp_vpn_realm* rlm = (rhp_vpn_realm*)ctx;

  err = rhp_xml_enum_tags(node,(xmlChar*)"address_pool",
  				_rhp_cfg_parse_config_server_internal_address_pool,rlm,1);
  if( err && err != -ENOENT ){
    RHP_BUG("");
    goto error;
  }

  err = rhp_xml_enum_tags(node,(xmlChar*)"peer",
  				_rhp_cfg_parse_config_server_internal_peer,rlm,1);
  if( err && err != -ENOENT ){
    RHP_BUG("");
    goto error;
  }


  rlm->config_server.addr_hold_hours = 1;
	rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"hold_hours"),
			RHP_XML_DT_INT,&(rlm->config_server.addr_hold_hours),&ret_len,NULL,0);

  return 0;

error:
	return err;
}


static int _rhp_cfg_parse_config_server_internal_route_map(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
  rhp_vpn_realm* rlm = (rhp_vpn_realm*)ctx;
  rhp_internal_route_map* rtmap = NULL;
  rhp_internal_route_map* rtmap_tail = NULL;
  int ret_len;

  rtmap = (rhp_internal_route_map*)_rhp_malloc(sizeof(rhp_internal_route_map));
  if( rtmap == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }

  memset(rtmap,0,sizeof(rhp_internal_route_map));

  rtmap->tag[0] = '#';
  rtmap->tag[1] = 'I';
  rtmap->tag[2] = 'R';
  rtmap->tag[3] = 'T';

  {
		rhp_ip_addr* ip_addr = NULL;

		err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"destination_v4"),
						RHP_XML_DT_IPV4_SUBNET,&ip_addr,&ret_len,NULL,0);

		if( err == -ENOENT ){

			err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"destination_v6"),
							RHP_XML_DT_IPV6_SUBNET,&ip_addr,&ret_len,NULL,0);
		}
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		memcpy(&(rtmap->dest_addr),ip_addr,sizeof(rhp_ip_addr));
		_rhp_free(ip_addr);
  }

  if( rtmap->dest_addr.addr_family == AF_INET ){
  	rtmap_tail = rlm->config_server.rt_maps;
  }else if( rtmap->dest_addr.addr_family == AF_INET6 ){
  	rtmap_tail = rlm->config_server.rt_maps_v6;
  }else{
  	RHP_BUG("%d",rtmap->dest_addr.addr_family);
  }
  while( rtmap_tail ){
  	if( rtmap_tail->next == NULL ){
  		break;
  	}
  	rtmap_tail = rtmap_tail->next;
  }

  if( rtmap_tail == NULL ){

  	if( rtmap->dest_addr.addr_family == AF_INET ){
    	rlm->config_server.rt_maps = rtmap;
    }else{ // AF_INET6
    	rlm->config_server.rt_maps_v6 = rtmap;
    }

  }else{

  	rtmap_tail->next = rtmap;
  }

  return 0;

error:
	if( rtmap ){
		_rhp_free(rtmap);
	}
  return err;
}


static int _rhp_cfg_parse_config_server_internal_networks(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
  rhp_vpn_realm* rlm = (rhp_vpn_realm*)ctx;
  int ret_len;

  {
  	u32 gw_addr_v4;

		rlm->config_server.gw_addr.addr_family = AF_UNSPEC;

		err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"gateway_address_v4"),
				RHP_XML_DT_IPV4,&gw_addr_v4,&ret_len,NULL,0);

		if( err && err != -ENOENT ){

			RHP_BUG("");
			goto error;

		}else if( err == 0 ){

			rlm->config_server.gw_addr.addr_family = AF_INET;
			rlm->config_server.gw_addr.addr.v4 = gw_addr_v4;
		}
    err = 0;
  }


  {
		rlm->config_server.gw_addr_v6.addr_family = AF_UNSPEC;

		err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"gateway_address_v6"),
				RHP_XML_DT_IPV6,&(rlm->config_server.gw_addr_v6),&ret_len,NULL,0);

		if( err && err != -ENOENT ){

			RHP_BUG("");
			goto error;

		}else if( err == 0 ){

			rlm->config_server.gw_addr_v6.addr_family = AF_INET6;
		}
    err = 0;
  }


  rlm->config_server.allow_v6_ra = 0;
  rhp_xml_check_enable(node,(xmlChar*)"allow_ipv6_router_adv",&(rlm->config_server.allow_v6_ra));


  err = rhp_xml_enum_tags(node,(xmlChar*)"route_map",_rhp_cfg_parse_config_server_internal_route_map,rlm,1);
  if( err && err != -ENOENT ){
  	RHP_BUG("");
  	goto error;
  }
  err = 0;

error:
	return err;
}


static int _rhp_cfg_parse_internal_dns_domain(xmlNodePtr node,void* ctx)
{
  int err;
  rhp_vpn_realm* rlm = (rhp_vpn_realm*)ctx;
  int ret_len;
  rhp_split_dns_domain *domain = NULL,*domain_p = NULL;

  domain = (rhp_split_dns_domain*)_rhp_malloc(sizeof(rhp_split_dns_domain));
  if( domain == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }

  memset(domain,0,sizeof(rhp_split_dns_domain));

  domain->tag[0] = '#';
  domain->tag[1] = 'C';
  domain->tag[2] = 'S';
  domain->tag[3] = 'D';

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"match"),RHP_XML_DT_STRING,&(domain->name),&ret_len,NULL,0);
  if( err ){
    RHP_BUG("");
    goto error;
  }
  err = 0;

	RHP_TRC(0,RHPTRCID_CFG_PARSE_INTERNAL_DNS_DOMAIN,"xs",domain,domain->name);

  domain_p = rlm->config_server.domains;
  while( domain_p ){
  	if( domain_p->next == NULL ){
  		break;
  	}
  	domain_p = domain_p->next;
  }

  if( domain_p == NULL ){
  	rlm->config_server.domains = domain;
  }else{
  	domain_p->next = domain;
  }

  return 0;

error:
	return err;
}


static int _rhp_cfg_parse_config_server_internal_dns(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
  rhp_vpn_realm* rlm = (rhp_vpn_realm*)ctx;
  int ret_len;

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"server_address_v4"),RHP_XML_DT_IPV4,
  		&(rlm->config_server.dns_server_addr.addr.v4),&ret_len,NULL,0);

  if( err && err != -ENOENT ){

    RHP_BUG("%d",err);
    goto error;

  }else if( err == 0 ){

  	if( rlm->config_server.dns_server_addr.addr.v4 == 0 ){
  		RHP_BUG("");
  		goto error;
  	}

  	rlm->config_server.dns_server_addr.addr_family = AF_INET;
  }
  err = 0;

  rhp_ip_addr_dump("rlm->config_server.dns_server_addr",&(rlm->config_server.dns_server_addr));


  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"server_address_v6"),
  		RHP_XML_DT_IPV6,&(rlm->config_server.dns_server_addr_v6),&ret_len,NULL,0);

  if( err && err != -ENOENT ){

    RHP_BUG("%d",err);
    goto error;

  }else if( err == 0 ){

  	if( rhp_ip_addr_null(&(rlm->config_server.dns_server_addr_v6)) ){
  		RHP_BUG("");
  		goto error;
  	}

  	rlm->config_server.dns_server_addr_v6.addr_family = AF_INET6;
  }
  err = 0;

  rhp_ip_addr_dump("rlm->config_server.dns_server_addr_v6",&(rlm->config_server.dns_server_addr_v6));


  return rhp_xml_enum_tags(node,(xmlChar*)"domain",_rhp_cfg_parse_internal_dns_domain,ctx,1);

error:
	return err;
}


static int _rhp_cfg_parse_config_server(xmlNodePtr node,rhp_vpn_realm* rlm)
{
	int err = -EINVAL;

  err = rhp_xml_enum_tags(node,(xmlChar*)"internal_address",_rhp_cfg_parse_config_server_internal_address,rlm,0);
  if( err &&  err != -ENOENT ){
    RHP_BUG("");
    goto error;
  }
  err = 0;

  err = rhp_xml_enum_tags(node,(xmlChar*)"internal_networks",_rhp_cfg_parse_config_server_internal_networks,rlm,0);
  if( err && err != -ENOENT ){
    RHP_BUG("");
    goto error;
  }
	err = 0;

  err = rhp_xml_enum_tags(node,(xmlChar*)"internal_dns",_rhp_cfg_parse_config_server_internal_dns,rlm,0);
  if( err && err != -ENOENT ){
    RHP_BUG("");
    goto error;
  }
	err = 0;

	{
  	xmlChar* narrow_ts_i = rhp_xml_get_prop_static(node,(const xmlChar*)"narrow_ts_i");

		if( narrow_ts_i ){

  		if( !strcmp((char*)narrow_ts_i,"enable") ){

				rlm->config_server.narrow_ts_i = RHP_IKEV2_CFG_NARROW_TS_I_ALL;

			}else if( !strcmp((char*)narrow_ts_i,"enable_for_non_rockhopper") ){

				rlm->config_server.narrow_ts_i = RHP_IKEV2_CFG_NARROW_TS_I_NON_ROCKHOPPER;

			}else if( !strcmp((char*)narrow_ts_i,"disable") ){

				rlm->config_server.narrow_ts_i = RHP_IKEV2_CFG_NARROW_TS_I_DONT;
			}
  	}
	}

  rhp_xml_check_enable(node,(xmlChar*)"reject_non_clients",&(rlm->config_server.reject_non_clients));

  rhp_xml_check_enable(node,(xmlChar*)"dont_fwd_pkts_between_clients",
  		&(rlm->config_server.dont_fwd_pkts_between_clients));

  if( rlm->config_server.dont_fwd_pkts_between_clients ){

  	rhp_xml_check_enable(node,(xmlChar*)"dont_fwd_pkts_between_clients_except_v6_auto",
  		&(rlm->config_server.dont_fwd_pkts_between_clients_except_v6_auto));
  }

  rhp_xml_check_enable(node,(xmlChar*)"disable_non_ip",&(rlm->config_server.disable_non_ip));

  rhp_xml_check_enable(node,(xmlChar*)"reject_client_ts",&(rlm->config_server.reject_client_ts));

  rhp_xml_check_enable(node,(xmlChar*)"allow_ipv6_autoconf",&(rlm->config_server.allow_ipv6_autoconf));

	return 0;

error:
	return err;
}


static int _rhp_cfg_parse_my_service(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
  rhp_vpn_realm* rlm = (rhp_vpn_realm*)ctx;

  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"name"),(xmlChar*)"access_point") ){

  	if( rlm->is_mesh_node ){
  		RHP_BUG("");
  		return -EINVAL;
  	}

  	rlm->is_access_point = 1;

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"name"),(xmlChar*)"config_client") ){

  	if( rlm->config_service ){
  		RHP_BUG("");
  		return -EINVAL;
  	}

  	rlm->config_service = RHP_IKEV2_CONFIG_CLIENT;

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"name"),(xmlChar*)"config_server") ){

  	if( rlm->config_service ){
  		RHP_BUG("");
  		return -EINVAL;
  	}

  	err = _rhp_cfg_parse_config_server(node,rlm);
  	if( err ){
  		RHP_BUG("%d",err);
  		return err;
  	}

  	rlm->config_service = RHP_IKEV2_CONFIG_SERVER;

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"name"),(xmlChar*)"nhrp_server") ){

  	if( rlm->nhrp.service ){
  		RHP_BUG("");
  		return -EINVAL;
  	}

  	rlm->nhrp.service = RHP_NHRP_SERVICE_SERVER;

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"name"),(xmlChar*)"nhrp_client") ){

  	if( rlm->nhrp.service ){
  		RHP_BUG("");
  		return -EINVAL;
  	}

  	rlm->nhrp.service = RHP_NHRP_SERVICE_CLIENT;

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"name"),(xmlChar*)"dmvpn") ){

  	if( rlm->nhrp.dmvpn_enabled ){
  		RHP_BUG("");
  		return -EINVAL;
  	}

  	rlm->nhrp.dmvpn_enabled = 1;

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"name"),
  						(xmlChar*)"authentication_ticket") ){

  	if( rlm->nhrp.auth_tkt_enabled ){
  		RHP_BUG("");
  		return -EINVAL;
  	}

  	rlm->nhrp.auth_tkt_enabled = 1;

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"name"),(xmlChar*)"mesh_node") ){

  	if( rlm->is_access_point ){
  		RHP_BUG("");
  		return -EINVAL;
  	}

  	rlm->is_mesh_node = 1;

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"name"),(xmlChar*)"peer_discovery_mediator") ){

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"name"),(xmlChar*)"peer_discovery_client") ){

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"name"),(xmlChar*)"nat_t_mediator") ){

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"name"),(xmlChar*)"policy_server") ){

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"name"),(xmlChar*)"group_management_server") ){

  }

  return 0;
}


static int _rhp_cfg_parse_encap(xmlNodePtr node,void* ctx)
{
  rhp_vpn_realm* rlm = (rhp_vpn_realm*)ctx;
  int err = -EINVAL;
  int ret_len;

  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"mode"),(xmlChar*)"etherip") ){
  	rlm->encap_mode_c = RHP_VPN_ENCAP_ETHERIP;
  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"mode"),(xmlChar*)"ipip") ){
  	rlm->encap_mode_c = RHP_VPN_ENCAP_IPIP;
  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"mode"),(xmlChar*)"gre") ){
  	rlm->encap_mode_c = RHP_VPN_ENCAP_GRE;
  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"mode"),(xmlChar*)"any") ){
  	rlm->encap_mode_c = RHP_VPN_ENCAP_ANY;
  }else{
  	RHP_BUG("");
  	err = -EINVAL;
		goto error;
  }

  if( rlm->encap_mode_c == RHP_VPN_ENCAP_GRE || rlm->encap_mode_c == RHP_VPN_ENCAP_ANY ){

		err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"gre_key"),
					RHP_XML_DT_UINT,&(rlm->gre.key),&ret_len,NULL,0);
		if( err == -ENOENT ){

			rlm->gre.key_enabled = 0;

		}else if( !err ){

			rlm->gre.key_enabled = 1;

		}else{
	  	RHP_BUG("");
			goto error;
		}

		err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"nhrp_key"),
				RHP_XML_DT_STRING,&(rlm->nhrp.key),&ret_len,NULL,0);
		if( err == -ENOENT ){

			rlm->nhrp.key_len = 0;

		}else if( !err ){

			rlm->nhrp.key_len = (ret_len - 1);

		}else{
	  	RHP_BUG("");
			goto error;
		}
  }

  return 0;

error:
	return err;
}



static int _rhp_cfg_parse_virtual_interface(xmlNodePtr node,void* ctx)
{
  int err;
  rhp_vpn_realm* rlm = (rhp_vpn_realm*)ctx;
  rhp_cfg_internal_if* cfg_internal_if = NULL;
  int ret_len;
  char* rlm_id_str = NULL;
  int if_name_len;

  rlm_id_str = (char*)rhp_xml_get_prop(node->parent,(const xmlChar*)"id");

  cfg_internal_if = (rhp_cfg_internal_if*)_rhp_malloc(sizeof(rhp_cfg_internal_if));
  if( cfg_internal_if == NULL ){
  	RHP_BUG("");
    return -ENOMEM;
  }
  memset(cfg_internal_if,0,sizeof(rhp_cfg_internal_if));

  cfg_internal_if->tag[0] = '#';
  cfg_internal_if->tag[1] = 'C';
  cfg_internal_if->tag[2] = 'V';
  cfg_internal_if->tag[3] = 'I';

  if_name_len = strlen(RHP_VIRTUAL_IF_NAME) + strlen(rlm_id_str) + 1;

  if( if_name_len > (RHP_IFNAMSIZ + 1) ){
    RHP_BUG("");
    goto error;
  }

  cfg_internal_if->if_name = (char*)_rhp_malloc(if_name_len);
  if( cfg_internal_if->if_name == NULL ){
    RHP_BUG("");
    goto error;
  }
  cfg_internal_if->if_name[0] = '\0';

  sprintf(cfg_internal_if->if_name,"%s%s",RHP_VIRTUAL_IF_NAME,rlm_id_str);


  rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"fixed_mtu"),
  		RHP_XML_DT_INT,&(cfg_internal_if->fixed_mtu),&ret_len,NULL,0);


  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,
  			(xmlChar*)"address_type"),(xmlChar*)"static") ){

    rhp_ip_addr *ret_ipv4 = NULL, *ret_ipv6 = NULL;
    rhp_ip_addr_list* addr_lst = NULL;

    cfg_internal_if->addrs_type = RHP_VIF_ADDR_STATIC;

    rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"address_v4"),
    		RHP_XML_DT_IPV4_SUBNET,&ret_ipv4,&ret_len,NULL,0);

    rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"address_v6"),
    		RHP_XML_DT_IPV6_SUBNET,&ret_ipv6,&ret_len,NULL,0);

    if( ret_ipv4 == NULL && ret_ipv6 == NULL ){
      RHP_BUG("");
      goto error;
    }

    if( ret_ipv6 ){

    	addr_lst = (rhp_ip_addr_list*)_rhp_malloc(sizeof(rhp_ip_addr_list));
    	if( addr_lst == NULL ){
    		RHP_BUG("");
        _rhp_free(ret_ipv6);
      	if( ret_ipv4 ){
        	_rhp_free(ret_ipv4);
      	}
    		goto error;
    	}
    	memset(addr_lst,0,sizeof(rhp_ip_addr_list));

    	memcpy(&(addr_lst->ip_addr),ret_ipv6,sizeof(rhp_ip_addr));

    	cfg_internal_if->addrs = addr_lst;

    	_rhp_free(ret_ipv6);
    }

    if( ret_ipv4 ){

    	addr_lst = (rhp_ip_addr_list*)_rhp_malloc(sizeof(rhp_ip_addr_list));
    	if( addr_lst == NULL ){
    		RHP_BUG("");
      	_rhp_free(ret_ipv4);
    		goto error;
    	}
    	memset(addr_lst,0,sizeof(rhp_ip_addr_list));

    	memcpy(&(addr_lst->ip_addr),ret_ipv4,sizeof(rhp_ip_addr));

    	addr_lst->next = cfg_internal_if->addrs;
    	cfg_internal_if->addrs = addr_lst;

    	_rhp_free(ret_ipv4);
    }

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,
  						(xmlChar*)"address_type"),(xmlChar*)"ikev2-config-v4") ||
  					!rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,
  						(xmlChar*)"address_type"),(xmlChar*)"ikev2-config") ){

  	// Actually, "ikev2-config-v4" is obsoleted.

  	cfg_internal_if->addrs_type = RHP_VIF_ADDR_IKEV2CFG;

  	cfg_internal_if->ikev2_config_ipv6_auto = 0;
    rhp_xml_check_enable(node,(xmlChar*)"ikev2_config_ipv6_auto",
    		&(cfg_internal_if->ikev2_config_ipv6_auto));

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,
  						(xmlChar*)"address_type"),(xmlChar*)"dhcp") ){

  	// TODO : dhcp Support

  	cfg_internal_if->addrs_type = RHP_VIF_ADDR_DHCP;

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,
  						(xmlChar*)"address_type"),(xmlChar*)"none") ){

  	cfg_internal_if->addrs_type = RHP_VIF_ADDR_NONE;

  }else{
    RHP_BUG("");
    goto error;
  }


  {
  	u32 gw_addr_v4;
  	rhp_ip_addr gw_addr_v6;

  	memset(&gw_addr_v6,0,sizeof(rhp_ip_addr));

		err = rhp_xml_str2val(rhp_xml_get_prop_static(node,
					(const xmlChar*)"gateway_address_v4"),RHP_XML_DT_IPV4,&gw_addr_v4,&ret_len,NULL,0);
		if( err && err != -ENOENT ){

			RHP_BUG("");
			goto error;

		}else if( err == 0 ){

			cfg_internal_if->gw_addr.addr_family = AF_INET;
			cfg_internal_if->gw_addr.addr.v4 = gw_addr_v4;
		}
		err = 0;

		err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"gateway_address_v6"),
						RHP_XML_DT_IPV6,&gw_addr_v6,&ret_len,NULL,0);
		if( err && err != -ENOENT ){

			RHP_BUG("");
			goto error;

		}else if( err == 0 ){

			rhp_ip_addr_set2(&(cfg_internal_if->gw_addr_v6),AF_INET6,gw_addr_v6.addr.v6,0);
		}
		err = 0;
  }

	if( cfg_internal_if->addrs_type == RHP_VIF_ADDR_NONE ){

  	err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"bridge"),
  					RHP_XML_DT_STRING,&(cfg_internal_if->bridge_name),&ret_len,NULL,0);

		if( err && err != -ENOENT ){

			RHP_BUG("");
			goto error;

		}else if( !err ){

			if( ret_len >= RHP_IFNAMSIZ ){
				err = -EINVAL;
				RHP_BUG("");
				goto error;
			}
		}
		err = 0;


	  if( cfg_internal_if->fixed_mtu ){
	  	cfg_internal_if->bridge_def_mtu = cfg_internal_if->fixed_mtu;
	  }else{
	  	cfg_internal_if->bridge_def_mtu = rhp_gcfg_def_vif_mtu;
	  }

  	if( cfg_internal_if->bridge_def_mtu < rhp_gcfg_min_pmtu ){
  		cfg_internal_if->bridge_def_mtu = rhp_gcfg_min_pmtu;
  	}

	}else{

		// When VIF is bridged(RHP_VIF_ADDR_NONE), use a system default MTU.

	  if( !cfg_internal_if->fixed_mtu ){
	  	cfg_internal_if->fixed_mtu = rhp_gcfg_def_vif_mtu;
	  }
  }

	if( cfg_internal_if->fixed_mtu && (cfg_internal_if->fixed_mtu < rhp_gcfg_min_pmtu) ){
		cfg_internal_if->fixed_mtu = rhp_gcfg_min_pmtu;
	}


  rlm->internal_ifc = cfg_internal_if;

  if( rlm_id_str ){
  	_rhp_free(rlm_id_str);
  }
  return 0;

error:
  if( cfg_internal_if ){
    if( cfg_internal_if->if_name ){
      _rhp_free(cfg_internal_if->if_name);
    }
    _rhp_free(cfg_internal_if);
  }
  if( rlm_id_str ){
  	_rhp_free(rlm_id_str);
  }
  return -EINVAL;
}


static int _rhp_create_def_virtual_interface(rhp_vpn_realm* rlm)
{
  rhp_cfg_internal_if* cfg_internal_if = NULL;
  int if_name_len;

  cfg_internal_if = (rhp_cfg_internal_if*)_rhp_malloc(sizeof(rhp_cfg_internal_if));
  if( cfg_internal_if == NULL ){
  	RHP_BUG("");
    return -ENOMEM;
  }
  memset(cfg_internal_if,0,sizeof(rhp_cfg_internal_if));

  cfg_internal_if->tag[0] = '#';
  cfg_internal_if->tag[1] = 'C';
  cfg_internal_if->tag[2] = 'V';
  cfg_internal_if->tag[3] = 'I';

  if_name_len = RHP_IFNAMSIZ + 1;

  cfg_internal_if->if_name = (char*)_rhp_malloc(if_name_len);
  if( cfg_internal_if->if_name == NULL ){
    RHP_BUG("");
    goto error;
  }
  cfg_internal_if->if_name[0] = '\0';

  if( snprintf(cfg_internal_if->if_name,if_name_len,"%s%lu",RHP_VIRTUAL_IF_NAME,rlm->id) >= if_name_len ){
  	RHP_BUG("%d",rlm->id);
  	goto error;
  }

	cfg_internal_if->addrs_type = RHP_VIF_ADDR_NONE;

	cfg_internal_if->fixed_mtu = 0;

  rlm->internal_ifc = cfg_internal_if;

  return 0;

error:
  if( cfg_internal_if ){
    if( cfg_internal_if->if_name ){
      _rhp_free(cfg_internal_if->if_name);
    }
    _rhp_free(cfg_internal_if);
  }
  return -EINVAL;
}


rhp_vpn_realm* rhp_cfg_parse_realm(xmlNodePtr realm_node)
{
  rhp_vpn_realm* rlm = NULL;
  int ret_len;
  char rlm_name_def[64];
  int err = 0;

  rlm = rhp_realm_alloc();
  if( rlm == NULL ){
    RHP_BUG("");
    return NULL;
  }

  if( rhp_xml_str2val(rhp_xml_get_prop_static(realm_node,(const xmlChar*)"id"),RHP_XML_DT_ULONG,&(rlm->id),&ret_len,NULL,0) ){
    RHP_BUG("");
  	RHP_LOG_W(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm id=?&gt",-EINVAL);
    goto error;
  }

  if( rlm->id == 0 ||  rlm->id > RHP_VPN_REALM_ID_MAX ){
    RHP_BUG("%d",rlm->id);
  	RHP_LOG_W(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm id=?&gt",-EINVAL);
    goto error;
  }

  rlm_name_def[0] = '\0';
  sprintf(rlm_name_def,"vpn_realm%lu",rlm->id);
  err = rhp_xml_str2val(rhp_xml_get_prop_static(realm_node,(const xmlChar*)"name"),RHP_XML_DT_STRING,&(rlm->name),&ret_len,rlm_name_def,0);
  if( err ){
  	RHP_LOG_W(RHP_LOG_SRC_CFG,rlm->id,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm name=?&gt",err);
  	RHP_BUG("");
  	goto error;
  }

  rlm_name_def[0] = '\0';
  sprintf(rlm_name_def,"%s","Not Specified");
  err = rhp_xml_str2val(rhp_xml_get_prop_static(realm_node,(const xmlChar*)"mode"),RHP_XML_DT_STRING,&(rlm->mode_label),&ret_len,rlm_name_def,0);
  if( err ){
  	RHP_LOG_W(RHP_LOG_SRC_CFG,rlm->id,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm mode=?&gt",err);
  	RHP_BUG("");
  	goto error;
  }

  rlm_name_def[0] = '\0';
  err = rhp_xml_str2val(rhp_xml_get_prop_static(realm_node,(const xmlChar*)"description"),RHP_XML_DT_STRING,&(rlm->description),&ret_len,rlm_name_def,0);
  if( err ){
  	RHP_LOG_W(RHP_LOG_SRC_CFG,rlm->id,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm description=?&gt",err);
  	RHP_BUG("");
  	goto error;
  }

  {
  	int realm_enabled = 1;
    rhp_xml_check_enable(realm_node,(xmlChar*)"status",&realm_enabled);

    if( !realm_enabled ){
    	rlm->disabled = 1;
    }
  }

  {
  	int64_t created_time;

  	created_time = -1;
  	rhp_xml_str2val(rhp_xml_get_prop_static(realm_node,(const xmlChar*)"created_time"),RHP_XML_DT_LONGLONG,&created_time,&ret_len,NULL,0);
  	rlm->realm_created_time = (time_t)created_time; // -1 is OK.

  	created_time = -1;
  	rhp_xml_str2val(rhp_xml_get_prop_static(realm_node,(const xmlChar*)"updated_time"),RHP_XML_DT_LONGLONG,&created_time,&ret_len,NULL,0);
  	rlm->realm_updated_time = (time_t)created_time; // -1 is OK.

  	created_time = -1;
  	rhp_xml_str2val(rhp_xml_get_prop_static(realm_node,(const xmlChar*)"sess_resume_policy_index"),RHP_XML_DT_LONGLONG,&created_time,&ret_len,NULL,0);
  	if( created_time != -1 ){
    	rlm->sess_resume_policy_index = (time_t)created_time;
  	}else{
    	rlm->sess_resume_policy_index = rlm->realm_updated_time;
  	}
  }


  err = rhp_xml_enum_tags(realm_node,(xmlChar*)"internal_interface",_rhp_cfg_parse_virtual_interface,rlm,0);
  if( err == -ENOENT ){

  	err = _rhp_create_def_virtual_interface(rlm);
  	if( err ){
    	RHP_LOG_W(RHP_LOG_SRC_CFG,rlm->id,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm&gt&ltinternal_interface&gt",err);
      RHP_BUG("");
  		goto error;
  	}

  	rlm->is_not_ready = 1;

  }else if( err ){

  	RHP_LOG_W(RHP_LOG_SRC_CFG,rlm->id,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm&gt&ltinternal_interface&gt",err);
    RHP_BUG("%d",err);
    goto error;

  }else{

  	rlm->is_not_ready = 0;
  }


  rlm->gre.key_enabled = 0;

  err = rhp_xml_enum_tags(realm_node,(xmlChar*)"encap",_rhp_cfg_parse_encap,rlm,0);
  if( err == -ENOENT ){
    rlm->encap_mode_c = RHP_VPN_ENCAP_ANY;
  }else if( err ){
  	RHP_LOG_W(RHP_LOG_SRC_CFG,rlm->id,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm&gt&ltencap&gt",err);
    RHP_BUG("");
    goto error;
  }
  err = 0;


	rlm->config_server.narrow_ts_i = RHP_IKEV2_CFG_NARROW_TS_I_UNDEF;
	rlm->config_server.dont_fwd_pkts_between_clients = 1;

	rlm->nhrp.service = RHP_NHRP_SERVICE_NONE;
	rlm->nhrp.dmvpn_enabled = 0;
	rlm->nhrp.auth_tkt_enabled = 0;

  err = rhp_xml_enum_tags(realm_node,(xmlChar*)"service",_rhp_cfg_parse_my_service,rlm,1);
  if( err && err != -ENOENT ){
  	RHP_LOG_W(RHP_LOG_SRC_CFG,rlm->id,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm&gt&ltservice&gt",err);
    RHP_BUG("");
    goto error;
  }
	err = 0;

  err = rhp_xml_enum_tags(realm_node,(xmlChar*)"my_interfaces",_rhp_cfg_parse_my_interfaces,rlm,0);
  if( err == -ENOENT ){
    rlm->my_interfaces = NULL; // ANY
    rlm->my_interfaces_any = 1;
    err = 0;
  }else if( err ){
  	RHP_LOG_W(RHP_LOG_SRC_CFG,rlm->id,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm&gt&ltmy_interfaces&gt",err);
    RHP_BUG("");
    goto error;
  }

  rlm->ikesa.keep_alive_interval = rhp_gcfg_keep_alive_interval;
  rlm->ikesa.nat_t_keep_alive_interval = rhp_gcfg_nat_t_keep_alive_interval;
  rlm->ikesa.lifetime_larval = rhp_gcfg_ikesa_lifetime_larval;
  rlm->ikesa.lifetime_eap_larval = rhp_gcfg_ikesa_lifetime_eap_larval;
  rlm->ikesa.lifetime_soft = rhp_gcfg_ikesa_lifetime_soft;
  rlm->ikesa.lifetime_hard = rhp_gcfg_ikesa_lifetime_hard;
  rlm->ikesa.lifetime_deleted = rhp_gcfg_ikesa_lifetime_deleted;
  rlm->v1.ikesa_lifetime_deleted = rhp_gcfg_ikev1_ikesa_lifetime_deleted;

  rlm->vpn_conn_lifetime = 0;
  rlm->vpn_conn_idle_timeout = rhp_gcfg_dmvpn_vpn_conn_idle_timeout;

  rlm->ikesa.resp_not_rekeying = rhp_gcfg_ikesa_resp_not_rekeying;
  rlm->ikesa.use_nat_t_port = 0;
  rlm->ikesa.nat_t = 1;
  rlm->ikesa.delete_no_childsa = rhp_gcfg_delete_ikesa_if_no_childsa_exists;
  rlm->ikesa.send_realm_id = 0;
  rlm->ikesa.send_responder_id = 1;

  rlm->my_auth.http_cert_lookup = 0;
  rlm->my_auth.send_ca_chains = 1;

  rlm->mobike.enabled = 1;
  rlm->mobike.resp_ka_interval = rhp_gcfg_ikev2_mobike_resp_keep_alive_interval;
  rlm->mobike.resp_ka_interval_null_auth = rhp_gcfg_ikev2_mobike_resp_null_auth_keep_alive_interval;
  rlm->mobike.resp_ka_retx_interval = rhp_gcfg_ikev2_mobike_resp_keep_alive_retry_interval;
  rlm->mobike.resp_routability_check = 1;
  rlm->mobike.resp_ka_retx_retries = rhp_gcfg_ikev2_mobike_resp_keep_alive_max_retries;

  rlm->mobike.init_hold_time = rhp_gcfg_ikev2_mobike_init_rt_check_hold_time;
  rlm->mobike.init_hold_ka_interval = rhp_gcfg_ikev2_mobike_init_rt_check_hold_ka_interval;
  rlm->mobike.init_hold_ka_max_retries = rhp_gcfg_ikev2_mobike_init_rt_check_hold_ka_max_retries;
  rlm->mobike.init_cache_additional_addr = 0;

  rlm->v1.dpd_enabled = rhp_gcfg_ikev1_dpd_enabled;


  err = rhp_xml_enum_tags(realm_node,(xmlChar*)"ikesa",_rhp_cfg_parse_rlm_ikesa,rlm,1);
  if( err == -ENOENT ){
    err = 0;
  }else if( err ){
  	RHP_LOG_W(RHP_LOG_SRC_CFG,rlm->id,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm&gt&ltikesa&gt",err);
    RHP_BUG("");
    goto error;
  }

	if( rlm->config_server.narrow_ts_i != RHP_IKEV2_CFG_NARROW_TS_I_NON_ROCKHOPPER &&
			rlm->config_server.narrow_ts_i != RHP_IKEV2_CFG_NARROW_TS_I_ALL &&
			rlm->config_server.narrow_ts_i != RHP_IKEV2_CFG_NARROW_TS_I_DONT ){

    rlm->config_server.narrow_ts_i = rhp_gcfg_ikesa_remote_cfg_narrow_ts_i;

  	if( rlm->config_server.narrow_ts_i != RHP_IKEV2_CFG_NARROW_TS_I_NON_ROCKHOPPER &&
  			rlm->config_server.narrow_ts_i != RHP_IKEV2_CFG_NARROW_TS_I_ALL &&
  			rlm->config_server.narrow_ts_i != RHP_IKEV2_CFG_NARROW_TS_I_DONT ){

      rlm->config_server.narrow_ts_i = RHP_IKEV2_CFG_NARROW_TS_I_NON_ROCKHOPPER;
    }
  }


  rlm->childsa.lifetime_larval = rhp_gcfg_childsa_lifetime_larval;
  rlm->childsa.lifetime_soft = rhp_gcfg_childsa_lifetime_soft;
  rlm->childsa.lifetime_hard = rhp_gcfg_childsa_lifetime_hard;
  rlm->childsa.lifetime_deleted = rhp_gcfg_childsa_lifetime_deleted;
  rlm->v1.ipsecsa_lifetime_deleted = rhp_gcfg_ikev1_ipsecsa_lifetime_deleted;

  rlm->childsa.anti_replay = rhp_gcfg_childsa_anti_replay;
  rlm->childsa.anti_replay_win_size = rhp_gcfg_childsa_anti_replay_win_size;

  rlm->childsa.tfc_padding = rhp_gcfg_childsa_tfc_padding;
  rlm->childsa.pfs = rhp_gcfg_childsa_pfs;
  rlm->childsa.resp_not_rekeying = rhp_gcfg_childsa_resp_not_rekeying;
  rlm->childsa.apply_ts_to_eoip = 1;
  rlm->childsa.apply_ts_to_gre = 1;
  rlm->childsa.exec_pmtud = 1;
  rlm->childsa.v6_enable_udp_encap_after_rx = 0;
  rlm->childsa.v6_udp_encap_disabled = 0;

	rlm->childsa.dummy_traffic_rate_per_packets = RHP_CFG_DUMMY_TRAFFIC_RATE_PER_PACKETS;
	rlm->childsa.tfc_padding_max_size = RHP_CFG_TFC_PADDING_MAX_SIZE;
	rlm->childsa.dummy_traffic_interval = RHP_CFG_DUMMY_TRAFFIC_INTERVAL;
	rlm->childsa.exact_match_ts = 0;
	rlm->childsa.dont_fwd_pkts_between_vpn_conns = 0;

	rlm->childsa.gre_auto_gen_ts = 1;
	rlm->childsa.gre_ts_allow_nat_reflexive_addr = 1;

  err = rhp_xml_enum_tags(realm_node,(xmlChar*)"childsa",_rhp_cfg_parse_rlm_childsa,rlm,1);
  if( err == -ENOENT ){
    err = 0;
  }else if( err ){
  	RHP_LOG_W(RHP_LOG_SRC_CFG,rlm->id,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm&gt&ltchildsa&gt",err);
    RHP_BUG("");
    goto error;
  }

  err = rhp_xml_enum_tags(realm_node,(xmlChar*)"peers",_rhp_cfg_parse_peers,rlm,0);
  if( err == -ENOENT ){

  	err = _rhp_create_def_rlm_peer(rlm);
  	if( err ){
    	RHP_LOG_W(RHP_LOG_SRC_CFG,rlm->id,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm&gt&ltpeers&gt",err);
      RHP_BUG("");
  		goto error;
  	}

  }else if( err ){
  	RHP_LOG_W(RHP_LOG_SRC_CFG,rlm->id,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm&gt&ltpeers&gt",err);
    RHP_BUG("%d",err);
    goto error;
  }

  err = rhp_xml_enum_tags(realm_node,(xmlChar*)"ext_traffic_selectors",_rhp_cfg_parse_ext_traffic_selectors,rlm,0);
  if( err == -ENOENT ){
  	rlm->ext_tss.etss_num = 0;
  	rlm->ext_tss.etss = NULL;
    err = 0;
  }else if( err ){
  	RHP_LOG_W(RHP_LOG_SRC_CFG,rlm->id,RHP_LOG_ID_CFG_PARSE_ERR,"s","&ltvpn_realm&gt&ltext_traffic_selectors&lt");
    RHP_BUG("");
    goto error;
  }

  err = rhp_xml_enum_tags(realm_node,(xmlChar*)"route_maps",_rhp_cfg_parse_route_maps,rlm,0);
  if( err == -ENOENT ){
    err = 0;
  }else if( err ){
  	RHP_LOG_W(RHP_LOG_SRC_CFG,rlm->id,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm&gt&ltroute_maps&gt",err);
    RHP_BUG("");
    goto error;
  }

  err = rhp_xml_enum_tags(realm_node,(xmlChar*)"split_dns",_rhp_cfg_parse_split_dns,rlm,0);
  if( err == -ENOENT ){
    err = 0;
  }else if( err ){
  	RHP_LOG_W(RHP_LOG_SRC_CFG,rlm->id,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm&gt&ltsplit_dns&gt",err);
    RHP_BUG("");
    goto error;
  }

  return rlm;

error:
  rhp_realm_free(rlm);
  return NULL;
}


static int _rhp_cfg_static_params(xmlNodePtr node,rhp_gcfg_param* list_head)
{
	int i;
  int ret_len;

  for( i = 0; ; i++){

  	xmlChar* prop;

  	if( list_head[i].type < 0 ){
  		break;
  	}

  	prop = rhp_xml_get_prop(node,(const xmlChar*)list_head[i].val_name);
  	if( prop ){

  		if( !xmlStrcmp(prop,(xmlChar*)"enable") || !xmlStrcmp(prop,(xmlChar*)"disable") ){

  			rhp_xml_check_enable(node,(xmlChar*)(list_head[i].val_name),list_head[i].val_p);

  		}else{

  			rhp_xml_str2val(prop,list_head[i].type,list_head[i].val_p,&ret_len,NULL,0);
  		}

  		_rhp_free(prop);
  	}
  }

  return 0;
}


static int _rhp_cfg_parse_ikesa_params(xmlNodePtr node,void* ctx)
{
  _rhp_cfg_static_params(node,rhp_gcfg_ikesa_params);
  return 0;
}


static int _rhp_cfg_parse_childsa_params(xmlNodePtr node,void* ctx)
{
  _rhp_cfg_static_params(node,rhp_gcfg_childsa_params);
  return 0;
}



static int _rhp_cfg_parse_vpn_params(xmlNodePtr node,void* ctx)
{
  _rhp_cfg_static_params(node,rhp_gcfg_vpn_params);
  return 0;
}


static int _rhp_cfg_parse_realm(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
  rhp_vpn_realm* rlm =  rhp_cfg_parse_realm(node);
  rhp_vpn_realm* rlm_ck = NULL;

  if( rlm == NULL ){
    RHP_BUG("");
    goto error;
  }

  if( !rlm->disabled ){

		rlm_ck = rhp_realm_get(rlm->id);
		if( rlm_ck != NULL ){

			RHP_BUG("%d",rlm->id);

			rhp_realm_unhold(rlm_ck);

			err = 0;
			goto error;
		}

		_rhp_atomic_set(&(rlm->is_active),1);

		if( rlm->split_dns.domains != NULL ){

			if( !rhp_ip_addr_null(&(rlm->split_dns.internal_server_addr)) ||
					(!rhp_gcfg_ipv6_disabled && !rhp_ip_addr_null(&(rlm->split_dns.internal_server_addr_v6))) ){

				rhp_dns_pxy_inc_users();
			}
		}


		err = rhp_vpn_aoc_put(rlm); // Call this before rhp_realm_put()!!!
		if( err && err != -ENOENT ){
			RHP_BUG("%d");
			goto error;
		}
		err = 0;

		err = rhp_realm_put(rlm);
		if( err ){
			RHP_BUG("%d");
			goto error;
		}

  }else{

  	err = rhp_realm_disabled_put(rlm->id,rlm->name,rlm->mode_label,
  					rlm->description,rlm->realm_created_time,rlm->realm_updated_time);
  	if( err ){
  		RHP_BUG("%d",err);
  		goto error;
  	}
  }

  _rhp_cfg_trc_dump_realm(rlm);

  if( rlm->disabled ){
  	rhp_realm_unhold(rlm);
  }

  return 0;

error:
	if( rlm ){
    rhp_realm_unhold(rlm);
	}
	return err;
}



void rhp_cfg_free_ikesa_security(rhp_cfg_ikesa* cfg_ikesa)
{
  if( cfg_ikesa != &_rhp_ikesa_config_def ){

    rhp_cfg_transform *tmp,*tmp2;

    tmp = cfg_ikesa->encr_trans_list;
    while( tmp ){
      tmp2 = tmp->next;
      _rhp_free(tmp);
      tmp = tmp2;
    }

    tmp = cfg_ikesa->prf_trans_list;
    while( tmp ){
      tmp2 = tmp->next;
      _rhp_free(tmp);
      tmp = tmp2;
    }

    tmp = cfg_ikesa->integ_trans_list;
    while( tmp ){
      tmp2 = tmp->next;
      _rhp_free(tmp);
      tmp = tmp2;
    }

    tmp = cfg_ikesa->dh_trans_list;
    while( tmp ){
      tmp2 = tmp->next;
      _rhp_free(tmp);
      tmp = tmp2;
    }
  }
}


void rhp_cfg_free_childsa_security(rhp_cfg_childsa* cfg_childsa)
{
  if( cfg_childsa != &_rhp_childsa_config_def ){

    rhp_cfg_transform *tmp,*tmp2;

    tmp = cfg_childsa->encr_trans_list;
    while( tmp ){
      tmp2 = tmp->next;
      _rhp_free(tmp);
      tmp = tmp2;
    }

    tmp = cfg_childsa->integ_trans_list;
    while( tmp ){
      tmp2 = tmp->next;
      _rhp_free(tmp);
      tmp = tmp2;
    }

    tmp = cfg_childsa->esn_trans;
    while( tmp ){
      tmp2 = tmp->next;
      _rhp_free(tmp);
      tmp = tmp2;
    }
  }
}


int rhp_cfg_add_transform_list(xmlNodePtr node,int trans_type,rhp_cfg_transform** trans_list_head)
{
  char* name;
  int priority;
  int trans_id;
  int ret_len;
  rhp_cfg_transform *trans = NULL,*trans_c = NULL,*trans_p = NULL;
  int key_bits_len = 0;

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),
      RHP_XML_DT_STRING,&name,&ret_len,NULL,0) ){
    RHP_BUG("");
    goto error;
  }

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"priority"),
      RHP_XML_DT_INT,&priority,&ret_len,NULL,0) ){
    priority = INT_MAX;
  }

  trans_id = rhp_cfg_transform_str2id(trans_type,name);
  if( trans_id < 0 ){
    RHP_BUG("");
    goto error;
  }

  if( trans_type == RHP_PROTO_IKE_TRANSFORM_TYPE_ENCR ){
    if( trans_id == RHP_PROTO_IKE_TRANSFORM_ID_ENCR_AES_CBC ){
      if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"key_bits"),
          RHP_XML_DT_INT,&key_bits_len,&ret_len,NULL,0) ){
        RHP_BUG("");
        goto error;
      }
    }
  }

  trans = (rhp_cfg_transform*)_rhp_malloc(sizeof(rhp_cfg_transform));
  if( trans == NULL ){
    RHP_BUG("");
    goto error;
  }
  memset(trans,0,sizeof(rhp_cfg_transform));

  trans->tag[0] = '#';
  trans->tag[1] = 'T';
  trans->tag[2] = 'R';
  trans->tag[3] = 'S';

  trans->type = trans_type;
  trans->id = trans_id;
  trans->priority = priority;

  if( trans_type == RHP_PROTO_IKE_TRANSFORM_TYPE_ENCR ){
    trans->key_bits_len = key_bits_len;
  }

  trans_c = *trans_list_head;
  while( trans_c ){

    if( trans_type == RHP_PROTO_IKE_TRANSFORM_TYPE_ENCR ){
      if( trans_c->id == trans->id && trans_c->key_bits_len == trans->key_bits_len ){
        RHP_BUG("");
        goto error;
      }
    }else{
      if( trans_c->id == trans->id ){
        RHP_BUG("");
        goto error;
      }
    }

    if( trans_c->priority > trans->priority ){
      break;
    }
    trans_p = trans_c;
    trans_c = trans_c->next;
  }

  if( trans_p == NULL ){
  	trans->next = *trans_list_head;
  	*trans_list_head = trans;
  }else{
    trans->next = trans_p->next;
    trans_p->next = trans;
  }

  return 0;

error:
  if( trans ){
    _rhp_free(trans);
  }
  return -1;
}


static int _rhp_cfg_parse_ikesa_transform(xmlNodePtr node,void* ctx)
{
  rhp_cfg_ikesa* cfg_ikesa = (rhp_cfg_ikesa*)ctx;
  int trans_type = (int)cfg_ikesa->cb[0];
  rhp_cfg_transform** trans_list_head;

  switch( trans_type ){
    case RHP_PROTO_IKE_TRANSFORM_TYPE_ENCR:
      trans_list_head = &(cfg_ikesa->encr_trans_list);
      break;
    case RHP_PROTO_IKE_TRANSFORM_TYPE_PRF:
      trans_list_head = &(cfg_ikesa->prf_trans_list);
      break;
    case RHP_PROTO_IKE_TRANSFORM_TYPE_INTEG:
      trans_list_head = &(cfg_ikesa->integ_trans_list);
      break;
    case RHP_PROTO_IKE_TRANSFORM_TYPE_DH:
      trans_list_head = &(cfg_ikesa->dh_trans_list);
      break;
    default:
      RHP_BUG("%d",trans_type);
      goto error;
  }

  if( rhp_cfg_add_transform_list(node,trans_type,trans_list_head) ){
    RHP_BUG("");
    goto error;
  }

  return 0;

error:
  return -1;
}


static int _rhp_cfg_parse_ikesa_transforms(xmlNodePtr node,void* ctx)
{
  rhp_cfg_ikesa* cfg_ikesa = (rhp_cfg_ikesa*)ctx;
  char* name;
  int trans_type;
  int ret_len;
  int err = 0;

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),
      RHP_XML_DT_STRING,&name,&ret_len,NULL,0) ){
    RHP_BUG("");
    goto error;
  }

  trans_type = rhp_cfg_transform_type_str2id(name);
  if( trans_type < 0 ){
    RHP_BUG("");
    goto error;
  }

  cfg_ikesa->cb[0] = trans_type;

  err = rhp_xml_enum_tags(node,(xmlChar*)"transform",_rhp_cfg_parse_ikesa_transform,cfg_ikesa,1);
  if( err == -ENOENT ){
    err = 0;
  }else if( err ){
    RHP_BUG("");
    goto error;
  }

  return 0;

error:
  return -1;
}


rhp_cfg_ikesa* rhp_cfg_parse_ikesa_security(xmlNodePtr node)
{
  rhp_cfg_ikesa* cfg_ikesa;
  int err = 0;

  cfg_ikesa = (rhp_cfg_ikesa*)_rhp_malloc(sizeof(rhp_cfg_ikesa));
  if( cfg_ikesa == NULL ){
    return NULL;
  }

  memset(cfg_ikesa,0,sizeof(rhp_cfg_ikesa));

  cfg_ikesa->tag[0] = '#';
  cfg_ikesa->tag[1] = 'C';
  cfg_ikesa->tag[2] = 'I';
  cfg_ikesa->tag[3] = 'K';

  cfg_ikesa->protocol_id = RHP_PROTO_IKE_PROTOID_IKE;

  err = rhp_xml_enum_tags(node,(xmlChar*)"transforms",_rhp_cfg_parse_ikesa_transforms,cfg_ikesa,1);
  if( err == -ENOENT ){
    err = 0;
  }else if( err ){
    RHP_BUG("");
    rhp_cfg_free_ikesa_security(cfg_ikesa);
    return NULL;
  }

  if( cfg_ikesa->encr_trans_list == NULL || cfg_ikesa->prf_trans_list == NULL ||
      cfg_ikesa->integ_trans_list == NULL || cfg_ikesa->dh_trans_list == NULL ){
    RHP_TRC(0,RHPTRCID_CFG_NO_IKESA,"xxxx",cfg_ikesa->encr_trans_list ,cfg_ikesa->prf_trans_list ,cfg_ikesa->integ_trans_list ,cfg_ikesa->dh_trans_list );
    rhp_cfg_free_ikesa_security(cfg_ikesa);
    return NULL;
  }

  _rhp_cfg_trc_dump_ikesa(cfg_ikesa);
  return cfg_ikesa;
}


static int _rhp_cfg_parse_ikesa_security(xmlNodePtr node,void* ctx)
{
  rhp_cfg_ikesa* cfg_ikesa = rhp_cfg_parse_ikesa_security(node);

  if( cfg_ikesa == NULL ){
    return -1;
  }

  rhp_ikesa_config = cfg_ikesa;
  return 0;
}


static int _rhp_cfg_parse_childsa_transform(xmlNodePtr node,void* ctx)
{
  rhp_cfg_childsa* cfg_childsa = (rhp_cfg_childsa*)ctx;
  int trans_type = (int)cfg_childsa->cb[0];
  rhp_cfg_transform** trans_list_head;

  switch( trans_type ){
    case RHP_PROTO_IKE_TRANSFORM_TYPE_ENCR:
      trans_list_head = &(cfg_childsa->encr_trans_list);
      break;
    case RHP_PROTO_IKE_TRANSFORM_TYPE_INTEG:
      trans_list_head = &(cfg_childsa->integ_trans_list);
      break;
    case RHP_PROTO_IKE_TRANSFORM_TYPE_ESN:
      trans_list_head = &(cfg_childsa->esn_trans);
      break;
    default:
      RHP_BUG("%d",trans_type);
      goto error;
  }

  if( rhp_cfg_add_transform_list(node,trans_type,trans_list_head) ){
    RHP_BUG("");
    goto error;
  }

  return 0;

error:
    return -1;
}


static int _rhp_cfg_parse_childsa_transforms(xmlNodePtr node,void* ctx)
{
  rhp_cfg_childsa* cfg_childsa = (rhp_cfg_childsa*)ctx;
  char* name;
  int trans_type;
  int ret_len;
  int err = 0;

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"name"),
      RHP_XML_DT_STRING,&name,&ret_len,NULL,0) ){
    RHP_BUG("");
    goto error;
  }

  trans_type = rhp_cfg_transform_type_str2id(name);
  if( trans_type < 0 ){
    RHP_BUG("");
    goto error;
  }

  cfg_childsa->cb[0] = trans_type;

  err = rhp_xml_enum_tags(node,(xmlChar*)"transform",_rhp_cfg_parse_childsa_transform,cfg_childsa,1);
  if( err == -ENOENT ){
    err = 0;
  }else if( err ){
    RHP_BUG("");
    goto error;
  }

  return 0;

error:
  return -1;
}


rhp_cfg_childsa* rhp_cfg_parse_childsa_security(xmlNodePtr node)
{
  rhp_cfg_childsa* cfg_childsa;
  int err = 0;

  cfg_childsa = (rhp_cfg_childsa*)_rhp_malloc(sizeof(rhp_cfg_childsa));;
  if( cfg_childsa == NULL ){
    return NULL;
  }

  memset(cfg_childsa,0,sizeof(rhp_cfg_childsa));

  cfg_childsa->tag[0] = '#';
  cfg_childsa->tag[1] = 'C';
  cfg_childsa->tag[2] = 'C';
  cfg_childsa->tag[3] = 'H';

  cfg_childsa->protocol_id = RHP_PROTO_IKE_PROTOID_ESP;

  err = rhp_xml_enum_tags(node,(xmlChar*)"transforms",_rhp_cfg_parse_childsa_transforms,cfg_childsa,1);
  if( err == -ENOENT ){
    err = 0;
  }else if( err ){
    RHP_BUG("");
    rhp_cfg_free_childsa_security(cfg_childsa);
    return NULL;
  }

  if( cfg_childsa->esn_trans == NULL || cfg_childsa->encr_trans_list == NULL ||
      cfg_childsa->integ_trans_list == NULL ){
    RHP_TRC(0,RHPTRCID_CFG_NO_CHILDSA,"xxx",cfg_childsa->encr_trans_list ,cfg_childsa->integ_trans_list ,cfg_childsa->esn_trans );
    rhp_cfg_free_childsa_security(cfg_childsa);
    return NULL;
  }

  _rhp_cfg_trc_dump_childsa(cfg_childsa);
  return cfg_childsa;
}


rhp_cfg_ikesa* rhp_cfg_default_ikesa_security()
{
  return &_rhp_ikesa_config_def;
}


rhp_cfg_childsa* rhp_cfg_default_childsa_security()
{
  return &_rhp_childsa_config_def;
}


rhp_cfg_ikesa* rhp_cfg_get_ikesa_security()
{
  return rhp_ikesa_config;
}


rhp_cfg_childsa* rhp_cfg_get_childsa_security()
{
  return rhp_childsa_config;
}



void rhp_cfg_free_ikev1_ikesa_security(rhp_cfg_ikev1_ikesa* cfg_ikesa)
{
  if( cfg_ikesa != &_rhp_ikev1_ikesa_config_def ){

    rhp_cfg_ikev1_transform *tmp,*tmp2;

    tmp = cfg_ikesa->trans_list;
    while( tmp ){
      tmp2 = tmp->next;
      _rhp_free(tmp);
      tmp = tmp2;
    }
  }
}


void rhp_cfg_free_ikev1_ipsecsa_security(rhp_cfg_ikev1_ipsecsa* cfg_ipsecsa)
{
  if( cfg_ipsecsa != &_rhp_ikev1_ipsecsa_config_def ){

    rhp_cfg_ikev1_transform *tmp,*tmp2;

    tmp = cfg_ipsecsa->trans_list;
    while( tmp ){
      tmp2 = tmp->next;
      _rhp_free(tmp);
      tmp = tmp2;
    }
  }
}


static int _rhp_cfg_parse_ikev1_ikesa_transform(xmlNodePtr node,void* ctx)
{
  rhp_cfg_ikev1_ikesa* cfg_ikesa = (rhp_cfg_ikev1_ikesa*)ctx;
  char* name;
  int ret_len;
  rhp_cfg_ikev1_transform *trans = NULL,*trans_c = NULL,*trans_p = NULL;

  trans = (rhp_cfg_ikev1_transform*)_rhp_malloc(sizeof(rhp_cfg_ikev1_transform));
  if( trans == NULL ){
    return -1;
  }

  memset(trans,0,sizeof(rhp_cfg_ikev1_transform));

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"priority"),
      RHP_XML_DT_INT,&trans->priority,&ret_len,NULL,0) ){
    RHP_BUG("");
    goto error;
  }

  {
		if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"encryption"),
				RHP_XML_DT_STRING,&name,&ret_len,NULL,0) ){
			RHP_BUG("");
			goto error;
		}

		trans->enc_alg = rhp_cfg_ikev1_ikesa_attr_value_str2id(RHP_PROTO_IKEV1_P1_ATTR_TYPE_ENCRYPTION,name);
		if( trans->enc_alg < 0 ){
			RHP_BUG("");
			goto error;
		}

    if( trans->enc_alg == RHP_PROTO_IKEV1_P1_ATTR_ENC_AES_CBC ){
      if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"key_bits"),
          RHP_XML_DT_INT,&trans->key_bits_len,&ret_len,NULL,0) ){
        RHP_BUG("");
        goto error;
      }
	  }
  }

  {
		if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"hash"),
				RHP_XML_DT_STRING,&name,&ret_len,NULL,0) ){
			RHP_BUG("");
			goto error;
		}

		trans->hash_alg = rhp_cfg_ikev1_ikesa_attr_value_str2id(RHP_PROTO_IKEV1_P1_ATTR_TYPE_HASH,name);
		if( trans->hash_alg < 0 ){
			RHP_BUG("");
			goto error;
		}
  }

  {
		if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"group"),
				RHP_XML_DT_STRING,&name,&ret_len,NULL,0) ){
			RHP_BUG("");
			goto error;
		}

		trans->dh_group = rhp_cfg_ikev1_ikesa_attr_value_str2id(RHP_PROTO_IKEV1_P1_ATTR_TYPE_GROUP_DESC,name);
		if( trans->dh_group < 0 ){
			RHP_BUG("");
			goto error;
		}
  }

  trans_c = cfg_ikesa->trans_list;
  while( trans_c ){

    if( trans_c->priority > trans->priority ){
      break;
    }
    trans_p = trans_c;
    trans_c = trans_c->next;
  }

  if( trans_p == NULL ){
  	trans->next = cfg_ikesa->trans_list;
  	cfg_ikesa->trans_list = trans;
  }else{
    trans->next = trans_p->next;
    trans_p->next = trans;
  }

  return 0;

error:
  return -1;
}


rhp_cfg_ikev1_ikesa* rhp_cfg_parse_ikev1_ikesa_security(xmlNodePtr node)
{
  rhp_cfg_ikev1_ikesa* cfg_ikesa;
  int err = 0;

  cfg_ikesa = (rhp_cfg_ikev1_ikesa*)_rhp_malloc(sizeof(rhp_cfg_ikev1_ikesa));
  if( cfg_ikesa == NULL ){
    return NULL;
  }

  memset(cfg_ikesa,0,sizeof(rhp_cfg_ikev1_ikesa));

  cfg_ikesa->tag[0] = '#';
  cfg_ikesa->tag[1] = 'C';
  cfg_ikesa->tag[2] = 'I';
  cfg_ikesa->tag[3] = 'K';


  err = rhp_xml_enum_tags(node,(xmlChar*)"transform",_rhp_cfg_parse_ikev1_ikesa_transform,cfg_ikesa,1);
  if( err == -ENOENT ){
    err = 0;
  }else if( err ){
    RHP_BUG("");
    rhp_cfg_free_ikev1_ikesa_security(cfg_ikesa);
    return NULL;
  }

  if( cfg_ikesa->trans_list == NULL ){
    RHP_TRC(0,RHPTRCID_CFG_IKEV1_NO_IKESA,"x",cfg_ikesa->trans_list);
    rhp_cfg_free_ikev1_ikesa_security(cfg_ikesa);
    return NULL;
  }

  _rhp_cfg_trc_dump_ikev1_ikesa(cfg_ikesa);
  return cfg_ikesa;
}


static int _rhp_cfg_parse_ikev1_ipsecsa_transform(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
  rhp_cfg_ikev1_ipsecsa* cfg_ipsecsa = (rhp_cfg_ikev1_ipsecsa*)ctx;
  char* name;
  int ret_len;
  rhp_cfg_ikev1_transform *trans = NULL,*trans_c = NULL,*trans_p = NULL;

  trans = (rhp_cfg_ikev1_transform*)_rhp_malloc(sizeof(rhp_cfg_ikev1_transform));
  if( trans == NULL ){
    return -1;
  }

  memset(trans,0,sizeof(rhp_cfg_ikev1_transform));

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"priority"),
      RHP_XML_DT_INT,&trans->priority,&ret_len,NULL,0) ){
    RHP_BUG("");
    goto error;
  }

  {
		if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"encryption"),
				RHP_XML_DT_STRING,&name,&ret_len,NULL,0) ){
			RHP_BUG("");
			goto error;
		}

		trans->trans_id = rhp_cfg_ikev1_transform_id_str2id(name);
		if( trans->trans_id < 0 ){
			RHP_BUG("");
			goto error;
		}

    if( trans->trans_id == RHP_PROTO_IKEV1_TF_ESP_AES_CBC ){
      if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"key_bits"),
          RHP_XML_DT_INT,&trans->key_bits_len,&ret_len,NULL,0) ){
        RHP_BUG("");
        goto error;
      }
	  }
  }

  {
		if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"authentication"),
				RHP_XML_DT_STRING,&name,&ret_len,NULL,0) ){
			RHP_BUG("");
			goto error;
		}

		trans->auth_alg = rhp_cfg_ikev1_ipsecsa_attr_value_str2id(RHP_PROTO_IKEV1_P2_ATTR_TYPE_AUTH,name);
		if( trans->auth_alg < 0 ){
			RHP_BUG("");
			goto error;
		}
  }

  {
		err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"group"),
				RHP_XML_DT_STRING,&name,&ret_len,NULL,0);
		if( err && err != -ENOENT ){

			RHP_BUG("%d",err);
			goto error;

		}else if( !err ){

			trans->dh_group = rhp_cfg_ikev1_ipsecsa_attr_value_str2id(RHP_PROTO_IKEV1_P2_ATTR_TYPE_GROUP_DESC,name);
			if( trans->dh_group < 0 ){
				RHP_BUG("");
				goto error;
			}
		}
  }

  {
		if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"esn"),
				RHP_XML_DT_STRING,&name,&ret_len,NULL,0) ){
			RHP_BUG("");
			goto error;
		}

		trans->esn = rhp_cfg_ikev1_ipsecsa_attr_value_str2id(RHP_PROTO_IKEV1_P2_ATTR_TYPE_ESN,name);
		if( trans->esn < 0 ){
			RHP_BUG("");
			goto error;
		}
  }

  trans_c = cfg_ipsecsa->trans_list;
  while( trans_c ){

    if( trans_c->priority > trans->priority ){
      break;
    }
    trans_p = trans_c;
    trans_c = trans_c->next;
  }

  if( trans_p == NULL ){
  	trans->next = cfg_ipsecsa->trans_list;
  	cfg_ipsecsa->trans_list = trans;
  }else{
    trans->next = trans_p->next;
    trans_p->next = trans;
  }

  return 0;

error:
  return -1;
}


rhp_cfg_ikev1_ipsecsa* rhp_cfg_parse_ikev1_ipsecsa_security(xmlNodePtr node)
{
  rhp_cfg_ikev1_ipsecsa* cfg_ipsecsa;
  int err = 0;

  cfg_ipsecsa = (rhp_cfg_ikev1_ipsecsa*)_rhp_malloc(sizeof(rhp_cfg_ikev1_ipsecsa));
  if( cfg_ipsecsa == NULL ){
    return NULL;
  }

  memset(cfg_ipsecsa,0,sizeof(rhp_cfg_ikev1_ipsecsa));

  cfg_ipsecsa->tag[0] = '#';
  cfg_ipsecsa->tag[1] = 'C';
  cfg_ipsecsa->tag[2] = 'C';
  cfg_ipsecsa->tag[3] = 'H';

  cfg_ipsecsa->protocol_id = RHP_PROTO_IKEV1_PROP_PROTO_ID_ESP;

  err = rhp_xml_enum_tags(node,(xmlChar*)"transform",_rhp_cfg_parse_ikev1_ipsecsa_transform,cfg_ipsecsa,1);
  if( err == -ENOENT ){
    err = 0;
  }else if( err ){
    RHP_BUG("");
    rhp_cfg_free_ikev1_ipsecsa_security(cfg_ipsecsa);
    return NULL;
  }

  if( cfg_ipsecsa->trans_list == NULL ){
    RHP_TRC(0,RHPTRCID_CFG_IKEV1_NO_IPSECSA,"x",cfg_ipsecsa->trans_list);
    rhp_cfg_free_ikev1_ipsecsa_security(cfg_ipsecsa);
    return NULL;
  }

  _rhp_cfg_trc_dump_ikev1_ipsecsa(cfg_ipsecsa);
  return cfg_ipsecsa;
}



rhp_cfg_ikev1_ikesa* rhp_cfg_ikev1_default_ikesa_security()
{
  return &_rhp_ikev1_ikesa_config_def;
}


rhp_cfg_ikev1_ipsecsa* rhp_cfg_ikev1_default_ipsecsa_security()
{
  return &_rhp_ikev1_ipsecsa_config_def;
}


rhp_cfg_ikev1_ikesa* rhp_cfg_ikev1_get_ikesa_security()
{
  return rhp_ikev1_ikesa_config;
}


static int _rhp_cfg_parse_ikev1_ikesa_security(xmlNodePtr node,void* ctx)
{
	rhp_cfg_ikev1_ikesa* cfg_ikesa = rhp_cfg_parse_ikev1_ikesa_security(node);

  if( cfg_ikesa == NULL ){
    return -1;
  }

  rhp_ikev1_ikesa_config = cfg_ikesa;
  return 0;
}


static int _rhp_cfg_parse_ikev1_ipsecsa_security(xmlNodePtr node,void* ctx)
{
	rhp_cfg_ikev1_ipsecsa* cfg_ipsecsa = rhp_cfg_parse_ikev1_ipsecsa_security(node);

  if( cfg_ipsecsa == NULL ){
    return -1;
  }

  rhp_ikev1_ipsecsa_config = cfg_ipsecsa;
  return 0;
}


rhp_cfg_ikev1_ipsecsa* rhp_cfg_ikev1_get_ipsecsa_security()
{
  return rhp_ikev1_ipsecsa_config;
}



void rhp_cfg_dump_res_sa_prop(rhp_res_sa_proposal* res_prop)
{
  RHP_TRC(0,RHPTRCID_CFG_DUMP_RES_SA_PROP,"xbbbpwddwdwdwdwdd",res_prop,res_prop->number,res_prop->protocol_id,res_prop->spi_len,RHP_PROTO_SPI_MAX_SIZE,res_prop->spi,res_prop->encr_id,res_prop->encr_key_bits,res_prop->encr_priority,res_prop->prf_id,res_prop->prf_priority,res_prop->integ_id,res_prop->integ_priority,res_prop->dhgrp_id,res_prop->dhgrp_priority,res_prop->esn,res_prop->esn_priority,res_prop->pfs);
}


void rhp_cfg_dump_res_ikev1_sa_prop(rhp_res_ikev1_sa_proposal* res_prop)
{
  RHP_TRC(0,RHPTRCID_CFG_DUMP_RES_IKEV1_SA_PROP,"xbbbbpdddduuddddd",res_prop,res_prop->number,res_prop->protocol_id,res_prop->spi_len,res_prop->trans_number,RHP_PROTO_SPI_MAX_SIZE,res_prop->spi,res_prop->enc_alg,res_prop->hash_alg,res_prop->auth_method,res_prop->dh_group,res_prop->life_time,res_prop->life_bytes,res_prop->trans_id,res_prop->encap_mode,res_prop->auth_alg,res_prop->esn,res_prop->key_bits_len);
}


#define RHP_CFG_MATCH_IKESA_TRANS_MASK_ENCR		1
#define RHP_CFG_MATCH_IKESA_TRANS_MASK_PRF		2
#define RHP_CFG_MATCH_IKESA_TRANS_MASK_INTEG	4
#define RHP_CFG_MATCH_IKESA_TRANS_MASK_DH			8
#define RHP_CFG_MATCH_IKESA_TRANS_MASK_ALL		(RHP_CFG_MATCH_IKESA_TRANS_MASK_ENCR | RHP_CFG_MATCH_IKESA_TRANS_MASK_PRF | RHP_CFG_MATCH_IKESA_TRANS_MASK_INTEG | RHP_CFG_MATCH_IKESA_TRANS_MASK_DH)

int rhp_cfg_match_ikesa_proposal(rhp_ikev2_proposal* prop,rhp_res_sa_proposal* res_prop)
{
  rhp_cfg_transform* cfg_trans;
  unsigned long mask = 0;
  rhp_ikev2_transform* trans = prop->trans_list_head;

  RHP_TRC(0,RHPTRCID_CFG_MATCH_IKESA_PROPOSAL,"xx",prop,res_prop);

  RHP_LOCK(&rhp_cfg_lock);

  if( prop->proph == NULL ){
    RHP_BUG("");
    goto error;
  }

  if( prop->proph->protocol != RHP_PROTO_IKE_PROTOID_IKE ){
    RHP_TRC(0,RHPTRCID_CFG_MATCH_IKESA_PROPOSAL_NOT_PROTO_IKE,"xxb",prop,res_prop,prop->proph->protocol);
    goto error;
  }

  if( prop->proph->spi_len != 0 && prop->proph->spi_len != RHP_PROTO_IKE_SPI_SIZE  ){
    RHP_TRC(0,RHPTRCID_CFG_MATCH_IKESA_PROPOSAL_BAD_SPI_LEN,"xxbb",prop,res_prop,prop->proph->spi_len,RHP_PROTO_IKE_SPI_SIZE);
    goto error;
  }


  while( trans ){

    unsigned long mask_bit;

    switch( trans->type ){

    case RHP_PROTO_IKE_TRANSFORM_TYPE_ENCR:
      mask_bit = RHP_CFG_MATCH_IKESA_TRANS_MASK_ENCR;
      cfg_trans = rhp_ikesa_config->encr_trans_list;
      break;

    case RHP_PROTO_IKE_TRANSFORM_TYPE_PRF:
      mask_bit = RHP_CFG_MATCH_IKESA_TRANS_MASK_PRF;
      cfg_trans = rhp_ikesa_config->prf_trans_list;
      break;

    case RHP_PROTO_IKE_TRANSFORM_TYPE_INTEG:
      mask_bit = RHP_CFG_MATCH_IKESA_TRANS_MASK_INTEG;
      cfg_trans = rhp_ikesa_config->integ_trans_list;
      break;

    case RHP_PROTO_IKE_TRANSFORM_TYPE_DH:
      mask_bit = RHP_CFG_MATCH_IKESA_TRANS_MASK_DH;
      cfg_trans = rhp_ikesa_config->dh_trans_list;
      break;

    default:
      RHP_BUG("");
      goto error;
    }

    if( mask & mask_bit ){
      goto next;
    }

    while( cfg_trans ){

      if( cfg_trans->id == trans->id ){

      	switch( cfg_trans->type ){

      	case RHP_PROTO_IKE_TRANSFORM_TYPE_ENCR:
      		if( cfg_trans->id == RHP_PROTO_IKE_TRANSFORM_ID_ENCR_AES_CBC ){
      			if( cfg_trans->key_bits_len != trans->key_bits_len ){
      				goto next2;
      			}
      		}
      		res_prop->encr_id = cfg_trans->id;
      		res_prop->encr_key_bits = cfg_trans->key_bits_len;
      		res_prop->encr_priority = cfg_trans->priority;
      		break;

      	case RHP_PROTO_IKE_TRANSFORM_TYPE_PRF:
      		res_prop->prf_id = cfg_trans->id;
      		res_prop->prf_priority = cfg_trans->priority;
      		break;

      	case RHP_PROTO_IKE_TRANSFORM_TYPE_INTEG:
      		res_prop->integ_id = cfg_trans->id;
      		res_prop->integ_priority = cfg_trans->priority;
      		break;

      	case RHP_PROTO_IKE_TRANSFORM_TYPE_DH:
      		res_prop->dhgrp_id = cfg_trans->id;
      		res_prop->dhgrp_priority = cfg_trans->priority;
      		break;

      	default:
      		RHP_BUG("");
      		goto error;
        }

      	mask |= mask_bit;
        break;
      }

next2:
      cfg_trans = cfg_trans->next;
    }

next:
    if( mask == RHP_CFG_MATCH_IKESA_TRANS_MASK_ALL ){
      break;
    }

    trans = trans->next;
  }

  if( mask != RHP_CFG_MATCH_IKESA_TRANS_MASK_ALL ){
    RHP_TRC(0,RHPTRCID_CFG_MATCH_IKESA_PROPOSAL_TRAS_NOT_ENOUGH,"xxLB",prop,res_prop,"MATCH_IKESA_TRANS_MASK",sizeof(unsigned long),&mask);
    goto error;
  }

  res_prop->number = prop->proph->proposal_number;
  res_prop->protocol_id = prop->proph->protocol;

  res_prop->spi_len = prop->proph->spi_len;
  if( prop->proph->spi_len ){
    memcpy(res_prop->spi,(u8*)(prop->proph+1),prop->proph->spi_len);
  }

  RHP_UNLOCK(&rhp_cfg_lock);

  rhp_cfg_dump_res_sa_prop(res_prop);
  RHP_TRC(0,RHPTRCID_CFG_MATCH_IKESA_PROPOSAL_RTRN,"xx",prop,res_prop);
  return 0;

error:
  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_CFG_MATCH_IKESA_PROPOSAL_ERR,"xx",prop,res_prop);
  return -1;
}

#define RHP_CFG_MATCH_CHILDSA_TRANS_MASK_ENCR				1
#define RHP_CFG_MATCH_CHILDSA_TRANS_MASK_INTEG			2
#define RHP_CFG_MATCH_CHILDSA_TRANS_MASK_PFS_DH			4
#define RHP_CFG_MATCH_CHILDSA_TRANS_MASK_ESN				8
#define RHP_CFG_MATCH_CHILDSA_TRANS_MASK_ALL				(RHP_CFG_MATCH_IKESA_TRANS_MASK_ENCR | RHP_CFG_MATCH_CHILDSA_TRANS_MASK_INTEG | RHP_CFG_MATCH_CHILDSA_TRANS_MASK_PFS_DH | RHP_CFG_MATCH_CHILDSA_TRANS_MASK_ESN)

int rhp_cfg_match_childsa_proposal(rhp_ikev2_proposal* prop,rhp_res_sa_proposal* res_prop,int pfs)
{
	int err = -EINVAL;
  rhp_cfg_transform* cfg_trans;
  unsigned long mask = 0;
  rhp_ikev2_transform* trans = prop->trans_list_head;

  RHP_TRC(0,RHPTRCID_CFG_MATCH_CHILDSA_PROPOSAL,"xxd",prop,res_prop,pfs);

  RHP_LOCK(&rhp_cfg_lock);

  if( prop->proph == NULL ){
    RHP_BUG("");
    goto error;
  }

  if( prop->proph->protocol != RHP_PROTO_IKE_PROTOID_ESP ){
    RHP_TRC(0,RHPTRCID_CFG_MATCH_CHILDSA_PROPOSAL_NOT_PROTO_ESP,"xxb",prop,res_prop,prop->proph->protocol);
    goto error;
  }

  if( prop->proph->spi_len != RHP_PROTO_IPSEC_SPI_SIZE  ){
    RHP_TRC(0,RHPTRCID_CFG_MATCH_CHILDSA_PROPOSAL_BAD_SPI_LEN,"xxbb",prop,res_prop,prop->proph->spi_len,RHP_PROTO_IPSEC_SPI_SIZE);
    goto error;
  }

  if( !pfs ){
    mask |= RHP_CFG_MATCH_CHILDSA_TRANS_MASK_PFS_DH;
  }

  while( trans ){

    unsigned long mask_bit;

    switch( trans->type ){

      case RHP_PROTO_IKE_TRANSFORM_TYPE_ENCR:
        mask_bit = RHP_CFG_MATCH_CHILDSA_TRANS_MASK_ENCR;
        cfg_trans = rhp_childsa_config->encr_trans_list;
        break;

      case RHP_PROTO_IKE_TRANSFORM_TYPE_INTEG:
        mask_bit = RHP_CFG_MATCH_CHILDSA_TRANS_MASK_INTEG;
        cfg_trans = rhp_childsa_config->integ_trans_list;
        break;

      case RHP_PROTO_IKE_TRANSFORM_TYPE_ESN:
        mask_bit = RHP_CFG_MATCH_CHILDSA_TRANS_MASK_ESN;
        cfg_trans = rhp_childsa_config->esn_trans;
        break;

      case RHP_PROTO_IKE_TRANSFORM_TYPE_DH:
        mask_bit = RHP_CFG_MATCH_CHILDSA_TRANS_MASK_PFS_DH;
        cfg_trans = rhp_ikesa_config->dh_trans_list;
        break;

      default:
        RHP_BUG("");
        goto error;
    }

    if( mask & mask_bit ){
      goto next;
    }

    while( cfg_trans ){

      if( cfg_trans->id == trans->id ){

        switch( cfg_trans->type ){

          case RHP_PROTO_IKE_TRANSFORM_TYPE_ENCR:
            if( cfg_trans->id == RHP_PROTO_IKE_TRANSFORM_ID_ENCR_AES_CBC ){
              if( cfg_trans->key_bits_len != trans->key_bits_len ){
                goto next2;
              }
            }
            res_prop->encr_id = cfg_trans->id;
            res_prop->encr_key_bits = cfg_trans->key_bits_len;
            res_prop->encr_priority = cfg_trans->priority;
            break;

          case RHP_PROTO_IKE_TRANSFORM_TYPE_INTEG:
            res_prop->integ_id = cfg_trans->id;
            res_prop->integ_priority = cfg_trans->priority;
            break;

          case RHP_PROTO_IKE_TRANSFORM_TYPE_ESN:
            res_prop->esn = ( cfg_trans->id == RHP_PROTO_IKE_TRANSFORM_ESN_ENABLE ? 1 : 0);
            res_prop->esn_priority = cfg_trans->priority;
            break;

          case RHP_PROTO_IKE_TRANSFORM_TYPE_DH:
            res_prop->dhgrp_id = cfg_trans->id;
            res_prop->dhgrp_priority = cfg_trans->priority;
            break;

          default:
            RHP_BUG("");
            goto error;
        }

        mask |= mask_bit;
        break;
      }

next2:
      cfg_trans = cfg_trans->next;
    }

next:
    if( mask == RHP_CFG_MATCH_CHILDSA_TRANS_MASK_ALL ){
      break;
    }

    trans = trans->next;
  }


  if( !(mask & RHP_CFG_MATCH_CHILDSA_TRANS_MASK_ENCR) ||
  		!(mask & RHP_CFG_MATCH_CHILDSA_TRANS_MASK_INTEG) ||
  		!(mask & RHP_CFG_MATCH_CHILDSA_TRANS_MASK_PFS_DH) ){

  	RHP_TRC(0,RHPTRCID_CFG_MATCH_CHILDSA_PROPOSAL_TRANS_NOT_ENOUGH,"xxLB",prop,res_prop,"MATCH_CHILDSA_TRANS_MASK",sizeof(unsigned long),&mask);

    if( pfs &&
    	!(mask & RHP_CFG_MATCH_CHILDSA_TRANS_MASK_PFS_DH) ){

    	err = RHP_STATUS_INVALID_IKEV2_MESG_PFS_REQUIRED;
    }

  	goto error;
  }

  if( !(mask & RHP_CFG_MATCH_CHILDSA_TRANS_MASK_ESN) ){

  	if( rhp_childsa_config->esn_trans->id != RHP_PROTO_IKE_TRANSFORM_ESN_ENABLE ){
  		RHP_TRC(0,RHPTRCID_CFG_MATCH_CHILDSA_PROPOSAL_TRANS_ESN_NOT_ENABLED,"xx",prop,res_prop);
  		goto error;
  	}

  	res_prop->esn = 1;
	}

  res_prop->number = prop->proph->proposal_number;
  res_prop->protocol_id = prop->proph->protocol;

  res_prop->spi_len = prop->proph->spi_len;
  if( prop->proph->spi_len ){
    memcpy(res_prop->spi,(u8*)(prop->proph+1),prop->proph->spi_len);
  }

  RHP_UNLOCK(&rhp_cfg_lock);

  rhp_cfg_dump_res_sa_prop(res_prop);
  RHP_TRC(0,RHPTRCID_CFG_MATCH_CHILDSA_PROPOSAL_RTRN,"xx",prop,res_prop);
  return 0;

error:
  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_CFG_MATCH_CHILDSA_PROPOSAL_ERR,"xxE",prop,res_prop,err);
  return err;
}


int rhp_cfg_match_ikev1_ikesa_proposal(rhp_ikev1_proposal* prop,rhp_res_ikev1_sa_proposal* res_prop)
{
  rhp_cfg_ikev1_transform* cfg_trans;
  rhp_ikev1_transform* trans = prop->trans_list_head;
  int found = 0;
  int auth_method = 0;

  RHP_TRC(0,RHPTRCID_CFG_MATCH_IKEV1_IKESA_PROPOSAL,"xxdud",prop,res_prop,res_prop->auth_method,res_prop->life_time,res_prop->xauth_method);

  RHP_LOCK(&rhp_cfg_lock);

  if( prop->proph == NULL ){
    RHP_BUG("");
    goto error;
  }

  if( prop->proph->protocol_id != RHP_PROTO_IKEV1_PROP_PROTO_ID_ISAKMP ){
    RHP_TRC(0,RHPTRCID_CFG_MATCH_IKEV1_IKESA_PROPOSAL_NOT_PROTO_IKE,"xxb",prop,res_prop,prop->proph->protocol_id);
    goto error;
  }

  if( prop->proph->spi_len != 0 && prop->proph->spi_len != RHP_PROTO_IKE_SPI_SIZE  ){
    RHP_TRC(0,RHPTRCID_CFG_MATCH_IKEV1_IKESA_PROPOSAL_BAD_SPI_LEN,"xxbb",prop,res_prop,prop->proph->spi_len,RHP_PROTO_IKE_SPI_SIZE);
    goto error;
  }


  if( res_prop->auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ){
  	auth_method = RHP_PROTO_IKEV1_P1_ATTR_AUTH_METHOD_PSK;
  }else if( res_prop->auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){
  	auth_method = RHP_PROTO_IKEV1_P1_ATTR_AUTH_METHOD_RSASIG;
  }else{
  	if( res_prop->xauth_method ){
  		RHP_BUG("%d",res_prop->auth_method);
  		goto error;
  	}
  }

  while( trans ){

    RHP_TRC(0,RHPTRCID_CFG_MATCH_IKEV1_IKESA_PROPOSAL_PROTO_TRANS,"xxxxxbbdddduuddddu",prop,res_prop,trans,trans->next,trans->transh,trans->trans_number,trans->trans_id,trans->enc_alg,trans->hash_alg,trans->auth_method,trans->dh_group,trans->life_time,trans->life_bytes,trans->encap_mode,trans->auth_alg,trans->esn,trans->key_bits_len,res_prop->life_time);

    cfg_trans = rhp_ikev1_ikesa_config->trans_list;
    while( cfg_trans ){

      RHP_TRC(0,RHPTRCID_CFG_MATCH_IKEV1_IKESA_PROPOSAL_CFG_TRANS,"xdddddddu",cfg_trans,cfg_trans->priority,cfg_trans->enc_alg,cfg_trans->hash_alg,cfg_trans->dh_group,cfg_trans->key_bits_len,res_prop->xauth_method,auth_method,res_prop->life_time);

    	if( cfg_trans->enc_alg == trans->enc_alg &&
    			cfg_trans->hash_alg == trans->hash_alg &&
    			cfg_trans->dh_group == trans->dh_group &&
    			cfg_trans->key_bits_len == trans->key_bits_len &&
    			((res_prop->xauth_method && res_prop->xauth_method == trans->auth_method) ||
    				auth_method == trans->auth_method) ){

    		res_prop->cfg_priority = cfg_trans->priority;
    		res_prop->trans_number = trans->trans_number;
    		res_prop->enc_alg = cfg_trans->enc_alg;
    		res_prop->hash_alg = cfg_trans->hash_alg;
    		res_prop->dh_group = cfg_trans->dh_group;
    		res_prop->key_bits_len = cfg_trans->key_bits_len;

    		if( trans->life_time &&
    				(!res_prop->life_time ||
    				 trans->life_time < res_prop->life_time) ){

    			res_prop->life_time = trans->life_time;
    		}

    		found = 1;

    		break;
    	}

      cfg_trans = cfg_trans->next;
    }

    if( found ){
    	break;
    }

    trans = trans->next;
  }

  if( !found ){
    RHP_TRC(0,RHPTRCID_CFG_MATCH_IKEV1_IKESA_PROPOSAL_TRAS_NOT_ENOUGH,"xx",prop,res_prop);
    goto error;
  }

  res_prop->number = prop->proph->proposal_number;
  res_prop->protocol_id = prop->proph->protocol_id;

  res_prop->spi_len = prop->proph->spi_len;
  if( prop->proph->spi_len ){
    memcpy(res_prop->spi,(u8*)(prop->proph+1),prop->proph->spi_len);
  }

  RHP_UNLOCK(&rhp_cfg_lock);

  rhp_cfg_dump_res_ikev1_sa_prop(res_prop);
  RHP_TRC(0,RHPTRCID_CFG_MATCH_IKEV1_IKESA_PROPOSAL_RTRN,"xx",prop,res_prop);
  return 0;

error:
  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_CFG_MATCH_IKEV1_IKESA_PROPOSAL_ERR,"xx",prop,res_prop);
  return -1;
}


int rhp_cfg_match_ikev1_ipsecsa_proposal(rhp_ikev1_proposal* prop,rhp_res_ikev1_sa_proposal* res_prop)
{
  rhp_cfg_ikev1_transform* cfg_trans;
  rhp_ikev1_transform* trans = prop->trans_list_head;
  int found = 0;
  int dh_grp_p1 = 0;

  RHP_TRC(0,RHPTRCID_CFG_MATCH_IKEV1_IPSECSA_PROPOSAL,"xx",prop,res_prop);

  RHP_LOCK(&rhp_cfg_lock);

  if( prop->proph == NULL ){
    RHP_BUG("");
    goto error;
  }

  if( prop->proph->protocol_id != RHP_PROTO_IKEV1_PROP_PROTO_ID_ESP ){
    RHP_TRC(0,RHPTRCID_CFG_MATCH_IKEV1_IPSECSA_PROPOSAL_NOT_PROTO_IKE,"xxb",prop,res_prop,prop->proph->protocol_id);
    goto error;
  }

  if( prop->proph->spi_len != RHP_PROTO_IPSEC_SPI_SIZE  ){
    RHP_TRC(0,RHPTRCID_CFG_MATCH_IKEV1_IPSECSA_PROPOSAL_BAD_SPI_LEN,"xxbb",prop,res_prop,prop->proph->spi_len,RHP_PROTO_IPSEC_SPI_SIZE);
    goto error;
  }

  if( res_prop->dh_group ){
  	dh_grp_p1 = res_prop->dh_group;
  }

  while( trans ){

    cfg_trans = rhp_ikev1_ipsecsa_config->trans_list;
    while( cfg_trans ){

    	int dh_grp = 0;

    	if( dh_grp_p1 ){
    		dh_grp = dh_grp_p1;
    	}else if( cfg_trans->dh_group ){
    		dh_grp = cfg_trans->dh_group;
    	}

    	if( cfg_trans->trans_id == trans->trans_id &&
    			cfg_trans->auth_alg == trans->auth_alg &&
    			(!dh_grp || dh_grp == trans->dh_group) &&
    			cfg_trans->esn == trans->esn &&
    			cfg_trans->key_bits_len == trans->key_bits_len ){

    		res_prop->trans_number = trans->trans_number;
    		res_prop->trans_id = cfg_trans->trans_id;
    		res_prop->auth_alg = cfg_trans->auth_alg;
    		res_prop->dh_group = dh_grp;
    		res_prop->esn = cfg_trans->esn;
    		res_prop->key_bits_len = cfg_trans->key_bits_len;
    		res_prop->encap_mode = trans->encap_mode;

    		res_prop->rx_life_time = trans->life_time;

    		if( trans->life_time &&
    				(!res_prop->life_time ||
    				 trans->life_time < res_prop->life_time) ){

    			res_prop->life_time = trans->life_time;
    		}

    		found = 1;

    		break;
    	}

      cfg_trans = cfg_trans->next;
    }

    if( found ){
    	break;
    }

    trans = trans->next;
  }

  if( !found ){
    RHP_TRC(0,RHPTRCID_CFG_MATCH_IKEV1_IPSECSA_PROPOSAL_TRAS_NOT_ENOUGH,"xx",prop,res_prop);
    goto error;
  }

  res_prop->number = prop->proph->proposal_number;
  res_prop->protocol_id = prop->proph->protocol_id;

  res_prop->spi_len = prop->proph->spi_len;
  if( prop->proph->spi_len ){
    memcpy(res_prop->spi,(u8*)(prop->proph+1),prop->proph->spi_len);
  }

  RHP_UNLOCK(&rhp_cfg_lock);

  rhp_cfg_dump_res_ikev1_sa_prop(res_prop);
  RHP_TRC(0,RHPTRCID_CFG_MATCH_IKEV1_IPSECSA_PROPOSAL_RTRN,"xx",prop,res_prop);
  return 0;

error:
  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_CFG_MATCH_IKEV1_IPSECSA_PROPOSAL_ERR,"xx",prop,res_prop);
  return -1;
}



static int _rhp_cfg_parse_childsa_security(xmlNodePtr node,void* ctx)
{
  rhp_cfg_childsa* cfg_childsa = rhp_cfg_parse_childsa_security(node);

  if( cfg_childsa == NULL ){
    RHP_BUG("");
    return -1;
  }

  rhp_childsa_config = cfg_childsa;

  RHP_TRC(0,RHPTRCID_CFG_INIT_LOAD_CHILD_SECURITY,"x",rhp_childsa_config);

  return 0;
}


static int _rhp_cfg_parse_event_log(xmlNodePtr node,void* ctx)
{
	int err;
	int ret_len;

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,
  				(const xmlChar*)"path"),RHP_XML_DT_STRING,&rhp_main_log_file_path,&ret_len,NULL,0);
  if( err == -ENOENT ){
  	err = 0;
  }else if( err ){
    RHP_BUG("%d",err);
    return -EINVAL;
  }

  return 0;
}


static int _rhp_cfg_parse_packet_capture(xmlNodePtr node,void* ctx)
{
	int err;
	int ret_len;

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,
  				(const xmlChar*)"path"),RHP_XML_DT_STRING,&rhp_packet_capture_file_path,&ret_len,NULL,0);
  if( err == -ENOENT ){
  	err = 0;
  }else if( err ){
    RHP_BUG("%d",err);
    return -EINVAL;
  }

  return 0;
}


static int _rhp_cfg_parse_dbg_trace_file(xmlNodePtr node,void* ctx)
{
	int err;
	int ret_len;

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"main_path"),RHP_XML_DT_STRING,&rhp_gcfg_dbg_f_trace_main_path,&ret_len,NULL,0);
  if( err == -ENOENT ){
  	err = 0;
  }else if( err ){
    RHP_BUG("%d",err);
    return -EINVAL;
  }

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"syspxy_path"),RHP_XML_DT_STRING,&rhp_gcfg_dbg_f_trace_syspxy_path,&ret_len,NULL,0);
  if( err == -ENOENT ){
  	err = 0;
  }else if( err ){
    RHP_BUG("%d",err);
    return -EINVAL;
  }

  return 0;
}


int rhp_cfg_global_load(char* conf_xml_path)
{
  int err = 0;
  xmlDocPtr cfg_doc = NULL;
  xmlNodePtr cfg_root_node;

  cfg_doc = xmlParseFile(conf_xml_path);
  if( cfg_doc == NULL ){
    err = -ENOENT;
    goto error;
  }

  cfg_root_node = xmlDocGetRootElement(cfg_doc);
  if( cfg_root_node == NULL ){
    err = -ENOENT;
    goto error;
  }

  if( xmlStrcmp(cfg_root_node->name,(xmlChar*)"rhp_config") ){
    err = -ENOENT;
    goto error;
  }


  err = rhp_xml_enum_tags(cfg_root_node,(xmlChar*)"vpn",_rhp_cfg_parse_vpn_params,NULL,1);
  if( err == -ENOENT ){
    err = 0;
  }else if( err ){
    goto error;
  }

  if( (err = rhp_xml_enum_tags(cfg_root_node,(xmlChar*)"event_log",_rhp_cfg_parse_event_log,NULL,0)) ){
    RHP_BUG("");
    goto error;
  }


  if( (err = rhp_xml_enum_tags(cfg_root_node,(xmlChar*)"packet_capture",_rhp_cfg_parse_packet_capture,NULL,0)) ){
    RHP_BUG("");
    goto error;
  }


  rhp_xml_enum_tags(cfg_root_node,(xmlChar*)"dbg_trace_file",_rhp_cfg_parse_dbg_trace_file,NULL,0);


  xmlFreeDoc(cfg_doc);

  return 0;

error:
	if( cfg_doc ){
		xmlFreeDoc(cfg_doc);
	}
  return err;
}


static int _rhp_cfg_parse_cfg_bkup_script(xmlNodePtr node,void* ctx)
{
	int ret_len;

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"script"),RHP_XML_DT_STRING,
  		&rhp_cfg_bkup_cmd_path,&ret_len,NULL,0) ){
    RHP_BUG("");
    return -EINVAL;
  }

  return 0;
}


static int _rhp_cfg_parse_event_log_convert_script(xmlNodePtr node,void* ctx)
{
	int ret_len;

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"script"),RHP_XML_DT_STRING,
  		&rhp_event_log_convert_cmd_path,&ret_len,NULL,0) ){
    RHP_BUG("");
    return -EINVAL;
  }

  return 0;
}


static int _rhp_cfg_parse_home(xmlNodePtr node,void* ctx)
{
	int ret_len;

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"dir"),RHP_XML_DT_STRING,
  		&rhp_home_dir,&ret_len,NULL,0) ){
    RHP_BUG("");
    return -EINVAL;
  }

  return 0;
}


int rhp_cfg_init_load(char* conf_xml_path)
{
  int err = 0;
  xmlDocPtr cfg_doc = NULL;
  xmlNodePtr cfg_root_node;

  RHP_TRC(0,RHPTRCID_CFG_INIT_LOAD,"s",conf_xml_path);

  cfg_doc = xmlParseFile(conf_xml_path);
  if( cfg_doc == NULL ){
    RHP_BUG(" %s ",conf_xml_path);
    err = -ENOENT;
    goto error;
  }

  cfg_root_node = xmlDocGetRootElement(cfg_doc);
  if( cfg_root_node == NULL ){
    RHP_BUG(" %s ",conf_xml_path);
    err = -ENOENT;
    goto error;
  }

  if( xmlStrcmp(cfg_root_node->name,(xmlChar*)"rhp_config") ){
    err = -ENOENT;
    RHP_BUG("%d, %s ",err,conf_xml_path);
    goto error;
  }

  err = rhp_xml_enum_tags(cfg_root_node,(xmlChar*)"ikesa",_rhp_cfg_parse_ikesa_params,NULL,1);
  if( err == -ENOENT ){
    err = 0;
  }else if( err ){
    RHP_BUG("%d, %s ",err,conf_xml_path);
    goto error;
  }

  err = rhp_xml_enum_tags(cfg_root_node,(xmlChar*)"childsa",_rhp_cfg_parse_childsa_params,NULL,1);
  if( err == -ENOENT ){
    err = 0;
  }else if( err ){
    RHP_BUG("%d, %s ",err,conf_xml_path);
    goto error;
  }


  err = rhp_xml_enum_tags(cfg_root_node,(xmlChar*)"admin_services",_rhp_cfg_parse_admin_services,NULL,0);
  if( err == -ENOENT ){

    rhp_cfg_admin_service *cfg_admin_srv = NULL;

    cfg_admin_srv = (rhp_cfg_admin_service*)_rhp_malloc(sizeof(rhp_cfg_admin_service));
    if( cfg_admin_srv == NULL ){
	  RHP_BUG("");
      goto error;
    }
    memset(cfg_admin_srv,0,sizeof(rhp_cfg_admin_service));

    cfg_admin_srv->root_dir = (char*)_rhp_malloc(strlen("."));
    if( cfg_admin_srv->root_dir == NULL ){
      err = -ENOMEM;
      RHP_BUG("");
      _rhp_free(cfg_admin_srv);
      goto error;
    }
    cfg_admin_srv->root_dir[0] = '\0';
    strcpy(cfg_admin_srv->root_dir,".");

    cfg_admin_srv->tag[0] = '#';
    cfg_admin_srv->tag[1] = 'A';
    cfg_admin_srv->tag[2] = 'S';
    cfg_admin_srv->tag[3] = 'V';

    cfg_admin_srv->addr.addr_family = AF_INET;
    cfg_admin_srv->addr.addr.v4 = 0x01007F;
    cfg_admin_srv->addr.netmask.v4 = 0xFFFFFFFF;
    cfg_admin_srv->addr.prefixlen = 32;
    cfg_admin_srv->addr.port = htons(rhp_gcfg_http_default_port);
    cfg_admin_srv->protocol = RHP_CFG_ADMIN_SERVICE_PROTO_HTTP;
    cfg_admin_srv->client_acls = NULL;

    cfg_admin_srv->keep_alive_interval = rhp_gcfg_http_rx_timeout;
    cfg_admin_srv->max_conns = rhp_gcfg_http_max_connections;

    rhp_cfg_admin_services = cfg_admin_srv;
    err = 0;

  }else if( err ){
    RHP_BUG("%d, %s ",err,conf_xml_path);
    goto error;
  }

  {
		err = rhp_xml_enum_tags(cfg_root_node,(xmlChar*)"ikesa_security",
						_rhp_cfg_parse_ikesa_security,NULL,0);
		if( err == -ENOENT ){
			err = 0;
		}else if( err ){
			RHP_BUG("%d, %s ",err,conf_xml_path);
			goto error;
		}

		err = rhp_xml_enum_tags(cfg_root_node,(xmlChar*)"childsa_security",
						_rhp_cfg_parse_childsa_security,NULL,0);
		if( err == -ENOENT ){
			err = 0;
		}else if( err ){
			RHP_BUG("%d, %s ",err,conf_xml_path);
			goto error;
		}

		if( rhp_ikesa_config == NULL ){

			RHP_TRC(0,RHPTRCID_CFG_INIT_LOAD_DEF_IKESA,"");

			rhp_ikesa_config = rhp_cfg_default_ikesa_security();
			_rhp_cfg_trc_dump_ikesa(rhp_ikesa_config);
		}

		if( rhp_childsa_config == NULL ){

			RHP_TRC(0,RHPTRCID_CFG_INIT_LOAD_DEF_CHILDSA,"");

			rhp_childsa_config = rhp_cfg_default_childsa_security();
			_rhp_cfg_trc_dump_childsa(rhp_childsa_config);
		}
  }

  {
		err = rhp_xml_enum_tags(cfg_root_node,(xmlChar*)"ikev1_ikesa_security",
						_rhp_cfg_parse_ikev1_ikesa_security,NULL,0);
		if( err == -ENOENT ){
			err = 0;
		}else if( err ){
			RHP_BUG("%d, %s ",err,conf_xml_path);
			goto error;
		}

		err = rhp_xml_enum_tags(cfg_root_node,(xmlChar*)"ikev1_ipsecsa_security",
						_rhp_cfg_parse_ikev1_ipsecsa_security,NULL,0);
		if( err == -ENOENT ){
			err = 0;
		}else if( err ){
			RHP_BUG("%d, %s ",err,conf_xml_path);
			goto error;
		}

		if( rhp_ikev1_ikesa_config == NULL ){

			RHP_TRC(0,RHPTRCID_CFG_INIT_LOAD_DEF_IKEV1_IKESA,"");

			rhp_ikev1_ikesa_config = rhp_cfg_ikev1_default_ikesa_security();
			_rhp_cfg_trc_dump_ikev1_ikesa(rhp_ikev1_ikesa_config);
		}

		if( rhp_ikev1_ipsecsa_config == NULL ){

			RHP_TRC(0,RHPTRCID_CFG_INIT_LOAD_DEF_IKEV1_IPSECSA,"");

			rhp_ikev1_ipsecsa_config = rhp_cfg_ikev1_default_ipsecsa_security();
			_rhp_cfg_trc_dump_ikev1_ipsecsa(rhp_ikev1_ipsecsa_config);
		}
  }


  err = rhp_xml_enum_tags(cfg_root_node,(xmlChar*)"ikev2_hash_url",_rhp_gcfg_parse_hash_url,NULL,0);
  if( err == -ENOENT ){

  	rhp_global_cfg_hash_url = _rhp_gcfg_malloc_hash_url();
  	if( rhp_global_cfg_hash_url == NULL ){
  		RHP_BUG("");
  		err = -ENOMEM;
  		goto error;
  	}

  	err = 0;

  }else if( err ){
    RHP_BUG("%d, %s ",err,conf_xml_path);
    goto error;
  }


  err = rhp_xml_enum_tags(cfg_root_node,(xmlChar*)"radius",_rhp_gcfg_parse_eap_radius,NULL,0);
  if( err == -ENOENT ){

  	if( rhp_gcfg_eap_radius == NULL ){

			rhp_gcfg_eap_radius = rhp_gcfg_alloc_eap_radius();
			if( rhp_gcfg_eap_radius == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			rhp_gcfg_eap_radius->enabled = 0;
  	}

		err = 0;

  }else if( err ){
    RHP_BUG("%d, %s ",err,conf_xml_path);
    goto error;
  }

  err = rhp_xml_enum_tags(cfg_root_node,(xmlChar*)"radius_acct",_rhp_gcfg_parse_radius_acct,NULL,0);
  if( err == -ENOENT ){

  	if( rhp_gcfg_radius_acct == NULL ){

  		rhp_gcfg_radius_acct = rhp_gcfg_alloc_radius_acct();
    	if( rhp_gcfg_radius_acct == NULL ){
    		RHP_BUG("");
    		err = -ENOMEM;
    		goto error;
    	}

    	rhp_gcfg_radius_acct->enabled = 0;
  	}

  	err = 0;

  }else if( err ){
    RHP_BUG("%d, %s ",err,conf_xml_path);
    goto error;
  }


  err = rhp_xml_enum_tags(cfg_root_node,(xmlChar*)"vpn_realm",_rhp_cfg_parse_realm,NULL,1);
  if( err == -ENOENT ){
  	err = 0;
  }else if( err ){
    RHP_BUG("%d, %s ",err,conf_xml_path);
    goto error;
  }


  err = rhp_xml_enum_tags(cfg_root_node,(xmlChar*)"peer_acls",_rhp_cfg_parse_peer_acls,NULL,0);
  if( err == -ENOENT ){
  	rhp_cfg_peer_acl_list = NULL;
    err = 0;
  }else if( err ){
    RHP_BUG("%d, %s ",err,conf_xml_path);
    goto error;
  }

  err = rhp_xml_enum_tags(cfg_root_node,(xmlChar*)"firewall",_rhp_cfg_parse_firewall,NULL,0);
  if( err == -ENOENT ){
  	rhp_cfg_firewall_rules = NULL;
    err = 0;
  }else if( err ){
    RHP_BUG("%d, %s ",err,conf_xml_path);
    goto error;
  }


  if( (err = rhp_xml_enum_tags(cfg_root_node,(xmlChar*)"home",_rhp_cfg_parse_home,NULL,0)) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_xml_enum_tags(cfg_root_node,(xmlChar*)"cfg_bkup_script",
  			_rhp_cfg_parse_cfg_bkup_script,NULL,0)) ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( (err = rhp_xml_enum_tags(cfg_root_node,(xmlChar*)"event_log_convert_script",
  			_rhp_cfg_parse_event_log_convert_script,NULL,0)) ){
    RHP_BUG("%d",err);
    goto error;
  }

  xmlFreeDoc(cfg_doc);

  RHP_TRC(0,RHPTRCID_CFG_INIT_LOAD_RTRN,"sd",conf_xml_path,0);
  return 0;

error:
	if( cfg_doc ){
		xmlFreeDoc(cfg_doc);
	}
  RHP_TRC(0,RHPTRCID_CFG_INIT_LOAD_RTRN,"sd",conf_xml_path,err);
  return err;
}


int rhp_eap_radius_rx_attr_enabled(u8 rx_attr_type,
		unsigned long vendor_id,u8 vendor_type)
{
	int flag = 0;
	u8* attr_param = NULL;

	RHP_TRC(0,RHPTRCID_EAP_RADIUS_RX_ATTR_ENABLED,"Lbub","RADIUS_ATTR",rx_attr_type,vendor_id,vendor_type);

	if( rx_attr_type == 0 || (vendor_id && vendor_type == 0) ){
		flag = 0;
		goto end;
	}

	switch( rx_attr_type ){

	case RHP_RADIUS_ATTR_TYPE_FRAMED_MTU:
		attr_param = &(rhp_gcfg_eap_radius->rx_framed_mtu_enabled);
		break;
	case RHP_RADIUS_ATTR_TYPE_SESSION_TIMEOUT:
		attr_param = &(rhp_gcfg_eap_radius->rx_session_timeout_enabled);
		break;
	case RHP_RADIUS_ATTR_TYPE_FRAMED_IP_ADDRESS:
	case RHP_RADIUS_ATTR_TYPE_FRAMED_IP_NETMASK:
		attr_param = &(rhp_gcfg_eap_radius->rx_framed_ipv4_enabled);
		break;
	case RHP_RADIUS_ATTR_TYPE_FRAMED_IPV6_ADDRESS:
		attr_param = &(rhp_gcfg_eap_radius->rx_framed_ipv6_enabled);
		break;
	case RHP_RADIUS_ATTR_TYPE_DNS_IPV6_ADDRESS:
		attr_param = &(rhp_gcfg_eap_radius->rx_dns_server_v6_enabled);
		break;
	case RHP_RADIUS_ATTR_TYPE_TUNNEL_PRIVATE_GROUP_ID:
		attr_param = &(rhp_gcfg_eap_radius->rx_tunnel_private_group_id_enabled);
		break;
	case RHP_RADIUS_ATTR_TYPE_TUNNEL_CLIENT_AUTH_ID:
		attr_param = &(rhp_gcfg_eap_radius->rx_tunnel_client_auth_id_enabled);
		break;
	default:
		break;
	}

	if( rx_attr_type == RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC &&
			vendor_id == RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC_MICROSOFT ){

		switch( vendor_type ){
		case RHP_RADIUS_VENDOR_MS_ATTR_TYPE_PRIMARY_DNS_SERVER:
			attr_param = &(rhp_gcfg_eap_radius->rx_ms_primary_nbns_server_v4_enabled);
			break;
		case RHP_RADIUS_VENDOR_MS_ATTR_TYPE_PRIMARY_NBNS_SERVER:
			attr_param = &(rhp_gcfg_eap_radius->rx_ms_primary_nbns_server_v4_enabled);
			break;
		default:
			break;
		}
	}

	if( attr_param && *attr_param ){
		flag = 1;
		goto end;
	}

	if( rx_attr_type == rhp_gcfg_eap_radius->rx_vpn_realm_id_attr_type ||
			rx_attr_type == rhp_gcfg_eap_radius->rx_vpn_realm_role_attr_type ||
			rx_attr_type == rhp_gcfg_eap_radius->rx_user_index_attr_type ||
			rx_attr_type == rhp_gcfg_eap_radius->rx_internal_dns_v4_attr_type ||
			rx_attr_type == rhp_gcfg_eap_radius->rx_internal_dns_v6_attr_type ||
			rx_attr_type == rhp_gcfg_eap_radius->rx_internal_domain_names_attr_type ||
			rx_attr_type == rhp_gcfg_eap_radius->rx_internal_rt_maps_v4_attr_type ||
			rx_attr_type == rhp_gcfg_eap_radius->rx_internal_rt_maps_v6_attr_type ||
			rx_attr_type == rhp_gcfg_eap_radius->rx_internal_gw_v4_attr_type ||
			rx_attr_type == rhp_gcfg_eap_radius->rx_internal_gw_v6_attr_type ||
			rx_attr_type == rhp_gcfg_eap_radius->rx_internal_addr_ipv4 ||
			rx_attr_type == rhp_gcfg_eap_radius->rx_internal_addr_ipv6 ||
			rx_attr_type == rhp_gcfg_eap_radius->rx_common_priv_attr ){

		flag = 1;
	}

end:
	RHP_TRC(0,RHPTRCID_EAP_RADIUS_RX_ATTR_ENABLED_RTRN,"bubd",rx_attr_type,vendor_id,vendor_type,flag);
	return flag;
}


//
// TODO ACLs objects should be held by each wthread and be checked without no global lock(rhp_cfg_lock)
// for better performance... Or should be cached in TLS buffer???
//

int rhp_cfg_check_peer_acls(rhp_packet* pkt)
{
  rhp_cfg_peer_acl* peer_acl;

  RHP_TRC(0,RHPTRCID_CFG_CHECK_PEER_ACLS,"x",pkt);

  if( pkt->l3.raw == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  RHP_LOCK(&rhp_cfg_lock);

  if( rhp_cfg_peer_acl_list == NULL ){
    RHP_TRC(0,RHPTRCID_CFG_CHECK_PEER_ACLS_NO_ACLS,"xx",pkt,rhp_cfg_peer_acl_list);
    goto found;
  }

  peer_acl = rhp_cfg_peer_acl_list;

  while( peer_acl ){

  	if( peer_acl->any ){
  		goto found;
  	}

    switch( pkt->type ){

    case RHP_PKT_IPV4_IKE:
    case RHP_PKT_IPV4_ESP_NAT_T:
    case RHP_PKT_IPV4_ESP:

      if( peer_acl->addr.addr_family == AF_INET &&
      		peer_acl->addr.addr.v4 &&
      		peer_acl->addr.prefixlen &&
      		rhp_ip_same_subnet_v4(pkt->l3.iph_v4->src_addr,peer_acl->addr.addr.v4,peer_acl->addr.prefixlen) ){
        goto found;
      }

      break;

    case RHP_PKT_IPV6_IKE:
    case RHP_PKT_IPV6_ESP_NAT_T:
    case RHP_PKT_IPV6_ESP:

      if( peer_acl->addr.addr_family == AF_INET6 &&
      		!rhp_ipv6_addr_null(peer_acl->addr.addr.v6) &&
      		peer_acl->addr.prefixlen &&
      		rhp_ip_same_subnet_v6(pkt->l3.iph_v6->src_addr,peer_acl->addr.addr.v6,peer_acl->addr.prefixlen) ){
        goto found;
      }

      break;

    default:
    	goto error;
    }

    peer_acl = peer_acl->next;
  }

error:
  RHP_UNLOCK(&rhp_cfg_lock);

  if( pkt->type == RHP_PKT_IPV4_IKE ||
  		pkt->type == RHP_PKT_IPV4_ESP_NAT_T ||
  		pkt->type == RHP_PKT_IPV4_ESP ){

  	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_PKT_REJECTED,"44b",pkt->l3.iph_v4->src_addr,pkt->l3.iph_v4->dst_addr,pkt->l3.iph_v4->protocol);

  }else if( pkt->type == RHP_PKT_IPV6_IKE ||
  					pkt->type == RHP_PKT_IPV6_ESP_NAT_T ||
  					pkt->type == RHP_PKT_IPV6_ESP ){

  	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_PKT_V6_REJECTED,"66b",pkt->l3.iph_v6->src_addr,pkt->l3.iph_v6->dst_addr,pkt->l3.iph_v6->next_header);

  }else{

  	if(  pkt->l2.raw ){
  		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_UNSUPPORTED_PKT_REJECTED,"MMW",pkt->l2.eth->src_addr,pkt->l2.eth->dst_addr,pkt->l2.eth->protocol);
  	}else{
  		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_UNSUPPORTED_PKT_REJECTED,"W",0);
  	}
  }

  RHP_TRC(0,RHPTRCID_CFG_CHECK_PEER_ACLS_NOT_ALLOWED,"x",pkt);
  return -EPERM;

found:
  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_CFG_CHECK_PEER_ACLS_OK,"x",pkt);
  return 0;
}


void rhp_cfg_realm_free_ext_traffic_selectors(rhp_ext_traffic_selector* etss)
{
	rhp_ext_traffic_selector *etss_n,*etss1;

  RHP_TRC(0,RHPTRCID_CFG_REALM_FREE_EXT_TRAFFIC_SELECTORS,"x",etss);

	etss1 = etss;

	while( etss1 ){
		etss_n = etss1->next;
		_rhp_free(etss1);
		etss1 = etss_n;
	}

  RHP_TRC(0,RHPTRCID_CFG_REALM_FREE_EXT_TRAFFIC_SELECTORS_RTRN,"x",etss);
	return;
}


int rhp_cfg_realm_dup_ext_traffic_selectors(rhp_vpn_realm* rlm,rhp_ext_traffic_selector** etss_r)
{
	int err;
	rhp_ext_traffic_selector *etss = NULL,*dup_etss_h = NULL,*dup_etss = NULL,*dup_etss_t = NULL;

  RHP_TRC(0,RHPTRCID_CFG_REALM_DUP_EXT_TRAFFIC_SELECTORS,"xxx",rlm,rlm->ext_tss.etss,etss_r);

	etss = rlm->ext_tss.etss;
	dup_etss_t = NULL;

	while( etss ){

		dup_etss = (rhp_ext_traffic_selector*)_rhp_malloc(sizeof(rhp_ext_traffic_selector));
		if( dup_etss == NULL ){
			err = -ENOMEM;
			goto error;
		}

		memcpy(dup_etss,etss,sizeof(rhp_ext_traffic_selector));

		dup_etss->next = NULL;

		if( dup_etss_t == NULL ){
			dup_etss_h = dup_etss;
		}else{
			dup_etss_t->next = dup_etss;
		}

		dup_etss_t = dup_etss;
		etss = etss->next;
	}

	*etss_r = dup_etss_h;

  RHP_TRC(0,RHPTRCID_CFG_REALM_DUP_EXT_TRAFFIC_SELECTORS_RTRN,"xx",rlm,*etss_r);
	return 0;

error:
	rhp_cfg_realm_free_ext_traffic_selectors(etss);

	RHP_TRC(0,RHPTRCID_CFG_REALM_DUP_EXT_TRAFFIC_SELECTORS_ERR,"xE",rlm,err);
	return err;
}



int rhp_cfg_rename(char* config_file_path)
{
	int err = -EINVAL;
	char* sfx_p;
	int path_len,wk_path_len;
	int i;
	char* wk_file_path = NULL;

	RHP_TRC(0,RHPTRCID_CFG_RENAME,"s",config_file_path);

	path_len = strlen(config_file_path) + 1;
	sfx_p = (config_file_path + path_len - 1);

	for( i = path_len; i > 0; i--){
		if( *sfx_p == '.' ){
			break;
		}
		sfx_p--;
	}

	wk_path_len = path_len + strlen(".old");

	wk_file_path = (char*)_rhp_malloc(wk_path_len);
	if( wk_file_path == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}
	memset(wk_file_path,'\0',wk_path_len);
	memcpy(wk_file_path,config_file_path,(sfx_p - config_file_path));

	memcpy((wk_file_path + (sfx_p - config_file_path)),".old",strlen(".old"));

	if( rename(config_file_path,wk_file_path) < 0 ){
		err = -errno;
		RHP_BUG("%d",err);
		goto error;
	}

	memcpy((wk_file_path + (sfx_p - config_file_path)),".tmp",strlen(".tmp"));

	if( rename(wk_file_path,config_file_path) < 0 ){
		err = -errno;
		RHP_BUG("%d",err);
		goto error;
	}

	_rhp_free(wk_file_path);

	RHP_TRC(0,RHPTRCID_CFG_RENAME_RTRN,"s",config_file_path);
	return 0;

error:
	if( wk_file_path ){
		_rhp_free(wk_file_path);
	}

	RHP_TRC(0,RHPTRCID_CFG_RENAME_ERR,"sE",config_file_path,err);
	return err;
}


int rhp_cfg_save_config(char* config_file_path,void* cfg_doc_t)
{
	int err = -EINVAL;
	char* sfx_p;
	int path_len,wk_path_len;
	int i;
	char* wk_file_path = NULL;
	xmlDocPtr cfg_doc = (xmlDocPtr)cfg_doc_t;

	RHP_TRC(0,RHPTRCID_CFG_SAVE_CONFIG,"sx",config_file_path,cfg_doc_t);

	rhp_xml_doc_dump(config_file_path,cfg_doc);

	path_len = strlen(config_file_path) + 1;
	sfx_p = (config_file_path + path_len - 1);

	for( i = path_len; i > 0; i--){
		if( *sfx_p == '.' ){
			break;
		}
		sfx_p--;
	}

	wk_path_len = path_len + strlen(".tmp");

	wk_file_path = (char*)_rhp_malloc(wk_path_len);
	if( wk_file_path == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	memset(wk_file_path,'\0',wk_path_len);
	memcpy(wk_file_path,config_file_path,(sfx_p - config_file_path));

	memcpy((wk_file_path + (sfx_p - config_file_path)),".tmp",strlen(".tmp"));

	if( xmlSaveFormatFile(wk_file_path,cfg_doc,1) < 0 ){
		err = -errno;
		RHP_BUG("%d",err);
		goto error;
	}

	err = rhp_cfg_rename(config_file_path);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	_rhp_free(wk_file_path);

	RHP_TRC(0,RHPTRCID_CFG_SAVE_CONFIG_RTRN,"s",config_file_path);
	return 0;

error:
	RHP_LOG_E(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_SAVE_CFG_FILE_ERR,"sE",config_file_path,err);
	if( wk_file_path ){
		_rhp_free(wk_file_path);
	}

	RHP_TRC(0,RHPTRCID_CFG_SAVE_CONFIG_ERR,"sE",config_file_path,err);
	return err;
}


int rhp_realm_cfg_svr_narrow_ts_i(rhp_vpn_realm* rlm,rhp_vpn* vpn)
{
	if( rlm->config_service != RHP_IKEV2_CONFIG_SERVER ){
		return 0;
	}

  if( (rlm->config_server.narrow_ts_i == RHP_IKEV2_CFG_NARROW_TS_I_ALL) ||
  		(rlm->config_server.narrow_ts_i == RHP_IKEV2_CFG_NARROW_TS_I_NON_ROCKHOPPER && !(vpn->peer_is_rockhopper)) ){
  	return 1;
  }

  return 0;
}



int rhp_cfg_init()
{
  _rhp_mutex_init("CFG",&(rhp_cfg_lock));

  _rhp_mutex_init("HUL",&(rhp_gcfg_hash_url_lock));

  _rhp_mutex_init("RCG",&(rhp_eap_radius_cfg_lock));

  _rhp_ikesa_config_def.tag[0] = '#';
  _rhp_ikesa_config_def.tag[1] = 'C';
  _rhp_ikesa_config_def.tag[2] = 'I';
  _rhp_ikesa_config_def.tag[3] = 'K';

  _rhp_childsa_config_def.tag[0] = '#';
  _rhp_childsa_config_def.tag[1] = 'C';
  _rhp_childsa_config_def.tag[2] = 'C';
  _rhp_childsa_config_def.tag[3] = 'H';

  _rhp_atomic_init(&rhp_dns_pxy_users);


  RHP_LINE("rhp_cfg_init() OK.");
  return 0;
}


