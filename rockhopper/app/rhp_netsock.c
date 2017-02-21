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
#include "rhp_crypto.h"
#include "rhp_ikev2.h"
#include "rhp_esp.h"
#include "rhp_pcap.h"

#define RHP_NETSOCK_RX_SK_IKE			0
#define RHP_NETSOCK_RX_SK_ESP			1
#define RHP_NETSOCK_RX_SK_NAT_T		2

static int _rhp_rx_cur_buffer_size;
static int _rhp_rx_ike_cur_buffer_size;
static int _rhp_rx_def_pkt_size_cnt = 0;

static long _rhp_stat_max_rx_pkt_ike_sk = 0;
static long _rhp_stat_max_rx_pkt_esp_sk = 0;
static long _rhp_stat_max_rx_pkt_ike_natt_sk = 0;

static u32 _rhp_netsock_disp_hash_udp_rnd = 0;
static u32 _rhp_netsock_disp_hash_esp_rnd = 0;

//#define RHP_NETSOCK_ESP_SK_EPOLL_EVT_MASK		(EPOLLIN | EPOLLERR)
#define RHP_NETSOCK_ESP_SK_EPOLL_EVT_MASK		(EPOLLIN)

static rhp_atomic_t _rhp_dbg_tx_ikev2_pkt_consecutive_num;
static rhp_atomic_t _rhp_dbg_tx_esp_pkt_consecutive_num;

void rhp_netsock_get_stat(rhp_netsock_stat* netsock_stat)
{
	netsock_stat->rx_cur_buffer_size = _rhp_rx_cur_buffer_size;
	netsock_stat->rx_ike_cur_buffer_size = _rhp_rx_ike_cur_buffer_size;
	netsock_stat->rx_def_pkt_size_cnt = _rhp_rx_def_pkt_size_cnt;

	netsock_stat->max_rx_pkt_ike_sk = _rhp_stat_max_rx_pkt_ike_sk;
	netsock_stat->max_rx_pkt_esp_sk = _rhp_stat_max_rx_pkt_esp_sk;
	netsock_stat->max_rx_pkt_ike_natt_sk = _rhp_stat_max_rx_pkt_ike_natt_sk;
}


#define RHP_NETSOCK_PCAP_PKT(pkt_type,ikev2_exchg_type)	(\
(((pkt_type) == RHP_PKT_IPV4_IKE || (pkt_type) == RHP_PKT_IPV6_IKE) &&\
(rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_IKEV2_CIPHER] ||\
(rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_IKEV2_PLAIN] &&\
((ikev2_exchg_type) == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT || (ikev2_exchg_type) == RHP_PROTO_IKE_EXCHG_SESS_RESUME)))) ||\
(((pkt_type) == RHP_PKT_IPV4_ESP || (pkt_type) == RHP_PKT_IPV4_ESP_NAT_T ||\
(pkt_type) == RHP_PKT_IPV6_ESP || (pkt_type) == RHP_PKT_IPV6_ESP_NAT_T) &&\
rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_ESP_CIPHER])\
)

static void _rhp_netsock_pcap_write(rhp_packet* pkt)
{
  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_PCAP_WRITE,"xLd",pkt,"PKT",pkt->type);

  rhp_pcap_write_pkt(pkt);

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_PCAP_WRITE_RTRN,"x",pkt);
	return;
}


static u32 _rhp_netsock_rx_disp_hash(void *key_seed,int* err)
{
  rhp_packet *pkt = (rhp_packet*)key_seed;

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_DISP_HASH,"xLdx",pkt,"PKT",pkt->type,err);

  if( pkt->l3.raw == NULL ){
    RHP_BUG("0x%x,%d",pkt,pkt->type);
    return -EINVAL;
  }

  if( pkt->type == RHP_PKT_IPV4_IKE ||
  		pkt->type == RHP_PKT_IPV4_DNS ||
  		pkt->type == RHP_PKT_IPV4_RADIUS ){

  	*err = 0;
  	return _rhp_hash_ipv4_udp(pkt->l3.iph_v4->src_addr,pkt->l4.udph->src_port,
  			pkt->l3.iph_v4->dst_addr,pkt->l4.udph->dst_port,_rhp_netsock_disp_hash_udp_rnd);

  }else if( pkt->type == RHP_PKT_IPV4_ESP_NAT_T || pkt->type == RHP_PKT_IPV4_ESP ||
  		      pkt->type == RHP_PKT_IPV6_ESP_NAT_T || pkt->type == RHP_PKT_IPV6_ESP ){

  	rhp_proto_esp* esph = (rhp_proto_esp*)pkt->app.raw;

  	*err = 0;
  	return _rhp_hash_u32(esph->spi,_rhp_netsock_disp_hash_esp_rnd); // Inbound SPI is random value.

  }else if( pkt->type == RHP_PKT_IPV6_IKE ||
  					pkt->type == RHP_PKT_IPV6_DNS ||
  					pkt->type == RHP_PKT_IPV6_RADIUS ){

  	*err = 0;
  	return _rhp_hash_ipv6_udp(pkt->l3.iph_v6->src_addr,pkt->l4.udph->src_port,
  			pkt->l3.iph_v6->dst_addr,pkt->l4.udph->dst_port,_rhp_netsock_disp_hash_udp_rnd);

  }else if( pkt->type == RHP_PKT_GRE_NHRP ){

  	if( pkt->nhrp.nbma_addr_family == AF_INET ){

    	*err = 0;
  		return _rhp_hash_ipv4_2(
  				*((u32*)pkt->nhrp.nbma_src_addr),*((u32*)pkt->nhrp.nbma_dst_addr),_rhp_netsock_disp_hash_esp_rnd);

  	}else if( pkt->nhrp.nbma_addr_family == AF_INET6 ){

    	*err = 0;
  		return _rhp_hash_ipv6_2(
  				pkt->nhrp.nbma_src_addr,pkt->nhrp.nbma_dst_addr,_rhp_netsock_disp_hash_esp_rnd);

  	}else{
  		RHP_BUG("%d",pkt->nhrp.nbma_addr_family);
  	}

  }else{
  	RHP_BUG("%d",pkt->type);
  }

  *err = -EINVAL;
  return 0;
}

int rhp_netsock_init()
{
  int err = 0;

  RHP_TRC(0,RHPTRCID_NETSOCK_INIT,"");

  if( rhp_random_bytes((u8*)&_rhp_netsock_disp_hash_udp_rnd,sizeof(_rhp_netsock_disp_hash_udp_rnd)) ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  if( rhp_random_bytes((u8*)&_rhp_netsock_disp_hash_esp_rnd,sizeof(_rhp_netsock_disp_hash_esp_rnd)) ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  _rhp_rx_cur_buffer_size = rhp_gcfg_max_packet_default_size;
  _rhp_rx_ike_cur_buffer_size = rhp_gcfg_max_packet_default_size;

  if( (err = rhp_wts_register_disp_rule(RHP_WTS_DISP_RULE_NETSOCK,_rhp_netsock_rx_disp_hash)) ){
    RHP_BUG("%d",err);
    goto error;
  }

  _rhp_atomic_init(&_rhp_dbg_tx_ikev2_pkt_consecutive_num);
  _rhp_atomic_init(&_rhp_dbg_tx_esp_pkt_consecutive_num);

error:
	RHP_TRC(0,RHPTRCID_NETSOCK_INIT_RTRN,"E",err);
	return err;
}


static int _rhp_netsock_open_ike(rhp_ifc_entry *ifc,rhp_ifc_addr* ifc_addr,u16 port,int* sk_ike_r)
{
	int err = -EINVAL;
	int sk_ike = -1;
  union {
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
    unsigned char raw;
  } my_sin;
  int my_sin_len;
  int flag, pmtu_flag;

  RHP_TRC(0,RHPTRCID_NETSOCK_OPEN_IKE,"xxWx",ifc,ifc_addr,port,sk_ike_r);

  pmtu_flag = rhp_gcfg_socket_path_mtu_discover;
  if( pmtu_flag ){
    pmtu_flag = IP_PMTUDISC_DO;
  }else{
    pmtu_flag = IP_PMTUDISC_DONT;
  }

  sk_ike = socket( ifc_addr->addr.addr_family, SOCK_DGRAM, 0 );
	if(sk_ike < 0){
		err = -errno;
		RHP_BUG( "%d", err );
		goto error;
	}

	switch(ifc_addr->addr.addr_family){

	case AF_INET:

		my_sin.v4.sin_family = AF_INET;
		my_sin.v4.sin_port = port;
		my_sin.v4.sin_addr.s_addr = ifc_addr->addr.addr.v4;
		my_sin_len = sizeof(struct sockaddr_in);

		RHP_TRC( 0, RHPTRCID_NETSOCK_OPEN_IKE_BIND, "xddW4dp", ifc, sk_ike,my_sin.v4.sin_family, my_sin.v4.sin_port, my_sin.v4.sin_addr.s_addr,my_sin_len, my_sin_len, &(my_sin.raw) );

		if(bind( sk_ike, (struct sockaddr*) &(my_sin.raw), my_sin_len ) < 0){

			err = -errno;

			if(err != -EADDRNOTAVAIL){
				RHP_BUG( "%d", err );
			}else{
				RHP_TRC( 0, RHPTRCID_NETSOCK_OPEN_IKE_BIND_ERROR, "xddW4E", ifc, sk_ike,my_sin.v4.sin_family, my_sin.v4.sin_port, my_sin.v4.sin_addr.s_addr,err );
			}
			goto error;
		}
		/*
		 flag = 1;
		 if( setsockopt(sk_ike,IPPROTO_IP,IP_RECVERR,&flag,sizeof(flag)) < 0 ){
		 	 err = -errno;
		 	 RHP_BUG("%d",err);
		 	 goto error;
		 }
		 */
		if(setsockopt( sk_ike, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu_flag,sizeof(pmtu_flag) ) < 0){
			err = -errno;
			RHP_BUG( "%d", err );
			goto error;
		}

		break;

	case AF_INET6:

		my_sin.v6.sin6_family = AF_INET6;
		my_sin.v6.sin6_port = port;
		my_sin.v6.sin6_flowinfo = 0;
		memcpy( my_sin.v6.sin6_addr.s6_addr, ifc_addr->addr.addr.v6, 16 );
		if(rhp_ipv6_is_linklocal( ifc_addr->addr.addr.v6 )){
			my_sin.v6.sin6_scope_id = ifc_addr->addr.ipv6_scope_id;
		}else{
			my_sin.v6.sin6_scope_id = 0;
		}
		my_sin_len = sizeof(struct sockaddr_in6);

		flag = 1;
		if(setsockopt( sk_ike, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag) ) < 0){
			err = -errno;
			RHP_BUG( "%d", err );
			goto error;
		}

		RHP_TRC( 0, RHPTRCID_NETSOCK_OPEN_IKE_BIND_V6, "xddW6ddp", ifc, sk_ike,my_sin.v6.sin6_family, my_sin.v6.sin6_port, my_sin.v6.sin6_addr.s6_addr,my_sin.v6.sin6_scope_id,my_sin_len, my_sin_len, &(my_sin.raw) );

		if(bind( sk_ike, (struct sockaddr*) &(my_sin.raw), my_sin_len ) < 0){

			err = -errno;

			if(err != -EADDRNOTAVAIL){
				RHP_BUG( "%d", err );
			}else{
				RHP_TRC( 0, RHPTRCID_NETSOCK_OPEN_IKE_BIND_V6_ERROR, "xddW6E", ifc,sk_ike, my_sin.v6.sin6_family, my_sin.v6.sin6_port,my_sin.v6.sin6_addr.s6_addr, err );
			}

			goto error;
		}

		if(setsockopt( sk_ike, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &pmtu_flag,sizeof(pmtu_flag) ) < 0){
			err = -errno;
			RHP_BUG( "%d", err );
			goto error;
		}

		break;

	default:
		RHP_BUG( "%d", ifc_addr->addr.addr_family );
		err = -EAFNOSUPPORT;
		goto error;
	}

	//
	// [CAUTION]
	//  O_NONBLOCK is NOT set because MSG_DONTWAIT is set with recvmsg().
	//

	*sk_ike_r = sk_ike;

  RHP_TRC(0,RHPTRCID_NETSOCK_OPEN_IKE_RTRN,"xxWLdd",ifc,ifc_addr,port,"IP_PMTUD_FLAG",pmtu_flag,*sk_ike_r);
	return 0;

error:
	if( sk_ike >= 0 ){
		close(sk_ike);
	}
  RHP_TRC(0,RHPTRCID_NETSOCK_OPEN_IKE_ERR,"xxE",ifc,ifc_addr,err);
	return err;
}

static int _rhp_netsock_open_esp_raw(rhp_ifc_entry *ifc,rhp_ifc_addr* ifc_addr,int* sk_esp_r)
{
	int err = -EINVAL;
	int sk_esp = -1;
  union {
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
    unsigned char raw;
  } my_sin;
  int my_sin_len;
  int flag, pmtu_flag;

  RHP_TRC(0,RHPTRCID_NETSOCK_OPEN_ESP_RAW,"xxx",ifc,ifc_addr,sk_esp_r);

  pmtu_flag = rhp_gcfg_socket_path_mtu_discover;
  if( pmtu_flag ){
    pmtu_flag = IP_PMTUDISC_DO;
  }else{
    pmtu_flag = IP_PMTUDISC_DONT;
  }

  sk_esp = socket( ifc_addr->addr.addr_family, SOCK_RAW, IPPROTO_ESP );
	if(sk_esp < 0){
		err = -errno;
		RHP_BUG( "%d", err );
		goto error;
	}

	switch(ifc_addr->addr.addr_family){

	case AF_INET:

		my_sin.v4.sin_family = AF_INET;
		my_sin.v4.sin_port = 0;
		my_sin.v4.sin_addr.s_addr = ifc_addr->addr.addr.v4;
		my_sin_len = sizeof(struct sockaddr_in);

		RHP_TRC( 0, RHPTRCID_NETSOCK_OPEN_ESP_BIND, "xddW4dp", ifc, sk_esp,my_sin.v4.sin_family, my_sin.v4.sin_port, my_sin.v4.sin_addr.s_addr,my_sin_len, my_sin_len, &(my_sin.raw) );

		if(bind( sk_esp, (struct sockaddr*) &(my_sin.raw), my_sin_len ) < 0){
			err = -errno;
			RHP_BUG( "%d", err );
			goto error;
		}

		flag = 0;
		if(setsockopt( sk_esp, IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag) ) < 0){
			err = -errno;
			RHP_BUG( "%d", err );
			goto error;
		}

		if(setsockopt( sk_esp, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu_flag,sizeof(pmtu_flag) ) < 0){
			err = -errno;
			RHP_BUG( "%d", err );
			goto error;
		}

		break;

	case AF_INET6:

		my_sin.v6.sin6_family = AF_INET6;
		my_sin.v6.sin6_port = 0;
		my_sin.v6.sin6_flowinfo = 0;
		memcpy( my_sin.v6.sin6_addr.s6_addr, ifc_addr->addr.addr.v6, 16 );
		if(rhp_ipv6_is_linklocal( ifc_addr->addr.addr.v6 )){
			my_sin.v6.sin6_scope_id = ifc_addr->addr.ipv6_scope_id;
		}else{
			my_sin.v6.sin6_scope_id = 0;
		}
		my_sin_len = sizeof(struct sockaddr_in6);

/*
		flag = 1;
		if(setsockopt( sk_esp, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag) ) < 0){
			err = -errno;
			RHP_BUG( "%d", err );
			goto error;
		}
*/

		if(bind( sk_esp, (struct sockaddr*) &(my_sin.raw), my_sin_len ) < 0){
			err = -errno;
			RHP_BUG( "%d", err );
			goto error;
		}

		if(setsockopt( sk_esp, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &pmtu_flag,sizeof(pmtu_flag) ) < 0){
			err = -errno;
			RHP_BUG( "%d", err );
			goto error;
		}

		break;

	default:
		RHP_BUG( "%d", ifc_addr->addr.addr_family );
		err = -EAFNOSUPPORT;
		goto error;
	}

	*sk_esp_r = sk_esp;

  RHP_TRC(0,RHPTRCID_NETSOCK_OPEN_ESP_RAW_RTRN,"xxLdd",ifc,ifc_addr,"IP_PMTUD_FLAG",pmtu_flag,*sk_esp_r);
	return 0;

error:
	if( sk_esp >= 0 ){
		close(sk_esp);
  }
  RHP_TRC(0,RHPTRCID_NETSOCK_OPEN_ESP_RAW_ERR,"xxE",ifc,ifc_addr,err);
  return err;
}

// ifc->lock must be acquired.
int rhp_netsock_open(rhp_ifc_entry *ifc,rhp_ifc_addr* ifc_addr)
{
  int sk_ike = -1,sk_esp = -1,sk_nat_t = -1;
  int err = 0;
  struct epoll_event ep_evt;
  u16 ike_port,ike_port_nat_t;

  RHP_TRC(0,RHPTRCID_NETSOCK_OPEN,"xxdd",ifc,ifc_addr,rhp_gcfg_socket_path_mtu_discover,rhp_main_net_epoll_fd);
  ifc->dump_no_lock("rhp_netsock_open(C)",ifc);

  if( rhp_gcfg_ipv6_disabled && ifc_addr->addr.addr_family == AF_INET6 ){
  	err = RHP_STATUS_IPV6_DISABLED;
  	goto error;
  }

  ike_port = htons(rhp_gcfg_ike_port);
  ike_port_nat_t = htons(rhp_gcfg_ike_port_nat_t);

  RHP_NETSOCK_EPOLL_IFC(&(ifc_addr->net_sk_epoll_ctx_ike)) = (unsigned long)NULL;
  RHP_NETSOCK_EPOLL_IFC(&(ifc_addr->net_sk_epoll_ctx_esp)) = (unsigned long)NULL;
  RHP_NETSOCK_EPOLL_IFC(&(ifc_addr->net_sk_epoll_ctx_nat_t)) = (unsigned long)NULL;
  RHP_NETSOCK_EPOLL_IFC_ADDR(&(ifc_addr->net_sk_epoll_ctx_ike)) = (unsigned long)NULL;
  RHP_NETSOCK_EPOLL_IFC_ADDR(&(ifc_addr->net_sk_epoll_ctx_esp)) = (unsigned long)NULL;
  RHP_NETSOCK_EPOLL_IFC_ADDR(&(ifc_addr->net_sk_epoll_ctx_nat_t)) = (unsigned long)NULL;

  err = _rhp_netsock_open_ike(ifc,ifc_addr,ike_port,&sk_ike);
  if( err ){
  	goto error;
  }

  err = _rhp_netsock_open_ike(ifc,ifc_addr,ike_port_nat_t,&sk_nat_t);
  if( err ){
  	goto error;
  }

  err = _rhp_netsock_open_esp_raw(ifc,ifc_addr,&sk_esp);
  if( err ){
  	goto error;
  }

  {
    ifc_addr->net_sk_epoll_ctx_ike.event_type = RHP_MAIN_EPOLL_NETSOCK;

    RHP_NETSOCK_EPOLL_IFC(&(ifc_addr->net_sk_epoll_ctx_ike)) =  (unsigned long)ifc; // (**)
    rhp_ifc_hold(ifc); // (**)
    RHP_NETSOCK_EPOLL_IFC_ADDR(&(ifc_addr->net_sk_epoll_ctx_ike)) =  (unsigned long)ifc_addr;

    memset(&ep_evt,0,sizeof(struct epoll_event));
//  ep_evt.events = EPOLLIN | EPOLLERR;
    ep_evt.events = EPOLLIN;
    ep_evt.data.ptr = (void*)&(ifc_addr->net_sk_epoll_ctx_ike);

    if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_ADD,sk_ike,&ep_evt) < 0 ){
      err = -errno;
      RHP_BUG("%d",err);
      goto error;
    }
  }

  {
  	ifc_addr->net_sk_epoll_ctx_esp.event_type = RHP_MAIN_EPOLL_NETSOCK;

    RHP_NETSOCK_EPOLL_IFC(&(ifc_addr->net_sk_epoll_ctx_esp)) =  (unsigned long)ifc; // (**)
    rhp_ifc_hold(ifc); // (**)
    RHP_NETSOCK_EPOLL_IFC_ADDR(&(ifc_addr->net_sk_epoll_ctx_esp)) =  (unsigned long)ifc_addr;

    memset(&ep_evt,0,sizeof(struct epoll_event));
    ep_evt.events = RHP_NETSOCK_ESP_SK_EPOLL_EVT_MASK;
    ep_evt.data.ptr = (void*)&(ifc_addr->net_sk_epoll_ctx_esp);

    if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_ADD,sk_esp,&ep_evt) < 0 ){
      err = -errno;
      RHP_BUG("%d",err);
      goto error;
    }
  }

  if( sk_nat_t != -1 ){

  	ifc_addr->net_sk_epoll_ctx_nat_t.event_type = RHP_MAIN_EPOLL_NETSOCK;

    RHP_NETSOCK_EPOLL_IFC(&(ifc_addr->net_sk_epoll_ctx_nat_t)) =  (unsigned long)ifc; // (**)
    rhp_ifc_hold(ifc); // (**)
    RHP_NETSOCK_EPOLL_IFC_ADDR(&(ifc_addr->net_sk_epoll_ctx_nat_t)) =  (unsigned long)ifc_addr;

    memset(&ep_evt,0,sizeof(struct epoll_event));
    ep_evt.events = RHP_NETSOCK_ESP_SK_EPOLL_EVT_MASK;
    ep_evt.data.ptr = (void*)&(ifc_addr->net_sk_epoll_ctx_nat_t);

    if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_ADD,sk_nat_t,&ep_evt) < 0 ){
      err = -errno;
      RHP_BUG("%d",err);
      goto error;
    }
  }

  ifc_addr->net_sk_ike = sk_ike;
  ifc_addr->net_sk_esp = sk_esp;
  ifc_addr->net_sk_nat_t = sk_nat_t;

  RHP_TRC(0,RHPTRCID_NETSOCK_OPEN_RTRN,"xxWWd",ifc,ifc_addr,ike_port,ike_port_nat_t,rhp_main_net_epoll_fd);
  ifc->dump_no_lock("rhp_netsock_open(R)",ifc);

  {
  	rhp_if_entry if_info_r;
  	rhp_ifc_copy_to_if_entry(ifc,&if_info_r,ifc_addr->addr.addr_family,ifc_addr->addr.addr.raw);
  	RHP_LOG_D(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_NETSOCK_OPEN,"F",&if_info_r);
  }

  return 0;

error:
  if( sk_ike >= 0 ){
    close(sk_ike);
    ifc_addr->net_sk_ike = -1;
  }

  if( RHP_NETSOCK_EPOLL_IFC(&(ifc_addr->net_sk_epoll_ctx_ike)) ){ // (**)
    RHP_NETSOCK_EPOLL_IFC(&(ifc_addr->net_sk_epoll_ctx_ike)) =  (unsigned long)NULL;
    rhp_ifc_unhold(ifc);
    RHP_NETSOCK_EPOLL_IFC_ADDR(&(ifc_addr->net_sk_epoll_ctx_ike)) =  (unsigned long)NULL;
  }

  if( sk_esp >= 0 ){
    close(sk_esp);
    ifc_addr->net_sk_esp = -1;
  }

  if( RHP_NETSOCK_EPOLL_IFC(&(ifc_addr->net_sk_epoll_ctx_esp)) ){ // (**)
    RHP_NETSOCK_EPOLL_IFC(&(ifc_addr->net_sk_epoll_ctx_esp)) =  (unsigned long)NULL;
    rhp_ifc_unhold(ifc);
    RHP_NETSOCK_EPOLL_IFC_ADDR(&(ifc_addr->net_sk_epoll_ctx_esp)) =  (unsigned long)NULL;
  }

  if( sk_nat_t >= 0 ){
    close(sk_nat_t);
    ifc_addr->net_sk_nat_t = -1;
  }

  if( RHP_NETSOCK_EPOLL_IFC(&(ifc_addr->net_sk_epoll_ctx_nat_t)) ){ // (**)
    RHP_NETSOCK_EPOLL_IFC(&(ifc_addr->net_sk_epoll_ctx_nat_t)) =  (unsigned long)NULL;
    rhp_ifc_unhold(ifc);
    RHP_NETSOCK_EPOLL_IFC_ADDR(&(ifc_addr->net_sk_epoll_ctx_nat_t)) =  (unsigned long)NULL;
  }

  RHP_TRC(0,RHPTRCID_NETSOCK_OPEN_ERR,"xxdE",ifc,ifc_addr,rhp_main_net_epoll_fd,err);
  ifc->dump_no_lock("rhp_netsock_open(ERR)",ifc);

  {
  	rhp_if_entry if_info_r;
  	rhp_ifc_copy_to_if_entry(ifc,&if_info_r,ifc_addr->addr.addr_family,ifc_addr->addr.addr.raw);
  	RHP_LOG_DE(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_NETSOCK_OPEN_ERR,"FE",&if_info_r,err);
  }
  return err;
}

// ifc->lock must be acquired.
void rhp_netsock_close(rhp_ifc_entry *ifc,rhp_ifc_addr* ifc_addr)
{
  struct epoll_event ep_evt; // See man 2 epoll_ctl ---BUG REPORT---

  RHP_TRC(0,RHPTRCID_NETSOCK_CLOSE,"xx",ifc,ifc_addr);
  ifc->dump_no_lock("rhp_netsock_close(C)",ifc);

  if( ifc_addr->net_sk_ike == -1 ){
    RHP_BUG("");
    goto error;
  }

  {
    memset(&ep_evt,0,sizeof(struct epoll_event));

    if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_DEL,ifc_addr->net_sk_ike,&ep_evt) < 0 ){
      RHP_BUG("");
    }

    close(ifc_addr->net_sk_ike);

    RHP_NETSOCK_EPOLL_IFC(&(ifc_addr->net_sk_epoll_ctx_ike)) =  (unsigned long)NULL;
    rhp_ifc_unhold(ifc); // ifc->net_sk_epoll_ctx.params[0]
    RHP_NETSOCK_EPOLL_IFC_ADDR(&(ifc_addr->net_sk_epoll_ctx_ike)) =  (unsigned long)NULL;

    ifc_addr->net_sk_ike = -1;
  }

  {
    memset(&ep_evt,0,sizeof(struct epoll_event));

    if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_DEL,ifc_addr->net_sk_esp,&ep_evt) < 0 ){
      RHP_BUG("");
    }

    close(ifc_addr->net_sk_esp);

    RHP_NETSOCK_EPOLL_IFC(&(ifc_addr->net_sk_epoll_ctx_esp)) =  (unsigned long)NULL;
    rhp_ifc_unhold(ifc); // ifc->net_sk_epoll_ctx.params[0]
    RHP_NETSOCK_EPOLL_IFC_ADDR(&(ifc_addr->net_sk_epoll_ctx_esp)) =  (unsigned long)NULL;

    ifc_addr->net_sk_esp = -1;
  }

  if( ifc_addr->net_sk_nat_t != -1 ){

    memset(&ep_evt,0,sizeof(struct epoll_event));

    if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_DEL,ifc_addr->net_sk_nat_t,&ep_evt) < 0 ){
      RHP_BUG("");
    }

    close(ifc_addr->net_sk_nat_t);

    RHP_NETSOCK_EPOLL_IFC(&(ifc_addr->net_sk_epoll_ctx_nat_t)) =  (unsigned long)NULL;
    rhp_ifc_unhold(ifc); // ifc->net_sk_epoll_ctx.params[0]
    RHP_NETSOCK_EPOLL_IFC_ADDR(&(ifc_addr->net_sk_epoll_ctx_nat_t)) =  (unsigned long)NULL;

    ifc_addr->net_sk_nat_t = -1;
  }

  {
  	rhp_if_entry if_info_r;
  	rhp_ifc_copy_to_if_entry(ifc,&if_info_r,ifc_addr->addr.addr_family,ifc_addr->addr.addr.raw);
  	RHP_LOG_D(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_NETSOCK_CLOSE,"F",&if_info_r);
  }

error:
  RHP_TRC(0,RHPTRCID_NETSOCK_CLOSE_RTRN,"xx",ifc,ifc_addr);
  ifc->dump_no_lock("rhp_netsock_close(R)",ifc);

  return;
}

// ifc->lock must be acquired.
int rhp_netsock_check_and_open_all(rhp_ifc_entry *ifc,int addr_family)
{
	int err = -EINVAL, err2 = 0;
	rhp_ifc_addr* ifc_addr = ifc->ifc_addrs;
	int n_err = 0;

  RHP_TRC(0,RHPTRCID_NETSOCK_CHECK_AND_OPEN_ALL,"xLd",ifc,"AF",addr_family);

	while( ifc_addr ){

		if( ifc_addr->net_sk_ike == -1 ){

		  if( rhp_gcfg_ipv6_disabled &&
		  		ifc_addr->addr.addr_family == AF_INET6 ){
		  	goto next;
		  }

		  if( addr_family == AF_UNSPEC ||
		  		ifc_addr->addr.addr_family == addr_family ){

				err = rhp_netsock_open(ifc,ifc_addr);
				if( err ){
					err2 = err;
					n_err++;
					RHP_TRC(0,RHPTRCID_NETSOCK_CHECK_AND_OPEN_ALL_OPEN_ERR,"xdE",ifc,n_err,err);
				}
		  }
		}

next:
		ifc_addr = ifc_addr->lst_next;
	}

	if( err2 ){
	  RHP_TRC(0,RHPTRCID_NETSOCK_CHECK_AND_OPEN_ALL_ERR,"xE",ifc,err2);
		return err2;
	}

  RHP_TRC(0,RHPTRCID_NETSOCK_CHECK_AND_OPEN_ALL_RTRN,"x",ifc);
	return 0;
}

// ifc->lock must be acquired.
void rhp_netsock_close_all(rhp_ifc_entry *ifc,int addr_family)
{
	rhp_ifc_addr* ifc_addr = ifc->ifc_addrs;

  RHP_TRC(0,RHPTRCID_NETSOCK_CLOSE_ALL,"xx",ifc,ifc->ifc_addrs);

	while( ifc_addr ){

		if( ifc_addr->net_sk_ike != -1 ){

			if( addr_family == AF_UNSPEC ||
					ifc_addr->addr.addr_family == addr_family ){

				rhp_netsock_close(ifc,ifc_addr);
			}
		}

		ifc_addr = ifc_addr->lst_next;
	}

  RHP_TRC(0,RHPTRCID_NETSOCK_CLOSE_ALL_RTRN,"x",ifc);
	return;
}

void rhp_netsock_dispached_task(rhp_packet *pkt)
{
	rhp_proto_ike* ikeh;

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_DISPATCHED_TASK,"xLd",pkt,"PKT",pkt->type);

  switch( pkt->type ){

    case RHP_PKT_IPV4_IKE:

			if( *((u32*)pkt->app.raw) == RHP_PROTO_NON_ESP_MARKER ){
				ikeh = (rhp_proto_ike*)(pkt->app.raw + RHP_PROTO_NON_ESP_MARKER_SZ);
			}else{
				ikeh = pkt->app.ikeh;
			}

			if( ikeh->ver_major == RHP_PROTO_IKE_V1_VER_MAJOR ){
				rhp_ikev1_recv_ipv4(pkt);
			}else{
				rhp_ikev2_recv_ipv4(pkt);
			}
      break;

    case RHP_PKT_IPV4_ESP:
    case RHP_PKT_IPV4_ESP_NAT_T:
    case RHP_PKT_IPV6_ESP:
    case RHP_PKT_IPV6_ESP_NAT_T:

    	rhp_esp_recv(pkt);
    	break;

    case RHP_PKT_IPV6_IKE:

			if( *((u32*)pkt->app.raw) == RHP_PROTO_NON_ESP_MARKER ){
				ikeh = (rhp_proto_ike*)(pkt->app.raw + RHP_PROTO_NON_ESP_MARKER_SZ);
			}else{
				ikeh = pkt->app.ikeh;
			}

			if( ikeh->ver_major == RHP_PROTO_IKE_V1_VER_MAJOR ){
				rhp_ikev2_recv_ipv4(pkt);
			}else{
				rhp_ikev2_recv_ipv6(pkt);
			}
      break;

    default:
    	RHP_BUG("%d",pkt->type);
    	break;
  }

  rhp_pkt_unhold(pkt);

	return;
}

static int _rhp_netsock_recv_restart(rhp_ifc_entry* rx_ifc)
{
	int err = 0;
  struct epoll_event ep_evt;
  rhp_ifc_addr* ifc_addr;

  RHP_TRC(0,RHPTRCID_NETSOCK_RECV_RESTART,"xfd",rx_ifc,rx_ifc->rx_esp_pkt_pend_flag.c,rx_ifc->rx_esp_pkt_pend_flag.flag);

  ifc_addr = rx_ifc->ifc_addrs;
  while( ifc_addr ){

		if( ifc_addr->net_sk_esp != -1 ){

			memset(&ep_evt,0,sizeof(struct epoll_event));
			ep_evt.events = RHP_NETSOCK_ESP_SK_EPOLL_EVT_MASK;
			ep_evt.data.ptr = (void*)&(ifc_addr->net_sk_epoll_ctx_esp);

			if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_MOD,ifc_addr->net_sk_esp,&ep_evt) < 0 ){
				err = -errno;
				RHP_BUG("%d",err);
			}
		}

		if( ifc_addr->net_sk_nat_t != -1 ){

			memset(&ep_evt,0,sizeof(struct epoll_event));
			ep_evt.events = RHP_NETSOCK_ESP_SK_EPOLL_EVT_MASK;
			ep_evt.data.ptr = (void*)&(ifc_addr->net_sk_epoll_ctx_nat_t);

			if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_MOD,ifc_addr->net_sk_nat_t,&ep_evt) < 0 ){
				err = -errno;
				RHP_BUG("%d",err);
			}
		}

  	ifc_addr = ifc_addr->lst_next;
  }

  rx_ifc->statistics.netif.rx_restart++;

  RHP_TRC(0,RHPTRCID_NETSOCK_RECV_RESTART_RTRN,"xE",rx_ifc,err);
  return err;
}

static int _rhp_netsock_recv_stop(rhp_ifc_entry* rx_ifc)
{
	int err = 0;
  struct epoll_event ep_evt;
  rhp_ifc_addr* ifc_addr;

  RHP_TRC(0,RHPTRCID_NETSOCK_RECV_STOP,"xfd",rx_ifc,rx_ifc->rx_esp_pkt_pend_flag.c,rx_ifc->rx_esp_pkt_pend_flag.flag);

  ifc_addr = rx_ifc->ifc_addrs;
  while( ifc_addr ){

		if( ifc_addr->net_sk_esp != -1 ){

			memset(&ep_evt,0,sizeof(struct epoll_event));
			ep_evt.events = 0;
			ep_evt.data.ptr = (void*)&(ifc_addr->net_sk_epoll_ctx_esp);

			if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_MOD,ifc_addr->net_sk_esp,&ep_evt) < 0 ){
				err = -errno;
				RHP_BUG("%d",err);
			}
		}

		if( ifc_addr->net_sk_nat_t != -1 ){

			memset(&ep_evt,0,sizeof(struct epoll_event));
			ep_evt.events = 0;
			ep_evt.data.ptr = (void*)&(ifc_addr->net_sk_epoll_ctx_nat_t);

			if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_MOD,ifc_addr->net_sk_nat_t,&ep_evt) < 0 ){
				err = -errno;
				RHP_BUG("%d",err);
			}
		}

		ifc_addr = ifc_addr->lst_next;
  }

  rx_ifc->statistics.netif.rx_stop++;

  RHP_TRC(0,RHPTRCID_NETSOCK_RECV_STOP_RTRN,"xE",rx_ifc,err);
  return err;
}

static void _rhp_netsock_rx_esp_pkt_done_final(rhp_packet* pkt)
{
	rhp_ifc_entry* rx_ifc = (rhp_ifc_entry*)pkt->esp_pkt_pend_done_ctx;

	RHP_TRC(0,RHPTRCID_NETSOCK_RX_ESP_PKT_DESTRUCTOR_IMPL,"xxsLdfd",pkt,rx_ifc,rx_ifc->if_name,"VIF_TYPE",rx_ifc->tuntap_type,rx_ifc->rx_esp_pkt_pend_flag.c,rx_ifc->rx_esp_pkt_pend_flag.flag);

  RHP_LOCK(&(rx_ifc->lock));

	_rhp_netsock_recv_restart(rx_ifc);

  RHP_UNLOCK(&(rx_ifc->lock));
	rhp_ifc_unhold(rx_ifc);

	pkt->esp_pkt_pend_done_ctx = NULL;
	pkt->esp_pkt_pend_done = NULL;
	rhp_pkt_unhold(pkt);

	RHP_TRC(0,RHPTRCID_NETSOCK_RX_ESP_PKT_DESTRUCTOR_IMPL_RTRN,"xx",pkt,rx_ifc);
	return;
}

static int _rhp_netsock_rx_esp_pkt_done(rhp_packet* pkt)
{
	int err;
	rhp_ifc_entry* rx_ifc = (rhp_ifc_entry*)pkt->esp_pkt_pend_done_ctx;

	RHP_TRC(0,RHPTRCID_NETSOCK_RX_ESP_PKT_DONE,"xxsLdfd",pkt,rx_ifc,rx_ifc->if_name,"VIF_TYPE",rx_ifc->tuntap_type,rx_ifc->rx_esp_pkt_pend_flag.c,rx_ifc->rx_esp_pkt_pend_flag.flag);

	if( _rhp_atomic_flag_dec_and_test(&(rx_ifc->rx_esp_pkt_pend_flag),0,NULL) ){

		// Nobody knows when pkt->esp_pkt_pend_done()(rhp_pkt_unhold) is called. So, just to make sure,
		// switch the context to avoid racing condition of rx_ifc->lock.
		pkt->process_packet = _rhp_netsock_rx_esp_pkt_done_final;
		rhp_pkt_hold(pkt);

		err = rhp_wts_sta_invoke_task(RHP_WTS_DISP_RULE_SAME_WORKER,
				RHP_WTS_STA_TASK_NAME_PKT,RHP_WTS_DISP_LEVEL_HIGH_3,NULL,pkt);

		if( err ){
			RHP_BUG("%d",err);
		}

		RHP_TRC(0,RHPTRCID_NETSOCK_RX_ESP_PKT_DONE_PENDING,"xx",pkt,rx_ifc);
		return 1;

	}else{

		pkt->esp_pkt_pend_done = NULL;
		rhp_ifc_unhold(rx_ifc);
  }

	RHP_TRC(0,RHPTRCID_NETSOCK_RX_ESP_PKT_DONE_RTRN,"xx",pkt,rx_ifc);
	return 0;
}


int rhp_netsock_rx_dispach_packet(rhp_packet *pkt)
{
	int err;
  int priority;

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_DISPATCH_PACKET,"dLd",pkt,"PKT",pkt->type);

  if( pkt->type == RHP_PKT_IPV4_IKE || pkt->type == RHP_PKT_IPV6_IKE ){
  	priority = RHP_WTS_DISP_LEVEL_HIGH_2;
  }else{
  	priority = RHP_WTS_DISP_LEVEL_LOW_2;
  }

	pkt->process_packet = rhp_netsock_dispached_task;

	err = rhp_wts_sta_invoke_task(RHP_WTS_DISP_RULE_NETSOCK,
			RHP_WTS_STA_TASK_NAME_PKT,priority,pkt,pkt);

	if( err ){
		RHP_BUG("%d",err);
		return err;
	}

	return 0;
}


static inline void _rhp_netsock_recv_trunc_pkt(int rx_sk,ssize_t rx_len,int dmy_hdr_len)
{
  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_TRUNC_PKT,"dddddddd",rx_sk,rx_len,dmy_hdr_len,_rhp_rx_cur_buffer_size,_rhp_rx_def_pkt_size_cnt,_rhp_rx_ike_cur_buffer_size,rhp_gcfg_max_packet_size,rhp_gcfg_max_ike_packet_size);

  if( (rx_sk == RHP_NETSOCK_RX_SK_ESP || rx_sk == RHP_NETSOCK_RX_SK_NAT_T) &&
			rx_len < (rhp_gcfg_max_packet_size > rhp_gcfg_max_ike_packet_size ? rhp_gcfg_max_packet_size : rhp_gcfg_max_ike_packet_size)){

		_rhp_rx_cur_buffer_size = rx_len + dmy_hdr_len;

		_rhp_rx_def_pkt_size_cnt = 0;

	}else if( (rx_sk == RHP_NETSOCK_RX_SK_IKE) && rx_len < rhp_gcfg_max_ike_packet_size){

		_rhp_rx_ike_cur_buffer_size = rx_len + dmy_hdr_len;
  }

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_TRUNC_PKT_RTRN,"dddddd",rx_sk,rx_len,dmy_hdr_len,_rhp_rx_cur_buffer_size,_rhp_rx_def_pkt_size_cnt,_rhp_rx_ike_cur_buffer_size);
}

static inline void _rhp_netsock_recv_recover_buf_len(rhp_ifc_entry *ifc,int net_sk,ssize_t rx_len)
{
	if( _rhp_rx_cur_buffer_size > rhp_gcfg_max_packet_default_size ){

		if( rx_len < rhp_gcfg_max_packet_default_size ){
			_rhp_rx_def_pkt_size_cnt++;
		}else{
			_rhp_rx_def_pkt_size_cnt = 0;
		}

		if( rhp_gcfg_recover_packet_default_size_num &&
				_rhp_rx_def_pkt_size_cnt > rhp_gcfg_recover_packet_default_size_num ){

			RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_RECOVER_BUF_LEN_RECOVER_RX_SIZE,"xdddd",ifc,net_sk,rx_len,_rhp_rx_cur_buffer_size,rhp_gcfg_max_packet_default_size);

			_rhp_rx_cur_buffer_size = rhp_gcfg_max_packet_default_size;
			_rhp_rx_def_pkt_size_cnt = 0;

		}else{

			RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_RECOVER_BUF_LEN_KEEP_BIG_RX_SIZE,"xdddddd",ifc,net_sk,rx_len,_rhp_rx_cur_buffer_size,rhp_gcfg_max_packet_default_size,_rhp_rx_def_pkt_size_cnt,rhp_gcfg_recover_packet_default_size_num);
		}
	}
}

static inline void _rhp_netsock_recv_pkt_max_len(int rx_sk,ssize_t rx_len,int dmy_hdr_len)
{
	rx_len += dmy_hdr_len;

	switch( rx_sk ){
	case RHP_NETSOCK_RX_SK_IKE:
		if( rx_len > _rhp_stat_max_rx_pkt_ike_sk ){
			_rhp_stat_max_rx_pkt_ike_sk = rx_len;
		}
		break;
	case RHP_NETSOCK_RX_SK_NAT_T:
		if( rx_len > _rhp_stat_max_rx_pkt_ike_natt_sk ){
			_rhp_stat_max_rx_pkt_ike_natt_sk = rx_len;
		}
		break;
	case RHP_NETSOCK_RX_SK_ESP:
		if( rx_len > _rhp_stat_max_rx_pkt_esp_sk ){
			_rhp_stat_max_rx_pkt_esp_sk = rx_len;
		}
		break;
	}
}

static inline void _rhp_netsock_peek_rx_data(int rx_sk,int net_sk,
		int dmy_hdr_len,int* rx_len_r)
{
	int rx_buf_len = sizeof(rhp_proto_ike) + RHP_PROTO_NON_ESP_MARKER_SZ;
	u8 rx_buf[sizeof(rhp_proto_ike) + RHP_PROTO_NON_ESP_MARKER_SZ];
	struct msghdr msg;
	struct iovec iov[1];
	struct sockaddr_in peer_sin;
	ssize_t rx_len = 0;
	rhp_proto_ike* ikeh = NULL;

	//
	// [CAUTION]
	//
	// Don't initialize *rx_len_r here. A default length is already set
	// to rx_len_r by caller.
	//
	//

	if( rx_sk != RHP_NETSOCK_RX_SK_NAT_T && rx_sk != RHP_NETSOCK_RX_SK_IKE ){
		goto skip;
	}

	msg.msg_name = &peer_sin;
	msg.msg_namelen = sizeof(peer_sin);
	iov[0].iov_base = rx_buf;
	iov[0].iov_len  = rx_buf_len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	rx_len = recvmsg(net_sk,&msg,MSG_DONTWAIT | MSG_PEEK);
	if( rx_len < 0 ){
		RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_PEEK_RX_DATA_RECVMSG_ERR,"ddE",rx_sk,net_sk,-errno);
		goto error;
	}

	if( rx_sk == RHP_NETSOCK_RX_SK_NAT_T ){

		if( rx_len >= (ssize_t)(sizeof(rhp_proto_ike) + RHP_PROTO_NON_ESP_MARKER_SZ) &&
				*((u32*)rx_buf) == RHP_PROTO_NON_ESP_MARKER ){

			ikeh = (rhp_proto_ike*)(rx_buf + RHP_PROTO_NON_ESP_MARKER_SZ);
		}

	}else if( rx_sk == RHP_NETSOCK_RX_SK_IKE ){

		if( rx_len >= (ssize_t)sizeof(rhp_proto_ike) ){

			ikeh = (rhp_proto_ike*)rx_buf ;
		}
	}


	if( ikeh ){

		u32 ike_len = ntohl(ikeh->len);
		u32 max_len = (rhp_gcfg_max_packet_size > rhp_gcfg_max_ike_packet_size ? rhp_gcfg_max_packet_size : rhp_gcfg_max_ike_packet_size);
		int res_len;

		if( rx_sk == RHP_NETSOCK_RX_SK_NAT_T ){
			ike_len += RHP_PROTO_NON_ESP_MARKER_SZ;
		}

		res_len = (int)(ike_len < max_len ? ike_len : max_len) + dmy_hdr_len;

		if( res_len > 0 ){
			*rx_len_r = res_len;
		}else{
			RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_PEEK_RX_DATA_IKEV2_TOO_LARGE,"dddd",rx_sk,net_sk,rx_len,res_len);
		}
	}

error:
skip:
	RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_PEEK_RX_DATA,"dddd",rx_sk,net_sk,rx_len,*rx_len_r);
	return;
}

static inline int _rhp_netsock_recv_ctx(rhp_ifc_entry *ifc,rhp_ifc_addr* ifc_addr,int rx_sk,
		int* net_sk_r,u16* ike_port_r,int* pkt_buf_len_r)
{

	switch( rx_sk ){

  case RHP_NETSOCK_RX_SK_IKE:
    *ike_port_r = htons(rhp_gcfg_ike_port);
    *net_sk_r = ifc_addr->net_sk_ike;
    *pkt_buf_len_r = _rhp_rx_ike_cur_buffer_size;
    break;

  case RHP_NETSOCK_RX_SK_ESP:
    *ike_port_r = 0;
    *net_sk_r = ifc_addr->net_sk_esp;
  	*pkt_buf_len_r = _rhp_rx_cur_buffer_size;
    break;

  case RHP_NETSOCK_RX_SK_NAT_T:
    *ike_port_r = htons(rhp_gcfg_ike_port_nat_t);
    *net_sk_r = ifc_addr->net_sk_nat_t;
  	*pkt_buf_len_r = _rhp_rx_cur_buffer_size;
    break;

  default:
	  RHP_BUG("%d",rx_sk);
	  return -EINVAL;
  }

	return 0;
}

static inline void _rhp_netsock_recv_stat_trunc_err(rhp_ifc_entry *ifc,int rx_sk)
{
	ifc->statistics.netif.rx_trunc_err_pkts++;

	switch( rx_sk ){
	case RHP_NETSOCK_RX_SK_IKE:
		ifc->statistics.netif.rx_ikev2_sk_trunc_err_pkts++;
		break;
	case RHP_NETSOCK_RX_SK_NAT_T:
		ifc->statistics.netif.rx_nat_t_sk_trunc_err_pkts++;
		break;
	case RHP_NETSOCK_RX_SK_ESP:
		ifc->statistics.netif.rx_esp_raw_sk_trunc_err_pkts++;
		break;
	}
}

static inline void _rhp_netsock_recv_stat_rt_loop_err(rhp_ifc_entry *ifc,int rx_sk)
{
	ifc->statistics.netif.rx_invalid_pkts++;

	switch( rx_sk ){
	case RHP_NETSOCK_RX_SK_IKE:
		ifc->statistics.netif.rx_ikev2_invalid_pkts++;
		break;
	case RHP_NETSOCK_RX_SK_NAT_T:
		ifc->statistics.netif.rx_ikev2_nat_t_invalid_pkts++;
		break;
	case RHP_NETSOCK_RX_SK_ESP:
		ifc->statistics.netif.rx_esp_invalid_pkts++;
		break;
	}
}

static inline void _rhp_netsock_recv_stat_no_app_data(rhp_ifc_entry *ifc,int pkt_type,int rx_sk)
{
	ifc->statistics.netif.rx_invalid_pkts++;

	switch( pkt_type ){
	case RHP_PKT_IPV4_IKE:
	case RHP_PKT_IPV6_IKE:
		if( rx_sk == RHP_NETSOCK_RX_SK_NAT_T ){
			ifc->statistics.netif.rx_ikev2_nat_t_invalid_pkts++;
		}else{
			ifc->statistics.netif.rx_ikev2_invalid_pkts++;
		}
		break;
	case RHP_PKT_IPV4_ESP_NAT_T:
	case RHP_PKT_IPV6_ESP_NAT_T:
		ifc->statistics.netif.rx_esp_nat_t_invalid_pkts++;
		break;
	case RHP_PKT_IPV4_ESP:
	case RHP_PKT_IPV6_ESP:
		ifc->statistics.netif.rx_esp_invalid_pkts++;
		break;
	}
}

static inline void _rhp_netsock_recv_stat_disp_pkt_err(rhp_ifc_entry *ifc,int pkt_type,int rx_sk)
{
	ifc->statistics.netif.rx_err_pkts++;

	switch( pkt_type ){
	case RHP_PKT_IPV4_IKE:
	case RHP_PKT_IPV6_IKE:
		if( rx_sk == RHP_NETSOCK_RX_SK_NAT_T ){
			ifc->statistics.netif.rx_ikev2_nat_t_err_pkts++;
		}else{
			ifc->statistics.netif.rx_ikev2_err_pkts++;
		}
		break;
	case RHP_PKT_IPV4_ESP_NAT_T:
	case RHP_PKT_IPV6_ESP_NAT_T:
		ifc->statistics.netif.rx_esp_nat_t_err_pkts++;
		break;
	case RHP_PKT_IPV4_ESP:
	case RHP_PKT_IPV6_ESP:
		ifc->statistics.netif.rx_esp_err_pkts++;
		break;
	}
}

static inline void _rhp_netsock_recv_stat_rx_pkt_len(rhp_ifc_entry *ifc,int pkt_type,int rx_sk,ssize_t rx_len2)
{
	ifc->statistics.netif.rx_pkts++;
	ifc->statistics.netif.rx_bytes += rx_len2;

	switch( pkt_type ){
	case RHP_PKT_IPV4_IKE:
	case RHP_PKT_IPV6_IKE:
		if( rx_sk == RHP_NETSOCK_RX_SK_NAT_T ){
			ifc->statistics.netif.rx_ikev2_nat_t_pkts++;
			ifc->statistics.netif.rx_ikev2_nat_t_bytes += rx_len2;
		}else{
			ifc->statistics.netif.rx_ikev2_pkts++;
			ifc->statistics.netif.rx_ikev2_bytes += rx_len2;
		}
		break;
	case RHP_PKT_IPV4_ESP_NAT_T:
	case RHP_PKT_IPV6_ESP_NAT_T:
		ifc->statistics.netif.rx_esp_nat_t_pkts++;
		ifc->statistics.netif.rx_esp_nat_t_bytes += rx_len2;
		break;
	case RHP_PKT_IPV4_ESP:
	case RHP_PKT_IPV6_ESP:
		ifc->statistics.netif.rx_esp_pkts++;
		ifc->statistics.netif.rx_esp_bytes += rx_len2;
		break;
	}
}


#define RHP_NETSOCK_RX_PKT_IPV4_DMY_HEADERS_LEN	(sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v4) + sizeof(rhp_proto_udp))

// Needs ifc->lock acquired.
static int _rhp_netsock_recv_ipv4(rhp_ifc_entry *ifc,rhp_ifc_addr* ifc_addr,int rx_sk)
{
  u16 ike_port;
  ssize_t rx_len,rx_len2 = 0;
  int net_sk = -1;
  int pkt_buf_len;

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4,"xxsLd",ifc,ifc_addr,ifc->if_name,"NETSOCK_RX_SOCK",rx_sk);


  if( _rhp_netsock_recv_ctx(ifc,ifc_addr,rx_sk,&net_sk,&ike_port,&pkt_buf_len) ){
	  RHP_BUG("%d",rx_sk);
	  return -EINVAL;
  }


  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_PARAMS,"xLdWdddd",ifc,"NETSOCK_RX_SOCK",rx_sk,ike_port,net_sk,rhp_gcfg_max_ike_packet_size,rhp_gcfg_max_packet_size,_rhp_rx_cur_buffer_size);

  while( 1 ){

  	rhp_packet* pkt = NULL;
  	struct msghdr msg;
		struct iovec iov[1];
		struct sockaddr_in peer_sin;
		int buf_len = pkt_buf_len;
		int pkt_type = -1;
		rhp_proto_ether* dmy_ethhdr;
		rhp_proto_ip_v4* dmy_iphdr = NULL;
		rhp_proto_udp* dmy_udphdr = NULL;
		int mesg_len = 0;
		u8* data_head;
		int stop_recv = 0;
		u8 ikev2_exchg_type = 0;


		if( !RHP_PROCESS_IS_ACTIVE() ){
			rx_len = -EINTR;
			RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_NOT_ACTIVE,"");
			goto error;
		}


		if( rhp_gcfg_peek_rx_packet_size ){

			_rhp_netsock_peek_rx_data(rx_sk,net_sk,
					RHP_NETSOCK_RX_PKT_IPV4_DMY_HEADERS_LEN,&buf_len);
		}


		pkt = rhp_pkt_alloc(buf_len);
		if( pkt == NULL ){
			rx_len = -ENOMEM;
			RHP_BUG("%d",buf_len);
      RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_ALLOC_PKT_ERR,"xdd",ifc,net_sk,buf_len);
			goto error;
		}


		// RHP_NETSOCK_RX_PKT_IPV4_DMY_HEADERS_LEN bytes.
		dmy_ethhdr = (rhp_proto_ether*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ether));
		if( rx_sk == RHP_NETSOCK_RX_SK_IKE || rx_sk == RHP_NETSOCK_RX_SK_NAT_T ){
			dmy_iphdr = (rhp_proto_ip_v4*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ip_v4));
			dmy_udphdr = (rhp_proto_udp*)_rhp_pkt_push(pkt,sizeof(rhp_proto_udp));
		}


		data_head = pkt->data + pkt->len;

		msg.msg_name = &peer_sin;
		msg.msg_namelen = sizeof(peer_sin);
		iov[0].iov_base = data_head;
		iov[0].iov_len  = (buf_len - pkt->len);
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		msg.msg_flags = 0;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;

		rx_len = recvmsg(net_sk,&msg,MSG_TRUNC | MSG_DONTWAIT);
		if( rx_len < 0 ){

			rx_len = -errno;

			if( rx_sk == RHP_NETSOCK_RX_SK_IKE || rx_sk == RHP_NETSOCK_RX_SK_NAT_T ){
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_RECVMSG_ERR2,"sxd44WWE","[TRF](RX_ERR)",ifc,net_sk,peer_sin.sin_addr.s_addr,ifc_addr->addr.addr.v4,peer_sin.sin_port,ike_port,rx_len);
			}else if( rx_sk == RHP_NETSOCK_RX_SK_ESP ){
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_RECVMSG_ERR3,"sxd44E","[TRF](RX_ERR_ESP_RAW)",ifc,net_sk,peer_sin.sin_addr.s_addr,ifc_addr->addr.addr.v4,rx_len);
			}else{
				RHP_BUG("%d",rx_len);
			}

			if( rx_len != -EAGAIN && rx_len != -EINTR ){
				ifc->statistics.netif.rx_err_pkts++;
			}

			rhp_pkt_unhold(pkt);
			goto error;
		}
		rx_len2 = rx_len;
		mesg_len = rx_len;

#ifndef RHP_PKT_DEBUG
		{
			const char* tag;
			if( rx_sk == RHP_NETSOCK_RX_SK_IKE ){
				tag = "[TRF](RX_SK_IKEV2)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_RECVMSG_SK_IKE,"s44WWddda",tag,peer_sin.sin_addr.s_addr,ifc_addr->addr.addr.v4,peer_sin.sin_port,ike_port,buf_len,iov[0].iov_len,rx_len2,(rx_len2 > 256 ? 256 : rx_len2),RHP_TRC_FMT_A_IKEV2_UDP_SK,0,0,iov[0].iov_base);
			}else if( rx_sk == RHP_NETSOCK_RX_SK_NAT_T ){
				tag = "[TRF](RX_SK_IKEV2_NAT_T)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_RECVMSG_SK_IKE_NATT,"s44WWddda",tag,peer_sin.sin_addr.s_addr,ifc_addr->addr.addr.v4,peer_sin.sin_port,ike_port,buf_len,iov[0].iov_len,rx_len2,(rx_len2 > 256 ? 256 : rx_len2),RHP_TRC_FMT_A_IKEV2_NAT_T_UDP_SK,0,0,iov[0].iov_base);
			}else if( rx_sk == RHP_NETSOCK_RX_SK_ESP ){
				tag = "[TRF](RX_SK_ESP_RAW)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_RECVMSG_SK_ESP_RAW,"s44ddda",tag,peer_sin.sin_addr.s_addr,ifc_addr->addr.addr.v4,buf_len,iov[0].iov_len,rx_len2,(rx_len2 > 256 ? 256 : rx_len2),RHP_TRC_FMT_A_ESP_RAW_SK,0,0,iov[0].iov_base);
			}
		}
#else // RHP_PKT_DEBUG
		{
			const char* tag;
			if( rx_sk == RHP_NETSOCK_RX_SK_IKE ){
				tag = "[TRF](RX_SK_IKEV2)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_RECVMSG_SK_IKE_D,"s44WWddda",tag,peer_sin.sin_addr.s_addr,ifc_addr->addr.addr.v4,peer_sin.sin_port,ike_port,buf_len,iov[0].iov_len,rx_len2,rx_len2,RHP_TRC_FMT_A_IKEV2_UDP_SK,0,0,iov[0].iov_base);
			}else if( rx_sk == RHP_NETSOCK_RX_SK_NAT_T ){
				tag = "[TRF](RX_SK_IKEV2_NAT_T)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_RECVMSG_SK_IKE_NATT_D,"s44WWddda",tag,peer_sin.sin_addr.s_addr,ifc_addr->addr.addr.v4,peer_sin.sin_port,ike_port,buf_len,iov[0].iov_len,rx_len2,rx_len2,RHP_TRC_FMT_A_IKEV2_NAT_T_UDP_SK,0,0,iov[0].iov_base);
			}else if( rx_sk == RHP_NETSOCK_RX_SK_ESP ){
				tag = "[TRF](RX_SK_ESP_RAW)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_RECVMSG_SK_ESP_RAW_D,"s44ddda",tag,peer_sin.sin_addr.s_addr,ifc_addr->addr.addr.v4,buf_len,iov[0].iov_len,rx_len2,rx_len2,RHP_TRC_FMT_A_ESP_RAW_SK,0,0,iov[0].iov_base);
			}
		}
#endif // RHP_PKT_DEBUG


		_rhp_netsock_recv_pkt_max_len(rx_sk,rx_len,RHP_NETSOCK_RX_PKT_IPV4_DMY_HEADERS_LEN);


		if( msg.msg_flags & MSG_TRUNC ){

			RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_RECVMSG_TRUNC,"sxdxdddddp","[TRF](RX_TRUNC)",ifc,net_sk,pkt,rx_len,_rhp_rx_cur_buffer_size,_rhp_rx_ike_cur_buffer_size,buf_len,iov[0].iov_len,(rx_len > 256 ? 256 : rx_len),iov[0].iov_base);

			_rhp_netsock_recv_trunc_pkt(rx_sk,rx_len,RHP_NETSOCK_RX_PKT_IPV4_DMY_HEADERS_LEN);

			_rhp_netsock_recv_stat_trunc_err(ifc,rx_sk);

			rhp_pkt_unhold(pkt);
			continue;
		}


		if( rhp_gcfg_check_pkt_routing_loop &&
				rhp_ifc_is_my_ip_v4(peer_sin.sin_addr.s_addr) ){

			RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_RECVMSG_LOOPBACK,"xddd4",ifc,net_sk,rx_sk,rx_len,peer_sin.sin_addr.s_addr);

			_rhp_netsock_recv_stat_rt_loop_err(ifc,rx_sk);

			rhp_pkt_unhold(pkt);
			continue;
		}


		_rhp_netsock_recv_recover_buf_len(ifc,net_sk,rx_len);


		if( rx_sk == RHP_NETSOCK_RX_SK_IKE ){

			rhp_proto_ike* ikehdr = (rhp_proto_ike*)data_head;

			if( rx_len < (int)sizeof(rhp_proto_ike) ){

				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_RECVMSG_INVALID_LEN_PKT,"xddd",ifc,net_sk,rx_len,sizeof(rhp_proto_ike));

				ifc->statistics.netif.rx_invalid_pkts++;
				ifc->statistics.netif.rx_ikev2_invalid_pkts++;

				rhp_pkt_unhold(pkt);
   	  	continue;
			}

			RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_RECVMSG_IKEV2,"x",pkt);

			if( ikehdr->ver_major != RHP_PROTO_IKE_VER_MAJOR &&
					(!rhp_gcfg_ikev1_enabled || ikehdr->ver_major != RHP_PROTO_IKE_V1_VER_MAJOR) ){

				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_UNKNOWN_IKE_VER,"xdb",ifc,net_sk,ikehdr->ver_major);

				if( RHP_PROTO_IKE_HDR_RESPONSE(ikehdr->flag) ){
			  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_unsup_ver_packets);
				}else{
			  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_unsup_ver_packets);
				}

				ifc->statistics.netif.rx_invalid_pkts++;
				ifc->statistics.netif.rx_ikev2_invalid_pkts++;

				rhp_pkt_unhold(pkt);
   	  	continue;
			}

			if( rx_len > rhp_gcfg_max_ike_packet_size ){

				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_EXCEED_MAX_LEN,"xdd",ifc,net_sk,buf_len);

				if( RHP_PROTO_IKE_HDR_RESPONSE(ikehdr->flag) ){
			  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_invalid_len_packets);
				}else{
			  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_invalid_len_packets);
				}

				ifc->statistics.netif.rx_invalid_pkts++;
				ifc->statistics.netif.rx_ikev2_too_large_pkts++;

   	  	rhp_pkt_unhold(pkt);
   	  	continue;
      }

			pkt_type = RHP_PKT_IPV4_IKE;
			ikev2_exchg_type = ikehdr->exchange_type;

		}else if( rx_sk == RHP_NETSOCK_RX_SK_NAT_T ){

			if( rx_len >= ((int)sizeof(rhp_proto_ike) + RHP_PROTO_NON_ESP_MARKER_SZ) &&
					*((u32*)data_head) == RHP_PROTO_NON_ESP_MARKER ){

				// IKE packets

				rhp_proto_ike* ikehdr = (rhp_proto_ike*)(data_head + RHP_PROTO_NON_ESP_MARKER_SZ);

				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_RECVMSG_IKEV2,"x",pkt);

				if( ikehdr->ver_major != RHP_PROTO_IKE_VER_MAJOR &&
						(!rhp_gcfg_ikev1_enabled || ikehdr->ver_major != RHP_PROTO_IKE_V1_VER_MAJOR) ){

					RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_UNKNOWN_IKE_VER,"xdb",ifc,net_sk,ikehdr->ver_major);

					if( RHP_PROTO_IKE_HDR_RESPONSE(ikehdr->flag) ){
				  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_unsup_ver_packets);
					}else{
				  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_unsup_ver_packets);
					}

					ifc->statistics.netif.rx_invalid_pkts++;
					ifc->statistics.netif.rx_ikev2_nat_t_invalid_pkts++;

	   	  	rhp_pkt_unhold(pkt);
	   	  	continue;
				}

				if( rx_len > rhp_gcfg_max_ike_packet_size ){

					RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_EXCEED_MAX_LEN,"xdd",ifc,net_sk,buf_len);

					if( RHP_PROTO_IKE_HDR_RESPONSE(ikehdr->flag) ){
				  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_invalid_len_packets);
					}else{
				  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_invalid_len_packets);
					}

					ifc->statistics.netif.rx_invalid_pkts++;
					ifc->statistics.netif.rx_ikev2_nat_t_too_large_pkts++;

	   	  	rhp_pkt_unhold(pkt);
	   	  	continue;
				}

				pkt_type = RHP_PKT_IPV4_IKE;
				ikev2_exchg_type = ikehdr->exchange_type;

			}else{

				// ESP over UDP packets

				if( rx_len <= (int)sizeof(rhp_proto_esp) ){

					if( rx_len == 1 && data_head[0] == 0xFF ){

						RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_ESP_NAT_T_KEEP_ALIVE,"xdp",ifc,net_sk,rx_len,data_head);

						ifc->statistics.netif.rx_nat_t_keep_alive_pkts++;

					}else{

						RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_INVALID_ESP_NAT_T_LEN,"xdp",ifc,net_sk,rx_len,data_head);

						ifc->statistics.netif.rx_invalid_pkts++;
						ifc->statistics.netif.rx_esp_nat_t_invalid_pkts++;
					}

					rhp_pkt_unhold(pkt);
	   	  	continue;
				}

				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_RECVMSG_IPV4_RAW,"x",pkt);

				pkt_type = RHP_PKT_IPV4_ESP_NAT_T;
			}

		}else if( rx_sk == RHP_NETSOCK_RX_SK_ESP ){

			pkt_type = RHP_PKT_IPV4_ESP;

		}else{

			RHP_BUG("%d",rx_sk);

			rhp_pkt_unhold(pkt);
 	  	continue;
		}



		pkt->type = pkt_type;

		memcpy(dmy_ethhdr->dst_addr,ifc->mac,6);
		memset(dmy_ethhdr->src_addr,0,6);
		dmy_ethhdr->protocol = RHP_PROTO_ETH_IP;


		if( rx_sk == RHP_NETSOCK_RX_SK_IKE || rx_sk == RHP_NETSOCK_RX_SK_NAT_T ){

			dmy_iphdr->ver = 4;
			dmy_iphdr->ihl = 5;
			dmy_iphdr->tos = 0;
			dmy_iphdr->total_len = htons(mesg_len + sizeof(rhp_proto_ip_v4) + sizeof(rhp_proto_udp));
			dmy_iphdr->id = 0;
			dmy_iphdr->frag = 0;
			dmy_iphdr->ttl = 64;
			dmy_iphdr->protocol = RHP_PROTO_IP_UDP;
			dmy_iphdr->check_sum = 0;
			dmy_iphdr->src_addr = peer_sin.sin_addr.s_addr;
			dmy_iphdr->dst_addr = ifc_addr->addr.addr.v4;

			dmy_udphdr->src_port = peer_sin.sin_port;
			dmy_udphdr->dst_port = ike_port;
			dmy_udphdr->len = htons(mesg_len + sizeof(rhp_proto_udp));
			dmy_udphdr->check_sum = 0;

			pkt->l2.raw = (u8*)dmy_ethhdr;
			pkt->l3.raw = (u8*)dmy_iphdr;
			pkt->l4.raw = (u8*)dmy_udphdr;

			// This may still point a head of RHP_PROTO_NON_ESP_MARKER.
			// This pointer is modified in rhp_ikev2_check_mesg().
			pkt->app.raw = (u8*)_rhp_pkt_push(pkt,mesg_len);

		}else if( rx_sk == RHP_NETSOCK_RX_SK_ESP ){

			int iphdr_len,tot_len;

			if( mesg_len <= (int)sizeof(rhp_proto_ip_v4) ){

				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_RECVMSG_RAW_ESP_INVALID_RX_LEN,"xdpd",ifc,net_sk,mesg_len,iov[0].iov_base,sizeof(rhp_proto_ip_v4));

				ifc->statistics.netif.rx_invalid_pkts++;
				ifc->statistics.netif.rx_esp_invalid_pkts++;

				rhp_pkt_unhold(pkt);

   	  	continue;
   	  }

			dmy_iphdr = (rhp_proto_ip_v4*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ip_v4));

			iphdr_len = (dmy_iphdr->ihl*4);
			tot_len = ntohs(dmy_iphdr->total_len);

			if( iphdr_len < (int)sizeof(rhp_proto_ip_v4) ){

				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_RECVMSG_RAW_ESP_INVALID_HDR_LEN,"xddp",ifc,net_sk,iphdr_len,mesg_len,iov[0].iov_base);

				ifc->statistics.netif.rx_invalid_pkts++;
				ifc->statistics.netif.rx_esp_invalid_pkts++;

				rhp_pkt_unhold(pkt);
				continue;
			}

			if( _rhp_pkt_push(pkt,(iphdr_len - sizeof(rhp_proto_ip_v4))) == NULL ){

				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_RECVMSG_RAW_ESP_INVALID_DATA_LEN,"xddp",ifc,net_sk,iphdr_len,mesg_len,iov[0].iov_base);

				ifc->statistics.netif.rx_invalid_pkts++;
				ifc->statistics.netif.rx_esp_invalid_pkts++;

				rhp_pkt_unhold(pkt);
				continue;
			}

			if( mesg_len != tot_len ){

				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_RECVMSG_RAW_ESP_INVALID_RX_DATA_LEN_OR_HDR_LEN,"xdddp",ifc,net_sk,iphdr_len,tot_len,mesg_len,iov[0].iov_base);

				ifc->statistics.netif.rx_invalid_pkts++;
				ifc->statistics.netif.rx_esp_invalid_pkts++;

				rhp_pkt_unhold(pkt);
				continue;
			}

			if( tot_len - iphdr_len <= (int)sizeof(rhp_proto_esp) ){

				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_RECVMSG_RAW_ESP_INVALID_ESP_HDR_LEN,"xdddddp",ifc,net_sk,iphdr_len,tot_len,(tot_len - iphdr_len),sizeof(rhp_proto_esp),mesg_len,iov[0].iov_base);

				ifc->statistics.netif.rx_invalid_pkts++;
				ifc->statistics.netif.rx_esp_invalid_pkts++;

				rhp_pkt_unhold(pkt);
				continue;
			}

			pkt->l2.raw = (u8*)dmy_ethhdr;
			pkt->l3.raw = (u8*)dmy_iphdr;
			pkt->app.raw = (u8*)_rhp_pkt_push(pkt,(mesg_len - iphdr_len));

		}else{
			RHP_BUG("%d",rx_sk);
		}


		if( pkt->app.raw == NULL ){

			RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_RECVMSG_NO_APP_DATA,"xdp",ifc,net_sk,mesg_len,iov[0].iov_base);

			_rhp_netsock_recv_stat_no_app_data(ifc,pkt_type,rx_sk);

			rhp_pkt_unhold(pkt);
   		continue;
		}


		pkt->rx_if_index = ifc->if_index;
		pkt->rx_ifc = ifc;
		rhp_ifc_hold(ifc);


		if( pkt->type == RHP_PKT_IPV4_ESP || pkt->type == RHP_PKT_IPV4_ESP_NAT_T ){

				pkt->esp_pkt_pend_done = _rhp_netsock_rx_esp_pkt_done;
				pkt->esp_pkt_pend_done_ctx = ifc;
				rhp_ifc_hold(ifc);

				if( _rhp_atomic_flag_inc_and_test(&(ifc->rx_esp_pkt_pend_flag),rhp_gcfg_netsock_rx_esp_pkt_upper_limit,NULL) ){

					_rhp_netsock_recv_stop(ifc);
					stop_recv = 1;
				}
		}

		rhp_pkt_trace_dump("_rhp_netsock_recv_ipv4",pkt);

		if( RHP_NETSOCK_PCAP_PKT(pkt_type,ikev2_exchg_type) ){

			_rhp_netsock_pcap_write(pkt);
		}


		rx_len = rhp_netsock_rx_dispach_packet(pkt);
		if( rx_len ){

			RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_RECVMSG_DISP_ERR,"xdxE",ifc,net_sk,pkt,rx_len);

			_rhp_netsock_recv_stat_disp_pkt_err(ifc,pkt_type,rx_sk);

			rhp_pkt_unhold(pkt);
			continue;
		}


		_rhp_netsock_recv_stat_rx_pkt_len(ifc,pkt_type,rx_sk,rx_len2);


		if( stop_recv ){
			break;
		}
  }

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_RECVMSG_RTRN,"xddd",ifc,net_sk,_rhp_rx_cur_buffer_size,_rhp_rx_ike_cur_buffer_size);
  return 0;

error:
  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV4_RECVMSG_RTRN_ERR,"xdddd",ifc,net_sk,rx_len,_rhp_rx_cur_buffer_size,_rhp_rx_ike_cur_buffer_size);
  return rx_len;
}


#define RHP_NETSOCK_RX_PKT_IPV6_DMY_HEADERS_LEN	(sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v6) + sizeof(rhp_proto_udp))

// Needs ifc->lock acquired.
static int _rhp_netsock_recv_ipv6(rhp_ifc_entry *ifc,rhp_ifc_addr* ifc_addr,int rx_sk)
{
  u16 ike_port;
  ssize_t rx_len,rx_len2 = 0;
  int net_sk = -1;
  int pkt_buf_len;

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6,"xxsLd",ifc,ifc_addr,ifc->if_name,"NETSOCK_RX_SOCK",rx_sk);


  if( _rhp_netsock_recv_ctx(ifc,ifc_addr,rx_sk,&net_sk,&ike_port,&pkt_buf_len) ){
	  RHP_BUG("%d",rx_sk);
	  return -EINVAL;
  }


  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_PARAMS,"xLdWdddd",ifc,"NETSOCK_RX_SOCK",rx_sk,ike_port,net_sk,rhp_gcfg_max_ike_packet_size,rhp_gcfg_max_packet_size,_rhp_rx_cur_buffer_size);

  while( 1 ){

  	rhp_packet* pkt = NULL;
  	struct msghdr msg;
		struct iovec iov[1];
		struct sockaddr_in6 peer_sin;
		int buf_len = pkt_buf_len;
		int pkt_type = -1;
		rhp_proto_ether* dmy_ethhdr;
		rhp_proto_ip_v6* dmy_ip6hdr;
		rhp_proto_udp* dmy_udphdr = NULL;
		int mesg_len = 0;
		u8* data_head;
		int stop_recv = 0;
		u8 ikev2_exchg_type = 0;


		if( !RHP_PROCESS_IS_ACTIVE() ){
			rx_len = -EINTR;
			RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_NOT_ACTIVE,"");
			goto error;
		}


		if( rhp_gcfg_peek_rx_packet_size ){

			_rhp_netsock_peek_rx_data(rx_sk,net_sk,
					RHP_NETSOCK_RX_PKT_IPV6_DMY_HEADERS_LEN,&buf_len);
		}


		pkt = rhp_pkt_alloc(buf_len);
		if( pkt == NULL ){
			rx_len = -ENOMEM;
			RHP_BUG("%d",buf_len);
      RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_ALLOC_PKT_ERR,"xdd",ifc,net_sk,buf_len);
			goto error;
		}


		// RHP_NETSOCK_RX_PKT_IPV6_DMY_HEADERS_LEN bytes.
		dmy_ethhdr = (rhp_proto_ether*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ether));
		dmy_ip6hdr = (rhp_proto_ip_v6*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ip_v6));
		if( rx_sk == RHP_NETSOCK_RX_SK_IKE || rx_sk == RHP_NETSOCK_RX_SK_NAT_T ){
			dmy_udphdr = (rhp_proto_udp*)_rhp_pkt_push(pkt,sizeof(rhp_proto_udp));
		}


		data_head = pkt->data + pkt->len;

		msg.msg_name = &peer_sin;
		msg.msg_namelen = sizeof(peer_sin);
		iov[0].iov_base = data_head;
		iov[0].iov_len  = (buf_len - pkt->len);
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		msg.msg_flags = 0;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;

		rx_len = recvmsg(net_sk,&msg,MSG_TRUNC | MSG_DONTWAIT);
		if( rx_len < 0 ){

			rx_len = -errno;

			if( rx_sk == RHP_NETSOCK_RX_SK_IKE || rx_sk == RHP_NETSOCK_RX_SK_NAT_T ){
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_RECVMSG_ERR2,"sxd66WWE","[TRF](RX_ERR_V6)",ifc,net_sk,peer_sin.sin6_addr.s6_addr,ifc_addr->addr.addr.v6,peer_sin.sin6_port,ike_port,rx_len);
			}else if( rx_sk == RHP_NETSOCK_RX_SK_ESP ){
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_RECVMSG_ERR3,"sxd66E","[TRF](RX_ERR_ESP_RAW_V6)",ifc,net_sk,peer_sin.sin6_addr.s6_addr,ifc_addr->addr.addr.v6,rx_len);
			}else{
				RHP_BUG("%d",rx_len);
			}

			if( rx_len != -EAGAIN && rx_len != -EINTR ){
				ifc->statistics.netif.rx_err_pkts++;
			}

			rhp_pkt_unhold(pkt);
			goto error;
		}
		rx_len2 = rx_len;
		mesg_len = rx_len;

#ifndef RHP_PKT_DEBUG
		{
			const char* tag;
			if( rx_sk == RHP_NETSOCK_RX_SK_IKE ){
				tag = "[TRF](RX_SK_IKEV2_V6)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_RECVMSG_SK_IKE,"s66WWddda",tag,peer_sin.sin6_addr.s6_addr,ifc_addr->addr.addr.v6,peer_sin.sin6_port,ike_port,buf_len,iov[0].iov_len,rx_len2,(rx_len2 > 256 ? 256 : rx_len2),RHP_TRC_FMT_A_IKEV2_UDP_SK,0,0,iov[0].iov_base);
			}else if( rx_sk == RHP_NETSOCK_RX_SK_NAT_T ){
				tag = "[TRF](RX_SK_IKEV2_NAT_T_V6)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_RECVMSG_SK_IKE_NATT,"s66WWddda",tag,peer_sin.sin6_addr.s6_addr,ifc_addr->addr.addr.v6,peer_sin.sin6_port,ike_port,buf_len,iov[0].iov_len,rx_len2,(rx_len2 > 256 ? 256 : rx_len2),RHP_TRC_FMT_A_IKEV2_NAT_T_UDP_SK,0,0,iov[0].iov_base);
			}else if( rx_sk == RHP_NETSOCK_RX_SK_ESP ){
				tag = "[TRF](RX_SK_ESP_RAW_V6)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_RECVMSG_SK_ESP_RAW,"s66ddda",tag,peer_sin.sin6_addr.s6_addr,ifc_addr->addr.addr.v6,buf_len,iov[0].iov_len,rx_len2,(rx_len2 > 256 ? 256 : rx_len2),RHP_TRC_FMT_A_ESP_RAW_SK,0,0,iov[0].iov_base);
			}
		}
#else // RHP_PKT_DEBUG
		{
			const char* tag;
			if( rx_sk == RHP_NETSOCK_RX_SK_IKE ){
				tag = "[TRF](RX_SK_IKEV2_V6)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_RECVMSG_SK_IKE_D,"s66WWddda",tag,peer_sin.sin6_addr.s6_addr,ifc_addr->addr.addr.v6,peer_sin.sin6_port,ike_port,buf_len,iov[0].iov_len,rx_len2,rx_len2,RHP_TRC_FMT_A_IKEV2_UDP_SK,0,0,iov[0].iov_base);
			}else if( rx_sk == RHP_NETSOCK_RX_SK_NAT_T ){
				tag = "[TRF](RX_SK_IKEV2_NAT_T_V6)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_RECVMSG_SK_IKE_NATT_D,"s66WWddda",tag,peer_sin.sin6_addr.s6_addr,ifc_addr->addr.addr.v6,peer_sin.sin6_port,ike_port,buf_len,iov[0].iov_len,rx_len2,rx_len2,RHP_TRC_FMT_A_IKEV2_NAT_T_UDP_SK,0,0,iov[0].iov_base);
			}else if( rx_sk == RHP_NETSOCK_RX_SK_ESP ){
				tag = "[TRF](RX_SK_ESP_RAW_V6)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_RECVMSG_SK_ESP_RAW_D,"s66ddda",tag,peer_sin.sin6_addr.s6_addr,ifc_addr->addr.addr.v6,buf_len,iov[0].iov_len,rx_len2,rx_len2,RHP_TRC_FMT_A_ESP_RAW_SK,0,0,iov[0].iov_base);
			}
		}
#endif // RHP_PKT_DEBUG


		_rhp_netsock_recv_pkt_max_len(rx_sk,rx_len,RHP_NETSOCK_RX_PKT_IPV6_DMY_HEADERS_LEN);


		if( msg.msg_flags & MSG_TRUNC ){

			RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_RECVMSG_TRUNC,"sxdxdddddp","[TRF](RX_TRUNC_V6)",ifc,net_sk,pkt,rx_len,_rhp_rx_cur_buffer_size,_rhp_rx_ike_cur_buffer_size,buf_len,iov[0].iov_len,(rx_len > 256 ? 256 : rx_len),iov[0].iov_base);

			_rhp_netsock_recv_trunc_pkt(rx_sk,rx_len,RHP_NETSOCK_RX_PKT_IPV6_DMY_HEADERS_LEN);

			_rhp_netsock_recv_stat_trunc_err(ifc,rx_sk);

			rhp_pkt_unhold(pkt);
			continue;
		}


		if( rhp_gcfg_check_pkt_routing_loop &&
				rhp_ifc_is_my_ip_v6(peer_sin.sin6_addr.s6_addr) ){

			RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_RECVMSG_LOOPBACK,"xddd6",ifc,net_sk,rx_sk,rx_len,peer_sin.sin6_addr.s6_addr);

			_rhp_netsock_recv_stat_rt_loop_err(ifc,rx_sk);

			rhp_pkt_unhold(pkt);
			continue;
		}


		_rhp_netsock_recv_recover_buf_len(ifc,net_sk,rx_len);


		if( rx_sk == RHP_NETSOCK_RX_SK_IKE ){

			rhp_proto_ike* ikehdr = (rhp_proto_ike*)data_head;

			if( rx_len < (int)sizeof(rhp_proto_ike) ){

				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_RECVMSG_INVALID_LEN_PKT,"xddd",ifc,net_sk,rx_len,sizeof(rhp_proto_ike));

				ifc->statistics.netif.rx_invalid_pkts++;
				ifc->statistics.netif.rx_ikev2_invalid_pkts++;

				rhp_pkt_unhold(pkt);
   	  	continue;
			}

			RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_RECVMSG_IKEV2,"x",pkt);

			if( ikehdr->ver_major != RHP_PROTO_IKE_VER_MAJOR &&
					(!rhp_gcfg_ikev1_enabled || ikehdr->ver_major != RHP_PROTO_IKE_V1_VER_MAJOR) ){

				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_UNKNOWN_IKE_VER,"xdb",ifc,net_sk,ikehdr->ver_major);

				if( RHP_PROTO_IKE_HDR_RESPONSE(ikehdr->flag) ){
			  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_unsup_ver_packets);
				}else{
			  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_unsup_ver_packets);
				}

				ifc->statistics.netif.rx_invalid_pkts++;
				ifc->statistics.netif.rx_ikev2_invalid_pkts++;

				rhp_pkt_unhold(pkt);
   	  	continue;
			}

			if( rx_len > rhp_gcfg_max_ike_packet_size ){

				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_EXCEED_MAX_LEN,"xdd",ifc,net_sk,buf_len);

				if( RHP_PROTO_IKE_HDR_RESPONSE(ikehdr->flag) ){
			  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_invalid_len_packets);
				}else{
			  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_invalid_len_packets);
				}

				ifc->statistics.netif.rx_invalid_pkts++;
				ifc->statistics.netif.rx_ikev2_too_large_pkts++;

   	  	rhp_pkt_unhold(pkt);
   	  	continue;
      }

			pkt_type = RHP_PKT_IPV6_IKE;
			ikev2_exchg_type = ikehdr->exchange_type;

		}else if( rx_sk == RHP_NETSOCK_RX_SK_NAT_T ){

			if( rx_len >= ((int)sizeof(rhp_proto_ike) + RHP_PROTO_NON_ESP_MARKER_SZ) &&
					*((u32*)data_head) == RHP_PROTO_NON_ESP_MARKER ){

				// IKE packets

				rhp_proto_ike* ikehdr = (rhp_proto_ike*)(data_head + RHP_PROTO_NON_ESP_MARKER_SZ);

				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_RECVMSG_IKEV2,"x",pkt);

				if( ikehdr->ver_major != RHP_PROTO_IKE_VER_MAJOR &&
						(!rhp_gcfg_ikev1_enabled || ikehdr->ver_major != RHP_PROTO_IKE_V1_VER_MAJOR) ){

					RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_UNKNOWN_IKE_VER,"xdb",ifc,net_sk,ikehdr->ver_major);

					if( RHP_PROTO_IKE_HDR_RESPONSE(ikehdr->flag) ){
				  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_unsup_ver_packets);
					}else{
				  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_unsup_ver_packets);
					}

					ifc->statistics.netif.rx_invalid_pkts++;
					ifc->statistics.netif.rx_ikev2_nat_t_invalid_pkts++;

	   	  	rhp_pkt_unhold(pkt);
	   	  	continue;
				}

				if( rx_len > rhp_gcfg_max_ike_packet_size ){

					RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_EXCEED_MAX_LEN,"xdd",ifc,net_sk,buf_len);

					if( RHP_PROTO_IKE_HDR_RESPONSE(ikehdr->flag) ){
				  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_invalid_len_packets);
					}else{
				  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_invalid_len_packets);
					}

					ifc->statistics.netif.rx_invalid_pkts++;
					ifc->statistics.netif.rx_ikev2_nat_t_too_large_pkts++;

	   	  	rhp_pkt_unhold(pkt);
	   	  	continue;
				}

				pkt_type = RHP_PKT_IPV6_IKE;
				ikev2_exchg_type = ikehdr->exchange_type;

			}else{

				// ESP over UDP packets

				if( rx_len <= (int)sizeof(rhp_proto_esp) ){

					if( rx_len == 1 && data_head[0] == 0xFF ){

						RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_ESP_NAT_T_KEEP_ALIVE,"xdp",ifc,net_sk,rx_len,data_head);

						ifc->statistics.netif.rx_nat_t_keep_alive_pkts++;

					}else{

						RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_INVALID_ESP_NAT_T_LEN,"xdp",ifc,net_sk,rx_len,data_head);

						ifc->statistics.netif.rx_invalid_pkts++;
						ifc->statistics.netif.rx_esp_nat_t_invalid_pkts++;
					}

					rhp_pkt_unhold(pkt);
	   	  	continue;
				}

				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_RECVMSG_IPV4_RAW,"x",pkt);

				pkt_type = RHP_PKT_IPV6_ESP_NAT_T;
			}

		}else if( rx_sk == RHP_NETSOCK_RX_SK_ESP ){

			pkt_type = RHP_PKT_IPV6_ESP;

		}else{

			RHP_BUG("%d",rx_sk);

			rhp_pkt_unhold(pkt);
 	  	continue;
		}


		pkt->type = pkt_type;

		memcpy(dmy_ethhdr->dst_addr,ifc->mac,6);
		memset(dmy_ethhdr->src_addr,0,6);
		dmy_ethhdr->protocol = RHP_PROTO_ETH_IPV6;

		dmy_ip6hdr->ver = 6;
		dmy_ip6hdr->priority = 0;
		dmy_ip6hdr->flow_label[0] = 0;
		dmy_ip6hdr->flow_label[1] = 0;
		dmy_ip6hdr->flow_label[2] = 0;
		dmy_ip6hdr->hop_limit = 64;
		memcpy(dmy_ip6hdr->src_addr,peer_sin.sin6_addr.s6_addr,16);
		memcpy(dmy_ip6hdr->dst_addr,ifc_addr->addr.addr.v6,16);


		if( rx_sk == RHP_NETSOCK_RX_SK_IKE || rx_sk == RHP_NETSOCK_RX_SK_NAT_T ){

			dmy_ip6hdr->next_header = RHP_PROTO_IP_UDP;
			dmy_ip6hdr->payload_len = htons(mesg_len + sizeof(rhp_proto_udp));

			dmy_udphdr->src_port = peer_sin.sin6_port;
			dmy_udphdr->dst_port = ike_port;
			dmy_udphdr->len = htons(mesg_len + sizeof(rhp_proto_udp));
			dmy_udphdr->check_sum = 0;


			// This may still point a head of RHP_PROTO_NON_ESP_MARKER.
			// This pointer is modified in rhp_ikev2_check_mesg().
			pkt->app.raw = (u8*)_rhp_pkt_push(pkt,mesg_len);

		}else if( rx_sk == RHP_NETSOCK_RX_SK_ESP ){

			dmy_ip6hdr->next_header = RHP_PROTO_IP_ESP;
			dmy_ip6hdr->payload_len = htons(mesg_len);

			if( mesg_len <= (int)sizeof(rhp_proto_esp) ){

				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_RECVMSG_RAW_ESP_INVALID_ESP_HDR_LEN,"xdp",ifc,net_sk,mesg_len,iov[0].iov_base);

				ifc->statistics.netif.rx_invalid_pkts++;
				ifc->statistics.netif.rx_esp_invalid_pkts++;

				rhp_pkt_unhold(pkt);
				continue;
			}

			pkt->app.raw = (u8*)_rhp_pkt_push(pkt,mesg_len);

		}else{
			RHP_BUG("%d",rx_sk);
		}

		if( pkt->app.raw == NULL ){

			RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_RECVMSG_NO_APP_DATA,"xdp",ifc,net_sk,mesg_len,iov[0].iov_base);

			_rhp_netsock_recv_stat_no_app_data(ifc,pkt_type,rx_sk);

			rhp_pkt_unhold(pkt);
   		continue;
		}

		pkt->l2.raw = (u8*)dmy_ethhdr;
		pkt->l3.raw = (u8*)dmy_ip6hdr;
		if( dmy_udphdr ){
			pkt->l4.raw = (u8*)dmy_udphdr;
		}

		pkt->rx_if_index = ifc->if_index;
		pkt->rx_ifc = ifc;
		rhp_ifc_hold(ifc);


		if( pkt->type == RHP_PKT_IPV6_ESP || pkt->type == RHP_PKT_IPV6_ESP_NAT_T ){

				pkt->esp_pkt_pend_done = _rhp_netsock_rx_esp_pkt_done;
				pkt->esp_pkt_pend_done_ctx = ifc;
				rhp_ifc_hold(ifc);

				if( _rhp_atomic_flag_inc_and_test(&(ifc->rx_esp_pkt_pend_flag),rhp_gcfg_netsock_rx_esp_pkt_upper_limit,NULL) ){

					_rhp_netsock_recv_stop(ifc);
					stop_recv = 1;
				}
		}

		rhp_pkt_trace_dump("_rhp_netsock_recv_ipv6",pkt);

		if( RHP_NETSOCK_PCAP_PKT(pkt_type,ikev2_exchg_type) ){

			_rhp_netsock_pcap_write(pkt);
		}


		rx_len = rhp_netsock_rx_dispach_packet(pkt);
		if( rx_len ){

			RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_RECVMSG_DISP_ERR,"xdxE",ifc,net_sk,pkt,rx_len);

			_rhp_netsock_recv_stat_disp_pkt_err(ifc,pkt_type,rx_sk);

			rhp_pkt_unhold(pkt);
			continue;
		}


		_rhp_netsock_recv_stat_rx_pkt_len(ifc,pkt_type,rx_sk,rx_len2);


		if( stop_recv ){
			break;
		}
  }

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_RECVMSG_RTRN,"xddd",ifc,net_sk,_rhp_rx_cur_buffer_size,_rhp_rx_ike_cur_buffer_size);
  return 0;

error:
  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV_IPV6_RECVMSG_RTRN_ERR,"xdddd",ifc,net_sk,rx_len,_rhp_rx_cur_buffer_size,_rhp_rx_ike_cur_buffer_size);
  return rx_len;
}


// Needs ifc->lock acquired.
static int _rhp_netsock_recv(rhp_ifc_entry *ifc,rhp_ifc_addr* ifc_addr,int rx_sk)
{
  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_RECV,"xxsdddLdLd",ifc,ifc_addr,ifc->if_name,ifc_addr->net_sk_ike,ifc_addr->net_sk_nat_t,ifc_addr->net_sk_esp,"AF",ifc_addr->addr.addr_family,"NETSOCK_RX_SOCK",rx_sk);

  switch( ifc_addr->addr.addr_family ){

  case AF_INET:

  	return _rhp_netsock_recv_ipv4(ifc,ifc_addr,rx_sk);

  case AF_INET6:

  	return _rhp_netsock_recv_ipv6(ifc,ifc_addr,rx_sk);

  default:
  	RHP_BUG("%d",ifc_addr->addr.addr_family);
  	return -EINVAL;
  }
}


static inline int _rhp_netsock_dbg_is_lost_pkt(rhp_packet* pkt)
{
	u32 randtx;
	int n;

	if( pkt->type == RHP_PKT_IPV4_IKE ){

		if( !rhp_gcfg_dbg_tx_ikev2_pkt_lost_rate ){
			return 0;
		}

		rhp_random_bytes((u8*)&randtx,sizeof(u32));
		randtx = randtx % 100;

		n = _rhp_atomic_read(&_rhp_dbg_tx_ikev2_pkt_consecutive_num);
	  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_DBG_IS_LOST_PKT_IKEV2,"xLdddu",pkt,"PKT",pkt->type,n,rhp_gcfg_dbg_tx_ikev2_pkt_cons_drop,randtx);

		if( (int)randtx > rhp_gcfg_dbg_tx_ikev2_pkt_lost_rate ){
			_rhp_atomic_set(&_rhp_dbg_tx_ikev2_pkt_consecutive_num,0);
  		return 0;
  	}

		if( (n = (int)_rhp_atomic_inc_and_read(&_rhp_dbg_tx_ikev2_pkt_consecutive_num)) > rhp_gcfg_dbg_tx_ikev2_pkt_cons_drop ){
			_rhp_atomic_set(&_rhp_dbg_tx_ikev2_pkt_consecutive_num,0);
  		return 0;
		}

		if( pkt->app.raw ){

			rhp_proto_ike* ikeh;

		  if( *((u32*)pkt->app.raw) == RHP_PROTO_NON_ESP_MARKER ){
		    ikeh = (rhp_proto_ike*)(pkt->app.raw + RHP_PROTO_NON_ESP_MARKER_SZ);
		  }else{
		    ikeh = pkt->app.ikeh;
		  }


		  RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_DROP_IKEV2_PKT,"44WWGGdLJ",(pkt->l3.raw ? pkt->l3.iph_v4->src_addr : 0),(pkt->l3.raw ? pkt->l3.iph_v4->dst_addr : 0),(pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt->l4.raw ? pkt->l4.udph->dst_port : 0),ikeh->init_spi,ikeh->resp_spi,RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag),"PROTO_IKE_EXCHG",(int)ikeh->exchange_type,ikeh->message_id);

		}else{
			RHP_BUG("");
		}

  }else if( (pkt->type == RHP_PKT_IPV4_ESP) ||
  					(pkt->type == RHP_PKT_IPV4_ESP_NAT_T) ||
  					(pkt->type == RHP_PKT_IPV6_ESP) ||
  					(pkt->type == RHP_PKT_IPV6_ESP_NAT_T) ){

		if( !rhp_gcfg_dbg_tx_esp_pkt_lost_rate ){
			return 0;
		}

		rhp_random_bytes((u8*)&randtx,sizeof(u32));
		randtx = randtx % 100;

		n = _rhp_atomic_read(&_rhp_dbg_tx_esp_pkt_consecutive_num);
	  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_DBG_IS_LOST_PKT_ESP_DROP,"xLdddu",pkt,"PKT",pkt->type,n,rhp_gcfg_dbg_tx_esp_pkt_cons_drop,randtx);

		if( (int)randtx > rhp_gcfg_dbg_tx_esp_pkt_lost_rate ){
			_rhp_atomic_set(&_rhp_dbg_tx_esp_pkt_consecutive_num,0);
  		return 0;
  	}

		if( (n = (int)_rhp_atomic_inc_and_read(&_rhp_dbg_tx_esp_pkt_consecutive_num)) > rhp_gcfg_dbg_tx_esp_pkt_cons_drop ){
			_rhp_atomic_set(&_rhp_dbg_tx_esp_pkt_consecutive_num,0);
  		return 0;
		}

  }else{
  	return 0;
  }

  return 1;
}

static inline void _rhp_netsock_send_stat(rhp_ifc_entry* ifc,rhp_ifc_addr* ifc_addr,
		int net_sk,int tx_bytes,rhp_packet* pkt)
{
	ifc->statistics.netif.tx_pkts++;
	ifc->statistics.netif.tx_bytes += tx_bytes;

	switch( pkt->type ){
	case RHP_PKT_IPV4_IKE:
	case RHP_PKT_IPV6_IKE:
		if( pkt->nat_t_keep_alive ){
	  	ifc->statistics.netif.tx_nat_t_keep_alive_pkts++;
		}else if( net_sk == ifc_addr->net_sk_ike ){
	  	ifc->statistics.netif.tx_ikev2_pkts++;
	  	ifc->statistics.netif.tx_ikev2_bytes =+ tx_bytes;
		}else if( net_sk == ifc_addr->net_sk_nat_t ){
	  	ifc->statistics.netif.tx_ikev2_nat_t_pkts++;
	  	ifc->statistics.netif.tx_ikev2_nat_t_bytes += tx_bytes;
		}
		break;
	case RHP_PKT_IPV4_ESP_NAT_T:
	case RHP_PKT_IPV6_ESP_NAT_T:
  	ifc->statistics.netif.tx_esp_nat_t_pkts++;
  	ifc->statistics.netif.tx_esp_nat_t_bytes += tx_bytes;
		break;
	case RHP_PKT_IPV4_ESP:
	case RHP_PKT_IPV6_ESP:
  	ifc->statistics.netif.tx_esp_pkts++;
  	ifc->statistics.netif.tx_esp_bytes += tx_bytes;
		break;
	default:
		break;
	}
}

static inline void _rhp_netsock_send_stat_err(rhp_ifc_entry* ifc,rhp_ifc_addr* ifc_addr,
		int net_sk,rhp_packet* pkt)
{
	ifc->statistics.netif.tx_err_pkts++;

	if( pkt ){

		switch( pkt->type ){
		case RHP_PKT_IPV4_IKE:
			if( net_sk == ifc_addr->net_sk_ike ){
				ifc->statistics.netif.tx_ikev2_err_pkts++;
			}else if( net_sk == ifc_addr->net_sk_nat_t ){
				ifc->statistics.netif.tx_ikev2_nat_t_err_pkts++;
			}
			break;
		case RHP_PKT_IPV4_ESP_NAT_T:
			ifc->statistics.netif.tx_esp_nat_t_err_pkts++;
			break;
		case RHP_PKT_IPV4_ESP:
			ifc->statistics.netif.tx_esp_err_pkts++;
			break;
		default:
			break;
		}
	}
}


#ifdef RHP_PKT_DBG_PRINT_PKT_DATA
static void _rhp_netsock_print_pkt_data(rhp_packet* pkt,int tx_len,u8* tx_buf)
{
#define RHP_PKT_CAP_FILE_1	"/home/rhpmain/tmp/ike_sa_init_i.cap"
#define RHP_PKT_CAP_FILE_2	"/home/rhpmain/tmp/ike_sa_init_nat_t_i.cap"
#define RHP_PKT_CAP_FILE_3	"/home/rhpmain/tmp/ike_info_i.cap"
#define RHP_PKT_CAP_FILE_4	"/home/rhpmain/tmp/ike_info_nat_t_i.cap"
	if( pkt->type == RHP_PKT_IPV4_IKE ){

		u8* app = pkt->app.raw;
		rhp_proto_ike* ikeh;
		int nat_t = 0;

		if( *((u32*)app) == 0 ){
			ikeh = (rhp_proto_ike*)(app + sizeof(u32));
			nat_t = 1;
		}else{
			ikeh = pkt->app.ikeh;
		}

		if( ikeh->exchange_type == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT &&
				RHP_PROTO_IKE_HDR_INITIATOR(ikeh->flag) &&
				!RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){

			if( !nat_t && rhp_file_exists(RHP_PKT_CAP_FILE_1) ){
				rhp_file_write(RHP_PKT_CAP_FILE_1,tx_buf,tx_len,(S_IRUSR | S_IWUSR | S_IXUSR));
			}else if( nat_t && rhp_file_exists(RHP_PKT_CAP_FILE_2) ){
				rhp_file_write(RHP_PKT_CAP_FILE_2,tx_buf,tx_len,(S_IRUSR | S_IWUSR | S_IXUSR));
			}
		}

		if( ikeh->exchange_type == RHP_PROTO_IKE_EXCHG_INFORMATIONAL &&
				RHP_PROTO_IKE_HDR_INITIATOR(ikeh->flag) &&
				!RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){

			if( !nat_t && rhp_file_exists(RHP_PKT_CAP_FILE_3) ){
				rhp_file_write(RHP_PKT_CAP_FILE_3,tx_buf,tx_len,(S_IRUSR | S_IWUSR | S_IXUSR));
			}else if( nat_t && rhp_file_exists(RHP_PKT_CAP_FILE_4) ){
				rhp_file_write(RHP_PKT_CAP_FILE_4,tx_buf,tx_len,(S_IRUSR | S_IWUSR | S_IXUSR));
			}
		}
	}
}
#endif // RHP_PKT_DBG_PRINT_PKT_DATA


#if defined(RHP_PKT_DBG_IKEV2_RETRANS_TEST) || defined(RHP_PKT_DBG_IKEV2_RETRANS_FRAG_TEST)


struct _rhp_ikev2_retrans_test {
	u32 message_id; // Host byte order
	int drop; // 1: drop
	int drop_num; // 0: Always dropping pkts.
	int drop_num_cur;
	int for_req;
	u16 frag_id; // If any.
};
typedef struct _rhp_ikev2_retrans_test	rhp_ikev2_retrans_test;

#endif // RHP_PKT_DBG_IKEV2_RETRANS_TEST || RHP_PKT_DBG_IKEV2_RETRANS_FRAG_TEST


#ifdef RHP_PKT_DBG_IKEV2_RETRANS_TEST

rhp_ikev2_retrans_test rhp_ikev2_retrans_test_tbls[] =
{
		{
				message_id: 0,
				drop: 			1,
				drop_num: 	2,
				drop_num_cur: 0,
				for_req: 0,
				frag_id: (u16)-1,
		},
		{(u32)-1,-1,-1,-1,-1,(u16)-1},
};

static int _rhp_ikev2_retrans_test(rhp_packet* pkt)
{
	rhp_proto_ike* ikeh = pkt->app.ikeh;
	u32 message_id = ntohl(ikeh->message_id);
	rhp_ikev2_retrans_test* tbl = rhp_ikev2_retrans_test_tbls;
	int i;

	for( i = 0; tbl[i].drop != -1; i++ ){

		if( (!RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) && !tbl[i].for_req) ||
				(RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) && tbl[i].for_req)){
			continue;
		}

		if( tbl[i].message_id == message_id ){
			break;
		}
	}

	if( tbl[i].drop == -1 || tbl[i].drop == 0 ){
		return 0;
	}

	if( tbl[i].drop_num && tbl[i].drop_num_cur > tbl[i].drop_num ){
		return 0;
	}

	tbl[i].drop_num_cur++;

	return -EINVAL;
}

#endif // RHP_PKT_DBG_IKEV2_RETRANS_TEST


#ifdef RHP_PKT_DBG_IKEV2_RETRANS_FRAG_TEST

rhp_ikev2_retrans_test rhp_ikev2_retrans_test_frag_tbls[] =
{
		{
				message_id: 1,
				drop: 			1,
				drop_num: 	2,
				drop_num_cur: 0,
				for_req: 1,
				frag_id: 1,
		},
		{(u32)-1,-1,-1,-1,-1,(u16)-1},
};

static int _rhp_ikev2_retrans_test_frag(rhp_packet* pkt,rhp_packet_frag* pktfrag)
{
	rhp_proto_ike* ikeh = (pktfrag ? pktfrag->app.ikeh : pkt->app.ikeh);
	rhp_proto_ike_skf_payload* skf = (rhp_proto_ike_skf_payload*)(ikeh + 1);
	u32 message_id = ntohl(ikeh->message_id);
	u16 frag_id = ntohs(skf->frag_num);
	rhp_ikev2_retrans_test* tbl = rhp_ikev2_retrans_test_frag_tbls;
	int i;

	if( pkt->frags.frags_num < 1 ){
		return 0;
	}

	for( i = 0; tbl[i].drop != -1; i++ ){

		if( (!RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) && !tbl[i].for_req) ||
				(RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) && tbl[i].for_req)){
			continue;
		}

		if( tbl[i].message_id == message_id && tbl[i].frag_id == frag_id ){
			break;
		}
	}

	if( tbl[i].drop == -1 || tbl[i].drop == 0 ){
		return 0;
	}

	if( tbl[i].drop_num && tbl[i].drop_num_cur > tbl[i].drop_num ){
		return 0;
	}

	tbl[i].drop_num_cur++;

	return -EINVAL;
}

#endif // RHP_PKT_DBG_IKEV2_RETRANS_FRAG_TEST


static int _rhp_netsock_send_ipv4_sk_ike(rhp_ifc_entry* ifc,rhp_ifc_addr* ifc_addr,
		rhp_proto_ip_v4* iph_v4,rhp_proto_udp* udph,rhp_proto_ike* ikeh,
		int* net_sk_r,struct sockaddr_in* dst_in_r,
		struct sockaddr** dst_sa_r,socklen_t* dst_sa_len_r,
		int* tx_len_r,u8** tx_buf_r)
{
  int err = -EINVAL;

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV4_SK_IKE,"xxxxx",ifc,ifc_addr,iph_v4,udph,ikeh);

  if( udph == NULL ){
    err = -EINVAL;
    RHP_BUG("0x%lx,0x%lx,0x%lx",iph_v4,udph,ikeh);
    goto error;
  }

  if( iph_v4->protocol != RHP_PROTO_IP_UDP ||
      udph->dst_port == 0 ||
      udph->src_port == 0 ){
    err = -EINVAL;
    RHP_BUG("%d,%d,%d",iph_v4->protocol,udph->dst_port,udph->src_port);
    goto error;
  }

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV4_SK_IKE_UDPHDR,"xxxWW",ifc,ifc_addr,udph,udph->src_port,udph->dst_port);

  if( udph->src_port == htons(rhp_gcfg_ike_port) ){
    *net_sk_r = ifc_addr->net_sk_ike;
  }else if( udph->src_port == htons(rhp_gcfg_ike_port_nat_t) ){
  	*net_sk_r = ifc_addr->net_sk_nat_t;
  }else{
    err = -EINVAL;
    RHP_BUG("%d",ntohs(udph->src_port));
    goto error;
  }

  dst_in_r->sin_family = AF_INET;
  dst_in_r->sin_port = udph->dst_port;
  dst_in_r->sin_addr.s_addr = iph_v4->dst_addr;
  *dst_sa_r = (struct sockaddr*)dst_in_r;
  *dst_sa_len_r = sizeof(struct sockaddr_in);

  *tx_len_r = (ntohs(udph->len) - sizeof(rhp_proto_udp));
  *tx_buf_r = (u8*)ikeh;

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV4_SK_IKE_RTRN,"xxxxx",ifc,ifc_addr,iph_v4,udph,ikeh);
  return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV4_SK_IKE_ERR,"xxxxxE",ifc,ifc_addr,iph_v4,udph,ikeh,err);
	return err;
}

// Needs ifc->lock acquired.
static int _rhp_netsock_send_ipv4(rhp_ifc_entry* ifc,rhp_ifc_addr* ifc_addr,rhp_packet* pkt)
{
  int err = 0;
  struct sockaddr_in dst_in;
  struct sockaddr* dst_sa;
  socklen_t dst_sa_len = 0;
  int net_sk = -1;
  int tx_len;
  u8* tx_buf;

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV4,"xxsdddxLd",ifc,ifc_addr,ifc->if_name,ifc_addr->net_sk_ike,ifc_addr->net_sk_nat_t,ifc_addr->net_sk_esp,pkt,"PKT",pkt->type);
  rhp_ip_addr_dump("_rhp_netsock_send_ipv4",&(ifc_addr->addr));

  if( pkt->l3.iph_v4 == NULL || pkt->app.raw == NULL ){
    err = -EINVAL;
    RHP_BUG("0x%lx,0x%lx",pkt->l3.iph_v4,pkt->app.raw);
    goto error;
  }

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV4_IPV4HDR,"xxx44Lb",ifc,pkt,pkt->l3.raw,pkt->l3.iph_v4->src_addr,pkt->l3.iph_v4->dst_addr,"PROTO_IP",pkt->l3.iph_v4->protocol);

  if( pkt->l3.iph_v4->dst_addr == 0 ){
    err = -EINVAL;
    RHP_BUG("%d",pkt->l3.iph_v4->dst_addr);
    goto error;
  }

  if( pkt->type == RHP_PKT_IPV4_IKE || pkt->type == RHP_PKT_IPV4_ESP_NAT_T ){

#ifdef RHP_PKT_DBG_IKEV2_RETRANS_TEST
  	if( pkt->type == RHP_PKT_IPV4_IKE && (err = _rhp_ikev2_retrans_test(pkt)) ){
  		goto error;
  	}
#endif // RHP_PKT_DBG_IKEV2_RETRANS_TEST

#ifdef RHP_PKT_DBG_IKEV2_RETRANS_FRAG_TEST
  	if( pkt->type == RHP_PKT_IPV4_IKE && (err = _rhp_ikev2_retrans_test_frag(pkt,NULL)) ){
  		goto error;
  	}
#endif // RHP_PKT_DBG_IKEV2_RETRANS_FRAG_TEST

  	err = _rhp_netsock_send_ipv4_sk_ike(ifc,ifc_addr,
						pkt->l3.iph_v4,pkt->l4.udph,pkt->app.ikeh,
						&net_sk,&dst_in,&dst_sa,&dst_sa_len,
						&tx_len,&tx_buf);

    if( err ){
      goto error;
    }

  }else if( pkt->type == RHP_PKT_IPV4_ESP ){

    dst_in.sin_family = AF_INET;
    dst_in.sin_port = 0;
    dst_in.sin_addr.s_addr = pkt->l3.iph_v4->dst_addr;
    dst_sa = (struct sockaddr*)&dst_in;
    dst_sa_len = sizeof(dst_in);

    tx_len = ntohs(pkt->l3.iph_v4->total_len) - sizeof(rhp_proto_ip_v4);
    tx_buf = (u8*)(pkt->l3.iph_v4 + 1);

    net_sk = ifc_addr->net_sk_esp;

  }else{
    RHP_BUG("%d",pkt->type);
    err = -EINVAL;
    goto error;
  }


  if( !_rhp_netsock_dbg_is_lost_pkt(pkt) ){

#ifndef RHP_PKT_DEBUG
		{
			const char* tag;
			if( net_sk == ifc_addr->net_sk_ike ){
				tag = "[TRF](TX_SK_IKEV2)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV4_SK_IKE,"sxxx44WWpa",tag,ifc,ifc_addr,pkt,ifc_addr->addr.addr.v4,dst_in.sin_addr.s_addr,pkt->l4.udph->src_port,dst_in.sin_port,sizeof(struct sockaddr),&dst_sa,(tx_len > 256 ? 256 : tx_len),RHP_TRC_FMT_A_IKEV2_UDP_SK,0,0,tx_buf);
			}else if( net_sk == ifc_addr->net_sk_nat_t ){
				tag = "[TRF](TX_SK_IKEV2_NAT_T)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV4_SK_IKE_NATT,"sxxx44WWpa",tag,ifc,ifc_addr,pkt,ifc_addr->addr.addr.v4,dst_in.sin_addr.s_addr,pkt->l4.udph->src_port,dst_in.sin_port,sizeof(struct sockaddr),&dst_sa,(tx_len > 256 ? 256 : tx_len),RHP_TRC_FMT_A_IKEV2_NAT_T_UDP_SK,0,0,tx_buf);
			}else if( net_sk == ifc_addr->net_sk_esp ){
				tag = "[TRF](TX_SK_ESP_RAW)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV4_SK_ESP_RAW,"sxxx44pa",tag,ifc,ifc_addr,pkt,ifc_addr->addr.addr.v4,dst_in.sin_addr.s_addr,sizeof(struct sockaddr),&dst_sa,(tx_len > 256 ? 256 : tx_len),RHP_TRC_FMT_A_ESP_RAW_SK,0,0,tx_buf);
			}
		}
#else // RHP_PKT_DEBUG
		{
			const char* tag;
			if( net_sk == ifc_addr->net_sk_ike ){
				tag = "[TRF](TX_SK_IKEV2)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV4_SK_IKE_D,"sxxx44WWpa",tag,ifc,ifc_addr,pkt,ifc_addr->addr.addr.v4,dst_in.sin_addr.s_addr,pkt->l4.udph->src_port,dst_in.sin_port,sizeof(struct sockaddr),&dst_sa,tx_len,RHP_TRC_FMT_A_IKEV2_UDP_SK,0,0,tx_buf);
			}else if( net_sk == ifc_addr->net_sk_nat_t ){
				tag = "[TRF](TX_SK_IKEV2_NAT_T)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV4_SK_IKE_NATT_D,"sxxx44WWpa",tag,ifc,ifc_addr,pkt,ifc_addr->addr.addr.v4,dst_in.sin_addr.s_addr,pkt->l4.udph->src_port,dst_in.sin_port,sizeof(struct sockaddr),&dst_sa,tx_len,RHP_TRC_FMT_A_IKEV2_NAT_T_UDP_SK,0,0,tx_buf);
			}else if( net_sk == ifc_addr->net_sk_esp ){
				tag = "[TRF](TX_SK_ESP_RAW)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV4_SK_ESP_RAW_D,"sxxx44pa",tag,ifc,ifc_addr,pkt,ifc_addr->addr.addr.v4,dst_in.sin_addr.s_addr,sizeof(struct sockaddr),&dst_sa,tx_len,RHP_TRC_FMT_A_ESP_RAW_SK,0,0,tx_buf);
			}
		}
#endif // RHP_PKT_DEBUG


  	err = sendto(net_sk,tx_buf,tx_len,0,dst_sa,dst_sa_len);
    if( err < 0 ){
      err = -errno;
      RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV4_SENDTO_ERR,"xdxE",ifc,net_sk,pkt,err);
      goto error;
    }


		if( RHP_NETSOCK_PCAP_PKT(pkt->type,pkt->ikev2_exchange_type) ){

			_rhp_netsock_pcap_write(pkt);
		}

    _rhp_netsock_send_stat(ifc,ifc_addr,net_sk,err,pkt);

#ifdef RHP_PKT_DBG_PRINT_PKT_DATA
	_rhp_netsock_print_pkt_data(pkt,tx_len,tx_buf);
#endif // RHP_PKT_DBG_PRINT_PKT_DATA

  }else{

    RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV4_SK_SENDTO_DROP,"xx44W4pp",ifc,net_sk,pkt->l3.iph_v4->src_addr,dst_in.sin_addr.s_addr,dst_in.sin_port,pkt->l3.iph_v4->dst_addr,sizeof(struct sockaddr),&dst_in,tx_len,tx_buf);
  }


  if( (pkt->type == RHP_PKT_IPV4_IKE || pkt->type == RHP_PKT_IPV4_ESP_NAT_T) &&
  		pkt->frags.frags_num ){

  	rhp_packet_frag* pktfrag = pkt->frags.head;
  	while( pktfrag ){

#ifdef RHP_PKT_DBG_IKEV2_RETRANS_FRAG_TEST
  		if( pkt->type == RHP_PKT_IPV4_IKE && (err = _rhp_ikev2_retrans_test_frag(pkt,pktfrag)) ){
  			goto frag_retrans_test_next;
  		}
#endif // RHP_PKT_DBG_IKEV2_RETRANS_FRAG_TEST

    	err = _rhp_netsock_send_ipv4_sk_ike(ifc,ifc_addr,
    					pktfrag->l3.iph_v4,pktfrag->l4.udph,pktfrag->app.ikeh,
  						&net_sk,&dst_in,&dst_sa,&dst_sa_len,
  						&tx_len,&tx_buf);

      if( err ){
        goto error;
      }

      if( !_rhp_netsock_dbg_is_lost_pkt(pkt) ){

#ifndef RHP_PKT_DEBUG
      	{
      		const char* tag;
      		if( net_sk == ifc_addr->net_sk_ike ){
      			tag = "[TRF](TX_SK_IKEV2_FRAG)";
      			RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV4_SK_IKE_FRAG,"sxxxx44WWpa",tag,ifc,ifc_addr,pkt,pktfrag,ifc_addr->addr.addr.v4,dst_in.sin_addr.s_addr,pktfrag->l4.udph->src_port,dst_in.sin_port,sizeof(struct sockaddr),&dst_sa,(tx_len > 256 ? 256 : tx_len),RHP_TRC_FMT_A_IKEV2_UDP_SK,0,0,tx_buf);
      		}else if( net_sk == ifc_addr->net_sk_nat_t ){
      			tag = "[TRF](TX_SK_IKEV2_NAT_T_FRAG)";
      			RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV4_SK_IKE_NATT_FRAG,"sxxxx44WWpa",tag,ifc,ifc_addr,pkt,pktfrag,ifc_addr->addr.addr.v4,dst_in.sin_addr.s_addr,pktfrag->l4.udph->src_port,dst_in.sin_port,sizeof(struct sockaddr),&dst_sa,(tx_len > 256 ? 256 : tx_len),RHP_TRC_FMT_A_IKEV2_NAT_T_UDP_SK,0,0,tx_buf);
      		}
      	}
#else // RHP_PKT_DEBUG
      	{
      		const char* tag;
      		if( net_sk == ifc_addr->net_sk_ike ){
      			tag = "[TRF](TX_SK_IKEV2_FRAG)";
      			RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV4_SK_IKE_FRAG_D,"sxxxx44WWpa",tag,ifc,ifc_addr,pkt,pktfrag,ifc_addr->addr.addr.v4,dst_in.sin_addr.s_addr,pkt->l4.udph->src_port,dst_in.sin_port,sizeof(struct sockaddr),&dst_sa,tx_len,RHP_TRC_FMT_A_IKEV2_UDP_SK,0,0,tx_buf);
      		}else if( net_sk == ifc_addr->net_sk_nat_t ){
      			tag = "[TRF](TX_SK_IKEV2_NAT_T_FRAG)";
      			RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV4_SK_IKE_NATT_FRAG_D,"sxxxx44WWpa",tag,ifc,ifc_addr,pkt,pktfrag,ifc_addr->addr.addr.v4,dst_in.sin_addr.s_addr,pktfrag->l4.udph->src_port,dst_in.sin_port,sizeof(struct sockaddr),&dst_sa,tx_len,RHP_TRC_FMT_A_IKEV2_NAT_T_UDP_SK,0,0,tx_buf);
      		}
      	}
#endif // RHP_PKT_DEBUG

				err = sendto(net_sk,tx_buf,tx_len,0,dst_sa,dst_sa_len);
				if( err < 0 ){
					err = -errno;
					RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV4_SENDTO_ERR_2,"xdxxE",ifc,net_sk,pkt,pktfrag,err);
					goto error;
				}

				_rhp_netsock_send_stat(ifc,ifc_addr,net_sk,err,pkt);

      }else{

        RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV4_SK_SENDTO_FRAG_DROP,"xx44W4pp",ifc,net_sk,pktfrag->l3.iph_v4->src_addr,dst_in.sin_addr.s_addr,dst_in.sin_port,pktfrag->l3.iph_v4->dst_addr,sizeof(struct sockaddr),&dst_in,tx_len,tx_buf);
      }

#ifdef RHP_PKT_DBG_IKEV2_RETRANS_FRAG_TEST
frag_retrans_test_next:
#endif // RHP_PKT_DBG_IKEV2_RETRANS_FRAG_TEST
  		pktfrag = pktfrag->next;
  	}
  }

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV4_RTRN,"xdxd",ifc,net_sk,pkt,err);
  return err;

error:

	_rhp_netsock_send_stat_err(ifc,ifc_addr,net_sk,pkt);

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV4_ERR,"xdxE",ifc,net_sk,pkt,err);
  return err;
}

static int _rhp_netsock_send_ipv6_sk_ike(rhp_ifc_entry* ifc,rhp_ifc_addr* ifc_addr,
		rhp_proto_ip_v6* iph_v6,rhp_proto_udp* udph,rhp_proto_ike* ikeh,
		int* net_sk_r,struct sockaddr_in6* dst_in_r,
		struct sockaddr** dst_sa_r,socklen_t* dst_sa_len_r,
		int* tx_len_r,u8** tx_buf_r)
{
  int err = -EINVAL;

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV6_SK_IKE,"xxxxx",ifc,ifc_addr,iph_v6,udph,ikeh);

  if( udph == NULL ){
    err = -EINVAL;
    RHP_BUG("0x%lx,0x%lx,0x%lx",iph_v6,udph,ikeh);
    goto error;
  }

  if( iph_v6->next_header != RHP_PROTO_IP_UDP ||
      udph->dst_port == 0 ||
      udph->src_port == 0 ){
    err = -EINVAL;
    RHP_BUG("%d,%d,%d",iph_v6->next_header,udph->dst_port,udph->src_port);
    goto error;
  }

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV6_SK_IKE_UDPHDR,"xxxWW",ifc,ifc_addr,udph,udph->src_port,udph->dst_port);

  if( udph->src_port == htons(rhp_gcfg_ike_port) ){
    *net_sk_r = ifc_addr->net_sk_ike;
  }else if( udph->src_port == htons(rhp_gcfg_ike_port_nat_t) ){
  	*net_sk_r = ifc_addr->net_sk_nat_t;
  }else{
    err = -EINVAL;
    RHP_BUG("%d",ntohs(udph->src_port));
    goto error;
  }

  dst_in_r->sin6_family = AF_INET6;
	dst_in_r->sin6_port = udph->dst_port;
	dst_in_r->sin6_flowinfo = 0;
	memcpy(dst_in_r->sin6_addr.s6_addr,iph_v6->dst_addr,16);
	dst_in_r->sin6_scope_id = 0;

  *dst_sa_r = (struct sockaddr*)dst_in_r;
  *dst_sa_len_r = sizeof(struct sockaddr_in6);

  *tx_len_r = (ntohs(udph->len) - sizeof(rhp_proto_udp));
  *tx_buf_r = (u8*)ikeh;

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV6_SK_IKE_RTRN,"xxxxx",ifc,ifc_addr,iph_v6,udph,ikeh);
  return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV6_SK_IKE_ERR,"xxxxxE",ifc,ifc_addr,iph_v6,udph,ikeh,err);
	return err;
}

// Needs ifc->lock acquired.
static int _rhp_netsock_send_ipv6(rhp_ifc_entry* ifc,rhp_ifc_addr* ifc_addr,rhp_packet* pkt)
{
  int err = 0;
  struct sockaddr_in6 dst_in;
  struct sockaddr* dst_sa;
  socklen_t dst_sa_len = 0;
  int net_sk = -1;
  int tx_len;
  u8* tx_buf;

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV6,"xxsdddxLd",ifc,ifc_addr,ifc->if_name,ifc_addr->net_sk_ike,ifc_addr->net_sk_nat_t,ifc_addr->net_sk_esp,pkt,"PKT",pkt->type);
  rhp_ip_addr_dump("_rhp_netsock_send_ipv6",&(ifc_addr->addr));

  if( pkt->l3.iph_v6 == NULL || pkt->app.raw == NULL ){
    err = -EINVAL;
    RHP_BUG("0x%lx,0x%lx",pkt->l3.iph_v6,pkt->app.raw);
    goto error;
  }

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV6_IPV6HDR,"xxx66Lb",ifc,pkt,pkt->l3.raw,pkt->l3.iph_v6->src_addr,pkt->l3.iph_v6->dst_addr,"PROTO_IP",pkt->l3.iph_v6->next_header);

  if( rhp_ipv6_addr_null(pkt->l3.iph_v6->dst_addr) ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  if( (pkt->type == RHP_PKT_IPV6_IKE) || (pkt->type == RHP_PKT_IPV6_ESP_NAT_T) ){

#ifdef RHP_PKT_DBG_IKEV2_RETRANS_TEST
  	if( pkt->type == RHP_PKT_IPV6_IKE && (err = _rhp_ikev2_retrans_test(pkt)) ){
  		goto error;
  	}
#endif // RHP_PKT_DBG_IKEV2_RETRANS_TEST

#ifdef RHP_PKT_DBG_IKEV2_RETRANS_FRAG_TEST
  	if( pkt->type == RHP_PKT_IPV6_IKE && (err = _rhp_ikev2_retrans_test_frag(pkt,NULL)) ){
  		goto error;
  	}
#endif // RHP_PKT_DBG_IKEV2_RETRANS_FRAG_TEST

  	err = _rhp_netsock_send_ipv6_sk_ike(ifc,ifc_addr,
						pkt->l3.iph_v6,pkt->l4.udph,pkt->app.ikeh,
						&net_sk,&dst_in,&dst_sa,&dst_sa_len,
						&tx_len,&tx_buf);

    if( err ){
      goto error;
    }

  }else if( pkt->type == RHP_PKT_IPV6_ESP ){

  	dst_in.sin6_family = AF_INET6;
  	dst_in.sin6_port = 0;
  	dst_in.sin6_flowinfo = 0;
  	memcpy(dst_in.sin6_addr.s6_addr,pkt->l3.iph_v6->dst_addr,16);
  	dst_in.sin6_scope_id = 0;

    dst_sa = (struct sockaddr*)&dst_in;
    dst_sa_len = sizeof(dst_in);

    tx_len = ntohs(pkt->l3.iph_v6->payload_len);
    tx_buf = (u8*)(pkt->l3.iph_v6 + 1);

    net_sk = ifc_addr->net_sk_esp;

  }else{
    RHP_BUG("%d",pkt->type);
    err = -EINVAL;
    goto error;
  }


  if( !_rhp_netsock_dbg_is_lost_pkt(pkt) ){

#ifndef RHP_PKT_DEBUG
		{
			const char* tag;
			if( net_sk == ifc_addr->net_sk_ike ){
				tag = "[TRF](TX_SK_IKEV2_V6)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV6_SK_IKE,"sxxx66WWpa",tag,ifc,ifc_addr,pkt,ifc_addr->addr.addr.v6,dst_in.sin6_addr.s6_addr,pkt->l4.udph->src_port,dst_in.sin6_port,sizeof(struct sockaddr),&dst_sa,(tx_len > 256 ? 256 : tx_len),RHP_TRC_FMT_A_IKEV2_UDP_SK,0,0,tx_buf);
			}else if( net_sk == ifc_addr->net_sk_nat_t ){
				tag = "[TRF](TX_SK_IKEV2_NAT_T_V6)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV6_SK_IKE_NATT,"sxxx66WWpa",tag,ifc,ifc_addr,pkt,ifc_addr->addr.addr.v6,dst_in.sin6_addr.s6_addr,pkt->l4.udph->src_port,dst_in.sin6_port,sizeof(struct sockaddr),&dst_sa,(tx_len > 256 ? 256 : tx_len),RHP_TRC_FMT_A_IKEV2_NAT_T_UDP_SK,0,0,tx_buf);
			}else if( net_sk == ifc_addr->net_sk_esp ){
				tag = "[TRF](TX_SK_ESP_RAW_V6)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV6_SK_ESP_RAW,"sxxx66pa",tag,ifc,ifc_addr,pkt,ifc_addr->addr.addr.v6,dst_in.sin6_addr.s6_addr,sizeof(struct sockaddr),&dst_sa,(tx_len > 256 ? 256 : tx_len),RHP_TRC_FMT_A_ESP_RAW_SK,0,0,tx_buf);
			}
		}
#else // RHP_PKT_DEBUG
		{
			const char* tag;
			if( net_sk == ifc_addr->net_sk_ike ){
				tag = "[TRF](TX_SK_IKEV2_V6)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV6_SK_IKE_D,"sxxx66WWpa",tag,ifc,ifc_addr,pkt,ifc_addr->addr.addr.v6,dst_in.sin6_addr.s6_addr,pkt->l4.udph->src_port,dst_in.sin6_port,sizeof(struct sockaddr),&dst_sa,tx_len,RHP_TRC_FMT_A_IKEV2_UDP_SK,0,0,tx_buf);
			}else if( net_sk == ifc_addr->net_sk_nat_t ){
				tag = "[TRF](TX_SK_IKEV2_NAT_T_V6)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV6_SK_IKE_NATT_D,"sxxx66WWpa",tag,ifc,ifc_addr,pkt,ifc_addr->addr.addr.v6,dst_in.sin6_addr.s6_addr,pkt->l4.udph->src_port,dst_in.sin6_port,sizeof(struct sockaddr),&dst_sa,tx_len,RHP_TRC_FMT_A_IKEV2_NAT_T_UDP_SK,0,0,tx_buf);
			}else if( net_sk == ifc_addr->net_sk_esp ){
				tag = "[TRF](TX_SK_ESP_RAW_V6)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV6_SK_ESP_RAW_D,"sxxx66pa",tag,ifc,ifc_addr,pkt,ifc_addr->addr.addr.v6,dst_in.sin6_addr.s6_addr,sizeof(struct sockaddr),&dst_sa,tx_len,RHP_TRC_FMT_A_ESP_RAW_SK,0,0,tx_buf);
			}
		}
#endif // RHP_PKT_DEBUG


  	err = sendto(net_sk,tx_buf,tx_len,0,dst_sa,dst_sa_len);
    if( err < 0 ){
      err = -errno;
      RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV6_SENDTO_ERR,"xdxE",ifc,net_sk,pkt,err);
      goto error;
    }

#ifdef RHP_PKT_DBG_PRINT_PKT_DATA
	_rhp_netsock_print_pkt_data(pkt,tx_len,tx_buf);
#endif // RHP_PKT_DBG_PRINT_PKT_DATA

    _rhp_netsock_send_stat(ifc,ifc_addr,net_sk,err,pkt);

  }else{

    RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV6_SK_SENDTO_DROP,"xx66W6pp",ifc,net_sk,pkt->l3.iph_v6->src_addr,dst_in.sin6_addr.s6_addr,dst_in.sin6_port,pkt->l3.iph_v6->dst_addr,sizeof(struct sockaddr),&dst_in,tx_len,tx_buf);
  	err = tx_len;
  	goto error;
  }


  if( ((pkt->type == RHP_PKT_IPV6_IKE) || (pkt->type == RHP_PKT_IPV6_ESP_NAT_T)) &&
  		pkt->frags.frags_num ){

  	rhp_packet_frag* pktfrag = pkt->frags.head;
  	while( pktfrag ){


#ifdef RHP_PKT_DBG_IKEV2_RETRANS_FRAG_TEST
  		if( pkt->type == RHP_PKT_IPV6_IKE && (err = _rhp_ikev2_retrans_test_frag(pkt,pktfrag)) ){
  			goto frag_retrans_test_next;
  		}
#endif // RHP_PKT_DBG_IKEV2_RETRANS_FRAG_TEST

    	err = _rhp_netsock_send_ipv6_sk_ike(ifc,ifc_addr,
    					pktfrag->l3.iph_v6,pktfrag->l4.udph,pktfrag->app.ikeh,
  						&net_sk,&dst_in,&dst_sa,&dst_sa_len,
  						&tx_len,&tx_buf);

      if( err ){
        goto error;
      }

      if( !_rhp_netsock_dbg_is_lost_pkt(pkt) ){

#ifndef RHP_PKT_DEBUG
		{
			const char* tag;
			if( net_sk == ifc_addr->net_sk_ike ){
				tag = "[TRF](TX_SK_IKEV2_V6_FRAG)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV6_SK_IKE,"sxxx66WWpa",tag,ifc,ifc_addr,pktfrag,ifc_addr->addr.addr.v6,dst_in.sin6_addr.s6_addr,pktfrag->l4.udph->src_port,dst_in.sin6_port,sizeof(struct sockaddr),&dst_sa,(tx_len > 256 ? 256 : tx_len),RHP_TRC_FMT_A_IKEV2_UDP_SK,0,0,tx_buf);
			}else if( net_sk == ifc_addr->net_sk_nat_t ){
				tag = "[TRF](TX_SK_IKEV2_NAT_T_V6_FRAG)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV6_SK_IKE_NATT,"sxxx66WWpa",tag,ifc,ifc_addr,pktfrag,ifc_addr->addr.addr.v6,dst_in.sin6_addr.s6_addr,pktfrag->l4.udph->src_port,dst_in.sin6_port,sizeof(struct sockaddr),&dst_sa,(tx_len > 256 ? 256 : tx_len),RHP_TRC_FMT_A_IKEV2_NAT_T_UDP_SK,0,0,tx_buf);
			}else if( net_sk == ifc_addr->net_sk_esp ){
				tag = "[TRF](TX_SK_ESP_RAW_V6_FRAG)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV6_SK_ESP_RAW,"sxxx66pa",tag,ifc,ifc_addr,pktfrag,ifc_addr->addr.addr.v6,dst_in.sin6_addr.s6_addr,sizeof(struct sockaddr),&dst_sa,(tx_len > 256 ? 256 : tx_len),RHP_TRC_FMT_A_ESP_RAW_SK,0,0,tx_buf);
			}
		}
#else // RHP_PKT_DEBUG
		{
			const char* tag;
			if( net_sk == ifc_addr->net_sk_ike ){
				tag = "[TRF](TX_SK_IKEV2_V6_FRAG)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV6_SK_IKE_D,"sxxx66WWpa",tag,ifc,ifc_addr,pktfrag,ifc_addr->addr.addr.v6,dst_in.sin6_addr.s6_addr,pktfrag->l4.udph->src_port,dst_in.sin6_port,sizeof(struct sockaddr),&dst_sa,tx_len,RHP_TRC_FMT_A_IKEV2_UDP_SK,0,0,tx_buf);
			}else if( net_sk == ifc_addr->net_sk_nat_t ){
				tag = "[TRF](TX_SK_IKEV2_NAT_T_V6_FRAG)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV6_SK_IKE_NATT_D,"sxxx66WWpa",tag,ifc,ifc_addr,pktfrag,ifc_addr->addr.addr.v6,dst_in.sin6_addr.s6_addr,pktfrag->l4.udph->src_port,dst_in.sin6_port,sizeof(struct sockaddr),&dst_sa,tx_len,RHP_TRC_FMT_A_IKEV2_NAT_T_UDP_SK,0,0,tx_buf);
			}else if( net_sk == ifc_addr->net_sk_esp ){
				tag = "[TRF](TX_SK_ESP_RAW_V6_FRAG)";
				RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV6_SK_ESP_RAW_D,"sxxx66pa",tag,ifc,ifc_addr,pktfrag,ifc_addr->addr.addr.v6,dst_in.sin6_addr.s6_addr,sizeof(struct sockaddr),&dst_sa,tx_len,RHP_TRC_FMT_A_ESP_RAW_SK,0,0,tx_buf);
			}
		}
#endif // RHP_PKT_DEBUG

				err = sendto(net_sk,tx_buf,tx_len,0,dst_sa,dst_sa_len);
				if( err < 0 ){
					err = -errno;
					RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV6_SENDTO_ERR_2,"xdxxE",ifc,net_sk,pkt,pktfrag,err);
					goto error;
				}


				if( RHP_NETSOCK_PCAP_PKT(pkt->type,pkt->ikev2_exchange_type) ){

					_rhp_netsock_pcap_write(pkt);
				}


				_rhp_netsock_send_stat(ifc,ifc_addr,net_sk,err,pkt);

      }else{

        RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV6_SK_SENDTO_FRAG_DROP,"xx66W4pp",ifc,net_sk,pktfrag->l3.iph_v6->src_addr,dst_in.sin6_addr.s6_addr,dst_in.sin6_port,pktfrag->l3.iph_v6->dst_addr,sizeof(struct sockaddr),&dst_in,tx_len,tx_buf);
      }

#ifdef RHP_PKT_DBG_IKEV2_RETRANS_FRAG_TEST
frag_retrans_test_next:
#endif // RHP_PKT_DBG_IKEV2_RETRANS_FRAG_TEST
  		pktfrag = pktfrag->next;
  	}
  }


  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV6_RTRN,"xdxd",ifc,net_sk,pkt,err);
  return err;

error:

	_rhp_netsock_send_stat_err(ifc,ifc_addr,net_sk,pkt);

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IPV6_ERR,"xdxE",ifc,net_sk,pkt,err);
  return err;
}


int rhp_netsock_send(rhp_ifc_entry* ifc,rhp_packet* pkt)
{
  int err = -EINVAL;
  rhp_ifc_addr* ifc_addr;

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND,"xx",ifc,pkt);
  rhp_pkt_trace_dump("_rhp_netsock_send",pkt);


  RHP_LOCK(&(ifc->lock));

  if( pkt->l2.raw == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  switch( pkt->l2.eth->protocol ){

  case RHP_PROTO_ETH_IP:

  	ifc_addr = ifc->get_addr(ifc,AF_INET,(u8*)&(pkt->l3.iph_v4->src_addr));
    if( ifc_addr == NULL ){
      RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IFC_NOT_ACTIVE_IFC_ADDR,"x",ifc);
    	err = -ENODEV;
    	goto error;
    }

    if( !rhp_ifc_is_active_ifc_addr(ifc,ifc_addr) ){
      RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IFC_NOT_ACTIVE,"xx",ifc,ifc_addr);
  		ifc->statistics.netif.tx_err_pkts++;
      goto error;
    }

  	err = _rhp_netsock_send_ipv4(ifc,ifc_addr,pkt);
    break;


  case RHP_PROTO_ETH_IPV6:

  	ifc_addr = ifc->get_addr(ifc,AF_INET6,pkt->l3.iph_v6->src_addr);
    if( ifc_addr == NULL ){
      RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IFC_NOT_ACTIVE_IFC_ADDR,"x",ifc);
    	err = -ENODEV;
    	goto error;
    }

    if( !rhp_ifc_is_active_ifc_addr(ifc,ifc_addr) ){
      RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_IFC_NOT_ACTIVE,"xx",ifc,ifc_addr);
  		ifc->statistics.netif.tx_err_pkts++;
      goto error;
    }

  	err = _rhp_netsock_send_ipv6(ifc,ifc_addr,pkt);
    break;


  default:
  	RHP_BUG("%d",pkt->l2.eth->protocol);
		ifc->statistics.netif.tx_err_pkts++;
  	err = -EINVAL;
  	goto error;
  }

  ifc->move_addr_to_top(ifc,ifc_addr);


error:
  RHP_UNLOCK(&(ifc->lock));

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_SEND_RTRN,"xxE",ifc,pkt,err);
  return err;
}


struct _rhp_net_cmsg {
  struct sock_extended_err se_err;
  union {
    struct sockaddr_in v4;
  } router_sin;
};
typedef struct _rhp_net_cmsg  rhp_net_cmsg;


static int _rhp_netsock_handle_error(rhp_ifc_entry *ifc,rhp_ifc_addr* ifc_addr)
{
  int err;
  struct msghdr msg;
  rhp_net_cmsg *cmsg;
  int clen = CMSG_SPACE(sizeof(rhp_net_cmsg));
  char cbuffer[CMSG_SPACE(sizeof(rhp_net_cmsg))];
  struct sockaddr_in peer_sin;
  struct cmsghdr* chdr;

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_HANDLE_ERROR,"xx",ifc,ifc_addr);

  memset(cbuffer,0,clen);

  msg.msg_name = &peer_sin;
  msg.msg_namelen = sizeof(peer_sin);
  msg.msg_iov = NULL;
  msg.msg_iovlen = 0;
  msg.msg_flags = 0;
  msg.msg_control = cbuffer;
  msg.msg_controllen = clen;

  err = recvmsg(ifc_addr->net_sk_ike,&msg,MSG_ERRQUEUE | MSG_DONTWAIT);
  if( err < 0 ){
    RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_HANDLE_ERROR_RECVMSG_ERR,"xxxdd",ifc,ifc_addr,ifc_addr->net_sk_ike,err,errno);
    goto error;
  }

  if( msg.msg_flags & MSG_CTRUNC ){
    err = -EMSGSIZE;
    RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_HANDLE_ERROR_RECVMSG_CTRUNC,"xxxd",ifc,ifc_addr,ifc_addr->net_sk_ike,err);
    goto error;
  }

  for( chdr = CMSG_FIRSTHDR(&msg); chdr != NULL; chdr = CMSG_NXTHDR(&msg,chdr) ){

    if( !RHP_PROCESS_IS_ACTIVE() ){
      err = -EINTR;
      RHP_TRC_FREQ(0,RHPTRCID_NOT_ACTIVE,"s","rhp_main_run():4");
      break;
    }

    RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_HANDLE_ERROR_CHDR,"dd",(int)chdr->cmsg_level,(int)chdr->cmsg_type);

    if( chdr->cmsg_level != SOL_IP || chdr->cmsg_type != IP_RECVERR ){
      continue;
    }

    cmsg = (rhp_net_cmsg*)CMSG_DATA(chdr);

    RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_HANDLE_ERROR_CHDR2,"d",(int)cmsg->se_err.ee_origin);

    if( cmsg->se_err.ee_origin != SO_EE_ORIGIN_ICMP ){
      continue;
    }

    RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_HANDLE_ERROR_CHDR3,"d",(int)cmsg->se_err.ee_type);

    switch( cmsg->se_err.ee_type ){

      case ICMP_DEST_UNREACH:

        if( cmsg->se_err.ee_code == ICMP_FRAG_NEEDED ){

          switch( ifc_addr->addr.addr_family ){

            case AF_INET:
            	// TODO : NOT implemented yet...
              RHP_BUG("NOT IMPLEMENTED");
              break;

            case AF_INET6:
            default:
              RHP_BUG("");
              err = -EAFNOSUPPORT;
              goto error;
          }
        }

        break;

      default:
        break;
    }
  }

error:
  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_HANDLE_ERROR_RETN,"xxxxd",ifc,ifc_addr,ifc_addr->net_sk_ike,ifc_addr->net_sk_esp,err);
  return err;
}

int rhp_netsock_handle_event(struct epoll_event* epoll_evt)
{
  int err = 0;
  rhp_epoll_ctx* epoll_ctx = (rhp_epoll_ctx*)epoll_evt->data.ptr;
  rhp_ifc_entry* ifc = (rhp_ifc_entry*)RHP_NETSOCK_EPOLL_IFC(epoll_ctx);
  rhp_ifc_addr* ifc_addr = NULL;
  int rx_sk;
  int net_sk;

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_HANDLE_EVENT,"xx",epoll_evt,ifc);

  if( ifc == NULL ){
    err = -ENODEV;
    RHP_BUG("");
    goto error;
  }

  RHP_LOCK(&(ifc->lock));


  ifc->statistics.netif.rx_net_events++;

  if( !_rhp_atomic_read(&(ifc->is_active)) ){
    err = -ENODEV;
    RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_HANDLE_EVENT_IFC_NOT_ACTIVE,"xx",epoll_evt,ifc);
    goto error_l;
  }


  ifc_addr = (rhp_ifc_addr*)RHP_NETSOCK_EPOLL_IFC_ADDR(epoll_ctx);
  if( ifc_addr == NULL ){
    err = -ENODEV;
    RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_HANDLE_EVENT_IFC_NO_IF_ADDR_IN_CTX,"xxx",epoll_evt,epoll_ctx,ifc);
    goto error_l;
  }

  {
  	rhp_ifc_addr* ifc_addr_tmp = ifc->ifc_addrs;
  	while( ifc_addr_tmp ){
  		if( ifc_addr == ifc_addr_tmp ){
  			break;
  		}
  		ifc_addr_tmp = ifc_addr_tmp->lst_next;
  	}

  	if( ifc_addr_tmp == NULL ){
      err = -ENODEV;
      RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_HANDLE_EVENT_IFC_NO_IF_ADDR,"xxx",epoll_evt,epoll_ctx,ifc);
      goto error_l;
  	}
  }

  if( epoll_ctx == &(ifc_addr->net_sk_epoll_ctx_ike) ){
    rx_sk = RHP_NETSOCK_RX_SK_IKE;
    net_sk = ifc_addr->net_sk_ike;
  }else if( epoll_ctx == &(ifc_addr->net_sk_epoll_ctx_esp) ){
    rx_sk = RHP_NETSOCK_RX_SK_ESP;
    net_sk = ifc_addr->net_sk_esp;
  }else if( epoll_ctx == &(ifc_addr->net_sk_epoll_ctx_nat_t) ){
    rx_sk = RHP_NETSOCK_RX_SK_NAT_T;
    net_sk = ifc_addr->net_sk_nat_t;
  }else{
    err = -EINVAL;
    RHP_BUG("");
    goto error_l;
  }

  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_HANDLE_EVENT_DISP_PARAMS,"xxxsdLd",epoll_evt,ifc,ifc_addr,ifc->if_name,net_sk,"NETSOCK_RX_SOCK",rx_sk);

  if( net_sk < 0 ){
    err = -ENODEV;
    RHP_BUG("");
    goto error_l;
  }

  if( epoll_evt->events & EPOLLERR ){

  	_rhp_netsock_handle_error(ifc,ifc_addr);
  	ifc->statistics.netif.rx_net_err_events++;

  }else{

  	err = _rhp_netsock_recv(ifc,ifc_addr,rx_sk);
  }

error_l:
  RHP_UNLOCK(&(ifc->lock));

error:
  RHP_TRC_FREQ(0,RHPTRCID_NETSOCK_HANDLE_EVENT_RTRN,"xxE",epoll_evt,ifc,err);
  return err;
}

#define RHP_RXTX_WAIT_TIMES				100
#define RHP_RXTX_WAIT_INTERVAL		500  // (nsec)

static void _rhp_rx_tx_wait()
{
  struct timespec ts = {0,RHP_RXTX_WAIT_INTERVAL};
  nanosleep(&ts,NULL);
}

ssize_t rhp_recvmsg(int sk,struct msghdr *msg,int flags,int wait_flag)
{
  int i;
  ssize_t rs = 0;

  RHP_TRC_FREQ(0,RHPTRCID_RECVMSG,"dxxd",sk,msg,flags,wait_flag);

  for( i = 0; i < RHP_RXTX_WAIT_TIMES; i++ ){

    if( (rs = recvmsg(sk,msg,flags)) >= 0 ){
      break;
    }

    rs = -errno;
    RHP_TRC_FREQ(0,RHPTRCID_RECVMSG_ERR,"xE",sk,rs);

    if( RHP_PROCESS_IS_ACTIVE() ){
      switch( -rs ){
        case EINTR:
          break;
        case EAGAIN:
        {
        	if( wait_flag ){
        		_rhp_rx_tx_wait();
        	}else{
        		return rs;
        	}
        }
          break;
        default:
          return rs;
      }
    }else{
      RHP_TRC_FREQ(0,RHPTRCID_RHP_RECVMSG_NOT_ACTIVE,"");
      return rs;
    }
  }

  RHP_TRC_FREQ(0,RHPTRCID_RECVMSG_RTRN,"ddd",sk,i,rs);
  return rs;
}

ssize_t rhp_send(int sk,const void *buf,size_t len,int flags)
{
  int i;
  ssize_t rs = 0;

  RHP_TRC_FREQ(0,RHPTRCID_SEND,"dpx",sk,len,buf,flags);

  for( i = 0; i < RHP_RXTX_WAIT_TIMES; i++ ){

    if( (rs = send(sk,buf,len,flags)) >= 0 ){
      break;
    }

    rs = -errno;
    RHP_TRC_FREQ(0,RHPTRCID_SEND_ERR,"xd",sk,rs);

    if( RHP_PROCESS_IS_ACTIVE() ){
      switch( -rs ){
        case EINTR:
          break;
        case ENOMEM:
        case ENOBUFS:
        {
        	_rhp_rx_tx_wait();
          break;
        }
        default:
          RHP_TRC_FREQ(0,RHPTRCID_RHP_SEND_ERR,"E",rs);
          return rs;
      }
    }else{
      RHP_TRC_FREQ(0,RHPTRCID_RHP_SEND_NOT_ACTIVE,"E",rs);
      return rs;
    }
  }

  RHP_TRC_FREQ(0,RHPTRCID_SEND_RTRN,"ddd",sk,i,rs);
  return rs;
}


