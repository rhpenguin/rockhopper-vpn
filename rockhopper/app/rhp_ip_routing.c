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
#include "rhp_tuntap.h"
#include "rhp_esp.h"
#include "rhp_ipv6.h"



rhp_mutex_t rhp_ip_routing_lock;
static u32 _rhp_ip_routing_hashtbl_rnd;

static rhp_ip_routing_bkt* _rhp_ip_routing_bkts_v4_head = NULL;
static long _rhp_ip_routing_entries_v4_num = 0;

static rhp_ip_routing_bkt* _rhp_ip_routing_bkts_v6_head = NULL;
static long _rhp_ip_routing_entries_v6_num = 0;

static rhp_ip_route_cache** _rhp_ip_routing_cache_v4_htbl = NULL;
static long _rhp_ip_routing_cache_v4_num = 0;

static rhp_ip_route_cache** _rhp_ip_routing_cache_v6_htbl = NULL;
static long _rhp_ip_routing_cache_v6_num = 0;

static rhp_ip_route_cache _rhp_ip_routing_cache_list_head;


static rhp_timer _rhp_ip_routing_cache_timer;

static u8 _rhp_ip_routing_src_addr_v6_null[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
static u8 _rhp_ip_routing_src_v6_vpn_uid_null[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};


static unsigned long _rhp_ip_routing_coarse_tick_running = 0;
static rhp_mutex_t _rhp_ip_routing_coarse_tick_lock;
static u64 _rhp_ip_routing_coarse_tick = 0;
static rhp_timer _rhp_ip_routing_coarse_tick_timer;
static u64 _rhp_gcfg_nhrp_traffic_indication_rate_limit = 1;

static void _rhp_ip_routing_coarse_tick_handler(void *ctx,rhp_timer *timer)
{

	RHP_LOCK(&_rhp_ip_routing_coarse_tick_lock);
	{
		_rhp_ip_routing_coarse_tick++;

		if( _rhp_ip_routing_coarse_tick_running ){

			rhp_timer_reset(&_rhp_ip_routing_coarse_tick_timer);
			rhp_timer_add(&_rhp_ip_routing_coarse_tick_timer,(time_t)rhp_gcfg_ip_routing_coarse_tick_interval);
		}

//	RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_COARSE_TICK_HANDLER,"qf",_rhp_ip_routing_coarse_tick,_rhp_ip_routing_coarse_tick_running);
	}
	RHP_UNLOCK(&_rhp_ip_routing_coarse_tick_lock);

  return;
}

static void _rhp_ip_routing_start_coarse_tick_timer()
{
	RHP_LOCK(&_rhp_ip_routing_coarse_tick_lock);
	{
		if( !_rhp_ip_routing_coarse_tick_running ){

			rhp_timer_reset(&_rhp_ip_routing_coarse_tick_timer);
			rhp_timer_add(&_rhp_ip_routing_coarse_tick_timer,(time_t)rhp_gcfg_ip_routing_coarse_tick_interval);
		}

		_rhp_ip_routing_coarse_tick_running++;

	  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_START_COARSE_TICK_TIMER,"qf",_rhp_ip_routing_coarse_tick,_rhp_ip_routing_coarse_tick_running);
	}
	RHP_UNLOCK(&_rhp_ip_routing_coarse_tick_lock);

	return;
}

static void _rhp_ip_routing_stop_coarse_tick_timer()
{
	RHP_LOCK(&_rhp_ip_routing_coarse_tick_lock);
	{
		_rhp_ip_routing_coarse_tick_running--;

		if( _rhp_ip_routing_coarse_tick_running == 0 ){

			rhp_timer_delete(&_rhp_ip_routing_coarse_tick_timer);
		}

	  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_STOP_COARSE_TICK_TIMER,"qf",_rhp_ip_routing_coarse_tick,_rhp_ip_routing_coarse_tick_running);
	}
	RHP_UNLOCK(&_rhp_ip_routing_coarse_tick_lock);

	return;
}

static inline u64 _rhp_ip_routing_get_tick()
{
	u64 ret;

	RHP_LOCK(&_rhp_ip_routing_coarse_tick_lock);
	{
		ret = _rhp_ip_routing_coarse_tick;
	}
	RHP_UNLOCK(&_rhp_ip_routing_coarse_tick_lock);

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_GET_TICK,"q",ret);
	return ret;
}

u64 rhp_ip_routing_get_tick(u64* rate_limit_r)
{
	*rate_limit_r = _rhp_gcfg_nhrp_traffic_indication_rate_limit;
	return _rhp_ip_routing_get_tick();
}


//
// [CAUTION] This internally acquires rhp_ip_routing_lock.
//
int rhp_ip_routing_enum(int addr_family,
		int (*callback)(int addr_family,
				rhp_ip_routing_bkt* ip_rt_bkt,rhp_ip_routing_entry* ip_rt_ent,void* ctx),void* ctx)
{
	int err = -EINVAL;
	unsigned int i;
	rhp_ip_routing_bkt* ip_rt_bkt;
	int n = 0;

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_ENUM,"LdYx","AF",addr_family,callback,ctx);

	RHP_LOCK(&rhp_ip_routing_lock);

	if( addr_family == AF_INET ){
		ip_rt_bkt = _rhp_ip_routing_bkts_v4_head;
	}else if( addr_family == AF_INET6 ){
		ip_rt_bkt = _rhp_ip_routing_bkts_v6_head;
	}else{
		RHP_BUG("%d",addr_family);
		err = -EINVAL;
		goto error;
	}

	while( ip_rt_bkt ){

		for(i = 0; i < ip_rt_bkt->bkt_size; i++ ){

			rhp_ip_routing_entry* ip_rt_ent = ip_rt_bkt->entries_hash_tbl[i];
			while( ip_rt_ent ){

				err = callback(addr_family,ip_rt_bkt,ip_rt_ent,ctx);
				if( err ){
					goto error;
				}

				n++;
				ip_rt_ent = ip_rt_ent->next;
			}
		}

		ip_rt_bkt = ip_rt_bkt->next;
	}

	if( n < 1 ){
		err = -ENOENT;
	}else{
		err = 0;
	}

error:
	RHP_UNLOCK(&rhp_ip_routing_lock);

	RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_ENUM_RTRN,"LdYxE","AF",addr_family,callback,ctx,err);
	return err;
}

//
// [CAUTION] This internally acquires rhp_ip_routing_lock.
//
int rhp_ip_routing_cache_enum(int addr_family,
		int (*callback)(int addr_family,rhp_ip_route_cache* ip_rt_c,void* ctx),void* ctx)
{
	int err = -EINVAL;
	int i;
	rhp_ip_route_cache *ip_rt_c,**ip_rt_c_head;
	int n = 0;

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_ENUM,"LdYx","AF",addr_family,callback,ctx);

	RHP_LOCK(&rhp_ip_routing_lock);

	if( addr_family == AF_INET ){
		ip_rt_c_head = _rhp_ip_routing_cache_v4_htbl;
	}else if( addr_family == AF_INET6 ){
		ip_rt_c_head = _rhp_ip_routing_cache_v6_htbl;
	}else{
		RHP_BUG("%d",addr_family);
		err = -EINVAL;
		goto error;
	}

	for( i = 0; i < rhp_gcfg_ip_routing_cache_hash_size; i++ ){

		ip_rt_c = ip_rt_c_head[i];
		while( ip_rt_c ){

			err = callback(addr_family,ip_rt_c,ctx);
			if( err ){
				goto error;
			}

			n++;
			ip_rt_c = ip_rt_c->next_hash;
		}
	}

	if( n < 1 ){
		err = -ENOENT;
	}else{
		err = 0;
	}

error:
	RHP_UNLOCK(&rhp_ip_routing_lock);

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_ENUM_RTRN,"LdYxE","AF",addr_family,callback,ctx,err);
	return err;
}

static int _rhp_ip_routing_slow_v4_no_lock(
		int type,
		u32 src_addr,u32 dst_addr,
		u32* next_hop_addr_r,unsigned long* out_realm_id_r,
		rhp_ip_addr* dst_network_r,
		rhp_vpn_ref** tx_vpn_ref_r,
		rhp_ip_routing_entry** ip_rt_ent_r)
{
	rhp_ip_routing_bkt* ip_rt_bkt = _rhp_ip_routing_bkts_v4_head;

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_SLOW_V4_NO_LOCK,"44dxxxxux",src_addr,dst_addr,type,next_hop_addr_r,out_realm_id_r,dst_network_r,tx_vpn_ref_r,(out_realm_id_r ? *out_realm_id_r : 0),ip_rt_ent_r);

	if( src_addr == dst_addr ){
	  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_SLOW_V4_NO_LOCK_SRC_DST_SAME,"44",src_addr,dst_addr);
		return -EINVAL;
	}

	while( ip_rt_bkt ){

	  u32 hval, src_addr2, dst_addr2;
	  rhp_ip_routing_entry *ip_rt_ent,*ip_rt_ent_tmp;

	  if( ip_rt_bkt->entries_num < 1 ||
	  		ip_rt_bkt->entries_hash_tbl == NULL ){
	  	goto next;
	  }

	  src_addr2 = (src_addr & ip_rt_bkt->netmask.v4);
	  dst_addr2 = (dst_addr & ip_rt_bkt->netmask.v4);

	  hval = _rhp_hash_ipv4_1(dst_addr2,_rhp_ip_routing_hashtbl_rnd);
	  hval %= ip_rt_bkt->bkt_size;

	  ip_rt_ent_tmp = NULL;
	  ip_rt_ent = ip_rt_bkt->entries_hash_tbl[hval];

	  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_SLOW_V4_NO_LOCK_BKT_SRCH,"xxd44444j",ip_rt_bkt,ip_rt_ent,ip_rt_bkt->prefix_len,ip_rt_bkt->netmask.v4,src_addr,dst_addr,src_addr2,dst_addr2,hval);

	  //
  	// [TODO] Default routes should be always included?
	  //

	  while( ip_rt_ent ){

		  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_SLOW_V4_NO_LOCK_ENT_SRCH,"xx4444dduu",ip_rt_bkt,ip_rt_ent,ip_rt_ent->info.dest_network.addr.v4,dst_addr,dst_addr2,ip_rt_ent->info.gateway_addr.addr.v4,ip_rt_ent->info.metric,(ip_rt_ent_tmp ? ip_rt_ent_tmp->info.metric : -1),ip_rt_ent->out_realm_id,(out_realm_id_r ? *out_realm_id_r : 0));

	  	if( ip_rt_ent->type == type &&
	  			ip_rt_ent->info.dest_network.addr.v4 == dst_addr2 &&
	  			(out_realm_id_r && *out_realm_id_r != 0 ? (*out_realm_id_r == ip_rt_ent->out_realm_id) : 1) &&
	  			(ip_rt_ent_tmp == NULL ||
	  			 ip_rt_ent_tmp->info.metric > ip_rt_ent->info.metric) ){

	  		ip_rt_ent_tmp = ip_rt_ent;
	  	}

	  	ip_rt_ent = ip_rt_ent->next;
	  }

	  if( ip_rt_ent_tmp ){

		  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_SLOW_V4_NO_LOCK_ENT_FOUND,"xx4d4u",ip_rt_bkt,ip_rt_ent_tmp,ip_rt_ent_tmp->info.dest_network.addr.v4,ip_rt_ent_tmp->info.dest_network.prefixlen,ip_rt_ent_tmp->info.gateway_addr.addr.v4,ip_rt_ent_tmp->out_realm_id);

	  	if( (ip_rt_bkt->prefix_len > 0 && src_addr2 == dst_addr2) || // On the same subnet.
	  			!ip_rt_ent_tmp->info.gateway_addr.addr.v4 ){ 				 		 // A direct dev route, possibly.

	  		*next_hop_addr_r = dst_addr;

	  	}else{

	  		*next_hop_addr_r = ip_rt_ent_tmp->info.gateway_addr.addr.v4;
	  	}

	  	if( out_realm_id_r ){
	  		*out_realm_id_r = ip_rt_ent_tmp->out_realm_id;
	  	}

	  	if( dst_network_r ){
	  		memcpy(dst_network_r,&(ip_rt_ent_tmp->info.dest_network),sizeof(rhp_ip_addr));
	  	}

	  	if( tx_vpn_ref_r && ip_rt_ent_tmp->tx_vpn_ref ){
	  		*tx_vpn_ref_r = rhp_vpn_hold_ref(RHP_VPN_REF(ip_rt_ent_tmp->tx_vpn_ref));
	  	}

	  	if( ip_rt_ent_r ){
	  		*ip_rt_ent_r = ip_rt_ent_tmp;
	  	}

	  	ip_rt_ent_tmp->used++;

	    RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_SLOW_V4_NO_LOCK_RTRN,"444xux4dxxq",src_addr,dst_addr,*next_hop_addr_r,next_hop_addr_r,(out_realm_id_r ? *out_realm_id_r : 0),out_realm_id_r,(dst_network_r ? dst_network_r->addr.v4 : 0),(dst_network_r ? dst_network_r->prefixlen : 0),(tx_vpn_ref_r ? RHP_VPN_REF(*tx_vpn_ref_r) : NULL),(tx_vpn_ref_r ? *tx_vpn_ref_r : NULL),ip_rt_ent_tmp->used);
	  	return 0;
	  }

next:
		ip_rt_bkt = ip_rt_bkt->next;
	}

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_SLOW_V4_NO_LOCK_NO_ENT,"44",src_addr,dst_addr);
	return -ENOENT;
}

int rhp_ip_routing_slow_v4(u32 src_addr,u32 dst_addr,
		u32* next_hop_addr_r,unsigned long* out_realm_id_r,
		rhp_ip_addr* dst_network_r)
{
	int err;

	if( rhp_gcfg_ip_routing_disabled ){
	  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_V4_DISABLED,"44",src_addr,dst_addr);
		return RHP_STATUS_IP_ROUTING_DISABLED;
	}

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_SLOW_V4,"44xxx",src_addr,dst_addr,next_hop_addr_r,out_realm_id_r,dst_network_r);

	RHP_LOCK(&rhp_ip_routing_lock);

	err = _rhp_ip_routing_slow_v4_no_lock(
					RHP_IP_RT_ENT_TYPE_SYSTEM,
					src_addr,dst_addr,
					next_hop_addr_r,out_realm_id_r,dst_network_r,NULL,NULL);

	RHP_UNLOCK(&rhp_ip_routing_lock);

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_SLOW_V4_RTRN,"44E",src_addr,dst_addr,err);
	return err;
}

static int _rhp_ip_routing_slow_v6_no_lock(int type,u8* src_addr,u8* dst_addr,
		u8* next_hop_addr_r,unsigned long* out_realm_id_r,rhp_ip_addr* dst_network_r,
		rhp_vpn_ref** tx_vpn_ref_r,
		rhp_ip_routing_entry** ip_rt_ent_r)
{
	rhp_ip_routing_bkt* ip_rt_bkt = _rhp_ip_routing_bkts_v6_head;

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_SLOW_V6_NO_LOCK,"66dxxxxux",src_addr,dst_addr,type,next_hop_addr_r,out_realm_id_r,dst_network_r,tx_vpn_ref_r,(out_realm_id_r ? *out_realm_id_r : 0),ip_rt_ent_r);

	if( !memcmp(src_addr,dst_addr,16) ){
	  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_SLOW_V6_NO_LOCK_SRC_DST_SAME,"66",src_addr,dst_addr);
		return -EINVAL;
	}

	while( ip_rt_bkt ){

	  u32 hval;
	  u8 src_addr2[16], dst_addr2[16];
	  int i;
	  rhp_ip_routing_entry *ip_rt_ent,*ip_rt_ent_tmp;

	  if( ip_rt_bkt->entries_num < 1 ||
	  		ip_rt_bkt->entries_hash_tbl == NULL ){
	  	goto next;
	  }

	  for( i = 0; i < 16; i++ ){
	  	src_addr2[i] = (src_addr[i] & ip_rt_bkt->netmask.v6[i]);
	  	dst_addr2[i] = (dst_addr[i] & ip_rt_bkt->netmask.v6[i]);
	  }

	  hval = _rhp_hash_ipv6_1(dst_addr2,_rhp_ip_routing_hashtbl_rnd);
	  hval %= ip_rt_bkt->bkt_size;

	  ip_rt_ent_tmp = NULL;
	  ip_rt_ent = ip_rt_bkt->entries_hash_tbl[hval];

	  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_SLOW_V6_NO_LOCK_BKT_SRCH,"xxd66666j",ip_rt_bkt,ip_rt_ent,ip_rt_bkt->prefix_len,ip_rt_bkt->netmask.v6,src_addr,dst_addr,src_addr2,dst_addr2,hval);

	  //
  	// [TODO] Default routes should be always included?
	  //

	  while( ip_rt_ent ){

		  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_SLOW_V6_NO_LOCK_ENT_SRCH,"xx6666dduu",ip_rt_bkt,ip_rt_ent,ip_rt_ent->info.dest_network.addr.v6,dst_addr,dst_addr2,ip_rt_ent->info.gateway_addr.addr.v6,ip_rt_ent->info.metric,(ip_rt_ent_tmp ? ip_rt_ent_tmp->info.metric : -1),ip_rt_ent->out_realm_id,(out_realm_id_r ? *out_realm_id_r : 0));

	  	if( ip_rt_ent->type == type &&
	  			rhp_ipv6_is_same_addr(ip_rt_ent->info.dest_network.addr.v6,dst_addr2) &&
	  			(out_realm_id_r && *out_realm_id_r != 0 ? (*out_realm_id_r == ip_rt_ent->out_realm_id) : 1) &&
	  			(ip_rt_ent_tmp == NULL ||
	  			 ip_rt_ent_tmp->info.metric > ip_rt_ent->info.metric) ){

	  		ip_rt_ent_tmp = ip_rt_ent;
	  	}

	  	ip_rt_ent = ip_rt_ent->next;
	  }

	  if( ip_rt_ent_tmp ){

		  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_SLOW_V6_NO_LOCK_ENT_FOUND,"xx66u6u",ip_rt_bkt,ip_rt_ent_tmp,ip_rt_ent_tmp->info.dest_network.addr.v6,ip_rt_ent_tmp->info.gateway_addr.addr.v6,ip_rt_ent_tmp->out_realm_id,ip_rt_ent_tmp->info.dest_network.addr.v6,ip_rt_ent_tmp->info.dest_network.prefixlen);

	  	if( (ip_rt_bkt->prefix_len > 0 &&
	  			 rhp_ipv6_is_same_addr(src_addr2,dst_addr2)) || 								// On the same subnet.
	  			rhp_ipv6_addr_null(ip_rt_ent_tmp->info.gateway_addr.addr.v6) ){ // A direct dev route, possibly.

	  		memcpy(next_hop_addr_r,dst_addr,16);

	  	}else{

	  		memcpy(next_hop_addr_r,ip_rt_ent_tmp->info.gateway_addr.addr.v6,16);
	  	}

	  	if( out_realm_id_r ){
	  		*out_realm_id_r = ip_rt_ent_tmp->out_realm_id;
	  	}

	  	if( dst_network_r ){
	  		memcpy(dst_network_r,&(ip_rt_ent_tmp->info.dest_network),sizeof(rhp_ip_addr));
	  	}

	  	if( tx_vpn_ref_r && ip_rt_ent_tmp->tx_vpn_ref ){
	  		*tx_vpn_ref_r = rhp_vpn_hold_ref(RHP_VPN_REF(ip_rt_ent_tmp->tx_vpn_ref));
	  	}

	  	if( ip_rt_ent_r ){
	  		*ip_rt_ent_r = ip_rt_ent_tmp;
	  	}

	  	ip_rt_ent_tmp->used++;

	    RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_SLOW_V6_NO_LOCK_RTRN,"666ux6dxxq",src_addr,dst_addr,next_hop_addr_r,(out_realm_id_r ? *out_realm_id_r : 0),out_realm_id_r,(dst_network_r ? dst_network_r->addr.v6 : NULL),(dst_network_r ? dst_network_r->prefixlen : 0),(tx_vpn_ref_r ? RHP_VPN_REF(*tx_vpn_ref_r) : NULL),(tx_vpn_ref_r ? *tx_vpn_ref_r : NULL),ip_rt_ent_tmp->used);
	  	return 0;
	  }

next:
		ip_rt_bkt = ip_rt_bkt->next;
	}

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_SLOW_V6_NO_LOCK_NO_ENT,"66",src_addr,dst_addr);
	return -ENOENT;
}

int rhp_ip_routing_slow_v6(u8* src_addr,u8* dst_addr,
		u8* next_hop_addr_r,unsigned long* out_realm_id_r,
		rhp_ip_addr* dst_network_r)
{
	int err;

	if( rhp_gcfg_ip_routing_disabled ){
	  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_V6_DISABLED,"66",src_addr,dst_addr);
		return RHP_STATUS_IP_ROUTING_DISABLED;
	}

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_SLOW_V6,"66xx",src_addr,dst_addr,next_hop_addr_r,out_realm_id_r);

	RHP_LOCK(&rhp_ip_routing_lock);

	err = _rhp_ip_routing_slow_v6_no_lock(
					RHP_IP_RT_ENT_TYPE_SYSTEM,
					src_addr,dst_addr,
					next_hop_addr_r,out_realm_id_r,dst_network_r,NULL,NULL);

	RHP_UNLOCK(&rhp_ip_routing_lock);

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_SLOW_V6_RTRN,"66E",src_addr,dst_addr,err);
	return err;
}


static void _rhp_ip_routing_cache_free(rhp_ip_route_cache* ip_rt_c)
{
  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_FREE,"xxx",ip_rt_c,ip_rt_c->src_vpn_ref,RHP_VPN_REF(ip_rt_c->src_vpn_ref));

  if( ip_rt_c->src_vpn_ref ){
  	rhp_vpn_unhold(ip_rt_c->src_vpn_ref);
  }

  if( ip_rt_c->tx_vpn_ref ){
  	rhp_vpn_unhold(ip_rt_c->tx_vpn_ref);
  }

  _rhp_free(ip_rt_c);

	return;
}

static rhp_ip_route_cache* _rhp_ip_routing_cache_alloc_v4(
		int type,
		u32 src_addr,u32 dst_addr,
		u32 next_hop_addr,unsigned long out_realm_id,rhp_vpn* src_vpn,
		rhp_vpn* tx_vpn,unsigned long gen_marker)
{
	rhp_ip_route_cache* ip_rt_c = (rhp_ip_route_cache*)_rhp_malloc(sizeof(rhp_ip_route_cache));

	if( ip_rt_c == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(ip_rt_c,0,sizeof(rhp_ip_route_cache));

	ip_rt_c->tag[0] = '#';
	ip_rt_c->tag[1] = 'I';
	ip_rt_c->tag[2] = 'C';
	ip_rt_c->tag[3] = 'R';

	ip_rt_c->type = type;
	ip_rt_c->addr_family = AF_INET;
	ip_rt_c->src_addr.v4 = src_addr;
	ip_rt_c->dst_addr.v4 = dst_addr;
	ip_rt_c->nexthop_addr.v4 = next_hop_addr;
	ip_rt_c->out_realm_id = out_realm_id;
	ip_rt_c->gen_marker = gen_marker;

	if( src_vpn ){
		ip_rt_c->src_vpn_ref = rhp_vpn_hold_ref(src_vpn);
	}

	if( tx_vpn ){
		ip_rt_c->tx_vpn_ref = rhp_vpn_hold_ref(tx_vpn);
	}

	ip_rt_c->created = ip_rt_c->last_checked_time = _rhp_get_time();

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_ALLOC_V4,"d444uxxxx",type,src_addr,dst_addr,next_hop_addr,out_realm_id,src_vpn,tx_vpn,ip_rt_c,gen_marker);
	return ip_rt_c;
}

static rhp_ip_route_cache* _rhp_ip_routing_cache_alloc_v6(
		int type,
		u8* src_addr,u8* dst_addr,
		u8* next_hop_addr,unsigned long out_realm_id,rhp_vpn* src_vpn,
		rhp_vpn* tx_vpn,unsigned long gen_marker)
{
	rhp_ip_route_cache* ip_rt_c = (rhp_ip_route_cache*)_rhp_malloc(sizeof(rhp_ip_route_cache));

	if( ip_rt_c == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(ip_rt_c,0,sizeof(rhp_ip_route_cache));

	ip_rt_c->tag[0] = '#';
	ip_rt_c->tag[1] = 'I';
	ip_rt_c->tag[2] = 'C';
	ip_rt_c->tag[3] = 'R';

	ip_rt_c->type = type;
	ip_rt_c->addr_family = AF_INET6;
	memcpy(ip_rt_c->src_addr.v6,src_addr,16);
	memcpy(ip_rt_c->dst_addr.v6,dst_addr,16);
	memcpy(ip_rt_c->nexthop_addr.v6,next_hop_addr,16);
	ip_rt_c->out_realm_id = out_realm_id;
	ip_rt_c->gen_marker = gen_marker;

	if( src_vpn ){
		ip_rt_c->src_vpn_ref = rhp_vpn_hold_ref(src_vpn);
	}

	if( tx_vpn ){
		ip_rt_c->tx_vpn_ref = rhp_vpn_hold_ref(tx_vpn);
	}

	ip_rt_c->created = ip_rt_c->last_checked_time = _rhp_get_time();

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_ALLOC_V6,"666uxxx",src_addr,dst_addr,next_hop_addr,out_realm_id,src_vpn,ip_rt_c,gen_marker);
	return ip_rt_c;
}

static u32 _rhp_ip_routing_cache_hash_v4(u32 src_addr,u32 dst_addr,rhp_vpn* src_vpn)
{
	u32 hval;
	u32 src_vpn_uid;

	if( src_vpn ){
		src_vpn_uid = ((u32*)src_vpn->unique_id)[3];
	}else{
		src_vpn_uid = 0;
	}

	hval = _rhp_hash_ipv4_2_ext(src_addr,dst_addr,src_vpn_uid,_rhp_ip_routing_hashtbl_rnd);
	hval %= rhp_gcfg_ip_routing_cache_hash_size;

	return hval;
}

static u32 _rhp_ip_routing_cache_hash_v6(u8* src_addr,u8* dst_addr,rhp_vpn* src_vpn)
{
	u32 hval;
	u8* src_vpn_uid;

	if( src_vpn ){
		src_vpn_uid = src_vpn->unique_id;
	}else{
		src_vpn_uid = _rhp_ip_routing_src_v6_vpn_uid_null;
	}

	hval = _rhp_hash_ipv6_2_ext(src_addr,dst_addr,src_vpn_uid,_rhp_ip_routing_hashtbl_rnd);
	hval %= rhp_gcfg_ip_routing_cache_hash_size;

	return hval;
}


static int _rhp_ip_routing_cache_delete_v4(rhp_ip_route_cache *ip_rt_c_d)
{
	u32 hval;
	rhp_ip_route_cache *ip_rt_c, *ip_rt_c_p = NULL;
	rhp_vpn* src_vpn = RHP_VPN_REF(ip_rt_c_d->src_vpn_ref);

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_DELETE,"x44x",ip_rt_c_d,ip_rt_c_d->src_addr.v4,ip_rt_c_d->dst_addr.v4,src_vpn);

	hval = _rhp_ip_routing_cache_hash_v4(ip_rt_c_d->src_addr.v4,ip_rt_c_d->dst_addr.v4,src_vpn);

	ip_rt_c = _rhp_ip_routing_cache_v4_htbl[hval];
	while( ip_rt_c ){

		if( ip_rt_c_d == ip_rt_c ){
			break;
		}

		ip_rt_c_p = ip_rt_c;
		ip_rt_c = ip_rt_c->next_hash;
	}

	if( ip_rt_c == NULL ){
	  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_DELETE_NO_ENT,"x",ip_rt_c_d);
		return -ENOENT;
	}

	if( ip_rt_c_p ){
		ip_rt_c_p->next_hash = ip_rt_c->next_hash;
	}else{
		_rhp_ip_routing_cache_v4_htbl[hval] = ip_rt_c->next_hash;
	}


	ip_rt_c->pre_list->next_list = ip_rt_c->next_list;
  if( ip_rt_c->next_list ){
  	ip_rt_c->next_list->pre_list = ip_rt_c->pre_list;
  }
  ip_rt_c->pre_list = NULL;
  ip_rt_c->next_list = NULL;


	_rhp_ip_routing_cache_v4_num--;
	_rhp_ip_routing_stop_coarse_tick_timer();

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_DELETE_RTRN,"xf",ip_rt_c_d,_rhp_ip_routing_cache_v4_num);
	return 0;
}

static int _rhp_ip_routing_cache_delete_v6(rhp_ip_route_cache *ip_rt_c_d)
{
	u32 hval;
	rhp_ip_route_cache *ip_rt_c, *ip_rt_c_p = NULL;
	rhp_vpn* src_vpn = RHP_VPN_REF(ip_rt_c_d->src_vpn_ref);

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_DELETE_V6,"x66x",ip_rt_c_d,ip_rt_c_d->src_addr.v6,ip_rt_c_d->dst_addr.v6,src_vpn);


	hval = _rhp_ip_routing_cache_hash_v6(ip_rt_c_d->src_addr.v6,ip_rt_c_d->dst_addr.v6,src_vpn);

	ip_rt_c = _rhp_ip_routing_cache_v6_htbl[hval];
	while( ip_rt_c ){

		if( ip_rt_c_d == ip_rt_c ){
			break;
		}

		ip_rt_c_p = ip_rt_c;
		ip_rt_c = ip_rt_c->next_hash;
	}

	if( ip_rt_c == NULL ){
	  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_DELETE_V6_NO_ENT,"x",ip_rt_c_d);
		return -ENOENT;
	}

	if( ip_rt_c_p ){
		ip_rt_c_p->next_hash = ip_rt_c->next_hash;
	}else{
		_rhp_ip_routing_cache_v6_htbl[hval] = ip_rt_c->next_hash;
	}


	ip_rt_c->pre_list->next_list = ip_rt_c->next_list;
  if( ip_rt_c->next_list ){
  	ip_rt_c->next_list->pre_list = ip_rt_c->pre_list;
  }
  ip_rt_c->pre_list = NULL;
  ip_rt_c->next_list = NULL;


	_rhp_ip_routing_cache_v6_num--;
	_rhp_ip_routing_stop_coarse_tick_timer();

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_DELETE_V6_RTRN,"xf",ip_rt_c_d,_rhp_ip_routing_cache_v6_num);
	return 0;
}

static void _rhp_ip_routing_cache_flush(int addr_family)
{
	rhp_ip_route_cache** htbl
		= (addr_family == AF_INET ? _rhp_ip_routing_cache_v4_htbl : _rhp_ip_routing_cache_v6_htbl);
	rhp_ip_route_cache *ip_rt_c;
	int i;

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_FLUSH,"Ld","AF",addr_family);

	for( i = 0; i < rhp_gcfg_ip_routing_cache_hash_size; i++ ){

		ip_rt_c = htbl[i];
		while( ip_rt_c ){

			rhp_ip_route_cache* ip_rt_c_n = ip_rt_c->next_hash;

			if( addr_family == AF_INET ){

				if( !_rhp_ip_routing_cache_delete_v4(ip_rt_c) ){
					_rhp_ip_routing_cache_free(ip_rt_c);
				}

			}else if( addr_family == AF_INET6 ){

				if( !_rhp_ip_routing_cache_delete_v6(ip_rt_c) ){
					_rhp_ip_routing_cache_free(ip_rt_c);
				}
			}

			ip_rt_c = ip_rt_c_n;
		}
		htbl[i] = NULL;
	}

	RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_FLUSH_RTRN,"Ld","AF",addr_family);
	return;
}

void rhp_ip_routing_cache_flush(int addr_family)
{
	if( rhp_gcfg_ip_routing_disabled ){
	  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_FLUSH_DISABLED,"Ld","AF",addr_family);
		return;
	}

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_FLUSH,"Ld","AF",addr_family);

	RHP_LOCK(&rhp_ip_routing_lock);

	_rhp_ip_routing_cache_flush(addr_family);

	RHP_UNLOCK(&rhp_ip_routing_lock);

	return;
}

int rhp_ip_routing_cache_flush_by_vpn(rhp_vpn* vpn)
{
	int err = 0;
	rhp_ip_route_cache *ip_rt_c;
	int n = 0;

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_FLUSH_BY_VPN,"x",vpn);

  RHP_LOCK(&rhp_ip_routing_lock);

  ip_rt_c = _rhp_ip_routing_cache_list_head.next_list;
  while( ip_rt_c ){

  	rhp_ip_route_cache* ip_rt_c_n = ip_rt_c->next_list;

  	if( RHP_VPN_REF(ip_rt_c->src_vpn_ref) == vpn ||
  			RHP_VPN_REF(ip_rt_c->tx_vpn_ref) == vpn ){

			if( ip_rt_c->addr_family == AF_INET ){

				if( !_rhp_ip_routing_cache_delete_v4(ip_rt_c) ){
					_rhp_ip_routing_cache_free(ip_rt_c);
				}

			}else if( ip_rt_c->addr_family == AF_INET6 ){

				if( !_rhp_ip_routing_cache_delete_v6(ip_rt_c) ){
					_rhp_ip_routing_cache_free(ip_rt_c);
				}

			}else{
				RHP_BUG("%d",ip_rt_c->addr_family);
			}

  		n++;
  	}

  	ip_rt_c = ip_rt_c_n;
  }

  RHP_UNLOCK(&rhp_ip_routing_lock);

  if( !err && n < 1 ){
  	err = -ENOENT;
  }

	RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_FLUSH_BY_VPN_RTRN,"xE",vpn,err);

	return err;
}

// Caller must acquire rhp_ip_routing_lock.
static int _rhp_ip_routing_cache_flush_by_gen_marker(unsigned long gen_marker)
{
	int err = 0;
	rhp_ip_route_cache *ip_rt_c;
	int n = 0;

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_FLUSH_BY_GEN_MARKER,"x",gen_marker);

  ip_rt_c = _rhp_ip_routing_cache_list_head.next_list;
  while( ip_rt_c ){

  	rhp_ip_route_cache* ip_rt_c_n = ip_rt_c->next_list;

  	if( ip_rt_c->addr_family == AF_INET ){
  		RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_FLUSH_BY_GEN_MARKER_IP_RT_C_V4,"xxx444",gen_marker,ip_rt_c,ip_rt_c->gen_marker,ip_rt_c->src_addr.v4,ip_rt_c->dst_addr.v4,ip_rt_c->nexthop_addr.v4);
  	}else if( ip_rt_c->addr_family == AF_INET6 ){
  		RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_FLUSH_BY_GEN_MARKER_IP_RT_C_V6,"xxx666",gen_marker,ip_rt_c,ip_rt_c->gen_marker,ip_rt_c->src_addr.v6,ip_rt_c->dst_addr.v6,ip_rt_c->nexthop_addr.v6);
  	}else{
  		RHP_BUG("%d",ip_rt_c->addr_family);
  	}

  	if( ip_rt_c->gen_marker &&
  			ip_rt_c->gen_marker == gen_marker ){

			if( ip_rt_c->addr_family == AF_INET ){

				if( !_rhp_ip_routing_cache_delete_v4(ip_rt_c) ){
					_rhp_ip_routing_cache_free(ip_rt_c);
				}

			}else if( ip_rt_c->addr_family == AF_INET6 ){

				if( !_rhp_ip_routing_cache_delete_v6(ip_rt_c) ){
					_rhp_ip_routing_cache_free(ip_rt_c);
				}

			}else{
				RHP_BUG("%d",ip_rt_c->addr_family);
			}

  		n++;
  	}

  	ip_rt_c = ip_rt_c_n;
  }

  if( !err && n < 1 ){
  	err = -ENOENT;
  }

	RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_FLUSH_BY_GEN_MARKER_RTRN,"xE",gen_marker,err);

	return err;
}

static void _rhp_ip_routing_cache_flush_task(int worker_index,void *ctx)
{
	rhp_vpn* vpn_ref = (rhp_vpn_ref*)ctx;
	rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);

  RHP_TRC(0,RHPTRCID_IP_ROUTING_CACHE_FLUSH_TASK,"dxx",worker_index,vpn,vpn_ref);

  //
  // vpn may be already destroyed. Don't touch the object itself.
  //

  rhp_ip_routing_cache_flush_by_vpn(vpn);
	rhp_vpn_unhold(vpn_ref);

  RHP_TRC(0,RHPTRCID_IP_ROUTING_CACHE_FLUSH_TASK_RTRN,"xx",vpn,vpn_ref);
	return;
}

int rhp_ip_routing_invoke_flush_task(rhp_vpn* vpn)
{
	int err;
	rhp_vpn_ref* vpn_ref;

  RHP_TRC(0,RHPTRCID_IP_ROUTING_CACHE_INVOKE_FLUSH_TASK,"x",vpn);

  vpn_ref = rhp_vpn_hold_ref(vpn);

  err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_1,
  				_rhp_ip_routing_cache_flush_task,(void*)vpn_ref);
	if( err ){
		RHP_BUG("%d",err);
		rhp_vpn_unhold(vpn_ref);
	}

  RHP_TRC(0,RHPTRCID_IP_ROUTING_CACHE_INVOKE_FLUSH_TASK_RTRN,"xxE",vpn,vpn_ref,err);
	return err;
}

static int _rhp_ip_routing_cache_update_v4(
		int type,
		u32 src_addr,u32 dst_addr,rhp_vpn* src_vpn,
		u32 next_hop_addr,unsigned long out_realm_id,
		rhp_vpn* tx_vpn,
		u32 hval,
		unsigned long gen_marker,
		rhp_ip_route_cache** ip_rt_c_r)
{
	int err = -EINVAL;
	rhp_ip_route_cache* ip_rt_c;

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_UPDATE_V4,"d44x4ujxxx",type,src_addr,dst_addr,src_vpn,next_hop_addr,out_realm_id,hval,tx_vpn,ip_rt_c_r,gen_marker);

	if( !hval ){
		hval = _rhp_ip_routing_cache_hash_v4(src_addr,dst_addr,src_vpn);
	}

	ip_rt_c = _rhp_ip_routing_cache_v4_htbl[hval];
	while( ip_rt_c ){

		// src_vpn, ip_rt_c->src_vpn, tx_vpn and ip_rt_c->tx_vpn may be NULL.
		if( type == ip_rt_c->type &&
				src_addr == ip_rt_c->src_addr.v4 && dst_addr == ip_rt_c->dst_addr.v4 &&
				src_vpn == RHP_VPN_REF(ip_rt_c->src_vpn_ref) &&
				tx_vpn == RHP_VPN_REF(ip_rt_c->tx_vpn_ref) ){

			ip_rt_c->nexthop_addr.v4 = next_hop_addr;
			ip_rt_c->out_realm_id = out_realm_id;

			break;
		}

		ip_rt_c = ip_rt_c->next_hash;
	}

	if( ip_rt_c == NULL ){

		if( _rhp_ip_routing_cache_v4_num >= rhp_gcfg_ip_routing_cache_max_entries_v4 ){
			err = RHP_STATUS_IP_ROUTING_MAX_ENTRIES_REACHED;
			goto error;
		}

		ip_rt_c = _rhp_ip_routing_cache_alloc_v4(type,src_addr,dst_addr,
								next_hop_addr,out_realm_id,src_vpn,tx_vpn,gen_marker);
		if( ip_rt_c == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		ip_rt_c->next_hash = _rhp_ip_routing_cache_v4_htbl[hval];
		_rhp_ip_routing_cache_v4_htbl[hval] = ip_rt_c;


		ip_rt_c->next_list = _rhp_ip_routing_cache_list_head.next_list;
	  if( _rhp_ip_routing_cache_list_head.next_list ){
	  	_rhp_ip_routing_cache_list_head.next_list->pre_list = ip_rt_c;
	  }
	  ip_rt_c->pre_list = &_rhp_ip_routing_cache_list_head;
	  _rhp_ip_routing_cache_list_head.next_list = ip_rt_c;


		_rhp_ip_routing_cache_v4_num++;
		_rhp_ip_routing_start_coarse_tick_timer();
	}

	if( ip_rt_c_r ){
		*ip_rt_c_r = ip_rt_c;
	}

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_UPDATE_V4_RTRN,"444ufx",src_addr,dst_addr,next_hop_addr,out_realm_id,_rhp_ip_routing_cache_v4_num,ip_rt_c);
	return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_UPDATE_V4_ERR,"444uE",src_addr,dst_addr,next_hop_addr,out_realm_id,err);
	return err;
}

static int _rhp_ip_routing_cache_update_v6(
		int type,
		u8* src_addr,u8* dst_addr,rhp_vpn* src_vpn,
		u8* next_hop_addr,unsigned long out_realm_id,
		rhp_vpn* tx_vpn,
		u32 hval,unsigned long gen_marker,
		rhp_ip_route_cache** ip_rt_c_r)
{
	int err = -EINVAL;
	rhp_ip_route_cache* ip_rt_c;

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_UPDATE_V6,"d66x6ujxxx",type,src_addr,dst_addr,src_vpn,next_hop_addr,out_realm_id,hval,tx_vpn,gen_marker,ip_rt_c_r);

	if( !hval ){
		hval = _rhp_ip_routing_cache_hash_v6(src_addr,dst_addr,src_vpn);
	}

	ip_rt_c = _rhp_ip_routing_cache_v6_htbl[hval];
	while( ip_rt_c ){

		// src_vpn, ip_rt_c->src_vpn, tx_vpn and ip_rt_c->tx_vpn may be NULL.
		if( type == ip_rt_c->type &&
				rhp_ipv6_is_same_addr(src_addr,ip_rt_c->src_addr.v6) &&
				rhp_ipv6_is_same_addr(dst_addr,ip_rt_c->dst_addr.v6) &&
				src_vpn == RHP_VPN_REF(ip_rt_c->src_vpn_ref) &&
				tx_vpn == RHP_VPN_REF(ip_rt_c->tx_vpn_ref) ){

			memcpy(ip_rt_c->nexthop_addr.v6,next_hop_addr,16);
			ip_rt_c->out_realm_id = out_realm_id;

			break;
		}

		ip_rt_c = ip_rt_c->next_hash;
	}

	if( ip_rt_c == NULL ){

		if( _rhp_ip_routing_cache_v6_num >= rhp_gcfg_ip_routing_cache_max_entries_v6 ){
			err = RHP_STATUS_IP_ROUTING_MAX_ENTRIES_REACHED;
			goto error;
		}

		ip_rt_c = _rhp_ip_routing_cache_alloc_v6(type,src_addr,dst_addr,
								next_hop_addr,out_realm_id,src_vpn,tx_vpn,gen_marker);
		if( ip_rt_c == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		ip_rt_c->next_hash = _rhp_ip_routing_cache_v6_htbl[hval];
		_rhp_ip_routing_cache_v6_htbl[hval] = ip_rt_c;


		ip_rt_c->next_list = _rhp_ip_routing_cache_list_head.next_list;
	  if( _rhp_ip_routing_cache_list_head.next_list ){
	  	_rhp_ip_routing_cache_list_head.next_list->pre_list = ip_rt_c;
	  }
	  ip_rt_c->pre_list = &_rhp_ip_routing_cache_list_head;
	  _rhp_ip_routing_cache_list_head.next_list = ip_rt_c;


		_rhp_ip_routing_cache_v6_num++;
		_rhp_ip_routing_start_coarse_tick_timer();
	}

	if( ip_rt_c_r ){
		*ip_rt_c_r = ip_rt_c;
	}

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_UPDATE_V6_RTRN,"666ufx",src_addr,dst_addr,next_hop_addr,out_realm_id,_rhp_ip_routing_cache_v6_num,ip_rt_c);
	return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_UPDATE_V6_ERR,"666uE",src_addr,dst_addr,next_hop_addr,out_realm_id,err);
	return err;
}

static int _rhp_ip_routing_cache_aging_exec = 0;

static void _rhp_ip_routing_cache_aging_task(int worker_idx,void *ctx)
{
	int err = -EINVAL;
	rhp_ip_route_cache *ip_rt_c;
  time_t now = _rhp_get_time();
  struct timespec proc_start,proc_now;
  int exec_forcedly = 0;

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_AGING_TASK,"dxu",worker_idx,ctx,now);

  RHP_LOCK(&rhp_ip_routing_lock);

	if( _rhp_ip_routing_cache_v4_num >= (rhp_gcfg_ip_routing_cache_max_entries_v4/10)*9 ||
			_rhp_ip_routing_cache_v6_num >= (rhp_gcfg_ip_routing_cache_max_entries_v6/10)*9 ){

		exec_forcedly = 1;

	}else{

		clock_gettime(CLOCK_MONOTONIC,&proc_start);
	}

	ip_rt_c = _rhp_ip_routing_cache_list_head.next_list;
	while( ip_rt_c ){

		rhp_vpn* src_vpn = RHP_VPN_REF(ip_rt_c->src_vpn_ref);

		rhp_ip_route_cache* ip_rt_c_n = ip_rt_c->next_list;

		if(	(ip_rt_c->used_cnt == 0 &&
				 ((now - ip_rt_c->last_checked_time) >= (time_t)rhp_gcfg_ip_routing_cache_hold_time)) ||
				(src_vpn && !_rhp_atomic_read(&(src_vpn->is_active))) ){

			if( ip_rt_c->addr_family == AF_INET ){

				if( !_rhp_ip_routing_cache_delete_v4(ip_rt_c) ){
					_rhp_ip_routing_cache_free(ip_rt_c);
				}

			}else if( ip_rt_c->addr_family == AF_INET6 ){

				if( !_rhp_ip_routing_cache_delete_v6(ip_rt_c) ){
					_rhp_ip_routing_cache_free(ip_rt_c);
				}

			}else{
				RHP_BUG("%d",ip_rt_c->addr_family);
			}

		}else{

			if( ip_rt_c->used_cnt ){

				ip_rt_c->last_checked_time = now;

				ip_rt_c->used_cnt = 0;
			}
		}

		if( !exec_forcedly ){

			clock_gettime(CLOCK_MONOTONIC,&proc_now);

			if( proc_start.tv_sec != proc_now.tv_sec ||
					proc_now.tv_nsec - proc_start.tv_nsec > RHP_NET_CACHE_AGING_TASK_MAX_NSEC ){

				goto schedule_again;
			}
		}

		ip_rt_c = ip_rt_c_n;
	}


	_rhp_ip_routing_cache_aging_exec = 0;

  RHP_UNLOCK(&rhp_ip_routing_lock);

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_AGING_TASK_RTRN,"");
  return;

schedule_again:

  err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_2,_rhp_ip_routing_cache_aging_task,NULL);
  if( err ){
  	_rhp_ip_routing_cache_aging_exec = 0; // Next interval.
  }

  RHP_UNLOCK(&rhp_ip_routing_lock);

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_AGING_TASK_SCHEDULE_AGAIN,"tutudE",proc_start.tv_sec,proc_start.tv_nsec,proc_now.tv_sec,proc_now.tv_nsec,_rhp_ip_routing_cache_aging_exec,err);
  return;
}

static void _rhp_ip_routing_cache_aging_timer(void *ctx,rhp_timer *timer)
{
	int err = 0;

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_AGING_TIMER,"xx",ctx,timer);

	RHP_LOCK(&rhp_ip_routing_lock);

	if( _rhp_ip_routing_cache_aging_exec ){
	  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_AGING_TIMER_ADD_TASK_ALREADY_INVOKED,"xxd",ctx,timer,_rhp_ip_routing_cache_aging_exec);
		goto next_interval;
	}

  if( rhp_wts_dispach_ok(RHP_WTS_DISP_LEVEL_HIGH_2,1) ){

  	err = rhp_wts_add_task(RHP_WTS_DISP_RULE_MISC,
  					RHP_WTS_DISP_LEVEL_HIGH_2,NULL,_rhp_ip_routing_cache_aging_task,NULL);
  	if( err ){
  	  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_AGING_TIMER_ADD_TASK_ERR,"xxE",ctx,timer,err);
  		goto next_interval;
  	}

  	_rhp_ip_routing_cache_aging_exec = 1;
  }

next_interval:
  rhp_timer_reset(&_rhp_ip_routing_cache_timer);
  rhp_timer_add(&_rhp_ip_routing_cache_timer,(time_t)rhp_gcfg_ip_routing_cache_aging_interval);

	RHP_UNLOCK(&rhp_ip_routing_lock);

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_CACHE_AGING_TIMER_RTRN,"xx",ctx,timer);
	return;
}


// src_vpn: No lock is needed.
int rhp_ip_routing_v4(u32 src_addr,u32 dst_addr,rhp_vpn* src_vpn,
		u32* next_hop_addr_r,unsigned long* out_realm_id_r,int* tx_nhrp_trf_indication_r)
{
	int err = -ENOENT;
	u32 hval;
	rhp_ip_route_cache* ip_rt_c;
	u32 src_addr_org = src_addr;

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_V4,"44xpxxxd",src_addr,dst_addr,src_vpn,RHP_VPN_UNIQUE_ID_SIZE,src_vpn->unique_id,next_hop_addr_r,out_realm_id_r,tx_nhrp_trf_indication_r,(tx_nhrp_trf_indication_r ? *tx_nhrp_trf_indication_r : 0));

	if( rhp_gcfg_ip_routing_disabled ){
	  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_V4_DISABLED,"44",src_addr,dst_addr);
		return RHP_STATUS_IP_ROUTING_DISABLED;
	}

	if( rhp_gcfg_ip_routing_cache_dst_addr_only ){
		src_addr = 0;
	}


	hval = _rhp_ip_routing_cache_hash_v4(src_addr,dst_addr,src_vpn);


	RHP_LOCK(&rhp_ip_routing_lock);

	ip_rt_c = _rhp_ip_routing_cache_v4_htbl[hval];
	while( ip_rt_c ){

		if( ip_rt_c->type == RHP_IP_RT_ENT_TYPE_SYSTEM &&
				src_addr == ip_rt_c->src_addr.v4 && dst_addr == ip_rt_c->dst_addr.v4 &&
				(src_vpn == RHP_VPN_REF(ip_rt_c->src_vpn_ref)) ){ // src_vpn and ip_rt_c->src_vpn may be NULL. OK.

			*next_hop_addr_r = ip_rt_c->nexthop_addr.v4;

			*out_realm_id_r = ip_rt_c->out_realm_id;

			if( ip_rt_c->out_realm_id && tx_nhrp_trf_indication_r ){

				u64 now_tick = _rhp_ip_routing_get_tick();

			  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_V4_NHRP_TRF_IND,"44xqqq",src_addr,dst_addr,ip_rt_c,ip_rt_c->last_tx_nhrp_trf_indication_tick,now_tick,_rhp_gcfg_nhrp_traffic_indication_rate_limit);

				if( !ip_rt_c->last_tx_nhrp_trf_indication_tick ||
						(now_tick - ip_rt_c->last_tx_nhrp_trf_indication_tick) > _rhp_gcfg_nhrp_traffic_indication_rate_limit ){

					*tx_nhrp_trf_indication_r = 1;

					ip_rt_c->last_tx_nhrp_trf_indication_tick = now_tick;

				}else{

					*tx_nhrp_trf_indication_r = 0;
				}
			}

			break;
		}

		ip_rt_c = ip_rt_c->next_hash;
	}

	if( ip_rt_c == NULL ){

		err = _rhp_ip_routing_slow_v4_no_lock(
						RHP_IP_RT_ENT_TYPE_SYSTEM,
						src_addr_org,dst_addr,
						next_hop_addr_r,out_realm_id_r,NULL,NULL,NULL);
		if( !err ){

			int err2;

			err2 = _rhp_ip_routing_cache_update_v4(
								RHP_IP_RT_ENT_TYPE_SYSTEM,
								src_addr,dst_addr,src_vpn,
								*next_hop_addr_r,*out_realm_id_r,NULL,
								hval,0,&ip_rt_c);
			if( err2 ){

				RHP_BUG("%d",err2);

			}else{

				if( *out_realm_id_r && tx_nhrp_trf_indication_r ){

					*tx_nhrp_trf_indication_r = 1;

					ip_rt_c->last_tx_nhrp_trf_indication_tick = _rhp_ip_routing_get_tick();
				}
			}
		}

	}else{

	  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_V4_CACHE_FOUND,"x4444u",ip_rt_c,src_addr,src_addr_org,dst_addr,*next_hop_addr_r,(out_realm_id_r ? *out_realm_id_r : 0));

		err = 0;
	}

	if( ip_rt_c ){
		ip_rt_c->used_cnt++;
	}

	RHP_UNLOCK(&rhp_ip_routing_lock);

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_V4_RTRN,"4444udE",src_addr,src_addr_org,dst_addr,*next_hop_addr_r,(out_realm_id_r ? *out_realm_id_r : 0),(tx_nhrp_trf_indication_r ? *tx_nhrp_trf_indication_r : 0),err);
	return err;
}

//
// [CAUTION]
//
//  Before calling this function, check dst_addr is linklocal address on the same subnet.
//
int rhp_ip_routing_v6(u8* src_addr,u8* dst_addr,rhp_vpn* src_vpn,
		u8* next_hop_addr_r,unsigned long* out_realm_id_r,
		int* tx_nhrp_trf_indication_r)
{
	int err = -ENOENT;
	u32 hval;
	rhp_ip_route_cache* ip_rt_c;
	u8* src_addr_org = src_addr;

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_V6,"66xpxxx",src_addr,dst_addr,src_vpn,RHP_VPN_UNIQUE_ID_SIZE,src_vpn->unique_id,next_hop_addr_r,out_realm_id_r,tx_nhrp_trf_indication_r);

	if( rhp_gcfg_ip_routing_disabled ){
	  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_V6_DISABLED,"44",src_addr,dst_addr);
		return RHP_STATUS_IP_ROUTING_DISABLED;
	}

	if( rhp_gcfg_ip_routing_cache_dst_addr_only ){
		src_addr = _rhp_ip_routing_src_addr_v6_null;
	}


	hval = _rhp_ip_routing_cache_hash_v6(src_addr,dst_addr,src_vpn);


	RHP_LOCK(&rhp_ip_routing_lock);

	ip_rt_c = _rhp_ip_routing_cache_v6_htbl[hval];
	while( ip_rt_c ){

		if( ip_rt_c->type == RHP_IP_RT_ENT_TYPE_SYSTEM &&
				rhp_ipv6_is_same_addr(src_addr,ip_rt_c->src_addr.v6) &&
				rhp_ipv6_is_same_addr(dst_addr,ip_rt_c->dst_addr.v6) &&
				(src_vpn == RHP_VPN_REF(ip_rt_c->src_vpn_ref)) ){ // src_vpn and ip_rt_c->src_vpn may be NULL. OK.

			memcpy(next_hop_addr_r,ip_rt_c->nexthop_addr.v6,16);

			*out_realm_id_r = ip_rt_c->out_realm_id;

			if( ip_rt_c->out_realm_id && tx_nhrp_trf_indication_r ){

				u64 now_tick = _rhp_ip_routing_get_tick();

			  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_V6_NHRP_TRF_IND,"66xqqq",src_addr,dst_addr,ip_rt_c,ip_rt_c->last_tx_nhrp_trf_indication_tick,now_tick,_rhp_gcfg_nhrp_traffic_indication_rate_limit);

				if( !ip_rt_c->last_tx_nhrp_trf_indication_tick ||
						(now_tick - ip_rt_c->last_tx_nhrp_trf_indication_tick) > _rhp_gcfg_nhrp_traffic_indication_rate_limit ){

					*tx_nhrp_trf_indication_r = 1;

					ip_rt_c->last_tx_nhrp_trf_indication_tick = now_tick;

				}else{

					*tx_nhrp_trf_indication_r = 0;
				}
			}

			break;
		}

		ip_rt_c = ip_rt_c->next_hash;
	}

	if( ip_rt_c == NULL ){

		err = _rhp_ip_routing_slow_v6_no_lock(
						RHP_IP_RT_ENT_TYPE_SYSTEM,
						src_addr_org,dst_addr,
						next_hop_addr_r,out_realm_id_r,NULL,NULL,NULL);
		if( !err ){

			int err2;

			err2 = _rhp_ip_routing_cache_update_v6(
								RHP_IP_RT_ENT_TYPE_SYSTEM,
								src_addr,dst_addr,src_vpn,
								next_hop_addr_r,*out_realm_id_r,NULL,
								hval,0,&ip_rt_c);
			if( err2 ){

				RHP_BUG("%d",err2);

			}else{

				if( *out_realm_id_r && tx_nhrp_trf_indication_r ){

					*tx_nhrp_trf_indication_r = 1;

					ip_rt_c->last_tx_nhrp_trf_indication_tick = _rhp_ip_routing_get_tick();
				}
			}
		}

	}else{

	  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_V6_CACHE_FOUND,"x6666u",ip_rt_c,src_addr,src_addr_org,dst_addr,next_hop_addr_r,(out_realm_id_r ? *out_realm_id_r : 0));

		err = 0;
	}

	if( ip_rt_c ){
		ip_rt_c->used_cnt++;
	}

	RHP_UNLOCK(&rhp_ip_routing_lock);

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_V6_RTRN,"6666udE",src_addr,src_addr_org,dst_addr,next_hop_addr_r,(out_realm_id_r ? *out_realm_id_r : 0),(tx_nhrp_trf_indication_r ? *tx_nhrp_trf_indication_r : 0),err);
	return err;
}


int rhp_ip_routing_nhrp_v4(u32 src_addr,u32 dst_addr,unsigned long tx_realm_id,
		rhp_vpn_ref** tx_vpn_ref_r)
{
	int err = -ENOENT;
	u32 hval;
	rhp_ip_route_cache* ip_rt_c;
	u32 src_addr_org = src_addr;
	rhp_vpn_ref* tx_vpn_ref = NULL;
	unsigned long out_realm_id = tx_realm_id;
	u32 next_hop_addr = 0;

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_NHRP_V4,"44ux",src_addr,dst_addr,tx_realm_id,tx_vpn_ref_r);

	if( rhp_gcfg_ip_routing_disabled ){
	  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_NHRP_V4_DISABLED,"44",src_addr,dst_addr);
		return RHP_STATUS_IP_ROUTING_DISABLED;
	}

	if( rhp_gcfg_ip_routing_cache_dst_addr_only ){
		src_addr = 0;
	}


	hval = _rhp_ip_routing_cache_hash_v4(src_addr,dst_addr,NULL);


	RHP_LOCK(&rhp_ip_routing_lock);

	ip_rt_c = _rhp_ip_routing_cache_v4_htbl[hval];
	while( ip_rt_c ){

		if( ip_rt_c->type == RHP_IP_RT_ENT_TYPE_NHRP &&
				src_addr == ip_rt_c->src_addr.v4 && dst_addr == ip_rt_c->dst_addr.v4 &&
				ip_rt_c->out_realm_id == out_realm_id &&
				ip_rt_c->tx_vpn_ref ){

			break;
		}

		ip_rt_c = ip_rt_c->next_hash;
	}

	if( ip_rt_c == NULL ){

		rhp_ip_routing_entry* ip_rt_ent = NULL;

		err = _rhp_ip_routing_slow_v4_no_lock(
						RHP_IP_RT_ENT_TYPE_NHRP,
						src_addr_org,dst_addr,
						&next_hop_addr,&out_realm_id,NULL,
						&tx_vpn_ref,&ip_rt_ent);

		if( !err && tx_vpn_ref && out_realm_id == tx_realm_id ){

			int err2;

			err2 = _rhp_ip_routing_cache_update_v4(
								RHP_IP_RT_ENT_TYPE_NHRP,
								src_addr,dst_addr,NULL,
								next_hop_addr,out_realm_id,RHP_VPN_REF(tx_vpn_ref),
								hval,(unsigned long)ip_rt_ent,&ip_rt_c);
			if( err2 ){
				RHP_BUG("%lu,%d,0x%lx",out_realm_id,err2,(unsigned long)RHP_VPN_REF(tx_vpn_ref));
			}

		}else if( !err ){
			RHP_BUG("%lu,%d,0x%lx",out_realm_id,err,(unsigned long)RHP_VPN_REF(tx_vpn_ref));
			err = -EINVAL;
		}

	}else{

	  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_NHRP_V4_CACHE_FOUND,"x4444ux",ip_rt_c,src_addr,src_addr_org,dst_addr,next_hop_addr,out_realm_id,RHP_VPN_REF(tx_vpn_ref));

	  tx_vpn_ref = rhp_vpn_hold_ref(RHP_VPN_REF(ip_rt_c->tx_vpn_ref));

		err = 0;
	}

	if( ip_rt_c ){
		ip_rt_c->used_cnt++;
	}

	RHP_UNLOCK(&rhp_ip_routing_lock);


	if( !err ){

		rhp_vpn* tx_vpn = RHP_VPN_REF(tx_vpn_ref);

		RHP_LOCK(&(tx_vpn->lock));

		if( tx_vpn->childsa_established(tx_vpn) ){

			RHP_UNLOCK(&(tx_vpn->lock));

			*tx_vpn_ref_r = tx_vpn_ref;

		}else{

			RHP_UNLOCK(&(tx_vpn->lock));

			err = -ENOENT;
			rhp_vpn_unhold(tx_vpn_ref);
		}

	}else if( tx_vpn_ref ){

		rhp_vpn_unhold(tx_vpn_ref);
	}

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_NHRP_V4_RTRN,"4444uxxE",src_addr,src_addr_org,dst_addr,next_hop_addr,out_realm_id,tx_vpn_ref,RHP_VPN_REF(tx_vpn_ref),err);
	return err;
}

int rhp_ip_routing_nhrp_v6(u8* src_addr,u8* dst_addr,unsigned long tx_realm_id,
		rhp_vpn_ref** tx_vpn_ref_r)
{
	int err = -ENOENT;
	u32 hval;
	rhp_ip_route_cache* ip_rt_c;
	u8* src_addr_org = src_addr;
	rhp_vpn_ref* tx_vpn_ref = NULL;
	unsigned long out_realm_id = tx_realm_id;
	u8 next_hop_addr[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_NHRP_V6,"66ux",src_addr,dst_addr,tx_realm_id,tx_vpn_ref_r);

  memcpy(src_addr_org,src_addr,16);

	if( rhp_gcfg_ip_routing_disabled ){
	  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_NHRP_V6_DISABLED,"66",src_addr,dst_addr);
		return RHP_STATUS_IP_ROUTING_DISABLED;
	}

	if( rhp_gcfg_ip_routing_cache_dst_addr_only ){
		src_addr = _rhp_ip_routing_src_addr_v6_null;
	}


	hval = _rhp_ip_routing_cache_hash_v6(src_addr,dst_addr,NULL);


	RHP_LOCK(&rhp_ip_routing_lock);

	ip_rt_c = _rhp_ip_routing_cache_v6_htbl[hval];
	while( ip_rt_c ){

		if( ip_rt_c->type == RHP_IP_RT_ENT_TYPE_NHRP &&
				rhp_ipv6_is_same_addr(src_addr,ip_rt_c->src_addr.v6) &&
				rhp_ipv6_is_same_addr(dst_addr,ip_rt_c->dst_addr.v6) &&
				ip_rt_c->out_realm_id == out_realm_id &&
				ip_rt_c->tx_vpn_ref ){

			break;
		}

		ip_rt_c = ip_rt_c->next_hash;
	}

	if( ip_rt_c == NULL ){

		rhp_ip_routing_entry* ip_rt_ent = NULL;

		err = _rhp_ip_routing_slow_v6_no_lock(
						RHP_IP_RT_ENT_TYPE_NHRP,
						src_addr_org,dst_addr,
						next_hop_addr,&out_realm_id,NULL,&tx_vpn_ref,&ip_rt_ent);

		if( !err && tx_vpn_ref && out_realm_id == tx_realm_id ){

			int err2;

			err2 = _rhp_ip_routing_cache_update_v6(
								RHP_IP_RT_ENT_TYPE_NHRP,
								src_addr,dst_addr,NULL,
								next_hop_addr,out_realm_id,RHP_VPN_REF(tx_vpn_ref),
								hval,(unsigned long)ip_rt_ent,&ip_rt_c);
			if( err2 ){
				RHP_BUG("%lu,%d,0x%lx",out_realm_id,err2,(unsigned long)RHP_VPN_REF(tx_vpn_ref));
			}

		}else if( !err ){
			RHP_BUG("%lu,%d,0x%lx",out_realm_id,err,(unsigned long)RHP_VPN_REF(tx_vpn_ref));
			err = -EINVAL;
		}

	}else{

	  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_NHRP_V6_CACHE_FOUND,"x6666ux",ip_rt_c,src_addr,src_addr_org,dst_addr,next_hop_addr,out_realm_id,RHP_VPN_REF(tx_vpn_ref));

	  if( ip_rt_c->tx_vpn_ref ){

	  	tx_vpn_ref = rhp_vpn_hold_ref(RHP_VPN_REF(ip_rt_c->tx_vpn_ref));

			err = 0;

	  }else{
	  	RHP_BUG("");
	  	err = -EINVAL;;
	  }
	}

	if( ip_rt_c ){
		ip_rt_c->used_cnt++;
	}

	RHP_UNLOCK(&rhp_ip_routing_lock);


	if( !err ){

		rhp_vpn* tx_vpn = RHP_VPN_REF(tx_vpn_ref);

		RHP_LOCK(&(tx_vpn->lock));

		if( tx_vpn->childsa_established(tx_vpn) ){

			RHP_UNLOCK(&(tx_vpn->lock));

			*tx_vpn_ref_r = tx_vpn_ref;

		}else{

			RHP_UNLOCK(&(tx_vpn->lock));

			err = -ENOENT;
			rhp_vpn_unhold(tx_vpn_ref);
		}

	}else if( tx_vpn_ref ){

		rhp_vpn_unhold(tx_vpn_ref);
	}

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_NHRP_V6_RTRN,"6666uxxE",src_addr,src_addr_org,dst_addr,next_hop_addr,out_realm_id,tx_vpn_ref,RHP_VPN_REF(tx_vpn_ref),err);
	return err;
}

#define RHP_IP_ROUTING_BKT_PRIMES_MAX		13
static unsigned long _rhp_ip_routing_bkt_primes[RHP_IP_ROUTING_BKT_PRIMES_MAX]
= {131,257,521,1031,2153,4099,8209,16411,32779,65537,131041,262147,524309};

static int _rhp_ip_routing_bkt_rehash(int addr_family,rhp_ip_routing_bkt* ip_rt_bkt)
{
	int err = -EINVAL;
	rhp_ip_routing_entry** entries_hash_tbl_new = NULL;
	unsigned int i, new_bkt_size;

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_BKT_REHASH,"Ldxjdx","AF",addr_family,ip_rt_bkt,ip_rt_bkt->bkt_size,rhp_gcfg_ip_routing_hash_bucket_max_size,ip_rt_bkt->entries_hash_tbl);

	if( ip_rt_bkt->bkt_size >= (unsigned int)rhp_gcfg_ip_routing_hash_bucket_max_size ){
	  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_BKT_REHASH_NOP,"Ldxjd","AF",addr_family,ip_rt_bkt,ip_rt_bkt->bkt_size,rhp_gcfg_ip_routing_hash_bucket_max_size);
		return 0;
	}

	if( (ip_rt_bkt->rehashed + 1) >= RHP_IP_ROUTING_BKT_PRIMES_MAX ){
		new_bkt_size = ip_rt_bkt->bkt_size*2;
	}else{
		new_bkt_size = _rhp_ip_routing_bkt_primes[(ip_rt_bkt->rehashed + 1)];
	}

	entries_hash_tbl_new
		= (rhp_ip_routing_entry**)_rhp_malloc(sizeof(rhp_ip_routing_entry*)*new_bkt_size);
	if( entries_hash_tbl_new == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memset(entries_hash_tbl_new,0,sizeof(rhp_ip_routing_entry*)*new_bkt_size);

	for( i = 0; i < ip_rt_bkt->bkt_size; i++ ){

		rhp_ip_routing_entry* ip_rt_ent = ip_rt_bkt->entries_hash_tbl[i];

		while( ip_rt_ent ){

			rhp_ip_routing_entry* ip_rt_ent_n = ip_rt_ent->next;
			u32 hval = 0;

			if( addr_family == AF_INET ){
				hval = _rhp_hash_ipv4_1(ip_rt_ent->info.dest_network.addr.v4,_rhp_ip_routing_hashtbl_rnd);
			}else if( addr_family == AF_INET6 ){
				hval = _rhp_hash_ipv6_1(ip_rt_ent->info.dest_network.addr.v6,_rhp_ip_routing_hashtbl_rnd);
			}
		  hval %= new_bkt_size;

			ip_rt_ent->next = entries_hash_tbl_new[hval];
			entries_hash_tbl_new[hval] = ip_rt_ent;

			ip_rt_ent = ip_rt_ent_n;
		}
	}

	_rhp_free(ip_rt_bkt->entries_hash_tbl);
	ip_rt_bkt->entries_hash_tbl = entries_hash_tbl_new;
	ip_rt_bkt->bkt_size = new_bkt_size;
	ip_rt_bkt->rehashed++;

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_BKT_REHASH_RTRN,"Ldxjdx","AF",addr_family,ip_rt_bkt,ip_rt_bkt->bkt_size,ip_rt_bkt->rehashed,ip_rt_bkt->entries_hash_tbl);
	return 0;

error:
	if( entries_hash_tbl_new ){
		_rhp_free(entries_hash_tbl_new);
	}
  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_BKT_REHASH_ERR,"LdxjE","AF",addr_family,ip_rt_bkt,ip_rt_bkt->bkt_size,err);
	return err;
}

static void _rhp_ip_routing_entry_free(rhp_ip_routing_entry* ip_rt_ent)
{
  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_ENTRY_FREE,"xdxx",ip_rt_ent,ip_rt_ent->type,ip_rt_ent->tx_vpn_ref,RHP_VPN_REF(ip_rt_ent->tx_vpn_ref));

  if( ip_rt_ent->tx_vpn_ref ){
  	rhp_vpn_unhold(ip_rt_ent->tx_vpn_ref);
  }

	_rhp_free(ip_rt_ent);

	return;
}

static rhp_ip_routing_entry* _rhp_ip_routing_entry_alloc(int addr_family,
		rhp_rt_map_entry* rtmap,int type,rhp_vpn* tx_vpn,time_t hold_time)
{
	rhp_ip_routing_entry* ip_rt_ent
		= (rhp_ip_routing_entry*)_rhp_malloc(sizeof(rhp_ip_routing_entry));

	if( ip_rt_ent == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(ip_rt_ent,0,sizeof(rhp_ip_routing_entry));

	ip_rt_ent->tag[0] = '#';
	ip_rt_ent->tag[1] = 'I';
	ip_rt_ent->tag[2] = 'R';
	ip_rt_ent->tag[3] = 'E';

	ip_rt_ent->type = type;

	memcpy(&(ip_rt_ent->info),rtmap,sizeof(rhp_rt_map_entry));

	{
		char *p, *endp;

		if( rtmap->oif_name[0] != '\0' &&
				(p = strstr(rtmap->oif_name,RHP_VIRTUAL_IF_NAME)) ){

			p += strlen(RHP_VIRTUAL_IF_NAME);

			ip_rt_ent->out_realm_id = strtoul(p,&endp,0);
	    if( *endp != '\0' ){
	    	RHP_BUG("%s",rtmap->oif_name);
	    	_rhp_ip_routing_entry_free(ip_rt_ent);
	    	return NULL;
	    }
		}
	}

	ip_rt_ent->hold_time = hold_time;

	if( tx_vpn ){
		ip_rt_ent->tx_vpn_ref = rhp_vpn_hold_ref(tx_vpn);
	}

	ip_rt_ent->created_time = _rhp_get_time();

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_ENTRY_ALLOC,"Ldxxx","AF",addr_family,ip_rt_ent,rtmap,tx_vpn);
	rhp_rtmap_entry_dump("rtmap",rtmap);

	return ip_rt_ent;
}

static int _rhp_ip_routing_entry_add(rhp_rt_map_entry* rtmap,rhp_ip_routing_bkt* ip_rt_bkt,
		int type,rhp_vpn* tx_vpn,time_t hold_time,
		u32 hval)
{
	int err = -EINVAL;
	rhp_ip_routing_entry* ip_rt_ent;

	if( !hval ){

		if( rtmap->dest_network.addr_family == AF_INET ){
			hval = _rhp_hash_ipv4_1(rtmap->dest_network.addr.v4,_rhp_ip_routing_hashtbl_rnd);
		}else if( rtmap->dest_network.addr_family == AF_INET6 ){
			hval = _rhp_hash_ipv6_1(rtmap->dest_network.addr.v6,_rhp_ip_routing_hashtbl_rnd);
		}else{
			RHP_BUG("%d",rtmap->dest_network.addr_family);
			return -EINVAL;
		}

		hval %= ip_rt_bkt->bkt_size;
	}

	if( rtmap->dest_network.addr_family == AF_INET ){

		if( _rhp_ip_routing_entries_v4_num > rhp_gcfg_ip_routing_max_entries_v4 ){
			err = RHP_STATUS_IP_ROUTING_MAX_ENTRIES_REACHED;
			goto error;
		}

	}else if( rtmap->dest_network.addr_family == AF_INET6 ){

		if( _rhp_ip_routing_entries_v6_num > rhp_gcfg_ip_routing_max_entries_v6 ){
			err = RHP_STATUS_IP_ROUTING_MAX_ENTRIES_REACHED;
			goto error;
		}
	}

	// dddddddddddddddddddddddddddddd
	{
		rhp_ip_routing_entry* ip_rt_ent_tmp = ip_rt_bkt->entries_hash_tbl[hval];
		while( ip_rt_ent_tmp ){

			rhp_vpn* tx_vpn_tmp = RHP_VPN_REF(ip_rt_ent_tmp->tx_vpn_ref);

			if( ip_rt_ent_tmp->info.addr_family == rtmap->addr_family &&
					ip_rt_ent_tmp->info.dest_network.addr.v4 == rtmap->dest_network.addr.v4 &&
					ip_rt_ent_tmp->type == type && type == RHP_IP_RT_ENT_TYPE_NHRP &&
					tx_vpn && tx_vpn_tmp != tx_vpn ){

				_rhp_panic_time_bomb(3);
			}
			ip_rt_ent_tmp = ip_rt_ent_tmp->next;
		}
	}
	// dddddddddddddddddddddddddddddd

	ip_rt_ent = _rhp_ip_routing_entry_alloc(rtmap->dest_network.addr_family,
								rtmap,type,tx_vpn,hold_time);
	if( ip_rt_ent == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}


	ip_rt_ent->next = ip_rt_bkt->entries_hash_tbl[hval];
	ip_rt_bkt->entries_hash_tbl[hval] = ip_rt_ent;

	ip_rt_bkt->entries_num++;


	if( rtmap->dest_network.addr_family == AF_INET ){
		_rhp_ip_routing_entries_v4_num++;
	}else if( rtmap->dest_network.addr_family == AF_INET6 ){
		_rhp_ip_routing_entries_v6_num++;
	}


	if( ((double)ip_rt_bkt->entries_num/(double)ip_rt_bkt->bkt_size)
				>= rhp_gcfg_ip_routing_hash_bucket_max_occupancy_ratio ){

		if( _rhp_ip_routing_bkt_rehash(AF_INET,ip_rt_bkt) ){
			RHP_BUG("");
		}
	}

	return 0;

error:
	return err;
}

static int _rhp_ip_routing_entry_delete(rhp_ip_routing_entry* ip_rt_ent,
		rhp_ip_routing_bkt* ip_rt_bkt,u32 hval)
{
	rhp_ip_routing_entry *ip_rt_ent_d,*ip_rt_ent_d_p = NULL;

	if( !hval ){

		if( ip_rt_ent->info.dest_network.addr_family == AF_INET ){
			hval = _rhp_hash_ipv4_1(ip_rt_ent->info.dest_network.addr.v4,_rhp_ip_routing_hashtbl_rnd);
		}else if( ip_rt_ent->info.dest_network.addr_family == AF_INET6 ){
			hval = _rhp_hash_ipv6_1(ip_rt_ent->info.dest_network.addr.v6,_rhp_ip_routing_hashtbl_rnd);
		}else{
			RHP_BUG("%d",ip_rt_ent->info.dest_network.addr_family);
		}

		hval %= ip_rt_bkt->bkt_size;
	}

	ip_rt_ent_d = ip_rt_bkt->entries_hash_tbl[hval];
	while( ip_rt_ent_d ){

		if( ip_rt_ent_d == ip_rt_ent ){
			break;
		}

		ip_rt_ent_d_p = ip_rt_ent_d;
		ip_rt_ent_d = ip_rt_ent_d->next;
	}

	if( ip_rt_ent_d ){

		if( ip_rt_ent_d_p ){
			ip_rt_ent_d_p->next = ip_rt_ent_d->next;
		}else{
			ip_rt_bkt->entries_hash_tbl[hval] = ip_rt_ent_d->next;
		}

		ip_rt_bkt->entries_num--;

		if( ip_rt_ent->info.dest_network.addr_family == AF_INET ){
			_rhp_ip_routing_entries_v4_num--;
		}else if( ip_rt_ent->info.dest_network.addr_family == AF_INET6 ){
			_rhp_ip_routing_entries_v6_num--;
		}

		return 0;
	}

	RHP_BUG("");
	return -ENOENT;
}


static int _rhp_ip_routing_rtmapc_notifier_v4(int event,rhp_rtmapc_entry* rtmapc,
		rhp_rt_map_entry* old,rhp_ip_routing_bkt *ip_rt_bkt)
{
	int err = -EINVAL;
	rhp_ip_routing_entry* ip_rt_ent;
	u32 hval;

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_RTMAPC_NOTIFIER_V4,"Ldxxxd","RTMAP_EVT",event,rtmapc,old,ip_rt_bkt,ip_rt_bkt->prefix_len);


  hval = _rhp_hash_ipv4_1(rtmapc->info.dest_network.addr.v4,_rhp_ip_routing_hashtbl_rnd);
  hval %= ip_rt_bkt->bkt_size;

  ip_rt_ent = ip_rt_bkt->entries_hash_tbl[hval];
  while( ip_rt_ent ){

  	if( ip_rt_ent->type == RHP_IP_RT_ENT_TYPE_SYSTEM ){

  		if( ip_rt_ent->info.dest_network.addr.v4 == rtmapc->info.dest_network.addr.v4 &&
					ip_rt_ent->info.metric == rtmapc->info.metric ){

				break;
			}
  	}

  	ip_rt_ent = ip_rt_ent->next;
  }


  if( event == RHP_RTMAPC_EVT_UPDATED ){

		if( ip_rt_ent == NULL ){

			err = _rhp_ip_routing_entry_add(&(rtmapc->info),ip_rt_bkt,
							RHP_IP_RT_ENT_TYPE_SYSTEM,NULL,0,hval);
			if( err ){
				goto error;
			}

		}else{

			memcpy(&(ip_rt_ent->info),&(rtmapc->info),sizeof(rhp_rt_map_entry));
		}

		_rhp_ip_routing_cache_flush(AF_INET);


  }else if( event == RHP_RTMAPC_EVT_DELETED ){

  	if( ip_rt_ent == NULL ){
  		err = -ENOENT;
  		goto error;
  	}

  	if( !_rhp_ip_routing_entry_delete(ip_rt_ent,ip_rt_bkt,hval) ){
			_rhp_ip_routing_entry_free(ip_rt_ent);
  	}

		_rhp_ip_routing_cache_flush(AF_INET);
  }

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_RTMAPC_NOTIFIER_V4_RTRN,"Ldxxxd","RTMAP_EVT",event,rtmapc,old,ip_rt_bkt,ip_rt_bkt->prefix_len);
  return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_RTMAPC_NOTIFIER_V4_ERR,"LdxxxdE","RTMAP_EVT",event,rtmapc,old,ip_rt_bkt,ip_rt_bkt->prefix_len,err);
	return err;
}

static int _rhp_ip_routing_rtmapc_notifier_v6(int event,rhp_rtmapc_entry* rtmapc,
		rhp_rt_map_entry* old,rhp_ip_routing_bkt *ip_rt_bkt)
{
	int err = -EINVAL;
	rhp_ip_routing_entry* ip_rt_ent;
	u32 hval;

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_RTMAPC_NOTIFIER_V6,"Ldxxxd","RTMAP_EVT",event,rtmapc,old,ip_rt_bkt,ip_rt_bkt->prefix_len);


  hval = _rhp_hash_ipv6_1(rtmapc->info.dest_network.addr.v6,_rhp_ip_routing_hashtbl_rnd);
  hval %= ip_rt_bkt->bkt_size;

  ip_rt_ent = ip_rt_bkt->entries_hash_tbl[hval];
  while( ip_rt_ent ){

  	if( ip_rt_ent->type == RHP_IP_RT_ENT_TYPE_SYSTEM ){

			if( rhp_ipv6_is_linklocal(rtmapc->info.dest_network.addr.v6) ){

				if( rhp_ipv6_is_same_addr(ip_rt_ent->info.dest_network.addr.v6,rtmapc->info.dest_network.addr.v6) &&
						rtmapc->info.oif_name[0] != '\0' && ip_rt_ent->info.oif_name[0] != '\0' &&
						!strcmp(rtmapc->info.oif_name,ip_rt_ent->info.oif_name) ){
					break;
				}

			}else{

				if( rhp_ipv6_is_same_addr(ip_rt_ent->info.dest_network.addr.v6,rtmapc->info.dest_network.addr.v6) &&
						ip_rt_ent->info.metric == rtmapc->info.metric ){

					break;
				}
			}
  	}

  	ip_rt_ent = ip_rt_ent->next;
  }


  if( event == RHP_RTMAPC_EVT_UPDATED ){

		if( ip_rt_ent == NULL ){

			err = _rhp_ip_routing_entry_add(&(rtmapc->info),ip_rt_bkt,
							RHP_IP_RT_ENT_TYPE_SYSTEM,NULL,0,hval);
			if( err ){
				goto error;
			}

		}else{

			memcpy(&(ip_rt_ent->info),&(rtmapc->info),sizeof(rhp_rt_map_entry));
		}

		_rhp_ip_routing_cache_flush(AF_INET6);


  }else if( event == RHP_RTMAPC_EVT_DELETED ){

  	if( ip_rt_ent == NULL ){
  		err = -ENOENT;
  		goto error;
  	}

  	if( !_rhp_ip_routing_entry_delete(ip_rt_ent,ip_rt_bkt,hval) ){
			_rhp_ip_routing_entry_free(ip_rt_ent);
  	}

		_rhp_ip_routing_cache_flush(AF_INET6);
  }

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_RTMAPC_NOTIFIER_V6_RTRN,"Ldxxxd","RTMAP_EVT",event,rtmapc,old,ip_rt_bkt,ip_rt_bkt->prefix_len);
  return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_RTMAPC_NOTIFIER_V6_ERR,"LdxxxdE","RTMAP_EVT",event,rtmapc,old,ip_rt_bkt,ip_rt_bkt->prefix_len,err);
	return err;
}


static void _rhp_ip_routing_bkt_free(rhp_ip_routing_bkt* ip_rt_bkt)
{
  RHP_TRC(0,RHPTRCID_IP_ROUTING_BKT_FREE,"xx",ip_rt_bkt,ip_rt_bkt->entries_hash_tbl);

  if( ip_rt_bkt->entries_hash_tbl ){
		_rhp_free(ip_rt_bkt->entries_hash_tbl);
	}

	_rhp_free(ip_rt_bkt);

	return;
}

static rhp_ip_routing_bkt* _rhp_ip_routing_bkt_alloc(int addr_family,int prefix_len)
{
	rhp_ip_routing_bkt* ip_rt_bkt
		= (rhp_ip_routing_bkt*)_rhp_malloc(sizeof(rhp_ip_routing_bkt));

	if( ip_rt_bkt == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(ip_rt_bkt,0,sizeof(rhp_ip_routing_bkt));

	ip_rt_bkt->tag[0] = '#';
	ip_rt_bkt->tag[1] = 'I';
	ip_rt_bkt->tag[2] = 'R';
	ip_rt_bkt->tag[3] = 'B';

	ip_rt_bkt->prefix_len = prefix_len;
	if( addr_family == AF_INET ){

		ip_rt_bkt->netmask.v4 = rhp_ipv4_prefixlen_to_netmask(prefix_len);

	}else if( addr_family == AF_INET6 ){

		rhp_ipv6_prefixlen_to_netmask(prefix_len,ip_rt_bkt->netmask.v6);

	}else{
		RHP_BUG("%d",addr_family);
		_rhp_ip_routing_bkt_free(ip_rt_bkt);
		return NULL;
	}


	ip_rt_bkt->bkt_size = rhp_gcfg_ip_routing_hash_bucket_init_size;
	ip_rt_bkt->entries_num = 0;

	ip_rt_bkt->entries_hash_tbl
		= (rhp_ip_routing_entry**)_rhp_malloc(sizeof(rhp_ip_routing_entry*)*ip_rt_bkt->bkt_size);
	if( ip_rt_bkt->entries_hash_tbl == NULL ){
		RHP_BUG("");
		_rhp_ip_routing_bkt_free(ip_rt_bkt);
		return NULL;
	}

	memset(ip_rt_bkt->entries_hash_tbl,0,sizeof(rhp_ip_routing_entry*)*ip_rt_bkt->bkt_size);


	ip_rt_bkt->created = _rhp_get_time();

  RHP_TRC(0,RHPTRCID_IP_ROUTING_BKT_ALLOC,"Ldxxd","AF",addr_family,ip_rt_bkt,ip_rt_bkt->entries_hash_tbl,prefix_len);
	return ip_rt_bkt;
}

static rhp_ip_routing_bkt* _rhp_ip_routing_bkt_get(rhp_ip_addr* dst_network)
{
	rhp_ip_routing_bkt *ip_rt_bkt, *ip_rt_bkt_p, **ip_rt_bkt_head;

	if( dst_network->addr_family == AF_INET ){

		ip_rt_bkt = _rhp_ip_routing_bkts_v4_head;
		ip_rt_bkt_head = &_rhp_ip_routing_bkts_v4_head;

	}else if( dst_network->addr_family == AF_INET6 ){

		ip_rt_bkt = _rhp_ip_routing_bkts_v6_head;
		ip_rt_bkt_head = &_rhp_ip_routing_bkts_v6_head;

	}else{
	  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_BKT_GET_IGNORED,"xd",dst_network,dst_network->addr_family);
		goto ignored;
	}

	ip_rt_bkt_p = NULL;
	while( ip_rt_bkt ){

		if( dst_network->prefixlen >= ip_rt_bkt->prefix_len ){
			break;
		}

		ip_rt_bkt_p = ip_rt_bkt;
		ip_rt_bkt = ip_rt_bkt->next;
	}

	if( ip_rt_bkt == NULL ||
			(ip_rt_bkt->prefix_len != dst_network->prefixlen) ){

		rhp_ip_routing_bkt* ip_rt_bkt_new;

		ip_rt_bkt_new = _rhp_ip_routing_bkt_alloc(
				dst_network->addr_family,dst_network->prefixlen);
		if( ip_rt_bkt_new == NULL ){
			RHP_BUG("");
			goto error;
		}

		if( ip_rt_bkt_p ){
			ip_rt_bkt_p->next = ip_rt_bkt_new;
		}else{
			*ip_rt_bkt_head = ip_rt_bkt_new;
		}
		ip_rt_bkt_new->next = ip_rt_bkt;

		ip_rt_bkt = ip_rt_bkt_new;
	}

	return ip_rt_bkt;

ignored:
error:
	return NULL;
}


int rhp_ip_routing_nhrp_add_cache(rhp_ip_addr* dest_network,
		rhp_ip_addr* gateway_addr,unsigned long out_realm_id,int oif_index,
		rhp_vpn* tx_vpn,time_t hold_time,int metric)
{
	int err = -EINVAL;
	rhp_rt_map_entry rtmap;
	rhp_ip_routing_bkt* ip_rt_bkt;

  RHP_TRC(0,RHPTRCID_IP_ROUTING_NHRP_ADD_CACHE,"xxudxdd",dest_network,gateway_addr,out_realm_id,oif_index,tx_vpn,hold_time,metric);
	rhp_ip_addr_dump("dest_network",dest_network);
	rhp_ip_addr_dump("gateway_addr",gateway_addr);

	memset(&rtmap,0,sizeof(rhp_rt_map_entry));

	{
		rtmap.type = RHP_RTMAP_TYPE_NHRP_CACHE;
		rtmap.rtm_type = RTN_UNICAST;
		rtmap.addr_family = dest_network->addr_family;

		memcpy(&(rtmap.dest_network),dest_network,sizeof(rhp_ip_addr));

		if( gateway_addr ){
			memcpy(&(rtmap.gateway_addr),gateway_addr,sizeof(rhp_ip_addr));
		}

		if( snprintf(rtmap.oif_name,RHP_IFNAMSIZ,"%s%lu",RHP_VIRTUAL_IF_NAME,out_realm_id) >= (RHP_IFNAMSIZ + 1) ){
			RHP_BUG("%d",out_realm_id);
			err = -EINVAL;
			goto error;
		}

		rtmap.oif_index = oif_index;

		rtmap.metric = metric;
	}


  RHP_LOCK(&rhp_ip_routing_lock);

	ip_rt_bkt = _rhp_ip_routing_bkt_get(dest_network);
	if( ip_rt_bkt == NULL ){

		RHP_BUG("");

	  RHP_UNLOCK(&rhp_ip_routing_lock);
		err = -ENOMEM;
		goto error;
	}


	err = _rhp_ip_routing_entry_add(&rtmap,ip_rt_bkt,
					RHP_IP_RT_ENT_TYPE_NHRP,tx_vpn,hold_time,0);
	if( err ){
	  RHP_UNLOCK(&rhp_ip_routing_lock);
		goto error;
	}

  RHP_UNLOCK(&rhp_ip_routing_lock);

  RHP_TRC(0,RHPTRCID_IP_ROUTING_NHRP_ADD_CACHE_RTRN,"xx",dest_network,tx_vpn);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IP_ROUTING_NHRP_ADD_CACHE_ERR,"xxE",dest_network,tx_vpn,err);
	return err;
}

int rhp_ip_routing_nhrp_aging_cache(int* schedule_again_r)
{
	int err = -EINVAL;
  time_t now = _rhp_get_time();
  struct timespec proc_start,proc_now;
	rhp_ip_routing_bkt* ip_rt_bkt;
	int j;

  RHP_TRC(0,RHPTRCID_IP_ROUTING_NHRP_AGING_CACHE,"x",schedule_again_r);

  RHP_LOCK(&rhp_ip_routing_lock);

  clock_gettime(CLOCK_MONOTONIC,&proc_start);

  for( j = 0; j < 2; j++ ){

  	if( j == 0 ){
  		ip_rt_bkt = _rhp_ip_routing_bkts_v4_head;
  	}else{
  		ip_rt_bkt = _rhp_ip_routing_bkts_v6_head;
  	}

		while( ip_rt_bkt ){

			unsigned int i;

			for( i = 0; i < ip_rt_bkt->bkt_size; i++ ){

				rhp_ip_routing_entry* ip_rt_ent = ip_rt_bkt->entries_hash_tbl[i];

				while( ip_rt_ent ){

					rhp_ip_routing_entry* ip_rt_ent_n = ip_rt_ent->next;
					rhp_vpn* tx_vpn = RHP_VPN_REF(ip_rt_ent->tx_vpn_ref);

				  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_NHRP_AGING_CACHE_IP_RT_ENT,"xxxdtttt",ip_rt_bkt,ip_rt_ent,tx_vpn,ip_rt_ent->type,now,ip_rt_ent->created_time,ip_rt_ent->hold_time,(now - ip_rt_ent->created_time));

					if(	ip_rt_ent->type == RHP_IP_RT_ENT_TYPE_NHRP &&
							( (ip_rt_ent->hold_time &&
							  ((now - ip_rt_ent->created_time) >= ip_rt_ent->hold_time)) ||
							  (tx_vpn && !_rhp_atomic_read(&(tx_vpn->is_active))) ) ){

						_rhp_ip_routing_cache_flush_by_gen_marker((unsigned long)ip_rt_ent);

						if( !_rhp_ip_routing_entry_delete(ip_rt_ent,ip_rt_bkt,0) ){
							_rhp_ip_routing_entry_free(ip_rt_ent);
						}
					}

					{
						clock_gettime(CLOCK_MONOTONIC,&proc_now);

						if( proc_start.tv_sec != proc_now.tv_sec ||
								proc_now.tv_nsec - proc_start.tv_nsec > RHP_NET_CACHE_AGING_TASK_MAX_NSEC ){

							err = 0;
							goto schedule_again;
						}
					}

					ip_rt_ent = ip_rt_ent_n;
				}
			}

			ip_rt_bkt = ip_rt_bkt->next;
		}
  }

  RHP_UNLOCK(&rhp_ip_routing_lock);

	*schedule_again_r = 0;

  RHP_TRC(0,RHPTRCID_IP_ROUTING_NHRP_AGING_CACHE_RTRN,"");
  return 0;


schedule_again:

	RHP_UNLOCK(&rhp_ip_routing_lock);

	*schedule_again_r = 1;

	RHP_TRC(0,RHPTRCID_IP_ROUTING_NHRP_AGING_CACHE_SCHEDULE_AGAIN,"tutuE",proc_start.tv_sec,proc_start.tv_nsec,proc_now.tv_sec,proc_now.tv_nsec,err);
	return err;
}

int rhp_ip_routing_nhrp_flush_cache_by_vpn(rhp_vpn* tx_vpn)
{
	int err = -EINVAL;
	rhp_ip_routing_bkt* ip_rt_bkt;
	int j, n = 0;

  RHP_TRC(0,RHPTRCID_IP_ROUTING_NHRP_FLUSH_CACHE_BY_VPN,"x",tx_vpn);

  RHP_LOCK(&rhp_ip_routing_lock);

  for( j = 0; j < 2; j++ ){

  	if( j == 0 ){
  		ip_rt_bkt = _rhp_ip_routing_bkts_v4_head;
  	}else{
  		ip_rt_bkt = _rhp_ip_routing_bkts_v6_head;
  	}

		while( ip_rt_bkt ){

			unsigned int i;

			for( i = 0; i < ip_rt_bkt->bkt_size; i++ ){

				rhp_ip_routing_entry* ip_rt_ent = ip_rt_bkt->entries_hash_tbl[i];

				while( ip_rt_ent ){

					rhp_ip_routing_entry* ip_rt_ent_n = ip_rt_ent->next;

					if( ip_rt_ent->type == RHP_IP_RT_ENT_TYPE_NHRP &&
							tx_vpn == RHP_VPN_REF(ip_rt_ent->tx_vpn_ref) ){

						if( !_rhp_ip_routing_entry_delete(ip_rt_ent,ip_rt_bkt,0) ){
							_rhp_ip_routing_entry_free(ip_rt_ent);
							n++;
						}
					}

					ip_rt_ent = ip_rt_ent_n;
				}
			}

			ip_rt_bkt = ip_rt_bkt->next;
		}
  }

  RHP_UNLOCK(&rhp_ip_routing_lock);

  if( n > 0 ){
  	err = 0;
  }else{
  	err = -ENOENT;
  }

  RHP_TRC(0,RHPTRCID_IP_ROUTING_NHRP_FLUSH_CACHE_BY_VPN_RTRN,"E",err);
  return err;
}


static void _rhp_ip_routing_rtmapc_notifier(int event,rhp_rtmapc_entry* rtmapc,
		rhp_rt_map_entry* old,void* ctx)
{
	int err = -EINVAL;
	rhp_ip_routing_bkt* ip_rt_bkt;

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_RTMAPC_NOTIFIER,"Ldxxx","RTMAP_EVT",event,rtmapc,old,ctx);

	if( rhp_gcfg_ip_routing_disabled ){
	  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_RTMAPC_NOTIFIER_DISABLED,"Ldxxx","RTMAP_EVT",event,rtmapc,old,ctx);
		return;
	}

	RHP_LOCK(&rhp_ip_routing_lock);

	RHP_LOCK(&(rtmapc->lock));

  rtmapc->dump("rtmapc",rtmapc);
  rhp_rtmap_entry_dump("old",old);


  ip_rt_bkt = _rhp_ip_routing_bkt_get(&(rtmapc->info.dest_network));
  if( ip_rt_bkt == NULL ){
  	goto error;
  }


	if( rtmapc->info.addr_family == AF_INET ){

		err = _rhp_ip_routing_rtmapc_notifier_v4(event,rtmapc,old,ip_rt_bkt);

	}else if( rtmapc->info.addr_family == AF_INET6 ){

		err = _rhp_ip_routing_rtmapc_notifier_v6(event,rtmapc,old,ip_rt_bkt);
	}

error:
	RHP_UNLOCK(&(rtmapc->lock));

	RHP_UNLOCK(&rhp_ip_routing_lock);

  RHP_TRC_FREQ(0,RHPTRCID_IP_ROUTING_RTMAPC_NOTIFIER_RTRN,"LdxxxE","RTMAP_EVT",event,rtmapc,old,ctx,err);
	return;
}

int rhp_ip_routing_init()
{

  if( rhp_random_bytes((u8*)&_rhp_ip_routing_hashtbl_rnd,sizeof(_rhp_ip_routing_hashtbl_rnd)) ){
    RHP_BUG("");
    return -EINVAL;
  }

  _rhp_mutex_init("IRL",&rhp_ip_routing_lock);


  _rhp_ip_routing_cache_v4_htbl
  	= (rhp_ip_route_cache**)_rhp_malloc(sizeof(rhp_ip_route_cache*)*rhp_gcfg_ip_routing_cache_hash_size);
  if( _rhp_ip_routing_cache_v4_htbl == NULL ){
  	RHP_BUG("");
  	return -ENOMEM;
  }
  memset(_rhp_ip_routing_cache_v4_htbl,0,sizeof(rhp_ip_route_cache*)*rhp_gcfg_ip_routing_cache_hash_size);

  _rhp_ip_routing_cache_v6_htbl
  	= (rhp_ip_route_cache**)_rhp_malloc(sizeof(rhp_ip_route_cache*)*rhp_gcfg_ip_routing_cache_hash_size);
  if( _rhp_ip_routing_cache_v6_htbl == NULL ){
  	RHP_BUG("");
  	return -ENOMEM;
  }
  memset(_rhp_ip_routing_cache_v6_htbl,0,sizeof(rhp_ip_route_cache*)*rhp_gcfg_ip_routing_cache_hash_size);


  memset(&_rhp_ip_routing_cache_list_head,0,sizeof(rhp_ip_route_cache));
  _rhp_ip_routing_cache_list_head.tag[0] = '#';
  _rhp_ip_routing_cache_list_head.tag[1] = 'I';
  _rhp_ip_routing_cache_list_head.tag[2] = 'C';
  _rhp_ip_routing_cache_list_head.tag[3] = 'R';


  rhp_timer_init(&_rhp_ip_routing_cache_timer,_rhp_ip_routing_cache_aging_timer,NULL);
  rhp_timer_add(&_rhp_ip_routing_cache_timer,(time_t)rhp_gcfg_ip_routing_cache_aging_interval);


  _rhp_mutex_init("ICC",&_rhp_ip_routing_coarse_tick_lock);

  _rhp_gcfg_nhrp_traffic_indication_rate_limit
  	= rhp_gcfg_nhrp_traffic_indication_rate_limit / rhp_gcfg_ip_routing_coarse_tick_interval;
  if( _rhp_gcfg_nhrp_traffic_indication_rate_limit < 1 ){
  	_rhp_gcfg_nhrp_traffic_indication_rate_limit = 1;
  }

  rhp_timer_init(&_rhp_ip_routing_coarse_tick_timer,_rhp_ip_routing_coarse_tick_handler,NULL);


  RHP_TRC(0,RHPTRCID_IP_ROUTING_INIT,"");
  return 0;
}

int rhp_ip_routing_set_notifier()
{
  rhp_rtmapc_notifiers[RHP_RTMAPC_NOTIFIER_IP_ROUTING].callback = _rhp_ip_routing_rtmapc_notifier;
  rhp_rtmapc_notifiers[RHP_RTMAPC_NOTIFIER_IP_ROUTING].ctx = NULL;

  RHP_TRC(0,RHPTRCID_IP_ROUTING_SET_NOTIFIER,"Y",rhp_rtmapc_notifiers[RHP_RTMAPC_NOTIFIER_IP_ROUTING].callback);

  return 0;
}

int rhp_ip_routing_cleanup()
{
	_rhp_mutex_destroy(&rhp_ip_routing_lock);
	_rhp_mutex_destroy(&_rhp_ip_routing_coarse_tick_lock);

  RHP_TRC(0,RHPTRCID_IP_ROUTING_CLEANUP,"");
	return 0;
}
