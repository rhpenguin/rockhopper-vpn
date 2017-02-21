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
#include "rhp_tuntap.h"
#include "rhp_esp.h"
#include "rhp_ipv6.h"
#include "rhp_nhrp.h"


//
// TODO : IGMP snooping not to flood multicast packets.
//

//
// TODO : DHCP snooping to relay DHCP request packets from a DHCP
//        client to a server to avoid broadcasts.
//

//
// TODO : DHCP snooping to relay DHCP reply packets from a DHCP
//        server to a client.
//

//
// TODO : Keeping bridge cache entries as TLS ones to avoid acquiring
//        the global lock (rhp_bridge_lock).
//

rhp_mutex_t rhp_bridge_lock;


static u32 _rhp_bridge_hashtbl_rnd;

static rhp_bridge_cache**	_rhp_bridge_cache_hash_tbl = NULL;

static rhp_bridge_cache _rhp_bridge_list_head;


static u32 _rhp_bridge_neigh_hashtbl_rnd;

static rhp_bridge_neigh_cache**	_rhp_bridge_neigh_cache_tgt_ip_hash_tbl = NULL;
static rhp_bridge_neigh_cache**	_rhp_bridge_neigh_cache_tgt_mac_hash_tbl = NULL;

static rhp_bridge_neigh_cache _rhp_bridge_neigh_list_head;

static rhp_timer _rhp_bridge_cache_timer;

rhp_bridge_cache_global_statistics rhp_bridge_cache_statistics_tbl;

void rhp_bridge_get_statistics(rhp_bridge_cache_global_statistics* table)
{
	RHP_LOCK(&rhp_bridge_lock);
	memcpy(table,&rhp_bridge_cache_statistics_tbl,sizeof(rhp_bridge_cache_global_statistics));
	RHP_UNLOCK(&rhp_bridge_lock);
}

void rhp_bridge_clear_statistics()
{
	RHP_LOCK(&rhp_bridge_lock);
	memset(&rhp_bridge_cache_statistics_tbl,0,
			sizeof(rhp_bridge_cache_global_statistics) - sizeof(rhp_bridge_cache_global_statistics_dont_clear));
	RHP_UNLOCK(&rhp_bridge_lock);
}


static u32 _rhp_arp_rslv_hashtbl_rnd;

static rhp_neigh_rslv_ctx**	_rhp_neigh_rslv_hash_tbl = NULL;

static rhp_neigh_rslv_ctx* _rhp_neigh_resolve_get(unsigned long vpn_realm_id,int addr_family,u8* target_ip);


static int _rhp_bridge_hash(unsigned long vpn_realm_id,u8* dest_mac,u32 table_size)
{
  u32 hval;

  hval = _rhp_hash_bytes(dest_mac,6,_rhp_bridge_hashtbl_rnd);

  return (hval % table_size);
}

static inline int _rhp_bridge_neigh_hash_tgt_mac(unsigned long vpn_realm_id,u8* tgt_mac)
{
	int ret;
	ret = _rhp_bridge_hash(vpn_realm_id,tgt_mac,rhp_gcfg_neigh_cache_hash_size);
	RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_HASH_TGT_MAC,"uMd",vpn_realm_id,tgt_mac,ret);
	return ret;
}

static int _rhp_bridge_neigh_hash_tgt_ip(unsigned long vpn_realm_id,int addr_family,u8* target_ip)
{
  u32 hval = 0;

  if( addr_family == AF_INET ){
  	hval = _rhp_hash_ipv4_1(*((u32*)target_ip),_rhp_bridge_neigh_hashtbl_rnd);
  }else if( addr_family == AF_INET6 ){
  	hval = _rhp_hash_ipv6_1(target_ip,_rhp_bridge_neigh_hashtbl_rnd);
  }else{
  	RHP_BUG("%d",addr_family);
  }

  return (hval % rhp_gcfg_neigh_cache_hash_size);
}

static int _rhp_bridge_neigh_hash_tgt_ip2(unsigned long vpn_realm_id,rhp_ip_addr* target_ip)
{
	return _rhp_bridge_neigh_hash_tgt_ip(vpn_realm_id,target_ip->addr_family,target_ip->addr.raw);
}

static void _rhp_bridge_free_cache(rhp_bridge_cache* br_c)
{
  RHP_TRC(0,RHPTRCID_BRIDGE_FREE_CACHE,"xx",br_c,RHP_VPN_REF(br_c->vpn_ref));

	if( br_c->vpn_ref ){
		rhp_vpn_unhold(br_c->vpn_ref);
	}

	_rhp_free(br_c);
	return;
}

static int _rhp_bridge_cache_delete(rhp_bridge_cache* br_c)
{
  int err = 0;
  u32 hval;
  rhp_bridge_cache *br_c_tmp = NULL,*br_c_tmp_p;

  RHP_TRC(0,RHPTRCID_BRIDGE_CACHE_DELETE,"x",br_c);

  hval = _rhp_bridge_hash(br_c->vpn_realm_id,br_c->dest_mac,rhp_gcfg_mac_cache_hash_size);

  br_c_tmp = _rhp_bridge_cache_hash_tbl[hval];
  br_c_tmp_p = NULL;
  while( br_c_tmp ){

    if( br_c_tmp == br_c ){
   	  break;
    }

    br_c_tmp_p = br_c_tmp;
    br_c_tmp = br_c_tmp->next_hash;
  }

  if( br_c_tmp == NULL ){
    err = -ENOENT;
    RHP_TRC(0,RHPTRCID_BRIDGE_CACHE_DELETE_NOT_FOUND,"x",br_c);
    goto error;
  }

  if( br_c_tmp_p ){
    br_c_tmp_p->next_hash = br_c_tmp->next_hash;
  }else{
    _rhp_bridge_cache_hash_tbl[hval] = br_c_tmp->next_hash;
  }

  br_c->pre_list->next_list = br_c->next_list;
  if( br_c->next_list ){
  	br_c->next_list->pre_list = br_c->pre_list;
  }
  br_c->pre_list = NULL;
  br_c->next_list = NULL;

  rhp_bridge_cache_statistics_tbl.dc.bridge.cache_num--;

  RHP_TRC(0,RHPTRCID_BRIDGE_CACHE_DELETE_RTRN,"x",br_c);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_BRIDGE_CACHE_DELETE_ERR,"xE",br_c,err);
	return err;
}


static void _rhp_bridge_neigh_cache_tbl_ck(rhp_bridge_neigh_cache* br_c_n,int tgt_mac_only,u8* new_mac)
{
	int i;

	RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_TBL_CK,"xxuMMd",br_c_n,RHP_VPN_REF(br_c_n->vpn_ref),br_c_n->vpn_realm_id,br_c_n->target_mac,new_mac,new_mac);

	for( i = 0; i < rhp_gcfg_neigh_cache_hash_size; i++){

		rhp_bridge_neigh_cache* hoge = _rhp_bridge_neigh_cache_tgt_ip_hash_tbl[i];

		if( !tgt_mac_only ){

			while( hoge ){
				if( hoge == br_c_n ){
					RHP_BUG("br_c_n(tgt_ip): 0x%x",(unsigned long)br_c_n);
					_rhp_panic();
				}
				hoge = hoge->next_hash_tgt_ip;
			}
		}

		hoge = _rhp_bridge_neigh_cache_tgt_mac_hash_tbl[i];
		while( hoge ){
			if( hoge == br_c_n ){
				RHP_BUG("br_c_n(tgt_mac): 0x%x, %d",(unsigned long)br_c_n,i);
				_rhp_panic();
			}
			hoge = hoge->next_hash_tgt_mac;
		}
	}
}

static void _rhp_bridge_free_neigh_cache(rhp_bridge_neigh_cache* br_c_n)
{
	if( br_c_n->addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_BRIDGE_FREE_NEIGH_CACHE,"xxu4M",br_c_n,RHP_VPN_REF(br_c_n->vpn_ref),br_c_n->vpn_realm_id,br_c_n->target_ip.addr.v4,br_c_n->target_mac);
	}else if( br_c_n->addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_BRIDGE_FREE_NEIGH_CACHE_V6,"xxu6M",br_c_n,RHP_VPN_REF(br_c_n->vpn_ref),br_c_n->vpn_realm_id,br_c_n->target_ip.addr.v6,br_c_n->target_mac);
	}else{
		RHP_BUG("0x%x, %d",(unsigned long)br_c_n,br_c_n->addr_family);
	}

//	_rhp_bridge_neigh_cache_tbl_ck(br_c_n,0,NULL);

	if( br_c_n->vpn_ref ){
		rhp_vpn_unhold(br_c_n->vpn_ref);
	}

	_rhp_free(br_c_n);
	return;
}


static int _rhp_bridge_neigh_cache_delete(rhp_bridge_neigh_cache* br_c_n)
{
  int err = 0;
  u32 hval;
  rhp_bridge_neigh_cache *br_c_n_tmp = NULL,*br_c_n_tmp_p;

  if( br_c_n->addr_family == AF_INET ){
  	RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_DELETE,"xxu4MdLdd",br_c_n,RHP_VPN_REF(br_c_n->vpn_ref),br_c_n->vpn_realm_id,br_c_n->target_ip.addr.v4,br_c_n->target_mac,br_c_n->static_cache,"BRIDGE_SIDE",br_c_n->side,br_c_n->tgt_mac_cached);
  }else if( br_c_n->addr_family == AF_INET6 ){
  	RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_DELETE_V6,"xxu6MdLdd",br_c_n,RHP_VPN_REF(br_c_n->vpn_ref),br_c_n->vpn_realm_id,br_c_n->target_ip.addr.v6,br_c_n->target_mac,br_c_n->static_cache,"BRIDGE_SIDE",br_c_n->side,br_c_n->tgt_mac_cached);
  }else{
  	RHP_BUG("%d, %d, %d",br_c_n->addr_family,br_c_n->static_cache,br_c_n->tgt_mac_cached);
  }

  {
		hval = _rhp_bridge_neigh_hash_tgt_ip2(br_c_n->vpn_realm_id,&(br_c_n->target_ip));

		br_c_n_tmp = _rhp_bridge_neigh_cache_tgt_ip_hash_tbl[hval];
		br_c_n_tmp_p = NULL;
		while( br_c_n_tmp ){

			if( br_c_n_tmp == br_c_n ){
				break;
			}

			br_c_n_tmp_p = br_c_n_tmp;
			br_c_n_tmp = br_c_n_tmp->next_hash_tgt_ip;
		}

		if( br_c_n_tmp == NULL ){
			err = -ENOENT;
			RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_DELETE_NOT_FOUND,"xu",br_c_n,hval);
			goto error;
		}

		if( br_c_n_tmp_p ){
			br_c_n_tmp_p->next_hash_tgt_ip = br_c_n_tmp->next_hash_tgt_ip;
		}else{
			_rhp_bridge_neigh_cache_tgt_ip_hash_tbl[hval] = br_c_n_tmp->next_hash_tgt_ip;
		}
  }

  {
		hval = _rhp_bridge_neigh_hash_tgt_mac(br_c_n->vpn_realm_id,br_c_n->target_mac);

		br_c_n_tmp = _rhp_bridge_neigh_cache_tgt_mac_hash_tbl[hval];
		br_c_n_tmp_p = NULL;
		while( br_c_n_tmp ){

			if( br_c_n_tmp == br_c_n ){
				break;
			}

			br_c_n_tmp_p = br_c_n_tmp;
			br_c_n_tmp = br_c_n_tmp->next_hash_tgt_mac;
		}

		if( br_c_n_tmp == NULL ){

			RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_DELETE_NOT_FOUND_2,"xu",br_c_n,hval); // This is OK.

			if( br_c_n->tgt_mac_cached ){

				RHP_BUG("0x%x",(unsigned long)br_c_n);

				err = -EBUSY;
				goto error;
			}

		}else{

			if( br_c_n_tmp_p ){
				br_c_n_tmp_p->next_hash_tgt_mac = br_c_n_tmp->next_hash_tgt_mac;
			}else{
				_rhp_bridge_neigh_cache_tgt_mac_hash_tbl[hval] = br_c_n_tmp->next_hash_tgt_mac;
			}
		}
  }

  {
		br_c_n->pre_list->next_list = br_c_n->next_list;
		if( br_c_n->next_list ){
			br_c_n->next_list->pre_list = br_c_n->pre_list;
		}
		br_c_n->pre_list = NULL;
		br_c_n->next_list = NULL;
  }

  rhp_bridge_cache_statistics_tbl.dc.neigh.cache_num--;

  RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_DELETE_RTRN,"x",br_c_n);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_DELETE_ERR,"xE",br_c_n,err);
	return err;
}

static int _rhp_bridge_cache_aging_exec = 0;

static void _rhp_bridge_cache_aging_task(int worker_idx,void *ctx)
{
	int err = -EINVAL;
  rhp_bridge_cache *br_c_tmp,*br_c_tmp_next;
  rhp_bridge_neigh_cache *br_c_n_tmp,*br_c_n_tmp_next;
  time_t now = _rhp_get_time();
  struct timespec proc_start,proc_now;

  RHP_TRC(0,RHPTRCID_BRIDGE_CACHE_AGING_TASK,"dxu",worker_idx,ctx,now);

  RHP_LOCK(&rhp_bridge_lock);

  clock_gettime(CLOCK_MONOTONIC,&proc_start);

  {
	  br_c_tmp = _rhp_bridge_list_head.next_list;

	  while( br_c_tmp ){

	  	br_c_tmp_next = br_c_tmp->next_list;

	  	if( !(br_c_tmp->static_cache) ){

	  		rhp_vpn* vpn = RHP_VPN_REF(br_c_tmp->vpn_ref);

	  		if(	( br_c_tmp->last_used_cnt == 0 &&
	  				  ((now - br_c_tmp->last_checked_time) >= (time_t)rhp_gcfg_mac_cache_hold_time) ) ||
	  				(vpn && !_rhp_atomic_read(&(vpn->is_active))) ){

	  			if( !_rhp_bridge_cache_delete(br_c_tmp) ){
	  				_rhp_bridge_free_cache(br_c_tmp);
	  			}

	  		}else if( br_c_tmp->last_used_cnt ){

	  			br_c_tmp->last_checked_time = now;

	  			br_c_tmp->last_used_cnt = 0;
	  		}
	  	}

	  	{
				clock_gettime(CLOCK_MONOTONIC,&proc_now);

				if( proc_start.tv_sec != proc_now.tv_sec ||
						proc_now.tv_nsec - proc_start.tv_nsec > RHP_NET_CACHE_AGING_TASK_MAX_NSEC ){

					goto schedule_again;
				}
	  	}

	  	br_c_tmp = br_c_tmp_next;
	  }
  }


  {
	  br_c_n_tmp = _rhp_bridge_neigh_list_head.next_list;

	  while( br_c_n_tmp ){

	  	br_c_n_tmp_next = br_c_n_tmp->next_list;

	  	if( !(br_c_n_tmp->static_cache) ){

		  	if( br_c_n_tmp->last_used_cnt == 0 ){

		  		if( (now - br_c_n_tmp->last_checked_time)	>= (time_t)rhp_gcfg_mac_cache_hold_time ){

						if( !_rhp_bridge_neigh_cache_delete(br_c_n_tmp) ){
							_rhp_bridge_free_neigh_cache(br_c_n_tmp);
						}
		  		}

		  	}else{

		  		if( !br_c_n_tmp->stale &&
		  				(now - br_c_n_tmp->last_checked_time) >= (time_t)rhp_gcfg_mac_cache_hold_time ){

	  				br_c_n_tmp->last_checked_time = now;

		  			br_c_n_tmp->stale = 1;
		  		}

		  		br_c_n_tmp->last_used_cnt = 0;
		  	}
	  	}

	  	{
				clock_gettime(CLOCK_MONOTONIC,&proc_now);

				if( proc_start.tv_sec != proc_now.tv_sec ||
						proc_now.tv_nsec - proc_start.tv_nsec > RHP_NET_CACHE_AGING_TASK_MAX_NSEC ){

					goto schedule_again;
				}
	  	}

	  	br_c_n_tmp = br_c_n_tmp_next;
	  }
  }


	_rhp_bridge_cache_aging_exec = 0;

  RHP_UNLOCK(&rhp_bridge_lock);

  RHP_TRC(0,RHPTRCID_BRIDGE_CACHE_AGING_TASK_RTRN,"");
  return;


schedule_again:

	err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_2,_rhp_bridge_cache_aging_task,NULL);
	if( err ){
		_rhp_bridge_cache_aging_exec = 0; // Next interval.
	}

	RHP_UNLOCK(&rhp_bridge_lock);

	RHP_TRC(0,RHPTRCID_BRIDGE_CACHE_AGING_TASK_SCHEDULE_AGAIN,"tutudE",proc_start.tv_sec,proc_start.tv_nsec,proc_now.tv_sec,proc_now.tv_nsec,_rhp_bridge_cache_aging_exec,err);
	return;
}

static void _rhp_bridge_cache_aging_timer(void *ctx,rhp_timer *timer)
{
	int err = 0;

  RHP_TRC(0,RHPTRCID_BRIDGE_CACHE_AGING_TIMER,"xx",ctx,timer);

	RHP_LOCK(&rhp_bridge_lock);

	if( _rhp_bridge_cache_aging_exec ){
	  RHP_TRC(0,RHPTRCID_BRIDGE_CACHE_AGING_TIMER_ADD_TASK_ALREADY_INVOKED,"xxd",ctx,timer,_rhp_bridge_cache_aging_exec);
		goto next_interval;
	}

  if( rhp_wts_dispach_ok(RHP_WTS_DISP_LEVEL_HIGH_2,1) ){

  	err = rhp_wts_add_task(RHP_WTS_DISP_RULE_MISC,
  					RHP_WTS_DISP_LEVEL_HIGH_2,NULL,_rhp_bridge_cache_aging_task,NULL);
  	if( err ){
  	  RHP_TRC(0,RHPTRCID_BRIDGE_CACHE_AGING_TIMER_ADD_TASK_ERR,"xxE",ctx,timer,err);
  		goto next_interval;
  	}

  	_rhp_bridge_cache_aging_exec = 1;
  }

next_interval:
  rhp_timer_reset(&(_rhp_bridge_cache_timer));
  rhp_timer_add(&(_rhp_bridge_cache_timer),(time_t)rhp_gcfg_mac_cache_aging_interval);

	RHP_UNLOCK(&rhp_bridge_lock);

  RHP_TRC(0,RHPTRCID_BRIDGE_CACHE_AGING_TIMER_RTRN,"xx",ctx,timer);
	return;
}

int rhp_bridge_init()
{
  if( rhp_random_bytes((u8*)&_rhp_bridge_hashtbl_rnd,sizeof(_rhp_bridge_hashtbl_rnd)) ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( rhp_random_bytes((u8*)&_rhp_bridge_neigh_hashtbl_rnd,sizeof(_rhp_bridge_neigh_hashtbl_rnd)) ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( rhp_random_bytes((u8*)&_rhp_arp_rslv_hashtbl_rnd,sizeof(_rhp_arp_rslv_hashtbl_rnd)) ){
    RHP_BUG("");
    return -EINVAL;
  }

  _rhp_mutex_init("SWT",&(rhp_bridge_lock));


  _rhp_bridge_cache_hash_tbl
  	= (rhp_bridge_cache**)_rhp_malloc(sizeof(rhp_bridge_cache*)*rhp_gcfg_mac_cache_hash_size);
  if( _rhp_bridge_cache_hash_tbl == NULL ){
  	RHP_BUG("");
  	return -ENOMEM;
  }
  memset(_rhp_bridge_cache_hash_tbl,0,sizeof(rhp_bridge_cache*)*rhp_gcfg_mac_cache_hash_size);


  memset(&_rhp_bridge_list_head,0,sizeof(rhp_bridge_cache));
  _rhp_bridge_list_head.tag[0] = '#';
  _rhp_bridge_list_head.tag[1] = 'S';
  _rhp_bridge_list_head.tag[2] = 'W';
  _rhp_bridge_list_head.tag[3] = 'C';



  _rhp_bridge_neigh_cache_tgt_ip_hash_tbl
  	= (rhp_bridge_neigh_cache**)_rhp_malloc(sizeof(rhp_bridge_neigh_cache*)*rhp_gcfg_neigh_cache_hash_size);
  if( _rhp_bridge_neigh_cache_tgt_ip_hash_tbl == NULL ){
  	RHP_BUG("");
  	return -ENOMEM;
  }
  memset(_rhp_bridge_neigh_cache_tgt_ip_hash_tbl,0,sizeof(rhp_bridge_neigh_cache*)*rhp_gcfg_neigh_cache_hash_size);

  _rhp_bridge_neigh_cache_tgt_mac_hash_tbl
  	= (rhp_bridge_neigh_cache**)_rhp_malloc(sizeof(rhp_bridge_neigh_cache*)*rhp_gcfg_neigh_cache_hash_size);
  if( _rhp_bridge_neigh_cache_tgt_mac_hash_tbl == NULL ){
  	RHP_BUG("");
  	return -ENOMEM;
  }
  memset(_rhp_bridge_neigh_cache_tgt_mac_hash_tbl,0,sizeof(rhp_bridge_neigh_cache*)*rhp_gcfg_neigh_cache_hash_size);


  memset(&_rhp_bridge_neigh_list_head,0,sizeof(rhp_bridge_neigh_cache));
  _rhp_bridge_neigh_list_head.tag[0] = '#';
  _rhp_bridge_neigh_list_head.tag[1] = 'S';
  _rhp_bridge_neigh_list_head.tag[2] = 'A';
  _rhp_bridge_neigh_list_head.tag[3] = 'C';



  _rhp_neigh_rslv_hash_tbl
  	= (rhp_neigh_rslv_ctx**)_rhp_malloc(sizeof(rhp_neigh_rslv_ctx*)*rhp_gcfg_neigh_cache_hash_size);
  if( _rhp_neigh_rslv_hash_tbl == NULL ){
  	RHP_BUG("");
  	return -ENOMEM;
  }
  memset(_rhp_neigh_rslv_hash_tbl,0,sizeof(rhp_neigh_rslv_ctx*)*rhp_gcfg_neigh_cache_hash_size);



  rhp_timer_init(&(_rhp_bridge_cache_timer),_rhp_bridge_cache_aging_timer,NULL);

  rhp_timer_add(&(_rhp_bridge_cache_timer),(time_t)rhp_gcfg_mac_cache_aging_interval);


  memset(&rhp_bridge_cache_statistics_tbl,0,sizeof(rhp_bridge_cache_global_statistics));

  RHP_TRC(0,RHPTRCID_BRIDGE_INIT,"");
  return 0;
}

int rhp_bridge_cleanup()
{
  _rhp_mutex_destroy(&(rhp_bridge_lock));

  RHP_TRC(0,RHPTRCID_BRIDGE_CLEANUP,"");
  return 0;
}


static rhp_bridge_cache* _rhp_bridge_cache_alloc()
{
	rhp_bridge_cache* br_c;

	br_c = (rhp_bridge_cache*)_rhp_malloc(sizeof(rhp_bridge_cache));
	if( br_c == NULL ){
    RHP_BUG("");
    return NULL;
	}

	memset(br_c,0,sizeof(rhp_bridge_cache));

	br_c->tag[0] = '#';
	br_c->tag[1] = 'S';
	br_c->tag[2] = 'W';
	br_c->tag[3] = 'C';

	br_c->last_checked_time = _rhp_get_time();

  RHP_TRC(0,RHPTRCID_BRIDGE_CACHE_ALLOC,"x",br_c);
	return br_c;
}

static rhp_bridge_neigh_cache* _rhp_bridge_neigh_cache_alloc(int addr_family)
{
	rhp_bridge_neigh_cache* br_c_n;

	br_c_n = (rhp_bridge_neigh_cache*)_rhp_malloc(sizeof(rhp_bridge_neigh_cache));
	if( br_c_n == NULL ){
    RHP_BUG("");
    return NULL;
	}

	memset(br_c_n,0,sizeof(rhp_bridge_neigh_cache));

	br_c_n->tag[0] = '#';
	br_c_n->tag[1] = 'S';
	br_c_n->tag[2] = 'A';
	br_c_n->tag[3] = 'C';

	br_c_n->addr_family = addr_family;

	br_c_n->last_checked_time = _rhp_get_time();

	br_c_n->target_ip.addr_family = addr_family;

  RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_ALLOC,"x",br_c_n);
	return br_c_n;
}

static int _rhp_bridge_cache_cleanup_impl(unsigned long vpn_realm_id,rhp_vpn* vpn)
{
  int err = -ENOENT;
  rhp_bridge_cache *br_c_tmp,*br_c_tmp_next;
  rhp_bridge_neigh_cache *br_c_n_tmp,*br_c_n_tmp_next;

  RHP_TRC(0,RHPTRCID_BRIDGE_CACHE_CLEANUP,"ux",vpn_realm_id,vpn);

  RHP_LOCK(&rhp_bridge_lock);

  {
	  br_c_tmp = _rhp_bridge_list_head.next_list;

	  while( br_c_tmp ){

	  	br_c_tmp_next = br_c_tmp->next_list;

	  	if( (vpn_realm_id > 0 && br_c_tmp->vpn_realm_id == vpn_realm_id) ||
	  			(vpn && RHP_VPN_REF(br_c_tmp->vpn_ref) == vpn) ){

	  		if( !_rhp_bridge_cache_delete(br_c_tmp) ){
	  			_rhp_bridge_free_cache(br_c_tmp);
	  			err = 0;
	  		}
	  	}

	  	br_c_tmp = br_c_tmp_next;
	  }
  }

  {
  	br_c_n_tmp = _rhp_bridge_neigh_list_head.next_list;

	  while( br_c_n_tmp ){

	  	br_c_n_tmp_next = br_c_n_tmp->next_list;

		  if( (vpn_realm_id > 0 && br_c_n_tmp->vpn_realm_id == vpn_realm_id) ||
		  		(vpn && RHP_VPN_REF(br_c_n_tmp->vpn_ref) == vpn) ){

	  		if( !_rhp_bridge_neigh_cache_delete(br_c_n_tmp) ){
	  			_rhp_bridge_free_neigh_cache(br_c_n_tmp);
	  			err = 0;
	  		}
	  	}

 			br_c_n_tmp = br_c_n_tmp_next;
	  }
  }

  RHP_UNLOCK(&rhp_bridge_lock);

  RHP_TRC(0,RHPTRCID_BRIDGE_CACHE_CLEANUP_RTRN,"uxE",vpn_realm_id,vpn,err);
  return err;
}

int rhp_bridge_cache_cleanup_by_vpn(rhp_vpn* vpn)
{
	return _rhp_bridge_cache_cleanup_impl(0,vpn);
}

int rhp_bridge_cache_cleanup_by_realm_id(unsigned long vpn_realm_id)
{
	return _rhp_bridge_cache_cleanup_impl(vpn_realm_id,NULL);
}


static void _rhp_bridge_cache_put(rhp_bridge_cache* br_c)
{
  u32 hval;

  RHP_TRC(0,RHPTRCID_BRIDGE_CACHE_PUT,"xuM",br_c,br_c->vpn_realm_id,br_c->dest_mac);

  hval = _rhp_bridge_hash(br_c->vpn_realm_id,br_c->dest_mac,rhp_gcfg_mac_cache_hash_size);

  if( rhp_bridge_cache_statistics_tbl.dc.bridge.cache_num
  			> (unsigned long)rhp_gcfg_mac_cache_max_entries ){

  	rhp_bridge_cache* br_c_tmp = NULL;
  	int i;

  	for( i = 0; i < rhp_gcfg_mac_cache_hash_size; i++ ){

  		br_c_tmp = _rhp_bridge_cache_hash_tbl[i];
  		while( br_c_tmp ){

  			if( !br_c_tmp->static_cache ){
  				goto gc_end;
  			}

  			br_c_tmp = br_c_tmp->next_hash;
  		}
  	}

gc_end:
		if( br_c_tmp && !_rhp_bridge_cache_delete(br_c_tmp) ){
			_rhp_bridge_free_cache(br_c_tmp);
		}
  }

  br_c->next_hash = _rhp_bridge_cache_hash_tbl[hval];
  _rhp_bridge_cache_hash_tbl[hval] = br_c;

  br_c->next_list = _rhp_bridge_list_head.next_list;
  if( _rhp_bridge_list_head.next_list ){
	  _rhp_bridge_list_head.next_list->pre_list = br_c;
  }
  br_c->pre_list = &_rhp_bridge_list_head;
  _rhp_bridge_list_head.next_list = br_c;

  rhp_bridge_cache_statistics_tbl.dc.bridge.cache_num++;

  RHP_TRC(0,RHPTRCID_BRIDGE_CACHE_PUT_RTRN,"xd",br_c,rhp_bridge_cache_statistics_tbl.dc.bridge.cache_num);
  return;
}

static rhp_bridge_cache* _rhp_bridge_cache_get(unsigned long vpn_realm_id,u8* dest_mac)
{
  rhp_bridge_cache* br_c = NULL;
  u32 hval;

  RHP_TRC(0,RHPTRCID_BRIDGE_CACHE_GET,"uM",vpn_realm_id,dest_mac);

  rhp_bridge_cache_statistics_tbl.bridge.referenced++;

  hval = _rhp_bridge_hash(vpn_realm_id,dest_mac,rhp_gcfg_mac_cache_hash_size);

  br_c = _rhp_bridge_cache_hash_tbl[hval];

  while( br_c ){

    if( br_c->vpn_realm_id == vpn_realm_id && !memcmp(br_c->dest_mac,dest_mac,6) ){
      break;
    }

    br_c = br_c->next_hash;
  }

  if( br_c ){

  	switch( br_c->static_cache ){
  	case RHP_BRIDGE_SCACHE_DUMMY:
  		rhp_bridge_cache_statistics_tbl.bridge.static_dmy_cached_found++;
  		break;
  	case RHP_BRIDGE_SCACHE_IKEV2_EXCHG:
  		rhp_bridge_cache_statistics_tbl.bridge.static_exchg_cached_found++;
  		break;
  	default:
  		rhp_bridge_cache_statistics_tbl.bridge.dyn_cached_found++;
  		break;
  	}

  	RHP_TRC(0,RHPTRCID_BRIDGE_CACHE_GET_RTRN,"xxMLdd",br_c,RHP_VPN_REF(br_c->vpn_ref),br_c->dest_mac,"BRIDGE_SIDE",br_c->side,br_c->static_cache);

  }else{
    rhp_bridge_cache_statistics_tbl.bridge.cached_not_found++;
  	RHP_TRC(0,RHPTRCID_BRIDGE_CACHE_GET_NO_ENT,"uM",vpn_realm_id,dest_mac);
  }
  return br_c;
}

static void _rhp_bridge_neigh_cache_put(rhp_bridge_neigh_cache* br_c_n)
{
  u32 hval;

  if( br_c_n->addr_family == AF_INET ){
  	RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_PUT,"xu4dd",br_c_n,br_c_n->vpn_realm_id,br_c_n->target_ip.addr.v4,br_c_n->static_cache,br_c_n->tgt_mac_cached);
  }else if( br_c_n->addr_family == AF_INET6 ){
  	RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_PUT_V6,"xu6dd",br_c_n,br_c_n->vpn_realm_id,br_c_n->target_ip.addr.v6,br_c_n->static_cache,br_c_n->tgt_mac_cached);
  }

	if( rhp_bridge_cache_statistics_tbl.dc.neigh.cache_num
				> (unsigned long)rhp_gcfg_mac_cache_max_entries ){

		rhp_bridge_neigh_cache* br_c_n_tmp = NULL;
		int i;

		for( i = 0; i < rhp_gcfg_neigh_cache_hash_size ; i++ ){

			br_c_n_tmp = _rhp_bridge_neigh_cache_tgt_ip_hash_tbl[i];

			while( br_c_n_tmp ){

				if( !br_c_n_tmp->static_cache ){
					goto gc_end;
				}

				br_c_n_tmp = br_c_n_tmp->next_hash_tgt_ip;
			}
		}

gc_end:
		if( br_c_n_tmp && !_rhp_bridge_neigh_cache_delete(br_c_n_tmp) ){
			_rhp_bridge_free_neigh_cache(br_c_n_tmp);
		}
	}

  {
		hval = _rhp_bridge_neigh_hash_tgt_ip2(br_c_n->vpn_realm_id,&(br_c_n->target_ip));

		br_c_n->next_hash_tgt_ip = _rhp_bridge_neigh_cache_tgt_ip_hash_tbl[hval];
  	_rhp_bridge_neigh_cache_tgt_ip_hash_tbl[hval] = br_c_n;
  }

  if( br_c_n->static_cache &&
  		br_c_n->static_cache != RHP_BRIDGE_SCACHE_V6_DUMMY_LL_ADDR ){

		hval = _rhp_bridge_neigh_hash_tgt_mac(br_c_n->vpn_realm_id,br_c_n->target_mac);

		br_c_n->next_hash_tgt_mac = _rhp_bridge_neigh_cache_tgt_mac_hash_tbl[hval];
  	_rhp_bridge_neigh_cache_tgt_mac_hash_tbl[hval] = br_c_n;

  	br_c_n->tgt_mac_cached = 1;
  }

  {
		br_c_n->next_list = _rhp_bridge_neigh_list_head.next_list;
		if( _rhp_bridge_neigh_list_head.next_list ){
			_rhp_bridge_neigh_list_head.next_list->pre_list = br_c_n;
		}
		br_c_n->pre_list = &_rhp_bridge_neigh_list_head;
		_rhp_bridge_neigh_list_head.next_list = br_c_n;
  }

  rhp_bridge_cache_statistics_tbl.dc.neigh.cache_num++;

  RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_PUT_RTRN,"xdd",br_c_n,rhp_bridge_cache_statistics_tbl.dc.neigh.cache_num,br_c_n->tgt_mac_cached);
  return;
}

static rhp_bridge_neigh_cache* _rhp_bridge_neigh_cache_get_by_tgt_ip(unsigned long vpn_realm_id,
		int addr_family,u8* target_ip)
{
  rhp_bridge_neigh_cache* br_c_n = NULL;
  u32 hval;

  if( addr_family == AF_INET ){
  	RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_GET_TGT_IP,"u4",vpn_realm_id,*((u32*)target_ip));
  }else if( addr_family == AF_INET6 ){
  	RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_GET_TGT_IP_V6,"u6",vpn_realm_id,target_ip);
  }else{
  	RHP_BUG("%d",addr_family);
  }

  rhp_bridge_cache_statistics_tbl.neigh_cache.referenced++;

  hval = _rhp_bridge_neigh_hash_tgt_ip(vpn_realm_id,addr_family,target_ip);

  br_c_n = _rhp_bridge_neigh_cache_tgt_ip_hash_tbl[hval];

  while( br_c_n ){

    if( (br_c_n->vpn_realm_id == vpn_realm_id) &&
    		(br_c_n->target_ip.addr_family == addr_family ) ){

    	if( (addr_family == AF_INET &&
    			 br_c_n->target_ip.addr.v4 == *((u32*)target_ip)) ||
    			(addr_family == AF_INET6 &&
    			 rhp_ipv6_is_same_addr(br_c_n->target_ip.addr.v6,target_ip)) ){

        break;
    	}
    }

    br_c_n = br_c_n->next_hash_tgt_ip;
  }

  if( br_c_n ){

  	switch( br_c_n->static_cache ){
  	case RHP_BRIDGE_SCACHE_DUMMY:
  		rhp_bridge_cache_statistics_tbl.neigh_cache.static_dmy_cached_found++;
  		break;
  	case RHP_BRIDGE_SCACHE_IKEV2_EXCHG:
  		rhp_bridge_cache_statistics_tbl.neigh_cache.static_exchg_cached_found++;
  		break;
  	case RHP_BRIDGE_SCACHE_V6_DUMMY_LL_ADDR:
  		rhp_bridge_cache_statistics_tbl.neigh_cache.static_v6_dmy_linklocal_cached_found++;
  		break;
  	case RHP_BRIDGE_SCACHE_IKEV2_CFG:
  		rhp_bridge_cache_statistics_tbl.neigh_cache.static_ikev2_cfg_cached_found++;
  		break;
  	default:
  		rhp_bridge_cache_statistics_tbl.neigh_cache.dyn_cached_found++;
  		break;
  	}

  	if( addr_family == AF_INET ){
  		RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_GET_TGT_IP_RTRN,"xxu4MLddd",br_c_n,RHP_VPN_REF(br_c_n->vpn_ref),br_c_n->vpn_realm_id,br_c_n->target_ip.addr.v4,br_c_n->target_mac,"BRIDGE_SIDE",br_c_n,br_c_n->side,br_c_n->static_cache,br_c_n->stale);
  	}else if( addr_family == AF_INET6 ){
  		RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_GET_TGT_IP_V6_RTRN,"xxu6MLddd",br_c_n,RHP_VPN_REF(br_c_n->vpn_ref),br_c_n->vpn_realm_id,br_c_n->target_ip.addr.v6,br_c_n->target_mac,"BRIDGE_SIDE",br_c_n,br_c_n->side,br_c_n->static_cache,br_c_n->stale);
  	}

  }else{

  	rhp_bridge_cache_statistics_tbl.neigh_cache.cached_not_found++;

  	if( addr_family == AF_INET ){
  		RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_GET_TGT_IP_NO_CACHE,"u4",vpn_realm_id,*((u32*)target_ip));
  	}else if( addr_family == AF_INET6 ){
  		RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_GET_TGT_IP_NO_CACHE_V6,"u6",vpn_realm_id,target_ip);
  	}
  }

  return br_c_n;
}

static void _rhp_bridge_neigh_cache_rx_update(rhp_packet* pkt,
		unsigned long vpn_realm_id,int side,rhp_vpn* vpn)
{
	rhp_bridge_neigh_cache* br_c_n_src = NULL;
	rhp_neigh_rslv_ctx* rslv_ctx = NULL;
	int src_addr_family = AF_UNSPEC;
	u8* src_addr = NULL; // Just reference! Don't free it.
	u8* src_mac = NULL; // Just reference! Don't free it.
	u8 nd_type;

  RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_RX_UPDATE,"xudx",pkt,vpn_realm_id,side,vpn);

  if( pkt->l2.eth->protocol == RHP_PROTO_ETH_ARP ){

  	rhp_proto_arp* arph;

  	arph = (rhp_proto_arp*)(pkt->l2.eth + 1);
  	RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_RX_UPDATE_ARP_PKT,"xp",pkt,sizeof(rhp_proto_arp),arph);


  	if( RHP_PROTO_ETHER_MULTICAST_SRC(pkt->l2.eth) ){  // Including Broadcast address
  		RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_RX_UPDATE_ARP_IGNORE_SRC_MAC_MULTICAST,"xM",pkt,pkt->l2.eth->src_addr);
  		goto ignored;
  	}

  	if( (arph->hw_type == RHP_PROTO_ARP_HW_TYPE_ETHER) &&
  			(arph->proto_type == RHP_PROTO_ETH_IP) &&
  			((arph->operation == RHP_PROTO_ARP_OPR_REPLY) ||
  			 (arph->operation == RHP_PROTO_ARP_OPR_REQUEST)) ){

  		if( _rhp_mac_addr_null(arph->sender_mac) ){
  			RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_RX_UPDATE_ARP_IGNORE_SENDER_MAC_NULL,"xM",pkt,arph->sender_mac);
  			goto ignored;
  		}

  		// RFC5227(IPv4 Address Conflict Detection)
  		if( arph->sender_ipv4 == 0 ){
  			RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_RX_UPDATE_ARP_IGNORE_SENDER_IPV4_NULL,"x4",pkt,arph->sender_ipv4);
  			goto ignored;
  		}

			//
			// In case of Gratuitous ARP, sender_ipv4 == target_ipv4 (in most cases).
			//
			// Don't ref target_mac's value. It may be a broadcast address
			// (e.g. a GARP packet by Solaris) or a null address.
			//
			// http://wiki.wireshark.org/Gratuitous_ARP
			//

			rslv_ctx = _rhp_neigh_resolve_get(vpn_realm_id,
											AF_INET,(u8*)&(arph->sender_ipv4)); // Null may be returned.
			if( rslv_ctx &&
					arph->operation != RHP_PROTO_ARP_OPR_REPLY ){
				RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_RX_UPDATE_NOW_RESOLVING_BUT_NOT_RX_ARP_REP,"xx",pkt,rslv_ctx);
				goto ignored;
			}

			src_addr_family = AF_INET;
			src_addr = (u8*)&(arph->sender_ipv4);
			src_mac = arph->sender_mac;

  	}else{

			RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_RX_UPDATE_ARP_IGNORE_NOT_INTERESTED_TYPES,"x",pkt);
    	goto ignored;
  	}

  }else if( pkt->l2.eth->protocol == RHP_PROTO_ETH_IPV6 &&
  					rhp_ipv6_is_nd_packet(pkt,&nd_type) &&
  					(nd_type == RHP_PROTO_ICMP6_TYPE_NEIGHBOR_ADV ||
  					 nd_type == RHP_PROTO_ICMP6_TYPE_NEIGHBOR_SOLICIT) ){

		rhp_proto_ether* nd_eth;
		rhp_proto_ip_v6* nd_ip6h;
		rhp_proto_icmp6* nd_icmp6h;

		if( rhp_ipv6_icmp6_parse_rx_pkt(pkt,&nd_eth,&nd_ip6h,&nd_icmp6h) ){
			RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_RX_UPDATE_ND_IGNORE_ICMP6_PARSE_ERR,"x",pkt);
    	goto ignored;
		}

		if( rhp_ipv6_addr_null(nd_ip6h->src_addr) ){ // Ignore a DAD packet.
			RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_RX_UPDATE_ND_IGNORE_IPV6_SRC_ADDR_NULL,"x",pkt);
    	goto ignored;
		}

  	if( nd_type == RHP_PROTO_ICMP6_TYPE_NEIGHBOR_ADV ){

  		if( rhp_ipv6_nd_parse_adv_pkt(pkt,nd_eth,nd_ip6h,nd_icmp6h,
  				&src_addr,&src_mac) ){

  			RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_RX_UPDATE_ND_IGNORE_ADV_PARSE_ERR,"x",pkt);
  			goto ignored;
  		}

  	}else if( nd_type == RHP_PROTO_ICMP6_TYPE_NEIGHBOR_SOLICIT ){

  		if( rhp_ipv6_nd_parse_solicit_pkt(pkt,nd_eth,nd_ip6h,nd_icmp6h,
  				NULL,&src_addr,&src_mac) ){

  			RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_RX_UPDATE_ND_IGNORE_SOLICIT_PARSE_ERR,"x",pkt);
  			goto ignored;
  		}

  	}else{

			RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_RX_UPDATE_ND_IGNORE_NOT_INTERESTED_TYPE,"x",pkt);
    	goto ignored;
  	}

		if( src_addr == NULL || src_mac == NULL ){

			RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_RX_UPDATE_ND_IGNORE_TGT_ADDR_OR_LLMAC_NULL,"x",pkt);
			goto ignored;
		}


		rslv_ctx = _rhp_neigh_resolve_get(vpn_realm_id,
										AF_INET6,src_addr); // Null may be returned.
		if( rslv_ctx &&
				nd_type != RHP_PROTO_ICMP6_TYPE_NEIGHBOR_ADV ){
			RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_RX_UPDATE_NOW_RESOLVING_BUT_NOT_RX_ND_ADV,"xx",pkt,rslv_ctx);
			goto ignored;
		}

		src_addr_family = AF_INET6;

  }else{

		RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_RX_UPDATE_NOT_INTERESTED,"xW",pkt,pkt->l2.eth->protocol);
  	goto ignored;
  }


  if( src_addr_family != AF_INET && src_addr_family != AF_INET6 ){
  	RHP_BUG("%d",src_addr_family);
  	goto ignored;
  }


	br_c_n_src = _rhp_bridge_neigh_cache_get_by_tgt_ip(vpn_realm_id,src_addr_family,src_addr);

	if( br_c_n_src == NULL ){

		br_c_n_src = _rhp_bridge_neigh_cache_alloc(src_addr_family);
  	if( br_c_n_src == NULL ){
  		RHP_BUG("");
  		goto ignored;
  	}

  	br_c_n_src->vpn_realm_id = vpn_realm_id;
		br_c_n_src->side = side;

  	memcpy(br_c_n_src->target_mac,src_mac,6);

  	if( src_addr_family == AF_INET ){
  		memcpy(br_c_n_src->target_ip.addr.raw,src_addr,4);
  	}else if( src_addr_family == AF_INET6 ){
  		memcpy(br_c_n_src->target_ip.addr.v6,src_addr,16);
  	}

		if( vpn ){
			br_c_n_src->vpn_ref = rhp_vpn_hold_ref(vpn);
		}

  	_rhp_bridge_neigh_cache_put(br_c_n_src);

  	br_c_n_src->last_used_cnt++;

	}else if( !(br_c_n_src->static_cache) ){

		if( br_c_n_src->side != side ||
				memcmp(br_c_n_src->target_mac,src_mac,6) ){

			memcpy(br_c_n_src->target_mac,src_mac,6);

			br_c_n_src->side = side;

			if( br_c_n_src->vpn_ref ){
				rhp_vpn_unhold(br_c_n_src->vpn_ref);
				br_c_n_src->vpn_ref = NULL;
			}

			if( vpn ){
				br_c_n_src->vpn_ref = rhp_vpn_hold_ref(vpn);
			}

			if( rslv_ctx == NULL ){
				br_c_n_src->stale = 1;
			}
		}
	}

	if( rslv_ctx ){

		if( br_c_n_src ){
			br_c_n_src->stale = 0;
		}

		if( rhp_timer_pending(&(rslv_ctx->timer)) ){
			rhp_timer_update(&(rslv_ctx->timer),0);
		}
	}

ignored:

	RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_RX_UPDATE_RTRN,"x",pkt);
	return;
}

static int _rhp_bridge_cache_update_to_vpn(rhp_packet* pkt,rhp_ifc_entry* rx_v_ifc)
{
	int err = -EINVAL;
	rhp_bridge_cache* br_c_src = NULL;

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_CACHE_UPDATE_TO_VPN,"xxs",pkt,rx_v_ifc,rx_v_ifc->if_name);

	RHP_LOCK(&rhp_bridge_lock);

	if( _rhp_mac_addr_null(pkt->l2.eth->src_addr) ){
		err = 0;
		goto error;
	}


  br_c_src = _rhp_bridge_cache_get(rx_v_ifc->tuntap_vpn_realm_id,pkt->l2.eth->src_addr);

  if( br_c_src == NULL ){

  	br_c_src = _rhp_bridge_cache_alloc();
  	if( br_c_src == NULL ){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}

  	br_c_src->vpn_realm_id = rx_v_ifc->tuntap_vpn_realm_id;
  	br_c_src->side = RHP_BRIDGE_SIDE_TUNTAP;

  	memcpy(br_c_src->dest_mac,pkt->l2.eth->src_addr,6);

  	_rhp_bridge_cache_put(br_c_src);

  }else{

  	if( br_c_src->static_cache != RHP_BRIDGE_SCACHE_V6_DUMMY_LL_ADDR ){

			if( br_c_src->vpn_ref ){
				rhp_vpn_unhold(br_c_src->vpn_ref);
				br_c_src->vpn_ref = NULL;
			}

			br_c_src->side = RHP_BRIDGE_SIDE_TUNTAP;
  	}
  }

 	br_c_src->last_used_cnt++;


	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_CACHE_UPDATE_TO_VPN_ARP_CACHE,"xddWd",pkt,rhp_gcfg_proxy_arp_cache,rhp_gcfg_proxy_ipv6_nd_cache,pkt->l2.eth->protocol,pkt->len);
	rhp_pkt_trace_dump("_rhp_bridge_cache_update_to_vpn.arp",pkt);

	if( (rhp_gcfg_proxy_arp_cache && (pkt->l2.eth->protocol == RHP_PROTO_ETH_ARP)) ||
			(!rhp_gcfg_ipv6_disabled &&
				rhp_gcfg_proxy_ipv6_nd_cache && (pkt->l2.eth->protocol == RHP_PROTO_ETH_IPV6)) ){

		_rhp_bridge_neigh_cache_rx_update(pkt,rx_v_ifc->tuntap_vpn_realm_id,
				RHP_BRIDGE_SIDE_TUNTAP,NULL);
	}

  RHP_UNLOCK(&rhp_bridge_lock);

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_CACHE_UPDATE_TO_VPN_RTRN,"xx",pkt,rx_v_ifc);
	return 0;

error:
	RHP_UNLOCK(&rhp_bridge_lock);

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_CACHE_UPDATE_TO_VPN_ERR,"xxE",pkt,rx_v_ifc,err);
	return err;
}

static int _rhp_bridge_cache_update_from_vpn(rhp_packet* pkt,unsigned long vpn_realm_id,rhp_vpn* rx_vpn)
{
	int err = -EINVAL;
	rhp_bridge_cache* br_c_src = NULL;

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_CACHE_UPDATE_FROM_VPN,"xux",pkt,vpn_realm_id,rx_vpn);

	RHP_LOCK(&rhp_bridge_lock);

	if( _rhp_mac_addr_null(pkt->l2.eth->src_addr) ){
		err = 0;
		goto error;
	}


  br_c_src = _rhp_bridge_cache_get(vpn_realm_id,pkt->l2.eth->src_addr);

  if( br_c_src == NULL ){

  	br_c_src = _rhp_bridge_cache_alloc();
  	if( br_c_src == NULL ){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}

  	br_c_src->side = RHP_BRIDGE_SIDE_VPN;
  	br_c_src->vpn_realm_id = vpn_realm_id;

  	memcpy(br_c_src->dest_mac,pkt->l2.eth->src_addr,6);

  	_rhp_bridge_cache_put(br_c_src);

  }else{

  	if( br_c_src->static_cache != RHP_BRIDGE_SCACHE_V6_DUMMY_LL_ADDR ){

  		br_c_src->side = RHP_BRIDGE_SIDE_VPN;
  	}
  }

	if( br_c_src->static_cache != RHP_BRIDGE_SCACHE_V6_DUMMY_LL_ADDR ){

		if( br_c_src->vpn_ref && (RHP_VPN_REF(br_c_src->vpn_ref) != rx_vpn) ){
			rhp_vpn_unhold(br_c_src->vpn_ref);
			br_c_src->vpn_ref = NULL;
		}

		if( (br_c_src->vpn_ref == NULL) && (rx_vpn != NULL) ){
			br_c_src->vpn_ref = rhp_vpn_hold_ref(rx_vpn);
		}
	}

  br_c_src->last_used_cnt++;


  RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_CACHE_UPDATE_FROM_VPN_NEIGH_CACHE,"xddWd",pkt,rhp_gcfg_proxy_arp_cache,rhp_gcfg_proxy_ipv6_nd_cache,pkt->l2.eth->protocol,pkt->len);
	rhp_pkt_trace_dump("_rhp_bridge_cache_update_from_vpn.neigh",pkt);

	if( (rhp_gcfg_proxy_arp_cache && (pkt->l2.eth->protocol == RHP_PROTO_ETH_ARP)) ||
			(!rhp_gcfg_ipv6_disabled &&
				rhp_gcfg_proxy_ipv6_nd_cache && (pkt->l2.eth->protocol == RHP_PROTO_ETH_IPV6))){

		_rhp_bridge_neigh_cache_rx_update(pkt,vpn_realm_id,RHP_BRIDGE_SIDE_VPN,rx_vpn);
	}

  RHP_UNLOCK(&rhp_bridge_lock);

  RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_CACHE_UPDATE_FROM_VPN_RTRN,"x",pkt);
  return 0;

error:
	RHP_UNLOCK(&rhp_bridge_lock);

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_CACHE_UPDATE_FROM_VPN_ERR,"xE",pkt,err);
	return err;
}


static rhp_packet* _rhp_arp_new_reply(rhp_packet* rx_pkt,u8* cached_sender_mac)
{
	rhp_packet* pkt_reply = NULL;
	rhp_proto_arp *arph,*rx_arph;
	rhp_proto_ether *eth,*rx_eth;

	RHP_TRC(0,RHPTRCID_ARP_NEW_REPLY,"xM",rx_pkt,cached_sender_mac);
	rhp_pkt_trace_dump("rx_pkt",rx_pkt);

	if( _rhp_mac_addr_null(cached_sender_mac) ){
		RHP_BUG("");
		return NULL;
	}

	rx_eth = rx_pkt->l2.eth;
	rx_arph = (rhp_proto_arp*)(rx_eth + 1);

	if( rx_eth->protocol != RHP_PROTO_ETH_ARP ){
		RHP_BUG("");
		return NULL;
	}

	pkt_reply = rhp_pkt_alloc(sizeof(rhp_proto_ether)+sizeof(rhp_proto_arp));
	if( pkt_reply == NULL ){
		RHP_BUG("");
		return NULL;
	}

	pkt_reply->type = RHP_PKT_PLAIN_ETHER_TAP;

	eth = (rhp_proto_ether*)_rhp_pkt_push(pkt_reply,(int)sizeof(rhp_proto_ether));
	arph = (rhp_proto_arp*)_rhp_pkt_push(pkt_reply,(int)sizeof(rhp_proto_arp));

	pkt_reply->l2.eth = eth;
	pkt_reply->l3.raw = (u8*)arph;

	eth->protocol = RHP_PROTO_ETH_ARP;
	memcpy(eth->dst_addr,rx_eth->src_addr,6);
	memcpy(eth->src_addr,cached_sender_mac,6);


	arph->hw_type = RHP_PROTO_ARP_HW_TYPE_ETHER;
	arph->hw_len = 6;
	arph->proto_type = RHP_PROTO_ETH_IP;
	arph->proto_len = 4;
	arph->operation = RHP_PROTO_ARP_OPR_REPLY;

	memcpy(arph->target_mac,rx_eth->src_addr,6);
	memcpy(arph->sender_mac,cached_sender_mac,6);

	arph->sender_ipv4 = rx_arph->target_ipv4;
	arph->target_ipv4 = rx_arph->sender_ipv4;

	rhp_pkt_trace_dump("_rhp_arp_new_reply",pkt_reply);
	RHP_TRC(0,RHPTRCID_ARP_NEW_REPLY_RTRN,"xxa",rx_pkt,pkt_reply,(sizeof(rhp_proto_ether) + sizeof(rhp_proto_arp)),RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,eth);

	return pkt_reply;
}

static rhp_packet* _rhp_nd_new_reply(
		rhp_packet* rx_pkt,
		rhp_proto_ether* rx_v6_eth,
		rhp_proto_ip_v6* rx_v6_ip6h,rhp_proto_icmp6* rx_v6_icmp6h,
		u8* target_ipv6,u8* cached_sender_mac,u8* v6_lladdr,u8* v6_llmac)
{
	rhp_packet* pkt_reply;

	RHP_TRC(0,RHPTRCID_ND_NEW_REPLY,"xxxx6M6M",rx_pkt,rx_v6_eth,rx_v6_ip6h,rx_v6_icmp6h,target_ipv6,cached_sender_mac,v6_lladdr,v6_llmac);
	rhp_pkt_trace_dump("rx_pkt",rx_pkt);

	pkt_reply = rhp_ipv6_nd_new_adv_pkt(cached_sender_mac,target_ipv6,
								v6_llmac,rx_v6_eth->src_addr,v6_lladdr,rx_v6_ip6h->src_addr,1);

	if( pkt_reply == NULL ){
		RHP_BUG("");
		return NULL;
	}

	rhp_pkt_trace_dump("_rhp_nd_new_reply",pkt_reply);
	RHP_TRC(0,RHPTRCID_ND_NEW_REPLY_RTRN,"xxa",rx_pkt,pkt_reply,(sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v6) + ntohs(pkt_reply->l3.iph_v6->payload_len)),RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,pkt_reply->l2.raw);

	return pkt_reply;
}

static rhp_packet* _rhp_arp_new_request(u8* sender_mac,u8* target_mac,
		u32 sender_ipv4,u32 target_ipv4,rhp_ifc_entry *rx_ifc)
{
	rhp_packet* pkt_req = NULL;
	rhp_proto_arp *arph;
	rhp_proto_ether* eth;

	RHP_TRC(0,RHPTRCID_ARP_NEW_REQUEST,"MM44xs",sender_mac,target_mac,sender_ipv4,target_ipv4,rx_ifc,rx_ifc->if_name);

	if( _rhp_mac_addr_null(sender_mac) ){
		RHP_BUG("");
		return NULL;
	}

	if( (sender_ipv4 == 0) || (target_ipv4 == 0) ){
		RHP_BUG("");
		return NULL;
	}

	pkt_req = rhp_pkt_alloc(sizeof(rhp_proto_ether) + sizeof(rhp_proto_arp));
	if( pkt_req == NULL ){
		RHP_BUG("");
		return NULL;
	}

	pkt_req->type = RHP_PKT_PLAIN_ETHER_TAP;

	eth = (rhp_proto_ether*)_rhp_pkt_push(pkt_req,(int)sizeof(rhp_proto_ether));
	arph = (rhp_proto_arp*)_rhp_pkt_push(pkt_req,(int)sizeof(rhp_proto_arp));

	pkt_req->l2.eth = eth;
	pkt_req->l3.raw = (u8*)arph;

	if( target_mac && !_rhp_mac_addr_null(target_mac) ){

		memcpy(eth->dst_addr,target_mac,6);

		memcpy(arph->target_mac,target_mac,6);

	}else{

		eth->dst_addr[0] = 0xFF;
		eth->dst_addr[1] = 0xFF;
		eth->dst_addr[2] = 0xFF;
		eth->dst_addr[3] = 0xFF;
		eth->dst_addr[4] = 0xFF;
		eth->dst_addr[5] = 0xFF;

		memset(arph->target_mac,0,6);
	}
	memcpy(eth->src_addr,sender_mac,6);
	eth->protocol = RHP_PROTO_ETH_ARP;

	arph->hw_type = RHP_PROTO_ARP_HW_TYPE_ETHER;
	arph->hw_len = 6;
	arph->proto_type = RHP_PROTO_ETH_IP;
	arph->proto_len = 4;
	arph->operation = RHP_PROTO_ARP_OPR_REQUEST;
	memcpy(arph->sender_mac,sender_mac,6);

	arph->sender_ipv4 = sender_ipv4;
	arph->target_ipv4 = target_ipv4;

	pkt_req->rx_if_index = rx_ifc->if_index;
	pkt_req->rx_ifc = rx_ifc;
	rhp_ifc_hold(rx_ifc);

	rhp_pkt_trace_dump("_rhp_arp_new_request",pkt_req);
	RHP_TRC(0,RHPTRCID_ARP_NEW_REQUEST_RTRN,"xa",pkt_req,(sizeof(rhp_proto_ether) + sizeof(rhp_proto_arp)),RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,eth);

	return pkt_req;
}

static rhp_packet* _rhp_nd_new_solicitation(u8* sender_mac,
		u8* sender_ipv6,u8* target_ipv6,rhp_ifc_entry* rx_ifc)
{
	rhp_packet* sol_pkt = NULL;

	RHP_TRC(0,RHPTRCID_ND_NEW_SOLICITATION,"M66xs",sender_mac,sender_ipv6,target_ipv6,rx_ifc,rx_ifc->if_name);

	sol_pkt = rhp_ipv6_nd_new_solicitation_pkt(sender_mac,target_ipv6,sender_ipv6,1);
	if( sol_pkt == NULL ){
		RHP_BUG("");
		return NULL;
	}

	sol_pkt->rx_if_index = rx_ifc->if_index;
	sol_pkt->rx_ifc = rx_ifc;
	rhp_ifc_hold(rx_ifc);

	RHP_TRC(0,RHPTRCID_ND_NEW_SOLICITATION_RTRN,"M66x",sender_mac,sender_ipv6,target_ipv6,rx_ifc);
	return sol_pkt;
}


static int _rhp_bridge_handle_rx_mld_query_for_tuntap(rhp_packet* pkt,
		u8 nd_icmp6_type,rhp_packet** mld_rep_pkt_r)
{
	int err = -EINVAL;
	rhp_ifc_entry* v_ifc = pkt->rx_ifc;
	int pld_len;
	rhp_packet* mld_rep_pkt = NULL;
	rhp_proto_ether* eth = NULL;
	rhp_proto_ip_v6* ip6h = NULL;
	rhp_proto_icmp6* icmp6h = NULL;

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_RX_MLD_QUERY_FOR_TUNTAP,"xux",pkt,nd_icmp6_type,mld_rep_pkt_r);

	if( pkt->l2.raw == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( RHP_PROTO_ETHER_MULTICAST_SRC(pkt->l2.eth) ){  // Including Broadcast address
		RHP_TRC(0,RHPTRCID_BRIDGE_HANDLE_RX_MLD_QUERY_FOR_TUNTAP_IGNORE_SRC_MAC_MULTICAST,"xM",pkt,pkt->l2.eth->src_addr);
		return 0;
	}

	if( pkt->l2.eth->protocol != RHP_PROTO_ETH_IPV6 ||
			nd_icmp6_type != RHP_PROTO_ICMP6_TYPE_MLD_LISTENER_QUERY ){
		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_RX_MLD_QUERY_FOR_TUNTAP_NOT_INTERESTED_ND,"x",pkt);
		return 0;
	}

	if( v_ifc == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}


	err = rhp_ipv6_icmp6_parse_rx_pkt(pkt,&eth,&ip6h,&icmp6h);
	if( err ){
		RHP_TRC_FREQ(0,RRHPTRCID_BRIDGE_HANDLE_RX_MLD_QUERY_FOR_TUNTAP_PARSE_ICMP6_ERR,"xE",pkt,err);
		return 0;
	}


	RHP_LOCK(&(v_ifc->lock));

  if( !_rhp_atomic_read(&(v_ifc->is_active)) || v_ifc->tuntap_fd < -1 ){
  	err = 0;
		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_RX_MLD_QUERY_FOR_TUNTAP_IGNORE_TUNTAP_NOT_ACTIVE,"x",pkt);
  	goto error;
  }

	if( v_ifc->v6_aux_lladdr.state != RHP_V6_LINK_LOCAL_ADDR_AVAILABLE ){
		err = 0;
		goto error;
	}

	pld_len = ntohs(ip6h->payload_len);

	if( pld_len == (int)sizeof(rhp_proto_icmp6_mld1_query) ){

		rhp_proto_icmp6_mld1_query* mld1h = (rhp_proto_icmp6_mld1_query*)icmp6h;

		if( rhp_ipv6_addr_null(mld1h->mc_addr) ||
				rhp_ipv6_is_same_addr(mld1h->mc_addr,v_ifc->v6_aux_lladdr.lladdr_sol_node_mc) ){

			mld_rep_pkt = rhp_ipv6_new_mld1_report(v_ifc->v6_aux_lladdr.mac,
											v_ifc->v6_aux_lladdr.lladdr.addr.v6,mld1h->mc_addr);
		}

	}else if( pld_len >= (int)sizeof(rhp_proto_icmp6_mld2_query) ){

		rhp_proto_icmp6_mld2_query* mld2h = (rhp_proto_icmp6_mld2_query*)icmp6h;

		if( rhp_ipv6_addr_null(mld2h->mc_addr) ||
				rhp_ipv6_is_same_addr(mld2h->mc_addr,v_ifc->v6_aux_lladdr.lladdr_sol_node_mc) ){

			mld_rep_pkt = rhp_ipv6_new_mld2_report(v_ifc->v6_aux_lladdr.mac,
											v_ifc->v6_aux_lladdr.lladdr.addr.v6,mld2h->mc_addr);
		}
	}

  RHP_UNLOCK(&(v_ifc->lock));


  if( mld_rep_pkt ){

		rhp_tuntap_write(v_ifc,mld_rep_pkt);

		if( rhp_ip_multicast(AF_INET6,mld_rep_pkt->l3.iph_v6->dst_addr) ){

			mld_rep_pkt->rx_if_index = pkt->rx_if_index;
			mld_rep_pkt->rx_ifc = pkt->rx_ifc;
			if( mld_rep_pkt->rx_ifc ){
				rhp_ifc_hold(mld_rep_pkt->rx_ifc);
			}

			*mld_rep_pkt_r = mld_rep_pkt;
			mld_rep_pkt = NULL;

		}else{

			rhp_pkt_unhold(mld_rep_pkt);
		}
  }

  RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_RX_MLD_QUERY_FOR_TUNTAP_RTRN,"xxx",pkt,mld_rep_pkt,*mld_rep_pkt_r);
  return 0;

error:
 	RHP_UNLOCK(&(v_ifc->lock));
  if( mld_rep_pkt ){
		rhp_pkt_unhold(mld_rep_pkt);
  }

  RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_RX_MLD_QUERY_FOR_TUNTAP_ERR,"xE",pkt,err);
 	return err;
}

static int _rhp_bridge_handle_neigh_cache_for_tuntap(rhp_packet* pkt,
		u8 nd_icmp6_type,int* nd_req_ok_r,rhp_packet** ex_flood_pkt_r)
{
	int err = -EINVAL;
	rhp_bridge_neigh_cache *br_c_n_dst = NULL;
	rhp_ifc_entry* rx_v_ifc = pkt->rx_ifc;
	int side;
	rhp_packet* pkt_nd_reply = NULL;
	rhp_proto_ether* rx_v6_eth = NULL;
	rhp_proto_ip_v6* rx_v6_ip6h = NULL;
	rhp_proto_icmp6* rx_v6_icmp6h = NULL;
	int addr_family = AF_UNSPEC;
	u8* target_addr = NULL;
	u8 v6_llmac[6],v6_lladdr[16];


	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_TUNTAP,"xxddbx",pkt,nd_req_ok_r,rhp_gcfg_proxy_arp_cache,rhp_gcfg_proxy_ipv6_nd_cache,nd_icmp6_type,ex_flood_pkt_r);

	if( pkt->l2.raw == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( RHP_PROTO_ETHER_MULTICAST_SRC(pkt->l2.eth) ){  // Including Broadcast address
		RHP_TRC(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_TUNTAP_IGNORE_SRC_MAC_MULTICAST,"xM",pkt,pkt->l2.eth->src_addr);
		return 0;
	}

	if( pkt->l2.eth->protocol == RHP_PROTO_ETH_IPV6 &&
			nd_icmp6_type == RHP_PROTO_ICMP6_TYPE_MLD_LISTENER_QUERY ){

		*nd_req_ok_r = 0;

		err = _rhp_bridge_handle_rx_mld_query_for_tuntap(pkt,
						nd_icmp6_type,ex_flood_pkt_r);

		RHP_TRC(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_TUNTAP_HANDLE_RX_MLD_QUERY,"xE",pkt,err);
		return err;
	}


	if( pkt->l2.eth->protocol == RHP_PROTO_ETH_ARP ){

		rhp_proto_arp* arph;

		if( !rhp_gcfg_proxy_arp_cache ){
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_TUNTAP_ARP_DISABLED,"x",pkt);
			return 0;
		}

		arph = (rhp_proto_arp*)(pkt->l2.eth + 1);
		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_TUNTAP_ARP_PKT,"xp",pkt,sizeof(rhp_proto_arp),arph);

		*nd_req_ok_r = 0;

		// - Ignore ARP request to detect address collision...
		// - Ignore GARP request.

		{
			if( arph->operation != RHP_PROTO_ARP_OPR_REQUEST ){
				RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_TUNTAP_ARP_IGNORE_NOT_REQ,"xp",pkt,sizeof(rhp_proto_arp),arph);
				return 0;
			}

			if( arph->sender_ipv4 == 0 || arph->target_ipv4 == 0 ){
				RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_TUNTAP_ARP_IGNORE_SNDR_TGT_IP_ZERO,"x44",pkt,arph->sender_ipv4,arph->target_ipv4);
				return 0;
			}

			if( *((u32*)arph->sender_mac) == 0 && *((u16*)&(arph->sender_mac[4])) == 0 ){
				RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_TUNTAP_ARP_IGNORE_SENDER_SNDR_MAC_ZERO,"xM",pkt,arph->sender_mac);
				return 0;
			}

			if( arph->target_ipv4 == arph->sender_ipv4 ){
				RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_TUNTAP_ARP_IGNORE_SAME_SNDR_TGT_IP,"x44",pkt,arph->target_ipv4,arph->sender_ipv4);
				return 0;
			}

			if( *((u32*)arph->target_mac) != 0 || *((u16*)&(arph->target_mac[4])) != 0 ){
				RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_TUNTAP_ARP_IGNORE_TGT_MAC_ZERO,"xM",pkt,arph->target_mac);
				return 0;
			}
		}

		addr_family = AF_INET;
		target_addr = (u8*)&(arph->target_ipv4);


	}else if( pkt->l2.eth->protocol == RHP_PROTO_ETH_IPV6 &&
						nd_icmp6_type == RHP_PROTO_ICMP6_TYPE_NEIGHBOR_SOLICIT ){

		u8* src_mac = NULL;

		if( !rhp_gcfg_proxy_ipv6_nd_cache ){
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_TUNTAP_IPV6_ND_DISABLED,"x",pkt);
			return 0;
		}

		*nd_req_ok_r = 0;

		err = rhp_ipv6_icmp6_parse_rx_pkt(pkt,&rx_v6_eth,&rx_v6_ip6h,&rx_v6_icmp6h);
		if( err ){
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_TUNTAP_IPV6_ND_PARSE_ERR,"x",pkt);
			return 0;
		}

		if( rhp_ipv6_addr_null(rx_v6_ip6h->src_addr) ){ // Ignore a DAD packet.
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_TUNTAP_IPV6_ND_SRC_NULL,"x",pkt);
			return 0;
		}

		err = rhp_ipv6_nd_parse_solicit_pkt(pkt,
						rx_v6_eth,rx_v6_ip6h,rx_v6_icmp6h,&target_addr,NULL,&src_mac);
		if( err ){
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_TUNTAP_IPV6_ND_PARSE_SOL_ERR,"x",pkt);
			return 0;
		}

		addr_family = AF_INET6;

		if( target_addr == NULL || src_mac == NULL ){
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_TUNTAP_TGT_ADDRS_NULL,"x",pkt);
			return 0;
		}


	}else{

		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_TUNTAP_NOT_INTERESTED_ND,"x",pkt);
		return 0;
	}


	*nd_req_ok_r = 1;

	if( rx_v_ifc == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}


	RHP_LOCK(&(rx_v_ifc->lock));

  if( !_rhp_atomic_read(&(rx_v_ifc->is_active)) || rx_v_ifc->tuntap_fd < -1 ){
  	err = 0;
		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_TUNTAP_IGNORE_TUNTAP_NOT_ACTIVE,"x",pkt);
  	goto error;
  }

	RHP_LOCK(&rhp_bridge_lock);

	br_c_n_dst = _rhp_bridge_neigh_cache_get_by_tgt_ip(rx_v_ifc->tuntap_vpn_realm_id,
								addr_family,target_addr);

  if( br_c_n_dst ){

  	side = br_c_n_dst->side;

  	if( side == RHP_BRIDGE_SIDE_VPN ){

  		if( br_c_n_dst->static_cache || !br_c_n_dst->stale ){

  			if( addr_family == AF_INET ){

  				pkt_nd_reply = _rhp_arp_new_reply(pkt,br_c_n_dst->target_mac);

  			}else if( addr_family == AF_INET6 ){

  				// rx_v_ifc->lock is needed.
  				err = rhp_ipv6_v_ifc_lladdr_get(rx_v_ifc,v6_lladdr,v6_llmac);
  				if( !err ){

  					pkt_nd_reply = _rhp_nd_new_reply(
  													pkt,rx_v6_eth,rx_v6_ip6h,rx_v6_icmp6h,
  													target_addr,br_c_n_dst->target_mac,v6_lladdr,v6_llmac);
  				}
  			}

  			br_c_n_dst->last_used_cnt++;

  		}else{

  			//
  			// The end node requesting the ARP Req or ND-Solicitation may be
  			// resolving/probing the MAC address and Rockhopper will cache
  			// the resolved address again.
  			//

				if( !_rhp_bridge_neigh_cache_delete(br_c_n_dst) ){

					_rhp_bridge_free_neigh_cache(br_c_n_dst);
				}

				br_c_n_dst = NULL;
  		}

    	if( pkt_nd_reply ){

    		*nd_req_ok_r = 1;

  			if( addr_family == AF_INET ){
  				rhp_bridge_cache_statistics_tbl.arp.pxy_arp_reply++;
  			}else if( addr_family == AF_INET6 ){
  				rhp_bridge_cache_statistics_tbl.v6_neigh.pxy_nd_adv++;
  			}

    	}else{

    		*nd_req_ok_r = 0;
    	}

    }else{

    	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_TUNTAP_IGNORE_SIDE_NOT_VPN,"xx",pkt,br_c_n_dst);

			//
			// Rockhopper will cache the resolved address again.
			//

  		if( !br_c_n_dst->static_cache ){

				if( !_rhp_bridge_neigh_cache_delete(br_c_n_dst) ){

					_rhp_bridge_free_neigh_cache(br_c_n_dst);
				}

				br_c_n_dst = NULL;
      }

    	*nd_req_ok_r = 0;
    }

  }else{

		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_TUNTAP_IGNORE_NO_ARP_CACHE,"xd",pkt,rx_v_ifc->ipip_dummy_mac_flag);

		if( rx_v_ifc->ipip_dummy_mac_flag ){

			if( addr_family == AF_INET ){

				pkt_nd_reply = _rhp_arp_new_reply(pkt,rx_v_ifc->ipip_dummy_mac);

			}else if( addr_family == AF_INET6 ){

				// rx_v_ifc->lock is needed.
				err = rhp_ipv6_v_ifc_lladdr_get(rx_v_ifc,v6_lladdr,v6_llmac);
				if( !err ){

					pkt_nd_reply = _rhp_nd_new_reply(
													pkt,rx_v6_eth,rx_v6_ip6h,rx_v6_icmp6h,
													target_addr,rx_v_ifc->ipip_dummy_mac,v6_lladdr,v6_llmac);
				}
			}

		}else{

	  	unsigned long nhrp_peer_rlm_id;
	  	rhp_ip_addr nhrp_peer_nbma_addr;
	  	u8 nhrp_peer_dmy_mac[6] = {0,0,0,0,0,0};

			err = rhp_nhrp_cache_get(addr_family,target_addr,rx_v_ifc->tuntap_vpn_realm_id,
							&nhrp_peer_rlm_id,&nhrp_peer_nbma_addr,nhrp_peer_dmy_mac);

			if( !err &&
					rx_v_ifc->tuntap_vpn_realm_id == nhrp_peer_rlm_id &&
					!_rhp_mac_addr_null(nhrp_peer_dmy_mac) ){

				if( addr_family == AF_INET ){

					pkt_nd_reply = _rhp_arp_new_reply(pkt,nhrp_peer_dmy_mac);

				}else if( addr_family == AF_INET6 ){

					// rx_v_ifc->lock is needed.
					err = rhp_ipv6_v_ifc_lladdr_get(rx_v_ifc,v6_lladdr,v6_llmac);
					if( !err ){

						pkt_nd_reply = _rhp_nd_new_reply(
														pkt,rx_v6_eth,rx_v6_ip6h,rx_v6_icmp6h,
														target_addr,nhrp_peer_dmy_mac,v6_lladdr,v6_llmac);
					}
				}
			}
		}

  	if( pkt_nd_reply ){

  		*nd_req_ok_r = 1;

			if( addr_family == AF_INET ){
				rhp_bridge_cache_statistics_tbl.arp.pxy_arp_reply++;
			}else if( addr_family == AF_INET6 ){
				rhp_bridge_cache_statistics_tbl.v6_neigh.pxy_nd_adv++;
			}

  	}else{

  		*nd_req_ok_r = 0;
  	}
  }

  RHP_UNLOCK(&rhp_bridge_lock);

  RHP_UNLOCK(&(rx_v_ifc->lock));


  //
  // [CAUTION]
  //
  // br_c_n_dst may be NULL. Don't touch anymore.
  //


  if( pkt_nd_reply ){

		rhp_tuntap_write(rx_v_ifc,pkt_nd_reply);

		if( addr_family == AF_INET6 &&
				rhp_ip_multicast(AF_INET6,pkt_nd_reply->l3.iph_v6->dst_addr) ){

			pkt_nd_reply->rx_if_index = pkt->rx_if_index;
			pkt_nd_reply->rx_ifc = pkt->rx_ifc;
			if( pkt_nd_reply->rx_ifc ){
				rhp_ifc_hold(pkt_nd_reply->rx_ifc);
			}

			*ex_flood_pkt_r = pkt_nd_reply;
			pkt_nd_reply = NULL;

		}else{

			rhp_pkt_unhold(pkt_nd_reply);
		}
  }

  RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_TUNTAP_RTRN,"xdxx",pkt,*nd_req_ok_r,pkt_nd_reply,*ex_flood_pkt_r);
  return 0;

error:
 	RHP_UNLOCK(&(rx_v_ifc->lock));
  if( pkt_nd_reply ){
		rhp_pkt_unhold(pkt_nd_reply);
  }

  RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_TUNTAP_ERR,"xE",pkt,err);
 	return err;
}

static int _rhp_bridge_handle_rx_mld_query_for_vpn(rhp_packet* pkt,
		unsigned long vpn_realm_id,rhp_vpn* tx_vpn,u8 nd_icmp6_type,
		rhp_packet** mld_rep_pkt_r)
{
	int err = -EINVAL;
	int pld_len;
	rhp_packet* mld_rep_pkt = NULL;
	rhp_proto_ether* eth = NULL;
	rhp_proto_ip_v6* ip6h = NULL;
	rhp_proto_icmp6* icmp6h = NULL;
	rhp_ifc_entry* v_ifc = NULL;

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_RX_MLD_QUERY_FOR_VPN,"xuxb",pkt,vpn_realm_id,tx_vpn,nd_icmp6_type);


	if( pkt->l2.raw == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( RHP_PROTO_ETHER_MULTICAST_SRC(pkt->l2.eth) ){  // Including Broadcast address
		RHP_TRC(0,RHPTRCID_BRIDGE_HANDLE_RX_MLD_QUERY_FOR_VPN_IGNORE_SRC_MAC_MULTICAST,"xM",pkt,pkt->l2.eth->src_addr);
		return 0;
	}

	if( pkt->l2.eth->protocol != RHP_PROTO_ETH_IPV6 ||
			nd_icmp6_type != RHP_PROTO_ICMP6_TYPE_MLD_LISTENER_QUERY ){
		RHP_TRC(0,RHPTRCID_BRIDGE_HANDLE_RX_MLD_QUERY_FOR_VPN_IGNORE_NOT_INTERESTED,"x",pkt);
		return 0;
	}


	err = rhp_ipv6_icmp6_parse_rx_pkt(pkt,&eth,&ip6h,&icmp6h);
	if( err ){
		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_RX_MLD_QUERY_FOR_VPN_PARSE_ICMP6_ERR,"xE",pkt,err);
		return 0;
	}


	RHP_LOCK(&(tx_vpn->lock));

	if( tx_vpn->rlm == NULL ){

		RHP_UNLOCK(&(tx_vpn->lock));
		err = 0;

		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_RX_MLD_QUERY_FOR_VPN_NO_TX_VPN,"xux",pkt,vpn_realm_id,tx_vpn);
		goto error;
	}

	RHP_LOCK(&(tx_vpn->rlm->lock));
	{
		v_ifc = tx_vpn->rlm->internal_ifc->ifc;
		if( v_ifc ){

			rhp_ifc_hold(v_ifc);
		}
	}
	RHP_UNLOCK(&(tx_vpn->rlm->lock));

	RHP_UNLOCK(&(tx_vpn->lock));


	if( v_ifc == NULL ){
		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_RX_MLD_QUERY_FOR_VPN_NO_V_IFC,"xux",pkt,vpn_realm_id,tx_vpn);
		goto error;
	}


	RHP_LOCK(&(v_ifc->lock));

	if( !_rhp_atomic_read(&(v_ifc->is_active)) || v_ifc->tuntap_fd < -1 ){
		RHP_UNLOCK(&(v_ifc->lock));
		err = 0;
		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_RX_MLD_QUERY_FOR_TUNTAP_IGNORE_TUNTAP_NOT_ACTIVE,"x",pkt);
		goto error;
	}

	if( v_ifc->v6_aux_lladdr.state != RHP_V6_LINK_LOCAL_ADDR_AVAILABLE ){
		RHP_UNLOCK(&(v_ifc->lock));
		err = 0;
		goto error;
	}

	pld_len = ntohs(ip6h->payload_len);

	if( pld_len == (int)sizeof(rhp_proto_icmp6_mld1_query) ){

		rhp_proto_icmp6_mld1_query* mld1h = (rhp_proto_icmp6_mld1_query*)icmp6h;

		if( rhp_ipv6_addr_null(mld1h->mc_addr) ||
				rhp_ipv6_is_same_addr(mld1h->mc_addr,v_ifc->v6_aux_lladdr.lladdr_sol_node_mc) ){

			mld_rep_pkt = rhp_ipv6_new_mld1_report(v_ifc->v6_aux_lladdr.mac,
											v_ifc->v6_aux_lladdr.lladdr.addr.v6,mld1h->mc_addr);
		}

	}else if( pld_len >= (int)sizeof(rhp_proto_icmp6_mld2_query) ){

		rhp_proto_icmp6_mld2_query* mld2h = (rhp_proto_icmp6_mld2_query*)icmp6h;

		if( rhp_ipv6_addr_null(mld2h->mc_addr) ||
				rhp_ipv6_is_same_addr(mld2h->mc_addr,v_ifc->v6_aux_lladdr.lladdr_sol_node_mc) ){

			mld_rep_pkt = rhp_ipv6_new_mld2_report(v_ifc->v6_aux_lladdr.mac,
											v_ifc->v6_aux_lladdr.lladdr.addr.v6,mld2h->mc_addr);
		}
	}

	RHP_UNLOCK(&(v_ifc->lock));



	if( mld_rep_pkt ){


		rhp_encap_send(tx_vpn,mld_rep_pkt);


		if( rhp_ip_multicast(AF_INET6,mld_rep_pkt->l3.iph_v6->dst_addr) ){

			mld_rep_pkt->rx_if_index = pkt->rx_if_index;
			mld_rep_pkt->rx_ifc = pkt->rx_ifc;
			if( mld_rep_pkt->rx_ifc ){
				rhp_ifc_hold(mld_rep_pkt->rx_ifc);
			}

			*mld_rep_pkt_r = mld_rep_pkt;
			mld_rep_pkt = NULL;
		}
  }

error:
	if( v_ifc ){
		rhp_ifc_unhold(v_ifc);
	}

	if( mld_rep_pkt ){
		rhp_pkt_unhold(mld_rep_pkt);
	}

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_RX_MLD_QUERY_FOR_VPN_RTRN,"xxx",pkt,mld_rep_pkt,*mld_rep_pkt_r);
  return 0;
}

// Caller DON'T acquire tx_vpn->lock.
static int _rhp_bridge_handle_neigh_cache_for_vpn(rhp_packet* pkt,
		unsigned long vpn_realm_id,rhp_vpn* tx_vpn,u8 nd_icmp6_type,
		int* nd_req_ok_r,rhp_packet** ex_flood_pkt_r)
{
	int err = -EINVAL;
	rhp_bridge_neigh_cache *br_c_n_dst = NULL;
	int side;
	rhp_packet* pkt_nd_reply = NULL;
	rhp_proto_ether* rx_v6_eth = NULL;
	rhp_proto_ip_v6* rx_v6_ip6h = NULL;
	rhp_proto_icmp6* rx_v6_icmp6h = NULL;
	int addr_family = AF_UNSPEC;
	u8* target_addr = NULL;
	u8 v6_llmac[6],v6_lladdr[16];

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_VPN,"xuxxbdd",pkt,vpn_realm_id,tx_vpn,nd_req_ok_r,nd_icmp6_type,rhp_gcfg_proxy_arp_cache,rhp_gcfg_proxy_ipv6_nd_cache);


	if( pkt->l2.raw == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( RHP_PROTO_ETHER_MULTICAST_SRC(pkt->l2.eth) ){  // Including Broadcast address
		RHP_TRC(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_VPN_IGNORE_SRC_MAC_MULTICAST,"xM",pkt,pkt->l2.eth->src_addr);
		return 0;
	}


	if( pkt->l2.eth->protocol == RHP_PROTO_ETH_IPV6 &&
			nd_icmp6_type == RHP_PROTO_ICMP6_TYPE_MLD_LISTENER_QUERY ){

		*nd_req_ok_r = 0;

		err = _rhp_bridge_handle_rx_mld_query_for_vpn(pkt,vpn_realm_id,
							tx_vpn,nd_icmp6_type,ex_flood_pkt_r);

		RHP_TRC(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_VPN_HANDLE_RX_MLD_QUERY,"xE",pkt,err);
		return err;


	}else if( pkt->l2.eth->protocol == RHP_PROTO_ETH_ARP ){

		rhp_proto_arp* arph;

		if( !rhp_gcfg_proxy_arp_cache ){
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_VPN_ARP_DISABLED,"xux",pkt,vpn_realm_id,tx_vpn);
			return 0;
		}

		arph = (rhp_proto_arp*)(pkt->l2.eth + 1);
		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_VPN_ARP_PKT,"xp",pkt,sizeof(rhp_proto_arp),arph);

		*nd_req_ok_r = 0;


		// - Ignore ARP request to detect address collision...
		// - Ignore GARP request.

		if( arph->operation != RHP_PROTO_ARP_OPR_REQUEST ){
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_VPN_IGNORE_ARP_NOT_REQ,"xp",pkt,sizeof(rhp_proto_arp),arph);
			return 0;
		}

		if( arph->sender_ipv4 == 0 || arph->target_ipv4 == 0 ){
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_VPN_IGNORE_ARP_SNDR_TGT_IP_ZERO,"x44",pkt,arph->sender_ipv4,arph->target_ipv4);
			return 0;
		}

		if( *((u32*)arph->sender_mac) == 0 && *((u16*)&(arph->sender_mac[4])) == 0 ){
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_VPN_IGNORE_ARP_SENDER_SNDR_MAC_ZERO,"xM",pkt,arph->sender_mac);
			return 0;
		}

		if( arph->target_ipv4 == arph->sender_ipv4 ){
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_VPN_IGNORE_ARP_SAME_SNDR_TGT_IP,"x44",pkt,arph->target_ipv4,arph->sender_ipv4);
			return 0;
		}

		if( *((u32*)arph->target_mac) != 0 || *((u16*)&(arph->target_mac[4])) != 0 ){
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_VPN_IGNORE_ARP_TGT_MAC_ZERO,"xM",pkt,arph->target_mac);
			return 0;
		}

		addr_family = AF_INET;
		target_addr = (u8*)&(arph->target_ipv4);


	}else if( pkt->l2.eth->protocol == RHP_PROTO_ETH_IPV6 &&
						nd_icmp6_type == RHP_PROTO_ICMP6_TYPE_NEIGHBOR_SOLICIT ){

		u8* src_mac = NULL;

		if( !rhp_gcfg_proxy_ipv6_nd_cache ){
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_VPN_ND_DISABLED,"xux",pkt,vpn_realm_id,tx_vpn);
			return 0;
		}

		*nd_req_ok_r = 0;


		err = rhp_ipv6_icmp6_parse_rx_pkt(pkt,&rx_v6_eth,&rx_v6_ip6h,&rx_v6_icmp6h);
		if( err ){
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_VPN_ND_PARSE_ERR,"xux",pkt,vpn_realm_id,tx_vpn);
			return 0;
		}

		if( rhp_ipv6_addr_null(rx_v6_ip6h->src_addr) ){ // Ignore a DAD packet.
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_VPN_ND_SRC_NULL,"xux",pkt,vpn_realm_id,tx_vpn);
			return 0;
		}

		err = rhp_ipv6_nd_parse_solicit_pkt(pkt,
						rx_v6_eth,rx_v6_ip6h,rx_v6_icmp6h,&target_addr,NULL,&src_mac);
		if( err ){
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_VPN_ND_PARSE_SOL_ERR,"xux",pkt,vpn_realm_id,tx_vpn);
			return 0;
		}

		addr_family = AF_INET6;

		if( target_addr == NULL || src_mac == NULL ){
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_VPN_TGT_ADDRS_NULL,"x",pkt);
			return 0;
		}

		RHP_LOCK(&(tx_vpn->lock));
		{

			if( tx_vpn->rlm == NULL ){

				RHP_UNLOCK(&(tx_vpn->lock));

				RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_VPN_ND_NO_TX_VPN,"xux",pkt,vpn_realm_id,tx_vpn);
				return 0;
			}

			// Don't acquire rlm->lock and v_ifc->lock.
			err = rhp_ipv6_rlm_lladdr_get(tx_vpn->rlm,v6_lladdr,v6_llmac);
			if( err ){

				RHP_UNLOCK(&(tx_vpn->lock));

				RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_VPN_ND_NO_LLADDR,"xux",pkt,vpn_realm_id,tx_vpn);
				return 0;
			}
		}
		RHP_UNLOCK(&(tx_vpn->lock));

	}else{

		*nd_req_ok_r = 0;

		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_VPN_ND_NOT_INTERESTED,"xux",pkt,vpn_realm_id,tx_vpn);
		return 0;
	}


	*nd_req_ok_r = 1;


	RHP_LOCK(&rhp_bridge_lock);

	br_c_n_dst = _rhp_bridge_neigh_cache_get_by_tgt_ip(vpn_realm_id,
								addr_family,target_addr);

  if( br_c_n_dst ){

  	side = br_c_n_dst->side;

  	if( side == RHP_BRIDGE_SIDE_VPN ){

  		if( br_c_n_dst->static_cache || !br_c_n_dst->stale ){

  			if( addr_family == AF_INET ){

  				pkt_nd_reply = _rhp_arp_new_reply(pkt,br_c_n_dst->target_mac);

  			}else if( addr_family == AF_INET6 ){

					pkt_nd_reply = _rhp_nd_new_reply(
													pkt,rx_v6_eth,rx_v6_ip6h,rx_v6_icmp6h,
													target_addr,br_c_n_dst->target_mac,v6_lladdr,v6_llmac);
  			}

  			br_c_n_dst->last_used_cnt++;

  		}else{

  			//
  			// The end node requesting the ARP Req or ND-Solicitation may
  			// be probing the MAC address and Rockhopper will cache the
  			// resolved address again.
  			//

  			if( !_rhp_bridge_neigh_cache_delete(br_c_n_dst) ){

					_rhp_bridge_free_neigh_cache(br_c_n_dst);
				}

  			br_c_n_dst = NULL;
  		}

  		if( pkt_nd_reply ){
    		*nd_req_ok_r = 1;
    	}else{
    		*nd_req_ok_r = 0;
    	}

    }else{

    	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_VPN_IGNORE_SIDE_NOT_VPN,"xdx",pkt,side,br_c_n_dst);

    	//
			// Rockhopper will cache the resolved address again.
			//

    	if( !br_c_n_dst->static_cache ){

    		if( !_rhp_bridge_neigh_cache_delete(br_c_n_dst) ){

					_rhp_bridge_free_neigh_cache(br_c_n_dst);
				}

  			br_c_n_dst = NULL;
  		}

    	*nd_req_ok_r = 0;
    }

  }else{

		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_VPN_IGNORE_NO_ARP_CACHE,"x",pkt);

  	*nd_req_ok_r = 0;
  }

  RHP_UNLOCK(&rhp_bridge_lock);


  //
  // [CAUTION]
  //
  // br_c_n_dst may be NULL. Don't touch anymore.
  //


	if( pkt_nd_reply ){


		rhp_encap_send(tx_vpn,pkt_nd_reply);


		if( addr_family == AF_INET6 &&
				rhp_ip_multicast(AF_INET6,pkt_nd_reply->l3.iph_v6->dst_addr) ){

			pkt_nd_reply->rx_if_index = pkt->rx_if_index;
			pkt_nd_reply->rx_ifc = pkt->rx_ifc;
			if( pkt_nd_reply->rx_ifc ){
				rhp_ifc_hold(pkt_nd_reply->rx_ifc);
			}

			*ex_flood_pkt_r = pkt_nd_reply;
			pkt_nd_reply = NULL;

		}else{

			rhp_pkt_unhold(pkt_nd_reply);
		}
  }

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_HANDLE_NEIGH_CACHE_FOR_VPN_RTRN,"xdxx",pkt,*nd_req_ok_r,pkt_nd_reply,*ex_flood_pkt_r);
  return 0;
}

static int _rhp_bridge_flood_pkt_to_vpn(rhp_packet* pkt,
		unsigned long rlm_id,rhp_vpn_realm* tx_rlm,rhp_ifc_entry* rx_v_ifc,
		int is_access_point,int is_mesh_node, int peer_is_access_point,
		int to_v6_lladdr,int dont_fwd_pkts_btwn_conns,int dont_fwd_pkts_btwn_clts)
{
	int tx_err;

	if( to_v6_lladdr ){

		rhp_packet* pkt_d = rhp_pkt_dup(pkt);

		if( pkt_d ){

			pkt_d->rx_if_index = pkt->rx_if_index;
			pkt_d->rx_ifc = pkt->rx_ifc;
			if( pkt_d->rx_ifc ){
				rhp_ifc_hold(pkt_d->rx_ifc);
			}

			rhp_ipv6_rlm_lladdr_rx(rx_v_ifc,pkt_d);
			rhp_pkt_unhold(pkt_d);

		}else{
			RHP_BUG("");
		}
	}

	if( !dont_fwd_pkts_btwn_conns &&
			(is_access_point ||
			 is_mesh_node ||
			 (rhp_gcfg_flood_pkts_if_no_accesspoint_exists && !peer_is_access_point)) ){

		tx_err = rhp_eoip_send_flooding(rlm_id,pkt,NULL,dont_fwd_pkts_btwn_clts);
		if( tx_err == RHP_STATUS_NO_ETHERIP_ENCAP ){

			tx_err = rhp_ip_bridge_send_flooding(rlm_id,pkt,NULL,dont_fwd_pkts_btwn_clts);
			if( tx_err == RHP_STATUS_NO_IPIP_ENCAP ){

				rhp_gre_send_flooding(rlm_id,pkt,NULL,dont_fwd_pkts_btwn_clts);
			}
		}
		tx_err = 0;

	}else{

		tx_err = rhp_eoip_send_access_point(tx_rlm,pkt);
		if( tx_err == RHP_STATUS_NO_ETHERIP_ENCAP ){

			tx_err = rhp_ip_bridge_send_access_point(tx_rlm,pkt);
			if( tx_err == RHP_STATUS_NO_IPIP_ENCAP ){

				rhp_gre_send_access_point(tx_rlm,pkt);
			}
		}
		tx_err = 0;
	}

	return 0;
}

int rhp_bridge_pkt_to_vpn(rhp_packet* pkt)
{
	int err = -EINVAL;
	rhp_ifc_entry* rx_v_ifc = pkt->rx_ifc;
	rhp_vpn* tx_vpn = NULL;
	rhp_vpn_ref* tx_vpn_ref = NULL;
	int flooding = 0;
	int neigh_req_ok = 0;
	int is_access_point = 0;
	int is_mesh_node = 0;
	int peer_is_access_point = 0;
	rhp_vpn_realm* tx_rlm = NULL;
	int to_v6_lladdr = 0;
	u8 nd_icmp6_type;
	rhp_packet* ex_flood_pkt = NULL;
	int dont_fwd_pkts_btwn_conns = 0, dont_fwd_pkts_btwn_clts = 0;
	int tx_err;

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_TO_VPN,"xx",pkt,rx_v_ifc);

	if( rx_v_ifc == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_TO_VPN_IFNAME,"xxs",pkt,rx_v_ifc,rx_v_ifc->if_name);

	if( pkt->l2.raw == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( RHP_PROTO_ETHER_MULTICAST_SRC(pkt->l2.eth) ){ // Including Broadcast address
		err = 0;
		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_TO_VPN_IGNORE_INVALID_PKT_SRC_BROADCAST,"xM",pkt,pkt->l2.eth->src_addr);
		goto error;
	}

	if( RHP_PROTO_ETHER_MULTICAST_DST(pkt->l2.eth) ){  // Including Broadcast address

		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_TO_VPN_FLOODING_DST_MULTICAST,"xM",pkt,pkt->l2.eth->dst_addr);

		flooding = 2;

		if( pkt->l2.eth->protocol == RHP_PROTO_ETH_IPV6 ){
			to_v6_lladdr = 1;
		}
	}


  if( !flooding && pkt->dmvpn_enabled ){

  	// DMVPN

		//
		// pkt->l3.ipv4/6 alignment is already verified
		// by _rhp_tuntap_read().
		//

  	//
  	// If a shortcut path btwn spoke nodes exists, this pkt
  	// is re-routed here.
  	//

		if( pkt->l2.eth->protocol == RHP_PROTO_ETH_IP ){

			//
			// [CAUTION]
			// This may internally acquire tx_vpn->lock.
			//
			rhp_ip_routing_nhrp_v4(pkt->l3.iph_v4->src_addr,pkt->l3.iph_v4->dst_addr,
							rx_v_ifc->tuntap_vpn_realm_id,&tx_vpn_ref);

		}else if( pkt->l2.eth->protocol == RHP_PROTO_ETH_IPV6 ){

			// rx_v_ifc->v6_aux_lladdr.mac is immutable.
			if( memcmp(pkt->l2.eth->dst_addr,rx_v_ifc->v6_aux_lladdr.mac,6)){

				//
				// [CAUTION]
				// This may internally acquire tx_vpn->lock.
				//
				rhp_ip_routing_nhrp_v6(pkt->l3.iph_v6->src_addr,pkt->l3.iph_v6->dst_addr,
								rx_v_ifc->tuntap_vpn_realm_id,&tx_vpn_ref);

			}else{

				// RHP_BRIDGE_SCACHE_V6_DUMMY_LL_ADDR is skipped.
			}
		}

		if( tx_vpn_ref ){

			tx_vpn = RHP_VPN_REF(tx_vpn_ref);

			// tx_vpn->internal_net_info.dummy_peer_mac is immutable.
			memcpy(pkt->l2.eth->dst_addr,tx_vpn->internal_net_info.dummy_peer_mac,6);

		}else{

			//
			// This pkt will be sent to a remote peer via a Hub gw.
			// pkt->l2.eth->dst_addr is destinated to the gw by kernel's IP protocol stack.
			//
		}
	}


	RHP_LOCK(&(rx_v_ifc->lock));

	rx_v_ifc->statistics.tuntap.bridge_rx_from_tuntap++;

  if( !_rhp_atomic_read(&(rx_v_ifc->is_active)) ){
  	err = 0;
		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_TO_VPN_VIF_NOT_ACTIVE,"xx",pkt,rx_v_ifc);
  	goto error_l;
  }

  if( rx_v_ifc->tuntap_fd < -1 ){
  	err = 0;
		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_TO_VPN_IGNORE_TUNTAP_NOT_ACTIVE,"xx",pkt,rx_v_ifc);
  	goto error_l;
  }


  if( !flooding && tx_vpn_ref == NULL ){

  	rhp_bridge_cache *br_c_dst = NULL;

		RHP_LOCK(&rhp_bridge_lock);

		br_c_dst = _rhp_bridge_cache_get(rx_v_ifc->tuntap_vpn_realm_id,pkt->l2.eth->dst_addr);
		if( br_c_dst ){

			if( br_c_dst->static_cache == RHP_BRIDGE_SCACHE_V6_DUMMY_LL_ADDR ){

				to_v6_lladdr = 1;

			}else{

				if( br_c_dst->side != RHP_BRIDGE_SIDE_VPN ){

					RHP_UNLOCK(&rhp_bridge_lock);

					err = 0;
					RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_TO_VPN_INVALID_BRDG_CACHE_SIDE,"xxxd",pkt,rx_v_ifc,br_c_dst,br_c_dst->side);
					goto error_l;
				}

				tx_vpn = RHP_VPN_REF(br_c_dst->vpn_ref);
				if( tx_vpn == NULL ){

					RHP_UNLOCK(&rhp_bridge_lock);

					err = 0;

					rhp_esp_g_statistics_inc(tx_esp_no_childsa_err_packets);

					RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_TO_VPN_NO_TX_VPN,"xxxd",pkt,rx_v_ifc,br_c_dst,br_c_dst->side);
					goto error_l;
				}

				tx_vpn_ref = rhp_vpn_hold_ref(tx_vpn);
			}

			br_c_dst->last_used_cnt++;

		}else{

			flooding = 1;
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_TO_VPN_FLOODING_NO_BRDG_CACHE,"x",pkt);
		}

		RHP_UNLOCK(&rhp_bridge_lock);
	}

  _rhp_bridge_cache_update_to_vpn(pkt,rx_v_ifc);

	RHP_UNLOCK(&(rx_v_ifc->lock));


	if( pkt->l2.eth->protocol == RHP_PROTO_ETH_ARP ||
			(!rhp_gcfg_ipv6_disabled && rhp_ipv6_is_nd_packet(pkt,&nd_icmp6_type)) ){

		err = _rhp_bridge_handle_neigh_cache_for_tuntap(pkt,
						nd_icmp6_type,&neigh_req_ok,&ex_flood_pkt);

		if( err ){
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_TO_VPN_FAIL_TO_HANDLE_ND_CACHE_FOR_TUNTAP,"xE",pkt,err);
			goto error;
		}
	}


	if( flooding || ex_flood_pkt ){

		tx_rlm = rhp_realm_get(rx_v_ifc->tuntap_vpn_realm_id);
		if( tx_rlm == NULL ){
			RHP_BUG("%d",rx_v_ifc->tuntap_vpn_realm_id);
			goto error;
		}

		RHP_LOCK(&(tx_rlm->lock));

  	if( !_rhp_atomic_read(&(tx_rlm->is_active)) ){
  		RHP_UNLOCK(&(tx_rlm->lock));
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_TO_VPN_TX_RLM_NOT_ACTIVE,"xxx",pkt,tx_vpn,tx_rlm);
  		goto error;
  	}

  	is_access_point = tx_rlm->is_access_point;

  	is_mesh_node = tx_rlm->is_mesh_node;

  	if( flooding != 2 ){

  		dont_fwd_pkts_btwn_conns = tx_rlm->childsa.dont_fwd_pkts_between_vpn_conns;

    	if( !dont_fwd_pkts_btwn_conns ){

				dont_fwd_pkts_btwn_clts = tx_rlm->config_server.dont_fwd_pkts_between_clients;
				if( dont_fwd_pkts_btwn_clts &&
						tx_rlm->config_server.dont_fwd_pkts_between_clients_except_v6_auto &&
						rhp_esp_is_v6_linklocal_icmp_pkt(pkt) ){

					dont_fwd_pkts_btwn_clts = 0;
				}
    	}
  	}

		if( tx_rlm->access_point_peer_vpn_ref ){
			peer_is_access_point = 1;
		}

		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_TO_VPN_TX_RLM,"xxuddddd",pkt,tx_rlm,tx_rlm->id,is_access_point,peer_is_access_point,is_mesh_node,dont_fwd_pkts_btwn_conns,dont_fwd_pkts_btwn_clts);

		tx_rlm->statistics.bridge.tx_to_vpn_flooding_pkts++;

		RHP_LOCK(&rhp_bridge_lock);
		{
			rhp_bridge_cache_statistics_tbl.bridge.tx_to_vpn_flooding_pkts++;
		}
	  RHP_UNLOCK(&rhp_bridge_lock);

		RHP_UNLOCK(&(tx_rlm->lock));
	}


	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_TO_VPN_NEIGH_CACHE,"xdddWd",pkt,rhp_gcfg_proxy_arp_cache,rhp_gcfg_proxy_ipv6_nd_cache,is_access_point,pkt->l2.eth->protocol,pkt->len);
	rhp_pkt_trace_dump("rhp_bridge_pkt_to_vpn.neigh",pkt);


	if( ex_flood_pkt ){

		tx_err = _rhp_bridge_flood_pkt_to_vpn(ex_flood_pkt,
							rx_v_ifc->tuntap_vpn_realm_id,tx_rlm,rx_v_ifc,
							is_access_point,is_mesh_node,peer_is_access_point,0,0,0);

		if( tx_err ){
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_TO_VPN_FLOOD_PKT_ERR,"xE",pkt,tx_err);
		}
	}


	if( !neigh_req_ok ){

		if( flooding ){

			tx_err = _rhp_bridge_flood_pkt_to_vpn(pkt,
								rx_v_ifc->tuntap_vpn_realm_id,tx_rlm,rx_v_ifc,
								is_access_point,is_mesh_node,peer_is_access_point,to_v6_lladdr,
								dont_fwd_pkts_btwn_conns,dont_fwd_pkts_btwn_clts);

			if( tx_err ){
				RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_TO_VPN_FLOOD_PKT_ERR,"xE",pkt,tx_err);
			}

		}else{

			if( to_v6_lladdr ){

				rhp_ipv6_rlm_lladdr_rx(rx_v_ifc,pkt);
				tx_err = 0;

			}else{

				rhp_encap_send(tx_vpn,pkt);
			}
		}
	}

	if( tx_vpn_ref ){
		rhp_vpn_unhold(tx_vpn_ref);
	}

	if( tx_rlm ){
    rhp_realm_unhold(tx_rlm);
	}

	if( ex_flood_pkt ){
		rhp_pkt_unhold(ex_flood_pkt);
	}

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_TO_VPN_RTRN,"xx",pkt,ex_flood_pkt);
	return 0;

error_l:
	RHP_UNLOCK(&(rx_v_ifc->lock));
error:
	if( tx_vpn_ref ){
		rhp_vpn_unhold(tx_vpn_ref);
	}
	if( tx_rlm ){
    rhp_realm_unhold(tx_rlm);
	}
	if( ex_flood_pkt ){
		rhp_pkt_unhold(ex_flood_pkt);
	}

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_TO_VPN_ERR,"xxE",pkt,ex_flood_pkt,err);
	return err;
}

static int _rhp_bridge_flood_pkt_from_vpn(rhp_packet* pkt,
		rhp_vpn* rx_vpn,unsigned long rlm_id,rhp_ifc_entry* tx_v_ifc,
		int is_access_point,int to_v6_lladdr,
		int dont_fwd_pkts_btwn_conns,int dont_fwd_pkts_btwn_clts)
{
	int tx_err;
	rhp_packet* pkt_d = rhp_pkt_dup(pkt);

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_FLOOD_PKT_FROM_VPN,"xxuxddddx",pkt,rx_vpn,rlm_id,tx_v_ifc,is_access_point,to_v6_lladdr,dont_fwd_pkts_btwn_conns,dont_fwd_pkts_btwn_clts,pkt_d);

	if( pkt_d ){

		pkt_d->rx_if_index = pkt->rx_if_index;
		pkt_d->rx_ifc = pkt->rx_ifc;
		if( pkt_d->rx_ifc ){
			rhp_ifc_hold(pkt_d->rx_ifc);
		}

		rhp_tuntap_write(tx_v_ifc,pkt_d);
		rhp_pkt_unhold(pkt_d);

	}else{
		RHP_BUG("");
	}

	if( to_v6_lladdr ){

		pkt_d = rhp_pkt_dup(pkt);

		if( pkt_d ){

			pkt_d->rx_if_index = pkt->rx_if_index;
			pkt_d->rx_ifc = pkt->rx_ifc;
			if( pkt_d->rx_ifc ){
				rhp_ifc_hold(pkt_d->rx_ifc);
			}

			rhp_ipv6_rlm_lladdr_rx(tx_v_ifc,pkt_d);
			rhp_pkt_unhold(pkt_d);

		}else{
			RHP_BUG("");
		}
	}

	if( !dont_fwd_pkts_btwn_conns && is_access_point ){

		tx_err = rhp_eoip_send_flooding(rlm_id,pkt,rx_vpn,dont_fwd_pkts_btwn_clts);
		if( tx_err == RHP_STATUS_NO_ETHERIP_ENCAP ){

			tx_err = rhp_ip_bridge_send_flooding(rlm_id,pkt,rx_vpn,dont_fwd_pkts_btwn_clts);
			if( tx_err == RHP_STATUS_NO_IPIP_ENCAP ){

				rhp_gre_send_flooding(rlm_id,pkt,rx_vpn,dont_fwd_pkts_btwn_clts);
			}
		}

		tx_err = 0;
	}

	return 0;
}

int rhp_bridge_pkt_from_vpn(rhp_packet* pkt,rhp_vpn* rx_vpn)
{
	int err = -EINVAL;
	rhp_bridge_cache *br_c_dst = NULL;
	int side = RHP_BRIDGE_SIDE_VPN;
	rhp_vpn_ref* tx_vpn_ref = NULL;
	rhp_vpn* tx_vpn = NULL;
  rhp_vpn_realm* rlm = NULL;
  unsigned long rlm_id;
	int flooding = 0;
	int neigh_req_ok = 0;
	rhp_ifc_entry* tx_v_ifc = NULL;
	int is_access_point = 0;
	int to_local = 0, to_v6_lladdr = 0;
	u8 nd_icmp6_type;
	rhp_packet* ex_flood_pkt = NULL;
	int dont_fwd_pkts_btwn_conns = 0, dont_fwd_pkts_btwn_clts = 0;
	int tx_err;

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN,"xxx",pkt,rx_vpn,pkt->rx_ifc);

	if( pkt->rx_ifc == NULL || rx_vpn == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_RX_IFNAME,"xxxs",pkt,rx_vpn,pkt->rx_ifc,pkt->rx_ifc->if_name);

	if( pkt->l2.raw == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( RHP_PROTO_ETHER_MULTICAST_SRC(pkt->l2.eth) ){ // Including Broadcast address
		err = 0;
		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IGNORE_1,"xM",pkt,pkt->l2.eth->src_addr);
		goto error;
	}

	if( RHP_PROTO_ETHER_MULTICAST_DST(pkt->l2.eth) ){  // Including Broadcast address

		flooding = 1;

		if( pkt->l2.eth->protocol == RHP_PROTO_ETH_IPV6 ){
			to_v6_lladdr = 1;
		}

		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_FLOODING_1,"xM",pkt,pkt->l2.eth->dst_addr);
	}

	RHP_LOCK(&(rx_vpn->lock));

  if( !_rhp_atomic_read(&(rx_vpn->is_active)) ){
    err = -ENOENT;
		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_RX_VPN_NOT_ACTIVE,"xx",pkt,rx_vpn);
    goto error_l;
  }


	rlm = rx_vpn->rlm;

	{
  	RHP_LOCK(&(rlm->lock));

  	rlm->statistics.bridge.rx_from_vpn_pkts++;

  	if( !_rhp_atomic_read(&(rlm->is_active)) ){
  		RHP_UNLOCK(&(rlm->lock));
  		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_RX_RLM_NOT_ACTIVE,"xxx",pkt,rx_vpn,rlm);
  		goto error_l;
  	}

  	rlm_id = rlm->id;

  	tx_v_ifc = rlm->internal_ifc->ifc;
  	if( tx_v_ifc ){

  		rhp_ifc_hold(tx_v_ifc);

  		if( !flooding && !memcmp(tx_v_ifc->mac,pkt->l2.eth->dst_addr,6) ){
  			to_local = 1;
  			side = RHP_BRIDGE_SIDE_TUNTAP;
  		}
  	}

  	is_access_point = rlm->is_access_point;

  	dont_fwd_pkts_btwn_conns = rlm->childsa.dont_fwd_pkts_between_vpn_conns;

  	if( !dont_fwd_pkts_btwn_conns ){

			dont_fwd_pkts_btwn_clts
				= (rlm->config_server.dont_fwd_pkts_between_clients && rx_vpn->peer_is_remote_client ? 1 : 0);

			if( dont_fwd_pkts_btwn_clts &&
					rlm->config_server.dont_fwd_pkts_between_clients_except_v6_auto &&
					rhp_esp_is_v6_linklocal_icmp_pkt(pkt) ){

				dont_fwd_pkts_btwn_clts = 0;
			}
  	}

  	RHP_UNLOCK(&(rlm->lock));
  }


  if( !flooding && !to_local ){

	  RHP_LOCK(&rhp_bridge_lock);

	  br_c_dst = _rhp_bridge_cache_get(rlm_id,pkt->l2.eth->dst_addr);
	  if( br_c_dst ){

	  	side = br_c_dst->side;

	  	if( side == RHP_BRIDGE_SIDE_VPN ){

	    	tx_vpn = RHP_VPN_REF(br_c_dst->vpn_ref);
		  	if( tx_vpn ){
		  		tx_vpn_ref = rhp_vpn_hold_ref(tx_vpn);
		  	}
	  	}

	  	if( br_c_dst->static_cache == RHP_BRIDGE_SCACHE_V6_DUMMY_LL_ADDR ){

	  		to_v6_lladdr = 1;
	  	}

	  	br_c_dst->last_used_cnt++;

	  }else{

	  	flooding = 1;
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_FLOODING_2,"x",pkt);
	  }

	  RHP_UNLOCK(&rhp_bridge_lock);
	}

  if( !flooding ){

  	if( ( side == RHP_BRIDGE_SIDE_VPN && tx_vpn == NULL ) ||
  			( (side == RHP_BRIDGE_SIDE_TUNTAP || to_local || to_v6_lladdr) && tx_v_ifc == NULL ) ){
  		err = 0;
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_TX_NOT_FOUND,"xdxx",pkt,side,tx_vpn,tx_v_ifc);
  		goto error_l;
  	}

  }else{

  	RHP_LOCK(&(rlm->lock));
  	rlm->statistics.bridge.tx_from_vpn_flooding_pkts++;
  	RHP_UNLOCK(&(rlm->lock));

		RHP_LOCK(&rhp_bridge_lock);
		rhp_bridge_cache_statistics_tbl.bridge.tx_from_vpn_flooding_pkts++;
	  RHP_UNLOCK(&rhp_bridge_lock);

  	if( tx_v_ifc == NULL ){
  		err = 0;
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_TX_INTERNAL_IFC_NOT_FOUND,"x",pkt);
  		goto error_l;
  	}
  }

  _rhp_bridge_cache_update_from_vpn(pkt,rlm_id,rx_vpn);

	RHP_UNLOCK(&(rx_vpn->lock));


	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_NEIGH_CACHE,"xdddWddd",pkt,rhp_gcfg_proxy_arp_cache,rhp_gcfg_proxy_ipv6_nd_cache,is_access_point,pkt->l2.eth->protocol,pkt->len,dont_fwd_pkts_btwn_conns,dont_fwd_pkts_btwn_clts);
	rhp_pkt_trace_dump("rhp_bridge_pkt_from_vpn.neigh",pkt);

	if( pkt->l2.eth->protocol == RHP_PROTO_ETH_ARP ||
			(!rhp_gcfg_ipv6_disabled && rhp_ipv6_is_nd_packet(pkt,&nd_icmp6_type)) ){

		err = _rhp_bridge_handle_neigh_cache_for_vpn(pkt,rlm_id,
						rx_vpn,nd_icmp6_type,&neigh_req_ok,&ex_flood_pkt);

		if( err ){
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_HANDLE_NEIGH_CACHE_FOR_VPN_ERR,"xE",pkt,err);
			goto error;
		}
	}

	if( ex_flood_pkt ){

		tx_err = _rhp_bridge_flood_pkt_from_vpn(ex_flood_pkt,
								rx_vpn,rlm_id,tx_v_ifc,is_access_point,0,
								dont_fwd_pkts_btwn_conns,dont_fwd_pkts_btwn_clts);

		if( tx_err ){
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_HANDLE_NEIGH_CACHE_FOR_VPN_EX_FLOOD_PKT_ERR,"xxE",pkt,ex_flood_pkt,err);
		}
	}


	if( !neigh_req_ok ){

		if( flooding ){

			tx_err = _rhp_bridge_flood_pkt_from_vpn(pkt,
								rx_vpn,rlm_id,tx_v_ifc,is_access_point,to_v6_lladdr,
								dont_fwd_pkts_btwn_conns,dont_fwd_pkts_btwn_clts);

			if( tx_err ){
				RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_HANDLE_NEIGH_CACHE_FOR_VPN_FLOOD_PKT_ERR,"xE",pkt,err);
			}

		}else{

			if( to_v6_lladdr ){

				rhp_ipv6_rlm_lladdr_rx(tx_v_ifc,pkt);

			//
			// If this node is not access-point, packets received from a vpn tunnel
			// are not forwarded to other vpn tunnels to avoid packet-loops.
			//
			}else if( side == RHP_BRIDGE_SIDE_VPN &&
								is_access_point &&
								!dont_fwd_pkts_btwn_conns &&
								(!tx_vpn->peer_is_remote_client || !dont_fwd_pkts_btwn_clts) ){

				if( rx_vpn && (tx_vpn == rx_vpn) ){

					RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_PKT_LOOP,"xxx",pkt,tx_vpn,rx_vpn);
					err = RHP_STATUS_PKT_RECV_FROM_VPN_LOOP;
					goto error;

				}else{

					rhp_encap_send(tx_vpn,pkt);
				}

			}else if( to_local || side == RHP_BRIDGE_SIDE_TUNTAP ){

				rhp_tuntap_write(tx_v_ifc,pkt);
			}
		}
	}

	if( tx_vpn_ref ){
		rhp_vpn_unhold(tx_vpn_ref);
	}

	if( tx_v_ifc ){
		rhp_ifc_unhold(tx_v_ifc);
	}

	if( ex_flood_pkt ){
		rhp_pkt_unhold(ex_flood_pkt);
	}

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_RTRN,"xx",pkt,ex_flood_pkt);
	return 0;

error_l:
	RHP_LOCK(&(rx_vpn->rlm->lock));
	rx_vpn->rlm->statistics.bridge.rx_from_vpn_err_pkts++;
	RHP_UNLOCK(&(rx_vpn->rlm->lock));

	RHP_UNLOCK(&(rx_vpn->lock));
error:
	if( tx_vpn_ref ){
		rhp_vpn_unhold(tx_vpn_ref);
	}
	if( tx_v_ifc ){
		rhp_ifc_unhold(tx_v_ifc);
	}
	if( ex_flood_pkt ){
		rhp_pkt_unhold(ex_flood_pkt);
	}

	RHP_LOCK(&rhp_bridge_lock);
	rhp_bridge_cache_statistics_tbl.bridge.rx_from_vpn_err_pkts++;
  RHP_UNLOCK(&rhp_bridge_lock);

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_ERR,"xxE",pkt,ex_flood_pkt,err);
	return err;
}


static int _rhp_bridge_neigh_cache_init(unsigned long vpn_realm_id,
		u8* peer_mac,rhp_ip_addr* peer_addr,int side,int static_by,
		rhp_bridge_neigh_cache** br_c_n_src_r)
{
	int err = -EINVAL;
	rhp_bridge_neigh_cache* br_c_n_src = NULL;

	RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_INIT,"uMxddx",vpn_realm_id,peer_mac,peer_addr,side,static_by,br_c_n_src_r);

	br_c_n_src = _rhp_bridge_neigh_cache_alloc(peer_addr->addr_family);
	if( br_c_n_src == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto ignored;
	}

	br_c_n_src->vpn_realm_id = vpn_realm_id;
	br_c_n_src->side = side;

	memcpy(br_c_n_src->target_mac,peer_mac,6);

	if( peer_addr->addr_family == AF_INET ){
		br_c_n_src->target_ip.addr.v4 = peer_addr->addr.v4;
	}else if( peer_addr->addr_family == AF_INET6 ){
		memcpy(br_c_n_src->target_ip.addr.v6,peer_addr->addr.v6,16);
	}

	br_c_n_src->static_cache = static_by;

	*br_c_n_src_r = br_c_n_src;
	err = 0;

ignored:
	RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CACHE_INIT_RTRN,"uxx",vpn_realm_id,br_c_n_src_r,br_c_n_src);
	return err;
}

static int _rhp_bridge_neigh_create_vpn_cache(unsigned long vpn_realm_id,
		u8* peer_mac,rhp_ip_addr* peer_addr,int static_by,rhp_vpn* vpn)
{
	int err = -EINVAL;
	rhp_bridge_neigh_cache* br_c_n_src = NULL;

	RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CREATE_VPN_CACHE,"uMxx",vpn_realm_id,peer_mac,peer_addr,vpn);
	rhp_ip_addr_dump("peer_addr",peer_addr);

	if( peer_addr->addr_family != AF_INET &&
			peer_addr->addr_family != AF_INET6){
		RHP_BUG("%d",peer_addr->addr_family);
		return -EINVAL;
	}


	br_c_n_src = _rhp_bridge_neigh_cache_get_by_tgt_ip(vpn_realm_id,
								peer_addr->addr_family,peer_addr->addr.raw);

	if( br_c_n_src == NULL ){

		err = _rhp_bridge_neigh_cache_init(vpn_realm_id,
						peer_mac,peer_addr,RHP_BRIDGE_SIDE_VPN,static_by,
						&br_c_n_src);
		if( err ){
  		RHP_BUG("%d",err);
  		goto ignored;
		}

  	if( vpn ){
  		br_c_n_src->vpn_ref = rhp_vpn_hold_ref(vpn);
  	}

  	_rhp_bridge_neigh_cache_put(br_c_n_src);

	}else if( memcmp(br_c_n_src->target_mac,peer_mac,6) ){

//		_rhp_bridge_neigh_cache_tbl_ck(br_c_n_src,1,peer_mac);

  	memcpy(br_c_n_src->target_mac,peer_mac,6);

  	br_c_n_src->side = RHP_BRIDGE_SIDE_VPN;

  	if( vpn ){

  		if( br_c_n_src->vpn_ref ){
    		rhp_vpn_unhold(br_c_n_src->vpn_ref);
  		}

  		br_c_n_src->vpn_ref = rhp_vpn_hold_ref(vpn);
  	}
	}

	br_c_n_src->last_used_cnt++;

	RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CREATE_VPN_CACHE_RTRN,"uMx",vpn_realm_id,peer_mac,peer_addr);
	return 0;

ignored:
	RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_CREATE_VPN_CACHE_ERR,"uMxE",vpn_realm_id,peer_mac,peer_addr,err);
	return err;
}

int rhp_bridge_static_neigh_cache_create(unsigned long vpn_realm_id,
		u8* peer_mac,rhp_ip_addr* peer_addr,int side,int static_by)
{
	int err = -EINVAL;
	rhp_bridge_neigh_cache* br_c_n_src = NULL;

	RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_NEIGH_CACHE_CREATE,"uMx",vpn_realm_id,peer_mac,peer_addr);
	rhp_ip_addr_dump("peer_addr",peer_addr);

	if( (peer_mac == NULL) || (peer_addr == NULL) ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( _rhp_mac_addr_null(peer_mac) ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( peer_addr->addr_family != AF_INET &&
			peer_addr->addr_family != AF_INET6 ){
		RHP_BUG("%d",peer_addr->addr_family);
		return -EINVAL;
	}

	if( rhp_gcfg_ipv6_disabled &&
			peer_addr->addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_NEIGH_CACHE_CREATE_IPV6_DISABLED,"uMx",vpn_realm_id,peer_mac,peer_addr);
		return -EINVAL;
	}

  RHP_LOCK(&rhp_bridge_lock);

	br_c_n_src = _rhp_bridge_neigh_cache_get_by_tgt_ip(vpn_realm_id,
								peer_addr->addr_family,peer_addr->addr.raw);

	if( br_c_n_src == NULL ){

		err = _rhp_bridge_neigh_cache_init(vpn_realm_id,
						peer_mac,peer_addr,side,static_by,
						&br_c_n_src);
		if( err ){
  		RHP_BUG("");
  		goto ignored;
		}

  	_rhp_bridge_neigh_cache_put(br_c_n_src);

	}else if( memcmp(br_c_n_src->target_mac,peer_mac,6) ){

//	_rhp_bridge_neigh_cache_tbl_ck(br_c_n_src,1,peer_mac);

  	memcpy(br_c_n_src->target_mac,peer_mac,6);

  	br_c_n_src->side = side;
	}

	br_c_n_src->last_used_cnt++;

  RHP_UNLOCK(&rhp_bridge_lock);

	RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_NEIGH_CACHE_CREATE_RTRN,"uMx",vpn_realm_id,peer_mac,peer_addr);
	return 0;

ignored:
	RHP_UNLOCK(&rhp_bridge_lock);

	RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_NEIGH_CACHE_CREATE_ERR,"uMxE",vpn_realm_id,peer_mac,peer_addr,err);
	return err;
}

int rhp_bridge_static_neigh_cache_delete(unsigned long vpn_realm_id,
		rhp_ip_addr* peer_addr,rhp_vpn* vpn,u8* old_target_mac)
{
	int err = -ENOENT;
	rhp_bridge_neigh_cache* br_c_n_src = NULL;

	RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_NEIGH_CACHE_DELETE,"uxx",vpn_realm_id,peer_addr,vpn);

  RHP_LOCK(&rhp_bridge_lock);

	br_c_n_src = _rhp_bridge_neigh_cache_get_by_tgt_ip(vpn_realm_id,
								peer_addr->addr_family,peer_addr->addr.raw);

	if( br_c_n_src ){

		if( vpn == NULL || RHP_VPN_REF(br_c_n_src->vpn_ref) == vpn ){

			if( !_rhp_bridge_neigh_cache_delete(br_c_n_src) ){

				if( old_target_mac ){
					memcpy(old_target_mac,br_c_n_src->target_mac,6);
				}

				_rhp_bridge_free_neigh_cache(br_c_n_src);

				err = 0;
			}
		}
	}

	RHP_UNLOCK(&rhp_bridge_lock);

	RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_NEIGH_CACHE_DELETE_RTRN,"uxE",vpn_realm_id,peer_addr,err);
	return err;
}


static void _rhp_bridge_neigh_adv_from_vpn_task(rhp_packet* adv_pkt);

static void _rhp_bridge_neigh_adv_from_vpn_timer_handler(void* ctx)
{
	int err = -EINVAL;
	rhp_packet* adv_pkt = (rhp_packet*)ctx;

	RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_ADV_FROM_VPN_TIMER_HANDLER,"x",adv_pkt);

	adv_pkt->process_packet = _rhp_bridge_neigh_adv_from_vpn_task;

	err = rhp_wts_sta_invoke_task(RHP_WTS_DISP_RULE_RAND,
			RHP_WTS_STA_TASK_NAME_PKT,RHP_WTS_DISP_LEVEL_LOW_1,adv_pkt,adv_pkt);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_ADV_FROM_VPN_TIMER_HANDLER_RTRN,"x",adv_pkt);
	return;

error:
	rhp_pkt_unhold(adv_pkt);

	RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_ADV_FROM_VPN_TIMER_HANDLER_ERR,"xE",adv_pkt,err);
	return;
}

static void _rhp_bridge_neigh_adv_from_vpn_task(rhp_packet* adv_pkt)
{
	int err = -EINVAL;
	rhp_vpn_ref* rx_vpn_ref = adv_pkt->esp_rx_vpn_ref;
	rhp_vpn* rx_vpn = RHP_VPN_REF(rx_vpn_ref);
	unsigned long n = (unsigned long)adv_pkt->priv;
	rhp_vpn_realm* rlm;
	rhp_ifc_entry *v_ifc = NULL,*rx_ifc = NULL;
	int addr_family;
	int max_num;

	RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_ADV_FROM_VPN_TASK,"xxu",adv_pkt,rx_vpn,n);

	if( adv_pkt->l2.eth->protocol == RHP_PROTO_ETH_ARP ){

		addr_family = AF_INET;
		max_num = rhp_gcfg_bridge_static_cache_garp_num;

	}else if( adv_pkt->l2.eth->protocol == RHP_PROTO_ETH_IPV6 ){

		addr_family = AF_INET6;
		max_num = rhp_gcfg_bridge_static_cache_unsolicited_nd_adv_num;

	}else{
		RHP_BUG("");
		goto error;
	}

	RHP_LOCK(&(rx_vpn->lock));

	rlm = rx_vpn->rlm;

	if( rlm == NULL ){
		RHP_BUG("");
		goto error_vpn_l;
	}

	RHP_LOCK(&(rlm->lock));
	{
		rhp_cfg_if* cfg_if;

		v_ifc = rlm->internal_ifc->ifc;
		if( v_ifc == NULL ){
			RHP_BUG("");
			goto error_vpn_rlm_l;
		}

		rhp_ifc_hold(v_ifc);

		if( !_rhp_atomic_read(&(v_ifc->is_active)) ){
			goto error_vpn_rlm_l;
		}

		cfg_if = rlm->get_my_interface(rlm,rx_vpn->local.if_info.if_name,addr_family);
		if( cfg_if == NULL ){
			goto error_vpn_rlm_l;
		}

		if( cfg_if->ifc == NULL ){
			RHP_BUG("");
			goto error_vpn_rlm_l;
		}

		rx_ifc = cfg_if->ifc;
		rhp_ifc_hold(rx_ifc);

		if( !_rhp_atomic_read(&(rx_ifc->is_active)) ){
			goto error_vpn_rlm_l;
		}
	}
	RHP_UNLOCK(&(rlm->lock));

	RHP_UNLOCK(&(rx_vpn->lock));


	if( addr_family == AF_INET6 && n == 1 ){

		RHP_LOCK(&(v_ifc->lock));
		{
			u8 llmac[6],v6_lladdr[16];

			err = rhp_ipv6_v_ifc_lladdr_get(v_ifc,v6_lladdr,llmac);
			if( err ){
				RHP_UNLOCK(&(v_ifc->lock));
				goto error;
			}

			memcpy(adv_pkt->l2.eth->src_addr,llmac,6);
			memcpy(adv_pkt->l3.iph_v6->src_addr,v6_lladdr,16);
		}
		RHP_UNLOCK(&(v_ifc->lock));
	}


	{
		rhp_packet* tx_pkt;

		if( (int)n >= max_num ){
			tx_pkt = adv_pkt;
		}else{
			tx_pkt = rhp_pkt_dup(adv_pkt);
		}

		if( tx_pkt ){

			tx_pkt->rx_if_index = rx_ifc->if_index;
			tx_pkt->rx_ifc = rx_ifc;
			rhp_ifc_hold(rx_ifc);

			RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_ADV_FROM_VPN_TASK_TX_PKT,"dxxxa",n,tx_pkt,rx_vpn,v_ifc,tx_pkt->len,RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,tx_pkt->l2.raw);

			rhp_bridge_pkt_from_vpn(tx_pkt,rx_vpn);

			if( tx_pkt != adv_pkt ){
				rhp_pkt_unhold(tx_pkt);
			}
		}
	}

	if( (int)n >= max_num ){

		rhp_pkt_unhold(adv_pkt);

	}else{

		adv_pkt->priv = (void*)(n + 1);

		err = rhp_timer_oneshot(_rhp_bridge_neigh_adv_from_vpn_timer_handler,adv_pkt,1);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
	}

	rhp_ifc_unhold(v_ifc);
	rhp_ifc_unhold(rx_ifc);

	RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_ADV_FROM_VPN_TASK_RTRN,"xxu",adv_pkt,rx_vpn,n);
	return;

error_vpn_rlm_l:
	RHP_UNLOCK(&(rlm->lock));
error_vpn_l:
	RHP_UNLOCK(&(rx_vpn->lock));
error:

	if( v_ifc ){
		rhp_ifc_unhold(v_ifc);
	}
	if( rx_ifc ){
		rhp_ifc_unhold(rx_ifc);
	}
	rhp_pkt_unhold(adv_pkt);

	RHP_TRC(0,RHPTRCID_BRIDGE_NEIGH_ADV_FROM_VPN_TASK_ERR,"xxu",adv_pkt,rx_vpn,n);
	return;
}

static int _rhp_bridge_tx_garp_from_vpn(rhp_vpn* vpn,u8* mac,rhp_ip_addr* addr)
{
	int err = -EINVAL;
	rhp_packet* garp_pkt = NULL;
	rhp_proto_ether* ethh;
	rhp_proto_arp* arph;

	RHP_TRC(0,RHPTRCID_BRIDGE_TX_GARP_FROM_VPN,"uxMxd",(vpn ? vpn->vpn_realm_id : 0),vpn,mac,addr,rhp_gcfg_bridge_tx_garp_for_vpn_peers);
	rhp_ip_addr_dump("addr",addr);

	if( !rhp_gcfg_bridge_tx_garp_for_vpn_peers ){
		return 0;
	}

	if( vpn == NULL ){
		RHP_TRC(0,RHPTRCID_BRIDGE_TX_GARP_FROM_VPN_VPN_NULL,"ux",(vpn ? vpn->vpn_realm_id : 0),vpn);
		return -EINVAL;
	}

	garp_pkt = rhp_pkt_alloc(sizeof(rhp_proto_ether) + sizeof(rhp_proto_arp));
	if( garp_pkt == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	garp_pkt->type = RHP_PKT_PLAIN_ETHER_TAP;

	ethh = (rhp_proto_ether*)_rhp_pkt_push(garp_pkt,sizeof(rhp_proto_ether));
	arph = (rhp_proto_arp*)_rhp_pkt_push(garp_pkt,sizeof(rhp_proto_arp));

	ethh->dst_addr[0] = 0xFF;
	ethh->dst_addr[1] = 0xFF;
	ethh->dst_addr[2] = 0xFF;
	ethh->dst_addr[3] = 0xFF;
	ethh->dst_addr[4] = 0xFF;
	ethh->dst_addr[5] = 0xFF;
	memcpy(ethh->src_addr,mac,6);
	ethh->protocol = RHP_PROTO_ETH_ARP;

	arph->hw_type = RHP_PROTO_ARP_HW_TYPE_ETHER;
	arph->hw_len = 6;
	arph->proto_type = RHP_PROTO_ETH_IP;
	arph->proto_len = 4;
	arph->operation = RHP_PROTO_ARP_OPR_REQUEST;
	memcpy(arph->sender_mac,mac,6);
	memset(arph->target_mac,0,6);

	arph->sender_ipv4 = addr->addr.v4;
	arph->target_ipv4 = addr->addr.v4;

	garp_pkt->l2.raw = (u8*)ethh;

	garp_pkt->esp_rx_vpn_ref = rhp_vpn_hold_ref(vpn);

	garp_pkt->priv = (void*)1;

	err = rhp_timer_oneshot(_rhp_bridge_neigh_adv_from_vpn_timer_handler,garp_pkt,1);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	RHP_TRC(0,RHPTRCID_BRIDGE_TX_GARP_FROM_VPN_RTRN,"xx",vpn,garp_pkt);
	return 0;

error:
	if( garp_pkt ){
		rhp_pkt_unhold(garp_pkt);
	}
	RHP_TRC(0,RHPTRCID_BRIDGE_TX_GARP_FROM_VPN_ERR,"xE",vpn,err);
	return err;
}

// vpn may be NULL.
static int _rhp_bridge_tx_unsol_nd_adv_from_vpn(rhp_vpn* vpn,u8* mac,rhp_ip_addr* addr)
{
	int err = -EINVAL;
	rhp_packet* adv_pkt = NULL;

	RHP_TRC(0,RHPTRCID_BRIDGE_UNSOLICITED_ND_ADV_FROM_VPN,"uxMxd",(vpn ? vpn->vpn_realm_id : 0),vpn,mac,addr,rhp_gcfg_bridge_tx_unsol_nd_adv_for_vpn_peers);
	rhp_ip_addr_dump("addr",addr);

	if( !rhp_gcfg_bridge_tx_unsol_nd_adv_for_vpn_peers ){
		return 0;
	}

	if( vpn == NULL ){
		RHP_TRC(0,RHPTRCID_BRIDGE_UNSOLICITED_ND_ADV_FROM_VPN_VPN_NULL,"ux",(vpn ? vpn->vpn_realm_id : 0),vpn);
		return -EINVAL;
	}

	// adv_pkt->l2.eth->src_addr and adv_pkt->l3.ipv6->src_addr will
	// be correctly set later. (LinkLocal address)
	adv_pkt = rhp_ipv6_nd_new_adv_pkt(mac,addr->addr.v6,NULL,NULL,addr->addr.v6,NULL,0);
	if( adv_pkt == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}


	adv_pkt->esp_rx_vpn_ref = rhp_vpn_hold_ref(vpn);

	adv_pkt->priv = (void*)1;

	err = rhp_timer_oneshot(_rhp_bridge_neigh_adv_from_vpn_timer_handler,adv_pkt,1);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	RHP_TRC(0,RHPTRCID_BRIDGE_UNSOLICITED_ND_ADV_FROM_VPN_RTRN,"xx",vpn,adv_pkt);
	return 0;

error:
	if( adv_pkt ){
		rhp_pkt_unhold(adv_pkt);
	}
	RHP_TRC(0,RHPTRCID_BRIDGE_UNSOLICITED_ND_ADV_FROM_VPN_ERR,"xE",vpn,err);
	return err;
}


static int _rhp_bridge_static_cache_create(unsigned long vpn_realm_id,
		u8* peer_mac,int side,int static_by,rhp_bridge_cache** br_c_src_r)
{
	int err = -EINVAL;
	rhp_bridge_cache* br_c_src = NULL;

	RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_CACHE_CREATE_L,"uMddx",vpn_realm_id,peer_mac,side,static_by,br_c_src_r);

	br_c_src = _rhp_bridge_cache_get(vpn_realm_id,peer_mac);
	if( br_c_src != NULL ){

		RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_CACHE_CREATE_L_EXISTS_ERR,"uM",vpn_realm_id,peer_mac);

		if( br_c_src_r ){
			*br_c_src_r = br_c_src;
		}

		err = -EEXIST;
		goto error;
	}

	br_c_src = _rhp_bridge_cache_alloc();
	if( br_c_src == NULL ){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}

	br_c_src->side = side;
	br_c_src->vpn_realm_id = vpn_realm_id;
	br_c_src->static_cache = static_by;

	memcpy(br_c_src->dest_mac,peer_mac,6);

	_rhp_bridge_cache_put(br_c_src);


	if( br_c_src_r ){
		*br_c_src_r = br_c_src;
	}

	RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_CACHE_CREATE_L_RTRN,"uMx",vpn_realm_id,peer_mac,br_c_src);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_CACHE_CREATE_L_ERR,"uMxE",vpn_realm_id,peer_mac,br_c_src,err);
	return err;
}

int rhp_bridge_static_cache_delete(unsigned long vpn_realm_id,u8* peer_mac)
{
	int err = -EINVAL;
	rhp_bridge_cache* br_c_src = NULL;

	RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_CACHE_DELETE,"uM",vpn_realm_id,peer_mac);

	RHP_LOCK(&rhp_bridge_lock);

	br_c_src = _rhp_bridge_cache_get(vpn_realm_id,peer_mac);
	if( br_c_src == NULL ){
		err = -ENOENT;
		goto error_l;
	}

	if( !_rhp_bridge_cache_delete(br_c_src) ){
		_rhp_bridge_free_cache(br_c_src);
	}

	RHP_UNLOCK(&rhp_bridge_lock);

	RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_CACHE_DELETE_RTRN,"uMx",vpn_realm_id,peer_mac,br_c_src);
	return 0;

error_l:
	RHP_UNLOCK(&rhp_bridge_lock);

	RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_CACHE_DELETE_ERR,"uMxE",vpn_realm_id,peer_mac,br_c_src,err);
	return err;
}

int rhp_bridge_static_cache_create(unsigned long vpn_realm_id,
		u8* peer_mac,int side,int static_by)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_CACHE_CREATE,"uMdd",vpn_realm_id,peer_mac,side,static_by);

	if( peer_mac == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( _rhp_mac_addr_null(peer_mac) ){
		RHP_BUG("");
		return -EINVAL;
	}

	RHP_LOCK(&rhp_bridge_lock);

	err = _rhp_bridge_static_cache_create(vpn_realm_id,
					peer_mac,side,static_by,NULL);
	if( err ){
		goto error_l;
	}

  RHP_UNLOCK(&rhp_bridge_lock);

	RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_CACHE_CREATE_RTRN,"uM",vpn_realm_id,peer_mac);
  return 0;

error_l:
	RHP_UNLOCK(&rhp_bridge_lock);

	RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_CACHE_CREATE_ERR,"uME",vpn_realm_id,peer_mac,err);
	return err;
}

// Clear also static cache entries.
static int _rhp_bridge_neigh_cache_clear_by_peer_mac(unsigned long rlm_id,
		u8* peer_mac)
{
	u32 hval;
  rhp_bridge_neigh_cache *br_c_n_tmp = NULL,*br_c_n_tmp_n = NULL;

	hval = _rhp_bridge_neigh_hash_tgt_mac(rlm_id,peer_mac);

	br_c_n_tmp = _rhp_bridge_neigh_cache_tgt_mac_hash_tbl[hval];

	while( br_c_n_tmp ){

		br_c_n_tmp_n = br_c_n_tmp->next_hash_tgt_mac;

    if( br_c_n_tmp->vpn_realm_id == rlm_id &&
    		!memcmp(br_c_n_tmp->target_mac,peer_mac,6) ){

			if( !_rhp_bridge_neigh_cache_delete(br_c_n_tmp) ){
				_rhp_bridge_free_neigh_cache(br_c_n_tmp);
			}
		}

		br_c_n_tmp = br_c_n_tmp_n;
	}

	return 0;
}

int rhp_bridge_static_cache_reset_for_vpn(unsigned long rlm_id,rhp_vpn* vpn,
		u8* peer_mac,rhp_ip_addr_list* peer_addrs,int static_by)
{
	int err = -EINVAL;
	rhp_bridge_cache* br_c_src = NULL;
	rhp_ip_addr_list* peer_addr = peer_addrs;

	RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_CACHE_RESET_FOR_VPN,"uxMxd",rlm_id,vpn,peer_mac,peer_addrs,static_by);
	while( peer_addr ){
		rhp_ip_addr_dump("peer_addr",&(peer_addr->ip_addr));
		peer_addr = peer_addr->next;
	}

	if( peer_mac == NULL  || peer_addrs == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( _rhp_mac_addr_null(peer_mac) ){
		RHP_BUG("");
		return -EINVAL;
	}


	RHP_LOCK(&rhp_bridge_lock);

	err = _rhp_bridge_static_cache_create(rlm_id,
					peer_mac,RHP_BRIDGE_SIDE_VPN,static_by,&br_c_src);
	if( err && err != -EEXIST ){

		RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_CACHE_RESET_FOR_VPN_EXISTS_ERR,"uxMx",rlm_id,vpn,peer_mac,peer_addr);
		goto error_l;

	}else if( err == -EEXIST ){

		err = _rhp_bridge_neigh_cache_clear_by_peer_mac(rlm_id,peer_mac);
		if( err ){
			RHP_BUG("%d",err);
			err = 0;
		}
	}


	if( br_c_src->static_cache != RHP_BRIDGE_SCACHE_V6_DUMMY_LL_ADDR ){

		if( br_c_src->vpn_ref && (RHP_VPN_REF(br_c_src->vpn_ref) != vpn) ){
			rhp_vpn_unhold(br_c_src->vpn_ref);
			br_c_src->vpn_ref = NULL;
		}

		if( (br_c_src->vpn_ref == NULL) && (vpn != NULL) ){
			br_c_src->vpn_ref = rhp_vpn_hold_ref(vpn);
		}
	}

	br_c_src->last_used_cnt++;


	peer_addr = peer_addrs;
	while( peer_addr ){

		int static_by2 = static_by;

		if( static_by2 && static_by2 != RHP_BRIDGE_SCACHE_DUMMY ){

			if( peer_addr->ip_addr.tag == RHP_IPADDR_TAG_IKEV2_CFG_ASSIGNED ){
				static_by2 = RHP_BRIDGE_SCACHE_IKEV2_CFG;
			}else if( peer_addr->ip_addr.tag == RHP_IPADDR_TAG_IKEV2_EXCHG ){
				static_by2 = RHP_BRIDGE_SCACHE_IKEV2_EXCHG;
			}
		}

		if( !rhp_ip_addr_null(&(peer_addr->ip_addr)) ){

			err = _rhp_bridge_neigh_create_vpn_cache(rlm_id,
							peer_mac,&(peer_addr->ip_addr),static_by2,vpn);
			if( err ){
				RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_CACHE_RESET_FOR_VPN_CREATE_ARP_CACHE_ERR,"uE",rlm_id,err);
				goto error_l;
			}

			if( vpn ){

				if( peer_addr->ip_addr.addr_family == AF_INET ){

					_rhp_bridge_tx_garp_from_vpn(vpn,peer_mac,&(peer_addr->ip_addr));

				}else if( peer_addr->ip_addr.addr_family == AF_INET6 ){

					_rhp_bridge_tx_unsol_nd_adv_from_vpn(vpn,peer_mac,&(peer_addr->ip_addr));
				}
			}
		}

		peer_addr = peer_addr->next;
	}

  RHP_UNLOCK(&rhp_bridge_lock);

	RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_CACHE_RESET_FOR_VPN_RTRN,"uxMx",rlm_id,vpn,peer_mac,peer_addr);
  return 0;

error_l:
	RHP_UNLOCK(&rhp_bridge_lock);

	RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_CACHE_RESET_FOR_VPN_ERR,"uxMxE",rlm_id,vpn,peer_mac,peer_addr,err);
	return err;
}

int rhp_bridge_static_neigh_cache_update_for_vpn(
		rhp_vpn* vpn,
		rhp_ip_addr* old_peer_addr,rhp_ip_addr* new_peer_addr,
		u8* new_peer_mac,
		int static_by)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_NEIGH_CACHE_UPDATE_FOR_VPN,"uxxxMd",vpn->vpn_realm_id,vpn,old_peer_addr,new_peer_addr,new_peer_mac,static_by);
	rhp_ip_addr_dump("old_peer_addr",old_peer_addr);
	rhp_ip_addr_dump("new_peer_addr",new_peer_addr);

	if( new_peer_addr == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( new_peer_addr->addr_family != AF_INET &&
			new_peer_addr->addr_family != AF_INET6 ){
		RHP_BUG("");
		return 0;
	}

	if( old_peer_addr->addr_family != new_peer_addr->addr_family ){
		RHP_BUG("");
		return 0;
	}

	if( new_peer_mac && _rhp_mac_addr_null(new_peer_mac) ){
		RHP_BUG("");
		return 0;
	}

	RHP_LOCK(&rhp_bridge_lock);

	{
		rhp_bridge_neigh_cache* br_c_n = NULL;

		if( old_peer_addr == NULL ||
				rhp_ip_addr_null(old_peer_addr) ){
			RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_NEIGH_CACHE_UPDATE_FOR_VPN_OLD_PEER_NULL,"uxxx",vpn->vpn_realm_id,vpn,old_peer_addr,new_peer_addr);
			err = -EINVAL;
			goto error_l;
		}

		br_c_n = _rhp_bridge_neigh_cache_get_by_tgt_ip(vpn->vpn_realm_id,
							old_peer_addr->addr_family,old_peer_addr->addr.raw);

		if( br_c_n == NULL ){

			RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_NEIGH_CACHE_UPDATE_FOR_VPN_NO_ENT,"uxxx",vpn->vpn_realm_id,vpn,old_peer_addr,new_peer_addr);

			if( new_peer_mac && !rhp_ip_addr_null(new_peer_addr) ){

				err = _rhp_bridge_neigh_create_vpn_cache(vpn->vpn_realm_id,
								new_peer_mac,new_peer_addr,static_by,vpn);
				if( err ){
					RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_NEIGH_CACHE_UPDATE_FOR_VPN_CREATE_ERR,"xuE",vpn,vpn->vpn_realm_id,err);
					goto error_l;
				}

				if( new_peer_addr->addr_family == AF_INET ){

					_rhp_bridge_tx_garp_from_vpn(vpn,new_peer_mac,new_peer_addr);

				}else if( new_peer_addr->addr_family == AF_INET6 ){

					_rhp_bridge_tx_unsol_nd_adv_from_vpn(vpn,new_peer_mac,new_peer_addr);
				}

				goto end;

			}else{

				RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_NEIGH_CACHE_UPDATE_FOR_VPN_CREATE_NO_ENT_NOT_UPDATED,"xu",vpn,vpn->vpn_realm_id);
			}

		}else{

			_rhp_bridge_neigh_cache_delete(br_c_n);

			if( new_peer_mac ){

//			_rhp_bridge_neigh_cache_tbl_ck(br_c_n,1,new_peer_mac);

				memcpy(br_c_n->target_mac,new_peer_mac,6);
			}

			if( new_peer_addr->addr_family == AF_INET ){

				br_c_n->target_ip.addr.v4 = new_peer_addr->addr.v4;

				_rhp_bridge_neigh_cache_put(br_c_n);

				_rhp_bridge_tx_garp_from_vpn(vpn, br_c_n->target_mac,new_peer_addr);

			}else if( new_peer_addr->addr_family == AF_INET6 ){

				memcpy(br_c_n->target_ip.addr.v6,new_peer_addr->addr.v6,16);

				_rhp_bridge_neigh_cache_put(br_c_n);

				_rhp_bridge_tx_unsol_nd_adv_from_vpn(vpn,br_c_n->target_mac,new_peer_addr);
			}

			br_c_n->last_used_cnt++;
		}
	}

end:
  RHP_UNLOCK(&rhp_bridge_lock);

	RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_NEIGH_CACHE_UPDATE_FOR_VPN_RTRN,"uxxx",vpn->vpn_realm_id,vpn,old_peer_addr,new_peer_addr);
	return 0;

error_l:
	RHP_UNLOCK(&rhp_bridge_lock);

	RHP_TRC(0,RHPTRCID_BRIDGE_STATIC_NEIGH_CACHE_UPDATE_FOR_VPN_ERR,"uxxxE",vpn->vpn_realm_id,vpn,old_peer_addr,new_peer_addr,err);
	return err;
}


static void _rhp_neigh_resolve_put(rhp_neigh_rslv_ctx* rslv_ctx)
{
  u32 hval;

  hval = _rhp_bridge_neigh_hash_tgt_ip2(rslv_ctx->vpn_realm_id,&(rslv_ctx->target_ip));

  rslv_ctx->next_hash = _rhp_neigh_rslv_hash_tbl[hval];
  _rhp_neigh_rslv_hash_tbl[hval] = rslv_ctx;

  rhp_bridge_cache_statistics_tbl.dc.neigh.resolving_addrs++;

  if( rslv_ctx->addr_family == AF_INET ){
  	RHP_TRC(0,RHPTRCID_NEIGH_RESOLVE_PUT,"xu4d",rslv_ctx,rslv_ctx->vpn_realm_id,rslv_ctx->target_ip.addr.v4,rhp_bridge_cache_statistics_tbl.dc.neigh.resolving_addrs);
  }else if( rslv_ctx->addr_family == AF_INET6 ){
  	RHP_TRC(0,RHPTRCID_NEIGH_RESOLVE_PUT_V6,"xu6d",rslv_ctx,rslv_ctx->vpn_realm_id,rslv_ctx->target_ip.addr.v6,rhp_bridge_cache_statistics_tbl.dc.neigh.resolving_addrs);
  }else{
  	RHP_BUG("%d",rslv_ctx->addr_family);
  }

  return;
}

static rhp_neigh_rslv_ctx* _rhp_neigh_resolve_get(unsigned long vpn_realm_id,int addr_family,u8* target_ip)
{
  rhp_neigh_rslv_ctx* rslv_ctx = NULL;
  u32 hval;

  hval = _rhp_bridge_neigh_hash_tgt_ip(vpn_realm_id,addr_family,target_ip);

  rslv_ctx = _rhp_neigh_rslv_hash_tbl[hval];

  while( rslv_ctx ){

    if( (rslv_ctx->vpn_realm_id == vpn_realm_id) &&
    		(rslv_ctx->target_ip.addr_family == addr_family) ){

    	if( (addr_family == AF_INET &&
    			 rslv_ctx->target_ip.addr.v4 == *((u32*)target_ip)) ||
    			(addr_family == AF_INET6 &&
    			 rhp_ipv6_is_same_addr(rslv_ctx->target_ip.addr.v6,target_ip)) ){
        break;
    	}
    }

    rslv_ctx = rslv_ctx->next_hash;
  }

  if( rslv_ctx ){
  	if( addr_family == AF_INET ){
  		RHP_TRC(0,RHPTRCID_NEIGH_RESOLVE_GET,"xu4ddxx",rslv_ctx,rslv_ctx->vpn_realm_id,rslv_ctx->target_ip.addr.v4,rslv_ctx->retries,rslv_ctx->pkt_q.head,rhp_bridge_cache_statistics_tbl.dc.neigh.resolving_addrs);
  	}else if( addr_family == AF_INET6 ){
  		RHP_TRC(0,RHPTRCID_NEIGH_RESOLVE_GET_V6,"xu6ddxx",rslv_ctx,rslv_ctx->vpn_realm_id,rslv_ctx->target_ip.addr.v6,rslv_ctx->retries,rslv_ctx->pkt_q.head,rhp_bridge_cache_statistics_tbl.dc.neigh.resolving_addrs);
  	}
  }else{
  	if( addr_family == AF_INET ){
  		RHP_TRC(0,RHPTRCID_NEIGH_RESOLVE_GET_NO_ENT,"u4d",vpn_realm_id,*((u32*)target_ip),rhp_bridge_cache_statistics_tbl.dc.neigh.resolving_addrs);
  	}else if( addr_family == AF_INET6 ){
  		RHP_TRC(0,RHPTRCID_NEIGH_RESOLVE_GET_NO_ENT_V6,"u6d",vpn_realm_id,target_ip,rhp_bridge_cache_statistics_tbl.dc.neigh.resolving_addrs);
  	}else{
  		RHP_BUG("%d",addr_family);
  	}
  }
  return rslv_ctx;
}

static void _rhp_neigh_resolve_free(rhp_neigh_rslv_ctx* rslv_ctx)
{
	rhp_packet* pkt;

	if( rslv_ctx->addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_NEIGH_RESOLVE_FREE,"xu4",rslv_ctx,rslv_ctx->vpn_realm_id,rslv_ctx->target_ip.addr.v4);
	}else if( rslv_ctx->addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_NEIGH_RESOLVE_FREE_V6,"xu6",rslv_ctx,rslv_ctx->vpn_realm_id,rslv_ctx->target_ip.addr.v6);
	}else{
		RHP_BUG("%d",rslv_ctx->addr_family);
	}

	while( 1 ){

		pkt = _rhp_pkt_q_deq(&(rslv_ctx->pkt_q));
		if( pkt == NULL ){
			break;
		}

		rslv_ctx->pkt_q_num--;

		if( pkt->priv ){
			rhp_vpn_unhold((rhp_vpn_ref*)pkt->priv);
		}

		rhp_pkt_unhold(pkt);
	  rhp_bridge_cache_statistics_tbl.dc.arp.pxy_arp_queued_num--;
	}

	if( rslv_ctx->rx_ifc ){
		rhp_ifc_unhold(rslv_ctx->rx_ifc);
	}

	if( rslv_ctx->rx_vpn_ref ){
		rhp_vpn_unhold(rslv_ctx->rx_vpn_ref);
	}

	_rhp_free(rslv_ctx);

	RHP_TRC(0,RHPTRCID_NEIGH_RESOLVE_FREE_RTRN,"x",rslv_ctx);
	return;
}

static int _rhp_neigh_resolve_delete(rhp_neigh_rslv_ctx* rslv_ctx)
{
  int err = 0;
  u32 hval;
  rhp_neigh_rslv_ctx *rslv_ctx_tmp = NULL,*rslv_ctx_tmp_p;

  hval = _rhp_bridge_neigh_hash_tgt_ip2(rslv_ctx->vpn_realm_id,&(rslv_ctx->target_ip));

  rslv_ctx_tmp = _rhp_neigh_rslv_hash_tbl[hval];
  rslv_ctx_tmp_p = NULL;
  while( rslv_ctx_tmp ){

    if( rslv_ctx_tmp == rslv_ctx ){
   	  break;
    }

    rslv_ctx_tmp_p = rslv_ctx_tmp;
    rslv_ctx_tmp = rslv_ctx_tmp->next_hash;
  }

  if( rslv_ctx_tmp == NULL ){
    err = -ENOENT;
    goto error;
  }

  if( rslv_ctx_tmp_p ){
  	rslv_ctx_tmp_p->next_hash = rslv_ctx_tmp->next_hash;
  }else{
    _rhp_neigh_rslv_hash_tbl[hval] = rslv_ctx_tmp->next_hash;
  }

  rhp_bridge_cache_statistics_tbl.dc.neigh.resolving_addrs--;

  if( rslv_ctx->target_ip.addr_family == AF_INET ){
  	RHP_TRC(0,RHPTRCID_NEIGH_RESOLVE_DELETE,"xu4d",rslv_ctx,rslv_ctx->vpn_realm_id,rslv_ctx->target_ip.addr.v4,rhp_bridge_cache_statistics_tbl.dc.neigh.resolving_addrs);
  }else if( rslv_ctx->target_ip.addr_family == AF_INET6 ){
  	RHP_TRC(0,RHPTRCID_NEIGH_RESOLVE_DELETE_V6,"xu6d",rslv_ctx,rslv_ctx->vpn_realm_id,rslv_ctx->target_ip.addr.v6,rhp_bridge_cache_statistics_tbl.dc.neigh.resolving_addrs);
  }else{
  	RHP_BUG("%d",rslv_ctx->target_ip.addr_family);
  }

  return 0;

error:
	if( rslv_ctx->target_ip.addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_NEIGH_RESOLVE_DELETE_ERR,"xu4d",rslv_ctx,rslv_ctx->vpn_realm_id,rslv_ctx->target_ip.addr.v4,rhp_bridge_cache_statistics_tbl.dc.neigh.resolving_addrs);
  }else if( rslv_ctx->target_ip.addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_NEIGH_RESOLVE_DELETE_ERR_V6,"xu4d",rslv_ctx,rslv_ctx->vpn_realm_id,rslv_ctx->target_ip.addr.v6,rhp_bridge_cache_statistics_tbl.dc.neigh.resolving_addrs);
  }else{
  	RHP_BUG("%d",rslv_ctx->target_ip.addr_family);
  }
	return err;
}

static void _rhp_neigh_resolve_timer(void* arg,rhp_timer* timer)
{
	rhp_neigh_rslv_ctx* rslv_ctx = (rhp_neigh_rslv_ctx*)arg;
	rhp_packet *req_pkt = NULL,*tx_pkt_tmp = NULL;
	rhp_bridge_neigh_cache *br_c_dst = NULL;
	int rslv_ok = 0;
	int retry_times = (rslv_ctx->addr_family == AF_INET ?
		 rhp_gcfg_arp_resolve_retry_times : rhp_gcfg_ipv6_nd_resolve_retry_times);
	int timeout = (rslv_ctx->addr_family == AF_INET ?
		 rhp_gcfg_arp_resolve_timeout : rhp_gcfg_ipv6_nd_resolve_timeout);
	rhp_vpn* rx_vpn = RHP_VPN_REF(rslv_ctx->rx_vpn_ref);

  RHP_TRC(0,RHPTRCID_NEIGH_RESOLVE_TIMER,"xx",arg,timer);

	RHP_LOCK(&rhp_bridge_lock);

  RHP_TRC(0,RHPTRCID_NEIGH_RESOLVE_TIMER_TX_PKT,"xxxxdMdx",arg,timer,rx_vpn,rslv_ctx->rx_ifc,rslv_ctx->rx_if_index,rslv_ctx->sender_mac,rslv_ctx->pkt_q_num,rslv_ctx->pkt_q.head);
  rhp_ip_addr_dump("rslv_ctx->sender_ip",&(rslv_ctx->sender_ip));
  rhp_ip_addr_dump("rslv_ctx->target_ip",&(rslv_ctx->target_ip));

  if( !_rhp_atomic_read(&(rslv_ctx->rx_ifc->is_active)) ||
  		!_rhp_atomic_read(&(rx_vpn->is_active)) ){

  	// TODO: If packets are queued from other VPN connections,
  	//       they are also discarded. Umm...

  	RHP_TRC(0,RHPTRCID_NEIGH_RESOLVE_TIMER_VPN_OR_IFC_NOT_ACTIVE,"xxxx",arg,timer,rslv_ctx->rx_ifc,rx_vpn);
  	goto error;
  }

	br_c_dst = _rhp_bridge_neigh_cache_get_by_tgt_ip(rslv_ctx->vpn_realm_id,
									rslv_ctx->addr_family,rslv_ctx->target_ip.addr.raw);

  if( br_c_dst && !br_c_dst->stale ){

  	tx_pkt_tmp = _rhp_pkt_q_peek(&(rslv_ctx->pkt_q));

  	while( tx_pkt_tmp ){
    	memcpy(tx_pkt_tmp->l2.eth->dst_addr,br_c_dst->target_mac,6);
  		tx_pkt_tmp = tx_pkt_tmp->next;
  	}

  	_rhp_neigh_resolve_delete(rslv_ctx);

  	rslv_ok = 1;

  }else{

		if( rslv_ctx->retries > retry_times ){
			goto error;
		}

		if( rslv_ctx->addr_family == AF_INET ){

			req_pkt = _rhp_arp_new_request(rslv_ctx->sender_mac,rslv_ctx->target_mac,
									rslv_ctx->sender_ip.addr.v4,rslv_ctx->target_ip.addr.v4,
									rslv_ctx->rx_ifc);

			rhp_bridge_cache_statistics_tbl.arp.pxy_arp_tx_req_retried++;

		}else if( rslv_ctx->addr_family == AF_INET6 ){

			req_pkt = _rhp_nd_new_solicitation(rslv_ctx->sender_mac,
									rslv_ctx->sender_ip.addr.v6,rslv_ctx->target_ip.addr.v6,
									rslv_ctx->rx_ifc);

			rhp_bridge_cache_statistics_tbl.v6_neigh.pxy_nd_tx_sol_retried++;
		}

		if( req_pkt == NULL ){
			// Retry later in timer handler.
		}

		rslv_ctx->retries++;

		rhp_timer_reset(timer);
		rhp_timer_add(timer,timeout);
  }

	RHP_UNLOCK(&rhp_bridge_lock);


	//
	// No lock(rhp_bridge_lock) is needed anymore.
	//

  if( req_pkt ){

  	// rx_vpn is used for split-horizon of the ARP broadcast request.
  	rhp_bridge_pkt_from_vpn(req_pkt,rx_vpn);
  	rhp_pkt_unhold(req_pkt);
  }


  if( rslv_ok ){

		while( 1 ){

			tx_pkt_tmp = _rhp_pkt_q_deq(&(rslv_ctx->pkt_q));
			if( tx_pkt_tmp == NULL ){
				break;
			}

			rslv_ctx->pkt_q_num--;

	  	rhp_bridge_pkt_from_vpn(tx_pkt_tmp,(rhp_vpn*)RHP_VPN_REF((rhp_vpn_ref*)tx_pkt_tmp->priv));

			if( tx_pkt_tmp->priv ){
				rhp_vpn_unhold((rhp_vpn_ref*)tx_pkt_tmp->priv);
			}

			rhp_pkt_unhold(tx_pkt_tmp);

			if( rslv_ctx->addr_family == AF_INET ){
				rhp_bridge_cache_statistics_tbl.dc.arp.pxy_arp_queued_num--;
			}else if( rslv_ctx->addr_family == AF_INET ){
				rhp_bridge_cache_statistics_tbl.dc.v6_neigh.pxy_nd_queued_num--;
			}
		}

		_rhp_neigh_resolve_free(rslv_ctx);
  }

  RHP_TRC(0,RHPTRCID_NEIGH_RESOLVE_TIMER_RTRN,"xx",arg,timer);
	return;

error:
	_rhp_neigh_resolve_delete(rslv_ctx);
	_rhp_neigh_resolve_free(rslv_ctx);

  if( br_c_dst &&
  		!br_c_dst->static_cache && br_c_dst->stale ){

		if( !_rhp_bridge_neigh_cache_delete(br_c_dst) ){
			_rhp_bridge_free_neigh_cache(br_c_dst);
		}
  }

	if( rslv_ctx->addr_family == AF_INET ){
		rhp_bridge_cache_statistics_tbl.arp.pxy_arp_req_rslv_err++;
	}else if( rslv_ctx->addr_family == AF_INET ){
		rhp_bridge_cache_statistics_tbl.v6_neigh.pxy_nd_sol_rslv_err++;
	}

	RHP_UNLOCK(&rhp_bridge_lock);

  if( req_pkt ){
  	rhp_pkt_unhold(req_pkt);
  }

  RHP_TRC(0,RHPTRCID_NEIGH_RESOLVE_TIMER_ERR,"xx",arg,timer);
	return;
}

static rhp_neigh_rslv_ctx* _rhp_neigh_resolve_ctx_alloc(int addr_family)
{
	rhp_neigh_rslv_ctx* rslv_ctx = NULL;

	rslv_ctx = (rhp_neigh_rslv_ctx*)_rhp_malloc(sizeof(rhp_neigh_rslv_ctx));
	if( rslv_ctx == NULL ){
		RHP_BUG("");
		return NULL;
	}
	memset(rslv_ctx,0,sizeof(rhp_neigh_rslv_ctx));

	rslv_ctx->tag[0] = '#';
	rslv_ctx->tag[1] = 'N';
	rslv_ctx->tag[2] = 'E';
	rslv_ctx->tag[3] = 'R';

	rslv_ctx->addr_family = addr_family;

	rhp_timer_init(&(rslv_ctx->timer),_rhp_neigh_resolve_timer,rslv_ctx);

	_rhp_pkt_q_init(&(rslv_ctx->pkt_q));

	rslv_ctx->created_time = _rhp_get_time();

  RHP_TRC(0,RHPTRCID_NEIGH_RESOLVE_CTX_ALLOC,"x",rslv_ctx);
  return rslv_ctx;
}

static rhp_neigh_rslv_ctx* _rhp_bridge_resolve_ctx_init(
		int addr_family,
		unsigned long rlm_id,
		rhp_vpn* src_vpn,rhp_ifc_entry* src_ifc,
		u8* sender_mac,u8* target_mac,
		u8* sender_ip,u8* target_ip)
{
	rhp_neigh_rslv_ctx* rslv_ctx;
	int ip_len;

	if( addr_family == AF_INET ){
		ip_len = 4;
	}else if( addr_family == AF_INET6 ){
		ip_len = 16;
	}else{
		RHP_BUG("");
		return NULL;
	}

	rslv_ctx = _rhp_neigh_resolve_ctx_alloc(addr_family);
	if( rslv_ctx == NULL ){
		RHP_BUG("");
		return NULL;
	}

	rslv_ctx->vpn_realm_id = rlm_id;

	if( src_vpn ){
		rslv_ctx->rx_vpn_ref = rhp_vpn_hold_ref(src_vpn);
	}

	rslv_ctx->rx_if_index = src_ifc->if_index;
	rslv_ctx->rx_ifc = src_ifc;
	rhp_ifc_hold(src_ifc);

	memcpy(rslv_ctx->sender_mac,sender_mac,6);
	if( target_mac && !_rhp_mac_addr_null(target_mac) ){
		memcpy(rslv_ctx->target_mac,target_mac,6);
	}else{
		memset(rslv_ctx->target_mac,0,6);
	}

	rslv_ctx->target_ip.addr_family = addr_family;
	memcpy(rslv_ctx->target_ip.addr.raw,target_ip,ip_len);

	rslv_ctx->sender_ip.addr_family = addr_family;
	memcpy(rslv_ctx->sender_ip.addr.raw,sender_ip,ip_len);

	return rslv_ctx;
}




struct _rhp_bridge_arp_rslv_ctx {

	u8 tag[4]; // '#ARC'

	unsigned long rlm_id;

	rhp_vpn_ref* src_vpn_ref;
	rhp_ifc_entry* src_ifc;

	u8 sender_mac[6];
	u8 target_mac[6];

	u32 sender_ipv4;
	u32 target_ipv4;

	rhp_packet_ref* tx_pkt_ref;
};
typedef struct _rhp_bridge_arp_rslv_ctx	rhp_bridge_arp_rslv_ctx;

static rhp_bridge_arp_rslv_ctx* _rhp_bridge_arp_exec_rslv_alloc_ctx(
		unsigned long rlm_id,
		rhp_vpn* src_vpn,rhp_ifc_entry* src_ifc,
		u8* sender_mac,u8* target_mac,
		u32 sender_ipv4,u32 target_ipv4,
		rhp_packet* tx_pkt) // tx_pkt may be NULL.
{
	rhp_bridge_arp_rslv_ctx* arp_exec_rslv_ctx
		= (rhp_bridge_arp_rslv_ctx*)_rhp_malloc(sizeof(rhp_bridge_arp_rslv_ctx));

	if( arp_exec_rslv_ctx == NULL ){
		RHP_BUG("");
		return NULL;
	}

	arp_exec_rslv_ctx->tag[0] = '#';
	arp_exec_rslv_ctx->tag[1] = 'A';
	arp_exec_rslv_ctx->tag[2] = 'R';
	arp_exec_rslv_ctx->tag[3] = 'C';

	arp_exec_rslv_ctx->rlm_id = rlm_id;

	arp_exec_rslv_ctx->src_vpn_ref = rhp_vpn_hold_ref(src_vpn);

	arp_exec_rslv_ctx->src_ifc = src_ifc;
	rhp_ifc_hold(src_ifc);

	if( sender_mac ){
		memcpy(arp_exec_rslv_ctx->sender_mac,sender_mac,6);
	}else{
		memset(arp_exec_rslv_ctx->sender_mac,0,6);
	}

	if( target_mac ){
		memcpy(arp_exec_rslv_ctx->target_mac,target_mac,6);
	}else{
		memset(arp_exec_rslv_ctx->target_mac,0,6);
	}

	if( sender_ipv4 ){
		arp_exec_rslv_ctx->sender_ipv4 = sender_ipv4;
	}else{
		arp_exec_rslv_ctx->sender_ipv4 = 0;
	}

	arp_exec_rslv_ctx->target_ipv4 = target_ipv4;

	if( tx_pkt ){
		arp_exec_rslv_ctx->tx_pkt_ref = rhp_pkt_hold_ref(tx_pkt);
	}else{
		arp_exec_rslv_ctx->tx_pkt_ref = NULL;
	}

	return arp_exec_rslv_ctx;
}

void _rhp_bridge_arp_exec_rslv_free_ctx(rhp_bridge_arp_rslv_ctx* arp_exec_rslv_ctx)
{

	rhp_vpn_unhold(arp_exec_rslv_ctx->src_vpn_ref);
	rhp_ifc_unhold(arp_exec_rslv_ctx->src_ifc);

	if(arp_exec_rslv_ctx->tx_pkt_ref){
		rhp_pkt_unhold(arp_exec_rslv_ctx->tx_pkt_ref);
	}

	_rhp_free(arp_exec_rslv_ctx);

	return;
}

static void _rhp_bridge_arp_exec_resolve_task(int worker_index,void *ctx)
{
	int err = -EINVAL;
	rhp_bridge_arp_rslv_ctx* arp_exec_rslv_ctx = (rhp_bridge_arp_rslv_ctx*)ctx;
	rhp_vpn* src_vpn = RHP_VPN_REF(arp_exec_rslv_ctx->src_vpn_ref);
	rhp_neigh_rslv_ctx* rslv_ctx = NULL;
	rhp_packet* tx_pkt = RHP_PKT_REF(arp_exec_rslv_ctx->tx_pkt_ref);
	rhp_packet* arp_req_pkt = NULL;
	int use_laddr = 0;

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_ARP_EXEC_RESOLVE_TASK,"dxxxMM44dd",worker_index,arp_exec_rslv_ctx,src_vpn,arp_exec_rslv_ctx->src_ifc,arp_exec_rslv_ctx->sender_mac,arp_exec_rslv_ctx->target_mac,arp_exec_rslv_ctx->sender_ipv4,arp_exec_rslv_ctx->target_ipv4,rhp_bridge_cache_statistics_tbl.dc.neigh.resolving_addrs,rhp_gcfg_ipv6_disabled);


	RHP_LOCK(&(src_vpn->lock));

	if( !_rhp_atomic_read(&(src_vpn->is_active)) ){
		RHP_UNLOCK(&(src_vpn->lock));
		err = -EINVAL;
		goto error;
	}


	if( arp_exec_rslv_ctx->sender_ipv4 ){

		rhp_ip_addr_list* internal_ifc_addr = NULL, *internal_ifc_addrs = NULL;
		rhp_vpn_realm* rlm = src_vpn->rlm;

		if( rlm == NULL ){
			RHP_UNLOCK(&(src_vpn->lock));
			err = -EINVAL;
			goto error;
		}


		RHP_LOCK(&(rlm->lock));

		if( !_rhp_atomic_read(&(rlm->is_active)) ){
			RHP_UNLOCK(&(rlm->lock));
			RHP_UNLOCK(&(src_vpn->lock));
			err = -EINVAL;
			goto error;
		}

		if( rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_NONE ){
			internal_ifc_addrs = rlm->internal_ifc->bridge_addrs;
		}else{
			internal_ifc_addrs = rlm->internal_ifc->addrs;
		}

		internal_ifc_addr = internal_ifc_addrs;
		while( internal_ifc_addr ){

			rhp_ip_addr_dump("internal_ifc_addr_v4",&(internal_ifc_addr->ip_addr));

			if( internal_ifc_addr->ip_addr.addr_family == AF_INET &&
					rhp_ip_same_subnet(&(internal_ifc_addr->ip_addr),AF_INET,(u8*)&(arp_exec_rslv_ctx->sender_ipv4)) ){
				break;
			}

			internal_ifc_addr = internal_ifc_addr->next;
		}

		if( internal_ifc_addr == NULL ){
			use_laddr = 1;
		}

		RHP_UNLOCK(&(rlm->lock));
	}


	if( use_laddr ||
			_rhp_mac_addr_null(arp_exec_rslv_ctx->sender_mac) ||
			!arp_exec_rslv_ctx->sender_ipv4 ){

		rhp_ip_addr_list* nhs_next_hop_addr = src_vpn->nhrp.nhs_next_hop_addrs;

		while( nhs_next_hop_addr ){

			rhp_ip_addr_dump("nhs_next_hop_addr_v4",&(nhs_next_hop_addr->ip_addr));

			if( nhs_next_hop_addr->ip_addr.addr_family == AF_INET ){
				break;
			}

			nhs_next_hop_addr = nhs_next_hop_addr->next;
		}

		if( nhs_next_hop_addr == NULL ){
			RHP_UNLOCK(&(src_vpn->lock));
			err = -ENOENT;
			goto error;
		}

		memcpy(arp_exec_rslv_ctx->sender_mac,src_vpn->internal_net_info.dummy_peer_mac,6);
		arp_exec_rslv_ctx->sender_ipv4 = nhs_next_hop_addr->ip_addr.addr.v4;
	}

	RHP_UNLOCK(&(src_vpn->lock));



	RHP_LOCK(&rhp_bridge_lock);

	rslv_ctx = _rhp_neigh_resolve_get(arp_exec_rslv_ctx->rlm_id,AF_INET,(u8*)&(arp_exec_rslv_ctx->target_ipv4));
	if( rslv_ctx == NULL ){

		if( rhp_bridge_cache_statistics_tbl.dc.neigh.resolving_addrs
					> (unsigned long)rhp_gcfg_neigh_resolve_max_addrs ){

			RHP_UNLOCK(&rhp_bridge_lock);

			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_ARP_EXEC_RESOLVE_TASK_MAX_ADDRS_REACHED,"xxxMM44d",arp_exec_rslv_ctx,src_vpn,arp_exec_rslv_ctx->src_ifc,arp_exec_rslv_ctx->sender_mac,arp_exec_rslv_ctx->target_mac,arp_exec_rslv_ctx->sender_ipv4,arp_exec_rslv_ctx->target_ipv4,rhp_bridge_cache_statistics_tbl.dc.neigh.resolving_addrs);

			err = RHP_STATUS_ARP_MAX_ADDRS_REACHED;
			goto error;
		}

		rslv_ctx = _rhp_bridge_resolve_ctx_init(AF_INET,arp_exec_rslv_ctx->rlm_id,
										src_vpn,arp_exec_rslv_ctx->src_ifc,
										arp_exec_rslv_ctx->sender_mac,arp_exec_rslv_ctx->target_mac,
										(u8*)&(arp_exec_rslv_ctx->sender_ipv4),(u8*)&(arp_exec_rslv_ctx->target_ipv4));
		if( rslv_ctx == NULL ){

			RHP_UNLOCK(&rhp_bridge_lock);

			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}



		arp_req_pkt = _rhp_arp_new_request(arp_exec_rslv_ctx->sender_mac,arp_exec_rslv_ctx->target_mac,
											arp_exec_rslv_ctx->sender_ipv4,arp_exec_rslv_ctx->target_ipv4,
											arp_exec_rslv_ctx->src_ifc);
		if( arp_req_pkt == NULL ){
			// Retry later in timer handler.
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_ARP_EXEC_RESOLVE_RETRY_LATER,"xxxM44",arp_exec_rslv_ctx,src_vpn,arp_exec_rslv_ctx->src_ifc,arp_exec_rslv_ctx->sender_mac,arp_exec_rslv_ctx->sender_ipv4,arp_exec_rslv_ctx->target_ipv4);
		}

		_rhp_neigh_resolve_put(rslv_ctx);

		rhp_timer_add(&(rslv_ctx->timer),rhp_gcfg_arp_resolve_timeout);

		rhp_bridge_cache_statistics_tbl.arp.pxy_arp_tx_req++;
	}


	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV6_ARP_RSLV_Q_PKT_TO_CACHE,"xx4xd",arp_exec_rslv_ctx,tx_pkt,arp_exec_rslv_ctx->target_ipv4,rslv_ctx,rslv_ctx->pkt_q_num);

	if( tx_pkt ){

		if( rslv_ctx->pkt_q_num > rhp_gcfg_neigh_resolve_max_q_pkts ){

			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV4_ARP_RSLV_MAX_Q_PKTS_REACHED,"xx4x",arp_exec_rslv_ctx,tx_pkt,arp_exec_rslv_ctx->target_ipv4,rslv_ctx);

		}else{

			tx_pkt->priv = rhp_vpn_hold_ref(src_vpn);

			_rhp_pkt_q_enq(&(rslv_ctx->pkt_q),tx_pkt);
			rhp_pkt_hold(tx_pkt);
			rslv_ctx->pkt_q_num++;

			rhp_pkt_pending(tx_pkt);

			rhp_bridge_cache_statistics_tbl.v6_neigh.pxy_nd_queued_packets++;
			rhp_bridge_cache_statistics_tbl.dc.v6_neigh.pxy_nd_queued_num++;
		}
	}

	RHP_UNLOCK(&rhp_bridge_lock);


	if( arp_req_pkt ){

		rhp_bridge_pkt_from_vpn(arp_req_pkt,src_vpn);
  	rhp_pkt_unhold(arp_req_pkt);
  }

	_rhp_bridge_arp_exec_rslv_free_ctx(arp_exec_rslv_ctx);

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_ARP_EXEC_RESOLVE_TASK_RTRN,"xxxx",arp_exec_rslv_ctx,src_vpn,arp_exec_rslv_ctx,arp_req_pkt);
	return;

error:

	if( arp_req_pkt ){
  	rhp_pkt_unhold(arp_req_pkt);
  }

	_rhp_bridge_arp_exec_rslv_free_ctx(arp_exec_rslv_ctx);

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_ARP_EXEC_RESOLVE_TASK_ERR,"xxxE",arp_exec_rslv_ctx,src_vpn,arp_exec_rslv_ctx,err);
	return;
}

// Caller must acquire the rhp_bridge_lock lock.
static int _rhp_bridge_arp_exec_resolve(
		unsigned long rlm_id,
		rhp_vpn* src_vpn,rhp_ifc_entry* src_ifc,
		u8* sender_mac,u8* target_mac,
		u32 sender_ipv4,u32 target_ipv4,
		rhp_packet* tx_pkt)
{
	int err = -EINVAL;
	rhp_bridge_arp_rslv_ctx* arp_exec_rslv_ctx = NULL;

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_ARP_EXEC_RESOLVE,"xxMM44dd",src_vpn,src_ifc,sender_mac,target_mac,sender_ipv4,target_ipv4,rhp_bridge_cache_statistics_tbl.dc.neigh.resolving_addrs,rhp_gcfg_ipv6_disabled);

	if( rhp_bridge_cache_statistics_tbl.dc.neigh.resolving_addrs
				> (unsigned long)rhp_gcfg_neigh_resolve_max_addrs ){

		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_ARP_EXEC_RESOLVE_MAX_ADDRS_REACHED,"xxMM44dx",src_vpn,src_ifc,sender_mac,target_mac,sender_ipv4,target_ipv4,rhp_bridge_cache_statistics_tbl.dc.neigh.resolving_addrs,tx_pkt);

		err = RHP_STATUS_ARP_MAX_ADDRS_REACHED;
		goto error;
	}

	arp_exec_rslv_ctx = _rhp_bridge_arp_exec_rslv_alloc_ctx(rlm_id,src_vpn,src_ifc,
									sender_mac,target_mac,sender_ipv4,target_ipv4,tx_pkt);

	if( arp_exec_rslv_ctx == NULL ){
		err = -ENOMEM;
		goto error;
	}


	err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_3,_rhp_bridge_arp_exec_resolve_task,arp_exec_rslv_ctx);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}


	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_ARP_EXEC_RESOLVE_RTRN,"xxx",arp_exec_rslv_ctx,src_vpn,tx_pkt);
	return 0;

error:
	if( arp_exec_rslv_ctx ){
		_rhp_bridge_arp_exec_rslv_free_ctx(arp_exec_rslv_ctx);
	}
	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_ARP_EXEC_RESOLVE_ERR,"xxxE",arp_exec_rslv_ctx,src_vpn,tx_pkt,err);
	return err;
}


static void _rhp_bridge_arp_exec_probe(
		rhp_bridge_neigh_cache* br_c_n_dst,
		rhp_vpn* rx_vpn,rhp_ifc_entry* rx_ifc,
		u8* sender_mac,u8* target_mac,
		u32 sender_ipv4,u32 target_ipv4)
{
	rhp_neigh_rslv_ctx* rslv_ctx = NULL;
	time_t now = _rhp_get_time();

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_ARP_EXEC_PROBE,"xxxMM44",br_c_n_dst,rx_vpn,rx_ifc,sender_mac,target_mac,sender_ipv4,target_ipv4);

	if( !br_c_n_dst->last_probed_time ||
			(now - br_c_n_dst->last_probed_time) > rhp_gcfg_arp_reprobe_min_interval ){

		rslv_ctx = _rhp_neigh_resolve_get(br_c_n_dst->vpn_realm_id,AF_INET,(u8*)&target_ipv4);
		if( rslv_ctx == NULL ){

			if( !_rhp_bridge_arp_exec_resolve(br_c_n_dst->vpn_realm_id,
						rx_vpn,rx_ifc,sender_mac,target_mac,sender_ipv4,target_ipv4,NULL) ){

				br_c_n_dst->last_probed_time = _rhp_get_time();
			}
		}

		rslv_ctx = NULL;

	}else{

		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_ARP_EXEC_PROBE_TOO_FREQ,"xxxMM44",br_c_n_dst,rx_vpn,rx_ifc,sender_mac,target_mac,sender_ipv4,target_ipv4);
	}

	return;
}



extern u64 rhp_ip_routing_get_tick();

int rhp_bridge_pkt_from_vpn_ipv4_arp_rslv(unsigned long vpn_realm_id,
		rhp_vpn* rx_vpn,rhp_vpn_realm* rx_rlm,rhp_packet* tx_pkt,
		int dmvpn_enabled)
{
	rhp_bridge_neigh_cache* br_c_n_dst = NULL;
	int err = -EINVAL;
	rhp_ip_addr_list *internal_ifc_addrs = NULL, *internal_ifc_addr;
	u32 target_ipv4;
	int rslv_ok = 0;
	int tx_nhrp_trf_ind = 0;
	int dst_local_subnet = 0;

  RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV4_ARP_RSLV,"uxxd",vpn_realm_id,rx_vpn,rx_rlm,tx_pkt,dmvpn_enabled);
  rhp_pkt_trace_dump("rhp_bridge_pkt_from_vpn_ipv4_arp_rslv",tx_pkt);


	if( tx_pkt->l2.raw == NULL || tx_pkt->l3.raw == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

  RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV4_ARP_RSLV_PKT,"xa",tx_pkt,tx_pkt->len,RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,tx_pkt->l2.raw);

	if( !tx_pkt->l3.iph_v4->dst_addr || !tx_pkt->l3.iph_v4->src_addr ){
	  RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV4_ARP_RSLV_NULL_ADDR,"xdp",tx_pkt,(tx_pkt->l3.raw - tx_pkt->head),sizeof(rhp_proto_ip_v4),tx_pkt->l3.iph_v4);
		return -EINVAL;
	}

	target_ipv4 = tx_pkt->l3.iph_v4->dst_addr;

	if( target_ipv4 == 0xFFFFFFFF ){

		tx_pkt->l2.eth->dst_addr[0] = 0xFF;
		tx_pkt->l2.eth->dst_addr[1] = 0xFF;
		tx_pkt->l2.eth->dst_addr[2] = 0xFF;
		tx_pkt->l2.eth->dst_addr[3] = 0xFF;
		tx_pkt->l2.eth->dst_addr[4] = 0xFF;
		tx_pkt->l2.eth->dst_addr[5] = 0xFF;
		rslv_ok = 1;

		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV4_ARP_RSLV_IP_BROADCAST,"xM",tx_pkt,tx_pkt->l2.eth->dst_addr);

	}else if( rhp_ip_multicast(AF_INET,(u8*)&target_ipv4) ){

		rhp_ip_gen_multicast_mac(AF_INET,(u8*)&target_ipv4,tx_pkt->l2.eth->dst_addr);
		rslv_ok = 1;

		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV4_ARP_RSLV_IP_MULTICAST,"xM",tx_pkt,tx_pkt->l2.eth->dst_addr);
	}

	{
		RHP_LOCK(&(rx_rlm->lock));

		rx_rlm->statistics.bridge.rx_from_vpn_ipip_pkts++;


    if( !rslv_ok ){

			if( !_rhp_atomic_read(&(rx_rlm->is_active)) ){
				RHP_UNLOCK(&(rx_rlm->lock));
				RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV4_ARP_RSLV_RLM_NOT_ACTIVE,"xx",rx_rlm,tx_pkt);
				return RHP_STATUS_INVALID_STATE;
			}

			if( rx_rlm->internal_ifc == NULL ){
				RHP_UNLOCK(&(rx_rlm->lock));
				RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV4_ARP_RSLV_NO_ACTIVE_IF,"xx",rx_rlm,tx_pkt);
				return RHP_STATUS_INVALID_STATE;
			}

			if( rhp_ipv4_is_linklocal(target_ipv4) ){

				RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV4_ND_RSLV_DST_LINKLOCAL,"x4",tx_pkt,target_ipv4);
				rx_rlm->statistics.bridge.rx_from_vpn_ipip_same_subnet_pkts++;

				dst_local_subnet = 1;

			}else{

				if( rx_rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_NONE ){

					internal_ifc_addrs = rx_rlm->internal_ifc->bridge_addrs;

					RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV4_ARP_RSLV_ADDR_NONE,"xx",rx_rlm,tx_pkt);

				}else{

					internal_ifc_addrs = rx_rlm->internal_ifc->addrs;
				}

				internal_ifc_addr = internal_ifc_addrs;
				while( internal_ifc_addr ){

					if( internal_ifc_addr->ip_addr.addr_family == AF_INET &&
							rhp_ip_same_subnet(&(internal_ifc_addr->ip_addr),AF_INET,(u8*)&target_ipv4) ){
						break;
					}

					internal_ifc_addr = internal_ifc_addr->next;
				}

				if( internal_ifc_addr ){

					if( rhp_ip_subnet_broadcast(&(internal_ifc_addr->ip_addr),AF_INET,(u8*)&target_ipv4) ){

						//
						// Bridging to Local IP subnet.
						//

						tx_pkt->l2.eth->dst_addr[0] = 0xFF;
						tx_pkt->l2.eth->dst_addr[1] = 0xFF;
						tx_pkt->l2.eth->dst_addr[2] = 0xFF;
						tx_pkt->l2.eth->dst_addr[3] = 0xFF;
						tx_pkt->l2.eth->dst_addr[4] = 0xFF;
						tx_pkt->l2.eth->dst_addr[5] = 0xFF;
						rslv_ok = 1;

						RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV4_ARP_RSLV_IP_SUBNET_BROADCAST,"xM",tx_pkt,tx_pkt->l2.eth->dst_addr);
						rx_rlm->statistics.bridge.rx_from_vpn_ipip_subnet_broadcast_pkts++;

					}else{

						//
						// Bridging to Local IP subnet.
						//

						RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV4_ARP_RSLV_IP_LOCAL_SUBNET,"x4",tx_pkt,target_ipv4);
						rx_rlm->statistics.bridge.rx_from_vpn_ipip_same_subnet_pkts++;

						dst_local_subnet = 1;
					}

					rhp_ip_addr_dump("internal_ifc_addr_4",&(internal_ifc_addr->ip_addr));

				}else{

					//
					// Try IP Forwarding...
					//

					if( !rhp_ip_addr_null(&(rx_rlm->internal_ifc->gw_addr)) ){ // Bridge

						//
						//                                             packet---->>
						// [Remote nodes]--==<IPsec Tunnel>==--[This machine: Bridge]--+--[Router(nexthop)]---<protected networks>
						//                                                                                          |
						//                                                                                          +--[local nodes]

						target_ipv4 = rx_rlm->internal_ifc->gw_addr.addr.v4;

						RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV4_ARP_RSLV_IP_BRIDGE_FWD_TO_ROUTER,"x4",tx_pkt,target_ipv4);
						rx_rlm->statistics.bridge.rx_from_vpn_ipip_fwd_nexthop_pkts++;

					}else	if( !rhp_ip_addr_null(&(rx_rlm->internal_ifc->sys_def_gw_addr)) ){ // Bridge

						//
						//                                            packet---->>
						// [Remote nodes]--==<IPsec Tunnel>==--[This machine: Bridge]--+--[Router(nexthop)]---<protected networks>
						//                                                                                          |
						//                                                                                          +--[local nodes]

						target_ipv4 = rx_rlm->internal_ifc->sys_def_gw_addr.addr.v4;

						RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV4_ARP_RSLV_IP_BRIDGE_FWD_TO_SYS_DEF_ROUTER,"x4",tx_pkt,target_ipv4);
						rx_rlm->statistics.bridge.rx_from_vpn_ipip_fwd_nexthop_pkts++;

					}else{

						unsigned long out_realm_id = 0;

						//
						//                                                     packet---->>
						// [Remote node X]--==<IPsec Tunnel>==--[This machine: Bridge and/or Router]--==<IPsec Tunnel>==--[Remote node Y]
						// (Realm A)                                                                                      (Realm A)
						//


						if( tx_pkt->l3.iph_v4->ttl <= 1 ){

							RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV4_ARP_RSLV_TTL_EXPIRED,"xx",rx_rlm,tx_pkt);
							err = RHP_STATUS_IP_ROUTING_HOPLIMIT_TTL_EXCEEDED;

							goto ip_routing_error;
						}

						_rhp_proto_ip_v4_dec_ttl(tx_pkt->l3.iph_v4);


						err = rhp_ip_routing_v4(
										tx_pkt->l3.iph_v4->src_addr,tx_pkt->l3.iph_v4->dst_addr,rx_vpn,
										&target_ipv4,&out_realm_id,
										(dmvpn_enabled ? &tx_nhrp_trf_ind : NULL));

						if( err || out_realm_id == 0 || out_realm_id != rx_rlm->id ){

							//
							// TODO: Inter-vpn-realm NHRP short-cut support.
							//
							tx_nhrp_trf_ind = 0;


							internal_ifc_addr = internal_ifc_addrs;
							while( internal_ifc_addr ){

								if( internal_ifc_addr->ip_addr.addr_family == AF_INET &&
										!rhp_ipv4_is_loopback(internal_ifc_addr->ip_addr.addr.v4) &&
										!rhp_ipv4_is_linklocal(internal_ifc_addr->ip_addr.addr.v4)){
									break;
								}

								internal_ifc_addr = internal_ifc_addr->next;
							}

							if( internal_ifc_addr ){

								//
								//                                                                                +--[local nodes]
								// (Realm A)                                  packet---->>                        |
								// [Remote nodes]--==<IPsec Tunnel>==--[This machine: Bridge and/or Router]---<protected networks>
								//                                                              |
								//                                                              +--==<IPsec Tunnel>==--[Remote nodes]
								//                                                                                     (Realm B)
								//

								target_ipv4 = internal_ifc_addr->ip_addr.addr.v4;

								RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV4_ARP_RSLV_IP_ROUTING,"x4",tx_pkt,target_ipv4);
								rx_rlm->statistics.bridge.rx_from_vpn_ipip_fwd_thisnode_pkts++;

							}else{

								err = RHP_STATUS_INVALID_STATE;

ip_routing_error:
								RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV4_ARP_RSLV_INVALID_CFG,"xx",rx_rlm,tx_pkt);
								rx_rlm->statistics.bridge.rx_from_vpn_ipip_fwd_err_pkts++;

								RHP_UNLOCK(&(rx_rlm->lock));

								RHP_LOCK(&rhp_bridge_lock);
								rhp_bridge_cache_statistics_tbl.bridge.rx_from_vpn_ipip_fwd_err_pkts++;
								RHP_UNLOCK(&rhp_bridge_lock);

								return err;
							}

						}else{

							rx_rlm->statistics.bridge.rx_from_vpn_ipip_fwd_nexthop_pkts++;
						}
					}
				}
			}

    }else{

  		rx_rlm->statistics.bridge.rx_from_vpn_ipip_broadcast_pkts++;
    }

    RHP_UNLOCK(&(rx_rlm->lock));
	}


	if( !rslv_ok ){

		RHP_LOCK(&rhp_bridge_lock);

		br_c_n_dst = _rhp_bridge_neigh_cache_get_by_tgt_ip(vpn_realm_id,AF_INET,(u8*)&(target_ipv4));
		if( br_c_n_dst ){

			memcpy(tx_pkt->l2.eth->dst_addr,br_c_n_dst->target_mac,6);

			rslv_ok = 1;
			br_c_n_dst->last_used_cnt++;

			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV4_ARP_RSLV_GET_FROM_CACHE,"x4Mxdd",tx_pkt,target_ipv4,tx_pkt->l2.eth->dst_addr,br_c_n_dst,br_c_n_dst->stale,br_c_n_dst->last_used_cnt);

			if( !br_c_n_dst->static_cache && br_c_n_dst->stale ){

  			//
  			// The end node (IP over IPsec) doesn't resolve the dest MAC address
  			// and so Rockhopper's ARP proxy needs to probe it again.
  			//

				// Probing by unicast Dst-MAC address (target address).
				_rhp_bridge_arp_exec_probe(br_c_n_dst,rx_vpn,tx_pkt->rx_ifc,
						tx_pkt->l2.eth->src_addr,tx_pkt->l2.eth->dst_addr,
						tx_pkt->l3.iph_v4->src_addr,target_ipv4);
			}

			if( dst_local_subnet &&
					br_c_n_dst->side == RHP_BRIDGE_SIDE_VPN ){

				u64 rate_limit;
				u64 now_tick = rhp_ip_routing_get_tick(&rate_limit);

			  RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV4_ARP_RSLV_NHRP_TRF_IND,"xqqq",br_c_n_dst,br_c_n_dst->last_tx_nhrp_trf_indication_tick,now_tick,rate_limit);

				if( !br_c_n_dst->last_tx_nhrp_trf_indication_tick ||
						(now_tick - br_c_n_dst->last_tx_nhrp_trf_indication_tick) > rate_limit ){

					tx_nhrp_trf_ind = 1;

					br_c_n_dst->last_tx_nhrp_trf_indication_tick = now_tick;

				}else{

					tx_nhrp_trf_ind = 0;
				}
			}

		}else{

			_rhp_bridge_arp_exec_resolve(rx_vpn->vpn_realm_id,rx_vpn,tx_pkt->rx_ifc,
							tx_pkt->l2.eth->src_addr,NULL,tx_pkt->l3.iph_v4->src_addr,target_ipv4,tx_pkt);
		}

		RHP_UNLOCK(&rhp_bridge_lock);
	}


  if( dmvpn_enabled && tx_nhrp_trf_ind ){

  	rhp_nhrp_invoke_tx_traffic_indication_task(rx_vpn,tx_pkt);
  }

  if( rslv_ok ){

  	rhp_bridge_pkt_from_vpn(tx_pkt,rx_vpn);
  }

  RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV4_ARP_RSLV_RTRN,"uxxddd",vpn_realm_id,rx_vpn,tx_pkt,dmvpn_enabled,tx_nhrp_trf_ind,dst_local_subnet);
  return 0;
}




struct _rhp_bridge_nd_rslv_ctx {

	u8 tag[4]; // '#NRC'

	unsigned long rlm_id;

	rhp_vpn_ref* src_vpn_ref;
	rhp_ifc_entry* src_ifc;

	u8 sender_mac[6];
	u8 target_mac[6];

	u8 sender_ipv6[16];
	u8 target_ipv6[16];

	rhp_packet_ref* tx_pkt_ref;
};
typedef struct _rhp_bridge_nd_rslv_ctx	rhp_bridge_nd_rslv_ctx;

static rhp_bridge_nd_rslv_ctx* _rhp_bridge_nd_exec_rslv_alloc_ctx(
		unsigned long rlm_id,
		rhp_vpn* src_vpn,rhp_ifc_entry* src_ifc,
		u8* sender_mac,u8* target_mac,
		u8* sender_ipv6,u8* target_ipv6,
		rhp_packet* tx_pkt) // tx_pkt may be NULL.
{
	rhp_bridge_nd_rslv_ctx* nd_exec_rslv_ctx
		= (rhp_bridge_nd_rslv_ctx*)_rhp_malloc(sizeof(rhp_bridge_nd_rslv_ctx));

	if( nd_exec_rslv_ctx == NULL ){
		RHP_BUG("");
		return NULL;
	}

	nd_exec_rslv_ctx->tag[0] = '#';
	nd_exec_rslv_ctx->tag[1] = 'N';
	nd_exec_rslv_ctx->tag[2] = 'R';
	nd_exec_rslv_ctx->tag[3] = 'C';

	nd_exec_rslv_ctx->rlm_id = rlm_id;

	nd_exec_rslv_ctx->src_vpn_ref = rhp_vpn_hold_ref(src_vpn);

	nd_exec_rslv_ctx->src_ifc = src_ifc;
	rhp_ifc_hold(src_ifc);

	if( sender_mac ){
		memcpy(nd_exec_rslv_ctx->sender_mac,sender_mac,6);
	}else{
		memset(nd_exec_rslv_ctx->sender_mac,0,6);
	}

	memcpy(nd_exec_rslv_ctx->target_mac,target_mac,6);


	if( sender_ipv6 ){
		memcpy(nd_exec_rslv_ctx->sender_ipv6,sender_ipv6,16);
	}else{
		memset(nd_exec_rslv_ctx->sender_ipv6,0,16);
	}

	memcpy(nd_exec_rslv_ctx->target_ipv6,target_ipv6,16);

	if( tx_pkt ){
		nd_exec_rslv_ctx->tx_pkt_ref = rhp_pkt_hold_ref(tx_pkt);
	}else{
		nd_exec_rslv_ctx->tx_pkt_ref = NULL;
	}

	return nd_exec_rslv_ctx;
}

void _rhp_bridge_nd_exec_rslv_free_ctx(rhp_bridge_nd_rslv_ctx* nd_exec_rslv_ctx)
{

	rhp_vpn_unhold(nd_exec_rslv_ctx->src_vpn_ref);
	rhp_ifc_unhold(nd_exec_rslv_ctx->src_ifc);

	if(nd_exec_rslv_ctx->tx_pkt_ref){
		rhp_pkt_unhold(nd_exec_rslv_ctx->tx_pkt_ref);
	}

	_rhp_free(nd_exec_rslv_ctx);

	return;
}

static void _rhp_bridge_nd_exec_resolve_task(int worker_index,void *ctx)
{
	int err = -EINVAL;
	rhp_bridge_nd_rslv_ctx* nd_exec_rslv_ctx = (rhp_bridge_nd_rslv_ctx*)ctx;
	rhp_vpn* src_vpn = RHP_VPN_REF(nd_exec_rslv_ctx->src_vpn_ref);
	rhp_neigh_rslv_ctx* nd_rslv_ctx = NULL;
	rhp_packet* tx_pkt = RHP_PKT_REF(nd_exec_rslv_ctx->tx_pkt_ref);
	rhp_packet* nd_req_pkt = NULL;
	int use_ll_addr = 0;

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_ND_EXEC_RESOLVE_TASK,"dxxxMM66dd",worker_index,nd_exec_rslv_ctx,src_vpn,nd_exec_rslv_ctx->src_ifc,nd_exec_rslv_ctx->sender_mac,nd_exec_rslv_ctx->target_mac,nd_exec_rslv_ctx->sender_ipv6,nd_exec_rslv_ctx->target_ipv6,rhp_bridge_cache_statistics_tbl.dc.neigh.resolving_addrs,rhp_gcfg_ipv6_disabled);


	RHP_LOCK(&(src_vpn->lock));

	if( !_rhp_atomic_read(&(src_vpn->is_active)) ){
		RHP_UNLOCK(&(src_vpn->lock));
		err = -EINVAL;
		goto error;
	}

	if( !rhp_ipv6_addr_null(nd_exec_rslv_ctx->sender_ipv6) ){

		rhp_ip_addr_list* internal_ifc_addr = NULL, *internal_ifc_addrs = NULL;
		rhp_vpn_realm* rlm = src_vpn->rlm;

		if( rlm == NULL ){
			RHP_UNLOCK(&(src_vpn->lock));
			err = -EINVAL;
			goto error;
		}


		RHP_LOCK(&(rlm->lock));

		if( !_rhp_atomic_read(&(rlm->is_active)) ){
			RHP_UNLOCK(&(rlm->lock));
			RHP_UNLOCK(&(src_vpn->lock));
			err = -EINVAL;
			goto error;
		}

		if( rlm->internal_ifc == NULL ){
			RHP_UNLOCK(&(rlm->lock));
			RHP_UNLOCK(&(src_vpn->lock));
			err = -EINVAL;
			goto error;
		}

		if( rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_NONE ){
			internal_ifc_addrs = rlm->internal_ifc->bridge_addrs;
		}else{
			internal_ifc_addrs = rlm->internal_ifc->addrs;
		}

		internal_ifc_addr = internal_ifc_addrs;
		while( internal_ifc_addr ){

			rhp_ip_addr_dump("internal_ifc_addr_v6",&(internal_ifc_addr->ip_addr));

			// Including LinkLocal address.
			if( internal_ifc_addr->ip_addr.addr_family == AF_INET6 &&
					rhp_ip_same_subnet(&(internal_ifc_addr->ip_addr),AF_INET6,nd_exec_rslv_ctx->sender_ipv6) ){
				break;
			}

			internal_ifc_addr = internal_ifc_addr->next;
		}

		if( internal_ifc_addr == NULL ){
			use_ll_addr = 1;
		}

		RHP_UNLOCK(&(rlm->lock));
	}


	if( use_ll_addr ||
			_rhp_mac_addr_null(nd_exec_rslv_ctx->sender_mac) ||
			rhp_ipv6_addr_null(nd_exec_rslv_ctx->sender_ipv6) ){

		err = rhp_ipv6_rlm_lladdr_get(src_vpn->rlm,nd_exec_rslv_ctx->sender_ipv6,nd_exec_rslv_ctx->sender_mac);
		if( err ){
			RHP_UNLOCK(&(src_vpn->lock));
			goto error;
		}
	}

	RHP_UNLOCK(&(src_vpn->lock));



	RHP_LOCK(&rhp_bridge_lock);

	nd_rslv_ctx = _rhp_neigh_resolve_get(nd_exec_rslv_ctx->rlm_id,AF_INET6,nd_exec_rslv_ctx->target_ipv6);
	if( nd_rslv_ctx == NULL ){

		if( rhp_bridge_cache_statistics_tbl.dc.neigh.resolving_addrs
					> (unsigned long)rhp_gcfg_neigh_resolve_max_addrs ){

			RHP_UNLOCK(&rhp_bridge_lock);

			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_ND_EXEC_RESOLVE_TASK_MAX_ADDRS_REACHED,"xxxMM66d",nd_exec_rslv_ctx,src_vpn,nd_exec_rslv_ctx->src_ifc,nd_exec_rslv_ctx->sender_mac,nd_exec_rslv_ctx->target_mac,nd_exec_rslv_ctx->sender_ipv6,nd_exec_rslv_ctx->target_ipv6,rhp_bridge_cache_statistics_tbl.dc.neigh.resolving_addrs);

			err = RHP_STATUS_ARP_MAX_ADDRS_REACHED;
			goto error;
		}

		nd_rslv_ctx = _rhp_bridge_resolve_ctx_init(AF_INET6,nd_exec_rslv_ctx->rlm_id,
										src_vpn,nd_exec_rslv_ctx->src_ifc,
										nd_exec_rslv_ctx->sender_mac,nd_exec_rslv_ctx->target_mac,
										nd_exec_rslv_ctx->sender_ipv6,nd_exec_rslv_ctx->target_ipv6);
		if( nd_rslv_ctx == NULL ){

			RHP_UNLOCK(&rhp_bridge_lock);

			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}


		nd_req_pkt = _rhp_nd_new_solicitation(nd_exec_rslv_ctx->sender_mac,
									nd_exec_rslv_ctx->sender_ipv6,nd_exec_rslv_ctx->target_ipv6,nd_exec_rslv_ctx->src_ifc);
		if( nd_req_pkt == NULL ){
			// Retry later in timer handler.
			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_ND_EXEC_RESOLVE_TASK_RETRY_LATER,"xxxM66",nd_exec_rslv_ctx,src_vpn,nd_exec_rslv_ctx->src_ifc,nd_exec_rslv_ctx->sender_mac,nd_exec_rslv_ctx->sender_ipv6,nd_exec_rslv_ctx->target_ipv6);
		}

		_rhp_neigh_resolve_put(nd_rslv_ctx);

		rhp_timer_add(&(nd_rslv_ctx->timer),rhp_gcfg_ipv6_nd_resolve_timeout);

		rhp_bridge_cache_statistics_tbl.v6_neigh.pxy_nd_tx_sol++;
	}


	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV6_ND_RSLV_Q_PKT_TO_CACHE,"xx6xd",nd_exec_rslv_ctx,tx_pkt,nd_exec_rslv_ctx->target_ipv6,nd_rslv_ctx,nd_rslv_ctx->pkt_q_num);

	if( tx_pkt ){

		if( nd_rslv_ctx->pkt_q_num > rhp_gcfg_neigh_resolve_max_q_pkts ){

			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV6_ND_RSLV_MAX_Q_PKTS_REACHED,"xx6x",nd_exec_rslv_ctx,tx_pkt,nd_exec_rslv_ctx->target_ipv6,nd_rslv_ctx);

		}else{

			tx_pkt->priv = rhp_vpn_hold_ref(src_vpn);

			_rhp_pkt_q_enq(&(nd_rslv_ctx->pkt_q),tx_pkt);
			rhp_pkt_hold(tx_pkt);
			nd_rslv_ctx->pkt_q_num++;

			rhp_pkt_pending(tx_pkt);

			rhp_bridge_cache_statistics_tbl.v6_neigh.pxy_nd_queued_packets++;
			rhp_bridge_cache_statistics_tbl.dc.v6_neigh.pxy_nd_queued_num++;
		}
	}

	RHP_UNLOCK(&rhp_bridge_lock);


	if( nd_req_pkt ){

		rhp_bridge_pkt_from_vpn(nd_req_pkt,src_vpn);
  	rhp_pkt_unhold(nd_req_pkt);
  }

	_rhp_bridge_nd_exec_rslv_free_ctx(nd_exec_rslv_ctx);

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_ND_EXEC_RESOLVE_TASK_RTRN,"xxxx",nd_exec_rslv_ctx,src_vpn,nd_rslv_ctx,nd_req_pkt);
	return;

error:

	if( nd_req_pkt ){
  	rhp_pkt_unhold(nd_req_pkt);
  }

	 _rhp_bridge_nd_exec_rslv_free_ctx(nd_exec_rslv_ctx);

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_ND_EXEC_RESOLVE_TASK_ERR,"xxxE",nd_exec_rslv_ctx,src_vpn,nd_rslv_ctx,err);
	return;
}

// Caller must acquire the rhp_bridge_lock lock.
static int _rhp_bridge_nd_exec_resolve(
		unsigned long rlm_id,
		rhp_vpn* src_vpn,rhp_ifc_entry* src_ifc,
		u8* sender_mac,u8* target_mac,
		u8* sender_ipv6,u8* target_ipv6,
		rhp_packet* tx_pkt)
{
	int err = -EINVAL;
	rhp_bridge_nd_rslv_ctx* nd_exec_rslv_ctx = NULL;

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_ND_EXEC_RESOLVE,"xxMM66dd",src_vpn,src_ifc,sender_mac,target_mac,sender_ipv6,target_ipv6,rhp_bridge_cache_statistics_tbl.dc.neigh.resolving_addrs,rhp_gcfg_ipv6_disabled);

	if( rhp_gcfg_ipv6_disabled ){
		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_ND_EXEC_RESOLVE_V6_DISABLED,"xx",src_vpn,src_ifc);
		return -EINVAL;
	}

	if( rhp_bridge_cache_statistics_tbl.dc.neigh.resolving_addrs
				> (unsigned long)rhp_gcfg_neigh_resolve_max_addrs ){

		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_ND_EXEC_RESOLVE_MAX_ADDRS_REACHED,"xxMM66dx",src_vpn,src_ifc,sender_mac,target_mac,sender_ipv6,target_ipv6,rhp_bridge_cache_statistics_tbl.dc.neigh.resolving_addrs,tx_pkt);

		err = RHP_STATUS_ARP_MAX_ADDRS_REACHED;
		goto error;
	}

	nd_exec_rslv_ctx = _rhp_bridge_nd_exec_rslv_alloc_ctx(rlm_id,src_vpn,src_ifc,
									sender_mac,target_mac,sender_ipv6,target_ipv6,tx_pkt);

	if( nd_exec_rslv_ctx == NULL ){
		err = -ENOMEM;
		goto error;
	}


	err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_3,_rhp_bridge_nd_exec_resolve_task,nd_exec_rslv_ctx);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}


	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_ND_EXEC_RESOLVE_RTRN,"xxx",nd_exec_rslv_ctx,src_vpn,tx_pkt);
	return 0;

error:
	if( nd_exec_rslv_ctx ){
		_rhp_bridge_nd_exec_rslv_free_ctx(nd_exec_rslv_ctx);
	}
	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_ND_EXEC_RESOLVE_ERR,"xxxE",nd_exec_rslv_ctx,src_vpn,tx_pkt,err);
	return err;
}

static void _rhp_bridge_nd_exec_probe(
		rhp_bridge_neigh_cache* br_c_nd_dst,
		rhp_vpn* rx_vpn,rhp_ifc_entry* rx_ifc,
		u8* sender_mac,u8* target_mac,
		u8* sender_ipv6,u8* target_ipv6)
{
	rhp_neigh_rslv_ctx* nd_rslv_ctx = NULL;
	time_t now = _rhp_get_time();

	RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_ND_EXEC_PROBE,"xxxMM66",br_c_nd_dst,rx_vpn,rx_ifc,sender_mac,target_mac,sender_ipv6,target_ipv6);

	if( rhp_gcfg_ipv6_disabled ){
		return;
	}

	if( !br_c_nd_dst->last_probed_time ||
			(now - br_c_nd_dst->last_probed_time) > rhp_gcfg_ipv6_nd_reprobe_min_interval ){

		nd_rslv_ctx = _rhp_neigh_resolve_get(br_c_nd_dst->vpn_realm_id,AF_INET6,target_ipv6);
		if( nd_rslv_ctx == NULL ){

			if( !_rhp_bridge_nd_exec_resolve(br_c_nd_dst->vpn_realm_id,
						rx_vpn,rx_ifc,sender_mac,target_mac,sender_ipv6,target_ipv6,NULL) ){

				br_c_nd_dst->last_probed_time = _rhp_get_time();
			}
		}

		nd_rslv_ctx = NULL;

	}else{

		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_ND_EXEC_PROBE_TOO_FREQ,"xxxMM66",br_c_nd_dst,rx_vpn,rx_ifc,sender_mac,target_mac,sender_ipv6,target_ipv6);
	}

	return;
}

// TODO: Destination Cache???
int rhp_bridge_pkt_from_vpn_ipv6_nd_rslv(unsigned long vpn_realm_id,rhp_vpn* rx_vpn,
		rhp_vpn_realm* rx_rlm,rhp_packet* tx_pkt,
		int dmvpn_enabled)
{
	rhp_bridge_neigh_cache *br_c_nd_dst = NULL;
	int err = -EINVAL;
	u8 target_ipv6[16];
	int rslv_ok = 0;
	int tx_nhrp_trf_ind = 0;
	int dst_local_subnet = 0;

  RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV6_ND_RSLV,"uxxxd",vpn_realm_id,rx_vpn,rx_rlm,tx_pkt,dmvpn_enabled);
  rhp_pkt_trace_dump("rhp_bridge_pkt_from_vpn_ipv6_nd_rslv",tx_pkt);

  if( rhp_gcfg_ipv6_disabled ){
    RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV6_ND_RSLV_IPV6_DISABLED,"uxx",vpn_realm_id,rx_vpn,tx_pkt);
  	return -EINVAL;
  }

	if( tx_pkt->l2.raw == NULL || tx_pkt->l3.raw == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

  RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV6_ND_RSLV_PKT,"xa",tx_pkt,tx_pkt->len,RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,tx_pkt->l2.raw);

	if( !tx_pkt->l3.iph_v6->dst_addr || !tx_pkt->l3.iph_v6->src_addr ){
	  RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV6_ND_RSLV_NULL_ADDR,"xdp",tx_pkt,(tx_pkt->l3.raw - tx_pkt->head),sizeof(rhp_proto_ip_v6),tx_pkt->l3.iph_v6);
		return -EINVAL;
	}

	memcpy(target_ipv6,tx_pkt->l3.iph_v6->dst_addr,16);

	if( rhp_ip_multicast(AF_INET6,target_ipv6) ){

		rhp_ip_gen_multicast_mac(AF_INET6,target_ipv6,tx_pkt->l2.eth->dst_addr);
		rslv_ok = 1;

		RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV6_ND_RSLV_IP_MULTICAST,"xM",tx_pkt,tx_pkt->l2.eth->dst_addr);
	}

	{
		RHP_LOCK(&(rx_rlm->lock));

		rx_rlm->statistics.bridge.rx_from_vpn_ipip_pkts++;

    if( !rslv_ok ){

			if( !_rhp_atomic_read(&(rx_rlm->is_active)) ){
				RHP_UNLOCK(&(rx_rlm->lock));
				RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV6_ND_RSLV_RLM_NOT_ACTIVE,"xx",rx_rlm,tx_pkt);
				return RHP_STATUS_INVALID_STATE;
			}

			if( rx_rlm->internal_ifc == NULL ){
				RHP_UNLOCK(&(rx_rlm->lock));
				RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV6_ND_RSLV_NO_ACTIVE_IF,"xx",rx_rlm,tx_pkt);
				return RHP_STATUS_INVALID_STATE;
			}

			if( rhp_ipv6_is_linklocal(target_ipv6) ){

				RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV6_ND_RSLV_DST_LINKLOCAL,"x6",tx_pkt,target_ipv6);
				rx_rlm->statistics.bridge.rx_from_vpn_ipip_same_subnet_pkts++;

				dst_local_subnet = 1;

			}else{

				rhp_ip_addr_list *internal_ifc_addr = NULL,*internal_ifc_addrs = NULL;

				if( rx_rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_NONE ){

					internal_ifc_addrs = rx_rlm->internal_ifc->bridge_addrs;

					RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV6_ND_RSLV_ADDR_NONE,"xx",rx_rlm,tx_pkt);

				}else{

					internal_ifc_addrs = rx_rlm->internal_ifc->addrs;
				}

				internal_ifc_addr = internal_ifc_addrs;
				while( internal_ifc_addr ){

					rhp_ip_addr_dump("internal_ifc_addr_v6",&(internal_ifc_addr->ip_addr));

					if( internal_ifc_addr->ip_addr.addr_family == AF_INET6 &&
							rhp_ip_same_subnet(&(internal_ifc_addr->ip_addr),AF_INET6,target_ipv6) ){

						//
						// Bridging to Local IP subnet.
						//

						RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV6_ND_RSLV_IP_LOCAL_SUBNET,"x6",tx_pkt,target_ipv6);
						rx_rlm->statistics.bridge.rx_from_vpn_ipip_same_subnet_pkts++;

						dst_local_subnet = 1;

						break;
					}

					internal_ifc_addr = internal_ifc_addr->next;
				}

				if( internal_ifc_addr == NULL ){

					//
					// Try IP Forwarding...
					//

					if( !rhp_ip_addr_null(&(rx_rlm->internal_ifc->gw_addr_v6)) ){ // Bridge

						//
						//                                             packet---->>
						// [Remote nodes]--==<IPsec Tunnel>==--[This machine: Bridge]--+--[Router(nexthop)]---<protected networks>
						//                                                                                          |
						//                                                                                          +--[local nodes]

						memcpy(target_ipv6,rx_rlm->internal_ifc->gw_addr_v6.addr.v6,16);

						RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV6_ND_RSLV_IP_BRIDGE_FWD_TO_ROUTER,"x6",tx_pkt,target_ipv6);
						rx_rlm->statistics.bridge.rx_from_vpn_ipip_fwd_nexthop_pkts++;

					}else	if( !rhp_ip_addr_null(&(rx_rlm->internal_ifc->sys_def_gw_addr_v6)) ){ // Bridge

						//
						//                                             packet---->>
						// [Remote nodes]--==<IPsec Tunnel>==--[This machine: Bridge]--+--[Router(nexthop)]---<protected networks>
						//                                                                                          |
						//                                                                                          +--[local nodes]

						memcpy(target_ipv6,rx_rlm->internal_ifc->sys_def_gw_addr_v6.addr.v6,16);

						RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV6_ND_RSLV_IP_BRIDGE_FWD_TO_ROUTER,"x6",tx_pkt,target_ipv6);
						rx_rlm->statistics.bridge.rx_from_vpn_ipip_fwd_nexthop_pkts++;

					}else{

						unsigned long out_realm_id = 0;

						//
						//                                                     packet---->>
						// [Remote node X]--==<IPsec Tunnel>==--[This machine: Bridge and/or Router]--==<IPsec Tunnel>==--[Remote node Y]
						// (Realm A)                                                                                      (Realm A)
						//

						if( tx_pkt->l3.iph_v6->hop_limit <= 1 ){

							RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV6_ND_RSLV_HOPLIMIT_EXCEEDED,"xx",rx_rlm,tx_pkt);
							err = RHP_STATUS_IP_ROUTING_HOPLIMIT_TTL_EXCEEDED;

							goto ip_routing_error;
						}


						err = rhp_ip_routing_v6(
										tx_pkt->l3.iph_v6->src_addr,tx_pkt->l3.iph_v6->dst_addr,rx_vpn,
										target_ipv6,&out_realm_id,
										(dmvpn_enabled ? &tx_nhrp_trf_ind : NULL));

						if( err || out_realm_id == 0 || out_realm_id != rx_rlm->id ){

							rhp_ip_addr_list *internal_ifc_addr_ll = NULL;

							//
							// TODO: Inter-vpn-realm NHRP short-cut support.
							//
							tx_nhrp_trf_ind = 0;


							internal_ifc_addr = internal_ifc_addrs;
							while( internal_ifc_addr ){

								if( internal_ifc_addr->ip_addr.addr_family == AF_INET6 ){

									if( rhp_ipv6_is_linklocal(internal_ifc_addr->ip_addr.addr.v6)){
										internal_ifc_addr_ll = internal_ifc_addr;
									}else{
										break;
									}
								}

								internal_ifc_addr = internal_ifc_addr->next;
							}

							if( internal_ifc_addr == NULL && internal_ifc_addr_ll ){
								internal_ifc_addr = internal_ifc_addr_ll;
							}

							if( internal_ifc_addr ){

								//
								//                                                                                +--[local nodes]
								// (Realm A)                                  packet---->>                        |
								// [Remote nodes]--==<IPsec Tunnel>==--[This machine: Bridge and/or Router]---<protected networks>
								//                                                              |
								//                                                              +--==<IPsec Tunnel>==--[Remote nodes]
								//                                                                                     (Realm B)
								//

								memcpy(target_ipv6,internal_ifc_addr->ip_addr.addr.v6,16);

								RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV6_ND_RSLV_IP_ROUTING,"x6",tx_pkt,target_ipv6);
								rx_rlm->statistics.bridge.rx_from_vpn_ipip_fwd_thisnode_pkts++;

							}else{

								err = RHP_STATUS_INVALID_STATE;

ip_routing_error:
								RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV6_ND_RSLV_INVALID_CFG,"xx",rx_rlm,tx_pkt);
								rx_rlm->statistics.bridge.rx_from_vpn_ipip_fwd_err_pkts++;

								RHP_UNLOCK(&(rx_rlm->lock));

								RHP_LOCK(&rhp_bridge_lock);
								rhp_bridge_cache_statistics_tbl.bridge.rx_from_vpn_ipip_fwd_err_pkts++;
								RHP_UNLOCK(&rhp_bridge_lock);

								return err;
							}

						}else{

							rx_rlm->statistics.bridge.rx_from_vpn_ipip_fwd_nexthop_pkts++;
						}
					}
				}
			}
    }

    RHP_UNLOCK(&(rx_rlm->lock));
	}


	if( !rslv_ok ){

		RHP_LOCK(&rhp_bridge_lock);

		br_c_nd_dst = _rhp_bridge_neigh_cache_get_by_tgt_ip(vpn_realm_id,AF_INET6,target_ipv6);
		if( br_c_nd_dst ){

			memcpy(tx_pkt->l2.eth->dst_addr,br_c_nd_dst->target_mac,6);

			rslv_ok = 1;
			br_c_nd_dst->last_used_cnt++;

			RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV6_ND_RSLV_GET_FROM_CACHE,"x6Mxdd",tx_pkt,target_ipv6,tx_pkt->l2.eth->dst_addr,br_c_nd_dst,br_c_nd_dst->stale,br_c_nd_dst->last_used_cnt);

			if( !br_c_nd_dst->static_cache && br_c_nd_dst->stale ){

  			//
  			// The end node (IPv6 over IPsec) doesn't resolve the dest MAC address
  			// and so Rockhopper's ND proxy needs to probe it again.
  			//

				_rhp_bridge_nd_exec_probe(br_c_nd_dst,rx_vpn,tx_pkt->rx_ifc,
						tx_pkt->l2.eth->src_addr,tx_pkt->l2.eth->dst_addr,
						tx_pkt->l3.iph_v6->src_addr,target_ipv6);
			}

			if( dst_local_subnet &&
					br_c_nd_dst->side == RHP_BRIDGE_SIDE_VPN ){

				u64 rate_limit;
				u64 now_tick = rhp_ip_routing_get_tick(&rate_limit);

			  RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV6_ND_RSLV_NHRP_TRF_IND,"xqqq",br_c_nd_dst,br_c_nd_dst->last_tx_nhrp_trf_indication_tick,now_tick,rate_limit);

				if( !br_c_nd_dst->last_tx_nhrp_trf_indication_tick ||
						(now_tick - br_c_nd_dst->last_tx_nhrp_trf_indication_tick) > rate_limit ){

					tx_nhrp_trf_ind = 1;

					br_c_nd_dst->last_tx_nhrp_trf_indication_tick = now_tick;

				}else{

					tx_nhrp_trf_ind = 0;
				}

			}

		}else{

				_rhp_bridge_nd_exec_resolve(
						rx_vpn->vpn_realm_id,rx_vpn,tx_pkt->rx_ifc,
						tx_pkt->l2.eth->src_addr,tx_pkt->l2.eth->dst_addr,
						tx_pkt->l3.iph_v6->src_addr,target_ipv6,tx_pkt);
		}

		RHP_UNLOCK(&rhp_bridge_lock);
	}

  if( dmvpn_enabled && tx_nhrp_trf_ind ){

  	rhp_nhrp_invoke_tx_traffic_indication_task(rx_vpn,tx_pkt);
  }

  if( rslv_ok ){

  	rhp_bridge_pkt_from_vpn(tx_pkt,rx_vpn);
  }

  RHP_TRC_FREQ(0,RHPTRCID_BRIDGE_PKT_FROM_VPN_IPV6_ND_RSLV_RTRN,"uxxddd",vpn_realm_id,rx_vpn,tx_pkt,dmvpn_enabled,tx_nhrp_trf_ind,dst_local_subnet);
  return 0;
}

void rhp_bridge_cache_flush(rhp_vpn* vpn,unsigned long rlm_id)
{
  rhp_bridge_cache *br_c_tmp,*br_c_tmp_n;
  rhp_bridge_neigh_cache *br_c_n_tmp,*br_c_n_tmp_n;

  RHP_TRC(0,RHPTRCID_BRIDGE_CACHE_FLUSH,"xu",vpn,rlm_id);

  RHP_LOCK(&rhp_bridge_lock);

  {
	  br_c_tmp = _rhp_bridge_list_head.next_list;

	  while( br_c_tmp ){

	  	br_c_tmp_n = br_c_tmp->next_list;

	  	if( !(br_c_tmp->static_cache) ){

		  	if( ((vpn == NULL) || (vpn == RHP_VPN_REF(br_c_tmp->vpn_ref))) &&
		  			((rlm_id == 0) || (br_c_tmp->vpn_realm_id == rlm_id)) ){

	  			if( !_rhp_bridge_cache_delete(br_c_tmp) ){
	  				_rhp_bridge_free_cache(br_c_tmp);
	  			}
		  	}
	  	}

	  	br_c_tmp = br_c_tmp_n;
	  }
  }


  {
	  br_c_n_tmp = _rhp_bridge_neigh_list_head.next_list;

	  while( br_c_n_tmp ){

	  	br_c_n_tmp_n = br_c_n_tmp->next_list;

	  	if( !(br_c_n_tmp->static_cache) ){

			  if( ((vpn == NULL) || (vpn == RHP_VPN_REF(br_c_n_tmp->vpn_ref))) &&
			  		((rlm_id == 0) || (br_c_n_tmp->vpn_realm_id == rlm_id)) ){

		  		if( !_rhp_bridge_neigh_cache_delete(br_c_n_tmp) ){
		 	  		_rhp_bridge_free_neigh_cache(br_c_n_tmp);
		 	  	}
		  	}
	  	}

	  	br_c_n_tmp = br_c_n_tmp_n;
	  }
  }


	if( !rhp_timer_pending(&(_rhp_bridge_cache_timer)) ){

		rhp_timer_reset(&(_rhp_bridge_cache_timer));
  	rhp_timer_add(&(_rhp_bridge_cache_timer),(time_t)rhp_gcfg_mac_cache_aging_interval);
	}

  RHP_UNLOCK(&rhp_bridge_lock);

  RHP_TRC(0,RHPTRCID_BRIDGE_CACHE_FLUSH_RTRN,"xu",vpn,rlm_id);
  return;
}

void rhp_bridge_cache_flush_by_vpn(rhp_vpn* vpn)
{
	rhp_bridge_cache_flush(vpn,0);
}


int rhp_bridge_enum(unsigned long rlm_id,
		int (*callback)(rhp_bridge_cache* br_c,void* ctx),void* ctx)
{
	int err = -EINVAL;
	rhp_bridge_cache *br_c,*br_c_n;
	int n = 0;

  RHP_TRC(0,RHPTRCID_BRIDGE_ENUM,"uYx",rlm_id,callback,ctx);

	RHP_LOCK(&rhp_bridge_lock);

	br_c = _rhp_bridge_list_head.next_list;
	while( br_c ){

		br_c_n = br_c->next_list;

		if( rlm_id == 0 || br_c->vpn_realm_id == rlm_id ){

			err = callback(br_c,ctx);
			if( err ){

  	  	if( err == RHP_STATUS_ENUM_OK ){
  	  		err = 0;
  	  	}

  	  	break;
			}

			n++;
		}

		br_c = br_c_n;
	}

	if( n == 0 ){
		err = -ENOENT;
	}

  RHP_UNLOCK(&rhp_bridge_lock);

  RHP_TRC(0,RHPTRCID_BRIDGE_ENUM_RTRN,"uYE",rlm_id,callback,err);
  return err;
}

static int _rhp_bridge_neigh_enum(unsigned long rlm_id,
		int addr_family,
		int (*callback0)(rhp_bridge_neigh_cache* br_c_n,void* ctx0),void* ctx0,
		int (*callback1)(rhp_neigh_rslv_ctx* rslv_ctx,void* ctx1),void* ctx1)
{
	int err = -EINVAL;
	int n = 0, i;

	RHP_LOCK(&rhp_bridge_lock);

	if( callback0 ){

		rhp_bridge_neigh_cache *br_c_n,*br_c_n_n;

		br_c_n = _rhp_bridge_neigh_list_head.next_list;
		while( br_c_n ){

			br_c_n_n = br_c_n->next_list;

			if( (addr_family == AF_UNSPEC || br_c_n->addr_family == addr_family) &&
					(rlm_id == 0 || br_c_n->vpn_realm_id == rlm_id) ){

				err = callback0(br_c_n,ctx0);
				if( err ){

					if( err == RHP_STATUS_ENUM_OK ){
						err = 0;
					}

					break;
				}

				n++;
			}

			br_c_n = br_c_n_n;
		}
	}

	if( callback1 ){

		rhp_neigh_rslv_ctx *rslv_ctx = NULL,*rslv_ctx_n;

  	for( i = 0; i < rhp_gcfg_neigh_cache_hash_size; i++ ){

  		rslv_ctx = _rhp_neigh_rslv_hash_tbl[i];
  		while( rslv_ctx ){

  			rslv_ctx_n = rslv_ctx->next_hash;

  			if( (addr_family == AF_UNSPEC || rslv_ctx_n->addr_family == addr_family) &&
  					(rlm_id == 0 || rslv_ctx->vpn_realm_id == rlm_id) ){

  				err = callback1(rslv_ctx,ctx1);
  				if( err ){

  					if( err == RHP_STATUS_ENUM_OK ){
  						err = 0;
  					}

  					break;
  				}

  				n++;
  			}

  			rslv_ctx = rslv_ctx_n;
  		}
  	}
	}

	if( n == 0 ){
		err = -ENOENT;
	}

  RHP_UNLOCK(&rhp_bridge_lock);

  return err;
}

int rhp_bridge_arp_enum(unsigned long rlm_id,
		int (*callback0)(rhp_bridge_neigh_cache* br_c_n,void* ctx0),void* ctx0,
		int (*callback1)(rhp_neigh_rslv_ctx* rslv_ctx,void* ctx1),void* ctx1)
{
	return _rhp_bridge_neigh_enum(rlm_id,AF_INET,callback0,ctx0,callback1,ctx1);
}

int rhp_bridge_nd_enum(unsigned long rlm_id,
		int (*callback0)(rhp_bridge_neigh_cache* br_c_n,void* ctx0),void* ctx0,
		int (*callback1)(rhp_neigh_rslv_ctx* rslv_ctx,void* ctx1),void* ctx1)
{
	return _rhp_bridge_neigh_enum(rlm_id,AF_INET6,callback0,ctx0,callback1,ctx1);
}


int rhp_encap_send(rhp_vpn* tx_vpn,rhp_packet* pkt)
{
	int encap_mode_c;

  if( tx_vpn == NULL ){
  	RHP_BUG("");
  	return 0;
  }

	RHP_LOCK(&(tx_vpn->lock));
	{
		encap_mode_c = tx_vpn->internal_net_info.encap_mode_c;
	}
	RHP_UNLOCK(&(tx_vpn->lock));


	if( encap_mode_c == RHP_VPN_ENCAP_ETHERIP ){

		return rhp_eoip_send(tx_vpn,pkt);

	}else if( encap_mode_c == RHP_VPN_ENCAP_IPIP ){

		return rhp_ip_bridge_send(tx_vpn,pkt);

	}else if( encap_mode_c == RHP_VPN_ENCAP_GRE ){

		return rhp_gre_send(tx_vpn,pkt);
	}

  RHP_TRC(0,RHPTRCID_ENCAP_SEND_ERR,"xxd",tx_vpn,pkt,encap_mode_c);
	return -EINVAL;
}
