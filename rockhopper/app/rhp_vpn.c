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
#include <byteswap.h>
#include <net/if.h>
#include <arpa/inet.h>


#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_protocol.h"
#include "rhp_packet.h"
#include "rhp_netsock.h"
#include "rhp_config.h"
#include "rhp_vpn.h"
#include "rhp_ikev2_mesg.h"
#include "rhp_ikev2.h"
#include "rhp_http.h"
#include "rhp_event.h"
#include "rhp_forward.h"
#include "rhp_eap.h"
#include "rhp_eap_sup_impl.h"
#include "rhp_eap_auth_impl.h"
#include "rhp_dns_pxy.h"
#include "rhp_radius_impl.h"
#include "rhp_radius_acct.h"
#include "rhp_nhrp.h"


rhp_mutex_t rhp_vpn_lock;

struct _rhp_vpn_ikesa_spi_entry {

  u8 tag[4]; // '#ISE'

  struct _rhp_vpn_ikesa_spi_entry* next_hash;
  struct _rhp_vpn_ikesa_spi_entry* pre_lst;
  struct _rhp_vpn_ikesa_spi_entry* next_lst;

  int my_side;
  u8 my_spi[RHP_PROTO_IKE_SPI_SIZE];

  rhp_vpn* vpn;
};
typedef struct _rhp_vpn_ikesa_spi_entry rhp_vpn_ikesa_spi_entry;


struct _rhp_vpn_ikesa_v1_spi_entry {

  u8 tag[4]; // '#IS1'

  struct _rhp_vpn_ikesa_v1_spi_entry* next_hash;
  struct _rhp_vpn_ikesa_v1_spi_entry* pre_lst;
  struct _rhp_vpn_ikesa_v1_spi_entry* next_lst;

  rhp_ip_addr my_addr;
  rhp_ip_addr peer_addr;

  int my_side;
  u8 my_spi[RHP_PROTO_IKE_SPI_SIZE];
  u8 peer_spi[RHP_PROTO_IKE_SPI_SIZE];
};
typedef struct _rhp_vpn_ikesa_v1_spi_entry rhp_vpn_ikesa_v1_spi_entry;


struct _rhp_vpn_childsa_spi_entry {

  u8 tag[4]; // '#CSE'

  struct _rhp_vpn_childsa_spi_entry* next_hash;

  u32 spi_inb;

  rhp_vpn* vpn;
};
typedef struct _rhp_vpn_childsa_spi_entry rhp_vpn_childsa_spi_entry;


static rhp_vpn* _rhp_vpn_hashtbl[RHP_VPN_HASH_TABLE_SIZE];
static u32 _rhp_vpn_hashtbl_rnd;

static rhp_vpn* _rhp_vpn_eap_peer_id_hashtbl[RHP_VPN_HASH_TABLE_SIZE];

static rhp_vpn* _rhp_vpn_unique_id_hashtbl[RHP_VPN_HASH_TABLE_SIZE];

//static rhp_vpn* _rhp_vpn_dummy_peer_mac_hashtbl[RHP_VPN_HASH_TABLE_SIZE];
//static u32 _rhp_vpn_dummy_peer_mac_hashtbl_rnd;

static rhp_vpn* _rhp_vpn_peer_addr_v4_hashtbl[RHP_VPN_HASH_TABLE_SIZE];
static rhp_vpn* _rhp_vpn_peer_addr_v6_hashtbl[RHP_VPN_HASH_TABLE_SIZE];


struct _rhp_vpn_itnl_peera_entry {

  u8 tag[4]; // '#VMP'

  struct _rhp_vpn_itnl_peera_entry* next_hash;

  unsigned long vpn_realm_id;
  rhp_ip_addr peer_internal_ip;

  rhp_vpn_ref* vpn_ref;
};
typedef struct _rhp_vpn_itnl_peera_entry	rhp_vpn_itnl_peera_entry;

static rhp_vpn_itnl_peera_entry* _rhp_vpn_internal_peer_addr_v4_hashtbl[RHP_VPN_HASH_TABLE_SIZE];
static rhp_vpn_itnl_peera_entry* _rhp_vpn_internal_peer_addr_v6_hashtbl[RHP_VPN_HASH_TABLE_SIZE];
static u32 _rhp_vpn_peer_addr_hashtbl_rnd;


struct _rhp_vpn_itnl_peerm_entry {

  u8 tag[4]; // '#VAP'

  struct _rhp_vpn_itnl_peerm_entry* next_hash;

  unsigned long vpn_realm_id;
  u8 peer_internal_mac[6];

  rhp_vpn_ref* vpn_ref;
};
typedef struct _rhp_vpn_itnl_peerm_entry	rhp_vpn_itnl_peerm_entry;

static rhp_vpn_itnl_peerm_entry* _rhp_vpn_internal_peer_mac_hashtbl[RHP_VPN_HASH_TABLE_SIZE];
static u32 _rhp_vpn_internal_peer_mac_hashtbl_rnd;


static rhp_vpn_ikesa_spi_entry* _rhp_ikesa_hashtbl[2][RHP_VPN_HASH_TABLE_SIZE];
static u32 _rhp_ikesa_hashtbl_rnd;

static rhp_vpn_ikesa_v1_spi_entry* _rhp_ikesa_v1_hashtbl[RHP_VPN_HASH_TABLE_SIZE];
static u32 _rhp_ikesa_v1_hashtbl_rnd;

static rhp_vpn_childsa_spi_entry* _rhp_childsa_hashtbl[RHP_VPN_HASH_TABLE_SIZE];
static u32 _rhp_childsa_hashtbl_rnd;

rhp_vpn rhp_vpn_list_head;
rhp_vpn_ikesa_spi_entry rhp_vpn_ikesa_spi_list_head;

rhp_vpn_ikesa_v1_spi_entry rhp_vpn_ikesa_v1_spi_list_head;

static rhp_mutex_t _rhp_vpn_unique_id_lock;
static u64 _rhp_vpn_unique_id_gen = 0;
static u64 _rhp_vpn_unique_id = 0;

struct _rhp_vpn_local_mac_marker {

	struct _rhp_vpn_local_mac_marker* next;

	u8 local_mac[6];
	u8 reserved[2];
};
typedef struct _rhp_vpn_local_mac_marker rhp_vpn_local_mac_marker;

static rhp_vpn_local_mac_marker* _rhp_vpn_local_mac_hashtbl[RHP_VPN_HASH_TABLE_SIZE];
static u32 _rhp_vpn_local_mac_marker_hashtbl_rnd;
static u32 _rhp_vpn_local_mac_idx = 0;


rhp_atomic_t rhp_vpn_fwd_any_dns_queries;


static time_t _rhp_vpn_lifetime_random_impl(int lifetime_secs,int range)
{
  u32 random_secs;
  time_t ret;

  if( rhp_random_bytes((u8*)&random_secs,sizeof(random_secs)) ){
    RHP_BUG("");
    return 0;
  }

  ret = (time_t)(lifetime_secs + (random_secs % range));

	RHP_TRC(0,RHPTRCID_VPN_LIFETIME_RANDOM_IMPL,"ddd",lifetime_secs,range,ret);

  return ret;
}

time_t rhp_vpn_lifetime_random(int lifetime_secs)
{
	if( !rhp_gcfg_randomize_sa_lifetime ){
		RHP_TRC(0,RHPTRCID_VPN_LIFETIME_RANDOM_DISABLED,"d",lifetime_secs);
		return lifetime_secs;
	}

	return _rhp_vpn_lifetime_random_impl(lifetime_secs,RHP_CFG_LIFETIME_RANDOM_RANGE);
}

int rhp_vpn_max_sessions_reached()
{
	int flag = 0;

	RHP_LOCK(&rhp_ikev2_lock_statistics);

	RHP_TRC_FREQ(0,RHPTRCID_VPN_MAX_SESSIONS_REACHED,"dq",rhp_gcfg_vpn_max_sessions,rhp_ikev2_statistics_global_tbl.dc.vpn_num);

	if( rhp_gcfg_vpn_max_sessions &&
			rhp_ikev2_statistics_global_tbl.dc.vpn_num >= (unsigned long)rhp_gcfg_vpn_max_sessions ){
		flag = 1;
	}

	RHP_UNLOCK(&rhp_ikev2_lock_statistics);

	return flag;
}

void rhp_vpn_gen_unique_id(u8* unique_id_r)
{
  RHP_LOCK(&_rhp_vpn_unique_id_lock);

  if( _rhp_vpn_unique_id == 0xFFFFFFFFFFFFFFFFULL ){
  	_rhp_vpn_unique_id_gen++;
  }
  _rhp_vpn_unique_id++;

  *((u64*)unique_id_r) = _rhp_htonll(_rhp_vpn_unique_id_gen);
  *(((u64*)unique_id_r) + 1) = _rhp_htonll(_rhp_vpn_unique_id);

  RHP_UNLOCK(&_rhp_vpn_unique_id_lock);

	RHP_TRC(0,RHPTRCID_VPN_GEN_UNIQUE_ID,"p",RHP_VPN_UNIQUE_ID_SIZE,unique_id_r);
	return;
}

// [CAUTION] Don't use realm_id as a hash key!
static u32 _rhp_vpn_local_mac_hash(u8* mac_addr)
{
	u32 hval = _rhp_hash_bytes(mac_addr,6,_rhp_vpn_local_mac_marker_hashtbl_rnd);
	return (hval % RHP_VPN_HASH_TABLE_SIZE);
}

int rhp_vpn_gen_or_add_local_mac(u8* added_mac,u8* mac_addr_r)
{
	u32 hval;
	u8 mac[6];
	rhp_vpn_local_mac_marker *mkr = NULL,*n_mkr = NULL;
	int retries = 0;

	RHP_TRC(0,RHPTRCID_VPN_GEN_LOCAL_MAC,"Mx",added_mac,mac_addr_r);

	n_mkr = (rhp_vpn_local_mac_marker*)_rhp_malloc(sizeof(rhp_vpn_local_mac_marker));
	if( n_mkr == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	memset(n_mkr,0,sizeof(rhp_vpn_local_mac_marker));


  RHP_LOCK(&_rhp_vpn_unique_id_lock);

  if( added_mac ){

  	hval = _rhp_vpn_local_mac_hash(added_mac);

  	memcpy(mac,added_mac,6);

    goto add;
  }

retry:
	if( retries >= 1000 ){
	  RHP_UNLOCK(&_rhp_vpn_unique_id_lock);
	  RHP_BUG("");
		return -EINVAL;
	}


	if( !rhp_gcfg_dummy_mac_min_idx ){

		if( rhp_random_bytes(mac,6) ){
			retries++;
			goto retry;
		}
		mac[0] &= 0xFE;
		mac[0] |= 0x02; // Local address

	}else{

		mac[0] = ((rhp_gcfg_dummy_mac_oui >> 16) & 0x000000FF);
		mac[1] = ((rhp_gcfg_dummy_mac_oui >> 8) & 0x000000FF);
		mac[2] = (rhp_gcfg_dummy_mac_oui & 0x000000FF);

		if( _rhp_vpn_local_mac_idx == 0 || _rhp_vpn_local_mac_idx == 0x00FFFFFF ||
				_rhp_vpn_local_mac_idx > rhp_gcfg_dummy_mac_max_idx ){

			_rhp_vpn_local_mac_idx = rhp_gcfg_dummy_mac_min_idx;
		}

		memcpy(&(mac[3]),&_rhp_vpn_local_mac_idx,3);
		_rhp_vpn_local_mac_idx++;
	}

  hval = _rhp_vpn_local_mac_hash(mac);

  mkr = _rhp_vpn_local_mac_hashtbl[hval];
  while( mkr ){

  	if( !memcmp(mkr->local_mac,mac,6) ){
  		break;
  	}

  	mkr = mkr->next;
  }

  if( mkr ){
  	retries++;
  	goto retry;
  }

add:
  memcpy(n_mkr->local_mac,mac,6);

  if( mac_addr_r ){
  	memcpy(mac_addr_r,mac,6);
  }

  n_mkr->next = _rhp_vpn_local_mac_hashtbl[hval];
  _rhp_vpn_local_mac_hashtbl[hval] = n_mkr;

  RHP_UNLOCK(&_rhp_vpn_unique_id_lock);

  RHP_TRC(0,RHPTRCID_VPN_GEN_LOCAL_MAC_RTRN,"xMdu",n_mkr,mac_addr_r,retries,hval);
	return 0;
}

void rhp_vpn_clear_local_mac(u8* mac_addr)
{
	u32 hval;
	rhp_vpn_local_mac_marker *mkr,*mkr_p = NULL;

  RHP_TRC(0,RHPTRCID_VPN_CLEAR_LOCAL_MAC,"M",mac_addr);

	RHP_LOCK(&_rhp_vpn_unique_id_lock);

  hval = _rhp_vpn_local_mac_hash(mac_addr);

  mkr = _rhp_vpn_local_mac_hashtbl[hval];
  while( mkr ){

  	if( !memcmp(mkr->local_mac,mac_addr,6) ){
  		break;
  	}

  	mkr_p = mkr;
  	mkr = mkr->next;
  }

  if( mkr == NULL ){
    RHP_UNLOCK(&_rhp_vpn_unique_id_lock);
    RHP_TRC(0,RHPTRCID_VPN_CLEAR_LOCAL_MAC_NO_ENTRY,"M",mac_addr);
    return;
  }

  if( mkr_p ){
  	mkr_p->next = mkr->next;
  }else{
  	_rhp_vpn_local_mac_hashtbl[hval] = mkr->next;
  }

  _rhp_free(mkr);

  RHP_UNLOCK(&_rhp_vpn_unique_id_lock);

  RHP_TRC(0,RHPTRCID_VPN_CLEAR_LOCAL_MAC_RTRN,"Mx",mac_addr,mkr);
  return;
}

extern int rhp_vpn_addr_pool_init();

int rhp_vpn_init()
{
  int err = 0;

  if( rhp_random_bytes((u8*)&_rhp_vpn_hashtbl_rnd,sizeof(_rhp_vpn_hashtbl_rnd)) ){
    RHP_BUG("");
    return -EINVAL;
  }
/*
  if( rhp_random_bytes((u8*)&_rhp_vpn_dummy_peer_mac_hashtbl_rnd,sizeof(_rhp_vpn_dummy_peer_mac_hashtbl_rnd)) ){
    RHP_BUG("");
    return -EINVAL;
  }
*/
  if( rhp_random_bytes((u8*)&_rhp_vpn_peer_addr_hashtbl_rnd,sizeof(_rhp_vpn_peer_addr_hashtbl_rnd)) ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( rhp_random_bytes((u8*)&_rhp_vpn_internal_peer_mac_hashtbl_rnd,sizeof(_rhp_vpn_internal_peer_mac_hashtbl_rnd)) ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( rhp_random_bytes((u8*)&_rhp_ikesa_hashtbl_rnd,sizeof(_rhp_ikesa_hashtbl_rnd)) ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( rhp_random_bytes((u8*)&_rhp_ikesa_v1_hashtbl_rnd,sizeof(_rhp_ikesa_v1_hashtbl_rnd)) ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( rhp_random_bytes((u8*)&_rhp_childsa_hashtbl_rnd,sizeof(_rhp_childsa_hashtbl_rnd)) ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( rhp_random_bytes((u8*)&_rhp_vpn_local_mac_marker_hashtbl_rnd,sizeof(_rhp_vpn_local_mac_marker_hashtbl_rnd)) ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( rhp_random_bytes((u8*)&_rhp_vpn_unique_id,sizeof(_rhp_vpn_unique_id)) ){
    RHP_BUG("");
    return -EINVAL;
  }


  _rhp_mutex_init("VPG",&(rhp_vpn_lock));

  memset(_rhp_vpn_hashtbl,0,sizeof(rhp_vpn*)*RHP_VPN_HASH_TABLE_SIZE);
  memset(_rhp_vpn_eap_peer_id_hashtbl,0,sizeof(rhp_vpn*)*RHP_VPN_HASH_TABLE_SIZE);
  memset(_rhp_vpn_unique_id_hashtbl,0,sizeof(rhp_vpn*)*RHP_VPN_HASH_TABLE_SIZE);
//  memset(_rhp_vpn_dummy_peer_mac_hashtbl,0,sizeof(rhp_vpn*)*RHP_VPN_HASH_TABLE_SIZE);
  memset(_rhp_vpn_peer_addr_v4_hashtbl,0,sizeof(rhp_vpn*)*RHP_VPN_HASH_TABLE_SIZE);
  memset(_rhp_vpn_peer_addr_v6_hashtbl,0,sizeof(rhp_vpn*)*RHP_VPN_HASH_TABLE_SIZE);
  memset(_rhp_vpn_internal_peer_addr_v4_hashtbl,0,sizeof(rhp_vpn*)*RHP_VPN_HASH_TABLE_SIZE);
  memset(_rhp_vpn_internal_peer_addr_v6_hashtbl,0,sizeof(rhp_vpn*)*RHP_VPN_HASH_TABLE_SIZE);
  memset(_rhp_vpn_internal_peer_mac_hashtbl,0,sizeof(rhp_vpn*)*RHP_VPN_HASH_TABLE_SIZE);

  memset(_rhp_ikesa_hashtbl,0,sizeof(rhp_vpn_ikesa_spi_entry*)*RHP_VPN_HASH_TABLE_SIZE*2);

  memset(_rhp_ikesa_v1_hashtbl,0,sizeof(rhp_vpn_ikesa_v1_spi_entry*)*RHP_VPN_HASH_TABLE_SIZE);

  memset(_rhp_childsa_hashtbl,0,sizeof(rhp_vpn_childsa_spi_entry*)*RHP_VPN_HASH_TABLE_SIZE);


  memset(&rhp_vpn_list_head,0,sizeof(rhp_vpn));
  rhp_vpn_list_head.tag[0] = '#';
  rhp_vpn_list_head.tag[1] = 'V';
  rhp_vpn_list_head.tag[2] = 'P';
  rhp_vpn_list_head.tag[3] = 'N';


  memset(&rhp_vpn_ikesa_spi_list_head,0,sizeof(rhp_vpn_ikesa_spi_entry));
  rhp_vpn_ikesa_spi_list_head.tag[0] = '#';
  rhp_vpn_ikesa_spi_list_head.tag[1] = 'I';
  rhp_vpn_ikesa_spi_list_head.tag[2] = 'S';
  rhp_vpn_ikesa_spi_list_head.tag[3] = 'E';

  memset(&rhp_vpn_ikesa_v1_spi_list_head,0,sizeof(rhp_vpn_ikesa_v1_spi_entry));
  rhp_vpn_ikesa_v1_spi_list_head.tag[0] = '#';
  rhp_vpn_ikesa_v1_spi_list_head.tag[1] = 'I';
  rhp_vpn_ikesa_v1_spi_list_head.tag[2] = 'S';
  rhp_vpn_ikesa_v1_spi_list_head.tag[3] = '1';


  err = rhp_ikesa_init();
  if( err ){
    RHP_BUG("%d");
    goto error;
  }

  err = rhp_vpn_addr_pool_init();
  if( err ){
    RHP_BUG("%d");
    goto error;
  }

  _rhp_mutex_init("VUI",&(_rhp_vpn_unique_id_lock));

  _rhp_atomic_init(&rhp_vpn_fwd_any_dns_queries);

  RHP_TRC(0,RHPTRCID_VPN_INIT,"");
  return  0;

error:
	RHP_TRC(0,RHPTRCID_VPN_INIT_ERR,"E",err);
	return err;
}

int rhp_vpn_cleanup()
{

  rhp_ikesa_cleanup();

  _rhp_mutex_destroy(&(_rhp_vpn_unique_id_lock));

  _rhp_mutex_destroy(&(rhp_vpn_lock));

  RHP_TRC(0,RHPTRCID_VPN_CLEANUP,"");
  return 0;
}

// [CAUTION] Don't use realm_id as a hash key!
static int _rhp_vpn_id_hash(rhp_ikev2_id* peer_id,u32* hval_r)
{
  int err;
  u32 hval1;

  err = rhp_ikev2_id_hash(peer_id,_rhp_vpn_hashtbl_rnd,&hval1);
  if( err ){
    RHP_BUG("%d",err);
    return err;
  }

  *hval_r = hval1 % RHP_VPN_HASH_TABLE_SIZE;
  return 0;
}

// [CAUTION] Don't use realm_id as a hash key!
static int _rhp_vpn_eap_id_hash(rhp_eap_id* eap_peer_id,u32* hval_r)
{
  int err;
  u32 hval1;

  err = rhp_eap_id_hash(eap_peer_id,_rhp_vpn_hashtbl_rnd,&hval1);
  if( err ){
    RHP_BUG("%d",err);
    return err;
  }

  *hval_r = hval1 % RHP_VPN_HASH_TABLE_SIZE;
  return 0;
}



// [CAUTION] Don't use realm_id as a hash key!
u32 rhp_vpn_unique_id_hash(u8* unique_id)
{
  u32 *hval;
  hval = ((u32*)(((u64*)unique_id) + 1)) + 1;
  return  (*hval % RHP_VPN_HASH_TABLE_SIZE);
}

/*
// [CAUTION] Don't use realm_id as a hash key!
static u32 _rhp_vpn_dummy_peer_mac_hash(u8* dummy_peer_mac)
{
	u32 hval = _rhp_hash_bytes(dummy_peer_mac,6,_rhp_vpn_dummy_peer_mac_hashtbl_rnd);
  return  (hval % RHP_VPN_HASH_TABLE_SIZE);
}
*/


// [CAUTION] Don't use realm_id as a hash key!
static u32 _rhp_vpn_peer_addrv4_hash(u32 peer_addr)
{
	u32 hval = _rhp_hash_ipv4_1(peer_addr,_rhp_vpn_peer_addr_hashtbl_rnd);
  return  (hval % RHP_VPN_HASH_TABLE_SIZE);
}

// [CAUTION] Don't use realm_id as a hash key!
static u32 _rhp_vpn_peer_addrv6_hash(u8* peer_addr)
{
	u32 hval = _rhp_hash_ipv6_1(peer_addr,_rhp_vpn_peer_addr_hashtbl_rnd);
  return  (hval % RHP_VPN_HASH_TABLE_SIZE);
}

// [CAUTION] Don't use realm_id as a hash key!
static u32 _rhp_vpn_internal_peer_mac_hash(u8* mac)
{
	u32 hval = _rhp_hash_bytes(mac,6,_rhp_vpn_internal_peer_mac_hashtbl_rnd);
  return  (hval % RHP_VPN_HASH_TABLE_SIZE);
}

static int _rhp_vpn_delete_by_unique_id(rhp_vpn* vpn)
{
	int hval;
  rhp_vpn *vpn_tmp = NULL,*vpn_tmp_p = NULL;

	RHP_TRC(0,RHPTRCID_VPN_DELETE_BY_UNIQUE_ID,"xp",vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id);

  hval = rhp_vpn_unique_id_hash(vpn->unique_id);

  vpn_tmp = _rhp_vpn_unique_id_hashtbl[hval];

  while( vpn_tmp ){

    if( vpn_tmp == vpn ){
   	  break;
    }

    vpn_tmp_p = vpn_tmp;
    vpn_tmp = vpn_tmp->next_hash_unique_id;
  }

  if( vpn_tmp ){

  	if( vpn_tmp_p ){
  		vpn_tmp_p->next_hash_unique_id = vpn_tmp->next_hash_unique_id;
  	}else{
  		_rhp_vpn_unique_id_hashtbl[hval] = vpn_tmp->next_hash_unique_id;
  	}

  	{
			rhp_http_bus_broadcast_async(vpn->vpn_realm_id,1,1,
					rhp_ui_http_vpn_deleted_serialize,
					rhp_ui_http_vpn_bus_btx_async_cleanup,(void*)rhp_vpn_hold_ref(vpn));  // (*x*)

			if( vpn->established ){

				RHP_LOG_N(RHP_LOG_SRC_VPNMNG,vpn->vpn_realm_id,RHP_LOG_ID_VPN_DELETED,"IAsN",&(vpn->peer_id),&(vpn->peer_addr),vpn->peer_fqdn,vpn->unique_id);

				if( vpn->radius.acct_tx_start_notify ){

					rhp_radius_acct_send(vpn,
						RHP_RADIUS_ATTR_TYPE_ACCT_STATUS_STOP,vpn->radius.acct_term_cause);
				}

			}else{

				if( vpn->vpn_realm_id ){
					RHP_LOG_E(RHP_LOG_SRC_VPNMNG,vpn->vpn_realm_id,RHP_LOG_ID_VPN_ESTABLISH_ERR,"IAsN",&(vpn->peer_id),&(vpn->peer_addr),vpn->peer_fqdn,vpn->unique_id);
				}else{
					// NOT authenticated yet...
					RHP_LOG_DE(RHP_LOG_SRC_VPNMNG,0,RHP_LOG_ID_VPN_ESTABLISH_ERR,"IAsN",&(vpn->peer_id),&(vpn->peer_addr),vpn->peer_fqdn,vpn->unique_id);
				}
			}
  	}

  	if( vpn->origin_side == RHP_IKE_INITIATOR ){

  		if( vpn->init_by_peer_addr ){
  			if( !rhp_gcfg_dmvpn_connect_shortcut_rate_limit ){
  				rhp_vpn_connect_i_pending_clear(vpn->vpn_realm_id,NULL,&(vpn->peer_addr));
  			}
  		}else{
  			rhp_vpn_connect_i_pending_clear(vpn->vpn_realm_id,&(vpn->peer_id),NULL);
  		}
  	}


		rhp_vpn_unhold(vpn);

  }else{

  	RHP_TRC(0,RHPTRCID_VPN_DELETE_BY_UNIQUE_ID_NO_ENTRY,"x",vpn);
    return -ENOENT;
  }

	RHP_TRC(0,RHPTRCID_VPN_DELETE_BY_UNIQUE_ID_RTRN,"x",vpn);
  return 0;
}

/*
#ifdef RHP_CK_OBJ_TAG_GDB
static void _rhp_vpn_ck_next_hash_dummy_peer_mac()
{
  volatile rhp_vpn *vpn_tmp;
  volatile int i;

  for(i = 0; i < RHP_VPN_HASH_TABLE_SIZE; i++){

  	vpn_tmp = RHP_CK_OBJTAG("#VPN",_rhp_vpn_dummy_peer_mac_hashtbl[i]);
		while( vpn_tmp ){
			vpn_tmp = RHP_CK_OBJTAG("#VPN",vpn_tmp->next_hash_dummy_peer_mac);
		}
	}
}
#else // RHP_CK_OBJ_TAG_GDB
#define _rhp_vpn_ck_next_hash_dummy_peer_mac()	do{}while(0)
#endif // RHP_CK_OBJ_TAG_GDB
*/

static int _rhp_vpn_delete_by_peer_addr(rhp_vpn* vpn)
{
	u32 hval = 0;
	rhp_vpn *vpn_tmp,*vpn_tmp_p = NULL;

	if( vpn->peer_addr.addr_family == AF_INET ){

		hval = _rhp_vpn_peer_addrv4_hash(vpn->peer_addr.addr.v4);

		vpn_tmp = RHP_CK_OBJTAG("#VPN",_rhp_vpn_peer_addr_v4_hashtbl[hval]);

	}else if(vpn->peer_addr.addr_family == AF_INET6 ){

		hval = _rhp_vpn_peer_addrv6_hash(vpn->peer_addr.addr.v6);

		vpn_tmp = RHP_CK_OBJTAG("#VPN",_rhp_vpn_peer_addr_v6_hashtbl[hval]);

	}else{
		RHP_BUG("%d",vpn->peer_addr.addr_family);
		vpn_tmp = NULL;
	}

	while( vpn_tmp ){

		if( vpn_tmp == vpn ){
			break;
		}

		vpn_tmp_p = RHP_CK_OBJTAG("#VPN",vpn_tmp);
		vpn_tmp = RHP_CK_OBJTAG("#VPN",vpn_tmp->next_hash_peer_addr);
	}

	if( vpn_tmp == NULL ){

		RHP_TRC(0,RHPTRCID_VPN_DELETE_BY_PEER_ADDR_NO_ENT,"x",vpn);
		return -ENOENT;

	}else{

		if( vpn_tmp_p ){

			vpn_tmp_p->next_hash_peer_addr = RHP_CK_OBJTAG("#VPN",vpn_tmp->next_hash_peer_addr);

		}else{

    	if( vpn->peer_addr.addr_family == AF_INET ){

    		_rhp_vpn_peer_addr_v4_hashtbl[hval] = RHP_CK_OBJTAG("#VPN",vpn_tmp->next_hash_peer_addr);

    	}else if(vpn->peer_addr.addr_family == AF_INET6 ){

    		_rhp_vpn_peer_addr_v6_hashtbl[hval] = RHP_CK_OBJTAG("#VPN",vpn_tmp->next_hash_peer_addr);
    	}
		}
	}

	RHP_TRC(0,RHPTRCID_VPN_DELETE_BY_PEER_ADDR_OK,"x",vpn);
	return 0;
}

int rhp_vpn_delete_unlocked(rhp_vpn* vpn)
{
  int err = 0;

  RHP_TRC(0,RHPTRCID_VPN_DELETE_UNLOCKED,"xpux",vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm);
  rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
  rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));

//  _rhp_vpn_ck_next_hash_dummy_peer_mac();

  if( vpn->pre_list == NULL ){

  	err = -ENOENT;
		RHP_TRC(0,RHPTRCID_VPN_DELETE_UNLOCKED_NO_ENTRY_0,"x",vpn);

  }else{

    {
			vpn->pre_list->next_list = vpn->next_list;
			if( vpn->next_list ){
				vpn->next_list->pre_list = vpn->pre_list;
			}

			vpn->pre_list = NULL;
			vpn->next_list = NULL;
    }

    {
      u32 hval = 0;

			err = _rhp_vpn_id_hash(&(vpn->peer_id),&hval);
			if( err ){

				RHP_BUG("");

			}else{

				rhp_vpn *vpn_tmp,*vpn_tmp_p = NULL;

				vpn_tmp = RHP_CK_OBJTAG("#VPN",_rhp_vpn_hashtbl[hval]);

				while( vpn_tmp ){

					if( vpn_tmp == vpn ){
						break;
					}

					vpn_tmp_p = RHP_CK_OBJTAG("#VPN",vpn_tmp);
					vpn_tmp = RHP_CK_OBJTAG("#VPN",vpn_tmp->next_hash);
				}

				if( vpn_tmp == NULL ){

					RHP_TRC(0,RHPTRCID_VPN_DELETE_UNLOCKED_NO_ENTRY_1,"x",vpn);

				}else{

					if( vpn_tmp_p ){
						vpn_tmp_p->next_hash = RHP_CK_OBJTAG("#VPN",vpn_tmp->next_hash);
					}else{
						_rhp_vpn_hashtbl[hval] = RHP_CK_OBJTAG("#VPN",vpn_tmp->next_hash);
					}
				}
			}
	  }

    if( !rhp_eap_id_is_null(&(vpn->eap.peer_id)) ){

    	u32 hval = 0;

    	if( vpn->eap.peer_id.identity_len < 1 ){
    		RHP_BUG("vpn->eap.peer_id.id_len: %d",vpn->eap.peer_id.identity_len);
    	}

			err = _rhp_vpn_eap_id_hash(&(vpn->eap.peer_id),&hval);
			if( err ){

				RHP_BUG("");

			}else{

				rhp_vpn *vpn_tmp,*vpn_tmp_p = NULL;

				vpn_tmp = RHP_CK_OBJTAG("#VPN",_rhp_vpn_eap_peer_id_hashtbl[hval]);

				while( vpn_tmp ){

					if( vpn_tmp == vpn ){
						break;
					}

					vpn_tmp_p = RHP_CK_OBJTAG("#VPN",vpn_tmp);
					vpn_tmp = RHP_CK_OBJTAG("#VPN",vpn_tmp->next_hash_eap_id);
				}

				if( vpn_tmp == NULL ){

					RHP_TRC(0,RHPTRCID_VPN_DELETE_UNLOCKED_NO_ENTRY_2,"x",vpn);

				}else{

					if( vpn_tmp_p ){
						vpn_tmp_p->next_hash_eap_id = RHP_CK_OBJTAG("#VPN",vpn_tmp->next_hash_eap_id);
					}else{
						_rhp_vpn_eap_peer_id_hashtbl[hval] = RHP_CK_OBJTAG("#VPN",vpn_tmp->next_hash_eap_id);
					}
				}
			}
	  }

/*
	  {
	    rhp_vpn *vpn_tmp,*vpn_tmp_p = NULL;
	    u32 hval2;

	    hval2 = _rhp_vpn_dummy_peer_mac_hash(vpn->internal_net_info.dummy_peer_mac);

			vpn_tmp = RHP_CK_OBJTAG("#VPN",_rhp_vpn_dummy_peer_mac_hashtbl[hval2]);

			while( vpn_tmp ){

				if( vpn_tmp == vpn ){
					break;
				}

				vpn_tmp_p = RHP_CK_OBJTAG("#VPN",vpn_tmp);
				vpn_tmp = RHP_CK_OBJTAG("#VPN",vpn_tmp->next_hash_dummy_peer_mac);
			}

			if( vpn_tmp ){

				if( vpn_tmp_p ){
					vpn_tmp_p->next_hash_dummy_peer_mac = RHP_CK_OBJTAG("#VPN",vpn_tmp->next_hash_dummy_peer_mac);
				}else{
					_rhp_vpn_dummy_peer_mac_hashtbl[hval2] = RHP_CK_OBJTAG("#VPN",vpn_tmp->next_hash_dummy_peer_mac);
				}

			}else{

				RHP_TRC(0,RHPTRCID_VPN_DELETE_UNLOCKED_NO_ENTRY_3,"x",vpn);
			}

		  _rhp_vpn_ck_next_hash_dummy_peer_mac();
	  }
*/

    _rhp_vpn_delete_by_peer_addr(vpn);

	  rhp_vpn_unhold(vpn);
  }

  _rhp_vpn_delete_by_unique_id(vpn);

  RHP_TRC(0,RHPTRCID_VPN_DELETE_UNLOCKED_RTRN,"x",vpn);
  return 0;
}

int rhp_vpn_delete(rhp_vpn* vpn)
{
  int err;

	RHP_TRC(0,RHPTRCID_VPN_DELETE,"x",vpn);

  RHP_LOCK(&rhp_vpn_lock);

  err = rhp_vpn_delete_unlocked(vpn);

  RHP_UNLOCK(&rhp_vpn_lock);

	RHP_TRC(0,RHPTRCID_VPN_DELETE_RTRN,"xE",vpn,err);
	return err;
}

rhp_vpn_ref* rhp_vpn_get_by_unique_id_unlocked(u8* unique_id)
{
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;
  u32 hval;

  RHP_TRC(0,RHPTRCID_VPN_GET_BY_UNIQUE_ID_UNLOCKED,"p",RHP_VPN_UNIQUE_ID_SIZE,unique_id);

  hval = rhp_vpn_unique_id_hash(unique_id);

  vpn = _rhp_vpn_unique_id_hashtbl[hval];

  while( vpn ){

  	if( !memcmp(unique_id,vpn->unique_id,16) ){
  		break;
  	}

    vpn = vpn->next_hash_unique_id;
  }

  if( vpn ){

  	vpn_ref = rhp_vpn_hold_ref(vpn);

  	RHP_TRC(0,RHPTRCID_VPN_GET_BY_UNIQUE_ID_UNLOCKED_RTNR,"xpuxx",vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm,vpn_ref);
  	rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
  	rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));

  }else{

    RHP_TRC(0,RHPTRCID_VPN_GET_BY_UNIQUE_ID_UNLOCKED_NO_ENTRY,"");
  }

  return vpn_ref;
}

rhp_vpn_ref* rhp_vpn_get_by_unique_id(u8* unique_id)
{
	rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;

  RHP_TRC(0,RHPTRCID_VPN_GET_BY_UNIQUE_ID,"p",RHP_VPN_UNIQUE_ID_SIZE,unique_id);

  RHP_LOCK(&rhp_vpn_lock);

  vpn_ref = rhp_vpn_get_by_unique_id_unlocked(unique_id);
  vpn = RHP_VPN_REF(vpn_ref);

  RHP_UNLOCK(&rhp_vpn_lock);

  RHP_TRC(0,RHPTRCID_VPN_GET_BY_UNIQUE_ID_RTRN,"pxx",RHP_VPN_UNIQUE_ID_SIZE,unique_id,vpn,vpn_ref);
  return vpn_ref;
}

static void _rhp_vpn_put_by_unique_id(rhp_vpn* vpn)
{
	int hval;
	void* c_vpn_ref = rhp_vpn_get_by_unique_id_unlocked(vpn->unique_id);
	rhp_vpn* c_vpn = RHP_VPN_REF(c_vpn_ref);

	if( c_vpn == NULL ){

		hval = rhp_vpn_unique_id_hash(vpn->unique_id);

		vpn->next_hash_unique_id = _rhp_vpn_unique_id_hashtbl[hval];
		_rhp_vpn_unique_id_hashtbl[hval] = vpn;

  	rhp_vpn_hold(vpn); // rhp_vpn_hold_ref NOT used here.

	}else{

		if( vpn != c_vpn ){
			RHP_BUG("0x%lx : 0x%lx",(unsigned long)vpn,(unsigned long)c_vpn);
		}

		rhp_vpn_unhold(c_vpn_ref);
	}

	return;
}

void rhp_vpn_put(rhp_vpn* vpn)
{
	RHP_TRC(0,RHPTRCID_VPN_PUT,"x",vpn);

  RHP_LOCK(&rhp_vpn_lock);

  RHP_TRC(0,RHPTRCID_VPN_PUT_VPN,"xpux",vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm);
  rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
  rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));

//  _rhp_vpn_ck_next_hash_dummy_peer_mac();

  {
    u32 hval;

	  if( _rhp_vpn_id_hash(&(vpn->peer_id),&hval) ){
	    RHP_BUG("");
	    goto error;
	  }

	  vpn->next_hash = _rhp_vpn_hashtbl[hval];
	  _rhp_vpn_hashtbl[hval] = vpn;
  }

  if( !rhp_eap_id_is_null(&(vpn->eap.peer_id)) ){

  	if( vpn->eap.peer_id.identity_len < 1 ){

  		RHP_BUG("vpn->eap.peer_id.id_len: %d",vpn->eap.peer_id.identity_len);

  	}else{

  		u32 hval;

			if( _rhp_vpn_eap_id_hash(&(vpn->eap.peer_id),&hval) ){
				RHP_BUG("");
				goto error;
			}

			vpn->next_hash_eap_id = _rhp_vpn_eap_peer_id_hashtbl[hval];
			_rhp_vpn_eap_peer_id_hashtbl[hval] = vpn;
  	}
  }

  {
	  vpn->next_list = rhp_vpn_list_head.next_list;
	  if( rhp_vpn_list_head.next_list ){
		  rhp_vpn_list_head.next_list->pre_list = vpn;
	  }
	  vpn->pre_list = &rhp_vpn_list_head;
	  rhp_vpn_list_head.next_list = vpn;
  }

  _rhp_vpn_put_by_unique_id(vpn);

/*
  {
    u32 hval;

  	hval = _rhp_vpn_dummy_peer_mac_hash(vpn->internal_net_info.dummy_peer_mac);

  	vpn->next_hash_dummy_peer_mac = RHP_CK_OBJTAG("#VPN",_rhp_vpn_dummy_peer_mac_hashtbl[hval]);
  	_rhp_vpn_dummy_peer_mac_hashtbl[hval] = RHP_CK_OBJTAG("#VPN",vpn);
  }
*/

  {
  	u32 hval = 0;

  	if( vpn->peer_addr.addr_family == AF_INET ){

  		hval = _rhp_vpn_peer_addrv4_hash(vpn->peer_addr.addr.v4);

  		vpn->next_hash_peer_addr = _rhp_vpn_peer_addr_v4_hashtbl[hval];
  		_rhp_vpn_peer_addr_v4_hashtbl[hval] = vpn;

  	}else if(vpn->peer_addr.addr_family == AF_INET6 ){

  		hval = _rhp_vpn_peer_addrv6_hash(vpn->peer_addr.addr.v6);

  		vpn->next_hash_peer_addr = _rhp_vpn_peer_addr_v6_hashtbl[hval];
  		_rhp_vpn_peer_addr_v6_hashtbl[hval] = vpn;

  	}else{
  		RHP_BUG("%d",vpn->peer_addr.addr_family);
  	}
  }


  rhp_vpn_hold(vpn); // rhp_vpn_hold_ref NOT used here.

error:
  RHP_UNLOCK(&rhp_vpn_lock);

	RHP_TRC(0,RHPTRCID_VPN_PUT_RTRN,"x",vpn);
	return;
}

// rlm_id == 0 means any.
rhp_vpn_ref* rhp_vpn_get_unlocked(unsigned long rlm_id,rhp_ikev2_id* peer_id,
		rhp_eap_id* eap_peer_id,int no_alt_id)
{
  int err = 0;
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;
  u32 hval;

  RHP_TRC(0,RHPTRCID_VPN_GET_UNLOCKED,"uxdx",rlm_id,peer_id,no_alt_id,eap_peer_id);
  rhp_ikev2_id_dump("peer_id",peer_id);
  rhp_eap_id_dump("eap_peer_id",eap_peer_id);

  if( peer_id->type == RHP_PROTO_IKE_ID_ANY ){
    RHP_TRC(0,RHPTRCID_VPN_GET_UNLOCKED_ID_TYPE_ANY,"x",peer_id);
  	goto error;
  }

  err = _rhp_vpn_id_hash(peer_id,&hval);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  vpn = _rhp_vpn_hashtbl[hval];

  while( vpn ){

    if( (!rlm_id || vpn->vpn_realm_id == rlm_id) &&
    		( (!no_alt_id && !rhp_ikev2_id_cmp(peer_id,&(vpn->peer_id))) ||
    			(no_alt_id && !rhp_ikev2_id_cmp_no_alt_id(peer_id,&(vpn->peer_id)))) &&
    			( (rhp_eap_id_is_null(eap_peer_id) && rhp_eap_id_is_null(&(vpn->eap.peer_id))) ||
    				!rhp_eap_id_cmp(&(vpn->eap.peer_id),eap_peer_id)) ){

    	break;
    }

    vpn = vpn->next_hash;
  }

  if( vpn ){

  	vpn_ref = rhp_vpn_hold_ref(vpn);

    RHP_TRC(0,RHPTRCID_VPN_GET_UNLOCKED_RTRN,"xpuxx",vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm,vpn_ref);

  }else{
    RHP_TRC(0,RHPTRCID_VPN_GET_UNLOCKED_NO_ENTRY,"");
  }

error:
  return vpn_ref;
}

// rlm_id == 0 means any.
rhp_vpn_ref* rhp_vpn_get(unsigned long rlm_id,rhp_ikev2_id* peer_id,rhp_eap_id* eap_peer_id)
{
	rhp_vpn* vpn = NULL;
	rhp_vpn_ref* vpn_ref = NULL;

  RHP_TRC(0,RHPTRCID_VPN_GET_VPN,"uxx",rlm_id,peer_id,eap_peer_id);

  RHP_LOCK(&rhp_vpn_lock);

  vpn_ref = rhp_vpn_get_unlocked(rlm_id,peer_id,eap_peer_id,0);
  vpn = RHP_VPN_REF(vpn_ref);

  RHP_UNLOCK(&rhp_vpn_lock);

  RHP_TRC(0,RHPTRCID_VPN_GET_RTRN,"uxxx",rlm_id,peer_id,vpn_ref,vpn);
  return vpn_ref;
}

rhp_vpn_ref* rhp_vpn_get_no_alt_id(unsigned long rlm_id,rhp_ikev2_id* peer_id,rhp_eap_id* eap_peer_id)
{
	rhp_vpn* vpn = NULL;
	rhp_vpn_ref* vpn_ref = NULL;

  RHP_TRC(0,RHPTRCID_VPN_GET_VPN_NO_ALT_ID,"uxx",rlm_id,peer_id,eap_peer_id);

  RHP_LOCK(&rhp_vpn_lock);

  vpn_ref = rhp_vpn_get_unlocked(rlm_id,peer_id,eap_peer_id,1);
  vpn = RHP_VPN_REF(vpn_ref);

  RHP_UNLOCK(&rhp_vpn_lock);

  RHP_TRC(0,RHPTRCID_VPN_GET_NO_ALT_ID_RTRN,"uxxx",rlm_id,peer_id,vpn,vpn_ref);

  return vpn_ref;
}

rhp_vpn_ref* rhp_vpn_get_by_eap_peer_id_unlocked(unsigned long rlm_id,rhp_eap_id* eap_peer_id)
{
  int err = 0;
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;
  u32 hval;

  RHP_TRC(0,RHPTRCID_VPN_GET_BY_EAP_PEER_ID_UNLOCKED,"uxx",rlm_id,eap_peer_id,eap_peer_id);
  rhp_eap_id_dump("rhp_vpn_get_by_eap_peer_id_unlocked",eap_peer_id);

  if( eap_peer_id->identity_len < 1 || eap_peer_id->identity == NULL || !eap_peer_id->method ){
  	RHP_BUG("%d, 0x%x, %d",eap_peer_id->identity_len,eap_peer_id->identity,eap_peer_id->method);
  	return NULL;
  }

  err = _rhp_vpn_eap_id_hash(eap_peer_id,&hval);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  vpn = _rhp_vpn_eap_peer_id_hashtbl[hval];

  while( vpn ){

    if( (!rlm_id || (vpn->vpn_realm_id == rlm_id)) &&
    		!rhp_eap_id_cmp(&(vpn->eap.peer_id),eap_peer_id) ){

    	break;
    }

    vpn = vpn->next_hash_eap_id;
  }

  if( vpn ){

  	vpn_ref = rhp_vpn_hold_ref(vpn);

    RHP_TRC(0,RHPTRCID_VPN_GET_BY_EAP_PEER_ID_UNLOCKED_RTRN,"xpuxx",vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm,vpn_ref);

  }else{
    RHP_TRC(0,RHPTRCID_VPN_GET_BY_EAP_PEER_ID_UNLOCKED_NO_ENTRY,"");
  }

error:
  return vpn_ref;
}

rhp_vpn_ref* rhp_vpn_get_by_eap_peer_id(unsigned long rlm_id,rhp_eap_id* eap_peer_id)
{
	rhp_vpn* vpn = NULL;
	rhp_vpn_ref* vpn_ref = NULL;

  RHP_TRC(0,RHPTRCID_VPN_GET_BY_EAP_PEER_ID,"uxx",rlm_id,eap_peer_id,eap_peer_id);
  rhp_eap_id_dump("rhp_vpn_get_by_eap_peer_id",eap_peer_id);

  RHP_LOCK(&rhp_vpn_lock);

  vpn_ref = rhp_vpn_get_by_eap_peer_id_unlocked(rlm_id,eap_peer_id);
  vpn = RHP_VPN_REF(vpn_ref);

  RHP_UNLOCK(&rhp_vpn_lock);

  RHP_TRC(0,RHPTRCID_VPN_GET_BY_EAP_PEER_ID_RTRN,"uxxx",rlm_id,eap_peer_id,vpn_ref,vpn);
  return vpn_ref;
}

rhp_vpn_list* rhp_vpn_list_alloc(rhp_vpn* vpn)
{
	rhp_vpn_list* vpn_lst = (rhp_vpn_list*)_rhp_malloc(sizeof(rhp_vpn_list));

	if( vpn_lst == NULL ){

		RHP_BUG("");
		return NULL;

	}

	memset(vpn_lst,0,sizeof(rhp_vpn_list));

	if( vpn ){
		vpn_lst->vpn_ref = rhp_vpn_hold_ref(vpn);
	}

	return vpn_lst;
}

void rhp_vpn_list_free(rhp_vpn_list* vpn_lst_head)
{
	rhp_vpn_list* vpn_lst = vpn_lst_head;

	while( vpn_lst ){

		rhp_vpn_list* vpn_lst_n = vpn_lst->next;

		if( vpn_lst->vpn_ref ){
			rhp_vpn_unhold(vpn_lst->vpn_ref);
		}

		_rhp_free(vpn_lst);

		vpn_lst = vpn_lst_n;
	}

	return;
}

int rhp_vpn_get_by_peer_addr_impl(unsigned long rlm_id,
		int addr_family,u8* peer_address,rhp_vpn_list** vpn_lst_head_r)
{
	int err = -ENOENT;
  rhp_vpn* vpn = NULL;
  rhp_vpn_list* vpn_lst;
  rhp_vpn_list *vpn_lst_head = NULL, *vpn_lst_tail = NULL;
  u32 hval;
  int n = 0;

	if( addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_VPN_GET_BY_PEER_ADDR_IMPL_V4,"uLd4",rlm_id,"AF",addr_family,*((u32*)peer_address));
	}else if( addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_VPN_GET_BY_PEER_ADDR_IMPL_V6,"uLd6",rlm_id,"AF",addr_family,peer_address);
	}else{
		RHP_BUG("%d",addr_family);
		return -EINVAL;
  }

  RHP_LOCK(&rhp_vpn_lock);

	if( addr_family == AF_INET ){

		hval = _rhp_vpn_peer_addrv4_hash(*((u32*)peer_address));
		vpn = _rhp_vpn_peer_addr_v4_hashtbl[hval];

	}else if( addr_family == AF_INET6 ){

		hval = _rhp_vpn_peer_addrv6_hash(peer_address);
		vpn = _rhp_vpn_peer_addr_v6_hashtbl[hval];
	}

  while( vpn ){

    if( !rlm_id ||
    		vpn->vpn_realm_id == rlm_id ){

    	vpn_lst = rhp_vpn_list_alloc(vpn);
    	if( vpn_lst == NULL ){

    		RHP_UNLOCK(&rhp_vpn_lock);

    		RHP_BUG("");
    		err = -ENOMEM;

    		goto error;
    	}

    	if( vpn_lst_head == NULL ){
    		vpn_lst_head = vpn_lst;
    	}else{
    		vpn_lst_tail->next = vpn_lst;
    	}
    	vpn_lst_tail = vpn_lst;

    	n++;

    	RHP_TRC(0,RHPTRCID_VPN_GET_BY_PEER_ADDR_IMPL_VPN,"uxdxxxu",rlm_id,vpn_lst_head,n,vpn_lst,vpn_lst->vpn_ref,RHP_VPN_REF(vpn_lst->vpn_ref),vpn->vpn_realm_id);
    }

    vpn = vpn->next_hash_peer_addr;
  }

	RHP_UNLOCK(&rhp_vpn_lock);


	if( vpn_lst_head == NULL ){
		err = -ENOENT;
		goto error;
	}

	*vpn_lst_head_r = vpn_lst_head;

	RHP_TRC(0,RHPTRCID_VPN_GET_BY_PEER_ADDR_IMPL_RTRN,"uxd",rlm_id,vpn_lst_head,n);
  return 0;

error:
	if( vpn_lst_head ){
		rhp_vpn_list_free(vpn_lst_head);
	}
	RHP_TRC(0,RHPTRCID_VPN_GET_BY_PEER_ADDR_IMPL_ERR,"uE",rlm_id,err);
	return err;
}

int rhp_vpn_update_by_peer_addr(rhp_vpn* vpn,int new_addr_family,u8* new_peer_addr)
{
  u32 hval;

	if( new_addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_VPN_UPDATE_BY_PEER_ADDR_V4,"xuLd4",vpn,vpn->vpn_realm_id,"AF",new_addr_family,*((u32*)new_peer_addr));
	}else if( new_addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_VPN_UPDATE_BY_PEER_ADDR_V6,"xuLd6",vpn,vpn->vpn_realm_id,"AF",new_addr_family,new_peer_addr);
	}else{
		RHP_BUG("%d",new_addr_family);
		return -EINVAL;
  }

  RHP_LOCK(&rhp_vpn_lock);

  _rhp_vpn_delete_by_peer_addr(vpn);
  vpn->next_hash_peer_addr = NULL;

	if( new_addr_family == AF_INET ){

		hval = _rhp_vpn_peer_addrv4_hash(*((u32*)new_peer_addr));
		vpn->next_hash_peer_addr = _rhp_vpn_peer_addr_v4_hashtbl[hval];
		_rhp_vpn_peer_addr_v4_hashtbl[hval] = vpn;

	}else if( new_addr_family == AF_INET6 ){

		hval = _rhp_vpn_peer_addrv6_hash(new_peer_addr);
		vpn->next_hash_peer_addr = _rhp_vpn_peer_addr_v6_hashtbl[hval];
		_rhp_vpn_peer_addr_v6_hashtbl[hval] = vpn;

	}else{

		RHP_BUG("%d",new_addr_family);
	}

	RHP_UNLOCK(&rhp_vpn_lock);

	RHP_TRC(0,RHPTRCID_VPN_UPDATE_BY_PEER_ADDR_RTRN,"xu",vpn,vpn->vpn_realm_id);
	return 0;
}

//
// Get a head of vpn lists if multiple and redundant vpns
// (destinated to the same address) exist.
//
rhp_vpn_ref* rhp_vpn_get_by_peer_addr(unsigned long rlm_id,rhp_ip_addr* peer_addr0,rhp_ip_addr* peer_addr1)
{
	int err = -EINVAL;
  rhp_vpn_list* vpn_lst_head = NULL;
  rhp_vpn_ref* vpn_ref;


  RHP_TRC(0,RHPTRCID_VPN_GET_BY_PEER_ADDR,"uxx",rlm_id,peer_addr0,peer_addr1);
  rhp_ip_addr_dump("rhp_vpn_get_by_peer_addr.peer_addr0",peer_addr0);
  rhp_ip_addr_dump("rhp_vpn_get_by_peer_addr.peer_addr1",peer_addr1);


  err = rhp_vpn_get_by_peer_addr_impl(rlm_id,peer_addr0->addr_family,peer_addr0->addr.raw,&vpn_lst_head);

  if( err == -ENOENT && peer_addr1 ){

    err = rhp_vpn_get_by_peer_addr_impl(rlm_id,peer_addr1->addr_family,peer_addr1->addr.raw,&vpn_lst_head);
    if( err ){
    	goto error;
    }

  }else if( err ){

  	goto error;
  }


  vpn_ref = rhp_vpn_hold_ref(RHP_VPN_REF(vpn_lst_head->vpn_ref));


	rhp_vpn_list_free(vpn_lst_head);

  RHP_TRC(0,RHPTRCID_VPN_GET_BY_PEER_ADDR_RTRN,"uxxxxx",rlm_id,peer_addr0,peer_addr1,vpn_lst_head,RHP_VPN_REF(vpn_ref),vpn_ref);
  return vpn_ref;

error:
	if( vpn_lst_head ){
		rhp_vpn_list_free(vpn_lst_head);
	}

	RHP_TRC(0,RHPTRCID_VPN_GET_BY_PEER_ADDR_ERR,"uxxxE",rlm_id,peer_addr0,peer_addr1,vpn_lst_head,err);
	return NULL;
}

//
// peer_proto_addr is compared with NRHP registration cache.
//
rhp_vpn_ref* rhp_vpn_get_by_nhrp_peer_nbma_proto_addrs(unsigned long rlm_id,
		rhp_ip_addr* peer_nbma_addr,rhp_ip_addr* peer_proto_addr)
{
	int err = -EINVAL;
	rhp_vpn_list *vpn_lst_head = NULL, *vpn_lst;
	rhp_vpn* vpn_by_proto_addr = NULL;
	rhp_vpn_ref* vpn_ref = NULL;

	RHP_TRC(0,RHPTRCID_VPN_GET_BY_NHRP_PEER_NBMA_PROTO_ADDRS,"uxx",rlm_id,peer_nbma_addr,peer_proto_addr);
	rhp_ip_addr_dump("peer_nbma_addr",peer_nbma_addr);
	rhp_ip_addr_dump("peer_proto_addr",peer_proto_addr);


	err = rhp_vpn_get_by_peer_addr_impl(rlm_id,
			peer_nbma_addr->addr_family,peer_nbma_addr->addr.raw,&vpn_lst_head);
	if( err ){
		goto error;
	}


	vpn_by_proto_addr = rhp_nhrp_cache_get_vpn(
										peer_proto_addr->addr_family,peer_proto_addr->addr.raw,rlm_id);
	if( vpn_by_proto_addr == NULL ){
		goto error;
	}

	vpn_lst = vpn_lst_head;
	while( vpn_lst ){

		if( RHP_VPN_REF(vpn_lst->vpn_ref) == vpn_by_proto_addr ){
			break;
		}

		vpn_lst = vpn_lst->next;
	}

	if( vpn_lst == NULL ){
		goto error;
	}

	vpn_ref = rhp_vpn_hold_ref(RHP_VPN_REF(vpn_lst->vpn_ref));

	rhp_vpn_unhold(vpn_by_proto_addr);
	rhp_vpn_list_free(vpn_lst_head);

	RHP_TRC(0,RHPTRCID_VPN_GET_BY_NHRP_PEER_NBMA_PROTO_ADDRS_RTRN,"uxxxx",rlm_id,peer_nbma_addr,peer_proto_addr,vpn_ref,RHP_VPN_REF(vpn_ref));
	return vpn_ref;

error:
	if( vpn_by_proto_addr ){
		rhp_vpn_unhold(vpn_by_proto_addr);
	}
	if( vpn_lst_head ){
		rhp_vpn_list_free(vpn_lst_head);
	}

	RHP_TRC(0,RHPTRCID_VPN_GET_BY_NHRP_PEER_NBMA_PROTO_ADDRS_ERR,"uxxxxE",rlm_id,peer_nbma_addr,peer_proto_addr,vpn_lst_head,vpn_by_proto_addr,err);
	return NULL;
}


struct _rhp_vpn_get_by_ctx {

	rhp_ip_addr* peer_addr0;
	rhp_ip_addr* peer_addr1;
	char* peer_fqdn;

	rhp_vpn_ref* vpn_ref;
};
typedef struct _rhp_vpn_get_by_ctx rhp_vpn_get_by_ctx;

static int _rhp_vpn_get_by_peer_fqdn_cb(rhp_vpn* vpn,void* ctx)
{
	rhp_vpn_get_by_ctx* b_ctx = (rhp_vpn_get_by_ctx*)ctx;

  RHP_LOCK(&(vpn->lock));

  if( vpn->peer_fqdn &&
  		!strcmp(vpn->peer_fqdn,b_ctx->peer_fqdn) ){

    RHP_UNLOCK(&(vpn->lock));

		b_ctx->vpn_ref = rhp_vpn_hold_ref(vpn);

		RHP_TRC(0,RHPTRCID_VPN_GET_VPN_BY_PEER_FQDN_FOUND,"xspuxx",vpn,b_ctx->peer_fqdn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm,b_ctx->vpn_ref);
		return RHP_STATUS_ENUM_OK;
  }

  RHP_UNLOCK(&(vpn->lock));

  RHP_TRC(0,RHPTRCID_VPN_GET_VPN_BY_PEER_FQDN_NOT_INTERESTED,"xsx",b_ctx,b_ctx->peer_fqdn,vpn);
  return 0;
}

// [CAUTION] Don't call this api within ANY locked scope!
rhp_vpn_ref* rhp_vpn_get_by_peer_fqdn(unsigned long rlm_id,char* peer_fqdn)
{
	rhp_vpn_get_by_ctx b_ctx;

  RHP_TRC(0,RHPTRCID_VPN_GET_VPN_BY_PEER_FQDN,"us",rlm_id,peer_fqdn);

  memset(&b_ctx,0,sizeof(rhp_vpn_get_by_ctx));
  b_ctx.peer_fqdn = peer_fqdn;

  rhp_vpn_enum(rlm_id,_rhp_vpn_get_by_peer_fqdn_cb,(void*)&b_ctx);

  RHP_TRC(0,RHPTRCID_VPN_GET_VPN_BY_PEER_FQDN_RTRN,"usx",rlm_id,peer_fqdn,b_ctx.vpn_ref);
  return b_ctx.vpn_ref;
}


struct _rhp_vpn_unique_ids_tls_cache {

	//
	// This table is stored in TLS area. So mutex or refcnt not needed.
	//

	u8 tag[4]; // '#VUC'

	struct _rhp_vpn_unique_ids_tls_cache* hash_next;

	unsigned long rml_id;
  u8* unique_ids;
  int unique_ids_num;
  unsigned long hval;
};
typedef struct _rhp_vpn_unique_ids_tls_cache		rhp_vpn_unique_ids_tls_cache;



static __thread rhp_vpn_unique_ids_tls_cache** _rhp_vpn_uids_cache_hashtbl = NULL;
static __thread int rhp_vpn_unique_ids_tls_cache_num = 0;

void rhp_vpn_unique_ids_init_tls()
{
	_rhp_vpn_uids_cache_hashtbl
	= (rhp_vpn_unique_ids_tls_cache**)_rhp_malloc(sizeof(rhp_vpn_unique_ids_tls_cache*)*RHP_VPN_HASH_TABLE_SIZE);

	if( _rhp_vpn_uids_cache_hashtbl ){
		memset(_rhp_vpn_uids_cache_hashtbl,0,sizeof(rhp_vpn_unique_ids_tls_cache*)*RHP_VPN_HASH_TABLE_SIZE);
	}

  RHP_TRC(0,RHPTRCID_VPN_UNIQUE_IDS_INIT_TLS,"x",_rhp_vpn_uids_cache_hashtbl);
	return;
}

static unsigned long _rhp_vpn_unique_ids_tls_hash(unsigned long rlm_id)
{
	return (rlm_id % RHP_VPN_HASH_TABLE_SIZE);
}

static void _rhp_vpn_unique_ids_tls_cache_put(unsigned long rlm_id,rhp_vpn_unique_ids_tls_cache* uids_cent)
{
	unsigned long hval;
	rhp_vpn_unique_ids_tls_cache* uids_cent_head;

  RHP_TRC(0,RHPTRCID_VPN_UNIQUE_IDS_TLS_CACHE_PUT,"ux",rlm_id,uids_cent);

	if( _rhp_vpn_uids_cache_hashtbl == NULL ){
	  RHP_TRC(0,RHPTRCID_VPN_UNIQUE_IDS_TLS_CACHE_PUT_TBL_NULL,"ux",rlm_id,uids_cent);
		return;
	}

	hval = _rhp_vpn_unique_ids_tls_hash(rlm_id);
	uids_cent->hval = hval;
	uids_cent_head = _rhp_vpn_uids_cache_hashtbl[hval];

	if( uids_cent_head ){
		uids_cent->hash_next = uids_cent_head;
	}
	_rhp_vpn_uids_cache_hashtbl[hval] = uids_cent;

	rhp_vpn_unique_ids_tls_cache_num++;

  RHP_TRC(0,RHPTRCID_VPN_UNIQUE_IDS_TLS_CACHE_PUT_RTRN,"ux",rlm_id,uids_cent);
	return;
}

static void _rhp_vpn_unique_ids_tls_cache_clear(unsigned long rlm_id)
{
	unsigned long hval;
	rhp_vpn_unique_ids_tls_cache *uids_cent,*uids_cent_p = NULL;

  RHP_TRC(0,RHPTRCID_VPN_UNIQUE_IDS_TLS_CACHE_CLEAR,"u",rlm_id);

	if( _rhp_vpn_uids_cache_hashtbl == NULL ){
	  RHP_TRC(0,RHPTRCID_VPN_UNIQUE_IDS_TLS_CACHE_CLEAR_TBL_NULL,"u",rlm_id);
		return;
	}

	hval = _rhp_vpn_unique_ids_tls_hash(rlm_id);
	uids_cent = _rhp_vpn_uids_cache_hashtbl[hval];

	while( uids_cent ){

		if( uids_cent->rml_id == rlm_id ){
			break;
		}

		uids_cent_p = uids_cent;
		uids_cent = uids_cent->hash_next;
	}

	if( uids_cent == NULL ){
	  RHP_TRC(0,RHPTRCID_VPN_UNIQUE_IDS_TLS_CACHE_CLEAR_NO_ENTRY,"u",rlm_id);
		return;
	}

	if( uids_cent_p ){
		uids_cent_p->hash_next = uids_cent->hash_next;
	}else{
		_rhp_vpn_uids_cache_hashtbl[hval] = uids_cent->hash_next;
	}

	_rhp_free(uids_cent->unique_ids);
	_rhp_free(uids_cent);

	rhp_vpn_unique_ids_tls_cache_num--;

  RHP_TRC(0,RHPTRCID_VPN_UNIQUE_IDS_TLS_CACHE_CLEAR_RTRN,"ux",rlm_id,uids_cent);
	return;
}

static rhp_vpn_unique_ids_tls_cache* _rhp_vpn_unique_ids_tls_cache_get(unsigned long rlm_id)
{
	unsigned long hval;
	rhp_vpn_unique_ids_tls_cache* uids_cent;

  RHP_TRC(0,RHPTRCID_VPN_UNIQUE_IDS_TLS_CACHE_GET,"u",rlm_id);

	if( _rhp_vpn_uids_cache_hashtbl == NULL ){
	  RHP_TRC(0,RHPTRCID_VPN_UNIQUE_IDS_TLS_CACHE_GET_TBL_NULL,"u",rlm_id);
		return NULL;
	}

	hval = _rhp_vpn_unique_ids_tls_hash(rlm_id);
	uids_cent = _rhp_vpn_uids_cache_hashtbl[hval];

	while(uids_cent){

		if( uids_cent->rml_id == rlm_id ){

			RHP_TRC(0,RHPTRCID_VPN_UNIQUE_IDS_TLS_CACHE_GET_RTRN,"ux",rlm_id,uids_cent);

			return uids_cent;
		}

		uids_cent = uids_cent->hash_next;
	}

  RHP_TRC(0,RHPTRCID_VPN_UNIQUE_IDS_TLS_CACHE_GET_NO_ENTRY,"u",rlm_id);
	return NULL;
}

static void _rhp_vpn_clear_unique_ids_tls_cache_task(int worker_idx,void* ctx)
{
	unsigned long rlm_id = (unsigned long)ctx;

  RHP_TRC(0,RHPTRCID_VPN_CLEAR_UNIQUE_IDS_TLS_CACHE_TASK,"du",worker_idx,rlm_id);

	_rhp_vpn_unique_ids_tls_cache_clear(rlm_id);

  RHP_TRC(0,RHPTRCID_VPN_CLEAR_UNIQUE_IDS_TLS_CACHE_TASK_RTRN,"u",rlm_id);
	return;
}

int rhp_vpn_clear_unique_ids_tls_cache(unsigned long rlm_id)
{
	int err;

	RHP_TRC(0,RHPTRCID_VPN_CLEAR_UNIQUE_IDS_TLS_CACHE,"u",rlm_id);

	err = rhp_wts_add_ctrl_task(_rhp_vpn_clear_unique_ids_tls_cache_task,NULL,(void*)rlm_id);

	RHP_TRC(0,RHPTRCID_VPN_CLEAR_UNIQUE_IDS_TLS_CACHE_RTRN,"uE",rlm_id,err);
	return err;
}

int rhp_vpn_enum_unique_ids2(unsigned long rlm_id,int no_tls_cache,u8** unique_ids_r,int* unique_ids_num_r,int* free_by_caller_r)
{
  rhp_vpn *vpn;
  u8* unique_ids = NULL;
  int unique_ids_num = 0;
#define RHP_VPN_ENUM_BUF_SIZE		8
  int buf_n = 0;
  int err = 0;
  rhp_vpn_unique_ids_tls_cache* uids_cent = NULL;

	RHP_TRC_FREQ(0,RHPTRCID_VPN_ENUM_UNIQUE_IDS,"uxxx",rlm_id,unique_ids_r,unique_ids_num_r,free_by_caller_r);

	if( !no_tls_cache ){

		uids_cent = _rhp_vpn_unique_ids_tls_cache_get(rlm_id);

		if( uids_cent ){

			*unique_ids_r = uids_cent->unique_ids;
			*unique_ids_num_r = uids_cent->unique_ids_num;
			*free_by_caller_r = 0;

			RHP_TRC_FREQ(0,RHPTRCID_VPN_ENUM_UNIQUE_IDS_CACHED_FOUND,"xudp",uids_cent,uids_cent->rml_id,uids_cent->unique_ids_num,(RHP_VPN_UNIQUE_ID_SIZE*uids_cent->unique_ids_num),uids_cent->unique_ids);
			return 0;
		}
	}

  //
  // [CAUTION] Don't call APIs with rhp_vpn_lock locked.
  //

  RHP_LOCK(&rhp_vpn_lock);

  vpn = rhp_vpn_list_head.next_list;
  while( vpn ){

  	// 'vpn->vpn_realm_id' and 'vpn->unique_id' are immutable values.
  	// 'vpn->lock' is NOT needed.

  	if( vpn->vpn_realm_id == rlm_id ){

  		if( buf_n < 1 ){

  			u8* new_buf;

  			new_buf = (u8*)_rhp_malloc((unique_ids_num + RHP_VPN_ENUM_BUF_SIZE)*RHP_VPN_UNIQUE_ID_SIZE);
  		  if( new_buf == NULL ){

  		  	RHP_BUG("");
  		  	err = -ENOMEM;
  		  	goto error;
  		  }

  		  if( unique_ids_num ){
  		  	memcpy(new_buf,unique_ids,unique_ids_num*RHP_VPN_UNIQUE_ID_SIZE);
  		  }

  		  memset((new_buf + unique_ids_num*RHP_VPN_UNIQUE_ID_SIZE),0,RHP_VPN_UNIQUE_ID_SIZE*RHP_VPN_ENUM_BUF_SIZE);

  		  if( unique_ids ){
  		  	_rhp_free(unique_ids);
  		  }

		  	unique_ids = new_buf;
		  	buf_n = RHP_VPN_ENUM_BUF_SIZE;
  		}

		  memcpy((unique_ids + unique_ids_num*RHP_VPN_UNIQUE_ID_SIZE),vpn->unique_id,RHP_VPN_UNIQUE_ID_SIZE);

		  buf_n--;
		  unique_ids_num++;
  	}

  	vpn = vpn->next_list;
  }

  if( unique_ids_num < 1 ){
  	RHP_TRC_FREQ(0,RHPTRCID_VPN_ENUM_UNIQUE_IDS_NO_ENTRY,"u",rlm_id);
  	err = -ENOENT;
  	goto error;
  }

  //
  // TODO : Limits max cache size for each TLS.
  //
	if( !no_tls_cache ){

	  uids_cent = (rhp_vpn_unique_ids_tls_cache*)_rhp_malloc(sizeof(rhp_vpn_unique_ids_tls_cache));

	  if( uids_cent ){

		  memset(uids_cent,0,sizeof(rhp_vpn_unique_ids_tls_cache));

		  uids_cent->tag[0] = '#';
		  uids_cent->tag[1] = 'V';
		  uids_cent->tag[2] = 'U';
		  uids_cent->tag[3] = 'C';

		  uids_cent->unique_ids = unique_ids;
		  uids_cent->unique_ids_num = unique_ids_num;
		  uids_cent->rml_id = rlm_id;

		  _rhp_vpn_unique_ids_tls_cache_clear(rlm_id);
		  _rhp_vpn_unique_ids_tls_cache_put(rlm_id,uids_cent);

	  	*free_by_caller_r = 0;

	  }else{
	  	*free_by_caller_r = 1;
	  }

	}else{
  	*free_by_caller_r = 1;
  }

  RHP_UNLOCK(&rhp_vpn_lock);

 	*unique_ids_r = unique_ids;
 	*unique_ids_num_r = unique_ids_num;

  RHP_TRC_FREQ(0,RHPTRCID_VPN_ENUM_UNIQUE_IDS_RTRN,"udpd",rlm_id,*unique_ids_num_r,(RHP_VPN_UNIQUE_ID_SIZE*unique_ids_num),*unique_ids_r,*free_by_caller_r);
 	return 0;

error:
	RHP_UNLOCK(&rhp_vpn_lock);

	if( unique_ids ){
		_rhp_free(unique_ids);
	}

	RHP_TRC_FREQ(0,RHPTRCID_VPN_ENUM_UNIQUE_IDS_ERR,"uE",rlm_id,err);
	return err;
}

int rhp_vpn_enum_unique_ids(unsigned long rlm_id,u8** unique_ids_r,int* unique_ids_num_r,int* free_by_caller_r)
{
	return rhp_vpn_enum_unique_ids2(rlm_id,0,unique_ids_r,unique_ids_num_r,free_by_caller_r);
}

#define RHP_VPN_ENUM_LST_LEN		128
static int _rhp_vpn_enum_list_realloc(int n,int* vpn_list_num_r,rhp_vpn*** vpn_list_head_r)
{
	if( n >= *vpn_list_num_r ){

		rhp_vpn** tmp;

		*vpn_list_num_r += RHP_VPN_ENUM_LST_LEN;

		tmp = (rhp_vpn**)_rhp_malloc(sizeof(rhp_vpn*)*(*vpn_list_num_r));
		if( tmp == NULL ){
			RHP_BUG("");
			return -ENOMEM;
		}

		memset(tmp,0,sizeof(rhp_vpn*)*(*vpn_list_num_r));

		memcpy(tmp,*vpn_list_head_r,sizeof(rhp_vpn*)*n);
		_rhp_free(*vpn_list_head_r);

		*vpn_list_head_r = tmp;
	}

	return 0;
}

int rhp_vpn_enum(unsigned long rlm_id,int (*callback)(rhp_vpn* vpn,void* ctx),void* ctx)
{
	int err = -EINVAL;
	rhp_vpn** vpn_list_head;
	int vpn_list_num = RHP_VPN_ENUM_LST_LEN;
  rhp_vpn* vpn;
  rhp_vpn_ikesa_spi_entry* spi_ent;
  int n = 0,i;

  RHP_TRC(0,RHPTRCID_VPN_ENUM,"uYx",rlm_id,callback,ctx);

  if( callback == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  vpn_list_head = (rhp_vpn**)_rhp_malloc(sizeof(rhp_vpn*)*vpn_list_num);
  if( vpn_list_head == NULL ){
  	RHP_BUG("");
  	return -ENOMEM;
  }
	memset(vpn_list_head,0,sizeof(rhp_vpn*)*vpn_list_num);


  RHP_LOCK(&rhp_vpn_lock);

  vpn = rhp_vpn_list_head.next_list;
  while( vpn ){

  	if( rlm_id == 0 || vpn->vpn_realm_id == rlm_id ){

  		err = _rhp_vpn_enum_list_realloc(n,&vpn_list_num,&vpn_list_head);
  		if( err ){

  			RHP_BUG("");

  		  for( i = 0; i < n; i++ ){
  		  	rhp_vpn_unhold(vpn_list_head[i]);
  		  }
  			_rhp_free(vpn_list_head);

  			RHP_UNLOCK(&rhp_vpn_lock);

  			return err;
  		}

    	vpn_list_head[n] = vpn;
    	rhp_vpn_hold(vpn); // rhp_vpn_hold_ref NOT used here.

    	n++;
  	}

  	vpn = vpn->next_list;
  }


  spi_ent = rhp_vpn_ikesa_spi_list_head.next_lst;
	while( spi_ent ){

		vpn = spi_ent->vpn;

		if( (rlm_id == 0 || vpn->vpn_realm_id == rlm_id) && vpn->connecting ){

  		err = _rhp_vpn_enum_list_realloc(n,&vpn_list_num,&vpn_list_head);
  		if( err ){

  			RHP_BUG("");

  		  for( i = 0; i < n; i++ ){
  		  	rhp_vpn_unhold(vpn_list_head[i]);
  		  }
  			_rhp_free(vpn_list_head);

  			RHP_UNLOCK(&rhp_vpn_lock);

  			return err;
  		}

    	vpn_list_head[n] = vpn;
    	rhp_vpn_hold(vpn); // rhp_vpn_hold_ref NOT used here.

    	n++;
		}

		spi_ent = spi_ent->next_lst;
	}

  RHP_UNLOCK(&rhp_vpn_lock);


  if( n == 0 ){
  	_rhp_free(vpn_list_head);
    RHP_TRC(0,RHPTRCID_VPN_ENUM_NO_ENT,"u",rlm_id);
  	return -ENOENT;
  }

  for( i = 0; i < n; i++ ){

  	vpn = vpn_list_head[i];

		err = callback(vpn,ctx);
		if( err ){

	  	if( err == RHP_STATUS_ENUM_OK ){
	  		err = 0;
	  	}

			break;
		}
  }

  for( i = 0; i < n; i++ ){
  	rhp_vpn_unhold(vpn_list_head[i]);
  }

  _rhp_free(vpn_list_head);

  RHP_TRC(0,RHPTRCID_VPN_ENUM_RTRN,"u",rlm_id);
  return 0;
}

/*
rhp_vpn_ref* rhp_vpn_get_by_dummy_peer_mac_no_lock(u8* dummy_peer_mac)
{
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;
  u32 hval;

	RHP_TRC(0,RHPTRCID_VPN_GET_BY_DUMMY_PEER_MAC_NO_LOCK,"M",dummy_peer_mac);

  _rhp_vpn_ck_next_hash_dummy_peer_mac();

  hval = _rhp_vpn_dummy_peer_mac_hash(vpn->internal_net_info.dummy_peer_mac);

  vpn = _rhp_vpn_dummy_peer_mac_hashtbl[hval];

  while( vpn ){

  	if( !memcmp(dummy_peer_mac,vpn->internal_net_info.dummy_peer_mac,6) ){
  		break;
  	}

    vpn = RHP_CK_OBJTAG("#VPN",vpn->next_hash_dummy_peer_mac);
  }

  if( vpn ){

		vpn_ref = rhp_vpn_hold_ref(vpn);

  	RHP_TRC(0,RHPTRCID_VPN_GET_BY_DUMMY_PEER_MAC_NO_LOCK_RTRN,"Mxpuxx",dummy_peer_mac,vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm,vpn_ref);
  	rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
  	rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));

  }else{
  	RHP_TRC(0,RHPTRCID_VPN_GET_BY_DUMMY_PEER_MAC_NO_LOCK_NO_ENTRY,"M",dummy_peer_mac);
  }

  return vpn_ref;
}
*/
/*
rhp_vpn_ref* rhp_vpn_get_by_dummy_peer_mac(u8* dummy_peer_mac)
{
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;

	RHP_TRC(0,RHPTRCID_VPN_GET_BY_DUMMY_PEER_MAC,"M",dummy_peer_mac);

  RHP_LOCK(&rhp_vpn_lock);

  vpn_ref = rhp_vpn_get_by_dummy_peer_mac_no_lock(dummy_peer_mac);
  vpn = RHP_VPN_REF(vpn_ref);

  RHP_UNLOCK(&rhp_vpn_lock);

	RHP_TRC(0,RHPTRCID_VPN_GET_BY_DUMMY_PEER_MAC_RTRN,"Mxx",dummy_peer_mac,vpn,vpn_ref);

	return vpn_ref;
}
*/


int rhp_vpn_put_by_peer_internal_addr(rhp_ip_addr* peer_internal_ip,rhp_vpn* vpn)
{
  u32 hval;
  rhp_vpn_itnl_peera_entry* pa_vpn = NULL;

	RHP_TRC(0,RHPTRCID_VPN_PUT_BY_PEER_INTERNAL_ADDR,"xx",peer_internal_ip,vpn);
	rhp_ip_addr_dump("peer_internal_ip",peer_internal_ip);

	{
		pa_vpn = (rhp_vpn_itnl_peera_entry*)_rhp_malloc(sizeof(rhp_vpn_itnl_peera_entry));
		if( pa_vpn == NULL ){
			RHP_BUG("");
			return -ENOMEM;
		}
		memset(pa_vpn,0,sizeof(rhp_vpn_itnl_peera_entry));

		pa_vpn->tag[0] = '#';
		pa_vpn->tag[1] = 'V';
		pa_vpn->tag[2] = 'A';
		pa_vpn->tag[3] = 'P';

		pa_vpn->vpn_realm_id = vpn->vpn_realm_id;
		memcpy(&(pa_vpn->peer_internal_ip),peer_internal_ip,sizeof(rhp_ip_addr));
	}


  RHP_LOCK(&rhp_vpn_lock);

	RHP_TRC(0,RHPTRCID_VPN_PUT_BY_PEER_INTERNAL_ADDR_VPN,"xxpux",peer_internal_ip,vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm);
	rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
	rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));

	if( peer_internal_ip->addr_family == AF_INET ){

		hval = _rhp_vpn_peer_addrv4_hash(peer_internal_ip->addr.v4);

		pa_vpn->next_hash = _rhp_vpn_internal_peer_addr_v4_hashtbl[hval];
	  _rhp_vpn_internal_peer_addr_v4_hashtbl[hval] = pa_vpn;

	}else if( peer_internal_ip->addr_family == AF_INET6 ){

		hval = _rhp_vpn_peer_addrv6_hash(peer_internal_ip->addr.v6);

		pa_vpn->next_hash = _rhp_vpn_internal_peer_addr_v6_hashtbl[hval];
	  _rhp_vpn_internal_peer_addr_v6_hashtbl[hval] = pa_vpn;

	}else{

		RHP_BUG("%d",peer_internal_ip->addr_family);

		RHP_UNLOCK(&rhp_vpn_lock);

		_rhp_free(pa_vpn);
		return -EINVAL;
	}


	pa_vpn->vpn_ref = rhp_vpn_hold_ref(vpn);

  RHP_UNLOCK(&rhp_vpn_lock);

	RHP_TRC(0,RHPTRCID_VPN_PUT_BY_PEER_INTERNAL_ADDR_RTRN,"xxxx",peer_internal_ip,vpn,pa_vpn,pa_vpn->vpn_ref);
	return 0;
}

int rhp_vpn_delete_by_peer_internal_addr(rhp_ip_addr* peer_internal_ip,rhp_vpn* vpn)
{
  int err = 0;
  u32 hval;
  rhp_vpn_itnl_peera_entry *pa_vpn_tmp = NULL,*pa_vpn_tmp_p = NULL;

	RHP_TRC(0,RHPTRCID_VPN_DELETE_BY_PEER_INTERNAL_ADDR,"xx",peer_internal_ip,vpn);
	rhp_ip_addr_dump("peer_internal_ip",peer_internal_ip);

  RHP_LOCK(&rhp_vpn_lock);

	RHP_TRC(0,RHPTRCID_VPN_DELETE_BY_PEER_INTERNAL_ADDR_VPN,"xxpux",peer_internal_ip,vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm);
	rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
	rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));

	if( peer_internal_ip->addr_family == AF_INET ){

		hval = _rhp_vpn_peer_addrv4_hash(peer_internal_ip->addr.v4);
		pa_vpn_tmp = _rhp_vpn_internal_peer_addr_v4_hashtbl[hval];

	}else if( peer_internal_ip->addr_family == AF_INET6 ){

		hval = _rhp_vpn_peer_addrv6_hash(peer_internal_ip->addr.v6);
		pa_vpn_tmp = _rhp_vpn_internal_peer_addr_v6_hashtbl[hval];

	}else{
		RHP_BUG("%d",peer_internal_ip->addr_family);
		err = -EINVAL;
		goto error;
	}

  while( pa_vpn_tmp ){

  	if( RHP_VPN_REF(pa_vpn_tmp->vpn_ref) == vpn ){
			break;
  	}

    pa_vpn_tmp_p = pa_vpn_tmp;

  	pa_vpn_tmp = pa_vpn_tmp->next_hash;
  }

  if( pa_vpn_tmp == NULL ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_VPN_DELETE_BY_PEER_INTERNAL_ADDR_NO_ENTRY,"xx",peer_internal_ip,vpn);
  	goto error;
  }

  if( pa_vpn_tmp_p ){

  	pa_vpn_tmp_p->next_hash = pa_vpn_tmp->next_hash;

  }else{

  	if( peer_internal_ip->addr_family == AF_INET ){
  		_rhp_vpn_internal_peer_addr_v4_hashtbl[hval] = pa_vpn_tmp->next_hash;
  	}else{ // AF_INET6
  		_rhp_vpn_internal_peer_addr_v6_hashtbl[hval] = pa_vpn_tmp->next_hash;
  	}
  }

  rhp_vpn_unhold(pa_vpn_tmp->vpn_ref);
  _rhp_free(pa_vpn_tmp);

	RHP_UNLOCK(&rhp_vpn_lock);

	RHP_TRC(0,RHPTRCID_VPN_DELETE_BY_PEER_INTERNAL_ADDR_RTRN,"xxx",peer_internal_ip,vpn,pa_vpn_tmp);
	return 0;

error:
	RHP_UNLOCK(&rhp_vpn_lock);

	RHP_TRC(0,RHPTRCID_VPN_DELETE_BY_PEER_INTERNAL_ADDR_ERR,"xxE",peer_internal_ip,vpn,err);
	return err;
}

// Caller must acquire rhp_vpn_lock...
rhp_vpn_ref* rhp_vpn_get_by_peer_internal_addr_no_lock(unsigned long rlm_id,
		rhp_ip_addr* peer_internal_ip)
{
	rhp_vpn_itnl_peera_entry* pa_vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;
  u32 hval;

	RHP_TRC(0,RHPTRCID_VPN_GET_BY_PEER_INTERNAL_ADDR_L,"ux",rlm_id,peer_internal_ip);
	rhp_ip_addr_dump("peer_internal_ip",peer_internal_ip);

	if( peer_internal_ip->addr_family == AF_INET ){

		hval = _rhp_vpn_peer_addrv4_hash(peer_internal_ip->addr.v4);
		pa_vpn = _rhp_vpn_internal_peer_addr_v4_hashtbl[hval];

	}else if( peer_internal_ip->addr_family == AF_INET6 ){

		hval = _rhp_vpn_peer_addrv6_hash(peer_internal_ip->addr.v6);
		pa_vpn = _rhp_vpn_internal_peer_addr_v6_hashtbl[hval];

	}else{
		RHP_BUG("%d",peer_internal_ip->addr_family);
		return NULL;
	}

  while( pa_vpn ){

  	if( pa_vpn->vpn_realm_id == rlm_id &&
  			!rhp_ip_addr_cmp_ip_only(peer_internal_ip,&(pa_vpn->peer_internal_ip)) ){
			break;
  	}

  	pa_vpn = pa_vpn->next_hash;
  }

  if( pa_vpn ){

  	vpn_ref = rhp_vpn_hold_ref(RHP_VPN_REF(pa_vpn->vpn_ref));

    RHP_TRC(0,RHPTRCID_VPN_GET_BY_PEER_INTERNAL_ADDR_L_RTRN,"xxxxpuxx",peer_internal_ip,pa_vpn,pa_vpn->vpn_ref,RHP_VPN_REF(pa_vpn->vpn_ref),RHP_VPN_UNIQUE_ID_SIZE,RHP_VPN_REF(pa_vpn->vpn_ref)->unique_id,RHP_VPN_REF(pa_vpn->vpn_ref)->vpn_realm_id,RHP_VPN_REF(pa_vpn->vpn_ref)->rlm,vpn_ref);
    rhp_ikev2_id_dump("vpn->my_id",&(RHP_VPN_REF(pa_vpn->vpn_ref)->my_id));
    rhp_ikev2_id_dump("vpn->peer_id",&(RHP_VPN_REF(pa_vpn->vpn_ref)->peer_id));

  }else{
  	RHP_TRC(0,RHPTRCID_VPN_GET_BY_PEER_INTERNAL_ADDR_L_NO_ENTRY,"x",peer_internal_ip);
  }

  return vpn_ref;
}

rhp_vpn_ref* rhp_vpn_get_by_peer_internal_addr(unsigned long rlm_id,rhp_ip_addr* peer_internal_ip)
{
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;

	RHP_TRC(0,RHPTRCID_VPN_GET_BY_PEER_INTERNAL_ADDR,"ux",rlm_id,peer_internal_ip);
	rhp_ip_addr_dump("peer_internal_ip",peer_internal_ip);

	RHP_LOCK(&rhp_vpn_lock);

	vpn_ref = rhp_vpn_get_by_peer_internal_addr_no_lock(rlm_id,peer_internal_ip);
	vpn = RHP_VPN_REF(vpn_ref);

  if( vpn ){
    RHP_TRC(0,RHPTRCID_VPN_GET_BY_PEER_INTERNAL_ADDR_RTRN,"xxpuxx",peer_internal_ip,vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm,vpn_ref);
  }else{
  	RHP_TRC(0,RHPTRCID_VPN_GET_BY_PEER_INTERNAL_ADDR_NO_ENTRY,"x",peer_internal_ip);
  }

  RHP_UNLOCK(&rhp_vpn_lock);

	return vpn_ref;
}

int rhp_vpn_put_by_peer_internal_mac(u8* mac,rhp_vpn* vpn)
{
  u32 hval;
  rhp_vpn_itnl_peerm_entry* pm_vpn = NULL;

	RHP_TRC(0,RHPTRCID_VPN_PUT_BY_PEER_INTERNAL_MAC,"MMx",mac,vpn->internal_net_info.exchg_peer_mac,vpn);

	if( !_rhp_mac_addr_null(vpn->internal_net_info.exchg_peer_mac) ){
		RHP_BUG("");
		return -EINVAL;
	}

	{
		pm_vpn = (rhp_vpn_itnl_peerm_entry*)_rhp_malloc(sizeof(rhp_vpn_itnl_peerm_entry));
		if( pm_vpn == NULL ){
			RHP_BUG("");
			return -ENOMEM;
		}
		memset(pm_vpn,0,sizeof(rhp_vpn_itnl_peerm_entry));

		pm_vpn->tag[0] = '#';
		pm_vpn->tag[1] = 'V';
		pm_vpn->tag[2] = 'M';
		pm_vpn->tag[3] = 'P';

		pm_vpn->vpn_realm_id = vpn->vpn_realm_id;
		memcpy(pm_vpn->peer_internal_mac,mac,6);
	}


  RHP_LOCK(&rhp_vpn_lock);

	RHP_TRC(0,RHPTRCID_VPN_PUT_BY_PEER_INTERNAL_MAC_VPN,"Mxpux",mac,vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm);
	rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
	rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));


	hval = _rhp_vpn_internal_peer_mac_hash(mac);

	pm_vpn->next_hash = _rhp_vpn_internal_peer_mac_hashtbl[hval];
  _rhp_vpn_internal_peer_mac_hashtbl[hval] = pm_vpn;

	pm_vpn->vpn_ref = rhp_vpn_hold_ref(vpn);

  RHP_UNLOCK(&rhp_vpn_lock);

	RHP_TRC(0,RHPTRCID_VPN_PUT_BY_PEER_INTERNAL_MAC_RTRN,"Mx",mac,vpn);
	return 0;
}

int rhp_vpn_delete_by_peer_internal_mac(u8* mac,rhp_vpn* vpn)
{
  int err = 0;
  u32 hval;
  rhp_vpn_itnl_peerm_entry *pm_vpn_tmp = NULL,*pm_vpn_tmp_p = NULL;

	RHP_TRC(0,RHPTRCID_VPN_DELETE_BY_PEER_INTERNAL_MAC,"MMx",mac,vpn->internal_net_info.exchg_peer_mac,vpn);

	if( _rhp_mac_addr_null(mac) ){
  	RHP_TRC(0,RHPTRCID_VPN_DELETE_BY_PEER_INTERNAL_MAC_NULL_NO_ENT,"Mx",mac,vpn);
		return -ENONET;
	}

  RHP_LOCK(&rhp_vpn_lock);

	RHP_TRC(0,RHPTRCID_VPN_DELETE_BY_PEER_INTERNAL_MAC_VPN,"Mxpux",mac,vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm);
	rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
	rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));

	hval = _rhp_vpn_internal_peer_mac_hash(mac);
	pm_vpn_tmp = _rhp_vpn_internal_peer_mac_hashtbl[hval];

  while( pm_vpn_tmp ){

  	if( RHP_VPN_REF(pm_vpn_tmp->vpn_ref) == vpn ){
	  	break;
  	}

    pm_vpn_tmp_p = pm_vpn_tmp;

  	pm_vpn_tmp = pm_vpn_tmp->next_hash;
  }

  if( pm_vpn_tmp == NULL ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_VPN_DELETE_BY_PEER_INTERNAL_MAC_NO_ENTRY,"Mx",mac,vpn);
  	goto error;
  }

  if( pm_vpn_tmp_p ){

  	pm_vpn_tmp_p->next_hash = pm_vpn_tmp->next_hash;

  }else{

		_rhp_vpn_internal_peer_mac_hashtbl[hval] = pm_vpn_tmp->next_hash;
  }

  rhp_vpn_unhold(pm_vpn_tmp->vpn_ref);
  _rhp_free(pm_vpn_tmp);

	RHP_UNLOCK(&rhp_vpn_lock);

	RHP_TRC(0,RHPTRCID_VPN_DELETE_BY_PEER_INTERNAL_MAC_RTRN,"Mxx",mac,vpn,pm_vpn_tmp);
	return 0;

error:
	RHP_UNLOCK(&rhp_vpn_lock);

	RHP_TRC(0,RHPTRCID_VPN_DELETE_BY_PEER_INTERNAL_MAC_ERR,"MxE",mac,vpn,err);
	return err;
}

// Caller must acquire rhp_vpn_lock...
rhp_vpn_ref* rhp_vpn_get_by_peer_internal_mac_no_lock(unsigned long rlm_id,u8* mac)
{
	rhp_vpn_itnl_peerm_entry* pm_vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;
  u32 hval;

	RHP_TRC(0,RHPTRCID_VPN_GET_BY_PEER_INTERNAL_MAC_L,"uM",rlm_id,mac);

	hval = _rhp_vpn_internal_peer_mac_hash(mac);
	pm_vpn = _rhp_vpn_internal_peer_mac_hashtbl[hval];

  while( pm_vpn ){

  	if( pm_vpn->vpn_realm_id == rlm_id &&
  			!memcmp(mac,pm_vpn->peer_internal_mac,6) ){
  		break;
  	}

  	pm_vpn = pm_vpn->next_hash;
  }

  if( pm_vpn ){

  	vpn_ref = rhp_vpn_hold_ref(RHP_VPN_REF(pm_vpn->vpn_ref));

    RHP_TRC(0,RHPTRCID_VPN_GET_BY_PEER_INTERNAL_MAC_L_RTRN,"Mxxxpuxx",mac,pm_vpn,pm_vpn->vpn_ref,RHP_VPN_REF(pm_vpn->vpn_ref),RHP_VPN_UNIQUE_ID_SIZE,RHP_VPN_REF(pm_vpn->vpn_ref)->unique_id,RHP_VPN_REF(pm_vpn->vpn_ref)->vpn_realm_id,RHP_VPN_REF(pm_vpn->vpn_ref)->rlm,vpn_ref);
    rhp_ikev2_id_dump("vpn->my_id",&(RHP_VPN_REF(pm_vpn->vpn_ref)->my_id));
    rhp_ikev2_id_dump("vpn->peer_id",&(RHP_VPN_REF(pm_vpn->vpn_ref)->peer_id));

  }else{
  	RHP_TRC(0,RHPTRCID_VPN_GET_BY_PEER_INTERNAL_MAC_L_NO_ENTRY,"M",mac);
  }

  return vpn_ref;
}

rhp_vpn_ref* rhp_vpn_get_by_peer_internal_mac(unsigned long rlm_id,u8* mac)
{
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;

	RHP_TRC(0,RHPTRCID_VPN_GET_BY_PEER_INTERNAL_MAC,"uM",rlm_id,mac);

	RHP_LOCK(&rhp_vpn_lock);

	vpn_ref = rhp_vpn_get_by_peer_internal_mac_no_lock(rlm_id,mac);
	vpn = RHP_VPN_REF(vpn_ref);

  if( vpn ){
    RHP_TRC(0,RHPTRCID_VPN_GET_BY_PEER_INTERNAL_MAC_RTRN,"Mxpuxx",mac,vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm,vpn_ref);
  }else{
  	RHP_TRC(0,RHPTRCID_VPN_GET_BY_PEER_INTERNAL_MAC_NO_ENTRY,"M",mac);
  }

  RHP_UNLOCK(&rhp_vpn_lock);

	return vpn_ref;
}

static void _rhp_vpn_auto_reconnect_free(rhp_vpn_reconnect_info* reconnect_info)
{
	rhp_ikev2_id_clear(&(reconnect_info->peer_id));

	if( reconnect_info->peer_fqdn ){
		_rhp_free(reconnect_info->peer_fqdn);
	}

	if( reconnect_info->sess_resume_material_i ){
		rhp_vpn_sess_resume_clear(reconnect_info->sess_resume_material_i);
	}

	_rhp_free(reconnect_info);
}

static void _rhp_vpn_free(rhp_vpn* vpn)
{
	int i;

	RHP_TRC(0,RHPTRCID_VPN_FREE,"xpuxddd",vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm,vpn->connecting,vpn->established,_rhp_atomic_read(&(vpn->is_active)));
  rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
  rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));

  if( _rhp_atomic_read(&(vpn->is_active)) ){
  	RHP_BUG("0x%lx",vpn);
#ifdef RHP_REFCNT_DEBUG_X
  	_rhp_panic();
#endif // RHP_REFCNT_DEBUG_X
  }

  if( vpn->connecting ){
  	rhp_ikesa_half_open_sessions_dec();
  }

  if( vpn->last_my_tss || vpn->last_peer_tss ){

  	rhp_childsa_free_traffic_selectors(vpn->last_my_tss,vpn->last_peer_tss);
  }

  if( vpn->ipv6_autoconf_my_tss || vpn->ipv6_autoconf_peer_tss ){

  	rhp_childsa_free_traffic_selectors(vpn->ipv6_autoconf_my_tss,vpn->ipv6_autoconf_peer_tss);
  }

  if( vpn->reconnect_info ){

  	_rhp_vpn_auto_reconnect_free(vpn->reconnect_info);
  }

 	rhp_vpn_clear_local_mac(vpn->internal_net_info.dummy_peer_mac);

 	if( vpn->cfg_peer ){
 		rhp_realm_free_peer_cfg(vpn->cfg_peer);
 	}

  if( vpn->rlm ){
  	rhp_realm_unhold(vpn->rlm);
  }

  {
    rhp_ikev2_mesg* ikemesg;

    for(i = 0;i < RHP_VPN_TX_IKEMESG_Q_NUM;i++){

    	while( 1 ){

	      ikemesg = rhp_ikemesg_q_deq(&(vpn->req_tx_ikemesg_q[i]));
	      if( ikemesg == NULL ){
	        break;
	      }

    		rhp_ikev2_unhold_mesg(ikemesg);
	    }
    }
  }

  if( vpn->ikesa_list_head ){
  	RHP_BUG(" vpn->ikesa_list_head not released! : 0x%x ",vpn->ikesa_list_head);
  }

  if( vpn->childsa_list_head ){
  	RHP_BUG(" vpn->childsa_list_head not released! : 0x%x ",vpn->childsa_list_head);
  }


  rhp_eap_id_clear(&(vpn->eap.peer_id));
  rhp_eap_id_clear(&(vpn->eap.my_id));

  if( vpn->peer_fqdn ){
  	_rhp_free(vpn->peer_fqdn);
  }

  if( vpn->rx_peer_cert ){
  	_rhp_free(vpn->rx_peer_cert);
  }

  if( vpn->rx_peer_cert_url ){
  	_rhp_free(vpn->rx_peer_cert_url);
  }

  if( vpn->rx_peer_cert_hash ){
  	_rhp_free(vpn->rx_peer_cert_hash);
  }

  if( vpn->rx_untrust_ca_certs ){
  	_rhp_free(vpn->rx_untrust_ca_certs);
  }

  {
		rhp_vpn_mobike_cookie2 *tx_cookie2 = NULL;

		if( vpn->origin_side == RHP_IKE_INITIATOR ){

			{
				rhp_ip_addr_list* aaddr = vpn->mobike.init.additional_addrs;

				while( aaddr ){
					rhp_ip_addr_list* aaddr_n = aaddr->next;
					_rhp_free(aaddr);
					aaddr = aaddr_n;
				}
			}

			if( vpn->mobike.init.tx_probe_pkt_ref ){
				rhp_pkt_unhold(vpn->mobike.init.tx_probe_pkt_ref);
			}

			rhp_ikev2_mobike_free_path_maps(vpn);

			if( vpn->mobike.init.cand_path_maps_result ){
				_rhp_free(vpn->mobike.init.cand_path_maps_result);
			}

			tx_cookie2 = vpn->mobike.init.rt_ck_cookie2_head;

		}else{

			// Responder

			tx_cookie2 = vpn->mobike.resp.rt_ck_cookie2_head;
		}

		while( tx_cookie2 ){

			rhp_vpn_mobike_cookie2* tx_cookie2_n = tx_cookie2->next;

			rhp_ikev2_mobike_free_tx_cookie2(tx_cookie2);

			tx_cookie2 = tx_cookie2_n;
		}
  }

  if( vpn->internal_net_info.peer_addrs ){

  	rhp_ip_addr_list_free(vpn->internal_net_info.peer_addrs);
  }

  if( vpn->sess_resume.material ){
  	rhp_vpn_sess_resume_clear(vpn->sess_resume.material);
  }

  if( vpn->radius.rx_accept_attrs ){
  	_rhp_radius_access_accept_attrs_free(vpn->radius.rx_accept_attrs);
  }


  {
  	rhp_nhrp_addr_map* nhc_addr_map = vpn->nhrp.nhc_addr_maps_head;
  	while( nhc_addr_map ){
  		rhp_nhrp_addr_map* nhc_addr_map_n = nhc_addr_map->next;
  		_rhp_free(nhc_addr_map);
  		nhc_addr_map = nhc_addr_map_n;
  	}
  }

  if( vpn->nhrp.nhs_next_hop_addrs ){

  	rhp_ip_addr_list_free(vpn->nhrp.nhs_next_hop_addrs);
  }

	{
		rhp_nhrp_mesg* rx_nhrp_mesg = vpn->nhrp.pend_resolution_req_q.head;
		while( rx_nhrp_mesg ){
			rhp_nhrp_mesg* rx_nhrp_mesg_n = rx_nhrp_mesg->next;
			rhp_nhrp_mesg_unhold(rx_nhrp_mesg);
			rx_nhrp_mesg = rx_nhrp_mesg_n;
		}

		if( vpn->nhrp.key ){
			_rhp_free(vpn->nhrp.key);
		}
	}

	if( vpn->v1.rx_mode_cfg_internal_addrs ){
		_rhp_free(vpn->v1.rx_mode_cfg_internal_addrs);
	}


  rhp_ikev2_id_clear(&(vpn->my_id));
  rhp_ikev2_id_clear(&(vpn->peer_id));

  _rhp_atomic_destroy(&(vpn->refcnt));
  _rhp_atomic_destroy(&(vpn->is_active));
  _rhp_mutex_destroy(&(vpn->lock));

	rhp_ikev2_g_statistics_dec(dc.vpn_num);
	rhp_ikev2_g_statistics_inc(vpn_deleted);

  _rhp_free_zero(vpn,sizeof(rhp_vpn));

	RHP_TRC(0,RHPTRCID_VPN_FREE_RTRN,"x",vpn);
	return;
}

#ifdef RHP_REFCNT_DEBUG
void rhp_vpn_free(rhp_vpn* vpn)
{
	_rhp_vpn_free(vpn);
}
#endif // RHP_REFCNT_DEBUG

#ifndef RHP_REFCNT_DEBUG
void rhp_vpn_hold(rhp_vpn* vpn)
{
  _rhp_atomic_inc(&((vpn)->refcnt));
	RHP_TRC(0,RHPTRCID_VPN_HOLD,"xf",vpn,_rhp_atomic_read(&(vpn->refcnt)));
}
#endif // RHP_REFCNT_DEBUG

#ifndef RHP_REFCNT_DEBUG
rhp_vpn_ref* rhp_vpn_hold_ref(rhp_vpn* vpn)
{
  _rhp_atomic_inc(&((vpn)->refcnt));
	RHP_TRC(0,RHPTRCID_VPN_HOLD,"xf",vpn,_rhp_atomic_read(&(vpn->refcnt)));
	return (rhp_vpn_ref*)vpn;
}
#endif // RHP_REFCNT_DEBUG

#ifndef RHP_REFCNT_DEBUG
void rhp_vpn_unhold(void* vpn_t)
{
	rhp_vpn* vpn = (rhp_vpn*)vpn_t;
	RHP_TRC(0,RHPTRCID_VPN_UNHOLD,"xf",vpn,_rhp_atomic_read(&(vpn->refcnt)));

	if( _rhp_atomic_dec_and_test(&(vpn->refcnt)) ){
    _rhp_vpn_free(vpn);
  }
}
#endif // RHP_REFCNT_DEBUG


void rhp_vpn_ikev2_cfg_split_dns_clear(rhp_vpn_realm* rlm,rhp_vpn* vpn)
{
	rhp_split_dns_domain *domain = rlm->split_dns.domains,*domain_p = NULL;
	int rx_domains = 0, updated = 0;

	RHP_TRC(0,RHPTRCID_VPN_IKEV2_CFG_SPLIT_DNS_CLEAR,"xxdf",rlm,vpn,vpn->internal_net_info.fwd_any_dns_queries,_rhp_atomic_read(&rhp_vpn_fwd_any_dns_queries));

	if( vpn->cfg_peer && !vpn->cfg_peer->is_access_point ){
		RHP_TRC(0,RHPTRCID_VPN_IKEV2_CFG_SPLIT_DNS_CLEAR_RTRN_IS_ACCESS_POINT,"xx",rlm,vpn);
		return;
	}

	while( domain ){

		rhp_split_dns_domain* domain_n = domain->next;

		if( domain->ikev2_cfg ){

			if( domain_p ){
				domain_p->next = domain->next;
			}else{
				rlm->split_dns.domains = domain->next;
			}

			if( domain->name ){
				_rhp_free(domain->name);
			}
			_rhp_free(domain);
			rx_domains++;

		}else{

			domain_p = domain;
		}

		domain = domain_n;
	}

	if( rx_domains ){

		if( !rlm->split_dns.static_internal_server_addr &&
				!rhp_ip_addr_null(&(rlm->split_dns.internal_server_addr)) ){

			updated++;
		}

		if( !rlm->split_dns.static_internal_server_addr_v6 &&
				!rhp_ip_addr_null(&(rlm->split_dns.internal_server_addr_v6)) ){

			updated++;
		}

	}else{

		if( vpn->internal_net_info.fwd_any_dns_queries ){

			vpn->internal_net_info.fwd_any_dns_queries = 0;

			_rhp_atomic_dec(&rhp_vpn_fwd_any_dns_queries);

			updated++;

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_RESP_FWD_ANY_DNS_QUERIES_DISABLED,"Vu",vpn,_rhp_atomic_read(&rhp_vpn_fwd_any_dns_queries));
			RHP_TRC(0,RHPTRCID_VPN_IKEV2_CFG_SPLIT_DNS_CLEAR_FWD_ANY_DNS_QUERIES_DISABLED,"xxf",rlm,vpn,_rhp_atomic_read(&rhp_vpn_fwd_any_dns_queries));
		}
	}

	if( updated && rhp_dns_pxy_dec_and_test_users() ){

		rhp_dns_pxy_main_end(AF_INET);
		rhp_dns_pxy_main_end(AF_INET6);
	}


	// If static config exists, rlm->split_dns.domains is NOT NULL.
	if( !rlm->split_dns.static_internal_server_addr ){
		rlm->split_dns.internal_server_addr.addr_family = AF_UNSPEC;
		memset(rlm->split_dns.internal_server_addr.addr.raw,0,16);
	}

	if( !rlm->split_dns.static_internal_server_addr_v6 ){
		rlm->split_dns.internal_server_addr_v6.addr_family = AF_UNSPEC;
		memset(rlm->split_dns.internal_server_addr_v6.addr.raw,0,16);
	}


	RHP_TRC(0,RHPTRCID_VPN_IKEV2_CFG_SPLIT_DNS_CLEAR_RTRN,"xxd",rlm,vpn,updated);
	return;
}

void rhp_vpn_ikev2_cfg_internal_routes_clear(rhp_vpn_realm* rlm,rhp_vpn* vpn)
{
	rhp_route_map* rtmap = rlm->route_maps;

	RHP_TRC(0,RHPTRCID_VPN_IKEV2_CFG_INTERNAL_ROUTES_CLEAR,"xx",rlm,vpn);

	if( vpn->cfg_peer && !vpn->cfg_peer->is_access_point ){
		RHP_TRC(0,RHPTRCID_VPN_IKEV2_CFG_INTERNAL_ROUTES_CLEAR_RTRN_IS_ACCESS_POINT,"xx",rlm,vpn);
		return;
	}

	while( rtmap ){

		rhp_route_map* rtmap_n = rtmap->next;

		if( rtmap->ikev2_cfg ){
			rlm->rtmap_delete(rlm,rtmap);
		}

		rtmap = rtmap_n;
	}

	memset(&(rlm->ext_internal_gateway_addr),0,sizeof(rhp_ip_addr));
	memset(&(rlm->ext_internal_gateway_addr_v6),0,sizeof(rhp_ip_addr));

	RHP_TRC(0,RHPTRCID_VPN_IKEV2_CFG_INTERNAL_ROUTES_CLEAR_RTRN,"xx",rlm,vpn);
	return;
}

void rhp_vpn_ikev2_cfg_cleanup(rhp_vpn* vpn)
{
	int err = -EINVAL;
	rhp_vpn_realm* rlm = vpn->rlm;
	rhp_if_entry* if_info = NULL;
	int n = 0, i;

	RHP_TRC(0,RHPTRCID_VPN_IKEV2_CFG_CLEANUP,"xx",rlm,vpn);

	if( rlm == NULL ){
		RHP_BUG("");
		return;
	}

	if( vpn->cfg_peer && !vpn->cfg_peer->is_access_point ){
		RHP_TRC(0,RHPTRCID_VPN_IKEV2_CFG_CLEANUP_RTRN_IS_ACCESS_POINT,"xx",rlm,vpn);
		return;
	}

	RHP_LOCK(&(rlm->lock));

	rhp_vpn_ikev2_cfg_internal_routes_clear(rlm,vpn);

	rhp_vpn_ikev2_cfg_split_dns_clear(rlm,vpn);

	if( (rlm->config_service == RHP_IKEV2_CONFIG_CLIENT) &&
			(rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_IKEV2CFG ) ){

  	if( rlm->internal_ifc->ifc ){

  	  rhp_ifc_entry* v_ifc = rlm->internal_ifc->ifc;

  		RHP_LOCK(&(v_ifc->lock));
  		{
  			if( v_ifc->ifc_addrs_num ){

					if_info = (rhp_if_entry*)_rhp_malloc(sizeof(rhp_if_entry)*v_ifc->ifc_addrs_num);
					if( if_info == NULL ){

						RHP_BUG("");
						err = -ENOMEM;

					}else{

						rhp_ifc_addr* if_addr = v_ifc->ifc_addrs;

						memset(if_info,0,sizeof(rhp_if_entry)*v_ifc->ifc_addrs_num);

						for( i = 0; i < v_ifc->ifc_addrs_num; i++ ){

							if( !rhp_ip_addr_null(&(if_addr->addr)) &&
									(if_addr->addr.addr_family == AF_INET ||
									 (if_addr->addr.addr_family == AF_INET6 &&
										!rhp_ipv6_is_linklocal(if_addr->addr.addr.v6))) ){

								if_info[n].addr_family = if_addr->addr.addr_family;
								memcpy(if_info[n].addr.raw,if_addr->addr.addr.raw,16);
								if_info[n].prefixlen = if_addr->addr.prefixlen;

								strcpy(if_info[n].if_name,rlm->internal_ifc->if_name);

								n++;
							}

							if_addr = if_addr->lst_next;
						}
					}

  			}else{

  				RHP_TRC(0,RHPTRCID_VPN_IKEV2_CFG_CLEANUP_NO_VIFC_ADDR,"xxx",rlm,vpn,v_ifc);
  			}
  		}
  		RHP_UNLOCK(&(v_ifc->lock));

  		for( i = 0; i < n; i++ ){

				err = rhp_ipc_send_update_vif_raw(rlm->id,rlm->internal_ifc->if_name,
								RHP_IPC_VIF_DELETE_ADDR,&(if_info[i]));
				if( err ){
					RHP_BUG("%d",err);
				}
  		}

  	}else{
  		RHP_BUG("");
  	}
	}

	RHP_UNLOCK(&(rlm->lock));

	if( if_info ){
		_rhp_free(if_info);
	}

	RHP_TRC(0,RHPTRCID_VPN_IKEV2_CFG_CLEANUP_RTRN,"xx",rlm,vpn);
	return;
}

//
// [CAUTION]
// This API internally acqures rlm->lock. So, don't call this API with the lock acquired.
//
void rhp_vpn_destroy(rhp_vpn* vpn)
{
	RHP_TRC(0,RHPTRCID_VPN_DESTROY,"xpux",vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm);

	if( !_rhp_atomic_read(&(vpn->is_active)) ){
		RHP_TRC(0,RHPTRCID_VPN_DESTROY_ALREADY_DESTROYED_ERR,"x",vpn);
    return;
  }

  _rhp_atomic_set(&(vpn->is_active),0);

	rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
	rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));


	if( rhp_timer_pending(&(vpn->vpn_conn_timer)) ){
		vpn->quit_vpn_conn_life_timer(vpn);
	}

	if( rhp_timer_pending(&(vpn->nhrp.nhc_registration_timer)) ){
		vpn->quit_nhc_registration_timer(vpn);
	}

	if( rhp_timer_pending(&(vpn->vpn_conn_idle_timer)) ){
		vpn->quit_vpn_conn_idle_timer(vpn);
	}


	rhp_bridge_cache_cleanup_by_vpn(vpn);

	if( vpn->rlm ){

	  rhp_vpn_internal_route_delete(vpn,NULL); // [CAUTION] NULL means 'rlm' !!!

	  rhp_vpn_internal_address_free(vpn,0); // Address Pool

	  rhp_vpn_ikev2_cfg_cleanup(vpn);


		RHP_LOCK(&(vpn->rlm->lock));
		{

			if( RHP_VPN_REF(vpn->rlm->access_point_peer_vpn_ref) == vpn ){

				rhp_vpn_unhold(vpn->rlm->access_point_peer_vpn_ref);
				vpn->rlm->access_point_peer_vpn_ref = NULL;
			}
		}
		RHP_UNLOCK(&(vpn->rlm->lock));
	}


 	if( vpn->eap.impl_ctx ){

 		if( vpn->eap.role == RHP_EAP_SUPPLICANT ){
 			rhp_eap_sup_impl_vpn_cleanup(vpn,vpn->eap.impl_ctx);
 		}else if( vpn->eap.role == RHP_EAP_AUTHENTICATOR ){
 			rhp_eap_auth_impl_vpn_cleanup(vpn,vpn->eap.impl_ctx);
 		}else{
 			RHP_BUG("%d",vpn->eap.role);
 		}

 		vpn->eap.impl_ctx = NULL;
 	}

  {
    rhp_childsa *childsa = vpn->childsa_list_head,*childsa_n;

    while( childsa ){
      childsa_n = childsa->next_vpn_list;
      rhp_childsa_destroy(vpn,childsa);
      childsa = childsa_n;
    }
  }

  {
    rhp_ikesa *ikesa = vpn->ikesa_list_head,*ikesa_n;

    while( ikesa ){
      ikesa_n = ikesa->next_vpn_list;
      rhp_ikesa_destroy(vpn,ikesa);
      ikesa = ikesa_n;
    }
  }

  if( vpn->origin_side == RHP_IKE_INITIATOR ){

  	if( !rhp_timer_delete(&(vpn->mobike.init.rt_ck_waiting_timer)) ){
			rhp_vpn_unhold(vpn);
  	}
  }

	if( !rhp_timer_delete(&(vpn->ikev2_tx_new_req.task)) ){

		rhp_ikev2_tx_new_req* tx_req = vpn->ikev2_tx_new_req.req_head;
		while( tx_req ){

			rhp_ikev2_tx_new_req *tx_req_n = tx_req->next;

			rhp_ikev2_tx_new_req_free_ctx(tx_req);

	  	tx_req = tx_req_n;
		}

		rhp_vpn_unhold(vpn);
	}

  {
  	rhp_ip_addr_list* peer_addr = vpn->internal_net_info.peer_addrs;
		while( peer_addr ){
			rhp_vpn_delete_by_peer_internal_addr(&(peer_addr->ip_addr),vpn);
			peer_addr = peer_addr->next;
		}
  }


  {
  	rhp_auth_tkt_pending_req* auth_tkt_req = vpn->auth_ticket.hb2spk_pend_req_q_head;

  	while( auth_tkt_req ){

  		rhp_auth_tkt_pending_req* auth_tkt_req_n = auth_tkt_req->next;

  		auth_tkt_req->rx_resp_cb(vpn,auth_tkt_req->hb2spk_my_side,auth_tkt_req->hb2spk_my_spi,
  				-EINVAL,NULL,RHP_VPN_REF(auth_tkt_req->spk2spk_vpn_ref));

			rhp_ikev2_auth_tkt_pending_req_free(auth_tkt_req);

  		auth_tkt_req = auth_tkt_req_n;
  	}

  	if( vpn->auth_ticket.spk2spk_session_key ){
  		_rhp_free_zero(vpn->auth_ticket.spk2spk_session_key,vpn->auth_ticket.spk2spk_session_key_len);
  	}

  	if( vpn->auth_ticket.spk2spk_n_enc_auth_tkt ){
  		_rhp_free_zero(vpn->auth_ticket.spk2spk_n_enc_auth_tkt,vpn->auth_ticket.spk2spk_n_enc_auth_tkt_len);
  	}

  	rhp_ikev2_id_clear(&(vpn->auth_ticket.spk2spk_resp_id));
  }


	rhp_vpn_delete_by_peer_internal_mac(vpn->internal_net_info.exchg_peer_mac,vpn);


	if( vpn->nhrp.role != RHP_NHRP_SERVICE_NONE ){

		rhp_nhrp_cache_invoke_flush_task(vpn);
	}

	rhp_ip_routing_invoke_flush_task(vpn);


  rhp_vpn_delete(vpn);

  rhp_vpn_unhold(vpn);

	RHP_TRC(0,RHPTRCID_VPN_DESTROY_RTRN,"x",vpn);
	return;
}


int rhp_vpn_ikesa_spi_put(rhp_vpn* vpn,int my_side,u8* my_spi)
{
  u32 hval;
  rhp_vpn_ikesa_spi_entry* spi_ent;

	RHP_TRC(0,RHPTRCID_VPN_IKESA_SPI_PUT,"xLdG",vpn,"IKE_SIDE",my_side,my_spi);

  spi_ent = (rhp_vpn_ikesa_spi_entry*)_rhp_malloc(sizeof(rhp_vpn_ikesa_spi_entry));
  if( spi_ent == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  memset(spi_ent,0,sizeof(rhp_vpn_ikesa_spi_entry));

  spi_ent->tag[0] = '#';
  spi_ent->tag[1] = 'I';
  spi_ent->tag[2] = 'S';
  spi_ent->tag[3] = 'E';

  spi_ent->my_side = my_side;
  memcpy(spi_ent->my_spi,my_spi,RHP_PROTO_IKE_SPI_SIZE);

  RHP_LOCK(&rhp_vpn_lock);

  spi_ent->vpn = vpn;
  rhp_vpn_hold(vpn); // rhp_vpn_hold_ref NOT used here.

  hval = _rhp_hash_u32s(my_spi,RHP_PROTO_IKE_SPI_SIZE,_rhp_ikesa_hashtbl_rnd);
  hval = hval % RHP_VPN_HASH_TABLE_SIZE;

  spi_ent->next_hash = _rhp_ikesa_hashtbl[my_side][hval];
  _rhp_ikesa_hashtbl[my_side][hval] = spi_ent;

  {
	  spi_ent->next_lst = rhp_vpn_ikesa_spi_list_head.next_lst;
	  if( rhp_vpn_ikesa_spi_list_head.next_lst ){
	  	rhp_vpn_ikesa_spi_list_head.next_lst->pre_lst = spi_ent;
	  }
	  spi_ent->pre_lst = &rhp_vpn_ikesa_spi_list_head;
	  rhp_vpn_ikesa_spi_list_head.next_lst = spi_ent;
  }

  _rhp_vpn_put_by_unique_id(vpn);

  RHP_UNLOCK(&rhp_vpn_lock);

	RHP_TRC(0,RHPTRCID_VPN_IKESA_SPI_PUT_RTRN,"xx",vpn,spi_ent);
	return 0;
}

int rhp_vpn_ikesa_spi_delete(rhp_vpn* vpn,int my_side,u8* my_spi)
{
  int err = -ENOENT;
  u32 hval;
  rhp_vpn_ikesa_spi_entry *spi_ent,*spi_ent_p = NULL;

	RHP_TRC(0,RHPTRCID_VPN_IKESA_SPI_DELETE,"xLdG",vpn,"IKE_SIDE",my_side,my_spi);

  RHP_LOCK(&rhp_vpn_lock);

  hval = _rhp_hash_u32s(my_spi,RHP_PROTO_IKE_SPI_SIZE,_rhp_ikesa_hashtbl_rnd);
  hval = hval % RHP_VPN_HASH_TABLE_SIZE;

  spi_ent = _rhp_ikesa_hashtbl[my_side][hval];

  while( spi_ent ){

    if( spi_ent->my_side == my_side &&
    	 !memcmp(spi_ent->my_spi,my_spi,RHP_PROTO_IKE_SPI_SIZE) &&
    	 spi_ent->vpn == vpn ){
     break;
    }

    spi_ent_p = spi_ent;
    spi_ent = spi_ent->next_hash;
  }

  if( spi_ent == NULL ){
  	RHP_TRC(0,RHPTRCID_VPN_IKESA_SPI_PUT_NO_ENTRY,"x",vpn);
  	goto error;
  }

  if( spi_ent_p ){
    spi_ent_p->next_hash = spi_ent->next_hash;
  }else{
    _rhp_ikesa_hashtbl[my_side][hval] = spi_ent->next_hash;
  }

  {
  	spi_ent->pre_lst->next_lst = spi_ent->next_lst;
	  if( spi_ent->next_lst ){
	    spi_ent->next_lst->pre_lst = spi_ent->pre_lst;
	  }
	  spi_ent->pre_lst = NULL;
	  spi_ent->next_lst = NULL;
  }

  {
  	rhp_vpn* c_vpn;
  	void* c_vpn_ref
  		= rhp_vpn_get_unlocked(spi_ent->vpn->vpn_realm_id,&(spi_ent->vpn->peer_id),&(spi_ent->vpn->eap.peer_id),0);

  	c_vpn = RHP_VPN_REF(c_vpn_ref);

  	if( c_vpn == NULL ){

  		_rhp_vpn_delete_by_unique_id(spi_ent->vpn);

  	}else{

  		rhp_vpn_unhold(c_vpn_ref);
  	}
  }

  rhp_vpn_unhold(spi_ent->vpn);
  _rhp_free(spi_ent);

  RHP_UNLOCK(&rhp_vpn_lock);

	RHP_TRC(0,RHPTRCID_VPN_IKESA_SPI_DELETE_RTRN,"x",vpn,spi_ent);
  return 0;

error:
  RHP_UNLOCK(&rhp_vpn_lock);

  RHP_TRC(0,RHPTRCID_VPN_IKESA_SPI_DELETE_ERR,"xE",vpn,err);
  return err;
}

rhp_vpn_ref* rhp_vpn_ikesa_spi_get(int my_side,u8* my_spi)
{
  u32 hval;
  rhp_vpn_ikesa_spi_entry *spi_ent = NULL;
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;

  RHP_TRC(0,RHPTRCID_VPN_IKESA_SPI_GET,"LdG","IKE_SIDE",my_side,my_spi);

  RHP_LOCK(&rhp_vpn_lock);

  hval = _rhp_hash_u32s(my_spi,RHP_PROTO_IKE_SPI_SIZE,_rhp_ikesa_hashtbl_rnd);
  hval = hval % RHP_VPN_HASH_TABLE_SIZE;

  spi_ent = _rhp_ikesa_hashtbl[my_side][hval];

  while( spi_ent ){

    if( spi_ent->my_side == my_side &&
    	 !memcmp(spi_ent->my_spi,my_spi,RHP_PROTO_IKE_SPI_SIZE) ){
    	break;
    }

    spi_ent = spi_ent->next_hash;
  }

  if( spi_ent ){

  	vpn = spi_ent->vpn;
  	vpn_ref = rhp_vpn_hold_ref(spi_ent->vpn);

  }else{
    RHP_TRC(0,RHPTRCID_VPN_IKESA_SPI_GET_NO_ENTRY,"x",vpn);
  }

  RHP_UNLOCK(&rhp_vpn_lock);

  RHP_TRC(0,RHPTRCID_VPN_IKESA_SPI_GET_RTRN,"xxx",vpn,spi_ent,vpn_ref);

  return vpn_ref;
}

rhp_vpn_ref* rhp_vpn_ikesa_spi_get_by_peer_id(unsigned long rlm_id,rhp_ikev2_id* peer_id,int no_alt_id)
{
  rhp_vpn_ikesa_spi_entry *spi_ent = NULL;
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;

  RHP_TRC(0,RHPTRCID_VPN_IKESA_SPI_GET_BY_PEER_ID,"ux",rlm_id,peer_id);

  RHP_LOCK(&rhp_vpn_lock);

  spi_ent = rhp_vpn_ikesa_spi_list_head.next_lst;
	while( spi_ent ){

		if( (spi_ent->vpn->vpn_realm_id == rlm_id) &&
	    	( (!no_alt_id && !rhp_ikev2_id_cmp(peer_id,&(spi_ent->vpn->peer_id))) ||
	    		(no_alt_id && !rhp_ikev2_id_cmp_no_alt_id(peer_id,&(spi_ent->vpn->peer_id)))) ){

    	break;
		}

		spi_ent = spi_ent->next_lst;
	}

  if( spi_ent ){

  	vpn = spi_ent->vpn;
  	vpn_ref = rhp_vpn_hold_ref(spi_ent->vpn);

  }else{

  	RHP_TRC(0,RHPTRCID_VPN_IKESA_SPI_GET_BY_PEER_ID_NO_ENTRY,"ux",rlm_id,peer_id);
  }

  RHP_UNLOCK(&rhp_vpn_lock);

  RHP_TRC(0,RHPTRCID_VPN_IKESA_SPI_GET_BY_PEER_ID_RTRN,"uxxxx",rlm_id,peer_id,vpn,spi_ent,vpn_ref);
  return vpn_ref;
}

static u32 _rhp_vpn_ikesa_v1_spi_hash(u8* my_spi,u8* peer_spi)
{
	u32 hval;

	hval = _rhp_hash_bytes_2((const void*)my_spi,RHP_PROTO_IKE_SPI_SIZE,
						(const void*)peer_spi,RHP_PROTO_IKE_SPI_SIZE,_rhp_ikesa_v1_hashtbl_rnd);

	return (hval % RHP_VPN_HASH_TABLE_SIZE);
}

int rhp_vpn_ikesa_v1_spi_put(rhp_ip_addr* my_addr,rhp_ip_addr* peer_addr,
		int my_side,u8* my_spi,u8* peer_spi)
{
  u32 hval;
  rhp_vpn_ikesa_v1_spi_entry* spi_ent;

	RHP_TRC(0,RHPTRCID_VPN_IKESA_V1_SPI_PUT,"xLdGG",my_addr,"IKE_SIDE",my_side,my_spi,peer_spi);
	rhp_ip_addr_dump("my_addr",my_addr);
	rhp_ip_addr_dump("peer_addr",peer_addr);

  spi_ent = (rhp_vpn_ikesa_v1_spi_entry*)_rhp_malloc(sizeof(rhp_vpn_ikesa_v1_spi_entry));
  if( spi_ent == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  memset(spi_ent,0,sizeof(rhp_vpn_ikesa_v1_spi_entry));

  spi_ent->tag[0] = '#';
  spi_ent->tag[1] = 'I';
  spi_ent->tag[2] = 'S';
  spi_ent->tag[3] = '1';

  memcpy(&(spi_ent->my_addr),my_addr,sizeof(rhp_ip_addr));
  memcpy(&(spi_ent->peer_addr),peer_addr,sizeof(rhp_ip_addr));

  spi_ent->my_side = my_side;
  memcpy(spi_ent->my_spi,my_spi,RHP_PROTO_IKE_SPI_SIZE);
  memcpy(spi_ent->peer_spi,peer_spi,RHP_PROTO_IKE_SPI_SIZE);


  RHP_LOCK(&rhp_vpn_lock);

  hval = _rhp_vpn_ikesa_v1_spi_hash(my_spi,peer_spi);

  spi_ent->next_hash = _rhp_ikesa_v1_hashtbl[hval];
  _rhp_ikesa_v1_hashtbl[hval] = spi_ent;

  {
	  spi_ent->next_lst = rhp_vpn_ikesa_v1_spi_list_head.next_lst;
	  if( rhp_vpn_ikesa_v1_spi_list_head.next_lst ){
	  	rhp_vpn_ikesa_v1_spi_list_head.next_lst->pre_lst = spi_ent;
	  }
	  spi_ent->pre_lst = &rhp_vpn_ikesa_v1_spi_list_head;
	  rhp_vpn_ikesa_v1_spi_list_head.next_lst = spi_ent;
  }

  RHP_UNLOCK(&rhp_vpn_lock);

	RHP_TRC(0,RHPTRCID_VPN_IKESA_V1_SPI_PUT_RTRN,"xx",my_addr,spi_ent);
	return 0;
}

int rhp_vpn_ikesa_v1_spi_delete(rhp_ip_addr* my_addr,rhp_ip_addr* peer_addr,
		int my_side,u8* my_spi,u8* peer_spi)
{
  int err = -ENOENT;
  u32 hval;
  rhp_vpn_ikesa_v1_spi_entry *spi_ent,*spi_ent_p = NULL;

	RHP_TRC(0,RHPTRCID_VPN_IKESA_V1_SPI_DELETE,"xLdGG",my_addr,"IKE_SIDE",my_side,my_spi,peer_spi);
	rhp_ip_addr_dump("my_addr",my_addr);
	rhp_ip_addr_dump("peer_addr",peer_addr);

  RHP_LOCK(&rhp_vpn_lock);

  hval = _rhp_vpn_ikesa_v1_spi_hash(my_spi,peer_spi);

  spi_ent = _rhp_ikesa_v1_hashtbl[hval];

  while( spi_ent ){

    if( spi_ent->my_side == my_side &&
    	 !memcmp(spi_ent->my_spi,my_spi,RHP_PROTO_IKE_SPI_SIZE) &&
    	 !memcmp(spi_ent->peer_spi,peer_spi,RHP_PROTO_IKE_SPI_SIZE) &&
    	 !rhp_ip_addr_cmp_ip_only(&(spi_ent->my_addr),my_addr) &&
    	 !rhp_ip_addr_cmp_ip_only(&(spi_ent->peer_addr),peer_addr) ){

     break;
    }

    spi_ent_p = spi_ent;
    spi_ent = spi_ent->next_hash;
  }

  if( spi_ent == NULL ){
  	RHP_TRC(0,RHPTRCID_VPN_IKESA_V1_SPI_PUT_NO_ENTRY,"x",my_addr);
  	goto error;
  }

  if( spi_ent_p ){
    spi_ent_p->next_hash = spi_ent->next_hash;
  }else{
    _rhp_ikesa_v1_hashtbl[hval] = spi_ent->next_hash;
  }

  {
  	spi_ent->pre_lst->next_lst = spi_ent->next_lst;
	  if( spi_ent->next_lst ){
	    spi_ent->next_lst->pre_lst = spi_ent->pre_lst;
	  }
	  spi_ent->pre_lst = NULL;
	  spi_ent->next_lst = NULL;
  }

  _rhp_free(spi_ent);

  RHP_UNLOCK(&rhp_vpn_lock);

	RHP_TRC(0,RHPTRCID_VPN_IKESA_V1_SPI_DELETE_RTRN,"x",my_addr,spi_ent);
  return 0;

error:
  RHP_UNLOCK(&rhp_vpn_lock);

  RHP_TRC(0,RHPTRCID_VPN_IKESA_V1_SPI_DELETE_ERR,"xE",my_addr,err);
  return err;
}

int rhp_vpn_ikesa_v1_spi_get(rhp_ip_addr* my_addr,rhp_ip_addr* peer_addr,
		u8* my_spi,u8* peer_spi,int* my_side_r)
{
	int err = -EINVAL;
  u32 hval;
  rhp_vpn_ikesa_v1_spi_entry *spi_ent = NULL;

  RHP_TRC(0,RHPTRCID_VPN_IKESA_V1_SPI_GET,"xGG",my_addr,my_spi,peer_spi);
	rhp_ip_addr_dump("my_addr",my_addr);
	rhp_ip_addr_dump("peer_addr",peer_addr);

  RHP_LOCK(&rhp_vpn_lock);

  hval = _rhp_vpn_ikesa_v1_spi_hash(my_spi,peer_spi);

  spi_ent = _rhp_ikesa_v1_hashtbl[hval];

  while( spi_ent ){

    if( !memcmp(spi_ent->my_spi,my_spi,RHP_PROTO_IKE_SPI_SIZE) &&
    	  !memcmp(spi_ent->peer_spi,peer_spi,RHP_PROTO_IKE_SPI_SIZE) &&
    	  !rhp_ip_addr_cmp_ip_only(&(spi_ent->my_addr),my_addr) &&
    	  !rhp_ip_addr_cmp_ip_only(&(spi_ent->peer_addr),peer_addr) ){

    	break;
    }

    spi_ent = spi_ent->next_hash;
  }

  if( spi_ent == NULL ){
    RHP_TRC(0,RHPTRCID_VPN_IKESA_V1_SPI_GET_NO_ENTRY,"x",my_addr);
    err = -ENOENT;
  }else{
  	*my_side_r = spi_ent->my_side;
  	err = 0;
  }

  RHP_UNLOCK(&rhp_vpn_lock);

  RHP_TRC(0,RHPTRCID_VPN_IKESA_V1_SPI_GET_RTRN,"xxLd",my_addr,spi_ent,"IKE_SIDE",*my_side_r);

  return err;
}

static void _rhp_vpn_ikesa_put(rhp_vpn* vpn,rhp_ikesa* ikesa)
{
  vpn->ikesa_num++;
  ikesa->next_vpn_list = vpn->ikesa_list_head;
  vpn->ikesa_list_head = ikesa;

  RHP_TRC(0,RHPTRCID_VPN_IKESA_PUT,"xxLdGGLdd",vpn,ikesa,"IKE_SIDE",ikesa->side,ikesa->init_spi,ikesa->resp_spi,"IKESA_STAT",ikesa->state,vpn->ikesa_num);
  return;
}

static rhp_ikesa* _rhp_vpn_ikesa_delete(rhp_vpn* vpn,int my_side,u8* my_spi)
{
  rhp_ikesa *ikesa = NULL,*ikesa_p = NULL;

  RHP_TRC(0,RHPTRCID_VPN_IKESA_DELETE,"xLdG",vpn,"IKE_SIDE",my_side,my_spi);

  ikesa = vpn->ikesa_list_head;
  while( ikesa ){

  	u8* cmp_spi;

  	if( my_side == RHP_IKE_INITIATOR ){
  		cmp_spi = ikesa->init_spi;
  	}else{
  		cmp_spi = ikesa->resp_spi;
  	}

  	if( my_side == ikesa->side &&
  			!memcmp(cmp_spi,my_spi,RHP_PROTO_IKE_SPI_SIZE) ){
  		break;
    }

  	ikesa_p = ikesa;
  	ikesa = ikesa->next_vpn_list;
  }

  if( ikesa == NULL ){
    RHP_TRC(0,RHPTRCID_VPN_IKESA_DELETE_NO_ENTRY,"x",vpn);
    return NULL;
  }

  if( ikesa_p ){
    ikesa_p->next_vpn_list = ikesa->next_vpn_list;
  }else{
    vpn->ikesa_list_head = ikesa->next_vpn_list;
  }
  vpn->ikesa_num--;

  if( ikesa ){
  	RHP_TRC(0,RHPTRCID_VPN_IKESA_DELETE_RTRN,"xxdLdGGLd",vpn,ikesa,vpn->ikesa_num,"IKE_SIDE",ikesa->side,ikesa->init_spi,ikesa->resp_spi,"IKESA_STAT",ikesa->state);
  }else{
  	RHP_TRC(0,RHPTRCID_VPN_IKESA_DELETE_ERR,"x",vpn);
  }
  return ikesa;
}

static rhp_ikesa* _rhp_vpn_ikesa_get(rhp_vpn* vpn,int my_side,u8* spi)
{
  rhp_ikesa *ikesa = NULL;

  RHP_TRC(0,RHPTRCID_VPN_IKESA_GET,"xLdG",vpn,"IKE_SIDE",my_side,spi);

  if( spi == NULL ){
  	RHP_BUG("");
  	return NULL;
  }

  ikesa = vpn->ikesa_list_head;
  while( ikesa ){

  	u8* cmp_spi;

  	if( my_side == RHP_IKE_INITIATOR ){
  		cmp_spi = ikesa->init_spi;
  	}else{
  		cmp_spi = ikesa->resp_spi;
  	}

  	if( my_side == ikesa->side && !memcmp(cmp_spi,spi,RHP_PROTO_IKE_SPI_SIZE) ){
  		break;
    }

  	ikesa = ikesa->next_vpn_list;
  }

  if( ikesa ){
  	RHP_TRC(0,RHPTRCID_VPN_IKESA_GET_RTRN,"xxLdGGLd",vpn,ikesa,"IKE_SIDE",ikesa->side,ikesa->init_spi,ikesa->resp_spi,"IKESA_STAT",ikesa->state);
  }else{
    RHP_TRC(0,RHPTRCID_VPN_IKESA_GET_NO_ENTRY,"x",vpn);
  }

  return ikesa;
}

static rhp_childsa* _rhp_vpn_childsa_get(rhp_vpn* vpn,int direction,u32 spi)
{
  rhp_childsa *childsa = NULL;

  RHP_TRC(0,RHPTRCID_VPN_CHILDSA_GET,"xLdH",vpn,"IPSEC_DIR",direction,spi);

  childsa = vpn->childsa_list_head;
  while( childsa ){

	 u32 cmp_spi;

	 if( direction == RHP_DIR_INBOUND ){
       cmp_spi = childsa->spi_inb;
	 }else{
       cmp_spi = childsa->spi_outb;
	 }

    if( cmp_spi == spi ){
   	  break;
    }

    childsa = childsa->next_vpn_list;
  }

  if( childsa ){
    RHP_TRC(0,RHPTRCID_VPN_CHILDSA_GET_RTRN,"xxLdHHLd",vpn,childsa,"IKE_SIDE",childsa->side,childsa->spi_inb,childsa->spi_outb,"CHILDSA_STAT",childsa->state);
  }else{
    RHP_TRC(0,RHPTRCID_VPN_CHILDSA_GET_NO_ENTRY,"x",vpn);
  }

  return childsa;
}

static void _rhp_vpn_childsa_put(rhp_vpn* vpn,rhp_childsa* childsa)
{
  rhp_childsa *childsa_p = NULL;

  RHP_TRC(0,RHPTRCID_VPN_CHILDSA_PUT,"xxLdHHLd",vpn,childsa,"IKE_SIDE",childsa->side,childsa->spi_inb,childsa->spi_outb,"CHILDSA_STAT",childsa->state);

  childsa_p = vpn->childsa_list_head;
  while( childsa_p ){

    if( childsa == childsa_p ){
   	  return;
    }

    childsa_p = childsa_p->next_vpn_list;
  }

  vpn->childsa_num++;
  childsa->next_vpn_list = vpn->childsa_list_head;
  vpn->childsa_list_head = childsa;

  RHP_TRC(0,RHPTRCID_VPN_CHILDSA_PUT_RTRN,"xxd",vpn,childsa,vpn->childsa_num);
  return;
}

static rhp_childsa* _rhp_vpn_childsa_delete(rhp_vpn* vpn,int direction,u32 spi)
{
  rhp_childsa *childsa = NULL,*childsa_p = NULL;

  RHP_TRC(0,RHPTRCID_VPN_CHILDSA_DELETE,"xLdH",vpn,"IPSEC_DIR",direction,spi);

  childsa = vpn->childsa_list_head;
  while( childsa ){

	 u32 cmp_spi;

	 if( direction == RHP_DIR_INBOUND ){
       cmp_spi = childsa->spi_inb;
	 }else{
       cmp_spi = childsa->spi_outb;
	 }

    if( cmp_spi == spi ){
   	  break;
    }

    childsa_p = childsa;
    childsa = childsa->next_vpn_list;
  }

  if( childsa == NULL ){
    RHP_TRC(0,RHPTRCID_VPN_CHILDSA_DELETE_NO_ENTRY,"x",vpn);
    return NULL;
  }

  if( childsa_p ){
    childsa_p->next_vpn_list = childsa->next_vpn_list;
  }else{
    vpn->childsa_list_head = childsa->next_vpn_list;
  }
  vpn->childsa_num--;

  RHP_TRC(0,RHPTRCID_VPN_CHILDSA_DELETE_RTRN,"xxLdHHd",vpn,childsa,"IKE_SIDE",childsa->side,childsa->spi_inb,childsa->spi_outb,vpn->childsa_num);
  return childsa;
}

static void _rhp_vpn_ikesa_move_to_top(rhp_vpn* vpn,rhp_ikesa* ikesa)
{
  if( vpn->ikesa_list_head != ikesa ){

    u8* my_spi;
    my_spi = ikesa->get_my_spi(ikesa);

	 if( vpn->ikesa_delete(vpn,ikesa->side,my_spi) ){

		 vpn->ikesa_put(vpn,ikesa); // Moves to the top of list.
	 }

	  RHP_TRC(0,RHPTRCID_VPN_IKESA_MOVE_TO_TOP,"xx",vpn,ikesa);

  }else{
	  RHP_TRC(0,RHPTRCID_VPN_IKESA_MOVE_TO_TOP_DO_NOTHING,"xx",vpn,ikesa);
  }
}

static void _rhp_vpn_childsa_move_to_top(rhp_vpn* vpn,rhp_childsa* childsa)
{
  if( 	vpn->childsa_list_head != childsa ){

    if( vpn->childsa_delete(vpn,RHP_DIR_INBOUND,childsa->spi_inb) ){
      vpn->childsa_put(vpn,childsa); // Moves to the top of list.
    }

    RHP_TRC(0,RHPTRCID_VPN_CHILDSA_MOVE_TO_TOP,"xx",vpn,childsa);

  }else{
	  RHP_TRC(0,RHPTRCID_VPN_CHILDSA_MOVE_TO_TOP_DO_NOTHING,"xx",vpn,childsa);
  }
}

static int _rhp_vpn_childsa_established(rhp_vpn* vpn)
{
	rhp_childsa* cur_childsa = vpn->childsa_list_head;

	while( cur_childsa ){

		if( cur_childsa->state == RHP_CHILDSA_STAT_MATURE 		|| // IKEv2
  			cur_childsa->state == RHP_CHILDSA_STAT_REKEYING 	|| // IKEv2
  			cur_childsa->state == RHP_IPSECSA_STAT_V1_MATURE 	||
  			cur_childsa->state == RHP_IPSECSA_STAT_V1_REKEYING){

			RHP_TRC(0,RHPTRCID_VPN_CHILDSA_ESTABLISHED_OK,"xxx",vpn,vpn->childsa_list_head,cur_childsa);
  		return 1;
		}
		cur_childsa = cur_childsa->next_vpn_list;
	}

  RHP_TRC(0,RHPTRCID_VPN_CHILDSA_ESTABLISHED_NG,"xxx",vpn,vpn->childsa_list_head,cur_childsa);
	return 0;
}

static rhp_childsa* _rhp_vpn_v1_ipsecsa_get_by_mesg_id(rhp_vpn* vpn,rhp_ikesa* ikesa,u32 mesg_id)
{
	rhp_childsa* childsa = vpn->childsa_list_head;

  RHP_TRC(0,RHPTRCID_VPN_V1_IPSECSA_GET_BY_MESG_ID,"xxk",vpn,ikesa,mesg_id);

	while( childsa ){

	  RHP_TRC(0,RHPTRCID_VPN_V1_IPSECSA_GET_BY_MESG_ID_IPSECSA,"xxxLdGGGGddkk",vpn,ikesa,childsa,"CHILDSA_STAT",childsa->state,childsa->parent_ikesa.init_spi,ikesa->init_spi,childsa->parent_ikesa.resp_spi,ikesa->resp_spi,childsa->parent_ikesa.side,ikesa->side,mesg_id,childsa->gen_message_id);

		if( childsa->parent_ikesa.side == ikesa->side &&
				!memcmp(childsa->parent_ikesa.init_spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE) &&
				!memcmp(childsa->parent_ikesa.resp_spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE) ){

			if( childsa->gen_message_id == mesg_id ){

				break;
			}
		}

		childsa = childsa->next_vpn_list;
	}

  RHP_TRC(0,RHPTRCID_VPN_V1_IPSECSA_GET_BY_MESG_ID_RTRN,"xxKx",vpn,ikesa,mesg_id,childsa);
	return childsa;
}


static int _rhp_vpn_check_cfg_address(rhp_vpn* vpn,rhp_vpn_realm* rlm,
		rhp_packet* ike_pkt)
{
  int err = 0;
  rhp_cfg_if* cfg_if = NULL;
  int addr_family;
  u8* addr;

  RHP_TRC(0,RHPTRCID_VPN_CHECK_CFG_ADDRESS,"xxxdLdxsd",vpn,rlm,rlm->id,ike_pkt,"PKT",ike_pkt->type,ike_pkt->rx_ifc,ike_pkt->rx_ifc->if_name,rhp_gcfg_ikev2_rx_if_strictly_check);

  if( !rhp_gcfg_ikev2_rx_if_strictly_check ){
  	goto ignore;
  }

  if( ike_pkt->type == RHP_PKT_IPV4_IKE ){

  	addr_family = AF_INET;
  	addr = (u8*)&(ike_pkt->l3.iph_v4->dst_addr);
    RHP_TRC(0,RHPTRCID_VPN_CHECK_CFG_ADDRESS_PKT_V4,"x4",ike_pkt,ike_pkt->l3.iph_v4->dst_addr);

  }else if( ike_pkt->type == RHP_PKT_IPV6_IKE ){

  	addr_family = AF_INET6;
  	addr = ike_pkt->l3.iph_v6->dst_addr;
    RHP_TRC(0,RHPTRCID_VPN_CHECK_CFG_ADDRESS_PKT_V6,"x6",ike_pkt,ike_pkt->l3.iph_v6->dst_addr);

  }else{
  	RHP_BUG("%d",ike_pkt->type);
    err = -EINVAL;
    goto error;
  }


  cfg_if = rlm->my_interfaces;
  while( cfg_if ){

  	if( cfg_if->ifc ){

  		RHP_LOCK(&(cfg_if->ifc->lock));

  		if( !_rhp_atomic_read(&(cfg_if->ifc->is_active)) ){
    		RHP_UNLOCK(&(cfg_if->ifc->lock));
  			goto next;
  		}

			if( addr_family == AF_INET ){
				RHP_TRC(0,RHPTRCID_VPN_CHECK_CFG_ADDRESS_CFG,"xxsddLd",cfg_if,cfg_if->ifc,cfg_if->ifc->if_name,cfg_if->ifc->if_index,ike_pkt->rx_if_index,"AF",cfg_if->addr_family);
			}else if( addr_family == AF_INET6 ){
				RHP_TRC(0,RHPTRCID_VPN_CHECK_CFG_ADDRESS_CFG_V6,"xxsddLd",cfg_if,cfg_if->ifc,cfg_if->ifc->if_name,cfg_if->ifc->if_index,ike_pkt->rx_if_index,"AF",cfg_if->addr_family);
			}

			if( (cfg_if->addr_family == AF_UNSPEC || cfg_if->addr_family == addr_family) &&
					(cfg_if->ifc->if_index == ike_pkt->rx_if_index) &&
  				(cfg_if->ifc->get_addr(cfg_if->ifc,addr_family,addr) != NULL) ){

  			RHP_UNLOCK(&(cfg_if->ifc->lock));
  			break;
  		}

  		RHP_UNLOCK(&(cfg_if->ifc->lock));
  	}

next:
    cfg_if = cfg_if->next;
  }

  if( cfg_if == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

ignore:
  RHP_TRC(0,RHPTRCID_VPN_CHECK_CFG_ADDRESS_RTRN,"xxx",vpn,rlm,ike_pkt);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_VPN_CHECK_CFG_ADDRESS_ERR,"xxxE",vpn,rlm,ike_pkt,err);
	return err;
}

static void _rhp_vpn_dump(char* label,rhp_vpn* vpn)
{
	_RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
  if( !_RHP_TRC_COND(_rhp_trc_user_id(),0) ){
    return;
  }

	RHP_TRC(0,RHPTRCID_VPN_DUMP,"sxpuxxdddddLdM",label,vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm,vpn->cfg_peer,vpn->connecting,vpn->ikesa_num,vpn->childsa_num,vpn->peer_is_rockhopper,vpn->peer_rockhopper_ver,"VPN_ENCAP",vpn->internal_net_info.encap_mode_c,vpn->internal_net_info.dummy_peer_mac);
	rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
	rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));

	if( vpn->rlm ){

	  rhp_cfg_peer* cfg_peer = vpn->rlm->peers;

		RHP_TRC(0,RHPTRCID_VPN_DUMP_RLM,"xu",vpn->rlm,vpn->rlm->id);

		while( cfg_peer ){

			RHP_TRC(0,RHPTRCID_VPN_DUMP_RLM_CFG_PEER,"xd",cfg_peer,cfg_peer->is_access_point);
			rhp_ikev2_id_dump("cfg_peer->id",&(cfg_peer->id));
			rhp_ip_addr_dump("cfg_peer->primary_addr",&(cfg_peer->primary_addr));
			rhp_ip_addr_dump("cfg_peer->secondary_addr",&(cfg_peer->secondary_addr));
			rhp_ip_addr_dump("cfg_peer->internal_addr",&(cfg_peer->internal_addr));

			cfg_peer = cfg_peer->next;
		}
	}

	{
		rhp_ip_addr_list* peer_addr = vpn->internal_net_info.peer_addrs;
		while( peer_addr ){
			rhp_ip_addr_dump("vpn->internal_net_info.peer_addr",&(peer_addr->ip_addr));
			peer_addr = peer_addr->next;
		}
	}

	if( vpn->last_my_tss ){

    RHP_TRC(0,RHPTRCID_VPN_DUMP_LAST_MY_TRAFFIC_SELECTOR,"xbbWWbbbb",vpn->last_my_tss,vpn->last_my_tss->ts_or_id_type,vpn->last_my_tss->protocol,vpn->last_my_tss->start_port,vpn->last_my_tss->end_port,vpn->last_my_tss->icmp_start_type,vpn->last_my_tss->icmp_end_type,vpn->last_my_tss->icmp_start_code,vpn->last_my_tss->icmp_end_code);
    rhp_ip_addr_dump("last_my_tss:start_addr",&(vpn->last_my_tss->start_addr));
    rhp_ip_addr_dump("last_my_tss:end_addr",&(vpn->last_my_tss->end_addr));
	}

	if( vpn->last_peer_tss ){

    RHP_TRC(0,RHPTRCID_VPN_DUMP_LAST_PEER_TRAFFIC_SELECTOR,"xbbWWbbbb",vpn->last_peer_tss,vpn->last_peer_tss->ts_or_id_type,vpn->last_peer_tss->protocol,vpn->last_peer_tss->start_port,vpn->last_peer_tss->end_port,vpn->last_peer_tss->icmp_start_type,vpn->last_peer_tss->icmp_end_type,vpn->last_peer_tss->icmp_start_code,vpn->last_peer_tss->icmp_end_code);
    rhp_ip_addr_dump("last_peer_tss:start_addr",&(vpn->last_peer_tss->start_addr));
    rhp_ip_addr_dump("last_peer_tss:end_addr",&(vpn->last_peer_tss->end_addr));
	}

	return;
}

static void _rhp_vpn_set_local_net_info(rhp_vpn* vpn,rhp_ifc_entry* ifc,int addr_family,u8* addr)
{
	rhp_if_entry* if_info = &(vpn->local.if_info);

  vpn->local.port = htons(rhp_gcfg_ike_port);
  vpn->local.port_nat_t = htons(rhp_gcfg_ike_port_nat_t);

	ifc->dump_no_lock("net_info(NEW)",ifc);
 	rhp_if_entry_dump("net_info(OLD)",&(vpn->local.if_info));

 	if( rhp_ifc_copy_to_if_entry(ifc,if_info,addr_family,addr) ){
 		RHP_BUG("");
 	}

  RHP_TRC(0,RHPTRCID_CHILDSA_SET_LOCAL_IFC,"xxWWd46",vpn,ifc,vpn->local.port,vpn->local.port_nat_t,addr_family,*((u32*)addr),addr);
  return;
}

static void _rhp_vpn_set_peer_addr(rhp_vpn* vpn,rhp_ip_addr* addr,rhp_ip_addr* origin_addr)
{
  RHP_TRC(0,RHPTRCID_CHILDSA_SET_PEER_ADDR,"xxx",vpn,addr,origin_addr);
  rhp_ip_addr_dump("addr",addr);

  memcpy(&(vpn->peer_addr),addr,sizeof(rhp_ip_addr));
  if( origin_addr ){
    rhp_ip_addr_dump("origin_addr",origin_addr);
    memcpy(&(vpn->origin_peer_addr),origin_addr,sizeof(rhp_ip_addr));
  }

  return;
}

void rhp_vpn_sess_resume_clear(rhp_vpn_sess_resume_material* material)
{
	RHP_TRC(0,RHPTRCID_VPN_SESS_RESUME_CLEAR,"x",material);

#ifndef RHP_SESS_RESUME_DEBUG_1
	if( material == NULL ){
		return;
	}

	if( material->old_sa_prop_i ){
		_rhp_free(material->old_sa_prop_i);
	}

	if( material->old_sk_d_i ){
		_rhp_free_zero(material->old_sk_d_i,material->old_sk_d_i_len);
	}

	if( material->peer_tkt_r ){
		_rhp_free(material->peer_tkt_r);
	}

	rhp_ikev2_id_clear(&(material->my_id_i));
	rhp_eap_id_clear(&(material->my_eap_id_i));

	_rhp_free(material);
#endif // RHP_SESS_RESUME_DEBUG_1

	RHP_TRC(0,RHPTRCID_VPN_SESS_RESUME_CLEAR_RTRN,"x",material);
	return;
}

static void _rhp_vpn_sess_resume_clear(rhp_vpn* vpn)
{
	RHP_TRC(0,RHPTRCID_VPN_SESS_RESUME_CLEAR_BY_VPN,"xxx",vpn,vpn->ikesa_list_head,vpn->sess_resume.material);

	if( vpn->sess_resume.material ){

		rhp_ikesa* ikesa = vpn->ikesa_list_head;

		while( ikesa ){

			if( ikesa->side == RHP_IKE_INITIATOR &&
					ikesa->sess_resume.init.material == vpn->sess_resume.material ){

				ikesa->sess_resume.init.material = NULL;
			}

			ikesa = ikesa->next_vpn_list;
		}

		rhp_vpn_sess_resume_clear(vpn->sess_resume.material);
		vpn->sess_resume.material = NULL;
	}

	return;
}

#ifdef RHP_SESS_RESUME_DEBUG_1

rhp_vpn_sess_resume_material* rhp_sess_resume_material_i_c = NULL;

static rhp_vpn_sess_resume_material* _rhp_vpn_sess_resume_get_material_i(rhp_vpn* vpn)
{
	return rhp_sess_resume_material_i_c;
}

/*
static void _rhp_vpn_sess_resume_set_material_i(rhp_vpn* vpn,rhp_vpn_sess_resume_material* material_i)
{
	if( material_i == NULL ){
		return;
	}
	if( rhp_sess_resume_material_i_c ){
		rhp_vpn_sess_resume_clear(rhp_sess_resume_material_i_c);
	}
	rhp_sess_resume_material_i_c = material_i;
	return;
}
*/

static void _rhp_vpn_sess_resume_set_material_i(rhp_vpn* vpn,rhp_vpn_sess_resume_material* material_i)
{
	if( material_i == NULL ){
		return;
	}
	if( rhp_sess_resume_material_i_c == NULL ){
		rhp_sess_resume_material_i_c = material_i;
	}
	return;
}

#else // RHP_SESS_RESUME_DEBUG_1

static rhp_vpn_sess_resume_material* _rhp_vpn_sess_resume_get_material_i(rhp_vpn* vpn)
{
  RHP_TRC(0,RHPTRCID_VPN_SESS_RESUME_GET_MATERIAL_I,"xx",vpn,vpn->sess_resume.material);
	return vpn->sess_resume.material;
}

static void _rhp_vpn_sess_resume_set_material_i(rhp_vpn* vpn,rhp_vpn_sess_resume_material* material_i)
{
  RHP_TRC(0,RHPTRCID_VPN_SESS_RESUME_SET_MATERIAL_I,"xxx",vpn,vpn->sess_resume.material,material_i);
	vpn->sess_resume.material = material_i;
	return;
}
#endif // RHP_SESS_RESUME_DEBUG_1

static int _rhp_vpn_conn_start_life_timer(rhp_vpn* vpn)
{
  RHP_TRC(0,RHPTRCID_VPN_CONN_START_LIFE_TIMER,"xLdd",vpn,"IKE_SIDE",vpn->origin_side,vpn->vpn_conn_lifetime);

  if( !vpn->vpn_conn_lifetime ){
		RHP_TRC(0,RHPTRCID_VPN_CONN_START_LIFE_TIMER_DISABLED,"x",vpn);
  	return 0;
  }

	if( rhp_timer_pending(&(vpn->vpn_conn_timer)) ){
		RHP_TRC(0,RHPTRCID_VPN_CONN_START_LIFE_TIMER_REQ_PENDING,"x",vpn);
		return 0;
	}

	vpn->vpn_conn_timer.ctx = (void*)rhp_vpn_hold_ref(vpn);

	rhp_timer_reset(&(vpn->vpn_conn_timer));
	rhp_timer_add(&(vpn->vpn_conn_timer),vpn->vpn_conn_lifetime);

  RHP_TRC(0,RHPTRCID_VPN_CONN_START_LIFE_TIMER_RTRN,"xx",vpn,vpn->vpn_conn_timer.ctx);
  return 0;
}

static int _rhp_vpn_conn_quit_life_timer(rhp_vpn* vpn)
{
  RHP_TRC(0,RHPTRCID_VPN_CONN_QUIT_LIFE_TIMER,"xLd",vpn,"IKE_SIDE",vpn->origin_side);

	if( rhp_timer_delete(&(vpn->vpn_conn_timer)) ){
		RHP_TRC(0,RHPTRCID_VPN_CONN_QUIT_LIFE_TIMER_REQ_NOT_ACTIVE,"x",vpn);
		return -1;
	}

	rhp_vpn_unhold((rhp_vpn_ref*)(vpn->vpn_conn_timer.ctx));
	vpn->vpn_conn_timer.ctx = NULL;

  RHP_TRC(0,RHPTRCID_VPN_CONN_QUIT_LIFE_TIMER_RTRN,"x",vpn);
  return 0;
}

static void _rhp_vpn_conn_life_timer(void *ctx,rhp_timer *timer)
{
  rhp_vpn_ref* vpn_ref = (rhp_vpn_ref*)ctx;
  rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);

  RHP_TRC(0,RHPTRCID_VPN_CONN_LIFE_TIMER,"xxxLd",vpn,vpn_ref,timer,"IKE_SIDE",vpn->origin_side);

  RHP_LOCK(&(vpn->lock));

  RHP_TRC(0,RHPTRCID_VPN_CONN_LIFE_TIMER_VPN,"xpuxdd",vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm,vpn->ikesa_num,vpn->childsa_num);
  rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
  rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));


  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_VPN_CONN_LIFE_TIMER_VPN_NOT_ACTIVE,"xx",vpn,timer);
    goto error;
  }

  rhp_ip_addr_dump("vpn->peer_addr",&(vpn->peer_addr));
  rhp_if_entry_dump("vpn->local.if_info",&(vpn->local.if_info));

	if( vpn->eap.eap_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS &&
			!vpn->radius.acct_term_cause ){
		vpn->radius.acct_term_cause = RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_SESSION_TIMEOUT;
	}

  rhp_vpn_close_impl(vpn);

error:
  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

	RHP_TRC(0,RHPTRCID_VPN_CONN_LIFE_TIMER_RTRN,"xxx",vpn,vpn_ref,timer);
	return;
}

static int _rhp_vpn_nhc_start_registration_timer(rhp_vpn* vpn,time_t next_interval)
{
  RHP_TRC(0,RHPTRCID_VPN_NHC_START_REGISTRATION_TIMER,"xxLdd",vpn,&(vpn->nhrp.nhc_registration_timer),"IKE_SIDE",vpn->origin_side,next_interval);

  if( vpn->nhrp.role != RHP_NHRP_SERVICE_CLIENT ||
  		vpn->nhrp.dmvpn_shortcut ){
		RHP_TRC(0,RHPTRCID_VPN_NHC_START_REGISTRATION_TIMER_DISABLED,"xxbdd",vpn,&(vpn->nhrp.nhc_registration_timer),vpn->nhrp.role,vpn->internal_net_info.encap_mode_c,vpn->nhrp.dmvpn_shortcut);
  	return 0;
  }

  if( vpn->internal_net_info.encap_mode_c != RHP_VPN_ENCAP_GRE ){
		RHP_TRC(0,RHPTRCID_VPN_NHC_START_REGISTRATION_TIMER_NOT_GRE_ENCAP,"xxbd",vpn,&(vpn->nhrp.nhc_registration_timer),vpn->nhrp.role,vpn->internal_net_info.encap_mode_c);
  	return 0;
  }

	if( rhp_timer_pending(&(vpn->nhrp.nhc_registration_timer)) ){
		RHP_TRC(0,RHPTRCID_VPN_NHC_START_REGISTRATION_TIMER_REQ_PENDING,"xx",vpn,&(vpn->nhrp.nhc_registration_timer));
		return 0;
	}

	vpn->nhrp.nhc_registration_timer.ctx = (void*)rhp_vpn_hold_ref(vpn);

	rhp_timer_reset(&(vpn->nhrp.nhc_registration_timer));
	rhp_timer_add(&(vpn->nhrp.nhc_registration_timer),next_interval);

  RHP_TRC(0,RHPTRCID_VPN_NHC_START_REGISTRATION_TIMER_RTRN,"xxx",vpn,&(vpn->nhrp.nhc_registration_timer),vpn->nhrp.nhc_registration_timer.ctx);
  return 0;
}

static int _rhp_vpn_nhc_quit_registration_timer(rhp_vpn* vpn)
{
  RHP_TRC(0,RHPTRCID_VPN_NHC_QUIT_REGISTRATION_TIMER,"xxLd",vpn,&(vpn->nhrp.nhc_registration_timer),"IKE_SIDE",vpn->origin_side);

	if( rhp_timer_delete(&(vpn->nhrp.nhc_registration_timer)) ){
		RHP_TRC(0,RHPTRCID_VPN_NHC_QUIT_REGISTRATION_TIMER_REQ_NOT_ACTIVE,"xx",vpn,&(vpn->nhrp.nhc_registration_timer));
		return -1;
	}

	rhp_vpn_unhold((rhp_vpn_ref*)(vpn->nhrp.nhc_registration_timer.ctx));
	vpn->nhrp.nhc_registration_timer.ctx = NULL;

  RHP_TRC(0,RHPTRCID_VPN_NHC_QUIT_REGISTRATION_TIMER_RTRN,"xx",vpn,&(vpn->nhrp.nhc_registration_timer));
  return 0;
}

static void _rhp_vpn_nhc_registration_timer(void *ctx,rhp_timer *timer)
{
	int err = -EINVAL;
  rhp_vpn_ref* vpn_ref = (rhp_vpn_ref*)ctx;
  rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);
  int nhrp_dmvpn_shortcut = 0;

  RHP_TRC(0,RHPTRCID_VPN_NHC_REGISTRATION_TIMER,"xxxLd",vpn,vpn_ref,timer,"IKE_SIDE",vpn->origin_side);

  RHP_LOCK(&(vpn->lock));

  RHP_TRC(0,RHPTRCID_VPN_NHC_REGISTRATION_TIMER_VPN,"xpuxddd",vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm,vpn->ikesa_num,vpn->childsa_num,vpn->nhrp.dmvpn_shortcut);
  rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
  rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));


  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_VPN_NHC_REGISTRATION_TIMER_VPN_NOT_ACTIVE,"xx",vpn,timer);
    goto error;
  }

  rhp_ip_addr_dump("vpn->peer_addr",&(vpn->peer_addr));
  rhp_if_entry_dump("vpn->local.if_info",&(vpn->local.if_info));


	rhp_timer_reset(&(vpn->nhrp.nhc_registration_timer));
	rhp_timer_add(&(vpn->nhrp.nhc_registration_timer),(time_t)rhp_gcfg_nhrp_cache_update_interval);


	nhrp_dmvpn_shortcut = vpn->nhrp.dmvpn_shortcut;

	RHP_UNLOCK(&(vpn->lock));


	if( !nhrp_dmvpn_shortcut ){

		err = rhp_nhrp_tx_registration_req(vpn);
		if( err ){
			RHP_BUG("%d",err);
		}
	}

	RHP_TRC(0,RHPTRCID_VPN_NHC_REGISTRATION_TIMER_RTRN,"xxxd",vpn,vpn_ref,timer,nhrp_dmvpn_shortcut);
  return;

error:
  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

	RHP_TRC(0,RHPTRCID_VPN_NHC_REGISTRATION_TIMER_ERR,"xxx",vpn,vpn_ref,timer);
	return;
}

static time_t _rhp_vpn_random_interval(int interval_secs,u32 range)
{
  u32 random_secs;
  time_t ret;

  if( rhp_random_bytes((u8*)&random_secs,sizeof(random_secs)) ){
    RHP_BUG("");
    return 0;
  }

  ret = (time_t)(interval_secs + (random_secs % range));

  RHP_TRC(0,RHPTRCID_VPN_RANDOM_INTERVAL,"ddj",interval_secs,ret,range);

  return ret;
}

static int _rhp_vpn_conn_start_idle_timer(rhp_vpn* vpn)
{
  RHP_TRC(0,RHPTRCID_VPN_CONN_START_IDLE_TIMER,"xLdd",vpn,"IKE_SIDE",vpn->origin_side,vpn->vpn_conn_lifetime);

  if( !vpn->vpn_conn_idle_timeout ){
		RHP_TRC(0,RHPTRCID_VPN_CONN_START_IDLE_TIMER_DISABLED,"x",vpn);
  	return 0;
  }

	if( rhp_timer_pending(&(vpn->vpn_conn_idle_timer)) ){
		RHP_TRC(0,RHPTRCID_VPN_CONN_START_IDLE_TIMER_REQ_PENDING,"x",vpn);
		return 0;
	}

	vpn->vpn_conn_idle_timer.ctx = (void*)rhp_vpn_hold_ref(vpn);

	rhp_timer_reset(&(vpn->vpn_conn_idle_timer));
	rhp_timer_add(&(vpn->vpn_conn_idle_timer),
			_rhp_vpn_random_interval(vpn->vpn_conn_idle_timeout,RHP_VPN_CONN_IDLE_TIMEOUT_RANDOM_RANGE));

  RHP_TRC(0,RHPTRCID_VPN_CONN_START_IDLE_TIMER_RTRN,"xx",vpn,vpn->vpn_conn_idle_timer.ctx);
  return 0;
}

static int _rhp_vpn_conn_quit_idle_timer(rhp_vpn* vpn)
{
  RHP_TRC(0,RHPTRCID_VPN_CONN_QUIT_IDLE_TIMER,"xLd",vpn,"IKE_SIDE",vpn->origin_side);

	if( rhp_timer_delete(&(vpn->vpn_conn_idle_timer)) ){
		RHP_TRC(0,RHPTRCID_VPN_CONN_QUIT_IDLE_TIMER_REQ_NOT_ACTIVE,"x",vpn);
		return -1;
	}

	rhp_vpn_unhold((rhp_vpn_ref*)(vpn->vpn_conn_idle_timer.ctx));
	vpn->vpn_conn_idle_timer.ctx = NULL;

  RHP_TRC(0,RHPTRCID_VPN_CONN_QUIT_IDLE_TIMER_RTRN,"x",vpn);
  return 0;
}

static void _rhp_vpn_conn_idle_timer(void *ctx,rhp_timer *timer)
{
  rhp_vpn_ref* vpn_ref = (rhp_vpn_ref*)ctx;
  rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);
  int idle_num = 0;
  rhp_childsa* cur_childsa;

  RHP_TRC(0,RHPTRCID_VPN_CONN_IDLE_TIMER,"xxxLd",vpn,vpn_ref,timer,"IKE_SIDE",vpn->origin_side);

  RHP_LOCK(&(vpn->lock));

  RHP_TRC(0,RHPTRCID_VPN_CONN_IDLE_TIMER_VPN,"xpuxdd",vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm,vpn->ikesa_num,vpn->childsa_num);
  rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
  rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));


  if( !_rhp_atomic_read(&(vpn->is_active)) ){
  	RHP_TRC(0,RHPTRCID_VPN_CONN_IDLE_TIMER_VPN_NOT_ACTIVE,"xx",vpn,timer);
    goto error;
  }

  rhp_ip_addr_dump("vpn->peer_addr",&(vpn->peer_addr));
  rhp_if_entry_dump("vpn->local.if_info",&(vpn->local.if_info));


  cur_childsa = vpn->childsa_list_head;
  while( cur_childsa ){

  	if( cur_childsa->statistics.tx_esp_packets == cur_childsa->last_tx_esp_packets &&
  			cur_childsa->statistics.rx_esp_packets == cur_childsa->last_rx_esp_packets ){

  		idle_num++;
  	}

  	cur_childsa->last_tx_esp_packets = cur_childsa->statistics.tx_esp_packets;
  	cur_childsa->last_rx_esp_packets = cur_childsa->statistics.rx_esp_packets;

  	cur_childsa = cur_childsa->next_vpn_list;
  }

  if( vpn->childsa_num &&
  		(vpn->childsa_num != idle_num) ){

		rhp_timer_reset(&(vpn->vpn_conn_idle_timer));
		rhp_timer_add(&(vpn->vpn_conn_idle_timer),
				_rhp_vpn_random_interval(vpn->vpn_conn_idle_timeout,RHP_VPN_CONN_IDLE_TIMEOUT_RANDOM_RANGE));

  }else{

  	rhp_vpn_close_impl(vpn);

  	goto close_vpn;
  }

	RHP_UNLOCK(&(vpn->lock));

	RHP_TRC(0,RHPTRCID_VPN_CONN_IDLE_TIMER_RTRN,"xxxd",vpn,vpn_ref,timer,idle_num);
  return;

close_vpn:
error:
	RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

	RHP_TRC(0,RHPTRCID_VPN_CONN_IDLE_TIMER_ERR,"xxxd",vpn,vpn_ref,timer,idle_num);
	return;
}

extern void rhp_ikev2_mobike_i_rt_ck_waiting_timer(void* ctx,rhp_timer *timer);
extern void rhp_ikev2_tx_new_req_task(void *ctx,rhp_timer *timer);

rhp_vpn* rhp_vpn_alloc(rhp_ikev2_id* my_id,rhp_ikev2_id* peer_id,
		rhp_vpn_realm* rlm,rhp_ip_addr* peer_ip,int origin_side)
{
  int err = 0;
  rhp_vpn* vpn = NULL;
  u8 local_mac[6];
  int i;

  RHP_TRC(0,RHPTRCID_VPN_ALLOC,"xxxLd",my_id,peer_id,rlm,"IKE_SIDE",origin_side);
	rhp_ikev2_id_dump("my_id",my_id);
	rhp_ikev2_id_dump("peer_id",peer_id);

	if( peer_ip && rhp_ip_addr_null(peer_ip) ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

  err = rhp_vpn_gen_or_add_local_mac(NULL,local_mac);
  if( err ){
  	RHP_BUG("");
  	return NULL;
  }

  vpn = (rhp_vpn*)_rhp_malloc(sizeof(rhp_vpn));
  if( vpn == NULL ){
   RHP_BUG("");
   err = -ENOMEM;
   goto error;
  }

  memset(vpn,0,sizeof(rhp_vpn));

  vpn->tag[0] = '#';
  vpn->tag[1] = 'V';
  vpn->tag[2] = 'P';
  vpn->tag[3] = 'N';

  rhp_vpn_gen_unique_id(vpn->unique_id);
  memcpy(vpn->internal_net_info.dummy_peer_mac,local_mac,6);

  _rhp_atomic_init(&(vpn->refcnt));
  _rhp_atomic_init(&(vpn->is_active));

  _rhp_mutex_init("VPN",&(vpn->lock));

  _rhp_atomic_set(&(vpn->refcnt),0);

  vpn->peer_notified_realm_id = RHP_VPN_REALM_ID_UNKNOWN;

  rhp_vpn_hold(vpn); // Unheld by rhp_vpn_destroy().


  if( my_id ){

    err = rhp_ikev2_id_dup(&(vpn->my_id),my_id);
    if( err ){
       RHP_BUG("");
       goto error;
    }
  }

  if( peer_id ){

  	err = rhp_ikev2_id_dup(&(vpn->peer_id),peer_id);
    if( err ){
       RHP_BUG("");
       goto error;
    }
  }


  for( i = 0; i < RHP_VPN_TX_IKEMESG_Q_NUM;i++){
  	rhp_ikemesg_q_init(&(vpn->req_tx_ikemesg_q[i]));
  }

  vpn->ikesa_get = _rhp_vpn_ikesa_get;
  vpn->ikesa_put = _rhp_vpn_ikesa_put;
  vpn->ikesa_delete = _rhp_vpn_ikesa_delete;

  vpn->childsa_get = _rhp_vpn_childsa_get;
  vpn->childsa_put = _rhp_vpn_childsa_put;
  vpn->childsa_delete = _rhp_vpn_childsa_delete;

  vpn->ikesa_move_to_top = _rhp_vpn_ikesa_move_to_top;
  vpn->childsa_move_to_top = _rhp_vpn_childsa_move_to_top;

  vpn->childsa_established = _rhp_vpn_childsa_established;

  vpn->v1_ipsecsa_get_by_mesg_id = _rhp_vpn_v1_ipsecsa_get_by_mesg_id;

  vpn->check_cfg_address = _rhp_vpn_check_cfg_address;

  vpn->set_local_net_info =_rhp_vpn_set_local_net_info;
  vpn->set_peer_addr = _rhp_vpn_set_peer_addr;

  vpn->sess_resume_clear = _rhp_vpn_sess_resume_clear;
  vpn->sess_resume_get_material_i = _rhp_vpn_sess_resume_get_material_i;
  vpn->sess_resume_set_material_i = _rhp_vpn_sess_resume_set_material_i;

  vpn->eap.ask_usr_key_ipc_txn_id = (u64)-1;

  vpn->dump = _rhp_vpn_dump;

  {
		rhp_timer_init(&(vpn->vpn_conn_timer),_rhp_vpn_conn_life_timer,NULL);

		vpn->start_vpn_conn_life_timer = _rhp_vpn_conn_start_life_timer;
		vpn->quit_vpn_conn_life_timer = _rhp_vpn_conn_quit_life_timer;
  }

  {
		rhp_timer_init(&(vpn->nhrp.nhc_registration_timer),_rhp_vpn_nhc_registration_timer,NULL);

		vpn->start_nhc_registration_timer = _rhp_vpn_nhc_start_registration_timer;
		vpn->quit_nhc_registration_timer = _rhp_vpn_nhc_quit_registration_timer;
  }

  {
		rhp_timer_init(&(vpn->vpn_conn_idle_timer),_rhp_vpn_conn_idle_timer,NULL);

		vpn->start_vpn_conn_idle_timer = _rhp_vpn_conn_start_idle_timer;
		vpn->quit_vpn_conn_idle_timer = _rhp_vpn_conn_quit_idle_timer;
  }

  if( rlm ){

  	vpn->vpn_realm_id = rlm->id;

    vpn->rlm = rlm;
    rhp_realm_hold(rlm);

    vpn->cfg_peer = rlm->dup_peer_by_id(rlm,peer_id,peer_ip);
    if( vpn->cfg_peer == NULL ){
    	goto error;
    }

    vpn->nat_t_info.use_nat_t_port = rlm->ikesa.use_nat_t_port;
    vpn->nat_t_info.always_use_nat_t_port = rlm->ikesa.use_nat_t_port;

    vpn->is_configured_peer = rlm->is_configued_peer(rlm,peer_id);

  	vpn->nhrp.role = rlm->nhrp.service;
  	vpn->nhrp.dmvpn_enabled = rlm->nhrp.dmvpn_enabled;

    if( rlm->nhrp.key ){

    	vpn->nhrp.key = (u8*)_rhp_malloc(rlm->nhrp.key_len);
    	if( vpn->nhrp.key == NULL ){
    		RHP_BUG("");
    		err = -ENOMEM;
    		goto error;
    	}

    	memcpy(vpn->nhrp.key,rlm->nhrp.key,rlm->nhrp.key_len);
    	vpn->nhrp.key_len = rlm->nhrp.key_len;
    }

  	RHP_TRC(0,RHPTRCID_VPN_ALLOC_RLM,"xdddddp",rlm,rlm->id,vpn->cfg_peer->is_access_point,vpn->nat_t_info.use_nat_t_port,vpn->nhrp.role,vpn->nhrp.dmvpn_enabled,vpn->nhrp.key_len,vpn->nhrp.key);
  	rhp_ip_addr_dump("cfg_peer->primary_addr",&(vpn->cfg_peer->primary_addr));
  	rhp_ip_addr_dump("cfg_peer->secondary_addr",&(vpn->cfg_peer->secondary_addr));
  	rhp_ip_addr_dump("cfg_peer->internal_addr",&(vpn->cfg_peer->internal_addr));
  }

  vpn->created = _rhp_get_time(NULL);

  vpn->origin_side = origin_side;

  if( origin_side == RHP_IKE_INITIATOR ){
  	rhp_timer_init(&(vpn->mobike.init.rt_ck_waiting_timer),rhp_ikev2_mobike_i_rt_ck_waiting_timer,vpn);
  }


  rhp_timer_init(&(vpn->ikev2_tx_new_req.task),rhp_ikev2_tx_new_req_task,vpn);


	RHP_LOCK(&rhp_eap_radius_cfg_lock);
	{
		vpn->radius.acct_enabled = rhp_gcfg_radius_acct->enabled;
	}
	RHP_UNLOCK(&rhp_eap_radius_cfg_lock);


	rhp_ikev2_g_statistics_inc(dc.vpn_num);
	rhp_ikev2_g_statistics_inc(vpn_allocated);

  vpn->dump("rhp_vpn_alloc",vpn);
  RHP_TRC(0,RHPTRCID_VPN_ALLOC_RTRN,"x",vpn);
  return vpn;

error:
	if( vpn ){
	  rhp_vpn_unhold(vpn);
	}
	RHP_TRC(0,RHPTRCID_VPN_ALLOC_ERR,"");
	return NULL;
}

rhp_vpn_ref* rhp_vpn_inb_childsa_get(u32 inb_spi)
{
  u32 hval = _rhp_hash_u32(inb_spi,_rhp_childsa_hashtbl_rnd);
  rhp_vpn_childsa_spi_entry* spi_ent;
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;

	RHP_TRC(0,RHPTRCID_VPN_INB_CHILDSA_GET,"H",inb_spi);

  RHP_LOCK(&rhp_vpn_lock);

  hval = hval % RHP_VPN_HASH_TABLE_SIZE;

  spi_ent = _rhp_childsa_hashtbl[hval];

  while( spi_ent ){

  	if( spi_ent->spi_inb == inb_spi ){
	   break;
  	}

  	spi_ent = spi_ent->next_hash;
  }

  if( spi_ent ){
    vpn = spi_ent->vpn;
    vpn_ref = rhp_vpn_hold_ref(spi_ent->vpn);
  }

  RHP_UNLOCK(&rhp_vpn_lock);

	RHP_TRC(0,RHPTRCID_VPN_INB_CHILDSA_GET_RTRN,"Hxxx",inb_spi,vpn,spi_ent,vpn_ref);

	return vpn_ref;
}

int rhp_vpn_inb_childsa_put(rhp_vpn* vpn,u32 inb_spi)
{
  u32 hval;
  rhp_vpn_childsa_spi_entry* spi_ent;

	RHP_TRC(0,RHPTRCID_VPN_INB_CHILDSA_PUT,"xH",vpn,inb_spi);

  spi_ent = (rhp_vpn_childsa_spi_entry*)_rhp_malloc(sizeof(rhp_vpn_childsa_spi_entry));
  if( spi_ent == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  spi_ent->tag[0] = '#';
  spi_ent->tag[1] = 'C';
  spi_ent->tag[2] = 'S';
  spi_ent->tag[3] = 'E';

  spi_ent->spi_inb = inb_spi;

  RHP_LOCK(&rhp_vpn_lock);

  spi_ent->vpn = vpn;
  rhp_vpn_hold(vpn); // rhp_vpn_hold_ref NOT used here.

  hval = _rhp_hash_u32(inb_spi,_rhp_childsa_hashtbl_rnd);
  hval = hval % RHP_VPN_HASH_TABLE_SIZE;

  spi_ent->next_hash = _rhp_childsa_hashtbl[hval];
  _rhp_childsa_hashtbl[hval] = spi_ent;

  RHP_UNLOCK(&rhp_vpn_lock);

	RHP_TRC(0,RHPTRCID_VPN_INB_CHILDSA_PUT_RTRN,"xHx",vpn,inb_spi,spi_ent);
  return 0;
}

int rhp_vpn_inb_childsa_delete(u32 inb_spi)
{
  int err = -ENOENT;
  u32 hval = _rhp_hash_u32(inb_spi,_rhp_childsa_hashtbl_rnd);
  rhp_vpn_childsa_spi_entry *spi_ent,*spi_ent_p = NULL;
  rhp_vpn* vpn = NULL;

	RHP_TRC(0,RHPTRCID_VPN_INB_CHILDSA_DELETE,"H",inb_spi);

  RHP_LOCK(&rhp_vpn_lock);

  hval = hval % RHP_VPN_HASH_TABLE_SIZE;

  spi_ent = _rhp_childsa_hashtbl[hval];

  while( spi_ent ){

	 if( spi_ent->spi_inb == inb_spi ){
	   break;
	 }

	 spi_ent_p = spi_ent;
	 spi_ent = spi_ent->next_hash;
  }

  if( spi_ent == NULL ){
    err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_VPN_INB_CHILDSA_DELETE_NO_ENTRY,"H",inb_spi);
    goto error;
  }

  if( spi_ent_p ){
    spi_ent_p->next_hash = spi_ent->next_hash;
  }else{
    _rhp_childsa_hashtbl[hval] = spi_ent->next_hash;
  }

  vpn = spi_ent->vpn;

  RHP_UNLOCK(&rhp_vpn_lock);

  rhp_vpn_unhold(spi_ent->vpn);
  _rhp_free(spi_ent);

	RHP_TRC(0,RHPTRCID_VPN_INB_CHILDSA_DELETE_RTRN,"Hxx",inb_spi,spi_ent,vpn);
  return 0;

error:
  RHP_UNLOCK(&rhp_vpn_lock);

  RHP_TRC(0,RHPTRCID_VPN_INB_CHILDSA_DELETE_ERR,"HE",inb_spi,err);
  return err;
}

static time_t _rhp_ikesa_keep_alive_random(int interval_secs)
{
	return _rhp_vpn_random_interval(interval_secs,RHP_CFG_KEEP_ALIVE_RANDOM_RANGE);
}


struct _rhp_ikesa_timer_ctx {
  int my_side;
  u8 my_spi[RHP_PROTO_IKE_SPI_SIZE];
  rhp_vpn_ref* vpn_ref;
};
typedef struct _rhp_ikesa_timer_ctx rhp_ikesa_timer_ctx;

static int _rhp_ikesa_start_retransmit_timer(rhp_vpn* vpn,rhp_ikesa* ikesa,int dont_wait)
{
  rhp_ikesa_timer_ctx* ctx;

  RHP_TRC(0,RHPTRCID_IKESA_START_RETRANSMIT_TIMER,"xxLdGGxLdd",vpn,ikesa,"IKE_SIDE",ikesa->side,ikesa->init_spi,ikesa->resp_spi,ikesa->timers,"IKESA_STAT",ikesa->state,dont_wait);

  if( rhp_timer_pending(&(ikesa->timers->retx_timer)) ){
    RHP_TRC(0,RHPTRCID_IKESA_START_RETRANSMIT_TIMER_TIMER_PENDING,"xxxx",vpn,ikesa,ikesa->timers,&(ikesa->timers->retx_timer));
    return 0;
  }

  ctx = (rhp_ikesa_timer_ctx*)_rhp_malloc(sizeof(rhp_ikesa_timer_ctx));
  if( ctx == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  memset(ctx,0,sizeof(rhp_ikesa_timer_ctx));

  ctx->vpn_ref = rhp_vpn_hold_ref(vpn);

  ctx->my_side = ikesa->side;
  if( ikesa->side == RHP_IKE_INITIATOR ){
    memcpy(ctx->my_spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
  }else{
    memcpy(ctx->my_spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
  }

  ikesa->timers->retx_timer.ctx = (void*)ctx;

  ikesa->timers->retx_counter = 0;
  ikesa->timers->retx_mobike_resp_counter = 0;

  rhp_timer_reset(&(ikesa->timers->retx_timer));
  rhp_timer_add(&(ikesa->timers->retx_timer),
  		( dont_wait ? 0 : (time_t)rhp_gcfg_ike_retry_init_interval));

  RHP_TRC(0,RHPTRCID_IKESA_START_RETRANSMIT_TIMER_RTRN,"xxxx",vpn,ikesa,ikesa->timers,ctx);
  return 0;
}

static int _rhp_ikesa_quit_retransmit_timer(rhp_vpn* vpn,rhp_ikesa* ikesa)
{
  RHP_TRC(0,RHPTRCID_IKESA_QUIT_RETRANSMIT_TIMER,"xxLdGGxLd",vpn,ikesa,"IKE_SIDE",ikesa->side,ikesa->init_spi,ikesa->resp_spi,ikesa->timers,"IKESA_STAT",ikesa->state);

	if( rhp_timer_delete(&(ikesa->timers->retx_timer)) ){
    RHP_TRC(0,RHPTRCID_IKESA_QUIT_RETRANSMIT_TIMER_NOT_ACTIVE,"xxxx",vpn,ikesa,ikesa->timers,&(ikesa->timers->retx_timer));
    return -1;
  }

  rhp_vpn_unhold(((rhp_ikesa_timer_ctx*)(ikesa->timers->retx_timer.ctx))->vpn_ref);
  _rhp_free(ikesa->timers->retx_timer.ctx);
  ikesa->timers->retx_timer.ctx = NULL;

  RHP_TRC(0,RHPTRCID_IKESA_QUIT_RETRANSMIT_TIMER_RTRN,"xxx",vpn,ikesa,ikesa->timers);

  return 0;
}

static int _rhp_ikesa_get_secondary_peer_cfg(rhp_vpn* vpn,rhp_vpn_realm* rlm,rhp_ikesa* ikesa,
		rhp_ip_addr** secondary_peer_addr_r,rhp_cfg_if** secondary_tx_cfg_if_r)
{
	int err = -EINVAL;
	rhp_ip_addr* secondary_peer_addr = NULL;
	rhp_cfg_if* cfg_if = NULL;

  RHP_TRC(0,RHPTRCID_IKESA_GET_SECONDARY_PEER_CFG,"xxxxx",vpn,rlm,ikesa,secondary_peer_addr_r,secondary_tx_cfg_if_r);

  if( rhp_ip_addr_null(&(vpn->cfg_peer->secondary_addr)) ||
  		rhp_ip_is_loopback(&(vpn->cfg_peer->secondary_addr)) ){
  	err = -ENOENT;
  	goto error;
  }

	secondary_peer_addr = &(vpn->cfg_peer->secondary_addr);

  if( rhp_gcfg_ipv6_disabled &&
  		secondary_peer_addr->addr_family == AF_INET6 ){

  	RHP_TRC(0,RHPTRCID_IKESA_GET_SECONDARY_PEER_CFG_IPV6_DISABLED,"xxx",vpn,rlm,ikesa);

  	err = -ENOENT;
  	goto error;
  }

	if( vpn->cfg_peer->secondary_tx_if_name ){

		cfg_if = rlm->get_my_interface(rlm,vpn->cfg_peer->secondary_tx_if_name,
							secondary_peer_addr->addr_family);
		if( cfg_if == NULL ){
	  	err = -ENOENT;
			goto error;
		}
	}

	*secondary_peer_addr_r = secondary_peer_addr;
	*secondary_tx_cfg_if_r = cfg_if;

	if( *secondary_peer_addr_r ){
	  rhp_ip_addr_dump("secondary_peer_addr_r",*secondary_peer_addr_r);
	}

	if( *secondary_tx_cfg_if_r ){
	  RHP_TRC(0,RHPTRCID_IKESA_GET_SECONDARY_PEER_CFG_2ND_CFG_IF,"xs",vpn,(*secondary_tx_cfg_if_r)->if_name);
	}

  RHP_TRC(0,RHPTRCID_IKESA_GET_SECONDARY_PEER_CFG_RTRN,"xxxxx",vpn,rlm,ikesa,*secondary_peer_addr_r,*secondary_tx_cfg_if_r);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKESA_GET_SECONDARY_PEER_CFG_ERR,"xxxxxE",vpn,rlm,ikesa,secondary_peer_addr_r,secondary_tx_cfg_if_r,err);
	return err;
}

static int _rhp_ikesa_secondary_path(rhp_vpn* vpn,rhp_vpn_realm* rlm,rhp_ikesa* ikesa,
		rhp_ip_addr** secondary_peer_addr_r,rhp_cfg_if** secondary_tx_cfg_if_r)
{
	int err = -EINVAL;
	rhp_ip_addr* secondary_peer_addr = NULL;
	rhp_cfg_if* secondary_tx_cfg_if = NULL;

  RHP_TRC(0,RHPTRCID_IKESA_SECONDARY_PATH,"xxxxx",vpn,rlm,ikesa,secondary_peer_addr_r,secondary_tx_cfg_if_r);

	err = _rhp_ikesa_get_secondary_peer_cfg(vpn,rlm,ikesa,&secondary_peer_addr,&secondary_tx_cfg_if);
	if( err ){

		if( vpn->cfg_peer &&
				!rhp_ip_addr_null(&(vpn->cfg_peer->mobike_additional_addr_cache)) &&
				rhp_ip_addr_cmp(&(vpn->peer_addr),&(vpn->cfg_peer->mobike_additional_addr_cache)) ){

			secondary_peer_addr = &(vpn->cfg_peer->mobike_additional_addr_cache);
		  rhp_ip_addr_dump("_rhp_ikesa_secondary_path:mobike",secondary_peer_addr);

		}else{

			secondary_peer_addr = &(vpn->peer_addr);
		  rhp_ip_addr_dump("_rhp_ikesa_secondary_path:current",secondary_peer_addr);

			if( rlm->my_interface_use_def_route ){

				secondary_tx_cfg_if = rlm->get_next_my_interface_def_route(rlm,vpn->local.if_info.if_name,secondary_peer_addr);

			}else{

				secondary_tx_cfg_if = rlm->get_next_my_interface(rlm,vpn->local.if_info.if_name,secondary_peer_addr);
			}

			if( secondary_tx_cfg_if == NULL ){
		  	err = -ENOENT;
				goto error;
			}
		}

		err = 0;
	}

	if( secondary_tx_cfg_if == NULL ){

		if( rlm->my_interface_use_def_route ){

			secondary_tx_cfg_if = rlm->get_next_my_interface_def_route(rlm,NULL,secondary_peer_addr);

		}else{

			secondary_tx_cfg_if = rlm->get_next_my_interface(rlm,NULL,secondary_peer_addr);
		}

		if( secondary_tx_cfg_if == NULL ){
	  	err = -ENOENT;
			goto error;
		}
	}

	*secondary_peer_addr_r = secondary_peer_addr;
	*secondary_tx_cfg_if_r = secondary_tx_cfg_if;

  RHP_TRC(0,RHPTRCID_IKESA_SECONDARY_PATH_RTRN,"xxxxxxs",vpn,rlm,ikesa,*secondary_peer_addr_r,*secondary_tx_cfg_if_r,secondary_tx_cfg_if,secondary_tx_cfg_if->if_name);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKESA_SECONDARY_PATH_ERR,"xxxE",vpn,rlm,ikesa,err);
	return err;
}

static void _rhp_ikesa_retransmit_timer(void *ctx,rhp_timer *timer)
{
  int err = 0;
  rhp_vpn_ref* vpn_ref = ((rhp_ikesa_timer_ctx*)ctx)->vpn_ref;
  rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);
  rhp_ikesa* ikesa = NULL;
  int next_interval = 0;
  int my_side = ((rhp_ikesa_timer_ctx*)ctx)->my_side;
  u8* my_spi = ((rhp_ikesa_timer_ctx*)ctx)->my_spi;
  int exec_mobike = 0;
  int retry_times = rhp_gcfg_ike_retry_times;

  RHP_TRC(0,RHPTRCID_IKESA_RETRANSMIT_TIMER,"xxLdG",vpn,timer,"IKE_SIDE",my_side,my_spi);

  RHP_LOCK(&(vpn->lock));

  RHP_TRC(0,RHPTRCID_IKESA_RETRANSMIT_TIMER_VPN,"xxpux",vpn,vpn_ref,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm);
  rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
  rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKESA_RETRANSMIT_TIMER_IKESA_VPN_NOT_ACTIVE,"xx",vpn,timer);
    goto error;
  }


  ikesa = vpn->ikesa_get(vpn,my_side,my_spi);
  if( ikesa == NULL ){
    RHP_TRC(0,RHPTRCID_IKESA_RETRANSMIT_TIMER_NO_IKESA,"xx",vpn,timer);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKESA_RETRANSMIT_TIMER_IKESA,"xxLdLd",vpn,ikesa,"IKESA_STAT",ikesa->state,"IKE_SIDE",ikesa->side);
  rhp_ip_addr_dump("vpn->peer_addr",&(vpn->peer_addr));
  rhp_if_entry_dump("vpn->local.if_info",&(vpn->local.if_info));


	if( vpn->exec_mobike &&
			(ikesa->state == RHP_IKESA_STAT_ESTABLISHED || ikesa->state == RHP_IKESA_STAT_REKEYING) ){

		exec_mobike = 1;
	}

  if( ikesa->state == RHP_IKESA_STAT_I_IKE_SA_INIT_SENT ){

  	retry_times = rhp_gcfg_ike_init_retry_times;
  }

  RHP_TRC(0,RHPTRCID_IKESA_RETRANSMIT_TIMER_IKESA_TIMERS,"xxxdddddd",vpn,ikesa,ikesa->timers,ikesa->timers->retx_counter,exec_mobike,rhp_gcfg_ike_retry_times,rhp_gcfg_ike_init_retry_times,retry_times,vpn->exec_ikev2_frag);


  if( vpn->exec_ikev2_frag ){

    ikesa->reset_rep_frag_pkts_q(ikesa);
  }


  if( ikesa->timers->retx_counter >= retry_times ){

    RHP_TRC(0,RHPTRCID_IKESA_RETRANSMIT_TIMER_TIMEOUT,"xxx",vpn,ikesa,ikesa->timers);

    if( ikesa->state == RHP_IKESA_STAT_I_IKE_SA_INIT_SENT ){

  	  rhp_vpn_realm* rlm = NULL;

  	  rlm = vpn->rlm;

  	  RHP_LOCK(&(rlm->lock));

  	  if( !_rhp_atomic_read(&(rlm->is_active)) ){
  	    RHP_UNLOCK(&(rlm->lock));
  	    RHP_TRC(0,RHPTRCID_IKESA_RETRANSMIT_TIMER_RLM_NOT_ACTIVE,"xx",vpn,timer);
  	    goto error;
  	  }

      RHP_TRC(0,RHPTRCID_IKESA_RETRANSMIT_TIMER_TIMEOUT_SECONDARY_PEER,"xxss",vpn,vpn->cfg_peer,vpn->cfg_peer->primary_tx_if_name,vpn->cfg_peer->secondary_tx_if_name);
      rhp_ip_addr_dump("vpn->cfg_peer->primary_addr",&(vpn->cfg_peer->primary_addr));
      rhp_ip_addr_dump("vpn->cfg_peer->secondary_addr",&(vpn->cfg_peer->secondary_addr));

    	if( !ikesa->tried_secondary_peer ){

    		rhp_ip_addr* secondary_peer_addr = NULL;
    		rhp_cfg_if* secondary_tx_cfg_if = NULL;

    		ikesa->tried_secondary_peer = 1;

    		err = _rhp_ikesa_secondary_path(vpn,rlm,ikesa,
    						&secondary_peer_addr,&secondary_tx_cfg_if);
    		if( !err ){

      	  rhp_ikev2_mesg* new_1st_mesg = NULL;
      	  time_t lifetime_larval;

    			err = rhp_ikev2_ike_sa_init_i_try_secondary(vpn,ikesa,
    							secondary_peer_addr,secondary_tx_cfg_if,&new_1st_mesg);
    			if( err ){
    			  RHP_UNLOCK(&(rlm->lock));
    				RHP_TRC(0,RHPTRCID_IKESA_RETRANSMIT_TIMER_TIMEOUT_TRY_SECONDARY_ERR,"xxxE",vpn,ikesa,ikesa->timers,err);
    				goto error;
          }

    			ikesa->timers->retx_counter = 0;

    		  lifetime_larval = (time_t)rlm->ikesa.lifetime_larval;

    		  rhp_timer_reset(&(ikesa->timers->retx_timer));
    		  rhp_timer_add(&(ikesa->timers->retx_timer),(time_t)rhp_gcfg_ike_retry_init_interval);

  				RHP_TRC(0,RHPTRCID_IKESA_RETRANSMIT_TIMER_TIMEOUT_TRY_SECONDARY,"xxx",vpn,ikesa,ikesa->timers);

  			  RHP_UNLOCK(&(rlm->lock));


  			  rhp_ikev2_send_request(vpn,ikesa,new_1st_mesg,RHP_IKEV2_MESG_HANDLER_IKESA_INIT);
					rhp_ikev2_unhold_mesg(new_1st_mesg);


  			  if( !ikesa->timers->quit_lifetime_timer(vpn,ikesa) ){

  			  	ikesa->timers->start_lifetime_timer(vpn,ikesa,lifetime_larval,1);

  			  }else{

  			  	RHP_TRC(0,RHPTRCID_IKESA_RETRANSMIT_TIMER_TIMEOUT_TRY_SECONDARY_RESTART_LIFETIMER_ERR,"xxx",vpn,ikesa,ikesa->timers);
    				goto error;
  			  }

    			goto try_secondary;
    		}
    	}

    	RHP_UNLOCK(&(rlm->lock));


    }else if( exec_mobike ){

    	// VPN is already established.

			if( vpn->origin_side == RHP_IKE_INITIATOR ){

				err = rhp_ikev2_mobike_i_start_routability_check(vpn,ikesa,0);
				if( !err ){
					goto mobike_rt_check;
				}

			}else{ // RHP_IKE_RESPONDER

				if( ikesa->req_retx_pkt &&
						ikesa->req_retx_pkt->ikev2_keep_alive &&
						!rhp_ikev2_mobike_pending(vpn) ){

					rhp_vpn_realm* rlm = vpn->rlm;
					int mobike_retries;

					RHP_TRC(0,RHPTRCID_IKESA_RETRANSMIT_TIMER_EXEC_MOBIKE_KEEP_ALIVE,"xxxd",vpn,rlm,timer,ikesa->timers->retx_mobike_resp_counter);

					{
						RHP_LOCK(&(rlm->lock));

						if( !_rhp_atomic_read(&(rlm->is_active)) ){
							RHP_UNLOCK(&(rlm->lock));
							RHP_TRC(0,RHPTRCID_IKESA_RETRANSMIT_TIMER_EXEC_MOBIKE_RLM_NOT_ACTIVE,"xx",vpn,timer);
							goto error;
						}

						next_interval
						= _rhp_vpn_random_interval(rlm->mobike.resp_ka_retx_interval,RHP_IKEV2_CFG_MOBIKE_KA_RANGE);

						mobike_retries = rlm->mobike.resp_ka_retx_retries;

						RHP_UNLOCK(&(rlm->lock));
					}

					if( ikesa->timers->retx_mobike_resp_counter < mobike_retries ){

						if( vpn->mobike.resp.keepalive_pending == 0 ){

							vpn->mobike.resp.keepalive_pending = 1;


					  	rhp_http_bus_broadcast_async(vpn->vpn_realm_id,1,1,
					  			rhp_ui_http_vpn_mobike_r_net_outage_detected_serialize,
					  			rhp_ui_http_vpn_bus_btx_async_cleanup,(void*)rhp_vpn_hold_ref(vpn)); // (*x*)

							RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_NET_OUTAGE_DETECTED,"VP",vpn,ikesa);

							rhp_ikev2_g_statistics_inc(mobike_resp_net_outage_times);
						}

						ikesa->timers->retx_mobike_resp_counter++;

						goto retx_timer_cont;
					}
				}
			}
    }

    RHP_TRC(0,RHPTRCID_IKESA_RETRANSMIT_TIMER_TIMEOUT_2,"xxx",vpn,ikesa,ikesa->timers);
    goto error;

  }else{

  	int scale = 2;
    int i;

    for( i = 0; i < ikesa->timers->retx_counter; i++ ){scale *= 2;}

    next_interval = rhp_gcfg_ike_retry_init_interval*scale;
    if( next_interval > rhp_gcfg_ike_retry_max_interval ){
      next_interval = rhp_gcfg_ike_retry_max_interval;
    }

    ikesa->timers->retx_counter++;
  }


retx_timer_cont:

  //
  // [CAUTION]
  //
  //  This call may acquire (rhp_ifc_entry*)ifc->lock.
  //
  err = rhp_ikev2_retransmit_req(vpn,ikesa);
  if( err != RHP_STATUS_IKEV2_RETRANS_PKT_CLEARED ){

  	rhp_timer_reset(&(ikesa->timers->retx_timer));
    rhp_timer_add(&(ikesa->timers->retx_timer),(time_t)next_interval);
  }
  err = 0;

try_secondary:
  RHP_UNLOCK(&(vpn->lock));

  rhp_ikev2_g_statistics_inc(tx_ikev2_req_retransmit_packets);

	RHP_TRC(0,RHPTRCID_IKESA_RETRANSMIT_TIMER_RTRN,"xxxdd",vpn,ikesa,timer,rhp_gcfg_ike_retry_times,next_interval);
  return;


error:
	if( vpn->connecting ){
		vpn->connecting = 0;
		rhp_ikesa_half_open_sessions_dec();
	}

	RHP_LOG_E(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV2_RETRANSMIT_ERR,"VPddE",vpn,ikesa,ikesa->timers->retx_counter,rhp_gcfg_ike_retry_times,err);

  if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
  }

mobike_rt_check:
  RHP_UNLOCK(&(vpn->lock));

  rhp_vpn_unhold(vpn_ref);
  _rhp_free(ctx);

	rhp_ikev2_g_statistics_inc(tx_ikev2_req_retransmit_errors);

  RHP_TRC(0,RHPTRCID_IKESA_RETRANSMIT_TIMER_ERR,"xxxx",vpn,vpn_ref,ikesa,timer);
  return;
}

static void _rhp_ikesa_v1_retransmit_timer(void *ctx,rhp_timer *timer)
{
  int err = 0;
  rhp_vpn_ref* vpn_ref = ((rhp_ikesa_timer_ctx*)ctx)->vpn_ref;
  rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);
  rhp_ikesa* ikesa = NULL;
  int next_interval = 0;
  int my_side = ((rhp_ikesa_timer_ctx*)ctx)->my_side;
  u8* my_spi = ((rhp_ikesa_timer_ctx*)ctx)->my_spi;
  int retry_times = rhp_gcfg_ike_retry_times;
  int negotiating = 0;

  RHP_TRC(0,RHPTRCID_IKESA_V1_RETRANSMIT_TIMER,"xxLdG",vpn,timer,"IKE_SIDE",my_side,my_spi);

  RHP_LOCK(&(vpn->lock));

  RHP_TRC(0,RHPTRCID_IKESA_V1_RETRANSMIT_TIMER_VPN,"xxpux",vpn,vpn_ref,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm);
  rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
  rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKESA_V1_RETRANSMIT_TIMER_IKESA_VPN_NOT_ACTIVE,"xx",vpn,timer);
    goto error;
  }


  ikesa = vpn->ikesa_get(vpn,my_side,my_spi);
  if( ikesa == NULL ){
    RHP_TRC(0,RHPTRCID_IKESA_V1_RETRANSMIT_TIMER_NO_IKESA,"xx",vpn,timer);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKESA_V1_RETRANSMIT_TIMER_IKESA,"xxLdLd",vpn,ikesa,"IKESA_STAT",ikesa->state,"IKE_SIDE",ikesa->side);
  rhp_ip_addr_dump("vpn->peer_addr",&(vpn->peer_addr));
  rhp_if_entry_dump("vpn->local.if_info",&(vpn->local.if_info));


  if( ikesa->state == RHP_IKESA_STAT_V1_MAIN_1ST_SENT_I ||
  		ikesa->state == RHP_IKESA_STAT_V1_MAIN_3RD_SENT_I ||
  		ikesa->state == RHP_IKESA_STAT_V1_MAIN_5TH_SENT_I ||
  		ikesa->state == RHP_IKESA_STAT_V1_AGG_1ST_SENT_I  ||
  		ikesa->state == RHP_IKESA_STAT_V1_AGG_WAIT_COMMIT_I ){

  	negotiating = 1;
  	retry_times = rhp_gcfg_ike_init_retry_times;
  }

  RHP_TRC(0,RHPTRCID_IKESA_V1_RETRANSMIT_TIMER_IKESA_TIMERS,"xxxdddd",vpn,ikesa,ikesa->timers,ikesa->timers->retx_counter,rhp_gcfg_ike_retry_times,rhp_gcfg_ike_init_retry_times,retry_times);


  if( ikesa->timers->retx_counter >= retry_times ){

    RHP_TRC(0,RHPTRCID_IKESA_V1_RETRANSMIT_TIMER_TIMEOUT,"xxx",vpn,ikesa,ikesa->timers);

    if( negotiating ){

  	  rhp_vpn_realm* rlm = NULL;

  	  rlm = vpn->rlm;

  	  RHP_LOCK(&(rlm->lock));

  	  if( !_rhp_atomic_read(&(rlm->is_active)) ){
  	    RHP_UNLOCK(&(rlm->lock));
  	    RHP_TRC(0,RHPTRCID_IKESA_V1_RETRANSMIT_TIMER_RLM_NOT_ACTIVE,"xx",vpn,timer);
  	    goto error;
  	  }

      RHP_TRC(0,RHPTRCID_IKESA_V1_RETRANSMIT_TIMER_TIMEOUT_SECONDARY_PEER,"xxss",vpn,vpn->cfg_peer,vpn->cfg_peer->primary_tx_if_name,vpn->cfg_peer->secondary_tx_if_name);
      rhp_ip_addr_dump("vpn->cfg_peer->primary_addr",&(vpn->cfg_peer->primary_addr));
      rhp_ip_addr_dump("vpn->cfg_peer->secondary_addr",&(vpn->cfg_peer->secondary_addr));

    	if( !ikesa->tried_secondary_peer ){

    		rhp_ip_addr* secondary_peer_addr = NULL;
    		rhp_cfg_if* secondary_tx_cfg_if = NULL;

    		ikesa->tried_secondary_peer = 1;

    		err = _rhp_ikesa_secondary_path(vpn,rlm,ikesa,
    						&secondary_peer_addr,&secondary_tx_cfg_if);
    		if( !err ){

      	  rhp_ikev2_mesg* new_1st_mesg = NULL;
      	  int tx_handler_type;
      	  time_t lifetime_larval;

    			err = rhp_ikev1_connect_i_try_secondary(vpn,ikesa,rlm,
    							secondary_peer_addr,secondary_tx_cfg_if,&new_1st_mesg);
    			if( err ){
    			  RHP_UNLOCK(&(rlm->lock));
    				RHP_TRC(0,RHPTRCID_IKESA_V1_RETRANSMIT_TIMER_TIMEOUT_TRY_SECONDARY_ERR,"xxxE",vpn,ikesa,ikesa->timers,err);
    				goto error;
          }

    			ikesa->timers->retx_counter = 0;

    		  lifetime_larval = (time_t)rlm->ikesa.lifetime_larval;

    		  rhp_timer_reset(&(ikesa->timers->retx_timer));
    		  rhp_timer_add(&(ikesa->timers->retx_timer),(time_t)rhp_gcfg_ike_retry_init_interval);

  				RHP_TRC(0,RHPTRCID_IKESA_V1_RETRANSMIT_TIMER_TIMEOUT_TRY_SECONDARY,"xxx",vpn,ikesa,ikesa->timers);

  			  RHP_UNLOCK(&(rlm->lock));

     			if( ikesa->v1.p1_exchange_mode == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ){
     				tx_handler_type = RHP_IKEV1_MESG_HANDLER_P1_MAIN;
     			}else if( ikesa->v1.p1_exchange_mode == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){
     				tx_handler_type = RHP_IKEV1_MESG_HANDLER_P1_AGGRESSIVE;
     			}else{
    			  RHP_UNLOCK(&(rlm->lock));
     				err = -EINVAL;
     				RHP_BUG("");
     				goto error;
     			}

  			  rhp_ikev1_send_mesg(vpn,ikesa,new_1st_mesg,tx_handler_type);
					rhp_ikev2_unhold_mesg(new_1st_mesg);


  			  if( !ikesa->timers->quit_lifetime_timer(vpn,ikesa) ){

  			  	ikesa->timers->start_lifetime_timer(vpn,ikesa,lifetime_larval,1);

  			  }else{

  			  	RHP_TRC(0,RHPTRCID_IKESA_V1_RETRANSMIT_TIMER_TIMEOUT_TRY_SECONDARY_RESTART_LIFETIMER_ERR,"xxx",vpn,ikesa,ikesa->timers);
    				goto error;
  			  }

    			goto try_secondary;
    		}
    	}

    	RHP_UNLOCK(&(rlm->lock));
    }

    RHP_TRC(0,RHPTRCID_IKESA_V1_RETRANSMIT_TIMER_TIMEOUT_2,"xxx",vpn,ikesa,ikesa->timers);
    goto error;

  }else{

  	int scale = 2;
    int i;

    for( i = 0; i < ikesa->timers->retx_counter; i++ ){scale *= 2;}

    next_interval = rhp_gcfg_ike_retry_init_interval*scale;
    if( next_interval > rhp_gcfg_ike_retry_max_interval ){
      next_interval = rhp_gcfg_ike_retry_max_interval;
    }

    ikesa->timers->retx_counter++;
  }


  //
  // [CAUTION]
  //
  //  This call may acquire (rhp_ifc_entry*)ifc->lock.
  //
  err = rhp_ikev1_retransmit_mesg(vpn,ikesa);
  if( err != RHP_STATUS_IKEV2_RETRANS_PKT_CLEARED ){

  	rhp_timer_reset(&(ikesa->timers->retx_timer));
    rhp_timer_add(&(ikesa->timers->retx_timer),(time_t)next_interval);
  }
  err = 0;

try_secondary:
  RHP_UNLOCK(&(vpn->lock));

  rhp_ikev2_g_statistics_inc(tx_ikev1_retransmit_packets);

	RHP_TRC(0,RHPTRCID_IKESA_V1_RETRANSMIT_TIMER_RTRN,"xxxdd",vpn,ikesa,timer,rhp_gcfg_ike_retry_times,next_interval);
  return;


error:
	if( vpn->connecting ){
		vpn->connecting = 0;
		rhp_ikesa_half_open_sessions_dec();
	}

	RHP_LOG_E(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV1_RETRANSMIT_ERR,"VPddE",vpn,ikesa,ikesa->timers->retx_counter,rhp_gcfg_ike_retry_times,err);

  if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
  }

  RHP_UNLOCK(&(vpn->lock));

  rhp_vpn_unhold(vpn_ref);
  _rhp_free(ctx);

	rhp_ikev2_g_statistics_inc(tx_ikev1_retransmit_errors);

  RHP_TRC(0,RHPTRCID_IKESA_V1_RETRANSMIT_TIMER_ERR,"xxxx",vpn,vpn_ref,ikesa,timer);
  return;
}

static int _rhp_ikesa_start_lifetime_timer(rhp_vpn* vpn,rhp_ikesa* ikesa,time_t secs,int sec_randomized)
{
	rhp_ikesa_timer_ctx* ctx;
	time_t secs_r = secs;

  RHP_TRC(0,RHPTRCID_IKESA_START_LIFETIME_TIMER,"xxLdGGxdLdd",vpn,ikesa,"IKE_SIDE",ikesa->side,ikesa->init_spi,ikesa->resp_spi,ikesa->timers,secs,"IKESA_STAT",ikesa->state,ikesa->v1.p1_exchange_mode);

  if( rhp_timer_pending(&(ikesa->timers->lifetime_timer)) ){
    RHP_TRC(0,RHPTRCID_IKESA_START_LIFETIME_TIMER_PENDING,"xxxx",vpn,ikesa,ikesa->timers,&(ikesa->timers->lifetime_timer));
    return 0;
  }

  ctx = (rhp_ikesa_timer_ctx*)_rhp_malloc(sizeof(rhp_ikesa_timer_ctx));
  if( ctx == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }
  memset(ctx,0,sizeof(rhp_ikesa_timer_ctx));

  ctx->vpn_ref = rhp_vpn_hold_ref(vpn);

  ctx->my_side = ikesa->side;
  if( ikesa->side == RHP_IKE_INITIATOR ){
    memcpy(ctx->my_spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
  }else{
    memcpy(ctx->my_spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
  }

  ikesa->timers->lifetime_timer.ctx = (void*)ctx;

  rhp_timer_reset(&(ikesa->timers->lifetime_timer));

  if( sec_randomized ){
  	secs_r = rhp_vpn_lifetime_random(secs);
  }
  rhp_timer_add(&(ikesa->timers->lifetime_timer),secs_r);

  RHP_TRC(0,RHPTRCID_IKESA_START_LIFETIME_TIMER_RTRN,"xxxx",vpn,ikesa,ikesa->timers,ctx);
  return 0;
}

static int _rhp_ikesa_quit_lifetime_timer(rhp_vpn* vpn,rhp_ikesa* ikesa)
{
  RHP_TRC(0,RHPTRCID_IKESA_QUIT_LIFETIME_TIMER,"xxLdGGxLdd",vpn,ikesa,"IKE_SIDE",ikesa->side,ikesa->init_spi,ikesa->resp_spi,ikesa->timers,"IKESA_STAT",ikesa->state,ikesa->v1.p1_exchange_mode);

	if( rhp_timer_delete(&(ikesa->timers->lifetime_timer)) ){
	  RHP_TRC(0,RHPTRCID_IKESA_QUIT_LIFETIME_TIMER_NOT_ACTIVE,"xxxx",vpn,ikesa,ikesa->timers,&(ikesa->timers->lifetime_timer));
	  return -1;
  }

  rhp_vpn_unhold(((rhp_ikesa_timer_ctx*)(ikesa->timers->lifetime_timer.ctx))->vpn_ref);
  _rhp_free(ikesa->timers->lifetime_timer.ctx);
  ikesa->timers->lifetime_timer.ctx = NULL;

  RHP_TRC(0,RHPTRCID_IKESA_QUIT_LIFETIME_TIMER_RTRN,"xxx",vpn,ikesa,ikesa->timers);
  return 0;
}

static void _rhp_vpn_auto_reconnect_handler(void *ctx);

static void _rhp_vpn_auto_reconnect_dns_task_bh(int worker_index,void *ctx)
{
  RHP_TRC(0,RHPTRCID_VPN_AUTO_RECONNECT_DNS_TASK_BH,"dx",worker_index,ctx);
	_rhp_vpn_auto_reconnect_handler(ctx);
  RHP_TRC(0,RHPTRCID_VPN_AUTO_RECONNECT_DNS_TASK_BH_RTRN,"dx",worker_index,ctx);
}

static void _rhp_vpn_auto_reconnect_dns_task(void* ctx,void* not_used,int err,int res_addrs_num,rhp_ip_addr* res_addrs)
{
	rhp_vpn_reconnect_info* reconnect_info = (rhp_vpn_reconnect_info*)ctx;

  RHP_TRC(0,RHPTRCID_VPN_AUTO_RECONNECT_DNS_TASK,"xxEdx",ctx,not_used,err,res_addrs_num,res_addrs);

	if( err ){
		goto error;
	}else if( res_addrs_num == 0 ){
		err = -ENOENT;
		goto error;
	}

	rhp_ip_addr_dump("peer_fqdn_addr_primary",&(res_addrs[0]));
	memcpy(&(reconnect_info->peer_fqdn_addr_primary),&(res_addrs[0]),sizeof(rhp_ip_addr));
	reconnect_info->peer_fqdn_addr_primary.port = htons(rhp_gcfg_ike_port); // LOCK not needed.;

	if( res_addrs_num > 1 ){
		rhp_ip_addr_dump("peer_fqdn_addr_secondary",&(res_addrs[1]));
		memcpy(&(reconnect_info->peer_fqdn_addr_secondary),&(res_addrs[1]),sizeof(rhp_ip_addr));
		reconnect_info->peer_fqdn_addr_secondary.port = htons(rhp_gcfg_ike_port); // LOCK not needed.;
	}

	if( !rhp_wts_dispach_ok(RHP_WTS_DISP_LEVEL_HIGH_2,0) ){
		err = -EBUSY;
		goto error;
	}

	err = rhp_wts_add_task(RHP_WTS_DISP_RULE_RAND,RHP_WTS_DISP_LEVEL_HIGH_2,NULL,
			_rhp_vpn_auto_reconnect_dns_task_bh,(void*)reconnect_info);

	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	err = 0;

  RHP_TRC(0,RHPTRCID_VPN_AUTO_RECONNECT_DNS_TASK_RTRN,"x",ctx);
	return;

error:
	_rhp_vpn_auto_reconnect_free(reconnect_info);

  RHP_TRC(0,RHPTRCID_VPN_AUTO_RECONNECT_DNS_TASK_ERR,"xE",ctx,err);
	return;
}

static void _rhp_vpn_auto_reconnect_handler(void *ctx)
{
	int err = -EINVAL;
	rhp_vpn_reconnect_info* reconnect_info = (rhp_vpn_reconnect_info*)ctx;
	rhp_ip_addr* peer_addr_p = NULL;
	u16 peer_port = 0;
	int cont_flag = 0;

  RHP_TRC(0,RHPTRCID_VPN_AUTO_RECONNECT_HANDLER,"xx",reconnect_info,reconnect_info->sess_resume_material_i);

  if( !rhp_ip_addr_null(&(reconnect_info->peer_addr)) ){
  	peer_addr_p = &(reconnect_info->peer_addr);
  	peer_port = reconnect_info->peer_port;
  }

	RHP_LOG_I(RHP_LOG_SRC_VPNMNG,reconnect_info->rlm_id,RHP_LOG_ID_EXEC_AUTO_RECONNECT,"d",reconnect_info->retries);
	if( reconnect_info->sess_resume_material_i ){
		RHP_LOG_D(RHP_LOG_SRC_VPNMNG,reconnect_info->rlm_id,RHP_LOG_ID_EXEC_AUTO_RECONNECT_BY_SESS_RESUME,"d",reconnect_info->retries);
	}

	if( peer_addr_p == NULL ){

		if( reconnect_info->peer_fqdn && rhp_ip_addr_null(&(reconnect_info->peer_fqdn_addr_primary)) ){

			err = rhp_dns_resolve(RHP_WTS_DISP_LEVEL_HIGH_2,reconnect_info->peer_fqdn,AF_UNSPEC,
					_rhp_vpn_auto_reconnect_dns_task,ctx,NULL);
			if( err ){
			  RHP_TRC(0,RHPTRCID_VPN_AUTO_RECONNECT_HANDLER_DNS_ERR,"xsE",reconnect_info,reconnect_info->peer_fqdn,err);
				goto error;
			}

			cont_flag = 1;

			// Don't free reconnect_info.
		}
	}

	if( !cont_flag ){

		rhp_vpn_conn_args conn_args;
		rhp_vpn_reconn_args reconn_args;

		memset(&conn_args,0,sizeof(rhp_vpn_conn_args));
		memset(&reconn_args,0,sizeof(rhp_vpn_reconn_args));

		conn_args.peer_id = &(reconnect_info->peer_id);
		conn_args.peer_addr = peer_addr_p;
		conn_args.peer_fqdn = reconnect_info->peer_fqdn;
		conn_args.peer_fqdn_addr_primary = &(reconnect_info->peer_fqdn_addr_primary);
		conn_args.peer_fqdn_addr_secondary = &(reconnect_info->peer_fqdn_addr_secondary);
		conn_args.peer_port = peer_port;
		conn_args.eap_sup_method = 0;
		conn_args.eap_sup_user_id_len = 0;
		conn_args.eap_sup_user_id = NULL;
		conn_args.eap_sup_user_key_len = 0;
		conn_args.eap_sup_user_key = NULL;
		conn_args.ui_info = NULL;

		reconn_args.auto_reconnect = 1;
		reconn_args.exec_auto_reconnect = 1;
		reconn_args.auto_reconnect_retries = reconnect_info->retries;

		if( reconnect_info->sess_resume_material_i ){

			time_t now = _rhp_get_time();

		  RHP_TRC(0,RHPTRCID_VPN_AUTO_RECONNECT_HANDLER_SESS_RESUME_MAT_I,"xxtt",reconnect_info,reconnect_info->sess_resume_material_i,now,reconnect_info->sess_resume_material_i->peer_tkt_r_expire_time);

			if( reconnect_info->sess_resume_material_i->peer_tkt_r_expire_time == 0 ||
					now < reconnect_info->sess_resume_material_i->peer_tkt_r_expire_time ){

				reconn_args.sess_resume_material_i = reconnect_info->sess_resume_material_i;

			}else{

				RHP_TRC(0,RHPTRCID_VPN_AUTO_RECONNECT_HANDLER_SESS_RESUME_MAT_I_EXPIRED,"xx",reconnect_info,reconnect_info->sess_resume_material_i);
				RHP_LOG_DE(RHP_LOG_SRC_VPNMNG,reconnect_info->rlm_id,RHP_LOG_ID_AUTO_RECONNECT_I_SESS_RESUME_TKT_EXPIRED,"IAs",&(reconnect_info->peer_id),&(reconnect_info->peer_addr),reconnect_info->peer_fqdn);
			}
		}

		{
			err = rhp_vpn_connect_i(reconnect_info->rlm_id,&(conn_args),&(reconn_args),0);

			if( reconn_args.sess_resume_material_i == NULL ){
				reconnect_info->sess_resume_material_i = NULL;
			}

			if( err ){
				RHP_TRC(0,RHPTRCID_VPN_AUTO_RECONNECT_HANDLER_CONN_I_ERR,"xE",reconnect_info,err);
				goto error;
			}
		}

		_rhp_vpn_auto_reconnect_free(reconnect_info);
	}

  RHP_TRC(0,RHPTRCID_VPN_AUTO_RECONNECT_HANDLER_RTRN,"xE",reconnect_info);
	return;

error:
	if( err == RHP_STATUS_IKESA_EXISTS ){
		RHP_LOG_D(RHP_LOG_SRC_VPNMNG,reconnect_info->rlm_id,RHP_LOG_ID_EXEC_AUTO_RECONNECT_IKESA_ALREADY_EXISTS,"IE",(reconnect_info ? &(reconnect_info->peer_id) : NULL),err);
	}else if( err == RHP_STATUS_CONNECT_VPN_I_EAP_SUP_USER_KEY_NEEDED ){
		RHP_LOG_E(RHP_LOG_SRC_VPNMNG,reconnect_info->rlm_id,RHP_LOG_ID_EXEC_AUTO_RECONNECT_EAP_KEY_NOT_CACHED,"IE",(reconnect_info ? &(reconnect_info->peer_id) : NULL),err);
	}else{
		RHP_LOG_E(RHP_LOG_SRC_VPNMNG,reconnect_info->rlm_id,RHP_LOG_ID_EXEC_AUTO_RECONNECT_ERR,"IdE",(reconnect_info ? &(reconnect_info->peer_id) : NULL),reconnect_info->retries,err);
	}

	_rhp_vpn_auto_reconnect_free(reconnect_info);

  RHP_TRC(0,RHPTRCID_VPN_AUTO_RECONNECT_HANDLER_ERR,"xE",reconnect_info,err);
	return;
}

int rhp_vpn_start_reconnect(rhp_vpn* vpn)
{
	int err = -EINVAL;

  RHP_TRC(0,RHPTRCID_VPN_START_RECONNECT,"xddx",vpn,vpn->auto_reconnect,vpn->exec_auto_reconnect,vpn->reconnect_info);

	if( vpn->auto_reconnect &&
			vpn->exec_auto_reconnect &&
			vpn->reconnect_info ){

		if( vpn->auto_reconnect_retries < rhp_gcfg_vpn_auto_reconnect_max_retries ){

			rhp_vpn_sess_resume_material* material_i = vpn->sess_resume_get_material_i(vpn);

	    RHP_TRC(0,RHPTRCID_VPN_START_RECONNECT_TIMER_SCHEDULE_AUTO_RECONNECT,"xux",vpn,rhp_gcfg_vpn_auto_reconnect_interval_2,material_i);

	    if( vpn->sess_resume.exec_sess_resume &&
	    		material_i ){

	    	vpn->reconnect_info->sess_resume_material_i = material_i;

	    	vpn->sess_resume.exec_sess_resume = 0;
	    	vpn->sess_resume_set_material_i(vpn,NULL);
	    }

			vpn->reconnect_info->retries = ++vpn->auto_reconnect_retries;

			if( rhp_timer_oneshot(_rhp_vpn_auto_reconnect_handler,
					(void*)vpn->reconnect_info,rhp_gcfg_vpn_auto_reconnect_interval_2) ){

				RHP_BUG("");

			}else{

				vpn->reconnect_info = NULL;
				err = 0;
			}

		}else{

	  	RHP_LOG_W(RHP_LOG_SRC_VPNMNG,vpn->vpn_realm_id,RHP_LOG_ID_AUTO_RECONNECT_CANCELED,"d",vpn->auto_reconnect_retries);

	    RHP_TRC(0,RHPTRCID_VPN_START_RECONNECT_CANCEL_AUTO_RECONNECT,"xuu",vpn,vpn->auto_reconnect_retries,rhp_gcfg_vpn_auto_reconnect_max_retries);
	    vpn->exec_auto_reconnect = 0;

	    err = -ETIMEDOUT;
		}

	}else{

		err = 0; // Ignored...
	}

  RHP_TRC(0,RHPTRCID_VPN_START_RECONNECT_RTRN,"xE",vpn,err);
	return err;
}

void _rhp_ikesa_lifetime_timer(void *ctx,rhp_timer *timer)
{
  int err = 0;
  rhp_vpn_ref* vpn_ref = ((rhp_ikesa_timer_ctx*)ctx)->vpn_ref;
  rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);
  rhp_vpn_realm* rlm = NULL;
  rhp_ikesa* ikesa = NULL;
  int my_side = ((rhp_ikesa_timer_ctx*)ctx)->my_side;
  u8* my_spi = ((rhp_ikesa_timer_ctx*)ctx)->my_spi;
  rhp_ikev2_payload* d_ikepayload = NULL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  int tx_handler_type = -1;

  RHP_TRC(0,RHPTRCID_IKESA_LIFETIME_TIMER,"xxxLdG",vpn,vpn_ref,timer,"IKE_SIDE",my_side,my_spi);

  RHP_LOCK(&(vpn->lock));

  RHP_TRC(0,RHPTRCID_IKESA_LIFETIME_TIMER_VPN,"xpuxdd",vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm,vpn->ikesa_num,vpn->childsa_num);
  rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
  rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));
  rhp_ip_addr_dump("vpn->peer_addr",&(vpn->peer_addr));
  rhp_if_entry_dump("vpn->local.if_info",&(vpn->local.if_info));


  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKESA_LIFETIME_TIMER_VPN_NOT_ACTIVE,"xx",vpn,timer);
    goto error_1;
  }


  ikesa = vpn->ikesa_get(vpn,((rhp_ikesa_timer_ctx*)ctx)->my_side,((rhp_ikesa_timer_ctx*)ctx)->my_spi);
  if( ikesa == NULL ){
    RHP_TRC(0,RHPTRCID_IKESA_LIFETIME_TIMER_NO_IKESA,"xxx",vpn,timer,vpn->rlm);
    goto error;
  }


  rlm = vpn->rlm;
  if( rlm == NULL ){
    RHP_TRC(0,RHPTRCID_IKESA_LIFETIME_TIMER_NO_RLM,"xx",vpn,timer);
    RHP_UNLOCK(&(vpn->lock));
    goto error_1;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKESA_LIFETIME_TIMER_RLM_NOT_ACTIVE,"xxx",vpn,timer,rlm);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKESA_LIFETIMER_TIMER_IKESA,"xxLddddd",vpn,ikesa,"IKESA_STAT",ikesa->state,rlm->ikesa.resp_not_rekeying,rlm->ikesa.lifetime_soft,rlm->ikesa.lifetime_hard,rlm->ikesa.delete_no_childsa);


  if( _rhp_ikesa_negotiating(ikesa) ){

    RHP_TRC(0,RHPTRCID_IKESA_LIFETIME_TIMER_NEGOTIATION_TIMEOUT,"xxx",vpn,rlm,ikesa);
	  goto error;


  }else if( ikesa->state == RHP_IKESA_STAT_ESTABLISHED ){

  	if( rlm->ikesa.delete_no_childsa && vpn->childsa_num == 0 ){

  		RHP_TRC(0,RHPTRCID_IKESA_LIFETIME_TIMER_CLEANUP_1,"xxxd",vpn,rlm,ikesa,vpn->childsa_num);

  		goto delete;

  	}else{

  		time_t diff;
  		int pending = 0;

      RHP_TRC(0,RHPTRCID_IKESA_LIFETIME_TIMER_EXEC_REKEY,"xxxdd",vpn,rlm,ikesa,vpn->ikesa_req_rekeying,vpn->childsa_req_rekeying);

      if( vpn->childsa_req_rekeying ||
      		rhp_ikev2_mobike_pending(vpn) ){

      	pending = 1;

      }else if( rhp_ikev2_mobike_ka_pending(vpn) ){

      	time_t now = _rhp_get_time();

    		// When MOBIKE is enabled, resonpder's keepalive may take longer.
      	if( ikesa->expire_hard <= now ){
          RHP_TRC(0,RHPTRCID_IKESA_LIFETIME_TIMER_EXEC_REKEY_WAIT_KEEPALIVE_PEND_TIMEOUT,"xxx",vpn,rlm,ikesa);
          goto delete_wait;
      	}

      	pending = 1;

      	RHP_TRC(0,RHPTRCID_IKESA_LIFETIME_TIMER_EXEC_REKEY_WAIT_KEEPALIVE_PEND,"xxx",vpn,rlm,ikesa);
      }

      if( pending ){

      	diff = _rhp_vpn_lifetime_random_impl(RHP_CFG_LIFETIME_DEFERRED_REKEY,
      					RHP_CFG_LIFETIME_DEFERRED_REKEY_RANDOM_RANGE);

      	rhp_timer_reset(&(ikesa->timers->lifetime_timer));
      	rhp_timer_add(&(ikesa->timers->lifetime_timer),diff);

        RHP_TRC(0,RHPTRCID_IKESA_LIFETIME_TIMER_EXEC_REKEY_WAIT_REKEYING,"xxxdddd",vpn,rlm,ikesa,vpn->ikesa_req_rekeying,vpn->childsa_req_rekeying,vpn->exec_mobike,vpn->mobike.resp.rt_ck_pending);
      	goto wait_rekeying;

      }else if( vpn->ikesa_req_rekeying ){

      	RHP_BUG("");
      }


   		if( ikesa->side == RHP_IKE_INITIATOR ||
   				(ikesa->side == RHP_IKE_RESPONDER && !rlm->ikesa.resp_not_rekeying) ){

   			err = rhp_ikev2_rekey_create_ikesa(vpn,rlm,ikesa,&tx_ikemesg);
   			if( err ){
   				RHP_TRC(0,RHPTRCID_IKESA_LIFETIME_MK_REKEY_ERR,"xxxE",vpn,rlm,ikesa,err);
   				goto error;
   			}

   			vpn->ikesa_req_rekeying = 1;

   			tx_handler_type = RHP_IKEV2_MESG_HANDLER_REKEY;
   		}

      rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_REKEYING);

     	diff = rlm->ikesa.lifetime_hard - rlm->ikesa.lifetime_soft;
     	diff = rhp_vpn_lifetime_random(diff);

     	rhp_timer_reset(&(ikesa->timers->lifetime_timer));
     	rhp_timer_add(&(ikesa->timers->lifetime_timer),diff);

    	ikesa->expire_hard = _rhp_get_time() + diff;
  	}

  	ikesa->expire_soft = 0;


  }else if( ikesa->state == RHP_IKESA_STAT_REKEYING ){

  	RHP_TRC(0,RHPTRCID_IKESA_LIFETIME_TIMER_REKEY_TIMEOUT,"xxx",vpn,rlm,ikesa);

  	goto delete;


  }else if( ikesa->state == RHP_IKESA_STAT_DELETE ){

delete:
		RHP_TRC(0,RHPTRCID_IKESA_LIFETIME_TIMER_CLEARNUP_IKESA,"xxx",vpn,rlm,ikesa);

		tx_ikemesg = rhp_ikev2_new_mesg_tx(RHP_PROTO_IKE_EXCHG_INFORMATIONAL,0,0);
		if( tx_ikemesg == NULL ){
 		  err = -ENOMEM;
 	    RHP_BUG("");
 	    goto error;
 	  }

		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_D,&d_ikepayload) ){
				RHP_BUG("");
				rhp_ikev2_unhold_mesg(tx_ikemesg);
				tx_ikemesg = NULL;
				goto error;
			}

		tx_ikemesg->put_payload(tx_ikemesg,d_ikepayload);

		d_ikepayload->ext.d->set_protocol_id(d_ikepayload,RHP_PROTO_IKE_PROTOID_IKE);

		tx_handler_type = RHP_IKEV2_MESG_HANDLER_DELETE_SA;

		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);

		rhp_timer_reset(&(ikesa->timers->lifetime_timer));

		{
			time_t del_wait = (time_t)rlm->ikesa.lifetime_deleted;

			if( vpn->ikesa_num == 1 ){

				if( vpn->auto_reconnect ){
					del_wait = rhp_gcfg_vpn_auto_reconnect_interval_1;
				}
			}

			rhp_timer_add(&(ikesa->timers->lifetime_timer),del_wait);

			ikesa->expire_soft = 0;
			ikesa->expire_hard = _rhp_get_time() + del_wait;
		}


  }else if( ikesa->state == RHP_IKESA_STAT_DELETE_WAIT ){

delete_wait:
    RHP_TRC(0,RHPTRCID_IKESA_LIFETIME_TIMER_CLEANUP_2,"xxx",vpn,rlm,ikesa);

    ikesa->expire_soft = 0;
		ikesa->expire_hard = 0;

    goto cleanup;


  }else{
    RHP_TRC(0,RHPTRCID_IKESA_LIFETIME_TIMER_UNKNOWN_STATE,"xxxd",vpn,rlm,ikesa,ikesa->state);
    goto error;
  }


wait_rekeying:

  RHP_UNLOCK(&(rlm->lock));

  if( tx_ikemesg ){
    rhp_ikev2_send_request(vpn,ikesa,tx_ikemesg,tx_handler_type);
    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }

  RHP_UNLOCK(&(vpn->lock));

  RHP_TRC(0,RHPTRCID_IKESA_LIFETIME_TIMER_RTRN,"xxxx",vpn,vpn_ref,rlm,ikesa);
  return;

cleanup:
error:
  RHP_UNLOCK(&(rlm->lock));
error_1:

	{
		vpn->deleting = 0;

		if( vpn->connecting ){
			vpn->connecting = 0;
			rhp_ikesa_half_open_sessions_dec();
		}
	}

  if( ikesa ){
    rhp_ikesa_destroy(vpn,ikesa);
    // Don't touch ikesa anymore!
  }

  if( vpn->ikesa_num == 0 || // This is the last IKE SA...
  		ikesa == NULL ){ // IKESA was not really established or some errors occurred???

    RHP_TRC(0,RHPTRCID_IKESA_LIFETIME_TIMER_AUTO_RECONNECT_INFO,"xxxdduux",vpn,rlm,ikesa,vpn->auto_reconnect,vpn->exec_auto_reconnect,vpn->auto_reconnect_retries,rhp_gcfg_vpn_auto_reconnect_max_retries,vpn->reconnect_info);

    err = rhp_vpn_start_reconnect(vpn);
    if( err ){
      RHP_TRC(0,RHPTRCID_IKESA_LIFETIME_TIMER_START_RECONNECT_ERR,"xxE",vpn,vpn_ref,err);
    }
    err = 0;

  	rhp_vpn_destroy(vpn);
  }

  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

  if( tx_ikemesg ){
    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }

  _rhp_free(ctx);

  RHP_TRC(0,RHPTRCID_IKESA_LIFETIME_TIMER_ERR,"xxx",vpn,vpn_ref,timer);
  return;
}

static void _rhp_ikesa_v1_lifetime_timer(void *ctx,rhp_timer *timer)
{
  int err = 0;
  rhp_vpn_ref* vpn_ref = ((rhp_ikesa_timer_ctx*)ctx)->vpn_ref;
  rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);
  rhp_vpn_realm* rlm = NULL;
  rhp_ikesa* ikesa = NULL, *tx_ikesa = NULL;
  int my_side = ((rhp_ikesa_timer_ctx*)ctx)->my_side;
  u8* my_spi = ((rhp_ikesa_timer_ctx*)ctx)->my_spi;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  int tx_handler_type = -1;

  RHP_TRC(0,RHPTRCID_IKESA_V1_LIFETIME_TIMER,"xxxLdG",vpn,vpn_ref,timer,"IKE_SIDE",my_side,my_spi);

  RHP_LOCK(&(vpn->lock));

  RHP_TRC(0,RHPTRCID_IKESA_V1_LIFETIME_TIMER_VPN,"xpuxdd",vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm,vpn->ikesa_num,vpn->childsa_num);
  rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
  rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));
  rhp_ip_addr_dump("vpn->peer_addr",&(vpn->peer_addr));
  rhp_if_entry_dump("vpn->local.if_info",&(vpn->local.if_info));


  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKESA_V1_LIFETIME_TIMER_VPN_NOT_ACTIVE,"xx",vpn,timer);
    goto error_1;
  }


  ikesa = vpn->ikesa_get(vpn,((rhp_ikesa_timer_ctx*)ctx)->my_side,((rhp_ikesa_timer_ctx*)ctx)->my_spi);
  if( ikesa == NULL ){
    RHP_TRC(0,RHPTRCID_IKESA_V1_LIFETIME_TIMER_NO_IKESA,"xxx",vpn,timer,vpn->rlm);
    goto error;
  }
  tx_ikesa = ikesa;


  rlm = vpn->rlm;
  if( rlm == NULL ){
    RHP_TRC(0,RHPTRCID_IKESA_V1_LIFETIME_TIMER_NO_RLM,"xx",vpn,timer);
    RHP_UNLOCK(&(vpn->lock));
    goto error_1;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKESA_V1_LIFETIME_TIMER_RLM_NOT_ACTIVE,"xxx",vpn,timer,rlm);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKESA_LIFETIMER_TIMER_IKESA,"xxLddddddd",vpn,ikesa,"IKESA_STAT",ikesa->state,rlm->ikesa.resp_not_rekeying,rlm->ikesa.lifetime_soft,rlm->ikesa.lifetime_hard,rlm->ikesa.delete_no_childsa,ikesa->v1.dont_rekey,ikesa->prop.v1.xauth_method);

  if( _rhp_ikesa_negotiating(ikesa) ){

    RHP_TRC(0,RHPTRCID_IKESA_V1_LIFETIME_TIMER_NEGOTIATION_TIMEOUT,"xxx",vpn,rlm,ikesa);
	  goto error;


  }else if( ikesa->state == RHP_IKESA_STAT_V1_ESTABLISHED ){

  	if( rlm->ikesa.delete_no_childsa && vpn->childsa_num == 0 ){

  		RHP_TRC(0,RHPTRCID_IKESA_V1_LIFETIME_TIMER_CLEANUP_1,"xxxd",vpn,rlm,ikesa,vpn->childsa_num);

  		goto delete;

  	}else{

  		time_t diff;

      RHP_TRC(0,RHPTRCID_IKESA_V1_LIFETIME_TIMER_EXEC_REKEY,"xxxdd",vpn,rlm,ikesa,vpn->ikesa_req_rekeying,vpn->childsa_req_rekeying);

      if( vpn->ikesa_req_rekeying ){
      	RHP_BUG("");
      }


      if( !ikesa->v1.dont_rekey ){

      	if( ikesa->side == RHP_IKE_INITIATOR ||
						(ikesa->side == RHP_IKE_RESPONDER && !rlm->ikesa.resp_not_rekeying) ){

					err = rhp_ikev1_rekey_create_ikesa(vpn,rlm,ikesa,&tx_ikesa,&tx_ikemesg);
					if( err ){
						RHP_TRC(0,RHPTRCID_IKESA_LIFETIME_MK_REKEY_ERR,"xxxE",vpn,rlm,ikesa,err);
						goto error;
					}

					tx_handler_type = RHP_IKEV1_MESG_HANDLER_P1_MAIN;

					vpn->ikesa_req_rekeying = 1;

					if( ikesa->v1.p1_exchange_mode == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ){
						tx_handler_type = RHP_IKEV1_MESG_HANDLER_P1_MAIN;
					}else if( ikesa->v1.p1_exchange_mode == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){
						tx_handler_type = RHP_IKEV1_MESG_HANDLER_P1_AGGRESSIVE;
					}else{
						err = -EINVAL;
						RHP_BUG("");
						goto error;
					}
				}
      }

      rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_REKEYING);

     	diff = rlm->ikesa.lifetime_hard - rlm->ikesa.lifetime_soft;
     	diff = rhp_vpn_lifetime_random(diff);

     	rhp_timer_reset(&(ikesa->timers->lifetime_timer));
     	rhp_timer_add(&(ikesa->timers->lifetime_timer),diff);

    	ikesa->expire_hard = _rhp_get_time() + diff;
  	}

  	ikesa->expire_soft = 0;


  }else if( ikesa->state == RHP_IKESA_STAT_V1_REKEYING ){

  	RHP_TRC(0,RHPTRCID_IKESA_V1_LIFETIME_TIMER_REKEY_TIMEOUT,"xxx",vpn,rlm,ikesa);

  	goto delete;


  }else if( ikesa->state == RHP_IKESA_STAT_V1_DELETE ){

delete:
		RHP_TRC(0,RHPTRCID_IKESA_V1_LIFETIME_TIMER_CLEARNUP_IKESA,"xxx",vpn,rlm,ikesa);


		tx_ikemesg = rhp_ikev1_new_pkt_delete_ikesa(vpn,ikesa);
		if( tx_ikemesg == NULL ){
			err = -EINVAL;
			goto error;
		}


		tx_handler_type = RHP_IKEV1_MESG_HANDLER_DELETE_SA;

		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_DELETE_WAIT);

		rhp_timer_reset(&(ikesa->timers->lifetime_timer));

		{
			time_t del_wait = (time_t)rlm->v1.ikesa_lifetime_deleted;

			if( vpn->ikesa_num == 1 ){

				if( vpn->auto_reconnect ){

					del_wait = rhp_gcfg_vpn_auto_reconnect_interval_1;
				}
			}

			rhp_timer_add(&(ikesa->timers->lifetime_timer),del_wait);

			ikesa->expire_soft = 0;
			ikesa->expire_hard = _rhp_get_time() + del_wait;
		}


  }else if( ikesa->state == RHP_IKESA_STAT_V1_DELETE_WAIT ){

    RHP_TRC(0,RHPTRCID_IKESA_V1_LIFETIME_TIMER_CLEANUP_2,"xxx",vpn,rlm,ikesa);

    ikesa->expire_soft = 0;
		ikesa->expire_hard = 0;

    goto cleanup;


  }else{
    RHP_TRC(0,RHPTRCID_IKESA_V1_LIFETIME_TIMER_UNKNOWN_STATE,"xxxd",vpn,rlm,ikesa,ikesa->state);
    goto error;
  }

  RHP_UNLOCK(&(rlm->lock));


  if( tx_ikemesg ){

  	// Don't acquire rlm->lock.
    rhp_ikev1_send_mesg(vpn,tx_ikesa,tx_ikemesg,tx_handler_type);
    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }

  RHP_UNLOCK(&(vpn->lock));

  RHP_TRC(0,RHPTRCID_IKESA_V1_LIFETIME_TIMER_RTRN,"xxxx",vpn,vpn_ref,rlm,ikesa);
  return;

cleanup:
error:
  RHP_UNLOCK(&(rlm->lock));
error_1:

	{
		vpn->deleting = 0;

		if( vpn->connecting ){
			vpn->connecting = 0;
			rhp_ikesa_half_open_sessions_dec();
		}
	}

  if( ikesa ){

  	//
    // Don't touch ikesa anymore!
  	//

  	rhp_ikesa_destroy(vpn,ikesa);
  }


  //
  // [TODO] IKEv1: If IPsec SA is still exists, we should not destroy this vpn?
  //
  if( vpn->ikesa_num == 0 || // This is the last IKE SA...
  		ikesa == NULL ){ // IKESA was not really established or some errors occurred???

    RHP_TRC(0,RHPTRCID_IKESA_V1_LIFETIME_TIMER_AUTO_RECONNECT_INFO,"xxxdduux",vpn,rlm,ikesa,vpn->auto_reconnect,vpn->exec_auto_reconnect,vpn->auto_reconnect_retries,rhp_gcfg_vpn_auto_reconnect_max_retries,vpn->reconnect_info);

    err = rhp_vpn_start_reconnect(vpn);
    if( err ){
      RHP_TRC(0,RHPTRCID_IKESA_V1_LIFETIME_TIMER_START_RECONNECT_ERR,"xxE",vpn,vpn_ref,err);
    }
    err = 0;

  	rhp_vpn_destroy(vpn);
  }

  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

  if( tx_ikemesg ){
    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }

  _rhp_free(ctx);

  RHP_TRC(0,RHPTRCID_IKESA_V1_LIFETIME_TIMER_ERR,"xxxxx",vpn,vpn_ref,ikesa,rlm,timer);
  return;
}

static int _rhp_ikesa_start_keep_alive_timer(rhp_vpn* vpn,rhp_ikesa* ikesa,time_t interval)
{
  rhp_ikesa_timer_ctx* ctx;

  RHP_TRC(0,RHPTRCID_IKESA_START_KEEP_ALIVE_TIMER,"xxLdGGxdLdd",vpn,ikesa,"IKE_SIDE",ikesa->side,ikesa->init_spi,ikesa->resp_spi,ikesa->timers,interval,"IKESA_STAT",ikesa->state,vpn->is_v1);

  if( rhp_timer_pending(&(ikesa->timers->keep_alive_timer)) ){
    RHP_TRC(0,RHPTRCID_IKESA_START_KEEP_ALIVE_TIMER_PENDING,"xxxx",vpn,ikesa,ikesa->timers,&(ikesa->timers->keep_alive_timer));
    return 0;
  }

  ctx = (rhp_ikesa_timer_ctx*)_rhp_malloc(sizeof(rhp_ikesa_timer_ctx));
  if( ctx == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }
  memset(ctx,0,sizeof(rhp_ikesa_timer_ctx));

  ctx->vpn_ref = rhp_vpn_hold_ref(vpn);

  ctx->my_side = ikesa->side;
  if( ikesa->side == RHP_IKE_INITIATOR ){
    memcpy(ctx->my_spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
  }else{
    memcpy(ctx->my_spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
  }

  ikesa->timers->keep_alive_timer.ctx = (void*)ctx;

  if( vpn->is_v1 ){
  	ikesa->v1.keep_alive_interval = interval;
  }

  rhp_timer_reset(&(ikesa->timers->keep_alive_timer));
  rhp_timer_add(&(ikesa->timers->keep_alive_timer),_rhp_ikesa_keep_alive_random(interval));

  RHP_TRC(0,RHPTRCID_IKESA_START_KEEP_ALIVE_TIMER_RTRN,"xxxx",vpn,ikesa,ikesa->timers,ctx);
  return 0;
}

static int _rhp_ikesa_quit_keep_alive_timer(rhp_vpn* vpn,rhp_ikesa* ikesa)
{
  RHP_TRC(0,RHPTRCID_IKESA_QUIT_KEEP_ALIVE_TIMER,"xxLdGGxLd",vpn,ikesa,"IKE_SIDE",ikesa->side,ikesa->init_spi,ikesa->resp_spi,ikesa->timers,"IKESA_STAT",ikesa->state);

	if( rhp_timer_delete(&(ikesa->timers->keep_alive_timer)) ){
	  RHP_TRC(0,RHPTRCID_IKESA_QUIT_KEEP_ALIVE_TIMER_NOT_ACTIVE,"xxxx",vpn,ikesa,ikesa->timers,&(ikesa->timers->keep_alive_timer));
	  return -1;
  }

  rhp_vpn_unhold(((rhp_ikesa_timer_ctx*)(ikesa->timers->keep_alive_timer.ctx))->vpn_ref);
  _rhp_free(ikesa->timers->keep_alive_timer.ctx);
  ikesa->timers->keep_alive_timer.ctx = NULL;

  RHP_TRC(0,RHPTRCID_IKESA_QUIT_KEEP_ALIVE_TIMER_RTRN,"xxx",vpn,ikesa,ikesa->timers);
  return 0;
}


static void _rhp_vpn_keep_alive_req_completed(rhp_vpn* vpn,rhp_ikesa* tx_ikesa,
		rhp_ikev2_mesg* ikemesg,rhp_packet* serialized_pkt)
{
	u32 mesg_id = ikemesg->get_mesg_id(ikemesg);

  RHP_TRC(0,RHPTRCID_IKESA_KEEP_ALIVE_REQ_COMPLETED,"xxxux",vpn,tx_ikesa,ikemesg,mesg_id,serialized_pkt);
	tx_ikesa->keep_alive.req_mesg_id = mesg_id;

	return;
}

void _rhp_ikesa_keep_alive_timer(void *ctx,rhp_timer *timer)
{
	rhp_vpn_ref* vpn_ref = ((rhp_ikesa_timer_ctx*)ctx)->vpn_ref;
  rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);
  rhp_vpn_realm* rlm = NULL;
  rhp_ikesa* ikesa = NULL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  int my_side = ((rhp_ikesa_timer_ctx*)ctx)->my_side;
  u8* my_spi = ((rhp_ikesa_timer_ctx*)ctx)->my_spi;

  RHP_TRC(0,RHPTRCID_IKESA_KEEP_ALIVE_TIMER,"xxxLdG",vpn,vpn_ref,timer,"IKE_SIDE",my_side,my_spi);

  RHP_LOCK(&(vpn->lock));

  RHP_TRC(0,RHPTRCID_IKESA_KEEP_ALIVE_TIMER_VPN,"xpuxdd",vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm,vpn->ikesa_num,vpn->childsa_num);
  rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
  rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));


  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKESA_KEEP_ALIVE_TIMER_VPN_NOT_ACTIVE,"xx",vpn,timer);
    goto error_1;
  }

  rlm = vpn->rlm;

  if( rlm == NULL ){
    RHP_TRC(0,RHPTRCID_IKESA_KEEP_ALIVE_TIMER_NO_RLM,"xx",vpn,timer);
    RHP_UNLOCK(&(vpn->lock));
    goto error_1;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKESA_KEEP_ALIVE_TIMER_RLM_NOT_ACTIVE,"xx",vpn,timer);
    goto error;
  }

  ikesa = vpn->ikesa_get(vpn,((rhp_ikesa_timer_ctx*)ctx)->my_side,((rhp_ikesa_timer_ctx*)ctx)->my_spi);
  if( ikesa == NULL ){
    RHP_TRC(0,RHPTRCID_IKESA_KEEP_ALIVE_TIMER_NO_IKESA,"xxx",vpn,timer,rlm);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKESA_KEEP_ALIVE_TIMER_IKESA,"xxLd",vpn,ikesa,"IKESA_STAT",ikesa->state);
  rhp_ip_addr_dump("vpn->peer_addr",&(vpn->peer_addr));
  rhp_if_entry_dump("vpn->local.if_info",&(vpn->local.if_info));


  if( ikesa->state == RHP_IKESA_STAT_ESTABLISHED ||
  		ikesa->state == RHP_IKESA_STAT_REKEYING ){

  	RHP_TRC(0,RHPTRCID_IKESA_KEEP_ALIVE_TIMER_EXEC_KEEPALIVE,"xxxxdqqqqq",vpn,rlm,ikesa,ikesa->req_retx_pkt,ikesa->timers->keep_alive_forced,ikesa->timers->last_rx_esp_packets,vpn->statistics.rx_esp_packets,ikesa->timers->last_rx_encrypted_packets,ikesa->statistics.rx_encrypted_packets,ikesa->statistics.rx_keep_alive_reply_packets);

  	u64 rx_enc_pkts
  		= ikesa->statistics.rx_encrypted_packets - ikesa->statistics.rx_keep_alive_reply_packets;

  	if( ikesa->req_retx_pkt ){

  		// Now some request packets are on the fly!
  		RHP_TRC(0,RHPTRCID_IKESA_KEEP_ALIVE_TIMER_NOT_TX_KEEPALIVE_SOME_REQ_ON_THE_FLY,"xxx",vpn,rlm,ikesa);

  	}else if( rhp_ikev2_mobike_pending(vpn) ){

  		RHP_TRC(0,RHPTRCID_IKESA_KEEP_ALIVE_TIMER_NOT_TX_KEEPALIVE_MOBIKE_RT_CK_PEND,"xxx",vpn,rlm,ikesa);

  	}else if( rhp_gcfg_always_exec_keep_alive														||
  			      ikesa->timers->keep_alive_forced 													||
  						!ikesa->timers->last_rx_encrypted_packets 								||
  					  (ikesa->timers->last_rx_encrypted_packets == rx_enc_pkts) ||
  						( vpn->exec_mobike && (vpn->origin_side == RHP_IKE_INITIATOR) && vpn->nat_t_info.exec_nat_t ) ){

  		tx_ikemesg = rhp_ikev2_new_mesg_tx(RHP_PROTO_IKE_EXCHG_INFORMATIONAL,0,0);
  		if( tx_ikemesg == NULL ){
  			RHP_BUG("");
  			goto error;
			}

  		tx_ikemesg->packet_serialized = _rhp_vpn_keep_alive_req_completed;

  		tx_ikemesg->tx_flag = RHP_IKEV2_SEND_REQ_FLAG_BUSY_SKIP;
  		tx_ikemesg->activated++;

  		tx_ikemesg->ikev2_keep_alive = 1;

  		if( vpn->exec_mobike && vpn->origin_side == RHP_IKE_INITIATOR ){
  			tx_ikemesg->add_nat_t_info = 1;
  		}

  	}else{
  		RHP_TRC(0,RHPTRCID_IKESA_KEEP_ALIVE_TIMER_NOT_TX_KEEPALIVE,"xxx",vpn,rlm,ikesa);
    }

  	ikesa->timers->last_rx_esp_packets = vpn->statistics.rx_esp_packets; // [TODO] Watching Rx ESP pkts.
  	ikesa->timers->last_rx_encrypted_packets = rx_enc_pkts;

    rhp_timer_reset(&(ikesa->timers->keep_alive_timer));
    rhp_timer_add(&(ikesa->timers->keep_alive_timer),_rhp_ikesa_keep_alive_random(rlm->ikesa.keep_alive_interval));

  }else if( ikesa->state == RHP_IKESA_STAT_DELETE ||
  					ikesa->state == RHP_IKESA_STAT_DELETE_WAIT ){

		RHP_TRC(0,RHPTRCID_IKESA_KEEP_ALIVE_TIMER_CLEANUP,"xxx",vpn,rlm,ikesa);
		goto cleanup;

  }else{
    RHP_BUG("%d",ikesa->state);
    goto error;
  }

  ikesa->timers->keep_alive_forced = 0;

  RHP_UNLOCK(&(rlm->lock));

  if( tx_ikemesg ){

    rhp_ikev2_send_request(vpn,ikesa,tx_ikemesg,RHP_IKEV2_MESG_HANDLER_KEEP_ALIVE);
    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }

  RHP_UNLOCK(&(vpn->lock));

	RHP_TRC(0,RHPTRCID_IKESA_KEEP_ALIVE_TIMER_RTRN,"xxxxxx",vpn,vpn_ref,timer,rlm,ikesa);
	return;

cleanup:
error:
  RHP_UNLOCK(&(rlm->lock));
error_1:

  RHP_UNLOCK(&(vpn->lock));

  if( tx_ikemesg ){
    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }

  rhp_vpn_unhold(vpn_ref);
  _rhp_free(ctx);

	RHP_TRC(0,RHPTRCID_IKESA_KEEP_ALIVE_TIMER_IGNORE_ERR,"xxx",vpn,vpn_ref,timer);
	return;
}

static void _rhp_ikesa_v1_keep_alive_timer(void *ctx,rhp_timer *timer)
{
	rhp_vpn_ref* vpn_ref = ((rhp_ikesa_timer_ctx*)ctx)->vpn_ref;
  rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);
  rhp_vpn_realm* rlm = NULL;
  rhp_ikesa* ikesa = NULL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  int my_side = ((rhp_ikesa_timer_ctx*)ctx)->my_side;
  u8* my_spi = ((rhp_ikesa_timer_ctx*)ctx)->my_spi;

  RHP_TRC(0,RHPTRCID_IKESA_V1_KEEP_ALIVE_TIMER,"xxxLdG",vpn,vpn_ref,timer,"IKE_SIDE",my_side,my_spi);

  RHP_LOCK(&(vpn->lock));

  RHP_TRC(0,RHPTRCID_IKESA_V1_KEEP_ALIVE_TIMER_VPN,"xpuxdd",vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm,vpn->ikesa_num,vpn->childsa_num);
  rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
  rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));


  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKESA_V1_KEEP_ALIVE_TIMER_VPN_NOT_ACTIVE,"xx",vpn,timer);
    goto error_1;
  }

  rlm = vpn->rlm;

  if( rlm == NULL ){
    RHP_TRC(0,RHPTRCID_IKESA_V1_KEEP_ALIVE_TIMER_NO_RLM,"xx",vpn,timer);
    RHP_UNLOCK(&(vpn->lock));
    goto error_1;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKESA_V1_KEEP_ALIVE_TIMER_RLM_NOT_ACTIVE,"xx",vpn,timer);
    goto error;
  }

  ikesa = vpn->ikesa_get(vpn,((rhp_ikesa_timer_ctx*)ctx)->my_side,((rhp_ikesa_timer_ctx*)ctx)->my_spi);
  if( ikesa == NULL ){
    RHP_TRC(0,RHPTRCID_IKESA_V1_KEEP_ALIVE_TIMER_NO_IKESA,"xxx",vpn,timer,rlm);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKESA_V1_KEEP_ALIVE_TIMER_IKESA,"xxLd",vpn,ikesa,"IKESA_STAT",ikesa->state);
  rhp_ip_addr_dump("vpn->peer_addr",&(vpn->peer_addr));
  rhp_if_entry_dump("vpn->local.if_info",&(vpn->local.if_info));


  if( ikesa->state == RHP_IKESA_STAT_V1_ESTABLISHED ||
  		ikesa->state == RHP_IKESA_STAT_V1_REKEYING ){

  	RHP_TRC(0,RHPTRCID_IKESA_V1_KEEP_ALIVE_TIMER_EXEC_KEEPALIVE,"xxxxdqqqqq",vpn,rlm,ikesa,ikesa->req_retx_pkt,ikesa->timers->keep_alive_forced,ikesa->timers->last_rx_esp_packets,vpn->statistics.rx_esp_packets,ikesa->timers->last_rx_encrypted_packets,ikesa->statistics.rx_encrypted_packets,ikesa->statistics.rx_keep_alive_reply_packets);

  	u64 rx_enc_pkts
  		= ikesa->statistics.rx_encrypted_packets - ikesa->statistics.rx_keep_alive_reply_packets;

  	if( ikesa->v1.p2_sessions ){

  		// Now some request packets are on the fly!
  		RHP_TRC(0,RHPTRCID_IKESA_V1_KEEP_ALIVE_TIMER_NOT_TX_KEEPALIVE_SOME_REQ_ON_THE_FLY,"xxxx",vpn,rlm,ikesa,ikesa->v1.p2_sessions);

  	}else if( rhp_gcfg_always_exec_keep_alive														||
  			      ikesa->timers->keep_alive_forced 													||
  						!ikesa->timers->last_rx_encrypted_packets 								||
  					  (ikesa->timers->last_rx_encrypted_packets == rx_enc_pkts) ){

  		u32 dpd_seq;

  		tx_ikemesg = rhp_ikev1_new_pkt_dpd_r_u_there(vpn,ikesa,&dpd_seq);
  		if( tx_ikemesg == NULL ){
  			RHP_BUG("");
  			goto error;
			}

  		tx_ikemesg->packet_serialized = _rhp_vpn_keep_alive_req_completed;

  	  tx_ikemesg->v1_start_retx_timer = 1;


  	  //
  	  // A DPD's R_U_THERE_ACK's mesg ID (INFORMATIONAL exchange) may not be
  		// the same one and so a DPD's seq ID is used instead.
  	  //

  	  rhp_ikev1_p2_session_tx_put(ikesa,
  	  		tx_ikemesg->get_mesg_id(tx_ikemesg),tx_ikemesg->get_exchange_type(tx_ikemesg),dpd_seq,0);

  	}else{
  		RHP_TRC(0,RHPTRCID_IKESA_V1_KEEP_ALIVE_TIMER_NOT_TX_KEEPALIVE,"xxx",vpn,rlm,ikesa);
    }

  	ikesa->timers->last_rx_esp_packets = vpn->statistics.rx_esp_packets; // [TODO] Watching Rx ESP pkts.
  	ikesa->timers->last_rx_encrypted_packets = rx_enc_pkts;

    rhp_timer_reset(&(ikesa->timers->keep_alive_timer));
    rhp_timer_add(&(ikesa->timers->keep_alive_timer),_rhp_ikesa_keep_alive_random(rlm->ikesa.keep_alive_interval));

  }else if( ikesa->state == RHP_IKESA_STAT_V1_DELETE ||
  					ikesa->state == RHP_IKESA_STAT_V1_DELETE_WAIT ){

		RHP_TRC(0,RHPTRCID_IKESA_V1_KEEP_ALIVE_TIMER_CLEANUP,"xxx",vpn,rlm,ikesa);
		goto cleanup;

  }else{
    RHP_BUG("%d",ikesa->state);
    goto error;
  }

  ikesa->timers->keep_alive_forced = 0;

  RHP_UNLOCK(&(rlm->lock));

  if( tx_ikemesg ){

    rhp_ikev1_send_mesg(vpn,ikesa,tx_ikemesg,RHP_IKEV1_MESG_HANDLER_DPD);

  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_TX_IKEV1_DPD_R_U_THERE,"KVP",tx_ikemesg,vpn,ikesa);

    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }

  RHP_UNLOCK(&(vpn->lock));

	RHP_TRC(0,RHPTRCID_IKESA_V1_KEEP_ALIVE_TIMER_RTRN,"xxxxxx",vpn,vpn_ref,timer,rlm,ikesa);
	return;

cleanup:
error:
  RHP_UNLOCK(&(rlm->lock));
error_1:

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_TX_IKEV1_DPD_R_U_THERE_ERR,"VP",vpn,ikesa);

  RHP_UNLOCK(&(vpn->lock));

  if( tx_ikemesg ){
    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }

  rhp_vpn_unhold(vpn_ref);
  _rhp_free(ctx);

	RHP_TRC(0,RHPTRCID_IKESA_V1_KEEP_ALIVE_TIMER_IGNORE_ERR,"xxx",vpn,vpn_ref,timer);
	return;
}


static int _rhp_ikesa_start_nat_t_keep_alive_timer(rhp_vpn* vpn,rhp_ikesa* ikesa,time_t interval)
{
  rhp_ikesa_timer_ctx* ctx;

  RHP_TRC(0,RHPTRCID_IKESA_START_NAT_T_KEEP_ALIVE_TIMER,"xLdxLdGGxdLdddd",vpn,"IKE_SIDE",vpn->origin_side,ikesa,"IKE_SIDE",ikesa->side,ikesa->init_spi,ikesa->resp_spi,ikesa->timers,interval,"IKESA_STAT",ikesa->state,vpn->nat_t_info.exec_nat_t,vpn->nat_t_info.behind_a_nat,vpn->is_v1);

  if( !interval ||
  		!vpn->nat_t_info.exec_nat_t ||
  		!(vpn->nat_t_info.behind_a_nat & RHP_IKESA_BEHIND_A_NAT_LOCAL) ||
  		(vpn->origin_side != RHP_IKE_INITIATOR) ){
    RHP_TRC(0,RHPTRCID_IKESA_START_NAT_T_KEEP_ALIVE_TIMER_NAT_T_DISABLED,"xxxx",vpn,ikesa,ikesa->timers,&(ikesa->timers->nat_t_keep_alive_timer));
  	return 0;
  }

  if( rhp_timer_pending(&(ikesa->timers->nat_t_keep_alive_timer)) ){
    RHP_TRC(0,RHPTRCID_IKESA_START_NAT_T_KEEP_ALIVE_TIMER_PENDING,"xxxx",vpn,ikesa,ikesa->timers,&(ikesa->timers->nat_t_keep_alive_timer));
    return 0;
  }

  ctx = (rhp_ikesa_timer_ctx*)_rhp_malloc(sizeof(rhp_ikesa_timer_ctx));
  if( ctx == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }
  memset(ctx,0,sizeof(rhp_ikesa_timer_ctx));

  ctx->vpn_ref = rhp_vpn_hold_ref(vpn);

  ctx->my_side = ikesa->side;
  if( ikesa->side == RHP_IKE_INITIATOR ){
    memcpy(ctx->my_spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
  }else{
    memcpy(ctx->my_spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
  }

  ikesa->timers->nat_t_keep_alive_timer.ctx = (void*)ctx;

  if( vpn->is_v1 ){
  	ikesa->v1.nat_t_keep_alive_interval = interval;
  }

  rhp_timer_reset(&(ikesa->timers->nat_t_keep_alive_timer));
  rhp_timer_add(&(ikesa->timers->nat_t_keep_alive_timer),interval);

  RHP_TRC(0,RHPTRCID_IKESA_START_NAT_T_KEEP_ALIVE_TIMER_RTRN,"xxxx",vpn,ikesa,ikesa->timers,ctx);
  return 0;
}

static int _rhp_ikesa_quit_nat_t_keep_alive_timer(rhp_vpn* vpn,rhp_ikesa* ikesa)
{
  RHP_TRC(0,RHPTRCID_IKESA_QUIT_NAT_T_KEEP_ALIVE_TIMER,"xxLdGGxLd",vpn,ikesa,"IKE_SIDE",ikesa->side,ikesa->init_spi,ikesa->resp_spi,ikesa->timers,"IKESA_STAT",ikesa->state);

	if( rhp_timer_delete(&(ikesa->timers->nat_t_keep_alive_timer)) ){
	  RHP_TRC(0,RHPTRCID_IKESA_QUIT_NAT_T_KEEP_ALIVE_TIMER_NOT_ACTIVE,"xxxx",vpn,ikesa,ikesa->timers,&(ikesa->timers->nat_t_keep_alive_timer));
	  return -1;
  }

  rhp_vpn_unhold(((rhp_ikesa_timer_ctx*)(ikesa->timers->nat_t_keep_alive_timer.ctx))->vpn_ref);
  _rhp_free(ikesa->timers->nat_t_keep_alive_timer.ctx);
  ikesa->timers->nat_t_keep_alive_timer.ctx = NULL;

  RHP_TRC(0,RHPTRCID_IKESA_QUIT_NAT_T_KEEP_ALIVE_TIMER_RTRN,"xxx",vpn,ikesa,ikesa->timers);
  return 0;
}

static void _rhp_ikesa_nat_t_keep_alive_timer(void *ctx,rhp_timer *timer)
{
  rhp_vpn_ref* vpn_ref = ((rhp_ikesa_timer_ctx*)ctx)->vpn_ref;
  rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);
  rhp_vpn_realm* rlm = NULL;
  rhp_ikesa* ikesa = NULL;
  int my_side = ((rhp_ikesa_timer_ctx*)ctx)->my_side;
  u8* my_spi = ((rhp_ikesa_timer_ctx*)ctx)->my_spi;
  int tx_mesg = 0;

  RHP_TRC(0,RHPTRCID_IKESA_NAT_T_KEEP_ALIVE_TIMER,"xxxLdG",vpn,vpn_ref,timer,"IKE_SIDE",my_side,my_spi);

  RHP_LOCK(&(vpn->lock));

  RHP_TRC(0,RHPTRCID_IKESA_NAT_T_KEEP_ALIVE_TIMER_VPN,"xpuxdd",vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm,vpn->ikesa_num,vpn->childsa_num);
  rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
  rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));


  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKESA_NAT_T_KEEP_ALIVE_TIMER_VPN_NOT_ACTIVE,"xx",vpn,timer);
    goto error_1;
  }

  rlm = vpn->rlm;

  if( rlm == NULL ){
    RHP_TRC(0,RHPTRCID_IKESA_NAT_T_KEEP_ALIVE_TIMER_NO_RLM,"xx",vpn,timer);
    RHP_UNLOCK(&(vpn->lock));
    goto error_1;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKESA_NAT_T_KEEP_ALIVE_TIMER_RLM_NOT_ACTIVE,"xx",vpn,timer);
    goto error;
  }

  ikesa = vpn->ikesa_get(vpn,((rhp_ikesa_timer_ctx*)ctx)->my_side,((rhp_ikesa_timer_ctx*)ctx)->my_spi);
  if( ikesa == NULL ){
    RHP_TRC(0,RHPTRCID_IKESA_NAT_T_KEEP_ALIVE_TIMER_NO_IKESA,"xxx",vpn,timer,rlm);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKESA_NAT_T_KEEP_ALIVE_TIMER_IKESA,"xxLd",vpn,ikesa,"IKESA_STAT",ikesa->state);
  rhp_ip_addr_dump("vpn->peer_addr",&(vpn->peer_addr));
  rhp_if_entry_dump("vpn->local.if_info",&(vpn->local.if_info));


  if( ikesa->state == RHP_IKESA_STAT_ESTABLISHED 		||
  		ikesa->state == RHP_IKESA_STAT_REKEYING 			||
  		ikesa->state == RHP_IKESA_STAT_V1_ESTABLISHED ||
  		ikesa->state == RHP_IKESA_STAT_V1_REKEYING ){

  	RHP_TRC(0,RHPTRCID_IKESA_NAT_T_KEEP_ALIVE_TIMER_EXEC_KEEPALIVE,"xxx",vpn,rlm,ikesa);

  	tx_mesg = 1;

    rhp_timer_reset(&(ikesa->timers->nat_t_keep_alive_timer));
    rhp_timer_add(&(ikesa->timers->nat_t_keep_alive_timer),(time_t)rlm->ikesa.nat_t_keep_alive_interval);

  }else if( ikesa->state == RHP_IKESA_STAT_DELETE 			||
  					ikesa->state == RHP_IKESA_STAT_DELETE_WAIT 	||
  					ikesa->state == RHP_IKESA_STAT_V1_DELETE 		||
  					ikesa->state == RHP_IKESA_STAT_V1_DELETE_WAIT ){

		RHP_TRC(0,RHPTRCID_IKESA_NAT_T_KEEP_ALIVE_TIMER_CLEANUP,"xxx",vpn,rlm,ikesa);
		goto cleanup;

  }else{
    RHP_BUG("%d",ikesa->state);
    goto error;
  }

  RHP_UNLOCK(&(rlm->lock));


  if( tx_mesg ){

  	rhp_ikev2_nat_t_send_keep_alive(vpn,ikesa);
  }

  RHP_UNLOCK(&(vpn->lock));

	RHP_TRC(0,RHPTRCID_IKESA_NAT_T_KEEP_ALIVE_TIMER_RTRN,"xxxxx",vpn,vpn_ref,timer,rlm,ikesa);
	return;

cleanup:
error:
  RHP_UNLOCK(&(rlm->lock));
error_1:

  RHP_UNLOCK(&(vpn->lock));

  rhp_vpn_unhold(vpn_ref);
  _rhp_free(ctx);

	RHP_TRC(0,RHPTRCID_IKESA_NAT_T_KEEP_ALIVE_TIMER_IGNORE_ERR,"xxx",vpn,vpn_ref,timer);
	return;
}

static int _rhp_ikesa_start_frag_rx_req_timer(rhp_vpn* vpn,rhp_ikesa* ikesa,time_t interval)
{
  rhp_ikesa_timer_ctx* ctx;

  RHP_TRC(0,RHPTRCID_IKESA_START_FRAG_RX_REQ_TIMER,"xLdxLdGGxdLdd",vpn,"IKE_SIDE",vpn->origin_side,ikesa,"IKE_SIDE",ikesa->side,ikesa->init_spi,ikesa->resp_spi,ikesa->timers,interval,"IKESA_STAT",ikesa->state,vpn->exec_ikev2_frag);

  if( !vpn->exec_ikev2_frag ){
    RHP_TRC(0,RHPTRCID_IKESA_START_FRAG_RX_REQ_TIMER_DISABLED,"xxx",vpn,ikesa,ikesa->timers);
  	return 0;
  }

	if( rhp_timer_pending(&(ikesa->timers->frag_rx_req_timer)) ){
		RHP_TRC(0,RHPTRCID_IKESA_START_FRAG_RX_REQ_TIMER_REQ_PENDING,"xxx",vpn,ikesa,ikesa->timers);
		return 0;
	}

  ctx = (rhp_ikesa_timer_ctx*)_rhp_malloc(sizeof(rhp_ikesa_timer_ctx));
  if( ctx == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }
  memset(ctx,0,sizeof(rhp_ikesa_timer_ctx));

  ctx->vpn_ref = rhp_vpn_hold_ref(vpn);

  ctx->my_side = ikesa->side;
  if( ikesa->side == RHP_IKE_INITIATOR ){
    memcpy(ctx->my_spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
  }else{
    memcpy(ctx->my_spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
  }

	ikesa->timers->frag_rx_req_timer.ctx = (void*)ctx;

	rhp_timer_reset(&(ikesa->timers->frag_rx_req_timer));
	rhp_timer_add(&(ikesa->timers->frag_rx_req_timer),interval);

  RHP_TRC(0,RHPTRCID_IKESA_START_FRAG_RX_REQ_TIMER_RTRN,"xxxx",vpn,ikesa,ikesa->timers,ctx);
  return 0;
}

static int _rhp_ikesa_v1_start_frag_rx_req_timer(rhp_vpn* vpn,rhp_ikesa* ikesa,time_t interval)
{
	// NOP
	return 0;
}

static int _rhp_ikesa_quit_frag_rx_req_timer(rhp_vpn* vpn,rhp_ikesa* ikesa)
{
  RHP_TRC(0,RHPTRCID_IKESA_QUIT_FRAG_RX_REQ_TIMER,"xxLdGGxLd",vpn,ikesa,"IKE_SIDE",ikesa->side,ikesa->init_spi,ikesa->resp_spi,ikesa->timers,"IKESA_STAT",ikesa->state);

	if( rhp_timer_delete(&(ikesa->timers->frag_rx_req_timer)) ){
		RHP_TRC(0,RHPTRCID_IKESA_QUIT_FRAG_RX_REQ_TIMER_REQ_NOT_ACTIVE,"xxx",vpn,ikesa,ikesa->timers);
		return -1;
	}

	rhp_vpn_unhold(((rhp_ikesa_timer_ctx*)(ikesa->timers->frag_rx_req_timer.ctx))->vpn_ref);
	_rhp_free(ikesa->timers->frag_rx_req_timer.ctx);
	ikesa->timers->frag_rx_req_timer.ctx = NULL;

  RHP_TRC(0,RHPTRCID_IKESA_QUIT_FRAG_RX_REQ_TIMER_RTRN,"xxx",vpn,ikesa,ikesa->timers);
  return 0;
}

static int _rhp_ikesa_v1_quit_frag_rx_req_timer(rhp_vpn* vpn,rhp_ikesa* ikesa)
{
	// NOP
	return 0;
}

static void _rhp_ikesa_frag_rx_req_timer(void *ctx,rhp_timer *timer)
{
  rhp_vpn_ref* vpn_ref = ((rhp_ikesa_timer_ctx*)ctx)->vpn_ref;
  rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);
  rhp_ikesa* ikesa = NULL;
  int my_side = ((rhp_ikesa_timer_ctx*)ctx)->my_side;
  u8* my_spi = ((rhp_ikesa_timer_ctx*)ctx)->my_spi;

  RHP_TRC(0,RHPTRCID_IKESA_FRAG_RX_REQ_TIMER,"xxxLdG",vpn,vpn_ref,timer,"IKE_SIDE",my_side,my_spi);

  RHP_LOCK(&(vpn->lock));

  RHP_TRC(0,RHPTRCID_IKESA_FRAG_RX_REQ_TIMER_VPN,"xpuxdd",vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm,vpn->ikesa_num,vpn->childsa_num);
  rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
  rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));


  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKESA_FRAG_RX_REQ_TIMER_VPN_NOT_ACTIVE,"xx",vpn,timer);
    goto error;
  }


  ikesa = vpn->ikesa_get(vpn,((rhp_ikesa_timer_ctx*)ctx)->my_side,((rhp_ikesa_timer_ctx*)ctx)->my_spi);
  if( ikesa == NULL ){
    RHP_TRC(0,RHPTRCID_IKESA_FRAG_RX_REQ_TIMER_NO_IKESA,"xx",vpn,timer);
    goto error;
  }


  RHP_TRC(0,RHPTRCID_IKESA_FRAG_RX_REQ_TIMER_IKESA,"xxLddxdx",vpn,ikesa,"IKESA_STAT",ikesa->state,ikesa->rx_frag.req_pkts_num,ikesa->rx_frag.req_pkts.head,ikesa->rx_frag.rep_pkts_num,ikesa->rx_frag.rep_pkts.head);
  rhp_ip_addr_dump("vpn->peer_addr",&(vpn->peer_addr));
  rhp_if_entry_dump("vpn->local.if_info",&(vpn->local.if_info));

  if( ikesa->rx_frag.req_pkts_num ){

		rhp_ikev2_g_statistics_inc(rx_ikev2_req_rx_frag_timedout);

  	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKEV2_RX_REQ_FRAG_TIMEDOUT,"VP",vpn,ikesa);
  }

  ikesa->reset_req_frag_pkts_q(ikesa);


error:
  RHP_UNLOCK(&(vpn->lock));

  rhp_vpn_unhold(vpn_ref);
  _rhp_free(ctx);

	RHP_TRC(0,RHPTRCID_IKESA_FRAG_RX_REQ_TIMER_RTRN,"xxxx",vpn,vpn_ref,timer,ikesa);
	return;
}

static void _rhp_ikesa_v1_frag_rx_req_timer(void *ctx,rhp_timer *timer)
{
	// NOP
	return;
}


struct _rhp_childsa_timer_ctx {
  u32 spi_inb;
  u32 spi_outb;
  rhp_vpn_ref* vpn_ref;
};
typedef struct _rhp_childsa_timer_ctx rhp_childsa_timer_ctx;

static int _rhp_childsa_start_lifetime_timer(rhp_vpn* vpn,rhp_childsa* childsa,time_t secs,int sec_randomized)
{
  rhp_childsa_timer_ctx* ctx;
  time_t secs_r = secs;

  RHP_TRC(0,RHPTRCID_CHILDSA_START_LIFETIME_TIMER,"xxLdHHxdLd",vpn,childsa,"IKE_SIDE",childsa->side,childsa->spi_inb,childsa->spi_outb,childsa->timers,secs,"CHILDSA_STAT",childsa->state);

  if( rhp_timer_pending(&(childsa->timers->lifetime_timer)) ){
    RHP_TRC(0,RHPTRCID_CHILDSA_START_LIFETIME_TIMER_PENDING,"xxxx",vpn,childsa,childsa->timers,&(childsa->timers->lifetime_timer));
    return 0;
  }

  ctx = (rhp_childsa_timer_ctx*)_rhp_malloc(sizeof(rhp_childsa_timer_ctx));
  if( ctx == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }
  memset(ctx,0,sizeof(rhp_childsa_timer_ctx));

  ctx->vpn_ref = rhp_vpn_hold_ref(vpn);

  ctx->spi_inb = childsa->spi_inb;
  ctx->spi_outb = childsa->spi_outb;

  childsa->timers->lifetime_timer.ctx = (void*)ctx;

  rhp_timer_reset(&(childsa->timers->lifetime_timer));

  if( sec_randomized ){
  	secs_r = rhp_vpn_lifetime_random(secs);
  }
  rhp_timer_add(&(childsa->timers->lifetime_timer),secs_r);

  RHP_TRC(0,RHPTRCID_CHILDSA_START_LIFETIME_TIMER_RTRN,"xxx",vpn,childsa,childsa->timers);
  return 0;
}

static int _rhp_childsa_quit_lifetime_timer(rhp_vpn* vpn,rhp_childsa* childsa)
{

  RHP_TRC(0,RHPTRCID_CHILDSA_QUIT_LIFETIME_TIMER,"xxLdHHxLd",vpn,childsa,"IKE_SIDE",childsa->side,childsa->spi_inb,childsa->spi_outb,childsa->timers,"CHILDSA_STAT",childsa->state);

  if( rhp_timer_delete(&(childsa->timers->lifetime_timer)) ){
    RHP_TRC(0,RHPTRCID_CHILDSA_QUIT_LIFETIME_TIMER_NOT_ACTIVE,"xxxx",vpn,childsa,childsa->timers,&(childsa->timers->lifetime_timer));
    return -1;
  }

  rhp_vpn_unhold(((rhp_childsa_timer_ctx*)(childsa->timers->lifetime_timer.ctx))->vpn_ref);
  _rhp_free(childsa->timers->lifetime_timer.ctx);
  childsa->timers->lifetime_timer.ctx = NULL;

  RHP_TRC(0,RHPTRCID_CHILDSA_QUIT_LIFETIME_TIMER_RTRN,"xxx",vpn,childsa,childsa->timers);
  return 0;
}

static void _rhp_childsa_lifetime_timer(void *ctx,rhp_timer *timer)
{
  int err = 0;
  rhp_vpn_ref* vpn_ref = ((rhp_childsa_timer_ctx*)ctx)->vpn_ref;
  rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);
  rhp_childsa* childsa = NULL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_vpn_realm* rlm = NULL;

  RHP_TRC(0,RHPTRCID_CHILDSA_LIFETIME_TIMER,"xxHH",vpn,timer,((rhp_childsa_timer_ctx*)ctx)->spi_inb,((rhp_childsa_timer_ctx*)ctx)->spi_outb);

  RHP_LOCK(&(vpn->lock));

  RHP_TRC(0,RHPTRCID_CHILDSA_LIFETIME_TIMER_VPN,"xpuxddx",vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm,vpn->ikesa_num,vpn->childsa_num,vpn->childsa_list_head);
  rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
  rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_CHILDSA_LIFETIME_TIMER_VPN_NOT_ACTIVE,"xx",vpn,timer);
    goto error;
  }


  if( ((rhp_childsa_timer_ctx*)ctx)->spi_inb ){
    childsa = vpn->childsa_get(vpn,RHP_DIR_INBOUND,((rhp_childsa_timer_ctx*)ctx)->spi_inb);
  }else{
    childsa = vpn->childsa_get(vpn,RHP_DIR_OUTBOUND,((rhp_childsa_timer_ctx*)ctx)->spi_outb);
  }

  if( childsa == NULL ){
    RHP_TRC(0,RHPTRCID_CHILDSA_LIFETIME_TIMER_NO_CHILDSA,"xx",vpn,timer);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_CHILDSA_LIFETIME_TIMER_CHILDSA,"xxLdHHLd",vpn,childsa,"IKE_SIDE",childsa->side,childsa->spi_inb,childsa->spi_outb,"CHILDSA_STAT",childsa->state);
  rhp_ip_addr_dump("vpn->peer_addr",&(vpn->peer_addr));
  rhp_if_entry_dump("vpn->local.if_info",&(vpn->local.if_info));


  ((rhp_childsa_timer_ctx*)ctx)->spi_inb = childsa->spi_inb;
  ((rhp_childsa_timer_ctx*)ctx)->spi_outb = childsa->spi_outb;


  if( childsa->state == RHP_CHILDSA_STAT_LARVAL ){

    RHP_TRC(0,RHPTRCID_CHILDSA_LIFETIME_TIMER_LARVAL_TIMEOUT,"xx",vpn,childsa);
  	goto cleanup;


  }else if( childsa->state == RHP_CHILDSA_STAT_MATURE ){

  	time_t diff;
  	int pending = 0;

    RHP_TRC(0,RHPTRCID_CHILDSA_LIFETIME_TIMER_EXEC_REKEY,"xxdd",vpn,childsa,vpn->ikesa_req_rekeying,vpn->childsa_req_rekeying);

    if( vpn->ikesa_req_rekeying ||
    		rhp_ikev2_mobike_pending(vpn) ){

      	pending = 1;

    }else if( rhp_ikev2_mobike_ka_pending(vpn) ){

    	time_t now = _rhp_get_time();

  		// When MOBIKE is enabled, resonpder's keepalive may take longer.
    	if( childsa->expire_hard <= now ){
        RHP_TRC(0,RHPTRCID_CHILDSA_LIFETIME_TIMER_EXEC_REKEY_WAIT_KEEPALIVE_PEND_TIMEOUT,"xxx",vpn,rlm,childsa);
        goto delete_wait;
    	}

    	pending = 1;

    	RHP_TRC(0,RHPTRCID_CHILDSA_LIFETIME_TIMER_EXEC_REKEY_WAIT_KEEPALIVE_PEND,"xxx",vpn,rlm,childsa);
    }

    if( pending ){

    	diff = _rhp_vpn_lifetime_random_impl(RHP_CFG_LIFETIME_DEFERRED_REKEY,RHP_CFG_LIFETIME_DEFERRED_REKEY_RANDOM_RANGE);

    	rhp_timer_reset(&(childsa->timers->lifetime_timer));
    	rhp_timer_add(&(childsa->timers->lifetime_timer),diff);

      RHP_TRC(0,RHPTRCID_CHILDSA_LIFETIME_TIMER_EXEC_REKEY_WAIT_REKEYING,"xxdddd",vpn,childsa,vpn->ikesa_req_rekeying,vpn->childsa_req_rekeying,vpn->exec_mobike,vpn->mobike.resp.rt_ck_pending);
    	goto wait_rekeying;

    }else if( vpn->childsa_req_rekeying ){

    	RHP_BUG("");
    }

    rlm = vpn->rlm;
    if( rlm == NULL ){
      RHP_TRC(0,RHPTRCID_CHILDSA_LIFETIME_TIMER_NO_RLM,"xx",vpn,timer);
      goto error;
    }

    RHP_LOCK(&(rlm->lock));

    if( !_rhp_atomic_read(&(rlm->is_active)) ){
    	RHP_UNLOCK(&(rlm->lock));
      RHP_TRC(0,RHPTRCID_CHILDSA_LIFETIME_TIMER_RLM_NOT_ACTIVE,"xx",vpn,rlm);
      goto error;
    }

  	if( childsa->side == RHP_IKE_INITIATOR ||
  			(childsa->side == RHP_IKE_RESPONDER && !rlm->childsa.resp_not_rekeying) ||
  			vpn->exec_rekey_ipv6_autoconf ){

  		err = rhp_ikev2_rekey_create_childsa(vpn,rlm,childsa,vpn->exec_rekey_ipv6_autoconf,&tx_ikemesg);
  		if( err ){
  	  	RHP_UNLOCK(&(rlm->lock));
  			RHP_TRC(0,RHPTRCID_CHILDSA_LIFETIME_TIMER_MK_REKEY_ERR,"xxE",vpn,childsa,err);
  			goto error;
  		}

  		vpn->childsa_req_rekeying = 1;
  		vpn->exec_rekey_ipv6_autoconf = 0;

  	}else{
      RHP_TRC(0,RHPTRCID_CHILDSA_LIFETIME_TIMER_SKIP_REKEY,"xxLdd",vpn,childsa,"IKE_SIDE",childsa->side,rlm->childsa.resp_not_rekeying);
  	}

  	diff = rlm->childsa.lifetime_hard - rlm->childsa.lifetime_soft;
  	diff = rhp_vpn_lifetime_random(diff);

  	rhp_timer_reset(&(childsa->timers->lifetime_timer));
  	rhp_timer_add(&(childsa->timers->lifetime_timer),diff);

  	RHP_UNLOCK(&(rlm->lock));


  	rhp_childsa_set_state(childsa,RHP_CHILDSA_STAT_REKEYING);

  	if( tx_ikemesg ){
  		rhp_ikev2_send_request(vpn,NULL,tx_ikemesg,RHP_IKEV2_MESG_HANDLER_REKEY);
  		rhp_ikev2_unhold_mesg(tx_ikemesg);
  	}

  	childsa->expire_soft = 0;
  	childsa->expire_hard = _rhp_get_time() + diff;


  }else if( childsa->state == RHP_CHILDSA_STAT_REKEYING ){

    RHP_TRC(0,RHPTRCID_CHILDSA_LIFETIME_TIMER_HARD_LIFETIME,"xx",vpn,childsa);

  	childsa->expire_soft = 0;
  	childsa->expire_hard = 0;
    goto delete;


  }else if( childsa->state == RHP_CHILDSA_STAT_DELETE ){

  	time_t lifetime_deleted;
    rhp_ikev2_payload* d_ikepayload;

delete:
  	RHP_TRC(0,RHPTRCID_CHILDSA_LIFETIME_TIMER_CLEANUP,"xx",vpn,childsa);

  	{
			rlm = vpn->rlm;
			if( rlm == NULL ){
				RHP_TRC(0,RHPTRCID_CHILDSA_LIFETIME_TIMER_CLEANUP_NO_RLM,"xx",vpn,childsa);
				goto error;
			}

			RHP_LOCK(&(rlm->lock));

			if( !_rhp_atomic_read(&(rlm->is_active)) ){
				RHP_UNLOCK(&(rlm->lock));
				RHP_TRC(0,RHPTRCID_CHILDSA_LIFETIME_TIMER_CLEANUP_RLM_NOT_ACTIVE,"xxx",vpn,rlm,childsa);
				goto error;
			}

			lifetime_deleted = (time_t)rlm->childsa.lifetime_deleted;

			RHP_UNLOCK(&(rlm->lock));
  	}

  	{
			tx_ikemesg = rhp_ikev2_new_mesg_tx(RHP_PROTO_IKE_EXCHG_INFORMATIONAL,0,0);
			if( tx_ikemesg == NULL ){
				RHP_BUG("");
				goto error;
			}

 	    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_D,&d_ikepayload) ){
 	      RHP_BUG("");
 	      goto error;
 	    }

 	    tx_ikemesg->put_payload(tx_ikemesg,d_ikepayload);

 	    d_ikepayload->ext.d->set_protocol_id(d_ikepayload,RHP_PROTO_IKE_PROTOID_ESP);

 	    if( d_ikepayload->ext.d->set_spi(d_ikepayload,childsa->spi_inb) ){
 	      RHP_BUG("");
 	      goto error;
 	    }
 	  }

    rhp_childsa_set_state(childsa,RHP_CHILDSA_STAT_DELETE_WAIT);

    rhp_timer_reset(&(childsa->timers->lifetime_timer));
    rhp_timer_add(&(childsa->timers->lifetime_timer),lifetime_deleted);

    rhp_ikev2_send_request(vpn,NULL,tx_ikemesg,RHP_IKEV2_MESG_HANDLER_DELETE_SA);
	  rhp_ikev2_unhold_mesg(tx_ikemesg);

  	childsa->expire_soft = 0;
  	childsa->expire_hard = _rhp_get_time() + lifetime_deleted;


  }else if( childsa->state == RHP_CHILDSA_STAT_DELETE_WAIT ){

  	int delete_no_childsa = 0;

delete_wait:
		RHP_TRC(0,RHPTRCID_CHILDSA_LIFETIME_TIMER_DELETE_WAIT,"xxxxxddd",vpn,timer,childsa,childsa->timers,vpn->childsa_list_head,vpn->ikesa_num,vpn->childsa_num,childsa->delete_ikesa_too);

  	if( childsa->delete_ikesa_too ){

  		rhp_ikesa* deleted_ikesa;
  		u8* deleted_ikesa_spi;

  		if( childsa->parent_ikesa.side == RHP_IKE_INITIATOR ){
  			deleted_ikesa_spi = childsa->parent_ikesa.init_spi;
  		}else{
  			deleted_ikesa_spi = childsa->parent_ikesa.resp_spi;
  		}

  		deleted_ikesa = vpn->ikesa_get(vpn,childsa->parent_ikesa.side,deleted_ikesa_spi);
  		if( deleted_ikesa == NULL ){
  			RHP_BUG("");
  		}else{

  			deleted_ikesa->timers->schedule_delete(vpn,deleted_ikesa,0);
  			childsa->delete_ikesa_too = 0;
  		}
	  }


  	{
			rlm = vpn->rlm;
			if( rlm != NULL  ){

				RHP_LOCK(&(rlm->lock));

				delete_no_childsa = (time_t)rlm->ikesa.delete_no_childsa;

				RHP_UNLOCK(&(rlm->lock));
			}

			if( delete_no_childsa || vpn->deleting ){

				if( vpn->childsa_num == 1 && vpn->ikesa_num != 0 ){

					rhp_ikesa* deleted_ikesa;

					if( vpn->childsa_list_head != childsa ){
						RHP_BUG("");
					}

					if( vpn->ikesa_list_head == NULL ){
						RHP_BUG("");
					}

					deleted_ikesa = vpn->ikesa_list_head;
					while( deleted_ikesa ){

						RHP_TRC(0,RHPTRCID_CHILDSA_LIFETIME_TIMER_CLEANUP_IKESA,"xxLd",vpn,deleted_ikesa,"IKESA_STAT",deleted_ikesa->state);

						deleted_ikesa->timers->schedule_delete(vpn,deleted_ikesa,0);

						deleted_ikesa = deleted_ikesa->next_vpn_list;
					}
				}

			}else{

				RHP_TRC(0,RHPTRCID_CHILDSA_LIFETIME_TIMER_NO_CHILDSA_BUT_DONT_CLEANUP_IKESA,"x",vpn);
			}
  	}


  	childsa->expire_soft = 0;
  	childsa->expire_hard = 0;

  	goto cleanup;


  }else if( childsa->state == RHP_CHILDSA_STAT_DEAD ){

  	// <EX> Cleanup Child SA forcefully.
    RHP_TRC(0,RHPTRCID_CHILDSA_LIFETIME_TIMER_CLEANUP,"xxxx",vpn,timer,childsa,childsa->timers);

  	childsa->expire_soft = 0;
  	childsa->expire_hard = 0;

    goto cleanup;


  }else{

  	RHP_BUG("childsa->state:%d",childsa->state);
  	goto error;
  }

wait_rekeying:
  if( (err = rhp_vpn_clear_unique_ids_tls_cache(vpn->vpn_realm_id)) ){
  	RHP_BUG("%d",err);
  }
  err = 0;

  RHP_UNLOCK(&(vpn->lock));

  RHP_TRC(0,RHPTRCID_CHILDSA_LIFETIME_TIMER_RTRN,"xx",vpn,childsa);
  return;

cleanup:
error:

  if( childsa ){
    rhp_childsa_destroy(vpn,childsa);
  }
	//
	// Don't touch "childsa" any more.
	//

  RHP_UNLOCK(&(vpn->lock));

  rhp_vpn_unhold(vpn_ref);
  _rhp_free(ctx);

  RHP_TRC(0,RHPTRCID_CHILDSA_LIFETIME_TIMER_IGNORE_ERR,"xx",vpn,childsa);
  return;
}

static void _rhp_ipsecsa_v1_lifetime_timer(void *ctx,rhp_timer *timer)
{
  int err = 0;
  rhp_vpn_ref* vpn_ref = ((rhp_childsa_timer_ctx*)ctx)->vpn_ref;
  rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);
  rhp_childsa* childsa = NULL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_vpn_realm* rlm = NULL;

  RHP_TRC(0,RHPTRCID_IPSECSA_V1_LIFETIME_TIMER,"xxHH",vpn,timer,((rhp_childsa_timer_ctx*)ctx)->spi_inb,((rhp_childsa_timer_ctx*)ctx)->spi_outb);

  RHP_LOCK(&(vpn->lock));

  RHP_TRC(0,RHPTRCID_IPSECSA_V1_LIFETIME_TIMER_VPN,"xpuxddx",vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm,vpn->ikesa_num,vpn->childsa_num,vpn->childsa_list_head);
  rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
  rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_IPSECSA_V1_LIFETIME_TIMER_VPN_NOT_ACTIVE,"xx",vpn,timer);
    goto error;
  }


  if( ((rhp_childsa_timer_ctx*)ctx)->spi_inb ){
    childsa = vpn->childsa_get(vpn,RHP_DIR_INBOUND,((rhp_childsa_timer_ctx*)ctx)->spi_inb);
  }else{
    childsa = vpn->childsa_get(vpn,RHP_DIR_OUTBOUND,((rhp_childsa_timer_ctx*)ctx)->spi_outb);
  }

  if( childsa == NULL ){
    RHP_TRC(0,RHPTRCID_IPSECSA_V1_LIFETIME_TIMER_NO_CHILDSA,"xx",vpn,timer);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IPSECSA_V1_LIFETIME_TIMER_CHILDSA,"xxLdHHLdd",vpn,childsa,"IKE_SIDE",childsa->side,childsa->spi_inb,childsa->spi_outb,"CHILDSA_STAT",childsa->state,childsa->v1.dont_rekey);
  rhp_ip_addr_dump("vpn->peer_addr",&(vpn->peer_addr));
  rhp_if_entry_dump("vpn->local.if_info",&(vpn->local.if_info));


  ((rhp_childsa_timer_ctx*)ctx)->spi_inb = childsa->spi_inb;
  ((rhp_childsa_timer_ctx*)ctx)->spi_outb = childsa->spi_outb;


  if( childsa->state == RHP_IPSECSA_STAT_V1_1ST_SENT_I ||
  		childsa->state == RHP_IPSECSA_STAT_V1_WAIT_COMMIT_I ||
  		childsa->state == RHP_IPSECSA_STAT_V1_2ND_SENT_R ){

    RHP_TRC(0,RHPTRCID_IPSECSA_V1_LIFETIME_TIMER_LARVAL_TIMEOUT,"xx",vpn,childsa);
  	goto cleanup;

  }else if( childsa->state == RHP_IPSECSA_STAT_V1_MATURE ){

  	time_t diff;

    RHP_TRC(0,RHPTRCID_IPSECSA_V1_LIFETIME_TIMER_EXEC_REKEY,"xxdd",vpn,childsa,vpn->ikesa_req_rekeying,vpn->childsa_req_rekeying);

		if( vpn->ikesa_req_rekeying ){

			diff = _rhp_vpn_lifetime_random_impl(RHP_CFG_LIFETIME_DEFERRED_REKEY,
							RHP_CFG_LIFETIME_DEFERRED_REKEY_RANDOM_RANGE);

			rhp_timer_reset(&(childsa->timers->lifetime_timer));
			rhp_timer_add(&(childsa->timers->lifetime_timer),diff);

			RHP_TRC(0,RHPTRCID_IPSECSA_V1_LIFETIME_TIMER_EXEC_REKEY_WAIT_REKEYING,"xxdddd",vpn,childsa,vpn->ikesa_req_rekeying,vpn->childsa_req_rekeying,vpn->exec_mobike,vpn->mobike.resp.rt_ck_pending);
			goto wait_rekeying;

		}else if( vpn->childsa_req_rekeying ){

			RHP_BUG("");
		}

	  if( !childsa->v1.dont_rekey ){

			rlm = vpn->rlm;
			if( rlm == NULL ){
				RHP_TRC(0,RHPTRCID_IPSECSA_V1_LIFETIME_TIMER_NO_RLM,"xx",vpn,timer);
				goto error;
			}

			RHP_LOCK(&(rlm->lock));

			if( !_rhp_atomic_read(&(rlm->is_active)) ){
				RHP_UNLOCK(&(rlm->lock));
				RHP_TRC(0,RHPTRCID_IPSECSA_V1_LIFETIME_TIMER_RLM_NOT_ACTIVE,"xx",vpn,rlm);
				goto error;
			}


			if( childsa->side == RHP_IKE_INITIATOR ||
					(childsa->side == RHP_IKE_RESPONDER && !rlm->childsa.resp_not_rekeying) ){

				err = rhp_ikev1_rekey_create_childsa(vpn,rlm,childsa,&tx_ikemesg);
				if( err ){
					RHP_UNLOCK(&(rlm->lock));
					RHP_TRC(0,RHPTRCID_IPSECSA_V1_LIFETIME_TIMER_MK_REKEY_ERR,"xxE",vpn,childsa,err);
					goto error;
				}

				vpn->childsa_req_rekeying = 1;

			}else{

				RHP_TRC(0,RHPTRCID_IPSECSA_V1_LIFETIME_TIMER_SKIP_REKEY,"xxLdd",vpn,childsa,"IKE_SIDE",childsa->side,rlm->childsa.resp_not_rekeying);
			}

	  	RHP_UNLOCK(&(rlm->lock));
  	}


  	diff = childsa->expire_hard - childsa->expire_soft;
  	if( diff < (time_t)rhp_gcfg_ikev1_ipsecsa_rekey_margin ){
  		diff = (time_t)rhp_gcfg_ikev1_ipsecsa_rekey_margin;
  	}
  	diff = rhp_vpn_lifetime_random(diff);

  	rhp_timer_reset(&(childsa->timers->lifetime_timer));
  	rhp_timer_add(&(childsa->timers->lifetime_timer),diff);

  	rhp_childsa_set_state(childsa,RHP_IPSECSA_STAT_V1_REKEYING);


  	if( tx_ikemesg ){

      rhp_ikev1_send_mesg(vpn,NULL,tx_ikemesg,RHP_IKEV1_MESG_HANDLER_P2_QUICK);
  		rhp_ikev2_unhold_mesg(tx_ikemesg);
  	}


  	childsa->expire_soft = 0;
  	childsa->expire_hard = _rhp_get_time() + diff;


  }else if( childsa->state == RHP_IPSECSA_STAT_V1_REKEYING ){

    RHP_TRC(0,RHPTRCID_IPSECSA_V1_LIFETIME_TIMER_HARD_LIFETIME,"xx",vpn,childsa);

  	childsa->expire_soft = 0;
  	childsa->expire_hard = 0;
    goto delete;


  }else if( childsa->state == RHP_IPSECSA_STAT_V1_DELETE ){

  	time_t lifetime_deleted;
    rhp_ikesa* cur_ikesa = NULL;

delete:
  	RHP_TRC(0,RHPTRCID_IPSECSA_V1_LIFETIME_TIMER_CLEANUP,"xx",vpn,childsa);

  	{
			rlm = vpn->rlm;
			if( rlm == NULL ){
				RHP_TRC(0,RHPTRCID_IPSECSA_V1_LIFETIME_TIMER_CLEANUP_NO_RLM,"xx",vpn,childsa);
				goto error;
			}

			RHP_LOCK(&(rlm->lock));

			if( !_rhp_atomic_read(&(rlm->is_active)) ){
				RHP_UNLOCK(&(rlm->lock));
				RHP_TRC(0,RHPTRCID_IPSECSA_V1_LIFETIME_TIMER_CLEANUP_RLM_NOT_ACTIVE,"xxx",vpn,rlm,childsa);
				goto error;
			}

			lifetime_deleted = (time_t)rlm->v1.ipsecsa_lifetime_deleted;

			RHP_UNLOCK(&(rlm->lock));
  	}


  	{
			cur_ikesa = vpn->ikesa_list_head;
			while( cur_ikesa ){

				if( (cur_ikesa->state == RHP_IKESA_STAT_V1_ESTABLISHED ||
						 cur_ikesa->state == RHP_IKESA_STAT_V1_REKEYING) &&
						cur_ikesa->side == childsa->parent_ikesa.side &&
						!memcmp(cur_ikesa->init_spi,childsa->parent_ikesa.init_spi,RHP_PROTO_IKE_SPI_SIZE) &&
						!memcmp(cur_ikesa->resp_spi,childsa->parent_ikesa.resp_spi,RHP_PROTO_IKE_SPI_SIZE) ){

					break;
				}

				cur_ikesa = cur_ikesa->next_vpn_list;
			}
  	}

  	if( cur_ikesa ){

 			tx_ikemesg = rhp_ikev1_new_pkt_delete_ipsecsa(vpn,cur_ikesa,childsa);
 			if( tx_ikemesg == NULL ){
 				err = -EINVAL;
 				goto error;
 			}
 	  }

    rhp_childsa_set_state(childsa,RHP_IPSECSA_STAT_V1_DELETE_WAIT);

    rhp_timer_reset(&(childsa->timers->lifetime_timer));
    rhp_timer_add(&(childsa->timers->lifetime_timer),lifetime_deleted);

    if( tx_ikemesg ){

    	rhp_ikev1_send_mesg(vpn,cur_ikesa,tx_ikemesg,RHP_IKEV1_MESG_HANDLER_DELETE_SA);
    	rhp_ikev2_unhold_mesg(tx_ikemesg);
    }

  	childsa->expire_soft = 0;
  	childsa->expire_hard = _rhp_get_time() + lifetime_deleted;


  }else if( childsa->state == RHP_IPSECSA_STAT_V1_DELETE_WAIT ){

  	int delete_no_childsa = 0;

		RHP_TRC(0,RHPTRCID_IPSECSA_V1_LIFETIME_TIMER_DELETE_WAIT,"xxxxxddd",vpn,timer,childsa,childsa->timers,vpn->childsa_list_head,vpn->ikesa_num,vpn->childsa_num,childsa->delete_ikesa_too);

  	if( childsa->delete_ikesa_too ){

  		rhp_ikesa* deleted_ikesa;
  		u8* deleted_ikesa_spi;

  		if( childsa->parent_ikesa.side == RHP_IKE_INITIATOR ){
  			deleted_ikesa_spi = childsa->parent_ikesa.init_spi;
  		}else{
  			deleted_ikesa_spi = childsa->parent_ikesa.resp_spi;
  		}

  		deleted_ikesa = vpn->ikesa_get(vpn,childsa->parent_ikesa.side,deleted_ikesa_spi);
  		if( deleted_ikesa == NULL ){
  			RHP_BUG("");
  		}else{

  			deleted_ikesa->timers->schedule_delete(vpn,deleted_ikesa,0);
  			childsa->delete_ikesa_too = 0;
  		}
	  }


  	{
			rlm = vpn->rlm;
			if( rlm != NULL  ){

				RHP_LOCK(&(rlm->lock));

				delete_no_childsa = (time_t)rlm->ikesa.delete_no_childsa;

				RHP_UNLOCK(&(rlm->lock));
			}

			if( delete_no_childsa || vpn->deleting ){

				if( vpn->childsa_num == 1 && vpn->ikesa_num != 0 ){

					rhp_ikesa* deleted_ikesa;

					if( vpn->childsa_list_head != childsa ){
						RHP_BUG("");
					}

					if( vpn->ikesa_list_head == NULL ){
						RHP_BUG("");
					}

					deleted_ikesa = vpn->ikesa_list_head;
					while( deleted_ikesa ){

						RHP_TRC(0,RHPTRCID_IPSECSA_V1_LIFETIME_TIMER_CLEANUP_IKESA,"xxLd",vpn,deleted_ikesa,"IKESA_STAT",deleted_ikesa->state);

						deleted_ikesa->timers->schedule_delete(vpn,deleted_ikesa,0);

						deleted_ikesa = deleted_ikesa->next_vpn_list;
					}
				}

			}else{

				RHP_TRC(0,RHPTRCID_IPSECSA_V1_LIFETIME_TIMER_NO_CHILDSA_BUT_DONT_CLEANUP_IKESA,"x",vpn);
			}
  	}


  	childsa->expire_soft = 0;
  	childsa->expire_hard = 0;

  	goto cleanup;


  }else if( childsa->state == RHP_IPSECSA_STAT_V1_DEAD ){

  	// <EX> Cleanup Child SA forcefully.
    RHP_TRC(0,RHPTRCID_IPSECSA_V1_LIFETIME_TIMER_CLEANUP,"xxxx",vpn,timer,childsa,childsa->timers);

  	childsa->expire_soft = 0;
  	childsa->expire_hard = 0;

    goto cleanup;


  }else{

  	RHP_BUG("childsa->state:%d",childsa->state);
  	goto error;
  }

wait_rekeying:
  if( (err = rhp_vpn_clear_unique_ids_tls_cache(vpn->vpn_realm_id)) ){
  	RHP_BUG("%d",err);
  }
  err = 0;

  RHP_UNLOCK(&(vpn->lock));

  RHP_TRC(0,RHPTRCID_IPSECSA_V1_LIFETIME_TIMER_RTRN,"xxx",vpn,childsa,ctx);
  return;


cleanup:
error:

  if( childsa ){

  	//
  	// Don't touch "childsa" any more.
  	//

  	rhp_childsa_destroy(vpn,childsa);
  }

  RHP_UNLOCK(&(vpn->lock));

  rhp_vpn_unhold(vpn_ref);
  _rhp_free(ctx);

  RHP_TRC(0,RHPTRCID_IPSECSA_V1_LIFETIME_TIMER_IGNORE_ERR,"xxx",vpn,childsa,ctx);
  return;
}


static int _rhp_childsa_schedule_delete(rhp_vpn* vpn,rhp_childsa* childsa,int defered_sec)
{
	int err = -EINVAL;
	int next_state = -1;

  RHP_TRC(0,RHPTRCID_CHILDSA_SCHEDULE_DELETE,"xxLdd",vpn,childsa,"CHILDSA_STAT",childsa->state,defered_sec);

	childsa->timers->quit_lifetime_timer(vpn,childsa);

	switch( childsa->state ){

	case RHP_CHILDSA_STAT_DEFAULT:
	case RHP_CHILDSA_STAT_LARVAL:
		next_state = RHP_CHILDSA_STAT_DELETE_WAIT;
		break;

	case RHP_CHILDSA_STAT_MATURE:
	case RHP_CHILDSA_STAT_REKEYING:
		next_state = RHP_CHILDSA_STAT_DELETE;
		break;

	case RHP_CHILDSA_STAT_DELETE:
	case RHP_CHILDSA_STAT_DELETE_WAIT:
	case RHP_CHILDSA_STAT_DEAD:
		next_state = -1;
		break;

	default:
		RHP_BUG("%d",childsa->state);
		err = -EINVAL;
		goto error;
	}

	if( next_state >= 0 ){

		rhp_childsa_set_state(childsa,next_state);
	}

	childsa->timers->start_lifetime_timer(vpn,childsa,(time_t)defered_sec,0); // Exec immediately!

  RHP_TRC(0,RHPTRCID_CHILDSA_SCHEDULE_DELETE_RTRN,"xxLd",vpn,childsa,"CHILDSA_STAT",childsa->state);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_CHILDSA_SCHEDULE_DELETE_ERR,"xxE",vpn,childsa,err);
	return err;
}

static int _rhp_ipsecsa_v1_schedule_delete(rhp_vpn* vpn,rhp_childsa* childsa,int defered_sec)
{
	int err = -EINVAL;
	int next_state = -1;

  RHP_TRC(0,RHPTRCID_IPSECSA_V1_SCHEDULE_DELETE,"xxLdd",vpn,childsa,"CHILDSA_STAT",childsa->state,defered_sec);

	childsa->timers->quit_lifetime_timer(vpn,childsa);

	switch( childsa->state ){

	case RHP_CHILDSA_STAT_DEFAULT:
	case RHP_IPSECSA_STAT_V1_1ST_SENT_I:
	case RHP_IPSECSA_STAT_V1_WAIT_COMMIT_I:
	case RHP_IPSECSA_STAT_V1_2ND_SENT_R:
		next_state = RHP_IPSECSA_STAT_V1_DELETE_WAIT;
		break;

	case RHP_IPSECSA_STAT_V1_MATURE:
	case RHP_IPSECSA_STAT_V1_REKEYING:
		next_state = RHP_IPSECSA_STAT_V1_DELETE;
		break;

	case RHP_IPSECSA_STAT_V1_DELETE:
	case RHP_IPSECSA_STAT_V1_DELETE_WAIT:
	case RHP_IPSECSA_STAT_V1_DEAD:
		next_state = -1;
		break;

	default:
		RHP_BUG("%d",childsa->state);
		err = -EINVAL;
		goto error;
	}

	if( next_state >= 0 ){

		rhp_childsa_set_state(childsa,next_state);
	}

	childsa->timers->start_lifetime_timer(vpn,childsa,(time_t)defered_sec,0); // Exec immediately!

  RHP_TRC(0,RHPTRCID_IPSECSA_V1_SCHEDULE_DELETE_RTRN,"xxLd",vpn,childsa,"CHILDSA_STAT",childsa->state);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IPSECSA_V1_SCHEDULE_DELETE_ERR,"xxE",vpn,childsa,err);
	return err;
}

static int _rhp_ikesa_schedule_delete(rhp_vpn* vpn,rhp_ikesa* ikesa,int defered_sec)
{
	int err = -EINVAL;
	int next_state = -1;

  RHP_TRC(0,RHPTRCID_IKESA_SCHEDULE_DELETE,"xxLdd",vpn,ikesa,"IKESA_STAT",ikesa->state,defered_sec);

	ikesa->timers->quit_lifetime_timer(vpn,ikesa);

	switch( ikesa->state ){

	case RHP_IKESA_STAT_DEFAULT:
	case RHP_IKESA_STAT_I_IKE_SA_INIT_SENT:
	case RHP_IKESA_STAT_I_AUTH_SENT:
	case RHP_IKESA_STAT_R_IKE_SA_INIT_SENT:
	case RHP_IKESA_STAT_I_REKEY_SENT:
		next_state = RHP_IKESA_STAT_DELETE_WAIT;
		break;

	case RHP_IKESA_STAT_ESTABLISHED:
	case RHP_IKESA_STAT_REKEYING:
		next_state = RHP_IKESA_STAT_DELETE;
		break;

	case RHP_IKESA_STAT_DELETE:
	case RHP_IKESA_STAT_DELETE_WAIT:
	case RHP_IKESA_STAT_DEAD:
		next_state = -1;
		break;

	default:
		RHP_BUG("%d",ikesa->state);
		err = -EINVAL;
		goto error;
	}

	if( next_state >= 0 ){

		rhp_ikesa_set_state(ikesa,next_state);
	}

	ikesa->timers->start_lifetime_timer(vpn,ikesa,(time_t)defered_sec,0);

  RHP_TRC(0,RHPTRCID_IKESA_SCHEDULE_DELETE_RTRN,"xxLd",vpn,ikesa,"IKESA_STAT",ikesa->state);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKESA_SCHEDULE_DELETE_ERR,"xxE",vpn,ikesa,err);
	return err;
}

static int _rhp_ikesa_v1_main_schedule_delete(rhp_vpn* vpn,rhp_ikesa* ikesa,int defered_sec)
{
	int err = -EINVAL;
	int next_state = -1;

  RHP_TRC(0,RHPTRCID_IKESA_V1_MAIN_SCHEDULE_DELETE,"xxLdd",vpn,ikesa,"IKESA_STAT",ikesa->state,defered_sec);

	ikesa->timers->quit_lifetime_timer(vpn,ikesa);

	switch( ikesa->state ){

	case RHP_IKESA_STAT_DEFAULT:
	case RHP_IKESA_STAT_V1_MAIN_1ST_SENT_I:
	case RHP_IKESA_STAT_V1_MAIN_3RD_SENT_I:
	case RHP_IKESA_STAT_V1_MAIN_5TH_SENT_I:
	case RHP_IKESA_STAT_V1_MAIN_2ND_SENT_R:
	case RHP_IKESA_STAT_V1_MAIN_4TH_SENT_R:
	case RHP_IKESA_STAT_V1_XAUTH_PEND_I:
	case RHP_IKESA_STAT_V1_XAUTH_PEND_R:
		next_state = RHP_IKESA_STAT_V1_DELETE_WAIT;
		break;

	case RHP_IKESA_STAT_V1_ESTABLISHED:
	case RHP_IKESA_STAT_V1_REKEYING:
		next_state = RHP_IKESA_STAT_V1_DELETE;
		break;

	case RHP_IKESA_STAT_V1_DELETE:
	case RHP_IKESA_STAT_V1_DELETE_WAIT:
	case RHP_IKESA_STAT_V1_DEAD:
		next_state = -1;
		break;

	default:
		RHP_BUG("%d",ikesa->state);
		err = -EINVAL;
		goto error;
	}

	if( next_state >= 0 ){

		rhp_ikesa_set_state(ikesa,next_state);
	}

	ikesa->timers->start_lifetime_timer(vpn,ikesa,(time_t)defered_sec,0);

  RHP_TRC(0,RHPTRCID_IKESA_V1_MAIN_SCHEDULE_DELETE_RTRN,"xxLd",vpn,ikesa,"IKESA_STAT",ikesa->state);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKESA_V1_MAIN_SCHEDULE_DELETE_ERR,"xxE",vpn,ikesa,err);
	return err;
}

static int _rhp_ikesa_v1_aggressive_schedule_delete(rhp_vpn* vpn,rhp_ikesa* ikesa,int defered_sec)
{
	int err = -EINVAL;
	int next_state = -1;

  RHP_TRC(0,RHPTRCID_IKESA_V1_AGGRESSIVE_SCHEDULE_DELETE,"xxLdd",vpn,ikesa,"IKESA_STAT",ikesa->state,defered_sec);

	ikesa->timers->quit_lifetime_timer(vpn,ikesa);

	switch( ikesa->state ){

	case RHP_IKESA_STAT_DEFAULT:
	case RHP_IKESA_STAT_V1_AGG_1ST_SENT_I:
	case RHP_IKESA_STAT_V1_AGG_WAIT_COMMIT_I:
	case RHP_IKESA_STAT_V1_AGG_2ND_SENT_R:
		next_state = RHP_IKESA_STAT_V1_DELETE_WAIT;
		break;

	case RHP_IKESA_STAT_V1_ESTABLISHED:
	case RHP_IKESA_STAT_V1_REKEYING:
		next_state = RHP_IKESA_STAT_V1_DELETE;
		break;

	case RHP_IKESA_STAT_V1_DELETE:
	case RHP_IKESA_STAT_V1_DELETE_WAIT:
	case RHP_IKESA_STAT_V1_DEAD:
		next_state = -1;
		break;

	default:
		RHP_BUG("%d",ikesa->state);
		err = -EINVAL;
		goto error;
	}

	if( next_state >= 0 ){

		rhp_ikesa_set_state(ikesa,next_state);
	}

	ikesa->timers->start_lifetime_timer(vpn,ikesa,(time_t)defered_sec,0);

  RHP_TRC(0,RHPTRCID_IKESA_V1_AGGRESSIVE_SCHEDULE_DELETE_RTRN,"xxLd",vpn,ikesa,"IKESA_STAT",ikesa->state);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKESA_V1_AGGRESSIVE_SCHEDULE_DELETE_ERR,"xxE",vpn,ikesa,err);
	return err;
}

static int _rhp_ikesa_v1_schedule_delete(rhp_vpn* vpn,rhp_ikesa* ikesa,int defered_sec)
{
	if( ikesa->v1.p1_exchange_mode == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ){
		return _rhp_ikesa_v1_main_schedule_delete(vpn,ikesa,defered_sec);
	}else if( ikesa->v1.p1_exchange_mode == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){
		return _rhp_ikesa_v1_aggressive_schedule_delete(vpn,ikesa,defered_sec);
	}else{
		RHP_BUG("%d",ikesa->v1.p1_exchange_mode);
		return -EINVAL;
	}
}

rhp_ikesa_timers* rhp_ikesa_new_timers(int my_side,u8* my_spi)
{
  rhp_ikesa_timers* timers = NULL;

  timers = (rhp_ikesa_timers*)_rhp_malloc(sizeof(rhp_ikesa_timers));
  if( timers == NULL ){
    RHP_BUG("");
    return NULL;
  }
  memset(timers,0,sizeof(rhp_ikesa_timers));

  timers->tag[0] = '#';
  timers->tag[1] = 'V';
  timers->tag[2] = 'I';
  timers->tag[3] = 'T';

  timers->my_side = my_side;
  memcpy(timers->my_spi,my_spi,RHP_PROTO_IKE_SPI_SIZE);

  rhp_timer_init(&(timers->lifetime_timer),_rhp_ikesa_lifetime_timer,NULL);
  rhp_timer_init(&(timers->retx_timer),_rhp_ikesa_retransmit_timer,NULL);
  rhp_timer_init(&(timers->keep_alive_timer),_rhp_ikesa_keep_alive_timer,NULL);
  rhp_timer_init(&(timers->nat_t_keep_alive_timer),_rhp_ikesa_nat_t_keep_alive_timer,NULL);
  rhp_timer_init(&(timers->frag_rx_req_timer),_rhp_ikesa_frag_rx_req_timer,NULL);

  timers->start_lifetime_timer = _rhp_ikesa_start_lifetime_timer;
  timers->quit_lifetime_timer = _rhp_ikesa_quit_lifetime_timer;

  timers->start_retransmit_timer = _rhp_ikesa_start_retransmit_timer;
  timers->quit_retransmit_timer = _rhp_ikesa_quit_retransmit_timer;

  timers->start_keep_alive_timer = _rhp_ikesa_start_keep_alive_timer;
  timers->quit_keep_alive_timer = _rhp_ikesa_quit_keep_alive_timer;

  timers->start_nat_t_keep_alive_timer = _rhp_ikesa_start_nat_t_keep_alive_timer;
  timers->quit_nat_t_keep_alive_timer = _rhp_ikesa_quit_nat_t_keep_alive_timer;

  timers->start_frag_rx_req_timer = _rhp_ikesa_start_frag_rx_req_timer;
  timers->quit_frag_rx_req_timer = _rhp_ikesa_quit_frag_rx_req_timer;

  timers->schedule_delete = _rhp_ikesa_schedule_delete;

  RHP_TRC(0,RHPTRCID_IKESA_NEW_TIMERS,"LdGx","IKE_SIDE",my_side,my_spi,timers);
  return timers;
}

rhp_ikesa_timers* rhp_ikesa_v1_new_timers(int my_side,u8* my_spi)
{
  rhp_ikesa_timers* timers = NULL;

  timers = (rhp_ikesa_timers*)_rhp_malloc(sizeof(rhp_ikesa_timers));
  if( timers == NULL ){
    RHP_BUG("");
    return NULL;
  }
  memset(timers,0,sizeof(rhp_ikesa_timers));

  timers->tag[0] = '#';
  timers->tag[1] = 'V';
  timers->tag[2] = 'I';
  timers->tag[3] = 'T';

  timers->my_side = my_side;
  memcpy(timers->my_spi,my_spi,RHP_PROTO_IKE_SPI_SIZE);

  rhp_timer_init(&(timers->lifetime_timer),_rhp_ikesa_v1_lifetime_timer,NULL);
  rhp_timer_init(&(timers->retx_timer),_rhp_ikesa_v1_retransmit_timer,NULL);
  rhp_timer_init(&(timers->keep_alive_timer),_rhp_ikesa_v1_keep_alive_timer,NULL);
  rhp_timer_init(&(timers->nat_t_keep_alive_timer),_rhp_ikesa_nat_t_keep_alive_timer,NULL);
  rhp_timer_init(&(timers->frag_rx_req_timer),_rhp_ikesa_v1_frag_rx_req_timer,NULL);

  timers->start_lifetime_timer = _rhp_ikesa_start_lifetime_timer;
  timers->quit_lifetime_timer = _rhp_ikesa_quit_lifetime_timer;

  timers->start_retransmit_timer = _rhp_ikesa_start_retransmit_timer;
  timers->quit_retransmit_timer = _rhp_ikesa_quit_retransmit_timer;

  timers->start_keep_alive_timer = _rhp_ikesa_start_keep_alive_timer;
  timers->quit_keep_alive_timer = _rhp_ikesa_quit_keep_alive_timer;

  timers->start_nat_t_keep_alive_timer = _rhp_ikesa_start_nat_t_keep_alive_timer;
  timers->quit_nat_t_keep_alive_timer = _rhp_ikesa_quit_nat_t_keep_alive_timer;

  timers->start_frag_rx_req_timer = _rhp_ikesa_v1_start_frag_rx_req_timer;
  timers->quit_frag_rx_req_timer = _rhp_ikesa_v1_quit_frag_rx_req_timer;

  timers->schedule_delete = _rhp_ikesa_v1_schedule_delete;

  RHP_TRC(0,RHPTRCID_IKESA_V1_NEW_TIMERS,"LdGx","IKE_SIDE",my_side,my_spi,timers);
  return timers;
}


rhp_childsa_timers* rhp_childsa_new_timers(u32 spi_inb,u32 spi_outb)
{
  rhp_childsa_timers* timers = NULL;

  timers = (rhp_childsa_timers*)_rhp_malloc(sizeof(rhp_childsa_timers));
  if( timers == NULL ){
    RHP_BUG("");
    return NULL;
  }
  memset(timers,0,sizeof(rhp_childsa_timers));

  timers->tag[0] = '#';
  timers->tag[1] = 'V';
  timers->tag[2] = 'C';
  timers->tag[3] = 'T';

  timers->spi_inb = spi_inb;
  timers->spi_outb = spi_outb;

  rhp_timer_init(&(timers->lifetime_timer),_rhp_childsa_lifetime_timer,NULL);

  timers->start_lifetime_timer = _rhp_childsa_start_lifetime_timer;
  timers->quit_lifetime_timer = _rhp_childsa_quit_lifetime_timer;

  timers->schedule_delete = _rhp_childsa_schedule_delete;

  RHP_TRC(0,RHPTRCID_CHILDSA_NEW_TIMERS,"HHx",spi_inb,spi_outb,timers);
  return timers;
}

rhp_childsa_timers* rhp_ipsecsa_v1_new_timers(u32 spi_inb,u32 spi_outb)
{
  rhp_childsa_timers* timers = NULL;

  timers = (rhp_childsa_timers*)_rhp_malloc(sizeof(rhp_childsa_timers));
  if( timers == NULL ){
    RHP_BUG("");
    return NULL;
  }
  memset(timers,0,sizeof(rhp_childsa_timers));

  timers->tag[0] = '#';
  timers->tag[1] = 'V';
  timers->tag[2] = 'C';
  timers->tag[3] = 'T';

  timers->spi_inb = spi_inb;
  timers->spi_outb = spi_outb;

  rhp_timer_init(&(timers->lifetime_timer),_rhp_ipsecsa_v1_lifetime_timer,NULL);

  timers->start_lifetime_timer = _rhp_childsa_start_lifetime_timer;
  timers->quit_lifetime_timer = _rhp_childsa_quit_lifetime_timer;

  timers->schedule_delete = _rhp_ipsecsa_v1_schedule_delete;

  RHP_TRC(0,RHPTRCID_IPSECSA_V1_NEW_TIMERS,"HHx",spi_inb,spi_outb,timers);
  return timers;
}



rhp_vpn_ref* rhp_vpn_get_in_valid_rlm_cfg(unsigned long rlm_id,rhp_ikev2_id* peer_id)
{
  int err = -EINVAL;
  rhp_vpn_realm* rlm;
  rhp_vpn *vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;

  RHP_TRC(0,RHPTRCID_VPN_GET_IN_VALID_RLM_CFG,"ux",rlm_id,peer_id);
  rhp_ikev2_id_dump("peer_id",peer_id);


  rlm = rhp_realm_get(rlm_id);
  if( rlm == NULL ){
    err = -ENOENT;
    RHP_TRC(0,RHPTRCID_VPN_GET_IN_VALID_RLM_CFG_NO_REALM,"u",rlm_id);
    goto error;
  }

  RHP_LOCK(&(rlm->lock));
  {
  	int eap_enabled = rhp_eap_sup_impl_is_enabled(rlm,NULL);

		rhp_ikev2_id_dump("rlm->my_auth.my_id",&(rlm->my_auth.my_id));

		if( rlm->my_auth.my_id.type == 0 && !eap_enabled ){
			err = -ENOENT;
			RHP_TRC(0,RHPTRCID_VPN_GET_IN_VALID_RLM_CFG_NO_MY_ID_CFG,"uxdd",rlm_id,rlm,rlm->my_auth.my_id.type,eap_enabled);
			goto error_rlm_l;
		}

		if( rlm->internal_ifc->ifc == NULL ){
			err = -ENOENT;
			RHP_TRC(0,RHPTRCID_VPN_GET_IN_VALID_RLM_CFG_NO_INTERNAL_IF,"uxs",rlm_id,rlm,rlm->internal_ifc->if_name);
			goto error_rlm_l;
		}

		if( peer_id->alt_id ){

			vpn_ref = rhp_vpn_get(rlm->id,peer_id,NULL);
			vpn = RHP_VPN_REF(vpn_ref);

		}else{

			vpn_ref = rhp_vpn_get_no_alt_id(rlm->id,peer_id,NULL);
			vpn = RHP_VPN_REF(vpn_ref);

			if( vpn == NULL ){

				vpn_ref = rhp_vpn_ikesa_spi_get_by_peer_id(rlm->id,peer_id,1);
				vpn = RHP_VPN_REF(vpn_ref);
			}
		}

		if( vpn == NULL ){
			err = -ENOENT;
			RHP_TRC(0,RHPTRCID_VPN_GET_IN_VALID_RLM_CFG_NO_VPN,"ux",rlm_id,rlm);
			goto error_rlm_l;
		}
  }
	RHP_UNLOCK(&(rlm->lock));
	rhp_realm_unhold(rlm);
	rlm = NULL;


  RHP_TRC(0,RHPTRCID_VPN_GET_IN_VALID_RLM_CFG_RTRN,"uxxxx",rlm_id,peer_id,vpn,rlm,vpn_ref);

  return vpn_ref;


error_rlm_l:
	if( rlm ){
		RHP_UNLOCK(&(rlm->lock));
		rhp_realm_unhold(rlm);
	}
error:

  RHP_TRC(0,RHPTRCID_VPN_GET_IN_VALID_RLM_CFG_ERR,"uxE",rlm_id,peer_id,err);
  return NULL;
}

static int _rhp_vpn_internal_route_update_enum_ip_cb(rhp_ip_addr* ipaddr,rhp_route_map* rtmap)
{
  RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_UPDATE_ENUM_IP_CB,"xx",ipaddr,rtmap);
  rhp_ip_addr_dump("internal_route_update_enum_ip_cb",ipaddr);
  rhp_rtmap_dump("internal_route_update_enum_ip_cb",rtmap);

	if( ipaddr->addr_family != rtmap->dest_addr.addr_family &&
			ipaddr->addr_family != rtmap->gateway_addr.addr_family ){
	  RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_UPDATE_ENUM_IP_CB_BAD_ADDR_FAMILY,"xx",ipaddr,rtmap);
		return 0;
	}

	if( rhp_ip_addr_null(ipaddr) ||
			rhp_ip_is_linklocal(ipaddr->addr_family,ipaddr->addr.raw) ){

	  RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_UPDATE_ENUM_IP_CB_NULL_OR_LINK_LOCAL_ADDR,"xx",ipaddr,rtmap);
		return 0;
	}

	if( !rhp_ip_addr_null(&(rtmap->dest_addr)) ){ // Not default route.

		if( rtmap->dest_addr.prefixlen && ipaddr->prefixlen ){

			int prefix_len = ( rtmap->dest_addr.prefixlen > ipaddr->prefixlen ?
												 rtmap->dest_addr.prefixlen : ipaddr->prefixlen );

			if( rhp_ip_same_subnet2(ipaddr->addr_family,
							rtmap->dest_addr.addr.raw,ipaddr->addr.raw,prefix_len) ){
			  RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_UPDATE_ENUM_IP_CB_FOUND_0,"xx",ipaddr,rtmap);
				return 1;
			}
		}
	}

  RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_UPDATE_ENUM_IP_CB_FOUND_1,"xx",ipaddr,rtmap);
	return 1;
}

static int _rhp_vpn_internal_route_update_enum_ipv4_cb(rhp_ip_addr* ipaddr,void* ctx)
{
	rhp_route_map* rtmap = (rhp_route_map*)ctx;

	if( ipaddr->addr_family != AF_INET ){
		return 0;
	}

	return _rhp_vpn_internal_route_update_enum_ip_cb(ipaddr,rtmap);
}

static int _rhp_vpn_internal_route_update_enum_ipv6_cb(rhp_ip_addr* ipaddr,void* ctx)
{
	rhp_route_map* rtmap = (rhp_route_map*)ctx;

	if( ipaddr->addr_family != AF_INET6 ){
		return 0;
	}

	return _rhp_vpn_internal_route_update_enum_ip_cb(ipaddr,rtmap);
}

rhp_ip_addr* rhp_vpn_internal_route_get_gw_addr(int addr_family,
		rhp_vpn_realm* rlm,rhp_vpn* vpn,rhp_route_map* rtmap)
{
	rhp_ip_addr* gateway_addr_p = NULL;

	RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_GET_GW_ADDR,"LdxxxLdLds","AF",addr_family,rlm,vpn,rtmap,"AF",(rtmap ? rtmap->dest_addr.addr_family : AF_UNSPEC),"AF",(rtmap ? rtmap->gateway_addr.addr_family : AF_UNSPEC),(rtmap ? rtmap->tx_interface : NULL));

	if( rtmap &&
			((rtmap->dest_addr.addr_family != addr_family && rtmap->gateway_addr.addr_family != addr_family) ||
				rtmap->tx_interface) ){
		goto error;
	}

	if( addr_family == AF_INET ){

		if( rtmap ){

			gateway_addr_p = rhp_ip_search_addr_list(
											vpn->internal_net_info.peer_addrs,
											_rhp_vpn_internal_route_update_enum_ipv4_cb,(void*)rtmap);

			RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_GET_GW_ADDR_V4_1,"Ldxxxx","AF",addr_family,rlm,vpn,rtmap,gateway_addr_p);
		}

		if( gateway_addr_p == NULL ){

				gateway_addr_p = rhp_ip_search_addr_list(
													vpn->internal_net_info.peer_addrs,
													rhp_ip_search_addr_list_cb_addr_family_no_linklocal,(void*)AF_INET);

				RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_GET_GW_ADDR_V4_2,"Ldxxxx","AF",addr_family,rlm,vpn,rtmap,gateway_addr_p);
		}

		if( gateway_addr_p == NULL &&
				!rhp_ip_addr_null(&(rlm->ext_internal_gateway_addr)) ){

			gateway_addr_p = &(rlm->ext_internal_gateway_addr);

			RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_GET_GW_ADDR_V4_3,"Ldxxxx","AF",addr_family,rlm,vpn,rtmap,gateway_addr_p);
		}

		if( gateway_addr_p == NULL ){

			gateway_addr_p = rhp_ip_search_addr_list(
												vpn->internal_net_info.peer_addrs,
												rhp_ip_search_addr_list_cb_addr_family,(void*)AF_INET);

			RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_GET_GW_ADDR_V4_4,"Ldxxxx","AF",addr_family,rlm,vpn,rtmap,gateway_addr_p);
		}

	}else if( addr_family == AF_INET6 ){

		if( rtmap ){

			gateway_addr_p = rhp_ip_search_addr_list(
											vpn->internal_net_info.peer_addrs,
											_rhp_vpn_internal_route_update_enum_ipv6_cb,(void*)rtmap);

			RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_GET_GW_ADDR_V6_1,"Ldxxxx","AF",addr_family,rlm,vpn,rtmap,gateway_addr_p);
		}

		if( gateway_addr_p == NULL ){

			gateway_addr_p = rhp_ip_search_addr_list(
												vpn->internal_net_info.peer_addrs,
												rhp_ip_search_addr_list_cb_addr_family_no_linklocal,(void*)AF_INET6);

			RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_GET_GW_ADDR_V6_2,"Ldxxxx","AF",addr_family,rlm,vpn,rtmap,gateway_addr_p);
		}

		if( gateway_addr_p == NULL &&
				!rhp_ip_addr_null(&(rlm->ext_internal_gateway_addr_v6)) ){

			gateway_addr_p = &(rlm->ext_internal_gateway_addr_v6);

			RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_GET_GW_ADDR_V6_3,"Ldxxxx","AF",addr_family,rlm,vpn,rtmap,gateway_addr_p);
		}

		if( gateway_addr_p == NULL ){

			gateway_addr_p = rhp_ip_search_addr_list(
												vpn->internal_net_info.peer_addrs,
												rhp_ip_search_addr_list_cb_addr_family,(void*)AF_INET6);

			RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_GET_GW_ADDR_V6_4,"Ldxxxx","AF",addr_family,rlm,vpn,rtmap,gateway_addr_p);
		}

	}else{

		RHP_BUG("%d",addr_family);
	}


error:
	RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_GET_GW_ADDR_RTRN,"Ldxxxx","AF",addr_family,rlm,vpn,rtmap,gateway_addr_p);
	if( gateway_addr_p ){
	  rhp_ip_addr_dump("gateway_addr_p",gateway_addr_p);
	}

	return gateway_addr_p;
}

static int _rhp_vpn_internal_route_update_enum_cb_impl(rhp_vpn_realm* rlm,
		rhp_route_map* rtmap,rhp_vpn* vpn)
{
	int err = -EINVAL;
	rhp_ip_addr* gateway_addr_p = NULL;
	int addr_family = rtmap->dest_addr.addr_family;

	if( addr_family != AF_INET && addr_family != AF_INET6 ){
		addr_family = rtmap->gateway_addr.addr_family;
	}

	RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_UPDATE_ENUM_CB_IMPL,"xxx","AF",addr_family,rlm,rtmap,vpn);
	rhp_rtmap_dump("internal_route_update_enum_cb_impl",rtmap);


	if( addr_family == AF_INET || addr_family == AF_INET6 ){

		gateway_addr_p = rhp_vpn_internal_route_get_gw_addr(addr_family,rlm,vpn,rtmap);

		if( gateway_addr_p &&
				rhp_ip_addr_null(&(rtmap->gateway_addr)) ){

			memcpy(&(rtmap->gateway_addr),gateway_addr_p,sizeof(rhp_ip_addr));
		}
	}

	if( gateway_addr_p == NULL &&
			(rtmap->tx_interface == NULL || rtmap->tx_interface[0] == '\0') &&
			rhp_ip_addr_null(&(rtmap->gateway_addr)) ){

		err = -ENOENT;
		RHP_BUG("");
		goto error;
	}

	err = rhp_ipc_send_update_route(rlm,rtmap,gateway_addr_p);
	if( err ){
		RHP_BUG("%d",err);
	}

	vpn->route_updated++;

error:
	rhp_ip_addr_dump("gateway_addr_p",gateway_addr_p);
  RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_UPDATE_ENUM_CB_IMPL_RTRN,"xxdE",rlm,rtmap,vpn->route_updated,err);
	return err;
}

static int _rhp_vpn_internal_route_update_enum_cb(rhp_vpn_realm* rlm,
		rhp_ikev2_id* peer_id,rhp_route_map* rtmap,void* ctx)
{
	int err = -EINVAL;
	rhp_vpn* vpn = (rhp_vpn*)ctx;

	err = _rhp_vpn_internal_route_update_enum_cb_impl(rlm,rtmap,vpn);

  RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_UPDATE_ENUM_CB,"xxxxdE",rlm,peer_id,rtmap,ctx,vpn->route_updated,err);
	return err;
}

static int _rhp_vpn_internal_route_update_enum_cb2(rhp_vpn_realm* rlm,
		rhp_route_map* rtmap,void* ctx)
{
	int err = -EINVAL;
	rhp_vpn* vpn = (rhp_vpn*)ctx;

	err = _rhp_vpn_internal_route_update_enum_cb_impl(rlm,rtmap,vpn);

  RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_UPDATE_ENUM_CB2,"xxxdE",rlm,rtmap,ctx,vpn->route_updated,err);
	return err;
}

static void _rhp_vpn_internal_route_update_handler(void* ctx)
{
	int err = -EINVAL;
	rhp_vpn_ref* vpn_ref = (rhp_vpn_ref*)ctx;
	rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);
	rhp_vpn_realm* rlm = NULL;
	int route_updated = 0;

  RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_UPDATE_HANLDER,"xxuxd",vpn,vpn_ref,vpn->vpn_realm_id,vpn->rlm,vpn->route_updated);

  RHP_LOCK(&(vpn->lock));

  rlm = vpn->rlm;

  if( rlm == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  RHP_LOCK(&(rlm->lock));

	if( !_rhp_atomic_read(&(rlm->is_active)) ){
	  RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_UPDATE_HANLDER_RLM_NOT_ACTIVE,"xxu",vpn,rlm,vpn->vpn_realm_id);
		goto error_l;
	}

	{
		err = rlm->enum_route_map_by_peerid(rlm,&(vpn->peer_id),_rhp_vpn_internal_route_update_enum_cb,vpn);
		if( err == -ENOENT ){
			err = 0;
		}else if( err ){
			RHP_BUG("%d",err);
			goto error_l;
		}
	}

	{
		err = rlm->enum_route_map_by_ikev2_cfg(rlm,_rhp_vpn_internal_route_update_enum_cb2,vpn);
		if( err == -ENOENT ){
			err = 0;
		}else if( err ){
			RHP_BUG("%d",err);
			goto error_l;
		}
	}

	route_updated = vpn->route_updated;

	RHP_UNLOCK(&(rlm->lock));
	RHP_UNLOCK(&(vpn->lock));

	rhp_vpn_unhold(vpn_ref);

  RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_UPDATE_HANLDER_RTRN,"xxd",vpn,vpn_ref,route_updated);
	return;

error_l:
	if( rlm ){
		RHP_UNLOCK(&(rlm->lock));
	}
error:
	RHP_UNLOCK(&(vpn->lock));

	rhp_vpn_unhold(vpn_ref);

	RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_UPDATE_HANLDER_ERR,"xxE",vpn,vpn_ref,err);
	return;
}

int rhp_vpn_internal_route_update_impl(rhp_vpn* vpn,time_t conv_interval)
{
	int err = -EINVAL;
	rhp_vpn_ref* vpn_ref;

	RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_UPDATE,"xuxd",vpn,vpn->vpn_realm_id,vpn->rlm,vpn->route_updated);

	vpn_ref = rhp_vpn_hold_ref(vpn);

	err = rhp_timer_oneshot(_rhp_vpn_internal_route_update_handler,(void*)vpn_ref,conv_interval);
	if( err ){

		rhp_vpn_unhold(vpn_ref);

		RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_UPDATE_ERR,"xuxE",vpn,vpn->vpn_realm_id,vpn->rlm,err);
		return err;
	}

	RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_UPDATE_RTRN,"xux",vpn,vpn->vpn_realm_id,vpn->rlm);
	return 0;
}

int rhp_vpn_internal_route_update(rhp_vpn* vpn)
{
	return rhp_vpn_internal_route_update_impl(vpn,(time_t)rhp_gcfg_net_event_convergence_interval);
}

static int _rhp_vpn_internal_route_delete_enum_cb(rhp_vpn_realm* rlm,rhp_ikev2_id* peer_id,rhp_route_map* rtmap,void* ctx)
{
	int err = -EINVAL;
	rhp_vpn* vpn = (rhp_vpn*)ctx;

	err = rhp_ipc_send_delete_route(rlm,rtmap,NULL);
	if( err ){
		RHP_BUG("%d",err);
	}

	vpn->route_updated--;

  RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_DELETE_ENUM_CB,"xxxxdE",rlm,peer_id,rtmap,ctx,vpn->route_updated,err);
	return err;
}

static int _rhp_vpn_internal_route_delete_enum_cb2(rhp_vpn_realm* rlm,rhp_route_map* rtmap,void* ctx)
{
	int err = -EINVAL;
	rhp_vpn* vpn = (rhp_vpn*)ctx;

	err = rhp_ipc_send_delete_route(rlm,rtmap,NULL);
	if( err ){
		RHP_BUG("%d",err);
	}

	vpn->route_updated--;

  RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_DELETE_ENUM_CB2,"xxxdE",rlm,rtmap,ctx,vpn->route_updated,err);
	return err;
}

int rhp_vpn_internal_route_delete(rhp_vpn* vpn,rhp_vpn_realm* c_rlm)
{
	int err = -EINVAL;
	rhp_vpn_realm* rlm = c_rlm;

  RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_DELETE,"xxud",vpn,c_rlm,vpn->vpn_realm_id,vpn->route_updated);

	if( !vpn->route_updated ){
	  RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_DELETE_NO_ENT,"xxu",vpn,c_rlm,vpn->vpn_realm_id);
		return 0;
	}


	if( rlm == NULL ){

		rlm = vpn->rlm;

		if( rlm == NULL ){
		  RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_DELETE_NO_RLM_ERR,"xu",vpn,vpn->vpn_realm_id);
			err = -EINVAL;
			goto error;
		}

		RHP_LOCK(&(rlm->lock));
	}

	if( !_rhp_atomic_read(&(rlm->is_active)) ){
	  RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_DELETE_RLM_NOT_ACTIVE,"xxu",vpn,c_rlm,vpn->vpn_realm_id);
		goto error_l;
	}

	{
		err = rlm->enum_route_map_by_peerid(rlm,&(vpn->peer_id),_rhp_vpn_internal_route_delete_enum_cb,vpn);

		if( err == -ENOENT ){
			err = 0;
		}else if( err ){
			RHP_BUG("%d",err);
			goto error_l;
		}
	}

	{
		err = rlm->enum_route_map_by_ikev2_cfg(rlm,_rhp_vpn_internal_route_delete_enum_cb2,vpn);

		if( err == -ENOENT ){
			err = 0;
		}else if( err ){
			RHP_BUG("%d",err);
			goto error_l;
		}
	}

	if( c_rlm == NULL ){
		RHP_UNLOCK(&(rlm->lock));
	}

  RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_DELETE_RTRN,"xxud",vpn,c_rlm,vpn->vpn_realm_id,vpn->route_updated);
	return 0;

error_l:
	if( rlm && (c_rlm == NULL) ){
		RHP_UNLOCK(&(rlm->lock));
	}
error:
	RHP_TRC(0,RHPTRCID_VPN_INTERNAL_ROUTE_DELETE_ERR,"xxuE",vpn,c_rlm,vpn->vpn_realm_id,err);
	return err;
}

int rhp_vpn_cleanup_by_realm_id(unsigned long rlm_id,int only_dormant)
{
	int err = -EINVAL;
	u8 *unique_ids = NULL,* unique_id = NULL;
	int unique_ids_num = 0;
	int free_by_caller = 0;
	int i;

  RHP_TRC(0,RHPTRCID_VPN_CLEANUP_BY_REALM_ID,"ud",rlm_id,only_dormant);

	err = rhp_vpn_enum_unique_ids2(rlm_id,1,&unique_ids,&unique_ids_num,&free_by_caller);
	if( err && err != -ENOENT ){
	  RHP_TRC(0,RHPTRCID_VPN_CLEANUP_BY_REALM_ID_NO_ENT,"u",rlm_id);
		goto error;
	}
	err = 0;

	unique_id = unique_ids;
	for( i = 0; i < unique_ids_num; i++ ){

		rhp_vpn_ref* vpn_ref = rhp_vpn_get_by_unique_id(unique_id);
		rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);

		if( vpn ){

			RHP_LOCK(&(vpn->lock));
			{
				if( !only_dormant ||
						(vpn->exec_mobike &&
								((vpn->origin_side == RHP_IKE_INITIATOR && (vpn->mobike.init.rt_ck_pending || vpn->mobike.init.rt_ck_waiting)) ||
						     (vpn->origin_side == RHP_IKE_RESPONDER && vpn->mobike.resp.keepalive_pending))) ){

					rhp_vpn_internal_address_free(vpn,1); // Address Pool

					if( vpn->eap.eap_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS &&
							!vpn->radius.acct_term_cause ){
						vpn->radius.acct_term_cause = RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_ADMIN_RESET;
					}

					rhp_vpn_destroy(vpn);
				}
			}
			RHP_UNLOCK(&(vpn->lock));

  		rhp_vpn_unhold(vpn_ref);

		}else{
		  RHP_TRC(0,RHPTRCID_VPN_CLEANUP_BY_REALM_ID_NOT_FOUND,"up",rlm_id,RHP_VPN_UNIQUE_ID_SIZE,unique_id);
		}

		unique_id += RHP_VPN_UNIQUE_ID_SIZE;
	}

	if( free_by_caller ){
		_rhp_free(unique_ids);
	}

  RHP_TRC(0,RHPTRCID_VPN_CLEANUP_BY_REALM_ID_RTRN,"u",rlm_id);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_VPN_CLEANUP_BY_REALM_ID_ERR,"uE",rlm_id,err);
	return err;
}

rhp_vpn_ref* rhp_vpn_get_access_point_peer(unsigned long rlm_id)
{
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;

  RHP_TRC(0,RHPTRCID_VPN_GET_ACCESS_POINT_PEER,"u",rlm_id);

  RHP_LOCK(&rhp_vpn_lock);

	vpn = rhp_vpn_list_head.next_list;
	while( vpn  ){

    if( (vpn->vpn_realm_id == rlm_id) &&
    		vpn->cfg_peer &&
    		vpn->cfg_peer->is_access_point ){

    	break;
    }

		vpn = vpn->next_list;
	}

	if( vpn ){

		vpn_ref = rhp_vpn_hold_ref(vpn);

		RHP_TRC(0,RHPTRCID_VPN_GET_ACCESS_POINT_PEER_RTRN,"xpuxx",vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm,vpn_ref);

	}else{
		RHP_TRC(0,RHPTRCID_VPN_GET_ACCESS_POINT_PEER_NO_ENTRY,"u",rlm_id);
	}

  RHP_UNLOCK(&rhp_vpn_lock);

  return vpn_ref;
}
