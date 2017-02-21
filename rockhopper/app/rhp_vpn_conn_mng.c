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
#include <netdb.h>


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
#include "rhp_wthreads.h"
#include "rhp_http.h"
#include "rhp_eap.h"
#include "rhp_eap_auth_impl.h"
#include "rhp_eap_sup_impl.h"
#include "rhp_nhrp.h"


static rhp_mutex_t _rhp_vpn_conn_mng_lock;

static u64 _rhp_vpn_objid_last = 1;

struct _rhp_vpn_aoc_peer {

	u8 tag[4]; // '#AOC'

	struct _rhp_vpn_aoc_peer* lst_prev;
	struct _rhp_vpn_aoc_peer* lst_next;

	unsigned long rlm_id;
	rhp_ikev2_id peer_id;

	rhp_ip_addr peer_addr;
	char* peer_addr_fqdn;

	u64 objid;
};
typedef struct _rhp_vpn_aoc_peer		rhp_vpn_aoc_peer;

static rhp_vpn_aoc_peer _rhp_vpn_aoc_peers;

static rhp_timer _rhp_vpn_aoc_timer;
static void _rhp_vpn_aoc_timer_handler(void *ctx,rhp_timer *timer);


int rhp_vpn_conn_mng_init()
{
  _rhp_mutex_init("VCM",&(_rhp_vpn_conn_mng_lock));

  memset(&_rhp_vpn_aoc_peers,0,sizeof(rhp_vpn_aoc_peer));
  _rhp_vpn_aoc_peers.tag[0] = '#';
  _rhp_vpn_aoc_peers.tag[1] = 'A';
  _rhp_vpn_aoc_peers.tag[2] = 'O';
  _rhp_vpn_aoc_peers.tag[3] = 'C';

  rhp_timer_init(&(_rhp_vpn_aoc_timer),_rhp_vpn_aoc_timer_handler,NULL);

  RHP_TRC(0,RHPTRCID_VPN_AOC_PEER_INIT,"");
  return 0;
}

//
// [CAUTION]
//
//  If -EEXIST or zero is returnd and old_vpn_r is specified, *old_vpn_r may NOT be NULL,
//
static int _rhp_vpn_conn_i_check_old_vpn(unsigned long rlm_id,
		rhp_ikev2_id* peer_id,
		rhp_ip_addr* peer_addr0,rhp_ip_addr* peer_addr1,
		rhp_vpn_ref** old_vpn_ref_r)
{
  rhp_vpn* old_vpn = NULL;
  void* old_vpn_ref = NULL;
	rhp_ikesa* cur_ikesa = NULL;

	RHP_TRC_FREQ(0,RHPTRCID_VPN_CONN_I_CHECK_OLD_VPN,"uxxxx",rlm_id,peer_id,peer_addr0,peer_addr1,old_vpn_ref_r);

	if( peer_id ){

		if( peer_id->alt_id ){

			old_vpn_ref = rhp_vpn_get(rlm_id,peer_id,NULL);
			old_vpn = RHP_VPN_REF(old_vpn_ref);

		}else{

			old_vpn_ref = rhp_vpn_get_no_alt_id(rlm_id,peer_id,NULL);
			old_vpn = RHP_VPN_REF(old_vpn_ref);

			if( old_vpn == NULL ){

				old_vpn_ref = rhp_vpn_ikesa_spi_get_by_peer_id(rlm_id,peer_id,1);
				old_vpn = RHP_VPN_REF(old_vpn_ref);
			}
		}
	}

	if( (old_vpn == NULL) && peer_addr0 ){

		old_vpn_ref = rhp_vpn_get_by_peer_addr(rlm_id,peer_addr0,peer_addr1);
		old_vpn = RHP_VPN_REF(old_vpn_ref);
	}

  if( old_vpn ){

  	int err = 0;

  	RHP_LOCK(&(old_vpn->lock));

  	RHP_TRC(0,RHPTRCID_VPN_CONN_I_CHECK_OLD_VPN_OLD_VPN,"xpuxdd",old_vpn,RHP_VPN_UNIQUE_ID_SIZE,old_vpn->unique_id,old_vpn->vpn_realm_id,old_vpn->rlm,old_vpn->ikesa_num,old_vpn->childsa_num);
  	rhp_ikev2_id_dump("vpn->my_id",&(old_vpn->my_id));
  	rhp_ikev2_id_dump("vpn->peer_id",&(old_vpn->peer_id));

  	if( !_rhp_atomic_read(&(old_vpn->is_active)) ){

  		RHP_UNLOCK(&(old_vpn->lock));
      rhp_vpn_unhold(old_vpn_ref);

  		RHP_TRC(0,RHPTRCID_VPN_CONN_I_CHECK_OLD_VPN_NOT_ACTIVE,"x",old_vpn);
  		return -ENOENT;
    }

  	cur_ikesa = old_vpn->ikesa_list_head;
  	while( cur_ikesa ){

  	  RHP_TRC(0,RHPTRCID_VPN_CONN_I_CHECK_OLD_VPN_OLD_VPN_IKESA,"xxLdGGLd",old_vpn,cur_ikesa,"IKE_SIDE",cur_ikesa->side,cur_ikesa->init_spi,cur_ikesa->resp_spi,"IKESA_STAT",cur_ikesa->state);

  		if( cur_ikesa->state != RHP_IKESA_STAT_DELETE &&
  				cur_ikesa->state != RHP_IKESA_STAT_DELETE_WAIT &&
  				cur_ikesa->state != RHP_IKESA_STAT_DEAD ){
  			break;
      }

  		cur_ikesa = cur_ikesa->next_vpn_list;
  	}

  	if( cur_ikesa ){

  		RHP_TRC(0,RHPTRCID_VPN_CONN_I_CHECK_OLD_VPN_ACTIVE_IKESA_FOUND,"uxxx",old_vpn->vpn_realm_id,peer_id,old_vpn,cur_ikesa);

      err = -EEXIST;

  	}else{

  		RHP_TRC(0,RHPTRCID_RHPTRCID_VPN_CONN_I_CHECK_OLD_VPN_NO_ACTIVE_IKESA,"uxx",old_vpn->vpn_realm_id,peer_id,old_vpn);

  		err = 0;
  	}

  	if( old_vpn_ref_r ){
  		*old_vpn_ref_r = rhp_vpn_hold_ref(old_vpn);
  	}

  	RHP_UNLOCK(&(old_vpn->lock));
    rhp_vpn_unhold(old_vpn_ref);

    return err;
  }

	RHP_TRC_FREQ(0,RHPTRCID_VPN_CONN_I_CHECK_OLD_VPN_NOENT,"uxx",rlm_id,peer_id,old_vpn);
  return -ENOENT;
}

static int _rhp_vpn_connect_i_cleanup_old_vpn(unsigned long rlm_id,
		rhp_ikev2_id* peer_id,
		rhp_ip_addr* peer_addr0,rhp_ip_addr* peer_addr1,
		rhp_ui_ctx* ui_info)
{
	int err = -EINVAL;
  rhp_vpn_ref* old_vpn_ref = NULL;
  rhp_vpn* old_vpn = NULL;

	RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_CLEANUP_OLD_VPN,"uxxxx",rlm_id,peer_id,peer_addr0,peer_addr1,ui_info);

  err = _rhp_vpn_conn_i_check_old_vpn(rlm_id,peer_id,
  				peer_addr0,peer_addr1,&old_vpn_ref);
  old_vpn = RHP_VPN_REF(old_vpn_ref);
  if( !err ){

    RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_CLEANUP_OLD_VPN_NO_ACTIVE_IKESA,"uxx",rlm_id,peer_id,ui_info);

    if( old_vpn ){

    	RHP_LOCK(&(old_vpn->lock));

			rhp_vpn_destroy(old_vpn);

			RHP_UNLOCK(&(old_vpn->lock));
			rhp_vpn_unhold(old_vpn_ref);
    }

  }else if( err == -EEXIST ){

		RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_CLEANUP_OLD_VPN_ACTIVE_IKESA_FOUND,"uxxx",rlm_id,peer_id,ui_info,old_vpn);

		if( old_vpn ){

			if( ui_info ){

				RHP_LOCK(&(old_vpn->lock));

				memcpy(&(old_vpn->ui_info),ui_info,sizeof(rhp_ui_ctx));

				RHP_UNLOCK(&(old_vpn->lock));
			}

			rhp_vpn_unhold(old_vpn_ref);
		}

		return -EEXIST;
  }

  RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_CLEANUP_OLD_VPN_NO_ACTIVE_IKESA,"uxxxE",rlm_id,peer_id,ui_info,old_vpn,err);
  return 0;
}

static int _rhp_vpn_connect_i_check_eap_sup(
		rhp_vpn_realm* rlm,
		rhp_eap_sup_info* eap_sup_i,
		int exec_auto_reconnect,
		int eap_sup_method,
		u8* eap_sup_user_id,int eap_sup_user_id_len,
		u8* eap_sup_user_key,int eap_sup_user_key_len)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_CHECK_EAP_SUP,"xxddpp",rlm,eap_sup_i,exec_auto_reconnect,eap_sup_method,eap_sup_user_id_len,eap_sup_user_id,eap_sup_user_key_len,eap_sup_user_key);

	if( !exec_auto_reconnect ){ // Caller is a user or a AOC task.

		if( eap_sup_method ){

			if( eap_sup_i->eap_method != eap_sup_method ){
				err = -EINVAL;
				RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_INVALID_EAP_SUP_METHOD,"uxdd",rlm->id,rlm,eap_sup_i->eap_method,eap_sup_method);
				goto error;
			}

			if( eap_sup_i->ask_for_user_key &&
					( eap_sup_user_id_len == 0 || eap_sup_user_id == NULL ||
						eap_sup_user_key_len == 0 || eap_sup_user_key == NULL ) ){

				err = RHP_STATUS_CONNECT_VPN_I_EAP_SUP_USER_KEY_NEEDED;
				RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_NO_EAP_SUP_USER_KEY,"uxd",rlm->id,rlm,eap_sup_i->eap_method);
				goto error;
			}

		}else{

			if( eap_sup_i->ask_for_user_key ){ // No user_id and password are saved in conf.

				if( !eap_sup_i->user_key_cache_enabled ||
						!eap_sup_i->user_key_is_cached ){

					// User_id and password may be cached in protected process.
					// If the cache exists, rockhopper can use them as EAP peer's auth info.
					// So caller must confirm the cache in protected process.
					//
					// Otherwise, a cache of user_id and password is not allowed by config.
					// User must specify them when connecting vpn.

					err = RHP_STATUS_CONNECT_VPN_I_EAP_SUP_USER_KEY_NEEDED;
					RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_EAP_SUP_USER_KEY_NEEDED,"uxd",rlm->id,rlm,eap_sup_i->eap_method);
					goto error;
				}
			}
		}

	}else{

		// Caller want to auto-reconnect the vpn.

		if( !eap_sup_i->user_key_cache_enabled ||
				!eap_sup_i->user_key_is_cached ){

			err = RHP_STATUS_CONNECT_VPN_I_EAP_SUP_USER_KEY_NEEDED;

			RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_EAP_SUP_USER_KEY_NOT_CACHED_FOR_AUTO_RECONNECT,"uxd",rlm->id,rlm,eap_sup_i->eap_method);
			goto error;
		}
	}

	RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_CHECK_EAP_SUP_RTRN,"xx",rlm,eap_sup_i);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_CHECK_EAP_SUP_ERR,"xxE",rlm,eap_sup_i,err);
	return err;
}

static int _rhp_vpn_connect_i_check_cfg_peer(
		rhp_vpn_realm* rlm,
		rhp_ikev2_id* dmy_peer_id,
		rhp_ikev2_id** peer_id_r,
		rhp_ip_addr** peer_addr_r,
		char* peer_fqdn,
		rhp_ip_addr** peer_fqdn_addr_secondary_p_r,
		rhp_ikev2_id* res_peer_id_r,
	  rhp_cfg_peer** cfg_peer_r)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_CHECK_CFG_PEER,"xxxxxxxx",rlm,dmy_peer_id,peer_id_r,peer_addr_r,peer_fqdn,peer_fqdn_addr_secondary_p_r,res_peer_id_r,cfg_peer_r);

	if( (*peer_id_r == NULL) && *peer_addr_r ){

		*cfg_peer_r = rlm->get_peer_by_primary_addr(rlm,*peer_addr_r);
		if( *cfg_peer_r == NULL ){

			if( *peer_fqdn_addr_secondary_p_r ){

				*cfg_peer_r = rlm->get_peer_by_primary_addr(rlm,*peer_fqdn_addr_secondary_p_r);
				if( *cfg_peer_r ){

					rhp_ip_addr* tmp_addr = *peer_addr_r;

					*peer_addr_r = *peer_fqdn_addr_secondary_p_r;
					*peer_fqdn_addr_secondary_p_r = tmp_addr;

					RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_SWAP_DNS_RSLV_PEER_ADDRS,"uxx",rlm->id,(peer_addr_r ? *peer_addr_r : NULL),(peer_fqdn_addr_secondary_p_r ? *peer_fqdn_addr_secondary_p_r : NULL));
				}
			}
		}

		if( *cfg_peer_r ){

			err = rhp_ikev2_id_dup(res_peer_id_r,&((*cfg_peer_r)->id));
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			*peer_id_r = res_peer_id_r;

			RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_ASIGN_PEER_ID_BY_ADDR,"ux",rlm->id,(peer_id_r ? *peer_id_r : NULL));
		  rhp_ikev2_id_dump("rhp_vpn_connect_i.peer_id",*peer_id_r);

		}else{

			RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_SEARCH_BY_PEER_ADDR_NO_ENT,"u",rlm->id);

			goto cfg_peer_get_by_id; // ANY_ID
		}

	}else{

cfg_peer_get_by_id:

		if( *peer_id_r == NULL ){

			*peer_id_r = dmy_peer_id;

			RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_ASIGN_DMY_PEER_ID,"ux",rlm->id,(peer_id_r ? *peer_id_r : NULL));
			rhp_ikev2_id_dump("rhp_vpn_connect_i.peer_id",(peer_id_r ? *peer_id_r : NULL));
		}

		*cfg_peer_r = rlm->get_peer_by_id(rlm,*peer_id_r);
		if( *cfg_peer_r == NULL ){

			err = -ENOENT;
			RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_NO_PEER_CFG,"ux",rlm->id,rlm);

			RHP_LOG_DE(RHP_LOG_SRC_UI,rlm->id,RHP_LOG_ID_CONNECT_I_NO_PEER_CFG_FOUND,"IAs",(peer_id_r ? *peer_id_r : NULL),(peer_addr_r ? *peer_addr_r : NULL),peer_fqdn);

			goto error;
		}
	}

	RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_CHECK_CFG_PEER_RTRN,"x",rlm);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_CHECK_CFG_PEER_ERR,"xE",rlm,err);
	return err;
}

static int _rhp_vpn_connect_i_setup_reconnect_info(
		rhp_vpn_realm* rlm,
		rhp_ikev2_id* peer_id,
		rhp_ip_addr* peer_addr,
		char* peer_fqdn,
		u16 peer_port,
		rhp_vpn *new_vpn,
		int auto_reconnect,int exec_auto_reconnect,int auto_reconnect_retries,
		rhp_vpn_reconnect_info** reconnect_info_r)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_SETUP_RECONNECT_INFO,"xxxxWxdddx",rlm,peer_id,peer_addr,peer_fqdn,peer_port,new_vpn,auto_reconnect,exec_auto_reconnect,auto_reconnect_retries,reconnect_info_r);

	*reconnect_info_r = (rhp_vpn_reconnect_info*)_rhp_malloc(sizeof(rhp_vpn_reconnect_info));
	if( *reconnect_info_r == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
  	goto error;
	}
	memset((*reconnect_info_r),0,sizeof(rhp_vpn_reconnect_info));

	(*reconnect_info_r)->tag[0] = '#';
	(*reconnect_info_r)->tag[1] = 'V';
	(*reconnect_info_r)->tag[2] = 'R';
	(*reconnect_info_r)->tag[3] = 'C';

	new_vpn->auto_reconnect = auto_reconnect;
	new_vpn->exec_auto_reconnect = exec_auto_reconnect;
	new_vpn->reconnect_info = *reconnect_info_r;

	(*reconnect_info_r)->rlm_id = rlm->id;

	if( peer_id ){

		err = rhp_ikev2_id_dup(&((*reconnect_info_r)->peer_id),peer_id);
		if( err ){
			RHP_BUG("");
    	goto error;
		}
	}

	if( peer_fqdn ){

		(*reconnect_info_r)->peer_fqdn = (char*)_rhp_malloc(strlen(peer_fqdn) + 1);
		if( (*reconnect_info_r)->peer_fqdn == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
    	goto error;
		}

		(*reconnect_info_r)->peer_fqdn[0] = '\0';
		strcpy((*reconnect_info_r)->peer_fqdn,peer_fqdn);

	}else if( peer_addr ){

		memcpy(&((*reconnect_info_r)->peer_addr),peer_addr,sizeof(rhp_ip_addr));
	}

	(*reconnect_info_r)->peer_port = peer_port;
	(*reconnect_info_r)->retries = auto_reconnect_retries;
	new_vpn->auto_reconnect_retries = auto_reconnect_retries;

	RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_SETUP_RECONNECT_INFO_RTRN,"x",rlm);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_SETUP_RECONNECT_INFO_ERR,"xE",rlm,err);
	return err;
}


static int _rhp_vpn_eap_sup_random_addr_id(int addr_family,u8* addr_r)
{
	if( addr_family == AF_INET ){

		rhp_random_bytes(addr_r,4);
		addr_r[0] = 0x0A; // 10.0.0.0/8 (Private)
    RHP_TRC(0,RHPTRCID_VPN_EAP_SUP_RANDOM_ADDR_ID_V4,"Ld4p","AF",addr_family,*((u32*)addr_r),4,addr_r);

	}else if( addr_family == AF_INET6 ){

		rhp_random_bytes(addr_r,16);
		addr_r[0] = 0xFD; // FD00::/8 (ULA)
    RHP_TRC(0,RHPTRCID_VPN_EAP_SUP_RANDOM_ADDR_ID_V6,"Ld6p","AF",addr_family,addr_r,16,addr_r);

	}else{
		RHP_BUG("%d",addr_family);
		return -EINVAL;
	}
	return 0;
}


#ifdef RHP_SESS_RESUME_DEBUG_1
extern rhp_vpn_sess_resume_material* rhp_sess_resume_material_i_c;
#endif // RHP_SESS_RESUME_DEBUG_1

int rhp_vpn_connect_i(unsigned long rlm_id,
			rhp_vpn_conn_args* conn_args,
			rhp_vpn_reconn_args* reconn_args,
			int is_initiated_by_user)
{
  int err = -EINVAL;

  rhp_ikev2_id* peer_id = conn_args->peer_id;
	rhp_ip_addr* peer_addr = conn_args->peer_addr;
	char* peer_fqdn = conn_args->peer_fqdn;
	rhp_ip_addr* peer_fqdn_addr_primary = conn_args->peer_fqdn_addr_primary;
	rhp_ip_addr* peer_fqdn_addr_secondary = conn_args->peer_fqdn_addr_secondary;
	u16 peer_port = conn_args->peer_port;
	rhp_ui_ctx* ui_info = conn_args->ui_info;
	int eap_sup_method = conn_args->eap_sup_method;
	u8* eap_sup_user_id = conn_args->eap_sup_user_id;
	int eap_sup_user_id_len = conn_args->eap_sup_user_id_len;
	u8* eap_sup_user_key = conn_args->eap_sup_user_key;
	int eap_sup_user_key_len = conn_args->eap_sup_user_key_len;

	int auto_reconnect = (reconn_args ? reconn_args->auto_reconnect : 0);
	int exec_auto_reconnect = (reconn_args ? reconn_args->exec_auto_reconnect : 0);
	int auto_reconnect_retries = (reconn_args ? reconn_args->auto_reconnect_retries : 0);
	rhp_vpn_sess_resume_material* sess_resume_material_i
		= (reconn_args ? reconn_args->sess_resume_material_i : NULL);

	rhp_vpn_realm* rlm = NULL;
  rhp_cfg_peer* cfg_peer = NULL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_ikesa* ikesa = NULL;
  rhp_vpn* new_vpn = NULL;
  rhp_vpn_ref* new_vpn_ref = NULL;
	time_t lifetime_larval;
	rhp_ikev2_id my_id;
	rhp_ikev2_id res_peer_id;
	rhp_ip_addr* peer_fqdn_addr_secondary_p = NULL;
	static rhp_ikev2_id dmy_peer_id = {
		  type: RHP_PROTO_IKE_ID_ANY,
		  cert_sub_type: 0,
		  string: NULL,
		  dn_der_len: 0,
		  dn_der: NULL
	};
	rhp_vpn_reconnect_info* reconnect_info = NULL;
  rhp_eap_sup_info eap_sup_i;
  rhp_ip_addr mobike_additional_addr;

  int use_fqdn = 0;
  int eap_sup_enabled = 0;
  int exec_sess_resume = 0, init_by_peer_addr = 0;
  int auth_tkt_enabled = 0;


#ifdef RHP_SESS_RESUME_DEBUG_1
  if( sess_resume_material_i == NULL && rhp_sess_resume_material_i_c ){

  	time_t now = _rhp_get_time();

  	if( now < rhp_sess_resume_material_i_c->peer_tkt_r_expire_time ){
    	sess_resume_material_i = rhp_sess_resume_material_i_c;
  	}
  }
#endif // RHP_SESS_RESUME_DEBUG_1

  exec_sess_resume
  	= (rhp_gcfg_ikev2_sess_resume_init_enabled && sess_resume_material_i ? 1 : 0);


  if( ui_info ){
    RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_UI_INFO,"uxxxxxsLdsuqdddxd",rlm_id,conn_args,reconn_args,peer_id,peer_addr,ui_info,peer_fqdn,"UI",ui_info->ui_type,ui_info->user_name,ui_info->vpn_realm_id,ui_info->http.http_bus_sess_id,auto_reconnect,exec_auto_reconnect,rhp_gcfg_ikev2_sess_resume_init_enabled,sess_resume_material_i,exec_sess_resume);
  }else{
    RHP_TRC(0,RHPTRCID_VPN_CONNECT_I,"uxxxxxsdddxd",rlm_id,conn_args,reconn_args,peer_id,peer_addr,ui_info,peer_fqdn,auto_reconnect,exec_auto_reconnect,rhp_gcfg_ikev2_sess_resume_init_enabled,sess_resume_material_i,exec_sess_resume);
  }
  rhp_ikev2_id_dump("rhp_vpn_connect_i.peer_id",peer_id);
  rhp_ip_addr_dump("rhp_vpn_connect_i.peer_ip",peer_addr);

	memset(&my_id,0,sizeof(rhp_ikev2_id));
	memset(&res_peer_id,0,sizeof(rhp_ikev2_id));
	memset(&mobike_additional_addr,0,sizeof(rhp_ip_addr));

	if( peer_id && peer_id->type == 0 ){
		peer_id = NULL;
	}

  if( (peer_id == NULL) && (peer_addr == NULL) && (peer_fqdn == NULL) ){
  	RHP_BUG("");
		err = -EINVAL;
		goto error;
  }

  if( peer_id && (peer_id->type == RHP_PROTO_IKE_ID_ANY) ){

  	RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_PEER_ID_ANY_TREATED_NULL,"uxxxs",rlm_id,peer_id,peer_addr,ui_info,peer_fqdn);
  	peer_id = NULL;
  }


	if( peer_addr ){

		if( rhp_ip_addr_null(peer_addr) ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		if( peer_id == NULL ){
			init_by_peer_addr = 1;
		}

	}else if( peer_fqdn ){

		if( peer_fqdn_addr_primary && !rhp_ip_addr_null(peer_fqdn_addr_primary) &&
				peer_fqdn_addr_primary->port ){

			peer_addr = peer_fqdn_addr_primary;
			use_fqdn = 1;

			if( peer_fqdn_addr_secondary && !rhp_ip_addr_null(peer_fqdn_addr_secondary) ){

				if( !peer_fqdn_addr_secondary->port ){
					peer_fqdn_addr_secondary->port = peer_fqdn_addr_primary->port;
				}

				peer_fqdn_addr_secondary_p = peer_fqdn_addr_secondary;
			}

		}else{

			err = -EINVAL;

			RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_FQDN_RESOLVE_ERR,"uxxxsE",rlm_id,peer_id,peer_addr,ui_info,peer_fqdn,err);

			RHP_LOG_DE(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_CONNECT_I_PEER_FQDN_RESOLV_ERR,"IsE",peer_id,peer_fqdn,err);

			goto error;
		}

		if( peer_id == NULL ){
			init_by_peer_addr = 1;
		}
	}


  rlm = rhp_realm_get(rlm_id);
  if( rlm == NULL ){

    err = -ENOENT;
    RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_NO_REALM,"u",rlm_id);

		RHP_LOG_DE(RHP_LOG_SRC_UI,0,RHP_LOG_ID_CONNECT_I_NO_REALM_FOUND,"uIAs",rlm_id,peer_id,peer_addr,peer_fqdn);

    goto error;
  }

  RHP_LOCK(&(rlm->lock));
  {
    rhp_ikev2_id_dump("rlm->my_auth.my_id",&(rlm->my_auth.my_id));

    eap_sup_enabled = rhp_eap_sup_impl_is_enabled(rlm,&eap_sup_i);

		if( rlm->my_auth.my_id.type == 0 && !eap_sup_enabled ){

			err = -ENOENT;
			RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_NO_MY_ID_CFG,"uxd",rlm_id,rlm,rlm->my_auth.my_id.type);

			RHP_LOG_DE(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_CONNECT_I_MY_ID_NOT_CONFIGURED,"IAs",peer_id,peer_addr,peer_fqdn);

			goto error_rlm_l;
		}

		if( rlm->internal_ifc->ifc == NULL ){

			err = -ENOENT;
			RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_NO_INTERNAL_IF,"uxs",rlm_id,rlm,rlm->internal_ifc->if_name);

			RHP_LOG_DE(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_CONNECT_I_VIF_NOT_CONFIGURED,"IAs",peer_id,peer_addr,peer_fqdn);

			goto error_rlm_l;
		}

		err = rhp_ikev2_id_dup(&my_id,&(rlm->my_auth.my_id));
		if( err ){
			RHP_BUG("%d",err);
			goto error_rlm_l;
		}
  }
  RHP_UNLOCK(&(rlm->lock));


  err = _rhp_vpn_connect_i_cleanup_old_vpn(rlm_id,peer_id,
  				peer_addr,peer_fqdn_addr_secondary_p,ui_info);
	if( err == -EEXIST ){
		rhp_realm_unhold(rlm);
		goto exists;
  }else if( err ){
		rhp_realm_unhold(rlm);
  	goto error;
  }


  RHP_LOCK(&(rlm->lock));

  if( !exec_sess_resume && eap_sup_enabled ){

		err = _rhp_vpn_connect_i_check_eap_sup(
				rlm,
				&eap_sup_i,
				exec_auto_reconnect,
				eap_sup_method,
				eap_sup_user_id,eap_sup_user_id_len,
				eap_sup_user_key,eap_sup_user_key_len);
		if( err ){
			goto error_rlm_l;
		}
	}

	err = _rhp_vpn_connect_i_check_cfg_peer(
			rlm,&dmy_peer_id,
			&peer_id,&peer_addr,
			peer_fqdn,&peer_fqdn_addr_secondary_p,
			&res_peer_id,&cfg_peer);
	if( err ){
		goto error_rlm_l;
	}

	{
		rhp_ikev2_id* my_id_tmp;

		if( eap_sup_enabled && rlm->my_auth.my_id.type == 0 ){
			my_id_tmp = NULL;
		}else{
			my_id_tmp = &(rlm->my_auth.my_id);
		}

		// addr_family is specified later.
		new_vpn = rhp_vpn_alloc(my_id_tmp,peer_id,rlm,peer_addr,RHP_IKE_INITIATOR);
		if( new_vpn == NULL ){
			RHP_BUG("");
			err = -EINVAL;
			goto error_rlm_l;
		}

		if( new_vpn->nat_t_info.always_use_nat_t_port ){

			peer_port = htons(rhp_gcfg_ike_port_nat_t);
		}

		new_vpn->init_by_peer_addr = init_by_peer_addr;


		if( conn_args->ikev1_init_mode != RHP_IKEV1_INITIATOR_DISABLED ){

			new_vpn->cfg_peer->ikev1_init_mode = conn_args->ikev1_init_mode;
		}
	}

  _rhp_atomic_set(&(new_vpn->is_active),1);

  new_vpn->is_initiated_by_user = is_initiated_by_user;

  new_vpn->is_remote_client = (rlm->config_service == RHP_IKEV2_CONFIG_CLIENT ? 1 : 0);

  if( auto_reconnect ){

  	err = _rhp_vpn_connect_i_setup_reconnect_info(
  			rlm,
  			peer_id,peer_addr,peer_fqdn,peer_port,
  			new_vpn,
  			auto_reconnect,exec_auto_reconnect,auto_reconnect_retries,
  			&reconnect_info);
  	if( err ){
    	goto error_rlm_l;
  	}
  }

  cfg_peer = new_vpn->cfg_peer;

  RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_ALLOC_NEW_VPN,"uxxxdddd",rlm_id,peer_id,ui_info,new_vpn,cfg_peer->ikev1_init_mode,rhp_gcfg_ikev1_enabled,rhp_gcfg_ikev1_main_mode_enabled,rhp_gcfg_ikev1_aggressive_mode_enabled);

  {
		if( !rhp_gcfg_ikev1_enabled && cfg_peer->ikev1_init_mode != RHP_IKEV1_INITIATOR_DISABLED ){
			RHP_LOG_DE(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_CONNECT_I_IKEV1_NOT_ENABLED,"IAs",peer_id,peer_addr,peer_fqdn);
			err = -EINVAL;
			goto error_rlm_l;
		}

		if( cfg_peer->ikev1_init_mode == RHP_IKEV1_INITIATOR_MODE_MAIN &&
				!rhp_gcfg_ikev1_main_mode_enabled ){
			RHP_LOG_DE(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_CONNECT_I_IKEV1_MAIN_MODE_NOT_ENABLED,"IAs",peer_id,peer_addr,peer_fqdn);
			err = -EINVAL;
			goto error_rlm_l;
		}

		if( cfg_peer->ikev1_init_mode == RHP_IKEV1_INITIATOR_MODE_AGGRESSIVE &&
				!rhp_gcfg_ikev1_aggressive_mode_enabled ){
			RHP_LOG_DE(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_CONNECT_I_IKEV1_AGGRESSIVE_MODE_NOT_ENABLED,"IAs",peer_id,peer_addr,peer_fqdn);
			err = -EINVAL;
			goto error_rlm_l;
		}
  }

  memcpy(&(mobike_additional_addr),&(cfg_peer->mobike_additional_addr_cache),sizeof(rhp_ip_addr));

	if( use_fqdn ){

		memcpy(&(cfg_peer->primary_addr),peer_fqdn_addr_primary,sizeof(rhp_ip_addr));

		if( peer_fqdn_addr_secondary_p ){

			memcpy(&(cfg_peer->secondary_addr),peer_fqdn_addr_secondary_p,sizeof(rhp_ip_addr));
		}

		new_vpn->peer_fqdn = (char*)_rhp_malloc(strlen(peer_fqdn) + 1);
		if( new_vpn->peer_fqdn == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error_rlm_l;
		}

		new_vpn->peer_fqdn[0] = '\0';
		strcpy(new_vpn->peer_fqdn,peer_fqdn);

	  RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_ASIGN_FQDN_RES_ADDRS,"uxxx",rlm_id,new_vpn,peer_fqdn_addr_primary,peer_fqdn_addr_secondary_p);
	}


	if( peer_port ){

		cfg_peer->primary_addr.port = peer_port;
		cfg_peer->secondary_addr.port = peer_port;
	}

	if( cfg_peer->primary_addr.port == 0 ){

		cfg_peer->primary_addr.port = htons(rhp_gcfg_ike_port);
	}

	if( cfg_peer->secondary_addr.port == 0 ){

		cfg_peer->secondary_addr.port = htons(rhp_gcfg_ike_port);
	}


	if( rhp_ip_addr_null(&(cfg_peer->primary_addr)) ||
			rhp_ip_is_loopback(&(cfg_peer->primary_addr)) ){

		err = RHP_STATUS_NO_IP;
		RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_PEER_IP_ZERO,"uxx",rlm_id,rlm,cfg_peer);

		RHP_LOG_DE(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_CONNECT_I_PEER_IP_NOT_CONFIGURED,"IAs",peer_id,peer_addr,peer_fqdn);

		goto error_rlm_l;
	}

	if( rhp_gcfg_ipv6_disabled &&
			cfg_peer->primary_addr.addr_family == AF_INET6 ){

		err = RHP_STATUS_IPV6_DISABLED;
		RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_PEER_IPV6_DISABLED,"uxx",rlm_id,rlm,cfg_peer);

		RHP_LOG_DE(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_CONNECT_I_PEER_IPV6_DISABLED,"IAs",peer_id,peer_addr,peer_fqdn);

		goto error_rlm_l;
	}


	{
    rhp_cfg_if* cfg_if;
		rhp_ifc_addr* src_ifc_addr;

		if( cfg_peer->primary_tx_if_name ){

			cfg_if = rlm->get_my_interface(rlm,cfg_peer->primary_tx_if_name,
								cfg_peer->primary_addr.addr_family);

			if( cfg_if == NULL && cfg_peer->secondary_tx_if_name ){

				cfg_if = rlm->get_my_interface(rlm,cfg_peer->secondary_tx_if_name,
									cfg_peer->primary_addr.addr_family);
			}

		}else if( rlm->my_interface_use_def_route ){

			cfg_if = rlm->get_next_my_interface_def_route(rlm,NULL,&(cfg_peer->primary_addr));

		}else{

			cfg_if = rlm->get_next_my_interface(rlm,NULL,&(cfg_peer->primary_addr));
		}

		if( cfg_if == NULL ){

			err = RHP_STATUS_NO_ACTIVE_IF;
			RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_CFG_IF_NULL,"x",cfg_peer);

			RHP_LOG_DE(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_CONNECT_I_CFG_IF_NOT_ACTIVE,"IAss",peer_id,&(cfg_peer->primary_addr),peer_fqdn,cfg_peer->primary_tx_if_name);

			goto error_rlm_l;
		}

		if( cfg_if->addr_family != AF_UNSPEC &&
				cfg_if->addr_family != cfg_peer->primary_addr.addr_family ){

			err = RHP_STATUS_NO_ACTIVE_IF;
			RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_CFG_IF_NULL,"xLd",cfg_peer,"AF",cfg_peer->primary_addr.addr_family);

			if( cfg_peer->primary_addr.addr_family == AF_INET ){
				RHP_LOG_DE(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_CONNECT_I_IPV4_NOT_ENABLED,"IAss",peer_id,&(cfg_peer->primary_addr),peer_fqdn,cfg_peer->primary_tx_if_name);
			}else if( cfg_peer->primary_addr.addr_family == AF_INET6 ){
				RHP_LOG_DE(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_CONNECT_I_IPV6_NOT_ENABLED,"IAss",peer_id,&(cfg_peer->primary_addr),peer_fqdn,cfg_peer->primary_tx_if_name);
			}

			goto error_rlm_l;
		}


		RHP_LOCK(&(cfg_if->ifc->lock));

		src_ifc_addr = cfg_if->ifc->select_src_addr(cfg_if->ifc,
										cfg_peer->primary_addr.addr_family,cfg_peer->primary_addr.addr.raw,
										cfg_if->is_by_def_route);

		if( src_ifc_addr == NULL ){

			RHP_UNLOCK(&(cfg_if->ifc->lock));

			err = RHP_STATUS_NO_ACTIVE_IF;
			RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_CFG_IF_NO_ACTIVE_SRC_ADDR,"xxx",cfg_peer,cfg_if,cfg_if->ifc);

			RHP_LOG_DE(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_CONNECT_I_CFG_IF_NO_SRC_IP,"IAss",peer_id,&(cfg_peer->primary_addr),peer_fqdn,cfg_peer->primary_tx_if_name);

			goto error_rlm_l;
		}

		new_vpn->set_local_net_info(new_vpn,cfg_if->ifc,
				src_ifc_addr->addr.addr_family,src_ifc_addr->addr.addr.raw);


		if( eap_sup_enabled && rlm->my_auth.my_id.type == 0 ){

		  if( exec_sess_resume ){

		  	err = rhp_ikev2_id_dup(&(new_vpn->my_id),&(sess_resume_material_i->my_id_i));
				if( err ){
					RHP_BUG("");
					RHP_UNLOCK(&(cfg_if->ifc->lock));
					err = -EINVAL;
					goto error_rlm_l;
				}

				if( !rhp_eap_id_is_null(&(sess_resume_material_i->my_eap_id_i)) ){

					if( rhp_eap_id_dup(&(new_vpn->eap.my_id),&(sess_resume_material_i->my_eap_id_i)) ){
						RHP_BUG("");
						RHP_UNLOCK(&(cfg_if->ifc->lock));
						err = -EINVAL;
						goto error_rlm_l;
					}
				}

		  }else{

				u8 my_id_addr[16];
				int my_id_addr_len = 0;
				int my_id_addr_type = 0;

				if( src_ifc_addr->addr.addr_family == AF_INET ){

					my_id_addr_len = 4;
					my_id_addr_type = RHP_PROTO_IKE_ID_IPV4_ADDR;

				}else if( src_ifc_addr->addr.addr_family == AF_INET6 ){

					my_id_addr_len = 16;
					my_id_addr_type = RHP_PROTO_IKE_ID_IPV6_ADDR;
				}


		  	if( !rhp_gcfg_eap_client_use_ikev2_random_addr_id ){

					memcpy(my_id_addr,src_ifc_addr->addr.addr.raw,my_id_addr_len);

				}else{

					if( _rhp_vpn_eap_sup_random_addr_id(src_ifc_addr->addr.addr_family,my_id_addr) ){
						RHP_BUG("");
						RHP_UNLOCK(&(cfg_if->ifc->lock));
						err = -EINVAL;
						goto error_rlm_l;
					}
				}

				err = rhp_ikev2_id_setup(my_id_addr_type,my_id_addr,my_id_addr_len,&(new_vpn->my_id));
				if( err ){
					RHP_BUG("");
					RHP_UNLOCK(&(cfg_if->ifc->lock));
					err = -EINVAL;
					goto error_rlm_l;
				}
		  }
		}

		RHP_UNLOCK(&(cfg_if->ifc->lock));


		new_vpn->set_peer_addr(new_vpn,&(cfg_peer->primary_addr),&(cfg_peer->primary_addr));

	  if( peer_port == htons(rhp_gcfg_ike_port_nat_t) ){
	  	new_vpn->nat_t_info.use_nat_t_port = 1;
	  }
	}

	if( cfg_peer->ikev1_init_mode == RHP_IKEV1_INITIATOR_DISABLED ){

		u16 dhgrp_id = 0;

		//
		// IKEv2
		//

		if( exec_sess_resume ){

			if( sess_resume_material_i->old_sa_prop_i == NULL ){
				RHP_BUG("");
				err = -EINVAL;
				goto error_rlm_l;
			}

			dhgrp_id = sess_resume_material_i->old_sa_prop_i->dhgrp_id;
		}

		ikesa = rhp_ikesa_new_i(rlm,cfg_peer,dhgrp_id);
		if( ikesa == NULL ){
			RHP_BUG("");
			err = -EINVAL;
			goto error_rlm_l;
		}

		ikesa->v1.p1_exchange_mode = RHP_PROTO_IKE_EXCHG_RESEVED;

		ikesa->timers = rhp_ikesa_new_timers(RHP_IKE_INITIATOR,ikesa->init_spi);
		if( ikesa->timers == NULL ){
			RHP_BUG("");
			err = -EINVAL;
			goto error_rlm_l;
		}

	}else{

		//
		// IKEv1
		//

		if( cfg_peer->ikev1_init_mode == RHP_IKEV1_INITIATOR_MODE_MAIN ){

			ikesa = rhp_ikesa_v1_main_new_i(rlm,cfg_peer);
			if( ikesa == NULL ){
				RHP_BUG("");
				err = -EINVAL;
				goto error_rlm_l;
			}

		}else if( cfg_peer->ikev1_init_mode == RHP_IKEV1_INITIATOR_MODE_AGGRESSIVE ){

			ikesa = rhp_ikesa_v1_aggressive_new_i(rlm,cfg_peer,0);
			if( ikesa == NULL ){
				RHP_BUG("");
				err = -EINVAL;
				goto error_rlm_l;
			}

		}else{
			RHP_BUG("%d",cfg_peer->ikev1_init_mode);
			err = -EINVAL;
			goto error_rlm_l;
		}

		new_vpn->is_v1 = 1;

		ikesa->v1.tx_initial_contact = 1;

    if( rhp_gcfg_ikev1_commit_bit_enabled &&
    		new_vpn->cfg_peer->ikev1_commit_bit_enabled ){

    	new_vpn->v1.commit_bit_enabled = 1;
    }
	}

  new_vpn->ikesa_put(new_vpn,ikesa);



  lifetime_larval = (time_t)rlm->ikesa.lifetime_larval;


	if( eap_sup_enabled ){

		new_vpn->eap.role = RHP_EAP_SUPPLICANT;
		new_vpn->eap.eap_method = new_vpn->eap.my_id.method
														= eap_sup_i.eap_method;

		new_vpn->eap.impl_ctx = rhp_eap_sup_impl_vpn_init(
				eap_sup_i.eap_method,new_vpn,rlm,ikesa,
				eap_sup_user_id,eap_sup_user_id_len,eap_sup_user_key,eap_sup_user_key_len);

		if( new_vpn->eap.impl_ctx == NULL ){
			err = -EINVAL;
			goto error_rlm_l;
		}
	}

	auth_tkt_enabled = rlm->nhrp.auth_tkt_enabled;

	new_vpn->gre.key_enabled = rlm->gre.key_enabled;
	if( new_vpn->gre.key_enabled ){
		new_vpn->gre.key = rlm->gre.key;
	}


	if( cfg_peer->ikev1_init_mode == RHP_IKEV1_INITIATOR_MODE_AGGRESSIVE ){

		tx_ikemesg = rhp_ikev1_new_pkt_aggressive_i_1(new_vpn,ikesa,rlm);
		if( tx_ikemesg == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error_rlm_l;
		}
	}


  RHP_UNLOCK(&(rlm->lock));
  rhp_realm_unhold(rlm);
  rlm = NULL;


	if( cfg_peer->ikev1_init_mode == RHP_IKEV1_INITIATOR_DISABLED ){

		//
		// IKEv2
		//

		if( exec_sess_resume ){

			new_vpn->sess_resume.gen_by_sess_resume = 1;
			ikesa->gen_by_sess_resume = 1;

			new_vpn->sess_resume_set_material_i(new_vpn,sess_resume_material_i);
			ikesa->sess_resume.init.material = sess_resume_material_i; // Just reference. Don't free it.

			reconn_args->sess_resume_material_i = NULL;

			tx_ikemesg = rhp_ikev2_new_pkt_sess_resume_req(new_vpn,ikesa,sess_resume_material_i,0,NULL);

		}else{

			// This API internally (in sa_payload->set_def_ikesa_prop()) acquire rhp_cfg_lock.
			// So, a caller must not call this API with rlm->lock and rhp_cfg_lock locked.

			tx_ikemesg = rhp_ikev2_new_pkt_ike_sa_init_req(ikesa,0,0,NULL);
		}
		if( tx_ikemesg == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}

	}else if( cfg_peer->ikev1_init_mode == RHP_IKEV1_INITIATOR_MODE_MAIN ){

		//
		// IKEv1 Main-mode
		//

		tx_ikemesg = rhp_ikev1_new_pkt_main_i_1(ikesa);
		if( tx_ikemesg == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
  }


  {
		rhp_ip_addr_list* intr_peer_addr;

		if( !rhp_ip_addr_null(&(cfg_peer->internal_addr)) ){

			new_vpn->internal_net_info.static_peer_addr = 1;

			intr_peer_addr = rhp_ip_dup_addr_list(&(cfg_peer->internal_addr));
			if( intr_peer_addr == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}
			intr_peer_addr->ip_addr.tag = RHP_IPADDR_TAG_STATIC_PEER_ADDR;

			intr_peer_addr->next = new_vpn->internal_net_info.peer_addrs;
			new_vpn->internal_net_info.peer_addrs = intr_peer_addr;
		}

		if( !rhp_ip_addr_null(&(cfg_peer->internal_addr_v6)) ){

			new_vpn->internal_net_info.static_peer_addr = 1;

			intr_peer_addr = rhp_ip_dup_addr_list(&(cfg_peer->internal_addr_v6));
			if( intr_peer_addr == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}
			intr_peer_addr->ip_addr.tag = RHP_IPADDR_TAG_STATIC_PEER_ADDR;

			intr_peer_addr->next = new_vpn->internal_net_info.peer_addrs;
			new_vpn->internal_net_info.peer_addrs = intr_peer_addr;
		}
  }


  if( ui_info ){

  	memcpy(&(new_vpn->ui_info),ui_info,sizeof(rhp_ui_ctx));
  }


  // B4 putting new_vpn (somebody can access it now), the lock is acqured.
  new_vpn_ref = rhp_vpn_hold_ref(new_vpn); // (xxx*)
  RHP_LOCK(&(new_vpn->lock));

  err = rhp_vpn_ikesa_spi_put(new_vpn,ikesa->side,ikesa->init_spi);
  if( err ){
    RHP_BUG("%d",err);
    RHP_UNLOCK(&(new_vpn->lock));
    goto error;
  }

  {
		rhp_http_bus_broadcast_async(new_vpn->vpn_realm_id,1,1,
			rhp_ui_http_vpn_added_serialize,
			rhp_ui_http_vpn_bus_btx_async_cleanup,(void*)rhp_vpn_hold_ref(new_vpn)); // (*x*)

  	RHP_LOG_I(RHP_LOG_SRC_VPNMNG,new_vpn->vpn_realm_id,RHP_LOG_ID_VPN_ADDED,"IAsNA",&(new_vpn->peer_id),&(new_vpn->peer_addr),new_vpn->peer_fqdn,new_vpn->unique_id,&mobike_additional_addr);
  }


  ikesa->signed_octets.ikemesg_i_1st = tx_ikemesg;
  rhp_ikev2_hold_mesg(tx_ikemesg);


  ikesa->timers->start_lifetime_timer(new_vpn,ikesa,lifetime_larval,1);

  new_vpn->origin_peer_port = new_vpn->peer_addr.port;

  {
		new_vpn->connecting = 1;
		rhp_ikesa_half_open_sessions_inc();
  }


	{
		if( conn_args->pend_nhrp_resolution_req ){

			new_vpn->nhrp.pend_resolution_req_q.head = conn_args->pend_nhrp_resolution_req;
			new_vpn->nhrp.pend_resolution_req_q.tail = conn_args->pend_nhrp_resolution_req;

			rhp_nhrp_mesg_hold(conn_args->pend_nhrp_resolution_req);
		}

		new_vpn->nhrp.dmvpn_shortcut = conn_args->nhrp_dmvpn_shortcut;

		new_vpn->mobike_disabled = conn_args->mobike_disabled;


		if( auth_tkt_enabled ){

			if( conn_args->auth_tkt_conn_type == RHP_AUTH_TKT_CONN_TYPE_SPOKE2SPOKE ){

				if( conn_args->peer_addr ){
					memcpy(&(new_vpn->auth_ticket.spk2spk_resp_pub_addr),conn_args->peer_addr,sizeof(rhp_ip_addr));
				}

				if( conn_args->nhrp_peer_proto_addr ){
					memcpy(&(new_vpn->auth_ticket.spk2spk_resp_itnl_addr),conn_args->nhrp_peer_proto_addr,sizeof(rhp_ip_addr));
				}

				rhp_ip_addr_dump("spk2spk_resp_pub_addr",&(new_vpn->auth_ticket.spk2spk_resp_pub_addr));
				rhp_ip_addr_dump("spk2spk_resp_itnl_addr",&(new_vpn->auth_ticket.spk2spk_resp_itnl_addr));

				new_vpn->auth_ticket.conn_type = RHP_AUTH_TKT_CONN_TYPE_SPOKE2SPOKE;
			}
		}
	}


	if( cfg_peer->ikev1_init_mode == RHP_IKEV1_INITIATOR_DISABLED ){

		// IKEv2

		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_I_IKE_SA_INIT_SENT);

		rhp_ikev2_send_request(new_vpn,ikesa,tx_ikemesg,RHP_IKEV2_MESG_HANDLER_IKESA_INIT);

	}else{

		tx_ikemesg->v1_start_retx_timer = 1;

		// This should be the last one, though new_vpn is locked.
		if( cfg_peer->ikev1_init_mode == RHP_IKEV1_INITIATOR_MODE_MAIN ){

	  	rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_MAIN_1ST_SENT_I);

			rhp_ikev1_send_mesg(new_vpn,ikesa,tx_ikemesg,RHP_IKEV1_MESG_HANDLER_P1_MAIN);

		}else if( cfg_peer->ikev1_init_mode == RHP_IKEV1_INITIATOR_MODE_AGGRESSIVE ){

			rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_AGG_1ST_SENT_I);

			rhp_ikev1_send_mesg(new_vpn,ikesa,tx_ikemesg,RHP_IKEV1_MESG_HANDLER_P1_AGGRESSIVE);
		}

		if( tx_ikemesg->tx_pkt == NULL ){
			RHP_BUG("");
		}
	}


	rhp_ikev2_unhold_mesg(tx_ikemesg);
  tx_ikemesg = NULL;

  RHP_UNLOCK(&(new_vpn->lock));
  rhp_vpn_unhold(new_vpn_ref); // (xxx*)


  rhp_ikev2_id_clear(&my_id);
  rhp_ikev2_id_clear(&res_peer_id);

  RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_RTRN,"uxxxxx",rlm_id,peer_id,ui_info,new_vpn,rlm,ikesa);
  return 0;

error_rlm_l:
	if( rlm ){
		RHP_UNLOCK(&(rlm->lock));
		rhp_realm_unhold(rlm);
	}
error:
	if( new_vpn_ref ){
    rhp_vpn_unhold(new_vpn_ref); // (xxx*)
	}
  if( new_vpn ){

  	rhp_vpn_ref* new_vpn_ref2 = rhp_vpn_hold_ref(new_vpn); // (xx*)

  	rhp_vpn_destroy(new_vpn);
    rhp_vpn_unhold(new_vpn_ref2); // (xx*)
  }

  if( tx_ikemesg ) {
    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }

  rhp_ikev2_id_clear(&my_id);
  rhp_ikev2_id_clear(&res_peer_id);

  RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_ERR,"uxxE",rlm_id,peer_id,ui_info,err);
  return err;

exists:
	rhp_ikev2_id_clear(&my_id);
	rhp_ikev2_id_clear(&res_peer_id);

  RHP_TRC(0,RHPTRCID_VPN_CONNECT_I_EXISTS_RTRN,"uxx",rlm_id,peer_id,ui_info);
  return RHP_STATUS_IKESA_EXISTS;
}

extern void rhp_vpn_ikev2_cfg_cleanup(rhp_vpn* vpn);

//
// Caller must not acquire vpn->lock.
//
int rhp_vpn_close_impl(rhp_vpn* vpn)
{
  int err = -EINVAL;
  rhp_childsa* cur_childsa = NULL;
  rhp_ikesa* cur_ikesa = NULL;

	RHP_TRC(0,RHPTRCID_VPN_CLOSE_VPN_IMPL,"xpuxdd",vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm,vpn->ikesa_num,vpn->childsa_num);
	rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
	rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));

	if( !_rhp_atomic_read(&(vpn->is_active)) ){
		RHP_TRC(0,RHPTRCID_VPN_CLOSE_VPN_IMPL_OLD_VPN_NOT_ACTIVE,"x",vpn);
		err = -EINVAL;
		goto error;
	}

	if( vpn->deleting ){
		RHP_TRC(0,RHPTRCID_VPN_CLOSE_VPN_IMPL_NOW_DELETING,"x",vpn);
		err = 0;
		goto error;
	}


	vpn->auto_reconnect = 0;
	vpn->deleting = 1;


	//
	// Gracefully deleting ===> Forcedly deleting...
	//
	if( rhp_ikev2_mobike_pending(vpn) || rhp_ikev2_mobike_ka_pending(vpn) ){

		RHP_TRC(0,RHPTRCID_VPN_CLOSE_VPN_IMPL_MOBIKE_PENDING_VPN_DESTROY,"x",vpn);
  	rhp_vpn_destroy(vpn);

	}else if( vpn->childsa_list_head ){

	  rhp_vpn_internal_route_delete(vpn,NULL); // [CAUTION] NULL means 'rlm' !!!
		rhp_vpn_ikev2_cfg_cleanup(vpn);

		cur_childsa = vpn->childsa_list_head;
		while( cur_childsa ){

			RHP_TRC(0,RHPTRCID_VPN_CLOSE_VPN_IMPL_VPN_CHILDSA,"xxLdHHLd",vpn,cur_childsa,"IKE_SIDE",cur_childsa->side,cur_childsa->spi_inb,cur_childsa->spi_outb,"CHILDSA_STAT",cur_childsa->state);

			cur_childsa->timers->schedule_delete(vpn,cur_childsa,0);

			cur_childsa = cur_childsa->next_vpn_list;
		}

	}else if( vpn->ikesa_list_head ){

	  rhp_vpn_internal_route_delete(vpn,NULL); // [CAUTION] NULL means 'rlm' !!!
		rhp_vpn_ikev2_cfg_cleanup(vpn);

		cur_ikesa = vpn->ikesa_list_head;
		while( cur_ikesa ){

			RHP_TRC(0,RHPTRCID_VPN_CLOSE_VPN_IMPL_VPN_IKESA,"xxLdGGLd",vpn,cur_ikesa,"IKE_SIDE",cur_ikesa->side,cur_ikesa->init_spi,cur_ikesa->resp_spi,"IKESA_STAT",cur_ikesa->state);

			cur_ikesa->timers->schedule_delete(vpn,cur_ikesa,0);

			cur_ikesa = cur_ikesa->next_vpn_list;
		}

	}else{

		RHP_TRC(0,RHPTRCID_VPN_CLOSE_VPN_IMPL_VPN_DESTROY,"x",vpn);
  	rhp_vpn_destroy(vpn);
	}


	{
		rhp_http_bus_broadcast_async(vpn->vpn_realm_id,1,1,
				rhp_ui_http_vpn_close_serialize,
				rhp_ui_http_vpn_bus_btx_async_cleanup,(void*)rhp_vpn_hold_ref(vpn)); // (*x*)

		RHP_LOG_I(RHP_LOG_SRC_VPNMNG,vpn->vpn_realm_id,RHP_LOG_ID_CLOSE_VPN,"IAs",&(vpn->peer_id),&(vpn->peer_addr),vpn->peer_fqdn);
	}

  RHP_TRC(0,RHPTRCID_VPN_CLOSE_IMPL_RTRN,"x",vpn);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_VPN_CLOSE_IMPL_ERR,"xE",vpn,err);
	return err;
}

//
// Caller must not acquire rlm->lock.
//
int rhp_vpn_close(unsigned long rlm_id,rhp_ikev2_id* peer_id,rhp_ip_addr* peer_addr,
		char* peer_fqdn,u8* vpn_unique_id,rhp_ui_ctx* ui_info)
{
  int err = -EINVAL;
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;
  int unique_id_len = (vpn_unique_id ? RHP_VPN_UNIQUE_ID_SIZE : 0);

  if( ui_info ){
  	RHP_TRC(0,RHPTRCID_VPN_CLOSE,"uxxxsLdsuqp",rlm_id,peer_id,ui_info,peer_addr,peer_fqdn,"UI",ui_info->ui_type,ui_info->user_name,ui_info->vpn_realm_id,ui_info->http.http_bus_sess_id,unique_id_len,vpn_unique_id);
  }else{
  	RHP_TRC(0,RHPTRCID_VPN_CLOSE_NO_UI_INFO,"uxxxsp",rlm_id,peer_id,ui_info,peer_addr,peer_fqdn,unique_id_len,vpn_unique_id);
  }
  rhp_ikev2_id_dump("rhp_vpn_close.peer_id",peer_id);
  rhp_ip_addr_dump("rhp_vpn_close.peer_ip",peer_addr);

  if( (peer_id == NULL) && (peer_addr == NULL) && (peer_fqdn == NULL) ){
  	RHP_BUG("");
  	goto error;
  }

  if( vpn_unique_id ){

  	vpn_ref = rhp_vpn_get_by_unique_id(vpn_unique_id);

	}else if( peer_id && (peer_id->type != RHP_PROTO_IKE_ID_ANY) ){

		if( peer_id->alt_id ){
			vpn_ref = rhp_vpn_get(rlm_id,peer_id,NULL);
		}else{
			vpn_ref = rhp_vpn_get_no_alt_id(rlm_id,peer_id,NULL);
		}

	}else if( peer_addr ){

		vpn_ref = rhp_vpn_get_by_peer_addr(rlm_id,peer_addr,NULL);

	}else if( peer_fqdn ){

		vpn_ref = rhp_vpn_get_by_peer_fqdn(rlm_id,peer_fqdn);
	}
	vpn = RHP_VPN_REF(vpn_ref);

	if( vpn == NULL ){
		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_VPN_CLOSE_NO_VPN,"u",rlm_id);
		goto error;
	}

	if( vpn->vpn_realm_id != rlm_id ){
		err = -EPERM;
		RHP_TRC(0,RHPTRCID_VPN_CLOSE_INVALID_RLM_ID,"uu",rlm_id,vpn->vpn_realm_id);
  	rhp_vpn_unhold(vpn);
		goto error;
	}


	RHP_LOCK(&(vpn->lock));

	if( vpn->eap.eap_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS &&
			!vpn->radius.acct_term_cause ){
		vpn->radius.acct_term_cause = RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_ADMIN_RESET;
	}

	err = rhp_vpn_close_impl(vpn);
	if( err ){
		goto error_vpn_l;
	}

	RHP_UNLOCK(&(vpn->lock));


	rhp_vpn_unhold(vpn_ref);

  RHP_TRC(0,RHPTRCID_VPN_CLOSE_RTRN,"uxxx",rlm_id,peer_id,ui_info,vpn);
  return 0;

error_vpn_l:
  if( vpn ){
  	RHP_UNLOCK(&(vpn->lock));
  	rhp_vpn_unhold(vpn_ref);
  }

error:
  RHP_TRC(0,RHPTRCID_VPN_CLOSE_ERR,"uxxxE",rlm_id,peer_id,ui_info,vpn,err);
  return err;
}


static int rhp_vpn_forcedly_close_conns_cb(rhp_vpn* vpn,void* ctx)
{
  rhp_ikesa* cur_ikesa = NULL;

  RHP_LOCK(&(vpn->lock));

	RHP_TRC_FREQ(0,RHPTRCID_VPN_FORCEDLY_CLOSE_CONNS_CB,"xpuxdd",vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm,vpn->ikesa_num,vpn->childsa_num);
	rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
	rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));

	if( !_rhp_atomic_read(&(vpn->is_active)) ){
		RHP_TRC(0,RHPTRCID_VPN_CLOSE_OLD_VPN_NOT_ACTIVE,"x",vpn);
		goto ignored;
	}

	if( vpn->deleting ){
		RHP_TRC_FREQ(0,RHPTRCID_VPN_FORCEDLY_CLOSE_CONNS_CB_NOW_DELETING,"x",vpn);
		goto ignored;
	}

	vpn->auto_reconnect = 0;
	vpn->deleting = 1;

	if( vpn->ikesa_list_head ){ // Forcedly deleting...

		cur_ikesa = vpn->ikesa_list_head;
		while( cur_ikesa ){

			RHP_TRC_FREQ(0,RHPTRCID_VPN_FORCEDLY_CLOSE_CONNS_CB_VPN_IKESA,"xxLdGGLd",vpn,cur_ikesa,"IKE_SIDE",cur_ikesa->side,cur_ikesa->init_spi,cur_ikesa->resp_spi,"IKESA_STAT",cur_ikesa->state);

			cur_ikesa->timers->schedule_delete(vpn,cur_ikesa,0);

			cur_ikesa = cur_ikesa->next_vpn_list;
		}
	}

ignored:
	RHP_UNLOCK(&(vpn->lock));

	RHP_TRC_FREQ(0,RHPTRCID_VPN_FORCEDLY_CLOSE_CONNS_CB_RTRN,"x");
	return 0;
}


int rhp_vpn_forcedly_close_conns(unsigned long rlm_id)
{
	int err;
	RHP_TRC(0,RHPTRCID_VPN_FORCEDLY_CLOSE_CONNS,"u",rlm_id);

	err = rhp_vpn_enum(rlm_id,rhp_vpn_forcedly_close_conns_cb,NULL);

	RHP_TRC(0,RHPTRCID_VPN_FORCEDLY_CLOSE_CONNS_RTRN,"uE",rlm_id,err);
	return err;
}


void rhp_vpn_aoc_start()
{
	RHP_TRC(0,RHPTRCID_VPN_AOC_START,"");

	if( !rhp_timer_pending(&(_rhp_vpn_aoc_timer)) ){

		rhp_timer_reset(&(_rhp_vpn_aoc_timer));
  	rhp_timer_add(&(_rhp_vpn_aoc_timer),(time_t)RHP_VPN_AOC_TIMER_INIT_INTERVAL);
	}

	RHP_TRC(0,RHPTRCID_VPN_AOC_START_RTRN,"");
	return;
}

void rhp_vpn_aoc_update()
{
	RHP_TRC(0,RHPTRCID_VPN_AOC_UPDATE,"");

	if( !rhp_timer_pending(&(_rhp_vpn_aoc_timer)) ){

		rhp_timer_reset(&(_rhp_vpn_aoc_timer));
  	rhp_timer_add(&(_rhp_vpn_aoc_timer),(time_t)RHP_VPN_AOC_TIMER_INIT_INTERVAL);

  	RHP_TRC(0,RHPTRCID_VPN_AOC_UPDATE_1,"");

	}else{

		rhp_timer_update(&(_rhp_vpn_aoc_timer),(time_t)RHP_VPN_AOC_TIMER_INIT_INTERVAL);

		RHP_TRC(0,RHPTRCID_VPN_AOC_UPDATE_2,"");
	}
}

void rhp_vpn_aoc_stop()
{
	RHP_TRC(0,RHPTRCID_VPN_AOC_END,"");

	rhp_timer_delete(&(_rhp_vpn_aoc_timer));

	RHP_TRC(0,RHPTRCID_VPN_AOC_END_RTRN,"");
	return;
}

// Don't call within a scope where rlm->lock or vpn->lock is acquired.
// Call this before rhp_realm_put()!!!
int rhp_vpn_aoc_put(rhp_vpn_realm* rlm)
{
	int err = -EINVAL;
	rhp_vpn_aoc_peer *aoc_peer;
  rhp_cfg_peer* cfg_peer;
  int n = 0;

	RHP_TRC(0,RHPTRCID_VPN_AOC_PUT,"xu",rlm,rlm->id);

  RHP_LOCK(&_rhp_vpn_conn_mng_lock);

	cfg_peer = rlm->peers;
	while( cfg_peer ){

		if( cfg_peer->always_on_connection ){

			if( rhp_ip_addr_null(&(cfg_peer->primary_addr)) &&
					cfg_peer->id.type != RHP_PROTO_IKE_ID_FQDN ){

				goto next;
			}

		  aoc_peer = (rhp_vpn_aoc_peer*)_rhp_malloc(sizeof(rhp_vpn_aoc_peer));
		  if( aoc_peer == NULL ){
		  	RHP_BUG("");
		  	err = -ENOMEM;
		  	goto error;
		  }
		  memset(aoc_peer,0,sizeof(rhp_vpn_aoc_peer));

		  aoc_peer->tag[0] = '#';
		  aoc_peer->tag[1] = 'A';
		  aoc_peer->tag[2] = 'O';
		  aoc_peer->tag[3] = 'C';

		  aoc_peer->rlm_id = rlm->id;

		  err = rhp_ikev2_id_dup(&(aoc_peer->peer_id),&(cfg_peer->id));
		  if( err ){
		  	RHP_BUG("%d",err);
		  	goto error;
		  }

		  if( !rhp_ip_addr_null(&(cfg_peer->primary_addr)) ){

		  	memcpy(&(aoc_peer->peer_addr),&(cfg_peer->primary_addr),sizeof(rhp_ip_addr));
		  }

		  if( cfg_peer->primary_addr_fqdn ){

		  	int addr_fqdn_len = strlen(cfg_peer->primary_addr_fqdn) + 1;

		  	aoc_peer->peer_addr_fqdn = (char*)_rhp_malloc(addr_fqdn_len);
		  	if( aoc_peer->peer_addr_fqdn == NULL ){
			  	RHP_BUG("");
			  	err = -ENOMEM;
			  	goto error;
		  	}

		  	memcpy(aoc_peer->peer_addr_fqdn,cfg_peer->primary_addr_fqdn,addr_fqdn_len);
		  }

		  if( _rhp_vpn_objid_last == 0 ){
		  	_rhp_vpn_objid_last++;
		  }

		  aoc_peer->objid = cfg_peer->vpn_aoc_objid = _rhp_vpn_objid_last++;

		  {
				aoc_peer->lst_next = _rhp_vpn_aoc_peers.lst_next;
			  if( _rhp_vpn_aoc_peers.lst_next ){
			  	_rhp_vpn_aoc_peers.lst_next->lst_prev = aoc_peer;
			  }
			  aoc_peer->lst_prev = &_rhp_vpn_aoc_peers;
			  _rhp_vpn_aoc_peers.lst_next = aoc_peer;
		  }

		  n++;
		}

next:
		cfg_peer = cfg_peer->next;
	}

  RHP_UNLOCK(&_rhp_vpn_conn_mng_lock);

  if( n == 0 ){
  	err = -ENOENT;
  	goto error2;
  }

	RHP_TRC(0,RHPTRCID_VPN_AOC_PUT_RTRN,"xud",rlm,rlm->id,n);
  return 0;

error:
	RHP_UNLOCK(&_rhp_vpn_conn_mng_lock);

error2:
	RHP_TRC(0,RHPTRCID_VPN_AOC_PUT_ERR,"xuE",rlm,rlm->id,err);
	return err;
}

// Don't call within a scope where rlm->lock or vpn->lock is acquired.
void rhp_vpn_aoc_delete(u64 vpn_aoc_objid)
{
	rhp_vpn_aoc_peer *aoc_peer;

	RHP_TRC(0,RHPTRCID_VPN_AOC_DELETE,"q",vpn_aoc_objid);

	if( vpn_aoc_objid == 0 ){
		goto error;
	}

  RHP_LOCK(&_rhp_vpn_conn_mng_lock);

  aoc_peer = _rhp_vpn_aoc_peers.lst_next;
	while( aoc_peer ){

		if( aoc_peer->objid == vpn_aoc_objid ){
			break;
		}

		aoc_peer = aoc_peer->lst_next;
	}

	if( aoc_peer ){

		aoc_peer->lst_prev->lst_next = aoc_peer->lst_next;
	  if( aoc_peer->lst_next ){
	  	aoc_peer->lst_next->lst_prev = aoc_peer->lst_prev;
	  }

	  rhp_ikev2_id_clear(&(aoc_peer->peer_id));

	  if( aoc_peer->peer_addr_fqdn ){
	  	_rhp_free(aoc_peer->peer_addr_fqdn);
	  }

	  _rhp_free(aoc_peer);
	}

  RHP_UNLOCK(&_rhp_vpn_conn_mng_lock);

	RHP_TRC(0,RHPTRCID_VPN_AOC_DELETE_RTRN,"q",vpn_aoc_objid);
  return;

error:
	RHP_UNLOCK(&_rhp_vpn_conn_mng_lock);

	RHP_TRC(0,RHPTRCID_VPN_AOC_DELETE_ERR,"q",vpn_aoc_objid);
	return;
}


struct _rhp_vpn_aoc_timer_dns {

	u8 tag[4]; // '#AOD'

	unsigned long rlm_id;
	u64 objid;
	rhp_ikev2_id peer_id;

	char* peer_fqdn;
	rhp_ip_addr peer_fqdn_addr_primary;
	rhp_ip_addr peer_fqdn_addr_secondary;
	u16 peer_port;
	u16 reserved0;
};
typedef struct _rhp_vpn_aoc_timer_dns	rhp_vpn_aoc_timer_dns;

static void _rhp_vpn_aoc_timer_dns_ctx_free(rhp_vpn_aoc_timer_dns* aoc_dns_ctx)
{
	if( aoc_dns_ctx ){

		if( aoc_dns_ctx->peer_fqdn ){
			_rhp_free(aoc_dns_ctx->peer_fqdn);
		}

		rhp_ikev2_id_clear(&(aoc_dns_ctx->peer_id));

		_rhp_free(aoc_dns_ctx);
	}
}

static void _rhp_vpn_aoc_timer_dns_task_bh(int worker_idx,void *cb_ctx)
{
	int err = -EINVAL;
	rhp_vpn_aoc_timer_dns* aoc_dns_ctx = (rhp_vpn_aoc_timer_dns*)cb_ctx;
	rhp_vpn_conn_args conn_args;

	RHP_TRC_FREQ(0,RHPTRCID_VPN_AOC_TIMER_DNS_TASK_BH,"dxu",worker_idx,aoc_dns_ctx,aoc_dns_ctx->rlm_id);

	memset(&conn_args,0,sizeof(rhp_vpn_conn_args));

	conn_args.peer_id = &(aoc_dns_ctx->peer_id);
	conn_args.peer_fqdn = aoc_dns_ctx->peer_fqdn;
	conn_args.peer_fqdn_addr_primary = &(aoc_dns_ctx->peer_fqdn_addr_primary);
	conn_args.peer_fqdn_addr_secondary = &(aoc_dns_ctx->peer_fqdn_addr_secondary);
	conn_args.peer_port = aoc_dns_ctx->peer_port;

	err = rhp_vpn_connect_i(aoc_dns_ctx->rlm_id,&conn_args,NULL,0);
	if( err ){

		RHP_TRC_FREQ(0,RHPTRCID_VPN_AOC_TIMER_DNS_TASK_BH_CONNECT_I_ERR,"dxuE",worker_idx,aoc_dns_ctx,aoc_dns_ctx->rlm_id,err);

		if( err == RHP_STATUS_IKESA_EXISTS ||
				err == RHP_STATUS_CONNECT_VPN_I_EAP_SUP_USER_KEY_NEEDED ){

			if( err == RHP_STATUS_CONNECT_VPN_I_EAP_SUP_USER_KEY_NEEDED ){
				RHP_LOG_DE(RHP_LOG_SRC_VPNMNG,aoc_dns_ctx->rlm_id,RHP_LOG_ID_ALWAYS_ON_CONNECT_EAP_KEY_NOT_SAVED,"IE",(aoc_dns_ctx ? &(aoc_dns_ctx->peer_id) : NULL),err);
			}

			err = 0;

		}else{

			RHP_LOG_DE(RHP_LOG_SRC_VPNMNG,aoc_dns_ctx->rlm_id,RHP_LOG_ID_ALWAYS_ON_CONNECT_START_CONN_ERR_2,"IAE",&(aoc_dns_ctx->peer_id),&(aoc_dns_ctx->peer_fqdn_addr_primary),err);
		}

	}else{

		RHP_LOG_D(RHP_LOG_SRC_VPNMNG,aoc_dns_ctx->rlm_id,RHP_LOG_ID_ALWAYS_ON_CONNECT_START_CONN_2,"IA",&(aoc_dns_ctx->peer_id),&(aoc_dns_ctx->peer_fqdn_addr_primary));
	}

	_rhp_vpn_aoc_timer_dns_ctx_free(aoc_dns_ctx);

	RHP_TRC_FREQ(0,RHPTRCID_VPN_AOC_TIMER_DNS_TASK_BH_RTRN,"dx",worker_idx,aoc_dns_ctx);
	return;
}

static void _rhp_vpn_aoc_timer_dns_task(void* cb_ctx,void* not_used,int err,int res_addrs_num,rhp_ip_addr* res_addrs)
{
	rhp_vpn_aoc_timer_dns* aoc_dns_ctx = (rhp_vpn_aoc_timer_dns*)cb_ctx;

	RHP_TRC_FREQ(0,RHPTRCID_VPN_AOC_TIMER_DNS_TASK,"xEdx",aoc_dns_ctx,err,res_addrs_num,res_addrs);

	if( err ){
		goto error;
	}else if( res_addrs_num == 0 ){
		err = -ENOENT;
		goto error;
	}

	{
		if( rhp_ip_addr_null(&(res_addrs[0])) ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		memcpy(&(aoc_dns_ctx->peer_fqdn_addr_primary),&(res_addrs[0]),sizeof(rhp_ip_addr));
		aoc_dns_ctx->peer_fqdn_addr_primary.port = htons(rhp_gcfg_ike_port); // LOCK not needed.;

		rhp_ip_addr_dump("_rhp_vpn_aoc_timer_dns_task:1",&(aoc_dns_ctx->peer_fqdn_addr_primary));
	}

	if( res_addrs_num > 1 ){

		if( rhp_ip_addr_null(&(res_addrs[1])) ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		memcpy(&(aoc_dns_ctx->peer_fqdn_addr_secondary),&(res_addrs[1]),sizeof(rhp_ip_addr));
		aoc_dns_ctx->peer_fqdn_addr_secondary.port = htons(rhp_gcfg_ike_port); // LOCK not needed.;

		rhp_ip_addr_dump("_rhp_vpn_aoc_timer_dns_task:2",&(aoc_dns_ctx->peer_fqdn_addr_secondary));
	}


	RHP_LOG_D(RHP_LOG_SRC_VPNMNG,aoc_dns_ctx->rlm_id,RHP_LOG_ID_ALWAYS_ON_CONNECT_I_RSLV_PEER_ADDRS,"IsAA",&(aoc_dns_ctx->peer_id),aoc_dns_ctx->peer_fqdn,&(aoc_dns_ctx->peer_fqdn_addr_primary),&(aoc_dns_ctx->peer_fqdn_addr_secondary));

	if( !rhp_wts_dispach_ok(RHP_WTS_DISP_LEVEL_HIGH_2,0) ){
		err = -EBUSY;
		goto error;
	}

	err = rhp_wts_add_task(RHP_WTS_DISP_RULE_RAND,RHP_WTS_DISP_LEVEL_HIGH_2,NULL,
			_rhp_vpn_aoc_timer_dns_task_bh,aoc_dns_ctx);

	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	RHP_TRC_FREQ(0,RHPTRCID_VPN_AOC_TIMER_DNS_TASK_RTRN,"x",aoc_dns_ctx);
	return;

error:
	RHP_LOG_DE(RHP_LOG_SRC_VPNMNG,aoc_dns_ctx->rlm_id,RHP_LOG_ID_ALWAYS_ON_CONNECT_RSLV_PEER_ADDRS_ERR,"IsE",&(aoc_dns_ctx->peer_id),aoc_dns_ctx->peer_fqdn,err);

	_rhp_vpn_aoc_timer_dns_ctx_free(aoc_dns_ctx);

	RHP_TRC_FREQ(0,RHPTRCID_VPN_AOC_TIMER_DNS_TASK_ERR,"xE",aoc_dns_ctx,err);
	return;
}


static int _rhp_vpn_aoc_exec = 0;

static void _rhp_vpn_aoc_timer_task(int worker_idx,void *ctx)
{
	int err = -EINVAL;
	rhp_vpn_aoc_peer *aoc_peer;
  RHP_TRC_FREQ(0,RHPTRCID_VPN_AOC_TIMER_TASK,"dx",worker_idx,ctx);

  RHP_LOCK(&_rhp_vpn_conn_mng_lock);

  aoc_peer = _rhp_vpn_aoc_peers.lst_next;

  while( aoc_peer ){

  	err = _rhp_vpn_conn_i_check_old_vpn(aoc_peer->rlm_id,&(aoc_peer->peer_id),NULL,NULL,NULL);
  	if( err != -ENOENT ){
  		err = 0;
  		goto next;
  	}

  	if( rhp_ip_addr_null(&(aoc_peer->peer_addr)) ){

  		if( aoc_peer->peer_addr_fqdn ||
  				aoc_peer->peer_id.type == RHP_PROTO_IKE_ID_FQDN ){

				int id_len;
				int id_type;
				rhp_vpn_aoc_timer_dns* aoc_dns_ctx
					= (rhp_vpn_aoc_timer_dns*)_rhp_malloc(sizeof(rhp_vpn_aoc_timer_dns));

				if( aoc_dns_ctx == NULL ){
					RHP_BUG("");
					goto next;
				}
				memset(aoc_dns_ctx,0,sizeof(rhp_vpn_aoc_timer_dns));

				aoc_dns_ctx->tag[0] = '#';
				aoc_dns_ctx->tag[1] = 'A';
				aoc_dns_ctx->tag[2] = 'O';
				aoc_dns_ctx->tag[3] = 'D';

				aoc_dns_ctx->rlm_id = aoc_peer->rlm_id;
				aoc_dns_ctx->objid = aoc_peer->objid;

				if( aoc_peer->peer_addr_fqdn ){

					int addr_fqdn_len = strlen(aoc_peer->peer_addr_fqdn) + 1;

					aoc_dns_ctx->peer_fqdn = (char*)_rhp_malloc(addr_fqdn_len);
					if( aoc_dns_ctx->peer_fqdn == NULL ){
						RHP_BUG("");
						_rhp_vpn_aoc_timer_dns_ctx_free(aoc_dns_ctx);
						err = -ENOMEM;
						goto next;
					}

					memcpy(aoc_dns_ctx->peer_fqdn,aoc_peer->peer_addr_fqdn,addr_fqdn_len);


				}else if( aoc_peer->peer_id.type == RHP_PROTO_IKE_ID_FQDN ){

					err = rhp_ikev2_id_dup(&(aoc_dns_ctx->peer_id),&(aoc_peer->peer_id));
					if( err ){
						RHP_BUG("");
						_rhp_vpn_aoc_timer_dns_ctx_free(aoc_dns_ctx);
						goto next;
					}

					err = rhp_ikev2_id_value_str(&(aoc_peer->peer_id),(u8**)&(aoc_dns_ctx->peer_fqdn),&id_len,&id_type); // '\0' included.
					if( err ){
						RHP_BUG("");
						_rhp_vpn_aoc_timer_dns_ctx_free(aoc_dns_ctx);
						goto next;
					}

				}else{

					RHP_BUG("");
					_rhp_vpn_aoc_timer_dns_ctx_free(aoc_dns_ctx);
					goto next;
				}


				err = rhp_dns_resolve(RHP_WTS_DISP_LEVEL_HIGH_2,aoc_dns_ctx->peer_fqdn,AF_UNSPEC,
						_rhp_vpn_aoc_timer_dns_task,aoc_dns_ctx,NULL);
				if( err ){
					RHP_TRC_FREQ(0,RHPTRCID_VPN_AOC_TIMER_TASK_DNS_RSLV_ERR,"dxuE",worker_idx,ctx,aoc_peer->rlm_id,err);
					_rhp_vpn_aoc_timer_dns_ctx_free(aoc_dns_ctx);
					goto next;
				}
  		}

  		goto next;
  	}

  	{
			rhp_vpn_conn_args conn_args;

			memset(&conn_args,0,sizeof(rhp_vpn_conn_args));

			conn_args.peer_id = &(aoc_peer->peer_id);


			err = rhp_vpn_connect_i(aoc_peer->rlm_id,&conn_args,NULL,0);
			if( err ){

				RHP_TRC_FREQ(0,RHPTRCID_VPN_AOC_TIMER_TASK_VPN_CONNECT_I_ERR,"dxuE",worker_idx,ctx,aoc_peer->rlm_id,err);

				if( err == RHP_STATUS_IKESA_EXISTS ||
						err == RHP_STATUS_CONNECT_VPN_I_EAP_SUP_USER_KEY_NEEDED ){

					if( err == RHP_STATUS_CONNECT_VPN_I_EAP_SUP_USER_KEY_NEEDED ){
						RHP_LOG_DE(RHP_LOG_SRC_VPNMNG,aoc_peer->rlm_id,RHP_LOG_ID_ALWAYS_ON_CONNECT_EAP_KEY_NOT_SAVED,"IE",(aoc_peer ? &(aoc_peer->peer_id) : NULL),err);
					}

					err = 0;

				}else{

					RHP_LOG_DE(RHP_LOG_SRC_VPNMNG,aoc_peer->rlm_id,RHP_LOG_ID_ALWAYS_ON_CONNECT_START_CONN_ERR,"IAE",&(aoc_peer->peer_id),&(aoc_peer->peer_addr),err);
				}

			}else{

				RHP_LOG_D(RHP_LOG_SRC_VPNMNG,aoc_peer->rlm_id,RHP_LOG_ID_ALWAYS_ON_CONNECT_START_CONN,"IA",&(aoc_peer->peer_id),&(aoc_peer->peer_addr));
			}
  	}

next:
  	aoc_peer = aoc_peer->lst_next;
  }

	_rhp_vpn_aoc_exec = 0;

  RHP_UNLOCK(&_rhp_vpn_conn_mng_lock);

  RHP_TRC_FREQ(0,RHPTRCID_VPN_AOC_TIMER_TASK_RTRN,"dx",worker_idx,ctx);
  return;
}


static void _rhp_vpn_aoc_timer_handler(void *ctx,rhp_timer *timer)
{
	int err = 0;

  RHP_TRC_FREQ(0,RHPTRCID_VPN_AOC_TIMER_TIMER,"xx",ctx,timer);

	RHP_LOCK(&_rhp_vpn_conn_mng_lock);

	if( _rhp_vpn_aoc_exec ){
	  RHP_TRC_FREQ(0,RHPTRCID_VPN_AOC_TIMER_TIMER_NEXT_INTERVAL1,"xxd",ctx,timer,_rhp_vpn_aoc_exec);
		goto next_interval;
	}

  if( rhp_wts_dispach_ok(RHP_WTS_DISP_LEVEL_HIGH_2,1) ){

  	err = rhp_wts_add_task(RHP_WTS_DISP_RULE_MISC,RHP_WTS_DISP_LEVEL_HIGH_2,NULL,_rhp_vpn_aoc_timer_task,NULL);
  	if( err ){
  	  RHP_TRC_FREQ(0,RHPTRCID_VPN_AOC_TIMER_TIMER_NEXT_INTERVAL2,"xx",ctx,timer);
  		goto next_interval;
  	}

  	_rhp_vpn_aoc_exec = 1;

  }else{

  	RHP_TRC_FREQ(0,RHPTRCID_VPN_AOC_TIMER_TIMER_NEXT_INTERVAL3,"xx",ctx,timer);
  }

next_interval:
  rhp_timer_reset(&(_rhp_vpn_aoc_timer));
  rhp_timer_add(&(_rhp_vpn_aoc_timer),(time_t)rhp_gcfg_vpn_always_on_connect_poll_interval);

	RHP_UNLOCK(&_rhp_vpn_conn_mng_lock);

  RHP_TRC_FREQ(0,RHPTRCID_VPN_AOC_TIMER_TIMER_RTRN,"xx",ctx,timer);
	return;
}


struct _rhp_conn_i_pend {

	u8 tag[4]; // '#RIP'

	struct _rhp_conn_i_pend* next;

	unsigned long rlm_id;
	rhp_ikev2_id peer_id;

	rhp_ip_addr peer_addr;
};
typedef struct _rhp_conn_i_pend	rhp_conn_i_pend;

static rhp_conn_i_pend* _rhp_conn_i_pend_head = NULL;

static int _rhp_vpn_connect_i_pending(unsigned long rlm_id,
		rhp_ikev2_id* peer_id,rhp_ip_addr* peer_addr)
{
	rhp_conn_i_pend* conn_pnd = _rhp_conn_i_pend_head;

  RHP_TRC_FREQ(0,RHPTRCID_VPN_CONNECT_I_PENDING,"uxx",rlm_id,peer_id,peer_addr);
  rhp_ikev2_id_dump("connect_i_pending",peer_id);
  rhp_ip_addr_dump("connect_i_pending",peer_addr);

	while( conn_pnd ){

		if( conn_pnd->rlm_id == rlm_id &&
				(peer_id == NULL || !rhp_ikev2_id_cmp_no_alt_id(peer_id,&(conn_pnd->peer_id))) &&
				(peer_addr == NULL || !rhp_ip_addr_cmp_ip_only(peer_addr,&(conn_pnd->peer_addr))) ){
			break;
		}

		conn_pnd = conn_pnd->next;
	}

	if( conn_pnd ){
	  RHP_TRC_FREQ(0,RHPTRCID_VPN_CONNECT_I_PENDING_PENDING,"uxx",rlm_id,peer_id,peer_addr);
		return 1;
	}

  RHP_TRC_FREQ(0,RHPTRCID_VPN_CONNECT_I_PENDING_NOENT,"uxx",rlm_id,peer_id,peer_addr);
	return 0;
}


int rhp_vpn_connect_i_pending(unsigned long rlm_id,
		rhp_ikev2_id* peer_id,rhp_ip_addr* peer_addr)
{
	int ret;

	RHP_LOCK(&_rhp_vpn_conn_mng_lock);

	ret = _rhp_vpn_connect_i_pending(rlm_id,peer_id,peer_addr);

	RHP_UNLOCK(&_rhp_vpn_conn_mng_lock);

	return ret;
}

int rhp_vpn_connect_i_pending_put(unsigned long rlm_id,
		rhp_ikev2_id* peer_id,rhp_ip_addr* peer_addr)
{
	int err = -EINVAL;
	rhp_conn_i_pend* conn_pnd = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_VPN_CONNECT_I_PENDING_PUT,"uxx",rlm_id,peer_id,peer_addr);
  rhp_ikev2_id_dump("connect_i_pending_put",peer_id);
  rhp_ip_addr_dump("connect_i_pending_put",peer_addr);

	if( !rlm_id ){
		RHP_BUG("");
		return -EINVAL;
	}

	RHP_LOCK(&_rhp_vpn_conn_mng_lock);

	err = _rhp_vpn_connect_i_pending(rlm_id,peer_id,peer_addr);
	if( err ){
		err = -EEXIST;
		goto ignore;
	}

	conn_pnd = (rhp_conn_i_pend*)_rhp_malloc(sizeof(rhp_conn_i_pend));
	if( conn_pnd == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memset(conn_pnd,0,sizeof(rhp_conn_i_pend));
	conn_pnd->tag[0] = '#';
	conn_pnd->tag[1] = 'R';
	conn_pnd->tag[2] = 'I';
	conn_pnd->tag[3] = 'P';

	conn_pnd->rlm_id = rlm_id;

	if( peer_id ){

		err = rhp_ikev2_id_dup(&(conn_pnd->peer_id),peer_id);
		if( err ){
			_rhp_free(conn_pnd);
			goto error;
		}
	}

	if( peer_addr ){

		memcpy(&(conn_pnd->peer_addr),peer_addr,sizeof(rhp_ip_addr));
	}


	conn_pnd->next = _rhp_conn_i_pend_head;
	_rhp_conn_i_pend_head = conn_pnd;

	err = 0;

	rhp_ikev2_id_dump("conn_pnd->peer_id",&(conn_pnd->peer_id));
	rhp_ip_addr_dump("conn_pnd->peer_addr",&(conn_pnd->peer_addr));

error:
ignore:
	RHP_UNLOCK(&_rhp_vpn_conn_mng_lock);

	RHP_TRC_FREQ(0,RHPTRCID_VPN_CONNECT_I_PENDING_PUT_RTRN,"uxxE",rlm_id,peer_id,peer_addr,err);
	return err;
}


int rhp_vpn_connect_i_pending_clear(unsigned long rlm_id,
			rhp_ikev2_id* peer_id,rhp_ip_addr* peer_addr)
{
	int err = -EINVAL;
	rhp_conn_i_pend *conn_pnd, *conn_pnd_p = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_VPN_CONNECT_I_PENDING_CLEAR,"uxx",rlm_id,peer_id,peer_addr);
  rhp_ikev2_id_dump("connect_i_pending_clear",peer_id);
  rhp_ip_addr_dump("connect_i_pending_clear",peer_addr);

	RHP_LOCK(&_rhp_vpn_conn_mng_lock);

	conn_pnd = _rhp_conn_i_pend_head;

	while( conn_pnd ){

		if( conn_pnd->rlm_id == rlm_id &&
				(peer_id == NULL || !rhp_ikev2_id_cmp_no_alt_id(peer_id,&(conn_pnd->peer_id))) &&
				(peer_addr == NULL || !rhp_ip_addr_cmp_ip_only(peer_addr,&(conn_pnd->peer_addr))) ){
			break;
		}

		conn_pnd_p = conn_pnd;
		conn_pnd = conn_pnd->next;
	}

	if( conn_pnd ){

		if( conn_pnd_p ){
			conn_pnd_p->next = conn_pnd->next;
		}else{
			_rhp_conn_i_pend_head = conn_pnd->next;
		}

		rhp_ikev2_id_clear(&(conn_pnd->peer_id));
		_rhp_free(conn_pnd);

		err = 0;

	}else{
		err = -ENOENT;
	}

	RHP_UNLOCK(&_rhp_vpn_conn_mng_lock);

  RHP_TRC_FREQ(0,RHPTRCID_VPN_CONNECT_I_PENDING_CLEAR_RTRN,"uxE",rlm_id,peer_id,err);
	return err;
}
