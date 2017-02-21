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
#include "rhp_crypto.h"
#include "rhp_auth_tool.h"
#include "rhp_cert.h"
#include "rhp_ui.h"
#include "rhp_eap_auth_impl.h"
#include "rhp_radius_impl.h"

//
// TODO : Managing peer IDs and keys with DB library like SQLite.
//

rhp_mutex_t rhp_auth_lock;

rhp_mutex_t rhp_auth_radius_cfg_lock;

rhp_vpn_auth_realm* rhp_auth_realm_list_head = NULL;

struct _rhp_auth_realm_disabled {

	struct _rhp_auth_realm_disabled* next;
	unsigned long rlm_id;
};
typedef struct _rhp_auth_realm_disabled rhp_auth_realm_disabled;

static rhp_auth_realm_disabled* rhp_auth_realm_disabled_list_head = NULL;


char* rhp_syspxy_cert_store_path = NULL;
char* rhp_syspxy_policy_conf_path = NULL;

extern char* rhp_syspxy_auth_conf_path;

rhp_auth_admin_info* rhp_auth_admin_head = NULL;


// Set and get their values with rhp_auth_radius_cfg_lock acquired.
static int _rhp_auth_radius_tunnel_private_group_id_attr_enabled = 0;
static u8 _rhp_auth_radius_priv_attr_type_realm_id = 0;
static u8 _rhp_auth_radius_priv_attr_type_realm_role = 0;
static u8 _rhp_auth_radius_priv_attr_type_common = 0;

void rhp_cfg_trc_dump_auth_realm(rhp_vpn_auth_realm* auth_rlm)
{
  rhp_auth_role* roles;
  rhp_auth_peer* peers;

  RHP_TRC(0,RHPTRCID_AUTH_REALM_DUMP,"xusdddsxxxp",auth_rlm,auth_rlm->id,auth_rlm->name,auth_rlm->refcnt.c,auth_rlm->is_active.c,auth_rlm->accept_expired_cert,rhp_syspxy_cert_store_path,auth_rlm->my_auth,auth_rlm->roles,auth_rlm->peers,sizeof(rhp_vpn_auth_realm),auth_rlm);

  if( auth_rlm->my_auth ){

    RHP_TRC(0,RHPTRCID_AUTH_REALM_DUMP_MY_AUTH,"dxsx",auth_rlm->my_auth->auth_method,auth_rlm->my_auth->my_psks,auth_rlm->my_cert_store_password,auth_rlm->my_auth->cert_store);

		switch( auth_rlm->my_auth->my_id.type ){

		case RHP_PROTO_IKE_ID_ANY:
			RHP_TRC(0,RHPTRCID_AUTH_REALM_DUMP_MY_ANY,"Ldp","PROTO_IKE_ID",auth_rlm->my_auth->my_id.type,sizeof(rhp_ikev2_id),&(auth_rlm->my_auth->my_id));
			break;

		case RHP_PROTO_IKE_ID_FQDN:
		case RHP_PROTO_IKE_ID_RFC822_ADDR:
			RHP_TRC(0,RHPTRCID_AUTH_REALM_DUMP_MY_STR,"Ldsp","PROTO_IKE_ID",auth_rlm->my_auth->my_id.type,auth_rlm->my_auth->my_id.string,sizeof(rhp_ikev2_id),&(auth_rlm->my_auth->my_id));
			break;

		case RHP_PROTO_IKE_ID_DER_ASN1_DN:
		case RHP_PROTO_IKE_ID_PRIVATE_SUBJECTALTNAME:
		case RHP_PROTO_IKE_ID_PRIVATE_CERT_AUTO:
			RHP_TRC(0,RHPTRCID_AUTH_REALM_DUMP_MY_BIN,"Ldspp","PROTO_IKE_ID",auth_rlm->my_auth->my_id.type,auth_rlm->my_auth->my_id.string,auth_rlm->my_auth->my_id.dn_der_len,auth_rlm->my_auth->my_id.dn_der,sizeof(rhp_ikev2_id),&(auth_rlm->my_auth->my_id));
			break;

		case RHP_PROTO_IKE_ID_IPV4_ADDR:
		case RHP_PROTO_IKE_ID_IPV6_ADDR:
		case RHP_PROTO_IKE_ID_DER_ASN1_GN:
		case RHP_PROTO_IKE_ID_KEY_ID:
		default:
			break;
		}
  }

  roles = auth_rlm->roles;
  while( roles ){
    RHP_TRC(0,RHPTRCID_AUTH_REALM_DUMP_ROLE,"xdsxp",roles,roles->match_type,roles->string,roles->cert_dn,sizeof(rhp_auth_role),roles);
    roles = roles->next;
  }

  peers = auth_rlm->peers;
  while( peers ){

  	if( peers->peer_id_type == RHP_PEER_ID_TYPE_IKEV2 ){

			switch( peers->peer_id.ikev2.type ){

			case RHP_PROTO_IKE_ID_ANY:
				RHP_TRC(0,RHPTRCID_AUTH_REALM_DUMP_PEER_ANY,"xdxp",peers,peers->peer_id.ikev2.type,peers->peer_psks,sizeof(rhp_auth_peer),peers);
				break;

			case RHP_PROTO_IKE_ID_FQDN:
			case RHP_PROTO_IKE_ID_RFC822_ADDR:
				RHP_TRC(0,RHPTRCID_AUTH_REALM_DUMP_PEER_STR,"xdsxp",peers,peers->peer_id.ikev2.type,peers->peer_id.ikev2.string,peers->peer_psks,sizeof(rhp_auth_peer),peers);
				break;

			case RHP_PROTO_IKE_ID_DER_ASN1_DN:

				RHP_TRC(0,RHPTRCID_AUTH_REALM_DUMP_PEER_BIN,"xdspxp",peers,peers->peer_id.ikev2.type,peers->peer_id.ikev2.string,peers->peer_id.ikev2.dn_der_len,peers->peer_id.ikev2.dn_der,peers->peer_psks,sizeof(rhp_auth_peer),peers);
				break;

			case RHP_PROTO_IKE_ID_IPV4_ADDR:
			case RHP_PROTO_IKE_ID_IPV6_ADDR:

				break;

			case RHP_PROTO_IKE_ID_DER_ASN1_GN:
			case RHP_PROTO_IKE_ID_KEY_ID:
			default:
				RHP_BUG("%d",peers->peer_id.ikev2.type);
				break;
			}

  	}else if( peers->peer_id_type == RHP_PEER_ID_TYPE_EAP ){

			RHP_TRC(0,RHPTRCID_AUTH_REALM_DUMP_PEER_EAP_STR,"xdpxp",peers,peers->peer_id.eap.method,peers->peer_id.eap.identity_len,peers->peer_id.eap.identity,peers->peer_psks,sizeof(rhp_auth_peer),peers);
  	}

  	peers = peers->next;
  }
}

void rhp_auth_free_auth_peer(rhp_auth_peer* cfg_auth_peer)
{
	rhp_auth_psk *peer_psk,*peer_psk2;

  RHP_TRC(0,RHPTRCID_AUTH_FREE_AUTH_PEER,"xd",cfg_auth_peer,cfg_auth_peer->peer_id_type);

	peer_psk = cfg_auth_peer->peer_psks;
	while( peer_psk ){

		peer_psk2 = peer_psk->next;

		if( peer_psk->hashed_key ){
			_rhp_free(peer_psk->hashed_key);
    }

		if( peer_psk->key ){
			_rhp_free_zero(peer_psk->key,strlen((char*)peer_psk->key) + 1);
    }

		peer_psk = peer_psk2;
	}


	if( cfg_auth_peer->peer_id_type == RHP_PEER_ID_TYPE_IKEV2 ){

		rhp_ikev2_id_clear(&(cfg_auth_peer->peer_id.ikev2));

	}else if( cfg_auth_peer->peer_id_type == RHP_PEER_ID_TYPE_EAP ){

		rhp_eap_id_clear(&(cfg_auth_peer->peer_id.eap));
	}

	_rhp_free_zero(cfg_auth_peer,sizeof(rhp_auth_peer));

  RHP_TRC(0,RHPTRCID_AUTH_FREE_AUTH_PEER_RTRN,"x",cfg_auth_peer);
  return;
}


void _rhp_auth_free_admin(rhp_auth_admin_info* admin_info)
{
	_rhp_free(admin_info->id);

	if( admin_info->hashed_key_base64 ){
		_rhp_free_zero(admin_info->hashed_key_base64,strlen((char*)admin_info->hashed_key_base64));
	}

	if( admin_info->hashed_key ){
		_rhp_free_zero(admin_info->hashed_key,strlen((char*)admin_info->hashed_key) + 1);
	}

  if( admin_info->prf ){
  	rhp_crypto_prf_free(admin_info->prf);
  }

  _rhp_free(admin_info);
}

rhp_auth_admin_info* rhp_auth_admin_get(char* admin_id,unsigned int admin_id_len)
{
	rhp_auth_admin_info* admin_info = rhp_auth_admin_head;

	while( admin_info ){

		if( (admin_id_len == strlen((char*)admin_info->id) + 1) &&
			!strcasecmp((char*)admin_id,(char*)admin_info->id) ){
			break;
		}

		admin_info = admin_info->next_list;
	}

  RHP_TRC(0,RHPTRCID_AUTH_ADMIN_GET,"sdx",admin_id,admin_id_len,admin_info);

	return admin_info;
}

int rhp_auth_admin_replace(rhp_auth_admin_info* new_admin_info)
{
	rhp_auth_admin_info* admin_info = rhp_auth_admin_head;
	rhp_auth_admin_info* admin_info_p = NULL;

	while( admin_info ){

		if( !strcasecmp((char*)new_admin_info->id,(char*)admin_info->id) ){

			if( admin_info_p ){
				admin_info_p->next_list = new_admin_info;
			}else{
				rhp_auth_admin_head = new_admin_info;
			}
			new_admin_info->next_list = admin_info->next_list;

			_rhp_auth_free_admin(admin_info);

			break;
		}

		admin_info_p = admin_info;
		admin_info = admin_info->next_list;
	}

	if( admin_info ){

		RHP_TRC(0,RHPTRCID_AUTH_ADMIN_REPLACE,"sx",new_admin_info->id,new_admin_info);
		return 0;

	}else{

		if( admin_info_p ){
			admin_info_p->next_list = new_admin_info;
		}else{
			rhp_auth_admin_head = new_admin_info;
		}

		RHP_TRC(0,RHPTRCID_AUTH_ADMIN_REPLACE_NEW,"sx",new_admin_info->id,new_admin_info);
		return 0;
	}
}

int rhp_auth_admin_delete(char* id)
{
	rhp_auth_admin_info* admin_info = rhp_auth_admin_head;
	rhp_auth_admin_info* admin_info_p = NULL;

	while( admin_info ){

		if( !strcasecmp(id,(char*)admin_info->id) ){

			if( admin_info_p ){
				admin_info_p->next_list = admin_info->next_list;
			}else{
				rhp_auth_admin_head = admin_info->next_list;
			}

			break;
		}

		admin_info_p = admin_info;
		admin_info = admin_info->next_list;
	}

	if( admin_info ){

		RHP_TRC(0,RHPTRCID_AUTH_ADMIN_DELETE,"sx",admin_info->id,admin_info);

		_rhp_auth_free_admin(admin_info);
		return 0;

	}else{

		RHP_TRC(0,RHPTRCID_AUTH_ADMIN_DELETE_NO_ENT,"s",id);
		return -ENOENT;
	}
}

static rhp_auth_peer* _rhp_auth_realm_get_peer_by_id(rhp_vpn_auth_realm* auth_rlm,
		int id_type,void* id)
{
  rhp_auth_peer* tmp = auth_rlm->peers;
  rhp_auth_peer* tmp2 = NULL;

  RHP_TRC(0,RHPTRCID_AUTH_REALM_GET_PEER_BY_ID,"xuxd",auth_rlm,auth_rlm->id,id,id_type);

  while( tmp ){

  	if( tmp->peer_id_type == id_type ){

  		if( tmp->peer_id_type == RHP_PEER_ID_TYPE_IKEV2 ){

				rhp_ikev2_id* ikev2_id = (rhp_ikev2_id*)id;
				rhp_ikev2_id_dump("_rhp_auth_realm_get_peer_by_id",ikev2_id);

				if( tmp->peer_id.ikev2.alt_id == NULL ){

					if( !rhp_ikev2_id_cmp_no_alt_id(ikev2_id,&(tmp->peer_id.ikev2)) ){
						break;
					}

				}else{

					if( !rhp_ikev2_id_cmp(ikev2_id,&(tmp->peer_id.ikev2)) ){
						break;
					}
				}

				if( tmp2 == NULL && tmp->peer_id.ikev2.type == RHP_PROTO_IKE_ID_ANY ){
					tmp2 = tmp;
				}

  		}else if( tmp->peer_id_type == RHP_PEER_ID_TYPE_EAP ){

				rhp_eap_id* eap_id = (rhp_eap_id*)id;
				rhp_eap_id_dump("_rhp_auth_realm_get_peer_by_id",eap_id);

				if( !rhp_eap_id_cmp(eap_id,&(tmp->peer_id.eap)) ){
					break;
				}
  		}
  	}

  	tmp = tmp->next;
  }

  if( tmp == NULL ){
  	tmp = tmp2; // ANY_ID
  }

  RHP_TRC(0,RHPTRCID_AUTH_REALM_GET_PEER_BY_ID_RTRN,"xx",auth_rlm,tmp);

  return tmp;
}

static int _rhp_auth_realm_delete_auth_peer(rhp_vpn_auth_realm* auth_rlm,
		int id_type,void* id)
{
	int err = -EINVAL;
  rhp_auth_peer* tmp = auth_rlm->peers;
  rhp_auth_peer* tmp_p = NULL;

  RHP_TRC(0,RHPTRCID_AUTH_REALM_DELETE_AUTH_PEER,"xux",auth_rlm,auth_rlm->id,id);

  if( id_type == RHP_PEER_ID_TYPE_IKEV2 ){
    rhp_ikev2_id_dump("rhp_auth_realm_delete_auth_peer",id);
  }else if( id_type == RHP_PEER_ID_TYPE_EAP ){
    RHP_TRC(0,RHPTRCID_AUTH_REALM_DELETE_AUTH_PEER_EAP_ID,"dp",((rhp_eap_id*)id)->method,((rhp_eap_id*)id)->identity_len,((rhp_eap_id*)id)->identity);
  }


  while( tmp ){

  	if( tmp->peer_id_type == id_type ){

  		if( tmp->peer_id_type == RHP_PEER_ID_TYPE_IKEV2 ){

  			rhp_ikev2_id* ikev2_id = (rhp_ikev2_id*)id;

  			if( !rhp_ikev2_id_cmp(ikev2_id,&(tmp->peer_id.ikev2)) ){
					break;
				}

  		}else if( tmp->peer_id_type == RHP_PEER_ID_TYPE_EAP ){

  			rhp_eap_id* eap_id = (rhp_eap_id*)id;

				if( !rhp_eap_id_cmp(eap_id,&(tmp->peer_id.eap)) ){
					break;
				}
  		}
  	}

  	tmp_p = tmp;
  	tmp = tmp->next;
  }

  if( tmp ){

		if( tmp_p ){
			tmp_p->next = tmp->next;
		}else{
			auth_rlm->peers = tmp->next;
		}

  	rhp_auth_free_auth_peer(tmp);
  	err = 0;

  }else{
  	err = -ENOENT;
  }

  RHP_TRC(0,RHPTRCID_AUTH_REALM_DELETE_AUTH_PEER_RTRN,"xxE",auth_rlm,tmp,err);

  return err;
}

static int _rhp_auth_realm_replace_auth_peer(rhp_vpn_auth_realm* auth_rlm,rhp_auth_peer* auth_peer)
{
  rhp_auth_peer* tmp = auth_rlm->peers;
  rhp_auth_peer *tmp_p = NULL;

	if( auth_peer->peer_id_type == RHP_PEER_ID_TYPE_IKEV2 ){
	  RHP_TRC(0,RHPTRCID_AUTH_REALM_REPLACE_AUTH_PEER,"xux",auth_rlm,auth_rlm->id,auth_peer);
		rhp_ikev2_id_dump("_rhp_auth_realm_replace_auth_peer",&(auth_peer->peer_id.ikev2));
	}else if( auth_peer->peer_id_type == RHP_PEER_ID_TYPE_EAP ){
	  RHP_TRC(0,RHPTRCID_AUTH_REALM_REPLACE_AUTH_PEER_EAP_ID,"xuxdp",auth_rlm,auth_rlm->id,auth_peer,auth_peer->peer_id.eap.method,auth_peer->peer_id.eap.identity_len,auth_peer->peer_id.eap.identity);
	}

  while( tmp ){

  	if( tmp->peer_id_type == auth_peer->peer_id_type ){

			if( tmp->peer_id_type == RHP_PEER_ID_TYPE_IKEV2 ){

				if( !rhp_ikev2_id_cmp(&(auth_peer->peer_id.ikev2),&(tmp->peer_id.ikev2)) ){
					break;
				}

			}else if( tmp->peer_id_type == RHP_PEER_ID_TYPE_EAP ){

				if( !rhp_eap_id_cmp(&(auth_peer->peer_id.eap),&(tmp->peer_id.eap)) ){
					break;
				}
			}
  	}

  	tmp_p = tmp;
  	tmp = tmp->next;
  }

  if( tmp ){

		if( tmp_p ){
			tmp_p->next = auth_peer;
		}else{
			auth_rlm->peers = auth_peer;
		}
		auth_peer->next = tmp->next;

  	rhp_auth_free_auth_peer(tmp);

  }else{

  	if( tmp_p ){
			tmp_p->next = auth_peer;
		}else{
			auth_rlm->peers = auth_peer;
		}
  }

  RHP_TRC(0,RHPTRCID_AUTH_REALM_REPLACE_AUTH_PEER_RTRN,"xxx",auth_rlm,auth_peer,tmp);

  return 0;
}

rhp_vpn_auth_realm* rhp_auth_realm_alloc()
{
  rhp_vpn_auth_realm* auth_rlm = (rhp_vpn_auth_realm*)_rhp_malloc(sizeof(rhp_vpn_auth_realm));

  if( auth_rlm == NULL ){
  	RHP_BUG("");
  	return NULL;
  }

  memset(auth_rlm,0,sizeof(rhp_vpn_auth_realm));

  auth_rlm->tag[0] = '#';
  auth_rlm->tag[1] = 'V';
  auth_rlm->tag[2] = 'R';
  auth_rlm->tag[3] = 'A';

  _rhp_mutex_init("ATR",&(auth_rlm->lock));

  _rhp_atomic_init((&auth_rlm->refcnt));
  _rhp_atomic_init((&auth_rlm->is_active));

  auth_rlm->get_peer_by_id = _rhp_auth_realm_get_peer_by_id;
  auth_rlm->delete_auth_peer = _rhp_auth_realm_delete_auth_peer;
  auth_rlm->replace_auth_peer = _rhp_auth_realm_replace_auth_peer;

  RHP_TRC(0,RHPTRCID_AUTH_REALM_ALLOC,"x",auth_rlm);
  return auth_rlm;
}

static void _rhp_auth_free_cert_url(rhp_cert_url* cert_url)
{
	if( cert_url->cert_dn_str ){
		_rhp_free(cert_url->cert_dn_str);
	}
	if( cert_url->url ){
		_rhp_free(cert_url->url);
	}
	if( cert_url->cert_dn ){
		rhp_cert_dn_free(cert_url->cert_dn);
	}
	_rhp_free(cert_url);
}

void rhp_auth_free_cert_urls(rhp_cert_url* cert_url_lst_head)
{
	rhp_cert_url* cert_url = cert_url_lst_head;

	while( cert_url ){

		rhp_cert_url* cert_url_n = cert_url->next;

		_rhp_auth_free_cert_url(cert_url);

		cert_url = cert_url_n;
	}
}


void rhp_auth_free_my_auth(rhp_my_auth* my_auth)
{
	rhp_auth_psk *my_psk,*my_psk2;

	my_psk = my_auth->my_psks;
	while( my_psk ){

		my_psk2 = my_psk->next;

		if( my_psk->hashed_key ){
			_rhp_free(my_psk->hashed_key);
    }

		if( my_psk->key ){
			_rhp_free_zero(my_psk->key,strlen((char*)my_psk->key)+1);
    }

		_rhp_free(my_psk);

		my_psk = my_psk2;
	}

	rhp_ikev2_id_clear(&(my_auth->my_id));

	rhp_eap_id_clear(&(my_auth->my_eap_sup_id));

	if( my_auth->cert_store_tmp ){
		rhp_cert_store_destroy(my_auth->cert_store_tmp);
		rhp_cert_store_unhold(my_auth->cert_store_tmp);
	}

	if( my_auth->cert_store ){
		rhp_cert_store_destroy(my_auth->cert_store);
		rhp_cert_store_unhold(my_auth->cert_store);
	}

	if( my_auth->eap_sup.cached_user_id ){
		_rhp_free_zero(my_auth->eap_sup.cached_user_id,my_auth->eap_sup.cached_user_id_len);
	}
	if( my_auth->eap_sup.cached_user_key ){
		_rhp_free_zero(my_auth->eap_sup.cached_user_key,my_auth->eap_sup.cached_user_key_len);
	}

  if( my_auth->cert_urls ){
  	rhp_auth_free_cert_urls(my_auth->cert_urls);
  }

  if( my_auth->rsa_priv_key_pw ){
  	_rhp_free_zero(my_auth->rsa_priv_key_pw,strlen((char*)my_auth->rsa_priv_key_pw));
  }

  _rhp_free(my_auth);
}


static void _rhp_auth_realm_free(rhp_vpn_auth_realm* auth_rlm)
{
	unsigned long rlm_id = auth_rlm->id;
	int cert_store_flag = auth_rlm->just_updated;

  RHP_TRC(0,RHPTRCID_AUTH_REALM_FREE,"xud",auth_rlm,auth_rlm->id,cert_store_flag);


  {
  	rhp_auth_peer *cfg_auth_peer,*cfg_auth_peer_n;

  	cfg_auth_peer = auth_rlm->peers;
  	while( cfg_auth_peer ){

  		cfg_auth_peer_n = cfg_auth_peer->next;

  		rhp_auth_free_auth_peer(cfg_auth_peer);

  		cfg_auth_peer = cfg_auth_peer_n;
  	}
  }

  {
  	rhp_auth_role *auth_role,*auth_role2;

  	auth_role = auth_rlm->roles;
  	while( auth_role ){

  		auth_role2 = auth_role->next;

  		if( auth_role->string ){
  			_rhp_free(auth_role->string);
      }

  		if( auth_role->cert_dn ){
  			rhp_cert_dn_free(auth_role->cert_dn);
      }

  		_rhp_free_zero(auth_role,sizeof(rhp_auth_role));

  		auth_role = auth_role2;
  	}
  }

  if( auth_rlm->my_auth ){
  	rhp_auth_free_my_auth(auth_rlm->my_auth);
  	auth_rlm->my_auth = NULL;
  }

  if( auth_rlm->my_cert_store_password ){

  	_rhp_free(auth_rlm->my_cert_store_password);
  }

  _rhp_mutex_destroy(&(auth_rlm->lock));
  _rhp_atomic_destroy((&auth_rlm->refcnt));
  _rhp_atomic_destroy((&auth_rlm->is_active));

  if( auth_rlm->name ){
  	_rhp_free_zero(auth_rlm->name,strlen(auth_rlm->name));
  }

  _rhp_free_zero(auth_rlm,sizeof(rhp_vpn_auth_realm));

  if( !cert_store_flag ){
  	rhp_cert_store_clear_resources(rhp_syspxy_cert_store_path,rlm_id);
  }

  RHP_TRC(0,RHPTRCID_AUTH_REALM_FREE_RTRN,"xd",auth_rlm,cert_store_flag);
  return;
}

void rhp_auth_realm_hold(rhp_vpn_auth_realm* auth_rlm)
{
  _rhp_atomic_inc(&(auth_rlm->refcnt));

  RHP_TRC(0,RHPTRCID_AUTH_REALM_HOLD,"xd",auth_rlm,_rhp_atomic_read(&(auth_rlm->refcnt)));
  return;
}

void rhp_auth_realm_unhold(rhp_vpn_auth_realm* auth_rlm)
{
  RHP_TRC(0,RHPTRCID_AUTH_REALM_UNHOLD,"xd",auth_rlm,_rhp_atomic_read(&(auth_rlm->refcnt)));

  if( _rhp_atomic_dec_and_test(&(auth_rlm->refcnt)) ){

    if( auth_rlm->destructor ){
      auth_rlm->destructor(auth_rlm);
    }

    _rhp_auth_realm_free(auth_rlm);
  }

  return;
}


static rhp_vpn_auth_realm* _rhp_auth_realm_get_no_lock(unsigned long id)
{
  rhp_vpn_auth_realm* auth_rlm;

  if( id == RHP_VPN_REALM_ID_UNKNOWN ){
    RHP_TRC(0,RHPTRCID_AUTH_REALM_GET_L_ID_UNKNOWN,"d",id);
    return NULL;
  }

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return NULL;
  }

  auth_rlm = rhp_auth_realm_list_head;

  while( auth_rlm ){
    if( auth_rlm->id == id ){
      break;
    }
    auth_rlm = auth_rlm->next;
  }

  if( auth_rlm ){
    rhp_auth_realm_hold(auth_rlm);
  }

  if( auth_rlm ){
    RHP_TRC(0,RHPTRCID_AUTH_REALM_GET_L,"xu",auth_rlm,auth_rlm->id);
  }else{
    RHP_TRC(0,RHPTRCID_AUTH_REALM_GET_L_ERR,"d",id);
  }
  return auth_rlm;
}

rhp_vpn_auth_realm* rhp_auth_realm_get(unsigned long id)
{
  rhp_vpn_auth_realm* auth_rlm;

  RHP_LOCK(&rhp_auth_lock);

  auth_rlm = _rhp_auth_realm_get_no_lock(id);

  RHP_UNLOCK(&rhp_auth_lock);

  if( auth_rlm ){
    RHP_TRC(0,RHPTRCID_AUTH_REALM_GET,"xd",auth_rlm,auth_rlm->id);
  }else{
    RHP_TRC(0,RHPTRCID_AUTH_REALM_GET_ERR,"d",id);
  }
  return auth_rlm;
}

int rhp_auth_realm_put(rhp_vpn_auth_realm* auth_rlm)
{
	int err = -EINVAL;
  rhp_vpn_auth_realm *rlm_c = NULL,*rlm_p = NULL;

  RHP_TRC(0,RHPTRCID_AUTH_REALM_PUT,"xd",auth_rlm,auth_rlm->id);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return -EPERM;
  }

  RHP_LOCK(&rhp_auth_lock);

  rlm_c = _rhp_auth_realm_get_no_lock(auth_rlm->id);
  if( rlm_c ){
  	RHP_BUG("rlm->id: %d",rlm_c->id);
  	err = -EEXIST;
    rhp_auth_realm_unhold(rlm_c);
  	goto error;
  }

  rlm_c = rhp_auth_realm_list_head;

  while( rlm_c ){
    if( rlm_c->id > auth_rlm->id ){
      break;
    }
    rlm_p = rlm_c;
    rlm_c = rlm_c->next;
  }

  if( rlm_p == NULL ){
    rhp_auth_realm_list_head = auth_rlm;
    auth_rlm->next = rlm_c;
  }else{
    auth_rlm->next = rlm_p->next;
    rlm_p->next = auth_rlm;
  }

  rhp_auth_realm_hold(auth_rlm);
  err = 0;

error:
  RHP_UNLOCK(&rhp_auth_lock);
  return err;
}

static int _rhp_auth_realm_cmp_id_with_role_ikev2_id(rhp_ikev2_id* ikev2_id,rhp_auth_role* auth_role,int cmp_any)
{
  int ret = -1;

  RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_ID_WITH_ROLE_IKEV2_ID,"xxLdsd",ikev2_id,auth_role,"ROLE_TYPE",auth_role->match_type,auth_role->string,cmp_any);

  switch( auth_role->match_type ){

		case RHP_ROLE_TYPE_FQDN:

			if( ikev2_id->string == NULL || auth_role->string == NULL ){
				RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_ID_WITH_ROLE_IKEV2_ID_ERR1,"");
				return -1;
			}

			if( ikev2_id->type != RHP_PROTO_IKE_ID_FQDN ){
				RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_ID_WITH_ROLE_IKEV2_ID_ERR2,"");
				return -1;
			}

			ret = rhp_string_suffix_search((u8*)ikev2_id->string,strlen(ikev2_id->string),auth_role->string);
			break;

		case RHP_ROLE_TYPE_EMAIL:

			if( ikev2_id->string == NULL || auth_role->string == NULL ){
				RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_ID_WITH_ROLE_IKEV2_ID_ERR3,"");
				return -1;
			}

			if( ikev2_id->type != RHP_PROTO_IKE_ID_RFC822_ADDR ){
				RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_ID_WITH_ROLE_IKEV2_ID_ERR4,"");
				return -1;
			}

			ret = rhp_string_suffix_search((u8*)ikev2_id->string,strlen(ikev2_id->string),auth_role->string);
			break;

		case RHP_ROLE_TYPE_SUBJECT:
		{
			rhp_cert_dn* id_dn;

			if( ikev2_id->dn_der == NULL || auth_role->cert_dn == NULL ){
				RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_ID_WITH_ROLE_IKEV2_ID_ERR5,"");
				return -1;
			}

			if( ikev2_id->type != RHP_PROTO_IKE_ID_DER_ASN1_DN ){
				RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_ID_WITH_ROLE_IKEV2_ID_ERR6,"");
				return -1;
			}

			id_dn = rhp_cert_dn_alloc_by_DER(ikev2_id->dn_der,ikev2_id->dn_der_len);
			if( id_dn == NULL ){
				RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_ID_WITH_ROLE_IKEV2_ID_ERR7,"");
				return -1;
			}

			ret = id_dn->contains_rdns(id_dn,auth_role->cert_dn);
			rhp_cert_dn_free(id_dn);
		}
		break;

		case RHP_ROLE_TYPE_ANY:

			if( cmp_any ){
				ret = 0;
			}

			break;

		default:
		  RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_ID_WITH_ROLE_IKEV2_ID_UNKNOWN_TYPE,"xxd",ikev2_id,auth_role,auth_role->match_type);
			return -1;
	}

  RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_ID_WITH_ROLE_IKEV2_ID_RTRN,"xxd",ikev2_id,auth_role,ret);
  return ret;
}

// id_type : RHP_PEER_ID_TYPE_XXX
static int _rhp_auth_realm_cmp_id_with_role(int id_type,void* id,rhp_auth_role* auth_role,int cmp_any)
{
  int ret = -1;

  RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_ID_WITH_ROLE,"xxLdsd",id,auth_role,"ROLE_TYPE",auth_role->match_type,auth_role->string,cmp_any);

  if( id_type == RHP_PEER_ID_TYPE_IKEV2 ){

    rhp_ikev2_id_dump("_rhp_auth_realm_cmp_id_with_role",id);

    ret = _rhp_auth_realm_cmp_id_with_role_ikev2_id((rhp_ikev2_id*)id,auth_role,cmp_any);
    if( ret && ((rhp_ikev2_id*)id)->alt_id ){

      ret = _rhp_auth_realm_cmp_id_with_role_ikev2_id(((rhp_ikev2_id*)id)->alt_id,auth_role,cmp_any);
    }

  }else if( id_type == RHP_PEER_ID_TYPE_EAP ){

  	rhp_eap_id* eap_id = (rhp_eap_id*)id;
  	int id_nlen, id_nlen2;

    RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_ID_WITH_ROLE_EAP_ID,"dp",eap_id->method,eap_id->identity_len,eap_id->identity);

		if( rhp_eap_id_is_null(eap_id) || auth_role->string == NULL ){
			RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_ID_WITH_ROLE_ERR8,"");
			return -1;
		}

  	id_nlen = eap_id->identity_len;
  	id_nlen2 = strlen(auth_role->string);

		switch( auth_role->match_type ){

			case RHP_ROLE_TYPE_EAP_PREFIX_SEARCH:

				ret = strncmp((char*)eap_id->identity,auth_role->string,(id_nlen > id_nlen2 ? id_nlen2 : id_nlen));
				break;

			case RHP_ROLE_TYPE_EAP_SUFFIX_SEARCH:

				ret = rhp_string_suffix_search((u8*)eap_id->identity,eap_id->identity_len,auth_role->string);
				break;

			case RHP_ROLE_TYPE_ANY:

				if( cmp_any ){
					ret = 0;
				}

				break;

			default:
			  RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_ID_WITH_ROLE_EAP_UNKNOWN_TYPE,"xxd",id,auth_role,auth_role->match_type);
				return -1;
		}

  }else if( id_type == RHP_PEER_ID_TYPE_RADIUS_RX_ROLE ){

  	rhp_string_list* rx_radius_role = (rhp_string_list*)id; // Linked lists
  	int id_nlen, id_nlen2;

  	while( rx_radius_role ){

			RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_ID_WITH_ROLE_RADIUS_RX_ROLE,"xs",rx_radius_role,rx_radius_role->string);

			if( rx_radius_role->string == NULL || auth_role->string == NULL ){
				RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_ID_WITH_ROLE_ERR9,"");
				goto next;
			}

			id_nlen = strlen(rx_radius_role->string);
			id_nlen2 = strlen(auth_role->string);

			switch( auth_role->match_type ){

				case RHP_ROLE_TYPE_RADIUS_ATTRIBUTE:

					if( id_nlen == id_nlen2 &&
							!strcmp(rx_radius_role->string,auth_role->string) ){
						ret = 0;
					}

					break;

				case RHP_ROLE_TYPE_ANY:

					if( cmp_any ){
						ret = 0;
					}

					break;

				default:
					RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_ID_WITH_ROLE_RADIUS_RX_ROLE_UNKNOWN_TYPE,"xxd",id,auth_role,auth_role->match_type);
					return -1;
			}

			if( !ret ){
				break;
			}

next:
			rx_radius_role = rx_radius_role->next;
  	}

  }else{

  	RHP_BUG("%d",id_type);
  	return -1;
  }

  RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_ID_WITH_ROLE_RTRN,"xxd",id,auth_role,ret);
  return ret;
}

static int _rhp_auth_realm_cmp_cert_with_role(rhp_cert* cert,rhp_auth_role* auth_role,int cmp_any)
{
  int ret = -1;
  char* altname = NULL;
  int altname_len = 0;
  int altname_type = 0;
  rhp_cert_dn* dn = NULL;

  RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_CERT_WITH_ROLE,"xxLdsd",cert,auth_role,"ROLE_TYPE",auth_role->match_type,auth_role->string,cmp_any);

  if( cert == NULL ){
    RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_CERT_WITH_ROLE_ERR1,"x",auth_role);
    return -1;
  }

  if( cmp_any ){
    RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_CERT_WITH_ROLE_ERR2,"x",auth_role);
  	return -1;
  }

  dn = cert->get_cert_dn(cert);

  ret = cert->get_cert_subjectaltname(cert,&altname,&altname_len,&altname_type);
  if( ret && ret != -ENOENT ){
    RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_CERT_WITH_ROLE_ERR3,"x",auth_role);
    return -1;
  }
  ret = -1;

  switch( auth_role->match_type ){

    case RHP_ROLE_TYPE_SUBJECT:

      if( dn == NULL || auth_role->cert_dn == NULL ){
	    RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_CERT_WITH_ROLE_ERR4,"x",auth_role);
        return -1;
      }

      ret = dn->contains_rdns(dn,auth_role->cert_dn);
      break;

    case RHP_ROLE_TYPE_SUBJECTALTNAME_FQDN:

      if( altname == NULL || auth_role->string == NULL ){
        RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_CERT_WITH_ROLE_ERR5,"x",auth_role);
        return -1;
      }

      if( altname_type != RHP_PROTO_IKE_ID_FQDN ){
        RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_CERT_WITH_ROLE_ERR6,"x",auth_role);
        return -1;
      }

      ret = rhp_string_suffix_search((u8*)altname,altname_len - 1,auth_role->string);
      break;

    case RHP_ROLE_TYPE_SUBJECTALTNAME_EMAIL:

      if( altname == NULL || auth_role->string == NULL ){
        RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_CERT_WITH_ROLE_ERR7,"x",auth_role);
        return -1;
      }

      if( altname_type != RHP_PROTO_IKE_ID_RFC822_ADDR ){
        RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_CERT_WITH_ROLE_ERR8,"x",auth_role);
        return -1;
      }

      ret = rhp_string_suffix_search((u8*)altname,altname_len - 1,auth_role->string);
      break;

    default:
      RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_CERT_WITH_ROLE_UNKNOWN_TYPE,"xxd",cert,auth_role,auth_role->match_type);
      return -1;
  }

  RHP_TRC(0,RHPTRCID_AUTH_REALM_CMP_CERT_WITH_ROLE_RTRN,"xxd",cert,auth_role,ret);
  return ret;
}

// peer_id_type : RHP_PEER_ID_TYPE_XXX
static int _rhp_auth_realm_match_role(rhp_vpn_auth_realm* auth_rlm,rhp_ikev2_id* my_id,
		int peer_id_type,void* peer_id,rhp_cert* cert,int cmp_any)
{
  rhp_auth_role* auth_role = NULL;

  RHP_TRC(0,RHPTRCID_AUTH_REALM_MATCH_ROLE,"xuxdxxd",auth_rlm,auth_rlm->id,my_id,peer_id_type,peer_id,cert,cmp_any);

  if( my_id ){

  	if( auth_rlm->my_auth ){

			if( rhp_ikev2_id_cmp_sub_type_too(&(auth_rlm->my_auth->my_id),my_id) ){
				RHP_TRC(0,RHPTRCID_AUTH_REALM_MATCH_ROLE_NOT_MATCHED0,"x",auth_rlm);
				rhp_ikev2_id_dump("_rhp_auth_realm_match_role.my_auth->my_id",&(auth_rlm->my_auth->my_id));
				return -1;
			}

			if( auth_rlm->roles == NULL && cmp_any ){
				RHP_TRC(0,RHPTRCID_AUTH_REALM_ROLES_MATCHED0_ANY_ROLE,"x",auth_rlm);
				return 0;
			}

  	}else{
      RHP_TRC(0,RHPTRCID_AUTH_REALM_MATCH_ROLE_NO_MY_AUTH,"x",auth_rlm);
  	}
  }

  if( peer_id ){

		if( peer_id_type == RHP_PEER_ID_TYPE_IKEV2 &&
				((rhp_ikev2_id*)peer_id)->type == RHP_PROTO_IKE_ID_NULL_ID ){

			if( auth_rlm->null_auth_for_peers ){
				RHP_TRC(0,RHPTRCID_AUTH_REALM_ROLES_MATCHED1_NULL_ID,"xu",auth_rlm,auth_rlm->id);
				return 0;
			}

		}else{

			auth_role = auth_rlm->roles;

			if( cmp_any && (auth_role == NULL) ){
				RHP_TRC(0,RHPTRCID_AUTH_REALM_ROLES_MATCHED1_ANY_ROLE,"xu",auth_rlm,auth_rlm->id);
				return 0;
			}

			while( auth_role ){

				if( !_rhp_auth_realm_cmp_id_with_role(peer_id_type,peer_id,auth_role,cmp_any) ){
					RHP_TRC(0,RHPTRCID_AUTH_REALM_ROLES_MATCHED1,"xu",auth_rlm,auth_rlm->id);
					return 0;
				}

				auth_role = auth_role->next;
			}
		}
  }

  if( cert ){

    auth_role = auth_rlm->roles;

    if( cmp_any && (auth_role == NULL) ){
      RHP_TRC(0,RHPTRCID_AUTH_REALM_ROLES_MATCHED2_ANY_ROLE,"xu",auth_rlm,auth_rlm->id);
      return 0;
    }

    while( auth_role ){

      if( !_rhp_auth_realm_cmp_cert_with_role(cert,auth_role,cmp_any) ){
        RHP_TRC(0,RHPTRCID_AUTH_REALM_ROLES_MATCHED2,"xu",auth_rlm,auth_rlm->id);
        return 0;
      }

      auth_role = auth_role->next;
    }
  }

  RHP_TRC(0,RHPTRCID_AUTH_REALM_MATCH_ROLE_NOT_MATCHED1,"x",auth_rlm);
  return -1;
}

rhp_vpn_auth_realm* rhp_auth_realm_get_by_role(rhp_ikev2_id* my_id,
		int peer_id_type,void* peer_id,rhp_cert* cert,int also_any,
		unsigned long peer_notified_realm_id)
{
  rhp_vpn_auth_realm* auth_rlm = NULL;

  RHP_TRC(0,RHPTRCID_AUTH_REALM_GET_BY_ROLE,"xdxxu",my_id,peer_id_type,peer_id,cert,peer_notified_realm_id);
  rhp_ikev2_id_dump("rhp_auth_realm_get_by_role:my_id",my_id);
  if( peer_id_type == RHP_PEER_ID_TYPE_IKEV2 ){
  	rhp_ikev2_id_dump("_rhp_auth_realm_match_role.peer_id",(rhp_ikev2_id*)peer_id);
  }else if( peer_id_type == RHP_PEER_ID_TYPE_EAP ){
    RHP_TRC(0,RHPTRCID_AUTH_REALM_MATCH_ROLE_EAP_ID,"dp",((rhp_eap_id*)peer_id)->method,((rhp_eap_id*)peer_id)->identity_len,((rhp_eap_id*)peer_id)->identity);
  }else if( peer_id_type == RHP_PEER_ID_TYPE_RADIUS_RX_ROLE ){
    RHP_TRC(0,RHPTRCID_AUTH_REALM_MATCH_ROLE_RADIUS_RX_ROLE,"x",peer_id);
  }


  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return NULL;
  }

  RHP_LOCK(&rhp_auth_lock);

  auth_rlm = rhp_auth_realm_list_head;
  while( auth_rlm ){

  	// roles in auth_rlm are immutable. No lock needed.
    if( !_rhp_auth_realm_match_role(auth_rlm,my_id,peer_id_type,peer_id,cert,0) ){

    	if( (peer_id_type != RHP_PEER_ID_TYPE_EAP || auth_rlm->eap_for_peers) &&
    			(peer_notified_realm_id == RHP_VPN_REALM_ID_UNKNOWN ||
    			 peer_notified_realm_id == auth_rlm->id) ){
    		break;
    	}
    }

    auth_rlm = auth_rlm->next;
  }


  if( also_any && auth_rlm == NULL ){

    auth_rlm = rhp_auth_realm_list_head;
    while( auth_rlm ){

    	// roles in auth_rlm are immutable. No lock needed.
      if( !_rhp_auth_realm_match_role(auth_rlm,my_id,peer_id_type,peer_id,cert,1) ){

      	if( ( peer_id_type == RHP_PEER_ID_TYPE_IKEV2 ||

      			(peer_id_type == RHP_PEER_ID_TYPE_EAP &&
      				!((rhp_eap_id*)peer_id)->for_xauth &&
      				auth_rlm->eap_for_peers &&
      				auth_rlm->eap.role == RHP_EAP_AUTHENTICATOR &&
      				auth_rlm->eap.method != RHP_PROTO_EAP_TYPE_PRIV_RADIUS) ||

        		(peer_id_type == RHP_PEER_ID_TYPE_EAP &&
        			((rhp_eap_id*)peer_id)->for_xauth &&
        			auth_rlm->xauth.role == RHP_EAP_AUTHENTICATOR &&
        			auth_rlm->xauth.method == RHP_PROTO_EAP_TYPE_PRIV_IKEV1_XAUTH_PAP) ||

      			(peer_id_type == RHP_PEER_ID_TYPE_RADIUS_RX_ROLE &&
      				auth_rlm->eap_for_peers &&
      				auth_rlm->eap.role == RHP_EAP_AUTHENTICATOR &&
      				auth_rlm->eap.method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS) ) &&

      			(peer_notified_realm_id == RHP_VPN_REALM_ID_UNKNOWN ||
      			 peer_notified_realm_id == auth_rlm->id) ){

      		break;
      	}
      }

      auth_rlm = auth_rlm->next;
    }
  }


  if( auth_rlm ){
    rhp_auth_realm_hold(auth_rlm);
  }

  RHP_UNLOCK(&rhp_auth_lock);

  if( auth_rlm ){
    RHP_TRC(0,RHPTRCID_AUTH_REALM_GET_BY_ROLE_RTRN,"xd",auth_rlm,auth_rlm->id);
  }else{
    RHP_TRC(0,RHPTRCID_AUTH_REALM_GET_BY_ROLE_ERR,"");
  }
  return auth_rlm;
}

rhp_vpn_auth_realm* rhp_auth_realm_get_def_eap_server(rhp_ikev2_id* my_id,
		unsigned long peer_notified_realm_id)
{
  rhp_vpn_auth_realm* auth_rlm = NULL;

  RHP_TRC(0,RHPTRCID_AUTH_REALM_GET_DEF_EAP_SERVER,"xu",my_id,peer_notified_realm_id);
  rhp_ikev2_id_dump("rhp_auth_realm_get_def_eap_server:my_id",my_id);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return NULL;
  }

  RHP_LOCK(&rhp_auth_lock);

  auth_rlm = rhp_auth_realm_list_head;
	while( auth_rlm ){

		if( my_id ){

			if( rhp_ikev2_id_cmp_sub_type_too(&(auth_rlm->my_auth->my_id),my_id) ){
				goto next;
			}
		}

		if( auth_rlm->eap_for_peers &&
				auth_rlm->eap.is_default_eap_server ){
			break;
		}

next:
		auth_rlm = auth_rlm->next;
	}

	if( auth_rlm == NULL &&
			rhp_gcfg_def_eap_server_if_only_single_rlm_defined &&
			(rhp_auth_realm_list_head && rhp_auth_realm_list_head->next == NULL) ){

		auth_rlm = rhp_auth_realm_list_head;
	}

  if( auth_rlm ){

  	if( !auth_rlm->eap_for_peers ||
  			(peer_notified_realm_id != RHP_VPN_REALM_ID_UNKNOWN &&
  			 auth_rlm->id != peer_notified_realm_id) ){

  		auth_rlm = NULL;

  	}else{

  		rhp_auth_realm_hold(auth_rlm);
  	}
  }

  RHP_UNLOCK(&rhp_auth_lock);

  if( auth_rlm ){
    RHP_TRC(0,RHPTRCID_AUTH_REALM_GET_DEF_EAP_SERVER_RTRN,"xd",auth_rlm,auth_rlm->id);
  }else{
    RHP_TRC(0,RHPTRCID_AUTH_REALM_GET_DEF_EAP_SERVER_ERR,"");
  }
	return auth_rlm;
}

void rhp_auth_realm_delete(rhp_vpn_auth_realm* auth_rlm)
{
  rhp_vpn_auth_realm* tmp;
  rhp_vpn_auth_realm* tmp2 = NULL;

  RHP_TRC(0,RHPTRCID_AUTH_REALM_DELETE,"xd",auth_rlm,auth_rlm->id);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return;
  }

  RHP_LOCK(&rhp_auth_lock);

  tmp = rhp_auth_realm_list_head;

  while( tmp ){
    if( tmp == auth_rlm ){
      break;
    }
    tmp2 = tmp;
    tmp = tmp->next;
  }

  if( tmp == NULL ){
    RHP_BUG("0x%x,%d",auth_rlm,auth_rlm->id);
    goto error;
  }

  if( tmp2 ){
    tmp2->next = tmp->next;
  }
  rhp_auth_realm_unhold(auth_rlm);

error:
  RHP_UNLOCK(&rhp_auth_lock);

  return;
}

rhp_vpn_auth_realm* rhp_auth_realm_delete_by_id(unsigned long rlm_id)
{
  rhp_vpn_auth_realm* auth_rlm;
  rhp_vpn_auth_realm* tmp2 = NULL;

  RHP_TRC(0,RHPTRCID_AUTH_REALM_DELETE_BY_ID,"d",rlm_id);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return NULL;
  }

  RHP_LOCK(&rhp_auth_lock);

  auth_rlm = rhp_auth_realm_list_head;

  while( auth_rlm ){

  	if( auth_rlm->id == rlm_id ){
      break;
    }
    tmp2 = auth_rlm;
    auth_rlm = auth_rlm->next;
  }

  if( auth_rlm == NULL ){
    RHP_TRC(0,RHPTRCID_AUTH_REALM_DELETE_BY_ID_NO_ENT,"d",rlm_id);
    goto error;
  }

  rhp_auth_realm_hold(auth_rlm);

  if( tmp2 ){
    tmp2->next = auth_rlm->next;
  }else{
  	rhp_auth_realm_list_head = auth_rlm->next;
  }
  rhp_auth_realm_unhold(auth_rlm);

  auth_rlm->next = NULL;

  RHP_UNLOCK(&rhp_auth_lock);

  RHP_TRC(0,RHPTRCID_AUTH_REALM_DELETE_BY_ID_NO_ENT,"xd",auth_rlm,auth_rlm->id);
  return auth_rlm;

error:
  RHP_UNLOCK(&rhp_auth_lock);

  return NULL;
}

static int _rhp_auth_parse_peer_peer_psk(xmlNodePtr node,void* ctx)
{
  rhp_auth_peer* cfg_auth_peer = (rhp_auth_peer*)ctx;
  rhp_auth_psk *cfg_psk = NULL,*cfg_psk_p = NULL;
  char* prf_method;
  int ret_len;
  xmlChar* key_str = NULL;

  cfg_psk = (rhp_auth_psk*)_rhp_malloc(sizeof(rhp_auth_psk));
  if( cfg_psk == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }
  memset(cfg_psk,0,sizeof(rhp_auth_psk));

  cfg_psk->tag[0] = '#';
  cfg_psk->tag[1] = 'A';
  cfg_psk->tag[2] = 'P';
  cfg_psk->tag[3] = 'K';

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"prf_method"),RHP_XML_DT_STRING,&prf_method,&ret_len,NULL,0) ){

  	key_str = rhp_xml_get_prop(node,(const xmlChar*)"key");

  	if( key_str == NULL ){

    	key_str = rhp_xml_get_prop(node,(const xmlChar*)"mschapv2_key");
  	}

  	if( key_str == NULL || xmlStrlen(key_str) < 1 ){
  		RHP_BUG("");
  		goto error;
  	}


    if( rhp_xml_str2val(key_str, RHP_XML_DT_STRING,&(cfg_psk->key),&ret_len,NULL,0) ){
      RHP_BUG("");
      goto error;
    }

  }else{

    cfg_psk->prf_method = rhp_cfg_transform_str2id(RHP_PROTO_IKE_TRANSFORM_TYPE_PRF,prf_method);
    if( cfg_psk->prf_method < 0 ){
      RHP_BUG("");
      goto error;
    }

    if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"hashed_key"),RHP_XML_DT_BASE64,&(cfg_psk->hashed_key),&(cfg_psk->hashed_key_len),NULL,0) ){
      RHP_BUG("");
      goto error;
    }
  }

  cfg_psk_p = cfg_auth_peer->peer_psks;
  while( cfg_psk_p && cfg_psk_p->next ){
    cfg_psk_p = cfg_psk_p->next;
  }

  if( cfg_psk_p ){
    cfg_psk_p->next = cfg_psk;
  }else{
    cfg_auth_peer->peer_psks = cfg_psk;
  }

  if( key_str ){
  	_rhp_free_zero(key_str,xmlStrlen(key_str));
  }

  return 0;

error:
	if( key_str ){
		_rhp_free_zero(key_str,xmlStrlen(key_str));
	}
  return -EINVAL;
}

rhp_auth_peer* rhp_auth_parse_auth_peer(xmlNodePtr node)
{
	int err = -EINVAL;
  rhp_auth_peer* cfg_auth_peer = NULL;

  cfg_auth_peer = (rhp_auth_peer*)_rhp_malloc(sizeof(rhp_auth_peer));
  if( cfg_auth_peer == NULL ){
    RHP_BUG("");
    goto error;
  }
  memset(cfg_auth_peer,0,sizeof(rhp_auth_peer));

  cfg_auth_peer->tag[0] = '#';
  cfg_auth_peer->tag[1] = 'A';
  cfg_auth_peer->tag[2] = 'P';
  cfg_auth_peer->tag[3] = 'R';

  err = rhp_cfg_parse_ikev2_id(node,(const xmlChar*)"id_type",(const xmlChar*)"id",&(cfg_auth_peer->peer_id.ikev2));
  if( !err ){

  	cfg_auth_peer->peer_id_type = RHP_PEER_ID_TYPE_IKEV2;

    if( cfg_auth_peer->peer_id.ikev2.type != RHP_PROTO_IKE_ID_FQDN &&
        cfg_auth_peer->peer_id.ikev2.type != RHP_PROTO_IKE_ID_RFC822_ADDR &&
        cfg_auth_peer->peer_id.ikev2.type != RHP_PROTO_IKE_ID_IPV4_ADDR &&
        cfg_auth_peer->peer_id.ikev2.type != RHP_PROTO_IKE_ID_IPV6_ADDR &&
        cfg_auth_peer->peer_id.ikev2.type != RHP_PROTO_IKE_ID_DER_ASN1_DN &&
        cfg_auth_peer->peer_id.ikev2.type != RHP_PROTO_IKE_ID_ANY ){
      RHP_BUG("");
      goto error;
    }

  }else if( err == -ENOENT ){

  	cfg_auth_peer->peer_id_type = RHP_PEER_ID_TYPE_EAP;

    err = rhp_cfg_parse_eap_id(node,(const xmlChar*)"id_type",(const xmlChar*)"id",&(cfg_auth_peer->peer_id.eap));
    if( err ){
    	RHP_BUG("");
    	goto error;
    }

  }else{
    RHP_BUG("");
    goto error;
  }

  rhp_xml_enum_tags(node,(xmlChar*)"peer_psk",_rhp_auth_parse_peer_peer_psk,(void*)cfg_auth_peer,1);

  return cfg_auth_peer;

error:
  if( cfg_auth_peer ){
  	rhp_auth_free_auth_peer(cfg_auth_peer);
  }
  return NULL;
}

static int _rhp_auth_parse_auth_peer(xmlNodePtr node,void* ctx)
{
  rhp_vpn_auth_realm* auth_rlm = (rhp_vpn_auth_realm*)ctx;
  rhp_auth_peer* cfg_auth_peer = NULL;
  rhp_auth_peer *cfg_peer_p = NULL;

  cfg_auth_peer = rhp_auth_parse_auth_peer(node);
  if( cfg_auth_peer == NULL ){
    RHP_BUG("");
    goto error;
  }

  if( cfg_auth_peer->peer_id.ikev2.type == RHP_PROTO_IKE_ID_ANY ){
    cfg_peer_p = auth_rlm->peers;
    while(  cfg_peer_p && cfg_peer_p->next ){
      cfg_peer_p = cfg_peer_p->next;
    }
  }

  if( cfg_peer_p == NULL ){
    cfg_auth_peer->next = auth_rlm->peers;
    auth_rlm->peers = cfg_auth_peer;
  }else{
    cfg_peer_p->next = cfg_auth_peer;
  }

  return 0;

error:
  if( cfg_auth_peer ){
  	rhp_auth_free_auth_peer(cfg_auth_peer);
  }
  return -EINVAL;
}

static int _rhp_auth_parse_auth_peers(xmlNodePtr node,void* ctx)
{
  return rhp_xml_enum_tags(node,(xmlChar*)"peer",_rhp_auth_parse_auth_peer,ctx,1);
}

static int _rhp_auth_parse_auth_method_for_peers(xmlNodePtr node,void* ctx)
{
  rhp_vpn_auth_realm* auth_rlm = (rhp_vpn_auth_realm*)ctx;

  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"psk"),(xmlChar*)"disable") ){
  	auth_rlm->psk_for_peers = 0;
  }

  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"rsa_sig"),(xmlChar*)"disable") ){
  	auth_rlm->rsa_sig_for_peers = 0;
  }

  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"eap"),(xmlChar*)"disable") ){
  	auth_rlm->eap_for_peers = 0;
  }

  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"null_auth"),(xmlChar*)"enable") ){
  	auth_rlm->null_auth_for_peers = 1;
  }


  if( rhp_gcfg_ikev_other_auth_disabled_if_null_auth_enabled &&
  		auth_rlm->null_auth_for_peers ){

  	auth_rlm->psk_for_peers = 0;
  	auth_rlm->rsa_sig_for_peers = 0;
  	auth_rlm->eap_for_peers = 0;
  }

  return 0;
}

static int _rhp_auth_parse_eap(xmlNodePtr node,void* ctx)
{
  rhp_vpn_auth_realm* auth_rlm = (rhp_vpn_auth_realm*)ctx;
  int ret_len;

  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"role"),(xmlChar*)"server") ){
    auth_rlm->eap.role = RHP_EAP_AUTHENTICATOR;
  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"role"),(xmlChar*)"peer") ){
    auth_rlm->eap.role = RHP_EAP_SUPPLICANT;
  }else{
    auth_rlm->eap.role = RHP_EAP_DISABLED;
  }

  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"method"),(xmlChar*)"mschapv2") ){
    auth_rlm->eap.method = RHP_PROTO_EAP_TYPE_MS_CHAPV2;
  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"method"),(xmlChar*)"radius") ){
    auth_rlm->eap.method = RHP_PROTO_EAP_TYPE_PRIV_RADIUS;
  }else{
  	// RADIUS Auth Also
    auth_rlm->eap.method = RHP_PROTO_EAP_TYPE_NONE;
  }

  auth_rlm->eap.eap_vendor = 0; // IETF
  rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"vendor"),RHP_XML_DT_INT,&(auth_rlm->eap.eap_vendor),&ret_len,NULL,0);

  return 0;
}

static int _rhp_auth_parse_eap_server(xmlNodePtr node,void* ctx)
{
  rhp_vpn_auth_realm* auth_rlm = (rhp_vpn_auth_realm*)ctx;

  rhp_xml_check_enable(node,(xmlChar*)"default_server",&(auth_rlm->eap.is_default_eap_server));

  return 0;
}

static int _rhp_auth_parse_xauth(xmlNodePtr node,void* ctx)
{
  rhp_vpn_auth_realm* auth_rlm = (rhp_vpn_auth_realm*)ctx;
  int ret_len;

  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"role"),(xmlChar*)"server") ){
    auth_rlm->xauth.role = RHP_EAP_AUTHENTICATOR;
  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"role"),(xmlChar*)"client") ){
    auth_rlm->xauth.role = RHP_EAP_SUPPLICANT;
  }else{
    auth_rlm->xauth.role = RHP_EAP_DISABLED;
  }

  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"method"),(xmlChar*)"xauth_psk_pap") ){
    auth_rlm->xauth.method = RHP_PROTO_EAP_TYPE_PRIV_IKEV1_XAUTH_PAP;
    auth_rlm->xauth.p1_auth_method = RHP_XAUTH_P1_AUTH_PSK;
  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"method"),(xmlChar*)"xauth_rsasig_pap") ){
    auth_rlm->xauth.method = RHP_PROTO_EAP_TYPE_PRIV_IKEV1_XAUTH_PAP;
    auth_rlm->xauth.p1_auth_method = RHP_XAUTH_P1_AUTH_RSASIG;
  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"method"),(xmlChar*)"hybrid_rsasig_pap") ){
    auth_rlm->xauth.method = RHP_PROTO_EAP_TYPE_PRIV_IKEV1_XAUTH_PAP;
    auth_rlm->xauth.p1_auth_method = RHP_XAUTH_P1_AUTH_HYBRID_RSASIG;
  }else{
  	// RADIUS Auth Also
    auth_rlm->xauth.method = RHP_PROTO_EAP_TYPE_NONE;
    auth_rlm->xauth.p1_auth_method = RHP_XAUTH_P1_AUTH_NONE;
  }

  return 0;
}

static int _rhp_auth_parse_my_auth_my_psks(xmlNodePtr node,void* ctx)
{
  rhp_my_auth* my_auth = (rhp_my_auth*)ctx;
  rhp_auth_psk *cfg_psk = NULL,*cfg_psk_p = NULL;
  char* prf_method;
  int ret_len;
  xmlChar* key_str = NULL;

  cfg_psk = (rhp_auth_psk*)_rhp_malloc(sizeof(rhp_auth_psk));
  if( cfg_psk == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }
  memset(cfg_psk,0,sizeof(rhp_auth_psk));

  cfg_psk->tag[0] = '#';
  cfg_psk->tag[1] = 'A';
  cfg_psk->tag[2] = 'P';
  cfg_psk->tag[3] = 'K';

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,
  			(const xmlChar*)"prf_method"),RHP_XML_DT_STRING,&prf_method,&ret_len,NULL,0) ){

  	key_str = rhp_xml_get_prop(node,(const xmlChar*)"key");

  	if( key_str == NULL ){

    	key_str = rhp_xml_get_prop(node,(const xmlChar*)"mschapv2_key");
  	}

  	if( key_str == NULL || xmlStrlen(key_str) < 1 ){
  		RHP_BUG("");
  		goto error;
  	}

    if( rhp_xml_str2val(key_str,RHP_XML_DT_STRING,&(cfg_psk->key),&ret_len,NULL,0) ){
      RHP_BUG("");
      goto error;
    }

  }else{

    cfg_psk->prf_method = rhp_cfg_transform_str2id(RHP_PROTO_IKE_TRANSFORM_TYPE_PRF,prf_method);
    if( cfg_psk->prf_method < 0 ){
      RHP_BUG("");
      goto error;
    }

    if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"hashed_key"),RHP_XML_DT_BASE64,&(cfg_psk->hashed_key),&(cfg_psk->hashed_key_len),NULL,0) ){
      RHP_BUG("");
      goto error;
    }
  }

  cfg_psk_p = my_auth->my_psks;
  while( cfg_psk_p && cfg_psk_p->next ){
    cfg_psk_p = cfg_psk_p->next;
  }

  if( cfg_psk_p ){
    cfg_psk_p->next = cfg_psk;
  }else{
    my_auth->my_psks = cfg_psk;
  }

  if( key_str ){
  	_rhp_free_zero(key_str,xmlStrlen(key_str));
  }

  return 0;

error:
	if( key_str ){
		_rhp_free_zero(key_str,xmlStrlen(key_str));
	}
  return -EINVAL;
}

static int _rhp_auth_parse_realm_cert_store(xmlNodePtr node,void* ctx)
{
  rhp_vpn_auth_realm* auth_rlm = (rhp_vpn_auth_realm*)ctx;

  auth_rlm->accept_expired_cert = 0;
  rhp_xml_check_enable(node,(xmlChar*)"accept_expired_cert",&(auth_rlm->accept_expired_cert));

  return 0;
}

static int _rhp_auth_parse_realm_cert_my_priv_key(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
  rhp_vpn_auth_realm* auth_rlm = (rhp_vpn_auth_realm*)ctx;
  int ret_len;

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"password"),RHP_XML_DT_STRING,
  		&(auth_rlm->my_cert_store_password),&ret_len,NULL,0);

  if( err == -ENOENT ){
    RHP_TRC(0,RHPTRCID_AUTH_PARSE_REALM_CERT_MY_PRIV_KEY_NO_PASSWORD,"xu",auth_rlm,auth_rlm->id);
  	err = 0;
  }else if( err ){
    RHP_BUG("%d",err);
    return -EINVAL;
  }

  return 0;
}


static int _rhp_auth_parse_realm_cert_url(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
  rhp_cert_url* tmp_hdr = (rhp_cert_url*)ctx;
  rhp_cert_url* tmp_tail = NULL;
  int ret_len;
  rhp_cert_url* cert_url = NULL;

  cert_url = (rhp_cert_url*)_rhp_malloc(sizeof(rhp_cert_url));
  if( cert_url == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }
  memset(cert_url,0,sizeof(rhp_cert_url));


  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"type"),(xmlChar*)"my_certificate") ){
  	cert_url->is_my_cert = 1;
  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"type"),(xmlChar*)"ca_certificate") ){
  	// OK...
  }else{
  	err = -EINVAL;
    RHP_BUG("%d",err);
  	goto error;
  }


  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"url"),RHP_XML_DT_STRING,
  		&(cert_url->url),&ret_len,NULL,0);

  if( err == -ENOENT ){
    RHP_TRC(0,RHPTRCID_AUTH_PARSE_REALM_CERT_URL_NO_URL,"x",ctx);
  	err = 0;
  	goto error;
  }else if( err ){
    RHP_BUG("%d",err);
    err = -EINVAL;
    goto error;
  }


  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"dn"),RHP_XML_DT_STRING,
  		&(cert_url->cert_dn_str),&ret_len,NULL,0);

  if( err == -ENOENT ){

    RHP_TRC(0,RHPTRCID_AUTH_PARSE_REALM_CERT_URL_NO_DN,"x",ctx);

    if( !cert_url->is_my_cert ){
    	goto error;
    }
    err = 0;

  }else if( err ){
    RHP_BUG("%d",err);
    err = -EINVAL;
    goto error;
  }


  tmp_tail = tmp_hdr;
  while( tmp_tail->next ){
  	tmp_tail = tmp_tail->next;
  }

  tmp_tail->next = cert_url;

  return 0;

error:
	if( cert_url ){
		_rhp_auth_free_cert_url(cert_url);
	}
	return err;
}

static int _rhp_auth_parse_realm_cert_urls(xmlNodePtr node,void* ctx)
{
  return rhp_xml_enum_tags(node,(xmlChar*)"cert_url",_rhp_auth_parse_realm_cert_url,ctx,1);
}


rhp_cert_url* rhp_auth_parse_realm_cert_urls(xmlNodePtr node,unsigned long rlm_id)
{
	int err = -EINVAL;
	rhp_cert_url tmp_hdr;

  RHP_TRC(0,RHPTRCID_AUTH_PARSE_REALM_CERT,"xu",node,rlm_id);

	memset(&tmp_hdr,0,sizeof(rhp_cert_url));

  err = rhp_xml_enum_tags(node,(xmlChar*)"cert_urls",_rhp_auth_parse_realm_cert_urls,&tmp_hdr,0);
  if( err == -ENOENT ){
    RHP_TRC(0,RHPTRCID_AUTH_PARSE_REALM_CERT_NO_CERT_URL,"u",rlm_id);
    err = 0;
  }else if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_AUTH_PARSE_REALM_CERT_RTRN,"xux",node,rlm_id,tmp_hdr.next);
  return tmp_hdr.next;

error:
	if( tmp_hdr.next ){
		rhp_auth_free_cert_urls(tmp_hdr.next);
	}
  RHP_TRC(0,RHPTRCID_AUTH_PARSE_REALM_CERT_ERR,"xu",node,rlm_id);
  return NULL;
}

int rhp_auth_resolve_my_auth_cert_my_id(rhp_my_auth* my_auth,rhp_cert_store* cert_store)
{
	int err = -EINVAL;
  int dmy_len;

	RHP_TRC(0,RHPTRCID_AUTH_RESOLVE_MY_AUTH_CERT_MY_ID,"xx",my_auth,cert_store);

	if( my_auth->my_id.type == RHP_PROTO_IKE_ID_DER_ASN1_DN ){

subjectName:
		err = cert_store->get_my_cert_dn_der(cert_store,&(my_auth->my_id.dn_der),&(my_auth->my_id.dn_der_len));
		if( err == -ENOENT ){
			RHP_TRC(0,RHPTRCID_AUTH_RESOLVE_MY_AUTH_CERT_MY_ID_NO_MY_CERT_DN_DER,"xxLd",my_auth,cert_store,"PROTO_IKE_ID",my_auth->my_id.type);
			goto error;
		}else if( err ){
			RHP_BUG("");
			goto error;
		}

		if( my_auth->my_id.type == RHP_PROTO_IKE_ID_PRIVATE_CERT_AUTO ){
			my_auth->my_id.cert_sub_type = RHP_PROTO_IKE_ID_DER_ASN1_DN;
		}

	}else if( my_auth->my_id.type == RHP_PROTO_IKE_ID_PRIVATE_SUBJECTALTNAME ){

		err = cert_store->get_my_cert_subjectaltname(cert_store,&(my_auth->my_id.string),&dmy_len,&(my_auth->my_id.cert_sub_type));
		if( err == -ENOENT ){
			RHP_TRC(0,RHPTRCID_AUTH_RESOLVE_MY_AUTH_CERT_MY_ID_NO_MY_SUBJECTALTNAME,"xxLd",my_auth,cert_store,"PROTO_IKE_ID",my_auth->my_id.type);
			goto error;
		}else if( err ){
			RHP_BUG("");
			goto error;
		}

	}else if( my_auth->my_id.type == RHP_PROTO_IKE_ID_PRIVATE_CERT_AUTO ){

		err = cert_store->get_my_cert_subjectaltname(cert_store,&(my_auth->my_id.string),&dmy_len,&(my_auth->my_id.cert_sub_type));
		if( err == -ENOENT ){

			RHP_TRC(0,RHPTRCID_AUTH_RESOLVE_MY_AUTH_CERT_MY_ID_NO_CERT_DN_DER,"xxLd",my_auth,cert_store,"PROTO_IKE_ID",my_auth->my_id.type);
			goto subjectName;

		}else if( err ){

			RHP_BUG("");
			goto error;

		}else{

			RHP_TRC(0,RHPTRCID_AUTH_RESOLVE_MY_AUTH_CERT_MY_ID_CERT_AUTO_SUB_TYPE,"xxLd",my_auth,cert_store,"PROTO_IKE_ID",my_auth->my_id.cert_sub_type);
		}

	}else{
		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_AUTH_RESOLVE_MY_AUTH_CERT_MY_ID_NOT_INTERESTED,"xxLd",my_auth,cert_store,"PROTO_IKE_ID",my_auth->my_id.type);
		goto error;
	}

	RHP_TRC(0,RHPTRCID_AUTH_RESOLVE_MY_AUTH_CERT_MY_ID_RTRN,"xxLdLd",my_auth,cert_store,"PROTO_IKE_ID",my_auth->my_id.type,"PROTO_IKE_ID",my_auth->my_id.cert_sub_type);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_AUTH_RESOLVE_MY_AUTH_CERT_MY_ID_ERR,"xxE",my_auth,cert_store,err);
	return err;
}

rhp_my_auth* rhp_auth_parse_auth_my_auth(xmlNodePtr node,unsigned long rlm_id)
{
	int err = -EINVAL;
	rhp_my_auth* my_auth = NULL;
	int eap_sup_enabled = 0;
  int ret_len;

	my_auth = (rhp_my_auth*)_rhp_malloc(sizeof(rhp_my_auth));
	if( my_auth == NULL ){
		RHP_BUG("");
		goto error;
	}
	memset(my_auth,0,sizeof(rhp_my_auth));

	my_auth->tag[0] = '#';
	my_auth->tag[1] = 'M';
	my_auth->tag[2] = 'A';
	my_auth->tag[3] = 'U';

  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,
  			(xmlChar*)"auth_method"),(xmlChar*)"psk") ){

    my_auth->auth_method = RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY;

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,
  						(xmlChar*)"auth_method"),(xmlChar*)"rsa-sig") ){

    my_auth->auth_method = RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG;

    err = rhp_xml_str2val(rhp_xml_get_prop(node,(const xmlChar*)"upload_cert_file_password"),
    			RHP_XML_DT_STRING,&(my_auth->rsa_priv_key_pw),&ret_len,NULL,0);
    if( err && err != -ENOENT ){
      RHP_BUG("");
      goto error;
    }
    err = 0;

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,
  						(xmlChar*)"auth_method"),(xmlChar*)"eap") ){

    my_auth->auth_method = RHP_PROTO_IKE_AUTHMETHOD_NONE;
    eap_sup_enabled = 1;

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,
  						(xmlChar*)"auth_method"),(xmlChar*)"null-auth") ){

  	my_auth->auth_method = RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH;

  }else{
    RHP_BUG("");
    goto error;
  }


  if( my_auth->auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ||
  		my_auth->auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG 		||
  		my_auth->auth_method == RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH ){

  	if( rhp_cfg_parse_ikev2_id(node,(const xmlChar*)"id_type",(const xmlChar*)"id",&(my_auth->my_id)) ){
			RHP_BUG("");
			goto error;
		}

  	if( (my_auth->my_id.type == RHP_PROTO_IKE_ID_NULL_ID &&
  			 my_auth->auth_method != RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH) ||
  			(my_auth->my_id.type != RHP_PROTO_IKE_ID_FQDN &&
				 my_auth->my_id.type != RHP_PROTO_IKE_ID_RFC822_ADDR &&
				 my_auth->my_id.type != RHP_PROTO_IKE_ID_IPV4_ADDR &&
				 my_auth->my_id.type != RHP_PROTO_IKE_ID_IPV6_ADDR &&
				 my_auth->my_id.type != RHP_PROTO_IKE_ID_DER_ASN1_DN &&
				 my_auth->my_id.type != RHP_PROTO_IKE_ID_PRIVATE_SUBJECTALTNAME &&
				 my_auth->my_id.type != RHP_PROTO_IKE_ID_PRIVATE_CERT_AUTO &&
				 my_auth->my_id.type != RHP_PROTO_IKE_ID_NULL_ID) ){
  		RHP_BUG("%d",my_auth->my_id.type);
			goto error;
		}

  }else if( eap_sup_enabled ){

  	int eap_method = 0;

    if( rhp_cfg_parse_eap_method(node,(const xmlChar*)"id_type",&eap_method) ){
    	RHP_BUG("");
    	goto error;
    }

    if( eap_method ){

  		rhp_cfg_parse_eap_id(node,(const xmlChar*)"id_type",(const xmlChar*)"id",&(my_auth->my_eap_sup_id));

    }else{
    	RHP_BUG("");
    	goto error;
  	}

    my_auth->eap_sup.user_key_cache_enabled = 1;
    rhp_xml_check_enable(node,(xmlChar*)"eap_sup_key_cached",&(my_auth->eap_sup.user_key_cache_enabled));
  }


  err = rhp_xml_enum_tags(node,(xmlChar*)"my_psk",_rhp_auth_parse_my_auth_my_psks,my_auth,1);
  if( err == -ENOENT ){
    RHP_TRC(0,RHPTRCID_AUTH_PARSE_MY_AUTH_NO_MY_PSK_OR_PASSWORD,"x",my_auth);
    err = 0;
  }else if( err ){
    RHP_BUG("");
    goto error;
  }

  if( my_auth->my_psks == NULL && rhp_syspxy_cert_store_path == NULL ){
    RHP_BUG("");
    goto error;
  }

  return my_auth;

error:
	rhp_auth_free_my_auth(my_auth);
  return NULL;
}

int rhp_auth_setup_cert_urls(rhp_cert_store* cert_store,rhp_my_auth* my_auth,unsigned long rlm_id)
{
	rhp_cert_url* cert_url = my_auth->cert_urls;

	RHP_TRC(0,RHPTRCID_AUTH_SETUP_CERT_URLS,"xxux",cert_store,my_auth,rlm_id,cert_url);

	while( cert_url ){

		if( cert_url->cert_dn ){
			rhp_cert_dn_free(cert_url->cert_dn);
			cert_url->cert_dn = NULL;
		}

		if( cert_url->is_my_cert && cert_url->cert_dn_str == NULL ){

			cert_url->cert_dn_str = cert_store->get_my_cert_dn_text(cert_store);
			if( cert_url->cert_dn_str == NULL ){
				RHP_TRC(0,RHPTRCID_AUTH_SETUP_CERT_URLS_NO_MY_CERT_DN,"xxu",cert_store,my_auth,rlm_id);
			}
		}

		if( cert_url->cert_dn_str ){

			cert_url->cert_dn = rhp_cert_dn_alloc_by_text(cert_url->cert_dn_str);
			if( cert_url->cert_dn == NULL ){
				RHP_TRC(0,RHPTRCID_AUTH_SETUP_CERT_URLS_FAILED_TO_PARSE_CERT_DN,"xxus",cert_store,my_auth,rlm_id,cert_url->cert_dn_str);
				RHP_LOG_E(RHP_LOG_SRC_AUTHCFG,rlm_id,RHP_LOG_ID_CERT_URL_INVALID_DN,"sss",(cert_url->is_my_cert ? "My certificate" : "CA certificate"),cert_url->url,cert_url->cert_dn_str);
			}

		}else{
			RHP_TRC(0,RHPTRCID_AUTH_SETUP_CERT_URLS_NO_CERT_DN,"xxu",cert_store,my_auth,rlm_id);
		}

		RHP_TRC(0,RHPTRCID_AUTH_SETUP_CERT_URLS_DONE,"xxuxdssx",cert_store,my_auth,rlm_id,cert_url,cert_url->is_my_cert,cert_url->url,cert_url->cert_dn_str,cert_url->cert_dn);
		if( cert_url->cert_dn ){
			RHP_LOG_D(RHP_LOG_SRC_AUTHCFG,rlm_id,RHP_LOG_ID_CERT_URL,"sss",(cert_url->is_my_cert ? "My certificate" : "CA certificate"),cert_url->url,cert_url->cert_dn_str);
		}else{
			RHP_LOG_D(RHP_LOG_SRC_AUTHCFG,rlm_id,RHP_LOG_ID_CERT_URL_IGNORED,"sss",(cert_url->is_my_cert ? "My certificate" : "CA certificate"),cert_url->url,cert_url->cert_dn_str);
		}

		cert_url = cert_url->next;
	}

	RHP_TRC(0,RHPTRCID_AUTH_SETUP_CERT_URLS_RTRN,"xxu",cert_store,my_auth,rlm_id);
	return 0;
}

static int _rhp_auth_setup_cert_store(rhp_vpn_auth_realm* auth_rlm)
{
	int err = -EINVAL;
	unsigned long rlm_id = auth_rlm->id;
	rhp_my_auth* my_auth = auth_rlm->my_auth;
  rhp_cert_store* cert_store = NULL;

  RHP_TRC(0,RHPTRCID_AUTH_SETUP_CERT_STORE,"xxu",auth_rlm,my_auth,rlm_id);

  if( my_auth && rhp_syspxy_cert_store_path ){

    cert_store = rhp_cert_store_alloc(rhp_syspxy_cert_store_path,rlm_id,auth_rlm->my_cert_store_password);

    if( cert_store == NULL ){
      RHP_TRC(0,RHPTRCID_AUTH_SETUP_CERT_STORE_FAILED_TO_ALLOC_CERT_STORE,"xuss",auth_rlm,rlm_id,rhp_syspxy_cert_store_path,auth_rlm->my_cert_store_password);
    	goto no_cert_store;
    }

    err = rhp_auth_resolve_my_auth_cert_my_id(my_auth,cert_store);
    if( err && err != -ENOENT ){
      RHP_BUG("%d",err);
      goto error;
    }
    err = 0;

		if( cert_store->imcomplete &&
				(my_auth->auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG) ){

	      RHP_TRC(0,RHPTRCID_AUTH_SETUP_CERT_STORE_ALLOC_IMCOMPLETE_CERT_STORE,"uss",rlm_id,rhp_syspxy_cert_store_path,auth_rlm->my_cert_store_password);
	      my_auth->cert_store_tmp = cert_store;

		}else{

			my_auth->cert_store = cert_store;
    }


		err = rhp_auth_setup_cert_urls(cert_store,my_auth,rlm_id);
		if( err ){
      RHP_BUG("%d",err);
			goto error;
		}

  }else{

  	RHP_TRC(0,RHPTRCID_AUTH_SETUP_CERT_STORE_NO_CERT_STORE_PATH_OR_NO_MY_AUTH,"xu",auth_rlm,auth_rlm->id,my_auth);
  }

no_cert_store:
	RHP_TRC(0,RHPTRCID_AUTH_SETUP_CERT_STORE_RTRN,"xu",auth_rlm,rlm_id);
	return 0;

error:
	if( cert_store ){
		rhp_cert_store_destroy(cert_store);
		rhp_cert_store_unhold(cert_store);
		my_auth->cert_store = NULL;
		my_auth->cert_store_tmp = NULL;
	}
  RHP_TRC(0,RHPTRCID_AUTH_SETUP_CERT_STORE_ERR,"xuE",auth_rlm,rlm_id,err);
	return err;
}


static int _rhp_auth_parse_auth_my_auth(xmlNodePtr node,void* ctx)
{
  rhp_vpn_auth_realm* auth_rlm = (rhp_vpn_auth_realm*)ctx;

  auth_rlm->my_auth = rhp_auth_parse_auth_my_auth(node,auth_rlm->id);

  if( auth_rlm->my_auth == NULL ){
  	return -EINVAL;
  }

  return 0;
}


// TODO Should we support regex matching for role string??? (But regex is sometimes very heavy ,
// too flexible and insecure..., I think).
static int _rhp_auth_parse_role(xmlNodePtr node,void* ctx)
{
  rhp_vpn_auth_realm* auth_rlm = (rhp_vpn_auth_realm*)ctx;
  rhp_auth_role* auth_role;
  int ret_len;

  auth_role = (rhp_auth_role*)_rhp_malloc(sizeof(rhp_auth_role));
  if( auth_role == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }
  memset(auth_role,0,sizeof(rhp_auth_role));

  auth_role->tag[0] = '#';
  auth_role->tag[1] = 'A';
  auth_role->tag[2] = 'R';
  auth_role->tag[3] = 'L';

  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"type"),
  		(xmlChar*)"fqdn") ){

    auth_role->match_type = RHP_ROLE_TYPE_FQDN;

    if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"match"),
    		RHP_XML_DT_STRING,&(auth_role->string),&ret_len,NULL,0) ){
    	RHP_BUG("");
    	goto error;
    }

    if( ret_len == 0 ){
    	RHP_BUG("");
    	goto error;
    }

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"type"),
  		(xmlChar*)"email") ){

    auth_role->match_type = RHP_ROLE_TYPE_EMAIL;

    if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"match"),
    		RHP_XML_DT_STRING,&(auth_role->string),&ret_len,NULL,0) ){
    	RHP_BUG("");
    	goto error;
    }

    if( ret_len == 0 ){
    	RHP_BUG("");
    	goto error;
    }

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"type"),
  		(xmlChar*)"subject") ){

    auth_role->match_type = RHP_ROLE_TYPE_SUBJECT;

    if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"match"),
    		RHP_XML_DT_STRING,&(auth_role->string),&ret_len,NULL,0) ){
      RHP_BUG("");
      goto error;
    }

    auth_role->cert_dn = rhp_cert_dn_alloc_by_text(auth_role->string);
    if( auth_role->cert_dn == NULL ){
      RHP_BUG("");
      goto error;
    }

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"type"),
  		(xmlChar*)"subjectAltName_fqdn") ){

    auth_role->match_type = RHP_ROLE_TYPE_SUBJECTALTNAME_FQDN;

    if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"match"),
    		RHP_XML_DT_STRING,&(auth_role->string),&ret_len,NULL,0) ){
      RHP_BUG("");
      goto error;
    }

    if( ret_len == 0 ){
      RHP_BUG("");
      goto error;
    }

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"type"),
  		(xmlChar*)"subjectAltName_email") ){

    auth_role->match_type = RHP_ROLE_TYPE_SUBJECTALTNAME_EMAIL;

    if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"match"),
    		RHP_XML_DT_STRING,&(auth_role->string),&ret_len,NULL,0) ){
    	RHP_BUG("");
      goto error;
    }

    if( ret_len == 0 ){
    	RHP_BUG("");
      goto error;
    }

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"type"),
  		(xmlChar*)"eap_prefix_search") ){

    auth_role->match_type = RHP_ROLE_TYPE_EAP_PREFIX_SEARCH;

    if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"match"),
    		RHP_XML_DT_STRING,&(auth_role->string),&ret_len,NULL,0) ){
      RHP_BUG("");
      goto error;
    }

    if( ret_len == 0 ){
      RHP_BUG("");
      goto error;
    }

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"type"),
  		(xmlChar*)"eap_suffix_search") ){

    auth_role->match_type = RHP_ROLE_TYPE_EAP_SUFFIX_SEARCH;

    if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"match"),
    		RHP_XML_DT_STRING,&(auth_role->string),&ret_len,NULL,0) ){
      RHP_BUG("");
      goto error;
    }

    if( ret_len == 0 ){
      RHP_BUG("");
      goto error;
    }

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"type"),
  		(xmlChar*)"radius_attribute_value") ){

    auth_role->match_type = RHP_ROLE_TYPE_RADIUS_ATTRIBUTE;

    if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"match"),
    		RHP_XML_DT_STRING,&(auth_role->string),&ret_len,NULL,0) ){
      RHP_BUG("");
      goto error;
    }

    if( ret_len == 0 ){
      RHP_BUG("");
      goto error;
    }

  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"type"),(xmlChar*)"any") ){

    auth_role->match_type = RHP_ROLE_TYPE_ANY;

  }else{
    RHP_BUG("");
    goto error;
  }

  auth_role->next = auth_rlm->roles;
  auth_rlm->roles = auth_role;

  return 0;

error:
  if( auth_role->string ){
    _rhp_free(auth_role->string);
  }
  if( auth_role->cert_dn ){
    rhp_cert_dn_free(auth_role->cert_dn);
  }
  if( auth_role ){
    _rhp_free(auth_role);
  }
  return -1;
}

static int _rhp_auth_parse_roles(xmlNodePtr node,void* ctx)
{
  return rhp_xml_enum_tags(node,(xmlChar*)"role",_rhp_auth_parse_role,ctx,1);
}

rhp_vpn_auth_realm* rhp_auth_parse_auth_realm(xmlNodePtr realm_node)
{
	int err = -EINVAL;
  rhp_vpn_auth_realm* auth_rlm = rhp_auth_realm_alloc();
  int ret_len;
  char rlm_name_def[64];
  int flag;

	RHP_TRC(0,RHPTRCID_AUTH_PARSE_AUTH_REALM,"xx",realm_node,auth_rlm);

  if( auth_rlm == NULL ){
    RHP_BUG("");
    return NULL;
  }

  if( rhp_xml_str2val(rhp_xml_get_prop_static(realm_node,(const xmlChar*)"id"),RHP_XML_DT_ULONG,&(auth_rlm->id),&ret_len,NULL,0) ){
  	RHP_LOG_W(RHP_LOG_SRC_AUTHCFG,0,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm id=?&gt",-EINVAL);
    RHP_BUG("");
    goto error;
  }

  if( auth_rlm->id == 0 || auth_rlm->id > RHP_VPN_REALM_ID_MAX ){
  	RHP_LOG_W(RHP_LOG_SRC_AUTHCFG,0,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm id=?&gt",-EINVAL);
    RHP_BUG("%d",auth_rlm->id);
    goto error;
  }


  rlm_name_def[0] = '\0';
  sprintf(rlm_name_def,"realm%lu",auth_rlm->id);


  rhp_xml_str2val(rhp_xml_get_prop_static(realm_node,(const xmlChar*)"name"),RHP_XML_DT_STRING,&(auth_rlm->name),&ret_len,rlm_name_def,0);


  {
  	int realm_enabled = 1;
    rhp_xml_check_enable(realm_node,(xmlChar*)"status",&realm_enabled);

    if( !realm_enabled ){
    	auth_rlm->disabled = 1;
    }
  }


  flag = 0;
  rhp_xml_check_enable(realm_node,(xmlChar*)"authentication_ticket",&flag);
  auth_rlm->auth_tkt_enabled = flag;


  err = rhp_xml_enum_tags(realm_node,(xmlChar*)"cert_store",_rhp_auth_parse_realm_cert_store,auth_rlm,0);
  if( err == -ENOENT ){
    RHP_TRC(0,RHPTRCID_AUTH_PARSE_AUTH_REALM_NO_CERT_STORE,"xu",auth_rlm,auth_rlm->id);
    err = 0;
  }else if( err ){
  	RHP_LOG_W(RHP_LOG_SRC_AUTHCFG,auth_rlm->id,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm&lt&gtcert_store&gt",err);
    RHP_BUG("%d",err);
    goto error;
  }


  err = rhp_xml_enum_tags(realm_node,(xmlChar*)"cert_my_priv_key",_rhp_auth_parse_realm_cert_my_priv_key,auth_rlm,0);
  if( err == -ENOENT ){
    RHP_TRC(0,RHPTRCID_AUTH_PARSE_AUTH_REALM_NO_CERT_MY_PRIV_KEY,"xu",auth_rlm,auth_rlm->id);
    err = 0;
  }else if( err ){
  	RHP_LOG_W(RHP_LOG_SRC_AUTHCFG,auth_rlm->id,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm&lt&gtcert_my_priv_key&gt",err);
    RHP_BUG("%d",err);
    goto error;
  }

  {
    auth_rlm->eap.role = RHP_EAP_DISABLED;
    auth_rlm->eap.method = RHP_PROTO_EAP_TYPE_NONE;

  	err = rhp_xml_enum_tags(realm_node,(xmlChar*)"eap",_rhp_auth_parse_eap,auth_rlm,0);
		if( err == -ENOENT ){
			err = 0;
			RHP_TRC(0,RHPTRCID_AUTH_PARSE_AUTH_REALM_NO_EAP,"xu",auth_rlm,auth_rlm->id);
		}else if( err ){
			RHP_LOG_W(RHP_LOG_SRC_AUTHCFG,auth_rlm->id,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm&lt&gteap&gt",err);
			RHP_BUG("%d",err);
			goto error;
		}


		auth_rlm->eap.is_default_eap_server = 0;

		err = rhp_xml_enum_tags(realm_node,(xmlChar*)"eap_server",_rhp_auth_parse_eap_server,auth_rlm,0);
		if( err == -ENOENT ){
			err = 0;
			RHP_TRC(0,RHPTRCID_AUTH_PARSE_AUTH_REALM_NO_EAP,"xu",auth_rlm,auth_rlm->id);
		}else if( err ){
			RHP_LOG_W(RHP_LOG_SRC_AUTHCFG,auth_rlm->id,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm&lt&gteap&gt",err);
			RHP_BUG("%d",err);
			goto error;
		}
	}

  {
    auth_rlm->xauth.role = RHP_EAP_DISABLED;
    auth_rlm->xauth.method = RHP_PROTO_EAP_TYPE_NONE;
    auth_rlm->xauth.p1_auth_method = RHP_XAUTH_P1_AUTH_NONE;

  	err = rhp_xml_enum_tags(realm_node,(xmlChar*)"xauth",_rhp_auth_parse_xauth,auth_rlm,0);
		if( err == -ENOENT ){
			err = 0;
			RHP_TRC(0,RHPTRCID_AUTH_PARSE_AUTH_REALM_NO_EAP,"xu",auth_rlm,auth_rlm->id);
		}else if( err ){
			RHP_LOG_W(RHP_LOG_SRC_AUTHCFG,auth_rlm->id,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm&lt&gtxauth&gt",err);
			RHP_BUG("%d",err);
			goto error;
		}
	}



  {
		auth_rlm->psk_for_peers = 1;
		auth_rlm->rsa_sig_for_peers = 1;
		auth_rlm->eap_for_peers = (auth_rlm->eap.role == RHP_EAP_AUTHENTICATOR ? 1 : 0);
		auth_rlm->null_auth_for_peers = 0;

		err = rhp_xml_enum_tags(realm_node,(xmlChar*)"auth_method_for_peers",_rhp_auth_parse_auth_method_for_peers,auth_rlm,1);
		if( err && err != -ENOENT ){
			RHP_LOG_W(RHP_LOG_SRC_AUTHCFG,auth_rlm->id,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm&gt&ltservice&gt",err);
			RHP_BUG("");
			goto error;
		}
		err = 0;
  }


  err = rhp_xml_enum_tags(realm_node,(xmlChar*)"my_auth",_rhp_auth_parse_auth_my_auth,auth_rlm,0);
  if( err == -ENOENT ){
    RHP_TRC(0,RHPTRCID_AUTH_PARSE_AUTH_REALM_NO_MY_AUTH,"xu",auth_rlm,auth_rlm->id);
    err = 0;
  }else if( err ){
  	RHP_LOG_W(RHP_LOG_SRC_AUTHCFG,auth_rlm->id,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm&lt&gtmy_auth&gt",err);
    RHP_BUG("%d",err);
    goto error;
  }


  if( auth_rlm->my_auth ){

  	auth_rlm->my_auth->cert_urls = rhp_auth_parse_realm_cert_urls(realm_node,auth_rlm->id);

		if( auth_rlm->my_auth->cert_urls == NULL ){
			RHP_TRC(0,RHPTRCID_AUTH_PARSE_AUTH_REALM_NO_CERT_URL,"xu",auth_rlm,auth_rlm->id);
		}

  }else{

		RHP_TRC(0,RHPTRCID_AUTH_PARSE_AUTH_REALM_PARSE_CERT_URL_NO_MY_AUTH,"xu",auth_rlm,auth_rlm->id);
  }


  err = rhp_xml_enum_tags(realm_node,(xmlChar*)"roles",_rhp_auth_parse_roles,auth_rlm,0);
  if( err == -ENOENT ){
    auth_rlm->roles = NULL;
    err = 0;
    RHP_TRC(0,RHPTRCID_AUTH_PARSE_AUTH_REALM_NO_ROLES,"xu",auth_rlm,auth_rlm->id);
  }else if( err ){
  	RHP_LOG_W(RHP_LOG_SRC_AUTHCFG,auth_rlm->id,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm&lt&gtroles&gt",err);
    RHP_BUG("%d",err);
    goto error;
  }


  err = rhp_xml_enum_tags(realm_node,(xmlChar*)"peers",_rhp_auth_parse_auth_peers,auth_rlm,0);
  if( err == -ENOENT ){
    err = 0;
    RHP_TRC(0,RHPTRCID_AUTH_PARSE_AUTH_REALM_NO_PEERS,"xu",auth_rlm,auth_rlm->id);
  }else if( err ){
  	RHP_LOG_W(RHP_LOG_SRC_AUTHCFG,auth_rlm->id,RHP_LOG_ID_CFG_PARSE_ERR,"sE","&ltvpn_realm&lt&gtpeers&gt",err);
    RHP_BUG("%d",err);
    goto error;
  }


  if( !auth_rlm->disabled ){

  	err = _rhp_auth_setup_cert_store(auth_rlm);
  	if( err ){
  		RHP_BUG("%d",err);
  		goto error;
  	}

  }else{

  	auth_rlm->just_updated = 1;
  }

	RHP_TRC(0,RHPTRCID_AUTH_PARSE_AUTH_REALM_RTRN,"xu",auth_rlm,auth_rlm->id);
	return auth_rlm;

error:
	RHP_BUG("%u",auth_rlm->id);
  _rhp_auth_realm_free(auth_rlm);
  return NULL;
}

static int _rhp_auth_init_load_realm(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
  rhp_vpn_auth_realm* auth_rlm = rhp_auth_parse_auth_realm(node);

  if( auth_rlm == NULL ){
    RHP_BUG("");
    goto error;
  }

  if( !auth_rlm->disabled ){

		_rhp_atomic_set(&(auth_rlm->is_active),1);

		rhp_auth_realm_put(auth_rlm);

		rhp_cfg_trc_dump_auth_realm(auth_rlm);

  }else{

  	err = rhp_auth_realm_disabled_put(auth_rlm->id);
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}

    _rhp_auth_realm_free(auth_rlm);
  }

error:
	RHP_TRC(0,RHPTRCID_AUTH_INIT_LOAD_REALM,"x",auth_rlm);
  return 0;
}


static char* _rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_MAX + 1] = {NULL,NULL,NULL,NULL};

static int _rhp_auth_init_load_radius(xmlNodePtr node,void* ctx)
{
  int ret_len;
	int tmp;
	u8 priv_attr_type_realm_id = 0;
	u8 priv_attr_type_realm_role = 0;
	u8 priv_attr_type_common = 0;
	int tunnel_private_group_id_attr_enabled = 0;

	RHP_TRC(0,RHPTRCID_AUTH_INIT_LOAD_RADIUS,"x",node);

  rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"secret"),
  		RHP_XML_DT_STRING,&(_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_PRIMARY]),
  		&ret_len,NULL,0);

  rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"secondary_secret"),
  		RHP_XML_DT_STRING,&(_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_SECONDARY]),
  		&ret_len,NULL,0);

  rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"acct_secret"),
  		RHP_XML_DT_STRING,&(_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_ACCT_PRIMARY]),
  		&ret_len,NULL,0);

  rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"acct_secondary_secret"),
  		RHP_XML_DT_STRING,&(_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_ACCT_SECONDARY]),
  		&ret_len,NULL,0);

  {
  	tmp = 0;
		rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"priv_attr_type_vpn_realm_id"),
				RHP_XML_DT_INT,&tmp,&ret_len,NULL,0);
  	if( tmp > 255 ){
  		RHP_BUG("%d",tmp);
  	}else{
  		priv_attr_type_realm_id = (u8)tmp;
  	}

  	tmp = 0;
		rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"priv_attr_type_vpn_realm_role"),
				RHP_XML_DT_INT,&tmp,&ret_len,NULL,0);
  	if( tmp > 255 ){
  		RHP_BUG("%d",tmp);
  	}else{
  		priv_attr_type_realm_role = (u8)tmp;
  	}

  	tmp = 0;
		rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"priv_attr_type_common"),
				RHP_XML_DT_INT,&tmp,&ret_len,NULL,0);
  	if( tmp > 255 ){
  		RHP_BUG("%d",tmp);
  	}else{
  		priv_attr_type_common = (u8)tmp;
  	}

		rhp_xml_check_enable(node,(xmlChar*)"attr_tunnel_private_group_id",
				&tunnel_private_group_id_attr_enabled);


		rhp_auth_radius_set_settings(
				&priv_attr_type_realm_id,&priv_attr_type_realm_role,&priv_attr_type_common,
				&tunnel_private_group_id_attr_enabled);
  }

	RHP_TRC(0,RHPTRCID_AUTH_INIT_LOAD_RADIUS_RTRN,"x",node);

	return 0;
}

int rhp_auth_init_radius_cfg()
{
	int err = -EINVAL;
	int i;

	RHP_TRC(0,RHPTRCID_AUTH_INIT_RADIUS_CFG,"ssss",_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_PRIMARY],_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_SECONDARY],_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_ACCT_PRIMARY],_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_ACCT_SECONDARY]);

	if( _rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_PRIMARY] ){

		err = rhp_eap_auth_impl_radius_set_secret(RHP_RADIUS_SECRET_IDX_PRIMARY,
					(u8*)_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_PRIMARY],
					strlen(_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_PRIMARY]));
		if( err ){
			RHP_BUG("%d",err);
		}

		_rhp_free_zero(_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_PRIMARY],
				strlen(_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_PRIMARY]));

		_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_PRIMARY] = NULL;

	}else{

		err = 0;
	}

	if( _rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_SECONDARY] ){

		err = rhp_eap_auth_impl_radius_set_secret(RHP_RADIUS_SECRET_IDX_SECONDARY,
					(u8*)_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_SECONDARY],
					strlen(_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_SECONDARY]));
		if( err ){
			RHP_BUG("%d",err);
		}

		_rhp_free_zero(_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_SECONDARY],
				strlen(_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_SECONDARY]));

		_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_SECONDARY] = NULL;

	}else{

		err = 0;
	}

	if( _rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_ACCT_PRIMARY] ){

		err = rhp_eap_auth_impl_radius_set_secret(RHP_RADIUS_SECRET_IDX_ACCT_PRIMARY,
					(u8*)_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_ACCT_PRIMARY],
					strlen(_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_ACCT_PRIMARY]));
		if( err ){
			RHP_BUG("%d",err);
		}

		_rhp_free_zero(_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_ACCT_PRIMARY],
				strlen(_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_ACCT_PRIMARY]));

		_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_ACCT_PRIMARY] = NULL;

	}else{

		err = 0;
	}

	if( _rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_ACCT_SECONDARY] ){

		err = rhp_eap_auth_impl_radius_set_secret(RHP_RADIUS_SECRET_IDX_ACCT_SECONDARY,
					(u8*)_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_ACCT_SECONDARY],
					strlen(_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_ACCT_SECONDARY]));
		if( err ){
			RHP_BUG("%d",err);
		}

		_rhp_free_zero(_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_ACCT_SECONDARY],
				strlen(_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_ACCT_SECONDARY]));

		_rhp_auth_init_radius_secrets_tmp[RHP_RADIUS_SECRET_IDX_ACCT_SECONDARY] = NULL;

	}else{

		err = 0;
	}

	RHP_TRC(0,RHPTRCID_AUTH_INIT_RADIUS_CFG_RTFN,"E",err);
	return err;
}

void rhp_auth_radius_get_settings(
				u8* priv_attr_type_realm_id_r,
				u8* priv_attr_type_realm_role_r,
				u8* priv_attr_type_common_p,
				int* tunnel_private_group_id_attr_enabled_r)
{
	RHP_LOCK(&rhp_auth_radius_cfg_lock);

	*tunnel_private_group_id_attr_enabled_r = _rhp_auth_radius_tunnel_private_group_id_attr_enabled;
	*priv_attr_type_realm_id_r = _rhp_auth_radius_priv_attr_type_realm_id;
	*priv_attr_type_realm_role_r = _rhp_auth_radius_priv_attr_type_realm_role;
	*priv_attr_type_common_p = _rhp_auth_radius_priv_attr_type_common;

	RHP_UNLOCK(&rhp_auth_radius_cfg_lock);

	RHP_TRC(0,RHPTRCID_AUTH_RADIUS_GET_SETTIGNS,"bbbd",*priv_attr_type_realm_id_r,*priv_attr_type_realm_role_r,*priv_attr_type_common_p,*tunnel_private_group_id_attr_enabled_r);

	return;
}

void rhp_auth_radius_set_settings(
				u8* priv_attr_type_realm_id_p,
				u8* priv_attr_type_realm_role_p,
				u8* priv_attr_type_common_p,
				int* tunnel_private_group_id_attr_enabled_p)
{
	RHP_LOCK(&rhp_auth_radius_cfg_lock);

	if( tunnel_private_group_id_attr_enabled_p ){
		_rhp_auth_radius_tunnel_private_group_id_attr_enabled = *tunnel_private_group_id_attr_enabled_p;
	}

	if( priv_attr_type_realm_id_p ){
		_rhp_auth_radius_priv_attr_type_realm_id = *priv_attr_type_realm_id_p;
	}

	if( priv_attr_type_realm_role_p ){
		_rhp_auth_radius_priv_attr_type_realm_role = *priv_attr_type_realm_role_p;
	}

	if( priv_attr_type_common_p ){
		_rhp_auth_radius_priv_attr_type_common = *priv_attr_type_common_p;
	}

	RHP_TRC(0,RHPTRCID_AUTH_RADIUS_SET_SETTIGNS,"bbdbbbd",(priv_attr_type_realm_id_p ? *priv_attr_type_realm_id_p : 0),(priv_attr_type_realm_role_p ? *priv_attr_type_realm_role_p : 0),(tunnel_private_group_id_attr_enabled_p ? *tunnel_private_group_id_attr_enabled_p : 0),_rhp_auth_radius_priv_attr_type_realm_id,_rhp_auth_radius_priv_attr_type_realm_role,_rhp_auth_radius_priv_attr_type_common,_rhp_auth_radius_tunnel_private_group_id_attr_enabled);

	RHP_UNLOCK(&rhp_auth_radius_cfg_lock);

	return;
}


rhp_auth_admin_info* rhp_auth_parse_admin(xmlNodePtr node,void* ctx,char** admin_hashed_key)
{
	int err = -EINVAL;
  char* prf_method;
  int ret_len;
  rhp_auth_admin_info* new_admin_info = NULL;

  new_admin_info = (rhp_auth_admin_info*)_rhp_malloc(sizeof(rhp_auth_admin_info));
  if( new_admin_info == NULL ){
    RHP_BUG("");
    return NULL;
  }
  memset(new_admin_info,0,sizeof(rhp_auth_admin_info));

  new_admin_info->tag[0] = '#';
  new_admin_info->tag[1] = 'A';
  new_admin_info->tag[2] = 'D';
  new_admin_info->tag[3] = 'I';

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"id"),RHP_XML_DT_STRING,&(new_admin_info->id),&ret_len,NULL,0) ){
    RHP_BUG("");
    goto error;
  }

  if( strlen((char*)new_admin_info->id) < RHP_AUTH_REQ_MIN_ID_LEN ){
    RHP_BUG("");
    goto error;
  }

	RHP_TRC(0,RHPTRCID_AUTH_PARSE_ADMIN_ID,"xs",new_admin_info,new_admin_info->id);

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"prf_method"),
  			RHP_XML_DT_STRING,&prf_method,&ret_len,NULL,0) ){

  	RHP_BUG("");
    goto error;

  }else{

    new_admin_info->prf_method = rhp_cfg_transform_str2id(RHP_PROTO_IKE_TRANSFORM_TYPE_PRF,prf_method);
    if( new_admin_info->prf_method < 0 ){
      RHP_BUG("");
      goto error;
    }

    new_admin_info->prf = rhp_crypto_prf_alloc(new_admin_info->prf_method);
    if( new_admin_info->prf == NULL ){
      RHP_BUG("");
      goto error;
    }

    if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"hashed_key"),
    			RHP_XML_DT_BASE64,&(new_admin_info->hashed_key),&(new_admin_info->hashed_key_len),NULL,0) ){

    	if( admin_hashed_key == NULL || *admin_hashed_key == NULL ){
    		RHP_BUG("");
    		goto error;
    	}

    	err = rhp_base64_decode((unsigned char*)*admin_hashed_key,
    					&(new_admin_info->hashed_key),&(new_admin_info->hashed_key_len));
    	if( err ){
     		RHP_BUG("");
      	goto error;
      }

      if( new_admin_info->hashed_key_len <= 1 ){
        RHP_BUG("");
        goto error;
      }

      new_admin_info->hashed_key_base64 = *admin_hashed_key;
      *admin_hashed_key = NULL;

    }else{

      if( new_admin_info->hashed_key_len <= 1 ){
        RHP_BUG("");
        goto error;
      }

      if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"hashed_key"),
      			RHP_XML_DT_STRING,&(new_admin_info->hashed_key_base64),&ret_len,NULL,0) ){
        RHP_BUG("");
        goto error;
      }
    }
  }

  if( rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"vpn_realm"),(xmlChar*)"any") ){

  	if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"vpn_realm"),RHP_XML_DT_ULONG,&(new_admin_info->vpn_realm_id),&ret_len,NULL,0) ){
  		RHP_BUG("");
  		goto error;
  	}

  	RHP_TRC(0,RHPTRCID_AUTH_PARSE_ADMIN_REALM_ID,"xu",new_admin_info,new_admin_info->vpn_realm_id);

  }else{
  	new_admin_info->vpn_realm_id = 0;
  	RHP_TRC(0,RHPTRCID_AUTH_PARSE_ADMIN_ANY,"x",new_admin_info);
  }

  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(const xmlChar*)"is_nobody"),(xmlChar*)"enable") ){
  	new_admin_info->is_nobody = 1;
  }else{
  	new_admin_info->is_nobody = 0;
  }
	RHP_TRC(0,RHPTRCID_AUTH_PARSE_ADMIN_IS_NOBODY,"xd",new_admin_info,new_admin_info->is_nobody);

	RHP_TRC(0,RHPTRCID_AUTH_PARSE_ADMIN_RTRN,"x",new_admin_info);
  return new_admin_info;

error:
  if( new_admin_info ){

  	RHP_TRC(0,RHPTRCID_AUTH_PARSE_ADMIN_ERR_1,"s",new_admin_info->id);

  	if( new_admin_info->id ){
      _rhp_free(new_admin_info->id);
    }
    if( new_admin_info->hashed_key ){
      _rhp_free(new_admin_info->hashed_key);
    }
    if( new_admin_info->hashed_key_base64 ){
      _rhp_free(new_admin_info->hashed_key_base64);
    }
    rhp_crypto_prf_free(new_admin_info->prf);
    _rhp_free(new_admin_info);

  }else{
  	RHP_TRC(0,RHPTRCID_AUTH_PARSE_ADMIN_ERR_2,"");
  }
  return NULL;
}


int rhp_auth_admin_replace_key(rhp_auth_admin_info* admin_info,char* new_key)
{
	int err = -EINVAL;
  rhp_crypto_prf* prf = NULL;
  u8* hashed_key = NULL;
  int hashed_key_len = 0;
  unsigned char* res_text = NULL;

	prf  = rhp_crypto_prf_alloc(RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA1);
	if( prf == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	err = _rhp_auth_hashed_auth_key(prf,admin_info->id,strlen((char*)admin_info->id)+1,
				 (unsigned char*)new_key,strlen((char*)new_key)+1,&hashed_key,&hashed_key_len);


	err = rhp_base64_encode(hashed_key,hashed_key_len,&res_text);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	_rhp_free(admin_info->hashed_key);
	_rhp_free(admin_info->hashed_key_base64);

	admin_info->hashed_key = hashed_key;
	admin_info->hashed_key_len = hashed_key_len;
	admin_info->hashed_key_base64 = (char*)res_text;

	rhp_crypto_prf_free(prf);

	return 0;

error:
	if( prf ){
		rhp_crypto_prf_free(prf);
	}
	if( hashed_key ){
		_rhp_free(hashed_key);
	}
	if( res_text ){
		_rhp_free(res_text);
	}
	return err;
}

static int _rhp_auth_init_load_admin(xmlNodePtr node,void* ctx)
{
  rhp_auth_admin_info *new_admin_info,*admin_info_tail;

  new_admin_info = rhp_auth_parse_admin(node,ctx,NULL);
  if( new_admin_info == NULL ){
    RHP_BUG("");
    goto error;
  }

  admin_info_tail = rhp_auth_admin_head;
  while( admin_info_tail ){

    if( admin_info_tail->next_list == NULL ){
      break;
    }

    admin_info_tail = admin_info_tail->next_list;
  }

  if( admin_info_tail == NULL ){
    rhp_auth_admin_head = new_admin_info;
  }else{
    admin_info_tail->next_list = new_admin_info;
  }

error:
	RHP_TRC(0,RHPTRCID_AUTH_INIT_LOAD_ADMIN,"x",new_admin_info);
  return 0;
}

int rhp_auth_init_load(char* conf_xml_path)
{
  int err = 0;
  xmlDocPtr doc;
  xmlNodePtr root_node;

  RHP_TRC(0,RHPTRCID_AUTH_INIT_LOAD,"s",conf_xml_path);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return -EPERM;
  }

  doc = xmlParseFile(conf_xml_path);
  if( doc == NULL )
  {
    err = -ENOENT;
    RHP_BUG(" %s ",conf_xml_path);
    goto error;
  }

  root_node = xmlDocGetRootElement(doc);
  if( root_node == NULL ){
    err = -ENOENT;
    RHP_BUG(" %s ",conf_xml_path);
    goto error;
  }

  if( xmlStrcmp(root_node->name,(xmlChar*)"rhp_auth") ){
    err = -ENOENT;
    RHP_BUG(" %s ",conf_xml_path);
    goto error;
  }

  err = rhp_xml_enum_tags(root_node,(xmlChar*)"vpn_realm",_rhp_auth_init_load_realm,NULL,1);
  if( err && err != -ENOENT ){
    RHP_BUG(" %s ",conf_xml_path);
    goto error;
  }
  err = 0;

  err = rhp_xml_enum_tags(root_node,(xmlChar*)"radius",_rhp_auth_init_load_radius,NULL,0);
  if( err && err != -ENOENT ){
    RHP_BUG(" %s ",conf_xml_path);
    goto error;
  }
  err = 0;

  if( (err = rhp_xml_enum_tags(root_node,(xmlChar*)"admin",_rhp_auth_init_load_admin,NULL,1)) ){
    RHP_BUG("");
    goto error;
  }

  xmlFreeDoc(doc);

  RHP_TRC(0,RHPTRCID_AUTH_INIT_LOAD_RTRN,"s",conf_xml_path);
  return 0;

error:
	if( doc ){
		xmlFreeDoc(doc);
	}
  RHP_TRC(0,RHPTRCID_AUTH_INIT_LOAD_ERR,"sd",conf_xml_path,err);
  return err;
}

int rhp_auth_policy_permitted_if_entry(unsigned long rlm_id,rhp_if_entry* if_ent)
{
	// TODO : NOT Implemented yet.
	return 0;
}

int rhp_auth_policy_permitted_addr(unsigned long rlm_id,rhp_ip_addr* addr,unsigned long* metric_base,unsigned long* matric_max)
{
	// TODO : NOT Implemented yet.

	if( metric_base ){
		*metric_base = 0;
	}

	if( matric_max ){
		*matric_max = LONG_MAX;
	}

	return 0;
}


int rhp_auth_realm_disabled_exists(unsigned long rlm_id)
{
	rhp_auth_realm_disabled* auth_rlm_disabled;
	int flag = 0;

	RHP_TRC(0,RHPTRCID_AUTH_REALM_DISABLED_EXISTS,"d",rlm_id);

  RHP_LOCK(&rhp_auth_lock);

  auth_rlm_disabled = rhp_auth_realm_disabled_list_head;
  while( auth_rlm_disabled ){

  	if( auth_rlm_disabled->rlm_id == rlm_id ){
  		flag = 1;
  		break;
  	}

  	auth_rlm_disabled = auth_rlm_disabled->next;
  }

  RHP_UNLOCK(&rhp_auth_lock);

	RHP_TRC(0,RHPTRCID_AUTH_REALM_DISABLED_EXISTS_RTRN,"dd",rlm_id,flag);
  return flag;
}

int rhp_auth_realm_disabled_put(unsigned long rlm_id)
{
	rhp_auth_realm_disabled* auth_rlm_disabled;

	RHP_TRC(0,RHPTRCID_AUTH_REALM_DISABLED_PUT,"d",rlm_id);

	auth_rlm_disabled = (rhp_auth_realm_disabled*)_rhp_malloc(sizeof(rhp_auth_realm_disabled));
	if( auth_rlm_disabled == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	memset(auth_rlm_disabled,0,sizeof(rhp_auth_realm_disabled));

	auth_rlm_disabled->rlm_id = rlm_id;

  RHP_LOCK(&rhp_auth_lock);

	auth_rlm_disabled->next = rhp_auth_realm_disabled_list_head;
	rhp_auth_realm_disabled_list_head = auth_rlm_disabled;

  RHP_UNLOCK(&rhp_auth_lock);

	RHP_TRC(0,RHPTRCID_AUTH_REALM_DISABLED_PUT_RTRN,"dx",rlm_id,auth_rlm_disabled);
  return 0;
}

int rhp_auth_realm_disabled_delete(unsigned long rlm_id)
{
	int err = -EINVAL;
	rhp_auth_realm_disabled *auth_rlm_disabled = NULL, *auth_rlm_disabled_p = NULL;

	RHP_TRC(0,RHPTRCID_AUTH_REALM_DISABLED_DELETE,"d",rlm_id);

  RHP_LOCK(&rhp_auth_lock);

  auth_rlm_disabled = rhp_auth_realm_disabled_list_head;
  while( auth_rlm_disabled ){

  	if( auth_rlm_disabled->rlm_id == rlm_id ){
  		break;
  	}

  	auth_rlm_disabled_p = auth_rlm_disabled;
  	auth_rlm_disabled = auth_rlm_disabled->next;
  }

  if( auth_rlm_disabled ){

  	if( auth_rlm_disabled_p ){
  		auth_rlm_disabled_p->next = auth_rlm_disabled->next;
  	}else{
  		rhp_auth_realm_disabled_list_head = auth_rlm_disabled->next;
  	}

  	_rhp_free(auth_rlm_disabled);

  	err = 0;

  }else{

  	err = -ENOENT;
  }

  RHP_UNLOCK(&rhp_auth_lock);

	RHP_TRC(0,RHPTRCID_AUTH_REALM_DISABLED_DELETE_RTRN,"dxE",rlm_id,auth_rlm_disabled,err);
  return err;
}


int rhp_auth_cfg_init()
{
  _rhp_mutex_init("ATH",&(rhp_auth_lock));

  _rhp_mutex_init("RAK",&(rhp_auth_radius_cfg_lock));

  RHP_LINE("rhp_auth_init() OK.");

  return 0;
}



