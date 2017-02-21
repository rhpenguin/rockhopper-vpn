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

#include "wpa_supplicant/includes.h"

#include "wpa_supplicant/common.h"
#include "wpa_supplicant/ms_funcs.h"
#include "wpa_supplicant/eap_i.h"

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
#include "rhp_eap_auth_impl.h"
#include "rhp_radius_impl.h"
#include "rhp_eap_auth_priv.h"
#include "rhp_radius_acct.h"


rhp_atomic_t _rhp_eap_auth_radius_open_sessions;

static int _rhp_eap_auth_radius_secondary_server_used = 0;
static time_t _rhp_eap_auth_radius_secondary_server_swiched_time = 0;

static int _rhp_eap_auth_radius_switch_primary_server(int flag)
{
	time_t now;

	RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_SWITCH_PRIMARY_SERVER,"dd",flag,_rhp_eap_auth_radius_secondary_server_used);

	if( !_rhp_eap_auth_radius_secondary_server_used ){
		return 0;
	}

	if( !flag ){

		now = _rhp_get_time();

		if( (now - _rhp_eap_auth_radius_secondary_server_swiched_time)
					>= rhp_gcfg_radius_secondary_server_hold_time ){

			_rhp_eap_auth_radius_secondary_server_used = 0;

			RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_SWITCH_PRIMARY_SERVER_1,"dttd",flag,now,_rhp_eap_auth_radius_secondary_server_swiched_time,rhp_gcfg_radius_secondary_server_hold_time);

		}else{

			RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_SWITCH_PRIMARY_SERVER_1_NOT,"dttd",flag,now,_rhp_eap_auth_radius_secondary_server_swiched_time,rhp_gcfg_radius_secondary_server_hold_time);
		}

	}else{

		_rhp_eap_auth_radius_secondary_server_used = 0;

		RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_SWITCH_PRIMARY_SERVER_2,"d",flag);
	}

	return 0;
}

static int _rhp_eap_auth_radius_switch_secondary_server()
{
	RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_SWITCH_SECONDARY_SERVER,"d",_rhp_eap_auth_radius_secondary_server_used);

	if( _rhp_eap_auth_radius_secondary_server_used ){
		return 0;
	}

	_rhp_eap_auth_radius_secondary_server_used = 1;
	_rhp_eap_auth_radius_secondary_server_swiched_time = _rhp_get_time();

	RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_SWITCH_SECONDARY_SERVER_RTRN,"dt",_rhp_eap_auth_radius_secondary_server_used,_rhp_eap_auth_radius_secondary_server_swiched_time);
	return 0;
}

static int _rhp_eap_auth_radius_use_secondary_server()
{
	RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_USE_SECONDARY_SERVER,"d",_rhp_eap_auth_radius_secondary_server_used);
	return _rhp_eap_auth_radius_secondary_server_used;
}

static rhp_radius_session* _rhp_eap_auth_radius_session_open(
					rhp_vpn* vpn,
					rhp_eap_auth_impl_radius_ctx* ctx,
					int use_secondary_server,
					void (*receive_response_cb)(rhp_radius_session* radius_sess,void* cb_ctx,rhp_radius_mesg* rx_radius_mesg),
					void (*error_cb)(rhp_radius_session* radius_sess,void* cb_ctx,rhp_radius_mesg* tx_radius_mesg,int err),
					void* cb_ctx)
{
	int err = -EINVAL;
	rhp_radius_session* radius_sess = NULL;
	rhp_ip_addr *server_addr_port_p = NULL, *nas_addr_p = NULL;
	char* server_fqdn_p = NULL;


	if( rhp_gcfg_eap_radius->max_sessions &&
			_rhp_atomic_read(&_rhp_eap_auth_radius_open_sessions) >= rhp_gcfg_eap_radius->max_sessions ){

		err = RHP_STATUS_RADIUS_MAX_SESSIONS_REACHED;

		RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_SESSION_OPEN_MAX_SESSION_REACHED,"xxYYxdd",vpn,ctx,receive_response_cb,error_cb,cb_ctx,rhp_gcfg_eap_radius->max_sessions,_rhp_eap_auth_radius_open_sessions.c);
		goto error;
	}

	if( !rhp_ip_addr_null(&(rhp_gcfg_eap_radius->server_secondary_addr_port)) ||
  		rhp_gcfg_eap_radius->server_secondary_fqdn ){

		ctx->secondary_server_configured = 1;

  	_rhp_eap_auth_radius_switch_primary_server(0);

  	if( !use_secondary_server ){

  		use_secondary_server = _rhp_eap_auth_radius_use_secondary_server();
  	}

  	ctx->tx_secondary_server = use_secondary_server;


  	if( use_secondary_server ){

			server_addr_port_p = &(rhp_gcfg_eap_radius->server_secondary_addr_port);
			server_fqdn_p = rhp_gcfg_eap_radius->server_secondary_fqdn;
			nas_addr_p = &(rhp_gcfg_eap_radius->nas_secondary_addr);

  	}else{

  		server_addr_port_p = &(rhp_gcfg_eap_radius->server_addr_port);
			server_fqdn_p = rhp_gcfg_eap_radius->server_fqdn;
			nas_addr_p = &(rhp_gcfg_eap_radius->nas_addr);
		}

	}else{

		ctx->secondary_server_configured = 0;

		if( use_secondary_server ){
			err = -EINVAL;
			goto error;
		}

		server_addr_port_p = &(rhp_gcfg_eap_radius->server_addr_port);
		server_fqdn_p = rhp_gcfg_eap_radius->server_fqdn;
		nas_addr_p = &(rhp_gcfg_eap_radius->nas_addr);
	}

	//
	// Copy needed config to the ctx object.
	//
  if( rhp_ip_addr_null(server_addr_port_p) && server_fqdn_p == NULL ){
  	RHP_BUG("");
		return NULL;
  }



	radius_sess = rhp_radius_session_open(
									RHP_RADIUS_USAGE_AUTHENTICATION,
									server_addr_port_p,server_fqdn_p,
									receive_response_cb,error_cb,cb_ctx);

	if( radius_sess ){

		if( !rhp_ip_addr_null(nas_addr_p) ){

			err = radius_sess->set_nas_addr(radius_sess,nas_addr_p);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}
		}

		if( vpn->vpn_realm_id && vpn->vpn_realm_id != RHP_VPN_REALM_ID_UNKNOWN ){

			radius_sess->set_realm_id(radius_sess,vpn->vpn_realm_id);
		}

		err = radius_sess->set_gateway_id(radius_sess,&(vpn->my_id));
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		if( vpn->peer_notified_realm_id &&
				vpn->peer_notified_realm_id != RHP_VPN_REALM_ID_UNKNOWN ){

			radius_sess->set_peer_notified_realm_id(radius_sess,vpn->peer_notified_realm_id);
		}

		if( !use_secondary_server ){
			radius_sess->set_secret_index(radius_sess,RHP_RADIUS_SECRET_IDX_PRIMARY);
		}else{
			radius_sess->set_secret_index(radius_sess,RHP_RADIUS_SECRET_IDX_SECONDARY);
		}

		if( rhp_gcfg_eap_radius->nas_id ){

			radius_sess->set_nas_id(radius_sess,rhp_gcfg_eap_radius->nas_id);
		}

		if( rhp_gcfg_eap_radius->connect_info ){

			radius_sess->set_connect_info(radius_sess,rhp_gcfg_eap_radius->connect_info);
		}

		if( rhp_gcfg_eap_radius->tx_framed_mtu ){

			radius_sess->set_framed_mtu(radius_sess,rhp_gcfg_eap_radius->tx_framed_mtu);
		}

		if( rhp_gcfg_eap_radius->tx_calling_station_id_enabled ){

			char* client_ip_port = rhp_ip_port_string(&(vpn->peer_addr));

			if( client_ip_port ){
				radius_sess->set_calling_station_id(radius_sess,client_ip_port);
				_rhp_free(client_ip_port);
			}
		}

		if( rhp_gcfg_eap_radius->tx_nas_id_as_ikev2_id_enabled ){
			radius_sess->include_nas_id_as_ikev2_id(radius_sess,1);
		}

		if( rhp_gcfg_radius_acct->enabled ){

			char* acct_sess_id = rhp_radius_acct_get_session_id_str(vpn);

			if( acct_sess_id ){

				radius_sess->set_acct_session_id(radius_sess,acct_sess_id);

				_rhp_free(acct_sess_id);
			}
		}

		if( rhp_gcfg_eap_radius->tx_nas_port_type_enabled ){

			radius_sess->include_nas_port_type(radius_sess,1);
		}

		if( rhp_gcfg_eap_radius->retransmit_interval ){

			radius_sess->set_retransmit_interval(radius_sess,
					(time_t)rhp_gcfg_eap_radius->retransmit_interval);
		}

		if( rhp_gcfg_eap_radius->retransmit_times ){

			radius_sess->set_retransmit_times(radius_sess,
					rhp_gcfg_eap_radius->retransmit_times);
		}

		if( rhp_gcfg_eap_radius->rx_vpn_realm_id_attr_type ){

			radius_sess->set_private_attr_type(radius_sess,
					RHP_RADIUS_RX_ATTR_PRIV_REALM_ID,
					rhp_gcfg_eap_radius->rx_vpn_realm_id_attr_type);
		}

		if( rhp_gcfg_eap_radius->rx_vpn_realm_role_attr_type ){

			radius_sess->set_private_attr_type(radius_sess,
					RHP_RADIUS_RX_ATTR_PRIV_REALM_ROLE,
					rhp_gcfg_eap_radius->rx_vpn_realm_role_attr_type);
		}

		if( rhp_gcfg_eap_radius->rx_user_index_attr_type ){

			radius_sess->set_private_attr_type(radius_sess,
					RHP_RADIUS_RX_ATTR_PRIV_USER_INDEX,
					rhp_gcfg_eap_radius->rx_user_index_attr_type);
		}

		if( rhp_gcfg_eap_radius->rx_internal_addr_ipv4 ){

			radius_sess->set_private_attr_type(radius_sess,
					RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_ADDR_IPV4,
					rhp_gcfg_eap_radius->rx_internal_addr_ipv4);
		}

		if( rhp_gcfg_eap_radius->rx_internal_addr_ipv6 ){

			radius_sess->set_private_attr_type(radius_sess,
					RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_ADDR_IPV6,
					rhp_gcfg_eap_radius->rx_internal_addr_ipv6);
		}

		if( rhp_gcfg_eap_radius->rx_internal_dns_v4_attr_type ){

			radius_sess->set_private_attr_type(radius_sess,
					RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_DNS_SERVER_IPV4,
					rhp_gcfg_eap_radius->rx_internal_dns_v4_attr_type);
		}

		if( rhp_gcfg_eap_radius->rx_internal_dns_v6_attr_type ){

			radius_sess->set_private_attr_type(radius_sess,
					RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_DNS_SERVER_IPV6,
					rhp_gcfg_eap_radius->rx_internal_dns_v6_attr_type);
		}

		if( rhp_gcfg_eap_radius->rx_internal_domain_names_attr_type ){

			radius_sess->set_private_attr_type(radius_sess,
					RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_DOMAIN_NAME,
					rhp_gcfg_eap_radius->rx_internal_domain_names_attr_type);
		}

		if( rhp_gcfg_eap_radius->rx_internal_rt_maps_v4_attr_type ){

			radius_sess->set_private_attr_type(radius_sess,
					RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_ROUTE_IPV4,
					rhp_gcfg_eap_radius->rx_internal_rt_maps_v4_attr_type);
		}

		if( rhp_gcfg_eap_radius->rx_internal_rt_maps_v6_attr_type ){

			radius_sess->set_private_attr_type(radius_sess,
					RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_ROUTE_IPV6,
					rhp_gcfg_eap_radius->rx_internal_rt_maps_v6_attr_type);
		}

		if( rhp_gcfg_eap_radius->rx_internal_gw_v4_attr_type ){

			radius_sess->set_private_attr_type(radius_sess,
					RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_GATEWAY_IPV4,
					rhp_gcfg_eap_radius->rx_internal_gw_v4_attr_type);
		}

		if( rhp_gcfg_eap_radius->rx_internal_gw_v6_attr_type ){

			radius_sess->set_private_attr_type(radius_sess,
					RHP_RADIUS_RX_ATTR_PRIV_INTERNAL_GATEWAY_IPV6,
					rhp_gcfg_eap_radius->rx_internal_gw_v6_attr_type);
		}

		if( rhp_gcfg_eap_radius->rx_common_priv_attr ){

			radius_sess->set_private_attr_type(radius_sess,
					RHP_RADIUS_RX_ATTR_PRIV_COMMON,
					rhp_gcfg_eap_radius->rx_common_priv_attr);
		}


		_rhp_atomic_inc(&_rhp_eap_auth_radius_open_sessions);

	}else{
		RHP_BUG("");
		goto error;
	}

  RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_SESSION_OPEN,"xd",radius_sess,_rhp_eap_auth_radius_open_sessions.c);
	return radius_sess;

error:
	if( radius_sess ){
		rhp_radius_session_close(radius_sess);
	}
  RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_SESSION_OPEN_ERR,"xE",radius_sess,err);
	return NULL;
}


static int _rhp_eap_auth_session_close(rhp_radius_session* radius_sess)
{
	int err;

	err = rhp_radius_session_close(radius_sess);

	if( !err ){
		_rhp_atomic_dec(&_rhp_eap_auth_radius_open_sessions);
	}

  RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_SESSION_CLOSE,"xdE",radius_sess,_rhp_eap_auth_radius_open_sessions.c,err);

	return err;
}


static void _rhp_eap_auth_radius_auth_receive_response_cb(rhp_radius_session* radius_sess,
		void* cb_ctx,rhp_radius_mesg* rx_radius_mesg)
{
	int err = -EINVAL;
	rhp_vpn_ref* vpn_ref = (rhp_vpn_ref*)cb_ctx;
	rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);
	rhp_eap_auth_impl_radius_ctx* ctx = NULL;
	u8 radius_code;
  rhp_ikev2_payload* ikepayload = NULL;
  rhp_ikev2_mesg* rx_ikemesg = NULL;
	rhp_ikev2_mesg* tx_ikemesg = NULL;
	int vpn_unhold = 0;
	int eap_status = RHP_EAP_STAT_NONE;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_AUTH_RECEIVE_RESPONSE_CB,"xxxxx",radius_sess,cb_ctx,rx_radius_mesg,vpn_ref,vpn);

  RHP_LOCK(&(vpn->lock));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
  	err = -EINVAL;
    RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_AUTH_RECEIVE_RESPONSE_CB_VPN_NOT_ACTIVE,"xxxxx",radius_sess,cb_ctx,rx_radius_mesg,vpn_ref,vpn);
  	goto error;
  }

  ctx = (rhp_eap_auth_impl_radius_ctx*)vpn->eap.impl_ctx;
  if( ctx == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  ctx->rx_mesg_num++;


  if( ctx->radius_sess == NULL ){
		err = 0;
    RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_AUTH_RECEIVE_RESPONSE_CB_NO_CTX_RADIUS_SESS,"xxxxxx",radius_sess,cb_ctx,rx_radius_mesg,vpn_ref,vpn,ctx);
  	goto ignored;
  }

  if( ctx->radius_sess != radius_sess ){
  	RHP_BUG("");
    RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_AUTH_RECEIVE_RESPONSE_CB_INVALID_CTX_RADIUS_SESS,"xxxxxxx",radius_sess,cb_ctx,rx_radius_mesg,vpn_ref,vpn,ctx,ctx->radius_sess);
  	err = -EINVAL;
  	goto error;
  }


  RHP_LOCK(&(radius_sess->lock));

  if( !_rhp_atomic_read(&(radius_sess->is_active)) ){
  	err = -EINVAL;
    RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_AUTH_RECEIVE_RESPONSE_CB_RADIUS_SESS_NOT_ACTIVE,"xxxxxx",radius_sess,cb_ctx,rx_radius_mesg,vpn_ref,vpn,ctx);
  	goto error_radius_l;
  }

	radius_code = rx_radius_mesg->get_code(rx_radius_mesg);

	if( radius_code != RHP_RADIUS_CODE_ACCESS_ACCEPT &&
			radius_code != RHP_RADIUS_CODE_ACCESS_REJECT &&
			radius_code != RHP_RADIUS_CODE_ACCESS_CHALLENGE ){

	  RHP_UNLOCK(&(radius_sess->lock));

    RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_AUTH_RECEIVE_RESPONSE_CB_NOT_INTERESTED_RADIUS_MESG_CODE,"xxxxxxb",radius_sess,cb_ctx,rx_radius_mesg,vpn_ref,vpn,ctx,radius_code);

		err = 0;
		goto ignored;
	}


	rx_ikemesg = ctx->rx_ikemesg;
	ctx->rx_ikemesg = NULL;
	tx_ikemesg = ctx->tx_ikemesg;
	ctx->tx_ikemesg = NULL;


	//
	// EAP FAILURE also
	//
	{
		rhp_radius_attr* radius_attr_eap = rx_radius_mesg->get_attr_eap(rx_radius_mesg,0,0);
		rhp_proto_eap* eaph = NULL;
		int eap_len = 0;

		if( radius_attr_eap ){

			if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_EAP,&ikepayload) ){
				RHP_BUG("");
				goto error_radius_l;
			}

			tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

			eaph = radius_attr_eap->ext.eap->get_eap_packet(radius_attr_eap,&eap_len);
			if( eaph == NULL ){
				RHP_BUG("");
				err = -EINVAL;
				goto error_radius_l;
			}

			err = ikepayload->ext.eap->set_eap_message(ikepayload,(u8*)eaph,eap_len);
			if( err ){
				RHP_BUG("");
				goto error_radius_l;
			}

		}else{

			RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_AUTH_RECEIVE_RESPONSE_CB_NO_EAP_ATTR_FOUND,"xxxxxxb",radius_sess,cb_ctx,rx_radius_mesg,vpn_ref,vpn,ctx,radius_code);

			if( radius_code != RHP_RADIUS_CODE_ACCESS_REJECT ){

				err = RHP_STATUS_RADIUS_NO_EAP_ATTR_FOUND;
				goto error_radius_l;
			}
		}
	}


	if( radius_code == RHP_RADIUS_CODE_ACCESS_REJECT ){

		eap_status = RHP_EAP_STAT_ERROR;

	  RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_AUTH_REJECTED,"sVKrRL",radius_sess->get_user_name(radius_sess),vpn,rx_ikemesg,radius_sess,rx_radius_mesg,"EAP_TYPE",radius_sess->get_eap_method(radius_sess));

    RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_AUTH_RECEIVE_RESPONSE_CB_RX_ACCESS_REJECT,"xxxxxxb",radius_sess,cb_ctx,rx_radius_mesg,vpn_ref,vpn,ctx,radius_code);

		goto error_radius_l;

	}else if( radius_code == RHP_RADIUS_CODE_ACCESS_ACCEPT ){

		u8* msk = NULL;
		int msk_len = 0;
		char* user_name = NULL;
		int user_name_len = 0;

    RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_AUTH_RECEIVE_RESPONSE_CB_RX_ACCESS_ACCEPT,"xxxxxxb",radius_sess,cb_ctx,rx_radius_mesg,vpn_ref,vpn,ctx,radius_code);

		ctx->is_completed = 1;

		err = radius_sess->get_msk(radius_sess,&msk,&msk_len);
		if( !err ){

			ctx->msk = msk;
			ctx->msk_len = msk_len;

		  if( rhp_gcfg_dbg_log_keys_info ){
			  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_AUTH_ACCEPTED_MSK_INFO,"VKrRp",vpn,rx_ikemesg,radius_sess,rx_radius_mesg,msk_len,msk);
			}

		}else{

		  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_AUTH_ACCEPTED_NO_MSK_FOUND,"VKrR",vpn,rx_ikemesg,radius_sess,rx_radius_mesg);

			RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_AUTH_RECEIVE_RESPONSE_CB_NO_MSK,"xxxxxx",radius_sess,cb_ctx,rx_radius_mesg,vpn_ref,vpn,ctx);
		}
		err = 0;

		user_name = radius_sess->get_user_name(radius_sess);
		if( user_name ){

			user_name_len = strlen(user_name);

			ctx->peer_identity = (u8*)_rhp_malloc(user_name_len + 1);
			if( ctx->peer_identity == NULL ){
				RHP_BUG("");
			}else{

				memcpy(ctx->peer_identity,user_name,user_name_len);

				ctx->peer_identity_len = user_name_len;
				ctx->peer_identity[user_name_len] = '\0';
			}

		}else{

		  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_AUTH_ACCEPTED_NO_USER_NAME_FOUND,"VKrR",vpn,rx_ikemesg,radius_sess,rx_radius_mesg);

			RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_AUTH_RECEIVE_RESPONSE_CB_NO_USERNAME,"xxxxxx",radius_sess,cb_ctx,rx_radius_mesg,vpn_ref,vpn,ctx);
		}

		vpn->radius.rx_accept_attrs
			= rx_radius_mesg->get_access_accept_attributes(rx_radius_mesg);


		vpn->eap.rebound_vpn_realm_id
			= rx_radius_mesg->get_realm_id_by_access_accept_attrs(rx_radius_mesg);

		if( vpn->eap.rebound_vpn_realm_id == RHP_VPN_REALM_ID_UNKNOWN ){
			vpn->eap.rebound_vpn_realm_id = 0;
		}

		vpn->radius.eap_method = radius_sess->get_eap_method(radius_sess);

	  RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_AUTH_ACCEPTED,"sVKrRsLu",user_name,vpn,rx_ikemesg,radius_sess,rx_radius_mesg,user_name,"EAP_TYPE",vpn->radius.eap_method,vpn->eap.rebound_vpn_realm_id);

		eap_status = RHP_EAP_STAT_COMPLETED;

	}else{

		RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_AUTH_RECEIVE_RESPONSE_CB_CONTINUE,"xxxxxx",radius_sess,cb_ctx,rx_radius_mesg,vpn_ref,vpn,ctx);

		eap_status = RHP_EAP_STAT_CONTINUE;
	}


	if( eap_status == RHP_EAP_STAT_COMPLETED ){
		_rhp_eap_auth_session_close(ctx->radius_sess); // (***)
		ctx->radius_sess = NULL;
		vpn_unhold = 1;
	}

	rhp_eap_recv_callback(vpn,ctx->my_ikesa_side,ctx->my_ikesa_spi,rx_ikemesg,tx_ikemesg,eap_status);

	rhp_ikev2_unhold_mesg(rx_ikemesg);
	rhp_ikev2_unhold_mesg(tx_ikemesg);

  RHP_UNLOCK(&(radius_sess->lock));

  RHP_UNLOCK(&(vpn->lock));
  if( vpn_unhold ){
  	rhp_vpn_unhold(vpn_ref); // Held by rhp_radius_session_open(). (***)
	}

  RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_AUTH_RECEIVE_RESPONSE_CB_RTRN,"xxxxx",radius_sess,cb_ctx,rx_radius_mesg,vpn_ref,vpn);
	return;


error_radius_l:

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_RX_MESG_ERROR,"VKrRE",vpn,rx_ikemesg,radius_sess,rx_radius_mesg,err);

	_rhp_eap_auth_session_close(ctx->radius_sess); // (****)
	ctx->radius_sess = NULL;
	vpn_unhold = 1;

	RHP_UNLOCK(&(radius_sess->lock));

error:
	ctx->is_completed = 1;

	if( ctx->radius_sess ){
	  RHP_LOCK(&(ctx->radius_sess->lock));
		_rhp_eap_auth_session_close(ctx->radius_sess); // (****)
	  RHP_UNLOCK(&(ctx->radius_sess->lock));
		ctx->radius_sess = NULL;
		vpn_unhold = 1;
	}

	if( rx_ikemesg && tx_ikemesg ){

		rhp_eap_recv_callback(vpn,ctx->my_ikesa_side,ctx->my_ikesa_spi,rx_ikemesg,tx_ikemesg,RHP_EAP_STAT_ERROR);
	}

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_RX_MESG_ERROR_2,"VKRE",vpn,rx_ikemesg,rx_radius_mesg,err);

	RHP_UNLOCK(&(vpn->lock));
	if( vpn_unhold ){
		rhp_vpn_unhold(vpn_ref); // Held by rhp_radius_session_open(). (****)
	}

  if( rx_ikemesg ){
  	rhp_ikev2_unhold_mesg(rx_ikemesg);
  }

  if( tx_ikemesg ){
  	rhp_ikev2_unhold_mesg(tx_ikemesg);
  }

  RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_AUTH_RECEIVE_RESPONSE_CB_ERR,"xxxxxE",radius_sess,cb_ctx,rx_radius_mesg,vpn_ref,vpn,err);
  return;

ignored:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_RX_MESG_IGNORED,"VKR",vpn,rx_ikemesg,rx_radius_mesg);
	RHP_UNLOCK(&(vpn->lock));
  if( vpn_unhold ){
  	rhp_vpn_unhold(vpn_ref); // Held by rhp_radius_session_open(). (***)
	}

  RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_AUTH_RECEIVE_RESPONSE_CB_IGNORED,"xxxxxE",radius_sess,cb_ctx,rx_radius_mesg,vpn_ref,vpn);
  return;
}


static int _rhp_eap_auth_impl_fwd_eap_pkt(rhp_vpn* vpn,rhp_radius_session* radius_sess,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_payload* rx_eap_pld)
{
	int err = -EINVAL;
	rhp_proto_eap* eaph = NULL;
	int eap_len = 0;
	rhp_radius_mesg* radius_mesg = NULL;
	rhp_radius_attr* radius_attr_eap = NULL;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_FWD_EAP_PKT,"xxxx",vpn,rx_ikemesg,rx_eap_pld,radius_sess);

  RHP_LOCK(&(radius_sess->lock));

  if( !_rhp_atomic_read(&(radius_sess->is_active))  ){
  	err = RHP_STATUS_RADIUS_INVALID_SESSION;
    RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_FWD_EAP_PKT_RADIUS_SESS_NOT_ACTIVE,"xxxx",vpn,rx_ikemesg,rx_eap_pld,radius_sess);
  	goto error;
  }


  eaph = (rhp_proto_eap*)rx_eap_pld->ext.eap->get_eap_message(rx_eap_pld,&eap_len);
	if( eaph == NULL ){
		err = RHP_STATUS_INVALID_MSG;
	  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_FWD_EAP_PKT_NO_EAP_ATTR,"xxxx",vpn,rx_ikemesg,rx_eap_pld,radius_sess);
		goto error;
	}


	if( eaph->code == RHP_PROTO_EAP_CODE_RESPONSE &&
			((rhp_proto_eap_response*)eaph)->type == RHP_PROTO_EAP_TYPE_IDENTITY &&
			radius_sess->get_user_name(radius_sess) == NULL ){

		int user_name_len = eap_len - sizeof(rhp_proto_eap_response);
		u8* user_name;

		if( eap_len < 1 ){
			err = RHP_STATUS_INVALID_MSG;
		  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_FWD_EAP_PKT_NO_EAP_DATA,"xxxx",vpn,rx_ikemesg,rx_eap_pld,radius_sess);
			goto error;
		}


		user_name = (u8*)_rhp_malloc(user_name_len + 1);
		if( user_name == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
		memcpy(user_name,(u8*)(((rhp_proto_eap_response*)eaph) + 1),user_name_len);
		user_name[user_name_len] = '\0';


		err = radius_sess->set_user_name(radius_sess,(char*)user_name);
		if( err ){
			_rhp_free(user_name);
		  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_FWD_EAP_PKT_SET_USERNAME_ERR,"xxxx",vpn,rx_ikemesg,rx_eap_pld,radius_sess);
			goto error;
		}

		_rhp_free(user_name);
	}


	radius_mesg = rhp_radius_new_mesg_tx(RHP_RADIUS_CODE_ACCESS_REQUEST,0);
	if( radius_mesg == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_ALLOC_TX_MESG,"VKrL",vpn,rx_ikemesg,radius_sess,"RADIUS_CODE",(int)radius_mesg->get_code(radius_mesg));


	{
		err = rhp_radius_new_attr_tx(radius_sess,radius_mesg,
				RHP_RADIUS_ATTR_TYPE_EAP,0,&radius_attr_eap);
		if( err ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		radius_mesg->put_attr(radius_mesg,radius_attr_eap);

		err = radius_attr_eap->ext.eap->set_eap_packet(radius_attr_eap,eap_len,eaph);
		if( err ){
			RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_FWD_EAP_PKT_SET_EAP_ATTR_ERR,"xxxxxE",vpn,rx_ikemesg,rx_eap_pld,radius_sess,radius_attr_eap,err);
			goto error;
		}

		{
			int eap_l_data_len;
			if( eap_len >= sizeof(rhp_proto_eap_response) && ((rhp_proto_eap_response*)eaph)->type == RHP_PROTO_EAP_TYPE_IDENTITY ){
				eap_l_data_len = eap_len - sizeof(rhp_proto_eap_response);
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_ATTR_EAP_IDENTITY_TX,"VKrLLLbLa",vpn,rx_ikemesg,radius_sess,"RADIUS_CODE",(int)radius_mesg->get_code(radius_mesg),"RADIUS_ATTR",(int)radius_attr_eap->get_attr_type(radius_attr_eap),"EAP_CODE",(int)eaph->code,eaph->identifier,"EAP_TYPE",(int)(eap_len >= sizeof(rhp_proto_eap_response) ? ((rhp_proto_eap_response*)eaph)->type : 0),(int)(eap_l_data_len >= 64 ? 64 : eap_l_data_len),(eap_len > sizeof(rhp_proto_eap_response) ? (((rhp_proto_eap_response*)eaph) + 1) : NULL));
			}else{
				eap_l_data_len = eap_len - sizeof(rhp_proto_eap);
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_ATTR_EAP_TX,"VKrLLLbLp",vpn,rx_ikemesg,radius_sess,"RADIUS_CODE",(int)radius_mesg->get_code(radius_mesg),"RADIUS_ATTR",(int)radius_attr_eap->get_attr_type(radius_attr_eap),"EAP_CODE",(int)eaph->code,eaph->identifier,"EAP_TYPE",(int)(eap_len >= sizeof(rhp_proto_eap_response) ? ((rhp_proto_eap_response*)eaph)->type : 0),(int)(eap_l_data_len >= 64 ? 64 : eap_l_data_len),(eap_len > sizeof(rhp_proto_eap) ? (u8*)(eaph + 1) : NULL));
			}
		}
	}


	err = radius_sess->send_message(radius_sess,radius_mesg);
	if( err ){
	  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_FWD_EAP_PKT_TX_ACCESS_REQUEST_ERR,"xxxxxE",vpn,rx_ikemesg,rx_eap_pld,radius_sess,radius_mesg,err);
		goto error;
	}

	rhp_radius_mesg_unhold(radius_mesg);


	RHP_UNLOCK(&(radius_sess->lock));

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_FWD_EAP_PKT_RTRN,"xxxx",vpn,rx_ikemesg,rx_eap_pld,radius_sess);
	return 0;

error:
	if( radius_mesg ){
		rhp_radius_mesg_unhold(radius_mesg);
	}
	RHP_UNLOCK(&(radius_sess->lock));

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_FWD_EAP_PKT_ERR,"xxxxxE",vpn,rx_ikemesg,rx_eap_pld,radius_sess,radius_mesg,err);
	return err;
}

//
// Caller must NOT acquire rhp_eap_radius_cfg_lock.
//
static void _rhp_eap_auth_radius_auth_error_cb(rhp_radius_session* radius_sess,void* cb_ctx,
		rhp_radius_mesg* tx_radius_mesg,int cb_err)
{
	int err = -EINVAL;
	rhp_vpn_ref* vpn_ref = (rhp_vpn_ref*)cb_ctx;
	rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);
	rhp_eap_auth_impl_radius_ctx* ctx = NULL;
  rhp_ikev2_mesg* rx_ikemesg = NULL;
	rhp_ikev2_mesg* tx_ikemesg = NULL;
	int vpn_unhold = 0;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_AUTH_ERROR_CB,"xxxxxE",radius_sess,cb_ctx,tx_radius_mesg,vpn_ref,vpn,cb_err);

  RHP_LOCK(&(vpn->lock));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_AUTH_ERROR_CB_VPN_NOT_ACTIVE,"xxxx",radius_sess,cb_ctx,vpn_ref,vpn);
  	err = -EINVAL;
  	goto error;
  }

  ctx = (rhp_eap_auth_impl_radius_ctx*)vpn->eap.impl_ctx;
  if( ctx == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  if( ctx->radius_sess == NULL ){
		err = 0;
    RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_AUTH_ERROR_CB_NO_CTX_RADIUS_SESS,"xxxxx",radius_sess,cb_ctx,vpn_ref,vpn,ctx);
  	goto ignored;
  }

  if( ctx->radius_sess != radius_sess ){
  	RHP_BUG("");
    RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_AUTH_ERROR_CB_CTX_RADIUS_SESS_NOT_MATCH,"xxxxxx",radius_sess,cb_ctx,vpn_ref,vpn,ctx,ctx->radius_sess);
  	err = -EINVAL;
  	goto error;
  }

  if( cb_err == RHP_STATUS_RADIUS_RETX_REQ_ERR ||
  		cb_err == RHP_STATUS_DNS_RSLV_ERR ){

  	if( ctx->secondary_server_configured ){

			if( ctx->tx_secondary_server ){

				RHP_LOCK(&rhp_eap_radius_cfg_lock);
				{
					_rhp_eap_auth_radius_switch_primary_server(1);
				}
				RHP_UNLOCK(&rhp_eap_radius_cfg_lock);

				goto error;

			}else{

				RHP_LOCK(&(ctx->radius_sess->lock));
				{
					_rhp_eap_auth_session_close(ctx->radius_sess); // (****)
				}
				RHP_UNLOCK(&(ctx->radius_sess->lock));


				RHP_LOCK(&rhp_eap_radius_cfg_lock);
				{

					_rhp_eap_auth_radius_switch_secondary_server();


					ctx->radius_sess = _rhp_eap_auth_radius_session_open(
																vpn,ctx,1,
																_rhp_eap_auth_radius_auth_receive_response_cb,
																_rhp_eap_auth_radius_auth_error_cb,
																cb_ctx); // rhp_vpn_ref*
					if( ctx->radius_sess == NULL ){
						err = -EINVAL;
						RHP_UNLOCK(&rhp_eap_radius_cfg_lock);
						goto error;
					}
				}
				RHP_UNLOCK(&rhp_eap_radius_cfg_lock);


				err = _rhp_eap_auth_impl_fwd_eap_pkt(vpn,ctx->radius_sess,ctx->rx_ikemesg,ctx->rx_eap_pld);
				if( err ){
					goto error;
				}

				goto try_secondary;
			}
  	}
  }


error:
	rx_ikemesg = ctx->rx_ikemesg;
	ctx->rx_ikemesg = NULL;
	tx_ikemesg = ctx->tx_ikemesg;
	ctx->tx_ikemesg = NULL;

	ctx->is_completed = 1;

	if( ctx->radius_sess ){
		RHP_LOCK(&(ctx->radius_sess->lock));
		_rhp_eap_auth_session_close(ctx->radius_sess); // (****)
		vpn_unhold = 1;
		RHP_UNLOCK(&(ctx->radius_sess->lock));
		ctx->radius_sess = NULL;
	}

	if( rx_ikemesg && tx_ikemesg ){

		rhp_eap_recv_callback(vpn,ctx->my_ikesa_side,ctx->my_ikesa_spi,rx_ikemesg,tx_ikemesg,RHP_EAP_STAT_ERROR);
	}

	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_ERROR,"VKE",vpn,rx_ikemesg,cb_err);

	RHP_UNLOCK(&(vpn->lock));
	if( vpn_unhold ){
		rhp_vpn_unhold(vpn_ref); // Held by rhp_radius_session_open(). (****)
	}

	if( rx_ikemesg ){
  	rhp_ikev2_unhold_mesg(rx_ikemesg);
  }

  if( tx_ikemesg ){
  	rhp_ikev2_unhold_mesg(tx_ikemesg);
  }

  RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_AUTH_ERROR_CB_RTRN,"xxxxE",radius_sess,cb_ctx,vpn_ref,vpn,err);
  return;

ignored:
try_secondary:
	RHP_UNLOCK(&(vpn->lock));
  if( vpn_unhold ){
  	rhp_vpn_unhold(vpn_ref); // Held by rhp_radius_session_open(). (***)
	}

  RHP_TRC(0,RHPTRCID_EAP_AUTH_RADIUS_AUTH_ERROR_CB_IGNORED,"xxxxE",radius_sess,cb_ctx,vpn_ref,vpn,err);
  return;
}

//
// Caller needs to acquire rhp_eap_radius_cfg_lock.
//
void* rhp_eap_auth_impl_vpn_init_for_radius(rhp_vpn* vpn,rhp_vpn_realm* rlm,rhp_ikesa* ikesa)
{
	rhp_eap_auth_impl_radius_ctx* ctx = NULL;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_VPN_INIT_FOR_RADIUS,"xxx",vpn,rlm,ikesa);


	ctx = (rhp_eap_auth_impl_radius_ctx*)_rhp_malloc(sizeof(rhp_eap_auth_impl_radius_ctx));
	if( ctx == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(ctx,0,sizeof(rhp_eap_auth_impl_radius_ctx));

	ctx->method = RHP_PROTO_EAP_TYPE_PRIV_RADIUS;

	ctx->tag[0] = '#';
	ctx->tag[1] = 'E';
	ctx->tag[2] = 'R';
	ctx->tag[3] = 'A';

	ctx->vpn_ref = rhp_vpn_hold_ref(vpn);

	ctx->my_ikesa_side = ikesa->side;
	memcpy(ctx->my_ikesa_spi,ikesa->get_my_spi(ikesa),RHP_PROTO_IKE_SPI_SIZE);


	{
		rhp_vpn_ref* vpn_ref_for_radius = rhp_vpn_hold_ref(vpn);

		ctx->radius_sess = _rhp_eap_auth_radius_session_open(
													vpn,ctx,0,
													_rhp_eap_auth_radius_auth_receive_response_cb,
													_rhp_eap_auth_radius_auth_error_cb,
													(void*)vpn_ref_for_radius);
		if( ctx->radius_sess == NULL ){

			rhp_vpn_unhold(vpn_ref_for_radius);
			rhp_vpn_unhold(ctx->vpn_ref);

			_rhp_free(ctx);

			return NULL;
		}
	}


	RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_VPN_INIT_FOR_RADIUS_DUMP_CFG,"xbbbbbbbbbbbbbbbbbbbbbbbbbbbb",ctx,rhp_gcfg_eap_radius->enabled,rhp_gcfg_eap_radius->tx_nas_id_as_ikev2_id_enabled,rhp_gcfg_eap_radius->tx_calling_station_id_enabled,rhp_gcfg_eap_radius->tx_nas_port_type_enabled,rhp_gcfg_eap_radius->rx_session_timeout_enabled,rhp_gcfg_eap_radius->rx_term_action_enabled,rhp_gcfg_eap_radius->rx_framed_mtu_enabled,rhp_gcfg_eap_radius->rx_framed_ipv4_enabled,rhp_gcfg_eap_radius->rx_framed_ipv6_enabled,rhp_gcfg_eap_radius->rx_ms_primary_dns_server_v4_enabled,rhp_gcfg_eap_radius->rx_dns_server_v6_enabled,rhp_gcfg_eap_radius->rx_route_v6_info_enabled,rhp_gcfg_eap_radius->rx_ms_primary_nbns_server_v4_enabled,rhp_gcfg_eap_radius->rx_tunnel_private_group_id_enabled,rhp_gcfg_eap_radius->rx_tunnel_client_auth_id_enabled,rhp_gcfg_eap_radius->rx_vpn_realm_id_attr_type,rhp_gcfg_eap_radius->rx_vpn_realm_role_attr_type,rhp_gcfg_eap_radius->rx_user_index_attr_type,rhp_gcfg_eap_radius->rx_internal_dns_v4_attr_type,rhp_gcfg_eap_radius->rx_internal_dns_v6_attr_type,rhp_gcfg_eap_radius->rx_internal_domain_names_attr_type,rhp_gcfg_eap_radius->rx_internal_rt_maps_v4_attr_type,rhp_gcfg_eap_radius->rx_internal_rt_maps_v6_attr_type,rhp_gcfg_eap_radius->rx_internal_gw_v4_attr_type,rhp_gcfg_eap_radius->rx_internal_gw_v6_attr_type,rhp_gcfg_eap_radius->rx_internal_addr_ipv4,rhp_gcfg_eap_radius->rx_internal_addr_ipv6,rhp_gcfg_eap_radius->rx_common_priv_attr);
	RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_VPN_INIT_FOR_RADIUS_DUMP_CFG_2,"xxbbbbbbbbbbbbbbbbb",ctx,ctx->radius_sess,ctx->radius_sess->priv_attr_type_realm_id,ctx->radius_sess->priv_attr_type_realm_role,ctx->radius_sess->priv_attr_type_user_index,ctx->radius_sess->priv_attr_type_internal_address_ipv4,ctx->radius_sess->priv_attr_type_internal_address_ipv6,ctx->radius_sess->priv_attr_type_internal_dns_server_ipv4,ctx->radius_sess->priv_attr_type_internal_dns_server_ipv6,ctx->radius_sess->priv_attr_type_internal_domain_name,ctx->radius_sess->priv_attr_type_internal_route_ipv4,ctx->radius_sess->priv_attr_type_internal_route_ipv6,ctx->radius_sess->priv_attr_type_internal_gateway_ipv4,ctx->radius_sess->priv_attr_type_internal_gateway_ipv6,ctx->radius_sess->priv_attr_type_common);

  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_EAP_RADIUS_AUTH_IS_ENABLED,"VPr",vpn,ikesa,ctx->radius_sess);

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_VPN_INIT_FOR_RADIUS_RTRN,"xxxx",vpn,rlm,ikesa,ctx);

	return (void*)ctx;
}


#if 0

//
// RADIUS Termination-Action attribute for future use.
//

struct _rhp_eap_auth_radius_term_action_ctx {

	rhp_ip_addr orig_nas_addr;

	unsigned long vpn_realm_id;

	rhp_ikev2_id gateway_id;

	int termination_action_state_len;
	u8* termination_action_state;
};
typedef struct _rhp_eap_auth_radius_term_action_ctx	rhp_eap_auth_radius_term_action_ctx;

static void _rhp_eap_auth_radius_term_action_ctx_free(rhp_eap_auth_radius_term_action_ctx* task_ctx)
{
	if(task_ctx){
		if( task_ctx->termination_action_state ){
			_rhp_free(task_ctx->termination_action_state);
		}
		_rhp_free(task_ctx);
	}
}

static void _rhp_eap_auth_radius_tx_term_action_response_cb(
		rhp_radius_session* radius_sess,void* cb_ctx,rhp_radius_mesg* rx_radius_mesg)
{
	rhp_eap_auth_radius_term_action_ctx* task_ctx = (rhp_eap_auth_radius_term_action_ctx*)cb_ctx;

	RHP_LOCK(&(radius_sess->lock));
	_rhp_eap_auth_session_close(radius_sess);
	RHP_UNLOCK(&(radius_sess->lock));

	_rhp_eap_auth_radius_term_action_ctx_free(task_ctx);
	return;
}

static void _rhp_eap_auth_radius_tx_term_action_error_cb(
		rhp_radius_session* radius_sess,void* cb_ctx,int cb_err)
{
	rhp_eap_auth_radius_term_action_ctx* task_ctx = (rhp_eap_auth_radius_term_action_ctx*)cb_ctx;

	RHP_LOCK(&(radius_sess->lock));
	_rhp_eap_auth_session_close(radius_sess);
	RHP_UNLOCK(&(radius_sess->lock));

	_rhp_eap_auth_radius_term_action_ctx_free(task_ctx);
	return;
}

static void _rhp_eap_auth_radius_tx_term_action_task(int worker_index,void *ctx)
{
	int err = -EINVAL;
	rhp_eap_auth_radius_term_action_ctx* task_ctx = (rhp_eap_auth_radius_term_action_ctx*)ctx;
	rhp_radius_session* radius_sess = NULL;
	rhp_ip_addr server_addr_port;
	rhp_radius_mesg* tx_radius_mesg = NULL;
	rhp_radius_attr* radius_attr_state = NULL;
	int max_session = 0;

	RHP_LOCK(&rhp_eap_radius_cfg_lock);

	if( rhp_ip_addr_cmp_ip_only(&(rhp_gcfg_eap_radius->nas_addr),&(task_ctx->orig_nas_addr)) ||
			rhp_gcfg_eap_radius->nas_addr.port != task_ctx->orig_nas_addr.port ){
		err = -ENOENT;
		RHP_UNLOCK(&rhp_eap_radius_cfg_lock);
		goto error;
	}

	memcpy(&server_addr_port,&(rhp_gcfg_eap_radius->server_addr_port),sizeof(rhp_ip_addr));

	max_session = rhp_gcfg_eap_radius->max_sessions;

	RHP_UNLOCK(&rhp_eap_radius_cfg_lock);



	radius_sess = _rhp_eap_auth_radius_session_open(
												&(task_ctx->orig_nas_addr),&server_addr_port,
												task_ctx->vpn_realm_id,&(task_ctx->gateway_id),
												_rhp_eap_auth_radius_tx_term_action_response_cb,
												_rhp_eap_auth_radius_tx_term_action_error_cb,
												(void*)task_ctx,
												max_session);
	if( radius_sess == NULL ){
		err = -EINVAL;
		goto error;
	}

	RHP_LOCK(&(radius_sess->lock));

	tx_radius_mesg = rhp_radius_new_mesg_tx(RHP_RADIUS_CODE_ACCESS_REQUEST,0);
	if( tx_radius_mesg == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}


	{
		err = rhp_radius_new_attr_tx(radius_sess,tx_radius_mesg,
				RHP_RADIUS_ATTR_TYPE_STATE,0,&radius_attr_state);
		if( err ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		err = radius_attr_state->ext.basic->set_attr_value(
						radius_attr_state,
						task_ctx->termination_action_state_len,task_ctx->termination_action_state);
		if( err ){
			goto error;
		}

		tx_radius_mesg->put_attr(tx_radius_mesg,radius_attr_state);
	}

	err = radius_sess->send_message(radius_sess,tx_radius_mesg);
	if( err ){
		goto error;
	}

	rhp_radius_mesg_unhold(tx_radius_mesg);


	RHP_UNLOCK(&(radius_sess->lock));

	return;

error:
	if( radius_sess ){
		_rhp_eap_auth_session_close(radius_sess);
		RHP_UNLOCK(&(radius_sess->lock));
	}
	_rhp_eap_auth_radius_term_action_ctx_free(task_ctx);
	return;
}

static int _rhp_eap_auth_radius_tx_term_action(rhp_vpn* vpn,rhp_eap_auth_impl_radius_ctx* ctx)
{
	int err = -EINVAL;
	rhp_eap_auth_radius_term_action_ctx* task_ctx
		= (rhp_eap_auth_radius_term_action_ctx*)_rhp_malloc(sizeof(rhp_eap_auth_radius_term_action_ctx));

	if( task_ctx == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	memset(task_ctx,0,sizeof(rhp_eap_auth_radius_term_action_ctx));

	task_ctx->vpn_realm_id = vpn->vpn_realm_id;

	if( rhp_ikev2_id_dup(&(task_ctx->gateway_id),&(vpn->my_id)) ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	{
		task_ctx->termination_action_state
			= (u8*)_rhp_malloc(vpn->radius.rx_accept_attrs->termination_action_state_len);
		if( task_ctx->termination_action_state == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		memcpy(task_ctx->termination_action_state,
				vpn->radius.rx_accept_attrs->termination_action_state,
				vpn->radius.rx_accept_attrs->termination_action_state_len);

		task_ctx->termination_action_state_len
			= vpn->radius.rx_accept_attrs->termination_action_state_len;
	}

	memcpy(&(task_ctx->orig_nas_addr),
			&(vpn->radius.rx_accept_attrs->orig_nas_addr),sizeof(rhp_ip_addr));

	err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_2,
				_rhp_eap_auth_radius_tx_term_action_task,task_ctx);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	return 0;

error:
	_rhp_eap_auth_radius_term_action_ctx_free(task_ctx);
	return err;
}
#endif

void rhp_eap_auth_impl_vpn_cleanup_for_radius(rhp_vpn* vpn,void* impl_ctx)
{
	rhp_eap_auth_impl_radius_ctx* ctx = (rhp_eap_auth_impl_radius_ctx*)impl_ctx;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_VPN_CLEANUP_FOR_RADIUS,"xxxxx",vpn,impl_ctx,ctx->vpn_ref,ctx->rx_ikemesg,ctx->tx_ikemesg);

	if( RHP_VPN_REF(ctx->vpn_ref) != vpn ){
		RHP_BUG("");
	}

// Termination-Action for future use.
#if 0
  if( vpn->radius.rx_accept_attrs &&
  		vpn->radius.rx_accept_attrs->termination_action
  			== RHP_RADIUS_ATTR_TYPE_TERMINATION_ACTION_REQUEST &&
  		vpn->radius.rx_accept_attrs->termination_action_state ){

  	_rhp_eap_auth_radius_tx_term_action(vpn,ctx);
  }
#endif

	if( ctx->radius_sess ){
		RHP_LOCK(&(ctx->radius_sess->lock));
		_rhp_eap_auth_session_close(ctx->radius_sess);
		RHP_UNLOCK(&(ctx->radius_sess->lock));
	}

	if( ctx->rx_ikemesg ){
		rhp_ikev2_unhold_mesg(ctx->rx_ikemesg);
	}

	if( ctx->tx_ikemesg ){
		rhp_ikev2_unhold_mesg(ctx->tx_ikemesg);
	}

	if( ctx->vpn_ref ){
		rhp_vpn_unhold(ctx->vpn_ref);
	}

	if( ctx->peer_identity ){
		_rhp_free(ctx->peer_identity);
	}

	if( ctx->msk ){
		_rhp_free_zero(ctx->msk,ctx->msk_len);
	}

	_rhp_free_zero(ctx,sizeof(rhp_eap_auth_impl_radius_ctx));

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_VPN_CLEANUP_FOR_RADIUS_RTRN,"xx",vpn,impl_ctx);
	return;
}

int rhp_eap_auth_impl_init_req_for_radius(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg,void* impl_ctx)
{
	int err = -EINVAL;
	rhp_eap_auth_impl_radius_ctx* ctx = (rhp_eap_auth_impl_radius_ctx*)impl_ctx;
	rhp_proto_eap_request eap_req;
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_INIT_REQ_FOR_RADIUS,"xxxxxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg,impl_ctx,ctx->vpn_ref,ctx->radius_sess);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_MAIN ){
    RHP_BUG("");
    return -EPERM;
  }

	if( RHP_VPN_REF(ctx->vpn_ref) != vpn ){
		RHP_BUG("");
		return -EINVAL;
	}

	eap_req.code = RHP_PROTO_EAP_CODE_REQUEST;
	eap_req.identifier = 1;
	eap_req.len = htons(sizeof(rhp_proto_eap_request));
	eap_req.type = RHP_PROTO_EAP_TYPE_IDENTITY;

	{
		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_EAP,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

		err = ikepayload->ext.eap->set_eap_message(ikepayload,
				(u8*)&eap_req,(int)ntohs(eap_req.len));

		if( err ){
			RHP_BUG("");
			goto error;
		}
	}

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_INIT_REQ_FOR_RADIUS_RTRN,"xxxxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg,impl_ctx,ctx->vpn_ref);
	return RHP_EAP_STAT_CONTINUE;

error:
	RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_INIT_REQ_FOR_RADIUS_ERR,"xxxxxxE",vpn,ikesa,rx_ikemesg,tx_ikemesg,impl_ctx,ctx->vpn_ref,err);
	return err;
}


//
// Caller must NOT acquire rhp_eap_radius_cfg_lock.
//
int rhp_eap_auth_impl_recv_for_radius(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_payload* rx_eap_pld,rhp_ikev2_mesg* tx_ikemesg,void* impl_ctx)
{
	int err = -EINVAL;
	rhp_eap_auth_impl_radius_ctx* ctx = (rhp_eap_auth_impl_radius_ctx*)impl_ctx;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_RECV_FOR_RADIUS,"xxxxxxx",vpn,ikesa,rx_ikemesg,rx_eap_pld,tx_ikemesg,impl_ctx,ctx->vpn_ref);


  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_MAIN ){
    RHP_BUG("");
    return -EPERM;
  }

  err = _rhp_eap_auth_impl_fwd_eap_pkt(vpn,ctx->radius_sess,rx_ikemesg,rx_eap_pld);
  if( err ){
  	goto error;
  }


  ctx->rx_ikemesg = rx_ikemesg;
  ctx->rx_eap_pld = rx_eap_pld;
	rhp_ikev2_hold_mesg(rx_ikemesg);

  ctx->tx_ikemesg = tx_ikemesg;
	rhp_ikev2_hold_mesg(tx_ikemesg);


  RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_RECV_FOR_RADIUS_RTRN,"xxxxxxx",vpn,ikesa,rx_ikemesg,rx_eap_pld,tx_ikemesg,impl_ctx,ctx->vpn_ref);
	return RHP_EAP_STAT_PENDING;

error:
	RHP_TRC(0,RHPTRCID_EAP_AUTH_IMPL_RECV_FOR_RADIUS_ERR,"xxxxxxxE",vpn,ikesa,rx_ikemesg,rx_eap_pld,tx_ikemesg,impl_ctx,ctx->vpn_ref,err);
	return err;
}

int rhp_eap_auth_get_msk_for_radius(rhp_vpn* vpn,void* impl_ctx,int* msk_len_r,u8** msk_r)
{
	rhp_eap_auth_impl_radius_ctx* ctx = (rhp_eap_auth_impl_radius_ctx*)impl_ctx;
	u8* ret;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_GET_MSK_FOR_RADIUS,"xxxx",vpn,impl_ctx,msk_len_r,msk_r);

	if( !ctx->is_completed ){
		RHP_BUG("");
		return -ENOENT;
	}

	if( ctx->msk == NULL || ctx->msk_len == 0 ){
	  RHP_TRC(0,RHPTRCID_EAP_AUTH_GET_MSK_FOR_RADIUS_NO_MSK,"xx",vpn,impl_ctx);
		return -ENOENT;
	}

	ret = (u8*)_rhp_malloc(ctx->msk_len);
	if( ret == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	memcpy(ret,ctx->msk,ctx->msk_len);

	*msk_len_r = ctx->msk_len;
	*msk_r = ret;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_GET_MSK_FOR_RADIUS_RTRN,"xxp",vpn,impl_ctx,*msk_len_r,*msk_r);
	return 0;
}

int rhp_eap_auth_get_peer_identity_for_radius(rhp_vpn* vpn,void* impl_ctx,int* ident_len_r,u8** ident_r)
{
	rhp_eap_auth_impl_radius_ctx* ctx = (rhp_eap_auth_impl_radius_ctx*)impl_ctx;
	u8* ret;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_GET_PEER_IDENTITY_FOR_RADIUS,"xxxx",vpn,impl_ctx,ident_len_r,ident_r);

	if( !ctx->is_completed ){
		RHP_BUG("");
		return -ENOENT;
	}

	if( ctx->peer_identity_len < 1 ){
		RHP_BUG("");
		return -ENOENT;
	}

	ret = (u8*)_rhp_malloc(ctx->peer_identity_len);
	if( ret == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	memcpy(ret,ctx->peer_identity,ctx->peer_identity_len);

	*ident_len_r = ctx->peer_identity_len;
	*ident_r = ret;

  RHP_TRC(0,RHPTRCID_EAP_AUTH_GET_PEER_IDENTITY_FOR_RADIUS_RTRN,"xxp",vpn,impl_ctx,*ident_len_r,*ident_r);
	return 0;
}
