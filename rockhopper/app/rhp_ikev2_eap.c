/*

	Copyright (C) 2009-2013 TETSUHARU HANADA <rhpenguine@gmail.com>
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
#include "rhp_packet.h"
#include "rhp_config.h"
#include "rhp_ikev2_mesg.h"
#include "rhp_vpn.h"
#include "rhp_ikev2.h"
#include "rhp_forward.h"
#include "rhp_eap.h"
#include "rhp_eap_auth_impl.h"
#include "rhp_eap_sup_impl.h"
#include "rhp_radius_impl.h"


extern int rhp_ikev2_rx_ike_auth_rep_eap_comp(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ikev2_mesg* tx_req_ikemesg);


static int _rhp_ikev2_rx_eap_get_payload(rhp_ikev2_mesg* rx_ikemesg,rhp_vpn* vpn,rhp_ikev2_payload** rx_eap_pld_r)
{
	int err = -EINVAL;
  rhp_proto_ike* ikeh;
  rhp_ikev2_payload* rx_eap_pld = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_EAP_GET_PAYLOAD,"xxx",rx_ikemesg,vpn,rx_eap_pld_r);

  ikeh = rx_ikemesg->rx_pkt->app.ikeh;

  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


  rx_eap_pld = rx_ikemesg->get_payload(rx_ikemesg,RHP_PROTO_IKE_PAYLOAD_EAP);
  if( rx_eap_pld == NULL ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_GET_PAYLOAD_NOT_FOUND,"xxE",rx_ikemesg,vpn,err);
  	goto error;
  }

  *rx_eap_pld_r = rx_eap_pld;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_EAP_GET_PAYLOAD_RTRN,"xxx",rx_ikemesg,vpn,*rx_eap_pld_r);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_EAP_GET_PAYLOAD_ERR,"xxxE",rx_ikemesg,vpn,rx_eap_pld_r,err);
	return err;
}

static int _rhp_ikev2_rx_ike_eap_req_init(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,
		rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err = -EINVAL;
	rhp_vpn_realm* rlm = vpn->rlm;
  u16 notify_mesg_type = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;
  unsigned long notify_error_arg = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_EAP_REQ_INIT,"xxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_EAP_REQ_INIT_RLM_NOT_ACTIVE,"xxx",vpn,ikesa,rx_req_ikemesg,rlm);
    goto notify_error_rlm_l;
  }


	vpn->eap.impl_ctx = rhp_eap_auth_impl_vpn_init(vpn->eap.eap_method,vpn,rlm,ikesa);
	if( vpn->eap.impl_ctx == NULL ){
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_EAP_REQ_INIT_FAIL_TO_GET_IMPL_CTX,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,rlm);
    goto notify_error_rlm_l;
	}

  RHP_UNLOCK(&(rlm->lock));


  err = rhp_eap_auth_impl_init_req(vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,vpn->eap.impl_ctx);

  if( err == RHP_EAP_STAT_PENDING ){

  	// This EAP message is forwarded to an external authentication service like a Rockhopper
  	// protected process or a RADIUS server.

  	err = RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;
    rhp_vpn_hold(vpn);

		ikesa->busy_flag = 1;

  }else if( err == RHP_EAP_STAT_CONTINUE ){

  	err = RHP_STATUS_IKEV2_MESG_HANDLER_END;

  }else{

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_EAP_REQ_INIT_IMPL_INIT_REQ_ERR,"xxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);

  	err = -EINVAL;
    goto notify_error;
  }

	ikesa->eap.state = RHP_IKESA_EAP_STAT_R_PEND;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_EAP_REQ_INIT_RTRN,"xxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);
  return err;


notify_error_rlm_l:
	RHP_UNLOCK(&(rlm->lock));

notify_error:

	err = rhp_ikev2_new_pkt_ike_auth_error_notify(ikesa,tx_resp_ikemesg,0,0,
					notify_mesg_type,notify_error_arg);

	if( err ){
		RHP_BUG("");
		goto error;
	}

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_EAP_REQ_INIT_TX_ERR_NOTIFY,"KVPL",tx_resp_ikemesg,vpn,ikesa,"PROTO_IKE_NOTIFY",notify_mesg_type);

	err = RHP_STATUS_IKEV2_DESTROY_SA_AFTER_TX;
	goto error;

	RHP_UNLOCK(&(rlm->lock));

error:

	RHP_TRC(0,RHPTRCID_IKEV2_RX_EAP_REQ_INIT_RTRN,"xxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);
	return err;
}

int rhp_ikev2_eap_auth_set_peer_ident(rhp_vpn* vpn)
{
	int err = -EINVAL;
	u8* peer_identity = NULL;
	int peer_identity_len = 0;

	RHP_TRC(0,RHPTRCID_IKEV2_EAP_AUTH_SET_PEER_IDENT,"xp",vpn,vpn->eap.peer_id.identity_len,vpn->eap.peer_id.identity);

	rhp_eap_id_clear(&(vpn->eap.peer_id));

	rhp_eap_auth_get_peer_identity(vpn,vpn->eap.impl_ctx,&peer_identity_len,&peer_identity);

	if( peer_identity_len ){

		err = rhp_eap_id_setup(vpn->eap.eap_method,
				peer_identity_len,peer_identity,vpn->is_v1,
				&(vpn->eap.peer_id));
		if( err ){
			RHP_BUG("");
			goto error;
		}

		_rhp_free(peer_identity);
		peer_identity = NULL;


		if( vpn->eap.eap_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS ){

			if( vpn->radius.rx_accept_attrs ){

				char* user_index = NULL;
				rhp_ip_addr *assigned_addr_v4 = NULL, *assigned_addr_v6 = NULL;
				rhp_ip_addr *tmp_addr = NULL;


				vpn->eap.peer_id.radius.eap_method = vpn->radius.eap_method;


				RHP_LOCK(&rhp_eap_radius_cfg_lock);

				if( rhp_eap_radius_rx_attr_enabled(rhp_gcfg_eap_radius->rx_user_index_attr_type,0,0) ){

					user_index = vpn->radius.rx_accept_attrs->priv_user_index;
					RHP_VPN_RADIUS_ATTRS_MASK_SET(vpn,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_USER_INDEX);

				}else if( rhp_eap_radius_rx_attr_enabled(RHP_RADIUS_ATTR_TYPE_TUNNEL_CLIENT_AUTH_ID,0,0) ){

					user_index = vpn->radius.rx_accept_attrs->tunnel_client_auth_id;
					RHP_VPN_RADIUS_ATTRS_MASK_SET(vpn,RHP_VPN_RADIUS_ATTRS_MASK_TUNNEL_CLIENT_AUTH_ID);
				}

				{
					if( rhp_eap_radius_rx_attr_enabled(rhp_gcfg_eap_radius->rx_internal_addr_ipv4,0,0) ){
						tmp_addr = &(vpn->radius.rx_accept_attrs->priv_internal_addr_ipv4);
					}else if( rhp_eap_radius_rx_attr_enabled(RHP_RADIUS_ATTR_TYPE_FRAMED_IP_ADDRESS,0,0) ){
						tmp_addr = &(vpn->radius.rx_accept_attrs->framed_ipv4);
					}

					if( tmp_addr ){

						assigned_addr_v4 = (rhp_ip_addr*)_rhp_malloc(sizeof(rhp_ip_addr));
						if( assigned_addr_v4 == NULL ){
							RHP_UNLOCK(&rhp_eap_radius_cfg_lock);
							RHP_BUG("");
							err = -ENOMEM;
							goto error;
						}

						memcpy(assigned_addr_v4,tmp_addr,sizeof(rhp_ip_addr));

						vpn->eap.peer_id.radius.assigned_addr_v4 = assigned_addr_v4;

						tmp_addr = NULL;
					}
				}

				{
					if( rhp_eap_radius_rx_attr_enabled(rhp_gcfg_eap_radius->rx_internal_addr_ipv6,0,0) ){
						tmp_addr = &(vpn->radius.rx_accept_attrs->priv_internal_addr_ipv6);
					}else if( rhp_eap_radius_rx_attr_enabled(RHP_RADIUS_ATTR_TYPE_FRAMED_IPV6_ADDRESS,0,0) ){
						tmp_addr = &(vpn->radius.rx_accept_attrs->framed_ipv6);
					}

					if( tmp_addr ){

						assigned_addr_v6 = (rhp_ip_addr*)_rhp_malloc(sizeof(rhp_ip_addr));
						if( assigned_addr_v6 == NULL ){
							RHP_UNLOCK(&rhp_eap_radius_cfg_lock);
							RHP_BUG("");
							err = -ENOMEM;
							goto error;
						}

						memcpy(assigned_addr_v6,tmp_addr,sizeof(rhp_ip_addr));

						vpn->eap.peer_id.radius.assigned_addr_v6 = assigned_addr_v6;

						tmp_addr = NULL;
					}
				}

				RHP_UNLOCK(&rhp_eap_radius_cfg_lock);


				if( user_index ){

					int idx_len = strlen(user_index);

					vpn->eap.peer_id.radius.user_index = (char*)_rhp_malloc(idx_len + 1);
					if( vpn->eap.peer_id.radius.user_index == NULL ){
						RHP_BUG("");
						err = -ENOMEM;
						goto error;
					}
					memcpy(vpn->eap.peer_id.radius.user_index,user_index,idx_len);
					vpn->eap.peer_id.radius.user_index[idx_len] = '\0';
				}
			}

			if( !rhp_eap_identity_not_protected(vpn->eap.peer_id.radius.eap_method) &&
					vpn->eap.peer_id.radius.user_index == NULL &&
					vpn->eap.peer_id.radius.assigned_addr_v4 == NULL &&
					vpn->eap.peer_id.radius.assigned_addr_v6 == NULL ){

			  if( rhp_random_bytes((u8*)&(vpn->eap.peer_id.radius.salt),sizeof(u32)) ){
			    RHP_BUG("");
			  }

			}else{

				vpn->eap.peer_id.radius.salt = 0;
			}
		}

		RHP_TRC(0,RHPTRCID_IKEV2_EAP_AUTH_SET_PEER_IDENT_RTRN,"xp",vpn,vpn->eap.peer_id.identity_len,vpn->eap.peer_id.identity);
		return 0;
	}

	err = -ENOENT;

error:
	if( peer_identity ){
		_rhp_free(peer_identity);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_EAP_AUTH_SET_PEER_IDENT_ERR,"xE",vpn,err);
	return err;
}

static int _rhp_ikev2_eap_sup_set_my_ident(rhp_vpn* vpn)
{
	int err = -EINVAL;
	u8* my_identity = NULL;
	int my_identity_len = 0;

	RHP_TRC(0,RHPTRCID_IKEV2_EAP_SUP_SET_MY_IDENT,"xp",vpn,vpn->eap.my_id.identity_len,vpn->eap.my_id.identity);

	rhp_eap_id_clear(&(vpn->eap.my_id));

	rhp_eap_sup_get_my_identity(vpn,vpn->eap.impl_ctx,&my_identity_len,&my_identity);

	if( my_identity_len ){

		err = rhp_eap_id_setup(vpn->eap.eap_method,
				my_identity_len,my_identity,vpn->is_v1,
				&(vpn->eap.my_id));
		if( err ){
			RHP_BUG("");
			goto error;
		}

		_rhp_free(my_identity);

		RHP_TRC(0,RHPTRCID_IKEV2_EAP_SUP_SET_MY_IDENT_RTRN,"xp",vpn,vpn->eap.my_id.identity_len,vpn->eap.my_id.identity);
		return 0;
	}

	err = -ENOENT;

error:
	if( my_identity ){
		_rhp_free(my_identity);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_EAP_SUP_SET_MY_IDENT_ERR,"xE",vpn,err);
	return err;
}

static int _rhp_ikev2_rx_ike_eap_req_pend(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,
		rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err = -EINVAL;
  u16 notify_mesg_type = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;
  unsigned long notify_error_arg = 0;
  rhp_ikev2_payload* rx_eap_pld = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_REQ_PEND,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);

  err = _rhp_ikev2_rx_eap_get_payload(rx_req_ikemesg,vpn,&rx_eap_pld);
  if( err ){
    goto notify_error;
  }


  err = rhp_eap_auth_impl_recv(vpn,ikesa,rx_req_ikemesg,rx_eap_pld,tx_resp_ikemesg,vpn->eap.impl_ctx);
  if( err == RHP_EAP_STAT_PENDING ){

  	// This EAP message is forwarded to an external authentication service like a Rockhopper
  	// protected process or a RADIUS server.

  	err = RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;
    rhp_vpn_hold(vpn);

		ikesa->busy_flag = 1;

  }else if( err == RHP_EAP_STAT_CONTINUE ){

  	err = RHP_STATUS_IKEV2_MESG_HANDLER_END;

  }else if( err == RHP_EAP_STAT_COMPLETED ){

		rhp_ikev2_eap_auth_set_peer_ident(vpn);

  	ikesa->eap.state = RHP_IKESA_EAP_STAT_R_COMP;
  	err = 0;

  }else{

    RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_REQ_PEND_IMPL_RECV_ERR,"xxxE",vpn,ikesa,rx_req_ikemesg,err);

  	err = -EINVAL;
    goto notify_error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_REQ_PEND_RTRN,"xxxE",vpn,ikesa,rx_req_ikemesg,err);
  return err;


notify_error:
	{
		rhp_ikev2_payload* eap_pld = tx_resp_ikemesg->get_payload(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_EAP);

		if( eap_pld == NULL ||
			 (eap_pld->ext.eap->get_code(eap_pld) != RHP_PROTO_EAP_CODE_FAILURE) ){

			err = rhp_ikev2_new_pkt_ike_auth_error_notify(ikesa,tx_resp_ikemesg,0,0,
						notify_mesg_type,notify_error_arg);

			if( err ){
				RHP_BUG("");
			}else{
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_EAP_REQ_PEND_TX_ERR_NOTIFY,"KVPL",tx_resp_ikemesg,vpn,ikesa,"PROTO_IKE_NOTIFY",notify_mesg_type);
			}
		}

		err = RHP_STATUS_IKEV2_DESTROY_SA_AFTER_TX;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_REQ_PEND_ERR,"xxxE",vpn,ikesa,rx_req_ikemesg,err);
	return err;
}


// Caller must acquire vpn->lock.
void rhp_eap_recv_callback(rhp_vpn* vpn,int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* rx_ikemesg,
		rhp_ikev2_mesg* tx_ikemesg,int eap_stat/*RHP_EAP_STAT_XXX*/)
{
	int err = -EINVAL;
	int caller_type;
	rhp_ikesa* ikesa = NULL;
  u16 notify_mesg_type = RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED;
  unsigned long notify_error_arg = 0;
  int rx_is_req = rx_ikemesg->is_request(rx_ikemesg);

  RHP_TRC(0,RHPTRCID_EAP_RECV_CALLBACK,"xLdLdGxxLdd",vpn,"EAP_ROLE",vpn->eap.role,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,rx_ikemesg,tx_ikemesg,"EAP_STAT",eap_stat,rx_is_req);

  ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
  if( ikesa == NULL ){
    RHP_TRC(0,RHPTRCID_EAP_RECV_CALLBACK_NO_IKESA,"xx",vpn,rx_ikemesg);
    err = -ENOENT;
  	goto error_vpn;
  }

  ikesa->busy_flag = 0;


  if( (rx_is_req && (vpn->eap.role != RHP_EAP_AUTHENTICATOR)) ||
  		(!rx_is_req && (vpn->eap.role != RHP_EAP_SUPPLICANT)) ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error_vpn;
  }

  if( eap_stat == RHP_EAP_STAT_CONTINUE ){

  	caller_type = RHP_IKEV2_MESG_HANDLER_END;

  	if( rx_is_req ){
  		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_EAP_SERVER_AUTH_CONTINUE,"KVP",rx_ikemesg,vpn,ikesa);
  	}else{
  		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_EAP_PEER_AUTH_CONTINUE,"KVP",rx_ikemesg,vpn,ikesa);
  	}

  }else if( eap_stat == RHP_EAP_STAT_COMPLETED ){

  	if( rx_is_req ){

  		rhp_ikev2_eap_auth_set_peer_ident(vpn);

  		ikesa->eap.state = RHP_IKESA_EAP_STAT_R_COMP;

  		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_EAP_SERVER_AUTH_COMPLETED,"KVPe",rx_ikemesg,vpn,ikesa,&(vpn->eap.peer_id));

  	}else{

  		err = rhp_ikev2_rx_ike_auth_rep_eap_comp(vpn,ikesa,rx_ikemesg,tx_ikemesg);
  		if( err ){
  			goto error_vpn;
  		}

  		ikesa->eap.state = RHP_IKESA_EAP_STAT_I_COMP;

  		_rhp_ikev2_eap_sup_set_my_ident(vpn);

  		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_EAP_PEER_AUTH_COMPLETED,"KVPe",rx_ikemesg,vpn,ikesa,&(vpn->eap.peer_id));
  	}

  	caller_type = RHP_IKEV2_MESG_HANDLER_EAP;

  }else{

  	if( rx_is_req ){

  		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_EAP_SERVER_AUTH_ERROR,"KVP",rx_ikemesg,vpn,ikesa);

  	}else{

  		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_EAP_PEER_AUTH_ERROR,"KVP",rx_ikemesg,vpn,ikesa);
  	}

		rhp_ikev2_g_statistics_inc(ikesa_auth_errors);

  	err = eap_stat;
    goto notify_error;
  }

  if( rx_is_req ){

  	rhp_ikev2_call_next_rx_request_mesg_handlers(rx_ikemesg,vpn,
  		my_ikesa_side,my_ikesa_spi,tx_ikemesg,caller_type);

  }else{

  	rhp_ikev2_call_next_rx_response_mesg_handlers(rx_ikemesg,vpn,
  		my_ikesa_side,my_ikesa_spi,tx_ikemesg,caller_type);
  }


  err = 0;

  // rhp_eap_auth_impl_recv() or rhp_eap_sup_impl_recv() held the vpn and returned PENDING.
  rhp_vpn_unhold(vpn);

  RHP_TRC(0,RHPTRCID_EAP_RECV_CALLBACK_EAP_STAT_RTRN,"xxE",vpn,rx_ikemesg,ikesa->eap.state);
  return;


notify_error:
error_vpn:
	if( ikesa ){

		if( rx_is_req ){

			rhp_ikev2_payload* eap_pld = tx_ikemesg->get_payload(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_EAP);

			if( eap_pld == NULL ||
				 (eap_pld->ext.eap->get_code(eap_pld) != RHP_PROTO_EAP_CODE_FAILURE) ){

				err = rhp_ikev2_new_pkt_ike_auth_error_notify(ikesa,tx_ikemesg,0,0,
								notify_mesg_type,notify_error_arg);

				if( err ){
					RHP_BUG("");
				}else{
					RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_EAP_REQ_CB_TX_ERR_NOTIFY,"KVPL",tx_ikemesg,vpn,ikesa,"PROTO_IKE_NOTIFY",notify_mesg_type);
				}
			}

			rhp_ikev2_call_next_rx_request_mesg_handlers(rx_ikemesg,vpn,
						my_ikesa_side,my_ikesa_spi,tx_ikemesg,RHP_IKEV2_MESG_HANDLER_END);
		}

		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
	}


	if( rx_is_req ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_EAP_SERVER_AUTH_FAILED,"KVPE",rx_ikemesg,vpn,ikesa,err);
	}else{
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_EAP_PEER_AUTH_FAILED,"KVPE",rx_ikemesg,vpn,ikesa,err);
	}

  // rhp_eap_auth_impl_recv() or rhp_eap_sup_impl_recv() held the vpn and returned PENDING.
  rhp_vpn_unhold(vpn);

  RHP_TRC(0,RHPTRCID_EAP_RECV_CALLBACK_EAP_STAT_ERR,"xxE",vpn,rx_ikemesg,err);
  return;
}


int rhp_ikev2_rx_ike_eap_req(rhp_ikev2_mesg* rx_req_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err = -EINVAL;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_req_ikemesg->get_exchange_type(rx_req_ikemesg);
	u32 mesg_id;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_REQ,"xxLdGxLb",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_resp_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

	if( exchange_type != RHP_PROTO_IKE_EXCHG_IKE_AUTH ){
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_REQ_NOT_IKE_AUTH_EXCHG,"xxLb",rx_req_ikemesg,vpn,"PROTO_IKE_EXCHG",exchange_type);
		return 0;
	}

	if( vpn->eap.role != RHP_EAP_AUTHENTICATOR ){
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_REQ_NOT_AUTHENTICATOR,"xx",rx_req_ikemesg,vpn);
  	err = 0;
  	goto error;
  }

	if( !RHP_PROTO_IKE_HDR_INITIATOR(rx_req_ikemesg->rx_pkt->app.ikeh->flag) ){
		err = RHP_STATUS_INVALID_MSG;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_REQ_INVALID_MESG1,"xx",rx_req_ikemesg,vpn);
		goto error;
  }

  if( !rx_req_ikemesg->decrypted ){
  	err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_REQ_NOT_DECRYPTED,"xx",rx_req_ikemesg,vpn);
  	goto error;
  }


	if( my_ikesa_spi == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

	ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
	if( ikesa == NULL ){
		err = -ENOENT;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_REQ_NO_IKESA,"xxLdG",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
		goto error;
	}

  if( ikesa->state != RHP_IKESA_STAT_R_IKE_SA_INIT_SENT ){
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_REQ_NOT_INTRESTED_STATE,"xxLdGLd",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state);
  	err = 0;
  	goto error;
  }


	mesg_id = rx_req_ikemesg->get_mesg_id(rx_req_ikemesg);

	if( mesg_id == 1 ){

		if( ikesa->eap.state != RHP_IKESA_EAP_STAT_DEFAULT ){
	  	err = RHP_STATUS_BAD_SA_STATE;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_REQ_BAD_EAP_STAT1,"xxLdGLd",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"EAP_STAT",ikesa->eap.state);
			goto error;
		}

		err = _rhp_ikev2_rx_ike_eap_req_init(vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);

	}else{

	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_REQ_EAP_STAT,"xxLdGLd",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state,"EAP_STAT",ikesa->eap.state);

		if( ikesa->eap.state == RHP_IKESA_EAP_STAT_R_PEND ){

			err = _rhp_ikev2_rx_ike_eap_req_pend(vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);

		}else if( ikesa->eap.state == RHP_IKESA_EAP_STAT_R_COMP ){

			err = 0;
			goto error;

		}else{
	  	err = RHP_STATUS_BAD_SA_STATE;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_REQ_BAD_EAP_STAT2,"xxLdGLd",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"EAP_STAT",ikesa->eap.state);
			goto error;
		}
	}

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_REQ_RTRN,"xxxE",rx_req_ikemesg,vpn,tx_resp_ikemesg,err);
  return err;
}


struct _rhp_ike_eap_srch_plds_ctx {

	rhp_ikev2_payload* n_error_payload;
  int n_err;

};
typedef struct _rhp_ike_eap_srch_plds_ctx rhp_ike_eap_srch_plds_ctx;


static int _rhp_ikev2_ike_eap_srch_n_error_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_ike_eap_srch_plds_ctx* s_pld_ctx = (rhp_ike_eap_srch_plds_ctx*)ctx;
  rhp_ikev2_n_payload* n_payload = (rhp_ikev2_n_payload*)payload->ext.n;
  u16 notify_mesg_type;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_EAP_SRCH_N_ERROR_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

  if( n_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  notify_mesg_type = n_payload->get_message_type(payload);

  //
  // TODO : Handling more interested notify-error codes???
  //
  if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ERR_INVALID_SYNTAX ||
  		notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED ){

    RHP_TRC(0,RHPTRCID_IKEV2_IKE_EAP_SRCH_N_ERROR_CB_FOUND,"xxLw",rx_ikemesg,payload,"PROTO_IKE_NOTIFY",notify_mesg_type);

    s_pld_ctx->n_error_payload = payload;
    s_pld_ctx->n_err = notify_mesg_type;

    err = RHP_STATUS_ENUM_OK;
    goto error;
  }

  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_IKE_EAP_SRCH_N_ERROR_CB_RTRN,"xxE",rx_ikemesg,payload,err);
  return err;
}

static int _rhp_ikev2_rx_ike_eap_resp_pend(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_resp_ikemesg,
		rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err = -EINVAL;
  rhp_ikev2_payload* rx_eap_pld = NULL;
  u8 tx_ikemesg_exchg = tx_req_ikemesg->get_exchange_type(tx_req_ikemesg);
  rhp_ike_eap_srch_plds_ctx s_pld_ctx;
  int delete_ikesa = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_RESP_PEND,"xxxxb",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,tx_ikemesg_exchg);

  memset(&s_pld_ctx,0,sizeof(rhp_ike_eap_srch_plds_ctx));


	{
		err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
				rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_N),
				_rhp_ikev2_ike_eap_srch_n_error_cb,&s_pld_ctx);

		if( ( err == 0 || err == RHP_STATUS_ENUM_OK ) && (s_pld_ctx.n_error_payload != NULL ) ){

			RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_RESP_PEND_RX_N_PEER_ERROR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);

			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_EAP_RESP_N_ERR_PAYLOAD,"KVPL",rx_resp_ikemesg,vpn,ikesa,"PROTO_IKE_NOTIFY",s_pld_ctx.n_err);

			err = RHP_STATUS_PEER_NOTIFIED_ERROR;
			delete_ikesa = 1;
			goto error;

		}else if( err && err != -ENOENT ){

			RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_RESP_PEND_N_ERROR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_EAP_RESP_PARSE_N_ERR_PAYLOAD_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);

			delete_ikesa = 1;
			goto error;
		}
		err = 0;
	}


  err = _rhp_ikev2_rx_eap_get_payload(rx_resp_ikemesg,vpn,&rx_eap_pld);
  if( err ){
		delete_ikesa = 1;
    goto error;
  }

	if( tx_ikemesg_exchg == RHP_PROTO_IKE_EXCHG_RESEVED ){
		tx_req_ikemesg->set_exchange_type(tx_req_ikemesg,RHP_PROTO_IKE_EXCHG_IKE_AUTH);
	}else{
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_RESP_PEND_TX_MSG_NOT_IKE_AUTH_EXCHG,"xxxxb",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,tx_ikemesg_exchg);
	}



  err = rhp_eap_sup_impl_recv(vpn,ikesa,rx_resp_ikemesg,rx_eap_pld,tx_req_ikemesg,vpn->eap.impl_ctx);

  if( err == RHP_EAP_STAT_PENDING ){

  	// This EAP message is forwarded to an external authentication service like a Rockhopper
  	// protected process or a supplicant app.

  	err = RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;
    rhp_vpn_hold(vpn);

		ikesa->busy_flag = 1;

  }else if( err == RHP_EAP_STAT_CONTINUE ){

  	err = RHP_STATUS_IKEV2_MESG_HANDLER_END;

  }else if( err == RHP_EAP_STAT_COMPLETED ){

		err = rhp_ikev2_rx_ike_auth_rep_eap_comp(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
		if( err ){
			goto error;
		}

		ikesa->eap.state = RHP_IKESA_EAP_STAT_I_COMP;

		_rhp_ikev2_eap_sup_set_my_ident(vpn);

		err = 0;

  }else{

    RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_RESP_PEND_IMPL_RECV_ERR,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);

  	err = -EINVAL;
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_RESP_PEND_RTRN,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
  return err;

error:

	if( delete_ikesa && ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_RESP_PEND_ERR,"xxxdE",vpn,ikesa,rx_resp_ikemesg,delete_ikesa,err);
	return err;
}

//
//  Call rhp_ikev2_rx_ike_auth_rep_eap_comp() to set an initiator's AUTH payload
//  after handling EAP Success message and setting state 'RHP_IKESA_EAP_STAT_I_COMP'.
int rhp_ikev2_rx_ike_eap_rep(rhp_ikev2_mesg* rx_resp_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err = -EINVAL;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_resp_ikemesg->get_exchange_type(rx_resp_ikemesg);
	u32 mesg_id;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_RESP,"xxLdGxLb",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_req_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

	if( exchange_type != RHP_PROTO_IKE_EXCHG_IKE_AUTH ){
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_RESP_NOT_IKE_AUTH_EXCHG,"xxLb",rx_resp_ikemesg,vpn,"PROTO_IKE_EXCHG",exchange_type);
		return 0;
	}

	if( vpn->eap.role != RHP_EAP_SUPPLICANT ){
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_RESP_NOT_AUTHENTICATOR,"xx",rx_resp_ikemesg,vpn);
  	err = 0;
  	goto error;
  }

	if( RHP_PROTO_IKE_HDR_INITIATOR(rx_resp_ikemesg->rx_pkt->app.ikeh->flag) ){
		err = RHP_STATUS_INVALID_MSG;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_RESP_INVALID_MESG1,"xx",rx_resp_ikemesg,vpn);
		goto error;
  }

  if( !rx_resp_ikemesg->decrypted ){
  	err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_RESP_NOT_DECRYPTED,"xx",rx_resp_ikemesg,vpn);
  	goto error;
  }


	if( my_ikesa_spi == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

	ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
	if( ikesa == NULL ){
		err = -ENOENT;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_RESP_NO_IKESA,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
		goto error;
	}

  if( ikesa->state != RHP_IKESA_STAT_I_AUTH_SENT ){
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_RESP_NOT_INTRESTED_STATE,"xxLdGLd",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state);
  	err = 0;
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_RESP_EAP_STAT,"xxLdGLd",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state,"EAP_STAT",ikesa->eap.state);

	mesg_id = rx_resp_ikemesg->get_mesg_id(rx_resp_ikemesg);

	if( mesg_id == 1 ){

		if( ikesa->eap.state != RHP_IKESA_EAP_STAT_DEFAULT ){
	  	err = RHP_STATUS_BAD_SA_STATE;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_RESP_BAD_EAP_STAT1,"xxLdGLd",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"EAP_STAT",ikesa->eap.state);
			goto error;
		}

		ikesa->eap.state = RHP_IKESA_EAP_STAT_I_PEND;
	}

	if( ikesa->eap.state == RHP_IKESA_EAP_STAT_DEFAULT ||
			ikesa->eap.state == RHP_IKESA_EAP_STAT_I_PEND ){

		err = _rhp_ikev2_rx_ike_eap_resp_pend(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);

	}else if( ikesa->eap.state == RHP_IKESA_EAP_STAT_I_COMP ){

		err = 0;
		goto error;

	}else{
  	err = RHP_STATUS_BAD_SA_STATE;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_RESP_BAD_EAP_STAT2,"xxLdGLd",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"EAP_STAT",ikesa->eap.state);
		goto error;
	}

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_EAP_RESP_RTRN,"xxxE",rx_resp_ikemesg,vpn,tx_req_ikemesg,err);
  return err;
}


extern int rhp_ui_http_eap_sup_ask_for_user_key(rhp_vpn* vpn,int my_ikesa_side,u8* my_ikesa_spi,
		int eap_method, // RHP_PROTO_EAP_TYPE_XXX
		u8* user_id,int user_id_len);

struct _rhp_eap_sup_ask_for_ukey_ctx {

	u8 tag[4]; // '#SAF'

	rhp_vpn_ref* vpn_ref;

	int my_ikesa_side;
	u8 my_ikesa_spi[RHP_PROTO_IKE_SPI_SIZE];

	int eap_method; // RHP_PROTO_EAP_TYPE_XXX

	u8* user_id;
	int user_id_len;
};
typedef struct _rhp_eap_sup_ask_for_ukey_ctx	rhp_eap_sup_ask_for_ukey_ctx;

#define RHP_EAP_SUP_ASK_FOR_USER_KEY_UI_MIN_INTERVAL	3 // (secs)

void rhp_eap_sup_ask_for_user_key_task(void* ctx)
{
	int err = -EINVAL;
	rhp_eap_sup_ask_for_ukey_ctx* task_ctx = (rhp_eap_sup_ask_for_ukey_ctx*)ctx;
	rhp_vpn* vpn = RHP_VPN_REF(task_ctx->vpn_ref);

	RHP_TRC(0,RHPTRCID_EAP_SUP_ASK_FOR_USER_KEY_TASK,"xxxLdGdpYx",ctx,task_ctx->vpn_ref,vpn,"IKE_SIDE",task_ctx->my_ikesa_side,task_ctx->my_ikesa_spi,task_ctx->eap_method,task_ctx->user_id_len,task_ctx->user_id,vpn->eap.ask_for_user_key_cb,vpn->eap.ask_usrkey_cb_ctx);

	RHP_LOCK(&(vpn->lock));

	if( !_rhp_atomic_read(&(vpn->is_active)) ){
		RHP_TRC(0,RHPTRCID_EAP_SUP_ASK_FOR_USER_KEY_TASK_VPN_NOT_ACTIVE,"xx",ctx,vpn);
		goto error;
	}

	err = rhp_ui_http_eap_sup_ask_for_user_key(vpn,
					task_ctx->my_ikesa_side,task_ctx->my_ikesa_spi,
					task_ctx->eap_method,
					task_ctx->user_id,task_ctx->user_id_len);
	if( err ){
		RHP_TRC(0,RHPTRCID_EAP_SUP_ASK_FOR_USER_KEY_TASK_ASK_FOR_USER_KEY_ERR,"xxE",ctx,vpn,err);
		goto error;
	}

error:
	RHP_UNLOCK(&(vpn->lock));
	rhp_vpn_unhold(task_ctx->vpn_ref);

	_rhp_free(task_ctx->user_id);
	_rhp_free(task_ctx);

	RHP_TRC(0,RHPTRCID_EAP_SUP_ASK_FOR_USER_KEY_TASK_RTRN,"xxE",ctx,vpn,err);
	return;
}


int rhp_eap_sup_ask_for_user_key(rhp_vpn* vpn,int my_ikesa_side,u8* my_ikesa_spi,
		int eap_method, // RHP_PROTO_EAP_TYPE_XXX
		u8* user_id,int user_id_len,
		RHP_EAP_SUP_ASK_FOR_USER_KEY_CB callback,void* cb_ctx)
{
	int err = -EINVAL;
	rhp_eap_sup_ask_for_ukey_ctx* task_ctx = NULL;

	RHP_TRC(0,RHPTRCID_EAP_SUP_ASK_FOR_USER_KEY,"xLdGdpYx",vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,eap_method,user_id_len,user_id,callback,cb_ctx);

	if( vpn->eap.ask_for_user_key_cb ){
		RHP_BUG("");
		return -EINVAL;
	}


	task_ctx = (rhp_eap_sup_ask_for_ukey_ctx*)_rhp_malloc(sizeof(rhp_eap_sup_ask_for_ukey_ctx));
	if( task_ctx == NULL ){
		RHP_BUG("");
		goto error;
	}

	memset(task_ctx,0,sizeof(rhp_eap_sup_ask_for_ukey_ctx));

	task_ctx->user_id = (u8*)_rhp_malloc(user_id_len);
	if( task_ctx->user_id == NULL ){
		RHP_BUG("");
		goto error;
	}

	task_ctx->tag[0] = '#';
	task_ctx->tag[1] = 'S';
	task_ctx->tag[2] = 'A';
	task_ctx->tag[3] = 'F';

	task_ctx->vpn_ref = rhp_vpn_hold_ref(vpn);

	memcpy(task_ctx->user_id,user_id,user_id_len);
	task_ctx->user_id_len = user_id_len;

	task_ctx->my_ikesa_side = my_ikesa_side;
	memcpy(task_ctx->my_ikesa_spi,my_ikesa_spi,RHP_PROTO_IKE_SPI_SIZE);
	task_ctx->eap_method = eap_method;

	vpn->eap.ask_for_user_key_cb = callback;
	vpn->eap.ask_usrkey_cb_ctx = cb_ctx;


	//
	// To avoid too frequent requests to UI(Web browser), waiting and switching context here.
	//
	err = rhp_timer_oneshot(rhp_eap_sup_ask_for_user_key_task,task_ctx,RHP_EAP_SUP_ASK_FOR_USER_KEY_UI_MIN_INTERVAL);
	if( err ){
		RHP_BUG("");
		goto error;
	}

	RHP_TRC(0,RHPTRCID_EAP_SUP_ASK_FOR_USER_KEY_RTRN,"x",vpn);
	return 0;

error:
	vpn->eap.ask_for_user_key_cb = NULL;
	vpn->eap.ask_usrkey_cb_ctx = NULL;

	if( task_ctx ){
		if( task_ctx->user_id ){
			_rhp_free(task_ctx->user_id);
		}
		if( task_ctx->vpn_ref ){
			rhp_vpn_unhold(task_ctx->vpn_ref);
		}
		_rhp_free(task_ctx);
	}

	RHP_TRC(0,RHPTRCID_EAP_SUP_ASK_FOR_USER_KEY_ERR,"xE",vpn,err);
	return err;
}

int rhp_eap_sup_ask_for_user_key_reply(rhp_vpn* vpn,
		int eap_method,u8* user_id,int user_id_len,u8* user_key,int user_key_len)
{
	rhp_ikesa* ikesa;

	RHP_TRC(0,RHPTRCID_EAP_SUP_ASK_FOR_USER_REPLY,"xdpp",vpn,eap_method,user_id_len,user_id,user_key_len,user_key);

	if(user_id == NULL || user_id_len < 1 || user_key == NULL || user_key_len < 1){
		RHP_BUG("");
		return -EINVAL;
	}

	ikesa = vpn->ikesa_list_head;
	if( ikesa == NULL ){
		RHP_TRC(0,RHPTRCID_EAP_SUP_ASK_FOR_USER_REPLY_NO_IKESA,"xdpp",vpn,eap_method,user_id_len,user_id,user_key_len,user_key);
		return -ENOENT;
	}

	if( ikesa->eap.state != RHP_IKESA_EAP_STAT_I_PEND ){
		RHP_BUG("");
		return -ENOENT;
	}

	if( vpn->eap.ask_for_user_key_cb == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	vpn->eap.ask_for_user_key_cb(vpn->eap.ask_usrkey_cb_ctx,vpn,ikesa->side,ikesa->init_spi,
			eap_method,user_id,user_id_len,user_key,user_key_len);

	vpn->eap.ask_for_user_key_cb = NULL;
	vpn->eap.ask_usrkey_cb_ctx = NULL;

	RHP_TRC(0,RHPTRCID_EAP_SUP_ASK_FOR_USER_REPLY_RTRN,"x",vpn);
	return 0;
}


struct _rhp_eap_method2str_label {
	int method;
	char* label;
};
typedef struct _rhp_eap_method2str_label rhp_eap_method2str_label;

static rhp_eap_method2str_label rhp_eap_method2str_labels[] = {
		{
				method: RHP_PROTO_EAP_TYPE_NONE,
				label:"none",
		},
		{
				method: RHP_PROTO_EAP_TYPE_IDENTITY,
				label:"identity",
		},
		{
				method: RHP_PROTO_EAP_TYPE_NOTIFICATION,
				label:"notification",
		},
		{
				method: RHP_PROTO_EAP_TYPE_NAK,
				label:"nak",
		},
		{
				method: RHP_PROTO_EAP_TYPE_MD5_CHALLENGE,
				label:"md5-challenge",
		},
		{
				method: RHP_PROTO_EAP_TYPE_ONE_TIME_PASSWORD,
				label:"otp",
		},
		{
				method: RHP_PROTO_EAP_TYPE_GENERIC_TOKEN_CARD,
				label:"gtc",
		},
		{
				method: RHP_PROTO_EAP_TYPE_EAP_TLS,
				label:"eap-tls",
		},
		{
				method: RHP_PROTO_EAP_TYPE_EAP_GSM_SIM,
				label:"eap-gsm-sim",
		},
		{
				method: RHP_PROTO_EAP_TYPE_EAP_TTLS,
				label:"eap-ttls",
		},
		{
				method: RHP_PROTO_EAP_TYPE_EAP_AKA,
				label:"eap-aka",
		},
		{
				method: RHP_PROTO_EAP_TYPE_PEAP,
				label:"peap",
		},
		{
				method: RHP_PROTO_EAP_TYPE_MS_CHAPV2,
				label:"eap-mschapv2",
		},
		{
				method: RHP_PROTO_EAP_TYPE_PEAPV0_MS_CHAPV2,
				label:"peap0-mschapv2",
		},
		{
				method: RHP_PROTO_EAP_TYPE_EAP_FAST,
				label:"eap-fast",
		},
		{
				method: RHP_PROTO_EAP_TYPE_EAP_PSK,
				label:"eap-psk",
		},
		{
				method: RHP_PROTO_EAP_TYPE_EAP_SAKE,
				label:"eap-sake",
		},
		{
				method: RHP_PROTO_EAP_TYPE_EAP_IKEV2,
				label:"eap-ikev2",
		},
		{
				method: RHP_PROTO_EAP_TYPE_EAP_AKA_PRIME,
				label:"eap-aka'",
		},
		{
				method: RHP_PROTO_EAP_TYPE_EAP_GPSK,
				label:"eap-gpsk",
		},
		{
				method: RHP_PROTO_EAP_TYPE_EAP_PWD,
				label:"eap-pwd",
		},
		{
				method: RHP_PROTO_EAP_TYPE_EAP_EKE_V1,
				label:"eap-eke",
		},
		{
				method: RHP_PROTO_EAP_TYPE_EAP_PT_EAP,
				label:"pt-eap",
		},
		{
				method: RHP_PROTO_EAP_TYPE_TEAP,
				label:"teap",
		},
		{
				method: RHP_PROTO_EAP_TYPE_PRIV_RADIUS,
				label:"radius",
		},
		{
				method: RHP_PROTO_EAP_TYPE_PRIV_IKEV1_XAUTH_PAP,
				label:"xauth-pap",
		},
		{-1,NULL},
};


char* rhp_eap_method2str_def(int method)
{
	int ret_len;
	char* ret = NULL;
	int i;

	for(i = 0; (rhp_eap_method2str_labels[i].method != -1) ; i++){

		if( rhp_eap_method2str_labels[i].method == method ){

			ret_len = strlen(rhp_eap_method2str_labels[i].label) + 1;
			ret = _rhp_malloc(ret_len);
			if( ret == NULL ){
				RHP_BUG("");
				goto error;
			}
			ret[ret_len - 1] = '\0';
			strcpy(ret,rhp_eap_method2str_labels[i].label);

			break;
		}
	}

error:
	RHP_TRC(0,RHPTRCID_EAP_METHOD2STR_DEF,"ds",method,ret);
	return ret;
}

int rhp_eap_str2method_def(char* method_name)
{
	int ret = RHP_PROTO_EAP_TYPE_NONE;
	int i;

	for(i = 0; (rhp_eap_method2str_labels[i].method != -1) ; i++){

		if( !strcmp(method_name,rhp_eap_method2str_labels[i].label) ){
			ret = rhp_eap_method2str_labels[i].method;
			break;
		}
	}

	RHP_TRC(0,RHPTRCID_EAP_STR2METHOD_DEF,"sd",method_name,ret);
	return ret;
}

int rhp_eap_identity_not_protected(int eap_method)
{
	RHP_TRC(0,RHPTRCID_EAP_IDENTITY_NOT_PROTECTED,"Ldd","EAP_TYPE",eap_method,rhp_gcfg_radius_mschapv2_eap_identity_not_protected);
	if( rhp_gcfg_radius_mschapv2_eap_identity_not_protected &&
	    eap_method == RHP_PROTO_EAP_TYPE_MS_CHAPV2){
		return 1;
	}
	return 0;
}


int rhp_eap_init()
{
	int err = -EINVAL;

	err = rhp_eap_auth_impl_init();
	if( err ){
		RHP_BUG("");
		return err;
	}

	err = rhp_eap_sup_impl_init();
	if( err ){
		RHP_BUG("");
		return err;
	}

	RHP_TRC(0,RHPTRCID_EAP_INIT,"");
	return 0;
}

int rhp_eap_cleanup()
{
	int err = -EINVAL;

	err = rhp_eap_auth_impl_cleanup();
	if( err ){
		RHP_BUG("");
		goto error;
	}

	err = rhp_eap_sup_impl_cleanup();
	if( err ){
		RHP_BUG("");
		goto error;
	}

error:
	RHP_TRC(0,RHPTRCID_EAP_CLEANUP,"E",err);
	return err;
}

