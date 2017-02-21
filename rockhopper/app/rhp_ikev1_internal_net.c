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
#include "rhp_packet.h"
#include "rhp_config.h"
#include "rhp_ikev2_mesg.h"
#include "rhp_vpn.h"
#include "rhp_ikev2.h"
#include "rhp_forward.h"



extern int rhp_ikev2_internal_net_v6_linklocal_srch(rhp_ip_addr* ipaddr,void* ctx);

extern int rhp_ikev2_internal_net_srch_n_info_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx);

extern void rhp_ikev2_internal_net_clear_src_ctx(rhp_intr_net_srch_plds_ctx* s_pld_ctx);

extern int rhp_ikev2_rx_internal_net_info_req_update_peer_addrs(
		rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_vpn_realm* rlm,
		rhp_ikev2_mesg* rx_req_ikemesg,rhp_intr_net_srch_plds_ctx* s_pld_ctx,
		int* updated_r);



static int _rhp_ikev1_new_pkt_internal_net_r(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_proto_ike* ikeh;
  rhp_vpn_realm* rlm = NULL;
	rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_INTERNAL_NET_R,"xxxxddd",vpn,ikesa,rx_ikemesg,tx_ikemesg,vpn->peer_is_rockhopper,vpn->nhrp.role,vpn->nhrp.dmvpn_shortcut);

  ikeh = rx_ikemesg->rx_pkt->app.ikeh;

  if( !(vpn->peer_is_rockhopper) ){
    RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_INTERNAL_NET_R_PEER_IS_NOT_RHP,"xxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg);
    goto ignore;
  }

  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  rlm = vpn->rlm;
  if( rlm == NULL ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }


  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
    err = -EINVAL;
    RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_INTERNAL_NET_R_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg);
    goto error_l;
  }

	if( rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_STATIC &&
			(vpn->nhrp.role == RHP_NHRP_SERVICE_SERVER || vpn->nhrp.role == RHP_NHRP_SERVICE_NONE) &&
			!vpn->nhrp.dmvpn_shortcut ){

		rhp_ip_addr_list* addr_lst = rlm->internal_ifc->addrs;
		while( addr_lst ){

			if( !rhp_ip_addr_null(&(addr_lst->ip_addr)) ){

				int ip_addr_len = 0;
				u16 msg_type = 0;

				if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_N,&ikepayload) ){
					RHP_BUG("");
					goto error_l;
				}

				tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

				ikepayload->ext.n->set_protocol_id(ikepayload,0);

				if( addr_lst->ip_addr.addr_family == AF_INET ){

					msg_type = RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_IP4_ADDRESS;
					ip_addr_len = 4;

				}else if( addr_lst->ip_addr.addr_family == AF_INET6 ){

					msg_type = RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_IP6_ADDRESS;
					ip_addr_len = 16;
				}

				ikepayload->ext.n->set_message_type(ikepayload,msg_type);

				if( ikepayload->ext.n->set_data(ikepayload,ip_addr_len,addr_lst->ip_addr.addr.raw) ){
					RHP_BUG("");
					goto error_l;
				}
			}

			addr_lst = addr_lst->next;
		}
	}

	if( rlm->internal_ifc->ifc ){

		rhp_ifc_entry* v_ifc = rlm->internal_ifc->ifc;

		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error_l;
		}

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);

		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_MAC_ADDRESS);

		ikepayload->set_non_critical(ikepayload,1);

		RHP_LOCK(&(v_ifc->lock));
		{
			if( ikepayload->ext.n->set_data(ikepayload,6,v_ifc->mac) ){

				RHP_BUG("");

				RHP_UNLOCK(&(v_ifc->lock));
				goto error_l;
			}
		}
		RHP_UNLOCK(&(v_ifc->lock));
	}

	if( rlm->is_mesh_node ){

		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error_l;
		}

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);

		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_MESH_NODE);

	}else	if( rlm->is_access_point ){

		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error_l;
		}

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);

		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_ACCESSPOINT);
	}

  RHP_UNLOCK(&(rlm->lock));

ignore:
  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_INTERNAL_NET_R_RTRN,"xxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg);
	return 0;

error_l:
	RHP_UNLOCK(&(rlm->lock));
error:

	RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_INTERNAL_NET_R_ERR,"xxxxE",vpn,ikesa,rx_ikemesg,tx_ikemesg,err);
  return err;
}

static int _rhp_ikev1_rx_internal_net_r_quick_1(rhp_ikev2_mesg* rx_ikemesg,rhp_vpn* vpn,
		rhp_ikesa* ikesa,rhp_ikev2_mesg* tx_ikemesg)
{
  RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_R_QUICK_1,"xxxx",rx_ikemesg,vpn,ikesa,tx_ikemesg);

  if( !rx_ikemesg->decrypted ){
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_R_QUICK_1_NOT_DECRYPTED,"xxx",rx_ikemesg,vpn,ikesa);
  	goto error;
  }

  _rhp_ikev1_new_pkt_internal_net_r(vpn,ikesa,rx_ikemesg,tx_ikemesg);

  vpn->v1.internal_addr_flag |= RHP_IKEV1_ITNL_ADDR_FLAG_TX;

error:
	RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_R_QUICK_1_RTRN,"xxx",rx_ikemesg,vpn,tx_ikemesg);
	return 0;
}


static int _rhp_ikev1_rx_internal_net_i_tx_my_addrs(
		rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_vpn_realm* rlm,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg,
		rhp_intr_net_srch_plds_ctx* s_pld_ctx)
{
  int err = RHP_STATUS_INVALID_MSG;
	rhp_ip_addr* rx_mode_cfg_internal_addrs = vpn->v1.rx_mode_cfg_internal_addrs;
	rhp_ip_addr_list* my_addr = NULL;
	rhp_ip_addr_list* intr_addrs = NULL;
	int free_intr_addrs_tmp = 0;

	RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_I_TX_MY_ADDRS,"xxxxxxdd",vpn,ikesa,rlm,rx_ikemesg,tx_ikemesg,s_pld_ctx,vpn->nhrp.role,vpn->nhrp.dmvpn_shortcut);

	if( rx_mode_cfg_internal_addrs ){
		rhp_ip_addr_dump("vpn->v1.rx_mode_cfg_internal_addrs[0]",&(rx_mode_cfg_internal_addrs[0])); // IPv4
		rhp_ip_addr_dump("vpn->v1.rx_mode_cfg_internal_addrs[1]",&(rx_mode_cfg_internal_addrs[1])); // IPv6
	}

	if( (vpn->nhrp.role == RHP_NHRP_SERVICE_SERVER ||
			 vpn->nhrp.role == RHP_NHRP_SERVICE_NONE) &&
			!vpn->nhrp.dmvpn_shortcut ){

		if( rx_mode_cfg_internal_addrs &&
				(!rhp_ip_addr_null(&(rx_mode_cfg_internal_addrs[0])) ||
				 !rhp_ip_addr_null(&(rx_mode_cfg_internal_addrs[1]))) ){

			rhp_ip_addr* my_linklocal_addr;

			free_intr_addrs_tmp = 1;

			if( !rhp_ip_addr_null(&(rx_mode_cfg_internal_addrs[0])) ){

				my_addr = rhp_ip_dup_addr_list(&(rx_mode_cfg_internal_addrs[0]));
				if( my_addr == NULL ){
					RHP_BUG("");
					goto error;
				}

				my_addr->next = intr_addrs;
				intr_addrs = my_addr;
			}

			if( !rhp_ip_addr_null(&(rx_mode_cfg_internal_addrs[1])) ){

				my_addr = rhp_ip_dup_addr_list(&(rx_mode_cfg_internal_addrs[1]));
				if( my_addr == NULL ){
					RHP_BUG("");
					goto error;
				}

				my_addr->next = intr_addrs;
				intr_addrs = my_addr;
			}

			my_linklocal_addr = rhp_ip_search_addr_list(rlm->internal_ifc->addrs,
					rhp_ikev2_internal_net_v6_linklocal_srch,NULL);
			if( my_linklocal_addr ){

				my_addr = rhp_ip_dup_addr_list(my_linklocal_addr);
				if( my_addr == NULL ){
					RHP_BUG("");
					goto error;
				}

				my_addr->next = intr_addrs;
				intr_addrs = my_addr;
			}

		}else{

			intr_addrs = rlm->internal_ifc->addrs;
		}

		my_addr = intr_addrs;
		while( my_addr ){

			rhp_ip_addr_dump("my_addr",&(my_addr->ip_addr));

			if( !rhp_ip_addr_null(&(my_addr->ip_addr)) ){

				rhp_ikev2_payload* ikepayload = NULL;
				int addr_len = 0;
				u16 msg_type = 0;

				if( my_addr->ip_addr.addr_family == AF_INET ){
					msg_type = RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_IP4_ADDRESS;
					addr_len = 4;
				}else if( my_addr->ip_addr.addr_family == AF_INET6 ){
					msg_type = RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_IP6_ADDRESS;
					addr_len = 16;
				}else{
					RHP_BUG("%d",my_addr->ip_addr.addr_family);
					goto skip;
				}


				if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_N,&ikepayload) ){
					RHP_BUG("");
					goto error;
				}

				tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

				ikepayload->ext.n->set_protocol_id(ikepayload,0);

				ikepayload->ext.n->set_message_type(ikepayload,msg_type);

				if( ikepayload->ext.n->set_data(ikepayload,addr_len,my_addr->ip_addr.addr.raw) ){
					RHP_BUG("");
					goto error;
				}

			}else{

				RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_I_TX_MY_ADDRS_NULL_ADDR,"xxxx",vpn,ikesa,rx_ikemesg,my_addr);
			}

skip:
			my_addr = my_addr->next;
		}
	}


	if( rlm->internal_ifc->ifc ){

		rhp_ifc_entry* v_ifc = rlm->internal_ifc->ifc;
		rhp_ikev2_payload* ikepayload = NULL;

		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);

		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_MAC_ADDRESS);

		RHP_LOCK(&(v_ifc->lock));
		{
			if( ikepayload->ext.n->set_data(ikepayload,6,v_ifc->mac) ){

				RHP_BUG("");

				RHP_UNLOCK(&(v_ifc->lock));
				goto error;
			}
		}
		RHP_UNLOCK(&(v_ifc->lock));
	}

	if( free_intr_addrs_tmp ){

		my_addr = intr_addrs;
		while( my_addr ){
			rhp_ip_addr_list* my_addr_n = my_addr->next;
			_rhp_free(my_addr);
			my_addr = my_addr_n;
		}
	}

	RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_I_TX_MY_ADDRS_RTRN,"xxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg);
	return 0;

error:

	if( free_intr_addrs_tmp ){

		my_addr = intr_addrs;
		while( my_addr ){
			rhp_ip_addr_list* my_addr_n = my_addr->next;
			_rhp_free(my_addr);
			my_addr = my_addr_n;
		}
	}

	RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_I_TX_MY_ADDRS_ERR,"xxxxE",vpn,ikesa,rx_ikemesg,tx_ikemesg,err);
	return err;
}

static int _rhp_ikev1_rx_internal_net_i_quick_2(rhp_ikev2_mesg* rx_ikemesg,rhp_vpn* vpn,
		rhp_ikesa* ikesa,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_vpn_realm* rlm = NULL;
	rhp_intr_net_srch_plds_ctx s_pld_ctx;
	rhp_ip_addr_list* new_peer_addr = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_I_QUICK_2,"xxxx",rx_ikemesg,vpn,ikesa,tx_ikemesg);

	memset(&s_pld_ctx,0,sizeof(rhp_intr_net_srch_plds_ctx));


  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  if( !rx_ikemesg->decrypted ){
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_I_QUICK_2_NOT_DECRYPTED,"xxx",rx_ikemesg,vpn,ikesa);
  	err = 0;
  	goto ignore;
  }

  if( !(vpn->peer_is_rockhopper) ){
  	RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_I_QUICK_2_PEER_IS_NOT_RHP,"xxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg);
  	err = 0;
  	goto ignore;
  }


  RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_I_QUICK_2_VPN,"xxxxdLddd",vpn,ikesa,rx_ikemesg,tx_ikemesg,vpn->internal_net_info.static_peer_addr,"VPN_ENCAP",vpn->internal_net_info.encap_mode_c,vpn->peer_is_rockhopper,vpn->internal_net_info.static_peer_addr);


	s_pld_ctx.vpn = vpn;
	s_pld_ctx.ikesa = ikesa;

	{
		s_pld_ctx.dup_flag = 0;
		u16 intr_net_mesg_ids[6] = { RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_IP4_ADDRESS,
																 RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_IP6_ADDRESS,
																 RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_MAC_ADDRESS,
																 RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_ACCESSPOINT,
																 RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_MESH_NODE,
																 RHP_PROTO_IKE_NOTIFY_RESERVED};

		err = rx_ikemesg->search_payloads(rx_ikemesg,0,
						rhp_ikev2_mesg_srch_cond_n_mesg_ids,intr_net_mesg_ids,
						rhp_ikev2_internal_net_srch_n_info_cb,&s_pld_ctx);

		if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
		  RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_I_QUICK_2_NTFY_ERR,"xxxxE",vpn,ikesa,rx_ikemesg,tx_ikemesg,err);
			goto error;
		}
		err = 0;

		new_peer_addr = s_pld_ctx.peer_addrs;
		while( new_peer_addr ){
			rhp_ip_addr_dump("_rhp_ikev1_rx_internal_net_i_quick_2.new_peer_addr",&(new_peer_addr->ip_addr));
			new_peer_addr = new_peer_addr->next;
		}
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_I_QUICK_2_PEER_MAC,"xxxxM",vpn,ikesa,rx_ikemesg,tx_ikemesg,s_pld_ctx.peer_mac);
	}


  rlm = vpn->rlm;
  if( rlm == NULL ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
  	RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_I_QUICK_2_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg);
    err = -EINVAL;
    goto error_l;
  }

  if( s_pld_ctx.peer_is_access_point && rlm->is_access_point ){ // Avoiding broadcast storm and Dup packets...

	  RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_I_QUICK_2_PEER_ALSO_ACCESS_POINT,"xxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg);

		RHP_LOG_E(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_INTERNAL_NET_REP_PEER_IS_ALSO_HUB,"KVP",rx_ikemesg,vpn,ikesa);

		ikesa->timers->schedule_delete(vpn,ikesa,0);

		err = RHP_STATUS_PEER_IS_ALSO_ACCESSPOINT;
		goto error_l;

  }else if( (s_pld_ctx.peer_is_mesh_node && rlm->is_access_point) ||
  					(s_pld_ctx.peer_is_access_point && rlm->is_mesh_node) ){ // Avoiding broadcast storm and Dup packets...

	  RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_I_QUICK_2_PEER_MESH_NODE,"xxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg);

		RHP_LOG_E(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_INTERNAL_NET_REP_PEER_IS_MESH_NODE,"KVP",rx_ikemesg,vpn,ikesa);

		ikesa->timers->schedule_delete(vpn,ikesa,0);

		err = RHP_STATUS_PEER_IS_MESH_NODE;
		goto error_l;

  }else if( !(s_pld_ctx.peer_is_access_point) &&
  					vpn->cfg_peer && vpn->cfg_peer->is_access_point ){

	  RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_I_QUICK_2_PEER_PEER_IS_NOT_EXPECTED_ACCESS_POINT,"xxxxdd",vpn,ikesa,rx_ikemesg,tx_ikemesg,s_pld_ctx.peer_is_access_point,vpn->cfg_peer->is_access_point);

  }else if( s_pld_ctx.peer_is_access_point &&
  					vpn->cfg_peer && !(vpn->cfg_peer->is_access_point) ){

	  RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_I_QUICK_2_PEER_PEER_IS_ACCESS_POINT,"xxxxxdd",vpn,ikesa,rx_ikemesg,tx_ikemesg,rlm->access_point_peer,s_pld_ctx.peer_is_access_point,vpn->cfg_peer->is_access_point);

	  if( (rlm->access_point_peer == NULL) && (rlm->access_point_peer_vpn_ref == NULL) ){

		  RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_I_QUICK_2_SET_ACCESSPOINT,"xxxx",vpn,ikesa,rx_ikemesg,rlm);

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_INTERNAL_NET_REP_PEER_IS_HUB,"KVP",rx_ikemesg,vpn,ikesa);

	  	vpn->cfg_peer->is_access_point = 1;

	  	rlm->set_access_point(rlm,vpn);

	  }else{

		  RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_I_QUICK_2_NOT_SET_ACCESSPOINT,"xxxxxx",vpn,ikesa,rx_ikemesg,rlm,rlm->access_point_peer,RHP_VPN_REF(rlm->access_point_peer_vpn_ref));

	  	if( rlm->access_point_peer ){

	  		rhp_ikev2_id_dump("access_point_peer_cfg",&(rlm->access_point_peer->id));
	  		rhp_ip_addr_dump("primary_addr",&(rlm->access_point_peer->primary_addr));
	  		rhp_ip_addr_dump("secondary_addr",&(rlm->access_point_peer->secondary_addr));

	  		RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_INTERNAL_NET_REP_STATIC_PEER_IS_CONFIGURED,"KVP",rx_ikemesg,vpn,ikesa);
	  	}
	  }
  }


  if( s_pld_ctx.peer_addrs &&
  		!(vpn->internal_net_info.static_peer_addr) ){

		rhp_ip_addr_list* cur_peer_addr = vpn->internal_net_info.peer_addrs;
		int n = 0;

		while( cur_peer_addr ){

			rhp_ip_addr_list* cur_peer_addr_n = cur_peer_addr->next;

			rhp_ip_addr_dump("_rhp_ikev1_rx_internal_net_i_quick_2.cur_peer_addr",&(cur_peer_addr->ip_addr));

			rhp_vpn_delete_by_peer_internal_addr(&(cur_peer_addr->ip_addr),vpn);
			_rhp_free(cur_peer_addr);
			n++;

			cur_peer_addr = cur_peer_addr_n;
		}
		vpn->internal_net_info.peer_addrs = NULL;

		if( n ){
			rhp_vpn_internal_route_delete(vpn,rlm);
		}


		n = 0;
		new_peer_addr = s_pld_ctx.peer_addrs;
		while( new_peer_addr ){

			if( !rhp_ip_addr_null(&(new_peer_addr->ip_addr)) ){

				rhp_vpn* col_vpn;
				rhp_vpn_ref* col_vpn_ref;

				col_vpn_ref = rhp_vpn_get_by_peer_internal_addr(
												vpn->vpn_realm_id,&(new_peer_addr->ip_addr));
				col_vpn = RHP_VPN_REF(col_vpn_ref);
				if( col_vpn == NULL ){

					rhp_ip_addr_list* peer_addr = rhp_ip_dup_addr_list(&(new_peer_addr->ip_addr));

					if( peer_addr == NULL ){
						RHP_BUG("");
						err = -ENOMEM;
						goto error_l;
					}

					err = rhp_vpn_put_by_peer_internal_addr(&(new_peer_addr->ip_addr),vpn);
					if( err ){
						RHP_BUG("%d",err);
						goto error_l;
					}

					if( peer_addr->ip_addr.addr_family != AF_INET &&
							peer_addr->ip_addr.addr_family != AF_INET6 ){
						RHP_BUG("%d",peer_addr->ip_addr.addr_family);
					}

					peer_addr->next = vpn->internal_net_info.peer_addrs;
					vpn->internal_net_info.peer_addrs = peer_addr;

					n++;

				}else{

					RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_I_QUICK_2_ADDR_COLLISION,"xxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg);

					rhp_vpn_unhold(col_vpn);
				}
			}

			new_peer_addr = new_peer_addr->next;
		}

		if( n ){
			rhp_vpn_internal_route_update(vpn);
		}
  }

	if( !vpn->internal_net_info.peer_addrs_notified ){

		if( !_rhp_mac_addr_null(s_pld_ctx.peer_mac)	){

			memcpy(vpn->internal_net_info.exchg_peer_mac,s_pld_ctx.peer_mac,6);
		}
	}


	err = _rhp_ikev1_rx_internal_net_i_tx_my_addrs(vpn,ikesa,rlm,
					rx_ikemesg,tx_ikemesg,&s_pld_ctx);
	if( err ){
		RHP_BUG("%d",err);
		goto error_l;
	}

	if( !vpn->internal_net_info.peer_addrs_notified &&
			(s_pld_ctx.peer_addrs || !_rhp_mac_addr_null(s_pld_ctx.peer_mac)) ){

		vpn->internal_net_info.peer_addrs_notified = 1;
	}

	vpn->v1.internal_addr_flag |= (RHP_IKEV1_ITNL_ADDR_FLAG_TX | RHP_IKEV1_ITNL_ADDR_FLAG_RX);


error_l:
	RHP_UNLOCK(&(rlm->lock));
error:
ignore:

	rhp_ikev2_internal_net_clear_src_ctx(&s_pld_ctx);

	RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_I_QUICK_2_RTRN,"xxxMdx",rx_ikemesg,vpn,tx_ikemesg,vpn->internal_net_info.exchg_peer_mac,vpn->internal_net_info.peer_addrs_notified,vpn->internal_net_info.peer_addrs);
  return 0;
}


static int _rhp_ikev1_rx_internal_net_r_quick_3(rhp_ikev2_mesg* rx_ikemesg,
		rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
	rhp_intr_net_srch_plds_ctx s_pld_ctx;
	int peer_addrs_updated = 0;
	u8* peer_mac = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_R_QUICK_3,"xxxxdd",vpn,ikesa,rx_ikemesg,tx_ikemesg,vpn->peer_is_rockhopper,vpn->internal_net_info.peer_addrs_notified);

	memset(&s_pld_ctx,0,sizeof(rhp_intr_net_srch_plds_ctx));

  if( !(vpn->peer_is_rockhopper) ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_R_QUICK_3_PEER_IS_NOT_RHP,"xxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg);
  	return 0;
  }


  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_R_QUICK_3_VPN,"xxxxdLd",vpn,ikesa,rx_ikemesg,tx_ikemesg,vpn->internal_net_info.static_peer_addr,"VPN_ENCAP",vpn->internal_net_info.encap_mode_c);


	s_pld_ctx.vpn = vpn;
	s_pld_ctx.ikesa = ikesa;

	{
		rhp_ip_addr_list* peer_addr;

		s_pld_ctx.dup_flag = 0;
		u16 intr_net_mesg_ids[4] = { RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_IP4_ADDRESS,
																 RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_IP6_ADDRESS,
																 RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_MAC_ADDRESS,
																 RHP_PROTO_IKE_NOTIFY_RESERVED};

		err = rx_ikemesg->search_payloads(rx_ikemesg,0,
						rhp_ikev2_mesg_srch_cond_n_mesg_ids,intr_net_mesg_ids,
						rhp_ikev2_internal_net_srch_n_info_cb,&s_pld_ctx);

		if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
		  RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_R_QUICK_3_NTFY_ERR,"xxxxE",vpn,ikesa,rx_ikemesg,tx_ikemesg,err);
			goto error;
		}else if( err == -ENOENT ){
		  RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_R_QUICK_3_NTFY_IGNORED,"xxxxE",vpn,ikesa,rx_ikemesg,tx_ikemesg,err);
			err = 0;
			goto ignore;
		}

		peer_addr = s_pld_ctx.peer_addrs;
		while( peer_addr ){
			rhp_ip_addr_dump("_rhp_ikev1_rx_internal_net_r_quick_3.new_peer_addr",&(peer_addr->ip_addr));
			peer_addr = peer_addr->next;
		}
		RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_R_QUICK_3_NTFY_PEER_MAC,"xxxxM",vpn,ikesa,rx_ikemesg,tx_ikemesg,s_pld_ctx.peer_mac);
	}

  if( s_pld_ctx.peer_addrs &&
  		!(vpn->internal_net_info.static_peer_addr) ){

    rhp_vpn_realm* rlm = vpn->rlm;
    if( rlm == NULL ){
      err = -EINVAL;
      RHP_BUG("");
			goto error;
    }

    RHP_LOCK(&(rlm->lock));

    if( !_rhp_atomic_read(&(rlm->is_active)) ){

    	RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_R_QUICK_3_UPDATE_PEER_ADDRS_RLM_NOT_ACTIVE,"xxxx",rlm,vpn,ikesa,rx_ikemesg);
      err = -EINVAL;

    	RHP_UNLOCK(&(rlm->lock));
			goto error;
    }

  	err = rhp_ikev2_rx_internal_net_info_req_update_peer_addrs(vpn,ikesa,rlm,
  					rx_ikemesg,&s_pld_ctx,&peer_addrs_updated);
  	if( err ){

  		RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_R_QUICK_3_UPDATE_PEER_ADDRS_ERR,"xxxxE",vpn,ikesa,rx_ikemesg,tx_ikemesg,err);

    	RHP_UNLOCK(&(rlm->lock));
		  goto error;
  	}

  	RHP_UNLOCK(&(rlm->lock));
  }


	if( !vpn->internal_net_info.peer_addrs_notified ){

		//
		// A peer's internal MAC can't be updated.
		//

		if( !_rhp_mac_addr_null(s_pld_ctx.peer_mac) ){

			rhp_vpn_ref* col_vpn_ref
				= rhp_vpn_get_by_peer_internal_mac(vpn->vpn_realm_id,s_pld_ctx.peer_mac);
			rhp_vpn* col_vpn = RHP_VPN_REF(col_vpn_ref);
			if( col_vpn && col_vpn != vpn ){

				RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_R_QUICK_3_MAC_COLLISION,"xxxxM",vpn,col_vpn,ikesa,rx_ikemesg,s_pld_ctx.peer_mac);
				RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_INTERNAL_NET_INFO_REQ_MAC_COLLISION,"KPVVM",rx_ikemesg,ikesa,vpn,col_vpn,s_pld_ctx.peer_mac);

			}else{

				err = rhp_vpn_put_by_peer_internal_mac(s_pld_ctx.peer_mac,vpn);
				if( err ){
					RHP_BUG("%d",err);
					goto error;
				}

				memcpy(vpn->internal_net_info.exchg_peer_mac,s_pld_ctx.peer_mac,6);

				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_INTERNAL_NET_PEER_MAC_UPDATED,"KVPM",rx_ikemesg,vpn,ikesa,s_pld_ctx.peer_mac);

				peer_mac = s_pld_ctx.peer_mac;
			}

			if( col_vpn ){
				rhp_vpn_unhold(col_vpn);
			}
		}

		peer_mac = s_pld_ctx.peer_mac;

	}else{

		peer_mac = vpn->internal_net_info.exchg_peer_mac;
	}


	if( peer_addrs_updated ){

		if( vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_IPIP ||
				vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_GRE ){

			err = rhp_bridge_static_cache_reset_for_vpn(vpn->vpn_realm_id,vpn,
							vpn->internal_net_info.dummy_peer_mac,
							vpn->internal_net_info.peer_addrs,
							RHP_BRIDGE_SCACHE_DUMMY);
			if( err){
				RHP_BUG("%d",err);
				goto error;
			}

		}else if( vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_ETHERIP ){

			if( !_rhp_mac_addr_null(peer_mac) ){

				err = rhp_bridge_static_cache_reset_for_vpn(vpn->vpn_realm_id,vpn,
								peer_mac,vpn->internal_net_info.peer_addrs,
								RHP_BRIDGE_SCACHE_IKEV2_EXCHG);
				if( err ){
					RHP_BUG("%d",err);
					goto error;
				}
				err = 0;

			}else{

				RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_R_QUICK_3_PEER_MAC_UNKNOWN,"xxxdMM",vpn,ikesa,rx_ikemesg,vpn->internal_net_info.peer_addrs_notified,s_pld_ctx.peer_mac,vpn->internal_net_info.exchg_peer_mac);
			}
		}


		rhp_vpn_internal_route_update(vpn);
  }


	if( !vpn->internal_net_info.peer_addrs_notified &&
			(s_pld_ctx.peer_addrs || !_rhp_mac_addr_null(s_pld_ctx.peer_mac)) ){

		vpn->internal_net_info.peer_addrs_notified = 1;
	}


	rhp_bridge_cache_flush_by_vpn(vpn);


ignore:
	rhp_ikev2_internal_net_clear_src_ctx(&s_pld_ctx);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_R_QUICK_3_RTRN,"xxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg);
  return 0;

error:
	rhp_ikev2_internal_net_clear_src_ctx(&s_pld_ctx);

	RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_R_QUICK_3_ERR,"xxxxE",vpn,ikesa,rx_ikemesg,tx_ikemesg,err);
	return err;
}


int rhp_ikev1_rx_internal_net(rhp_ikev2_mesg* rx_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_ikemesg)
{
	int err;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_ikemesg->get_exchange_type(rx_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET,"xxLdGxLbx",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_ikemesg,"PROTO_IKE_EXCHG",exchange_type,vpn->v1.internal_addr_flag);

  if( !rx_ikemesg->decrypted ){
  	err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_NOT_DECRYPTED,"xxLdG",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
  	goto error;
  }

	if( exchange_type == RHP_PROTO_IKEV1_EXCHG_QUICK ){

		if( my_ikesa_spi == NULL ){
	    RHP_BUG("");
	    err = -EINVAL;
	    goto error;
	  }

		ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
		if( ikesa == NULL ){
			err = -ENOENT;
		  RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_NO_IKESA,"xxLdG",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}

		if( vpn->origin_side == RHP_IKE_INITIATOR ){

		  if( !vpn->v1.internal_addr_flag ){

		  	err = _rhp_ikev1_rx_internal_net_i_quick_2(rx_ikemesg,vpn,ikesa,tx_ikemesg);

		  }else{
			  RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_NOT_INTERESTED_1,"xxxLdG",rx_ikemesg,vpn,ikesa,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
		  	err = 0;
		  }

		}else{ // Responder

		  if( !vpn->v1.internal_addr_flag ){

		  	err = _rhp_ikev1_rx_internal_net_r_quick_1(rx_ikemesg,vpn,ikesa,tx_ikemesg);

		  }else if( !(vpn->v1.internal_addr_flag & RHP_IKEV1_ITNL_ADDR_FLAG_RX) ){

		  	err = _rhp_ikev1_rx_internal_net_r_quick_3(rx_ikemesg,vpn,ikesa,tx_ikemesg);

		  }else{
			  RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_NOT_INTERESTED_2,"xxxLdG",rx_ikemesg,vpn,ikesa,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
		  	err = 0;
		  }
		}

	}else{
		err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_NOT_INTERESTED_3,"xxLdG",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
	}

error:
	RHP_TRC(0,RHPTRCID_IKEV1_RX_INTERNAL_NET_RTRN,"xxxE",rx_ikemesg,vpn,tx_ikemesg,err);
  return err;
}

