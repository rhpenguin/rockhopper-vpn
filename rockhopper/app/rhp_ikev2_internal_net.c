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
#include "rhp_packet.h"
#include "rhp_config.h"
#include "rhp_ikev2_mesg.h"
#include "rhp_vpn.h"
#include "rhp_ikev2.h"
#include "rhp_forward.h"


static rhp_mutex_t _rhp_ikev2_itnl_net_lock;



void rhp_ikev2_internal_net_clear_src_ctx(rhp_intr_net_srch_plds_ctx* s_pld_ctx)
{
	rhp_ip_addr_list* peer_addr = s_pld_ctx->peer_addrs;

	while( peer_addr ){

		rhp_ip_addr_list* peer_addr_n = peer_addr->next;
		_rhp_free(peer_addr);
		peer_addr = peer_addr_n;
	}

	return;
}

int rhp_ikev2_internal_net_srch_n_info_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_intr_net_srch_plds_ctx* s_pld_ctx = (rhp_intr_net_srch_plds_ctx*)ctx;
	rhp_ikev2_n_payload* n_payload = (rhp_ikev2_n_payload*)payload->ext.n;
	u16 notify_mesg_type;

  RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_SRCH_N_INFO_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

	if( n_payload == NULL ){
		RHP_BUG("");
  	return -EINVAL;
  }

	notify_mesg_type = n_payload->get_message_type(payload);

	if( s_pld_ctx->peer_addrs_num < rhp_gcfg_internal_net_max_peer_addrs &&
			(notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_IP4_ADDRESS ||
			 (!rhp_gcfg_ipv6_disabled && notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_IP6_ADDRESS)) ){

 	 	int rx_ip_len = payload->ext.n->get_data_len(payload);
  	u8* rx_ip = payload->ext.n->get_data(payload);
  	rhp_ip_addr_list* rx_ip_lst;

		rx_ip_lst = (rhp_ip_addr_list*)_rhp_malloc(sizeof(rhp_ip_addr_list));
		if( rx_ip_lst ){

			memset(rx_ip_lst,0,sizeof(rhp_ip_addr_list));
			rx_ip_lst->ip_addr.addr_family = AF_UNSPEC;

	  	if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_IP4_ADDRESS ){

	    	if( rx_ip_len == 4 ){

	    		rx_ip_lst->ip_addr.addr_family = AF_INET;
					memcpy(rx_ip_lst->ip_addr.addr.raw,rx_ip,rx_ip_len);

					RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_INTERNAL_NET_INFO_INTERNAL_PEER_IPV4,"KVPA",rx_ikemesg,s_pld_ctx->vpn,s_pld_ctx->ikesa,&(rx_ip_lst->ip_addr));
	    	}

				RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_SRCH_N_INFO_CB_IPV4_ADDR,"x4",rx_ikemesg,*((u32*)rx_ip));

	  	}else if(notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_IP6_ADDRESS ){

	    	if( rx_ip_len == 16 ){

	    		rx_ip_lst->ip_addr.addr_family = AF_INET6;
					memcpy(rx_ip_lst->ip_addr.addr.raw,rx_ip,rx_ip_len);

					RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_INTERNAL_NET_INFO_INTERNAL_PEER_IPV6,"KVPA",rx_ikemesg,s_pld_ctx->vpn,s_pld_ctx->ikesa,&(rx_ip_lst->ip_addr));
	    	}

				RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_SRCH_N_INFO_CB_IPV6_ADDR,"x6",rx_ikemesg,rx_ip);
	  	}

  		if( rx_ip_lst->ip_addr.addr_family != AF_UNSPEC ){

  			rx_ip_lst->ip_addr.tag = RHP_IPADDR_TAG_IKEV2_EXCHG;

				rx_ip_lst->next = s_pld_ctx->peer_addrs;
				s_pld_ctx->peer_addrs = rx_ip_lst;

				s_pld_ctx->peer_addrs_num++;

			}else{

				_rhp_free(rx_ip_lst);
			}

		}else{

			RHP_BUG("");
		}

	}else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_MAC_ADDRESS ){

 	 	int rx_mac_len = payload->ext.n->get_data_len(payload);
  	u8* rx_mac = payload->ext.n->get_data(payload);

  	if( rx_mac_len == 6 ){

  		memcpy(s_pld_ctx->peer_mac,rx_mac,6);

      RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_SRCH_N_INFO_CB_MAC_ADDR,"xM",rx_ikemesg,rx_mac);

  		RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_INTERNAL_NET_INFO_INTERNAL_PEER_MAC,"KVPM",rx_ikemesg,s_pld_ctx->vpn,s_pld_ctx->ikesa,s_pld_ctx->peer_mac);

  	}else{

      RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_SRCH_N_INFO_CB_INVALID_MAC_ADDR,"xd",rx_ikemesg,rx_mac_len);
  	}

	}else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_ACCESSPOINT ){

		s_pld_ctx->peer_is_access_point = 1;

    RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_SRCH_N_INFO_CB_PEER_IS_ACCESSPOINT,"xd",rx_ikemesg,s_pld_ctx->peer_is_access_point);

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_INTERNAL_NET_INFO_INTERNAL_PEER_IS_HUB,"KVP",rx_ikemesg,s_pld_ctx->vpn,s_pld_ctx->ikesa);

	}else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_MESH_NODE ){

		s_pld_ctx->peer_is_mesh_node = 1;

    RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_SRCH_N_INFO_CB_MESH_MODE,"xd",rx_ikemesg,s_pld_ctx->peer_is_mesh_node);

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_INTERNAL_NET_INFO_INTERNAL_PEER_IS_MESH_NODE,"KVP",rx_ikemesg,s_pld_ctx->vpn,s_pld_ctx->ikesa);
	}

	err = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_SRCH_N_INFO_CB_RTRN,"xE",rx_ikemesg,err);
	return err;
}


static int _rhp_ikev2_rx_internal_net_ike_auth_req(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_proto_ike* ikeh;
  rhp_vpn_realm* rlm = NULL;
	rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_IKE_AUTH_REQ,"xxxxddd",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,vpn->peer_is_rockhopper,vpn->nhrp.role,vpn->nhrp.dmvpn_shortcut);

  ikeh = rx_req_ikemesg->rx_pkt->app.ikeh;

  if( !(vpn->peer_is_rockhopper) ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_IKE_AUTH_REQ_PEER_IS_NOT_RHP,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
    goto ignore;
  }

  if( rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
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
    RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_IKE_AUTH_REQ_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
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

				if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
					RHP_BUG("");
					goto error_l;
				}

				tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

				if( tx_resp_ikemesg->get_exchange_type(tx_resp_ikemesg) == RHP_PROTO_IKE_EXCHG_RESEVED ){
					tx_resp_ikemesg->set_exchange_type(tx_resp_ikemesg,RHP_PROTO_IKE_EXCHG_INFORMATIONAL);
				}

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

				ikepayload->set_non_critical(ikepayload,1);
			}

			addr_lst = addr_lst->next;
		}
	}

	if( rlm->internal_ifc->ifc ){

		rhp_ifc_entry* v_ifc = rlm->internal_ifc->ifc;

		if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error_l;
		}

		tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

		if( tx_resp_ikemesg->get_exchange_type(tx_resp_ikemesg) == RHP_PROTO_IKE_EXCHG_RESEVED ){
			tx_resp_ikemesg->set_exchange_type(tx_resp_ikemesg,RHP_PROTO_IKE_EXCHG_INFORMATIONAL);
		}

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

		if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error_l;
		}

		tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);

		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_MESH_NODE);

		ikepayload->set_non_critical(ikepayload,1);

	}else	if( rlm->is_access_point ){

		if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error_l;
		}

		tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);

		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_ACCESSPOINT);

		ikepayload->set_non_critical(ikepayload,1);
	}

  RHP_UNLOCK(&(rlm->lock));

ignore:
  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_IKE_AUTH_REQ_RTRN,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
	return 0;

error_l:
	RHP_UNLOCK(&(rlm->lock));
error:

	RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_IKE_AUTH_REQ_ERR,"xxxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);
  return err;
}


static int _rhp_ikev2_rx_internal_net_info_req_clear_old_peer_addrs(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_req_ikemesg,rhp_intr_net_srch_plds_ctx* s_pld_ctx)
{
	rhp_ip_addr_list *cur_peer_addr = vpn->internal_net_info.peer_addrs, *cur_peer_addr_p = NULL;
	int n = 0;

	while( cur_peer_addr ){

		rhp_ip_addr_list *cur_peer_addr_n = cur_peer_addr->next;

		if( cur_peer_addr->ip_addr.tag != RHP_IPADDR_TAG_IKEV2_CFG_ASSIGNED ){

			rhp_vpn_delete_by_peer_internal_addr(&(cur_peer_addr->ip_addr),vpn);
			n++;

			if( cur_peer_addr_p ){
				cur_peer_addr_p->next = cur_peer_addr_n;
			}else{
				vpn->internal_net_info.peer_addrs = cur_peer_addr_n;
			}

			RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_INFO_REQ_CLEAR_OLD_PEER_ADDRS,"xxxx",vpn,ikesa,rx_req_ikemesg,cur_peer_addr);
			rhp_ip_addr_dump("CLEAR_OLD_PEER_ADDRS",&(cur_peer_addr->ip_addr));

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_INTERNAL_NET_PEER_ADDR_CLEARED,"KVPA",rx_req_ikemesg,vpn,ikesa,&(cur_peer_addr->ip_addr));

			_rhp_free(cur_peer_addr);

		}else{

			rhp_ip_addr_dump("NOT_CLEAR_OLD_PEER_CFG_ASSIGNED_ADDR",&(cur_peer_addr->ip_addr));

			cur_peer_addr_p = cur_peer_addr;
		}

		cur_peer_addr = cur_peer_addr_n;
	}

	if( n ){
		rhp_vpn_internal_route_delete(vpn,NULL); // [CAUTION] NULL means 'rlm' !!!
	}

	return 0;
}

static int _rhp_ikev2_rx_internal_net_info_req_mark_peer_addrs(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_vpn_realm* rlm,
		rhp_ikev2_mesg* rx_req_ikemesg,rhp_intr_net_srch_plds_ctx* s_pld_ctx)
{
	rhp_ip_addr_list *rx_peer_addr = s_pld_ctx->peer_addrs;

	while( rx_peer_addr ){

		rhp_ip_addr_dump("RX_PEER_ADDR_B4",&(rx_peer_addr->ip_addr));

		if( vpn->internal_net_info.peer_addr_v4_cp == RHP_IKEV2_CFG_CP_ADDR_ASSIGNED ||
				vpn->internal_net_info.peer_addr_v6_cp == RHP_IKEV2_CFG_CP_ADDR_ASSIGNED ){

			rhp_ip_addr_list *cur_peer_addr
				= rhp_ip_addr_list_included(vpn->internal_net_info.peer_addrs,&(rx_peer_addr->ip_addr),1);
			if( cur_peer_addr == NULL ){

				RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_INFO_REQ_UNKNOWN_PEER_ADDR_NOTIFIED,"xxx",vpn,ikesa,rx_req_ikemesg);
				rhp_ip_addr_dump("UNKNOWN_PEER_ADDR",&(rx_peer_addr->ip_addr));

				if( !rhp_ip_is_linklocal(rx_peer_addr->ip_addr.addr_family,rx_peer_addr->ip_addr.addr.raw) ){

					// Non Link Local address

					RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_INTERNAL_NET_INFO_REQ_NEW_PEER_ADDR_NOTIFIED,"KVPA",rx_req_ikemesg,vpn,ikesa,&(rx_peer_addr->ip_addr));

					rx_peer_addr->ip_addr.tag = RHP_IPADDR_TAG_INVALID_ADDR; // Reset rx_addr as INVALD_ADDR.

				}else{

					// Link Local address

					if( rx_peer_addr->ip_addr.addr_family != AF_INET6 ||
							vpn->internal_net_info.peer_exec_ipv6_autoconf ){

						RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_INTERNAL_NET_INFO_REQ_NEW_PEER_LL_ADDR_NOTIFIED,"KVPA",rx_req_ikemesg,vpn,ikesa,&(rx_peer_addr->ip_addr));

						rx_peer_addr->ip_addr.tag = RHP_IPADDR_TAG_IKEV2_EXCHG;

					}else{

						RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_INTERNAL_NET_INFO_REQ_NEW_PEER_ADDR_NOTIFIED,"KVPA",rx_req_ikemesg,vpn,ikesa,&(rx_peer_addr->ip_addr));
					}
				}

			}else{

				rx_peer_addr->ip_addr.tag = cur_peer_addr->ip_addr.tag;
			}
		}

		if( vpn->internal_net_info.peer_exec_ipv6_autoconf &&
				rx_peer_addr->ip_addr.addr_family == AF_INET6 &&
				rx_peer_addr->ip_addr.tag != RHP_IPADDR_TAG_IKEV2_CFG_ASSIGNED ){

			if( rhp_vpn_internal_addr_pool_v6_included(rlm,&(rx_peer_addr->ip_addr)) ){

				RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_INFO_REQ_IPV6_AUTO_CONF_RESERVED_ADDRS_COLLISION,"xxx",vpn,ikesa,rx_req_ikemesg);
				rhp_ip_addr_dump("IPV6_AUTO_CONF_ADDR_RSVD_COL",&(rx_peer_addr->ip_addr));

				RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_INTERNAL_NET_INFO_REQ_ADDR_RESERVED,"KPVA",rx_req_ikemesg,ikesa,vpn,&(rx_peer_addr->ip_addr));

				rx_peer_addr->ip_addr.tag = RHP_IPADDR_TAG_INVALID_ADDR;

			}else{

				RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_INFO_REQ_IPV6_AUTO_CONF_ADDR,"xxx",vpn,ikesa,rx_req_ikemesg);
				rhp_ip_addr_dump("IPV6_AUTO_CONF_ADDR",&(rx_peer_addr->ip_addr));

				rx_peer_addr->ip_addr.tag = RHP_IPADDR_TAG_IKEV2_EXCHG;
			}
		}


		{
			rhp_vpn* col_vpn;
			rhp_vpn_ref* col_vpn_ref;

			col_vpn_ref = rhp_vpn_get_by_peer_internal_addr(
											vpn->vpn_realm_id,&(rx_peer_addr->ip_addr));
			col_vpn = RHP_VPN_REF(col_vpn_ref);
			if( col_vpn && col_vpn != vpn ){

				RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_INFO_REQ_ADDR_COLLISION,"xxxx",vpn,col_vpn,ikesa,rx_req_ikemesg);
				rhp_ip_addr_dump("ITNL_ADDR_COL",&(rx_peer_addr->ip_addr));

				RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_INTERNAL_NET_INFO_REQ_ADDR_COLLISION,"KPVVA",rx_req_ikemesg,ikesa,vpn,col_vpn,&(rx_peer_addr->ip_addr));

				rx_peer_addr->ip_addr.tag = RHP_IPADDR_TAG_INVALID_ADDR;
			}

			if( col_vpn ){
				rhp_vpn_unhold(col_vpn_ref);
			}
		}

		rhp_ip_addr_dump("RX_PEER_ADDR_AFTR",&(rx_peer_addr->ip_addr));

		rx_peer_addr = rx_peer_addr->next;
	}

	return 0;
}


int rhp_ikev2_rx_internal_net_info_req_update_peer_addrs(
		rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_vpn_realm* rlm,
		rhp_ikev2_mesg* rx_req_ikemesg,rhp_intr_net_srch_plds_ctx* s_pld_ctx,
		int* updated_r)
{
	int err = -EINVAL;
	rhp_ip_addr_list *rx_peer_addr;
	int n = 0;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_INFO_REQ_UPDATE_PEER_ADDRS,"xxxxxbbb",vpn,ikesa,rlm,rx_req_ikemesg,s_pld_ctx,vpn->internal_net_info.peer_addr_v4_cp,vpn->internal_net_info.peer_addr_v6_cp,vpn->internal_net_info.peer_exec_ipv6_autoconf);


	_rhp_ikev2_rx_internal_net_info_req_mark_peer_addrs(vpn,ikesa,rlm,rx_req_ikemesg,s_pld_ctx);


	rx_peer_addr = s_pld_ctx->peer_addrs;
	while( rx_peer_addr ){

		if( rx_peer_addr->ip_addr.tag == RHP_IPADDR_TAG_IKEV2_EXCHG ){

			rhp_ip_addr_list* peer_addr = rhp_ip_dup_addr_list(&(rx_peer_addr->ip_addr));
			if( peer_addr == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			if( n == 0 ){

				_rhp_ikev2_rx_internal_net_info_req_clear_old_peer_addrs(vpn,ikesa,rx_req_ikemesg,s_pld_ctx);
			}

			peer_addr->next = vpn->internal_net_info.peer_addrs;
			vpn->internal_net_info.peer_addrs = peer_addr;

			err = rhp_vpn_put_by_peer_internal_addr(&(rx_peer_addr->ip_addr),vpn);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_INTERNAL_NET_PEER_ADDR_UPDATED,"KVPA",rx_req_ikemesg,vpn,ikesa,&(rx_peer_addr->ip_addr));

			n++;

		}else{

			RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_INFO_REQ_UPDATE_PEER_ADDRS_NOT_INTERESTED_ADDR,"xxxx",vpn,ikesa,rx_req_ikemesg,rx_peer_addr);
			rhp_ip_addr_dump("NOT_INTERESTED_PEER_ADDR",&(rx_peer_addr->ip_addr));
		}

		rx_peer_addr = rx_peer_addr->next;
	}

	if( n ){

		*updated_r = 1;

	}else{

		*updated_r = 0;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_INFO_REQ_UPDATE_PEER_ADDRS_RTRN,"xxxxd",vpn,ikesa,rx_req_ikemesg,s_pld_ctx,*updated_r);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_INFO_REQ_UPDATE_PEER_ADDRS_ERR,"xxxxE",vpn,ikesa,rx_req_ikemesg,s_pld_ctx,err);
	return err;
}


static int _rhp_ikev2_itnl_net_ipv6_autoconf_exec_rekey(rhp_vpn* vpn)
{
	rhp_ip_addr_list* peer_addr = vpn->internal_net_info.peer_addrs;

	if( !vpn->internal_net_info.peer_exec_ipv6_autoconf ){
		RHP_TRC(0,RHPTRCID_IKEV2_ITNL_NET_IPV6_AUTOCONF_EXEC_REKEY_NOT_PEER_EXEC,"x",vpn);
		return 0;
	}

	if( !vpn->internal_net_info.ipv6_autoconf_narrow_ts_i ){
		RHP_TRC(0,RHPTRCID_IKEV2_ITNL_NET_IPV6_AUTOCONF_EXEC_REKEY_NOT_EXEC_REKEY,"x",vpn);
		return 0;
	}

	while( peer_addr ){

		if( peer_addr->ip_addr.addr_family == AF_INET6 ){
			RHP_TRC(0,RHPTRCID_IKEV2_ITNL_NET_IPV6_AUTOCONF_EXEC_DO,"x",vpn);
			return 1;
		}

		peer_addr = peer_addr->next;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_ITNL_NET_IPV6_AUTOCONF_EXEC_NOT,"x",vpn);
	return 0;
}


static int _rhp_ikev2_rx_internal_net_info_req(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
	rhp_intr_net_srch_plds_ctx s_pld_ctx;
	int peer_addrs_updated = 0;
	u8* peer_mac = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_INFO_REQ,"xxxxdddd",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,vpn->peer_is_rockhopper,vpn->internal_net_info.peer_exec_ipv6_autoconf,vpn->internal_net_info.peer_addrs_notified,vpn->internal_net_info.ipv6_autoconf_narrow_ts_i);

	memset(&s_pld_ctx,0,sizeof(rhp_intr_net_srch_plds_ctx));

  if( !(vpn->peer_is_rockhopper) ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_INFO_REQ_PEER_IS_NOT_RHP,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
  	return 0;
  }

	if( !vpn->internal_net_info.peer_exec_ipv6_autoconf &&
			vpn->internal_net_info.peer_addrs_notified ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_INFO_REQ_PEER_ADDRS_NOTIFIED,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
		return 0;
	}


  if( rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_INFO_REQ_VPN,"xxxxdLd",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,vpn->internal_net_info.static_peer_addr,"VPN_ENCAP",vpn->internal_net_info.encap_mode_c);


	s_pld_ctx.vpn = vpn;
	s_pld_ctx.ikesa = ikesa;

	{
		rhp_ip_addr_list* peer_addr;

		s_pld_ctx.dup_flag = 0;
		u16 intr_net_mesg_ids[4] = { RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_IP4_ADDRESS,
																 RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_IP6_ADDRESS,
																 RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_MAC_ADDRESS,
																 RHP_PROTO_IKE_NOTIFY_RESERVED};

		err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
						rhp_ikev2_mesg_srch_cond_n_mesg_ids,intr_net_mesg_ids,
						rhp_ikev2_internal_net_srch_n_info_cb,&s_pld_ctx);

		if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_INFO_REQ_NTFY_ERR,"xxxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);
			goto error;
		}else if( err == -ENOENT ){
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_INFO_REQ_NTFY_IGNORED,"xxxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);
			err = 0;
			goto ignore;
		}

		peer_addr = s_pld_ctx.peer_addrs;
		while( peer_addr ){
			rhp_ip_addr_dump("_rhp_ikev2_rx_internal_net_info_req.new_peer_addr",&(peer_addr->ip_addr));
			peer_addr = peer_addr->next;
		}
		RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_INFO_REQ_NTFY_PEER_MAC,"xxxxM",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,s_pld_ctx.peer_mac);
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

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_INFO_REQ_UPDATE_PEER_ADDRS_RLM_NOT_ACTIVE,"xxxx",rlm,vpn,ikesa,rx_req_ikemesg);
      err = -EINVAL;

    	RHP_UNLOCK(&(rlm->lock));
			goto error;
    }

  	err = rhp_ikev2_rx_internal_net_info_req_update_peer_addrs(vpn,ikesa,rlm,
  					rx_req_ikemesg,&s_pld_ctx,&peer_addrs_updated);
  	if( err ){

  		RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_INFO_REQ_UPDATE_PEER_ADDRS_ERR,"xxxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);

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

				RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_INFO_REQ_MAC_COLLISION,"xxxxM",vpn,col_vpn,ikesa,rx_req_ikemesg,s_pld_ctx.peer_mac);
				RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_INTERNAL_NET_INFO_REQ_MAC_COLLISION,"KPVVM",rx_req_ikemesg,ikesa,vpn,col_vpn,s_pld_ctx.peer_mac);

			}else{

				err = rhp_vpn_put_by_peer_internal_mac(s_pld_ctx.peer_mac,vpn);
				if( err ){
					RHP_BUG("%d",err);
					goto error;
				}

				memcpy(vpn->internal_net_info.exchg_peer_mac,s_pld_ctx.peer_mac,6);

				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_INTERNAL_NET_PEER_MAC_UPDATED,"KVPM",rx_req_ikemesg,vpn,ikesa,s_pld_ctx.peer_mac);

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

				RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_INFO_REQ_PEER_MAC_UNKNOWN,"xxxdMM",vpn,ikesa,rx_req_ikemesg,vpn->internal_net_info.peer_addrs_notified,s_pld_ctx.peer_mac,vpn->internal_net_info.exchg_peer_mac);
			}
		}


		rhp_vpn_internal_route_update(vpn);


		if( _rhp_ikev2_itnl_net_ipv6_autoconf_exec_rekey(vpn) ){

			rhp_childsa* cur_childsa;

			vpn->exec_rekey_ipv6_autoconf = 1;

			cur_childsa = vpn->childsa_list_head;
		  while( cur_childsa ){

		  	RHP_TRC_FREQ(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_INFO_REQ_CUR_CHILDSA,"xxxLd",rx_req_ikemesg,vpn,cur_childsa,"CHILDSA_STAT",cur_childsa->state);

		  	// Newer one is adopted.
		  	if( cur_childsa->state == RHP_CHILDSA_STAT_MATURE ){
		  		break;
		  	}

		  	cur_childsa = cur_childsa->next_vpn_list;
		  }

		  if( cur_childsa ){

				RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_INTERNAL_NET_IPV6_AUTOCONF_EXEC_REKEY,"KVPC",rx_req_ikemesg,vpn,ikesa,cur_childsa);

				// Start rekeying!
				cur_childsa->timers->quit_lifetime_timer(vpn,cur_childsa);
				cur_childsa->timers->start_lifetime_timer(vpn,cur_childsa,0,0); // Exec immediately!

		  }else{

				vpn->exec_rekey_ipv6_autoconf = 0;

				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_INTERNAL_NET_IPV6_AUTOCONF_NO_CHILDSA_FOUND,"KVP",rx_req_ikemesg,vpn,ikesa);

		  	RHP_TRC_FREQ(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_INFO_REQ_NO_CUR_CHILDSA,"xx",rx_req_ikemesg,vpn);
		  }
		}
  }


	if( !vpn->internal_net_info.peer_addrs_notified &&
			(s_pld_ctx.peer_addrs || !_rhp_mac_addr_null(s_pld_ctx.peer_mac)) ){

		vpn->internal_net_info.peer_addrs_notified = 1;
	}


	rhp_bridge_cache_flush_by_vpn(vpn);


ignore:
	rhp_ikev2_internal_net_clear_src_ctx(&s_pld_ctx);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_INFO_REQ_RTRN,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
  return 0;

error:
	rhp_ikev2_internal_net_clear_src_ctx(&s_pld_ctx);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_INFO_REQ_ERR,"xxxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);
	return err;
}

int rhp_ikev2_internal_net_v6_linklocal_srch(rhp_ip_addr* ipaddr,void* ctx)
{
	if( ipaddr->addr_family == AF_INET6 &&
			rhp_ipv6_is_linklocal(ipaddr->addr.v6) ){
		return 1;
	}

	return 0;
}

static int _rhp_ikev2_rx_internal_net_ike_auth_rep_tx_my_addrs(
		rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_vpn_realm* rlm,
		rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ikev2_mesg* tx_req_ikemesg,
		rhp_intr_net_srch_plds_ctx* s_pld_ctx)
{
  int err = RHP_STATUS_INVALID_MSG;
	rhp_ip_addr* rx_cp_internal_addrs = rx_resp_ikemesg->rx_cp_internal_addrs;
	rhp_ip_addr_list* my_addr = NULL;
	rhp_ip_addr_list* intr_addrs = NULL;
	int free_intr_addrs_tmp = 0;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_IKE_AUTH_REP_TX_MY_ADDRS,"xxxxxxdd",vpn,ikesa,rlm,rx_resp_ikemesg,tx_req_ikemesg,s_pld_ctx,vpn->nhrp.role,vpn->nhrp.dmvpn_shortcut);

	rhp_ip_addr_dump("rx_resp_ikemesg->rx_cp_internal_addrs[0]",&(rx_cp_internal_addrs[0])); // IPv4
	rhp_ip_addr_dump("rx_resp_ikemesg->rx_cp_internal_addrs[1]",&(rx_cp_internal_addrs[1])); // IPv6


	if( (vpn->nhrp.role == RHP_NHRP_SERVICE_SERVER || vpn->nhrp.role == RHP_NHRP_SERVICE_NONE) &&
			!vpn->nhrp.dmvpn_shortcut ){

		if( !rhp_ip_addr_null(&(rx_cp_internal_addrs[0])) ||
				!rhp_ip_addr_null(&(rx_cp_internal_addrs[1])) ){

			rhp_ip_addr* my_linklocal_addr;

			free_intr_addrs_tmp = 1;

			if( !rhp_ip_addr_null(&(rx_cp_internal_addrs[0])) ){

				my_addr = rhp_ip_dup_addr_list(&(rx_cp_internal_addrs[0]));
				if( my_addr == NULL ){
					RHP_BUG("");
					goto error;
				}

				my_addr->next = intr_addrs;
				intr_addrs = my_addr;
			}

			if( !rhp_ip_addr_null(&(rx_cp_internal_addrs[1])) ){

				my_addr = rhp_ip_dup_addr_list(&(rx_cp_internal_addrs[1]));
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

			if( vpn->internal_net_info.exec_ipv6_autoconf &&
					rhp_ikev2_internal_net_v6_linklocal_srch(&(my_addr->ip_addr),NULL) ){

				//
				// The address will be sent later.
				//

				RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_IKE_AUTH_REP_TX_MY_ADDRS_V6_AUTOCONF_SKIP_LL_ADDR,"xxxx",vpn,ikesa,rx_resp_ikemesg,my_addr);
				goto skip;
			}

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


				if( rhp_ikev2_new_payload_tx(tx_req_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
					RHP_BUG("");
					goto error;
				}

				tx_req_ikemesg->put_payload(tx_req_ikemesg,ikepayload);

				if( tx_req_ikemesg->get_exchange_type(tx_req_ikemesg) == RHP_PROTO_IKE_EXCHG_RESEVED ){
					tx_req_ikemesg->set_exchange_type(tx_req_ikemesg,RHP_PROTO_IKE_EXCHG_INFORMATIONAL);
				}

				ikepayload->ext.n->set_protocol_id(ikepayload,0);

				ikepayload->ext.n->set_message_type(ikepayload,msg_type);

				if( ikepayload->ext.n->set_data(ikepayload,addr_len,my_addr->ip_addr.addr.raw) ){
					RHP_BUG("");
					goto error;
				}

				ikepayload->set_non_critical(ikepayload,1);

			}else{

				RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_IKE_AUTH_REP_TX_MY_ADDRS_NULL_ADDR,"xxxx",vpn,ikesa,rx_resp_ikemesg,my_addr);
			}

skip:
			my_addr = my_addr->next;
		}
	}


	if( rlm->internal_ifc->ifc ){

		rhp_ifc_entry* v_ifc = rlm->internal_ifc->ifc;
		rhp_ikev2_payload* ikepayload = NULL;

		if( rhp_ikev2_new_payload_tx(tx_req_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_req_ikemesg->put_payload(tx_req_ikemesg,ikepayload);

		if( tx_req_ikemesg->get_exchange_type(tx_req_ikemesg) == RHP_PROTO_IKE_EXCHG_RESEVED ){
			tx_req_ikemesg->set_exchange_type(tx_req_ikemesg,RHP_PROTO_IKE_EXCHG_INFORMATIONAL);
		}

		ikepayload->ext.n->set_protocol_id(ikepayload,0);

		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_MAC_ADDRESS);

		ikepayload->set_non_critical(ikepayload,1);

#ifdef RHP_DBG_IPV6_AUTOCONF_TEST
		{
			u8 dup_test_mac[6] = {0x82,0xba,0x87,0xe1,0xbe,0xef};
			if( ikepayload->ext.n->set_data(ikepayload,6,dup_test_mac) ){

				RHP_BUG("");

				RHP_UNLOCK(&(v_ifc->lock));
				goto error;
			}
		}
#else // RHP_DBG_IPV6_AUTOCONF_TEST
		RHP_LOCK(&(v_ifc->lock));
		{
			if( ikepayload->ext.n->set_data(ikepayload,6,v_ifc->mac) ){

				RHP_BUG("");

				RHP_UNLOCK(&(v_ifc->lock));
				goto error;
			}
		}
		RHP_UNLOCK(&(v_ifc->lock));
#endif // RHP_DBG_IPV6_AUTOCONF_TEST
	}

	if( free_intr_addrs_tmp ){

		my_addr = intr_addrs;
		while( my_addr ){
			rhp_ip_addr_list* my_addr_n = my_addr->next;
			_rhp_free(my_addr);
			my_addr = my_addr_n;
		}
	}

	RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_IKE_AUTH_REP_TX_MY_ADDRS_RTRN,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
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

	RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_IKE_AUTH_REP_TX_MY_ADDRS_ERR,"xxxxE",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,err);
	return err;
}

static int _rhp_ikev2_rx_internal_net_ike_auth_rep(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ikev2_mesg* tx_req_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_vpn_realm* rlm = NULL;
	rhp_intr_net_srch_plds_ctx s_pld_ctx;
	rhp_ip_addr_list* new_peer_addr = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_IKE_AUTH_REP,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);

	memset(&s_pld_ctx,0,sizeof(rhp_intr_net_srch_plds_ctx));

  if( !(vpn->peer_is_rockhopper) ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_IKE_AUTH_REP_PEER_IS_NOT_RHP,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
  	return 0;
  }

  if( rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_IKE_AUTH_REP_VPN,"xxxxdLddd",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,vpn->internal_net_info.static_peer_addr,"VPN_ENCAP",vpn->internal_net_info.encap_mode_c,vpn->peer_is_rockhopper,vpn->internal_net_info.static_peer_addr);


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

		err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
						rhp_ikev2_mesg_srch_cond_n_mesg_ids,intr_net_mesg_ids,
						rhp_ikev2_internal_net_srch_n_info_cb,&s_pld_ctx);

		if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_IKE_AUTH_REP_NTFY_ERR,"xxxxE",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,err);
			goto error;
		}
		err = 0;

		new_peer_addr = s_pld_ctx.peer_addrs;
		while( new_peer_addr ){
			rhp_ip_addr_dump("_rhp_ikev2_rx_internal_net_ike_auth_rep.new_peer_addr",&(new_peer_addr->ip_addr));
			new_peer_addr = new_peer_addr->next;
		}
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_IKE_AUTH_REP_PEER_MAC,"xxxxM",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,s_pld_ctx.peer_mac);
	}


  rlm = vpn->rlm;
  if( rlm == NULL ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_IKE_AUTH_REP_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
    err = -EINVAL;
    goto error_l;
  }

  if( s_pld_ctx.peer_is_access_point && rlm->is_access_point ){ // Avoiding broadcast storm and Dup packets...

	  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_IKE_AUTH_REP_PEER_ALSO_ACCESS_POINT,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);

		RHP_LOG_E(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_INTERNAL_NET_REP_PEER_IS_ALSO_HUB,"KVP",rx_resp_ikemesg,vpn,ikesa);

		ikesa->timers->schedule_delete(vpn,ikesa,0);

		err = RHP_STATUS_PEER_IS_ALSO_ACCESSPOINT;
		goto error_l;

  }else if( (s_pld_ctx.peer_is_mesh_node && rlm->is_access_point) ||
  					(s_pld_ctx.peer_is_access_point && rlm->is_mesh_node) ){ // Avoiding broadcast storm and Dup packets...

	  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_IKE_AUTH_REP_PEER_MESH_NODE,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);

		RHP_LOG_E(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_INTERNAL_NET_REP_PEER_IS_MESH_NODE,"KVP",rx_resp_ikemesg,vpn,ikesa);

		ikesa->timers->schedule_delete(vpn,ikesa,0);

		err = RHP_STATUS_PEER_IS_MESH_NODE;
		goto error_l;

  }else if( !(s_pld_ctx.peer_is_access_point) &&
  					vpn->cfg_peer && vpn->cfg_peer->is_access_point ){

	  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_IKE_AUTH_REP_PEER_PEER_IS_NOT_EXPECTED_ACCESS_POINT,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);

  }else if( s_pld_ctx.peer_is_access_point &&
  					vpn->cfg_peer && !(vpn->cfg_peer->is_access_point) ){

	  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_IKE_AUTH_REP_PEER_PEER_IS_ACCESS_POINT,"xxxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,rlm->access_point_peer);


	  if( (rlm->access_point_peer == NULL) && (rlm->access_point_peer_vpn_ref == NULL) ){

		  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_IKE_AUTH_REP_SET_ACCESSPOINT,"xxxx",vpn,ikesa,rx_resp_ikemesg,rlm);

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_INTERNAL_NET_REP_PEER_IS_HUB,"KVP",rx_resp_ikemesg,vpn,ikesa);

	  	vpn->cfg_peer->is_access_point = 1;

	  	rlm->set_access_point(rlm,vpn);

	  }else{

		  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_IKE_AUTH_REP_NOT_SET_ACCESSPOINT,"xxxxxx",vpn,ikesa,rx_resp_ikemesg,rlm,rlm->access_point_peer,RHP_VPN_REF(rlm->access_point_peer_vpn_ref));

	  	if( rlm->access_point_peer ){

	  		rhp_ikev2_id_dump("access_point_peer_cfg",&(rlm->access_point_peer->id));
	  		rhp_ip_addr_dump("primary_addr",&(rlm->access_point_peer->primary_addr));
	  		rhp_ip_addr_dump("secondary_addr",&(rlm->access_point_peer->secondary_addr));

	  		RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_INTERNAL_NET_REP_STATIC_PEER_IS_CONFIGURED,"KVP",rx_resp_ikemesg,vpn,ikesa);
	  	}
	  }
  }


  if( s_pld_ctx.peer_addrs &&
  		!(vpn->internal_net_info.static_peer_addr) ){

		rhp_ip_addr_list* cur_peer_addr = vpn->internal_net_info.peer_addrs;
		int n = 0;

		while( cur_peer_addr ){

			rhp_ip_addr_list* cur_peer_addr_n = cur_peer_addr->next;

			rhp_ip_addr_dump("_rhp_ikev2_rx_internal_net_ike_auth_rep.cur_peer_addr",&(cur_peer_addr->ip_addr));

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

					RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_IKE_AUTH_REP_ADDR_COLLISION,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);

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


	err = _rhp_ikev2_rx_internal_net_ike_auth_rep_tx_my_addrs(vpn,ikesa,rlm,
					rx_resp_ikemesg,tx_req_ikemesg,&s_pld_ctx);
	if( err ){
		RHP_BUG("%d",err);
		goto error_l;
	}


	if( !vpn->internal_net_info.peer_addrs_notified &&
			(s_pld_ctx.peer_addrs || !_rhp_mac_addr_null(s_pld_ctx.peer_mac)) ){

		vpn->internal_net_info.peer_addrs_notified = 1;
	}

  RHP_UNLOCK(&(rlm->lock));

	rhp_ikev2_internal_net_clear_src_ctx(&s_pld_ctx);


	RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_IKE_AUTH_REP_RTRN,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
	return 0;

error_l:
	RHP_UNLOCK(&(rlm->lock));
error:

	rhp_ikev2_internal_net_clear_src_ctx(&s_pld_ctx);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_IKE_AUTH_REP_ERR,"xxxxE",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,err);
  return err;
}

int rhp_ikev2_rx_internal_net_req(rhp_ikev2_mesg* rx_req_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_req_ikemesg->get_exchange_type(rx_req_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_REQ,"xxLdGxLb",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_resp_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

  if( !rx_req_ikemesg->decrypted ){
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_REQ_NOT_DECRYPTED,"xxLdG",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
  	goto error;
  }

	if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_AUTH ){

		if( my_ikesa_spi == NULL ){
	    RHP_BUG("");
	    goto error;
	  }

		ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
		if( ikesa == NULL ){
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_REQ_NO_IKESA_1,"xxLdG",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}

		if( ikesa->state != RHP_IKESA_STAT_ESTABLISHED ){
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_REQ_NOT_ESTABLISHED_1,"xxLdGxLd",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,ikesa,"IKESA_STAT",ikesa->state);
			goto error;
		}

		_rhp_ikev2_rx_internal_net_ike_auth_req(vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);

	}else if( exchange_type == RHP_PROTO_IKE_EXCHG_INFORMATIONAL ){

		if( my_ikesa_spi == NULL ){
	    RHP_BUG("");
	    goto error;
	  }

		ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
		if( ikesa == NULL ){
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_REQ_NO_IKESA_2,"xxLdG",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}

		if( ikesa->state != RHP_IKESA_STAT_ESTABLISHED ){
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_REQ_NOT_ESTABLISHED_2,"xxLdGxLd",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,ikesa,"IKESA_STAT",ikesa->state);
			goto error;
		}

		_rhp_ikev2_rx_internal_net_info_req(vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
	}

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_REQ_RTRN,"xxx",rx_req_ikemesg,vpn,tx_resp_ikemesg);
	return 0;
}

int rhp_ikev2_rx_internal_net_rep(rhp_ikev2_mesg* rx_resp_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_req_ikemesg)
{
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_resp_ikemesg->get_exchange_type(rx_resp_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_REP,"xxLdGxLb",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_req_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

  if( !rx_resp_ikemesg->decrypted ){
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_REP_NOT_DECRYPTED,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
  	goto error;
  }

	if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_AUTH ){

		if( my_ikesa_spi == NULL ){
	    RHP_BUG("");
	    goto error;
	  }

		ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
		if( ikesa == NULL ){
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_REP_NO_IKESA,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}

		if( ikesa->state != RHP_IKESA_STAT_ESTABLISHED ){
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_REP_NO_IKESA,"xxLdGxLd",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,ikesa,"IKESA_STAT",ikesa->state);
			goto error;
		}

		_rhp_ikev2_rx_internal_net_ike_auth_rep(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
	}

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_INTERNAL_NET_REP_RTRN,"xxx",rx_resp_ikemesg,vpn,tx_req_ikemesg);
  return 0;
}


struct _rhp_ikev2_itnl_net_ifc_ctx {

	u8 tag[4]; // '#ITI'

	struct _rhp_ikev2_itnl_net_ifc_ctx* next;

	int if_index;
	unsigned long rlm_id;

	int retries;
};
typedef struct _rhp_ikev2_itnl_net_ifc_ctx	rhp_ikev2_itnl_net_ifc_ctx;

static rhp_ikev2_itnl_net_ifc_ctx* _rhp_ikev2_itnl_net_ifc_ctx_list = NULL;

static rhp_ikev2_itnl_net_ifc_ctx* _rhp_ikev2_itnl_net_ifcx_delete(int if_index)
{
	rhp_ikev2_itnl_net_ifc_ctx *ifcx, *ifcx_p = NULL;

	ifcx = _rhp_ikev2_itnl_net_ifc_ctx_list;
	while( ifcx ){

		if( ifcx->if_index == if_index ){
			break;
		}

		ifcx_p = ifcx;
		ifcx = ifcx->next;
	}

	if( ifcx ){

		if( ifcx_p ){
			ifcx_p->next = ifcx->next;
		}else{
			_rhp_ikev2_itnl_net_ifc_ctx_list = ifcx->next;
		}

	}else{

		RHP_BUG("%d",if_index);
	}

	RHP_TRC(0,RHPTRCID_ikev2_itnl_net_IFCX_DELETE,"dx",if_index,ifcx);
	return ifcx;
}

static rhp_ikev2_itnl_net_ifc_ctx* _rhp_ikev2_itnl_net_ifcx_get(int if_index)
{
	rhp_ikev2_itnl_net_ifc_ctx *ifcx;

	ifcx = _rhp_ikev2_itnl_net_ifc_ctx_list;
	while( ifcx ){

		if( ifcx->if_index == if_index ){
			break;
		}

		ifcx = ifcx->next;
	}

	RHP_TRC(0,RHPTRCID_ikev2_itnl_net_IFCX_GET,"dx",if_index,ifcx);
	return ifcx;
}

static rhp_ikev2_itnl_net_ifc_ctx* _rhp_ikev2_itnl_net_ifcx_alloc(int if_index,unsigned long rlm_id)
{
	rhp_ikev2_itnl_net_ifc_ctx* ifcx = (rhp_ikev2_itnl_net_ifc_ctx*)_rhp_malloc(sizeof(rhp_ikev2_itnl_net_ifc_ctx));
	if( ifcx == NULL ){
		RHP_BUG("");
		goto error;
	}

	memset(ifcx,0,sizeof(rhp_ikev2_itnl_net_ifc_ctx));

	ifcx->tag[0] = '#';
	ifcx->tag[1] = 'I';
	ifcx->tag[2] = 'T';
	ifcx->tag[3] = 'I';

	ifcx->if_index = if_index;
	ifcx->rlm_id = rlm_id;

	return ifcx;

error:
	return NULL;
}

static int _rhp_ikev2_itnl_net_vif_addr_changed(rhp_vpn* vpn,rhp_vpn_realm* rlm,int* linklocal_addr_only_r)
{
	int diff = 0, glb_addrs = 0, i;
	rhp_ip_addr_list *addr_lst0, *addr_lst1;

	RHP_TRC(0,RHPTRCID_IKEV2_ITNL_NET_VIF_ADDR_CHANGED,"xxxxx",vpn,rlm,linklocal_addr_only_r,vpn->internal_net_info.ipv6_autoconf_old_addrs,rlm->internal_ifc->addrs);

	for( i = 0; i < 2; i++ ){

		if( i == 0 ){
			addr_lst0 = vpn->internal_net_info.ipv6_autoconf_old_addrs;
		}else{
			addr_lst0 = rlm->internal_ifc->addrs;
		}
		while( addr_lst0 ){

			if( i == 0 ){

				addr_lst1 = rlm->internal_ifc->addrs;

			}else{

				addr_lst1 = vpn->internal_net_info.ipv6_autoconf_old_addrs;

				if( addr_lst0->ip_addr.addr_family == AF_INET6 &&
						!rhp_ipv6_is_linklocal(addr_lst0->ip_addr.addr.v6) ){

					glb_addrs++;
				}
			}
			while( addr_lst1 ){

				if( addr_lst1->ip_addr.addr_family == AF_INET6 &&
						!rhp_ip_addr_cmp_ip_only(&(addr_lst1->ip_addr),&(addr_lst0->ip_addr)) ){
					break;
				}

				addr_lst1 = addr_lst1->next;
			}

			if( addr_lst1 == NULL ){
				diff++;
				rhp_ip_addr_dump("vif_addr_changed_different",&(addr_lst1->ip_addr));
			}else{
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_INTERNAL_NET_IPV6_AUTOCONF_UPDATED_ADDR_IGNORED,"V6",vpn,addr_lst1->ip_addr.addr.v6);
				rhp_ip_addr_dump("vif_addr_changed_ignored",&(addr_lst1->ip_addr));
			}

			addr_lst0 = addr_lst0->next;
		}

		if( diff ){

			if( !glb_addrs ){
				*linklocal_addr_only_r = 1;
			}else{
				*linklocal_addr_only_r = 0;
			}

			RHP_TRC(0,RHPTRCID_IKEV2_ITNL_NET_VIF_ADDR_CHANGED_CHANGED,"xxdd",vpn,rlm,*linklocal_addr_only_r,glb_addrs);
			return 1;
		}
	}

	RHP_TRC(0,RHPTRCID_IKEV2_ITNL_NET_VIF_ADDR_CHANGED_NOT_CHANGED,"xx",vpn,rlm);
	return 0;
}

static int _rhp_ikev2_itnl_net_vif_add_old_addrs(rhp_vpn* vpn,rhp_vpn_realm* rlm)
{
	int err = -EINVAL;
	rhp_ip_addr_list* old_addr_lst = vpn->internal_net_info.ipv6_autoconf_old_addrs;
	rhp_ip_addr_list *cur_addr_lst, *old_addr_lst_head = NULL, *old_addr_lst_tail = NULL;

	while( old_addr_lst ){

		rhp_ip_addr_list* old_addr_lst_n = old_addr_lst->next;

		_rhp_free(old_addr_lst);

		old_addr_lst = old_addr_lst_n;
	}

	vpn->internal_net_info.ipv6_autoconf_old_addrs = NULL;


	cur_addr_lst = rlm->internal_ifc->addrs;
	while( cur_addr_lst ){

		if( cur_addr_lst->ip_addr.addr_family == AF_INET6 ){

			old_addr_lst = (rhp_ip_addr_list*)_rhp_malloc(sizeof(rhp_ip_addr_list));
			if( old_addr_lst == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			memcpy(&(old_addr_lst->ip_addr),&(cur_addr_lst->ip_addr),sizeof(rhp_ip_addr));
			old_addr_lst->next = NULL;

			if( old_addr_lst_head == NULL ){
				old_addr_lst_head = old_addr_lst;
			}else{
				old_addr_lst_tail->next = old_addr_lst;
			}
			old_addr_lst_tail = old_addr_lst;
		}

		cur_addr_lst = cur_addr_lst->next;
	}

	vpn->internal_net_info.ipv6_autoconf_old_addrs = old_addr_lst_head;

	return 0;

error:
	return err;
}


struct _rhp_ikev2_itnl_net_cb_ctx {
	int retries;
	rhp_ifc_entry* ifc_tmp;
	int exec_retry;
};
typedef struct _rhp_ikev2_itnl_net_cb_ctx	rhp_ikev2_itnl_net_cb_ctx;

static int _rhp_ikev2_itnl_net_ifc_notifier_cb(rhp_vpn* vpn,void* ctx)
{
	rhp_ikev2_itnl_net_cb_ctx* ifcb_ctx = (rhp_ikev2_itnl_net_cb_ctx*)ctx;
	rhp_ifc_entry* ifc = ifcb_ctx->ifc_tmp;
	rhp_vpn_realm* rlm = NULL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  int tx_req = 0;
  int linklocal_addr_only = 0;

	RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_IFC_NOTIFIER_CB,"xxxddd",vpn,ifcb_ctx,ifc,vpn->exec_mobike,vpn->mobike.init.rt_ck_pending,vpn->mobike.init.rt_ck_waiting);


  RHP_LOCK(&(vpn->lock));

  if( vpn->is_v1 ){
		RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_IFC_NOTIFIER_CB_VPN_IS_V1_IGNORED,"xx",vpn,ifc);
		goto ignored;
  }

	if( vpn->origin_side != RHP_IKE_INITIATOR ){
		RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_IFC_NOTIFIER_CB_VPN_NOT_INITIATOR,"xx",vpn,ifc);
		goto ignored;
	}

	if( !vpn->internal_net_info.exec_ipv6_autoconf ){
		RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_IFC_NOTIFIER_CB_INTERNAL_NET_DISABLED,"xx",vpn,ifc);
		goto ignored;
	}

	rlm = vpn->rlm;
	if( rlm == NULL ){
		goto ignored;
	}

  RHP_LOCK(&(rlm->lock));

	if( !_rhp_atomic_read(&(rlm->is_active)) ){
		RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_IFC_NOTIFIER_CB_RLM_NOT_ACTIVE,"xxx",vpn,ifc,rlm);
		goto ignored;
	}

	if( rlm->internal_ifc == NULL ){
		RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_IFC_NOTIFIER_CB_NO_INTERNAL_IFC,"xxx",vpn,ifc,rlm);
		goto ignored;
	}

	if( rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_STATIC &&
			rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_NONE ){
		RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_IFC_NOTIFIER_CB_VIF_ADDR_NOT_INTERESTED,"xxd",vpn,ifc,rlm->internal_ifc->addrs_type);
		goto ignored;
	}

	if( !_rhp_ikev2_itnl_net_vif_addr_changed(vpn,rlm,&linklocal_addr_only) ){
		RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_IFC_NOTIFIER_CB_VIF_ADDR_NOT_CHANGED_IGNORED,"xx",vpn,ifc);
		goto ignored;
	}

	if( linklocal_addr_only &&
			ifcb_ctx->retries < rhp_gcfg_ikev2_itnl_net_convergence_max_wait_times ){

		ifcb_ctx->exec_retry = 1;

		RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_IFC_NOTIFIER_CB_EXEC_RETRY,"xxd",vpn,ifc,ifcb_ctx->retries);
		goto ignored;
	}



  tx_ikemesg = rhp_ikev2_new_mesg_tx(RHP_PROTO_IKE_EXCHG_INFORMATIONAL,0,0);
  if( tx_ikemesg == NULL ){
    RHP_BUG("");
    goto error;
  }

#ifdef RHP_DBG_IPV6_AUTOCONF_TEST
  {
  	rhp_ip_addr_list *cur_addr_lst = rlm->internal_ifc->addrs;
		while( cur_addr_lst ){

			rhp_ip_addr_dump("cur_addr_lst",&(cur_addr_lst->ip_addr));

			if( !rhp_ip_addr_null(&(cur_addr_lst->ip_addr)) &&
					cur_addr_lst->ip_addr.addr_family == AF_INET ){

				rhp_ikev2_payload* ikepayload = NULL;
				int addr_len = 0;
				u16 msg_type = 0;

				if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
					RHP_BUG("");
					goto error;
				}

				tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

				ikepayload->ext.n->set_protocol_id(ikepayload,0);

				msg_type = RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_IP4_ADDRESS;
				addr_len = 4;

				ikepayload->ext.n->set_message_type(ikepayload,msg_type);

				if( ikepayload->ext.n->set_data(ikepayload,addr_len,cur_addr_lst->ip_addr.addr.raw) ){
					RHP_BUG("");
					goto error;
				}

				ikepayload->set_non_critical(ikepayload,1);

				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_INTERNAL_NET_IPV6_AUTOCONF_TX_UPDATED_ADDR_V4,"V4",vpn,cur_addr_lst->ip_addr.addr.v4);
			}

			cur_addr_lst = cur_addr_lst->next;
		}
  }
  {
  	int a;
  	u8 dup_test_v6[3][16] = { {0xfe,0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,0xd0,0xcb,0xc7,0xff,0xfe,0x02,0xd1,0x5c},
  														{0x20, 0x1, 0xd,0xb8, 0x1, 0x0, 0x0, 0x0,0xd0,0xcb,0xc7,0xff,0xfe,0x02,0xd1,0x5c},
  														{0x20, 0x1, 0xd,0xb8, 0x1, 0x0, 0x0, 0x0,0xd5,0xfb,0x7b,0x82,0x55,0x60,0xc5,0xdb}
  													};

  	for( a = 0; a < 3; a++ ){

  		rhp_ip_addr_list cur_addr_lst0;
  		rhp_ip_addr_list *cur_addr_lst = &cur_addr_lst0;

  		memset(&cur_addr_lst0,0,sizeof(rhp_ip_addr_list));

  		cur_addr_lst0.ip_addr.addr_family = AF_INET6;
  		cur_addr_lst0.ip_addr.prefixlen = 64;
  		memcpy(cur_addr_lst0.ip_addr.addr.raw,&(dup_test_v6[a][0]),16);

			rhp_ip_addr_dump("cur_addr_lst",&(cur_addr_lst->ip_addr));

			if( !rhp_ip_addr_null(&(cur_addr_lst->ip_addr)) ){

				rhp_ikev2_payload* ikepayload = NULL;
				int addr_len = 0;
				u16 msg_type = 0;

				if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
					RHP_BUG("");
					goto error;
				}

				tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

				ikepayload->ext.n->set_protocol_id(ikepayload,0);

				msg_type = RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_IP6_ADDRESS;
				addr_len = 16;

				ikepayload->ext.n->set_message_type(ikepayload,msg_type);

				if( ikepayload->ext.n->set_data(ikepayload,addr_len,cur_addr_lst->ip_addr.addr.raw) ){
					RHP_BUG("");
					goto error;
				}

				ikepayload->set_non_critical(ikepayload,1);

				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_INTERNAL_NET_IPV6_AUTOCONF_TX_UPDATED_ADDR_V6,"V6",vpn,cur_addr_lst->ip_addr.addr.v6);
			}
  	}
  }
#else
  {
  	rhp_ip_addr_list *cur_addr_lst = rlm->internal_ifc->addrs;
		while( cur_addr_lst ){

			rhp_ip_addr_dump("cur_addr_lst",&(cur_addr_lst->ip_addr));

			if( !rhp_ip_addr_null(&(cur_addr_lst->ip_addr)) ){

				rhp_ikev2_payload* ikepayload = NULL;
				int addr_len = 0;
				u16 msg_type = 0;

				if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
					RHP_BUG("");
					goto error;
				}

				tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

				ikepayload->ext.n->set_protocol_id(ikepayload,0);

				if( cur_addr_lst->ip_addr.addr_family == AF_INET ){
					msg_type = RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_IP4_ADDRESS;
					addr_len = 4;
				}else if( cur_addr_lst->ip_addr.addr_family == AF_INET6 ){
					msg_type = RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_IP6_ADDRESS;
					addr_len = 16;
				}

				ikepayload->ext.n->set_message_type(ikepayload,msg_type);

				if( ikepayload->ext.n->set_data(ikepayload,addr_len,cur_addr_lst->ip_addr.addr.raw) ){
					RHP_BUG("");
					goto error;
				}

				ikepayload->set_non_critical(ikepayload,1);

				if( cur_addr_lst->ip_addr.addr_family == AF_INET ){
					RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_INTERNAL_NET_IPV6_AUTOCONF_TX_UPDATED_ADDR_V4,"V4",vpn,cur_addr_lst->ip_addr.addr.v4);
				}else if( cur_addr_lst->ip_addr.addr_family == AF_INET6 ){
					RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_INTERNAL_NET_IPV6_AUTOCONF_TX_UPDATED_ADDR_V6,"V6",vpn,cur_addr_lst->ip_addr.addr.v6);
				}
			}

			cur_addr_lst = cur_addr_lst->next;
		}
  }
#endif // RHP_DBG_IPV6_AUTOCONF_TEST

  _rhp_ikev2_itnl_net_vif_add_old_addrs(vpn,rlm);
  tx_req = 1;


ignored:
error:
	if( rlm ){
	  RHP_UNLOCK(&(rlm->lock));
	}

	if( tx_ikemesg ){

		if( tx_req ){

			rhp_ikev2_send_request(vpn,NULL,tx_ikemesg,RHP_IKEV2_MESG_HANDLER_RHP_INTERNAL_NET);
		}

		rhp_ikev2_unhold_mesg(tx_ikemesg);
	}

  RHP_UNLOCK(&(vpn->lock));


	RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_IFC_NOTIFIER_CB_RTRN,"xxxd",vpn,ifcb_ctx,ifc,ifcb_ctx->exec_retry);
  return 0;
}

static void _rhp_ikev2_itnl_net_ifc_notifier_task(void* ctx)
{
	int err = -EINVAL;
	int if_index = (int)ctx;
	rhp_ifc_entry* ifc = NULL;
	rhp_ikev2_itnl_net_ifc_ctx* ifcx;
	unsigned long rlm_id;
	rhp_ikev2_itnl_net_cb_ctx ifcb_ctx;

	RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_IFC_NOTIFIER_TASK,"d",if_index);

	memset(&ifcb_ctx,0,sizeof(rhp_ikev2_itnl_net_cb_ctx));


	ifc = rhp_ifc_get_by_if_idx(if_index);
	if( ifc == NULL ){
		RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_IFC_NOTIFIER_TASK_NO_IFC,"d",if_index);
		err = -ENOENT;
		goto error;
	}

	{
		RHP_LOCK(&(_rhp_ikev2_itnl_net_lock));

		ifcx = _rhp_ikev2_itnl_net_ifcx_get(if_index);
		if( ifcx == NULL ){

			RHP_UNLOCK(&(_rhp_ikev2_itnl_net_lock));

			err = -ENOENT;
			goto error;
		}

		rlm_id = ifcx->rlm_id;

		ifcb_ctx.exec_retry = 0;
		ifcb_ctx.ifc_tmp = ifc;
		ifcb_ctx.retries = ifcx->retries;

		RHP_UNLOCK(&(_rhp_ikev2_itnl_net_lock));
	}

	{
		err = rhp_vpn_enum(rlm_id,_rhp_ikev2_itnl_net_ifc_notifier_cb,&ifcb_ctx);
		ifcb_ctx.ifc_tmp = NULL;
		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_IFC_NOTIFIER_TASK_ENUM_VPN_ERR,"dE",if_index,err);
			goto error;
		}
	}

error:
	{
		RHP_LOCK(&(_rhp_ikev2_itnl_net_lock));

		ifcx = _rhp_ikev2_itnl_net_ifcx_get(if_index);
		if( ifcx ){

			if( ifcb_ctx.exec_retry ){

				ifcx->retries++;

				err = rhp_timer_oneshot(_rhp_ikev2_itnl_net_ifc_notifier_task,(void*)if_index,
						(time_t)rhp_gcfg_ikev2_itnl_net_convergence_interval);
				if( err ){
					RHP_BUG("%d",err);
					goto retry_error;
				}

			}else{

retry_error:

				_rhp_ikev2_itnl_net_ifcx_delete(if_index);
				_rhp_free(ifcx);
			}
		}

		RHP_UNLOCK(&(_rhp_ikev2_itnl_net_lock));
	}

	if( ifc ){
		rhp_ifc_unhold(ifc);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_IFC_NOTIFIER_TASK_RTRN,"dxdE",if_index,ifcx,ifcb_ctx.exec_retry,err);
	return;
}

static void _rhp_ikev2_itnl_net_ifc_notifier(int event,rhp_ifc_entry* ifc,
		rhp_if_entry* new_info,rhp_if_entry* old_info,void* ctx)
{
	int err = -EINVAL;
	rhp_ikev2_itnl_net_ifc_ctx* ifcx = NULL;
	unsigned long rlm_id;

	RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_IFC_NOTIFIER,"Ldxxxx","IFC_EVT",event,ifc,new_info,old_info,ctx);

	if( !_rhp_atomic_read(&(ifc->is_active)) ){
		RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_IFC_NOT_ACTIVE,"Ldxxx","IFC_EVT",event,ifc,old_info,ctx);
		return;
	}

	if( old_info == NULL ){
		RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_IFC_NOTIFIER_IGNORED,"Ldxxx","IFC_EVT",event,ifc,old_info,ctx);
		return;
	}

  if( strstr(old_info->if_name,RHP_VIRTUAL_IF_NAME) == NULL ){
		RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_IFC_NOTIFIER_NOT_INTERESTED_IF,"Ldxxs","IFC_EVT",event,ifc,old_info,old_info->if_name);
		return;
  }

  if( old_info->addr_family != AF_INET6 && new_info->addr_family != AF_INET6 ){
		RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_IFC_NOTIFIER_NOT_V6_ADDR,"LdxxsLdLd","IFC_EVT",event,ifc,new_info,new_info->if_name,"AF",new_info->addr_family,"AF",old_info->addr_family);
  	return;
  }

	{
		RHP_LOCK(&(ifc->lock));

		if( new_info->addr_family == old_info->addr_family &&
				((new_info->addr_family == AF_INET  && (new_info->addr.v4 == old_info->addr.v4)) ||
				 (new_info->addr_family == AF_INET6 && !memcmp(new_info->addr.v6,old_info->addr.v6,16))) ){

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_INTERNAL_NET_IF_STATE_CHANGED_BUT_IGNORED_0,"Lsd","IFC_EVT",event,old_info->if_name,old_info->if_index);

			RHP_UNLOCK(&(ifc->lock));
			RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_IFC_NOTIFIER_NOT_CHANGED,"Ldxxs","IFC_EVT",event,ifc,old_info,old_info->if_name);
			return;
		}

		rlm_id = ifc->tuntap_vpn_realm_id;

		RHP_UNLOCK(&(ifc->lock));
	}


	RHP_LOCK(&(_rhp_ikev2_itnl_net_lock));
	{

		ifcx = _rhp_ikev2_itnl_net_ifcx_get(old_info->if_index);
		if( ifcx ){

			// Don't goto error_l and free ifcx here!

			RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_IFC_NOTIFIER_ALREADY_PENDING,"xsd",ifc,old_info->if_name,old_info->if_index);

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_INTERNAL_NET_IF_STATE_CHANGED_PENDING,"sd",old_info->if_name,old_info->if_index);

			RHP_UNLOCK(&(_rhp_ikev2_itnl_net_lock));

			return;
		}


		ifcx = _rhp_ikev2_itnl_net_ifcx_alloc(old_info->if_index,rlm_id);
		if( ifcx == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error_l;
		}


		err = rhp_timer_oneshot(_rhp_ikev2_itnl_net_ifc_notifier_task,(void*)old_info->if_index,
			(time_t)rhp_gcfg_ikev2_itnl_net_convergence_interval);

		if( !err ){

			ifcx->next = _rhp_ikev2_itnl_net_ifc_ctx_list;
			_rhp_ikev2_itnl_net_ifc_ctx_list = ifcx;

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_INTERNAL_NET_IF_STATE_CHANGED,"sd",old_info->if_name,ifcx->if_index);

		}else{

			RHP_BUG("");
			goto error_l;
		}
	}
	RHP_UNLOCK(&(_rhp_ikev2_itnl_net_lock));


	RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_IFC_NOTIFIER_RTRN,"xx",ifc,ifcx);
	return;

error_l:
	if( ifcx ){

		_rhp_ikev2_itnl_net_ifcx_delete(old_info->if_index);
		_rhp_free(ifcx);
	}

	RHP_UNLOCK(&(_rhp_ikev2_itnl_net_lock));

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_INTERNAL_NET_IF_STATE_CHANGED_ERR,"sdE",old_info->if_name,old_info->if_index,err);

	RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_IFC_NOTIFIER_ERR,"xE",ifc,err);
	return;
}



int rhp_ikev2_rx_internal_net_init()
{

	rhp_ifc_notifiers[RHP_IFC_NOTIFIER_ITNL_NET].callback = _rhp_ikev2_itnl_net_ifc_notifier;
  rhp_ifc_notifiers[RHP_IFC_NOTIFIER_ITNL_NET].ctx = NULL;
  RHP_LINE("rhp_ikev2_rx_internal_net_init() : 0x%x,0x%x",_rhp_ikev2_itnl_net_ifc_notifier,NULL);

  _rhp_mutex_init("MBK",&(_rhp_ikev2_itnl_net_lock));

	RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_INIT,"");
  return 0;
}

int rhp_ikev2_rx_internal_net_cleanup()
{
  _rhp_mutex_destroy(&(_rhp_ikev2_itnl_net_lock));

	RHP_TRC(0,RHPTRCID_IKEV2_INTERNAL_NET_CLEANUP,"");
	return 0;
}
