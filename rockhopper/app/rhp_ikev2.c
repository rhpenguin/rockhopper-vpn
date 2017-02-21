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
#include "rhp_eap_auth_impl.h"
#include "rhp_eap_sup_impl.h"
#include "rhp_http.h"
#include "rhp_radius_impl.h"
#include "rhp_radius_acct.h"

rhp_mutex_t rhp_ikev2_lock_statistics;
rhp_ikev2_global_statistics rhp_ikev2_statistics_global_tbl;

extern long rhp_ikesa_half_open_sessions_num_get();

void rhp_ikev2_get_statistics(rhp_ikev2_global_statistics* table)
{
	RHP_LOCK(&rhp_ikev2_lock_statistics);
	memcpy(table,&rhp_ikev2_statistics_global_tbl,sizeof(rhp_ikev2_global_statistics));
	RHP_UNLOCK(&rhp_ikev2_lock_statistics);

	table->dc.ikesa_half_open_num = rhp_ikesa_half_open_sessions_num_get();
	table->dc.qcd_pend_req_packets = rhp_ikev2_qcd_pend_req_num();
}

void rhp_ikev2_clear_statistics()
{
	RHP_LOCK(&rhp_ikev2_lock_statistics);
	memset(&rhp_ikev2_statistics_global_tbl,0,
			sizeof(rhp_ikev2_global_statistics) - sizeof(rhp_ikev2_global_statistics_dont_clear));
	RHP_UNLOCK(&rhp_ikev2_lock_statistics);
}


static rhp_ikev2_message_handler* _rhp_ikev2_mesg_handlers = NULL;

// NOT thread safe! Call this api only when process starts.
int rhp_ikev2_register_message_handler(int handler_type,
		RHP_IKEV2_MESG_HANDLER_TX_REQ send_request_mesg,
		RHP_IKEV2_MESG_HANDLER_RX_REQ_NO_VPN recv_request_mesg_no_vpn,
		RHP_IKEV2_MESG_HANDLER_RX_REQ recv_request_mesg,
		RHP_IKEV2_MESG_HANDLER_RX_RESP recv_response_mesg)
{
	rhp_ikev2_message_handler* handler;
	rhp_ikev2_message_handler *handler_p = NULL,*handler_n;

  RHP_TRC(0,RHPTRCID_IKEV2_REGISTER_MESSAGE_HANDLER,"LdYYYY","IKEV2_MESG_HDLR",handler_type,send_request_mesg,recv_request_mesg_no_vpn,recv_request_mesg,recv_response_mesg);

	handler = (rhp_ikev2_message_handler*)_rhp_malloc(sizeof(rhp_ikev2_message_handler));
	if( handler == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	memset(handler,0,sizeof(rhp_ikev2_message_handler));

	handler->tag[0] = '#';
	handler->tag[1] = 'I';
	handler->tag[2] = 'M';
	handler->tag[3] = 'H';

	handler->type = handler_type;

	handler->send_request_mesg = send_request_mesg;
	handler->recv_request_mesg_no_vpn = recv_request_mesg_no_vpn;
	handler->recv_request_mesg = recv_request_mesg;
	handler->recv_response_mesg = recv_response_mesg;

	handler_n = _rhp_ikev2_mesg_handlers;
	while( handler_n ){

		if( handler_n->type > handler->type ){
			break;
		}

		handler_p = handler_n;
		handler_n = handler_p->next;
	}

	if( handler_p == NULL ){
		handler->next = _rhp_ikev2_mesg_handlers;
		_rhp_ikev2_mesg_handlers = handler;
	}else{
		handler->next = handler_p->next;
		handler_p->next = handler;
	}

  RHP_TRC(0,RHPTRCID_IKEV2_REGISTER_MESSAGE_HANDLER_RTRN,"Ldx","IKEV2_MESG_HDLR",handler_type,handler);

	return 0;
}


// flag : RHP_IKEV2_SEND_REQ_FLAG_XXX
static int _rhp_ikev2_call_tx_request_mesg_handlers(rhp_ikev2_mesg* tx_req_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,int caller_type,int req_initiator)
{
	rhp_ikev2_message_handler* handler;
	int err;

	 RHP_TRC(0,RHPTRCID_IKEV2_CALL_TX_REQUEST_MESG_HANDLER,"xxLdGLdLd",tx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKEV2_MESG_HDLR",caller_type,"IKEV2_MESG_HDLR",req_initiator);

	if( caller_type == RHP_IKEV2_MESG_HANDLER_END ){
		RHP_TRC(0,RHPTRCID_IKEV2_CALL_TX_REQUEST_MESG_HANDLER_END,"xxLdLd",tx_req_ikemesg,vpn,"IKEV2_MESG_HDLR",caller_type,"IKEV2_MESG_HDLR",req_initiator);
		return 0;
	}

	handler = _rhp_ikev2_mesg_handlers;

	if( caller_type != RHP_IKEV2_MESG_HANDLER_START ){

		while( handler ){

			if( handler->type == caller_type ){
				handler = handler->next;
				break;
			}

			handler = handler->next;
		}
	}

	while( handler ){

		if( handler->send_request_mesg && (handler->type != req_initiator) ){

			RHP_TRC(0,RHPTRCID_IKEV2_CALL_TX_REQUEST_MESG_HANDLER_START_HDLR,"xxxLdY",tx_req_ikemesg,vpn,handler,"IKEV2_MESG_HDLR",handler->type,handler->send_request_mesg);

			err = handler->send_request_mesg(tx_req_ikemesg,vpn,my_ikesa_side,my_ikesa_spi,req_initiator);

			RHP_TRC(0,RHPTRCID_IKEV2_CALL_TX_REQUEST_MESG_HANDLER_END_HDLR,"xxxE",tx_req_ikemesg,vpn,handler,err);

		}else{
			err = 0;
		}

		if( err == RHP_STATUS_IKEV2_MESG_HANDLER_PENDING ){
			goto pending;
		}else if( err == RHP_STATUS_IKEV2_MESG_HANDLER_END ){
			err = 0;
			break;
		}else if( err ){

			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,( vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV2_TX_REQ_ERR,"VLE",vpn,"IKEV2_MESG_HDLR",handler->type,err);
			goto error;
		}

		handler = handler->next;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_CALL_TX_REQUEST_MESG_HANDLER_RTRN,"xxLdLd",tx_req_ikemesg,vpn,"IKEV2_MESG_HDLR",caller_type,"IKEV2_MESG_HDLR",req_initiator);
	return 0;

pending:
error:
	RHP_TRC(0,RHPTRCID_IKEV2_CALL_TX_REQUEST_MESG_HANDLER_ERR,"xxLdLdE",tx_req_ikemesg,vpn,"IKEV2_MESG_HDLR",caller_type,"IKEV2_MESG_HDLR",req_initiator,err);
	return err;
}

static int _rhp_ikev2_call_rx_request_mesg_handlers(rhp_ikev2_mesg* rx_req_ikemesg,rhp_vpn* vpn,
		int my_ike_side,u8* my_ike_spi,rhp_ikev2_mesg* tx_resp_ikemesg,int caller_type,
		rhp_vpn_ref** vpn_ref_r,int* my_ike_side_r,u8* my_ike_spi_r)
{
	rhp_ikev2_message_handler* handler;
	int err;
	int my_ike_side_i = -1;
	u8 my_ike_spi_i[RHP_PROTO_IKE_SPI_SIZE];
	rhp_vpn *vpn_i = NULL;

	 RHP_TRC(0,RHPTRCID_IKEV2_CALL_RX_REQUEST_MESG_HANDLERS,"xxLdGxLdxxx",rx_req_ikemesg,vpn,"IKE_SIDE",my_ike_side,my_ike_spi,tx_resp_ikemesg,"IKEV2_MESG_HDLR",caller_type,vpn_ref_r,my_ike_side_r,my_ike_spi_r);

	if( caller_type == RHP_IKEV2_MESG_HANDLER_END ){
		RHP_TRC(0,RHPTRCID_IKEV2_CALL_RX_REQUEST_MESG_HANDLERS_END,"xxLd",rx_req_ikemesg,vpn,"IKEV2_MESG_HDLR",caller_type);
		return 0;
	}

	handler = _rhp_ikev2_mesg_handlers;

	if( caller_type != RHP_IKEV2_MESG_HANDLER_START ){

		while( handler ){

			if( handler->type == caller_type ){
				handler = handler->next;
				break;
			}

			handler = handler->next;
		}
	}

	while( handler ){

		if( handler->recv_request_mesg_no_vpn ){

			RHP_TRC(0,RHPTRCID_IKEV2_CALL_RX_REQUEST_MESG_HANDLERS_NO_VPN_START_HDLR,"xxxLdY",rx_req_ikemesg,vpn,handler,"IKEV2_MESG_HDLR",handler->type,handler->recv_request_mesg_no_vpn);

			err = handler->recv_request_mesg_no_vpn(rx_req_ikemesg,tx_resp_ikemesg,&vpn_i,&my_ike_side_i,my_ike_spi_i);

			RHP_TRC(0,RHPTRCID_IKEV2_CALL_RX_REQUEST_MESG_HANDLERS_NO_VPN_END_HDLR,"xxxxLdGE",rx_req_ikemesg,vpn,handler,vpn_i,"IKE_SIDE",my_ike_side_i,my_ike_spi_i,err);

		}else if( handler->recv_request_mesg ){

			RHP_TRC(0,RHPTRCID_IKEV2_CALL_RX_REQUEST_MESG_HANDLERS_START_HDLR,"xxxLdY",rx_req_ikemesg,vpn,handler,"IKEV2_MESG_HDLR",handler->type,handler->recv_request_mesg);

			err = handler->recv_request_mesg(rx_req_ikemesg,vpn,my_ike_side,my_ike_spi,tx_resp_ikemesg);

			RHP_TRC(0,RHPTRCID_IKEV2_CALL_RX_REQUEST_MESG_HANDLERS_END_HDLR,"xxxE",rx_req_ikemesg,vpn,handler,err);

		}else{

			err = 0;
		}

		if( err == RHP_STATUS_IKEV2_MESG_HANDLER_PENDING ){

			goto pending;

		}else if( err == RHP_STATUS_IKEV2_MESG_HANDLER_END ){

			err = 0;
			break;

		}else if( err ){

			if( err == RHP_STATUS_PEER_NOTIFIED_ERROR ){

				if( vpn && vpn->exec_auto_reconnect ){

					RHP_TRC(0,RHPTRCID_IKEV2_CALL_RX_REQUEST_MESG_HANDLERS_CANCEL_AUTO_RECONNECT,"xx",rx_req_ikemesg,vpn);

					if( vpn->auto_reconnect ){
						RHP_LOG_W(RHP_LOG_SRC_VPNMNG,vpn->vpn_realm_id,RHP_LOG_ID_AUTO_RECONNECT_CANCELED,"d",vpn->auto_reconnect_retries);
					}

					vpn->exec_auto_reconnect = 0;
				}
			}

			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,( vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV2_RX_REQ_ERR,"VKLE",vpn,rx_req_ikemesg,"IKEV2_MESG_HDLR",handler->type,err);

			goto error;
		}

		if( vpn == NULL && vpn_i ){

			vpn = vpn_i;

			rhp_vpn_hold(vpn_i);
			RHP_LOCK(&(vpn_i->lock));

			if( my_ike_spi == NULL && my_ike_side_i != -1 ){
				my_ike_side = my_ike_side_i;
				my_ike_spi = my_ike_spi_i;
			}
		}

		handler = handler->next;
	}

	if( vpn_i ){

  	RHP_UNLOCK(&(vpn_i->lock));

  	if( vpn_ref_r ){
  		*vpn_ref_r = rhp_vpn_hold_ref(vpn_i);
  		*my_ike_side_r = my_ike_side;
  		memcpy(my_ike_spi_r,my_ike_spi,RHP_PROTO_IKE_SPI_SIZE);
  	}

  	rhp_vpn_unhold(vpn_i);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_CALL_RX_REQUEST_MESG_HANDLERS_RTRN,"xxxxLd",rx_req_ikemesg,vpn,vpn_i,(vpn_ref_r ? *vpn_ref_r : NULL),"IKEV2_MESG_HDLR",caller_type);
	return 0;

pending:
error:
	if( vpn_i ){
  	RHP_UNLOCK(&(vpn_i->lock));
		rhp_vpn_unhold(vpn_i);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_CALL_RX_REQUEST_MESG_HANDLERS_ERR,"xxxLdE",rx_req_ikemesg,vpn,vpn_i,"IKEV2_MESG_HDLR",caller_type,err);
	return err;
}

static int _rhp_ikev2_call_rx_response_mesg_handlers(rhp_ikev2_mesg* rx_resp_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_ikemesg,int caller_type)
{
	rhp_ikev2_message_handler* handler;
	int err;

	 RHP_TRC(0,RHPTRCID_IKEV2_CALL_RX_RESPONSE_MESG_HANDLERS,"xxLdxLd",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_ikemesg,"IKEV2_MESG_HDLR",caller_type);

	if( caller_type == RHP_IKEV2_MESG_HANDLER_END ){
		RHP_TRC(0,RHPTRCID_IKEV2_CALL_RX_RESPONSE_MESG_HANDLERS_END,"xxLd",rx_resp_ikemesg,vpn,"IKEV2_MESG_HDLR",caller_type);
		return 0;
	}

	handler = _rhp_ikev2_mesg_handlers;

	if( caller_type != RHP_IKEV2_MESG_HANDLER_START ){

		while( handler ){

			if( handler->type == caller_type ){
				handler = handler->next;
				break;
			}

			handler = handler->next;
		}
	}

	while( handler ){

		if( handler->recv_response_mesg ){

			RHP_TRC(0,RHPTRCID_IKEV2_CALL_RX_RESPONSE_MESG_HANDLERS_START_HDLR,"xxxLdYx",rx_resp_ikemesg,vpn,handler,"IKEV2_MESG_HDLR",handler->type,handler->recv_response_mesg,tx_ikemesg);

			err = handler->recv_response_mesg(rx_resp_ikemesg,vpn,my_ikesa_side,my_ikesa_spi,tx_ikemesg);

			RHP_TRC(0,RHPTRCID_IKEV2_CALL_RX_RESPONSE_MESG_HANDLERS_END_HDLR,"xxxxdE",rx_resp_ikemesg,vpn,handler,tx_ikemesg,tx_ikemesg->activated,err);

		}else{
			err = 0;
		}

		if( err == RHP_STATUS_IKEV2_MESG_HANDLER_PENDING ){

			goto pending;

		}else if( err == RHP_STATUS_IKEV2_MESG_HANDLER_END ){

			err = 0;
			break;

		}else if( err ){

			if( err == RHP_STATUS_PEER_NOTIFIED_ERROR ){

				if( vpn && vpn->exec_auto_reconnect ){

					RHP_TRC(0,RHPTRCID_IKEV2_CALL_RX_RESPONSE_MESG_HANDLERS_CANCEL_AUTO_RECONNECT,"xx",rx_resp_ikemesg,vpn);

					if( vpn->auto_reconnect ){
						RHP_LOG_W(RHP_LOG_SRC_VPNMNG,vpn->vpn_realm_id,RHP_LOG_ID_AUTO_RECONNECT_CANCELED,"d",vpn->auto_reconnect_retries);
					}

					vpn->exec_auto_reconnect = 0;
				}
			}

			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,( vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV2_RX_RESP_ERR,"VKLE",vpn,rx_resp_ikemesg,"IKEV2_MESG_HDLR",handler->type,err);

			goto error;
		}

		handler = handler->next;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_CALL_RX_RESPONSE_MESG_HANDLERS_RTRN,"xxLdxd",rx_resp_ikemesg,vpn,"IKEV2_MESG_HDLR",caller_type,tx_ikemesg,tx_ikemesg->activated);
	return 0;

pending:
error:
	RHP_TRC(0,RHPTRCID_IKEV2_CALL_RX_RESPONSE_MESG_HANDLERS_ERR,"xxLdE",rx_resp_ikemesg,vpn,"IKEV2_MESG_HDLR",caller_type,err);
	return err;
}


int rhp_ikev2_check_tx_addr(rhp_vpn* vpn,rhp_ikesa* tx_ikesa,rhp_ifc_entry* tx_ifc)
{
	int tx_addr_ok = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_CHECK_TX_ADDR,"xxs",tx_ikesa,tx_ifc,tx_ifc->if_name);

	RHP_LOCK(&(tx_ifc->lock));

	if( tx_ifc->get_addr(tx_ifc,vpn->local.if_info.addr_family,vpn->local.if_info.addr.raw) ){
		tx_addr_ok = 1;
	}

	RHP_UNLOCK(&(tx_ifc->lock));

	if( !tx_addr_ok ){
		RHP_TRC(0,RHPTRCID_IKEV2_CHECK_TX_ADDR_ERR,"xxsd",tx_ikesa,tx_ifc,tx_ifc->if_name,tx_addr_ok);
	}else{
		RHP_TRC(0,RHPTRCID_IKEV2_CHECK_TX_ADDR_RTRN,"xxsd",tx_ikesa,tx_ifc,tx_ifc->if_name,tx_addr_ok);
	}

	return tx_addr_ok;
}

static int _rhp_ikev2_tx_req_cur_ikesa_state_ok(rhp_ikesa* ikesa)
{
  if(	ikesa->state == RHP_IKESA_STAT_I_IKE_SA_INIT_SENT 	||
  		ikesa->state == RHP_IKESA_STAT_I_AUTH_SENT 					||
  		ikesa->state == RHP_IKESA_STAT_ESTABLISHED ){

  	RHP_TRC(0,RHPTRCID_IKEV2_SEND_REQUEST_OK,"xLd",ikesa,"IKESA_STAT",ikesa->state);
  	return 1;
  }

	RHP_TRC(0,RHPTRCID_IKEV2_SEND_REQUEST_NG,"xLd",ikesa,"IKESA_STAT",ikesa->state);
	return 0;
}

static rhp_ikesa* _rhp_ikev2_tx_req_get_cur_ikesa(rhp_vpn* vpn)
{
	rhp_ikesa* cur_ikesa = vpn->ikesa_list_head;

	while( cur_ikesa ){

  	// Newer one is adopted.
  	if( _rhp_ikev2_tx_req_cur_ikesa_state_ok(cur_ikesa) ){
  		break;
  	}

  	cur_ikesa = cur_ikesa->next_vpn_list;
  }

  return cur_ikesa;
}

static rhp_ikesa* _rhp_ikev2_tx_req_get_rekeying_ikesa(rhp_vpn* vpn)
{
	rhp_ikesa *ikesa = vpn->ikesa_list_head, *rekeying_ikesa = NULL, *old_ikesa = NULL;

	while( ikesa ){

		RHP_TRC(0,RHPTRCID_IKEV2_TX_REQ_GET_REKEYING_IKESA_IKESA,"xLdxx",ikesa,"IKESA_STAT",ikesa->state,rekeying_ikesa,old_ikesa);

		if( ikesa->state == RHP_IKESA_STAT_I_REKEY_SENT ){

			rekeying_ikesa = ikesa;

		}else if( old_ikesa == NULL &&
							ikesa->state == RHP_IKESA_STAT_REKEYING ){

			old_ikesa = ikesa;
		}

		ikesa = ikesa->next_vpn_list;
  }

	RHP_TRC(0,RHPTRCID_IKEV2_TX_REQ_GET_REKEYING_IKESA,"xLdxLd",rekeying_ikesa,"IKESA_STAT",(rekeying_ikesa ? rekeying_ikesa->state : -1),old_ikesa,"IKESA_STAT",(old_ikesa ? old_ikesa->state : -1));
  return (rekeying_ikesa && old_ikesa ? old_ikesa : NULL);
}

void rhp_ikev2_finalize_tx_request(rhp_vpn* vpn,rhp_ikesa* tx_ikesa,rhp_ikev2_mesg* tx_ikemesg)
{
	tx_ikemesg->set_init_spi(tx_ikemesg,tx_ikesa->init_spi);
	tx_ikemesg->set_resp_spi(tx_ikemesg,tx_ikesa->resp_spi);

  if( tx_ikesa->side == RHP_IKE_INITIATOR ){
  	tx_ikemesg->tx_ikeh->flag = (tx_ikemesg->tx_ikeh->flag | RHP_PROTO_IKE_HDR_SET_INITIATOR);
  }

  tx_ikemesg->set_mesg_id(tx_ikemesg,++(tx_ikesa->req_message_id));

  return;
}

static rhp_ifc_entry* _rhp_ikev2_tx_request_get_ifc(rhp_vpn* vpn,rhp_packet* pkt)
{
	int tx_if_index;
	rhp_ifc_entry* tx_ifc;

	if( pkt->fixed_tx_if_index >= 0 ){

		tx_if_index = pkt->fixed_tx_if_index;

	}else if( rhp_ikev2_mobike_pending(vpn) ){

  	if( vpn->origin_side == RHP_IKE_RESPONDER ){

  		tx_if_index = vpn->mobike.resp.rt_ck_pend_local_if_info.if_index;

  	}else{

  		// RHP_IKE_INITIATOR

  		rhp_mobike_path_map* pmap;

  		if( vpn->mobike.init.cand_path_maps_num && vpn->mobike.init.cand_path_maps &&
  				vpn->mobike.init.cand_path_maps_cur_idx < vpn->mobike.init.cand_path_maps_num ){

  			pmap = &(vpn->mobike.init.cand_path_maps[vpn->mobike.init.cand_path_maps_cur_idx]);
  			tx_if_index = pmap->my_if_info.if_index;

  		}else{

  			tx_if_index = vpn->local.if_info.if_index;
  		}
  	}

  }else{

  	tx_if_index = vpn->local.if_info.if_index;
	}

	tx_ifc = rhp_ifc_get_by_if_idx(tx_if_index);
	if( tx_ifc == NULL ){
		return NULL;
	}

	return tx_ifc;
}

static void _rhp_ikev2_send_request(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* tx_ikemesg,
		int caller_type,int req_initiator)
{
	int err = -EINVAL;
  rhp_ikesa *cur_ikesa = NULL,*fixed_ikesa = NULL,*tx_ikesa;
  rhp_ikev2_mesg *enum_ikemesg = NULL,*enum_ikemesg_n;
  int i;
  int my_ikesa_side = -1;
  u8* my_ikesa_spi = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_SEND_REQUEST_L,"xxxLdLddd",vpn,ikesa,tx_ikemesg,"IKEV2_MESG_HDLR",caller_type,"IKEV2_MESG_HDLR",req_initiator,vpn->exec_mobike,(vpn->origin_side == RHP_IKE_INITIATOR ? vpn->mobike.init.rt_ck_pending : vpn->mobike.resp.rt_ck_pending));

  if( tx_ikemesg && !tx_ikemesg->activated ){
  	RHP_BUG("");
  }

  if( (tx_ikemesg == NULL) && (ikesa != NULL) ){
  	RHP_BUG("");
  	return;
  }

  if( ikesa ){
    my_ikesa_side = ikesa->side;
    my_ikesa_spi = ikesa->get_my_spi(ikesa);
  }

  if( tx_ikemesg ){

    if( tx_ikemesg->tx_ikesa_fixed ){

    	ikesa = vpn->ikesa_get(vpn,tx_ikemesg->ikesa_my_side,tx_ikemesg->ikesa_my_spi);
    	if( ikesa == NULL ){
        RHP_BUG("");
        err = -ENOENT;
        goto error;
    	}

    }else if( ikesa ){

      tx_ikemesg->ikesa_my_side = ikesa->side;
      memcpy(tx_ikemesg->ikesa_my_spi,ikesa->get_my_spi(ikesa),RHP_PROTO_IKE_SPI_SIZE);

      tx_ikemesg->tx_ikesa_fixed = 1;
    }
  }


  cur_ikesa = _rhp_ikev2_tx_req_get_cur_ikesa(vpn);
  if( cur_ikesa == NULL ){

  	cur_ikesa = _rhp_ikev2_tx_req_get_rekeying_ikesa(vpn);
  }

  if( cur_ikesa ){

  	RHP_TRC(0,RHPTRCID_IKEV2_SEND_REQUEST_L_CUR_IKESA,"xxxxLdGGLd",vpn,ikesa,tx_ikemesg,cur_ikesa,"IKE_SIDE",cur_ikesa->side,cur_ikesa->init_spi,cur_ikesa->resp_spi,"IKESA_STAT",cur_ikesa->state);

  	if( my_ikesa_side == -1 ){
      my_ikesa_side = cur_ikesa->side;
      my_ikesa_spi = cur_ikesa->get_my_spi(cur_ikesa);
  	}
  }


  if( tx_ikemesg ){

  	if( (tx_ikemesg->tx_flag & RHP_IKEV2_SEND_REQ_FLAG_BUSY_SKIP) ){

  		if( ikesa ){

  			if( ikesa->req_retx_pkt ||
  					(ikesa->state != RHP_IKESA_STAT_ESTABLISHED) ){
  				RHP_TRC(0,RHPTRCID_IKEV2_SEND_REQUEST_L_BUSY_SKIP_1,"xxxxxLd",vpn,ikesa,tx_ikemesg,cur_ikesa,ikesa->req_retx_pkt,"IKESA_STAT",ikesa->state);
  				err = -EBUSY;
  				goto error;
        }

    	}else{

    		if( (cur_ikesa == NULL) ||
    				 cur_ikesa->req_retx_pkt ||
    				 (cur_ikesa->state != RHP_IKESA_STAT_ESTABLISHED) ){

    				if( cur_ikesa == NULL ){
    					RHP_TRC(0,RHPTRCID_IKEV2_SEND_REQUEST_L_BUSY_SKIP_2,"xxxx",vpn,ikesa,tx_ikemesg,cur_ikesa);
    				}else{
    					RHP_TRC(0,RHPTRCID_IKEV2_SEND_REQUEST_L_BUSY_SKIP_3,"xxxxxLd",vpn,ikesa,tx_ikemesg,cur_ikesa,cur_ikesa->req_retx_pkt,"IKESA_STAT",cur_ikesa->state);
    				}

    				err = -EBUSY;
    				goto error;
        }
      }
    }

  	if( my_ikesa_side == -1 || my_ikesa_spi ){

  		err = _rhp_ikev2_call_tx_request_mesg_handlers(tx_ikemesg,vpn,my_ikesa_side,my_ikesa_spi,caller_type,req_initiator);

			if( err == RHP_STATUS_IKEV2_MESG_HANDLER_PENDING ){

				RHP_TRC(0,RHPTRCID_IKEV2_SEND_REQUEST_L_MESG_HANDLER_PENDING,"xxx",vpn,ikesa,tx_ikemesg);
				goto pending;

			}else if( err ){

      	rhp_ikev2_g_statistics_inc(tx_ikev2_req_process_err_packets);

				RHP_TRC(0,RHPTRCID_IKEV2_SEND_REQUEST_L_MESG_HANDLER_ERR,"xxxE",vpn,ikesa,tx_ikemesg,err);
				goto error;
			}

  	}else{

			RHP_TRC(0,RHPTRCID_IKEV2_SEND_REQUEST_L_MESG_HANDLER_NO_IKESA,"xxx",vpn,ikesa,tx_ikemesg);
  	}


  	if( (tx_ikemesg->tx_flag & RHP_IKEV2_SEND_REQ_FLAG_URGENT) ){

    	RHP_TRC(0,RHPTRCID_IKEV2_SEND_REQUEST_L_URGENT,"xxx",vpn,ikesa,tx_ikemesg);

 	  	rhp_ikev2_hold_mesg(tx_ikemesg);
  		rhp_ikemesg_q_enq(&(vpn->req_tx_ikemesg_q[RHP_VPN_TX_IKEMESG_Q_URG]),tx_ikemesg);

  	}else{

 	  	rhp_ikev2_hold_mesg(tx_ikemesg);
  		rhp_ikemesg_q_enq(&(vpn->req_tx_ikemesg_q[RHP_VPN_TX_IKEMESG_Q_NORMAL]),tx_ikemesg);
    }

    tx_ikemesg = NULL;
  }


  for( i = 0; i < RHP_VPN_TX_IKEMESG_Q_NUM; i++ ){

 		enum_ikemesg = rhp_ikemesg_q_peek(&(vpn->req_tx_ikemesg_q[i]));

	  while( enum_ikemesg ){

	  	rhp_packet* tx_pkt = NULL;

	  	tx_ikesa = NULL;
	  	enum_ikemesg_n = enum_ikemesg->next;

			RHP_TRC_FREQ(0,RHPTRCID_IKEV2_SEND_REQUEST_L_TX_Q_PEEK,"xxdxdY",vpn,enum_ikemesg,enum_ikemesg->tx_ikesa_fixed,cur_ikesa,enum_ikemesg->mobike_probe_req,enum_ikemesg->packet_serialized);

	  	if( !(enum_ikemesg->tx_ikesa_fixed) ){

	  		tx_ikesa = cur_ikesa;

	  	}else{

	  		fixed_ikesa = vpn->ikesa_get(vpn,enum_ikemesg->ikesa_my_side,enum_ikemesg->ikesa_my_spi);

	   	  if( fixed_ikesa == NULL ){

	  			RHP_TRC_FREQ(0,RHPTRCID_IKEV2_SEND_REQUEST_L_OlD_IKESA_ALREADY_DELETED,"xxLdG",vpn,enum_ikemesg,"IKE_SIDE",enum_ikemesg->ikesa_my_side,enum_ikemesg->ikesa_my_spi);

	   	  	//
	   	  	// Old IKE SA that have already been deleted. Cleanup Queued ikemesg...
	   	  	//

	   	  	rhp_ikemesg_q_remove(&(vpn->req_tx_ikemesg_q[i]),enum_ikemesg);
	   	  	rhp_ikev2_unhold_mesg(enum_ikemesg);

	      	rhp_ikev2_g_statistics_inc(tx_ikev2_req_no_ikesa_err_packets);

	   	  	goto next;
	   	  }

	   	  tx_ikesa = fixed_ikesa;
	  	}

	  	if( tx_ikesa == NULL ){

  			RHP_TRC_FREQ(0,RHPTRCID_IKEV2_SEND_REQUEST_L_NO_IKESA_TO_TX,"xx",vpn,enum_ikemesg);

      	rhp_ikev2_g_statistics_inc(tx_ikev2_req_no_ikesa_err_packets);

	  		goto next;

	  	}else{

  			RHP_TRC_FREQ(0,RHPTRCID_IKEV2_SEND_REQUEST_L_TX_IKESA_FOUND,"xxxLdGx",vpn,enum_ikemesg,tx_ikesa,"IKE_SIDE",tx_ikesa->side,tx_ikesa->get_my_spi(tx_ikesa),tx_ikesa->req_retx_ikemesg);
	  	}

	  	if( tx_ikesa->req_retx_ikemesg ){

	  		//
	  		// The other message is on the fly... (WinSize == 1) Skip!
	  		//

  			RHP_TRC_FREQ(0,RHPTRCID_IKEV2_SEND_REQUEST_L_OTHER_MESG_ON_THE_FLY,"xxxLdGx",vpn,enum_ikemesg,tx_ikesa,"IKE_SIDE",tx_ikesa->side,tx_ikesa->get_my_spi(tx_ikesa),tx_ikesa->req_retx_ikemesg);

      	rhp_ikev2_g_statistics_inc(tx_ikev2_req_queued_packets);

	  		goto next;
	  	}


	  	rhp_ikemesg_q_remove(&(vpn->req_tx_ikemesg_q[i]),enum_ikemesg); //(**)

	  	{
				rhp_ikev2_finalize_tx_request(vpn,tx_ikesa,enum_ikemesg);

				err = enum_ikemesg->serialize(enum_ikemesg,vpn,tx_ikesa,&tx_pkt);
				if( err ){

					RHP_TRC(0,RHPTRCID_IKEV2_SEND_REQUEST_L_NETSOCK_SEND_SERIALIZE_PKT_ERR,"xxxuE",vpn,tx_ikesa,enum_ikemesg,err);

					rhp_ikev2_g_statistics_inc(tx_ikev2_req_alloc_packet_err);

					goto error;
				}

				enum_ikemesg->tx_pkt = tx_pkt;
				rhp_pkt_hold(tx_pkt);
	  	}

	  	tx_ikesa->set_retrans_request(tx_ikesa,tx_pkt);

  	  tx_ikesa->req_retx_ikemesg = enum_ikemesg;
  	  rhp_ikev2_hold_mesg(enum_ikemesg);

  	  if( enum_ikemesg->packet_serialized ){

  	  	enum_ikemesg->packet_serialized(vpn,tx_ikesa,enum_ikemesg,tx_pkt);
  	  }


  	  // If duplication of pkt_d is failed, this timer will retry it.
  	  tx_ikesa->timers->start_retransmit_timer(vpn,tx_ikesa,0);

  	  {
  	  	rhp_ifc_entry* tx_ifc = NULL;

				tx_ifc = _rhp_ikev2_tx_request_get_ifc(vpn,tx_pkt); // (***)
				if( tx_ifc == NULL ){

					RHP_TRC(0,RHPTRCID_IKEV2_SEND_REQUEST_L_NETSOCK_SEND_NO_TX_IFC,"xxxu",vpn,tx_ikesa,enum_ikemesg,vpn->local.if_info.if_index);
					rhp_ikev2_g_statistics_inc(tx_ikev2_req_no_if_err_packets);

				}else{

					rhp_packet* tx_pkt_d = rhp_pkt_dup(tx_pkt);
					if( tx_pkt_d ){

						if( enum_ikemesg->mobike_probe_req ||
								rhp_ikev2_check_tx_addr(vpn,tx_ikesa,tx_ifc) ){

							tx_pkt_d->tx_ifc = tx_ifc;
							rhp_ifc_hold(tx_pkt_d->tx_ifc);

							err = rhp_netsock_send(tx_pkt_d->tx_ifc,tx_pkt_d);
							if( err < 0 ){
								RHP_TRC(0,RHPTRCID_IKEV2_SEND_REQUEST_L_NETSOCK_SEND_ERR,"xxxE",vpn,tx_ikesa,enum_ikemesg,err);
							}

						}else{

							rhp_ikev2_g_statistics_inc(tx_ikev2_req_no_if_err_packets);
						}
						err = 0;

						rhp_pkt_unhold(tx_pkt_d);

					}else{

						RHP_TRC(0,RHPTRCID_IKEV2_SEND_REQUEST_L_NETSOCK_SEND_NO_MEM_ERROR,"xxx",vpn,tx_ikesa,enum_ikemesg);
						rhp_ikev2_g_statistics_inc(tx_ikev2_req_alloc_packet_err);
					}

					rhp_pkt_unhold(tx_pkt);

					rhp_ifc_unhold(tx_ifc); // (***)
				}

				rhp_ikev2_unhold_mesg(enum_ikemesg); // (**)
  	  }

next:
			enum_ikemesg = enum_ikemesg_n;
	  }
  }

pending:
	RHP_TRC(0,RHPTRCID_IKEV2_SEND_REQUEST_L_RTRN,"xxx",vpn,ikesa,cur_ikesa);
	return;

error:
	rhp_ikev2_g_statistics_inc(tx_ikev2_req_err_packets);

	RHP_TRC(0,RHPTRCID_IKEV2_SEND_REQUEST_L_ERR,"xxE",vpn,ikesa,err);
	return;
}

static int _rhp_ikev2_tx_response_mobike(rhp_vpn* vpn,rhp_ikev2_mesg* tx_ikemesg,rhp_packet* rx_pkt)
{
	int err = -EINVAL;

  RHP_TRC(0,RHPTRCID_IKEV2_TX_RESPONSE_MOBIKE,"xxx",vpn,tx_ikemesg,rx_pkt);

	tx_ikemesg->fixed_src_addr = (rhp_ip_addr*)_rhp_malloc(sizeof(rhp_ip_addr));
	tx_ikemesg->fixed_dst_addr = (rhp_ip_addr*)_rhp_malloc(sizeof(rhp_ip_addr));

	if( tx_ikemesg->fixed_src_addr == NULL || tx_ikemesg->fixed_dst_addr == NULL ){
		RHP_BUG("");
    err = -ENOMEM;
    goto error;
	}

	memset(tx_ikemesg->fixed_src_addr,0,sizeof(rhp_ip_addr));
	memset(tx_ikemesg->fixed_dst_addr,0,sizeof(rhp_ip_addr));

  if( rx_pkt->type == RHP_PKT_IPV4_IKE ){

		tx_ikemesg->fixed_src_addr->addr_family = AF_INET;
		tx_ikemesg->fixed_src_addr->addr.v4 = rx_pkt->l3.iph_v4->dst_addr;

		tx_ikemesg->fixed_dst_addr->addr_family = AF_INET;
		tx_ikemesg->fixed_dst_addr->addr.v4 = rx_pkt->l3.iph_v4->src_addr;

  }else if( rx_pkt->type == RHP_PKT_IPV6_IKE ){

		tx_ikemesg->fixed_src_addr->addr_family = AF_INET6;
		memcpy(tx_ikemesg->fixed_src_addr->addr.v6,rx_pkt->l3.iph_v6->dst_addr,16);

		tx_ikemesg->fixed_dst_addr->addr_family = AF_INET6;
		memcpy(tx_ikemesg->fixed_dst_addr->addr.v6,rx_pkt->l3.iph_v6->src_addr,16);

  }else{
		RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

	tx_ikemesg->fixed_src_addr->port = 0;
	tx_ikemesg->fixed_dst_addr->port = rx_pkt->l4.udph->src_port;

	tx_ikemesg->fixed_tx_if_index = rx_pkt->rx_if_index;

  RHP_TRC(0,RHPTRCID_IKEV2_TX_RESPONSE_MOBIKE_RTRN,"xxxd",vpn,tx_ikemesg,rx_pkt,tx_ikemesg->fixed_tx_if_index);
  rhp_ip_addr_dump("fixed_src_addr",tx_ikemesg->fixed_src_addr);
  rhp_ip_addr_dump("fixed_dst_addr",tx_ikemesg->fixed_dst_addr);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_TX_RESPONSE_MOBIKE_ERR,"xxxE",vpn,tx_ikemesg,rx_pkt,err);
	return err;
}

static void _rhp_ikev2_send_response(rhp_vpn* vpn,rhp_ikesa* tx_ikesa,rhp_ikev2_mesg* tx_ikemesg,
		rhp_ikev2_mesg* rx_ikemesg,rhp_packet* rx_pkt)
{
  int err = 0;
  rhp_packet *tx_pkt = NULL,*tx_pkt_d = NULL;
  rhp_ifc_entry* tx_ifc = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_SEND_RESPONSE,"xxxxx",tx_ikesa,tx_ikemesg,rx_ikemesg,rx_pkt);

  if( rx_ikemesg ){
  	rx_pkt = rx_ikemesg->rx_pkt;
  }

  if( rx_pkt == NULL ){
  	RHP_BUG("");
  	return;
  }

  if( !tx_ikemesg->activated ){
  	RHP_BUG("");
  	return;
  }


  tx_ikemesg->set_init_spi(tx_ikemesg,tx_ikesa->init_spi);
  tx_ikemesg->set_resp_spi(tx_ikemesg,tx_ikesa->resp_spi);

  tx_ikemesg->tx_ikeh->flag = (tx_ikemesg->tx_ikeh->flag | RHP_PROTO_IKE_HDR_SET_RESPONSE);

  if( tx_ikesa->side == RHP_IKE_INITIATOR ){
    tx_ikemesg->tx_ikeh->flag = (tx_ikemesg->tx_ikeh->flag | RHP_PROTO_IKE_HDR_SET_INITIATOR);
  }

	if( rx_pkt->l4.udph->dst_port == vpn->local.port_nat_t ){
  	tx_ikemesg->tx_from_nat_t_port = 1;
	}


  if( vpn->exec_mobike ){

  	err = _rhp_ikev2_tx_response_mobike(vpn,tx_ikemesg,rx_pkt);
  	if( err ){

  		rhp_ikev2_g_statistics_inc(tx_ikev2_resp_process_err_packets);
      goto error;
  	}
  }


  err = tx_ikemesg->serialize(tx_ikemesg,vpn,tx_ikesa,&tx_pkt);
	if( err ){

  	RHP_BUG("");
  	rhp_ikev2_g_statistics_inc(tx_ikev2_resp_process_err_packets);

    goto error;
  }
  tx_ikemesg->tx_pkt = tx_pkt;
  rhp_pkt_hold(tx_pkt);


  {
    int tx_if_index = -1;

  	if( tx_ikemesg->fixed_tx_if_index >= 0 ){
  		tx_if_index = tx_ikemesg->fixed_tx_if_index;
  	}else{
  		tx_if_index = vpn->local.if_info.if_index;
  	}

  	tx_ifc = rhp_ifc_get_by_if_idx(tx_if_index);  // (***)
	 	if( tx_ifc == NULL ){

	 		RHP_BUG("");

	 		rhp_ikev2_g_statistics_inc(tx_ikev2_resp_process_err_packets);
	    goto error;
	 	}
  }


  tx_ikesa->set_retrans_reply(tx_ikesa,tx_pkt);

  if( err == 0 && tx_ikemesg->packet_serialized ){

  	tx_ikemesg->packet_serialized(vpn,tx_ikesa,tx_ikemesg,tx_pkt);
  }


	tx_pkt_d = rhp_pkt_dup(tx_pkt);
	if( tx_pkt_d ){

		tx_pkt_d->tx_ifc = tx_ifc;
		rhp_ifc_hold(tx_pkt_d->tx_ifc);

		if( rhp_ikev2_check_tx_addr(vpn,tx_ikesa,tx_pkt_d->tx_ifc) ){

			err = rhp_netsock_send(tx_pkt_d->tx_ifc,tx_pkt_d);
			if( err < 0 ){
				RHP_TRC(0,RHPTRCID_IKEV2_SEND_RESPONSE_TX_ERR,"xxxxxE",tx_ikesa,tx_ikemesg,rx_ikemesg,tx_pkt_d->tx_ifc,tx_pkt_d,err);
			}

		}else{

			rhp_ikev2_g_statistics_inc(tx_ikev2_resp_no_if_err_packets);
		}

		err = 0;

		rhp_pkt_unhold(tx_pkt_d);

	}else{

		RHP_BUG("");
	}

	rhp_pkt_unhold(tx_pkt);

	rhp_ifc_unhold(tx_ifc); // (***)


	RHP_TRC(0,RHPTRCID_IKEV2_SEND_RESPONSE_RTRN,"xxxxE",tx_ikesa,tx_ikemesg,rx_ikemesg,rx_pkt,err);
	return;

error:
	if( tx_pkt ){
		rhp_pkt_unhold(tx_pkt);
	}

	if( tx_ifc ){
  	rhp_ifc_unhold(tx_ifc); // (***)
	}

	rhp_ikev2_g_statistics_inc(tx_ikev2_resp_err_packets);

	RHP_TRC(0,RHPTRCID_IKEV2_SEND_RESPONSE_ERR,"xxxxE",tx_ikesa,tx_ikemesg,rx_ikemesg,rx_pkt,err);
	return;
}

static int _rhp_ikev2_send_radius_acct_start(rhp_vpn* vpn)
{
	if( vpn == NULL ){
		RHP_BUG("");
		return 0;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_SEND_RADIUS_ACCT_START,"xbxLdxLdLdbb",vpn,vpn->established,vpn->ikesa_list_head,"IKESA_STAT",(vpn->ikesa_list_head ? vpn->ikesa_list_head->state : 0),vpn->childsa_list_head,"CHILDSA_STAT",(vpn->childsa_list_head ? vpn->childsa_list_head->state : 0),"EAP_TYPE",vpn->eap.eap_method,vpn->radius.acct_enabled,vpn->radius.acct_tx_start_notify);

	if( vpn->established &&
			vpn->ikesa_list_head &&
			(vpn->ikesa_list_head->state == RHP_IKESA_STAT_ESTABLISHED ||
			 vpn->ikesa_list_head->state == RHP_IKESA_STAT_V1_ESTABLISHED) &&
			vpn->childsa_list_head &&
			(vpn->childsa_list_head->state == RHP_CHILDSA_STAT_MATURE ||
			 vpn->childsa_list_head->state == RHP_IPSECSA_STAT_V1_MATURE) &&
			vpn->eap.eap_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS &&
			vpn->radius.acct_enabled &&
			!vpn->radius.acct_tx_start_notify ){

		rhp_radius_acct_send(vpn,RHP_RADIUS_ATTR_TYPE_ACCT_STATUS_START,0);

		vpn->radius.acct_tx_start_notify = 1;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_SEND_RADIUS_ACCT_START_RTRN,"xbxLdxLdLdbb",vpn,vpn->established,vpn->ikesa_list_head,"IKESA_STAT",(vpn->ikesa_list_head ? vpn->ikesa_list_head->state : 0),vpn->childsa_list_head,"CHILDSA_STAT",(vpn->childsa_list_head ? vpn->childsa_list_head->state : 0),"EAP_TYPE",vpn->eap.eap_method,vpn->radius.acct_enabled,vpn->radius.acct_tx_start_notify);
	return 0;
}


void rhp_ikev2_call_next_tx_request_mesg_handlers(rhp_ikev2_mesg* tx_req_ikemesg,
		rhp_vpn* vpn,int my_ikesa_side,u8* my_ikesa_spi,int caller_type,int req_initiator)
{
	rhp_ikesa* ikesa = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_CALL_NEXT_TX_REQUEST_MESG_HANDLERS,"xxLdGLdLd",tx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKEV2_MESG_HDLR",caller_type,"IKEV2_MESG_HDLR",req_initiator);

	if( my_ikesa_spi ){

		ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
		if( ikesa == NULL ){
			RHP_BUG("");
			goto error;
		}
	}

	_rhp_ikev2_send_request(vpn,ikesa,tx_req_ikemesg,caller_type,req_initiator);

error:
	RHP_TRC(0,RHPTRCID_IKEV2_CALL_NEXT_TX_REQUEST_MESG_HANDLERS_RTRN,"xxLdLd",tx_req_ikemesg,vpn,"IKEV2_MESG_HDLR",caller_type,"IKEV2_MESG_HDLR",req_initiator);
	return;
}

void rhp_ikev2_call_next_rx_request_mesg_handlers(rhp_ikev2_mesg* rx_req_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_resp_ikemesg,int caller_type)
{
	int err;
	int do_destroy_vpn = 0;

	RHP_TRC(0,RHPTRCID_IKEV2_CALL_NEXT_RX_REQUEST_MESG_HANDLERS,"xxLdGxLd",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_resp_ikemesg,"IKEV2_MESG_HDLR",caller_type);

	if( my_ikesa_spi == NULL ){
		RHP_BUG("");
		goto error;
	}

	err = _rhp_ikev2_call_rx_request_mesg_handlers(rx_req_ikemesg,vpn,my_ikesa_side,my_ikesa_spi,
					tx_resp_ikemesg,caller_type,NULL,NULL,NULL);

	if( err == RHP_STATUS_IKEV2_MESG_HANDLER_PENDING ){

		if( rx_req_ikemesg->rx_pkt ){
			rhp_pkt_pending(rx_req_ikemesg->rx_pkt);
		}

		goto pending;

	}else if( err == RHP_STATUS_IKEV2_DESTROY_SA_AFTER_TX ){

		do_destroy_vpn = 1;

	}else if( err ){

		goto error;
	}

	if( tx_resp_ikemesg->activated ){

		rhp_ikesa* ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
		if( ikesa == NULL ){
			RHP_BUG("");
			err = -ENOENT;
			goto error;
		}

		_rhp_ikev2_send_response(vpn,ikesa,tx_resp_ikemesg,rx_req_ikemesg,NULL);

		if( do_destroy_vpn ){

			rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
			ikesa->timers->schedule_delete(vpn,ikesa,0);
		}
	}

	_rhp_ikev2_send_radius_acct_start(vpn);

pending:
error:
	RHP_TRC(0,RHPTRCID_IKEV2_CALL_NEXT_RX_REQUEST_MESG_HANDLERS_RTRN,"xxLd",rx_req_ikemesg,vpn,"IKEV2_MESG_HDLR",caller_type);
	return;
}

void rhp_ikev2_call_next_rx_response_mesg_handlers(rhp_ikev2_mesg* rx_resp_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_next_req_ikemesg,int caller_type)
{
	int err;
	int do_destroy_vpn = 0;

	RHP_TRC(0,RHPTRCID_IKEV2_CALL_NEXT_RX_RESPONSE_MESG_HANDLERS,"xxLdGxLd",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_next_req_ikemesg,"IKEV2_MESG_HDLR",caller_type);

	if( my_ikesa_spi == NULL ){
		RHP_BUG("");
		goto error;
	}

	err = _rhp_ikev2_call_rx_response_mesg_handlers(rx_resp_ikemesg,
					vpn,my_ikesa_side,my_ikesa_spi,tx_next_req_ikemesg,caller_type);

	if( err == RHP_STATUS_IKEV2_MESG_HANDLER_PENDING ){

		if( rx_resp_ikemesg->rx_pkt ){
			rhp_pkt_pending(rx_resp_ikemesg->rx_pkt);
		}

		goto pending;

	}else if( err == RHP_STATUS_IKEV2_DESTROY_SA_AFTER_TX ){

		do_destroy_vpn = 1;

	}else if( err ){

		goto error;
	}

	if( tx_next_req_ikemesg->activated ){

		rhp_ikesa* ikesa = NULL;

		if( my_ikesa_spi ){

			ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
		}

		rhp_ikev2_send_request(vpn,ikesa,tx_next_req_ikemesg,RHP_IKEV2_MESG_HANDLER_START);

		if( do_destroy_vpn ){

			rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
			ikesa->timers->schedule_delete(vpn,ikesa,0);
		}

	}else{

		rhp_ikev2_send_request(vpn,NULL,NULL,RHP_IKEV2_MESG_HANDLER_START); // Send a Qed request packet , if any.
	}

	_rhp_ikev2_send_radius_acct_start(vpn);

pending:
error:
	RHP_TRC(0,RHPTRCID_IKEV2_CALL_NEXT_RX_RESPONSE_MESG_HANDLERS_RTRN,"xxLd",rx_resp_ikemesg,vpn,"IKEV2_MESG_HDLR",caller_type);
	return;
}


static int _rhp_ikev2_rx_verify_response(rhp_packet* pkt,int qcd_err_resp,rhp_vpn_ref** vpn_ref_r)
{
  int err = -EINVAL;
  u8 exchange_type;
  rhp_proto_ike *ikeh = pkt->app.ikeh,*ikeh_r;
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;
  rhp_ikesa* ikesa = NULL;
  int my_side = 0;
  u8* my_spi = NULL;
  rhp_packet* pkt_r = NULL;
  rhp_vpn_realm* rlm = NULL;
  int eap_sup_enabled = 0;
  int rx_frag_completed = 0;
  int src_addr_changed = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP,"xx",pkt,vpn_ref_r);

  if( pkt->type != RHP_PKT_IPV4_IKE && pkt->type != RHP_PKT_IPV6_IKE ){
  	RHP_BUG("%d",pkt->type);
  	goto error;
  }

  exchange_type = ikeh->exchange_type;
  my_side = RHP_PROTO_IKE_HDR_INITIATOR(ikeh->flag) ?  RHP_IKE_RESPONDER : RHP_IKE_INITIATOR;
  my_spi = ( my_side == RHP_IKE_INITIATOR ? ikeh->init_spi : ikeh->resp_spi );

  RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_IKEHDR,"xLbLdGd",pkt,"PROTO_IKE_EXCHG",exchange_type,"IKE_SIDE",my_side,my_spi,qcd_err_resp);

  vpn_ref = rhp_vpn_ikesa_spi_get(my_side,my_spi);
  vpn = RHP_VPN_REF(vpn_ref);
  if( vpn == NULL ){

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_NO_IKESA,"xLdG",pkt,"IKE_SIDE",my_side,my_spi);

    err = RHP_STATUS_INVALID_IKEV2_MESG_NO_VPN;
  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_no_ikesa_err_packets);

    goto error;
  }

  RHP_LOCK(&(vpn->lock));

  vpn->dump("_rhp_ikev2_rx_verify_response",vpn);

  if( !_rhp_atomic_read(&(vpn->is_active)) ){

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_VPN_NOT_ACTIVE,"xx",pkt,vpn);

  	err = RHP_STATUS_INVALID_IKEV2_MESG_VPN_NOT_ACTIVE;
  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_no_ikesa_err_packets);

    goto error_l;
  }


  ikesa = vpn->ikesa_get(vpn,my_side,my_spi);
  if( ikesa == NULL ){

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_NO_IKESA,"xx",pkt,vpn);

  	err = RHP_STATUS_INVALID_IKEV2_MESG_NO_IKESA;
  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_no_ikesa_err_packets);

  	goto error_l;
  }

  ikesa->dump(ikesa);


  if( exchange_type == RHP_PROTO_IKE_EXCHG_SESS_RESUME &&
  		(!vpn->sess_resume.gen_by_sess_resume || !ikesa->gen_by_sess_resume ||
  			vpn->origin_side != RHP_IKE_INITIATOR || ikesa->side != RHP_IKE_INITIATOR ) ){

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_BAD_SESS_RESUME_PKT,"xxx",pkt,vpn,ikesa);

  	err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_EXCHG_TYPE_RESP;
  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_invalid_exchg_type_packets);

  	goto error_l;
  }


  rlm = vpn->rlm;
  if( rlm == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_NO_RLM,"xx",pkt,vpn);
    err = RHP_STATUS_INVALID_IKEV2_MESG_NO_REALM;
    goto error_l;
  }

  RHP_LOCK(&(rlm->lock));

  RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_RLM,"xxxus",pkt,vpn,rlm,rlm->id,rlm->name);
  if( vpn->cfg_peer ){
	  rhp_ikev2_id_dump("vpn->cfg_peer->id",&(vpn->cfg_peer->id));
	  rhp_ip_addr_dump("vpn->cfg_peer->primary_addr",&(vpn->cfg_peer->primary_addr));
	  rhp_ip_addr_dump("vpn->cfg_peer->secondary_addr",&(vpn->cfg_peer->secondary_addr));
	  rhp_ip_addr_dump("vpn->cfg_peer->internal_addr",&(vpn->cfg_peer->internal_addr));
  }

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_RLM_NOT_ACTIVE,"xxx",pkt,vpn,rlm);
    err = RHP_STATUS_INVALID_IKEV2_MESG_REALM_NOT_ACTIVE;
    goto error_l;
  }

  err = vpn->check_cfg_address(vpn,rlm,pkt);
  if( err ){

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_CHECK_CFG_ADDR_ERR,"xxxE",pkt,vpn,rlm,err);

    err = RHP_STATUS_INVALID_IKEV2_MESG_CHECK_CFG_ADDR_ERR;
  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_unknown_if_err_packets);

    goto error_l;
  }

  eap_sup_enabled = rhp_eap_sup_impl_is_enabled(rlm,NULL);

  RHP_UNLOCK(&(rlm->lock));
  rlm = NULL;


	if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ||
			exchange_type == RHP_PROTO_IKE_EXCHG_SESS_RESUME ){

		if( ikesa->state != RHP_IKESA_STAT_I_IKE_SA_INIT_SENT ){

			RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_IKE_SA_INIT_BAD_STAT,"xxxxLd",pkt,vpn,rlm,ikesa,"IKESA_STAT",ikesa->state);

			err = RHP_STATUS_INVALID_IKEV2_MESG_IKE_SA_INIT_BAD_SA_STATUS;
			rhp_ikev2_g_statistics_inc(rx_ikev2_resp_bad_ikesa_state_packets);

			goto error_l;
		}

	}else if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_AUTH ){

		if( ikesa->state != RHP_IKESA_STAT_I_AUTH_SENT &&
				(eap_sup_enabled && ikesa->state != RHP_IKESA_STAT_I_AUTH_EAP_SENT) ){

			RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_IKE_AUTH_BAD_STAT,"xxxxLdd",pkt,vpn,rlm,ikesa,"IKESA_STAT",ikesa->state,eap_sup_enabled);

			err = RHP_STATUS_INVALID_IKEV2_MESG_IKE_AUTH_BAD_SA_STATUS;
			rhp_ikev2_g_statistics_inc(rx_ikev2_resp_bad_ikesa_state_packets);

			goto error_l;
		}

	}else{

		if( ikesa->state != RHP_IKESA_STAT_ESTABLISHED &&
				ikesa->state != RHP_IKESA_STAT_REKEYING &&
				ikesa->state != RHP_IKESA_STAT_DELETE &&
				ikesa->state != RHP_IKESA_STAT_DELETE_WAIT ){

			RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_BAD_STAT,"xxxxLd",pkt,vpn,rlm,ikesa,"IKESA_STAT",ikesa->state);

			err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_SA_STATUS;
			rhp_ikev2_g_statistics_inc(rx_ikev2_resp_bad_ikesa_state_packets);

			goto error_l;
		}
	}


  pkt_r = ikesa->req_retx_pkt;
  if( pkt_r == NULL ){

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_NO_REQ_PKT,"xxxx",pkt,vpn,rlm,ikesa);

  	err = RHP_STATUS_INVALID_IKEV2_MESG_NO_REQ_PKT;
  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_no_req_err_packets);

    goto error_l;
  }

  rhp_pkt_hold(pkt_r);


  if( pkt_r->l4.udph->src_port == vpn->local.port_nat_t ){
  	ikeh_r = (rhp_proto_ike*)(pkt_r->app.raw + RHP_PROTO_NON_ESP_MARKER_SZ);
  }else{
  	ikeh_r = (rhp_proto_ike*)(pkt_r->app.raw);
  }


  if( pkt->mobike_verified ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_MOBIKE_VERIFIED,"xxxx",pkt,vpn,rlm,ikesa);
  	goto mobike_verified;
  }


  if( ikeh->message_id != ikeh_r->message_id ){

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_BAD_SEQ,"xxxxJJ",pkt,vpn,rlm,ikesa,ikeh->message_id,ikeh_r->message_id);

  	err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_MESG_ID;
  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_invalid_seq_packets);

    goto error_l;
  }


  if( exchange_type != ikeh_r->exchange_type ){

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_BAD_EXCHG_TYPE,"xxxxLbLb",pkt,vpn,rlm,ikesa,"PROTO_IKE_EXCHG",ikeh->exchange_type,"PROTO_IKE_EXCHG",ikeh_r->exchange_type);

  	err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_EXCHG_TYPE_RESP;
  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_invalid_exchg_type_packets);

  	goto error_l;
  }


  if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ||
  		exchange_type == RHP_PROTO_IKE_EXCHG_SESS_RESUME ){

		if( (pkt_r->type != pkt->type) ||
				(pkt_r->l4.udph->src_port != pkt->l4.udph->dst_port) ||
				(pkt_r->l4.udph->dst_port != pkt->l4.udph->src_port) ||
				(pkt->type == RHP_PKT_IPV4_IKE &&
				 (pkt_r->l3.iph_v4->src_addr != pkt->l3.iph_v4->dst_addr ||
					pkt_r->l3.iph_v4->dst_addr != pkt->l3.iph_v4->src_addr) ) ||
				(pkt->type == RHP_PKT_IPV6_IKE &&
					(!rhp_ipv6_is_same_addr(pkt_r->l3.iph_v6->src_addr,pkt->l3.iph_v6->dst_addr) ||
					 !rhp_ipv6_is_same_addr(pkt_r->l3.iph_v6->dst_addr,pkt->l3.iph_v6->src_addr))) ){

			src_addr_changed = 1;

			if( pkt->type == RHP_PKT_IPV4_IKE ){
				RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_FROM_UNKNOWN_PEER_1_IKE_SA_INIT,"xxxxx44WW44WW",pkt,pkt_r,vpn,rlm,ikesa,pkt_r->l3.iph_v4->src_addr,pkt->l3.iph_v4->dst_addr,pkt_r->l4.udph->src_port,pkt->l4.udph->dst_port,pkt_r->l3.iph_v4->dst_addr,pkt->l3.iph_v4->src_addr,pkt_r->l4.udph->dst_port,pkt->l4.udph->src_port);
			}else if( pkt->type == RHP_PKT_IPV6_IKE) {
				RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_FROM_UNKNOWN_PEER_1_IKE_SA_INIT_V6,"xxxxx66WW66WW",pkt,pkt_r,vpn,rlm,ikesa,pkt_r->l3.iph_v6->src_addr,pkt->l3.iph_v6->dst_addr,pkt_r->l4.udph->src_port,pkt->l4.udph->dst_port,pkt_r->l3.iph_v6->dst_addr,pkt->l3.iph_v6->src_addr,pkt_r->l4.udph->dst_port,pkt->l4.udph->src_port);
			}

			err = RHP_STATUS_INVALID_IKEV2_MESG_RX_FROM_UNKNOWN_PEER;
			rhp_ikev2_g_statistics_inc(rx_ikev2_resp_from_unknown_peer_packets);

			goto error_l;
		}

  }else{

  	if( !qcd_err_resp ){

    	//
    	// TODO: Handling a IKEv2 message including additional non-encrypted payloads ???
    	//
			if( ikeh->next_payload != RHP_PROTO_IKE_PAYLOAD_E &&
					ikeh->next_payload != RHP_PROTO_IKE_PAYLOAD_SKF ){

				RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_NOT_ENCRYPTED_MESG,"xxxx",pkt,vpn,rlm,ikesa);

				err = RHP_STATUS_IKEV2_NOT_ENCRYPTED_MESG;
				rhp_ikev2_g_statistics_inc(rx_ikev2_resp_not_encrypted_packets);

				goto error_l;
			}


			if( ikeh->next_payload == RHP_PROTO_IKE_PAYLOAD_SKF ){

				//
				// [CAUTION]
				//
				// rx_frag_completed can be valid after cheking this packet's ICV value
				// by rhp_ikev2_mesg_rx_integ_check().
				//
				err = rhp_ikev2_rx_verify_frag(pkt,vpn,ikesa,ikeh,&rx_frag_completed);
				if( err ){

					RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_BAD_FRAG_PKT,"xxxx",pkt,vpn,rlm,ikesa);
					goto error_l;
				}
			}


			err = rhp_ikev2_mesg_rx_integ_check(pkt,ikesa);
			if( err ){

				RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_BAD_ICV,"xxxx",pkt,vpn,rlm,ikesa);

				err = RHP_STATUS_INVALID_IKEV2_MESG_INTEG_ERR;
				rhp_ikev2_g_statistics_inc(rx_ikev2_resp_integ_err_packets);

				goto error_l;
			}


			if( (pkt->type == RHP_PKT_IPV4_IKE && vpn->peer_addr.addr_family != AF_INET ) ||
					(pkt->type == RHP_PKT_IPV6_IKE && vpn->peer_addr.addr_family != AF_INET6 ) ||
					(pkt->type == RHP_PKT_IPV4_IKE &&
					 vpn->peer_addr.addr.v4 != pkt->l3.iph_v4->src_addr) ||
					(pkt->type == RHP_PKT_IPV6_IKE &&
					 !rhp_ipv6_is_same_addr(vpn->peer_addr.addr.v6,pkt->l3.iph_v6->src_addr)) ||
					(vpn->peer_addr.port != pkt->l4.udph->src_port)  ){

				src_addr_changed = 1;

				rhp_ikev2_g_statistics_inc(rx_ikev2_resp_from_unknown_peer_packets);

				if( pkt->type == RHP_PKT_IPV4_IKE ){
					RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_FROM_UNKNOWN_PEER_2,"xxxx44WW",pkt,vpn,rlm,ikesa,vpn->peer_addr.addr.v4,pkt->l3.iph_v4->src_addr,vpn->peer_addr.port,pkt->l4.udph->src_port);
				}else if( pkt->type == RHP_PKT_IPV6_IKE ){
					RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_FROM_UNKNOWN_PEER_2_V6,"xxxx66WW",pkt,vpn,rlm,ikesa,vpn->peer_addr.addr.v6,pkt->l3.iph_v6->src_addr,vpn->peer_addr.port,pkt->l4.udph->src_port);
				}

				if( vpn->exec_mobike ){

					if( !rhp_ikev2_mobike_pending(vpn) ){
						RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_RX_FROM_UNKNOWN_PEER_MOBIKE_NOT_PENDING,"xxxx",pkt,vpn,rlm,ikesa);
						err = RHP_STATUS_INVALID_IKEV2_MESG_RX_FROM_UNKNOWN_PEER;
						goto error_l;
					}

					if( vpn->origin_side == RHP_IKE_RESPONDER ){

						if( !rhp_ikev2_mobike_rx_resp_rt_ck_addrs(pkt,vpn) ){
							RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_RX_FROM_UNKNOWN_PEER_MOBIKE_ADDRS_MISMATCH,"xxxx",pkt,vpn,rlm,ikesa);
							err = RHP_STATUS_INVALID_IKEV2_MESG_RX_FROM_UNKNOWN_PEER;
							goto error_l;
						}
					}

				}else{

					// IKE_AUTH exchg is included. Mobike supported is NOT exchanged yet.

					err = rhp_ikev2_nat_t_rx_from_unknown_peer(vpn,ikesa,pkt,ikeh);
					if( err ){
						RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_RX_FROM_UNKNOWN_PEER_NAT_T_ERR,"xxxx",pkt,vpn,rlm,ikesa);
						err = RHP_STATUS_INVALID_IKEV2_MESG_RX_FROM_UNKNOWN_PEER;
						goto error_l;
					}
				}
			}

  	}else{

    	err = rhp_ikev2_qcd_rx_invalid_ikesa_spi_resp(pkt,vpn);
    	if( !err ){
    		err = RHP_STATUS_IKEV2_MESG_QCD_INVALID_IKE_SPI_NTFY;
    	}

    	goto error_l;
  	}
  }


  if( !qcd_err_resp &&
  		rhp_ikev2_mobike_pending(vpn) && vpn->origin_side == RHP_IKE_INITIATOR ){

  	err = rhp_ikev2_mobike_i_rx_probe_pkt(vpn,ikesa,pkt);
  	if( err == RHP_STATUS_IKEV2_MOBIKE_RT_CK_PENDING ){

		  RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_MOBIKE_I_RX_PROBE_PKT_PENDING,"xxxxx",pkt,vpn,rlm,ikesa,vpn_ref);
  		goto pending_l;

  	}else if( err == RHP_STATUS_IKEV2_MOBIKE_NOT_INTERESTED ){

  		if( src_addr_changed ){

				err = RHP_STATUS_INVALID_IKEV2_MESG_RX_FROM_UNKNOWN_PEER;

  		  RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_MOBIKE_I_RX_PROBE_PKT_NOT_INTERESTED_BUT_SRC_CHANGED,"xxxxx",pkt,vpn,rlm,ikesa,vpn_ref);
  			goto error_l;
  		}

  		err = 0;
  		goto mobike_not_interested;

  	}else{

		  RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_MOBIKE_I_RX_PROBE_PKT_ERR,"xxxxxE",pkt,vpn,rlm,ikesa,vpn_ref,err);
  		goto error_l;
  	}

  }else{

mobike_verified:
mobike_not_interested:

		if( ikeh->next_payload == RHP_PROTO_IKE_PAYLOAD_SKF &&
				!rx_frag_completed ){

		  RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_RX_FRAG_PENDING,"xxxxx",pkt,vpn,rlm,ikesa,vpn_ref);

		}else{

			ikesa->timers->quit_retransmit_timer(vpn,ikesa);

			ikesa->set_retrans_request(ikesa,NULL); // Keep-Alive timer's handler watches this.

			if( ikesa->req_retx_ikemesg ){

				rhp_ikev2_unhold_mesg(ikesa->req_retx_ikemesg);
				ikesa->req_retx_ikemesg = NULL;
			}
		}

		*vpn_ref_r = vpn_ref;
  }

  if( pkt_r ){
		rhp_pkt_unhold(pkt_r);
  }

	RHP_UNLOCK(&(vpn->lock));

  RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_RTRN,"xxxxxx",pkt,vpn,rlm,ikesa,*vpn_ref_r,vpn);
  return 0;

pending_l:
error_l:
  if( rlm ){
    RHP_UNLOCK(&(rlm->lock));
  }
  RHP_UNLOCK(&(vpn->lock));

error:
	if( err != RHP_STATUS_IKEV2_MOBIKE_RT_CK_PENDING &&
			err != RHP_STATUS_IKEV2_MESG_QCD_INVALID_IKE_SPI_NTFY ){
		if( pkt->type == RHP_PKT_IPV4_IKE ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV2_RX_VERIFY_RESP_ERR,"VLG44WWGGLUE",vpn,"IKE_SIDE",my_side,my_spi,(pkt && pkt->l3.raw ? pkt->l3.iph_v4->src_addr : 0),(pkt && pkt->l3.raw ? pkt->l3.iph_v4->dst_addr : 0),(pkt && pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt && pkt->l4.raw ? pkt->l4.udph->dst_port : 0),(pkt && pkt->app.ikeh ? pkt->app.ikeh->init_spi : NULL),(pkt && pkt->app.ikeh ? pkt->app.ikeh->resp_spi : NULL),"PROTO_IKE_EXCHG",(int)(pkt && pkt->app.ikeh ? pkt->app.ikeh->exchange_type : 0),(pkt && pkt->app.ikeh ? pkt->app.ikeh->message_id : 0),err);
		}else if( pkt->type == RHP_PKT_IPV6_IKE ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV2_RX_VERIFY_RESP_V6_ERR,"VLG66WWGGLUE",vpn,"IKE_SIDE",my_side,my_spi,(pkt && pkt->l3.raw ? pkt->l3.iph_v6->src_addr : 0),(pkt && pkt->l3.raw ? pkt->l3.iph_v6->dst_addr : 0),(pkt && pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt && pkt->l4.raw ? pkt->l4.udph->dst_port : 0),(pkt && pkt->app.ikeh ? pkt->app.ikeh->init_spi : NULL),(pkt && pkt->app.ikeh ? pkt->app.ikeh->resp_spi : NULL),"PROTO_IKE_EXCHG",(int)(pkt && pkt->app.ikeh ? pkt->app.ikeh->exchange_type : 0),(pkt && pkt->app.ikeh ? pkt->app.ikeh->message_id : 0),err);
		}
		rhp_ikev2_g_statistics_inc(rx_ikev2_resp_verify_err_packets);
	}

	if( vpn ){
    rhp_vpn_unhold(vpn_ref);
  }

  if( pkt_r ){
		rhp_pkt_unhold(pkt_r);
  }

	RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_ERR,"xxxxxE",pkt,vpn,vpn_ref,rlm,ikesa,err);
  return err;
}

static int _rhp_ikev2_req_mesg_id_check(rhp_ikesa* ikesa,rhp_packet* pkt,
		rhp_packet* pkt_r,rhp_proto_ike *ikeh,rhp_proto_ike *ikeh_r)
{
	RHP_TRC(0,RHPTRCID_IKEV2_REQ_MESG_ID_CHECK,"xxxxxJJ",ikesa,pkt,pkt_r,ikeh,ikeh_r,ikeh->message_id,(ikeh_r ? ikeh_r->message_id : 0));

	if( ntohl(ikeh->message_id) == 0 && (ikeh_r == NULL) ){
		RHP_TRC(0,RHPTRCID_IKEV2_REQ_MESG_ID_CHECK_SEQ_ZERO,"xxJ",pkt,ikesa,ikeh->message_id);
		return RHP_STATUS_NEW_REQUEST_PKT;
	}


	if( pkt_r == NULL || ikeh_r == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_REQ_MESG_ID_CHECK_NO_RETRANS_PKT,"xxxJx",pkt,pkt_r,ikesa,ikeh->message_id,ikeh_r);
    return RHP_STATUS_INVALID_MSG;
	}

  if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){
    RHP_TRC(0,RHPTRCID_IKEV2_REQ_MESG_ID_CHECK_NOT_REQ,"xxxJJ",pkt,pkt_r,ikesa,ikeh->message_id,ikeh_r->message_id);
    return RHP_STATUS_INVALID_MSG;
  }

  if( ntohl(ikeh->message_id) == (ntohl(ikeh_r->message_id) + 1) ) {
    RHP_TRC(0,RHPTRCID_IKEV2_REQ_MESG_ID_CHECK_NEW_SEQ,"xxxJJ",pkt,pkt_r,ikesa,ikeh->message_id,ikeh_r->message_id);
    return RHP_STATUS_NEW_REQUEST_PKT;
  }

  if( ikeh->message_id != ikeh_r->message_id ){
    RHP_TRC(0,RHPTRCID_IKEV2_REQ_MESG_ID_CHECK_NOT_MATCHED,"xxxJJ",pkt,pkt_r,ikesa,ikeh->message_id,ikeh_r->message_id);
    return RHP_STATUS_INVALID_MSG;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_REQ_MESG_ID_CHECK_OK,"xxxJJ",pkt,pkt_r,ikesa,ikeh->message_id,ikeh_r->message_id);
  return 0;
}

static int _rhp_ikev2_rx_skf_frag_head(rhp_packet* pkt,rhp_proto_ike* ikeh)
{
	int flag = 0;

  RHP_TRC_FREQ(0,RHPTRCID_IKEV2_RX_SKF_FRAG_HEAD,"xxbb",pkt,ikeh,ikeh->exchange_type,ikeh->next_payload);

	if( pkt->tail > ((u8*)(ikeh + 1)) + sizeof(rhp_proto_ike_skf_payload) ){

		rhp_proto_ike_skf_payload* skf = (rhp_proto_ike_skf_payload*)(ikeh + 1);
		u16 frag_num = ntohs(skf->frag_num);

		if( frag_num == 1 ){
			flag = 1;
		}
	}

  RHP_TRC_FREQ(0,RHPTRCID_IKEV2_RX_SKF_FRAG_HEAD_RTRN,"xxd",pkt,ikeh,flag);
	return flag;
}

static int _rhp_ikev2_rx_verify_req_no_vpn_enc(rhp_packet* pkt,rhp_proto_ike* ikeh)
{
	int flag = 0;

  RHP_TRC_FREQ(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_NO_VPN_ENC,"xxbb",pkt,ikeh,ikeh->exchange_type,ikeh->next_payload);

	if( ikeh->exchange_type != RHP_PROTO_IKE_EXCHG_IKE_SA_INIT &&
			ikeh->exchange_type != RHP_PROTO_IKE_EXCHG_SESS_RESUME &&
			ikeh->exchange_type != RHP_PROTO_IKE_EXCHG_IKE_AUTH ){

		if( ikeh->next_payload == RHP_PROTO_IKE_PAYLOAD_E ){

			flag = 1;

		}else if( ikeh->next_payload == RHP_PROTO_IKE_PAYLOAD_SKF ){

			flag = _rhp_ikev2_rx_skf_frag_head(pkt,ikeh);
		}
	}

  RHP_TRC_FREQ(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_NO_VPN_ENC_RTRN,"xxd",pkt,ikeh,flag);
	return flag;
}

void rhp_ikev2_sync_frag_headers(rhp_packet* pkt)
{
	rhp_packet_frag* pktfrag = pkt->frags.head;

	while( pktfrag ){

		if( pkt->l2.eth && pktfrag->l2.eth ){

			memcpy(pktfrag->l2.eth,pkt->l2.eth,sizeof(rhp_proto_ether));
		}

		if( pkt->l3.raw && pktfrag->l3.raw ){

			if( pkt->type == RHP_PKT_IPV4_IKE ){

	      u16 v4_total_len = pktfrag->l3.iph_v4->total_len;
	      u16 v4_id = pktfrag->l3.iph_v4->id;

				memcpy(pktfrag->l3.iph_v4,pkt->l3.iph_v4,sizeof(rhp_proto_ip_v4));
				pktfrag->l3.iph_v4->total_len = v4_total_len;
				pktfrag->l3.iph_v4->id = v4_id;

			}else if( pkt->type == RHP_PKT_IPV6_IKE ){

	      u16 v6_payload_len = pktfrag->l3.iph_v6->payload_len;

				memcpy(pktfrag->l3.iph_v6,pkt->l3.iph_v6,sizeof(rhp_proto_ip_v6));
				pktfrag->l3.iph_v6->payload_len = v6_payload_len;

			}else{
				RHP_BUG("%d",pkt->type);
			}
		}

		if( pkt->l4.udph && pktfrag->l4.udph ){

		  u16 udp_len = pktfrag->l4.udph->len;

			memcpy(pktfrag->l4.udph,pkt->l4.udph,sizeof(rhp_proto_udp));
			pktfrag->l4.udph->len = udp_len;
		}

		pktfrag = pktfrag->next;
	}

	return;
}

static int _rhp_ikev2_rx_verify_request(rhp_packet* pkt,rhp_vpn_ref** vpn_ref_r)
{
  int err = -EINVAL;
  u8 exchange_type = 0;
  rhp_proto_ike *ikeh = NULL,*ikeh_r = NULL;
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;
  rhp_ikesa* ikesa = NULL;
  rhp_packet *pkt_r = NULL, *pkt_r_d = NULL;
  time_t now;
  int my_side = 0;
  u8* my_spi = NULL;
  rhp_vpn_realm* rlm = NULL;
  u8 my_init_resp_spi[RHP_PROTO_IKE_SPI_SIZE];
  rhp_ifc_entry* tx_ifc = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ,"xx",pkt,vpn_ref_r);

  if( pkt->type != RHP_PKT_IPV4_IKE && pkt->type != RHP_PKT_IPV6_IKE ){
  	RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }


  ikeh = pkt->app.ikeh;
  exchange_type = ikeh->exchange_type;

  if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ||
  		exchange_type == RHP_PROTO_IKE_EXCHG_SESS_RESUME ){

  	err = rhp_ikesa_init_i_get(pkt,my_init_resp_spi);
  	if( err == -ENOENT ){

    	RHP_TRC_FREQ(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_NEW_IKESA,"x",pkt);

    	if( rhp_ikesa_max_half_open_sessions_reached() ){

      	RHP_TRC_FREQ(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_MAX_HALF_OPEN_SESSIONS_REACHED,"x",pkt);

    		rhp_ikev2_g_statistics_inc(max_ikesa_half_open_sessions_reached);
    		err = RHP_STATUS_IKESA_MAX_HALF_OPEN_SESSIONS_REACHED;
    		goto error;

    	}else if( rhp_vpn_max_sessions_reached() ){

      	RHP_TRC_FREQ(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_MAX_VPN_SESSIONS_REACHED,"x",pkt);

    		rhp_ikev2_g_statistics_inc(max_vpn_sessions_reached);
    		err = RHP_STATUS_VPN_MAX_SESSIONS_REACHED;
    		goto error;
    	}

    	if( !(pkt->cookie_checked) && rhp_ikesa_cookie_active(1) ){

    		err = rhp_ikev2_ike_sa_init_disp_cookie_handler(pkt);
      	if( err ){
        	RHP_TRC_FREQ(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_DISP_COOKIE_HANDLER_ERR,"xE",pkt,err);
        	err = RHP_STATUS_INVALID_IKEV2_MESG_COOKIE_HANDLER_ERR;
      		goto error;
      	}

      	pkt->cookie_checked = 1;
      	err = RHP_STATUS_HANDLE_COOKIE;

      	RHP_TRC_FREQ(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_DISP_COOKIE_HANDLER,"x",pkt);

      	goto error;
    	}

      if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ){
      	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV2_RX_NEW_IKE_SA_INIT_REQ,"VLGGL",vpn,"PROTO_IKE_EXCHG",exchange_type,(ikeh ? ikeh->init_spi : NULL),(ikeh ? ikeh->resp_spi : NULL),"IKE_SIDE",my_side);
      }else if( exchange_type == RHP_PROTO_IKE_EXCHG_SESS_RESUME ){
      	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV2_RX_NEW_SESS_RESUME_REQ,"VLGGL",vpn,"PROTO_IKE_EXCHG",exchange_type,(ikeh ? ikeh->init_spi : NULL),(ikeh ? ikeh->resp_spi : NULL),"IKE_SIDE",my_side);
      }

    	rhp_ikev2_g_statistics_inc(rx_ikev2_req_new_ike_sa_init_packets);

    	goto new_req;

  	}else if( err ){
  		goto error;
    }

  	my_side = RHP_IKE_RESPONDER;
  	my_spi = my_init_resp_spi;

  }else{

  	my_side = RHP_PROTO_IKE_HDR_INITIATOR(ikeh->flag) ? RHP_IKE_RESPONDER : RHP_IKE_INITIATOR;
  	my_spi = ( my_side == RHP_IKE_INITIATOR ? ikeh->init_spi : ikeh->resp_spi );
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_IKEHDR,"xLbLdG",pkt,"PROTO_IKE_EXCHG",exchange_type,"IKE_SIDE",my_side,my_spi);


  vpn_ref = rhp_vpn_ikesa_spi_get(my_side,my_spi);
  vpn = RHP_VPN_REF(vpn_ref);
  if( vpn == NULL ){

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_NO_VPN,"xLdG",pkt,"IKE_SIDE",my_side,my_spi);

  	if( _rhp_ikev2_rx_verify_req_no_vpn_enc(pkt,ikeh) ){

  		// For QCD processing...

  		err = RHP_STATUS_INVALID_IKEV2_MESG_NO_VPN_ENC;

  	}else{

  		err = RHP_STATUS_INVALID_IKEV2_MESG_NO_VPN;
  	}

  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_no_ikesa_err_packets);

  	goto error;
  }


  RHP_LOCK(&(vpn->lock));

  vpn->dump("_rhp_ikev2_rx_verify_request",vpn);

  if( !_rhp_atomic_read(&(vpn->is_active)) ){

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_VPN_NOT_ACTIVE,"xx",pkt,vpn);
  	err = RHP_STATUS_INVALID_IKEV2_MESG_VPN_NOT_ACTIVE;

  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_no_ikesa_err_packets);

  	goto error_l;
  }


  ikesa = vpn->ikesa_get(vpn,my_side,my_spi);
  if( ikesa == NULL ){

  	err = RHP_STATUS_INVALID_IKEV2_MESG_NO_IKESA;
    RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_RESP_NO_IKESA,"xxx",pkt,vpn,rlm);

  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_no_ikesa_err_packets);

  	goto error_l;
  }

  ikesa->dump(ikesa);


  rlm = vpn->rlm;
  if( rlm ){

  	RHP_LOCK(&(rlm->lock));

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_RLM,"xxxus",pkt,vpn,rlm,rlm->id,rlm->name);
  	if( vpn->cfg_peer ){
	  	rhp_ikev2_id_dump("vpn->cfg_peer->id",&(vpn->cfg_peer->id));
	  	rhp_ip_addr_dump("vpn->cfg_peer->primary_addr",&(vpn->cfg_peer->primary_addr));
	  	rhp_ip_addr_dump("vpn->cfg_peer->secondary_addr",&(vpn->cfg_peer->secondary_addr));
	  	rhp_ip_addr_dump("vpn->cfg_peer->internal_addr",&(vpn->cfg_peer->internal_addr));
  	}

  	if( !_rhp_atomic_read(&(rlm->is_active)) ){
  		RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_RLM_NOT_ACTIVE,"xxx",pkt,vpn,rlm);
  		err = RHP_STATUS_INVALID_IKEV2_MESG_REALM_NOT_ACTIVE;
  		goto error_l;
    }

    err = vpn->check_cfg_address(vpn,rlm,pkt);
    if( err ){

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_CHECK_CFG_ADDR_ERR,"xxxE",pkt,vpn,rlm,err);
    	err = RHP_STATUS_INVALID_IKEV2_MESG_CHECK_CFG_ADDR_ERR;

    	rhp_ikev2_g_statistics_inc(rx_ikev2_req_unknown_if_err_packets);

    	goto error_l;
    }

    RHP_UNLOCK(&(rlm->lock));
    rlm = NULL;

  }else{

    if( exchange_type != RHP_PROTO_IKE_EXCHG_IKE_SA_INIT &&
    		exchange_type != RHP_PROTO_IKE_EXCHG_SESS_RESUME &&
    		exchange_type != RHP_PROTO_IKE_EXCHG_IKE_AUTH ){

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_INVALID_EXCHANGE,"xxb",pkt,vpn,exchange_type);
    	err = RHP_STATUS_INVALID_IKEV2_MESG_NO_REALM;

    	rhp_ikev2_g_statistics_inc(rx_ikev2_req_invalid_exchg_type_packets);

    	goto error_l;
    }
  }


  if( ikesa->busy_flag ){

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_IKESA_BUSY,"xxxx",pkt,vpn,rlm,ikesa);

  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_busy_err_packets);

  	goto ignore_l;
  }


  if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ||
  		exchange_type == RHP_PROTO_IKE_EXCHG_SESS_RESUME ){

    if( ikesa->state != RHP_IKESA_STAT_R_IKE_SA_INIT_SENT ){

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_IKE_SA_INIT_BAD_STAT,"xxxxd",pkt,vpn,rlm,ikesa,ikesa->state);

    	rhp_ikev2_g_statistics_inc(rx_ikev2_req_bad_ikesa_state_packets);

    	goto ignore_l;
    }

  }else if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_AUTH ){

    if( ikesa->state != RHP_IKESA_STAT_R_IKE_SA_INIT_SENT &&
        ikesa->state != RHP_IKESA_STAT_ESTABLISHED ){

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_IKE_AUTH_BAD_STAT,"xxxxd",pkt,vpn,rlm,ikesa,ikesa->state);

    	rhp_ikev2_g_statistics_inc(rx_ikev2_req_bad_ikesa_state_packets);

    	goto ignore_l;
    }

  }else{

    if( ikesa->state != RHP_IKESA_STAT_ESTABLISHED &&
    	  ikesa->state != RHP_IKESA_STAT_REKEYING &&
    	  ikesa->state != RHP_IKESA_STAT_DELETE &&
    	  ikesa->state != RHP_IKESA_STAT_DELETE_WAIT ){

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_IKESA_BAD_STAT,"xxxxd",pkt,vpn,rlm,ikesa,ikesa->state);

    	rhp_ikev2_g_statistics_inc(rx_ikev2_req_bad_ikesa_state_packets);

    	goto ignore_l;
    }
  }


  pkt_r = ikesa->rep_retx_pkt;
  if( pkt_r ){

		rhp_pkt_hold(pkt_r); // (ZZ)

  	if( pkt_r->l4.udph->src_port == vpn->local.port_nat_t ){
  		ikeh_r = (rhp_proto_ike*)(pkt_r->app.raw + RHP_PROTO_NON_ESP_MARKER_SZ);
  	}else{
  		ikeh_r = (rhp_proto_ike*)(pkt_r->app.raw);
  	}

  	if( ntohl(ikeh->message_id) < ntohl(ikeh_r->message_id) ){

  		RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_BAD_SEQ,"xxxxJJ",pkt,vpn,rlm,ikesa,ikeh->message_id,ikeh_r->message_id);

    	rhp_ikev2_g_statistics_inc(rx_ikev2_req_invalid_seq_packets);

    	goto ignore_l;
  	}

  }else{

  	if( ntohl(ikeh->message_id) != 0 ){

  		RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_BAD_SEQ_ZERO,"xxxxJ",pkt,vpn,rlm,ikesa,ikeh->message_id);

    	rhp_ikev2_g_statistics_inc(rx_ikev2_req_invalid_seq_packets);

    	goto ignore_l;
  	}
  }


  if( exchange_type != RHP_PROTO_IKE_EXCHG_IKE_SA_INIT &&
  		exchange_type != RHP_PROTO_IKE_EXCHG_SESS_RESUME ){

  	int msg_err;

  	//
  	// TODO: Handling a IKEv2 message including additional non-encrypted payloads ???
  	//
    if( ikeh->next_payload != RHP_PROTO_IKE_PAYLOAD_E &&
    		ikeh->next_payload != RHP_PROTO_IKE_PAYLOAD_SKF ){

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_NOT_ENCRYPTED_MESG,"xxxx",pkt,vpn,rlm,ikesa);
    	err = RHP_STATUS_IKEV2_NOT_ENCRYPTED_MESG;

    	rhp_ikev2_g_statistics_inc(rx_ikev2_req_not_encrypted_packets);

    	goto error_l;
    }


    if( ikeh->next_payload == RHP_PROTO_IKE_PAYLOAD_SKF ){

			//
			// [CAUTION]
			//
			// rx_frag_completed can be valid after cheking this packet's ICV value
			// by rhp_ikev2_mesg_rx_integ_check().
			//
    	err = rhp_ikev2_rx_verify_frag(pkt,vpn,ikesa,ikeh,NULL);
			if( err ){

				RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_BAD_FRAG_PKT,"xxxx",pkt,vpn,rlm,ikesa);
				goto error_l;
			}
    }


  	err = rhp_ikev2_mesg_rx_integ_check(pkt,ikesa);
  	if( err ){

  		RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_BAD_ICV,"xxxx",pkt,vpn,rlm,ikesa);
  		err = RHP_STATUS_INVALID_IKEV2_MESG_INTEG_ERR;

    	rhp_ikev2_g_statistics_inc(rx_ikev2_req_integ_err_packets);

  		goto error_l;
    }

  	err = _rhp_ikev2_req_mesg_id_check(ikesa,pkt,pkt_r,ikeh,ikeh_r);
  	if( err && err != RHP_STATUS_NEW_REQUEST_PKT ){

  		RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_BAD_MESG_ID,"xxxxE",pkt,vpn,rlm,ikesa,err);
  		err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_MESG_ID;

    	rhp_ikev2_g_statistics_inc(rx_ikev2_req_invalid_seq_packets);

  		goto error_l;
    }
  	msg_err = err;


  	if( (pkt->type == RHP_PKT_IPV4_IKE && vpn->peer_addr.addr_family != AF_INET) ||
  			(pkt->type == RHP_PKT_IPV6_IKE && vpn->peer_addr.addr_family != AF_INET6) ||
  			(pkt->type == RHP_PKT_IPV4_IKE && vpn->peer_addr.addr.v4 != pkt->l3.iph_v4->src_addr) ||
  			(pkt->type == RHP_PKT_IPV6_IKE && !rhp_ipv6_is_same_addr(vpn->peer_addr.addr.v6,pkt->l3.iph_v6->src_addr)) ||
				(vpn->peer_addr.port != pkt->l4.udph->src_port) ){

			rhp_ikev2_g_statistics_inc(rx_ikev2_req_from_unknown_peer_packets);

		  if( !vpn->exec_mobike ){

				err = rhp_ikev2_nat_t_rx_from_unknown_peer(vpn,ikesa,pkt,ikeh);
				if( err ){
					RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_NAT_T_ERR,"xxxx",pkt,vpn,rlm,ikesa);
					err = RHP_STATUS_INVALID_IKEV2_MESG_RX_FROM_UNKNOWN_PEER;
					goto error_l;
				}
			}
  	}


  	if( msg_err == RHP_STATUS_NEW_REQUEST_PKT ){

		 	RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_NEW_REQ,"xxxx",pkt,vpn,rlm,ikesa);

  		// [TODO] When failing to create new response for this new request,
		 	//        we should requeue this packet and wait for retransmitted
		 	//        request pkt again?

  		err = 0;
  		goto new_req_l;
  	}

  }else{

  	err = _rhp_ikev2_req_mesg_id_check(ikesa,pkt,pkt_r,ikeh,ikeh_r);
  	if( err == RHP_STATUS_NEW_REQUEST_PKT ){

		 	RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_IKE_SA_INIT_NEW_REQ,"xxxx",pkt,vpn,rlm,ikesa);

  		// [TODO] When failing to create new response for this new request,
		 	//        we should requeue this packet and wait for retransmitted
		 	//        request pkt again?

		 	err = 0;
		 	goto new_req_l;

  	}else if( err ){

  		RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_IKE_SA_INIT_MESG_ID_ERR,"xxxxE",pkt,vpn,rlm,ikesa,err);
		 	err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_MESG_ID;

    	rhp_ikev2_g_statistics_inc(rx_ikev2_req_invalid_seq_packets);

		 	goto error_l;
    }
  }




  //
  // Retransmitting a response.
  //

  if( pkt_r == NULL ){
  	RHP_BUG("");
  	goto error_l;
  }


  if( ikeh->next_payload == RHP_PROTO_IKE_PAYLOAD_SKF &&
  		!_rhp_ikev2_rx_skf_frag_head(pkt,ikeh) ){

		RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_SKF_NOT_FRAG_HEAD,"xxxxu",pkt,vpn,rlm,ikesa);
  	goto ignore_l;
  }


  {
		now = _rhp_get_time();

		if( ikesa->rep_retx_last_time == now ){

			if( ikesa->rep_retx_cnt > (unsigned long)rhp_gcfg_ike_retransmit_reps_limit_per_sec ){

				RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_RATE_LIMITED,"xxxxu",pkt,vpn,rlm,ikesa,ikesa->rep_retx_cnt);

				rhp_ikev2_g_statistics_inc(tx_ikev2_resp_rate_limited_err_packets);

				goto ignore_l;
			}

			ikesa->rep_retx_cnt++;

		}else{

			ikesa->rep_retx_last_time = now;
			ikesa->rep_retx_cnt = 0;
		}
  }



	pkt_r_d = rhp_pkt_dup(pkt_r);
	if( pkt_r_d == NULL ){
		RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_DUP_PKT_FAILED,"xxxxx",pkt,vpn,rlm,ikesa,pkt_r);
		goto ignore_l;
	}

#if defined(RHP_PKT_DBG_IKEV2_RETRANS_TEST) || defined(RHP_PKT_DBG_IKEV2_RETRANS_FRAG_TEST)
	pkt_r_d->ikev2_retrans_pkt = RHP_PKT_IKEV2_RETRANS_REP;
#endif // RHP_PKT_DBG_IKEV2_RETRANS_TEST

	if( vpn->exec_mobike ){

		if( pkt->type == RHP_PKT_IPV4_IKE ){

			err = rhp_pkt_rebuild_ip_udp_header(pkt_r_d,
							AF_INET,(u8*)&(pkt->l3.iph_v4->dst_addr),(u8*)&(pkt->l3.iph_v4->src_addr),
							pkt->l4.udph->dst_port,pkt->l4.udph->src_port);
			if( err ){
				goto ignore_l;
			}

		}else if( pkt->type == RHP_PKT_IPV6_IKE ){

			err = rhp_pkt_rebuild_ip_udp_header(pkt_r_d,
							AF_INET6,pkt->l3.iph_v6->dst_addr,pkt->l3.iph_v6->src_addr,
							pkt->l4.udph->dst_port,pkt->l4.udph->src_port);
			if( err ){
				goto ignore_l;
			}
		}

		tx_ifc = pkt->rx_ifc;
		if( tx_ifc == NULL ){
			RHP_BUG("");
			goto ignore_l;
		}

		rhp_ifc_hold(tx_ifc); // (***)

	}else{

		err = rhp_pkt_rebuild_ip_udp_header(pkt_r_d,
						vpn->peer_addr.addr_family,
						NULL,vpn->peer_addr.addr.raw,
						0,vpn->peer_addr.port);
		if( err ){
			goto ignore_l;
		}

		tx_ifc = rhp_ifc_get_by_if_idx(vpn->local.if_info.if_index);  // (***)
		if( tx_ifc == NULL ){
			RHP_BUG("");
			goto ignore_l;
		}
	}

	pkt_r_d->tx_ifc = tx_ifc;
	rhp_ifc_hold(pkt_r_d->tx_ifc);


	err = rhp_netsock_send(pkt_r_d->tx_ifc,pkt_r_d);
	if( err < 0 ){
		RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_TX_PKT_FAILED,"xxxxxE",pkt,vpn,rlm,ikesa,pkt_r_d,err);
	}

	rhp_ikev2_g_statistics_inc(tx_ikev2_resp_retransmit_packets);
	err = 0;

	if( pkt->type == RHP_PKT_IPV4_IKE ){
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKEV2_RETRANSMIT_RESPONSE,"VP44WWLG",vpn,ikesa,pkt_r_d->l3.iph_v4->src_addr,pkt_r_d->l3.iph_v4->dst_addr,pkt_r_d->l4.udph->src_port,pkt_r_d->l4.udph->dst_port,"IKE_SIDE",my_side,my_spi);
	}else if( pkt->type == RHP_PKT_IPV6_IKE ){
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKEV2_RETRANSMIT_RESPONSE_V6,"VP66WWLG",vpn,ikesa,pkt_r_d->l3.iph_v6->src_addr,pkt_r_d->l3.iph_v6->dst_addr,pkt_r_d->l4.udph->src_port,pkt_r_d->l4.udph->dst_port,"IKE_SIDE",my_side,my_spi);
	}

	rhp_pkt_unhold(pkt_r_d);
	pkt_r_d = NULL;


	rhp_pkt_unhold(pkt_r); // (ZZ)
	pkt_r = NULL;

  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

	rhp_ifc_unhold(tx_ifc); // (***)

  RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_RTRN,"xxxxxx",pkt,vpn,rlm,ikesa,pkt_r,pkt_r_d);

  return RHP_STATUS_RETRANS_OK;


ignore_l:
	err = RHP_STATUS_RETRANS_OK;

	if( vpn ){
    RHP_UNLOCK(&(vpn->lock));
  }
  goto error;

new_req_l:
  if( vpn ){
    RHP_UNLOCK(&(vpn->lock));
  }
new_req:
  *vpn_ref_r = vpn_ref;

  if( tx_ifc ){
  	rhp_ifc_unhold(tx_ifc); // (***)
  }

	if( pkt_r ){
		rhp_pkt_unhold(pkt_r); // (ZZ)
	}

  RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_NEW_REQ_RTRN,"xxxxxx",pkt,vpn,vpn_ref,rlm,ikesa,pkt_r);
  return 0;


error_l:
  if( rlm ){
    RHP_UNLOCK(&(rlm->lock));
  }
  if( vpn ){
    RHP_UNLOCK(&(vpn->lock));
  }

error:
  if( err == 0 ){
    err = RHP_STATUS_INVALID_MSG;
  }

  if( err != RHP_STATUS_RETRANS_OK &&
  		err != RHP_STATUS_HANDLE_COOKIE &&
  		err != RHP_STATUS_IKEV2_FRAG_RX_IGNORED ){
    if( pkt->type == RHP_PKT_IPV4_IKE ){
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV2_RX_VERIFY_REQ_ERR,"VLG44WWGGLUE",vpn,"IKE_SIDE",my_side,my_spi,(pkt && pkt->l3.raw ? pkt->l3.iph_v4->src_addr : 0),(pkt && pkt->l3.raw ? pkt->l3.iph_v4->dst_addr : 0),(pkt && pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt && pkt->l4.raw ? pkt->l4.udph->dst_port : 0),(pkt && pkt->app.ikeh ? pkt->app.ikeh->init_spi : NULL),(pkt && pkt->app.ikeh ? pkt->app.ikeh->resp_spi : NULL),"PROTO_IKE_EXCHG",(int)(pkt && pkt->app.ikeh ? pkt->app.ikeh->exchange_type : 0),(pkt && pkt->app.ikeh ? pkt->app.ikeh->message_id : 0),err);
    }else if( pkt->type == RHP_PKT_IPV6_IKE ){
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV2_RX_VERIFY_REQ_V6_ERR,"VLG66WWGGLUE",vpn,"IKE_SIDE",my_side,my_spi,(pkt && pkt->l3.raw ? pkt->l3.iph_v6->src_addr : NULL),(pkt && pkt->l3.raw ? pkt->l3.iph_v6->dst_addr : NULL),(pkt && pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt && pkt->l4.raw ? pkt->l4.udph->dst_port : 0),(pkt && pkt->app.ikeh ? pkt->app.ikeh->init_spi : NULL),(pkt && pkt->app.ikeh ? pkt->app.ikeh->resp_spi : NULL),"PROTO_IKE_EXCHG",(int)(pkt && pkt->app.ikeh ? pkt->app.ikeh->exchange_type : 0),(pkt && pkt->app.ikeh ? pkt->app.ikeh->message_id : 0),err);
    }
  }

  if( vpn ){
    rhp_vpn_unhold(vpn_ref);
  }

  if( tx_ifc ){
  	rhp_ifc_unhold(tx_ifc); // (***)
  }

	if( pkt_r ){
		rhp_pkt_unhold(pkt_r); // (ZZ)
	}

	if( pkt_r_d ){
		rhp_pkt_unhold(pkt_r_d);
	}

	rhp_ikev2_g_statistics_inc(rx_ikev2_req_verify_err_packets);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_REQ_NEW_REQ_ERR,"xxxxxxE",pkt,vpn,vpn_ref,rlm,ikesa,pkt_r,err);
  return err;
}

static int _rhp_ikev2_recv_impl(int addr_family,rhp_packet* pkt)
{
  rhp_ikev2_mesg* rx_ikemesg = NULL;
  rhp_proto_ike* ikeh = NULL;
  int err = -EINVAL;
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;
  rhp_ikesa* ikesa = NULL;
  rhp_ikev2_mesg* ikemesg_error = NULL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  int my_ikesa_side = -1;
  u8* my_ikesa_spi = NULL;

  if( pkt->type == RHP_PKT_IPV4_IKE ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RECV_IMPL,"Ldxa","AF",addr_family,pkt,(pkt->tail - pkt->l2.raw),RHP_TRC_FMT_A_MAC_IPV4_IKEV2,0,0,pkt->l2.raw);
  }else if( pkt->type == RHP_PKT_IPV6_IKE ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RECV_IMPL_V6,"Ldxa","AF",addr_family,pkt,(pkt->tail - pkt->l2.raw),RHP_TRC_FMT_A_MAC_IPV6_IKEV2,0,0,pkt->l2.raw);
  }else{
  	RHP_BUG("%d",pkt->type);
  }

  if( rhp_cfg_check_peer_acls(pkt) ){

  	RHP_TRC(0,RHPTRCID_IKEV2_RECV_IMPL_ACL_NOT_MATCHED,"x",pkt);

  	rhp_ikev2_g_statistics_inc(rx_ikev2_acl_err_packets);

  	goto error;
  }

  // Don't ref pkt->app.ikeh here! This may still point a head
  // of RHP_PROTO_NON_ESP_MARKER.
  // rhp_ikev2_check_mesg() will inc the pointer to IKEv2 header.
  err = rhp_ikev2_check_mesg(pkt);
  if( err == RHP_STATUS_IKEV2_MESG_QCD_INVALID_IKE_SPI_NTFY ){

    if( rhp_gcfg_ikev2_qcd_enabled ){

      err = _rhp_ikev2_rx_verify_response(pkt,1,&vpn_ref);
      vpn = RHP_VPN_REF(vpn_ref); // vpn may be NULL.
      if( err != RHP_STATUS_IKEV2_MESG_QCD_INVALID_IKE_SPI_NTFY ){

      	if( pkt->type == RHP_PKT_IPV4_IKE ){
      		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_QCD_RX_INVALID_ERR_RESP,"44WW",pkt->l3.iph_v4->dst_addr,pkt->l3.iph_v4->src_addr,pkt->l4.udph->dst_port,pkt->l4.udph->src_port);
      	}else if( pkt->type == RHP_PKT_IPV6_IKE ){
      		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_QCD_RX_INVALID_ERR_RESP_V6,"66WW",pkt->l3.iph_v6->dst_addr,pkt->l3.iph_v6->src_addr,pkt->l4.udph->dst_port,pkt->l4.udph->src_port);
      	}

      	if( err != RHP_STATUS_IKEV2_QCD_ERR_RESP_IGNORED ){
      		rhp_ikev2_g_statistics_inc(qcd_rx_err_resp_no_ikesa);
      	}

      	RHP_TRC(0,RHPTRCID_IKEV2_RECV_IMPL_QCD_INVALID_IKESA_SPI_IGNORE_RESP,"xE",pkt,err);

      }else{

      	RHP_TRC(0,RHPTRCID_IKEV2_RECV_IMPL_QCD_INVALID_IKESA_SPI_OK,"xE",pkt,err);
      }
    }

    goto error;

#ifdef RHP_IKEV2_INTEG_ERR_DBG
  }else if( err == RHP_STATUS_INVALID_IKEV2_MESG_INTEG_ERR ){

  	rhp_ikev2_dbg_rx_integ_err_notify(pkt);

  	goto error;
#endif // RHP_IKEV2_INTEG_ERR_DBG

  }else if( err ){

  	RHP_TRC(0,RHPTRCID_IKEV2_RECV_IMPL_INVALID_MESG,"xE",pkt,err);

  	goto error;
  }

  // OK! Now pkt->app.ikeh point a head of IKEv2 header.
  ikeh = pkt->app.ikeh;

  if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){

    err = _rhp_ikev2_rx_verify_response(pkt,0,&vpn_ref);
    vpn = RHP_VPN_REF(vpn_ref);

    if( err ){

      RHP_TRC(0,RHPTRCID_IKEV2_RECV_IMPL_IGNORE_RESP,"xE",pkt,err);

      err = 0;
      goto end;
    }

  }else{

    err = _rhp_ikev2_rx_verify_request(pkt,&vpn_ref);
    vpn = RHP_VPN_REF(vpn_ref);

    if( err == RHP_STATUS_INVALID_IKEV2_MESG_NO_VPN_ENC ){

      RHP_TRC(0,RHPTRCID_IKEV2_RECV_IMPL_INVALID_REQ_ENC_NO_VPN_FOUND,"xdE",pkt,rhp_gcfg_ikev2_qcd_enabled,err);

      if( rhp_gcfg_ikev2_qcd_enabled ){

      	rhp_ikev2_qcd_rx_invalid_ikesa_spi_req(pkt);
      }

      goto error;

    }else if( err == RHP_STATUS_INVALID_IKEV2_MESG_NO_VPN ){

    	//
    	// TODO : Return INVALID_SPI Notify Payload with limited
    	//        rate to prevent flooding attacks.
    	//
      RHP_TRC(0,RHPTRCID_IKEV2_RECV_IMPL_INVALID_REQ_NO_VPN_FOUND,"xE",pkt,err);

      goto error;

    }else if( err == RHP_STATUS_RETRANS_OK 		|| // Or the rx packet was ignored.
    		 	 	 	err == RHP_STATUS_HANDLE_COOKIE ||
    		 	 	 	err == RHP_STATUS_IKEV2_NOT_ENCRYPTED_MESG ||
    		 	 	 	err == RHP_STATUS_VPN_MAX_SESSIONS_REACHED ||
    		 	 	 	err == RHP_STATUS_IKESA_MAX_HALF_OPEN_SESSIONS_REACHED ||
    		 	 	 	err == RHP_STATUS_IKEV2_FRAG_RX_IGNORED ){

      RHP_TRC(0,RHPTRCID_IKEV2_RECV_IMPL_IGNOED_REQ,"xE",pkt,err);

      err = 0;
      goto end;

    }else if( err ){

    	if( err == RHP_STATUS_INVALID_IKEV2_MESG_INTEG_ERR ){

    		rhp_ikev2_dbg_tx_integ_err_notify(pkt,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_DBG_IKE_INTEG_ERR);
    	}

      RHP_TRC(0,RHPTRCID_IKEV2_RECV_IMPL_INVALID_REQ,"xE",pkt,err);
      goto error;
    }

    RHP_TRC(0,RHPTRCID_IKEV2_RECV_IMPL_NEW_REQ,"x",pkt);
  }


  if( vpn ){

    RHP_LOCK(&(vpn->lock));

    if( !_rhp_atomic_read(&(vpn->is_active)) ){

    	RHP_TRC(0,RHPTRCID_IKEV2_RECV_IMPL_VPN_NOT_ACTIVE,"xx",pkt,vpn);
      err = -ENOENT;

  		if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){
  	  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_no_ikesa_err_packets);
  		}else{
  	  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_no_ikesa_err_packets);
  		}

      goto error_l;
    }

    my_ikesa_side
    	= RHP_PROTO_IKE_HDR_INITIATOR(ikeh->flag) ?  RHP_IKE_RESPONDER : RHP_IKE_INITIATOR;
    if( my_ikesa_side == RHP_IKE_INITIATOR ){
    	my_ikesa_spi = ikeh->init_spi;
    }else{
    	my_ikesa_spi = ikeh->resp_spi;
    }

    ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
    if( ikesa == NULL ){

    	RHP_TRC(0,RHPTRCID_IKEV2_RECV_IMPL_NO_IKESA,"xxLdG",pkt,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
    	err = -ENOENT;

  		if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){
  	  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_no_ikesa_err_packets);
  		}else{
  	  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_no_ikesa_err_packets);
  		}

      goto error_l;
    }

   	if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) &&
   			(ikesa->keep_alive.req_mesg_id == ntohl(ikeh->message_id)) ){
      ikesa->statistics.rx_keep_alive_reply_packets++;
    }
  }


  //
  // [CAUTION]
  //
  //  - A value of ikeh's pointer may change after defragmentation.
  //
  //	- ikesa may be NULL before SA is established.
  //
  err = rhp_ikev2_new_mesg_rx(pkt,&ikeh,vpn,ikesa,&rx_ikemesg,NULL,NULL,&ikemesg_error);

  if( err == RHP_STATUS_IKEV2_FRAG_RX_COMPLETED ){

		RHP_TRC(0,RHPTRCID_IKEV2_RECV_IMPL_RX_FRAG_PENDING_RX_COMPLETED,"xxx",pkt,vpn,ikesa);

   	if( !RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){

   		ikesa->timers->quit_frag_rx_req_timer(vpn,ikesa);
  	}

   	err = 0;

  }else if( err == RHP_STATUS_IKEV2_FRAG_RX_1ST_FRAG ){

   	if( !RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){

   		ikesa->timers->start_frag_rx_req_timer(vpn,ikesa,(time_t)rhp_gcfg_ikev2_frag_rx_timeout);
  	}

		RHP_TRC(0,RHPTRCID_IKEV2_RECV_IMPL_RX_FRAG_PENDING_RX_1ST_FRAG,"xxx",pkt,vpn,ikesa);
		err = 0;

		goto end;

	}else if( err == RHP_STATUS_IKEV2_FRAG_RX_PENDING ||
						err == RHP_STATUS_IKEV2_FRAG_RX_IGNORED ){

		RHP_TRC(0,RHPTRCID_IKEV2_RECV_IMPL_RX_FRAG_PENDING,"xxx",pkt,vpn,ikesa);
		err = 0;

		goto end;

  }else if( err ){

  	RHP_TRC(0,RHPTRCID_IKEV2_RECV_IMPL_NEW_REQ_ALLOC_ERR,"xxxxE",pkt,vpn,ikesa,ikemesg_error,err);

    if( ikemesg_error ){

    	if( vpn && ikesa ){
    		_rhp_ikev2_send_response(vpn,ikesa,ikemesg_error,NULL,pkt);
    	}

    	rhp_ikev2_unhold_mesg(ikemesg_error);
    }

    if( err > 0 ){

			if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){
  	  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_parse_err_packets);
			}else{
  	  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_parse_err_packets);
			}
    }

  	err = RHP_STATUS_INVALID_MSG;
    goto error_l;
  }


  if( rx_ikemesg->decrypted ){
    ikesa->statistics.rx_encrypted_packets++;
  }


	if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){

		int do_destroy_vpn = 0;

	  tx_ikemesg = rhp_ikev2_new_mesg_tx(0,0,0);
	  if( tx_ikemesg == NULL ){
	  	RHP_BUG("");
	  	goto error_l;
	  }

		err = _rhp_ikev2_call_rx_response_mesg_handlers(rx_ikemesg,vpn,
				my_ikesa_side,my_ikesa_spi,tx_ikemesg,RHP_IKEV2_MESG_HANDLER_START);

	  //*********************************************************************
		//
		// [CAUTION]
		// Don't touch 'ikesa' any more! It may be deleted from 'vpn'.
		//
		// If needed, get 'ikesa' again from vpn.
		//
	  //*********************************************************************

		if( err == RHP_STATUS_IKEV2_MESG_HANDLER_PENDING ){

			rhp_pkt_pending(pkt);
			goto pending;

		}else if( err == RHP_STATUS_IKEV2_DESTROY_SA_AFTER_TX ){

	  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_process_err_packets);

			do_destroy_vpn = 1;

		}else if( err ){

	  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_process_err_packets);

			goto error_l;
		}

		if( vpn && tx_ikemesg->activated ){

			// Get 'ikesa' again here.
			ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
			if( ikesa ){

				rhp_ikev2_send_request(vpn,ikesa,tx_ikemesg,RHP_IKEV2_MESG_HANDLER_START);

				if( do_destroy_vpn ){

					rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		  		ikesa->timers->schedule_delete(vpn,ikesa,0);
				}

			}else{
				RHP_BUG("");
			}
		}

	}else{

		int my_ikesa_side_new = -1;
		u8 my_ikesa_spi_new[RHP_PROTO_IKE_SPI_SIZE];
		int do_destroy_vpn = 0;

	  tx_ikemesg = rhp_ikev2_new_mesg_tx(rx_ikemesg->get_exchange_type(rx_ikemesg),
	  							rx_ikemesg->get_mesg_id(rx_ikemesg),0);
	  if( tx_ikemesg == NULL ){
	  	RHP_BUG("");
	  	goto error_l;
	  }

		err = _rhp_ikev2_call_rx_request_mesg_handlers(rx_ikemesg,vpn,
						my_ikesa_side,my_ikesa_spi,tx_ikemesg,RHP_IKEV2_MESG_HANDLER_START,
						&vpn_ref,&my_ikesa_side_new,my_ikesa_spi_new);
		vpn = RHP_VPN_REF(vpn_ref);

	  //*********************************************************************
		//
		// [CAUTION]
		// Don't touch 'ikesa' any more! It may be deleted from 'vpn'.
		//
		// If needed, get 'ikesa' again from vpn.
		//
	  //*********************************************************************

		if( err == RHP_STATUS_IKEV2_MESG_HANDLER_PENDING ){

			rhp_pkt_pending(pkt);
			goto pending;

		}else if( err == RHP_STATUS_IKEV2_DESTROY_SA_AFTER_TX ){

	  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_process_err_packets);

			do_destroy_vpn = 1;

		}else if( err ){

  		rhp_ikev2_g_statistics_inc(rx_ikev2_req_process_err_packets);

    	if( err == RHP_STATUS_INVALID_MSG &&
    			!rhp_gcfg_ikev2_dont_tx_general_err_resp &&
    			vpn &&
    			rx_ikemesg->decrypted && (tx_ikemesg->put_n_payload_err < 1) ){

    		rhp_ikev2_payload* ikepayload = NULL;

  	    if( !rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){

  	    	tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

  	    	ikepayload->ext.n->set_protocol_id(ikepayload,0);
  	    	ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ERR_INVALID_SYNTAX);

  	    }else{

  	    	RHP_BUG("");
      		goto error_l;
  	    }

    	}else{
    		goto error_l;
    	}
		}

	  //*********************************************************************
		//
		// [CAUTION]
		// Don't touch 'ikesa' any more! It may be deleted from 'vpn'.
		//
		// If needed, get 'ikesa' again from vpn.
		//
	  //*********************************************************************

		if( vpn && my_ikesa_side_new != -1 ){
			my_ikesa_side = my_ikesa_side_new;
			my_ikesa_spi = my_ikesa_spi_new;
		}


  	if( vpn && tx_ikemesg->activated ){

  	  //*********************************************************************
  		//
  		// [CAUTION]
  		// Don't touch 'ikesa' any more! It may be deleted from 'vpn'.
  		//
  		// If needed, get 'ikesa' again from vpn.
  		//
  	  //*********************************************************************

  		ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
  		if( ikesa ){

  			_rhp_ikev2_send_response(vpn,ikesa,tx_ikemesg,rx_ikemesg,NULL);

				if( do_destroy_vpn ){

					rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
					ikesa->timers->schedule_delete(vpn,ikesa,0);
				}

  		}else{
  			RHP_BUG("");
  		}
    }
	}


end:
	if( vpn && RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){

		rhp_ikev2_send_request(vpn,NULL,NULL,RHP_IKEV2_MESG_HANDLER_START); // Send a Qed request packet , if any.
	}


	_rhp_ikev2_send_radius_acct_start(vpn);


pending:
  if( vpn ){
  	RHP_UNLOCK(&(vpn->lock));
    rhp_vpn_unhold(vpn_ref);
  }

  if( rx_ikemesg ){
    rhp_ikev2_unhold_mesg(rx_ikemesg);
  }

  if( tx_ikemesg ){
    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RECV_IMPL_RTRN,"xxx",pkt,vpn,vpn_ref);
  return 0;


error_l:
  if( vpn ){
    RHP_UNLOCK(&(vpn->lock));
  }

error:
	if( err != RHP_STATUS_IKEV2_MESG_QCD_INVALID_IKE_SPI_NTFY ){

		if( addr_family == AF_INET ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV2_IPV4_RX_ERR,"V44WWGGLUUddE",vpn,(pkt && pkt->l3.raw ? pkt->l3.iph_v4->src_addr : 0),(pkt && pkt->l3.raw ? pkt->l3.iph_v4->dst_addr : 0),(pkt && pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt && pkt->l4.raw ? pkt->l4.udph->dst_port : 0),(pkt && pkt->app.ikeh ? pkt->app.ikeh->init_spi : NULL),(pkt && pkt->app.ikeh ? pkt->app.ikeh->resp_spi : NULL),"PROTO_IKE_EXCHG",(int)(pkt && pkt->app.ikeh ? pkt->app.ikeh->exchange_type : 0),(pkt && pkt->app.ikeh ? pkt->app.ikeh->message_id : 0),(pkt && pkt->app.ikeh ? pkt->app.ikeh->len : 0),(pkt && pkt->app.ikeh ? RHP_PROTO_IKE_HDR_INITIATOR(pkt->app.ikeh->flag) : -1),(pkt && pkt->app.ikeh ? RHP_PROTO_IKE_HDR_RESPONSE(pkt->app.ikeh->flag) : -1),err);
		}else if( addr_family == AF_INET6 ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV2_IPV6_RX_ERR,"V66WWGGLUUddE",vpn,(pkt && pkt->l3.raw ? pkt->l3.iph_v6->src_addr : NULL),(pkt && pkt->l3.raw ? pkt->l3.iph_v6->dst_addr : NULL),(pkt && pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt && pkt->l4.raw ? pkt->l4.udph->dst_port : 0),(pkt && pkt->app.ikeh ? pkt->app.ikeh->init_spi : NULL),(pkt && pkt->app.ikeh ? pkt->app.ikeh->resp_spi : NULL),"PROTO_IKE_EXCHG",(int)(pkt && pkt->app.ikeh ? pkt->app.ikeh->exchange_type : 0),(pkt && pkt->app.ikeh ? pkt->app.ikeh->message_id : 0),(pkt && pkt->app.ikeh ? pkt->app.ikeh->len : 0),(pkt && pkt->app.ikeh ? RHP_PROTO_IKE_HDR_INITIATOR(pkt->app.ikeh->flag) : -1),(pkt && pkt->app.ikeh ? RHP_PROTO_IKE_HDR_RESPONSE(pkt->app.ikeh->flag) : -1),err);
		}

		if( ikeh ){
	  	if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){
		  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_err_packets);
	  	}else{
		  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_err_packets);
	  	}
	  }
		rhp_ikev2_g_statistics_inc(rx_ikev2_err_packets);
	}


	if( vpn ){
    rhp_vpn_unhold(vpn_ref);
  }

	if( rx_ikemesg ){
    rhp_ikev2_unhold_mesg(rx_ikemesg);
  }

	if( tx_ikemesg ){
    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }

	RHP_TRC(0,RHPTRCID_IKEV2_RECV_IMPL_ERR,"xxxE",pkt,vpn,vpn_ref,err);
  return 0;
}

int rhp_ikev2_recv_ipv4(rhp_packet* pkt)
{
	return _rhp_ikev2_recv_impl(AF_INET,pkt);
}

int rhp_ikev2_recv_ipv6(rhp_packet* pkt)
{
	return _rhp_ikev2_recv_impl(AF_INET6,pkt);
}


// Even if error occurs , ikemesg is released in this function.
void rhp_ikev2_send_request(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* tx_ikemesg,int req_initiator)
{
  RHP_TRC(0,RHPTRCID_IKEV2_SEND_REQUEST,"xxxLd",vpn,ikesa,tx_ikemesg,"IKEV2_MESG_HDLR",req_initiator);
	_rhp_ikev2_send_request(vpn,ikesa,tx_ikemesg,RHP_IKEV2_MESG_HANDLER_START,req_initiator);
}

//
// [CAUTION]
//  This call may acquire (rhp_ifc_entry*)ifc->lock.
//
int rhp_ikev2_retransmit_req(rhp_vpn* vpn,rhp_ikesa* ikesa)
{
  int err = 0;
  rhp_packet *pkt = NULL,*pkt_d = NULL;
  rhp_ifc_entry* tx_ifc = NULL;
  int tx_if_index;
  int mobike_r_pending = 0;
	int retx_cnt = ( vpn->exec_mobike && ikesa->timers->retx_mobike_resp_counter ?
									 ikesa->timers->retx_mobike_resp_counter : ikesa->timers->retx_counter );
	int addr_family;
	u8* addr;
	u16 src_port = 0;
	rhp_proto_ike* ikeh = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_RETRANSMIT_REQ,"xxdd",vpn,ikesa,vpn->exec_mobike,(vpn->origin_side == RHP_IKE_RESPONDER ? vpn->mobike.resp.rt_ck_pending : vpn->mobike.init.rt_ck_pending));

  if( ikesa->req_retx_pkt == NULL ||
  		ikesa->req_retx_ikemesg == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_RETRANSMIT_REQ_NO_PKT,"xxx",ikesa,ikesa->req_retx_ikemesg,ikesa->req_retx_pkt);
    err = RHP_STATUS_IKEV2_RETRANS_PKT_CLEARED;
    goto skip;
  }

  pkt = ikesa->req_retx_pkt;

	RHP_TRC(0,RHPTRCID_IKEV2_RETRANSMIT_REQ_Q_PKT,"xxx",ikesa,ikesa->req_retx_ikemesg,pkt);


  if( rhp_ikev2_mobike_pending(vpn) &&
  		vpn->origin_side == RHP_IKE_RESPONDER ){
  	mobike_r_pending = 1;
  }

	if( ikesa->req_retx_ikemesg->tx_from_nat_t_port ){
		src_port = vpn->local.port_nat_t;
	}else{
		src_port = vpn->local.port;
	}

	if( pkt->type == RHP_PKT_IPV4_IKE ){
		addr_family = AF_INET;
		addr = (u8*)&(pkt->l3.iph_v4->src_addr);
	}else if( pkt->type == RHP_PKT_IPV6_IKE ){
		addr_family = AF_INET6;
		addr = (u8*)&(pkt->l3.iph_v6->src_addr);
	}else{
		RHP_BUG("");
		err = -EINVAL;
		goto skip;
	}


	if( mobike_r_pending ){

		tx_if_index = vpn->mobike.resp.rt_ck_pend_local_if_info.if_index;

		err = rhp_pkt_rebuild_ip_udp_header(pkt,
						vpn->mobike.resp.rt_ck_pend_local_if_info.addr_family,
						vpn->mobike.resp.rt_ck_pend_local_if_info.addr.raw,
						vpn->mobike.resp.rt_ck_pend_peer_addr.addr.raw,
						src_port,vpn->mobike.resp.rt_ck_pend_peer_addr.port);

		if( err ){
			goto skip;
		}

	}else{

		if( pkt->fixed_tx_if_index >= 0 ){
			tx_if_index = pkt->fixed_tx_if_index;
		}else{
			tx_if_index = vpn->local.if_info.if_index;
		}

		err = rhp_pkt_rebuild_ip_udp_header(pkt,
						vpn->local.if_info.addr_family,
						vpn->local.if_info.addr.raw,vpn->peer_addr.addr.raw,
						src_port,vpn->peer_addr.port);

		if( err ){
			goto skip;
		}
	}


	tx_ifc = rhp_ifc_get_by_if_idx(tx_if_index); // (***)
	if( tx_ifc == NULL ){
		if( pkt->type == RHP_PKT_IPV4_IKE ){
			RHP_TRC(0,RHPTRCID_IKEV2_RETRANSMIT_REQ_NO_TX_IF_FOUND,"xdx44WW",ikesa,tx_if_index,pkt,pkt->l3.iph_v4->src_addr,pkt->l3.iph_v4->dst_addr,pkt->l4.udph->src_port,pkt->l4.udph->dst_port);
		}else if( pkt->type == RHP_PKT_IPV6_IKE ){
			RHP_TRC(0,RHPTRCID_IKEV2_RETRANSMIT_REQ_NO_TX_IF_FOUND_V6,"xdx66WW",ikesa,tx_if_index,pkt,pkt->l3.iph_v6->src_addr,pkt->l3.iph_v6->dst_addr,pkt->l4.udph->src_port,pkt->l4.udph->dst_port);
		}
		err = -ENODEV;
		goto skip;
	}

	if( pkt->fixed_tx_if_index >= 0 ){

		RHP_LOCK(&(tx_ifc->lock));

		if( tx_ifc->get_addr(tx_ifc,addr_family,addr) ){

			if( pkt->type == RHP_PKT_IPV4_IKE ){
				RHP_TRC(0,RHPTRCID_IKEV2_RETRANSMIT_REQ_TX_SRC_ADDR_NOT_MATCHED,"xddx44WW",ikesa,pkt->fixed_tx_if_index,tx_if_index,pkt,pkt->l3.iph_v4->src_addr,pkt->l3.iph_v4->dst_addr,pkt->l4.udph->src_port,pkt->l4.udph->dst_port);
			}else if( pkt->type == RHP_PKT_IPV6_IKE ){
				RHP_TRC(0,RHPTRCID_IKEV2_RETRANSMIT_REQ_TX_SRC_ADDR_NOT_MATCHED_V6,"xddx66WW",ikesa,pkt->fixed_tx_if_index,tx_if_index,pkt,pkt->l3.iph_v6->src_addr,pkt->l3.iph_v6->dst_addr,pkt->l4.udph->src_port,pkt->l4.udph->dst_port);
			}

			RHP_UNLOCK(&(tx_ifc->lock));

			err = -ENODEV;
			goto skip;
		}

		RHP_UNLOCK(&(tx_ifc->lock));
	}


	if( (pkt->type == RHP_PKT_IPV4_IKE &&
			 (pkt->l3.iph_v4->src_addr == 0 || pkt->l3.iph_v4->dst_addr == 0)) ||
			(pkt->type == RHP_PKT_IPV6_IKE &&
			 (rhp_ipv6_addr_null(pkt->l3.iph_v6->src_addr) || rhp_ipv6_addr_null(pkt->l3.iph_v6->dst_addr))) ||
			pkt->l4.udph->dst_port == 0 ){

		if( pkt->type == RHP_PKT_IPV4_IKE ){
			RHP_TRC(0,RHPTRCID_IKEV2_RETRANSMIT_REQ_NO_IP_PORT,"xx44W",ikesa,pkt,pkt->l3.iph_v4->src_addr,pkt->l3.iph_v4->dst_addr,pkt->l4.udph->dst_port);
		}else if( pkt->type == RHP_PKT_IPV6_IKE ){
			RHP_TRC(0,RHPTRCID_IKEV2_RETRANSMIT_REQ_NO_IP_PORT_V6,"xx66W",ikesa,pkt,pkt->l3.iph_v6->src_addr,pkt->l3.iph_v6->dst_addr,pkt->l4.udph->dst_port);
		}

		err = RHP_STATUS_NO_IP;
		goto skip;
	}


	pkt_d = rhp_pkt_dup(pkt);
	if( pkt_d == NULL ){
		RHP_BUG("");
		goto skip;
	}

	pkt_d->tx_ifc = tx_ifc;
	rhp_ifc_hold(pkt_d->tx_ifc);



	if( ikesa->req_retx_ikemesg->tx_from_nat_t_port ){
		ikeh = (rhp_proto_ike*)(pkt->app.raw + RHP_PROTO_NON_ESP_MARKER_SZ);
	}else{
		ikeh = pkt->app.ikeh;
	}

	_RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
	if( _RHP_TRC_COND(_rhp_trc_user_id(),0) ){

		int iv_len = 0;
		int icv_len = 0;
		rhp_crypto_integ* integ = NULL;

		if( ikesa->encr ){
			iv_len = ikesa->encr->get_iv_len(ikesa->encr);
		}

		if( ikesa->side == RHP_IKE_INITIATOR ){
			integ = ikesa->integ_i;
		}else{
			integ = ikesa->integ_r;
		}

		if( integ ){

			icv_len = integ->get_output_len(integ);
		}

		if( pkt->type == RHP_PKT_IPV4_IKE ){
			RHP_TRC(0,RHPTRCID_IKEV2_RETRANSMIT_TX_DUP_V4_PKT,"xxxxa",vpn,ikesa,pkt,pkt_d,(pkt_d->tail - pkt_d->data),RHP_TRC_FMT_A_MAC_IPV4_IKEV2,iv_len,icv_len,pkt_d->data);
		}else if( pkt->type == RHP_PKT_IPV6_IKE ){
			RHP_TRC(0,RHPTRCID_IKEV2_RETRANSMIT_TX_DUP_V6_PKT,"xxxxa",vpn,ikesa,pkt,pkt_d,(pkt_d->tail - pkt_d->data),RHP_TRC_FMT_A_MAC_IPV6_IKEV2,iv_len,icv_len,pkt_d->data);
		}
	}

#if defined(RHP_PKT_DBG_IKEV2_RETRANS_TEST) || defined(RHP_PKT_DBG_IKEV2_RETRANS_FRAG_TEST)
	pkt_d->ikev2_retrans_pkt = RHP_PKT_IKEV2_RETRANS_REQ;
#endif // RHP_PKT_DBG_IKEV2_RETRANS_TEST

	err = rhp_netsock_send(pkt_d->tx_ifc,pkt_d);
	if( err < 0 ){

		RHP_TRC(0,RHPTRCID_IKEV2_RETRANSMIT_REQ_TX_PKT_ERR,"xxxxxE",vpn,ikesa,pkt,pkt_d,pkt_d->tx_ifc,err);

		if( pkt->type == RHP_PKT_IPV4_IKE ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV2_RETRANSMIT_REQ_ERR,"VPd44WWGGLJE",vpn,ikesa,retx_cnt,(pkt_d->l3.raw ? pkt_d->l3.iph_v4->src_addr : 0),(pkt_d && pkt_d->l3.raw ? pkt_d->l3.iph_v4->dst_addr : 0),(pkt_d && pkt_d->l4.raw ? pkt_d->l4.udph->src_port : 0),(pkt_d && pkt_d->l4.raw ? pkt_d->l4.udph->dst_port : 0),(ikeh ? ikeh->init_spi : NULL),(ikeh ? ikeh->resp_spi : NULL),"PROTO_IKE_EXCHG",(ikeh ? (int)ikeh->exchange_type : 0),(ikeh ? ikeh->message_id : 0),err);
		}else if( pkt->type == RHP_PKT_IPV6_IKE ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV2_RETRANSMIT_REQ_V6_ERR,"VPd66WWGGLJE",vpn,ikesa,retx_cnt,(pkt_d->l3.raw ? pkt_d->l3.iph_v6->src_addr : NULL),(pkt_d && pkt_d->l3.raw ? pkt_d->l3.iph_v6->dst_addr : NULL),(pkt_d && pkt_d->l4.raw ? pkt_d->l4.udph->src_port : 0),(pkt_d && pkt_d->l4.raw ? pkt_d->l4.udph->dst_port : 0),(ikeh ? ikeh->init_spi : NULL),(ikeh ? ikeh->resp_spi : NULL),"PROTO_IKE_EXCHG",(ikeh ? (int)ikeh->exchange_type : 0),(ikeh ? ikeh->message_id : 0),err);
		}
	}
	err = 0;


	if( pkt->type == RHP_PKT_IPV4_IKE ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV2_EXEC_RETRANSMIT,"VPd44WWGGLJ",vpn,ikesa,retx_cnt,(pkt_d->l3.raw ? pkt_d->l3.iph_v4->src_addr : 0),(pkt_d && pkt_d->l3.raw ? pkt_d->l3.iph_v4->dst_addr : 0),(pkt_d && pkt_d->l4.raw ? pkt_d->l4.udph->src_port : 0),(pkt_d && pkt_d->l4.raw ? pkt_d->l4.udph->dst_port : 0),(ikeh ? ikeh->init_spi : NULL),(ikeh ? ikeh->resp_spi : NULL),"PROTO_IKE_EXCHG",(ikeh ? (int)ikeh->exchange_type : 0),(ikeh ? ikeh->message_id : 0));
	}else if( pkt->type == RHP_PKT_IPV6_IKE ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV2_EXEC_RETRANSMIT_V6,"VPd66WWGGLJ",vpn,ikesa,retx_cnt,(pkt_d->l3.raw ? pkt_d->l3.iph_v6->src_addr : NULL),(pkt_d && pkt_d->l3.raw ? pkt_d->l3.iph_v6->dst_addr : NULL),(pkt_d && pkt_d->l4.raw ? pkt_d->l4.udph->src_port : 0),(pkt_d && pkt_d->l4.raw ? pkt_d->l4.udph->dst_port : 0),(ikeh ? ikeh->init_spi : NULL),(ikeh ? ikeh->resp_spi : NULL),"PROTO_IKE_EXCHG",(ikeh ? (int)ikeh->exchange_type : 0),(ikeh ? ikeh->message_id : 0));
	}

	rhp_pkt_unhold(pkt_d);
	pkt_d = NULL;

	rhp_ifc_unhold(tx_ifc);

  RHP_TRC(0,RHPTRCID_IKEV2_RETRANSMIT_REQ_RTRN,"xd",ikesa,err);
  return 0;


skip:
	if( pkt ){
		if( pkt->type == RHP_PKT_IPV4_IKE ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV2_RETRANSMIT_REQ_ERR,"VPd44WWGGLJE",vpn,ikesa,retx_cnt,(pkt_d && pkt_d->l3.raw ? pkt_d->l3.iph_v4->src_addr : 0),(pkt_d && pkt_d->l3.raw ? pkt_d->l3.iph_v4->dst_addr : 0),(pkt_d && pkt_d->l4.raw ? pkt_d->l4.udph->src_port : 0),(pkt_d && pkt_d->l4.raw ? pkt_d->l4.udph->dst_port : 0),(ikeh ? ikeh->init_spi : NULL),(ikeh ? ikeh->resp_spi : NULL),"PROTO_IKE_EXCHG",(ikeh ? (int)ikeh->exchange_type : 0),(ikeh ? ikeh->message_id : 0),err);
		}else if( pkt->type == RHP_PKT_IPV6_IKE ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV2_RETRANSMIT_REQ_V6_ERR,"VPd66WWGGLJE",vpn,ikesa,retx_cnt,(pkt_d && pkt_d->l3.raw ? pkt_d->l3.iph_v6->src_addr : NULL),(pkt_d && pkt_d->l3.raw ? pkt_d->l3.iph_v6->dst_addr : NULL),(pkt_d && pkt_d->l4.raw ? pkt_d->l4.udph->src_port : 0),(pkt_d && pkt_d->l4.raw ? pkt_d->l4.udph->dst_port : 0),(ikeh ? ikeh->init_spi : NULL),(ikeh ? ikeh->resp_spi : NULL),"PROTO_IKE_EXCHG",(ikeh ? (int)ikeh->exchange_type : 0),(ikeh ? ikeh->message_id : 0),err);
		}
	}else{
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV2_RETRANSMIT_REQ_NO_PACKET,"VPdE",vpn,ikesa,retx_cnt,err);
	}
  if( pkt_d ){
    rhp_pkt_unhold(pkt_d);
  }
  if( tx_ifc ){
  	rhp_ifc_unhold(tx_ifc);
  }
  RHP_TRC(0,RHPTRCID_RHPTRCID_IKEV2_RETRANSMIT_REQ_SKIP,"xxxE",vpn,ikesa,pkt_d,err);
  return err;
}


static int rhp_ikev2_tx_plain_err_serialize_payload_cb(rhp_ikev2_mesg* ikemesg,
		int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  rhp_packet* pkt = (rhp_packet*)ctx;
  int err;

  RHP_TRC(0,RHPTRCID_IKEV2_TX_PLAIN_ERR_SERIALIZE_PAYLOAD_CB,"xxLbxxd",ikemesg,payload,"PROTO_IKE_PAYLOAD",payload->payload_id,ctx,pkt,ikemesg->tx_mesg_len);

  err = payload->ext_serialize(payload,pkt);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV2_TX_PLAIN_ERR_SERIALIZE_PAYLOAD_CB_ERR,"xxLbxE",ikemesg,payload,"PROTO_IKE_PAYLOAD",payload->payload_id,ctx,err);
    return err;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_TX_PLAIN_ERR_SERIALIZE_PAYLOAD_CB_RTRN,"xxxd",ikemesg,payload,pkt,ikemesg->tx_mesg_len);

  return 0;
}

int rhp_ikev2_tx_plain_error_rep_v4(
		rhp_proto_ip_v4* rx_req_iph,rhp_proto_udp* rx_req_udph,rhp_proto_ike* rx_req_ikeh,
		rhp_ifc_entry *rx_req_ifc,
		int (*add_payloads_callback)(rhp_ikev2_mesg* tx_ikemesg,void* ctx),void* ctx)
{
  int err = -EINVAL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_packet* pkt = NULL;
  rhp_proto_ether* dmy_ethh_r;
  rhp_proto_ip_v4* dmy_iph_r;
  rhp_proto_udp* dmy_udph_r;
  rhp_proto_ike* ikeh_r;
  u8* head;
  int nat_t = 0;
  u8 ikeh_flag = RHP_PROTO_IKE_HDR_SET_RESPONSE;

  RHP_TRC(0,RHPTRCID_IKEV2_TX_PLAIN_ERROR_REP_V4,"pppxYx",sizeof(rhp_proto_ip_v4),rx_req_iph,sizeof(rhp_proto_udp),rx_req_udph,sizeof(rhp_proto_ike),rx_req_ikeh,rx_req_ifc,add_payloads_callback,ctx);

  if( rx_req_ifc == NULL || rx_req_iph == NULL || rx_req_udph == NULL || rx_req_ikeh == NULL ){
    RHP_BUG("");
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_TX_PLAIN_ERROR_REP_V4_RX_DATA,"44WWGGbbbbbJsd",rx_req_iph->src_addr,rx_req_iph->dst_addr,rx_req_udph->src_port,rx_req_udph->dst_port,rx_req_ikeh->init_spi,rx_req_ikeh->resp_spi,rx_req_ikeh->exchange_type,rx_req_ikeh->next_payload,rx_req_ikeh->flag,RHP_PROTO_IKE_HDR_INITIATOR(rx_req_ikeh->flag),RHP_PROTO_IKE_HDR_RESPONSE(rx_req_ikeh->flag),rx_req_ikeh->message_id,rx_req_ifc->if_name,rx_req_ifc->if_index);


  if( *((u32*)rx_req_ikeh) == RHP_PROTO_NON_ESP_MARKER ){
  	rx_req_ikeh = (rhp_proto_ike*)(((u8*)rx_req_ikeh) + RHP_PROTO_NON_ESP_MARKER_SZ);
  }


  if( rx_req_udph->dst_port == htons(rhp_gcfg_ike_port_nat_t) ){
    nat_t = 1;
  }

  if( !RHP_PROTO_IKE_HDR_INITIATOR(rx_req_ikeh->flag) ){
  	ikeh_flag = (ikeh_flag | RHP_PROTO_IKE_HDR_SET_INITIATOR);
  }

  tx_ikemesg = rhp_ikev2_new_mesg_tx(rx_req_ikeh->exchange_type,
  								ntohl(rx_req_ikeh->message_id),ikeh_flag);
  if( tx_ikemesg == NULL ){
    RHP_BUG("");
    goto error;
  }

  tx_ikemesg->set_init_spi(tx_ikemesg,rx_req_ikeh->init_spi);

  if( rx_req_ikeh->exchange_type != RHP_PROTO_IKE_EXCHG_IKE_SA_INIT &&
  		rx_req_ikeh->exchange_type != RHP_PROTO_IKE_EXCHG_SESS_RESUME ){

  	tx_ikemesg->set_resp_spi(tx_ikemesg,rx_req_ikeh->resp_spi);
  }


  if( add_payloads_callback ){

  	err = add_payloads_callback(tx_ikemesg,ctx);
  	if( err ){
  		goto error;
  	}
  }


  //*******************************************************************************************
  //
  // vpn and ikesa don't exist. Packet for response is created directly here.
  //
  //*******************************************************************************************

  pkt = rhp_pkt_alloc(RHP_PKT_IKE_DEFAULT_SIZE);
  if( pkt == NULL ){
    RHP_BUG("");
    goto error;
  }

  pkt->type = RHP_PKT_IPV4_IKE;

  dmy_ethh_r = (rhp_proto_ether*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ether));
  dmy_iph_r = (rhp_proto_ip_v4*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ip_v4));
  dmy_udph_r = (rhp_proto_udp*)_rhp_pkt_push(pkt,sizeof(rhp_proto_udp));
  if( nat_t ){

    head = _rhp_pkt_push(pkt,RHP_PROTO_NON_ESP_MARKER_SZ);
    *((u32*)head) = RHP_PROTO_NON_ESP_MARKER;
    pkt->ikev2_non_esp_marker = 1;

  }else{

  	head = _rhp_pkt_push(pkt,0);
    pkt->ikev2_non_esp_marker = 0;
  }
  ikeh_r = (rhp_proto_ike*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ike));

  pkt->l2.eth = dmy_ethh_r;
  pkt->l3.iph_v4 = dmy_iph_r;
  pkt->l4.udph = dmy_udph_r;
  pkt->app.raw = head;

  dmy_ethh_r->protocol = RHP_PROTO_ETH_IP;
  memset(dmy_ethh_r->src_addr,0,6);
  memset(dmy_ethh_r->dst_addr,0,6);

  dmy_iph_r->ver = 4;
  dmy_iph_r->ihl = 5;
  dmy_iph_r->tos = 0;
  dmy_iph_r->total_len = 0;
  dmy_iph_r->id = 0;
  dmy_iph_r->frag = 0;
  dmy_iph_r->ttl = 64;
  dmy_iph_r->protocol = RHP_PROTO_IP_UDP;
  dmy_iph_r->check_sum = 0;

  dmy_udph_r->len = 0;
  dmy_udph_r->check_sum = 0;

  dmy_iph_r->src_addr = rx_req_iph->dst_addr;
  dmy_udph_r->src_port = rx_req_udph->dst_port;

  dmy_iph_r->dst_addr = rx_req_iph->src_addr;
  dmy_udph_r->dst_port = rx_req_udph->src_port;


  //
  //
  // [CAUTION] rhp_pkt_realloc() may be called. Don't access pointers of dmy_xxxhs, non_esp_marker and ikeh_r any more.
  //
  //
	err = tx_ikemesg->search_payloads(tx_ikemesg,0,NULL,NULL,
					rhp_ikev2_tx_plain_err_serialize_payload_cb,pkt);
  if( err && err != -ENOENT && err != RHP_STATUS_ENUM_OK  ){
    RHP_BUG("");
    goto error;
  }
  err = 0;


  // [CAUTION] rhp_pkt_realloc() may be called. Get new pointers from pkt.
  dmy_iph_r = pkt->l3.iph_v4;
  dmy_udph_r = pkt->l4.udph;
  if( pkt->ikev2_non_esp_marker ){
  	ikeh_r = (rhp_proto_ike*)(pkt->app.raw + RHP_PROTO_NON_ESP_MARKER_SZ);
  }else{
  	ikeh_r = pkt->app.ikeh;
  }

  tx_ikemesg->tx_ikeh->len = htonl(tx_ikemesg->tx_mesg_len);

  if( tx_ikemesg->payload_list_head ){
    tx_ikemesg->tx_ikeh->next_payload = tx_ikemesg->payload_list_head->get_payload_id(tx_ikemesg->payload_list_head);
  }

  memcpy(ikeh_r,tx_ikemesg->tx_ikeh,sizeof(rhp_proto_ike));

  if( nat_t ){

    dmy_iph_r->total_len
    = htons(tx_ikemesg->tx_mesg_len + sizeof(rhp_proto_ip_v4) + sizeof(rhp_proto_udp) + RHP_PROTO_NON_ESP_MARKER_SZ);

    dmy_udph_r->len = htons(tx_ikemesg->tx_mesg_len + sizeof(rhp_proto_udp) + RHP_PROTO_NON_ESP_MARKER_SZ);

  }else{

    dmy_iph_r->total_len
    = htons(tx_ikemesg->tx_mesg_len + sizeof(rhp_proto_ip_v4) + sizeof(rhp_proto_udp));

    dmy_udph_r->len = htons(tx_ikemesg->tx_mesg_len + sizeof(rhp_proto_udp));
  }

  RHP_TRC(0,RHPTRCID_IKEV2_TX_PLAIN_ERROR_REP_V4_TX_PKT,"xxa",rx_req_iph,pkt,(pkt->tail - pkt->l2.raw),RHP_TRC_FMT_A_MAC_IPV4_IKEV2,0,0,pkt->l2.raw);
  rhp_pkt_trace_dump("rhp_ikev2_tx_plain_error_rep_v4",pkt);

  err = rhp_netsock_send(rx_req_ifc,pkt);
  if( err < 0 ){
    RHP_TRC(0,RHPTRCID_IKEV2_TX_PLAIN_ERROR_REP_V4_TX_PKT_ERR,"xxE",rx_req_iph,pkt,err);
  }
  err = 0;

  rhp_pkt_unhold(pkt);
  rhp_ikev2_unhold_mesg(tx_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_TX_PLAIN_ERROR_REP_V4_RTRN,"xxx",rx_req_iph,pkt,tx_ikemesg);
  return 0;

error:
	if( pkt ){
		rhp_pkt_unhold(pkt);
	}

  if( tx_ikemesg ){
    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_TX_PLAIN_ERROR_REP_V4_ERR,"xxxE",rx_req_iph,pkt,tx_ikemesg,err);
  return err;
}


int rhp_ikev2_tx_plain_error_rep_v6(
		rhp_proto_ip_v6* rx_req_ip6h,rhp_proto_udp* rx_req_udph,rhp_proto_ike* rx_req_ikeh,
		rhp_ifc_entry *rx_req_ifc,
		int (*add_payloads_callback)(rhp_ikev2_mesg* tx_ikemesg,void* ctx),void* ctx)
{
  int err = -EINVAL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_packet* pkt = NULL;
  rhp_proto_ether* dmy_ethh_r;
  rhp_proto_ip_v6* dmy_ip6h_r;
  rhp_proto_udp* dmy_udph_r;
  rhp_proto_ike* ikeh_r;
  u8* head;
  int nat_t = 0;
  u8 ikeh_flag = RHP_PROTO_IKE_HDR_SET_RESPONSE;

  RHP_TRC(0,RHPTRCID_IKEV2_TX_PLAIN_ERROR_REP_V6,"pppxYx",sizeof(rhp_proto_ip_v6),rx_req_ip6h,sizeof(rhp_proto_udp),rx_req_udph,sizeof(rhp_proto_ike),rx_req_ikeh,rx_req_ifc,add_payloads_callback,ctx);

  if( rx_req_ifc == NULL || rx_req_ip6h == NULL || rx_req_udph == NULL || rx_req_ikeh == NULL ){
    RHP_BUG("");
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_TX_PLAIN_ERROR_REP_V6_RX_DATA,"66WWGGbbbbbJsd",rx_req_ip6h->src_addr,rx_req_ip6h->dst_addr,rx_req_udph->src_port,rx_req_udph->dst_port,rx_req_ikeh->init_spi,rx_req_ikeh->resp_spi,rx_req_ikeh->exchange_type,rx_req_ikeh->next_payload,rx_req_ikeh->flag,RHP_PROTO_IKE_HDR_INITIATOR(rx_req_ikeh->flag),RHP_PROTO_IKE_HDR_RESPONSE(rx_req_ikeh->flag),rx_req_ikeh->message_id,rx_req_ifc->if_name,rx_req_ifc->if_index);


  if( *((u32*)rx_req_ikeh) == RHP_PROTO_NON_ESP_MARKER ){
  	rx_req_ikeh = (rhp_proto_ike*)(((u8*)rx_req_ikeh) + RHP_PROTO_NON_ESP_MARKER_SZ);
  }


  if( rx_req_udph->dst_port == htons(rhp_gcfg_ike_port_nat_t) ){
    nat_t = 1;
  }

  if( !RHP_PROTO_IKE_HDR_INITIATOR(rx_req_ikeh->flag) ){
  	ikeh_flag = (ikeh_flag | RHP_PROTO_IKE_HDR_SET_INITIATOR);
  }

  tx_ikemesg = rhp_ikev2_new_mesg_tx(rx_req_ikeh->exchange_type,
  								ntohl(rx_req_ikeh->message_id),ikeh_flag);
  if( tx_ikemesg == NULL ){
    RHP_BUG("");
    goto error;
  }

  tx_ikemesg->set_init_spi(tx_ikemesg,rx_req_ikeh->init_spi);

  if( rx_req_ikeh->exchange_type != RHP_PROTO_IKE_EXCHG_IKE_SA_INIT &&
  		rx_req_ikeh->exchange_type != RHP_PROTO_IKE_EXCHG_SESS_RESUME ){

  	tx_ikemesg->set_resp_spi(tx_ikemesg,rx_req_ikeh->resp_spi);
  }


  if( add_payloads_callback ){

  	err = add_payloads_callback(tx_ikemesg,ctx);
  	if( err ){
  		goto error;
  	}
  }


  //*******************************************************************************************
  //
  // vpn and ikesa don't exist. Packet for response is created directly here.
  //
  //*******************************************************************************************

  pkt = rhp_pkt_alloc(RHP_PKT_IKE_DEFAULT_SIZE);
  if( pkt == NULL ){
    RHP_BUG("");
    goto error;
  }

  pkt->type = RHP_PKT_IPV6_IKE;

  dmy_ethh_r = (rhp_proto_ether*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ether));
  dmy_ip6h_r = (rhp_proto_ip_v6*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ip_v6));
  dmy_udph_r = (rhp_proto_udp*)_rhp_pkt_push(pkt,sizeof(rhp_proto_udp));
  if( nat_t ){

    head = _rhp_pkt_push(pkt,RHP_PROTO_NON_ESP_MARKER_SZ);
    *((u32*)head) = RHP_PROTO_NON_ESP_MARKER;
    pkt->ikev2_non_esp_marker = 1;

  }else{

  	head = _rhp_pkt_push(pkt,0);
    pkt->ikev2_non_esp_marker = 0;
  }
  ikeh_r = (rhp_proto_ike*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ike));

  pkt->l2.eth = dmy_ethh_r;
  pkt->l3.iph_v6 = dmy_ip6h_r;
  pkt->l4.udph = dmy_udph_r;
  pkt->app.raw = head;

  dmy_ethh_r->protocol = RHP_PROTO_ETH_IPV6;
  memset(dmy_ethh_r->src_addr,0,6);
  memset(dmy_ethh_r->dst_addr,0,6);

  dmy_ip6h_r->ver = 6;
  dmy_ip6h_r->priority = 0;
  dmy_ip6h_r->flow_label[0] = 0;
  dmy_ip6h_r->flow_label[1] = 0;
  dmy_ip6h_r->flow_label[2] = 0;
  dmy_ip6h_r->next_header = RHP_PROTO_IP_UDP;
  dmy_ip6h_r->hop_limit = 64;
  dmy_ip6h_r->payload_len = 0;

  dmy_udph_r->len = 0;
  dmy_udph_r->check_sum = 0;

	memcpy(dmy_ip6h_r->src_addr,rx_req_ip6h->dst_addr,16);
  dmy_udph_r->src_port = rx_req_udph->dst_port;

	memcpy(dmy_ip6h_r->dst_addr,rx_req_ip6h->src_addr,16);
  dmy_udph_r->dst_port = rx_req_udph->src_port;


  //
  //
  // [CAUTION] rhp_pkt_realloc() may be called. Don't access pointers of dmy_xxxhs,
  //           non_esp_marker and ikeh_r any more.
  //
  //
	err = tx_ikemesg->search_payloads(tx_ikemesg,0,NULL,NULL,
					rhp_ikev2_tx_plain_err_serialize_payload_cb,pkt);
  if( err && err != -ENOENT && err != RHP_STATUS_ENUM_OK  ){
    RHP_BUG("");
    goto error;
  }
  err = 0;


  // [CAUTION] rhp_pkt_realloc() may be called. Get new pointers from pkt.
  dmy_ip6h_r = pkt->l3.iph_v6;
  dmy_udph_r = pkt->l4.udph;
  if( pkt->ikev2_non_esp_marker ){
  	ikeh_r = (rhp_proto_ike*)(pkt->app.raw + RHP_PROTO_NON_ESP_MARKER_SZ);
  }else{
  	ikeh_r = pkt->app.ikeh;
  }


  tx_ikemesg->tx_ikeh->len = htonl(tx_ikemesg->tx_mesg_len);

  if( tx_ikemesg->payload_list_head ){

  	tx_ikemesg->tx_ikeh->next_payload
    	= tx_ikemesg->payload_list_head->get_payload_id(tx_ikemesg->payload_list_head);
  }

  memcpy(ikeh_r,tx_ikemesg->tx_ikeh,sizeof(rhp_proto_ike));

  if( nat_t ){

    dmy_ip6h_r->payload_len
    = htons(tx_ikemesg->tx_mesg_len + sizeof(rhp_proto_udp) + RHP_PROTO_NON_ESP_MARKER_SZ);

    dmy_udph_r->len
    = htons(tx_ikemesg->tx_mesg_len + sizeof(rhp_proto_udp) + RHP_PROTO_NON_ESP_MARKER_SZ);

  }else{

    dmy_ip6h_r->payload_len = htons(tx_ikemesg->tx_mesg_len + sizeof(rhp_proto_udp));

    dmy_udph_r->len = htons(tx_ikemesg->tx_mesg_len + sizeof(rhp_proto_udp));
  }

  RHP_TRC(0,RHPTRCID_IKEV2_TX_PLAIN_ERROR_REP_V6_TX_PKT,"xxa",rx_req_ip6h,pkt,(pkt->tail - pkt->l2.raw),RHP_TRC_FMT_A_MAC_IPV6_IKEV2,0,0,pkt->l2.raw);
  rhp_pkt_trace_dump("rhp_ikev2_tx_plain_error_rep_v6",pkt);

  err = rhp_netsock_send(rx_req_ifc,pkt);
  if( err < 0 ){
    RHP_TRC(0,RHPTRCID_IKEV2_TX_PLAIN_ERROR_REP_V6_TX_PKT_ERR,"xxE",rx_req_ip6h,pkt,err);
  }
  err = 0;

  rhp_pkt_unhold(pkt);
  rhp_ikev2_unhold_mesg(tx_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_TX_PLAIN_ERROR_REP_V6_RTRN,"xxx",rx_req_ip6h,pkt,tx_ikemesg);
  return 0;

error:
	if( pkt ){
		rhp_pkt_unhold(pkt);
	}

  if( tx_ikemesg ){
    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_TX_PLAIN_ERROR_REP_V6_ERR,"xxxE",rx_req_ip6h,pkt,tx_ikemesg,err);
  return err;
}



extern int rhp_ikev2_vid_payload_init();
extern void rhp_ikev2_vid_payload_cleanup();
extern int rhp_ikev2_setup_cookie_timer();

int rhp_ikev2_init()
{
  int err;

  err = rhp_ikev2_vid_payload_init();
  if( err ){
    RHP_BUG("%d",err);
    return err;
  }

  {
	  err = rhp_ikev2_register_message_handler(RHP_IKEV2_MESG_HANDLER_IKESA_INIT,
	  					NULL,
	  					rhp_ikev2_rx_ike_sa_init_req_no_vpn,
	  					NULL,
	  					rhp_ikev2_rx_ike_sa_init_rep);

	  if( err ){
	    RHP_BUG("%d",err);
	    return err;
	  }
  }

  {
	  err = rhp_ikev2_register_message_handler(RHP_IKEV2_MESG_HANDLER_SESS_RESUME,
	  					NULL,
	  					rhp_ikev2_rx_sess_resume_req_no_vpn,
	  					NULL,
	  					rhp_ikev2_rx_sess_resume_rep);

	  if( err ){
	    RHP_BUG("%d",err);
	    return err;
	  }
  }

  {
	  err = rhp_ikev2_register_message_handler(RHP_IKEV2_MESG_HANDLER_IKESA_AUTH,
	  					NULL,NULL,
	  					rhp_ikev2_rx_ike_auth_req,
	  					rhp_ikev2_rx_ike_auth_rep);

	  if( err ){
	    RHP_BUG("%d",err);
	    return err;
	  }
  }

  {
	  err = rhp_ikev2_register_message_handler(RHP_IKEV2_MESG_HANDLER_EAP,
	  					NULL,NULL,
	  					rhp_ikev2_rx_ike_eap_req,
	  					rhp_ikev2_rx_ike_eap_rep);

	  if( err ){
	    RHP_BUG("%d",err);
	    return err;
	  }
  }

  {
	  err = rhp_ikev2_register_message_handler(RHP_IKEV2_MESG_HANDLER_CREATE_CHILDSA,
	  					NULL,NULL,
				  		rhp_ikev2_rx_create_child_sa_req,
				  		rhp_ikev2_rx_create_child_sa_rep);

	  if( err ){
	    RHP_BUG("%d",err);
	    return err;
	  }
  }

  {
	  err = rhp_ikev2_register_message_handler(RHP_IKEV2_MESG_HANDLER_REKEY,
	  					NULL,NULL,
				  		rhp_ikev2_rx_rekey_req,
				  		rhp_ikev2_rx_rekey_rep);

	  if( err ){
	    RHP_BUG("%d",err);
	    return err;
	  }
  }

  {
	  err = rhp_ikev2_register_message_handler(RHP_IKEV2_MESG_HANDLER_NAT_T,
	  					rhp_ikev2_tx_nat_t_req,
	  					NULL,
	  					rhp_ikev2_rx_nat_t_req,
	  					rhp_ikev2_rx_nat_t_rep);

	  if( err ){
	    RHP_BUG("%d",err);
	    return err;
	  }
  }

  {
	  err = rhp_ikev2_register_message_handler(RHP_IKEV2_MESG_HANDLER_RHP_INTERNAL_NET,
	  					NULL,NULL,
	  					rhp_ikev2_rx_internal_net_req,
	  					rhp_ikev2_rx_internal_net_rep);

	  if( err ){
	    RHP_BUG("%d",err);
	    return err;
	  }
  }

  {
	  err = rhp_ikev2_register_message_handler(RHP_IKEV2_MESG_HANDLER_CONFIG,
	  					rhp_ikev2_tx_cfg_req,
	  					NULL,
	  					rhp_ikev2_rx_cfg_req,
	  					rhp_ikev2_rx_cfg_rep);

	  if( err ){
	    RHP_BUG("%d",err);
	    return err;
	  }
  }

  {
	  err = rhp_ikev2_register_message_handler(RHP_IKEV2_MESG_HANDLER_MOBIKE,
	  					NULL,
	  					NULL,
	  					rhp_ikev2_rx_mobike_req,
	  					rhp_ikev2_rx_mobike_rep);

	  if( err ){
	    RHP_BUG("%d",err);
	    return err;
	  }
  }

  {
	  err = rhp_ikev2_register_message_handler(RHP_IKEV2_MESG_HANDLER_SESS_RESUME_TKT,
	  					NULL,
	  					NULL,
	  					rhp_ikev2_rx_sess_resume_tkt_req,
	  					rhp_ikev2_rx_sess_resume_tkt_rep);

	  if( err ){
	    RHP_BUG("%d",err);
	    return err;
	  }
  }


  {
	  err = rhp_ikev2_register_message_handler(RHP_IKEV2_MESG_HANDLER_AUTH_TKT_HUB2SPOKE,
	  					NULL,
	  					NULL,
	  					rhp_ikev2_rx_auth_tkt_hb2spk_req,
	  					rhp_ikev2_rx_auth_tkt_hb2spk_rep);

	  if( err ){
	    RHP_BUG("%d",err);
	    return err;
	  }
  }


  {
	  err = rhp_ikev2_register_message_handler(RHP_IKEV2_MESG_HANDLER_QCD,
	  					NULL,
	  					NULL,
	  					rhp_ikev2_rx_qcd_req,
	  					rhp_ikev2_rx_qcd_rep);

	  if( err ){
	    RHP_BUG("%d",err);
	    return err;
	  }
  }

  {
	  err = rhp_ikev2_register_message_handler(RHP_IKEV2_MESG_HANDLER_INFORMATIONAL,
	  					NULL,NULL,
	  					rhp_ikev2_rx_info_req,
	  					rhp_ikev2_rx_info_rep);

	  if( err ){
	    RHP_BUG("%d",err);
	    return err;
	  }
  }

  {
	  err = rhp_ikev2_register_message_handler(RHP_IKEV2_MESG_HANDLER_DELETE_SA,
	  					NULL,NULL,
	  					rhp_ikev2_rx_delete_sa_req,
	  					rhp_ikev2_rx_delete_sa_rep);

	  if( err ){
	    RHP_BUG("%d",err);
	    return err;
	  }
  }


  {
	  err = rhp_ikev2_register_message_handler(RHP_IKEV2_MESG_HANDLER_TX_NEW_REQ,
	  					NULL,NULL,
	  					rhp_ikev2_rx_tx_new_req_req,
	  					rhp_ikev2_rx_tx_new_req_rep);

	  if( err ){
	    RHP_BUG("%d",err);
	    return err;
	  }
  }

  err = rhp_ikev2_cfg_alloc_v6_ra_tss(rhp_gcfg_v6_allow_ra_tss_type);
  if( err ){
  	RHP_BUG("%d",err);
  }

  err = rhp_ikev2_cfg_alloc_v6_auto_tss(rhp_gcfg_v6_allow_auto_tss_type);
  if( err ){
  	RHP_BUG("%d",err);
  }

  err = rhp_ikev2_setup_cookie_timer();
  if( err ){
    RHP_BUG("%d",err);
    return err;
  }

  _rhp_mutex_init("IST",&(rhp_ikev2_lock_statistics));

  memset(&rhp_ikev2_statistics_global_tbl,0,sizeof(rhp_ikev2_global_statistics));


  RHP_TRC(0,RHPTRCID_IKEV2_INIT,"");
  return 0;
}

void rhp_ikev2_cleanup()
{
  rhp_ikev2_vid_payload_cleanup();

  _rhp_mutex_destroy(&(rhp_ikev2_lock_statistics));

  RHP_TRC(0,RHPTRCID_IKEV2_CLEANUP,"");
}


