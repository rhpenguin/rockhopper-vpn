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
#include "rhp_ikev1.h"
#include "rhp_http.h"
#include "rhp_radius_impl.h"
#include "rhp_radius_acct.h"

static rhp_ikev1_message_handler* _rhp_ikev1_mesg_handlers = NULL;


rhp_ikev1_auth_srch_plds_ctx* rhp_ikev1_auth_alloc_srch_ctx()
{
	rhp_ikev1_auth_srch_plds_ctx* s_pld_ctx;

	s_pld_ctx = (rhp_ikev1_auth_srch_plds_ctx*)_rhp_malloc(sizeof(rhp_ikev1_auth_srch_plds_ctx));
	if( s_pld_ctx == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(s_pld_ctx,0,sizeof(rhp_ikev1_auth_srch_plds_ctx));

	s_pld_ctx->tag[0] = '#';
	s_pld_ctx->tag[1] = 'A';
	s_pld_ctx->tag[2] = 'S';
	s_pld_ctx->tag[3] = '1';

	s_pld_ctx->peer_notified_realm_id = RHP_VPN_REALM_ID_UNKNOWN;

  RHP_TRC(0,RHPTRCID_IKE_AUTH_ALLOC_SRC_CTX,"x",s_pld_ctx);
	return s_pld_ctx;
}

void rhp_ikev1_auth_free_srch_ctx(rhp_ikev1_auth_srch_plds_ctx* s_pld_ctx)
{
  RHP_TRC(0,RHPTRCID_IKE_AUTH_FREE_SRC_CTX,"x",s_pld_ctx);

	if( s_pld_ctx ){

		if( s_pld_ctx->vpn_ref ){
			rhp_vpn_unhold(s_pld_ctx->vpn_ref);
		}

		if( s_pld_ctx->rx_ikemesg ){
			rhp_ikev2_unhold_mesg(s_pld_ctx->rx_ikemesg);
		}

		if( s_pld_ctx->tx_ikemesg ){
			rhp_ikev2_unhold_mesg(s_pld_ctx->tx_ikemesg);
		}

	  if( s_pld_ctx->peer_cert_der ){
	    _rhp_free(s_pld_ctx->peer_cert_der);
	  }

	  if( s_pld_ctx->untrust_ca_cert_ders ){
	    _rhp_free(s_pld_ctx->untrust_ca_cert_ders);
	  }

		_rhp_free(s_pld_ctx);
	}

  RHP_TRC(0,RHPTRCID_IKE_AUTH_FREE_SRC_CTX_RTRN,"x",s_pld_ctx);
	return;
}


// NOT thread safe! Call this api only when process starts.
int rhp_ikev1_register_message_handler(int handler_type,
		RHP_IKEV1_MESG_HANDLER_TX send_mesg,
		RHP_IKEV1_MESG_HANDLER_RX_NO_VPN recv_mesg_no_vpn,
		RHP_IKEV1_MESG_HANDLER_RX recv_mesg)
{
	rhp_ikev1_message_handler* handler;
	rhp_ikev1_message_handler *handler_p = NULL,*handler_n;

  RHP_TRC(0,RHPTRCID_IKEV1_REGISTER_MESSAGE_HANDLER_IMPL,"LdYYY","IKEV1_MESG_HDLR",handler_type,send_mesg,recv_mesg_no_vpn,recv_mesg);

	handler = (rhp_ikev1_message_handler*)_rhp_malloc(sizeof(rhp_ikev1_message_handler));
	if( handler == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	memset(handler,0,sizeof(rhp_ikev1_message_handler));

	handler->tag[0] = '#';
	handler->tag[1] = 'I';
	handler->tag[2] = 'M';
	handler->tag[3] = 'H';

	handler->type = handler_type;

	handler->send_mesg = send_mesg;
	handler->recv_mesg_no_vpn = recv_mesg_no_vpn;
	handler->recv_mesg = recv_mesg;

	handler_n = _rhp_ikev1_mesg_handlers;
	while( handler_n ){

		if( handler_n->type > handler->type ){
			break;
		}

		handler_p = handler_n;
		handler_n = handler_p->next;
	}

	if( handler_p == NULL ){
		handler->next = _rhp_ikev1_mesg_handlers;
		_rhp_ikev1_mesg_handlers = handler;
	}else{
		handler->next = handler_p->next;
		handler_p->next = handler;
	}

  RHP_TRC(0,RHPTRCID_IKEV1_REGISTER_MESSAGE_HANDLER_IMPL_RTRN,"Ldx","IKEV1_MESG_HDLR",handler_type,handler);

	return 0;
}


static int _rhp_ikev1_call_tx_mesg_handlers(rhp_ikev2_mesg* tx_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,int caller_type,int req_initiator)
{
	rhp_ikev1_message_handler* handler;
	int err;

	 RHP_TRC(0,RHPTRCID_IKEV1_CALL_TX_MESG_HANDLER,"xxLdGLdLd",tx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKEV1_MESG_HDLR",caller_type,"IKEV1_MESG_HDLR",req_initiator);

	if( caller_type == RHP_IKEV1_MESG_HANDLER_END ){
		RHP_TRC(0,RHPTRCID_IKEV1_CALL_TX_MESG_HANDLER_END,"xxLdLd",tx_ikemesg,vpn,"IKEV1_MESG_HDLR",caller_type,"IKEV1_MESG_HDLR",req_initiator);
		return 0;
	}

	handler = _rhp_ikev1_mesg_handlers;

	if( caller_type != RHP_IKEV1_MESG_HANDLER_START ){

		while( handler ){

			if( handler->type == caller_type ){
				handler = handler->next;
				break;
			}

			handler = handler->next;
		}
	}

	while( handler ){

		if( handler->send_mesg && (handler->type != req_initiator) ){

			RHP_TRC(0,RHPTRCID_IKEV1_CALL_TX_MESG_HANDLER_START_HDLR,"xxxLdY",tx_ikemesg,vpn,handler,"IKEV1_MESG_HDLR",handler->type,handler->send_mesg);

			err = handler->send_mesg(tx_ikemesg,vpn,my_ikesa_side,my_ikesa_spi,req_initiator);

			RHP_TRC(0,RHPTRCID_IKEV1_CALL_TX_MESG_HANDLER_END_HDLR,"xxxE",tx_ikemesg,vpn,handler,err);

		}else{
			err = 0;
		}

		if( err == RHP_STATUS_IKEV2_MESG_HANDLER_PENDING ){
			goto pending;
		}else if( err == RHP_STATUS_IKEV2_MESG_HANDLER_END ){
			err = 0;
			break;
		}else if( err ){

			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,( vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV1_TX_MESG_ERR,"VLE",vpn,"IKEV1_MESG_HDLR",handler->type,err);
			goto error;
		}

		handler = handler->next;
	}

	RHP_TRC(0,RHPTRCID_IKEV1_CALL_TX_MESG_HANDLER_RTRN,"xxLdLd",tx_ikemesg,vpn,"IKEV1_MESG_HDLR",caller_type,"IKEV1_MESG_HDLR",req_initiator);
	return 0;

pending:
error:
	RHP_TRC(0,RHPTRCID_IKEV1_CALL_TX_MESG_HANDLER_ERR,"xxLdLdE",tx_ikemesg,vpn,"IKEV1_MESG_HDLR",caller_type,"IKEV1_MESG_HDLR",req_initiator,err);
	return err;
}

static int _rhp_ikev1_call_rx_mesg_handlers(rhp_ikev2_mesg* rx_ikemesg,rhp_vpn* vpn,
		int my_ike_side,u8* my_ike_spi,rhp_ikev2_mesg* tx_ikemesg,int caller_type,
		rhp_vpn_ref** vpn_ref_r,int* my_ike_side_r,u8* my_ike_spi_r)
{
	rhp_ikev1_message_handler* handler;
	int err;
	int my_ike_side_i = -1;
	u8 my_ike_spi_i[RHP_PROTO_IKE_SPI_SIZE];
	rhp_vpn *vpn_i = NULL;

	 RHP_TRC(0,RHPTRCID_IKEV1_CALL_RX_MESG_HANDLERS,"xxLdGxLdxxx",rx_ikemesg,vpn,"IKE_SIDE",my_ike_side,my_ike_spi,tx_ikemesg,"IKEV1_MESG_HDLR",caller_type,vpn_ref_r,my_ike_side_r,my_ike_spi_r);

	if( caller_type == RHP_IKEV1_MESG_HANDLER_END ){
		RHP_TRC(0,RHPTRCID_IKEV1_CALL_RX_MESG_HANDLERS_END,"xxLd",rx_ikemesg,vpn,"IKEV1_MESG_HDLR",caller_type);
		return 0;
	}

	handler = _rhp_ikev1_mesg_handlers;

	if( caller_type != RHP_IKEV1_MESG_HANDLER_START ){

		while( handler ){

			if( handler->type == caller_type ){
				handler = handler->next;
				break;
			}

			handler = handler->next;
		}
	}

	while( handler ){

		if( vpn == NULL && handler->recv_mesg_no_vpn ){

			RHP_TRC(0,RHPTRCID_IKEV1_CALL_RX_MESG_HANDLERS_NO_VPN_START_HDLR,"xxxLdY",rx_ikemesg,vpn,handler,"IKEV1_MESG_HDLR",handler->type,handler->recv_mesg_no_vpn);

			err = handler->recv_mesg_no_vpn(rx_ikemesg,tx_ikemesg,&vpn_i,&my_ike_side_i,my_ike_spi_i);

			RHP_TRC(0,RHPTRCID_IKEV1_CALL_RX_MESG_HANDLERS_NO_VPN_END_HDLR,"xxxxLdGE",rx_ikemesg,vpn,handler,vpn_i,"IKE_SIDE",my_ike_side_i,my_ike_spi_i,err);

		}else if( vpn && handler->recv_mesg ){

			RHP_TRC(0,RHPTRCID_IKEV1_CALL_RX_MESG_HANDLERS_START_HDLR,"xxxLdY",rx_ikemesg,vpn,handler,"IKEV1_MESG_HDLR",handler->type,handler->recv_mesg);

			err = handler->recv_mesg(rx_ikemesg,vpn,my_ike_side,my_ike_spi,tx_ikemesg);

			RHP_TRC(0,RHPTRCID_IKEV1_CALL_RX_MESG_HANDLERS_END_HDLR,"xxxE",rx_ikemesg,vpn,handler,err);

		}else{

			RHP_TRC(0,RHPTRCID_IKEV1_CALL_RX_MESG_HANDLERS_NO_HDLR_CB,"xxxLd",rx_ikemesg,vpn,handler,"IKEV1_MESG_HDLR",handler->type);
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

					RHP_TRC(0,RHPTRCID_IKEV1_CALL_RX_MESG_HANDLERS_CANCEL_AUTO_RECONNECT,"xx",rx_ikemesg,vpn);

					if( vpn->auto_reconnect ){
						RHP_LOG_W(RHP_LOG_SRC_VPNMNG,vpn->vpn_realm_id,RHP_LOG_ID_AUTO_RECONNECT_CANCELED,"d",vpn->auto_reconnect_retries);
					}

					vpn->exec_auto_reconnect = 0;
				}
			}

			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,( vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV1_RX_MESG_ERR,"VKLE",vpn,rx_ikemesg,"IKEV1_MESG_HDLR",handler->type,err);

			goto error;
		}

		if( vpn == NULL && vpn_i ){

			vpn = vpn_i;

			rhp_vpn_hold(vpn_i);
			RHP_LOCK(&(vpn_i->lock));

			if( my_ike_side == -1 && my_ike_side_i != -1 ){
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

	RHP_TRC(0,RHPTRCID_IKEV1_CALL_RX_MESG_HANDLERS_RTRN,"xxxxLd",rx_ikemesg,vpn,vpn_i,(vpn_ref_r ? *vpn_ref_r : NULL),"IKEV1_MESG_HDLR",caller_type);
	return 0;

pending:
error:
	if( vpn_i ){
  	RHP_UNLOCK(&(vpn_i->lock));
		rhp_vpn_unhold(vpn_i);
	}

	RHP_TRC(0,RHPTRCID_IKEV1_CALL_RX_MESG_HANDLERS_ERR,"xxxLdE",rx_ikemesg,vpn,vpn_i,"IKEV1_MESG_HDLR",caller_type,err);
	return err;
}


rhp_ikesa* rhp_ikev1_tx_get_established_ikesa(rhp_vpn* vpn)
{
	rhp_ikesa* ikesa = vpn->ikesa_list_head;

	while( ikesa ){

	  if(	ikesa->state == RHP_IKESA_STAT_V1_ESTABLISHED ){
	  	RHP_TRC(0,RHPTRCID_IKEV1_TX_GET_ESTABLISHED_IKESA_OK,"xLd",ikesa,"IKESA_STAT",ikesa->state);
	  	break;
	  }

  	RHP_TRC(0,RHPTRCID_IKEV1_TX_GET_ESTABLISHED_IKESA_NG,"xLd",ikesa,"IKESA_STAT",ikesa->state);
		ikesa = ikesa->next_vpn_list;
  }

  return ikesa;
}

static rhp_ifc_entry* _rhp_ikev1_tx_get_ifc(rhp_vpn* vpn,rhp_packet* pkt)
{
	int tx_if_index;
	rhp_ifc_entry* tx_ifc;

	if( pkt->fixed_tx_if_index >= 0 ){

		tx_if_index = pkt->fixed_tx_if_index;

  }else{

  	tx_if_index = vpn->local.if_info.if_index;
	}

	tx_ifc = rhp_ifc_get_by_if_idx(tx_if_index);
	if( tx_ifc == NULL ){
		return NULL;
	}

	return tx_ifc;
}

static int _rhp_ikev1_send_mesg(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* tx_ikemesg,
		int caller_type,int req_initiator,int dont_call_handlers)
{
	int err = -EINVAL;
  int my_ikesa_side = -1;
  u8* my_ikesa_spi = NULL;
  u8 exchg_type = tx_ikemesg->get_exchange_type(tx_ikemesg);
	rhp_packet* tx_pkt = NULL;

	RHP_TRC(0,RHPTRCID_IKEV1_SEND_MESG,"xxxLdLdd",vpn,ikesa,tx_ikemesg,"IKEV1_MESG_HDLR",caller_type,"IKEV1_MESG_HDLR",req_initiator,dont_call_handlers);

	if( !rhp_gcfg_ikev1_enabled ){
		err = 0;
		goto error;
	}

  if( !tx_ikemesg->activated ){
  	RHP_BUG("");
  }

  if( ikesa ){
    my_ikesa_side = ikesa->side;
    my_ikesa_spi = ikesa->get_my_spi(ikesa);
  }


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


	if( !tx_ikemesg->tx_ikesa_fixed ){

		// [TODO] After Phase1 is completed, any non-encrypted exchange occurs?
		if( exchg_type != RHP_PROTO_IKEV1_EXCHG_BASE &&
				exchg_type != RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION &&
				exchg_type != RHP_PROTO_IKEV1_EXCHG_AUTH_ONLY &&
				exchg_type != RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){

			ikesa = rhp_ikev1_tx_get_established_ikesa(vpn);
		}

		if( ikesa ){

			RHP_TRC(0,RHPTRCID_IKEV1_SEND_MESG_CUR_IKESA,"xxxxLdGGLd",vpn,ikesa,tx_ikemesg,ikesa,"IKE_SIDE",ikesa->side,ikesa->init_spi,ikesa->resp_spi,"IKESA_STAT",ikesa->state);

			if( my_ikesa_side == -1 ){
				my_ikesa_side = ikesa->side;
				my_ikesa_spi = ikesa->get_my_spi(ikesa);
			}
		}
	}

	if( ikesa == NULL ){

  	rhp_ikev2_g_statistics_inc(tx_ikev1_no_ikesa_err_packets);

		RHP_TRC(0,RHPTRCID_IKEV1_SEND_MESG_MESG_HANDLER_NO_TX_IKESA,"xx",vpn,tx_ikemesg);
		err = -ENOENT;
		goto error;
	}


	tx_ikemesg->set_init_spi(tx_ikemesg,ikesa->init_spi);
	tx_ikemesg->set_resp_spi(tx_ikemesg,ikesa->resp_spi);


	if( !dont_call_handlers ){

		if( my_ikesa_side == -1 || my_ikesa_spi ){

			err = _rhp_ikev1_call_tx_mesg_handlers(tx_ikemesg,vpn,my_ikesa_side,my_ikesa_spi,caller_type,req_initiator);
			if( err == RHP_STATUS_IKEV2_MESG_HANDLER_PENDING ){

				RHP_TRC(0,RHPTRCID_IKEV1_SEND_MESG_MESG_HANDLER_PENDING,"xxx",vpn,ikesa,tx_ikemesg);
				goto pending;

			}else if( err ){

				rhp_ikev2_g_statistics_inc(tx_ikev1_process_err_packets);

				RHP_TRC(0,RHPTRCID_IKEV1_SEND_MESG_MESG_HANDLER_ERR,"xxxE",vpn,ikesa,tx_ikemesg,err);
				goto error;
			}

		}else{
			RHP_TRC(0,RHPTRCID_IKEV1_SEND_MESG_MESG_HANDLER_DONT,"xxx",vpn,ikesa,tx_ikemesg);
		}
	}

	RHP_TRC_FREQ(0,RHPTRCID_IKEV1_SEND_MESG_TX_EXEC,"xxdxY",vpn,tx_ikemesg,tx_ikemesg->tx_ikesa_fixed,ikesa,tx_ikemesg->packet_serialized);
	RHP_TRC_FREQ(0,RHPTRCID_IKEV1_SEND_MESG_TX_IKESA,"xxxLdG",vpn,tx_ikemesg,ikesa,"IKE_SIDE",ikesa->side,ikesa->get_my_spi(ikesa));

	{
		err = tx_ikemesg->serialize_v1(tx_ikemesg,vpn,ikesa,&tx_pkt);
		if( err ){

			RHP_TRC(0,RHPTRCID_IKEV1_SEND_MESG_NETSOCK_SEND_SERIALIZE_PKT_ERR,"xxxuE",vpn,ikesa,tx_ikemesg,err);

			rhp_ikev2_g_statistics_inc(tx_ikev1_alloc_packet_err);

			goto error;
		}


		if( tx_ikemesg->v1_sa_b ){

			if( ikesa->side == RHP_IKE_INITIATOR ){

				int sa_b_len = ntohs(tx_ikemesg->v1_sa_b->len) - 4;

				if( ikesa->v1.sai_b ){
					_rhp_free(ikesa->v1.sai_b);
					ikesa->v1.sai_b_len = 0;
				}

				ikesa->v1.sai_b = (u8*)_rhp_malloc(sa_b_len);
				if( ikesa->v1.sai_b == NULL ){
					RHP_BUG("");
					err = -ENOMEM;
					goto error;
				}

				memcpy(ikesa->v1.sai_b,((u8*)tx_ikemesg->v1_sa_b) + 4,sa_b_len);
				ikesa->v1.sai_b_len = sa_b_len;
			}
		}

		tx_ikemesg->tx_pkt = tx_pkt;
		rhp_pkt_hold(tx_pkt);
	}

  if( tx_ikemesg->packet_serialized ){

  	tx_ikemesg->packet_serialized(vpn,ikesa,tx_ikemesg,tx_pkt);
  }

  if( tx_ikemesg->v1_start_retx_timer ){

		if( tx_ikemesg->tx_pkt == NULL || ikesa == NULL ){

			RHP_BUG("0x%lx, 0x%lx",tx_ikemesg->tx_pkt,ikesa);

		}else{

			if( ikesa->req_retx_ikemesg ){
				RHP_TRC(0,RHPTRCID_IKEV1_SEND_MESG_CLEAR_PENDING_IKEMESG,"xxxxx",vpn,ikesa,ikesa->req_retx_ikemesg,tx_ikemesg,tx_ikemesg->tx_pkt);
				RHP_BUG("");
				rhp_ikev2_unhold_mesg(ikesa->req_retx_ikemesg);
				ikesa->req_retx_ikemesg = NULL;
			}

			ikesa->set_retrans_request(ikesa,tx_ikemesg->tx_pkt);

			ikesa->req_retx_ikemesg = tx_ikemesg;
			rhp_ikev2_hold_mesg(tx_ikemesg);

			ikesa->timers->start_retransmit_timer(vpn,ikesa,0);
		}
  }

  {
  	rhp_ifc_entry* tx_ifc = NULL;

		tx_ifc = _rhp_ikev1_tx_get_ifc(vpn,tx_pkt); // (***)
		if( tx_ifc == NULL ){

			RHP_TRC(0,RHPTRCID_IKEV1_SEND_MESG_NETSOCK_SEND_NO_TX_IFC,"xxxu",vpn,ikesa,tx_ikemesg,vpn->local.if_info.if_index);

			rhp_ikev2_g_statistics_inc(tx_ikev1_no_if_err_packets);
			err = -ENOENT;

			goto error;

		}else{

			int tx_pkts;

			for( tx_pkts = 0; tx_pkts <= tx_ikemesg->v1_tx_redundant_pkts; tx_pkts++ ){

				rhp_packet* tx_pkt_d = rhp_pkt_dup(tx_pkt);
				if( tx_pkt_d ){

					if( rhp_ikev2_check_tx_addr(vpn,ikesa,tx_ifc) ){

						tx_pkt_d->tx_ifc = tx_ifc;
						rhp_ifc_hold(tx_pkt_d->tx_ifc);

						err = rhp_netsock_send(tx_pkt_d->tx_ifc,tx_pkt_d);
						if( err < 0 ){
							RHP_TRC(0,RHPTRCID_IKEV1_SEND_MESG_NETSOCK_SEND_ERR,"xxxE",vpn,ikesa,tx_ikemesg,err);
						}

					}else{

						rhp_ikev2_g_statistics_inc(tx_ikev1_no_if_err_packets);
					}

					rhp_pkt_unhold(tx_pkt_d);

				}else{

					RHP_TRC(0,RHPTRCID_IKEV1_SEND_MESG_NETSOCK_SEND_NO_MEM_ERROR,"xxx",vpn,ikesa,tx_ikemesg);
					rhp_ikev2_g_statistics_inc(tx_ikev1_alloc_packet_err);
				}
			}
			err = 0;

			rhp_pkt_unhold(tx_pkt);

			rhp_ifc_unhold(tx_ifc); // (***)
		}
  }

pending:
	RHP_TRC(0,RHPTRCID_IKEV1_SEND_MESG_RTRN,"xxxxxd",vpn,ikesa,ikesa,tx_ikemesg,tx_ikemesg->tx_pkt,tx_ikemesg->v1_set_retrans_resp);
	return 0;

error:
	if( err ){
		rhp_ikev2_g_statistics_inc(tx_ikev1_err_packets);
	}

	RHP_TRC(0,RHPTRCID_IKEV1_SEND_MESG_ERR,"xxE",vpn,ikesa,err);
	return err;
}

int rhp_ikev1_send_mesg(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* tx_ikemesg,int req_initiator)
{
  RHP_TRC(0,RHPTRCID_IKEV1_SEND_MESG_G,"xxxLd",vpn,ikesa,tx_ikemesg,"IKEV1_MESG_HDLR",req_initiator);
	return _rhp_ikev1_send_mesg(vpn,ikesa,tx_ikemesg,RHP_IKEV1_MESG_HANDLER_START,req_initiator,0);
}

//
// [CAUTION]
//  This call may acquire (rhp_ifc_entry*)ifc->lock.
//
int rhp_ikev1_retransmit_mesg(rhp_vpn* vpn,rhp_ikesa* ikesa)
{
  int err = 0;
  rhp_packet *pkt = NULL,*pkt_d = NULL;
  rhp_ifc_entry* tx_ifc = NULL;
  int tx_if_index;
	int retx_cnt = ikesa->timers->retx_counter;
	int addr_family;
	u8* addr;
	rhp_proto_ike* ikeh = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_RETRANSMIT_MESG,"xx",vpn,ikesa);

  if( ikesa->req_retx_pkt == NULL ||
  		ikesa->req_retx_ikemesg == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV1_RETRANSMIT_MESG_NO_PKT,"xxx",ikesa,ikesa->req_retx_ikemesg,ikesa->req_retx_pkt);
    err = RHP_STATUS_IKEV2_RETRANS_PKT_CLEARED;
    goto skip;
  }

  pkt = ikesa->req_retx_pkt;

	RHP_TRC(0,RHPTRCID_IKEV1_RETRANSMIT_MESG_Q_PKT,"xxx",ikesa,ikesa->req_retx_ikemesg,pkt);


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

	if( pkt->fixed_tx_if_index >= 0 ){
		tx_if_index = pkt->fixed_tx_if_index;
	}else{
		tx_if_index = vpn->local.if_info.if_index;
	}

	tx_ifc = rhp_ifc_get_by_if_idx(tx_if_index); // (***)
	if( tx_ifc == NULL ){
		if( pkt->type == RHP_PKT_IPV4_IKE ){
			RHP_TRC(0,RHPTRCID_IKEV1_RETRANSMIT_MESG_NO_TX_IF_FOUND,"xdx44WW",ikesa,tx_if_index,pkt,pkt->l3.iph_v4->src_addr,pkt->l3.iph_v4->dst_addr,pkt->l4.udph->src_port,pkt->l4.udph->dst_port);
		}else if( pkt->type == RHP_PKT_IPV6_IKE ){
			RHP_TRC(0,RHPTRCID_IKEV1_RETRANSMIT_MESG_NO_TX_IF_FOUND_V6,"xdx66WW",ikesa,tx_if_index,pkt,pkt->l3.iph_v6->src_addr,pkt->l3.iph_v6->dst_addr,pkt->l4.udph->src_port,pkt->l4.udph->dst_port);
		}
		err = -ENODEV;
		goto skip;
	}

	if( pkt->fixed_tx_if_index >= 0 ){

		RHP_LOCK(&(tx_ifc->lock));

		if( tx_ifc->get_addr(tx_ifc,addr_family,addr) ){

			if( pkt->type == RHP_PKT_IPV4_IKE ){
				RHP_TRC(0,RHPTRCID_IKEV1_RETRANSMIT_MESG_TX_SRC_ADDR_NOT_MATCHED,"xddx44WW",ikesa,pkt->fixed_tx_if_index,tx_if_index,pkt,pkt->l3.iph_v4->src_addr,pkt->l3.iph_v4->dst_addr,pkt->l4.udph->src_port,pkt->l4.udph->dst_port);
			}else if( pkt->type == RHP_PKT_IPV6_IKE ){
				RHP_TRC(0,RHPTRCID_IKEV1_RETRANSMIT_MESG_TX_SRC_ADDR_NOT_MATCHED_V6,"xddx66WW",ikesa,pkt->fixed_tx_if_index,tx_if_index,pkt,pkt->l3.iph_v6->src_addr,pkt->l3.iph_v6->dst_addr,pkt->l4.udph->src_port,pkt->l4.udph->dst_port);
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
			RHP_TRC(0,RHPTRCID_IKEV1_RETRANSMIT_MESG_NO_IP_PORT,"xx44W",ikesa,pkt,pkt->l3.iph_v4->src_addr,pkt->l3.iph_v4->dst_addr,pkt->l4.udph->dst_port);
		}else if( pkt->type == RHP_PKT_IPV6_IKE ){
			RHP_TRC(0,RHPTRCID_IKEV1_RETRANSMIT_MESG_NO_IP_PORT_V6,"xx66W",ikesa,pkt,pkt->l3.iph_v6->src_addr,pkt->l3.iph_v6->dst_addr,pkt->l4.udph->dst_port);
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
			RHP_TRC(0,RHPTRCID_IKEV1_RETRANSMIT_TX_DUP_V4_PKT,"xxxxa",vpn,ikesa,pkt,pkt_d,(pkt_d->tail - pkt_d->data),RHP_TRC_FMT_A_MAC_IPV4_IKEV2,iv_len,icv_len,pkt_d->data);
		}else if( pkt->type == RHP_PKT_IPV6_IKE ){
			RHP_TRC(0,RHPTRCID_IKEV1_RETRANSMIT_TX_DUP_V6_PKT,"xxxxa",vpn,ikesa,pkt,pkt_d,(pkt_d->tail - pkt_d->data),RHP_TRC_FMT_A_MAC_IPV6_IKEV2,iv_len,icv_len,pkt_d->data);
		}
	}


	err = rhp_netsock_send(pkt_d->tx_ifc,pkt_d);
	if( err < 0 ){

		RHP_TRC(0,RHPTRCID_IKEV1_RETRANSMIT_MESG_TX_PKT_ERR,"xxxxxE",vpn,ikesa,pkt,pkt_d,pkt_d->tx_ifc,err);

		if( pkt->type == RHP_PKT_IPV4_IKE ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV1_RETRANSMIT_MESG_ERR,"VPd44WWGGLJE",vpn,ikesa,retx_cnt,(pkt_d->l3.raw ? pkt_d->l3.iph_v4->src_addr : 0),(pkt_d && pkt_d->l3.raw ? pkt_d->l3.iph_v4->dst_addr : 0),(pkt_d && pkt_d->l4.raw ? pkt_d->l4.udph->src_port : 0),(pkt_d && pkt_d->l4.raw ? pkt_d->l4.udph->dst_port : 0),(ikeh ? ikeh->init_spi : NULL),(ikeh ? ikeh->resp_spi : NULL),"PROTO_IKE_EXCHG",(ikeh ? (int)ikeh->exchange_type : 0),(ikeh ? ikeh->message_id : 0),err);
		}else if( pkt->type == RHP_PKT_IPV6_IKE ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV1_RETRANSMIT_MESG_V6_ERR,"VPd66WWGGLJE",vpn,ikesa,retx_cnt,(pkt_d->l3.raw ? pkt_d->l3.iph_v6->src_addr : NULL),(pkt_d && pkt_d->l3.raw ? pkt_d->l3.iph_v6->dst_addr : NULL),(pkt_d && pkt_d->l4.raw ? pkt_d->l4.udph->src_port : 0),(pkt_d && pkt_d->l4.raw ? pkt_d->l4.udph->dst_port : 0),(ikeh ? ikeh->init_spi : NULL),(ikeh ? ikeh->resp_spi : NULL),"PROTO_IKE_EXCHG",(ikeh ? (int)ikeh->exchange_type : 0),(ikeh ? ikeh->message_id : 0),err);
		}
	}
	err = 0;


	if( pkt->type == RHP_PKT_IPV4_IKE ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV1_EXEC_RETRANSMIT,"VPd44WWGGLJ",vpn,ikesa,retx_cnt,(pkt_d->l3.raw ? pkt_d->l3.iph_v4->src_addr : 0),(pkt_d && pkt_d->l3.raw ? pkt_d->l3.iph_v4->dst_addr : 0),(pkt_d && pkt_d->l4.raw ? pkt_d->l4.udph->src_port : 0),(pkt_d && pkt_d->l4.raw ? pkt_d->l4.udph->dst_port : 0),(ikeh ? ikeh->init_spi : NULL),(ikeh ? ikeh->resp_spi : NULL),"PROTO_IKE_EXCHG",(ikeh ? (int)ikeh->exchange_type : 0),(ikeh ? ikeh->message_id : 0));
	}else if( pkt->type == RHP_PKT_IPV6_IKE ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV1_EXEC_RETRANSMIT_V6,"VPd66WWGGLJ",vpn,ikesa,retx_cnt,(pkt_d->l3.raw ? pkt_d->l3.iph_v6->src_addr : NULL),(pkt_d && pkt_d->l3.raw ? pkt_d->l3.iph_v6->dst_addr : NULL),(pkt_d && pkt_d->l4.raw ? pkt_d->l4.udph->src_port : 0),(pkt_d && pkt_d->l4.raw ? pkt_d->l4.udph->dst_port : 0),(ikeh ? ikeh->init_spi : NULL),(ikeh ? ikeh->resp_spi : NULL),"PROTO_IKE_EXCHG",(ikeh ? (int)ikeh->exchange_type : 0),(ikeh ? ikeh->message_id : 0));
	}

	rhp_pkt_unhold(pkt_d);
	pkt_d = NULL;

	rhp_ifc_unhold(tx_ifc);

  RHP_TRC(0,RHPTRCID_IKEV1_RETRANSMIT_MESG_RTRN,"xd",ikesa,err);
  return 0;


skip:
	if( pkt ){
		if( pkt->type == RHP_PKT_IPV4_IKE ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV1_RETRANSMIT_MESG_ERR,"VPd44WWGGLJE",vpn,ikesa,retx_cnt,(pkt_d && pkt_d->l3.raw ? pkt_d->l3.iph_v4->src_addr : 0),(pkt_d && pkt_d->l3.raw ? pkt_d->l3.iph_v4->dst_addr : 0),(pkt_d && pkt_d->l4.raw ? pkt_d->l4.udph->src_port : 0),(pkt_d && pkt_d->l4.raw ? pkt_d->l4.udph->dst_port : 0),(ikeh ? ikeh->init_spi : NULL),(ikeh ? ikeh->resp_spi : NULL),"PROTO_IKE_EXCHG",(ikeh ? (int)ikeh->exchange_type : 0),(ikeh ? ikeh->message_id : 0),err);
		}else if( pkt->type == RHP_PKT_IPV6_IKE ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV1_RETRANSMIT_MESG_V6_ERR,"VPd66WWGGLJE",vpn,ikesa,retx_cnt,(pkt_d && pkt_d->l3.raw ? pkt_d->l3.iph_v6->src_addr : NULL),(pkt_d && pkt_d->l3.raw ? pkt_d->l3.iph_v6->dst_addr : NULL),(pkt_d && pkt_d->l4.raw ? pkt_d->l4.udph->src_port : 0),(pkt_d && pkt_d->l4.raw ? pkt_d->l4.udph->dst_port : 0),(ikeh ? ikeh->init_spi : NULL),(ikeh ? ikeh->resp_spi : NULL),"PROTO_IKE_EXCHG",(ikeh ? (int)ikeh->exchange_type : 0),(ikeh ? ikeh->message_id : 0),err);
		}
	}else{
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV1_RETRANSMIT_MESG_NO_PACKET,"VPdE",vpn,ikesa,retx_cnt,err);
	}
  if( pkt_d ){
    rhp_pkt_unhold(pkt_d);
  }
  if( tx_ifc ){
  	rhp_ifc_unhold(tx_ifc);
  }
  RHP_TRC(0,RHPTRCID_RHPTRCID_IKEV1_RETRANSMIT_MESG_SKIP,"xxxE",vpn,ikesa,pkt_d,err);
  return err;
}


void rhp_ikev1_call_next_tx_mesg_handlers(rhp_ikev2_mesg* tx_ikemesg,
		rhp_vpn* vpn,int my_ikesa_side,u8* my_ikesa_spi,int caller_type,int req_initiator)
{
	rhp_ikesa* ikesa = NULL;

	RHP_TRC(0,RHPTRCID_IKEV1_CALL_NEXT_TX_MESG_HANDLERS,"xxLdGLdLd",tx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKEV1_MESG_HDLR",caller_type,"IKEV1_MESG_HDLR",req_initiator);

	if( my_ikesa_spi ){

		ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
		if( ikesa == NULL ){
			RHP_BUG("");
			goto error;
		}
	}

	_rhp_ikev1_send_mesg(vpn,ikesa,tx_ikemesg,caller_type,req_initiator,0);

error:
	RHP_TRC(0,RHPTRCID_IKEV1_CALL_NEXT_TX_MESG_HANDLERS_RTRN,"xxLdLd",tx_ikemesg,vpn,"IKEV1_MESG_HDLR",caller_type,"IKEV1_MESG_HDLR",req_initiator);
	return;
}

void rhp_ikev1_call_next_rx_mesg_handlers(rhp_ikev2_mesg* rx_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_ikemesg,int caller_type)
{
	int err = -EINVAL;
	int do_destroy_vpn = 0;
	rhp_ikesa* ikesa = NULL;

	RHP_TRC(0,RHPTRCID_IKEV1_CALL_NEXT_RX_MESG_HANDLERS,"xxLdGxLdxxd",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_ikemesg,"IKEV1_MESG_HDLR",caller_type,rx_ikemesg->rx_pkt,tx_ikemesg->tx_pkt,tx_ikemesg->v1_set_retrans_resp);

	if( my_ikesa_spi == NULL ){
		RHP_BUG("");
		goto error;
	}

	err = _rhp_ikev1_call_rx_mesg_handlers(rx_ikemesg,vpn,my_ikesa_side,my_ikesa_spi,
					tx_ikemesg,caller_type,NULL,NULL,NULL);

	if( err == RHP_STATUS_IKEV2_MESG_HANDLER_PENDING ){

		if( rx_ikemesg->rx_pkt ){
			rhp_pkt_pending(rx_ikemesg->rx_pkt);
		}

		goto pending;

	}else if( err == RHP_STATUS_IKEV2_DESTROY_SA_AFTER_TX ){

		do_destroy_vpn = 1;

	}else if( err ){

		goto error;
	}


	ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
	if( ikesa == NULL ){
		RHP_BUG("");
		err = -ENOENT;
		goto error;
	}

	if( rx_ikemesg->decrypted ){
    ikesa->statistics.rx_encrypted_packets++;
  	RHP_TRC(0,RHPTRCID_IKEV1_CALL_NEXT_RX_MESG_HANDLERS_RX_ENC_PKTS,"xxxqqq",rx_ikemesg,vpn,ikesa,ikesa->statistics.rx_encrypted_packets,ikesa->statistics.rx_keep_alive_reply_packets,ikesa->timers->last_rx_encrypted_packets);
  }

	if( !err || do_destroy_vpn ){

		if( rx_ikemesg->v1_src_changed ){

			int addr_chg_family = AF_UNSPEC;
			u8 addr_chg_src_addr[16];
			u16 addr_chg_src_port, addr_chg_dst_port;
			rhp_packet* pkt = rx_ikemesg->rx_pkt;

			if( pkt->type == RHP_PKT_IPV4_IKE ){

				addr_chg_family = AF_INET;
				*((u32*)addr_chg_src_addr) = pkt->l3.iph_v4->src_addr;
				addr_chg_src_port = pkt->l4.udph->src_port;
				addr_chg_dst_port = pkt->l4.udph->dst_port;

				RHP_TRC(0,RHPTRCID_IKEV1_CALL_NEXT_RX_MESG_HANDLERS_RX_FROM_UNKNOWN_PEER,"xx44WW",pkt,vpn,vpn->peer_addr.addr.v4,pkt->l3.iph_v4->src_addr,vpn->peer_addr.port,pkt->l4.udph->src_port);

			}else if( pkt->type == RHP_PKT_IPV6_IKE ){

				addr_chg_family = AF_INET6;
				memcpy(addr_chg_src_addr,pkt->l3.iph_v6->src_addr,16);
				addr_chg_src_port = pkt->l4.udph->src_port;
				addr_chg_dst_port = pkt->l4.udph->dst_port;

				RHP_TRC(0,RHPTRCID_IKEV1_CALL_NEXT_RX_MESG_HANDLERS_RX_FROM_UNKNOWN_PEER_V6,"xx66WW",pkt,vpn,vpn->peer_addr.addr.v6,pkt->l3.iph_v6->src_addr,vpn->peer_addr.port,pkt->l4.udph->src_port);
			}

			if( addr_chg_family != AF_UNSPEC ){

				err = rhp_ikev2_nat_t_change_peer_addr_port(vpn,addr_chg_family,
								addr_chg_src_addr,addr_chg_src_port,addr_chg_dst_port,0);
				if( err ){
					RHP_TRC(0,RHPTRCID_IKEV1_CALL_NEXT_RX_MESG_HANDLERS_RX_FROM_UNKNOWN_PEER_NAT_T_ERR,"xx",pkt,vpn);
				}
				err = 0;
			}
		}
	}


	if( tx_ikemesg->activated ){

		_rhp_ikev1_send_mesg(vpn,ikesa,tx_ikemesg,RHP_IKEV1_MESG_HANDLER_END,RHP_IKEV1_MESG_HANDLER_END,1);

		if( tx_ikemesg->tx_pkt &&
				tx_ikemesg->v1_set_retrans_resp &&
				rx_ikemesg->rx_pkt &&
				rx_ikemesg->rx_pkt->ikev1_pkt_hash ){

				tx_ikemesg->tx_pkt->ikev1_pkt_hash = rx_ikemesg->rx_pkt->ikev1_pkt_hash;
				tx_ikemesg->tx_pkt->ikev1_pkt_hash_len = rx_ikemesg->rx_pkt->ikev1_pkt_hash_len;

				rx_ikemesg->rx_pkt->ikev1_pkt_hash = NULL;
				rx_ikemesg->rx_pkt->ikev1_pkt_hash_len = 0;

				ikesa->set_retrans_reply(ikesa,tx_ikemesg->tx_pkt);
		}

		if( do_destroy_vpn ){

			rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_DELETE_WAIT);
			ikesa->timers->schedule_delete(vpn,ikesa,0);

		}else{

			if( rx_ikemesg->v1_sa_b ){

				if( ikesa->side == RHP_IKE_RESPONDER ){

					int sa_b_len = ntohs(rx_ikemesg->v1_sa_b->len) - 4;

					if( ikesa->v1.sai_b ){
						_rhp_free(ikesa->v1.sai_b);
						ikesa->v1.sai_b_len = 0;
					}

					ikesa->v1.sai_b = (u8*)_rhp_malloc(sa_b_len);
					if( ikesa->v1.sai_b == NULL ){
						RHP_BUG("");
						err = -ENOMEM;
						goto error;
					}

					memcpy(ikesa->v1.sai_b,((u8*)rx_ikemesg->v1_sa_b) + 4,sa_b_len);
					ikesa->v1.sai_b_len = sa_b_len;
				}
			}
		}
	}

	err = 0;

pending:
error:
	RHP_TRC(0,RHPTRCID_IKEV1_CALL_NEXT_RX_MESG_HANDLERS_RTRN,"xxxLdE",rx_ikemesg,vpn,ikesa,"IKEV1_MESG_HDLR",caller_type,err);
	return;
}


int rhp_ikev1_detach_old_ikesa(rhp_vpn* vpn,rhp_ikesa* new_ikesa)
{
	rhp_ikesa* old_ikesa;
	rhp_ikesa* old_ikesa2 = NULL;

	RHP_TRC(0,RHPTRCID_IKEV1_DETACH_OLD_IKESA,"xx",vpn,new_ikesa);

	old_ikesa = vpn->ikesa_list_head;
	while( old_ikesa ){

		RHP_TRC(0,RHPTRCID_IKEV1_DETACH_OLD_IKESA_1,"xxxxLdtt",vpn,new_ikesa,old_ikesa,old_ikesa2,"IKESA_STAT",old_ikesa->state,(old_ikesa2 ? old_ikesa2->expire_hard : 0),old_ikesa->expire_hard);

		if( old_ikesa != new_ikesa ){

			if( (old_ikesa->state == RHP_IKESA_STAT_V1_ESTABLISHED ||
					 old_ikesa->state == RHP_IKESA_STAT_V1_REKEYING) &&
					(old_ikesa2 == NULL || old_ikesa2->expire_hard < old_ikesa->expire_hard) ){

				old_ikesa2 = old_ikesa;
			}

			old_ikesa->v1.dont_rekey = 1;
		}

		old_ikesa = old_ikesa->next_vpn_list;
	}


	old_ikesa = vpn->ikesa_list_head;
	while( old_ikesa ){

		if( old_ikesa != new_ikesa &&
				old_ikesa != old_ikesa2 ){

			RHP_TRC(0,RHPTRCID_IKEV1_DETACH_OLD_IKESA_2,"xxxx",vpn,new_ikesa,old_ikesa,old_ikesa2);

			rhp_ikesa_set_state(old_ikesa,RHP_IKESA_STAT_V1_DELETE_WAIT);
			old_ikesa->timers->schedule_delete(vpn,old_ikesa,1);
		}

		old_ikesa = old_ikesa->next_vpn_list;
	}

	RHP_TRC(0,RHPTRCID_IKEV1_DETACH_OLD_IKESA_RTRN,"xxx",vpn,new_ikesa,old_ikesa2);
	return 0;
}

static int _rhp_ikev1_attach_larval_vpn_ikesa(rhp_vpn* vpn,rhp_ikesa* ikesa)
{
	time_t rem_lifetime = ikesa->expire_hard - _rhp_get_time();

	RHP_TRC(0,RHPTRCID_IKEV1_ATTACH_LARVAL_VPN_IKESA,"xxttdtt",vpn,ikesa,ikesa->expire_hard,rem_lifetime,vpn->v1.dpd_enabled,ikesa->v1.keep_alive_interval,ikesa->v1.nat_t_keep_alive_interval);

	if( rem_lifetime < 1 ){
		rem_lifetime = 1;
	}

	ikesa->v1.dont_rekey = 1;

	vpn->ikesa_put(vpn,ikesa);

	rhp_vpn_ikesa_spi_put(vpn,ikesa->side,ikesa->get_my_spi(ikesa));


	ikesa->timers->start_lifetime_timer(vpn,ikesa,rem_lifetime,0);

	if( vpn->v1.dpd_enabled && ikesa->v1.keep_alive_interval ){

		ikesa->timers->start_keep_alive_timer(vpn,ikesa,ikesa->v1.keep_alive_interval);
	}

	if( ikesa->v1.nat_t_keep_alive_interval ){

		ikesa->timers->start_nat_t_keep_alive_timer(vpn,ikesa,ikesa->v1.nat_t_keep_alive_interval);
	}

	RHP_TRC(0,RHPTRCID_IKEV1_ATTACH_LARVAL_VPN_IKESA_RTRN,"xx",vpn,ikesa);
	return 0;
}

static int _rhp_ikev1_detach_larval_vpn_ikesa(rhp_vpn* larval_vpn,rhp_ikesa** ikesa_r)
{
	rhp_ikesa* ikesa = larval_vpn->ikesa_list_head;

	RHP_TRC(0,RHPTRCID_IKEV1_DETACH_LARVAL_VPN_IKESA,"xx",larval_vpn,ikesa_r);

	while( ikesa ){

		RHP_TRC(0,RHPTRCID_IKEV1_DETACH_LARVAL_VPN_IKESA_1,"xxLd",larval_vpn,ikesa,"IKESA_STAT",ikesa->state);

		if( ikesa->state == RHP_IKESA_STAT_V1_ESTABLISHED ||
				ikesa->state == RHP_IKESA_STAT_V1_REKEYING ){

		  u8* my_spi;

	  	ikesa->timers->quit_lifetime_timer(larval_vpn,ikesa);

	  	ikesa->timers->quit_retransmit_timer(larval_vpn,ikesa);

	  	ikesa->timers->quit_keep_alive_timer(larval_vpn,ikesa);

	  	ikesa->timers->quit_nat_t_keep_alive_timer(larval_vpn,ikesa);


		  my_spi = ikesa->get_my_spi(ikesa);

		  larval_vpn->ikesa_delete(larval_vpn,ikesa->side,my_spi);

			rhp_vpn_ikesa_spi_delete(larval_vpn,ikesa->side,my_spi);

			*ikesa_r = ikesa;

			break;
		}

		ikesa = ikesa->next_vpn_list;
	}

	RHP_TRC(0,RHPTRCID_IKEV1_DETACH_LARVAL_VPN_IKESA_RTRN,"xx",larval_vpn,*ikesa_r);
	return 0;
}

// For IKE SA's responder.
int rhp_ikev1_merge_larval_vpn(rhp_vpn* larval_vpn)
{
	int err = -EINVAL;
	rhp_vpn_ref* cur_vpn_ref = NULL;
	rhp_vpn* cur_vpn = NULL;
	rhp_ikesa* larval_ikesa = NULL;
	unsigned long created_ikesas = 0;

	RHP_TRC(0,RHPTRCID_IKEV1_MERGE_LARVAL_VPN,"x",larval_vpn);

	cur_vpn_ref = rhp_vpn_get_by_unique_id(larval_vpn->v1.cur_vpn_unique_id);
	cur_vpn = RHP_VPN_REF(cur_vpn_ref);

	if( cur_vpn == NULL ){
		RHP_TRC(0,RHPTRCID_IKEV1_MERGE_LARVAL_VPN_NOENT,"x",larval_vpn);
		err = -ENOENT;
		goto error;
	}


	RHP_LOCK(&(larval_vpn->lock));
	{
		if( !_rhp_atomic_read(&(larval_vpn->is_active))){
			err = -EINVAL;
			RHP_UNLOCK(&(larval_vpn->lock));
			goto error;
		}

		_rhp_ikev1_detach_larval_vpn_ikesa(larval_vpn,&larval_ikesa);

		created_ikesas = larval_vpn->created_ikesas;

		if( larval_vpn->childsa_num ){
			//
			// TODO: This func is called just after a new IKE SA is rekeyed.
			//       IPsec SAs are also moved to the current vpn object?
			RHP_BUG("%d",larval_vpn->created_childsas);
		}

		RHP_TRC(0,RHPTRCID_IKEV1_MERGE_LARVAL_VPN_INFO,"xxxudd",cur_vpn,larval_vpn,larval_ikesa,created_ikesas,larval_vpn->ikesa_num,larval_vpn->childsa_num);

		rhp_vpn_destroy(larval_vpn);
	}
	RHP_UNLOCK(&(larval_vpn->lock));


	RHP_LOCK(&(cur_vpn->lock));
	{

		if( larval_ikesa ){

			_rhp_ikev1_attach_larval_vpn_ikesa(cur_vpn,larval_ikesa);

			cur_vpn->ikesa_move_to_top(cur_vpn,larval_ikesa);

			rhp_ikev1_detach_old_ikesa(cur_vpn,larval_ikesa);
		}

		cur_vpn->created_ikesas += created_ikesas;
	}
	RHP_UNLOCK(&(cur_vpn->lock));
  rhp_vpn_unhold(cur_vpn);

	RHP_TRC(0,RHPTRCID_IKEV1_MERGE_LARVAL_VPN_RTRN,"xxx",larval_vpn,cur_vpn,cur_vpn_ref);
	return 0;

error:
	if( cur_vpn ){
    rhp_vpn_unhold(cur_vpn);
	}
	RHP_TRC(0,RHPTRCID_IKEV1_MERGE_LARVAL_VPN_ERR,"xxxE",larval_vpn,cur_vpn,cur_vpn_ref,err);
	return err;
}


static int _rhp_ikev1_check_mesg(rhp_packet* pkt)
{
  rhp_proto_ike* ikeh = NULL;
  int err = 0;
  u32 len;
  u32* non_esp_marker;
  u8 exchange_type = 0;

  RHP_TRC(0,RHPTRCID_IKEV1_CHECK_MESG,"x",pkt);

  if( pkt->l3.raw == NULL || pkt->l4.raw == NULL || pkt->app.raw == NULL ){
    RHP_BUG("0x%x,0x%x,0x%x",pkt->l3.raw,pkt->l4.raw,pkt->app.raw);
    err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_PKT;
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV1_CHECK_MESG_L4,"xWddd",pkt,pkt->l4.udph->dst_port,rhp_gcfg_ike_port_nat_t,pkt->cookie_checked,pkt->mobike_verified);


  if( pkt->l4.udph->dst_port == htons(rhp_gcfg_ike_port_nat_t) ){

    non_esp_marker = (u32*)pkt->app.raw;

    if( ntohl(*non_esp_marker) != RHP_PROTO_NON_ESP_MARKER ){

      RHP_TRC(0,RHPTRCID_IKEV1_CHECK_MESG_INVALID_MESG_1,"xxK",pkt,non_esp_marker,*non_esp_marker);
      err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_NON_ESP_MARKER;
      goto error;

    }else{

      pkt->data = pkt->app.raw;

      if( _rhp_pkt_pull(pkt,RHP_PROTO_NON_ESP_MARKER_SZ) == NULL ){
        RHP_TRC(0,RHPTRCID_IKEV1_CHECK_MESG_INVALID_MESG_2,"x",pkt);
        err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;
        goto error;
      }

      pkt->app.raw = _rhp_pkt_pull(pkt,sizeof(rhp_proto_ike));

      if( pkt->app.raw == NULL ){
        RHP_TRC(0,RHPTRCID_IKEV1_CHECK_MESG_INVALID_MESG_3,"x",pkt);
        err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;
        goto error;
      }
    }

    ikeh = pkt->app.ikeh;

  }else{

    non_esp_marker = NULL;

    pkt->data = pkt->app.raw;

    pkt->app.raw = _rhp_pkt_pull(pkt,sizeof(rhp_proto_ike));
    if( pkt->app.raw == NULL ){
      RHP_TRC(0,RHPTRCID_IKEV1_CHECK_MESG_INVALID_MESG_4,"x",pkt);
      err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;
      goto error;
    }

    ikeh = pkt->app.ikeh;
  }

  RHP_TRC(0,RHPTRCID_IKEV1_CHECK_MESG_APP,"xbbLbUdGGLbU",pkt,ikeh->ver_major,ikeh->ver_minor,"PROTO_IKE_EXCHG",ikeh->exchange_type,ikeh->len,rhp_gcfg_max_ike_packet_size,ikeh->init_spi,ikeh->resp_spi,"PROTO_IKE_PAYLOAD",ikeh->next_payload,ikeh->message_id);


  exchange_type = ikeh->exchange_type;



  if( !(ikeh->ver_major == RHP_PROTO_IKE_V1_VER_MAJOR &&
        ikeh->ver_minor == RHP_PROTO_IKE_V1_VER_MINOR) ){

  	RHP_TRC(0,RHPTRCID_IKEV1_CHECK_MESG_INVALID_VER,"xbb",pkt,ikeh->ver_major,ikeh->ver_minor);
    err = RHP_STATUS_NOT_SUPPORTED_VER;

	  rhp_ikev2_g_statistics_inc(rx_ikev1_unsup_ver_packets);

    goto error;
  }


  len = ntohl(ikeh->len);

  if( len < (sizeof(rhp_proto_ike) + sizeof(rhp_proto_ike_payload)) ){

  	RHP_TRC(0,RHPTRCID_IKEV1_CHECK_MESG_INVALID_MESG_5,"x",pkt);
    err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;

	  rhp_ikev2_g_statistics_inc(rx_ikev1_invalid_len_packets);

    goto error;
  }


  if( len > (u32)rhp_gcfg_max_ike_packet_size ){

  	RHP_TRC(0,RHPTRCID_IKEV1_CHECK_MESG_TOO_LARGE,"xdd",pkt,len,rhp_gcfg_max_ike_packet_size);
    err = RHP_STATUS_MSG_TOO_LONG;

  	rhp_ikev2_g_statistics_inc(rx_ikev1_invalid_len_packets);

    goto error;
  }


  if( ((u32*)ikeh->init_spi)[0] == 0 && ((u32*)ikeh->init_spi)[1] == 0 ){

  	RHP_TRC(0,RHPTRCID_IKEV1_CHECK_MESG_BAD_I_SPI,"xG",pkt,ikeh->init_spi);
    err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_SPI_FIELD;

	  rhp_ikev2_g_statistics_inc(rx_ikev1_invalid_spi_packets);

    goto error;
  }


	if( ikeh->next_payload == RHP_PROTO_IKE_NO_MORE_PAYLOADS ){

		RHP_TRC(0,RHPTRCID_IKEV1_CHECK_NO_PAYLOADS,"xb",pkt,ikeh->next_payload);
		err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_NEXT_PAYLOAD_FIELD;

		rhp_ikev2_g_statistics_inc(rx_ikev1_parse_err_packets);

		goto error;
	}


  switch( exchange_type ){

    case RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION:
    case RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE:

    	if( (exchange_type == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION &&
    			 !rhp_gcfg_ikev1_main_mode_enabled) ||
    			(exchange_type == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE &&
    			 !rhp_gcfg_ikev1_aggressive_mode_enabled) ){

    		RHP_TRC(0,RHPTRCID_IKEV1_CHECK_MESG_EXCHG_TYPE_NOT_ENABLED,"xbdd",pkt,ikeh->exchange_type,rhp_gcfg_ikev1_main_mode_enabled,rhp_gcfg_ikev1_aggressive_mode_enabled);
        err = RHP_STATUS_INVALID_IKEV2_MESG_IKE_UNSUPPORTED_EXCHANGE_TYPE;

    	  rhp_ikev2_g_statistics_inc(rx_ikev1_invalid_exchg_type_packets);

        goto error;
    	}

      if( ikeh->message_id != 0 ){

      	RHP_TRC(0,RHPTRCID_IKEV1_CHECK_BAD_MESGID,"xJ",pkt,ikeh->message_id);
        err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_MESG_ID;

    	  rhp_ikev2_g_statistics_inc(rx_ikev1_invalid_seq_packets);

    		goto error;
      }

      if( ((u32*)ikeh->resp_spi)[0] == 0 && ((u32*)ikeh->resp_spi)[1] == 0 ){

      	if( ikeh->next_payload != RHP_PROTO_IKEV1_PAYLOAD_SA ){

      		RHP_TRC(0,RHPTRCID_IKEV1_CHECK_P1_1ST_NOT_SA_PAYLOAD,"xb",pkt,ikeh->next_payload);
      		err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_NEXT_PAYLOAD_FIELD;

      		rhp_ikev2_g_statistics_inc(rx_ikev1_parse_err_packets);
      		goto error;
      	}

      	if( RHP_PROTO_IKEV1_HDR_ENCRYPT(ikeh->flag) ){

      		RHP_TRC(0,RHPTRCID_IKEV1_CHECK_P1_1ST_INVALID_ENCRYPT_FLAG,"xb",pkt,ikeh->flag);
      		err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_PKT;

      		rhp_ikev2_g_statistics_inc(rx_ikev1_parse_err_packets);
      		goto error;
      	}

      	if( len <= sizeof(rhp_proto_ike)
      						 + sizeof(rhp_proto_ikev1_sa_payload)
      						 + sizeof(rhp_proto_ikev1_proposal_payload)
      						 + sizeof(rhp_proto_ikev1_transform_payload) ){

      		RHP_TRC(0,RHPTRCID_IKEV1_CHECK_P1_1ST_INVALID_LEN,"xd",pkt,len);
      		err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;

      	  rhp_ikev2_g_statistics_inc(rx_ikev1_invalid_len_packets);
      		goto error;
      	}
      }

      break;

    case RHP_PROTO_IKEV1_EXCHG_QUICK:
    case RHP_PROTO_IKEV1_EXCHG_INFORMATIONAL:
    case RHP_PROTO_IKEV1_EXCHG_TRANSACTION:

      // After Phase 1 exchg, should we handle a IKE message
    	// with 'NOT' encrypted payload(s)?

      if( ((u32*)ikeh->resp_spi)[0] == 0 && ((u32*)ikeh->resp_spi)[1] == 0 ){

      	RHP_TRC(0,RHPTRCID_IKEV1_CHECK_MESG_BAD_R_SPI,"xG",pkt,ikeh->resp_spi);
        err = RHP_STATUS_INVALID_IKEV2_MESG_IKE_AUTH_BAD_R_SPI;

    	  rhp_ikev2_g_statistics_inc(rx_ikev1_invalid_spi_packets);

    		goto error;
      }

      if( ikeh->message_id == 0 ){ // >= 1

      	RHP_TRC(0,RHPTRCID_IKEV1_CHECK_BAD_MESGID_2,"xJ",pkt,ikeh->message_id);
        err = RHP_STATUS_INVALID_IKEV2_MESG_IKE_AUTH_BAD_MESG_ID;

    	  rhp_ikev2_g_statistics_inc(rx_ikev1_invalid_seq_packets);

    		goto error;
      }

      if( !RHP_PROTO_IKEV1_HDR_ENCRYPT(ikeh->flag) ){

      	RHP_TRC(0,RHPTRCID_IKEV1_CHECK_MESG_INVALID_MESG_REQ_NOT_ENCRYPTED,"x",pkt);

      	rhp_ikev2_g_statistics_inc(rx_ikev1_not_encrypted_packets);

      	err = RHP_STATUS_INVALID_IKEV2_MESG_NOT_ENCRYPTED;
      }

      break;

    default:

    	RHP_TRC(0,RHPTRCID_IKEV1_CHECK_MESG_UNKNOW_EXCHG_TYPE,"xb",pkt,ikeh->exchange_type);
      err = RHP_STATUS_INVALID_IKEV2_MESG_IKE_UNSUPPORTED_EXCHANGE_TYPE;

  	  rhp_ikev2_g_statistics_inc(rx_ikev1_invalid_exchg_type_packets);

      goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV1_CHECK_MESG_OK,"xLb",pkt,"PROTO_IKE_EXCHG",ikeh->exchange_type);
  return 0;

error:

	if( pkt->type == RHP_PKT_IPV4_IKE ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_INVALID_IKEV1_MESG,"MMW44bWWE",(pkt->l2.raw ? pkt->l2.eth->dst_addr : NULL),(pkt->l2.raw ? pkt->l2.eth->src_addr : NULL),(pkt->l2.raw ? pkt->l2.eth->protocol : 0),(pkt->l3.raw ? pkt->l3.iph_v4->dst_addr : 0),(pkt->l3.raw ? pkt->l3.iph_v4->src_addr : 0),(pkt->l3.raw ? pkt->l3.iph_v4->protocol : 0),(pkt->l4.raw ? pkt->l4.udph->dst_port : 0),(pkt->l4.raw ? pkt->l4.udph->src_port : 0),	err);
	}else if( pkt->type == RHP_PKT_IPV6_IKE ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_INVALID_IKEV1_MESG_V6,"MMW66bWWE",(pkt->l2.raw ? pkt->l2.eth->dst_addr : NULL),(pkt->l2.raw ? pkt->l2.eth->src_addr : NULL),(pkt->l2.raw ? pkt->l2.eth->protocol : 0),(pkt->l3.raw ? pkt->l3.iph_v6->dst_addr : NULL),(pkt->l3.raw ? pkt->l3.iph_v6->src_addr : NULL),(pkt->l3.raw ? pkt->l3.iph_v6->next_header : 0),(pkt->l4.raw ? pkt->l4.udph->dst_port : 0),(pkt->l4.raw ? pkt->l4.udph->src_port : 0),	err);
	}

	if( ikeh ){
		rhp_ikev2_g_statistics_inc(rx_ikev1_verify_err_packets);
	}else{
		rhp_ikev2_g_statistics_inc(rx_ikev1_invalid_packets);
	}

	RHP_TRC(0,RHPTRCID_IKEV1_CHECK_MESG_ERR,"xLbE",pkt,"PROTO_IKE_EXCHG",exchange_type,err);
  return err;
}

//
// Retransmitting a response.
//
static int _rhp_ikev1_retransmit_response(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_packet* rx_pkt,
		rhp_packet* pkt_r)
{
	int err = -EINVAL;
	rhp_packet* pkt_r_d = NULL;
  rhp_ifc_entry* tx_ifc = NULL;
  time_t now;
  int my_side = ikesa->side;
  u8* my_spi = ikesa->get_my_spi(ikesa);

	RHP_TRC(0,RHPTRCID_IKEV1_RETRANSMIT_RESPONSE,"xxxx",vpn,ikesa,rx_pkt,pkt_r);

	tx_ifc = rx_pkt->rx_ifc;
	if( tx_ifc == NULL ){
		RHP_BUG("");
		goto ignore;
	}


  {
		now = _rhp_get_time();

		if( ikesa->rep_retx_last_time == now ){

			if( ikesa->rep_retx_cnt > (unsigned long)rhp_gcfg_ike_retransmit_reps_limit_per_sec ){

				RHP_TRC(0,RHPTRCID_IKEV1_RETRANSMIT_RESPONSE_RATE_LIMITED,"xxxu",rx_pkt,vpn,ikesa,ikesa->rep_retx_cnt);

				rhp_ikev2_g_statistics_inc(tx_ikev1_resp_rate_limited_err_packets);

				goto ignore;
			}

			ikesa->rep_retx_cnt++;

		}else{

			ikesa->rep_retx_last_time = now;
			ikesa->rep_retx_cnt = 0;
		}
  }

	pkt_r_d = rhp_pkt_dup(pkt_r);
	if( pkt_r_d == NULL ){
		RHP_TRC(0,RHPTRCID_IKEV1_RETRANSMIT_RESPONSE_DUP_PKT_FAILED,"xxxx",rx_pkt,vpn,ikesa,pkt_r);
		goto ignore;
	}


	pkt_r_d->tx_ifc = tx_ifc;
	rhp_ifc_hold(pkt_r_d->tx_ifc);


	err = rhp_netsock_send(pkt_r_d->tx_ifc,pkt_r_d);
	if( err < 0 ){
		RHP_TRC(0,RHPTRCID_IKEV1_RETRANSMIT_RESPONSE_TX_PKT_FAILED,"xxxxE",rx_pkt,vpn,ikesa,pkt_r_d,err);
	}

	rhp_ikev2_g_statistics_inc(tx_ikev1_resp_retransmit_packets);
	err = 0;

	if( pkt_r->type == RHP_PKT_IPV4_IKE ){
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKEV1_RETRANSMIT_RESPONSE,"VP44WWLG",vpn,ikesa,pkt_r_d->l3.iph_v4->src_addr,pkt_r_d->l3.iph_v4->dst_addr,pkt_r_d->l4.udph->src_port,pkt_r_d->l4.udph->dst_port,"IKE_SIDE",my_side,my_spi);
	}else if( pkt_r->type == RHP_PKT_IPV6_IKE ){
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKEV1_RETRANSMIT_RESPONSE_V6,"VP66WWLG",vpn,ikesa,pkt_r_d->l3.iph_v6->src_addr,pkt_r_d->l3.iph_v6->dst_addr,pkt_r_d->l4.udph->src_port,pkt_r_d->l4.udph->dst_port,"IKE_SIDE",my_side,my_spi);
	}

	rhp_pkt_unhold(pkt_r_d);
	pkt_r_d = NULL;

ignore:
	RHP_TRC(0,RHPTRCID_IKEV1_RETRANSMIT_RESPONSE_RTRN,"xxxxx",rx_pkt,vpn,ikesa,pkt_r,pkt_r_d);
  return 0;
}

static int _rhp_ikev1_rx_mesg_handle_retransmit(rhp_packet* pkt,rhp_proto_ike* ikeh,rhp_vpn* vpn,rhp_ikesa* ikesa)
{
	int err = -EINVAL;
	rhp_packet* pkt_r = ikesa->v1.rep_retx_pkts.head;

	RHP_TRC(0,RHPTRCID_IKEV1_RX_MESG_HANDLE_RETRANSMIT,"xxxxx",pkt,ikeh,vpn,ikesa,pkt_r);

	while( pkt_r ){

  	rhp_proto_ike* ikeh_r;
  	u8* pkt_hash = NULL;
  	int pkt_hash_len = 0;

  	err = rhp_ikesa_pkt_hash_v1(pkt,&pkt_hash,&pkt_hash_len,NULL,NULL); // Secure Hash
  	if( err ){
  		RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_RETX_REP_PKT_HASH_ERR,"xxxE",pkt,vpn,ikesa,err);
  		goto error;
  	}


  	if( pkt_r->l4.udph->src_port == vpn->local.port_nat_t ){
  		ikeh_r = (rhp_proto_ike*)(pkt_r->app.raw + RHP_PROTO_NON_ESP_MARKER_SZ);
  	}else{
  		ikeh_r = (rhp_proto_ike*)(pkt_r->app.raw);
  	}

		RHP_TRC(0,RHPTRCID_IKEV1_RX_MESG_HANDLE_RETRANSMIT_REP_QD_PKT,"xxxxbbkkpppp",pkt,pkt_r,vpn,ikesa,ikeh->exchange_type,ikeh_r->exchange_type,ntohl(ikeh->message_id),ntohl(ikeh_r->message_id),pkt_hash_len,pkt_hash,pkt_r->ikev1_pkt_hash_len,pkt_r->ikev1_pkt_hash,sizeof(rhp_proto_ike),ikeh,sizeof(rhp_proto_ike),ikeh_r);

  	if( ikeh->exchange_type == ikeh_r->exchange_type &&
  			ntohl(ikeh->message_id) == ntohl(ikeh_r->message_id) &&
  			pkt_hash_len == pkt_r->ikev1_pkt_hash_len &&
  			!memcmp(pkt_hash,pkt_r->ikev1_pkt_hash,pkt_hash_len) ){

  		_rhp_ikev1_retransmit_response(vpn,ikesa,pkt,pkt_r);

    	_rhp_free(pkt_hash);

  		goto retx_ok;
  	}

  	_rhp_free(pkt_hash);

		pkt_r = pkt_r->next;
	}

	RHP_TRC(0,RHPTRCID_IKEV1_RX_MESG_HANDLE_RETRANSMIT_NEW_PKT,"xxx",pkt,vpn,ikesa);
	return 0;

retx_ok:
	RHP_TRC(0,RHPTRCID_IKEV1_RX_MESG_HANDLE_RETRANSMIT_OK,"xxx",pkt,vpn,ikesa);
	return RHP_STATUS_RETRANS_OK;

error:
	RHP_TRC(0,RHPTRCID_IKEV1_RX_MESG_HANDLE_RETRANSMIT_ERR,"xxxE",pkt,vpn,ikesa,err);
	return err;
}


extern int rhp_ikev1_xauth_pending(rhp_vpn* vpn,rhp_ikesa* ikesa,u8 exchange_type,rhp_packet* pkt);

static int _rhp_ikev1_rx_verify_mesg(rhp_packet* pkt,
		rhp_vpn_ref** vpn_ref_r,int* my_side_r,u8* my_spi_r)
{
  int err = -EINVAL;
  u8 exchange_type = 0;
  rhp_proto_ike *ikeh = NULL;
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;
  rhp_ikesa* ikesa = NULL;
  rhp_vpn_realm* rlm = NULL;
  u8 my_spi_v[RHP_PROTO_IKE_SPI_SIZE];
  rhp_ifc_entry* tx_ifc = NULL;
  rhp_ip_addr src_addr, dst_addr;
  int my_side = -1;
  u8* my_spi = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG,"xx",pkt,vpn_ref_r);

  memset(&src_addr,0,sizeof(rhp_ip_addr));
  memset(&dst_addr,0,sizeof(rhp_ip_addr));

  if( pkt->type == RHP_PKT_IPV4_IKE ){

  	src_addr.addr_family = AF_INET;
  	src_addr.addr.v4 = pkt->l3.iph_v4->src_addr;
  	src_addr.port = pkt->l4.udph->src_port;
  	dst_addr.addr_family = AF_INET;
  	dst_addr.addr.v4 = pkt->l3.iph_v4->dst_addr;
  	dst_addr.port = pkt->l4.udph->dst_port;

  }else if( pkt->type == RHP_PKT_IPV6_IKE ){

  	src_addr.addr_family = AF_INET;
  	memcpy(src_addr.addr.v6,pkt->l3.iph_v6->src_addr,16);
  	src_addr.port = pkt->l4.udph->src_port;
  	dst_addr.addr_family = AF_INET;
  	memcpy(dst_addr.addr.v6,pkt->l3.iph_v6->dst_addr,16);
  	dst_addr.port = pkt->l4.udph->dst_port;

  }else{
  	RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

  ikeh = pkt->app.ikeh;
  exchange_type = ikeh->exchange_type;


  if( (exchange_type == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ||
  		 exchange_type == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE) &&
  		((u32*)ikeh->resp_spi)[0] == 0 && ((u32*)ikeh->resp_spi)[1] == 0 ){

  	err = rhp_ikesa_init_i_get(pkt,my_spi_v);
		if( err == -ENOENT ){

			RHP_TRC_FREQ(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_NEW_IKESA,"x",pkt);

			if( rhp_ikesa_max_half_open_sessions_reached() ){

				RHP_TRC_FREQ(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_MAX_HALF_OPEN_SESSIONS_REACHED,"x",pkt);

				rhp_ikev2_g_statistics_inc(max_ikesa_half_open_sessions_reached);
				err = RHP_STATUS_IKESA_MAX_HALF_OPEN_SESSIONS_REACHED;
				goto error;

			}else if( rhp_vpn_max_sessions_reached() ){

				RHP_TRC_FREQ(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_MAX_VPN_SESSIONS_REACHED,"x",pkt);

				rhp_ikev2_g_statistics_inc(max_vpn_sessions_reached);
				err = RHP_STATUS_VPN_MAX_SESSIONS_REACHED;
				goto error;
			}

			if( exchange_type == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ){
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV1_RX_NEW_MAIN_MODE_REQ,"VLGG",vpn,"PROTO_IKE_EXCHG",exchange_type,(ikeh ? ikeh->init_spi : NULL),(ikeh ? ikeh->resp_spi : NULL));
				rhp_ikev2_g_statistics_inc(rx_ikev1_new_main_mode_packets);
			}else if( exchange_type == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV1_RX_NEW_AGGRESSIVE_MODE_REQ,"VLGG",vpn,"PROTO_IKE_EXCHG",exchange_type,(ikeh ? ikeh->init_spi : NULL),(ikeh ? ikeh->resp_spi : NULL));
				rhp_ikev2_g_statistics_inc(rx_ikev1_new_aggressive_mode_packets);
			}

		  RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_NEW_P1,"x",pkt);

			goto new_phase1;

		}else if( err ){

		  RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_INIT_I_GET_ERR,"xE",pkt,err);
			goto error;
		}

		my_side = RHP_IKE_RESPONDER;
		my_spi = my_spi_v;

  }else{

		err = rhp_vpn_ikesa_v1_spi_get(&dst_addr,&src_addr,ikeh->init_spi,ikeh->resp_spi,&my_side);
		if( err == -ENOENT ){

			err = rhp_vpn_ikesa_v1_spi_get(&dst_addr,&src_addr,ikeh->resp_spi,ikeh->init_spi,&my_side);
			if( err == -ENOENT ){

				if( exchange_type == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ||
						exchange_type == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){

					my_side = RHP_IKE_INITIATOR;
					my_spi = ikeh->init_spi;

				}else{
				  RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_SPI_GET_INVALID_EXCHANGE_TYPE,"xb",pkt,exchange_type);
					goto error;
				}

			}else if( err ){
			  RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_SPI_GET_INITIATOR_ERR,"xE",pkt,err);
			}

		}else if( err ){
		  RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_SPI_GET_RESPONDER_ERR,"xE",pkt,err);
			goto error;
		}

		if( my_side == RHP_IKE_INITIATOR ){

			my_spi = ikeh->init_spi;

		}else if( my_side == RHP_IKE_RESPONDER ){

			my_spi = ikeh->resp_spi;

		}else{
			err = -ENOENT;
		  RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_NO_IKESA_FOUND,"xE",pkt,err);
			goto error;
		}
  }


  vpn_ref = rhp_vpn_ikesa_spi_get(my_side,my_spi);
  vpn = RHP_VPN_REF(vpn_ref);
  if( vpn == NULL ){

  	RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_NO_VPN,"xLdG",pkt,"IKE_SIDE",my_side,my_spi);
		err = RHP_STATUS_INVALID_IKEV2_MESG_NO_VPN;

  	rhp_ikev2_g_statistics_inc(rx_ikev1_no_ikesa_err_packets);

  	goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_IKEHDR,"xLbLdG",pkt,"PROTO_IKE_EXCHG",exchange_type,"IKE_SIDE",my_side,my_spi);


  RHP_LOCK(&(vpn->lock));

  vpn->dump("_rhp_ikev1_rx_verify_mesg",vpn);

  if( !_rhp_atomic_read(&(vpn->is_active)) ){

  	RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_VPN_NOT_ACTIVE,"xx",pkt,vpn);
  	err = RHP_STATUS_INVALID_IKEV2_MESG_VPN_NOT_ACTIVE;

  	rhp_ikev2_g_statistics_inc(rx_ikev1_no_ikesa_err_packets);

  	goto error_l;
  }


  ikesa = vpn->ikesa_get(vpn,my_side,my_spi);
  if( ikesa == NULL ){

  	err = RHP_STATUS_INVALID_IKEV2_MESG_NO_IKESA;
    RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_RESP_NO_VPN_IKESA,"xxx",pkt,vpn,rlm);

  	rhp_ikev2_g_statistics_inc(rx_ikev1_no_ikesa_err_packets);

  	goto error_l;
  }

  ikesa->dump(ikesa);


  rlm = vpn->rlm;
  if( rlm ){

  	RHP_LOCK(&(rlm->lock));

  	RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_RLM,"xxxus",pkt,vpn,rlm,rlm->id,rlm->name);
  	if( vpn->cfg_peer ){
	  	rhp_ikev2_id_dump("vpn->cfg_peer->id",&(vpn->cfg_peer->id));
	  	rhp_ip_addr_dump("vpn->cfg_peer->primary_addr",&(vpn->cfg_peer->primary_addr));
	  	rhp_ip_addr_dump("vpn->cfg_peer->secondary_addr",&(vpn->cfg_peer->secondary_addr));
	  	rhp_ip_addr_dump("vpn->cfg_peer->internal_addr",&(vpn->cfg_peer->internal_addr));
  	}

  	if( !_rhp_atomic_read(&(rlm->is_active)) ){
  		RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_RLM_NOT_ACTIVE,"xxx",pkt,vpn,rlm);
  		err = RHP_STATUS_INVALID_IKEV2_MESG_REALM_NOT_ACTIVE;
  		goto error_l;
    }

    err = vpn->check_cfg_address(vpn,rlm,pkt);
    if( err ){

    	RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_CHECK_CFG_ADDR_ERR,"xxxE",pkt,vpn,rlm,err);
    	err = RHP_STATUS_INVALID_IKEV2_MESG_CHECK_CFG_ADDR_ERR;

    	rhp_ikev2_g_statistics_inc(rx_ikev1_unknown_if_err_packets);

    	goto error_l;
    }

    RHP_UNLOCK(&(rlm->lock));
    rlm = NULL;

  }else{

    if( exchange_type != RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION &&
    		exchange_type != RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){

    	RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_INVALID_EXCHANGE,"xxb",pkt,vpn,exchange_type);
    	err = RHP_STATUS_INVALID_IKEV2_MESG_NO_REALM;

    	rhp_ikev2_g_statistics_inc(rx_ikev1_invalid_exchg_type_packets);

    	goto error_l;
    }
  }


  if( ikesa->busy_flag ){

  	RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_IKESA_BUSY,"xxxxd",pkt,vpn,rlm,ikesa,pkt->v1_mode_cfg_pending);

  	if( !pkt->v1_mode_cfg_pending ){

			if( rhp_ikev1_xauth_pending(vpn,ikesa,exchange_type,pkt) ){

				if( ikesa->v1.mode_cfg_pending_pkt_ref == NULL ){

					ikesa->v1.mode_cfg_pending_pkt_ref = rhp_pkt_hold_ref(pkt);

					pkt->v1_mode_cfg_pending = 1;
				}
			}

			rhp_ikev2_g_statistics_inc(rx_ikev1_busy_err_packets);
			err = -EBUSY;

			goto error_l;
  	}

  	ikesa->busy_flag = 0;
  }


	if( (pkt->type == RHP_PKT_IPV4_IKE && vpn->peer_addr.addr_family != AF_INET) ||
			(pkt->type == RHP_PKT_IPV6_IKE && vpn->peer_addr.addr_family != AF_INET6) ||
			(pkt->type == RHP_PKT_IPV4_IKE && vpn->peer_addr.addr.v4 != pkt->l3.iph_v4->src_addr) ||
			(pkt->type == RHP_PKT_IPV6_IKE && !rhp_ipv6_is_same_addr(vpn->peer_addr.addr.v6,pkt->l3.iph_v6->src_addr)) ||
			(vpn->peer_addr.port != pkt->l4.udph->src_port) ){

		rhp_ikev2_g_statistics_inc(rx_ikev1_from_unknown_peer_packets);

		RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_FROM_UNKNOWN_PEER,"xxxxd",pkt,vpn,rlm,ikesa,vpn->nat_t_info.exec_nat_t);

	  if( !vpn->nat_t_info.exec_nat_t ){
			err = RHP_STATUS_INVALID_IKEV2_MESG_RX_FROM_UNKNOWN_PEER;
			goto error_l;
	  }
  }


	err = _rhp_ikev1_rx_mesg_handle_retransmit(pkt,ikeh,vpn,ikesa);
	if( err == RHP_STATUS_RETRANS_OK ){
		goto error_l;
	}else if( err ){
		goto error_l;
	}else{
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_RX_NEW_MESG,"xxxx",pkt,vpn,ikesa,rlm);
	}


  if( exchange_type == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ){

  	if( my_side == RHP_IKE_INITIATOR ){

      if( ikesa->state != RHP_IKESA_STAT_V1_MAIN_1ST_SENT_I &&
      		ikesa->state != RHP_IKESA_STAT_V1_MAIN_3RD_SENT_I &&
      		ikesa->state != RHP_IKESA_STAT_V1_MAIN_5TH_SENT_I ){

      	RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_MAIN_MODE_I_BAD_STAT,"xxxxd",pkt,vpn,rlm,ikesa,ikesa->state);

      	rhp_ikev2_g_statistics_inc(rx_ikev1_bad_ikesa_state_packets);
    		err = RHP_STATUS_INVALID_MSG;

    		goto error_l;
      }

  	}else{ // RHP_IKE_RESPONDER

      if( ikesa->state != RHP_IKESA_STAT_V1_MAIN_2ND_SENT_R &&
      		ikesa->state != RHP_IKESA_STAT_V1_MAIN_4TH_SENT_R ){

      	RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_MAIN_MODE_R_BAD_STAT,"xxxxd",pkt,vpn,rlm,ikesa,ikesa->state);

      	rhp_ikev2_g_statistics_inc(rx_ikev1_bad_ikesa_state_packets);
    		err = RHP_STATUS_INVALID_MSG;

    		goto error_l;
      }
    }

  }else if( exchange_type == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){

  	if( my_side == RHP_IKE_INITIATOR ){

      if( ikesa->state != RHP_IKESA_STAT_V1_AGG_1ST_SENT_I &&
      		ikesa->state != RHP_IKESA_STAT_V1_AGG_WAIT_COMMIT_I ){

      	RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_AGGRESSIVE_MODE_I_BAD_STAT,"xxxxd",pkt,vpn,rlm,ikesa,ikesa->state);

      	rhp_ikev2_g_statistics_inc(rx_ikev1_bad_ikesa_state_packets);
    		err = RHP_STATUS_INVALID_MSG;

    		goto error_l;
      }

  	}else{ // RHP_IKE_RESPONDER

      if( ikesa->state != RHP_IKESA_STAT_V1_AGG_2ND_SENT_R ){

      	RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_AGGRESSIVE_MODE_R_BAD_STAT,"xxxxd",pkt,vpn,rlm,ikesa,ikesa->state);

      	rhp_ikev2_g_statistics_inc(rx_ikev1_bad_ikesa_state_packets);
    		err = RHP_STATUS_INVALID_MSG;

    		goto error_l;
      }
    }

  }else if( exchange_type == RHP_PROTO_IKEV1_EXCHG_TRANSACTION ){

    if( ikesa->state != RHP_IKESA_STAT_V1_XAUTH_PEND_I &&
    		ikesa->state != RHP_IKESA_STAT_V1_XAUTH_PEND_R &&
    		ikesa->state != RHP_IKESA_STAT_V1_ESTABLISHED &&
    		ikesa->state != RHP_IKESA_STAT_V1_REKEYING ){

    	RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_TRANSACTION_IKESA_BAD_STAT,"xxxxd",pkt,vpn,rlm,ikesa,ikesa->state);

    	rhp_ikev2_g_statistics_inc(rx_ikev1_bad_ikesa_state_packets);
  		err = RHP_STATUS_INVALID_MSG;

  		goto error_l;
    }

  }else if( exchange_type == RHP_PROTO_IKEV1_EXCHG_INFORMATIONAL ){

  	//
  	// TODO: Handle INITIAL-CONTACT notification after P1 exchange is completed.
  	//       Some IKEv1 implementations (e.g. Android and ipsec-tools) send the
  	//       notification like this. Other implementations (e.g. Cisco and
  	//       strongSwan) including Rockhopper send it during the P1 exchange.
  	//

    if( ikesa->state != RHP_IKESA_STAT_V1_ESTABLISHED &&
    		ikesa->state != RHP_IKESA_STAT_V1_REKEYING &&
    	  ikesa->state != RHP_IKESA_STAT_V1_DELETE &&
    	  ikesa->state != RHP_IKESA_STAT_V1_DELETE_WAIT /*&&
    	  ikesa->state != RHP_IKESA_STAT_V1_XAUTH_PEND_R*/ ){

    	RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_INFORMATIONAL_IKESA_BAD_STAT,"xxxxd",pkt,vpn,rlm,ikesa,ikesa->state);

    	rhp_ikev2_g_statistics_inc(rx_ikev1_bad_ikesa_state_packets);
  		err = RHP_STATUS_INVALID_MSG;

  		goto error_l;
    }

  }else{

    if( ikesa->state != RHP_IKESA_STAT_V1_ESTABLISHED &&
    		ikesa->state != RHP_IKESA_STAT_V1_REKEYING &&
    	  ikesa->state != RHP_IKESA_STAT_V1_DELETE &&
    	  ikesa->state != RHP_IKESA_STAT_V1_DELETE_WAIT ){

    	RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_IKESA_BAD_STAT,"xxxxd",pkt,vpn,rlm,ikesa,ikesa->state);

    	rhp_ikev2_g_statistics_inc(rx_ikev1_bad_ikesa_state_packets);
  		err = RHP_STATUS_INVALID_MSG;

  		goto error_l;
    }
  }


  if( my_side_r ){
  	*my_side_r = my_side;
  	memcpy(my_spi_r,my_spi,RHP_PROTO_IKE_SPI_SIZE);
  }

  *vpn_ref_r = vpn_ref;

  RHP_UNLOCK(&(vpn->lock));


new_phase1:
  if( tx_ifc ){
  	rhp_ifc_unhold(tx_ifc); // (***)
  }

  RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_RTRN,"xxxxx",pkt,vpn,rlm,ikesa,vpn_ref);

  return 0;


error_l:
  if( rlm ){
    RHP_UNLOCK(&(rlm->lock));
  }
  if( vpn ){
    RHP_UNLOCK(&(vpn->lock));
  }

error:

	if( err && err != RHP_STATUS_RETRANS_OK ){

		if( pkt->type == RHP_PKT_IPV4_IKE ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV1_RX_VERIFY_REQ_ERR,"VLG44WWGGLUE",vpn,"IKE_SIDE",my_side,my_spi,(pkt && pkt->l3.raw ? pkt->l3.iph_v4->src_addr : 0),(pkt && pkt->l3.raw ? pkt->l3.iph_v4->dst_addr : 0),(pkt && pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt && pkt->l4.raw ? pkt->l4.udph->dst_port : 0),(pkt && pkt->app.ikeh ? pkt->app.ikeh->init_spi : NULL),(pkt && pkt->app.ikeh ? pkt->app.ikeh->resp_spi : NULL),"PROTO_IKE_EXCHG",(int)(pkt && pkt->app.ikeh ? pkt->app.ikeh->exchange_type : 0),(pkt && pkt->app.ikeh ? pkt->app.ikeh->message_id : 0),err);
		}else if( pkt->type == RHP_PKT_IPV6_IKE ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV1_RX_VERIFY_REQ_V6_ERR,"VLG66WWGGLUE",vpn,"IKE_SIDE",my_side,my_spi,(pkt && pkt->l3.raw ? pkt->l3.iph_v6->src_addr : NULL),(pkt && pkt->l3.raw ? pkt->l3.iph_v6->dst_addr : NULL),(pkt && pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt && pkt->l4.raw ? pkt->l4.udph->dst_port : 0),(pkt && pkt->app.ikeh ? pkt->app.ikeh->init_spi : NULL),(pkt && pkt->app.ikeh ? pkt->app.ikeh->resp_spi : NULL),"PROTO_IKE_EXCHG",(int)(pkt && pkt->app.ikeh ? pkt->app.ikeh->exchange_type : 0),(pkt && pkt->app.ikeh ? pkt->app.ikeh->message_id : 0),err);
		}

		rhp_ikev2_g_statistics_inc(rx_ikev1_verify_err_packets);
	}

  if( vpn ){
    rhp_vpn_unhold(vpn_ref);
  }

  if( tx_ifc ){
  	rhp_ifc_unhold(tx_ifc); // (***)
  }


  RHP_TRC(0,RHPTRCID_IKEV1_RX_VERIFY_MESG_ERR,"xxxxxE",pkt,vpn,vpn_ref,rlm,ikesa,err);
  return err;
}

int rhp_ikev1_recv_impl(int addr_family,rhp_packet* pkt)
{
  rhp_ikev2_mesg* rx_ikemesg = NULL;
  int err = -EINVAL;
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;
  rhp_ikesa* ikesa = NULL;
  rhp_ikev2_mesg* ikemesg_error = NULL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  int my_ikesa_side = -1;
  u8 my_ikesa_spi[RHP_PROTO_IKE_SPI_SIZE];

  if( pkt->type == RHP_PKT_IPV4_IKE ){
  	RHP_TRC(0,RHPTRCID_IKEV1_RECV_IMPL,"Ldxad","AF",addr_family,pkt,(pkt->tail - pkt->l2.raw),RHP_TRC_FMT_A_MAC_IPV4_IKEV2,0,0,pkt->l2.raw,pkt->v1_mode_cfg_pending);
  }else if( pkt->type == RHP_PKT_IPV6_IKE ){
  	RHP_TRC(0,RHPTRCID_IKEV1_RECV_IMPL_V6,"Ldxad","AF",addr_family,pkt,(pkt->tail - pkt->l2.raw),RHP_TRC_FMT_A_MAC_IPV6_IKEV2,0,0,pkt->l2.raw,pkt->v1_mode_cfg_pending);
  }else{
  	RHP_BUG("%d",pkt->type);
  }


  if( !pkt->v1_mode_cfg_pending ){

		if( rhp_cfg_check_peer_acls(pkt) ){

			RHP_TRC(0,RHPTRCID_IKEV1_RECV_IMPL_ACL_NOT_MATCHED,"x",pkt);

			rhp_ikev2_g_statistics_inc(rx_ikev1_acl_err_packets);

			goto error;
		}

		// Don't ref pkt->app.ikeh here! This may still point a head
		// of RHP_PROTO_NON_ESP_MARKER.
		// _rhp_ikev1_check_mesg() will inc the pointer to IKEv2 header.
		err = _rhp_ikev1_check_mesg(pkt);
		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV1_RECV_IMPL_INVALID_MESG,"xE",pkt,err);
			goto error;
		}
  }


  err = _rhp_ikev1_rx_verify_mesg(pkt,&vpn_ref,&my_ikesa_side,my_ikesa_spi);
  vpn = RHP_VPN_REF(vpn_ref);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV1_RECV_IMPL_VERIFY_IGNORE_MESG,"xE",pkt,err);
    err = 0;
    goto end;
  }


  if( vpn ){

    RHP_LOCK(&(vpn->lock));

    if( !_rhp_atomic_read(&(vpn->is_active)) ){

    	RHP_TRC(0,RHPTRCID_IKEV1_RECV_IMPL_VPN_NOT_ACTIVE,"xx",pkt,vpn);
      err = -ENOENT;

  	  rhp_ikev2_g_statistics_inc(rx_ikev1_no_ikesa_err_packets);

      goto error_l;
    }

  	if( my_ikesa_side != -1 ){

			ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
			if( ikesa == NULL ){

				RHP_TRC(0,RHPTRCID_IKEV1_RECV_IMPL_NO_IKESA,"xxLdG",pkt,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
				err = -ENOENT;

				rhp_ikev2_g_statistics_inc(rx_ikev1_no_ikesa_err_packets);

				goto error_l;
			}

  	}else{

			RHP_TRC(0,RHPTRCID_IKEV1_RECV_IMPL_NO_IKESA_SPI,"xxLdG",pkt,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			err = -ENOENT;

			rhp_ikev2_g_statistics_inc(rx_ikev1_no_ikesa_err_packets);

			goto error_l;
  	}
  }


  {
		u8* pkt_hash;
		int pkt_hash_len;

		if( !rhp_ikesa_pkt_hash_v1(pkt,&pkt_hash,&pkt_hash_len,NULL,NULL) ){ // Secure Hash

			pkt->ikev1_pkt_hash = pkt_hash;
			pkt->ikev1_pkt_hash_len = pkt_hash_len;

		}else{

  	  rhp_ikev2_g_statistics_inc(rx_ikev1_parse_err_packets);

			RHP_BUG("");
			err = -EINVAL;
			goto error_l;
		}
  }


  //
  // [CAUTION]
  //
  //	- vpn and ikesa may be NULLs before SA is established.
  //
  err = rhp_ikev1_new_mesg_rx(pkt,vpn,ikesa,&rx_ikemesg,&ikemesg_error);
  if( err ){

  	RHP_TRC(0,RHPTRCID_IKEV1_RECV_IMPL_NEW_REQ_ALLOC_ERR,"xxxxE",pkt,vpn,ikesa,ikemesg_error,err);

    if( ikemesg_error ){

    	if( vpn && ikesa ){

    		_rhp_ikev1_send_mesg(vpn,ikesa,ikemesg_error,
    				RHP_IKEV1_MESG_HANDLER_END,RHP_IKEV1_MESG_HANDLER_END,1);
    	}

    	rhp_ikev2_unhold_mesg(ikemesg_error);
    }

    if( err > 0 ){
  	  rhp_ikev2_g_statistics_inc(rx_ikev1_parse_err_packets);
    }

  	err = RHP_STATUS_INVALID_MSG;
    goto error_l;
  }


  if( vpn &&
  		vpn->nat_t_info.exec_nat_t ){

		if( (pkt->type == RHP_PKT_IPV4_IKE && vpn->peer_addr.addr_family != AF_INET ) ||
				(pkt->type == RHP_PKT_IPV6_IKE && vpn->peer_addr.addr_family != AF_INET6 ) ||
				(pkt->type == RHP_PKT_IPV4_IKE &&
				 vpn->peer_addr.addr.v4 != pkt->l3.iph_v4->src_addr) ||
				(pkt->type == RHP_PKT_IPV6_IKE &&
				 !rhp_ipv6_is_same_addr(vpn->peer_addr.addr.v6,pkt->l3.iph_v6->src_addr)) ||
				(vpn->peer_addr.port != pkt->l4.udph->src_port)  ){

			if( !rhp_gcfg_nat_dont_change_addr_port_by_ikev1 ){

				if( pkt->type == RHP_PKT_IPV4_IKE ){
					RHP_TRC(0,RHPTRCID_IKEV1_RECV_IMPL_NAT_T_PEER_SRC_CHANGED,"xx44WW",pkt,vpn,vpn->peer_addr.addr.v4,pkt->l3.iph_v4->src_addr,vpn->peer_addr.port,pkt->l4.udph->src_port);
				}else if(pkt->type == RHP_PKT_IPV6_IKE){
					RHP_TRC(0,RHPTRCID_IKEV1_RECV_IMPL_NAT_T_PEER_SRC_CHANGED_V6,"xx66WW",pkt,vpn,vpn->peer_addr.addr.v6,pkt->l3.iph_v6->src_addr,vpn->peer_addr.port,pkt->l4.udph->src_port);
				}

				rx_ikemesg->v1_src_changed = 1;
			}
		}
  }


  {
		int my_ikesa_side_new = -1;
		u8 my_ikesa_spi_new[RHP_PROTO_IKE_SPI_SIZE];
		int do_destroy_vpn = 0;

	  tx_ikemesg = rhp_ikev1_new_mesg_tx(rx_ikemesg->get_exchange_type(rx_ikemesg),
	  							rx_ikemesg->get_mesg_id(rx_ikemesg),0);
	  if( tx_ikemesg == NULL ){
	  	RHP_BUG("");
	  	goto error_l;
	  }


		err = _rhp_ikev1_call_rx_mesg_handlers(rx_ikemesg,vpn,
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

	  	rhp_ikev2_g_statistics_inc(rx_ikev1_process_err_packets);

			do_destroy_vpn = 1;

		}else if( err ){

  		rhp_ikev2_g_statistics_inc(rx_ikev1_process_err_packets);
  		goto error_l;
		}


		if( rx_ikemesg->decrypted ){
	    ikesa->statistics.rx_encrypted_packets++;
	  	RHP_TRC(0,RHPTRCID_IKEV1_RECV_IMPL_RX_ENC_PKTS,"xxxqqq",rx_ikemesg,vpn,ikesa,ikesa->statistics.rx_encrypted_packets,ikesa->statistics.rx_keep_alive_reply_packets,ikesa->timers->last_rx_encrypted_packets);
	  }


		//*********************************************************************
		//
		// [CAUTION]
		// Don't touch 'ikesa' any more! It may be deleted from 'vpn'.
		//
		// If needed, get 'ikesa' again from vpn.
		//
	  //*********************************************************************


		if( !err || do_destroy_vpn ){

			if( rx_ikemesg->v1_src_changed ){

				int addr_chg_family = AF_UNSPEC;
				u8 addr_chg_src_addr[16];
				u16 addr_chg_src_port, addr_chg_dst_port;

				if( pkt->type == RHP_PKT_IPV4_IKE ){

					addr_chg_family = AF_INET;
					*((u32*)addr_chg_src_addr) = pkt->l3.iph_v4->src_addr;
					addr_chg_src_port = pkt->l4.udph->src_port;
					addr_chg_dst_port = pkt->l4.udph->dst_port;

					RHP_TRC(0,RHPTRCID_IKEV1_RX_FROM_UNKNOWN_PEER,"xxx44WW",pkt,vpn,ikesa,vpn->peer_addr.addr.v4,pkt->l3.iph_v4->src_addr,vpn->peer_addr.port,pkt->l4.udph->src_port);

				}else if( pkt->type == RHP_PKT_IPV6_IKE ){

					addr_chg_family = AF_INET6;
					memcpy(addr_chg_src_addr,pkt->l3.iph_v6->src_addr,16);
					addr_chg_src_port = pkt->l4.udph->src_port;
					addr_chg_dst_port = pkt->l4.udph->dst_port;

					RHP_TRC(0,RHPTRCID_IKEV1_RX_FROM_UNKNOWN_PEER_V6,"xxx66WW",pkt,vpn,ikesa,vpn->peer_addr.addr.v6,pkt->l3.iph_v6->src_addr,vpn->peer_addr.port,pkt->l4.udph->src_port);
				}

				if( addr_chg_family != AF_UNSPEC ){

					err = rhp_ikev2_nat_t_change_peer_addr_port(vpn,addr_chg_family,
									addr_chg_src_addr,addr_chg_src_port,addr_chg_dst_port,0);
					if( err ){
						RHP_TRC(0,RHPTRCID_IKEV1_RX_FROM_UNKNOWN_PEER_NAT_T_ERR,"xxx",pkt,vpn,ikesa);
					}
					err = 0;
				}
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
			memcpy(my_ikesa_spi,my_ikesa_spi_new,RHP_PROTO_IKE_SPI_SIZE);
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

  			if( pkt->l4.udph->dst_port == vpn->local.port_nat_t ){
  		  	tx_ikemesg->tx_from_nat_t_port = 1;
  			}

  			_rhp_ikev1_send_mesg(vpn,ikesa,tx_ikemesg,RHP_IKEV1_MESG_HANDLER_END,RHP_IKEV1_MESG_HANDLER_END,1);

				if( tx_ikemesg->tx_pkt &&
						tx_ikemesg->v1_set_retrans_resp &&
						pkt->ikev1_pkt_hash ){

					tx_ikemesg->tx_pkt->ikev1_pkt_hash = pkt->ikev1_pkt_hash;
					tx_ikemesg->tx_pkt->ikev1_pkt_hash_len = pkt->ikev1_pkt_hash_len;

					pkt->ikev1_pkt_hash = NULL;
					pkt->ikev1_pkt_hash_len = 0;

					ikesa->set_retrans_reply(ikesa,tx_ikemesg->tx_pkt);
				}

				if( do_destroy_vpn ){

					rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_DELETE_WAIT);
					ikesa->timers->schedule_delete(vpn,ikesa,0);

				}else{

					if( rx_ikemesg->v1_sa_b ){

						if( ikesa->side == RHP_IKE_RESPONDER ){

							int sa_b_len = ntohs(rx_ikemesg->v1_sa_b->len) - 4;

							if( ikesa->v1.sai_b ){
								_rhp_free(ikesa->v1.sai_b);
								ikesa->v1.sai_b_len = 0;
							}

							ikesa->v1.sai_b = (u8*)_rhp_malloc(sa_b_len);
							if( ikesa->v1.sai_b == NULL ){
								RHP_BUG("");
								err = -ENOMEM;
								goto error;
							}

							memcpy(ikesa->v1.sai_b,((u8*)rx_ikemesg->v1_sa_b) + 4,sa_b_len);
							ikesa->v1.sai_b_len = sa_b_len;
						}
					}
				}

  		}else{
  			RHP_BUG("");
  		}
    }
	}


end:
pending:
  if( vpn ){

  	RHP_UNLOCK(&(vpn->lock));

  	if( vpn->v1.merge_larval_vpn ){

  		rhp_ikev1_merge_larval_vpn(vpn);
  	}

    rhp_vpn_unhold(vpn_ref);
  }

  if( rx_ikemesg ){
    rhp_ikev2_unhold_mesg(rx_ikemesg);
  }

  if( tx_ikemesg ){
    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_RECV_IMPL_RTRN,"xxx",pkt,vpn,vpn_ref);
  return 0;


error_l:
  if( vpn ){
    RHP_UNLOCK(&(vpn->lock));
  }

error:
	if( err ){

		if( addr_family == AF_INET ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV2_IPV4_RX_ERR,"V44WWGGLUUddE",vpn,(pkt && pkt->l3.raw ? pkt->l3.iph_v4->src_addr : 0),(pkt && pkt->l3.raw ? pkt->l3.iph_v4->dst_addr : 0),(pkt && pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt && pkt->l4.raw ? pkt->l4.udph->dst_port : 0),(pkt && pkt->app.ikeh ? pkt->app.ikeh->init_spi : NULL),(pkt && pkt->app.ikeh ? pkt->app.ikeh->resp_spi : NULL),"PROTO_IKE_EXCHG",(int)(pkt && pkt->app.ikeh ? pkt->app.ikeh->exchange_type : 0),(pkt && pkt->app.ikeh ? pkt->app.ikeh->message_id : 0),(pkt && pkt->app.ikeh ? pkt->app.ikeh->len : 0),(pkt && pkt->app.ikeh ? RHP_PROTO_IKE_HDR_INITIATOR(pkt->app.ikeh->flag) : -1),(pkt && pkt->app.ikeh ? RHP_PROTO_IKE_HDR_RESPONSE(pkt->app.ikeh->flag) : -1),err);
		}else if( addr_family == AF_INET6 ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_IKEV2_IPV6_RX_ERR,"V66WWGGLUUddE",vpn,(pkt && pkt->l3.raw ? pkt->l3.iph_v6->src_addr : NULL),(pkt && pkt->l3.raw ? pkt->l3.iph_v6->dst_addr : NULL),(pkt && pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt && pkt->l4.raw ? pkt->l4.udph->dst_port : 0),(pkt && pkt->app.ikeh ? pkt->app.ikeh->init_spi : NULL),(pkt && pkt->app.ikeh ? pkt->app.ikeh->resp_spi : NULL),"PROTO_IKE_EXCHG",(int)(pkt && pkt->app.ikeh ? pkt->app.ikeh->exchange_type : 0),(pkt && pkt->app.ikeh ? pkt->app.ikeh->message_id : 0),(pkt && pkt->app.ikeh ? pkt->app.ikeh->len : 0),(pkt && pkt->app.ikeh ? RHP_PROTO_IKE_HDR_INITIATOR(pkt->app.ikeh->flag) : -1),(pkt && pkt->app.ikeh ? RHP_PROTO_IKE_HDR_RESPONSE(pkt->app.ikeh->flag) : -1),err);
		}

		rhp_ikev2_g_statistics_inc(rx_ikev1_err_packets);
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

	RHP_TRC(0,RHPTRCID_IKEV1_RECV_IPV4_ERR,"xxxE",pkt,vpn,vpn_ref,err);
  return 0;
}

int rhp_ikev1_recv_ipv4(rhp_packet* pkt)
{
	return rhp_ikev1_recv_impl(AF_INET,pkt);
}

int rhp_ikev1_recv_ipv6(rhp_packet* pkt)
{
	return rhp_ikev1_recv_impl(AF_INET6,pkt);
}


int rhp_ikev1_p1_prf_alg(int ikev1_hash_alg)
{
	switch( ikev1_hash_alg ){

	case RHP_PROTO_IKEV1_P1_ATTR_HASH_MD5:
		return RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_MD5;

	case RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA1:
		return RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA1;

	case RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA2_256:
		return RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_256;

	case RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA2_384:
		return RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_384;

	case RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA2_512:
		return RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_512;

	default:
		RHP_BUG("%d",ikev1_hash_alg);
		break;
	}

	return -1;
}

int rhp_ikev1_p1_encr_alg(int ikev1_alg)
{
	switch( ikev1_alg ){

	case RHP_PROTO_IKEV1_P1_ATTR_ENC_AES_CBC:

		return RHP_PROTO_IKE_TRANSFORM_ID_ENCR_AES_CBC;

	case RHP_PROTO_IKEV1_P1_ATTR_ENC_3DES_CBC:

		return RHP_PROTO_IKE_TRANSFORM_ID_ENCR_3DES;
	}

	RHP_BUG("%d",ikev1_alg);
	return -1;
}

int rhp_ikev1_p2_encr_alg(int ikev1_trans_id)
{
	switch( ikev1_trans_id ){

	case RHP_PROTO_IKEV1_TF_ESP_AES_CBC:

		return RHP_PROTO_IKE_TRANSFORM_ID_ENCR_AES_CBC;

	case RHP_PROTO_IKEV1_TF_ESP_3DES:

		return RHP_PROTO_IKE_TRANSFORM_ID_ENCR_3DES;
	}

	RHP_BUG("%d",ikev1_trans_id);
	return -1;
}

int rhp_ikev1_p2_integ_alg(int ikev1_auth_alg)
{

	switch( ikev1_auth_alg ){

	case RHP_PROTO_IKEV1_P2_ATTR_AUTH_HMAC_MD5:

		return RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_MD5_96;

	case RHP_PROTO_IKEV1_P2_ATTR_AUTH_HMAC_SHA1:

		return RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA1_96;

	case RHP_PROTO_IKEV1_P2_ATTR_AUTH_HMAC_SHA2_256:

		return RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_256_128;

	case RHP_PROTO_IKEV1_P2_ATTR_AUTH_HMAC_SHA2_384:

		return RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_384_192;

	case RHP_PROTO_IKEV1_P2_ATTR_AUTH_HMAC_SHA2_512:

		return RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_512_256;
	}

	RHP_BUG("%d",ikev1_auth_alg);
	return -1;
}


int rhp_ikev1_id_type(int ikev2_id_type)
{
	switch( ikev2_id_type ){

	case RHP_PROTO_IKE_ID_ANY:

		return RHP_PROTO_IKE_ID_ANY;

	case RHP_PROTO_IKE_ID_IPV4_ADDR:

		return RHP_PROTO_IKEV1_ID_IPV4_ADDR;

	case RHP_PROTO_IKEV1_ID_FQDN:

		return RHP_PROTO_IKEV1_ID_FQDN;

	case RHP_PROTO_IKE_ID_RFC822_ADDR:

		return RHP_PROTO_IKEV1_ID_USER_FQDN;

	case RHP_PROTO_IKE_ID_IPV6_ADDR:

		return RHP_PROTO_IKEV1_ID_IPV6_ADDR;

	case RHP_PROTO_IKE_ID_DER_ASN1_DN:

		return RHP_PROTO_IKEV1_ID_DER_ASN1_DN;
	}

	RHP_BUG("%d",ikev2_id_type);
	return -1;
}

int rhp_ikev1_connect_i_try_secondary(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_vpn_realm* rlm,
		rhp_ip_addr* secondary_peer_addr,rhp_cfg_if* cfg_if,rhp_ikev2_mesg** new_1st_mesg_r)
{
  int err = -EINVAL;
  rhp_ikev2_mesg *old_1st_mesg,*new_1st_mesg = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_CONNECT_I_TRY_SECONDARY,"xxxxxdd",vpn,ikesa,rlm,secondary_peer_addr,cfg_if,vpn->sess_resume.gen_by_sess_resume,ikesa->gen_by_sess_resume);
  if( secondary_peer_addr ){
  	rhp_ip_addr_dump("rhp_ikev1_connect_i_try_secondary:secondary_peer_addr",secondary_peer_addr);
  }
  if( cfg_if ){
    RHP_TRC(0,RHPTRCID_IKEV1_CONNECT_I_TRY_SECONDARY_CFG_IF_NAME,"xxs",vpn,cfg_if,cfg_if->if_name);
  }

  if( secondary_peer_addr == NULL && cfg_if == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }


	if( ikesa->req_retx_ikemesg ){

		ikesa->set_retrans_request(ikesa,NULL);

		rhp_ikev2_unhold_mesg(ikesa->req_retx_ikemesg);
		ikesa->req_retx_ikemesg = NULL;
	}


  if( secondary_peer_addr ){

  	vpn->set_peer_addr(vpn,secondary_peer_addr,secondary_peer_addr);
  }

  if( cfg_if ){

  	if( cfg_if->ifc == NULL ){
  		RHP_BUG("");
  		err = -EINVAL;
  		goto error;
  	}

  	RHP_LOCK(&(cfg_if->ifc->lock));
  	{
  		rhp_ifc_addr* ifc_addr;

  		ifc_addr = cfg_if->ifc->select_src_addr(cfg_if->ifc,
  								vpn->peer_addr.addr_family,vpn->peer_addr.addr.raw,cfg_if->is_by_def_route);

  		if( ifc_addr == NULL ){
  	  	RHP_UNLOCK(&(cfg_if->ifc->lock));
  			err = -ENOENT;
  			goto error;
  		}

  		vpn->set_local_net_info(vpn,cfg_if->ifc,ifc_addr->addr.addr_family,ifc_addr->addr.addr.raw);
  	}
  	RHP_UNLOCK(&(cfg_if->ifc->lock));
  }

  {
		if( ikesa->v1.p1_exchange_mode == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ){

			new_1st_mesg = rhp_ikev1_new_pkt_main_i_1(ikesa);

		}else if( ikesa->v1.p1_exchange_mode == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){

			new_1st_mesg = rhp_ikev1_new_pkt_aggressive_i_1(vpn,ikesa,rlm);

		}else{
			RHP_BUG("%d",ikesa->v1.p1_exchange_mode);
		}
		if( new_1st_mesg == NULL ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}
  }

  ikesa->req_message_id = (u32)-1;


  *new_1st_mesg_r = new_1st_mesg;


  if( vpn->peer_addr.addr_family == AF_INET ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKEV1_TRY_SECONDARY_ROUTE,"4Ws",vpn->peer_addr.addr.v4,vpn->peer_addr.port,vpn->local.if_info.if_name);
  }else if( vpn->peer_addr.addr_family == AF_INET6 ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKEV1_TRY_SECONDARY_ROUTE_V6,"6Ws",vpn->peer_addr.addr.v6,vpn->peer_addr.port,vpn->local.if_info.if_name);
  }
  RHP_TRC(0,RHPTRCID_IKEV1_CONNECT_I_TRY_SECONDARY_RTRN,"xxxx",vpn,ikesa,secondary_peer_addr,cfg_if);
  return 0;

error:
  if( new_1st_mesg ){
    rhp_ikev2_unhold_mesg(new_1st_mesg);
  }

  if( vpn->peer_addr.addr_family == AF_INET ){
  	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKEV1_TRY_SECONDARY_ROUTE_ERR,"4Ws",vpn->peer_addr.addr.v4,vpn->peer_addr.port,vpn->local.if_info.if_name);
  }else if( vpn->peer_addr.addr_family == AF_INET6 ){
  	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKEV1_TRY_SECONDARY_ROUTE_V6_ERR,"6Ws",vpn->peer_addr.addr.v6,vpn->peer_addr.port,vpn->local.if_info.if_name);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_CONNECT_I_TRY_SECONDARY_ERR,"xxxxE",vpn,ikesa,secondary_peer_addr,cfg_if,err);
  return err;
}


u8* rhp_ikev1_mesg_gen_iv(rhp_ikesa* ikesa,u32 mesg_id,int* iv_len_r)
{
	int err = -EINVAL;
	rhp_crypto_hash* v1_hash = NULL;
	int iv_len, iv_hash_len, iv_mat_len = 0;
	u8* iv_mat = NULL, *iv = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_MESG_GEN_IV,"xKp",ikesa,mesg_id,ikesa->v1.p2_iv_material_len,ikesa->v1.p2_iv_material);

	iv_len = ikesa->keys.v1.iv_len;

	if( ikesa->v1.p2_iv_material == NULL || ikesa->v1.p2_iv_material_len < iv_len ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	v1_hash = rhp_crypto_hash_alloc(ikesa->prop.v1.hash_alg);
	if( v1_hash == NULL ){
		RHP_BUG("%d",ikesa->prop.v1.hash_alg);
		goto error;
	}

	iv_hash_len = v1_hash->get_output_len(v1_hash);
	if( iv_len > iv_hash_len ){
		RHP_BUG("%d,%d",ikesa->prop.v1.hash_alg,iv_len);
		goto error;
	}

	iv_mat_len = iv_len + sizeof(u32);
	iv_mat = (u8*)_rhp_malloc(iv_mat_len);
	if( iv_mat == NULL ){
		RHP_BUG("");
		goto error;
	}
	memcpy(iv_mat,ikesa->v1.p2_iv_material,iv_len);
	*((u32*)(iv_mat + iv_len)) = mesg_id;


	iv = (u8*)_rhp_malloc(iv_hash_len);
	if( iv == NULL ){
		RHP_BUG("");
		goto error;
	}

	err = v1_hash->compute(v1_hash,iv_mat,iv_mat_len,
					iv,iv_hash_len);
	if( err ){
		goto error;
	}

	rhp_crypto_hash_free(v1_hash);
	_rhp_free(iv_mat);

	*iv_len_r = iv_len;

  RHP_TRC(0,RHPTRCID_IKEV1_MESG_GEN_IV_RTRN,"xKp",ikesa,mesg_id,iv_len,iv);
	return iv;

error:
	if( v1_hash ){
		rhp_crypto_hash_free(v1_hash);
	}
	if( iv_mat ){
		_rhp_free(iv_mat);
	}
	if( iv ){
		_rhp_free(iv);
	}
  RHP_TRC(0,RHPTRCID_IKEV1_MESG_GEN_IV_ERR,"xK",ikesa,mesg_id);
	return NULL;
}


rhp_ikev1_p2_session* rhp_ikev1_p2_session_alloc(u8 clear_aftr_proc)
{
	rhp_ikev1_p2_session* p2_sess = (rhp_ikev1_p2_session*)_rhp_malloc(sizeof(rhp_ikev1_p2_session));
	if( p2_sess == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(p2_sess,0,sizeof(rhp_ikev1_p2_session));
	p2_sess->clear_aftr_proc = clear_aftr_proc;

  RHP_TRC(0,RHPTRCID_IKEV1_P2_SESSION_ALLOC,"xd",p2_sess,p2_sess->clear_aftr_proc);
	return p2_sess;
}

void rhp_ikev1_p2_session_free(rhp_ikev1_p2_session* p2_sess)
{
	if( p2_sess ){

	  RHP_TRC(0,RHPTRCID_IKEV1_P2_SESSION_FREE,"xkbxx",p2_sess,p2_sess->mesg_id,p2_sess->exchange_type,p2_sess->dec_iv,p2_sess->iv_last_rx_blk);

		if( p2_sess->dec_iv ){
			_rhp_free(p2_sess->dec_iv);
		}

		if( p2_sess->iv_last_rx_blk ){
			_rhp_free(p2_sess->iv_last_rx_blk);
		}

		_rhp_free(p2_sess);
	}

  RHP_TRC(0,RHPTRCID_IKEV1_P2_SESSION_FREE_RTRN,"x",p2_sess);
	return;
}

rhp_ikev1_p2_session* rhp_ikev1_p2_session_get(rhp_ikesa* ikesa,u32 mesg_id,u8 exchange_type)
{
	rhp_ikev1_p2_session* p2_sess = ikesa->v1.p2_sessions;

	while( p2_sess ){

		RHP_TRC(0,RHPTRCID_IKEV1_P2_SESSION_GET_P2_SESS,"xxkkbb",ikesa,p2_sess,mesg_id,p2_sess->mesg_id,exchange_type,p2_sess->exchange_type);

		if( p2_sess->exchange_type == exchange_type &&
				p2_sess->mesg_id == mesg_id ){
			break;
		}

		p2_sess = p2_sess->next;
	}

	if( p2_sess ){
		RHP_TRC(0,RHPTRCID_IKEV1_P2_SESSION_GET,"xxkb",ikesa,p2_sess,p2_sess->mesg_id,p2_sess->exchange_type);
	}else{
		RHP_TRC(0,RHPTRCID_IKEV1_P2_SESSION_GET_NOENT,"xkb",ikesa,p2_sess,mesg_id,exchange_type);
	}
	return p2_sess;
}

int rhp_ikev1_p2_session_tx_put(rhp_ikesa* ikesa,u32 mesg_id,u8 exchange_type,u32 dpd_seq,u8 clear_aftr_proc)
{
	int err = -EINVAL;
  rhp_ikev1_p2_session* p2_sess = NULL;

	RHP_TRC(0,RHPTRCID_IKEV1_P2_SESSION_TX_PUT,"xkbbj",ikesa,mesg_id,exchange_type,clear_aftr_proc,dpd_seq);

	p2_sess = rhp_ikev1_p2_session_alloc(clear_aftr_proc);
	if( p2_sess == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	p2_sess->mesg_id = mesg_id;
	p2_sess->exchange_type = exchange_type;

	p2_sess->iv_last_rx_blk
		= rhp_ikev1_mesg_gen_iv(ikesa,htonl(p2_sess->mesg_id),&(p2_sess->iv_len));
	if( p2_sess->iv_last_rx_blk == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	p2_sess->dec_iv = (u8*)_rhp_malloc(p2_sess->iv_len);
	if( p2_sess->dec_iv == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	memset(p2_sess->dec_iv,0,p2_sess->iv_len);

	p2_sess->dpd_seq = dpd_seq;

	p2_sess->next = ikesa->v1.p2_sessions;
	ikesa->v1.p2_sessions = p2_sess;

	RHP_TRC(0,RHPTRCID_IKEV1_P2_SESSION_TX_PUT_RTRN,"xxkb",ikesa,p2_sess,p2_sess->mesg_id,p2_sess->exchange_type);
	return 0;

error:
	if( p2_sess ){
		rhp_ikev1_p2_session_free(p2_sess);
	}
	RHP_TRC(0,RHPTRCID_IKEV1_P2_SESSION_TX_PUT_ERR,"xkbE",ikesa,mesg_id,exchange_type,err);
	return err;
}

int rhp_ikev1_p2_session_rx_put(rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_ikemesg,u8 clear_aftr_proc)
{
	int err = -EINVAL;
  rhp_ikev1_p2_session* p2_sess = NULL;

	RHP_TRC(0,RHPTRCID_IKEV1_P2_SESSION_RX_PUT,"xxkbb",ikesa,rx_ikemesg,rx_ikemesg->get_mesg_id(rx_ikemesg),rx_ikemesg->get_exchange_type(rx_ikemesg),clear_aftr_proc);

  p2_sess = rhp_ikev1_p2_session_alloc(clear_aftr_proc);
	if( p2_sess == NULL ){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}

	if( ikesa->keys.v1.iv_len != rx_ikemesg->v1_p2_iv_len ){
		RHP_BUG("%d,%d",ikesa->keys.v1.iv_len,rx_ikemesg->v1_p2_iv_len);
		err = -EINVAL;
		goto error;
	}

	p2_sess->mesg_id = rx_ikemesg->get_mesg_id(rx_ikemesg);
	p2_sess->exchange_type = rx_ikemesg->get_exchange_type(rx_ikemesg);

	p2_sess->iv_len = rx_ikemesg->v1_p2_iv_len;
	p2_sess->iv_last_rx_blk = rx_ikemesg->v1_p2_rx_last_blk;
	rx_ikemesg->v1_p2_rx_last_blk = NULL;
	rx_ikemesg->v1_p2_iv_len = 0;

	p2_sess->dec_iv = (u8*)_rhp_malloc(ikesa->keys.v1.iv_len);
	if( p2_sess->dec_iv == NULL ){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	memset(p2_sess->dec_iv,0,ikesa->keys.v1.iv_len);

	p2_sess->next = ikesa->v1.p2_sessions;
	ikesa->v1.p2_sessions = p2_sess;

	RHP_TRC(0,RHPTRCID_IKEV1_P2_SESSION_RX_PUT_RTRN,"xxxkb",ikesa,rx_ikemesg,p2_sess,p2_sess->mesg_id,p2_sess->exchange_type);
	return 0;

error:
	if( p2_sess ){
		rhp_ikev1_p2_session_free(p2_sess);
	}
	RHP_TRC(0,RHPTRCID_IKEV1_P2_SESSION_RX_PUT_ERR,"xxE",ikesa,rx_ikemesg,err);
	return err;
}

int rhp_ikev1_p2_session_clear(rhp_ikesa* ikesa,u32 mesg_id,u8 exchange_type,u32 dpd_seq)
{
	rhp_ikev1_p2_session *p2_sess = ikesa->v1.p2_sessions, *p2_sess_p = NULL;

	while( p2_sess ){

		RHP_TRC(0,RHPTRCID_IKEV1_P2_SESSION_CLEAR_P2_SESS,"xxkkbbj",ikesa,p2_sess,mesg_id,p2_sess->mesg_id,exchange_type,p2_sess->exchange_type,p2_sess->dpd_seq);

		if( p2_sess->exchange_type == exchange_type &&
				(p2_sess->mesg_id == mesg_id || p2_sess->dpd_seq == dpd_seq) ){
			break;
		}

		p2_sess_p = p2_sess;
		p2_sess = p2_sess->next;
	}

	if( p2_sess == NULL ){
		RHP_TRC(0,RHPTRCID_IKEV1_P2_SESSION_CLEAR_NOENT,"xkb",ikesa,mesg_id,exchange_type);
		return -ENOENT;
	}

	if( p2_sess_p ){
		p2_sess_p->next = p2_sess->next;
	}else{
		ikesa->v1.p2_sessions = p2_sess->next;
	}

	RHP_TRC(0,RHPTRCID_IKEV1_P2_SESSION_CLEAR,"xxkbj",ikesa,p2_sess,mesg_id,exchange_type,dpd_seq);
	return 0;
}


int rhp_ikev1_tx_info_mesg_hash_add(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* tx_ikemesg,
		int (*enum_pld_cb)(rhp_ikev2_mesg* ikemesg,int enum_end,rhp_ikev2_payload* payload,void* pkt_for_hash_c))
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;
  rhp_packet* pkt_for_hash = NULL;
  int hash_octets_len = 0;
  u8* hash_octets = NULL;
	int buf_offset, buf_len, org_tx_len = tx_ikemesg->tx_mesg_len;
	u8* buf;
  u32 tx_mesg_id = tx_ikemesg->get_mesg_id(tx_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV1_TX_INFO_MESG_HASH_ADD,"xxxk",vpn,ikesa,tx_ikemesg,tx_mesg_id);

  if( ikesa == NULL ){

  	ikesa = rhp_ikev1_tx_get_established_ikesa(vpn);
  }

  if( ikesa == NULL ){
  	err = -ENOENT;
  	goto error;
  }


	pkt_for_hash = rhp_pkt_alloc(RHP_PKT_IKE_DEFAULT_SIZE);
	if( pkt_for_hash == NULL ){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}

	buf = _rhp_pkt_push(pkt_for_hash,sizeof(u32));
	buf_offset = buf - pkt_for_hash->head;
	*((u32*)buf) = htonl(tx_mesg_id);

	err = tx_ikemesg->search_payloads(tx_ikemesg,0,NULL,NULL,
					enum_pld_cb,pkt_for_hash);
	if( err && err != -ENOENT && err != RHP_STATUS_ENUM_OK  ){
		RHP_BUG("");
		goto error;
	}
	err = 0;

	buf = pkt_for_hash->head + buf_offset;
	buf_len = pkt_for_hash->tail - buf;


	hash_octets_len = ikesa->prf->get_output_len(ikesa->prf);

  hash_octets = (u8*)_rhp_malloc(hash_octets_len);
  if( hash_octets == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV1_TX_INFO_MESG_HASH_ADD_DATA,"xxxpp",vpn,ikesa,tx_ikemesg,ikesa->keys.v1.skeyid_a_len,ikesa->keys.v1.skeyid_a,buf_len,buf);

  if( ikesa->prf->set_key(ikesa->prf,ikesa->keys.v1.skeyid_a,ikesa->keys.v1.skeyid_a_len) ){
    RHP_TRC(0,RHPTRCID_IKEV1_TX_INFO_MESG_HASH_ADD_PRF_SET_KEY_ERR,"xx",ikesa,ikesa->prf);
    goto error;
  }

  if( ikesa->prf->compute(ikesa->prf,buf,buf_len,hash_octets,hash_octets_len) ){
    RHP_TRC(0,RHPTRCID_IKEV1_TX_INFO_MESG_HASH_ADD_PRF_COMPUTE_ERR,"xx",ikesa,ikesa->prf);
    goto error;
  }

  if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_HASH,&ikepayload) ){
    RHP_BUG("");
    goto error;
  }

  tx_ikemesg->put_payload_head(tx_ikemesg,ikepayload);

  if( ikepayload->ext.v1_hash->set_hash(ikepayload,hash_octets_len,hash_octets) ){
    RHP_BUG("");
    goto error;
  }

  tx_ikemesg->tx_mesg_len = org_tx_len;

	rhp_pkt_unhold(pkt_for_hash);
	_rhp_free(hash_octets);

  RHP_TRC(0,RHPTRCID_IKEV1_TX_INFO_MESG_HASH_ADD_RTRN,"xxxk",vpn,ikesa,tx_ikemesg,tx_mesg_id);
	return 0;

error:
	if( pkt_for_hash ){
		rhp_pkt_unhold(pkt_for_hash);
	}
	if( hash_octets ){
		_rhp_free(hash_octets);
	}
  RHP_TRC(0,RHPTRCID_IKEV1_TX_INFO_MESG_HASH_ADD_ERR,"xxxkE",vpn,ikesa,tx_ikemesg,tx_mesg_id,err);
	return err;
}

struct _rhp_ikev1_hash_pld_buf {

	rhp_ikev2_payload* v1_hash_payload;

	u8 pld_id;
	u8 reserved0;
	u16 reserved1;

	rhp_ikev2_payload* v1_payload;
};
typedef struct _rhp_ikev1_hash_pld_buf	rhp_ikev1_hash_pld_buf;

static int _rhp_ikev1_hash_pld_srch_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	rhp_ikev1_hash_pld_buf* hash_buf = (rhp_ikev1_hash_pld_buf*)ctx;
	u8 pld_id = payload->get_payload_id(payload);

  if( payload->payloadh == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

	if( pld_id == RHP_PROTO_IKEV1_PAYLOAD_HASH ){

		hash_buf->v1_hash_payload = payload;

	}else if( pld_id == hash_buf->pld_id ){

		hash_buf->v1_payload = payload;
	}

	return 0;
}

static int _rhp_ikev1_rx_hash_pld_verify(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev1_hash_pld_buf* hash_buf)
{
	int err = -EINVAL;
	int mat_len;
	u8* mat_buf = NULL;
  int rx_hash_len, hash_octets_len;
  u8 *rx_hash, *hash_octets = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_HASH_PLD_VERIFY,"xxxxxxx",vpn,ikesa,rx_ikemesg,hash_buf,hash_buf->v1_payload,hash_buf->v1_hash_payload,ikesa->prf);

	hash_octets_len = ikesa->prf->get_output_len(ikesa->prf);

  rx_hash_len = hash_buf->v1_hash_payload->ext.v1_hash->get_hash_len(hash_buf->v1_hash_payload);
  rx_hash = hash_buf->v1_hash_payload->ext.v1_hash->get_hash(hash_buf->v1_hash_payload);

  if( rx_hash_len != hash_octets_len ||
  		rx_hash == NULL ){
  	err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV1_RX_HASH_PLD_VERIFY_NO_HASH_VAL,"xxxddx",vpn,ikesa,rx_ikemesg,rx_hash_len,hash_octets_len,rx_hash);
    goto error;
  }


	{
		int pld_len = ntohs(hash_buf->v1_payload->payloadh->len);

		mat_len = sizeof(u32) + pld_len;

		mat_buf = (u8*)_rhp_malloc(mat_len);
		if( mat_buf == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		*((u32*)mat_buf) = htonl(rx_ikemesg->get_mesg_id(rx_ikemesg));
		memcpy((mat_buf + sizeof(u32)),hash_buf->v1_payload->payloadh,pld_len);
	}


  hash_octets = (u8*)_rhp_malloc(hash_octets_len);
  if( hash_octets == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

  if( ikesa->prf->set_key(ikesa->prf,
  			ikesa->keys.v1.skeyid_a,ikesa->keys.v1.skeyid_a_len) ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_HASH_PLD_VERIFY_PRF_SET_KEY_ERR,"xxx",vpn,ikesa,ikesa->prf);
    err = -EINVAL;
    goto error;
  }

  if( ikesa->prf->compute(ikesa->prf,mat_buf,mat_len,hash_octets,hash_octets_len) ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_HASH_PLD_VERIFY_PRF_COMPUTE_ERR,"xxx",vpn,ikesa,ikesa->prf);
    err = -EINVAL;
    goto error;
  }

	RHP_TRC(0,RHPTRCID_IKEV1_RX_HASH_PLD_VERIFY_BUF_DATA,"xxxppp",vpn,ikesa,rx_ikemesg,mat_len,mat_buf,hash_octets_len,hash_octets,ikesa->keys.v1.skeyid_a_len,ikesa->keys.v1.skeyid_a);

  if( memcmp(rx_hash,hash_octets,hash_octets_len) ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_HASH_PLD_VERIFY_NOT_MACHED,"xxxpp",vpn,ikesa,rx_ikemesg,rx_hash_len,rx_hash,hash_octets_len,hash_octets);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

	_rhp_free(mat_buf);
	_rhp_free(hash_octets);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_HASH_PLD_VERIFY_RTRN,"xxx",vpn,ikesa,rx_ikemesg);
	return 0;

error:
	if( mat_buf ){
		_rhp_free(mat_buf);
	}
	if( hash_octets ){
		_rhp_free(hash_octets);
	}
  RHP_TRC(0,RHPTRCID_IKEV1_RX_HASH_PLD_VERIFY_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);
	return err;
}

int rhp_ikev1_rx_info_mesg_hash_verify(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_ikemesg,
		u8 pld_id)
{
	int err = -EINVAL;
	rhp_ikev1_hash_pld_buf hash_buf;

	RHP_TRC(0,RHPTRCID_IKEV1_RX_INFO_MESG_HASH_VERIFY,"xxxb",vpn,ikesa,rx_ikemesg,pld_id);

	memset(&hash_buf,0,sizeof(rhp_ikev1_hash_pld_buf));

	hash_buf.pld_id = pld_id;

	err = rx_ikemesg->search_payloads(rx_ikemesg,0,NULL,NULL,
			_rhp_ikev1_hash_pld_srch_cb,&hash_buf);

	if( err && err != RHP_STATUS_ENUM_OK ){

		RHP_TRC(0,RHPTRCID_IKEV1_RX_INFO_MESG_HASH_VERIFY_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);

 		err = RHP_STATUS_INVALID_MSG;
  	goto error;
	}

	if( hash_buf.v1_payload == NULL || hash_buf.v1_hash_payload == NULL ){

		RHP_TRC(0,RHPTRCID_IKEV1_RX_INFO_MESG_HASH_VERIFY_ERR_2,"xxxxx",vpn,ikesa,rx_ikemesg,hash_buf.v1_payload,hash_buf.v1_hash_payload);

		err = RHP_STATUS_INVALID_MSG;
  	goto error;
	}

	err = _rhp_ikev1_rx_hash_pld_verify(vpn,ikesa,rx_ikemesg,&hash_buf);
	if( err ){
  	goto error;
	}

	err = 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV1_RX_INFO_MESG_HASH_VERIFY_RTRN,"xxxE",vpn,ikesa,rx_ikemesg,err);
	return err;
}

int rhp_ikev1_gen_rsasig_skeyid(rhp_vpn* vpn,rhp_ikesa* ikesa,
		u8** skeyid_r,int* skeyid_len_r)
{
	int err = -EINVAL;
	u8* skeyid_key = NULL, *skeyid_octets = NULL;
	int skeyid_key_len = 0, skeyid_octets_len = 0;
	u8 *dh_shared_key, *ni_b, *nr_b;
	int dh_shared_key_len, ni_b_len, nr_b_len;

	RHP_TRC(0,RHPTRCID_IKEV1_GEN_RSASIG_SKEYID,"xxxx",vpn,ikesa,skeyid_r,skeyid_len_r);

	dh_shared_key = ikesa->dh->get_shared_key(ikesa->dh,&dh_shared_key_len);
	if( dh_shared_key == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	ni_b_len = ikesa->nonce_i->get_nonce_len(ikesa->nonce_i);
	ni_b = ikesa->nonce_i->get_nonce(ikesa->nonce_i);
	if( ni_b_len < 1 || ni_b == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	nr_b_len = ikesa->nonce_r->get_nonce_len(ikesa->nonce_r);
	nr_b = ikesa->nonce_r->get_nonce(ikesa->nonce_r);
	if( nr_b_len < 1 || nr_b == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}


	skeyid_key_len = ni_b_len + nr_b_len;

	skeyid_key = (u8*)_rhp_malloc(skeyid_key_len);
	if( skeyid_key == NULL ){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}

	memcpy(skeyid_key,ni_b,ni_b_len);
	memcpy((skeyid_key + ni_b_len),nr_b,nr_b_len);


  if( ikesa->prf->set_key(ikesa->prf,skeyid_key,skeyid_key_len) ){
  	err = -EINVAL;
    goto error;
  }

  skeyid_octets_len = ikesa->prf->get_output_len(ikesa->prf);

  skeyid_octets = (u8*)_rhp_malloc(skeyid_octets_len);
  if( skeyid_octets == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

  if( ikesa->prf->compute(ikesa->prf,dh_shared_key,dh_shared_key_len,
  			skeyid_octets,skeyid_octets_len) ){
  	err = -EINVAL;
    goto error;
  }

	_rhp_free_zero(skeyid_key,skeyid_key_len);

	*skeyid_r = skeyid_octets;
	*skeyid_len_r = skeyid_octets_len;

	RHP_TRC(0,RHPTRCID_IKEV1_GEN_RSASIG_SKEYID_RTRN,"xxp",vpn,ikesa,*skeyid_len_r,*skeyid_r);
  return 0;

error:
	if( skeyid_key ){
		_rhp_free_zero(skeyid_key,skeyid_key_len);
	}
	if( skeyid_octets ){
		_rhp_free_zero(skeyid_octets,skeyid_octets_len);
	}
	RHP_TRC(0,RHPTRCID_IKEV1_GEN_RSASIG_SKEYID_ERR,"xxE",vpn,ikesa,err);
	return err;
}

int rhp_ikev1_gen_psk_skeyid_material(rhp_vpn* vpn,rhp_ikesa* ikesa,
		u8** skeyid_mat_r,int* skeyid_mat_len_r)
{
	int err = -EINVAL;
	int ni_b_len = 0, nr_b_len = 0;
	u8 *ni_b = NULL, *nr_b = NULL;
	u8* skeyid_mat = NULL;
	int skeyid_mat_len = 0;

	RHP_TRC(0,RHPTRCID_IKEV1_GEN_PSK_SKEYID_MATERIAL,"xxxx",vpn,ikesa,skeyid_mat_len_r,skeyid_mat_r);

	ni_b = ikesa->nonce_i->get_nonce(ikesa->nonce_i);
	nr_b = ikesa->nonce_r->get_nonce(ikesa->nonce_r);
	ni_b_len = ikesa->nonce_i->get_nonce_len(ikesa->nonce_i);
	nr_b_len = ikesa->nonce_r->get_nonce_len(ikesa->nonce_r);

	if( ni_b == NULL || nr_b == NULL || ni_b_len < 1 || nr_b_len < 1 ){
		RHP_BUG("0x%lx, 0x%lx, %d, %d",ni_b,nr_b,ni_b_len,nr_b_len);
		err = -EINVAL;
		goto error;
	}

	skeyid_mat_len = ni_b_len + nr_b_len;

	skeyid_mat = (u8*)_rhp_malloc(skeyid_mat_len);
	if( skeyid_mat == NULL ){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}

	memcpy(skeyid_mat,ni_b,ni_b_len);
	memcpy((skeyid_mat + ni_b_len),nr_b,nr_b_len);


	*skeyid_mat_len_r = skeyid_mat_len;
	*skeyid_mat_r = skeyid_mat;

	RHP_TRC(0,RHPTRCID_IKEV1_GEN_PSK_SKEYID_MATERIAL_RTRN,"xxp",vpn,ikesa,*skeyid_mat_len_r,*skeyid_mat_r);
	return 0;

error:
	if( skeyid_mat ){
		_rhp_free(skeyid_mat);
	}
	RHP_TRC(0,RHPTRCID_IKEV1_GEN_PSK_SKEYID_MATERIAL_ERR,"xxE",vpn,ikesa,err);
	return err;
}

int rhp_ikev1_p1_gen_hash_ir_material_part(
			int for_side,
			rhp_ikesa* ikesa,
			u8** mesg_octets_r,int* mesg_octets_len_r)
{
	int err = -EINVAL;
	u8 *gxi, *gxr, *ckyi, *ckyr, *sai_b;
	int gxi_len, gxr_len;
	int material_len = 0;
	u8 *material = NULL;
	u8* p;

  RHP_TRC(0,RHPTRCID_IKEV1_P1_GEN_HASH_IR_MATERIAL_PART,"dxxx",for_side,ikesa,mesg_octets_r,mesg_octets_len_r);


	sai_b = ikesa->v1.sai_b;
	if( sai_b == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}
	material_len += ikesa->v1.sai_b_len;

	if( ikesa->side == RHP_IKE_INITIATOR ){
		gxi = ikesa->dh->get_my_pub_key(ikesa->dh,&gxi_len);
		gxr = ikesa->dh->get_peer_pub_key(ikesa->dh,&gxr_len);
	}else{ // RESPONDER
		gxi = ikesa->dh->get_peer_pub_key(ikesa->dh,&gxr_len);
		gxr = ikesa->dh->get_my_pub_key(ikesa->dh,&gxi_len);
	}
	if( gxi == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}
	if( gxr == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	material_len += gxi_len;
	material_len += gxr_len;

	ckyi = ikesa->init_spi;
	ckyr = ikesa->resp_spi;
	material_len += RHP_PROTO_IKE_SPI_SIZE*2;

	material = (u8*)_rhp_malloc(material_len);
	if( material == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	p = material;

	if( for_side == RHP_IKE_INITIATOR ){

		memcpy(p,gxi,gxi_len);
		p += gxi_len;
		memcpy(p,gxr,gxr_len);
		p += gxr_len;
		memcpy(p,ckyi,RHP_PROTO_IKE_SPI_SIZE);
		p += RHP_PROTO_IKE_SPI_SIZE;
		memcpy(p,ckyr,RHP_PROTO_IKE_SPI_SIZE);
		p += RHP_PROTO_IKE_SPI_SIZE;
		memcpy(p,sai_b,ikesa->v1.sai_b_len);
		p += ikesa->v1.sai_b_len;

	}else{ // RESPONDER

		memcpy(p,gxr,gxr_len);
		p += gxr_len;
		memcpy(p,gxi,gxi_len);
		p += gxi_len;
		memcpy(p,ckyr,RHP_PROTO_IKE_SPI_SIZE);
		p += RHP_PROTO_IKE_SPI_SIZE;
		memcpy(p,ckyi,RHP_PROTO_IKE_SPI_SIZE);
		p += RHP_PROTO_IKE_SPI_SIZE;
		memcpy(p,sai_b,ikesa->v1.sai_b_len);
		p += ikesa->v1.sai_b_len;
	}

	*mesg_octets_r = material;
	*mesg_octets_len_r = material_len;

  RHP_TRC(0,RHPTRCID_IKEV1_P1_GEN_HASH_IR_MATERIAL_PART_RTRN,"dxp",for_side,ikesa,*mesg_octets_len_r,*mesg_octets_r);
  return 0;

error:
	if( material ){
		_rhp_free(material);
	}
  RHP_TRC(0,RHPTRCID_IKEV1_P1_GEN_HASH_IR_MATERIAL_PART_ERR,"dxE",for_side,ikesa,err);
	return err;
}

int rhp_ikev1_p1_gen_hash_ir(
			int for_side,
			rhp_ikesa* ikesa,
			int idix_b_bin_len,u8* idix_b_bin, // idix_b: idii_b or idir_b
			int idix_b_type,int idix_b_len,u8* idix_b, // idix_b: idii_b or idir_b
			int skeyid_len,u8* skeyid,
			u8** hash_octets_r,int* hash_octets_len_r)
{
	int err = -EINVAL;
	u8 *gxi, *gxr, *ckyi, *ckyr, *sai_b, *idix_b_buf = NULL;
	int gxi_len, gxr_len, idix_b_buf_len;
	int material_len = 0, hash_octets_len = 0;
	u8 *material = NULL, *hash_octets = NULL;
	u8* p;

  RHP_TRC(0,RHPTRCID_IKEV1_P1_GEN_HASH_IR,"dxpdppxx",for_side,ikesa,idix_b_bin_len,idix_b_bin,idix_b_type,idix_b_len,idix_b,skeyid_len,skeyid,hash_octets_r,hash_octets_len_r);

  if( idix_b_bin == NULL ){

		idix_b_buf_len = 4 + idix_b_len;

		idix_b_buf = (u8*)_rhp_malloc(idix_b_buf_len);
		if( idix_b_buf == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
		idix_b_buf[0] = (u8)idix_b_type;
		idix_b_buf[1] = 0;
		idix_b_buf[2] = 0;
		idix_b_buf[3] = 0;
		memcpy(&(idix_b_buf[4]),idix_b,idix_b_len);

		material_len += idix_b_buf_len;

  }else{

  	idix_b_buf_len = idix_b_bin_len;

  	idix_b_buf = idix_b_bin;

  	material_len += idix_b_bin_len;
  }

	sai_b = ikesa->v1.sai_b;
	if( sai_b == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}
	material_len += ikesa->v1.sai_b_len;

	if( ikesa->side == RHP_IKE_INITIATOR ){
		gxi = ikesa->dh->get_my_pub_key(ikesa->dh,&gxi_len);
		gxr = ikesa->dh->get_peer_pub_key(ikesa->dh,&gxr_len);
	}else{ // RESPONDER
		gxi = ikesa->dh->get_peer_pub_key(ikesa->dh,&gxr_len);
		gxr = ikesa->dh->get_my_pub_key(ikesa->dh,&gxi_len);
	}
	if( gxi == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}
	if( gxr == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	material_len += gxi_len;
	material_len += gxr_len;

	ckyi = ikesa->init_spi;
	ckyr = ikesa->resp_spi;
	material_len += RHP_PROTO_IKE_SPI_SIZE*2;

	material = (u8*)_rhp_malloc(material_len);
	if( material == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	p = material;

	if( for_side == RHP_IKE_INITIATOR ){

		memcpy(p,gxi,gxi_len);
		p += gxi_len;
		memcpy(p,gxr,gxr_len);
		p += gxr_len;
		memcpy(p,ckyi,RHP_PROTO_IKE_SPI_SIZE);
		p += RHP_PROTO_IKE_SPI_SIZE;
		memcpy(p,ckyr,RHP_PROTO_IKE_SPI_SIZE);
		p += RHP_PROTO_IKE_SPI_SIZE;
		memcpy(p,sai_b,ikesa->v1.sai_b_len);
		p += ikesa->v1.sai_b_len;
		memcpy(p,idix_b_buf,idix_b_buf_len);
		p += idix_b_buf_len;

	}else{ // RESPONDER

		memcpy(p,gxr,gxr_len);
		p += gxr_len;
		memcpy(p,gxi,gxi_len);
		p += gxi_len;
		memcpy(p,ckyr,RHP_PROTO_IKE_SPI_SIZE);
		p += RHP_PROTO_IKE_SPI_SIZE;
		memcpy(p,ckyi,RHP_PROTO_IKE_SPI_SIZE);
		p += RHP_PROTO_IKE_SPI_SIZE;
		memcpy(p,sai_b,ikesa->v1.sai_b_len);
		p += ikesa->v1.sai_b_len;
		memcpy(p,idix_b_buf,idix_b_buf_len);
		p += idix_b_buf_len;
	}

	hash_octets_len = ikesa->prf->get_output_len(ikesa->prf);

  hash_octets = (u8*)_rhp_malloc(hash_octets_len);
  if( hash_octets == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

  if( ikesa->prf->set_key(ikesa->prf,skeyid,skeyid_len) ){
    RHP_TRC(0,RHPTRCID_IKEV1_P1_GEN_HASH_IR_PRF_SET_KEY_ERR,"xx",ikesa,ikesa->prf);
    goto error;
  }

  if( ikesa->prf->compute(ikesa->prf,material,material_len,hash_octets,hash_octets_len) ){
    RHP_TRC(0,RHPTRCID_IKEV1_P1_GEN_HASH_IR_PRF_COMPUTE_ERR,"xx",ikesa,ikesa->prf);
    goto error;
  }

  if( idix_b_bin == NULL ){
  	_rhp_free(idix_b_buf);
  }
	_rhp_free(material);

	*hash_octets_r = hash_octets;
	*hash_octets_len_r = hash_octets_len;

  RHP_TRC(0,RHPTRCID_IKEV1_P1_GEN_HASH_IR_RTRN,"dxp",for_side,ikesa,hash_octets_len,hash_octets);
  return 0;

error:
	if( idix_b_bin == NULL && idix_b_buf ){
		_rhp_free(idix_b_buf);
	}
	if( material ){
		_rhp_free(material);
	}
	if( hash_octets ){
		_rhp_free(hash_octets);
	}
  RHP_TRC(0,RHPTRCID_IKEV1_P1_GEN_HASH_IR_ERR,"dxE",for_side,ikesa,err);
	return err;
}


int rhp_ikev1_get_my_cert_ca_dn_der(rhp_vpn_realm* rlm,
		u8** my_cert_issuer_dn_der_r,int* my_cert_issuer_dn_der_len_r)
{
	int err = -EINVAL;
	int my_cert_issuer_dn_der_len = 0;
	u8* my_cert_issuer_dn_der = NULL;

	if( rlm->my_auth.my_auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){

		if( rlm->my_auth.untrust_sub_ca_cert_issuer_dn_der ){

			my_cert_issuer_dn_der = (u8*)_rhp_malloc(rlm->my_auth.untrust_sub_ca_cert_issuer_dn_der_len);
			if( my_cert_issuer_dn_der == NULL ){
				RHP_BUG("");
  	  	RHP_UNLOCK(&(rlm->lock));
				err = -ENOMEM;
				goto error;
			}

			memcpy(my_cert_issuer_dn_der,rlm->my_auth.untrust_sub_ca_cert_issuer_dn_der,
					rlm->my_auth.untrust_sub_ca_cert_issuer_dn_der_len);
			my_cert_issuer_dn_der_len = rlm->my_auth.untrust_sub_ca_cert_issuer_dn_der_len;

		}else if( rlm->my_auth.my_cert_issuer_dn_der ){

			my_cert_issuer_dn_der = (u8*)_rhp_malloc(rlm->my_auth.my_cert_issuer_dn_der_len);
			if( my_cert_issuer_dn_der == NULL ){
				RHP_BUG("");
  	  	RHP_UNLOCK(&(rlm->lock));
				err = -ENOMEM;
				goto error;
			}

			memcpy(my_cert_issuer_dn_der,rlm->my_auth.my_cert_issuer_dn_der,
					rlm->my_auth.my_cert_issuer_dn_der_len);
			my_cert_issuer_dn_der_len = rlm->my_auth.my_cert_issuer_dn_der_len;
		}

		*my_cert_issuer_dn_der_r = my_cert_issuer_dn_der;
		*my_cert_issuer_dn_der_len_r = my_cert_issuer_dn_der_len;

		return 0;

	}else{

		return 0;
	}

error:
	return err;
}


rhp_vpn_realm* rhp_ikev1_r_get_def_realm(rhp_ip_addr* rx_addr,rhp_ip_addr* peer_addr)
{
	int err = -EINVAL;
	rhp_vpn_realm* def_rlm = NULL;
	rhp_ikev2_id def_peer_id;
	rhp_vpn_list* vpn_lst_head = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_R_GET_DEF_REALM,"xx",rx_addr,peer_addr);
  rhp_ip_addr_dump("rx_addr",rx_addr);
  rhp_ip_addr_dump("peer_addr",peer_addr);

	memset(&def_peer_id,0,sizeof(rhp_ikev2_id));

	if( rx_addr->addr_family == AF_INET ){

    def_peer_id.type = RHP_PROTO_IKE_ID_IPV4_ADDR;
    memcpy(&(def_peer_id.addr),peer_addr,sizeof(rhp_ip_addr));

	}else if( rx_addr->addr_family == AF_INET6 ){

    def_peer_id.type = RHP_PROTO_IKE_ID_IPV6_ADDR;
    memcpy(&(def_peer_id.addr),peer_addr,sizeof(rhp_ip_addr));

	}else{
		RHP_BUG("%d",rx_addr->addr_family);
		return NULL;
	}


	err = rhp_vpn_get_by_peer_addr_impl(0,peer_addr->addr_family,
					peer_addr->addr.raw,&vpn_lst_head);
	if( !err ){

		rhp_vpn* cur_vpn;
		rhp_vpn_list* vpn_lst = vpn_lst_head;

		while( vpn_lst ){

			cur_vpn = RHP_VPN_REF(vpn_lst->vpn_ref);

			if( cur_vpn->local.if_info.addr_family == rx_addr->addr_family &&
					( rx_addr->addr_family == AF_INET ?
							(cur_vpn->local.if_info.addr.v4 == rx_addr->addr.v4) :
							!memcmp(cur_vpn->local.if_info.addr.v6,rx_addr->addr.v6,16)) ){

				def_rlm = cur_vpn->rlm;
				if( def_rlm ){

					RHP_TRC(0,RHPTRCID_IKEV1_R_GET_DEF_REALM_FOUND,"xxxxu",rx_addr,peer_addr,def_rlm,def_rlm->id,cur_vpn);

					rhp_realm_hold(def_rlm);

					break;

				}else{
				  RHP_TRC(0,RHPTRCID_IKEV1_R_GET_DEF_REALM_NEXT_2,"xxx",rx_addr,peer_addr,cur_vpn);
				}
			}

			if( cur_vpn->local.if_info.addr_family == AF_INET ){
				RHP_TRC(0,RHPTRCID_IKEV1_R_GET_DEF_REALM_NEXT_V4,"xxx44",rx_addr,peer_addr,cur_vpn,cur_vpn->local.if_info.addr.v4,cur_vpn->peer_addr.addr.v4);
			}else if( cur_vpn->local.if_info.addr_family == AF_INET6 ){
				RHP_TRC(0,RHPTRCID_IKEV1_R_GET_DEF_REALM_NEXT_V6,"xxx6",rx_addr,peer_addr,cur_vpn,cur_vpn->local.if_info.addr.v6,cur_vpn->peer_addr.addr.v6);
			}else{
				RHP_TRC(0,RHPTRCID_IKEV1_R_GET_DEF_REALM_NEXT_UNKNOWN_AF,"xxx",rx_addr,peer_addr,cur_vpn);
			}

			vpn_lst = vpn_lst->next;
		}

		rhp_vpn_list_free(vpn_lst_head);
	}


	if( def_rlm == NULL ){

		def_rlm = rhp_realm_get_def_ikev1(&def_peer_id,peer_addr);
	}

  RHP_TRC(0,RHPTRCID_IKEV1_R_GET_DEF_REALM_RTRN,"xxxu",rx_addr,peer_addr,def_rlm,(def_rlm ? def_rlm->id : 0));
	return def_rlm;
}


int rhp_ikev1_srch_sa_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_ike_sa_init_srch_plds_ctx* s_pld_ctx = (rhp_ike_sa_init_srch_plds_ctx*)ctx;
  rhp_ikev1_sa_payload* sa_payload = (rhp_ikev1_sa_payload*)payload->ext.v1_sa;

  RHP_TRC(0,RHPTRCID_IKEV1_SRCH_SA_CB,"xdxxx",rx_ikemesg,enum_end,payload,sa_payload,ctx);

  if( sa_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV1_SRCH_SA_CB_DUP_ERR,"xd",rx_ikemesg,s_pld_ctx->dup_flag);
  	goto error;
  }


  err = sa_payload->get_matched_ikesa_prop(payload,&(s_pld_ctx->resolved_prop.v1));
  if( err ){

  	s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_NO_PROPOSAL_CHOSEN;

  	RHP_TRC(0,RHPTRCID_IKEV1_SRCH_SA_CB_NO_MATCHED_PROP,"xxxE",rx_ikemesg,s_pld_ctx->vpn,s_pld_ctx->ikesa,err);
    goto error;
  }

  if( s_pld_ctx->resolved_prop.v1.life_time < (unsigned long)rhp_gcfg_ikev1_ikesa_min_lifetime ){

  	s_pld_ctx->resolved_prop.v1.life_time = (unsigned long)rhp_gcfg_ikev1_ikesa_min_lifetime;

  	RHP_TRC(0,RHPTRCID_IKEV1_SRCH_SA_CB_MIN_LIFETIME_APPLIED,"xxxud",rx_ikemesg,s_pld_ctx->vpn,s_pld_ctx->ikesa,s_pld_ctx->resolved_prop.v1.life_time,rhp_gcfg_ikev1_ikesa_min_lifetime);
  }


  s_pld_ctx->sa_payload = payload;
  err = 0;

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_MAIN_PARSE_SA_PAYLOAD,"Kbbddddud",rx_ikemesg,s_pld_ctx->resolved_prop.v1.number,s_pld_ctx->resolved_prop.v1.trans_number,s_pld_ctx->resolved_prop.v1.enc_alg,s_pld_ctx->resolved_prop.v1.hash_alg,s_pld_ctx->resolved_prop.v1.auth_method,s_pld_ctx->resolved_prop.v1.dh_group,s_pld_ctx->resolved_prop.v1.life_time,s_pld_ctx->resolved_prop.v1.key_bits_len);

error:
  RHP_TRC(0,RHPTRCID_IKEV1_SRCH_SA_CB_RTRN,"xxxE",rx_ikemesg,payload,sa_payload,err);
  return err;
}

int rhp_ikev1_srch_ke_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_ike_sa_init_srch_plds_ctx* s_pld_ctx = (rhp_ike_sa_init_srch_plds_ctx*)ctx;
  rhp_ikev1_ke_payload* ke_payload = (rhp_ikev1_ke_payload*)payload->ext.v1_ke;
  int dh_group = 0;
  int keylen = -1;

  RHP_TRC(0,RHPTRCID_IKEV1_SRCH_KE_CB,"xdxxxxd",rx_ikemesg,enum_end,payload,ke_payload,ctx,s_pld_ctx->ikesa,s_pld_ctx->resolved_prop.v1.dh_group);

  if( ke_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV1_SRCH_KE_CB_DUP_ERR,"xd",rx_ikemesg,s_pld_ctx->dup_flag);
  	goto error;
  }

	dh_group = s_pld_ctx->resolved_prop.v1.dh_group;
  if( dh_group == 0 && s_pld_ctx->ikesa ){
  	dh_group = s_pld_ctx->ikesa->prop.v1.dh_group;
  }

  keylen = _rhp_proto_dh_keylen(dh_group);
  if( keylen <= 0 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV1_SRCH_KE_CB_INVALID_KEY_LEN,"xddd",rx_ikemesg,keylen,(s_pld_ctx->ikesa ? s_pld_ctx->ikesa->prop.v1.dh_group : -1),s_pld_ctx->resolved_prop.v1.dh_group);
    goto error;
  }


  s_pld_ctx->peer_dh_pub_key_len = ke_payload->get_key_len(payload);
  s_pld_ctx->peer_dh_pub_key = ke_payload->get_key(payload);
  if( s_pld_ctx->peer_dh_pub_key_len != keylen || s_pld_ctx->peer_dh_pub_key == NULL ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV1_SRCH_KE_CB_GET_DH_PUTKEY_ERR,"xxxdddd",rx_ikemesg,s_pld_ctx->vpn,s_pld_ctx->ikesa,s_pld_ctx->peer_dh_pub_key_len,keylen,(s_pld_ctx->ikesa ? s_pld_ctx->ikesa->prop.v1.dh_group : -1),s_pld_ctx->resolved_prop.v1.dh_group);
  	goto error;
  }


  s_pld_ctx->ke_payload = payload;
  err = 0;

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_PARSE_KE_PAYLOAD,"Kw",rx_ikemesg,(u16)dh_group);

error:
  RHP_TRC(0,RHPTRCID_IKEV1_SRCH_KE_CB_RTRN,"xxxE",rx_ikemesg,payload,ke_payload,err);
  return err;
}

int rhp_ikev1_srch_nonce_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_ike_sa_init_srch_plds_ctx* s_pld_ctx = (rhp_ike_sa_init_srch_plds_ctx*)ctx;
  rhp_ikev2_nir_payload* nir_payload = (rhp_ikev2_nir_payload*)payload->ext.sa;

  RHP_TRC(0,RHPTRCID_IKEV1_SRCH_NONCE_CB,"xdxxx",rx_ikemesg,enum_end,payload,nir_payload,ctx);

  if( nir_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV1_SRCH_NONCE_CB_DUP_ERR,"xd",rx_ikemesg,s_pld_ctx->dup_flag);
  	goto error;
  }

  s_pld_ctx->nonce_len = nir_payload->get_nonce_len(payload);
  if( s_pld_ctx->nonce_len < rhp_gcfg_ikev1_min_nonce_size ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV1_SRCH_NONCE_CB_NONCE_LEN_TOO_SHORT_ERR,"xxxdd",rx_ikemesg,s_pld_ctx->vpn,s_pld_ctx->ikesa,s_pld_ctx->nonce_len,rhp_gcfg_ikev1_min_nonce_size);
  	goto error;
  }

  s_pld_ctx->nonce = nir_payload->get_nonce(payload);
  if( s_pld_ctx->nonce == NULL ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV1_SRCH_NONCE_CB_GET_NONCE_ERR,"xxx",rx_ikemesg,s_pld_ctx->vpn,s_pld_ctx->ikesa);
  	goto error;
  }

  s_pld_ctx->nir_payload = payload;
  err = 0;

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_PARSE_NONCE_PAYLOAD,"Kd",rx_ikemesg,s_pld_ctx->nonce_len);

error:
  RHP_TRC(0,RHPTRCID_IKEV1_SRCH_NONCE_CB_RTRN,"xxxxE",rx_ikemesg,payload,nir_payload,ctx,err);
  return err;
}

static int _rhp_ikev1_srch_cert_req_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,rhp_vpn* vpn,rhp_ikesa* ikesa)
{
  int err = -EINVAL;
  rhp_ikev1_cr_payload* cert_req_payload = (rhp_ikev1_cr_payload*)payload->ext.v1_cr;
  u8 cert_encoding;
  u8 *dn_der, *dn_ders = NULL;
  int dn_der_len, dn_ders_len = 0, dn_ders_len2;
  rhp_cert_data* dn_der_head;
  rhp_cert_dn* ca_dn = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_SRCH_CERT_REQ_CB,"xdxxxx",rx_ikemesg,enum_end,payload,cert_req_payload,vpn,ikesa);

  if( cert_req_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  cert_encoding = cert_req_payload->get_cert_encoding(payload);
  if( cert_encoding != RHP_PROTO_IKEV1_CERT_ENC_X509_CERT_SIG ){
  	err = 0;
  	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_PARSE_CERT_REQ_PAYLOAD_UNSUP_CERT_ENCODING,"Kb",rx_ikemesg,cert_encoding);
  	goto ignored;
  }


  dn_der_len = cert_req_payload->get_ca_len(payload);
  dn_der = cert_req_payload->get_ca(payload);
  if( dn_der_len < 1 || dn_der == NULL ){

  	//
  	// Some IKEv1 implementations (e.g. Android) send a CR payload with no CA's DN.
  	//

  	err = 0;
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_PARSE_CERT_REQ_PAYLOAD_INVALID_CA_DN_DER,"K",rx_ikemesg);
  	goto ignored;
  }


  //
  // TODO: VPN realm is not resolved yet here. Compare received
  //       DNs with all DNs of all CA's certs installed into this
  //       node.
  //


  ca_dn = rhp_cert_dn_alloc_by_DER(dn_der,dn_der_len);
  if( ca_dn == NULL ){
  	err = 0;
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_PARSE_CERT_REQ_PAYLOAD_INVALID_CA_DN_DER,"K",rx_ikemesg);
  	goto ignored;
  }


  dn_ders_len = ikesa->v1.rx_ca_dn_ders_len + (int)sizeof(rhp_cert_data) + dn_der_len;
  dn_ders_len2 = dn_ders_len - (int)sizeof(rhp_cert_data)*(ikesa->v1.rx_ca_dn_ders_num + 1);
  if( dn_ders_len2 > rhp_gcfg_ca_dn_ders_max_size ){
  	err = 0;
  	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_PARSE_CERT_REQ_PAYLOAD_MAX_CA_DN_DATA_REACHED,"Kd",rx_ikemesg,dn_ders_len2);
  	goto ignored;
  }

  dn_ders = (u8*)_rhp_malloc(dn_ders_len);
  if( dn_ders == NULL ){
  	err = -ENOMEM;
  	RHP_BUG("");
  	goto error;
  }

  if( ikesa->v1.rx_ca_dn_ders ){

  	memcpy(dn_ders,ikesa->v1.rx_ca_dn_ders,ikesa->v1.rx_ca_dn_ders_len);
  	dn_der_head = (rhp_cert_data*)(((u8*)dn_ders) + ikesa->v1.rx_ca_dn_ders_len);

  	_rhp_free(ikesa->v1.rx_ca_dn_ders);

  }else{

  	dn_der_head = (rhp_cert_data*)dn_ders;
  }

  ikesa->v1.rx_ca_dn_ders = dn_ders;
  ikesa->v1.rx_ca_dn_ders_len = dn_ders_len;
  ikesa->v1.rx_ca_dn_ders_num++;

  dn_der_head->len = dn_der_len;
  dn_der_head->type = RHP_CERT_DATA_CA_DN;
  memcpy((u8*)(dn_der_head + 1),dn_der,dn_der_len);

  err = 0;

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_PARSE_CERT_REQ_PAYLOAD,"Ks",rx_ikemesg,ca_dn->to_text(ca_dn));

ignored:
error:
	if( ca_dn ){
		rhp_cert_dn_free(ca_dn);
	}
  RHP_TRC(0,RHPTRCID_IKEV1_SRCH_CERT_REQ_CB_RTRN,"xxxE",rx_ikemesg,payload,cert_req_payload,err);
  return err;
}

int rhp_ikev1_srch_cert_req_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
  rhp_ike_sa_init_srch_plds_ctx* s_pld_ctx = (rhp_ike_sa_init_srch_plds_ctx*)ctx;

  s_pld_ctx->dup_flag++;

  return _rhp_ikev1_srch_cert_req_cb(rx_ikemesg,enum_end,payload,s_pld_ctx->vpn,s_pld_ctx->ikesa);
}

int rhp_ikev1_srch_cert_req_cb_2(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
  rhp_ikev1_auth_srch_plds_ctx* s_pld_ctx = (rhp_ikev1_auth_srch_plds_ctx*)ctx;

  s_pld_ctx->dup_flag++;

  return _rhp_ikev1_srch_cert_req_cb(rx_ikemesg,enum_end,payload,RHP_VPN_REF(s_pld_ctx->vpn_ref),s_pld_ctx->ikesa);
}


int rhp_ikev1_auth_srch_hash_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_ikev1_auth_srch_plds_ctx* s_pld_ctx = (rhp_ikev1_auth_srch_plds_ctx*)ctx;
  rhp_ikev1_hash_payload* hash_payload = (rhp_ikev1_hash_payload*)payload->ext.v1_hash;

  RHP_TRC(0,RHPTRCID_IKEV1_AUTH_SRCH_HASH_CB,"xdxxx",rx_ikemesg,enum_end,payload,hash_payload,ctx);

  if( hash_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV1_AUTH_SRCH_HASH_CB_DUP_ERR,"xd",rx_ikemesg,s_pld_ctx->dup_flag);
  	goto error;
  }

  s_pld_ctx->hash_len = hash_payload->get_hash_len(payload);

  s_pld_ctx->hash = hash_payload->get_hash(payload);
  if( s_pld_ctx->hash == NULL ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV1_AUTH_SRCH_HASH_CB_GET_NONCE_ERR,"xxx",rx_ikemesg,RHP_VPN_REF(s_pld_ctx->vpn_ref),s_pld_ctx->ikesa);
  	goto error;
  }

  s_pld_ctx->peer_hash_payload = payload;
  err = 0;

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(RHP_VPN_REF(s_pld_ctx->vpn_ref) ? RHP_VPN_REF(s_pld_ctx->vpn_ref)->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_PARSE_HASH_PAYLOAD,"Kd",rx_ikemesg,s_pld_ctx->hash_len);

error:
  RHP_TRC(0,RHPTRCID_IKEV1_AUTH_SRCH_HASH_CB_RTRN,"xxxxE",rx_ikemesg,payload,hash_payload,ctx,err);
  return err;
}

int rhp_ikev1_auth_srch_id_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_ikev1_auth_srch_plds_ctx* s_pld_ctx = (rhp_ikev1_auth_srch_plds_ctx*)ctx;
  rhp_ikev1_id_payload* id_payload = (rhp_ikev1_id_payload*)payload->ext.v1_id;

  RHP_TRC(0,RHPTRCID_IKEV1_AUTH_SRCH_ID_CB,"xdxxx",rx_ikemesg,enum_end,payload,id_payload,ctx);

  if( id_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV1_AUTH_SRCH_ID_CB_DUP_ERR,"xd",rx_ikemesg,s_pld_ctx->dup_flag);
  	goto error;
  }

  s_pld_ctx->peer_id_type = id_payload->get_id_type(payload);
  s_pld_ctx->peer_id_len = id_payload->get_id_len(payload);

  s_pld_ctx->peer_id = id_payload->get_id(payload);
  if( s_pld_ctx->peer_id == NULL ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV1_AUTH_SRCH_ID_CB_GET_ID_ERR,"xxx",rx_ikemesg,RHP_VPN_REF(s_pld_ctx->vpn_ref),s_pld_ctx->ikesa);
  	goto error;
  }

  s_pld_ctx->peer_id_payload = payload;

  err = 0;

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(RHP_VPN_REF(s_pld_ctx->vpn_ref) ? RHP_VPN_REF(s_pld_ctx->vpn_ref)->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_PARSE_ID_PAYLOAD,"Kd",rx_ikemesg,s_pld_ctx->peer_id_len);

error:
  RHP_TRC(0,RHPTRCID_IKEV1_AUTH_SRCH_ID_CB_RTRN,"xxxxE",rx_ikemesg,payload,id_payload,ctx,err);
  return err;
}

int rhp_ikev1_auth_srch_sign_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_ikev1_auth_srch_plds_ctx* s_pld_ctx = (rhp_ikev1_auth_srch_plds_ctx*)ctx;
  rhp_ikev1_sig_payload* sig_payload = (rhp_ikev1_sig_payload*)payload->ext.v1_sig;

  RHP_TRC(0,RHPTRCID_IKEV1_AUTH_SRCH_SIGN_CB,"xdxxx",rx_ikemesg,enum_end,payload,sig_payload,ctx);

  if( sig_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV1_AUTH_SRCH_SIGN_CB_DUP_ERR,"xd",rx_ikemesg,s_pld_ctx->dup_flag);
  	goto error;
  }

  s_pld_ctx->sign_octets_len = sig_payload->get_sig_len(payload);

  s_pld_ctx->sign_octets = sig_payload->get_sig(payload);
  if( s_pld_ctx->sign_octets == NULL ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV1_AUTH_SRCH_SIGN_CB_GET_NONCE_ERR,"xxx",rx_ikemesg,RHP_VPN_REF(s_pld_ctx->vpn_ref),s_pld_ctx->ikesa);
  	goto error;
  }

  s_pld_ctx->peer_sig_payload = payload;
  err = 0;

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(RHP_VPN_REF(s_pld_ctx->vpn_ref) ? RHP_VPN_REF(s_pld_ctx->vpn_ref)->vpn_realm_id : 0),RHP_LOG_ID_RX_IKEV1_PARSE_HASH_PAYLOAD,"Kd",rx_ikemesg,s_pld_ctx->sign_octets_len);

error:
  RHP_TRC(0,RHPTRCID_IKEV1_AUTH_SRCH_SIGN_CB_RTRN,"xxxxE",rx_ikemesg,payload,sig_payload,ctx,err);
  return err;
}

int rhp_ikev1_auth_srch_n_realm_id_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
			rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	int rx_len = 0;
	u8* rx_data = NULL;
	rhp_ikev1_auth_srch_plds_ctx* s_pld_ctx = (rhp_ikev1_auth_srch_plds_ctx*)ctx;

  RHP_TRC(0,RHPTRCID_IKEV1_SRCH_N_REALM_ID_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV1_SRCH_N_REALM_ID_CB_DUP_ERR,"xx",rx_ikemesg,ctx);
    goto error;
  }

  rx_len = payload->ext.n->get_data_len(payload);
	rx_data = payload->ext.n->get_data(payload);

	if( rx_len == sizeof(u32) ){

		unsigned long peer_notified_realm_id = ntohl(*((u32*)rx_data));

    RHP_TRC(0,RHPTRCID_IKEV1_SRCH_N_REALM_ID_CB_DATA,"xu",rx_ikemesg,peer_notified_realm_id);

    if( peer_notified_realm_id &&
    		peer_notified_realm_id <= RHP_VPN_REALM_ID_MAX ){

     	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_N_REALM_ID_PAYLOAD,"Ku",rx_ikemesg,peer_notified_realm_id);

     	RHP_VPN_REF(s_pld_ctx->vpn_ref)->peer_notified_realm_id = peer_notified_realm_id;

    }else{

    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_N_INVALID_REALM_ID_PAYLOAD,"Ku",rx_ikemesg,peer_notified_realm_id);
  		RHP_TRC(0,RHPTRCID_IKEV1_SRCH_N_REALM_ID_CB_BAD_ID,"xxxu",rx_ikemesg,payload,ctx,peer_notified_realm_id);
    }

	}else{

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_N_INVALID_REALM_ID_PAYLOAD_LEN,"Kd",rx_ikemesg,rx_len);
		RHP_TRC(0,RHPTRCID_IKEV1_SRCH_N_REALM_ID_CB_BAD_LEN,"xxxd",rx_ikemesg,payload,ctx,rx_len);
	}

  err = 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV1_SRCH_N_REALM_ID_CB_RTRN,"xxxE",rx_ikemesg,payload,ctx,err);
	return err;
}

int rhp_ikev1_auth_srch_cert_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_ikev1_auth_srch_plds_ctx* s_pld_ctx = (rhp_ikev1_auth_srch_plds_ctx*)ctx;

  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_CERT_CB,"xdxu",rx_ikemesg,enum_end,payload,s_pld_ctx->dup_flag);

  if( enum_end ){

  	if( s_pld_ctx->peer_cert_der ){

  	 	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_PARSE_CERT_PAYLOADS,"Kd",rx_ikemesg,s_pld_ctx->untrust_ca_cert_ders_num);

  	}else{

  		RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_CERT_CB_NO_CERT_PLD,"xx",rx_ikemesg,s_pld_ctx->ikesa);
  	 	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_NO_CERT_PAYLOAD,"K",rx_ikemesg);
    }

  }else{

  	rhp_ikev2_cert_payload* cert_payload = (rhp_ikev2_cert_payload*)payload->ext.cert;
  	u8 enc;

  	if( cert_payload == NULL ){
    	RHP_BUG("");
    	return -EINVAL;
    }

	  enc = cert_payload->get_cert_encoding(payload);

	  if( enc != RHP_PROTO_IKEV1_CERT_ENC_X509_CERT_SIG ){
  	 	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_NOT_SUPPORTED_CERT_ENCODING,"Kb",rx_ikemesg,enc);
	  	RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_SRCH_CERT_REQ_CB_UNKNOWN_ENCODE,"xxxb",rx_ikemesg,RHP_VPN_REF(s_pld_ctx->vpn_ref),s_pld_ctx->ikesa,enc);
  	 	err = RHP_STATUS_IKEV2_AUTH_FAILED;
	  	goto error;
	  }

  	s_pld_ctx->dup_flag++;

  	if( s_pld_ctx->dup_flag == 1 ){ // Peer's endpoint certificate.

	  	s_pld_ctx->peer_cert_der_len = cert_payload->get_cert_len(payload);

	  	s_pld_ctx->peer_cert_der = (u8*)_rhp_malloc(s_pld_ctx->peer_cert_der_len);
	  	if( s_pld_ctx->peer_cert_der == NULL ){
	  		RHP_BUG("");
	  		err = -ENOMEM;
	  		goto error;
	  	}

	  	memcpy(s_pld_ctx->peer_cert_der,cert_payload->get_cert(payload),s_pld_ctx->peer_cert_der_len);

	  	payload->list_next = NULL;

	  }else if( s_pld_ctx->dup_flag > rhp_gcfg_max_cert_payloads ){

	    RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_CERT_SRCH_CB_TOO_MANY,"xxud",rx_ikemesg,payload,s_pld_ctx->dup_flag,rhp_gcfg_max_cert_payloads);
  	 	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn_ref ? ((rhp_vpn*)RHP_VPN_REF(s_pld_ctx->vpn_ref))->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_AUTH_TOO_MANY_CERT_PAYLOADS,"Kd",rx_ikemesg,s_pld_ctx->dup_flag);

	    goto error;

	  }else{ // SubCAs(Intermediate CAs) certificates.

	  	u8* untrust_ca_cert_der = s_pld_ctx->untrust_ca_cert_ders;
	  	int untrust_ca_cert_der_len = s_pld_ctx->untrust_ca_cert_ders_len;
	  	int cert_data_len = cert_payload->get_cert_len(payload);

	  	s_pld_ctx->untrust_ca_cert_ders_len += (int)sizeof(rhp_cert_data) + cert_data_len;

	  	s_pld_ctx->untrust_ca_cert_ders = (u8*)_rhp_malloc(s_pld_ctx->untrust_ca_cert_ders_len);
	  	if( s_pld_ctx->untrust_ca_cert_ders == NULL ){
	  		RHP_BUG("");
	  		err = -ENOENT;
	  		goto error;
	  	}

	  	if( untrust_ca_cert_der ){
	  		memcpy(s_pld_ctx->untrust_ca_cert_ders,untrust_ca_cert_der,untrust_ca_cert_der_len);
	  	}

	  	((rhp_cert_data*)(s_pld_ctx->untrust_ca_cert_ders + untrust_ca_cert_der_len))->type
	  			= RHP_CERT_DATA_DER;

	  	((rhp_cert_data*)(s_pld_ctx->untrust_ca_cert_ders + untrust_ca_cert_der_len))->len
	  			= cert_data_len;

	  	memcpy((s_pld_ctx->untrust_ca_cert_ders + untrust_ca_cert_der_len + (int)sizeof(rhp_cert_data)),
	  			cert_payload->get_cert(payload),cert_data_len);

		  s_pld_ctx->untrust_ca_cert_ders_num++;
	  }
  }

  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_IKE_AUTH_CERT_SRCH_CB_RTRN,"xxdddE",rx_ikemesg,payload,s_pld_ctx->dup_flag,s_pld_ctx->peer_cert_der_len,s_pld_ctx->untrust_ca_cert_ders_num,err);
  return err;
}

int rhp_ikev1_auth_srch_n_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_ikev1_auth_srch_plds_ctx* s_pld_ctx = (rhp_ikev1_auth_srch_plds_ctx*)ctx;
  rhp_ikev2_n_payload* n_payload = (rhp_ikev2_n_payload*)payload->ext.n;
  u16 notify_mesg_type;

  RHP_TRC(0,RHPTRCID_IKEV1_AUTH_SRCH_N_CB,"xdxxxxx",rx_ikemesg,enum_end,payload,n_payload,ctx,RHP_VPN_REF(s_pld_ctx->vpn_ref),s_pld_ctx->ikesa);
  if( n_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  notify_mesg_type = n_payload->get_message_type(payload);

  if( notify_mesg_type == RHP_PROTO_IKEV1_N_ST_INITIAL_CONTACT ){

  	s_pld_ctx->rx_initial_contact = 1;
  }

  err = 0;

  RHP_TRC(0,RHPTRCID_IKEV1_AUTH_SRCH_N_CB_RTRN,"xxxxwdE",rx_ikemesg,payload,n_payload,ctx,notify_mesg_type,s_pld_ctx->rx_initial_contact,err);
  return err;
}

int rhp_ikev1_auth_srch_n_error_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_ikev1_auth_srch_plds_ctx* s_pld_ctx = (rhp_ikev1_auth_srch_plds_ctx*)ctx;
  rhp_ikev2_n_payload* n_payload = (rhp_ikev2_n_payload*)payload->ext.n;
  u16 notify_mesg_type;

  RHP_TRC(0,RHPTRCID_IKEV1_SRCH_N_ERROR_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

  if( n_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  notify_mesg_type = n_payload->get_message_type(payload);

  //
  // TODO : Handling only interested notify-error codes.
  //
  if( notify_mesg_type >= RHP_PROTO_IKEV1_N_ERR_MIN && notify_mesg_type <= RHP_PROTO_IKEV1_N_ERR_END ){

    RHP_TRC(0,RHPTRCID_IKEV1_SRCH_N_ERROR_CB_FOUND,"xxLw",rx_ikemesg,payload,"PROTO_IKEV1_NOTIFY",notify_mesg_type);

    s_pld_ctx->n_error_payload = payload;
    s_pld_ctx->n_err = notify_mesg_type;

    err = RHP_STATUS_ENUM_OK;
    goto error;
  }

  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV1_SRCH_N_ERROR_CB_RTRN,"xxE",rx_ikemesg,payload,err);
  return err;
}

int rhp_ikev1_new_pkt_error_notify_rep(rhp_ikesa* ikesa,rhp_ikev2_mesg* tx_ikemesg,
		                u16 notify_mesg_type,unsigned long arg0)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;

	if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_N,&ikepayload) ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

	ikepayload->ext.n->set_protocol_id(ikepayload,RHP_PROTO_IKEV1_PROP_PROTO_ID_ISAKMP);

	ikepayload->ext.n->set_message_type(ikepayload,notify_mesg_type);

	ikepayload->ext.n->v1_set_ikesa_spi(ikepayload,ikesa->init_spi,ikesa->resp_spi);

	return 0;

error:
	return err;
}




extern void rhp_ikev1_main_ipc_psk_skeyid_rep_handler(rhp_ipcmsg** ipcmsg);
extern void rhp_ikev1_main_ipc_rsasig_sign_rep_handler(rhp_ipcmsg** ipcmsg);
extern void rhp_ikev1_main_ipc_rsasig_verify_and_sign_rep_handler(rhp_ipcmsg** ipcmsg);
extern void rhp_ikev1_main_ipc_rsasig_verify_rep_handler(rhp_ipcmsg** ipcmsg);

extern void rhp_ikev1_aggressive_ipc_psk_skeyid_rep_handler(rhp_ipcmsg** ipcmsg);
extern void rhp_ikev1_aggressive_ipc_rsasig_sign_rep_handler(rhp_ipcmsg** ipcmsg);
extern void rhp_ikev1_aggressive_ipc_rsasig_verify_and_sign_rep_handler(rhp_ipcmsg** ipcmsg);
extern void rhp_ikev1_aggressive_ipc_rsasig_verify_rep_handler(rhp_ipcmsg** ipcmsg);
extern void rhp_ikev1_aggressive_ipc_rslv_auth_rep_handler(rhp_ipcmsg** ipcmsg);

static void _rhp_ikev1_ipc_psk_skeyid_rep_handler(rhp_ipcmsg** ipcmsg)
{
  rhp_ipcmsg_ikev1_psk_skeyid_rep* psk_rep;

  RHP_TRC(0,RHPTRCID_IKEV1_IPC_PSK_SKEYID_REP_HANDLER,"xx",ipcmsg,*ipcmsg);

  if( (*ipcmsg)->len < sizeof(rhp_ipcmsg_ikev1_psk_skeyid_rep) ){
    RHP_BUG("%d < sizeof(rhp_ipcmsg_ikev1_psk_skeyid_rep)(%d)",(*ipcmsg)->len,sizeof(rhp_ipcmsg_ikev1_psk_skeyid_rep));
    goto error;
  }

  psk_rep = (rhp_ipcmsg_ikev1_psk_skeyid_rep*)(*ipcmsg);

  if( psk_rep->exchange_type == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ){

  	rhp_ikev1_main_ipc_psk_skeyid_rep_handler(ipcmsg);

  }else if( psk_rep->exchange_type == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){

  	rhp_ikev1_aggressive_ipc_psk_skeyid_rep_handler(ipcmsg);

  }else{
  	RHP_BUG("%d",psk_rep->exchange_type);
  }

error:
	return;
}

static void _rhp_ikev1_ipc_rsasig_sign_rep_handler(rhp_ipcmsg** ipcmsg)
{
	rhp_ipcmsg_ikev1_rsasig_sign_rep* rsasig_sign_rep;

  RHP_TRC(0,RHPTRCID_IKEV1_IPC_RSASIG_SIGN_REP_HANDLER,"xx",ipcmsg,*ipcmsg);

  if( (*ipcmsg)->len < sizeof(rhp_ipcmsg_ikev1_rsasig_sign_rep) ){
    RHP_BUG("%d < sizeof(rhp_ipcmsg_ikev1_rsasig_sign_rep)(%d)",(*ipcmsg)->len,sizeof(rhp_ipcmsg_ikev1_rsasig_sign_rep));
    goto error;
  }

  rsasig_sign_rep = (rhp_ipcmsg_ikev1_rsasig_sign_rep*)(*ipcmsg);

  if( rsasig_sign_rep->exchange_type == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ){

  	rhp_ikev1_main_ipc_rsasig_sign_rep_handler(ipcmsg);

  }else if( rsasig_sign_rep->exchange_type == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){

  	rhp_ikev1_aggressive_ipc_rsasig_sign_rep_handler(ipcmsg);

  }else{
  	RHP_BUG("%d",rsasig_sign_rep->exchange_type);
  }

error:
	return;
}

static void _rhp_ikev1_ipc_rsasig_verify_and_sign_rep_handler(rhp_ipcmsg** ipcmsg)
{
  rhp_ipcmsg_verify_and_sign_rep* verify_sign_rep;

  RHP_TRC(0,RHPTRCID_IKEV1_IPC_RSASIG_VERIFY_AND_SIGN_REP_HANDLER,"xx",ipcmsg,*ipcmsg);

  if( (*ipcmsg)->len < sizeof(rhp_ipcmsg_verify_and_sign_rep) ){
    RHP_BUG("%d < sizeof(rhp_ipcmsg_verify_and_sign_rep)(%d)",(*ipcmsg)->len,sizeof(rhp_ipcmsg_verify_and_sign_rep));
    goto error;
  }

  verify_sign_rep = (rhp_ipcmsg_verify_and_sign_rep*)(*ipcmsg);

  if( verify_sign_rep->v1_exchange_type == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ){

  	rhp_ikev1_main_ipc_rsasig_verify_and_sign_rep_handler(ipcmsg);

  }else if( verify_sign_rep->v1_exchange_type == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){

  	rhp_ikev1_aggressive_ipc_rsasig_verify_and_sign_rep_handler(ipcmsg);

  }else{
  	RHP_BUG("%d",verify_sign_rep->v1_exchange_type);
  }

error:
	return;
}

static void _rhp_ikev1_ipc_rsasig_verify_rep_handler(rhp_ipcmsg** ipcmsg)
{
  rhp_ipcmsg_ikev1_rsasig_verify_rep* rsasig_verify_rep;

  RHP_TRC(0,RHPTRCID_IKEV1_IPC_RSASIG_VERIFY_REP_HANDLER,"xx",ipcmsg,*ipcmsg);

  if( (*ipcmsg)->len < sizeof(rhp_ipcmsg_ikev1_rsasig_verify_rep) ){
    RHP_BUG("%d < sizeof(rhp_ipcmsg_ikev1_rsasig_verify_rep)(%d)",(*ipcmsg)->len,sizeof(rhp_ipcmsg_ikev1_rsasig_verify_rep));
    goto error;
  }

  rsasig_verify_rep = (rhp_ipcmsg_ikev1_rsasig_verify_rep*)(*ipcmsg);

  if( rsasig_verify_rep->exchange_type == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ){

  	rhp_ikev1_main_ipc_rsasig_verify_rep_handler(ipcmsg);

  }else if( rsasig_verify_rep->exchange_type == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){

  	rhp_ikev1_aggressive_ipc_rsasig_verify_rep_handler(ipcmsg);

  }else{
  	RHP_BUG("%d",rsasig_verify_rep->exchange_type);
  }

error:
	return;
}

static void _rhp_ikev1_ipc_rslv_auth_rep_handler(rhp_ipcmsg** ipcmsg)
{
	rhp_ipcmsg_ikev1_rslv_auth_rep* rslv_auth_rep;

  RHP_TRC(0,RHPTRCID_IKEV1_IPC_RSLV_AUTH_REP_HANDLER,"xx",ipcmsg,*ipcmsg);

  if( (*ipcmsg)->len < sizeof(rhp_ipcmsg_ikev1_rslv_auth_rep) ){
    RHP_BUG("%d < sizeof(rhp_ipcmsg_ikev1_rslv_auth_rep)(%d)",(*ipcmsg)->len,sizeof(rhp_ipcmsg_ikev1_rslv_auth_rep));
    goto error;
  }

  rslv_auth_rep = (rhp_ipcmsg_ikev1_rslv_auth_rep*)(*ipcmsg);

  if( rslv_auth_rep->exchange_type == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){

  	rhp_ikev1_aggressive_ipc_rslv_auth_rep_handler(ipcmsg);

  }else{
  	RHP_BUG("%d",rslv_auth_rep->exchange_type);
  }

error:
	return;
}


extern int rhp_ikev1_aggressive_init();
extern int rhp_ikev1_aggressive_cleanup();


int rhp_ikev1_init()
{
	int err = -EINVAL;

	err = rhp_ikev1_aggressive_init();
	if( err ){
		RHP_BUG("%d",err);
    return err;
	}

  {
	  err = rhp_ikev1_register_message_handler(RHP_IKEV1_MESG_HANDLER_P1_MAIN,
							NULL,
							rhp_ikev1_rx_main_no_vpn,
							rhp_ikev1_rx_main);

	  if( err ){
	    RHP_BUG("%d",err);
	    return err;
	  }
  }

  {
	  err = rhp_ikev1_register_message_handler(RHP_IKEV1_MESG_HANDLER_P1_AGGRESSIVE,
							NULL,
							rhp_ikev1_rx_aggressive_no_vpn,
							rhp_ikev1_rx_aggressive);

	  if( err ){
	    RHP_BUG("%d",err);
	    return err;
	  }
  }

  {
	  err = rhp_ikev1_register_message_handler(RHP_IKEV1_MESG_HANDLER_XAUTH,
							NULL,
							NULL,
							rhp_ikev1_rx_xauth);

	  if( err ){
	    RHP_BUG("%d",err);
	    return err;
	  }
  }



  {
	  err = rhp_ikev1_register_message_handler(RHP_IKEV1_MESG_HANDLER_P2_QUICK,
							NULL,
							NULL,
							rhp_ikev1_rx_quick);

	  if( err ){
	    RHP_BUG("%d",err);
	    return err;
	  }
  }

  {
	  err = rhp_ikev1_register_message_handler(RHP_IKEV1_MESG_HANDLER_NAT_T,
	  					rhp_ikev1_tx_nat_t_req,
							NULL,
							rhp_ikev1_rx_nat_t);

	  if( err ){
	    RHP_BUG("%d",err);
	    return err;
	  }
  }

  {
	  err = rhp_ikev1_register_message_handler(RHP_IKEV1_MESG_HANDLER_RHP_INTERNAL_NET,
							NULL,
							NULL,
							rhp_ikev1_rx_internal_net);

	  if( err ){
	    RHP_BUG("%d",err);
	    return err;
	  }
  }

  {
	  err = rhp_ikev1_register_message_handler(RHP_IKEV1_MESG_HANDLER_DELETE_SA,
							NULL,
							NULL,
							rhp_ikev1_rx_delete_sa);

	  if( err ){
	    RHP_BUG("%d",err);
	    return err;
	  }
  }

  {
	  err = rhp_ikev1_register_message_handler(RHP_IKEV1_MESG_HANDLER_DPD,
	  					rhp_ikev1_tx_dpd_req,
							NULL,
							rhp_ikev1_rx_dpd);

	  if( err ){
	    RHP_BUG("%d",err);
	    return err;
	  }
  }

  {
	  err = rhp_ikev1_register_message_handler(RHP_IKEV1_MESG_HANDLER_MODE_CFG,
	  					NULL,
							NULL,
							rhp_ikev1_rx_mode_cfg);

	  if( err ){
	    RHP_BUG("%d",err);
	    return err;
	  }
  }


	err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_IKEV1_PSK_SKEYID_REPLY,
					_rhp_ikev1_ipc_psk_skeyid_rep_handler,NULL);
	if( err ){
		RHP_BUG("");
		return err;
	}

	err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_IKEV1_SIGN_RSASIG_REPLY,
					_rhp_ikev1_ipc_rsasig_sign_rep_handler,NULL);
	if( err ){
		RHP_BUG("");
		return err;
	}

	err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_IKEV1_VERIFY_AND_SIGN_RSASIG_REPLY,
					_rhp_ikev1_ipc_rsasig_verify_and_sign_rep_handler,NULL);
	if( err ){
		RHP_BUG("");
		return err;
	}

	err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_IKEV1_VERIFY_RSASIG_REPLY,
					_rhp_ikev1_ipc_rsasig_verify_rep_handler,NULL);
	if( err ){
		RHP_BUG("");
		return err;
	}

	err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_IKEV1_RESOLVE_AUTH_REPLY,
					_rhp_ikev1_ipc_rslv_auth_rep_handler,NULL);
	if( err ){
		RHP_BUG("");
		return err;
	}

	RHP_TRC(0,RHPTRCID_IKEV1_INIT,"");
  return 0;
}

void rhp_ikev1_cleanup()
{
  RHP_TRC(0,RHPTRCID_IKEV1_CLEANUP,"");

  rhp_ikev1_aggressive_cleanup();

  return;
}
