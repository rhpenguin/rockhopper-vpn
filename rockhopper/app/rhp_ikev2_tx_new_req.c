/*

	Copyright (C) 2009-2015 TETSUHARU HANADA <rhpenguine@gmail.com>
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

static rhp_ikev2_tx_new_req* _rhp_ikev2_tx_new_req_alloc(rhp_vpn* vpn,int my_side,u8* my_spi)
{
	rhp_ikev2_tx_new_req* tx_req = (rhp_ikev2_tx_new_req*)_rhp_malloc(sizeof(rhp_ikev2_tx_new_req));
	if( tx_req == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(tx_req,0,sizeof(rhp_ikev2_tx_new_req));

	tx_req->tag[0] = '#';
	tx_req->tag[1] = 'T';
	tx_req->tag[2] = 'N';
	tx_req->tag[3] = 'R';

	tx_req->tx_ikemesg = rhp_ikev2_new_mesg_tx(RHP_PROTO_IKE_EXCHG_INFORMATIONAL,0,0);
	if( tx_req->tx_ikemesg == NULL ){
		RHP_BUG("");
		_rhp_free(tx_req);
		return NULL;
	}

	tx_req->my_side = my_side;
	memcpy(tx_req->my_spi,my_spi,RHP_PROTO_IKE_SPI_SIZE);

	RHP_TRC(0,RHPTRCID_IKEV2_TX_NEW_REQ_ALLOC,"xLdGx",vpn,"IKE_SIDE",my_side,my_spi,tx_req);
	return tx_req;
}

rhp_ikev2_mesg* rhp_ikev2_tx_new_req_get(rhp_vpn* vpn,int my_side,u8* my_spi)
{
	rhp_ikev2_tx_new_req* tx_req = vpn->ikev2_tx_new_req.req_head;

	RHP_TRC(0,RHPTRCID_IKEV2_TX_NEW_REQ_GET,"xLdG",vpn,"IKE_SIDE",my_side,my_spi);

	while( tx_req ){

		if( tx_req->my_side == my_side &&
				!memcmp(tx_req->my_spi,my_spi,RHP_PROTO_IKE_SPI_SIZE) ){

			RHP_TRC(0,RHPTRCID_IKEV2_TX_NEW_REQ_GET_CUR_RTRN,"xxx",vpn,tx_req,tx_req->tx_ikemesg);
			return tx_req->tx_ikemesg;
		}

		RHP_TRC(0,RHPTRCID_IKEV2_TX_NEW_REQ_GET_NXT,"xLdG",vpn,"IKE_SIDE",my_side,my_spi,tx_req);
		tx_req = tx_req->next;
	}

	tx_req = _rhp_ikev2_tx_new_req_alloc(vpn,my_side,my_spi);
	if( tx_req ){

		tx_req->next = vpn->ikev2_tx_new_req.req_head;
		vpn->ikev2_tx_new_req.req_head = tx_req;

		RHP_TRC(0,RHPTRCID_IKEV2_TX_NEW_REQ_GET_NEW_RTRN,"xxx",vpn,tx_req,tx_req->tx_ikemesg);
		return tx_req->tx_ikemesg;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_TX_NEW_REQ_GET_ERR,"x",vpn);
	return NULL;
}

void rhp_ikev2_tx_new_req_free_ctx(rhp_ikev2_tx_new_req* tx_new_req)
{
	RHP_TRC(0,RHPTRCID_IKEV2_TX_NEW_REQ_FREE_CTX,"xLdGx",tx_new_req,"IKE_SIDE",tx_new_req->my_side,tx_new_req->my_spi,tx_new_req->tx_ikemesg);

	if( tx_new_req->tx_ikemesg ){
		rhp_ikev2_unhold_mesg(tx_new_req->tx_ikemesg);
	}

	_rhp_free(tx_new_req);

	RHP_TRC(0,RHPTRCID_IKEV2_TX_NEW_REQ_FREE_CTX_LRTRN,"x",tx_new_req);
	return;
}

void rhp_ikev2_tx_new_req_free_ctx_vpn(rhp_vpn* vpn,rhp_ikev2_tx_new_req* tx_new_req)
{
	rhp_ikev2_tx_new_req *tx_req = vpn->ikev2_tx_new_req.req_head, *tx_req_p = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_TX_NEW_REQ_FREE_CTX_VPN,"xxLdGx",vpn,tx_new_req,"IKE_SIDE",tx_new_req->my_side,tx_new_req->my_spi,tx_new_req->tx_ikemesg);

	while( tx_req ){

		if( tx_req == tx_new_req ){

			if( tx_req_p ){
				tx_req_p->next = tx_req->next;
			}

			rhp_ikev2_tx_new_req_free_ctx(tx_req);

			RHP_TRC(0,RHPTRCID_IKEV2_TX_NEW_REQ_FREE_CTX_VPN_RTRN,"xx",vpn,tx_new_req);

			return;
		}

		tx_req_p = tx_req;
		tx_req = tx_req->next;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_TX_NEW_REQ_FREE_CTX_VPN_NO_ENT,"xx",vpn,tx_new_req);
	return;
}


#define RHP_IKEV2_TX_NEW_REQ_MAX_RETRIES 	50

void rhp_ikev2_tx_new_req_task(void *ctx,rhp_timer *timer)
{
	int err = -EINVAL;
  rhp_vpn_ref* vpn_ref = (rhp_vpn_ref*)ctx;
  rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);
	rhp_ikev2_tx_new_req *tx_req = NULL, *tx_req_p = NULL, *tx_req_removed = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_TX_NEW_REQ_TASK,"xx",vpn,timer);

  RHP_LOCK(&(vpn->lock));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV2_TX_NEW_REQ_TASK_VPN_NOT_ACTIVE,"xx",tx_req,vpn);
    goto error;
  }


  tx_req = vpn->ikev2_tx_new_req.req_head;
	while( tx_req ){

		int do_remove = 1, tx_ok = 0;
		rhp_ikesa* ikesa = NULL;

	  RHP_TRC(0,RHPTRCID_IKEV2_TX_NEW_REQ_TASK_VPN,"xxLdGxd",vpn,tx_req,"IKE_SIDE",tx_req->my_side,tx_req->my_spi,tx_req->tx_ikemesg,tx_req->tx_ikemesg->activated);

	  if( tx_req->tx_ikemesg->activated ){

	  	ikesa = vpn->ikesa_get(vpn,tx_req->my_side,tx_req->my_spi);
			if( ikesa ){

				if( ikesa->state == RHP_IKESA_STAT_ESTABLISHED || ikesa->state == RHP_IKESA_STAT_REKEYING ){

					if( ikesa->busy_flag ){

						if(tx_req->retries <= RHP_IKEV2_TX_NEW_REQ_MAX_RETRIES ){

							do_remove = 0;
						}

					}else{

						rhp_ikev2_send_request(vpn,ikesa,tx_req->tx_ikemesg,RHP_IKEV2_MESG_HANDLER_SESS_RESUME_TKT);

						tx_ok = 1;
					}
				}
			}
	  }

	  if( !do_remove ){

	  	tx_req_p = tx_req;
	  	tx_req = tx_req->next;

	  }else{

	  	rhp_ikev2_tx_new_req *tx_req_n = tx_req->next;

		  if( tx_ok ){
				RHP_TRC(0,RHPTRCID_IKEV2_TX_NEW_REQ_TASK_VPN_TX_OK,"xLdGxx",vpn,"IKE_SIDE",tx_req->my_side,tx_req->my_spi,tx_req,ikesa);
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_TX_NEW_REQ,"VP",vpn,ikesa);
		  }else{
				RHP_TRC(0,RHPTRCID_IKEV2_TX_NEW_REQ_TASK_VPN_TX_ERR,"xLdGxx",vpn,"IKE_SIDE",tx_req->my_side,tx_req->my_spi,tx_req,ikesa);
				RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_TX_NEW_REQ_ERR,"VLGP",vpn,"IKE_SIDE",tx_req->my_side,tx_req->my_spi,ikesa);
		  }

	  	if( tx_req_p ){

	  		tx_req_p->next = tx_req_n;

	  	}else{

	  		vpn->ikev2_tx_new_req.req_head = tx_req_n;
	  	}

  		tx_req->next = tx_req_removed;
  		tx_req_removed = tx_req;

  		tx_req = tx_req_n;
	  }
	}


  tx_req = tx_req_removed;
	while( tx_req ){

		rhp_ikev2_tx_new_req *tx_req_n = tx_req->next;

		rhp_ikev2_tx_new_req_free_ctx(tx_req);

  	tx_req = tx_req_n;
	}


	if( vpn->ikev2_tx_new_req.req_head ){

		rhp_vpn_ref* vpn_ref2 = rhp_vpn_hold_ref(vpn);

	  rhp_timer_reset(&(vpn->ikev2_tx_new_req.task));

	  err = rhp_timer_add_with_ctx(&(vpn->ikev2_tx_new_req.task),(time_t)rhp_gcfg_ikev2_tx_new_req_retry_interval,vpn_ref2);
	  if( err ){
	  	RHP_BUG("%d",err);
	  	rhp_vpn_unhold(vpn_ref2);
	  }
	}

error:
  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

  RHP_TRC(0,RHPTRCID_IKEV2_TX_NEW_REQ_TASK_RTRN,"x",vpn);
  return;
}


int rhp_ikev2_rx_tx_new_req_req(rhp_ikev2_mesg* rx_req_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err = 0;
	u8 exchange_type = rx_req_ikemesg->get_exchange_type(rx_req_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_TX_NEW_REQ_REQ,"xxLdGxLb",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_resp_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

  if( vpn->ikev2_tx_new_req.req_head ){

  	if( !rhp_timer_pending(&(vpn->ikev2_tx_new_req.task)) ){

  		rhp_vpn_ref* vpn_ref2 = rhp_vpn_hold_ref(vpn);

  	  rhp_timer_reset(&(vpn->ikev2_tx_new_req.task));

  	  err = rhp_timer_add_with_ctx(&(vpn->ikev2_tx_new_req.task),
  	  				(time_t)rhp_gcfg_ikev2_tx_new_req_retry_interval,vpn_ref2);
  	  if( err ){
  	  	RHP_BUG("%d",err);
  	  	rhp_vpn_unhold(vpn_ref2);
  	  }
  	}
  }

	RHP_TRC(0,RHPTRCID_IKEV2_RX_TX_NEW_REQ_REQ_RTRN,"xxxE",rx_req_ikemesg,vpn,tx_resp_ikemesg,err);
  return 0;
}

int rhp_ikev2_rx_tx_new_req_rep(rhp_ikev2_mesg* rx_resp_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err = 0;
	u8 exchange_type = rx_resp_ikemesg->get_exchange_type(rx_resp_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_TX_NEW_REQ_REP,"xxLdGxLb",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_req_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

  if( vpn->ikev2_tx_new_req.req_head ){

  	if( !rhp_timer_pending(&(vpn->ikev2_tx_new_req.task)) ){

  		rhp_vpn_ref* vpn_ref2 = rhp_vpn_hold_ref(vpn);

  	  rhp_timer_reset(&(vpn->ikev2_tx_new_req.task));

  	  err = rhp_timer_add_with_ctx(&(vpn->ikev2_tx_new_req.task),
  	  				(time_t)rhp_gcfg_ikev2_tx_new_req_retry_interval,vpn_ref2);
  	  if( err ){
  	  	RHP_BUG("%d",err);
  	  	rhp_vpn_unhold(vpn_ref2);
  	  }
  	}
  }

	RHP_TRC(0,RHPTRCID_IKEV2_RX_TX_NEW_REQ_REP_RTRN,"xxxE",rx_resp_ikemesg,vpn,tx_req_ikemesg,err);
  return 0;
}
