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
#include "rhp_radius_impl.h"
#include "rhp_radius_acct.h"


static rhp_mutex_t _rhp_radius_acct_lock;


struct _rhp_radius_acct_handle {

	u8 tag[4]; // "#RAH"

	rhp_mutex_t lock;

	int idx;

	rhp_radius_session* radius_sess;

	int secondary_server_configured;

	int secondary_server_used;
	time_t secondary_server_swiched_time;

	int tx_radius_mesg_q_num;
	rhp_radius_mesg* tx_radius_mesg_q_head;
	rhp_radius_mesg* tx_radius_mesg_q_tail;

	rhp_radius_mesg* tx_radius_mesg_on_the_fly;
};
typedef struct _rhp_radius_acct_handle 	rhp_radius_acct_handle;


static rhp_radius_acct_handle* _rhp_radius_acct_handles = NULL;
static int _rhp_radius_acct_next_handle_idx = 0;


static void _rhp_radius_acct_del_mesg_from_tx_queue(rhp_radius_acct_handle* radius_acct_hdl,
		rhp_radius_mesg* tx_radius_mesg)
{
	rhp_radius_mesg* radius_mesg = radius_acct_hdl->tx_radius_mesg_q_head,*radius_mesg_p = NULL;

  RHP_TRC(0,RHPTRCID_RADIUS_ACCT_DEL_MESG_FROM_TX_QUEUE,"xxxd",radius_acct_hdl,tx_radius_mesg,radius_acct_hdl->tx_radius_mesg_q_head,radius_acct_hdl->tx_radius_mesg_q_num);

	while( radius_mesg ){

		rhp_radius_mesg* radius_mesg_n = radius_mesg->next;

		if( radius_mesg == tx_radius_mesg ){
			break;
		}

		radius_mesg_p = radius_mesg;
		radius_mesg = radius_mesg_n;
	}

	if( radius_mesg == NULL ){
	  RHP_TRC(0,RHPTRCID_RADIUS_ACCT_DEL_MESG_FROM_TX_QUEUE_NOT_FOUND,"xx",radius_acct_hdl,tx_radius_mesg);
		return;
	}

	if( radius_mesg_p ){

		radius_mesg_p->next = radius_mesg->next;

		if( radius_acct_hdl->tx_radius_mesg_q_tail == tx_radius_mesg ){
			radius_acct_hdl->tx_radius_mesg_q_tail = radius_mesg_p;
		}

	}else{

		radius_acct_hdl->tx_radius_mesg_q_head = radius_mesg->next;

		if( radius_acct_hdl->tx_radius_mesg_q_tail == tx_radius_mesg ){
			radius_acct_hdl->tx_radius_mesg_q_tail = NULL;
		}
	}

	rhp_radius_mesg_unhold(radius_mesg);

	radius_acct_hdl->tx_radius_mesg_q_num--;

  RHP_TRC(0,RHPTRCID_RADIUS_ACCT_DEL_MESG_FROM_TX_QUEUE_RTRN,"xxd",radius_acct_hdl,tx_radius_mesg,radius_acct_hdl->tx_radius_mesg_q_num);
	return;
}

static void _rhp_radius_acct_clear_tx_queue(rhp_radius_acct_handle* radius_acct_hdl)
{
	rhp_radius_mesg* radius_mesg = radius_acct_hdl->tx_radius_mesg_q_head;

  RHP_TRC(0,RHPTRCID_RADIUS_ACCT_CLEAR_TX_QUEUE,"xx",radius_acct_hdl,radius_mesg);

	while( radius_mesg ){

		rhp_radius_mesg* radius_mesg_n = radius_mesg->next;

		rhp_radius_mesg_unhold(radius_mesg);

		radius_mesg = radius_mesg_n;
	}

	radius_acct_hdl->tx_radius_mesg_q_head = NULL;
	radius_acct_hdl->tx_radius_mesg_q_tail = NULL;
	radius_acct_hdl->tx_radius_mesg_q_num = 0;

  RHP_TRC(0,RHPTRCID_RADIUS_ACCT_CLEAR_TX_QUEUE_RTRN,"x",radius_acct_hdl);
	return;
}


static int _rhp_radius_acct_get_handle_index()
{
	int idx;

	RHP_LOCK(&_rhp_radius_acct_lock);

	idx = _rhp_radius_acct_next_handle_idx++;
	if( _rhp_radius_acct_next_handle_idx >= rhp_gcfg_radius_acct_max_sessions  ){
		_rhp_radius_acct_next_handle_idx = 0;
	}

	RHP_UNLOCK(&_rhp_radius_acct_lock);

  RHP_TRC(0,RHPTRCID_RADIUS_ACCT_GET_HANDLE_INDEX,"d",idx);
	return idx;
}


static int _rhp_radius_acct_switch_primary_server(rhp_radius_acct_handle* radius_acct_hdl,int flag)
{
	time_t now;

  RHP_TRC(0,RHPTRCID_RADIUS_ACCT_SWITCH_PRIMARY_SERVER,"xddd",radius_acct_hdl,radius_acct_hdl->idx,flag,radius_acct_hdl->secondary_server_used);

	if( !radius_acct_hdl->secondary_server_used ){
		return 0;
	}

	if( !flag ){

		now = _rhp_get_time();

		if( (now - radius_acct_hdl->secondary_server_swiched_time)
					>= rhp_gcfg_radius_secondary_server_hold_time ){

			radius_acct_hdl->secondary_server_used = 0;

		  RHP_TRC(0,RHPTRCID_RADIUS_ACCT_SWITCH_PRIMARY_SERVER_1,"xdddttd",radius_acct_hdl,radius_acct_hdl->idx,flag,radius_acct_hdl->secondary_server_used,now,radius_acct_hdl->secondary_server_swiched_time,rhp_gcfg_radius_secondary_server_hold_time);

		}else{

		  RHP_TRC(0,RHPTRCID_RADIUS_ACCT_SWITCH_PRIMARY_SERVER_1_NOT,"xdddttd",radius_acct_hdl,radius_acct_hdl->idx,flag,radius_acct_hdl->secondary_server_used,now,radius_acct_hdl->secondary_server_swiched_time,rhp_gcfg_radius_secondary_server_hold_time);
		}

	}else{

		radius_acct_hdl->secondary_server_used = 0;

		RHP_TRC(0,RHPTRCID_RADIUS_ACCT_SWITCH_PRIMARY_SERVER_2,"xddd",radius_acct_hdl,radius_acct_hdl->idx,flag,radius_acct_hdl->secondary_server_used);
	}

	return 0;
}

static int _rhp_radius_acct_switch_secondary_server(rhp_radius_acct_handle* radius_acct_hdl)
{
  RHP_TRC(0,RHPTRCID_RADIUS_ACCT_SWITCH_SECONDARY_SERVER,"xdd",radius_acct_hdl,radius_acct_hdl->idx,radius_acct_hdl->secondary_server_used);

  if( radius_acct_hdl->secondary_server_used ){
		return 0;
	}

	radius_acct_hdl->secondary_server_used = 1;
	radius_acct_hdl->secondary_server_swiched_time = _rhp_get_time();

  RHP_TRC(0,RHPTRCID_RADIUS_ACCT_SWITCH_SECONDARY_SERVER_RTRN,"xddt",radius_acct_hdl,radius_acct_hdl->idx,radius_acct_hdl->secondary_server_used,radius_acct_hdl->secondary_server_swiched_time);
	return 0;
}

static int _rhp_radius_acct_use_secondary_server(rhp_radius_acct_handle* radius_acct_hdl)
{
  RHP_TRC(0,RHPTRCID_RADIUS_ACCT_USE_SECONDARY_SERVER,"xdd",radius_acct_hdl,radius_acct_hdl->idx,radius_acct_hdl->secondary_server_used);
	return radius_acct_hdl->secondary_server_used;
}


static int _rhp_radius_acct_session_close(rhp_radius_acct_handle* radius_acct_hdl)
{
	int err;

	if( radius_acct_hdl->radius_sess == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}


	RHP_LOCK(&(radius_acct_hdl->radius_sess->lock));

	err = rhp_radius_session_close(radius_acct_hdl->radius_sess);

	RHP_UNLOCK(&(radius_acct_hdl->radius_sess->lock));

	rhp_radius_sess_unhold(radius_acct_hdl->radius_sess);
	radius_acct_hdl->radius_sess = NULL;

  RHP_TRC(0,RHPTRCID_RADIUS_ACCT_SESSION_CLOSE,"xxE",radius_acct_hdl,radius_acct_hdl->radius_sess,err);

	return err;
}


static void _rhp_radius_acct_receive_response_cb(rhp_radius_session* radius_sess,void* cb_ctx,
		rhp_radius_mesg* rx_radius_mesg)
{
	int err = -EINVAL;
	rhp_radius_acct_handle* radius_acct_hdl = (rhp_radius_acct_handle*)cb_ctx;

  RHP_TRC(0,RHPTRCID_RADIUS_ACCT_RECEIVE_RESPONSE_CB,"xxx",radius_sess,radius_acct_hdl,rx_radius_mesg);

  RHP_LOCK(&(radius_acct_hdl->lock));

  if( radius_acct_hdl->radius_sess == NULL ){
		err = 0;
    RHP_TRC(0,RHPTRCID_RADIUS_ACCT_RECEIVE_RESPONSE_CB_NO_CTX_RADIUS_SESS,"xx",radius_sess,radius_acct_hdl);
  	goto ignored;
  }

  if( radius_acct_hdl->radius_sess != radius_sess ){
  	RHP_BUG("");
    RHP_TRC(0,RHPTRCID_RADIUS_ACCT_RECEIVE_RESPONSE_CB_CTX_RADIUS_SESS_NOT_MATCH,"xxx",radius_sess,radius_acct_hdl,radius_acct_hdl->radius_sess);
  	err = -EINVAL;
  	goto error;
  }

  if( radius_acct_hdl->tx_radius_mesg_on_the_fly == NULL ){
  	RHP_BUG("");
    goto ignored;
  }

  if( rx_radius_mesg->get_id(rx_radius_mesg)
  		!= radius_acct_hdl->tx_radius_mesg_on_the_fly->get_id(radius_acct_hdl->tx_radius_mesg_on_the_fly) ){
    goto ignored;
  }


  _rhp_radius_acct_del_mesg_from_tx_queue(radius_acct_hdl,radius_acct_hdl->tx_radius_mesg_on_the_fly);

	rhp_radius_mesg_unhold(radius_acct_hdl->tx_radius_mesg_on_the_fly);
	radius_acct_hdl->tx_radius_mesg_on_the_fly = NULL;


	if( radius_acct_hdl->tx_radius_mesg_q_head ){

		RHP_LOCK(&(radius_acct_hdl->radius_sess->lock));

		err = radius_acct_hdl->radius_sess->send_message(
						radius_acct_hdl->radius_sess,radius_acct_hdl->tx_radius_mesg_q_head);
		if( err ){
			// _rhp_radius_acct_mesg_destroy_user_priv() will be called later in rhp_radius_mesg_unhold().
			RHP_UNLOCK(&(radius_acct_hdl->radius_sess->lock));
			goto error;
		}

		RHP_UNLOCK(&(radius_acct_hdl->radius_sess->lock));

		radius_acct_hdl->tx_radius_mesg_on_the_fly = radius_acct_hdl->tx_radius_mesg_q_head;
		rhp_radius_mesg_hold(radius_acct_hdl->tx_radius_mesg_q_head);

	}else{

		// [CAUTION] Internally, radius_acct_hdl->radius_sess->lock is acquired.
		_rhp_radius_acct_session_close(radius_acct_hdl);
	}

  RHP_UNLOCK(&(radius_acct_hdl->lock));

  return;

error:
	if( radius_acct_hdl->radius_sess ){
		// [CAUTION] Internally, radius_acct_hdl->radius_sess->lock is acquired.
		_rhp_radius_acct_session_close(radius_acct_hdl);
	}

	if( radius_acct_hdl->tx_radius_mesg_on_the_fly ){
		rhp_radius_mesg_unhold(radius_acct_hdl->tx_radius_mesg_on_the_fly);
		radius_acct_hdl->tx_radius_mesg_on_the_fly = NULL;
	}

	_rhp_radius_acct_clear_tx_queue(radius_acct_hdl);

  RHP_UNLOCK(&(radius_acct_hdl->lock));

  RHP_TRC(0,RHPTRCID_RADIUS_ACCT_RECEIVE_RESPONSE_CB_RTRN,"xxE",radius_sess,radius_acct_hdl,err);
  return;

ignored:
	RHP_UNLOCK(&(radius_acct_hdl->lock));

  RHP_TRC(0,RHPTRCID_RADIUS_ACCT_RECEIVE_RESPONSE_CB_IGNORED,"xxE",radius_sess,radius_acct_hdl,err);
  return;
}


static rhp_radius_session* _rhp_radius_acct_open_session(
		rhp_radius_acct_handle* radius_acct_hdl,
		int use_secondary_server);


//
// _rhp_radius_acct_mesg_destroy_user_priv will be called later in rhp_radius_mesg_unhold().
//
static void _rhp_radius_acct_error_cb(rhp_radius_session* radius_sess,void* cb_ctx,
		rhp_radius_mesg* tx_radius_mesg,int cb_err)
{
	int err = -EINVAL;
	rhp_radius_acct_handle* radius_acct_hdl = (rhp_radius_acct_handle*)cb_ctx;

  RHP_TRC(0,RHPTRCID_RADIUS_ACCT_ERROR_CB,"xxxxE",radius_sess,cb_ctx,tx_radius_mesg,radius_acct_hdl,cb_err);

  RHP_LOCK(&(radius_acct_hdl->lock));

  RHP_TRC(0,RHPTRCID_RADIUS_ACCT_ERROR_CB_DATA,"xxxdd",radius_sess,radius_acct_hdl,radius_acct_hdl->radius_sess,radius_acct_hdl->secondary_server_configured,radius_acct_hdl->secondary_server_used);

  if( radius_acct_hdl->radius_sess == NULL ){
		err = 0;
    RHP_TRC(0,RHPTRCID_RADIUS_ACCT_ERROR_CB_NO_CTX_RADIUS_SESS,"xx",radius_sess,radius_acct_hdl);
  	goto ignored;
  }

  if( radius_acct_hdl->radius_sess != radius_sess ){
  	RHP_BUG("");
    RHP_TRC(0,RHPTRCID_RADIUS_ACCT_ERROR_CB_CTX_RADIUS_SESS_NOT_MATCH,"xxx",radius_sess,radius_acct_hdl,radius_acct_hdl->radius_sess);
  	err = -EINVAL;
  	goto error;
  }

  if( radius_acct_hdl->tx_radius_mesg_on_the_fly != tx_radius_mesg ){
  	RHP_BUG("");
  	err = -EINVAL;
    goto error;
  }

  if( cb_err == RHP_STATUS_RADIUS_RETX_REQ_ERR ||
  		cb_err == RHP_STATUS_DNS_RSLV_ERR ){

  	if( radius_acct_hdl->secondary_server_configured ){

			if( radius_acct_hdl->secondary_server_used ){

				RHP_LOCK(&rhp_eap_radius_cfg_lock);
				{
					_rhp_radius_acct_switch_primary_server(radius_acct_hdl,1);
				}
				RHP_UNLOCK(&rhp_eap_radius_cfg_lock);

				goto error;

			}else{

				rhp_radius_session* new_radius_sess;


				RHP_LOCK(&rhp_eap_radius_cfg_lock);
				{

					_rhp_radius_acct_switch_secondary_server(radius_acct_hdl);


					new_radius_sess = _rhp_radius_acct_open_session(radius_acct_hdl,1);
					if( new_radius_sess == NULL ){
						RHP_UNLOCK(&rhp_eap_radius_cfg_lock);
						goto error;
					}
				}
				RHP_UNLOCK(&rhp_eap_radius_cfg_lock);

				// [CAUTION] Internally, radius_acct_hdl->radius_sess->lock is acquired.
				_rhp_radius_acct_session_close(radius_acct_hdl);


				radius_acct_hdl->radius_sess = new_radius_sess;
				rhp_radius_sess_hold(radius_acct_hdl->radius_sess);

				RHP_LOCK(&(radius_acct_hdl->radius_sess->lock));

				err = radius_acct_hdl->radius_sess->send_message(
								radius_acct_hdl->radius_sess,tx_radius_mesg);
				if( err ){

					// _rhp_radius_acct_mesg_destroy_user_priv() will be called later in rhp_radius_mesg_unhold().

					RHP_UNLOCK(&(radius_acct_hdl->radius_sess->lock));

					goto error;
				}

				RHP_UNLOCK(&(radius_acct_hdl->radius_sess->lock));

				goto try_secondary;
			}
  	}
  }


error:
	if( radius_acct_hdl->radius_sess ){
		// [CAUTION] Internally, radius_acct_hdl->radius_sess->lock is acquired.
		_rhp_radius_acct_session_close(radius_acct_hdl);
	}

	if( radius_acct_hdl->tx_radius_mesg_on_the_fly ){
		rhp_radius_mesg_unhold(radius_acct_hdl->tx_radius_mesg_on_the_fly);
		radius_acct_hdl->tx_radius_mesg_on_the_fly = NULL;
	}

	_rhp_radius_acct_clear_tx_queue(radius_acct_hdl);

  RHP_UNLOCK(&(radius_acct_hdl->lock));

  RHP_TRC(0,RHPTRCID_RADIUS_ACCT_ERROR_CB_RTRN,"xxE",radius_sess,radius_acct_hdl,err);
  return;

ignored:
try_secondary:
	RHP_UNLOCK(&(radius_acct_hdl->lock));

  RHP_TRC(0,RHPTRCID_RADIUS_ACCT_ERROR_CB_IGNORED,"xxE",radius_sess,radius_acct_hdl,err);
  return;
}

static rhp_radius_session* _rhp_radius_acct_open_session(
		rhp_radius_acct_handle* radius_acct_hdl,
		int use_secondary_server)
{
	int err = -EINVAL;
	rhp_radius_session* radius_sess = NULL;
	rhp_ip_addr *server_addr_port_p = NULL, *nas_addr_p = NULL;
	char* server_fqdn_p = NULL;

  RHP_TRC(0,RHPTRCID_RADIUS_ACCT_OPEN_SESSION,"xds",radius_acct_hdl,use_secondary_server,rhp_gcfg_radius_acct->server_secondary_fqdn);
  rhp_ip_addr_dump("server_secondary_addr_port",&(rhp_gcfg_radius_acct->server_secondary_addr_port));

	if( !rhp_ip_addr_null(&(rhp_gcfg_radius_acct->server_secondary_addr_port)) ||
  		rhp_gcfg_radius_acct->server_secondary_fqdn ){

		radius_acct_hdl->secondary_server_configured = 1;

  	_rhp_radius_acct_switch_primary_server(radius_acct_hdl,0);

  	if( !use_secondary_server ){

  		use_secondary_server = _rhp_radius_acct_use_secondary_server(radius_acct_hdl);
  	}


  	if( use_secondary_server ){

			server_addr_port_p = &(rhp_gcfg_radius_acct->server_secondary_addr_port);
			server_fqdn_p = rhp_gcfg_radius_acct->server_secondary_fqdn;
			nas_addr_p = &(rhp_gcfg_radius_acct->nas_secondary_addr);

  	}else{

  		server_addr_port_p = &(rhp_gcfg_radius_acct->server_addr_port);
			server_fqdn_p = rhp_gcfg_radius_acct->server_fqdn;
			nas_addr_p = &(rhp_gcfg_radius_acct->nas_addr);
		}

	}else{

		radius_acct_hdl->secondary_server_configured = 0;

		if( use_secondary_server ){
			err = -EINVAL;
			goto error;
		}

		server_addr_port_p = &(rhp_gcfg_radius_acct->server_addr_port);
		server_fqdn_p = rhp_gcfg_radius_acct->server_fqdn;
		nas_addr_p = &(rhp_gcfg_radius_acct->nas_addr);
	}

	//
	// Copy needed config to the ctx object.
	//
  if( rhp_ip_addr_null(server_addr_port_p) && server_fqdn_p == NULL ){
  	RHP_BUG("");
		err = -EINVAL;
		goto error;
  }



	radius_sess = rhp_radius_session_open(
									RHP_RADIUS_USAGE_ACCOUNTING,
									server_addr_port_p,server_fqdn_p,
									_rhp_radius_acct_receive_response_cb,_rhp_radius_acct_error_cb,
									radius_acct_hdl);

	if( radius_sess ){

		if( !rhp_ip_addr_null(nas_addr_p) ){

			err = radius_sess->set_nas_addr(radius_sess,nas_addr_p);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}
		}


		if( !use_secondary_server ){
			radius_sess->set_secret_index(radius_sess,RHP_RADIUS_SECRET_IDX_ACCT_PRIMARY);
		}else{
			radius_sess->set_secret_index(radius_sess,RHP_RADIUS_SECRET_IDX_ACCT_SECONDARY);
		}

		if( rhp_gcfg_radius_acct->connect_info ){

			radius_sess->set_connect_info(radius_sess,rhp_gcfg_radius_acct->connect_info);
		}


		radius_sess->include_nas_port_type(radius_sess,1);

		if( rhp_gcfg_radius_acct->retransmit_interval ){

			radius_sess->set_retransmit_interval(radius_sess,
					(time_t)rhp_gcfg_radius_acct->retransmit_interval);
		}

		if( rhp_gcfg_radius_acct->retransmit_times ){

			radius_sess->set_retransmit_times(radius_sess,
					rhp_gcfg_radius_acct->retransmit_times);
		}

	}else{
		RHP_BUG("");
		goto error;
	}

  RHP_TRC(0,RHPTRCID_RADIUS_ACCT_OPEN_SESSION_RTRN,"xxdd",radius_acct_hdl,radius_sess,use_secondary_server,radius_acct_hdl->secondary_server_configured);

  return radius_sess;

error:
	if( radius_sess ){
		rhp_radius_session_close(radius_sess);
	}
  RHP_TRC(0,RHPTRCID_RADIUS_ACCT_OPEN_SESSION_ERR,"xxE",radius_acct_hdl,radius_sess,err);
	return NULL;
}

rhp_radius_mesg* _rhp_radius_acct_new_tx_mesg(rhp_vpn* vpn,rhp_radius_acct_handle* radius_acct_hdl,
		int status,int term_cause)
{
	int err = -EINVAL;
	rhp_radius_mesg* radius_mesg = NULL;
	rhp_radius_attr* radius_attr = NULL;
	rhp_radius_session* radius_sess = radius_acct_hdl->radius_sess;

	RHP_TRC(0,RHPTRCID_RADIUS_ACCT_NEW_TX_MESG,"xxxLdLd",vpn,radius_acct_hdl,radius_acct_hdl->radius_sess,"RADIUS_ACCT_STAT",status,"RADIUS_ACCT_TERM_CAUSE",term_cause);

	radius_mesg = rhp_radius_new_mesg_tx(RHP_RADIUS_CODE_ACCT_REQUEST,0);
	if( radius_mesg == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}


	{
		err = rhp_radius_new_attr_tx(radius_sess,radius_mesg,
				RHP_RADIUS_ATTR_TYPE_USER_NAME,0,&radius_attr);
		if( err ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		radius_mesg->put_attr(radius_mesg,radius_attr);

		if( rhp_eap_id_is_null(&(vpn->eap.peer_id)) ){

			char* id_type = NULL;
			char* id_str = NULL;

			err = rhp_ikev2_id_to_string(&(vpn->peer_id),&id_type,&id_str);
			if( err ){
				goto error;
			}

			err = radius_attr->ext.basic->set_attr_value(radius_attr,
							strlen(id_str),(u8*)id_str);
			if( err ){
				_rhp_free(id_type);
				_rhp_free(id_str);
				goto error;
			}

		  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_ACCT_ATTR_USER_NAME_IKEV2_ID_TX,"VrLLs",vpn,radius_acct_hdl->radius_sess,"RADIUS_CODE",(int)radius_mesg->get_code(radius_mesg),"RADIUS_ATTR",(int)radius_attr->get_attr_type(radius_attr),id_str);

			_rhp_free(id_type);
			_rhp_free(id_str);

		}else{

			char* eap_id_method = NULL;
			char* eap_id_str = NULL;

			err = rhp_eap_id_to_string(&(vpn->eap.peer_id),&eap_id_method,&eap_id_str);
			if( err ){
				goto error;
			}

			err = radius_attr->ext.basic->set_attr_value(radius_attr,
							strlen(eap_id_str),(u8*)eap_id_str);
			if( err ){
				_rhp_free(eap_id_method);
				_rhp_free(eap_id_str);
				goto error;
			}

		  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_ACCT_ATTR_USER_NAME_EAP_ID_TX,"VrLLs",vpn,radius_acct_hdl->radius_sess,"RADIUS_CODE",(int)radius_mesg->get_code(radius_mesg),"RADIUS_ATTR",(int)radius_attr->get_attr_type(radius_attr),eap_id_str);

			_rhp_free(eap_id_method);
			_rhp_free(eap_id_str);
		}
	}


	if( rhp_gcfg_radius_acct->nas_id ){

		err = rhp_radius_new_attr_tx(radius_sess,radius_mesg,
						RHP_RADIUS_ATTR_TYPE_NAS_ID,0,&radius_attr);
		if( err ){
			goto error;
		}

		radius_mesg->put_attr_head(radius_mesg,radius_attr);

		err = radius_attr->ext.basic->set_attr_value(radius_attr,
						strlen(rhp_gcfg_radius_acct->nas_id),(u8*)rhp_gcfg_radius_acct->nas_id);
		if( err ){
			goto error;
		}

	  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_ACCT_ATTR_NAS_ID_TX,"VrLLs",vpn,radius_acct_hdl->radius_sess,"RADIUS_CODE",(int)radius_mesg->get_code(radius_mesg),"RADIUS_ATTR",(int)radius_attr->get_attr_type(radius_attr),rhp_gcfg_radius_acct->nas_id);

	}else if( rhp_gcfg_radius_acct->tx_nas_id_as_ikev2_id_enabled &&
						vpn->my_id.type != RHP_PROTO_IKE_ID_ANY &&
						!rhp_ikev2_is_null_auth_id(vpn->my_id.type) ){

		char *id_type,*id_str;
		int id_str_len;

		err = rhp_ikev2_id_to_string(&(vpn->my_id),&id_type,&id_str);
		if( err ){
      RHP_BUG("");
      goto error;
		}
		id_str_len = strlen(id_str);
		if( id_str_len > RHP_RADIUS_ATTR_VAL_MAX_LEN ){
			id_str_len = RHP_RADIUS_ATTR_VAL_MAX_LEN;
		}

		err = rhp_radius_new_attr_tx(radius_sess,radius_mesg,
						RHP_RADIUS_ATTR_TYPE_NAS_ID,0,&radius_attr);
		if( err ){
			_rhp_free(id_type);
			_rhp_free(id_str);
			goto error;
		}

		radius_mesg->put_attr(radius_mesg,radius_attr);

		err = radius_attr->ext.basic->set_attr_value(radius_attr,
						id_str_len,(u8*)id_str);
		if( err ){
			_rhp_free(id_type);
			_rhp_free(id_str);
			goto error;
		}

	  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_ACCT_ATTR_NAS_ID_IKEV2_ID_TX,"VrLLs",vpn,radius_acct_hdl->radius_sess,"RADIUS_CODE",(int)radius_mesg->get_code(radius_mesg),"RADIUS_ATTR",(int)radius_attr->get_attr_type(radius_attr),id_str);

		_rhp_free(id_type);
		_rhp_free(id_str);
	}


	{
		char* client_ip_port = rhp_ip_port_string(&(vpn->peer_addr));
		if( client_ip_port ){

			err = rhp_radius_new_attr_tx(radius_sess,radius_mesg,
							RHP_RADIUS_ATTR_TYPE_CALLING_STATION_ID,0,&radius_attr);
			if( err ){
				goto error;
			}

			radius_mesg->put_attr(radius_mesg,radius_attr);

			err = radius_attr->ext.basic->set_attr_value(radius_attr,
							strlen(client_ip_port),(u8*)client_ip_port);
			if( err ){
				goto error;
			}

		  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_ACCT_ATTR_CALLING_STATION_ID_TX,"VrLLs",vpn,radius_acct_hdl->radius_sess,"RADIUS_CODE",(int)radius_mesg->get_code(radius_mesg),"RADIUS_ATTR",(int)radius_attr->get_attr_type(radius_attr),client_ip_port);

			_rhp_free(client_ip_port);
		}
	}


	{
		u32 status_val = htonl((u32)status);

		err = rhp_radius_new_attr_tx(radius_sess,radius_mesg,
				RHP_RADIUS_ATTR_TYPE_ACCT_STATUS_TYPE,0,&radius_attr);
		if( err ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		radius_mesg->put_attr(radius_mesg,radius_attr);

		err = radius_attr->ext.basic->set_attr_value(radius_attr,
						sizeof(u32),(u8*)&status_val);
		if( err ){
			goto error;
		}

	  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_ACCT_ATTR_STATUS_TYPE_TX,"VrLLL",vpn,radius_acct_hdl->radius_sess,"RADIUS_CODE",(int)radius_mesg->get_code(radius_mesg),"RADIUS_ATTR",(int)radius_attr->get_attr_type(radius_attr),"RADIUS_ACCT_STAT",ntohl(status_val));
	}

	{
		char* acct_sess_id = rhp_radius_acct_get_session_id_str(vpn);

		if( acct_sess_id == NULL ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		err = rhp_radius_new_attr_tx(radius_sess,radius_mesg,
						RHP_RADIUS_ATTR_TYPE_ACCT_SESSION_ID,0,&radius_attr);
		if( err ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		radius_mesg->put_attr(radius_mesg,radius_attr);

		err = radius_attr->ext.basic->set_attr_value(radius_attr,
						strlen(acct_sess_id),(u8*)acct_sess_id);
		if( err ){
			goto error;
		}

	  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_ACCT_ATTR_SESSION_ID_TX,"VrLLs",vpn,radius_acct_hdl->radius_sess,"RADIUS_CODE",(int)radius_mesg->get_code(radius_mesg),"RADIUS_ATTR",(int)radius_attr->get_attr_type(radius_attr),acct_sess_id);

		_rhp_free(acct_sess_id);
	}

	{
		u32 authentic;

		if( vpn->eap.eap_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS ){
			authentic = htonl(RHP_RADIUS_ATTR_TYPE_ACCT_AUTHENTIC_RADIUS);
		}else{
			authentic = htonl(RHP_RADIUS_ATTR_TYPE_ACCT_AUTHENTIC_LOCAL);
		}

		err = rhp_radius_new_attr_tx(radius_sess,radius_mesg,
						RHP_RADIUS_ATTR_TYPE_ACCT_AUTHENTIC,0,&radius_attr);
		if( err ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		radius_mesg->put_attr(radius_mesg,radius_attr);

		err = radius_attr->ext.basic->set_attr_value(radius_attr,
						sizeof(u32),(u8*)&authentic);
		if( err ){
			goto error;
		}

	  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_ACCT_ATTR_AUTHENTIC_TX,"VrLLL",vpn,radius_acct_hdl->radius_sess,"RADIUS_CODE",(int)radius_mesg->get_code(radius_mesg),"RADIUS_ATTR",(int)radius_attr->get_attr_type(radius_attr),"RADIUS_ACCT_AUTHENTIC",ntohl(authentic));
	}

	if( status == RHP_RADIUS_ATTR_TYPE_ACCT_STATUS_STOP ){

		if( !term_cause ){
			term_cause = RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_NAS_ERROR;
		}

		{
			u32 term_cause_val = htonl((u32)term_cause);

			err = rhp_radius_new_attr_tx(radius_sess,radius_mesg,
					RHP_RADIUS_ATTR_TYPE_ACCT_TERMINATE_CAUSE,0,&radius_attr);
			if( err ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			radius_mesg->put_attr(radius_mesg,radius_attr);

			err = radius_attr->ext.basic->set_attr_value(radius_attr,
							sizeof(u32),(u8*)&term_cause_val);
			if( err ){
				goto error;
			}

		  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_ACCT_ATTR_TERMINATE_CAUSE_TX,"VrLLL",vpn,radius_acct_hdl->radius_sess,"RADIUS_CODE",(int)radius_mesg->get_code(radius_mesg),"RADIUS_ATTR",(int)radius_attr->get_attr_type(radius_attr),"RADIUS_ACCT_TERM_CAUSE",ntohl(term_cause_val));
		}

		{
			u32 sess_time =  htonl((u32)(_rhp_get_time() - vpn->created));

			err = rhp_radius_new_attr_tx(radius_sess,radius_mesg,
					RHP_RADIUS_ATTR_TYPE_ACCT_SESSION_TIME,0,&radius_attr);
			if( err ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			radius_mesg->put_attr(radius_mesg,radius_attr);

			err = radius_attr->ext.basic->set_attr_value(radius_attr,
							sizeof(u32),(u8*)&sess_time);
			if( err ){
				goto error;
			}

		  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_ACCT_ATTR_SESSION_TIME_TX,"VrLLJ",vpn,radius_acct_hdl->radius_sess,"RADIUS_CODE",(int)radius_mesg->get_code(radius_mesg),"RADIUS_ATTR",(int)radius_attr->get_attr_type(radius_attr),sess_time);
		}

		{
			u32 in_bytes =  htonl((u32)vpn->statistics.rx_esp_bytes);

			err = rhp_radius_new_attr_tx(radius_sess,radius_mesg,
					RHP_RADIUS_ATTR_TYPE_ACCT_INPUT_OCTETS,0,&radius_attr);
			if( err ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			radius_mesg->put_attr(radius_mesg,radius_attr);

			err = radius_attr->ext.basic->set_attr_value(radius_attr,
							sizeof(u32),(u8*)&in_bytes);
			if( err ){
				goto error;
			}

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_ACCT_ATTR_INPUT_OCTETS_TX,"VrLLJ",vpn,radius_acct_hdl->radius_sess,"RADIUS_CODE",(int)radius_mesg->get_code(radius_mesg),"RADIUS_ATTR",(int)radius_attr->get_attr_type(radius_attr),in_bytes);
		}

		{
			u32 out_bytes =  htonl((u32)vpn->statistics.tx_esp_bytes);

			err = rhp_radius_new_attr_tx(radius_sess,radius_mesg,
					RHP_RADIUS_ATTR_TYPE_ACCT_OUTPUT_OCTETS,0,&radius_attr);
			if( err ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			radius_mesg->put_attr(radius_mesg,radius_attr);

			err = radius_attr->ext.basic->set_attr_value(radius_attr,
							sizeof(u32),(u8*)&out_bytes);
			if( err ){
				goto error;
			}

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_ACCT_ATTR_OUTPUT_OCTETS_TX,"VrLLJ",vpn,radius_acct_hdl->radius_sess,"RADIUS_CODE",(int)radius_mesg->get_code(radius_mesg),"RADIUS_ATTR",(int)radius_attr->get_attr_type(radius_attr),out_bytes);
		}


		{
			u32 in_pkts =  htonl((u32)vpn->statistics.rx_esp_packets);

			err = rhp_radius_new_attr_tx(radius_sess,radius_mesg,
					RHP_RADIUS_ATTR_TYPE_ACCT_INPUT_PACKETS,0,&radius_attr);
			if( err ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			radius_mesg->put_attr(radius_mesg,radius_attr);

			err = radius_attr->ext.basic->set_attr_value(radius_attr,
							sizeof(u32),(u8*)&in_pkts);
			if( err ){
				goto error;
			}

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_ACCT_ATTR_INPUT_PACKETS_TX,"VrLLJ",vpn,radius_acct_hdl->radius_sess,"RADIUS_CODE",(int)radius_mesg->get_code(radius_mesg),"RADIUS_ATTR",(int)radius_attr->get_attr_type(radius_attr),in_pkts);
		}

		{
			u32 out_pkts =  htonl((u32)vpn->statistics.tx_esp_packets);

			err = rhp_radius_new_attr_tx(radius_sess,radius_mesg,
					RHP_RADIUS_ATTR_TYPE_ACCT_OUTPUT_PACKETS,0,&radius_attr);
			if( err ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			radius_mesg->put_attr(radius_mesg,radius_attr);

			err = radius_attr->ext.basic->set_attr_value(radius_attr,
							sizeof(u32),(u8*)&out_pkts);
			if( err ){
				goto error;
			}

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RADIUS_ACCT_ATTR_OUTPUT_PACKETS_TX,"VrLLJ",vpn,radius_acct_hdl->radius_sess,"RADIUS_CODE",(int)radius_mesg->get_code(radius_mesg),"RADIUS_ATTR",(int)radius_attr->get_attr_type(radius_attr),out_pkts);
		}
	}

	RHP_TRC(0,RHPTRCID_RADIUS_ACCT_NEW_TX_MESG_RTRN,"xxx",vpn,radius_acct_hdl,radius_mesg);
	return radius_mesg;

error:
	if( radius_mesg ){
		rhp_radius_mesg_unhold(radius_mesg);
	}
	RHP_TRC(0,RHPTRCID_RADIUS_ACCT_NEW_TX_MESG_ERR,"xxE",vpn,radius_acct_hdl,err);
	return NULL;
}


struct _rhp_radius_acct_send_ctx {
	rhp_vpn_ref* vpn_ref;
	int status;
	int term_cause;
};
typedef struct _rhp_radius_acct_send_ctx	rhp_radius_acct_send_ctx;

static void _rhp_radius_acct_send_task(int worker_index,void *cb_ctx)
{
	int err = -EINVAL;
	rhp_radius_acct_send_ctx* ctx = (rhp_radius_acct_send_ctx*)cb_ctx;
	rhp_vpn* vpn = RHP_VPN_REF(ctx->vpn_ref);
	int idx = _rhp_radius_acct_get_handle_index();
	rhp_radius_acct_handle* radius_acct_hdl = NULL;
	rhp_radius_mesg* tx_radius_mesg = NULL;

	RHP_TRC(0,RHPTRCID_RADIUS_ACCT_SEND_TASK,"xxxdLdLd",ctx,ctx->vpn_ref,vpn,idx,"RADIUS_ACCT_STAT",ctx->status,"RADIUS_ACCT_TERM_CAUSE",ctx->term_cause);

	RHP_LOCK(&(vpn->lock));

	//
	// [CAUTION]
	//
	// vpn may be already deactivated by rhp_vpn_destroy() if ctx->status is STOP.
	//
	//

	if( ctx->status == RHP_RADIUS_ATTR_TYPE_ACCT_STATUS_START &&
			!_rhp_atomic_read(&(vpn->is_active))){
		err = -EINVAL;
		RHP_TRC(0,RHPTRCID_RADIUS_ACCT_SEND_TASK_VPN_NOT_ACTIVE,"xx",ctx,vpn);
		goto error;
	}

	if( vpn->peer_id.type == RHP_PROTO_IKE_ID_ANY ||
			vpn->peer_id.type == RHP_PROTO_IKE_ID_NULL_ID ){
		err = -EINVAL;
		RHP_TRC(0,RHPTRCID_RADIUS_ACCT_SEND_TASK_VPN_NO_PEER_ID,"xx",ctx,vpn);
		goto error;
	}


	radius_acct_hdl = &(_rhp_radius_acct_handles[idx]);

	RHP_LOCK(&(_rhp_radius_acct_handles[idx].lock));

	if( radius_acct_hdl->tx_radius_mesg_q_num > rhp_gcfg_radius_acct_max_queued_tx_messages ){
		err = RHP_STATUS_RADIUS_ACCT_MAX_QUEUED_MESGS_REACHED;
		RHP_TRC(0,RHPTRCID_RADIUS_ACCT_SEND_TASK_MAX_TX_Q_REACHED,"xxx",ctx,vpn,radius_acct_hdl);
		goto error;
	}


	RHP_LOCK(&rhp_eap_radius_cfg_lock);


	if( !rhp_gcfg_radius_acct->enabled ){
		RHP_UNLOCK(&rhp_eap_radius_cfg_lock);
		err = -EINVAL;
		RHP_TRC(0,RHPTRCID_RADIUS_ACCT_SEND_TASK_RADIUS_ACCT_DISABLED,"xxx",ctx,vpn,radius_acct_hdl);
		goto error;
	}


	if( radius_acct_hdl->radius_sess == NULL ){

		radius_acct_hdl->radius_sess = _rhp_radius_acct_open_session(radius_acct_hdl,0);
		if( radius_acct_hdl->radius_sess == NULL ){
			RHP_UNLOCK(&rhp_eap_radius_cfg_lock);
			err = -EINVAL;
			RHP_TRC(0,RHPTRCID_RADIUS_ACCT_SEND_TASK_OPEN_SESSION_ERR,"xxx",ctx,vpn,radius_acct_hdl);
			goto error;
		}
		rhp_radius_sess_hold(radius_acct_hdl->radius_sess);
	}

	tx_radius_mesg = _rhp_radius_acct_new_tx_mesg(vpn,radius_acct_hdl,
										ctx->status,ctx->term_cause);
	if( tx_radius_mesg == NULL ){
		RHP_UNLOCK(&rhp_eap_radius_cfg_lock);
		err = -ENOMEM;
		RHP_TRC(0,RHPTRCID_RADIUS_ACCT_SEND_TASK_ALLOC_TX_MESG_ERR,"xxx",ctx,vpn,radius_acct_hdl);
		goto error;
	}

	RHP_UNLOCK(&rhp_eap_radius_cfg_lock);


	if( radius_acct_hdl->tx_radius_mesg_on_the_fly == NULL ){

		err = radius_acct_hdl->radius_sess->send_message(
						radius_acct_hdl->radius_sess,tx_radius_mesg);
		if( err ){
			// _rhp_radius_acct_mesg_destroy_user_priv() will be called later in rhp_radius_mesg_unhold().
			RHP_TRC(0,RHPTRCID_RADIUS_ACCT_SEND_TASK_TX_MESG_ERR,"xxxxxE",ctx,vpn,radius_acct_hdl,radius_acct_hdl->radius_sess,tx_radius_mesg,err);
			goto error;
		}

		radius_acct_hdl->tx_radius_mesg_on_the_fly = tx_radius_mesg;
		rhp_radius_mesg_hold(tx_radius_mesg);
	}


	if( radius_acct_hdl->tx_radius_mesg_q_head == NULL ){
		radius_acct_hdl->tx_radius_mesg_q_head = tx_radius_mesg;
	}else{
		radius_acct_hdl->tx_radius_mesg_q_tail->next = tx_radius_mesg;
	}
	radius_acct_hdl->tx_radius_mesg_q_tail = tx_radius_mesg;
	rhp_radius_mesg_hold(tx_radius_mesg);

	radius_acct_hdl->tx_radius_mesg_q_num++;


	RHP_UNLOCK(&(_rhp_radius_acct_handles[idx].lock));


	rhp_radius_mesg_unhold(tx_radius_mesg);

	RHP_UNLOCK(&(vpn->lock));
	rhp_vpn_unhold(ctx->vpn_ref);
	_rhp_free(ctx);

	RHP_TRC(0,RHPTRCID_RADIUS_ACCT_SEND_TASK_RTRN,"xxx",ctx,vpn,radius_acct_hdl);
	return;

error:
	if( radius_acct_hdl ){
		RHP_UNLOCK(&(_rhp_radius_acct_handles[idx].lock));
	}

	if( tx_radius_mesg ){
		rhp_radius_mesg_unhold(tx_radius_mesg);
	}

	RHP_UNLOCK(&(vpn->lock));
	rhp_vpn_unhold(ctx->vpn_ref);
	_rhp_free(ctx);

	RHP_TRC(0,RHPTRCID_RADIUS_ACCT_SEND_TASK_ERR,"xxxE",ctx,vpn,radius_acct_hdl,err);
	return;
}

// status: RHP_RADIUS_ATTR_TYPE_ACCT_STATUS_XXX
// term_cause: RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_XXX
int rhp_radius_acct_send(rhp_vpn* vpn,int status,int term_cause)
{
	int err = -EINVAL;
	rhp_radius_acct_send_ctx* ctx = NULL;

	RHP_TRC(0,RHPTRCID_RADIUS_ACCT_SEND,"xLdLd",vpn,"RADIUS_ACCT_STAT",status,"RADIUS_ACCT_STAT",term_cause);

	ctx = (rhp_radius_acct_send_ctx*)_rhp_malloc(sizeof(rhp_radius_acct_send_ctx));
	if( ctx == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memset(ctx,0,sizeof(rhp_radius_acct_send_ctx));

	ctx->vpn_ref = rhp_vpn_hold_ref(vpn);
	ctx->status = status;
	ctx->term_cause = term_cause;


	err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_2,_rhp_radius_acct_send_task,ctx);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	RHP_TRC(0,RHPTRCID_RADIUS_ACCT_SEND_RTRN,"xx",vpn,ctx);
	return 0;

error:
	if( ctx ){
		rhp_vpn_unhold(ctx->vpn_ref);
		_rhp_free(ctx);
	}
	RHP_TRC(0,RHPTRCID_RADIUS_ACCT_SEND_ERR,"xE",vpn,err);
	return err;
}


static time_t _rhp_radius_acct_boot_time = 0;

char* rhp_radius_acct_get_session_id_str(rhp_vpn* vpn)
{
	char* ret = (char*)_rhp_malloc(64);

	if( ret ){

		snprintf(ret,64,"%lx-%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
				(u_int64_t)_rhp_radius_acct_boot_time,
				(((u_int8_t*)vpn->unique_id)[0]), (((u_int8_t*)vpn->unique_id)[1]),
				(((u_int8_t*)vpn->unique_id)[2]), (((u_int8_t*)vpn->unique_id)[3]),
				(((u_int8_t*)vpn->unique_id)[4]), (((u_int8_t*)vpn->unique_id)[5]),
				(((u_int8_t*)vpn->unique_id)[6]), (((u_int8_t*)vpn->unique_id)[7]),
				(((u_int8_t*)vpn->unique_id)[8]), (((u_int8_t*)vpn->unique_id)[9]),
				(((u_int8_t*)vpn->unique_id)[10]), (((u_int8_t*)vpn->unique_id)[11]),
				(((u_int8_t*)vpn->unique_id)[12]), (((u_int8_t*)vpn->unique_id)[13]),
				(((u_int8_t*)vpn->unique_id)[14]), (((u_int8_t*)vpn->unique_id)[15]));

	}else{

		RHP_BUG("");
	}

	RHP_TRC(0,RHPTRCID_RADIUS_ACCT_GET_SESSION_ID_STR,"s",ret);
	return ret;
}


int rhp_radius_acct_init()
{
	int i;

	_rhp_mutex_init("RAC",&_rhp_radius_acct_lock);

	_rhp_radius_acct_handles = _rhp_malloc(sizeof(rhp_radius_acct_handle)*rhp_gcfg_radius_acct_max_sessions);
	if( _rhp_radius_acct_handles == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	memset(_rhp_radius_acct_handles,0,sizeof(rhp_radius_acct_handle));

	for(i = 0; i < rhp_gcfg_radius_acct_max_sessions; i++){

		rhp_radius_acct_handle* radius_acct_hdl = &(_rhp_radius_acct_handles[i]);

		radius_acct_hdl->tag[0] = '#';
		radius_acct_hdl->tag[1] = 'R';
		radius_acct_hdl->tag[2] = 'A';
		radius_acct_hdl->tag[3] = 'H';

		radius_acct_hdl->idx = i;

		_rhp_mutex_init("RAC",&(radius_acct_hdl->lock));
	}

	_rhp_radius_acct_boot_time = _rhp_get_realtime();

	return 0;
}

int rhp_radius_acct_cleanup()
{
	int i;

	for(i = 0; i < rhp_gcfg_radius_acct_max_sessions; i++){

		rhp_radius_acct_handle* radius_acct_hdl = &(_rhp_radius_acct_handles[i]);

		_rhp_mutex_destroy(&(radius_acct_hdl->lock));
	}
	_rhp_free(_rhp_radius_acct_handles);


	_rhp_mutex_destroy(&_rhp_radius_acct_lock);
	return 0;
}


