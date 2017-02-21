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

static rhp_mutex_t _rhp_ikev2_qcd_lock;

static time_t _rhp_ikev2_qcd_req_last_rx_time;
static time_t _rhp_ikev2_qcd_rep_last_rx_time;

#define RHP_IKEV2_QCD_PER_SECS_INTERVAL	1
static long _rhp_ikev2_qcd_req_rx_per_secs = 0;
static long _rhp_ikev2_qcd_rep_rx_per_secs = 0;


static rhp_atomic_t _rhp_ikev2_qcd_pend_pkts;
static rhp_atomic_t _rhp_ikev2_qcd_pend_pkts2;

static time_t _rhp_ikev2_qcd_boot_time;

struct _rhp_ikev2_qcd_ipc_req_cookie
{
	unsigned int addr_family;
	union {
		rhp_proto_ip_v4 v4;
		rhp_proto_ip_v6 v6;
	} rx_req_iph;
	rhp_proto_udp rx_req_udph;
	rhp_proto_ike rx_req_ikeh;
	unsigned int rx_if_idx;
};
typedef struct _rhp_ikev2_qcd_ipc_req_cookie	rhp_ikev2_qcd_ipc_req_cookie;

static void _rhp_ikev2_qcd_rx_invalid_ikesa_spi_req_task(rhp_packet* rx_pkt)
{
	rhp_ipcmsg_qcd_gen_rep_tkn_req* ipc_req = NULL;
	rhp_ikev2_qcd_ipc_req_cookie* cookie;

	RHP_TRC(0,RHPTRCID_IKEV2_QCD_RX_INVALID_IKESA_SPI_REQ_TASK,"x",rx_pkt);

	ipc_req = (rhp_ipcmsg_qcd_gen_rep_tkn_req*)rhp_ipc_alloc_msg(
							RHP_IPC_QCD_GEN_REPLY_TOKEN_REQUEST,
							sizeof(rhp_ipcmsg_qcd_gen_rep_tkn_req) + sizeof(rhp_ikev2_qcd_ipc_req_cookie));

	if( ipc_req == NULL ){
		RHP_BUG("");
		goto error;
	}

	ipc_req->len = sizeof(rhp_ipcmsg_qcd_gen_rep_tkn_req) + sizeof(rhp_ikev2_qcd_ipc_req_cookie);

	memcpy(ipc_req->init_spi,rx_pkt->app.ikeh->init_spi,RHP_PROTO_IKE_SPI_SIZE);
	memcpy(ipc_req->resp_spi,rx_pkt->app.ikeh->resp_spi,RHP_PROTO_IKE_SPI_SIZE);


	cookie = (rhp_ikev2_qcd_ipc_req_cookie*)(ipc_req + 1);
	ipc_req->cookie_len = sizeof(rhp_ikev2_qcd_ipc_req_cookie);

	if( rx_pkt->type == RHP_PKT_IPV4_IKE ){

		cookie->addr_family = AF_INET;
		memcpy(&(cookie->rx_req_iph.v4),rx_pkt->l3.iph_v4,sizeof(rhp_proto_ip_v4));

	}else if( rx_pkt->type == RHP_PKT_IPV6_IKE ){

		cookie->addr_family = AF_INET6;
		memcpy(&(cookie->rx_req_iph.v6),rx_pkt->l3.iph_v6,sizeof(rhp_proto_ip_v6));
	}

	memcpy(&(cookie->rx_req_udph),rx_pkt->l4.udph,sizeof(rhp_proto_udp));

	memcpy(&(cookie->rx_req_ikeh),rx_pkt->app.ikeh,sizeof(rhp_proto_ike));

	cookie->rx_if_idx = rx_pkt->rx_ifc->if_index;


	if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipc_req,ipc_req->len,0) < 0 ){
		RHP_BUG("");
		goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_QCD_RX_INVALID_IKESA_SPI_REQ_TASK_IPC_TX_DATA,"xGGpppd",rx_pkt,ipc_req->init_spi,ipc_req->resp_spi,sizeof(rhp_proto_ip_v4),&(cookie->rx_req_iph),sizeof(rhp_proto_udp),&(cookie->rx_req_udph),sizeof(rhp_proto_ike),&(cookie->rx_req_ikeh),cookie->rx_if_idx);

	_rhp_free_zero(ipc_req,ipc_req->len);

error:
	rhp_pkt_unhold(rx_pkt);
  _rhp_atomic_dec(&_rhp_ikev2_qcd_pend_pkts);

  RHP_TRC(0,RHPTRCID_IKEV2_QCD_RX_INVALID_IKESA_SPI_REQ_TASK_RTRN,"x",rx_pkt);
  return;
}

static int _rhp_ikev2_qcd_rx_packets_rate_limit(int rx_req)
{
	time_t now;
	time_t* rx_time;
	long* rx_per_secs;
	int cfg_lmt;

	if( rx_req ){
		rx_time = &_rhp_ikev2_qcd_req_last_rx_time;
		rx_per_secs = &_rhp_ikev2_qcd_req_rx_per_secs;
		cfg_lmt = rhp_gcfg_ikev2_qcd_max_rx_packets_per_sec;
	}else{
		rx_time = &_rhp_ikev2_qcd_rep_last_rx_time;
		rx_per_secs = &_rhp_ikev2_qcd_rep_rx_per_secs;
		cfg_lmt = rhp_gcfg_ikev2_qcd_max_rx_err_per_sec;
	}

	now = _rhp_get_time();

	RHP_TRC(0,RHPTRCID_IKEV2_QCD_RX_PACKETS_RATE_LIMIT,"dffdf",rx_req,*rx_time,*rx_per_secs,cfg_lmt,now);

  RHP_LOCK(&_rhp_ikev2_qcd_lock);

	if( *rx_time + RHP_IKEV2_QCD_PER_SECS_INTERVAL < now ){

		*rx_time = now;
		*rx_per_secs = 0;

	}else{

		(*rx_per_secs)++;

  	if( *rx_per_secs > cfg_lmt ){
  		RHP_UNLOCK(&_rhp_ikev2_qcd_lock);
  		RHP_TRC(0,RHPTRCID_IKEV2_QCD_RX_PACKETS_RATE_LIMIT_NG,"dffd",rx_req,*rx_time,*rx_per_secs,cfg_lmt);
  		return -1;
    }
  }

	RHP_TRC(0,RHPTRCID_IKEV2_QCD_RX_PACKETS_RATE_LIMIT_OK,"dffd",rx_req,*rx_time,*rx_per_secs,cfg_lmt);

	RHP_UNLOCK(&_rhp_ikev2_qcd_lock);

	return 0;
}

long rhp_ikev2_qcd_pend_req_num()
{
	return _rhp_atomic_read(&_rhp_ikev2_qcd_pend_pkts);
}

int rhp_ikev2_qcd_rx_invalid_ikesa_spi_req(rhp_packet* rx_pkt)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_IKEV2_QCD_RX_INVALID_IKESA_SPI_REQ,"x",rx_pkt);

	rhp_ikev2_g_statistics_inc(qcd_rx_req_packets);

	if( rhp_gcfg_ikev2_qcd_enabled_time ){

		time_t now = _rhp_get_time();

		if( now - _rhp_ikev2_qcd_boot_time > rhp_gcfg_ikev2_qcd_enabled_time ){
			RHP_TRC(0,RHPTRCID_IKEV2_QCD_RX_INVALID_IKESA_SPI_REQ_ENABLED_TIME_EXCEEDED,"xff",rx_pkt,now,_rhp_ikev2_qcd_boot_time);
			goto ignored;
		}
	}

	if( _rhp_ikev2_qcd_rx_packets_rate_limit(1) ){
		RHP_TRC(0,RHPTRCID_IKEV2_QCD_RX_INVALID_IKESA_SPI_REQ_RATE_LIMIT,"x",rx_pkt);
		goto ignored;
	}

	if( _rhp_atomic_read(&_rhp_ikev2_qcd_pend_pkts) >= rhp_gcfg_ikev2_qcd_max_pend_packets ){
		RHP_TRC(0,RHPTRCID_IKEV2_QCD_RX_INVALID_IKESA_SPI_REQ_RATE_LIMIT_2,"xf",rx_pkt,_rhp_ikev2_qcd_pend_pkts.lock);
		goto ignored;
	}


	if( !rhp_wts_dispach_ok(RHP_WTS_DISP_LEVEL_LOW_3,1) ){
		RHP_TRC(0,RHPTRCID_IKEV2_QCD_RX_INVALID_IKESA_SPI_REQ_MAX_DISP,"x",rx_pkt);
    goto ignored;
  }


  rhp_pkt_hold(rx_pkt);
  rx_pkt->process_packet = _rhp_ikev2_qcd_rx_invalid_ikesa_spi_req_task;

  _rhp_atomic_inc(&_rhp_ikev2_qcd_pend_pkts);

  // QCD task is dispatched to a MISC worker.
  err = rhp_wts_sta_invoke_task(RHP_WTS_DISP_RULE_MISC,
					RHP_WTS_STA_TASK_NAME_PKT,RHP_WTS_DISP_LEVEL_LOW_3,rx_pkt,rx_pkt);

  if( err ){
    _rhp_atomic_dec(&_rhp_ikev2_qcd_pend_pkts);
    rhp_pkt_unhold(rx_pkt);
    goto error;
  }

	RHP_TRC(0,RHPTRCID_IKEV2_QCD_RX_INVALID_IKESA_SPI_REQ_RTRN,"x",rx_pkt);
	return 0;

error:
	rhp_ikev2_g_statistics_inc(qcd_rx_req_err_packets);
	RHP_TRC(0,RHPTRCID_IKEV2_QCD_RX_INVALID_IKESA_SPI_REQ_ERR,"xE",rx_pkt,err);
	return err;

ignored:
	rhp_ikev2_g_statistics_inc(qcd_rx_req_ignored_packets);
	RHP_TRC(0,RHPTRCID_IKEV2_QCD_RX_INVALID_IKESA_SPI_REQ_IGNORED_RTRN,"x",rx_pkt);
	return 0;
}

static int rhp_ikev2_qcd_invalid_ikesa_spi_plds_cb(rhp_ikev2_mesg* tx_ikemesg,void* ctx)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;
	rhp_ipcmsg_qcd_gen_rep_tkn_rep* ipc_rep = (rhp_ipcmsg_qcd_gen_rep_tkn_rep*)ctx;

	RHP_TRC(0,RHPTRCID_IKEV2_QCD_INVALID_IKESA_SPK_PLDS_CB,"xx",tx_ikemesg,ipc_rep);

	{
		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

		ikepayload->set_non_critical(ikepayload,1);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);
		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ERR_INVALID_IKE_SPI);
	}

	{
		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);
		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_QCD_TOKEN);

		ikepayload->set_non_critical(ikepayload,1);

		if( ikepayload->ext.n->set_data(ikepayload,RHP_IKEV2_QCD_TOKEN_LEN,ipc_rep->token) ){
			RHP_BUG("");
			goto error;
		}
	}

	RHP_TRC(0,RHPTRCID_IKEV2_QCD_INVALID_IKESA_SPK_PLDS_CB_RTRN,"xx",tx_ikemesg,ipc_rep);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_QCD_INVALID_IKESA_SPK_PLDS_CB_ERR,"xxE",tx_ikemesg,ipc_rep,err);
	return err;
}

static void _rhp_ikev2_qcd_gen_rep_tkn_rep_task(int worker_idx,void *ctx)
{
	int err = -EINVAL;
	rhp_ipcmsg_qcd_gen_rep_tkn_rep* ipc_rep = (rhp_ipcmsg_qcd_gen_rep_tkn_rep*)ctx;
	rhp_ikev2_qcd_ipc_req_cookie* cookie;
  rhp_ifc_entry* rx_ifc = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_QCD_GEN_REP_TKN_REP_TASK,"dx",worker_idx,ipc_rep);

	if( ipc_rep->len < sizeof(rhp_ipcmsg_qcd_gen_rep_tkn_rep) ){
		RHP_BUG("%d:%d",ipc_rep->len,sizeof(rhp_ipcmsg_qcd_gen_rep_tkn_rep));
		return;
	}

	if( ipc_rep->len < sizeof(rhp_ipcmsg_qcd_gen_rep_tkn_rep) + ipc_rep->cookie_len ){
		RHP_BUG("%d:%d",ipc_rep->len,sizeof(rhp_ipcmsg_qcd_gen_rep_tkn_rep) + ipc_rep->cookie_len);
		return;
	}

	if( ipc_rep->type != RHP_IPC_QCD_GEN_REPLY_TOKEN_REPLY ){
		RHP_BUG("%d",ipc_rep->type);
		return;
	}

	if( ipc_rep->cookie_len < 1 ){
		RHP_BUG("%d",ipc_rep->cookie_len);
		return;
	}

	cookie = (rhp_ikev2_qcd_ipc_req_cookie*)(ipc_rep + 1);


	rx_ifc = rhp_ifc_get_by_if_idx((int)cookie->rx_if_idx);
	if( rx_ifc == NULL ){
		RHP_TRC(0,RHPTRCID_IKEV2_QCD_GEN_REP_TKN_REP_TASK_NO_RX_IF,"dxd",worker_idx,ipc_rep,(int)cookie->rx_if_idx);
		goto error;
	}


	if( cookie->addr_family == AF_INET ){

		err = rhp_ikev2_tx_plain_error_rep_v4(&(cookie->rx_req_iph.v4),&(cookie->rx_req_udph),
						&(cookie->rx_req_ikeh),rx_ifc,rhp_ikev2_qcd_invalid_ikesa_spi_plds_cb,(void*)ipc_rep);

	}else if( cookie->addr_family == AF_INET6 ){

		err = rhp_ikev2_tx_plain_error_rep_v6(&(cookie->rx_req_iph.v6),&(cookie->rx_req_udph),
						&(cookie->rx_req_ikeh),rx_ifc,rhp_ikev2_qcd_invalid_ikesa_spi_plds_cb,(void*)ipc_rep);
	}
  if( err ){
  	RHP_TRC(0,RHPTRCID_IKEV2_QCD_GEN_REP_TKN_REP_TASK_TX_ERR,"dx",worker_idx,ipc_rep);
  	goto error;
  }

	rhp_ikev2_g_statistics_inc(qcd_tx_err_resp_packets);

	if( cookie->addr_family == AF_INET ){
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_QCD_TX_ERR_RESP,"44WWGGLp",cookie->rx_req_iph.v4.dst_addr,cookie->rx_req_iph.v4.src_addr,cookie->rx_req_udph.dst_port,cookie->rx_req_udph.src_port,cookie->rx_req_ikeh.init_spi,cookie->rx_req_ikeh.resp_spi,"PROTO_IKE_EXCHG",(int)cookie->rx_req_ikeh.exchange_type,RHP_IKEV2_QCD_TOKEN_LEN,ipc_rep->token);
	}else if( cookie->addr_family == AF_INET6 ){
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_QCD_TX_ERR_RESP_V6,"66WWGGLp",cookie->rx_req_iph.v6.dst_addr,cookie->rx_req_iph.v6.src_addr,cookie->rx_req_udph.dst_port,cookie->rx_req_udph.src_port,cookie->rx_req_ikeh.init_spi,cookie->rx_req_ikeh.resp_spi,"PROTO_IKE_EXCHG",(int)cookie->rx_req_ikeh.exchange_type,RHP_IKEV2_QCD_TOKEN_LEN,ipc_rep->token);
	}

	err = 0;

error:
	if( ipc_rep ){
		_rhp_free_zero(ipc_rep,ipc_rep->len);
	}

	if( rx_ifc ){
		rhp_ifc_unhold(rx_ifc);
	}

	_rhp_atomic_dec(&_rhp_ikev2_qcd_pend_pkts2);

	RHP_TRC(0,RHPTRCID_IKEV2_QCD_GEN_REP_TKN_REP_TASK_RTRN,"dxE",worker_idx,ipc_rep,err);
	return;
}

static void _rhp_ikev2_qcd_gen_rep_tkn_rep_ipc_handler(rhp_ipcmsg** ipcmsg)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_IKEV2_QCD_GEN_REP_TKN_REP_IPC_HANDLER,"xxf",ipcmsg,*ipcmsg,_rhp_ikev2_qcd_pend_pkts2.lock);

	if( _rhp_atomic_read(&_rhp_ikev2_qcd_pend_pkts2) >= rhp_gcfg_ikev2_qcd_max_pend_packets ){
		RHP_TRC(0,RHPTRCID_IKEV2_QCD_GEN_REP_TKN_REP_IPC_HANDLER_RATE_LIMIT,"xx",ipcmsg,*ipcmsg);
		goto ignore;
	}

  if( rhp_wts_dispach_ok(RHP_WTS_DISP_LEVEL_LOW_3,1) ){

    _rhp_atomic_inc(&_rhp_ikev2_qcd_pend_pkts2);

    // QCD task is dispatched to a MISC worker.
  	err = rhp_wts_add_task(RHP_WTS_DISP_RULE_MISC,RHP_WTS_DISP_LEVEL_LOW_3,NULL,
  			_rhp_ikev2_qcd_gen_rep_tkn_rep_task,*ipcmsg);

  	if( err ){
      _rhp_atomic_dec(&_rhp_ikev2_qcd_pend_pkts2);
  		goto ignore;
  	}

    *ipcmsg = NULL;
    err = 0;

  }else{

		RHP_TRC(0,RHPTRCID_IKEV2_QCD_GEN_REP_TKN_REP_IPC_HANDLER_MAX_DISP,"xx",ipcmsg,*ipcmsg);
		goto ignore;
  }

ignore:
	RHP_TRC(0,RHPTRCID_IKEV2_QCD_GEN_REP_TKN_REP_IPC_HANDLER_RTRN,"xxE",ipcmsg,*ipcmsg,err);
	return;
}

static int _rhp_ikev2_qcd_valid_peer_addr(rhp_packet* pkt,rhp_vpn* vpn)
{
	int peer_addr_len;
	u8* peer_addr;
	rhp_ip_addr_list* mobike_addr_lst;

	if( pkt->type == RHP_PKT_IPV4_IKE ){
		peer_addr_len = 4;
		peer_addr = (u8*)&(pkt->l3.iph_v4->src_addr);
		RHP_TRC(0,RHPTRCID_IKEV2_QCD_VALID_PEER_ADDR,"xx4W",pkt,vpn,pkt->l3.iph_v4->src_addr,pkt->l4.udph->src_port);
	}else if( pkt->type == RHP_PKT_IPV6_IKE ){
		peer_addr_len = 16;
		peer_addr = pkt->l3.iph_v6->src_addr;
		RHP_TRC(0,RHPTRCID_IKEV2_QCD_VALID_PEER_ADDR_V6,"xx6W",pkt,vpn,pkt->l3.iph_v6->src_addr,pkt->l4.udph->src_port);
	}else{
		RHP_BUG("%d",pkt->type);
		return 0;
	}

	rhp_ip_addr_dump("vpn->peer_addr",&(vpn->peer_addr));
	if( !rhp_ip_addr_cmp_value(&(vpn->peer_addr),peer_addr_len,peer_addr) ){
		RHP_TRC(0,RHPTRCID_IKEV2_QCD_VALID_PEER_ADDR_VPN_PEER_ADDR,"xx",pkt,vpn);
		return 1;
	}

	rhp_ip_addr_dump("vpn->cfg_peer->primary_addr",&(vpn->cfg_peer->primary_addr));
	if( !rhp_ip_addr_null(&(vpn->cfg_peer->primary_addr)) ){

		if( !rhp_ip_addr_cmp_value(&(vpn->cfg_peer->primary_addr),peer_addr_len,peer_addr) ){
			RHP_TRC(0,RHPTRCID_IKEV2_QCD_VALID_PEER_ADDR_CFG_PRIMARY,"xx",pkt,vpn);
			return 1;
		}
	}

	rhp_ip_addr_dump("vpn->cfg_peer->secondary_addr",&(vpn->cfg_peer->secondary_addr));
	if( !rhp_ip_addr_null(&(vpn->cfg_peer->secondary_addr)) ){

		if( !rhp_ip_addr_cmp_value(&(vpn->cfg_peer->secondary_addr),peer_addr_len,peer_addr) ){
			RHP_TRC(0,RHPTRCID_IKEV2_QCD_VALID_PEER_ADDR_CFG_SECONDARY,"xx",pkt,vpn);
			return 1;
		}
	}

	mobike_addr_lst = vpn->mobike.init.additional_addrs;
	while( mobike_addr_lst ){

		rhp_ip_addr_dump("mobike_addr_lst->ip_addr",&(mobike_addr_lst->ip_addr));
		if( !rhp_ip_addr_cmp_value(&(mobike_addr_lst->ip_addr),peer_addr_len,peer_addr) ){
			RHP_TRC(0,RHPTRCID_IKEV2_QCD_VALID_PEER_ADDR_MOBIKE_ADDITIONAL,"xx",pkt,vpn);
			return 1;
		}

		mobike_addr_lst = mobike_addr_lst->next;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_QCD_VALID_PEER_ADDR_UNKNOWN_PEER_ADDR,"xx",pkt,vpn);
	return 0;
}

int rhp_ikev2_qcd_rx_invalid_ikesa_spi_resp(rhp_packet* pkt,rhp_vpn* vpn)
{
	int err = -EINVAL;
  rhp_proto_ike* ikeh = pkt->app.ikeh;
	u8* p = (u8*)(ikeh + 1);
	u8 next_pld = ikeh->next_payload;
	int invalid_ike_spi = 0;
	int qcd_token = 0;
	int qcd_token_len = 0;
	u8* qcd_token_data = NULL;
  int my_side = 0;
  u8* my_spi = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_QCD_RX_INVALID_IKESA_SPI_RESP,"xx",pkt,vpn);

	rhp_ikev2_g_statistics_inc(qcd_rx_err_resp_packets);

  if( _rhp_ikev2_qcd_rx_packets_rate_limit(0) ){
  	RHP_TRC(0,RHPTRCID_IKEV2_QCD_RX_INVALID_IKESA_SPI_RESP_RATE_LIMIT,"x",pkt);
		goto ignored;
	}


  if( !_rhp_ikev2_qcd_valid_peer_addr(pkt,vpn) ){

		rhp_ikev2_g_statistics_inc(rx_ikev2_resp_from_unknown_peer_packets);

		goto ignored;
  }

  //
	// Rx buffer is already checked by _rhp_ikev2_allowed_plain_payloads().
  //
	while( p < pkt->tail ){

		rhp_proto_ike_payload* pld_h = (rhp_proto_ike_payload*)p;
		u16 pld_len;
		rhp_proto_ike_notify_payload* n_pld_h;
		u16 n_type;

		pld_len = ntohs(pld_h->len);

		if( next_pld == RHP_PROTO_IKE_PAYLOAD_N ){

			n_pld_h = (rhp_proto_ike_notify_payload*)pld_h;
			n_type = ntohs(n_pld_h->notify_mesg_type);

			if( n_type == RHP_PROTO_IKE_NOTIFY_ERR_INVALID_IKE_SPI ){

				invalid_ike_spi = 1;

			}else if( n_type == RHP_PROTO_IKE_NOTIFY_ST_QCD_TOKEN ){

				qcd_token_len = pld_len - sizeof(rhp_proto_ike_notify_payload);
				qcd_token_data = (u8*)(n_pld_h + 1);

	    	RHP_TRC(0,RHPTRCID_IKEV2_QCD_RX_INVALID_IKESA_SPI_RESP_RX_TKN,"xp",pkt,qcd_token_len,qcd_token_data);
				qcd_token = 1;
			}
		}

		if( invalid_ike_spi && qcd_token ){
			break;
		}

		next_pld = pld_h->next_payload;
		p += pld_len;
	}

	if( !invalid_ike_spi || !qcd_token ){
		RHP_TRC(0,RHPTRCID_IKEV2_QCD_RX_INVALID_IKESA_SPI_RESP_NO_QCD_TKN,"x",pkt);
		goto ignored;
	}

  my_side = RHP_PROTO_IKE_HDR_INITIATOR(ikeh->flag) ?  RHP_IKE_RESPONDER : RHP_IKE_INITIATOR;
  my_spi = ( my_side == RHP_IKE_INITIATOR ? ikeh->init_spi : ikeh->resp_spi );

  {
  	rhp_ikesa* ikesa = vpn->ikesa_get(vpn,my_side,my_spi);

  	if( ikesa ){

    	RHP_TRC(0,RHPTRCID_IKEV2_QCD_RX_INVALID_IKESA_SPI_RESP_IKESA_TKN,"xxpp",pkt,ikesa,ikesa->qcd.peer_token_len,ikesa->qcd.peer_token,qcd_token_len,qcd_token_data);

    	if( ikesa->qcd.peer_token_len &&
    			ikesa->qcd.peer_token_len == qcd_token_len &&
    			!memcmp(ikesa->qcd.peer_token,qcd_token_data,qcd_token_len) ){

    		if( ikesa->state == RHP_IKESA_STAT_ESTABLISHED || ikesa->state == RHP_IKESA_STAT_REKEYING ){

    			if( pkt->type == RHP_PKT_IPV4_IKE ){
    				RHP_LOG_I(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_QCD_RX_ERR_RESP_VPN_CLEARED,"44WWGGLVP",pkt->l3.iph_v4->dst_addr,pkt->l3.iph_v4->src_addr,pkt->l4.udph->dst_port,pkt->l4.udph->src_port,ikeh->init_spi,ikeh->resp_spi,"PROTO_IKE_EXCHG",(int)ikeh->exchange_type,vpn,ikesa);
    				if( rhp_gcfg_dbg_log_keys_info ){
    					RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_QCD_RX_ERR_RESP_QCD_TOKENS,"4GGpp",pkt->l3.iph_v4->src_addr,ikeh->init_spi,ikeh->resp_spi,ikesa->qcd.peer_token_len,ikesa->qcd.peer_token,qcd_token_len,qcd_token_data);
    				}
    			}else if( pkt->type == RHP_PKT_IPV6_IKE ){
    				RHP_LOG_I(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_QCD_RX_ERR_RESP_VPN_CLEARED_V6,"66WWGGLVP",pkt->l3.iph_v6->dst_addr,pkt->l3.iph_v6->src_addr,pkt->l4.udph->dst_port,pkt->l4.udph->src_port,ikeh->init_spi,ikeh->resp_spi,"PROTO_IKE_EXCHG",(int)ikeh->exchange_type,vpn,ikesa);
    				if( rhp_gcfg_dbg_log_keys_info ){
    					RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_QCD_RX_ERR_RESP_QCD_TOKENS_V6,"6GGpp",pkt->l3.iph_v6->src_addr,ikeh->init_spi,ikeh->resp_spi,ikesa->qcd.peer_token_len,ikesa->qcd.peer_token,qcd_token_len,qcd_token_data);
    				}
    			}

    			err = rhp_vpn_start_reconnect(vpn);
			    if( err ){
			      RHP_TRC(0,RHPTRCID_IKEV2_QCD_RX_INVALID_IKESA_SPI_RESP_START_RECONNECT_ERR,"xE",vpn,err);
			    }
			    err = 0;

					rhp_vpn_destroy(vpn);

					rhp_ikev2_g_statistics_inc(qcd_rx_err_resp_cleared_ikesas);

    		}else{

    			if( pkt->type == RHP_PKT_IPV4_IKE ){
    				RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_QCD_RX_ERR_RESP_BAD_IKESA_STATE,"44WWGGLVP",pkt->l3.iph_v4->dst_addr,pkt->l3.iph_v4->src_addr,pkt->l4.udph->dst_port,pkt->l4.udph->src_port,ikeh->init_spi,ikeh->resp_spi,"PROTO_IKE_EXCHG",(int)ikeh->exchange_type,vpn,ikesa);
    				if( rhp_gcfg_dbg_log_keys_info ){
    					RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_QCD_RX_ERR_RESP_BAD_IKESA_STATE_QCD_TOKENS,"4GGpp",pkt->l3.iph_v4->src_addr,ikeh->init_spi,ikeh->resp_spi,ikesa->qcd.peer_token_len,ikesa->qcd.peer_token,qcd_token_len,qcd_token_data);
    				}
    			}else if( pkt->type == RHP_PKT_IPV6_IKE ){
    				RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_QCD_RX_ERR_RESP_BAD_IKESA_STATE_V6,"66WWGGLVP",pkt->l3.iph_v6->dst_addr,pkt->l3.iph_v6->src_addr,pkt->l4.udph->dst_port,pkt->l4.udph->src_port,ikeh->init_spi,ikeh->resp_spi,"PROTO_IKE_EXCHG",(int)ikeh->exchange_type,vpn,ikesa);
    				if( rhp_gcfg_dbg_log_keys_info ){
    					RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_QCD_RX_ERR_RESP_BAD_IKESA_STATE_QCD_TOKENS_V6,"6GGpp",pkt->l3.iph_v6->src_addr,ikeh->init_spi,ikeh->resp_spi,ikesa->qcd.peer_token_len,ikesa->qcd.peer_token,qcd_token_len,qcd_token_data);
    				}
    			}
    		}

    	}else{

  			if( pkt->type == RHP_PKT_IPV4_IKE ){
  				RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_QCD_RX_ERR_RESP_BAD_QCD_TOKEN,"44WWGGLpVP",pkt->l3.iph_v4->dst_addr,pkt->l3.iph_v4->src_addr,pkt->l4.udph->dst_port,pkt->l4.udph->src_port,ikeh->init_spi,ikeh->resp_spi,"PROTO_IKE_EXCHG",(int)ikeh->exchange_type,qcd_token_len,qcd_token_data,vpn,ikesa);
  				if( rhp_gcfg_dbg_log_keys_info ){
  					RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_QCD_RX_ERR_RESP_BAD_QCD_TOKEN_VAL,"4GGpp",pkt->l3.iph_v4->src_addr,ikeh->init_spi,ikeh->resp_spi,ikesa->qcd.peer_token_len,ikesa->qcd.peer_token,qcd_token_len,qcd_token_data);
  				}
  			}else if( pkt->type == RHP_PKT_IPV6_IKE ){
  				RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_QCD_RX_ERR_RESP_BAD_QCD_TOKEN_V6,"66WWGGLpVP",pkt->l3.iph_v6->dst_addr,pkt->l3.iph_v6->src_addr,pkt->l4.udph->dst_port,pkt->l4.udph->src_port,ikeh->init_spi,ikeh->resp_spi,"PROTO_IKE_EXCHG",(int)ikeh->exchange_type,qcd_token_len,qcd_token_data,vpn,ikesa);
  				if( rhp_gcfg_dbg_log_keys_info ){
  					RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_QCD_RX_ERR_RESP_BAD_QCD_TOKEN_VAL_V6,"6GGpp",pkt->l3.iph_v6->src_addr,ikeh->init_spi,ikeh->resp_spi,ikesa->qcd.peer_token_len,ikesa->qcd.peer_token,qcd_token_len,qcd_token_data);
  				}
  			}

				rhp_ikev2_g_statistics_inc(qcd_rx_err_resp_bad_tokens);

	      goto ignored;
    	}

    }else{

			if( pkt->type == RHP_PKT_IPV4_IKE ){
				RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_QCD_RX_ERR_RESP_NO_IKESA,"44WWGGLpV",pkt->l3.iph_v4->dst_addr,pkt->l3.iph_v4->src_addr,pkt->l4.udph->dst_port,pkt->l4.udph->src_port,ikeh->init_spi,ikeh->resp_spi,"PROTO_IKE_EXCHG",(int)ikeh->exchange_type,qcd_token_len,qcd_token_data,vpn);
			}else if( pkt->type == RHP_PKT_IPV6_IKE ){
				RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_QCD_RX_ERR_RESP_NO_IKESA_V6,"66WWGGLpV",pkt->l3.iph_v6->dst_addr,pkt->l3.iph_v6->src_addr,pkt->l4.udph->dst_port,pkt->l4.udph->src_port,ikeh->init_spi,ikeh->resp_spi,"PROTO_IKE_EXCHG",(int)ikeh->exchange_type,qcd_token_len,qcd_token_data,vpn);
			}

			rhp_ikev2_g_statistics_inc(qcd_rx_err_resp_no_ikesa);

      goto ignored;
    }
  }

	RHP_TRC(0,RHPTRCID_IKEV2_QCD_RX_INVALID_IKESA_SPI_RESP_RTRN,"x",pkt);
  return 0;

ignored:
	rhp_ikev2_g_statistics_inc(qcd_rx_err_resp_ignored_packets);
	RHP_TRC(0,RHPTRCID_IKEV2_QCD_RX_INVALID_IKESA_SPI_RESP_IGNORED_RTRN,"x",pkt);
	return RHP_STATUS_IKEV2_QCD_ERR_RESP_IGNORED;
}

static int _rhp_ikev2_qcd_add_my_token(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_QCD_ADD_MY_TOKEN,"xxx",vpn,ikesa,tx_ikemesg);

	if( ikesa->qcd.my_token_enabled ){

		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);

		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_QCD_TOKEN);

		ikepayload->set_non_critical(ikepayload,1);

		if( ikepayload->ext.n->set_data(ikepayload,RHP_IKEV2_QCD_TOKEN_LEN,ikesa->qcd.my_token) ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_QCD_TX_TOKEN,"KVP",tx_ikemesg,vpn,ikesa);
		if( rhp_gcfg_dbg_log_keys_info ){
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_QCD_TX_TOKEN_DATA,"Kp",tx_ikemesg,RHP_IKEV2_QCD_TOKEN_LEN,ikesa->qcd.my_token);
		}
	}

	RHP_TRC(0,RHPTRCID_IKEV2_QCD_ADD_MY_TOKEN_RTRN,"xxx",vpn,ikesa,tx_ikemesg);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_QCD_ADD_MY_TOKEN_ERR,"xxxE",vpn,ikesa,tx_ikemesg,err);
	return err;
}

static int _rhp_ikev2_ike_qcd_srch_n_token_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_ikesa* ikesa = (rhp_ikesa*)ctx;
  rhp_ikev2_n_payload* n_payload = (rhp_ikev2_n_payload*)payload->ext.n;
  u16 notify_mesg_type;

	RHP_TRC(0,RHPTRCID_IKEV2_QCD_SRCH_N_TOKEN_CB,"xdxx",rx_ikemesg,enum_end,payload,ikesa);

  if( n_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  notify_mesg_type = n_payload->get_message_type(payload);

  if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_QCD_TOKEN ){

  	int data_len = n_payload->get_data_len(payload);
  	u8* data = n_payload->get_data(payload);

		if( ikesa->qcd.peer_token ){
			_rhp_free_zero(ikesa->qcd.peer_token,ikesa->qcd.peer_token_len);
			ikesa->qcd.peer_token_len = 0;
			ikesa->qcd.peer_token = NULL;
		}

		RHP_TRC(0,RHPTRCID_IKEV2_QCD_SRCH_N_TOKEN_CB_TKN,"xp",rx_ikemesg,data_len,data);

  	if( data &&
  			data_len >= rhp_gcfg_ikev2_qcd_min_token_len &&
  			data_len <= rhp_gcfg_ikev2_qcd_max_token_len ){

			ikesa->qcd.peer_token = (u8*)_rhp_malloc(data_len);
			if( ikesa->qcd.peer_token == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			ikesa->qcd.peer_token_len = data_len;
			memcpy(ikesa->qcd.peer_token,data,data_len);

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_QCD_RX_PEER_TOKEN,"KP",rx_ikemesg,ikesa);
		  if( rhp_gcfg_dbg_log_keys_info ){
		  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_QCD_RX_PEER_TOKEN_DATA,"Pp",ikesa,ikesa->qcd.peer_token_len,ikesa->qcd.peer_token);
		  }

  	}else{

  		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_QCD_RX_INVALID_PEER_TOKEN,"KPd",rx_ikemesg,ikesa,data_len);
  	}

    err = RHP_STATUS_ENUM_OK;
    goto error;
  }

  err = 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_QCD_SRCH_N_TOKEN_CB_RTRN,"xxxE",rx_ikemesg,payload,ikesa,err);
  return err;
}

static int _rhp_ikev2_rx_qcd_peer_token(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_PEER_TOKEN,"xxx",vpn,ikesa,rx_ikemesg);

	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_N),
			_rhp_ikev2_ike_qcd_srch_n_token_cb,ikesa);

	if( err && err != -ENOENT && err != RHP_STATUS_ENUM_OK ){
		goto error;
	}


	RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_PEER_TOKEN_RTRN,"xxx",vpn,ikesa,rx_ikemesg);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_PEER_TOKEN_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);
	return err;
}

static int _rhp_ikev2_qcd_ipc_send_tkn_req(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikesa* old_ikesa)
{
	int err = -EINVAL;
	rhp_ipcmsg_qcd_token_req ipc_req;

	RHP_TRC(0,RHPTRCID_IKEV2_QCD_IPC_SEND_TKN_REQ,"xxLdGG",vpn,ikesa,"IKE_SIDE",ikesa->side,ikesa->init_spi,ikesa->resp_spi);
	if( old_ikesa ){
		RHP_TRC(0,RHPTRCID_IKEV2_QCD_IPC_SEND_TKN_REQ_OLD_IKESA,"xLdGG",old_ikesa,"IKE_SIDE",old_ikesa->side,old_ikesa->init_spi,old_ikesa->resp_spi);
	}

	memset(&ipc_req,0,sizeof(rhp_ipcmsg_qcd_token_req));

	ipc_req.tag[0] = '#';
	ipc_req.tag[1] = 'I';
	ipc_req.tag[2] = 'M';
	ipc_req.tag[3] = 'S';

	ipc_req.type = RHP_IPC_QCD_TOKEN_REQUEST;
	ipc_req.len = sizeof(rhp_ipcmsg_qcd_token_req);

	ipc_req.my_realm_id = vpn->vpn_realm_id;
	ipc_req.side = ikesa->side;

	if( (((u32*)ikesa->init_spi)[0] == 0 && ((u32*)ikesa->init_spi)[1] == 0) ||
			(((u32*)ikesa->resp_spi)[0] == 0 && ((u32*)ikesa->resp_spi)[1] == 0) ){
		RHP_BUG("");
	}

	if( ikesa->side == RHP_IKE_INITIATOR ){
		memcpy(ipc_req.spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
		memcpy(ipc_req.peer_spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
	}else{
		memcpy(ipc_req.spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
		memcpy(ipc_req.peer_spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
	}

	if( old_ikesa ){

		ipc_req.old_ikesa = 1;
		ipc_req.old_side = old_ikesa->side;

		if( old_ikesa->side == RHP_IKE_INITIATOR ){
			memcpy(ipc_req.old_spi,old_ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
			memcpy(ipc_req.old_peer_spi,old_ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
		}else{
			memcpy(ipc_req.old_spi,old_ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
			memcpy(ipc_req.old_peer_spi,old_ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
		}
	}

	ikesa->qcd.ipc_txn_id = rhp_ikesa_new_ipc_txn_id();
	ipc_req.txn_id = ikesa->qcd.ipc_txn_id;

	if( rhp_ipc_send(RHP_MY_PROCESS,(void*)&ipc_req,ipc_req.len,0) < 0 ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
  }

	RHP_TRC(0,RHPTRCID_IKEV2_QCD_IPC_SEND_TKN_REQ_RTRN,"xx",vpn,ikesa);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_QCD_IPC_SEND_TKN_REQ_ERR,"xxE",vpn,ikesa,err);
	return err;
}


int rhp_ikev2_rx_qcd_req(rhp_ikev2_mesg* rx_req_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err = -EINVAL;
	rhp_ikesa* ikesa = NULL;
	rhp_ikesa* old_ikesa = NULL;
	u8 exchange_type = rx_req_ikemesg->get_exchange_type(rx_req_ikemesg);
	int is_rekey_exchg = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_REQ,"xxLdGxLbd",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_resp_ikemesg,"PROTO_IKE_EXCHG",exchange_type,rhp_gcfg_ikev2_qcd_enabled);

  if( !rhp_gcfg_ikev2_qcd_enabled ){
  	err = 0;
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_REQ_DISABLED,"xxx",rx_req_ikemesg,vpn,tx_resp_ikemesg);
  	goto error;
  }

	if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ||
			exchange_type == RHP_PROTO_IKE_EXCHG_SESS_RESUME ){

		err = 0;
  	goto error;

	}else if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_AUTH ){

		if( !RHP_PROTO_IKE_HDR_INITIATOR(rx_req_ikemesg->rx_pkt->app.ikeh->flag) ){
			err = RHP_STATUS_INVALID_MSG;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_REQ_INVALID_MESG1,"xx",rx_req_ikemesg,vpn);
			goto error;
	  }

	}else if( exchange_type == RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA &&
						rx_req_ikemesg->for_ikesa_rekey ){

  	is_rekey_exchg = 1;
	}


  if( !rx_req_ikemesg->decrypted ){
  	err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_REQ_NOT_DECRYPTED,"xx",rx_req_ikemesg,vpn);
  	goto error;
  }

	if( my_ikesa_spi == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

	ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
	if( ikesa ){

		if( is_rekey_exchg ||
				(ikesa->state != RHP_IKESA_STAT_ESTABLISHED && ikesa->state != RHP_IKESA_STAT_REKEYING) ){
			err = 0;
			RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_REQ_IKESA_STATE_NOT_INTERESTED,"xxLdGLd",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state);
			old_ikesa = ikesa;
			ikesa = NULL;
		}
	}

	if( ikesa == NULL && is_rekey_exchg ){

		ikesa = vpn->ikesa_get(vpn,rx_req_ikemesg->rekeyed_ikesa_my_side,rx_req_ikemesg->rekeyed_ikesa_my_spi);
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_REQ_GET_REKEYED_NEW_IKESA,"xxLdGx",rx_req_ikemesg,vpn,"IKE_SIDE",rx_req_ikemesg->rekeyed_ikesa_my_side,rx_req_ikemesg->rekeyed_ikesa_my_spi,ikesa);
	}

	if( ikesa == NULL ){
		err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_REQ_NO_IKESA,"xxLdG",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
		goto error;
	}

	if( exchange_type != RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA ){

  	err = _rhp_ikev2_rx_qcd_peer_token(vpn,ikesa,rx_req_ikemesg);
  	if( err ){
    	RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_REQ_QCD_PEER_TKN_ERR,"xxxE",rx_req_ikemesg,vpn,tx_resp_ikemesg,err);
  		goto error;
  	}

  	if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_AUTH ){

  		err = _rhp_ikev2_qcd_add_my_token(vpn,ikesa,tx_resp_ikemesg);
  		if( err ){
  			goto error;
  		}
  	}

  }else if( is_rekey_exchg ){

  	if( old_ikesa == NULL ){
  		RHP_BUG("");
  		err = 0;
  		goto error;
  	}

  	if( ikesa->qcd.my_token_set_by_sess_resume ){

  		err = _rhp_ikev2_qcd_add_my_token(vpn,ikesa,tx_resp_ikemesg);
  		if( err ){
				RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_REQ_ADD_MY_TOKEN_GEN_BY_SESS_RESUME_ERR,"xxxE",rx_req_ikemesg,vpn,tx_resp_ikemesg,err);
				goto error;
  		}

  	}else{

			err = _rhp_ikev2_qcd_ipc_send_tkn_req(vpn,ikesa,old_ikesa);
			if( err ){
				RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_REQ_QCD_IPC_TX_ERR,"xxxE",rx_req_ikemesg,vpn,tx_resp_ikemesg,err);
				goto error;
			}

			ikesa->qcd.pend_pos = RHP_IKEV2_QCD_PEND_RX_REQ;

			ikesa->qcd.pend_rx_ikemesg = rx_req_ikemesg;
			rhp_ikev2_hold_mesg(rx_req_ikemesg);
			ikesa->qcd.pend_tx_ikemesg = tx_resp_ikemesg;
			rhp_ikev2_hold_mesg(tx_resp_ikemesg);

			ikesa->busy_flag = 1;

			old_ikesa->timers->quit_lifetime_timer(vpn,old_ikesa);

			old_ikesa->busy_flag = 1;

			RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_REQ_PEND_RTRN,"xxx",rx_req_ikemesg,vpn,tx_resp_ikemesg);
			return RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;
  	}
  }

  err = 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_REQ_RTRN,"xxxE",rx_req_ikemesg,vpn,tx_resp_ikemesg,err);
  return err;
}


int rhp_ikev2_rx_qcd_rep(rhp_ikev2_mesg* rx_resp_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err = -EINVAL;;
	rhp_ikesa* ikesa = NULL;
	rhp_ikesa* old_ikesa = NULL;
	u8 exchange_type = rx_resp_ikemesg->get_exchange_type(rx_resp_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_REP,"xxLdGxLbd",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_req_ikemesg,"PROTO_IKE_EXCHG",exchange_type,rhp_gcfg_ikev2_qcd_enabled);

  if( !rhp_gcfg_ikev2_qcd_enabled ){
  	err = 0;
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_REP_DISABLED,"xxx",rx_resp_ikemesg,vpn,tx_req_ikemesg);
  	goto error;
  }

	if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ||
			exchange_type == RHP_PROTO_IKE_EXCHG_SESS_RESUME ){

		if( RHP_PROTO_IKE_HDR_INITIATOR(rx_resp_ikemesg->rx_pkt->app.ikeh->flag) ){
			err = RHP_STATUS_INVALID_MSG;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_REP_INVALID_MESG_1,"xx",rx_resp_ikemesg,vpn);
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
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_REP_NO_IKESA_1,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}

		if( ikesa->state != RHP_IKESA_STAT_I_AUTH_SENT ){
			err = 0;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_REP_NOT_INTERESTED_1,"xxLdGLd",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state);
			goto error;
		}


		//
		// RHP_IKEV2_MESG_HANDLER_IKESA_AUTH handler is already called
		// and so ikesa->state is already RHP_IKESA_STAT_I_AUTH_SENT.
		// tx_req_ikemesg will be encrypted. OK.
		//

		if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ){

			err = _rhp_ikev2_qcd_add_my_token(vpn,ikesa,tx_req_ikemesg);
			if( err ){
				goto error;
			}

		}else if( exchange_type == RHP_PROTO_IKE_EXCHG_SESS_RESUME ){

	  	err = _rhp_ikev2_qcd_ipc_send_tkn_req(vpn,ikesa,NULL);
	  	if( err ){
	  		goto error;
	  	}

			ikesa->qcd.pend_pos = RHP_IKEV2_QCD_PEND_RX_RESP_SESS_RESUME;

			ikesa->qcd.pend_rx_ikemesg = rx_resp_ikemesg;
			rhp_ikev2_hold_mesg(rx_resp_ikemesg);
			ikesa->qcd.pend_tx_ikemesg = tx_req_ikemesg;
			rhp_ikev2_hold_mesg(tx_req_ikemesg);

			ikesa->busy_flag = 1;

			return RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;
		}

	}else{

		int is_rekey_exchg = 0;

	  if( exchange_type == RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA &&
  			rx_resp_ikemesg->for_ikesa_rekey ){

	  	is_rekey_exchg = 1;

	  }else if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_AUTH ){

			if( RHP_PROTO_IKE_HDR_INITIATOR(rx_resp_ikemesg->rx_pkt->app.ikeh->flag) ){
				err = RHP_STATUS_INVALID_MSG;
				RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_REP_INVALID_MESG_2,"xx",rx_resp_ikemesg,vpn);
				goto error;
			}
		}

	  if( !rx_resp_ikemesg->decrypted ){
	  	err = 0;
			RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_REP_NOT_DECRYPTED,"xx",rx_resp_ikemesg,vpn);
	  	goto error;
	  }

		if( my_ikesa_spi == NULL ){
	    RHP_BUG("");
	    err = -EINVAL;
	    goto error;
	  }


		ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
		if( ikesa ){

			if( is_rekey_exchg ||
				 (ikesa->state != RHP_IKESA_STAT_ESTABLISHED && ikesa->state != RHP_IKESA_STAT_REKEYING) ){
				RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_REP_BAD_IKESA_STAT_2,"xxLdGLd",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state);
				old_ikesa = ikesa;
				ikesa = NULL; // Try a new rekeyed ikesa.
			}
		}

		if( ikesa == NULL && is_rekey_exchg ){

			ikesa = vpn->ikesa_get(vpn,
								rx_resp_ikemesg->rekeyed_ikesa_my_side,
								rx_resp_ikemesg->rekeyed_ikesa_my_spi);

			RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_REP_GET_REKEYED_NEW_IKESA,"xxLdGx",rx_resp_ikemesg,vpn,"IKE_SIDE",rx_resp_ikemesg->rekeyed_ikesa_my_side,rx_resp_ikemesg->rekeyed_ikesa_my_spi,ikesa);
		}

		if( ikesa == NULL ){
			err = 0;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_REP_NO_IKESA_2,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}


	  err = _rhp_ikev2_rx_qcd_peer_token(vpn,ikesa,rx_resp_ikemesg);
	  if( err ){
	  	goto error;
	  }


	  if( is_rekey_exchg ){

	  	if( old_ikesa == NULL ){
	  		RHP_BUG("");
	  		err = 0;
	  		goto error;
	  	}

	  	err = _rhp_ikev2_qcd_ipc_send_tkn_req(vpn,ikesa,old_ikesa);
	  	if( err ){
	  		goto error;
	  	}

			ikesa->qcd.pend_pos = RHP_IKEV2_QCD_PEND_RX_RESP;

			ikesa->qcd.pend_rx_ikemesg = rx_resp_ikemesg;
			rhp_ikev2_hold_mesg(rx_resp_ikemesg);
			ikesa->qcd.pend_tx_ikemesg = tx_req_ikemesg;
			rhp_ikev2_hold_mesg(tx_req_ikemesg);

			ikesa->busy_flag = 1;

	  	old_ikesa->timers->quit_lifetime_timer(vpn,old_ikesa);

			old_ikesa->busy_flag = 1;

			return RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;
	  }
	}

  err = 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_QCD_REP_RTRN,"xxxE",rx_resp_ikemesg,vpn,tx_req_ikemesg,err);
  return err;
}

static void _rhp_ikev2_qcd_tkn_rep_ipc_handler(rhp_ipcmsg** ipcmsg)
{
  int err = -EINVAL;
  rhp_ipcmsg_qcd_token_rep* ipc_rep;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_ikev2_mesg* rx_ikemesg = NULL;
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;
  rhp_ikesa* ikesa = NULL;
  rhp_ikesa* old_ikesa = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_QCD_TKN_REP_IPC_HANDLER,"xx",ipcmsg,*ipcmsg);

  if( (*ipcmsg)->len < sizeof(rhp_ipcmsg_qcd_token_rep) ){
    RHP_BUG("%d < sizeof(rhp_ipcmsg_qcd_token_rep)(%d)",(*ipcmsg)->len,sizeof(rhp_ipcmsg_qcd_token_rep));
		return;
  }

	if( (*ipcmsg)->type != RHP_IPC_QCD_TOKEN_REPLY ){
		RHP_BUG("%d",(*ipcmsg)->type);
		return;
	}

  ipc_rep = (rhp_ipcmsg_qcd_token_rep*)(*ipcmsg);



  vpn_ref = rhp_vpn_ikesa_spi_get(ipc_rep->side,ipc_rep->spi);
  vpn = RHP_VPN_REF(vpn_ref);
  if( vpn == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_QCD_TKN_REP_IPC_HANDLER_NO_IKESA,"xLdG",ipc_rep,"IKE_SIDE",ipc_rep->side,ipc_rep->spi);
    goto error;
  }

  RHP_LOCK(&(vpn->lock));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV2_QCD_TKN_REP_IPC_HANDLER_IKESA_NOT_ACTIVE,"xx",ipc_rep,ikesa);
    goto error;
  }

  if( ipc_rep->old_ikesa ){

    old_ikesa = vpn->ikesa_get(vpn,ipc_rep->old_side,ipc_rep->old_spi);
    if( old_ikesa == NULL ){
      RHP_TRC(0,RHPTRCID_IKEV2_QCD_TKN_REP_IPC_HANDLER_NO_OLD_IKESA,"x",ipc_rep);
    }else{
      RHP_TRC(0,RHPTRCID_IKEV2_QCD_TKN_REP_IPC_HANDLER_GET_OLD_IKESA,"xx",ipc_rep,old_ikesa);
    }
  }

  ikesa = vpn->ikesa_get(vpn,ipc_rep->side,ipc_rep->spi);
  if( ikesa == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_QCD_TKN_REP_IPC_HANDLER_NO_IKESA,"x",ipc_rep);
    goto error;
  }


  ikesa->busy_flag = 0;
	ikesa->qcd.my_token_enabled = 0;

  tx_ikemesg = ikesa->qcd.pend_tx_ikemesg;
 	ikesa->qcd.pend_tx_ikemesg = NULL;
  rx_ikemesg = ikesa->qcd.pend_rx_ikemesg;
  ikesa->qcd.pend_rx_ikemesg = NULL;

  if( tx_ikemesg == NULL || rx_ikemesg == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  if( ipc_rep->txn_id != ikesa->qcd.ipc_txn_id ){
    RHP_TRC(0,RHPTRCID_IKEV2_QCD_TKN_REP_IPC_HANDLER_IKESA_BAD_TXNID,"xxxqq",ipc_rep,vpn,ikesa,ipc_rep->txn_id,ikesa->qcd.ipc_txn_id);
    goto error;
  }


  if( ipc_rep->my_realm_id != vpn->vpn_realm_id ){
    RHP_TRC(0,RHPTRCID_IKEV2_QCD_TKN_REP_IPC_HANDLER_REALM_BAD_ID,"xxxuu",ipc_rep,vpn,ikesa,ipc_rep->my_realm_id,vpn->vpn_realm_id);
    goto error;
  }

  if( ipc_rep->result == 0 ){
  	RHP_TRC(0,RHPTRCID_IKEV2_QCD_TKN_REP_IPC_HANDLER_RESULT_ERR,"xxx",ipc_rep,vpn,ikesa);
  	goto error;
  }


  if( rhp_gcfg_ikev2_qcd_enabled ){

  	ikesa->qcd.my_token_enabled = 1;
  	memcpy(ikesa->qcd.my_token,ipc_rep->my_token,RHP_IKEV2_QCD_TOKEN_LEN);

		if( ikesa->qcd.pend_pos == RHP_IKEV2_QCD_PEND_RX_RESP ){

			rhp_ikev2_mesg* tx_new_qcd_ikemesg = rhp_ikev2_tx_new_req_get(vpn,ipc_rep->side,ipc_rep->spi);
  		if( tx_new_qcd_ikemesg ){

  			err = _rhp_ikev2_qcd_add_my_token(vpn,ikesa,tx_new_qcd_ikemesg);
				if( err ){
	  			RHP_BUG("%d",err);
				}

			}else{
				RHP_BUG("");
			}

			err = 0;

		}else if( ikesa->qcd.pend_pos == RHP_IKEV2_QCD_PEND_RX_REQ ||
							ikesa->qcd.pend_pos == RHP_IKEV2_QCD_PEND_RX_RESP_SESS_RESUME ){

			err = _rhp_ikev2_qcd_add_my_token(vpn,ikesa,tx_ikemesg);
			if( err ){
				goto error;
			}
  	}

  }else{

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_QCD_GEN_TX_TOKEN_ERR,"KKVP",rx_ikemesg,tx_ikemesg,vpn,ikesa);
  }

error:
  if( vpn ){

  	time_t old_ikesa_dt = 0;

  	if( rx_ikemesg && tx_ikemesg && ikesa ){

  		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_QCD_TX_TOKEN_2,"KKVP",rx_ikemesg,tx_ikemesg,vpn,ikesa);

  		if( ikesa->qcd.pend_pos == RHP_IKEV2_QCD_PEND_RX_RESP ){

  			rhp_ikev2_call_next_rx_response_mesg_handlers(rx_ikemesg,vpn,
  					ipc_rep->old_side,ipc_rep->old_spi,tx_ikemesg,RHP_IKEV2_MESG_HANDLER_QCD);

  		}else if( ikesa->qcd.pend_pos == RHP_IKEV2_QCD_PEND_RX_RESP_SESS_RESUME ){

  			rhp_ikev2_call_next_rx_response_mesg_handlers(rx_ikemesg,vpn,
  					ipc_rep->side,ipc_rep->spi,tx_ikemesg,RHP_IKEV2_MESG_HANDLER_QCD);

  		}else if( ikesa->qcd.pend_pos == RHP_IKEV2_QCD_PEND_RX_REQ ){

    		rhp_ikev2_call_next_rx_request_mesg_handlers(rx_ikemesg,vpn,
    				ipc_rep->old_side,ipc_rep->old_spi,tx_ikemesg,RHP_IKEV2_MESG_HANDLER_QCD);

    		old_ikesa_dt = rhp_vpn_lifetime_random(10);

  		}else{
  			RHP_BUG("");
  			goto vpn_destroy;
  		}


    	if( old_ikesa ){

    		old_ikesa->busy_flag = 0;

    		old_ikesa->timers->schedule_delete(vpn,old_ikesa,old_ikesa_dt);
    	}

    	err = 0;

		}else{

vpn_destroy:
			rhp_vpn_destroy(vpn);
		}

		RHP_UNLOCK(&(vpn->lock));
		rhp_vpn_unhold(vpn_ref);
  }



	if( tx_ikemesg ){
		rhp_ikev2_unhold_mesg(tx_ikemesg);
	}

	if( rx_ikemesg ){
		rhp_ikev2_unhold_mesg(rx_ikemesg);
	}

  _rhp_free_zero(*ipcmsg,(*ipcmsg)->len);
  *ipcmsg = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_QCD_TKN_REP_IPC_HANDLER_RTRN,"xxxxxx",ipcmsg,ipc_rep,vpn,ikesa,tx_ikemesg,rx_ikemesg);
  return;
}


int rhp_ikev2_qcd_init()
{
	int err = -EINVAL;

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_MAIN ){
  	RHP_BUG("");
  	return -EINVAL;
  }

	{
		err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_QCD_TOKEN_REPLY,
				_rhp_ikev2_qcd_tkn_rep_ipc_handler,NULL);
		if( err ){
			RHP_BUG("");
			goto error;
		}


		err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_QCD_GEN_REPLY_TOKEN_REPLY,
				_rhp_ikev2_qcd_gen_rep_tkn_rep_ipc_handler,NULL);
		if( err ){
			RHP_BUG("");
			goto error;
		}
	}

  _rhp_mutex_init("LQC",&_rhp_ikev2_qcd_lock);
  _rhp_ikev2_qcd_req_last_rx_time = _rhp_get_time();
  _rhp_ikev2_qcd_rep_last_rx_time = _rhp_get_time();

  _rhp_atomic_init(&_rhp_ikev2_qcd_pend_pkts);
  _rhp_atomic_set(&_rhp_ikev2_qcd_pend_pkts,0);
  _rhp_atomic_init(&_rhp_ikev2_qcd_pend_pkts2);
  _rhp_atomic_set(&_rhp_ikev2_qcd_pend_pkts2,0);

  _rhp_ikev2_qcd_boot_time = _rhp_get_time();

	RHP_TRC(0,RHPTRCID_IKEV2_QCD_INIT_OK,"");
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_QCD_INIT_ERR,"E",err);
	return err;
}

int rhp_ikev2_qcd_cleanup()
{

	if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_MAIN ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  _rhp_mutex_destroy(&_rhp_ikev2_qcd_lock);
  _rhp_atomic_destroy(&_rhp_ikev2_qcd_pend_pkts);

	RHP_TRC(0,RHPTRCID_IKEV2_QCD_CLEANUP_OK,"");
	return 0;
}
