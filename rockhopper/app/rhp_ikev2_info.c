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
#include "rhp_http.h"



static int _rhp_ikev2_rx_info_req(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg)
{
  int err = 0;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_INFO_REQ_L,"xxxxLd",vpn,ikesa,rx_req_ikemesg,rx_req_ikemesg->rx_pkt,"IKESA_STAT",ikesa->state);

  if( rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  tx_resp_ikemesg->activated++;


  if( vpn->exec_mobike &&
  		vpn->origin_side == RHP_IKE_INITIATOR &&
  		vpn->mobike.init.rt_ck_waiting ){

		rhp_ikev2_mobike_i_rt_invoke_waiting_timer(vpn);
	}

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_INFO_REQ,"KVP",rx_req_ikemesg,vpn,ikesa);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_INFO_REQ_L_RTRN,"xxx",vpn,ikesa,rx_req_ikemesg);
  return 0;

error:
	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_INFO_REQ_ERR,"KVE",rx_req_ikemesg,vpn,err);

	rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
	ikesa->timers->schedule_delete(vpn,ikesa,0);

	return err;
}

static int _rhp_ikev2_rx_info_rep(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ikev2_mesg* tx_req_ikemesg)
{
  int err = 0;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_INFO_REP_L,"xxxxxLd",vpn,ikesa,rx_resp_ikemesg,rx_resp_ikemesg->rx_pkt,tx_req_ikemesg,"IKESA_STAT",ikesa->state);

  if( rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  if( vpn->exec_mobike && vpn->origin_side == RHP_IKE_RESPONDER &&
  		vpn->mobike.resp.keepalive_pending ){

  	vpn->mobike.resp.keepalive_pending = 0;


  	rhp_http_bus_broadcast_async(vpn->vpn_realm_id,1,1,
  			rhp_ui_http_vpn_mobike_r_net_outage_finished_serialize,
  			rhp_ui_http_vpn_bus_btx_async_cleanup,(void*)rhp_vpn_hold_ref(vpn)); // (*x*)

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_NET_OUTAGE_FINISHED_RT_CK,"VPK",vpn,ikesa,rx_resp_ikemesg);
  }

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_INFO_RESP,"KVP",rx_resp_ikemesg,vpn,ikesa);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_INFO_REP_L_RTRN,"xxx",vpn,ikesa,rx_resp_ikemesg);
	return 0;

error:
	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_INFO_RESP_ERR,"KVE",rx_resp_ikemesg,vpn,err);

	rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
	ikesa->timers->schedule_delete(vpn,ikesa,0);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_INFO_REP_L_ERR,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
	return err;
}

int rhp_ikev2_rx_info_req(rhp_ikev2_mesg* rx_req_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_req_ikemesg->get_exchange_type(rx_req_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_INFO_REQ,"xxLdGxLb",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_resp_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

	if( exchange_type == RHP_PROTO_IKE_EXCHG_INFORMATIONAL ){

		if( my_ikesa_spi == NULL ){
	    RHP_BUG("");
	    err = -EINVAL;
	    goto error;
	  }

	  if( !rx_req_ikemesg->decrypted ){
	  	err = 0;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_INFO_REQ_NOT_DECRYPTED,"xxLdG",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
	  	goto error;
	  }

		ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
		if( ikesa == NULL ){
			err = -ENOENT;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_INFO_REQ_NO_IKESA,"xxLdG",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}

		err = _rhp_ikev2_rx_info_req(vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);

	}else{
		err = 0;
		RHP_TRC(0,RHPTRCID_IKEV2_RX_INFO_REQ_NOT_INTERESTED,"xxx",rx_req_ikemesg,vpn,tx_resp_ikemesg);
	}

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_INFO_REQ_RTRN,"xxxE",rx_req_ikemesg,vpn,tx_resp_ikemesg,err);
  return err;
}

int rhp_ikev2_rx_info_rep(rhp_ikev2_mesg* rx_resp_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_resp_ikemesg->get_exchange_type(rx_resp_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_INFO_REP,"xxLdGxLb",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_req_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

	if( exchange_type == RHP_PROTO_IKE_EXCHG_INFORMATIONAL ){

	  if( !rx_resp_ikemesg->decrypted ){
	  	err = 0;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_INFO_REP_NOT_DECRYPTED,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
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
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_INFO_REP_NO_IKESA,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}

		err = _rhp_ikev2_rx_info_rep(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);

	}else{
		err = 0;
		RHP_TRC(0,RHPTRCID_IKEV2_RX_INFO_REP_NOT_INTERESTED,"xxx",rx_resp_ikemesg,vpn,tx_req_ikemesg);
	}

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_INFO_REP_RTRN,"xxxE",rx_resp_ikemesg,vpn,tx_req_ikemesg,err);
  return err;
}


