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


extern void rhp_ikev2_rekey_inherit_ikesa_info(rhp_ikesa* new_ikesa,rhp_ikesa* old_ikesa);

extern void rhp_ikev2_rekey_ikesa_tx_comp_cb(rhp_vpn* vpn,rhp_ikesa* tx_ikesa,
		rhp_ikev2_mesg* tx_ikemesg,rhp_packet* serialized_pkt);


extern int rhp_ikev1_new_pkt_quick_i_1(rhp_vpn* vpn,rhp_vpn_realm* rlm,
		rhp_ikesa* ikesa,rhp_childsa* childsa,int addr_family,rhp_ikev2_mesg* tx_ikemesg);

extern void rhp_ikev1_quick_i_new_sa_tx_comp_cb(rhp_vpn* vpn,rhp_ikesa* tx_ikesa,
		rhp_ikev2_mesg* tx_ikemesg,rhp_packet* serialized_pkt);



int rhp_ikev1_rekey_create_ikesa(rhp_vpn* vpn,rhp_vpn_realm* rlm,
		rhp_ikesa* old_ikesa,rhp_ikesa** new_ikesa_r,rhp_ikev2_mesg** ikemesg_r)
{
	int err = -EINVAL;
	rhp_ikesa* ikesa = NULL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_REKEY_CREATE_IKESA,"xxxxxx",vpn,rlm,old_ikesa,new_ikesa_r,ikemesg_r,old_ikesa->dh);


	if( old_ikesa->v1.p1_exchange_mode == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ){

		// This must be the top of this funcion.
		ikesa = rhp_ikesa_v1_main_new_i(rlm,vpn->cfg_peer);

	}else if( old_ikesa->v1.p1_exchange_mode == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){

		ikesa = rhp_ikesa_v1_aggressive_new_i(rlm,vpn->cfg_peer,old_ikesa->dh->grp);

	}else{
		RHP_BUG("%d",old_ikesa->v1.p1_exchange_mode);
	}
	if( ikesa == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}


  ikesa->peer_is_rockhopper = vpn->peer_is_rockhopper;
  ikesa->peer_rockhopper_ver = vpn->peer_rockhopper_ver;

	rhp_ikev2_rekey_inherit_ikesa_info(ikesa,old_ikesa);

	vpn->ikesa_put(vpn,ikesa);


	ikesa->timers = rhp_ikesa_v1_new_timers(RHP_IKE_INITIATOR,ikesa->init_spi);
	if( ikesa->timers == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}


  {
		if( old_ikesa->v1.p1_exchange_mode == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ){

			tx_ikemesg = rhp_ikev1_new_pkt_main_i_1(ikesa);

		}else if( old_ikesa->v1.p1_exchange_mode == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){

			tx_ikemesg = rhp_ikev1_new_pkt_aggressive_i_1(vpn,ikesa,rlm);

		}else{
			RHP_BUG("%d",old_ikesa->v1.p1_exchange_mode);
		}
		if( tx_ikemesg == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}

		tx_ikemesg->ikesa_rekey.new_ikesa_my_side = ikesa->side;
		memcpy(tx_ikemesg->ikesa_rekey.new_ikesa_my_spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);

		tx_ikemesg->packet_serialized = rhp_ikev2_rekey_ikesa_tx_comp_cb;

		{
			tx_ikemesg->for_ikesa_rekey = 1;

			tx_ikemesg->rekeyed_ikesa_my_side = ikesa->side;
			memcpy(tx_ikemesg->rekeyed_ikesa_my_spi,ikesa->get_my_spi(ikesa),RHP_PROTO_IKE_SPI_SIZE);
		}
  }


  err = rhp_vpn_ikesa_spi_put(vpn,ikesa->side,ikesa->init_spi);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }


  ikesa->signed_octets.ikemesg_i_1st = tx_ikemesg;
  rhp_ikev2_hold_mesg(tx_ikemesg);


  ikesa->timers->start_lifetime_timer(vpn,ikesa,(time_t)rlm->ikesa.lifetime_larval,1);


	if( old_ikesa->v1.p1_exchange_mode == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ){

		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_MAIN_1ST_SENT_I);

	}else if( old_ikesa->v1.p1_exchange_mode == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){

		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_AGG_1ST_SENT_I);
	}


	*new_ikesa_r = ikesa;
	*ikemesg_r = tx_ikemesg;

  RHP_TRC(0,RHPTRCID_IKEV1_REKEY_CREATE_IKESA_RTRN,"xxxxx",vpn,rlm,ikesa,old_ikesa,tx_ikemesg);
	return 0;

error:
	if( tx_ikemesg ){
		rhp_ikev2_unhold_mesg(tx_ikemesg);
	}
	if( ikesa ){
		rhp_ikesa_destroy(vpn,ikesa);
	}

  RHP_TRC(0,RHPTRCID_IKEV1_REKEY_CREATE_IKESA_ERR,"xxxE",vpn,rlm,old_ikesa,err);
	return err;
}

int rhp_ikev1_rekey_create_childsa(rhp_vpn* vpn,rhp_vpn_realm* rlm,
			rhp_childsa* old_childsa,rhp_ikev2_mesg** ikemesg_r)
{
	int err = -EINVAL;
  rhp_childsa* childsa = NULL;
  rhp_ikesa* ikesa = NULL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  u32 tx_mesg_id;

  RHP_TRC(0,RHPTRCID_IKEV1_REKEY_CREATE_CHILDSA,"xxxd",vpn,vpn->ikesa_list_head,rlm->encap_mode_c,vpn->peer_is_rockhopper);


  ikesa = vpn->ikesa_list_head;
  if( ikesa == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }


  {
		err = rhp_random_bytes((u8*)&tx_mesg_id,sizeof(u32));
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		tx_ikemesg = rhp_ikev1_new_mesg_tx(RHP_PROTO_IKEV1_EXCHG_QUICK,tx_mesg_id,0);
		if( tx_ikemesg == NULL ){
			RHP_BUG("");
			goto error;
		}

		tx_ikemesg->set_mesg_id(tx_ikemesg,tx_mesg_id);
  }


  childsa = rhp_childsa_alloc(RHP_IKE_INITIATOR,1);
  if( childsa == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

  childsa->gen_type = RHP_CHILDSA_GEN_IKEV1_REKEY;

  childsa->v1.addr_family = old_childsa->v1.addr_family;

  err = childsa->generate_inb_spi(childsa);
  if( err ){
    RHP_BUG("");
    goto error;
  }


  childsa->timers = rhp_ipsecsa_v1_new_timers(childsa->spi_inb,childsa->spi_outb);
  if( childsa->timers == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

  childsa->rekeyed_gen = (old_childsa->rekeyed_gen + 1);

  childsa->ipsec_mode = old_childsa->ipsec_mode;



	err = rhp_ikev1_new_pkt_quick_i_1(vpn,rlm,ikesa,childsa,childsa->v1.addr_family,tx_ikemesg);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

  tx_ikemesg->v1_start_retx_timer = 1;


  rhp_childsa_set_state(childsa,RHP_IPSECSA_STAT_V1_1ST_SENT_I);


  err = rhp_vpn_inb_childsa_put(vpn,childsa->spi_inb);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  vpn->childsa_put(vpn,childsa);

  childsa->timers->start_lifetime_timer(vpn,childsa,(time_t)rlm->childsa.lifetime_larval,1);


	tx_ikemesg->childsa_spi_inb = childsa->spi_inb;
	tx_ikemesg->packet_serialized = rhp_ikev1_quick_i_new_sa_tx_comp_cb;


	rhp_ikev1_p2_session_tx_put(ikesa,tx_ikemesg->get_mesg_id(tx_ikemesg),RHP_PROTO_IKEV1_EXCHG_QUICK,0,0);


	*ikemesg_r = tx_ikemesg;

  RHP_TRC(0,RHPTRCID_IKEV1_REKEY_CREATE_CHILDSA_RTRN,"xxx",vpn,ikesa,tx_ikemesg);
  return 0;

error:

	if( childsa ){
    rhp_childsa_destroy(vpn,childsa);
  }

	if( tx_ikemesg ){
		rhp_ikev2_unhold_mesg(tx_ikemesg);
	}

  RHP_TRC(0,RHPTRCID_IKEV1_REKEY_CREATE_CHILDSA_ERR,"xxxE",vpn,ikesa,tx_ikemesg,err);
  return err;
}
