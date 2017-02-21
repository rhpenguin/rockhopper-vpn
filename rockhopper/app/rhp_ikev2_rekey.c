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
#include "rhp_esp.h"
#include "rhp_nhrp.h"

#define RHP_IKEV2_RX_CREATE_CHILDSA_REKEY_IKE_SA			1
#define RHP_IKEV2_RX_CREATE_CHILDSA_REKEY_CHILD_SA		2

void rhp_ikev2_rekey_inherit_ikesa_info(rhp_ikesa* new_ikesa,rhp_ikesa* old_ikesa)
{
  new_ikesa->rekeyed_gen = (old_ikesa->rekeyed_gen + 1);

  new_ikesa->auth_method = old_ikesa->auth_method;
  new_ikesa->peer_auth_method = old_ikesa->peer_auth_method;

  new_ikesa->eap.state = old_ikesa->eap.state;

	return;
}

void rhp_ikev2_rekey_childsa_tx_comp_cb(rhp_vpn* vpn,rhp_ikesa* tx_ikesa,
		rhp_ikev2_mesg* tx_ikemesg,rhp_packet* serialized_pkt)
{
  rhp_childsa* new_childsa = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_REKEY_CHILDSA_TX_COMP_CB,"xxxxx",vpn,tx_ikesa,tx_ikemesg,tx_ikemesg->rx_pkt,serialized_pkt);

  new_childsa = vpn->childsa_get(vpn,RHP_DIR_INBOUND,tx_ikemesg->childsa_spi_inb);

  if( new_childsa ){

  	new_childsa->parent_ikesa.side = tx_ikesa->side;

  	memcpy(new_childsa->parent_ikesa.init_spi,tx_ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
  	memcpy(new_childsa->parent_ikesa.resp_spi,tx_ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);

  	new_childsa->gen_message_id = tx_ikemesg->get_mesg_id(tx_ikemesg);

  }else{

    RHP_TRC(0,RHPTRCID_IKEV2_REKEY_CHILDSA_TX_COMP_CB_CHILDSA_NOT_FOUND,"xxx",vpn,tx_ikesa,tx_ikemesg);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_REKEY_CHILDSA_TX_COMP_CB_RTRN,"xxx",vpn,tx_ikesa,tx_ikemesg);
  return;
}


static int _rhp_ikev2_rekey_ipv6_autoconf_dup_ts(rhp_childsa_ts* old_ts,
		rhp_childsa_ts** new_tss_head,rhp_childsa_ts** new_tss_tail)
{
  int err = -EINVAL;
	rhp_childsa_ts* new_ts = (rhp_childsa_ts*)_rhp_malloc(sizeof(rhp_childsa_ts));

  RHP_TRC(0,RHPTRCID_IKEV2_REKEY_IPV6_AUTOCONF_DUP_TS,"xxxxx",old_ts,new_tss_head,*new_tss_head,new_tss_tail,*new_tss_tail);
  rhp_childsa_ts_dump("old_ts",old_ts);

	if( new_ts == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	memset(new_ts,0,sizeof(rhp_childsa_ts));

	err = rhp_childsa_ts_dup(old_ts,new_ts);
	if( err ){
		RHP_BUG("");
		goto error;
	}

	if( new_ts->flag == RHP_CHILDSA_TS_IS_PENDING ){
		new_ts->flag = 0;
	}
	new_ts->next = NULL;

	if( *new_tss_head == NULL ){
		*new_tss_head = new_ts;
	}else{
		(*new_tss_tail)->next = new_ts;
	}
	*new_tss_tail = new_ts;

	rhp_childsa_ts_dump("new_ts",new_ts);
	new_ts = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_REKEY_IPV6_AUTOCONF_DUP_TS_RTRN,"xxx",old_ts,*new_tss_head,*new_tss_tail);
	return 0;

error:
	if( new_ts ){
		_rhp_free(new_ts);
	}
  RHP_TRC(0,RHPTRCID_IKEV2_REKEY_IPV6_AUTOCONF_DUP_TS_ERR,"xE",old_ts);
	return err;
}

static int _rhp_ikev2_rekey_ipv6_autoconf_replace_ts_r(rhp_vpn* vpn,rhp_childsa_ts* old_ts,
		rhp_childsa_ts** new_tss_head,rhp_childsa_ts** new_tss_tail)
{
  int err = -EINVAL;
	rhp_ip_addr_list* peer_addr = vpn->internal_net_info.peer_addrs;
	rhp_childsa_ts* new_ts = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_REKEY_IPV6_AUTOCONF_REPLACE_TS_R,"xxxxxxx",vpn,old_ts,new_tss_head,*new_tss_head,new_tss_tail,*new_tss_tail,peer_addr);
  rhp_childsa_ts_dump("old_ts",old_ts);

	while( peer_addr ){

		rhp_ip_addr_dump("peer_addr",&(peer_addr->ip_addr));

		if( peer_addr->ip_addr.addr_family == AF_INET6 &&
				old_ts->ts_or_id_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){

			if( rhp_childsa_ts_addr_included(old_ts,&(peer_addr->ip_addr)) ){

				new_ts = (rhp_childsa_ts*)_rhp_malloc(sizeof(rhp_childsa_ts));
				if( new_ts == NULL ){
					RHP_BUG("");
					err = -ENOMEM;
					goto error;
				}
				memset(new_ts,0,sizeof(rhp_childsa_ts));

				err = rhp_childsa_ts_dup(old_ts,new_ts);
				if( err ){
					RHP_BUG("");
					goto error;
				}

				err = rhp_childsa_ts_replace_addrs(new_ts,&(peer_addr->ip_addr),&(peer_addr->ip_addr));
				if( err ){
					RHP_BUG("");
					goto error;
				}

				if( new_ts->flag == RHP_CHILDSA_TS_IS_PENDING ){
					new_ts->flag = 0;
				}
				new_ts->next = NULL;

				if( *new_tss_head == NULL ){
					*new_tss_head = new_ts;
				}else{
					(*new_tss_tail)->next = new_ts;
				}
				*new_tss_tail = new_ts;

				rhp_childsa_ts_dump("new_ts",new_ts);
				new_ts = NULL;
			}
		}

		peer_addr = peer_addr->next;
	}

  RHP_TRC(0,RHPTRCID_IKEV2_REKEY_IPV6_AUTOCONF_REPLACE_TS_R_RTRN,"xx",vpn,old_ts);
	return 0;

error:
	if( new_ts ){
		_rhp_free(new_ts);
	}
  RHP_TRC(0,RHPTRCID_IKEV2_REKEY_IPV6_AUTOCONF_REPLACE_TS_R_ERR,"xxE",vpn,old_ts,err);
	return err;
}

static int _rhp_ikev2_rekey_ipv6_autoconf_new_csa_ts(int side,rhp_vpn* vpn,
		rhp_childsa* old_childsa,rhp_childsa_ts** res_tss_r)
{
  int err = -EINVAL;
  rhp_childsa_ts *old_ts = NULL, *old_tss = NULL;
  rhp_childsa_ts *new_tss_head = NULL, *new_tss_tail = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_REKEY_IPV6_AUTOCONF_NEW_CSA_TS,"Ldxxxxx","IKE_SIDE",side,vpn,old_childsa,res_tss_r,vpn->ipv6_autoconf_my_tss,vpn->ipv6_autoconf_peer_tss);

  if( side == RHP_IKE_INITIATOR ){

    if( vpn->ipv6_autoconf_my_tss ){

    	old_ts = vpn->ipv6_autoconf_my_tss;
    	old_tss = vpn->ipv6_autoconf_my_tss;

    }else{

    	old_ts = old_childsa->my_tss;
    	old_tss = old_childsa->my_tss;

    	err = rhp_childsa_dup_traffic_selectors(old_childsa,&(vpn->ipv6_autoconf_my_tss),NULL);
    	if( err ){
    		RHP_BUG("");
    	}
    	err = 0;
    }

  }else{

    if( vpn->ipv6_autoconf_peer_tss ){

    	old_ts = vpn->ipv6_autoconf_peer_tss;
    	old_tss = vpn->ipv6_autoconf_peer_tss;

    }else{

    	old_ts = old_childsa->peer_tss;
    	old_tss = old_childsa->peer_tss;

    	err = rhp_childsa_dup_traffic_selectors(old_childsa,NULL,&(vpn->ipv6_autoconf_peer_tss));
    	if( err ){
    		RHP_BUG("");
    	}
    	err = 0;
    }
  }

  while( old_ts ){

//  rhp_childsa_ts_dump("IKEV2_REKEY_IPV6_AUTOCONF_NEW_CSA_TS",old_ts);

  	if( old_ts->flag != RHP_CHILDSA_TS_NOT_USED ){

			if( !old_ts->flag ||
					side == RHP_IKE_INITIATOR ||
					!vpn->internal_net_info.ipv6_autoconf_narrow_ts_i ){

		  	if( side == RHP_IKE_RESPONDER ||
		  			rhp_childsa_ts_cmp_same_or_any(old_ts,old_tss) ){

					err = _rhp_ikev2_rekey_ipv6_autoconf_dup_ts(old_ts,&new_tss_head,&new_tss_tail);
					if( err ){
						goto error;
					}
		  	}

			}else{

				err = _rhp_ikev2_rekey_ipv6_autoconf_replace_ts_r(vpn,old_ts,&new_tss_head,&new_tss_tail);
				if( err ){
					goto error;
				}
			}
  	}

  	old_ts = old_ts->next;
  }


  *res_tss_r = new_tss_head;


	_RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
  if( _RHP_TRC_COND(_rhp_trc_user_id(),0) ){
  	rhp_childsa_ts* tmp_ts = *res_tss_r;
  	while(tmp_ts){
  		rhp_childsa_ts_dump("IPV6_AUTOCONF_NEW_CSA_TS",tmp_ts);
  		tmp_ts = tmp_ts->next;
  	}
  }

  RHP_TRC(0,RHPTRCID_IKEV2_REKEY_IPV6_AUTOCONF_NEW_CSA_TS_RTRN,"Ldxxx","IKE_SIDE",side,vpn,old_childsa,res_tss_r);
  return 0;

error:
	if( new_tss_head ){
		rhp_childsa_free_traffic_selectors(new_tss_head,NULL);
	}

  RHP_TRC(0,RHPTRCID_IKEV2_REKEY_IPV6_AUTOCONF_NEW_CSA_TS_ERR,"LdxxE","IKE_SIDE",side,vpn,old_childsa,err);
	return err;
}

int rhp_ikev2_rekey_create_childsa(rhp_vpn* vpn,rhp_vpn_realm* rlm,
			rhp_childsa* old_childsa,int by_ipv6_autoconf,rhp_ikev2_mesg** ikemesg_r)
{
  int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;
  rhp_childsa* new_childsa = NULL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_ikesa* ikesa = NULL;
	time_t now = _rhp_get_time();
	time_t lifetime_larval;

  RHP_TRC(0,RHPTRCID_IKEV2_REKEY_CREATE_CHILDSA,"xxxffddd",vpn,old_childsa,ikemesg_r,old_childsa->expire_hard,now,rlm->config_server.allow_v6_ra,vpn->ts_extended_flag,by_ipv6_autoconf);

  if( old_childsa->expire_hard <= now ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  lifetime_larval = old_childsa->expire_hard - now;


  ikesa = vpn->ikesa_list_head;
  if( ikesa == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }


  new_childsa = rhp_childsa_alloc2_i(vpn,rlm->childsa.pfs);
  if( new_childsa == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

  new_childsa->gen_type = RHP_CHILDSA_GEN_REKEY;

  new_childsa->timers = rhp_childsa_new_timers(new_childsa->spi_inb,new_childsa->spi_outb);
  if( new_childsa->timers == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

  new_childsa->rekeyed_gen = (old_childsa->rekeyed_gen + 1);

	new_childsa->ipsec_mode = old_childsa->ipsec_mode;



  tx_ikemesg = rhp_ikev2_new_mesg_tx(RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA,0,0);
  if( tx_ikemesg == NULL ){
    RHP_BUG("");
    goto error;
  }

  {
    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    ikepayload->ext.n->set_protocol_id(ikepayload,RHP_PROTO_IKE_PROTOID_ESP);

    ikepayload->ext.n->set_spi(ikepayload,old_childsa->spi_inb);

    ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_REKEY_SA);
  }

	if( new_childsa->ipsec_mode == RHP_CHILDSA_MODE_TRANSPORT ){

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    ikepayload->ext.n->set_protocol_id(ikepayload,0);

    ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_USE_TRANSPORT_MODE);
	}

  {
  	u16 rekey_pfs_dhgrp_id = 0;

    if( (err = rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_SA,&ikepayload)) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( rlm->childsa.pfs ){
   	  rekey_pfs_dhgrp_id = new_childsa->rekey_dh->grp;
    }

    err = ikepayload->ext.sa->copy_childsa_prop(ikepayload,(u8*)&(new_childsa->spi_inb),
  		 RHP_PROTO_IPSEC_SPI_SIZE,old_childsa,rekey_pfs_dhgrp_id);

    if( err ){
    	RHP_BUG("");
    	goto error;
    }
  }

  {
    int nonce_len = new_childsa->rekey_nonce_i->get_nonce_len(new_childsa->rekey_nonce_i);
    u8* nonce = new_childsa->rekey_nonce_i->get_nonce(new_childsa->rekey_nonce_i);

    if( nonce == NULL ){
      RHP_BUG("");
      goto error;
    }

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N_I_R,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.nir->set_nonce(ikepayload,nonce_len,nonce) ){
      RHP_BUG("");
      goto error;
    }
  }

  if( rlm->childsa.pfs ){

    int key_len;
    u8* key = new_childsa->rekey_dh->get_my_pub_key(new_childsa->rekey_dh,&key_len);

    if( key == NULL ){
      RHP_BUG("");
      goto error;
    }

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_KE,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.ke->set_key(ikepayload,new_childsa->rekey_dh->grp,key_len,key) ){
      RHP_BUG("");
      goto error;
    }
  }

  {
    if( (err = rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_TS_I,&ikepayload)) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( vpn->internal_net_info.peer_exec_ipv6_autoconf ){

    	rhp_childsa_ts* res_tss_i = NULL;

    	err = _rhp_ikev2_rekey_ipv6_autoconf_new_csa_ts(RHP_IKE_INITIATOR,vpn,
    					old_childsa,&res_tss_i);
    	if( err ){
    		RHP_BUG("%d",err);
    		goto error;
    	}

			if( (err = ikepayload->ext.ts->set_tss(ikepayload,res_tss_i)) ){
				RHP_BUG("");
				goto error;
			}

  		rhp_childsa_free_traffic_selectors(res_tss_i,NULL);

    }else if( vpn->ts_extended_flag ){

    	if( vpn->last_my_tss == NULL ){
    		err = -EINVAL;
    		RHP_BUG("");
    		goto error;
    	}

			if( (err = ikepayload->ext.ts->set_tss(ikepayload,vpn->last_my_tss)) ){
				RHP_BUG("");
				goto error;
			}

    }else{

      if( (err = ikepayload->ext.ts->set_i_tss(ikepayload,rlm,vpn->cfg_peer,NULL,NULL)) ){
        RHP_BUG("");
        goto error;
      }
    }
  }

  {
    if( (err = rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_TS_R,&ikepayload)) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( vpn->internal_net_info.peer_exec_ipv6_autoconf ){

    	rhp_childsa_ts* res_tss_r = NULL;

    	err = _rhp_ikev2_rekey_ipv6_autoconf_new_csa_ts(RHP_IKE_RESPONDER,vpn,
    					old_childsa,&res_tss_r);
    	if( err ){
    		RHP_BUG("%d",err);
    		goto error;
    	}

			if( (err = ikepayload->ext.ts->set_tss(ikepayload,res_tss_r)) ){
				RHP_BUG("");
				goto error;
			}

  		rhp_childsa_free_traffic_selectors(res_tss_r,NULL);

    }else if( vpn->ts_extended_flag ){

    	if( vpn->last_peer_tss == NULL ){
    		err = -EINVAL;
    		RHP_BUG("");
    		goto error;
    	}

			if( (err = ikepayload->ext.ts->set_tss(ikepayload,vpn->last_peer_tss)) ){
				RHP_BUG("");
				goto error;
			}

    }else{

      if( (err = ikepayload->ext.ts->set_i_tss(ikepayload,rlm,vpn->cfg_peer,NULL,NULL)) ){
        RHP_BUG("");
        goto error;
      }
    }
  }

	if( (vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_ETHERIP) && vpn->peer_is_rockhopper ){

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    ikepayload->ext.n->set_protocol_id(ikepayload,0);

    ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_ETHERIP_ENCAP);

	}else if( (vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_GRE) && vpn->peer_is_rockhopper ){

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    ikepayload->ext.n->set_protocol_id(ikepayload,0);

    ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_GRE_ENCAP);
	}


	if( vpn->internal_net_info.peer_exec_ipv6_autoconf && by_ipv6_autoconf ){

		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    ikepayload->ext.n->set_protocol_id(ikepayload,0);

    ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_IPV6_AUTOCONF_REKEY_SA);
	}



  rhp_childsa_set_state(new_childsa,RHP_CHILDSA_STAT_LARVAL);

  err = rhp_vpn_inb_childsa_put(vpn,new_childsa->spi_inb);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  vpn->childsa_put(vpn,new_childsa);


  new_childsa->timers->start_lifetime_timer(vpn,new_childsa,lifetime_larval,0);


  tx_ikemesg->childsa_spi_inb = new_childsa->spi_inb;
  tx_ikemesg->packet_serialized = rhp_ikev2_rekey_childsa_tx_comp_cb;

  *ikemesg_r = tx_ikemesg;

  RHP_TRC(0,RHPTRCID_IKEV2_REKEY_CREATE_CHILDSA_RTRN,"xxxf",vpn,old_childsa,*ikemesg_r,lifetime_larval);
  return 0;

error:
  if( new_childsa ){
  	rhp_childsa_destroy(vpn,new_childsa);
  }

  if( tx_ikemesg ){
    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_REKEY_CREATE_CHILDSA_ERR,"xxE",vpn,old_childsa,err);
  return -EINVAL;
}

void rhp_ikev2_rekey_ikesa_tx_comp_cb(rhp_vpn* vpn,rhp_ikesa* tx_ikesa,
		rhp_ikev2_mesg* tx_ikemesg,rhp_packet* serialized_pkt)
{
  rhp_ikesa* new_ikesa;
  u32 mesg_id;

  RHP_TRC(0,RHPTRCID_IKEV2_REKEY_IKESA_TX_COMP_CB,"xxxx",vpn,tx_ikesa,tx_ikemesg,serialized_pkt);

  mesg_id = tx_ikemesg->get_mesg_id(tx_ikemesg);

  new_ikesa = vpn->ikesa_get(vpn,tx_ikemesg->ikesa_rekey.new_ikesa_my_side,tx_ikemesg->ikesa_rekey.new_ikesa_my_spi);

  if( new_ikesa ){

    new_ikesa->parent_ikesa.side = tx_ikesa->side;

    memcpy(new_ikesa->parent_ikesa.init_spi,tx_ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
    memcpy(new_ikesa->parent_ikesa.resp_spi,tx_ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);

    new_ikesa->gen_message_id = tx_ikemesg->get_mesg_id(tx_ikemesg);
    tx_ikesa->rekey_ikesa_message_id = new_ikesa->gen_message_id;

  }else{

    RHP_TRC(0,RHPTRCID_IKEV2_REKEY_IKESA_TX_COMP_CB_NEW_IKESA_NOT_FOUND,"xxxxJ",vpn,tx_ikesa,new_ikesa,tx_ikemesg,mesg_id);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_REKEY_IKESA_TX_COMP_CB_RTRN,"xxxxJ",vpn,tx_ikesa,new_ikesa,tx_ikemesg,mesg_id);
  return;
}

int rhp_ikev2_rekey_create_ikesa(rhp_vpn* vpn,rhp_vpn_realm* rlm,rhp_ikesa* old_ikesa,rhp_ikev2_mesg** ikemesg_r)
{
  int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;
  rhp_ikesa* new_ikesa = NULL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
	time_t now = _rhp_get_time();
	time_t lifetime_larval;

  RHP_TRC(0,RHPTRCID_IKEV2_REKEY_CREATE_IKESA,"xxxffdLddd",vpn,old_ikesa,ikemesg_r,old_ikesa->expire_hard,now,rhp_gcfg_ikev2_sess_resume_init_enabled,"IKE_SIDE",vpn->origin_side,vpn->sess_resume.exec_sess_resume,vpn->sess_resume.tkt_req_pending);

  if( old_ikesa->expire_hard <= now ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  lifetime_larval = old_ikesa->expire_hard - now;


  new_ikesa = rhp_ikesa_new_i(rlm,NULL,old_ikesa->dh->grp);
  if( new_ikesa == NULL ){
    RHP_BUG("");
    goto error;
  }

  new_ikesa->peer_is_rockhopper = vpn->peer_is_rockhopper;
  new_ikesa->peer_rockhopper_ver = vpn->peer_rockhopper_ver;

	rhp_ikev2_rekey_inherit_ikesa_info(new_ikesa,old_ikesa);

  new_ikesa->timers = rhp_ikesa_new_timers(RHP_IKE_INITIATOR,new_ikesa->init_spi);
  if( new_ikesa->timers == NULL ){
    RHP_BUG("");
    goto error;
  }

  tx_ikemesg = rhp_ikev2_new_mesg_tx(RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA,0,0);
  if( tx_ikemesg == NULL ){
    RHP_BUG("");
    goto error;
  }

  {
    if( (err = rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_SA,&ikepayload)) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    // Copy old IKE SA's security props. For inter-op with Win7.
    err = ikepayload->ext.sa->copy_ikesa_prop(ikepayload,new_ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE,old_ikesa);
    if( err ){
      RHP_BUG("");
      goto error;
    }
  }

  {
    int nonce_len = new_ikesa->nonce_i->get_nonce_len(new_ikesa->nonce_i);
    u8* nonce = new_ikesa->nonce_i->get_nonce(new_ikesa->nonce_i);

    if( nonce == NULL ){
      RHP_BUG("");
      goto error;
    }

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N_I_R,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.nir->set_nonce(ikepayload,nonce_len,nonce) ){
      RHP_BUG("");
      goto error;
    }
  }

  {
    int key_len;
    u8* key = new_ikesa->dh->get_my_pub_key(new_ikesa->dh,&key_len);

    if( key == NULL ){
      RHP_BUG("");
      goto error;
    }

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_KE,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.ke->set_key(ikepayload,new_ikesa->dh->grp,key_len,key) ){
      RHP_BUG("");
      goto error;
    }
  }


  if( rhp_gcfg_ikev2_sess_resume_init_enabled ){

    if( vpn->origin_side == RHP_IKE_INITIATOR &&
    		vpn->sess_resume.exec_sess_resume &&
    		!vpn->sess_resume.tkt_req_pending ){

		 	err = rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload);
		 	if( err ){
	      RHP_BUG("");
	      goto error;
		 	}

		 	tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

		 	ikepayload->ext.n->set_protocol_id(ikepayload,0);

		 	ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_TICKET_REQUEST);


	  	vpn->sess_resume.tkt_req_pending = 1;
    }
  }

  rhp_ikesa_set_state(new_ikesa,RHP_IKESA_STAT_I_REKEY_SENT);

  err = rhp_vpn_ikesa_spi_put(vpn,new_ikesa->side,new_ikesa->init_spi);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  vpn->ikesa_put(vpn,new_ikesa);


  new_ikesa->timers->start_lifetime_timer(vpn,new_ikesa,lifetime_larval,0);


  tx_ikemesg->ikesa_rekey.new_ikesa_my_side = new_ikesa->side;
  memcpy(tx_ikemesg->ikesa_rekey.new_ikesa_my_spi,new_ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);

  tx_ikemesg->packet_serialized = rhp_ikev2_rekey_ikesa_tx_comp_cb;

  {
		tx_ikemesg->for_ikesa_rekey = 1;

		tx_ikemesg->rekeyed_ikesa_my_side = new_ikesa->side;
		memcpy(tx_ikemesg->rekeyed_ikesa_my_spi,new_ikesa->get_my_spi(new_ikesa),RHP_PROTO_IKE_SPI_SIZE);
  }

  *ikemesg_r = tx_ikemesg;

  RHP_TRC(0,RHPTRCID_IKEV2_REKEY_CREATE_IKESA_RTRN,"xxxLdGGxf",vpn,old_ikesa,new_ikesa,"IKE_SIDE",new_ikesa->side,new_ikesa->init_spi,new_ikesa->resp_spi,*ikemesg_r,lifetime_larval);
  return 0;

error:
  if( new_ikesa ){
		rhp_ikesa_set_state(new_ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		new_ikesa->timers->schedule_delete(vpn,new_ikesa,0);
  }

  if( tx_ikemesg ){
    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_REKEY_CREATE_IKESA_ERR,"xxxE",vpn,old_ikesa,new_ikesa,err);
  return err;
}

static int _rhp_ikev2_rekey_srch_sa_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_childsa_srch_plds_ctx* s_pld_ctx = (rhp_childsa_srch_plds_ctx*)ctx;
  rhp_ikev2_sa_payload* sa_payload = (rhp_ikev2_sa_payload*)payload->ext.sa;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_SA_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

  if( sa_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_SA_CB_DUP_ERR,"xxx",rx_ikemesg,payload,ctx);
    goto error;
  }

  s_pld_ctx->sa_payload = payload;
  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_SA_CB_RTRN,"xxxE",rx_ikemesg,payload,ctx,err);
  return err;
}

static int _rhp_ikev2_rekey_new_pkt_error_notify_rep(rhp_ikev2_mesg* tx_ikemesg,rhp_ikesa* ikesa,
		u8 protocol_id,u32 childsa_spi,u16 notify_mesg_type,unsigned long arg0)
{
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_ERROR_NOTIFY_REKEY_R,"xxbJwx",tx_ikemesg,ikesa,protocol_id,childsa_spi,notify_mesg_type,arg0);

  {
  	if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
    	RHP_BUG("");
    	goto error;
    }

  	tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

  	ikepayload->ext.n->set_message_type(ikepayload,notify_mesg_type);

  	if( childsa_spi ){
    	ikepayload->ext.n->set_protocol_id(ikepayload,protocol_id);
  		ikepayload->ext.n->set_spi(ikepayload,childsa_spi);
    }else{
    	ikepayload->ext.n->set_protocol_id(ikepayload,0);
    }

    switch( notify_mesg_type ){

    case RHP_PROTO_IKE_NOTIFY_ERR_NO_PROPOSAL_CHOSEN:
    case RHP_PROTO_IKE_NOTIFY_ERR_TS_UNACCEPTABLE:
    case RHP_PROTO_IKE_NOTIFY_ERR_NO_ADDITIONAL_SAS:
    case RHP_PROTO_IKE_NOTIFY_ERR_INVALID_SPI:
    case RHP_PROTO_IKE_NOTIFY_ERR_TEMPORARY_FAILURE:
    case RHP_PROTO_IKE_NOTIFY_ERR_CHILD_SA_NOT_FOUND:
    	break;

    default:
      RHP_BUG("%d",notify_mesg_type);
      goto error;
    }
  }

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_ERROR_NOTIFY_REKEY_R_RTRN,"x",tx_ikemesg);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_NEW_ERROR_NOTIFY_REKEY_R_ERR,"x",tx_ikemesg);
	return -1; // ikepayload will be released later by rhp_ikev2_destroy_mesg().
}

static void _rhp_rekey_cleanup_dup_ikesa_handler(void *ctx)
{
	int err = -EINVAL;
  rhp_vpn_ref* vpn_ref = (rhp_vpn_ref*)ctx;
  rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);
  rhp_ikesa *col_ikesa = NULL,*colsa0 = NULL,*colsa1 = NULL;

  RHP_TRC(0,RHPTRCID_REKEY_CLEANUP_DUP_IKESA_HANDLER,"x",vpn);

  RHP_LOCK(&(vpn->lock));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_REKEY_CLEANUP_DUP_IKESA_HANDLER_VPN_NOT_ACTIVE,"x",vpn);
    goto error;
  }

  col_ikesa = vpn->ikesa_list_head;

  while( col_ikesa ){

    if( col_ikesa->collision_detected ){

    	if( col_ikesa->state == RHP_IKESA_STAT_I_REKEY_SENT ){
    		goto retry;
    	}else if( col_ikesa->state != RHP_IKESA_STAT_ESTABLISHED ){
    		goto ignore;
    	}

      if( colsa0 == NULL ){
      	colsa0 = col_ikesa;
      }else if( colsa1 == NULL ){
      	colsa1 = col_ikesa;
       }

      col_ikesa->collision_detected = 0;
     }

    col_ikesa = col_ikesa->next_vpn_list;
  }

  if( colsa0 && colsa1 ){

  	rhp_crypto_nonce *col_nonce0 = NULL,*col_nonce1 = NULL;

    if( rhp_crypto_nonce_cmp(col_ikesa->nonce_i,col_ikesa->nonce_r) <= 0 ){
    	col_nonce0 = colsa0->nonce_i;
    }else{
    	col_nonce0 = colsa0->nonce_r;
     }

    if( rhp_crypto_nonce_cmp(col_ikesa->nonce_i,col_ikesa->nonce_r) <= 0 ){
    	col_nonce1 = colsa1->nonce_i;
    }else{
    	col_nonce1 = colsa1->nonce_r;
     }

  	if( rhp_crypto_nonce_cmp(col_nonce0,col_nonce1) <= 0 ){
  		col_ikesa = colsa0;
  	}else{
  		col_ikesa = colsa1;
  	}

  	if( col_ikesa->side != RHP_IKE_INITIATOR ){

  		// This collision SA is NOT initiated by this node. Peer node will sent Delete SA mesg soon!

  		rhp_ikesa* topsa = NULL;

  		if( colsa0->side == RHP_IKE_INITIATOR ){
  			topsa = colsa0;
  		}else if( colsa1->side == RHP_IKE_INITIATOR ){
  			topsa = colsa1;
  		}

  		if( topsa ){
  			vpn->ikesa_move_to_top(vpn,topsa);
  		}

  	  RHP_TRC(0,RHPTRCID_REKEY_CLEANUP_DUP_IKESA_HANDLER_NOT_INITIATOR_IGNORED,"xxxxx",vpn,col_ikesa,colsa0,colsa1,topsa);
  		goto ignore;
  	}

	  RHP_TRC(0,RHPTRCID_REKEY_CLEANUP_DUP_IKESA_HANDLER_DELETED_SA,"xxxx",vpn,col_ikesa,colsa0,colsa1);

	  col_ikesa->timers->schedule_delete(vpn,col_ikesa,0);
  	err = 0;
  }

ignore:
  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

  RHP_TRC(0,RHPTRCID_REKEY_CLEANUP_DUP_IKESA_HANDLER_RTRN,"x",vpn);
  return;

error:
  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

  RHP_TRC(0,RHPTRCID_REKEY_CLEANUP_DUP_IKESA_HANDLER_ERR,"xE",vpn,err);
  return;

retry:
  rhp_timer_oneshot(_rhp_rekey_cleanup_dup_ikesa_handler,rhp_vpn_hold_ref(vpn),RHP_CFG_CLEANUP_DUP_SA_MARGIN);

  RHP_UNLOCK(&(vpn->lock));
  rhp_vpn_unhold(vpn_ref);

  RHP_TRC(0,RHPTRCID_REKEY_CLEANUP_DUP_IKESA_HANDLER_RETRY,"x",vpn);
  return;
}

static int _rhp_rekey_ikesa_exchg_collision(rhp_vpn* vpn)
{
	int err = 0;
  rhp_ikesa *col_ikesa = NULL;

  RHP_TRC(0,RHPTRCID_REKEY_IKESA_EXCHG_COLLISION,"x",vpn);

  col_ikesa = vpn->ikesa_list_head;
  while( col_ikesa ){

    if( col_ikesa->collision_detected ){
    	err = RHP_STATUS_CHILDSA_COLLISION;
    	break;
    }

    col_ikesa = col_ikesa->next_vpn_list;
  }

	RHP_TRC(0,RHPTRCID_REKEY_IKESA_EXCHG_COLLISION_RTRN,"xxE",vpn,col_ikesa,err);
	return err;
}

static int _rhp_ikev2_rekey_srch_childsa_n_info_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_childsa_srch_plds_ctx* s_pld_ctx = (rhp_childsa_srch_plds_ctx*)ctx;
  rhp_ikev2_n_payload* n_payload = (rhp_ikev2_n_payload*)payload->ext.n;
  u16 notify_mesg_type;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_SRCH_CHILDSA_N_INFO_CB,"xdxxx",rx_ikemesg,enum_end,payload,n_payload,ctx);

  if( n_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  notify_mesg_type = n_payload->get_message_type(payload);

  if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_USE_TRANSPORT_MODE ){

  	s_pld_ctx->use_trans_port_mode = 1;

  }else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_ESP_TFC_PADDING_NOT_SUPPORTED ){

  	s_pld_ctx->esp_tfc_padding_not_supported = 1;

  }else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_ETHERIP_ENCAP ){

  	s_pld_ctx->use_etherip_encap = 1;

  }else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_GRE_ENCAP ){

  	s_pld_ctx->use_gre_encap = 1;

	}else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_IPV6_AUTOCONF_REKEY_SA ){

  	if( s_pld_ctx->vpn->internal_net_info.exec_ipv6_autoconf ){
  		RHP_LOG_D(RHP_LOG_SRC_IKEV2,s_pld_ctx->vpn->vpn_realm_id,RHP_LOG_ID_REKEYED_CHILDSA_RX_IPV6_AUTOCONF_REKEY_SA,"KV",rx_ikemesg,s_pld_ctx->vpn);
  	}else{
  		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,s_pld_ctx->vpn->vpn_realm_id,RHP_LOG_ID_REKEYED_CHILDSA_RX_IPV6_AUTOCONF_REKEY_SA_BUT_NOT_ENABLED,"KV",rx_ikemesg,s_pld_ctx->vpn);
  	}

		s_pld_ctx->rekey_ipv6_autoconf = 1;
	}

  s_pld_ctx->dup_flag++;
  err = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_SRCH_CHILDSA_N_INFO_CB_RTRN,"xxxxwE",rx_ikemesg,payload,n_payload,ctx,notify_mesg_type,err);
  return err;
}

static int _rhp_ikev2_rekey_srch_n_error_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_childsa_srch_plds_ctx* s_pld_ctx = (rhp_childsa_srch_plds_ctx*)ctx;
  rhp_ikev2_n_payload* n_payload = (rhp_ikev2_n_payload*)payload->ext.n;
  u16 notify_mesg_type;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_N_ERROR_CB,"xdxxx",rx_ikemesg,enum_end,payload,n_payload,ctx);

  if( n_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  notify_mesg_type = n_payload->get_message_type(payload);


#ifdef RHP_DBUG_NO_ADDITIONAL_SAS_ERR
    if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ERR_NO_ADDITIONAL_SAS ){
    	RHP_BUG("");
    	_rhp_panic();
    }
#endif // RHP_DBUG_NO_ADDITIONAL_SAS_ERR


  //
  // TODO : Handling only interested notify-error codes.
  //
  if( notify_mesg_type >= RHP_PROTO_IKE_NOTIFY_ERR_MIN && notify_mesg_type <= RHP_PROTO_IKE_NOTIFY_ERR_MAX ){

    RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_N_ERROR_CB_FOUND,"xxxxw",rx_ikemesg,payload,n_payload,ctx,notify_mesg_type);

    s_pld_ctx->n_error_payload = payload;
    return RHP_STATUS_ENUM_OK;
  }

  s_pld_ctx->dup_flag++;
  err = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_N_ERROR_CB_RTRN,"xxxxwE",rx_ikemesg,payload,n_payload,ctx,notify_mesg_type,err);
  return err;
}

static int _rhp_ikev2_rekey_srch_ikesa_nir_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_childsa_srch_plds_ctx* s_pld_ctx = (rhp_childsa_srch_plds_ctx*)ctx;
  rhp_ikev2_nir_payload* nir_payload = (rhp_ikev2_nir_payload*)payload->ext.sa;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_IKESA_NIR_CB,"xdxxx",rx_ikemesg,enum_end,payload,nir_payload,ctx);

  if( nir_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_IKESA_NIR_CB_DUP_ERR,"xx",rx_ikemesg,payload);
  	return RHP_STATUS_INVALID_MSG;
  }

  s_pld_ctx->prf_key_len = rhp_crypto_prf_key_len(s_pld_ctx->resolved_prop.v2.prf_id);
  if( s_pld_ctx->prf_key_len < 0 ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_IKESA_NIR_CB_BAD_PRF_KEY_LEN,"xxwd",s_pld_ctx->vpn,rx_ikemesg,s_pld_ctx->resolved_prop.v2.prf_id,s_pld_ctx->prf_key_len);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  s_pld_ctx->nonce_len = nir_payload->get_nonce_len(payload);

  if( (s_pld_ctx->prf_key_len >> 1) > s_pld_ctx->nonce_len ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_IKESA_NIR_CB_BAD_NONCE_LEN,"xxdd",s_pld_ctx->vpn,rx_ikemesg,(s_pld_ctx->prf_key_len >> 1),s_pld_ctx->nonce_len);
  	goto error;
  }

  s_pld_ctx->nonce = nir_payload->get_nonce(payload);
  if( s_pld_ctx->nonce == NULL ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_IKESA_NIR_CB_NIR_PLD_NO_NONCE,"xx",s_pld_ctx->vpn,rx_ikemesg);
  	goto error;
  }

  s_pld_ctx->nir_payload = payload;
  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_IKESA_NIR_CB_RTRN,"xxE",rx_ikemesg,payload,err);
  return err;
}

static int _rhp_ikev2_rekey_srch_ikesa_ke_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_childsa_srch_plds_ctx* s_pld_ctx = (rhp_childsa_srch_plds_ctx*)ctx;
  rhp_ikev2_ke_payload* ke_payload = (rhp_ikev2_ke_payload*)payload->ext.ke;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_IKESA_KE_CB,"xdxxx",rx_ikemesg,enum_end,payload,ke_payload,ctx);

  if( ke_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_IKESA_KE_CB_DUP_ERR,"xx",rx_ikemesg,payload);
  	return RHP_STATUS_INVALID_MSG;
  }

  s_pld_ctx->dhgrp = ke_payload->get_dhgrp(payload);

  if( s_pld_ctx->dhgrp != s_pld_ctx->resolved_prop.v2.dhgrp_id ){

		RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_IKESA_KE_CB_DHGRP_NOT_MATCHED,"xxww",s_pld_ctx->vpn,rx_ikemesg,s_pld_ctx->dhgrp,s_pld_ctx->resolved_prop.v2.dhgrp_id);

		s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_NO_PROPOSAL_CHOSEN;
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

  s_pld_ctx->peer_dh_pub_key_len = ke_payload->get_key_len(payload);
  s_pld_ctx->peer_dh_pub_key = ke_payload->get_key(payload);

  if( s_pld_ctx->peer_dh_pub_key_len < 0 || s_pld_ctx->peer_dh_pub_key == NULL ){
  	err = RHP_STATUS_INVALID_MSG;
		RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_IKESA_KE_CB_BAD_DH_PUB_KEY,"xxdx",s_pld_ctx->vpn,rx_ikemesg,s_pld_ctx->peer_dh_pub_key_len,s_pld_ctx->peer_dh_pub_key);
		goto error;
  }

  s_pld_ctx->ke_payload = payload;
  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_IKESA_KE_CB_RTRN,"xxE",rx_ikemesg,payload,err);
  return err;
}

static int _rhp_ikev2_rx_rekey_rep_ikesa_sec_params(rhp_vpn* vpn,rhp_ikesa* old_ikesa,rhp_ikesa *new_ikesa,rhp_childsa_srch_plds_ctx* s_pld_ctx)
{
	int err = -EINVAL;

  new_ikesa->prf = rhp_crypto_prf_alloc(s_pld_ctx->resolved_prop.v2.prf_id);
  if( new_ikesa->prf == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  new_ikesa->integ_i = rhp_crypto_integ_alloc(s_pld_ctx->resolved_prop.v2.integ_id);
  if( new_ikesa->integ_i == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  new_ikesa->integ_r = rhp_crypto_integ_alloc(s_pld_ctx->resolved_prop.v2.integ_id);
  if( new_ikesa->integ_r == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  new_ikesa->encr = rhp_crypto_encr_alloc(s_pld_ctx->resolved_prop.v2.encr_id,
  										s_pld_ctx->resolved_prop.v2.encr_key_bits);
  if( new_ikesa->encr == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }


  new_ikesa->set_resp_spi(new_ikesa,s_pld_ctx->resolved_prop.v2.spi);

  err = new_ikesa->nonce_r->set_nonce(new_ikesa->nonce_r,s_pld_ctx->nonce,s_pld_ctx->nonce_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  err = new_ikesa->dh->set_peer_pub_key(new_ikesa->dh,s_pld_ctx->peer_dh_pub_key,s_pld_ctx->peer_dh_pub_key_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  err = new_ikesa->dh->compute_key(new_ikesa->dh);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  err = new_ikesa->generate_new_keys(old_ikesa,new_ikesa);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  err = new_ikesa->encr->set_enc_key(new_ikesa->encr,new_ikesa->keys.v2.sk_ei,new_ikesa->keys.v2.sk_e_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  err = new_ikesa->encr->set_dec_key(new_ikesa->encr,new_ikesa->keys.v2.sk_er,new_ikesa->keys.v2.sk_e_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }


  err = new_ikesa->integ_i->set_key(new_ikesa->integ_i,new_ikesa->keys.v2.sk_ai,new_ikesa->keys.v2.sk_a_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  err = new_ikesa->integ_r->set_key(new_ikesa->integ_r,new_ikesa->keys.v2.sk_ar,new_ikesa->keys.v2.sk_a_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  return 0;

error:
	return err;
}

static int _rhp_ikev2_rx_rekey_rep_ikesa(rhp_vpn* vpn,rhp_ikesa* old_ikesa,
		rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ikev2_mesg* tx_req_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_ikesa *new_ikesa = NULL;
  rhp_vpn_realm* rlm = NULL;
  rhp_childsa_srch_plds_ctx s_pld_ctx;
  int exchg_col = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_IKESA,"xxxxx",vpn,old_ikesa,rx_resp_ikemesg,rx_resp_ikemesg->rx_pkt,tx_req_ikemesg);

  new_ikesa = vpn->ikesa_list_head;

  while( new_ikesa ){

  	new_ikesa->dump(new_ikesa);

    if( new_ikesa != old_ikesa &&
    		new_ikesa->parent_ikesa.side == old_ikesa->side &&
    	 !memcmp(new_ikesa->parent_ikesa.init_spi,old_ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE) &&
    	 !memcmp(new_ikesa->parent_ikesa.resp_spi,old_ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE) &&
    	 new_ikesa->gen_message_id == rx_resp_ikemesg->get_mesg_id(rx_resp_ikemesg) ){

    	break;
    }

    new_ikesa = new_ikesa->next_vpn_list;
  }

  if( new_ikesa == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_IKESA_IKESA_NOT_FOUND,"xxx",vpn,old_ikesa,rx_resp_ikemesg);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_IKESA_NEW_IKESA,"xxxLdGGLd",vpn,old_ikesa,new_ikesa,"IKE_SIDE",new_ikesa->side,new_ikesa->init_spi,new_ikesa->resp_spi,"IKESA_STAT",new_ikesa->state);

  if( new_ikesa->state != RHP_IKESA_STAT_I_REKEY_SENT ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_IKESA_IKESA_BAD_STATE,"xxxxLd",vpn,old_ikesa,rx_resp_ikemesg,new_ikesa,"IKESA_STAT",new_ikesa->state);
    err = RHP_STATUS_BAD_SA_STATE;
    goto error;
  }


  rlm = vpn->rlm;
  if( rlm == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_IKESA_RLM_NOT_ACTIVE,"xxxxx",vpn,old_ikesa,new_ikesa,rx_resp_ikemesg,rlm);
    err = -EINVAL;
    goto error_l;
  }

  memset(&s_pld_ctx,0,sizeof(rhp_childsa_srch_plds_ctx));

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = old_ikesa;
  s_pld_ctx.rlm = rlm;

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
			  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_N),
			  			_rhp_ikev2_rekey_srch_n_error_cb,&s_pld_ctx);

  	if( ( err == 0 || err == RHP_STATUS_ENUM_OK ) && (s_pld_ctx.n_error_payload != NULL ) ){

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_IKESA_ERR_NOTIFIED,"xxxxxx",vpn,old_ikesa,new_ikesa,rx_resp_ikemesg,rlm,s_pld_ctx.n_error_payload);

   	  err = RHP_STATUS_PEER_NOTIFIED_ERROR;
   	  goto error_l;

  	}else if( err && err != -ENOENT ){
    	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_IKESA_RX_NOTIFY_ERR,"xxxxxE",vpn,old_ikesa,new_ikesa,rx_resp_ikemesg,rlm,err);
   	  goto error_l;
  	}
  	err = 0;
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
			  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_SA),
			  			_rhp_ikev2_rekey_srch_sa_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK ){
  		RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_IKESA_NO_SA_PLD_1,"xxxxE",vpn,old_ikesa,new_ikesa,rx_resp_ikemesg,err);
  		err = RHP_STATUS_INVALID_MSG;
  		goto error_l;
  	}

    if( s_pld_ctx.sa_payload == NULL ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_IKESA_NO_SA_PLD_2,"xxxx",vpn,old_ikesa,new_ikesa,rx_resp_ikemesg);
      err = RHP_STATUS_INVALID_MSG;
      goto error_l;
    }


    err = s_pld_ctx.sa_payload->ext.sa->get_matched_ikesa_prop(s_pld_ctx.sa_payload,&(s_pld_ctx.resolved_prop.v2));
    if( err ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_IKESA_SA_PLD_PROP_NOT_MATCHED,"xxxxE",vpn,old_ikesa,new_ikesa,rx_resp_ikemesg,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error_l;
    }

    RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_IKESA_SA_PLD_MATCHED_PROP,"xxxxxbbbpwdwwwwd",vpn,old_ikesa,new_ikesa,rx_resp_ikemesg,s_pld_ctx.sa_payload,s_pld_ctx.resolved_prop.v2.number,s_pld_ctx.resolved_prop.v2.protocol_id,s_pld_ctx.resolved_prop.v2.spi_len,RHP_PROTO_SPI_MAX_SIZE,s_pld_ctx.resolved_prop.v2.spi,s_pld_ctx.resolved_prop.v2.encr_id,s_pld_ctx.resolved_prop.v2.encr_key_bits,s_pld_ctx.resolved_prop.v2.prf_id,s_pld_ctx.resolved_prop.v2.integ_id,s_pld_ctx.resolved_prop.v2.dhgrp_id,s_pld_ctx.resolved_prop.v2.esn,s_pld_ctx.resolved_prop.v2.pfs);
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
			  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_N_I_R),
			  			_rhp_ikev2_rekey_srch_ikesa_nir_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_IKESA_NO_NIR_PLD_1,"xxxxE",vpn,old_ikesa,new_ikesa,rx_resp_ikemesg,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error_l;
    }
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
			  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_KE),
			  			_rhp_ikev2_rekey_srch_ikesa_ke_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_IKESA_NO_KE_PLD_1,"xxxxE",vpn,old_ikesa,new_ikesa,rx_resp_ikemesg,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error_l;
    }
  }

  new_ikesa->timers->quit_lifetime_timer(vpn,new_ikesa);


  err = _rhp_rekey_ikesa_exchg_collision(vpn);

  if( err == RHP_STATUS_CHILDSA_COLLISION ){
    err = 0;
    RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_IKESA_COL_OCCURED,"xxxx",vpn,old_ikesa,new_ikesa,rx_resp_ikemesg);
    exchg_col = 1;
  }else if( err ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_IKESA_COL_ERR,"xxxxE",vpn,old_ikesa,new_ikesa,rx_resp_ikemesg,err);
    goto error_l;
  }


  memcpy(&(new_ikesa->prop.v2),&(s_pld_ctx.resolved_prop.v2),sizeof(rhp_res_sa_proposal));


  // Setup security alg's params.
  err = _rhp_ikev2_rx_rekey_rep_ikesa_sec_params(vpn,old_ikesa,new_ikesa,&s_pld_ctx);
  if( err ){
  	RHP_BUG("");
  	goto error_l;
  }


  rhp_ikesa_set_state(new_ikesa,RHP_IKESA_STAT_ESTABLISHED);
  vpn->created_ikesas++;

  vpn->ikesa_req_rekeying = 0;


  old_ikesa->timers->schedule_delete(vpn,old_ikesa,
  		(vpn->origin_side == RHP_IKE_INITIATOR ?
  		 rhp_gcfg_ikev2_rekey_ikesa_delete_deferred_init : rhp_gcfg_ikev2_rekey_ikesa_delete_deferred_resp));

  {
  	new_ikesa->established_time = _rhp_get_time();
  	new_ikesa->expire_soft = new_ikesa->established_time + (time_t)rlm->ikesa.lifetime_soft;
  	new_ikesa->expire_hard = new_ikesa->established_time + (time_t)rlm->ikesa.lifetime_hard;

  	new_ikesa->timers->start_lifetime_timer(vpn,new_ikesa,(time_t)rlm->ikesa.lifetime_soft,1);
  	new_ikesa->timers->start_keep_alive_timer(vpn,new_ikesa,(time_t)rlm->ikesa.keep_alive_interval);
  	new_ikesa->timers->start_nat_t_keep_alive_timer(vpn,new_ikesa,(time_t)rlm->ikesa.nat_t_keep_alive_interval);
  }


  if( exchg_col ){

  	rhp_timer_oneshot(_rhp_rekey_cleanup_dup_ikesa_handler,rhp_vpn_hold_ref(vpn),RHP_CFG_CLEANUP_DUP_SA_MARGIN);
  }

  RHP_UNLOCK(&(rlm->lock));

	if( vpn->origin_side == RHP_IKE_INITIATOR ){
		vpn->mobike.init.nat_t_src_hash_rx_times = 0;
	}

	{
		rx_resp_ikemesg->for_ikesa_rekey = 1;

		rx_resp_ikemesg->rekeyed_ikesa_my_side = new_ikesa->side;
		memcpy(rx_resp_ikemesg->rekeyed_ikesa_my_spi,new_ikesa->get_my_spi(new_ikesa),RHP_PROTO_IKE_SPI_SIZE);
	}

	RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_REKEYED_IKESA_INITIATOR,"KVP",rx_resp_ikemesg,vpn,new_ikesa);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_IKESA_RTRN,"xxxx",vpn,old_ikesa,new_ikesa,rx_resp_ikemesg);
  return 0;

error_l:
  RHP_UNLOCK(&(rlm->lock));
error:
  if( new_ikesa ){
		rhp_ikesa_set_state(new_ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		new_ikesa->timers->schedule_delete(vpn,new_ikesa,0);
  }

	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_REKEYED_IKESA_INITIATOR_ERR,"KVE",rx_resp_ikemesg,vpn,err);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_IKESA_ERR,"xxxx",vpn,old_ikesa,new_ikesa,rx_resp_ikemesg);
  return err;
}

static int _rhp_ikev2_rx_rekey_rep_childsa_internal_net(rhp_vpn* vpn,rhp_childsa* childsa,rhp_vpn_realm* rlm,rhp_childsa_srch_plds_ctx* s_pld_ctx)
{
	int err = -EINVAL;
  int encap_mode_c;

  err = rhp_ikev2_rx_create_child_sa_rep_encap_mode(vpn,rlm,s_pld_ctx,&encap_mode_c);
  if( err ){
		goto error;
  }


  if( vpn->peer_is_remote_client && rlm->config_server.disable_non_ip &&
  		encap_mode_c != RHP_VPN_ENCAP_IPIP ){

  	err = RHP_STATUS_NO_PROPOSAL_CHOSEN;
		goto error;
  }

	vpn->internal_net_info.encap_mode_c = encap_mode_c;

  if( encap_mode_c == RHP_VPN_ENCAP_ETHERIP ||
  		encap_mode_c == RHP_VPN_ENCAP_GRE ){

  	childsa->ipsec_mode = RHP_CHILDSA_MODE_TRANSPORT;

  }else{ // RHP_VPN_ENCAP_IPIP

  	childsa->ipsec_mode = RHP_CHILDSA_MODE_TUNNEL;
	}

  return 0;

error:
	return err;
}

static int _rhp_ikev2_rx_rekey_rep_childsa_sec_params(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_childsa* childsa,
		rhp_vpn_realm* rlm,rhp_childsa_srch_plds_ctx* s_pld_ctx)
{
	int err = -EINVAL;

  childsa->integ_inb = rhp_crypto_integ_alloc(s_pld_ctx->resolved_prop.v2.integ_id);
  if( childsa->integ_inb == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  childsa->integ_outb = rhp_crypto_integ_alloc(s_pld_ctx->resolved_prop.v2.integ_id);
  if( childsa->integ_outb == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  childsa->encr = rhp_crypto_encr_alloc(s_pld_ctx->resolved_prop.v2.encr_id,
  									s_pld_ctx->resolved_prop.v2.encr_key_bits);
  if( childsa->encr == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }


  childsa->rx_anti_replay.window_mask = rhp_crypto_bn_alloc(rlm->childsa.anti_replay_win_size);
  if( childsa->rx_anti_replay.window_mask == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  childsa->rekey_nonce_r = rhp_crypto_nonce_alloc();
  if( childsa->rekey_nonce_r == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  err = childsa->rekey_nonce_r->set_nonce(childsa->rekey_nonce_r,s_pld_ctx->nonce,s_pld_ctx->nonce_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }


  if( rlm->childsa.pfs ){

    err = childsa->rekey_dh->set_peer_pub_key(childsa->rekey_dh,s_pld_ctx->peer_dh_pub_key,s_pld_ctx->peer_dh_pub_key_len);
    if( err ){
    	RHP_BUG("%d",err);
    	goto error;
    }

    err = childsa->rekey_dh->compute_key(childsa->rekey_dh);
    if( err ){
    	RHP_BUG("%d",err);
    	goto error;
    }
  }

  childsa->esn = s_pld_ctx->resolved_prop.v2.esn;

  if( childsa->esn ){
  	childsa->rx_anti_replay.rx_seq.esn.b = 1;
  	childsa->rx_anti_replay.rx_seq.esn.t = 1;
  }else{
  	childsa->rx_anti_replay.rx_seq.non_esn.last = 1;
  }

  err = childsa->setup_sec_params2(ikesa,childsa);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  return 0;

error:
	return err;
}

extern int rhp_ikev2_rx_create_child_sa_rep_delete_ikesa(rhp_vpn* vpn,rhp_ikesa* ikesa);

static int _rhp_ikev2_rx_rekey_rep_childsa(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ikev2_mesg* tx_req_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_childsa* new_childsa = NULL;
  rhp_childsa* old_childsa = NULL;
  rhp_vpn_realm* rlm = NULL;
  rhp_childsa_srch_plds_ctx s_pld_ctx;
  int immediately_delete = 0;
  int exchg_col = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_CHILDSA,"xxxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,rlm);


  new_childsa = vpn->childsa_list_head;
  while( new_childsa ){

  	new_childsa->dump(new_childsa);

    if( new_childsa->parent_ikesa.side == ikesa->side &&
    	 !memcmp(new_childsa->parent_ikesa.init_spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE) &&
   		 !memcmp(new_childsa->parent_ikesa.resp_spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE) &&
   		 new_childsa->gen_message_id == rx_resp_ikemesg->get_mesg_id(rx_resp_ikemesg) ){

    	break;
    }

    new_childsa = new_childsa->next_vpn_list;
  }

  if( new_childsa == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_CHILDSA_NO_CHILDSA,"xxx",vpn,ikesa,rx_resp_ikemesg);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

	if( new_childsa->gen_type != RHP_CHILDSA_GEN_REKEY ){ // For dynamically created childsa.
    RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_NOT_INTERESTED_GEN_TYPE,"xxxxd",vpn,ikesa,rx_resp_ikemesg,new_childsa,new_childsa->gen_type);
    err = 0;
    goto ignore;
	}

  if( new_childsa->state != RHP_CHILDSA_STAT_LARVAL ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_CHILDSA_BAD_CHILDSA_STATE,"xxxxd",vpn,ikesa,rx_resp_ikemesg,new_childsa,new_childsa->state);
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
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_CHILDSA_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,rx_resp_ikemesg,rlm);
  	goto error_l;
  }

  memset(&s_pld_ctx,0,sizeof(rhp_childsa_srch_plds_ctx));

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;
  s_pld_ctx.rlm = rlm;

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_N),
  			_rhp_ikev2_rekey_srch_n_error_cb,&s_pld_ctx);

    if( ( err == 0 || err == RHP_STATUS_ENUM_OK ) && (s_pld_ctx.n_error_payload != NULL ) ){

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_CHILDSA_ERR_NOTIFIED,"xxx",vpn,ikesa,rx_resp_ikemesg);

    	err = RHP_STATUS_PEER_NOTIFIED_ERROR;

    	goto error_l;

    }else if( err && err != -ENOENT ){
    	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_CHILDSA_RX_NOTIFY_ERR,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
    	goto error_l;
    }
    err = 0;
  }


  {
  	s_pld_ctx.dup_flag = 0;
  	s_pld_ctx.resolved_prop.v2.pfs = rlm->childsa.pfs;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_SA),
  			rhp_ikev2_create_child_sa_srch_sa_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_CHILDSA_NO_SA_PLD_1,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error_l;
  	}

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_CHILDSA_SA_PLD_MATCHED_PROP,"xxxxbbbpwdwwwwd",vpn,ikesa,rx_resp_ikemesg,s_pld_ctx.sa_payload,s_pld_ctx.resolved_prop.v2.number,s_pld_ctx.resolved_prop.v2.protocol_id,s_pld_ctx.resolved_prop.v2.spi_len,RHP_PROTO_SPI_MAX_SIZE,s_pld_ctx.resolved_prop.v2.spi,s_pld_ctx.resolved_prop.v2.encr_id,s_pld_ctx.resolved_prop.v2.encr_key_bits,s_pld_ctx.resolved_prop.v2.prf_id,s_pld_ctx.resolved_prop.v2.integ_id,s_pld_ctx.resolved_prop.v2.dhgrp_id,s_pld_ctx.resolved_prop.v2.esn,s_pld_ctx.resolved_prop.v2.pfs);
  }


  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_N_I_R),
  			rhp_ikev2_create_child_sa_srch_childsa_nir_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_CHILDSA_NO_NIR_PLD_1,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error_l;
    }
  }

  if( rlm->childsa.pfs ){

  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
		  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_KE),
		  			rhp_ikev2_create_child_sa_srch_childsa_ke_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_CHILDSA_NO_KE_PLD_1,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error_l;
    }
  }


  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
		  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_TS_I),
		  			rhp_ikev2_create_child_sa_rep_srch_ts_i_cb,&s_pld_ctx);

   if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_CHILDSA_NO_TS_I_PLD_1,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error_l;
    }

   RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_CHILDSA_MATCHED_TS_I,"xxxx",vpn,ikesa,rx_resp_ikemesg,s_pld_ctx.res_tss_i);
   s_pld_ctx.res_tss_i->dump(s_pld_ctx.res_tss_i,"_rhp_ikev2_rx_rekey_rep_childsa:ts_i");
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
		  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_TS_R),
		  			rhp_ikev2_create_child_sa_rep_srch_ts_r_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_CHILDSA_NO_TS_R_PLD_1,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error_l;
  	}

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_CHILDSA_MATCHED_TS_R,"xxxx",vpn,ikesa,rx_resp_ikemesg,s_pld_ctx.res_tss_r);
  	s_pld_ctx.res_tss_r->dump(s_pld_ctx.res_tss_r,"_rhp_ikev2_rx_rekey_rep_childsa:ts_r");
  }

  {
  	s_pld_ctx.dup_flag = 0;
  	u16 rekey_mesg_ids[5] = {	RHP_PROTO_IKE_NOTIFY_ST_USE_TRANSPORT_MODE,
  																RHP_PROTO_IKE_NOTIFY_ST_ESP_TFC_PADDING_NOT_SUPPORTED,
  																RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_ETHERIP_ENCAP,
  																RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_GRE_ENCAP,
  																RHP_PROTO_IKE_NOTIFY_RESERVED};

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
			  			rhp_ikev2_mesg_srch_cond_n_mesg_ids,rekey_mesg_ids,_rhp_ikev2_rekey_srch_childsa_n_info_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_CHILDSA_N_PLD_ERR,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error_l;
    }
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_CHILDSA_TRANS_MODE,"xxxdd",vpn,ikesa,rx_resp_ikemesg,rlm->encap_mode_c,s_pld_ctx.use_trans_port_mode);


  new_childsa->timers->quit_lifetime_timer(vpn,new_childsa);

  err = rhp_childsa_detect_exchg_collision(vpn);
  if( err == RHP_STATUS_CHILDSA_COLLISION ){
    err = 0;
    RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_CHILDSA_COL_OCCURED,"xxx",vpn,ikesa,rx_resp_ikemesg);
    exchg_col = 1;
  }else if( err ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_CHILDSA_COL_ERR,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
    goto error_l;
  }

  memcpy(&(new_childsa->prop.v2),&(s_pld_ctx.resolved_prop.v2),sizeof(rhp_res_sa_proposal));

  new_childsa->set_outb_spi(new_childsa,*((u32*)s_pld_ctx.resolved_prop.v2.spi));
  new_childsa->timers->spi_outb = new_childsa->spi_outb;


  // Setup internal network.
  err = _rhp_ikev2_rx_rekey_rep_childsa_internal_net(vpn,new_childsa,rlm,&s_pld_ctx);
  if( err ){

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_CHILDSA_EOIP_INVALID_ENCAP_MODE,"xxxdbbb",vpn,ikesa,rx_resp_ikemesg,rlm->encap_mode_c,s_pld_ctx.use_trans_port_mode,s_pld_ctx.use_etherip_encap,s_pld_ctx.use_gre_encap);

  	immediately_delete = 1;
  }
	err = 0;


  err = new_childsa->set_traffic_selectors(new_childsa,s_pld_ctx.res_tss_i,s_pld_ctx.res_tss_r,vpn);
  if( err ){
    RHP_BUG("");
    goto error_l;
  }


  // Setup security alg's params.
  err = _rhp_ikev2_rx_rekey_rep_childsa_sec_params(vpn,ikesa,new_childsa,rlm,&s_pld_ctx);
  if( err ){
    RHP_BUG("");
    goto error_l;
  }


  if( s_pld_ctx.esp_tfc_padding_not_supported || !rlm->childsa.tfc_padding ){
  	new_childsa->tfc_padding = 0;
  }else{
  	new_childsa->tfc_padding = 1;
  }

  new_childsa->anti_replay = rlm->childsa.anti_replay;


  new_childsa->out_of_order_drop = rlm->childsa.out_of_order_drop;

  {
		rhp_childsa_calc_pmtu(vpn,rlm,new_childsa);
		new_childsa->exec_pmtud = rlm->childsa.exec_pmtud;
  }


  rhp_childsa_set_state(new_childsa,RHP_CHILDSA_STAT_MATURE);
  vpn->created_childsas++;

  vpn->childsa_req_rekeying = 0;

  {
		new_childsa->established_time = _rhp_get_time();
		new_childsa->expire_soft = new_childsa->established_time + (time_t)rlm->childsa.lifetime_soft;
		new_childsa->expire_hard = new_childsa->established_time + (time_t)rlm->childsa.lifetime_hard;

		new_childsa->timers->start_lifetime_timer(vpn,new_childsa,(time_t)rlm->childsa.lifetime_soft,1);
  }


  rhp_esp_add_childsa_to_impl(vpn,new_childsa);


  if( exchg_col ){

    rhp_timer_oneshot(rhp_childsa_cleanup_dup_childsa_handler2,rhp_vpn_hold_ref(vpn),RHP_CFG_CLEANUP_DUP_SA_MARGIN);
  }


  old_childsa = vpn->childsa_list_head;
  while( old_childsa ){

  	if( old_childsa != new_childsa ){

  		if( exchg_col && old_childsa->collision_detected ){
  			// This will be cleaned up later.
  		}else{

  			old_childsa->timers->schedule_delete(vpn,old_childsa,
  					(vpn->origin_side == RHP_IKE_INITIATOR ?
  					 rhp_gcfg_ikev2_rekey_childsa_delete_deferred_init : rhp_gcfg_ikev2_rekey_childsa_delete_deferred_resp));
  		}
  	}

  	old_childsa = old_childsa->next_vpn_list;
  }


  if( (err = rhp_vpn_clear_unique_ids_tls_cache(vpn->vpn_realm_id)) ){
  	RHP_BUG("%d",err);
  }
  err = 0;


  RHP_UNLOCK(&(rlm->lock));

  //
  // Don't free s_pld_ctx.res_tss_i and s_pld_ctx.res_tss_r here! These are linked to ts_payload.
  //

  if( immediately_delete ){

  	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_REKEYED_CHILDSA_INITIATOR_ERR2,"KVC",rx_resp_ikemesg,vpn,new_childsa);

  	new_childsa->timers->schedule_delete(vpn,new_childsa,0);

  	vpn->create_child_sa_failed++;

  	rhp_ikev2_rx_create_child_sa_rep_delete_ikesa(vpn,ikesa);

  }else{

  	vpn->create_child_sa_failed = 0;

    if( vpn->nhrp.pend_resolution_req_q.head ){

    	rhp_nhrp_tx_queued_resolution_rep(vpn);
    }

  	RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_REKEYED_CHILDSA_INITIATOR,"KVC",rx_resp_ikemesg,vpn,new_childsa);
  }


ignore:
  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_CHILDSA_RTRN,"xxxdd",vpn,ikesa,rx_resp_ikemesg,immediately_delete,vpn->create_child_sa_failed);
  return 0;

error_l:
  RHP_UNLOCK(&(rlm->lock));
error:
  if( new_childsa ){

  	rhp_childsa_set_state(new_childsa,RHP_CHILDSA_STAT_DELETE_WAIT);
  	new_childsa->timers->schedule_delete(vpn,new_childsa,0);

    vpn->create_child_sa_failed++;
  }


  rhp_ikev2_rx_create_child_sa_rep_delete_ikesa(vpn,ikesa);


  //
  // Don't free s_pld_ctx.res_tss_i and s_pld_ctx.res_tss_r here! These are linked to ts_payload.
  //

	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_REKEYED_CHILDSA_INITIATOR_ERR,"KVE",rx_resp_ikemesg,vpn,err);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_CHILDSA_ERR,"xxxdE",vpn,ikesa,rx_resp_ikemesg,vpn->create_child_sa_failed,err);
  return err;
}

static int _rhp_ikev2_rx_rekey_rep(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ikev2_mesg* tx_req_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_proto_ike* ikeh;
  rhp_packet* rx_pkt;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_L,"xxx",vpn,ikesa,rx_resp_ikemesg,rx_resp_ikemesg->rx_pkt);

  rx_pkt = rx_resp_ikemesg->rx_pkt;
  ikeh = rx_pkt->app.ikeh;

  if( rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_L_RESP_MESG_ID,"xxxLduu",vpn,ikesa,rx_resp_ikemesg,"IKESA_STAT",ikesa->state,ikesa->rekey_ikesa_message_id,rx_resp_ikemesg->get_mesg_id(rx_resp_ikemesg));

  if( ikesa->state == RHP_IKESA_STAT_REKEYING &&
  		(ikesa->rekey_ikesa_message_id == rx_resp_ikemesg->get_mesg_id(rx_resp_ikemesg)) ){

  	err = _rhp_ikev2_rx_rekey_rep_ikesa(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);

  }else{

  	err = _rhp_ikev2_rx_rekey_rep_childsa(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
  }

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_L_RTRN,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
	return err;
}

static int _rhp_ikev2_rekey_new_pkt_ikesa_rep(rhp_ikesa* new_ikesa,rhp_res_sa_proposal* res_prop,
		rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg)
{
  rhp_ikev2_payload* ikepayload = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_REKEY_IKESA_REKEY_R,"xxx",new_ikesa,res_prop,rx_req_ikemesg);

  {
    if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_SA,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

    if( ikepayload->ext.sa->set_matched_ikesa_prop(ikepayload,res_prop,new_ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE) ){
      RHP_BUG("");
      goto error;
    }
  }

  {
    int nonce_len = new_ikesa->nonce_r->get_nonce_len(new_ikesa->nonce_r);
    u8* nonce = new_ikesa->nonce_r->get_nonce(new_ikesa->nonce_r);

    if( nonce == NULL ){
      RHP_BUG("");
      goto error;
    }

    if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_N_I_R,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

    if( ikepayload->ext.nir->set_nonce(ikepayload,nonce_len,nonce) ){
      RHP_BUG("");
      goto error;
    }
  }

  {
    int key_len;
    u8* key = new_ikesa->dh->get_my_pub_key(new_ikesa->dh,&key_len);

    if( key == NULL ){
      RHP_BUG("");
      goto error;
    }

    if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_KE,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

    if( ikepayload->ext.ke->set_key(ikepayload,new_ikesa->dh->grp,key_len,key) ){
      RHP_BUG("");
      goto error;
    }
  }

  {
  	tx_resp_ikemesg->for_ikesa_rekey = 1;

  	tx_resp_ikemesg->rekeyed_ikesa_my_side = new_ikesa->side;
		memcpy(tx_resp_ikemesg->rekeyed_ikesa_my_spi,new_ikesa->get_my_spi(new_ikesa),RHP_PROTO_IKE_SPI_SIZE);
  }

	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_REKEY_IKESA_REKEY_R_RTRN,"xxxx",new_ikesa,res_prop,rx_req_ikemesg,tx_resp_ikemesg);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_REKEY_IKESA_REKEY_R_ERR,"xxx",new_ikesa,res_prop,rx_req_ikemesg);
  return -EINVAL;
}

static void _rhp_ikev2_rx_rekey_req_ikesa_mark_collision_sa(rhp_vpn* vpn,rhp_ikesa* new_ikesa)
{
	rhp_ikesa* col_ikesa = vpn->ikesa_list_head;
  while( col_ikesa ){

    if( col_ikesa != new_ikesa &&
    	   col_ikesa->state == RHP_IKESA_STAT_I_REKEY_SENT ){

    	col_ikesa->collision_detected = 1;
      new_ikesa->collision_detected = 1;
    }

    col_ikesa = col_ikesa->next_vpn_list;
  }
}

static int _rhp_ikev2_rx_rekey_req_ikesa_sec_params(rhp_vpn* vpn,rhp_ikesa* new_ikesa,
		rhp_ikesa* old_ikesa,rhp_childsa_srch_plds_ctx* s_pld_ctx)
{
	int err = -EINVAL;

	err = new_ikesa->nonce_i->set_nonce(new_ikesa->nonce_i,s_pld_ctx->nonce,s_pld_ctx->nonce_len);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	err = new_ikesa->dh->set_peer_pub_key(new_ikesa->dh,s_pld_ctx->peer_dh_pub_key,s_pld_ctx->peer_dh_pub_key_len);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	memcpy(&(new_ikesa->prop.v2),&(s_pld_ctx->resolved_prop.v2),sizeof(rhp_res_sa_proposal));

	err = rhp_ikesa_crypto_setup_new_r(old_ikesa,new_ikesa);
	if( err ){
		RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_REKEY_IKESA_CRYPTO_SETUP_R_ERR,"xE",new_ikesa,err);
		goto error;
	}

	rhp_ikev2_rekey_inherit_ikesa_info(new_ikesa,old_ikesa);

	return 0;

error:
	return err;
}

static int _rhp_ikev2_rx_rekey_req_ikesa(rhp_vpn* vpn,rhp_ikesa* old_ikesa,
		rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg,rhp_ikev2_payload* sa_payload_i)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_ikesa* new_ikesa = NULL;
  rhp_vpn_realm* rlm = NULL;
  rhp_childsa_srch_plds_ctx s_pld_ctx;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_REKEY_IKESA,"xxxxx",vpn,old_ikesa,rx_req_ikemesg,sa_payload_i,vpn->rlm);

  rlm = vpn->rlm;
  if( rlm == NULL ){
  	err = -EINVAL;
  	RHP_BUG("");
  	goto error;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
  	err = -EINVAL;
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_REKEY_IKESA_RLM_NOT_ACTIVE,"xxxx",vpn,old_ikesa,rx_req_ikemesg,vpn->rlm);
  	goto error_l;
  }

  if( old_ikesa->state != RHP_IKESA_STAT_ESTABLISHED && old_ikesa->state != RHP_IKESA_STAT_REKEYING ){
  	s_pld_ctx.notify_error = RHP_PROTO_IKE_NOTIFY_ERR_TEMPORARY_FAILURE;
    RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_REKEY_IKESA_IKESA_BAD_STATE,"xxxLd",vpn,old_ikesa,rx_req_ikemesg,"IKESA_STAT",old_ikesa->state);
    goto notify_error;
  }

  memset(&s_pld_ctx,0,sizeof(rhp_childsa_srch_plds_ctx));

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = old_ikesa;
  s_pld_ctx.rlm = rlm;

  {
    if( sa_payload_i == NULL ){
    	err = RHP_STATUS_INVALID_MSG;
    	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_REKEY_IKESA_NO_SA_PLD,"xxx",vpn,old_ikesa,rx_req_ikemesg);
    	goto error_l;
    }

    err = sa_payload_i->ext.sa->get_matched_ikesa_prop(sa_payload_i,&(s_pld_ctx.resolved_prop.v2));
    if( err ){

    	s_pld_ctx.notify_error = RHP_PROTO_IKE_NOTIFY_ERR_NO_PROPOSAL_CHOSEN;

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_REKEY_IKESA_SA_PLD_NO_MATCHED_PROP,"xxxE",vpn,old_ikesa,rx_req_ikemesg,err);
     goto notify_error;
    }

    s_pld_ctx.prf_key_len = rhp_crypto_prf_key_len(s_pld_ctx.resolved_prop.v2.prf_id);
    if( s_pld_ctx.prf_key_len < 0 ){

    	err = RHP_STATUS_INVALID_MSG;
    	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_REKEY_IKESA_SA_PLD_BAD_PRF_KEY_LEN,"xxxd",vpn,old_ikesa,rx_req_ikemesg,s_pld_ctx.prf_key_len);
    	goto error_l;
    }
  }


  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
			  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_N_I_R),
			  			rhp_ikev2_create_child_sa_srch_childsa_nir_cb,&s_pld_ctx);

   if( err && err != RHP_STATUS_ENUM_OK ){

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_REKEY_IKESA_NO_NIR_PLD_1,"xxxE",vpn,old_ikesa,rx_req_ikemesg,err);

    	if( s_pld_ctx.notify_error ){
    		goto notify_error;
    	}

    	err = RHP_STATUS_INVALID_MSG;
    	goto error_l;
    }
  }


  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
			  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_KE),
			  			rhp_ikev2_create_child_sa_srch_childsa_ke_cb,&s_pld_ctx);

    if( err && (err != RHP_STATUS_ENUM_OK) && (err != -ENOENT) ){

      RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_REKEY_IKESA_NO_KE_PLD_1,"xxxE",vpn,old_ikesa,rx_req_ikemesg,err);

    	if( s_pld_ctx.notify_error ){
    		goto notify_error;
    	}

    	err = RHP_STATUS_INVALID_MSG;
    	goto error_l;
    }

  }

  new_ikesa = rhp_ikesa_new_r(&(s_pld_ctx.resolved_prop.v2));
  if( new_ikesa == NULL ){
  	RHP_BUG("");
  	goto error_l;
  }

  new_ikesa->peer_is_rockhopper = vpn->peer_is_rockhopper;
  new_ikesa->peer_rockhopper_ver = vpn->peer_rockhopper_ver;

  new_ikesa->set_init_spi(new_ikesa,s_pld_ctx.resolved_prop.v2.spi);


  // Setup security alg's params.
  err = _rhp_ikev2_rx_rekey_req_ikesa_sec_params(vpn,new_ikesa,old_ikesa,&s_pld_ctx);
  if( err ){
  	RHP_BUG("");
  	goto error_l;
  }


  err = _rhp_ikev2_rekey_new_pkt_ikesa_rep(new_ikesa,&(s_pld_ctx.resolved_prop.v2),rx_req_ikemesg,tx_resp_ikemesg);
  if( err ){
  	RHP_BUG("");
  	goto error_l;
  }


  new_ikesa->timers = rhp_ikesa_new_timers(RHP_IKE_RESPONDER,new_ikesa->resp_spi);
  if( new_ikesa->timers == NULL ){
    RHP_BUG("");
    goto error_l;
  }

	rhp_ikesa_set_state(new_ikesa,RHP_IKESA_STAT_ESTABLISHED);

	vpn->created_ikesas++;


  err = rhp_vpn_ikesa_spi_put(vpn,new_ikesa->side,new_ikesa->resp_spi);
  if( err ){
    RHP_BUG("%d",err);
    goto error_l;
  }

  vpn->ikesa_put(vpn,new_ikesa);


  // Mark collision to sa.
  _rhp_ikev2_rx_rekey_req_ikesa_mark_collision_sa(vpn,new_ikesa);


  {
  	time_t old_ikesa_dt = (vpn->origin_side == RHP_IKE_INITIATOR ?
   		 rhp_gcfg_ikev2_rekey_ikesa_delete_deferred_init : rhp_gcfg_ikev2_rekey_ikesa_delete_deferred_resp);

  	old_ikesa->expire_soft = 0;
  	old_ikesa->expire_hard = _rhp_get_time() + old_ikesa_dt;

		old_ikesa->timers->schedule_delete(vpn,old_ikesa,old_ikesa_dt);
  }

  {
    new_ikesa->established_time = _rhp_get_time();
    new_ikesa->expire_soft = new_ikesa->established_time + (time_t)rlm->ikesa.lifetime_soft;
    new_ikesa->expire_hard = new_ikesa->established_time + (time_t)rlm->ikesa.lifetime_hard;

    new_ikesa->timers->start_lifetime_timer(vpn,new_ikesa,(time_t)rlm->ikesa.lifetime_soft,1);
    new_ikesa->timers->start_keep_alive_timer(vpn,new_ikesa,(time_t)rlm->ikesa.keep_alive_interval);
    new_ikesa->timers->start_nat_t_keep_alive_timer(vpn,new_ikesa,(time_t)rlm->ikesa.nat_t_keep_alive_interval);
  }

  RHP_UNLOCK(&(rlm->lock));

	if( vpn->origin_side == RHP_IKE_INITIATOR ){
		vpn->mobike.init.nat_t_src_hash_rx_times = 0;
	}

	{
		rx_req_ikemesg->for_ikesa_rekey = 1;

		rx_req_ikemesg->rekeyed_ikesa_my_side = new_ikesa->side;
		memcpy(rx_req_ikemesg->rekeyed_ikesa_my_spi,new_ikesa->get_my_spi(new_ikesa),RHP_PROTO_IKE_SPI_SIZE);
	}

	RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_REKEYED_IKESA_RESPONDER,"KVP",rx_req_ikemesg,vpn,new_ikesa);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_REKEY_IKESA_RTRN,"xxx",vpn,old_ikesa,rx_req_ikemesg);
	return 0;

notify_error:
  err = _rhp_ikev2_rekey_new_pkt_error_notify_rep(tx_resp_ikemesg,old_ikesa,
  		RHP_PROTO_IKE_PROTOID_IKE,0,s_pld_ctx.notify_error,s_pld_ctx.notify_error_arg);

  if( err ){
  	RHP_BUG("");
  	goto error_l;
  }

  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_REKEY_IKESA_TX_ERR_RESP,"KVL",tx_resp_ikemesg,vpn,"PROTO_IKE_NOTIFY",s_pld_ctx.notify_error);
  err = RHP_STATUS_IKEV2_MESG_HANDLER_END;

error_l:
  RHP_UNLOCK(&(rlm->lock));
error:
  if( new_ikesa ){
  	rhp_ikesa_destroy(vpn,new_ikesa);
  }

	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_REKEYED_IKESA_RESPONDER_ERR,"KVE",rx_req_ikemesg,vpn,err);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_REKEY_IKESA_ERR,"xxxE",vpn,old_ikesa,rx_req_ikemesg,err);
	return err;
}

static int _rhp_ikev2_rekey_srch_n_rekey_sa_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_childsa_srch_plds_ctx* s_pld_ctx = (rhp_childsa_srch_plds_ctx*)ctx;
  rhp_ikev2_n_payload* n_payload = (rhp_ikev2_n_payload*)payload->ext.n;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_N_REKEY_CB,"xdxxx",rx_ikemesg,enum_end,payload,n_payload,ctx);

  if( n_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_N_REKEY_CB_DUP_ERR,"xxx",rx_ikemesg,payload,n_payload);
  	return RHP_STATUS_INVALID_MSG;
  }

  s_pld_ctx->rekey_outb_spi = n_payload->get_spi(payload);

  s_pld_ctx->n_rekey_sa_payload = payload;
  err = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_N_REKEY_CB_RTRN,"xxxE",rx_ikemesg,payload,n_payload,err);
  return err;
}

static int _rhp_ikev2_rekey_new_pkt_childsa_rep(rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg,
		rhp_childsa* new_childsa,rhp_childsa_srch_plds_ctx* s_pld_ctx)
{
  int err = 0;
  rhp_ikev2_payload* ikepayload = NULL;
  rhp_ikev2_payload* ts_i_payload = s_pld_ctx->ts_i_payload;
  rhp_ikev2_payload* ts_r_payload = s_pld_ctx->ts_r_payload;
  rhp_res_sa_proposal* res_prop = &(s_pld_ctx->resolved_prop.v2);
  rhp_ikev2_traffic_selector** res_tss_i = &(s_pld_ctx->res_tss_i);
  rhp_ikev2_traffic_selector** res_tss_r = &(s_pld_ctx->res_tss_r);
  rhp_vpn* vpn = s_pld_ctx->vpn;
  rhp_vpn_realm* rlm = s_pld_ctx->rlm;

	RHP_TRC(0,RHPTRCID_IKEV2_REKEY_NEW_PKT_CHILDSA_REP,"xxxxxxxxxxx",rx_req_ikemesg,tx_resp_ikemesg,new_childsa,s_pld_ctx,res_prop,res_tss_i,*res_tss_i,res_tss_r,*res_tss_r,rlm,vpn);

	if( new_childsa->ipsec_mode == RHP_CHILDSA_MODE_TRANSPORT ){

		if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
    }

    tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

    ikepayload->ext.n->set_protocol_id(ikepayload,0);

    ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_USE_TRANSPORT_MODE);
	}

  {
    if( (err = rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_SA,&ikepayload)) ){
      RHP_BUG("%d",err);
      goto error;
    }

    tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

    if( (err = ikepayload->ext.sa->set_matched_childsa_prop(ikepayload,res_prop,new_childsa->spi_inb)) ){
      RHP_BUG("%d",err);
      goto error;
    }
  }

  {
  	int nonce_len = new_childsa->rekey_nonce_r->get_nonce_len(new_childsa->rekey_nonce_r);
  	u8* nonce = new_childsa->rekey_nonce_r->get_nonce(new_childsa->rekey_nonce_r);

  	if( nonce == NULL ){
  		RHP_BUG("");
  		goto error;
    }

    if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_N_I_R,&ikepayload) ){
    	RHP_BUG("");
    	goto error;
    }

    tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

    if( ikepayload->ext.nir->set_nonce(ikepayload,nonce_len,nonce) ){
    	RHP_BUG("");
    	goto error;
    }
  }

  if( res_prop->pfs ){

    int key_len;
    u8* key = new_childsa->rekey_dh->get_my_pub_key(new_childsa->rekey_dh,&key_len);

    if( key == NULL ){
      RHP_BUG("");
      goto error;
    }

    if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_KE,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

    if( ikepayload->ext.ke->set_key(ikepayload,res_prop->dhgrp_id,key_len,key) ){
      RHP_BUG("");
      goto error;
    }
  }

  {
    if( (err = rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_TS_I,&ikepayload)) ){
      RHP_BUG("");
      goto error;
    }

    tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

    ikepayload->ext.ts->set_matched_r_tss(ikepayload,*res_tss_i);
    *res_tss_i = NULL;

    if( ts_i_payload->ext.ts->reconfirm_tss(ts_i_payload,ikepayload) ){

    	RHP_TRC(0,RHPTRCID_IKEV2_REKEY_NEW_PKT_CHILDSA_REP_RECONFIRM_TSS_TS_I_NOT_MATCHED,"xxxx",vpn,rlm,s_pld_ctx,tx_resp_ikemesg);

    	s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_TS_UNACCEPTABLE;

    	err = RHP_STATUS_INVALID_MSG;
    	goto error;
    }
  }

  {
  	if( (err = rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_TS_R,&ikepayload)) ){
       RHP_BUG("");
       goto error;
    }

    tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

		ikepayload->ext.ts->set_matched_r_tss(ikepayload,*res_tss_r);
		*res_tss_r = NULL;

    if( ts_r_payload->ext.ts->reconfirm_tss(ts_r_payload,ikepayload) ){

    	RHP_TRC(0,RHPTRCID_IKEV2_REKEY_NEW_PKT_CHILDSA_REP_RECONFIRM_TSS_TS_R_NOT_MATCHED,"xxxx",vpn,rlm,s_pld_ctx,tx_resp_ikemesg);

    	s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_TS_UNACCEPTABLE;

    	err = RHP_STATUS_INVALID_MSG;

    	goto error;
    }
  }

	if( (vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_ETHERIP) && vpn->peer_is_rockhopper ){

		if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
    }

    tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

    ikepayload->ext.n->set_protocol_id(ikepayload,0);

    ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_ETHERIP_ENCAP);

	}else if( (vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_GRE) && vpn->peer_is_rockhopper ){

		if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
    }

    tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

    ikepayload->ext.n->set_protocol_id(ikepayload,0);

    ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_GRE_ENCAP);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_REKEY_NEW_PKT_CHILDSA_REP_RTRN,"xxxxx",rx_req_ikemesg,new_childsa,res_prop,rlm,tx_resp_ikemesg);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_REKEY_NEW_PKT_CHILDSA_REP_ERR,"xx",rx_req_ikemesg,new_childsa);
	return -EINVAL;
}

static int _rhp_ikev2_rx_rekey_req_childsa_internal_net(rhp_vpn* vpn,rhp_vpn_realm* rlm,
		rhp_childsa* childsa,rhp_childsa_srch_plds_ctx* s_pld_ctx)
{
	int err = -EINVAL;
  int encap_mode_c;

  err = rhp_ikev2_rx_create_child_sa_req_encap_mode(vpn,rlm,s_pld_ctx,&encap_mode_c);
  if( err ){
    goto notify_error;
  }


	vpn->internal_net_info.encap_mode_c = encap_mode_c;

	if( encap_mode_c == RHP_VPN_ENCAP_ETHERIP ||
			encap_mode_c == RHP_VPN_ENCAP_GRE ){

		childsa->ipsec_mode = RHP_CHILDSA_MODE_TRANSPORT;

	}else{ // RHP_VPN_ENCAP_IPIP

		childsa->ipsec_mode = RHP_CHILDSA_MODE_TUNNEL;
	}

	return 0;

notify_error:
	return err;
}

static void _rhp_ikev2_rx_rekey_req_childsa_mark_collision_sa(rhp_vpn* vpn,rhp_childsa* childsa)
{
  rhp_childsa *col_childsa = vpn->childsa_list_head;
  while( col_childsa ){

    if( col_childsa != childsa &&
    	   col_childsa->state == RHP_CHILDSA_STAT_LARVAL ){

      col_childsa->collision_detected = 1;
      childsa->collision_detected = 1;
    }

    col_childsa = col_childsa->next_vpn_list;
  }
}

static int _rhp_ikev2_rekey_ipv6_autoconf_mod_tss_peer_addrs(
		rhp_vpn* vpn,rhp_childsa_srch_plds_ctx* s_pld_ctx)
{
	int err = -EINVAL;
	rhp_ikev2_traffic_selector *res_tss_head = NULL, *res_tss_tail = NULL;

	if( !vpn->internal_net_info.ipv6_autoconf_narrow_ts_i ){
		return 0;
	}

	while( s_pld_ctx->res_tss_i ){

		rhp_ikev2_traffic_selector* res_ts = s_pld_ctx->res_tss_i;

		s_pld_ctx->res_tss_i = s_pld_ctx->res_tss_i->next;
		res_ts->next = NULL;

		if( res_ts->get_ts_type(res_ts) == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){

			rhp_ip_addr_list* peer_addr = vpn->internal_net_info.peer_addrs;

			while( peer_addr ){

				if( peer_addr->ip_addr.addr_family == AF_INET6 ){

					if( res_ts->addr_is_included(res_ts,&(peer_addr->ip_addr)) ){

						rhp_ikev2_traffic_selector* res_ts_dup = NULL;

						err = rhp_ikev2_ts_tx_dup(res_ts,&res_ts_dup);
						if( err ){
							RHP_BUG("");
							rhp_ikev2_ts_payload_free_ts(res_ts);
							goto error;
						}

						if( res_tss_head == NULL ){
							res_tss_head = res_ts_dup;
						}else{
							res_tss_tail->next = res_ts_dup;
						}
						res_tss_tail = res_ts_dup;


						err = res_ts->replace_start_addr(res_ts_dup,&(peer_addr->ip_addr));
						if( err ){
							RHP_BUG("");
							rhp_ikev2_ts_payload_free_ts(res_ts);
							goto error;
						}

						err = res_ts->replace_end_addr(res_ts_dup,&(peer_addr->ip_addr));
						if( err ){
							RHP_BUG("");
							rhp_ikev2_ts_payload_free_ts(res_ts);
							goto error;
						}
					}
				}

				peer_addr = peer_addr->next;
			}

			rhp_ikev2_ts_payload_free_ts(res_ts);

		}else{

			if( res_tss_head == NULL ){
				res_tss_head = res_ts;
			}else{
				res_tss_tail->next = res_ts;
			}
			res_tss_tail = res_ts;
		}
	}


	s_pld_ctx->res_tss_i = res_tss_head;

	return 0;

error:

	s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_TS_UNACCEPTABLE;

	{
		rhp_ikev2_traffic_selector* res_ts = res_tss_head;
		while( res_ts ){
			rhp_ikev2_traffic_selector* res_ts_n = res_ts->next;
			rhp_ikev2_ts_payload_free_ts(res_ts);
			res_ts = res_ts_n;
		}
	}

	return err;
}

static int _rhp_ikev2_rx_rekey_req_childsa(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,
		rhp_ikev2_mesg* tx_resp_ikemesg,rhp_ikev2_payload* sa_payload_i)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_childsa* old_childsa = NULL;
  rhp_childsa* new_childsa = NULL;
  rhp_vpn_realm* rlm;
  rhp_childsa_srch_plds_ctx s_pld_ctx;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_CHILDSA,"xxxxxxdd",vpn,ikesa,rx_req_ikemesg,rx_req_ikemesg->rx_pkt,sa_payload_i,vpn->rlm,vpn->internal_net_info.peer_exec_ipv6_autoconf,vpn->internal_net_info.ipv6_autoconf_narrow_ts_i);

  rlm = vpn->rlm;
  if( rlm == NULL ){
  	err = -EINVAL;
  	RHP_BUG("");
  	goto error;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
  	err = -EINVAL;
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_CHILDSA_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,rx_req_ikemesg,vpn->rlm);
  	goto error_l;
  }

  memset(&s_pld_ctx,0,sizeof(rhp_childsa_srch_plds_ctx));

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;
  s_pld_ctx.rlm = rlm;

  s_pld_ctx.notify_proto = RHP_PROTO_IKE_PROTOID_ESP;
  s_pld_ctx.notify_spi = 0;

  if( ikesa->state != RHP_IKESA_STAT_ESTABLISHED && ikesa->state != RHP_IKESA_STAT_REKEYING ){

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_CHILDSA_IKESA_BAD_STATE,"xxxLd",vpn,ikesa,rx_req_ikemesg,"IKESA_STAT",ikesa->state);
  	err = RHP_STATUS_INVALID_MSG;

  	s_pld_ctx.notify_error = RHP_PROTO_IKE_NOTIFY_ERR_CHILD_SA_NOT_FOUND;
  	goto notify_error;
  }


  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  						rhp_ikev2_mesg_srch_cond_n_mesg_id,(void*)((unsigned long)RHP_PROTO_IKE_NOTIFY_ST_REKEY_SA),
			  			_rhp_ikev2_rekey_srch_n_rekey_sa_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK ){

    	if( err == -ENOENT ){
    		err = 0;
    		RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_CHILDSA_NO_ADDITIONAL_SAS_ERR_1,"xxx",vpn,ikesa,rx_req_ikemesg);
    	}

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_CHILDSA_N_REKEY_ERR_1,"xxxE",vpn,ikesa,rx_req_ikemesg,err);
    	goto error_l;
    }
  	err = 0;

    old_childsa = vpn->childsa_get(vpn,RHP_DIR_OUTBOUND,s_pld_ctx.rekey_outb_spi);

    if( old_childsa == NULL ){

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_CHILDSA_NO_OLD_CHILDSA,"xxxH",vpn,ikesa,rx_req_ikemesg,s_pld_ctx.rekey_outb_spi);
    	err = RHP_STATUS_INVALID_MSG;

    	s_pld_ctx.notify_error = RHP_PROTO_IKE_NOTIFY_ERR_CHILD_SA_NOT_FOUND;
    	goto notify_error;
    }

    if( old_childsa->state != RHP_CHILDSA_STAT_MATURE &&
    		old_childsa->state != RHP_CHILDSA_STAT_REKEYING ){

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_CHILDSA_OLD_CHILDSA_BAD_STATE,"xxxxLd",vpn,ikesa,rx_req_ikemesg,old_childsa,"CHILDSA_STAT",old_childsa->state);
    	err = RHP_STATUS_INVALID_MSG;

    	s_pld_ctx.notify_error = RHP_PROTO_IKE_NOTIFY_ERR_CHILD_SA_NOT_FOUND;
    	goto notify_error;
    }
  }

  s_pld_ctx.notify_proto = RHP_PROTO_IKE_PROTOID_ESP;
  s_pld_ctx.notify_spi = s_pld_ctx.rekey_outb_spi;

  {
    if( sa_payload_i == NULL ){

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_CHILDSA_NO_SA_PLD,"xxx",vpn,ikesa,rx_req_ikemesg);

    	err = RHP_STATUS_INVALID_MSG;
    	goto error_l;
    }

    s_pld_ctx.resolved_prop.v2.pfs = rlm->childsa.pfs;

    err = sa_payload_i->ext.sa->get_matched_childsa_prop(sa_payload_i,&(s_pld_ctx.resolved_prop.v2));
    if( err ){

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_CHILDSA_SA_PLD_NO_MATCHED_PROP,"xxxxE",vpn,ikesa,rx_req_ikemesg,sa_payload_i,err);

    	s_pld_ctx.notify_error = RHP_PROTO_IKE_NOTIFY_ERR_NO_PROPOSAL_CHOSEN;
     goto notify_error;
    }

    RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_CHILDSA_MATCHED_SA_PROP,"xxxxbbbpwdwwwwd",vpn,ikesa,rx_req_ikemesg,sa_payload_i,s_pld_ctx.resolved_prop.v2.number,s_pld_ctx.resolved_prop.v2.protocol_id,s_pld_ctx.resolved_prop.v2.spi_len,RHP_PROTO_SPI_MAX_SIZE,s_pld_ctx.resolved_prop.v2.spi,s_pld_ctx.resolved_prop.v2.encr_id,s_pld_ctx.resolved_prop.v2.encr_key_bits,s_pld_ctx.resolved_prop.v2.prf_id,s_pld_ctx.resolved_prop.v2.integ_id,s_pld_ctx.resolved_prop.v2.dhgrp_id,s_pld_ctx.resolved_prop.v2.esn,s_pld_ctx.resolved_prop.v2.pfs);
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  						rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_N_I_R),
  						rhp_ikev2_create_child_sa_srch_childsa_nir_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_CHILDSA_NO_NIR_PLD_1,"xxxE",vpn,ikesa,rx_req_ikemesg,err);
    	err = RHP_STATUS_INVALID_MSG;

    	if( s_pld_ctx.notify_error ){
    		goto notify_error;
    	}

     goto error_l;
    }
  }

  if( rlm->childsa.pfs ){

  	s_pld_ctx.dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  						rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_KE),
  						rhp_ikev2_create_child_sa_srch_childsa_ke_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_CHILDSA_NO_KE_PLD_1,"xxxE",vpn,ikesa,rx_req_ikemesg,err);
    	err = RHP_STATUS_INVALID_MSG;

    	if( s_pld_ctx.notify_error ){
    		goto notify_error;
    	}

    	goto error_l;
    }
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  						rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_TS_I),
  						rhp_ikev2_create_child_sa_req_srch_ts_i_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_CHILDSA_NO_TS_I_PLD_1,"xxxE",vpn,ikesa,rx_req_ikemesg,err);

    	if( s_pld_ctx.notify_error ){
    		goto notify_error;
    	}

    	goto error_l;
    }

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_CHILDSA_MATCHED_TS_I,"xxxx",vpn,ikesa,rx_req_ikemesg,s_pld_ctx.res_tss_i);
  	s_pld_ctx.res_tss_i->dump(s_pld_ctx.res_tss_i,"_rhp_ikev2_rx_rekey_req_childsa:ts_i");
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  						rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_TS_R),
  						rhp_ikev2_create_child_sa_req_srch_ts_r_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_CHILDSA_NO_TS_R_PLD_1,"xxxE",vpn,ikesa,rx_req_ikemesg,err);

    	if( s_pld_ctx.notify_error ){
    		goto notify_error;
    	}

    	goto error_l;
    }

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_CHILDSA_MATCHED_TS_R,"xxxx",vpn,ikesa,rx_req_ikemesg,s_pld_ctx.res_tss_r);
  	s_pld_ctx.res_tss_r->dump(s_pld_ctx.res_tss_r,"_rhp_ikev2_rx_rekey_req_childsa:ts_r");
  }

  {
  	s_pld_ctx.dup_flag = 0;
  	u16 rekey_mesg_ids[6] = {	RHP_PROTO_IKE_NOTIFY_ST_USE_TRANSPORT_MODE,
  														RHP_PROTO_IKE_NOTIFY_ST_ESP_TFC_PADDING_NOT_SUPPORTED,
  														RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_ETHERIP_ENCAP,
  														RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_GRE_ENCAP,
  														RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_IPV6_AUTOCONF_REKEY_SA,
  														RHP_PROTO_IKE_NOTIFY_RESERVED};

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
			  			rhp_ikev2_mesg_srch_cond_n_mesg_ids,rekey_mesg_ids,_rhp_ikev2_rekey_srch_childsa_n_info_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_CHILDSA_N_PLD_ERR,"xxxE",vpn,ikesa,rx_req_ikemesg,err);
      goto error_l;
    }
  }

	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_CHILDSA_TRANS_MODE,"xxxLdd",vpn,ikesa,rx_req_ikemesg,"CHILDSA_MODE",old_childsa->ipsec_mode,s_pld_ctx.use_trans_port_mode);


  //
  // Setup TSi/r for CP payload in TX Resp message.
  //
	{

		if( vpn->internal_net_info.peer_addr_v4_cp == RHP_IKEV2_CFG_CP_ADDR_REQUESTED ){

			err = rhp_ikev2_create_child_sa_purge_af_tss(tx_resp_ikemesg,&s_pld_ctx,
							RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE,NULL);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}
		}

		if( vpn->internal_net_info.peer_addr_v6_cp == RHP_IKEV2_CFG_CP_ADDR_REQUESTED &&
				!vpn->internal_net_info.peer_exec_ipv6_autoconf ){

			err = rhp_ikev2_create_child_sa_purge_af_tss(tx_resp_ikemesg,&s_pld_ctx,
							RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE,NULL);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}
		}


		if( rhp_realm_cfg_svr_narrow_ts_i(rlm,vpn) ){

			err = rhp_ikev2_create_child_sa_mod_tss_cp(tx_resp_ikemesg,&s_pld_ctx,(unsigned int)-1);

			if( s_pld_ctx.notify_error ){

				RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_MOD_TSS_WITH_CP_TX_NTFY_ERR,"xxxxw",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,s_pld_ctx.notify_error);
				goto notify_error;
			}

			err = 0;

		}else{

			RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_NO_CP,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
		}


		if( vpn->internal_net_info.peer_exec_ipv6_autoconf ){

			err = _rhp_ikev2_rekey_ipv6_autoconf_mod_tss_peer_addrs(vpn,&s_pld_ctx);

			if( s_pld_ctx.notify_error ){

				RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_IPV6_AUTOCONF_MOD_TSS_WITH_PEER_ADDRS_TX_NTFY_ERR,"xxxxw",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,s_pld_ctx.notify_error);
				goto notify_error;
			}

			err = rhp_ikev2_create_child_sa_add_v6_auto_ts(&s_pld_ctx,0);
			if( err && err != -ENOENT ){
				goto error;
			}
			err = 0;
		}
	}

  new_childsa = rhp_childsa_alloc2_r(&(s_pld_ctx.resolved_prop.v2),rlm);
  if( new_childsa == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error_l;
  }

  new_childsa->gen_type = RHP_CHILDSA_GEN_REKEY;

  new_childsa->timers = rhp_childsa_new_timers(new_childsa->spi_inb,new_childsa->spi_outb);

  if( new_childsa->timers == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error_l;
  }

  new_childsa->parent_ikesa.side = ikesa->side;
  memcpy(new_childsa->parent_ikesa.init_spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
  memcpy(new_childsa->parent_ikesa.resp_spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);

	new_childsa->ipsec_mode = old_childsa->ipsec_mode;


  if( rlm->childsa.pfs ){

    err = new_childsa->rekey_dh->set_peer_pub_key(new_childsa->rekey_dh,s_pld_ctx.peer_dh_pub_key,s_pld_ctx.peer_dh_pub_key_len);
    if( err ){
      RHP_BUG("%d",err);
      goto error_l;
    }

    err = new_childsa->rekey_dh->compute_key(new_childsa->rekey_dh);
    if( err ){
      RHP_BUG("%d",err);
      goto error_l;
    }
  }


  // Setup internal network
  err = _rhp_ikev2_rx_rekey_req_childsa_internal_net(vpn,rlm,new_childsa,&s_pld_ctx);
	if( err ){

		if( s_pld_ctx.notify_error ){
			RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_CHILDSA_INVALID_ENCAP_MODE,"xxxdbbb",vpn,ikesa,rx_req_ikemesg,rlm->encap_mode_c,s_pld_ctx.use_trans_port_mode,s_pld_ctx.use_etherip_encap,s_pld_ctx.use_gre_encap);
	    goto notify_error;
		}

		goto error_l;
	}


  err = new_childsa->set_traffic_selectors(new_childsa,s_pld_ctx.res_tss_r,s_pld_ctx.res_tss_i,vpn);
  if( err ){
    RHP_BUG("%d",err);
    goto error_l;
  }

  err = new_childsa->rekey_nonce_i->set_nonce(new_childsa->rekey_nonce_i,s_pld_ctx.nonce,s_pld_ctx.nonce_len);
  if( err ){
    RHP_BUG("%d",err);
    goto error_l;
  }

  new_childsa->esn = s_pld_ctx.resolved_prop.v2.esn;

  if( new_childsa->esn ){
  	new_childsa->rx_anti_replay.rx_seq.esn.b = 1;
  	new_childsa->rx_anti_replay.rx_seq.esn.t = 1;
  }else{
  	new_childsa->rx_anti_replay.rx_seq.non_esn.last = 1;
  }

  err = new_childsa->setup_sec_params2(ikesa,new_childsa);
  if( err ){
    RHP_BUG("%d",err);
    goto error_l;
  }

  if( s_pld_ctx.esp_tfc_padding_not_supported || !rlm->childsa.tfc_padding ){
  	new_childsa->tfc_padding = 0;
  }else{
  	new_childsa->tfc_padding = 1;
  }

  new_childsa->anti_replay = rlm->childsa.anti_replay;


  new_childsa->out_of_order_drop = rlm->childsa.out_of_order_drop;

  new_childsa->rekeyed_gen = (old_childsa->rekeyed_gen + 1);

  err = _rhp_ikev2_rekey_new_pkt_childsa_rep(rx_req_ikemesg,tx_resp_ikemesg,new_childsa,&s_pld_ctx);
  if( err ){

		if( s_pld_ctx.notify_error ){
	  	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_CHILDSA_NEW_PKT_REP_NTFY_ERR,"xxx",vpn,ikesa,rx_req_ikemesg);
	    goto notify_error;
		}

    RHP_BUG("");
    goto error_l;
  }

  {
		rhp_childsa_calc_pmtu(vpn,rlm,new_childsa);
		new_childsa->exec_pmtud = rlm->childsa.exec_pmtud;
  }


  rhp_childsa_set_state(new_childsa,RHP_CHILDSA_STAT_MATURE);
  vpn->created_childsas++;

  new_childsa->established_time = _rhp_get_time();
  new_childsa->expire_soft = new_childsa->established_time + (time_t)rlm->childsa.lifetime_soft;
  new_childsa->expire_hard = new_childsa->established_time + (time_t)rlm->childsa.lifetime_hard;

  new_childsa->timers->start_lifetime_timer(vpn,new_childsa,(time_t)rlm->childsa.lifetime_soft,1);


  err = rhp_vpn_inb_childsa_put(vpn,new_childsa->spi_inb);
  if( err ){
    RHP_BUG("%d",err);
    goto error_l;
  }

  vpn->childsa_put(vpn,new_childsa);


  rhp_esp_add_childsa_to_impl(vpn,new_childsa);


  old_childsa->timers->schedule_delete(vpn,old_childsa,
  		(vpn->origin_side == RHP_IKE_INITIATOR ?
  		 rhp_gcfg_ikev2_rekey_childsa_delete_deferred_init : rhp_gcfg_ikev2_rekey_childsa_delete_deferred_resp));


  // Mark collision flag to childsa.
  _rhp_ikev2_rx_rekey_req_childsa_mark_collision_sa(vpn,new_childsa);


  if( (err = rhp_vpn_clear_unique_ids_tls_cache(vpn->vpn_realm_id)) ){
  	RHP_BUG("%d",err);
  }
  err = 0;

  RHP_UNLOCK(&(rlm->lock));


  if( s_pld_ctx.res_tss_i ){
    rhp_ikev2_ts_payload_free_tss(s_pld_ctx.res_tss_i);
  }

  if( s_pld_ctx.res_tss_r ){
    rhp_ikev2_ts_payload_free_tss(s_pld_ctx.res_tss_r);
  }


	if( vpn->internal_net_info.exec_ipv6_autoconf &&
			vpn->nhrp.role == RHP_NHRP_SERVICE_CLIENT ){

		rhp_nhrp_invoke_update_addr_task(vpn,0,
				rhp_gcfg_nhrp_registration_req_tx_margin_time);
	}


	if( vpn->nhrp.pend_resolution_req_q.head ){

  	rhp_nhrp_tx_queued_resolution_rep(vpn);
  }


  RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_REKEYED_CHILDSA_RESPONDER,"KVC",rx_req_ikemesg,vpn,new_childsa);


	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_CHILDSA_RTRN,"xxx",vpn,ikesa,rx_req_ikemesg);
	return 0;

notify_error:
  err = _rhp_ikev2_rekey_new_pkt_error_notify_rep(tx_resp_ikemesg,ikesa,
  					s_pld_ctx.notify_proto,s_pld_ctx.notify_spi,s_pld_ctx.notify_error,s_pld_ctx.notify_error_arg);

  if( err ){
  	RHP_BUG("");
  	goto error_l;
  }

  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_REKEY_CHILDSA_TX_ERR_RESP,"KVL",tx_resp_ikemesg,vpn,"PROTO_IKE_NOTIFY",s_pld_ctx.notify_error);
  err = RHP_STATUS_IKEV2_MESG_HANDLER_END;

error_l:
  RHP_UNLOCK(&(rlm->lock));
error:
  if( new_childsa ){
  	rhp_childsa_destroy(vpn,new_childsa);
  }

  if( s_pld_ctx.res_tss_i ){
    rhp_ikev2_ts_payload_free_tss(s_pld_ctx.res_tss_i);
  }
  if( s_pld_ctx.res_tss_r ){
    rhp_ikev2_ts_payload_free_tss(s_pld_ctx.res_tss_r);
  }

	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_REKEY_CHILDSA_RESPONDER_ERR,"KVE",rx_req_ikemesg,vpn,err);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_CHILDSA_ERR,"xxxE",vpn,ikesa,rx_req_ikemesg,err);
  return err;
}

static int _rhp_ikev2_rx_rekey_req(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,
		rhp_ikev2_mesg* tx_resp_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_proto_ike* ikeh;
  rhp_packet* rx_pkt;
  rhp_ikev2_payload* sa_payload = NULL;
  rhp_childsa_srch_plds_ctx s_pld_ctx;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_L,"xxxx",vpn,ikesa,rx_req_ikemesg,rx_req_ikemesg->rx_pkt);

  rx_pkt = rx_req_ikemesg->rx_pkt;
  ikeh = rx_pkt->app.ikeh;

  if( rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
  	RHP_BUG("");
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

  memset(&s_pld_ctx,0,sizeof(rhp_childsa_srch_plds_ctx));

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  						rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_SA),
  						_rhp_ikev2_rekey_srch_sa_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_L_NO_SA_PLD_1,"xxxE",vpn,ikesa,rx_req_ikemesg,err);
      goto error;
    }

  	if( s_pld_ctx.sa_payload == NULL ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_L_NO_SA_PLD_2,"xxx",vpn,ikesa,rx_req_ikemesg);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }

    sa_payload = s_pld_ctx.sa_payload;
  }

  if( sa_payload->ext.sa->rx_payload_is_for_ikesa(sa_payload) ){
    err = _rhp_ikev2_rx_rekey_req_ikesa(vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,sa_payload);
  }else{
    err = _rhp_ikev2_rx_rekey_req_childsa(vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,sa_payload);
  }

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_L_IKESA_RTRN,"xxxE",vpn,ikesa,rx_req_ikemesg,err);
	return err;
}

int rhp_ikev2_rx_rekey_req(rhp_ikev2_mesg* rx_req_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_req_ikemesg->get_exchange_type(rx_req_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ,"xxLdGxLb",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_resp_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

	if( exchange_type != RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA ){
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_NOT_CREATE_CHILDSA_EXCHG,"xxLb",rx_req_ikemesg,vpn,"PROTO_IKE_EXCHG",exchange_type);
		return 0;
	}

	if( !rx_req_ikemesg->for_rekey_req ){
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_NOT_CREATE_CHILDSA_EXCHG_FOR_REKEY,"xxLb",rx_req_ikemesg,vpn,"PROTO_IKE_EXCHG",exchange_type);
		return 0;
	}

	if( my_ikesa_spi == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  if( !rx_req_ikemesg->decrypted ){
  	err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_NOT_DECRYPTED,"xxLdG",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
  	goto error;
  }

	ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
	if( ikesa == NULL ){
		err = -ENOENT;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_NO_IKESA,"xxLdG",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
		goto error;
	}

	if( ikesa->state != RHP_IKESA_STAT_ESTABLISHED && ikesa->state != RHP_IKESA_STAT_REKEYING ){
		err = 0; // Just ignore...
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_IKESA_STATE_NOT_INTERESTED,"xxLdGLd",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state);
		goto error;
	}

  err = _rhp_ikev2_rx_rekey_req(vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);

error:
	if( err ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_REKEY_REQ_ERR,"KVLGE",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,err);
	}
	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REQ_RTRN,"xxxE",rx_req_ikemesg,vpn,tx_resp_ikemesg,err);
  return err;
}

int rhp_ikev2_rx_rekey_rep(rhp_ikev2_mesg* rx_resp_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_resp_ikemesg->get_exchange_type(rx_resp_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP,"xxLdGxLb",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_req_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

	if( exchange_type != RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA ){
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_EXCHG_TYPE_NOT_INTERESTED,"xx",rx_resp_ikemesg,vpn);
		return 0;
	}

	if( my_ikesa_spi == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  if( !rx_resp_ikemesg->decrypted ){
  	err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_NOT_DECRYPTED,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
  	goto error;
  }

	ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
	if( ikesa == NULL ){
		err = -ENOENT;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_NO_IKESA,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
		goto error;
	}

	if( ikesa->state != RHP_IKESA_STAT_ESTABLISHED && ikesa->state != RHP_IKESA_STAT_REKEYING ){
		err = 0; // Just ignore...
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_NOT_INTERESTED,"xxLdGLd",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state);
		goto error;
	}

  err = _rhp_ikev2_rx_rekey_rep(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);

error:
	if( err ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_REKEY_REP_ERR,"KVLGE",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,err);
	}
	RHP_TRC(0,RHPTRCID_IKEV2_RX_REKEY_REP_RTRN,"xxxE",rx_resp_ikemesg,vpn,tx_req_ikemesg,err);
  return err;
}

