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
#include "rhp_esp.h"
#include "rhp_forward.h"
#include "rhp_nhrp.h"


static int _rhp_ikev1_rx_quick_update_p2_sess(rhp_ikesa* ikesa,rhp_childsa* childsa,rhp_ikev2_mesg* rx_ikemesg)
{
	int err = -EINVAL;
	rhp_ikev1_p2_session* p2_sess;
	u8 exchange_type = rx_ikemesg->get_exchange_type(rx_ikemesg);
	u32 mesg_id = rx_ikemesg->get_mesg_id(rx_ikemesg);

	RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_UPDATE_P2_SESS,"xxxbkLdLd",ikesa,childsa,rx_ikemesg,exchange_type,mesg_id,"IKESA_STAT",ikesa->state,"CHILDSA_STAT",childsa->state);

	p2_sess = rhp_ikev1_p2_session_get(ikesa,mesg_id,exchange_type);
	if( p2_sess ){

		if( childsa->state == RHP_IPSECSA_STAT_V1_MATURE ){

			p2_sess->clear_aftr_proc = 1;
		}

		if( rx_ikemesg->v1_p2_iv_len == p2_sess->iv_len ){

			memcpy(p2_sess->iv_last_rx_blk,
				rx_ikemesg->v1_p2_rx_last_blk,rx_ikemesg->v1_p2_iv_len);
		}

		err = 0;

	}else{

		RHP_BUG("0x%lx, %d, %d",p2_sess,rx_ikemesg->v1_p2_iv_len,(p2_sess ? p2_sess->iv_len : 0));
		err = -EINVAL;
	}

	RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_UPDATE_P2_SESS_RTRN,"xxxx",ikesa,childsa,rx_ikemesg,p2_sess);
	return err;
}

static int _rhp_ikev1_detach_old_childsa(rhp_vpn* vpn,rhp_childsa* new_childsa)
{
	rhp_childsa* old_childsa;
	rhp_childsa* old_childsa2 = NULL;

	RHP_TRC(0,RHPTRCID_IKEV1_DETACH_OLD_CHILDSA,"xxLd",vpn,new_childsa,"AF",new_childsa->v1.addr_family);

	old_childsa = vpn->childsa_list_head;
	while( old_childsa ){

		RHP_TRC(0,RHPTRCID_IKEV1_DETACH_OLD_CHILDSA_1,"xxxxLdLdtt",vpn,new_childsa,old_childsa,old_childsa2,"CHILDSA_STAT",old_childsa->state,"AF",old_childsa->v1.addr_family,(old_childsa2 ? old_childsa2->expire_hard : 0),old_childsa->expire_hard);

		if( old_childsa != new_childsa ){

			if( (old_childsa->v1.addr_family == new_childsa->v1.addr_family) &&
					(old_childsa->state == RHP_IPSECSA_STAT_V1_MATURE ||
					 old_childsa->state == RHP_IPSECSA_STAT_V1_REKEYING) &&
					(old_childsa2 == NULL || old_childsa2->expire_hard < old_childsa->expire_hard) ){

				old_childsa2 = old_childsa;
			}

			old_childsa->v1.dont_rekey = 1;
		}

		old_childsa = old_childsa->next_vpn_list;
	}


	old_childsa = vpn->childsa_list_head;
	while( old_childsa ){

		if( (old_childsa->v1.addr_family == new_childsa->v1.addr_family) &&
				old_childsa != new_childsa &&
				old_childsa != old_childsa2 ){

			RHP_TRC(0,RHPTRCID_IKEV1_DETACH_OLD_CHILDSA_2,"xxxx",vpn,new_childsa,old_childsa,old_childsa2);

	  	rhp_childsa_set_state(old_childsa,RHP_IPSECSA_STAT_V1_DELETE_WAIT);
			old_childsa->timers->schedule_delete(vpn,old_childsa,1);
		}

		old_childsa = old_childsa->next_vpn_list;
	}

	RHP_TRC(0,RHPTRCID_IKEV1_DETACH_OLD_CHILDSA_RTRN,"xxx",vpn,new_childsa,old_childsa2);
	return 0;
}

static int _rhp_ikev1_new_pkt_quick_i_1_hash_buf(rhp_ikev2_mesg* ikemesg,
		int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_packet* pkt_for_hash = (rhp_packet*)ctx;
	u8 pld_id = payload->get_payload_id(payload);

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_QUICK_I_1_HASH_BUF,"xxLbxxd",ikemesg,payload,"PROTO_IKE_PAYLOAD",payload->payload_id,ctx,pkt_for_hash,ikemesg->tx_mesg_len);

  if( pld_id != RHP_PROTO_IKEV1_PAYLOAD_HASH ){

		err = payload->ext_serialize(payload,pkt_for_hash);
		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_QUICK_I_1_HASH_BUF_ERR,"xxLbxE",ikemesg,payload,"PROTO_IKE_PAYLOAD",payload->payload_id,ctx,err);
			return err;
		}
  }

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_QUICK_I_1_HASH_BUF_RTRN,"xxxd",ikemesg,payload,pkt_for_hash,ikemesg->tx_mesg_len);
	return 0;
}

int rhp_ikev1_new_pkt_quick_i_1(rhp_vpn* vpn,rhp_vpn_realm* rlm,
		rhp_ikesa* ikesa,rhp_childsa* childsa,int addr_family,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;
  u32 tx_mesg_id;
  rhp_packet* pkt_for_hash = NULL;
  int hash_octets_len = 0;
  u8* hash_octets = NULL;
	rhp_childsa_ts *csa_ts_i = NULL, *csa_ts_r = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_QUICK_I_1,"xxxxxLdLdddLdd",vpn,rlm,ikesa,childsa,tx_ikemesg,"CHILDSA_MODE",childsa->ipsec_mode,"AF",addr_family,rlm->childsa.pfs,vpn->v1.commit_bit_enabled,"VPN_ENCAP",rlm->encap_mode_c,rlm->childsa.gre_auto_gen_ts);


  tx_ikemesg->set_exchange_type(tx_ikemesg,RHP_PROTO_IKEV1_EXCHG_QUICK);

  if( rhp_gcfg_ikev1_commit_bit_enabled &&
  		(vpn->cfg_peer->ikev1_commit_bit_enabled ||
  		 vpn->v1.commit_bit_enabled) ){

  	tx_ikemesg->tx_flag |= RHP_IKEV2_SEND_REQ_FLAG_V1_COMMIT_BIT;
  }

  {
		err = rhp_random_bytes((u8*)&tx_mesg_id,sizeof(u32));
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		tx_ikemesg->set_mesg_id(tx_ikemesg,tx_mesg_id);
  }


  {
  	u16 dhgrp = 0;
  	int encap_mode = RHP_PROTO_IKEV1_P2_ATTR_ENCAP_MODE_TUNNEL;

  	if( rlm->childsa.pfs ){
  		dhgrp = ikesa->prop.v1.dh_group;
  	}

  	if( childsa->ipsec_mode == RHP_CHILDSA_MODE_TRANSPORT ){
  		if( !vpn->nat_t_info.exec_nat_t ){
  			encap_mode = RHP_PROTO_IKEV1_P2_ATTR_ENCAP_MODE_TRANSPORT;
  		}else{
  			encap_mode = RHP_PROTO_IKEV1_P2_ATTR_ENCAP_MODE_UDP_TRANSPORT;
  		}
  	}else if( vpn->nat_t_info.exec_nat_t ){
  		encap_mode = RHP_PROTO_IKEV1_P2_ATTR_ENCAP_MODE_UDP_TUNNEL;
  	}

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_SA,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    err = ikepayload->ext.v1_sa->set_def_ipsecsa_prop(ikepayload,
    				childsa->spi_inb,dhgrp,encap_mode,rlm->childsa.lifetime_hard);
    if( err ){
      RHP_BUG("");
      goto error;
    }
  }


  {
    int nonce_len;
    u8* nonce;

    childsa->v1.nonce_i = rhp_crypto_nonce_alloc();
    if( childsa->v1.nonce_i == NULL ){
    	RHP_BUG("");
    	err = -EINVAL;
    	goto error;
    }

    childsa->v1.nonce_r = rhp_crypto_nonce_alloc();
    if( childsa->v1.nonce_r == NULL ){
    	RHP_BUG("");
    	err = -EINVAL;
    	goto error;
    }

    err = childsa->v1.nonce_i->generate_nonce(childsa->v1.nonce_i,rhp_gcfg_nonce_size);
    if( err ){
    	RHP_BUG("");
    	goto error;
    }

    nonce_len = childsa->v1.nonce_i->get_nonce_len(childsa->v1.nonce_i);
    nonce = childsa->v1.nonce_i->get_nonce(childsa->v1.nonce_i);

    if( nonce == NULL ){
      RHP_BUG("");
      goto error;
    }

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_NONCE,&ikepayload) ){
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
    u8* key;

    childsa->v1.dh = rhp_crypto_dh_alloc(ikesa->prop.v1.dh_group);
    if( childsa->v1.dh == NULL ){
      RHP_BUG("");
      goto error;
    }

    if( childsa->v1.dh->generate_key(childsa->v1.dh) ){
      RHP_BUG("");
      goto error;
    }


    key = childsa->v1.dh->get_my_pub_key(childsa->v1.dh,&key_len);
    if( key == NULL ){
      RHP_BUG("");
      goto error;
    }

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_KE,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.v1_ke->set_key(ikepayload,key_len,key) ){
      RHP_BUG("");
      goto error;
    }
	}


  {
  	rhp_ip_addr gre_local_addr;

		memset(&gre_local_addr,0,sizeof(rhp_ip_addr));

  	if( rlm->encap_mode_c == RHP_VPN_ENCAP_GRE &&
  			rlm->childsa.gre_auto_gen_ts ){

  		gre_local_addr.addr_family = vpn->local.if_info.addr_family;
  		memcpy(gre_local_addr.addr.raw,vpn->local.if_info.addr.raw,16);

  		rhp_ip_addr_dump("gre_local_addr",&gre_local_addr);
  	}

    if( (err = rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_ID,&ikepayload)) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( (err = ikepayload->ext.v1_id->set_i_ts(ikepayload,rlm,RHP_IKE_INITIATOR,
    						addr_family,vpn->cfg_peer,NULL,
    						((gre_local_addr.addr_family == AF_INET || gre_local_addr.addr_family == AF_INET6) ? &gre_local_addr : NULL),
    						&csa_ts_i)) ){
      RHP_BUG("");
      goto error;
    }

    childsa->gre_ts_auto_generated
    	= ikepayload->ext.v1_id->gre_ts_auto_generated;
  }

  {
    if( (err = rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_ID,&ikepayload)) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( (err = ikepayload->ext.v1_id->set_i_ts(ikepayload,rlm,RHP_IKE_RESPONDER,
    						addr_family,vpn->cfg_peer,NULL,
    						((rlm->encap_mode_c == RHP_VPN_ENCAP_GRE && rlm->childsa.gre_auto_gen_ts)
    								? &(vpn->peer_addr) : NULL), &csa_ts_r)) ){
      RHP_BUG("");
      goto error;
    }

    childsa->gre_ts_auto_generated
    	= ikepayload->ext.v1_id->gre_ts_auto_generated;
  }

  if( vpn->nat_t_info.exec_nat_t ){

    {
      if( (err = rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_NAT_OA,&ikepayload)) ){
        RHP_BUG("");
        goto error;
      }

      tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

      if( (err = ikepayload->ext.v1_nat_oa->set_orig_addr(ikepayload,
      			vpn->local.if_info.addr_family,vpn->local.if_info.addr.raw)) ){
        RHP_BUG("");
        goto error;
      }
    }

    {
      if( (err = rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_NAT_OA,&ikepayload)) ){
        RHP_BUG("");
        goto error;
      }

      tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

      if( (err = ikepayload->ext.v1_nat_oa->set_orig_addr(ikepayload,
      			vpn->peer_addr.addr_family,vpn->peer_addr.addr.raw)) ){
        RHP_BUG("");
        goto error;
      }
    }
  }



	if( (rlm->encap_mode_c & RHP_VPN_ENCAP_ETHERIP) && vpn->peer_is_rockhopper ){

		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);
		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_ETHERIP_ENCAP);

	}else if( (rlm->encap_mode_c & RHP_VPN_ENCAP_GRE) && vpn->peer_is_rockhopper ){

		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);
		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_GRE_ENCAP);
	}


	{
		int buf_offset, buf_len, org_tx_len = tx_ikemesg->tx_mesg_len;
		u8* buf;

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
						_rhp_ikev1_new_pkt_quick_i_1_hash_buf,pkt_for_hash);
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

	  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_QUICK_I_1_HASH_DATA,"xxxxpp",vpn,ikesa,childsa,tx_ikemesg,ikesa->keys.v1.skeyid_a_len,ikesa->keys.v1.skeyid_a,buf_len,buf);

	  if( ikesa->prf->set_key(ikesa->prf,ikesa->keys.v1.skeyid_a,ikesa->keys.v1.skeyid_a_len) ){
	    RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_QUICK_I_1_PRF_SET_KEY_ERR,"xx",ikesa,ikesa->prf);
	    goto error;
	  }

	  if( ikesa->prf->compute(ikesa->prf,buf,buf_len,hash_octets,hash_octets_len) ){
	    RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_QUICK_I_1_PRF_COMPUTE_ERR,"xx",ikesa,ikesa->prf);
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
	}


	err = childsa->set_traffic_selector_v1(childsa,csa_ts_i,csa_ts_r,NULL,NULL);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}


	{
	  tx_ikemesg->tx_ikesa_fixed = 1;

	  tx_ikemesg->ikesa_my_side = ikesa->side;
	  memcpy(tx_ikemesg->ikesa_my_spi,ikesa->get_my_spi(ikesa),RHP_PROTO_IKE_SPI_SIZE);
	}


	_rhp_free(csa_ts_i);
	_rhp_free(csa_ts_r);

	rhp_pkt_unhold(pkt_for_hash);
	_rhp_free(hash_octets);

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_QUICK_I_1_RTRN,"xxxxxd",vpn,rlm,ikesa,childsa,tx_ikemesg,vpn->v1.commit_bit_enabled);
  return 0;

error:
	if( pkt_for_hash ){
		rhp_pkt_unhold(pkt_for_hash);
	}
	if( hash_octets ){
		_rhp_free(hash_octets);
	}
	if( csa_ts_i ){
		_rhp_free(csa_ts_i);
	}
	if( csa_ts_r ){
		_rhp_free(csa_ts_r);
	}
	RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_QUICK_I_1_ERR,"xxxxxE",vpn,rlm,ikesa,childsa,tx_ikemesg,err);
  return err;
}

static int _rhp_ikev1_new_pkt_quick_i_3(rhp_vpn* vpn,rhp_vpn_realm* rlm,
		rhp_ikesa* ikesa,rhp_childsa* childsa,rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;
  u32 tx_mesg_id = rx_ikemesg->get_mesg_id(rx_ikemesg);
  int hash_octets_len = 0;
  u8* hash_octets = NULL;
	int buf_len,ni_b_len,nr_b_len;
	u8 *buf = NULL,*ni_b,*nr_b;
	u8* p;

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_QUICK_I_3,"xxxxxLdx",vpn,rlm,ikesa,childsa,tx_ikemesg,"CHILDSA_MODE",childsa->ipsec_mode,rx_ikemesg);

	tx_ikemesg->set_mesg_id(tx_ikemesg,tx_mesg_id);

  if( rhp_gcfg_ikev1_commit_bit_enabled &&
  		(vpn->cfg_peer->ikev1_commit_bit_enabled ||
  		 vpn->v1.commit_bit_enabled) ){

  	tx_ikemesg->tx_flag |= RHP_IKEV2_SEND_REQ_FLAG_V1_COMMIT_BIT;
  }

	ni_b_len = childsa->v1.nonce_i->get_nonce_len(childsa->v1.nonce_i);
	nr_b_len = childsa->v1.nonce_r->get_nonce_len(childsa->v1.nonce_r);
	ni_b = childsa->v1.nonce_i->get_nonce(childsa->v1.nonce_i);
	nr_b = childsa->v1.nonce_r->get_nonce(childsa->v1.nonce_r);

	if( ni_b_len < 0 || nr_b_len < 0 || ni_b == NULL || nr_b == NULL ){
		RHP_BUG("%d,%d,0x%lx,0x%lx",ni_b_len,nr_b_len,ni_b,nr_b);
		err = -EINVAL;
		goto error;
	}

	{
		buf_len = sizeof(u8) + sizeof(u32) + ni_b_len + nr_b_len;
		buf = (u8*)_rhp_malloc(buf_len);
		if( buf == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		p = buf;

		*p = 0;
		p += sizeof(u8);

		*((u32*)p) = htonl(tx_mesg_id);
		p += sizeof(u32);

		memcpy(p,ni_b,ni_b_len);
		p += ni_b_len;

		memcpy(p,nr_b,nr_b_len);
		p += nr_b_len;
	}

	{
		hash_octets_len = ikesa->prf->get_output_len(ikesa->prf);

	  hash_octets = (u8*)_rhp_malloc(hash_octets_len);
	  if( hash_octets == NULL ){
	    RHP_BUG("");
	    err = -ENOMEM;
	    goto error;
	  }

	  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_QUICK_I_3_HASH_DATA,"xxxxpp",vpn,ikesa,childsa,tx_ikemesg,ikesa->keys.v1.skeyid_a_len,ikesa->keys.v1.skeyid_a,buf_len,buf);

	  if( ikesa->prf->set_key(ikesa->prf,ikesa->keys.v1.skeyid_a,ikesa->keys.v1.skeyid_a_len) ){
	    RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_QUICK_I_3_PRF_SET_KEY_ERR,"xx",ikesa,ikesa->prf);
	    goto error;
	  }

	  if( ikesa->prf->compute(ikesa->prf,buf,buf_len,hash_octets,hash_octets_len) ){
	    RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_QUICK_I_3_PRF_COMPUTE_ERR,"xx",ikesa,ikesa->prf);
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
	}

	_rhp_free(buf);
	_rhp_free(hash_octets);

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_QUICK_I_3_RTRN,"xxxxx",vpn,rlm,ikesa,childsa,tx_ikemesg);
  return 0;

error:
	if( buf ){
		_rhp_free(buf);
	}
	if( hash_octets ){
		_rhp_free(hash_octets);
	}
	RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_QUICK_I_3_ERR,"xxxxxE",vpn,rlm,ikesa,childsa,tx_ikemesg,err);
  return err;
}


static int _rhp_ikev1_new_pkt_quick_r_2(rhp_vpn* vpn,rhp_vpn_realm* rlm,
		rhp_ikesa* ikesa,rhp_childsa* childsa,
		rhp_childsa_srch_plds_ctx* s_pld_ctx,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;
  u32 tx_mesg_id = rx_ikemesg->get_mesg_id(rx_ikemesg);
  rhp_packet* pkt_for_hash = NULL;
  int hash_octets_len = 0;
  u8* hash_octets = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_QUICK_R_2,"xxxxxxxLdLduxduu",vpn,rlm,ikesa,childsa,s_pld_ctx,rx_ikemesg,tx_ikemesg,"CHILDSA_MODE",childsa->ipsec_mode,tx_mesg_id,childsa->v1.dh,vpn->internal_net_info.encap_mode_c,childsa->prop.v1.life_time,childsa->prop.v1.rx_life_time);

	tx_ikemesg->set_mesg_id(tx_ikemesg,tx_mesg_id);

  if( rhp_gcfg_ikev1_commit_bit_enabled &&
  		rx_ikemesg->v1_commit_bit_enabled(rx_ikemesg) ){

  	tx_ikemesg->tx_flag |= RHP_IKEV2_SEND_REQ_FLAG_V1_COMMIT_BIT;
  }

  {

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_SA,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);


    err = ikepayload->ext.v1_sa->set_matched_ipsecsa_prop(ikepayload,
    				&(s_pld_ctx->resolved_prop.v1),childsa->spi_inb);
    if( err ){
      RHP_BUG("");
      goto error;
    }
  }


  {
    int nonce_len;
    u8* nonce;

    nonce_len = childsa->v1.nonce_r->get_nonce_len(childsa->v1.nonce_r);
    nonce = childsa->v1.nonce_r->get_nonce(childsa->v1.nonce_r);

    if( nonce == NULL ){
      RHP_BUG("");
      goto error;
    }

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_NONCE,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.nir->set_nonce(ikepayload,nonce_len,nonce) ){
      RHP_BUG("");
      goto error;
    }
  }


	if( childsa->v1.dh ){

    int key_len;
    u8* key;

    key = childsa->v1.dh->get_my_pub_key(childsa->v1.dh,&key_len);
    if( key == NULL ){
      RHP_BUG("");
      goto error;
    }

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_KE,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.v1_ke->set_key(ikepayload,key_len,key) ){
      RHP_BUG("");
      goto error;
    }
	}


  {
    if( (err = rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_ID,&ikepayload)) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    err = ikepayload->ext.v1_id->set_csa_ts(ikepayload,childsa->peer_tss);
    if( err ){
      RHP_BUG("");
      goto error;
    }
  }

  {
    if( (err = rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_ID,&ikepayload)) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    err = ikepayload->ext.v1_id->set_csa_ts(ikepayload,childsa->my_tss);
    if( err ){
      RHP_BUG("");
      goto error;
    }
  }


  if( childsa->prop.v1.rx_life_time &&
  		childsa->prop.v1.life_time < childsa->prop.v1.rx_life_time ){

  	rhp_proto_ikev1_attr *attr0, *attr1;
  	int attr0_len, attr1_len;

		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,RHP_PROTO_IKEV1_PROP_PROTO_ID_ESP);

		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKEV1_N_ST_RESPONDER_LIFETIME);

		ikepayload->ext.n->set_spi(ikepayload,childsa->spi_inb);



		attr0_len = sizeof(rhp_proto_ikev1_attr);
		attr0 = (rhp_proto_ikev1_attr*)_rhp_malloc(attr0_len);
    if( attr0 == NULL ){
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }

    attr1_len = sizeof(rhp_proto_ikev1_attr) + 4;
		attr1 = (rhp_proto_ikev1_attr*)_rhp_malloc(attr1_len);
    if( attr0 == NULL ){
    	_rhp_free(attr0);
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }

    attr0->attr_type = RHP_PROTO_IKE_ATTR_SET_AF(htons(RHP_PROTO_IKEV1_P1_ATTR_TYPE_LIFE_TYPE));
    attr0->len_or_value = htons(RHP_PROTO_IKEV1_ATTR_LIFE_TYPE_SECONDS);

    attr1->attr_type = htons(RHP_PROTO_IKEV1_P1_ATTR_TYPE_LIFE_DURATION);
    attr1->len_or_value = htons(4);
    *((u32*)(attr1 + 1)) = htonl((u32)childsa->prop.v1.life_time);


    err = ikepayload->ext.n->set_data2(ikepayload,attr0_len,(u8*)attr0,attr1_len,(u8*)attr1);
    if( err ){
    	_rhp_free(attr0);
    	_rhp_free(attr1);
      RHP_BUG("");
    	goto error;
    }

  	_rhp_free(attr0);
  	_rhp_free(attr1);
  }

  if( vpn->nat_t_info.exec_nat_t ){

    {
      if( (err = rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_NAT_OA,&ikepayload)) ){
        RHP_BUG("");
        goto error;
      }

      tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

      if( (err = ikepayload->ext.v1_nat_oa->set_orig_addr(ikepayload,
      			vpn->peer_addr.addr_family,vpn->peer_addr.addr.raw)) ){
        RHP_BUG("");
        goto error;
      }
    }

    {
      if( (err = rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_NAT_OA,&ikepayload)) ){
        RHP_BUG("");
        goto error;
      }

      tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

      if( (err = ikepayload->ext.v1_nat_oa->set_orig_addr(ikepayload,
      			vpn->local.if_info.addr_family,vpn->local.if_info.addr.raw)) ){
        RHP_BUG("");
        goto error;
      }
    }
  }


  if( (vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_ETHERIP) && vpn->peer_is_rockhopper ){

		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);
		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_ETHERIP_ENCAP);

  }else if( (vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_GRE) && vpn->peer_is_rockhopper ){

		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);
		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_GRE_ENCAP);
	}



	{
		int buf_offset, buf_len, org_tx_len = tx_ikemesg->tx_mesg_len, ni_b_len;
		u8 *buf, *ni_b;

		ni_b_len = childsa->v1.nonce_i->get_nonce_len(childsa->v1.nonce_i);
		ni_b = childsa->v1.nonce_i->get_nonce(childsa->v1.nonce_i);

		pkt_for_hash = rhp_pkt_alloc(RHP_PKT_IKE_DEFAULT_SIZE);
		if( pkt_for_hash == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}

		buf = _rhp_pkt_push(pkt_for_hash,sizeof(u32));
		buf_offset = buf - pkt_for_hash->head;
		*((u32*)buf) = htonl(tx_mesg_id);

		buf = _rhp_pkt_push(pkt_for_hash,ni_b_len);
		memcpy(buf,ni_b,ni_b_len);

		err = tx_ikemesg->search_payloads(tx_ikemesg,0,NULL,NULL,
						_rhp_ikev1_new_pkt_quick_i_1_hash_buf,pkt_for_hash);
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

	  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_QUICK_R_2_HASH_DATA,"xxxxpp",vpn,ikesa,childsa,tx_ikemesg,ikesa->keys.v1.skeyid_a_len,ikesa->keys.v1.skeyid_a,buf_len,buf);

	  if( ikesa->prf->set_key(ikesa->prf,ikesa->keys.v1.skeyid_a,ikesa->keys.v1.skeyid_a_len) ){
	    RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_QUICK_R_2_PRF_SET_KEY_ERR,"xx",ikesa,ikesa->prf);
	    goto error;
	  }

	  if( ikesa->prf->compute(ikesa->prf,buf,buf_len,hash_octets,hash_octets_len) ){
	    RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_QUICK_R_2_PRF_COMPUTE_ERR,"xx",ikesa,ikesa->prf);
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
	}


	rhp_pkt_unhold(pkt_for_hash);
	_rhp_free(hash_octets);

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_QUICK_R_2_RTRN,"xxxxx",vpn,rlm,ikesa,childsa,tx_ikemesg);
  return 0;

error:
	if( pkt_for_hash ){
		rhp_pkt_unhold(pkt_for_hash);
	}
	if( hash_octets ){
		_rhp_free(hash_octets);
	}
	RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_QUICK_R_2_ERR,"xxxxxE",vpn,rlm,ikesa,childsa,tx_ikemesg,err);
  return err;
}

static int _rhp_ikev1_quick_r_add_hash_buf(rhp_ikev2_mesg* ikemesg,
		int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_packet* pkt_for_hash = (rhp_packet*)ctx;
	u8 pld_id = payload->get_payload_id(payload);

  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_R_ADD_HASH_BUF,"xxLbxxd",ikemesg,payload,"PROTO_IKE_PAYLOAD",payload->payload_id,ctx,pkt_for_hash,ikemesg->tx_mesg_len);

  if( pld_id == RHP_PROTO_IKEV1_PAYLOAD_N ){

		err = payload->ext_serialize(payload,pkt_for_hash);
		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV1_QUICK_R_ADD_HASH_BUF_ERR,"xxLbxE",ikemesg,payload,"PROTO_IKE_PAYLOAD",payload->payload_id,ctx,err);
			return err;
		}
  }

  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_R_ADD_HASH_BUF_RTRN,"xxxd",ikemesg,payload,pkt_for_hash,ikemesg->tx_mesg_len);
	return 0;
}

static int _rhp_ikev1_new_pkt_quick_r_4_commit(rhp_vpn* vpn,
		rhp_ikesa* ikesa,rhp_childsa* childsa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
  rhp_ikev2_payload* n_ikepayload;
  u32 tx_mesg_id = rx_ikemesg->get_mesg_id(rx_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_QUICK_R_4_COMMIT,"xxk",vpn,ikesa,tx_mesg_id);


	tx_ikemesg->set_mesg_id(tx_ikemesg,tx_mesg_id);

	tx_ikemesg->tx_flag |= RHP_IKEV2_SEND_REQ_FLAG_V1_COMMIT_BIT;


	{
		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_N,&n_ikepayload) ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		tx_ikemesg->put_payload(tx_ikemesg,n_ikepayload);

		n_ikepayload->ext.n->set_protocol_id(n_ikepayload,RHP_PROTO_IKEV1_PROP_PROTO_ID_ESP);

		n_ikepayload->ext.n->set_message_type(n_ikepayload,RHP_PROTO_IKEV1_N_ST_CONNECTED);

		n_ikepayload->ext.n->set_spi(n_ikepayload,childsa->spi_outb);
	}


	if( rhp_ikev1_tx_info_mesg_hash_add(vpn,ikesa,
				tx_ikemesg,_rhp_ikev1_quick_r_add_hash_buf) ){
		RHP_BUG("");
		err = -EINVAL;
    goto error;
	}


  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_QUICK_R_4_COMMIT_RTRN,"xxx",vpn,ikesa,tx_ikemesg);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_QUICK_R_4_COMMIT_ERR,"xxE",vpn,ikesa,err);
	return err;
}


void rhp_ikev1_quick_i_new_sa_tx_comp_cb(rhp_vpn* vpn,rhp_ikesa* tx_ikesa,
		rhp_ikev2_mesg* tx_ikemesg,rhp_packet* serialized_pkt)
{
  rhp_childsa* childsa = NULL;
  u32 message_id = tx_ikemesg->get_mesg_id(tx_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_I_NEW_SA_TX_COMP_CB,"xxxxxkdGG",vpn,tx_ikesa,tx_ikemesg,tx_ikemesg->rx_pkt,serialized_pkt,message_id,tx_ikesa->side,tx_ikesa->init_spi,tx_ikesa->resp_spi);

  childsa = vpn->childsa_get(vpn,RHP_DIR_INBOUND,tx_ikemesg->childsa_spi_inb);
  if( childsa ){

  	childsa->parent_ikesa.side = tx_ikesa->side;

  	memcpy(childsa->parent_ikesa.init_spi,tx_ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
  	memcpy(childsa->parent_ikesa.resp_spi,tx_ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);

  	childsa->gen_message_id = message_id;

  }else{

  	RHP_TRC(0,RHPTRCID_IKEV1_QUICK_I_NEW_SA_TX_COMP_CB_CHILDSA_NOT_FOUND,"xxxx",vpn,tx_ikesa,tx_ikemesg,childsa);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_I_NEW_SA_TX_COMP_CB_RTRN,"xxxx",vpn,tx_ikesa,tx_ikemesg,childsa);
  return;
}

static int _rhp_ikev1_quick_i_create_new_sa(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
  rhp_childsa* childsa = NULL;
  rhp_vpn_realm* rlm = vpn->rlm;
  int af_flag = 0;

  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_I_CREATE_NEW_SA,"xxxxd",vpn,ikesa,rx_ikemesg,rlm->encap_mode_c,vpn->peer_is_rockhopper);

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
  	err = -EINVAL;
    RHP_TRC(0,RHPTRCID_IKEV1_QUICK_I_CREATE_NEW_SA_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,rx_ikemesg,rlm);
  	goto error;
  }

  {
  	rhp_childsa* cur_childsa = vpn->childsa_list_head;
  	while( cur_childsa ){

      RHP_TRC(0,RHPTRCID_IKEV1_QUICK_I_CREATE_NEW_SA_CUR_IPSECSA,"xxxxxLdLd",vpn,ikesa,rx_ikemesg,rlm,cur_childsa,"CHILDSA_STAT",cur_childsa->state,"AF",cur_childsa->v1.addr_family);

  		if( cur_childsa->state == RHP_IPSECSA_STAT_V1_1ST_SENT_I 		||
  				cur_childsa->state == RHP_IPSECSA_STAT_V1_WAIT_COMMIT_I ||
  				cur_childsa->state == RHP_IPSECSA_STAT_V1_2ND_SENT_R 		||
  				cur_childsa->state == RHP_IPSECSA_STAT_V1_MATURE ){

  			if( cur_childsa->v1.addr_family == AF_INET ){
  				af_flag |= 0x1;
  			}else if( cur_childsa->v1.addr_family == AF_INET6 ){
  				af_flag |= 0x2;
  			}
  		}

  		cur_childsa = cur_childsa->next_vpn_list;
  	}
  }

  if( af_flag == 0x1 ){
  	af_flag = AF_INET6;
  }else if( af_flag == 0x2 ){
  	af_flag = AF_INET;
  }else if( af_flag == 0x3 ){ // IPsec SA(s) already created.
    RHP_TRC(0,RHPTRCID_IKEV1_QUICK_I_CREATE_NEW_SA_NO_VALID_AF_FOUND,"xxxxdd",vpn,ikesa,rx_ikemesg,rlm,af_flag,rhp_gcfg_ipv6_disabled);
  	err = 0;
		goto error;
  }else{
  	af_flag = AF_UNSPEC;
  }

  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_I_CREATE_NEW_SA_AF_FLAG,"xxxxLd",vpn,ikesa,rx_ikemesg,rlm,"AF",af_flag);


  RHP_LOCK(&(rlm->lock));

  {
  	rhp_ip_addr_list* itnl_addr;

  	if( rlm->internal_ifc == NULL ){
  		RHP_BUG("");
  		err = -EINVAL;
  		goto error_l;
  	}

  	if( rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_NONE ){
  		itnl_addr = rlm->internal_ifc->bridge_addrs;
  	}else{
  		itnl_addr = rlm->internal_ifc->addrs;
  	}

  	while( itnl_addr ){

      RHP_TRC(0,RHPTRCID_IKEV1_QUICK_I_CREATE_NEW_SA_ITNL_IF,"xxxxdxLdLdx",vpn,ikesa,rx_ikemesg,rlm,rlm->internal_ifc->addrs_type,itnl_addr,"AF",af_flag,"AF",itnl_addr->ip_addr.addr_family,itnl_addr->next);
      rhp_ip_addr_dump("itnl_addr->ip_addr",&(itnl_addr->ip_addr));

  		if( (af_flag == AF_UNSPEC || af_flag == AF_INET) &&
  				itnl_addr->ip_addr.addr_family == AF_INET ){

  			af_flag = AF_INET;
  			break;

  		}else if( (af_flag == AF_UNSPEC || af_flag == AF_INET6) &&
  							itnl_addr->ip_addr.addr_family == AF_INET6 &&
  							!rhp_ipv6_is_linklocal(itnl_addr->ip_addr.addr.v6) ){

  			af_flag = AF_INET6;
  			break;
  		}

  		itnl_addr = itnl_addr->next;
  	}

  	if( itnl_addr == NULL ){
      RHP_TRC(0,RHPTRCID_IKEV1_QUICK_I_CREATE_NEW_SA_NO_ITNL_IF,"xxxxd",vpn,ikesa,rx_ikemesg,rlm,rlm->internal_ifc->addrs_type);
  		err = 0;
  		goto error_l;
  	}
  }


  if( (af_flag != AF_INET && af_flag != AF_INET6)  ||
  		(rhp_gcfg_ipv6_disabled && af_flag == AF_INET6) ){

    RHP_TRC(0,RHPTRCID_IKEV1_QUICK_I_CREATE_NEW_SA_NO_VALID_AF_FOUND_2,"xxxxLdd",vpn,ikesa,rx_ikemesg,rlm,"AF",af_flag,rhp_gcfg_ipv6_disabled);
  	err = 0;
		goto error_l;
  }


  childsa = rhp_childsa_alloc(RHP_IKE_INITIATOR,1);
  if( childsa == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error_l;
  }

  childsa->gen_type = RHP_CHILDSA_GEN_IKEV1;

  childsa->v1.addr_family = af_flag;

  err = childsa->generate_inb_spi(childsa);
  if( err ){
    RHP_BUG("");
    goto error_l;
  }


  childsa->timers = rhp_ipsecsa_v1_new_timers(childsa->spi_inb,childsa->spi_outb);
  if( childsa->timers == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error_l;
  }

	if( (rlm->encap_mode_c & RHP_VPN_ENCAP_ETHERIP) && vpn->peer_is_rockhopper ){

		childsa->ipsec_mode = RHP_CHILDSA_MODE_TRANSPORT;

	}else if( rlm->encap_mode_c & RHP_VPN_ENCAP_IPIP ){

		childsa->ipsec_mode = RHP_CHILDSA_MODE_TUNNEL;

	}else if( rlm->encap_mode_c & RHP_VPN_ENCAP_GRE ){

		childsa->ipsec_mode = RHP_CHILDSA_MODE_TRANSPORT;

	}else{

		RHP_BUG("0x%x",rlm->encap_mode_c);
		goto error_l;
	}


	err = rhp_ikev1_new_pkt_quick_i_1(vpn,rlm,ikesa,childsa,af_flag,tx_ikemesg);
	if( err ){
		RHP_BUG("%d",err);
		goto error_l;
	}

  tx_ikemesg->v1_start_retx_timer = 1;


  rhp_childsa_set_state(childsa,RHP_IPSECSA_STAT_V1_1ST_SENT_I);

  err = rhp_vpn_inb_childsa_put(vpn,childsa->spi_inb);
  if( err ){
    RHP_BUG("");
    goto error_l;
  }

  vpn->childsa_put(vpn,childsa);

  childsa->timers->start_lifetime_timer(vpn,childsa,(time_t)rlm->childsa.lifetime_larval,1);

	RHP_UNLOCK(&(rlm->lock));


	rhp_ikev1_p2_session_tx_put(ikesa,tx_ikemesg->get_mesg_id(tx_ikemesg),RHP_PROTO_IKEV1_EXCHG_QUICK,0,0);


	tx_ikemesg->childsa_spi_inb = childsa->spi_inb;
	tx_ikemesg->packet_serialized = rhp_ikev1_quick_i_new_sa_tx_comp_cb;

  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_I_CREATE_NEW_SA_RTRN,"xxx",vpn,ikesa,tx_ikemesg);
  return 0;

error_l:
	RHP_UNLOCK(&(rlm->lock));
error:

	if( childsa ){
    rhp_childsa_destroy(vpn,childsa);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_I_CREATE_NEW_SA_ERR,"xxxE",vpn,ikesa,tx_ikemesg,err);
  return err;
}


struct _rhp_quick_new_sa_task_ctx {

	rhp_vpn_ref* vpn_ref;

	int ikesa_side;
	u8 ikesa_spi[RHP_PROTO_IKE_SPI_SIZE];

	rhp_ikev2_mesg* rx_ikemesg;
};
typedef struct _rhp_quick_new_sa_task_ctx	rhp_quick_new_sa_task_ctx;

static void _rhp_quick_new_sa_task_ctx_free(rhp_quick_new_sa_task_ctx* new_sa_ctx)
{
  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_NEW_SA_TASK_FREE,"xxxdG",new_sa_ctx,RHP_VPN_REF(new_sa_ctx->vpn_ref),new_sa_ctx->rx_ikemesg,new_sa_ctx->ikesa_side,new_sa_ctx->ikesa_spi);

  if( new_sa_ctx->vpn_ref ){
		rhp_vpn_unhold(new_sa_ctx->vpn_ref);
	}

	if( new_sa_ctx->rx_ikemesg ){
		rhp_ikev2_unhold_mesg(new_sa_ctx->rx_ikemesg);
	}

	_rhp_free(new_sa_ctx);

	return;
}

void _rhp_ikev1_quick_i_create_new_sa_task(int worker_index,void *ctx)
{
	int err = -EINVAL;
	rhp_quick_new_sa_task_ctx* new_sa_ctx = (rhp_quick_new_sa_task_ctx*)ctx;
	rhp_vpn* vpn = RHP_VPN_REF(new_sa_ctx->vpn_ref);
	rhp_ikesa* ikesa;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  u32 tx_mesg_id;

  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_I_CREATED_NEW_SA_TASK,"xxxdG",new_sa_ctx,RHP_VPN_REF(new_sa_ctx->vpn_ref),new_sa_ctx->rx_ikemesg,new_sa_ctx->ikesa_side,new_sa_ctx->ikesa_spi);

	RHP_LOCK(&(vpn->lock));

	if( !_rhp_atomic_read(&(vpn->is_active)) ){
	  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_I_CREATED_NEW_SA_TASK_VPN_NOT_ACTIVE,"xxx",new_sa_ctx,vpn,new_sa_ctx->rx_ikemesg);
		err = -EINVAL;
		goto error;
	}

	ikesa = vpn->ikesa_get(vpn,new_sa_ctx->ikesa_side,new_sa_ctx->ikesa_spi);
	if( ikesa == NULL ){
	  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_I_CREATED_NEW_SA_TASK_VPN_NO_IKESA,"xxx",new_sa_ctx,vpn,new_sa_ctx->rx_ikemesg);
		err = -ENOENT;
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


  err = _rhp_ikev1_quick_i_create_new_sa(vpn,ikesa,new_sa_ctx->rx_ikemesg,tx_ikemesg);
  if( err ){
	  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_I_CREATED_NEW_SA_TASK_VPN_SETUP_SA_ERR,"xxx",new_sa_ctx,vpn,new_sa_ctx->rx_ikemesg);
  	goto error;
  }

  if( tx_ikemesg->activated ){

  	rhp_ikev1_send_mesg(vpn,NULL,tx_ikemesg,RHP_IKEV1_MESG_HANDLER_P2_QUICK);
  }

error:
	RHP_UNLOCK(&(vpn->lock));

	_rhp_quick_new_sa_task_ctx_free(new_sa_ctx);

	if( tx_ikemesg ){
		rhp_ikev2_unhold_mesg(tx_ikemesg);
	}

  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_I_CREATED_NEW_SA_TASK_RTRN,"xxxE",new_sa_ctx,vpn,tx_ikemesg,err);
	return;
}

static int _rhp_ikev1_quick_i_invoke_create_new_sa_task(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg)
{
	int err = -EINVAL;
	rhp_quick_new_sa_task_ctx* new_sa_ctx = NULL;

	new_sa_ctx = (rhp_quick_new_sa_task_ctx*)_rhp_malloc(sizeof(rhp_quick_new_sa_task_ctx));
	if( new_sa_ctx == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	memset(new_sa_ctx,0,sizeof(rhp_quick_new_sa_task_ctx));

	new_sa_ctx->vpn_ref = rhp_vpn_hold_ref(vpn);

	new_sa_ctx->ikesa_side = ikesa->side;
	memcpy(new_sa_ctx->ikesa_spi,ikesa->get_my_spi(ikesa),RHP_PROTO_IKE_SPI_SIZE);

	new_sa_ctx->rx_ikemesg = rx_ikemesg;
	rhp_ikev2_hold_mesg(rx_ikemesg);

	err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_2,_rhp_ikev1_quick_i_create_new_sa_task,new_sa_ctx);
	if( err ){
		RHP_BUG("%d",err);
		_rhp_quick_new_sa_task_ctx_free(new_sa_ctx);
	}

error:
	return err;
}


struct _rhp_ikev1_quick_hash_buf {

	int len;
	u8* buf;
};
typedef struct _rhp_ikev1_quick_hash_buf	rhp_ikev1_quick_hash_buf;

static int _rhp_ikev1_quick_1_srch_hash_buf(rhp_ikev2_mesg* ikemesg,
		int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
	rhp_ikev1_quick_hash_buf* hash_buf = (rhp_ikev1_quick_hash_buf*)ctx;

  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_1_SRCH_HASH_BUF,"xxLbxxpxd",ikemesg,payload,"PROTO_IKE_PAYLOAD",(payload ? payload->payload_id : 0),ctx,hash_buf,hash_buf->len,hash_buf->buf,(payload ? payload->payloadh : NULL),enum_end);

  if( enum_end ){

  	// payload is NULL.
    RHP_TRC(0,RHPTRCID_IKEV1_QUICK_1_SRCH_HASH_BUF_DATA,"xp",ikemesg,hash_buf->len,hash_buf->buf);

  }else{

  	u8 pld_id = payload->get_payload_id(payload);

    if( payload->payloadh == NULL ){
    	RHP_BUG("");
    	return -EINVAL;
    }

		if( pld_id != RHP_PROTO_IKEV1_PAYLOAD_HASH ){

	  	int pld_len = ntohs(payload->payloadh->len);
	  	u8* new_buf = (u8*)_rhp_malloc(hash_buf->len + pld_len);

	  	if( new_buf == NULL ){
	  		RHP_BUG("");
	    	return -ENOMEM;
	  	}

	  	memcpy(new_buf,hash_buf->buf,hash_buf->len);
	  	memcpy((new_buf + hash_buf->len),payload->payloadh,pld_len);

	    RHP_TRC(0,RHPTRCID_IKEV1_QUICK_1_SRCH_HASH_BUF_PART,"xxxpp",ikemesg,payload,hash_buf,(hash_buf->len + pld_len),new_buf,pld_len,(new_buf + hash_buf->len));

	  	_rhp_free(hash_buf->buf);

	  	hash_buf->buf = new_buf;
	  	hash_buf->len += pld_len;
		}
  }

  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_1_SRCH_HASH_BUF_RTRN,"xxx",ikemesg,payload,hash_buf);
	return 0;
}

static int _rhp_ikev1_quick_r_1_srch_hash_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_ikev1_hash_payload* hash_payload = (rhp_ikev1_hash_payload*)payload->ext.v1_hash;
  rhp_childsa_srch_plds_ctx* s_pld_ctx = (rhp_childsa_srch_plds_ctx*)ctx;
  rhp_ikev1_quick_hash_buf hash_buf;
  int rx_hash_len, hash_octets_len;
  u8 *rx_hash, *hash_octets = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_R_1_SRCH_HASH_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

  memset(&hash_buf,0,sizeof(rhp_ikev1_quick_hash_buf));

  if( hash_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV1_QUICK_R_1_SRCH_HASH_CB_DUP_ERR,"xxx",rx_ikemesg,payload,ctx);
    goto error;
  }

	hash_octets_len = s_pld_ctx->ikesa->prf->get_output_len(s_pld_ctx->ikesa->prf);

  rx_hash_len = hash_payload->get_hash_len(payload);
  rx_hash = hash_payload->get_hash(payload);

  if( rx_hash_len != hash_octets_len ||
  		rx_hash == NULL ){
    s_pld_ctx->notify_error = RHP_PROTO_IKEV1_N_ERR_INVALID_HASH_INFORMATION;
    RHP_TRC(0,RHPTRCID_IKEV1_QUICK_R_1_SRCH_HASH_CB_NO_HASH_VAL,"xxxddx",rx_ikemesg,payload,ctx,rx_hash_len,hash_octets_len,rx_hash);
    goto error;
  }


  hash_buf.len = sizeof(u32);
  hash_buf.buf = (u8*)_rhp_malloc(sizeof(u32));
  if( hash_buf.buf == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }
  *((u32*)hash_buf.buf) = htonl(rx_ikemesg->get_mesg_id(rx_ikemesg));

	err = rx_ikemesg->search_payloads(rx_ikemesg,1,NULL,NULL,
					_rhp_ikev1_quick_1_srch_hash_buf,&hash_buf);
	if( err && err != -ENOENT && err != RHP_STATUS_ENUM_OK  ){
		RHP_BUG("");
		goto error;
	}
	err = 0;


  hash_octets = (u8*)_rhp_malloc(hash_octets_len);
  if( hash_octets == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_R_1_SRCH_HASH_CB_HASH_DATA,"xxxpp",rx_ikemesg,payload,ctx,s_pld_ctx->ikesa->keys.v1.skeyid_a_len,s_pld_ctx->ikesa->keys.v1.skeyid_a,hash_buf.len,hash_buf.buf);

  if( s_pld_ctx->ikesa->prf->set_key(s_pld_ctx->ikesa->prf,
  			s_pld_ctx->ikesa->keys.v1.skeyid_a,s_pld_ctx->ikesa->keys.v1.skeyid_a_len) ){
    RHP_TRC(0,RHPTRCID_IKEV1_QUICK_R_1_SRCH_HASH_CB_PRF_SET_KEY_ERR,"xx",s_pld_ctx->ikesa,s_pld_ctx->ikesa->prf);
    err = -EINVAL;
    goto error;
  }

  if( s_pld_ctx->ikesa->prf->compute(s_pld_ctx->ikesa->prf,
  			hash_buf.buf,hash_buf.len,hash_octets,hash_octets_len) ){
    RHP_TRC(0,RHPTRCID_IKEV1_QUICK_R_1_SRCH_HASH_CB_PRF_COMPUTE_ERR,"xx",s_pld_ctx->ikesa,s_pld_ctx->ikesa->prf);
    err = -EINVAL;
    goto error;
  }

  if( memcmp(rx_hash,hash_octets,hash_octets_len) ){
    RHP_TRC(0,RHPTRCID_IKEV1_QUICK_R_1_SRCH_HASH_CB_NOT_MACHED,"xxxxppE",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg,hash_payload,rx_hash_len,rx_hash,hash_octets_len,hash_octets,err);
    err = RHP_STATUS_INVALID_MSG;
    s_pld_ctx->notify_error = RHP_PROTO_IKEV1_N_ERR_INVALID_HASH_INFORMATION;
    goto error;
  }

  s_pld_ctx->v1_hash_payload = payload;

  err = RHP_STATUS_ENUM_OK;

error:
	if( hash_octets ){
		_rhp_free(hash_octets);
	}
	if( hash_buf.buf ){
		_rhp_free(hash_buf.buf);
	}
  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_R_1_SRCH_HASH_CB_RTRN,"xxxE",rx_ikemesg,payload,ctx,err);
  return err;
}

static int _rhp_ikev1_quick_srch_sa_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
  rhp_ikev1_sa_payload* sa_payload = (rhp_ikev1_sa_payload*)payload->ext.v1_sa;
  rhp_childsa_srch_plds_ctx* s_pld_ctx = (rhp_childsa_srch_plds_ctx*)ctx;
  rhp_res_ikev1_sa_proposal* res_prop = &(s_pld_ctx->resolved_prop.v1);
  int pfs = (!res_prop->dh_group ? 0 : 1);

  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_SRCH_SA_CB,"xdxxdddu",rx_ikemesg,enum_end,payload,ctx,res_prop->encap_mode,res_prop->dh_group,pfs,res_prop->life_time);

  if( sa_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV1_QUICK_SRCH_SA_CB_DUP_ERR,"xxx",rx_ikemesg,payload,ctx);
    goto error;
  }

  err = sa_payload->get_matched_ipsecsa_prop(payload,res_prop);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV1_QUICK_SRCH_SA_CB_NOT_MACHED_PROP,"xxxxE",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg,sa_payload,err);
    s_pld_ctx->notify_error = RHP_PROTO_IKEV1_N_ERR_NO_PROPOSAL_CHOSEN;
    goto error;
  }

  if( (pfs && !res_prop->dh_group) || (!pfs && res_prop->dh_group) ){
    RHP_TRC(0,RHPTRCID_IKEV1_QUICK_SRCH_SA_CB_PFS_NOT_MACHED_PROP,"xxxxddE",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg,sa_payload,pfs,res_prop->dh_group,err);
    s_pld_ctx->notify_error = RHP_PROTO_IKEV1_N_ERR_NO_PROPOSAL_CHOSEN;
    goto error;
  }

  s_pld_ctx->sa_payload = payload;


  if( res_prop->encap_mode == RHP_PROTO_IKEV1_P2_ATTR_ENCAP_MODE_TRANSPORT ||
  		res_prop->encap_mode == RHP_PROTO_IKEV1_P2_ATTR_ENCAP_MODE_UDP_TRANSPORT ){

  	s_pld_ctx->use_trans_port_mode = 1;
  }

  if( res_prop->life_time < (unsigned long)rhp_gcfg_ikev1_ipsecsa_min_lifetime ){

  	res_prop->life_time = (unsigned long)rhp_gcfg_ikev1_ipsecsa_min_lifetime;

    RHP_TRC(0,RHPTRCID_IKEV1_QUICK_SRCH_SA_CB_MIN_LIFETIME_APPLIED,"xxxxud",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg,sa_payload,res_prop->life_time,rhp_gcfg_ikev1_ipsecsa_min_lifetime);
  }

  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_SRCH_SA_CB_RTRN,"xxxduE",rx_ikemesg,payload,ctx,s_pld_ctx->use_trans_port_mode,res_prop->life_time,err);
  return err;
}

static int _rhp_ikev1_quick_srch_n_info_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_childsa_srch_plds_ctx* s_pld_ctx = (rhp_childsa_srch_plds_ctx*)ctx;
  rhp_ikev2_n_payload* n_payload = (rhp_ikev2_n_payload*)payload->ext.n;
  u16 notify_mesg_type;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_SRCH_N_INFO_CB,"xdxxx",rx_ikemesg,enum_end,payload,n_payload,ctx);

  if( n_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  notify_mesg_type = n_payload->get_message_type(payload);

  if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_ETHERIP_ENCAP ){

  	s_pld_ctx->use_etherip_encap = 1;

  }else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_GRE_ENCAP ){

  	s_pld_ctx->use_gre_encap = 1;

  }else if( notify_mesg_type == RHP_PROTO_IKEV1_N_ST_CONNECTED ){

  	s_pld_ctx->v1_connected = 1;
  }


  s_pld_ctx->dup_flag++;
  err = 0;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_SRCH_N_INFO_CB_RTRN,"xxxxwbbbbbE",rx_ikemesg,payload,n_payload,ctx,notify_mesg_type,s_pld_ctx->use_trans_port_mode,s_pld_ctx->esp_tfc_padding_not_supported,s_pld_ctx->use_etherip_encap,s_pld_ctx->use_gre_encap,s_pld_ctx->v1_connected,err);
  return err;
}

static int _rhp_ikev1_quick_r_srch_ts_ids_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_childsa_srch_plds_ctx* s_pld_ctx = (rhp_childsa_srch_plds_ctx*)ctx;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_SRCH_TS_IDS_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

  if( enum_end ){

  	if( s_pld_ctx->ts_i_payload == NULL || s_pld_ctx->ts_r_payload == NULL ){

			RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_SRCH_TS_IDS_CB_NO_TS,"xxxE",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg,err);

			s_pld_ctx->notify_error = RHP_PROTO_IKEV1_N_ERR_INVALID_ID_INFORMATION;
			err = RHP_STATUS_SELECTOR_NOT_MATCHED;
			goto error;
  	}

  }else{

  	int gre_encap
  		= (s_pld_ctx->vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_GRE &&
  			 s_pld_ctx->rlm->childsa.gre_auto_gen_ts) ? 1 : 0;

  	rhp_ikev1_id_payload* id_payload = (rhp_ikev1_id_payload*)payload->ext.v1_id;
    if( id_payload == NULL ){
    	RHP_BUG("");
    	return -EINVAL;
    }


    s_pld_ctx->dup_flag++;

    if( s_pld_ctx->dup_flag > 2 ){
      err = RHP_STATUS_INVALID_MSG;
      RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_SRCH_TS_IDS_CB_ERR,"xx",rx_ikemesg,ctx);
      goto error;
    }


  	if( s_pld_ctx->ts_i_payload == NULL ){

			err = id_payload->get_matched_ts(payload,RHP_IKE_INITIATOR,s_pld_ctx->rlm,s_pld_ctx->vpn->cfg_peer,
					(gre_encap ? &(s_pld_ctx->vpn->peer_addr) : NULL));
			if( err ){

				RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_SRCH_TS_IDS_CB_INIT_NOT_MATCHED,"xxxxE",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg,id_payload,err);

				s_pld_ctx->notify_error = RHP_PROTO_IKEV1_N_ERR_INVALID_ID_INFORMATION;
				err = RHP_STATUS_SELECTOR_NOT_MATCHED;
				goto error;
			}

			s_pld_ctx->ts_i_payload = payload;

		}else if( s_pld_ctx->ts_r_payload == NULL ){

			rhp_ip_addr gre_local_addr;

			memset(&gre_local_addr,0,sizeof(rhp_ip_addr));

  		if( gre_encap ){

  			gre_local_addr.addr_family = s_pld_ctx->vpn->local.if_info.addr_family;
  			memcpy(gre_local_addr.addr.raw,s_pld_ctx->vpn->local.if_info.addr.raw,16);
  		}

			err = id_payload->get_matched_ts(payload,RHP_IKE_RESPONDER,s_pld_ctx->rlm,s_pld_ctx->vpn->cfg_peer,
							(gre_local_addr.addr_family == AF_INET || gre_local_addr.addr_family == AF_INET6 ? &gre_local_addr : NULL));
			if( err ){

				RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_SRCH_TS_IDS_CB_RESP_NOT_MATCHED,"xxxxE",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg,id_payload,err);

				s_pld_ctx->notify_error = RHP_PROTO_IKEV1_N_ERR_INVALID_ID_INFORMATION;
				err = RHP_STATUS_SELECTOR_NOT_MATCHED;
				goto error;
			}

			s_pld_ctx->ts_r_payload = payload;
		}
	}
  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_SRCH_TS_IDS_CB_RTRN,"xxxxxE",rx_ikemesg,payload,ctx,s_pld_ctx->ts_i_payload,s_pld_ctx->ts_r_payload,err);
  return err;
}

static int _rhp_ikev1_quick_srch_nat_oas_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_childsa_srch_plds_ctx* s_pld_ctx = (rhp_childsa_srch_plds_ctx*)ctx;
	rhp_ikev1_nat_oa_payload* nat_oa_payload;
	u8* addr;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_SRCH_NAT_OAS_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

  {
  	nat_oa_payload = (rhp_ikev1_nat_oa_payload*)payload->ext.v1_nat_oa;
    if( nat_oa_payload == NULL ){
    	RHP_BUG("");
    	return -EINVAL;
    }


    s_pld_ctx->dup_flag++;

    if( s_pld_ctx->dup_flag > 2 ){
      err = RHP_STATUS_INVALID_MSG;
      RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_SRCH_NAT_OAS_CB_ERR,"xx",rx_ikemesg,ctx);
      goto error;
    }


  	if( s_pld_ctx->v1_nat_oa_i.addr_family == AF_UNSPEC ){

  		s_pld_ctx->v1_nat_oa_i.addr_family = nat_oa_payload->get_orig_addr_family(payload);

  		addr = nat_oa_payload->get_orig_addr(payload);

			if( (s_pld_ctx->v1_nat_oa_i.addr_family != AF_INET &&
					 s_pld_ctx->v1_nat_oa_i.addr_family != AF_INET6) ||
					addr == NULL ){

				s_pld_ctx->v1_nat_oa_i.addr_family = AF_UNSPEC;

				RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_SRCH_NAT_OAS_CB_INIT_NOT_MATCHED,"xxxxE",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg,nat_oa_payload,err);

				s_pld_ctx->notify_error = RHP_PROTO_IKEV1_N_ERR_PAYLOAD_MALFORMED;
				err = -EINVAL;
				goto error;
			}

			if( s_pld_ctx->v1_nat_oa_i.addr_family == AF_INET ){
				memcpy(s_pld_ctx->v1_nat_oa_i.addr.raw,addr,4);
			}else if( s_pld_ctx->v1_nat_oa_i.addr_family == AF_INET6 ){
				memcpy(s_pld_ctx->v1_nat_oa_i.addr.raw,addr,16);
			}

		}else if( s_pld_ctx->v1_nat_oa_r.addr_family == AF_UNSPEC ){

  		s_pld_ctx->v1_nat_oa_r.addr_family = nat_oa_payload->get_orig_addr_family(payload);

  		addr = nat_oa_payload->get_orig_addr(payload);

			if( (s_pld_ctx->v1_nat_oa_r.addr_family != AF_INET &&
					 s_pld_ctx->v1_nat_oa_r.addr_family != AF_INET6) ||
					addr == NULL ){

				s_pld_ctx->v1_nat_oa_r.addr_family = AF_UNSPEC;

				RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_SRCH_NAT_OAS_CB_INIT_NOT_MATCHED,"xxxxE",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg,nat_oa_payload,err);

				s_pld_ctx->notify_error = RHP_PROTO_IKEV1_N_ERR_PAYLOAD_MALFORMED;
				err = -EINVAL;
				goto error;
			}

			if( s_pld_ctx->v1_nat_oa_r.addr_family == AF_INET ){
				memcpy(s_pld_ctx->v1_nat_oa_r.addr.raw,addr,4);
			}else if( s_pld_ctx->v1_nat_oa_r.addr_family == AF_INET6 ){
				memcpy(s_pld_ctx->v1_nat_oa_r.addr.raw,addr,16);
			}
		}
	}
  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_SRCH_NAT_OAS_CB_RTRN,"xxxxxE",rx_ikemesg,payload,ctx,s_pld_ctx->ts_i_payload,s_pld_ctx->ts_r_payload,err);
  return err;
}


static int _rhp_ikev1_quick_srch_nonce_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_childsa_srch_plds_ctx* s_pld_ctx = (rhp_childsa_srch_plds_ctx*)ctx;
  rhp_ikev2_nir_payload* nir_payload = (rhp_ikev2_nir_payload*)payload->ext.sa;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_SRCH_NONCE_CB,"xdxxx",rx_ikemesg,enum_end,payload,nir_payload,ctx);

  if( nir_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
  	RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_SRCH_NONCE_CB_DUP_ERR,"xxxx",rx_ikemesg,payload,nir_payload,ctx);
  	return RHP_STATUS_INVALID_MSG;
  }

  s_pld_ctx->nonce_len = nir_payload->get_nonce_len(payload);
  if( s_pld_ctx->nonce_len < 0 ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_SRCH_NONCE_CB_PLD_BAD_NONCE_LEN,"xxd",s_pld_ctx->vpn,rx_ikemesg,s_pld_ctx->nonce_len);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  if( s_pld_ctx->nonce_len < rhp_gcfg_ikev1_min_nonce_size ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_SRCH_NONCE_CB_PLD_TOO_SHORT_NONCE_LEN,"xxdd",s_pld_ctx->vpn,rx_ikemesg,s_pld_ctx->nonce_len,rhp_gcfg_ikev1_min_nonce_size);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  s_pld_ctx->nonce = nir_payload->get_nonce(payload);
  if( s_pld_ctx->nonce == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_SRCH_NONCE_CB_PLD_NO_NONCE,"xx",s_pld_ctx->vpn,rx_ikemesg);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  s_pld_ctx->nir_payload = payload;
  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_SRCH_NONCE_CB_RTRN,"xxxxE",rx_ikemesg,payload,nir_payload,ctx,err);
  return err;
}

static int _rhp_ikev1_quick_srch_ke_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_childsa_srch_plds_ctx* s_pld_ctx = (rhp_childsa_srch_plds_ctx*)ctx;
  rhp_ikev1_ke_payload* ke_payload = (rhp_ikev1_ke_payload*)payload->ext.v1_ke;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_SRCH_KE_CB,"xdxxx",rx_ikemesg,enum_end,payload,ke_payload,ctx);

  if( ke_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
  	RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_SRCH_KE_CB_DUP_ERR,"xxxx",rx_ikemesg,payload,ke_payload,ctx);
  	return RHP_STATUS_INVALID_MSG;
  }

  s_pld_ctx->dhgrp = s_pld_ctx->resolved_prop.v1.dh_group;
	s_pld_ctx->peer_dh_pub_key_len = ke_payload->get_key_len(payload);
	s_pld_ctx->peer_dh_pub_key = ke_payload->get_key(payload);

	if( s_pld_ctx->peer_dh_pub_key_len < 0 || s_pld_ctx->peer_dh_pub_key == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_SRCH_KE_CB_PLD_BAD_DH_PUB_KEY,"xxdx",s_pld_ctx->vpn,rx_ikemesg,s_pld_ctx->peer_dh_pub_key_len,s_pld_ctx->peer_dh_pub_key);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
	}

  s_pld_ctx->ke_payload = payload;
  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_SRCH_KE_CB_RTRN,"xxxxE",rx_ikemesg,payload,ke_payload,ctx,err);
  return err;
}

static int _rhp_ikev1_rx_quick_sec_params_r(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_childsa* childsa,
		rhp_vpn_realm* rlm,rhp_childsa_srch_plds_ctx* s_pld_ctx)
{
	int err = -EINVAL;
	int integ_id, encr_id;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_SEC_PARAMS_R,"xxxxxdd",vpn,ikesa,childsa,rlm,s_pld_ctx,s_pld_ctx->resolved_prop.v1.auth_alg,s_pld_ctx->resolved_prop.v1.trans_id);

	integ_id = rhp_ikev1_p2_integ_alg(s_pld_ctx->resolved_prop.v1.auth_alg);
	encr_id = rhp_ikev1_p2_encr_alg(s_pld_ctx->resolved_prop.v1.trans_id);

	if( integ_id < 0 || encr_id < 0 ){
		RHP_BUG("");
		return -EINVAL;
	}

	childsa->v1.trans_id = s_pld_ctx->resolved_prop.v1.trans_id;
	childsa->v1.auth_id = s_pld_ctx->resolved_prop.v1.auth_alg;


	childsa->integ_inb = rhp_crypto_integ_alloc(integ_id);
	if( childsa->integ_inb == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	childsa->integ_outb = rhp_crypto_integ_alloc(integ_id);
	if( childsa->integ_outb == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	childsa->encr = rhp_crypto_encr_alloc(encr_id,s_pld_ctx->resolved_prop.v1.key_bits_len);
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


	{
		int nonce_i_len = s_pld_ctx->nir_payload->ext.nir->get_nonce_len(s_pld_ctx->nir_payload);
		u8* nonce_i = s_pld_ctx->nir_payload->ext.nir->get_nonce(s_pld_ctx->nir_payload);

		childsa->v1.nonce_i = rhp_crypto_nonce_alloc();
		if( childsa->v1.nonce_i == NULL ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		childsa->v1.nonce_r = rhp_crypto_nonce_alloc();
		if( childsa->v1.nonce_r == NULL ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		err = childsa->v1.nonce_i->set_nonce(childsa->v1.nonce_i,nonce_i,nonce_i_len);
		if( err ){
			RHP_BUG("");
			goto error;
		}

		err = childsa->v1.nonce_r->generate_nonce(childsa->v1.nonce_r,rhp_gcfg_nonce_size);
		if( err ){
			RHP_BUG("");
			goto error;
		}
	}


	if( s_pld_ctx->resolved_prop.v1.dh_group ){

		int peer_pub_key_len = s_pld_ctx->ke_payload->ext.v1_ke->get_key_len(s_pld_ctx->ke_payload);
		u8* peer_pub_key = s_pld_ctx->ke_payload->ext.v1_ke->get_key(s_pld_ctx->ke_payload);

		childsa->v1.dh = rhp_crypto_dh_alloc(s_pld_ctx->resolved_prop.v1.dh_group);
		if( childsa->v1.dh == NULL ){
			err = -EINVAL;
			RHP_BUG("");
			goto error;
		}

		if( childsa->v1.dh->generate_key(childsa->v1.dh) ){
			err = -EINVAL;
			RHP_BUG("");
			goto error;
		}

		if( childsa->v1.dh->set_peer_pub_key(childsa->v1.dh,peer_pub_key,peer_pub_key_len) ){
			err = -EINVAL;
			RHP_BUG("");
			goto error;
		}

		if( childsa->v1.dh->compute_key(childsa->v1.dh) ){
			err = -EINVAL;
			RHP_BUG("");
			goto error;
		}
	}

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_SEC_PARAMS_R_RTRN,"xxxxx",vpn,ikesa,childsa,rlm,s_pld_ctx);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_SEC_PARAMS_R_ERR,"xxxxxE",vpn,ikesa,childsa,rlm,s_pld_ctx,err);
	return err;
}


extern int rhp_ikev2_rx_create_child_sa_req_encap_mode(rhp_vpn* vpn,rhp_vpn_realm* rlm,
		rhp_childsa_srch_plds_ctx* s_pld_ctx,int* encap_mode_c_r);

extern int rhp_ikev2_rx_create_child_sa_req_internal_net(rhp_vpn* vpn,rhp_childsa* childsa,rhp_vpn_realm* rlm,
		rhp_childsa_srch_plds_ctx* s_pld_ctx,int encap_mode_c);

static int _rhp_ikev1_quick_gen_nat_oa_ts(
		rhp_vpn* vpn,int side,
		rhp_childsa_srch_plds_ctx* s_pld_ctx,
		rhp_childsa_ts* csa_ts_i,rhp_childsa_ts* csa_ts_r,
		rhp_childsa_ts** csa_ts_i_gre_r,rhp_childsa_ts** csa_ts_r_gre_r)
{
	int err = -EINVAL;
	rhp_childsa_ts *csa_ts_i_gre = NULL,*csa_ts_r_gre = NULL;
	rhp_ip_addr local_addr;

	memset(&local_addr,0,sizeof(rhp_ip_addr));

	local_addr.addr_family = vpn->local.if_info.addr_family;
	memcpy(local_addr.addr.raw,vpn->local.if_info.addr.raw,16);


	csa_ts_i_gre = (rhp_childsa_ts*)_rhp_malloc(sizeof(rhp_childsa_ts));
	if( csa_ts_i_gre == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	csa_ts_r_gre = (rhp_childsa_ts*)_rhp_malloc(sizeof(rhp_childsa_ts));
	if( csa_ts_r_gre == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	memset(csa_ts_i_gre,0,sizeof(rhp_childsa_ts));
	memset(csa_ts_r_gre,0,sizeof(rhp_childsa_ts));
	csa_ts_i_gre->protocol = RHP_PROTO_IP_GRE;
	csa_ts_r_gre->protocol = RHP_PROTO_IP_GRE;
	csa_ts_i_gre->is_v1 = 1;
	csa_ts_r_gre->is_v1 = 1;
	csa_ts_i_gre->start_port = 0;
	csa_ts_r_gre->start_port = 0;
	csa_ts_i_gre->end_port = 0xFFFF;
	csa_ts_r_gre->end_port = 0xFFFF;

	if( side == RHP_IKE_RESPONDER ){

		if( !rhp_ip_addr_cmp_ip_only(&(s_pld_ctx->v1_nat_oa_i),&(vpn->peer_addr)) ){

			memcpy(&(csa_ts_i_gre->start_addr),&(s_pld_ctx->v1_nat_oa_i),sizeof(rhp_ip_addr));
			memcpy(&(csa_ts_i_gre->end_addr),&(s_pld_ctx->v1_nat_oa_i),sizeof(rhp_ip_addr));

		}else{

			memcpy(&(csa_ts_i_gre->start_addr),&(vpn->peer_addr),sizeof(rhp_ip_addr));
			memcpy(&(csa_ts_i_gre->end_addr),&(vpn->peer_addr),sizeof(rhp_ip_addr));
		}

		if( !rhp_ip_addr_cmp_ip_only(&(s_pld_ctx->v1_nat_oa_r),&local_addr) ){

			memcpy(&(csa_ts_r_gre->start_addr),&(s_pld_ctx->v1_nat_oa_r),sizeof(rhp_ip_addr));
			memcpy(&(csa_ts_r_gre->end_addr),&(s_pld_ctx->v1_nat_oa_r),sizeof(rhp_ip_addr));

		}else{

			memcpy(&(csa_ts_r_gre->start_addr),&local_addr,sizeof(rhp_ip_addr));
			memcpy(&(csa_ts_r_gre->end_addr),&local_addr,sizeof(rhp_ip_addr));
		}

	}else{ // Initiator

		if( !rhp_ip_addr_cmp_ip_only(&(s_pld_ctx->v1_nat_oa_r),&(vpn->peer_addr)) ){

			memcpy(&(csa_ts_r_gre->start_addr),&(s_pld_ctx->v1_nat_oa_r),sizeof(rhp_ip_addr));
			memcpy(&(csa_ts_r_gre->end_addr),&(s_pld_ctx->v1_nat_oa_r),sizeof(rhp_ip_addr));

		}else{

			memcpy(&(csa_ts_r_gre->start_addr),&(vpn->peer_addr),sizeof(rhp_ip_addr));
			memcpy(&(csa_ts_r_gre->end_addr),&(vpn->peer_addr),sizeof(rhp_ip_addr));
		}

		if( !rhp_ip_addr_cmp_ip_only(&(s_pld_ctx->v1_nat_oa_i),&local_addr) ){

			memcpy(&(csa_ts_i_gre->start_addr),&(s_pld_ctx->v1_nat_oa_i),sizeof(rhp_ip_addr));
			memcpy(&(csa_ts_i_gre->end_addr),&(s_pld_ctx->v1_nat_oa_i),sizeof(rhp_ip_addr));

		}else{

			memcpy(&(csa_ts_i_gre->start_addr),&local_addr,sizeof(rhp_ip_addr));
			memcpy(&(csa_ts_i_gre->end_addr),&local_addr,sizeof(rhp_ip_addr));
		}
	}


	if( csa_ts_i_gre->start_addr.addr_family == AF_INET &&
			csa_ts_r_gre->start_addr.addr_family == AF_INET ){

		csa_ts_i_gre->ts_or_id_type = RHP_PROTO_IKEV1_ID_IPV4_ADDR_RANGE;
		csa_ts_r_gre->ts_or_id_type = RHP_PROTO_IKEV1_ID_IPV4_ADDR_RANGE;

		csa_ts_i_gre->v1_prefix_len = 32;
		csa_ts_r_gre->v1_prefix_len = 32;

	}else if( csa_ts_i_gre->start_addr.addr_family == AF_INET6 &&
						csa_ts_r_gre->start_addr.addr_family == AF_INET6 ){

		csa_ts_i_gre->ts_or_id_type = RHP_PROTO_IKEV1_ID_IPV6_ADDR_RANGE;
		csa_ts_r_gre->ts_or_id_type = RHP_PROTO_IKEV1_ID_IPV6_ADDR_RANGE;

		csa_ts_i_gre->v1_prefix_len = 128;
		csa_ts_r_gre->v1_prefix_len = 128;
	}

	rhp_childsa_ts_dump("_rhp_ikev1_quick_gen_nat_oa_ts:csa_ts_i_gre",csa_ts_i_gre);
	rhp_childsa_ts_dump("_rhp_ikev1_quick_gen_nat_oa_ts:csa_ts_r_gre",csa_ts_r_gre);

	if( rhp_childsa_ts_cmp(csa_ts_i,csa_ts_i_gre) ){
		*csa_ts_i_gre_r = csa_ts_i_gre;
	}else{
		_rhp_free(csa_ts_i_gre);
	}

	if( rhp_childsa_ts_cmp(csa_ts_r,csa_ts_r_gre) ){
		*csa_ts_r_gre_r = csa_ts_r_gre;
	}else{
		_rhp_free(csa_ts_r_gre);
	}

	rhp_childsa_ts_dump("_rhp_ikev1_quick_gen_nat_oa_ts:csa_ts_i_gre_r",*csa_ts_i_gre_r);
	rhp_childsa_ts_dump("_rhp_ikev1_quick_gen_nat_oa_ts:csa_ts_r_gre_r",*csa_ts_r_gre_r);

	return 0;

error:
	if(csa_ts_i_gre){
		_rhp_free(csa_ts_i_gre);
	}
	if(csa_ts_r_gre){
		_rhp_free(csa_ts_r_gre);
	}
	return err;
}

static int _rhp_ikev1_rx_quick_r_1_check_ts_with_cp(rhp_vpn* vpn,
		rhp_ikev2_mesg* rx_ikemesg,rhp_childsa_srch_plds_ctx* s_pld_ctx)
{
	rhp_ip_addr_list* peer_addr_cp = vpn->internal_net_info.peer_addrs;
	u8 ts_i_type = s_pld_ctx->ts_i_payload->ext.v1_id->get_id_type(s_pld_ctx->ts_i_payload);
	int ts_i_len = s_pld_ctx->ts_i_payload->ext.v1_id->get_id_len(s_pld_ctx->ts_i_payload);
	u8* ts_i =  s_pld_ctx->ts_i_payload->ext.v1_id->get_id(s_pld_ctx->ts_i_payload);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1_CHECK_TS_WITH_CP,"xxxb",vpn,rx_ikemesg,s_pld_ctx,vpn->internal_net_info.peer_addr_v4_cp);

	if( vpn->internal_net_info.peer_addr_v4_cp == RHP_IKEV2_CFG_CP_ADDR_ASSIGNED ){

		while( peer_addr_cp ){

			rhp_ip_addr_dump("peer_addr_cp_v4",&(peer_addr_cp->ip_addr));

			if( peer_addr_cp->ip_addr.addr_family == AF_INET ){
				break;
			}

			peer_addr_cp = peer_addr_cp->next;
		}

		if( peer_addr_cp == NULL ){
		  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1_CHECK_TS_WITH_CP_NO_CP_V4_ADDR,"xxx",vpn,rx_ikemesg,s_pld_ctx);
			s_pld_ctx->notify_error = RHP_PROTO_IKEV1_N_ERR_NO_PROPOSAL_CHOSEN;
	  	goto notify_error;
		}

		if( ts_i_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR ){

			if( ts_i_len != 4 ||
					*((u32*)ts_i) != peer_addr_cp->ip_addr.addr.v4 ){
			  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1_CHECK_TS_WITH_CP_V4_NOT_MATCH_1,"xxxbd44",vpn,rx_ikemesg,s_pld_ctx,ts_i_type,ts_i_len,*((u32*)ts_i),peer_addr_cp->ip_addr.addr.v4);
				s_pld_ctx->notify_error = RHP_PROTO_IKEV1_N_ERR_NO_PROPOSAL_CHOSEN;
		  	goto notify_error;
			}

		}else if( ts_i_type != RHP_PROTO_IKEV1_ID_IPV4_ADDR_SUBNET ){

			if( ts_i_len != 8 ||
					*((u32*)ts_i) != peer_addr_cp->ip_addr.addr.v4 ||
					*((u32*)(ts_i + 4)) != 0xFFFFFFFF ){
			  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1_CHECK_TS_WITH_CP_V4_NOT_MATCH_2,"xxxbd444",vpn,rx_ikemesg,s_pld_ctx,ts_i_type,ts_i_len,*((u32*)ts_i),*((u32*)(ts_i + 4)),peer_addr_cp->ip_addr.addr.v4);
				s_pld_ctx->notify_error = RHP_PROTO_IKEV1_N_ERR_NO_PROPOSAL_CHOSEN;
		  	goto notify_error;
			}

		}else if( ts_i_type != RHP_PROTO_IKEV1_ID_IPV4_ADDR_RANGE ){

			if( ts_i_len != 8 ||
					peer_addr_cp->ip_addr.addr.v4 != *((u32*)ts_i) ||
					peer_addr_cp->ip_addr.addr.v4 != *((u32*)(ts_i + 4)) ){
			  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1_CHECK_TS_WITH_CP_V4_NOT_MATCH_3,"xxxbd444",vpn,rx_ikemesg,s_pld_ctx,ts_i_type,ts_i_len,*((u32*)ts_i),*((u32*)(ts_i + 4)),peer_addr_cp->ip_addr.addr.v4);
				s_pld_ctx->notify_error = RHP_PROTO_IKEV1_N_ERR_NO_PROPOSAL_CHOSEN;
		  	goto notify_error;
			}

		}else{
		  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1_CHECK_TS_WITH_CP_NO_CP_V4_ADDR_NOT_MATCH_4,"xxxb",vpn,rx_ikemesg,s_pld_ctx,ts_i_type);
			s_pld_ctx->notify_error = RHP_PROTO_IKEV1_N_ERR_NO_PROPOSAL_CHOSEN;
	  	goto notify_error;
		}

	}else if( vpn->internal_net_info.peer_addr_v6_cp == RHP_IKEV2_CFG_CP_ADDR_ASSIGNED ){

		while( peer_addr_cp ){

			rhp_ip_addr_dump("peer_addr_cp_v6",&(peer_addr_cp->ip_addr));

			if( peer_addr_cp->ip_addr.addr_family == AF_INET6 ){
				break;
			}

			peer_addr_cp = peer_addr_cp->next;
		}

		if( peer_addr_cp == NULL ){
		  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1_CHECK_TS_WITH_CP_NO_CP_V6_ADDR,"xxx",vpn,rx_ikemesg,s_pld_ctx);
			s_pld_ctx->notify_error = RHP_PROTO_IKEV1_N_ERR_NO_PROPOSAL_CHOSEN;
	  	goto notify_error;
		}

		if( ts_i_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR ){

			if( ts_i_len != 16 ||
					memcmp(ts_i,peer_addr_cp->ip_addr.addr.v6,16) ){
			  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1_CHECK_TS_WITH_CP_V6_NOT_MATCH_1,"xxxbd44",vpn,rx_ikemesg,s_pld_ctx,ts_i_type,ts_i_len,ts_i,peer_addr_cp->ip_addr.addr.v6);
				s_pld_ctx->notify_error = RHP_PROTO_IKEV1_N_ERR_NO_PROPOSAL_CHOSEN;
		  	goto notify_error;
			}

		}else if( ts_i_type != RHP_PROTO_IKEV1_ID_IPV6_ADDR_SUBNET ){

			if( ts_i_len != 32 ||
					memcmp(ts_i,peer_addr_cp->ip_addr.addr.v6,16) ||
					*((u64*)(ts_i + 16)) != 0xFFFFFFFFFFFFFFFFUL ||
					*((u64*)(ts_i + 24)) != 0xFFFFFFFFFFFFFFFFUL ){
			  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1_CHECK_TS_WITH_CP_V6_NOT_MATCH_2,"xxxbd666",vpn,rx_ikemesg,s_pld_ctx,ts_i_type,ts_i_len,ts_i,ts_i + 16,peer_addr_cp->ip_addr.addr.v6);
				s_pld_ctx->notify_error = RHP_PROTO_IKEV1_N_ERR_NO_PROPOSAL_CHOSEN;
		  	goto notify_error;
			}

		}else if( ts_i_type != RHP_PROTO_IKEV1_ID_IPV4_ADDR_RANGE ){

			if( ts_i_len != 32 ||
					memcmp(ts_i,peer_addr_cp->ip_addr.addr.v6,16) ||
					memcmp((ts_i + 16),peer_addr_cp->ip_addr.addr.v6,16) ){
			  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1_CHECK_TS_WITH_CP_V6_NOT_MATCH_3,"xxxbd666",vpn,rx_ikemesg,s_pld_ctx,ts_i_type,ts_i_len,ts_i,ts_i + 16,peer_addr_cp->ip_addr.addr.v6);
				s_pld_ctx->notify_error = RHP_PROTO_IKEV1_N_ERR_NO_PROPOSAL_CHOSEN;
		  	goto notify_error;
			}

		}else{
		  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1_CHECK_TS_WITH_CP_NO_CP_V6_ADDR_NOT_MATCH_4,"xxxb",vpn,rx_ikemesg,s_pld_ctx,ts_i_type);
			s_pld_ctx->notify_error = RHP_PROTO_IKEV1_N_ERR_NO_PROPOSAL_CHOSEN;
	  	goto notify_error;
		}
	}

notify_error:
	RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1_CHECK_TS_WITH_CP_RTRN,"xxxw",vpn,rx_ikemesg,s_pld_ctx,s_pld_ctx->notify_error);
	return 0;
}

static int _rhp_ikev1_rx_quick_r_1(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = -EINVAL;
  rhp_childsa_srch_plds_ctx s_pld_ctx;
  rhp_childsa* childsa = NULL;
  rhp_vpn_realm* rlm = vpn->rlm;
	rhp_childsa_ts *csa_ts_i = NULL, *csa_ts_r = NULL, *csa_ts_i_gre = NULL, *csa_ts_r_gre = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1,"xxxxx",vpn,ikesa,rx_ikemesg,rx_ikemesg->rx_pkt,tx_ikemesg);

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
  	err = -EINVAL;
  	RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,rx_ikemesg,vpn->rlm);
  	goto error_rlm_l;
  }

  memset(&s_pld_ctx,0,sizeof(rhp_childsa_srch_plds_ctx));

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;
  s_pld_ctx.rlm = rlm;

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_HASH),
    		_rhp_ikev1_quick_r_1_srch_hash_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK ){

     RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1_HASH1_PLD_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);

    	if( s_pld_ctx.notify_error ){
        goto notify_error;
    	}

   		err = RHP_STATUS_INVALID_MSG;
    	goto error_rlm_l;
  	}

  	err = 0;
  }


  {
  	s_pld_ctx.dup_flag = 0;

    memset(&(s_pld_ctx.resolved_prop.v1),0,sizeof(rhp_res_ikev1_sa_proposal));

    s_pld_ctx.resolved_prop.v1.life_time = rlm->childsa.lifetime_hard;

    if( rlm->childsa.pfs ){
    	s_pld_ctx.resolved_prop.v1.dh_group = ikesa->prop.v1.dh_group;
    }else{
    	s_pld_ctx.resolved_prop.v1.dh_group = 0;
    }

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_SA),
  			_rhp_ikev1_quick_srch_sa_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK ){

     RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1_SA_PLD_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);

    	if( s_pld_ctx.notify_error ){
        goto notify_error;
    	}

   		err = RHP_STATUS_INVALID_MSG;
    	goto error_rlm_l;
  	}

  	err = 0;
  }


  {
		s_pld_ctx.dup_flag = 0;

		err = rx_ikemesg->search_payloads(rx_ikemesg,0,
							rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_NONCE),
							_rhp_ikev1_quick_srch_nonce_cb,&s_pld_ctx);

		if( err && err != RHP_STATUS_ENUM_OK ){

			RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1_NO_NONCE_PLD_1,"xxxE",vpn,ikesa,rx_ikemesg,err);
			err = RHP_STATUS_INVALID_MSG;

			if( s_pld_ctx.notify_error ){
				goto notify_error;
			}

			goto error_rlm_l;
		}
  }


  if( rlm->childsa.pfs &&
  		s_pld_ctx.resolved_prop.v1.dh_group ){

  	s_pld_ctx.dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  						rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_KE),
  						_rhp_ikev1_quick_srch_ke_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){

    	RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1_NO_KE_PLD_1,"xxxE",vpn,ikesa,rx_ikemesg,err);
    	err = RHP_STATUS_INVALID_MSG;

    	if( s_pld_ctx.notify_error ){
    		goto notify_error;
    	}

    	goto error_rlm_l;
    }
  }


  {
  	u16 mesg_ids[3] = {	RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_ETHERIP_ENCAP,
  											RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_GRE_ENCAP,
  											RHP_PROTO_IKE_NOTIFY_RESERVED};

  	s_pld_ctx.dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
			  			rhp_ikev2_mesg_srch_cond_n_mesg_ids,mesg_ids,
			  			_rhp_ikev1_quick_srch_n_info_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){

      RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1_N_PLD_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);
      goto error_rlm_l;
    }

    err = 0;
  }

	{
		int encap_mode_c;

		err = rhp_ikev2_rx_create_child_sa_req_encap_mode(vpn,rlm,&s_pld_ctx,&encap_mode_c);
		if( err ){

			RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1_INVALID_ENCAP_MODE,"xxxxdbbb",vpn,ikesa,rx_ikemesg,rlm->encap_mode_c,s_pld_ctx.use_trans_port_mode,s_pld_ctx.use_etherip_encap,s_pld_ctx.use_gre_encap);

	  	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKEV1_RX_QUICK_R_1_ENCAP_MODE_NOT_MATCHED,"KVC",rx_ikemesg,vpn,childsa);

			if( s_pld_ctx.notify_error ){

				s_pld_ctx.notify_error = RHP_PROTO_IKEV1_N_ERR_NO_PROPOSAL_CHOSEN;

		  	goto notify_error;
			}

			goto error_rlm_l;
		}

	  vpn->internal_net_info.encap_mode_c = encap_mode_c;
	}


  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,1,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_ID),
  			_rhp_ikev1_quick_r_srch_ts_ids_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK ){

  		RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1_TS_IDS_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);

    	if( s_pld_ctx.notify_error ){
        goto notify_error;
    	}

  		err = RHP_STATUS_INVALID_MSG;
    	goto error_rlm_l;
    }

  	RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1_TS_IDS_MATCHED_TS,"xxxxxbbx",vpn,ikesa,rx_ikemesg,s_pld_ctx.ts_i_payload,s_pld_ctx.ts_r_payload,vpn->internal_net_info.peer_addr_v4_cp,vpn->internal_net_info.peer_addr_v6_cp,vpn->internal_net_info.peer_addrs);

		if( rhp_realm_cfg_svr_narrow_ts_i(rlm,vpn) &&
				(vpn->internal_net_info.peer_addr_v4_cp == RHP_IKEV2_CFG_CP_ADDR_ASSIGNED ||
				 vpn->internal_net_info.peer_addr_v6_cp == RHP_IKEV2_CFG_CP_ADDR_ASSIGNED) ){

			err = _rhp_ikev1_rx_quick_r_1_check_ts_with_cp(vpn,rx_ikemesg,&s_pld_ctx);
			if( err ){
	    	goto error_rlm_l;
			}

    	if( s_pld_ctx.notify_error ){
        goto notify_error;
    	}
  	}

  	err = 0;
  }


  if( vpn->nat_t_info.exec_nat_t ){

  	s_pld_ctx.dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_NAT_OA),
  			_rhp_ikev1_quick_srch_nat_oas_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK ){

  		RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1_NAT_OAS_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);

    	if( s_pld_ctx.notify_error ){
        goto notify_error;
    	}

  		err = RHP_STATUS_INVALID_MSG;
    	goto error_rlm_l;
    }

  	rhp_ip_addr_dump("s_pld_ctx->v1_nat_oa_i",&(s_pld_ctx.v1_nat_oa_i));
  	rhp_ip_addr_dump("s_pld_ctx->v1_nat_oa_r",&(s_pld_ctx.v1_nat_oa_r));

  	err = 0;
  }



  if( rhp_gcfg_ikev1_commit_bit_enabled &&
  		rx_ikemesg->v1_commit_bit_enabled(rx_ikemesg) ){

  	vpn->v1.commit_bit_enabled = 1;
  }


  {
  	childsa = rhp_childsa_alloc(RHP_IKE_RESPONDER,1);

		if( childsa == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error_rlm_l;
		}

	  childsa->gen_type = RHP_CHILDSA_GEN_IKEV1;

		childsa->parent_ikesa.side = ikesa->side;
		memcpy(childsa->parent_ikesa.init_spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
		memcpy(childsa->parent_ikesa.resp_spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);

		{
			if( vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_ETHERIP ){

				childsa->ipsec_mode = RHP_CHILDSA_MODE_TRANSPORT;
				s_pld_ctx.resolved_prop.v1.encap_mode = RHP_PROTO_IKEV1_P2_ATTR_ENCAP_MODE_TRANSPORT;

			}else if( vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_GRE ){

				childsa->ipsec_mode = RHP_CHILDSA_MODE_TRANSPORT;
				s_pld_ctx.resolved_prop.v1.encap_mode = RHP_PROTO_IKEV1_P2_ATTR_ENCAP_MODE_TRANSPORT;

			}else if( vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_IPIP ){

				childsa->ipsec_mode = RHP_CHILDSA_MODE_TUNNEL;
				s_pld_ctx.resolved_prop.v1.encap_mode = RHP_PROTO_IKEV1_P2_ATTR_ENCAP_MODE_TUNNEL;

			}else{
				RHP_BUG("%d",vpn->internal_net_info.encap_mode_c);
			}

			if( vpn->nat_t_info.exec_nat_t ){

				if( s_pld_ctx.resolved_prop.v1.encap_mode
							== RHP_PROTO_IKEV1_P2_ATTR_ENCAP_MODE_TRANSPORT ){

					s_pld_ctx.resolved_prop.v1.encap_mode
						= RHP_PROTO_IKEV1_P2_ATTR_ENCAP_MODE_UDP_TRANSPORT;

				}else if( s_pld_ctx.resolved_prop.v1.encap_mode
										== RHP_PROTO_IKEV1_P2_ATTR_ENCAP_MODE_TUNNEL ){

					s_pld_ctx.resolved_prop.v1.encap_mode
						= RHP_PROTO_IKEV1_P2_ATTR_ENCAP_MODE_UDP_TUNNEL;
				}
			}
		}

		memcpy(&(childsa->prop.v1),&(s_pld_ctx.resolved_prop.v1),sizeof(rhp_res_ikev1_sa_proposal));


		err = childsa->generate_inb_spi(childsa);
		if( err ){
			RHP_BUG("%d",err);
			goto error_rlm_l;
		}

		childsa->set_outb_spi(childsa,*((u32*)s_pld_ctx.resolved_prop.v1.spi));

  	childsa->gen_message_id = rx_ikemesg->get_mesg_id(rx_ikemesg);
  }


  // Setup security alg's params
  err = _rhp_ikev1_rx_quick_sec_params_r(vpn,ikesa,childsa,rlm,&s_pld_ctx);
  if( err ){
    RHP_BUG("%d",err);
    goto error_rlm_l;
  }


  childsa->timers = rhp_ipsecsa_v1_new_timers(childsa->spi_inb,childsa->spi_outb);
	if( childsa->timers == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error_rlm_l;
	}

	{
		childsa->gre_ts_auto_generated
			= (s_pld_ctx.ts_i_payload->ext.v1_id->gre_ts_auto_generated &&
				 s_pld_ctx.ts_r_payload->ext.v1_id->gre_ts_auto_generated ? 1 : 0);

		csa_ts_i = s_pld_ctx.ts_i_payload->ext.v1_id->to_csa_ts(s_pld_ctx.ts_i_payload);
		csa_ts_r = s_pld_ctx.ts_r_payload->ext.v1_id->to_csa_ts(s_pld_ctx.ts_r_payload);

		if( csa_ts_i == NULL || csa_ts_r == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error_rlm_l;
		}


		if( childsa->gre_ts_auto_generated &&
				rlm->childsa.gre_ts_allow_nat_reflexive_addr &&
				!rhp_ip_addr_null(&(s_pld_ctx.v1_nat_oa_i)) &&
				!rhp_ip_addr_null(&(s_pld_ctx.v1_nat_oa_r)) ){

			_rhp_ikev1_quick_gen_nat_oa_ts(vpn,RHP_IKE_RESPONDER,
					&s_pld_ctx,csa_ts_i,csa_ts_r,&csa_ts_i_gre,&csa_ts_r_gre);
		}

		err = childsa->set_traffic_selector_v1(childsa,csa_ts_r,csa_ts_i,csa_ts_r_gre,csa_ts_i_gre);
		if( err ){
	    RHP_BUG("%d",err);
	    goto error_rlm_l;
		}

		childsa->v1.addr_family = csa_ts_i->start_addr.addr_family;
		if( childsa->v1.addr_family != AF_INET && childsa->v1.addr_family != AF_INET6 ){
			RHP_BUG("%d",childsa->v1.addr_family);
		}
	}


  {
		childsa->esn = s_pld_ctx.resolved_prop.v1.esn;

		if( childsa->esn ){
			childsa->rx_anti_replay.rx_seq.esn.b = 1;
			childsa->rx_anti_replay.rx_seq.esn.t = 1;
		}else{
			childsa->rx_anti_replay.rx_seq.non_esn.last = 1;
		}
  }


	err = childsa->setup_sec_params(ikesa,childsa);
	if( err ){
		RHP_BUG("%d",err);
		goto error_rlm_l;
	}


  childsa->anti_replay = rlm->childsa.anti_replay;
  childsa->out_of_order_drop = rlm->childsa.out_of_order_drop;


  err = _rhp_ikev1_new_pkt_quick_r_2(vpn,rlm,ikesa,childsa,&s_pld_ctx,rx_ikemesg,tx_ikemesg);
  if( err ){

		if( s_pld_ctx.notify_error ){
	  	RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1_NEW_PKT_REP_NTFY_ERR,"xxx",vpn,ikesa,rx_ikemesg);
	    goto notify_error;
		}

  	RHP_BUG("%d",err);
  	goto error_rlm_l;
  }


  {
		rhp_childsa_calc_pmtu(vpn,rlm,childsa);
		childsa->exec_pmtud = rlm->childsa.exec_pmtud;
  }

  rhp_childsa_set_state(childsa,RHP_IPSECSA_STAT_V1_2ND_SENT_R);

	childsa->timers->start_lifetime_timer(vpn,childsa,(time_t)rlm->childsa.lifetime_larval,0);


  vpn->childsa_put(vpn,childsa);

  RHP_UNLOCK(&(rlm->lock));


  rhp_ikev1_p2_session_rx_put(ikesa,rx_ikemesg,0);


	_rhp_free(csa_ts_i);
	_rhp_free(csa_ts_r);

	if( csa_ts_i_gre ){
		_rhp_free(csa_ts_i_gre);
	}
	if( csa_ts_r_gre ){
		_rhp_free(csa_ts_r_gre);
	}


  tx_ikemesg->v1_set_retrans_resp = 1;


	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKEV1_RX_QUICK_R_1,"KVC",rx_ikemesg,vpn,childsa);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1_RTRN,"xxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg);
  return 0;


notify_error:
	if( s_pld_ctx.notify_error ){

		rhp_ikev2_payload* ikepayload = NULL;

		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			err = -EINVAL;
			goto error_rlm_l;
		}

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,RHP_PROTO_IKEV1_PROP_PROTO_ID_ISAKMP);
		ikepayload->ext.n->set_message_type(ikepayload,s_pld_ctx.notify_error);


		if( rhp_ikev1_tx_info_mesg_hash_add(vpn,ikesa,
					tx_ikemesg,_rhp_ikev1_quick_r_add_hash_buf) ){
			RHP_BUG("");
			err = -EINVAL;
			goto error_rlm_l;
		}


	  rhp_ikev1_p2_session_rx_put(ikesa,rx_ikemesg,1);

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKEV1_RX_QUICK_R_1_TX_ERR_NOTIFY,"KVPL",rx_ikemesg,vpn,ikesa,"PROTO_IKE_NOTIFY",s_pld_ctx.notify_error);

		err = RHP_STATUS_IKEV2_DESTROY_SA_AFTER_TX;
	}


error_rlm_l:
	RHP_UNLOCK(&(rlm->lock));

  if( childsa ){
  	rhp_childsa_destroy(vpn,childsa);
  }

  if( csa_ts_i ){
  	_rhp_free(csa_ts_i);
  }
  if( csa_ts_r ){
  	_rhp_free(csa_ts_r);
  }
	if( csa_ts_i_gre ){
		_rhp_free(csa_ts_i_gre);
	}
	if( csa_ts_r_gre ){
		_rhp_free(csa_ts_r_gre);
	}

	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKEV1_RX_QUICK_R_1_ERR,"KVEL",rx_ikemesg,vpn,err,"PROTO_IKE_NOTIFY",s_pld_ctx.notify_error);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_1_ERR,"xxxxLwE",vpn,ikesa,rx_ikemesg,tx_ikemesg,err,"PROTO_IKE_NOTIFY",s_pld_ctx.notify_error);
  return err;
}


static int _rhp_ikev1_quick_i_2_srch_hash_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_ikev1_hash_payload* hash_payload = (rhp_ikev1_hash_payload*)payload->ext.v1_hash;
  rhp_childsa_srch_plds_ctx* s_pld_ctx = (rhp_childsa_srch_plds_ctx*)ctx;
  rhp_ikev1_quick_hash_buf hash_buf;
  int rx_hash_len, hash_octets_len;
  u8 *rx_hash, *hash_octets = NULL;
  int ni_b_len;
  u8* ni_b;

  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_I_2_SRCH_HASH_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

  memset(&hash_buf,0,sizeof(rhp_ikev1_quick_hash_buf));

  if( hash_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV1_QUICK_I_2_SRCH_HASH_CB_DUP_ERR,"xxx",rx_ikemesg,payload,ctx);
    goto error;
  }

	hash_octets_len = s_pld_ctx->ikesa->prf->get_output_len(s_pld_ctx->ikesa->prf);

  rx_hash_len = hash_payload->get_hash_len(payload);
  rx_hash = hash_payload->get_hash(payload);

  if( rx_hash_len != hash_octets_len ||
  		rx_hash == NULL ){
    s_pld_ctx->notify_error = RHP_PROTO_IKEV1_N_ERR_INVALID_HASH_INFORMATION;
    RHP_TRC(0,RHPTRCID_IKEV1_QUICK_I_2_SRCH_HASH_CB_NO_HASH_VAL,"xxxddx",rx_ikemesg,payload,ctx,rx_hash_len,hash_octets_len,rx_hash);
    goto error;
  }


  ni_b_len = s_pld_ctx->childsa->v1.nonce_i->get_nonce_len(s_pld_ctx->childsa->v1.nonce_i);
  ni_b =  s_pld_ctx->childsa->v1.nonce_i->get_nonce(s_pld_ctx->childsa->v1.nonce_i);
  if( ni_b_len < 1 || ni_b == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }


  hash_buf.len = sizeof(u32) + ni_b_len;
  hash_buf.buf = (u8*)_rhp_malloc(hash_buf.len);
  if( hash_buf.buf == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }
  *((u32*)hash_buf.buf) = htonl(rx_ikemesg->get_mesg_id(rx_ikemesg));
  memcpy((hash_buf.buf + sizeof(u32)),ni_b,ni_b_len);


	err = rx_ikemesg->search_payloads(rx_ikemesg,1,NULL,NULL,
					_rhp_ikev1_quick_1_srch_hash_buf,&hash_buf);
	if( err && err != -ENOENT && err != RHP_STATUS_ENUM_OK  ){
		RHP_BUG("");
		goto error;
	}
	err = 0;


  hash_octets = (u8*)_rhp_malloc(hash_octets_len);
  if( hash_octets == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

  if( s_pld_ctx->ikesa->prf->set_key(s_pld_ctx->ikesa->prf,
  			s_pld_ctx->ikesa->keys.v1.skeyid_a,s_pld_ctx->ikesa->keys.v1.skeyid_a_len) ){
    RHP_TRC(0,RHPTRCID_IKEV1_QUICK_I_2_SRCH_HASH_CB_PRF_SET_KEY_ERR,"xx",s_pld_ctx->ikesa,s_pld_ctx->ikesa->prf);
    err = -EINVAL;
    goto error;
  }

  if( s_pld_ctx->ikesa->prf->compute(s_pld_ctx->ikesa->prf,
  			hash_buf.buf,hash_buf.len,hash_octets,hash_octets_len) ){
    RHP_TRC(0,RHPTRCID_IKEV1_QUICK_I_2_SRCH_HASH_CB_PRF_COMPUTE_ERR,"xx",s_pld_ctx->ikesa,s_pld_ctx->ikesa->prf);
    err = -EINVAL;
    goto error;
  }

  if( memcmp(rx_hash,hash_octets,hash_octets_len) ){
    RHP_TRC(0,RHPTRCID_IKEV1_QUICK_I_2_SRCH_HASH_CB_NOT_MACHED,"xxxxEpp",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg,hash_payload,err,rx_hash_len,rx_hash,hash_octets_len,hash_octets);
    err = RHP_STATUS_INVALID_MSG;
    s_pld_ctx->notify_error = RHP_PROTO_IKEV1_N_ERR_INVALID_HASH_INFORMATION;
    goto error;
  }

  s_pld_ctx->v1_hash_payload = payload;

  err = RHP_STATUS_ENUM_OK;

error:
	if( hash_octets ){
		_rhp_free(hash_octets);
	}
	if( hash_buf.buf ){
		_rhp_free(hash_buf.buf);
	}
  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_I_2_SRCH_HASH_CB_RTRN,"xxxE",rx_ikemesg,payload,ctx,err);
  return err;
}

static int _rhp_ikev1_quick_i_srch_ts_ids_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_childsa_srch_plds_ctx* s_pld_ctx = (rhp_childsa_srch_plds_ctx*)ctx;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_SRCH_TS_IDS_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

  if( enum_end ){

  	// payload is NULL.

  	if( s_pld_ctx->ts_i_payload == NULL || s_pld_ctx->ts_r_payload == NULL ){
			RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_SRCH_TS_IDS_CB_NO_TS,"xxxE",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg,err);
			err = RHP_STATUS_INVALID_MSG;
			goto error;
  	}

  }else{

  	rhp_ikev1_id_payload* id_payload = (rhp_ikev1_id_payload*)payload->ext.v1_id;

    if( id_payload == NULL ){
    	RHP_BUG("");
    	return -EINVAL;
    }


    s_pld_ctx->dup_flag++;

    if( s_pld_ctx->dup_flag > 2 ){
      err = RHP_STATUS_INVALID_MSG;
      RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_SRCH_TS_IDS_CB_ERR,"xx",rx_ikemesg,ctx);
      goto error;
    }


		if( s_pld_ctx->ts_i_payload == NULL ){

			err = id_payload->check_ts(payload,RHP_IKE_INITIATOR,s_pld_ctx->childsa);
			if( err ){
				RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_SRCH_TS_IDS_CB_INIT_NOT_MATCHED,"xxxxE",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg,id_payload,err);
				err = RHP_STATUS_SELECTOR_NOT_MATCHED;
				goto error;
			}

			s_pld_ctx->ts_i_payload = payload;

		}else if( s_pld_ctx->ts_r_payload == NULL ){

			err = id_payload->check_ts(payload,RHP_IKE_RESPONDER,s_pld_ctx->childsa);
			if( err ){
				RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_SRCH_TS_IDS_CB_RESP_NOT_MATCHED,"xxxxE",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg,id_payload,err);
				err = RHP_STATUS_SELECTOR_NOT_MATCHED;
				goto error;
			}

			s_pld_ctx->ts_r_payload = payload;
		}
  }
  err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_SRCH_TS_IDS_CB_RTRN,"xxxE",rx_ikemesg,payload,ctx,err);
  return err;
}


extern int rhp_ikev2_rx_create_child_sa_rep_internal_net(rhp_vpn* vpn, rhp_vpn_realm* rlm,
		rhp_childsa* childsa,rhp_childsa_srch_plds_ctx* s_pld_ctx);

static int _rhp_ikev1_rx_quick_sec_params_i(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_childsa* childsa,
		rhp_vpn_realm* rlm,rhp_childsa_srch_plds_ctx* s_pld_ctx)
{
	int err = -EINVAL;
	int integ_id, encr_id;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_SEC_PARAMS_I,"xxxxxdd",vpn,ikesa,childsa,rlm,s_pld_ctx,s_pld_ctx->resolved_prop.v1.auth_alg,s_pld_ctx->resolved_prop.v1.trans_id);

	integ_id = rhp_ikev1_p2_integ_alg(s_pld_ctx->resolved_prop.v1.auth_alg);
	encr_id = rhp_ikev1_p2_encr_alg(s_pld_ctx->resolved_prop.v1.trans_id);

	if( integ_id < 0 || encr_id < 0 ){
		RHP_BUG("");
		return -EINVAL;
	}

	childsa->v1.trans_id = s_pld_ctx->resolved_prop.v1.trans_id;
	childsa->v1.auth_id = s_pld_ctx->resolved_prop.v1.auth_alg;


	childsa->integ_inb = rhp_crypto_integ_alloc(integ_id);
	if( childsa->integ_inb == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	childsa->integ_outb = rhp_crypto_integ_alloc(integ_id);
	if( childsa->integ_outb == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	childsa->encr = rhp_crypto_encr_alloc(encr_id,s_pld_ctx->resolved_prop.v1.key_bits_len);
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


	{
		int nonce_r_len = s_pld_ctx->nir_payload->ext.nir->get_nonce_len(s_pld_ctx->nir_payload);
		u8* nonce_r = s_pld_ctx->nir_payload->ext.nir->get_nonce(s_pld_ctx->nir_payload);

		err = childsa->v1.nonce_r->set_nonce(childsa->v1.nonce_r,nonce_r,nonce_r_len);
		if( err ){
			RHP_BUG("");
			goto error;
		}
	}


	if( childsa->v1.dh ){

		int peer_pub_key_len = s_pld_ctx->ke_payload->ext.v1_ke->get_key_len(s_pld_ctx->ke_payload);
		u8* peer_pub_key = s_pld_ctx->ke_payload->ext.v1_ke->get_key(s_pld_ctx->ke_payload);

		if( childsa->v1.dh->set_peer_pub_key(childsa->v1.dh,peer_pub_key,peer_pub_key_len) ){
			err = -EINVAL;
			RHP_BUG("");
			goto error;
		}

		if( childsa->v1.dh->compute_key(childsa->v1.dh) ){
			err = -EINVAL;
			RHP_BUG("");
			goto error;
		}
	}


  childsa->esn = s_pld_ctx->resolved_prop.v1.esn;

  if( childsa->esn ){
  	childsa->rx_anti_replay.rx_seq.esn.b = 1;
  	childsa->rx_anti_replay.rx_seq.esn.t = 1;
  }else{
  	childsa->rx_anti_replay.rx_seq.non_esn.last = 1;
  }


	err = childsa->setup_sec_params(ikesa,childsa);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_SEC_PARAMS_I_RTRN,"xxxxx",vpn,ikesa,childsa,rlm,s_pld_ctx);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_SEC_PARAMS_I_ERR,"xxxxxE",vpn,ikesa,childsa,rlm,s_pld_ctx,err);
	return err;
}


extern int rhp_ikev2_rx_create_child_sa_rep_delete_ikesa(rhp_vpn* vpn,rhp_ikesa* ikesa);

static int _rhp_ikev1_rx_quick_i_2(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_childsa* childsa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_vpn_realm* rlm = NULL;
  rhp_childsa_srch_plds_ctx s_pld_ctx;
  int commit_bit_enabled = 0;
	rhp_childsa_ts *csa_ts_i = NULL, *csa_ts_r = NULL, *csa_ts_i_gre = NULL, *csa_ts_r_gre = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_2,"xxxxxxLbxd",vpn,ikesa,rx_ikemesg,rx_ikemesg->rx_pkt,tx_ikemesg,vpn->rlm,"PROTO_IKE_EXCHG",childsa,vpn->childsa_req_rekeying);

  if( childsa->state != RHP_IPSECSA_STAT_V1_1ST_SENT_I ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_2_BAD_CHILDSA_STATE,"xxxxd",vpn,ikesa,rx_ikemesg,childsa,childsa->state);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  {
		ikesa->timers->quit_retransmit_timer(vpn,ikesa);

		if( ikesa->req_retx_ikemesg ){

			ikesa->set_retrans_request(ikesa,NULL);

			rhp_ikev2_unhold_mesg(ikesa->req_retx_ikemesg);
			ikesa->req_retx_ikemesg = NULL;
		}
  }


  if( rhp_gcfg_ikev1_commit_bit_enabled &&
  		vpn->cfg_peer->ikev1_commit_bit_enabled ){

  	commit_bit_enabled = 1;
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
  	RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_2_RLM_NOT_ACTIVE,"xxxxx",vpn,ikesa,childsa,rx_ikemesg,vpn->rlm);
  	goto error_rlm_l;
  }

  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error_rlm_l;
  }


  memset(&s_pld_ctx,0,sizeof(rhp_childsa_srch_plds_ctx));

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;
  s_pld_ctx.childsa = childsa;
  s_pld_ctx.rlm = rlm;


  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_HASH),
    		_rhp_ikev1_quick_i_2_srch_hash_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK ){

  		RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_2_HASH1_PLD_ERR,"xxxxE",vpn,ikesa,childsa,rx_ikemesg,err);

   		err = RHP_STATUS_INVALID_MSG;
    	goto error_rlm_l;
  	}

  	err = 0;
  }


  {
  	s_pld_ctx.dup_flag = 0;

    memset(&(s_pld_ctx.resolved_prop.v1),0,sizeof(rhp_res_ikev1_sa_proposal));

    s_pld_ctx.resolved_prop.v1.life_time = rlm->childsa.lifetime_hard;

    if( childsa->v1.dh ){
    	s_pld_ctx.resolved_prop.v1.dh_group = childsa->v1.dh->grp;
    }else{
    	s_pld_ctx.resolved_prop.v1.dh_group = 0;
    }

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_SA),
  			_rhp_ikev1_quick_srch_sa_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK ){

  		RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_2_SA_PLD_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);

   		err = RHP_STATUS_INVALID_MSG;
    	goto error_rlm_l;
  	}

  	err = 0;
  }


  {
		s_pld_ctx.dup_flag = 0;

		err = rx_ikemesg->search_payloads(rx_ikemesg,0,
							rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_NONCE),
							_rhp_ikev1_quick_srch_nonce_cb,&s_pld_ctx);

		if( err && err != RHP_STATUS_ENUM_OK ){

			RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_2_NO_NONCE_PLD_1,"xxxE",vpn,ikesa,rx_ikemesg,err);
			err = RHP_STATUS_INVALID_MSG;

			goto error_rlm_l;
		}
  }


  if( rlm->childsa.pfs &&
  		s_pld_ctx.resolved_prop.v1.dh_group ){

  	s_pld_ctx.dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  						rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_KE),
  						_rhp_ikev1_quick_srch_ke_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){

    	RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_2_NO_KE_PLD_1,"xxxE",vpn,ikesa,rx_ikemesg,err);
    	err = RHP_STATUS_INVALID_MSG;

    	goto error_rlm_l;
    }
  }

  {
  	u16 mesg_ids[3] = {	RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_ETHERIP_ENCAP,
  											RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_GRE_ENCAP,
  											RHP_PROTO_IKE_NOTIFY_RESERVED};

  	s_pld_ctx.dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
			  			rhp_ikev2_mesg_srch_cond_n_mesg_ids,mesg_ids,
			  			_rhp_ikev1_quick_srch_n_info_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){

      RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_2_CHILDSA_N_PLD_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);
      goto error_rlm_l;
    }

    err = 0;
  }


  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,1,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_ID),
  			_rhp_ikev1_quick_i_srch_ts_ids_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK ){

  		RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_2_TS_IDS_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);

  		err = RHP_STATUS_INVALID_MSG;
    	goto error_rlm_l;
    }

  	RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_2_TS_IDS_MATCHED_TS,"xxxxx",vpn,ikesa,rx_ikemesg,s_pld_ctx.ts_i_payload,s_pld_ctx.ts_r_payload);

  	err = 0;
  }

  if( vpn->nat_t_info.exec_nat_t ){

  	s_pld_ctx.dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_NAT_OA),
  			_rhp_ikev1_quick_srch_nat_oas_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK ){

  		RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_2_NAT_OAS_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);

  		err = RHP_STATUS_INVALID_MSG;
    	goto error_rlm_l;
    }

  	rhp_ip_addr_dump("s_pld_ctx->v1_nat_oa_i",&(s_pld_ctx.v1_nat_oa_i));
  	rhp_ip_addr_dump("s_pld_ctx->v1_nat_oa_r",&(s_pld_ctx.v1_nat_oa_r));

  	err = 0;
  }


  childsa->timers->quit_lifetime_timer(vpn,childsa);


  memcpy(&(childsa->prop.v1),&(s_pld_ctx.resolved_prop.v1),sizeof(rhp_res_ikev1_sa_proposal));

  childsa->set_outb_spi(childsa,*((u32*)s_pld_ctx.resolved_prop.v1.spi));
  childsa->timers->spi_outb = childsa->spi_outb;


  // Setup security alg's params
  err = _rhp_ikev1_rx_quick_sec_params_i(vpn,ikesa,childsa,rlm,&s_pld_ctx);
  if( err ){
    RHP_BUG("");
    goto error_rlm_l;
  }


	{
		csa_ts_i = s_pld_ctx.ts_i_payload->ext.v1_id->to_csa_ts(s_pld_ctx.ts_i_payload);
		csa_ts_r = s_pld_ctx.ts_r_payload->ext.v1_id->to_csa_ts(s_pld_ctx.ts_r_payload);

		if( csa_ts_i == NULL || csa_ts_r == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error_rlm_l;
		}

		if( childsa->gre_ts_auto_generated &&
				rlm->childsa.gre_ts_allow_nat_reflexive_addr &&
				!rhp_ip_addr_null(&(s_pld_ctx.v1_nat_oa_i)) &&
				!rhp_ip_addr_null(&(s_pld_ctx.v1_nat_oa_r)) ){

			_rhp_ikev1_quick_gen_nat_oa_ts(vpn,RHP_IKE_INITIATOR,
					&s_pld_ctx,csa_ts_i,csa_ts_r,&csa_ts_i_gre,&csa_ts_r_gre);
		}


		err = childsa->set_traffic_selector_v1(childsa,csa_ts_i,csa_ts_r,csa_ts_i_gre,csa_ts_r_gre);
		if( err ){
	    RHP_BUG("%d",err);
	    goto error_rlm_l;
		}

		childsa->v1.addr_family = csa_ts_i->start_addr.addr_family;
		if( childsa->v1.addr_family != AF_INET && childsa->v1.addr_family != AF_INET6 ){
			RHP_BUG("%d",childsa->v1.addr_family);
		}
	}

	// Setup internal network and Encap mode.
  err = rhp_ikev2_rx_create_child_sa_rep_internal_net(vpn,rlm,childsa,&s_pld_ctx);
  if( err ){
  	goto error_rlm_l;
  }


  err = _rhp_ikev1_new_pkt_quick_i_3(vpn,rlm,ikesa,childsa,rx_ikemesg,tx_ikemesg);
  if( err ){
    RHP_BUG("");
  	goto error_rlm_l;
  }


  childsa->anti_replay = rlm->childsa.anti_replay;
  childsa->out_of_order_drop = rlm->childsa.out_of_order_drop;


  {
		rhp_childsa_calc_pmtu(vpn,rlm,childsa);
		childsa->exec_pmtud = rlm->childsa.exec_pmtud;
  }


  if( !commit_bit_enabled ){

		rhp_childsa_set_state(childsa,RHP_IPSECSA_STAT_V1_MATURE);
		vpn->created_childsas++;


		if( ikesa->state == RHP_IKESA_STAT_V1_ESTABLISHED ){
			RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_2_SET_EXEC_AUTO_RECONNECT,"xxxx",vpn,ikesa,childsa,rx_ikemesg);
			vpn->exec_auto_reconnect = 1;
		}

		{
			time_t lifetime_hard, lifetime_soft;

			lifetime_hard = (time_t)childsa->prop.v1.life_time;

			lifetime_soft = (time_t)(lifetime_hard - rhp_gcfg_ikev1_ipsecsa_rekey_margin);
			if( (time_t)rlm->childsa.lifetime_soft < lifetime_soft ){
				lifetime_soft = rlm->childsa.lifetime_soft;
			}

			childsa->established_time = _rhp_get_time();
			childsa->expire_hard = childsa->established_time + lifetime_hard;
			childsa->expire_soft = childsa->established_time + lifetime_soft;

			childsa->timers->start_lifetime_timer(vpn,childsa,lifetime_soft,1);
		}

		rhp_esp_add_childsa_to_impl(vpn,childsa);

  }else{

    tx_ikemesg->v1_start_retx_timer = 1;

    rhp_childsa_set_state(childsa,RHP_IPSECSA_STAT_V1_WAIT_COMMIT_I);

    childsa->timers->start_lifetime_timer(vpn,childsa,(time_t)rlm->childsa.lifetime_larval,1);
  }

  RHP_UNLOCK(&(rlm->lock));


  if( !commit_bit_enabled ){

		vpn->ikesa_move_to_top(vpn,ikesa);
		vpn->childsa_move_to_top(vpn,childsa);


		if( (err = rhp_vpn_clear_unique_ids_tls_cache(vpn->vpn_realm_id)) ){
			RHP_BUG("%d",err);
		}
		err = 0;

		vpn->create_child_sa_failed = 0;


		if( !vpn->childsa_req_rekeying ){

			if( vpn->nhrp.role == RHP_NHRP_SERVICE_CLIENT &&
					vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_GRE &&
					!vpn->nhrp.dmvpn_shortcut ){

				err = vpn->start_nhc_registration_timer(vpn,(time_t)rhp_gcfg_nhrp_registration_req_tx_margin_time);
				if( err ){
					RHP_BUG("%d",err);
				}
				err = 0;
			}


			if( vpn->nhrp.pend_resolution_req_q.head ){

				rhp_nhrp_tx_queued_resolution_rep(vpn);
			}


			if( vpn->nhrp.dmvpn_shortcut &&
					vpn->vpn_conn_idle_timeout ){

				err = vpn->start_vpn_conn_idle_timer(vpn);
				if( err ){
					RHP_BUG("%d",err);
				}
				err = 0;
			}


	  	err = _rhp_ikev1_quick_i_invoke_create_new_sa_task(vpn,ikesa,rx_ikemesg);
	  	if( err ){
	      RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_2_CREATE_NEW_SA_NEXT_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);
	  	}
		}


		_rhp_ikev1_detach_old_childsa(vpn,childsa);

		vpn->childsa_req_rekeying = 0;


		RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_CREATED_IPSECSA_INITIATOR,"KVC",rx_ikemesg,vpn,childsa);

  }else{

    RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_2_COMMIT_BIT_ENABLED,"xxxd",vpn,ikesa,rx_ikemesg,commit_bit_enabled);
  }


  _rhp_ikev1_rx_quick_update_p2_sess(ikesa,childsa,rx_ikemesg);


	_rhp_free(csa_ts_i);
	_rhp_free(csa_ts_r);

	if( csa_ts_i_gre ){
		_rhp_free(csa_ts_i_gre);
	}
	if( csa_ts_r_gre ){
		_rhp_free(csa_ts_r_gre);
	}

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_2_RTRN,"xxxd",vpn,ikesa,rx_ikemesg,commit_bit_enabled);
  return 0;

error_rlm_l:
	RHP_UNLOCK(&(rlm->lock));

error:
  if( childsa ){

  	childsa->timers->schedule_delete(vpn,childsa,0);

  	vpn->create_child_sa_failed++;
  }

  rhp_ikev2_rx_create_child_sa_rep_delete_ikesa(vpn,ikesa);

  if( csa_ts_i ){
  	_rhp_free(csa_ts_i);
  }
  if( csa_ts_r ){
  	_rhp_free(csa_ts_r);
  }
	if( csa_ts_i_gre ){
		_rhp_free(csa_ts_i_gre);
	}
	if( csa_ts_r_gre ){
		_rhp_free(csa_ts_r_gre);
	}

  //
  // Don't free s_pld_ctx.res_tss_i and s_pld_ctx.res_tss_r here! These are linked to ts_payload.
  //

	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKEV1_RX_QUICK_I_2_ERR,"KVE",rx_ikemesg,vpn,err);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_2_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);
  return err;
}

static int _rhp_ikev1_quick_r_2_srch_hash_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_ikev1_hash_payload* hash_payload = (rhp_ikev1_hash_payload*)payload->ext.v1_hash;
  rhp_childsa_srch_plds_ctx* s_pld_ctx = (rhp_childsa_srch_plds_ctx*)ctx;
  rhp_ikev1_quick_hash_buf hash_buf;
  int rx_hash_len, hash_octets_len, ni_b_len, nr_b_len;
  u8 *rx_hash, *hash_octets = NULL, *ni_b, *nr_b;
	u8* p;

  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_R_2_SRCH_HASH_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

  hash_buf.len = 0;
  hash_buf.buf = NULL;

  if( hash_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV1_QUICK_R_2_SRCH_HASH_CB_DUP_ERR,"xxx",rx_ikemesg,payload,ctx);
    goto error;
  }


	hash_octets_len = s_pld_ctx->ikesa->prf->get_output_len(s_pld_ctx->ikesa->prf);

  rx_hash_len = hash_payload->get_hash_len(payload);
  rx_hash = hash_payload->get_hash(payload);

  if( rx_hash_len != hash_octets_len ||
  		rx_hash == NULL ){
    s_pld_ctx->notify_error = RHP_PROTO_IKEV1_N_ERR_INVALID_HASH_INFORMATION;
    RHP_TRC(0,RHPTRCID_IKEV1_QUICK_R_2_SRCH_HASH_CB_NO_HASH_VAL,"xxxddx",rx_ikemesg,payload,ctx,rx_hash_len,hash_octets_len,rx_hash);
    goto error;
  }


  ni_b_len = s_pld_ctx->childsa->v1.nonce_i->get_nonce_len(s_pld_ctx->childsa->v1.nonce_i);
  nr_b_len = s_pld_ctx->childsa->v1.nonce_r->get_nonce_len(s_pld_ctx->childsa->v1.nonce_r);
  ni_b = s_pld_ctx->childsa->v1.nonce_i->get_nonce(s_pld_ctx->childsa->v1.nonce_i);
  nr_b = s_pld_ctx->childsa->v1.nonce_r->get_nonce(s_pld_ctx->childsa->v1.nonce_r);

  if( ni_b_len < 1 || nr_b_len < 1 || ni_b == NULL || nr_b == NULL ){
  	err = -EINVAL;
  	RHP_BUG("");
  	goto error;
  }

  {
		hash_buf.len = sizeof(u8) + sizeof(u32) + ni_b_len + nr_b_len;
		hash_buf.buf = (u8*)_rhp_malloc(hash_buf.len);
		if( hash_buf.buf == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
		p = hash_buf.buf;

		*p = 0;
		p += sizeof(u8);

		*((u32*)p) = htonl(rx_ikemesg->get_mesg_id(rx_ikemesg));
		p += sizeof(u32);

		memcpy(p,ni_b,ni_b_len);
		p += ni_b_len;

		memcpy(p,nr_b,nr_b_len);
		p += nr_b_len;
  }


  hash_octets = (u8*)_rhp_malloc(hash_octets_len);
  if( hash_octets == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_R_2_SRCH_HASH_CB_HASH_DATA,"xxxpp",rx_ikemesg,payload,ctx,s_pld_ctx->ikesa->keys.v1.skeyid_a_len,s_pld_ctx->ikesa->keys.v1.skeyid_a,hash_buf.len,hash_buf.buf);

  if( s_pld_ctx->ikesa->prf->set_key(s_pld_ctx->ikesa->prf,
  			s_pld_ctx->ikesa->keys.v1.skeyid_a,s_pld_ctx->ikesa->keys.v1.skeyid_a_len) ){
    RHP_TRC(0,RHPTRCID_IKEV1_QUICK_R_2_SRCH_HASH_CB_PRF_SET_KEY_ERR,"xx",s_pld_ctx->ikesa,s_pld_ctx->ikesa->prf);
    err = -EINVAL;
    goto error;
  }

  if( s_pld_ctx->ikesa->prf->compute(s_pld_ctx->ikesa->prf,
  			hash_buf.buf,hash_buf.len,hash_octets,hash_octets_len) ){
    RHP_TRC(0,RHPTRCID_IKEV1_QUICK_R_2_SRCH_HASH_CB_PRF_COMPUTE_ERR,"xx",s_pld_ctx->ikesa,s_pld_ctx->ikesa->prf);
    err = -EINVAL;
    goto error;
  }

  if( memcmp(rx_hash,hash_octets,hash_octets_len) ){
    RHP_TRC(0,RHPTRCID_IKEV1_QUICK_R_2_SRCH_HASH_CB_NOT_MACHED,"xxxxppE",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg,hash_payload,rx_hash_len,rx_hash,hash_octets_len,hash_octets,err);
    err = RHP_STATUS_INVALID_MSG;
    s_pld_ctx->notify_error = RHP_PROTO_IKEV1_N_ERR_INVALID_HASH_INFORMATION;
    goto error;
  }

  s_pld_ctx->v1_hash_payload = payload;

  err = RHP_STATUS_ENUM_OK;

error:
	if( hash_octets ){
		_rhp_free(hash_octets);
	}
	if( hash_buf.buf ){
		_rhp_free(hash_buf.buf);
	}
  RHP_TRC(0,RHPTRCID_IKEV1_QUICK_R_2_SRCH_HASH_CB_RTRN,"xxxE",rx_ikemesg,payload,ctx,err);
  return err;
}

static int _rhp_ikev1_rx_quick_r_3(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_childsa* childsa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = -EINVAL;
  rhp_childsa_srch_plds_ctx s_pld_ctx;
  rhp_vpn_realm* rlm = vpn->rlm;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_3,"xxxxxd",vpn,ikesa,rx_ikemesg,rx_ikemesg->rx_pkt,tx_ikemesg,vpn->v1.commit_bit_enabled);


  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
  	err = -EINVAL;
  	RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_3_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,rx_ikemesg,vpn->rlm);
  	goto error_rlm_l;
  }

  memset(&s_pld_ctx,0,sizeof(rhp_childsa_srch_plds_ctx));

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;
  s_pld_ctx.childsa = childsa;
  s_pld_ctx.rlm = rlm;

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_HASH),
    		_rhp_ikev1_quick_r_2_srch_hash_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK ){

     RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_3_HASH1_PLD_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);

   		err = RHP_STATUS_INVALID_MSG;
    	goto error_rlm_l;
  	}

  	err = 0;
  }


  childsa->timers->quit_lifetime_timer(vpn,childsa);


	// Setup internal network
	err = rhp_ikev2_rx_create_child_sa_req_internal_net(vpn,childsa,rlm,&s_pld_ctx,
					vpn->internal_net_info.encap_mode_c);
	if( err ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_3_ITNL_NET_ERR,"xxxx",vpn,ikesa,childsa,rx_ikemesg);
		goto error_rlm_l;
	}


  if( rhp_gcfg_ikev1_commit_bit_enabled &&
  		rx_ikemesg->v1_commit_bit_enabled(rx_ikemesg) ){

  	err = _rhp_ikev1_new_pkt_quick_r_4_commit(vpn,ikesa,childsa,rx_ikemesg,tx_ikemesg);
		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_3_ALLOC_CONNECTED_NOTIFY_ERR,"xxxx",vpn,ikesa,childsa,rx_ikemesg);
			goto error_rlm_l;
		}

  	vpn->v1.commit_bit_enabled = 1;
	}


  rhp_childsa_set_state(childsa,RHP_IPSECSA_STAT_V1_MATURE);
  vpn->created_childsas++;

  if( ikesa->state == RHP_IKESA_STAT_V1_ESTABLISHED ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_3_SET_EXEC_AUTO_RECONNECT,"xxxx",vpn,ikesa,childsa,rx_ikemesg);
  	vpn->exec_auto_reconnect = 1;
  }


  {
		time_t lifetime_hard, lifetime_soft;

		lifetime_hard = (time_t)childsa->prop.v1.life_time;

		lifetime_soft = (time_t)(lifetime_hard - rhp_gcfg_ikev1_ipsecsa_rekey_margin);
		if( (time_t)rlm->childsa.lifetime_soft < lifetime_soft ){
			lifetime_soft = rlm->childsa.lifetime_soft;
		}

		childsa->established_time = _rhp_get_time();
		childsa->expire_hard = childsa->established_time + lifetime_hard;
		childsa->expire_soft = childsa->established_time + lifetime_soft;

		childsa->timers->start_lifetime_timer(vpn,childsa,lifetime_soft,1);
  }


  err = rhp_vpn_inb_childsa_put(vpn,childsa->spi_inb);
  if( err ){
    RHP_BUG("%d",err);
    goto error_rlm_l;
  }


  rhp_esp_add_childsa_to_impl(vpn,childsa);

  RHP_UNLOCK(&(rlm->lock));


  if( (err = rhp_vpn_clear_unique_ids_tls_cache(vpn->vpn_realm_id)) ){
  	RHP_BUG("%d",err);
  }
  err = 0;


  if( vpn->nhrp.pend_resolution_req_q.head ){

  	rhp_nhrp_tx_queued_resolution_rep(vpn);
  }


	if( vpn->nhrp.dmvpn_shortcut &&
			vpn->vpn_conn_idle_timeout ){

		err = vpn->start_vpn_conn_idle_timer(vpn);
		if( err ){
			RHP_BUG("%d",err);
		}
		err = 0;
	}


	_rhp_ikev1_detach_old_childsa(vpn,childsa);

  tx_ikemesg->v1_set_retrans_resp = 1;


  if( !vpn->v1.commit_bit_enabled ){

  	rhp_ikev1_p2_session_clear(ikesa,
  			rx_ikemesg->get_mesg_id(rx_ikemesg),rx_ikemesg->get_exchange_type(rx_ikemesg),0);

  }else{

    _rhp_ikev1_rx_quick_update_p2_sess(ikesa,childsa,rx_ikemesg);
  }


	RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_CREATED_IPSECSA_RESPONDER,"KVC",rx_ikemesg,vpn,childsa);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_3_RTRN,"xxxxd",vpn,ikesa,rx_ikemesg,tx_ikemesg,vpn->v1.commit_bit_enabled);
  return 0;


error_rlm_l:
	RHP_UNLOCK(&(rlm->lock));

  if( childsa ){
  	rhp_childsa_destroy(vpn,childsa);
  }

	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKEV1_RX_QUICK_R_3_ERR,"KVEL",rx_ikemesg,vpn,err,"PROTO_IKE_NOTIFY",s_pld_ctx.notify_error);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_R_3_ERR,"xxxxLwE",vpn,ikesa,rx_ikemesg,tx_ikemesg,err,"PROTO_IKE_NOTIFY",s_pld_ctx.notify_error);
  return err;
}

// Commit-bit enabled.
static int _rhp_ikev1_rx_quick_i_4_commit(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_childsa* childsa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_vpn_realm* rlm = NULL;
  rhp_childsa_srch_plds_ctx s_pld_ctx;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_4_COMMIT,"xxxxxxLbxd",vpn,ikesa,rx_ikemesg,rx_ikemesg->rx_pkt,tx_ikemesg,vpn->rlm,"PROTO_IKE_EXCHG",childsa,vpn->childsa_req_rekeying);

  if( childsa->state != RHP_IPSECSA_STAT_V1_WAIT_COMMIT_I ){
    RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_4_COMMIT_BAD_CHILDSA_STATE,"xxxxd",vpn,ikesa,rx_ikemesg,childsa,childsa->state);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  {
		ikesa->timers->quit_retransmit_timer(vpn,ikesa);

		if( ikesa->req_retx_ikemesg ){

			ikesa->set_retrans_request(ikesa,NULL);

			rhp_ikev2_unhold_mesg(ikesa->req_retx_ikemesg);
			ikesa->req_retx_ikemesg = NULL;
		}
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
  	RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_4_COMMIT_RLM_NOT_ACTIVE,"xxxxx",vpn,ikesa,childsa,rx_ikemesg,vpn->rlm);
  	goto error_rlm_l;
  }

  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error_rlm_l;
  }


  memset(&s_pld_ctx,0,sizeof(rhp_childsa_srch_plds_ctx));

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;
  s_pld_ctx.childsa = childsa;
  s_pld_ctx.rlm = rlm;


	err = rhp_ikev1_rx_info_mesg_hash_verify(vpn,ikesa,rx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_N);
	if( err ){
  	goto error_rlm_l;
	}


	{
  	u16 mesg_ids[3] = {	RHP_PROTO_IKEV1_N_ST_CONNECTED,
  											RHP_PROTO_IKE_NOTIFY_RESERVED};

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
			  			rhp_ikev2_mesg_srch_cond_n_mesg_ids,mesg_ids,
			  			_rhp_ikev1_quick_srch_n_info_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){

      RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_4_COMMIT_PLD_PARSE_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);
      goto error_rlm_l;
    }

  	if( !s_pld_ctx.v1_connected ){
      err = RHP_STATUS_INVALID_MSG;
      goto error_rlm_l;
  	}

    err = 0;
  }


  childsa->timers->quit_lifetime_timer(vpn,childsa);


	rhp_childsa_set_state(childsa,RHP_IPSECSA_STAT_V1_MATURE);
	vpn->created_childsas++;


	if( ikesa->state == RHP_IKESA_STAT_V1_ESTABLISHED ){
		RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_4_COMMIT_SET_EXEC_AUTO_RECONNECT,"xxxx",vpn,ikesa,childsa,rx_ikemesg);
		vpn->exec_auto_reconnect = 1;
	}

	{
		time_t lifetime_hard, lifetime_soft;

		lifetime_hard = (time_t)childsa->prop.v1.life_time;

		lifetime_soft = (time_t)(lifetime_hard - rhp_gcfg_ikev1_ipsecsa_rekey_margin);
		if( (time_t)rlm->childsa.lifetime_soft < lifetime_soft ){
			lifetime_soft = rlm->childsa.lifetime_soft;
		}

		childsa->established_time = _rhp_get_time();
		childsa->expire_hard = childsa->established_time + (time_t)lifetime_hard;
		childsa->expire_soft = childsa->established_time + (time_t)lifetime_soft;

		childsa->timers->start_lifetime_timer(vpn,childsa,(time_t)lifetime_soft,1);
	}

	rhp_esp_add_childsa_to_impl(vpn,childsa);

  RHP_UNLOCK(&(rlm->lock));


	vpn->ikesa_move_to_top(vpn,ikesa);
	vpn->childsa_move_to_top(vpn,childsa);


	if( (err = rhp_vpn_clear_unique_ids_tls_cache(vpn->vpn_realm_id)) ){
		RHP_BUG("%d",err);
	}
	err = 0;

	vpn->create_child_sa_failed = 0;


	if( !vpn->childsa_req_rekeying ){

		if( vpn->nhrp.role == RHP_NHRP_SERVICE_CLIENT &&
				vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_GRE &&
				!vpn->nhrp.dmvpn_shortcut ){

			err = vpn->start_nhc_registration_timer(vpn,(time_t)rhp_gcfg_nhrp_registration_req_tx_margin_time);
			if( err ){
				RHP_BUG("%d",err);
			}
			err = 0;
		}


		if( vpn->nhrp.pend_resolution_req_q.head ){

			rhp_nhrp_tx_queued_resolution_rep(vpn);
		}


		if( vpn->nhrp.dmvpn_shortcut &&
				vpn->vpn_conn_idle_timeout ){

			err = vpn->start_vpn_conn_idle_timer(vpn);
			if( err ){
				RHP_BUG("%d",err);
			}
			err = 0;
		}

		err = _rhp_ikev1_quick_i_invoke_create_new_sa_task(vpn,ikesa,rx_ikemesg);
		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_4_COMMIT_CREATE_NEW_SA_NEXT_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);
		}
	}


	_rhp_ikev1_detach_old_childsa(vpn,childsa);


	rhp_ikev1_p2_session_clear(ikesa,
			rx_ikemesg->get_mesg_id(rx_ikemesg),rx_ikemesg->get_exchange_type(rx_ikemesg),0);


	vpn->childsa_req_rekeying = 0;


	RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_CREATED_IPSECSA_INITIATOR,"KVC",rx_ikemesg,vpn,childsa);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_4_COMMIT_RTRN,"xxx",vpn,ikesa,rx_ikemesg);
  return 0;

error_rlm_l:
	RHP_UNLOCK(&(rlm->lock));

error:
  if( childsa ){

  	childsa->timers->schedule_delete(vpn,childsa,0);

  	vpn->create_child_sa_failed++;
  }

  rhp_ikev2_rx_create_child_sa_rep_delete_ikesa(vpn,ikesa);

	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKEV1_RX_QUICK_I_4_ERR,"KVE",rx_ikemesg,vpn,err);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_I_4_COMMIT_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);
  return err;
}


static int _rhp_ikev1_rx_quick(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
  rhp_childsa* childsa = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_L,"xxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg);

  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


  childsa = vpn->v1_ipsecsa_get_by_mesg_id(vpn,ikesa,
  						rx_ikemesg->get_mesg_id(rx_ikemesg));

	if( childsa == NULL ){

		err = _rhp_ikev1_rx_quick_r_1(vpn,ikesa,rx_ikemesg,tx_ikemesg);

	}else{

		if( childsa->state == RHP_IPSECSA_STAT_V1_1ST_SENT_I ){

			err = _rhp_ikev1_rx_quick_i_2(vpn,ikesa,childsa,rx_ikemesg,tx_ikemesg);

		}else if( childsa->state == RHP_IPSECSA_STAT_V1_2ND_SENT_R ){

			err = _rhp_ikev1_rx_quick_r_3(vpn,ikesa,childsa,rx_ikemesg,tx_ikemesg);

		}else if( childsa->state == RHP_IPSECSA_STAT_V1_WAIT_COMMIT_I ){

			err = _rhp_ikev1_rx_quick_i_4_commit(vpn,ikesa,childsa,rx_ikemesg,tx_ikemesg);

		}else{

			err = 0;
		}
	}

error:
	RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_L_RTRN,"xxxxE",vpn,ikesa,rx_ikemesg,tx_ikemesg,err);
	return err;
}

int rhp_ikev1_rx_quick(rhp_ikev2_mesg* rx_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_ikemesg)
{
	int err;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_ikemesg->get_exchange_type(rx_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK,"xxLdGxLb",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

	if( exchange_type == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ||
			exchange_type == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){

		if( my_ikesa_spi == NULL ){
	    RHP_BUG("");
	    err = -EINVAL;
	    goto error;
	  }

		if( my_ikesa_side != RHP_IKE_INITIATOR ){
			err = 0;
		  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_NOT_INTERESTED_1,"xxLdG",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}


		ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
		if( ikesa == NULL ){
			err = -ENOENT;
		  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_NO_IKESA_1,"xxLdG",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}

		if( ikesa->state != RHP_IKESA_STAT_V1_ESTABLISHED &&
				ikesa->state != RHP_IKESA_STAT_V1_REKEYING ){
			err = 0;
		  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_NOT_INTERESTED_2,"xxLdGLd",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state);
			goto error;
		}

		if( vpn->eap.role != RHP_EAP_DISABLED ){ // Actually, Not EAP but XAUTH.

			if( (vpn->origin_side == RHP_IKE_INITIATOR && ikesa->eap.state != RHP_IKESA_EAP_STAT_I_COMP) ||
					(vpn->origin_side == RHP_IKE_RESPONDER && ikesa->eap.state != RHP_IKESA_EAP_STAT_R_COMP) ){
				err = 0;
			  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_NOT_INTERESTED_2_XAUTH,"xxLdLdGLdLd",rx_ikemesg,vpn,"IKE_SIDE",vpn->origin_side,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state,"EAP_STAT",ikesa->eap.state);
				goto error;
			}
		}

	  if( exchange_type == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION &&
	  		!rx_ikemesg->decrypted ){
		  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_NOT_ENCRYPTED_3,"xxLdGLd",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state);
	    err = RHP_STATUS_INVALID_MSG;
	    goto error;
	  }

		if( !ikesa->v1.tx_initial_contact ){

			//
			// For IKE SA's rekey exchange. Ignored.
			//

			err = 0;
		  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_NOT_INTERESTED_3,"xxLdGLd",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state);
			goto error;
		}

	  if( exchange_type == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ){

	  	err = _rhp_ikev1_quick_i_create_new_sa(vpn,ikesa,rx_ikemesg,tx_ikemesg);

	  }else if( exchange_type == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){

	  	err = _rhp_ikev1_quick_i_invoke_create_new_sa_task(vpn,ikesa,rx_ikemesg);

	  }else{
	  	RHP_BUG("");
	  	err = -EINVAL;
	  }

	}else if( exchange_type == RHP_PROTO_IKEV1_EXCHG_QUICK ){

		if( my_ikesa_spi == NULL ){
	    RHP_BUG("");
	    err = -EINVAL;
	    goto error;
	  }

		ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
		if( ikesa == NULL ){
			err = -ENOENT;
		  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_NO_IKESA_2,"xxLdG",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}

		if( ikesa->state != RHP_IKESA_STAT_V1_ESTABLISHED &&
				ikesa->state != RHP_IKESA_STAT_V1_REKEYING ){
			err = 0;
		  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_NOT_INTERESTED_4,"xxLdGLd",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state);
			goto error;
		}

		if( vpn->eap.role != RHP_EAP_DISABLED ){ // Actually, Not EAP but XAUTH.

			if( (vpn->origin_side == RHP_IKE_INITIATOR && ikesa->eap.state != RHP_IKESA_EAP_STAT_I_COMP) ||
					(vpn->origin_side == RHP_IKE_RESPONDER && ikesa->eap.state != RHP_IKESA_EAP_STAT_R_COMP) ){
				err = 0;
			  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_NOT_INTERESTED_4_XAUTH,"xxLdLdGLdLd",rx_ikemesg,vpn,"IKE_SIDE",vpn->origin_side,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state,"EAP_STAT",ikesa->eap.state);
				goto error;
			}
		}

	  if( !rx_ikemesg->decrypted ){
		  RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_NOT_ENCRYPTED_2,"xxLdGLd",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state);
	    err = RHP_STATUS_INVALID_MSG;
	    goto error;
	  }

		err = _rhp_ikev1_rx_quick(vpn,ikesa,rx_ikemesg,tx_ikemesg);


	}else{

		err = 0;
		RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_NOT_INTERESTED_2,"xxx",rx_ikemesg,vpn,tx_ikemesg);
	}

error:
	RHP_TRC(0,RHPTRCID_IKEV1_RX_QUICK_RTRN,"xxxE",rx_ikemesg,vpn,tx_ikemesg,err);
  return err;
}
