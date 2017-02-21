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
#include "rhp_http.h"


static int _rhp_ikev1_delete_srch_d_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_delete_srch_plds_ctx* s_pld_ctx = (rhp_delete_srch_plds_ctx*)ctx;
  rhp_ikev2_d_payload* d_payload = (rhp_ikev2_d_payload*)payload->ext.d;
	u8 protocol_id;

 	RHP_TRC(0,RHPTRCID_IKEV1_DELETE_SRCH_D__CB,"xdxxxx",rx_ikemesg,enum_end,payload,ctx,s_pld_ctx->vpn,s_pld_ctx->ikesa);

  if( d_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  protocol_id = d_payload->get_protocol_id(payload);

  if( protocol_id == RHP_PROTO_IKEV1_PROP_PROTO_ID_ISAKMP ){

  	u8 *ikesa_spi, *init_spi, *resp_spi;

  	if( s_pld_ctx->ikesa_dup_flag > 1 ){
	   	RHP_TRC(0,RHPTRCID_IKEV1_DELETE_SRCH_D_ISAKMP_CB_DUP_ERR,"xxxxx",rx_ikemesg,payload,s_pld_ctx);
	   	err = RHP_STATUS_INVALID_MSG;
	   	goto error;
  	}

  	ikesa_spi = d_payload->v1_get_ikesa_spi(payload);
  	if( ikesa_spi == NULL ){
	   	RHP_TRC(0,RHPTRCID_IKEV1_DELETE_SRCH_D_ISAKMP_CB_NO_SPI,"xxxxx",rx_ikemesg,payload,s_pld_ctx);
	   	err = RHP_STATUS_INVALID_MSG;
	   	goto error;
  	}

  	init_spi = s_pld_ctx->ikesa->init_spi;
  	resp_spi = s_pld_ctx->ikesa->resp_spi;

  	if( memcmp(init_spi,ikesa_spi,RHP_PROTO_IKE_SPI_SIZE) ||
  			memcmp(resp_spi,(ikesa_spi + RHP_PROTO_IKE_SPI_SIZE),RHP_PROTO_IKE_SPI_SIZE) ){
	   	RHP_TRC(0,RHPTRCID_IKEV1_DELETE_SRCH_D_ISAKMP_CB_SPI_NOT_MATCHED,"xxxxxpppp",rx_ikemesg,payload,s_pld_ctx,RHP_PROTO_IKE_SPI_SIZE,init_spi,RHP_PROTO_IKE_SPI_SIZE,ikesa_spi,RHP_PROTO_IKE_SPI_SIZE,resp_spi,RHP_PROTO_IKE_SPI_SIZE,(ikesa_spi + RHP_PROTO_IKE_SPI_SIZE));
	   	err = RHP_STATUS_INVALID_MSG;
	   	goto error;
  	}

  	s_pld_ctx->ikesa_my_side = s_pld_ctx->ikesa->side;
  	s_pld_ctx->ikesa_my_spi = s_pld_ctx->ikesa->get_my_spi(s_pld_ctx->ikesa);

  	s_pld_ctx->ikesa_dup_flag++;

  }else if( protocol_id == RHP_PROTO_IKEV1_PROP_PROTO_ID_ESP ){

  	int spis_num;
  	u32 *spis,*tmp;

  	spis_num = d_payload->get_spis_num(payload);
  	spis = d_payload->get_spis(payload);

  	if( spis_num < 1 || spis == NULL ){
  		err = RHP_STATUS_INVALID_MSG;
	   	RHP_TRC(0,RHPTRCID_IKEV1_DELETE_SRCH_D_ESP_CB_INVALID_SPI_NUM,"xxxxx",rx_ikemesg,payload,s_pld_ctx,spis_num,spis);
  		goto error;
  	}

  	tmp = (u32*)_rhp_malloc(sizeof(u32)*(spis_num + s_pld_ctx->childsa_outb_spis_num));
  	if( tmp == NULL ){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}

  	if( s_pld_ctx->childsa_outb_spis ){

  		memcpy(tmp,s_pld_ctx->childsa_outb_spis,(sizeof(u32)*s_pld_ctx->childsa_outb_spis_num));
  		memcpy((tmp + s_pld_ctx->childsa_outb_spis_num),spis,(sizeof(u32)*spis_num));

  		_rhp_free(s_pld_ctx->childsa_outb_spis);

  	}else{

  		memcpy(tmp,spis,(sizeof(u32)*spis_num));
  	}

  	s_pld_ctx->childsa_outb_spis = tmp;
  	s_pld_ctx->childsa_outb_spis_num += spis_num;

  	s_pld_ctx->childsa_dup_flag++;
  }

 	RHP_TRC(0,RHPTRCID_IKEV1_DELETE_SRCH_D__CB_RTRN,"xxx",rx_ikemesg,payload,ctx);
  return 0;

error:

	s_pld_ctx->ikesa_my_side = 0;
	s_pld_ctx->ikesa_my_spi = NULL;

	if( s_pld_ctx->childsa_outb_spis ){
		_rhp_free(s_pld_ctx->childsa_outb_spis);
		s_pld_ctx->childsa_outb_spis = NULL;
	}
	s_pld_ctx->childsa_outb_spis_num = 0;

 	RHP_TRC(0,RHPTRCID_IKEV1_DELETE_SRCH_D__CB_RTRN,"xxxE",rx_ikemesg,payload,ctx,err);
	return err;
}


static int _rhp_ikev1_delete_ikesa_req(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_vpn_realm* rlm,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg,rhp_delete_srch_plds_ctx* s_pld_ctx)
{
	RHP_TRC(0,RHPTRCID_IKEV1_DELETE_IKESA_REQ,"xxxxxx",vpn,ikesa,rlm,rx_ikemesg,tx_ikemesg,s_pld_ctx);

	if( ikesa->state == RHP_IKESA_STAT_V1_ESTABLISHED ||
			ikesa->state == RHP_IKESA_STAT_V1_REKEYING ||
			ikesa->state == RHP_IKESA_STAT_V1_DELETE ){

		RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_DELETE_IKESA_REQ,"KVP",rx_ikemesg,vpn,ikesa);

		ikesa->timers->quit_lifetime_timer(vpn,ikesa);

		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_DELETE_WAIT);

		ikesa->timers->start_lifetime_timer(vpn,ikesa,(time_t)rlm->v1.ikesa_lifetime_deleted,0);

		ikesa->expire_soft = 0;
		ikesa->expire_hard = _rhp_get_time() + (time_t)rlm->v1.ikesa_lifetime_deleted;


		if( vpn->ikesa_num == 1 ){ // This is the last IKE SA...

			rhp_http_bus_broadcast_async(vpn->vpn_realm_id,1,1,
					rhp_ui_http_vpn_close_serialize,
					rhp_ui_http_vpn_bus_btx_async_cleanup,(void*)rhp_vpn_hold_ref(vpn)); // (*x*)
		}

	}else{

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_DELETE_IKESA_REQ_IGNORED,"KVP",rx_ikemesg,vpn,ikesa);
	}

	RHP_TRC(0,RHPTRCID_IKEV1_DELETE_IKESA_REQ_RTRN,"xxxxx",vpn,ikesa,rlm,rx_ikemesg,tx_ikemesg);
	return 0;
}

static int _rhp_ikev1_delete_childsa_req(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_vpn_realm* rlm,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg,rhp_delete_srch_plds_ctx* s_pld_ctx)
{
  rhp_childsa* childsa = NULL;
  int i;
 	int deleted_childsa = 0;

	RHP_TRC(0,RHPTRCID_IKEV1_DELETE_CHILDSA_REQ,"xxxxxx",vpn,ikesa,rlm,rx_ikemesg,tx_ikemesg,s_pld_ctx);


 	for( i = 0; i < s_pld_ctx->childsa_outb_spis_num; i++ ){

 		childsa = vpn->childsa_get(vpn,RHP_DIR_OUTBOUND,s_pld_ctx->childsa_outb_spis[i]);

		if( childsa == NULL ){
			RHP_TRC(0,RHPTRCID_IKEV1_DELETE_CHILDSA_REQ_NO_CHILDSA,"xxxdH",vpn,ikesa,rlm,RHP_DIR_OUTBOUND,s_pld_ctx->childsa_outb_spis[i]);
	  	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_DELETE_IPSECSA_REQ_NOT_FOUND,"KVdH",rx_ikemesg,vpn,(i + 1),s_pld_ctx->childsa_outb_spis[i]);
			continue;
		}


  	childsa->timers->schedule_delete(vpn,childsa,0); // Delete mesg will be sent soon.

  	RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKEV1_DELETE_IPSECSA_REQ,"KVdC",rx_ikemesg,vpn,(i + 1),childsa);
		deleted_childsa++;
 	}

	RHP_TRC(0,RHPTRCID_IKEV1_DELETE_CHILDSA_REQ_RTRN,"xxxxxd",vpn,ikesa,rlm,rx_ikemesg,tx_ikemesg,deleted_childsa);
	return 0;
}


static int _rhp_ikev1_rx_delete_req(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_mesg* tx_ikemesg)
{
  int err = 0;
  rhp_vpn_realm* rlm = NULL;
  rhp_delete_srch_plds_ctx s_pld_ctx;

	RHP_TRC(0,RHPTRCID_IKEV1_RX_DELETE_REQ,"xxxxLd",vpn,ikesa,rx_ikemesg,rx_ikemesg->rx_pkt,"IKESA_STAT",ikesa->state);

  memset(&s_pld_ctx,0,sizeof(rhp_delete_srch_plds_ctx));

  if( rx_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
   RHP_BUG("");
   err = RHP_STATUS_INVALID_MSG;
   goto error;
  }

  rlm = vpn->rlm;
  if( rlm == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV1_RX_DELETE_REQ_NO_RLM,"xxx",vpn,ikesa,rx_ikemesg);
  	goto error;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
  	RHP_TRC(0,RHPTRCID_IKEV1_RX_DELETE_REQ_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,rx_ikemesg,rlm);
  	goto error_l;
  }

  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;
  s_pld_ctx.rlm = rlm;


	err = rhp_ikev1_rx_info_mesg_hash_verify(vpn,ikesa,rx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_D);
	if( err ){
  	goto error_l;
	}


  {
  	s_pld_ctx.ikesa_dup_flag = 0;
  	s_pld_ctx.childsa_dup_flag = 0;

  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
		  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_D),
		  			_rhp_ikev1_delete_srch_d_cb,&s_pld_ctx);

    if( err && (err != RHP_STATUS_ENUM_OK) && (err != -ENOENT) ){
    	RHP_TRC(0,RHPTRCID_IKEV1_RX_DELETE_REQ_ENUM_D_PLD_ERR,"xxxxE",vpn,ikesa,rx_ikemesg,rlm,err);
     goto error_l;
    }
  }

  if( s_pld_ctx.childsa_outb_spis ){

  	err = _rhp_ikev1_delete_childsa_req(vpn,ikesa,rlm,rx_ikemesg,tx_ikemesg,&s_pld_ctx);
  	if( err ){
  		goto error_l;
  	}
  }

  if( s_pld_ctx.ikesa_my_spi ){

  	err = _rhp_ikev1_delete_ikesa_req(vpn,ikesa,rlm,rx_ikemesg,tx_ikemesg,&s_pld_ctx);
  	if( err ){
  		goto error_l;
  	}
  }

  RHP_UNLOCK(&(rlm->lock));

  if( s_pld_ctx.childsa_outb_spis || s_pld_ctx.ikesa_my_spi ){
  	rhp_vpn_clear_unique_ids_tls_cache(vpn->vpn_realm_id);
  }

  if( s_pld_ctx.childsa_outb_spis ){
  	_rhp_free(s_pld_ctx.childsa_outb_spis);
  }

	RHP_TRC(0,RHPTRCID_IKEV1_RX_DELETE_REQ_RTRN,"xxx",vpn,ikesa,rx_ikemesg);
  return 0;

error_l:
  RHP_UNLOCK(&(rlm->lock));
error:

	if( s_pld_ctx.childsa_outb_spis ){
		_rhp_free(s_pld_ctx.childsa_outb_spis);
	}

	RHP_TRC(0,RHPTRCID_IKEV1_RX_DELETE_REQ_ERR,"xxxE",vpn,ikesa,rx_ikemesg,err);
	return 0; // Ignored.
}

int rhp_ikev1_rx_delete_sa(rhp_ikev2_mesg* rx_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_ikemesg)
{
	int err;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_ikemesg->get_exchange_type(rx_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_DELETE_SA,"xxLdGxLb",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

  if( !rx_ikemesg->decrypted ){
  	err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_DELETE_SA_NOT_DECRYPTED,"xxLdG",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
  	goto error;
  }

	if( exchange_type == RHP_PROTO_IKEV1_EXCHG_INFORMATIONAL ){

		if( my_ikesa_spi == NULL ){
	    RHP_BUG("");
	    err = -EINVAL;
	    goto error;
	  }

		ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
		if( ikesa == NULL ){
			err = -ENOENT;
		  RHP_TRC(0,RHPTRCID_IKEV1_RX_DELETE_SA_NO_IKESA,"xxLdG",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}

		err = _rhp_ikev1_rx_delete_req(vpn,ikesa,rx_ikemesg,tx_ikemesg);

	}else{
		err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_DELETE_SA_NOT_INTERESTED,"xxLdG",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
	}

error:
	RHP_TRC(0,RHPTRCID_IKEV1_RX_DELETE_SA_RTRN,"xxxE",rx_ikemesg,vpn,tx_ikemesg,err);
  return err;
}


static int _rhp_ikev1_tx_delete_sa_add_hash_buf(rhp_ikev2_mesg* ikemesg,
		int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_packet* pkt_for_hash = (rhp_packet*)ctx;
	u8 pld_id = payload->get_payload_id(payload);

  RHP_TRC(0,RHPTRCID_IKEV1_TX_DELETE_SA_ADD_HASH_BUF,"xxLbxxd",ikemesg,payload,"PROTO_IKE_PAYLOAD",payload->payload_id,ctx,pkt_for_hash,ikemesg->tx_mesg_len);

  if( pld_id == RHP_PROTO_IKEV1_PAYLOAD_D ){

		err = payload->ext_serialize(payload,pkt_for_hash);
		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV1_TX_DELETE_SA_ADD_HASH_BUF_ERR,"xxLbxE",ikemesg,payload,"PROTO_IKE_PAYLOAD",payload->payload_id,ctx,err);
			return err;
		}
  }

  RHP_TRC(0,RHPTRCID_IKEV1_TX_DELETE_SA_ADD_HASH_BUF_RTRN,"xxxd",ikemesg,payload,pkt_for_hash,ikemesg->tx_mesg_len);
	return 0;
}

rhp_ikev2_mesg* rhp_ikev1_new_pkt_delete_ikesa(rhp_vpn* vpn,rhp_ikesa* ikesa)
{
	int err = -EINVAL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_ikev2_payload* d_ikepayload;

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_DELETE_IKESA,"xx",vpn,ikesa);

	tx_ikemesg = rhp_ikev1_new_mesg_tx(RHP_PROTO_IKEV1_EXCHG_INFORMATIONAL,0,0);
	if( tx_ikemesg == NULL ){
		err = -ENOMEM;
	  RHP_BUG("");
	  goto error;
	}

  {
  	u32 tx_mesg_id;

		err = rhp_random_bytes((u8*)&tx_mesg_id,sizeof(u32));
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		tx_ikemesg->set_mesg_id(tx_ikemesg,tx_mesg_id);
  }

	if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_D,&d_ikepayload) ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	tx_ikemesg->put_payload(tx_ikemesg,d_ikepayload);

	d_ikepayload->ext.d->set_protocol_id(d_ikepayload,RHP_PROTO_IKEV1_PROP_PROTO_ID_ISAKMP);

	if( d_ikepayload->ext.d->v1_set_ikesa_spi(d_ikepayload,ikesa->init_spi,ikesa->resp_spi) ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	if( rhp_ikev1_tx_info_mesg_hash_add(vpn,ikesa,
				tx_ikemesg,_rhp_ikev1_tx_delete_sa_add_hash_buf) ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	tx_ikemesg->v1_tx_redundant_pkts = rhp_gcfg_ikev1_tx_redundant_delete_sa_mesg;

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_DELETE_IKESA_RTRN,"xxxd",vpn,ikesa,tx_ikemesg,tx_ikemesg->v1_tx_redundant_pkts);
	return tx_ikemesg;

error:
	if( tx_ikemesg ){
		rhp_ikev2_unhold_mesg(tx_ikemesg);
	}
	RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_DELETE_IKESA_ERR,"xxE",vpn,ikesa,err);
	return NULL;
}

rhp_ikev2_mesg* rhp_ikev1_new_pkt_delete_ipsecsa(rhp_vpn* vpn,
		rhp_ikesa* ikesa,rhp_childsa* childsa)
{
	int err = -EINVAL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_ikev2_payload* d_ikepayload;

	RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_DELETE_IPSECSA,"xxx",vpn,ikesa,childsa);

	tx_ikemesg = rhp_ikev1_new_mesg_tx(RHP_PROTO_IKEV1_EXCHG_INFORMATIONAL,0,0);
	if( tx_ikemesg == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

  {
  	u32 tx_mesg_id;

		err = rhp_random_bytes((u8*)&tx_mesg_id,sizeof(u32));
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		tx_ikemesg->set_mesg_id(tx_ikemesg,tx_mesg_id);
  }

  if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_D,&d_ikepayload) ){
  	RHP_BUG("");
		err = -EINVAL;
    goto error;
  }

  tx_ikemesg->put_payload(tx_ikemesg,d_ikepayload);

  d_ikepayload->ext.d->set_protocol_id(d_ikepayload,RHP_PROTO_IKE_PROTOID_ESP);

  if( d_ikepayload->ext.d->set_spi(d_ikepayload,childsa->spi_inb) ){
  	RHP_BUG("");
		err = -EINVAL;
    goto error;
  }

	if( rhp_ikev1_tx_info_mesg_hash_add(vpn,ikesa,
				tx_ikemesg,_rhp_ikev1_tx_delete_sa_add_hash_buf) ){
		RHP_BUG("");
		err = -EINVAL;
    goto error;
	}

	tx_ikemesg->v1_tx_redundant_pkts = rhp_gcfg_ikev1_tx_redundant_delete_sa_mesg;

	RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_DELETE_IPSECSA_RTRN,"xxxxd",vpn,ikesa,childsa,tx_ikemesg,tx_ikemesg->v1_tx_redundant_pkts);
	return tx_ikemesg;

error:
	if( tx_ikemesg ){
		rhp_ikev2_unhold_mesg(tx_ikemesg);
	}
	RHP_TRC(0,RHPTRCID_IKEV1_NEW_PKT_DELETE_IPSECSA_ERR,"xxxE",vpn,ikesa,childsa,err);
	return NULL;
}
