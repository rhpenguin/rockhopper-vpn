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
#include "rhp_radius_impl.h"


struct _rhp_sess_rsm_srch_plds_ctx {

	int dup_flag;

	rhp_vpn* vpn;

  int tkt_r_len;
  u8* tkt_r;
  u32 tkt_r_lifetime;

  int rx_tkt_req;

  u16 notify_error;
  unsigned long notify_error_arg;
};
typedef struct _rhp_sess_rsm_srch_plds_ctx	rhp_sess_rsm_srch_plds_ctx;


static int _rhp_ikev2_sess_resume_srch_n_tkt_r_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_sess_rsm_srch_plds_ctx* s_pld_ctx = (rhp_sess_rsm_srch_plds_ctx*)ctx;
	rhp_ikev2_n_payload* n_payload = (rhp_ikev2_n_payload*)payload->ext.n;
	u16 notify_mesg_type;
	int tkt_data_len = 0;
	u8* tkt_data = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SRCH_N_TKT_R_CB,"xdxxx",rx_ikemesg,enum_end,payload,n_payload,s_pld_ctx);

	if( n_payload == NULL ){
		RHP_BUG("");
  	return -EINVAL;
  }

	if( s_pld_ctx->dup_flag ){
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SRCH_N_TKT_R_CB_DUP_IGNORED,"x",rx_ikemesg);
		return 0;
	}
	s_pld_ctx->dup_flag++;

	notify_mesg_type = n_payload->get_message_type(payload);
	tkt_data_len = payload->ext.n->get_data_len(payload);
	tkt_data = payload->ext.n->get_data(payload);

	if( tkt_data == NULL || tkt_data_len < 1 ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_TICKET_LT_OPAQUE ){

		if( tkt_data_len <= (int)sizeof(u32) ){ // u32: Lifetime field.
			err = 0;
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SRCH_N_TKT_R_CB_NOTIFY_ST_TICKET_LT_OPAQUE_INVALID_LEN,"xd",rx_ikemesg,tkt_data_len);
			goto error;
		}

		s_pld_ctx->tkt_r_lifetime = ntohl(*((u32*)tkt_data));
		s_pld_ctx->tkt_r = tkt_data + sizeof(u32);
		s_pld_ctx->tkt_r_len = tkt_data_len - sizeof(u32);

		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SRCH_N_TKT_R_CB_NOTIFY_ST_TICKET_LT_OPAQUE,"xdup",rx_ikemesg,tkt_data_len,s_pld_ctx->tkt_r_lifetime,s_pld_ctx->tkt_r_len,s_pld_ctx->tkt_r);

	 	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SESS_RESUME_REP_TKT_LT_OPAQUE_PAYLOAD,"Kjd",rx_ikemesg,s_pld_ctx->tkt_r_lifetime,s_pld_ctx->tkt_r_len);

  	if( rhp_gcfg_dbg_log_keys_info ){
  		RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SESS_RESUME_REP_TKT_LT_OPAQUE_PLD_DATA,"jp",s_pld_ctx->tkt_r_lifetime,s_pld_ctx->tkt_r_len,(u8*)s_pld_ctx->tkt_r);
  	}

	}else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_TICKET_OPAQUE ){

		if( tkt_data_len <= 0 ){
			err = 0;
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SRCH_N_TKT_R_CB_NOTIFY_ST_TICKET_OPAQUE_INVALID_LEN,"xd",rx_ikemesg,tkt_data_len);
			goto error;
		}

		s_pld_ctx->tkt_r_lifetime = 0;
		s_pld_ctx->tkt_r = tkt_data;
		s_pld_ctx->tkt_r_len = tkt_data_len;

		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SRCH_N_TKT_R_CB_NOTIFY_ST_TICKET_OPAQUE,"xdup",rx_ikemesg,tkt_data_len,s_pld_ctx->tkt_r_lifetime,s_pld_ctx->tkt_r_len,s_pld_ctx->tkt_r);

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SESS_RESUME_REP_TKT_OPAQUE_PAYLOAD,"Kd",rx_ikemesg,s_pld_ctx->tkt_r_len);

  	if( rhp_gcfg_dbg_log_keys_info ){
  		RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SESS_RESUME_REP_TKT_OPAQUE_PLD_DATA,"p",s_pld_ctx->tkt_r_len,(u8*)s_pld_ctx->tkt_r);
  	}
	}

	err = 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SRCH_N_TKT_R_CB_RTRN,"xE",rx_ikemesg,err);
	return err;
}

static int _rhp_ikev2_sess_resume_srch_n_tkt_req_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	rhp_sess_rsm_srch_plds_ctx* s_pld_ctx = (rhp_sess_rsm_srch_plds_ctx*)ctx;
	rhp_ikev2_n_payload* n_payload = (rhp_ikev2_n_payload*)payload->ext.n;

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SRCH_N_TKT_REQ_CB,"xdxxx",rx_ikemesg,enum_end,payload,n_payload,s_pld_ctx);

	if( n_payload == NULL ){
		RHP_BUG("");
  	return -EINVAL;
  }

	if( s_pld_ctx->dup_flag ){
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SRCH_N_TKT_REQ_CB_DUP_IGNORED,"x",rx_ikemesg);
		return 0;
	}
	s_pld_ctx->dup_flag++;

	s_pld_ctx->rx_tkt_req = 1;

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SESS_RESUME_TKT_REQ_PAYLOAD,"K",rx_ikemesg);

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SRCH_N_TKT_REQ_CB_RTRN,"x",rx_ikemesg);
	return 0;
}

static rhp_vpn_sess_resume_material* _rhp_ikev2_sess_resume_alloc_material_i(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_sess_rsm_srch_plds_ctx* s_pld_ctx)
{
	rhp_vpn_sess_resume_material* material = NULL;
	time_t rexp_time = 0;

	if( vpn->origin_side != RHP_IKE_INITIATOR ){
		RHP_BUG("%d",vpn->origin_side);
		return NULL;
	}

	material = (rhp_vpn_sess_resume_material*)_rhp_malloc(sizeof(rhp_vpn_sess_resume_material));
	if( material == NULL ){
		RHP_BUG("");
		goto error;
	}
	memset(material,0,sizeof(rhp_vpn_sess_resume_material));

	material->tag[0] = '#';
	material->tag[1] = 'S';
	material->tag[2] = 'R';
	material->tag[3] = 'M';

	material->old_sa_prop_i = (rhp_res_sa_proposal*)_rhp_malloc(sizeof(rhp_res_sa_proposal));
	material->old_sk_d_i = (u8*)_rhp_malloc(ikesa->keys.v2.sk_d_len);
	material->peer_tkt_r = (u8*)_rhp_malloc(s_pld_ctx->tkt_r_len);

	if( material->old_sa_prop_i == NULL ||
			material->old_sk_d_i == NULL ||
			material->peer_tkt_r == NULL ){
		RHP_BUG("");
		goto error;
	}

	if( rhp_ikev2_id_dup(&(material->my_id_i),&(vpn->my_id)) ){
		RHP_BUG("");
		goto error;
	}

	if( !rhp_eap_id_is_null(&(vpn->eap.my_id)) ){

		if( rhp_eap_id_dup(&(material->my_eap_id_i),&(vpn->eap.my_id)) ){
			RHP_BUG("");
			goto error;
		}
	}

	memcpy(material->old_sa_prop_i,&(ikesa->prop.v2),sizeof(rhp_res_sa_proposal));

	material->my_side_i = ikesa->side;
	memcpy(material->my_spi_i,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);

	material->old_sk_d_i_len = ikesa->keys.v2.sk_d_len;
	memcpy(material->old_sk_d_i,ikesa->keys.v2.sk_d,ikesa->keys.v2.sk_d_len);

	material->peer_tkt_r_len = s_pld_ctx->tkt_r_len;
	memcpy(material->peer_tkt_r,s_pld_ctx->tkt_r,s_pld_ctx->tkt_r_len);

	if( s_pld_ctx->tkt_r_lifetime ){

		material->peer_tkt_r_expire_time = _rhp_get_time() + s_pld_ctx->tkt_r_lifetime;
	}
	rexp_time = material->peer_tkt_r_expire_time;

	if( material->peer_tkt_r_expire_time == 0 ||
			material->peer_tkt_r_expire_time > ikesa->expire_hard ){

		material->peer_tkt_r_expire_time = ikesa->expire_hard;
	}

 	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_SESS_RESUME_I_TICKET_INFO,"VPLGIdsjttt",vpn,ikesa,"IKE_SIDE",material->my_side_i,material->my_spi_i,&(material->my_id_i),(material->my_eap_id_i.identity_len ? material->my_eap_id_i.method : 0),(material->my_eap_id_i.identity_len ? material->my_eap_id_i.identity : NULL),s_pld_ctx->tkt_r_lifetime,ikesa->expire_hard,rexp_time,material->peer_tkt_r_expire_time);
	if( rhp_gcfg_dbg_log_keys_info ){
	 	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_SESS_RESUME_I_TICKET_INFO_2,"bbbGwdwwwpp",material->old_sa_prop_i->number,material->old_sa_prop_i->protocol_id,material->old_sa_prop_i->spi_len,material->old_sa_prop_i->spi,material->old_sa_prop_i->encr_id,material->old_sa_prop_i->encr_key_bits,material->old_sa_prop_i->prf_id,material->old_sa_prop_i->integ_id,material->old_sa_prop_i->dhgrp_id,material->old_sk_d_i_len,material->old_sk_d_i,material->peer_tkt_r_len,material->peer_tkt_r);
 	}

	RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_ALLOC_MATERIAL_I,"xxxxdGpppttt",vpn,ikesa,s_pld_ctx,material,material->my_side_i,material->my_spi_i,sizeof(rhp_res_sa_proposal),material->old_sa_prop_i,material->old_sk_d_i_len,material->old_sk_d_i,material->peer_tkt_r_len,material->peer_tkt_r,material->peer_tkt_r_expire_time,ikesa->expire_hard,rexp_time);
	return material;

error:
	if( material ){
		rhp_vpn_sess_resume_clear(material);
	}
	return NULL;
}

static int _rhp_ikev2_rx_sess_resume_tkt_rep(rhp_ikev2_mesg* rx_resp_ikemesg,rhp_vpn* vpn,
		rhp_ikesa* ikesa,rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err = -EINVAL;
	rhp_sess_rsm_srch_plds_ctx s_pld_ctx;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_TKT_REP_L,"xxxxd",rx_resp_ikemesg,vpn,ikesa,tx_req_ikemesg,vpn->sess_resume.tkt_req_pending);

	memset(&s_pld_ctx,0,sizeof(rhp_sess_rsm_srch_plds_ctx));

	s_pld_ctx.vpn = vpn;

	{
		s_pld_ctx.dup_flag = 0;
		u16 sess_rsm_n_ids[3] = { RHP_PROTO_IKE_NOTIFY_ST_TICKET_LT_OPAQUE,
														 RHP_PROTO_IKE_NOTIFY_ST_TICKET_OPAQUE,
														 RHP_PROTO_IKE_NOTIFY_RESERVED};

		err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
						rhp_ikev2_mesg_srch_cond_n_mesg_ids,sess_rsm_n_ids,
						_rhp_ikev2_sess_resume_srch_n_tkt_r_cb,&s_pld_ctx);

		if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
			RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_TKT_REP_L_SRCH_PLD_ERR,"xxxxE",rx_resp_ikemesg,vpn,ikesa,tx_req_ikemesg,err);
			goto error;
		}
		err = 0;
	}

	if( s_pld_ctx.tkt_r ){

		rhp_vpn_sess_resume_material* material_i;

		vpn->sess_resume_clear(vpn);

		material_i = _rhp_ikev2_sess_resume_alloc_material_i(vpn,ikesa,&s_pld_ctx);
		if( material_i == NULL ){

			RHP_BUG("");

			err = 0;
			goto error;
		}

		vpn->sess_resume_set_material_i(vpn,material_i);
		ikesa->sess_resume.init.material = material_i; // Just reference. Don't free it.

	  vpn->sess_resume.exec_sess_resume = 1;

	}else{

		//
		// OK. Peer doesn't support IKEv2 Session Resumption.
		//

		RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_TKT_REP_L_NO_SESS_RESUME_PLD_FOUND,"xxxx",rx_resp_ikemesg,vpn,ikesa,tx_req_ikemesg);
	}

	vpn->sess_resume.tkt_req_pending = 0;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_TKT_REP_L_RTRN,"xxxxdd",rx_resp_ikemesg,vpn,ikesa,tx_req_ikemesg,vpn->sess_resume.exec_sess_resume,vpn->sess_resume.tkt_req_pending);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_TKT_REP_L_ERR,"xxxxddE",rx_resp_ikemesg,vpn,ikesa,tx_req_ikemesg,vpn->sess_resume.exec_sess_resume,vpn->sess_resume.tkt_req_pending,err);
	return err;
}

int rhp_ikev2_sess_resume_dec_tkt_vals(rhp_ikev2_sess_resume_tkt* sess_res_tkt,
		rhp_ikev2_sess_resume_tkt_e** sess_res_tkt_e_r, // Just refereces. Don't free.
		u8** sk_d_r,
		u8** id_i_r,
		u8** alt_id_i_r,
		u8** id_r_r,
		u8** alt_id_r_r,
		u8** eap_id_i_r,
		u8** sess_res_radius_tkt_r)
{
	rhp_ikev2_sess_resume_tkt_e* sess_res_tkt_e = (rhp_ikev2_sess_resume_tkt_e*)(sess_res_tkt + 1);
	int sess_res_tkt_len;
	u8* sk_d = NULL;
	u8* id_i = NULL;
	u8* alt_id_i = NULL;
	u8* id_r = NULL;
	u8* alt_id_r = NULL;
	u8* eap_id_i = NULL;
	u8* sess_res_radius_tkt = NULL;
	int sk_d_len = 0;
	int id_i_len = 0;
	int alt_id_i_len = 0;
	int id_r_len = 0;
	int alt_id_r_len = 0;
	int eap_id_i_len = 0;
	int sess_res_radius_tkt_len = 0;
	u8 *p, *end_p;

	sess_res_tkt_len = ntohs(sess_res_tkt->len);
	if( sess_res_tkt_len <= (int)(sizeof(rhp_ikev2_sess_resume_tkt) + sizeof(rhp_ikev2_sess_resume_tkt_e)) ){
		RHP_BUG("%d",sess_res_tkt_len);
		return -EINVAL;
	}

	p = (u8*)(sess_res_tkt_e + 1);
	end_p = ((u8*)sess_res_tkt) + sess_res_tkt_len;

	if(sess_res_tkt_e->sk_d_len){
		if( p >= end_p ){
			RHP_BUG("");
			return -EINVAL;
		}
		sk_d = p;
		sk_d_len = ntohs(sess_res_tkt_e->sk_d_len);
		p += sk_d_len;
	}
	if(sess_res_tkt_e->id_i_len){
		if( p >= end_p ){
			RHP_BUG("");
			return -EINVAL;
		}
		id_i = p;
		id_i_len = ntohs(sess_res_tkt_e->id_i_len);
		p += id_i_len;
	}
	if(sess_res_tkt_e->alt_id_i_len){
		if( p >= end_p ){
			RHP_BUG("");
			return -EINVAL;
		}
		alt_id_i = p;
		alt_id_i_len = ntohs(sess_res_tkt_e->alt_id_i_len);
		p += alt_id_i_len;
	}
	if(sess_res_tkt_e->id_r_len){
		if( p >= end_p ){
			RHP_BUG("");
			return -EINVAL;
		}
		id_r = p;
		id_r_len = ntohs(sess_res_tkt_e->id_r_len);
		p += id_r_len;
	}
	if(sess_res_tkt_e->alt_id_r_len){
		if( p >= end_p ){
			RHP_BUG("");
			return -EINVAL;
		}
		alt_id_r = p;
		alt_id_r_len = ntohs(sess_res_tkt_e->alt_id_r_len);
		p += alt_id_r_len;
	}
	if(sess_res_tkt_e->eap_identity_len){
		if( p >= end_p ){
			RHP_BUG("");
			return -EINVAL;
		}
		eap_id_i = p;
		eap_id_i_len = ntohs(sess_res_tkt_e->eap_identity_len);
		p += eap_id_i_len;
	}
	if(sess_res_tkt_e->radius_info_len){
		if( p >= end_p ){
			RHP_BUG("");
			return -EINVAL;
		}
		sess_res_radius_tkt = p;
		sess_res_radius_tkt_len = ntohs(sess_res_tkt_e->radius_info_len);
		p += sess_res_radius_tkt_len;
	}


	if( p > end_p ){
		RHP_BUG("");
		return -EINVAL;
	}


	if( sess_res_tkt_e_r ){
		*sess_res_tkt_e_r = sess_res_tkt_e;
	}
	if( sk_d_r ){
		*sk_d_r = sk_d;
	}
	if( id_i_r ){
		*id_i_r = id_i;
	}
	if( alt_id_i_r ){
		*alt_id_i_r = alt_id_i;
	}
	if( id_r_r ){
		*id_r_r = id_r;
	}
	if( alt_id_r_r ){
		*alt_id_r_r = alt_id_r;
	}
	if( eap_id_i_r ){
		*eap_id_i_r = eap_id_i;
	}
	if( sess_res_radius_tkt_r ){
		*sess_res_radius_tkt_r = sess_res_radius_tkt;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_DEC_TKT_VALS_OK,"xpppppppp",sess_res_tkt,ntohs(sess_res_tkt_e->len),sess_res_tkt_e,sk_d_len,sk_d,id_i_len,id_i,alt_id_i_len,alt_id_i,id_r_len,id_r,alt_id_r_len,alt_id_r,eap_id_i_len,eap_id_i,sess_res_radius_tkt_len,sess_res_radius_tkt);
	return 0;
}

void rhp_ikev2_sess_resume_tkt_dump(char* tag,rhp_ikev2_sess_resume_tkt* sess_res_tkt,int is_plain_txt)
{
	int err = 0;
	int sess_res_tkt_len = ntohs(sess_res_tkt->len);

	_RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
  if( _RHP_TRC_COND(_rhp_trc_user_id(),0) ){

		if( is_plain_txt &&
				sess_res_tkt_len >= (int)(sizeof(rhp_ikev2_sess_resume_tkt) + sizeof(rhp_ikev2_sess_resume_tkt_e)) ){

			rhp_ikev2_sess_resume_tkt_e* sess_res_tkt_e = (rhp_ikev2_sess_resume_tkt_e*)(sess_res_tkt + 1);
			u8 *p = (u8*)(sess_res_tkt_e + 1), *end_p = ((u8*)sess_res_tkt) + sess_res_tkt_len;
			u8* sk_d = NULL;
			u8* id_i = NULL;
			u8* alt_id_i = NULL;
			u8* id_r = NULL;
			u8* alt_id_r = NULL;
			u8* eap_id_i = NULL;
			rhp_radius_sess_ressume_tkt* radius_tkt = NULL;
			int sk_d_len = 0;
			int id_i_len = 0;
			int alt_id_i_len = 0;
			int id_r_len = 0;
			int alt_id_r_len = 0;
			int eap_id_i_len = 0;
			int radius_tkt_len = 0;
			char created_time_str[64];
			char exp_time_str[64];
			char policy_idx_str[64];

			if(sess_res_tkt_e->sk_d_len){
				if( p >= end_p ){
					RHP_BUG("");
					err = -EINVAL;
					goto error_dump;
				}
				sk_d = p;
				sk_d_len = ntohs(sess_res_tkt_e->sk_d_len);
				p += sk_d_len;
			}
			if(sess_res_tkt_e->id_i_len){
				if( p >= end_p ){
					RHP_BUG("");
					err = -EINVAL;
					goto error_dump;
				}
				id_i = p;
				id_i_len = ntohs(sess_res_tkt_e->id_i_len);
				p += id_i_len;
			}
			if(sess_res_tkt_e->alt_id_i_len){
				if( p >= end_p ){
					RHP_BUG("");
					err = -EINVAL;
					goto error_dump;
				}
				alt_id_i = p;
				alt_id_i_len = ntohs(sess_res_tkt_e->alt_id_i_len);
				p += alt_id_i_len;
			}
			if(sess_res_tkt_e->id_r_len){
				if( p >= end_p ){
					RHP_BUG("");
					err = -EINVAL;
					goto error_dump;
				}
				id_r = p;
				id_r_len = ntohs(sess_res_tkt_e->id_r_len);
				p += id_r_len;
			}
			if(sess_res_tkt_e->alt_id_r_len){
				if( p >= end_p ){
					RHP_BUG("");
					err = -EINVAL;
					goto error_dump;
				}
				alt_id_r = p;
				alt_id_r_len = ntohs(sess_res_tkt_e->alt_id_r_len);
				p += alt_id_r_len;
			}
			if(sess_res_tkt_e->eap_identity_len){
				if( p >= end_p ){
					RHP_BUG("");
					err = -EINVAL;
					goto error_dump;
				}
				eap_id_i = p;
				eap_id_i_len = ntohs(sess_res_tkt_e->eap_identity_len);
				p += eap_id_i_len;
			}
			if(sess_res_tkt_e->radius_info_len){
				if( p >= end_p ){
					RHP_BUG("");
					err = -EINVAL;
					goto error_dump;
				}
				radius_tkt = (rhp_radius_sess_ressume_tkt*)p;
				radius_tkt_len = ntohs(sess_res_tkt_e->radius_info_len);
				p += radius_tkt_len;
			}

			if( p > end_p ){
				RHP_BUG("");
				err = -EINVAL;
				goto error_dump;
			}

			{
				struct tm ts;
				time_t exp_time = (time_t)(_rhp_ntohll(sess_res_tkt_e->expire_time));

				exp_time_str[0] = '\0';
				localtime_r(&exp_time,&ts);

				snprintf(exp_time_str,64,"%d-%02d-%02d %02d:%02d:%02d",
						ts.tm_year + 1900,ts.tm_mon + 1, ts.tm_mday, ts.tm_hour, ts.tm_min, ts.tm_sec);


				exp_time = (time_t)(_rhp_ntohll(sess_res_tkt_e->created_time));
				created_time_str[0] = '\0';

				localtime_r(&exp_time,&ts);

				snprintf(created_time_str,64,"%d-%02d-%02d %02d:%02d:%02d",
						ts.tm_year + 1900,ts.tm_mon + 1, ts.tm_mday, ts.tm_hour, ts.tm_min, ts.tm_sec);


				exp_time = (time_t)(_rhp_ntohll(sess_res_tkt_e->vpn_realm_policy_index));
				policy_idx_str[0] = '\0';

				localtime_r(&exp_time,&ts);

				snprintf(policy_idx_str,64,"%d-%02d-%02d %02d:%02d:%02d",
						ts.tm_year + 1900,ts.tm_mon + 1, ts.tm_mday, ts.tm_hour, ts.tm_min, ts.tm_sec);
			}

			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_DUMP_1,"sxxpWWQpWWQsQsQQsbbbbbbWGGWWWWWppppppppW",tag,sess_res_tkt,sess_res_tkt_e,4,sess_res_tkt->magic,sess_res_tkt->version,sess_res_tkt->len,sess_res_tkt->key_index,RHP_IKEV2_SESS_RESUME_TKT_ENC_IV_LEN,sess_res_tkt->enc_iv,sess_res_tkt_e->len,sess_res_tkt_e->pad_len,sess_res_tkt_e->created_time,created_time_str,sess_res_tkt_e->expire_time,exp_time_str,sess_res_tkt_e->vpn_realm_id,sess_res_tkt_e->vpn_realm_policy_index,policy_idx_str,sess_res_tkt_e->id_i_type,sess_res_tkt_e->alt_id_i_type,sess_res_tkt_e->id_r_type,sess_res_tkt_e->alt_id_r_type,sess_res_tkt_e->auth_method_i,sess_res_tkt_e->auth_method_r,sess_res_tkt_e->eap_i_method,sess_res_tkt_e->init_spi,sess_res_tkt_e->resp_spi,sess_res_tkt_e->encr_id,sess_res_tkt_e->encr_key_bits,sess_res_tkt_e->prf_id,sess_res_tkt_e->integ_id,sess_res_tkt_e->dhgrp_id,sk_d_len,sk_d,id_i_len,id_i,alt_id_i_len,alt_id_i,id_r_len,id_r,alt_id_r_len,alt_id_r,eap_id_i_len,eap_id_i,sess_res_tkt_len,sess_res_tkt,htons(sess_res_tkt_e->len),sess_res_tkt_e,sess_res_tkt_e->radius_info_len);

			if( sess_res_tkt_e->radius_info_len ){

				RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_DUMP_1_RADIUS_TKT,"sxxxWWWQQJJ46bb46446p",tag,sess_res_tkt,sess_res_tkt_e,radius_tkt,radius_tkt->radius_tkt_len,radius_tkt->eap_method,radius_tkt->attrs_num,radius_tkt->rx_accept_attrs_mask,radius_tkt->vpn_realm_id_by_radius,radius_tkt->session_timeout,radius_tkt->framed_mtu,radius_tkt->internal_addr_ipv4,radius_tkt->internal_addr_ipv6,radius_tkt->internal_addr_ipv4_prefix,radius_tkt->internal_addr_ipv6_prefix,radius_tkt->internal_dns_server_ipv4,radius_tkt->internal_dns_server_ipv6,radius_tkt->internal_wins_server_ipv4,radius_tkt->internal_gateway_ipv4,radius_tkt->internal_gateway_ipv6,ntohs(radius_tkt->radius_tkt_len),(u8*)radius_tkt);
				_RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
			  if( _RHP_TRC_COND(_rhp_trc_user_id(),0) ){

			  	if( ntohs(radius_tkt->radius_tkt_len) > sizeof(rhp_radius_sess_ressume_tkt) ){

			  		rhp_radius_sess_resume_tkt_attr* attr = (rhp_radius_sess_resume_tkt_attr*)(radius_tkt + 1);
			    	int i, n = ntohs(radius_tkt->attrs_num);

			    	for( i = 0; i < n; i++){

			    		u16 attr_len = ntohs(attr->len);

			    		if( ((u8*)attr) + attr_len > end_p ){
		    				RHP_BUG("");
		    				err = -EINVAL;
		    				goto error_dump;
			    		}

			    		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_DUMP_1_RADIUS_TKT_ATTR,"sxxxdWWp",tag,sess_res_tkt,sess_res_tkt_e,radius_tkt,i,attr->len,attr->type,attr_len,(u8*)attr);

			    		attr = (rhp_radius_sess_resume_tkt_attr*)(((u8*)attr) + attr_len);
			    	}
			  	}
			  }
			}
			err = 0;

		}else if( sess_res_tkt_len >= (int)sizeof(rhp_ikev2_sess_resume_tkt) ){

			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_DUMP_2,"sxpWWQpp",tag,sess_res_tkt,4,sess_res_tkt->magic,sess_res_tkt->version,sess_res_tkt->len,sess_res_tkt->key_index,RHP_IKEV2_SESS_RESUME_TKT_ENC_IV_LEN,sess_res_tkt->enc_iv,sess_res_tkt_len,sess_res_tkt);
			err = 0;

		}else{

			RHP_BUG("%s, 0x%x, %d",tag,sess_res_tkt,is_plain_txt);
		}
  }

error_dump:
	if( err ){
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_ERROR_DUMP_3,"sp",tag,sess_res_tkt,sess_res_tkt_len,sess_res_tkt);
	}
	return;
}

void rhp_ikev2_sess_resume_tkt_log_dump(unsigned long rlm_id,rhp_ikev2_sess_resume_tkt* sess_res_tkt,int is_plain_txt)
{
	int err = 0;
	int sess_res_tkt_len = ntohs(sess_res_tkt->len);

	if( !rhp_gcfg_dbg_log_keys_info ){
		return;
	}

	if( is_plain_txt &&
			sess_res_tkt_len >= (int)(sizeof(rhp_ikev2_sess_resume_tkt) + sizeof(rhp_ikev2_sess_resume_tkt_e)) ){

		rhp_ikev2_sess_resume_tkt_e* sess_res_tkt_e = (rhp_ikev2_sess_resume_tkt_e*)(sess_res_tkt + 1);
		u8 *p = (u8*)(sess_res_tkt_e + 1), *end_p = ((u8*)sess_res_tkt) + sess_res_tkt_len;
		u8* sk_d = NULL;
		u8* id_i = NULL;
		u8* alt_id_i = NULL;
		u8* id_r = NULL;
		u8* alt_id_r = NULL;
		u8* eap_id_i = NULL;
		rhp_radius_sess_ressume_tkt* radius_tkt = NULL;
		int sk_d_len = 0;
		int id_i_len = 0;
		int alt_id_i_len = 0;
		int id_r_len = 0;
		int alt_id_r_len = 0;
		int eap_id_i_len = 0;
		int radius_tkt_len = 0;
		char created_time_str[64];
		char exp_time_str[64];
		char policy_idx_str[64];
		char id_i_addr_str[INET6_ADDRSTRLEN + 1];

		id_i_addr_str[0] = '\0';

		if(sess_res_tkt_e->sk_d_len){
			if( p >= end_p ){
				RHP_BUG("");
				err = -EINVAL;
				goto error_dump;
			}
			sk_d = p;
			sk_d_len = ntohs(sess_res_tkt_e->sk_d_len);
			p += sk_d_len;
		}
		if(sess_res_tkt_e->id_i_len){

			if( p >= end_p ){
				RHP_BUG("");
				err = -EINVAL;
				goto error_dump;
			}

			id_i = p;
			id_i_len = ntohs(sess_res_tkt_e->id_i_len);
			p += id_i_len;

			if( id_i_len >= 4 && sess_res_tkt_e->id_i_type == RHP_PROTO_IKE_ID_IPV4_ADDR ){
				snprintf(id_i_addr_str,(INET6_ADDRSTRLEN + 1),"%d.%d.%d.%d",id_i[0],id_i[1],id_i[2],id_i[3]);
				id_i = (u8*)id_i_addr_str;
				id_i_len = strlen(id_i_addr_str);
			}else if( id_i_len >= 16 && sess_res_tkt_e->id_i_type == RHP_PROTO_IKE_ID_IPV6_ADDR ){
				rhp_ipv6_string2(id_i,id_i_addr_str);
				id_i = (u8*)id_i_addr_str;
				id_i_len = strlen(id_i_addr_str);
			}
		}
		if(sess_res_tkt_e->alt_id_i_len){
			if( p >= end_p ){
				RHP_BUG("");
				err = -EINVAL;
				goto error_dump;
			}
			alt_id_i = p;
			alt_id_i_len = ntohs(sess_res_tkt_e->alt_id_i_len);
			p += alt_id_i_len;
		}
		if(sess_res_tkt_e->id_r_len){
			if( p >= end_p ){
				RHP_BUG("");
				err = -EINVAL;
				goto error_dump;
			}
			id_r = p;
			id_r_len = ntohs(sess_res_tkt_e->id_r_len);
			p += id_r_len;
		}
		if(sess_res_tkt_e->alt_id_r_len){
			if( p >= end_p ){
				RHP_BUG("");
				err = -EINVAL;
				goto error_dump;
			}
			alt_id_r = p;
			alt_id_r_len = ntohs(sess_res_tkt_e->alt_id_r_len);
			p += alt_id_r_len;
		}
		if(sess_res_tkt_e->eap_identity_len){
			if( p >= end_p ){
				RHP_BUG("");
				err = -EINVAL;
				goto error_dump;
			}
			eap_id_i = p;
			eap_id_i_len = ntohs(sess_res_tkt_e->eap_identity_len);
			p += eap_id_i_len;
		}
		if(sess_res_tkt_e->radius_info_len){
			if( p >= end_p ){
				RHP_BUG("");
				err = -EINVAL;
				goto error_dump;
			}
			radius_tkt = (rhp_radius_sess_ressume_tkt*)p;
			radius_tkt_len = ntohs(sess_res_tkt_e->radius_info_len);
			p += radius_tkt_len;
		}

		if( p > end_p ){
			RHP_BUG("");
			err = -EINVAL;
			goto error_dump;
		}

		{
			struct tm ts;
			time_t exp_time = (time_t)(_rhp_ntohll(sess_res_tkt_e->expire_time));

			exp_time_str[0] = '\0';
			localtime_r(&exp_time,&ts);

			snprintf(exp_time_str,64,"%d-%02d-%02d %02d:%02d:%02d",
					ts.tm_year + 1900,ts.tm_mon + 1, ts.tm_mday, ts.tm_hour, ts.tm_min, ts.tm_sec);


			exp_time = (time_t)(_rhp_ntohll(sess_res_tkt_e->created_time));
			created_time_str[0] = '\0';

			localtime_r(&exp_time,&ts);

			snprintf(created_time_str,64,"%d-%02d-%02d %02d:%02d:%02d",
					ts.tm_year + 1900,ts.tm_mon + 1, ts.tm_mday, ts.tm_hour, ts.tm_min, ts.tm_sec);


			exp_time = (time_t)(_rhp_ntohll(sess_res_tkt_e->vpn_realm_policy_index));
			policy_idx_str[0] = '\0';

			localtime_r(&exp_time,&ts);

			snprintf(policy_idx_str,64,"%d-%02d-%02d %02d:%02d:%02d",
					ts.tm_year + 1900,ts.tm_mon + 1, ts.tm_mday, ts.tm_hour, ts.tm_min, ts.tm_sec);
		}

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,rlm_id,RHP_LOG_ID_IKE_SESS_RESUME_TKT_DUMP_PLAIN,"aWWQpWWQsQsQQsbbbbbbWGGWWWWWpaaaaapW",4,sess_res_tkt->magic,sess_res_tkt->version,sess_res_tkt->len,sess_res_tkt->key_index,RHP_IKEV2_SESS_RESUME_TKT_ENC_IV_LEN,sess_res_tkt->enc_iv,sess_res_tkt_e->len,sess_res_tkt_e->pad_len,sess_res_tkt_e->created_time,created_time_str,sess_res_tkt_e->expire_time,exp_time_str,sess_res_tkt_e->vpn_realm_id,sess_res_tkt_e->vpn_realm_policy_index,policy_idx_str,sess_res_tkt_e->id_i_type,sess_res_tkt_e->alt_id_i_type,sess_res_tkt_e->id_r_type,sess_res_tkt_e->alt_id_r_type,sess_res_tkt_e->auth_method_i,sess_res_tkt_e->auth_method_r,sess_res_tkt_e->eap_i_method,sess_res_tkt_e->init_spi,sess_res_tkt_e->resp_spi,sess_res_tkt_e->encr_id,sess_res_tkt_e->encr_key_bits,sess_res_tkt_e->prf_id,sess_res_tkt_e->integ_id,sess_res_tkt_e->dhgrp_id,sk_d_len,sk_d,id_i_len,id_i,alt_id_i_len,alt_id_i,id_r_len,id_r,alt_id_r_len,alt_id_r,eap_id_i_len,eap_id_i,sess_res_tkt_len,(u8*)sess_res_tkt,sess_res_tkt_e->radius_info_len);

		if( sess_res_tkt_e->radius_info_len ){

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,rlm_id,RHP_LOG_ID_IKE_SESS_RESUME_TKT_DUMP_PLAIN_RADIUS_TKT,"WLWQQJJ46bb46446p",radius_tkt->radius_tkt_len,"EAP_TYPE",ntohs(radius_tkt->eap_method),radius_tkt->attrs_num,radius_tkt->rx_accept_attrs_mask,radius_tkt->vpn_realm_id_by_radius,radius_tkt->session_timeout,radius_tkt->framed_mtu,radius_tkt->internal_addr_ipv4,radius_tkt->internal_addr_ipv6,radius_tkt->internal_addr_ipv4_prefix,radius_tkt->internal_addr_ipv6_prefix,radius_tkt->internal_dns_server_ipv4,radius_tkt->internal_dns_server_ipv6,radius_tkt->internal_wins_server_ipv4,radius_tkt->internal_gateway_ipv4,radius_tkt->internal_gateway_ipv6,ntohs(radius_tkt->radius_tkt_len),(u8*)radius_tkt);

	  	if( ntohs(radius_tkt->radius_tkt_len) > sizeof(rhp_radius_sess_ressume_tkt) ){

	  		rhp_radius_sess_resume_tkt_attr* attr = (rhp_radius_sess_resume_tkt_attr*)(radius_tkt + 1);
	    	int i, n = ntohs(radius_tkt->attrs_num);

	    	for( i = 0; i < n; i++){

	    		u16 attr_len = ntohs(attr->len);

	    		if( ((u8*)attr) + attr_len > end_p ){
    				RHP_BUG("");
    				err = -EINVAL;
    				goto error_dump;
	    		}

	    		switch( ntohs(attr->type) ){
	    		case RHP_SESS_RESUME_RADIUS_ATTR_PRIV_REALM_ROLE:
	    		case RHP_SESS_RESUME_RADIUS_ATTR_TUNNEL_PRIVATE_GROUP_ID:
	    		case RHP_SESS_RESUME_RADIUS_ATTR_USER_INDEX:
	    		case RHP_SESS_RESUME_RADIUS_ATTR_INTERNAL_DOMAIN_NAME:
		    		RHP_LOG_D(RHP_LOG_SRC_IKEV2,rlm_id,RHP_LOG_ID_IKE_SESS_RESUME_TKT_DUMP_PLAIN_RADIUS_TKT_ATTR_STR,"dWWa",i,attr->len,attr->type,(attr_len - sizeof(rhp_radius_sess_resume_tkt_attr)),(u8*)(attr + 1));
	    			break;
	    		case RHP_SESS_RESUME_RADIUS_ATTR_INTERNAL_ROUTE_IPV4:
		    		RHP_LOG_D(RHP_LOG_SRC_IKEV2,rlm_id,RHP_LOG_ID_IKE_SESS_RESUME_TKT_DUMP_PLAIN_RADIUS_TKT_ATTR_IPV4,"dWW4b",i,attr->len,attr->type,*((u32*)(attr + 1)),*(((u8*)(attr + 1)) + 4));
	    			break;
	    		case RHP_SESS_RESUME_RADIUS_ATTR_INTERNAL_ROUTE_IPV6:
		    		RHP_LOG_D(RHP_LOG_SRC_IKEV2,rlm_id,RHP_LOG_ID_IKE_SESS_RESUME_TKT_DUMP_PLAIN_RADIUS_TKT_ATTR_IPV6,"dWW6b",i,attr->len,attr->type,(u8*)(attr + 1),*(((u8*)(attr + 1)) + 16));
	    			break;
	    		default:
		    		RHP_LOG_D(RHP_LOG_SRC_IKEV2,rlm_id,RHP_LOG_ID_IKE_SESS_RESUME_TKT_DUMP_PLAIN_RADIUS_TKT_ATTR_BIN,"dWWpa",i,attr->len,attr->type,(attr_len - sizeof(rhp_radius_sess_resume_tkt_attr)),(u8*)(attr + 1),(attr_len - sizeof(rhp_radius_sess_resume_tkt_attr)),(u8*)(attr + 1));
	    			break;
	    		}

	    		attr = (rhp_radius_sess_resume_tkt_attr*)(((u8*)attr) + attr_len);
	    	}
	  	}
		}
		err = 0;

	}else if( sess_res_tkt_len >= (int)sizeof(rhp_ikev2_sess_resume_tkt) ){

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,rlm_id,RHP_LOG_ID_IKE_SESS_RESUME_TKT_DUMP_ENC,"aWWQpp",4,sess_res_tkt->magic,sess_res_tkt->version,sess_res_tkt->len,sess_res_tkt->key_index,RHP_IKEV2_SESS_RESUME_TKT_ENC_IV_LEN,sess_res_tkt->enc_iv,sess_res_tkt_len,(u8*)sess_res_tkt);
		err = 0;

	}else{

		err = -EINVAL;
	}

error_dump:
	if( err ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,rlm_id,RHP_LOG_ID_IKE_SESS_RESUME_TKT_DUMP_ERR,"E",err);
	}
	return;
}


static rhp_ikev2_sess_resume_tkt* _rhp_ikev2_sess_resume_alloc_tkt(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_vpn_realm* rlm)
{
	int err = -EINVAL;
	rhp_ikev2_sess_resume_tkt* sess_res_tkt = NULL;
	rhp_ikev2_sess_resume_tkt_e* sess_res_tkt_e = NULL;
	int sess_res_tkt_len = sizeof(rhp_ikev2_sess_resume_tkt) + sizeof(rhp_ikev2_sess_resume_tkt_e);
	u8 *id_i_value = NULL, *id_r_value = NULL;
	u8 *alt_id_i_value = NULL, *alt_id_r_value = NULL;
	int id_i_len = 0, id_r_len = 0;
	int alt_id_i_len = 0, alt_id_r_len = 0;
	int id_i_type = 0, id_r_type = 0, eap_method = vpn->eap.eap_method;
	int alt_id_i_type = 0, alt_id_r_type = 0;
	rhp_eap_id* peer_eap_id_ref = NULL; // Don't free !
	u8* p;

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_ALLOC_TKT,"xxxdd",vpn,ikesa,rlm,vpn->sess_resume.auth_method_i_org,ikesa->peer_auth_method);

	if( vpn->origin_side != RHP_IKE_RESPONDER ){
		RHP_BUG("");
		return NULL;
	}

	{
		err = rhp_ikev2_id_value(&(vpn->peer_id),&id_i_value,&id_i_len,&id_i_type);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		if( !rhp_ikev2_is_null_auth_id(id_i_type) && id_i_len < 1 ){
			RHP_BUG("%d",id_r_len);
			err = -EINVAL;
			goto error;
		}
	}

	{
		err = rhp_ikev2_id_value(&(vpn->my_id),&id_r_value,&id_r_len,&id_r_type);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		if( !rhp_ikev2_is_null_auth_id(id_r_type) && id_r_len < 1 ){
			RHP_BUG("%d",id_r_len);
			err = -EINVAL;
			goto error;
		}
	}

	if( ikesa->keys.v2.sk_d_len < 1 ){
		RHP_BUG("%d",ikesa->keys.v2.sk_d_len);
		err = -EINVAL;
		goto error;
	}

	if( vpn->peer_id.alt_id ){

		err = rhp_ikev2_id_value(&(vpn->peer_id),&alt_id_i_value,&alt_id_i_len,&alt_id_i_type);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
	}

	if( vpn->my_id.alt_id ){

		err = rhp_ikev2_id_value(&(vpn->my_id),&alt_id_r_value,&alt_id_r_len,&alt_id_r_type);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
	}


	if( eap_method != RHP_PROTO_EAP_TYPE_NONE ){
		peer_eap_id_ref = &(vpn->eap.peer_id);
	}

	sess_res_tkt_len += id_i_len + id_r_len + ikesa->keys.v2.sk_d_len + alt_id_i_len + alt_id_r_len;
	sess_res_tkt_len += (peer_eap_id_ref ? peer_eap_id_ref->identity_len : 0);


	sess_res_tkt = (rhp_ikev2_sess_resume_tkt*)_rhp_malloc(sess_res_tkt_len);
	if( sess_res_tkt == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	memset(sess_res_tkt,0,sess_res_tkt_len);

	sess_res_tkt_e = (rhp_ikev2_sess_resume_tkt_e*)(sess_res_tkt + 1);

	sess_res_tkt->magic[0] = 'R';
	sess_res_tkt->magic[1] = 'K';
	sess_res_tkt->magic[2] = 'H';
	sess_res_tkt->magic[3] = 'P';
	sess_res_tkt->version = htons(RHP_IKEV2_SESS_RESUME_TKT_VERSION);
	sess_res_tkt->len = htons((u16)sess_res_tkt_len);
	sess_res_tkt->key_index = 0;

	sess_res_tkt_e->len = htons((u16)(sess_res_tkt_len - sizeof(rhp_ikev2_sess_resume_tkt)));
	sess_res_tkt_e->vpn_realm_id = _rhp_htonll((u64)vpn->vpn_realm_id);
	sess_res_tkt_e->vpn_realm_policy_index = _rhp_htonll((u64)rlm->sess_resume_policy_index);
	memcpy(sess_res_tkt_e->unique_id,vpn->unique_id,RHP_VPN_UNIQUE_ID_SIZE);

	sess_res_tkt_e->id_i_type = id_i_type;
	sess_res_tkt_e->alt_id_i_type = alt_id_i_type;
	sess_res_tkt_e->id_r_type = id_r_type;
	sess_res_tkt_e->alt_id_r_type = alt_id_r_type;

	if( eap_method != RHP_PROTO_EAP_TYPE_NONE ){
		sess_res_tkt_e->auth_method_i = RHP_PROTO_IKE_AUTHMETHOD_NONE;
	}else if( vpn->sess_resume.auth_method_i_org != RHP_PROTO_IKE_AUTHMETHOD_NONE ){
		sess_res_tkt_e->auth_method_i = vpn->sess_resume.auth_method_i_org;
	}else{
		sess_res_tkt_e->auth_method_i = ikesa->peer_auth_method;
	}

	sess_res_tkt_e->auth_method_r = 0;
	sess_res_tkt_e->eap_i_method = htons((u16)eap_method);

	memcpy(sess_res_tkt_e->init_spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
	memcpy(sess_res_tkt_e->resp_spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);

	{
		time_t now = _rhp_get_time();
		time_t exp_time = now + (time_t)rhp_gcfg_ikev2_sess_resume_ticket_lifetime;

		if( exp_time > ikesa->expire_hard ){
			exp_time = ikesa->expire_hard;
		}

		sess_res_tkt_e->expire_time = (int64_t)_rhp_htonll((u64)(_rhp_get_realtime() + (exp_time - now)));
	}

	sess_res_tkt_e->encr_id = htons(ikesa->encr->alg);
	sess_res_tkt_e->encr_key_bits = htons(ikesa->encr->alg_key_bits);
	sess_res_tkt_e->prf_id = htons(ikesa->prf->alg);
	sess_res_tkt_e->integ_id = htons(ikesa->integ_i->alg);
	sess_res_tkt_e->dhgrp_id = htons(ikesa->dh->grp);
	sess_res_tkt_e->sk_d_len = htons((u16)ikesa->keys.v2.sk_d_len);
	sess_res_tkt_e->id_i_len = htons((u16)id_i_len);
	sess_res_tkt_e->alt_id_i_len = htons((u16)alt_id_i_len);
	sess_res_tkt_e->id_r_len = htons((u16)id_r_len);
	sess_res_tkt_e->alt_id_r_len = htons((u16)alt_id_r_len);
	sess_res_tkt_e->eap_identity_len = htons((u16)(peer_eap_id_ref ? peer_eap_id_ref->identity_len : 0));

	p = (u8*)(sess_res_tkt_e + 1);
	if(ikesa->keys.v2.sk_d_len){
		memcpy(p,ikesa->keys.v2.sk_d,ikesa->keys.v2.sk_d_len);
		p += ikesa->keys.v2.sk_d_len;
	}
	if(id_i_len){
		memcpy(p,id_i_value,id_i_len);
		p += id_i_len;
	}
	if(alt_id_i_len){
		memcpy(p,alt_id_i_value,alt_id_i_len);
		p += alt_id_i_len;
	}
	if(id_r_len){
		memcpy(p,id_r_value,id_r_len);
		p += id_r_len;
	}
	if(alt_id_r_len){
		memcpy(p,alt_id_r_value,alt_id_r_len);
		p += alt_id_r_len;
	}
	if(peer_eap_id_ref){
		memcpy(p,peer_eap_id_ref->identity,peer_eap_id_ref->identity_len);
		p += peer_eap_id_ref->identity_len;
	}

	if(id_i_value){
		_rhp_free(id_i_value);
	}
	if(alt_id_i_value){
		_rhp_free(alt_id_i_value);
	}
	if(id_r_value){
		_rhp_free(id_r_value);
	}
	if(alt_id_r_value){
		_rhp_free(alt_id_r_value);
	}


	rhp_ikev2_sess_resume_tkt_dump("_rhp_ikev2_sess_resume_alloc_tkt",sess_res_tkt,1);
	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_ALLOC_TKT_RTRN,"xxxx",vpn,ikesa,rlm,sess_res_tkt);
	return sess_res_tkt;

error:
	if(id_i_value){
		_rhp_free(id_i_value);
	}
	if(alt_id_i_value){
		_rhp_free(alt_id_i_value);
	}
	if(id_r_value){
		_rhp_free(id_r_value);
	}
	if(alt_id_r_value){
		_rhp_free(alt_id_r_value);
	}
	if( sess_res_tkt ){
		_rhp_free(sess_res_tkt);
	}
	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_ALLOC_TKT_ERR,"xxx",vpn,ikesa,rlm);
	return NULL;
}

static rhp_radius_sess_ressume_tkt* _rhp_ikev2_sess_resume_radius_alloc_tkt(rhp_vpn* vpn)
{
	int len = sizeof(rhp_radius_sess_ressume_tkt);
	rhp_radius_access_accept_attrs* rx_accept_attrs = vpn->radius.rx_accept_attrs;
	rhp_radius_sess_ressume_tkt dmyh;
	rhp_radius_sess_ressume_tkt* radius_tkt = NULL;
	rhp_radius_sess_resume_tkt_attr* attr;
	int attrs_num = 0;

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_RADIUS_ALLOC_TKT,"x",vpn);

	memset(&dmyh,0,sizeof(rhp_radius_sess_ressume_tkt));


	dmyh.eap_method = htons((u16)vpn->radius.eap_method);
	dmyh.rx_accept_attrs_mask = _rhp_htonll(vpn->radius.rx_accept_attrs_mask);

	dmyh.session_timeout = htonl(rx_accept_attrs->session_timeout);
	dmyh.framed_mtu = htonl(rx_accept_attrs->framed_mtu);

	if( rx_accept_attrs->priv_realm_id &&
			rx_accept_attrs->priv_realm_id != RHP_VPN_REALM_ID_UNKNOWN ){

			dmyh.vpn_realm_id_by_radius = _rhp_htonll((u64)rx_accept_attrs->priv_realm_id);

	}else{

		dmyh.vpn_realm_id_by_radius = 0;
	}

	if( RHP_VPN_RADIUS_ATTRS_MASK(vpn,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_IPV4) &&
			!rhp_ip_addr_null(&(rx_accept_attrs->priv_internal_addr_ipv4)) ){

		dmyh.internal_addr_ipv4 = rx_accept_attrs->priv_internal_addr_ipv4.addr.v4;
		dmyh.internal_addr_ipv4_prefix = (u8)rx_accept_attrs->priv_internal_addr_ipv4.prefixlen;

	}else if( RHP_VPN_RADIUS_ATTRS_MASK(vpn,RHP_VPN_RADIUS_ATTRS_MASK_FRAMED_IP_V4) &&
						!rhp_ip_addr_null(&(rx_accept_attrs->framed_ipv4))){

		dmyh.internal_addr_ipv4 = rx_accept_attrs->framed_ipv4.addr.v4;
	}

	if( RHP_VPN_RADIUS_ATTRS_MASK(vpn,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_IPV6) &&
			!rhp_ip_addr_null(&(rx_accept_attrs->priv_internal_addr_ipv6)) ){

		memcpy(dmyh.internal_addr_ipv6,rx_accept_attrs->priv_internal_addr_ipv6.addr.v6,16);
		dmyh.internal_addr_ipv6_prefix = (u8)rx_accept_attrs->priv_internal_addr_ipv6.prefixlen;

	}else if( RHP_VPN_RADIUS_ATTRS_MASK(vpn,RHP_VPN_RADIUS_ATTRS_MASK_FRAMED_IP_V4) &&
						!rhp_ip_addr_null(&(rx_accept_attrs->framed_ipv6))){

		mempcpy(dmyh.internal_addr_ipv6,rx_accept_attrs->framed_ipv6.addr.v6,16);
	}

	if( RHP_VPN_RADIUS_ATTRS_MASK(vpn,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_DNS_V4) &&
			!rhp_ip_addr_null(&(rx_accept_attrs->priv_internal_dns_server_ipv4)) ){

		dmyh.internal_dns_server_ipv4 = rx_accept_attrs->priv_internal_dns_server_ipv4.addr.v4;

	}else if( RHP_VPN_RADIUS_ATTRS_MASK(vpn,RHP_VPN_RADIUS_ATTRS_MASK_MS_PRIMARY_DNS_SERVER_V4) &&
						!rhp_ip_addr_null(&(rx_accept_attrs->ms_primary_dns_server_ipv4))){

		dmyh.internal_dns_server_ipv4 = rx_accept_attrs->ms_primary_dns_server_ipv4.addr.v4;
	}

	if( RHP_VPN_RADIUS_ATTRS_MASK(vpn,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_DNS_V6) &&
			!rhp_ip_addr_null(&(rx_accept_attrs->priv_internal_dns_server_ipv6)) ){

		memcpy(dmyh.internal_dns_server_ipv6,rx_accept_attrs->priv_internal_dns_server_ipv6.addr.v6,16);

	}else if( RHP_VPN_RADIUS_ATTRS_MASK(vpn,RHP_VPN_RADIUS_ATTRS_MASK_DNS_IPV6_SERVER) &&
						!rhp_ip_addr_null(&(rx_accept_attrs->dns_server_ipv6))){

		mempcpy(dmyh.internal_dns_server_ipv6,rx_accept_attrs->dns_server_ipv6.addr.v6,16);
	}

	if( RHP_VPN_RADIUS_ATTRS_MASK(vpn,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_USER_INDEX) &&
			rx_accept_attrs->priv_user_index ){

		len += sizeof(rhp_radius_sess_resume_tkt_attr) + strlen(rx_accept_attrs->priv_user_index);
		attrs_num++;

	}else if( RHP_VPN_RADIUS_ATTRS_MASK(vpn,RHP_VPN_RADIUS_ATTRS_MASK_TUNNEL_CLIENT_AUTH_ID) &&
						rx_accept_attrs->tunnel_client_auth_id ){

		len += sizeof(rhp_radius_sess_resume_tkt_attr) + strlen(rx_accept_attrs->tunnel_client_auth_id);
		attrs_num++;
	}

	{
		rhp_string_list* role_string;

		role_string = rx_accept_attrs->tunnel_private_group_ids;
		while( role_string ){

			if( role_string->string ){
				len += sizeof(rhp_radius_sess_resume_tkt_attr) + strlen(role_string->string);
				attrs_num++;
			}

			role_string = role_string->next;
		}


		role_string = rx_accept_attrs->priv_realm_roles;
		while( role_string ){

			if( role_string->string ){
				len += sizeof(rhp_radius_sess_resume_tkt_attr) + strlen(role_string->string);
				attrs_num++;
			}

			role_string = role_string->next;
		}
	}


	{
		rhp_split_dns_domain* domain = rx_accept_attrs->priv_domain_names;

		while( domain ){

			if( domain->name ){
				len += sizeof(rhp_radius_sess_resume_tkt_attr) + strlen(domain->name);
				attrs_num++;
			}

			domain = domain->next;
		}
	}


	if( RHP_VPN_RADIUS_ATTRS_MASK(vpn,RHP_VPN_RADIUS_ATTRS_MASK_MS_PRIMARY_NBNS_SERVER_V4) &&
			!rhp_ip_addr_null(&(rx_accept_attrs->ms_primary_nbns_server_ipv4))){

		dmyh.internal_wins_server_ipv4 = rx_accept_attrs->ms_primary_nbns_server_ipv4.addr.v4;
	}

	{
		rhp_internal_route_map* rtmap_v4 = rx_accept_attrs->priv_internal_route_ipv4;

		while( rtmap_v4 ){

			if( !rhp_ip_addr_null(&(rtmap_v4->dest_addr)) ){
				len += sizeof(rhp_radius_sess_resume_tkt_attr) + 5;
				attrs_num++;
			}

			rtmap_v4 = rtmap_v4->next;
		}
	}

	{
		rhp_internal_route_map* rtmap_v6 = rx_accept_attrs->priv_internal_route_ipv6;

		while( rtmap_v6 ){

			if( !rhp_ip_addr_null(&(rtmap_v6->dest_addr)) ){
				len += sizeof(rhp_radius_sess_resume_tkt_attr) + 17;
				attrs_num++;
			}

			rtmap_v6 = rtmap_v6->next;
		}
	}

	if( RHP_VPN_RADIUS_ATTRS_MASK(vpn,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_GW_V4) &&
			!rhp_ip_addr_null(&(rx_accept_attrs->priv_internal_gateway_ipv4))){

		dmyh.internal_gateway_ipv4 = rx_accept_attrs->priv_internal_gateway_ipv4.addr.v4;
	}

	if( RHP_VPN_RADIUS_ATTRS_MASK(vpn,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_GW_V6) &&
			!rhp_ip_addr_null(&(rx_accept_attrs->priv_internal_gateway_ipv6))){

		memcpy(dmyh.internal_gateway_ipv6,rx_accept_attrs->priv_internal_gateway_ipv6.addr.v6,16);
	}


	dmyh.attrs_num = htons(attrs_num);
	dmyh.radius_tkt_len = htons((u16)len);


	radius_tkt = (rhp_radius_sess_ressume_tkt*)_rhp_malloc(len);
	if( radius_tkt == NULL ){
		RHP_BUG("");
		goto error;
	}

	memcpy(radius_tkt,&dmyh,sizeof(rhp_radius_sess_ressume_tkt));


	if( len > (int)sizeof(rhp_radius_sess_ressume_tkt) ){

		int slen;

		attr = (rhp_radius_sess_resume_tkt_attr*)(radius_tkt + 1);

		if( RHP_VPN_RADIUS_ATTRS_MASK(vpn,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_USER_INDEX) &&
				rx_accept_attrs->priv_user_index ){

			slen = strlen(rx_accept_attrs->priv_user_index);

			attr->type = htons(RHP_SESS_RESUME_RADIUS_ATTR_USER_INDEX);
			attr->len = htons(sizeof(rhp_radius_sess_resume_tkt_attr) + slen);
			memcpy((u8*)(attr + 1),rx_accept_attrs->priv_user_index,slen);

			attr = (rhp_radius_sess_resume_tkt_attr*)(((u8*)(attr + 1)) + slen);

		}else if( RHP_VPN_RADIUS_ATTRS_MASK(vpn,RHP_VPN_RADIUS_ATTRS_MASK_TUNNEL_CLIENT_AUTH_ID) &&
							rx_accept_attrs->tunnel_client_auth_id ){

			slen = strlen(rx_accept_attrs->tunnel_client_auth_id);

			attr->type = htons(RHP_SESS_RESUME_RADIUS_ATTR_USER_INDEX);
			attr->len = htons(sizeof(rhp_radius_sess_resume_tkt_attr) + slen);
			memcpy((u8*)(attr + 1),rx_accept_attrs->tunnel_client_auth_id,slen);

			attr = (rhp_radius_sess_resume_tkt_attr*)(((u8*)(attr + 1)) + slen);
		}

		{
			rhp_string_list* role_string;

			role_string = rx_accept_attrs->tunnel_private_group_ids;
			while( role_string ){

				if( role_string->string ){

					slen = strlen(role_string->string);

					attr->type = htons(RHP_SESS_RESUME_RADIUS_ATTR_TUNNEL_PRIVATE_GROUP_ID);
					attr->len = htons(sizeof(rhp_radius_sess_resume_tkt_attr) + slen);
					memcpy((u8*)(attr + 1),role_string->string,slen);

					attr = (rhp_radius_sess_resume_tkt_attr*)(((u8*)(attr + 1)) + slen);
				}

				role_string = role_string->next;
			}

			role_string = rx_accept_attrs->priv_realm_roles;
			while( role_string ){

				if( role_string->string ){

					slen = strlen(role_string->string);

					attr->type = htons(RHP_SESS_RESUME_RADIUS_ATTR_PRIV_REALM_ROLE);
					attr->len = htons(sizeof(rhp_radius_sess_resume_tkt_attr) + slen);
					memcpy((u8*)(attr + 1),role_string->string,slen);

					attr = (rhp_radius_sess_resume_tkt_attr*)(((u8*)(attr + 1)) + slen);
				}

				role_string = role_string->next;
			}
		}

		{
			rhp_split_dns_domain* domain = rx_accept_attrs->priv_domain_names;

			while( domain ){

				if( domain->name ){

					slen = strlen(domain->name);

					attr->type = htons(RHP_SESS_RESUME_RADIUS_ATTR_INTERNAL_DOMAIN_NAME);
					attr->len = htons(sizeof(rhp_radius_sess_resume_tkt_attr) + slen);
					memcpy((u8*)(attr + 1),domain->name,slen);

					attr = (rhp_radius_sess_resume_tkt_attr*)(((u8*)(attr + 1)) + slen);
				}

				domain = domain->next;
			}
		}

		{
			rhp_internal_route_map* rtmap_v4 = rx_accept_attrs->priv_internal_route_ipv4;

			while( rtmap_v4 ){

				if( !rhp_ip_addr_null(&(rtmap_v4->dest_addr)) ){

					attr->type = htons(RHP_SESS_RESUME_RADIUS_ATTR_INTERNAL_ROUTE_IPV4);
					attr->len = htons(sizeof(rhp_radius_sess_resume_tkt_attr) + 5);
					memcpy((u8*)(attr + 1),&(rtmap_v4->dest_addr.addr.v4),4);
					*(((u8*)(attr + 1)) + 4) = rtmap_v4->dest_addr.prefixlen;

					attr = (rhp_radius_sess_resume_tkt_attr*)(((u8*)(attr + 1)) + 5);
				}

				rtmap_v4 = rtmap_v4->next;
			}
		}

		{
			rhp_internal_route_map* rtmap_v6 = rx_accept_attrs->priv_internal_route_ipv6;

			while( rtmap_v6 ){

				if( !rhp_ip_addr_null(&(rtmap_v6->dest_addr)) ){

					attr->type = htons(RHP_SESS_RESUME_RADIUS_ATTR_INTERNAL_ROUTE_IPV6);
					attr->len = htons(sizeof(rhp_radius_sess_resume_tkt_attr) + 17);
					memcpy((u8*)(attr + 1),&(rtmap_v6->dest_addr.addr.v6),16);
					*(((u8*)(attr + 1)) + 16) = rtmap_v6->dest_addr.prefixlen;

					attr = (rhp_radius_sess_resume_tkt_attr*)(((u8*)(attr + 1)) + 17);
				}

				rtmap_v6 = rtmap_v6->next;
			}
		}
	}

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_RADIUS_ALLOC_TKT_RTRN,"xxdWWWQQJJ46bb46446p",vpn,radius_tkt,len,radius_tkt->radius_tkt_len,radius_tkt->eap_method,radius_tkt->attrs_num,radius_tkt->rx_accept_attrs_mask,radius_tkt->vpn_realm_id_by_radius,radius_tkt->session_timeout,radius_tkt->framed_mtu,radius_tkt->internal_addr_ipv4,radius_tkt->internal_addr_ipv6,radius_tkt->internal_addr_ipv4_prefix,radius_tkt->internal_addr_ipv6_prefix,radius_tkt->internal_dns_server_ipv4,radius_tkt->internal_dns_server_ipv6,radius_tkt->internal_wins_server_ipv4,radius_tkt->internal_gateway_ipv4,radius_tkt->internal_gateway_ipv6,ntohs(radius_tkt->radius_tkt_len),(u8*)radius_tkt);
	_RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
  if( _RHP_TRC_COND(_rhp_trc_user_id(),0) ){

  	if( ntohs(radius_tkt->radius_tkt_len) > sizeof(rhp_radius_sess_ressume_tkt) ){

    	attr = (rhp_radius_sess_resume_tkt_attr*)(radius_tkt + 1);
    	int i, n = ntohs(radius_tkt->attrs_num);

    	for( i = 0; i < n; i++){

    		u16 attr_len = ntohs(attr->len);

    		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_RADIUS_ALLOC_TKT_ATTR_DUMP,"xxdWWp",vpn,radius_tkt,i,attr->len,attr->type,attr_len,(u8*)attr);

    		attr = (rhp_radius_sess_resume_tkt_attr*)(((u8*)attr) + attr_len);
    	}
  	}
  }
	return radius_tkt;

error:
	if( radius_tkt ){
		_rhp_free(radius_tkt);
	}
	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_RADIUS_ALLOC_TKT_ERR,"x",vpn);
	return NULL;
}

static int _rhp_ikev2_sess_resume_ipc_tkt_enc_req(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikesa* old_ikesa)
{
	int err = -EINVAL;
	int ipc_req_len = sizeof(rhp_ipcmsg_sess_resume_enc_req);
	rhp_ipcmsg_sess_resume_enc_req* ipc_req = NULL;
	rhp_ikev2_sess_resume_tkt* sess_res_tkt = NULL;
	rhp_radius_sess_ressume_tkt* sess_res_radius_tkt = NULL;
	int sess_res_tkt_len = 0, sess_res_radius_tkt_len = 0;

	RHP_TRC(0,RHPTRCID_IKEV2_SES_RESUME_IPC_TKT_ENC_REQ,"xxLdGGd",vpn,ikesa,"IKE_SIDE",ikesa->side,ikesa->init_spi,ikesa->resp_spi,rhp_gcfg_ikev2_qcd_enabled);
	if( old_ikesa ){
		RHP_TRC(0,RHPTRCID_IKEV2_SES_RESUME_IPC_TKT_ENC_REQ_OLD_IKESA,"xLdGG",old_ikesa,"IKE_SIDE",old_ikesa->side,old_ikesa->init_spi,old_ikesa->resp_spi);
	}

	{
		rhp_vpn_realm* rlm = vpn->rlm;

		if( rlm == NULL ){
			RHP_BUG("");
			goto error;
		}

		RHP_LOCK(&(rlm->lock));

		if( !_rhp_atomic_read(&(rlm->is_active)) ){
			err = -EINVAL;
			RHP_UNLOCK(&(rlm->lock));
			RHP_TRC(0,RHPTRCID_IKEV2_SES_RESUME_IPC_TKT_ENC_REQ_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,old_ikesa,rlm);
			goto error;
		}

		sess_res_tkt = _rhp_ikev2_sess_resume_alloc_tkt(vpn,ikesa,rlm);
		if( sess_res_tkt == NULL ){
			RHP_BUG("");
			err = -EINVAL;
			RHP_UNLOCK(&(rlm->lock));
			goto error;
		}

		RHP_UNLOCK(&(rlm->lock));
	}

	sess_res_tkt_len = ntohs(sess_res_tkt->len);


	if( vpn->eap.eap_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS &&
			vpn->radius.rx_accept_attrs ){

		sess_res_radius_tkt = _rhp_ikev2_sess_resume_radius_alloc_tkt(vpn);
		if( sess_res_radius_tkt == NULL ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		sess_res_radius_tkt_len = ntohs(sess_res_radius_tkt->radius_tkt_len);
	}


	ipc_req_len += sess_res_tkt_len + sess_res_radius_tkt_len;

	ipc_req = (rhp_ipcmsg_sess_resume_enc_req*)_rhp_malloc(ipc_req_len);
	if( ipc_req == NULL ){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	memset(ipc_req,0,ipc_req_len);

	ipc_req->tag[0] = '#';
	ipc_req->tag[1] = 'I';
	ipc_req->tag[2] = 'M';
	ipc_req->tag[3] = 'S';

	ipc_req->type = RHP_IPC_SESS_RESUME_ENC_REQUEST;
	ipc_req->len = ipc_req_len;

	ipc_req->my_realm_id = vpn->vpn_realm_id;
	ipc_req->side = ikesa->side;

	if( (((u32*)ikesa->init_spi)[0] == 0 && ((u32*)ikesa->init_spi)[1] == 0) ||
			(((u32*)ikesa->resp_spi)[0] == 0 && ((u32*)ikesa->resp_spi)[1] == 0) ){
		RHP_BUG("");
	}

	if( ikesa->side == RHP_IKE_INITIATOR ){
		memcpy(ipc_req->spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
		memcpy(ipc_req->peer_spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
	}else{
		memcpy(ipc_req->spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
		memcpy(ipc_req->peer_spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
	}

	if( old_ikesa ){

		ipc_req->old_ikesa = 1;
		ipc_req->old_side = old_ikesa->side;

		if( old_ikesa->side == RHP_IKE_INITIATOR ){
			memcpy(ipc_req->old_spi,old_ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
			memcpy(ipc_req->old_peer_spi,old_ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
		}else{
			memcpy(ipc_req->old_spi,old_ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
			memcpy(ipc_req->old_peer_spi,old_ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
		}

	  if( !ikesa->qcd.my_token_enabled ){ // For a NEW ikesa.

	  	ipc_req->qcd_enabled = (rhp_gcfg_ikev2_qcd_enabled ? 1 : 0);

	  }else{

			RHP_TRC(0,RHPTRCID_IKEV2_SES_RESUME_IPC_TKT_ENC_REQ_SOMEBODY_ALREADY_GOT_MY_QCD_TKN_FOR_NEW_IKESA,"xxxd",vpn,ikesa,old_ikesa,ikesa->qcd.my_token_enabled);
	  }
	}

	ikesa->sess_resume.resp.ipc_txn_id = rhp_ikesa_new_ipc_txn_id();
	ipc_req->txn_id = ikesa->sess_resume.resp.ipc_txn_id;

	ipc_req->tkt_len = sess_res_tkt_len;
	memcpy((u8*)(ipc_req + 1),(u8*)sess_res_tkt,sess_res_tkt_len);

	ipc_req->radius_tkt_len = sess_res_radius_tkt_len;
	if( sess_res_radius_tkt_len ){
		memcpy(((u8*)(ipc_req + 1)) + sess_res_tkt_len,(u8*)sess_res_radius_tkt,sess_res_radius_tkt_len);
	}

	if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipc_req,ipc_req->len,0) < 0 ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
  }

	_rhp_free_zero(ipc_req,ipc_req->len);
	_rhp_free_zero(sess_res_tkt,ntohs(sess_res_tkt->len));

	RHP_TRC(0,RHPTRCID_IKEV2_SES_RESUME_IPC_TKT_ENC_REQ_RTRN,"xxxx",vpn,ikesa,old_ikesa,sess_res_tkt);
	return 0;

error:

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_SESS_RESUME_TKT_ENC_REQ_ERR,"VPPE",vpn,ikesa,old_ikesa,err);

	if( ipc_req ){
		_rhp_free_zero(ipc_req,ipc_req->len);
	}
	if( sess_res_tkt ){
		_rhp_free_zero(sess_res_tkt,ntohs(sess_res_tkt->len));
	}
	if( sess_res_radius_tkt ){
		_rhp_free_zero(sess_res_radius_tkt,ntohl(sess_res_radius_tkt->radius_tkt_len));
	}
	RHP_TRC(0,RHPTRCID_IKEV2_SES_RESUME_IPC_TKT_ENC_REQ_ERR,"xxxxE",vpn,ikesa,old_ikesa,sess_res_tkt,err);
	return err;
}

#define RHP_IKEV2_SESS_RESUME_TKT_LIFETIME_MARGIN		10 // (secs)
static void _rhp_ikev2_sess_resume_tkt_enc_rep_ipc_handler(rhp_ipcmsg** ipcmsg)
{
  int err = -EINVAL;
  rhp_ipcmsg_sess_resume_enc_rep* ipc_rep = NULL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_ikev2_mesg* rx_ikemesg = NULL;
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;
  rhp_ikesa* ikesa = NULL;
  rhp_ikesa* old_ikesa = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_ENC_REP_IPC_HANDLER,"xxd",ipcmsg,*ipcmsg,rhp_gcfg_ikev2_qcd_enabled);

  ipc_rep = (rhp_ipcmsg_sess_resume_enc_rep*)*ipcmsg;

  if( ipc_rep->len < sizeof(rhp_ipcmsg_sess_resume_enc_rep) ){
    RHP_BUG("%d < sizeof(rhp_ipcmsg_sess_resume_enc_rep)(%d)",ipc_rep->len,sizeof(rhp_ipcmsg_sess_resume_enc_rep));
    err = -EINVAL;
    goto error;
  }


  vpn_ref = rhp_vpn_ikesa_spi_get(ipc_rep->side,ipc_rep->spi);
  vpn = RHP_VPN_REF(vpn_ref);
  if( vpn == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_ENC_REP_IPC_HANDLER_NO_IKESA,"xLdG",ipcmsg,"IKE_SIDE",ipc_rep->side,ipc_rep->spi);
    err = -ENOENT;
    goto error;
  }

  RHP_LOCK(&(vpn->lock));

  if( !_rhp_atomic_read(&(vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_ENC_REP_IPC_HANDLER_IKESA_NOT_ACTIVE,"xx",ipcmsg,ikesa);
    err = -ENOENT;
    goto error;
  }

  if( ipc_rep->old_ikesa ){ // old_ikesa: Just rekeyed IKE SA.

    old_ikesa = vpn->ikesa_get(vpn,ipc_rep->old_side,ipc_rep->old_spi);
    if( old_ikesa == NULL ){
      RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_ENC_REP_IPC_HANDLER_NO_OLD_IKESA,"x",ipcmsg);
      err = -ENOENT;
      goto error;
    }else{
      RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_ENC_REP_IPC_HANDLER_GET_OLD_IKESA,"xx",ipcmsg,old_ikesa);
    }
  }

  ikesa = vpn->ikesa_get(vpn,ipc_rep->side,ipc_rep->spi);
  if( ikesa == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_ENC_REP_IPC_HANDLER_NO_IKESA,"x",ipcmsg);
    err = -ENOENT;
    goto error;
  }


  ikesa->busy_flag = 0;
	if( old_ikesa ){
		old_ikesa->busy_flag = 0;
	}

	{
		tx_ikemesg = ikesa->sess_resume.resp.pend_tx_ikemesg;
		ikesa->sess_resume.resp.pend_tx_ikemesg = NULL;

 		rx_ikemesg = ikesa->sess_resume.resp.pend_rx_ikemesg;
 		ikesa->sess_resume.resp.pend_rx_ikemesg = NULL;
	}

  if( tx_ikemesg == NULL || rx_ikemesg == NULL ){
  	RHP_BUG("");
    err = -EINVAL;
  	goto error;
  }

  if( ipc_rep->txn_id != ikesa->sess_resume.resp.ipc_txn_id ){
    RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_ENC_REP_IPC_HANDLER_IKESA_BAD_TXNID,"xxxqq",ipcmsg,vpn,ikesa,ipc_rep->txn_id,ikesa->sess_resume.resp.ipc_txn_id);
    err = -EINVAL;
    goto error;
  }


  if( ipc_rep->my_realm_id != vpn->vpn_realm_id ){
    RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_ENC_REP_IPC_HANDLER_REALM_BAD_ID,"xxxuu",ipcmsg,vpn,ikesa,ipc_rep->my_realm_id,vpn->vpn_realm_id);
    err = -EINVAL;
    goto error;
  }

  if( ipc_rep->result == 0 ){

  	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_ENC_REP_IPC_HANDLER_RESULT_ERR,"xxx",ipcmsg,vpn,ikesa);
    err = -EINVAL;

  }else{

    rhp_ikev2_payload* ikepayload = NULL;
    rhp_ikev2_sess_resume_tkt* sess_res_tkt = (rhp_ikev2_sess_resume_tkt*)(ipc_rep + 1);
    u32 tkt_lifetime = 0;

    if( ipc_rep->len <= sizeof(rhp_ipcmsg_sess_resume_enc_rep)
    										+ sizeof(rhp_ikev2_sess_resume_tkt) + sizeof(rhp_ikev2_sess_resume_tkt_e) ){
    	RHP_BUG("");
    	goto error;
    }

    if( ntohs(sess_res_tkt->len) <=
    		sizeof(rhp_ikev2_sess_resume_tkt) + sizeof(rhp_ikev2_sess_resume_tkt_e) ){
    	RHP_BUG("");
    	goto error;
    }

		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);

		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_TICKET_LT_OPAQUE);

		ikepayload->set_non_critical(ikepayload,1);

		tkt_lifetime
		= htonl((u32)(ipc_rep->expired_time - _rhp_get_realtime() - RHP_IKEV2_SESS_RESUME_TKT_LIFETIME_MARGIN));

		if( ikepayload->ext.n->set_data2(ikepayload,(int)sizeof(u32),(u8*)&tkt_lifetime,
					(int)ntohs(sess_res_tkt->len),(u8*)sess_res_tkt) ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}


		vpn->sess_resume.exec_sess_resume = 1;


	  if( !ikesa->qcd.my_token_enabled ){

	  	if( rhp_gcfg_ikev2_qcd_enabled && ipc_rep->qcd_enabled ){

				memcpy(ikesa->qcd.my_token,ipc_rep->my_qcd_token,RHP_IKEV2_QCD_TOKEN_LEN);

				ikesa->qcd.my_token_set_by_sess_resume = 1;
				ikesa->qcd.my_token_enabled = 1;

		  	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_ENC_REP_IPC_HANDLER_QCD_MY_TKN_ENABLED,"xxxd",ipcmsg,vpn,ikesa,ikesa->qcd.my_token_enabled);

			}else{

				ikesa->qcd.my_token_enabled = 0;
		  	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_ENC_REP_IPC_HANDLER_QCD_MY_TKN_DISABLED,"xxxd",ipcmsg,vpn,ikesa,ikesa->qcd.my_token_enabled);
			}

	  }else{

	    //
	  	// ikesa->qcd.my_token_enabled is already set by RHP_IKEV2_MESG_HANDLER_IKESA_AUTH handler.
	    //
	  	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_ENC_REP_IPC_HANDLER_QCD_MY_TKN_ENABLED_BY_AUTH,"xxxd",ipcmsg,vpn,ikesa,ikesa->qcd.my_token_enabled);
	  }

  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_TX_IKE_SESS_RESUME_TKT_LT_OPAQUE,"KVJ",rx_ikemesg,vpn,tkt_lifetime);

/*
  	if( rhp_gcfg_dbg_log_keys_info ){
  		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_TX_IKE_SESS_RESUME_TKT_LT_OPAQUE_DATA,"Jp",tkt_lifetime,sess_res_tkt->len,(u8*)sess_res_tkt);
  	}
*/
	  rhp_ikev2_sess_resume_tkt_log_dump(vpn->vpn_realm_id,sess_res_tkt,0);
  }


error:

  if( vpn ){

  	time_t old_ikesa_dt = 0;

  	if( rx_ikemesg && tx_ikemesg && ikesa ){

  		int side = (ipc_rep->old_ikesa ? ipc_rep->old_side : ipc_rep->side);
  		u8* spi = (ipc_rep->old_ikesa ? ipc_rep->old_spi : ipc_rep->spi);

    	rhp_ikev2_call_next_rx_request_mesg_handlers(rx_ikemesg,vpn,
    			side,spi,tx_ikemesg,RHP_IKEV2_MESG_HANDLER_SESS_RESUME_TKT);


    	if( old_ikesa ){

      	old_ikesa_dt = rhp_vpn_lifetime_random(10);

        old_ikesa->timers->schedule_delete(vpn,old_ikesa,old_ikesa_dt);
    	}

    	err = 0;
		}

		RHP_UNLOCK(&(vpn->lock));
		rhp_vpn_unhold(vpn_ref);
  }

  if( err ){
  	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_SESS_RESUME_TKT_ENC_ERR,"KVE",rx_ikemesg,vpn,err);
  }

	if( tx_ikemesg ){
		rhp_ikev2_unhold_mesg(tx_ikemesg);
	}

	if( rx_ikemesg ){
		rhp_ikev2_unhold_mesg(rx_ikemesg);
	}

  _rhp_free_zero(ipc_rep,ipc_rep->len);
  *ipcmsg = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_ENC_REP_IPC_HANDLER_RTRN,"xxxxxE",ipcmsg,vpn,ikesa,tx_ikemesg,rx_ikemesg,err);
  return;
}

static int _rhp_ikev2_rx_sess_resume_tkt_req_r(rhp_ikev2_mesg* rx_req_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err = -EINVAL;
	rhp_ikesa* ikesa = NULL;
	rhp_ikesa* old_ikesa = NULL;
	u8 exchange_type = rx_req_ikemesg->get_exchange_type(rx_req_ikemesg);
	int is_rekey_exchg = 0;
	rhp_sess_rsm_srch_plds_ctx s_pld_ctx;

  RHP_TRC(0,RHPTRCID_RX_IKEV2_SESS_RESUME_TKT_REQ_R,"xxLdGxLddd",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_resp_ikemesg,"PROTO_IKE_EXCHG",exchange_type,rhp_gcfg_ikev2_sess_resume_init_enabled,rhp_gcfg_ikev2_sess_resume_resp_enabled);

	memset(&s_pld_ctx,0,sizeof(rhp_sess_rsm_srch_plds_ctx));

	s_pld_ctx.vpn = vpn;

  if( !rhp_gcfg_ikev2_sess_resume_resp_enabled ){
    RHP_TRC(0,RHPTRCID_RX_IKEV2_SESS_RESUME_TKT_REQ_R_RESP_DISABLED,"xx",rx_req_ikemesg,vpn);
  	return 0;
  }


	if( vpn->origin_side != RHP_IKE_RESPONDER ){
		RHP_TRC(0,RHPTRCID_RX_IKEV2_SESS_RESUME_TKT_REQ_R_PEER_IS_NOT_INITIATOR_2,"xxxLdLd",rx_req_ikemesg,tx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,"IKE_SIDE",vpn->origin_side);
		err = 0;
		goto error;
	}

  if( exchange_type != RHP_PROTO_IKE_EXCHG_IKE_AUTH &&
  		exchange_type != RHP_PROTO_IKE_EXCHG_INFORMATIONAL &&
  	 !(is_rekey_exchg = (exchange_type == RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA && rx_req_ikemesg->for_ikesa_rekey)) ){
    RHP_TRC(0,RHPTRCID_RX_IKEV2_SESS_RESUME_TKT_REQ_R_NOT_INTERESTED_EXCHG_TYPE,"xxd",rx_req_ikemesg,vpn,is_rekey_exchg);
  	err = 0;
		goto error;
	}

  if( !rx_req_ikemesg->decrypted ){
    RHP_TRC(0,RHPTRCID_RX_IKEV2_SESS_RESUME_TKT_REQ_R_NOT_ENC_PKT,"xxx",rx_req_ikemesg,rx_req_ikemesg->rx_pkt,vpn);
  	err = 0;
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

			RHP_TRC(0,RHPTRCID_RX_IKEV2_SESS_RESUME_TKT_REQ_R_IKESA_GET_NEW_IKESA,"xxxxdLd",rx_req_ikemesg,tx_resp_ikemesg,vpn,ikesa,is_rekey_exchg,"IKESA_STAT",ikesa->state);

			err = 0;
			old_ikesa = ikesa;
			ikesa = NULL;
		}
	}

	if( ikesa == NULL && is_rekey_exchg ){

		ikesa = vpn->ikesa_get(vpn,rx_req_ikemesg->rekeyed_ikesa_my_side,rx_req_ikemesg->rekeyed_ikesa_my_spi);
	}

	if( ikesa == NULL ){
		RHP_TRC(0,RHPTRCID_RX_IKEV2_SESS_RESUME_TKT_REQ_R_IKESA_NO_IKESA,"xxxd",rx_req_ikemesg,tx_resp_ikemesg,vpn,is_rekey_exchg);
		err = 0;
		goto error;
	}

	if( ikesa->state != RHP_IKESA_STAT_ESTABLISHED ){
		RHP_TRC(0,RHPTRCID_RX_IKEV2_SESS_RESUME_TKT_REQ_R_IKESA_BAD_STATE,"xxxxxdLd",rx_req_ikemesg,tx_resp_ikemesg,vpn,ikesa,old_ikesa,is_rekey_exchg,"IKESA_STAT",ikesa->state);
		err = 0;
		goto error;
	}



	{
		s_pld_ctx.dup_flag = 0;
		u16 sess_rsm_n_ids[2] = { RHP_PROTO_IKE_NOTIFY_ST_TICKET_REQUEST,
														 RHP_PROTO_IKE_NOTIFY_RESERVED};

		err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
						rhp_ikev2_mesg_srch_cond_n_mesg_ids,sess_rsm_n_ids,
						_rhp_ikev2_sess_resume_srch_n_tkt_req_cb,&s_pld_ctx);

		if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
			RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_TKT_REQ_SRCH_PLD_ERR,"xxxxE",rx_req_ikemesg,vpn,ikesa,tx_resp_ikemesg,err);
			goto error;
		}
		err = 0;
	}

	if( !s_pld_ctx.rx_tkt_req ){
		err = 0;
		RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_TKT_REQ_NOT_TKT_REQ,"xxxx",rx_req_ikemesg,vpn,ikesa,tx_resp_ikemesg);
		goto error;
	}


	err = _rhp_ikev2_sess_resume_ipc_tkt_enc_req(vpn,ikesa,old_ikesa);
	if( err ){
		RHP_TRC(0,RHPTRCID_RX_IKEV2_SESS_RESUME_TKT_REQ_R_TKT_ENC_ERR,"xxxxxdE",rx_req_ikemesg,tx_resp_ikemesg,vpn,ikesa,old_ikesa,is_rekey_exchg,err);
		goto error;
	}

	{
		ikesa->sess_resume.resp.pend_rx_ikemesg = rx_req_ikemesg;
		rhp_ikev2_hold_mesg(rx_req_ikemesg);

		ikesa->sess_resume.resp.pend_tx_ikemesg = tx_resp_ikemesg;
		rhp_ikev2_hold_mesg(tx_resp_ikemesg);
	}

	ikesa->busy_flag = 1;

	if( old_ikesa ){

		old_ikesa->busy_flag = 1;

		old_ikesa->timers->quit_lifetime_timer(vpn,old_ikesa);
	}

  err = RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;

error:
	if( err && err != RHP_STATUS_IKEV2_MESG_HANDLER_PENDING ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_SESS_RESUME_TKT_REQ_ERR,"KE",rx_req_ikemesg,err);
	}
	RHP_TRC(0,RHPTRCID_RX_IKEV2_SESS_RESUME_TKT_REQ_R_RTRN,"xxxxxdE",rx_req_ikemesg,tx_resp_ikemesg,vpn,ikesa,old_ikesa,is_rekey_exchg,err);
  return err;
}


static int _rhp_ikev2_rx_sess_resume_tkt_req_i(rhp_ikev2_mesg* rx_req_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err = -EINVAL;
	rhp_ikesa* rekeyd_ikesa = NULL;
	u8 exchange_type = rx_req_ikemesg->get_exchange_type(rx_req_ikemesg);
	int doit = 0;

  RHP_TRC(0,RHPTRCID_RX_IKEV2_SESS_RESUME_TKT_REQ_I,"xxLdGxLddddd",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_resp_ikemesg,"PROTO_IKE_EXCHG",exchange_type,rhp_gcfg_ikev2_sess_resume_init_enabled,rhp_gcfg_ikev2_sess_resume_resp_enabled,vpn->sess_resume.exec_sess_resume,vpn->sess_resume.tkt_req_pending);

  if( !rhp_gcfg_ikev2_sess_resume_init_enabled ){
    RHP_TRC(0,RHPTRCID_RX_IKEV2_SESS_RESUME_TKT_REQ_I_INIT_DISABLED,"xx",rx_req_ikemesg,vpn);
  	return 0;
  }

  if( !vpn->sess_resume.exec_sess_resume ){
		err = 0;
    RHP_TRC(0,RHPTRCID_RX_IKEV2_SESS_RESUME_TKT_REQ_I_SESS_RESUME_DONT_EXEC,"xx",rx_req_ikemesg,vpn);
		goto error;
  }

  if( vpn->sess_resume.tkt_req_pending ){
		err = 0;
    RHP_TRC(0,RHPTRCID_RX_IKEV2_SESS_RESUME_TKT_REQ_I_SESS_RESUME_REQ_TKT_IS_PENDING,"xx",rx_req_ikemesg,vpn);
		goto error;
  }

	if( vpn->origin_side != RHP_IKE_INITIATOR ){
		RHP_TRC(0,RHPTRCID_RX_IKEV2_SESS_RESUME_TKT_REQ_I_PEER_IS_NOT_ORIGIN_INITIATOR,"xxxLdLd",rx_req_ikemesg,tx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,"IKE_SIDE",vpn->origin_side);
		err = 0;
		goto error;
	}


	if( exchange_type != RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA ||
			!rx_req_ikemesg->for_ikesa_rekey ){
		RHP_TRC(0,RHPTRCID_RX_IKEV2_SESS_RESUME_TKT_REQ_I_NOT_IKESA_REKEY_EXCHG,"xxxLdLd",rx_req_ikemesg,tx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,"IKE_SIDE",vpn->origin_side);
		err = 0;
		goto error;
	}

  if( !rx_req_ikemesg->decrypted ){
    RHP_TRC(0,RHPTRCID_RX_IKEV2_SESS_RESUME_TKT_REQ_I_NOT_ENC_PKT,"xxx",rx_req_ikemesg,rx_req_ikemesg->rx_pkt,vpn);
  	err = 0;
  	goto error;
  }

	if( my_ikesa_spi == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }


	rekeyd_ikesa = vpn->ikesa_get(vpn,rx_req_ikemesg->rekeyed_ikesa_my_side,rx_req_ikemesg->rekeyed_ikesa_my_spi);
	if( rekeyd_ikesa == NULL ){
		err = -ENOENT;
	  RHP_TRC(0,RHPTRCID_RX_IKEV2_SESS_RESUME_TKT_REQ_I_NO_IKESA,"xxLdGLdG",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,rx_req_ikemesg->rekeyed_ikesa_my_side,rx_req_ikemesg->rekeyed_ikesa_my_spi);
		goto error;
	}

	if( rekeyd_ikesa->state != RHP_IKESA_STAT_ESTABLISHED ){
		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_RX_IKEV2_SESS_RESUME_TKT_REQ_I_IKESA_BAD_STATE,"xxxxLd",rx_req_ikemesg,tx_resp_ikemesg,vpn,rekeyd_ikesa,"IKESA_STAT",rekeyd_ikesa->state);
		goto error;
	}

	{
	  rhp_ikev2_mesg* tx_new_ikemesg = rhp_ikev2_tx_new_req_get(vpn,
	  		rx_req_ikemesg->rekeyed_ikesa_my_side,rx_req_ikemesg->rekeyed_ikesa_my_spi);

	  if( tx_new_ikemesg ){

			rhp_ikev2_payload* ikepayload = NULL;

		 	err = rhp_ikev2_new_payload_tx(tx_new_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload);
		 	if( err ){

  			RHP_BUG("%d",err);

		 		err = -ENOMEM;

		 		rhp_ikev2_unhold_mesg(tx_new_ikemesg);
		    goto error;
		 	}

		 	tx_new_ikemesg->put_payload(tx_new_ikemesg,ikepayload);

		 	ikepayload->ext.n->set_protocol_id(ikepayload,0);

		 	ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_TICKET_REQUEST);

	  	vpn->sess_resume.tkt_req_pending = 1;
	  	doit = 1;

	  }else{

	  	RHP_BUG("");

	 		err = -ENOMEM;
	  	goto error;
	  }
	}

error:
	if( err ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_SESS_RESUME_TKT_REQ_I_ERR,"KVPE",rx_req_ikemesg,vpn,rekeyd_ikesa,err);
	}else if( doit ){
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_SESS_RESUME_TKT_REQ_I,"KVP",rx_req_ikemesg,vpn,rekeyd_ikesa);
	}

	RHP_TRC(0,RHPTRCID_RX_IKEV2_SESS_RESUME_TKT_REQ_I_RTRN,"xxxxE",rx_req_ikemesg,tx_resp_ikemesg,vpn,rekeyd_ikesa,err);
	return 0;
}


int rhp_ikev2_rx_sess_resume_tkt_req(rhp_ikev2_mesg* rx_req_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err = -EINVAL;

	if( vpn->origin_side == RHP_IKE_INITIATOR ){

		err = _rhp_ikev2_rx_sess_resume_tkt_req_i(rx_req_ikemesg,vpn,my_ikesa_side,my_ikesa_spi,tx_resp_ikemesg);

	}else{

		err = _rhp_ikev2_rx_sess_resume_tkt_req_r(rx_req_ikemesg,vpn,my_ikesa_side,my_ikesa_spi,tx_resp_ikemesg);
	}

	return err;
}

int rhp_ikev2_rx_sess_resume_tkt_rep(rhp_ikev2_mesg* rx_resp_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err = -EINVAL;
	u8 rx_exchange_type = rx_resp_ikemesg->get_exchange_type(rx_resp_ikemesg);
	u8 tx_exchange_type = tx_req_ikemesg->get_exchange_type(tx_req_ikemesg);
	u32 tx_mesg_id = tx_req_ikemesg->get_mesg_id(tx_req_ikemesg);
	rhp_ikesa* ikesa = NULL;
	int nop = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_TKT_REP,"xxLdGxLdLdddud",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_req_ikemesg,"PROTO_IKE_EXCHG",rx_exchange_type,"PROTO_IKE_EXCHG",tx_exchange_type,rhp_gcfg_ikev2_sess_resume_init_enabled,rhp_gcfg_ikev2_sess_resume_resp_enabled,tx_mesg_id,vpn->sess_resume.tkt_req_pending);

	if( !rhp_gcfg_ikev2_sess_resume_init_enabled ){
		return 0;
	}


	if( vpn->origin_side != RHP_IKE_INITIATOR ){
		RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_TKT_REP_PEER_IS_NOT_RESPONDER_2,"xxxLdLd",rx_resp_ikemesg,tx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,"IKE_SIDE",vpn->origin_side);
		nop = 1;
		err = 0;
		goto error;
	}

	if( ( rx_exchange_type == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ||
			  rx_exchange_type == RHP_PROTO_IKE_EXCHG_SESS_RESUME ) &&
				tx_exchange_type == RHP_PROTO_IKE_EXCHG_IKE_AUTH &&
				tx_mesg_id == 1 ){

		rhp_ikev2_payload* ikepayload = NULL;

	 	err = rhp_ikev2_new_payload_tx(tx_req_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload);
	 	if( err ){
	 		RHP_BUG("");
	    goto error;
	 	}

	 	tx_req_ikemesg->put_payload(tx_req_ikemesg,ikepayload);

	 	ikepayload->ext.n->set_protocol_id(ikepayload,0);

	 	ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_TICKET_REQUEST);

	 	vpn->sess_resume.tkt_req_pending = 1;

	}else if( vpn->sess_resume.tkt_req_pending &&
			      (rx_exchange_type == RHP_PROTO_IKE_EXCHG_IKE_AUTH ||
			       rx_exchange_type == RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA ||
			       rx_exchange_type == RHP_PROTO_IKE_EXCHG_INFORMATIONAL ) ){

	  if( !rx_resp_ikemesg->decrypted ){
			RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_TKT_REP_NOT_ENC_PKT,"xxx",rx_resp_ikemesg,rx_resp_ikemesg->rx_pkt,vpn);
	  	err = 0;
	  	goto error;
	  }

		if( my_ikesa_spi == NULL ){
	    RHP_BUG("");
	    err = -EINVAL;
	    goto error;
	  }

	  if( rx_exchange_type == RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA &&
  			rx_resp_ikemesg->for_ikesa_rekey ){

	  	if( rx_resp_ikemesg->rekeyed_ikesa_my_spi == NULL ){
		    RHP_BUG("");
		    err = -EINVAL;
		    goto error;
	  	}

			RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_TKT_REP_GET_NEW_IKESA,"xxxLdG",rx_resp_ikemesg,tx_req_ikemesg,vpn,"IKESA_SIDE",rx_resp_ikemesg->rekeyed_ikesa_my_side,rx_resp_ikemesg->rekeyed_ikesa_my_spi);

			ikesa = vpn->ikesa_get(vpn,
								rx_resp_ikemesg->rekeyed_ikesa_my_side,
								rx_resp_ikemesg->rekeyed_ikesa_my_spi);

	  }else{

	  	ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
	  }

		if( ikesa == NULL ){
			RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_TKT_REP_NO_IKESA,"xxx",rx_resp_ikemesg,tx_req_ikemesg,vpn);
			err = 0;
			goto error;
		}

		if( ikesa->state != RHP_IKESA_STAT_ESTABLISHED ){
			RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_TKT_REP_BAD_IKESA_STATE,"xxxxLd",rx_resp_ikemesg,tx_req_ikemesg,vpn,ikesa,"IKESA_STAT",ikesa->state);
			err = 0;
			goto error;
		}

		err = _rhp_ikev2_rx_sess_resume_tkt_rep(rx_resp_ikemesg,vpn,ikesa,tx_req_ikemesg);
		if( err ){
			goto error;
		}

	}else{

		RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_TKT_REP_NOT_INTERESTED,"xxx",rx_resp_ikemesg,tx_req_ikemesg,vpn);

		nop = 1;
		err = 0;
		goto error;
	}

error:
	if( err ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_SESS_RESUME_TKT_REP_ERR,"KE",rx_resp_ikemesg,err);
	}else if( !nop ){
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_IKE_SESS_RESUME_TKT_REP,"K",rx_resp_ikemesg);
	}
	RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_TKT_REP_RTRN,"xxxxE",rx_resp_ikemesg,tx_req_ikemesg,vpn,ikesa,err);
	return err;
}



struct _rhp_ikev2_sess_resume_tx_err_ctx {
	u16 notify_mesg_type;
	unsigned long arg0;
};
typedef struct _rhp_ikev2_sess_resume_tx_err_ctx	rhp_ikev2_sess_resume_tx_err_ctx;

static int rhp_ikev2_sess_resume_tx_error_rep_plds_cb(rhp_ikev2_mesg* tx_ikemesg,void* ctx)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;
  rhp_ikev2_sess_resume_tx_err_ctx* plds_cb_ctx = (rhp_ikev2_sess_resume_tx_err_ctx*)ctx;

  if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
    RHP_BUG("");
    goto error;
  }

  tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

  ikepayload->ext.n->set_protocol_id(ikepayload,0);
  ikepayload->ext.n->set_message_type(ikepayload,plds_cb_ctx->notify_mesg_type);

  switch( plds_cb_ctx->notify_mesg_type ){

  case RHP_PROTO_IKE_NOTIFY_ST_TICKET_NACK:
    break;

  case RHP_PROTO_IKE_NOTIFY_ST_COOKIE:
  {
   u8* cookie = (u8*)plds_cb_ctx->arg0;
   if( ikepayload->ext.n->set_data(ikepayload,RHP_IKEV2_COOKIE_LEN,cookie) ){
     RHP_BUG("");
     goto error;
    }
  }
    break;

  default:
    RHP_BUG("%d",plds_cb_ctx->notify_mesg_type);
    goto error;
  }

  return 0;

error:
	return err;
}

static int _rhp_ikev2_sess_resume_tx_error_rep(rhp_ikev2_mesg* rx_ikemesg,
		u16 notify_mesg_type,unsigned long arg0)
{
  int err = -EINVAL;
  union {
  	rhp_proto_ip_v4* v4;
  	rhp_proto_ip_v6* v6;
  	u8* raw;
  } iph_i;
  rhp_proto_udp* udph_i;
  rhp_proto_ike* ikeh_i;
  rhp_ifc_entry* rx_ifc;
  rhp_ikev2_sess_resume_tx_err_ctx pld_cb_ctx;

  RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TX_ERR_R,"xLwu",rx_ikemesg,"PROTO_IKE_NOTIFY",notify_mesg_type,arg0);

	iph_i.raw = rx_ikemesg->rx_pkt->l3.raw;
  udph_i = rx_ikemesg->rx_pkt->l4.udph;
  ikeh_i = rx_ikemesg->rx_pkt->app.ikeh;
  rx_ifc = rx_ikemesg->rx_pkt->rx_ifc;

  memset(&pld_cb_ctx,0,sizeof(rhp_ikev2_sess_resume_tx_err_ctx));
  pld_cb_ctx.notify_mesg_type = notify_mesg_type;
  pld_cb_ctx.arg0 = arg0;

  if( rx_ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE ){

  	err = rhp_ikev2_tx_plain_error_rep_v4(iph_i.v4,udph_i,ikeh_i,rx_ifc,
  			rhp_ikev2_sess_resume_tx_error_rep_plds_cb,(void*)&pld_cb_ctx);

  }else if( rx_ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE ){

  	err = rhp_ikev2_tx_plain_error_rep_v6(iph_i.v6,udph_i,ikeh_i,rx_ifc,
  			rhp_ikev2_sess_resume_tx_error_rep_plds_cb,(void*)&pld_cb_ctx);

  }else{
  	RHP_BUG("");
  	err = -EINVAL;
  }
  if( err ){
  	goto error;
  }


	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_SESS_RESUME_TX_ERR_NOTIFY,"KL",rx_ikemesg,"PROTO_IKE_NOTIFY",notify_mesg_type);

  RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TX_ERR_R_RTRN,"x",rx_ikemesg);
  return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_SESS_RESUME_TX_ERR_NOTIFY_FAILED,"KLE",rx_ikemesg,"PROTO_IKE_NOTIFY",notify_mesg_type,err);

  RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TX_ERR_R_ERR,"xE",rx_ikemesg,err);
  return err;
}



#ifdef RHP_PKT_DBG_IKEV2_BAD_TKT_TEST

#define RHP_IKEV2_TEST_BAD_TKT_TX_TIMES		2
static int _rhp_ikev2_test_bad_tkt_tx_times =	0;

void rhp_ikev2_test_bad_tkt(rhp_vpn* vpn,rhp_ikesa* ikesa,u8* tkt,int tkt_len,u8** pt_r)
{
	u8* pt = NULL;

	if( tkt_len <= 1 || tkt == NULL ){
		RHP_BUG("");
		return;
	}

	if( _rhp_ikev2_test_bad_tkt_tx_times >= RHP_IKEV2_TEST_BAD_TKT_TX_TIMES ){
		_rhp_ikev2_test_bad_tkt_tx_times = 0;
		return;
	}

	if( tkt[0] == 'R' && tkt[1] == 'K' && tkt[2] == 'H' && tkt[3] == 'P'  ){

		rhp_ikev2_sess_resume_tkt* sess_resume_tkt = (rhp_ikev2_sess_resume_tkt*)tkt;

		pt = &(((u8*)(sess_resume_tkt + 1))[63]);
		*pt <<= 1;

	}else{

		pt = tkt;
		*pt <<= 1;
	}

	_rhp_ikev2_test_bad_tkt_tx_times++;
	*pt_r = pt;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_IKE_SA_INIT_I_COOKIE_COOKIE_DATA_TX_BAD_TKT,"dxxxxbp",_rhp_ikev2_test_bad_tkt_tx_times,vpn,vpn->rlm,ikesa,pt,*pt,tkt_len,tkt);

	return;
}

void rhp_ikev2_test_bad_tkt_bh(u8* pt)
{
	if( pt ){
		*pt >>= 1;
	}
	return;
}

#endif // RHP_PKT_DBG_IKEV2_BAD_TKT_TEST



rhp_ikev2_mesg* rhp_ikev2_new_pkt_sess_resume_req(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_vpn_sess_resume_material* sess_resume_material_i,int cookie_len,u8* cookie)
{
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_SESS_RESUME_REQ,"xxxp",vpn,ikesa,sess_resume_material_i,cookie_len,cookie);

  if( sess_resume_material_i == NULL ){
  	RHP_BUG("");
    goto error;
  }


  tx_ikemesg = rhp_ikev2_new_mesg_tx(RHP_PROTO_IKE_EXCHG_SESS_RESUME,0,0);
  if( tx_ikemesg == NULL ){
    RHP_BUG("");
    goto error;
  }

  if( cookie ){

    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    ikepayload->ext.n->set_protocol_id(ikepayload,0);

    ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_COOKIE);

    if( ikepayload->ext.n->set_data(ikepayload,cookie_len,cookie) ){
    	RHP_BUG("");
    	goto error;
    }
  }

  {
    int nonce_len = ikesa->nonce_i->get_nonce_len(ikesa->nonce_i);
    u8* nonce = ikesa->nonce_i->get_nonce(ikesa->nonce_i);

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
    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    ikepayload->ext.n->set_protocol_id(ikepayload,0);

    ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_TICKET_OPAQUE);

#ifdef RHP_PKT_DBG_IKEV2_BAD_TKT_TEST
    {
    	u8* pt = NULL;
    	rhp_ikev2_test_bad_tkt(vpn,ikesa,sess_resume_material_i->peer_tkt_r,sess_resume_material_i->peer_tkt_r_len,&pt);
#endif // RHP_PKT_DBG_IKEV2_BAD_TKT_TEST

    if( ikepayload->ext.n->set_data(ikepayload,
    		sess_resume_material_i->peer_tkt_r_len,sess_resume_material_i->peer_tkt_r) ){
    	RHP_BUG("");
    	goto error;
    }

#ifdef RHP_PKT_DBG_IKEV2_BAD_TKT_TEST
    	rhp_ikev2_test_bad_tkt_bh(pt);
    }
#endif // RHP_PKT_DBG_IKEV2_BAD_TKT_TEST
  }


  if( rhp_gcfg_ikev2_enable_fragmentation ){

		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);
		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_FRAG_SUPPORTED);

		ikepayload->set_non_critical(ikepayload,1);
  }


  {
    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_V,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    if( ikepayload->ext.vid->copy_my_app_vid(ikepayload) ){
      RHP_BUG("");
      goto error;
    }
  }

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_SESS_RESUME_REQ_RTRN,"xx",ikesa,tx_ikemesg);

  return tx_ikemesg;

error:
  if( tx_ikemesg ){
    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKEV2_TX_ALLOC_SESS_RESUME_REQ_ERR,"P",ikesa);
  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_SESS_RESUME_REQ_ERR,"x",ikesa);
  return NULL;
}

static int _rhp_ikev2_sess_resume_tkt_dec_check(rhp_ikev2_sess_resume_tkt* sess_res_tkt,
		rhp_ikev2_sess_resume_tkt_e* sess_res_tkt_e,rhp_vpn* larval_vpn,rhp_ikesa* ikesa)
{
	int err = -EINVAL;
	rhp_vpn_realm* rlm = NULL;
	unsigned long rlm_id;

  RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_DEC_CHECK,"xxxxppWLw",sess_res_tkt,sess_res_tkt_e,larval_vpn,ikesa,sizeof(rhp_ikev2_sess_resume_tkt),sess_res_tkt,sizeof(rhp_ikev2_sess_resume_tkt_e),sess_res_tkt_e,sess_res_tkt_e->radius_info_len,"EAP_TYPE",ntohs(sess_res_tkt_e->eap_i_method));
//  rhp_ikev2_sess_resume_tkt_dump("_rhp_ikev2_sess_resume_tkt_dec_check",sess_res_tkt,1);


  if( ntohs(sess_res_tkt_e->eap_i_method) == RHP_PROTO_EAP_TYPE_PRIV_RADIUS ){

		RHP_LOCK(&rhp_eap_radius_cfg_lock);

		if( !rhp_gcfg_eap_radius->enabled ){

			RHP_UNLOCK(&rhp_eap_radius_cfg_lock);

			err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_RADIUS_TKT;
			goto error;
		}

		RHP_UNLOCK(&rhp_eap_radius_cfg_lock);
  }


  if( sess_res_tkt_e->vpn_realm_id ){
  	rlm_id = (unsigned long)_rhp_ntohll(sess_res_tkt_e->vpn_realm_id);
  }else{
  	rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  }

	rlm = rhp_realm_get(rlm_id);
	if( rlm == NULL ){
	  RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_DEC_CHECK_NO_RLM_FOUND,"xxxx",sess_res_tkt,sess_res_tkt_e,larval_vpn,ikesa);
		err = -ENOENT;
		goto error;
	}

	RHP_LOCK(&(rlm->lock));

	if( !_rhp_atomic_read(&(rlm->is_active)) ){
		err = -EINVAL;
	  RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_DEC_CHECK_RLM_NOT_ACTIVE,"xxxx",sess_res_tkt,sess_res_tkt_e,larval_vpn,ikesa);
		goto error;
	}

	if( rlm->sess_resume_policy_index != (time_t)_rhp_ntohll(sess_res_tkt_e->vpn_realm_policy_index) ){
		err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT_BAD_POLICY_IDX;
	  RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_DEC_CHECK_TKT_EXPIRED,"xxxx",sess_res_tkt,sess_res_tkt_e,larval_vpn,ikesa);
		goto error;
	}

	RHP_UNLOCK(&(rlm->lock));
	rhp_realm_unhold(rlm);

  RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_DEC_CHECK_RTRN,"xxxx",sess_res_tkt,sess_res_tkt_e,larval_vpn,ikesa);
	return 0;

error:
	if( rlm ){
		RHP_UNLOCK(&(rlm->lock));
		rhp_realm_unhold(rlm);
	}
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKEV2_SESS_RESUME_DEC_RX_INVALID_TKT,"VPE",larval_vpn,ikesa,err);
  RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_DEC_CHECK_ERR,"xxxxE",sess_res_tkt,sess_res_tkt_e,larval_vpn,ikesa,err);
	return err;
}


static int _rhp_ikev2_new_pkt_sess_resume_rep(rhp_ikesa* ikesa,rhp_ikev2_mesg* tx_resp_ikemesg,int exec_ikev2_frag)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_REP,"xxd",ikesa,tx_resp_ikemesg,exec_ikev2_frag);


  {
    int nonce_len = ikesa->nonce_r->get_nonce_len(ikesa->nonce_r);
    u8* nonce = ikesa->nonce_r->get_nonce(ikesa->nonce_r);

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


  if( exec_ikev2_frag ){

		if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);
		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_FRAG_SUPPORTED);

		ikepayload->set_non_critical(ikepayload,1);
  }


  {
    if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_V,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

    if( ikepayload->ext.vid->copy_my_app_vid(ikepayload) ){
      RHP_BUG("");
      goto error;
    }
  }

  RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_REP_RTRN,"xx",ikesa,tx_resp_ikemesg);
  return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKEV2_SESS_RESUME_TX_ALLOC_REP_ERR,"PE",ikesa,err);
  RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_REP_ERR,"xE",ikesa,err);
  return err;
}

static void _rhp_ikev2_sess_resume_tkt_dec_rep_ipc_handler(rhp_ipcmsg** ipcmsg)
{
  int err = -EINVAL;
  rhp_ipcmsg_sess_resume_dec_rep* ipc_rep = NULL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_ikev2_mesg* rx_ikemesg = NULL;
  rhp_vpn* larval_vpn = NULL;
  rhp_vpn_ref* larval_vpn_ref = NULL;
  rhp_ikesa* ikesa = NULL;
  u16 notify_error = RHP_PROTO_IKE_NOTIFY_ST_TICKET_NACK;
  unsigned long notify_error_arg = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_DEC_REP_IPC_HANDLER,"xxd",ipcmsg,*ipcmsg,rhp_gcfg_ikev2_qcd_enabled);

  ipc_rep = (rhp_ipcmsg_sess_resume_dec_rep*)*ipcmsg;

  if( ipc_rep->len < sizeof(rhp_ipcmsg_sess_resume_dec_rep) ){
    RHP_BUG("%d < sizeof(rhp_ipcmsg_sess_resume_dec_rep)(%d)",ipc_rep->len,sizeof(rhp_ipcmsg_sess_resume_dec_rep));
    err = -EINVAL;
    goto error;
  }


  larval_vpn_ref = rhp_vpn_ikesa_spi_get(ipc_rep->side,ipc_rep->spi);
  larval_vpn = RHP_VPN_REF(larval_vpn_ref);
  if( larval_vpn == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_DEC_REP_IPC_HANDLER_NO_IKESA,"xLdG",ipcmsg,"IKE_SIDE",ipc_rep->side,ipc_rep->spi);
    err = -ENOENT;
    goto error;
  }

  RHP_LOCK(&(larval_vpn->lock));

  if( !_rhp_atomic_read(&(larval_vpn->is_active)) ){
    RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_DEC_REP_IPC_HANDLER_IKESA_NOT_ACTIVE,"xx",ipcmsg,ikesa);
    err = -EINVAL;
    goto error;
  }


  ikesa = larval_vpn->ikesa_get(larval_vpn,ipc_rep->side,ipc_rep->spi);
  if( ikesa == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_DEC_REP_IPC_HANDLER_NO_IKESA,"x",ipcmsg);
    err = -ENOENT;
    goto error;
  }

  ikesa->busy_flag = 0;

  {
  	tx_ikemesg = ikesa->sess_resume.resp.pend_tx_ikemesg;
  	ikesa->sess_resume.resp.pend_tx_ikemesg = NULL;

  	rx_ikemesg = ikesa->sess_resume.resp.pend_rx_ikemesg;
  	ikesa->sess_resume.resp.pend_rx_ikemesg = NULL;
  }

  if( tx_ikemesg == NULL || rx_ikemesg == NULL ){
  	RHP_BUG("");
    err = -EINVAL;
  	goto error;
  }

  if( ipc_rep->txn_id != ikesa->sess_resume.resp.ipc_txn_id ){
    RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_DEC_REP_IPC_HANDLER_IKESA_BAD_TXNID,"xxxqq",ipcmsg,larval_vpn,ikesa,ipc_rep->txn_id,ikesa->sess_resume.resp.ipc_txn_id);
    err = -EINVAL;
    goto error;
  }


  if( ipc_rep->my_realm_id != larval_vpn->vpn_realm_id ){
    RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_DEC_REP_IPC_HANDLER_REALM_BAD_ID,"xxxuu",ipcmsg,larval_vpn,ikesa,ipc_rep->my_realm_id,larval_vpn->vpn_realm_id);
    err = -EINVAL;
    goto error;
  }

  if( ipc_rep->result == 0 ){

  	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_DEC_REP_IPC_HANDLER_RESULT_ERR,"xxx",ipcmsg,larval_vpn,ikesa);

  	err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
  	goto error;

  }else{

    rhp_ikev2_sess_resume_tkt* sess_res_tkt = (rhp_ikev2_sess_resume_tkt*)(ipc_rep + 1);
    rhp_ikev2_sess_resume_tkt_e* sess_res_tkt_e;


    if( ipc_rep->len <= sizeof(rhp_ipcmsg_sess_resume_dec_rep)
    										+ sizeof(rhp_ikev2_sess_resume_tkt) + sizeof(rhp_ikev2_sess_resume_tkt_e) ){
    	RHP_BUG("");
      err = -EINVAL;
    	goto error;
    }

    if( ntohs(sess_res_tkt->len) <=
    			sizeof(rhp_ikev2_sess_resume_tkt) + sizeof(rhp_ikev2_sess_resume_tkt_e) ){
    	RHP_BUG("");
      err = -EINVAL;
    	goto error;
    }

    rhp_ikev2_sess_resume_tkt_dump("tkt_dec_rep_ipc_handler",sess_res_tkt,1);
    rhp_ikev2_sess_resume_tkt_log_dump(0,sess_res_tkt,1);

    sess_res_tkt_e = (rhp_ikev2_sess_resume_tkt_e*)(sess_res_tkt + 1);

    err = _rhp_ikev2_sess_resume_tkt_dec_check(sess_res_tkt,sess_res_tkt_e,larval_vpn,ikesa);
    if( err ){
    	goto error;
    }


    sess_res_tkt_e = (rhp_ikev2_sess_resume_tkt_e*)(sess_res_tkt + 1);


    ikesa->prop.v2.number = 1;
    ikesa->prop.v2.protocol_id = RHP_PROTO_IKE_PROTOID_IKE;
    ikesa->prop.v2.spi_len = 0;
    memset(ikesa->prop.v2.spi,0,RHP_PROTO_SPI_MAX_SIZE);
    ikesa->prop.v2.encr_id = ntohs(sess_res_tkt_e->encr_id);
    ikesa->prop.v2.encr_key_bits = ntohs(sess_res_tkt_e->encr_key_bits);
    ikesa->prop.v2.prf_id = ntohs(sess_res_tkt_e->prf_id);
    ikesa->prop.v2.integ_id = ntohs(sess_res_tkt_e->integ_id);
    ikesa->prop.v2.dhgrp_id = ntohs(sess_res_tkt_e->dhgrp_id);

    larval_vpn->sess_resume.auth_method_i_org = sess_res_tkt_e->auth_method_i;
    larval_vpn->sess_resume.auth_method_r_org = sess_res_tkt_e->auth_method_r;

    err = rhp_ikesa_r_init_params_bh(ikesa,&(ikesa->prop.v2));
    if( err ){
    	RHP_BUG("%d",err);
    	goto error;
    }

    //
  	// ikesa->qcd.my_token_enabled will be enabled during the following AUTH Exchange.
    //
    if( rhp_gcfg_ikev2_qcd_enabled && ipc_rep->qcd_enabled ){

    	memcpy(ikesa->qcd.my_token,ipc_rep->my_qcd_token,RHP_IKEV2_QCD_TOKEN_LEN);
    	ikesa->qcd.my_token_set_by_sess_resume = 1;

    	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_DEC_REP_IPC_HANDLER_QCD_MY_TKN_ENABLED,"xxxd",rx_ikemesg,larval_vpn,ikesa,ikesa->qcd.my_token_enabled);

    }else{

    	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_DEC_REP_IPC_HANDLER_QCD_MY_TKN_NOT_TOUCHED,"xxxd",rx_ikemesg,larval_vpn,ikesa,ikesa->qcd.my_token_enabled);
    }


    err = _rhp_ikev2_new_pkt_sess_resume_rep(ikesa,tx_ikemesg,larval_vpn->exec_ikev2_frag);
    if( err ){
    	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_DEC_REP_IPC_HANDLER_ALLOC_RESP_PKT_ERR,"xxxE",rx_ikemesg,larval_vpn,ikesa,err);
    	goto error;
    }


    ikesa->sess_resume.resp.dec_tkt_ipc_rep = ipc_rep; // (**)
  }


	rhp_ikev2_call_next_rx_request_mesg_handlers(rx_ikemesg,larval_vpn,
			ipc_rep->side,ipc_rep->spi,tx_ikemesg,RHP_IKEV2_MESG_HANDLER_SESS_RESUME);

	err = 0;


	RHP_UNLOCK(&(larval_vpn->lock));
	rhp_vpn_unhold(larval_vpn);

	rhp_ikev2_unhold_mesg(tx_ikemesg);
	rhp_ikev2_unhold_mesg(rx_ikemesg);

  *ipcmsg = NULL; // See (**).

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKEV2_SESS_RESUME_DEC_TKT_OK,"VPK",larval_vpn,ikesa,rx_ikemesg);

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_DEC_REP_IPC_HANDLER_RTRN,"xxxxx",ipcmsg,larval_vpn,ikesa,tx_ikemesg,rx_ikemesg);
	return;


error:

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKEV2_SESS_RESUME_DEC_TKT_ERR,"KE",rx_ikemesg,err);

  if( larval_vpn ){

  	if( rx_ikemesg && ikesa ){

  	  _rhp_ikev2_sess_resume_tx_error_rep(rx_ikemesg,notify_error,notify_error_arg);

			rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
			ikesa->timers->schedule_delete(larval_vpn,ikesa,0);
  	}

		RHP_UNLOCK(&(larval_vpn->lock));
		rhp_vpn_unhold(larval_vpn);
  }

	if( tx_ikemesg ){
		rhp_ikev2_unhold_mesg(tx_ikemesg);
	}

	if( rx_ikemesg ){
		rhp_ikev2_unhold_mesg(rx_ikemesg);
	}

	if( ipc_rep ){
		_rhp_free_zero(ipc_rep,ipc_rep->len);
		*ipcmsg = NULL;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_DEC_REP_IPC_HANDLER_ERR,"xxxxxE",ipcmsg,larval_vpn,ikesa,tx_ikemesg,rx_ikemesg,err);
  return;
}

static int _rhp_ikev2_sess_resume_ipc_tkt_dec_req(rhp_vpn* vpn,rhp_ikesa* ikesa,
	  rhp_ike_sa_init_srch_plds_ctx* s_pld_ctx,rhp_sess_rsm_srch_plds_ctx* s_pld_rsm_ctx)
{
	int err = -EINVAL;
	int ipc_req_len = sizeof(rhp_ipcmsg_sess_resume_dec_req);
	rhp_ipcmsg_sess_resume_dec_req* ipc_req = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_SES_RESUME_IPC_TKT_DEC_REQ,"xxLdGGxxd",vpn,ikesa,"IKE_SIDE",ikesa->side,ikesa->init_spi,ikesa->resp_spi,s_pld_ctx,s_pld_rsm_ctx,rhp_gcfg_ikev2_qcd_enabled);


	ipc_req_len += s_pld_rsm_ctx->tkt_r_len;

	ipc_req = (rhp_ipcmsg_sess_resume_dec_req*)_rhp_malloc(ipc_req_len);
	if( ipc_req == NULL ){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	memset(ipc_req,0,ipc_req_len);

	ipc_req->tag[0] = '#';
	ipc_req->tag[1] = 'I';
	ipc_req->tag[2] = 'M';
	ipc_req->tag[3] = 'S';

	ipc_req->type = RHP_IPC_SESS_RESUME_DEC_REQUEST;
	ipc_req->len = ipc_req_len;

	ipc_req->my_realm_id = 0;
	ipc_req->side = ikesa->side;

	if( (((u32*)ikesa->resp_spi)[0] == 0 && ((u32*)ikesa->resp_spi)[1] == 0) ){
		RHP_BUG("");
	}

	memcpy(ipc_req->spi,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
	memcpy(ipc_req->peer_spi,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);

	ipc_req->qcd_enabled = (rhp_gcfg_ikev2_qcd_enabled ? 1 : 0);

	ikesa->sess_resume.resp.ipc_txn_id = rhp_ikesa_new_ipc_txn_id();
	ipc_req->txn_id = ikesa->sess_resume.resp.ipc_txn_id;

	memcpy((u8*)(ipc_req + 1),s_pld_rsm_ctx->tkt_r,s_pld_rsm_ctx->tkt_r_len);


	if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipc_req,ipc_req->len,0) < 0 ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
  }

	_rhp_free_zero(ipc_req,ipc_req->len);

	RHP_TRC(0,RHPTRCID_IKEV2_SES_RESUME_IPC_TKT_DEC_REQ_RTRN,"xx",vpn,ikesa);
	return 0;

error:
	if( ipc_req ){
		_rhp_free_zero(ipc_req,ipc_req->len);
	}
	RHP_TRC(0,RHPTRCID_IKEV2_SES_RESUME_IPC_TKT_DEC_REQ_ERR,"xxE",vpn,ikesa,err);
	return err;
}

static int _rhp_ikev2_sess_resume_tkt_opaque_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_sess_rsm_srch_plds_ctx* s_pld_ctx = (rhp_sess_rsm_srch_plds_ctx*)ctx;
	rhp_ikev2_n_payload* n_payload = (rhp_ikev2_n_payload*)payload->ext.n;
	u16 notify_mesg_type;
	int tkt_data_len = 0;
	u8* tkt_data = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_OPAQUE_CB,"xdxxx",rx_ikemesg,enum_end,payload,n_payload,s_pld_ctx);

	if( n_payload == NULL ){
		RHP_BUG("");
  	return -EINVAL;
  }

	if( s_pld_ctx->dup_flag ){
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_OPAQUE_CB_DUP_ERROR,"x",rx_ikemesg);
		return RHP_STATUS_INVALID_MSG;
	}
	s_pld_ctx->dup_flag++;

	notify_mesg_type = n_payload->get_message_type(payload);
	tkt_data_len = payload->ext.n->get_data_len(payload);
	tkt_data = payload->ext.n->get_data(payload);

	if( tkt_data == NULL || tkt_data_len < 1 ){
		return RHP_STATUS_INVALID_MSG;
	}

	if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_TICKET_OPAQUE ){

		int tkt_len;
		rhp_ikev2_sess_resume_tkt* sess_res_tkt;

		if( tkt_data_len <= 0 ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_OPAQUE_CB_NOTIFY_ST_TICKET_OPAQUE_INVALID_LEN,"xd",rx_ikemesg,tkt_data_len);
			goto error;
		}

		if( tkt_data_len <= (int)(sizeof(rhp_ikev2_sess_resume_tkt)
					+ sizeof(rhp_ikev2_sess_resume_tkt_e) + RHP_IKEV2_SESS_RESUME_TKT_MAC_LEN) ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_OPAQUE_CB_NOTIFY_ST_TICKET_OPAQUE_INVALID_LEN_2,"xd",rx_ikemesg,tkt_data_len);
			goto error;
		}

		sess_res_tkt = (rhp_ikev2_sess_resume_tkt*)tkt_data;
		tkt_len = ntohs(sess_res_tkt->len);

		if( tkt_len <= (int)(sizeof(rhp_ikev2_sess_resume_tkt)
					+ sizeof(rhp_ikev2_sess_resume_tkt_e) + RHP_IKEV2_SESS_RESUME_TKT_MAC_LEN) ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_OPAQUE_CB_NOTIFY_ST_TICKET_OPAQUE_INVALID_LEN_3,"xdd",rx_ikemesg,tkt_data_len,tkt_len);
			goto error;
		}

		if( tkt_data + tkt_len != tkt_data + tkt_data_len ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_OPAQUE_CB_NOTIFY_ST_TICKET_OPAQUE_INVALID_LEN_4,"xdd",rx_ikemesg,tkt_data_len,tkt_len);
			goto error;
		}

		if( sess_res_tkt->magic[0] != 'R' || sess_res_tkt->magic[1] != 'K' ||
				sess_res_tkt->magic[2] != 'H' || sess_res_tkt->magic[3] != 'P'){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_OPAQUE_CB_NOTIFY_ST_TICKET_OPAQUE_INVALID_MAGIC,"xbbbb",rx_ikemesg,sess_res_tkt->magic[0],sess_res_tkt->magic[1],sess_res_tkt->magic[2],sess_res_tkt->magic[3]);
			goto error;
		}

		if( ntohs(sess_res_tkt->version) != RHP_IKEV2_SESS_RESUME_TKT_VERSION ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_OPAQUE_CB_NOTIFY_ST_TICKET_OPAQUE_INVALID_VER,"xW",rx_ikemesg,sess_res_tkt->version);
			goto error;
		}


		s_pld_ctx->tkt_r_lifetime = 0;
		s_pld_ctx->tkt_r = tkt_data;
		s_pld_ctx->tkt_r_len = tkt_data_len;

		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_OPAQUE_CB_NOTIFY_ST_TICKET_OPAQUE,"xdup",rx_ikemesg,tkt_data_len,s_pld_ctx->tkt_r_lifetime,s_pld_ctx->tkt_r_len,s_pld_ctx->tkt_r);

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SESS_RESUME_REQ_TKT_OPAQUE_PAYLOAD,"Kd",rx_ikemesg,s_pld_ctx->tkt_r_len);
	}

	err = 0;

error:
	if( err ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(s_pld_ctx->vpn ? s_pld_ctx->vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SESS_RESUME_REQ_TKT_OPAQUE_PAYLOAD_ERR,"KdpE",rx_ikemesg,tkt_data_len,(tkt_data_len > 64 ? 64 : tkt_data_len),tkt_data,err);
	}
	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_TKT_OPAQUE_CB_RTRN,"xE",rx_ikemesg,err);
	return err;
}

static int _rhp_ikev2_rx_sess_resume_req_no_vpn(rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg,
		rhp_vpn** vpn_i,int* my_ikesa_side_i,u8* my_ikesa_spi_i)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_ikesa* ikesa = NULL;
  rhp_ip_addr peer_addr, rx_addr;
  rhp_proto_ike* ikeh = rx_req_ikemesg->rx_pkt->app.ikeh;
  rhp_vpn* larval_vpn = NULL;
  rhp_ikesa_init_i* init_i = NULL;
  rhp_ike_sa_init_srch_plds_ctx s_pld_ctx;
  rhp_sess_rsm_srch_plds_ctx s_pld_rsm_ctx;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REQ_L,"x",rx_req_ikemesg);

  rhp_ip_addr_reset(&peer_addr);
  rhp_ip_addr_reset(&rx_addr);

  if( rx_req_ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE ){

    rhp_ip_addr_set(&peer_addr,AF_INET,
    		(u8*)&(rx_req_ikemesg->rx_pkt->l3.iph_v4->src_addr),NULL,32,
    		rx_req_ikemesg->rx_pkt->l4.udph->src_port,0);

    rhp_ip_addr_set2(&rx_addr,AF_INET,
    		(u8*)&(rx_req_ikemesg->rx_pkt->l3.iph_v4->dst_addr),
    		rx_req_ikemesg->rx_pkt->l4.udph->dst_port);

    RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_R_PEER_ADDR,"xd4WXd",rx_req_ikemesg,peer_addr.addr_family,peer_addr.addr.v4,peer_addr.port,peer_addr.netmask.v4,peer_addr.prefixlen);

  }else if( rx_req_ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE ){

    rhp_ip_addr_set(&peer_addr,AF_INET6,
    		rx_req_ikemesg->rx_pkt->l3.iph_v6->src_addr,NULL,128,
    		rx_req_ikemesg->rx_pkt->l4.udph->src_port,0);

    rhp_ip_addr_set2(&rx_addr,AF_INET6,
    		(u8*)&(rx_req_ikemesg->rx_pkt->l3.iph_v6->dst_addr),
    		rx_req_ikemesg->rx_pkt->l4.udph->dst_port);

    RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_R_PEER_ADDR_V6,"xd6WXd",rx_req_ikemesg,peer_addr.addr_family,peer_addr.addr.v6,peer_addr.port,peer_addr.netmask.v4,peer_addr.prefixlen);

  }else{
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  memset(&s_pld_ctx,0,sizeof(rhp_ike_sa_init_srch_plds_ctx));
  memset(&s_pld_rsm_ctx,0,sizeof(rhp_sess_rsm_srch_plds_ctx));

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_N_I_R),
  			rhp_ikev2_ike_sa_init_srch_nir_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_RX_IKEV2_SESS_RESUME_REQ_ENUM_NIR_PLD_ERR,"xxd",rx_req_ikemesg,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_SESS_RESUME_REQ_PARSE_N_I_R_PAYLOAD_ERR,"KVPE",rx_req_ikemesg,NULL,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
  }

  {
  	s_pld_rsm_ctx.dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_n_mesg_id,
  			(void*)((unsigned long)RHP_PROTO_IKE_NOTIFY_ST_TICKET_OPAQUE),
  			_rhp_ikev2_sess_resume_tkt_opaque_cb,&s_pld_rsm_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
  		RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REQ_L_TKT_OPAQUE_ERR,"xxE",ikesa,rx_req_ikemesg,err);
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_SESS_RESUME_REQ_PARSE_N_TICKET_OPAQUE_PAYLOAD_ERR,"KVPE",rx_req_ikemesg,NULL,ikesa,err);
    	goto error;
  	}
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  			rhp_ikev2_mesg_search_cond_my_verndor_id,NULL,
  			rhp_ikev2_ike_sa_init_srch_my_vid_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
  		RHP_TRC(0,RHPTRCID_RX_IKEV2_SESS_RESUME_REQ_ENUM_MY_VENDOR_ID_ERR,"xxE",ikesa,rx_req_ikemesg,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_SESS_RESUME_REQ_PARSE_V_PAYLOAD_ERR,"KVPE",rx_req_ikemesg,NULL,ikesa,err);
    	goto error;
  	}
  }


  if( rhp_gcfg_ikev2_enable_fragmentation ){

  	s_pld_ctx.dup_flag = 0;

  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_n_mesg_id,
  			(void*)((unsigned long)RHP_PROTO_IKE_NOTIFY_ST_FRAG_SUPPORTED),
  			rhp_ikev2_ike_sa_init_srch_n_frag_supported_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
  		RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REP_L_FRAG_SUPPORTED_ERR,"xxE",ikesa,rx_req_ikemesg,err);
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_SESS_RESUME_RESP_PARSE_N_FRAGMENTATION_SUPPORTED_PAYLOAD_ERR,"KVPE",rx_req_ikemesg,NULL,ikesa,err);
    	goto error;
  	}
  }


  larval_vpn = rhp_vpn_alloc(NULL,NULL,NULL,NULL,RHP_IKE_RESPONDER); // (xx*)
  if( larval_vpn == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  RHP_LOCK(&(larval_vpn->lock));

  _rhp_atomic_set(&(larval_vpn->is_active),1);


  ikesa = rhp_ikesa_new_r(NULL);
  if( ikesa == NULL ){
  	RHP_BUG("");
    err = -EINVAL;
  	goto error;
  }

  larval_vpn->sess_resume.gen_by_sess_resume = 1;
  ikesa->gen_by_sess_resume = 1;

  ikesa->timers = rhp_ikesa_new_timers(RHP_IKE_RESPONDER,ikesa->resp_spi);
  if( ikesa->timers == NULL ){
  	RHP_BUG("");
    err = -EINVAL;
  	goto error;
  }

  larval_vpn->ikesa_put(larval_vpn,ikesa);


  init_i = rhp_ikesa_alloc_init_i(ikesa->resp_spi,&peer_addr,rx_req_ikemesg);
  if( init_i == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  larval_vpn->exec_ikev2_frag = s_pld_ctx.frag_supported;

  larval_vpn->peer_is_rockhopper = s_pld_ctx.peer_is_rockhopper;
  larval_vpn->peer_rockhopper_ver = s_pld_ctx.peer_rockhopper_ver;
  ikesa->peer_is_rockhopper = s_pld_ctx.peer_is_rockhopper;
  ikesa->peer_rockhopper_ver = s_pld_ctx.peer_rockhopper_ver;


  err = rhp_vpn_ikesa_spi_put(larval_vpn,ikesa->side,ikesa->resp_spi);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

 	RHP_LOCK(&(rx_req_ikemesg->rx_pkt->rx_ifc->lock));
 	{
 		larval_vpn->set_local_net_info(larval_vpn,rx_req_ikemesg->rx_pkt->rx_ifc,
 				rx_addr.addr_family,rx_addr.addr.raw);
  }
	RHP_UNLOCK(&(rx_req_ikemesg->rx_pkt->rx_ifc->lock));

  ikesa->set_init_spi(ikesa,ikeh->init_spi);

  larval_vpn->set_peer_addr(larval_vpn,&peer_addr,&peer_addr);


  err = ikesa->nonce_i->set_nonce(ikesa->nonce_i,s_pld_ctx.nonce,s_pld_ctx.nonce_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }


  err = _rhp_ikev2_sess_resume_ipc_tkt_dec_req(larval_vpn,ikesa,&s_pld_ctx,&s_pld_rsm_ctx);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }


  rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_R_IKE_SA_INIT_SENT);

	{
		ikesa->signed_octets.ikemesg_i_1st = rx_req_ikemesg;
		rhp_ikev2_hold_mesg(rx_req_ikemesg);
		rhp_pkt_pending(rx_req_ikemesg->rx_pkt);

		ikesa->signed_octets.ikemesg_r_2nd = tx_resp_ikemesg;
		rhp_ikev2_hold_mesg(tx_resp_ikemesg);
	}

  {
		ikesa->sess_resume.resp.pend_rx_ikemesg = rx_req_ikemesg;
		rhp_ikev2_hold_mesg(rx_req_ikemesg);

		ikesa->sess_resume.resp.pend_tx_ikemesg = tx_resp_ikemesg;
		rhp_ikev2_hold_mesg(tx_resp_ikemesg);
  }

  ikesa->busy_flag = 1;

  rhp_ikesa_init_i_put(init_i,&(ikesa->ike_init_i_hash));
  init_i = NULL;

  ikesa->timers->start_lifetime_timer(larval_vpn,ikesa,rhp_gcfg_ikesa_lifetime_larval,1);

  larval_vpn->origin_peer_port = rx_req_ikemesg->rx_pkt->l4.udph->src_port;

  {
  	larval_vpn->connecting = 1;
  	rhp_ikesa_half_open_sessions_inc();
  }

  RHP_UNLOCK(&(larval_vpn->lock));


  return RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;


error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(larval_vpn ? larval_vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_SESS_RESUME_REQ_ERR,"KVPLE",rx_req_ikemesg,larval_vpn,ikesa,"PROTO_IKE_NOTIFY",s_pld_ctx.notify_error,err);

	if( s_pld_ctx.notify_error || s_pld_rsm_ctx.notify_error ){

	  u16 notify_error
	  	= (s_pld_ctx.notify_error ? s_pld_ctx.notify_error : s_pld_rsm_ctx.notify_error);
	  unsigned long notify_error_arg
	  	= (s_pld_ctx.notify_error ? s_pld_ctx.notify_error_arg : s_pld_rsm_ctx.notify_error_arg);

	  _rhp_ikev2_sess_resume_tx_error_rep(rx_req_ikemesg,notify_error,notify_error_arg);
  }

	if( larval_vpn ){

		rhp_vpn_ref* larval_vpn_ref = rhp_vpn_hold_ref(larval_vpn); // (xx*)

    rhp_vpn_destroy(larval_vpn); // ikesa is also released.

    RHP_UNLOCK(&(larval_vpn->lock));
		rhp_vpn_unhold(larval_vpn_ref); // (xx*)
  }

	if( init_i ){
    rhp_ikesa_free_init_i(init_i);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REQ_L_ERR,"xxE",rx_req_ikemesg,ikesa,err);
  return err;
}

int rhp_ikev2_rx_sess_resume_req_no_vpn(rhp_ikev2_mesg* rx_req_ikemesg,
		rhp_ikev2_mesg* tx_resp_ikemesg,rhp_vpn** vpn_i,int* my_ikesa_side_i,u8* my_ikesa_spi_i)
{
	int err = -EINVAL;
	u8 exchange_type = rx_req_ikemesg->get_exchange_type(rx_req_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REQ,"xxLbd",rx_req_ikemesg,tx_resp_ikemesg,"PROTO_IKE_EXCHG",exchange_type,rhp_gcfg_ikev2_sess_resume_resp_enabled);

	if( !rhp_gcfg_ikev2_sess_resume_resp_enabled ){
		return 0;
	}

	if( exchange_type != RHP_PROTO_IKE_EXCHG_SESS_RESUME ){
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REQ_NOT_SESS_RESUME_EXCHG,"xLb",rx_req_ikemesg,"PROTO_IKE_EXCHG",exchange_type);
		return 0;
	}

	if( !RHP_PROTO_IKE_HDR_INITIATOR(rx_req_ikemesg->rx_pkt->app.ikeh->flag) ){
		err = RHP_STATUS_INVALID_MSG;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REQ_INVALID_MESG1,"x",rx_req_ikemesg);
		goto error;
  }

	if( *vpn_i || *my_ikesa_side_i != -1 ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

	err = _rhp_ikev2_rx_sess_resume_req_no_vpn(rx_req_ikemesg,tx_resp_ikemesg,vpn_i,my_ikesa_side_i,my_ikesa_spi_i);

error:
	if( !err ){
		RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REQ_RTRN,"xxxLdG",rx_req_ikemesg,tx_resp_ikemesg,*vpn_i,"IKE_SIDE",*my_ikesa_side_i,my_ikesa_spi_i);
	}else{
		RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REQ_RTRN,"xxxE",rx_req_ikemesg,tx_resp_ikemesg,err);
	}
  return err;
}

#ifdef RHP_PKT_DBG_IKEV2_BAD_COOKIE_TEST
extern void rhp_ikev2_test_bad_cookie(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_payload* n_payload_r,u8* cookie,int cookie_len);
#endif // RHP_PKT_DBG_IKEV2_BAD_COOKIE_TEST

static int _rhp_ikev2_rx_sess_resume_i_cookie(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_payload* n_payload_r)
{
  int err = -EINVAL;
  int cookie_len = 0;
  u8* cookie = NULL;
  rhp_ikev2_mesg *old_1st_mesg,*new_1st_mesg = NULL;
  rhp_vpn_realm* rlm;
  rhp_vpn_sess_resume_material* material_i = vpn->sess_resume_get_material_i(vpn);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_I_COOKIE,"xxxxx",vpn,vpn->rlm,ikesa,n_payload_r,material_i);

  cookie_len = n_payload_r->ext.n->get_data_len(n_payload_r);

  if( cookie_len < RHP_PROTO_IKE_NOTIFY_COOKIE_MIN_SZ && cookie_len > RHP_PROTO_IKE_NOTIFY_COOKIE_MAX_SZ ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_I_COOKIE_BAD_COOKIE_LEN,"xxxddd",vpn,vpn->rlm,ikesa,cookie_len,RHP_PROTO_IKE_NOTIFY_COOKIE_MIN_SZ,RHP_PROTO_IKE_NOTIFY_COOKIE_MAX_SZ);
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

  cookie = n_payload_r->ext.n->get_data(n_payload_r);
  if( cookie == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_I_COOKIE_NO_COOKIE_DATA,"xxxx",vpn,vpn->rlm,ikesa,n_payload_r);
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

	RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_I_COOKIE_COOKIE_DATA,"xxxxp",vpn,vpn->rlm,ikesa,n_payload_r,cookie_len,cookie);

  if( ikesa->cookies.cookie ){
    _rhp_free(ikesa->cookies.cookie);
    ikesa->cookies.cookie = NULL;
    ikesa->cookies.cookie_len = 0;
  }

  ikesa->cookies.cookie = (u8*)_rhp_malloc(cookie_len);
  if( ikesa->cookies.cookie == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  ikesa->cookies.cookie_len = cookie_len;
  memcpy(ikesa->cookies.cookie,cookie,cookie_len);

#ifdef RHP_PKT_DBG_IKEV2_BAD_COOKIE_TEST
  rhp_ikev2_test_bad_cookie(vpn,ikesa,n_payload_r,cookie,cookie_len);
#endif // RHP_PKT_DBG_IKEV2_BAD_COOKIE_TEST

  old_1st_mesg = ikesa->signed_octets.ikemesg_i_1st;
  ikesa->signed_octets.ikemesg_i_1st = NULL;
  rhp_ikev2_unhold_mesg(old_1st_mesg);
  old_1st_mesg = NULL;

  new_1st_mesg = rhp_ikev2_new_pkt_sess_resume_req(vpn,ikesa,material_i,cookie_len,cookie);
  if( new_1st_mesg == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  ikesa->req_message_id = (u32)-1;

  ikesa->signed_octets.ikemesg_i_1st = new_1st_mesg;
  rhp_ikev2_hold_mesg(new_1st_mesg);


  rhp_ikev2_send_request(vpn,ikesa,new_1st_mesg,RHP_IKEV2_MESG_HANDLER_SESS_RESUME);
  rhp_ikev2_unhold_mesg(new_1st_mesg);
  new_1st_mesg = NULL;

  ikesa->timers->retx_counter = 0;

  rlm = vpn->rlm;
  if( rlm == NULL ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_I_COOKIE_NO_RLM,"xxx",vpn,vpn->rlm,ikesa);
  	goto error;
  }

  RHP_LOCK(&(rlm->lock));

  if( !_rhp_atomic_read(&(rlm->is_active)) ){
  	RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_I_COOKIE_RLM_NOT_ACTIVE,"xxx",vpn,vpn->rlm,ikesa);
  	goto error_l;
  }

  ikesa->timers->start_lifetime_timer(vpn,ikesa,rlm->ikesa.lifetime_larval,1);

  RHP_UNLOCK(&(rlm->lock));

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_COOKIE_OK,"VP",vpn,ikesa);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_I_COOKIE_RTRN,"xxxx",vpn,vpn->rlm,ikesa,n_payload_r);
	return 0;

error_l:
  RHP_UNLOCK(&(rlm->lock));
error:
  if( new_1st_mesg ){
    rhp_ikev2_unhold_mesg(new_1st_mesg);
  }

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_IKE_SA_INIT_COOKIE_ERR,"VPE",vpn,ikesa,err);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_I_COOKIE_ERR,"xxxxE",vpn,vpn->rlm,ikesa,n_payload_r,err);
	return err;
}

static int _rhp_ikev2_sess_resume_srch_n_error_cb(rhp_ikev2_mesg* ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  int err = -EINVAL;
  rhp_ike_sa_init_srch_plds_ctx* s_pld_ctx = (rhp_ike_sa_init_srch_plds_ctx*)ctx;
  rhp_ikev2_n_payload* n_payload = (rhp_ikev2_n_payload*)payload->ext.n;
  u16 notify_mesg_type;

  RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SRCH_N_ERROR_CB,"xdxxx",ikemesg,enum_end,payload,n_payload,ctx);

  if( n_payload == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  notify_mesg_type = n_payload->get_message_type(payload);

  //
  // TODO : Handling only interested notify-error codes.
  //
  if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_TICKET_NACK ||
  		(notify_mesg_type >= RHP_PROTO_IKE_NOTIFY_ERR_MIN && notify_mesg_type <= RHP_PROTO_IKE_NOTIFY_ERR_MAX) ){

    RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SRCH_N_ERROR_CB_ERROR_FOUND,"xxxLw",ikemesg,payload,n_payload,"PROTO_IKE_NOTIFY",notify_mesg_type);

    s_pld_ctx->n_error_payload = payload;
    s_pld_ctx->n_err = notify_mesg_type;

    return RHP_STATUS_ENUM_OK;
  }

  s_pld_ctx->dup_flag++;
  err = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SRCH_N_ERROR_CB_RTRN,"xxxxLwE",ikemesg,payload,n_payload,ctx,"PROTO_IKE_NOTIFY",notify_mesg_type,err);
  return err;
}

static int _rhp_ikev2_rx_sess_resume_rep(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_resp_ikemesg,
		rhp_ikev2_mesg* tx_req_ikemesg)
{
  int err = RHP_STATUS_INVALID_MSG;
  rhp_proto_ike* ikeh;
  rhp_ike_sa_init_srch_plds_ctx s_pld_ctx;
  rhp_vpn_sess_resume_material* material_i;
  rhp_res_sa_proposal* old_sa_prop_i;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REP_L,"xxxx",rx_resp_ikemesg,tx_req_ikemesg,vpn,ikesa);

  memset(&s_pld_ctx,0,sizeof(rhp_ike_sa_init_srch_plds_ctx));


  material_i = vpn->sess_resume_get_material_i(vpn);
  if( material_i == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

  if( material_i->old_sa_prop_i == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }
  old_sa_prop_i = material_i->old_sa_prop_i;


  ikeh = rx_resp_ikemesg->rx_pkt->app.ikeh;

  if( ikesa->state != RHP_IKESA_STAT_I_IKE_SA_INIT_SENT ){
    RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_I_IKESA_BAD_STATE,"xxxd",rx_resp_ikemesg,vpn,ikesa,ikesa->state);
    err = RHP_STATUS_BAD_SA_STATE;
    goto error;
  }

  if( rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


  ikesa->timers->quit_lifetime_timer(vpn,ikesa);


  s_pld_ctx.vpn = vpn;
  s_pld_ctx.ikesa = ikesa;

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  					rhp_ikev2_mesg_srch_cond_n_mesg_id,(void*)((unsigned long)RHP_PROTO_IKE_NOTIFY_ST_COOKIE),
  					rhp_ikev2_ike_sa_init_srch_n_cookie_cb,&s_pld_ctx);

  	if( err == RHP_STATUS_IKEV2_RETRY_COOKIE ){

  		err = _rhp_ikev2_rx_sess_resume_i_cookie(vpn,ikesa,s_pld_ctx.n_cookie_payload);
    	if( err ){
    		RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REP_L_COOKIE_RX_ERR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
    		goto error;
    	}

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REP_L_COOKIE_RETRY,"xxxd",rx_resp_ikemesg,vpn,ikesa,ikesa->cookies.cookie_retry);
    	goto retry;

  	}else if( err != -ENOENT ){

  		RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REP_L_COOKIE_RX_ENUM_N_COOKIE_ERR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_SESS_RESUME_RESP_PARSE_N_COOKIE_PAYLOAD_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
    	goto error;

    }else{
    	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_SESS_RESUME_RESP_NO_N_COOKIE_PAYLOAD,"KVP",rx_resp_ikemesg,vpn,ikesa);
    }
  }


  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_N),
  			_rhp_ikev2_sess_resume_srch_n_error_cb,&s_pld_ctx);

    if( ( err == 0 || err == RHP_STATUS_ENUM_OK ) && (s_pld_ctx.n_error_payload != NULL ) ){

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REP_L_PEER_NOTIFIED_ERROR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);

     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_SESS_RESUME_RESP_N_ERR_PAYLOAD,"KVPL",rx_resp_ikemesg,vpn,ikesa,"PROTO_IKE_NOTIFY",s_pld_ctx.n_err);

     	vpn->sess_resume_clear(vpn);

     	if( s_pld_ctx.n_err == RHP_PROTO_IKE_NOTIFY_ST_TICKET_NACK ){
     		err = RHP_STATUS_IKEV2_SESS_RESUME_RX_NACK;
     	}else{
     		err = RHP_STATUS_PEER_NOTIFIED_ERROR;
     	}

   	  goto error;

    }else if( err && err != -ENOENT ){
    	RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REP_L_ENUM_N_ERROR_ERR,"xxxE",rx_resp_ikemesg,vpn,ikesa,err);
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_SESS_RESUME_RESP_PARSE_N_ERR_PAYLOAD_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
    	goto error;
    }
  }

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_N_I_R),
  			rhp_ikev2_ike_sa_init_srch_nir_cb,&s_pld_ctx);

    if( err && err != RHP_STATUS_ENUM_OK ){
      RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REP_L_ENUM_NIR_PLD_ERR,"xxxd",rx_resp_ikemesg,vpn,ikesa,err);
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_SESS_RESUME_RESP_PARSE_N_I_R_PAYLOAD_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
  }


  if( rhp_gcfg_ikev2_enable_fragmentation ){

  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_n_mesg_id,
  			(void*)((unsigned long)RHP_PROTO_IKE_NOTIFY_ST_FRAG_SUPPORTED),
  			rhp_ikev2_ike_sa_init_srch_n_frag_supported_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
  		RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REP_L_FRAG_SUPPORTED_ERR,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_SESS_RESUME_RESP_PARSE_N_FRAGMENTATION_PAYLOAD_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
    	goto error;
  	}

  	vpn->exec_ikev2_frag = s_pld_ctx.frag_supported;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_I_ENUM_N_STATUS,"xxxdd",rx_resp_ikemesg,vpn,ikesa,ikesa->peer_http_cert_lookup_supported,vpn->exec_ikev2_frag);

  {
  	s_pld_ctx.dup_flag = 0;

  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  			rhp_ikev2_mesg_search_cond_my_verndor_id,NULL,
  			rhp_ikev2_ike_sa_init_srch_my_vid_cb,&s_pld_ctx);

  	if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
  		RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REP_L_ENUM_MY_VENDOR_ID_ERR,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
     	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_SESS_RESUME_RESP_PARSE_V_PAYLOAD_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
    	goto error;
  	}
  }


  memcpy(&(ikesa->prop.v2),old_sa_prop_i,sizeof(rhp_res_sa_proposal));

  ikesa->prf = rhp_crypto_prf_alloc(old_sa_prop_i->prf_id);
  if( ikesa->prf == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REP_L_I_PRF_ALLOC_ERR,"xxx",rx_resp_ikemesg,vpn,ikesa);
   	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_SESS_RESUME_RESP_PRF_ALG_ERR,"KVPdE",rx_resp_ikemesg,vpn,ikesa,old_sa_prop_i->prf_id,err);
    err = -EINVAL;
    goto error;
  }

  ikesa->integ_i = rhp_crypto_integ_alloc(old_sa_prop_i->integ_id);
  if( ikesa->integ_i == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REP_L_I_INTEG_I_ALLOC_ERR,"xxx",rx_resp_ikemesg,vpn,ikesa);
   	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_SESS_RESUME_RESP_INTEG_ALG_ERR,"KVPdE",rx_resp_ikemesg,vpn,ikesa,old_sa_prop_i->integ_id,err);
    err = -EINVAL;
    goto error;
  }

  ikesa->integ_r = rhp_crypto_integ_alloc(old_sa_prop_i->integ_id);
  if( ikesa->integ_r == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REP_L_I_INTEG_I_ALLOC_ERR,"xxx",rx_resp_ikemesg,vpn,ikesa);
   	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_SESS_RESUME_RESP_INTEG_ALG_ERR,"KVPdE",rx_resp_ikemesg,vpn,ikesa,old_sa_prop_i->integ_id,err);
    err = -EINVAL;
    goto error;
  }

  ikesa->encr = rhp_crypto_encr_alloc(old_sa_prop_i->encr_id,old_sa_prop_i->encr_key_bits);
  if( ikesa->encr == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REP_L_I_ENCR_ALLOC_ERR,"xxx",rx_resp_ikemesg,vpn,ikesa);
   	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_SESS_RESUME_RESP_ENCR_ALG_ERR,"KVPddE",rx_resp_ikemesg,vpn,ikesa,old_sa_prop_i->encr_id,old_sa_prop_i->encr_key_bits,err);
    err = -EINVAL;
    goto error;
  }


  ikesa->set_resp_spi(ikesa,ikeh->resp_spi);

  err = ikesa->nonce_r->set_nonce(ikesa->nonce_r,s_pld_ctx.nonce,s_pld_ctx.nonce_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

	err = ikesa->generate_keys(ikesa);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

  err = ikesa->encr->set_enc_key(ikesa->encr,ikesa->keys.v2.sk_ei,ikesa->keys.v2.sk_e_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  err = ikesa->encr->set_dec_key(ikesa->encr,ikesa->keys.v2.sk_er,ikesa->keys.v2.sk_e_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  err = ikesa->integ_i->set_key(ikesa->integ_i,ikesa->keys.v2.sk_ai,ikesa->keys.v2.sk_a_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  err = ikesa->integ_r->set_key(ikesa->integ_r,ikesa->keys.v2.sk_ar,ikesa->keys.v2.sk_a_len);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  ikesa->signed_octets.ikemesg_r_2nd = rx_resp_ikemesg;
  rhp_ikev2_hold_mesg(rx_resp_ikemesg);
  rhp_pkt_pending(rx_resp_ikemesg->rx_pkt);

  vpn->peer_is_rockhopper = s_pld_ctx.peer_is_rockhopper;
  vpn->peer_rockhopper_ver = s_pld_ctx.peer_rockhopper_ver;
  ikesa->peer_is_rockhopper = s_pld_ctx.peer_is_rockhopper;
  ikesa->peer_rockhopper_ver = s_pld_ctx.peer_rockhopper_ver;

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_SESS_RESUME_RESP_OK,"KVP",rx_resp_ikemesg,vpn,ikesa);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REP_L_RTRN,"xxx",rx_resp_ikemesg,vpn,ikesa);
  return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_SESS_RESUME_RESP_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
  if( ikesa ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REP_L_ERR,"xxx",rx_resp_ikemesg,vpn,ikesa);
  return err;

retry:
	RHP_LOG_D(RHP_LOG_SRC_IKEV2,(vpn ? vpn->vpn_realm_id : 0),RHP_LOG_ID_RX_SESS_RESUME_RESP_WAIT_RETRY,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);
  RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REP_L_RTRN_RETRY,"xxx",rx_resp_ikemesg,vpn,ikesa);
  return RHP_STATUS_IKEV2_MESG_HANDLER_END;
}

int rhp_ikev2_rx_sess_resume_rep(rhp_ikev2_mesg* rx_resp_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_resp_ikemesg->get_exchange_type(rx_resp_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REP,"xxLdGxLb",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_req_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

	if( exchange_type != RHP_PROTO_IKE_EXCHG_SESS_RESUME ){
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REP_NOT_SESS_RESUME_EXCHG,"xxLb",rx_resp_ikemesg,vpn,"PROTO_IKE_EXCHG",exchange_type);
		return 0;
	}

	if( RHP_PROTO_IKE_HDR_INITIATOR(rx_resp_ikemesg->rx_pkt->app.ikeh->flag) ){
		err = RHP_STATUS_INVALID_MSG;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REP_INVALID_MESG1,"xx",rx_resp_ikemesg,vpn);
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
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REP_NO_IKESA,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
		goto error;
	}

	if( !ikesa->gen_by_sess_resume ){
		err = RHP_STATUS_INVALID_MSG;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REP_GEN_NOT_BY_SESS_RESUME_SA,"xxLdGx",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,ikesa);
		goto error;
	}

	err = _rhp_ikev2_rx_sess_resume_rep(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_SESS_RESUME_REP_RTRN,"xxxE",rx_resp_ikemesg,vpn,tx_req_ikemesg,err);
  return err;
}



int rhp_ikev2_sess_resume_init()
{
	int err = -EINVAL;

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_MAIN ){
  	RHP_BUG("");
  	return -EINVAL;
  }

	{
		err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_SESS_RESUME_ENC_REPLY,
				_rhp_ikev2_sess_resume_tkt_enc_rep_ipc_handler,NULL);

		if( err ){
			RHP_BUG("");
			goto error;
		}
	}

	{
		err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_SESS_RESUME_DEC_REPLY,
				_rhp_ikev2_sess_resume_tkt_dec_rep_ipc_handler,NULL);

		if( err ){
			RHP_BUG("");
			goto error;
		}
	}

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_INIT_OK,"");
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_INIT_ERR,"E",err);
	return err;
}

int rhp_ikev2_sess_resume_cleanup()
{

	if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_MAIN ){
  	RHP_BUG("");
  	return -EINVAL;
  }

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_CLEANUP_OK,"");
	return 0;
}

