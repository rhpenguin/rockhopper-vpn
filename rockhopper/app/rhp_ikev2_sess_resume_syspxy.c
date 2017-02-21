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
#include "rhp_eap_auth_impl.h"

#include "rhp_bfilter.h"

static rhp_mutex_t _rhp_sess_resume_lock;

static rhp_timer _rhp_sess_resume_key_timer;


#define RHP_IKEV2_SESS_RESUME_KEY_MARGIN	3 // (secs)

char* rhp_syspxy_sess_resume_key_path = NULL;
char* rhp_syspxy_sess_resume_old_key_path = NULL;

char* rhp_syspxy_sess_resume_revocation_bfltr_path = NULL;
char* rhp_syspxy_sess_resume_revocation_old_bfltr_path = NULL;


extern void rhp_ikev2_sess_resume_tkt_dump(char* tag,rhp_ikev2_sess_resume_tkt* sess_res_tkt,int is_plain_txt);
extern void rhp_ikev2_sess_resume_tkt_log_dump(unsigned long rlm_id,rhp_ikev2_sess_resume_tkt* sess_res_tkt,int is_plain_txt);


struct _rhp_ikev2_sess_resume_key_data {

#define RHP_IKEV2_SESS_RESUME_KEY_DATA_VER		1
	u32 version;
	u64 key_index; // 0: Invalid key

	time_t expire_time;

	u8 enc_key[RHP_IKEV2_SESS_RESUME_TKT_ENC_KEY_LEN];
	u8 mac_key[RHP_IKEV2_SESS_RESUME_TKT_MAC_KEY_LEN];
};
typedef struct _rhp_ikev2_sess_resume_key_data	rhp_ikev2_sess_resume_key_data;

struct _rhp_ikev2_sess_resume_key {

	rhp_ikev2_sess_resume_key_data key;

	rhp_crypto_encr* encr;
	rhp_crypto_integ* mac;

	rhp_bloom_filter* revocation_bfltr;
};
typedef struct _rhp_ikev2_sess_resume_key	rhp_ikev2_sess_resume_key;


static rhp_ikev2_sess_resume_key _rhp_sess_res_key_cur;
static rhp_ikev2_sess_resume_key _rhp_sess_res_key_old;


static int _rhp_ikev2_sess_resume_copy_key(rhp_ikev2_sess_resume_key_data* to,rhp_ikev2_sess_resume_key_data* from)
{
	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_COPY_KEY,"qfpqfp",to->key_index,to->expire_time,sizeof(rhp_ikev2_sess_resume_key_data),to,from->key_index,from->expire_time,sizeof(rhp_ikev2_sess_resume_key_data),from);
	memcpy(to,from,sizeof(rhp_ikev2_sess_resume_key_data));
	return 0;
}

static int _rhp_ikev2_sess_resume_gen_key(u64 new_key_idx,rhp_ikev2_sess_resume_key_data* new_key_r)
{
	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_GEN_KEY,"qxd",new_key_idx,new_key_r,rhp_gcfg_ikev2_sess_resume_key_update_interval);

	new_key_r->version = RHP_IKEV2_SESS_RESUME_KEY_DATA_VER;

	new_key_r->key_index = new_key_idx;

	new_key_r->expire_time = _rhp_get_realtime() + (time_t)(rhp_gcfg_ikev2_sess_resume_key_update_interval*2);

  if( rhp_random_bytes(new_key_r->enc_key,RHP_IKEV2_SESS_RESUME_TKT_ENC_KEY_LEN) ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  if( rhp_random_bytes(new_key_r->mac_key,RHP_IKEV2_SESS_RESUME_TKT_MAC_KEY_LEN) ){
  	RHP_BUG("");
  	return -EINVAL;
  }

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_GEN_KEY_RTRN,"qxqfp",new_key_idx,new_key_r,new_key_r->key_index,new_key_r->expire_time,sizeof(rhp_ikev2_sess_resume_key_data),new_key_r);
  return 0;
}

static void _rhp_sess_resume_syspxy_bfltr_dump(rhp_bloom_filter* bf_ctx)
{
	_RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
  if( _RHP_TRC_COND(_rhp_trc_user_id(),0) ){

		if( bf_ctx ){

			char false_ratio_str[128];
			char false_ratio_str2[128];

			pthread_mutex_lock(&(bf_ctx->lock));


			snprintf(false_ratio_str,128,"%f",bf_ctx->false_ratio);

			if( bf_ctx->fdata ){
				snprintf(false_ratio_str2,128,"%f",bf_ctx->fdata->false_ratio);
			}else{
				false_ratio_str2[0] = '\0';
			}


	 		RHP_TRC_FREQ(0,RHPTRCID_IKEV2_SES_RESUME_SYSPXY_BFLTR_DUMP,"xjsjjjjjsdxksjjp",bf_ctx,bf_ctx->max_num_of_elements,false_ratio_str,bf_ctx->hashes_num,bf_ctx->bitmap_len,bf_ctx->bitmap_bytes_len,bf_ctx->added_num,bf_ctx->collision_num,bf_ctx->file_path,bf_ctx->fd,bf_ctx->fdata,(bf_ctx->fdata ? bf_ctx->fdata->magic : 0),false_ratio_str2,(bf_ctx->fdata ? bf_ctx->fdata->added_num : 0),(bf_ctx->fdata ? bf_ctx->fdata->collision_num : 0),(bf_ctx->fdata ? RHP_BFLTR_FDATA_TAG_LEN : 0),(bf_ctx->fdata ? bf_ctx->fdata->tag : NULL));
#ifdef RHP_BFLTR_DETAIL
			{
				int ext_len = sizeof(rhp_bloom_filter_fdata)
											+ bf_ctx->bitmap_bytes_len + (sizeof(32)*bf_ctx->hashes_num);

				if( bf_ctx->fdata == NULL ){
					ext_len = 0;
				}

				RHP_TRC_FREQ(0,RHPTRCID_IKEV2_SES_RESUME_SYSPXY_BFLTR_DUMP_2,"xpppp",bf_ctx,bf_ctx->bitmap_bytes_len,bf_ctx->bitmap,sizeof(u32)*bf_ctx->hashes_num,bf_ctx->salts,ext_len,(u8*)bf_ctx->fdata,sizeof(u32)*bf_ctx->hashes_num,bf_ctx->bitmap_updated_idxes);
			}
#endif // RHP_BFLTR_DETAIL

			pthread_mutex_unlock(&(bf_ctx->lock));

		}else{

			RHP_TRC_FREQ(0,RHPTRCID_IKEV2_SES_RESUME_SYSPXY_BFLTR_DUMP_NULL,"x",bf_ctx);
		}
  }
}

static void _rhp_ikev2_sess_resume_tkt_rvk_get_tag(rhp_ikev2_sess_resume_key* key_obj,u8* tag_r)
{
	u8 tag[RHP_BFLTR_FDATA_TAG_LEN];

	memset(tag,0,RHP_BFLTR_FDATA_TAG_LEN);
	memcpy(tag,&(key_obj->key.key_index),sizeof(u64));
	memcpy((tag + sizeof(u64)),&(key_obj->key.expire_time),sizeof(time_t));

	memcpy(tag_r,tag,RHP_BFLTR_FDATA_TAG_LEN);
	return;
}


static void* _rhp_bfltr_malloc(size_t size)
{
	return _rhp_malloc(size);
}

static void _rhp_bfltr_free(void *ptr)
{
	_rhp_free(ptr);
}

static int _rhp_ikev2_sess_resume_tkt_rvk_open_bfltr(rhp_ikev2_sess_resume_key* key_obj,char* path)
{
	int err = -EINVAL;
	u8 tag[RHP_BFLTR_FDATA_TAG_LEN];

	_rhp_ikev2_sess_resume_tkt_rvk_get_tag(key_obj,tag);

	key_obj->revocation_bfltr = rhp_bloom_filter_alloc_ex(
			(u64)rhp_gcfg_ikev2_sess_resume_tkt_rvk_bfltr_max_tkts,
			rhp_gcfg_ikev2_sess_resume_tkt_rvk_bfltr_false_ratio,
			path,(S_IRUSR | S_IWUSR | S_IXUSR),
			_rhp_sess_resume_syspxy_bfltr_dump,_rhp_bfltr_malloc,_rhp_bfltr_free,NULL,
			tag);
	if( key_obj->revocation_bfltr == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	key_obj->revocation_bfltr->dump(key_obj->revocation_bfltr);

	return 0;

error:
	key_obj->revocation_bfltr = NULL;
	return err;
}

static int _rhp_ikev2_sess_resume_update_key()
{
	int err = -EINVAL;
	rhp_ikev2_sess_resume_key_data new_key;
	u64 new_key_idx = 1;

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_UPDATE_KEY,"xqxq",&_rhp_sess_res_key_cur,_rhp_sess_res_key_cur.key.key_index,&_rhp_sess_res_key_old,_rhp_sess_res_key_old.key.key_index);

	if( _rhp_sess_res_key_cur.key.key_index ){

		new_key_idx = (_rhp_sess_res_key_cur.key.key_index + 1);
		if( new_key_idx == 0 ){
			new_key_idx = 1;
		}
	}

	err = _rhp_ikev2_sess_resume_gen_key(new_key_idx,&new_key);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	{
		err = _rhp_sess_res_key_old.encr->set_enc_key(_rhp_sess_res_key_old.encr,
				_rhp_sess_res_key_cur.key.enc_key,RHP_IKEV2_SESS_RESUME_TKT_ENC_KEY_LEN);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		err = _rhp_sess_res_key_old.encr->set_dec_key(_rhp_sess_res_key_old.encr,
				_rhp_sess_res_key_cur.key.enc_key,RHP_IKEV2_SESS_RESUME_TKT_ENC_KEY_LEN);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		err = _rhp_sess_res_key_old.mac->set_key(_rhp_sess_res_key_old.mac,
				_rhp_sess_res_key_cur.key.mac_key,RHP_IKEV2_SESS_RESUME_TKT_MAC_KEY_LEN);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
	}

	{
		err = _rhp_sess_res_key_cur.encr->set_enc_key(_rhp_sess_res_key_cur.encr,
				new_key.enc_key,RHP_IKEV2_SESS_RESUME_TKT_ENC_KEY_LEN);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		err = _rhp_sess_res_key_cur.encr->set_dec_key(_rhp_sess_res_key_cur.encr,
				new_key.enc_key,RHP_IKEV2_SESS_RESUME_TKT_ENC_KEY_LEN);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		err = _rhp_sess_res_key_cur.mac->set_key(_rhp_sess_res_key_cur.mac,
				new_key.mac_key,RHP_IKEV2_SESS_RESUME_TKT_MAC_KEY_LEN);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
	}

	memcpy(&_rhp_sess_res_key_old.key,&_rhp_sess_res_key_cur.key,sizeof(rhp_ikev2_sess_resume_key_data));
	memcpy(&_rhp_sess_res_key_cur.key,&new_key,sizeof(rhp_ikev2_sess_resume_key_data));

	{
		err = rhp_file_write(rhp_syspxy_sess_resume_old_key_path,
				(u8*)&_rhp_sess_res_key_old.key,sizeof(rhp_ikev2_sess_resume_key_data),(S_IRUSR | S_IWUSR | S_IXUSR));
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		err = rhp_file_write(rhp_syspxy_sess_resume_key_path,
				(u8*)&_rhp_sess_res_key_cur.key,sizeof(rhp_ikev2_sess_resume_key_data),(S_IRUSR | S_IWUSR | S_IXUSR));
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
	}

	if( rhp_gcfg_ikev2_sess_resume_resp_tkt_revocation ){

		if( _rhp_sess_res_key_cur.revocation_bfltr ){

			rhp_bloom_filter_free(_rhp_sess_res_key_cur.revocation_bfltr);
			_rhp_sess_res_key_cur.revocation_bfltr = NULL;
		}

		if( _rhp_sess_res_key_old.revocation_bfltr ){

			rhp_bloom_filter_free(_rhp_sess_res_key_old.revocation_bfltr);
			_rhp_sess_res_key_old.revocation_bfltr = NULL;
		}

		if( unlink(rhp_syspxy_sess_resume_revocation_old_bfltr_path) < 0 ){
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_UPDATE_KEY_UNLINK_OLD_RVK_BFLTR_FILE_ERR,"sE",rhp_syspxy_sess_resume_revocation_old_bfltr_path,-errno);
		}

		if( rename(rhp_syspxy_sess_resume_revocation_bfltr_path,rhp_syspxy_sess_resume_revocation_old_bfltr_path) < 0 ){
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_UPDATE_KEY_RENAME_RVK_BFLTR_FILE_ERR,"ssE",rhp_syspxy_sess_resume_revocation_bfltr_path,rhp_syspxy_sess_resume_revocation_old_bfltr_path,-errno);
		}


		err = _rhp_ikev2_sess_resume_tkt_rvk_open_bfltr(&_rhp_sess_res_key_cur,
					rhp_syspxy_sess_resume_revocation_bfltr_path);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		_rhp_sess_res_key_cur.revocation_bfltr->reset(_rhp_sess_res_key_cur.revocation_bfltr);


		err = _rhp_ikev2_sess_resume_tkt_rvk_open_bfltr(&_rhp_sess_res_key_old,
					rhp_syspxy_sess_resume_revocation_old_bfltr_path);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_TKT_RVK_DEPL_BFLTR,"xx",_rhp_sess_res_key_cur.revocation_bfltr,_rhp_sess_res_key_old.revocation_bfltr);
	}

	if( rhp_gcfg_dbg_log_keys_info ){
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_SESS_RESUME_KEY_UPDATED,"qupp",_rhp_sess_res_key_cur.key.key_index,_rhp_sess_res_key_cur.key.expire_time,RHP_IKEV2_SESS_RESUME_TKT_ENC_KEY_LEN,_rhp_sess_res_key_cur.key.enc_key,RHP_IKEV2_SESS_RESUME_TKT_MAC_KEY_LEN,_rhp_sess_res_key_cur.key.mac_key);
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_SESS_RESUME_KEY_UPDATED_OLD_KEY,"qupp",_rhp_sess_res_key_old.key.key_index,_rhp_sess_res_key_old.key.expire_time,RHP_IKEV2_SESS_RESUME_TKT_ENC_KEY_LEN,_rhp_sess_res_key_old.key.enc_key,RHP_IKEV2_SESS_RESUME_TKT_MAC_KEY_LEN,_rhp_sess_res_key_old.key.mac_key);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_UPDATE_KEY_RTRN,"xqxq",&_rhp_sess_res_key_cur,_rhp_sess_res_key_cur.key.key_index,&_rhp_sess_res_key_old,_rhp_sess_res_key_old.key.key_index);
	return 0;

error:
	_rhp_sess_res_key_cur.key.key_index = 0;
	_rhp_sess_res_key_old.key.key_index = 0;
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_SESS_RESUME_KEY_UPDATED_ERR,"quE",_rhp_sess_res_key_cur.key.key_index,_rhp_sess_res_key_cur.key.expire_time,err);
	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_UPDATE_KEY_ERR,"xqxqE",&_rhp_sess_res_key_cur,_rhp_sess_res_key_cur.key.key_index,&_rhp_sess_res_key_old,_rhp_sess_res_key_old.key.key_index,err);
	return err;
}

static int _rhp_sess_resume_syspxy_enc_tkt_impl(rhp_vpn_auth_realm* auth_rlm,
		u64 key_index,rhp_ikev2_sess_resume_tkt* sess_res_tkt,
		rhp_crypto_encr* encr,rhp_crypto_integ* mac,
		rhp_ikev2_sess_resume_tkt** sess_res_tkt_r,int64_t* expire_time_r)
{
	int err = -EINVAL;
	rhp_ikev2_sess_resume_tkt *tkt_plain = NULL;
	rhp_ikev2_sess_resume_tkt_e *tkt_e_plain = NULL, *tkt_e_enc = NULL;
	u8 mac_val_r[RHP_IKEV2_SESS_RESUME_TKT_MAC_LEN];
	int tkt_len = sizeof(rhp_ikev2_sess_resume_tkt) + RHP_IKEV2_SESS_RESUME_TKT_MAC_LEN;
	rhp_ikev2_sess_resume_tkt_e* sess_res_tkt_e = (rhp_ikev2_sess_resume_tkt_e*)(sess_res_tkt + 1);
	u16 sess_res_tkt_e_len = ntohs(sess_res_tkt_e->len);
	int aligned_len = encr->get_block_aligned_len(encr,(int)sess_res_tkt_e_len);
	int pad_len = aligned_len - (int)sess_res_tkt_e_len;
	u8* pad_p = NULL;
	u8 new_encr_iv[RHP_IKEV2_SESS_RESUME_TKT_ENC_IV_LEN];
	u8 i;
	time_t exp_time = 0;
	time_t now = _rhp_get_realtime();

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_ENC_TKT_IMPL,"xqxxxxx",auth_rlm,key_index,sess_res_tkt,encr,mac,sess_res_tkt_r,expire_time_r);

	tkt_len += aligned_len;

	tkt_plain = (rhp_ikev2_sess_resume_tkt*)_rhp_malloc(tkt_len);
	if( tkt_plain == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	tkt_e_enc = (rhp_ikev2_sess_resume_tkt_e*)_rhp_malloc(aligned_len);
	if( tkt_e_enc == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}


	memset(tkt_plain,0,tkt_len);
	tkt_e_plain = (rhp_ikev2_sess_resume_tkt_e*)(tkt_plain + 1);
	pad_p = ((u8*)tkt_e_plain) + sess_res_tkt_e_len;

	memcpy(tkt_plain,sess_res_tkt,sizeof(rhp_ikev2_sess_resume_tkt));
	tkt_plain->len = htons((u16)tkt_len);
	tkt_plain->key_index = _rhp_htonll(key_index);
	memcpy(tkt_plain->enc_iv,encr->get_enc_iv(encr),RHP_IKEV2_SESS_RESUME_TKT_ENC_IV_LEN);


	memcpy(tkt_e_plain,sess_res_tkt_e,(int)ntohs(sess_res_tkt_e->len));

	tkt_e_plain->auth_method_r = auth_rlm->my_auth->auth_method;

	tkt_e_plain->pad_len = htons((u16)aligned_len - sess_res_tkt_e_len);
	tkt_e_plain->len = htons((u16)aligned_len);

	tkt_e_plain->created_time = (int64_t)_rhp_htonll((u64)now);

	{
		time_t exp_time_r = (time_t)_rhp_ntohll((u64)(tkt_e_plain->expire_time));

		exp_time = now + rhp_gcfg_ikev2_sess_resume_ticket_lifetime;

		if( tkt_e_plain->expire_time == 0 ||
				exp_time_r > exp_time ){

			tkt_e_plain->expire_time = (int64_t)_rhp_htonll((u64)exp_time);

		}else{

			exp_time = exp_time_r;
		}
	}

	for(i = 0; i < pad_len; i++){
		pad_p[i] = i;
	}

	rhp_ikev2_sess_resume_tkt_dump("_rhp_sess_resume_syspxy_enc_tkt_impl plain",tkt_plain,1);
  rhp_ikev2_sess_resume_tkt_log_dump(auth_rlm->id,tkt_plain,1);

	{
		err = encr->encrypt(encr,(u8*)tkt_e_plain,aligned_len,(u8*)tkt_e_enc,aligned_len);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		if( rhp_random_bytes(new_encr_iv,RHP_IKEV2_SESS_RESUME_TKT_ENC_IV_LEN) ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		err = encr->update_enc_iv(encr,new_encr_iv,RHP_IKEV2_SESS_RESUME_TKT_ENC_IV_LEN);
		if( err ){
			RHP_BUG("");
			goto error;
		}

		memcpy(tkt_e_plain,tkt_e_enc,aligned_len);
	}

	{
		err = mac->compute(mac,(u8*)tkt_plain,tkt_len,mac_val_r,RHP_IKEV2_SESS_RESUME_TKT_MAC_LEN);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		memcpy((pad_p + pad_len),mac_val_r,RHP_IKEV2_SESS_RESUME_TKT_MAC_LEN);
	}

	*sess_res_tkt_r = tkt_plain;
	*expire_time_r = (int64_t)exp_time;

	_rhp_free(tkt_e_enc);

	rhp_ikev2_sess_resume_tkt_dump("_rhp_sess_resume_syspxy_enc_tkt_impl enc",tkt_plain,0);
	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_ENC_TKT_IMPL_RTRN,"xqxxxxxq",auth_rlm,key_index,sess_res_tkt,encr,mac,sess_res_tkt_r,*sess_res_tkt_r,*expire_time_r);
	return 0;

error:
	if( tkt_plain ){
		_rhp_free(tkt_plain);
	}
	if( tkt_e_enc ){
		_rhp_free(tkt_e_enc);
	}
	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_ENC_TKT_IMPL_ERR,"xqxE",auth_rlm,key_index,sess_res_tkt,err);
	return err;
}

static int _rhp_sess_resume_syspxy_enc_tkt(rhp_vpn_auth_realm* auth_rlm,
		rhp_ikev2_sess_resume_tkt* sess_res_tkt,
		rhp_ikev2_sess_resume_tkt** sess_res_tkt_r,int64_t* expire_time_r)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_ENC_TKT,"xxxx",auth_rlm,sess_res_tkt,sess_res_tkt_r,expire_time_r);
	rhp_ikev2_sess_resume_tkt_dump("_rhp_sess_resume_syspxy_enc_tkt",sess_res_tkt,1);

	// TODO: Store key info into TLS buffers.
  RHP_LOCK(&_rhp_sess_resume_lock);

  if( _rhp_sess_res_key_cur.key.key_index == 0 ){
  	err = -EINVAL;
		RHP_BUG("%d",err);
		goto error;
  }


	err = _rhp_sess_resume_syspxy_enc_tkt_impl(auth_rlm,_rhp_sess_res_key_cur.key.key_index,
					sess_res_tkt,_rhp_sess_res_key_cur.encr,_rhp_sess_res_key_cur.mac,
					sess_res_tkt_r,expire_time_r);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

  RHP_UNLOCK(&_rhp_sess_resume_lock);

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_ENC_TKT_RTRN,"xxxxxq",auth_rlm,sess_res_tkt,sess_res_tkt_r,*sess_res_tkt_r,expire_time_r,*expire_time_r);
  return 0;

error:
	RHP_UNLOCK(&_rhp_sess_resume_lock);
	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_ENC_TKT_ERR,"xxE",auth_rlm,sess_res_tkt,err);
	return err;
}

static int _rhp_sess_resume_syspxy_radius_dec_tkt_check(rhp_ikev2_sess_resume_tkt_e* sess_res_tkt_e,
		rhp_radius_sess_ressume_tkt* sess_res_radius_tkt,rhp_string_list** role_strings_r)
{
	int err = -EINVAL;
	u16 radius_tkt_len;
	u8 *p = NULL,*endp = NULL;
	rhp_string_list *role_strings_head = NULL, *role_strings_tail = NULL;
	int i, attrs_num = 0;

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_RADIUS_DEC_TKT_CHECK,"xxx",sess_res_tkt_e,sess_res_radius_tkt,role_strings_r);

	if( ntohs(sess_res_tkt_e->eap_i_method) != RHP_PROTO_EAP_TYPE_PRIV_RADIUS ){
		err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_RADIUS_TKT;
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_RADIUS_DEC_TKT_CHECK_INVALID_TKT_1,"xxLW",sess_res_tkt_e,sess_res_radius_tkt,role_strings_r,"EAP_TYPE",sess_res_tkt_e->eap_i_method);
		goto error;
	}

	radius_tkt_len = ntohs(sess_res_tkt_e->radius_info_len);
	if( radius_tkt_len < sizeof(rhp_radius_sess_ressume_tkt) ){
		err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_RADIUS_TKT;
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_RADIUS_DEC_TKT_CHECK_INVALID_TKT_2,"xxdd",sess_res_tkt_e,sess_res_radius_tkt,radius_tkt_len,sizeof(rhp_radius_sess_ressume_tkt));
		goto error;
	}

	if( radius_tkt_len != ntohs(sess_res_radius_tkt->radius_tkt_len) ){
		err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_RADIUS_TKT;
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_RADIUS_DEC_TKT_CHECK_INVALID_TKT_3,"xxdW",sess_res_tkt_e,sess_res_radius_tkt,radius_tkt_len,sess_res_radius_tkt->radius_tkt_len);
		goto error;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_RADIUS_DEC_TKT_CHECK_DUMP,"xxWLwWQUU46bb46446",sess_res_tkt_e,sess_res_radius_tkt,sess_res_radius_tkt->radius_tkt_len,"EAP_TYPE",ntohs(sess_res_radius_tkt->eap_method),sess_res_radius_tkt->attrs_num,sess_res_radius_tkt->rx_accept_attrs_mask,sess_res_radius_tkt->session_timeout,sess_res_radius_tkt->framed_mtu,sess_res_radius_tkt->internal_addr_ipv4,sess_res_radius_tkt->internal_addr_ipv6,sess_res_radius_tkt->internal_addr_ipv4_prefix,sess_res_radius_tkt->internal_addr_ipv6_prefix,sess_res_radius_tkt->internal_dns_server_ipv4,sess_res_radius_tkt->internal_dns_server_ipv6,sess_res_radius_tkt->internal_wins_server_ipv4,sess_res_radius_tkt->internal_gateway_ipv4,sess_res_radius_tkt->internal_gateway_ipv6);


	attrs_num = ntohs(sess_res_radius_tkt->attrs_num);

	if( attrs_num > RHP_SESS_RESUME_RADIUS_ATTRS_MAX_NUM ){
		err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_RADIUS_TKT;
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_RADIUS_DEC_TKT_CHECK_INVALID_TKT_TOO_MANY_ATTRS,"xxdd",sess_res_tkt_e,sess_res_radius_tkt,sizeof(rhp_radius_sess_resume_tkt_attr),attrs_num);
		goto error;
	}


	p = (u8*)(sess_res_radius_tkt + 1);
	endp = ((u8*)sess_res_radius_tkt) + radius_tkt_len;


	for( i = 0; i < attrs_num; i++ ){

		u16 attr_len;
		u16 attr_type;
		rhp_radius_sess_resume_tkt_attr* attr = (rhp_radius_sess_resume_tkt_attr*)p;

		if( p + sizeof(rhp_radius_sess_resume_tkt_attr) > endp ){
			err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_RADIUS_TKT;
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_RADIUS_DEC_TKT_CHECK_INVALID_TKT_4,"xxxxd",sess_res_tkt_e,sess_res_radius_tkt,p,endp,sizeof(rhp_radius_sess_resume_tkt_attr));
			goto error;
		}

		attr_type = ntohs(attr->type);
		attr_len = ntohs(attr->len);

		if( p + attr_len > endp ){
			err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_RADIUS_TKT;
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_RADIUS_DEC_TKT_CHECK_INVALID_TKT_5,"xxxxw",sess_res_tkt_e,sess_res_radius_tkt,p,endp,attr_len);
			goto error;
		}

		if( attr_type == RHP_SESS_RESUME_RADIUS_ATTR_PRIV_REALM_ROLE ||
				attr_type == RHP_SESS_RESUME_RADIUS_ATTR_TUNNEL_PRIVATE_GROUP_ID ){

			rhp_string_list* role_string;
			int slen;

			if( attr_len <= sizeof(rhp_radius_sess_resume_tkt_attr) ){
				err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_RADIUS_TKT;
				RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_RADIUS_DEC_TKT_CHECK_INVALID_TKT_6,"xxxxw",sess_res_tkt_e,sess_res_radius_tkt,p,endp,attr_len);
				goto error;
			}

			role_string = (rhp_string_list*)_rhp_malloc(sizeof(rhp_string_list));
			if( role_string == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}
			memset(role_string,0,sizeof(rhp_string_list));

			slen = attr_len - sizeof(rhp_radius_sess_resume_tkt_attr);
			role_string->string = (char*)_rhp_malloc(slen + 1);
			if( role_string->string == NULL ){
				_rhp_free(role_string);
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			memcpy(role_string->string,(u8*)(attr + 1),slen);
			role_string->string[slen] = '\0';

			if( role_strings_head == NULL ){
				role_strings_head = role_string;
			}else{
				role_strings_tail->next = role_string;
			}
			role_strings_tail = role_string;

			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_RADIUS_DEC_TKT_CHECK_ATTR_ROLE,"xxwpxs",sess_res_tkt_e,sess_res_radius_tkt,attr_type,attr_len,(u8*)attr,role_string,role_string->string);

		}else{

			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_RADIUS_DEC_TKT_CHECK_ATTR_VAL,"xxwp",sess_res_tkt_e,sess_res_radius_tkt,attr_type,attr_len,(u8*)attr);
		}

		p += attr_len;
	}

	*role_strings_r = role_strings_head;

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_RADIUS_DEC_TKT_CHECK_RTRN,"xxx",sess_res_tkt_e,sess_res_radius_tkt,*role_strings_r);
	return 0;

error:
	if( role_strings_head ){
		_rhp_string_list_free(role_strings_head);
	}
	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_RADIUS_DEC_TKT_CHECK_ERR,"xxE",sess_res_tkt_e,sess_res_radius_tkt,err);
	return err;
}

static int _rhp_sess_resume_syspxy_dec_tkt_check(rhp_ikev2_sess_resume_tkt* sess_res_tkt,
		rhp_ikev2_sess_resume_tkt_e* sess_res_tkt_e)
{
	int err = -EINVAL;
	rhp_vpn_auth_realm* auth_rlm = NULL;
	u8 *id_i = NULL, *alt_id_i = NULL;
	int id_i_len = 0, alt_id_i_len = 0;
	u8 *id_r = NULL, *alt_id_r = NULL;
	int id_r_len = 0, alt_id_r_len = 0;
	u8 *eap_id_i = NULL;
	int eap_id_i_len = 0;
	rhp_ikev2_id my_id, peer_id;
  rhp_eap_id eap_peer_id;
  rhp_radius_sess_ressume_tkt* sess_res_radius_tkt = NULL;
  rhp_string_list* radius_role_strings = NULL;
  unsigned long tkt_vpn_realm_id = (unsigned long)_rhp_ntohll(sess_res_tkt_e->vpn_realm_id);
  int eap_i_method = RHP_PROTO_EAP_TYPE_NONE;
  unsigned long vpn_realm_id_by_radius = RHP_VPN_REALM_ID_UNKNOWN;

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK,"xxu",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id);

  memset(&my_id,0,sizeof(rhp_ikev2_id));
  memset(&peer_id,0,sizeof(rhp_ikev2_id));
	memset(&eap_peer_id,0,sizeof(rhp_eap_id));

	if( tkt_vpn_realm_id == 0 ||
			tkt_vpn_realm_id == RHP_VPN_REALM_ID_UNKNOWN ||
			tkt_vpn_realm_id > RHP_VPN_REALM_ID_MAX ){
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_INVALID_RLM_ID,"xxu",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id);
		err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
		goto error;
	}


	err = rhp_ikev2_sess_resume_dec_tkt_vals(
					sess_res_tkt,NULL,NULL,&id_i,&alt_id_i,&id_r,&alt_id_r,&eap_id_i,
					(u8**)&sess_res_radius_tkt);
	if( err ){
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_INVALID_VALS,"xxu",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id);
		goto error;
	}


	eap_i_method = (int)ntohs(sess_res_tkt_e->eap_i_method);

	if( eap_i_method == RHP_PROTO_EAP_TYPE_NONE && eap_id_i ){
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_NOT_EAP_METHOD_I,"xxdx",sess_res_tkt,sess_res_tkt_e,eap_i_method,eap_id_i);
		goto error;
	}

	{
		if( sess_res_tkt_e->id_r_type != RHP_PROTO_IKE_ID_NULL_ID ){

			if( id_r == NULL ){
				err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
				RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_NO_ID_R,"xxu",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id);
				goto error;
			}

		}else{

			if( id_r ){
				err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
				RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_ID_R_INVALID_NULL_ID,"xxux",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id,id_r);
				goto error;
			}
		}
		id_r_len = (int)ntohs(sess_res_tkt_e->id_r_len);

		err = rhp_ikev2_id_setup(sess_res_tkt_e->id_r_type,id_r,id_r_len,&my_id);
		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_ID_R_SETUP_ERR,"xxuE",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id,err);
			goto error;
		}

		if( alt_id_r ){

			alt_id_r_len = ntohs(sess_res_tkt_e->alt_id_r_len);
		}
	}

	{
		if( sess_res_tkt_e->id_i_type != RHP_PROTO_IKE_ID_NULL_ID ){

			if( id_i == NULL ){
				err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
				RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_NO_ID_I,"xxu",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id);
				goto error;
			}

		}else{

			if( id_i ){
				err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
				RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_INVALID_NULL_ID,"xxux",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id,id_i);
				goto error;
			}
		}
		id_i_len = (int)ntohs(sess_res_tkt_e->id_i_len);

		err = rhp_ikev2_id_setup(sess_res_tkt_e->id_i_type,id_i,id_i_len,&peer_id);
		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_ID_I_SETUP_ERR,"xxuE",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id,err);
			goto error;
		}

		if( alt_id_i ){

			err = rhp_ikev2_id_alt_setup(sess_res_tkt_e->alt_id_i_type,alt_id_i,alt_id_i_len,&peer_id);
			if( err ){
				goto error;
			}
		}
	}

	if( eap_id_i ){

		eap_id_i_len = ntohs(sess_res_tkt_e->eap_identity_len);

		err = rhp_eap_id_setup(eap_i_method,eap_id_i_len,eap_id_i,0,&eap_peer_id);
		if( err ){
			RHP_BUG("");
			goto error;
		}
	}

	rhp_ikev2_id_dump("dec_tkt_check:my_id",&my_id);
	rhp_ikev2_id_dump("dec_tkt_check:peer_id",&peer_id);
	rhp_eap_id_dump("dec_tkt_check:eap_peer_id",&eap_peer_id);


	if( sess_res_radius_tkt ){

		err = _rhp_sess_resume_syspxy_radius_dec_tkt_check(sess_res_tkt_e,sess_res_radius_tkt,&radius_role_strings);
		if( err ){
			goto error;
		}

		if( sess_res_radius_tkt->vpn_realm_id_by_radius ){

			vpn_realm_id_by_radius
				= (unsigned long)_rhp_ntohll(sess_res_radius_tkt->vpn_realm_id_by_radius);
		}
	}

	if( eap_i_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS &&
			vpn_realm_id_by_radius && vpn_realm_id_by_radius != RHP_VPN_REALM_ID_UNKNOWN ){

		auth_rlm = rhp_auth_realm_get(vpn_realm_id_by_radius);

	}else if( eap_i_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS && radius_role_strings ){

		auth_rlm = rhp_auth_realm_get_by_role(&my_id,RHP_PEER_ID_TYPE_RADIUS_RX_ROLE,
			(void*)radius_role_strings,NULL,1,tkt_vpn_realm_id);

	}else if( eap_id_i ){

		if( eap_i_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS &&
				!rhp_eap_identity_not_protected((int)ntohs(sess_res_radius_tkt->eap_method)) ){

			auth_rlm = rhp_auth_realm_get(tkt_vpn_realm_id);

		}else{

			auth_rlm = rhp_auth_realm_get_by_role(&my_id,RHP_PEER_ID_TYPE_EAP,
					(void*)&eap_peer_id,NULL,1,tkt_vpn_realm_id);
		}

	}else{

		auth_rlm = rhp_auth_realm_get_by_role(&my_id,RHP_PEER_ID_TYPE_IKEV2,
			(void*)&peer_id,NULL,1,tkt_vpn_realm_id);
	}

	if( auth_rlm == NULL ){
		err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_NO_RLM_FOUND,"xxuxxLwLwd",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id,eap_id_i,radius_role_strings,"EAP_TYPE",eap_i_method,"EAP_TYPE",ntohs(sess_res_radius_tkt->eap_method),rhp_gcfg_radius_mschapv2_eap_identity_not_protected);
		goto error;
	}


	RHP_LOCK(&(auth_rlm->lock));

	if( !_rhp_atomic_read(&(auth_rlm->is_active)) ){
		err = -EINVAL;
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_RLM_IS_NOT_ACTIVE,"xxux",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id,auth_rlm);
		goto error;
	}

	if( auth_rlm->my_auth == NULL ){
		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_RLM_NO_MY_AUTH,"xxux",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id,auth_rlm);
		goto error;
	}

	rhp_ikev2_id_dump("dec_tkt_check:my_auth->my_id",&(auth_rlm->my_auth->my_id));

	if( auth_rlm->my_auth->auth_method != sess_res_tkt_e->auth_method_r ){
		err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_INVALID_AUTH_METHOD,"xxuxdb",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id,auth_rlm,auth_rlm->my_auth->auth_method,sess_res_tkt_e->auth_method_r);
		goto error;
	}

	if( eap_i_method != RHP_PROTO_EAP_TYPE_NONE ){

		if( auth_rlm->eap.role != RHP_EAP_AUTHENTICATOR ){
			err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_NOT_EAP_AUTHENTICATOR,"xxuxdbx",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id,auth_rlm,auth_rlm->eap.role,(int)eap_i_method,eap_id_i);
			goto error;
		}

		if( eap_i_method != auth_rlm->eap.method ){
			err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_INVALID_EAP_METHOD_I,"xxuxbd",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id,auth_rlm,eap_i_method,auth_rlm->eap.method);
			goto error;
		}

		if( sess_res_tkt_e->eap_identity_len == 0 ){
			err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_NO_EAP_IDENTITY_FOUND,"xxux",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id,auth_rlm);
			goto error;
		}
	}

	if( (alt_id_r && auth_rlm->my_auth->my_id.alt_id == NULL) ||
			(alt_id_r == NULL && auth_rlm->my_auth->my_id.alt_id) ||
			(alt_id_r && auth_rlm->my_auth->my_id.alt_id &&
			 rhp_ikev2_id_cmp_sub_type_too_by_value(auth_rlm->my_auth->my_id.alt_id,sess_res_tkt_e->alt_id_r_type,alt_id_r_len,alt_id_r)) ){
		err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_INVALID_ID_R,"xxuxxx",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id,auth_rlm,alt_id_r,auth_rlm->my_auth->my_id.alt_id);
		goto error;
	}

	{
		rhp_auth_peer* auth_peer = NULL;

		if( eap_i_method != RHP_PROTO_EAP_TYPE_NONE ){

			if( !auth_rlm->eap_for_peers ){
				err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
				RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_INVALID_ID_I_EAP_NOT_ALLOWED,"xxu",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id);
				goto error;
			}

			if( sess_res_tkt_e->auth_method_i != RHP_PROTO_IKE_AUTHMETHOD_NONE ){
				err = RHP_STATUS_IKEV2_SESS_RESUME_TKT_INVALID_PARAM;
				RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_INVALID_ID_I_EAP_BAD_AUTH_METHOD,"xxub",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id,sess_res_tkt_e->auth_method_i);
				goto error;
			}

			if( eap_id_i == NULL ){
				err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
				RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_INVALID_ID_I_NO_EAP_ID,"xxu",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id);
				goto error;
			}

			if( eap_i_method != RHP_PROTO_EAP_TYPE_PRIV_RADIUS ){

				auth_peer = auth_rlm->get_peer_by_id(auth_rlm,RHP_PEER_ID_TYPE_EAP,(void*)&eap_peer_id);
				if( auth_peer == NULL ){
					err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
					RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_INVALID_ID_I_NO_EAP_ID_2,"xxu",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id);
					goto error;
				}
			}

		}else if( sess_res_tkt_e->auth_method_i == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){

			// Role's check is done. OK.

			if( !auth_rlm->rsa_sig_for_peers ){
				err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
				RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_INVALID_ID_I_RSA_SIG_NOT_ALLOWED,"xxu",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id);
				goto error;
			}

			if( auth_rlm->my_auth->cert_store == NULL ){
				err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
				RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_NO_CERT_STORE_COFIG,"xxu",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id);
				goto error;
			}

		}else if( sess_res_tkt_e->auth_method_i == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ){

			if( !auth_rlm->psk_for_peers ){
				err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
				RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_INVALID_ID_I_PSK_NOT_ALLOWED,"xxu",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id);
				goto error;
			}

			auth_peer = auth_rlm->get_peer_by_id(auth_rlm,RHP_PEER_ID_TYPE_IKEV2,(void*)&peer_id);
			if( auth_peer == NULL ){
				err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
				RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_INVALID_ID_I_NO_PSK_ID,"xxu",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id);
				goto error;
			}

		}else if( sess_res_tkt_e->auth_method_i == RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH ){

			if( !auth_rlm->null_auth_for_peers ){
				err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
				RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_INVALID_ID_I_NULL_AUTH_NOT_ALLOWED,"xxu",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id);
				goto error;
			}

		}else{

			err = RHP_STATUS_IKEV2_SESS_RESUME_TKT_INVALID_PARAM;
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_INVALID_ID_I_AUTH_OR_EAP_METHOD,"xxu",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id);
			goto error;
		}
	}

	RHP_UNLOCK(&(auth_rlm->lock));
	rhp_auth_realm_unhold(auth_rlm);


	rhp_ikev2_id_clear(&my_id);
	rhp_ikev2_id_clear(&peer_id);
	rhp_eap_id_clear(&eap_peer_id);

	if( radius_role_strings ){
		_rhp_string_list_free(radius_role_strings);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_RTRN,"xxu",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id);
	return 0;

error:
	if( auth_rlm ){
		RHP_UNLOCK(&(auth_rlm->lock));
		rhp_auth_realm_unhold(auth_rlm);
	}
	rhp_ikev2_id_clear(&my_id);
	rhp_ikev2_id_clear(&peer_id);
	rhp_eap_id_clear(&eap_peer_id);

	if( radius_role_strings ){
		_rhp_string_list_free(radius_role_strings);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_CHECK_ERR,"xxuxE",sess_res_tkt,sess_res_tkt_e,tkt_vpn_realm_id,auth_rlm,err);
	return err;
}

static int _rhp_sess_resume_syspxy_dec_tkt_impl(rhp_ikev2_sess_resume_tkt* sess_res_tkt,
		rhp_crypto_encr* encr,rhp_crypto_integ* mac,rhp_bloom_filter* rvk_bfltr,u8* endp,
		rhp_ikev2_sess_resume_tkt** sess_res_tkt_r)
{
	int err = -EINVAL;
	rhp_ikev2_sess_resume_tkt* tkt_plain = NULL;
	rhp_ikev2_sess_resume_tkt_e *tkt_e_plain = NULL, *tkt_e_enc = NULL;
	u8 mac_val_org[RHP_IKEV2_SESS_RESUME_TKT_MAC_LEN];
	u8 mac_val_r[RHP_IKEV2_SESS_RESUME_TKT_MAC_LEN];
	u16 tkt_len = 0;
	int tkt_e_plain_len = 0, tkt_plain_len = sizeof(rhp_ikev2_sess_resume_tkt);
	time_t now = _rhp_get_realtime();
	u8 *mac_val_p;
	int64_t expired_time_enc;

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL,"xxxxxx",sess_res_tkt,encr,mac,rvk_bfltr,endp,sess_res_tkt_r);

	if( ((u8*)sess_res_tkt) + sizeof(rhp_ikev2_sess_resume_tkt) >= endp ){
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_INVALID_LEN_1,"xdx",sess_res_tkt,sizeof(rhp_ikev2_sess_resume_tkt),endp);
		err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
		goto error;
	}

	if( sess_res_tkt->magic[0] != 'R' || sess_res_tkt->magic[1] != 'K' ||
			sess_res_tkt->magic[2] != 'H' || sess_res_tkt->magic[3] != 'P'){
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_TKT_NOT_ROCKHOPPER_TKT,"xbbbb",sess_res_tkt,sess_res_tkt->magic[0],sess_res_tkt->magic[1],sess_res_tkt->magic[2],sess_res_tkt->magic[3]);
		err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
		goto error;
	}

	if( ntohs(sess_res_tkt->version) != RHP_IKEV2_SESS_RESUME_TKT_VERSION ){
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_TKT_INVALID_VERSION,"xW",sess_res_tkt,sess_res_tkt->version);
		err = RHP_STATUS_IKEV2_SESS_RESUME_TKT_INVALID_VER;
		goto error;
	}

	tkt_len = ntohs(sess_res_tkt->len);

	if( ((u8*)sess_res_tkt) + tkt_len > endp ){
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_INVALID_LEN_2,"xdx",sess_res_tkt,tkt_len,endp);
		err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
		goto error;
	}

	if( tkt_len < sizeof(rhp_ikev2_sess_resume_tkt)
				+ sizeof(rhp_ikev2_sess_resume_tkt_e) + RHP_IKEV2_SESS_RESUME_TKT_MAC_LEN ){
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_TKT_INVALID_LEN,"xw",sess_res_tkt,tkt_len);
		err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
		goto error;
	}

	{
		mac_val_p = ((u8*)sess_res_tkt) + (int)tkt_len - RHP_IKEV2_SESS_RESUME_TKT_MAC_LEN;
		memcpy(mac_val_org,mac_val_p,RHP_IKEV2_SESS_RESUME_TKT_MAC_LEN);
		memset(mac_val_p,0,RHP_IKEV2_SESS_RESUME_TKT_MAC_LEN);

		err = mac->compute(mac,(u8*)sess_res_tkt,tkt_len,mac_val_r,RHP_IKEV2_SESS_RESUME_TKT_MAC_LEN);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
		memcpy(mac_val_p,mac_val_org,RHP_IKEV2_SESS_RESUME_TKT_MAC_LEN);

		if( memcmp(mac_val_org,mac_val_r,RHP_IKEV2_SESS_RESUME_TKT_MAC_LEN) ){
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_MAC_NOT_MATCHED,"xpp",sess_res_tkt,RHP_IKEV2_SESS_RESUME_TKT_MAC_LEN,mac_val_org,RHP_IKEV2_SESS_RESUME_TKT_MAC_LEN,mac_val_r);
			err = RHP_STATUS_IKEV2_SESS_RESUME_TKT_MAC_ERR;
			goto error;
		}
	}


	{
		tkt_e_plain_len = (int)tkt_len - sizeof(rhp_ikev2_sess_resume_tkt) - RHP_IKEV2_SESS_RESUME_TKT_MAC_LEN;

		tkt_e_plain = (rhp_ikev2_sess_resume_tkt_e*)_rhp_malloc(tkt_e_plain_len);
		if( tkt_e_plain == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		tkt_e_enc = (rhp_ikev2_sess_resume_tkt_e*)(sess_res_tkt + 1);

		err = encr->decrypt(encr,(u8*)tkt_e_enc,tkt_e_plain_len,(u8*)tkt_e_plain,tkt_e_plain_len,sess_res_tkt->enc_iv);
		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_TKT_DEC_ERR,"xE",sess_res_tkt,err);
			err = RHP_STATUS_IKEV2_SESS_RESUME_TKT_DEC_ERR;
			goto error;
		}

		if( tkt_e_plain_len != (int)ntohs(tkt_e_plain->len) ){
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_INVALID_LEN_E,"xwW",sess_res_tkt,tkt_e_plain_len,tkt_e_plain->len);
			err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
			goto error;
		}

		if( tkt_e_plain_len - (int)sizeof(rhp_ikev2_sess_resume_tkt_e) <= (int)ntohs(tkt_e_plain->pad_len) ){
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_INVALID_LEN_E_2,"xwdW",sess_res_tkt,tkt_e_plain_len,sizeof(rhp_ikev2_sess_resume_tkt_e),tkt_e_plain->len);
			err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
			goto error;
		}

		tkt_e_plain_len -= (int)ntohs(tkt_e_plain->pad_len);
		tkt_plain_len += tkt_e_plain_len;

		if( tkt_plain_len >= tkt_len ){
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_INVALID_LEN_E_3,"xddW",sess_res_tkt,tkt_plain_len,tkt_len,tkt_e_plain->pad_len);
			err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
			goto error;
		}

		if( tkt_e_plain_len != (int)(sizeof(rhp_ikev2_sess_resume_tkt_e)
					+ ntohs(tkt_e_plain->id_i_len) + ntohs(tkt_e_plain->id_r_len)
					+ ntohs(tkt_e_plain->alt_id_i_len) + ntohs(tkt_e_plain->alt_id_r_len)
					+ ntohs(tkt_e_plain->sk_d_len) + ntohs(tkt_e_plain->eap_identity_len)
					+ ntohs(tkt_e_plain->radius_info_len) ) ){
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_INVALID_LEN_E_4,"xddWWWWW",sess_res_tkt,tkt_e_plain_len,sizeof(rhp_ikev2_sess_resume_tkt_e),tkt_e_plain->id_i_len,tkt_e_plain->id_r_len,tkt_e_plain->sk_d_len,tkt_e_plain->eap_identity_len,tkt_e_plain->radius_info_len);
			err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
			goto error;
		}

		if( tkt_e_plain->radius_info_len &&
				ntohs(tkt_e_plain->radius_info_len) < sizeof(rhp_radius_sess_ressume_tkt) ){
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_INVALID_LEN_E_RADIUS,"xdW",sess_res_tkt,sizeof(rhp_radius_sess_ressume_tkt),tkt_e_plain->radius_info_len);
			err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
			goto error;
		}

		if( !rhp_ikev2_is_null_auth_id(tkt_e_plain->id_i_type) ){

			if( !tkt_e_plain->id_i_len ){
				RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_INVALID_LEN_E_5,"xW",sess_res_tkt,tkt_e_plain->id_i_len);
				err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
				goto error;
			}

		}else{

			if( tkt_e_plain->id_i_len ){
				RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_INVALID_LEN_E_6,"xW",sess_res_tkt,tkt_e_plain->id_i_len);
				err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
				goto error;
			}
		}

		if( !rhp_ikev2_is_null_auth_id(tkt_e_plain->id_r_type) ){

			if( !tkt_e_plain->id_r_len ){
				RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_INVALID_LEN_E_7,"xW",sess_res_tkt,tkt_e_plain->id_r_len);
				err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
				goto error;
			}

		}else{

			if( tkt_e_plain->id_r_len ){
				RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_INVALID_LEN_E_8,"xW",sess_res_tkt,tkt_e_plain->id_r_len);
				err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
				goto error;
			}
		}

		if( !tkt_e_plain->sk_d_len ){
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_INVALID_LEN_E_9,"xWWW",sess_res_tkt,tkt_e_plain->sk_d_len);
			err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
			goto error;
		}


		if( tkt_e_plain->eap_identity_len &&
				ntohs(tkt_e_plain->eap_i_method) == RHP_PROTO_EAP_TYPE_NONE ){
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_INVALID_EAP_METHOD,"xWW",sess_res_tkt,tkt_e_plain->eap_identity_len,tkt_e_plain->eap_i_method);
			err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
			goto error;
		}

		if( ntohs(tkt_e_plain->eap_i_method) != RHP_PROTO_EAP_TYPE_NONE &&
				!rhp_eap_auth_impl_method_is_supported((int)ntohs(tkt_e_plain->eap_i_method)) ){
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_UNSUPPORTED_EAP_METHOD,"xWW",sess_res_tkt,tkt_e_plain->eap_identity_len,tkt_e_plain->eap_i_method);
			err = RHP_STATUS_INVALID_IKEV2_SESS_RESUME_TKT;
			goto error;
		}

		expired_time_enc = (int64_t)_rhp_ntohll(tkt_e_plain->expire_time);
		if( expired_time_enc <= now ){
			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_EXPIRED_TKT_ERR,"xqq",sess_res_tkt,expired_time_enc,now);
			err = RHP_STATUS_IKEV2_SESS_RESUME_TKT_EXPIRED;
			goto error;
		}

		tkt_e_plain->len = htons((u16)tkt_e_plain_len);
		tkt_e_plain->pad_len = 0;
	}


	tkt_plain = (rhp_ikev2_sess_resume_tkt*)_rhp_malloc(tkt_plain_len);
	if( tkt_plain == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memcpy(tkt_plain,sess_res_tkt,sizeof(rhp_ikev2_sess_resume_tkt));
	memcpy((u8*)(tkt_plain + 1),tkt_e_plain,tkt_e_plain_len);

	tkt_plain->len = htons((u16)tkt_plain_len);

	// This may acquire auth_rlm->lock.
	err = _rhp_sess_resume_syspxy_dec_tkt_check(tkt_plain,tkt_e_plain);
	if( err ){
		goto error;
	}


	if( rhp_gcfg_ikev2_sess_resume_resp_tkt_revocation ){

		u8 rvk_key[sizeof(int64_t) + RHP_VPN_UNIQUE_ID_SIZE];
		int rvk_key_len = sizeof(int64_t) + RHP_VPN_UNIQUE_ID_SIZE;
		u32 rvk_bfltr_num = rvk_bfltr->get_num(rvk_bfltr);

		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_TKT_RVK_CK,"xxud",sess_res_tkt,rvk_bfltr,rvk_bfltr_num,rhp_gcfg_ikev2_sess_resume_tkt_rvk_bfltr_max_tkts);

		if( rvk_bfltr_num > (u32)rhp_gcfg_ikev2_sess_resume_tkt_rvk_bfltr_max_tkts ){

			if( (_rhp_sess_res_key_cur.revocation_bfltr == rvk_bfltr) &&
					rhp_timer_pending(&_rhp_sess_resume_key_timer) ){

				rhp_timer_update(&_rhp_sess_resume_key_timer,0);
			}

			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_TKT_RVK_CK_MAX_TKSTS,"xx",sess_res_tkt,rvk_bfltr);

			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKEV2_SESS_RESUME_REACHED_MAX_REVOKED_TKTS,"u",rvk_bfltr_num);

			err = RHP_STATUS_IKEV2_SESS_RESUME_TKT_REVOKED_MAX_TKTS;
			goto error;
		}

		memcpy(rvk_key,&(tkt_e_plain->created_time),sizeof(int64_t));
		memcpy((rvk_key + sizeof(int64_t)),tkt_e_plain->unique_id,RHP_VPN_UNIQUE_ID_SIZE);

		if( rvk_bfltr->add(rvk_bfltr,rvk_key_len,rvk_key) ){

			unsigned long rlm_id = _rhp_ntohll(tkt_e_plain->vpn_realm_id);

			RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_TKT_RVK_CK_DUP_USED,"xxp",sess_res_tkt,rvk_bfltr,rvk_key_len,rvk_key);

			rvk_bfltr->dump(rvk_bfltr);

			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,rlm_id,RHP_LOG_ID_IKEV2_SESS_RESUME_RX_REVOKED_TKT_ERR,"N",tkt_e_plain->unique_id);

			err = RHP_STATUS_IKEV2_SESS_RESUME_TKT_REVOKED;
			goto error;
		}

		rvk_bfltr->dump(rvk_bfltr);
	}


	*sess_res_tkt_r = tkt_plain;

	_rhp_free(tkt_e_plain);


	rhp_ikev2_sess_resume_tkt_dump("_rhp_sess_resume_syspxy_dec_tkt_impl plain",tkt_plain,1);
	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_TKT_RTRN,"xx",sess_res_tkt,*sess_res_tkt_r);
	return 0;

error:
	if( tkt_plain ){
		rhp_ikev2_sess_resume_tkt_dump("_rhp_sess_resume_syspxy_dec_tkt_impl plain_err",tkt_plain,1);
	  rhp_ikev2_sess_resume_tkt_log_dump(0,tkt_plain,1);
		_rhp_free(tkt_plain);
	}
	if( tkt_e_plain ){
		_rhp_free(tkt_e_plain);
	}
	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_IMPL_TKT_ERR,"xE",sess_res_tkt,err);
	return err;
}

static int _rhp_sess_resume_syspxy_dec_tkt(rhp_ikev2_sess_resume_tkt* sess_res_tkt,u8* endp,
		rhp_ikev2_sess_resume_tkt** sess_res_tkt_r)
{
	int err = -EINVAL;
	rhp_ikev2_sess_resume_key_data* dec_key = NULL;
	u64 key_idx = _rhp_ntohll(sess_res_tkt->key_index);
	time_t now = _rhp_get_realtime();
	rhp_crypto_encr* encr;
	rhp_crypto_integ* mac;
	rhp_bloom_filter* rvk_bfltr;

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT,"xxx",sess_res_tkt,endp,sess_res_tkt_r);
	rhp_ikev2_sess_resume_tkt_dump("_rhp_sess_resume_syspxy_dec_tkt dec",sess_res_tkt,0);

	// TODO: Store key info into TLS buffers.
  RHP_LOCK(&_rhp_sess_resume_lock);

  if( _rhp_sess_res_key_cur.key.key_index == 0 ){
		err = -EINVAL;
		RHP_BUG("%d",err);
		goto error;
  }

	if( key_idx == 0 ){
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_INVALID_KEY_INDEX,"xqqq",sess_res_tkt,key_idx,_rhp_sess_res_key_cur.key.key_index,_rhp_sess_res_key_old.key.key_index);
		err = -EINVAL;
		goto error;
	}

	if( key_idx == _rhp_sess_res_key_cur.key.key_index ){

		dec_key = &_rhp_sess_res_key_cur.key;
		encr = _rhp_sess_res_key_cur.encr;
		mac = _rhp_sess_res_key_cur.mac;
		rvk_bfltr = _rhp_sess_res_key_cur.revocation_bfltr;

	}else if( key_idx == _rhp_sess_res_key_old.key.key_index ){

		dec_key = &_rhp_sess_res_key_old.key;
		encr = _rhp_sess_res_key_old.encr;
		mac = _rhp_sess_res_key_old.mac;
		rvk_bfltr = _rhp_sess_res_key_old.revocation_bfltr;

	}else{
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_KEY_INDEX_NOT_MATCHED,"x",sess_res_tkt);
		err = -ENOENT;
		goto error;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_KEY_INFO,"xxqff",sess_res_tkt,dec_key,dec_key->key_index,dec_key->expire_time,now);

	if( dec_key->key_index &&
			dec_key->expire_time > now ){

		err = _rhp_sess_resume_syspxy_dec_tkt_impl(sess_res_tkt,encr,mac,rvk_bfltr,endp,sess_res_tkt_r);
		if( err ){
			goto error;
		}

	}else{

		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_VALID_KEY_NOT_FOUND,"x",sess_res_tkt);

		err = -ENOENT;
		goto error;
	}

	RHP_UNLOCK(&_rhp_sess_resume_lock);

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_RTRN,"xx",sess_res_tkt,*sess_res_tkt_r);
	return 0;

error:
	RHP_UNLOCK(&_rhp_sess_resume_lock);
	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_TKT_ERR,"xE",sess_res_tkt,err);
	return err;
}


static void _rhp_sess_resume_syspxy_enc_req_ipc_handler(int worker_idx,void* wts_ctx)
{
	int err = -EINVAL;
	rhp_ipcmsg_sess_resume_enc_req* ipc_req = (rhp_ipcmsg_sess_resume_enc_req*)wts_ctx;
	rhp_ikev2_sess_resume_tkt *sess_res_tkt, *sess_res_tkt_r = NULL;
	int sess_res_tkt_len;
	rhp_ikev2_sess_resume_tkt_e* sess_res_tkt_e;
	int sess_res_tkt_e_len;
	rhp_radius_sess_ressume_tkt* sess_res_radius_tkt = NULL;
	int sess_res_radius_tkt_len = 0;
	rhp_ipcmsg_sess_resume_enc_rep* ipc_rep = NULL;
	int ipc_rep_len = sizeof(rhp_ipcmsg_sess_resume_enc_rep);
	int64_t expire_time_r = 0;
	rhp_ikev2_sess_resume_tkt* sess_res_tkt_p = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_ENC_REQ_IPC_HANDLER,"dx",worker_idx,ipc_req);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return;
  }

	if( ipc_req->len < (sizeof(rhp_ipcmsg_sess_resume_enc_req)
										 + sizeof(rhp_ikev2_sess_resume_tkt) + sizeof(rhp_ikev2_sess_resume_tkt_e)) ){
		RHP_BUG("%d, %d, %d, %d",ipc_req->len,sizeof(rhp_ipcmsg_sess_resume_enc_req),sizeof(rhp_ikev2_sess_resume_tkt),sizeof(rhp_ikev2_sess_resume_tkt_e));
		return;
	}

	if( ipc_req->type != RHP_IPC_SESS_RESUME_ENC_REQUEST ){
		RHP_BUG("%d",ipc_req->type);
		return;
	}


	sess_res_tkt = (rhp_ikev2_sess_resume_tkt*)(ipc_req + 1);
	sess_res_tkt_len = ntohs(sess_res_tkt->len);

	if( sess_res_tkt_len != (int)ipc_req->tkt_len ){
		RHP_BUG("%d, %d",sess_res_tkt_len,ipc_req->tkt_len);
		return;
	}

	if( (((u8*)sess_res_tkt) + sess_res_tkt_len) > (((u8*)ipc_req) + ipc_req->len) ){
		RHP_BUG("0x%x, %d, 0x%x %d",(u8*)sess_res_tkt,sess_res_tkt_len,(u8*)ipc_req,ipc_req->len);
		return;
	}

	if( sess_res_tkt_len <=
				(int)(sizeof(rhp_ikev2_sess_resume_tkt) + sizeof(rhp_ikev2_sess_resume_tkt_e)) ){
		RHP_BUG("%d, %d, %d",(u8*)sess_res_tkt,sizeof(rhp_ikev2_sess_resume_tkt),sizeof(rhp_ikev2_sess_resume_tkt_e));
		goto error;
	}


	sess_res_radius_tkt_len = ipc_req->radius_tkt_len;
	if( sess_res_radius_tkt_len ){

		if( sess_res_radius_tkt_len < (int)sizeof(rhp_radius_sess_ressume_tkt) ){
			RHP_BUG("%d, %d",sess_res_radius_tkt_len,sizeof(rhp_radius_sess_ressume_tkt));
			goto error;
		}

		if( ipc_req->len < sizeof(rhp_ipcmsg_sess_resume_enc_req) + sess_res_tkt_len + sess_res_radius_tkt_len ){
			RHP_BUG("%d, %d, %d, %d",ipc_req->len,sizeof(rhp_ipcmsg_sess_resume_enc_req),sess_res_tkt_len,sess_res_radius_tkt_len);
			goto error;
		}

		sess_res_radius_tkt = (rhp_radius_sess_ressume_tkt*)(((u8*)sess_res_tkt) + sess_res_tkt_len);

		if( sess_res_radius_tkt_len != (int)ntohs(sess_res_radius_tkt->radius_tkt_len) ){
			RHP_BUG("%d, %d",sess_res_radius_tkt_len,ntohs(sess_res_radius_tkt->radius_tkt_len));
			goto error;
		}

		if( (((u8*)sess_res_radius_tkt) + sess_res_radius_tkt_len) > (((u8*)ipc_req) + ipc_req->len) ){
			RHP_BUG("0x%x, %d, 0x%x, %d",(u8*)sess_res_radius_tkt,sess_res_radius_tkt_len,(u8*)ipc_req,ipc_req->len);
			goto error;
		}
	}


	sess_res_tkt_e = (rhp_ikev2_sess_resume_tkt_e*)(sess_res_tkt + 1);
	sess_res_tkt_e_len = ntohs(sess_res_tkt_e->len);

	if( sess_res_tkt_e_len <= (int)sizeof(rhp_ikev2_sess_resume_tkt_e) ){
		RHP_BUG("%d, %d",sess_res_tkt_e_len,sizeof(rhp_ikev2_sess_resume_tkt_e));
		goto error;
	}

	if( sess_res_tkt_len <= sess_res_tkt_e_len ){
		RHP_BUG("%d, %d",sess_res_tkt_len,sess_res_tkt_e_len);
		goto error;
	}

	if( (((u8*)sess_res_tkt_e) + sess_res_tkt_e_len) > (((u8*)ipc_req) + ipc_req->len) ){
		RHP_BUG("0x%x, %d, 0x%x, %d",(u8*)sess_res_tkt_e,sess_res_tkt_e_len,(u8*)ipc_req,ipc_req->len);
		goto error;
	}


	if( !rhp_ikev2_is_null_auth_id(sess_res_tkt_e->id_i_type) ){

		if( !sess_res_tkt_e->id_i_len ){
			RHP_BUG("%d",sess_res_tkt_e->id_i_len);
			goto error;
		}

	}else{

		if( sess_res_tkt_e->id_i_len ){
			RHP_BUG("%d",sess_res_tkt_e->id_i_len);
			goto error;
		}
	}


	if( !rhp_ikev2_is_null_auth_id(sess_res_tkt_e->id_r_type) ){

		if( !sess_res_tkt_e->id_r_len ){
			RHP_BUG("%d",sess_res_tkt_e->id_r_len);
			goto error;
		}

	}else{

		if( sess_res_tkt_e->id_r_len ){
			RHP_BUG("%d",sess_res_tkt_e->id_r_len);
			goto error;
		}
	}


	if( !sess_res_tkt_e->sk_d_len ){
		RHP_BUG("%d",sess_res_tkt_e->sk_d_len);
		goto error;
	}


	if( (((u8*)sess_res_tkt_e) + sizeof(rhp_ikev2_sess_resume_tkt_e)
			+ ntohs(sess_res_tkt_e->id_i_len) + ntohs(sess_res_tkt_e->id_r_len)
			+ ntohs(sess_res_tkt_e->alt_id_i_len) + ntohs(sess_res_tkt_e->alt_id_r_len)
			+ ntohs(sess_res_tkt_e->sk_d_len) + ntohs(sess_res_tkt_e->eap_identity_len))
			> ((u8*)ipc_req) + ipc_req->len ){
		RHP_BUG("0x%x, %d, %d, %d, %d, %d, %d, %d, 0x%x, %d",(u8*)sess_res_tkt_e,sizeof(rhp_ikev2_sess_resume_tkt_e),ntohs(sess_res_tkt_e->id_i_len),ntohs(sess_res_tkt_e->id_r_len),ntohs(sess_res_tkt_e->alt_id_i_len),ntohs(sess_res_tkt_e->alt_id_r_len),ntohs(sess_res_tkt_e->sk_d_len),ntohs(sess_res_tkt_e->eap_identity_len),(u8*)ipc_req,ipc_req->len);
		goto error;
	}


  if( sess_res_radius_tkt ){

  	rhp_ikev2_sess_resume_tkt_e* sess_res_tkt_e2;

  	sess_res_tkt_p = (rhp_ikev2_sess_resume_tkt*)_rhp_malloc(sess_res_tkt_len + sess_res_radius_tkt_len);
  	if(sess_res_tkt_p == NULL){
  		RHP_BUG("");
  		err = -ENOMEM;
  		goto error;
  	}

  	memcpy(sess_res_tkt_p,sess_res_tkt,sess_res_tkt_len);
  	sess_res_tkt_p->len = htons(sess_res_tkt_len + sess_res_radius_tkt_len);

  	sess_res_tkt_e2 = (rhp_ikev2_sess_resume_tkt_e*)(sess_res_tkt_p + 1);
  	sess_res_tkt_e2->len = htons((u16)(sess_res_tkt_e_len + sess_res_radius_tkt_len));
  	sess_res_tkt_e2->radius_info_len = htons((u16)sess_res_radius_tkt_len);

  	memcpy(((u8*)sess_res_tkt_e2) + sess_res_tkt_e_len,sess_res_radius_tkt,sess_res_radius_tkt_len);
  }


	{
		rhp_vpn_auth_realm* auth_rlm = rhp_auth_realm_get(ipc_req->my_realm_id);
		if( auth_rlm == NULL ){
			RHP_BUG("%u",ipc_req->my_realm_id);
			err = -ENOENT;
			goto error;
		}

		RHP_LOCK(&(auth_rlm->lock));

		if( auth_rlm->my_auth == NULL ){
			RHP_UNLOCK(&(auth_rlm->lock));
			err = -ENOENT;
			goto error;
		}

		err = _rhp_sess_resume_syspxy_enc_tkt(auth_rlm,
						(sess_res_tkt_p ? sess_res_tkt_p : sess_res_tkt),
						&sess_res_tkt_r,&expire_time_r);
		if( err ){
			RHP_BUG("%d",err);
		}

		RHP_UNLOCK(&(auth_rlm->lock));
	}


	if( sess_res_tkt_r ){

		ipc_rep_len += (int)ntohs(sess_res_tkt_r->len);
	}


error:
	ipc_rep = (rhp_ipcmsg_sess_resume_enc_rep*)_rhp_malloc(ipc_rep_len);
	if( ipc_rep == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	{
		memset(ipc_rep,0,ipc_rep_len);

		ipc_rep->tag[0] = '#';
		ipc_rep->tag[1] = 'I';
		ipc_rep->tag[2] = 'M';
		ipc_rep->tag[3] = 'S';

		ipc_rep->type = RHP_IPC_SESS_RESUME_ENC_REPLY;
		ipc_rep->len = ipc_rep_len;

		ipc_rep->txn_id = ipc_req->txn_id;
		ipc_rep->my_realm_id = ipc_req->my_realm_id;
		ipc_rep->side = ipc_req->side;
		memcpy(ipc_rep->spi,ipc_req->spi,RHP_PROTO_IKE_SPI_SIZE);
		memcpy(ipc_rep->peer_spi,ipc_req->peer_spi,RHP_PROTO_IKE_SPI_SIZE);

		if( ipc_req->old_ikesa ){

			ipc_rep->old_ikesa = 1;
			ipc_rep->old_side = ipc_req->old_side;
			memcpy(ipc_rep->old_spi,ipc_req->old_spi,RHP_PROTO_IKE_SPI_SIZE);
			memcpy(ipc_rep->old_peer_spi,ipc_req->old_peer_spi,RHP_PROTO_IKE_SPI_SIZE);
		}

		if( sess_res_tkt_r ){

			ipc_rep->result = 1;
			ipc_rep->expired_time = expire_time_r;

			memcpy((u8*)(ipc_rep + 1),sess_res_tkt_r,ntohs(sess_res_tkt_r->len));

	    {
				ipc_rep->qcd_enabled = 0;
				if( ipc_req->qcd_enabled ){

					if( rhp_ikev2_qcd_get_my_token(ipc_req->side,ipc_req->spi,
							ipc_req->peer_spi,ipc_rep->my_qcd_token) ){

						RHP_BUG("");

					}else{

						ipc_rep->qcd_enabled = 1;
					}
				}
	    }

		}else{

			ipc_rep->result = 0;
		}
	}

	if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipc_rep,ipc_rep->len,0) < 0 ){
		RHP_BUG("");
  }


	if( sess_res_tkt_r ){
		_rhp_free(sess_res_tkt_r);
	}
	if( ipc_rep ){
		_rhp_free(ipc_rep);
	}
	if( sess_res_tkt_p ){
		_rhp_free(sess_res_tkt_p);
	}

	_rhp_free_zero(ipc_req,ipc_req->len);

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_ENC_REQ_IPC_HANDLER_RTRN,"dxE",worker_idx,ipc_req,err);
	return;
}

static void _rhp_sess_resume_syspxy_dec_req_ipc_handler(int worker_idx,void* wts_ctx)
{
	int err = -EINVAL;
	rhp_ipcmsg_sess_resume_dec_req* ipc_req = (rhp_ipcmsg_sess_resume_dec_req*)wts_ctx;
	rhp_ikev2_sess_resume_tkt *sess_res_tkt, *sess_res_tkt_r = NULL;
	int sess_res_tkt_len;
	rhp_ipcmsg_sess_resume_dec_rep* ipc_rep = NULL;
	int ipc_rep_len = sizeof(rhp_ipcmsg_sess_resume_dec_rep);
	u8* endp = ((u8*)ipc_req) + ipc_req->len;

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_REQ_IPC_HANDLER,"dx",worker_idx,ipc_req);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return;
  }

	if( ipc_req->len <= (int)(sizeof(rhp_ipcmsg_sess_resume_dec_req)
										 + sizeof(rhp_ikev2_sess_resume_tkt) + sizeof(rhp_ikev2_sess_resume_tkt_e)
										 + RHP_IKEV2_SESS_RESUME_TKT_MAC_LEN)){
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_REQ_IPC_HANDLER_INVALID_TKT,"dddddd",worker_idx,ipc_req->len,sizeof(rhp_ipcmsg_sess_resume_dec_req),sizeof(rhp_ikev2_sess_resume_tkt),sizeof(rhp_ikev2_sess_resume_tkt_e),RHP_IKEV2_SESS_RESUME_TKT_MAC_LEN);
		goto error;
	}

	if( ipc_req->type != RHP_IPC_SESS_RESUME_DEC_REQUEST ){
		RHP_BUG("%d",ipc_req->type);
		return;
	}

	sess_res_tkt = (rhp_ikev2_sess_resume_tkt*)(ipc_req + 1);
	sess_res_tkt_len = ntohs(sess_res_tkt->len);

	if( (((u8*)sess_res_tkt) + sess_res_tkt_len) != (((u8*)ipc_req) + ipc_req->len) ){
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_REQ_IPC_HANDLER_INVALID_TKT_1,"dxxd",worker_idx,ipc_req,sess_res_tkt,sess_res_tkt_len);
		goto error;
	}


	err = _rhp_sess_resume_syspxy_dec_tkt(sess_res_tkt,endp,&sess_res_tkt_r);
	if( err ){
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_REQ_IPC_HANDLER_DEC_ERR,"dxx",worker_idx,ipc_req,sess_res_tkt);
		goto error;
	}


	if( sess_res_tkt_r ){

		ipc_rep_len += ntohs(sess_res_tkt_r->len);
		err = 0;
	}


error:
	ipc_rep = (rhp_ipcmsg_sess_resume_enc_rep*)_rhp_malloc(ipc_rep_len);
	if( ipc_rep == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	{
		memset(ipc_rep,0,ipc_rep_len);

		ipc_rep->tag[0] = '#';
		ipc_rep->tag[1] = 'I';
		ipc_rep->tag[2] = 'M';
		ipc_rep->tag[3] = 'S';

		ipc_rep->type = RHP_IPC_SESS_RESUME_DEC_REPLY;
		ipc_rep->len = ipc_rep_len;

		ipc_rep->txn_id = ipc_req->txn_id;
		ipc_rep->my_realm_id = ipc_req->my_realm_id;
		ipc_rep->side = ipc_req->side;
		memcpy(ipc_rep->spi,ipc_req->spi,RHP_PROTO_IKE_SPI_SIZE);
		memcpy(ipc_rep->peer_spi,ipc_req->peer_spi,RHP_PROTO_IKE_SPI_SIZE);

		if( sess_res_tkt_r ){

			ipc_rep->result = 1;

			memcpy((u8*)(ipc_rep + 1),sess_res_tkt_r,ntohs(sess_res_tkt_r->len));

	    {
				ipc_rep->qcd_enabled = 0;
				if( ipc_req->qcd_enabled ){

					if( rhp_ikev2_qcd_get_my_token(ipc_req->side,ipc_req->spi,
							ipc_req->peer_spi,ipc_rep->my_qcd_token) ){

						RHP_BUG("");

					}else{

						ipc_rep->qcd_enabled = 1;
					}
				}
	    }


		}else{

			ipc_rep->result = 0;
		}
	}

	if( rhp_ipc_send(RHP_MY_PROCESS,(void*)ipc_rep,ipc_rep->len,0) < 0 ){
		RHP_BUG("");
  }

	if( err || !ipc_rep->result ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,ipc_req->my_realm_id,RHP_LOG_ID_IKE_SESS_RESUME_DEC_TKT_ERR,"LGGE","IKE_SIDE",ipc_req->side,ipc_req->spi,ipc_req->peer_spi,err);
	}

	if( sess_res_tkt_r ){
		_rhp_free(sess_res_tkt_r);
	}
	if( ipc_rep ){
		_rhp_free(ipc_rep);
	}

	_rhp_free_zero(ipc_req,ipc_req->len);

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_SYSPXY_DEC_REQ_IPC_HANDLER_RTRN,"dxxE",worker_idx,ipc_req,ipc_rep,err);
	return;
}

static rhp_prc_ipcmsg_wts_handler _rhp_sess_resume_enc_req_syspxy_ipc = {
	wts_type: RHP_WTS_DISP_RULE_RAND,
	wts_disp_priority: RHP_WTS_DISP_LEVEL_HIGH_2,
	wts_disp_wait: 1,
	wts_is_fixed_rule: 0,
	wts_task_handler: _rhp_sess_resume_syspxy_enc_req_ipc_handler
};

static rhp_prc_ipcmsg_wts_handler _rhp_sess_resume_dec_req_syspxy_ipc = {
	wts_type: RHP_WTS_DISP_RULE_SESS_RESUME_DEC_TKT,
	wts_disp_priority: RHP_WTS_DISP_LEVEL_HIGH_3,
	wts_disp_wait: 1,
	wts_is_fixed_rule: 0,
	wts_task_handler: _rhp_sess_resume_syspxy_dec_req_ipc_handler
};

static void _rhp_sess_resume_syspxy_key_timer(void *ctx,rhp_timer *timer)
{
	int err = 0;

  RHP_TRC_FREQ(0,RHPTRCID_SESS_RESUME_SYSPXY_KEY_TIMER,"xx",ctx,timer);

  RHP_LOCK(&_rhp_sess_resume_lock);

  err = _rhp_ikev2_sess_resume_update_key();
  if( err ){
  	RHP_BUG("%d",err);
  }

  rhp_timer_reset(&(_rhp_sess_resume_key_timer));
  rhp_timer_add(&(_rhp_sess_resume_key_timer),
  		(time_t)(rhp_gcfg_ikev2_sess_resume_key_update_interval - RHP_IKEV2_SESS_RESUME_KEY_MARGIN));

  RHP_UNLOCK(&_rhp_sess_resume_lock);

  RHP_TRC_FREQ(0,RHPTRCID_SESS_RESUME_SYSPXY_KEY_TIMER_RTRN,"xx",ctx,timer);
	return;
}


static int _rhp_ikev2_sess_resume_init_key_obj(rhp_ikev2_sess_resume_key* key_obj)
{
	int err = -EINVAL;

	memset(key_obj,0,sizeof(rhp_ikev2_sess_resume_key));

	key_obj->encr
		= rhp_crypto_encr_alloc(RHP_IKEV2_SESS_RESUME_TKT_ENCR,RHP_IKEV2_SESS_RESUME_TKT_ENCR_KEY_LEN);
	if( key_obj->encr == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	key_obj->mac = rhp_crypto_integ_alloc(RHP_IKEV2_SESS_RESUME_TKT_MAC);
	if( key_obj->mac == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

  RHP_TRC(0,RHPTRCID_SESS_RESUME_INIT_KEY_OBJ,"x",key_obj);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_SESS_RESUME_INIT_KEY_OBJ_ERR,"xE",key_obj,err);
	return err;
}

static int _rhp_ikev2_sess_resume_init_read_key_file(rhp_ikev2_sess_resume_key* key_obj,
		char* path)
{
	int err = -EINVAL;

	err = rhp_file_read_data(path,
					sizeof(rhp_ikev2_sess_resume_key_data),(u8*)&(key_obj->key));
	if( err ){
		goto error;
	}

  RHP_TRC(0,RHPTRCID_SESS_RESUME_INIT_READ_KEY_FILE,"xs",key_obj,path);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_SESS_RESUME_INIT_READ_KEY_FILE_ERR,"xsE",key_obj,path,err);
	return err;
}

static int _rhp_ikev2_sess_resume_init_clear_key_files(rhp_ikev2_sess_resume_key* key_obj)
{
	if( key_obj == &_rhp_sess_res_key_cur ){

		if( unlink(rhp_syspxy_sess_resume_key_path) < 0 ){
			RHP_TRC(0,RHPTRCID_IKEV2_SES_RESUME_SYSPXY_INIT_UNLINK_KEY_FILE_ERR,"sE",rhp_syspxy_sess_resume_key_path,-errno);
		}

		if( unlink(rhp_syspxy_sess_resume_revocation_bfltr_path) < 0 ){
			RHP_TRC(0,RHPTRCID_IKEV2_SES_RESUME_SYSPXY_INIT_UNLINK_RVK_BFLTR_FILE_ERR,"sE",rhp_syspxy_sess_resume_revocation_bfltr_path,-errno);
		}

	  RHP_TRC(0,RHPTRCID_SESS_RESUME_INIT_CLEAR_KEY_FILES,"x",key_obj);

	}else if( key_obj == &_rhp_sess_res_key_old ){

		if( unlink(rhp_syspxy_sess_resume_old_key_path) < 0 ){
			RHP_TRC(0,RHPTRCID_IKEV2_SES_RESUME_SYSPXY_INIT_UNLINK_OLD_KEY_FILE_ERR,"sE",rhp_syspxy_sess_resume_old_key_path,-errno);
		}

		if( unlink(rhp_syspxy_sess_resume_revocation_old_bfltr_path) < 0 ){
			RHP_TRC(0,RHPTRCID_IKEV2_SES_RESUME_SYSPXY_INIT_UNLINK_OLD_RVK_BFLTR_FILE_ERR,"sE",rhp_syspxy_sess_resume_revocation_old_bfltr_path,-errno);
		}

	  RHP_TRC(0,RHPTRCID_SESS_RESUME_INIT_CLEAR_KEY_FILES_OLD,"x",key_obj);
	}

	return 0;
}

static int _rhp_ikev2_sess_resume_is_valid_key_data(rhp_ikev2_sess_resume_key* key_obj)
{
	if( !key_obj->key.key_index ){

	  RHP_TRC(0,RHPTRCID_SESS_RESUME_IS_VALID_KEY_DATA_INVALID_1,"x",key_obj);
		return 0;

	}else{

		time_t now = _rhp_get_realtime();

		if(key_obj->key.version != RHP_IKEV2_SESS_RESUME_KEY_DATA_VER ||
			 key_obj->key.expire_time <= now ){

		  RHP_TRC(0,RHPTRCID_SESS_RESUME_IS_VALID_KEY_DATA_INVALID_2,"x",key_obj);
			return 0;
		}
	}

  RHP_TRC(0,RHPTRCID_SESS_RESUME_IS_VALID_KEY_DATA,"x",key_obj);
	return 1;
}

static int _rhp_ikev2_sess_resume_init_setup_cur_key()
{
	int err = -EINVAL;
	u64 new_key_idx = 0;
	int j;

	for(j = 0; j < 100; j++){

		if( rhp_random_bytes((u8*)&new_key_idx,sizeof(u64)) ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		if( new_key_idx ){
			break;
		}
	}

	if( !new_key_idx ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}


	err = _rhp_ikev2_sess_resume_gen_key(new_key_idx,&_rhp_sess_res_key_cur.key);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	err = rhp_file_write(rhp_syspxy_sess_resume_key_path,
			(u8*)&_rhp_sess_res_key_cur.key,sizeof(rhp_ikev2_sess_resume_key_data),(S_IRUSR | S_IWUSR | S_IXUSR));
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	return 0;

error:
	return err;
}

static int _rhp_ikev2_sess_resume_init_set_enc_params(rhp_ikev2_sess_resume_key* key_obj)
{
	int err = -EINVAL;

	err = key_obj->encr->set_enc_key(key_obj->encr,
			key_obj->key.enc_key,RHP_IKEV2_SESS_RESUME_TKT_ENC_KEY_LEN);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	err = key_obj->encr->set_dec_key(key_obj->encr,
			key_obj->key.enc_key,RHP_IKEV2_SESS_RESUME_TKT_ENC_KEY_LEN);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	err = key_obj->mac->set_key(key_obj->mac,
			key_obj->key.mac_key,RHP_IKEV2_SESS_RESUME_TKT_MAC_KEY_LEN);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	return 0;

error:
	return err;
}

static int _rhp_ikev2_sess_resume_init_tkt_rvk(rhp_ikev2_sess_resume_key* key_obj,char* path)
{
	int err = -EINVAL;
	int reset_rvk_bfltr = 0;
	u8 tag[RHP_BFLTR_FDATA_TAG_LEN];
	u8 *tag_f = NULL;

	if( !rhp_gcfg_ikev2_sess_resume_resp_tkt_revocation ){
		return 0;
	}

reset_rvk_bfltr:

	err = _rhp_ikev2_sess_resume_tkt_rvk_open_bfltr(key_obj,path);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}


	_rhp_ikev2_sess_resume_tkt_rvk_get_tag(key_obj,tag);

	tag_f = key_obj->revocation_bfltr->get_tag(key_obj->revocation_bfltr);


	RHP_TRC(0,RHPTRCID_IKEV2_SES_RESUME_SYSPXY_INIT_RVK_BFLTR_CMP_PARAMS,"qppjd",key_obj->key.key_index,RHP_BFLTR_FDATA_TAG_LEN,tag,RHP_BFLTR_FDATA_TAG_LEN,tag_f,key_obj->revocation_bfltr->max_num_of_elements,rhp_gcfg_ikev2_sess_resume_tkt_rvk_bfltr_max_tkts);

	if( (key_obj->key.key_index && memcmp(tag,tag_f,RHP_BFLTR_FDATA_TAG_LEN)) ||
			 key_obj->revocation_bfltr->max_num_of_elements
			 	 != (u32)rhp_gcfg_ikev2_sess_resume_tkt_rvk_bfltr_max_tkts ||
			 key_obj->revocation_bfltr->false_ratio
			 	 != rhp_gcfg_ikev2_sess_resume_tkt_rvk_bfltr_false_ratio ){

		RHP_TRC(0,RHPTRCID_IKEV2_SES_RESUME_SYSPXY_INIT_RVK_BFLTR_CFG_CHANGED_EXEC_RESET,"s",path);

		if( reset_rvk_bfltr ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		rhp_bloom_filter_free(key_obj->revocation_bfltr);
		key_obj->revocation_bfltr = NULL;

		if( unlink(path) < 0 ){
			RHP_TRC(0,RHPTRCID_IKEV2_SES_RESUME_SYSPXY_INIT_UNLINK_RVK_BFLTR_FILE_2_ERR,"sE",path,-errno);
		}

		reset_rvk_bfltr = 1;

		goto reset_rvk_bfltr;
	}

	return 0;

error:
	return err;
}

static int _rhp_ikev2_sess_resume_init_start_key_timer()
{
	time_t now = _rhp_get_realtime();
	time_t key_update_interval = (time_t)rhp_gcfg_ikev2_sess_resume_key_update_interval;
	time_t tmp_interval;


	if( rhp_gcfg_ikev2_sess_resume_key_update_interval < rhp_gcfg_ikev2_sess_resume_key_update_interval_min ||
			rhp_gcfg_ikev2_sess_resume_key_update_interval < RHP_IKEV2_SESS_RESUME_KEY_MARGIN ){

		rhp_gcfg_ikev2_sess_resume_key_update_interval = rhp_gcfg_ikev2_sess_resume_key_update_interval_min;
	}


  rhp_timer_init(&(_rhp_sess_resume_key_timer),_rhp_sess_resume_syspxy_key_timer,NULL);

  {
		if( _rhp_sess_res_key_cur.key.expire_time <= now ){
			key_update_interval = RHP_IKEV2_SESS_RESUME_KEY_MARGIN;
		}else if( key_update_interval > (tmp_interval = (_rhp_sess_res_key_cur.key.expire_time - now)) ){
			key_update_interval = tmp_interval;
		}

		if( key_update_interval < RHP_IKEV2_SESS_RESUME_KEY_MARGIN ){
			key_update_interval = RHP_IKEV2_SESS_RESUME_KEY_MARGIN;
		}
  }

  rhp_timer_add(&(_rhp_sess_resume_key_timer),key_update_interval);

  RHP_TRC(0,RHPTRCID_SESS_RESUME_INIT_START_KEY_TIMER,"");
  return 0;
}

static u32 _rhp_sess_resume_dec_req_disp_hash(void *key_seed,int* err)
{
	rhp_ipcmsg_sess_resume_dec_req* ipc_req = (rhp_ipcmsg_sess_resume_dec_req*)key_seed;
	rhp_ikev2_sess_resume_tkt *sess_res_tkt;
	u8* endp = ((u8*)ipc_req) + ipc_req->len;
	u32 ret;

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_DEC_REQ_DISP_HASH,"xx",key_seed,err);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    goto error;
  }

	if( ipc_req->len <= (int)(sizeof(rhp_ipcmsg_sess_resume_dec_req)
										 + sizeof(rhp_ikev2_sess_resume_tkt)) ){
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_DEC_REQ_DISP_HASH_INVALID_IPC_MESG,"xd",key_seed,ipc_req,ipc_req->len);
    goto error;
	}

	if( ipc_req->type != RHP_IPC_SESS_RESUME_DEC_REQUEST ){
		RHP_BUG("%d",ipc_req->type);
    goto error;
	}


	sess_res_tkt = (rhp_ikev2_sess_resume_tkt*)(ipc_req + 1);

	if( (u8*)(sess_res_tkt + 1) > endp ){
		RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_DEC_REQ_DISP_HASH_INVALID_IPC_MESG_2,"xdxx",key_seed,ipc_req,ipc_req->len,endp,(sess_res_tkt + 1));
	}

	ret = *((u32*)sess_res_tkt->enc_iv);
	*err = 0;

	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_DEC_REQ_DISP_HASH_RTRN,"xEj",key_seed,*err,ret);
	return ret;

error:
	*err = -EINVAL;
	RHP_TRC(0,RHPTRCID_IKEV2_SESS_RESUME_DEC_REQ_DISP_HASH_ERR,"xE",key_seed,*err);
	return 0;
}

int rhp_ikev2_sess_resume_syspxy_init()
{
	int err = -EINVAL;


	if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
		RHP_BUG("");
		return -EINVAL;
  }

  _rhp_mutex_init("SRE",&(_rhp_sess_resume_lock));



	if( !rhp_gcfg_ikev2_sess_resume_resp_enabled ){

		_rhp_sess_res_key_cur.key.key_index = 0;
		_rhp_sess_res_key_old.key.key_index = 0;

		return 0;
	}


	{
		err = _rhp_ikev2_sess_resume_init_key_obj(&_rhp_sess_res_key_cur);
		if( err ){
			RHP_BUG("");
			goto error;
		}

		err = _rhp_ikev2_sess_resume_init_key_obj(&_rhp_sess_res_key_old);
		if( err ){
			RHP_BUG("");
			goto error;
		}
	}


	{
		err = _rhp_ikev2_sess_resume_init_read_key_file(&_rhp_sess_res_key_cur,
						rhp_syspxy_sess_resume_key_path);
		if( err ){

			_rhp_sess_res_key_cur.key.key_index = 0;
			_rhp_sess_res_key_old.key.key_index = 0;

		}else{

			err = _rhp_ikev2_sess_resume_init_read_key_file(&_rhp_sess_res_key_old,
							rhp_syspxy_sess_resume_old_key_path);
			if( err ){

				_rhp_sess_res_key_old.key.key_index = 0;
			}
		}
	}


	if( !_rhp_ikev2_sess_resume_is_valid_key_data(&_rhp_sess_res_key_cur) ){

		_rhp_sess_res_key_cur.key.key_index = 0;
		_rhp_sess_res_key_old.key.key_index = 0;

	}else{

		if( !_rhp_ikev2_sess_resume_is_valid_key_data(&_rhp_sess_res_key_old) ){

			_rhp_sess_res_key_old.key.key_index = 0;
		}
	}

	{
		if( _rhp_sess_res_key_cur.key.key_index == 0 ){

			_rhp_ikev2_sess_resume_init_clear_key_files(&_rhp_sess_res_key_cur);

			err = _rhp_ikev2_sess_resume_init_setup_cur_key();
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}
		}


		err = _rhp_ikev2_sess_resume_init_set_enc_params(&_rhp_sess_res_key_cur);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}


		err = _rhp_ikev2_sess_resume_init_tkt_rvk(&_rhp_sess_res_key_cur,
						rhp_syspxy_sess_resume_revocation_bfltr_path);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
	}


	if( _rhp_sess_res_key_old.key.key_index ){

		_rhp_ikev2_sess_resume_init_clear_key_files(&_rhp_sess_res_key_old);

		err = _rhp_ikev2_sess_resume_init_set_enc_params(&_rhp_sess_res_key_old);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		err = _rhp_ikev2_sess_resume_init_tkt_rvk(&_rhp_sess_res_key_old,
						rhp_syspxy_sess_resume_revocation_old_bfltr_path);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
	}


	if( rhp_gcfg_dbg_log_keys_info ){
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_SESS_RESUME_KEY,"qupp",_rhp_sess_res_key_cur.key.key_index,_rhp_sess_res_key_cur.key.expire_time,RHP_IKEV2_SESS_RESUME_TKT_ENC_KEY_LEN,_rhp_sess_res_key_cur.key.enc_key,RHP_IKEV2_SESS_RESUME_TKT_MAC_KEY_LEN,_rhp_sess_res_key_cur.key.mac_key);
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_SESS_RESUME_KEY_OLD,"qupp",_rhp_sess_res_key_old.key.key_index,_rhp_sess_res_key_old.key.expire_time,RHP_IKEV2_SESS_RESUME_TKT_ENC_KEY_LEN,_rhp_sess_res_key_old.key.enc_key,RHP_IKEV2_SESS_RESUME_TKT_MAC_KEY_LEN,_rhp_sess_res_key_old.key.mac_key);
	}

	{
		err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_SESS_RESUME_ENC_REQUEST,
				NULL,&_rhp_sess_resume_enc_req_syspxy_ipc);

		if( err ){
			RHP_BUG("");
			goto error;
		}

	  if( (err = rhp_wts_register_disp_rule(RHP_WTS_DISP_RULE_SESS_RESUME_DEC_TKT,
	  							_rhp_sess_resume_dec_req_disp_hash)) ){
	    RHP_BUG("");
	    goto error;
	  }

		err = rhp_ipc_register_handler(RHP_MY_PROCESS,RHP_IPC_SESS_RESUME_DEC_REQUEST,
				NULL,&_rhp_sess_resume_dec_req_syspxy_ipc);

		if( err ){
			RHP_BUG("");
			goto error;
		}
	}


	_rhp_ikev2_sess_resume_init_start_key_timer();


	RHP_TRC(0,RHPTRCID_IKEV2_SES_RESUME_SYSPXY_INIT_OK,"");
	return 0;

error:
	_rhp_sess_res_key_cur.key.key_index = 0;
	_rhp_sess_res_key_old.key.key_index = 0;
	RHP_TRC(0,RHPTRCID_IKEV2_SES_RESUME_SYSPXY_INIT_ERR,"E",err);
	return err;
}


int rhp_ikev2_sess_resume_syspxy_cleanup()
{

	if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
		RHP_BUG("");
		return -EINVAL;
  }

	if( _rhp_sess_res_key_cur.revocation_bfltr ){
		rhp_bloom_filter_free(_rhp_sess_res_key_cur.revocation_bfltr);
	}

	if( _rhp_sess_res_key_old.revocation_bfltr ){
		rhp_bloom_filter_free(_rhp_sess_res_key_old.revocation_bfltr);
	}

	_rhp_sess_res_key_cur.key.key_index = 0;
	_rhp_sess_res_key_old.key.key_index = 0;

	_rhp_mutex_destroy(&(_rhp_sess_resume_lock));

  RHP_TRC(0,RHPTRCID_IKEV2_SES_RESUME_SYSPXY_CLEANUP_OK,"");
	return 0;
}
