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
#include <byteswap.h>


#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_protocol.h"
#include "rhp_packet.h"
#include "rhp_netsock.h"
#include "rhp_config.h"
#include "rhp_vpn.h"
#include "rhp_ikev2_mesg.h"
#include "rhp_ikev2.h"
#include "rhp_http.h"

extern rhp_mutex_t rhp_vpn_lock;

static u64 _rhp_ikesa_dbg_init_spi = 0;
static u64 _rhp_ikesa_dbg_resp_spi = 0x100000;

#define RHP_IKESA_HASH_TABLE_SIZE   1277

static rhp_ikesa_init_i* _rhp_ikesa_init_i_hashtbl[RHP_IKESA_HASH_TABLE_SIZE];
static u32 _rhp_ikesa_init_i_hashtbl_rnd;

static rhp_mutex_t _rhp_ikesa_open_sess_lock;
static long _rhp_ikesa_half_open_sessions = 0;
#define RHP_IKESA_OPEN_REQ_PER_SECS_INTERVAL	1
static time_t _rhp_ikesa_open_req_per_secs_last_rec_time;
static long _rhp_ikesa_open_req_per_secs = 0;


struct _rhp_ikesa_spi {

	u8 tag[4]; // '#IPI'

	struct _rhp_ikesa_spi* next;

	int side; // RHP_IKE_INITIATOR or RHP_IKE_RESPONDER
	u8 spi[RHP_PROTO_IKE_SPI_SIZE];
};
typedef struct _rhp_ikesa_spi	rhp_ikesa_spi;


static rhp_ikesa_spi* _rhp_ikesa_spi_hash_tbl[RHP_IKESA_HASH_TABLE_SIZE];
static u32 _rhp_ikesa_spi_hashtbl_rnd;

#define RHP_IKESA_GEN_SPI_MAX_TRYING		(1024*1024)

long rhp_ikesa_half_open_sessions_num_get()
{
	long ret;

  RHP_LOCK(&_rhp_ikesa_open_sess_lock);
  ret = _rhp_ikesa_half_open_sessions;
  RHP_UNLOCK(&_rhp_ikesa_open_sess_lock);

  return ret;
}

void rhp_ikesa_half_open_sessions_inc()
{
  RHP_LOCK(&_rhp_ikesa_open_sess_lock);
  _rhp_ikesa_half_open_sessions++;
  RHP_UNLOCK(&_rhp_ikesa_open_sess_lock);

  RHP_TRC(0,RHPTRCID_IKESA_HALF_OPEN_SESSIONS_INC,"d",_rhp_ikesa_half_open_sessions);
  return;
}

void rhp_ikesa_half_open_sessions_dec()
{
  RHP_LOCK(&_rhp_ikesa_open_sess_lock);

  _rhp_ikesa_half_open_sessions--;

  if( _rhp_ikesa_half_open_sessions < 0 ){
    RHP_BUG("");
  }

  RHP_UNLOCK(&_rhp_ikesa_open_sess_lock);

  RHP_TRC(0,RHPTRCID_IKESA_HALF_OPEN_SESSIONS_DEC,"d",_rhp_ikesa_half_open_sessions);
  return;
}

void rhp_ikesa_open_req_per_sec_update()
{
  time_t now;

  RHP_LOCK(&_rhp_ikesa_open_sess_lock);

  now = _rhp_get_time();

  if( _rhp_ikesa_open_req_per_secs_last_rec_time + RHP_IKESA_OPEN_REQ_PER_SECS_INTERVAL < now ){
    _rhp_ikesa_open_req_per_secs = 0;
    _rhp_ikesa_open_req_per_secs_last_rec_time = now;
  }

  _rhp_ikesa_open_req_per_secs++;

  RHP_UNLOCK(&_rhp_ikesa_open_sess_lock);

  RHP_TRC(0,RHPTRCID_IKESA_OPEN_REQ_PER_SEC_UPDATE,"d",_rhp_ikesa_open_req_per_secs);
  return;
}

int rhp_ikesa_cookie_active(int inc_statistics)
{
  time_t now;
  int flag = 0;

  if( !rhp_gcfg_ikesa_cookie ){
    RHP_TRC(0,RHPTRCID_IKESA_COOKIE_ACTIVE_DISABLED,"d",rhp_gcfg_ikesa_cookie);
  	return 0;
  }

  RHP_LOCK(&_rhp_ikesa_open_sess_lock);

  RHP_TRC(0,RHPTRCID_IKESA_COOKIE_ACTIVE,"ddd",rhp_gcfg_ikesa_cookie,rhp_gcfg_ikesa_cookie_max_half_open_sessions,_rhp_ikesa_half_open_sessions);

  if( !rhp_gcfg_ikesa_cookie_max_half_open_sessions ||
  		(_rhp_ikesa_half_open_sessions > rhp_gcfg_ikesa_cookie_max_half_open_sessions) ){

  	flag = 1;

  	if( inc_statistics ){
  		rhp_ikev2_g_statistics_inc(max_cookie_half_open_sessions_reached);
  	}

  }else{

    now = _rhp_get_time();

    RHP_TRC(0,RHPTRCID_IKESA_COOKIE_ACTIVE_INTERVAL,"uudd",now,_rhp_ikesa_open_req_per_secs_last_rec_time,_rhp_ikesa_open_req_per_secs,rhp_gcfg_ikesa_cookie_max_open_req_per_sec);

    if( _rhp_ikesa_open_req_per_secs_last_rec_time + RHP_IKESA_OPEN_REQ_PER_SECS_INTERVAL >= now ){

    	if( _rhp_ikesa_open_req_per_secs > rhp_gcfg_ikesa_cookie_max_open_req_per_sec ){

    		flag = 1;

    		if( inc_statistics ){
    			rhp_ikev2_g_statistics_inc(max_cookie_half_open_sessions_per_sec_reached);
    		}
      }

    }else{

      _rhp_ikesa_open_req_per_secs = 0;
      _rhp_ikesa_open_req_per_secs_last_rec_time = now;
    }
  }

  RHP_UNLOCK(&_rhp_ikesa_open_sess_lock);

  RHP_TRC(0,RHPTRCID_IKESA_COOKIE_ACTIVE_RTRN,"d",flag);
  return flag;
}

int rhp_ikesa_max_half_open_sessions_reached()
{
	int flag = 0;

  RHP_LOCK(&_rhp_ikesa_open_sess_lock);

	RHP_TRC_FREQ(0,RHPTRCID_IKESA_MAX_HALF_OPEN_SESSIONS_REACHED,"df",rhp_gcfg_vpn_max_half_open_sessions,_rhp_ikesa_half_open_sessions);

  if( rhp_gcfg_vpn_max_half_open_sessions &&
  		(_rhp_ikesa_half_open_sessions >= rhp_gcfg_vpn_max_half_open_sessions) ){
  	flag = 1;
  }

  RHP_UNLOCK(&_rhp_ikesa_open_sess_lock);

  return flag;
}

int rhp_ikesa_init()
{
  int err;

  if( rhp_random_bytes((u8*)&_rhp_ikesa_init_i_hashtbl_rnd,sizeof(_rhp_ikesa_init_i_hashtbl_rnd)) ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( rhp_random_bytes((u8*)&_rhp_ikesa_spi_hashtbl_rnd,sizeof(_rhp_ikesa_spi_hashtbl_rnd)) ){
    RHP_BUG("");
    return -EINVAL;
  }

  memset(_rhp_ikesa_init_i_hashtbl,0,sizeof(rhp_ikesa_init_i*)*RHP_IKESA_HASH_TABLE_SIZE);
  memset(_rhp_ikesa_spi_hash_tbl,0,sizeof(rhp_ikesa_spi*)*RHP_IKESA_HASH_TABLE_SIZE);

  err = rhp_childsa_init();
  if( err ){
    RHP_BUG("%d",err);
  }

  _rhp_ikesa_open_req_per_secs_last_rec_time = _rhp_get_time();

  _rhp_mutex_init("LOS",&(_rhp_ikesa_open_sess_lock));

  RHP_TRC(0,RHPTRCID_IKESA_INIT,"E",err);
  return err;
}

int rhp_ikesa_cleanup()
{
  rhp_childsa_cleanup();

  _rhp_mutex_destroy(&(_rhp_ikesa_open_sess_lock));

  RHP_TRC(0,RHPTRCID_IKESA_CLEANUP,"");
  return 0;
}

static u64 _rhp_ikesa_ipc_txn_id = 0;

u64 rhp_ikesa_new_ipc_txn_id()
{
  u64 new_id;

  RHP_LOCK(&rhp_vpn_lock);
  if( _rhp_ikesa_ipc_txn_id == 0 ){
  	_rhp_ikesa_ipc_txn_id++;
  }
  new_id = ++_rhp_ikesa_ipc_txn_id;
  RHP_UNLOCK(&rhp_vpn_lock);

  RHP_TRC(0,RHPTRCID_IKESA_IPC_TXN_ID,"q",new_id);
  return new_id;
}


static int _rhp_ikesa_generate_spi(int my_side,u8* my_spi_r)
{
  int err = 0;
  u64 spi;
  u32 hval;
  rhp_ikesa_spi* entry = NULL;
  unsigned int i = 0;

  RHP_TRC(0,RHPTRCID_IKESA_GENERATE_SPI,"Ldxd","IKE_SIDE",my_side,my_spi_r,rhp_gcfg_ikesa_dbg_gen_spi);

  RHP_LOCK(&rhp_vpn_lock);

  do{

  	if( i > RHP_IKESA_GEN_SPI_MAX_TRYING ){
  		RHP_BUG("%d",i);
  		err = -EINVAL;
  		goto error;
  	}
  	i++;

  	if( rhp_gcfg_ikesa_dbg_gen_spi ){

  	  RHP_TRC(0,RHPTRCID_IKESA_GENERATE_SPI_DBG,"qq",_rhp_ikesa_dbg_init_spi,_rhp_ikesa_dbg_resp_spi);

  		if( my_side == RHP_IKE_INITIATOR ){

				if( _rhp_ikesa_dbg_init_spi == 0 ){
					_rhp_ikesa_dbg_init_spi++;
				}

				spi = _rhp_ikesa_dbg_init_spi;
				_rhp_ikesa_dbg_init_spi++;

  		}else{

  		  if( _rhp_ikesa_dbg_resp_spi == 0 ){
  		    _rhp_ikesa_dbg_resp_spi++;
  		  }

  		  spi = _rhp_ikesa_dbg_resp_spi;
  		  _rhp_ikesa_dbg_resp_spi++;
  		}

  	}else{

  		if( rhp_random_bytes((u8*)&spi,sizeof(u64)) ){
				RHP_BUG("");
				err = -EINVAL;
				goto error;
			}
  	}

    if( spi == 0 ){
    	continue;
    }

	  spi = bswap_64(spi);

    hval = _rhp_hash_bytes((u8*)&spi, sizeof(u64),_rhp_ikesa_spi_hashtbl_rnd);
    hval = hval % RHP_IKESA_HASH_TABLE_SIZE;

    entry = _rhp_ikesa_spi_hash_tbl[hval];
    while( entry ){

    	if( (entry->side == my_side) &&
    		  !memcmp(entry->spi,&spi,RHP_PROTO_IKE_SPI_SIZE) ){
    		break;
    	}

    	entry = entry->next;
    }

    if( entry == NULL ){

    	entry = (rhp_ikesa_spi*)_rhp_malloc(sizeof(rhp_ikesa_spi));
    	if( entry == NULL ){
    		RHP_BUG("");
    		err = -ENOMEM;
    		goto error;
    	}

    	memset(entry,0,sizeof(rhp_ikesa_spi));
    	entry->side = my_side;

    	entry->tag[0] = '#';
    	entry->tag[1] = 'I';
    	entry->tag[2] = 'P';
    	entry->tag[3] = 'I';
    	memcpy(entry->spi,(u8*)&spi,RHP_PROTO_IKE_SPI_SIZE);

    	hval = _rhp_hash_bytes((u8*)&spi, sizeof(u64),_rhp_ikesa_spi_hashtbl_rnd);
    	hval = hval % RHP_IKESA_HASH_TABLE_SIZE;

    	entry->next = _rhp_ikesa_spi_hash_tbl[hval];
    	_rhp_ikesa_spi_hash_tbl[hval] = entry;

    	memcpy(my_spi_r,&spi,RHP_PROTO_IKE_SPI_SIZE);

    	break;
    }

  }while( 1 );

  RHP_UNLOCK(&rhp_vpn_lock);

  RHP_TRC(0,RHPTRCID_IKESA_GENERATE_SPI_RTRN,"dxGx",my_side,my_spi_r,my_spi_r,entry);
  return 0;

error:
  RHP_UNLOCK(&rhp_vpn_lock);

  RHP_TRC(0,RHPTRCID_IKESA_GENERATE_SPI_ERR,"dxE",my_side,my_spi_r,err);
  return err;
}

static void _rhp_ikesa_clean_spi(int my_side,u8* my_spi)
{
  u32 hval;
  rhp_ikesa_spi *entry = NULL,*entry_p = NULL;

  RHP_TRC(0,RHPTRCID_IKESA_CLEAN_SPI,"LdxG","IKE_SIDE",my_side,my_spi,my_spi);

  RHP_LOCK(&rhp_vpn_lock);

  hval = _rhp_hash_bytes(my_spi, sizeof(u64),_rhp_ikesa_spi_hashtbl_rnd);
  hval = hval % RHP_IKESA_HASH_TABLE_SIZE;

  entry = _rhp_ikesa_spi_hash_tbl[hval];

  while( entry ){

    if( (entry->side == my_side) &&
   		 !memcmp(entry->spi,my_spi,RHP_PROTO_IKE_SPI_SIZE) ){
    	break;
    }

  	entry_p = entry;
  	entry = entry->next;
  }

  if( entry == NULL ){

  	RHP_UNLOCK(&rhp_vpn_lock);

  	RHP_TRC(0,RHPTRCID_IKESA_CLEAN_SPI_NOT_FOUND,"LdxG","",my_side,my_spi,my_spi);
  	return;
  }

  if( entry_p ){
    entry_p->next = entry->next;
  }else{
  	_rhp_ikesa_spi_hash_tbl[hval] = entry->next;
  }

  RHP_UNLOCK(&rhp_vpn_lock);

  _rhp_free(entry);

  RHP_TRC(0,RHPTRCID_IKESA_CLEAN_SPI_RTRN,"dxGx",my_side,my_spi,my_spi,entry);
  return;
}


static int _rhp_ikesa_generate_init_spi(rhp_ikesa* ikesa)
{
	int err;

  RHP_TRC(0,RHPTRCID_IKESA_GENERATE_INIT_SPI,"x",ikesa);

  err = _rhp_ikesa_generate_spi(RHP_IKE_INITIATOR,ikesa->init_spi);
  if( err ){
  	RHP_BUG("");
  }

  RHP_TRC(0,RHPTRCID_IKESA_GENERATE_INIT_SPI_RTRN,"xGE",ikesa,ikesa->init_spi,err);
  return err;
}

static int _rhp_ikesa_generate_resp_spi(rhp_ikesa* ikesa)
{
	int err;

  RHP_TRC(0,RHPTRCID_IKESA_GENERATE_RESP_SPI,"x",ikesa);

  err = _rhp_ikesa_generate_spi(RHP_IKE_RESPONDER,ikesa->resp_spi);
  if( err ){
  	RHP_BUG("");
  }

  RHP_TRC(0,RHPTRCID_IKESA_GENERATE_RESP_SPI_RTRN,"xGE",ikesa,ikesa->resp_spi,err);
  return err;
}

static void _rhp_ikesa_set_resp_spi(rhp_ikesa* ikesa,u8* spi)
{
  RHP_TRC(0,RHPTRCID_IKESA_SET_RESP_SPI,"xG",ikesa,spi);

  memcpy(ikesa->resp_spi,spi,RHP_PROTO_IKE_SPI_SIZE);
  return;
}

static void _rhp_ikesa_set_init_spi(rhp_ikesa* ikesa,u8* spi)
{
  RHP_TRC(0,RHPTRCID_IKESA_SET_INIT_SPI,"xG",ikesa,spi);

  memcpy(ikesa->init_spi,spi,RHP_PROTO_IKE_SPI_SIZE);
  return;
}


static int _rhp_ikesa_generate_keys(rhp_ikesa* ikesa)
{
  int err = -EINVAL;
  int km_buf_len = 0,prf_output_len = 0,prf_key_len = 0;
  u8* skeyseed = NULL;
  u8 *n_i_r_spi_i_r_buf = NULL,*n_i = NULL,*n_r = NULL;
  int n_i_r_len = 0,n_i_len,n_r_len = 0;
  u8* dh_shared_key = NULL;
  int dh_shared_key_len = 0;
  u8* sess_resume_sbuf = NULL;


  //
  // SKEYSEED = prf(Ni | Nr, g^ir)
  //
  // {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr | SK_dmvpn_a | SK_dmvpn_e}
  //  = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr )
  //

  RHP_TRC(0,RHPTRCID_IKESA_GENERATE_KEYS,"xd",ikesa,ikesa->gen_by_sess_resume);

  if( ikesa->dh == NULL || ikesa->prf == NULL || ikesa->integ_i == NULL || ikesa->integ_r == NULL  ||
      ikesa->encr == NULL || ikesa->nonce_i == NULL || ikesa->nonce_r == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( !ikesa->gen_by_sess_resume ){ // NOT IKEv2 Session Resumption!

    // Generate DH shared key.

		dh_shared_key = ikesa->dh->get_shared_key(ikesa->dh,&dh_shared_key_len);
		if( dh_shared_key == NULL ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		if( rhp_gcfg_dbg_log_keys_info ){
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_KEY_DH_SHAREDKEY,"Pp",ikesa,dh_shared_key_len,dh_shared_key);
		}

  }else{

  	if( (ikesa->side == RHP_IKE_INITIATOR && ikesa->sess_resume.init.material == NULL) ||
  			(ikesa->side == RHP_IKE_RESPONDER && ikesa->sess_resume.resp.dec_tkt_ipc_rep == NULL) ){
  		RHP_BUG("");
  		err = -EINVAL;
  		goto error;
  	}
  }

  prf_output_len = ikesa->prf->get_output_len(ikesa->prf);
  prf_key_len = ikesa->prf->get_key_len(ikesa->prf);

  // Prepare Ni and Nr
  {
		n_i_len = ikesa->nonce_i->get_nonce_len(ikesa->nonce_i);
		n_r_len = ikesa->nonce_r->get_nonce_len(ikesa->nonce_r);

		n_i_r_len = n_i_len + n_r_len;

		n_i = ikesa->nonce_i->get_nonce(ikesa->nonce_i);
		n_r = ikesa->nonce_r->get_nonce(ikesa->nonce_r);

		if( n_i_r_len < prf_key_len ){
			err = -EINVAL;
			RHP_TRC(0,RHPTRCID_IKESA_GENERATE_KEYS_INVALID_NONCE_LEN,"xdd",ikesa,n_i_r_len,prf_key_len);
			goto error;
		}

		if( n_i == NULL || n_r == NULL ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		if( rhp_gcfg_dbg_log_keys_info ){
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_KEY_N_I,"Pp",ikesa,n_i_len,n_i);
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_KEY_N_R,"Pp",ikesa,n_r_len,n_r);
		}
  }

  // Prepare a prf+ material.
  {
		n_i_r_spi_i_r_buf = (u8*)_rhp_malloc(n_i_r_len + RHP_PROTO_IKE_SPI_SIZE*2);
		if( n_i_r_spi_i_r_buf == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		memcpy(n_i_r_spi_i_r_buf,n_i,n_i_len);
		memcpy((n_i_r_spi_i_r_buf + n_i_len),n_r,n_r_len);
		memcpy((n_i_r_spi_i_r_buf + n_i_len + n_r_len),ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
		memcpy((n_i_r_spi_i_r_buf + n_i_len + n_r_len + RHP_PROTO_IKE_SPI_SIZE),ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);

		RHP_TRC(0,RHPTRCID_IKESA_GENERATE_KEYS_MATERIALS,"xpppp",ikesa,n_i_len,n_i,n_r_len,n_r,RHP_PROTO_IKE_SPI_SIZE,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE,ikesa->resp_spi);
  }

  // Generate SKEYSEED
  {
		skeyseed = (u8*)_rhp_malloc(prf_output_len);
		if( skeyseed == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		RHP_TRC(0,RHPTRCID_IKESA_GENERATE_KEYS_MATERIALS_2,"xp",ikesa,n_i_r_len,n_i_r_spi_i_r_buf);

		if( !ikesa->gen_by_sess_resume ){ // NOT IKEv2 Session Resumption!

			// SKEYSEED: Only Ni and Nr are used here. (n_i_r_len NOT including SPIs length).
			err = ikesa->prf->set_key(ikesa->prf,n_i_r_spi_i_r_buf,n_i_r_len);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			err = ikesa->prf->compute(ikesa->prf,dh_shared_key,dh_shared_key_len,skeyseed,prf_output_len);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			if( rhp_gcfg_dbg_log_keys_info ){
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_KEY_SKEYSEED,"Pp",ikesa,prf_output_len,skeyseed);
			}

		}else{ // IKEv2 Session Resumption!

			int old_sk_d_len = 0;
			u8* old_sk_d = NULL;
			int sbuf_len = 10 + n_i_len + n_r_len; // 10 : strlen("Resumption")

			/*
				SKEYSEED = prf(SK_d_old, "Resumption" | Ni | Nr)

				The keys are derived as follows, unchanged from IKEv2:
				{SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr | SK_dmvpn_a | SK_dmvpn_e}
				= prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)
			*/

			sess_resume_sbuf = (u8*)_rhp_malloc(sbuf_len);
			if( sess_resume_sbuf == NULL ){
				RHP_BUG("%d",sbuf_len);
				goto error;
			}
			memcpy(sess_resume_sbuf,"Resumption",10);
			memcpy(sess_resume_sbuf + 10,n_i,n_i_len);
			memcpy(sess_resume_sbuf + 10 + n_i_len,n_r,n_r_len);

			if( ikesa->side == RHP_IKE_INITIATOR ){

				old_sk_d = ikesa->sess_resume.init.material->old_sk_d_i;
				old_sk_d_len = ikesa->sess_resume.init.material->old_sk_d_i_len;

			}else{

				rhp_ikev2_sess_resume_tkt_e* sess_res_tkt_e = NULL;

				err = rhp_ikev2_sess_resume_dec_tkt_vals(
								(rhp_ikev2_sess_resume_tkt*)(ikesa->sess_resume.resp.dec_tkt_ipc_rep + 1),
								&sess_res_tkt_e,
								&old_sk_d,
								NULL,NULL,NULL,NULL,NULL,NULL);
				if( err ){
					RHP_BUG("%d",err);
					goto error;
				}

				old_sk_d_len = (int)ntohs(sess_res_tkt_e->sk_d_len);
			}

			if( old_sk_d == NULL || old_sk_d_len == 0 ){
				RHP_BUG("0x%x, %d",old_sk_d,old_sk_d_len);
				err = -EINVAL;
				goto error;
			}

			if( prf_key_len != old_sk_d_len ){
				RHP_BUG("%d, %d",prf_key_len,old_sk_d_len);
				err = -EINVAL;
				goto error;
			}

			err = ikesa->prf->set_key(ikesa->prf,old_sk_d,old_sk_d_len);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			err = ikesa->prf->compute(ikesa->prf,sess_resume_sbuf,sbuf_len,skeyseed,prf_output_len);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

	  	_rhp_free(sess_resume_sbuf);
	  	sess_resume_sbuf = NULL;

			if( rhp_gcfg_dbg_log_keys_info ){
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_SESS_RESUME_GENERATED_KEY_SKEYSEED,"Pp",ikesa,prf_output_len,skeyseed);
			}
		}
	}

  // Generate keys.
  {
		ikesa->keys.v2.sk_d_len = prf_key_len;
		ikesa->keys.v2.sk_a_len = ikesa->integ_i->get_key_len(ikesa->integ_i);
		ikesa->keys.v2.sk_e_len = ikesa->encr->get_key_len(ikesa->encr);
		ikesa->keys.v2.sk_p_len = prf_key_len;
		ikesa->keys.v2.sk_dmvpn_a_len = ikesa->keys.v2.sk_a_len;
		ikesa->keys.v2.sk_dmvpn_e_len = ikesa->keys.v2.sk_e_len;

		km_buf_len
			= ikesa->keys.v2.sk_d_len + (ikesa->keys.v2.sk_a_len*2) + (ikesa->keys.v2.sk_e_len*2) + (ikesa->keys.v2.sk_p_len*2)
				+ ikesa->keys.v2.sk_dmvpn_a_len + ikesa->keys.v2.sk_dmvpn_e_len;
		km_buf_len = ((km_buf_len+(prf_output_len-1)) & ~(prf_output_len - 1));


		ikesa->key_material.key_octets = (u8*)_rhp_malloc(km_buf_len);
		if( ikesa->key_material.key_octets == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
		memset(ikesa->key_material.key_octets,0,km_buf_len);

		err = rhp_crypto_prf_plus(ikesa->prf,skeyseed,prf_output_len,n_i_r_spi_i_r_buf,
													 ( n_i_r_len + RHP_PROTO_IKE_SPI_SIZE*2 ),ikesa->key_material.key_octets,km_buf_len);
		if( err ){
			RHP_BUG("");
			goto error;
		}
		ikesa->key_material.len = km_buf_len;
  }

  ikesa->keys.v2.sk_d = ikesa->key_material.key_octets;
  ikesa->keys.v2.sk_ai = ikesa->keys.v2.sk_d + ikesa->keys.v2.sk_d_len;
  ikesa->keys.v2.sk_ar = ikesa->keys.v2.sk_ai + ikesa->keys.v2.sk_a_len;
  ikesa->keys.v2.sk_ei = ikesa->keys.v2.sk_ar + ikesa->keys.v2.sk_a_len;
  ikesa->keys.v2.sk_er = ikesa->keys.v2.sk_ei + ikesa->keys.v2.sk_e_len;
  ikesa->keys.v2.sk_pi = ikesa->keys.v2.sk_er + ikesa->keys.v2.sk_e_len;
  ikesa->keys.v2.sk_pr = ikesa->keys.v2.sk_pi + ikesa->keys.v2.sk_p_len;
  ikesa->keys.v2.sk_dmvpn_a = ikesa->keys.v2.sk_pr + ikesa->keys.v2.sk_dmvpn_a_len;
  ikesa->keys.v2.sk_dmvpn_e = ikesa->keys.v2.sk_dmvpn_a + ikesa->keys.v2.sk_dmvpn_a_len;

  RHP_TRC(0,RHPTRCID_IKESA_GENERATE_KEYS_VALUES,"xppppppppp",ikesa,ikesa->keys.v2.sk_d_len,ikesa->keys.v2.sk_d,ikesa->keys.v2.sk_a_len,ikesa->keys.v2.sk_ai,ikesa->keys.v2.sk_a_len,ikesa->keys.v2.sk_ar,ikesa->keys.v2.sk_e_len,ikesa->keys.v2.sk_ei,ikesa->keys.v2.sk_e_len,ikesa->keys.v2.sk_er,ikesa->keys.v2.sk_p_len,ikesa->keys.v2.sk_pi,ikesa->keys.v2.sk_p_len,ikesa->keys.v2.sk_pr,ikesa->keys.v2.sk_dmvpn_a_len,ikesa->keys.v2.sk_dmvpn_a,ikesa->keys.v2.sk_dmvpn_e_len,ikesa->keys.v2.sk_dmvpn_e);


  if( rhp_gcfg_dbg_log_keys_info ){
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_KEY_VALUES_SK_D,"Pp",ikesa,ikesa->keys.v2.sk_d_len,ikesa->keys.v2.sk_d);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_KEY_VALUES_SK_AI,"Pp",ikesa,ikesa->keys.v2.sk_a_len,ikesa->keys.v2.sk_ai);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_KEY_VALUES_SK_AR,"Pp",ikesa,ikesa->keys.v2.sk_a_len,ikesa->keys.v2.sk_ar);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_KEY_VALUES_SK_EI,"Pp",ikesa,ikesa->keys.v2.sk_e_len,ikesa->keys.v2.sk_ei);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_KEY_VALUES_SK_ER,"Pp",ikesa,ikesa->keys.v2.sk_e_len,ikesa->keys.v2.sk_er);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_KEY_VALUES_SK_PI,"Pp",ikesa,ikesa->keys.v2.sk_p_len,ikesa->keys.v2.sk_pi);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_KEY_VALUES_SK_PR,"Pp",ikesa,ikesa->keys.v2.sk_p_len,ikesa->keys.v2.sk_pr);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_KEY_VALUES_SK_DMVPN_A,"Pp",ikesa,ikesa->keys.v2.sk_dmvpn_a_len,ikesa->keys.v2.sk_dmvpn_a);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_KEY_VALUES_SK_DMVPN_E,"Pp",ikesa,ikesa->keys.v2.sk_dmvpn_e_len,ikesa->keys.v2.sk_dmvpn_e);
  }

  _rhp_free_zero(n_i_r_spi_i_r_buf,n_i_r_len + RHP_PROTO_IKE_SPI_SIZE*2);
  _rhp_free_zero(skeyseed,prf_output_len);

  RHP_TRC(0,RHPTRCID_IKESA_GENERATE_KEYS_RTRN,"xp",ikesa,ikesa->key_material.len,ikesa->key_material.key_octets);
  return 0;

error:
  if( n_i_r_spi_i_r_buf ){
    _rhp_free(n_i_r_spi_i_r_buf);
  }
  if( skeyseed ){
    _rhp_free(skeyseed);
  }
  if( ikesa->key_material.key_octets ){
    _rhp_free(ikesa->key_material.key_octets);
    ikesa->key_material.key_octets = 0;
  }
  if( sess_resume_sbuf ){
  	_rhp_free(sess_resume_sbuf);
  }
  ikesa->key_material.len = 0;
  ikesa->keys.v2.sk_d_len = 0;
  ikesa->keys.v2.sk_a_len = 0;
  ikesa->keys.v2.sk_e_len = 0;
  ikesa->keys.v2.sk_p_len = 0;
  ikesa->keys.v2.sk_dmvpn_a_len = 0;
  ikesa->keys.v2.sk_dmvpn_e_len = 0;

  RHP_TRC(0,RHPTRCID_IKESA_GENERATE_KEYS_ERR,"xE",ikesa,err);
  return err;
}

static int _rhp_ikesa_generate_new_keys(rhp_ikesa* old_ikesa,rhp_ikesa* new_ikesa)
{
  int err = -EINVAL;
  int km_buf_len = 0,prf_output_len = 0,prf_key_len = 0,old_prf_output_len = 0;
  u8* skeyseed = NULL;
  u8 *n_i_r_spi_i_r_buf = NULL,*n_i = NULL,*n_r = NULL;
  int n_i_r_len = 0,n_i_len,n_r_len = 0;
  u8* dh_shared_key = NULL;
  int dh_shared_key_len = 0;
  u8* dh_n_i_r = NULL;
  int dh_n_i_r_len = 0;

  //
  // SKEYSEED = prf(SK_d (old), g^ir (new) | Ni | Nr)
  //
  // {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr | SK_dmvpn_a | SK_dmvpn_e}
  //  = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr )
  //

  RHP_TRC(0,RHPTRCID_IKESA_GENERATE_NEW_KEYS,"xx",old_ikesa,new_ikesa);

  if( new_ikesa->dh == NULL || new_ikesa->prf == NULL || new_ikesa->integ_i == NULL || new_ikesa->integ_r == NULL  ||
  		new_ikesa->encr == NULL || new_ikesa->nonce_i == NULL || new_ikesa->nonce_r == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  dh_shared_key = new_ikesa->dh->get_shared_key(new_ikesa->dh,&dh_shared_key_len);
  if( dh_shared_key == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  if( rhp_gcfg_dbg_log_keys_info ){
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_NEW_KEY_DH_SHAREDKEY,"Pp",new_ikesa,dh_shared_key_len,dh_shared_key);
  }


  prf_output_len = new_ikesa->prf->get_output_len(new_ikesa->prf);
  prf_key_len = new_ikesa->prf->get_key_len(new_ikesa->prf);

  n_i_len = new_ikesa->nonce_i->get_nonce_len(new_ikesa->nonce_i);
  n_r_len = new_ikesa->nonce_r->get_nonce_len(new_ikesa->nonce_r);

  n_i_r_len = n_i_len + n_r_len;

  n_i = new_ikesa->nonce_i->get_nonce(new_ikesa->nonce_i);
  n_r = new_ikesa->nonce_r->get_nonce(new_ikesa->nonce_r);

  if( n_i_r_len < prf_key_len ){
    err = -EINVAL;
    RHP_TRC(0,RHPTRCID_IKESA_GENERATE_NEW_KEYS_INVALID_NONCE_LEN,"xdd",new_ikesa,n_i_r_len,prf_key_len);
    goto error;
  }

  if( n_i == NULL || n_r == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  if( rhp_gcfg_dbg_log_keys_info ){
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_NEW_KEY_N_I,"Pp",new_ikesa,n_i_len,n_i);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_NEW_KEY_N_R,"Pp",new_ikesa,n_r_len,n_r);
  }


  old_prf_output_len = old_ikesa->prf->get_output_len(old_ikesa->prf);

	dh_n_i_r_len = dh_shared_key_len + n_i_r_len;
	dh_n_i_r = (u8*)_rhp_malloc(dh_n_i_r_len);
	if( dh_n_i_r == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memcpy(dh_n_i_r,dh_shared_key,dh_shared_key_len);
	memcpy((dh_n_i_r + dh_shared_key_len),n_i,n_i_len);
	memcpy((dh_n_i_r + dh_shared_key_len + n_i_len),n_r,n_r_len);

  skeyseed = (u8*)_rhp_malloc(old_prf_output_len);
  if( skeyseed == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

  err = old_ikesa->prf->set_key(old_ikesa->prf,old_ikesa->keys.v2.sk_d,old_ikesa->keys.v2.sk_d_len);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  err = old_ikesa->prf->compute(old_ikesa->prf,dh_n_i_r,dh_n_i_r_len,skeyseed,old_prf_output_len);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  if( rhp_gcfg_dbg_log_keys_info ){
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_NEW_KEY_SKEYSEED,"Pp",new_ikesa,prf_output_len,skeyseed);
  }



  n_i_r_spi_i_r_buf = (u8*)_rhp_malloc( n_i_r_len + RHP_PROTO_IKE_SPI_SIZE*2 );
  if( n_i_r_spi_i_r_buf == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

  memcpy(n_i_r_spi_i_r_buf,n_i,n_i_len);
  memcpy((n_i_r_spi_i_r_buf + n_i_len),n_r,n_r_len);
  memcpy((n_i_r_spi_i_r_buf + n_i_len + n_r_len),new_ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
  memcpy((n_i_r_spi_i_r_buf + n_i_len + n_r_len + RHP_PROTO_IKE_SPI_SIZE),new_ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);


  RHP_TRC(0,RHPTRCID_IKESA_GENERATE_NEW_KEYS_MATERIALS,"xxpppppp",old_ikesa,new_ikesa,n_i_len,n_i,n_r_len,n_r,RHP_PROTO_IKE_SPI_SIZE,new_ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE,new_ikesa->resp_spi,old_ikesa->keys.v2.sk_d_len,old_ikesa->keys.v2.sk_d,dh_n_i_r_len,dh_n_i_r);


  new_ikesa->keys.v2.sk_d_len = prf_key_len;
  new_ikesa->keys.v2.sk_a_len = new_ikesa->integ_i->get_key_len(new_ikesa->integ_i);
  new_ikesa->keys.v2.sk_e_len = new_ikesa->encr->get_key_len(new_ikesa->encr);
  new_ikesa->keys.v2.sk_p_len = prf_key_len;
  new_ikesa->keys.v2.sk_dmvpn_a_len = new_ikesa->keys.v2.sk_a_len;
  new_ikesa->keys.v2.sk_dmvpn_e_len = new_ikesa->keys.v2.sk_e_len;


  km_buf_len
  	= new_ikesa->keys.v2.sk_d_len + (new_ikesa->keys.v2.sk_a_len*2) + (new_ikesa->keys.v2.sk_e_len*2) + (new_ikesa->keys.v2.sk_p_len*2)
  		+ new_ikesa->keys.v2.sk_dmvpn_a_len + new_ikesa->keys.v2.sk_dmvpn_e_len;
  km_buf_len = ((km_buf_len+(prf_output_len-1)) & ~(prf_output_len-1));

  new_ikesa->key_material.key_octets = (u8*)_rhp_malloc(km_buf_len);
  if( new_ikesa->key_material.key_octets == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }
  memset(new_ikesa->key_material.key_octets,0,km_buf_len);

  err = rhp_crypto_prf_plus(new_ikesa->prf,skeyseed,prf_output_len,n_i_r_spi_i_r_buf,
                         ( n_i_r_len + RHP_PROTO_IKE_SPI_SIZE*2 ),new_ikesa->key_material.key_octets,km_buf_len);
  if( err ){
    RHP_BUG("");
    goto error;
  }
  new_ikesa->key_material.len = km_buf_len;

  new_ikesa->keys.v2.sk_d = new_ikesa->key_material.key_octets;
  new_ikesa->keys.v2.sk_ai = new_ikesa->keys.v2.sk_d + new_ikesa->keys.v2.sk_d_len;
  new_ikesa->keys.v2.sk_ar = new_ikesa->keys.v2.sk_ai + new_ikesa->keys.v2.sk_a_len;
  new_ikesa->keys.v2.sk_ei = new_ikesa->keys.v2.sk_ar + new_ikesa->keys.v2.sk_a_len;
  new_ikesa->keys.v2.sk_er = new_ikesa->keys.v2.sk_ei + new_ikesa->keys.v2.sk_e_len;
  new_ikesa->keys.v2.sk_pi = new_ikesa->keys.v2.sk_er + new_ikesa->keys.v2.sk_e_len;
  new_ikesa->keys.v2.sk_pr = new_ikesa->keys.v2.sk_pi + new_ikesa->keys.v2.sk_p_len;
  new_ikesa->keys.v2.sk_dmvpn_a = new_ikesa->keys.v2.sk_pr + new_ikesa->keys.v2.sk_dmvpn_a_len;
  new_ikesa->keys.v2.sk_dmvpn_e = new_ikesa->keys.v2.sk_dmvpn_a + new_ikesa->keys.v2.sk_dmvpn_a_len;

  RHP_TRC(0,RHPTRCID_IKESA_GENERATE_NEW_KEYS_VALUES,"xxppppppppp",old_ikesa,new_ikesa,new_ikesa->keys.v2.sk_d_len,new_ikesa->keys.v2.sk_d,new_ikesa->keys.v2.sk_a_len,new_ikesa->keys.v2.sk_ai,new_ikesa->keys.v2.sk_a_len,new_ikesa->keys.v2.sk_ar,new_ikesa->keys.v2.sk_e_len,new_ikesa->keys.v2.sk_ei,new_ikesa->keys.v2.sk_e_len,new_ikesa->keys.v2.sk_er,new_ikesa->keys.v2.sk_p_len,new_ikesa->keys.v2.sk_pi,new_ikesa->keys.v2.sk_p_len,new_ikesa->keys.v2.sk_pr,new_ikesa->keys.v2.sk_dmvpn_a_len,new_ikesa->keys.v2.sk_dmvpn_a,new_ikesa->keys.v2.sk_dmvpn_e_len,new_ikesa->keys.v2.sk_dmvpn_e);

  if( rhp_gcfg_dbg_log_keys_info ){
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_NEW_KEY_VALUES_SK_D,"Pp",new_ikesa,new_ikesa->keys.v2.sk_d_len,new_ikesa->keys.v2.sk_d);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_NEW_KEY_VALUES_SK_AI,"Pp",new_ikesa,new_ikesa->keys.v2.sk_a_len,new_ikesa->keys.v2.sk_ai);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_NEW_KEY_VALUES_SK_AR,"Pp",new_ikesa,new_ikesa->keys.v2.sk_a_len,new_ikesa->keys.v2.sk_ar);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_NEW_KEY_VALUES_SK_EI,"Pp",new_ikesa,new_ikesa->keys.v2.sk_e_len,new_ikesa->keys.v2.sk_ei);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_NEW_KEY_VALUES_SK_ER,"Pp",new_ikesa,new_ikesa->keys.v2.sk_e_len,new_ikesa->keys.v2.sk_er);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_NEW_KEY_VALUES_SK_PI,"Pp",new_ikesa,new_ikesa->keys.v2.sk_p_len,new_ikesa->keys.v2.sk_pi);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_NEW_KEY_VALUES_SK_PR,"Pp",new_ikesa,new_ikesa->keys.v2.sk_p_len,new_ikesa->keys.v2.sk_pr);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_NEW_KEY_VALUES_SK_DMVPN_A,"Pp",new_ikesa,new_ikesa->keys.v2.sk_dmvpn_a_len,new_ikesa->keys.v2.sk_dmvpn_a);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_NEW_KEY_VALUES_SK_DMVPN_E,"Pp",new_ikesa,new_ikesa->keys.v2.sk_dmvpn_e_len,new_ikesa->keys.v2.sk_dmvpn_e);

    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_OLD_KEY_VALUES_SK_D,"Pp",old_ikesa,old_ikesa->keys.v2.sk_d_len,old_ikesa->keys.v2.sk_d);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_OLD_KEY_VALUES_SK_AI,"Pp",old_ikesa,old_ikesa->keys.v2.sk_a_len,old_ikesa->keys.v2.sk_ai);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_OLD_KEY_VALUES_SK_AR,"Pp",old_ikesa,old_ikesa->keys.v2.sk_a_len,old_ikesa->keys.v2.sk_ar);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_OLD_KEY_VALUES_SK_EI,"Pp",old_ikesa,old_ikesa->keys.v2.sk_e_len,old_ikesa->keys.v2.sk_ei);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_OLD_KEY_VALUES_SK_ER,"Pp",old_ikesa,old_ikesa->keys.v2.sk_e_len,old_ikesa->keys.v2.sk_er);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_OLD_KEY_VALUES_SK_PI,"Pp",old_ikesa,old_ikesa->keys.v2.sk_p_len,old_ikesa->keys.v2.sk_pi);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_OLD_KEY_VALUES_SK_PR,"Pp",old_ikesa,old_ikesa->keys.v2.sk_p_len,old_ikesa->keys.v2.sk_pr);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_OLD_KEY_VALUES_SK_DMVPN_A,"Pp",old_ikesa,old_ikesa->keys.v2.sk_dmvpn_a_len,old_ikesa->keys.v2.sk_dmvpn_a);
    RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_GENERATED_OLD_KEY_VALUES_SK_DMVPN_E,"Pp",old_ikesa,old_ikesa->keys.v2.sk_dmvpn_e_len,old_ikesa->keys.v2.sk_dmvpn_e);
  }

  _rhp_free_zero(n_i_r_spi_i_r_buf,n_i_r_len + RHP_PROTO_IKE_SPI_SIZE*2);
  _rhp_free_zero(dh_n_i_r,dh_n_i_r_len);
  _rhp_free_zero(skeyseed,prf_output_len);

  RHP_TRC(0,RHPTRCID_IKESA_GENERATE_NEW_KEYS_RTRN,"xxp",old_ikesa,new_ikesa,new_ikesa->key_material.len,new_ikesa->key_material.key_octets);
  return 0;

error:
  if( n_i_r_spi_i_r_buf ){
    _rhp_free(n_i_r_spi_i_r_buf);
  }
  if( dh_n_i_r ){
    _rhp_free_zero(dh_n_i_r,dh_n_i_r_len);
  }
  if( skeyseed ){
    _rhp_free(skeyseed);
  }
  if( new_ikesa->key_material.key_octets ){
    _rhp_free(new_ikesa->key_material.key_octets);
    new_ikesa->key_material.key_octets = 0;
  }
  new_ikesa->key_material.len = 0;
  new_ikesa->keys.v2.sk_d_len = 0;
  new_ikesa->keys.v2.sk_a_len = 0;
  new_ikesa->keys.v2.sk_e_len = 0;
  new_ikesa->keys.v2.sk_dmvpn_a_len = 0;
  new_ikesa->keys.v2.sk_dmvpn_e_len = 0;

  RHP_TRC(0,RHPTRCID_IKESA_GENERATE_NEW_KEYS_ERR,"xxE",old_ikesa,new_ikesa,err);
  return err;
}

static int _rhp_ikesa_generate_keys_v1(rhp_ikesa* ikesa,int skeyid_len,u8* skeyid)
{
	int err = -EINVAL;
	rhp_crypto_hash* v1_hash = NULL;
	int dhpub_i_len, dhpub_r_len, iv_hash_len, dh_shared_key_len;
	u8 *dhpubs_p = NULL, *dhpub_i, *dhpub_r, *dh_shared_key;
	int skey_id_d_material_len, skey_id_a_material_len, skey_id_e_material_len;
	u8 *skey_id_d_material = NULL, *skey_id_a_material = NULL, *skey_id_e_material = NULL;
	int sk_e_len;
	u8* p;

  RHP_TRC(0,RHPTRCID_IKESA_GENERATE_KEYS_V1,"xpp",ikesa,skeyid_len,skeyid,ikesa->keys.v1.skeyid_len,ikesa->keys.v1.skeyid);

	if( ikesa->keys.v1.skeyid == NULL ){

		ikesa->keys.v1.skeyid = (u8*)_rhp_malloc(skeyid_len);
		if( ikesa->keys.v1.skeyid == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		memcpy(ikesa->keys.v1.skeyid,skeyid,skeyid_len);
		ikesa->keys.v1.skeyid_len = skeyid_len;
	}

	{
		ikesa->keys.v1.iv_len = ikesa->encr->get_iv_len(ikesa->encr);

		v1_hash = rhp_crypto_hash_alloc(ikesa->prop.v1.hash_alg);
		if( v1_hash == NULL ){
			RHP_BUG("%d",ikesa->prop.v1.hash_alg);
			err = -EINVAL;
			goto error;
		}

		iv_hash_len = v1_hash->get_output_len(v1_hash);
		if( ikesa->keys.v1.iv_len > iv_hash_len ){
			RHP_BUG("%d,%d",ikesa->prop.v1.hash_alg,ikesa->keys.v1.iv_len);
			err = -EINVAL;
			goto error;
		}

		if( ikesa->side == RHP_IKE_INITIATOR ){
			dhpub_i = ikesa->dh->get_my_pub_key(ikesa->dh,&dhpub_i_len);
			dhpub_r = ikesa->dh->get_peer_pub_key(ikesa->dh,&dhpub_r_len);
		}else{ // RHP_IKE_RESPONDER
			dhpub_i = ikesa->dh->get_peer_pub_key(ikesa->dh,&dhpub_i_len);
			dhpub_r = ikesa->dh->get_my_pub_key(ikesa->dh,&dhpub_r_len);
		}

		if( dhpub_i == NULL || dhpub_r == NULL ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		dhpubs_p = (u8*)_rhp_malloc(dhpub_i_len + dhpub_r_len);
		if( dhpubs_p == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
		memcpy(dhpubs_p,dhpub_i,dhpub_i_len);
		memcpy((dhpubs_p + dhpub_r_len),dhpub_r,dhpub_r_len);


		ikesa->keys.v1.p1_iv_dec = (u8*)_rhp_malloc(iv_hash_len);
		if( ikesa->keys.v1.p1_iv_dec == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		ikesa->keys.v1.p1_iv_rx_last_blk = (u8*)_rhp_malloc(iv_hash_len);
		if( ikesa->keys.v1.p1_iv_rx_last_blk == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		err = v1_hash->compute(v1_hash,dhpubs_p,(dhpub_i_len + dhpub_r_len),
				ikesa->keys.v1.p1_iv_rx_last_blk,iv_hash_len);
		if( err ){
			goto error;
		}

		// For responder's initial decryption.
		memcpy(ikesa->keys.v1.p1_iv_dec,ikesa->keys.v1.p1_iv_rx_last_blk,iv_hash_len);
	}


	dh_shared_key = ikesa->dh->get_shared_key(ikesa->dh,&dh_shared_key_len);
	if( dh_shared_key == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	err = ikesa->prf->set_key(ikesa->prf,skeyid,skeyid_len);
	if( err ){
		RHP_BUG("");
		goto error;
	}


	{
		skey_id_d_material_len = dh_shared_key_len + (RHP_PROTO_IKE_SPI_SIZE*2) + 1;

		skey_id_d_material = (u8*)_rhp_malloc(skey_id_d_material_len);
		if( skey_id_d_material == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		p = skey_id_d_material;
		memcpy(p,dh_shared_key,dh_shared_key_len);
		p += dh_shared_key_len;
		memcpy(p,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
		p += RHP_PROTO_IKE_SPI_SIZE;
		memcpy(p,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
		p += RHP_PROTO_IKE_SPI_SIZE;
		*p = 0;

		ikesa->keys.v1.skeyid_d_len = ikesa->prf->get_output_len(ikesa->prf);

		ikesa->keys.v1.skeyid_d = (u8*)_rhp_malloc(ikesa->keys.v1.skeyid_d_len);
		if( ikesa->keys.v1.skeyid_d == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}


		err = ikesa->prf->compute(ikesa->prf,skey_id_d_material,skey_id_d_material_len,
						ikesa->keys.v1.skeyid_d,ikesa->keys.v1.skeyid_d_len);
		if( err ){
			RHP_BUG("");
			goto error;
		}
	}

	{
		skey_id_a_material_len
		= ikesa->keys.v1.skeyid_d_len + dh_shared_key_len + (RHP_PROTO_IKE_SPI_SIZE*2) + 1;

		skey_id_a_material = (u8*)_rhp_malloc(skey_id_a_material_len);
		if( skey_id_a_material == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		p = skey_id_a_material;
		memcpy(p,ikesa->keys.v1.skeyid_d,ikesa->keys.v1.skeyid_d_len);
		p += ikesa->keys.v1.skeyid_d_len;
		memcpy(p,dh_shared_key,dh_shared_key_len);
		p += dh_shared_key_len;
		memcpy(p,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
		p += RHP_PROTO_IKE_SPI_SIZE;
		memcpy(p,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
		p += RHP_PROTO_IKE_SPI_SIZE;
		*p = 1;


		ikesa->keys.v1.skeyid_a_len = ikesa->prf->get_output_len(ikesa->prf);

		ikesa->keys.v1.skeyid_a = (u8*)_rhp_malloc(ikesa->keys.v1.skeyid_a_len);
		if( ikesa->keys.v1.skeyid_a == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}


		err = ikesa->prf->compute(ikesa->prf,skey_id_a_material,skey_id_a_material_len,
						ikesa->keys.v1.skeyid_a,ikesa->keys.v1.skeyid_a_len);
		if( err ){
			RHP_BUG("");
			goto error;
		}
	}

	{
		skey_id_e_material_len
		= ikesa->keys.v1.skeyid_a_len + dh_shared_key_len + (RHP_PROTO_IKE_SPI_SIZE*2) + 1;

		skey_id_e_material = (u8*)_rhp_malloc(skey_id_e_material_len);
		if( skey_id_e_material == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		p = skey_id_e_material;
		memcpy(p,ikesa->keys.v1.skeyid_a,ikesa->keys.v1.skeyid_a_len);
		p += ikesa->keys.v1.skeyid_a_len;
		memcpy(p,dh_shared_key,dh_shared_key_len);
		p += dh_shared_key_len;
		memcpy(p,ikesa->init_spi,RHP_PROTO_IKE_SPI_SIZE);
		p += RHP_PROTO_IKE_SPI_SIZE;
		memcpy(p,ikesa->resp_spi,RHP_PROTO_IKE_SPI_SIZE);
		p += RHP_PROTO_IKE_SPI_SIZE;
		*p = 2;


		ikesa->keys.v1.skeyid_e_len = ikesa->prf->get_output_len(ikesa->prf);

		ikesa->keys.v1.skeyid_e = (u8*)_rhp_malloc(ikesa->keys.v1.skeyid_e_len);
		if( ikesa->keys.v1.skeyid_e == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}


		err = ikesa->prf->compute(ikesa->prf,skey_id_e_material,skey_id_e_material_len,
						ikesa->keys.v1.skeyid_e,ikesa->keys.v1.skeyid_e_len);
		if( err ){
			RHP_BUG("");
			goto error;
		}
	}

	{
		int n, i;
		u8 sk_e_material_0 = 0;

		sk_e_len = ikesa->encr->get_key_len(ikesa->encr);

		if( sk_e_len > ikesa->keys.v1.skeyid_e_len ){

			n = (sk_e_len / ikesa->keys.v1.skeyid_e_len) + 1;

			ikesa->keys.v1.sk_e_len = sk_e_len;

			ikesa->keys.v1.sk_e = (u8*)_rhp_malloc(ikesa->keys.v1.skeyid_e_len*n);
			if( ikesa->keys.v1.sk_e == NULL ){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}

			err = ikesa->prf->set_key(ikesa->prf,ikesa->keys.v1.skeyid_e,ikesa->keys.v1.skeyid_e_len);
			if( err ){
				goto error;
			}

			p = ikesa->keys.v1.sk_e;

			for( i = 0; i < n; i++ ){

				int sk_e_material_len;
				u8* sk_e_material;

				if( i == 0 ){
					sk_e_material = &sk_e_material_0;
					sk_e_material_len = 1;
				}else{
					sk_e_material = p - ikesa->keys.v1.skeyid_e_len;
					sk_e_material_len = ikesa->keys.v1.skeyid_e_len;
				}

				err = ikesa->prf->compute(ikesa->prf,sk_e_material,sk_e_material_len,
								p,ikesa->keys.v1.skeyid_e_len);
				if( err ){
					RHP_BUG("");
					goto error;
				}

				p += ikesa->keys.v1.skeyid_e_len;
			}

		}else{

			ikesa->keys.v1.sk_e_len = sk_e_len;

			ikesa->keys.v1.sk_e = (u8*)_rhp_malloc(ikesa->keys.v1.skeyid_e_len);
			if( ikesa->keys.v1.sk_e == NULL ){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}

			memcpy(ikesa->keys.v1.sk_e,ikesa->keys.v1.skeyid_e,ikesa->keys.v1.skeyid_e_len);
		}
	}


	rhp_crypto_hash_free(v1_hash);
	_rhp_free(dhpubs_p);
	_rhp_free(skey_id_d_material);
	_rhp_free(skey_id_a_material);
	_rhp_free(skey_id_e_material);

  RHP_TRC(0,RHPTRCID_IKESA_GENERATE_KEYS_V1_RTRN,"xppppppp",ikesa,ikesa->keys.v1.iv_len,ikesa->keys.v1.p1_iv_dec,ikesa->keys.v1.iv_len,ikesa->keys.v1.p1_iv_rx_last_blk,ikesa->keys.v1.skeyid_len,ikesa->keys.v1.skeyid,ikesa->keys.v1.skeyid_d_len,ikesa->keys.v1.skeyid_d,ikesa->keys.v1.skeyid_a_len,ikesa->keys.v1.skeyid_a,ikesa->keys.v1.skeyid_e_len,ikesa->keys.v1.skeyid_e,ikesa->keys.v1.sk_e_len,ikesa->keys.v1.sk_e);
	return 0;

error:
	if( v1_hash ){
		rhp_crypto_hash_free(v1_hash);
	}
	if( dhpubs_p ){
		_rhp_free(dhpubs_p);
	}
	if( skey_id_d_material ){
		_rhp_free(skey_id_d_material);
	}
	if( skey_id_a_material ){
		_rhp_free(skey_id_a_material);
	}
	if( skey_id_e_material ){
		_rhp_free(skey_id_e_material);
	}
  RHP_TRC(0,RHPTRCID_IKESA_GENERATE_KEYS_V1_ERR,"xE",ikesa,err);
	return err;
}

static u8* _rhp_ikesa_get_my_spi(rhp_ikesa* ikesa)
{
  u8* my_spi;

  if( ikesa->side == RHP_IKE_INITIATOR ){
    my_spi = ikesa->init_spi;
  }else{
    my_spi = ikesa->resp_spi;
  }

  RHP_TRC(0,RHPTRCID_IKESA_GET_MY_SPI,"xLdG",ikesa,"IKE_SIDE",ikesa->side,my_spi);
  return my_spi;
}

static void _rhp_ikev2_set_retrans_reply(rhp_ikesa* ikesa,rhp_packet* pkt)
{
	RHP_TRC(0,RHPTRCID_IKEV2_SET_RETRANS_REPLY,"xxx",ikesa,ikesa->rep_retx_pkt,pkt);

	if( ikesa->rep_retx_pkt ){

		rhp_pkt_unhold(ikesa->rep_retx_pkt);
	}

	ikesa->rep_retx_pkt = pkt;
	if( pkt ){

		rhp_pkt_hold(pkt);
	}

  return;
}

static void _rhp_ikev1_set_retrans_reply(rhp_ikesa* ikesa,rhp_packet* pkt)
{
	RHP_TRC(0,RHPTRCID_IKEV1_SET_RETRANS_REPLY,"xxxd",ikesa,ikesa->v1.rep_retx_pkts.head,pkt,ikesa->v1.rep_retx_pkts_num);

	_rhp_pkt_q_enq(&(ikesa->v1.rep_retx_pkts),pkt);
	ikesa->v1.rep_retx_pkts_num++;
	rhp_pkt_hold(pkt);

	if( ikesa->v1.rep_retx_pkts_num > rhp_gcfg_ikev1_retx_pkts_num ){

		rhp_packet* del_pkt = _rhp_pkt_q_deq(&(ikesa->v1.rep_retx_pkts));
		if( del_pkt ){
			rhp_pkt_unhold(del_pkt);
			ikesa->v1.rep_retx_pkts_num--;
		}

		RHP_TRC(0,RHPTRCID_IKEV1_SET_RETRANS_REPLY_DROP_OLD_PKT,"xxxxx",ikesa,ikesa->v1.rep_retx_pkts.head,del_pkt,pkt);
	}

  return;
}

static void _rhp_ikev2_set_retrans_request(rhp_ikesa* ikesa,rhp_packet* pkt)
{
	RHP_TRC(0,RHPTRCID_IKEV2_SET_RETRANS_REQUEST,"xxx",ikesa,ikesa->req_retx_pkt,pkt);

	if( ikesa->req_retx_pkt ){

		rhp_pkt_unhold(ikesa->req_retx_pkt);
	}

	ikesa->req_retx_pkt = pkt;
	if( pkt ){

		rhp_pkt_hold(pkt);
	}

  return;
}


static void _rhp_ikesa_dump(rhp_ikesa* ikesa)
{
  RHP_TRC(0,RHPTRCID_IKESA_DUMP,"xLdLdGGdddd",ikesa,"IKESA_STAT",ikesa->state,"IKE_SIDE",ikesa->side,ikesa->init_spi,ikesa->resp_spi,ikesa->rekeyed_gen,ikesa->peer_is_rockhopper,ikesa->peer_rockhopper_ver,ikesa->busy_flag);
  return;
}

static void _rhp_ikev2_rx_clear_frag_q(rhp_packet_q* pkts_q)
{
	rhp_packet* pkt;

	while( (pkt = _rhp_pkt_q_deq(pkts_q)) ){
		rhp_pkt_unhold(pkt);
	}

	return;
}

static void _rhp_ikesa_reset_req_frag_pkts_q(rhp_ikesa* ikesa)
{
	_rhp_ikev2_rx_clear_frag_q(&(ikesa->rx_frag.req_pkts));
	ikesa->rx_frag.req_pkts_num = 0;
}

static void _rhp_ikesa_reset_rep_frag_pkts_q(rhp_ikesa* ikesa)
{
	_rhp_ikev2_rx_clear_frag_q(&(ikesa->rx_frag.rep_pkts));
	ikesa->rx_frag.rep_pkts_num = 0;
}

static rhp_ikesa* _rhp_ikesa_alloc(int side,int is_v1)
{
  rhp_ikesa* ikesa;

  ikesa = (rhp_ikesa*)_rhp_malloc(sizeof(rhp_ikesa));

  if( ikesa == NULL ){
    RHP_BUG("");
    return NULL;
  }
  memset(ikesa,0,sizeof(rhp_ikesa));

  ikesa->tag[0] = '#';
  ikesa->tag[1] = 'I';
  ikesa->tag[2] = 'S';
  ikesa->tag[3] = 'A';

  ikesa->side = side;
  rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DEFAULT);

  _rhp_pkt_q_init(&(ikesa->rx_frag.req_pkts));
  _rhp_pkt_q_init(&(ikesa->rx_frag.rep_pkts));

  ikesa->generate_init_spi = _rhp_ikesa_generate_init_spi;
  ikesa->generate_resp_spi = _rhp_ikesa_generate_resp_spi;
  ikesa->set_init_spi = _rhp_ikesa_set_init_spi;
  ikesa->set_resp_spi = _rhp_ikesa_set_resp_spi;
  ikesa->generate_keys = _rhp_ikesa_generate_keys;
  ikesa->generate_new_keys = _rhp_ikesa_generate_new_keys;
  ikesa->generate_keys_v1 = _rhp_ikesa_generate_keys_v1;
  ikesa->set_retrans_request = _rhp_ikev2_set_retrans_request;
  if( !is_v1 ){
  	ikesa->set_retrans_reply = _rhp_ikev2_set_retrans_reply;
  }else{
  	ikesa->set_retrans_reply = _rhp_ikev1_set_retrans_reply;
  }
  ikesa->reset_req_frag_pkts_q = _rhp_ikesa_reset_req_frag_pkts_q;
  ikesa->reset_rep_frag_pkts_q = _rhp_ikesa_reset_rep_frag_pkts_q;


  ikesa->dump = _rhp_ikesa_dump;

  ikesa->req_message_id = (u32)-1;

  ikesa->get_my_spi = _rhp_ikesa_get_my_spi;

  ikesa->created_time = _rhp_get_time();

	if( side == RHP_IKE_INITIATOR ){
		rhp_ikev2_g_statistics_inc(dc.ikesa_initiator_num);
	}else{
		rhp_ikev2_g_statistics_inc(dc.ikesa_responder_num);
	}


	_rhp_pkt_q_init(&(ikesa->v1.rep_retx_pkts));


  RHP_TRC(0,RHPTRCID_IKESA_ALLOC,"ddx",side,is_v1,ikesa);
  return ikesa;
}

static void _rhp_ikesa_free(rhp_ikesa* ikesa)
{
  RHP_TRC(0,RHPTRCID_IKESA_FREE,"x",ikesa);

  if( ikesa->pend_rx_ikemesg ){
  	rhp_ikev2_unhold_mesg(ikesa->pend_rx_ikemesg);
  }

  if( ikesa->pend_tx_ikemesg ){
  	rhp_ikev2_unhold_mesg(ikesa->pend_tx_ikemesg);
  }

  if( ikesa->req_retx_ikemesg ){
  	rhp_ikev2_unhold_mesg(ikesa->req_retx_ikemesg);
  }

  if( ikesa->eap.pend_rx_ikemesg ){
  	rhp_ikev2_unhold_mesg(ikesa->eap.pend_rx_ikemesg);
  }

  if( ikesa->eap.pend_mesg_octets_i ){
  	_rhp_free(ikesa->eap.pend_mesg_octets_i);
  }

  if( ikesa->eap.pend_mesg_octets_r ){
  	_rhp_free(ikesa->eap.pend_mesg_octets_r);
  }

  if( ikesa->v1.sai_b ){
  	_rhp_free(ikesa->v1.sai_b);
  }

  if( ikesa->v1.p1_exchange_mode ){

  	if( ikesa->keys.v1.skeyid ){
  		_rhp_free(ikesa->keys.v1.skeyid);
  	}
  	if( ikesa->keys.v1.skeyid_d ){
  		_rhp_free(ikesa->keys.v1.skeyid_d);
  	}
  	if( ikesa->keys.v1.skeyid_a ){
  		_rhp_free(ikesa->keys.v1.skeyid_a);
  	}
  	if( ikesa->keys.v1.skeyid_e ){
  		_rhp_free(ikesa->keys.v1.skeyid_e);
  	}
  	if( ikesa->keys.v1.sk_e ){
  		_rhp_free(ikesa->keys.v1.sk_e);
  	}
  	if( ikesa->keys.v1.p1_iv_dec ){
  		_rhp_free(ikesa->keys.v1.p1_iv_dec);
  	}
  	if( ikesa->keys.v1.p1_iv_rx_last_blk ){
  		_rhp_free(ikesa->keys.v1.p1_iv_rx_last_blk);
  	}

  	if( ikesa->v1.rx_psk_hash ){
  		_rhp_free(ikesa->v1.rx_psk_hash);
  	}
  }

  if( ikesa->v1.p2_iv_material ){
  	_rhp_free(ikesa->v1.p2_iv_material);
  }

  if( ikesa->v1.rx_ca_dn_ders ){
  	_rhp_free(ikesa->v1.rx_ca_dn_ders);
  }

  {
  	rhp_ikev1_p2_session* p2_sess = ikesa->v1.p2_sessions;

  	while( p2_sess ){

  		rhp_ikev1_p2_session* p2_sess_n = p2_sess->next;

  		rhp_ikev1_p2_session_free(p2_sess);

  		p2_sess = p2_sess_n;
  	}
  }

  if( ikesa->v1.mode_cfg_pending_pkt_ref ){
  	rhp_pkt_unhold(ikesa->v1.mode_cfg_pending_pkt_ref);
  }


  if( ikesa->dh ){
    rhp_crypto_dh_free(ikesa->dh);
  }

  if( ikesa->nonce_i ){
    rhp_crypto_nonce_free(ikesa->nonce_i);
  }

  if( ikesa->nonce_r ){
    rhp_crypto_nonce_free(ikesa->nonce_r);
  }

  if( ikesa->encr ){
    rhp_crypto_encr_free(ikesa->encr);
  }

  if( ikesa->prf ){
    rhp_crypto_prf_free(ikesa->prf);
  }

  if( ikesa->integ_i ){
    rhp_crypto_integ_free(ikesa->integ_i);
  }

  if( ikesa->integ_r ){
    rhp_crypto_integ_free(ikesa->integ_r);
  }

  if( ikesa->signed_octets.ikemesg_i_1st ){
  	rhp_ikev2_unhold_mesg(ikesa->signed_octets.ikemesg_i_1st);
  }

  if( ikesa->signed_octets.ikemesg_r_2nd ){
  	rhp_ikev2_unhold_mesg(ikesa->signed_octets.ikemesg_r_2nd);
  }

  if( ikesa->key_material.key_octets ){
    _rhp_free_zero(ikesa->key_material.key_octets,ikesa->key_material.len);
  }

  if( ikesa->cookies.cookie ){
    _rhp_free(ikesa->cookies.cookie);
  }

  {
  	rhp_packet* pkt;

  	 if( ikesa->req_retx_pkt ){
  		 rhp_pkt_unhold(ikesa->req_retx_pkt);
  	 }

  	 if( ikesa->rep_retx_pkt ){
  		 rhp_pkt_unhold(ikesa->rep_retx_pkt);
  	 }

  	 while( (pkt = _rhp_pkt_q_deq(&(ikesa->rx_frag.req_pkts))) ){
  		 rhp_pkt_unhold(pkt);
  	 }

  	 while( (pkt = _rhp_pkt_q_deq(&(ikesa->rx_frag.rep_pkts))) ){
  		 rhp_pkt_unhold(pkt);
  	 }

  	 while( (pkt = _rhp_pkt_q_deq(&(ikesa->v1.rep_retx_pkts))) ){
  		 rhp_pkt_unhold(pkt);
  	 }
  }

  {
		if( ikesa->qcd.peer_token ){
			_rhp_free_zero(ikesa->qcd.peer_token,ikesa->qcd.peer_token_len);
		}

		if( ikesa->qcd.pend_rx_ikemesg ){
			rhp_ikev2_unhold_mesg(ikesa->qcd.pend_rx_ikemesg);
		}

		if( ikesa->qcd.pend_tx_ikemesg ){
			rhp_ikev2_unhold_mesg(ikesa->qcd.pend_tx_ikemesg);
		}
  }

  {
		if( ikesa->sess_resume.resp.pend_rx_ikemesg ){
			rhp_ikev2_unhold_mesg(ikesa->sess_resume.resp.pend_rx_ikemesg);
		}

		if( ikesa->sess_resume.resp.pend_tx_ikemesg ){
			rhp_ikev2_unhold_mesg(ikesa->sess_resume.resp.pend_tx_ikemesg);
		}

		if( ikesa->sess_resume.resp.dec_tkt_ipc_rep ){
			_rhp_free_zero(ikesa->sess_resume.resp.dec_tkt_ipc_rep,ikesa->sess_resume.resp.dec_tkt_ipc_rep->len);
		}
  }

	if( ikesa->side == RHP_IKE_INITIATOR ){
		rhp_ikev2_g_statistics_dec(dc.ikesa_initiator_num);
	}else{
		rhp_ikev2_g_statistics_dec(dc.ikesa_responder_num);
	}

  _rhp_free_zero(ikesa,sizeof(rhp_ikesa));

  RHP_TRC(0,RHPTRCID_IKESA_FREE_RTRN,"x",ikesa);
  return;
}

static int _rhp_ikesa_top_dhgrp()
{
  int err = -ENOENT;
  rhp_cfg_ikesa* cfg_ikesa;
  int dhgrp;

  RHP_LOCK(&rhp_cfg_lock);

  cfg_ikesa = rhp_cfg_get_ikesa_security();

  if( cfg_ikesa == NULL ){
    RHP_BUG("");
    err = -ENOENT;
    goto error;
  }

  if( cfg_ikesa->dh_trans_list == NULL ){
    err = -ENOENT;
    RHP_BUG("");
    goto error;
  }

  dhgrp = cfg_ikesa->dh_trans_list->id;

  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_IKESA_TOP_DHGRP,"d",dhgrp);
  return dhgrp;

error:
  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_IKESA_TOP_DHGRP_ERR,"E",err);
  return err;
}

int rhp_ikesa_v1_top_dhgrp()
{
  int err = -ENOENT;
  rhp_cfg_ikev1_ikesa* cfg_ikesa;
  int dhgrp;

  RHP_LOCK(&rhp_cfg_lock);

  cfg_ikesa = rhp_cfg_ikev1_get_ikesa_security();

  if( cfg_ikesa == NULL ){
    RHP_BUG("");
    err = -ENOENT;
    goto error;
  }

  if( cfg_ikesa->trans_list == NULL ){
    err = -ENOENT;
    RHP_BUG("");
    goto error;
  }

  dhgrp = cfg_ikesa->trans_list->dh_group;

  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_IKESA_V1_TOP_DHGRP,"d",dhgrp);
  return dhgrp;

error:
  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_IKESA_V1_TOP_DHGRP_ERR,"E",err);
  return err;
}

// rlm->lock need be acquired by RHP_LOCK(). Caller must release ikesa->refcnt returend by this func.
rhp_ikesa* rhp_ikesa_new_i(rhp_vpn_realm* rlm,rhp_cfg_peer* cfg_peer,u16 dhgrp_id)
{
  rhp_ikesa* ikesa = NULL;
  int dhgrp;

  RHP_TRC(0,RHPTRCID_IKESA_NEW_I,"xdxw",rlm,rlm->id,cfg_peer,dhgrp_id);

  ikesa = _rhp_ikesa_alloc(RHP_IKE_INITIATOR,0);
  if( ikesa == NULL ){
    goto error;
  }


  if( ikesa->generate_init_spi(ikesa) ){
    RHP_TRC(0,RHPTRCID_IKESA_NEW_I_GENERATE_INIT_SPI_ERR,"xxx",rlm,cfg_peer,ikesa);
    goto error;
  }

  if( dhgrp_id ){

    dhgrp = dhgrp_id;

  }else{

    dhgrp = _rhp_ikesa_top_dhgrp();
    if( dhgrp < 0 ){
    	RHP_BUG("");
    	goto error;
    }
  }

  ikesa->dh = rhp_crypto_dh_alloc(dhgrp);
  if( ikesa->dh == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  if( ikesa->dh->generate_key(ikesa->dh) ){
  	RHP_BUG("");
  	goto error;
  }

  ikesa->nonce_i = rhp_crypto_nonce_alloc();
  if( ikesa->nonce_i == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  if( ikesa->nonce_i->generate_nonce(ikesa->nonce_i,rhp_gcfg_nonce_size) ){
  	RHP_BUG("");
  	goto error;
  }

  ikesa->nonce_r = rhp_crypto_nonce_alloc();
  if( ikesa->nonce_r == NULL ){
  	RHP_BUG("");
  	goto error;
  }


  RHP_TRC(0,RHPTRCID_IKESA_NEW_I_RTRN,"x",ikesa);
  return ikesa;

error:
  if( ikesa ){
    _rhp_ikesa_free(ikesa);
  }

  RHP_TRC(0,RHPTRCID_IKESA_NEW_I_ERR,"");
  return NULL;
}

// rlm->lock need be acquired by RHP_LOCK(). Caller must release ikesa->refcnt returend by this func.
rhp_ikesa* rhp_ikesa_v1_main_new_i(rhp_vpn_realm* rlm,rhp_cfg_peer* cfg_peer)
{
  rhp_ikesa* ikesa = NULL;

  RHP_TRC(0,RHPTRCID_IKESA_V1_MAIN_NEW_I,"xdx",rlm,rlm->id,cfg_peer);

  ikesa = _rhp_ikesa_alloc(RHP_IKE_INITIATOR,1);
  if( ikesa == NULL ){
    goto error;
  }

  if( ikesa->generate_init_spi(ikesa) ){
    RHP_TRC(0,RHPTRCID_IKESA_V1_MAIN_NEW_I_GENERATE_INIT_SPI_ERR,"xxx",rlm,cfg_peer,ikesa);
    goto error;
  }

  ikesa->auth_method = rlm->my_auth.my_auth_method;
  ikesa->peer_auth_method = rlm->my_auth.my_auth_method;

  ikesa->v1.lifetime = rlm->ikesa.lifetime_hard;

	ikesa->v1.p1_exchange_mode = RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION;


	ikesa->timers = rhp_ikesa_v1_new_timers(RHP_IKE_INITIATOR,ikesa->init_spi);
	if( ikesa->timers == NULL ){
    RHP_TRC(0,RHPTRCID_IKESA_V1_MAIN_NEW_I_ALLOC_TIMERS_ERR,"xxx",rlm,cfg_peer,ikesa);
    goto error;
	}

  {
  	u32 dpd_seq;

		if( rhp_random_bytes((u8*)&dpd_seq,sizeof(u32)) ){
			RHP_BUG("");
			goto error;
		}

		ikesa->v1.dpd_seq = dpd_seq & 0x7FFFFFFF;
  }

  RHP_TRC(0,RHPTRCID_IKESA_V1_MAIN_NEW_I_RTRN,"x",ikesa);
  return ikesa;

error:
  if( ikesa ){
    _rhp_ikesa_free(ikesa);
  }

  RHP_TRC(0,RHPTRCID_IKESA_V1_MAIN_NEW_I_ERR,"");
  return NULL;
}

// rlm->lock need be acquired by RHP_LOCK(). Caller must release ikesa->refcnt returend by this func.
rhp_ikesa* rhp_ikesa_v1_aggressive_new_i(rhp_vpn_realm* rlm,rhp_cfg_peer* cfg_peer,u16 dhgrp_id)
{
  rhp_ikesa* ikesa = NULL;
  int dhgrp;

  RHP_TRC(0,RHPTRCID_IKESA_V1_AGGRESSIVE_NEW_I,"xdxw",rlm,rlm->id,cfg_peer,dhgrp_id);

  ikesa = _rhp_ikesa_alloc(RHP_IKE_INITIATOR,1);
  if( ikesa == NULL ){
    goto error;
  }

  if( ikesa->generate_init_spi(ikesa) ){
    RHP_TRC(0,RHPTRCID_IKESA_V1_AGGRESSIVE_NEW_I_GENERATE_INIT_SPI_ERR,"xxx",rlm,cfg_peer,ikesa);
    goto error;
  }

  ikesa->auth_method = rlm->my_auth.my_auth_method;
  ikesa->peer_auth_method = rlm->my_auth.my_auth_method;

  ikesa->v1.lifetime = rlm->ikesa.lifetime_hard;

	ikesa->v1.p1_exchange_mode = RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE;


  if( dhgrp_id ){

    dhgrp = dhgrp_id;

  }else{

    dhgrp = rhp_ikesa_v1_top_dhgrp();
    if( dhgrp < 0 ){
    	RHP_BUG("");
    	goto error;
    }
  }

  ikesa->dh = rhp_crypto_dh_alloc(dhgrp);
  if( ikesa->dh == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  if( ikesa->dh->generate_key(ikesa->dh) ){
  	RHP_BUG("");
  	goto error;
  }

  ikesa->nonce_i = rhp_crypto_nonce_alloc();
  if( ikesa->nonce_i == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  if( ikesa->nonce_i->generate_nonce(ikesa->nonce_i,rhp_gcfg_nonce_size) ){
  	RHP_BUG("");
  	goto error;
  }

  ikesa->nonce_r = rhp_crypto_nonce_alloc();
  if( ikesa->nonce_r == NULL ){
  	RHP_BUG("");
  	goto error;
  }

	ikesa->timers = rhp_ikesa_v1_new_timers(RHP_IKE_INITIATOR,ikesa->init_spi);
	if( ikesa->timers == NULL ){
    RHP_TRC(0,RHPTRCID_IKESA_V1_AGGRESSIVE_NEW_I_ALLOC_TIMERS_ERR,"xxx",rlm,cfg_peer,ikesa);
    goto error;
	}

  {
  	u32 dpd_seq;

		if( rhp_random_bytes((u8*)&dpd_seq,sizeof(u32)) ){
			RHP_BUG("");
			goto error;
		}

		ikesa->v1.dpd_seq = dpd_seq & 0x7FFFFFFF;
  }

  RHP_TRC(0,RHPTRCID_IKESA_V1_AGGRESSIVE_NEW_I_RTRN,"x",ikesa);
  return ikesa;

error:
  if( ikesa ){
    _rhp_ikesa_free(ikesa);
  }

  RHP_TRC(0,RHPTRCID_IKESA_V1_AGGRESSIVE_NEW_I_ERR,"");
  return NULL;
}


int rhp_ikesa_r_init_params_bh(rhp_ikesa* ikesa,rhp_res_sa_proposal* res_prop)
{
	int err = -EINVAL;
  RHP_TRC(0,RHPTRCID_IKESA_R_SETUP_PARAMS_BH,"xx",ikesa,res_prop);

  if( ikesa->dh == NULL ){

  	ikesa->dh = rhp_crypto_dh_alloc(res_prop->dhgrp_id);
  	if( ikesa->dh == NULL ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}
  }

  ikesa->nonce_r = rhp_crypto_nonce_alloc();
  if( ikesa->nonce_r == NULL ){
		err = -EINVAL;
  	RHP_BUG("");
  	goto error;
  }

  if( ikesa->nonce_r->generate_nonce(ikesa->nonce_r,rhp_gcfg_nonce_size) ){
		err = -EINVAL;
  	RHP_BUG("");
  	goto error;
  }


  RHP_TRC(0,RHPTRCID_IKESA_R_SETUP_PARAMS_BH_RTRN,"xx",ikesa,res_prop);
  return 0;

error:
  RHP_TRC(0,RHPTRCID_IKESA_R_SETUP_PARAMS_BH_ERR,"xxE",ikesa,res_prop,err);
  return err;
}

rhp_ikesa* rhp_ikesa_new_r(rhp_res_sa_proposal* res_prop)
{
	int err = -EINVAL;
  rhp_ikesa* ikesa = NULL;

  RHP_TRC(0,RHPTRCID_IKESA_NEW_R,"x",res_prop);

  ikesa = _rhp_ikesa_alloc(RHP_IKE_RESPONDER,0);
  if( ikesa == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  if( ikesa->generate_resp_spi(ikesa) ){
  	RHP_BUG("");
  	goto error;
  }

  ikesa->nonce_i = rhp_crypto_nonce_alloc();
  if( ikesa->nonce_i == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  if( res_prop ){

  	ikesa->dh = rhp_crypto_dh_alloc(res_prop->dhgrp_id);
  	if( ikesa->dh == NULL ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}

  	if( ikesa->dh->generate_key(ikesa->dh) ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}

  	err = rhp_ikesa_r_init_params_bh(ikesa,res_prop);
		if( err ){
			goto error;
		}
  }

  RHP_TRC(0,RHPTRCID_IKESA_NEW_R_RTRN,"xx",res_prop,ikesa);
  return ikesa;

error:
  if( ikesa ){
    _rhp_ikesa_free(ikesa);
  }
  RHP_TRC(0,RHPTRCID_IKESA_NEW_R_ERR,"x",res_prop);
  return NULL;
}

rhp_ikesa* rhp_ikesa_v1_main_new_r(rhp_res_ikev1_sa_proposal* res_prop)
{
  rhp_ikesa* ikesa = NULL;

  RHP_TRC(0,RHPTRCID_IKESA_V1_MAIN_NEW_R,"x",res_prop);

  ikesa = _rhp_ikesa_alloc(RHP_IKE_RESPONDER,1);
  if( ikesa == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  if( ikesa->generate_resp_spi(ikesa) ){
  	RHP_BUG("");
  	goto error;
  }

  ikesa->auth_method = res_prop->auth_method;

  if( res_prop->xauth_method == RHP_PROTO_IKE_AUTHMETHOD_HYBRID_INIT_RSASIG ){
  	ikesa->peer_auth_method = RHP_PROTO_IKE_AUTHMETHOD_NONE;
  }else{
  	ikesa->peer_auth_method = res_prop->auth_method;
  }

	ikesa->v1.p1_exchange_mode = RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION;

  memcpy(&(ikesa->prop.v1),res_prop,sizeof(rhp_res_ikev1_sa_proposal));


  ikesa->timers = rhp_ikesa_v1_new_timers(RHP_IKE_RESPONDER,ikesa->resp_spi);
  if( ikesa->timers == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  {
  	u32 dpd_seq;

		if( rhp_random_bytes((u8*)&dpd_seq,sizeof(u32)) ){
			RHP_BUG("");
			goto error;
		}

		ikesa->v1.dpd_seq = dpd_seq & 0x7FFFFFFF;
  }

  RHP_TRC(0,RHPTRCID_IKESA_V1_MAIN_NEW_R_RTRN,"xx",res_prop,ikesa);
  return ikesa;

error:
  if( ikesa ){
    _rhp_ikesa_free(ikesa);
  }
  RHP_TRC(0,RHPTRCID_IKESA_V1_MAIN_NEW_R_ERR,"x",res_prop);
  return NULL;
}

rhp_ikesa* rhp_ikesa_v1_aggressive_new_r(rhp_res_ikev1_sa_proposal* res_prop)
{
  rhp_ikesa* ikesa = NULL;

  RHP_TRC(0,RHPTRCID_IKESA_V1_AGGRESSIVE_NEW_R,"x",res_prop);

  ikesa = _rhp_ikesa_alloc(RHP_IKE_RESPONDER,1);
  if( ikesa == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  if( ikesa->generate_resp_spi(ikesa) ){
  	RHP_BUG("");
  	goto error;
  }

  ikesa->auth_method = res_prop->auth_method;
  ikesa->peer_auth_method = res_prop->auth_method;

	ikesa->v1.p1_exchange_mode = RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE;

  memcpy(&(ikesa->prop.v1),res_prop,sizeof(rhp_res_ikev1_sa_proposal));


  ikesa->timers = rhp_ikesa_v1_new_timers(RHP_IKE_RESPONDER,ikesa->resp_spi);
  if( ikesa->timers == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  {
  	int prf_alg, encr_alg;

    ikesa->dh = rhp_crypto_dh_alloc(ikesa->prop.v1.dh_group);
    if( ikesa->dh == NULL ){
    	RHP_BUG("");
    	goto error;
    }

    if( ikesa->dh->generate_key(ikesa->dh) ){
    	RHP_BUG("");
    	goto error;
    }


    ikesa->nonce_i = rhp_crypto_nonce_alloc();
    if( ikesa->nonce_i == NULL ){
    	RHP_BUG("");
    	goto error;
    }


    ikesa->nonce_r = rhp_crypto_nonce_alloc();
    if( ikesa->nonce_r == NULL ){
    	RHP_BUG("");
    	goto error;
    }

    if( ikesa->nonce_r->generate_nonce(ikesa->nonce_r,rhp_gcfg_nonce_size) ){
    	RHP_BUG("");
    	goto error;
    }


    prf_alg = rhp_ikev1_p1_prf_alg(ikesa->prop.v1.hash_alg);
    if( prf_alg < 0 ){
    	RHP_BUG("");
    	goto error;
    }

    encr_alg = rhp_ikev1_p1_encr_alg(ikesa->prop.v1.enc_alg);
    if( encr_alg < 0 ){
    	RHP_BUG("");
    	goto error;
    }


    ikesa->prf = rhp_crypto_prf_alloc(prf_alg);
    if( ikesa->prf == NULL ){
      RHP_BUG("");
      goto error;
    }

    ikesa->encr = rhp_crypto_encr_alloc(encr_alg,ikesa->prop.v1.key_bits_len);
    if( ikesa->encr == NULL ){
      RHP_BUG("");
      goto error;
    }
  }

  {
  	u32 dpd_seq;

		if( rhp_random_bytes((u8*)&dpd_seq,sizeof(u32)) ){
			RHP_BUG("");
			goto error;
		}

		ikesa->v1.dpd_seq = dpd_seq & 0x7FFFFFFF;
  }

  RHP_TRC(0,RHPTRCID_IKESA_V1_AGGRESSIVE_NEW_R_RTRN,"xx",res_prop,ikesa);
  return ikesa;

error:
  if( ikesa ){
    _rhp_ikesa_free(ikesa);
  }
  RHP_TRC(0,RHPTRCID_IKESA_V1_AGGRESSIVE_NEW_R_ERR,"x",res_prop);
  return NULL;
}


void rhp_ikesa_init_i_put(rhp_ikesa_init_i* init_i,u32* hval_r)
{
  u32 hval;

  RHP_TRC(0,RHPTRCID_IKESA_INIT_I_PUT,"xxp",init_i,hval_r,init_i->ike_sa_init_i_len,init_i->ike_sa_init_i);

  hval = _rhp_hash_bytes(init_i->ike_sa_init_i,init_i->ike_sa_init_i_len,_rhp_ikesa_init_i_hashtbl_rnd);
  hval = hval % RHP_IKESA_HASH_TABLE_SIZE;

  init_i->ike_init_i_hash = hval;

  RHP_LOCK(&rhp_vpn_lock);

  init_i->next_hash = _rhp_ikesa_init_i_hashtbl[hval];
  _rhp_ikesa_init_i_hashtbl[hval] = init_i;

  RHP_UNLOCK(&rhp_vpn_lock);

  *hval_r = init_i->ike_init_i_hash;

  RHP_TRC(0,RHPTRCID_IKESA_INIT_I_PUT_RTRN,"xk",init_i,*hval_r);
  return;
}

rhp_ikesa_init_i* rhp_ikesa_init_i_delete(u8* my_resp_spi,u32 hval)
{
  rhp_ikesa_init_i* tmp;
  rhp_ikesa_init_i* tmp2 = NULL;

  RHP_TRC(0,RHPTRCID_IKESA_INIT_I_DELETE,"Gx",my_resp_spi,hval);

  RHP_LOCK(&rhp_vpn_lock);

  hval = hval % RHP_IKESA_HASH_TABLE_SIZE;

  tmp = _rhp_ikesa_init_i_hashtbl[hval];

  while( tmp ){
    if( !memcmp(my_resp_spi,tmp->my_resp_spi,RHP_PROTO_IKE_SPI_SIZE) ){
      break;
    }
    tmp2 = tmp;
    tmp = tmp->next_hash;
  }

  if( tmp ){

    if( tmp2 ){
      tmp2->next_hash = tmp->next_hash;
    }else{
      _rhp_ikesa_init_i_hashtbl[hval] = tmp->next_hash;
    }
    tmp->next_hash = NULL;

  }else{
    RHP_TRC(0,RHPTRCID_IKESA_INIT_I_DELETE_NOT_FOUND,"Gx",my_resp_spi,hval);
  }

  RHP_UNLOCK(&rhp_vpn_lock);

  RHP_TRC(0,RHPTRCID_IKESA_INIT_I_DELETE_RTRN,"Gx",my_resp_spi,tmp);
  return tmp;
}


int rhp_ikesa_pkt_hash(rhp_packet* pkt,u32* hval_r,u8** head_r,int* len_r)
{
  u8* head;
  int len;

  head = pkt->l3.raw;
  len = pkt->tail - pkt->l3.raw;

  if( len <= 0 ){
    RHP_BUG("");
    return -EINVAL;
  }

  *hval_r = _rhp_hash_bytes(head,len,_rhp_ikesa_init_i_hashtbl_rnd);

  if( head_r ){
  	*head_r = head;
  	*len_r = len;
  }

  RHP_TRC(0,RHPTRCID_IKESA_PKT_HASH,"xpk",pkt,len,head,*hval_r);
  return 0;
}

int rhp_ikesa_pkt_hash_v1(rhp_packet* pkt,u8** hval_r,int* hval_len_r,u8** head_r,int* len_r)
{
  u8* head;
  int len;

  head = pkt->l3.raw;
  len = pkt->tail - pkt->l3.raw;

  if( len <= 0 ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( rhp_crypto_md(RHP_CRYPTO_MD_SHA1,head,len,hval_r,hval_len_r) ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  if( head_r ){
  	*head_r = head;
  	*len_r = len;
  }

  RHP_TRC(0,RHPTRCID_IKESA_PKT_HASH_V1,"xpp",pkt,len,head,*hval_len_r,*hval_r);
  return 0;
}


int rhp_ikesa_init_i_get(rhp_packet* pkt_i,u8* my_resp_spi)
{
	int err = -EINVAL;
	u8* head;
	int len;
  u32 hval;
  rhp_ikesa_init_i* init_i = NULL;

  RHP_TRC(0,RHPTRCID_IKESA_INIT_I_GET,"x",pkt_i);

  err = rhp_ikesa_pkt_hash(pkt_i,&hval,&head,&len);
  if( err ){
  	return err;
  }
  hval = hval % RHP_IKESA_HASH_TABLE_SIZE;


  RHP_LOCK(&rhp_vpn_lock);

  init_i = _rhp_ikesa_init_i_hashtbl[hval];

  while( init_i ){

    if( len == init_i->ike_sa_init_i_len && init_i->ike_init_i_hash == hval ){

      if( pkt_i->type == RHP_PKT_IPV4_IKE ){
      	RHP_TRC_FREQ(0,RHPTRCID_IKESA_INIT_I_GET_V4,"x44WWpp",pkt_i,init_i->peer_addr.addr.v4,pkt_i->l3.iph_v4->src_addr,init_i->peer_addr.port,pkt_i->l4.udph->src_port,len,head,len,init_i->ike_sa_init_i);
      }else if( pkt_i->type == RHP_PKT_IPV6_IKE ){
      	RHP_TRC_FREQ(0,RHPTRCID_IKESA_INIT_I_GET_V6,"x66WWpp",pkt_i,init_i->peer_addr.addr.v6,pkt_i->l3.iph_v6->src_addr,init_i->peer_addr.port,pkt_i->l4.udph->src_port,len,head,len,init_i->ike_sa_init_i);
      }else{
        RHP_BUG("%d",pkt_i->type);
      }

      if( ((pkt_i->type == RHP_PKT_IPV4_IKE &&
      		  init_i->peer_addr.addr_family == AF_INET &&
      		  init_i->peer_addr.addr.v4 == pkt_i->l3.iph_v4->src_addr) ||
      		 (pkt_i->type == RHP_PKT_IPV6_IKE &&
         		init_i->peer_addr.addr_family == AF_INET6 &&
      			rhp_ipv6_is_same_addr(init_i->peer_addr.addr.v6,pkt_i->l3.iph_v6->src_addr))) &&
          (init_i->peer_addr.port == pkt_i->l4.udph->src_port) &&
          !memcmp(head,init_i->ike_sa_init_i,len) ){

      	break;
      }

    }else{

    	RHP_TRC_FREQ(0,RHPTRCID_IKESA_INIT_I_GET_DBG1,"xddkk",pkt_i,len,init_i->ike_sa_init_i_len,init_i->ike_init_i_hash,hval);
    }

    init_i = init_i->next_hash;
  }

  if( init_i ){

  	if( my_resp_spi ){
  		memcpy(my_resp_spi,init_i->my_resp_spi,RHP_PROTO_IKE_SPI_SIZE);
  	}
  	err = 0;

  	RHP_TRC(0,RHPTRCID_IKESA_INIT_I_GET_RTRN,"xxkpG",pkt_i,init_i,hval,len,head,init_i->my_resp_spi);
  	rhp_ip_addr_dump("init_i->peer_addr",&(init_i->peer_addr));

  }else{
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_IKESA_INIT_I_GET_NOT_FOUND,"xxkp",pkt_i,init_i,hval,len,head);
  }

  RHP_UNLOCK(&rhp_vpn_lock);

  return err;
}

rhp_ikesa_init_i* rhp_ikesa_alloc_init_i(u8* my_resp_spi,rhp_ip_addr* peer_addr,rhp_ikev2_mesg* rx_ikemesg)
{
  u8* head = rx_ikemesg->rx_pkt->l3.raw;
  int len = rx_ikemesg->rx_pkt->tail - rx_ikemesg->rx_pkt->l3.raw;
  rhp_ikesa_init_i* init_i = NULL;

  RHP_TRC(0,RHPTRCID_IKESA_ALLOC_INIT_I,"Gxxxp",my_resp_spi,peer_addr,rx_ikemesg,rx_ikemesg->rx_pkt,len,head);
  rhp_ip_addr_dump("peer_addr",peer_addr);

  init_i = (rhp_ikesa_init_i*)_rhp_malloc(sizeof(rhp_ikesa_init_i));
  if( init_i == NULL ){
    RHP_BUG("");
    return NULL;
  }
  memset(init_i,0,sizeof(rhp_ikesa_init_i));

  init_i->ike_sa_init_i = (u8*)_rhp_malloc(len);
  if( init_i->ike_sa_init_i == NULL ){
    RHP_BUG("");
    _rhp_free(init_i);
    return NULL;
  }

  init_i->tag[0] = '#';
  init_i->tag[1] = 'I';
  init_i->tag[2] = 'I';
  init_i->tag[3] = 'I';

  init_i->ike_sa_init_i_len = len;
  memcpy(init_i->ike_sa_init_i,head,len);

  memcpy(&(init_i->peer_addr),peer_addr,sizeof(rhp_ip_addr));

  memcpy(init_i->my_resp_spi,my_resp_spi,RHP_PROTO_IKE_SPI_SIZE);

	rhp_ikev2_g_statistics_inc(ikesa_responder_exchg_started);

  RHP_TRC(0,RHPTRCID_IKESA_ALLOC_INIT_I_RTRN,"Gxxxxp",my_resp_spi,peer_addr,rx_ikemesg,rx_ikemesg->rx_pkt,init_i,init_i->ike_sa_init_i_len,init_i->ike_sa_init_i);
  return init_i;
}

void rhp_ikesa_free_init_i(rhp_ikesa_init_i* init_i)
{
  if( init_i->ike_sa_init_i ){
    _rhp_free(init_i->ike_sa_init_i);
  }
  _rhp_free(init_i);

  RHP_TRC(0,RHPTRCID_IKESA_FREE_INIT_I,"x",init_i);
  return;
}


void rhp_ikesa_destroy(rhp_vpn* vpn,rhp_ikesa* ikesa)
{
  u8* my_spi;
  rhp_ikesa_init_i* init_i;

  RHP_TRC(0,RHPTRCID_IKESA_DESTROY,"xx",vpn,ikesa);

  my_spi = ikesa->get_my_spi(ikesa);

  if( ikesa->timers ){

  	ikesa->timers->quit_lifetime_timer(vpn,ikesa);

  	ikesa->timers->quit_retransmit_timer(vpn,ikesa);

  	ikesa->timers->quit_keep_alive_timer(vpn,ikesa);

  	ikesa->timers->quit_nat_t_keep_alive_timer(vpn,ikesa);

  	_rhp_free(ikesa->timers);
  }

  {
  	rhp_ip_addr my_addr;

  	memset(&my_addr,0,sizeof(rhp_ip_addr));
  	my_addr.addr_family = vpn->local.if_info.addr_family;
  	memcpy(my_addr.addr.raw,vpn->local.if_info.addr.raw,16);

		rhp_vpn_ikesa_v1_spi_delete(&my_addr,&(vpn->peer_addr),ikesa->side,
				(ikesa->side == RHP_IKE_RESPONDER ? ikesa->resp_spi : ikesa->init_spi),
				(ikesa->side == RHP_IKE_RESPONDER ? ikesa->init_spi : ikesa->resp_spi));
  }

  init_i = rhp_ikesa_init_i_delete(ikesa->resp_spi,ikesa->ike_init_i_hash);
  if( init_i ){
    rhp_ikesa_free_init_i(init_i);
  }

  vpn->ikesa_delete(vpn,ikesa->side,my_spi);

	rhp_vpn_ikesa_spi_delete(vpn,ikesa->side,my_spi);

  _rhp_ikesa_clean_spi(ikesa->side,ikesa->get_my_spi(ikesa));

  if( ikesa->v1.p1_exchange_mode ){
  	rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_V1_DEAD);
  }else{
  	// IKEv2
  	rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DEAD);
  }

  _rhp_ikesa_free(ikesa);

  RHP_TRC(0,RHPTRCID_IKESA_DESTROY_RTRN,"xx",vpn,ikesa);
  return;
}

void rhp_ikesa_set_state(rhp_ikesa* ikesa,int new_state)
{
	int old_state = ikesa->state;
  ikesa->state = new_state;

  RHP_TRC(0,RHPTRCID_IKESA_STATE,"xLdLd",ikesa,"IKESA_STAT",old_state,"IKESA_STAT",new_state);
	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKESA_STATE,"PLL",ikesa,"IKESA_STAT",old_state,"IKESA_STAT",new_state);

	switch( new_state ){
	case RHP_IKESA_STAT_ESTABLISHED:
	case RHP_IKESA_STAT_V1_ESTABLISHED:
		if( ikesa->side == RHP_IKE_INITIATOR ){
			rhp_ikev2_g_statistics_inc(ikesa_established_as_initiator);
		}else{
			rhp_ikev2_g_statistics_inc(ikesa_established_as_responder);
		}
		break;
	case RHP_IKESA_STAT_I_IKE_SA_INIT_SENT:
	case RHP_IKESA_STAT_R_IKE_SA_INIT_SENT:
	case RHP_IKESA_STAT_I_REKEY_SENT:
	case RHP_IKESA_STAT_V1_MAIN_1ST_SENT_I:
	case RHP_IKESA_STAT_V1_MAIN_2ND_SENT_R:
	case RHP_IKESA_STAT_V1_AGG_1ST_SENT_I:
	case RHP_IKESA_STAT_V1_AGG_2ND_SENT_R:
		if( ikesa->side == RHP_IKE_INITIATOR ){
			rhp_ikev2_g_statistics_inc(ikesa_negotiated_as_initiator);
		}else{
			rhp_ikev2_g_statistics_inc(ikesa_negotiated_as_responder);
		}
		break;
	case RHP_IKESA_STAT_DEAD:
	case RHP_IKESA_STAT_V1_DEAD:
		if( ikesa->side == RHP_IKE_INITIATOR ){
			rhp_ikev2_g_statistics_inc(ikesa_deleted_as_initiator);
		}else{
			rhp_ikev2_g_statistics_inc(ikesa_deleted_as_responder);
		}
		break;
	default:
		break;
	}

  return;
}


int rhp_ikesa_crypto_setup_r(rhp_ikesa* ikesa)
{
  int err = -EINVAL;

  RHP_TRC(0,RHPTRCID_IKESA_CRYPTO_SETUP_R,"x",ikesa);

  if( ikesa->dh == NULL ){
    RHP_BUG("");
    goto error;
  }

  ikesa->prf = rhp_crypto_prf_alloc(ikesa->prop.v2.prf_id);
  if( ikesa->prf == NULL ){
    RHP_BUG("");
    goto error;
  }

  ikesa->integ_i = rhp_crypto_integ_alloc(ikesa->prop.v2.integ_id);
  if( ikesa->integ_i == NULL ){
    RHP_BUG("");
    goto error;
  }

  ikesa->integ_r = rhp_crypto_integ_alloc(ikesa->prop.v2.integ_id);
  if( ikesa->integ_r == NULL ){
    RHP_BUG("");
    goto error;
  }

  ikesa->encr = rhp_crypto_encr_alloc(ikesa->prop.v2.encr_id,ikesa->prop.v2.encr_key_bits);
  if( ikesa->encr == NULL ){
    RHP_BUG("");
    goto error;
  }

  if( !ikesa->gen_by_sess_resume ){ // NOT IKEv2 Session Resumption!

  	err = ikesa->dh->compute_key(ikesa->dh);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
  }

  err = ikesa->generate_keys(ikesa);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

  err = ikesa->encr->set_enc_key(ikesa->encr,ikesa->keys.v2.sk_er,ikesa->keys.v2.sk_e_len);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

  err = ikesa->encr->set_dec_key(ikesa->encr,ikesa->keys.v2.sk_ei,ikesa->keys.v2.sk_e_len);
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

  RHP_TRC(0,RHPTRCID_IKESA_CRYPTO_SETUP_R_RTRN,"x",ikesa);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKESA_CRYPTO_SETUP_R_ERR,"xE",ikesa,err);
	return err;
}

int rhp_ikesa_crypto_setup_new_r(rhp_ikesa* old_ikesa,rhp_ikesa* new_ikesa)
{
  int err = -EINVAL;

  RHP_TRC(0,RHPTRCID_IKESA_CRYPTO_SETUP_NEW_R,"xx",old_ikesa,new_ikesa);

  if( new_ikesa->dh == NULL ){
    RHP_BUG("");
    goto error;
  }

  new_ikesa->prf = rhp_crypto_prf_alloc(new_ikesa->prop.v2.prf_id);
  if( new_ikesa->prf == NULL ){
    RHP_BUG("");
    goto error;
  }

  new_ikesa->integ_i = rhp_crypto_integ_alloc(new_ikesa->prop.v2.integ_id);
  if( new_ikesa->integ_i == NULL ){
    RHP_BUG("");
    goto error;
  }

  new_ikesa->integ_r = rhp_crypto_integ_alloc(new_ikesa->prop.v2.integ_id);
  if( new_ikesa->integ_r == NULL ){
    RHP_BUG("");
    goto error;
  }

  new_ikesa->encr = rhp_crypto_encr_alloc(new_ikesa->prop.v2.encr_id,new_ikesa->prop.v2.encr_key_bits);
  if( new_ikesa->encr == NULL ){
    RHP_BUG("");
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

  err = new_ikesa->encr->set_enc_key(new_ikesa->encr,new_ikesa->keys.v2.sk_er,new_ikesa->keys.v2.sk_e_len);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

  err = new_ikesa->encr->set_dec_key(new_ikesa->encr,new_ikesa->keys.v2.sk_ei,new_ikesa->keys.v2.sk_e_len);
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

  RHP_TRC(0,RHPTRCID_IKESA_CRYPTO_SETUP_NEW_R_RTRN,"xx",old_ikesa,new_ikesa);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKESA_CRYPTO_SETUP_NEW_R_ERR,"xxE",old_ikesa,new_ikesa,err);
	return err;
}



