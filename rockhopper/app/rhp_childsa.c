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
#include "rhp_esp.h"
#include "rhp_http.h"
#include "rhp_radius_impl.h"

static rhp_mutex_t _rhp_childsa_lock;


#define RHP_CHILDSA_HASH_TABLE_SIZE   1277
static rhp_childsa* _rhp_childsa_hashtbl[2][RHP_CHILDSA_HASH_TABLE_SIZE]; // [direction][hash_val]
static u32 _rhp_childsa_hashtbl_rnd;

struct _rhp_childsa_inb_spi {

	u8 tag[4]; // "#CIP"

	struct _rhp_childsa_inb_spi* next;

	u32 inb_spi;
};
typedef struct _rhp_childsa_inb_spi rhp_childsa_inb_spi;

static rhp_childsa_inb_spi* _rhp_childsa_inb_spi_hash_tbl[RHP_CHILDSA_HASH_TABLE_SIZE];
static u32 _rhp_childsa_inb_spi_hashtbl_rnd;

static u32 _rhp_gcfg_childsa_dbg_gen_spi_last = RHP_PROTO_ESP_RESV_SPI_MAX;

#define RHP_CHILDSA_GEN_INB_SPI_MAX_TRYING		(1024*1024)

static int _rhp_childsa_generate_inb_spi(rhp_childsa* childsa)
{
  int err = 0;
  u32 inb_spi;
  u32 hval;
  rhp_childsa_inb_spi* entry = NULL;
  unsigned int i = 0;

  RHP_TRC(0,RHPTRCID_CHILDSA_GENERATE_INB_SPI,"xd",childsa,rhp_gcfg_childsa_dbg_gen_spi);

  RHP_LOCK(&_rhp_childsa_lock);

  do{

  	if( i > RHP_CHILDSA_GEN_INB_SPI_MAX_TRYING ){
  		RHP_BUG("%d",i);
  		err = -EINVAL;
  		goto error;
  	}
  	i++;

  	if( rhp_gcfg_childsa_dbg_gen_spi ){

  		inb_spi = _rhp_gcfg_childsa_dbg_gen_spi_last++;
  		if( _rhp_gcfg_childsa_dbg_gen_spi_last == 0 ){
  			_rhp_gcfg_childsa_dbg_gen_spi_last = RHP_PROTO_ESP_RESV_SPI_MAX;
  		}

  	}else{

  		if( rhp_random_bytes((u8*)&inb_spi,sizeof(u32)) ){
				RHP_BUG("");
				err = -EINVAL;
				goto error;
			}
  	}

    if( inb_spi == 0 || (inb_spi >= RHP_PROTO_ESP_RESV_SPI_MIN && inb_spi <= RHP_PROTO_ESP_RESV_SPI_MAX) ){
    	continue;
    }

    inb_spi = htonl(inb_spi);

    hval = _rhp_hash_u32(inb_spi,_rhp_childsa_inb_spi_hashtbl_rnd);
    hval = hval % RHP_CHILDSA_HASH_TABLE_SIZE;

    entry = _rhp_childsa_inb_spi_hash_tbl[hval];

    while( entry ){

     if( entry->inb_spi == inb_spi ){
    	 break;
     	}

     entry = entry->next;
    }

    if( entry == NULL ){

    	entry = (rhp_childsa_inb_spi*)_rhp_malloc(sizeof(rhp_childsa_inb_spi));
    	if( entry == NULL ){
    		RHP_BUG("");
    		err = -ENOMEM;
    		goto error;
    	}

    	memset(entry,0,sizeof(rhp_childsa_inb_spi));

    	entry->tag[0] = '#';
    	entry->tag[1] = 'C';
    	entry->tag[2] = 'I';
    	entry->tag[3] = 'P';
    	entry->inb_spi = inb_spi;

     hval = _rhp_hash_u32(inb_spi,_rhp_childsa_inb_spi_hashtbl_rnd);
     hval = hval % RHP_CHILDSA_HASH_TABLE_SIZE;

     entry->next = _rhp_childsa_inb_spi_hash_tbl[hval];
     _rhp_childsa_inb_spi_hash_tbl[hval] = entry;

     break;
    }

  }while( 1 );

  RHP_UNLOCK(&_rhp_childsa_lock);

  childsa->spi_inb = inb_spi;

  RHP_TRC(0,RHPTRCID_CHILDSA_GENERATE_INB_SPI_RTRN,"xHx",childsa,inb_spi,entry);
  return 0;

error:
  RHP_UNLOCK(&_rhp_childsa_lock);

  RHP_TRC(0,RHPTRCID_CHILDSA_GENERATE_INB_SPI_ERR,"xE",childsa,err);
  return err;
}

static void _rhp_childsa_clean_inb_spi(u32 inb_spi)
{
  u32 hval;
  rhp_childsa_inb_spi *entry = NULL,*entry_p = NULL;

  RHP_TRC(0,RHPTRCID_CHILDSA_CLEAN_INB_SPI,"H",inb_spi);

  RHP_LOCK(&_rhp_childsa_lock);

  hval = _rhp_hash_u32(inb_spi,_rhp_childsa_inb_spi_hashtbl_rnd);
  hval = hval % RHP_CHILDSA_HASH_TABLE_SIZE;

  entry = _rhp_childsa_inb_spi_hash_tbl[hval];

  while( entry ){

  	if( entry->inb_spi == inb_spi ){
  		break;
  	}

  	entry_p = entry;
  	entry = entry->next;
  }

  if( entry == NULL ){

  	RHP_UNLOCK(&_rhp_childsa_lock);

  	RHP_TRC(0,RHPTRCID_CHILDSA_CLEAN_INB_SPI_NOT_FOUND,"H",inb_spi);
  	return;
  }

  if( entry_p ){
    entry_p->next = entry->next;
  }else{
    _rhp_childsa_inb_spi_hash_tbl[hval] = entry->next;
  }

  RHP_UNLOCK(&_rhp_childsa_lock);

  _rhp_free(entry);

  RHP_TRC(0,RHPTRCID_CHILDSA_CLEAN_INB_SPI_RTRN,"Hx",inb_spi,entry);
  return;
}


int rhp_childsa_init()
{
  if( rhp_random_bytes((u8*)&_rhp_childsa_hashtbl_rnd,sizeof(_rhp_childsa_hashtbl_rnd)) ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( rhp_random_bytes((u8*)&_rhp_childsa_inb_spi_hashtbl_rnd,sizeof(_rhp_childsa_inb_spi_hashtbl_rnd)) ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( rhp_random_bytes((u8*)&_rhp_gcfg_childsa_dbg_gen_spi_last,sizeof(_rhp_gcfg_childsa_dbg_gen_spi_last)) ){
    RHP_BUG("");
    return -EINVAL;
  }
  _rhp_gcfg_childsa_dbg_gen_spi_last = (_rhp_gcfg_childsa_dbg_gen_spi_last % 557) + RHP_PROTO_ESP_RESV_SPI_MAX;

  _rhp_mutex_init("CSA",&(_rhp_childsa_lock));

  memset(_rhp_childsa_hashtbl,0,sizeof(rhp_childsa*)*RHP_CHILDSA_HASH_TABLE_SIZE*2);
  memset(_rhp_childsa_inb_spi_hash_tbl,0,sizeof(rhp_childsa_inb_spi*)*RHP_CHILDSA_HASH_TABLE_SIZE);

  RHP_TRC(0,RHPTRCID_CHILDSA_INIT,"");

  return 0;
}

int rhp_childsa_cleanup()
{
  _rhp_mutex_destroy(&(_rhp_childsa_lock));

  RHP_TRC(0,RHPTRCID_CHILDSA_CLEANUP,"");
  return 0;
}


static void _rhp_childsa_set_outb_spi(rhp_childsa* childsa,u32 spi)
{
  childsa->spi_outb = spi;

  RHP_TRC(0,RHPTRCID_CHILDSA_SET_OUTB_SPI,"xJK",childsa,spi,spi);
  return;
}


static int _rhp_childsa_set_traffic_selectors(rhp_childsa* childsa,
		rhp_ikev2_traffic_selector* my_tss,rhp_ikev2_traffic_selector* peer_tss,rhp_vpn* vpn)
{
	int err = -EINVAL;
  rhp_childsa_ts* csa_ts;
  rhp_ikev2_traffic_selector* tss;
  rhp_childsa_ts** csa_ts_head;
  rhp_childsa_ts* csa_ts_tail;
  int i;

  RHP_TRC(0,RHPTRCID_CHILDSA_SET_TRAFFIC_SELECTORS,"xxxx",childsa,my_tss,peer_tss,vpn);

  if( my_tss == NULL || peer_tss == NULL ){
  	RHP_BUG("0x%x, 0x%x",my_tss,peer_tss);
  	return -EINVAL;
  }
  //  rhp_cfg_traffic_selectors_dump("_rhp_childsa_set_traffic_selectors.my_tss",NULL,my_tss);
  //  rhp_cfg_traffic_selectors_dump("_rhp_childsa_set_traffic_selectors.peer_tss",NULL,peer_tss);


  for( i = 0; i < 2; i++ ){

  	if( i == 0 ){
  		csa_ts_head = &(childsa->my_tss);
  		tss = my_tss;
  	}else{
  		csa_ts_head = &(childsa->peer_tss);
  		tss = peer_tss;
  	}
  	csa_ts_tail = NULL;

  	while( tss ){

  		csa_ts = (rhp_childsa_ts*)_rhp_malloc(sizeof(rhp_childsa_ts));
    	if( csa_ts == NULL ){
    		RHP_BUG("");
    		return -ENOMEM;
    	}

    	memset(csa_ts,0,sizeof(rhp_childsa_ts));

     csa_ts->tag[0] = '#';
     csa_ts->tag[1] = 'C';
     csa_ts->tag[2] = 'S';
     csa_ts->tag[3] = 'T';

     if( tss->is_pending ){
    	 csa_ts->flag = RHP_CHILDSA_TS_IS_PENDING;
     }

     csa_ts->ts_or_id_type = tss->get_ts_type(tss);

     csa_ts->protocol = tss->get_protocol(tss);

     if( csa_ts->protocol == RHP_PROTO_IP_ICMP ||
    		 csa_ts->protocol == RHP_PROTO_IP_IPV6_ICMP ){

    	 csa_ts->icmp_start_type = tss->get_icmp_start_type(tss);
       csa_ts->icmp_end_type = tss->get_icmp_end_type(tss);
       csa_ts->icmp_start_code = tss->get_icmp_start_code(tss);
       csa_ts->icmp_end_code = tss->get_icmp_end_code(tss);

     }else{

    	 csa_ts->start_port = tss->get_start_port(tss);
    	 csa_ts->end_port = tss->get_end_port(tss);
     }

     err = tss->get_start_addr(tss,&(csa_ts->start_addr));
     if( err ){
    	 RHP_BUG("%d",err);
    	 _rhp_free(csa_ts);
    	 return err;
     }

     err = tss->get_end_addr(tss,&(csa_ts->end_addr));
     if( err ){
    	 RHP_BUG("%d",err);
    	 _rhp_free(csa_ts);
    	 return err;
     }

     if( *csa_ts_head == NULL ){
    	 (*csa_ts_head) = csa_ts;
     }else{
       csa_ts_tail->next = csa_ts;
      }
     csa_ts_tail = csa_ts;

     RHP_TRC(0,RHPTRCID_CHILDSA_SET_TRAFFIC_SELECTOR,"dxxbbWWbbbb",i,childsa,csa_ts,csa_ts->ts_or_id_type,csa_ts->protocol,csa_ts->start_port,csa_ts->end_port,csa_ts->icmp_start_type,csa_ts->icmp_end_type,csa_ts->icmp_start_code,csa_ts->icmp_end_code);
     rhp_ip_addr_dump("start_addr",&(csa_ts->start_addr));
     rhp_ip_addr_dump("end_addr",&(csa_ts->end_addr));

     tss = tss->next;
  	}
  }


  if( vpn ){

  	if( vpn->last_my_tss || vpn->last_peer_tss ){
  		rhp_childsa_free_traffic_selectors(vpn->last_my_tss,vpn->last_peer_tss);
  	}

  	vpn->last_my_tss = NULL;
  	vpn->last_peer_tss = NULL;

  	err = rhp_childsa_dup_traffic_selectors(childsa,&(vpn->last_my_tss),&(vpn->last_peer_tss));
  	if( err ){
  		RHP_BUG("");
  	}
  	err = 0;
  }

  RHP_TRC(0,RHPTRCID_CHILDSA_SET_TRAFFIC_SELECTORS_RTRN,"xxx",childsa,my_tss,peer_tss);
  return 0;
}

static int _rhp_childsa_set_traffic_selector_v1(rhp_childsa* childsa,
		rhp_childsa_ts* my_csa_ts_c,rhp_childsa_ts* peer_csa_ts_c,
		rhp_childsa_ts* my_csa_ts_gre,rhp_childsa_ts* peer_csa_ts_gre)
{
	int err = -EINVAL;
  rhp_childsa_ts *my_csa_ts = NULL, *peer_csa_ts = NULL;
	rhp_childsa_ts *tss_tmp, *tss_tmp_n;

  RHP_TRC(0,RHPTRCID_CHILDSA_SET_TRAFFIC_SELECTOR_V1,"xxxxx",childsa,my_csa_ts_c,peer_csa_ts_c,childsa->my_tss,childsa->peer_tss);
  rhp_ip_addr_dump("my_csa_ts_c->start_addr",&(my_csa_ts_c->start_addr));
  rhp_ip_addr_dump("my_csa_ts_c->end_addr",&(my_csa_ts_c->end_addr));
  rhp_ip_addr_dump("peer_csa_ts_c->start_addr",&(peer_csa_ts_c->start_addr));
  rhp_ip_addr_dump("peer_csa_ts_c->end_addr",&(peer_csa_ts_c->end_addr));
  rhp_ip_addr_dump("my_csa_ts_gre->start_addr",(my_csa_ts_gre ? &(my_csa_ts_gre->start_addr) : NULL));
  rhp_ip_addr_dump("my_csa_ts_gre->end_addr",(my_csa_ts_gre ? &(my_csa_ts_gre->end_addr) : NULL));
  rhp_ip_addr_dump("peer_csa_ts_gre->start_addr",(peer_csa_ts_gre ? &(peer_csa_ts_gre->start_addr) : NULL));
  rhp_ip_addr_dump("peer_csa_ts_gre->end_addr",(peer_csa_ts_gre ? &(peer_csa_ts_gre->end_addr) : NULL));

  if( !my_csa_ts_c->is_v1 ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  if( !peer_csa_ts_c->is_v1 ){
  	RHP_BUG("");
  	return -EINVAL;
  }


  my_csa_ts = (rhp_childsa_ts*)_rhp_malloc(sizeof(rhp_childsa_ts));
  if( my_csa_ts == NULL ){
  	err = -ENOMEM;
  	RHP_BUG("");
  	goto error;
  }
  memcpy(my_csa_ts,my_csa_ts_c,sizeof(rhp_childsa_ts));
  my_csa_ts->next = NULL;

  if( my_csa_ts_gre ){

  	tss_tmp = (rhp_childsa_ts*)_rhp_malloc(sizeof(rhp_childsa_ts));
    if( tss_tmp == NULL ){
    	err = -ENOMEM;
    	RHP_BUG("");
    	goto error;
    }
    memcpy(tss_tmp,my_csa_ts_gre,sizeof(rhp_childsa_ts));
    tss_tmp->next = NULL;

    my_csa_ts->next = tss_tmp;
  }



  peer_csa_ts = (rhp_childsa_ts*)_rhp_malloc(sizeof(rhp_childsa_ts));
  if( peer_csa_ts == NULL ){
  	err = -ENOMEM;
  	RHP_BUG("");
  	goto error;
  }
  memcpy(peer_csa_ts,peer_csa_ts_c,sizeof(rhp_childsa_ts));
  peer_csa_ts->next = NULL;

  if( peer_csa_ts_gre ){

  	tss_tmp = (rhp_childsa_ts*)_rhp_malloc(sizeof(rhp_childsa_ts));
    if( tss_tmp == NULL ){
    	err = -ENOMEM;
    	RHP_BUG("");
    	goto error;
    }
    memcpy(tss_tmp,peer_csa_ts_gre,sizeof(rhp_childsa_ts));
    tss_tmp->next = NULL;

    peer_csa_ts->next = tss_tmp;
  }



  if( childsa->my_tss ){
    tss_tmp = childsa->my_tss;
  	while( tss_tmp ){
      rhp_ip_addr_dump("childsa->my_tss.start_addr(OLD)",&(tss_tmp->start_addr));
      rhp_ip_addr_dump("childsa->my_tss.end_addr(OLD)",&(tss_tmp->end_addr));
  		tss_tmp_n = tss_tmp->next;
  		_rhp_free(tss_tmp);
  		tss_tmp = tss_tmp_n;
  	}
  }

  if( childsa->peer_tss ){
    tss_tmp = childsa->peer_tss;
  	while( tss_tmp ){
      rhp_ip_addr_dump("childsa->peer_tss.start_addr(OLD)",&(tss_tmp->start_addr));
      rhp_ip_addr_dump("childsa->peer_tss.end_addr(OLD)",&(tss_tmp->end_addr));
  		tss_tmp_n = tss_tmp->next;
  		_rhp_free(tss_tmp);
  		tss_tmp = tss_tmp_n;
  	}
  }

  childsa->my_tss = my_csa_ts;
  childsa->peer_tss = peer_csa_ts;

  RHP_TRC(0,RHPTRCID_CHILDSA_SET_TRAFFIC_SELECTOR_V1_MY_TS,"xxbbWWbbbb",childsa,my_csa_ts,my_csa_ts->ts_or_id_type,my_csa_ts->protocol,my_csa_ts->start_port,my_csa_ts->end_port,my_csa_ts->icmp_start_type,my_csa_ts->icmp_end_type,my_csa_ts->icmp_start_code,my_csa_ts->icmp_end_code);
  rhp_ip_addr_dump("start_addr.my_ts",&(my_csa_ts->start_addr));
  rhp_ip_addr_dump("end_addr.my_ts",&(my_csa_ts->end_addr));
  if( my_csa_ts->next ){
    RHP_TRC(0,RHPTRCID_CHILDSA_SET_TRAFFIC_SELECTOR_V1_MY_TS_2,"xxbbWWbbbb",childsa,my_csa_ts->next,my_csa_ts->next->ts_or_id_type,my_csa_ts->next->protocol,my_csa_ts->next->start_port,my_csa_ts->next->end_port,my_csa_ts->next->icmp_start_type,my_csa_ts->next->icmp_end_type,my_csa_ts->next->icmp_start_code,my_csa_ts->next->icmp_end_code);
    rhp_ip_addr_dump("start_addr.my_ts_2",&(my_csa_ts->next->start_addr));
    rhp_ip_addr_dump("end_addr.my_ts_2",&(my_csa_ts->next->end_addr));
  }

  RHP_TRC(0,RHPTRCID_CHILDSA_SET_TRAFFIC_SELECTOR_V1_PEER_TS,"xxbbWWbbbb",childsa,peer_csa_ts,peer_csa_ts->ts_or_id_type,peer_csa_ts->protocol,peer_csa_ts->start_port,peer_csa_ts->end_port,peer_csa_ts->icmp_start_type,peer_csa_ts->icmp_end_type,peer_csa_ts->icmp_start_code,peer_csa_ts->icmp_end_code);
  rhp_ip_addr_dump("start_addr.peer_ts",&(peer_csa_ts->start_addr));
  rhp_ip_addr_dump("end_addr.peer_ts",&(peer_csa_ts->end_addr));
  if( peer_csa_ts->next ){
    RHP_TRC(0,RHPTRCID_CHILDSA_SET_TRAFFIC_SELECTOR_V1_PEER_TS_2,"xxbbWWbbbb",childsa,peer_csa_ts->next,peer_csa_ts->next->ts_or_id_type,peer_csa_ts->next->protocol,peer_csa_ts->next->start_port,peer_csa_ts->next->end_port,peer_csa_ts->next->icmp_start_type,peer_csa_ts->next->icmp_end_type,peer_csa_ts->next->icmp_start_code,peer_csa_ts->next->icmp_end_code);
    rhp_ip_addr_dump("start_addr.peer_ts_2",&(peer_csa_ts->next->start_addr));
    rhp_ip_addr_dump("end_addr.peer_ts_2",&(peer_csa_ts->next->end_addr));
  }

  return 0;

error:
	if( my_csa_ts ){
    tss_tmp = my_csa_ts;
  	while( tss_tmp ){
  		tss_tmp_n = tss_tmp->next;
  		_rhp_free(tss_tmp);
  		tss_tmp = tss_tmp_n;
  	}
	}
	if( peer_csa_ts ){
    tss_tmp = peer_csa_ts;
  	while( tss_tmp ){
  		tss_tmp_n = tss_tmp->next;
  		_rhp_free(tss_tmp);
  		tss_tmp = tss_tmp_n;
  	}
	}
  RHP_TRC(0,RHPTRCID_CHILDSA_SET_TRAFFIC_SELECTOR_V1_ERR,"xxxxxE",childsa,my_csa_ts_c,peer_csa_ts_c,childsa->my_tss,childsa->peer_tss,err);
	return err;
}


static int _rhp_childsa_setup_sec_params(rhp_ikesa* ikesa,rhp_childsa* childsa)
{
  int err = -EINVAL;
  int km_buf_len,prf_output_len,prf_key_len;
  u8 *n_i_r_buf = NULL,*n_i,*n_r;
  int n_i_r_len,n_i_len,n_r_len;

  RHP_TRC(0,RHPTRCID_CHILDSA_SETUP_SEC_PARAMS,"xx",ikesa,childsa);

  if( ikesa->prf == NULL || ikesa->nonce_i == NULL || ikesa->nonce_r == NULL ||
	   childsa->encr == NULL || childsa->integ_inb == NULL || childsa->integ_outb == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  prf_output_len = ikesa->prf->get_output_len(ikesa->prf);
  prf_key_len = ikesa->prf->get_key_len(ikesa->prf);

  n_i_len = ikesa->nonce_i->get_nonce_len(ikesa->nonce_i);
  n_r_len = ikesa->nonce_r->get_nonce_len(ikesa->nonce_r);

  n_i_r_len = n_i_len + n_r_len;

  n_i = ikesa->nonce_i->get_nonce(ikesa->nonce_i);
  n_r = ikesa->nonce_r->get_nonce(ikesa->nonce_r);

  if( n_i_r_len < prf_key_len ){
    err = -EINVAL;
    RHP_TRC(0,RHPTRCID_CHILDSA_SETUP_SEC_PARAMS_BAD_N_I_R_LEN,"xxdd",ikesa,childsa,n_i_r_len,prf_key_len);
    goto error;
  }

  if( n_i == NULL || n_r == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  if( rhp_gcfg_dbg_log_keys_info ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_CHILDSA_GENERATED_KEY_N_I,"Cp",childsa,n_i_len,n_i);
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_CHILDSA_GENERATED_KEY_N_R,"Cp",childsa,n_r_len,n_r);
  }

  n_i_r_buf = (u8*)_rhp_malloc( n_i_r_len );
  if( n_i_r_buf == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

  memcpy(n_i_r_buf,n_i,n_i_len);
  memcpy((n_i_r_buf + n_i_len),n_r,n_r_len);

  childsa->keys.integ_key_len = childsa->integ_inb->get_key_len(childsa->integ_inb);
  childsa->keys.encr_key_len = childsa->encr->get_key_len(childsa->encr);

  km_buf_len = (childsa->keys.integ_key_len*2) + (childsa->keys.encr_key_len*2);
  km_buf_len = ((km_buf_len+(prf_output_len-1)) & ~(prf_output_len-1));

  childsa->key_material.key_octets = (u8*)_rhp_malloc(km_buf_len);
  if( childsa->key_material.key_octets == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

  memset(childsa->key_material.key_octets,0,km_buf_len);

  if( rhp_gcfg_dbg_log_keys_info ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_CHILDSA_GENERATED_KEY_SK_D,"CPp",childsa,ikesa,ikesa->keys.v2.sk_d_len,ikesa->keys.v2.sk_d);
  }

  err = rhp_crypto_prf_plus(ikesa->prf,ikesa->keys.v2.sk_d,ikesa->keys.v2.sk_d_len,n_i_r_buf,n_i_r_len,
		  		childsa->key_material.key_octets,km_buf_len);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  childsa->key_material.len = km_buf_len;

  if( childsa->side == RHP_IKE_INITIATOR ){

	  childsa->keys.encr_enc_key = childsa->key_material.key_octets;
	  childsa->keys.integ_outb_key = childsa->keys.encr_enc_key + childsa->keys.encr_key_len;
	  childsa->keys.encr_dec_key = childsa->keys.integ_outb_key + childsa->keys.integ_key_len;
	  childsa->keys.integ_inb_key = childsa->keys.encr_dec_key + childsa->keys.encr_key_len;

  }else{

	  childsa->keys.encr_dec_key = childsa->key_material.key_octets;
	  childsa->keys.integ_inb_key = childsa->keys.encr_dec_key + childsa->keys.encr_key_len;
	  childsa->keys.encr_enc_key = childsa->keys.integ_inb_key + childsa->keys.integ_key_len;
	  childsa->keys.integ_outb_key = childsa->keys.encr_enc_key + childsa->keys.encr_key_len;
  }

  err = childsa->encr->set_enc_key(childsa->encr,childsa->keys.encr_enc_key,childsa->keys.encr_key_len);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

  err = childsa->encr->set_dec_key(childsa->encr,childsa->keys.encr_dec_key,childsa->keys.encr_key_len);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

  err = childsa->integ_inb->set_key(childsa->integ_inb,childsa->keys.integ_inb_key,childsa->keys.integ_key_len);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

  err = childsa->integ_outb->set_key(childsa->integ_outb,childsa->keys.integ_outb_key,childsa->keys.integ_key_len);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( rhp_gcfg_dbg_log_keys_info ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_CHILDSA_GENERATED_KEY_VALUES_ENC,"Cp",childsa,childsa->keys.encr_key_len,childsa->keys.encr_enc_key);
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_CHILDSA_GENERATED_KEY_VALUES_DEC,"Cp",childsa,childsa->keys.encr_key_len,childsa->keys.encr_dec_key);
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_CHILDSA_GENERATED_KEY_VALUES_INTEG_INB,"Cp",childsa,childsa->keys.integ_key_len,childsa->keys.integ_inb_key);
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_CHILDSA_GENERATED_KEY_VALUES_INTEG_OUTB,"Cp",childsa,childsa->keys.integ_key_len,childsa->keys.integ_outb_key);
  }

  _rhp_free_zero(n_i_r_buf,n_i_r_len);

  RHP_TRC(0,RHPTRCID_CHILDSA_SETUP_SEC_PARAMS_RTRN,"xx",ikesa,childsa);
  return 0;

error:
  if( n_i_r_buf ){
    _rhp_free(n_i_r_buf);
  }
  if( childsa->key_material.key_octets ){
    _rhp_free(childsa->key_material.key_octets);
    childsa->key_material.key_octets = 0;
  }
  childsa->key_material.len = 0;
  childsa->keys.integ_key_len = 0;
  childsa->keys.encr_key_len = 0;

  RHP_TRC(0,RHPTRCID_CHILDSA_SETUP_SEC_PARAMS_ERR,"xxE",ikesa,childsa,err);
  return err;
}

static int _rhp_childsa_setup_sec_params2(rhp_ikesa* ikesa,rhp_childsa* childsa)
{
  int err = -EINVAL;
  int km_buf_len,prf_output_len,prf_key_len;
  u8 *n_i_r_buf = NULL,*n_i,*n_r,*dh_shared_key = NULL,*p;
  int n_i_r_len,n_i_len,n_r_len,dh_shared_key_len = 0;

  RHP_TRC(0,RHPTRCID_CHILDSA_REKEY_SETUP_SEC_PARAMS,"xx",ikesa,childsa);

  if( ikesa->prf == NULL || childsa->rekey_nonce_i == NULL || childsa->rekey_nonce_r == NULL ||
	   childsa->encr == NULL || childsa->integ_inb == NULL || childsa->integ_outb == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( childsa->rekey_dh ){

    dh_shared_key = childsa->rekey_dh->get_shared_key(childsa->rekey_dh,&dh_shared_key_len);
    if( dh_shared_key == NULL ){
    	RHP_BUG("");
    	err = -EINVAL;
    	goto error;
    }

    if( rhp_gcfg_dbg_log_keys_info ){
    	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_CHILDSA_GENERATED_NEW_KEY_DH_SHAREDKEY,"Cp",childsa,dh_shared_key_len,dh_shared_key);
    }
  }

  prf_output_len = ikesa->prf->get_output_len(ikesa->prf);
  prf_key_len = ikesa->prf->get_key_len(ikesa->prf);

  n_i_len = childsa->rekey_nonce_i->get_nonce_len(childsa->rekey_nonce_i);
  n_r_len = childsa->rekey_nonce_r->get_nonce_len(childsa->rekey_nonce_r);

  n_i_r_len = n_i_len + n_r_len;

  n_i = childsa->rekey_nonce_i->get_nonce(childsa->rekey_nonce_i);
  n_r = childsa->rekey_nonce_r->get_nonce(childsa->rekey_nonce_r);

  if( n_i_r_len < prf_key_len ){
    err = -EINVAL;
    RHP_TRC(0,RHPTRCID_CHILDSA_REKEY_SETUP_SEC_PARAMS_BAD_N_I_R_LEN,"xxdd",ikesa,childsa,n_i_r_len,prf_key_len);
    goto error;
  }

  if( n_i == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  if( n_r == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  if( rhp_gcfg_dbg_log_keys_info ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_CHILDSA_GENERATED_NEW_KEY_N_I,"Cp",childsa,n_i_len,n_i);
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_CHILDSA_GENERATED_NEW_KEY_N_R,"Cp",childsa,n_r_len,n_r);
  }

  n_i_r_buf = (u8*)_rhp_malloc( n_i_r_len + dh_shared_key_len );
  if( n_i_r_buf == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

  if( dh_shared_key ){
    memcpy(n_i_r_buf,dh_shared_key,dh_shared_key_len);
    p = n_i_r_buf + dh_shared_key_len;
  }else{
    p = n_i_r_buf;
  }
  memcpy(p,n_i,n_i_len);
  memcpy((p + n_i_len),n_r,n_r_len);

  childsa->keys.integ_key_len = childsa->integ_inb->get_key_len(childsa->integ_inb);
  childsa->keys.encr_key_len = childsa->encr->get_key_len(childsa->encr);

  km_buf_len = (childsa->keys.integ_key_len*2) + (childsa->keys.encr_key_len*2);
  km_buf_len = ((km_buf_len+(prf_output_len-1)) & ~(prf_output_len-1));

  childsa->key_material.key_octets = (u8*)_rhp_malloc(km_buf_len);
  if( childsa->key_material.key_octets == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

  memset(childsa->key_material.key_octets,0,km_buf_len);

  if( rhp_gcfg_dbg_log_keys_info ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_CHILDSA_GENERATED_NEW_KEY_SK_D,"CPp",childsa,ikesa,ikesa->keys.v2.sk_d_len,ikesa->keys.v2.sk_d);
  }

  err = rhp_crypto_prf_plus(ikesa->prf,ikesa->keys.v2.sk_d,ikesa->keys.v2.sk_d_len,n_i_r_buf,
  			(n_i_r_len + dh_shared_key_len),childsa->key_material.key_octets,km_buf_len);

  if( err ){
    RHP_BUG("");
    goto error;
  }

  childsa->key_material.len = km_buf_len;

  if( childsa->side == RHP_IKE_INITIATOR ){

	  childsa->keys.encr_enc_key = childsa->key_material.key_octets;
	  childsa->keys.integ_outb_key = childsa->keys.encr_enc_key + childsa->keys.encr_key_len;
	  childsa->keys.encr_dec_key = childsa->keys.integ_outb_key + childsa->keys.integ_key_len;
	  childsa->keys.integ_inb_key = childsa->keys.encr_dec_key + childsa->keys.encr_key_len;

  }else{

	  childsa->keys.encr_dec_key = childsa->key_material.key_octets;
	  childsa->keys.integ_inb_key = childsa->keys.encr_dec_key + childsa->keys.encr_key_len;
	  childsa->keys.encr_enc_key = childsa->keys.integ_inb_key + childsa->keys.integ_key_len;
	  childsa->keys.integ_outb_key = childsa->keys.encr_enc_key + childsa->keys.encr_key_len;
  }


  err = childsa->encr->set_enc_key(childsa->encr,childsa->keys.encr_enc_key,childsa->keys.encr_key_len);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

  err = childsa->encr->set_dec_key(childsa->encr,childsa->keys.encr_dec_key,childsa->keys.encr_key_len);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

  err = childsa->integ_inb->set_key(childsa->integ_inb,childsa->keys.integ_inb_key,childsa->keys.integ_key_len);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

  err = childsa->integ_outb->set_key(childsa->integ_outb,childsa->keys.integ_outb_key,childsa->keys.integ_key_len);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( rhp_gcfg_dbg_log_keys_info ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_CHILDSA_GENERATED_NEW_KEY_VALUES_ENC,"Cp",childsa,childsa->keys.encr_key_len,childsa->keys.encr_enc_key);
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_CHILDSA_GENERATED_NEW_KEY_VALUES_DEC,"Cp",childsa,childsa->keys.encr_key_len,childsa->keys.encr_dec_key);
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_CHILDSA_GENERATED_NEW_KEY_VALUES_INTEG_INB,"Cp",childsa,childsa->keys.integ_key_len,childsa->keys.integ_inb_key);
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_CHILDSA_GENERATED_NEW_KEY_VALUES_INTEG_OUTB,"Cp",childsa,childsa->keys.integ_key_len,childsa->keys.integ_outb_key);
  }

  _rhp_free_zero(n_i_r_buf,n_i_r_len);

  RHP_TRC(0,RHPTRCID_CHILDSA_REKEY_SETUP_SEC_PARAMS_RTRN,"xx",ikesa,childsa);
  return 0;

error:
  if( n_i_r_buf ){
    _rhp_free(n_i_r_buf);
  }
  if( childsa->key_material.key_octets ){
    _rhp_free(childsa->key_material.key_octets);
    childsa->key_material.key_octets = 0;
  }
  childsa->key_material.len = 0;
  childsa->keys.integ_key_len = 0;
  childsa->keys.encr_key_len = 0;

  RHP_TRC(0,RHPTRCID_CHILDSA_REKEY_SETUP_SEC_PARAMS_ERR,"xxE",ikesa,childsa,err);
  return err;
}


static int _rhp_childsa_setup_sec_params_v1(rhp_ikesa* ikesa,rhp_childsa* childsa)
{
  int err = -EINVAL;
  int km_buf_len,prf_output_len,prf_key_len;
  u8 *material_i_buf = NULL, *material_o_buf = NULL, *n_i, *n_r, *dh_shared_key = NULL, *km_buf_i, *km_buf_o;
  int n_i_r_len,n_i_len,n_r_len,dh_shared_key_len = 0, material_len;
  u8* p;

  RHP_TRC(0,RHPTRCID_CHILDSA_SETUP_SEC_PARAMS_V1,"xxxp",ikesa,childsa,ikesa->prf,ikesa->keys.v1.skeyid_d_len,ikesa->keys.v1.skeyid_d);

  if( ikesa->prf == NULL || childsa->v1.nonce_i == NULL || childsa->v1.nonce_r == NULL ||
	   childsa->encr == NULL || childsa->integ_inb == NULL || childsa->integ_outb == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  prf_output_len = ikesa->prf->get_output_len(ikesa->prf);
  prf_key_len = ikesa->prf->get_key_len(ikesa->prf);

  {
		n_i_len = childsa->v1.nonce_i->get_nonce_len(childsa->v1.nonce_i);
		n_r_len = childsa->v1.nonce_r->get_nonce_len(childsa->v1.nonce_r);

		n_i_r_len = n_i_len + n_r_len;

		n_i = childsa->v1.nonce_i->get_nonce(childsa->v1.nonce_i);
		n_r = childsa->v1.nonce_r->get_nonce(childsa->v1.nonce_r);

		if( n_i_r_len < prf_key_len ){
			err = -EINVAL;
			RHP_TRC(0,RHPTRCID_CHILDSA_SETUP_SEC_PARAMS_V1_BAD_N_I_R_LEN,"xxdd",ikesa,childsa,n_i_r_len,prf_key_len);
			goto error;
		}

		if( n_i == NULL || n_r == NULL ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		if( rhp_gcfg_dbg_log_keys_info ){
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_CHILDSA_GENERATED_KEY_N_I,"Cp",childsa,n_i_len,n_i);
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_CHILDSA_GENERATED_KEY_N_R,"Cp",childsa,n_r_len,n_r);
		}
  }

  if( childsa->v1.dh ){

  	dh_shared_key = childsa->v1.dh->get_shared_key(childsa->v1.dh,&dh_shared_key_len);
  	if( dh_shared_key == NULL ){
  		RHP_BUG("");
  		err = -EINVAL;
  		goto error;
  	}
  }

  {
  	material_len = dh_shared_key_len + sizeof(u8) + RHP_PROTO_ESP_SPI_SIZE + n_i_r_len;

		material_i_buf = (u8*)_rhp_malloc(material_len);
		if( material_i_buf == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
		p = material_i_buf;

		if( dh_shared_key_len ){
			memcpy(p,dh_shared_key,dh_shared_key_len);
			p += dh_shared_key_len;
		}

		*p = RHP_PROTO_IKEV1_PROP_PROTO_ID_ESP;
		p += sizeof(u8);

		memcpy(p,&(childsa->spi_inb),RHP_PROTO_ESP_SPI_SIZE);
		p += RHP_PROTO_ESP_SPI_SIZE;

		memcpy(p,n_i,n_i_len);
		p += n_i_len;
		memcpy(p,n_r,n_r_len);
		p += n_r_len;
  }

  {
		material_o_buf = (u8*)_rhp_malloc(material_len);
		if( material_o_buf == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
		p = material_o_buf;

		if( dh_shared_key_len ){
			memcpy(p,dh_shared_key,dh_shared_key_len);
			p += dh_shared_key_len;
		}

		*p = RHP_PROTO_IKEV1_PROP_PROTO_ID_ESP;
		p += sizeof(u8);

		memcpy(p,&(childsa->spi_outb),RHP_PROTO_ESP_SPI_SIZE);
		p += RHP_PROTO_ESP_SPI_SIZE;

		memcpy(p,n_i,n_i_len);
		p += n_i_len;
		memcpy(p,n_r,n_r_len);
		p += n_r_len;
  }


  childsa->keys.integ_key_len = childsa->integ_inb->get_key_len(childsa->integ_inb);
  childsa->keys.encr_key_len = childsa->encr->get_key_len(childsa->encr);

  km_buf_len = childsa->keys.encr_key_len + childsa->keys.integ_key_len;
  km_buf_len = ((km_buf_len + (prf_output_len-1)) & ~(prf_output_len-1));

  childsa->key_material.key_octets = (u8*)_rhp_malloc(km_buf_len*2);
  if( childsa->key_material.key_octets == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

  memset(childsa->key_material.key_octets,0,km_buf_len*2);

  if( rhp_gcfg_dbg_log_keys_info ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_CHILDSA_GENERATED_KEY_SK_D,"CPp",childsa,ikesa,ikesa->keys.v1.skeyid_d_len,ikesa->keys.v1.skeyid_d);
  }

  childsa->key_material.len = km_buf_len*2;

  km_buf_o = childsa->key_material.key_octets;
  km_buf_i = childsa->key_material.key_octets + km_buf_len;


  {
  	int i;
  	u8 *material_tmp, *prf_output_tmp;

		material_tmp = (u8*)_rhp_malloc(prf_output_len + material_len);
		if( material_tmp == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}

		prf_output_tmp = (u8*)_rhp_malloc(prf_output_len);
		if( prf_output_tmp == NULL ){
			RHP_BUG("");
			_rhp_free(material_tmp);
			err = -ENOMEM;
			goto error;
		}

  	err = ikesa->prf->set_key(ikesa->prf,ikesa->keys.v1.skeyid_d,ikesa->keys.v1.skeyid_d_len);
  	if( err ){
  		RHP_BUG("%d",err);
			_rhp_free(material_tmp);
			_rhp_free(prf_output_tmp);
  		goto error;
  	}

  	for( i = 0; i < 2; i++ ){

  		int rem = km_buf_len, material_tmp_len;
  		u8 *material_1, *pk = NULL;

  		p = (i == 0 ? km_buf_i : km_buf_o);
  		material_1 = (i == 0 ? material_i_buf : material_o_buf);

  		while( rem > 0 ){

				material_tmp_len = material_len;
  			if( pk ){
					memcpy(material_tmp,pk,prf_output_len);
					memcpy((material_tmp + prf_output_len),material_1,material_len);
					material_tmp_len += prf_output_len;
  			}else{
					memcpy(material_tmp,material_1,material_len);
  			}

				err = ikesa->prf->compute(ikesa->prf,material_tmp,material_tmp_len,prf_output_tmp,prf_output_len);
				if( err ){
					RHP_BUG("%d",err);
					_rhp_free(material_tmp);
					_rhp_free(prf_output_tmp);
					goto error;
				}

				if( rem > prf_output_len ){
					memcpy(p,prf_output_tmp,prf_output_len);
				}else{
					memcpy(p,prf_output_tmp,rem);
				}

				pk = p;
				p += prf_output_len;
				rem -= prf_output_len;
			}
  	}

		_rhp_free(material_tmp);
		_rhp_free(prf_output_tmp);
  }


  childsa->keys.encr_enc_key = km_buf_o;
  childsa->keys.integ_outb_key = childsa->keys.encr_enc_key + childsa->keys.encr_key_len;
  childsa->keys.encr_dec_key = km_buf_i;
  childsa->keys.integ_inb_key = childsa->keys.encr_dec_key + childsa->keys.encr_key_len;


  err = childsa->encr->set_enc_key(childsa->encr,childsa->keys.encr_enc_key,childsa->keys.encr_key_len);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

  err = childsa->encr->set_dec_key(childsa->encr,childsa->keys.encr_dec_key,childsa->keys.encr_key_len);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

  err = childsa->integ_inb->set_key(childsa->integ_inb,childsa->keys.integ_inb_key,childsa->keys.integ_key_len);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

  err = childsa->integ_outb->set_key(childsa->integ_outb,childsa->keys.integ_outb_key,childsa->keys.integ_key_len);
  if( err ){
    RHP_BUG("%d",err);
    goto error;
  }

  if( rhp_gcfg_dbg_log_keys_info ){
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_CHILDSA_GENERATED_KEY_VALUES_ENC,"Cp",childsa,childsa->keys.encr_key_len,childsa->keys.encr_enc_key);
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_CHILDSA_GENERATED_KEY_VALUES_DEC,"Cp",childsa,childsa->keys.encr_key_len,childsa->keys.encr_dec_key);
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_CHILDSA_GENERATED_KEY_VALUES_INTEG_INB,"Cp",childsa,childsa->keys.integ_key_len,childsa->keys.integ_inb_key);
  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_CHILDSA_GENERATED_KEY_VALUES_INTEG_OUTB,"Cp",childsa,childsa->keys.integ_key_len,childsa->keys.integ_outb_key);
  }

  _rhp_free_zero(material_i_buf,material_len);
  _rhp_free_zero(material_o_buf,material_len);

  RHP_TRC(0,RHPTRCID_CHILDSA_SETUP_SEC_PARAMS_V1_RTRN,"xx",ikesa,childsa);
  return 0;

error:
  if( material_i_buf ){
    _rhp_free(material_i_buf);
  }
  if( material_o_buf ){
    _rhp_free(material_o_buf);
  }
  if( childsa->key_material.key_octets ){
    _rhp_free(childsa->key_material.key_octets);
    childsa->key_material.key_octets = 0;
  }
  childsa->key_material.len = 0;
  childsa->keys.integ_key_len = 0;
  childsa->keys.encr_key_len = 0;

  RHP_TRC(0,RHPTRCID_CHILDSA_SETUP_SEC_PARAMS_V1_ERR,"xxE",ikesa,childsa,err);
  return err;
}


static void* _rhp_childsa_get_esp_impl_ctx(rhp_childsa* childsa)
{
	return childsa->impl_ctx;
}

static void _rhp_childsa_dump(rhp_childsa* childsa)
{
  RHP_TRC(0,RHPTRCID_CHILDSA_DUMP,"xLdHHLd",childsa,"IKE_SIDE",childsa->side,childsa->spi_inb,childsa->spi_outb,"CHILDSA_STAT",childsa->state);
}

rhp_childsa* rhp_childsa_alloc(int side,int is_v1)
{
  rhp_childsa* childsa;

  childsa = (rhp_childsa*)_rhp_malloc(sizeof(rhp_childsa));

  if( childsa == NULL ){
    RHP_BUG("");
    return NULL;
  }
  memset(childsa,0,sizeof(rhp_childsa));

  childsa->tag[0] = '#';
  childsa->tag[1] = 'C';
  childsa->tag[2] = 'S';
  childsa->tag[3] = 'A';

  childsa->side = side;
  rhp_childsa_set_state(childsa,RHP_CHILDSA_STAT_DEFAULT);

  childsa->generate_inb_spi = _rhp_childsa_generate_inb_spi;
  childsa->set_outb_spi = _rhp_childsa_set_outb_spi;

  childsa->set_traffic_selectors = _rhp_childsa_set_traffic_selectors;
  childsa->set_traffic_selector_v1 = _rhp_childsa_set_traffic_selector_v1;

  if( !is_v1 ){
		childsa->setup_sec_params = _rhp_childsa_setup_sec_params;
		childsa->setup_sec_params2 = _rhp_childsa_setup_sec_params2;
  }else{
		childsa->setup_sec_params = _rhp_childsa_setup_sec_params_v1;
		childsa->setup_sec_params2 = NULL;
  }

  childsa->get_esp_impl_ctx = _rhp_childsa_get_esp_impl_ctx;
  childsa->dump = _rhp_childsa_dump;

  childsa->esn = 1;
  childsa->tx_seq = 1;

  childsa->created_time = _rhp_get_time();

  childsa->v1.addr_family = AF_UNSPEC;

	if( side == RHP_IKE_INITIATOR ){
		rhp_ikev2_g_statistics_inc(dc.childsa_initiator_num);
	}else{
		rhp_ikev2_g_statistics_inc(dc.childsa_responder_num);
	}

  RHP_TRC(0,RHPTRCID_CHILDSA_ALLOC,"dx",side,childsa);
  return childsa;
}

static void _rhp_childsa_free(rhp_childsa* childsa)
{

  RHP_TRC(0,RHPTRCID_CHILDSA_FREE,"xLdHH",childsa,"IKE_SIDE",childsa->side,childsa->spi_inb,childsa->spi_outb);

  if( childsa->rekey_dh ){
    rhp_crypto_dh_free(childsa->rekey_dh);
  }

  if( childsa->rekey_nonce_i ){
    rhp_crypto_nonce_free(childsa->rekey_nonce_i);
  }

  if( childsa->rekey_nonce_r ){
    rhp_crypto_nonce_free(childsa->rekey_nonce_r);
  }

  if( childsa->encr ){
    rhp_crypto_encr_free(childsa->encr);
  }

  if( childsa->integ_inb ){
    rhp_crypto_integ_free(childsa->integ_inb);
  }

  if( childsa->integ_outb ){
    rhp_crypto_integ_free(childsa->integ_outb);
  }

  if( childsa->rx_anti_replay.window_mask ){
  	rhp_crypto_bn_free(childsa->rx_anti_replay.window_mask);
  }

  if( childsa->key_material.key_octets ){
    _rhp_free_zero(childsa->key_material.key_octets,childsa->key_material.len);
  }

  {
  	rhp_childsa_ts *tss = childsa->my_tss,*tss_n;
  	while( tss ){
  		tss_n = tss->next;
  		_rhp_free(tss);
  		tss = tss_n;
  	}

  	tss = childsa->peer_tss;
  	while( tss ){
  		tss_n = tss->next;
  		_rhp_free(tss);
  		tss = tss_n;
  	}
  }


	if( childsa->side == RHP_IKE_INITIATOR ){
		rhp_ikev2_g_statistics_dec(dc.childsa_initiator_num);
	}else{
		rhp_ikev2_g_statistics_dec(dc.childsa_responder_num);
	}

  _rhp_free_zero(childsa,sizeof(rhp_childsa));

  RHP_TRC(0,RHPTRCID_CHILDSA_FREE_RTRN,"x",childsa);
  return;
}

void rhp_childsa_destroy(rhp_vpn* vpn,rhp_childsa* childsa)
{
  int err;

  RHP_TRC(0,RHPTRCID_CHILDSA_DESTROY,"xxLdHHLd",vpn,childsa,"IKE_SIDE",childsa->side,childsa->spi_inb,childsa->spi_outb,"CHILDSA_STAT",childsa->state);

  rhp_esp_delete_childsa_to_impl(vpn,childsa);

  if( childsa->timers ){
  	childsa->timers->quit_lifetime_timer(vpn,childsa);
  	_rhp_free(childsa->timers);
  }

  vpn->childsa_delete(vpn,RHP_DIR_OUTBOUND,childsa->spi_outb);

  vpn->childsa_delete(vpn,RHP_DIR_INBOUND,childsa->spi_inb);

  rhp_vpn_inb_childsa_delete(childsa->spi_inb);

  _rhp_childsa_clean_inb_spi(childsa->spi_inb);

  rhp_childsa_set_state(childsa,RHP_CHILDSA_STAT_DEAD);

  err = rhp_vpn_clear_unique_ids_tls_cache(vpn->vpn_realm_id);
  if( err ){
  	RHP_BUG("%d",err);
  }
  err = 0;

  _rhp_childsa_free(childsa);


  RHP_TRC(0,RHPTRCID_CHILDSA_DESTROY_RTRN,"xx",vpn,childsa);
  return;
}

// rlm->lock must be acquired by caller.
rhp_childsa* rhp_childsa_alloc2_r(rhp_res_sa_proposal* res_prop,rhp_vpn_realm* rlm)
{
  int err = 0;
  rhp_childsa* new_childsa = NULL;

  RHP_TRC(0,RHPTRCID_CHILDSA_ALLOC2_R,"x",res_prop);

  new_childsa = rhp_childsa_alloc(RHP_IKE_RESPONDER,0);
  if( new_childsa == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

  memcpy(&(new_childsa->prop.v2),res_prop,sizeof(rhp_res_sa_proposal));

  err = new_childsa->generate_inb_spi(new_childsa);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  new_childsa->set_outb_spi(new_childsa,*((u32*)res_prop->spi));

  if( res_prop->pfs ){

    new_childsa->rekey_dh = rhp_crypto_dh_alloc(res_prop->dhgrp_id);
    if( new_childsa->rekey_dh == NULL ){
      RHP_BUG("");
      goto error;
    }

    if( new_childsa->rekey_dh->generate_key(new_childsa->rekey_dh) ){
      RHP_BUG("");
      goto error;
    }
  }

  new_childsa->integ_inb = rhp_crypto_integ_alloc(res_prop->integ_id);
  if( new_childsa->integ_inb == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  new_childsa->integ_outb = rhp_crypto_integ_alloc(res_prop->integ_id);
  if( new_childsa->integ_outb == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  new_childsa->encr = rhp_crypto_encr_alloc(res_prop->encr_id,res_prop->encr_key_bits);
  if( new_childsa->encr == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  new_childsa->rx_anti_replay.window_mask = rhp_crypto_bn_alloc(rlm->childsa.anti_replay_win_size);
  if( new_childsa->rx_anti_replay.window_mask == NULL ){
    RHP_BUG("");
    goto error;
  }

  new_childsa->rekey_nonce_i = rhp_crypto_nonce_alloc();
  if( new_childsa->rekey_nonce_i == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  new_childsa->rekey_nonce_r = rhp_crypto_nonce_alloc();
  if( new_childsa->rekey_nonce_r == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  if( new_childsa->rekey_nonce_r->generate_nonce(new_childsa->rekey_nonce_r,rhp_gcfg_nonce_size) ){
  	RHP_BUG("");
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_CHILDSA_ALLOC2_R_RTRN,"xx",res_prop,new_childsa);
  return new_childsa;

error:
  if( new_childsa ){
    _rhp_childsa_free(new_childsa);
  }

  RHP_TRC(0,RHPTRCID_CHILDSA_ALLOC2_R_ERR,"x",res_prop);
  return NULL;
}

static int _rhp_childsa_rekey_dhgrp(rhp_vpn* vpn)
{
  rhp_ikesa* ikesa = NULL;

  RHP_TRC(0,RHPTRCID_CHILDSA_REKEY_DHGRP,"x",vpn);

  ikesa = vpn->ikesa_list_head;

  if( ikesa == NULL ){
    RHP_BUG("");
    return -EINVAL;
  }

  RHP_TRC(0,RHPTRCID_CHILDSA_REKEY_DHGRP,"xxd",vpn,ikesa,ikesa->dh->grp);

  return ikesa->dh->grp;
}

rhp_childsa* rhp_childsa_alloc2_i(rhp_vpn* vpn,int pfs)
{
  int err = 0;
  rhp_childsa* new_childsa = NULL;
  int dhgrp;

  RHP_TRC(0,RHPTRCID_CHILDSA_ALLOC2_I,"xd",vpn,pfs);

  new_childsa = rhp_childsa_alloc(RHP_IKE_INITIATOR,0);
  if( new_childsa == NULL ){
    RHP_BUG("");
    err = -ENOMEM;
    goto error;
  }

  err = new_childsa->generate_inb_spi(new_childsa);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  if( pfs ){

    dhgrp = _rhp_childsa_rekey_dhgrp(vpn);
    if( dhgrp < 0 ){
      RHP_BUG("");
      goto error;
    }

    new_childsa->rekey_dh = rhp_crypto_dh_alloc(dhgrp);
    if( new_childsa->rekey_dh == NULL ){
      RHP_BUG("");
      goto error;
    }

    if( new_childsa->rekey_dh->generate_key(new_childsa->rekey_dh) ){
      RHP_BUG("");
      goto error;
    }
  }

  new_childsa->rekey_nonce_i = rhp_crypto_nonce_alloc();

  if( new_childsa->rekey_nonce_i == NULL ){
    RHP_BUG("");
    goto error;
  }

  if( new_childsa->rekey_nonce_i->generate_nonce(new_childsa->rekey_nonce_i,rhp_gcfg_nonce_size) ){
    RHP_BUG("");
    goto error;
  }

  RHP_TRC(0,RHPTRCID_CHILDSA_ALLOC2_I_RTRN,"xx",vpn,new_childsa);
  return new_childsa;

error:
  if( new_childsa ){
    _rhp_childsa_free(new_childsa);
  }
  RHP_TRC(0,RHPTRCID_CHILDSA_ALLOC2_I_ERR,"x",vpn);
  return NULL;
}

void rhp_childsa_set_state(rhp_childsa* childsa,int new_state)
{
	int old_state = childsa->state;
	childsa->state = new_state;

	RHP_TRC(0,RHPTRCID_CHILDSA_STATE,"xLdLd",childsa,"CHILDSA_STAT",old_state,"CHILDSA_STAT",new_state);
	RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_CHILDSA_STATE,"CLL",childsa,"CHILDSA_STAT",old_state,"CHILDSA_STAT",new_state);

	switch( new_state ){
	case RHP_CHILDSA_STAT_MATURE:
	case RHP_IPSECSA_STAT_V1_MATURE:
		if( childsa->side == RHP_IKE_INITIATOR ){
			rhp_ikev2_g_statistics_inc(childsa_established_as_initiator);
		}else{
			rhp_ikev2_g_statistics_inc(childsa_established_as_responder);
		}
		break;
	case RHP_CHILDSA_STAT_LARVAL:
	case RHP_IPSECSA_STAT_V1_1ST_SENT_I:
	case RHP_IPSECSA_STAT_V1_WAIT_COMMIT_I:
	case RHP_IPSECSA_STAT_V1_2ND_SENT_R:
		if( childsa->side == RHP_IKE_INITIATOR ){
			rhp_ikev2_g_statistics_inc(childsa_negotiated_as_initiator);
		}else{
			rhp_ikev2_g_statistics_inc(childsa_negotiated_as_responder);
		}
		break;
	case RHP_CHILDSA_STAT_DEAD:
	case RHP_IPSECSA_STAT_V1_DEAD:
		if( childsa->side == RHP_IKE_INITIATOR ){
			rhp_ikev2_g_statistics_inc(childsa_deleted_as_initiator);
		}else{
			rhp_ikev2_g_statistics_inc(childsa_deleted_as_responder);
		}
		break;
	default:
		break;
	}

	return;
}

void rhp_childsa_free_traffic_selectors(rhp_childsa_ts* my_tss,rhp_childsa_ts* peer_tss)
{
	rhp_childsa_ts *tss_n,*tss;
	int i;

  RHP_TRC(0,RHPTRCID_CFG_CHILDSA_FREE_TRAFFIC_SELECTORS,"xx",my_tss,peer_tss);

	for( i = 0; i < 2;i++){

		if( i == 0 ){
			tss = my_tss;
		}else{
			tss = peer_tss;
		}

		while( tss ){
			tss_n = tss->next;
			_rhp_free(tss);
			tss = tss_n;
		}
	}

  RHP_TRC(0,RHPTRCID_CFG_CHILDSA_FREE_TRAFFIC_SELECTORS_RTRN,"xx",my_tss,peer_tss);
	return;
}

int rhp_childsa_dup_traffic_selectors(rhp_childsa* childsa,
		rhp_childsa_ts** my_tss_r,rhp_childsa_ts** peer_tss_r)
{
	int err;
	rhp_childsa_ts *my_tss_h = NULL,*peer_tss_h = NULL,*tss,*tss2 = NULL,*tss_t = NULL;
	int i;

  RHP_TRC(0,RHPTRCID_CFG_CHILDSA_DUP_TRAFFIC_SELECTORS,"xxxxx",childsa,childsa->my_tss,childsa->peer_tss,my_tss_r,peer_tss_r);

	for( i = 0; i < 2; i++ ){

		tss = NULL;
		tss_t = NULL;

		if( i == 0 && my_tss_r ){
			tss = childsa->my_tss;
		}else if( i == 1 && peer_tss_r ){
			tss = childsa->peer_tss;
		}

		while( tss ){

			tss2 = (rhp_childsa_ts*)_rhp_malloc(sizeof(rhp_childsa_ts));
			if( tss2 == NULL ){
				err = -ENOMEM;
				goto error;
			}

			memcpy(tss2,tss,sizeof(rhp_childsa_ts));

			tss2->next = NULL;

			tss2->flag = tss->flag;

			if( i == 0 ){
				if( my_tss_h == NULL ){
					my_tss_h = tss2;
				}else{
					tss_t->next = tss2;
				}
			}else{
				if( peer_tss_h == NULL ){
					peer_tss_h = tss2;
				}else{
					tss_t->next = tss2;
				}
			}

			tss_t = tss2;
			tss = tss->next;
		}
	}

	if( my_tss_r ){
		*my_tss_r = my_tss_h;
	}
	if( peer_tss_r ){
		*peer_tss_r = peer_tss_h;
	}

  RHP_TRC(0,RHPTRCID_CFG_CHILDSA_DUP_TRAFFIC_SELECTORS_RTRN,"xxx",childsa,(my_tss_r ? *my_tss_r : NULL),(peer_tss_r ? *peer_tss_r : NULL));
	return 0;

error:
	rhp_childsa_free_traffic_selectors(my_tss_h,peer_tss_h);

	RHP_TRC(0,RHPTRCID_CFG_CHILDSA_DUP_TRAFFIC_SELECTORS_ERR,"xE",childsa,err);
	return err;
}


static int _rhp_childsa_cmp_ts_to_ts(rhp_ikev2_traffic_selector* ts_from,rhp_ikev2_traffic_selector* ts_to)
{
	int err;
	rhp_ip_addr addr0;
	rhp_ip_addr addr1;

	if( ts_from == NULL || ts_to == NULL ){
  	RHP_BUG("");
  	return -EINVAL;
  }

	if( ts_to->get_ts_type(ts_to) != ts_from->get_ts_type(ts_from) ){
		return 1;
  }

	if( ts_to->get_protocol(ts_to) != ts_from->get_protocol(ts_from) ){
		return 1;
  }

	if( ts_to->protocol == RHP_PROTO_IP_ICMP ||
			ts_to->protocol == RHP_PROTO_IP_IPV6_ICMP ){

		if( ts_to->get_icmp_start_type(ts_to) != ts_from->get_icmp_start_type(ts_from) ){
			return 1;
    }

		if( ts_to->get_icmp_end_type(ts_to) != ts_from->get_icmp_end_type(ts_from) ){
			return 1;
    }

		if( ts_to->get_icmp_start_code(ts_to) != ts_from->get_icmp_start_code(ts_from) ){
			return 1;
    }

		if( ts_to->get_icmp_end_code(ts_to) != ts_from->get_icmp_end_code(ts_from) ){
			return 1;
    }

  }else{

  	if( ts_to->get_start_port(ts_to) != ts_from->get_start_port(ts_from) ){
  		return 1;
    }

  	if( ts_to->get_end_port(ts_to) != ts_from->get_end_port(ts_from) ){
  		return 1;
  	}
  }

  err = ts_from->get_start_addr(ts_from,&addr0);
  if( err ){
    return err;
  }

  err = ts_to->get_start_addr(ts_to,&addr1);
  if( err ){
    return err;
  }

  if( rhp_ip_addr_eq_ip(&addr0,&addr1) ){
    return 1;
  }

  err = ts_from->get_end_addr(ts_from,&addr0);
  if( err ){
    return err;
  }

  err = ts_to->get_end_addr(ts_to,&addr1);
  if( err ){
    return err;
  }

  if( rhp_ip_addr_eq_ip(&addr0,&addr1) ){
    return 1;
  }

  return 0;
}


static int _rhp_childsa_merge_traffic_selector(rhp_traffic_selector* cfg_ts,
		rhp_ikev2_traffic_selector* ts,rhp_childsa_ts* result)
{

	if( rhp_gcfg_ipv6_disabled &&
			(cfg_ts->ts_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ||
			 ts->get_ts_type(ts) == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE) ){

		return -1;
	}

  if( cfg_ts->ts_type != ts->get_ts_type(ts) ){
    return -1;
  }
  result->ts_or_id_type = cfg_ts->ts_type;

  {
  	u8 ts_protocol = ts->get_protocol(ts);

  	if( cfg_ts->protocol == ts_protocol ){
  		result->protocol = cfg_ts->protocol;
  	}else if( cfg_ts->protocol == 0 && ts_protocol ){
  		result->protocol = ts_protocol;
  	}else if( ts_protocol == 0 && cfg_ts->protocol ){
  		result->protocol = cfg_ts->protocol;
  	}else{
  		return -1;
  	}
  }

  {
  	if( result->protocol == RHP_PROTO_IP_ICMP ||
  			result->protocol == RHP_PROTO_IP_IPV6_ICMP ){

  		u8 ts_start_type = ts->get_icmp_start_type(ts);
  		u8 ts_start_code = ts->get_icmp_start_code(ts);
  		u8 ts_end_type = ts->get_icmp_end_type(ts);
  		u8 ts_end_code = ts->get_icmp_end_code(ts);
  		u8 cfg_ts_start_type = cfg_ts->icmp_start_type;
  		u8 cfg_ts_start_code = cfg_ts->icmp_start_code;
  		u8 cfg_ts_end_type = cfg_ts->icmp_end_type;
  		u8 cfg_ts_end_code = cfg_ts->icmp_end_code;

  		if( (ts_start_type == 0xFF) && (ts_start_code == 0xFF) &&
  				(ts_end_type == 0) && (ts_end_code == 0) ){ // OPAQUE

  			if( ((cfg_ts_start_type == 0) && (cfg_ts_start_code == 0) &&
  					 (cfg_ts_end_type == 0xFF) && (cfg_ts_end_code == 0xFF)) ||
  					((cfg_ts_start_type == 0xFF) && (cfg_ts_start_code == 0xFF) &&
  					 (cfg_ts_end_type == 0) && (cfg_ts_end_code == 0)) ){

  				result->icmp_start_type = ts_start_type;
  				result->icmp_start_code = ts_start_code;
  				result->icmp_end_type = ts_end_type;
  				result->icmp_end_code = ts_end_code;

  			}else{
  				return -1;
  			}

  		}else	if( (cfg_ts_start_type == 0xFF) && (cfg_ts_start_code == 0xFF) &&
  				      (cfg_ts_end_type == 0) && (cfg_ts_end_code == 0) ){ // OPAQUE

  			if( ((ts_start_type == 0) && (ts_start_code == 0) &&
  					 (ts_end_type == 0xFF) && (ts_end_code == 0xFF)) ||
  					((ts_start_type == 0xFF) && (ts_start_code == 0xFF) &&
  					 (ts_end_type == 0) && (ts_end_code == 0)) ){

  				result->icmp_start_type = cfg_ts_start_type;
  				result->icmp_start_code = cfg_ts_start_code;
  				result->icmp_end_type = cfg_ts_end_type;
  				result->icmp_end_code = cfg_ts_end_code;

  			}else{
  				return -1;
  			}

  		}else{

  			if( ts_start_type < cfg_ts_start_type ){
  				result->icmp_start_type = cfg_ts_start_type;
  			}else{
  				result->icmp_start_type = ts_start_type;
  			}

  			if( ts_end_type < cfg_ts_end_type ){
  				result->icmp_end_type = ts_end_type;
  			}else{
  				result->icmp_end_type = cfg_ts_end_type;
  			}

  			if( ts_start_code < cfg_ts_start_code ){
  				result->icmp_start_code = cfg_ts_start_code;
  			}else{
  				result->icmp_start_code = ts_start_code;
  			}

  			if( ts_end_code < cfg_ts_end_code ){
  				result->icmp_end_code = ts_end_code;
  			}else{
  				result->icmp_end_code = cfg_ts_end_code;
  			}

  			if( result->icmp_start_type > result->icmp_end_type ){
  				return -1;
  			}

  			if( result->icmp_start_code > result->icmp_end_code ){
  				return -1;
  			}
  		}

    }else if( result->protocol == RHP_PROTO_IP_UDP  || // UDP
							result->protocol == RHP_PROTO_IP_TCP  || // TCP
							result->protocol == RHP_PROTO_IP_SCTP || // SCTP
							result->protocol == RHP_PROTO_IP_UDPLITE ){ // UDPLite

  		u16 ts_start_port = ntohs(ts->get_start_port(ts));
  		u16 ts_end_port = ntohs(ts->get_end_port(ts));
  		u16 cfg_ts_start_port = ntohs(cfg_ts->start_port);
  		u16 cfg_ts_end_port = ntohs(cfg_ts->end_port);

			if( (ts_start_port == 0xFFFF) && (ts_end_port == 0) ){ // OPAQUE

				if( ((cfg_ts_start_port == 0) && (cfg_ts_end_port == 0xFFFF)) || // ANY
						((cfg_ts_start_port == 0xFFFF) && (cfg_ts_end_port == 0)) ){ // OPQAUE

					result->start_port = htons(ts_start_port);
					result->end_port = htons(ts_end_port);

				}else{
					return -1;
				}

			}else	if( (cfg_ts_start_port == 0xFFFF) && (cfg_ts_end_port == 0) ){ // OPAQUE

					if( ((ts_start_port == 0) && (ts_end_port == 0xFFFF)) || // ANY
							((ts_start_port == 0xFFFF) && (ts_end_port == 0)) ){ // OPQAUE

						result->start_port = htons(cfg_ts_start_port);
						result->end_port = htons(cfg_ts_end_port);

					}else{
						return -1;
					}

			}else{

				if( ts_start_port < cfg_ts_start_port ){
					result->start_port = htons(cfg_ts_start_port);
				}else{
					result->start_port = htons(ts_start_port);
				}

				if( ts_end_port < cfg_ts_end_port ){
					result->end_port = htons(ts_end_port);
				}else{
					result->end_port = htons(cfg_ts_end_port);
				}

				if( ntohs(result->start_port) > ntohs(result->end_port) ){
					return -1;
				}
			}

    }else{

			u16 ts_start_port = ntohs(ts->get_start_port(ts));
			u16 ts_end_port = ntohs(ts->get_end_port(ts));
			u16 cfg_ts_start_port = ntohs(cfg_ts->start_port);
			u16 cfg_ts_end_port = ntohs(cfg_ts->end_port);

			if( ts_start_port != 0 || ts_end_port != 0xFFFF ){
				return -1;
			}

			if( cfg_ts_start_port != 0 || cfg_ts_end_port != 0xFFFF ){
				return -1;
			}

			result->start_port = cfg_ts->start_port;
			result->end_port = cfg_ts->end_port;
		}
  }


  {
  	rhp_ip_addr ts_start_addr;
  	rhp_ip_addr ts_end_addr;
  	rhp_ip_addr* cfg_ts_start_addr;
  	rhp_ip_addr* cfg_ts_end_addr;
  	rhp_ip_addr cfg_ts_end_subnet;

    if( ts->get_start_addr(ts,&ts_start_addr) ){
      return -1;
    }

    if( ts->get_end_addr(ts,&ts_end_addr) ){
      return -1;
    }

    if( !rhp_ip_addr_gt_ip(&ts_start_addr,&ts_end_addr) ){
      return -1;
    }

    if( cfg_ts->ts_is_subnet ){

    	memset(&cfg_ts_end_subnet,0,sizeof(rhp_ip_addr));
    	cfg_ts_start_addr = &(cfg_ts->addr.subnet);

    	if( cfg_ts->addr.subnet.addr_family == AF_INET ){

    		cfg_ts_end_subnet.addr_family = AF_INET;

				rhp_ipv4_subnet_addr_range(cfg_ts->addr.subnet.addr.v4,
						cfg_ts->addr.subnet.netmask.v4,NULL,&(cfg_ts_end_subnet.addr.v4));

    	}else if( cfg_ts->addr.subnet.addr_family == AF_INET6 ){

    		cfg_ts_end_subnet.addr_family = AF_INET6;

    		rhp_ipv6_subnet_addr_range(cfg_ts->addr.subnet.addr.v6,cfg_ts->addr.subnet.prefixlen,
      				NULL,cfg_ts_end_subnet.addr.v6);

    	}else{
        return -1;
    	}

    	cfg_ts_end_addr = &cfg_ts_end_subnet;

    }else {

    	cfg_ts_start_addr = &(cfg_ts->addr.range.start);
    	cfg_ts_end_addr = &(cfg_ts->addr.range.end);
    }


    if( !rhp_ip_addr_gt_ip(&ts_start_addr,cfg_ts_start_addr) ){
    	memcpy(&(result->start_addr),&ts_start_addr,sizeof(rhp_ip_addr));
    }else{
    	memcpy(&(result->start_addr),cfg_ts_start_addr,sizeof(rhp_ip_addr));
    }

    if( !rhp_ip_addr_gt_ip(&ts_end_addr,cfg_ts_end_addr) ){
    	memcpy(&(result->end_addr),cfg_ts_end_addr,sizeof(rhp_ip_addr));
    }else{
    	memcpy(&(result->end_addr),&ts_end_addr,sizeof(rhp_ip_addr));
    }

    if( !rhp_ip_addr_gt_ip(&(result->start_addr),&(result->end_addr)) ){
      return -1;
    }
  }

  return 0;
}

// 1 : NOT matched , 0 : matched , < 0 : error
static int _rhp_childsa_match_traffic_selector(rhp_ikev2_traffic_selector* ts,
		rhp_traffic_selector* cfg_tss,rhp_ikev2_traffic_selector** res_ts_r)
{
  int err = -EINVAL;
  rhp_traffic_selector* cfg_ts = cfg_tss;
  int cmp_res = -1;
  rhp_ikev2_traffic_selector *res_ts_head = NULL,*res_ts_tail = NULL,*res_ts = NULL;
  rhp_childsa_ts result;

  while( cfg_ts ){

  	memset(&result,0,sizeof(rhp_childsa_ts));

  	cmp_res = _rhp_childsa_merge_traffic_selector(cfg_ts,ts,&result);

  	if( cmp_res == 0 ){

    	err = rhp_ikev2_alloc_ts(result.ts_or_id_type,&res_ts);
      if( err ){
        RHP_BUG("");
        goto error;
      }

      res_ts->ts_type = result.ts_or_id_type;
      res_ts->protocol = result.protocol;

      res_ts->start_port = result.start_port;
      res_ts->end_port = result.end_port;

      res_ts->icmp_start_type = result.icmp_start_type;
      res_ts->icmp_end_type = result.icmp_end_type;
      res_ts->icmp_start_code = result.icmp_start_code;
      res_ts->icmp_end_code = result.icmp_end_code;

      memcpy(&(res_ts->start_addr),&(result.start_addr),sizeof(rhp_ip_addr));
      memcpy(&(res_ts->end_addr),&(result.end_addr),sizeof(rhp_ip_addr));

      if( res_ts_head == NULL ){
      	res_ts_head = res_ts;
      }else{
      	res_ts_tail->next = res_ts;
      }
      res_ts_tail = res_ts;

  		rhp_cfg_traffic_selectors_dump_impl("_rhp_childsa_match_traffic_selector.merged_org_ts",cfg_ts,ts,1);
  		rhp_cfg_traffic_selectors_dump_impl("_rhp_childsa_match_traffic_selector.merged_res",NULL,res_ts,1);

  	}else{

  		rhp_cfg_traffic_selectors_dump_impl("_rhp_childsa_match_traffic_selector.not_merged",cfg_ts,ts,1);
  	}

  	cfg_ts = cfg_ts->next;
  }

  if( res_ts_head == NULL ){
    err = 1;
    goto error;
  }

  *res_ts_r = res_ts_head;

  RHP_TRC(0,RHPTRCID_CHILDSA_SEARCH_TRAFFIC_SELECTORS_MATCHED,"xxx",cfg_tss,ts,*res_ts_r);
  return 0;

error:
	res_ts = res_ts_head;
  while( res_ts ){
  	rhp_ikev2_traffic_selector* res_ts_n = res_ts->next;
    _rhp_free(res_ts);
    res_ts = res_ts_n;
  }
  return err;
}

static int _rhp_childsa_add_matched_ts(rhp_ikev2_traffic_selector *res_ts_head,
		rhp_ikev2_traffic_selector** tss_head,rhp_ikev2_traffic_selector** tss_tail)
{
	int err = -EINVAL;
  rhp_ikev2_traffic_selector* dup_ts = NULL;
  rhp_ikev2_traffic_selector* res_ts = res_ts_head;

  while( res_ts ){

  	rhp_ikev2_traffic_selector* res_ts_n = res_ts->next;

  	res_ts->next = NULL;

  	dup_ts = *tss_head;
		while( dup_ts ){

			err = _rhp_childsa_cmp_ts_to_ts(res_ts,dup_ts);

			if( err < 0 ){
				goto error;
			}else if( err == 0 ){
				break;
			}

			dup_ts = dup_ts->next;
		}

		if( dup_ts == NULL ){

			if( *tss_head == NULL ){
				*tss_head = res_ts;
		 }else{
			 (*tss_tail)->next = res_ts;
		 }
		 *tss_tail = res_ts;

		}else{
			_rhp_free(res_ts);
		}

		res_ts = res_ts_n;
  }

  return 0;

error:
	return err;
}

int rhp_childsa_search_traffic_selectors(rhp_traffic_selector* cfg_tss,
		rhp_ikev2_traffic_selector* tss,rhp_ikev2_traffic_selector** res_tss)
{
  int err = -ENOENT;
  rhp_ikev2_traffic_selector* ts = tss;
  rhp_ikev2_traffic_selector* tss_head = NULL;
  rhp_ikev2_traffic_selector* tss_tail = NULL;
  rhp_ikev2_traffic_selector* ts_r_head = NULL;

  rhp_cfg_traffic_selectors_dump("rhp_childsa_search_traffic_selectors",cfg_tss,tss);

  while( ts ){

  	ts_r_head = NULL;

  	err = _rhp_childsa_match_traffic_selector(ts,cfg_tss,&ts_r_head);
  	if( err < 0 ){
  		goto error;
  	}else if( err == 0 ){

  		err = _rhp_childsa_add_matched_ts(ts_r_head,&tss_head,&tss_tail);
  		if( err ){
  			goto error;
  		}
    }

  	ts = ts->next;
  }

  if( tss_head ){

  	*res_tss = tss_head;
  	err = 0;

    rhp_cfg_traffic_selectors_dump("rhp_childsa_search_traffic_selectors.res_tss",cfg_tss,*res_tss);
    RHP_TRC(0,RHPTRCID_CHILDSA_SEARCH_TRAFFIC_SELECTORS_OK,"xxx",cfg_tss,tss,*res_tss);

  }else{
  	err = -ENOENT;
    RHP_TRC(0,RHPTRCID_CHILDSA_SEARCH_TRAFFIC_SELECTORS_NOT_MATCHED_ERR,"xx",cfg_tss,tss);
  }

  return err;

error:
	{
		rhp_ikev2_traffic_selector* ts_r = tss_head;

		while( ts_r ){
			rhp_ikev2_traffic_selector* ts_r_n = ts_r->next;
			_rhp_free(ts_r);
			ts_r = ts_r_n;
		}
	}

	RHP_TRC(0,RHPTRCID_CHILDSA_SEARCH_TRAFFIC_SELECTORS_ERR,"xxE",cfg_tss,tss,err);
  return err;
}


int rhp_childsa_is_any_traffic_selector(rhp_ikev2_traffic_selector* ts)
{
	u8 ts_type = ts->get_ts_type(ts);
	u8 protocol = ts->get_protocol(ts);
	u16 start_port = ts->get_start_port(ts);
	u16 end_port = ts->get_end_port(ts);
	rhp_ip_addr start_addr, end_addr;

	ts->get_start_addr(ts,&start_addr);
	ts->get_end_addr(ts,&end_addr);

	if( protocol ){
	  RHP_TRC(0,RHPTRCID_CHILDSA_IS_ANY_TRAFFIC_SELECTOR_PROTO,"x",ts);
		return 0;
	}

	if( start_port != 0 ){
	  RHP_TRC(0,RHPTRCID_CHILDSA_IS_ANY_TRAFFIC_SELECTOR_START_PORT,"x",ts);
		return 0;
	}

	if( end_port != 0xFFFF ){
	  RHP_TRC(0,RHPTRCID_CHILDSA_IS_ANY_TRAFFIC_SELECTOR_END_PORT,"x",ts);
		return 0;
	}


	if( ts_type == RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE ){

		if( start_addr.addr.v4 != 0 ){
		  RHP_TRC(0,RHPTRCID_CHILDSA_IS_ANY_TRAFFIC_SELECTOR_START_ADDR,"x",ts);
			return 0;
		}

		if( end_addr.addr.v4 != 0xFFFFFFFF ){
		  RHP_TRC(0,RHPTRCID_CHILDSA_IS_ANY_TRAFFIC_SELECTOR_END_ADDR,"x",ts);
			return 0;
		}

	}else if( ts_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){

		u64* b = (u64*)start_addr.addr.v6;

		if( b[0] || b[1] ){
		  RHP_TRC(0,RHPTRCID_CHILDSA_IS_ANY_TRAFFIC_SELECTOR_START_ADDR_V6,"x",ts);
			return 0;
		}

		b = (u64*)end_addr.addr.v6;
		if( b[0] != 0xFFFFFFFFFFFFFFFFUL || b[1] != 0xFFFFFFFFFFFFFFFFUL ){
		  RHP_TRC(0,RHPTRCID_CHILDSA_IS_ANY_TRAFFIC_SELECTOR_END_ADDR_V6,"x",ts);
			return 0;
		}

	}else{

	  RHP_TRC(0,RHPTRCID_CHILDSA_IS_ANY_TRAFFIC_SELECTOR_UNKNOWN_AF,"x",ts);
		return 0;
	}

  RHP_TRC(0,RHPTRCID_CHILDSA_IS_ANY_TRAFFIC_SELECTOR_FOUND,"x",ts);
	return 1;
}

int rhp_childsa_exact_match_traffic_selector_cfg(
		rhp_traffic_selector* cfg_ts,rhp_ikev2_traffic_selector* ts)
{
	u8 ts_protocol;

	if( rhp_gcfg_ipv6_disabled &&
			(cfg_ts->ts_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ||
			 ts->get_ts_type(ts) == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE) ){

		return -1;
	}

  if( cfg_ts->ts_type != ts->get_ts_type(ts) ){
    return -1;
  }

  {
  	ts_protocol = ts->get_protocol(ts);

  	if( cfg_ts->protocol != ts_protocol ){
  		return -1;
  	}
  }

  {
  	if( ts_protocol == RHP_PROTO_IP_ICMP ||
  			ts_protocol == RHP_PROTO_IP_IPV6_ICMP ){

  		u8 ts_start_type = ts->get_icmp_start_type(ts);
  		u8 ts_start_code = ts->get_icmp_start_code(ts);
  		u8 ts_end_type = ts->get_icmp_end_type(ts);
  		u8 ts_end_code = ts->get_icmp_end_code(ts);
  		u8 cfg_ts_start_type = cfg_ts->icmp_start_type;
  		u8 cfg_ts_start_code = cfg_ts->icmp_start_code;
  		u8 cfg_ts_end_type = cfg_ts->icmp_end_type;
  		u8 cfg_ts_end_code = cfg_ts->icmp_end_code;

  		if( ((ts_start_type == 0xFF) && (ts_start_code == 0xFF) && // OPAQUE
  				 (ts_end_type == 0) && (ts_end_code == 0)) ||
  				((ts_start_type <= ts_end_type) && (ts_start_code <= ts_end_code)) ){

				if( ts_start_type != cfg_ts_start_type ||
						ts_start_code != cfg_ts_start_code ||
						ts_end_type != cfg_ts_end_type ||
						ts_end_code != cfg_ts_end_code ){
					return -1;
				}

  		}else{
  			return -1;
  		}

    }else if( ts_protocol == RHP_PROTO_IP_UDP  || // UDP
							ts_protocol == RHP_PROTO_IP_TCP  || // TCP
							ts_protocol == RHP_PROTO_IP_SCTP || // SCTP
							ts_protocol == RHP_PROTO_IP_UDPLITE ){ // UDPLite

  		u16 ts_start_port = ntohs(ts->get_start_port(ts));
  		u16 ts_end_port = ntohs(ts->get_end_port(ts));
  		u16 cfg_ts_start_port = ntohs(cfg_ts->start_port);
  		u16 cfg_ts_end_port = ntohs(cfg_ts->end_port);

			if( ((ts_start_port == 0xFFFF) && (ts_end_port == 0)) || // OPAQUE
					(ts_start_port <= ts_end_port) ){

	  		if( ts_start_port != cfg_ts_start_port ||
	  				ts_end_port != cfg_ts_end_port ){
	  			return -1;
	  		}

			}else{
				return -1;
			}

    }else{

			u16 ts_start_port = ntohs(ts->get_start_port(ts));
			u16 ts_end_port = ntohs(ts->get_end_port(ts));
			u16 cfg_ts_start_port = ntohs(cfg_ts->start_port);
			u16 cfg_ts_end_port = ntohs(cfg_ts->end_port);

			if( ts_start_port <= ts_end_port ){

				if( ts_start_port != cfg_ts_start_port ||
						ts_end_port != cfg_ts_end_port ){
						return -1;
				}

			}else{
				return -1;
			}
		}
  }


  {
  	rhp_ip_addr ts_start_addr;
  	rhp_ip_addr ts_end_addr;
  	rhp_ip_addr* cfg_ts_start_addr;
  	rhp_ip_addr* cfg_ts_end_addr;
  	rhp_ip_addr cfg_ts_end_subnet;

    if( ts->get_start_addr(ts,&ts_start_addr) ){
      return -1;
    }

    if( ts->get_end_addr(ts,&ts_end_addr) ){
      return -1;
    }

    if( !rhp_ip_addr_gt_ip(&ts_start_addr,&ts_end_addr) ){
      return -1;
    }

    if( cfg_ts->ts_is_subnet ){

    	memset(&cfg_ts_end_subnet,0,sizeof(rhp_ip_addr));
    	cfg_ts_start_addr = &(cfg_ts->addr.subnet);

    	if( cfg_ts->addr.subnet.addr_family == AF_INET ){

    		cfg_ts_end_subnet.addr_family = AF_INET;

				rhp_ipv4_subnet_addr_range(cfg_ts->addr.subnet.addr.v4,
						cfg_ts->addr.subnet.netmask.v4,NULL,&(cfg_ts_end_subnet.addr.v4));

    	}else if( cfg_ts->addr.subnet.addr_family == AF_INET6 ){

    		cfg_ts_end_subnet.addr_family = AF_INET6;

    		rhp_ipv6_subnet_addr_range(cfg_ts->addr.subnet.addr.v6,cfg_ts->addr.subnet.prefixlen,
      				NULL,cfg_ts_end_subnet.addr.v6);

    	}else{
        return -1;
    	}

    	cfg_ts_end_addr = &cfg_ts_end_subnet;

    }else {

    	cfg_ts_start_addr = &(cfg_ts->addr.range.start);
    	cfg_ts_end_addr = &(cfg_ts->addr.range.end);
    }

    if( rhp_ip_addr_cmp_ip_only(&ts_start_addr,cfg_ts_start_addr) ||
    		rhp_ip_addr_cmp_ip_only(&ts_end_addr,cfg_ts_end_addr) ){
    	return -1;
    }
  }

  return 0;
}

int rhp_childsa_exact_match_traffic_selectors_cfg(int cfg_tss_num,rhp_traffic_selector* cfg_tss,
		int tss_num,rhp_ikev2_traffic_selector* tss)
{
  int err = -ENOENT;
  rhp_ikev2_traffic_selector* ts = NULL;
  rhp_traffic_selector* cfg_ts = NULL;
  int cfg_ts_is_any = 0, ts_is_any = 0, n = 0;

  rhp_cfg_traffic_selectors_dump("rhp_childsa_exact_match_traffic_selectors_cfg",cfg_tss,tss);

  if( cfg_tss_num != tss_num ){
  	return -1;
  }

  {
		cfg_ts_is_any = 1;

		cfg_ts = cfg_tss;
		while( cfg_ts ){
			if( !rhp_cfg_is_any_traffic_selector(cfg_tss) ){
				cfg_ts_is_any = 0;
				break;
			}
			cfg_ts = cfg_ts->next;
		}
  }

  {
  	ts_is_any = 1;

  	ts = tss;
		while( ts ){

		  if( !rhp_childsa_is_any_traffic_selector(tss) ){
		  	ts_is_any = 0;
		  	break;
		  }

			ts = ts->next;
		}
  }

  if( (cfg_ts_is_any && ts_is_any) ||
  		(!cfg_ts_is_any && ts_is_any) ||
  		(cfg_ts_is_any && !ts_is_any) ){
  	RHP_TRC(0,RHPTRCID_CHILDSA_EXACT_MATCH_TRAFFIC_SELECTORS_ANY_OK,"xxdd",cfg_tss,tss,cfg_ts_is_any,ts_is_any);
  	return 0;
  }

  cfg_ts = cfg_tss;
  while( cfg_ts ){

  	ts = tss;
		while( ts ){

			err = rhp_childsa_exact_match_traffic_selector_cfg(cfg_ts,ts);
			if( !err ){
				n++;
			}

			ts = ts->next;
		}

		cfg_ts = cfg_ts->next;
  }

  if( n == cfg_tss_num ){
  	RHP_TRC(0,RHPTRCID_CHILDSA_EXACT_MATCH_TRAFFIC_SELECTORS_OK,"xxdd",cfg_tss,tss,cfg_ts_is_any,ts_is_any);
  	return 0;
  }

	RHP_TRC(0,RHPTRCID_CHILDSA_EXACT_MATCH_TRAFFIC_SELECTORS_NG,"xxdddd",cfg_tss,tss,cfg_ts_is_any,ts_is_any,n,cfg_tss_num);
  return -1;
}


int rhp_childsa_is_ikev1_any_traffic_selector(rhp_ikev2_payload* id_payload)
{
	rhp_ikev1_id_payload* id = id_payload->ext.v1_id;
	u8 id_type = id->get_id_type(id_payload);
	u8 protocol = id->get_protocol_id(id_payload);
	u16 port = id->get_port(id_payload);
	int ts_addr_len = id->get_id_len(id_payload);
	u8* ts_addr_val = id->get_id(id_payload);
	rhp_ip_addr start_addr, end_addr;

	RHP_TRC(0,RHPTRCID_CHILDSA_IS_IKEV1_ANY_TRAFFIC_SELECTOR,"x",id_payload);

	memset(&start_addr,0,sizeof(rhp_ip_addr));
	memset(&end_addr,0,sizeof(rhp_ip_addr));

	if( protocol ){
		RHP_TRC(0,RHPTRCID_CHILDSA_IS_IKEV1_ANY_TRAFFIC_SELECTOR_NG_PROTO,"xb",id_payload,protocol);
		return 0;
	}

	if( port != 0 ){
		RHP_TRC(0,RHPTRCID_CHILDSA_IS_IKEV1_ANY_TRAFFIC_SELECTOR_NG_PORT,"xw",id_payload,port);
		return 0;
	}


	if( id_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR_RANGE && ts_addr_len == 8 ){

		start_addr.addr_family = AF_INET;
		start_addr.addr.v4 = *((u32*)ts_addr_val);
		end_addr.addr_family = AF_INET;
		end_addr.addr.v4 = *(((u32*)ts_addr_val) + 1);

		if( start_addr.addr.v4 != 0 ){
			RHP_TRC(0,RHPTRCID_CHILDSA_IS_IKEV1_ANY_TRAFFIC_SELECTOR_NG_ADDR_RANGE_V4_1,"x4",id_payload,start_addr.addr.v4);
			return 0;
		}

		if( end_addr.addr.v4 != 0xFFFFFFFF ){
			RHP_TRC(0,RHPTRCID_CHILDSA_IS_IKEV1_ANY_TRAFFIC_SELECTOR_NG_ADDR_RANGE_V4_2,"x4",id_payload,end_addr.addr.v4);
			return 0;
		}

	}else if( id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR_RANGE && ts_addr_len == 32 ){

		u64* b;

		start_addr.addr_family = AF_INET6;
		memcpy(start_addr.addr.v6,ts_addr_val,16);
		end_addr.addr_family = AF_INET6;
		memcpy(end_addr.addr.v6,(ts_addr_val + 16),16);


		b = (u64*)start_addr.addr.v6;

		if( b[0] || b[1] ){
			RHP_TRC(0,RHPTRCID_CHILDSA_IS_IKEV1_ANY_TRAFFIC_SELECTOR_NG_ADDR_RANGE_V6_1,"x6",id_payload,start_addr.addr.v6);
			return 0;
		}

		b = (u64*)end_addr.addr.v6;
		if( b[0] != 0xFFFFFFFFFFFFFFFFUL || b[1] != 0xFFFFFFFFFFFFFFFFUL ){
			RHP_TRC(0,RHPTRCID_CHILDSA_IS_IKEV1_ANY_TRAFFIC_SELECTOR_NG_ADDR_RANGE_V6_2,"x6",id_payload,end_addr.addr.v6);
			return 0;
		}

	}else{

		RHP_TRC(0,RHPTRCID_CHILDSA_IS_IKEV1_ANY_TRAFFIC_SELECTOR_NG_UNKNOWN_ADDR,"x",id_payload);
		return 0;
	}

	RHP_TRC(0,RHPTRCID_CHILDSA_IS_IKEV1_ANY_TRAFFIC_SELECTOR_OK,"x",id_payload);
	return 1;
}

int rhp_childsa_match_ikev1_gre_traffic_selector(rhp_ikev2_payload* id_payload,rhp_ip_addr* gre_addr)
{
	rhp_ikev1_id_payload* id = id_payload->ext.v1_id;
	u8 id_type = id->get_id_type(id_payload);
	u8 protocol = id->get_protocol_id(id_payload);
	u16 port = id->get_port(id_payload);
	int ts_addr_len = id->get_id_len(id_payload);
	u8* ts_addr_val = id->get_id(id_payload);
	rhp_ip_addr start_addr, end_addr;

	RHP_TRC(0,RHPTRCID_CHILDSA_MATCH_IKEV1_GRE_TRAFFIC_SELECTOR,"xx",id_payload,gre_addr);
	rhp_ip_addr_dump("gre_addr",gre_addr);

	memset(&start_addr,0,sizeof(rhp_ip_addr));
	memset(&end_addr,0,sizeof(rhp_ip_addr));

	if( protocol != RHP_PROTO_IP_GRE ){
		RHP_TRC(0,RHPTRCID_CHILDSA_MATCH_IKEV1_GRE_TRAFFIC_SELECTOR_NG_PROTO,"xb",id_payload,protocol);
		return 0;
	}

	if( port != 0 ){
		RHP_TRC(0,RHPTRCID_CHILDSA_MATCH_IKEV1_GRE_TRAFFIC_SELECTOR_NG_PORT,"xw",id_payload,port);
		return 0;
	}


	if( id_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR_RANGE && ts_addr_len == 8 ){

		start_addr.addr_family = AF_INET;
		start_addr.addr.v4 = *((u32*)ts_addr_val);
		end_addr.addr_family = AF_INET;
		end_addr.addr.v4 = *(((u32*)ts_addr_val) + 1);

	}else if( id_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR_SUBNET && ts_addr_len == 8 ){

		u32 netmask = *(((u32*)ts_addr_val) + 1);

		if( netmask != 0xFFFFFFFF ){
			RHP_TRC(0,RHPTRCID_CHILDSA_MATCH_IKEV1_GRE_TRAFFIC_SELECTOR_NG_V4_NETMASK,"x4",id_payload,netmask);
			return 0;
		}

		start_addr.addr_family = AF_INET;
		start_addr.addr.v4 = *((u32*)ts_addr_val);
		end_addr.addr_family = AF_INET;
		end_addr.addr.v4 = *((u32*)ts_addr_val);;

	}else if( id_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR && ts_addr_len == 4 ){

		start_addr.addr_family = AF_INET;
		start_addr.addr.v4 = *((u32*)ts_addr_val);
		end_addr.addr_family = AF_INET;
		end_addr.addr.v4 = *((u32*)ts_addr_val);

	}else if( id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR_RANGE && ts_addr_len == 32 ){

		start_addr.addr_family = AF_INET6;
		memcpy(start_addr.addr.v6,ts_addr_val,16);
		end_addr.addr_family = AF_INET6;
		memcpy(end_addr.addr.v6,(ts_addr_val + 16),16);

	}else if( id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR_SUBNET && ts_addr_len == 32 ){

		u64* netmask = (u64*)(ts_addr_val + 16);

		if( netmask[0] != 0xFFFFFFFFFFFFFFFFUL || netmask[1] != 0xFFFFFFFFFFFFFFFFUL ){
			RHP_TRC(0,RHPTRCID_CHILDSA_MATCH_IKEV1_GRE_TRAFFIC_SELECTOR_NG_V6_NETMASK,"x6",id_payload,(u8*)netmask);
			return 0;
		}

		start_addr.addr_family = AF_INET6;
		memcpy(start_addr.addr.v6,ts_addr_val,16);
		end_addr.addr_family = AF_INET6;
		memcpy(end_addr.addr.v6,ts_addr_val,16);

	}else if( id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR && ts_addr_len == 16 ){

		start_addr.addr_family = AF_INET6;
		memcpy(start_addr.addr.v6,ts_addr_val,16);
		end_addr.addr_family = AF_INET6;
		memcpy(end_addr.addr.v6,ts_addr_val,16);

	}else{

		RHP_TRC(0,RHPTRCID_CHILDSA_MATCH_IKEV1_GRE_TRAFFIC_SELECTOR_NG_UNKNOWN_ADDR,"x",id_payload);
		return 0;
	}

	rhp_ip_addr_dump("start_addr",&start_addr);
	rhp_ip_addr_dump("end_addr",&end_addr);

	if( rhp_ip_addr_cmp_ip_only(&start_addr,gre_addr) ){
		RHP_TRC(0,RHPTRCID_CHILDSA_MATCH_IKEV1_GRE_TRAFFIC_SELECTOR_NG_START_ADDR,"x",id_payload);
		return 0;
	}

	if( rhp_ip_addr_cmp_ip_only(&end_addr,gre_addr) ){
		RHP_TRC(0,RHPTRCID_CHILDSA_MATCH_IKEV1_GRE_TRAFFIC_SELECTOR_NG_END_ADDR,"x",id_payload);
		return 0;
	}

	RHP_TRC(0,RHPTRCID_CHILDSA_MATCH_IKEV1_GRE_TRAFFIC_SELECTOR_OK,"x",id_payload);
	return 1;
}

int rhp_childsa_ikev1_match_traffic_selector_cfg(
		rhp_traffic_selector* cfg_ts,rhp_ikev2_payload* id_payload)
{
	u8 ts_protocol;
	rhp_ikev1_id_payload* id = id_payload->ext.v1_id;
	u8 id_type = id->get_id_type(id_payload);

	RHP_TRC(0,RHPTRCID_CHILDSA_IKEV1_MATCH_TRAFFIC_SELECTOR_CFG,"xxbbd",cfg_ts,id_payload,id_type,cfg_ts->ts_type,cfg_ts->ts_is_subnet);

	if( rhp_gcfg_ipv6_disabled &&
			(cfg_ts->ts_type == RHP_CFG_IKEV1_TS_IPV6_ADDR_RANGE ||
			 id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR 						 ||
			 id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR_SUBNET 		 ||
			 id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR_RANGE) ){

		RHP_TRC(0,RHPTRCID_CHILDSA_IKEV1_MATCH_TRAFFIC_SELECTOR_CFG_V6_DISABLED,"xxdb",cfg_ts,id_payload,rhp_gcfg_ipv6_disabled,id_type);
		return -1;
	}


	if( id_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR ||
			id_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR_SUBNET ||
			id_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR_RANGE ){

	  if( cfg_ts->ts_type != RHP_CFG_IKEV1_TS_IPV4_ADDR_RANGE ){
	  	RHP_TRC(0,RHPTRCID_CHILDSA_IKEV1_MATCH_TRAFFIC_SELECTOR_CFG_ID_TYPE_NOT_MATCH_1,"xxbd",cfg_ts,id_payload,id_type,cfg_ts->ts_type);
	    return -1;
	  }

	}else if( id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR ||
						id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR_SUBNET ||
						id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR_RANGE  ){

		if( cfg_ts->ts_type != RHP_CFG_IKEV1_TS_IPV6_ADDR_RANGE ){
	  	RHP_TRC(0,RHPTRCID_CHILDSA_IKEV1_MATCH_TRAFFIC_SELECTOR_CFG_ID_TYPE_NOT_MATCH_2,"xxbd",cfg_ts,id_payload,id_type,cfg_ts->ts_type);
	    return -1;
	  }

	}else{
  	RHP_TRC(0,RHPTRCID_CHILDSA_IKEV1_MATCH_TRAFFIC_SELECTOR_CFG_ID_TYPE_NOT_MATCH_3,"xxbd",cfg_ts,id_payload,id_type,cfg_ts->ts_type);
    return -1;
	}


  {
  	ts_protocol = id->get_protocol_id(id_payload);

  	if( cfg_ts->protocol != ts_protocol ){
  		RHP_TRC(0,RHPTRCID_CHILDSA_IKEV1_MATCH_TRAFFIC_SELECTOR_CFG_PROTO_NOT_MATCH,"xxbb",cfg_ts,id_payload,cfg_ts->protocol,ts_protocol);
  		return -1;
  	}
  }

  {
  	if( ts_protocol == RHP_PROTO_IP_UDP  || // UDP
				ts_protocol == RHP_PROTO_IP_TCP  || // TCP
				ts_protocol == RHP_PROTO_IP_SCTP || // SCTP
				ts_protocol == RHP_PROTO_IP_UDPLITE ){ // UDPLite

  		u16 ts_port = ntohs(id->get_port(id_payload));
  		u16 cfg_ts_port = ntohs(cfg_ts->start_port);

  		if( ts_port != cfg_ts_port ){
    		RHP_TRC(0,RHPTRCID_CHILDSA_IKEV1_MATCH_TRAFFIC_SELECTOR_CFG_PORT_NOT_MATCH,"xxww",cfg_ts,id_payload,ts_port,cfg_ts_port);
  			return -1;
  		}
  	}
  }


  {
  	int ts_addr_len = id->get_id_len(id_payload);
  	u8* ts_addr_val = id->get_id(id_payload);
  	rhp_ip_addr ts_start_addr;
  	rhp_ip_addr ts_end_addr;
  	rhp_ip_addr* cfg_ts_start_addr;
  	rhp_ip_addr* cfg_ts_end_addr;
  	rhp_ip_addr cfg_ts_end_subnet;

  	memset(&ts_start_addr,0,sizeof(rhp_ip_addr));
  	memset(&ts_end_addr,0,sizeof(rhp_ip_addr));

  	if( id_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR && ts_addr_len == 4 ){

  		ts_start_addr.addr_family = AF_INET;
  		ts_start_addr.addr.v4 = *((u32*)ts_addr_val);
  		ts_end_addr.addr_family = AF_INET;
  		ts_end_addr.addr.v4 = *((u32*)ts_addr_val);

  	}else if( id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR && ts_addr_len == 16 ){

  		ts_start_addr.addr_family = AF_INET6;
  		memcpy(ts_start_addr.addr.v6,ts_addr_val,16);
  		ts_end_addr.addr_family = AF_INET6;
  		memcpy(ts_end_addr.addr.v6,ts_addr_val,16);

  	}else if( id_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR_SUBNET && ts_addr_len == 8 ){

  		ts_start_addr.addr_family = AF_INET;
  		ts_start_addr.addr.v4 = *((u32*)ts_addr_val);

  		ts_end_addr.addr_family = AF_INET;
  		ts_end_addr.addr.v4 = *((u32*)ts_addr_val);
			rhp_ipv4_subnet_addr_range(ts_start_addr.addr.v4,
					*(((u32*)ts_addr_val) + 1),NULL,&(ts_end_addr.addr.v4));

  	}else if( id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR_SUBNET && ts_addr_len == 32 ){

  		int prefix_len;

  		ts_start_addr.addr_family = AF_INET6;
  		memcpy(ts_start_addr.addr.v6,ts_addr_val,16);

  		prefix_len = rhp_ipv6_netmask_to_prefixlen((ts_addr_val + 16));

  		ts_end_addr.addr_family = AF_INET6;
  		rhp_ipv6_subnet_addr_range(ts_start_addr.addr.v6,prefix_len,
					NULL,ts_end_addr.addr.v6);

  	}else if( id_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR_RANGE && ts_addr_len == 8 ){

  		ts_start_addr.addr_family = AF_INET;
  		ts_start_addr.addr.v4 = *((u32*)ts_addr_val);
  		ts_end_addr.addr_family = AF_INET;
  		ts_end_addr.addr.v4 = *(((u32*)ts_addr_val) + 1);

  	}else if( id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR_RANGE && ts_addr_len == 32 ){

  		ts_start_addr.addr_family = AF_INET6;
  		memcpy(ts_start_addr.addr.v6,ts_addr_val,16);
  		ts_end_addr.addr_family = AF_INET6;
  		memcpy(ts_end_addr.addr.v6,(ts_addr_val + 16),16);

  	}else{

  		RHP_TRC(0,RHPTRCID_CHILDSA_IKEV1_MATCH_TRAFFIC_SELECTOR_CFG_ID_TYPE_OR_LEN_NOT_MATCH,"xxbd",cfg_ts,id_payload,id_type,ts_addr_len);
  		return -1;
  	}

  	rhp_ip_addr_dump("ts_start_addr",&ts_start_addr);
  	rhp_ip_addr_dump("ts_end_addr",&ts_end_addr);

    if( !rhp_ip_addr_gt_ip(&ts_start_addr,&ts_end_addr) ){
    	RHP_TRC(0,RHPTRCID_CHILDSA_IKEV1_MATCH_TRAFFIC_SELECTOR_CFG_GT_IP_NG,"xx",cfg_ts,id_payload);
      return -1;
    }

    if( cfg_ts->ts_is_subnet ){

    	memset(&cfg_ts_end_subnet,0,sizeof(rhp_ip_addr));
    	cfg_ts_start_addr = &(cfg_ts->addr.subnet);

    	if( cfg_ts->addr.subnet.addr_family == AF_INET ){

    		cfg_ts_end_subnet.addr_family = AF_INET;

				rhp_ipv4_subnet_addr_range(cfg_ts->addr.subnet.addr.v4,
						cfg_ts->addr.subnet.netmask.v4,NULL,&(cfg_ts_end_subnet.addr.v4));

    	}else if( cfg_ts->addr.subnet.addr_family == AF_INET6 ){

    		cfg_ts_end_subnet.addr_family = AF_INET6;

    		rhp_ipv6_subnet_addr_range(cfg_ts->addr.subnet.addr.v6,cfg_ts->addr.subnet.prefixlen,
      				NULL,cfg_ts_end_subnet.addr.v6);

    	}else{
      	RHP_TRC(0,RHPTRCID_CHILDSA_IKEV1_MATCH_TRAFFIC_SELECTOR_CFG_SUBNET_ADDR_AF_NG,"xxd",cfg_ts,id_payload,cfg_ts->addr.subnet.addr_family);
        return -1;
    	}

    	cfg_ts_end_addr = &cfg_ts_end_subnet;

    }else {

    	cfg_ts_start_addr = &(cfg_ts->addr.range.start);
    	cfg_ts_end_addr = &(cfg_ts->addr.range.end);
    }

  	rhp_ip_addr_dump("cfg_ts_start_addr",cfg_ts_start_addr);
  	rhp_ip_addr_dump("cfg_ts_end_addr",cfg_ts_end_addr);

    if( rhp_ip_addr_cmp_ip_only(&ts_start_addr,cfg_ts_start_addr) ||
    		rhp_ip_addr_cmp_ip_only(&ts_end_addr,cfg_ts_end_addr) ){
    	RHP_TRC(0,RHPTRCID_CHILDSA_IKEV1_MATCH_TRAFFIC_SELECTOR_CFG_NOT_MATCH,"xx",cfg_ts,id_payload);
    	return -1;
    }
  }

	RHP_TRC(0,RHPTRCID_CHILDSA_IKEV1_MATCH_TRAFFIC_SELECTOR_CFG_OK,"xx",cfg_ts,id_payload);
  return 0;
}

int rhp_childsa_ikev1_match_traffic_selectors_cfg(int cfg_tss_num,rhp_traffic_selector* cfg_tss,
		rhp_ikev2_payload* id_payload,rhp_ip_addr* gre_addr)
{
  int err = -ENOENT;
  rhp_traffic_selector* cfg_ts = NULL;
  int cfg_ts_is_any = 0, ts_is_any = 0;

  rhp_cfg_traffic_selectors_dump("rhp_childsa_ikev1_match_traffic_selectors_cfg",cfg_tss,NULL);


  {
  	cfg_ts_is_any = 1;

    cfg_ts = cfg_tss;
    while( cfg_ts ){

      if( !rhp_cfg_is_any_traffic_selector(cfg_tss) ){
      	cfg_ts_is_any = 0;
      	break;
      }

  		cfg_ts = cfg_ts->next;
    }
  }

  if( rhp_childsa_is_ikev1_any_traffic_selector(id_payload)){
  	ts_is_any = 1;
  }

  if( (cfg_ts_is_any && ts_is_any) ||
  		(!cfg_ts_is_any && ts_is_any) ||
  		(cfg_ts_is_any && !ts_is_any) ){

  	if( gre_addr ){

  		if( rhp_gcfg_ikev1_ipsecsa_gre_strictly_match_ts &&
  				!rhp_childsa_match_ikev1_gre_traffic_selector(id_payload,gre_addr) ){
  			RHP_TRC(0,RHPTRCID_CHILDSA_IKEV1_MATCH_TRAFFIC_SELECTORS_ANY_MATCH_GRE_NG,"xxdd",cfg_tss,id_payload,cfg_ts_is_any,ts_is_any);
  			goto error;
  		}

  		id_payload->ext.v1_id->gre_ts_auto_generated = 1;
  	}

  	RHP_TRC(0,RHPTRCID_CHILDSA_IKEV1_MATCH_TRAFFIC_SELECTORS_ANY_OK,"xxdd",cfg_tss,id_payload,cfg_ts_is_any,ts_is_any);
  	return 0;
  }

  cfg_ts = cfg_tss;
  while( cfg_ts ){

		err = rhp_childsa_ikev1_match_traffic_selector_cfg(cfg_ts,id_payload);
		if( !err ){
			break;
		}

		cfg_ts = cfg_ts->next;
  }

  if( cfg_ts ){
  	RHP_TRC(0,RHPTRCID_CHILDSA_IKEV1_MATCH_TRAFFIC_SELECTORS_OK,"xxddd",cfg_tss,id_payload,cfg_ts_is_any,ts_is_any,cfg_tss_num);
  	return 0;
  }

error:
	RHP_TRC(0,RHPTRCID_CHILDSA_IKEV1_MATCH_TRAFFIC_SELECTORS_NG,"xxddd",cfg_tss,id_payload,cfg_ts_is_any,ts_is_any,cfg_tss_num);
  return -1;
}


// This means 'ts' is included within 'cfg_ts'.
int rhp_childsa_ts_included_cfg(rhp_traffic_selector* cfg_ts,rhp_ikev2_traffic_selector* ts)
{
	u8 ts_protocol = ts->get_protocol(ts);
	u8 ts_type;

  if( cfg_ts->ts_type != (ts_type = ts->get_ts_type(ts)) ){
  	RHP_TRC(0,RHPTRCID_CHILDSA_CONFIRM_TRAFFIC_SELECTOR_NOT_MATCHED_TS_TYPE,"xxbb",cfg_ts,ts,cfg_ts->ts_type,ts_type);
    return -1;
  }

  {
  	if( cfg_ts->protocol == ts_protocol ){
  		// OK!
  	}else if( cfg_ts->protocol == 0 && ts_protocol ){
  		// OK!
  	}else{
    	RHP_TRC(0,RHPTRCID_CHILDSA_CONFIRM_TRAFFIC_SELECTOR_NOT_MATCHED_PROTO,"xxbb",cfg_ts,ts,cfg_ts->protocol,ts_protocol);
  		return -1;
  	}
  }

  {
  	if( ts_protocol == RHP_PROTO_IP_ICMP ||
  			ts_protocol == RHP_PROTO_IP_IPV6_ICMP ){

  		u8 ts_start_type = ts->get_icmp_start_type(ts);
  		u8 ts_start_code = ts->get_icmp_start_code(ts);
  		u8 ts_end_type = ts->get_icmp_end_type(ts);
  		u8 ts_end_code = ts->get_icmp_end_code(ts);
  		u8 cfg_ts_start_type = cfg_ts->icmp_start_type;
  		u8 cfg_ts_start_code = cfg_ts->icmp_start_code;
  		u8 cfg_ts_end_type = cfg_ts->icmp_end_type;
  		u8 cfg_ts_end_code = cfg_ts->icmp_end_code;

  		if( (ts_start_type == 0xFF) && (ts_start_code == 0xFF) && (ts_end_type == 0) && (ts_end_code == 0) ){ // OPAQUE

  			if( ((cfg_ts_start_type == 0) && (cfg_ts_start_code == 0) && (cfg_ts_end_type == 0xFF) && (cfg_ts_end_code == 0xFF)) ||
  					((cfg_ts_start_type == 0xFF) && (cfg_ts_start_code == 0xFF) && (cfg_ts_end_type == 0) && (cfg_ts_end_code == 0)) ){

  				// OK!

  			}else{
  	    	RHP_TRC(0,RHPTRCID_CHILDSA_CONFIRM_TRAFFIC_SELECTOR_NOT_MATCHED_ICMP_OPAQUE,"xxbbbbbbbb",cfg_ts,ts,ts_start_type,cfg_ts_start_type,ts_start_code,cfg_ts_start_code,ts_end_type,cfg_ts_end_type,ts_end_code,cfg_ts_end_code);
  				return -1;
  			}

  		}else{

  			if( (ts_start_type >= cfg_ts_start_type) && (ts_end_type <= cfg_ts_end_type) ){
  				// OK!
  			}else{
  	    	RHP_TRC(0,RHPTRCID_CHILDSA_CONFIRM_TRAFFIC_SELECTOR_NOT_MATCHED_ICMP,"xxbbbbbbbb",cfg_ts,ts,ts_start_type,cfg_ts_start_type,ts_start_code,cfg_ts_start_code,ts_end_type,cfg_ts_end_type,ts_end_code,cfg_ts_end_code);
  				return -1;
  			}
  		}

    }else if( 	ts_protocol == RHP_PROTO_IP_UDP				|| // UDP
								ts_protocol == RHP_PROTO_IP_TCP   		|| // TCP
								ts_protocol == RHP_PROTO_IP_SCTP 			|| // SCTP
								ts_protocol == RHP_PROTO_IP_UDPLITE ){ // UDPLite

  		u16 ts_start_port = ntohs(ts->get_start_port(ts));
  		u16 ts_end_port = ntohs(ts->get_end_port(ts));
  		u16 cfg_ts_start_port = ntohs(cfg_ts->start_port);
  		u16 cfg_ts_end_port = ntohs(cfg_ts->end_port);

			if( (ts_start_port == 0xFFFF) && (ts_end_port == 0) ){ // OPAQUE

				if( ((cfg_ts_start_port == 0) && (cfg_ts_end_port == 0xFFFF)) || // ANY
						((cfg_ts_start_port == 0xFFFF) && (cfg_ts_end_port == 0)) ){ // OPQAUE

					// OK!

				}else{
  	    	RHP_TRC(0,RHPTRCID_CHILDSA_CONFIRM_TRAFFIC_SELECTOR_NOT_MATCHED_PORT_OPAQUE,"xxWWWW",cfg_ts,ts,htons(ts_start_port),htons(ts_end_port),htons(cfg_ts_start_port),htons(cfg_ts_end_port));
					return -1;
				}

			}else{

				if( (ts_start_port >= cfg_ts_start_port) && (ts_end_port <= cfg_ts_end_port)  ){

					// OK!

				}else{
  	    	RHP_TRC(0,RHPTRCID_CHILDSA_CONFIRM_TRAFFIC_SELECTOR_NOT_MATCHED_PORT,"xxWWWW",cfg_ts,ts,htons(ts_start_port),htons(ts_end_port),htons(cfg_ts_start_port),htons(cfg_ts_end_port));
					return -1;
				}
			}

    }else{

			u16 ts_start_port = ntohs(ts->get_start_port(ts));
			u16 ts_end_port = ntohs(ts->get_end_port(ts));

			if( ts_start_port != 0 || ts_end_port != 0xFFFF ){
	    	RHP_TRC(0,RHPTRCID_CHILDSA_CONFIRM_TRAFFIC_SELECTOR_NOT_MATCHED_PORT_2,"xxWW",cfg_ts,ts,htons(ts_start_port),htons(ts_end_port));
				return -1;
			}
		}
  }


  {
  	rhp_ip_addr ts_start_addr;
  	rhp_ip_addr ts_end_addr;
  	rhp_ip_addr* cfg_ts_start_addr;
  	rhp_ip_addr* cfg_ts_end_addr;
  	rhp_ip_addr cfg_ts_end_subnet;

    if( ts->get_start_addr(ts,&ts_start_addr) ){
    	RHP_TRC(0,RHPTRCID_CHILDSA_CONFIRM_TRAFFIC_SELECTOR_NO_TS_START_ADDR,"xx",cfg_ts,ts);
      return -1;
    }

    if( ts->get_end_addr(ts,&ts_end_addr) ){
    	RHP_TRC(0,RHPTRCID_CHILDSA_CONFIRM_TRAFFIC_SELECTOR_NO_TS_END_ADDR,"xx",cfg_ts,ts);
      return -1;
    }

    if( !rhp_ip_addr_gt_ip(&ts_start_addr,&ts_end_addr) ){
    	RHP_TRC(0,RHPTRCID_CHILDSA_CONFIRM_TRAFFIC_SELECTOR_NOT_MATCHED_START_ADDR_NOT_GT_END_ADDR,"xx",cfg_ts,ts);
    	rhp_ip_addr_dump("rhp_childsa_ts_included_cfg.ts_start_addr",&ts_start_addr);
    	rhp_ip_addr_dump("rhp_childsa_ts_included_cfg.ts_end_addr",&ts_end_addr);
      return -1;
    }

    if( cfg_ts->ts_is_subnet ){

    	memset(&cfg_ts_end_subnet,0,sizeof(rhp_ip_addr));
    	cfg_ts_start_addr = &(cfg_ts->addr.subnet);

    	if( cfg_ts->addr.subnet.addr_family == AF_INET ){

    		cfg_ts_end_subnet.addr_family = AF_INET;

				rhp_ipv4_subnet_addr_range(cfg_ts->addr.subnet.addr.v4,
						cfg_ts->addr.subnet.netmask.v4,NULL,&(cfg_ts_end_subnet.addr.v4));

    	}else if( cfg_ts->addr.subnet.addr_family == AF_INET6 ){

    		cfg_ts_end_subnet.addr_family = AF_INET6;

    		rhp_ipv6_subnet_addr_range(cfg_ts->addr.subnet.addr.v6,cfg_ts->addr.subnet.prefixlen,
    				NULL,cfg_ts_end_subnet.addr.v6);

    	}else{
      	RHP_TRC(0,RHPTRCID_CHILDSA_CONFIRM_TRAFFIC_SELECTOR_NOT_SUP_IP_VER,"xxd",cfg_ts,ts,cfg_ts->addr.subnet.addr_family);
        return -1;
    	}

    	cfg_ts_end_addr = &cfg_ts_end_subnet;

    	rhp_ip_addr_dump("rhp_childsa_ts_included_cfg.cfg_ts->is_subnet: cfg_ts_start_addr",cfg_ts_start_addr);
    	rhp_ip_addr_dump("rhp_childsa_ts_included_cfg.cfg_ts->is_subnet: cfg_ts_end_addr",cfg_ts_end_addr);

    }else {

    	cfg_ts_start_addr = &(cfg_ts->addr.range.start);
    	cfg_ts_end_addr = &(cfg_ts->addr.range.end);

    	rhp_ip_addr_dump("rhp_childsa_ts_included_cfg.cfg_ts->is_range: cfg_ts_start_addr",cfg_ts_start_addr);
    	rhp_ip_addr_dump("rhp_childsa_ts_included_cfg.cfg_ts->is_range: cfg_ts_end_addr",cfg_ts_end_addr);
    }


    if( rhp_ip_addr_gteq_ip(&ts_start_addr,cfg_ts_start_addr) ){
    	RHP_TRC(0,RHPTRCID_CHILDSA_CONFIRM_TRAFFIC_SELECTOR_NOT_MATCHED_CFG_START_ADDR_GTEQ_TS_START_ADDR,"xx",cfg_ts,ts);
    	rhp_ip_addr_dump("rhp_childsa_ts_included_cfg.&ts_start_addr",&ts_start_addr);
    	rhp_ip_addr_dump("rhp_childsa_ts_included_cfg.cfg_ts_start_addr",cfg_ts_start_addr);
    	return -1;
    }

    if( !rhp_ip_addr_gt_ip(&ts_end_addr,cfg_ts_end_addr) ){
    	RHP_TRC(0,RHPTRCID_CHILDSA_CONFIRM_TRAFFIC_SELECTOR_NOT_MATCHED_CFG_END_ADDR_NOT_GT_TS_END_ADDR,"xx",cfg_ts,ts);
    	rhp_ip_addr_dump("rhp_childsa_ts_included_cfg.&ts_end_addr",&ts_end_addr);
    	rhp_ip_addr_dump("rhp_childsa_ts_included_cfg.cfg_ts_end_addr",cfg_ts_end_addr);
    	return -1;
    }
  }

	RHP_TRC(0,RHPTRCID_CHILDSA_CONFIRM_TRAFFIC_SELECTOR_OK_MATCHED,"xx",cfg_ts,ts);
  return 0;
}

// This means 'ts' is included within 'ts_cmp'.
int rhp_childsa_ts_included(rhp_childsa_ts* ts_cmp, rhp_childsa_ts* ts)
{
  if( ts_cmp->ts_or_id_type != ts->ts_or_id_type ){
  	RHP_TRC(0,RHPTRCID_CHILDSA_TS_INCLUDED_NOT_MATCHED_TS_TYPE,"xxbb",ts_cmp,ts,ts_cmp->ts_or_id_type,ts->ts_or_id_type);
    return -1;
  }

  {
  	if( ts_cmp->protocol == ts->protocol ){
  		// OK!
  	}else if( ts_cmp->protocol == 0 && ts->protocol ){
  		// OK!
  	}else{
    	RHP_TRC(0,RHPTRCID_CHILDSA_TS_INCLUDED_NOT_MATCHED_PROTO,"xxbb",ts_cmp,ts,ts_cmp->protocol,ts->protocol);
  		return -1;
  	}
  }

  {
  	if( ts->protocol == RHP_PROTO_IP_ICMP ||
  			ts->protocol == RHP_PROTO_IP_IPV6_ICMP ){

  		if( (ts->icmp_start_type == 0xFF) && (ts->icmp_start_code == 0xFF) && (ts->icmp_end_type == 0) && (ts->icmp_end_code == 0) ){ // OPAQUE

  			if( ((ts_cmp->icmp_start_type == 0) && (ts_cmp->icmp_start_code == 0) && (ts_cmp->icmp_end_type == 0xFF) && (ts_cmp->icmp_end_code == 0xFF)) ||
  					((ts_cmp->icmp_start_type == 0xFF) && (ts_cmp->icmp_start_code == 0xFF) && (ts_cmp->icmp_end_type == 0) && (ts_cmp->icmp_end_code == 0)) ){

  				// OK!

  			}else{
  	    	RHP_TRC(0,RHPTRCID_CHILDSA_TS_INCLUDED_NOT_MATCHED_ICMP_OPAQUE,"xxbbbbbbbb",ts_cmp,ts,ts->icmp_start_type,ts_cmp->icmp_start_type,ts->icmp_start_code,ts_cmp->icmp_start_code,ts->icmp_end_type,ts_cmp->icmp_end_type,ts->icmp_end_code,ts_cmp->icmp_end_code);
  				return -1;
  			}

  		}else{

  			if( (ts->icmp_start_type >= ts_cmp->icmp_start_type) && (ts->icmp_end_type <= ts_cmp->icmp_end_type) ){
  				// OK!
  			}else{
  	    	RHP_TRC(0,RHPTRCID_CHILDSA_TS_INCLUDED_NOT_MATCHED_ICMP,"xxbbbbbbbb",ts_cmp,ts,ts->icmp_start_type,ts_cmp->icmp_start_type,ts->icmp_start_code,ts_cmp->icmp_start_code,ts->icmp_end_type,ts_cmp->icmp_end_type,ts->icmp_end_code,ts_cmp->icmp_end_code);
  				return -1;
  			}
  		}

    }else if( 	ts->protocol == RHP_PROTO_IP_UDP			|| // UDP
								ts->protocol == RHP_PROTO_IP_TCP   		|| // TCP
								ts->protocol == RHP_PROTO_IP_SCTP 		|| // SCTP
								ts->protocol == RHP_PROTO_IP_UDPLITE ){ // UDPLite

  		u16 ts_start_port = ntohs(ts->start_port);
  		u16 ts_end_port = ntohs(ts->end_port);
  		u16 ts_cmp_start_port = ntohs(ts_cmp->start_port);
  		u16 ts_cmp_end_port = ntohs(ts_cmp->end_port);

			if( (ts_start_port == 0xFFFF) && (ts_end_port == 0) ){ // OPAQUE

				if( ((ts_cmp_start_port == 0) && (ts_cmp_end_port == 0xFFFF)) || // ANY
						((ts_cmp_start_port == 0xFFFF) && (ts_cmp_end_port == 0)) ){ // OPQAUE

					// OK!

				}else{
  	    	RHP_TRC(0,RHPTRCID_CHILDSA_TS_INCLUDED_NOT_MATCHED_PORT_OPAQUE,"xxWWWW",ts_cmp,ts,htons(ts_start_port),htons(ts_end_port),htons(ts_cmp_start_port),htons(ts_cmp_end_port));
					return -1;
				}

			}else{

				if( (ts_start_port >= ts_cmp_start_port) && (ts_end_port <= ts_cmp_end_port)  ){

					// OK!

				}else{
  	    	RHP_TRC(0,RHPTRCID_CHILDSA_TS_INCLUDED_NOT_MATCHED_PORT,"xxWWWW",ts_cmp,ts,htons(ts_start_port),htons(ts_end_port),htons(ts_cmp_start_port),htons(ts_cmp_end_port));
					return -1;
				}
			}

    }else{

			u16 ts_start_port = ntohs(ts->start_port);
			u16 ts_end_port = ntohs(ts->end_port);

			if( ts_start_port != 0 || ts_end_port != 0xFFFF ){
	    	RHP_TRC(0,RHPTRCID_CHILDSA_TS_INCLUDED_NOT_MATCHED_PORT_2,"xxWW",ts_cmp,ts,htons(ts_start_port),htons(ts_end_port));
				return -1;
			}
		}
  }


  {
    rhp_ip_addr_dump("rhp_childsa_ts_included.ts_start_addr",&(ts->start_addr));
  	rhp_ip_addr_dump("rhp_childsa_ts_included.ts_end_addr",&(ts->end_addr));
  	rhp_ip_addr_dump("rhp_childsa_ts_included.ts_cmp_start_addr",&(ts_cmp->start_addr));
  	rhp_ip_addr_dump("rhp_childsa_ts_included.ts_cmp_end_addr",&(ts_cmp->end_addr));


    if( !rhp_ip_addr_gt_ip(&(ts->start_addr),&(ts->end_addr)) ){
    	RHP_TRC(0,RHPTRCID_CHILDSA_TS_INCLUDED_NOT_MATCHED_START_ADDR_NOT_GT_END_ADDR,"xx",ts_cmp,ts);
      return -1;
    }

    if( rhp_ip_addr_gteq_ip(&(ts->start_addr),&(ts_cmp->start_addr)) ){
    	RHP_TRC(0,RHPTRCID_CHILDSA_TS_INCLUDED_NOT_MATCHED_CMP_START_ADDR_GTEQ_TS_START_ADDR,"xx",ts_cmp,ts);
    	return -1;
    }

    if( !rhp_ip_addr_gt_ip(&(ts->end_addr),&(ts_cmp->end_addr)) ){
    	RHP_TRC(0,RHPTRCID_CHILDSA_TS_INCLUDED_NOT_MATCHED_CMP_END_ADDR_NOT_GT_TS_END_ADDR,"xx",ts_cmp,ts);
    	return -1;
    }
  }

	RHP_TRC(0,RHPTRCID_CHILDSA_TS_INCLUDED_OK,"xx",ts_cmp,ts);
  return 0;
}

int rhp_childsa_check_traffic_selectors_cfg(rhp_traffic_selector* cfg_tss,rhp_ikev2_traffic_selector* tss)
{
  rhp_ikev2_traffic_selector *ts = tss;
  rhp_traffic_selector* cfg_ts;
  int cmp_res;

  if( ts == NULL ){
  	RHP_BUG("");
    return -ENOENT;
  }

  rhp_cfg_traffic_selectors_dump("rhp_childsa_check_traffic_selectors_cfg",cfg_tss,tss);

  while( ts ){

    cfg_ts = cfg_tss;

    if( cfg_ts == NULL ){
   	  RHP_BUG("");
      return -ENOENT;
    }

    while( cfg_ts ){

      cmp_res = rhp_childsa_ts_included_cfg(cfg_ts,ts);

      if( cmp_res == 0 ){
      	break;
      }

      cfg_ts = cfg_ts->next;
    }

    if( cfg_ts == NULL ){

    	RHP_TRC(0,RHPTRCID_CHILDSA_CHECK_TRAFFIC_SELECTORS_NOT_MATCHED_ERR,"xx",cfg_tss,tss);

      return -ENOENT;
    }

    ts = ts->next;
  }

	RHP_TRC(0,RHPTRCID_CHILDSA_CHECK_TRAFFIC_SELECTORS_OK,"xx",cfg_tss,tss);
  return 0;
}


void rhp_childsa_calc_pmtu(rhp_vpn* vpn,rhp_vpn_realm* rlm,rhp_childsa* childsa)
{
	int err = -EINVAL;
	int pmtu;
	int iv_len,block_len,icv_len;
	int rlm_locked = 0;

  RHP_TRC(0,RHPTRCID_CHILDSA_CALC_PMTU,"xxx",vpn,rlm,childsa);

	if( childsa->encr == NULL || childsa->integ_outb == NULL ){
		err = -EINVAL;
    RHP_TRC(0,RHPTRCID_CHILDSA_CALC_PMTU_CHILDSA_NOT_READY,"xxxxxx",vpn,rlm,vpn->rlm,childsa,childsa->encr,childsa->integ_outb);
    goto error;
	}

  if( rlm == NULL ){

  	rlm = vpn->rlm;

  	RHP_LOCK(&(rlm->lock));
    rlm_locked = 1;

    if( !_rhp_atomic_read(&(rlm->is_active)) ){
    	err = -EINVAL;
      RHP_TRC(0,RHPTRCID_CHILDSA_CALC_PMTU_RLM_NOT_ACTIVE,"xxx",vpn,vpn->rlm,childsa);
    	goto error;
    }
  }

  RHP_TRC(0,RHPTRCID_CHILDSA_CALC_PMTU_2,"xxxddddLdddLdd",vpn,rlm,childsa,vpn->local.if_info.mtu,rhp_gcfg_min_pmtu,rlm->internal_ifc->fixed_mtu,rlm->internal_ifc->bridge_def_mtu,"VPN_ENCAP",vpn->internal_net_info.encap_mode_c,vpn->nat_t_info.use_nat_t_port,vpn->nat_t_info.exec_nat_t,"AF",vpn->local.if_info.addr_family,(vpn->radius.rx_accept_attrs ? vpn->radius.rx_accept_attrs->framed_mtu : 0));


  if( vpn->eap.eap_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS &&
  		vpn->radius.rx_accept_attrs && vpn->radius.rx_accept_attrs->framed_mtu ){

  	pmtu = vpn->radius.rx_accept_attrs->framed_mtu;

  }else if( rlm->internal_ifc && rlm->internal_ifc->bridge_def_mtu ){

  	pmtu = rlm->internal_ifc->bridge_def_mtu;

  }else if( rlm->internal_ifc && rlm->internal_ifc->fixed_mtu ){

  	pmtu = rlm->internal_ifc->fixed_mtu;

  }else{

  	pmtu = vpn->local.if_info.mtu;
	}
  childsa->pmtu_default = pmtu;


	if( vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_ETHERIP ){

		pmtu -= (sizeof(rhp_proto_etherip) + sizeof(rhp_proto_ether));

		if( vpn->local.if_info.addr_family == AF_INET ){
			pmtu -= sizeof(rhp_proto_ip_v4);
		}else if( vpn->local.if_info.addr_family == AF_INET6 ){
			pmtu -= sizeof(rhp_proto_ip_v6);
		}

	}else if( vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_IPIP ){

		if( vpn->local.if_info.addr_family == AF_INET ){
			pmtu -= sizeof(rhp_proto_ip_v4);
		}else if( vpn->local.if_info.addr_family == AF_INET6 ){
			pmtu -= sizeof(rhp_proto_ip_v6);
		}

	}else if( vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_GRE ){

		pmtu -= sizeof(rhp_proto_gre_csum);

		if( vpn->local.if_info.addr_family == AF_INET ){
			pmtu -= sizeof(rhp_proto_ip_v4);
		}else if( vpn->local.if_info.addr_family == AF_INET6 ){
			pmtu -= sizeof(rhp_proto_ip_v6);
		}
	}

  if( vpn->nat_t_info.use_nat_t_port || vpn->nat_t_info.exec_nat_t ){

		pmtu -= sizeof(rhp_proto_udp);
	}

	pmtu -= sizeof(rhp_proto_esp);


	iv_len = childsa->encr->get_iv_len(childsa->encr);
	if( iv_len < 0 ){
		RHP_BUG("%d",iv_len);
		err = -EINVAL;
		goto error;
	}

	icv_len = childsa->integ_outb->get_output_len(childsa->integ_outb);
	if( icv_len < 0 ){
		RHP_BUG("%d",icv_len);
		err = -EINVAL;
		goto error;
	}

	pmtu -= (iv_len + icv_len);

	block_len = childsa->encr->get_block_len(childsa->encr);
	if( block_len < 0 ){
		RHP_BUG("%d",block_len);
		err = -EINVAL;
		goto error;
	}

	pmtu -= pmtu % block_len;

	if( childsa->tfc_padding ){
		pmtu -= rlm->childsa.tfc_padding_max_size;
	}

	pmtu -= 2; // Pad Len + Nxt Hdr

	if( pmtu < 0 ){
		RHP_BUG("%d",pmtu);
		goto error;
	}


	if( rlm->internal_ifc &&
			rlm->internal_ifc->fixed_mtu && (pmtu > rlm->internal_ifc->fixed_mtu) ){

		RHP_TRC(0,RHPTRCID_CHILDSA_CALC_PMTU_FIXED_MTU,"xxxdd",vpn,rlm,childsa,pmtu,rlm->internal_ifc->fixed_mtu);
		pmtu = rlm->internal_ifc->fixed_mtu;
	}

	if( pmtu < rhp_gcfg_min_pmtu ){

		RHP_TRC(0,RHPTRCID_CHILDSA_CALC_PMTU_MIN_MTU,"xxxdd",vpn,rlm,childsa,pmtu,rhp_gcfg_min_pmtu);
		pmtu = rhp_gcfg_min_pmtu;
	}

	childsa->pmtu_cache = pmtu;

	if( rlm && rlm_locked ){
  	RHP_UNLOCK(&(rlm->lock));
	}

  RHP_TRC(0,RHPTRCID_CHILDSA_CALC_PMTU_RTRN,"xxxd",vpn,rlm,childsa,childsa->pmtu_cache);
	return;

error:

	childsa->pmtu_cache = childsa->pmtu_default;

	if( rlm && rlm_locked ){
  	RHP_UNLOCK(&(rlm->lock));
	}

	RHP_TRC(0,RHPTRCID_CHILDSA_CALC_PMTU_ERR,"xxxdE",vpn,rlm,childsa,childsa->pmtu_cache,err);
	return;
}


int rhp_childsa_ts_dup(rhp_childsa_ts* from,rhp_childsa_ts* to)
{
	memcpy(to,from,sizeof(rhp_childsa_ts));
	to->next = NULL;
	return 0;
}

int rhp_childsa_ts_addr_included(rhp_childsa_ts* ts,rhp_ip_addr* addr)
{
	rhp_ip_addr_dump("csa_addr_is_included: addr",addr);
	rhp_ip_addr_dump("csa_addr_is_included: ts->start_addr",&(ts->start_addr));
	rhp_ip_addr_dump("csa_addr_is_included: ts->end_addr",&(ts->end_addr));

	if( !rhp_ip_addr_gteq_ip(addr,&(ts->start_addr)) &&
			!rhp_ip_addr_lteq_ip(addr,&(ts->end_addr))){

		if( addr->addr_family == AF_INET ){
			RHP_TRC(0,RHPTRCID_CHILDSA_TS_ADDR_IS_INCLUDED_INCLUDED,"xx4",ts,addr,addr->addr.v4);
		}else if( addr->addr_family == AF_INET6 ){
			RHP_TRC(0,RHPTRCID_CHILDSA_TS_ADDR_IS_INCLUDED_INCLUDED_V6,"xx6",ts,addr,addr->addr.v6);
		}
		return 1;
	}

	if( addr->addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_CHILDSA_TS_ADDR_IS_INCLUDED_NOT_INCLUDED,"xx4",ts,addr,addr->addr.v4);
	}else if( addr->addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_CHILDSA_TS_ADDR_IS_INCLUDED_NOT_INCLUDED_V6,"xx6",ts,addr,addr->addr.v6);
	}
	return 0;
}

int rhp_childsa_ts_replace_addrs(rhp_childsa_ts* ts,rhp_ip_addr* start_addr,rhp_ip_addr* end_addr)
{
	if( start_addr ){

		rhp_ip_addr_dump("rhp_childsa_ts_replace_addrs: ts->start_addr",&(ts->start_addr));
		rhp_ip_addr_dump("rhp_childsa_ts_replace_addrs: start_addr",start_addr);

		memcpy(&(ts->start_addr),start_addr,sizeof(rhp_ip_addr));
	}

	if( end_addr ){

		rhp_ip_addr_dump("rhp_childsa_ts_replace_addrs: ts->end_addr",&(ts->end_addr));
		rhp_ip_addr_dump("rhp_childsa_ts_replace_addrs: end_addr",end_addr);

		memcpy(&(ts->end_addr),end_addr,sizeof(rhp_ip_addr));
	}
	return 0;
}

void rhp_childsa_ts_dump(char* tag,rhp_childsa_ts* ts)
{
	if( ts ){
		RHP_TRC(0,RHPTRCID_CHILDSA_TS_DUMP,"sxdLbLbWWbbbbbd",tag,ts,ts->is_v1,"PROTO_IKE_TS",ts->ts_or_id_type,"PROTO_IP",ts->protocol,ts->start_port,ts->end_port,ts->icmp_start_type,ts->icmp_end_type,ts->icmp_start_code,ts->icmp_end_code,ts->flag,ts->v1_prefix_len);
		rhp_ip_addr_dump("start_addr",&(ts->start_addr));
		rhp_ip_addr_dump("end_addr",&(ts->end_addr));
	}else{
		RHP_TRC(0,RHPTRCID_CHILDSA_TS_DUMP_NULL,"sx",tag,ts);
	}
	return;
}


int rhp_childsa_ts_cmp(rhp_childsa_ts* ts0, rhp_childsa_ts* ts1)
{
  if( ts0->is_v1 != ts1->is_v1 ){
  	return -1;
  }

  if( ts0->ts_or_id_type != ts1->ts_or_id_type ){
  	return -1;
  }

  if( ts0->protocol != ts1->protocol ){
  	return -1;
  }

  if( ts0->protocol == RHP_PROTO_IP_ICMP || ts0->protocol == RHP_PROTO_IP_IPV6_ICMP ){

    if( ts0->icmp_start_type != ts1->icmp_start_type ){
    	return -1;
    }

    if( ts0->icmp_end_type != ts1->icmp_end_type ){
    	return -1;
    }

    if( ts0->icmp_start_code != ts1->icmp_start_code ){
    	return -1;
    }

    if( ts0->icmp_end_code != ts1->icmp_end_code ){
    	return -1;
    }

  }else{

		if( ts0->start_port != ts1->start_port ){
			return -1;
		}

		if( ts0->end_port != ts1->end_port ){
			return -1;
		}
  }

  if( rhp_ip_addr_cmp_ip_only(&(ts0->start_addr),&(ts1->start_addr)) ){
  	return -1;
  }

  if( rhp_ip_addr_cmp_ip_only(&(ts0->end_addr),&(ts1->end_addr)) ){
  	return -1;
  }

  return 0;
}

int rhp_childsa_ts_is_any(rhp_childsa_ts* ts)
{
	if( ts->protocol ){
		return 0;
	}

	if( ts->start_port != 0 ){
		return 0;
	}

	if( ts->end_port != 0xFFFF ){
		return 0;
	}

	if( (ts->is_v1 && (ts->ts_or_id_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR_RANGE || ts->ts_or_id_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR_SUBNET)) ||
			ts->ts_or_id_type == RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE ){

		if( ts->start_addr.addr.v4 != 0 ){
			return 0;
		}

		if( ts->end_addr.addr.v4 != 0xFFFFFFFF ){
			return 0;
		}

	}else if( (ts->is_v1 && (ts->ts_or_id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR_RANGE || ts->ts_or_id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR_SUBNET)) ||
						ts->ts_or_id_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){

		u64* b = (u64*)(ts->start_addr.addr.v6);

		if( b[0] || b[1] ){
			return 0;
		}

		b = (u64*)(ts->end_addr.addr.v6);
		if( b[0] != 0xFFFFFFFFFFFFFFFFUL || b[1] != 0xFFFFFFFFFFFFFFFFUL ){
			return 0;
		}

	}else{

		return 0;
	}

	return 1;
}

int rhp_childsa_ts_cmp_same_or_any(rhp_childsa_ts* ts,rhp_childsa_ts* tss_head)
{
	rhp_childsa_ts* ts_d = tss_head;

  RHP_TRC(0,RHPTRCID_CHILDSA_TS_CMP_TS2TSS_SAME_OR_ANY,"xx",ts,tss_head);

	while( ts_d ){

		if( ts != ts_d &&
				ts_d->flag != RHP_CHILDSA_TS_NOT_USED ){

			if( ts->is_v1 == ts_d->is_v1 &&
					ts->ts_or_id_type == ts_d->ts_or_id_type &&
					rhp_childsa_ts_is_any(ts_d) ){
				RHP_TRC(0,RHPTRCID_CHILDSA_TS_CMP_TS2TSS_SAME_OR_ANY_ANY,"xx",ts,ts_d);
				return 0;
			}

			if( !rhp_childsa_ts_cmp(ts,ts_d) ){
				RHP_TRC(0,RHPTRCID_CHILDSA_TS_CMP_TS2TSS_SAME_OR_ANY_SAME,"xx",ts,ts_d);
				return 0;
			}

			{
				u8 ts_d_proto = ts_d->protocol;

				if( ts_d_proto == 0 &&
						rhp_childsa_ts_addr_included(ts_d,&(ts->start_addr)) &&
						rhp_childsa_ts_addr_included(ts_d,&(ts->end_addr)) ){
					RHP_TRC(0,RHPTRCID_CHILDSA_TS_CMP_TS2TSS_SAME_OR_ANY_ADDR_INCLUDED_AND_PROTO_ANY,"xx",ts,ts_d);
					return 0;
				}
			}
		}

		ts_d = ts_d->next;
	}

  RHP_TRC(0,RHPTRCID_CHILDSA_TS_CMP_TS2TSS_SAME_OR_ANY_RTRN,"x",ts);
	return 1;
}

