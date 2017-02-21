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
#include <sys/capability.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/errqueue.h>

#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_wthreads.h"
#include "rhp_config.h"
#include "rhp_netmng.h"
#include "rhp_protocol.h"
#include "rhp_packet.h"
#include "rhp_vpn.h"

rhp_mutex_t rhp_pkt_lock_statistics;
u64 rhp_pkt_statistics_alloc_no_pool = 0;
u64 rhp_pkt_statistics_alloc_large_pkt = 0;


static rhp_packet* _rhp_pkt_alloc_impl(int len,int head_room_len,int tail_room_len)
{
  rhp_packet* pkt = NULL;
  int buffer_len = len + head_room_len  + tail_room_len;

  pkt = (rhp_packet*)_rhp_malloc(sizeof(rhp_packet));
  if( pkt == NULL ){
    RHP_BUG("");
    goto error;
  }

  memset(pkt,0,sizeof(rhp_packet));

  pkt->head = (u8*)_rhp_malloc( buffer_len );
  if( pkt->head == NULL ){
    RHP_BUG("%d",buffer_len);
    goto error;
  }

#ifdef RHP_PKT_DEBUG
  memset(pkt->head,0,buffer_len);
#endif // RHP_PKT_DEBUG

  pkt->tag[0] = '#';
  pkt->tag[1] = 'R';
  pkt->tag[2] = 'P';
  pkt->tag[3] = 'K';

  pkt->buffer_len = buffer_len;
  pkt->len = 0;
  pkt->data = pkt->tail = (pkt->head + head_room_len);
  pkt->end = pkt->head + buffer_len;

  _rhp_atomic_init(&(pkt->refcnt));
  _rhp_atomic_set(&(pkt->refcnt),1);
  
  pkt->rx_if_index = -1;
  pkt->fixed_tx_if_index = -1;

  pkt->dmy_pkt_esp_tx_seq = 0;

	pkt->nhrp.nbma_addr_family = AF_UNSPEC;

  RHP_TRC_FREQ(0,RHPTRCID_PKT_ALLOC_RAW,"dddxxxxx",len,head_room_len,tail_room_len,pkt,pkt->head,pkt->data,pkt->tail,pkt->end);
  return pkt;

error:
  if( pkt ){
    if( pkt->head ){
      _rhp_free(pkt->head);
    }
    _rhp_free(pkt);
  }
  return NULL;
}

static void _rhp_pkt_reset(rhp_packet* pkt,int head_room_len)
{
	pkt->tag[0] = '%';

  pkt->len = 0;
  pkt->data = pkt->tail = (pkt->head + head_room_len);
  pkt->end = pkt->head + pkt->buffer_len;

  _rhp_atomic_set(&(pkt->refcnt),1);

  pkt->next = NULL;
  pkt->type = 0;
  pkt->l2.raw = NULL;
  pkt->l3.raw = NULL;
  pkt->l4.raw = NULL;
  pkt->app.raw = NULL;
  pkt->tx_ifc = NULL;
  pkt->rx_if_index = -1;
  pkt->fixed_tx_if_index = -1;
  pkt->rx_ifc = NULL;
  pkt->destructor = NULL;
  pkt->cookie_checked = 0;
  pkt->cookie_checked_rx_mesg = NULL;
  pkt->encap_mode = 0;
  pkt->esp_tx_vpn_ref = NULL;
  pkt->esp_rx_vpn_ref = NULL;
  pkt->esp_seq = 0;
  pkt->esp_tx_spi_outb = 0;
  pkt->esp_rx_spi_inb = 0;
  pkt->process_packet = NULL;
  pkt->dmy_pkt_esp_tx_seq = 0;
  pkt->esp_pkt_pend_done_ctx = NULL;
  pkt->esp_pkt_pend_done = NULL;
  pkt->priv = NULL;
  pkt->nat_t_keep_alive = 0;
  pkt->is_critical = 0;
  pkt->v6_rlm_lladdr = 0;
  pkt->ikev2_non_esp_marker = 0;
  pkt->ikev2_keep_alive = 0;
  pkt->mobike_verified = 0;
  pkt->dmvpn_enabled = 0;
  pkt->ikev2_exchange_type = 0;
  pkt->v1_mode_cfg_pending = 0;
  pkt->pcaped = 0;

  if( pkt->ikev1_pkt_hash ){
  	_rhp_free(pkt->ikev1_pkt_hash);
  	pkt->ikev1_pkt_hash = NULL;
  	pkt->ikev1_pkt_hash_len = 0;
  }

#if defined(RHP_PKT_DBG_IKEV2_RETRANS_TEST) || defined(RHP_PKT_DBG_IKEV2_RETRANS_FRAG_TEST)
  pkt->ikev2_retrans_pkt = RHP_PKT_IKEV2_RETRANS_NONE;
#endif // RHP_PKT_DBG_IKEV2_RETRANS_TEST

  {
  	rhp_packet_frag *pktfrag = pkt->frags.head;

  	while( pktfrag ){

  		rhp_packet_frag* pktfrag_n = pktfrag->next;

  		rhp_pkt_frag_free(pktfrag);

  		pktfrag = pktfrag_n;
  	}

  	pkt->frags.head = NULL;
  	pkt->frags.tail = NULL;
  	pkt->frags.frags_num = 0;
  }

  {
  	pkt->nhrp.nbma_addr_family = AF_UNSPEC;
  	pkt->nhrp.nbma_src_addr = NULL;
  	pkt->nhrp.nbma_dst_addr = NULL;
  }

  return;
}

static int _rhp_pkt_pool_cur_num = 0;
static rhp_packet_q _rhp_pkt_pool;
static rhp_mutex_t _rhp_pkt_pool_lock;

int rhp_pkt_get_pool_cur_num()
{
	int ret;
	RHP_LOCK(&_rhp_pkt_pool_lock);
	ret = _rhp_pkt_pool_cur_num;
	RHP_UNLOCK(&_rhp_pkt_pool_lock);
	return ret;
}

static void _rhp_pkt_pool_init()
{
	int i;

	for( i = 0; i < rhp_gcfg_packet_buffer_pool_init_num; i++){

		rhp_packet* pkt;

		pkt = _rhp_pkt_alloc_impl(rhp_gcfg_max_packet_default_size,RHP_PKT_HEADER_ROOM,RHP_PKT_TAIL_ROOM);
		if( pkt ){

			pkt->tag[0] = '%';

			RHP_LOCK(&_rhp_pkt_pool_lock);

			_rhp_pkt_q_enq(&_rhp_pkt_pool,pkt);
			_rhp_pkt_pool_cur_num++;

			RHP_UNLOCK(&_rhp_pkt_pool_lock);

		}else{
			RHP_BUG("");
			break;
		}
	}

	RHP_TRC(0,RHPTRCID_PACKET_INIT_POOL,"dddd",_rhp_pkt_pool_cur_num,rhp_gcfg_packet_buffer_pool_init_num,rhp_gcfg_packet_buffer_pool_max_num,rhp_gcfg_max_packet_default_size);

	return;
}

static rhp_packet* _rhp_pkt_alloc2(int len,int no_room)
{
	rhp_packet* pkt;

	if( (!no_room && (len > rhp_gcfg_max_packet_default_size)) ||
			(no_room && ((len - RHP_PKT_HEADER_ROOM - RHP_PKT_TAIL_ROOM) > rhp_gcfg_max_packet_default_size) )){

		RHP_TRC_FREQ(0,RHPTRCID_PKT_ALLOC_LARGER_DEF_SIZE,"dd",len,rhp_gcfg_max_packet_default_size);

		RHP_LOCK(&rhp_pkt_lock_statistics);
		rhp_pkt_statistics_alloc_large_pkt++;
		RHP_UNLOCK(&rhp_pkt_lock_statistics);

		goto alloc_new;
	}

	RHP_LOCK(&_rhp_pkt_pool_lock);

	if( _rhp_pkt_pool_cur_num <= 0 ){

		RHP_UNLOCK(&_rhp_pkt_pool_lock);
		RHP_TRC_FREQ(0,RHPTRCID_PKT_ALLOC_NO_POOL,"dd",len,_rhp_pkt_pool_cur_num);

		RHP_LOCK(&rhp_pkt_lock_statistics);
		rhp_pkt_statistics_alloc_no_pool++;
		RHP_UNLOCK(&rhp_pkt_lock_statistics);

		goto alloc_new;
	}

	pkt = _rhp_pkt_q_deq(&_rhp_pkt_pool);
	if( pkt == NULL ){
		RHP_BUG("");
	}else{
		_rhp_pkt_pool_cur_num--;
		pkt->tag[0] = '#';
	}

	RHP_UNLOCK(&_rhp_pkt_pool_lock);

	if( pkt ){
		RHP_TRC_FREQ(0,RHPTRCID_PKT_ALLOC_FROM_POOL,"ddddxxxxxd",pkt->buffer_len,no_room,RHP_PKT_HEADER_ROOM,RHP_PKT_TAIL_ROOM,pkt,pkt->head,pkt->data,pkt->tail,pkt->end,_rhp_pkt_pool_cur_num);
	}else{
		RHP_BUG("");
	}

	return pkt;

alloc_new:
	if( no_room ){
		return _rhp_pkt_alloc_impl(len,0,0);
	}else{
		return _rhp_pkt_alloc_impl(len,RHP_PKT_HEADER_ROOM,RHP_PKT_TAIL_ROOM);
	}
}

rhp_packet* rhp_pkt_alloc(int len)
{
	return _rhp_pkt_alloc2(len,0);
}

static int _rhp_pkt_return_to_pool(rhp_packet* pkt)
{
	if( pkt->buffer_len < (rhp_gcfg_max_packet_default_size
												 + RHP_PKT_HEADER_ROOM + RHP_PKT_TAIL_ROOM) ){
		return -1;
	}

	if( pkt->buffer_len > (rhp_gcfg_max_packet_size
												 + RHP_PKT_HEADER_ROOM + RHP_PKT_TAIL_ROOM) ){
		return -1;
	}

	_rhp_pkt_reset(pkt,RHP_PKT_HEADER_ROOM);

	RHP_LOCK(&_rhp_pkt_pool_lock);

	if( _rhp_pkt_pool_cur_num >= rhp_gcfg_packet_buffer_pool_max_num ){
		RHP_UNLOCK(&_rhp_pkt_pool_lock);
		return -1;
	}

	_rhp_pkt_q_enq(&_rhp_pkt_pool,pkt);
	_rhp_pkt_pool_cur_num++;

	RHP_UNLOCK(&_rhp_pkt_pool_lock);

  RHP_TRC_FREQ(0,RHPTRCID_PKT_RETURN_TO_POOL,"xdd",pkt,pkt->buffer_len,_rhp_pkt_pool_cur_num);
	return 0;
}


int rhp_pkt_realloc(rhp_packet* origpkt,int head_room_len,int tail_room_len)
{
  int len = origpkt->len + head_room_len + tail_room_len;
  u8* new_buf;
  u8* dst;

  if( origpkt->buffer_len >= len ){

    if( (origpkt->data - origpkt->head) < head_room_len ){

      dst = origpkt->head + head_room_len;
      memmove(dst,origpkt->data,origpkt->len);

      origpkt->data = dst;
      origpkt->tail = dst + origpkt->len;
    }

    goto proto_reset;
  }

  new_buf = (u8*)_rhp_malloc(len);
  if( new_buf == NULL ){
    RHP_BUG("%d",len);
    goto error;
  }

  dst = new_buf + head_room_len;
  memcpy(dst,origpkt->data,origpkt->len);

  _rhp_free(origpkt->head);

  origpkt->head = new_buf;
  origpkt->end = new_buf + len;
  origpkt->buffer_len = len;
  origpkt->data = dst;
  origpkt->tail = dst + origpkt->len;

proto_reset:
  origpkt->l2.raw = NULL;
  origpkt->l3.raw = NULL;
  origpkt->l4.raw = NULL;
  origpkt->app.raw = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_PKT_REALLOC,"xdd",origpkt,head_room_len,tail_room_len);
  return 0;

error:
  return -ENOMEM;
}

int rhp_pkt_frag_realloc(rhp_packet_frag* origfrag,int head_room_len,int tail_room_len)
{
  int len = origfrag->len + head_room_len + tail_room_len;
  u8* new_buf;
  u8* dst;

  if( origfrag->buffer_len >= len ){

    if( (origfrag->data - origfrag->head) < head_room_len ){

      dst = origfrag->head + head_room_len;
      memmove(dst,origfrag->data,origfrag->len);

      origfrag->data = dst;
      origfrag->tail = dst + origfrag->len;
    }

    goto proto_reset;
  }

  new_buf = (u8*)_rhp_malloc(len);
  if( new_buf == NULL ){
    RHP_BUG("%d",len);
    goto error;
  }

  dst = new_buf + head_room_len;
  memcpy(dst,origfrag->data,origfrag->len);

  _rhp_free(origfrag->head);

  origfrag->head = new_buf;
  origfrag->end = new_buf + len;
  origfrag->buffer_len = len;
  origfrag->data = dst;
  origfrag->tail = dst + origfrag->len;

proto_reset:
  origfrag->l2.raw = NULL;
  origfrag->l3.raw = NULL;
  origfrag->l4.raw = NULL;
  origfrag->app.raw = NULL;

  RHP_TRC_FREQ(0,RHPTRCID_PKT_FRAG_REALLOC,"xdd",origfrag,head_room_len,tail_room_len);
  return 0;

error:
  return -ENOMEM;
}

rhp_packet_frag* rhp_pkt_frag_alloc(int len,int head_room_len,int tail_room_len)
{
	rhp_packet_frag* pktfrag = NULL;
  int buffer_len = len + head_room_len  + tail_room_len;

  pktfrag = (rhp_packet_frag*)_rhp_malloc(sizeof(rhp_packet_frag));
  if( pktfrag == NULL ){
    RHP_BUG("");
    goto error;
  }

  memset(pktfrag,0,sizeof(rhp_packet_frag));

  pktfrag->head = (u8*)_rhp_malloc( buffer_len );
  if( pktfrag->head == NULL ){
    RHP_BUG("%d",buffer_len);
    goto error;
  }

#ifdef RHP_PKT_DEBUG
  memset(pktfrag->head,0,buffer_len);
#endif // RHP_PKT_DEBUG

  pktfrag->tag[0] = '#';
  pktfrag->tag[1] = 'P';
  pktfrag->tag[2] = 'F';
  pktfrag->tag[3] = 'R';

  pktfrag->buffer_len = buffer_len;
  pktfrag->len = 0;
  pktfrag->data = pktfrag->tail = (pktfrag->head + head_room_len);
  pktfrag->end = pktfrag->head + buffer_len;

  RHP_TRC_FREQ(0,RHPTRCID_PKT_FRAG_ALLOC,"dddxxxxx",len,head_room_len,tail_room_len,pktfrag,pktfrag->head,pktfrag->data,pktfrag->tail,pktfrag->end);
  return pktfrag;

error:
  if( pktfrag ){
    if( pktfrag->head ){
      _rhp_free(pktfrag->head);
    }
    _rhp_free(pktfrag);
  }
  return NULL;
}

void rhp_pkt_frag_free(rhp_packet_frag* pktfrag)
{
	if( pktfrag->head ){
		_rhp_free(pktfrag->head);
	}
	_rhp_free(pktfrag);
}

u8* rhp_pkt_frag_expand_tail(rhp_packet_frag* origfrag,int tail_room_len)
{
  u8* p;

  RHP_TRC_FREQ(0,RHPTRCID_PKT_FRAG_PUSH_OR_EXPAND_TAIL,"xd",origfrag,tail_room_len);

  p = _rhp_pkt_frag_push(origfrag,tail_room_len);
  if( p == NULL ){

    int head_room_len = ((u8*)origfrag->data) - ((u8*)origfrag->head);
    int l2_offset  = ( origfrag->l2.raw == NULL ? 0 : ((u8*)origfrag->l2.raw) - ((u8*)origfrag->head) );
    int l3_offset  = ( origfrag->l3.raw == NULL ? 0 : ((u8*)origfrag->l3.raw) - ((u8*)origfrag->head) );
    int l4_offset  = ( origfrag->l4.raw == NULL ? 0 : ((u8*)origfrag->l4.raw) - ((u8*)origfrag->head) );
    int app_offset = ( origfrag->app.raw == NULL ? 0 : ((u8*)origfrag->app.raw) - ((u8*)origfrag->head) );

    RHP_TRC_FREQ(0,RHPTRCID_PKT_PUSH_OR_EXPAND_TAIL_NEW,"x",origfrag);

    if( rhp_pkt_frag_realloc(origfrag,head_room_len,tail_room_len) ){
      RHP_BUG("");
      return NULL;
    }

    origfrag->l2.raw  = (l2_offset ? (origfrag->head + l2_offset) : NULL);
    origfrag->l3.raw  = (l3_offset ? (origfrag->head + l3_offset) : NULL);
    origfrag->l4.raw  = (l4_offset ? (origfrag->head + l4_offset) : NULL);
    origfrag->app.raw = (app_offset ? (origfrag->head + app_offset) : NULL);

    p = _rhp_pkt_frag_push(origfrag,tail_room_len);
  }

  RHP_TRC_FREQ(0,RHPTRCID_PKT_FRAG_PUSH_OR_EXPAND_TAIL_RTRN,"xx",origfrag,p);
  return p;
}

rhp_packet_frag* rhp_pkt_frag_dup(rhp_packet_frag* origfrag)
{
	rhp_packet_frag* pktfrag;

	pktfrag = rhp_pkt_frag_alloc(origfrag->buffer_len,0,0);
  if( pktfrag == NULL ){
    RHP_BUG("");
    goto error;
  }

  memcpy(pktfrag->head,origfrag->head,origfrag->buffer_len);

  if( origfrag->data ){
    pktfrag->data = pktfrag->head + (origfrag->data - origfrag->head);
  }

  if( origfrag->tail ){
    pktfrag->tail = pktfrag->head + (origfrag->tail - origfrag->head);
  }

  if( origfrag->l2.raw ){
    pktfrag->l2.raw = pktfrag->head + (origfrag->l2.raw - origfrag->head);
  }

  if( origfrag->l3.raw ){
    pktfrag->l3.raw = pktfrag->head + (origfrag->l3.raw - origfrag->head);
  }

  if( origfrag->l4.raw ){
    pktfrag->l4.raw = pktfrag->head + (origfrag->l4.raw - origfrag->head);
  }

  if( origfrag->app.raw ){
    pktfrag->app.raw = pktfrag->head + (origfrag->app.raw - origfrag->head);
  }

  pktfrag->len = origfrag->len;

  RHP_TRC_FREQ(0,RHPTRCID_PKT_FRAG_DUP,"xx",origfrag,pktfrag);

  return pktfrag;

error:
  return NULL;
}

rhp_packet* rhp_pkt_dup(rhp_packet* origpkt)
{
  rhp_packet* pkt;
	rhp_packet_frag *origfrag = origpkt->frags.head,
			*pktfrag_head = NULL,*pktfrag_p = NULL, *pktfrag;

	while( origfrag ){

		pktfrag = rhp_pkt_frag_dup(origfrag);
		if( pktfrag == NULL ){
			RHP_BUG("");
			goto error;
		}

		if( pktfrag_p == NULL ){
			pktfrag_head = pktfrag;
		}else{
			pktfrag_p->next = pktfrag;
		}
		pktfrag_p = pktfrag;

		origfrag = origfrag->next;
	}


  pkt = _rhp_pkt_alloc2(origpkt->buffer_len,1);
  if( pkt == NULL ){
    RHP_BUG("");
    goto error;
  }

  pkt->type = origpkt->type;
  pkt->encap_mode = origpkt->encap_mode;
  
  memcpy(pkt->head,origpkt->head,origpkt->buffer_len);

  if( origpkt->data ){
    pkt->data = pkt->head + (origpkt->data - origpkt->head);
  }
  
  if( origpkt->tail ){
    pkt->tail = pkt->head + (origpkt->tail - origpkt->head);
  }
  
  if( origpkt->l2.raw ){
    pkt->l2.raw = pkt->head + (origpkt->l2.raw - origpkt->head);
  }
  
  if( origpkt->l3.raw ){
    pkt->l3.raw = pkt->head + (origpkt->l3.raw - origpkt->head);
  }
  
  if( origpkt->l4.raw ){
    pkt->l4.raw = pkt->head + (origpkt->l4.raw - origpkt->head);
  }

  if( origpkt->app.raw ){
    pkt->app.raw = pkt->head + (origpkt->app.raw - origpkt->head);
  }
  
  pkt->len = origpkt->len;

  pkt->dmy_pkt_esp_tx_seq = origpkt->dmy_pkt_esp_tx_seq;

  pkt->v6_rlm_lladdr = origpkt->v6_rlm_lladdr;

  pkt->ikev2_non_esp_marker = origpkt->ikev2_non_esp_marker;

  pkt->frags.head = pktfrag_head;
  pkt->frags.frags_num = origpkt->frags.frags_num;

#ifdef RHP_PKT_DEBUG
//  rhp_pkt_trace_dump("rhp_pkt_dup.origpkt",origpkt);
//  rhp_pkt_trace_dump("rhp_pkt_dup.pkt",pkt);
#endif // RHP_PKT_DEBUG

  RHP_TRC_FREQ(0,RHPTRCID_PKT_DUP,"xx",origpkt,pkt);

  return pkt;

error:
	{
		pktfrag = pktfrag_head;
		while( pktfrag ){

			rhp_packet_frag *pktfrag_n = pktfrag->next;

			rhp_pkt_frag_free(pktfrag);

			pktfrag = pktfrag_n;
		}
	}
  return NULL;
}


extern void rhp_ikev2_unhold_mesg(struct _rhp_ikev2_mesg* ikemesg);

static void _rhp_pkt_free(rhp_packet* pkt)
{
  RHP_TRC_FREQ(0,RHPTRCID_PKT_FREE,"x",pkt);

  if( pkt->tx_ifc ){
    rhp_ifc_unhold(pkt->tx_ifc);
  }

  if( pkt->rx_ifc ){
    rhp_ifc_unhold(pkt->rx_ifc);
  }

  if( pkt->esp_tx_vpn_ref ){
  	rhp_vpn_unhold(pkt->esp_tx_vpn_ref);
  }

  if( pkt->esp_rx_vpn_ref ){
  	rhp_vpn_unhold(pkt->esp_rx_vpn_ref);
  }

  if( pkt->cookie_checked_rx_mesg ){
  	rhp_ikev2_unhold_mesg(pkt->cookie_checked_rx_mesg);
  }

  if( pkt->nhrp.nbma_src_addr ){
  	_rhp_free(pkt->nhrp.nbma_src_addr);
  }
  if( pkt->nhrp.nbma_dst_addr ){
  	_rhp_free(pkt->nhrp.nbma_dst_addr);
  }

  if( _rhp_pkt_return_to_pool(pkt) ){

  	rhp_packet_frag *pktfrag = pkt->frags.head;

  	while( pktfrag ){

  		rhp_packet_frag *pktfrag_n = pktfrag->next;

  		rhp_pkt_frag_free(pktfrag);

  		pktfrag = pktfrag_n;
  	}

		if( pkt->head ){
			_rhp_free(pkt->head);
		}

		_rhp_atomic_destroy(&(pkt->refcnt));

		_rhp_free(pkt);
  }

  return;
}

static void _rhp_pkt_hold(rhp_packet* pkt,rhp_packet_ref* pkt_ref)
{
  _rhp_atomic_inc(&(pkt->refcnt));
  RHP_TRC_FREQ(0,RHPTRCID_PKT_HOLD,"xxd",pkt,pkt_ref,_rhp_atomic_read(&(pkt->refcnt)));
}

static rhp_packet_ref* _rhp_pkt_hold_ref(rhp_packet* pkt,rhp_packet_ref* pkt_ref)
{
	_rhp_pkt_hold(pkt,pkt_ref);
	return (rhp_packet_ref*)pkt;
}

static void _rhp_pkt_unhold(rhp_packet* pkt,rhp_packet_ref* pkt_ref)
{
	RHP_TRC_FREQ(0,RHPTRCID_PKT_UNHOLD,"xxdYY",pkt,pkt_ref,_rhp_atomic_read(&(pkt->refcnt)),pkt->destructor,pkt->esp_pkt_pend_done);

	if( _rhp_atomic_dec_and_test(&(pkt->refcnt)) ){

		if( pkt->esp_pkt_pend_done ){

			if( pkt->esp_pkt_pend_done(pkt) ){
				RHP_TRC_FREQ(0,RHPTRCID_PKT_UNHOLD_CANCEL_FREE,"xdY",pkt,_rhp_atomic_read(&(pkt->refcnt)),pkt->esp_pkt_pend_done);
				goto cancel_free;
			}
		}

    if( pkt->destructor ){
      pkt->destructor(pkt);
    }

    _rhp_pkt_free(pkt);
  }

cancel_free:
	return;
}

#ifndef RHP_REFCNT_DEBUG

void rhp_pkt_hold(rhp_packet* pkt)
{
	_rhp_pkt_hold(pkt,NULL);
}

rhp_packet_ref* rhp_pkt_hold_ref(rhp_packet* pkt)
{
	return _rhp_pkt_hold_ref(pkt,NULL);
}

void rhp_pkt_unhold(void* pkt,NULL)
{
	_rhp_pkt_unhold(pkt);
}

#else // RHP_REFCNT_DEBUG

#ifndef RHP_REFCNT_DEBUG_X

void rhp_pkt_hold(rhp_packet* pkt)
{
	_rhp_pkt_hold(pkt,NULL);
}

rhp_packet_ref* rhp_pkt_hold_ref(rhp_packet* pkt)
{
	return _rhp_pkt_hold_ref(pkt,NULL);
}

void rhp_pkt_unhold(void* pkt)
{
	_rhp_pkt_unhold(pkt,NULL);
}

#else // RHP_REFCNT_DEBUG_X

void rhp_pkt_hold(rhp_packet* pkt)
{
	_rhp_pkt_hold(pkt,NULL);
}

rhp_packet_ref* rhp_pkt_hold_ref(rhp_packet* pkt)
{
	rhp_packet_ref* pkt_ref;
	pkt_ref = (rhp_packet_ref*)rhp_refcnt_dbg_alloc(pkt,__FILE__,__LINE__);
	_rhp_pkt_hold_ref(pkt,pkt_ref);
	return pkt_ref;
}

void rhp_pkt_unhold(void* pkt_or_ref)
{
	rhp_packet* pkt = (rhp_packet*)rhp_refcnt_dbg_free(pkt_or_ref);
	_rhp_pkt_unhold(pkt,pkt_or_ref);
}

#endif // RHP_REFCNT_DEBUG_X
#endif // RHP_REFCNT_DEBUG

void rhp_pkt_pending(rhp_packet* pkt)
{
	if( pkt == NULL ){
		RHP_BUG("");
		return;
	}

	RHP_TRC_FREQ(0,RHPTRCID_PKT_PENDING,"xdY",pkt,_rhp_atomic_read(&(pkt->refcnt)),pkt->esp_pkt_pend_done);

	if( pkt->esp_pkt_pend_done ){
		pkt->esp_pkt_pend_done(pkt);
	}
}

u8* rhp_pkt_expand_tail(rhp_packet* origpkt,int tail_room_len)
{
  u8* p;

  RHP_TRC_FREQ(0,RHPTRCID_PKT_PUSH_OR_EXPAND_TAIL,"xd",origpkt,tail_room_len);
  
  p = _rhp_pkt_push(origpkt,tail_room_len);
  if( p == NULL ){

    int head_room_len = ((u8*)origpkt->data) - ((u8*)origpkt->head);
    int l2_offset  = ( origpkt->l2.raw == NULL ? 0 : ((u8*)origpkt->l2.raw) - ((u8*)origpkt->head) );
    int l3_offset  = ( origpkt->l3.raw == NULL ? 0 : ((u8*)origpkt->l3.raw) - ((u8*)origpkt->head) );
    int l4_offset  = ( origpkt->l4.raw == NULL ? 0 : ((u8*)origpkt->l4.raw) - ((u8*)origpkt->head) );
    int app_offset = ( origpkt->app.raw == NULL ? 0 : ((u8*)origpkt->app.raw) - ((u8*)origpkt->head) );

    RHP_TRC_FREQ(0,RHPTRCID_PKT_PUSH_OR_EXPAND_TAIL_NEW,"x",origpkt);
    
    if( rhp_pkt_realloc(origpkt,head_room_len,tail_room_len) ){
      RHP_BUG("");
      return NULL;
    }

    origpkt->l2.raw  = (l2_offset ? (origpkt->head + l2_offset) : NULL);
    origpkt->l3.raw  = (l3_offset ? (origpkt->head + l3_offset) : NULL);
    origpkt->l4.raw  = (l4_offset ? (origpkt->head + l4_offset) : NULL);
    origpkt->app.raw = (app_offset ? (origpkt->head + app_offset) : NULL);

    p = _rhp_pkt_push(origpkt,tail_room_len);
  }

  RHP_TRC_FREQ(0,RHPTRCID_PKT_PUSH_OR_EXPAND_TAIL_RTRN,"xx",origpkt,p);
  return p;
}

u8* rhp_pkt_expand_head(rhp_packet* origpkt,int head_room_len)
{
  RHP_TRC_FREQ(0,RHPTRCID_PKT_EXPAND_HEAD,"xd",origpkt,head_room_len);
	
	if( (origpkt->data - origpkt->head) < head_room_len ){
	
		int tail_room_len = ((u8*)origpkt->end) - ((u8*)origpkt->tail);
		int l2_offset  = ( origpkt->l2.raw == NULL ? 0 : ((u8*)origpkt->l2.raw) - ((u8*)origpkt->head) );
		int l3_offset  = ( origpkt->l3.raw == NULL ? 0 : ((u8*)origpkt->l3.raw) - ((u8*)origpkt->head) );
		int l4_offset  = ( origpkt->l4.raw == NULL ? 0 : ((u8*)origpkt->l4.raw) - ((u8*)origpkt->head) );
		int app_offset = ( origpkt->app.raw == NULL ? 0 : ((u8*)origpkt->app.raw) - ((u8*)origpkt->head) );
		u8* head;
	
    RHP_TRC_FREQ(0,RHPTRCID_PKT_EXPAND_HEAD_NEW,"x",origpkt);
	    
	  if( rhp_pkt_realloc(origpkt,head_room_len,tail_room_len) ){
	    RHP_BUG("");
	    return NULL;
	  }
	
	  head = origpkt->head + head_room_len;
	  origpkt->l2.raw  = (l2_offset ? (head + l2_offset) : NULL);
	  origpkt->l3.raw  = (l3_offset ? (head + l3_offset) : NULL);
	  origpkt->l4.raw  = (l4_offset ? (head + l4_offset) : NULL);
	  origpkt->app.raw = (app_offset ? (head + app_offset) : NULL);
	}
	
  origpkt->data -= head_room_len;
  origpkt->len  += head_room_len;
    
  RHP_TRC_FREQ(0,RHPTRCID_PKT_EXPAND_HEAD_RTRN,"xx",origpkt,origpkt->data);
  return origpkt->data;
}

void rhp_pkt_trace_dump(char* label,rhp_packet* pkt)
{
#ifdef RHP_PKT_DEBUG
  RHP_TRC_FREQ(0,RHPTRCID_PKT_DUMP_DBG,"sxxdLdddxxxxxxxxxxYxYpppp",label,pkt,pkt->next,pkt->refcnt.c,"PKT",pkt->type,pkt->len,pkt->buffer_len,pkt->head,pkt->data,pkt->tail,pkt->end,pkt->l2.raw,pkt->l3.raw,pkt->l4.raw,pkt->app.raw,pkt->tx_ifc,pkt->rx_ifc,pkt->destructor,pkt->esp_pkt_pend_done_ctx,pkt->esp_pkt_pend_done,pkt->buffer_len,pkt->head,(pkt->data - pkt->head),pkt->head,(pkt->tail - pkt->data),pkt->data,(pkt->end - pkt->tail),pkt->tail);
#else
  if( rhp_gcfg_trace_pkt_full_dump ){
  	RHP_TRC_FREQ(0,RHPTRCID_PKT_DUMP,"sxxdLdddxxxxxxxxxxYxYpp",label,pkt,pkt->next,pkt->refcnt.c,"PKT",pkt->type,pkt->len,pkt->buffer_len,pkt->head,pkt->data,pkt->tail,pkt->end,pkt->l2.raw,pkt->l3.raw,pkt->l4.raw,pkt->app.raw,pkt->tx_ifc,pkt->rx_ifc,pkt->destructor,pkt->esp_pkt_pend_done_ctx,pkt->esp_pkt_pend_done,pkt->buffer_len,pkt->head,(pkt->tail - pkt->data),pkt->data);
  }
#endif // RHP_PKT_DEBUG
}

void rhp_pkt_frag_trace_dump(char* label,rhp_packet_frag* pktfrag)
{
#ifdef RHP_PKT_DEBUG
  RHP_TRC_FREQ(0,RHPTRCID_PKT_FRAG_DUMP_DBG,"sxxddxxxxxxxxpppp",label,pktfrag,pktfrag->next,pktfrag->len,pktfrag->buffer_len,pktfrag->head,pktfrag->data,pktfrag->tail,pktfrag->end,pktfrag->l2.raw,pktfrag->l3.raw,pktfrag->l4.raw,pktfrag->app.raw,pktfrag->buffer_len,pktfrag->head,(pktfrag->data - pktfrag->head),pktfrag->head,(pktfrag->tail - pktfrag->data),pktfrag->data,(pktfrag->end - pktfrag->tail),pktfrag->tail);
#else
  if( rhp_gcfg_trace_pkt_full_dump ){
  	RHP_TRC_FREQ(0,RHPTRCID_PKT_FRAG_DUMP,"sxxddxxxxxxxxpp",label,pktfrag,pktfrag->next,pktfrag->len,pktfrag->buffer_len,pktfrag->head,pktfrag->data,pktfrag->tail,pktfrag->end,pktfrag->l2.raw,pktfrag->l3.raw,pktfrag->l4.raw,pktfrag->app.raw,pktfrag->buffer_len,pktfrag->head,(pktfrag->tail - pktfrag->data),pktfrag->data);
  }
#endif // RHP_PKT_DEBUG
}

void rhp_pkt_frags_trace_dump(char* label,rhp_packet* pkt)
{
	rhp_packet_frag* pktfrag = pkt->frags.head;
	while( pktfrag ){
		rhp_pkt_frag_trace_dump(label,pktfrag);
		pktfrag = pktfrag->next;
	}
}


struct _rhp_pkt_task {

  unsigned char tag[4]; // "#PTK"

  rhp_mutex_t lock;

	int pkt_q_num;
	rhp_packet_q pkt_q;
};
typedef struct _rhp_pkt_task	rhp_pkt_task;

#define RHP_PKT_TASK_LST_NUM		5 // See below (**x**) in rhp_pkt_main_init().
static rhp_pkt_task* _rhp_pkt_task_lst[RHP_PKT_TASK_LST_NUM];

extern void rhp_esp_tx_dispatched_task(rhp_packet* pkt);
extern void rhp_netsock_dispached_task(rhp_packet* pkt);
extern void rhp_tuntap_read_dispached_task(rhp_packet* pkt);

static void _rhp_pkt_task_handler_impl(int worker_index,int level)
{
	rhp_pkt_task* pkt_task = &(_rhp_pkt_task_lst[level][worker_index]);
	rhp_packet* pkt;
	int i;

  RHP_TRC_FREQ(0,RHPTRCID_PKT_TASK_HANDLER_IMPL,"ddx",worker_index,level,pkt_task);

	rhp_wts_worker_statistics_tbl[worker_index].exec_sta_pkt_tasks_counter++;

  for( i = 0; ; i++ ){

  	if( (level != RHP_WTS_DISP_LEVEL_HIGH_3) && (i >= rhp_gcfg_wts_pkt_task_yield_limit) ){
  		break;
  	}

  	RHP_LOCK(&(pkt_task->lock));

		pkt = _rhp_pkt_q_deq(&(pkt_task->pkt_q)); // (***)
		if( pkt == NULL ){
			RHP_UNLOCK(&(pkt_task->lock));
			goto end;
		}

	  RHP_TRC_FREQ(0,RHPTRCID_PKT_TASK_HANDLER_IMPL_EXEC,"xYxYxd",pkt_task,pkt->esp_pkt_pend_done,pkt->esp_pkt_pend_done_ctx,pkt->process_packet,pkt,pkt_task->pkt_q_num);

		pkt_task->pkt_q_num--;

		RHP_UNLOCK(&(pkt_task->lock));

		if( pkt->process_packet ){

			rhp_wts_worker_statistics_tbl[worker_index].exec_sta_pkt_task_pkts++;
			if( pkt->process_packet == rhp_esp_tx_dispatched_task ){
				rhp_wts_worker_statistics_tbl[worker_index].exec_sta_esp_tx_tasks_pkts++;
			}else if( pkt->process_packet == rhp_netsock_dispached_task ){
				rhp_wts_worker_statistics_tbl[worker_index].exec_sta_netsock_rx_tasks_pkts++;
			}else if( pkt->process_packet == rhp_tuntap_read_dispached_task ){
				rhp_wts_worker_statistics_tbl[worker_index].exec_sta_tuntap_rd_tasks_pkts++;
			}

			pkt->process_packet(pkt);

		}else{
			RHP_BUG("");
		}

		rhp_pkt_unhold(pkt); // (***)
  }

end:

	RHP_TRC_FREQ(0,RHPTRCID_PKT_TASK_HANDLER_IMPL_RTRN,"x",pkt_task);
  return;
}

//
// *****[CAUTION]*******
//
//    All callback functions except task_handler()  DON'T call RHP_BUG("") or rhp_log_write()!
//    These apis may internally call rhp_wts_sta_invoke_task(), so the call will be deadlock!
//
// *****[CAUTION]*******
//
static int _rhp_pkt_task_do_exec_impl(int worker_index,int level)
{
	rhp_pkt_task* pkt_task = &(_rhp_pkt_task_lst[level][worker_index]);
	int flag = 0;

  RHP_TRC_FREQ(0,RHPTRCID_PKT_TASK_DO_EXEC_IMPL,"ddx",worker_index,level,pkt_task);

  RHP_LOCK(&(pkt_task->lock));

  flag = ( pkt_task->pkt_q.head != NULL );

  RHP_UNLOCK(&(pkt_task->lock));

  RHP_TRC_FREQ(0,RHPTRCID_PKT_TASK_DO_EXEC_IMPL_RTRN,"xd",pkt_task,flag);
  return flag;
}

//
// *****[CAUTION]*******
//
//    All callback functions except task_handler()  DON'T call RHP_BUG("") or rhp_log_write()!
//    These apis may internally call rhp_wts_sta_invoke_task(), so the call will be deadlock!
//
// *****[CAUTION]*******
//
static int _rhp_pkt_task_add_ctx_impl(int worker_index,int level,void* ctx)
{
	int err = -EINVAL;
	rhp_pkt_task* pkt_task = &(_rhp_pkt_task_lst[level][worker_index]);
	rhp_packet* pkt = (rhp_packet*)ctx;

  RHP_TRC_FREQ(0,RHPTRCID_PKT_TASK_ADD_CTX_IMPL,"ddxxYxY",worker_index,level,pkt_task,pkt,pkt->esp_pkt_pend_done,pkt->esp_pkt_pend_done_ctx,pkt->process_packet);

  if( pkt->process_packet == NULL ){
  	RHP_BUG("");
  }

  RHP_LOCK(&(pkt_task->lock));

  RHP_TRC_FREQ(0,RHPTRCID_PKT_TASK_ADD_CTX_IMPL_PKT_Q,"xdd",pkt_task,pkt_task->pkt_q_num,rhp_gcfg_wts_pkt_task_max_q_packets);

  if( (level != RHP_WTS_DISP_LEVEL_HIGH_3) &&
  		 (pkt_task->pkt_q_num >= rhp_gcfg_wts_pkt_task_max_q_packets) ){

  	err = -EBUSY;
  	goto error_l;
  }

  rhp_pkt_hold(pkt);
  _rhp_pkt_q_enq(&(pkt_task->pkt_q),pkt);

  pkt_task->pkt_q_num++;

  RHP_UNLOCK(&(pkt_task->lock));

  RHP_TRC_FREQ(0,RHPTRCID_PKT_TASK_ADD_CTX_IMPL_RTRN,"x",pkt_task);
  return 0;

error_l:
	RHP_UNLOCK(&(pkt_task->lock));

	RHP_TRC_FREQ(0,RHPTRCID_PKT_TASK_ADD_CTX_IMPL_ERR,"xE",pkt_task,err);
	return err;
}


static inline void _rhp_pkt_task_handler(int worker_index,void* task_ctx)
{
	_rhp_pkt_task_handler_impl(worker_index,(int)task_ctx);
}

static inline int _rhp_pkt_task_do_exec(int worker_index,void* task_ctx)
{
	return _rhp_pkt_task_do_exec_impl(worker_index,(int)task_ctx);
}

static inline int _rhp_pkt_task_add_ctx(int worker_index,void* task_ctx,void* ctx)
{
	return _rhp_pkt_task_add_ctx_impl(worker_index,(int)task_ctx,ctx);
}


int rhp_pkt_main_init()
{
	int err = -EINVAL;
	int i,j;
	int workers_num = rhp_wts_get_workers_num();
	int task_levels[RHP_PKT_TASK_LST_NUM] // (**x**)
	    = {RHP_WTS_DISP_LEVEL_LOW_1,RHP_WTS_DISP_LEVEL_LOW_2,RHP_WTS_DISP_LEVEL_LOW_3,
	       RHP_WTS_DISP_LEVEL_HIGH_2,RHP_WTS_DISP_LEVEL_HIGH_3};

	_rhp_mutex_init("PKP",&_rhp_pkt_pool_lock);
	_rhp_pkt_q_init(&_rhp_pkt_pool);


	for( j = 0; j < RHP_PKT_TASK_LST_NUM; j++ ){

		rhp_pkt_task* pkt_task;

		pkt_task = (rhp_pkt_task*)_rhp_malloc(sizeof(rhp_pkt_task)*(workers_num));
		if( pkt_task == NULL ){
			RHP_BUG("%d",err);
			goto error;
		}

		memset(pkt_task,0,sizeof(rhp_pkt_task)*(workers_num));

		for( i = 0; i < workers_num ; i++ ){

			pkt_task[i].tag[0] = '#';
			pkt_task[i].tag[1] = 'P';
			pkt_task[i].tag[2] = 'T';
			pkt_task[i].tag[3] = 'K';

			_rhp_mutex_init("PKT",&(pkt_task[i].lock));

			_rhp_pkt_q_init(&(pkt_task[i].pkt_q));
		}

		_rhp_pkt_task_lst[j] = pkt_task;

		err = rhp_wts_sta_register_task(RHP_WTS_STA_TASK_NAME_PKT,
				task_levels[j],_rhp_pkt_task_handler,_rhp_pkt_task_do_exec,_rhp_pkt_task_add_ctx,(void*)j);

		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
	}

	_rhp_pkt_pool_init();

  _rhp_mutex_init("PST",&(rhp_pkt_lock_statistics));

	RHP_TRC(0,RHPTRCID_PKT_MAIN_INIT_OK,"");
	return 0;

error:
	RHP_TRC(0,RHPTRCID_PKT_MAIN_INIT_ERR,"E",err);
	return err;
}

// TODO : Reading traffic definition from config.
int rhp_is_critical_pkt(rhp_packet* pkt)
{
	rhp_proto_ether* ethh;
	rhp_proto_udp* udph;
	rhp_proto_tcp* tcph;
	u8* l4_hdr = NULL;
	u8 protocol = 0;

	if( pkt->is_critical ){
		RHP_TRC_FREQ(0,RHPTRCID_IS_CRITICAL_PKT_CACHED_OK,"x",pkt);
		return 1;
	}

	if( pkt->type == RHP_PKT_GRE_NHRP ){
		RHP_TRC_FREQ(0,RHPTRCID_IS_CRITICAL_PKT_GRE_NHRP,"x",pkt);
		goto is_critical;
	}

	if( pkt->type != RHP_PKT_IPV4_ESP && pkt->type != RHP_PKT_IPV4_ESP_NAT_T &&
			pkt->type != RHP_PKT_IPV6_ESP && pkt->type != RHP_PKT_IPV6_ESP_NAT_T &&
			pkt->type != RHP_PKT_PLAIN_ETHER_TAP ){

		RHP_TRC_FREQ(0,RHPTRCID_IS_CRITICAL_PKT_IGNORED_PKT_TYPE,"x",pkt);
		goto ignored;
	}

	ethh = pkt->l2.eth;

	if( ethh == NULL || (u8*)(ethh + 1) >= pkt->end ){
		RHP_TRC_FREQ(0,RHPTRCID_IS_CRITICAL_PKT_NO_DATA,"x",pkt);
		goto ignored;
	}

	if( ethh->protocol == RHP_PROTO_ETH_ARP ){

		RHP_TRC_FREQ(0,RHPTRCID_IS_CRITICAL_PKT_ARP,"x",pkt);

	}else if( ethh->protocol == RHP_PROTO_ETH_IP ){

		rhp_proto_ip_v4* iph_v4 = (rhp_proto_ip_v4*)(ethh + 1);

		if( (u8*)(iph_v4 + 1) >= pkt->end ){
			RHP_TRC_FREQ(0,RHPTRCID_IS_CRITICAL_PKT_IPV4_NO_DATA,"x",pkt);
			goto ignored;
		}

		l4_hdr = (((u8*)iph_v4) + (iph_v4->ihl*4));
		protocol = iph_v4->protocol;

	}else if( ethh->protocol == RHP_PROTO_ETH_IPV6 ){

		rhp_proto_ip_v6* iph_v6 = (rhp_proto_ip_v6*)(ethh + 1);
		u8 protos[3] = {RHP_PROTO_IP_OSPF,RHP_PROTO_IP_UDP,RHP_PROTO_IP_TCP};
		int protos_num = 3;

		if( (u8*)(iph_v6 + 1) >= pkt->end ){
			RHP_TRC_FREQ(0,RHPTRCID_IS_CRITICAL_PKT_IPV6_NO_DATA,"x",pkt);
			goto ignored;
		}

		l4_hdr = rhp_proto_ip_v6_upper_layer(iph_v6,pkt->end,protos_num,protos,&protocol);
		if( l4_hdr == NULL ){
			RHP_TRC_FREQ(0,RHPTRCID_IS_CRITICAL_PKT_IPV6_NO_INTERESTED_L4_DATA,"x",pkt);
			goto ignored;
		}

	}else{

		RHP_TRC_FREQ(0,RHPTRCID_IS_CRITICAL_PKT_IGNORED,"x",pkt);
		goto ignored;
	}

	if( protocol == 0 || l4_hdr == NULL ){
		RHP_TRC_FREQ(0,RHPTRCID_IS_CRITICAL_PKT_IGNORED_NO_INTERESTED_L4_DATA,"x",pkt);
		goto ignored;
	}

	if( protocol == RHP_PROTO_IP_OSPF ){

		RHP_TRC_FREQ(0,RHPTRCID_IS_CRITICAL_PKT_OSPF,"x",pkt);

	}else if( rhp_gcfg_v4_icmp_is_critical && protocol == RHP_PROTO_IP_ICMP ){

		RHP_TRC_FREQ(0,RHPTRCID_IS_CRITICAL_PKT_ICMP,"x",pkt);

	}else if( protocol == RHP_PROTO_IP_IPV6_ICMP ){

		RHP_TRC_FREQ(0,RHPTRCID_IS_CRITICAL_PKT_IPV6_ICMP,"x",pkt);

	}else if( protocol == RHP_PROTO_IP_UDP ){

		udph = (rhp_proto_udp*)l4_hdr;

		if( (u8*)(udph + 1) >= pkt->end ){
			RHP_TRC_FREQ(0,RHPTRCID_IS_CRITICAL_PKT_UDP_NO_DATA,"x",pkt);
			goto ignored;
		}

		if( udph->dst_port == htons(RHP_PROTO_RIP_PORT) ){
			RHP_TRC_FREQ(0,RHPTRCID_IS_CRITICAL_PKT_RIP,"x",pkt);
		}else{
			RHP_TRC_FREQ(0,RHPTRCID_IS_CRITICAL_PKT_UDP_IGNORED,"x",pkt);
			goto ignored;
		}

	}else if( protocol == RHP_PROTO_IP_TCP ){

		tcph = (rhp_proto_tcp*)l4_hdr;

		if( (u8*)(tcph + 1) >= pkt->end ){
			RHP_TRC_FREQ(0,RHPTRCID_IS_CRITICAL_PKT_TCP_NO_DATA,"x",pkt);
			goto ignored;
		}

		if( tcph->dst_port == htons(RHP_PROTO_BGP_PORT) ){
			RHP_TRC_FREQ(0,RHPTRCID_IS_CRITICAL_PKT_BGP,"x",pkt);
		}else{
			RHP_TRC_FREQ(0,RHPTRCID_IS_CRITICAL_PKT_TCP_IGNORED,"x",pkt);
			goto ignored;
		}
	}

is_critical:
	pkt->is_critical = 1;

	return 1;

ignored:
	return 0;
}


int rhp_pkt_ipv4_set_addrs(rhp_packet* pkt,u32 src_addr,u32 dst_addr)
{
	rhp_packet_frag* pktfrag = pkt->frags.head;

	if( pkt->l2.raw == NULL ||
			pkt->l2.eth->protocol != RHP_PROTO_ETH_IP ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( pkt->l3.raw == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	pkt->l3.iph_v4->src_addr = src_addr;
	pkt->l3.iph_v4->dst_addr = dst_addr;

	while( pktfrag ){

		if( pktfrag->l2.raw == NULL ||
				pktfrag->l2.eth->protocol != RHP_PROTO_ETH_IP ){
			RHP_BUG("");
			return -EINVAL;
		}

		if( pktfrag->l3.raw == NULL ){
			RHP_BUG("");
			return -EINVAL;
		}

		pktfrag->l3.iph_v4->src_addr = src_addr;
		pktfrag->l3.iph_v4->dst_addr = dst_addr;

		pktfrag = pktfrag->next;
	}

	return 0;
}

int rhp_pkt_ipv6_set_addrs(rhp_packet* pkt,u8* src_addr,u8* dst_addr)
{
	rhp_packet_frag* pktfrag = pkt->frags.head;

	if( pkt->l2.raw == NULL ||
			pkt->l2.eth->protocol != RHP_PROTO_ETH_IPV6 ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( pkt->l3.raw == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	memcpy(pkt->l3.iph_v6->src_addr,src_addr,16);
	memcpy(pkt->l3.iph_v6->dst_addr,dst_addr,16);


	while( pktfrag ){

		if( pktfrag->l2.raw == NULL ||
				pktfrag->l2.eth->protocol != RHP_PROTO_ETH_IP ){
			RHP_BUG("");
			return -EINVAL;
		}

		if( pktfrag->l3.raw == NULL ){
			RHP_BUG("");
			return -EINVAL;
		}

		memcpy(pktfrag->l3.iph_v6->src_addr,src_addr,16);
		memcpy(pktfrag->l3.iph_v6->dst_addr,dst_addr,16);

		pktfrag = pktfrag->next;
	}

	return 0;
}

int rhp_pkt_ipv4_set_addrs_udp_ports(rhp_packet* pkt,u32 src_addr,u32 dst_addr,u16 src_port,u16 dst_port)
{
	rhp_packet_frag* pktfrag = pkt->frags.head;

	if( pkt->l2.raw == NULL ||
			pkt->l2.eth->protocol != RHP_PROTO_ETH_IP ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( pkt->l3.raw == NULL ||
			(pkt->l3.iph_v4->protocol != RHP_PROTO_IP_UDP &&
			 pkt->l3.iph_v4->protocol != RHP_PROTO_IP_UDPLITE) ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( pkt->l4.raw == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( src_addr ){
		pkt->l3.iph_v4->src_addr = src_addr;
	}

	if( dst_addr ){
		pkt->l3.iph_v4->dst_addr = dst_addr;
	}

	if( src_port ){
		pkt->l4.udph->src_port = src_port;
	}

	if( dst_port ){
		pkt->l4.udph->dst_port = dst_port;
	}

	while( pktfrag ){

		if( pktfrag->l2.raw == NULL ||
				pktfrag->l2.eth->protocol != RHP_PROTO_ETH_IP ){
			RHP_BUG("");
			return -EINVAL;
		}

		if( pktfrag->l3.raw == NULL ||
				(pktfrag->l3.iph_v4->protocol != RHP_PROTO_IP_UDP &&
				 pktfrag->l3.iph_v4->protocol != RHP_PROTO_IP_UDPLITE) ){
			RHP_BUG("");
			return -EINVAL;
		}

		if( pktfrag->l4.raw == NULL ){
			RHP_BUG("");
			return -EINVAL;
		}

		if( src_addr ){
			pktfrag->l3.iph_v4->src_addr = src_addr;
		}

		if( dst_addr ){
			pktfrag->l3.iph_v4->dst_addr = dst_addr;
		}

		if( src_port ){
			pktfrag->l4.udph->src_port = src_port;
		}

		if( dst_port ){
			pktfrag->l4.udph->dst_port = dst_port;
		}

		pktfrag = pktfrag->next;
	}

	return 0;
}

int rhp_pkt_ipv6_set_addrs_udp_ports(rhp_packet* pkt,u8* src_addr,u8* dst_addr,u16 src_port,u16 dst_port)
{
	rhp_packet_frag* pktfrag = pkt->frags.head;

	if( pkt->l2.raw == NULL ||
			pkt->l2.eth->protocol != RHP_PROTO_ETH_IPV6 ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( pkt->l3.raw == NULL ||
			(pkt->l3.iph_v6->next_header != RHP_PROTO_IP_UDP &&
			 pkt->l3.iph_v6->next_header != RHP_PROTO_IP_UDPLITE) ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( pkt->l4.raw == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( src_addr ){
		memcpy(pkt->l3.iph_v6->src_addr,src_addr,16);
	}

	if( dst_addr ){
		memcpy(pkt->l3.iph_v6->dst_addr,dst_addr,16);
	}

	if( src_port ){
		pkt->l4.udph->src_port = src_port;
	}

	if( dst_port ){
		pkt->l4.udph->dst_port = dst_port;
	}

	while( pktfrag ){

		if( pktfrag->l2.raw == NULL ||
				pktfrag->l2.eth->protocol != RHP_PROTO_ETH_IP ){
			RHP_BUG("");
			return -EINVAL;
		}

		if( pktfrag->l3.raw == NULL ||
				(pktfrag->l3.iph_v6->next_header != RHP_PROTO_IP_UDP &&
				 pktfrag->l3.iph_v6->next_header != RHP_PROTO_IP_UDPLITE) ){
			RHP_BUG("");
			return -EINVAL;
		}

		if( pktfrag->l4.raw == NULL ){
			RHP_BUG("");
			return -EINVAL;
		}

		if( src_addr ){
			memcpy(pktfrag->l3.iph_v6->src_addr,src_addr,16);
		}

		if( dst_addr ){
			memcpy(pktfrag->l3.iph_v6->dst_addr,dst_addr,16);
		}

		if( src_port ){
			pktfrag->l4.udph->src_port = src_port;
		}

		if( dst_port ){
			pktfrag->l4.udph->dst_port = dst_port;
		}

		pktfrag = pktfrag->next;
	}

	return 0;
}



static int _rhp_pkt_type_4to6(int pkt_type)
{
	switch( pkt_type ){
	case RHP_PKT_IPV4_IKE:
		return RHP_PKT_IPV6_IKE;
	case RHP_PKT_IPV4_ESP:
		return RHP_PKT_IPV6_ESP;
	case RHP_PKT_IPV4_ESP_NAT_T:
		return RHP_PKT_IPV6_ESP_NAT_T;
	case RHP_PKT_PLAIN_IPV4_TUNNEL:
		return RHP_PKT_PLAIN_IPV6_TUNNEL;
	case RHP_PKT_PLAIN_IPV4_ESP_DUMMY:
		return RHP_PKT_PLAIN_IPV6_ESP_DUMMY;
	case RHP_PKT_IPV4_DNS:
		return RHP_PKT_IPV6_DNS;
	default:
		break;
	}
	return pkt_type;
}

static int _rhp_pkt_type_6to4(int pkt_type)
{
	switch( pkt_type ){
	case RHP_PKT_IPV6_IKE:
		return RHP_PKT_IPV4_IKE;
	case RHP_PKT_IPV6_ESP:
		return RHP_PKT_IPV4_ESP;
	case RHP_PKT_IPV6_ESP_NAT_T:
		return RHP_PKT_IPV4_ESP_NAT_T;
	case RHP_PKT_PLAIN_IPV6_TUNNEL:
		return RHP_PKT_PLAIN_IPV4_TUNNEL;
	case RHP_PKT_PLAIN_IPV6_ESP_DUMMY:
		return RHP_PKT_PLAIN_IPV4_ESP_DUMMY;
	case RHP_PKT_IPV6_DNS:
		return RHP_PKT_IPV4_DNS;
	default:
		break;
	}
	return pkt_type;
}

static int _rhp_pkt_rebuild_ip_udp_header_2(rhp_pkt_or_frag* pkt_or_frag,int pkt_type,
		int addr_family,u8* src_addr,u8* dst_addr,u16 src_port,u16 dst_port)
{
	int h_diff = sizeof(rhp_proto_ip_v6) - sizeof(rhp_proto_ip_v4);
	size_t m_diff = 0;
	u16 eth_proto = 0;
	union {
		u8* raw;
		rhp_proto_ip_v4* iph_v4;
		rhp_proto_ip_v6* iph_v6;
	} l3_hdr;
	rhp_proto_udp* udph;
	u8 *app;
	int pkt_type_n = pkt_type;

	if( addr_family == AF_INET ){
		RHP_TRC_FREQ(0,RHPTRCID_RHPTRCID_PKT_REBUILD_IP_UDP_HEADER_2,"xLddxLd44WW",pkt_or_frag,"PKT",pkt_type,pkt_or_frag->is_frag,pkt_or_frag->d.raw,"AF",addr_family,(src_addr ? *((u32*)src_addr) : 0),(dst_addr ? *((u32*)dst_addr) : 0),src_port,dst_port);
	}else if( addr_family == AF_INET6 ){
		RHP_TRC_FREQ(0,RHPTRCID_RHPTRCID_PKT_REBUILD_IP_UDP_HEADER_2_V6,"xLddxLd66WW",pkt_or_frag,"PKT",pkt_type,pkt_or_frag->is_frag,pkt_or_frag->d.raw,"AF",addr_family,src_addr,dst_addr,src_port,dst_port);
	}else{
		RHP_BUG("%d",addr_family);
		return -EINVAL;
	}

	if( !pkt_or_frag->is_frag ){

		eth_proto = pkt_or_frag->d.pkt->l2.eth->protocol;

		l3_hdr.raw = pkt_or_frag->d.pkt->l3.raw;
		udph = pkt_or_frag->d.pkt->l4.udph;
		app = pkt_or_frag->d.pkt->app.raw;

	}else{

		eth_proto = pkt_or_frag->d.frag->l2.eth->protocol;

		l3_hdr.raw = pkt_or_frag->d.frag->l3.raw;
		udph = pkt_or_frag->d.frag->l4.udph;
		app = pkt_or_frag->d.frag->app.raw;
	}

	m_diff = (size_t)ntohs(udph->len);


	if( eth_proto == RHP_PROTO_ETH_IP && addr_family == AF_INET6 ){

		eth_proto = RHP_PROTO_ETH_IPV6;

		pkt_type_n = _rhp_pkt_type_4to6(pkt_type);

		if( !pkt_or_frag->is_frag ){

			if( rhp_pkt_expand_tail(pkt_or_frag->d.pkt,h_diff) == NULL ){
				RHP_BUG("%d",h_diff);
				return -ENOMEM;
			}

			pkt_or_frag->d.pkt->type = pkt_type_n;

			pkt_or_frag->d.pkt->l2.eth->protocol = eth_proto;

			l3_hdr.iph_v6 = pkt_or_frag->d.pkt->l3.iph_v6;

			udph = pkt_or_frag->d.pkt->l4.udph;


		}else{

			if( rhp_pkt_frag_expand_tail(pkt_or_frag->d.frag,h_diff) == NULL ){
				RHP_BUG("%d",h_diff);
				return -ENOMEM;
			}

			pkt_or_frag->d.frag->l2.eth->protocol = eth_proto;

			l3_hdr.iph_v6 = pkt_or_frag->d.frag->l3.iph_v6;
			udph = pkt_or_frag->d.frag->l4.udph;
		}

		memmove((((u8*)udph) + h_diff),(u8*)udph,(size_t)m_diff);

		udph = (rhp_proto_udp*)(((u8*)udph) + h_diff);
		app += h_diff;

		l3_hdr.iph_v6->ver = 6;
		l3_hdr.iph_v6->priority = 0;
		l3_hdr.iph_v6->flow_label[0] = 0;
		l3_hdr.iph_v6->flow_label[1] = 0;
		l3_hdr.iph_v6->flow_label[2] = 0;
		l3_hdr.iph_v6->payload_len = htons((u16)m_diff);
		l3_hdr.iph_v6->next_header = RHP_PROTO_IP_UDP;
		l3_hdr.iph_v6->hop_limit = 64;


	}else if( eth_proto == RHP_PROTO_ETH_IPV6 && addr_family == AF_INET ){

		memmove((((u8*)udph) - h_diff),(u8*)udph,m_diff);

		udph = (rhp_proto_udp*)(((u8*)udph) - h_diff);
		app -= h_diff;

		eth_proto = RHP_PROTO_ETH_IP;

		pkt_type_n = _rhp_pkt_type_6to4(pkt_type);

		if( !pkt_or_frag->is_frag ){

			if( _rhp_pkt_trim(pkt_or_frag->d.pkt,h_diff) == NULL ){
				RHP_BUG("%d",h_diff);
				return -EINVAL;
			}

		  pkt_or_frag->d.pkt->type = pkt_type_n;

		  pkt_or_frag->d.pkt->l2.eth->protocol = eth_proto;

			l3_hdr.iph_v4 = pkt_or_frag->d.pkt->l3.iph_v4;

		}else{

			if( _rhp_pkt_frag_trim(pkt_or_frag->d.frag,h_diff) == NULL ){
				RHP_BUG("%d",h_diff);
				return -EINVAL;
			}

			pkt_or_frag->d.frag->l2.eth->protocol = eth_proto;

			l3_hdr.iph_v4 = pkt_or_frag->d.frag->l3.iph_v4;
		}

		l3_hdr.iph_v4->ver = 4;
	  l3_hdr.iph_v4->ihl = 5;
	  l3_hdr.iph_v4->tos = 0;
	  l3_hdr.iph_v4->total_len = htons((u16)sizeof(rhp_proto_ip_v4) + (u16)m_diff);
	  l3_hdr.iph_v4->id = 0;
	  l3_hdr.iph_v4->frag = 0;
	  l3_hdr.iph_v4->ttl = 64;
	  l3_hdr.iph_v4->protocol = RHP_PROTO_IP_UDP;
	  l3_hdr.iph_v4->check_sum = 0;
	}


	if( !pkt_or_frag->is_frag ){

		pkt_or_frag->d.pkt->l4.udph = udph;
		pkt_or_frag->d.pkt->app.raw = app;

	}else{

		pkt_or_frag->d.frag->l4.udph = udph;
		pkt_or_frag->d.frag->app.raw = app;
	}

	if( eth_proto == RHP_PROTO_ETH_IP ){

		if( src_addr ){
			l3_hdr.iph_v4->src_addr = *((u32*)src_addr);
		}

		if( dst_addr ){
			l3_hdr.iph_v4->dst_addr = *((u32*)dst_addr);
		}

	}else if( eth_proto == RHP_PROTO_ETH_IPV6 ){

		if( src_addr ){
			memcpy(l3_hdr.iph_v6->src_addr,src_addr,16);
		}

		if( dst_addr ){
			memcpy(l3_hdr.iph_v6->dst_addr,dst_addr,16);
		}

	}else{

		RHP_BUG("%d",eth_proto);
		return -EINVAL;
	}


	if( dst_port ){
		udph->dst_port = dst_port;
	}

	if( src_port ){
		udph->src_port = src_port;
	}

	if( !pkt_or_frag->is_frag ){
		if( eth_proto == RHP_PROTO_ETH_IP && pkt_type_n == RHP_PKT_IPV4_IKE ){
			RHP_TRC_FREQ(0,RHPTRCID_RHPTRCID_PKT_REBUILD_IP_UDP_HEADER_2_IKEV2_PKT_RTRN,"xdxLda",pkt_or_frag,pkt_or_frag->is_frag,pkt_or_frag->d.pkt,"PKT",pkt_or_frag->d.pkt->type,(pkt_or_frag->d.pkt->tail - pkt_or_frag->d.pkt->l2.raw),RHP_TRC_FMT_A_MAC_IPV4_IKEV2,0,0,pkt_or_frag->d.pkt->l2.raw);
		}else if( eth_proto == RHP_PROTO_ETH_IPV6 && pkt_type_n == RHP_PKT_IPV6_IKE ){
			RHP_TRC_FREQ(0,RHPTRCID_RHPTRCID_PKT_REBUILD_IP_UDP_HEADER_2_IKEV2_PKT_V6_RTRN,"xdxLda",pkt_or_frag,pkt_or_frag->is_frag,pkt_or_frag->d.pkt,"PKT",pkt_or_frag->d.pkt->type,(pkt_or_frag->d.pkt->tail - pkt_or_frag->d.pkt->l2.raw),RHP_TRC_FMT_A_MAC_IPV6_IKEV2,0,0,pkt_or_frag->d.pkt->l2.raw);
		}else{
			RHP_TRC_FREQ(0,RHPTRCID_RHPTRCID_PKT_REBUILD_IP_UDP_HEADER_2_PKT_RTRN,"xdxLda",pkt_or_frag,pkt_or_frag->is_frag,pkt_or_frag->d.pkt,"PKT",pkt_or_frag->d.pkt->type,(pkt_or_frag->d.pkt->tail - pkt_or_frag->d.pkt->l2.raw),RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,pkt_or_frag->d.pkt->l2.raw);
		}
	}else{
		if( eth_proto == RHP_PROTO_ETH_IP && pkt_type_n == RHP_PKT_IPV4_IKE ){
			RHP_TRC_FREQ(0,RHPTRCID_RHPTRCID_PKT_REBUILD_IP_UDP_HEADER_2_IKEV2_FRAG_RTRN,"xdxa",pkt_or_frag,pkt_or_frag->is_frag,pkt_or_frag->d.frag,(pkt_or_frag->d.frag->tail - pkt_or_frag->d.frag->l2.raw),RHP_TRC_FMT_A_MAC_IPV4_IKEV2,0,0,pkt_or_frag->d.frag->l2.raw);
		}else if( eth_proto == RHP_PROTO_ETH_IPV6 && pkt_type_n == RHP_PKT_IPV6_IKE ){
			RHP_TRC_FREQ(0,RHPTRCID_RHPTRCID_PKT_REBUILD_IP_UDP_HEADER_2_IKEV2_FRAG_V6_RTRN,"xdxa",pkt_or_frag,pkt_or_frag->is_frag,pkt_or_frag->d.frag,(pkt_or_frag->d.frag->tail - pkt_or_frag->d.frag->l2.raw),RHP_TRC_FMT_A_MAC_IPV6_IKEV2,0,0,pkt_or_frag->d.frag->l2.raw);
		}else{
			RHP_TRC_FREQ(0,RHPTRCID_RHPTRCID_PKT_REBUILD_IP_UDP_HEADER_2_FRAG_RTRN,"xdxa",pkt_or_frag,pkt_or_frag->is_frag,pkt_or_frag->d.frag,(pkt_or_frag->d.frag->tail - pkt_or_frag->d.frag->l2.raw),RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,pkt_or_frag->d.frag->l2.raw);
		}
	}
	return 0;
}

int rhp_pkt_rebuild_ip_udp_header(rhp_packet* pkt,
		int addr_family,u8* src_addr,u8* dst_addr,u16 src_port,u16 dst_port)
{
	int err;
	rhp_pkt_or_frag pkt_or_frag;
	rhp_packet_frag* pktfrag;
	int pkt_type = pkt->type;

	if( addr_family == AF_INET ){
		RHP_TRC_FREQ(0,RHPTRCID_RHPTRCID_PKT_REBUILD_IP_UDP_HEADER,"xLdLd44WW",pkt,"AF",addr_family,"PKT",pkt->type,(src_addr ? *((u32*)src_addr) : 0),(dst_addr ? *((u32*)dst_addr) : 0),src_port,dst_port);
	}else if( addr_family == AF_INET6 ){
		RHP_TRC_FREQ(0,RHPTRCID_RHPTRCID_PKT_REBUILD_IP_UDP_HEADER_V6,"xLdLd66WW",pkt,"AF",addr_family,"PKT",pkt->type,src_addr,dst_addr,src_port,dst_port);
	}else{
		RHP_BUG("%d",addr_family);
		return -EINVAL;
	}

	memset(&pkt_or_frag,0,sizeof(rhp_pkt_or_frag));

	pkt_or_frag.is_frag = 0;
	pkt_or_frag.d.pkt = pkt;

	err = _rhp_pkt_rebuild_ip_udp_header_2(&pkt_or_frag,pkt_type,
					addr_family,src_addr,dst_addr,src_port,dst_port);
	if( err ){
		return err;
	}


	pkt_or_frag.is_frag = 1;

	pktfrag = pkt->frags.head;
	while( pktfrag ){

		pkt_or_frag.d.frag = pktfrag;

		err = _rhp_pkt_rebuild_ip_udp_header_2(&pkt_or_frag,pkt_type,
						addr_family,src_addr,dst_addr,src_port,dst_port);
		if( err ){
			return err;
		}

		pktfrag = pktfrag->next;
	}

	RHP_TRC_FREQ(0,RHPTRCID_RHPTRCID_PKT_REBUILD_IP_UDP_HEADER_RTRN,"x",pkt);
	return 0;
}


