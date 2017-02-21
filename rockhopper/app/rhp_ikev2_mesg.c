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
#include "rhp_ikesa.h"
#include "rhp_ikev2.h"
#include "rhp_vpn.h"
#include "rhp_pcap.h"


void rhp_ikemesg_q_init(rhp_ikemesg_q* ikemesg_q)
{
	ikemesg_q->head = NULL;
	ikemesg_q->tail = NULL;
	return;
}

void rhp_ikemesg_q_enq(rhp_ikemesg_q* ikemesg_q,rhp_ikev2_mesg* ikemesg)
{
  ikemesg->next = NULL;
  if( ikemesg_q->head == NULL ){
    ikemesg_q->head = ikemesg;
  }else{
    ikemesg_q->tail->next = ikemesg;
  }
  ikemesg_q->tail = ikemesg;
  RHP_TRC(0,RHPTRCID_IKEMESG_Q_ENQ,"xx",ikemesg_q,ikemesg);
  return;
}

void rhp_ikemesg_q_enq_head(rhp_ikemesg_q* ikemesg_q,rhp_ikev2_mesg* ikemesg)
{
  ikemesg->next = NULL;
  if( ikemesg_q->head == NULL ){
    ikemesg_q->tail = ikemesg;
  }else{
    ikemesg->next = ikemesg_q->head;
  }
  ikemesg_q->head = ikemesg;
  RHP_TRC(0,RHPTRCID_IKEMESG_Q_ENQ_HEAD,"xx",ikemesg_q,ikemesg);
  return;
}

rhp_ikev2_mesg* rhp_ikemesg_q_peek(rhp_ikemesg_q* ikemesg_q)
{
  return ikemesg_q->head;
}

rhp_ikev2_mesg* rhp_ikemesg_q_deq(rhp_ikemesg_q* ikemesg_q)
{
  rhp_ikev2_mesg* ikemesg = ikemesg_q->head;
  if( ikemesg ){
    ikemesg_q->head = ikemesg->next;
    if( ikemesg == ikemesg_q->tail ){
   	  ikemesg_q->tail = NULL;
    }
    ikemesg->next = NULL;
  }
  RHP_TRC(0,RHPTRCID_IKEMESG_Q_DEQ,"xx",ikemesg_q,ikemesg);
  return ikemesg;
}

int rhp_ikemesg_q_remove(rhp_ikemesg_q* ikemesg_q,rhp_ikev2_mesg* ikemesg)
{
  rhp_ikev2_mesg *ikemesg_tmp = ikemesg_q->head,*ikemesg_tmp_p = NULL;

  while( ikemesg_tmp ){

    if( ikemesg == ikemesg_tmp ){
      break;
    }

    ikemesg_tmp_p = ikemesg_tmp;
    ikemesg_tmp = ikemesg_tmp->next;
  }

  if( ikemesg_tmp == NULL ){
    RHP_TRC(0,RHPTRCID_IKEMESG_Q_REMOVE_NO_ENTRY,"xx",ikemesg_q,ikemesg);
    return -ENOENT;
  }

  if( ikemesg_tmp_p == NULL ){

    ikemesg_q->head = ikemesg_tmp->next;

    if( ikemesg_q->tail == ikemesg_tmp ){
   	  ikemesg_q->tail = NULL;
    }

  }else{

    ikemesg_tmp_p->next = ikemesg_tmp->next;

    if( ikemesg_q->tail == ikemesg_tmp ){
   	  ikemesg_q->tail = ikemesg_tmp_p;
    }
  }

  ikemesg->next = NULL;

  RHP_TRC(0,RHPTRCID_IKEMESG_Q_REMOVE,"xx",ikemesg_q,ikemesg);
  return 0;
}


static void _rhp_ikev2_mesg_tx_pcap_write(rhp_vpn* vpn,
		rhp_ikev2_mesg* ikemesg,int e_pld_head_offset,rhp_packet* pkt,
		int clear_v1_enc_flag)
{
	int buf_len = pkt->len - e_pld_head_offset, rem;
	u8 *buf, *p;
	rhp_proto_ether* ethh;
	union {
		rhp_proto_ip_v4* v4;
		rhp_proto_ip_v6* v6;
	} iph;
	rhp_proto_udp* udph;
	rhp_proto_ike *ikeh, *ikeh_org;


	buf = (u8*)_rhp_malloc(buf_len);
	if( buf == NULL ){
		return;
	}
	p = buf;

	rem = buf_len;


	memcpy(p,pkt->l2.raw,(int)sizeof(rhp_proto_ether));
	ethh = (rhp_proto_ether*)p;
	memcpy(ethh->src_addr,vpn->local.if_info.mac,6);
	p += (int)sizeof(rhp_proto_ether);
	rem -= (int)sizeof(rhp_proto_ether);

	if( ethh->protocol == RHP_PROTO_ETH_IP ){
		memcpy(p,pkt->l3.raw,(int)sizeof(rhp_proto_ip_v4));
		iph.v4 = (rhp_proto_ip_v4*)p;
		p += (int)sizeof(rhp_proto_ip_v4);
		iph.v4->total_len = htons((u16)rem);
		rem -= (int)sizeof(rhp_proto_ip_v4);
	}else if( ethh->protocol == RHP_PROTO_ETH_IPV6 ){
		memcpy(p,pkt->l3.raw,(int)sizeof(rhp_proto_ip_v6));
		iph.v6 = (rhp_proto_ip_v6*)p;
		p += (int)sizeof(rhp_proto_ip_v6);
		rem -= (int)sizeof(rhp_proto_ip_v6);
		iph.v6->payload_len = htons((u16)rem);
	}else{
		goto error;
	}

	memcpy(p,pkt->l4.raw,(int)sizeof(rhp_proto_udp));
	udph = (rhp_proto_udp*)p;
	p += (int)sizeof(rhp_proto_udp);
	udph->len = htons(rem);
	rem -= (int)sizeof(rhp_proto_udp);

	if( pkt->ikev2_non_esp_marker ){

		memcpy(p,pkt->app.raw,RHP_PROTO_NON_ESP_MARKER_SZ);
		ikeh = (rhp_proto_ike*)(p + RHP_PROTO_NON_ESP_MARKER_SZ);
		ikeh_org = (rhp_proto_ike*)(pkt->app.raw + RHP_PROTO_NON_ESP_MARKER_SZ);
		p += RHP_PROTO_NON_ESP_MARKER_SZ + (int)sizeof(rhp_proto_ike);
		rem -= RHP_PROTO_NON_ESP_MARKER_SZ + (int)sizeof(rhp_proto_ike);

	}else{

		ikeh = (rhp_proto_ike*)p;
		ikeh_org = (rhp_proto_ike*)pkt->app.raw;
		p += (int)sizeof(rhp_proto_ike);
		rem -= (int)sizeof(rhp_proto_ike);
	}

	memcpy(ikeh,ikemesg->tx_ikeh,sizeof(rhp_proto_ike));
	ikeh->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
	if( ikemesg->payload_list_head ){
		ikeh->next_payload
			= ikemesg->payload_list_head->get_payload_id(ikemesg->payload_list_head);
  }
	ikeh->len = htonl((u32)(rem + (int)sizeof(rhp_proto_ike)));

	if( clear_v1_enc_flag ){
	  ikeh->flag &= 0xFE; // E(ncryption Bit)
	}

	memcpy(p,((u8*)(ikeh_org + 1)) + e_pld_head_offset,rem);
	p += rem;

	rhp_pcap_write(buf_len,buf,0,NULL);

error:
	if(buf){
		_rhp_free(buf);
	}
	return;
}

static void _rhp_ikev2_mesg_rx_pcap_write(rhp_packet* pkt)
{
	rhp_pcap_write_pkt(pkt);

	return;
}


static u8* _rhp_ikev2_mesg_get_init_spi(rhp_ikev2_mesg* ikemesg)
{
  rhp_proto_ike* ikeh;
  if( ikemesg->rx_pkt ){
    ikeh = ikemesg->rx_pkt->app.ikeh;
  }else{
    ikeh = ikemesg->tx_ikeh;
  }
  RHP_TRC(0,RHPTRCID_IKEV2_MESG_GET_INIT_SPI,"xxG",ikemesg,ikemesg->rx_pkt,ikeh->init_spi);
  return ikeh->init_spi;
}

static u8* _rhp_ikev2_mesg_get_resp_spi(rhp_ikev2_mesg* ikemesg)
{
  rhp_proto_ike* ikeh;
  if( ikemesg->rx_pkt ){
    ikeh = ikemesg->rx_pkt->app.ikeh;
  }else{
    ikeh = ikemesg->tx_ikeh;
  }
  RHP_TRC(0,RHPTRCID_IKEV2_MESG_GET_RESP_SPI,"xxG",ikemesg,ikemesg->rx_pkt,ikeh->resp_spi);
  return ikeh->resp_spi;
}

static void _rhp_ikev2_mesg_set_init_spi(rhp_ikev2_mesg* ikemesg,u8* spi)
{
  if( ikemesg->tx_ikeh ){
    memcpy(ikemesg->tx_ikeh->init_spi,spi,RHP_PROTO_IKE_SPI_SIZE);
  }else{
    RHP_BUG("");
  }
  return;
}

static void _rhp_ikev2_mesg_set_resp_spi(rhp_ikev2_mesg* ikemesg,u8* spi)
{
  if( ikemesg->tx_ikeh ){
    memcpy(ikemesg->tx_ikeh->resp_spi,spi,RHP_PROTO_IKE_SPI_SIZE);
  }else{
    RHP_BUG("");
  }
  return;
}

static u8  _rhp_ikev2_mesg_get_next_payload(rhp_ikev2_mesg* ikemesg)
{
  rhp_proto_ike* ikeh;
  if( ikemesg->rx_pkt ){
    ikeh = ikemesg->rx_pkt->app.ikeh;
  }else{
    ikeh = ikemesg->tx_ikeh;
  }
  RHP_TRC(0,RHPTRCID_IKEV2_MESG_GET_NEXT_PAYLOADI,"xxLb",ikemesg,ikemesg->rx_pkt,"PROTO_IKE_PAYLOAD",ikeh->next_payload);
  return ikeh->next_payload;
}

static u8 _rhp_ikev2_mesg_get_major_ver(rhp_ikev2_mesg* ikemesg)
{
  rhp_proto_ike* ikeh;
  if( ikemesg->rx_pkt ){
    ikeh = ikemesg->rx_pkt->app.ikeh;
  }else{
    ikeh = ikemesg->tx_ikeh;
  }
  RHP_TRC(0,RHPTRCID_IKEV2_MESG_GET_MAJOR_VER,"xxb",ikemesg,ikemesg->rx_pkt,ikeh->ver_major);
  return ikeh->ver_major;
}

static u8 _rhp_ikev2_mesg_get_minor_ver(rhp_ikev2_mesg* ikemesg)
{
  rhp_proto_ike* ikeh;
  if( ikemesg->rx_pkt ){
    ikeh = ikemesg->rx_pkt->app.ikeh;
  }else{
    ikeh = ikemesg->tx_ikeh;
  }
  if( ikeh ){
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_GET_MINOR_VER,"xxb",ikemesg,ikemesg->rx_pkt,ikeh->ver_minor);
    return ikeh->ver_minor;
  }
  RHP_TRC(0,RHPTRCID_IKEV2_MESG_GET_MINOR_VER_ERR,"xx",ikemesg,ikemesg->rx_pkt);
  return (u8)-1;
}

static u8 _rhp_ikev2_mesg_get_exchange_type(rhp_ikev2_mesg* ikemesg)
{
  rhp_proto_ike* ikeh;
  if( ikemesg->rx_pkt ){
    ikeh = ikemesg->rx_pkt->app.ikeh;
  }else{
    ikeh = ikemesg->tx_ikeh;
  }
  RHP_TRC(0,RHPTRCID_IKEV2_MESG_GET_EXCHANGE_TYPE,"xxLb",ikemesg,ikemesg->rx_pkt,"PROTO_IKE_EXCHG",ikeh->exchange_type);
  return ikeh->exchange_type;
}

static void _rhp_ikev2_mesg_set_exchange_type(rhp_ikev2_mesg* ikemesg,u8 exchange_type)
{
  if( ikemesg->tx_ikeh ){
    ikemesg->tx_ikeh->exchange_type = exchange_type;
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_GET_EXCHANGE_TYPE,"xxLb",ikemesg,ikemesg->rx_pkt,"PROTO_IKE_EXCHG",ikemesg->tx_ikeh->exchange_type);
  }else{
  	RHP_BUG("");
  }
  return;
}

static int _rhp_ikev2_mesg_v1_commit_bit_enabled(rhp_ikev2_mesg* ikemesg)
{
  int ret;
  if( ikemesg->rx_pkt ){

  	rhp_proto_ike* ikeh;
    ikeh = ikemesg->rx_pkt->app.ikeh;

    ret = RHP_PROTO_IKEV1_HDR_COMMIT(ikeh->flag);

  }else{

  	ret = (ikemesg->tx_ikeh->flag & RHP_PROTO_IKEV1_HDR_SET_COMMIT);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_V1_COMMIT_BIT_ENABLED,"xxd",ikemesg,ikemesg->rx_pkt,ret);
  return ret;
}

static int _rhp_ikev2_mesg_is_initiator(rhp_ikev2_mesg* ikemesg)
{
  rhp_proto_ike* ikeh;
  if( ikemesg->rx_pkt ){
    ikeh = ikemesg->rx_pkt->app.ikeh;
  }else{
    ikeh = ikemesg->tx_ikeh;
  }
  RHP_TRC(0,RHPTRCID_IKEV2_MESG_IS_INITIATOR,"xxd",ikemesg,ikemesg->rx_pkt,RHP_PROTO_IKE_HDR_INITIATOR(ikeh->flag));
  return RHP_PROTO_IKE_HDR_INITIATOR(ikeh->flag);
}

static int _rhp_ikev2_mesg_is_responder(rhp_ikev2_mesg* ikemesg)
{
  rhp_proto_ike* ikeh;
  if( ikemesg->rx_pkt ){
    ikeh = ikemesg->rx_pkt->app.ikeh;
  }else{
    ikeh = ikemesg->tx_ikeh;
  }
  RHP_TRC(0,RHPTRCID_IKEV2_MESG_IS_RESPONDER,"xxd",ikemesg,ikemesg->rx_pkt,!(RHP_PROTO_IKE_HDR_INITIATOR(ikeh->flag)));
  return !(RHP_PROTO_IKE_HDR_INITIATOR(ikeh->flag));
}

static int _rhp_ikev2_mesg_is_request(rhp_ikev2_mesg* ikemesg)
{
  rhp_proto_ike* ikeh;
  if( ikemesg->rx_pkt ){
    ikeh = ikemesg->rx_pkt->app.ikeh;
  }else{
    ikeh = ikemesg->tx_ikeh;
  }
  RHP_TRC(0,RHPTRCID_IKEV2_MESG_IS_REQUEST,"xxd",ikemesg,ikemesg->rx_pkt,!(RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag)));
  return !(RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag));
}

static int _rhp_ikev2_mesg_is_response(rhp_ikev2_mesg* ikemesg)
{
  rhp_proto_ike* ikeh;
  if( ikemesg->rx_pkt ){
    ikeh = ikemesg->rx_pkt->app.ikeh;
  }else{
    ikeh = ikemesg->tx_ikeh;
  }
  RHP_TRC(0,RHPTRCID_IKEV2_MESG_IS_RESPONSE,"xxd",ikemesg,ikemesg->rx_pkt,(RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag)));
  return RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag);
}

static u32 _rhp_ikev2_mesg_get_mesg_id(rhp_ikev2_mesg* ikemesg)
{
  rhp_proto_ike* ikeh;
  if( ikemesg->rx_pkt ){
    ikeh = ikemesg->rx_pkt->app.ikeh;
  }else{
    ikeh = ikemesg->tx_ikeh;
  }
  RHP_TRC(0,RHPTRCID_IKEV2_MESG_GET_MESGID,"xxJ",ikemesg,ikemesg->rx_pkt,ikeh->message_id);
  return ntohl(ikeh->message_id);
}

static void _rhp_ikev2_mesg_set_mesg_id(rhp_ikev2_mesg* ikemesg,u32 mesg_id)
{
  if( ikemesg->tx_ikeh ){
    ikemesg->tx_ikeh->message_id = htonl(mesg_id);
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_SET_MESGID,"xJ",ikemesg,mesg_id);
  }else{
    RHP_BUG("");
  }
  return;
}

static u32 _rhp_ikev2_mesg_get_len(rhp_ikev2_mesg* ikemesg)
{
  rhp_proto_ike* ikeh;
  if( ikemesg->rx_pkt ){
    ikeh = ikemesg->rx_pkt->app.ikeh;
  }else{
    ikeh = ikemesg->tx_ikeh;
  }
  RHP_TRC(0,RHPTRCID_IKEV2_MESG_GET_LEN,"xxJ",ikemesg,ikemesg->rx_pkt,ikeh->len);
  return ntohs(ikeh->len);
}

static void _rhp_ikev2_mesg_put_payload_impl(rhp_ikev2_mesg* ikemesg,rhp_ikev2_payload* payload,int add_to_head)
{
  RHP_TRC(0,RHPTRCID_IKEV2_MESG_PUT_PAYLOAD_IMPL,"xxLbdd",ikemesg,payload,"PROTO_IKE_PAYLOAD",payload->payload_id,add_to_head,ikemesg->is_v1);

  if( add_to_head ){

  	payload->next = ikemesg->payload_list_head;
  	if( ikemesg->payload_list_head == NULL ){
  		ikemesg->payload_list_tail = payload;
  	}
  	ikemesg->payload_list_head = payload;

  }else{
		if( ikemesg->payload_list_head == NULL ){
			ikemesg->payload_list_head = payload;
		}else{
			ikemesg->payload_list_tail->next = payload;
		}
		ikemesg->payload_list_tail = payload;
  }

  if( payload->ikemesg == NULL ){
    payload->ikemesg = ikemesg;
  }

  if( payload->get_payload_id(payload) == RHP_PROTO_IKE_PAYLOAD_N ){

  	u16 mesg_type = payload->ext.n->get_message_type(payload);

    if( mesg_type >= RHP_PROTO_IKE_NOTIFY_ERR_MIN && mesg_type <= RHP_PROTO_IKE_NOTIFY_ERR_PRIV_END ){
    	ikemesg->put_n_payload_err++;
    	RHP_TRC(0,RHPTRCID_IKEV2_MESG_PUT_PAYLOAD_PUT_IMPL_N_ERR_INVALID_SYNTAX,"xxLb",ikemesg,payload,"PROTO_IKE_PAYLOAD",payload->payload_id);
    }
  }

  payload->is_v1 = ikemesg->is_v1;

  ikemesg->activated++;
  return;
}

static void _rhp_ikev2_mesg_put_payload_head(rhp_ikev2_mesg* ikemesg,rhp_ikev2_payload* payload)
{
	_rhp_ikev2_mesg_put_payload_impl(ikemesg,payload,1);
	return;
}

static void _rhp_ikev2_mesg_put_payload(rhp_ikev2_mesg* ikemesg,rhp_ikev2_payload* payload)
{
	_rhp_ikev2_mesg_put_payload_impl(ikemesg,payload,0);
	return;
}

static int _rhp_ikev2_mesg_search_payloads(rhp_ikev2_mesg* ikemesg,int notify_enum_end,
		int (*condition)(rhp_ikev2_mesg* ikemesg,rhp_ikev2_payload* payload,void* cond_ctx),void* cond_ctx,
		int (*action)(rhp_ikev2_mesg* ikemesg,int enum_end,rhp_ikev2_payload* payload,void* cb_ctx),void* cb_ctx)
{
  int err = 0;
  int cnt = 0;
  int merged = 0;
  rhp_ikev2_payload* payload = ikemesg->payload_list_head;

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_SEARCH_PAYLOADS,"xYxYx",ikemesg,condition,cond_ctx,action,cb_ctx);

  while( payload ){

		u8 payload_id =  payload->get_payload_id(payload);

  	if( condition == NULL || !condition(ikemesg,payload,cond_ctx) ){

  		if( (err = action(ikemesg,0,payload,cb_ctx)) ){
  			RHP_TRC(0,RHPTRCID_IKEV2_MESG_SEARCH_PAYLOADS_CB_ERR,"xbYxYxE",ikemesg,payload_id,condition,cond_ctx,action,cb_ctx,err);
  			return err;
      }

  		cnt++;
    }

  	payload = payload->next;

    if( payload == NULL && ikemesg->merged_mesg && !merged ){
    	payload = ikemesg->merged_mesg->payload_list_head;
    	merged = 1;
    }
  }

  if( cnt == 0 ){
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_SEARCH_PAYLOADS_NO_ENTRY,"xYxYx",ikemesg,condition,cond_ctx,action,cb_ctx);
    return -ENOENT;
  }

  if( notify_enum_end ){

  	if( (err = action(ikemesg,1,NULL,cb_ctx)) ){
  		RHP_TRC(0,RHPTRCID_IKEV2_MESG_SEARCH_PAYLOADS_CB_TERM_ERR,"xYxYxE",ikemesg,condition,cond_ctx,action,cb_ctx,err);
  		return err;
  	}
  }

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_SEARCH_PAYLOADS_RTRN,"xYxYx",ikemesg,condition,cond_ctx,action,cb_ctx);
  return 0;
}

int rhp_ikev2_mesg_srch_cond_payload_id(rhp_ikev2_mesg* ikemesg,rhp_ikev2_payload* payload,void* cond_ctx)
{
	u8 payload_id = (u8)((unsigned long)cond_ctx);

	if( payload_id == payload->payload_id ){
		return 0;
	}
	return -1;
}

int rhp_ikev2_mesg_srch_cond_payload_ids(rhp_ikev2_mesg* ikemesg,rhp_ikev2_payload* payload,void* cond_ctx)
{
	u8* payload_ids = (u8*)cond_ctx;
	int i;

	for( i = 0; payload_ids[i] != RHP_PROTO_IKE_NO_MORE_PAYLOADS; i++ ){
		if( payload_ids[i] == payload->payload_id ){
			return 0;
		}
	}

	return -1;
}

int rhp_ikev2_mesg_srch_cond_n_mesg_id(rhp_ikev2_mesg* ikemesg,rhp_ikev2_payload* payload,void* cond_ctx)
{
	u16 notify_mesg_type = (u16)((unsigned long)cond_ctx);
	rhp_ikev2_n_payload* n_payload;
  u16 mesg_type;

	if( payload->payload_id == RHP_PROTO_IKE_PAYLOAD_N ||
			(ikemesg->is_v1 && payload->payload_id == RHP_PROTO_IKEV1_PAYLOAD_N) ){

		n_payload = (rhp_ikev2_n_payload*)payload->ext.n;
		if( n_payload == NULL ){
			RHP_BUG("");
	  	return -EINVAL;
		}

		mesg_type = n_payload->get_message_type(payload);

		if( mesg_type == notify_mesg_type ){
	  	return 0;
	  }
	}

	return -1;
}

int rhp_ikev2_mesg_srch_cond_n_mesg_ids(rhp_ikev2_mesg* ikemesg,rhp_ikev2_payload* payload,void* cond_ctx)
{
	u16* notify_mesg_types = (u16*)cond_ctx;
	rhp_ikev2_n_payload* n_payload;
  u16 mesg_type;
  int i;

	if( payload->payload_id == RHP_PROTO_IKE_PAYLOAD_N ||
			(ikemesg->is_v1 && payload->payload_id == RHP_PROTO_IKEV1_PAYLOAD_N) ){

		n_payload = (rhp_ikev2_n_payload*)payload->ext.n;
		if( n_payload == NULL ){
			RHP_BUG("");
	  	return -EINVAL;
		}

		mesg_type = n_payload->get_message_type(payload);

		for( i = 0;notify_mesg_types[i] != RHP_PROTO_IKE_NOTIFY_RESERVED;i++ ){
			if( mesg_type == notify_mesg_types[i] ){
				return 0;
			}
		}
	}

	return -1;
}

int rhp_ikev2_mesg_search_cond_my_verndor_id(rhp_ikev2_mesg* ikemesg,rhp_ikev2_payload* payload,void* cond_ctx)
{
	rhp_ikev2_vid_payload* vid_payload;

	if( (ikemesg->is_v1 && payload->payload_id == RHP_PROTO_IKEV1_PAYLOAD_VID) ||
			payload->payload_id == RHP_PROTO_IKE_PAYLOAD_V ){

		vid_payload = (rhp_ikev2_vid_payload*)payload->ext.vid;

		if( vid_payload == NULL ){
			RHP_BUG("");
	  	return -EINVAL;
		}

		if( (vid_payload->is_my_app_id(payload,NULL)) ){
	  	return 0;
	  }
	}

	return -1;
}

static rhp_ikev2_payload* _rhp_ikev2_mesg_get_payload(rhp_ikev2_mesg* ikemesg,u8 payload_id)
{
  rhp_ikev2_payload* payload = ikemesg->payload_list_head;
  int merged = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_GET_PAYLOAD,"xLb",ikemesg,"PROTO_IKE_PAYLOAD",payload_id);

  while( payload ){

    if( payload->payload_id == payload_id ){
      RHP_TRC(0,RHPTRCID_IKEV2_MESG_GET_PAYLOAD_RTRN,"xLbx",ikemesg,"PROTO_IKE_PAYLOAD",payload_id,payload);
      return payload;
    }

    payload = payload->next;

    if( payload == NULL && ikemesg->merged_mesg && !merged ){
    	payload = ikemesg->merged_mesg->payload_list_head;
    	merged = 1;
    }
  }

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_GET_PAYLOAD_NO_ENTRY,"xLb",ikemesg,"PROTO_IKE_PAYLOAD",payload_id);
  return NULL;
}


static int _rhp_ikev2_mesg_serialize_payload_cb(rhp_ikev2_mesg* ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
  rhp_packet* pkt = (rhp_packet*)ctx;
  int err;

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_SERIALIZE_PAYLOAD_CB,"xxLbxxd",ikemesg,payload,"PROTO_IKE_PAYLOAD",payload->payload_id,ctx,pkt,ikemesg->tx_mesg_len);

  err = payload->ext_serialize(payload,pkt);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_SERIALIZE_PAYLOAD_CB_ERR,"xxLbxE",ikemesg,payload,"PROTO_IKE_PAYLOAD",payload->payload_id,ctx,err);
    return err;
  }


  if( ikemesg->is_v1 ){

  	u8 v1_exchg_type = ikemesg->get_exchange_type(ikemesg);

  	if( (v1_exchg_type == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ||
  			 v1_exchg_type == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE) &&
				payload->get_payload_id(payload) == RHP_PROTO_IKEV1_PAYLOAD_SA ){

			ikemesg->v1_sa_b = payload->ext.v1_sa->sa_b;
  	}
	}

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_SERIALIZE_PAYLOAD_CB_RTRN,"xxxd",ikemesg,payload,pkt,ikemesg->tx_mesg_len);

  return 0;
}

static int _rhp_ikev2_mesg_frag_needed(rhp_vpn* vpn,int addr_family,int tx_mesg_len,int* frag_size_r)
{
	int exec_frag = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_FRAG_NEEDED,"xLddxddddddd",vpn,"AF",addr_family,tx_mesg_len,frag_size_r,vpn->exec_ikev2_frag,rhp_gcfg_ikev2_frag_size_v4,rhp_gcfg_ikev2_frag_size_v6,rhp_gcfg_ikev2_frag_use_min_size,vpn->local.if_info.mtu,rhp_gcfg_ikev2_frag_min_size_v4,rhp_gcfg_ikev2_frag_min_size_v6);

	if( !vpn->exec_ikev2_frag ){
		exec_frag = 0;
		goto end;
	}

	if( addr_family == AF_INET && rhp_gcfg_ikev2_frag_size_v4 ){

		if( tx_mesg_len <= rhp_gcfg_ikev2_frag_size_v4 ){
			exec_frag = 0;
			goto end;
		}

		*frag_size_r = rhp_gcfg_ikev2_frag_size_v4;
		exec_frag = 1;

	}else if( addr_family == AF_INET6 && rhp_gcfg_ikev2_frag_size_v6 ){

		if( tx_mesg_len <= rhp_gcfg_ikev2_frag_size_v6 ){
			exec_frag = 0;
			goto end;
		}

		*frag_size_r = rhp_gcfg_ikev2_frag_size_v6;
		exec_frag = 1;

	}else if( !rhp_gcfg_ikev2_frag_use_min_size &&
						vpn->local.if_info.mtu ){

		int frag_size_mtu;

		if( addr_family == AF_INET ){

			frag_size_mtu = vpn->local.if_info.mtu - sizeof(rhp_proto_ip_v4) - sizeof(rhp_proto_udp);

		}else{ // AF_INET6

			frag_size_mtu = vpn->local.if_info.mtu - sizeof(rhp_proto_ip_v6) - sizeof(rhp_proto_udp);
		}

		if( tx_mesg_len > frag_size_mtu ){

			*frag_size_r = frag_size_mtu;

			exec_frag = 1;
		}

	}else if( addr_family == AF_INET &&
						rhp_gcfg_ikev2_frag_min_size_v4 &&
						tx_mesg_len > rhp_gcfg_ikev2_frag_min_size_v4 ){

		*frag_size_r = rhp_gcfg_ikev2_frag_min_size_v4;

		exec_frag = 1;

	}else if( addr_family == AF_INET6 &&
						rhp_gcfg_ikev2_frag_min_size_v6 &&
						tx_mesg_len > rhp_gcfg_ikev2_frag_min_size_v6 ){

		*frag_size_r = rhp_gcfg_ikev2_frag_min_size_v6;

		exec_frag = 1;
	}


	if( exec_frag ){

		if( addr_family == AF_INET ){

			if( rhp_gcfg_ikev2_frag_min_size_v4 &&
					*frag_size_r < rhp_gcfg_ikev2_frag_min_size_v4 ){

				*frag_size_r = rhp_gcfg_ikev2_frag_min_size_v4;
			}

		}else{ // AF_INET6

			if( rhp_gcfg_ikev2_frag_min_size_v6 &&
					*frag_size_r < rhp_gcfg_ikev2_frag_min_size_v6 ){

				*frag_size_r = rhp_gcfg_ikev2_frag_min_size_v6;
			}
		}
	}

end:

	RHP_TRC(0,RHPTRCID_IKEV2_MESG_FRAG_NEEDED_RTRN,"xLdddd",vpn,"AF",addr_family,tx_mesg_len,*frag_size_r,exec_frag);
	return exec_frag;
}

static int _rhp_ikev2_mesg_serialize_alloc_pkt(rhp_ikev2_mesg* ikemesg,
		rhp_ip_addr* src_addr,rhp_ip_addr* dst_addr,
		int pkt_len,rhp_pkt_or_frag* pkt_or_frag_r)
{
	int err = -EINVAL;
  u8* non_esp_marker = NULL;
  rhp_proto_ether* dmy_ethh;
  union {
  	rhp_proto_ip_v4* v4;
    rhp_proto_ip_v6* v6;
    u8* raw;
  } dmy_iph;
  rhp_proto_udp* dmy_udph;
  rhp_proto_ike* new_ikeh;

	RHP_TRC(0,RHPTRCID_IKEV2_MESG_SERIALIZE_ALLOC_PKT,"xxxdxd",ikemesg,src_addr,dst_addr,pkt_len,pkt_or_frag_r,pkt_or_frag_r->is_frag);
	rhp_ip_addr_dump("src_addr",src_addr);
	rhp_ip_addr_dump("dst_addr",dst_addr);


  if( pkt_len <= 0 ){
  	pkt_len = RHP_PKT_IKE_DEFAULT_SIZE;
  }

  if( !pkt_or_frag_r->is_frag ){

  	pkt_or_frag_r->d.pkt = rhp_pkt_alloc(pkt_len);
		if( pkt_or_frag_r->d.pkt == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		pkt_or_frag_r->d.pkt->ikev2_keep_alive = ikemesg->ikev2_keep_alive;

	  if( ikemesg->fixed_tx_if_index >= 0 ){

	  	pkt_or_frag_r->d.pkt->fixed_tx_if_index = ikemesg->fixed_tx_if_index;
	  }

	  dmy_ethh = (rhp_proto_ether*)_rhp_pkt_push(pkt_or_frag_r->d.pkt,sizeof(rhp_proto_ether));

  }else{

  	pkt_or_frag_r->d.frag = rhp_pkt_frag_alloc(pkt_len,0,0);
  	if( pkt_or_frag_r->d.frag == NULL ){
  		RHP_BUG("");
  		err = -ENOMEM;
  		goto error;
  	}

  	dmy_ethh = (rhp_proto_ether*)_rhp_pkt_frag_push(pkt_or_frag_r->d.frag,sizeof(rhp_proto_ether));
  }


	memset(dmy_ethh->dst_addr,0,6);
	memset(dmy_ethh->src_addr,0,6);

  if( src_addr->addr_family == AF_INET && dst_addr->addr_family == AF_INET ){

    dmy_ethh->protocol = RHP_PROTO_ETH_IP;

    if( !pkt_or_frag_r->is_frag ){

    	pkt_or_frag_r->d.pkt->type = RHP_PKT_IPV4_IKE;

    	dmy_iph.raw = (u8*)_rhp_pkt_push(pkt_or_frag_r->d.pkt,sizeof(rhp_proto_ip_v4));

    }else{

    	dmy_iph.raw = (u8*)_rhp_pkt_frag_push(pkt_or_frag_r->d.frag,sizeof(rhp_proto_ip_v4));
    }


	  dmy_iph.v4->ver = 4;
	  dmy_iph.v4->ihl = 5;
	  dmy_iph.v4->tos = 0;
	  dmy_iph.v4->total_len = 0;
	  dmy_iph.v4->id = 0;
	  dmy_iph.v4->frag = 0;
	  dmy_iph.v4->ttl = 64;
	  dmy_iph.v4->protocol = RHP_PROTO_IP_UDP;
	  dmy_iph.v4->check_sum = 0;
	  dmy_iph.v4->src_addr = src_addr->addr.v4;
	  dmy_iph.v4->dst_addr = dst_addr->addr.v4;

  }else if( src_addr->addr_family == AF_INET6 && dst_addr->addr_family == AF_INET6 ){

    dmy_ethh->protocol = RHP_PROTO_ETH_IPV6;

    if( !pkt_or_frag_r->is_frag ){

    	pkt_or_frag_r->d.pkt->type = RHP_PKT_IPV6_IKE;

  		dmy_iph.raw = (u8*)_rhp_pkt_push(pkt_or_frag_r->d.pkt,sizeof(rhp_proto_ip_v6));

    }else{

  		dmy_iph.raw = (u8*)_rhp_pkt_frag_push(pkt_or_frag_r->d.frag,sizeof(rhp_proto_ip_v6));
    }

		dmy_iph.v6->ver = 6;
		dmy_iph.v6->priority = 0;
		dmy_iph.v6->flow_label[0] = 0;
		dmy_iph.v6->flow_label[1] = 0;
		dmy_iph.v6->flow_label[2] = 0;
		dmy_iph.v6->payload_len = 0;
		dmy_iph.v6->next_header = RHP_PROTO_IP_UDP;
		dmy_iph.v6->hop_limit = 64;
		memcpy(dmy_iph.v6->src_addr,src_addr->addr.v6,16);
		memcpy(dmy_iph.v6->dst_addr,dst_addr->addr.v6,16);

  }else{
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  {
    if( !pkt_or_frag_r->is_frag ){
    	dmy_udph = (rhp_proto_udp*)_rhp_pkt_push(pkt_or_frag_r->d.pkt,sizeof(rhp_proto_udp));
    }else{
    	dmy_udph = (rhp_proto_udp*)_rhp_pkt_frag_push(pkt_or_frag_r->d.frag,sizeof(rhp_proto_udp));
    }

		dmy_udph->len = 0;
		dmy_udph->check_sum = 0;
		dmy_udph->src_port = src_addr->port;
		dmy_udph->dst_port = dst_addr->port;
  }

  if( ikemesg->tx_from_nat_t_port ){

    if( !pkt_or_frag_r->is_frag ){
    	non_esp_marker = (u8*)_rhp_pkt_push(pkt_or_frag_r->d.pkt,RHP_PROTO_NON_ESP_MARKER_SZ);
    }else{
    	non_esp_marker = (u8*)_rhp_pkt_frag_push(pkt_or_frag_r->d.frag,RHP_PROTO_NON_ESP_MARKER_SZ);
    }

    *((u32*)non_esp_marker) = RHP_PROTO_NON_ESP_MARKER;
  }

  if( !pkt_or_frag_r->is_frag ){

  	new_ikeh = (rhp_proto_ike*)_rhp_pkt_push(pkt_or_frag_r->d.pkt,sizeof(rhp_proto_ike));

  	pkt_or_frag_r->d.pkt->l2.eth = dmy_ethh;
  	pkt_or_frag_r->d.pkt->l3.raw = dmy_iph.raw;
  	pkt_or_frag_r->d.pkt->l4.udph = dmy_udph;

    if( non_esp_marker ){
    	pkt_or_frag_r->d.pkt->app.raw = non_esp_marker;
    	pkt_or_frag_r->d.pkt->ikev2_non_esp_marker = 1;
    }else{
    	pkt_or_frag_r->d.pkt->app.raw = (u8*)new_ikeh;
    	pkt_or_frag_r->d.pkt->ikev2_non_esp_marker = 0;
    }

  }else{

  	new_ikeh = (rhp_proto_ike*)_rhp_pkt_frag_push(pkt_or_frag_r->d.frag,sizeof(rhp_proto_ike));

  	pkt_or_frag_r->d.frag->l2.eth = dmy_ethh;
  	pkt_or_frag_r->d.frag->l3.raw = dmy_iph.raw;
  	pkt_or_frag_r->d.frag->l4.udph = dmy_udph;

    if( non_esp_marker ){
    	pkt_or_frag_r->d.frag->app.raw = non_esp_marker;
    	pkt_or_frag_r->d.frag->ikev2_non_esp_marker = 1;
    }else{
    	pkt_or_frag_r->d.frag->app.raw = (u8*)new_ikeh;
    	pkt_or_frag_r->d.frag->ikev2_non_esp_marker = 0;
    }
  }

	RHP_TRC(0,RHPTRCID_IKEV2_MESG_SERIALIZE_ALLOC_PKT_RTRN,"xxdx",ikemesg,pkt_or_frag_r,pkt_or_frag_r->is_frag,pkt_or_frag_r->d.raw);
  return 0;

error:
	if( !pkt_or_frag_r->is_frag ){

		if( pkt_or_frag_r->d.pkt ){
			rhp_pkt_unhold(pkt_or_frag_r->d.pkt);
		}

	}else{

		if( pkt_or_frag_r->d.frag ){
			rhp_pkt_frag_free(pkt_or_frag_r->d.frag);
		}
	}

	RHP_TRC(0,RHPTRCID_IKEV2_MESG_SERIALIZE_ALLOC_PKT_ERR,"xE",ikemesg,err);
	return err;
}


static rhp_proto_ike* _rhp_ikev2_mesg_pkt2ikeh(rhp_pkt_or_frag* pkt_or_frag)
{
	rhp_proto_ike* ikeh;

	if( !pkt_or_frag->is_frag ){

		if( pkt_or_frag->d.pkt->ikev2_non_esp_marker ){
			ikeh = (rhp_proto_ike*)(pkt_or_frag->d.pkt->app.raw + RHP_PROTO_NON_ESP_MARKER_SZ);
			RHP_TRC(0,RHPTRCID_IKEV2_MESG_PKT2IKEH_1,"xdxxp",pkt_or_frag,pkt_or_frag->is_frag,pkt_or_frag->d.raw,ikeh,sizeof(rhp_proto_ike),(u8*)ikeh);
		}else{
			ikeh = pkt_or_frag->d.pkt->app.ikeh;
			RHP_TRC(0,RHPTRCID_IKEV2_MESG_PKT2IKEH_2,"xdxxp",pkt_or_frag,pkt_or_frag->is_frag,pkt_or_frag->d.raw,ikeh,sizeof(rhp_proto_ike),(u8*)ikeh);
		}

	}else{

		if( pkt_or_frag->d.frag->ikev2_non_esp_marker ){
			ikeh = (rhp_proto_ike*)(pkt_or_frag->d.frag->app.raw + RHP_PROTO_NON_ESP_MARKER_SZ);
			RHP_TRC(0,RHPTRCID_IKEV2_MESG_PKT2IKEH_3,"xdxxp",pkt_or_frag,pkt_or_frag->is_frag,pkt_or_frag->d.raw,ikeh,sizeof(rhp_proto_ike),(u8*)ikeh);
		}else{
			ikeh = pkt_or_frag->d.frag->app.ikeh;
			RHP_TRC(0,RHPTRCID_IKEV2_MESG_PKT2IKEH_4,"xdxxp",pkt_or_frag,pkt_or_frag->is_frag,pkt_or_frag->d.raw,ikeh,sizeof(rhp_proto_ike),(u8*)ikeh);
		}
	}

	return ikeh;
}

rhp_proto_ike* rhp_ikev2_mesg_pkt2ikeh2(rhp_packet* pkt)
{
	rhp_proto_ike* ikeh;

	if( pkt->ikev2_non_esp_marker ){
		ikeh = (rhp_proto_ike*)(pkt->app.raw + RHP_PROTO_NON_ESP_MARKER_SZ);
	}else{
		ikeh = pkt->app.ikeh;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_MESG_PKT2IKEH2,"xx",pkt,ikeh);
	return ikeh;
}

static int _rhp_ikev2_mesg_exec_enc_impl(
		rhp_ikev2_mesg* ikemesg,
		rhp_vpn* vpn,rhp_ikesa* ikesa,
		int addr_family,rhp_pkt_or_frag* pkt_or_frag,
		u8 pld_type, // RHP_PROTO_IKE_PAYLOAD_E or RHP_PROTO_IKE_PAYLOAD_SKF
		u8 next_payload,
		int aligned_len,int encrypted_len,int enc_payload_len)
{
	int err = -EINVAL;
  rhp_proto_ike* new_ikeh = NULL;
  union {
  	rhp_proto_ike_payload* gen;
  	rhp_proto_ike_enc_payload* enc;
  	rhp_proto_ike_skf_payload* skf;
  } enc_payload;
  int pad_len,block_len,integ_checked_len,icv_len,iv_len;
  u8 *iv_p,*pad_p,*padlen_p,*icv_p,*encrypted_p,*plain_p = NULL;
  rhp_crypto_integ* integ;
  u8 i;

	RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_ENC_IMPL,"xxxLdxdLdLdddd",ikemesg,vpn,ikesa,"AF",addr_family,pkt_or_frag,pkt_or_frag->is_frag,"PROTO_IKE_PAYLOAD",pld_type,"PROTO_IKE_PAYLOAD",next_payload,aligned_len,encrypted_len,enc_payload_len);

  if( ikesa->side == RHP_IKE_INITIATOR ){
    integ = ikesa->integ_i;
  }else{
    integ = ikesa->integ_r;
  }

  icv_len = integ->get_output_len(integ);
  iv_len = ikesa->encr->get_iv_len(ikesa->encr);
  pad_len = aligned_len - encrypted_len - sizeof(u8);
  block_len = ikesa->encr->get_block_len(ikesa->encr);
  integ_checked_len = sizeof(rhp_proto_ike) + enc_payload_len - icv_len;


	//
	// [CAUTION] rhp_pkt_realloc() may be called. Don't access pointers
	//           of dmy_xxxhs, non_esp_marker and ikeh any more.
	//
  if( !pkt_or_frag->is_frag ){

  	pad_p = (u8*)rhp_pkt_expand_tail(pkt_or_frag->d.pkt,(pad_len + sizeof(u8) + icv_len));

  }else{

  	pad_p = (u8*)rhp_pkt_frag_expand_tail(pkt_or_frag->d.frag,(pad_len + sizeof(u8) + icv_len));
  }
	if( pad_p == NULL ){
		RHP_BUG("");
    err = -ENOMEM;
		goto error;
	}

	// [CAUTION] rhp_pkt_realloc() may be called. Get a new pointer from pkt.
	new_ikeh = _rhp_ikev2_mesg_pkt2ikeh(pkt_or_frag);

	enc_payload.gen = (rhp_proto_ike_payload*)(new_ikeh + 1);

	if( pld_type == RHP_PROTO_IKE_PAYLOAD_E ){
		iv_p = (u8*)(enc_payload.enc + 1);
	}else if( pld_type == RHP_PROTO_IKE_PAYLOAD_SKF ){
		iv_p = (u8*)(enc_payload.skf + 1);
	}else{
		RHP_BUG("%d",pld_type);
		err = -EINVAL;
		goto error;
	}

	padlen_p = pad_p + pad_len;
	icv_p = padlen_p + sizeof(u8);


	enc_payload.gen->next_payload = next_payload;
	enc_payload.gen->critical_rsv = RHP_PROTO_IKE_PLD_SET_CRITICAL;
	enc_payload.gen->len = htons(enc_payload_len);


	memcpy(iv_p,ikesa->encr->get_enc_iv(ikesa->encr),iv_len);


	for( i = 0; i < pad_len; i++ ){
		pad_p[i] = (ikesa->padcnt)++;
	}
	*padlen_p = pad_len;


	encrypted_p = iv_p + iv_len;

	plain_p = (u8*)_rhp_malloc(aligned_len);
	if( plain_p == NULL ){
		RHP_BUG("");
		goto error;
	}
	memcpy(plain_p,encrypted_p,aligned_len);

	// tx_ikeh: Default header's template...
	memcpy(new_ikeh,ikemesg->tx_ikeh,sizeof(rhp_proto_ike));
	new_ikeh->next_payload = pld_type;
	new_ikeh->len = htonl(sizeof(rhp_proto_ike) + enc_payload_len);

	if( addr_family == AF_INET ){
		if( !pkt_or_frag->is_frag ){
			RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_ENC_IMPL_PKT,"xxa",ikemesg,pkt_or_frag->d.pkt,(pkt_or_frag->d.pkt->tail - pkt_or_frag->d.pkt->data),RHP_TRC_FMT_A_MAC_IPV4_IKEV2_PLAIN,iv_len,icv_len,pkt_or_frag->d.pkt->data);
			rhp_pkt_trace_dump("_rhp_ikev2_mesg_exec_enc_impl(1)",pkt_or_frag->d.pkt);
		}else{
			RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_ENC_IMPL_PKTFRAG,"xxa",ikemesg,pkt_or_frag->d.frag,(pkt_or_frag->d.frag->tail - pkt_or_frag->d.frag->data),RHP_TRC_FMT_A_MAC_IPV4_IKEV2_PLAIN,iv_len,icv_len,pkt_or_frag->d.frag->data);
			rhp_pkt_frag_trace_dump("_rhp_ikev2_mesg_exec_enc_impl-fr(1)",pkt_or_frag->d.frag);
		}
	}else if( addr_family == AF_INET6 ){
		if( !pkt_or_frag->is_frag ){
			RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_ENC_IMPL_PKT_V6,"xxa",ikemesg,pkt_or_frag->d.pkt,(pkt_or_frag->d.pkt->tail - pkt_or_frag->d.pkt->data),RHP_TRC_FMT_A_MAC_IPV6_IKEV2_PLAIN,iv_len,icv_len,pkt_or_frag->d.pkt->data);
			rhp_pkt_trace_dump("_rhp_ikev2_mesg_exec_enc_impl-6(1)",pkt_or_frag->d.pkt);
		}else{
			RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_ENC_IMPL_PKTFRAG_V6,"xxa",ikemesg,pkt_or_frag->d.frag,(pkt_or_frag->d.frag->tail - pkt_or_frag->d.frag->data),RHP_TRC_FMT_A_MAC_IPV6_IKEV2_PLAIN,iv_len,icv_len,pkt_or_frag->d.frag->data);
			rhp_pkt_frag_trace_dump("_rhp_ikev2_mesg_exec_enc_impl-6-fr(1)",pkt_or_frag->d.frag);
		}
	}


	err = ikesa->encr->encrypt(ikesa->encr,plain_p,aligned_len,encrypted_p,aligned_len);
	if( err ){
		RHP_BUG("");
		goto error;
	}

	err = integ->compute(integ,(u8*)new_ikeh,integ_checked_len,icv_p,icv_len);
	if( err ){
		RHP_BUG("");
		goto error;
	}

	if( block_len < iv_len ){
		RHP_BUG("");
		goto error;
	}

	err = ikesa->encr->update_enc_iv(ikesa->encr,icv_p - iv_len,iv_len);
	if( err ){
		RHP_BUG("");
		goto error;
	}

  if( plain_p ){
  	_rhp_free(plain_p);
  }

	RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_ENC_IMPL_RTRN,"xxx",ikemesg,vpn,ikesa);
	return 0;

error:
	if( plain_p ){
		_rhp_free(plain_p);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_ENC_IMPL_ERR,"xxxE",ikemesg,vpn,ikesa,err);
	return err;
}

static int _rhp_ikev2_mesg_exec_enc(
		rhp_ikev2_mesg* ikemesg,
		rhp_vpn* vpn,rhp_ikesa* ikesa,
		int addr_family,rhp_packet* pkt,
		int aligned_len,int encrypted_len,int enc_payload_len)
{
	int err = -EINVAL;
	rhp_pkt_or_frag pkt_or_frag;
	u8 next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;

	RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_ENC,"xxxLdxddd",ikemesg,vpn,ikesa,"AF",addr_family,pkt,aligned_len,encrypted_len,enc_payload_len);

	if( ikemesg->payload_list_head ){

		next_payload
		= ikemesg->payload_list_head->get_payload_id(ikemesg->payload_list_head);
	}

	pkt_or_frag.is_frag = 0;
	pkt_or_frag.d.pkt = pkt;

	err = _rhp_ikev2_mesg_exec_enc_impl(
					ikemesg,
					vpn,ikesa,
					addr_family,&pkt_or_frag,
					RHP_PROTO_IKE_PAYLOAD_E,next_payload,
					aligned_len,encrypted_len,enc_payload_len);

	if( err ){
		goto error;
	}

	ikemesg->tx_ikeh->next_payload = RHP_PROTO_IKE_PAYLOAD_E;
	ikemesg->tx_ikeh->len = htonl(sizeof(rhp_proto_ike) + enc_payload_len);

	ikemesg->tx_mesg_len = sizeof(rhp_proto_ike) + enc_payload_len;

	RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_ENC_RTRN,"xxxx",ikemesg,vpn,ikesa,pkt);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_ENC_ERR,"xxxxE",ikemesg,vpn,ikesa,pkt,err);
	return err;
}


static int _rhp_ikev2_mesg_exec_enc_impl_v1(
		rhp_ikev2_mesg* ikemesg,
		rhp_vpn* vpn,rhp_ikesa* ikesa,
		int addr_family,rhp_pkt_or_frag* pkt_or_frag,
		int aligned_len,int encrypted_len)
{
	int err = -EINVAL;
  rhp_proto_ike* new_ikeh = NULL;
  int pad_len,block_len;
  u8 *pad_p,*padlen_p,*encrypted_p,*plain_p = NULL;
  u8 i;
  u8 exchange_type = ikemesg->get_exchange_type(ikemesg);
  u32 mesg_id = ikemesg->get_mesg_id(ikemesg);
	rhp_ikev1_p2_session* p2_sess = NULL;
	u8* iv_new = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_ENC_IMPL_V1,"xxxLdxdddbkxx",ikemesg,vpn,ikesa,"AF",addr_family,pkt_or_frag,pkt_or_frag->is_frag,encrypted_len,aligned_len,exchange_type,mesg_id,ikesa->v1.p2_sessions,ikemesg->tx_flag);

  pad_len = aligned_len - encrypted_len - sizeof(u8);
  block_len = ikesa->encr->get_block_len(ikesa->encr);

	if( block_len < ikesa->keys.v1.iv_len ){
		err = -EINVAL;
		RHP_BUG("%d, %d",block_len,ikesa->keys.v1.iv_len);
		goto error;
	}


	//
	// [CAUTION] rhp_pkt_realloc() may be called. Don't access pointers
	//           of dmy_xxxhs, non_esp_marker and ikeh any more.
	//
	pad_p = (u8*)rhp_pkt_expand_tail(pkt_or_frag->d.pkt,(pad_len + sizeof(u8)));
	if( pad_p == NULL ){
		RHP_BUG("");
    err = -ENOMEM;
		goto error;
	}

	// [CAUTION] rhp_pkt_realloc() may be called. Get a new pointer from pkt.
	new_ikeh = _rhp_ikev2_mesg_pkt2ikeh(pkt_or_frag);
	padlen_p = pad_p + pad_len;
	encrypted_p = (u8*)(new_ikeh + 1);

	if( exchange_type == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ||
			exchange_type == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){

		err = ikesa->encr->update_enc_iv(ikesa->encr,ikesa->keys.v1.p1_iv_rx_last_blk,ikesa->keys.v1.iv_len);
		if( err ){
			goto error;
		}

	}else if( exchange_type == RHP_PROTO_IKEV1_EXCHG_QUICK ||
						exchange_type == RHP_PROTO_IKEV1_EXCHG_INFORMATIONAL ||
						exchange_type == RHP_PROTO_IKEV1_EXCHG_TRANSACTION ){

		u8* iv;
		int iv_len;

		p2_sess = rhp_ikev1_p2_session_get(ikesa,mesg_id,exchange_type);
		if( p2_sess == NULL ){

			// One-way INFO mesg.

			iv_new = rhp_ikev1_mesg_gen_iv(ikesa,htonl(mesg_id),&iv_len);
			if( iv_new == NULL ){
				RHP_BUG("");
				err = -EINVAL;
				goto error;
			}

			iv = iv_new;

		}else{

			iv = p2_sess->iv_last_rx_blk;
			iv_len = p2_sess->iv_len;
		}

		err = ikesa->encr->update_enc_iv(ikesa->encr,iv,iv_len);
		if( err ){
			goto error;
		}

	}else{
		err = -EINVAL;
		RHP_BUG("%d",exchange_type);
		goto error;
	}


	for( i = 0; i < pad_len; i++ ){
		pad_p[i] = (ikesa->padcnt)++;
	}
	*padlen_p = pad_len;


	plain_p = (u8*)_rhp_malloc(aligned_len);
	if( plain_p == NULL ){
		RHP_BUG("");
		goto error;
	}
	memcpy(plain_p,encrypted_p,aligned_len);

	// tx_ikeh: Default header's template...
	memcpy(new_ikeh,ikemesg->tx_ikeh,sizeof(rhp_proto_ike));

	{
		new_ikeh->len = htonl((int)sizeof(rhp_proto_ike) + aligned_len);

		new_ikeh->flag = (new_ikeh->flag | RHP_PROTO_IKEV1_HDR_SET_ENCRYPT);

		if( ikemesg->tx_flag & RHP_IKEV2_SEND_REQ_FLAG_V1_COMMIT_BIT ){

			new_ikeh->flag = (new_ikeh->flag | RHP_PROTO_IKEV1_HDR_SET_COMMIT);
		}
	}

	if( addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_ENC_IMPL_V1_PKT,"xxa",ikemesg,pkt_or_frag->d.pkt,(pkt_or_frag->d.pkt->tail - pkt_or_frag->d.pkt->data),RHP_TRC_FMT_A_MAC_IPV4_IKEV2_PLAIN,ikesa->keys.v1.iv_len,0,pkt_or_frag->d.pkt->data);
		rhp_pkt_trace_dump("_rhp_ikev2_mesg_exec_enc_impl(1)",pkt_or_frag->d.pkt);
	}else if( addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_ENC_IMPL_V1_PKT_V6,"xxa",ikemesg,pkt_or_frag->d.pkt,(pkt_or_frag->d.pkt->tail - pkt_or_frag->d.pkt->data),RHP_TRC_FMT_A_MAC_IPV6_IKEV2_PLAIN,ikesa->keys.v1.iv_len,0,pkt_or_frag->d.pkt->data);
		rhp_pkt_trace_dump("_rhp_ikev2_mesg_exec_enc_impl-6(1)",pkt_or_frag->d.pkt);
	}


	err = ikesa->encr->encrypt(ikesa->encr,plain_p,aligned_len,encrypted_p,aligned_len);
	if( err ){
		RHP_BUG("");
		goto error;
	}

	{
		u8* last_blk = (encrypted_p + aligned_len - ikesa->keys.v1.iv_len);

		if( exchange_type == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ||
				exchange_type == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){

			if( !ikemesg->v1_p1_last_mesg ){

				memcpy(ikesa->keys.v1.p1_iv_dec,last_blk,ikesa->keys.v1.iv_len);

			}else{

				if( ikesa->v1.p2_iv_material ){
					_rhp_free(ikesa->v1.p2_iv_material);
				}

				ikesa->v1.p2_iv_material = (u8*)_rhp_malloc(ikesa->keys.v1.iv_len);
				if( ikesa->v1.p2_iv_material == NULL ){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}

				memcpy(ikesa->v1.p2_iv_material,last_blk,ikesa->keys.v1.iv_len);
				ikesa->v1.p2_iv_material_len = ikesa->keys.v1.iv_len;
			}

		}else if( exchange_type == RHP_PROTO_IKEV1_EXCHG_QUICK ||
							exchange_type == RHP_PROTO_IKEV1_EXCHG_INFORMATIONAL ||
							exchange_type == RHP_PROTO_IKEV1_EXCHG_TRANSACTION ){

			if( p2_sess && p2_sess->dec_iv ){

				memcpy(p2_sess->dec_iv,last_blk,ikesa->keys.v1.iv_len);
				p2_sess->iv_len = ikesa->keys.v1.iv_len;
			}

		}else{
			RHP_BUG("%d",exchange_type);
		}
	}


  if( plain_p ){
  	_rhp_free(plain_p);
  }

  if( iv_new ){
  	_rhp_free(iv_new);
  }

  if( p2_sess && p2_sess->clear_aftr_proc ){

  	rhp_ikev1_p2_session_clear(ikesa,p2_sess->mesg_id,p2_sess->exchange_type,0);
  }

	RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_ENC_IMPL_V1_RTRN,"xxx",ikemesg,vpn,ikesa);
	return 0;

error:
	if( plain_p ){
		_rhp_free(plain_p);
	}
  if( iv_new ){
  	_rhp_free(iv_new);
  }
	RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_ENC_IMPL_V1_ERR,"xxxE",ikemesg,vpn,ikesa,err);
	return err;
}

static int _rhp_ikev2_mesg_exec_enc_v1(
		rhp_ikev2_mesg* ikemesg,
		rhp_vpn* vpn,rhp_ikesa* ikesa,
		int addr_family,rhp_packet* pkt,
		int aligned_len,int encrypted_len)
{
	int err = -EINVAL;
	rhp_pkt_or_frag pkt_or_frag;

	RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_ENC_V1,"xxxLdxdd",ikemesg,vpn,ikesa,"AF",addr_family,pkt,encrypted_len,aligned_len);

	pkt_or_frag.is_frag = 0;
	pkt_or_frag.d.pkt = pkt;

	err = _rhp_ikev2_mesg_exec_enc_impl_v1(
					ikemesg,
					vpn,ikesa,
					addr_family,&pkt_or_frag,
					aligned_len,encrypted_len);

	if( err ){
		goto error;
	}

	ikemesg->tx_ikeh->len = htonl((int)sizeof(rhp_proto_ike) + aligned_len);
	ikemesg->tx_mesg_len = (int)sizeof(rhp_proto_ike) + aligned_len;

	RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_ENC_V1_RTRN,"xxxx",ikemesg,vpn,ikesa,pkt);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_ENC_V1_ERR,"xxxxE",ikemesg,vpn,ikesa,pkt,err);
	return err;
}


static int _rhp_ikev2_mesg_exec_frag(
		rhp_ikev2_mesg* ikemesg,rhp_packet* pkt_orig,
		rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ip_addr* src_addr,rhp_ip_addr* dst_addr,
		int frag_size,rhp_packet** pkt_r)
{
	int err = -EINVAL;
	int encrypted_len = (ikemesg->tx_mesg_len - sizeof(rhp_proto_ike));
	int n = 0, i, last_frag_size;
	int pkt_len = RHP_PKT_IKE_DEFAULT_HDRS_SIZE;
	int iv_len, icv_len, block_len;
  rhp_crypto_integ* integ = NULL;
	rhp_packet* pkt = NULL;
	u8* p;

	RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_FRAG,"xxxxxxdx",ikemesg,pkt_orig,vpn,ikesa,src_addr,dst_addr,frag_size,pkt_r);
	rhp_ip_addr_dump("src_addr",src_addr);
	rhp_ip_addr_dump("dst_addr",dst_addr);


	if( ikesa->side == RHP_IKE_INITIATOR ){
		integ = ikesa->integ_i;
	}else{
		integ = ikesa->integ_r;
	}

  iv_len = ikesa->encr->get_iv_len(ikesa->encr);
  block_len = ikesa->encr->get_block_len(ikesa->encr);
	icv_len = integ->get_output_len(integ);

	frag_size -= sizeof(rhp_proto_ike) + sizeof(rhp_proto_ike_skf_payload) + iv_len + icv_len;
	if( frag_size < block_len ){
		RHP_BUG("%d < %d",frag_size,block_len);
		err = -EINVAL;
		goto error;
	}

	frag_size -= (frag_size % block_len) + (int)sizeof(u8);

	n = encrypted_len / frag_size;

	last_frag_size = encrypted_len - (n * frag_size);
	if( last_frag_size ){
		n++;
	}

	pkt_len += (int)sizeof(rhp_proto_ike_skf_payload) + iv_len + frag_size;


	p = (u8*)(pkt_orig->app.ikeh + 1);
	if( pkt_orig->ikev2_non_esp_marker ){
		p += RHP_PROTO_NON_ESP_MARKER_SZ;
	}
	p += sizeof(rhp_proto_ike_enc_payload) + iv_len;


	{
		u8 trc_next_payload = 0;
		if( ikemesg->payload_list_head ){
			trc_next_payload = ikemesg->payload_list_head->get_payload_id(ikemesg->payload_list_head);
		}
		RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_FRAG_PKT,"xxddda",ikemesg,pkt_orig,iv_len,block_len,icv_len,encrypted_len,RHP_TRC_FMT_A_IKEV2_PLAIN_PAYLOADS,0,0,trc_next_payload,p);
	}


	for( i = 0; i < n; i++){

		int aligned_len, frag_enc_len = frag_size;
		int enc_payload_len = sizeof(rhp_proto_ike_skf_payload) + iv_len;
	  rhp_proto_ike_skf_payload* skf_payload;
		rhp_pkt_or_frag pkt_or_frag;
	  u8 next_payload = 0;
	  u8 *p1;

	  pkt_or_frag.d.raw = NULL;

	  if( last_frag_size && i == (n - 1) ){
	  	frag_enc_len = last_frag_size;
	  }

	  {
			pkt_or_frag.is_frag = (i == 0 ? 0 : 1);
			pkt_or_frag.d.raw = NULL;

			err = _rhp_ikev2_mesg_serialize_alloc_pkt(ikemesg,
							src_addr,dst_addr,pkt_len,&pkt_or_frag);
			if( err ){
				goto error;
			}
	  }


    if( !pkt_or_frag.is_frag ){

			pkt = pkt_or_frag.d.pkt;

    	skf_payload = (rhp_proto_ike_skf_payload*)_rhp_pkt_push(pkt_or_frag.d.pkt,
    									sizeof(rhp_proto_ike_skf_payload));
    	if( skf_payload == NULL ){
				err = -EINVAL;
				RHP_BUG("");
				goto error;
    	}

    	if( ikemesg->payload_list_head == NULL ){
				err = -EINVAL;
				RHP_BUG("");
				goto error;
			}

			next_payload
				= ikemesg->payload_list_head->get_payload_id(ikemesg->payload_list_head);

    	p1 = (u8*)_rhp_pkt_push(pkt_or_frag.d.pkt,(iv_len + frag_enc_len));
    	if( p1 == NULL ){
				err = -EINVAL;
				RHP_BUG("");
				goto error;
    	}

    }else{

			_rhp_pkt_frag_enq(pkt,pkt_or_frag.d.frag);

    	skf_payload = (rhp_proto_ike_skf_payload*)_rhp_pkt_frag_push(pkt_or_frag.d.frag,
    									sizeof(rhp_proto_ike_skf_payload));
    	if( skf_payload == NULL ){
				err = -EINVAL;
				RHP_BUG("");
				goto error;
    	}

    	p1 = (u8*)_rhp_pkt_frag_push(pkt_or_frag.d.frag,(iv_len + frag_enc_len));
    	if( p1 == NULL ){
				err = -EINVAL;
				RHP_BUG("");
				goto error;
    	}
    }


  	skf_payload->total_frags = htons((u16)n);
  	skf_payload->frag_num = htons((u16)(i + 1));

    p1 += iv_len;
  	memcpy(p1,p,frag_enc_len);


		aligned_len = ikesa->encr->get_block_aligned_len(ikesa->encr,frag_enc_len + (int)sizeof(u8));
		enc_payload_len += aligned_len + icv_len;

		RHP_TRC_FREQ(0,RHPTRCID_IKEV2_MESG_EXEC_FRAG_SKF_PLD,"dxxxxWWdddLdddddxp",i,ikemesg,pkt_orig,vpn,ikesa,skf_payload->total_frags,skf_payload->frag_num,aligned_len,iv_len,icv_len,"PROTO_IKE_PAYLOAD",next_payload,frag_enc_len,frag_size,last_frag_size,pkt_or_frag.is_frag,pkt_or_frag.d.raw,enc_payload_len,(u8*)skf_payload);
		if( !pkt_or_frag.is_frag ){
			rhp_pkt_trace_dump("pkt_or_frag.d.pkt",pkt_or_frag.d.pkt);
		}else{
			rhp_pkt_frag_trace_dump("pkt_or_frag.d.frag",pkt_or_frag.d.frag);
		}

		err = _rhp_ikev2_mesg_exec_enc_impl(
						ikemesg,
						vpn,ikesa,
						src_addr->addr_family,&pkt_or_frag,
						RHP_PROTO_IKE_PAYLOAD_SKF,next_payload,
						aligned_len,frag_enc_len,enc_payload_len);

		if( err ){
			goto error;
		}

    if( !pkt_or_frag.is_frag ){

			ikemesg->tx_ikeh->next_payload = RHP_PROTO_IKE_PAYLOAD_SKF;
			ikemesg->tx_ikeh->len = htonl(sizeof(rhp_proto_ike) + enc_payload_len);

			ikemesg->tx_mesg_len = sizeof(rhp_proto_ike) + enc_payload_len;
		}

  	p += frag_enc_len;
	}

	*pkt_r = pkt;

	rhp_pkt_trace_dump("*pkt_r",*pkt_r);
	rhp_pkt_frags_trace_dump("*pkt_r",*pkt_r);
	RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_FRAG_RTRN,"xxxxdxdddd",ikemesg,pkt_orig,vpn,ikesa,frag_size,*pkt_r,ikemesg->tx_ikeh->len,ikemesg->tx_mesg_len,encrypted_len,n);

	return 0;

error:
	if( pkt ){
		rhp_pkt_unhold(pkt);
	}
	RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_FRAG_ERR,"xxxxdddE",ikemesg,pkt_orig,vpn,ikesa,frag_size,encrypted_len,n,err);
	return err;
}


static int _rhp_ikev2_mesg_exec_serialize(rhp_ikev2_mesg* ikemesg,rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ip_addr* src_addr,rhp_ip_addr* dst_addr,rhp_packet** pkt_r)
{
	int err = -EINVAL;
  rhp_packet* pkt = NULL;
  int enc_payload_len,encrypted_len,aligned_len,iv_len = 0,icv_len = 0;
	rhp_pkt_or_frag pkt_or_frag;
	int e_pld_head_offset = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_SERIALIZE,"xxxxxx",ikemesg,vpn,ikesa,src_addr,dst_addr,pkt_r);
	rhp_ip_addr_dump("_rhp_ikev2_mesg_exec_serialize: src_addr",src_addr);
	rhp_ip_addr_dump("_rhp_ikev2_mesg_exec_serialize: dst_addr",dst_addr);

  if( ikesa == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_SERIALIZE_IKESA,"xxddsxLdddd",ikemesg,ikesa,vpn->nat_t_info.use_nat_t_port,vpn->nat_t_info.exec_nat_t,vpn->local.if_info.if_name,ikesa->encr,"IKE_SIDE",ikesa->side,ikemesg->fixed_tx_if_index,vpn->exec_mobike,vpn->mobike.resp.rt_ck_pending);

  {
  	pkt_or_frag.is_frag = 0;

  	err = _rhp_ikev2_mesg_serialize_alloc_pkt(ikemesg,
  					src_addr,dst_addr,0,&pkt_or_frag);
  	if( err ){
  		goto error;
  	}

  	pkt = pkt_or_frag.d.pkt;
  	pkt_or_frag.d.pkt = NULL;
  }

  if( ikesa->encr ){

  	u8* enc_payload_p;

    iv_len = ikesa->encr->get_iv_len(ikesa->encr);

    enc_payload_p = _rhp_pkt_push(pkt,sizeof(rhp_proto_ike_enc_payload) + iv_len);
    if( enc_payload_p == NULL ){
      RHP_BUG("");
      err = -ENOMEM;
      goto error;
    }

    e_pld_head_offset = (int)sizeof(rhp_proto_ike_enc_payload) + iv_len;
  }


  //
  //
  // [CAUTION] rhp_pkt_realloc() may be called. Don't access pointers of dmy_xxxhs,
  //           non_esp_marker and ikeh any more.
  //
  //
	err = ikemesg->search_payloads(ikemesg,0,NULL,NULL,
					_rhp_ikev2_mesg_serialize_payload_cb,pkt);
  if( err && err != -ENOENT && err != RHP_STATUS_ENUM_OK  ){
    RHP_BUG("");
    goto error;
  }
  err = 0;


  if( ikesa->encr ){

    rhp_crypto_integ* integ = NULL;
    int frag_size = 0;

  	if( rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_IKEV2_PLAIN] &&
  			(!rhp_packet_capture_realm_id || (vpn && rhp_packet_capture_realm_id == vpn->vpn_realm_id)) ){

  		_rhp_ikev2_mesg_tx_pcap_write(vpn,ikemesg,e_pld_head_offset,pkt,0);
    }


    {
			if( ikesa->side == RHP_IKE_INITIATOR ){
				integ = ikesa->integ_i;
			}else{
				integ = ikesa->integ_r;
			}

			enc_payload_len = sizeof(rhp_proto_ike_enc_payload) + iv_len;
			encrypted_len = (ikemesg->tx_mesg_len - sizeof(rhp_proto_ike));

			if( encrypted_len < 0 ){
				RHP_BUG("");
				err = -EINVAL;
				goto error;
			}

			aligned_len = ikesa->encr->get_block_aligned_len(ikesa->encr,encrypted_len + (int)sizeof(u8));
			icv_len = integ->get_output_len(integ);

			enc_payload_len += aligned_len + icv_len;
    }

    if( _rhp_ikev2_mesg_frag_needed(vpn,src_addr->addr_family,
    			(sizeof(rhp_proto_ike) + enc_payload_len),&frag_size) ){

    	err = _rhp_ikev2_mesg_exec_frag(ikemesg,pkt,vpn,ikesa,
    					src_addr,dst_addr,frag_size,pkt_r);
    	if( err ){
        goto error;
    	}

      rhp_pkt_unhold(pkt);

    	pkt = *pkt_r;

    }else{

    	err = _rhp_ikev2_mesg_exec_enc(ikemesg,
    					vpn,ikesa,
    					src_addr->addr_family,pkt,
    					aligned_len,encrypted_len,enc_payload_len);

    	if( err ){
        goto error;
    	}

    	*pkt_r = pkt;
    }

  }else{

  	rhp_proto_ike* new_ikeh = NULL;

  	if(	(ikesa->state != RHP_IKESA_STAT_DEFAULT)						&&
  			(ikesa->state != RHP_IKESA_STAT_I_IKE_SA_INIT_SENT) &&
  			(ikesa->state != RHP_IKESA_STAT_R_IKE_SA_INIT_SENT) ){
      RHP_BUG("%d",ikesa->state);
      err = -EINVAL;
      goto error;
  	}

  	pkt_or_frag.is_frag = 0;
  	pkt_or_frag.d.pkt = pkt;

    // [CAUTION] rhp_pkt_realloc() may be called. Get a new pointer from pkt.
  	new_ikeh = _rhp_ikev2_mesg_pkt2ikeh(&pkt_or_frag);

  	ikemesg->tx_ikeh->len = htonl(ikemesg->tx_mesg_len);

  	ikemesg->tx_ikeh->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
  	if( ikemesg->payload_list_head ){

  		ikemesg->tx_ikeh->next_payload
  			= ikemesg->payload_list_head->get_payload_id(ikemesg->payload_list_head);
    }

  	memcpy(new_ikeh,ikemesg->tx_ikeh,sizeof(rhp_proto_ike));

  	*pkt_r = pkt;
  }


  {
  	int apdx_len = (pkt->ikev2_non_esp_marker ? RHP_PROTO_NON_ESP_MARKER_SZ : 0);
  	rhp_proto_ike* new_ikeh;

  	{
			pkt_or_frag.is_frag = 0;
			pkt_or_frag.d.pkt = pkt;

			new_ikeh = _rhp_ikev2_mesg_pkt2ikeh(&pkt_or_frag);

			if( src_addr->addr_family == AF_INET ){

				// [CAUTION] rhp_pkt_realloc() may be called. Get a new pointer from pkt.
				pkt->l3.iph_v4->total_len
					= htons(ntohl(new_ikeh->len) + sizeof(rhp_proto_ip_v4) + sizeof(rhp_proto_udp) + apdx_len);

			}else if( src_addr->addr_family == AF_INET6 ){

				// [CAUTION] rhp_pkt_realloc() may be called. Get a new pointer from pkt.
				pkt->l3.iph_v6->payload_len
					= htons(ntohl(new_ikeh->len) + sizeof(rhp_proto_udp) + apdx_len);
			}

			// [CAUTION] rhp_pkt_realloc() may be called. Get a new pointer from pkt.
			pkt->l4.udph->len
				= htons(ntohl(new_ikeh->len) + sizeof(rhp_proto_udp) + apdx_len);

			pkt->ikev2_exchange_type = new_ikeh->exchange_type;
  	}

    if( pkt->frags.frags_num ){

    	rhp_packet_frag* frag = pkt->frags.head;

    	rhp_ikev2_sync_frag_headers(pkt);

	  	pkt_or_frag.is_frag = 1;

	  	while( frag ){

		  	pkt_or_frag.d.frag = frag;

		  	new_ikeh = _rhp_ikev2_mesg_pkt2ikeh(&pkt_or_frag);

		    if( src_addr->addr_family == AF_INET ){

		    	// [CAUTION] rhp_pkt_realloc() may be called. Get a new pointer from pkt.
		    	frag->l3.iph_v4->total_len
		    		= htons(ntohl(new_ikeh->len) + sizeof(rhp_proto_ip_v4) + sizeof(rhp_proto_udp) + apdx_len);

		    }else if( src_addr->addr_family == AF_INET6 ){

		    	// [CAUTION] rhp_pkt_realloc() may be called. Get a new pointer from pkt.
		    	frag->l3.iph_v6->payload_len
		    		= htons(ntohl(new_ikeh->len) + sizeof(rhp_proto_udp) + apdx_len);
		    }

		    // [CAUTION] rhp_pkt_realloc() may be called. Get a new pointer from pkt.
		    frag->l4.udph->len
		    	= htons(ntohl(new_ikeh->len) + sizeof(rhp_proto_udp) + apdx_len);

				frag = frag->next;
    	}
    }


    {
    	rhp_packet_frag* frag = pkt->frags.head;
			if( src_addr->addr_family == AF_INET ){
				RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_SERIALIZE_PKT_2,"xxda",ikemesg,pkt,pkt->frags.frags_num,(pkt->tail - pkt->data),RHP_TRC_FMT_A_MAC_IPV4_IKEV2,iv_len,icv_len,pkt->data);
				while( frag ){
					RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_SERIALIZE_PKT_FRAG_2,"xxxa",ikemesg,pkt,frag,(frag->tail - frag->data),RHP_TRC_FMT_A_MAC_IPV4_IKEV2,iv_len,icv_len,frag->data);
					frag = frag->next;
				}
			}else if( src_addr->addr_family == AF_INET6 ){
				RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_SERIALIZE_PKT_V6_2,"xxda",ikemesg,pkt,pkt->frags.frags_num,(pkt->tail - pkt->data),RHP_TRC_FMT_A_MAC_IPV6_IKEV2,iv_len,icv_len,pkt->data);
				while( frag ){
					RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_SERIALIZE_PKT_FRAG_V6_2,"xxxa",ikemesg,pkt,frag,(frag->tail - frag->data),RHP_TRC_FMT_A_MAC_IPV6_IKEV2,iv_len,icv_len,frag->data);
					frag = frag->next;
				}
			}
			rhp_pkt_trace_dump("_rhp_ikev2_mesg_exec_serialize(2)",pkt);
			rhp_pkt_frags_trace_dump("_rhp_ikev2_mesg_exec_serialize(2)-fr",pkt);
    }
  }


  RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_SERIALIZE_RTRN,"xxxd",ikemesg,vpn,ikesa);
  return 0;

error:
  if( pkt ){
    rhp_pkt_unhold(pkt);
  }

  *pkt_r = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_SERIALIZE_ERR,"xxxE",ikemesg,vpn,ikesa,err);
  return err;
}

static int _rhp_ikev2_mesg_serialize(rhp_ikev2_mesg* ikemesg,rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_packet** pkt_r)
{
	int err = -EINVAL;
	rhp_ip_addr src_addr, dst_addr;
	int mobike_i_pending = 0, mobike_r_pending = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_SERIALIZE,"xxxx",vpn,ikemesg,ikesa,pkt_r);

  rhp_ip_addr_reset(&src_addr);
  rhp_ip_addr_reset(&dst_addr);

  if( ikesa == NULL ){
    RHP_BUG("");
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_SERIALIZE_IKESA,"xxddsxLdddd",ikemesg,ikesa,vpn->nat_t_info.use_nat_t_port,vpn->nat_t_info.exec_nat_t,vpn->local.if_info.if_name,ikesa->encr,"IKE_SIDE",ikesa->side,ikemesg->fixed_tx_if_index,vpn->exec_mobike,vpn->mobike.resp.rt_ck_pending);
  if( ikemesg->fixed_src_addr ){
  	rhp_ip_addr_dump("_rhp_ikev2_mesg_serialize: fixed_src_addr",ikemesg->fixed_src_addr);
  }
  if( ikemesg->fixed_dst_addr ){
  	rhp_ip_addr_dump("_rhp_ikev2_mesg_serialize: fixed_dst_addr",ikemesg->fixed_dst_addr);
  }


  if( rhp_ikev2_mobike_pending(vpn) ){
  	if( vpn->origin_side == RHP_IKE_RESPONDER ){
  		mobike_r_pending = 1;
  	}else{
  		mobike_i_pending = 1;
  	}
  }

  if( (ikemesg->is_request(ikemesg) &&
  		 ( vpn->nat_t_info.use_nat_t_port || vpn->nat_t_info.always_use_nat_t_port )) ||
  		(vpn->nat_t_info.exec_nat_t &&
  		 (ikemesg->get_exchange_type(ikemesg) != RHP_PROTO_IKE_EXCHG_IKE_SA_INIT) &&
  		 (ikemesg->get_exchange_type(ikemesg) != RHP_PROTO_IKE_EXCHG_SESS_RESUME)) ){

  	ikemesg->tx_from_nat_t_port = 1;
  }


  if( ikemesg->fixed_src_addr ){

  	rhp_ip_addr_set2(&src_addr,
  			ikemesg->fixed_src_addr->addr_family,ikemesg->fixed_src_addr->addr.raw,0);

  }else if( mobike_i_pending ){

		if( vpn->mobike.init.cand_path_maps_num && vpn->mobike.init.cand_path_maps &&
				vpn->mobike.init.cand_path_maps_cur_idx < vpn->mobike.init.cand_path_maps_num ){

			rhp_mobike_path_map* pmap
			= &(vpn->mobike.init.cand_path_maps[vpn->mobike.init.cand_path_maps_cur_idx]);

	  	rhp_ip_addr_set2(&src_addr,
	  			pmap->my_if_info.addr_family,pmap->my_if_info.addr.raw,0);

		}else{

	  	rhp_ip_addr_set2(&src_addr,
	  			vpn->local.if_info.addr_family,vpn->local.if_info.addr.raw,0);
		}

  }else if( mobike_r_pending ){

  	rhp_ip_addr_set2(&src_addr,
  			vpn->mobike.resp.rt_ck_pend_local_if_info.addr_family,
  			vpn->mobike.resp.rt_ck_pend_local_if_info.addr.raw,0);

  }else{

  	rhp_ip_addr_set2(&src_addr,
  			vpn->local.if_info.addr_family,vpn->local.if_info.addr.raw,0);
  }

  if( ikemesg->tx_from_nat_t_port ){
  	src_addr.port = vpn->local.port_nat_t;
  }else{
  	src_addr.port = vpn->local.port;
  }


  if( ikemesg->fixed_dst_addr ){

  	rhp_ip_addr_set2(&dst_addr,
  			ikemesg->fixed_dst_addr->addr_family,
  			ikemesg->fixed_dst_addr->addr.raw,0);

		if( ikemesg->fixed_dst_addr->port ){
			dst_addr.port = ikemesg->fixed_dst_addr->port;
		}else{
			dst_addr.port = vpn->peer_addr.port;
		}

  }else if( mobike_i_pending ){

		if( vpn->mobike.init.cand_path_maps_num && vpn->mobike.init.cand_path_maps &&
				vpn->mobike.init.cand_path_maps_cur_idx < vpn->mobike.init.cand_path_maps_num ){

			rhp_mobike_path_map* pmap
			= &(vpn->mobike.init.cand_path_maps[vpn->mobike.init.cand_path_maps_cur_idx]);

	  	rhp_ip_addr_set2(&dst_addr,
	  			pmap->peer_addr.addr_family,pmap->peer_addr.addr.raw,
	  			pmap->peer_addr.port);

		}else{

	  	rhp_ip_addr_set2(&dst_addr,
	  			vpn->peer_addr.addr_family,vpn->peer_addr.addr.raw,vpn->peer_addr.port);
		}

  }else if( mobike_r_pending ){

  	rhp_ip_addr_set2(&dst_addr,
  			vpn->mobike.resp.rt_ck_pend_peer_addr.addr_family,
  			vpn->mobike.resp.rt_ck_pend_peer_addr.addr.raw,0);

  	if( vpn->mobike.resp.rt_ck_pend_peer_addr.port ){
  		dst_addr.port = vpn->mobike.resp.rt_ck_pend_peer_addr.port;
  	}else{
  		dst_addr.port = vpn->peer_addr.port;
  	}

  }else{

  	rhp_ip_addr_set2(&dst_addr,
  			vpn->peer_addr.addr_family,vpn->peer_addr.addr.raw,vpn->peer_addr.port);
  }


  err = _rhp_ikev2_mesg_exec_serialize(ikemesg,vpn,ikesa,&src_addr,&dst_addr,pkt_r);
  if( err ){
  	goto error;
  }


	RHP_TRC(0,RHPTRCID_IKEV2_MESG_SERIALIZE_RTRN,"xxxx",ikemesg,vpn,ikesa,*pkt_r);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_MESG_SERIALIZE_ERR,"xxxE",ikemesg,vpn,ikesa,err);
	return err;
}


static int _rhp_ikev2_mesg_exec_serialize_v1(rhp_ikev2_mesg* ikemesg,rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ip_addr* src_addr,rhp_ip_addr* dst_addr,rhp_packet** pkt_r)
{
	int err = -EINVAL;
  rhp_packet* pkt = NULL;
  int encrypted_len,aligned_len;
	rhp_pkt_or_frag pkt_or_frag;

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_SERIALIZE_V1,"xxxxxx",ikemesg,vpn,ikesa,src_addr,dst_addr,pkt_r);
	rhp_ip_addr_dump("_rhp_ikev2_mesg_exec_serialize_v1: src_addr",src_addr);
	rhp_ip_addr_dump("_rhp_ikev2_mesg_exec_serialize_v1: dst_addr",dst_addr);

  if( ikesa == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_SERIALIZE_V1_IKESA,"xxddsxLddx",ikemesg,ikesa,vpn->nat_t_info.use_nat_t_port,vpn->nat_t_info.exec_nat_t,vpn->local.if_info.if_name,ikesa->encr,"IKE_SIDE",ikesa->side,ikemesg->fixed_tx_if_index,ikemesg->tx_flag);

  {
  	pkt_or_frag.is_frag = 0;

  	err = _rhp_ikev2_mesg_serialize_alloc_pkt(ikemesg,
  					src_addr,dst_addr,0,&pkt_or_frag);
  	if( err ){
  		goto error;
  	}

  	pkt = pkt_or_frag.d.pkt;
  	pkt_or_frag.d.pkt = NULL;
  }


  //
  //
  // [CAUTION] rhp_pkt_realloc() may be called. Don't access pointers of dmy_xxxhs,
  //           non_esp_marker and ikeh any more.
  //
  //
	err = ikemesg->search_payloads(ikemesg,0,NULL,NULL,
					_rhp_ikev2_mesg_serialize_payload_cb,pkt);
  if( err && err != -ENOENT && err != RHP_STATUS_ENUM_OK  ){
    RHP_BUG("");
    goto error;
  }
  err = 0;


	ikemesg->tx_ikeh->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
	if( ikemesg->payload_list_head ){

		ikemesg->tx_ikeh->next_payload
			= ikemesg->payload_list_head->get_payload_id(ikemesg->payload_list_head);
  }


  if( ikesa->encr && !ikemesg->v1_dont_enc ){

  	if( rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_IKEV2_PLAIN] &&
  			(!rhp_packet_capture_realm_id || (vpn && rhp_packet_capture_realm_id == vpn->vpn_realm_id)) ){

  		_rhp_ikev2_mesg_tx_pcap_write(vpn,ikemesg,0,pkt,1);
    }

		encrypted_len = (ikemesg->tx_mesg_len - sizeof(rhp_proto_ike));
		if( encrypted_len < 0 ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		aligned_len = ikesa->encr->get_block_aligned_len(ikesa->encr,encrypted_len + (int)sizeof(u8));

		err = _rhp_ikev2_mesg_exec_enc_v1(ikemesg,
  					vpn,ikesa,
  					src_addr->addr_family,pkt,
  					aligned_len,encrypted_len);

  	if( err ){
      goto error;
  	}

  	*pkt_r = pkt;

  }else{

  	rhp_proto_ike* new_ikeh = NULL;

		if(	(ikesa->state != RHP_IKESA_STAT_DEFAULT)						&&
				(ikesa->state != RHP_IKESA_STAT_V1_MAIN_1ST_SENT_I) &&
				(ikesa->state != RHP_IKESA_STAT_V1_MAIN_3RD_SENT_I) &&
				(ikesa->state != RHP_IKESA_STAT_V1_MAIN_2ND_SENT_R) &&
				(ikesa->state != RHP_IKESA_STAT_V1_MAIN_4TH_SENT_R) &&
				(ikesa->state != RHP_IKESA_STAT_V1_AGG_1ST_SENT_I) &&
				(ikesa->state != RHP_IKESA_STAT_V1_AGG_2ND_SENT_R) ){
			RHP_BUG("%d",ikesa->state);
			err = -EINVAL;
			goto error;
		}

  	pkt_or_frag.is_frag = 0;
  	pkt_or_frag.d.pkt = pkt;

    // [CAUTION] rhp_pkt_realloc() may be called. Get a new pointer from pkt.
  	new_ikeh = _rhp_ikev2_mesg_pkt2ikeh(&pkt_or_frag);

  	ikemesg->tx_ikeh->len = htonl(ikemesg->tx_mesg_len);

  	if( ikemesg->tx_flag & RHP_IKEV2_SEND_REQ_FLAG_V1_COMMIT_BIT ){

  		ikemesg->tx_ikeh->flag = (ikemesg->tx_ikeh->flag | RHP_PROTO_IKEV1_HDR_SET_COMMIT);
  	}

  	memcpy(new_ikeh,ikemesg->tx_ikeh,sizeof(rhp_proto_ike));

  	*pkt_r = pkt;
  }


  {
  	int apdx_len = (pkt->ikev2_non_esp_marker ? RHP_PROTO_NON_ESP_MARKER_SZ : 0);
  	rhp_proto_ike* new_ikeh;

  	{
			pkt_or_frag.is_frag = 0;
			pkt_or_frag.d.pkt = pkt;

			new_ikeh = _rhp_ikev2_mesg_pkt2ikeh(&pkt_or_frag);

			if( src_addr->addr_family == AF_INET ){

				// [CAUTION] rhp_pkt_realloc() may be called. Get a new pointer from pkt.
				pkt->l3.iph_v4->total_len
					= htons(ntohl(new_ikeh->len) + sizeof(rhp_proto_ip_v4) + sizeof(rhp_proto_udp) + apdx_len);

			}else if( src_addr->addr_family == AF_INET6 ){

				// [CAUTION] rhp_pkt_realloc() may be called. Get a new pointer from pkt.
				pkt->l3.iph_v6->payload_len
					= htons(ntohl(new_ikeh->len) + sizeof(rhp_proto_udp) + apdx_len);
			}

			// [CAUTION] rhp_pkt_realloc() may be called. Get a new pointer from pkt.
			pkt->l4.udph->len
				= htons(ntohl(new_ikeh->len) + sizeof(rhp_proto_udp) + apdx_len);

			pkt->ikev2_exchange_type = new_ikeh->exchange_type;
  	}


    {
			if( src_addr->addr_family == AF_INET ){
				RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_SERIALIZE_V1_PKT_2,"xxa",ikemesg,pkt,(pkt->tail - pkt->data),RHP_TRC_FMT_A_MAC_IPV4_IKEV2,ikesa->keys.v1.iv_len,0,pkt->data);
			}else if( src_addr->addr_family == AF_INET6 ){
				RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_SERIALIZE_V1_PKT_V6_2,"xxa",ikemesg,pkt,(pkt->tail - pkt->data),RHP_TRC_FMT_A_MAC_IPV6_IKEV2,ikesa->keys.v1.iv_len,0,pkt->data);
			}
			rhp_pkt_trace_dump("_rhp_ikev2_mesg_exec_serialize_v1(2)",pkt);
    }
  }

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_SERIALIZE_V1_RTRN,"xxxd",ikemesg,vpn,ikesa);
  return 0;

error:
  if( pkt ){
    rhp_pkt_unhold(pkt);
  }

  *pkt_r = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_EXEC_SERIALIZE_V1_ERR,"xxxE",ikemesg,vpn,ikesa,err);
  return err;
}

static int _rhp_ikev2_mesg_serialize_v1(rhp_ikev2_mesg* ikemesg,rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_packet** pkt_r)
{
	int err = -EINVAL;
	rhp_ip_addr src_addr, dst_addr;

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_SERIALIZE_V1,"xxxx",vpn,ikemesg,ikesa,pkt_r);

  rhp_ip_addr_reset(&src_addr);
  rhp_ip_addr_reset(&dst_addr);

  if( ikesa == NULL ){
    RHP_BUG("");
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_SERIALIZE_V1_IKESA,"xxddsxLdddd",ikemesg,ikesa,vpn->nat_t_info.use_nat_t_port,vpn->nat_t_info.exec_nat_t,vpn->local.if_info.if_name,ikesa->encr,"IKE_SIDE",ikesa->side,ikemesg->fixed_tx_if_index,vpn->exec_mobike,vpn->mobike.resp.rt_ck_pending);
  if( ikemesg->fixed_src_addr ){
  	rhp_ip_addr_dump("_rhp_ikev2_mesg_serialize: fixed_src_addr",ikemesg->fixed_src_addr);
  }
  if( ikemesg->fixed_dst_addr ){
  	rhp_ip_addr_dump("_rhp_ikev2_mesg_serialize: fixed_dst_addr",ikemesg->fixed_dst_addr);
  }


  if( (!ikemesg->v1_dont_nat_t_port &&
  		 (vpn->nat_t_info.use_nat_t_port || vpn->nat_t_info.exec_nat_t)) ){

  	ikemesg->tx_from_nat_t_port = 1;
  }


  if( ikemesg->fixed_src_addr ){

  	rhp_ip_addr_set2(&src_addr,
  			ikemesg->fixed_src_addr->addr_family,ikemesg->fixed_src_addr->addr.raw,0);

  }else{

  	rhp_ip_addr_set2(&src_addr,
  			vpn->local.if_info.addr_family,vpn->local.if_info.addr.raw,0);
  }

  if( ikemesg->tx_from_nat_t_port ){
  	src_addr.port = vpn->local.port_nat_t;
  }else{
  	src_addr.port = vpn->local.port;
  }


  if( ikemesg->fixed_dst_addr ){

  	rhp_ip_addr_set2(&dst_addr,
  			ikemesg->fixed_dst_addr->addr_family,
  			ikemesg->fixed_dst_addr->addr.raw,0);

		if( ikemesg->fixed_dst_addr->port ){
			dst_addr.port = ikemesg->fixed_dst_addr->port;
		}else{
			dst_addr.port = vpn->peer_addr.port;
		}

  }else if( ikemesg->v1_dont_nat_t_port ){

  	rhp_ip_addr_set2(&dst_addr,
  			vpn->peer_addr.addr_family,vpn->peer_addr.addr.raw,ikemesg->v1_dont_nat_t_port);

  }else{

  	rhp_ip_addr_set2(&dst_addr,
  			vpn->peer_addr.addr_family,vpn->peer_addr.addr.raw,vpn->peer_addr.port);
  }


  err = _rhp_ikev2_mesg_exec_serialize_v1(ikemesg,vpn,ikesa,&src_addr,&dst_addr,pkt_r);
  if( err ){
  	goto error;
  }


	RHP_TRC(0,RHPTRCID_IKEV2_MESG_SERIALIZE_V1_RTRN,"xxxx",ikemesg,vpn,ikesa,*pkt_r);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_MESG_SERIALIZE_V1_ERR,"xxxE",ikemesg,vpn,ikesa,err);
	return err;
}


int rhp_ikev2_mesg_rx_integ_check(rhp_packet* pkt,rhp_ikesa* ikesa)
{
  int err = -EINVAL;
  rhp_proto_ike* ikeh;
  union {
  	rhp_proto_ike_payload* gen;
  	rhp_proto_ike_enc_payload* enc;
  	rhp_proto_ike_skf_payload* skf;
  } enc_payloadh;
  int enc_payload_len, enc_payload_hdr_len;
  rhp_crypto_integ* integ;
  int iv_len,block_len,icv_len,integ_checked_len,ikemesg_len;
  u8* icv_p,*icv_w = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_RX_INTEG_CHECK,"xx",pkt,ikesa);

  if( ikesa == NULL ){
    RHP_BUG("");
    goto error;
  }

  ikeh = pkt->app.ikeh;
  if( ikeh == NULL ){
    RHP_BUG("");
    goto error;
  }

  if( ikesa->prf == NULL || ikesa->encr == NULL ||
  		ikesa->integ_i == NULL || ikesa->integ_r == NULL ){

    if( ikesa->prf == NULL && ikesa->encr == NULL &&
    		ikesa->integ_i == NULL && ikesa->integ_r == NULL &&
        ikesa->side == RHP_IKE_RESPONDER &&
        ikesa->state == RHP_IKESA_STAT_R_IKE_SA_INIT_SENT &&
        ikeh->exchange_type == RHP_PROTO_IKE_EXCHG_IKE_AUTH ){

    	err = rhp_ikesa_crypto_setup_r(ikesa);
    	if( err ){
        RHP_TRC(0,RHPTRCID_IKEV2_MESG_RX_INTEG_CHECK_CRYPTO_SETUP_R_ERR,"xxE",pkt,ikesa,err);
        goto error;
      }

    }else{
      RHP_BUG("");
      goto error;
    }
  }


  if( ikeh->next_payload == RHP_PROTO_IKE_PAYLOAD_E ){

  	enc_payload_hdr_len = sizeof(rhp_proto_ike_enc_payload);

  }else if( ikeh->next_payload == RHP_PROTO_IKE_PAYLOAD_SKF ){

  	enc_payload_hdr_len = sizeof(rhp_proto_ike_skf_payload);

  }else{
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_RX_INTEG_CHECK_NOT_E_PLD_ERR,"xxLb",pkt,ikesa,"PROTO_IKE_PAYLOAD",ikeh->next_payload);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


  if( _rhp_pkt_try_pull(pkt,enc_payload_hdr_len) ){
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_RX_INTEG_CHECK_E_PLD_BAD_LEN_1,"xxd",pkt,ikesa,enc_payload_hdr_len);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


  enc_payloadh.gen = (rhp_proto_ike_payload*)pkt->data;

  ikemesg_len = ntohl(ikeh->len);
  enc_payload_len = (int)ntohs(enc_payloadh.gen->len);

  if( ((u8*)enc_payloadh.gen) + enc_payload_len != pkt->tail ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_RX_INTEG_CHECK_E_PLD_BAD_LEN_2,"xxdd",pkt,ikesa,ikemesg_len,enc_payload_len);
    goto error;
  }

  if( RHP_PROTO_IKE_HDR_INITIATOR(ikeh->flag) ){
    integ = ikesa->integ_i;
  }else{
    integ = ikesa->integ_r;
  }

  iv_len = ikesa->encr->get_iv_len(ikesa->encr);
  block_len = ikesa->encr->get_block_len(ikesa->encr);
  icv_len = integ->get_output_len(integ);

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_RX_INTEG_CHECK_CRYPTO_LENS,"xxddd",pkt,ikesa,iv_len,block_len,icv_len);

  if( enc_payload_len < enc_payload_hdr_len + iv_len + block_len + icv_len ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_RX_INTEG_CHECK_E_PLD_BAD_LEN_3,"xxddddd",pkt,ikesa,enc_payload_len,enc_payload_hdr_len,iv_len,block_len,icv_len);
    goto error;
  }

  icv_p = ((u8*)enc_payloadh.gen) + enc_payload_len - icv_len;

  icv_w = (u8*)_rhp_malloc(icv_len);
  if( icv_w == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }

  integ_checked_len = ntohl(ikeh->len) - icv_len;

  err = integ->compute(integ,(u8*)ikeh,integ_checked_len,icv_w,icv_len);
  if( err ){
  	RHP_TRC(0,RHPTRCID_IKEV2_MESG_RX_INTEG_CHECK_INTEG_COMPUTE_ERR,"xxxE",pkt,ikesa,integ,err);
  	err = RHP_STATUS_INTEG_INVALID;
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_RX_INTEG_CHECK_ICV,"xxpp",pkt,ikesa,icv_len,icv_p,icv_len,icv_w);

  if( memcmp(icv_p,icv_w,icv_len) ){

#ifdef RHP_IKEV2_CRYPT_ERR_INFO
    if( rhp_gcfg_dbg_log_keys_info ){
      RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_INTEG_ERR_SK_D,"Pp",ikesa,ikesa->keys.v2.sk_d_len,ikesa->keys.v2.sk_d);
      RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_INTEG_ERR_SK_AI,"Pp",ikesa,ikesa->keys.v2.sk_a_len,ikesa->keys.v2.sk_ai);
      RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_INTEG_ERR_SK_AR,"Pp",ikesa,ikesa->keys.v2.sk_a_len,ikesa->keys.v2.sk_ar);
      RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_INTEG_ERR_SK_EI,"Pp",ikesa,ikesa->keys.v2.sk_e_len,ikesa->keys.v2.sk_ei);
      RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_INTEG_ERR_SK_ER,"Pp",ikesa,ikesa->keys.v2.sk_e_len,ikesa->keys.v2.sk_er);
      RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_INTEG_ERR_SK_PI,"Pp",ikesa,ikesa->keys.v2.sk_p_len,ikesa->keys.v2.sk_pi);
      RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_INTEG_ERR_SK_PR,"Pp",ikesa,ikesa->keys.v2.sk_p_len,ikesa->keys.v2.sk_pr);
    }
#endif // RHP_IKEV2_CRYPT_ERR_INFO

    err = RHP_STATUS_INTEG_INVALID;
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_RX_INTEG_CHECK_ICV_ERR,"xx",pkt,ikesa);
    goto error;
  }


  enc_payloadh.gen->len = htons(enc_payload_len - icv_len);
  ikeh->len = htonl(ikemesg_len - icv_len);

  if( pkt->l3.raw ){

  	if( pkt->type == RHP_PKT_IPV4_IKE ){

      pkt->l3.iph_v4->total_len = ntohs(pkt->l3.iph_v4->total_len) - icv_len;
      pkt->l3.iph_v4->total_len = htons(pkt->l3.iph_v4->total_len);

      if( pkt->l4.raw &&
      		pkt->l3.iph_v4->protocol == RHP_PROTO_IP_UDP ){

      	pkt->l4.udph->len = ntohs(pkt->l4.udph->len) - icv_len;
    	  pkt->l4.udph->len = htons(pkt->l4.udph->len);
      }

    }else if( pkt->type == RHP_PKT_IPV6_IKE ){

    	pkt->l3.iph_v6->payload_len = ntohs(pkt->l3.iph_v6->payload_len) - icv_len;
    	pkt->l3.iph_v6->payload_len = htons(pkt->l3.iph_v6->payload_len);

      if( pkt->l4.raw ){

    		u8 protos = RHP_PROTO_IP_UDP;
    		u8 protocol = 0;
    		u8* l4_hdr;

    		l4_hdr = rhp_proto_ip_v6_upper_layer(pkt->l3.iph_v6,pkt->end,1,&protos,&protocol);

    		if( l4_hdr == pkt->l4.raw &&
    				protocol == RHP_PROTO_IP_UDP ){

    			pkt->l4.udph->len = ntohs(pkt->l4.udph->len) - icv_len;
    			pkt->l4.udph->len = htons(pkt->l4.udph->len);
    		}
      }

    }else{
    	RHP_BUG("%d",pkt->type);
    	err = RHP_STATUS_INVALID_MSG;
    	goto error;
    }


  }else{
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_RX_INTEG_CHECK_NO_PKT_L3_PTR,"xxd",pkt,ikesa,icv_len);
  }


  if( _rhp_pkt_trim(pkt,icv_len) == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_RX_INTEG_CHECK_E_PLD_BAD_LEN_4,"xxd",pkt,ikesa,icv_len);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  _rhp_free(icv_w);

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_RX_INTEG_CHECK_RTRN,"xx",pkt,ikesa);
  return 0;

error:
  if( icv_w ){
    _rhp_free(icv_w);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_MESG_RX_INTEG_CHECK_ERR,"xxE",pkt,ikesa,err);
  return err;
}

static int _rhp_ikev2_mesg_decrypt(rhp_packet* pkt,rhp_ikesa* ikesa,u8* next_payload)
{
  int err = -EINVAL;
  rhp_proto_ike* ikeh;
  union {
  	rhp_proto_ike_payload* gen;
  	rhp_proto_ike_skf_payload* skf;
  	rhp_proto_ike_enc_payload* enc;
  } enc_payloadh;
  int enc_payload_hdr_len;
  int enc_payload_len;
  int iv_len,block_len,enc_len,ikemesg_len,block_aligned_len;
  u8 *iv_p,*enc_p,*enc_p_tmp = NULL;
  u8 pad_len;
  int trim_len;

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT,"xxx",pkt,ikesa,next_payload);

  ikeh = pkt->app.ikeh;
  if( ikeh == NULL ){
    RHP_BUG("");
    goto error;
  }

  if( ikesa == NULL ){
    RHP_BUG("");
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_IKESA,"xxLd",pkt,ikesa,"IKESA_STAT",ikesa->state);

  if( ikesa->state == RHP_IKESA_STAT_DEFAULT ||
      ikesa->state == RHP_IKESA_STAT_I_IKE_SA_INIT_SENT ||
      ikesa->state == RHP_IKESA_STAT_DEAD ){
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_IKESA_BAD_STATE,"xxd",pkt,ikesa,ikesa->state);
    goto error;
  }

  if( ikesa->prf == NULL || ikesa->encr == NULL ||
  		ikesa->integ_i == NULL || ikesa->integ_r == NULL ){
    RHP_BUG("");
    goto error;
  }

  if( ikeh->next_payload == RHP_PROTO_IKE_PAYLOAD_E ){

  	enc_payload_hdr_len = sizeof(rhp_proto_ike_enc_payload);

  }else if( ikeh->next_payload == RHP_PROTO_IKE_PAYLOAD_SKF ){

  	enc_payload_hdr_len = sizeof(rhp_proto_ike_skf_payload);

  }else{
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_NOT_ENCRYPTED,"xxb",pkt,ikesa,ikeh->next_payload);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  if( _rhp_pkt_try_pull(pkt,enc_payload_hdr_len) ){
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_ENC_DATA_LESS_THAN_ENC_PLD_HDR,"xx",pkt,ikesa);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  enc_payloadh.gen = (rhp_proto_ike_payload*)pkt->data;

  ikemesg_len = ntohl(ikeh->len);
  enc_payload_len = (int)ntohs(enc_payloadh.gen->len);

  if( ((u8*)enc_payloadh.gen) + enc_payload_len != pkt->tail ){
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_BAD_ENC_PLD_HDR_LEN_VALUE,"xxd",pkt,ikesa,enc_payload_len);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  iv_len = ikesa->encr->get_iv_len(ikesa->encr);
  block_len = ikesa->encr->get_block_len(ikesa->encr);

  enc_len = enc_payload_len - enc_payload_hdr_len - iv_len;
  block_aligned_len = ikesa->encr->get_block_aligned_len(ikesa->encr,enc_len);

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_CRYPTO_LENS,"xxdddddd",pkt,ikesa,ikemesg_len,enc_payload_len,iv_len,block_len,enc_len,block_aligned_len);

  if( enc_payload_len < enc_payload_hdr_len + iv_len + block_len ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_BAD_ENC_PLD_DATA_LEN_VALUE,"xxdddd",pkt,ikesa,enc_payload_len,enc_payload_hdr_len,iv_len,block_len);
    goto error;
  }

  if( block_aligned_len != enc_len ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_BAD_ENC_PLD_DATA_LESS_THAN_BLK_LEN,"xxdd",pkt,ikesa,block_aligned_len,enc_len);
    goto error;
  }

  iv_p = ((u8*)enc_payloadh.gen) + enc_payload_hdr_len;
  enc_p = iv_p + iv_len;

  enc_p_tmp = (u8*)_rhp_malloc(enc_len);
  if( enc_p_tmp == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  err = ikesa->encr->decrypt(ikesa->encr,enc_p,enc_len,enc_p_tmp,enc_len,iv_p);
  if( err ){

#ifdef RHP_IKEV2_CRYPT_ERR_INFO
    if( rhp_gcfg_dbg_log_keys_info ){
      RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_DECRYPT_ERR_SK_D,"Pp",ikesa,ikesa->keys.v2.sk_d_len,ikesa->keys.v2.sk_d);
      RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_DECRYPT_ERR_SK_AI,"Pp",ikesa,ikesa->keys.v2.sk_a_len,ikesa->keys.v2.sk_ai);
      RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_DECRYPT_ERR_SK_AR,"Pp",ikesa,ikesa->keys.v2.sk_a_len,ikesa->keys.v2.sk_ar);
      RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_DECRYPT_ERR_SK_EI,"Pp",ikesa,ikesa->keys.v2.sk_e_len,ikesa->keys.v2.sk_ei);
      RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_DECRYPT_ERR_SK_ER,"Pp",ikesa,ikesa->keys.v2.sk_e_len,ikesa->keys.v2.sk_er);
      RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_DECRYPT_ERR_SK_PI,"Pp",ikesa,ikesa->keys.v2.sk_p_len,ikesa->keys.v2.sk_pi);
      RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_DECRYPT_ERR_SK_PR,"Pp",ikesa,ikesa->keys.v2.sk_p_len,ikesa->keys.v2.sk_pr);
    }
#endif // RHP_IKEV2_CRYPT_ERR_INFO

    RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_DECRYPTION_FAILED,"xxE",pkt,ikesa,err);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  pad_len = *(enc_p_tmp + enc_len - (int)sizeof(u8));
  pad_len += (int)sizeof(u8);

  if( enc_len < pad_len ){

    RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_BAD_ENC_PLD_DATA_LESS_THAN_PAD_LEN,"xxdd",pkt,ikesa,enc_len,pad_len);
    err = RHP_STATUS_INVALID_MSG;
    goto error;

  }else if( enc_len == pad_len ){

    if( ikeh->next_payload == RHP_PROTO_IKE_PAYLOAD_E &&
    		enc_payloadh.gen->next_payload != RHP_PROTO_IKE_NO_MORE_PAYLOADS ){
      RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_BAD_ENC_PLD_DATA_ZERO_LEN,"xxLb",pkt,ikesa,"PROTO_IKE_PAYLOAD",enc_payloadh.gen->next_payload);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }

  }else{

    if( enc_len < (int)sizeof(rhp_proto_ike_payload) + pad_len ){
      RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_BAD_PAYLOAD_7,"xxddd",pkt,ikesa,enc_len,sizeof(rhp_proto_ike_payload),pad_len);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
    }
  }

  _RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
  if( _RHP_TRC_COND(_rhp_trc_user_id(),0) ){

    rhp_crypto_integ* integ;
    int icv_len;

    if( RHP_PROTO_IKE_HDR_INITIATOR(ikeh->flag) ){
      integ = ikesa->integ_i;
    }else{
      integ = ikesa->integ_r;
    }

    if( integ ){

   	  icv_len = integ->get_output_len(integ);
      memcpy(enc_p,enc_p_tmp,enc_len);
      enc_payloadh.gen->len = ntohs(enc_payloadh.gen->len) + icv_len;
      enc_payloadh.gen->len = htons(enc_payloadh.gen->len);

      if( pkt->type == RHP_PKT_IPV4_IKE ){
      	RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_DECRYPTED_PKT,"xa",pkt,(pkt->tail - pkt->l2.raw) + icv_len,RHP_TRC_FMT_A_MAC_IPV4_IKEV2_PLAIN,iv_len,icv_len,pkt->l2.raw);
      }else if( pkt->type == RHP_PKT_IPV6_IKE ){
      	RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_DECRYPTED_PKT_V6,"xa",pkt,(pkt->tail - pkt->l2.raw) + icv_len,RHP_TRC_FMT_A_MAC_IPV6_IKEV2_PLAIN,iv_len,icv_len,pkt->l2.raw);
      }

      enc_payloadh.gen->len = ntohs(enc_payloadh.gen->len) - icv_len;
      enc_payloadh.gen->len = htons(enc_payloadh.gen->len);

    }else{
      RHP_BUG("");
    }
  }

  *next_payload = enc_payloadh.gen->next_payload;
  memcpy(enc_payloadh.gen,enc_p_tmp,enc_len - pad_len);

  trim_len = enc_payload_hdr_len + iv_len + pad_len;

  if( pkt->l3.raw ){

		if( pkt->type == RHP_PKT_IPV4_IKE ){

			pkt->l3.iph_v4->total_len = ntohs(pkt->l3.iph_v4->total_len) - trim_len;
			pkt->l3.iph_v4->total_len = htons(pkt->l3.iph_v4->total_len);

			if( pkt->l4.raw &&
					pkt->l3.iph_v4->protocol == RHP_PROTO_IP_UDP ){

				pkt->l4.udph->len = ntohs(pkt->l4.udph->len) - trim_len;
				pkt->l4.udph->len = htons(pkt->l4.udph->len);
			}

		}else if( pkt->type == RHP_PKT_IPV6_IKE ){

			pkt->l3.iph_v6->payload_len = ntohs(pkt->l3.iph_v6->payload_len) - trim_len;
			pkt->l3.iph_v6->payload_len = htons(pkt->l3.iph_v6->payload_len);

      if( pkt->l4.raw ){

    		u8 protos = RHP_PROTO_IP_UDP;
    		u8 protocol = 0;
    		u8* l4_hdr;

    		l4_hdr = rhp_proto_ip_v6_upper_layer(pkt->l3.iph_v6,pkt->end,1,&protos,&protocol);

    		if( l4_hdr == pkt->l4.raw &&
    				protocol == RHP_PROTO_IP_UDP ){

    			pkt->l4.udph->len = ntohs(pkt->l4.udph->len) - trim_len;
    			pkt->l4.udph->len = htons(pkt->l4.udph->len);
    		}
      }

		}else{
			RHP_BUG("");
			err = RHP_STATUS_INVALID_MSG;
			goto error;
		}

  }

  ikeh->len = htonl(ikemesg_len - trim_len);
  ikeh->next_payload = *next_payload;

  if( _rhp_pkt_trim(pkt,trim_len) == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_BAD_PAYLOAD_8,"xx",pkt,ikesa);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  _rhp_free(enc_p_tmp);

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_RTRN,"xx",pkt,ikesa);
  return 0;

error:
  if( enc_p_tmp ){
    _rhp_free(enc_p_tmp);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_ERR,"xxE",pkt,ikesa,err);
  return err;
}


static int _rhp_ikev2_mesg_decrypt_v1(rhp_packet* pkt,rhp_ikesa* ikesa,
		u8* next_payload,int* rx_last_blk_len_r,u8** rx_last_blk_r)
{
  int err = -EINVAL;
  rhp_proto_ike* ikeh;
  rhp_proto_ike_payload* pldh;
  int block_len,enc_len,ikemesg_len,block_aligned_len,enc_no_pad_len,iv_len = 0;
  u8 *enc_p,*enc_p_tmp = NULL, *endp, *iv = NULL;
  u8 last_next_hdr = (u8)-1;
  int pad_len, rx_last_blk_len = 0;
  u8 exchange_type;
	u8 *rx_last_blk = NULL, *iv_new = NULL;
	rhp_ikev1_p2_session* p2_sess = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_V1,"xxxxxx",pkt,ikesa,next_payload,rx_last_blk_len_r,rx_last_blk_r,ikesa->v1.p2_sessions);

  ikeh = pkt->app.ikeh;
  if( ikeh == NULL ){
    RHP_BUG("");
    goto error;
  }

  if( ikesa == NULL ){
    RHP_BUG("");
    goto error;
  }

  exchange_type = ikeh->exchange_type;

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_V1_IKESA,"xxLdb",pkt,ikesa,"IKESA_STAT",ikesa->state,exchange_type);


  if( ikesa->state == RHP_IKESA_STAT_DEFAULT ||
      ikesa->state == RHP_IKESA_STAT_V1_MAIN_1ST_SENT_I ||
      ikesa->state == RHP_IKESA_STAT_V1_MAIN_3RD_SENT_I ||
      ikesa->state == RHP_IKESA_STAT_V1_AGG_1ST_SENT_I ||
      ikesa->state == RHP_IKESA_STAT_DEAD ){
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_V1_IKESA_BAD_STATE,"xxd",pkt,ikesa,ikesa->state);
    goto error;
  }

  if( ikesa->encr == NULL ){
    RHP_BUG("");
    goto error;
  }


  ikemesg_len = ntohl(ikeh->len);
  enc_len = ikemesg_len - (int)sizeof(rhp_proto_ike);

  if( ((u8*)(ikeh + 1)) + enc_len != pkt->tail ){
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_V1_BAD_ENC_PLD_HDR_LEN_VALUE,"xxd",pkt,ikesa,enc_len);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  block_len = ikesa->encr->get_block_len(ikesa->encr);
  block_aligned_len = ikesa->encr->get_block_aligned_len(ikesa->encr,enc_len);

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_V1_CRYPTO_LENS,"xxdddd",pkt,ikesa,ikemesg_len,block_len,enc_len,block_aligned_len);

  if( enc_len < block_len ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_V1_BAD_ENC_PLD_DATA_LEN_VALUE,"xxddd",pkt,ikesa,enc_len,block_len,(int)sizeof(rhp_proto_ike_payload));
    goto error;
  }

  if( block_aligned_len != enc_len ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_V1_BAD_ENC_PLD_DATA_LESS_THAN_BLK_LEN,"xxdd",pkt,ikesa,block_aligned_len,enc_len);
    goto error;
  }

  enc_p = (u8*)(ikeh + 1);

  enc_p_tmp = (u8*)_rhp_malloc(enc_len);
  if( enc_p_tmp == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }


	if( exchange_type == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ||
			exchange_type == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){

		iv = ikesa->keys.v1.p1_iv_dec;
		iv_len = ikesa->keys.v1.iv_len;

	}else if( exchange_type == RHP_PROTO_IKEV1_EXCHG_QUICK ||
						exchange_type == RHP_PROTO_IKEV1_EXCHG_INFORMATIONAL ||
						exchange_type == RHP_PROTO_IKEV1_EXCHG_TRANSACTION ){

		p2_sess = rhp_ikev1_p2_session_get(ikesa,ntohl(ikeh->message_id),exchange_type);
		if( p2_sess ){

			iv = p2_sess->dec_iv;
			iv_len = p2_sess->iv_len;

		}else{

			iv_new = rhp_ikev1_mesg_gen_iv(ikesa,ikeh->message_id,&iv_len);
			if( iv_new == NULL ){
				RHP_BUG("");
				err = -EINVAL;
				goto error;
			}

			iv = iv_new;
		}

	}else{
		err = -EINVAL;
		RHP_BUG("%d",exchange_type);
		goto error;
	}

	if( iv == NULL ||
			iv_len < ikesa->encr->get_iv_len(ikesa->encr) ){
		err = -EINVAL;
		RHP_BUG("0x%lx, %d",iv,iv_len);
		goto error;
	}


  err = ikesa->encr->decrypt(ikesa->encr,enc_p,enc_len,enc_p_tmp,enc_len,iv);
  if( err ){

#ifdef RHP_IKEV2_CRYPT_ERR_INFO
    if( rhp_gcfg_dbg_log_keys_info ){
      RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_DECRYPT_ERR_SK_EI,"Pp",ikesa,ikesa->keys.v2.sk_e_len,ikesa->keys.v2.sk_ei);
      RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_DBG_IKESA_DECRYPT_ERR_SK_ER,"Pp",ikesa,ikesa->keys.v2.sk_e_len,ikesa->keys.v2.sk_er);
    }
#endif // RHP_IKEV2_CRYPT_ERR_INFO

    RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_V1_DECRYPTION_FAILED,"xxE",pkt,ikesa,err);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


  enc_no_pad_len = 0;
  pldh = (rhp_proto_ike_payload*)enc_p_tmp;
  endp = enc_p_tmp + enc_len;
  while( (u8*)pldh < endp &&
  		   last_next_hdr != RHP_PROTO_IKE_NO_MORE_PAYLOADS ){

  	int pld_len;

  	if( (u8*)(pldh + 1) > endp ){
      RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_V1_INVALID_PAYLOAD_LEN,"xxxx",pkt,ikesa,(u8*)(pldh + 1),endp);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
  	}

  	pld_len = ntohs(pldh->len);
  	if( pld_len < 1 || ((u8*)pldh) + pld_len > endp ){
      RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_V1_INVALID_PAYLOAD_LEN_2,"xxdxx",pkt,ikesa,pld_len,((u8*)pldh),endp);
      err = RHP_STATUS_INVALID_MSG;
      goto error;
  	}

  	last_next_hdr = pldh->next_payload;
  	enc_no_pad_len += pld_len;
  	pldh = (rhp_proto_ike_payload*)(((u8*)pldh) + pld_len);
  }


  if( last_next_hdr != RHP_PROTO_IKE_NO_MORE_PAYLOADS ){
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_V1_INVALID_LAST_NEXT_PAYLOAD,"xxxxb",pkt,ikesa,((u8*)pldh),endp,last_next_hdr);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  if( enc_len < enc_no_pad_len ){
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_V1_INVALID_PAYLOAD_LEN_3,"xxdd",pkt,ikesa,enc_len,enc_no_pad_len);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  pad_len = enc_len - enc_no_pad_len;

	{
  	u8* last_blk = (((u8*)(ikeh + 1)) + enc_len - ikesa->keys.v1.iv_len);

  	rx_last_blk_len = ikesa->keys.v1.iv_len;
  	rx_last_blk = (u8*)_rhp_malloc(rx_last_blk_len);
  	if( rx_last_blk == NULL ){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}

		memcpy(rx_last_blk,last_blk,rx_last_blk_len);
	}

  *next_payload = ikeh->next_payload;

  memcpy((u8*)(ikeh + 1),enc_p_tmp,enc_len - pad_len);


  if( pkt->l3.raw ){

		if( pkt->type == RHP_PKT_IPV4_IKE ){

			pkt->l3.iph_v4->total_len = ntohs(pkt->l3.iph_v4->total_len) - pad_len;
			pkt->l3.iph_v4->total_len = htons(pkt->l3.iph_v4->total_len);

			if( pkt->l4.raw &&
					pkt->l3.iph_v4->protocol == RHP_PROTO_IP_UDP ){

				pkt->l4.udph->len = ntohs(pkt->l4.udph->len) - pad_len;
				pkt->l4.udph->len = htons(pkt->l4.udph->len);
			}

		}else if( pkt->type == RHP_PKT_IPV6_IKE ){

			pkt->l3.iph_v6->payload_len = ntohs(pkt->l3.iph_v6->payload_len) - pad_len;
			pkt->l3.iph_v6->payload_len = htons(pkt->l3.iph_v6->payload_len);

      if( pkt->l4.raw ){

    		u8 protos = RHP_PROTO_IP_UDP;
    		u8 protocol = 0;
    		u8* l4_hdr;

    		l4_hdr = rhp_proto_ip_v6_upper_layer(pkt->l3.iph_v6,pkt->end,1,&protos,&protocol);

    		if( l4_hdr == pkt->l4.raw &&
    				protocol == RHP_PROTO_IP_UDP ){

    			pkt->l4.udph->len = ntohs(pkt->l4.udph->len) - pad_len;
    			pkt->l4.udph->len = htons(pkt->l4.udph->len);
    		}
      }

		}else{
			RHP_BUG("");
			err = RHP_STATUS_INVALID_MSG;
			goto error;
		}
  }

  ikeh->len = htonl(ikemesg_len - pad_len);
  ikeh->flag &= 0xFE; // E(ncryption Bit)
  ikeh->next_payload = *next_payload;

  if( _rhp_pkt_trim(pkt,pad_len) == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_V1_BAD_PAYLOAD_8,"xx",pkt,ikesa);
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  _rhp_free(enc_p_tmp);

  if( iv_new ){
  	_rhp_free(iv_new);
  }

  *rx_last_blk_r = rx_last_blk;
  *rx_last_blk_len_r = rx_last_blk_len;

  if( p2_sess && p2_sess->clear_aftr_proc ){

  	rhp_ikev1_p2_session_clear(ikesa,p2_sess->mesg_id,p2_sess->exchange_type,0);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_V1_RTRN,"xxp",pkt,ikesa,rx_last_blk_len,rx_last_blk);
  return 0;

error:
  if( enc_p_tmp ){
    _rhp_free(enc_p_tmp);
  }
  if( rx_last_blk ){
  	_rhp_free(rx_last_blk);
  }
  if( iv_new ){
  	_rhp_free(iv_new);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_MESG_DECRYPT_V1_ERR,"xxE",pkt,ikesa,err);
  return err;
}

// This always returns a status/error code (NOT zero!).
static int _rhp_ikev2_allowed_plain_payloads(rhp_packet* pkt,rhp_proto_ike* ikeh)
{
	int err = -EINVAL;
	u8* p = (u8*)(ikeh + 1);
	u8 next_pld = ikeh->next_payload;
	int invalid_ike_spi = 0;
	int qcd_token = 0;
#ifdef RHP_IKEV2_INTEG_ERR_DBG
	int integ_err = 0;
#endif // RHP_IKEV2_INTEG_ERR_DBG

	RHP_TRC_FREQ(0,RHPTRCID_IKEV2_ALLOWED_PLAIN_PAYLOADS,"xx",pkt,ikeh);

	while( p < pkt->tail ){

		rhp_proto_ike_payload* pld_h = (rhp_proto_ike_payload*)p;
		u16 pld_len;
		rhp_proto_ike_notify_payload* n_pld_h;
		u16 n_type;

		if( p + sizeof(rhp_proto_ike_payload) > pkt->tail ){
			err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;
			goto error;
		}

		pld_len = ntohs(pld_h->len);

		if( p + pld_len > pkt->tail ){
			err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;
			goto error;
		}

		if( next_pld == RHP_PROTO_IKE_PAYLOAD_N ){

			if( p + sizeof(rhp_proto_ike_notify_payload) > pkt->tail ){
				err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;
				goto error;
			}

			n_pld_h = (rhp_proto_ike_notify_payload*)pld_h;
			n_type = ntohs(n_pld_h->notify_mesg_type);

			if( n_type == RHP_PROTO_IKE_NOTIFY_ERR_INVALID_IKE_SPI ){

				if( pld_len != sizeof(rhp_proto_ike_notify_payload) ){
					err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;
					goto error;
				}

				invalid_ike_spi = 1;

			}else if( n_type == RHP_PROTO_IKE_NOTIFY_ST_QCD_TOKEN ){

				if( (pld_len < sizeof(rhp_proto_ike_notify_payload) + rhp_gcfg_ikev2_qcd_min_token_len) ||
						(pld_len > sizeof(rhp_proto_ike_notify_payload) + rhp_gcfg_ikev2_qcd_max_token_len) ){
					err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;
					goto error;
				}

				qcd_token = 1;

#ifdef RHP_IKEV2_INTEG_ERR_DBG
			}else if( n_type == RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_DBG_IKE_INTEG_ERR ){

				integ_err = 1;
#endif // RHP_IKEV2_INTEG_ERR_DBG
			}

			if( n_type >= RHP_PROTO_IKE_NOTIFY_ERR_MIN && n_type <= RHP_PROTO_IKE_NOTIFY_ERR_MAX ){

				if( pkt->type == RHP_PKT_IPV4_IKE ){
					RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV2_PLAIN_MESG_ERR_NOTIFY,"44WWGGLJL",(pkt->l3.raw ? pkt->l3.iph_v4->src_addr : 0),(pkt->l3.raw ? pkt->l3.iph_v4->dst_addr : 0),(pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt->l4.raw ? pkt->l4.udph->dst_port : 0),ikeh->init_spi,ikeh->resp_spi,"PROTO_IKE_EXCHG",(int)ikeh->exchange_type,ikeh->message_id,"PROTO_IKE_NOTIFY",(int)n_type);
				}else if( pkt->type == RHP_PKT_IPV6_IKE ){
					RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV2_PLAIN_MESG_ERR_NOTIFY_V6,"66WWGGLJL",(pkt->l3.raw ? pkt->l3.iph_v6->src_addr : NULL),(pkt->l3.raw ? pkt->l3.iph_v6->dst_addr : NULL),(pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt->l4.raw ? pkt->l4.udph->dst_port : 0),ikeh->init_spi,ikeh->resp_spi,"PROTO_IKE_EXCHG",(int)ikeh->exchange_type,ikeh->message_id,"PROTO_IKE_NOTIFY",(int)n_type);
				}

			}else if( n_type >= RHP_PROTO_IKE_NOTIFY_ERR_PRIV_START && n_type <= RHP_PROTO_IKE_NOTIFY_ERR_PRIV_END ){

				if( pkt->type == RHP_PKT_IPV4_IKE ){
					RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV2_PLAIN_MESG_PRIVATE_ERR_NOTIFY,"44WWGGLJL",(pkt->l3.raw ? pkt->l3.iph_v4->src_addr : 0),(pkt->l3.raw ? pkt->l3.iph_v4->dst_addr : 0),(pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt->l4.raw ? pkt->l4.udph->dst_port : 0),ikeh->init_spi,ikeh->resp_spi,"PROTO_IKE_EXCHG",(int)ikeh->exchange_type,ikeh->message_id,"PROTO_IKE_NOTIFY",(int)n_type);
				}else if( pkt->type == RHP_PKT_IPV6_IKE ){
					RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV2_PLAIN_MESG_PRIVATE_ERR_NOTIFY_V6,"66WWGGLJL",(pkt->l3.raw ? pkt->l3.iph_v6->src_addr : NULL),(pkt->l3.raw ? pkt->l3.iph_v6->dst_addr : NULL),(pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt->l4.raw ? pkt->l4.udph->dst_port : 0),ikeh->init_spi,ikeh->resp_spi,"PROTO_IKE_EXCHG",(int)ikeh->exchange_type,ikeh->message_id,"PROTO_IKE_NOTIFY",(int)n_type);
				}
			}
		}

		next_pld = pld_h->next_payload;
		p += pld_len;
	}

	if( ikeh->exchange_type != RHP_PROTO_IKE_EXCHG_IKE_SA_INIT &&
			ikeh->exchange_type != RHP_PROTO_IKE_EXCHG_SESS_RESUME &&
			ikeh->exchange_type != RHP_PROTO_IKE_EXCHG_IKE_AUTH &&
			invalid_ike_spi && qcd_token ){

		err = RHP_STATUS_IKEV2_MESG_QCD_INVALID_IKE_SPI_NTFY;

#ifdef RHP_IKEV2_INTEG_ERR_DBG
	}else if( integ_err ){

		err = RHP_STATUS_INVALID_IKEV2_MESG_INTEG_ERR;
#endif // RHP_IKEV2_INTEG_ERR_DBG

	}else{

		err = RHP_STATUS_INVALID_IKEV2_MESG_NOT_ENCRYPTED;
	}

error:
	RHP_TRC_FREQ(0,RHPTRCID_IKEV2_ALLOWED_PLAIN_PAYLOADS_RTRN,"xxE",pkt,ikeh,err);
	return err;
}

int rhp_ikev2_check_mesg(rhp_packet* pkt)
{
  rhp_proto_ike* ikeh = NULL;
  int err = 0, err2 = 0;
  u32 len;
  u32* non_esp_marker;
  u8 exchange_type = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG,"x",pkt);

  if( pkt->l3.raw == NULL || pkt->l4.raw == NULL || pkt->app.raw == NULL ){
    RHP_BUG("0x%x,0x%x,0x%x",pkt->l3.raw,pkt->l4.raw,pkt->app.raw);
    err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_PKT;
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_L4,"xWddd",pkt,pkt->l4.udph->dst_port,rhp_gcfg_ike_port_nat_t,pkt->cookie_checked,pkt->mobike_verified);

  if( pkt->cookie_checked || pkt->mobike_verified ){
    RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_ALREADY_CHECKED,"x",pkt);
  	return 0;
  }


  if( pkt->l4.udph->dst_port == htons(rhp_gcfg_ike_port_nat_t) ){

    non_esp_marker = (u32*)pkt->app.raw;

    if( ntohl(*non_esp_marker) != RHP_PROTO_NON_ESP_MARKER ){

      RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_INVALID_MESG_1,"xxK",pkt,non_esp_marker,*non_esp_marker);
      err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_NON_ESP_MARKER;
      goto error;

    }else{

      pkt->data = pkt->app.raw;

      if( _rhp_pkt_pull(pkt,RHP_PROTO_NON_ESP_MARKER_SZ) == NULL ){
        RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_INVALID_MESG_2,"x",pkt);
        err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;
        goto error;
      }

      pkt->app.raw = _rhp_pkt_pull(pkt,sizeof(rhp_proto_ike));

      if( pkt->app.raw == NULL ){
        RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_INVALID_MESG_3,"x",pkt);
        err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;
        goto error;
      }
    }

    ikeh = pkt->app.ikeh;

  }else{

    non_esp_marker = NULL;

    pkt->data = pkt->app.raw;

    pkt->app.raw = _rhp_pkt_pull(pkt,sizeof(rhp_proto_ike));
    if( pkt->app.raw == NULL ){
      RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_INVALID_MESG_4,"x",pkt);
      err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;
      goto error;
    }

    ikeh = pkt->app.ikeh;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_APP,"xbbLbUdGGLbU",pkt,ikeh->ver_major,ikeh->ver_minor,"PROTO_IKE_EXCHG",ikeh->exchange_type,ikeh->len,rhp_gcfg_max_ike_packet_size,ikeh->init_spi,ikeh->resp_spi,"PROTO_IKE_PAYLOAD",ikeh->next_payload,ikeh->message_id);


  exchange_type = ikeh->exchange_type;


  if( (exchange_type == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ||
  		 exchange_type == RHP_PROTO_IKE_EXCHG_SESS_RESUME) &&
  		!RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){

  	rhp_ikesa_open_req_per_sec_update();
  }


  if( !(ikeh->ver_major == RHP_PROTO_IKE_VER_MAJOR &&
        ikeh->ver_minor == RHP_PROTO_IKE_VER_MINOR) ){

  	RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_INVALID_VER,"xbb",pkt,ikeh->ver_major,ikeh->ver_minor);
    err = RHP_STATUS_NOT_SUPPORTED_VER;

		if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){
	  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_unsup_ver_packets);
		}else{
	  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_unsup_ver_packets);
		}

    goto error;
  }


  len = ntohl(ikeh->len);

  if( len < (sizeof(rhp_proto_ike) + sizeof(rhp_proto_ike_payload)) ){

  	RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_INVALID_MESG_5,"x",pkt);
    err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;

		if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){
	  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_invalid_len_packets);
		}else{
	  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_invalid_len_packets);
		}

    goto error;
  }


  if( len > (u32)rhp_gcfg_max_ike_packet_size ){

  	RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_TOO_LARGE,"xdd",pkt,len,rhp_gcfg_max_ike_packet_size);
    err = RHP_STATUS_MSG_TOO_LONG;

		if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){
	  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_invalid_len_packets);
		}else{
	  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_invalid_len_packets);
		}

    goto error;
  }


  if( exchange_type == RHP_PROTO_IKE_EXCHG_SESS_RESUME ){

  	if( (!rhp_gcfg_ikev2_sess_resume_init_enabled && !rhp_gcfg_ikev2_sess_resume_resp_enabled) ||
  			(!rhp_gcfg_ikev2_sess_resume_resp_enabled && !RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag)) ||
  			(!rhp_gcfg_ikev2_sess_resume_init_enabled && RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag)) ){

			RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_SESS_RESUME_NOT_ENABLED,"xb",pkt,ikeh->exchange_type);
			err = RHP_STATUS_INVALID_IKEV2_MESG_IKE_UNSUPPORTED_EXCHANGE_TYPE;

			if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){
				rhp_ikev2_g_statistics_inc(rx_ikev2_resp_invalid_exchg_type_packets);
			}else{
				rhp_ikev2_g_statistics_inc(rx_ikev2_req_invalid_exchg_type_packets);
			}

			goto error;
  	}
  }


  if( ((u32*)ikeh->init_spi)[0] == 0 && ((u32*)ikeh->init_spi)[1] == 0 ){

  	RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_BAD_I_SPI,"xG",pkt,ikeh->init_spi);
    err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_SPI_FIELD;

		if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){
	  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_invalid_spi_packets);
		}else{
	  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_invalid_spi_packets);
		}

    goto error;
  }


  if( ikeh->next_payload == RHP_PROTO_IKE_PAYLOAD_SKF ){

  	if( !rhp_gcfg_ikev2_enable_fragmentation ){

			RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_INVALID_MESG_FRAG_DISABLED,"x",pkt);
			err = RHP_STATUS_IKEV2_FRAG_RX_BAD_MESG;

			if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){
				rhp_ikev2_g_statistics_inc(rx_ikev2_resp_invalid_frag_packets);
			}else{
				rhp_ikev2_g_statistics_inc(rx_ikev2_req_invalid_frag_packets);
			}

			goto error;

  	}else{

			if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){
				rhp_ikev2_g_statistics_inc(rx_ikev2_resp_frag_packets);
			}else{
				rhp_ikev2_g_statistics_inc(rx_ikev2_req_frag_packets);
			}
  	}
  }


  if( ikeh->next_payload == RHP_PROTO_IKE_PAYLOAD_E ||
  		ikeh->next_payload == RHP_PROTO_IKE_PAYLOAD_SKF ){

  	int e_min_hdr_len;
  	rhp_proto_ike_payload* pld_gen;

    if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ||
    		exchange_type == RHP_PROTO_IKE_EXCHG_SESS_RESUME ){

			RHP_TRC(0,RHPTRCID_IKEV2_CHECK_IKE_SA_INIT_RX_ENC_MESG,"xb",pkt,ikeh->next_payload);
			err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_NEXT_PAYLOAD_FIELD;

			if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){
				rhp_ikev2_g_statistics_inc(rx_ikev2_resp_parse_err_packets);
			}else{
				rhp_ikev2_g_statistics_inc(rx_ikev2_req_parse_err_packets);
			}

			goto error;
    }

  	if( ikeh->next_payload == RHP_PROTO_IKE_PAYLOAD_E ){
  		e_min_hdr_len = sizeof(rhp_proto_ike_enc_payload);
  	}else if( ikeh->next_payload == RHP_PROTO_IKE_PAYLOAD_SKF ){
  		e_min_hdr_len = sizeof(rhp_proto_ike_skf_payload);
  	}else{
  		RHP_BUG("");
  		goto error;
  	}

		if( _rhp_pkt_try_pull(pkt,e_min_hdr_len) ){

			RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_INVALID_MESG_BAD_ENC_PLD_LEN,"x",pkt);
			err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_ENC_PAYLOAD_LENGTH;

			if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){
				rhp_ikev2_g_statistics_inc(rx_ikev2_resp_invalid_len_packets);
			}else{
				rhp_ikev2_g_statistics_inc(rx_ikev2_req_invalid_len_packets);
			}

			goto error;
		}


  	pld_gen = (rhp_proto_ike_payload*)(pkt->data);

		if( pkt->data + ntohs(pld_gen->len) != pkt->tail ){

			RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_INVALID_MESG_BAD_ENC_PLD_LEN_2,"xWd",pkt,pld_gen->len,(pkt->tail - pkt->data));
			err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_ENC_PAYLOAD_LENGTH;

			if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){
				rhp_ikev2_g_statistics_inc(rx_ikev2_resp_invalid_len_packets);
			}else{
				rhp_ikev2_g_statistics_inc(rx_ikev2_req_invalid_len_packets);
			}

			goto error;
		}


		if( ikeh->next_payload == RHP_PROTO_IKE_PAYLOAD_SKF ){

			rhp_proto_ike_skf_payload* skf = (rhp_proto_ike_skf_payload*)pld_gen;
			u16 frag_num = ntohs(skf->frag_num) , total_frags = ntohs(skf->total_frags);

			if( frag_num > total_frags ||
					total_frags == 0 || frag_num == 0 ||
					(frag_num > 1 && skf->next_payload != 0) ){

				RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_INVALID_MESG_BAD_SKF_PLD_HDR,"xWwwb",pkt,pld_gen->len,frag_num,total_frags,skf->next_payload);

				err = RHP_STATUS_IKEV2_FRAG_RX_BAD_MESG;

				if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){
					rhp_ikev2_g_statistics_inc(rx_ikev2_resp_invalid_frag_packets);
				}else{
					rhp_ikev2_g_statistics_inc(rx_ikev2_req_invalid_frag_packets);
				}

				goto error;
			}
		}

  }else{

		if( ikeh->next_payload == RHP_PROTO_IKE_NO_MORE_PAYLOADS ){

			RHP_TRC(0,RHPTRCID_IKEV2_CHECK_NO_PAYLOADS,"xb",pkt,ikeh->next_payload);
			err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_NEXT_PAYLOAD_FIELD;

			if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){
				rhp_ikev2_g_statistics_inc(rx_ikev2_resp_parse_err_packets);
			}else{
				rhp_ikev2_g_statistics_inc(rx_ikev2_req_parse_err_packets);
			}

			goto error;
		}
  }


  if( exchange_type != RHP_PROTO_IKE_EXCHG_IKE_SA_INIT &&
  		exchange_type != RHP_PROTO_IKE_EXCHG_SESS_RESUME ){

    // After IKE_SA_INIT exchg, should we handle a IKE message
  	// with 'NOT' encrypted payload(s)?

  	if( ikeh->next_payload != RHP_PROTO_IKE_PAYLOAD_E &&
    		ikeh->next_payload != RHP_PROTO_IKE_PAYLOAD_SKF ){

    	RHP_TRC(0,RHPTRCID_IKEV2_CHECK_NOT_ENCRYPTED,"xb",pkt,ikeh->next_payload);

  		if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){

  			rhp_ikev2_g_statistics_inc(rx_ikev2_resp_not_encrypted_packets);

  			//
  			// [CAUTION]
    		// This always returns a status/error code (NOT zero!).
  			//
    		err2 = _rhp_ikev2_allowed_plain_payloads(pkt,ikeh);
    		if( err2 != RHP_STATUS_IKEV2_MESG_QCD_INVALID_IKE_SPI_NTFY ){
    			err = err2;
    			goto error;
    		}

  		}else{

				RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_INVALID_MESG_REQ_NOT_ENCRYPTED,"x",pkt);

				rhp_ikev2_g_statistics_inc(rx_ikev2_req_not_encrypted_packets);

				err = RHP_STATUS_INVALID_IKEV2_MESG_NOT_ENCRYPTED;

				goto error;
    	}
    }
  }


  switch( exchange_type ){

    case RHP_PROTO_IKE_EXCHG_IKE_SA_INIT:
    case RHP_PROTO_IKE_EXCHG_SESS_RESUME:

      if( ikeh->message_id != 0 ){

      	RHP_TRC(0,RHPTRCID_IKEV2_CHECK_BAD_MESGID,"xJ",pkt,ikeh->message_id);
        err = RHP_STATUS_INVALID_IKEV2_MESG_BAD_MESG_ID;

    		if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){
    	  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_invalid_seq_packets);
    		}else{
    	  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_invalid_seq_packets);
    		}

    		goto error;
      }

      if( !RHP_PROTO_IKE_HDR_INITIATOR(ikeh->flag) ){

        if( !RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){

        	RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_NOT_REQUEST,"xb",pkt,ikeh->flag);
          err = RHP_STATUS_INVALID_IKEV2_MESG_IKE_SA_INIT_NOT_INITIATOR_REQ;

    	  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_bad_ikesa_state_packets);

          goto error;
         }

      }else{ // Responder Flag

        if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){

        	RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_NOT_RESPONSE,"xb",pkt,ikeh->flag);
          err = RHP_STATUS_INVALID_IKEV2_MESG_IKE_SA_INIT_NOT_RESPONDER_RESP;

    	  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_bad_ikesa_state_packets);

    	  	goto error;
        }
      }

      break;

    case RHP_PROTO_IKE_EXCHG_IKE_AUTH:

      if( ((u32*)ikeh->resp_spi)[0] == 0 && ((u32*)ikeh->resp_spi)[1] == 0 ){

      	RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_BAD_R_SPI,"xG",pkt,ikeh->resp_spi);
        err = RHP_STATUS_INVALID_IKEV2_MESG_IKE_AUTH_BAD_R_SPI;

    		if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){
    	  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_invalid_spi_packets);
    		}else{
    	  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_invalid_spi_packets);
    		}

    		goto error;
      }

      if( ikeh->message_id == 0 ){ // >= 1

      	RHP_TRC(0,RHPTRCID_IKEV2_CHECK_BAD_MESGID_2,"xJ",pkt,ikeh->message_id);
        err = RHP_STATUS_INVALID_IKEV2_MESG_IKE_AUTH_BAD_MESG_ID;

    		if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){
    	  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_invalid_seq_packets);
    		}else{
    	  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_invalid_seq_packets);
    		}

    		goto error;
      }

      if( RHP_PROTO_IKE_HDR_INITIATOR(ikeh->flag) ){

        if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){

        	RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_NOT_REQUEST_2,"xb",pkt,ikeh->flag);
          err = RHP_STATUS_INVALID_IKEV2_MESG_IKE_AUTH_NOT_INITIATOR_REQ;

    	  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_bad_ikesa_state_packets);

          goto error;
        }

      }else{ // Responder Flag

        if( !RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){

        	RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_NOT_RESPONSE_2,"xb",pkt,ikeh->flag);
          err = RHP_STATUS_INVALID_IKEV2_MESG_IKE_AUTH_NOT_RESPONDER_RESP;

      		if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){
      	  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_bad_ikesa_state_packets);
      		}else{
      	  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_bad_ikesa_state_packets);
      		}

      		goto error;
        }
      }

      break;

    case RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA:

      if( ((u32*)ikeh->resp_spi)[0] == 0 && ((u32*)ikeh->resp_spi)[1] == 0 ){

      	RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_BAD_R_SPI_2,"xG",pkt,ikeh->resp_spi);
        err = RHP_STATUS_INVALID_IKEV2_MESG_IKE_CREATE_CHILD_SA_BAD_MESG_ID;

    		if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){
    	  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_invalid_spi_packets);
    		}else{
    	  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_invalid_spi_packets);
    		}

    		goto error;
      }

      break;

    case RHP_PROTO_IKE_EXCHG_INFORMATIONAL:

      if( ((u32*)ikeh->resp_spi)[0] == 0 && ((u32*)ikeh->resp_spi)[1] == 0 ){

      	RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_BAD_R_SPI_3,"xG",pkt,ikeh->resp_spi);
        err = RHP_STATUS_INVALID_IKEV2_MESG_IKE_INFORMATIONAL_BAD_MESG_ID;

    		if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){
    	  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_invalid_spi_packets);
    		}else{
    	  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_invalid_spi_packets);
    		}

    		goto error;
       }

      break;

    default:

    	RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_UNKNOW_EXCHG_TYPE,"xb",pkt,ikeh->exchange_type);
      err = RHP_STATUS_INVALID_IKEV2_MESG_IKE_UNSUPPORTED_EXCHANGE_TYPE;

  		if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){
  	  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_invalid_exchg_type_packets);
  		}else{
  	  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_invalid_exchg_type_packets);
  		}

      goto error;
  }

  if( err2 ){
  	err = err2;
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_OK,"xLb",pkt,"PROTO_IKE_EXCHG",ikeh->exchange_type);
  return 0;

error:
	if( err != RHP_STATUS_IKEV2_MESG_QCD_INVALID_IKE_SPI_NTFY ){

		if( pkt->type == RHP_PKT_IPV4_IKE ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_INVALID_IKEV2_MESG,"MMW44bWWE",(pkt->l2.raw ? pkt->l2.eth->dst_addr : NULL),(pkt->l2.raw ? pkt->l2.eth->src_addr : NULL),(pkt->l2.raw ? pkt->l2.eth->protocol : 0),(pkt->l3.raw ? pkt->l3.iph_v4->dst_addr : 0),(pkt->l3.raw ? pkt->l3.iph_v4->src_addr : 0),(pkt->l3.raw ? pkt->l3.iph_v4->protocol : 0),(pkt->l4.raw ? pkt->l4.udph->dst_port : 0),(pkt->l4.raw ? pkt->l4.udph->src_port : 0),	err);
		}else if( pkt->type == RHP_PKT_IPV6_IKE ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_INVALID_IKEV2_MESG_V6,"MMW66bWWE",(pkt->l2.raw ? pkt->l2.eth->dst_addr : NULL),(pkt->l2.raw ? pkt->l2.eth->src_addr : NULL),(pkt->l2.raw ? pkt->l2.eth->protocol : 0),(pkt->l3.raw ? pkt->l3.iph_v6->dst_addr : NULL),(pkt->l3.raw ? pkt->l3.iph_v6->src_addr : NULL),(pkt->l3.raw ? pkt->l3.iph_v6->next_header : 0),(pkt->l4.raw ? pkt->l4.udph->dst_port : 0),(pkt->l4.raw ? pkt->l4.udph->src_port : 0),	err);
		}

		if( ikeh ){
			if( RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) ){
				rhp_ikev2_g_statistics_inc(rx_ikev2_resp_verify_err_packets);
			}else{
				rhp_ikev2_g_statistics_inc(rx_ikev2_req_verify_err_packets);
			}
		}else{
			rhp_ikev2_g_statistics_inc(rx_ikev2_invalid_packets);
		}
	}

	RHP_TRC(0,RHPTRCID_IKEV2_CHECK_MESG_ERR,"xLbE",pkt,"PROTO_IKE_EXCHG",exchange_type,err);
  return err;
}


static void _rhp_ikev2_mesg_dump_payloads(rhp_ikev2_mesg* ikemesg)
{
  rhp_ikev2_payload* payload = ikemesg->payload_list_head;

  while( payload ){
    if( payload->ext_dump ){
      payload->ext_dump(payload);
    }else{
      RHP_TRCSTR(0,"payload->ext_dump not defined. [payload_id:%d]",payload->payload_id);
    }
    payload = payload->next;
  }

  if( ikemesg->merged_mesg ){
  	_rhp_ikev2_mesg_dump_payloads(ikemesg->merged_mesg);
  }

  return;
}

static int _rhp_ikev2_mesg_rx_get_init_addr(rhp_ikev2_mesg* ikemesg,rhp_ip_addr* addr)
{
	if( ikemesg->rx_pkt == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE ){

		addr->addr_family = AF_INET;

		if( ikemesg->is_initiator(ikemesg) ){
			addr->addr.v4 = ikemesg->rx_pkt->l3.iph_v4->src_addr;
			addr->port = ikemesg->rx_pkt->l4.udph->src_port;
		}else{
			addr->addr.v4 = ikemesg->rx_pkt->l3.iph_v4->dst_addr;
			addr->port = ikemesg->rx_pkt->l4.udph->dst_port;
		}

	}else if( ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE ){

		addr->addr_family = AF_INET6;

		if( ikemesg->is_initiator(ikemesg) ){
			memcpy(addr->addr.v6,ikemesg->rx_pkt->l3.iph_v6->src_addr,16);
			addr->port = ikemesg->rx_pkt->l4.udph->src_port;
		}else{
			memcpy(addr->addr.v6,ikemesg->rx_pkt->l3.iph_v6->dst_addr,16);
			addr->port = ikemesg->rx_pkt->l4.udph->dst_port;
		}

	}else{
		RHP_BUG("");
		return -EINVAL;
	}

	return 0;
}

static int _rhp_ikev2_mesg_rx_get_resp_addr(rhp_ikev2_mesg* ikemesg,rhp_ip_addr* addr)
{
	if( ikemesg->rx_pkt == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE ){

		addr->addr_family = AF_INET;

		if( ikemesg->is_initiator(ikemesg) ){
			addr->addr.v4 = ikemesg->rx_pkt->l3.iph_v4->dst_addr;
			addr->port = ikemesg->rx_pkt->l4.udph->dst_port;
		}else{
			addr->addr.v4 = ikemesg->rx_pkt->l3.iph_v4->src_addr;
			addr->port = ikemesg->rx_pkt->l4.udph->src_port;
		}

	}else if( ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE ){

		addr->addr_family = AF_INET6;

		if( ikemesg->is_initiator(ikemesg) ){
			memcpy(addr->addr.v6,ikemesg->rx_pkt->l3.iph_v6->dst_addr,16);
			addr->port = ikemesg->rx_pkt->l4.udph->dst_port;
		}else{
			memcpy(addr->addr.v6,ikemesg->rx_pkt->l3.iph_v6->src_addr,16);
			addr->port = ikemesg->rx_pkt->l4.udph->src_port;
		}

	}else{
		RHP_BUG("");
		return -EINVAL;
	}

	return 0;
}

static int _rhp_ikev2_mesg_rx_get_src_addr(rhp_ikev2_mesg* ikemesg,rhp_ip_addr* addr)
{
	if( ikemesg->rx_pkt == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE ){

		addr->addr_family = AF_INET;
		addr->addr.v4 = ikemesg->rx_pkt->l3.iph_v4->src_addr;

	}else if( ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE ){

		addr->addr_family = AF_INET6;
		memcpy(addr->addr.v6,ikemesg->rx_pkt->l3.iph_v6->src_addr,16);

	}else{
		RHP_BUG("");
		return -EINVAL;
	}

	addr->port = ikemesg->rx_pkt->l4.udph->src_port;

	return 0;
}

static int _rhp_ikev2_mesg_rx_get_dst_addr(rhp_ikev2_mesg* ikemesg,rhp_ip_addr* addr)
{
	if( ikemesg->rx_pkt == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE ){

		addr->addr_family = AF_INET;
		addr->addr.v4 = ikemesg->rx_pkt->l3.iph_v4->dst_addr;

	}else if( ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE ){

		addr->addr_family = AF_INET6;
		memcpy(addr->addr.v6,ikemesg->rx_pkt->l3.iph_v6->dst_addr,16);

	}else{
		RHP_BUG("");
		return -EINVAL;
	}

	addr->port = ikemesg->rx_pkt->l4.udph->dst_port;

	return 0;
}

static rhp_ikev2_mesg* _rhp_ikev2_alloc_mesg(int for_tx)
{
  rhp_ikev2_mesg* ikemesg = _rhp_malloc(sizeof(rhp_ikev2_mesg));

  if( ikemesg == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(ikemesg,0,sizeof(rhp_ikev2_mesg));

  if( for_tx ){

    ikemesg->tx_ikeh = (rhp_proto_ike*)_rhp_malloc(sizeof(rhp_proto_ike));
    if( ikemesg->tx_ikeh == NULL ){
      _rhp_free(ikemesg);
      RHP_BUG("");
      return NULL;
    }

    memset(ikemesg->tx_ikeh,0,sizeof(rhp_proto_ike));
  }

  ikemesg->tag[0] = '#';
  ikemesg->tag[1] = 'I';
  ikemesg->tag[2] = 'K';
  ikemesg->tag[3] = 'M';

  ikemesg->get_init_spi = _rhp_ikev2_mesg_get_init_spi;
  ikemesg->get_resp_spi = _rhp_ikev2_mesg_get_resp_spi;
  ikemesg->set_init_spi = _rhp_ikev2_mesg_set_init_spi;
  ikemesg->set_resp_spi = _rhp_ikev2_mesg_set_resp_spi;
  ikemesg->get_next_payload = _rhp_ikev2_mesg_get_next_payload;
  ikemesg->get_major_ver = _rhp_ikev2_mesg_get_major_ver;
  ikemesg->get_minor_ver = _rhp_ikev2_mesg_get_minor_ver;
  ikemesg->get_exchange_type = _rhp_ikev2_mesg_get_exchange_type;
  ikemesg->set_exchange_type = _rhp_ikev2_mesg_set_exchange_type;
  ikemesg->is_initiator = _rhp_ikev2_mesg_is_initiator;
  ikemesg->is_responder = _rhp_ikev2_mesg_is_responder;
  ikemesg->is_request = _rhp_ikev2_mesg_is_request;
  ikemesg->is_response = _rhp_ikev2_mesg_is_response;
  ikemesg->get_mesg_id = _rhp_ikev2_mesg_get_mesg_id;
  ikemesg->set_mesg_id = _rhp_ikev2_mesg_set_mesg_id;
  ikemesg->get_len = _rhp_ikev2_mesg_get_len;
  ikemesg->put_payload = _rhp_ikev2_mesg_put_payload;
  ikemesg->put_payload_head = _rhp_ikev2_mesg_put_payload_head;
  ikemesg->search_payloads = _rhp_ikev2_mesg_search_payloads;
  ikemesg->get_payload = _rhp_ikev2_mesg_get_payload;
  ikemesg->serialize = _rhp_ikev2_mesg_serialize;
  ikemesg->serialize_v1 = _rhp_ikev2_mesg_serialize_v1;
  ikemesg->decrypt = _rhp_ikev2_mesg_decrypt;
  ikemesg->decrypt_v1 = _rhp_ikev2_mesg_decrypt_v1;
  ikemesg->dump_payloads = _rhp_ikev2_mesg_dump_payloads;
  ikemesg->rx_get_init_addr = _rhp_ikev2_mesg_rx_get_init_addr;
  ikemesg->rx_get_resp_addr = _rhp_ikev2_mesg_rx_get_resp_addr;
  ikemesg->rx_get_src_addr = _rhp_ikev2_mesg_rx_get_src_addr;
  ikemesg->rx_get_dst_addr = _rhp_ikev2_mesg_rx_get_dst_addr;

  ikemesg->v1_commit_bit_enabled = _rhp_ikev2_mesg_v1_commit_bit_enabled;

  ikemesg->rx_cp_internal_addrs[0].addr_family = AF_INET;
  ikemesg->rx_cp_internal_addrs[1].addr_family = AF_INET6;

  ikemesg->fixed_tx_if_index = -1;

  _rhp_atomic_init(&(ikemesg->refcnt));
  _rhp_atomic_set(&(ikemesg->refcnt),1);

  if( for_tx ){
  	rhp_ikev2_g_statistics_inc(dc.ikev2_alloc_tx_messages);
  }else{
  	rhp_ikev2_g_statistics_inc(dc.ikev2_alloc_rx_messages);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_ALLOC_MESG,"x",ikemesg);
  return ikemesg;
}

static void _rhp_ikev2_free_mesg(rhp_ikev2_mesg* ikemesg)
{
  rhp_ikev2_payload* ikepayload = ikemesg->payload_list_head;
  rhp_ikev2_payload *tmp;

  RHP_TRC(0,RHPTRCID_IKEV2_DESTROY_MESG,"x",ikemesg);

  if( ikemesg->merged_mesg ){
  	rhp_ikev2_unhold_mesg(ikemesg->merged_mesg);
  }

  while( ikepayload ){
    tmp = ikepayload->next;
    rhp_ikev2_destroy_payload(ikepayload);
    ikepayload = tmp;
  }


  if( ikemesg->tx_pkt ){
    rhp_pkt_unhold(ikemesg->tx_pkt);
  }

  if( ikemesg->rx_pkt ){
    rhp_pkt_unhold(ikemesg->rx_pkt);
  }

  if( ikemesg->tx_ikeh ){

  	_rhp_free(ikemesg->tx_ikeh);

  	rhp_ikev2_g_statistics_dec(dc.ikev2_alloc_tx_messages);

  }else{

  	rhp_ikev2_g_statistics_dec(dc.ikev2_alloc_rx_messages);
  }

  if( ikemesg->fixed_src_addr ){
  	_rhp_free(ikemesg->fixed_src_addr);
  }

  if( ikemesg->fixed_dst_addr ){
  	_rhp_free(ikemesg->fixed_dst_addr);
  }

  if( ikemesg->v1_p2_rx_last_blk ){
  	_rhp_free(ikemesg->v1_p2_rx_last_blk);
  }

  _rhp_atomic_destroy(&(ikemesg->refcnt));

  _rhp_free_zero(ikemesg,sizeof(rhp_ikev2_mesg));

  RHP_TRC(0,RHPTRCID_IKEV2_DESTROY_MESG_RTRN,"x",ikemesg);
  return;
}

void rhp_ikev2_hold_mesg(rhp_ikev2_mesg* ikemesg)
{
  RHP_TRC(0,RHPTRCID_IKEV2_HOLD_MESG,"x",ikemesg);

  _rhp_atomic_inc(&(ikemesg->refcnt));

  RHP_TRC(0,RHPTRCID_IKEV2_HOLD_MESG_RTRN,"xd",ikemesg,_rhp_atomic_read(&(ikemesg->refcnt)));
}

void rhp_ikev2_unhold_mesg(rhp_ikev2_mesg* ikemesg)
{
  RHP_TRC(0,RHPTRCID_IKEV2_UNHOLD_MESG_UNHOLD,"x",ikemesg);

#ifdef  RHP_CK_OBJ_TAG_GDB
  ikemesg = RHP_CK_OBJTAG("#IKM",ikemesg);
#endif // RHP_CK_OBJ_TAG_GDB

  if( _rhp_atomic_dec_and_test(&(ikemesg->refcnt)) ){

  	_rhp_ikev2_free_mesg(ikemesg);

  	RHP_TRC(0,RHPTRCID_IKEV2_UNHOLD_MESG_UNHOLD_FREE_MESG_RTRN,"x",ikemesg);

  }else{

  	RHP_TRC(0,RHPTRCID_IKEV2_UNHOLD_MESG_UNHOLD_RTRN,"xd",ikemesg,_rhp_atomic_read(&(ikemesg->refcnt)));
  }
}

static rhp_ikev2_mesg* _rhp_ikev2_new_error_pkt_for_new_rx_mesg(
		u32 message_id,u8 exchaneg_type,u16 notify_mesg_type,unsigned long arg0)
{
  rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_ERROR_PKT_FOR_NEW_RX_MESG,"ULbLwxu",message_id,"PROTO_IKE_EXCHG",exchaneg_type,"PROTO_IKE_NOTIFY",notify_mesg_type,arg0,arg0);

  tx_ikemesg = rhp_ikev2_new_mesg_tx(exchaneg_type,message_id,0);
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

    ikepayload->ext.n->set_protocol_id(ikepayload,0);
    ikepayload->ext.n->set_message_type(ikepayload,notify_mesg_type);

    switch( notify_mesg_type ){

      case RHP_PROTO_IKE_NOTIFY_ERR_UNSUPPORTED_CRITICAL_PAYLOAD:
      {
      	u8 payload_id = (u8)arg0;

      	if( ikepayload->ext.n->set_data(ikepayload,sizeof(u8),(u8*)&payload_id) ){
      		RHP_BUG("");
      		goto error;
      	}
      }
      	break;

      case RHP_PROTO_IKE_NOTIFY_ERR_INVALID_SYNTAX:
        break;

      default:
        RHP_BUG("%d",notify_mesg_type);
        goto error;
    }
  }

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_ERROR_PKT_FOR_NEW_RX_MESG_RTRN,"ULbLwx",message_id,"PROTO_IKE_EXCHG",exchaneg_type,"PROTO_IKE_NOTIFY",notify_mesg_type,tx_ikemesg);
  return tx_ikemesg;

error:
  if( tx_ikemesg ){
    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }
  RHP_TRC(0,RHPTRCID_IKEV2_NEW_ERROR_PKT_FOR_NEW_RX_MESG_ERR,"ULbLwx",message_id,"PROTO_IKE_EXCHG",exchaneg_type,"PROTO_IKE_NOTIFY",notify_mesg_type);
  return NULL;
}


//
// [CAUTION]
//
// rx_frag_completed can be valid after cheking this packet's ICV value
// by rhp_ikev2_mesg_rx_integ_check().
//
int rhp_ikev2_rx_verify_frag(rhp_packet* pkt,rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_proto_ike* rx_ikeh,
		int* rx_frag_completed_r)
{
	int err = -EINVAL;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_FRAG,"xxxxx",pkt,vpn,ikesa,rx_ikeh,rx_frag_completed_r);

  if( vpn == NULL || ikesa == NULL ||
  		(!vpn->exec_ikev2_frag &&
  		 rx_ikeh->next_payload == RHP_PROTO_IKE_PAYLOAD_SKF) ){

	  RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_FRAG_DISABLED,"xxxxb",pkt,vpn,ikesa,rx_ikeh,rx_ikeh->next_payload);
		err = RHP_STATUS_INVALID_MSG;
		goto error;
  }


	if( pkt->tail <= ((u8*)(rx_ikeh + 1)) + sizeof(rhp_proto_ike_skf_payload) ){

		RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_FRAG_BAD_MESG_LEN,"xxxx",pkt,vpn,ikesa,rx_ikeh);
		err = RHP_STATUS_INVALID_MSG;
		goto error;
	}

	{
		rhp_packet* pkt_f;
		rhp_packet_q* pkts_q;
		rhp_proto_ike* ikeh_f = NULL;
		rhp_proto_ike_skf_payload *rx_skf = (rhp_proto_ike_skf_payload*)(rx_ikeh + 1), *skf_f;
		u16 rx_frag_num = ntohs(rx_skf->frag_num) ,rx_total_frags = ntohs(rx_skf->total_frags), total_frags_f;
		int pkts_q_num;
		unsigned long total_frag_bytes_f = ntohl(rx_ikeh->len);

		if( RHP_PROTO_IKE_HDR_RESPONSE(rx_ikeh->flag) ){
			pkts_q = &(ikesa->rx_frag.rep_pkts);
			pkts_q_num = (ikesa->rx_frag.rep_pkts_num + 1);
		}else{
			pkts_q = &(ikesa->rx_frag.req_pkts);
			pkts_q_num = (ikesa->rx_frag.req_pkts_num + 1);
		}

		if( pkts_q_num > rhp_gcfg_ikev2_max_fragments ){

			err = RHP_STATUS_IKEV2_TOO_MANY_FRAGS;

			if( RHP_PROTO_IKE_HDR_RESPONSE(rx_ikeh->flag) ){
				rhp_ikev2_g_statistics_inc(rx_ikev2_resp_too_many_frag_packets);
			}else{
				rhp_ikev2_g_statistics_inc(rx_ikev2_req_too_many_frag_packets);
			}

			RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_FRAG_TOO_MANY_FRAGS,"xxxxJdd",pkt,vpn,ikesa,rx_ikeh,rx_ikeh->message_id,pkts_q_num,rhp_gcfg_ikev2_max_fragments);
			goto error;
		}


		pkt_f = _rhp_pkt_q_peek(pkts_q);
		if( pkt_f ){

			if( pkt_f->type != pkt->type ){
				err = RHP_STATUS_MISMATCHED_IP_VERSION;
				RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_FRAG_MISMATCHED_IP_VERSION,"xxxxLdLdJJ",pkt,vpn,ikesa,rx_ikeh,"PKT",pkt_f->type,"PKT",pkt->type,(ikeh_f ? ikeh_f->message_id : 0),rx_ikeh->message_id);
				goto error;
			}


			ikeh_f = pkt_f->app.ikeh;
			skf_f = (rhp_proto_ike_skf_payload*)(ikeh_f + 1);

			if( ntohl(ikeh_f->message_id) != ntohl(rx_ikeh->message_id) ){

				err = RHP_STATUS_INVALID_MSG;
				RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_FRAG_BAD_MESG_ID,"xxxxJJ",pkt,vpn,ikesa,rx_ikeh,ikeh_f->message_id,rx_ikeh->message_id);
				goto error;
			}

			total_frags_f = ntohs(skf_f->total_frags);
			if( total_frags_f > rx_total_frags ||
					((total_frags_f < rx_total_frags) && rx_frag_num != 1) ){

				err = RHP_STATUS_IKEV2_FRAG_RX_IGNORED;
				RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_FRAG_BAD_TOTAL_FRAGS,"xxxxwww",pkt,vpn,ikesa,rx_ikeh,total_frags_f,rx_total_frags,rx_frag_num);
				goto error;
			}

			while( pkt_f ){

				ikeh_f = pkt_f->app.ikeh;
				skf_f = (rhp_proto_ike_skf_payload*)(ikeh_f + 1);

				if( ntohs(skf_f->frag_num) == rx_frag_num ){

					err = RHP_STATUS_IKEV2_FRAG_RX_IGNORED;

					if( RHP_PROTO_IKE_HDR_RESPONSE(rx_ikeh->flag) ){
				  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_rx_dup_frag_packets);
					}else{
				  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_rx_dup_frag_packets);
					}

					RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_FRAG_REPLAYED,"xxxxWw",pkt,vpn,ikesa,rx_ikeh,skf_f->frag_num,rx_frag_num);
					goto error;
				}


				total_frag_bytes_f += ntohl(ikeh_f->len) - (int)sizeof(rhp_proto_ike);

				if( total_frag_bytes_f > (unsigned long)rhp_gcfg_ikev2_frag_max_packet_size ){

			    err = RHP_STATUS_MSG_TOO_LONG;

					if( RHP_PROTO_IKE_HDR_RESPONSE(rx_ikeh->flag) ){
				  	rhp_ikev2_g_statistics_inc(rx_ikev2_resp_too_long_frag_packets);
					}else{
				  	rhp_ikev2_g_statistics_inc(rx_ikev2_req_too_long_frag_packets);
					}

					RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_FRAG_MESG_TOO_LONG,"xxxxud",pkt,vpn,ikesa,rx_ikeh,total_frag_bytes_f,rhp_gcfg_ikev2_frag_max_packet_size);
					goto error;
				}

				pkt_f = pkt_f->next;
			}

			if( rx_frag_completed_r ){

				if( total_frags_f == rx_total_frags &&
						ikesa->rx_frag.rep_pkts_num == (total_frags_f - 1) ){

					*rx_frag_completed_r = 1;

				}else{

					*rx_frag_completed_r = 0;
				}
			}
		}
	}


  RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_FRAG_RTRN,"xxxxd",pkt,vpn,ikesa,rx_ikeh,(rx_frag_completed_r ? *rx_frag_completed_r : 0));
	return 0;

error:

	if( err != RHP_STATUS_IKEV2_FRAG_RX_IGNORED ){

		if( pkt->type == RHP_PKT_IPV4_IKE ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV2_VERIFY_DEFRAG_ERR,"VP44WWGGLJE",vpn,ikesa,(pkt->l3.raw ? pkt->l3.iph_v4->src_addr : 0),(pkt->l3.raw ? pkt->l3.iph_v4->dst_addr : 0),(pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt->l4.raw ? pkt->l4.udph->dst_port : 0),rx_ikeh->init_spi,rx_ikeh->resp_spi,"PROTO_IKE_EXCHG",(int)rx_ikeh->exchange_type,rx_ikeh->message_id,err);
		}else if( pkt->type == RHP_PKT_IPV6_IKE ){
			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV2_VERIFY_DEFRAG_ERR_V6,"VP66WWGGLJE",vpn,ikesa,(pkt->l3.raw ? pkt->l3.iph_v6->src_addr : NULL),(pkt->l3.raw ? pkt->l3.iph_v6->dst_addr : NULL),(pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt->l4.raw ? pkt->l4.udph->dst_port : 0),rx_ikeh->init_spi,rx_ikeh->resp_spi,"PROTO_IKE_EXCHG",(int)rx_ikeh->exchange_type,rx_ikeh->message_id,err);
		}

		if( RHP_PROTO_IKE_HDR_RESPONSE(rx_ikeh->flag) ){
			rhp_ikev2_g_statistics_inc(rx_ikev2_resp_invalid_frag_packets);
		}else{
			rhp_ikev2_g_statistics_inc(rx_ikev2_req_invalid_frag_packets);
		}
	}

	RHP_TRC(0,RHPTRCID_IKEV2_RX_VERIFY_FRAG_ERR,"xxxxE",pkt,vpn,ikesa,rx_ikeh,err);
	return err;
}

static void _rhp_ikev2_rx_reset_frag_q(rhp_ikesa* ikesa,rhp_proto_ike* rx_ikeh)
{
	rhp_packet* pkt_f;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_RESET_FRAG_Q,"xx",ikesa,rx_ikeh);

	if( ikesa == NULL ){
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_RESET_FRAG_Q_NO_IKESA,"xx",ikesa,rx_ikeh);
		return;
	}

	if( RHP_PROTO_IKE_HDR_RESPONSE(rx_ikeh->flag) ){

		pkt_f = _rhp_pkt_q_peek(&(ikesa->rx_frag.rep_pkts));
		if( pkt_f &&
				pkt_f->app.ikeh->message_id == rx_ikeh->message_id ){

			ikesa->reset_rep_frag_pkts_q(ikesa);
		}

	  RHP_TRC(0,RHPTRCID_IKEV2_RX_RESET_FRAG_Q_RESP_RTRN,"xx",ikesa,rx_ikeh);

	}else{

		pkt_f = _rhp_pkt_q_peek(&(ikesa->rx_frag.req_pkts));
		if( pkt_f &&
				pkt_f->app.ikeh->message_id == rx_ikeh->message_id ){

			ikesa->reset_req_frag_pkts_q(ikesa);
		}

		RHP_TRC(0,RHPTRCID_IKEV2_RX_RESET_FRAG_Q_REQ_RTRN,"xx",ikesa,rx_ikeh);
	}

	return;
}

static int _rhp_ikev2_rx_defrag_q_pos(rhp_packet_q* pkt_q_cb,rhp_packet* pkt_cur,rhp_packet* pkt_new)
{
	rhp_proto_ike *rx_ikeh = pkt_new->app.ikeh, *ikeh_f = pkt_cur->app.ikeh;
	rhp_proto_ike_skf_payload *rx_skf, *skf_f;
	u16 rx_frag_num, frag_num_f;

	rx_skf = (rhp_proto_ike_skf_payload*)(rx_ikeh + 1);
	rx_frag_num = ntohs(rx_skf->frag_num);

	skf_f = (rhp_proto_ike_skf_payload*)(ikeh_f + 1);
	frag_num_f = ntohs(skf_f->frag_num);

	if( frag_num_f > rx_frag_num ){
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_DEFRAG_Q_POS_1,"xxx",pkt_q_cb,pkt_cur,pkt_new);
		return 1;
	}

  RHP_TRC(0,RHPTRCID_IKEV2_RX_DEFRAG_Q_POS_0,"xxx",pkt_q_cb,pkt_cur,pkt_new);
	return 0;
}

// This func always returns status code.
static int _rhp_ikev2_rx_defrag_mesg(rhp_packet* pkt,rhp_ikesa* ikesa)
{
	int err = -EINVAL;
	rhp_packet *pkt_f;
	rhp_proto_ike *rx_ikeh = pkt->app.ikeh, *ikeh_f;
	rhp_proto_ike_skf_payload *rx_skf;
	u16 rx_total_frags = 0;
	rhp_packet_q* pkts_q;
	int pkts_q_num = -1;
	int exp_len = 0;
	u8 *rx_pkt_buf = NULL, *p0;
	int rx_pkt_buf_len = 0;
	u8 skf_next_payload = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_DEFRAG_MESG,"xxxdxdxd",pkt,ikesa,rx_ikeh,RHP_PROTO_IKE_HDR_RESPONSE(rx_ikeh->flag),ikesa->rx_frag.req_pkts.head,ikesa->rx_frag.req_pkts_num,ikesa->rx_frag.rep_pkts.head,ikesa->rx_frag.rep_pkts_num);

	if( pkt->tail > ((u8*)(rx_ikeh + 1)) + (int)sizeof(rhp_proto_ike_skf_payload) ){

		rx_skf = (rhp_proto_ike_skf_payload*)(rx_ikeh + 1);
		rx_total_frags = ntohs(rx_skf->total_frags);

		if( RHP_PROTO_IKE_HDR_RESPONSE(rx_ikeh->flag) ){
			pkts_q = &(ikesa->rx_frag.rep_pkts);
			pkts_q_num = ++ikesa->rx_frag.rep_pkts_num;
		}else{
			pkts_q = &(ikesa->rx_frag.req_pkts);
			pkts_q_num = ++ikesa->rx_frag.req_pkts_num;
		}


		pkt_f = _rhp_pkt_q_peek(pkts_q);
		if( pkt_f ){

			ikeh_f = pkt_f->app.ikeh;
			rhp_proto_ike_skf_payload* skf_f = (rhp_proto_ike_skf_payload*)(ikeh_f + 1);

			if( ntohs(skf_f->total_frags) < rx_total_frags ){

		  	_rhp_ikev2_rx_reset_frag_q(ikesa,rx_ikeh);

		  	_rhp_pkt_q_enq(pkts_q,pkt);
		  	rhp_pkt_hold(pkt);

				if( RHP_PROTO_IKE_HDR_RESPONSE(rx_ikeh->flag) ){
					ikesa->rx_frag.rep_pkts_num++;
				}else{
					ikesa->rx_frag.req_pkts_num++;
				}

				RHP_TRC(0,RHPTRCID_IKEV2_RX_DEFRAG_MESG_RESET_FRAG_Q,"xxxww",pkt,ikesa,skf_f,ntohs(skf_f->total_frags),rx_total_frags);

				err = RHP_STATUS_IKEV2_FRAG_RX_PENDING;
				goto error;
			}

			_rhp_pkt_q_insert(pkts_q,pkt,_rhp_ikev2_rx_defrag_q_pos);
	  	rhp_pkt_hold(pkt);

			RHP_TRC(0,RHPTRCID_IKEV2_RX_DEFRAG_MESG_INSERT_PKT_Q,"xxx",pkt,ikesa,skf_f);

		}else{

			RHP_TRC(0,RHPTRCID_IKEV2_RX_DEFRAG_MESG_ENQ_1ST_PKT_Q,"xxx",pkt,ikesa,pkt);

			_rhp_pkt_q_enq(pkts_q,pkt);
	  	rhp_pkt_hold(pkt);
		}

	}else{

	  RHP_TRC(0,RHPTRCID_IKEV2_RX_DEFRAG_MESG_BAD_MESG,"xxxxd",pkt,ikesa,pkt->tail,(u8*)(rx_ikeh + 1),(int)sizeof(rhp_proto_ike_skf_payload));

		err = RHP_STATUS_INVALID_MSG;
		goto error;
	}


	if( pkts_q_num != rx_total_frags ){

		RHP_TRC(0,RHPTRCID_IKEV2_RX_DEFRAG_MESG_PENDING,"xxdd",pkt,ikesa,pkts_q_num,rx_total_frags);

		if( pkts_q_num == 1 ){
			err = RHP_STATUS_IKEV2_FRAG_RX_1ST_FRAG;
		}else{
			err = RHP_STATUS_IKEV2_FRAG_RX_PENDING;
		}

		goto pending;
	}


	pkt_f = _rhp_pkt_q_peek(pkts_q);
	while( pkt_f ){

		u8 next_payload;

		err = _rhp_ikev2_mesg_decrypt(pkt_f,ikesa,&next_payload);
		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV2_RX_DEFRAG_MESG_DEC_ERR,"xxx",pkt_f,ikesa,pkt);
			goto error;
		}

		if( pkt_f == pkts_q->head ){
			skf_next_payload = next_payload;
		}

		exp_len += ntohl(pkt_f->app.ikeh->len) - (int)sizeof(rhp_proto_ike);

		pkt_f = pkt_f->next;
	}

	if( skf_next_payload == 0 ){

		RHP_TRC(0,RHPTRCID_IKEV2_RX_DEFRAG_MESG_INVALID_NXT_PLD_VAL,"xxb",pkt,ikesa,skf_next_payload);

		err = RHP_STATUS_INVALID_MSG;
		goto error;
	}


	rx_pkt_buf_len = ntohl(pkt->app.ikeh->len) - (int)sizeof(rhp_proto_ike);
	if( rx_pkt_buf_len > 0 ){

		rx_pkt_buf = (u8*)_rhp_malloc(rx_pkt_buf_len);
		if( rx_pkt_buf == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		memcpy(rx_pkt_buf,(u8*)(pkt->app.ikeh + 1),rx_pkt_buf_len);
	}


	if( rhp_pkt_expand_tail(pkt,
				(exp_len - ntohl(pkt->app.ikeh->len) + (int)sizeof(rhp_proto_ike))) == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	rx_ikeh = pkt->app.ikeh;
	rx_ikeh->next_payload = skf_next_payload;

	p0 = (u8*)(rx_ikeh + 1);


	pkt_f = _rhp_pkt_q_peek(pkts_q);
	while( pkt_f ){

		int p1_len = ntohl(pkt_f->app.ikeh->len) - (int)sizeof(rhp_proto_ike);
		u8* p1 = (u8*)(pkt_f->app.ikeh + 1);

		if( pkt_f != pkt && p1_len ){

			memcpy(p0,p1,p1_len);
			p0 += p1_len;

		}else if( pkt_f == pkt &&
							rx_pkt_buf && rx_pkt_buf_len > 0 ){

			memcpy(p0,rx_pkt_buf,rx_pkt_buf_len);
			p0 += rx_pkt_buf_len;
		}

		pkt_f = pkt_f->next;
	}


	// Qed frag packets are unheld/released here.
	_rhp_ikev2_rx_reset_frag_q(ikesa,pkt->app.ikeh);

	err = RHP_STATUS_IKEV2_FRAG_RX_COMPLETED;


pending:

	if( rx_pkt_buf ){
		_rhp_free_zero(rx_pkt_buf,rx_pkt_buf_len);
	}

	if( err == RHP_STATUS_IKEV2_FRAG_RX_COMPLETED ){
		if( pkt->type == RHP_PKT_IPV4_IKE ){
			RHP_TRC(0,RHPTRCID_IKEV2_RX_DEFRAG_MESG_DEFRAG_PKT_COMP,"xxEa",ikesa,pkt,err,(pkt->tail - pkt->l2.raw),RHP_TRC_FMT_A_MAC_IPV4_IKEV2_PLAIN,0,0,pkt->l2.raw);
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV2_DEFRAG_COMP_PKT,"P44WWGGLJE",ikesa,(pkt->l3.raw ? pkt->l3.iph_v4->src_addr : 0),(pkt->l3.raw ? pkt->l3.iph_v4->dst_addr : 0),(pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt->l4.raw ? pkt->l4.udph->dst_port : 0),rx_ikeh->init_spi,rx_ikeh->resp_spi,"PROTO_IKE_EXCHG",(int)rx_ikeh->exchange_type,rx_ikeh->message_id,err);
		}else if( pkt->type == RHP_PKT_IPV6_IKE ){
			RHP_TRC(0,RHPTRCID_IKEV2_RX_DEFRAG_MESG_DEFRAG_PKT_COMP_V6,"xxEa",ikesa,pkt,err,(pkt->tail - pkt->l2.raw),RHP_TRC_FMT_A_MAC_IPV6_IKEV2_PLAIN,0,0,pkt->l2.raw);
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV2_DEFRAG_COMP_PKT_V6,"P66WWGGLJE",ikesa,(pkt->l3.raw ? pkt->l3.iph_v6->src_addr : NULL),(pkt->l3.raw ? pkt->l3.iph_v6->dst_addr : NULL),(pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt->l4.raw ? pkt->l4.udph->dst_port : 0),rx_ikeh->init_spi,rx_ikeh->resp_spi,"PROTO_IKE_EXCHG",(int)rx_ikeh->exchange_type,rx_ikeh->message_id,err);
		}
	}else{
		if( pkt->type == RHP_PKT_IPV4_IKE ){
			RHP_TRC(0,RHPTRCID_IKEV2_RX_DEFRAG_MESG_DEFRAG_PKT,"xxEa",ikesa,pkt,err,(pkt->tail - pkt->l2.raw),RHP_TRC_FMT_A_MAC_IPV4_IKEV2,0,0,pkt->l2.raw);
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV2_DEFRAG_PKT,"P44WWGGLJE",ikesa,(pkt->l3.raw ? pkt->l3.iph_v4->src_addr : 0),(pkt->l3.raw ? pkt->l3.iph_v4->dst_addr : 0),(pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt->l4.raw ? pkt->l4.udph->dst_port : 0),rx_ikeh->init_spi,rx_ikeh->resp_spi,"PROTO_IKE_EXCHG",(int)rx_ikeh->exchange_type,rx_ikeh->message_id,err);
		}else if( pkt->type == RHP_PKT_IPV6_IKE ){
			RHP_TRC(0,RHPTRCID_IKEV2_RX_DEFRAG_MESG_DEFRAG_PKT_V6,"xxEa",ikesa,pkt,err,(pkt->tail - pkt->l2.raw),RHP_TRC_FMT_A_MAC_IPV6_IKEV2,0,0,pkt->l2.raw);
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV2_DEFRAG_PKT_V6,"P66WWGGLJE",ikesa,(pkt->l3.raw ? pkt->l3.iph_v6->src_addr : NULL),(pkt->l3.raw ? pkt->l3.iph_v6->dst_addr : NULL),(pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt->l4.raw ? pkt->l4.udph->dst_port : 0),rx_ikeh->init_spi,rx_ikeh->resp_spi,"PROTO_IKE_EXCHG",(int)rx_ikeh->exchange_type,rx_ikeh->message_id,err);
		}
	}

	RHP_TRC(0,RHPTRCID_IKEV2_RX_DEFRAG_MESG_RTRN,"xxLdE",pkt,ikesa,"PROTO_IKE_PAYLOAD",(int)skf_next_payload,err);
	return err;

error:
	if( rx_pkt_buf ){
		_rhp_free_zero(rx_pkt_buf,rx_pkt_buf_len);
	}

	_rhp_ikev2_rx_reset_frag_q(ikesa,pkt->app.ikeh);

	if( pkt->type == RHP_PKT_IPV4_IKE ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV2_DEFRAG_ERR,"P44WWGGLJE",ikesa,(pkt->l3.raw ? pkt->l3.iph_v4->src_addr : 0),(pkt->l3.raw ? pkt->l3.iph_v4->dst_addr : 0),(pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt->l4.raw ? pkt->l4.udph->dst_port : 0),rx_ikeh->init_spi,rx_ikeh->resp_spi,"PROTO_IKE_EXCHG",(int)rx_ikeh->exchange_type,rx_ikeh->message_id,err);
	}else if( pkt->type == RHP_PKT_IPV6_IKE ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_IKEV2_DEFRAG_ERR_V6,"P66WWGGLJE",ikesa,(pkt->l3.raw ? pkt->l3.iph_v6->src_addr : NULL),(pkt->l3.raw ? pkt->l3.iph_v6->dst_addr : NULL),(pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt->l4.raw ? pkt->l4.udph->dst_port : 0),rx_ikeh->init_spi,rx_ikeh->resp_spi,"PROTO_IKE_EXCHG",(int)rx_ikeh->exchange_type,rx_ikeh->message_id,err);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_RX_DEFRAG_MESG_ERR,"xxE",pkt,ikesa,err);
	return err;
}

// vpn, ikesa and ikeh_r may be NULL.
int rhp_ikev2_new_mesg_rx(rhp_packet* pkt,rhp_proto_ike** ikeh_r,rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg** ikemesg_r,
		rhp_ikev2_payload** n_cookie_payload_r,
		rhp_ikev2_payload** nir_payload_r,
		rhp_ikev2_mesg** ikemesg_err_r)
{
  int err = -EINVAL,suberr = -EINVAL, defragerr = 0;
  rhp_ikev2_mesg* ikemesg = NULL;
  rhp_proto_ike* ikeh = pkt->app.ikeh;
  u8 next_payload;
  u8 unknown_payload_id = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_MESG_RX,"xxxxxxxxdx",pkt,ikeh_r,(ikeh_r ? *ikeh_r : NULL),vpn,ikesa,ikemesg_r,n_cookie_payload_r,nir_payload_r,pkt->cookie_checked,pkt->cookie_checked_rx_mesg);

  //
  //
	// ICV's verification for the rx_pkt is already done.
  //
  //

  if( pkt->cookie_checked && pkt->cookie_checked_rx_mesg ){

  	// pkt->cookie_checked_rx_mesg's refcnt is already held
  	// in _rhp_ikev2_ike_sa_init_cookie_task().
  	ikemesg = pkt->cookie_checked_rx_mesg;
  	pkt->cookie_checked_rx_mesg = NULL;

  	ikemesg->dump_payloads(ikemesg);

    *ikemesg_r = ikemesg;

  	RHP_TRC(0,RHPTRCID_IKEV2_NEW_MESG_RX_COOKIE_CHECKED_RTRN,"xx",pkt,ikemesg);
    return 0;
  }

  if( ikeh_r ){

  	if( (*ikeh_r)->next_payload == RHP_PROTO_IKE_PAYLOAD_SKF ){

			if( ikesa == NULL ){
				err = RHP_STATUS_INVALID_MSG;
				goto error;
			}

			defragerr = _rhp_ikev2_rx_defrag_mesg(pkt,ikesa);

			if( defragerr == RHP_STATUS_IKEV2_FRAG_RX_1ST_FRAG ||
					defragerr == RHP_STATUS_IKEV2_FRAG_RX_PENDING ||
					defragerr == RHP_STATUS_IKEV2_FRAG_RX_IGNORED ){

				RHP_TRC(0,RHPTRCID_IKEV2_NEW_MESG_RX_FRAG_PENDING,"xE",pkt,defragerr);
				return defragerr;

			}else if( defragerr &&
								defragerr != RHP_STATUS_IKEV2_FRAG_RX_COMPLETED ){

				err = defragerr;
				RHP_TRC(0,RHPTRCID_IKEV2_NEW_MESG_RX_FRAG_ERR,"xE",pkt,defragerr);

				goto error;
			}

		}else{

			if( ikesa ){

				// Peer may cancel tx of fragments. Just to make sure,
				// clear fragments' Q here.
				_rhp_ikev2_rx_reset_frag_q(ikesa,pkt->app.ikeh);
			}
		}
  }


  ikeh = pkt->app.ikeh;
  if( ikeh_r ){
  	*ikeh_r = ikeh;
  }

	ikemesg = _rhp_ikev2_alloc_mesg(RHP_FALSE);
	if( ikemesg == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	ikemesg->rx_pkt = pkt;
	rhp_pkt_hold(pkt);


  next_payload = ikemesg->get_next_payload(ikemesg);

  if( next_payload == RHP_PROTO_IKE_PAYLOAD_E ){

  	if( defragerr ){ // RHP_STATUS_IKEV2_FRAG_RX_COMPLETED
  		err = RHP_STATUS_INVALID_MSG;
      suberr = RHP_STATUS_INVALID_IKEV2_MESG_BAD_NEXT_PAYLOAD;
  		goto error;
  	}

    err = ikemesg->decrypt(pkt,ikesa,&next_payload);
    if( err ){
      RHP_TRC(0,RHPTRCID_IKEV2_NEW_MESG_RX_INVALID_MESG_1,"xE",pkt,err);
      suberr = RHP_STATUS_INVALID_IKEV2_MESG_DECRYPTO_ERR;
      goto error;
    }

    ikemesg->decrypted = 1;

//	RHP_TRC(0,RHPTRCID_IKEV2_NEW_MESG_RX_DECRYPTED_AND_TRIMED,"xa",pkt,(pkt->tail - pkt->l2.raw),RHP_TRC_FMT_A_MAC_IPV4_IKEV2,0,0,pkt->l2.raw);


  	if( rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_IKEV2_PLAIN] &&
  			(!rhp_packet_capture_realm_id || (vpn && rhp_packet_capture_realm_id == vpn->vpn_realm_id)) ){

  		_rhp_ikev2_mesg_rx_pcap_write(pkt);
    }

  }else if( defragerr ){

    ikemesg->decrypted = 1;
  }


  while( next_payload != RHP_PROTO_IKE_NO_MORE_PAYLOADS ){

    int pl_len;
    rhp_proto_ike_payload* pl;
    rhp_ikev2_payload* ikepayload;

    if( next_payload == RHP_PROTO_IKE_PAYLOAD_E ||
    		next_payload == RHP_PROTO_IKE_PAYLOAD_SKF ){

      RHP_TRC(0,RHPTRCID_IKEV2_NEW_MESG_RX_INVALID_MESG_2,"x",pkt);
      err = RHP_STATUS_INVALID_MSG;
      suberr = RHP_STATUS_INVALID_IKEV2_MESG_BAD_NEXT_PAYLOAD;

      goto error;
    }

    if( _rhp_pkt_try_pull(pkt,sizeof(rhp_proto_ike_payload)) ){

    	RHP_TRC(0,RHPTRCID_IKEV2_NEW_MESG_RX_INVALID_MESG_3,"x",pkt);
      err = RHP_STATUS_INVALID_MSG;
      suberr = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;

      goto error;
    }

    pl_len = ntohs(((rhp_proto_ike_payload*)(pkt->data))->len);

    if( pl_len < (int)sizeof(rhp_proto_ike_payload) || _rhp_pkt_try_pull(pkt,pl_len) ){

    	RHP_TRC(0,RHPTRCID_IKEV2_NEW_MESG_RX_INVALID_MESG_4,"x",pkt);
      err = RHP_STATUS_INVALID_MSG;
      suberr = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;

      goto error;
    }

    pl = (rhp_proto_ike_payload*)pkt->data;

    err = rhp_ikev2_new_payload_rx(ikemesg,next_payload,pl,pl_len,&ikepayload);
    if( err ){

  		if( pkt->type == RHP_PKT_IPV4_IKE ){
  			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKEV2_PARSE_RX_PAYLOAD_ERR,"LP44WWE","PROTO_IKE_PAYLOAD",(unsigned long)next_payload,ikesa,(pkt->l3.raw ? pkt->l3.iph_v4->src_addr : 0),(pkt->l3.raw ? pkt->l3.iph_v4->dst_addr : 0),(pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt->l4.raw ? pkt->l4.udph->dst_port : 0),err);
  		}else if( pkt->type == RHP_PKT_IPV6_IKE ){
  			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKEV2_PARSE_RX_PAYLOAD_ERR_V6,"LP66WWE","PROTO_IKE_PAYLOAD",(unsigned long)next_payload,ikesa,(pkt->l3.raw ? pkt->l3.iph_v6->src_addr : NULL),(pkt->l3.raw ? pkt->l3.iph_v6->dst_addr : NULL),(pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt->l4.raw ? pkt->l4.udph->dst_port : 0),err);
  		}

    	if( err == RHP_STATUS_UNKNOWN_PAYLOAD && !RHP_PROTO_IKE_PLD_CRITICAL(pl->critical_rsv) ){

    		if( _rhp_pkt_pull(pkt,pl_len) != NULL ){

    			next_payload = pl->next_payload;
    			err = 0;
    			continue;

       }else{

      	 RHP_TRC(0,RHPTRCID_IKEV2_NEW_MESG_RX_INVALID_MESG_5,"xE",pkt,err);
         suberr = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;
       }

     }else{

    	 RHP_TRC(0,RHPTRCID_IKEV2_NEW_MESG_RX_INVALID_MESG_6,"xE",pkt,err);
       suberr = RHP_STATUS_INVALID_IKEV2_MESG_INVALID_PAYLOAD;
     }

    	unknown_payload_id = next_payload;
    	goto error;
    }

    ikemesg->put_payload(ikemesg,ikepayload);

    if( n_cookie_payload_r &&
    	 next_payload == RHP_PROTO_IKE_PAYLOAD_N &&
    	 ikepayload->ext.n->get_message_type(ikepayload) == RHP_PROTO_IKE_NOTIFY_ST_COOKIE ){

    	*n_cookie_payload_r = ikepayload;
    }

    if( nir_payload_r && next_payload == RHP_PROTO_IKE_PAYLOAD_N_I_R ){
      *nir_payload_r = ikepayload;
    }

    if( next_payload == RHP_PROTO_IKE_PAYLOAD_E ){
      break;
    }

    next_payload = ikepayload->get_next_payload(ikepayload);
  }

  if( pkt->data != pkt->tail ){

  	RHP_TRC(0,RHPTRCID_IKEV2_NEW_MESG_RX_INVALID_MESG_7,"x",pkt);
    err = RHP_STATUS_INVALID_MSG;
    suberr = RHP_STATUS_INVALID_IKEV2_MESG_INVALID_PAYLOAD;

    goto error;
  }

  ikemesg->dump_payloads(ikemesg);

  *ikemesg_r = ikemesg;


  if( n_cookie_payload_r && nir_payload_r ){
  	RHP_TRC(0,RHPTRCID_IKEV2_NEW_MESG_RX_RTRN,"xxxxxE",pkt,(ikeh_r ? *ikeh_r : NULL),ikemesg,*n_cookie_payload_r,*nir_payload_r,defragerr);
  }else if( n_cookie_payload_r ){
  	RHP_TRC(0,RHPTRCID_IKEV2_NEW_MESG_RX_RTRN,"xxxxxE",pkt,(ikeh_r ? *ikeh_r : NULL),ikemesg,*n_cookie_payload_r,NULL,defragerr);
  }else if( nir_payload_r ){
  	RHP_TRC(0,RHPTRCID_IKEV2_NEW_MESG_RX_RTRN,"xxxxxE",pkt,(ikeh_r ? *ikeh_r : NULL),ikemesg,NULL,*nir_payload_r,defragerr);
  }else{
  	RHP_TRC(0,RHPTRCID_IKEV2_NEW_MESG_RX_RTRN,"xxxxxE",pkt,(ikeh_r ? *ikeh_r : NULL),ikemesg,NULL,NULL,defragerr);
  }

  if( defragerr ){
  	return defragerr;
  }

  return 0;

error:
  if( ikemesg_err_r && ikeh &&
  		!RHP_PROTO_IKE_HDR_RESPONSE(ikeh->flag) && ikesa &&
  		ikemesg && ikemesg->decrypted ){

  	if( err == RHP_STATUS_UNKNOWN_PAYLOAD ){

  		*ikemesg_err_r = _rhp_ikev2_new_error_pkt_for_new_rx_mesg(ntohl(ikeh->message_id),
  				ikeh->exchange_type,RHP_PROTO_IKE_NOTIFY_ERR_UNSUPPORTED_CRITICAL_PAYLOAD,unknown_payload_id);

  	}else{

  		*ikemesg_err_r = _rhp_ikev2_new_error_pkt_for_new_rx_mesg(ntohl(ikeh->message_id),
  				ikeh->exchange_type,RHP_PROTO_IKE_NOTIFY_ERR_INVALID_SYNTAX,0);
  	}
  }

	if( pkt->type == RHP_PKT_IPV4_IKE ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKEV2_PARSE_RX_MESG_ERR,"P44WWEE",ikesa,(pkt->l3.raw ? pkt->l3.iph_v4->src_addr : 0),(pkt->l3.raw ? pkt->l3.iph_v4->dst_addr : 0),(pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt->l4.raw ? pkt->l4.udph->dst_port : 0),err,suberr);
	}else	if( pkt->type == RHP_PKT_IPV6_IKE ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKEV2_PARSE_RX_MESG_ERR_V6,"P66WWEE",ikesa,(pkt->l3.raw ? pkt->l3.iph_v6->src_addr : NULL),(pkt->l3.raw ? pkt->l3.iph_v6->dst_addr : NULL),(pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt->l4.raw ? pkt->l4.udph->dst_port : 0),err,suberr);
	}

	if( ikemesg ){
    rhp_ikev2_unhold_mesg(ikemesg);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_MESG_RX_ERR,"xxxEEE",pkt,(ikeh_r ? *ikeh_r : NULL),*ikemesg_err_r,err,suberr,defragerr);
  return err;
}

// vpn and ikesa may be NULL.
int rhp_ikev1_new_mesg_rx(rhp_packet* pkt,rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg** ikemesg_r,
		rhp_ikev2_mesg** ikemesg_err_r)
{
  int err = -EINVAL,suberr = -EINVAL;
  rhp_ikev2_mesg* ikemesg = NULL;
  rhp_proto_ike* ikeh = pkt->app.ikeh;
  u8 next_payload;

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_MESG_RX,"xxxxxx",pkt,ikeh,vpn,ikesa,ikemesg_r,ikemesg_err_r);

	ikemesg = _rhp_ikev2_alloc_mesg(RHP_FALSE);
	if( ikemesg == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	ikemesg->is_v1 = 1;

	ikemesg->rx_pkt = pkt;
	rhp_pkt_hold(pkt);


  next_payload = ikemesg->get_next_payload(ikemesg);

  if( RHP_PROTO_IKEV1_HDR_ENCRYPT(ikeh->flag) ){

  	if( vpn == NULL || ikesa == NULL ){
  		err = RHP_STATUS_INVALID_MSG;
  		goto error;
  	}

    err = ikemesg->decrypt_v1(pkt,ikesa,&next_payload,
    				&(ikemesg->v1_p2_iv_len),&(ikemesg->v1_p2_rx_last_blk));
    if( err ){

    	RHP_TRC(0,RHPTRCID_IKEV1_NEW_MESG_RX_INVALID_MESG_1,"xE",pkt,err);
      suberr = RHP_STATUS_INVALID_IKEV2_MESG_DECRYPTO_ERR;

      goto error;
    }

    ikemesg->decrypted = 1;

//	RHP_TRC(0,RHPTRCID_IKEV1_NEW_MESG_RX_DECRYPTED_AND_TRIMED,"xa",pkt,(pkt->tail - pkt->l2.raw),RHP_TRC_FMT_A_MAC_IPV4_IKEV2,0,0,pkt->l2.raw);


  	if( rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_IKEV2_PLAIN] &&
  			(!rhp_packet_capture_realm_id || (vpn && rhp_packet_capture_realm_id == vpn->vpn_realm_id)) ){

  		_rhp_ikev2_mesg_rx_pcap_write(pkt);
    }
  }


  while( next_payload != RHP_PROTO_IKE_NO_MORE_PAYLOADS ){

    int pl_len;
    rhp_proto_ike_payload* pl;
    rhp_ikev2_payload* ikepayload;


    if( _rhp_pkt_try_pull(pkt,sizeof(rhp_proto_ike_payload)) ){

    	RHP_TRC(0,RHPTRCID_IKEV1_NEW_MESG_RX_INVALID_MESG_3,"xxxxx",pkt,pkt->head,pkt->data,pkt->tail,pkt->end);
      err = RHP_STATUS_INVALID_MSG;
      suberr = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;

      goto error;
    }

    pl_len = ntohs(((rhp_proto_ike_payload*)(pkt->data))->len);

    if( pl_len < (int)sizeof(rhp_proto_ike_payload) || _rhp_pkt_try_pull(pkt,pl_len) ){

    	RHP_TRC(0,RHPTRCID_IKEV1_NEW_MESG_RX_INVALID_MESG_4,"xdxxxx",pkt,pl_len,pkt->head,pkt->data,pkt->tail,pkt->end);
      err = RHP_STATUS_INVALID_MSG;
      suberr = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;

      goto error;
    }

    pl = (rhp_proto_ike_payload*)pkt->data;

  	RHP_TRC_FREQ(0,RHPTRCID_IKEV1_NEW_MESG_RX_PLD_DATA,"xp",pkt,pl_len,pl);

    err = rhp_ikev2_new_payload_rx(ikemesg,next_payload,pl,pl_len,&ikepayload);
    if( err ){

  		if( pkt->type == RHP_PKT_IPV4_IKE ){
  			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKEV1_PARSE_RX_PAYLOAD_ERR,"LP44WWE","PROTO_IKE_PAYLOAD",(unsigned long)next_payload,ikesa,(pkt->l3.raw ? pkt->l3.iph_v4->src_addr : 0),(pkt->l3.raw ? pkt->l3.iph_v4->dst_addr : 0),(pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt->l4.raw ? pkt->l4.udph->dst_port : 0),err);
  		}else if( pkt->type == RHP_PKT_IPV6_IKE ){
  			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKEV1_PARSE_RX_PAYLOAD_ERR_V6,"LP66WWE","PROTO_IKE_PAYLOAD",(unsigned long)next_payload,ikesa,(pkt->l3.raw ? pkt->l3.iph_v6->src_addr : NULL),(pkt->l3.raw ? pkt->l3.iph_v6->dst_addr : NULL),(pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt->l4.raw ? pkt->l4.udph->dst_port : 0),err);
  		}

    	if( err == RHP_STATUS_UNKNOWN_PAYLOAD ){

    		if( _rhp_pkt_pull(pkt,pl_len) != NULL ){

    			next_payload = pl->next_payload;
    			err = 0;
    			continue;

    		}else{

    			RHP_TRC(0,RHPTRCID_IKEV1_NEW_MESG_RX_INVALID_MESG_5,"xE",pkt,err);
    			suberr = RHP_STATUS_INVALID_IKEV2_MESG_BAD_LENGTH;
    		}

    	}else{

    		RHP_TRC(0,RHPTRCID_IKEV1_NEW_MESG_RX_INVALID_MESG_6,"xE",pkt,err);
    		suberr = RHP_STATUS_INVALID_IKEV2_MESG_INVALID_PAYLOAD;
    	}

    	goto error;
    }

    {
    	u8 v1_exchg_type = ikemesg->get_exchange_type(ikemesg);

			if( (v1_exchg_type == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ||
					 v1_exchg_type == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE) &&
					next_payload == RHP_PROTO_IKEV1_PAYLOAD_SA &&
					ikepayload->ext.v1_sa->sa_b ){

				ikemesg->v1_sa_b = ikepayload->ext.v1_sa->sa_b;
			}
    }

    ikemesg->put_payload(ikemesg,ikepayload);

    next_payload = ikepayload->get_next_payload(ikepayload);
  }

  if( pkt->data != pkt->tail ){

  	RHP_TRC(0,RHPTRCID_IKEV1_NEW_MESG_RX_INVALID_MESG_7,"x",pkt);
    err = RHP_STATUS_INVALID_MSG;
    suberr = RHP_STATUS_INVALID_IKEV2_MESG_INVALID_PAYLOAD;

    goto error;
  }

  ikemesg->dump_payloads(ikemesg);

  *ikemesg_r = ikemesg;

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_MESG_RX_RTRN,"xx",pkt,ikemesg);

  return 0;

error:
	if( pkt->type == RHP_PKT_IPV4_IKE ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKEV1_PARSE_RX_MESG_ERR,"P44WWEE",ikesa,(pkt->l3.raw ? pkt->l3.iph_v4->src_addr : 0),(pkt->l3.raw ? pkt->l3.iph_v4->dst_addr : 0),(pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt->l4.raw ? pkt->l4.udph->dst_port : 0),err,suberr);
	}else	if( pkt->type == RHP_PKT_IPV6_IKE ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKEV1_PARSE_RX_MESG_ERR_V6,"P66WWEE",ikesa,(pkt->l3.raw ? pkt->l3.iph_v6->src_addr : NULL),(pkt->l3.raw ? pkt->l3.iph_v6->dst_addr : NULL),(pkt->l4.raw ? pkt->l4.udph->src_port : 0),(pkt->l4.raw ? pkt->l4.udph->dst_port : 0),err,suberr);
	}

	if( ikemesg ){
    rhp_ikev2_unhold_mesg(ikemesg);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_MESG_RX_ERR,"xEE",pkt,err,suberr);
  return err;
}

rhp_ikev2_mesg* rhp_ikev2_new_mesg_tx(u8 exchange_type,u32 message_id/*For response*/,u8 flag)
{
  rhp_proto_ike* ikeh;
  rhp_ikev2_mesg* ikemesg;

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_MESG_TX,"Lbub","PROTO_IKE_EXCHG",exchange_type,message_id,flag);

  ikemesg = _rhp_ikev2_alloc_mesg(RHP_TRUE);
  if( ikemesg == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  ikeh = ikemesg->tx_ikeh;

  ikeh->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
  ikeh->ver_major = RHP_PROTO_IKE_VER_MAJOR;
  ikeh->ver_minor = RHP_PROTO_IKE_VER_MINOR;
  ikeh->exchange_type = exchange_type;
  ikeh->flag = flag;
  ikeh->message_id = htonl(message_id);
  ikemesg->tx_mesg_len = sizeof(rhp_proto_ike);

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_MESG_TX_RTRN,"xLbu",ikemesg,"PROTO_IKE_EXCHG",exchange_type,message_id);
  return ikemesg;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_NEW_MESG_TX_ERR,"x",ikemesg);
  return NULL;
}

rhp_ikev2_mesg* rhp_ikev1_new_mesg_tx(u8 exchange_type,u32 message_id/*For response*/,u8 flag)
{
  rhp_proto_ike* ikeh;
  rhp_ikev2_mesg* ikemesg;

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_MESG_TX,"Lbub","PROTO_IKE_EXCHG",exchange_type,message_id,flag);

  ikemesg = _rhp_ikev2_alloc_mesg(RHP_TRUE);
  if( ikemesg == NULL ){
  	RHP_BUG("");
  	goto error;
  }

	ikemesg->is_v1 = 1;

  ikeh = ikemesg->tx_ikeh;

  ikeh->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
  ikeh->ver_major = RHP_PROTO_IKE_V1_VER_MAJOR;
  ikeh->ver_minor = RHP_PROTO_IKE_V1_VER_MINOR;
  ikeh->exchange_type = exchange_type;
  ikeh->flag = flag;
  ikeh->message_id = htonl(message_id);
  ikemesg->tx_mesg_len = sizeof(rhp_proto_ike);

  RHP_TRC(0,RHPTRCID_IKEV1_NEW_MESG_TX_RTRN,"xLbu",ikemesg,"PROTO_IKE_EXCHG",exchange_type,message_id);
  return ikemesg;

error:
  RHP_TRC(0,RHPTRCID_IKEV1_NEW_MESG_TX_ERR,"x",ikemesg);
  return NULL;
}
