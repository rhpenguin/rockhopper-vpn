/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifndef _RHP_PACKET_H_
#define _RHP_PACKET_H_

#include "rhp_protocol.h"

#define RHP_PKT_HEADER_ROOM   128  // >= ( struct tun_pi + IP/IPv6 header + ESP header + IV(AES:16bytes) + EtherIP/GRE header )
#define RHP_PKT_TAIL_ROOM     128  // >= ( ESP Trailer + ICV(HMAC-96:12bytes) )

//#define RHP_PKT_ICMP_EXT_ERR_LEN    (sizeof(struct sock_extended_err) + sizeof(struct sockaddr_in))
//#define RHP_PKT_ICMP_TOTAL_ERR_LEN  (RHP_PKT_ICMP_EXT_ERR_LEN + sizeof(struct sockaddr_in))

#define RHP_PKT_IKE_DEFAULT_HDRS_SIZE (sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v6) + RHP_PROTO_NON_ESP_MARKER_SZ + sizeof(rhp_proto_udp) + sizeof(rhp_proto_ike))
#define RHP_PKT_IKE_DEFAULT_SIZE  		(RHP_PKT_IKE_DEFAULT_HDRS_SIZE + 1024)

extern rhp_mutex_t rhp_pkt_lock_statistics;
extern u64 rhp_pkt_statistics_alloc_no_pool;
extern u64 rhp_pkt_statistics_alloc_large_pkt;


struct _rhp_vpn;
#ifndef rhp_vpn_ref
#ifdef RHP_REFCNT_DEBUG_X
typedef struct _rhp_refcnt_dbg	rhp_vpn_ref;
#else // RHP_REFCNT_DEBUG_X
typedef struct _rhp_vpn	rhp_vpn_ref;
#endif // RHP_REFCNT_DEBUG_X
#endif // rhp_vpn_ref

struct _rhp_ikev2_mesg;
struct _rhp_packet;

struct _rhp_packet_frag {

  char tag[4]; // "#PFR"

	struct _rhp_packet_frag* next;

  int  len;          // Length of data -- tail.
  int  buffer_len;   // Length of end - head.
  u8* head;
  u8* data;
  u8* tail;
  u8* end;

  union {
    rhp_proto_ether* eth;
    u8* raw;
  } l2;

  union {
    rhp_proto_ip_v4* iph_v4;
    rhp_proto_ip_v6* iph_v6;
    u8* raw;
  } l3;

  union{
    rhp_proto_udp*  	udph;
    rhp_proto_tcp*  	tcph;
    rhp_proto_sctp* 	sctph;
    rhp_proto_icmp* 	icmph;
    rhp_proto_icmp6* 	icmp6h;
    u8* raw;
  } l4;

  union{
    rhp_proto_ike* ikeh;
    rhp_proto_esp* esph;
    u8* raw;
  } app;

  int ikev2_non_esp_marker;
};
typedef struct _rhp_packet_frag rhp_packet_frag;

extern rhp_packet_frag* rhp_pkt_frag_alloc(int len,int head_room_len,int tail_room_len);
extern int rhp_pkt_frag_realloc(rhp_packet_frag* origfrag,int head_room_len,int tail_room_len);
extern void rhp_pkt_frag_free(rhp_packet_frag* pktfrag);
extern rhp_packet_frag* rhp_pkt_frag_dup(rhp_packet_frag* origfrag);

extern u8* rhp_pkt_frag_expand_tail(rhp_packet_frag* origfrag,int tail_room_len);

extern void rhp_pkt_frag_trace_dump(char* label,rhp_packet_frag* pktfrag);
extern void rhp_pkt_frags_trace_dump(char* label,struct _rhp_packet* pkt);


static inline u8* _rhp_pkt_frag_push(rhp_packet_frag* pktfrag,int len)
{
  u8* cur = pktfrag->tail;

  if( pktfrag->tail + len > pktfrag->end ){
#ifdef RHP_PKT_DEBUG
  	RHP_TRCSTR(0,"_rhp_pkt_frag_push Err: pktfrag: 0x%lx, pktfrag->tail: 0x%lx, len: %d, pktfrag->end: 0x%lx",pktfrag,pktfrag->tail,len,pktfrag->end);
#endif // RHP_PKT_DEBUG
    return NULL;
  }

  pktfrag->tail += len;
  pktfrag->len  += len;

  return cur;
}


static inline u8* _rhp_pkt_frag_trim(rhp_packet_frag* pktfrag,int len)
{
  u8* cur = pktfrag->tail;
  if( pktfrag->tail - len < pktfrag->data ){
#ifdef RHP_PKT_DEBUG
  	RHP_TRCSTR(0,"_rhp_pkt_frag_trim Err: pktfrag: 0x%lx, pktfrag->tail: 0x%lx, len: %d, pktfrag->data: 0x%lx",pktfrag,pktfrag->tail,len,pktfrag->data);
#endif // RHP_PKT_DEBUG
    return NULL;
  }
  pktfrag->tail -= len;
  pktfrag->len  -= len;
  return cur;
}


struct _rhp_packet {

  char tag[4]; // "#RPK"

  struct _rhp_packet* next;
  rhp_atomic_t refcnt;

#define RHP_PKT_IPV4_IKE        						0
#define RHP_PKT_IPV6_IKE 		 								1
#define RHP_PKT_IPV4_ESP  		 							2
#define RHP_PKT_IPV6_ESP		 								3
#define RHP_PKT_IPV4_ESP_NAT_T  						4
#define RHP_PKT_IPV6_ESP_NAT_T  						5
#define RHP_PKT_PLAIN_ETHER_TAP							6 // TUN/TAP device ==> TAP mode
#define RHP_PKT_PLAIN_IPV4_TUNNEL						7 // TUN/TAP device ==> TUNNEL mode
#define RHP_PKT_PLAIN_IPV6_TUNNEL						8 // TUN/TAP device ==> TUNNEL mode
#define RHP_PKT_PLAIN_IPV4_ESP_DUMMY				9
#define RHP_PKT_PLAIN_IPV6_ESP_DUMMY				10
#define RHP_PKT_IPV4_DNS										11
#define RHP_PKT_IPV6_DNS										12
#define RHP_PKT_IPV4_RADIUS									13
#define RHP_PKT_IPV6_RADIUS									14
#define RHP_PKT_GRE_NHRP										15
  int type;

  int  len;          // Length of data -- tail.
  int  buffer_len;   // Length of end - head.
  u8* head;
  u8* data;
  u8* tail;
  u8* end;

  union {
    rhp_proto_ether* eth;
    u8* raw;
  } l2;

  union {
    rhp_proto_ip_v4* iph_v4;
    rhp_proto_ip_v6* iph_v6;
    rhp_proto_gre*	 nhrp_greh;
    u8* raw;
  } l3;

  union{
    rhp_proto_udp*  	udph;
    rhp_proto_tcp*  	tcph;
    rhp_proto_sctp* 	sctph;
    rhp_proto_icmp* 	icmph;
    rhp_proto_icmp6* 	icmp6h;
    rhp_proto_nhrp* 	nhrph;
    u8* raw;
  } l4;

  union{
    rhp_proto_ike* ikeh;
    rhp_proto_esp* esph;
    u8* raw;
  } app;

  rhp_ifc_entry *tx_ifc;
  int fixed_tx_if_index;

  int rx_if_index;
  rhp_ifc_entry *rx_ifc;

  void (*destructor)(struct _rhp_packet* pkt);

  int encap_mode;

  rhp_vpn_ref* esp_tx_vpn_ref;
  rhp_vpn_ref* esp_rx_vpn_ref;
  u64 esp_seq;
  u32 esp_tx_spi_outb;
  u32 esp_rx_spi_inb;


  void (*process_packet)(struct _rhp_packet* pkt);

  u64 dmy_pkt_esp_tx_seq;

  void* esp_pkt_pend_done_ctx;
  int (*esp_pkt_pend_done)(struct _rhp_packet* pkt);

  int cookie_checked;
  struct _rhp_ikev2_mesg* cookie_checked_rx_mesg;

  int nat_t_keep_alive;
  int ikev2_keep_alive;
  int mobike_verified;

#if defined(RHP_PKT_DBG_IKEV2_RETRANS_TEST) || defined(RHP_PKT_DBG_IKEV2_RETRANS_FRAG_TEST)
#define RHP_PKT_IKEV2_RETRANS_NONE	0
#define RHP_PKT_IKEV2_RETRANS_REQ		1
#define RHP_PKT_IKEV2_RETRANS_REP		2
  int ikev2_retrans_pkt;
#endif // RHP_PKT_DBG_IKEV2_RETRANS_TEST || RHP_PKT_DBG_IKEV2_RETRANS_FRAG_TEST

  int is_critical;

  int v6_rlm_lladdr;

  int ikev2_non_esp_marker;

  struct {

  	int frags_num;

  	rhp_packet_frag* head; // 2nd fragment...
		rhp_packet_frag* tail;

  } frags;

  struct {

  	int nbma_addr_family;

  	u8* nbma_src_addr;
  	u8* nbma_dst_addr;

  } nhrp;

  u8 dmvpn_enabled;
  u8 ikev2_exchange_type;
  u8 v1_mode_cfg_pending;
  u8 pcaped;

  u8* ikev1_pkt_hash;
  int ikev1_pkt_hash_len;

  void* priv;
};
typedef struct _rhp_packet rhp_packet;


struct _rhp_pkt_or_frag {

	int is_frag;

	union {
		void* raw;
		rhp_packet* pkt;
		rhp_packet_frag* frag;
	} d;
};
typedef struct _rhp_pkt_or_frag rhp_pkt_or_frag;


static inline void _rhp_pkt_frag_enq(rhp_packet* pkt,rhp_packet_frag* pktfrag)
{
	pktfrag->next = NULL;
  if( pkt->frags.head == NULL ){
  	pkt->frags.head = pktfrag;
  }else{
  	pkt->frags.tail->next = pktfrag;
  }
  pkt->frags.tail = pktfrag;
  pkt->frags.frags_num++;
}


struct _rhp_packet_q {
  rhp_packet* head;
  rhp_packet* tail;
};
typedef struct _rhp_packet_q  rhp_packet_q;

static inline void _rhp_pkt_q_init(rhp_packet_q* pkt_q)
{
  pkt_q->head = NULL;
  pkt_q->tail = NULL;
}

// Caller must hold pkt by rhp_pkt_hold().
static inline void _rhp_pkt_q_enq(rhp_packet_q* pkt_q,rhp_packet* pkt)
{
  pkt->next = NULL;
  if( pkt_q->head == NULL ){
    pkt_q->head = pkt;
  }else{
    pkt_q->tail->next = pkt;
  }
  pkt_q->tail = pkt;
}

static inline rhp_packet* _rhp_pkt_q_peek(rhp_packet_q* pkt_q)
{
  return pkt_q->head;
}

static inline void _rhp_pkt_q_insert(rhp_packet_q* pkt_q,rhp_packet* pkt,
		int (*pos_cb)(rhp_packet_q* pkt_q_cb,rhp_packet* pkt_cur,rhp_packet* pkt_new))
{
  rhp_packet *pkt_w = pkt_q->head, *pkt_w_p = NULL;

  while( pkt_w ){

  	if( pos_cb(pkt_q,pkt_w,pkt) ){
  		break;
  	}

  	pkt_w_p = pkt_w;
  	pkt_w = pkt_w->next;
  }

	if( pkt_q->tail == pkt_w_p ){
		pkt_q->tail = pkt;
	}

	if( pkt_w_p ){

		pkt->next = pkt_w_p->next;
		pkt_w_p->next = pkt;

	}else{

		pkt->next = pkt_q->head;
		pkt_q->head = pkt;
	}

	return;
}


static inline rhp_packet* _rhp_pkt_q_deq(rhp_packet_q* pkt_q)
{
  rhp_packet* pkt = pkt_q->head;
  if( pkt ){
    pkt_q->head = pkt->next;
    if( pkt == pkt_q->tail ){
      pkt_q->tail = NULL;
    }
    pkt->next = NULL;
  }
  return pkt;
}


static inline u8* _rhp_pkt_pull(rhp_packet* packet,int len)
{
  u8* cur = packet->data;
  if( packet->data + len > packet->tail ){
#ifdef RHP_PKT_DEBUG
  	RHP_TRCSTR(0,"_rhp_pkt_pull Err: packet: 0x%lx, packet->data: 0x%lx, len: %d, packet->tail: 0x%lx",packet,packet->data,len,packet->tail);
#endif // RHP_PKT_DEBUG
    return NULL;
  }
  packet->data += len;
  packet->len  -= len;
  return cur;
}

static inline int _rhp_pkt_try_pull(rhp_packet* packet,int len)
{
  if( packet->data + len > packet->tail ){
#ifdef RHP_PKT_DEBUG
  	RHP_TRCSTR(0,"_rhp_pkt_try_pull Err: packet: 0x%lx, packet->data: 0x%lx, len: %d, packet->tail: 0x%lx",packet,packet->data,len,packet->tail);
#endif // RHP_PKT_DEBUG
    return -1;
  }
  return 0;
}

static inline u8* _rhp_pkt_push(rhp_packet* packet,int len)
{
  u8* cur = packet->tail;

  if( packet->tail + len > packet->end ){
#ifdef RHP_PKT_DEBUG
  	RHP_TRCSTR(0,"_rhp_pkt_push Err: packet: 0x%lx, packet->tail: 0x%lx, len: %d, packet->end: 0x%lx",packet,packet->tail,len,packet->end);
#endif // RHP_PKT_DEBUG
    return NULL;
  }

  packet->tail += len;
  packet->len  += len;

  return cur;
}

static inline u8* _rhp_pkt_try_push(rhp_packet* packet,int len)
{
  if( packet->tail + len > packet->end ){
#ifdef RHP_PKT_DEBUG
  	RHP_TRCSTR(0,"_rhp_pkt_try_push Err: packet: 0x%lx, packet->tail: 0x%lx, len: %d, packet->end: 0x%lx",packet,packet->tail,len,packet->end);
#endif // RHP_PKT_DEBUG
    return NULL;
  }
  return packet->tail;
}

static inline u8* _rhp_pkt_trim(rhp_packet* packet,int len)
{
  u8* cur = packet->tail;
  if( packet->tail - len < packet->data ){
#ifdef RHP_PKT_DEBUG
  	RHP_TRCSTR(0,"_rhp_pkt_trim Err: packet: 0x%lx, packet->tail: 0x%lx, len: %d, packet->data: 0x%lx",packet,packet->tail,len,packet->data);
#endif // RHP_PKT_DEBUG
    return NULL;
  }
  packet->tail -= len;
  packet->len  -= len;
  return cur;
}



#ifndef RHP_REFCNT_DEBUG
typedef struct _rhp_packet	rhp_packet_ref;
#define RHP_PKT_REF(pkt_or_pkt_ref) ((rhp_packet*)(pkt_or_pkt_ref))
#else // RHP_REFCNT_DEBUG

#ifndef RHP_REFCNT_DEBUG_X
typedef struct _rhp_packet	rhp_packet_ref;
#define RHP_PKT_REF(pkt_or_pkt_ref) ((rhp_packet*)(pkt_or_pkt_ref))
#else // RHP_REFCNT_DEBUG_X
struct _rhp_refcnt_dbg;
typedef struct _rhp_refcnt_dbg	rhp_packet_ref;
#define RHP_PKT_REF(pkt_or_pkt_ref) ((rhp_packet*)RHP_REFCNT_OBJ((pkt_or_pkt_ref)))
#endif // RHP_REFCNT_DEBUG_X

#endif // RHP_REFCNT_DEBUG

extern void rhp_pkt_hold(rhp_packet* pkt);
/*
  rhp_pkt_hold_ref() to debug a rhp_packet's refcnt. Also, see rhp_vpn_hold_ref()[rhp_vpn.h].
*/
extern rhp_packet_ref* rhp_pkt_hold_ref(rhp_packet* pkt);
extern void rhp_pkt_unhold(void* pkt);

extern void rhp_pkt_pending(rhp_packet* pkt);


extern rhp_packet* rhp_pkt_alloc(int len);
extern int rhp_pkt_realloc(rhp_packet* origpkt,int header_room_len,int tail_room_len);
extern rhp_packet* rhp_pkt_dup(rhp_packet* origpkt);

extern u8* rhp_pkt_expand_tail(rhp_packet* origpkt,int tail_room_len);
extern u8* rhp_pkt_expand_head(rhp_packet* origpkt,int head_room_len);

extern int rhp_pkt_get_pool_cur_num();

extern void rhp_pkt_trace_dump(char* label,rhp_packet* pkt);



extern int rhp_is_critical_pkt(rhp_packet* pkt);


extern int rhp_pkt_ipv4_set_addrs(rhp_packet* pkt,u32 src_addr,u32 dst_addr);
extern int rhp_pkt_ipv6_set_addrs(rhp_packet* pkt,u8* src_addr,u8* dst_addr);

extern int rhp_pkt_ipv4_set_addrs_udp_ports(rhp_packet* pkt,u32 src_addr,u32 dst_addr,u16 src_port,u16 dst_port);
extern int rhp_pkt_ipv6_set_addrs_udp_ports(rhp_packet* pkt,u8* src_addr,u8* dst_addr,u16 src_port,u16 dst_port);


extern int rhp_pkt_rebuild_ip_udp_header(rhp_packet* pkt,
		int addr_family,u8* src_addr,u8* dst_addr,u16 src_port,u16 dst_port);

#endif // _RHP_PACKET_H_




