/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifndef _RHP_PROTOCOL_H_
#define _RHP_PROTOCOL_H_

#pragma pack(1)

struct _rhp_proto_ether
{

  u8  dst_addr[6];
  u8  src_addr[6];

#ifdef RHP_BIG_ENDIAN
#define RHP_PROTO_ETH_IP        			0x0800
#define RHP_PROTO_ETH_IPV6      			0x86DD
#define RHP_PROTO_ETH_ARP       			0x0806
#define RHP_PROTO_ETH_NHRP		   			0x2001
#define RHP_PROTO_ETH_RARP      			0x8035
//#define RHP_PROTO_ETH_8021Q     		0x8100
#define RHP_PROTO_ETH_PPP_DISC  			0x8863
#define RHP_PROTO_ETH_PPP_SES   			0x8864
#else // RHP_BIG_ENDIAN
#define RHP_PROTO_ETH_IP        			0x0008
#define RHP_PROTO_ETH_IPV6      			0xDD86
#define RHP_PROTO_ETH_ARP       			0x0608
#define RHP_PROTO_ETH_NHRP		   			0x0120 // Not official number?
#define RHP_PROTO_ETH_RARP      			0x3580
//#define RHP_PROTO_ETH_8021Q     		0x0081
#define RHP_PROTO_ETH_PPP_DISC				0x6388
#define RHP_PROTO_ETH_PPP_SES   			0x6488
#endif // RHP_BIG_ENDIAN
  u16 protocol; // ether_type
};
typedef struct _rhp_proto_ether rhp_proto_ether;

#define RHP_PROTO_ETHER_BROADCAST_DST(eth)	 	( (*((u32*)(eth)->dst_addr) == 0xFFFFFFFF) && (*((u16*)&((eth)->dst_addr[4])) == 0xFFFF) )
#define RHP_PROTO_ETHER_MULTICAST_DST(eth) 		( ((eth)->dst_addr[0] & 0x01) )
#define RHP_PROTO_ETHER_BROADCAST_SRC(eth) 		( (*((u32*)(eth)->src_addr) == 0xFFFFFFFF) && (*((u16*)&((eth)->src_addr[4])) == 0xFFFF) )
#define RHP_PROTO_ETHER_MULTICAST_SRC(eth) 		( ((eth)->src_addr[0] & 0x01) )

/*
struct _rhp_proto_802_1q
{
	u16 tpid;
	u16 tci;
};
typedef struct _rhp_proto_802_1q rhp_proto_802_1q;
*/

struct _rhp_proto_arp
{

#ifdef RHP_BIG_ENDIAN
#define RHP_PROTO_ARP_HW_TYPE_ETHER	0x0001
#else
#define RHP_PROTO_ARP_HW_TYPE_ETHER	0x0100
#endif
	u16 hw_type;
	u16 proto_type;
	u8 hw_len;
	u8 proto_len;

#ifdef RHP_BIG_ENDIAN
#define RHP_PROTO_ARP_OPR_REQUEST			0x0001
#define RHP_PROTO_ARP_OPR_REPLY				0x0002
#else
#define RHP_PROTO_ARP_OPR_REQUEST			0x0100
#define RHP_PROTO_ARP_OPR_REPLY				0x0200
#endif
	u16 operation;

  u8 sender_mac[6];
  u32 sender_ipv4;
  u8 	target_mac[6];
  u32 target_ipv4;
};
typedef struct _rhp_proto_arp rhp_proto_arp;


struct _rhp_proto_ip_v4
{

#ifdef RHP_BIG_ENDIAN_BF
	u8 ver:4, ihl:4;
#else
	u8 ihl:4, ver:4;
#endif

  u8 tos;

  u16 total_len;
  u16 id;

#ifdef RHP_BIG_ENDIAN
#define RHP_PROTO_IP_DONTFLAG_MASK  0x4000
#define RHP_PROTO_IP_MOREFLAG_MASK  0x2000
#else
#define RHP_PROTO_IP_DONTFLAG_MASK  0x0040
#define RHP_PROTO_IP_MOREFLAG_MASK  0x0020
#endif
#define RHP_PROTO_IP_FRAG_OFFSET_MASK  0x1FFF

#define RHP_PROTO_IP_FRAG_DF(frag)       ((frag) & RHP_PROTO_IP_DONTFLAG_MASK)
#define RHP_PROTO_IP_FRAG_MF(frag)       ((frag) & RHP_PROTO_IP_MOREFLAG_MASK)
#define RHP_PROTO_IP_FRAG_OFFSET(frag)   (ntohs(frag) & RHP_PROTO_IP_FRAG_OFFSET_MASK)
  u16 frag;

  u8  ttl;

#define RHP_PROTO_IP_IPV6_HOP_BY_HOP     	0 // IPv6 ExtHdr
#define RHP_PROTO_IP_ICMP     						1
#define RHP_PROTO_IP_IP		     						4
#define RHP_PROTO_IP_UDP      						17
#define RHP_PROTO_IP_TCP      						6
#define RHP_PROTO_IP_IPV6	     						41
#define RHP_PROTO_IP_IPV6_ROUTE	     			43 // IPv6 ExtHdr
#define RHP_PROTO_IP_IPV6_FRAG	     			44 // IPv6 ExtHdr
#define RHP_PROTO_IP_GRE      						47
#define RHP_PROTO_IP_ESP      						50 // IPv6 ExtHdr
#define RHP_PROTO_IP_AH       						51 // IPv6 ExtHdr
#define RHP_PROTO_IP_IPV6_ICMP	     			58
#define RHP_PROTO_IP_NO_NEXT_HDR					59 // IPv6 ExtHdr
#define RHP_PROTO_IP_IPV6_OPTS	     			60 // IPv6 ExtHdr
#define RHP_PROTO_IP_OSPF									89
#define RHP_PROTO_IP_ETHERIP  						97
#define RHP_PROTO_IP_IPCOMP	  						108
#define RHP_PROTO_IP_L2TP     						115
#define RHP_PROTO_IP_SCTP     						132
#define RHP_PROTO_IP_MOBILITY_HDR	     		135
#define RHP_PROTO_IP_UDPLITE  						136
#define RHP_PROTO_IP_IPV6_SHIM6						140 // IPv6 ExtHdr
#define RHP_PROTO_IP_IPV6_HIP							139 // IPv6 ExtHdr
  u8  protocol;
  u16 check_sum;
  u32 src_addr;
  u32 dst_addr;
};
typedef struct _rhp_proto_ip_v4 rhp_proto_ip_v4;


static inline u16 _rhp_proto_ip_v4_set_csum(rhp_proto_ip_v4* ipv4h)
{
	int len = ipv4h->ihl*2;
	int i;
	u32 csum = 0;
	u16* buf = (u16*)ipv4h;
	u32 cr;

	ipv4h->check_sum = 0;

	for( i = 0; i < len;i++){
		csum += *buf;
		buf++;
	}

	while( (cr = ((csum >> 16) & 0x0000FFFF)) ){
		csum = (csum & 0x0000FFFF) + cr;
	}

	ipv4h->check_sum = (u16)(~csum);
	return ipv4h->check_sum;
}

static inline int _rhp_proto_ip_v4_dec_ttl(rhp_proto_ip_v4* ipv4h)
{
	u32 csum;

	if( ipv4h->ttl <= 1 ){
		return -1;
	}

	csum = (u32)(ipv4h->check_sum);

	// From [RFC1624]
	//
	// HC' = ~(C + (-m) + m')    --    [Eqn. 3]
	//     = ~(~HC + ~m + m')
	//
	// (-m) + m' is always '1' for TTL decrement.

	csum += (u32)htons(0x0100);

	if( csum >= 0xFFFF ){
		ipv4h->check_sum	= (u16)(csum + 1);
	}else{
		ipv4h->check_sum	= (u16)csum;
	}

	ipv4h->ttl--;

	return 0;
}



struct _rhp_proto_ip_v6 {

#ifdef RHP_BIG_ENDIAN_BF
	u8 ver:4, priority:4;
#else
	u8 priority:4, ver:4;
#endif

#define RHP_IPV6_TC(ip6h) 				( ((u8)((ip6h)->priority) << 4) | ((ip6h)->flow_label[0] >> 4) )
#define RHP_IPV6_FLOW_LABEL(ip6h) ( (((u32)(((ip6h)->flow_label[0]) & 0x0F)) << 16) | (((u32)((ip6h)->flow_label[1])) << 8) | ((u32)((ip6h)->flow_label[0])) )

  u8 flow_label[3];

  u16 payload_len;
  u8 next_header;
  u8 hop_limit;

  u8 src_addr[16];
  u8 dst_addr[16];
};
typedef struct _rhp_proto_ip_v6 rhp_proto_ip_v6;

#define RHP_IPV6_MSCOPE_UNKNOWN				0x0
#define RHP_IPV6_MSCOPE_IF_LOCAL			0x1
#define RHP_IPV6_MSCOPE_LINK_LOCAL		0x2
#define RHP_IPV6_MSCOPE_ADMIN_LOCAL		0x4
#define RHP_IPV6_MSCOPE_SITE_LOCAL		0x5
#define RHP_IPV6_MSCOPE_ORG_LOCAL			0x8
#define RHP_IPV6_MSCOPE_GLOBAL				0xE

extern u8* rhp_proto_ip_v6_upper_layer(rhp_proto_ip_v6* ip6h,u8* end,
		int protos_num,u8* protos,u8* proto_r);
extern int rhp_proto_ip_v6_frag(rhp_proto_ip_v6* ip6h,u8* end,u8* proto_r,u8** frag_data);

/*

  - Hop-by-Hop Options Header
  - Routing Header
  - Destination Options
  - SHIM6
  - HIP

  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  Next Header  |  Hdr Ext Len  |                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
  |                                                               |
  .                           Ext Data                            .
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


  - Fragment Header

  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  Next Header  |   Reserved    |      Fragment Offset    |Res|M|
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                         Identification                        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


  - Authentication Header Format

  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 | Next Header   |  Payload Len  |          RESERVED             |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                 Security Parameters Index (SPI)               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Sequence Number Field                      |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                                                               |
 +                Authentication Data (variable)                 |
 |                                                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


  - Encapsulating Security Payload Packet Format

  0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ----
 |               Security Parameters Index (SPI)                 | ^Auth.
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
 |                      Sequence Number                          | |erage
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | ----
 |                    Payload Data* (variable)                   | |   ^
 ~                                                               ~ |   |
 |                                                               | |Conf.
 +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
 |               |     Padding (0-255 bytes)                     | |erage*
 +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |   |
 |                               |  Pad Length   | Next Header   | v   v
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ------
 |                 Authentication Data (variable)                |
 ~                                                               ~
 |                                                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

struct _rhp_proto_ip_v6_exthdr {
	u8 next_header;
	u8 len; // In 8 byte-units, excluding the first 8 bytes.
};
typedef struct _rhp_proto_ip_v6_exthdr	rhp_proto_ip_v6_exthdr;


struct _rhp_proto_ip_v6_fraghdr {
	u8 next_header;
	u8 reserved0;
#ifdef RHP_BIG_ENDIAN_BF
	u16 offset:13, reserved1:2, mflag:1;
#else
	u16 mflag:1, reserved1:2, offset:13;
#endif
	u32 id;
};
typedef struct _rhp_proto_ip_v6_fraghdr	rhp_proto_ip_v6_fraghdr;



struct _rhp_proto_etherip {

#define RHP_PROTO_ETHERIP_VER					3
#define RHP_PROTO_ETHERIP_RESERVED		0
#ifdef RHP_BIG_ENDIAN_BF
	u8 ver:4, reserved:4;
#else
	u8 reserved:4, ver:4;
#endif

  u8 reserved1;
};
typedef struct _rhp_proto_etherip rhp_proto_etherip;



struct _rhp_proto_gre {

#define RHP_PROTO_GRE_VERSION		0

#ifdef RHP_BIG_ENDIAN_BF
	u8 check_sum_flag:1, reserved_flag0:1, key_flag:1, seq_flag:1, reserved_flag1:4;
	u8 reserved_flag2:5, ver:3;
#else
	u8 reserved_flag1:4, seq_flag:1, key_flag:1, reserved_flag0:1, check_sum_flag:1;
	u8 ver:3, reserved_flag2:5;
#endif

	u16 protocol_type; // ether_type
};
typedef struct _rhp_proto_gre rhp_proto_gre;


struct _rhp_proto_gre_csum {

#ifdef RHP_BIG_ENDIAN_BF
	u8 check_sum_flag:1, reserved:7;
	u8 reserved0:5, ver:3;
#else
	u8 reserved:7, check_sum_flag:1;
	u8 ver:3, reserved0:5;
#endif

	u16 protocol_type; // ether_type

	u16 check_sum;
	u16 reserved1;
};
typedef struct _rhp_proto_gre_csum rhp_proto_gre_csum;



/*

 [RFC2332] NBMA Next Hop Resolution Protocol (NHRP)

 5.1 NHRP Fixed Header

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            ar$afn             |          ar$pro.type          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          ar$pro.snap                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  ar$pro.snap  |   ar$hopcnt   |            ar$pktsz           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           ar$chksum           |            ar$extoff          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | ar$op.version |   ar$op.type  |    ar$shtl    |    ar$sstl    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


   ar$afn
     Defines the type of "link layer" addresses being carried.  This
     number is taken from the 'address family number' list specified in
     [6].  This field has implications to the coding of ar$shtl and
     ar$sstl as described below.

   ar$pro.type
     field is a 16 bit unsigned integer representing the following
     number space:

       0x0000 to 0x00FF  Protocols defined by the equivalent NLPIDs.
       0x0100 to 0x03FF  Reserved for future use by the IETF.
       0x0400 to 0x04FF  Allocated for use by the ATM Forum.
       0x0500 to 0x05FF  Experimental/Local use.
       0x0600 to 0xFFFF  Protocols defined by the equivalent Ethertypes.

     (based on the observations that valid Ethertypes are never smaller
     than 0x600, and NLPIDs never larger than 0xFF.)

   ar$pro.snap
     When ar$pro.type has a value of 0x0080, a SNAP encoded extension is
     being used to encode the protocol type. This snap extension is
     placed in the ar$pro.snap field.  This is termed the 'long form'
     protocol ID. If ar$pro != 0x0080 then the ar$pro.snap field MUST be
     zero on transmit and ignored on receive. The ar$pro.type field
     itself identifies the protocol being referred to. This is termed
     the 'short form' protocol ID.

     In all cases, where a protocol has an assigned number in the
     ar$pro.type space (excluding 0x0080) the short form MUST be used
     when transmitting NHRP messages; i.e., if Ethertype or NLPID
     codings exist then they are used on transmit rather than the
     ethertype.   If both Ethertype and NLPID codings exist then when
     transmitting NHRP messages, the Ethertype coding MUST be used (this
     is consistent with RFC 1483 coding).  So, for example, the
     following codings exist for IP:

       SNAP:      ar$pro.type = 0x00-80, ar$pro.snap = 0x00-00-00-08-00
       NLPID:     ar$pro.type = 0x00-CC, ar$pro.snap = 0x00-00-00-00-00
       Ethertype: ar$pro.type = 0x08-00, ar$pro.snap = 0x00-00-00-00-00

     and thus, since the Ethertype coding exists, it is used in
     preference.

   ar$hopcnt
     The Hop count indicates the maximum number of NHSs that an NHRP
     packet is allowed to traverse before being discarded.  This field
     is used in a similar fashion to the way that a TTL is used in an IP
     packet and should be set accordingly.  Each NHS decrements the TTL
     as the NHRP packet transits the NHS on the way to the next hop
     along the routed path to the destination.  If an NHS receives an
     NHRP packet which it would normally forward to a next hop and that
     packet contains an ar$hopcnt set to zero then the NHS sends an
     error indication message back to the source protocol address
     stating that the hop count has been exceeded (see Section 5.2.7)
     and the NHS drops the packet in error;  however, an error
     indication is never sent as a result of receiving an error
     indication.  When a responding NHS replies to an NHRP request, that
     NHS places a value in ar$hopcnt as if it were sending a request of
     its own.

   ar$pktsz
     The total length of the NHRP packet, in octets (excluding link
     layer encapsulation).

   ar$chksum
     The standard IP checksum over the entire NHRP packet starting at
     the fixed header.  If the packet is an odd number of bytes in
     length then this calculation is performed as if a byte set to 0x00
     is appended to the end of the packet.

   ar$extoff
     This field identifies the existence and location of NHRP
     extensions.  If this field is 0 then no extensions exist otherwise
     this field represents the offset from the beginning of the NHRP
     packet (i.e., starting from the ar$afn field) of the first
     extension.

   ar$op.version
     This field indicates what version of generic address mapping and
     management protocol is represented by this message.

       0               MARS protocol [11].
       1               NHRP as defined in this document.
       0x02 - 0xEF     Reserved for future use by the IETF.
       0xF0 - 0xFE     Allocated for use by the ATM Forum.
       0xFF            Experimental/Local use.

   ar$op.type
     When ar$op.version == 1, this is the NHRP packet type: NHRP
     Resolution Request(1), NHRP Resolution Reply(2), NHRP Registration
     Request(3), NHRP Registration Reply(4), NHRP Purge Request(5), NHRP
     Purge Reply(6), or NHRP Error Indication(7).  Use of NHRP packet
     Types in the range 128 to 255 are reserved for research or use in
     other protocol development and will be administered by IANA as
     described in Section 9.

   ar$shtl
     Type & length of source NBMA address interpreted in the context of
     the 'address family number'[6] indicated by ar$afn.  See below for
     more details.

   ar$sstl
     Type & length of source NBMA subaddress interpreted in the context
     of the 'address family number'[6] indicated by ar$afn.  When an
     NBMA technology has no concept of a subaddress, the subaddress
     length is always coded ar$sstl = 0 and no storage is allocated for
     the subaddress in the appropriate mandatory part.  See below for
     more details.
*/
struct _rhp_proto_nhrp_fixed {

#ifdef RHP_BIG_ENDIAN_BF
#define RHP_PROTO_NHRP_ADDR_FAMILY_IPV4		0x0001
#define RHP_PROTO_NHRP_ADDR_FAMILY_IPV6		0x0002
#else
#define RHP_PROTO_NHRP_ADDR_FAMILY_IPV4		0x0100
#define RHP_PROTO_NHRP_ADDR_FAMILY_IPV6		0x0200
#endif
	u16 address_family_no;

	u16 protocol_type; // Ether-ether_type
	u8 	ptotocol_type_snap[5];
	u8 	hop_count;
	u16 len;
	u16 check_sum;
	u16 extension_offset;

#define RHP_PROTO_NHRP_VERSION		1
	u8 	version;

#define RHP_PROTO_NHRP_PKT_RESOLUTION_REQ			1
#define RHP_PROTO_NHRP_PKT_RESOLUTION_REP			2
#define RHP_PROTO_NHRP_PKT_REGISTRATION_REQ		3
#define RHP_PROTO_NHRP_PKT_REGISTRATION_REP		4
#define RHP_PROTO_NHRP_PKT_PURGE_REQ					5
#define RHP_PROTO_NHRP_PKT_PURGE_REP					6
#define RHP_PROTO_NHRP_PKT_ERROR_INDICATION		7
#define RHP_PROTO_NHRP_PKT_TRAFFIC_INDICATION	8 // Cisco's extension
	u8 	packet_type;

	//
	// NSAP Format
	//
#define RHP_PROTO_NHRP_ADDR_IPV4_TYPE_LEN	4
#define RHP_PROTO_NHRP_ADDR_IPV6_TYPE_LEN	16
#ifdef RHP_BIG_ENDIAN_BF
	u8 src_nbma_addr_type_reserved:1,
		 src_nbma_addr_type_flag:1,
		 src_nbma_addr_type_len:6;
	u8 src_nbma_saddr_type_reserved:1,
		 src_nbma_saddr_type_flag:1,
		 src_nbma_saddr_type_len:6;
#else
	u8 src_nbma_addr_type_len:6,
		 src_nbma_addr_type_flag:1,
		 src_nbma_addr_type_reserved:1;
	u8 src_nbma_saddr_type_len:6,
		 src_nbma_saddr_type_flag:1,
		 src_nbma_saddr_type_reserved:1;
#endif
};
typedef struct _rhp_proto_nhrp_fixed	rhp_proto_nhrp_fixed;

/*

 [RFC2332] NBMA Next Hop Resolution Protocol (NHRP)

 5.2.0.1 Mandatory Part Format

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Src Proto Len | Dst Proto Len |           Flags               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Request ID                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            Source NBMA Address (variable length)              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source NBMA Subaddress (variable length)             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Protocol Address (variable length)            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       Destination  Protocol Address (variable length)         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   And the CIEs have the following format:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    Code       | Prefix Length |         unused                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Maximum Transmission Unit    |        Holding Time           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Cli Addr T/L | Cli SAddr T/L | Cli Proto Len |  Preference   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            Client NBMA Address (variable length)              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Client NBMA Subaddress (variable length)            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Client Protocol Address (variable length)            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                        .....................
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    Code       | Prefix Length |         unused                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Maximum Transmission Unit    |        Holding Time           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Cli Addr T/L | Cli SAddr T/L | Cli Proto Len |  Preference   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            Client NBMA Address (variable length)              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Client NBMA Subaddress (variable length)            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Client Protocol Address (variable length)            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   The meanings of the fields are as follows:

   Src Proto Len
     This field holds the length in octets of the Source Protocol
     Address.

   Dst Proto Len
     This field holds the length in octets of the Destination Protocol
     Address.

   Flags
     These flags are specific to the given message type and they are
     explained in each section.

   Request ID
     A value which, when coupled with the address of the source,
     provides a unique identifier for the information contained in a
     "request" packet.  This value is copied directly from an "request"
     packet into the associated "reply".  When a sender of a "request"
     receives "reply", it will compare the Request ID and source address
     information in the received "reply" against that found in its
     outstanding "request" list.  When a match is found then the
     "request" is considered to be acknowledged.

     The value is taken from a 32 bit counter that is incremented each
     time a new "request" is transmitted.  The same value MUST be used
     when resending a "request", i.e., when a "reply" has not been
     received for a "request" and a retry is sent after an appropriate
     interval.

     It is RECOMMENDED that the initial value for this number be 0.  A
     node MAY reuse a sequence number if and only if the reuse of the
     sequence number is not precluded by use of a particular method of
     synchronization (e.g., as described in Appendix A).

   The NBMA address/subaddress form specified below allows combined
   E.164/NSAPA form of NBMA addressing. For NBMA technologies without a
   subaddress concept, the subaddress field is always ZERO length and
   ar$sstl = 0.

   Source NBMA Address
     The Source NBMA address field is the address of the source station
     which is sending the "request". If the field's length as specified
     in ar$shtl is 0 then no storage is allocated for this address at
     all.

   Source NBMA SubAddress
     The Source NBMA subaddress field is the address of the source
     station which is sending the "request".  If the field's length as
     specified in ar$sstl is 0 then no storage is allocated for this
     address at all.

   For those NBMA technologies which have a notion of "Calling Party
   Addresses", the Source NBMA Addresses above are the addresses used
   when signaling for an SVC.

   "Requests" and "indications" follow the routed path from Source
   Protocol Address to the Destination Protocol Address. "Replies", on
   the other hand, follow the routed path from the Destination Protocol
   Address back to the Source Protocol Address with the following
   exceptions: in the case of a NHRP Registration Reply and in the case
   of an NHC initiated NHRP Purge Request, the packet is always returned
   via a direct VC (see Sections 5.2.4 and 5.2.5).

   Source Protocol Address
     This is the protocol address of the station which is sending the
     "request".  This is also the protocol address of the station toward
     which a "reply" packet is sent.

   Destination Protocol Address
     This is the protocol address of the station toward which a
     "request" packet is sent.

   Code
     This field is message specific.  See the relevant message sections
     below.  In general, this field is a NAK code; i.e., when the field
     is 0 in a reply then the packet is acknowledging a request and if
     it contains any other value the packet contains a negative
     acknowledgment.

   Prefix Length
     This field is message specific.  See the relevant message sections
     below.  In general, however, this fields is used to indicate that
     the information carried in an NHRP message pertains to an
     equivalence class of internetwork layer addresses rather than just
     a single internetwork layer address specified. All internetwork
     layer addresses that match the first "Prefix Length" bit positions
     for the specific internetwork layer address are included in the
     equivalence class.  If this field is set to 0x00 then this field
     MUST be ignored and no equivalence information is assumed (note
     that 0x00 is thus equivalent to 0xFF).

   Maximum Transmission Unit
     This field gives the maximum transmission unit for the relevant
     client station.  If this value is 0 then either the default MTU is
     used or the MTU negotiated via signaling is used if such
     negotiation is possible for the given NBMA.

   Holding Time
     The Holding Time field specifies the number of seconds for which
     the Next Hop NBMA information specified in the CIE is considered to
     be valid.  Cached information SHALL be discarded when the holding
     time expires.  This field must be set to 0 on a NAK.

   Cli Addr T/L
     Type & length of next hop NBMA address specified in the CIE.  This
     field is interpreted in the context of the 'address family
     number'[6] indicated by ar$afn (e.g., ar$afn=0x0003 for ATM).

   Cli SAddr T/L
     Type & length of next hop NBMA subaddress specified in the CIE.
     This field is interpreted in the context of the 'address family
     number'[6] indicated by ar$afn (e.g., ar$afn=0x0015 for ATM makes
     the address an E.164 and the subaddress an ATM Forum NSAP address).
     When an NBMA technology has no concept of a subaddress, the
     subaddress is always null with a length of 0.  When the address
     length is specified as 0 no storage is allocated for the address.

   Cli Proto Len
     This field holds the length in octets of the Client Protocol
     Address specified in the CIE.

   Preference
     This field specifies the preference for use of the specific CIE
     relative to other CIEs.  Higher values indicate higher preference.
     Action taken when multiple CIEs have equal or highest preference
     value is a local matter.

   Client NBMA Address
     This is the client's NBMA address.

   Client NBMA SubAddress
     This is the client's NBMA subaddress.

   Client Protocol Address
     This is the client's internetworking layer address specified.

*/

/*

 5.2.1 NHRP Resolution Request

   Flags - The flags field is coded as follows:

      0                   1
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |Q|A|D|U|S|       unused        |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

     Q
       Set if the station sending the NHRP Resolution Request is a
       router; clear if the it is a host.

     A
       This bit is set in a NHRP Resolution Request if only
       authoritative next hop information is desired and is clear
       otherwise.  See the NHRP Resolution Reply section below for
       further details on the "A" bit and its usage.

     D
       Unused (clear on transmit)

     U
       This is the Uniqueness bit. This bit aids in duplicate address
       detection.  When this bit is set in an NHRP Resolution Request
       and one or more entries exist in the NHS cache which meet the
       requirements of the NHRP Resolution Request then only the CIE in
       the NHS's cache with this bit set will be returned.  Note that
       even if this bit was set at registration time, there may still be
       multiple CIEs that might fulfill the NHRP Resolution Request
       because an entire subnet can be registered through use of the
       Prefix Length in the CIE and the address of interest might be
       within such a subnet. If the "uniqueness" bit is set and the
       responding NHS has one or more cache entries which match the
       request but no such cache entry has the "uniqueness" bit set,
       then the NHRP Resolution Reply returns with a NAK code of "13 -
       Binding Exists But Is Not Unique" and no CIE is included.  If a
       client wishes  to  receive  non- unique  Next  Hop Entries, then
       the client must have the "uniqueness" bit set to zero in its NHRP
       Resolution Request. Note that when this bit is set in an NHRP
       Registration Request, only a single CIE may be specified in the
       NHRP Registration Request and that CIE must have the Prefix
       Length field set to 0xFF.

     S
       Set if the binding between the Source Protocol Address and the
       Source NBMA information in the NHRP Resolution Request is
       guaranteed to be stable and accurate (e.g., these addresses are
       those of an ingress router which is connected to an ethernet stub
       network or the NHC is an NBMA attached host).

*/
struct _rhp_proto_nhrp_mandatory {

	u8 src_protocol_len; // RHP_PROTO_NHRP_ADDR_XXX_TYPE_LEN
	u8 dst_protocol_len; // RHP_PROTO_NHRP_ADDR_XXX_TYPE_LEN

#ifdef RHP_BIG_ENDIAN_BF
#define RHP_PROTO_NHRP_RES_FLAG_Q 0x8000
#define RHP_PROTO_NHRP_RES_FLAG_A	0x4000
#define RHP_PROTO_NHRP_RES_FLAG_D	0x2000
#define RHP_PROTO_NHRP_RES_FLAG_U	0x1000
#define RHP_PROTO_NHRP_RES_FLAG_S	0x0800
#define RHP_PROTO_NHRP_FLAG_CISCO_NAT_EXT	0x0002
#define RHP_PROTO_NHRP_REG_FLAG_U		0x8000
#define RHP_PROTO_NHRP_PRG_FLAG_N		0x8000
#else	//RHP_BIG_ENDIAN_BF
#define RHP_PROTO_NHRP_RES_FLAG_Q 0x0080
#define RHP_PROTO_NHRP_RES_FLAG_A	0x0040
#define RHP_PROTO_NHRP_RES_FLAG_D	0x0020
#define RHP_PROTO_NHRP_RES_FLAG_U	0x0010
#define RHP_PROTO_NHRP_RES_FLAG_S	0x0008
#define RHP_PROTO_NHRP_FLAG_CISCO_NAT_EXT	0x0200
#define RHP_PROTO_NHRP_REG_FLAG_U		0x0080
#define RHP_PROTO_NHRP_PRG_FLAG_N		0x0080
#endif // RHP_BIG_ENDIAN_BF

#define RHP_PROTO_NHRP_RES_FLAG_Q_ROUTER(flags) 				((flags) & RHP_PROTO_NHRP_RES_FLAG_Q)
#define RHP_PROTO_NHRP_RES_FLAG_A_AUTHORITATIVE(flags)	((flags) & RHP_PROTO_NHRP_RES_FLAG_A)
#define RHP_PROTO_NHRP_RES_FLAG_D_DST_STABLE(flags)			((flags) & RHP_PROTO_NHRP_RES_FLAG_D)
#define RHP_PROTO_NHRP_RES_FLAG_U_UNIQUE(flags)					((flags) & RHP_PROTO_NHRP_RES_FLAG_U)
#define RHP_PROTO_NHRP_RES_FLAG_S_SRC_STABLE(flags)			((flags) & RHP_PROTO_NHRP_RES_FLAG_S)
#define RHP_PROTO_NHRP_RES_FLAG_CISCO_NAT_EXT(flags)		((flags) & RHP_PROTO_NHRP_FLAG_CISCO_NAT_EXT)

#define RHP_PROTO_NHRP_REG_FLAG_U_UNIQUE(flags)					((flags) & RHP_PROTO_NHRP_REG_FLAG_U)

#define RHP_PROTO_NHRP_PRG_FLAG_N_NO_REPLY(flags)				((flags) & RHP_PROTO_NHRP_PRG_FLAG_N)
	u16 flags;

	u32 request_id;
};
typedef struct _rhp_proto_nhrp_mandatory	rhp_proto_nhrp_mandatory;


struct _rhp_proto_nhrp_clt_info_entry {

#define RHP_PROTO_NHRP_CIE_CODE_NONE							0
#define RHP_PROTO_NHRP_CIE_CODE_SUCCESS						0
#define RHP_PROTO_NHRP_CIE_CODE_ADMIN_PROHIBITED	4		// Administratively Prohibited
#define RHP_PROTO_NHRP_CIE_CODE_NO_RESOURCE				5		// Insufficient Resources
#define RHP_PROTO_NHRP_CIE_CODE_ADDR_COLLISION		14	// Unique Internetworking Layer Address Already Registered
	u8 code;

	u8 prefix_len;
	u16 unused;
	u16 mtu;
	u16 hold_time;
	u8 clt_nbma_addr_type_len;
	u8 clt_nbma_saddr_type_len;
	u8 clt_protocol_addr_len;
	u8 preference;
};
typedef struct _rhp_proto_nhrp_clt_info_entry	rhp_proto_nhrp_clt_info_entry;


/*

 [RFC2332] NBMA Next Hop Resolution Protocol (NHRP)

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Src Proto Len | Dst Proto Len |            unused             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Error Code          |        Error Offset           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            Source NBMA Address (variable length)              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source NBMA Subaddress (variable length)             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Protocol Address (variable length)            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       Destination  Protocol Address (variable length)         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       Contents of NHRP Packet in error (variable length)      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Src Proto Len
     This field holds the length in octets of the Source Protocol
     Address.

   Dst Proto Len
     This field holds the length in octets of the Destination Protocol
     Address.

   Error Code
     An error code indicating the type of error detected, chosen from
     the following list:

       1 - Unrecognized Extension

         When the Compulsory bit of an extension in NHRP packet is set,
         the NHRP packet cannot be processed unless the extension has
         been processed.  The responder MUST return an NHRP Error
         Indication of type Unrecognized Extension if it is incapable of
         processing the extension.  However, if a transit NHS (one which
         is not going to generate a reply) detects an unrecognized
         extension, it SHALL ignore the extension.

       3 - NHRP Loop Detected

         A Loop Detected error is generated when it is determined that
         an NHRP packet is being forwarded in a loop.

       6 - Protocol Address Unreachable

         This error occurs when a packet it moving along the routed path
         and it reaches a point such that the protocol address of
         interest is not reachable.

       7 - Protocol Error

         A generic packet processing error has occurred (e.g., invalid
         version number, invalid protocol type, failed checksum, etc.)

       8 - NHRP SDU Size Exceeded

         If the SDU size of the NHRP packet exceeds the MTU size of the
         NBMA network then this error is returned.

       9 - Invalid Extension

         If an NHS finds an extension in a packet which is inappropriate
         for the packet type, an error is sent back to the sender with
         Invalid Extension as the code.

       10 - Invalid NHRP Resolution Reply Received

         If a client receives a NHRP Resolution Reply for a Next Hop
         Resolution Request which it believes it did not make then an
         error packet is sent to the station making the reply with an
         error code of Invalid Reply Received.

       11 - Authentication Failure

         If a received packet fails an authentication test then this
         error is returned.

       15 - Hop Count Exceeded

         The hop count which was specified in the Fixed Header of an
         NHRP message has been exceeded.

   Error Offset
     The offset in octets into the original NHRP packet in which an
     error was detected.  This offset is calculated starting from the
     NHRP Fixed Header.

   Source NBMA Address
     The Source NBMA address field is the address of the station which
     observed the error.

   Source NBMA SubAddress
     The Source NBMA subaddress field is the address of the station
     which observed the error.  If the field's length as specified in
     ar$sstl is 0 then no storage is allocated for this address at all.

   Source Protocol Address
     This is the protocol address of the station which issued the Error
     packet.

   Destination Protocol Address
     This is the protocol address of the station which sent the packet
     which was found to be in error.

*/
struct _rhp_proto_nhrp_error {

	u8 src_protocol_len;
	u8 dst_protocol_len;

	u16 unused;

#define RHP_PROTO_NHRP_ERR_CODE_UNSUP_EXT					1  // Unrecognized Extension
#define RHP_PROTO_NHRP_ERR_CODE_LOOP_DECTECT			3  // NHRP Loop Detected
#define RHP_PROTO_NHRP_ERR_CODE_UNREACH						6  // Protocol Address Unreachable
#define RHP_PROTO_NHRP_ERR_CODE_PROTOCOL_ERR			7	 // Protocol Error
#define RHP_PROTO_NHRP_ERR_CODE_MESG_TOO_LONG			8  // NHRP SDU Size Exceeded
#define RHP_PROTO_NHRP_ERR_CODE_INVALID_EXT				9  // Invalid Extension
#define RHP_PROTO_NHRP_ERR_CODE_INVALID_RES_REP		10 // Invalid NHRP Resolution Reply Received
#define RHP_PROTO_NHRP_ERR_CODE_AUTH_FAILURE			11 // Authentication Failure
#define RHP_PROTO_NHRP_ERR_CODE_HOP_CNT_EXCEEDED	12 // Hop Count Exceeded
	u16 error_code;
	u16 error_offset;
};
typedef struct _rhp_proto_nhrp_error	rhp_proto_nhrp_error;

/*

 - Flexible Dynamic Mesh VPN (draft-detienne-dmvpn-01)
 	 https://tools.ietf.org/html/draft-detienne-dmvpn-01

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      | Src Proto Len | Dst Proto Len |            unused             |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |           Traffic Code        |            unused             |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |            Source NBMA Address (variable length)              |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |          Source NBMA Subaddress (variable length)             |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |          Source Protocol Address (variable length)            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |       Destination  Protocol Address (variable length)         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |       Contents of Data Packet in traffic (variable length)    |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                Figure 4: Traffic Indication Mandatory Part

   o  Src Proto Len: This field holds the length in octets of the Source
      Protocol Address.
   o  Dst Proto Len: This field holds the length in octets of the
      Destination Protocol Address.
   o  Traffic Code: A code indicating the type of traffic indication
      message, chosen from the following list

      *  0: NHRP Traffic Redirect/Indirection message.This indirection
         is an indication,to the receiver, of the possible existence of
         a 'better' path in the NBMA network.
   o  Source NBMA Address: The Source NBMA address field is the address
      of the station which generated the traffic indication.
   o  Source NBMA SubAddress: The Source NBMA subaddress field is the
      address of the station generated the traffic indication.  If the
      field's length as specified in ar$sstl is 0 then no storage is
      allocated for this address at all.
   o  Source Protocol Address: This is the protocol address of the
      station which issued the Traffic Indication packet.
   o  Destination Protocol Address: This is the destination IP address
      from the packet which triggered the sending of this Traffic
      Indication message.

   Note that unlike NHRP Resolution/Registration/Purge messages, Traffic
   Indication message doesn't have a request/reply pair nor does it
   contain any CIE though it may contain extension records.

*/
struct _rhp_proto_nhrp_traffic_indication {

	u8 src_protocol_len;
	u8 dst_protocol_len;

	u16 unused0;

#define RHP_PROTO_NHRP_TRAFFIC_CODE_NHRP		0
	u16 traffic_code;
	u16 unused1;
};
typedef struct _rhp_proto_nhrp_traffic_indication	rhp_proto_nhrp_traffic_indication;


struct _rhp_proto_nhrp {

	rhp_proto_nhrp_fixed fixed;

	union {
		rhp_proto_nhrp_mandatory mandatory;
		rhp_proto_nhrp_error error;
		rhp_proto_nhrp_traffic_indication traffic;
	} m;
};
typedef struct _rhp_proto_nhrp	rhp_proto_nhrp;

/*

 [RFC2332] NBMA Next Hop Resolution Protocol (NHRP)

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |C|u|        Type               |        Length                 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Value...                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   C
     "Compulsory."  If clear, and the NHS does not recognize the type
     code, the extension may safely be ignored.  If set, and the NHS
     does not recognize the type code, the NHRP "request" is considered
     to be in error.  (See below for details.)

   u
     Unused and must be set to zero.

   Type
     The extension type code (see below).  The extension type is not
     qualified by the Compulsory bit, but is orthogonal to it.

   Length
     The length in octets of the value (not including the Type and
     Length fields;  a null extension will have only an extension header
     and a length of zero).

*/
struct _rhp_proto_nhrp_ext {

#ifdef RHP_BIG_ENDIAN_BF
#define RHP_PROTO_NHRP_EXT_FLAG_COMPULSORY	0x8000
#define RHP_PROTO_NHRP_EXT_FLAG_UNUSED			0x4000
#define RHP_PROTO_NHRP_EXT_FLAG_IS_COMPULSORY(flags) 	((flags) & RHP_PROTO_NHRP_EXT_FLAG_COMPULSORY)
#define RHP_PROTO_NHRP_EXT_FLAG_IS_UNUSED(flags)			((flags) & RHP_PROTO_NHRP_EXT_FLAG_UNUSED)
#define RHP_PROTO_NHRP_EXT_TYPE(flags)								((flags) & 0x3FFF)
#else	//RHP_BIG_ENDIAN_BF
#define RHP_PROTO_NHRP_EXT_FLAG_COMPULSORY	0x0080
#define RHP_PROTO_NHRP_EXT_FLAG_UNUSED			0x0040
#define RHP_PROTO_NHRP_EXT_FLAG_IS_COMPULSORY(flags) 	((flags) & RHP_PROTO_NHRP_EXT_FLAG_COMPULSORY)
#define RHP_PROTO_NHRP_EXT_FLAG_IS_UNUSED(flags)			((flags) & RHP_PROTO_NHRP_EXT_FLAG_UNUSED)
#define RHP_PROTO_NHRP_EXT_TYPE(flags)								((flags) & 0xFF3F)
#endif // RHP_BIG_ENDIAN_BF

#define RHP_PROTO_NHRP_EXT_TYPE_END													0
#define RHP_PROTO_NHRP_EXT_TYPE_RESPONDER_ADDRESS						3
#define RHP_PROTO_NHRP_EXT_TYPE_FORWARD_TRANSIT_NHS_RECORD	4
#define RHP_PROTO_NHRP_EXT_TYPE_REVERSE_TRANSIT_NHS_RECORD	5
#define RHP_PROTO_NHRP_EXT_TYPE_AUTHENTICATION							7
#define RHP_PROTO_NHRP_EXT_TYPE_VENDOR_PRIVATE							8
#define RHP_PROTO_NHRP_EXT_TYPE_NAT_ADDRESS									9 // Cisco's extension
	u16 type;

	u16 len;
};
typedef struct _rhp_proto_nhrp_ext	rhp_proto_nhrp_ext;

struct _rhp_proto_nhrp_ext_auth {

	u16 reserved;

	u16 spi;
};
typedef struct _rhp_proto_nhrp_ext_auth	rhp_proto_nhrp_ext_auth;



static inline u16 _rhp_proto_nhrp_set_csum(rhp_proto_nhrp* nhrph)
{
	int len, nhrp_len = ntohs(nhrph->fixed.len);
	int is_odd_len = 0;
	int i;
	u32 csum = 0;
	u16* buf = (u16*)nhrph;
	u32 cr;

	nhrph->fixed.check_sum = 0;

	if( nhrp_len % 2 ){
		len = nhrp_len/2 + 1;
		is_odd_len = 1;
	}else{
		len = nhrp_len/2;
	}

	for( i = 0; i < len; i++ ){

		if( is_odd_len && i == (len - 1) ){

			u8 o_buf[2];

			o_buf[0] = *((u8*)buf);
			o_buf[1] = 0;

			csum += *((u16*)o_buf);

		}else{

			csum += *buf;
		}

		buf++;
	}

	while( (cr = ((csum >> 16) & 0x0000FFFF)) ){
		csum = (csum & 0x0000FFFF) + cr;
	}

	nhrph->fixed.check_sum = (u16)(~csum);
	return nhrph->fixed.check_sum;
}




struct _rhp_proto_udp
{
  u16 src_port;
  u16 dst_port;

  u16 len;
  u16 check_sum;
};
typedef struct _rhp_proto_udp rhp_proto_udp;

struct _rhp_proto_pseudo_hdr_v4
{
	u32 src_ipv4;
	u32 dst_ipv4;
	u8 pad;
	u8 protocol;
	u16 len;
};
typedef struct _rhp_proto_pseudo_hdr_v4 rhp_proto_pseudo_hdr_v4;

struct _rhp_proto_pseudo_hdr_v6
{
  u8 src_ipv6[16];
  u8 dst_ipv6[16];
  u32 len;
  u8 pad[3];
  u8 next_heder;
};
typedef struct _rhp_proto_pseudo_hdr_v6 rhp_proto_pseudo_hdr_v6;


static inline u16 _rhp_proto_ip_v4_udp_set_csum(u32 src_ipv4,u32 dst_ipv4,rhp_proto_udp* udph)
{
	int i;
	u32 csum = 0;
	u16* buf;
	u32 cr;
	int udp_len = ntohs(udph->len);
	rhp_proto_pseudo_hdr_v4 phdr;

	phdr.src_ipv4 = src_ipv4;
	phdr.dst_ipv4 = dst_ipv4;
	phdr.pad = 0;
	phdr.protocol = RHP_PROTO_IP_UDP;
	phdr.len = udph->len;

	udph->check_sum = 0;

	buf = (u16*)&phdr;
	for( i = 0; i < 6; i++ ){
		csum += *buf;
		buf++;
	}

	buf = (u16*)udph;
	while( udp_len > 1 ){
		csum += *buf;
		buf++;
		udp_len -= 2;
	}

	if( udp_len ){ // Odd udp_len's case
		csum += *((u8*)buf);
	}

	while( (cr = ((csum >> 16) & 0x0000FFFF)) ){
		csum = (csum & 0x0000FFFF) + cr;
	}

	udph->check_sum = (u16)(~csum);
	return udph->check_sum;
}

static inline u16 _rhp_proto_ip_v6_udp_set_csum(u8* src_ipv6,u8* dst_ipv6,rhp_proto_udp* udph)
{
	int i;
	u32 csum = 0;
	u16* buf;
	u32 cr;
	int udp_len = ntohs(udph->len);
	rhp_proto_pseudo_hdr_v6 phdr;

	memcpy(phdr.src_ipv6,src_ipv6,16);
	memcpy(phdr.dst_ipv6,dst_ipv6,16);
	phdr.len = udph->len;
	phdr.pad[0] = 0;
	phdr.pad[1] = 0;
	phdr.pad[2] = 0;
	phdr.next_heder = RHP_PROTO_IP_UDP;

	udph->check_sum = 0;

	buf = (u16*)&phdr;
	for( i = 0; i < 20; i++ ){
		csum += *buf;
		buf++;
	}

	buf = (u16*)udph;
	while( udp_len > 1 ){
		csum += *buf;
		buf++;
		udp_len -= 2;
	}

	if( udp_len ){ // Odd udp_len's case
		csum += *((u8*)buf);
	}

	while( (cr = ((csum >> 16) & 0x0000FFFF)) ){
		csum = (csum & 0x0000FFFF) + cr;
	}

	udph->check_sum = (u16)(~csum);
	return udph->check_sum;
}


struct _rhp_proto_tcp
{
  u16 src_port;
  u16 dst_port;

  u32   seq;
  u32   ack_seq;

#ifdef RHP_BIG_ENDIAN_BF
  u16 doff:4,
  reserved:4,
  cwr:1,
  ece:1,
  urg:1,
  ack:1,
  psh:1,
  rst:1,
  syn:1,
  fin:1;
#else
  u16 reserved:4,
  doff:4,
  fin:1,
  syn:1,
  rst:1,
  psh:1,
  ack:1,
  urg:1,
  ece:1,
  cwr:1;
#endif

  u16   win_size;
  u16   check_sum;
  u16   urg_ptr;

#define RHP_PROTO_TCP_OPT_EOP		0
#define RHP_PROTO_TCP_OPT_NOP		1
#define RHP_PROTO_TCP_OPT_MSS		2
};
typedef struct _rhp_proto_tcp rhp_proto_tcp;

static inline u16 _rhp_proto_ip_v4_tcp_set_csum(u32 src_ipv4,u32 dst_ipv4,
		rhp_proto_tcp* tcph,int tcp_seg_len)
{
	int i;
	u32 csum = 0;
	u16* buf;
	u32 cr;
	int len = tcp_seg_len;
	rhp_proto_pseudo_hdr_v4 phdr;

	phdr.src_ipv4 = src_ipv4;
	phdr.dst_ipv4 = dst_ipv4;
	phdr.pad = 0;
	phdr.protocol = RHP_PROTO_IP_TCP;
	phdr.len = htons((u16)tcp_seg_len);

	tcph->check_sum = 0;

	buf = (u16*)&phdr;
	for( i = 0; i < 6; i++ ){
		csum += *buf;
		buf++;
	}

	buf = (u16*)tcph;
	while( len > 1 ){
		csum += *buf;
		buf++;
		len -= 2;
	}

	if( len ){ // Odd tcp_seg_len's case
		csum += *((u8*)buf);
	}

	while( (cr = ((csum >> 16) & 0x0000FFFF)) ){
		csum = (csum & 0x0000FFFF) + cr;
	}

	tcph->check_sum = (u16)(~csum);
	return tcph->check_sum;
}

static inline u16 _rhp_proto_ip_v6_tcp_set_csum(u8* src_ipv6,u8* dst_ipv6,
		rhp_proto_tcp* tcph,int tcp_seg_len)
{
	int i;
	u32 csum = 0;
	u16* buf;
	u32 cr;
	int len = tcp_seg_len;
	rhp_proto_pseudo_hdr_v6 phdr;

	memcpy(phdr.src_ipv6,src_ipv6,16);
	memcpy(phdr.dst_ipv6,dst_ipv6,16);
	phdr.len = htonl((u32)tcp_seg_len);
	phdr.pad[0] = 0;
	phdr.pad[1] = 0;
	phdr.pad[2] = 0;
	phdr.next_heder = RHP_PROTO_IP_TCP;

	tcph->check_sum = 0;

	buf = (u16*)&phdr;
	for( i = 0; i < 20; i++ ){
		csum += *buf;
		buf++;
	}

	buf = (u16*)tcph;
	while( len > 1 ){
		csum += *buf;
		buf++;
		len -= 2;
	}

	if( len ){ // Odd tcp_seg_len's case
		csum += *((u8*)buf);
	}

	while( (cr = ((csum >> 16) & 0x0000FFFF)) ){
		csum = (csum & 0x0000FFFF) + cr;
	}

	tcph->check_sum = (u16)(~csum);

	return tcph->check_sum;
}



struct _rhp_proto_sctp
{
  u16 src_port;
  u16 dst_port;
  u32 vtag;
  u32 check_sum;
};
typedef struct _rhp_proto_sctp rhp_proto_sctp;


#define RHP_PROTO_ESP_SPI_SIZE  			4
#define RHP_PROTO_ESP_RESV_SPI_MIN		1			// See RFC4303 2.1
#define RHP_PROTO_ESP_RESV_SPI_MAX		255

struct _rhp_proto_esp
{
  u32 spi;
  u32 seq;
};
typedef struct _rhp_proto_esp rhp_proto_esp;



struct _rhp_proto_icmp
{
#define RHP_PROTO_ICMP_TYPE_ECHO_REPLY									0
#define RHP_PROTO_ICMP_TYPE_DEST_UNREACH   							3
#define RHP_PROTO_ICMP_TYPE_SOURCE_QUENCH								4
#define RHP_PROTO_ICMP_TYPE_REDIRECT										5
#define RHP_PROTO_ICMP_TYPE_ECHO_REQUEST								8
#define RHP_PROTO_ICMP_TYPE_ROUTER_ADVERTISEMENT				9
#define RHP_PROTO_ICMP_TYPE_ROUTER_SOLICITATION					10
#define RHP_PROTO_ICMP_TYPE_TIME_EXCEEDED								11
#define RHP_PROTO_ICMP_TYPE_PARAM_PROBLEM								12
  u8  type;
#define RHP_PROTO_ICMP_FRAG_NEEDED    	4
  u8  code;
  u16 check_sum;
};
typedef struct _rhp_proto_icmp  rhp_proto_icmp;

struct _rhp_proto_icmp_echo {
	u16 id;
	u16 seq;
};
typedef struct _rhp_proto_icmp_echo	rhp_proto_icmp_echo;

struct _rhp_proto_icmp_frag_needed
{
  u16 reserved;
  u16 mtu;
};
typedef struct _rhp_proto_icmp_frag_needed  rhp_proto_icmp_frag_needed;

static inline u16 _rhp_proto_icmp_set_csum(rhp_proto_icmp* icmph,int len/*Don't be odd number!*/)
{
	int i;
	u32 csum = 0;
	u16* buf = (u16*)icmph;
	u32 cr;

	len = (len >> 1);

	icmph->check_sum = 0;

	for( i = 0; i < len;i++){
		csum += *buf;
		buf++;
	}

	while( (cr = ((csum >> 16) & 0x0000FFFF)) ){
		csum = (csum & 0x0000FFFF) + cr;
	}

	icmph->check_sum = (u16)(~csum);

	return icmph->check_sum;
}



struct _rhp_proto_icmp6
{
#define RHP_PROTO_ICMP6_TYPE_DEST_UNREACH			1
#define RHP_PROTO_ICMP6_TYPE_PKT_TOO_BIG			2
#define RHP_PROTO_ICMP6_TYPE_TIME_EXCEEDED		3
#define RHP_PROTO_ICMP6_TYPE_PARAM_PROBLEM		4

#define RHP_PROTO_ICMP6_TYPE_ECHO_REQUEST			128
#define RHP_PROTO_ICMP6_TYPE_ECHO_REPLY				129

#define RHP_PROTO_ICMP6_TYPE_MLD_LISTENER_QUERY		130
#define RHP_PROTO_ICMP6_TYPE_MLD_LISTENER_REPORT	131
#define RHP_PROTO_ICMP6_TYPE_MLD2_LISTENER_REPORT	143
#define RHP_PROTO_ICMP6_TYPE_MLD_LISTENER_DONE		132

#define RHP_PROTO_ICMP6_TYPE_ROUTER_SOLICIT		133
#define RHP_PROTO_ICMP6_TYPE_ROUTER_ADV				134	// ADV: ADVertisement

#define RHP_PROTO_ICMP6_TYPE_NEIGHBOR_SOLICIT	135
#define RHP_PROTO_ICMP6_TYPE_NEIGHBOR_ADV			136

#define RHP_PROTO_ICMP6_TYPE_REDIRECT					137

#define RHP_PROTO_ICMP6_TYPE_ROUTER_RR				138 // RR: Router Renumbering
  u8  type;
  u8  code;
  u16 check_sum;
};
typedef struct _rhp_proto_icmp6  rhp_proto_icmp6;

static inline u16 _rhp_proto_icmpv6_set_csum(u8* src_ipv6,u8* dst_ipv6,
		rhp_proto_icmp6* icmpv6h,int len/*Don't be odd number!*/)
{
	int i;
	u32 csum = 0;
	u16* buf;
	u32 cr;
	rhp_proto_pseudo_hdr_v6 phdr;

	memcpy(phdr.src_ipv6,src_ipv6,16);
	memcpy(phdr.dst_ipv6,dst_ipv6,16);
	phdr.len = htonl((u32)len);
	phdr.pad[0] = 0;
	phdr.pad[1] = 0;
	phdr.pad[2] = 0;
	phdr.next_heder = RHP_PROTO_IP_IPV6_ICMP;

	icmpv6h->check_sum = 0;

	buf = (u16*)&phdr;
	for( i = 0; i < 20; i++ ){
		csum += *buf;
		buf++;
	}


	len = (len >> 1);

	buf = (u16*)icmpv6h;
	for( i = 0; i < len;i++){
		csum += *buf;
		buf++;
	}

	while( (cr = ((csum >> 16) & 0x0000FFFF)) ){
		csum = (csum & 0x0000FFFF) + cr;
	}

	icmpv6h->check_sum = (u16)(~csum);

	return icmpv6h->check_sum;
}

struct _rhp_proto_icmp6_nd_solict {

  u8  type;
  u8  code;
  u16 check_sum;

  u32 reserved;
  u8 target_addr[16];

  /* rhp_proto_icmp6_nd_opt_link_addr, if any. */
};
typedef struct _rhp_proto_icmp6_nd_solict	rhp_proto_icmp6_nd_solict;

struct _rhp_proto_icmp6_nd_adv {

  u8  type;
  u8  code;
  u16 check_sum;

#ifdef RHP_BIG_ENDIAN_BF
  u32	router:1,
      solicited:1,
      override:1,
      reserved:29;
#else
  u32	reserved:5,
      override:1,
      solicited:1,
      router:1,
      reserved2:24;
#endif
  u8 target_addr[16];

  /* rhp_proto_icmp6_nd_opt_link_addr, if any */
};
typedef struct _rhp_proto_icmp6_nd_adv	rhp_proto_icmp6_nd_adv;

struct _rhp_proto_icmp6_nd_opt_link_addr {

#define RHP_PROTO_ICMP6_ND_OPT_LINK_ADDR_SRC	1
#define RHP_PROTO_ICMP6_ND_OPT_LINK_ADDR_TGT	2
	u8 type;
	u8 len; // 1 for Ethernet.
	u8 mac[6];
};
typedef struct _rhp_proto_icmp6_nd_opt_link_addr	rhp_proto_icmp6_nd_opt_link_addr;

struct _rhp_proto_icmp6_mld1_query {

  u8  type;
  u8  code;
  u16 check_sum;

  u16 max_resp_delay;
  u16 reserved;

  u8 mc_addr[16];
};
typedef struct _rhp_proto_icmp6_mld1_query	rhp_proto_icmp6_mld1_query;

struct _rhp_proto_icmp6_mld2_query {

  u8  type;
  u8  code;
  u16 check_sum;

  u16 max_resp_code;
  u16 reserved0;

  u8 mc_addr[16];

#ifdef RHP_BIG_ENDIAN_BF
  u8	reserved1:4,
      suppress:1,
      qrv:3;
#else
  u8	qrv:3,
      suppress:1,
      reserved1:4;
#endif
  u8 qqic;
  u16 src_num;
};
typedef struct _rhp_proto_icmp6_mld2_query	rhp_proto_icmp6_mld2_query;

struct _rhp_proto_icmp6_mld1_report {

  u8  type;
  u8  code;
  u16 check_sum;

  u16 max_resp_delay;
  u16 reserved;

  u8 mc_addr[16];
};
typedef struct _rhp_proto_icmp6_mld1_report	rhp_proto_icmp6_mld1_report;

struct _rhp_proto_icmp6_mld2_report {

  u8  type;
  u8  code;
  u16 check_sum;

  u16 reserved;
  u16 mc_addr_rec_num;

  /* rhp_proto_icmp6_mld2_mc_addr_rec(s), if any. */
};
typedef struct _rhp_proto_icmp6_mld2_report	rhp_proto_icmp6_mld2_report;

struct _rhp_proto_icmp6_mld2_mc_addr_rec {

#define RHP_PROTO_ICMP6_MLD2_MC_ADDR_REC_IS_INCLUDE		1
#define RHP_PROTO_ICMP6_MLD2_MC_ADDR_REC_IS_EXCLUDE		2
#define RHP_PROTO_ICMP6_MLD2_MC_ADDR_REC_TO_INCLUDE		3
#define RHP_PROTO_ICMP6_MLD2_MC_ADDR_REC_TO_EXCLUDE		4
#define RHP_PROTO_ICMP6_MLD2_MC_ADDR_REC_ALLOW				5
#define RHP_PROTO_ICMP6_MLD2_MC_ADDR_REC_BLOCK				6
  u8 	type;
  u8 	aux_len;
  u16	src_addr_num;
  u8 	mc_addr[16];
};
typedef struct _rhp_proto_icmp6_mld2_mc_addr_rec	rhp_proto_icmp6_mld2_mc_addr_rec;

struct _rhp_proto_icmp6_mld1 {

  u8  type;
  u8  code;
  u16 check_sum;

  u16 max_resp_delay;
  u16 reserved;

  u16 mc_addr[16];
};
typedef struct _rhp_proto_icmp6_mld1 rhp_proto_icmp6_mld1;


struct _rhp_proto_icmp6_pkt_too_big
{
  u8  type;
  u8  code;
  u16 check_sum;
  u32 mtu;
};
typedef struct _rhp_proto_icmp6_pkt_too_big  rhp_proto_icmp6_pkt_too_big;



#define RHP_PROTO_DNS_PORT		53
struct _rhp_proto_dns {
	u16 txn_id;
	u16 flags;
	u16 qdcount;
	u16 ancount;
	u16 nscount;
	u16 arcount;
	/* [Len(1)=Label1_len][Label1][Len(1)=Label2_len][Label2]...[Len(1)=0][QTYPE(2)][QCLASS(2)] ... */
};
typedef struct _rhp_proto_dns	rhp_proto_dns;


#define RHP_PROTO_RIP_PORT		520
#define RHP_PROTO_BGP_PORT		179



/*

 (RFC 4306 and 5996) IKEv2

  3.1 The IKE Header
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                       IKE_SA Initiator's SPI                  !
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                       IKE_SA Responder's SPI                  !
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !  Next Payload ! MjVer ! MnVer ! Exchange Type !     Flags     !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                          Message ID                           !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                            Length                             !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                       Figure 4:  IKE Header Format

      o  Initiator's SPI (8 octets) - A value chosen by the
         initiator to identify a unique IKE security association. This
         value MUST NOT be zero.

      o  Responder's SPI (8 octets) - A value chosen by the
         responder to identify a unique IKE security association. This
         value MUST be zero in the first message of an IKE Initial
         Exchange (including repeats of that message including a
         cookie) and MUST NOT be zero in any other message.

      o  Next Payload (1 octet) - Indicates the type of payload that
         immediately follows the header. The format and value of each
         payload is defined below.

      o  Major Version (4 bits) - indicates the major version of the IKE
         protocol in use.  Implementations based on this version of IKE
         MUST set the Major Version to 2. Implementations based on
         previous versions of IKE and ISAKMP MUST set the Major Version
         to 1. Implementations based on this version of IKE MUST reject
         or ignore messages containing a version number greater than
         2.

      o  Minor Version (4 bits) - indicates the minor version of the
         IKE protocol in use.  Implementations based on this version of
         IKE MUST set the Minor Version to 0. They MUST ignore the minor
         version number of received messages.

      o  Exchange Type (1 octet) - indicates the type of exchange being
         used.  This constrains the payloads sent in each message and
         orderings of messages in an exchange.

                       Exchange Type            Value

                       RESERVED                 0-33
                       IKE_SA_INIT              34
                       IKE_AUTH                 35
                       CREATE_CHILD_SA          36
                       INFORMATIONAL            37
                       RESERVED TO IANA         38-239
                       Reserved for private use 240-255

      o  Flags (1 octet) - indicates specific options that are set
         for the message. Presence of options are indicated by the
         appropriate bit in the flags field being set. The bits are
         defined LSB first, so bit 0 would be the least significant
         bit of the Flags octet. In the description below, a bit
         being 'set' means its value is '1', while 'cleared' means
         its value is '0'.

       --  X(reserved) (bits 0-2) - These bits MUST be cleared
           when sending and MUST be ignored on receipt.

       --  I(nitiator) (bit 3 of Flags) - This bit MUST be set in
           messages sent by the original initiator of the IKE_SA
           and MUST be cleared in messages sent by the original
           responder. It is used by the recipient to determine
           which eight octets of the SPI was generated by the
           recipient.

       --  V(ersion) (bit 4 of Flags) - This bit indicates that
           the transmitter is capable of speaking a higher major
           version number of the protocol than the one indicated
           in the major version number field. Implementations of
           IKEv2 must clear this bit when sending and MUST ignore
           it in incoming messages.

       --  R(esponse) (bit 5 of Flags) - This bit indicates that
           this message is a response to a message containing
           the same message ID. This bit MUST be cleared in all
           request messages and MUST be set in all responses.
           An IKE endpoint MUST NOT generate a response to a
           message that is marked as being a response.

       --  X(reserved) (bits 6-7 of Flags) - These bits MUST be
           cleared when sending and MUST be ignored on receipt.

      o  Message ID (4 octets) - Message identifier used to control
         retransmission of lost packets and matching of requests and
         responses. It is essential to the security of the protocol
         because it is used to prevent message replay attacks.
         See sections 2.1 and 2.2.

      o  Length (4 octets) - Length of total message (header + payloads)
         in octets.
*/

/*

	(RFC2408) IKEv1

3.1 ISAKMP Header Format

   An ISAKMP message has a fixed header format, shown in Figure 2,
   followed by a variable number of payloads.  A fixed header simplifies
   parsing, providing the benefit of protocol parsing software that is
   less complex and easier to implement.  The fixed header contains the
   information required by the protocol to maintain state, process
   payloads and possibly prevent denial of service or replay attacks.

   The ISAKMP Header fields are defined as follows:

    o  Initiator Cookie (8 octets) - Cookie of entity that initiated SA
       establishment, SA notification, or SA deletion.

    o  Responder Cookie (8 octets) - Cookie of entity that is responding
       to an SA establishment request, SA notification, or SA deletion.

                         1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    !                          Initiator                            !
    !                            Cookie                             !
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    !                          Responder                            !
    !                            Cookie                             !
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    !  Next Payload ! MjVer ! MnVer ! Exchange Type !     Flags     !
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    !                          Message ID                           !
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    !                            Length                             !
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


                 Figure 2:  ISAKMP Header Format

    o  Next Payload (1 octet) - Indicates the type of the first payload
       in the message.  The format for each payload is defined in
       sections 3.4 through 3.16.  The processing for the payloads is
       defined in section 5.


                        Next Payload Type       Value
                    NONE                           0
                    Security Association (SA)      1
                    Proposal (P)                   2
                    Transform (T)                  3
                    Key Exchange (KE)              4
                    Identification (ID)            5
                    Certificate (CERT)             6
                    Certificate Request (CR)       7
                    Hash (HASH)                    8
                    Signature (SIG)                9
                    Nonce (NONCE)                 10
                    Notification (N)              11
                    Delete (D)                    12
                    Vendor ID (VID)               13
                    RESERVED                   14 - 127
                    Private USE               128 - 255

    o  Major Version (4 bits) - indicates the major version of the ISAKMP
       protocol in use.  Implementations based on this version of the
       ISAKMP Internet-Draft MUST set the Major Version to 1.
       Implementations based on previous versions of ISAKMP Internet-
       Drafts MUST set the Major Version to 0.  Implementations SHOULD
       never accept packets with a major version number larger than its
       own.

    o  Minor Version (4 bits) - indicates the minor version of the
       ISAKMP protocol in use.  Implementations based on this version of
       the ISAKMP Internet-Draft MUST set the Minor Version to 0.
       Implementations based on previous versions of ISAKMP Internet-
       Drafts MUST set the Minor Version to 1.  Implementations SHOULD
       never accept packets with a minor version number larger than its
       own, given the major version numbers are identical.

    o  Exchange Type (1 octet) - indicates the type of exchange being
       used.  This dictates the message and payload orderings in the
       ISAKMP exchanges.


                            Exchange Type      Value
                         NONE                    0
                         Base                    1
                         Identity Protection     2
                         Authentication Only     3
                         Aggressive              4
                         Informational           5
                         ISAKMP Future Use     6 - 31
                         DOI Specific Use     32 - 239
                         Private Use         240 - 255

    o  Flags (1 octet) - indicates specific options that are set for the
       ISAKMP exchange.  The flags listed below are specified in the
       Flags field beginning with the least significant bit, i.e the
       Encryption bit is bit 0 of the Flags field, the Commit bit is bit
       1 of the Flags field, and the Authentication Only bit is bit 2 of
       the Flags field.  The remaining bits of the Flags field MUST be
       set to 0 prior to transmission.

      --  E(ncryption Bit) (1 bit) - If set (1), all payloads following
          the header are encrypted using the encryption algorithm
          identified in the ISAKMP SA. The ISAKMP SA Identifier is the
          combination of the initiator and responder cookie.  It is
          RECOMMENDED that encryption of communications be done as soon
          as possible between the peers.  For all ISAKMP exchanges
          described in section 4.1, the encryption SHOULD begin after
          both parties have exchanged Key Exchange payloads.  If the
          E(ncryption Bit) is not set (0), the payloads are not
          encrypted.

      -- C(ommit Bit) (1 bit) - This bit is used to signal key exchange
          synchronization.  It is used to ensure that encrypted material
          is not received prior to completion of the SA establishment.
          The Commit Bit can be set (at anytime) by either party
          participating in the SA establishment, and can be used during
          both phases of an ISAKMP SA establishment.  However, the value
          MUST be reset after the Phase 1 negotiation.  If set(1), the
          entity which did not set the Commit Bit MUST wait for an
          Informational Exchange containing a Notify payload (with the
          CONNECTED Notify Message) from the entity which set the Commit
          Bit.  In this instance, the Message ID field of the
          Informational Exchange MUST contain the Message ID of the
          original ISAKMP Phase 2 SA negotiation.  This is done to
          ensure that the Informational Exchange with the CONNECTED
          Notify Message can be associated with the correct Phase 2 SA.
          The receipt and processing of the Informational Exchange
          indicates that the SA establishment was successful and either
          entity can now proceed with encrypted traffic communication.
          In addition to synchronizing key exchange, the Commit Bit can
          be used to protect against loss of transmissions over
          unreliable networks and guard against the need for multiple
          re-transmissions.

          NOTE: It is always possible that the final message of an
          exchange can be lost.  In this case, the entity expecting to
          receive the final message of an exchange would receive the
          Phase 2 SA negotiation message following a Phase 1 exchange or
          encrypted traffic following a Phase 2 exchange.  Handling of
          this situation is not standardized, but we propose the
          following possibilities.  If the entity awaiting the
          Informational Exchange can verify the received message (i.e.
          Phase 2 SA negotiation message or encrypted traffic), then
          they MAY consider the SA was established and continue
          processing.  The other option is to retransmit the last ISAKMP
          message to force the other entity to retransmit the final
          message.  This suggests that implementations may consider
          retaining the last message (locally) until they are sure the
          SA is established.

      --  A(uthentication Only Bit) (1 bit) - This bit is intended for
          use with the Informational Exchange with a Notify payload and
          will allow the transmission of information with integrity
          checking, but no encryption (e.g.  "emergency mode").  Section
          4.8 states that a Phase 2 Informational Exchange MUST be sent
          under the protection of an ISAKMP SA. This is the only
          exception to that policy.  If the Authentication Only bit is
          set (1), only authentication security services will be applied
          to the entire Notify payload of the Informational Exchange and
          the payload will not be encrypted.

    o  Message ID (4 octets) - Unique Message Identifier used to
       identify protocol state during Phase 2 negotiations.  This value
       is randomly generated by the initiator of the Phase 2
       negotiation.  In the event of simultaneous SA establishments
       (i.e.  collisions), the value of this field will likely be
       different because they are independently generated and, thus, two
       security associations will progress toward establishment.
       However, it is unlikely there will be absolute simultaneous
       establishments.  During Phase 1 negotiations, the value MUST be
       set to 0.

    o  Length (4 octets) - Length of total message (header + payloads)
       in octets.  Encryption can expand the size of an ISAKMP message.

*/

#define RHP_PROTO_PORT_IKE        	500
#define RHP_PROTO_PORT_IKE_NATT   	4500

#define RHP_PROTO_NON_ESP_MARKER    		0x00000000
#define RHP_PROTO_NON_ESP_MARKER_SZ 		4

struct _rhp_proto_ike
{

#define RHP_PROTO_IKE_SPI_SIZE    		8
#define RHP_PROTO_IPSEC_SPI_SIZE  		4
#define RHP_PROTO_SPI_MAX_SIZE    		RHP_PROTO_IKE_SPI_SIZE
  u8  init_spi[RHP_PROTO_IKE_SPI_SIZE];
  u8  resp_spi[RHP_PROTO_IKE_SPI_SIZE];

  u8  next_payload;

#define RHP_PROTO_IKE_VER_MAJOR				2
#define RHP_PROTO_IKE_VER_MINOR				0

#define RHP_PROTO_IKE_V1_VER_MAJOR		1
#define RHP_PROTO_IKE_V1_VER_MINOR		0

#ifdef RHP_BIG_ENDIAN
  u8  ver_major:4,
  ver_minor:4;
#else
  u8  ver_minor:4,
  ver_major:4;
#endif

#define RHP_PROTO_IKE_EXCHG_RESEVED						0
#define RHP_PROTO_IKE_EXCHG_IKE_SA_INIT       34
#define RHP_PROTO_IKE_EXCHG_IKE_AUTH          35
#define RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA   36
#define RHP_PROTO_IKE_EXCHG_INFORMATIONAL     37
#define RHP_PROTO_IKE_EXCHG_SESS_RESUME		    38

#define RHP_PROTO_IKEV1_EXCHG_BASE						1
#define RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION		2
#define RHP_PROTO_IKEV1_EXCHG_AUTH_ONLY				3
#define RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE			4
#define RHP_PROTO_IKEV1_EXCHG_INFORMATIONAL		5
#define RHP_PROTO_IKEV1_EXCHG_TRANSACTION			6
#define RHP_PROTO_IKEV1_EXCHG_QUICK						32
  u8 exchange_type;

#define RHP_PROTO_IKE_HDR_INITIATOR(flag)   	(((flag) & 0x08) ? RHP_TRUE : RHP_FALSE )
#define RHP_PROTO_IKE_HDR_RESPONSE(flag)    	(((flag) & 0x20) ? RHP_TRUE : RHP_FALSE )
#define RHP_PROTO_IKE_HDR_VERSION(flag)     	(((flag) & 0x10) ? RHP_TRUE : RHP_FALSE )

#define RHP_PROTO_IKEV1_HDR_ENCRYPT(flag)  		(((flag) & 0x01) ? RHP_TRUE : RHP_FALSE )
#define RHP_PROTO_IKEV1_HDR_COMMIT(flag)    	(((flag) & 0x02) ? RHP_TRUE : RHP_FALSE )
#define RHP_PROTO_IKEV1_HDR_AUTH_ONLY(flag)  	(((flag) & 0x04) ? RHP_TRUE : RHP_FALSE )

#define RHP_PROTO_IKE_HDR_SET_INITIATOR    		(0x08)
#define RHP_PROTO_IKE_HDR_SET_RESPONSE      	(0x20)
#define RHP_PROTO_IKE_HDR_SET_VERSION					(0x10)

#define RHP_PROTO_IKEV1_HDR_SET_ENCRYPT			(0x01)
#define RHP_PROTO_IKEV1_HDR_SET_COMMIT			(0x02)
#define RHP_PROTO_IKEV1_HDR_SET_AUTH_ONLY		(0x04)
  u8 flag;

  u32 message_id;
  u32 len;
};
typedef struct _rhp_proto_ike rhp_proto_ike;

/*
 - IKEv2

 3.2 Generic Payload Header

   Each IKE payload defined in sections 3.3 through 3.16 begins with a
   generic payload header, shown in Figure 5. Figures for each payload
   below will include the generic payload header but for brevity the
   description of each field will be omitted.

                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                         Figure 5:  Generic Payload Header

   The Generic Payload Header fields are defined as follows:

   o  Next Payload (1 octet) - Identifier for the payload type of the
      next payload in the message.  If the current payload is the last
      in the message, then this field will be 0.  This field provides
      a "chaining" capability whereby additional payloads can be
      added to a message by appending it to the end of the message
      and setting the "Next Payload" field of the preceding payload
      to indicate the new payload's type. An Encrypted payload,
      which must always be the last payload of a message, is an
      exception. It contains data structures in the format of
      additional payloads. In the header of an Encrypted payload,
      the Next Payload field is set to the payload type of the first
      contained payload (instead of 0).

      Payload Type Values

          Next Payload Type               Notation  Value

          No Next Payload                              		0

          RESERVED                                   			1-32
          Security Association            SA         			33
          Key Exchange                    KE         			34
          Identification - Initiator      IDi        			35
          Identification - Responder			IDr        			36
          Certificate                     CERT      			37
          Certificate Request             CERTREQ   			38
          Authentication                  AUTH       			39
          Nonce                           Ni, Nr     			40
          Notify                          N          			41
          Delete                          D          			42
          Vendor ID                       V          			43
          Traffic Selector - Initiator    TSi        			44
          Traffic Selector - Responder		TSr        			45
          Encrypted                       E          			46
          Configuration                   CP         			47
          Extensible Authentication				EAP        			48
          RESERVED TO IANA                								49-127
          PRIVATE USE                              				128-255

      Payload type values 1-32 should not be used so that there is no
      overlap with the code assignments for IKEv1.  Payload type values
      49-127 are reserved to IANA for future assignment in IKEv2 (see
      section 6). Payload type values 128-255 are for private use among
      mutually consenting parties.

   o  Critical (1 bit) - MUST be set to zero if the sender wants
      the recipient to skip this payload if it does not
      understand the payload type code in the Next Payload field
      of the previous payload. MUST be set to one if the
      sender wants the recipient to reject this entire message
      if it does not undeerrrstand the payload type. MUST be ignored
      by the recipient if the recipient understands the payload type
      code. MUST be set to zero for payload types defined in this
      document. Note that the critical bit applies to the current
      payload rather than the "next" payload whose type code
      appears in the first octet. The reasoning behind not setting
      the critical bit for payloads defined in this document is
      that all implementations MUST understand all payload types
      defined in this document and therefore must ignore the
      Critical bit's value. Skipped payloads are expected to
      have valid Next Payload and Payload Length fields.

   o  RESERVED (7 bits) - MUST be sent as zero; MUST be ignored on
      receipt.

   o  Payload Length (2 octets) - Length in octets of the current
      payload, including the generic payload header.
*/

/*

 - IKEv1 (RFC2408)

3.2 Generic Payload Header

   Each ISAKMP payload defined in sections 3.4 through 3.16 begins with
   a generic header, shown in Figure 3, which provides a payload
   "chaining" capability and clearly defines the boundaries of a
   payload.

                            1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       ! Next Payload  !   RESERVED    !         Payload Length        !
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                   Figure 3:  Generic Payload Header

   The Generic Payload Header fields are defined as follows:

    o  Next Payload (1 octet) - Identifier for the payload type of the
       next payload in the message.  If the current payload is the last
       in the message, then this field will be 0.  This field provides
       the "chaining" capability.

    o  RESERVED (1 octet) - Unused, set to 0.

    o  Payload Length (2 octets) - Length in octets of the current
       payload, including the generic payload header.
*/

struct _rhp_proto_ike_payload
{

#define RHP_PROTO_IKE_NO_MORE_PAYLOADS   0
#define RHP_PROTO_IKE_PAYLOAD_SA         33
#define RHP_PROTO_IKE_PAYLOAD_KE         34
#define RHP_PROTO_IKE_PAYLOAD_ID_I       35
#define RHP_PROTO_IKE_PAYLOAD_ID_R       36
#define RHP_PROTO_IKE_PAYLOAD_CERT       37
#define RHP_PROTO_IKE_PAYLOAD_CERTREQ    38
#define RHP_PROTO_IKE_PAYLOAD_AUTH       39
#define RHP_PROTO_IKE_PAYLOAD_N_I_R      40
#define RHP_PROTO_IKE_PAYLOAD_N          41
#define RHP_PROTO_IKE_PAYLOAD_D          42
#define RHP_PROTO_IKE_PAYLOAD_V          43
#define RHP_PROTO_IKE_PAYLOAD_TS_I       44
#define RHP_PROTO_IKE_PAYLOAD_TS_R       45
#define RHP_PROTO_IKE_PAYLOAD_E          46
#define RHP_PROTO_IKE_PAYLOAD_CP         47
#define RHP_PROTO_IKE_PAYLOAD_EAP        48
#define RHP_PROTO_IKE_PAYLOAD_GSPM			 49 // [RFC6467]
#define RHP_PROTO_IKE_PAYLOAD_IDG        50 // [draft-yeung-g-ikev2]
#define RHP_PROTO_IKE_PAYLOAD_GSA        51 // [draft-yeung-g-ikev2]
#define RHP_PROTO_IKE_PAYLOAD_KD	       52 // [draft-yeung-g-ikev2]
#define RHP_PROTO_IKE_PAYLOAD_SKF				 53 // [RFC7383]
// See the following links to get details.
//  - [MS-IKEE]: Internet Key Exchange Protocol Extensions
//    http://msdn.microsoft.com/en-us/library/cc233219(v=prot.10).aspx
#define RHP_PROTO_IKE_PAYLOAD_MS_CORRELATION	200

#define RHP_PROTO_IKE_PAYLOAD_RHP_STUN		247


#define RHP_PROTO_IKEV1_PAYLOAD_SA			1
#define RHP_PROTO_IKEV1_PAYLOAD_P				2
#define RHP_PROTO_IKEV1_PAYLOAD_T				3
#define RHP_PROTO_IKEV1_PAYLOAD_KE			4
#define RHP_PROTO_IKEV1_PAYLOAD_ID			5
#define RHP_PROTO_IKEV1_PAYLOAD_CERT		6
#define RHP_PROTO_IKEV1_PAYLOAD_CR			7
#define RHP_PROTO_IKEV1_PAYLOAD_HASH		8
#define RHP_PROTO_IKEV1_PAYLOAD_SIG			9
#define RHP_PROTO_IKEV1_PAYLOAD_NONCE		10
#define RHP_PROTO_IKEV1_PAYLOAD_N				11
#define RHP_PROTO_IKEV1_PAYLOAD_D				12
#define RHP_PROTO_IKEV1_PAYLOAD_VID			13
#define RHP_PROTO_IKEV1_PAYLOAD_ATTR		14
#define RHP_PROTO_IKEV1_PAYLOAD_NAT_D		20
#define RHP_PROTO_IKEV1_PAYLOAD_NAT_OA	21
  u8  next_payload;

#define RHP_PROTO_IKE_PLD_CRITICAL(critical_rsv)  	((critical_rsv) & 0x80)
#define RHP_PROTO_IKE_PLD_SET_CRITICAL            	(0x80)
  u8 critical_rsv;

  u16 len;
};
typedef struct _rhp_proto_ike_payload rhp_proto_ike_payload;

/*

 3.3 Security Association Payload

                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                          <Proposals>                          ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

               Figure 6:  Security Association Payload

      o  Proposals (variable) - one or more proposal substructures.

     The payload type for the Security Association Payload is thirty
      three (33).
*/
typedef rhp_proto_ike_payload rhp_proto_ike_sa_payload;

/*

  [ Supproted SA payload structure ]

  - IKE SA : Proposals with the same 'Proposal #' (i.e ANDed proposals) not supported...Sorry!

    1. PROPOSAL(1,IKE,spi(xxx or 0)) {
         TRANSFORM(3DES) or TRANSFORM(AES128) or ...
         and
         TRANSFORM(HMAC-MD5) or TRANSFORM(HMAC-SHA1) or ...
         and
         TRANSFORM(HMAC-MD5-96) or TRANSFORM(HMAC-SHA1-96) or ...
         and
         TRANSFORM(D-H-GRP2) or TRANSFORM(D-H-GRP5) or ...
        }

    2. PROPOSAL(1,IKE,spi(xxx or 0)) {
        TRANSFORM(3DES) or TRANSFORM(AES128) or ...
        and
        TRANSFORM(HMAC-MD5) or TRANSFORM(HMAC-SHA1) or ...
        and
        TRANSFORM(HMAC-MD5-96) or TRANSFORM(HMAC-SHA1-96) or ...
        and
        TRANSFORM(D-H-GRP2) or TRANSFORM(D-H-GRP5) or ...
       }
      or
      PROPOSAL(2,IKE.spi(yyy or 0)) {
        TRANSFORM(3DES) or TRANSFORM(AES128) or ...
        and
        TRANSFORM(HMAC-MD5) or TRANSFORM(HMAC-SHA1) or ...
        and
        TRANSFORM(HMAC-MD5-96) or TRANSFORM(HMAC-SHA1-96) or ...
        and
          TRANSFORM(D-H-GRP2) or TRANSFORM(D-H-GRP5) or ...
      }
      or
      ...

  - CHILD SA : SA bundle not supported...Sorry!
               (So proposals with the same 'Proposal #' (i.e ANDed proposals) not supported...)
                AH not supported... Sorry! (Use ESP-NULL.)

    1. PROPOSAL(1,ESP,spi(xxx)) {
        TRANSFORM(3DES) or TRANSFORM(AES128) or ...
        and
        TRANSFORM(HMAC-MD5-96) or TRANSFORM(HMAC-SHA1-96) or ...
        and
        TRANSFORM(D-H-GRP2) or TRANSFORM(D-H-GRP5) or ...
       }

    2. PROPOSAL(1,ESP,spi(xxx)) {
         TRANSFORM(3DES) or TRANSFORM(AES128) or ...
         and
         TRANSFORM(HMAC-MD5-96) or TRANSFORM(HMAC-SHA1-96) or ...
         and
         TRANSFORM(D-H-GRP2) or TRANSFORM(D-H-GRP5) or ...
         and
         TRANSFORM(NO-ESN) or TRANSFORM(ESN)
        }
        or
        PROPOSAL(2,ESP,spi(yyy)) {
         TRANSFORM(3DES) or TRANSFORM(AES128) or ...
         and
         TRANSFORM(HMAC-MD5-96) or TRANSFORM(HMAC-SHA1-96) or ...
         and
         TRANSFORM(D-H-GRP2) or TRANSFORM(D-H-GRP5) or ...
         and
         TRANSFORM(NO-ESN) or TRANSFORM(ESN)
        }
        or
        ...
*/


/*

 3.3.1 Proposal Substructure

                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! 0 (last) or 2 !   RESERVED    !         Proposal Length       !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Proposal #    !  Protocol ID  !    SPI Size   !# of Transforms!
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ~                        SPI (variable)                         ~
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                        <Transforms>                           ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

               Figure 7:  Proposal Substructure

      o  0 (last) or 2 (more) (1 octet) - Specifies whether this is thget_next_payloade
         last Proposal Substructure in the SA. This syntax is inherited
         from ISAKMP, but is unnecessary because the last Proposal
         could be identified from the length of the SA. The value (2)
         corresponds to a Payload Type of Proposal in IKEv1, and the
         first four octets of the Proposal structure are designed to
         look somewhat like the header of a Payload.

      o  RESERVED (1 octet) - MUST be sent as zero; MUST be ignored on
         receipt.

      o  Proposal Length (2 octets) - Length of this proposal,
         including all transforms and attributes that follow.

      o  Proposal # (1 octet) - When a proposal is made, the first
         proposal in an SA payload MUST be #1, and subsequent proposals
         MUST either be the same as the previous proposal (indicating
         an AND of the two proposals) or one more than the previous
         proposal (indicating an OR of the two proposals). When a
         proposal is accepted, all of the proposal numbers in the
         SA payload MUST be the same and MUST match the number on the
         proposal sent that was accepted.

      o  Protocol ID (1 octet) - Specifies the IPsec protocol
         identifier for the current negotiation. The defined values
         are:

          Protocol               Protocol ID
          RESERVED                0
          IKE                     1
          AH                      2
          ESP                     3
          RESERVED TO IANA        4-200
          PRIVATE USE             201-255


      o  SPI Size (1 octet) - For an initial IKE_SA negotiation,
         this field MUST be zero; the SPI is obtained from the
         outer header. During subsequent negotiations,
         it is equal to the size, in octets, of the SPI of the
         corresponding protocol (8 for IKE, 4 for ESP and AH).

      o  # of Transforms (1 octet) - Specifies the number of
         transforms in this proposal.

      o  SPI (variable) - The sending entity's SPI. Even if the SPI
         Size is not a multiple of 4 octets, there is no padding
         applied to the payload. When the SPI Size field is zero,
         this field is not present in the Security Association
         payload.

      o  Transforms (variable) - one or more transform substructures.
*/
struct _rhp_proto_ike_proposal
{

#define RHP_PROTO_IKE_PROPOSAL_LAST   0
#define RHP_PROTO_IKE_PROPOSAL_MORE   2
  u8  last_or_more; // last(0),more(2)
  u8  reserved;
  u16 len;
  u8  proposal_number;

#define RHP_PROTO_IKE_PROTOID_IKE       	1
#define RHP_PROTO_IKE_PROTOID_AH        	2
#define RHP_PROTO_IKE_PROTOID_ESP       	3
  u8  protocol;

  u8  spi_len;
  u8  transform_num;
};
typedef struct _rhp_proto_ike_proposal  rhp_proto_ike_proposal;


/*

 3.3.2 Transform Substructure

                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! 0 (last) or 3 !   RESERVED    !        Transform Length       !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !Transform Type !   RESERVED    !          Transform ID         !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                      Transform Attributes                     ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

               Figure 8:  Transform Substructure

   o  0 (last) or 3 (more) (1 octet) - Specifies whether this is the
      last Transform Substructure in the Proposal. This syntax is
      inherited from ISAKMP, but is unnecessary because the last
      Proposal could be identified from the length of the SA. The
      value (3) corresponds to a Payload Type of Transform in IKEv1,
      and the first four octets of the Transform structure are
      designed to look somewhat like the header of a Payload.

   o  RESERVED - MUST be sent as zero; MUST be ignored on receipt.

   o  Transform Length - The length (in octets) of the Transform
      Substructure including Header and Attributes.

   o  Transform Type (1 octet) - The type of transform being specified
      in this transform. Different protocols support different
      transform types. For some protocols, some of the transforms
      may be optional. If a transform is optional and the initiator
      wishes to propose that the transform be omitted, no transform
      of the given type is included in the proposal. If the
      initiator wishes to make use of the transform optional to
      the responder, it includes a transform substructure with
      transform ID = 0 as one of the options.

   o  Transform ID (2 octets) - The specific instance of the transform
      type being proposed.

   Transform Type Values

                                     Transform    Used In
                                        Type
          RESERVED                        0
          Encryption Algorithm (ENCR)     1  (IKE and ESP)
          Pseudo-random Function (PRF)    2  (IKE)
          Integrity Algorithm (INTEG)     3  (IKE, AH, optional in ESP)
          Diffie-Hellman Group (D-H)      4  (IKE, optional in AH & ESP)
          Extended Sequence Numbers (ESN) 5  (Optional in AH and ESP)
          RESERVED TO IANA                6-240
          PRIVATE USE                     241-255

   For Transform Type 1 (Encryption Algorithm), defined Transform IDs
   are:

          Name                     Number           Defined In
          RESERVED                    0
          ENCR_DES_IV64               1              (RFC1827)
          ENCR_DES                    2              (RFC2405)
          ENCR_3DES                   3              (RFC2451)
          ENCR_RC5                    4              (RFC2451)
          ENCR_IDEA                   5              (RFC2451)
          ENCR_CAST                   6              (RFC2451)
          ENCR_BLOWFISH               7              (RFC2451)
          ENCR_3IDEA                  8              (RFC2451)
          ENCR_DES_IV32               9
          RESERVED                   10
          ENCR_NULL                  11              (RFC2410)
          ENCR_AES_CBC               12              (RFC3602)
          ENCR_AES_CTR               13              (RFC3664)

          values 14-1023 are reserved to IANA. Values 1024-65535 are for
          private use among mutually consenting parties.

   For Transform Type 2 (Pseudo-random Function), defined Transform IDs
   are:

          Name                     Number                 Defined In
          RESERVED                    0
          PRF_HMAC_MD5                1                   (RFC2104)
          PRF_HMAC_SHA1               2                   (RFC2104)
          PRF_HMAC_TIGER              3                   (RFC2104)
          PRF_AES128_CBC              4                   (RFC3664)

          values 5-1023 are reserved to IANA. Values 1024-65535 are for
          private use among mutually consenting parties.


   For Transform Type 3 (Integrity Algorithm), defined Transform IDs
   are:

          Name                     Number                 Defined In
          NONE                       0
          AUTH_HMAC_MD5_96           1                     (RFC2403)
          AUTH_HMAC_SHA1_96          2                     (RFC2404)
          AUTH_DES_MAC               3
          AUTH_KPDK_MD5              4                     (RFC1826)
          AUTH_AES_XCBC_96           5                     (RFC3566)

          values 6-1023 are reserved to IANA. Values 1024-65535 are for
          private use among mutually consenting parties.

   For Transform Type 4 (Diffie-Hellman Group), defined Transform IDs
   are:

          Name                                Number
          NONE                               0
          Defined in Appendix B              1 - 2
          RESERVED                           3 - 4
          Defined in [ADDGROUP]              5
          RESERVED TO IANA                   6 - 13
          Defined in [ADDGROUP]              14 - 18
          RESERVED TO IANA                   19 - 1023
          PRIVATE USE                        1024-65535


   For Transform Type 5 (Extended Sequence Numbers), defined Transform
   IDs are:

          Name                                Number
          No Extended Sequence Numbers       0
          Extended Sequence Numbers          1
          RESERVED                           2 - 65535

          If Transform Type 5 is not included in a proposal, use of
          Extended Sequence Numbers is assumed.
*/

struct _rhp_proto_ike_transform
{

#define RHP_PROTO_IKE_TRANSFORM_LAST   	0
#define RHP_PROTO_IKE_TRANSFORM_MORE  	3
  u8  last_or_more; // last(0),more(3)
  u8  reserved1;
  u16 len;

#define RHP_PROTO_IKE_TRANSFORM_TYPE_RESERVED   0
#define RHP_PROTO_IKE_TRANSFORM_TYPE_ENCR       1
#define RHP_PROTO_IKE_TRANSFORM_TYPE_PRF        2
#define RHP_PROTO_IKE_TRANSFORM_TYPE_INTEG      3
#define RHP_PROTO_IKE_TRANSFORM_TYPE_DH         4
#define RHP_PROTO_IKE_TRANSFORM_TYPE_ESN        5
#define RHP_PROTO_IKE_TRANSFORM_TYPE_MAX        5
  u8  transform_type;
  u8  reserved2;

#define RHP_PROTO_IKE_TRANSFORM_ID_ENCR_DES_IV64       	1
#define RHP_PROTO_IKE_TRANSFORM_ID_ENCR_DES             2
#define RHP_PROTO_IKE_TRANSFORM_ID_ENCR_3DES            3
#define RHP_PROTO_IKE_TRANSFORM_ID_ENCR_RC5             4
#define RHP_PROTO_IKE_TRANSFORM_ID_ENCR_IDEA            5
#define RHP_PROTO_IKE_TRANSFORM_ID_ENCR_CAST            6
#define RHP_PROTO_IKE_TRANSFORM_ID_ENCR_BLOWFISH				7
#define RHP_PROTO_IKE_TRANSFORM_ID_ENCR_3IDEA           8
#define RHP_PROTO_IKE_TRANSFORM_ID_ENCR_DES_IV32        9
#define RHP_PROTO_IKE_TRANSFORM_ID_ENCR_NULL            11
#define RHP_PROTO_IKE_TRANSFORM_ID_ENCR_AES_CBC					12
#define RHP_PROTO_IKE_TRANSFORM_ID_ENCR_AES_CTR					13
#define RHP_PROTO_IKE_TRANSFORM_ID_ENCR_NUM							13

#define RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_MD5				1
#define RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA1      2
#define RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_TIGER     3
#define RHP_PROTO_IKE_TRANSFORM_ID_PRF_AES128_CBC     4
#define RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_256  5
#define RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_384  6
#define RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_512  7
#define RHP_PROTO_IKE_TRANSFORM_ID_PRF_NUM            7

#define RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_MD5_96     		1
#define RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA1_96    		2
#define RHP_PROTO_IKE_TRANSFORM_ID_AUTH_DES_MAC         		3
#define RHP_PROTO_IKE_TRANSFORM_ID_AUTH_KPDK_MD5        		4
#define RHP_PROTO_IKE_TRANSFORM_ID_AUTH_AES_XCBC_96     		5
#define RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_256_128  	12
#define RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_384_192  	13
#define RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_512_256  	14
#define RHP_PROTO_IKE_TRANSFORM_ID_AUTH_NUM             		8

#define RHP_PROTO_IKE_TRANSFORM_ID_DH_1         	1
#define RHP_PROTO_IKE_TRANSFORM_ID_DH_2         	2
#define RHP_PROTO_IKE_TRANSFORM_ID_DH_5         	5
#define RHP_PROTO_IKE_TRANSFORM_ID_DH_14        	14
#define RHP_PROTO_IKE_TRANSFORM_ID_DH_15        	15
#define RHP_PROTO_IKE_TRANSFORM_ID_DH_16        	16
#define RHP_PROTO_IKE_TRANSFORM_ID_DH_17        	17
#define RHP_PROTO_IKE_TRANSFORM_ID_DH_18        	18
#define RHP_PROTO_IKE_TRANSFORM_ID_DH_NUM      		18

#define RHP_PROTO_IKE_TRANSFORM_ESN_DISABLE     	0
#define RHP_PROTO_IKE_TRANSFORM_ESN_ENABLE      	1
#define RHP_PROTO_IKE_TRANSFORM_ESN_NUM         	1
  u16 transform_id;
};
typedef struct _rhp_proto_ike_transform rhp_proto_ike_transform;


/*

 3.3.5 Transform Attributes

   Each transform in a Security Association payload may include
   attributes that modify or complete the specification of the
   transform. These attributes are type/value pairs and are defined
   below. For example, if an encryption algorithm has a variable length
   key, the key length to be used may be specified as an attribute.
   Attributes can have a value with a fixed two octet length or a
   variable length value. For the latter, the attribute is encoded as
   type/length/value.

                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !A!       Attribute Type        !    AF=0  Attribute Length     !
      !F!                             !    AF=1  Attribute Value      !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                   AF=0  Attribute Value                       !
      !                   AF=1  Not Transmitted                       !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                      Figure 9:  Data Attributes

      o  Attribute Type (2 octets) - Unique identifier for each type of
         attribute (see below).
         The most significant bit of this field is the Attribute Format
         bit (AF). It indicates whether the data attributes follow the
         Type/Length/Value (TLV) format or a shortened Type/Value (TV)
         format.  If the AF bit is zero (0), then the Data Attributes
         are of the Type/Length/Value (TLV) form. If the AF bit is a
         one (1), then the Data Attributes are of the Type/Value form.

      o  Attribute Length (2 octets) - Length in octets of the Attribute
         Value.  When the AF bit is a one (1), the Attribute Value is
         only 2 octets and the Attribute Length field is not present.

      o  Attribute Value (variable length) - Value of the Attribute
         associated with the Attribute Type.  If the AF bit is a
         zero (0), this field has a variable length defined by the
         Attribute Length field.  If the AF bit is a one (1), the
         Attribute Value has a length of 2 octets.

   Note that only a single attribute type (Key Length) is defined, and
   it is fixed length. The variable length encoding specification is
   included only for future extensions.  The only algorithms defined in
   this document that accept attributes are the AES based encryption,
   integrity, and pseudo-random functions, which require a single
   attribute specifying key width.

   Attributes described as basic MUST NOT be encoded using the variable
   length encoding.  Variable length attributes MUST NOT be encoded as
   basic even if their value can fit into two octets. NOTE: This is a
   change from IKEv1, where increased flexibility may have simplified
   the composer of messages but certainly complicated the parser.

         Attribute Type                 value        Attribute Format
      --------------------------------------------------------------
      RESERVED                           0-13
      Key Length (in bits)               14                 TV
      RESERVED                           15-17
      RESERVED TO IANA                   18-16383
      PRIVATE USE                        16384-32767

   Values 0-13 and 15-17 were used in a similar context in IKEv1, and
   should not be assigned except to matching values. Values 18-16383 are
   reserved to IANA. Values 16384-32767 are for private use among
   mutually consenting parties.

   - Key Length

      When using an Encryption Algorithm that has a variable length key,
      this attribute specifies the key length in bits. (MUST use network
      byte order). This attribute MUST NOT be used when the specified
      Encryption Algorithm uses a fixed length key.
*/
struct _rhp_proto_ike_attr
{

#define RHP_PROTO_IKE_ATTR_KEYLEN 	14 // bits

#ifdef RHP_BIG_ENDIAN
#define RHP_PROTO_IKE_ATTR_TYPE(attr_type)    	ntohs((attr_type & 0x7FFF))
#define RHP_PROTO_IKE_ATTR_AF(attr_type)      	(attr_type & 0x8000)
#define RHP_PROTO_IKE_ATTR_SET_AF(attr_type)  	(attr_type | 0x8000)
#else
#define RHP_PROTO_IKE_ATTR_TYPE(attr_type)    	ntohs((attr_type & 0xFF7F))
#define RHP_PROTO_IKE_ATTR_AF(attr_type)      	(attr_type & 0x0080)
#define RHP_PROTO_IKE_ATTR_SET_AF(attr_type)  	(attr_type | 0x0080)
#endif
  u16 attr_type;

  u16 len_or_value; // AF(0) : Attr Length , AF(1) : Attr Value
};
typedef struct _rhp_proto_ike_attr rhp_proto_ike_attr;


/*

 3.4 Key Exchange Payload

                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !          DH Group #           !           RESERVED            !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                       Key Exchange Data                       ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                Figure 10:  Key Exchange Payload Format
*/

struct _rhp_proto_ike_ke_payload
{

  u8  next_payload;

  u8 critical_rsv;

  u16 len;
  u16 dh_group;
  u16 reserved2;
};
typedef struct _rhp_proto_ike_ke_payload  rhp_proto_ike_ke_payload;

/*

 3.5 Identification Payloads

                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !   ID Type     !                 RESERVED                      |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                   Identification Data                         ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

               Figure 11:  Identification Payload Format

   o  ID Type (1 octet) - Specifies the type of Identification being
      used.

   o  RESERVED - MUST be sent as zero; MUST be ignored on receipt.

   o  Identification Data (variable length) - Value, as indicated by
      the Identification Type. The length of the Identification Data
      is computed from the size in the ID payload header.

   The payload types for the Identification Payload are thirty five (35)
   for IDi and thirty six (36) for IDr.

   The following table lists the assigned values for the Identification
   Type field, followed by a description of the Identification Data
   which follows:

      ID Type                           Value
      -------                           -----
      RESERVED                            0

      ID_IPV4_ADDR                        1

            A single four (4) octet IPv4 address.

      ID_FQDN                             2

            A fully-qualified domain name string.  An example of a
            ID_FQDN is, "example.com".  The string MUST not contain any
            terminators (e.g., NULL, CR, etc.).

      ID_RFC822_ADDR                      3

            A fully-qualified RFC822 email address string, An example of
            a ID_RFC822_ADDR is, "jsmith@example.com".  The string MUST
            not contain any terminators.

      Reserved to IANA                    4

      ID_IPV6_ADDR                        5

            A single sixteen (16) octet IPv6 address.

      Reserved to IANA                    6 - 8

      ID_DER_ASN1_DN                      9

            The binary DER encoding of an ASN.1 X.500 Distinguished Name
            [X.501].

      ID_DER_ASN1_GN                      10

            The binary DER encoding of an ASN.1 X.500 GeneralName
            [X.509].

      ID_KEY_ID                           11

            An opaque octet stream which may be used to pass vendor-
            specific information necessary to do certain proprietary
            types of identification.

      Reserved to IANA                    12-200

      Reserved for private use            201-255
*/

struct _rhp_proto_ike_id_payload
{

  u8  next_payload;

  u8 critical_rsv;

  u16 len;

#define RHP_PROTO_IKE_ID_ANY           0 // Reserved value by IANA.
#define RHP_PROTO_IKE_ID_IPV4_ADDR     1
#define RHP_PROTO_IKE_ID_FQDN          2
#define RHP_PROTO_IKE_ID_RFC822_ADDR   3
#define RHP_PROTO_IKE_ID_UNASSIGNED4   4
#define RHP_PROTO_IKE_ID_IPV6_ADDR     5
#define RHP_PROTO_IKE_ID_UNASSIGNED6   6
#define RHP_PROTO_IKE_ID_UNASSIGNED7   7
#define RHP_PROTO_IKE_ID_UNASSIGNED8   8
#define RHP_PROTO_IKE_ID_DER_ASN1_DN   9
#define RHP_PROTO_IKE_ID_DER_ASN1_GN   10
#define RHP_PROTO_IKE_ID_KEY_ID        11
#define RHP_PROTO_IKE_ID_FC_NAME       12 // [NOTICE] IKEv1's ID_LIST is assigned to the same number.
#define RHP_PROTO_IKE_ID_NULL_ID			 13

// Internal user only!
#define RHP_PROTO_IKE_ID_PRIVATE_SUBJECTALTNAME     	10000 // > 255(sizeof(u8)). Intenal use only!
#define RHP_PROTO_IKE_ID_PRIVATE_CERT_AUTO          	10001 // > 255(sizeof(u8)). Intenal use only!
#define RHP_PROTO_IKE_ID_PRIVATE_NOT_RESOLVED         10002 // > 255(sizeof(u8)). Intenal use only!
#define RHP_PROTO_IKE_ID_PRIVATE_NULL_ID_WITH_ADDR		10003 // > 255(sizeof(u8)). Intenal use only!
  u8  id_type;
  u8  reserved1;
  u16 reserved2;
};
typedef struct _rhp_proto_ike_id_payload                rhp_proto_ike_id_payload;

/*

 3.6 Certificate Payload

                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Cert Encoding !                                               !
      +-+-+-+-+-+-+-+-+                                               !
      ~                       Certificate Data                        ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                Figure 12:  Certificate Payload Format

      o  Certificate Encoding (1 octet) - This field indicates the type
         of certificate or certificate-related information contained
         in the Certificate Data field.

           Certificate Encoding               Value
           --------------------               -----
           RESERVED                             0
           PKCS #7 wrapped X.509 certificate    1
           PGP Certificate                      2
           DNS Signed Key                       3
           X.509 Certificate - Signature        4
           Kerberos Token                       6
           Certificate Revocation List (CRL)    7
           Authority Revocation List (ARL)      8
           SPKI Certificate                     9
           X.509 Certificate - Attribute       10
           Raw RSA Key                         11
           Hash and URL of X.509 certificate   12
           Hash and URL of X.509 bundle        13
           RESERVED to IANA                  14 - 200
           PRIVATE USE                      201 - 255

      o  Certificate Data (variable length) - Actual encoding of
         certificate data.  The type of certificate is indicated
         by the Certificate Encoding field.
*/

struct _rhp_proto_ike_cert_payload
{

  u8  next_payload;

  u8 critical_rsv;

  u16 len;

#define RHP_PROTO_IKE_CERTENC_PKCS7_X509_CERT       		1
#define RHP_PROTO_IKE_CERTENC_PGP_CERT              		2
#define RHP_PROTO_IKE_CERTENC_DNS_SIGNED_KEY        		3
#define RHP_PROTO_IKE_CERTENC_X509_CERT_SIG         		4
#define RHP_PROTO_IKE_CERTENC_KERBEROS_TOKEN        		6
#define RHP_PROTO_IKE_CERTENC_CRL                   		7
#define RHP_PROTO_IKE_CERTENC_ARL                   		8
#define RHP_PROTO_IKE_CERTENC_SPKI_CERT             		9
#define RHP_PROTO_IKE_CERTENC_X509_CERT_ATTR        		10
#define RHP_PROTO_IKE_CERTENC_RAW_RSA_KEY           		11
#define RHP_PROTO_IKE_CERTENC_X509_CERT_HASH_URL    		12
#define RHP_PROTO_IKE_CERTENC_X509_BUNDLE_HASH_URL  		13
  u8  cert_encoding;
};
typedef struct _rhp_proto_ike_cert_payload  rhp_proto_ike_cert_payload;

/*

 3.7 Certificate Request Payload

                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Cert Encoding !                                               !
      +-+-+-+-+-+-+-+-+                                               !
      ~                    Certification Authority                    ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Figure 13:  Certificate Request Payload Format

   o  Certificate Encoding (1 octet) - Contains an encoding of the type
      or format of certificate requested. Values are listed in section
      3.6.

   o  Certification Authority (variable length) - Contains an encoding
      of an acceptable certification authority for the type of
      certificate requested.
*/

struct _rhp_proto_ike_certreq_payload
{

  u8  next_payload;

  u8 critical_rsv;

#define RHP_PROTO_IKE_CERTENC_SHA1_DIGEST_LEN 20
  u16 len;

  u8 cert_encoding;
};
typedef struct _rhp_proto_ike_certreq_payload rhp_proto_ike_certreq_payload;

/*

 3.8 Authentication Payload

   The Authentication Payload, denoted AUTH in this memo, contains data
   used for authentication purposes. The syntax of the Authentication
   data varies according to the Auth Method as specified below.

   The Authentication Payload is defined as follows:

                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Auth Method   !                RESERVED                       !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                      Authentication Data                      ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                 Figure 14:  Authentication Payload Format

   o  Auth Method (1 octet) - Specifies the method of authentication
      used. Values defined are:

        RSA Digital Signature (1) - Computed as specified in section
        2.15 using an RSA private key over a PKCS#1 padded hash.

        Shared Key Message Integrity Code (2) - Computed as specified in
        section 2.15 using the shared key associated with the identity
        in the ID payload and the negotiated prf function

        DSS Digital Signature (3) - Computed as specified in section
        2.15 using a DSS private key over a SHA-1 hash.

        The values 0 and 4-200 are reserved to IANA. The values 201-255
        are available for private use.

   o  Authentication Data (variable length) - see section 2.15.

*/

#define RHP_PROTO_IKE_AUTH_KEYPAD  "Key Pad for IKEv2"

struct _rhp_proto_ike_auth_payload
{

  u8  next_payload;

  u8 critical_rsv;

  u16 len;

#define RHP_PROTO_IKE_AUTHMETHOD_NONE					0
#define RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG      1
#define RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY   2
#define RHP_PROTO_IKE_AUTHMETHOD_DSS_SIG      3
#define RHP_PROTO_IKE_AUTHMETHOD_UNASSIGNED4	4
#define RHP_PROTO_IKE_AUTHMETHOD_UNASSIGNED5	5
#define RHP_PROTO_IKE_AUTHMETHOD_UNASSIGNED6	6
#define RHP_PROTO_IKE_AUTHMETHOD_UNASSIGNED7	7
#define RHP_PROTO_IKE_AUTHMETHOD_UNASSIGNED8	8
#define RHP_PROTO_IKE_AUTHMETHOD_ECDSA_SHA_256 	9
#define RHP_PROTO_IKE_AUTHMETHOD_ECDSA_SHA_384	10
#define RHP_PROTO_IKE_AUTHMETHOD_ECDSA_SHA_512	11
#define RHP_PROTO_IKE_AUTHMETHOD_GSPM						12
#define RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH			13
#define RHP_PROTO_IKE_AUTHMETHOD_DIGITAL_SIG		14

// For IKEv1/XAUTH. Actually, these are used for rhp_proto_ikev1_attr [IKEv1 SA payload].
#define RHP_PROTO_IKE_AUTHMETHOD_XAUTH_INIT_PSK			65001
#define RHP_PROTO_IKE_AUTHMETHOD_XAUTH_RESP_PSK			65002
#define RHP_PROTO_IKE_AUTHMETHOD_XAUTH_INIT_RSASIG	65005
#define RHP_PROTO_IKE_AUTHMETHOD_XAUTH_RESP_RSASIG	65006
#define RHP_PROTO_IKE_AUTHMETHOD_HYBRID_INIT_RSASIG	64221
#define RHP_PROTO_IKE_AUTHMETHOD_HYBRID_RESP_RSASIG	64222
  u8 auth_method;

  u8  reserved1;
  u16 reserved2;
};
typedef struct _rhp_proto_ike_auth_payload    rhp_proto_ike_auth_payload;


/*

 3.9 Nonce Payload

                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                            Nonce Data                         ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                   Figure 15:  Nonce Payload Format

   o  Nonce Data (variable length) - Contains the random data generated
      by the transmitting entity.
*/

typedef rhp_proto_ike_payload rhp_proto_ike_nonce_payload;

#define RHP_PROTO_IKE_NONCE_MIN_SZ      16
#define RHP_PROTO_IKE_NONCE_MAX_SZ     256


/*

 3.10 Notify Payload

                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !  Protocol ID  !   SPI Size    !      Notify Message Type      !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                Security Parameter Index (SPI)                 ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                       Notification Data                       ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

               Figure 16:  Notification Payload Format

   o  Protocol ID (1 octet) - If this notification concerns
      an existing SA, this field indicates the type of that SA.
      For IKE_SA notifications, this field MUST be one (1). For
      notifications concerning IPsec SAs this field MUST contain
      either (2) to indicate AH or (3) to indicate ESP. For
      notifications which do not relate to an existing SA, this
      field MUST be sent as zero and MUST be ignored on receipt.
      All other values for this field are reserved to IANA for future
      assignment.

   o  SPI Size (1 octet) - Length in octets of the SPI as defined by
      the IPsec protocol ID or zero if no SPI is applicable.  For a
      notification concerning the IKE_SA, the SPI Size MUST be zero.

   o  Notify Message Type (2 octets) - Specifies the type of
      notification message.

   o  SPI (variable length) - Security Parameter Index.

   o  Notification Data (variable length) - Informational or error data
      transmitted in addition to the Notify Message Type. Values for
      this field are type specific (see below).

 3.10.1 Notify Message Types

        NOTIFY MESSAGES - ERROR TYPES           Value
        -----------------------------           -----
        RESERVED                                  0

        UNSUPPORTED_CRITICAL_PAYLOAD              1

            Sent if the payload has the "critical" bit set and the
            payload type is not recognized. Notification Data contains
            the one octet payload type.

        INVALID_IKE_SPI                           4

            Indicates an IKE message was received with an unrecognized
            destination SPI. This usually indicates that the recipient
            has rebooted and forgotten the existence of an IKE_SA.

        INVALID_MAJOR_VERSION                     5

            Indicates the recipient cannot handle the version of IKE
            specified in the header. The closest version number that the
            recipient can support will be in the reply header.

        INVALID_SYNTAX                            7

            Indicates the IKE message was received was invalid because
            some type, length, or value was out of range or because the
            request was rejected for policy reasons. To avoid a denial
            of service attack using forged messages, this status may
            only be returned for and in an encrypted packet if the
            message ID and cryptographic checksum were valid. To avoid
            leaking information to someone probing a node, this status
            MUST be sent in response to any error not covered by one of
            the other status types. To aid debugging, more detailed
            error information SHOULD be written to a console or log.

        INVALID_MESSAGE_ID                        9

            Sent when an IKE message ID outside the supported window is
            received.  This Notify MUST NOT be sent in a response; the
            invalid request MUST NOT be acknowledged.  Instead, inform
            the other side by initiating an INFORMATIONAL exchange with
            Notification data containing the four octet invalid message
            ID. Sending this notification is optional and notifications
            of this type MUST be rate limited.

        INVALID_SPI                              11

            MAY be sent in an IKE INFORMATIONAL Exchange when a node
            receives an ESP or AH packet with an invalid SPI. The
            Notification Data contains the SPI of the invalid packet.
            This usually indicates a node has rebooted and forgotten an
            SA.  If this Informational Message is sent outside the
            context of an IKE_SA, it should only be used by the
            recipient as a "hint" that something might be wrong (because
            it could easily be forged).

        NO_PROPOSAL_CHOSEN                       14

            None of the proposed crypto suites was acceptable.

        INVALID_KE_PAYLOAD                       17

            The D-H Group # field in the KE payload is not the group #
            selected by the responder for this exchange. There are two
            octets of data associated with this notification: the
            accepted D-H Group # in big endian order.

        AUTHENTICATION_FAILED                    24

            Sent in the response to an IKE_AUTH message when for some
            reason the authentication failed. There is no associated
            data.

        SINGLE_PAIR_REQUIRED                     34
            This error indicates that a CREATE_CHILD_SA request is
            unacceptable because its sender is only willing to accept
            traffic selectors specifying a single pair of addresses.
            The requestor is expected to respond by requesting an SA for
            only the specific traffic it is trying to forward.

        NO_ADDITIONAL_SAS                        35

            This error indicates that a CREATE_CHILD_SA request is
            unacceptable because the responder is unwilling to accept
            any more CHILD_SAs on this IKE_SA. Some minimal
            implementations may only accept a single CHILD_SA setup in
            the context of an initial IKE exchange and reject any
            subsequent attempts to add more.

        INTERNAL_ADDRESS_FAILURE                 36

            Indicates an error assigning an internal address (i.e.,
            INTERNAL_IP4_ADDRESS or INTERNAL_IP6_ADDRESS) during the
            processing of a Configuration Payload by a responder.  If
            this error is generated within an IKE_AUTH exchange no
            CHILD_SA will be created.

        FAILED_CP_REQUIRED                       37

            Sent by responder in the case where CP(CFG_REQUEST) was
            expected but not received, and so is a conflict with locally
            configured policy. There is no associated data.

        TS_UNACCEPTABLE                          38

            Indicates that none of the addresses/protocols/ports in the
            supplied traffic selectors is acceptable.

        INVALID_SELECTORS                        39

            MAY be sent in an IKE INFORMATIONAL Exchange when a node
            receives an ESP or AH packet whose selectors do not match
            those of the SA on which it was delivered (and which caused
            the packet to be dropped). The Notification Data contains
            the start of the offending packet (as in ICMP messages) and
            the SPI field of the notification is set to match the SPI of
            the IPsec SA.

  			TEMPORARY_FAILURE                        	43
      			See section RFC5996-2.25.

  			CHILD_SA_NOT_FOUND                       44
      			See section RFC5996-2.25.

        RESERVED TO IANA - Error types         40 - 8191

        Private Use - Errors                8192 - 16383

        NOTIFY MESSAGES - STATUS TYPES           Value
        ------------------------------           -----

        INITIAL_CONTACT                          16384

            This notification asserts that this IKE_SA is the only
            IKE_SA currently active between the authenticated
            identities. It MAY be sent when an IKE_SA is established
            after a crash, and the recipient MAY use this information to
            delete any other IKE_SAs it has to the same authenticated
            identity without waiting for a timeout.  This notification
            MUST NOT be sent by an entity that may be replicated (e.g.,
            a roaming user's credentials where the user is allowed to
            connect to the corporate firewall from two remote systems at
            the same time).

        SET_WINDOW_SIZE                          16385

            This notification asserts that the sending endpoint is
            capable of keeping state for multiple outstanding exchanges,
            permitting the recipient to send multiple requests before
            getting a response to the first. The data associated with a
            SET_WINDOW_SIZE notification MUST be 4 octets long and
            contain the big endian representation of the number of
            messages the sender promises to keep. Window size is always
            one until the initial exchanges complete.

        ADDITIONAL_TS_POSSIBLE                   16386

            This notification asserts that the sending endpoint narrowed
            the proposed traffic selectors but that other traffic
            selectors would also have been acceptable, though only in a
            separate SA (see section 2.9). There is no data associated
            with this Notify type. It may only be sent as an additional
            payload in a message including accepted TSs.

        IPCOMP_SUPPORTED                         16387

            This notification may only be included in a message
            containing an SA payload negotiating a CHILD_SA and
            indicates a willingness by its sender to use IPComp on this
            SA. The data associated with this notification includes a
            two octet IPComp CPI followed by a one octet transform ID
            optionally followed by attributes whose length and format is
            defined by that transform ID. A message proposing an SA may
            contain multiple IPCOMP_SUPPORTED notifications to indicate
            multiple supported algorithms. A message accepting an SA may
            contain at most one.

            The transform IDs currently defined are:

                 NAME         NUMBER  DEFINED IN
                 -----------  ------  -----------
                 RESERVED       0
                 IPCOMP_OUI     1
                 IPCOMP_DEFLATE 2     RFC 2394
                 IPCOMP_LZS     3     RFC 2395
                 IPCOMP_LZJH    4     RFC 3051

                 values 5-240 are reserved to IANA. Values 241-255 are
                 for private use among mutually consenting parties.

        NAT_DETECTION_SOURCE_IP                  16388

            This notification is used by its recipient to determine
            whether the source is behind a NAT box. The data associated
            with this notification is a SHA-1 digest of the SPIs (in the
            order they appear in the header), IP address and port on
            which this packet was sent.  There MAY be multiple Notify
            payloads of this type in a message if the sender does not
            know which of several network attachments will be used to
            send the packet. The recipient of this notification MAY
            compare the supplied value to a SHA-1 hash of the SPIs,
            source IP address and port and if they don't match it SHOULD
            enable NAT traversal (see section 2.23).  Alternately, it
            MAY reject the connection attempt if NAT traversal is not
            supported.

        NAT_DETECTION_DESTINATION_IP             16389

            This notification is used by its recipient to determine
            whether it is behind a NAT box. The data associated with
            this notification is a SHA-1 digest of the SPIs (in the
            order they appear in the header), IP address and port to
            which this packet was sent.  The recipient of this
            notification MAY compare the supplied value to a hash of the
            SPIs, destination IP address and port and if they don't
            match it SHOULD invoke NAT traversal (see section 2.23). If
            they don't match, it means that this end is behind a NAT and
            this end SHOULD start sending keepalive packets as defined
            in [Hutt04].  Alternately, it MAY reject the connection
            attempt if NAT traversal is not supported.

        COOKIE                                   16390

            This notification MAY be included in an IKE_SA_INIT
            response. It indicates that the request should be retried
            with a copy of this notification as the first payload.  This
            notification MUST be included in an IKE_SA_INIT request
            retry if a COOKIE notification was included in the initial
            response.  The data associated with this notification MUST
            be between 1 and 64 octets in length (inclusive).

        USE_TRANSPORT_MODE                       16391

            This notification MAY be included in a request message that
            also includes an SA payload requesting a CHILD_SA. It
            requests that the CHILD_SA use transport mode rather than
            tunnel mode for the SA created. If the request is accepted,
            the response MUST also include a notification of type
            USE_TRANSPORT_MODE. If the responder declines the request,
            the CHILD_SA will be established in tunnel mode. If this is
            unacceptable to the initiator, the initiator MUST delete the
            SA. Note: except when using this option to negotiate
            transport mode, all CHILD_SAs will use tunnel mode.

            Note: The ECN decapsulation modifications specified in
            [RFC2401bis] MUST be performed for every tunnel mode SA
            created by IKEv2.

        HTTP_CERT_LOOKUP_SUPPORTED               16392

            This notification MAY be included in any message that can
            include a CERTREQ payload and indicates that the sender is
            capable of looking up certificates based on an HTTP-based
            URL (and hence presumably would prefer to receive
            certificate specifications in that format).

        REKEY_SA                                 16393

            This notification MUST be included in a CREATE_CHILD_SA
            exchange if the purpose of the exchange is to replace an
            existing ESP or AH SA. The SPI field identifies the SA being
            rekeyed. There is no data.

        ESP_TFC_PADDING_NOT_SUPPORTED            16394

            This notification asserts that the sending endpoint will NOT
            accept packets that contain Flow Confidentiality (TFC)
            padding.

        NON_FIRST_FRAGMENTS_ALSO                 16395

            Used for fragmentation control. See [RFC2401bis] for
            explanation.

        RESERVED TO IANA - STATUS TYPES      16396 - 40959

        Private Use - STATUS TYPES           40960 - 65535
*/

/*
 [RFC4555 : IKEv2 Mobility and Multihoming Protocol (MOBIKE)]

      Notify Messages - Error Types     Value
      -----------------------------     -----
      UNACCEPTABLE_ADDRESSES            40
      UNEXPECTED_NAT_DETECTED           41

      Notify Messages - Status Types    Value
      ------------------------------    -----
      MOBIKE_SUPPORTED                  16396
      ADDITIONAL_IP4_ADDRESS            16397
      ADDITIONAL_IP6_ADDRESS            16398
      NO_ADDITIONAL_ADDRESSES           16399
      UPDATE_SA_ADDRESSES               16400
      COOKIE2                           16401
      NO_NATS_ALLOWED                   16402

4.  Payload Formats

   This specification defines several new IKEv2 Notify payload types.
   See [IKEv2], Section 3.10, for a general description of the Notify
   payload.

4.1.  Notify Messages - Error Types

4.1.1.  UNACCEPTABLE_ADDRESSES Notify Payload

   The responder can include this notification in an INFORMATIONAL
   exchange response to indicate that the address change in the
   corresponding request message (which contained an UPDATE_SA_ADDRESSES
   notification) was not carried out.

   The Notify Message Type for UNACCEPTABLE_ADDRESSES is 40.  The
   Protocol ID and SPI Size fields are set to zero.  There is no data
   associated with this Notify type.

4.1.2.  UNEXPECTED_NAT_DETECTED Notify Payload

   See Section 3.9 for a description of this notification.

   The Notify Message Type for UNEXPECTED_NAT_DETECTED is 41.  The
   Protocol ID and SPI Size fields are set to zero.  There is no data
   associated with this Notify type.

4.2.  Notify Messages - Status Types

4.2.1.  MOBIKE_SUPPORTED Notify Payload

   The MOBIKE_SUPPORTED notification is included in the IKE_AUTH
   exchange to indicate that the implementation supports this
   specification.

   The Notify Message Type for MOBIKE_SUPPORTED is 16396.  The Protocol
   ID and SPI Size fields are set to zero.  The notification data field
   MUST be left empty (zero-length) when sending, and its contents (if
   any) MUST be ignored when this notification is received.  This allows
   the field to be used by future versions of this protocol.

4.2.2.  ADDITIONAL_IP4_ADDRESS and ADDITIONAL_IP6_ADDRESS Notify
        Payloads

   Both parties can include ADDITIONAL_IP4_ADDRESS and/or
   ADDITIONAL_IP6_ADDRESS notifications in the IKE_AUTH exchange and
   INFORMATIONAL exchange request messages; see Section 3.4 and
   Section 3.6 for more detailed description.

   The Notify Message Types for ADDITIONAL_IP4_ADDRESS and
   ADDITIONAL_IP6_ADDRESS are 16397 and 16398, respectively.  The
   Protocol ID and SPI Size fields are set to zero.  The data associated
   with these Notify types is either a four-octet IPv4 address or a
   16-octet IPv6 address.

4.2.3.  NO_ADDITIONAL_ADDRESSES Notify Payload

   The NO_ADDITIONAL_ADDRESSES notification can be included in an
   INFORMATIONAL exchange request message to indicate that the exchange
   initiator does not have addresses beyond the one used in the exchange
   (see Section 3.6 for more detailed description).

   The Notify Message Type for NO_ADDITIONAL_ADDRESSES is 16399.  The
   Protocol ID and SPI Size fields are set to zero.  There is no data
   associated with this Notify type.

4.2.4.  UPDATE_SA_ADDRESSES Notify Payload

   This notification is included in INFORMATIONAL exchange requests sent
   by the initiator to update addresses of the IKE_SA and IPsec SAs (see
   Section 3.5).

   The Notify Message Type for UPDATE_SA_ADDRESSES is 16400.  The
   Protocol ID and SPI Size fields are set to zero.  There is no data
   associated with this Notify type.

4.2.5.  COOKIE2 Notify Payload

   This notification MAY be included in any INFORMATIONAL request for
   return routability check purposes (see Section 3.7).  If the
   INFORMATIONAL request includes COOKIE2, the exchange responder MUST
   copy the notification to the response message.

   The data associated with this notification MUST be between 8 and 64
   octets in length (inclusive), and MUST be chosen by the exchange
   initiator in a way that is unpredictable to the exchange responder.
   The Notify Message Type for this message is 16401.  The Protocol ID
   and SPI Size fields are set to zero.

4.2.6.  NO_NATS_ALLOWED Notify Payload

   See Section 3.9 for a description of this notification.

   The Notify Message Type for this message is 16402.  The notification
   data contains the IP addresses and ports from/to which the packet was
   sent.  For IPv4, the notification data is 12 octets long and is
   defined as follows:
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                      Source IPv4 address                      !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                   Destination IPv4 address                    !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !          Source port          !       Destination port        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   For IPv6, the notification data is 36 octets long and is defined as
   follows:

                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      !                      Source IPv6 address                      !
      !                                                               !
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      !                   Destination IPv6 address                    !
      !                                                               !
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !          Source port          !       Destination port        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   The Protocol ID and SPI Size fields are set to zero.
*/

/*

 [RFC7383 : Internet Key Exchange Protocol Version 2 (IKEv2) Message Fragmentation]

	16430       IKEV2_FRAGMENTATION_SUPPORTED


2.3.  Negotiation

   The initiator indicates its support for IKE fragmentation and
   willingness to use it by including a Notification payload of type
   IKEV2_FRAGMENTATION_SUPPORTED in the IKE_SA_INIT request message.  If
   the responder also supports this extension and is willing to use it,
   it includes this notification in the response message.

   Initiator                   Responder
   -----------                 -----------
   HDR, SAi1, KEi, Ni,
      [N(IKEV2_FRAGMENTATION_SUPPORTED)]  -->

                       <--   HDR, SAr1, KEr, Nr, [CERTREQ],
                                  [N(IKEV2_FRAGMENTATION_SUPPORTED)]

   The Notify payload is formatted as follows:

                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Protocol ID(=0)| SPI Size (=0) |      Notify Message Type      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   o  Protocol ID (1 octet) - MUST be 0.

   o  SPI Size (1 octet) - MUST be 0, meaning no Security Parameter
      Index (SPI) is present.

   o  Notify Message Type (2 octets) - MUST be 16430, the value assigned
      for the IKEV2_FRAGMENTATION_SUPPORTED notification.

   This notification contains no data.

*/

/*

 [RFC5723 : IKEv2 Session Resumption]

7.  IKE Notifications

   This document defines a number of notifications.  The following
   Notify Message types have been assigned by IANA.

              +-------------------+-------+-----------------+
              | Notification Name | Value | Data            |
              +-------------------+-------+-----------------+
              | TICKET_LT_OPAQUE  | 16409 | See Section 7.1 |
              |                   |       |                 |
              | TICKET_REQUEST    | 16410 | None            |
              |                   |       |                 |
              | TICKET_ACK        | 16411 | None            |
              |                   |       |                 |
              | TICKET_NACK       | 16412 | None            |
              |                   |       |                 |
              | TICKET_OPAQUE     | 16413 | See Section 7.2 |
              +-------------------+-------+-----------------+

   For all these notifications, the Protocol ID and the SPI Size fields
   MUST both be sent as 0.

7.1.  TICKET_LT_OPAQUE Notify Payload

   The data for the TICKET_LT_OPAQUE Notify payload consists of the
   Notify message header, a Lifetime field and the ticket itself.  The
   four octet Lifetime field contains a relative time value, the number
   of seconds until the ticket expires (encoded as an unsigned integer,
   in network byte order).

        0                     1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Next Payload  |C|  Reserved   |      Payload Length           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Protocol ID   | SPI Size = 0  |    Notify Message Type        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                       Lifetime                                |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       ~                        Ticket                                 ~
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                 Figure 6: TICKET_LT_OPAQUE Notify Payload

7.2.  TICKET_OPAQUE Notify Payload

   The data for the TICKET_OPAQUE Notify payload consists of the Notify
   message header, and the ticket itself.  Unlike the TICKET_LT_OPAQUE
   payload, no lifetime value is included in the TICKET_OPAQUE Notify
   payload.

        0                     1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Next Payload  |C|  Reserved   |      Payload Length           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Protocol ID   | SPI Size = 0  |    Notify Message Type        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       ~                        Ticket                                 ~
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                  Figure 7: TICKET_OPAQUE Notify Payload

*/

/*

  Private Use

	- STATUS TYPES           40960 - 65535

		RHP_USE_ETHERIP_ENCAP	   		:		    		59300
		RHP_INTERNAL_IP4_ADDRESS 		:   				59301
		RHP_INTERNAL_IP6_ADDRESS 		:  					59302
		RHP_INTERNAL_MAC_ADDRESS 		:   				59303
		RHP_INTERNAL_ACCESSPOINT 		:						59304
		RHP_INTERNAL_MESH_NODE   		:           59305
		RHP_REALM_ID						 		:						59306
		RHP_IPV6_AUTOCONF_REKEY_SA	:           59307
		RHP_USE_GRE_ENCAP	   				:		    		59308
		RHP_AUTH_TICKET		   				:		    		59309
		RHP_ENC_AUTH_TICKET					:		    		59310
		RHP_AUTH_TICKET_SUPPORTED		:		    		59311

		RHP_USE_ETHERIP_ENCAP :
			Exchange : IKE_AUTH(IKE SA Initiator/Responder) or CREATE_CHILD_SA for Rekeying Child
			           SAs(IKE SA Initiator/Responder), Proto ID : 0 , SPI Size : 0
			Notification Data : none

		RHP_USE_GRE_ENCAP :
			Exchange : IKE_AUTH(IKE SA Initiator/Responder) or CREATE_CHILD_SA for Rekeying Child
			           SAs(IKE SA Initiator/Responder), Proto ID : 0 , SPI Size : 0
			Notification Data : none

		RHP_INTERNAL_IP4_ADDRESS :
			Exchange : IKE_AUTH(IKE SA Responder) or INFORMATIONAL(IKE SA Initiator) , Proto ID : 0 , SPI Size : 0
			Notification Data : A internal IPv4 address(4bytes)

		RHP_INTERNAL_IP6_ADDRESS :
			Exchange : IKE_AUTH(IKE SA Responder) or INFORMATIONAL(IKE SA Initiator) , Proto ID : 0 , SPI Size : 0
			Notification Data : A internal IPv6 address(16bytes)

		RHP_INTERNAL_MAC_ADDRESS :
			Exchange : IKE_AUTH(IKE SA Responder) or INFORMATIONAL(IKE SA Initiator) , Proto ID : 0 , SPI Size : 0
			Notification Data : A internal MAC address assigned to a virtual interface(6bytes)

		RHP_INTERNAL_ACCESSPOINT :
			Exchange : IKE_AUTH(IKE SA Initiator/Responder), Proto ID : 0 , SPI Size : 0
			Notification Data : none

		RHP_INTERNAL_MESH_NODE :
			Exchange : IKE_AUTH(IKE SA Responder), Proto ID : 0 , SPI Size : 0
			Notification Data : none

		RHP_REALM_ID :
			Exchange : IKE_AUTH(IKE SA Initiator), Proto ID : 0 , SPI Size : 0
			Notification Data : A realm ID(4bytes)

		RHP_IPV6_AUTOCONF_REKEY_SA :
			Exchange : CREATE_CHILD_SA for Rekeying Child SAs(Child SA Initiator), Proto ID : 0 , SPI Size : 0
			Notification Data : none

		RHP_AUTH_TICKET :
			Exchange : INFORMATIONAL , Proto ID : 0 , SPI Size : 0
			Notification Data : RHP_AUTH_TICKET Notify Payload

		RHP_ENC_AUTH_TICKET :
			Exchange : INFORMATIONAL , Proto ID : 0 , SPI Size : 0
			Notification Data : RHP_ENC_AUTH_TICKET Notify Payload

		RHP_AUTH_TICKET_SUPPORTED :
			Exchange : IKE_AUTH , Proto ID : 0 , SPI Size : 0
			Notification Data : none

	- ERROR TYPES           8192 - 16383

*/

struct _rhp_proto_ike_notify_payload
{
  u8  next_payload;

  u8 critical_rsv;

  u16 len;

  u8 protocol_id;
  u8 spi_len;


#define RHP_PROTO_IKE_NOTIFY_RESERVED															  0
#define RHP_PROTO_IKE_NOTIFY_ERR_UNSUPPORTED_CRITICAL_PAYLOAD				1
#define RHP_PROTO_IKE_NOTIFY_ERR_INVALID_IKE_SPI                    4
#define RHP_PROTO_IKE_NOTIFY_ERR_INVALID_MAJOR_VERSION              5
#define RHP_PROTO_IKE_NOTIFY_ERR_INVALID_SYNTAX                     7
#define RHP_PROTO_IKE_NOTIFY_ERR_INVALID_MESSAGE_ID                 9
#define RHP_PROTO_IKE_NOTIFY_ERR_INVALID_SPI                        11
#define RHP_PROTO_IKE_NOTIFY_ERR_NO_PROPOSAL_CHOSEN                 14
#define RHP_PROTO_IKE_NOTIFY_ERR_INVALID_KE_PAYLOAD                 17
#define RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED              24
#define RHP_PROTO_IKE_NOTIFY_ERR_SINGLE_PAIR_REQUIRED               34
#define RHP_PROTO_IKE_NOTIFY_ERR_NO_ADDITIONAL_SAS                  35
#define RHP_PROTO_IKE_NOTIFY_ERR_INTERNAL_ADDRESS_FAILURE           36
#define RHP_PROTO_IKE_NOTIFY_ERR_FAILED_CP_REQUIRED                 37
#define RHP_PROTO_IKE_NOTIFY_ERR_TS_UNACCEPTABLE                    38
#define RHP_PROTO_IKE_NOTIFY_ERR_INVALID_SELECTORS                  39
#define RHP_PROTO_IKE_NOTIFY_ERR_TEMPORARY_FAILURE			            43
#define RHP_PROTO_IKE_NOTIFY_ERR_CHILD_SA_NOT_FOUND	                44

#define RHP_PROTO_IKE_NOTIFY_ERR_UNACCEPTABLE_ADDRESSES             40 // [RFC4555]
#define RHP_PROTO_IKE_NOTIFY_ERR_UNEXPECTED_NAT_DETECTED            41 // [RFC4555]

#define RHP_PROTO_IKE_NOTIFY_ERR_USE_ASSIGNED_HOA										42	// [RFC5026]

#define RHP_PROTO_IKE_NOTIFY_ERR_INVALID_GROUP_ID	  								45 // [draft-yeung-g-ikev2]
#define RHP_PROTO_IKE_NOTIFY_ERR_AUTHORIZATION_FAILED  							46 // [draft-yeung-g-ikev2]

#define RHP_PROTO_IKE_NOTIFY_ERR_MIN								            		1
#define RHP_PROTO_IKE_NOTIFY_ERR_MAX								            		8191


#define RHP_PROTO_IKE_NOTIFY_ERR_PRIV_START			                  	8192
#define RHP_PROTO_IKE_NOTIFY_ERR_PRIV_END				                  	16383


// See the following links to get details.
//  - [MS-IKEE]: Internet Key Exchange Protocol Extensions
//    http://msdn.microsoft.com/en-us/library/cc233219(v=prot.10).aspx
#define RHP_PROTO_IKE_NOTIFY_ERR_PRIV_MS_STATUS			                12345



#define RHP_PROTO_IKE_NOTIFY_ST_INITIAL_CONTACT                     16384
#define RHP_PROTO_IKE_NOTIFY_ST_SET_WINDOW_SIZE                     16385
#define RHP_PROTO_IKE_NOTIFY_ST_ADDITIONAL_TS_POSSIBLE              16386
#define RHP_PROTO_IKE_NOTIFY_ST_IPCOMP_SUPPORTED                    16387
#define RHP_PROTO_IKE_NOTIFY_ST_NAT_DETECTION_SOURCE_IP             16388
#define RHP_PROTO_IKE_NOTIFY_ST_NAT_DETECTION_DESTINATION_IP        16389
#define RHP_PROTO_IKE_NOTIFY_ST_COOKIE                              16390
#define RHP_PROTO_IKE_NOTIFY_ST_USE_TRANSPORT_MODE                  16391
#define RHP_PROTO_IKE_NOTIFY_ST_HTTP_CERT_LOOKUP_SUPPORTED          16392
#define RHP_PROTO_IKE_NOTIFY_ST_REKEY_SA                            16393
#define RHP_PROTO_IKE_NOTIFY_ST_ESP_TFC_PADDING_NOT_SUPPORTED      	16394
#define RHP_PROTO_IKE_NOTIFY_ST_NON_FIRST_FRAGMENTS_ALSO            16395

#define RHP_PROTO_IKE_NOTIFY_ST_MOBIKE_SUPPORTED                 		16396
#define RHP_PROTO_IKE_NOTIFY_ST_ADDITIONAL_IP4_ADDRESS              16397
#define RHP_PROTO_IKE_NOTIFY_ST_ADDITIONAL_IP6_ADDRESS              16398
#define RHP_PROTO_IKE_NOTIFY_ST_NO_ADDITIONAL_ADDRESSES             16399
#define RHP_PROTO_IKE_NOTIFY_ST_UPDATE_SA_ADDRESSES                 16400
#define RHP_PROTO_IKE_NOTIFY_ST_COOKIE2                					 		16401
#define RHP_PROTO_IKE_NOTIFY_ST_NO_NATS_ALLOWED			                16402

#define RHP_PROTO_IKE_NOTIFY_ST_AUTH_LIFETIME  											16403	// [RFC4478]

#define RHP_PROTO_IKE_NOTIFY_ST_MULTIPLE_AUTH_SUPPORTED	  					16404	// [RFC4739]
#define RHP_PROTO_IKE_NOTIFY_ST_ANOTHER_AUTH_FOLLOWS	  						16405	// [RFC4739]

#define RHP_PROTO_IKE_NOTIFY_ST_REDIRECT_SUPPORTED	  							16406	// [RFC5685]
#define RHP_PROTO_IKE_NOTIFY_ST_REDIRECT														16407	// [RFC5685]
#define RHP_PROTO_IKE_NOTIFY_ST_REDIRECTED_FROM	  									16408	// [RFC5685]

#define RHP_PROTO_IKE_NOTIFY_ST_TICKET_LT_OPAQUE										16409	// [RFC5723]
#define RHP_PROTO_IKE_NOTIFY_ST_TICKET_REQUEST	  									16410	// [RFC5723]
#define RHP_PROTO_IKE_NOTIFY_ST_TICKET_ACK	  											16411	// [RFC5723]
#define RHP_PROTO_IKE_NOTIFY_ST_TICKET_NACK	  											16412	// [RFC5723]
#define RHP_PROTO_IKE_NOTIFY_ST_TICKET_OPAQUE	  										16413	// [RFC5723]

#define RHP_PROTO_IKE_NOTIFY_ST_LINK_ID	  													16414	// [RFC5739]

#define RHP_PROTO_IKE_NOTIFY_ST_USE_WESP_MODE				  							16415	// [RFC5840]

#define RHP_PROTO_IKE_NOTIFY_ST_ROHC_SUPPORTED				  						16416	// [RFC5857]

#define RHP_PROTO_IKE_NOTIFY_ST_EAP_ONLY_AUTHENTICATION			  			16417	// [RFC5998]

#define RHP_PROTO_IKE_NOTIFY_ST_CHILDLESS_IKEV2_SUPPORTED		  			16418	// [RFC6023]

#define RHP_PROTO_IKE_NOTIFY_ST_IKEV2_MESSAGE_ID_SYNC_SUPPORTED		  16420	// [RFC6311]
#define RHP_PROTO_IKE_NOTIFY_ST_IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED	16421	// [RFC6311]
#define RHP_PROTO_IKE_NOTIFY_ST_IKEV2_MESSAGE_ID_SYNC			  				16422	// [RFC6311]
#define RHP_PROTO_IKE_NOTIFY_ST_IPSEC_REPLAY_COUNTER_SYNC		  			16423	// [RFC6311]

#define RHP_PROTO_IKE_NOTIFY_ST_SECURE_PASSWORD_METHODS			  			16424	// [RFC6467]

#define RHP_PROTO_IKE_NOTIFY_ST_PSK_PERSIST				  								16425	// [RFC6631]
#define RHP_PROTO_IKE_NOTIFY_ST_PSK_CONFIRM				  								16426	// [RFC6631]

#define RHP_PROTO_IKE_NOTIFY_ST_ERX_SUPPORTED				  							16427	// [RFC6867]

#define RHP_PROTO_IKE_NOTIFY_ST_IFOM_CAPABILITY				  						16428	// [Frederic_Firmin][3GPP TS 24.303 v10.6.0 annex B.2]

#define RHP_PROTO_IKE_NOTIFY_ST_SENDER_REQUEST_ID			  						16429	// [draft-yeung-g-ikev2]

#define RHP_PROTO_IKE_NOTIFY_ST_QCD_TOKEN														16419 // [RFC6290]

#define RHP_PROTO_IKE_NOTIFY_ST_FRAG_SUPPORTED											16430 // [RFC7383]


#define RHP_PROTO_IKE_NOTIFY_ST_PRIV_START			                  	40960
#define RHP_PROTO_IKE_NOTIFY_ST_PRIV_END				                  	65535


// See the following links to get details.
//  - [MS-IKEE]: Internet Key Exchange Protocol Extensions
//    http://msdn.microsoft.com/en-us/library/cc233219(v=prot.10).aspx
#define RHP_PROTO_IKE_NOTIFY_ST_PRIV_MS_NOTIFY_STATUS					40003
#define RHP_PROTO_IKE_NOTIFY_ST_PRIV_MS_NOTIFY_DOS_COOKIE			40004
#define RHP_PROTO_IKE_NOTIFY_ST_PRIV_MS_NOTIFY_EXCHANGE_INFO	40005


#define RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_ETHERIP_ENCAP					  59300
#define RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_IP4_ADDRESS    			59301
#define RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_IP6_ADDRESS    			59302
#define RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_MAC_ADDRESS    			59303
#define RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_ACCESSPOINT					59304
#define RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_MESH_NODE						59305
#define RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_REALM_ID											59306
#define RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_IPV6_AUTOCONF_REKEY_SA				59307
#define RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_GRE_ENCAP					  		59308

#define RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_AUTH_TICKET					  			59309
#define RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_ENC_AUTH_TICKET							59310
#define RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_AUTH_TICKET_SUPPORTED				59311


// For debug purpose only.
#define RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_DBG_IKE_INTEG_ERR						59400
#define RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_DBG_ESP_INTEG_ERR						59401

  u16 notify_mesg_type;
};
typedef struct _rhp_proto_ike_notify_payload    rhp_proto_ike_notify_payload;



#define RHP_PROTO_IKE_NOTIFY_COOKIE_MIN_SZ      	1
#define RHP_PROTO_IKE_NOTIFY_COOKIE_MAX_SZ      	64

#define RHP_PROTO_IKE_NOTIFY_COOKIE2_MIN_SZ     	8
#define RHP_PROTO_IKE_NOTIFY_COOKIE2_MAX_SZ     	64

struct _rhp_proto_ike_notify_no_nats_allowed_v4 {
  u32 src_addr;
  u32 dst_addr;
  u16 src_port;
  u16 dst_port;
};
typedef struct _rhp_proto_ike_notify_no_nats_allowed_v4 rhp_proto_ike_notify_no_nats_allowed_v4;

struct _rhp_proto_ike_notify_no_nats_allowed_v6 {
  u8 src_addr[16];
  u8 dst_addr[16];
  u16 src_port;
  u16 dst_port;
};
typedef struct _rhp_proto_ike_notify_no_nats_allowed_v6 rhp_proto_ike_notify_no_nats_allowed_v6;





#define RHP_IKEV2_SESS_RESUME_TKT_ENCR					RHP_PROTO_IKE_TRANSFORM_ID_ENCR_AES_CBC
#define RHP_IKEV2_SESS_RESUME_TKT_ENCR_KEY_LEN	256
#define RHP_IKEV2_SESS_RESUME_TKT_MAC						RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_512_256

#define RHP_IKEV2_SESS_RESUME_TKT_ENC_KEY_LEN		32 // aes-256-cbc
#define RHP_IKEV2_SESS_RESUME_TKT_ENC_IV_LEN		16 // aes-256-cbc. This must be more than sizeof(u32).
																									 // See _rhp_sess_resume_dec_req_disp_hash()[rhp_ikev2_sess_resume_syspxy.c].
#define RHP_IKEV2_SESS_RESUME_TKT_MAC_KEY_LEN		64 // hmac_sha2_512_256
#define RHP_IKEV2_SESS_RESUME_TKT_MAC_LEN				32 // hmac_sha2_512_256

#ifndef RHP_VPN_UNIQUE_ID_SIZE
#define RHP_VPN_UNIQUE_ID_SIZE		16
#endif


struct _rhp_radius_sess_resume_tkt_attr {

#define RHP_SESS_RESUME_RADIUS_ATTRS_MAX_NUM						64

#define RHP_SESS_RESUME_RADIUS_ATTR_PRIV_REALM_ROLE						101
#define RHP_SESS_RESUME_RADIUS_ATTR_TUNNEL_PRIVATE_GROUP_ID		102
#define RHP_SESS_RESUME_RADIUS_ATTR_USER_INDEX								103
#define RHP_SESS_RESUME_RADIUS_ATTR_INTERNAL_DOMAIN_NAME			104
#define RHP_SESS_RESUME_RADIUS_ATTR_INTERNAL_ROUTE_IPV4				105
#define RHP_SESS_RESUME_RADIUS_ATTR_INTERNAL_ROUTE_IPV6				106
	u16 type;

	u16 len; // '\0' not included for a string value.

	/* attr_value data */
};
typedef struct _rhp_radius_sess_resume_tkt_attr rhp_radius_sess_resume_tkt_attr;

struct _rhp_radius_sess_ressume_tkt {

	u16 radius_tkt_len; // Including this header's length.
	u16 reserved0;

	u16 eap_method;
	u16 attrs_num;
	u64 rx_accept_attrs_mask;

	u64 vpn_realm_id_by_radius;

	u32 session_timeout;
	u32 framed_mtu;

	u32 internal_addr_ipv4;
	u8 internal_addr_ipv6[16];

	u8 internal_addr_ipv4_prefix;
	u8 internal_addr_ipv6_prefix;
	u16 reserved2;

	u32 internal_dns_server_ipv4;
	u8 internal_dns_server_ipv6[16];

	u32 internal_wins_server_ipv4;

	u32 internal_gateway_ipv4;
	u8 internal_gateway_ipv6[16];

	//
	// rhp_radius_sess_resume_tkt_attr structures follow. (if any)
	//
	/* user_index data */
	/* roles data */
	/* domain_names data */
	/* internal_route_ipv4s data */
	/* internal_route_ipv6s data */
};
typedef struct _rhp_radius_sess_ressume_tkt rhp_radius_sess_ressume_tkt;


struct _rhp_ikev2_sess_resume_tkt_e {

	u16 len; // Including the padding length.
	u16 pad_len;

	// Seconds since the Epoc generated by _rhp_get_realtime(). [rhp_misc.h]
  int64_t created_time;
  int64_t expire_time;

	u64 vpn_realm_id;
	u64 vpn_realm_policy_index;
  u8 unique_id[RHP_VPN_UNIQUE_ID_SIZE];

	u8 id_i_type; // RHP_PROTO_IKE_ID_XXX
	u8 alt_id_i_type; // RHP_PROTO_IKE_ID_XXX
	u8 id_r_type; // RHP_PROTO_IKE_ID_XXX
	u8 alt_id_r_type; // RHP_PROTO_IKE_ID_XXX
	u8 auth_method_i; // RHP_PROTO_IKE_AUTHMETHOD_XXX.
										// If EAP is used, this value is always RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY.
	u8 auth_method_r; // RHP_PROTO_IKE_AUTHMETHOD_XXX
	u16 eap_i_method; // RHP_PROTO_EAP_TYPE_XXX (e.g.) RHP_PROTO_EAP_TYPE_MS_CHAPV2

  u8 init_spi[RHP_PROTO_IKE_SPI_SIZE];
  u8 resp_spi[RHP_PROTO_IKE_SPI_SIZE];

  u16 encr_id; 	// RHP_PROTO_IKE_TRANSFORM_ID_ENCR_XXX
  u16 encr_key_bits; // if any
  u16 prf_id;		// RHP_PROTO_IKE_TRANSFORM_ID_PRF_XXX
  u16 integ_id;	// RHP_PROTO_IKE_TRANSFORM_ID_AUTH_XXX
  u16 dhgrp_id;	// RHP_PROTO_IKE_TRANSFORM_ID_DH_XXX
  u16 sk_d_len;
  u16 id_i_len;
  u16 alt_id_i_len;
  u16 id_r_len;
  u16 alt_id_r_len;
  u16 eap_identity_len;
  u16 radius_info_len; // rhp_radius_sess_ressume_tkt

  // sk_d value
  // IDi value
  // IDi(alt_id) value
  // IDr value
  // IDr(alt_id) value
  // EAP Identity value (if any)
  // RADIUS data (if any)
  // ...padding...
};
typedef struct _rhp_ikev2_sess_resume_tkt_e rhp_ikev2_sess_resume_tkt_e;

struct _rhp_ikev2_sess_resume_tkt {

	u8 magic[4]; // 'RKHP'

#define RHP_IKEV2_SESS_RESUME_TKT_VERSION		2
	u16 version;
	u16 len; // including the MAC length.

	u64 key_index;

	u8 enc_iv[RHP_IKEV2_SESS_RESUME_TKT_ENC_IV_LEN];

	/* rhp_ikev2_sess_resume_tkt_e enc */

	/* MAC[RHP_IKEV2_SESS_RESUME_TKT_MAC_LEN] value for this ticket
	   object(from 'version' to the tail of 'enc') */
};
typedef struct _rhp_ikev2_sess_resume_tkt rhp_ikev2_sess_resume_tkt;



struct _rhp_proto_ikev2_auth_tkt_attr {

#define RHP_PROTO_IKEV2_AUTH_TKT_ATTR_NONE									0
#define RHP_PROTO_IKEV2_AUTH_TKT_ATTR_AUTHENTICATOR_ID			1
#define RHP_PROTO_IKEV2_AUTH_TKT_ATTR_INITIATOR_ID					2
#define RHP_PROTO_IKEV2_AUTH_TKT_ATTR_RESPONDER_ID					3
#define RHP_PROTO_IKEV2_AUTH_TKT_ATTR_INITIATOR_PUB_IP			4
#define RHP_PROTO_IKEV2_AUTH_TKT_ATTR_RESPONDER_PUB_IP			5
#define RHP_PROTO_IKEV2_AUTH_TKT_ATTR_INITIATOR_ITNL_IP			6
#define RHP_PROTO_IKEV2_AUTH_TKT_ATTR_RESPONDER_ITNL_IP			7
#define RHP_PROTO_IKEV2_AUTH_TKT_ATTR_EXPIRATION_TIME				8
#define RHP_PROTO_IKEV2_AUTH_TKT_ATTR_SESSION_KEY						9
	u16 tkt_attr_type;
	u16 tkt_attr_sub_type;

	u16 tkt_attr_len;
};
typedef struct _rhp_proto_ikev2_auth_tkt_attr	rhp_proto_ikev2_auth_tkt_attr;


struct _rhp_proto_ikev2_auth_tkt_header {

#define RHP_PROTO_IKEV2_AUTH_TKT_TYPE_NONE				0
#define RHP_PROTO_IKEV2_AUTH_TKT_TYPE_REQUEST			1
#define RHP_PROTO_IKEV2_AUTH_TKT_TYPE_RESPONSE		2
#define RHP_PROTO_IKEV2_AUTH_TKT_TYPE_FORWARD			3
#define RHP_PROTO_IKEV2_AUTH_TKT_TYPE_ERROR				4
	u8 auth_tkt_type;
	u8 reserved;

	u16 auth_tkt_attrs_num;
};
typedef struct _rhp_proto_ikev2_auth_tkt_header	rhp_proto_ikev2_auth_tkt_header;




/*

 3.11 Delete Payload

                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Protocol ID   !   SPI Size    !           # of SPIs           !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~               Security Parameter Index(es) (SPI)              ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                  Figure 17:  Delete Payload Format

   o  Protocol ID (1 octet) - Must be 1 for an IKE_SA, 2 for AH, or
      3 for ESP.

   o  SPI Size (1 octet) - Length in octets of the SPI as defined by
      the protocol ID.  It MUST be zero for IKE (SPI is in message
      header) or four for AH and ESP.

   o  # of SPIs (2 octets) - The number of SPIs contained in the Delete
      payload.  The size of each SPI is defined by the SPI Size field.

   o  Security Parameter Index(es) (variable length) - Identifies the
      specific security association(s) to delete. The length of this
      field is determined by the SPI Size and # of SPIs fields.

*/

struct _rhp_proto_ike_delete_payload
{

  u8  next_payload;

  u8 critical_rsv;

  u16 len;

  u8 protocol_id;
  u8 spi_len;
  u16 spi_num;
};
typedef struct _rhp_proto_ike_delete_payload    rhp_proto_ike_delete_payload;


/*

 3.12 Vendor ID Payload
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                        Vendor ID (VID)                        ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                 Figure 18:  Vendor ID Payload Format

   o  Vendor ID (variable length) - It is the responsibility of
      the person choosing the Vendor ID to assure its uniqueness
      in spite of the absence of any central registry for IDs.
      Good practice is to include a company name, a person name
      or some such. If you want to show off, you might include
      the latitude and longitude and time where you were when
      you chose the ID and some random input. A message digest
      of a long unique string is preferable to the long unique
      string itself.

*/

typedef rhp_proto_ike_payload           rhp_proto_ike_vid_payload;

/*

 3.13 Traffic Selector Payload

                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Number of TSs !                 RESERVED                      !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                       <Traffic Selectors>                     ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

               Figure 19:  Traffic Selectors Payload Format

   o  Number of TSs (1 octet) - Number of traffic selectors
      being provided.

   o  RESERVED - This field MUST be sent as zero and MUST be ignored
      on receipt.

   o  Traffic Selectors (variable length) - one or more individual
      traffic selectors.
*/

struct _rhp_proto_ike_ts_payload
{

  u8  next_payload;

  u8 critical_rsv;

  u16 len;

  u8 ts_num;
  u8 reserved1;
  u16 reserved2;
};
typedef struct _rhp_proto_ike_ts_payload    rhp_proto_ike_ts_payload;


/*

 3.13.1 Traffic Selector

                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !   TS Type     !IP Protocol ID*|       Selector Length         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |           Start Port*         |           End Port*           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                         Starting Address*                     ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                         Ending Address*                       ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                  Figure 20: Traffic Selector

   o  TS Type (one octet) - Specifies the type of traffic selector.

   o  IP protocol ID (1 octet) - Value specifying an associated IP
      protocol ID (e.g., UDP/TCP/ICMP). A value of zero means that
      the protocol ID is not relevant to this traffic selector--
      the SA can carry all protocols.

   o  Selector Length - Specifies the length of this Traffic
      Selector Substructure including the header.

   o  Start Port (2 octets) - Value specifying the smallest port
      number allowed by this Traffic Selector. For protocols for
      which port is undefined, or if all ports are allowed,
      this field MUST be zero. For the
      ICMP protocol, the two one octet fields Type and Code are
      treated as a single 16 bit integer (with Type in the most
      significant eight bits and Code in the least significant
      eight bits) port number for the purposes of filtering based
      on this field.

   o  End Port (2 octets) - Value specifying the largest port
      number allowed by this Traffic Selector. For protocols for
      which port is undefined, or if all ports are allowed,
      this field MUST be 65535. For the
      ICMP protocol, the two one octet fields Type and Code are
      treated as a single 16 bit integer (with Type in the most
      significant eight bits and Code in the least significant
      eight bits) port number for the purposed of filtering based
      on this field.

   o  Starting Address - The smallest address included in this
      Traffic Selector (length determined by TS type).

   o  Ending Address - The largest address included in this
      Traffic Selector (length determined by TS type).

   The following table lists the assigned values for the Traffic
   Selector Type field and the corresponding Address Selector Data.

      TS Type                           Value
      -------                           -----
      RESERVED                           0-6

      TS_IPV4_ADDR_RANGE                  7

            A range of IPv4 addresses, represented by two four (4) octet
            values.  The first value is the beginning IPv4 address
            (inclusive) and the second value is the ending IPv4 address
            (inclusive). All addresses falling between the two specified
            addresses are considered to be within the list.

      TS_IPV6_ADDR_RANGE                  8

            A range of IPv6 addresses, represented by two sixteen (16)
            octet values.  The first value is the beginning IPv6 address
            (inclusive) and the second value is the ending IPv6 address
            (inclusive). All addresses falling between the two specified
            addresses are considered to be within the list.

*/

struct _rhp_proto_ike_ts_selector
{

#define RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE    7
#define RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE    8
  u8  ts_type;
  u8  ip_protocol_id;
  u16 len;

  union{

  	struct {
  		u8 type;
  		u8 code;
  	} icmp;

  	u16 port;

  } start_port;

  union{

  	struct {
  		u8 type;
  		u8 code;
  	} icmp;

  	u16 port;

  } end_port;

  // start_addr
  // end_addr
};
typedef struct _rhp_proto_ike_ts_selector    rhp_proto_ike_ts_selector;

#define RHP_PROTO_IKE_TS_IPV4_SIZE		(sizeof(rhp_proto_ike_ts_selector) + 8)
#define RHP_PROTO_IKE_TS_IPV6_SIZE		(sizeof(rhp_proto_ike_ts_selector) + 32)
#define RHP_PROTO_IKE_TS_MIN_SIZE			RHP_PROTO_IKE_TS_IPV4_SIZE


/*

 3.14 Encrypted Payload

                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                     Initialization Vector                     !
      !         (length is block size for encryption algorithm)       !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                    Encrypted IKE Payloads                     !
      +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !               !             Padding (0-255 octets)            !
      +-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
      !                                               !  Pad Length   !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ~                    Integrity Checksum Data                    ~
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

               Figure 21:  Encrypted Payload Format

   o  Next Payload - The payload type of the first embedded payload.
      Note that this is an exception in the standard header format,
      since the Encrypted payload is the last payload in the
      message and therefore the Next Payload field would normally
      be zero. But because the content of this payload is embedded
      payloads and there was no natural place to put the type of
      the first one, that type is placed here.

   o  Payload Length - Includes the lengths of the header, IV,
      Encrypted IKE Payloads, Padding, Pad Length and Integrity
      Checksum Data.

   o  Initialization Vector - A randomly chosen value whose length
      is equal to the block length of the underlying encryption
      algorithm. Recipients MUST accept any value. Senders SHOULD
      either pick this value pseudo-randomly and independently for
      each message or use the final ciphertext block of the previous
      message sent. Senders MUST NOT use the same value for each
      message, use a sequence of values with low hamming distance
      (e.g., a sequence number), or use ciphertext from a received
      message.

   o  IKE Payloads are as specified earlier in this section. This
      field is encrypted with the negotiated cipher.

   o  Padding MAY contain any value chosen by the sender, and MUST
      have a length that makes the combination of the Payloads, the
      Padding, and the Pad Length to be a multiple of the encryption
      block size. This field is encrypted with the negotiated
      cipher.

   o  Pad Length is the length of the Padding field. The sender
      SHOULD set the Pad Length to the minimum value that makes
      the combination of the Payloads, the Padding, and the Pad
      Length a multiple of the block size, but the recipient MUST
      accept any length that results in proper alignment. This
      field is encrypted with the negotiated cipher.

   o  Integrity Checksum Data is the cryptographic checksum of
      the entire message starting with the Fixed IKE Header
      through the Pad Length. The checksum MUST be computed over
      the encrypted message. Its length is determined by the
      integrity algorithm negotiated.

*/
typedef rhp_proto_ike_payload           rhp_proto_ike_enc_payload;


/*

 3.15 Configuration Payload

                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C! RESERVED    !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !   CFG Type    !                    RESERVED                   !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                   Configuration Attributes                    ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

               Figure 22:  Configuration Payload Format

   The payload type for the Configuration Payload is forty seven (47).

   o  CFG Type (1 octet) - The type of exchange represented by the
      Configuration Attributes.

             CFG Type       Value
             ===========    =====
             RESERVED         0
             CFG_REQUEST      1
             CFG_REPLY        2
             CFG_SET          3
             CFG_ACK          4

      values 5-127 are reserved to IANA. Values 128-255 are for private
      use among mutually consenting parties.

   o  RESERVED (3 octets)  - MUST be sent as zero; MUST be ignored on
      receipt.

   o  Configuration Attributes (variable length) - These are type
      length values specific to the Configuration Payload and are
      defined below. There may be zero or more Configuration
      Attributes in this payload.

*/

struct _rhp_proto_ike_cp_payload
{
  u8  next_payload;

  u8 critical_rsv;

  u16 len;

#define RHP_PROTO_IKE_CFG_REQUEST     1
#define RHP_PROTO_IKE_CFG_REPLY       2
#define RHP_PROTO_IKE_CFG_SET         3
#define RHP_PROTO_IKE_CFG_ACK         4
  u8 cfg_type;
  u8 reserved1;
  u16 reserved2;
};
typedef struct _rhp_proto_ike_cp_payload    rhp_proto_ike_cp_payload;


/*

 3.15.1 Configuration Attributes

                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !R|         Attribute Type      !            Length             |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      ~                             Value                             ~
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

               Figure 23:  Configuration Attribute Format

   o  Reserved (1 bit) - This bit MUST be set to zero and MUST be
      ignored on receipt.

   o  Attribute Type (7 bits) - A unique identifier for each of the
      Configuration Attribute Types.

   o  Length (2 octets) - Length in octets of Value.

   o  Value (0 or more octets) - The variable length value of this
      Configuration Attribute.

   The following attribute types have been defined:

															 				  Multi-
        Attribute Type    			 Value 	Valued 		Length
        =======================  =====  ======  ==================
         RESERVED                 	0
         INTERNAL_IP4_ADDRESS     	1    	YES*  		0 or 4 octets
         INTERNAL_IP4_NETMASK    	 	2    	NO    		0 or 4 octets
         INTERNAL_IP4_DNS         	3    	YES   		0 or 4 octets
         INTERNAL_IP4_NBNS        	4    	YES   		0 or 4 octets
         INTERNAL_ADDRESS_EXPIRY  	5    	NO    		0 or 4 octets
         INTERNAL_IP4_DHCP        	6    	YES   		0 or 4 octets
         APPLICATION_VERSION      	7    	NO    		0 or more
         INTERNAL_IP6_ADDRESS     	8    	YES*  		0 or 17 octets
         RESERVED                 	9
         INTERNAL_IP6_DNS        		10    YES   		0 or 16 octets
         INTERNAL_IP6_NBNS       		11    YES   		0 or 16 octets
         INTERNAL_IP6_DHCP       		12    YES   		0 or 16 octets
         INTERNAL_IP4_SUBNET     		13    YES   		0 or 8 octets
         SUPPORTED_ATTRIBUTES    		14    NO    		Multiple of 2
         INTERNAL_IP6_SUBNET     		15    YES   		17 octets

      * These attributes may be multi-valued on return only if
        multiple values were requested.

        Types 16-16383 are reserved to IANA. Values 16384-32767 are for
        private use among mutually consenting parties.

      o  INTERNAL_IP4_ADDRESS, INTERNAL_IP6_ADDRESS - An address on the
         internal network, sometimes called a red node address or
         private address and MAY be a private address on the Internet.
         In a request message, the address specified is a requested
         address (or zero if no specific address is requested). If a
         specific address is requested, it likely indicates that a
         previous connection existed with this address and the requestor
         would like to reuse that address. With IPv6, a requestor
         MAY supply the low order address bytes it wants to use.
         Multiple internal addresses MAY be requested by requesting
         multiple internal address attributes.  The responder MAY only
         send up to the number of addresses requested. The
         INTERNAL_IP6_ADDRESS is made up of two fields; the first
         being a 16 octet IPv6 address and the second being a one octet
         prefix-length as defined in [ADDRIPV6].

         The requested address is valid until the expiry time defined
         with the INTERNAL_ADDRESS EXPIRY attribute or there are no
         IKE_SAs between the peers.

      o  INTERNAL_IP4_NETMASK - The internal network's netmask.  Only
         one netmask is allowed in the request and reply messages
         (e.g., 255.255.255.0) and it MUST be used only with an
         INTERNAL_IP4_ADDRESS attribute.

      o  INTERNAL_IP4_DNS, INTERNAL_IP6_DNS - Specifies an address of a
         DNS server within the network.  Multiple DNS servers MAY be
         requested.  The responder MAY respond with zero or more DNS
         server attributes.

      o  INTERNAL_IP4_NBNS, INTERNAL_IP6_NBNS - Specifies an address of
         a NetBios Name Server (WINS) within the network.  Multiple NBNS
         servers MAY be requested.  The responder MAY respond with zero
         or more NBNS server attributes.

      o  INTERNAL_ADDRESS_EXPIRY - Specifies the number of seconds that
         the host can use the internal IP address.  The host MUST renew
         the IP address before this expiry time.  Only one of these
         attributes MAY be present in the reply.

      o  INTERNAL_IP4_DHCP, INTERNAL_IP6_DHCP - Instructs the host to
         send any internal DHCP requests to the address contained within
         the attribute.  Multiple DHCP servers MAY be requested.  The
         responder MAY respond with zero or more DHCP server attributes.

      o  APPLICATION_VERSION - The version or application information of
         the IPsec host.  This is a string of printable ASCII characters
         that is NOT null terminated.

      o  INTERNAL_IP4_SUBNET - The protected sub-networks that this
         edge-device protects.  This attribute is made up of two fields;
         the first being an IP address and the second being a netmask.
         Multiple sub-networks MAY be requested.  The responder MAY
         respond with zero or more sub-network attributes.

      o  SUPPORTED_ATTRIBUTES - When used within a Request, this
         attribute MUST be zero length and specifies a query to the
         responder to reply back with all of the attributes that it
         supports.  The response contains an attribute that contains a
         set of attribute identifiers each in 2 octets.  The length
         divided by 2 (octets) would state the number of supported
         attributes contained in the response.

      o  INTERNAL_IP6_SUBNET - The protected sub-networks that this
         edge-device protects.  This attribute is made up of two fields;
         the first being a 16 octet IPv6 address the second being a one
         octet prefix-length as defined in [ADDRIPV6].  Multiple
         sub-networks MAY be requested.  The responder MAY respond with
         zero or more sub-network attributes.

*/

struct _rhp_proto_ike_cfg_attr
{

#define RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_ADDRESS     			1
#define RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_NETMASK     			2
#define RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_DNS         			3
#define RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_NBNS        			4
#define RHP_PROTO_IKE_CFG_ATTR_INTERNAL_ADDRESS_EXPIRY 				5
#define RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_DHCP        			6
#define RHP_PROTO_IKE_CFG_ATTR_APPLICATION_VERSION      			7
#define RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_ADDRESS     			8
#define RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_DNS        				10
#define RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_NBNS       				11
#define RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_DHCP       				12
#define RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_SUBNET     				13
#define RHP_PROTO_IKE_CFG_ATTR_SUPPORTED_ATTRIBUTES    				14
#define RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_SUBNET     				15

// See the following links to get details.
//  - [MS-IKEE]: Internet Key Exchange Protocol Extensions
//    http://msdn.microsoft.com/en-us/library/cc233219(v=prot.10).aspx
#define RHP_PROTO_IKE_CFG_ATTR_MS_INTERNAL_IPV4_SERVER				23456
#define RHP_PROTO_IKE_CFG_ATTR_MS_INTERNAL_IPV6_SERVER				23457


#define RHP_PROTO_IKE_CFG_ATTR_RHP_DNS_SFX										28467
#define RHP_PROTO_IKE_CFG_ATTR_RHP_IPV4_GATEWAY								28468
#define RHP_PROTO_IKE_CFG_ATTR_RHP_IPV6_GATEWAY								28469
#define RHP_PROTO_IKE_CFG_ATTR_RHP_IPV6_AUTOCONF							28470


#ifdef RHP_BIG_ENDIAN
#define RHP_PROTO_IKE_CFG_ATTR_TYPE(cfg_attr_type_rsv)  ((cfg_attr_type_rsv) & 0x7FFF)
#else
#define RHP_PROTO_IKE_CFG_ATTR_TYPE(cfg_attr_type_rsv)  ((cfg_attr_type_rsv) & 0xFF7F)
#endif
  u16 cfg_attr_type_rsv;

  u16 len;
};
typedef struct _rhp_proto_ike_cfg_attr  rhp_proto_ike_cfg_attr;


/*

 3.16 Extensible Authentication Protocol (EAP) Payload

                            1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       ! Next Payload  !C!  RESERVED   !         Payload Length        !
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       !                                                               !
       ~                       EAP Message                             ~
       !                                                               !
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                      Figure 24:  EAP Payload Format

      The payload type for an EAP Payload is forty eight (48).

                            1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       !     Code      ! Identifier    !           Length              !
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       !     Type      ! Type_Data...
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

                      Figure 25:  EAP Message Format

   o  Code (one octet) indicates whether this message is a
      Request (1), Response (2), Success (3), or Failure (4).

   o  Identifier (one octet) is used in PPP to distinguish replayed
      messages from repeated ones. Since in IKE, EAP runs over a
      reliable protocol, it serves no function here. In a response
      message this octet MUST be set to match the identifier in the
      corresponding request. In other messages, this field MAY
      be set to any value.

   o  Length (two octets) is the length of the EAP message and MUST
      be four less than the Payload Length of the encapsulating
      payload.

   o  Type (one octet) is present only if the Code field is Request
      (1) or Response (2). For other codes, the EAP message length
      MUST be four octets and the Type and Type_Data fields MUST NOT
      be present. In a Request (1) message, Type indicates the
      data being requested. In a Response (2) message, Type MUST
      either be Nak or match the type of the data requested. The
      following types are defined in RFC 3748:

      1  Identity
      2  Notification
      3  Nak (Response Only)
      4  MD5-Challenge
      5  One-Time Password (OTP)
      6  Generic Token Card

   o  Type_Data (Variable Length) varies with the Type of Request
      and the associated Response. For the documentation of the
      EAP methods, see [EAP].

*/
struct _rhp_proto_ike_eap_payload
{
  u8  next_payload;

  u8 critical_rsv;

  u16 len;

#define RHP_PROTO_EAP_CODE_REQUEST		1
#define RHP_PROTO_EAP_CODE_RESPONSE		2
#define RHP_PROTO_EAP_CODE_SUCCESS		3
#define RHP_PROTO_EAP_CODE_FAILURE		4
  u8 eap_code;

  u8 eap_identifier;
  u16 eap_len;
};
typedef struct _rhp_proto_ike_eap_payload    rhp_proto_ike_eap_payload;


struct _rhp_proto_ike_eap_payload_request
{
  u8  next_payload;

  u8 critical_rsv;

  u16 len;

  u8 eap_code;
  u8 eap_identifier;
  u16 eap_len;

#define RHP_PROTO_EAP_TYPE_NONE									0
#define RHP_PROTO_EAP_TYPE_IDENTITY							1
#define RHP_PROTO_EAP_TYPE_NOTIFICATION					2
#define RHP_PROTO_EAP_TYPE_NAK									3
#define RHP_PROTO_EAP_TYPE_MD5_CHALLENGE				4
#define RHP_PROTO_EAP_TYPE_ONE_TIME_PASSWORD		5
#define RHP_PROTO_EAP_TYPE_GENERIC_TOKEN_CARD		6
#define RHP_PROTO_EAP_TYPE_EAP_TLS							13
#define RHP_PROTO_EAP_TYPE_EAP_GSM_SIM					18
#define RHP_PROTO_EAP_TYPE_EAP_TTLS							21
#define RHP_PROTO_EAP_TYPE_EAP_AKA							23
#define RHP_PROTO_EAP_TYPE_PEAP									25
#define RHP_PROTO_EAP_TYPE_MS_CHAPV2						26
#define RHP_PROTO_EAP_TYPE_PEAPV0_MS_CHAPV2			29
#define RHP_PROTO_EAP_TYPE_EAP_FAST							43
#define RHP_PROTO_EAP_TYPE_EAP_PSK							47
#define RHP_PROTO_EAP_TYPE_EAP_SAKE							48
#define RHP_PROTO_EAP_TYPE_EAP_IKEV2						49
#define RHP_PROTO_EAP_TYPE_EAP_AKA_PRIME				50
#define RHP_PROTO_EAP_TYPE_EAP_GPSK							51
#define RHP_PROTO_EAP_TYPE_EAP_PWD							52
#define RHP_PROTO_EAP_TYPE_EAP_EKE_V1						53
#define RHP_PROTO_EAP_TYPE_EAP_PT_EAP						54
#define RHP_PROTO_EAP_TYPE_TEAP									55


#define RHP_PROTO_EAP_TYPE_PRIV_MIN							500 // Internal use only. (u16)
#define RHP_PROTO_EAP_TYPE_PRIV_MAX							0xFFFF // Internal use only. (u16)
#define RHP_PROTO_EAP_TYPE_PRIV(eap_method)			((eap_method) >= RHP_PROTO_EAP_TYPE_PRIV_MIN && (eap_method) <= RHP_PROTO_EAP_TYPE_PRIV_MAX)

#define RHP_PROTO_EAP_TYPE_PRIV_RADIUS					500 // Internal use only. (> 255)
#define RHP_PROTO_EAP_TYPE_PRIV_IKEV1_XAUTH_PAP	550 // Internal use only. (> 255)
  u8 eap_type;
	/* type_data... */
};
typedef struct _rhp_proto_ike_eap_payload_request	rhp_proto_ike_eap_payload_request;
typedef struct _rhp_proto_ike_eap_payload_request	rhp_proto_ike_eap_payload_response;

typedef struct _rhp_proto_ike_eap_payload	rhp_proto_ike_eap_payload_success;
typedef struct _rhp_proto_ike_eap_payload	rhp_proto_ike_eap_payload_failure;


struct _rhp_proto_eap
{
/*
	RHP_PROTO_EAP_CODE_REQUEST		1
	RHP_PROTO_EAP_CODE_RESPONSE		2
	RHP_PROTO_EAP_CODE_SUCCESS		3
	RHP_PROTO_EAP_CODE_FAILURE		4
*/
  u8 code;
  u8 identifier;
  u16 len;
};
typedef struct _rhp_proto_eap    rhp_proto_eap;

struct _rhp_proto_eap_request
{
/*
	RHP_PROTO_EAP_CODE_REQUEST		1
	RHP_PROTO_EAP_CODE_RESPONSE		2
*/
  u8 code;
  u8 identifier;
  u16 len;

  u8 type;
};
typedef struct _rhp_proto_eap_request    rhp_proto_eap_request;
typedef struct _rhp_proto_eap_request    rhp_proto_eap_response;
typedef struct _rhp_proto_eap						 rhp_proto_eap_success;
typedef struct _rhp_proto_eap						 rhp_proto_eap_failure;

//
// "Extensible Authentication Protocol (EAP)"
//   - http://tools.ietf.org/html/rfc3748
//
// "PPP Challenge Handshake Authentication Protocol (CHAP)"
//   - http://tools.ietf.org/html/rfc1994
//
//
// "Microsoft PPP CHAP Extensions, Version 2"
//   - http://tools.ietf.org/html/rfc2759
//
// "Deriving Keys for use with Microsoft Point-to-Point Encryption (MPPE)"
//   - http://www.ietf.org/rfc/rfc3079.txt
//    3.3.  Generating 128-bit Session Keys
//    and
//    [EAP MSK] = MasterReceiveKey + MasterSendKey + 32 bytes zeroes (padding)
//
// "[MS-CHAP]: Extensible Authentication Protocol Method for Microsoft Challenge
//  Handshake Authentication Protocol (CHAP) Specification"
//   - http://msdn.microsoft.com/en-us/library/cc224612%28v=prot.13%29.aspx
//   - http://download.microsoft.com/download/a/e/6/ae6e4142-aa58-45c6-8dcf-a657e5900cd3/%5BMS-CHAP%5D.pdf
//
// "Microsoft EAP CHAP Extensions"
//   - http://tools.ietf.org/html/draft-kamath-pppext-eap-mschapv2-02
//
struct _rhp_proto_ms_chapv2
{
#define RHP_PROTO_MS_CHAPV2_CODE_CHALLENGE	1
#define RHP_PROTO_MS_CHAPV2_CODE_RESPONSE		2
#define RHP_PROTO_MS_CHAPV2_CODE_SUCCESS		3
#define RHP_PROTO_MS_CHAPV2_CODE_FAILURE		4
#define RHP_PROTO_MS_CHAPV2_CODE_CHANGE_PASSWORD	7
	u8 ms_code;
	u8 ms_identifier;
	u16 ms_len;
	/* data */
};
typedef struct _rhp_proto_ms_chapv2	rhp_proto_ms_chapv2;


struct _rhp_proto_ms_chapv2_challenge
{
	u8 ms_code;
	u8 ms_identifier;
	u16 ms_len;

	u8 ms_challenge_size; // 16 bytes
	u8 ms_challenge[16];
	/* name(if any) */
};
typedef struct _rhp_proto_ms_chapv2_challenge	rhp_proto_ms_chapv2_challenge;


struct _rhp_proto_ms_chapv2_response
{
	u8 ms_code;
	u8 ms_identifier;
	u16 ms_len;

	u8 ms_response_size; // 49 bytes
	u8 ms_peer_challenge[16];
	u8 ms_reserved[8];/* This field must be zero.*/
	u8 ms_nt_response[24];
	u8 ms_flags; /* This field must be zero.*/

#define RHP_PROTO_MS_CHAPV2_NAME_MAX	256
	/* name : 0 -- 256 bytes, case sensitive ascii chars */
};
typedef struct _rhp_proto_ms_chapv2_response	rhp_proto_ms_chapv2_response;


typedef struct _rhp_proto_ms_chapv2	rhp_proto_ms_chapv2_success;
typedef struct _rhp_proto_ms_chapv2	rhp_proto_ms_chapv2_failure;


#define RHP_PROTO_MS_CHAPV2_ERROR_RESTRICTED_LOGON_HOURS	"646"
#define RHP_PROTO_MS_CHAPV2_ERROR_ACCT_DISABLED	"647"
#define RHP_PROTO_MS_CHAPV2_ERROR_PASSWD_EXPIRED	"648"
#define RHP_PROTO_MS_CHAPV2_ERROR_NO_DIALIN_PERMISSION	"649"
#define RHP_PROTO_MS_CHAPV2_ERROR_AUTHENTICATION_FAILURE	"691"
#define RHP_PROTO_MS_CHAPV2_ERROR_CHANGING_PASSWORD	"709"


/*

 [RFC7383 : Internet Key Exchange Protocol Version 2 (IKEv2) Message Fragmentation]

2.5.  Fragmenting Message

   Only messages that contain an Encrypted payload are subject to IKE
   fragmentation.  For the purpose of construction of IKE Fragment
   messages, the original (unencrypted) content of the Encrypted payload
   is split into chunks.  The content is treated as a binary blob and is
   split regardless of the boundaries of inner payloads.  Each of the
   resulting chunks is treated as an original content of the Encrypted
   Fragment payload and is then encrypted and authenticated.  Thus, the
   Encrypted Fragment payload contains a chunk of the original content
   of the Encrypted payload in encrypted form.  The cryptographic
   processing of the Encrypted Fragment payload is identical to that

   described in Section 3.14 of [RFC7296], as well as documents updating
   such processing for particular algorithms or modes, such as
   [RFC5282].

   As is the case for the Encrypted payload, the Encrypted Fragment
   payload, if present in a message, MUST be the last payload in the
   message.

   The Encrypted Fragment payload is denoted SKF{...}, and its payload
   type is 53.  This payload is also called the "Encrypted and
   Authenticated Fragment" payload.

                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Fragment Number        |        Total Fragments        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Initialization Vector                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                      Encrypted content                        ~
   +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               |             Padding (0-255 octets)            |
   +-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
   |                                               |  Pad Length   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                    Integrity Checksum Data                    ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                        Encrypted Fragment Payload

   o  Next Payload (1 octet) - in the very first fragment (with Fragment
      Number equal to 1), this field MUST be set to the payload type of
      the first inner payload (the same as for the Encrypted payload).
      In the rest of the Fragment messages (with Fragment Number greater
      than 1), this field MUST be set to zero.

   o  Fragment Number (2 octets, unsigned integer) - current Fragment
      message number, starting from 1.  This field MUST be less than or
      equal to the next field (Total Fragments).  This field MUST NOT be
      zero.

   o  Total Fragments (2 octets, unsigned integer) - number of Fragment
      messages into which the original message was divided.  This field
      MUST NOT be zero.  With PMTU discovery, this field plays an
      additional role.  See Section 2.5.2 for details.

   The other fields are identical to those specified in Section 3.14 of
   [RFC7296].

   When prepending the IKE header to the IKE Fragment messages, it MUST
   be taken intact from the original message, except for the Length and
   Next Payload fields.  The Length field is adjusted to reflect the
   length of the IKE Fragment message being constructed, and the Next
   Payload field is set to the payload type of the first payload in that
   message (in most cases, it will be the Encrypted Fragment payload).
   After prepending the IKE header and all payloads that possibly
   precede the Encrypted payload in the original message (if any; see
   Section 2.5.3), the resulting messages are sent to the peer.

   Below is an example of fragmenting a message.

   HDR(MID=n), SK(NextPld=PLD1) {PLD1 ... PLDN}

                             Original Message

   HDR(MID=n), SKF(NextPld=PLD1, Frag#=1, TotalFrags=m) {...},
   HDR(MID=n), SKF(NextPld=0, Frag#=2, TotalFrags=m) {...},
   ...
   HDR(MID=n), SKF(NextPld=0, Frag#=m, TotalFrags=m) {...}

*/
struct _rhp_proto_ike_skf_payload
{
  u8  next_payload;

  u8 critical_rsv;

  u16 len;

  u16 frag_num;
  u16 total_frags;
};
typedef struct _rhp_proto_ike_skf_payload    rhp_proto_ike_skf_payload;




/*

  - STUN payload (RHP's private extension)


                      1               2               3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       ! Next Payload !C!  RESERVED   !       Payload Length           !
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       !                                                               !
       ~                       STUN Message                            ~
       !                                                               !
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                            STUN Payload Format


      The payload type for an STUN Payload is 215.


       0             1               2               3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |0 0|     STUN Message Type    |         Message Length         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                       Magic Cookie                            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      |                   Transaction ID (96 bits)                    |
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      ~                 STUN Attributes(if any)                       ~
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                      STUN Message Format (RFC5389)

*/
typedef rhp_proto_ike_payload		rhp_proto_ike_stun_payload;





/*

 (RFC 5389)

6. STUN Message Structure

   STUN messages are encoded in binary using network-oriented format
   (most significant byte or octet first, also commonly known as big-
   endian).  The transmission order is described in detail in Appendix B
   of RFC 791 [RFC0791].  Unless otherwise noted, numeric constants are
   in decimal (base 10).

   All STUN messages MUST start with a 20-byte header followed by zero
   or more Attributes.  The STUN header contains a STUN message type,
   magic cookie, transaction ID, and message length.

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |0 0|     STUN Message Type     |         Message Length        |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                        Magic Cookie                           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      |                   Transaction ID (96 bits)                    |
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                  Figure 2: Format of STUN Message Header

   The most significant 2 bits of every STUN message MUST be zeroes.
   This can be used to differentiate STUN packets from other protocols
   when STUN is multiplexed with other protocols on the same port.

   The message type defines the message class (request, success
   response, failure response, or indication) and the message method
   (the primary function) of the STUN message.  Although there are four
   message classes, there are only two types of transactions in STUN:
   request/response transactions (which consist of a request message and
   a response message) and indication transactions (which consist of a
   single indication message).  Response classes are split into error
   and success responses to aid in quickly processing the STUN message.

   The message type field is decomposed further into the following
   structure:

                         0                1
                         2  3 4 5 6 7 8 9 0 1 2 3 4 5
                       +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
                       | M| M|M|M|M|C|M|M|M|C|M|M|M|M|
                       |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
                       +--+--+-+-+-+-+-+-+-+-+-+-+-+-+

                Figure 3: Format of STUN Message Type Field

   Here the bits in the message type field are shown as most significant
   (M11) through least significant (M0).  M11 through M0 represent a 12-
   bit encoding of the method.  C1 and C0 represent a 2-bit encoding of
   the class.  A class of 0b00 is a request, a class of 0b01 is an
   indication, a class of 0b10 is a success response, and a class of
   0b11 is an error response.  This specification defines a single
   method, Binding.  The method and class are orthogonal, so that for
   each method, a request, success response, error response, and
   indication are possible for that method.  Extensions defining new
   methods MUST indicate which classes are permitted for that method.

   For example, a Binding request has class=0b00 (request) and
   method=0b000000000001 (Binding) and is encoded into the first 16 bits
   as 0x0001.  A Binding response has class=0b10 (success response) and
   method=0b000000000001, and is encoded into the first 16 bits as
   0x0101.

      Note: This unfortunate encoding is due to assignment of values in
      [RFC3489] that did not consider encoding Indications, Success, and
      Errors using bit fields.

   The magic cookie field MUST contain the fixed value 0x2112A442 in
   network byte order.  In RFC 3489 [RFC3489], this field was part of
   the transaction ID; placing the magic cookie in this location allows
   a server to detect if the client will understand certain attributes
   that were added in this revised specification.  In addition, it aids
   in distinguishing STUN packets from packets of other protocols when
   STUN is multiplexed with those other protocols on the same port.

   The transaction ID is a 96-bit identifier, used to uniquely identify
   STUN transactions.  For request/response transactions, the
   transaction ID is chosen by the STUN client for the request and
   echoed by the server in the response.  For indications, it is chosen
   by the agent sending the indication.  It primarily serves to
   correlate requests with responses, though it also plays a small role
   in helping to prevent certain types of attacks.  The server also uses
   the transaction ID as a key to identify each transaction uniquely
   across all clients.  As such, the transaction ID MUST be uniformly
   and randomly chosen from the interval 0 .. 2**96-1, and SHOULD be
   cryptographically random.  Resends of the same request reuse the same
   transaction ID, but the client MUST choose a new transaction ID for
   new transactions unless the new request is bit-wise identical to the
   previous request and sent from the same transport address to the same
   IP address.  Success and error responses MUST carry the same
   transaction ID as their corresponding request.  When an agent is
   acting as a STUN server and STUN client on the same port, the
   transaction IDs in requests sent by the agent have no relationship to
   the transaction IDs in requests received by the agent.

   The message length MUST contain the size, in bytes, of the message
   not including the 20-byte STUN header.  Since all STUN attributes are
   padded to a multiple of 4 bytes, the last 2 bits of this field are
   always zero.  This provides another way to distinguish STUN packets
   from packets of other protocols.

   Following the STUN fixed portion of the header are zero or more
   attributes.  Each attribute is TLV (Type-Length-Value) encoded.  The
   details of the encoding, and of the attributes themselves are given
   in Section 15.


18.1. STUN Methods Registry

   A STUN method is a hex number in the range 0x000 - 0xFFF.  The
   encoding of STUN method into a STUN message is described in
   Section 6.

   The initial STUN methods are:

   0x000: (Reserved)
   0x001: Binding
   0x002: (Reserved; was SharedSecret)

   STUN methods in the range 0x000 - 0x7FF are assigned by IETF Review
   [RFC5226].  STUN methods in the range 0x800 - 0xFFF are assigned by
   Designated Expert [RFC5226].  The responsibility of the expert is to
   verify that the selected codepoint(s) are not in use and that the
   request is not for an abnormally large number of codepoints.
   Technical review of the extension itself is outside the scope of the
   designated expert responsibility.

 18.4. STUN UDP and TCP Port Numbers

   IANA has previously assigned port 3478 for STUN.  This port appears
   in the IANA registry under the moniker "nat-stun-port".  In order to
   align the DNS SRV procedures with the registered protocol service,
   IANA is requested to change the name of protocol assigned to port
   3478 from "nat-stun-port" to "stun", and the textual name from
   "Simple Traversal of UDP Through NAT (STUN)" to "Session Traversal
   Utilities for NAT", so that the IANA port registry would read:

   stun   3478/tcp   Session Traversal Utilities for NAT (STUN) port
   stun   3478/udp   Session Traversal Utilities for NAT (STUN) port

   In addition, IANA has assigned port number 5349 for the "stuns"
   service, defined over TCP and UDP.  The UDP port is not currently
   defined; however, it is reserved for future use.

*/

static inline u16 _rhp_proto_stun_mesg_type(u8 class, u16 method)
{
	return htons( ((method & 0x0f80) << 2) | ((method & 0x0070) << 1) |
			((method & 0x000f) << 0) | ((class & 0x02) << 7) | ((class & 0x01) << 4) );
}

static inline u8 _rhp_proto_stun_mesg_class(u16 mesg_type)
{
	mesg_type = ntohs(mesg_type);
	return (u8)( ((mesg_type >> 7) | (mesg_type >> 4)) & 0x03);
}

static inline u16 _rhp_proto_stun_mesg_method(u16 mesg_type)
{
	mesg_type = ntohs(mesg_type);
	return ( ((mesg_type & 0x3e00) >> 2) | ((mesg_type & 0x00e0) >> 1) | (mesg_type & 0x000f) );
}


#define RHP_PROTO_STUN_PORT		3478

struct _rhp_proto_stun {

#define RHP_PROTO_STUN_METHOD_BIND								1
#define RHP_PROTO_STUN_METHOD_ALLOCATE						3 // (TURN: RFC5766)
#define RHP_PROTO_STUN_METHOD_REFRESH							4 // (TURN: RFC5766)
#define RHP_PROTO_STUN_METHOD_SEND								6 // (TURN: RFC5766)
#define RHP_PROTO_STUN_METHOD_DATA								7 // (TURN: RFC5766)
#define RHP_PROTO_STUN_METHOD_CREATE_PERMISSION		8 // (TURN: RFC5766)
#define RHP_PROTO_STUN_METHOD_CHANNEL_BIND				9 // (TURN: RFC5766)

#define RHP_PROTO_STUN_CLASS_REQ							0
#define RHP_PROTO_STUN_CLASS_INDICATION				1
#define RHP_PROTO_STUN_CLASS_RESP							2
#define RHP_PROTO_STUN_CLASS_ERROR						3
	u16 mesg_type;
	u16 mesg_len;

#define RHP_PROTO_STUN_MAGIC_COOKIE		0x2112a442
	u32 magic_cookie;

	#define RHP_PROTO_STUN_TXN_ID_SIZE		12
  u8  txn_id[RHP_PROTO_STUN_TXN_ID_SIZE];
};
typedef struct _rhp_proto_stun		rhp_proto_stun;


#define RHP_PROTO_STUN_AF_IPV4		1
#define RHP_PROTO_STUN_AF_IPV6		2


/*

  (RFC 5389)

 15. STUN Attributes

   After the STUN header are zero or more attributes.  Each attribute
   MUST be TLV encoded, with a 16-bit type, 16-bit length, and value.
   Each STUN attribute MUST end on a 32-bit boundary.  As mentioned
   above, all fields in an attribute are transmitted most significant
   bit first.

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |         Type                  |            Length             |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                         Value (variable)                ....
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                    Figure 4: Format of STUN Attributes

   The value in the length field MUST contain the length of the Value
   part of the attribute, prior to padding, measured in bytes.  Since
   STUN aligns attributes on 32-bit boundaries, attributes whose content
   is not a multiple of 4 bytes are padded with 1, 2, or 3 bytes of
   padding so that its value contains a multiple of 4 bytes.  The
   padding bits are ignored, and may be any value.

   Any attribute type MAY appear more than once in a STUN message.
   Unless specified otherwise, the order of appearance is significant:
   only the first occurrence needs to be processed by a receiver, and
   any duplicates MAY be ignored by a receiver.

   To allow future revisions of this specification to add new attributes
   if needed, the attribute space is divided into two ranges.
   Attributes with type values between 0x0000 and 0x7FFF are
   comprehension-required attributes, which means that the STUN agent
   cannot successfully process the message unless it understands the
   attribute.  Attributes with type values between 0x8000 and 0xFFFF are
   comprehension-optional attributes, which means that those attributes
   can be ignored by the STUN agent if it does not understand them.

   The set of STUN attribute types is maintained by IANA.  The initial
   set defined by this specification is found in Section 18.2.

   The rest of this section describes the format of the various
   attributes defined in this specification.


 18.2. STUN Attribute Registry

   A STUN Attribute type is a hex number in the range 0x0000 - 0xFFFF.
   STUN attribute types in the range 0x0000 - 0x7FFF are considered
   comprehension-required; STUN attribute types in the range 0x8000 -
   0xFFFF are considered comprehension-optional.  A STUN agent handles
   unknown comprehension-required and comprehension-optional attributes
   differently.

   The initial STUN Attributes types are:

   Comprehension-required range (0x0000-0x7FFF):
     0x0000: (Reserved)
     0x0001: MAPPED-ADDRESS
     0x0002: (Reserved; was RESPONSE-ADDRESS)
     0x0003: (Reserved; was CHANGE-ADDRESS)
     0x0004: (Reserved; was SOURCE-ADDRESS)
     0x0005: (Reserved; was CHANGED-ADDRESS)
     0x0006: USERNAME
     0x0007: (Reserved; was PASSWORD)
     0x0008: MESSAGE-INTEGRITY
     0x0009: ERROR-CODE
     0x000A: UNKNOWN-ATTRIBUTES
     0x000B: (Reserved; was REFLECTED-FROM)
     0x0014: REALM
     0x0015: NONCE
     0x0020: XOR-MAPPED-ADDRESS

   Comprehension-optional range (0x8000-0xFFFF)
     0x8022: SOFTWARE
     0x8023: ALTERNATE-SERVER
     0x8028: FINGERPRINT

   STUN Attribute types in the first half of the comprehension-required
   range (0x0000 - 0x3FFF) and in the first half of the comprehension-
   optional range (0x8000 - 0xBFFF) are assigned by IETF Review
   [RFC5226].  STUN Attribute types in the second half of the
   comprehension-required range (0x4000 - 0x7FFF) and in the second half
   of the comprehension-optional range (0xC000 - 0xFFFF) are assigned by
   Designated Expert [RFC5226].  The responsibility of the expert is to
   verify that the selected codepoint(s) are not in use, and that the
   request is not for an abnormally large number of codepoints.
   Technical review of the extension itself is outside the scope of the
   designated expert responsibility.

18.3. STUN Error Code Registry

   A STUN error code is a number in the range 0 - 699.  STUN error codes
   are accompanied by a textual reason phrase in UTF-8 [RFC3629] that is
   intended only for human consumption and can be anything appropriate;
   this document proposes only suggested values.

   STUN error codes are consistent in codepoint assignments and
   semantics with SIP [RFC3261] and HTTP [RFC2616].

   The initial values in this registry are given in Section 15.6.

   New STUN error codes are assigned based on IETF Review [RFC5226].
   The specification must carefully consider how clients that do not
   understand this error code will process it before granting the
   request.  See the rules in Section 7.3.4.




  (RFC 5766)

 14. New STUN Attributes

   This STUN extension defines the following new attributes:

     0x000C: CHANNEL-NUMBER
     0x000D: LIFETIME
     0x0010: Reserved (was BANDWIDTH)
     0x0012: XOR-PEER-ADDRESS
     0x0013: DATA
     0x0016: XOR-RELAYED-ADDRESS
     0x0018: EVEN-PORT
     0x0019: REQUESTED-TRANSPORT
     0x001A: DONT-FRAGMENT
     0x0021: Reserved (was TIMER-VAL)
     0x0022: RESERVATION-TOKEN

   Some of these attributes have lengths that are not multiples of 4.
   By the rules of STUN, any attribute whose length is not a multiple of
   4 bytes MUST be immediately followed by 1 to 3 padding bytes to
   ensure the next attribute (if any) would start on a 4-byte boundary
   (see [RFC5389]).
*/
struct _rhp_proto_stun_attr {

#define RHP_PROTO_STUN_ATTR_MAPPED_ADDRESS					0x01
#define RHP_PROTO_STUN_ATTR_USERNAME								0x06
#define RHP_PROTO_STUN_ATTR_MESSAGE_INTEGRITY				0x08
#define RHP_PROTO_STUN_ATTR_ERROR_CODE							0x09
#define RHP_PROTO_STUN_ATTR_UNKNOWN_ATTRIBUTES			0x0a
#define RHP_PROTO_STUN_ATTR_REALM										0x14
#define RHP_PROTO_STUN_ATTR_NONCE										0x15
#define RHP_PROTO_STUN_ATTR_XOR_MAPPED_ADDRESS			0x20
#define RHP_PROTO_STUN_ATTR_SOFTWARE								0x8022
#define RHP_PROTO_STUN_ATTR_ALTERNATE_SERVER				0x8023
#define RHP_PROTO_STUN_ATTR_FINGERPRINT							0x8028

#define RHP_PROTO_STUN_ATTR_CHANNEL_NUMBER					0x0c // (RFC 5766)
#define RHP_PROTO_STUN_ATTR_LIFETIME								0x0d // (RFC 5766)
#define RHP_PROTO_STUN_ATTR_XOR_PEER_ADDRESS				0x12 // (RFC 5766)
#define RHP_PROTO_STUN_ATTR_DATA										0x13 // (RFC 5766)
#define RHP_PROTO_STUN_ATTR_XOR_RELAYED_ADDRESS			0x16 // (RFC 5766)
#define RHP_PROTO_STUN_ATTR_EVEN_PORT								0x18 // (RFC 5766)
#define RHP_PROTO_STUN_ATTR_REQUESTED_TRANSPORT			0x19 // (RFC 5766)
#define RHP_PROTO_STUN_ATTR_DONT_FRAGMENT						0x1a // (RFC 5766)
#define RHP_PROTO_STUN_ATTR_RESERVATION_TOKEN				0x22 // (RFC 5766)
	u16 attr_type;

	u16 attr_len;

	/* ...Value(variable)... */
};
typedef struct _rhp_proto_stun_attr		rhp_proto_stun_attr;




/*

 15.1. MAPPED-ADDRESS

   The MAPPED-ADDRESS attribute indicates a reflexive transport address
   of the client.  It consists of an 8-bit address family and a 16-bit
   port, followed by a fixed-length value representing the IP address.
   If the address family is IPv4, the address MUST be 32 bits.  If the
   address family is IPv6, the address MUST be 128 bits.  All fields
   must be in network byte order.

   The format of the MAPPED-ADDRESS attribute is:

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |0 0 0 0 0 0 0 0|    Family     |           Port                |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      |                 Address (32 bits or 128 bits)                 |
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

               Figure 5: Format of MAPPED-ADDRESS Attribute

   The address family can take on the following values:

   0x01:IPv4
   0x02:IPv6

   The first 8 bits of the MAPPED-ADDRESS MUST be set to 0 and MUST be
   ignored by receivers.  These bits are present for aligning parameters
   on natural 32-bit boundaries.

   This attribute is used only by servers for achieving backwards
   compatibility with RFC 3489 [RFC3489] clients.
*/

struct _rhp_proto_stun_attr_mapped_addr_v {

	u8 reserved; // 0
	u8 addr_family; // RHP_PROTO_STUN_AF_XXX
	u16 port;

	/* IPv4 address(4 bytes) or IPv6 address(16 bytes) */
};
typedef struct _rhp_proto_stun_attr_mapped_addr_v		rhp_proto_stun_attr_mapped_addr_v;

struct _rhp_proto_stun_attr_mapped_addr {

	u16 attr_type;
	u16 attr_len;
	rhp_proto_stun_attr_mapped_addr_v attr_val;
};
typedef struct _rhp_proto_stun_attr_mapped_addr		rhp_proto_stun_attr_mapped_addr;


/*

 15.2. XOR-MAPPED-ADDRESS

   The XOR-MAPPED-ADDRESS attribute is identical to the MAPPED-ADDRESS
   attribute, except that the reflexive transport address is obfuscated
   through the XOR function.

   The format of the XOR-MAPPED-ADDRESS is:

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |x x x x x x x x|    Family     |         X-Port                |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                X-Address (Variable)
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

             Figure 6: Format of XOR-MAPPED-ADDRESS Attribute

   The Family represents the IP address family, and is encoded
   identically to the Family in MAPPED-ADDRESS.

   X-Port is computed by taking the mapped port in host byte order,
   XOR'ing it with the most significant 16 bits of the magic cookie, and
   then the converting the result to network byte order.  If the IP
   address family is IPv4, X-Address is computed by taking the mapped IP
   address in host byte order, XOR'ing it with the magic cookie, and
   converting the result to network byte order.  If the IP address
   family is IPv6, X-Address is computed by taking the mapped IP address
   in host byte order, XOR'ing it with the concatenation of the magic
   cookie and the 96-bit transaction ID, and converting the result to
   network byte order.

   The rules for encoding and processing the first 8 bits of the
   attribute's value, the rules for handling multiple occurrences of the
   attribute, and the rules for processing address families are the same
   as for MAPPED-ADDRESS.

   Note: XOR-MAPPED-ADDRESS and MAPPED-ADDRESS differ only in their
   encoding of the transport address.  The former encodes the transport
   address by exclusive-or'ing it with the magic cookie.  The latter
   encodes it directly in binary.  RFC 3489 originally specified only
   MAPPED-ADDRESS.  However, deployment experience found that some NATs
   rewrite the 32-bit binary payloads containing the NAT's public IP
   address, such as STUN's MAPPED-ADDRESS attribute, in the well-meaning
   but misguided attempt at providing a generic ALG function.  Such
   behavior interferes with the operation of STUN and also causes
   failure of STUN's message-integrity checking.
*/
struct _rhp_proto_stun_attr_xor_mapped_addr_v {

	u16 attr_type;
	u16 attr_len;

	u8 reserved; // 0
	u8 addr_family; // RHP_PROTO_STUN_AF_XXX
	u16 x_port;

	/* XORed IPv4 address(4 bytes) or XORed IPv6 address(16 bytes) */
};
typedef struct _rhp_proto_stun_attr_xor_mapped_addr_v		rhp_proto_stun_attr_xor_mapped_addr_v;

struct _rhp_proto_stun_attr_xor_mapped_addr {

	u16 attr_type;
	u16 attr_len;
	rhp_proto_stun_attr_xor_mapped_addr_v attr_val;
};
typedef struct _rhp_proto_stun_attr_xor_mapped_addr		rhp_proto_stun_attr_xor_mapped_addr;


/*
  15.3. USERNAME

   The USERNAME attribute is used for message integrity.  It identifies
   the username and password combination used in the message-integrity
   check.

   The value of USERNAME is a variable-length value.  It MUST contain a
   UTF-8 [RFC3629] encoded sequence of less than 513 bytes, and MUST
   have been processed using SASLprep [RFC4013].
*/

typedef struct _rhp_proto_stun_attr		rhp_proto_stun_attr_username;


/*
 15.4. MESSAGE-INTEGRITY

   The MESSAGE-INTEGRITY attribute contains an HMAC-SHA1 [RFC2104] of
   the STUN message.  The MESSAGE-INTEGRITY attribute can be present in
   any STUN message type.  Since it uses the SHA1 hash, the HMAC will be
   20 bytes.  The text used as input to HMAC is the STUN message,
   including the header, up to and including the attribute preceding the
   MESSAGE-INTEGRITY attribute.  With the exception of the FINGERPRINT
   attribute, which appears after MESSAGE-INTEGRITY, agents MUST ignore
   all other attributes that follow MESSAGE-INTEGRITY.

   The key for the HMAC depends on whether long-term or short-term
   credentials are in use.  For long-term credentials, the key is 16
   bytes:

            key = MD5(username ":" realm ":" SASLprep(password))

   That is, the 16-byte key is formed by taking the MD5 hash of the
   result of concatenating the following five fields: (1) the username,
   with any quotes and trailing nulls removed, as taken from the
   USERNAME attribute (in which case SASLprep has already been applied);
   (2) a single colon; (3) the realm, with any quotes and trailing nulls
   removed; (4) a single colon; and (5) the password, with any trailing
   nulls removed and after processing using SASLprep.  For example, if
   the username was 'user', the realm was 'realm', and the password was
   'pass', then the 16-byte HMAC key would be the result of performing
   an MD5 hash on the string 'user:realm:pass', the resulting hash being
   0x8493fbc53ba582fb4c044c456bdc40eb.

   For short-term credentials:

                          key = SASLprep(password)

   where MD5 is defined in RFC 1321 [RFC1321] and SASLprep() is defined
   in RFC 4013 [RFC4013].

   The structure of the key when used with long-term credentials
   facilitates deployment in systems that also utilize SIP.  Typically,
   SIP systems utilizing SIP's digest authentication mechanism do not
   actually store the password in the database.  Rather, they store a
   value called H(A1), which is equal to the key defined above.

   Based on the rules above, the hash used to construct MESSAGE-
   INTEGRITY includes the length field from the STUN message header.
   Prior to performing the hash, the MESSAGE-INTEGRITY attribute MUST be
   inserted into the message (with dummy content).  The length MUST then
   be set to point to the length of the message up to, and including,
   the MESSAGE-INTEGRITY attribute itself, but excluding any attributes
   after it.  Once the computation is performed, the value of the
   MESSAGE-INTEGRITY attribute can be filled in, and the value of the
   length in the STUN header can be set to its correct value -- the
   length of the entire message.  Similarly, when validating the
   MESSAGE-INTEGRITY, the length field should be adjusted to point to
   the end of the MESSAGE-INTEGRITY attribute prior to calculating the
   HMAC.  Such adjustment is necessary when attributes, such as
   FINGERPRINT, appear after MESSAGE-INTEGRITY.
*/

struct _rhp_proto_stun_attr_mesg_integ {

	u16 attr_type;
	u16 attr_len;

#define RHP_PROTO_STUN_ATTR_MESG_INTEG_SIZE	20
	u8 hmac[RHP_PROTO_STUN_ATTR_MESG_INTEG_SIZE];
};
typedef struct _rhp_proto_stun_attr_mesg_integ		rhp_proto_stun_attr_mesg_integ;



/*
 15.5. FINGERPRINT

   The FINGERPRINT attribute MAY be present in all STUN messages.  The
   value of the attribute is computed as the CRC-32 of the STUN message
   up to (but excluding) the FINGERPRINT attribute itself, XOR'ed with
   the 32-bit value 0x5354554e (the XOR helps in cases where an
   application packet is also using CRC-32 in it).  The 32-bit CRC is
   the one defined in ITU V.42 [ITU.V42.2002], which has a generator
   polynomial of x32+x26+x23+x22+x16+x12+x11+x10+x8+x7+x5+x4+x2+x+1.
   When present, the FINGERPRINT attribute MUST be the last attribute in
   the message, and thus will appear after MESSAGE-INTEGRITY.

   The FINGERPRINT attribute can aid in distinguishing STUN packets from
   packets of other protocols.  See Section 8.

   As with MESSAGE-INTEGRITY, the CRC used in the FINGERPRINT attribute
   covers the length field from the STUN message header.  Therefore,
   this value must be correct and include the CRC attribute as part of
   the message length, prior to computation of the CRC.  When using the
   FINGERPRINT attribute in a message, the attribute is first placed
   into the message with a dummy value, then the CRC is computed, and
   then the value of the attribute is updated.  If the MESSAGE-INTEGRITY
   attribute is also present, then it must be present with the correct
   message-integrity value before the CRC is computed, since the CRC is
   done over the value of the MESSAGE-INTEGRITY attribute as well.
*/

#define RHP_PROTO_STUN_ATTR_FINGERPRINT_MASK		0x5354554e
struct _rhp_proto_stun_attr_fingerprint {

	u16 attr_type;
	u16 attr_len;

	u32 crc32;
};
typedef struct _rhp_proto_stun_attr_fingerprint		rhp_proto_stun_attr_fingerprint;


/*

  (RFC 5389)

 15.6. ERROR-CODE

   The ERROR-CODE attribute is used in error response messages.  It
   contains a numeric error code value in the range of 300 to 699 plus a
   textual reason phrase encoded in UTF-8 [RFC3629], and is consistent
   in its code assignments and semantics with SIP [RFC3261] and HTTP
   [RFC2616].  The reason phrase is meant for user consumption, and can
   be anything appropriate for the error code.  Recommended reason
   phrases for the defined error codes are included in the IANA registry
   for error codes.  The reason phrase MUST be a UTF-8 [RFC3629] encoded
   sequence of less than 128 characters (which can be as long as 763
   bytes).

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |           Reserved, should be 0         |Class|     Number    |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |      Reason Phrase (variable)                                ..
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                      Figure 7: ERROR-CODE Attribute

   To facilitate processing, the class of the error code (the hundreds
   digit) is encoded separately from the rest of the code, as shown in
   Figure 7.

   The Reserved bits SHOULD be 0, and are for alignment on 32-bit
   boundaries.  Receivers MUST ignore these bits.  The Class represents
   the hundreds digit of the error code.  The value MUST be between 3
   and 6.  The Number represents the error code modulo 100, and its
   value MUST be between 0 and 99.

   The following error codes, along with their recommended reason
   phrases, are defined:

   300  Try Alternate: The client should contact an alternate server for
        this request.  This error response MUST only be sent if the
        request included a USERNAME attribute and a valid MESSAGE-
        INTEGRITY attribute; otherwise, it MUST NOT be sent and error
        code 400 (Bad Request) is suggested.  This error response MUST
        be protected with the MESSAGE-INTEGRITY attribute, and receivers
        MUST validate the MESSAGE-INTEGRITY of this response before
        redirecting themselves to an alternate server.

             Note: Failure to generate and validate message integrity
             for a 300 response allows an on-path attacker to falsify a
             300 response thus causing subsequent STUN messages to be
             sent to a victim.

   400  Bad Request: The request was malformed.  The client SHOULD NOT
        retry the request without modification from the previous
        attempt.  The server may not be able to generate a valid
        MESSAGE-INTEGRITY for this error, so the client MUST NOT expect
        a valid MESSAGE-INTEGRITY attribute on this response.

   401  Unauthorized: The request did not contain the correct
        credentials to proceed.  The client should retry the request
        with proper credentials.

   420  Unknown Attribute: The server received a STUN packet containing
        a comprehension-required attribute that it did not understand.
        The server MUST put this unknown attribute in the UNKNOWN-
        ATTRIBUTE attribute of its error response.

   438  Stale Nonce: The NONCE used by the client was no longer valid.
        The client should retry, using the NONCE provided in the
        response.

   500  Server Error: The server has suffered a temporary error.  The
        client should try again.



  (RFC 5766)

  15. New STUN Error Response Codes


   This document defines the following new error response codes:

   403  (Forbidden): The request was valid but cannot be performed due
      to administrative or similar restrictions.

   437  (Allocation Mismatch): A request was received by the server that
      requires an allocation to be in place, but no allocation exists,
      or a request was received that requires no allocation, but an
      allocation exists.

   441  (Wrong Credentials): The credentials in the (non-Allocate)
      request do not match those used to create the allocation.

   442  (Unsupported Transport Protocol): The Allocate request asked the
      server to use a transport protocol between the server and the peer
      that the server does not support.  NOTE: This does NOT refer to
      the transport protocol used in the 5-tuple.

   486  (Allocation Quota Reached): No more allocations using this
      username can be created at the present time.

   508  (Insufficient Capacity): The server is unable to carry out the
      request due to some capacity limit being reached.  In an Allocate
      response, this could be due to the server having no more relayed
      transport addresses available at that time, having none with the
      requested properties, or the one that corresponds to the specified
      reservation token is not available.
*/
struct _rhp_proto_stun_attr_error_code_v {

	u16 reserved0; // 0

#ifdef RHP_BIG_ENDIAN_BF
	u8 reserved1:5, error_class:3;
#else
	u8 error_class:3, reserved1:5;
#endif

#define RHP_PROTO_STUN_ERR_TRY_ALTERNATE_CLS			3
#define RHP_PROTO_STUN_ERR_TRY_ALTERNATE_ENO			0
#define RHP_PROTO_STUN_ERR_TRY_ALTERNATE_PHRASE		"Try Alternate"

#define RHP_PROTO_STUN_ERR_BAD_REQUEST_CLS  			4
#define RHP_PROTO_STUN_ERR_BAD_REQUEST_ENO  			0
#define RHP_PROTO_STUN_ERR_BAD_REQUEST_PHRASE			"Bad Request"

#define RHP_PROTO_STUN_ERR_UNAUTHORIZED_CLS  			4
#define RHP_PROTO_STUN_ERR_UNAUTHORIZED_ENO  			1
#define RHP_PROTO_STUN_ERR_UNAUTHORIZED_PHRASE		"Unauthorized"

#define RHP_PROTO_STUN_ERR_UNKNOWN_ATTR_CLS  			4
#define RHP_PROTO_STUN_ERR_UNKNOWN_ATTR_ENO  			20
#define RHP_PROTO_STUN_ERR_UNKNOWN_ATTR_PHRASE			"Unknown Attribute"

#define RHP_PROTO_STUN_ERR_STALE_NONCE_CLS  			4
#define RHP_PROTO_STUN_ERR_STALE_NONCE_ENO  			38
#define RHP_PROTO_STUN_ERR_STALE_NONCE_PHRASE			"Stale Nonce"

#define RHP_PROTO_STUN_ERR_SERVER_ERR_CLS  				5
#define RHP_PROTO_STUN_ERR_SERVER_ERR_ENO  				0
#define RHP_PROTO_STUN_ERR_SERVER_ERR_PHRASE			"Server Error"

#define RHP_PROTO_STUN_ERR_FORBIDDEN_CLS  				4
#define RHP_PROTO_STUN_ERR_FORBIDDEN_ENO  				3
#define RHP_PROTO_STUN_ERR_FORBIDDEN_PHRASE				"Forbidden"

#define RHP_PROTO_STUN_ERR_ALLOC_MISMATCH_CLS  		4
#define RHP_PROTO_STUN_ERR_ALLOC_MISMATCH_ENO  		37
#define RHP_PROTO_STUN_ERR_ALLOC_MISMATCH_PHRASE	"Allocation Mismatch"

#define RHP_PROTO_STUN_ERR_WRONG_CRED_CLS  				4
#define RHP_PROTO_STUN_ERR_WRONG_CRED_ENO  				41
#define RHP_PROTO_STUN_ERR_WRONG_CRED_PHRASE			"Wrong Credentials"

#define RHP_PROTO_STUN_ERR_UNSUP_TRANS_PROTO_CLS  	4
#define RHP_PROTO_STUN_ERR_UNSUP_TRANS_PROTO_ENO  	42
#define RHP_PROTO_STUN_ERR_UNSUP_TRANS_PROTO_PHRASE	"Unsupported Transport Protocol"

#define RHP_PROTO_STUN_ERR_ALLOC_QUOTA_REACHED_CLS		4
#define RHP_PROTO_STUN_ERR_ALLOC_QUOTA_REACHED_ENO		86
#define RHP_PROTO_STUN_ERR_ALLOC_QUOTA_REACHED_PHRASE	"Allocation Quota Reached"

#define RHP_PROTO_STUN_ERR_INSUF_CAPACITY_CLS  		5
#define RHP_PROTO_STUN_ERR_INSUF_CAPACITY_ENO  		8
#define RHP_PROTO_STUN_ERR_INSUF_CAPACITY_PHRASE	"Insufficient Capacity"

	u8 error_num;

	/* ... Reason Phrase (variable) ... */
};
typedef struct _rhp_proto_stun_attr_error_code_v		rhp_proto_stun_attr_error_code_v;

struct _rhp_proto_stun_attr_error_code {

	u16 attr_type;
	u16 attr_len;
	rhp_proto_stun_attr_error_code_v attr_val;
};
typedef struct _rhp_proto_stun_attr_error_code		rhp_proto_stun_attr_error_code;


/*
 15.7. REALM

   The REALM attribute may be present in requests and responses.  It
   contains text that meets the grammar for "realm-value" as described
   in RFC 3261 [RFC3261] but without the double quotes and their
   surrounding whitespace.  That is, it is an unquoted realm-value (and
   is therefore a sequence of qdtext or quoted-pair).  It MUST be a
   UTF-8 [RFC3629] encoded sequence of less than 128 characters (which
   can be as long as 763 bytes), and MUST have been processed using
   SASLprep [RFC4013].

   Presence of the REALM attribute in a request indicates that long-term
   credentials are being used for authentication.  Presence in certain
   error responses indicates that the server wishes the client to use a
   long-term credential for authentication.
*/

typedef struct _rhp_proto_stun_attr		rhp_proto_stun_attr_realm;


/*
 15.8. NONCE

   The NONCE attribute may be present in requests and responses.  It
   contains a sequence of qdtext or quoted-pair, which are defined in
   RFC 3261 [RFC3261].  Note that this means that the NONCE attribute
   will not contain actual quote characters.  See RFC 2617 [RFC2617],
   Section 4.3, for guidance on selection of nonce values in a server.

   It MUST be less than 128 characters (which can be as long as 763
   bytes).
*/

typedef struct _rhp_proto_stun_attr		rhp_proto_stun_attr_nonce;


/*
 15.9. UNKNOWN-ATTRIBUTES

   The UNKNOWN-ATTRIBUTES attribute is present only in an error response
   when the response code in the ERROR-CODE attribute is 420.

   The attribute contains a list of 16-bit values, each of which
   represents an attribute type that was not understood by the server.

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |      Attribute 1 Type           |     Attribute 2 Type        |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |      Attribute 3 Type           |     Attribute 4 Type    ...
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

             Figure 8: Format of UNKNOWN-ATTRIBUTES Attribute

      Note: In [RFC3489], this field was padded to 32 by duplicating the
      last attribute.  In this version of the specification, the normal
      padding rules for attributes are used instead.
*/

typedef struct _rhp_proto_stun_attr		rhp_proto_stun_attr_unknown_attrs;


/*
 15.10. SOFTWARE

   The SOFTWARE attribute contains a textual description of the software
   being used by the agent sending the message.  It is used by clients
   and servers.  Its value SHOULD include manufacturer and version
   number.  The attribute has no impact on operation of the protocol,
   and serves only as a tool for diagnostic and debugging purposes.  The
   value of SOFTWARE is variable length.  It MUST be a UTF-8 [RFC3629]
   encoded sequence of less than 128 characters (which can be as long as
   763 bytes).
*/

typedef struct _rhp_proto_stun_attr		rhp_proto_stun_attr_software;



/*
 15.11. ALTERNATE-SERVER

   The alternate server represents an alternate transport address
   identifying a different STUN server that the STUN client should try.

   It is encoded in the same way as MAPPED-ADDRESS, and thus refers to a
   single server by IP address.  The IP address family MUST be identical
   to that of the source IP address of the request.
*/

typedef struct _rhp_proto_stun_attr_mapped_addr		rhp_proto_stun_attr_alt_server;



/*

  (RFC 5766)

 14.1. CHANNEL-NUMBER

   The CHANNEL-NUMBER attribute contains the number of the channel.  The
   value portion of this attribute is 4 bytes long and consists of a 16-
   bit unsigned integer, followed by a two-octet RFFU (Reserved For
   Future Use) field, which MUST be set to 0 on transmission and MUST be
   ignored on reception.

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |        Channel Number         |         RFFU = 0              |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
struct _rhp_proto_stun_attr_channel_num_v {

	u16 channel_num;
	u16 reserved; // 0
};
typedef struct _rhp_proto_stun_attr_channel_num_v		rhp_proto_stun_attr_channel_num_v;

struct _rhp_proto_stun_attr_channel_num {

	u16 attr_type;
	u16 attr_len;
	rhp_proto_stun_attr_channel_num_v attr_val;
};
typedef struct _rhp_proto_stun_attr_channel_num		rhp_proto_stun_attr_channel_num;


/*
 14.2. LIFETIME

   The LIFETIME attribute represents the duration for which the server
   will maintain an allocation in the absence of a refresh.  The value
   portion of this attribute is 4-bytes long and consists of a 32-bit
   unsigned integral value representing the number of seconds remaining
   until expiration.
*/
struct _rhp_proto_stun_attr_lifetime_v {

	u32 lifetime; // (secs)
};
typedef struct _rhp_proto_stun_attr_lifetime_v		rhp_proto_stun_attr_lifetime_v;

struct _rhp_proto_stun_attr_lifetime {

	u16 attr_type;
	u16 attr_len;
	rhp_proto_stun_attr_lifetime_v attr_val;
};
typedef struct _rhp_proto_stun_attr_lifetime		rhp_proto_stun_attr_lifetime;


/*
 14.3. XOR-PEER-ADDRESS

   The XOR-PEER-ADDRESS specifies the address and port of the peer as
   seen from the TURN server.  (For example, the peer's server-reflexive
   transport address if the peer is behind a NAT.)  It is encoded in the
   same way as XOR-MAPPED-ADDRESS [RFC5389].
*/

typedef struct _rhp_proto_stun_attr_xor_mapped_addr		rhp_proto_stun_attr_xor_peer_addr;


/*
 14.4. DATA

   The DATA attribute is present in all Send and Data indications.  The
   value portion of this attribute is variable length and consists of
   the application data (that is, the data that would immediately follow
   the UDP header if the data was been sent directly between the client
   and the peer).  If the length of this attribute is not a multiple of
   4, then padding must be added after this attribute.
*/

typedef struct _rhp_proto_stun_attr		rhp_proto_stun_attr_data;


/*
 14.5. XOR-RELAYED-ADDRESS

   The XOR-RELAYED-ADDRESS is present in Allocate responses.  It
   specifies the address and port that the server allocated to the
   client.  It is encoded in the same way as XOR-MAPPED-ADDRESS
   [RFC5389].
*/

typedef struct _rhp_proto_stun_attr_xor_mapped_addr		rhp_proto_stun_attr_xor_relayed_addr;


/*
 14.6. EVEN-PORT

   This attribute allows the client to request that the port in the
   relayed transport address be even, and (optionally) that the server
   reserve the next-higher port number.  The value portion of this
   attribute is 1 byte long.  Its format is:

      0
      0 1 2 3 4 5 6 7
     +-+-+-+-+-+-+-+-+
     |R|    RFFU     |
     +-+-+-+-+-+-+-+-+

   The value contains a single 1-bit flag:

   R: If 1, the server is requested to reserve the next-higher port
      number (on the same IP address) for a subsequent allocation.  If
      0, no such reservation is requested.

   The other 7 bits of the attribute's value must be set to zero on
   transmission and ignored on reception.

   Since the length of this attribute is not a multiple of 4, padding
   must immediately follow this attribute.
*/
struct _rhp_proto_stun_attr_even_port_v {

	u8 flag;
}; /* padding(3 bytes) */
typedef struct _rhp_proto_stun_attr_even_port_v		rhp_proto_stun_attr_even_port_v;

struct _rhp_proto_stun_attr_even_port {

	u16 attr_type;
	u16 attr_len;
	rhp_proto_stun_attr_even_port_v attr_val;
}; /* padding(3 bytes) */
typedef struct _rhp_proto_stun_attr_even_port		rhp_proto_stun_attr_even_port;


/*
 14.7. REQUESTED-TRANSPORT

   This attribute is used by the client to request a specific transport
   protocol for the allocated transport address.  The value of this
   attribute is 4 bytes with the following format:
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |    Protocol   |                    RFFU                       |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   The Protocol field specifies the desired protocol.  The codepoints
   used in this field are taken from those allowed in the Protocol field
   in the IPv4 header and the NextHeader field in the IPv6 header
   [Protocol-Numbers].  This specification only allows the use of
   codepoint 17 (User Datagram Protocol).

   The RFFU field MUST be set to zero on transmission and MUST be
   ignored on reception.  It is reserved for future uses.
*/
struct _rhp_proto_stun_attr_req_transport_v {

	u8 protocol; // UDP(17)

	u8 reserved0;
	u16 reserved1;
};
typedef struct _rhp_proto_stun_attr_req_transport_v		rhp_proto_stun_attr_req_transport_v;

struct _rhp_proto_stun_attr_req_transport {

	u16 attr_type;
	u16 attr_len;
	rhp_proto_stun_attr_req_transport_v attr_val;
};
typedef struct _rhp_proto_stun_attr_req_transport		rhp_proto_stun_attr_req_transport;



/*
 14.8. DONT-FRAGMENT

   This attribute is used by the client to request that the server set
   the DF (Don't Fragment) bit in the IP header when relaying the
   application data onward to the peer.  This attribute has no value
   part and thus the attribute length field is 0.
*/

typedef struct _rhp_proto_stun_attr		rhp_proto_stun_attr_dont_frag;



/*

 14.9. RESERVATION-TOKEN

   The RESERVATION-TOKEN attribute contains a token that uniquely
   identifies a relayed transport address being held in reserve by the
   server.  The server includes this attribute in a success response to
   tell the client about the token, and the client includes this
   attribute in a subsequent Allocate request to request the server use
   that relayed transport address for the allocation.

   The attribute value is 8 bytes and contains the token value.
*/
struct _rhp_proto_stun_attr_rsrv_token_v {

#define RHP_PROTO_STUN_ATTR_RSRV_TKN_SIZE		8
	u8 token[RHP_PROTO_STUN_ATTR_RSRV_TKN_SIZE];
};
typedef struct _rhp_proto_stun_attr_rsrv_token_v		rhp_proto_stun_attr_rsrv_token_v;

struct _rhp_proto_stun_attr_rsrv_token {

	u16 attr_type;
	u16 attr_len;
	rhp_proto_stun_attr_rsrv_token_v attr_val;
};
typedef struct _rhp_proto_stun_attr_rsrv_token		rhp_proto_stun_attr_rsrv_token;





static inline int _rhp_proto_dh_keylen(u16 groupid) // Bytes
{
  switch( groupid )
  {
    case RHP_PROTO_IKE_TRANSFORM_ID_DH_1:
      return 96;
    case RHP_PROTO_IKE_TRANSFORM_ID_DH_2:
      return 128;
    case RHP_PROTO_IKE_TRANSFORM_ID_DH_5:
      return 192;
    case RHP_PROTO_IKE_TRANSFORM_ID_DH_14:
      return 256;
    case RHP_PROTO_IKE_TRANSFORM_ID_DH_15:
      return 384;
    case RHP_PROTO_IKE_TRANSFORM_ID_DH_16:
      return 512;
    case RHP_PROTO_IKE_TRANSFORM_ID_DH_17:
      return 768;
    case RHP_PROTO_IKE_TRANSFORM_ID_DH_18:
      return 1024;
      break;
    default:
      return -ENOENT;
  }
}

/*

- Group 1 - 768 Bit MODP

   This group is assigned id 1 (one).

   The prime is: 2^768 - 2 ^704 - 1 + 2^64 * { [2^638 pi] + 149686 } Its
   hexadecimal value is:

        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
        8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
        302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
        A63A3620 FFFFFFFF FFFFFFFF

   The generator is 2.

- Group 2 - 1024 Bit MODP

   This group is assigned id 2 (two).

   The prime is 2^1024 - 2^960 - 1 + 2^64 * { [2^894 pi] + 129093 }.
   Its hexadecimal value is:

        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
        8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
        302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
        A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
        49286651 ECE65381 FFFFFFFF FFFFFFFF

   The generator is 2.

- Group 5 - 1536 Bit MODP

   The 1536 bit MODP group has been used for the implementations for
   quite a long time, but was not defined in RFC 2409 (IKE).
   Implementations have been using group 5 to designate this group, we
   standardize that practice here.

   The prime is: 2^1536 - 2^1472 - 1 + 2^64 * { [2^1406 pi] + 741804 }

   Its hexadecimal value is:

      FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF

   The generator is: 2.

- Group 14 - 2048 Bit MODP

   This group is assigned id 14.

   This prime is: 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }

   Its hexadecimal value is:

      FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
      E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
      DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
      15728E5A 8AACAA68 FFFFFFFF FFFFFFFF

   The generator is: 2.

- Group 15 - 3072 Bit MODP

   This group is assigned id 15.

   This prime is: 2^3072 - 2^3008 - 1 + 2^64 * { [2^2942 pi] + 1690314 }

   Its hexadecimal value is:

      FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
      E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
      DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
      15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
      ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
      ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
      F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
      BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
      43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF

   The generator is: 2.

- Group 16 - 4096 Bit MODP

   This group is assigned id 16.

   This prime is: 2^4096 - 2^4032 - 1 + 2^64 * { [2^3966 pi] + 240904 }

   Its hexadecimal value is:

      FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
      E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
      DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
      15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
      ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
      ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
      F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
      BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
      43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7
      88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA
      2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6
      287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED
      1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9
      93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199
      FFFFFFFF FFFFFFFF

   The generator is: 2.

- Group 17 - 6144 Bit MODP

   This group is assigned id 17.

   This prime is: 2^6144 - 2^6080 - 1 + 2^64 * { [2^6014 pi] + 929484 }

   Its hexadecimal value is:

   FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
   8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
   302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
   A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
   49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
   FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
   670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
   180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
   3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D
   04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D
   B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226
   1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
   BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC
   E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26
   99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB
   04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2
   233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127
   D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492
   36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD F8FF9406
   AD9E530E E5DB382F 413001AE B06A53ED 9027D831 179727B0 865A8918
   DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B DB7F1447 E6CC254B 33205151
   2BD7AF42 6FB8F401 378CD2BF 5983CA01 C64B92EC F032EA15 D1721D03
   F482D7CE 6E74FEF6 D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F
   BEC7E8F3 23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA
   CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328 06A1D58B
   B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C DA56C9EC 2EF29632
   387FE8D7 6E3C0468 043E8F66 3F4860EE 12BF2D5B 0B7474D6 E694F91E
   6DCC4024 FFFFFFFF FFFFFFFF

   The generator is: 2.

- Group 18 - 8192 Bit MODP

   This group is assigned id 18.

   This prime is: 2^8192 - 2^8128 - 1 + 2^64 * { [2^8062 pi] + 4743158 }

   Its hexadecimal value is:

      FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
      E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
      DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
      15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
      ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
      ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
      F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
      BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
      43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7
      88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA
      2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6
      287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED
      1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9
      93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492
      36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD
      F8FF9406 AD9E530E E5DB382F 413001AE B06A53ED 9027D831
      179727B0 865A8918 DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B
      DB7F1447 E6CC254B 33205151 2BD7AF42 6FB8F401 378CD2BF
      5983CA01 C64B92EC F032EA15 D1721D03 F482D7CE 6E74FEF6
      D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F BEC7E8F3
      23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA
      CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328
      06A1D58B B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C
      DA56C9EC 2EF29632 387FE8D7 6E3C0468 043E8F66 3F4860EE
      12BF2D5B 0B7474D6 E694F91E 6DBE1159 74A3926F 12FEE5E4
      38777CB6 A932DF8C D8BEC4D0 73B931BA 3BC832B6 8D9DD300
      741FA7BF 8AFC47ED 2576F693 6BA42466 3AAB639C 5AE4F568
      3423B474 2BF1C978 238F16CB E39D652D E3FDB8BE FC848AD9
      22222E04 A4037C07 13EB57A8 1A23F0C7 3473FC64 6CEA306B
      4BCBC886 2F8385DD FA9D4B7F A2C087E8 79683303 ED5BDD3A
      062B3CF5 B3A278A6 6D2A13F8 3F44F82D DF310EE0 74AB6A36
      4597E899 A0255DC1 64F31CC5 0846851D F9AB4819 5DED7EA1
      B1D510BD 7EE74D73 FAF36BC3 1ECFA268 359046F4 EB879F92
      4009438B 481C6CD7 889A002E D5EE382B C9190DA6 FC026E47
      9558E447 5677E9AA 9E3050E2 765694DF C81F56E8 80B96E71
      60C980DD 98EDD3DF FFFFFFFF FFFFFFFF

   The generator is: 2.
*/

#define RHP_PROTO_IKE_DH_GENERATOR  	2

#define RHP_PROTO_IKE_DH_GRP2_PRIME_SZ  		128
#define RHP_PROTO_IKE_DH_GRP5_PRIME_SZ  		192
#define RHP_PROTO_IKE_DH_GRP14_PRIME_SZ 		256


#define RHP_PROTO_IKE_MD_MD5		1
#define RHP_PROTO_IKE_MD_SHA1  	2





/*

 - RADIUS (RFC 2865)

3.  Packet Format

   Exactly one RADIUS packet is encapsulated in the UDP Data field [4],
   where the UDP Destination Port field indicates 1812 (decimal).

   When a reply is generated, the source and destination ports are
   reversed.

   This memo documents the RADIUS protocol.  The early deployment of
   RADIUS was done using UDP port number 1645, which conflicts with the
   "datametrics" service.  The officially assigned port number for
   RADIUS is 1812.

   A summary of the RADIUS data format is shown below.  The fields are
   transmitted from left to right.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Code      |  Identifier   |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                         Authenticator                         |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Attributes ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-

   Code

      The Code field is one octet, and identifies the type of RADIUS
      packet.  When a packet is received with an invalid Code field, it
      is silently discarded.

      RADIUS Codes (decimal) are assigned as follows:

        1       Access-Request
        2       Access-Accept
        3       Access-Reject
        4       Accounting-Request
        5       Accounting-Response
       11       Access-Challenge
       12       Status-Server (experimental)
       13       Status-Client (experimental)
      255       Reserved

   Codes 4 and 5 are covered in the RADIUS Accounting document [5].
   Codes 12 and 13 are reserved for possible use, but are not further
   mentioned here.

   Identifier

      The Identifier field is one octet, and aids in matching requests
      and replies.  The RADIUS server can detect a duplicate request if
      it has the same client source IP address and source UDP port and
      Identifier within a short span of time.

   Length

      The Length field is two octets.  It indicates the length of the
      packet including the Code, Identifier, Length, Authenticator and
      Attribute fields.  Octets outside the range of the Length field
      MUST be treated as padding and ignored on reception.  If the
      packet is shorter than the Length field indicates, it MUST be
      silently discarded.  The minimum length is 20 and maximum length
      is 4096.

   Authenticator

      The Authenticator field is sixteen (16) octets.  The most
      significant octet is transmitted first.  This value is used to
      authenticate the reply from the RADIUS server, and is used in the
      password hiding algorithm.

      Request Authenticator

         In Access-Request Packets, the Authenticator value is a 16
         octet random number, called the Request Authenticator.  The
         value SHOULD be unpredictable and unique over the lifetime of a
         secret (the password shared between the client and the RADIUS
         server), since repetition of a request value in conjunction
         with the same secret would permit an attacker to reply with a
         previously intercepted response.  Since it is expected that the
         same secret MAY be used to authenticate with servers in
         disparate geographic regions, the Request Authenticator field
         SHOULD exhibit global and temporal uniqueness.

         The Request Authenticator value in an Access-Request packet
         SHOULD also be unpredictable, lest an attacker trick a server
         into responding to a predicted future request, and then use the
         response to masquerade as that server to a future Access-
         Request.

         Although protocols such as RADIUS are incapable of protecting
         against theft of an authenticated session via realtime active
         wiretapping attacks, generation of unique unpredictable
         requests can protect against a wide range of active attacks
         against authentication.

         The NAS and RADIUS server share a secret.  That shared secret
         followed by the Request Authenticator is put through a one-way
         MD5 hash to create a 16 octet digest value which is xored with
         the password entered by the user, and the xored result placed
         in the User-Password attribute in the Access-Request packet.
         See the entry for User-Password in the section on Attributes
         for a more detailed description.

      Response Authenticator

         The value of the Authenticator field in Access-Accept, Access-
         Reject, and Access-Challenge packets is called the Response
         Authenticator, and contains a one-way MD5 hash calculated over
         a stream of octets consisting of: the RADIUS packet, beginning
         with the Code field, including the Identifier, the Length, the
         Request Authenticator field from the Access-Request packet, and
         the response Attributes, followed by the shared secret.  That
         is, ResponseAuth =
         MD5(Code+ID+Length+RequestAuth+Attributes+Secret) where +
         denotes concatenation.

   Administrative Note

      The secret (password shared between the client and the RADIUS
      server) SHOULD be at least as large and unguessable as a well-
      chosen password.  It is preferred that the secret be at least 16
      octets.  This is to ensure a sufficiently large range for the
      secret to provide protection against exhaustive search attacks.
      The secret MUST NOT be empty (length 0) since this would allow
      packets to be trivially forged.

      A RADIUS server MUST use the source IP address of the RADIUS UDP
      packet to decide which shared secret to use, so that RADIUS
      requests can be proxied.

      When using a forwarding proxy, the proxy must be able to alter the
      packet as it passes through in each direction - when the proxy
      forwards the request, the proxy MAY add a Proxy-State Attribute,
      and when the proxy forwards a response, it MUST remove its Proxy-
      State Attribute if it added one.  Proxy-State is always added or
      removed after any other Proxy-States, but no other assumptions
      regarding its location within the list of attributes can be made.
      Since Access-Accept and Access-Reject replies are authenticated on
      the entire packet contents, the stripping of the Proxy-State
      attribute invalidates the signature in the packet - so the proxy
      has to re-sign it.

      Further details of RADIUS proxy implementation are outside the
      scope of this document.


4.  Packet Types

   The RADIUS Packet type is determined by the Code field in the first
   octet of the Packet.

4.1.  Access-Request

   Description

      Access-Request packets are sent to a RADIUS server, and convey
      information used to determine whether a user is allowed access to
      a specific NAS, and any special services requested for that user.
      An implementation wishing to authenticate a user MUST transmit a
      RADIUS packet with the Code field set to 1 (Access-Request).

      Upon receipt of an Access-Request from a valid client, an
      appropriate reply MUST be transmitted.

      An Access-Request SHOULD contain a User-Name attribute.  It MUST
      contain either a NAS-IP-Address attribute or a NAS-Identifier
      attribute (or both).

      An Access-Request MUST contain either a User-Password or a CHAP-
      Password or a State.  An Access-Request MUST NOT contain both a
      User-Password and a CHAP-Password.  If future extensions allow
      other kinds of authentication information to be conveyed, the
      attribute for that can be used in an Access-Request instead of
      User-Password or CHAP-Password.

      An Access-Request SHOULD contain a NAS-Port or NAS-Port-Type
      attribute or both unless the type of access being requested does
      not involve a port or the NAS does not distinguish among its
      ports.

      An Access-Request MAY contain additional attributes as a hint to
      the server, but the server is not required to honor the hint.

      When a User-Password is present, it is hidden using a method based
      on the RSA Message Digest Algorithm MD5 [3].

   A summary of the Access-Request packet format is shown below.  The
   fields are transmitted from left to right.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Code      |  Identifier   |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                     Request Authenticator                     |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Attributes ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-

   Code

      1 for Access-Request.

   Identifier

      The Identifier field MUST be changed whenever the content of the
      Attributes field changes, and whenever a valid reply has been
      received for a previous request.  For retransmissions, the
      Identifier MUST remain unchanged.

   Request Authenticator

      The Request Authenticator value MUST be changed each time a new
      Identifier is used.

   Attributes

      The Attribute field is variable in length, and contains the list
      of Attributes that are required for the type of service, as well
      as any desired optional Attributes.

4.2.  Access-Accept

   Description

      Access-Accept packets are sent by the RADIUS server, and provide
      specific configuration information necessary to begin delivery of
      service to the user.  If all Attribute values received in an
      Access-Request are acceptable then the RADIUS implementation MUST
      transmit a packet with the Code field set to 2 (Access-Accept).
      On reception of an Access-Accept, the Identifier field is matched
      with a pending Access-Request.  The Response Authenticator field
      MUST contain the correct response for the pending Access-Request.
      Invalid packets are silently discarded.

   A summary of the Access-Accept packet format is shown below.  The
   fields are transmitted from left to right.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Code      |  Identifier   |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                     Response Authenticator                    |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Attributes ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-

   Code

      2 for Access-Accept.

   Identifier

      The Identifier field is a copy of the Identifier field of the
      Access-Request which caused this Access-Accept.

   Response Authenticator

      The Response Authenticator value is calculated from the Access-
      Request value, as described earlier.

   Attributes

      The Attribute field is variable in length, and contains a list of
      zero or more Attributes.

4.3.  Access-Reject

   Description

      If any value of the received Attributes is not acceptable, then
      the RADIUS server MUST transmit a packet with the Code field set
      to 3 (Access-Reject).  It MAY include one or more Reply-Message
      Attributes with a text message which the NAS MAY display to the
      user.

   A summary of the Access-Reject packet format is shown below.  The
   fields are transmitted from left to right.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Code      |  Identifier   |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                     Response Authenticator                    |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Attributes ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-

   Code

      3 for Access-Reject.

   Identifier

      The Identifier field is a copy of the Identifier field of the
      Access-Request which caused this Access-Reject.

   Response Authenticator

      The Response Authenticator value is calculated from the Access-
      Request value, as described earlier.

   Attributes

      The Attribute field is variable in length, and contains a list of
      zero or more Attributes.

4.4.  Access-Challenge

   Description

      If the RADIUS server desires to send the user a challenge
      requiring a response, then the RADIUS server MUST respond to the
      Access-Request by transmitting a packet with the Code field set to
      11 (Access-Challenge).

      The Attributes field MAY have one or more Reply-Message
      Attributes, and MAY have a single State Attribute, or none.
      Vendor-Specific, Idle-Timeout, Session-Timeout and Proxy-State
      attributes MAY also be included.  No other Attributes defined in
      this document are permitted in an Access-Challenge.

      On receipt of an Access-Challenge, the Identifier field is matched
      with a pending Access-Request.  Additionally, the Response
      Authenticator field MUST contain the correct response for the
      pending Access-Request.  Invalid packets are silently discarded.

      If the NAS does not support challenge/response, it MUST treat an
      Access-Challenge as though it had received an Access-Reject
      instead.

      If the NAS supports challenge/response, receipt of a valid
      Access-Challenge indicates that a new Access-Request SHOULD be
      sent.  The NAS MAY display the text message, if any, to the user,
      and then prompt the user for a response.  It then sends its
      original Access-Request with a new request ID and Request
      Authenticator, with the User-Password Attribute replaced by the
      user's response (encrypted), and including the State Attribute
      from the Access-Challenge, if any.  Only 0 or 1 instances of the
      State Attribute can be present in an Access-Request.

      A NAS which supports PAP MAY forward the Reply-Message to the
      dialing client and accept a PAP response which it can use as
      though the user had entered the response.  If the NAS cannot do
      so, it MUST treat the Access-Challenge as though it had received
      an Access-Reject instead.


   A summary of the Access-Challenge packet format is shown below.  The
   fields are transmitted from left to right.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Code      |  Identifier   |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                     Response Authenticator                    |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Attributes ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-

   Code

      11 for Access-Challenge.

   Identifier

      The Identifier field is a copy of the Identifier field of the
      Access-Request which caused this Access-Challenge.

   Response Authenticator

      The Response Authenticator value is calculated from the Access-
      Request value, as described earlier.

   Attributes

      The Attributes field is variable in length, and contains a list of
      zero or more Attributes.

*/

#define RHP_PROTO_PORT_RADIUS     	   	1812
#define RHP_PROTO_PORT_RADIUS_ACCT      1813

struct _rhp_proto_radius {

#define RHP_RADIUS_CODE_NONE								0
#define RHP_RADIUS_CODE_ACCESS_REQUEST			1
#define RHP_RADIUS_CODE_ACCESS_ACCEPT				2
#define RHP_RADIUS_CODE_ACCESS_REJECT				3
#define RHP_RADIUS_CODE_ACCT_REQUEST				4
#define RHP_RADIUS_CODE_ACCT_RESPONSE				5
#define RHP_RADIUS_CODE_ACCESS_CHALLENGE		11
#define RHP_RADIUS_CODE_STATUS_SERVER				12
#define RHP_RADIUS_CODE_STATUS_CLIENT				13
#define RHP_RADIUS_CODE_RESERVED						255
	u8 code;

	u8 id;

#define RHP_RADIUS_PKT_LEN_MIN	20
#define RHP_RADIUS_PKT_LEN_MAX	4096
	u16 len;

#define RHP_RADIUS_AUTHENTICATOR_LEN	16
	u8 authenticator[RHP_RADIUS_AUTHENTICATOR_LEN];

	/* Followed by attributes. */
};
typedef struct _rhp_proto_radius	rhp_proto_radius;


/*

5.  Attributes

   RADIUS Attributes carry the specific authentication, authorization,
   information and configuration details for the request and reply.

   The end of the list of Attributes is indicated by the Length of the
   RADIUS packet.

   Some Attributes MAY be included more than once.  The effect of this
   is Attribute specific, and is specified in each Attribute
   description.  A summary table is provided at the end of the
   "Attributes" section.

   If multiple Attributes with the same Type are present, the order of
   Attributes with the same Type MUST be preserved by any proxies.  The
   order of Attributes of different Types is not required to be
   preserved.  A RADIUS server or client MUST NOT have any dependencies
   on the order of attributes of different types.  A RADIUS server or
   client MUST NOT require attributes of the same type to be contiguous.

   Where an Attribute's description limits which kinds of packet it can
   be contained in, this applies only to the packet types defined in
   this document, namely Access-Request, Access-Accept, Access-Reject
   and Access-Challenge (Codes 1, 2, 3, and 11).  Other documents
   defining other packet types may also use Attributes described here.
   To determine which Attributes are allowed in Accounting-Request and
   Accounting-Response packets (Codes 4 and 5) refer to the RADIUS
   Accounting document [5].

   Likewise where packet types defined here state that only certain
   Attributes are permissible in them, future memos defining new
   Attributes should indicate which packet types the new Attributes may
   be present in.

   A summary of the Attribute format is shown below.  The fields are
   transmitted from left to right.

    0                   1                   2
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
   |     Type      |    Length     |  Value ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

   Type

      The Type field is one octet.  Up-to-date values of the RADIUS Type
      field are specified in the most recent "Assigned Numbers" RFC [6].
      Values 192-223 are reserved for experimental use, values 224-240
      are reserved for implementation-specific use, and values 241-255
      are reserved and should not be used.

      A RADIUS server MAY ignore Attributes with an unknown Type.

      A RADIUS client MAY ignore Attributes with an unknown Type.

      This specification concerns the following values:

          1      User-Name
          2      User-Password
          3      CHAP-Password
          4      NAS-IP-Address
          5      NAS-Port
          6      Service-Type
          7      Framed-Protocol
          8      Framed-IP-Address
          9      Framed-IP-Netmask
         10      Framed-Routing
         11      Filter-Id
         12      Framed-MTU
         13      Framed-Compression
         14      Login-IP-Host
         15      Login-Service
         16      Login-TCP-Port
         17      (unassigned)
         18      Reply-Message
         19      Callback-Number
         20      Callback-Id
         21      (unassigned)
         22      Framed-Route
         23      Framed-IPX-Network
         24      State
         25      Class
         26      Vendor-Specific
         27      Session-Timeout
         28      Idle-Timeout
         29      Termination-Action
         30      Called-Station-Id
         31      Calling-Station-Id
         32      NAS-Identifier
         33      Proxy-State
         34      Login-LAT-Service
         35      Login-LAT-Node
         36      Login-LAT-Group
         37      Framed-AppleTalk-Link
         38      Framed-AppleTalk-Network
         39      Framed-AppleTalk-Zone
         40-59   (reserved for accounting)
         60      CHAP-Challenge
         61      NAS-Port-Type
         62      Port-Limit
         63      Login-LAT-Port

   Length

      The Length field is one octet, and indicates the length of this
      Attribute including the Type, Length and Value fields.  If an
      Attribute is received in an Access-Request but with an invalid
      Length, an Access-Reject SHOULD be transmitted.  If an Attribute
      is received in an Access-Accept, Access-Reject or Access-Challenge
      packet with an invalid length, the packet MUST either be treated
      as an Access-Reject or else silently discarded.

   Value

      The Value field is zero or more octets and contains information
      specific to the Attribute.  The format and length of the Value
      field is determined by the Type and Length fields.

      Note that none of the types in RADIUS terminate with a NUL (hex
      00).  In particular, types "text" and "string" in RADIUS do not
      terminate with a NUL (hex 00).  The Attribute has a length field
      and does not use a terminator.  Text contains UTF-8 encoded 10646
      [7] characters and String contains 8-bit binary data.  Servers and
      servers and clients MUST be able to deal with embedded nulls.
      RADIUS implementers using C are cautioned not to use strcpy() when
      handling strings.

      The format of the value field is one of five data types.  Note
      that type "text" is a subset of type "string".

      text      1-253 octets containing UTF-8 encoded 10646 [7]
                characters.  Text of length zero (0) MUST NOT be sent;
                omit the entire attribute instead.

      string    1-253 octets containing binary data (values 0 through
                255 decimal, inclusive).  Strings of length zero (0)
                MUST NOT be sent; omit the entire attribute instead.

      address   32 bit value, most significant octet first.

      integer   32 bit unsigned value, most significant octet first.

      time      32 bit unsigned value, most significant octet first --
                seconds since 00:00:00 UTC, January 1, 1970.  The
                standard Attributes do not use this data type but it is
                presented here for possible use in future attributes.


5.1.  User-Name

   Description

      This Attribute indicates the name of the user to be authenticated.
      It MUST be sent in Access-Request packets if available.

      It MAY be sent in an Access-Accept packet, in which case the
      client SHOULD use the name returned in the Access-Accept packet in
      all Accounting-Request packets for this session.  If the Access-
      Accept includes Service-Type = Rlogin and the User-Name attribute,
      a NAS MAY use the returned User-Name when performing the Rlogin
      function.

   A summary of the User-Name Attribute format is shown below.  The
   fields are transmitted from left to right.

    0                   1                   2
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
   |     Type      |    Length     |  String ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

   Type

      1 for User-Name.

   Length

      >= 3

   String

      The String field is one or more octets.  The NAS may limit the
      maximum length of the User-Name but the ability to handle at least
      63 octets is recommended.

      The format of the username MAY be one of several forms:

      text      Consisting only of UTF-8 encoded 10646 [7] characters.

      network access identifier
                A Network Access Identifier as described in RFC 2486
                [8].

      distinguished name
                A name in ASN.1 form used in Public Key authentication
                systems.


5.4.  NAS-IP-Address

   Description

      This Attribute indicates the identifying IP Address of the NAS
      which is requesting authentication of the user, and SHOULD be
      unique to the NAS within the scope of the RADIUS server. NAS-IP-
      Address is only used in Access-Request packets.  Either NAS-IP-
      Address or NAS-Identifier MUST be present in an Access-Request
      packet.

      Note that NAS-IP-Address MUST NOT be used to select the shared
      secret used to authenticate the request.  The source IP address of
      the Access-Request packet MUST be used to select the shared
      secret.

   A summary of the NAS-IP-Address Attribute format is shown below.  The
   fields are transmitted from left to right.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |    Length     |            Address
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            Address (cont)         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Type

      4 for NAS-IP-Address.

   Length

      6

   Address

      The Address field is four octets.


5.12.  Framed-MTU

   Description

      This Attribute indicates the Maximum Transmission Unit to be
      configured for the user, when it is not negotiated by some other
      means (such as PPP).  It MAY be used in Access-Accept packets.  It
      MAY be used in an Access-Request packet as a hint by the NAS to
      the server that it would prefer that value, but the server is not
      required to honor the hint.

   A summary of the Framed-MTU Attribute format is shown below.  The
   fields are transmitted from left to right.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |    Length     |             Value
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              Value (cont)         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Type

      12 for Framed-MTU.

   Length

      6

   Value

      The Value field is four octets.  Despite the size of the field,
      values range from 64 to 65535.


5.41.  NAS-Port-Type

   Description

      This Attribute indicates the type of the physical port of the NAS
      which is authenticating the user.  It can be used instead of or in
      addition to the NAS-Port (5) attribute.  It is only used in
      Access-Request packets.  Either NAS-Port (5) or NAS-Port-Type or
      both SHOULD be present in an Access-Request packet, if the NAS
      differentiates among its ports.

   A summary of the NAS-Port-Type Attribute format is shown below.  The
   fields are transmitted from left to right.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |    Length     |             Value
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              Value (cont)         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Type

      61 for NAS-Port-Type.

   Length

      6

   Value

      The Value field is four octets.  "Virtual" refers to a connection
      to the NAS via some transport protocol, instead of through a
      physical port.  For example, if a user telnetted into a NAS to
      authenticate himself as an Outbound-User, the Access-Request might
      include NAS-Port-Type = Virtual as a hint to the RADIUS server
      that the user was not on a physical port.

      0       Async
      1       Sync
      2       ISDN Sync
      3       ISDN Async V.120
      4       ISDN Async V.110
      5       Virtual
      6       PIAFS
      7       HDLC Clear Channel
      8       X.25
      9       X.75
      10      G.3 Fax
      11      SDSL - Symmetric DSL
      12      ADSL-CAP - Asymmetric DSL, Carrierless Amplitude Phase
              Modulation
      13      ADSL-DMT - Asymmetric DSL, Discrete Multi-Tone
      14      IDSL - ISDN Digital Subscriber Line
      15      Ethernet
      16      xDSL - Digital Subscriber Line of unknown type
      17      Cable
      18      Wireless - Other
      19      Wireless - IEEE 802.11

      PIAFS is a form of wireless ISDN commonly used in Japan, and
      stands for PHS (Personal Handyphone System) Internet Access Forum
      Standard (PIAFS).


5.5.  NAS-Port

   Description

      This Attribute indicates the physical port number of the NAS which
      is authenticating the user.  It is only used in Access-Request
      packets.  Note that this is using "port" in its sense of a
      physical connection on the NAS, not in the sense of a TCP or UDP
      port number.  Either NAS-Port or NAS-Port-Type (61) or both SHOULD
      be present in an Access-Request packet, if the NAS differentiates
      among its ports.

   A summary of the NAS-Port Attribute format is shown below.  The
   fields are transmitted from left to right.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |    Length     |             Value
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              Value (cont)         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Type

      5 for NAS-Port.

   Length

      6

   Value

      The Value field is four octets.

5.30.  Called-Station-Id

   Description

      This Attribute allows the NAS to send in the Access-Request packet
      the phone number that the user called, using Dialed Number
      Identification (DNIS) or similar technology.  Note that this may
      be different from the phone number the call comes in on.  It is
      only used in Access-Request packets.

   A summary of the Called-Station-Id Attribute format is shown below.
   The fields are transmitted from left to right.

    0                   1                   2
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
   |     Type      |    Length     |  String ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

   Type

      30 for Called-Station-Id.

   Length

      >= 3

   String

      The String field is one or more octets, containing the phone
      number that the user's call came in on.

      The actual format of the information is site or application
      specific.  UTF-8 encoded 10646 [7] characters are recommended, but
      a robust implementation SHOULD support the field as
      undistinguished octets.

      The codification of the range of allowed usage of this field is
      outside the scope of this specification.

5.31.  Calling-Station-Id

   Description

      This Attribute allows the NAS to send in the Access-Request packet
      the phone number that the call came from, using Automatic Number
      Identification (ANI) or similar technology.  It is only used in
      Access-Request packets.

   A summary of the Calling-Station-Id Attribute format is shown below.
   The fields are transmitted from left to right.

    0                   1                   2
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
   |     Type      |    Length     |  String ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

   Type

      31 for Calling-Station-Id.

   Length

      >= 3

   String

      The String field is one or more octets, containing the phone
      number that the user placed the call from.

      The actual format of the information is site or application
      specific.  UTF-8 encoded 10646 [7] characters are recommended, but
      a robust implementation SHOULD support the field as
      undistinguished octets.

      The codification of the range of allowed usage of this field is
      outside the scope of this specification.


5.27.  Session-Timeout

   Description

      This Attribute sets the maximum number of seconds of service to be
      provided to the user before termination of the session or prompt.
      This Attribute is available to be sent by the server to the client
      in an Access-Accept or Access-Challenge.

   A summary of the Session-Timeout Attribute format is shown below.
   The fields are transmitted from left to right.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |    Length     |             Value
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              Value (cont)         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Type

      27 for Session-Timeout.

   Length

      6

   Value

      The field is 4 octets, containing a 32-bit unsigned integer with
      the maximum number of seconds this user should be allowed to
      remain connected by the NAS.


5.18.  Reply-Message

   Description

      This Attribute indicates text which MAY be displayed to the user.

      When used in an Access-Accept, it is the success message.

      When used in an Access-Reject, it is the failure message.  It MAY
      indicate a dialog message to prompt the user before another
      Access-Request attempt.

      When used in an Access-Challenge, it MAY indicate a dialog message
      to prompt the user for a response.

      Multiple Reply-Message's MAY be included and if any are displayed,
      they MUST be displayed in the same order as they appear in the
      packet.

   A summary of the Reply-Message Attribute format is shown below.  The
   fields are transmitted from left to right.

    0                   1                   2
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
   |     Type      |    Length     |  Text ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

   Type

      18 for Reply-Message.

   Length

      >= 3

   Text

      The Text field is one or more octets, and its contents are
      implementation dependent.  It is intended to be human readable,
      and MUST NOT affect operation of the protocol.  It is recommended
      that the message contain UTF-8 encoded 10646 [7] characters.


5.24.  State

   Description

      This Attribute is available to be sent by the server to the client
      in an Access-Challenge and MUST be sent unmodified from the client
      to the server in the new Access-Request reply to that challenge,
      if any.

      This Attribute is available to be sent by the server to the client
      in an Access-Accept that also includes a Termination-Action
      Attribute with the value of RADIUS-Request.  If the NAS performs
      the Termination-Action by sending a new Access-Request upon
      termination of the current session, it MUST include the State
      attribute unchanged in that Access-Request.

      In either usage, the client MUST NOT interpret the attribute
      locally.  A packet must have only zero or one State Attribute.
      Usage of the State Attribute is implementation dependent.

   A summary of the State Attribute format is shown below.  The fields
   are transmitted from left to right.

    0                   1                   2
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
   |     Type      |    Length     |  String ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

   Type

      24 for State.

   Length

      >= 3

   String

      The String field is one or more octets.  The actual format of the
      information is site or application specific, and a robust
      implementation SHOULD support the field as undistinguished octets.

      The codification of the range of allowed usage of this field is
      outside the scope of this specification.

*/

/*

 - RADIUS Extensions (RFC2869)

5.17.  NAS-Port-Id

   Description

      This Attribute contains a text string which identifies the port of
      the NAS which is authenticating the user.  It is only used in
      Access-Request and Accounting-Request packets.  Note that this is
      using "port" in its sense of a physical connection on the NAS, not
      in the sense of a TCP or UDP port number.

      Either NAS-Port or NAS-Port-Id SHOULD be present in an Access-
      Request packet, if the NAS differentiates among its ports.  NAS-
      Port-Id is intended for use by NASes which cannot conveniently
      number their ports.

   A summary of the NAS-Port-Id Attribute format is shown below.  The
   fields are transmitted from left to right.

    0                   1                   2
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |    Length     |     Text...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


   Type

      87 for NAS-Port-Id.

   Length

      >= 3

   Text

      The Text field contains the name of the port using UTF-8 encoded
      10646 [8] characters.


5.32.  NAS-Identifier

   Description

      This Attribute contains a string identifying the NAS originating
      the Access-Request.  It is only used in Access-Request packets.
      Either NAS-IP-Address or NAS-Identifier MUST be present in an
      Access-Request packet.

      Note that NAS-Identifier MUST NOT be used to select the shared
      secret used to authenticate the request.  The source IP address of
      the Access-Request packet MUST be used to select the shared
      secret.

   A summary of the NAS-Identifier Attribute format is shown below.  The
   fields are transmitted from left to right.

    0                   1                   2
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
   |     Type      |    Length     |  String ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

   Type

      32 for NAS-Identifier.

   Length

      >= 3

   String

      The String field is one or more octets, and should be unique to
      the NAS within the scope of the RADIUS server.  For example, a
      fully qualified domain name would be suitable as a NAS-Identifier.

      The actual format of the information is site or application
      specific, and a robust implementation SHOULD support the field as
      undistinguished octets.

      The codification of the range of allowed usage of this field is
      outside the scope of this specification.


5.11.  Connect-Info

   Description

      This attribute is sent from the NAS to indicate the nature of the
      user's connection.

      The NAS MAY send this attribute in an Access-Request or
      Accounting-Request to indicate the nature of the user's
      connection.

   A summary of the Connect-Info attribute format is shown below.  The
   fields are transmitted from left to right.

    0                   1                   2
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |    Length     |     Text...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Type

      77 for Connect-Info.

   Length

      >= 3

   Text

      The Text field consists of UTF-8 encoded 10646 [8] characters.
      The connection speed SHOULD be included at the beginning of the
      first Connect-Info attribute in the packet.  If the transmit and
      receive connection speeds differ, they may both be included in the
      first attribute with the transmit speed first (the speed the NAS
      modem transmits at), a slash (/), the receive speed, then
      optionally other information.

      For example, "28800 V42BIS/LAPM" or "52000/31200 V90"

      More than one Connect-Info attribute may be present in an
      Accounting-Request packet to accommodate expected efforts by ITU
      to have modems report more connection information in a standard
      format that might exceed 252 octets.
*/

/*

 - RADIUS Support For EAP (RFC3579)

3.  Attributes

   The NAS-Port or NAS-Port-Id attributes SHOULD be included by the NAS
   in Access-Request packets, and either NAS-Identifier, NAS-IP-Address
   or NAS-IPv6-Address attributes MUST be included.  In order to permit
   forwarding of the Access-Reply by EAP-unaware proxies, if a User-Name
   attribute was included in an Access-Request, the RADIUS server MUST
   include the User-Name attribute in subsequent Access-Accept packets.
   Without the User-Name attribute, accounting and billing becomes
   difficult to manage.  The User-Name attribute within the Access-
   Accept packet need not be the same as the User-Name attribute in the
   Access-Request.

3.1.  EAP-Message

   Description

      This attribute encapsulates EAP [RFC2284] packets so as to allow
      the NAS to authenticate peers via EAP without having to understand
      the EAP method it is passing through.

      The NAS places EAP messages received from the authenticating peer
      into one or more EAP-Message attributes and forwards them to the
      RADIUS server within an Access-Request message.  If multiple
      EAP-Message attributes are contained within an Access-Request or
      Access-Challenge packet, they MUST be in order and they MUST be
      consecutive attributes in the Access-Request or Access-Challenge
      packet.  The RADIUS server can return EAP-Message attributes in
      Access-Challenge, Access-Accept and Access-Reject packets.

      When RADIUS is used to enable EAP authentication, Access-Request,
      Access-Challenge, Access-Accept, and Access-Reject packets SHOULD
      contain one or more EAP-Message attributes.  Where more than one
      EAP-Message attribute is included, it is assumed that the
      attributes are to be concatenated to form a single EAP packet.

      Multiple EAP packets MUST NOT be encoded within EAP-Message
      attributes contained within a single Access-Challenge,
      Access-Accept, Access-Reject or Access-Request packet.

      It is expected that EAP will be used to implement a variety of
      authentication methods, including methods involving strong
      cryptography.  In order to prevent attackers from subverting EAP
      by attacking RADIUS/EAP, (for example, by modifying EAP Success or
      EAP Failure packets) it is necessary that RADIUS provide
      per-packet authentication and integrity protection.

      Therefore the Message-Authenticator attribute MUST be used to
      protect all Access-Request, Access-Challenge, Access-Accept, and
      Access-Reject packets containing an EAP-Message attribute.

      Access-Request packets including EAP-Message attribute(s) without
      a Message-Authenticator attribute SHOULD be silently discarded by
      the RADIUS server.  A RADIUS server supporting the EAP-Message
      attribute MUST calculate the correct value of the
      Message-Authenticator and MUST silently discard the packet if it
      does not match the value sent.  A RADIUS server not supporting the
      EAP-Message attribute MUST return an Access-Reject if it receives
      an Access-Request containing an EAP-Message attribute.

      Access-Challenge, Access-Accept, or Access-Reject packets
      including EAP-Message attribute(s) without a Message-Authenticator
      attribute SHOULD be silently discarded by the NAS.  A NAS
      supporting the EAP-Message attribute MUST calculate the correct
      value of the Message-Authenticator and MUST silently discard the
      packet if it does not match the value sent.

      A summary of the EAP-Message attribute format is shown below.  The
      fields are transmitted from left to right.

       0                   1                   2
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |     Type      |    Length     |     String...
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Type

      79 for EAP-Message

   Length

      >= 3

   String

      The String field contains an EAP packet, as defined in [RFC2284].
      If multiple EAP-Message attributes are present in a packet their
      values should be concatenated; this allows EAP packets longer than
      253 octets to be transported by RADIUS.

3.2.  Message-Authenticator

   Description

      This attribute MAY be used to authenticate and integrity-protect
      Access-Requests in order to prevent spoofing.  It MAY be used in
      any Access-Request.  It MUST be used in any Access-Request,
      Access-Accept, Access-Reject or Access-Challenge that includes an
      EAP-Message attribute.

      A RADIUS server receiving an Access-Request with a
      Message-Authenticator attribute present MUST calculate the correct
      value of the Message-Authenticator and silently discard the packet
      if it does not match the value sent.

      A RADIUS client receiving an Access-Accept, Access-Reject or
      Access-Challenge with a Message-Authenticator attribute present
      MUST calculate the correct value of the Message-Authenticator and
      silently discard the packet if it does not match the value sent.

      This attribute is not required in Access-Requests which include
      the User-Password attribute, but is useful for preventing attacks
      on other types of authentication.  This attribute is intended to
      thwart attempts by an attacker to setup a "rogue" NAS, and perform
      online dictionary attacks against the RADIUS server.  It does not
      afford protection against "offline" attacks where the attacker
      intercepts packets containing (for example) CHAP challenge and
      response, and performs a dictionary attack against those packets
      offline.

      A summary of the Message-Authenticator attribute format is shown
      below.  The fields are transmitted from left to right.

       0                   1                   2
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |     Type      |    Length     |     String...
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Type

      80 for Message-Authenticator

   Length

      18

   String

      When present in an Access-Request packet, Message-Authenticator is
      an HMAC-MD5 [RFC2104] hash of the entire Access-Request packet,
      including Type, ID, Length and Authenticator, using the shared
      secret as the key, as follows.

      Message-Authenticator = HMAC-MD5 (Type, Identifier, Length,
      Request Authenticator, Attributes)

      When the message integrity check is calculated the signature
      string should be considered to be sixteen octets of zero.

      For Access-Challenge, Access-Accept, and Access-Reject packets,
      the Message-Authenticator is calculated as follows, using the
      Request-Authenticator from the Access-Request this packet is in
      reply to:

      Message-Authenticator = HMAC-MD5 (Type, Identifier, Length,
      Request Authenticator, Attributes)

      When the message integrity check is calculated the signature
      string should be considered to be sixteen octets of zero.  The
      shared secret is used as the key for the HMAC-MD5 message
      integrity check.  The Message-Authenticator is calculated and
      inserted in the packet before the Response Authenticator is
      calculated.


*/

/*

 - RADIUS and IPv6 (RFC3162)

2.1.  NAS-IPv6-Address

   Description

      This Attribute indicates the identifying IPv6 Address of the NAS
      which is requesting authentication of the user, and SHOULD be
      unique to the NAS within the scope of the RADIUS server.  NAS-
      IPv6-Address is only used in Access-Request packets.  NAS-IPv6-
      Address and/or NAS-IP-Address MAY be present in an Access-Request
      packet; however, if neither attribute is present then NAS-
      Identifier MUST be present.

   A summary of the NAS-IPv6-Address Attribute format is shown below.
   The fields are transmitted from left to right.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |    Length     |             Address
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                Address
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                Address
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                Address
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
               Address             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Type

      95 for NAS-IPv6-Address

   Length

      18

   Address

      The Address field is 16 octets.

*/

/*

 - Microsoft Vendor-specific RADIUS Attributes (RFC2548)


2.4.2.  MS-MPPE-Send-Key

   Description

      The MS-MPPE-Send-Key Attribute contains a session key for use by
      the Microsoft Point-to-Point Encryption Protocol (MPPE).  As the
      name implies, this key is intended for encrypting packets sent
      from the NAS to the remote host.  This Attribute is only included
      in Access-Accept packets.

   A summary of the MS-MPPE-Send-Key Attribute format is given below.
   The fields are transmitted left to right.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Vendor-Type  | Vendor-Length |             Salt
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                               String...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Vendor-Type
      16 for MS-MPPE-Send-Key.

   Vendor-Length
      > 4

   Salt
      The Salt field is two octets in length and is used to ensure the
      uniqueness of the keys used to encrypt each of the encrypted
      attributes occurring in a given Access-Accept packet.  The most
      significant bit (leftmost) of the Salt field MUST be set (1).  The
      contents of each Salt field in a given Access-Accept packet MUST
      be unique.

   String
      The plaintext String field consists of three logical sub-fields:
      the Key-Length and Key sub-fields (both of which are required),
      and the optional Padding sub-field.  The Key-Length sub-field is
      one octet in length and contains the length of the unencrypted Key
      sub-field.  The Key sub-field contains the actual encryption key.
      If the combined length (in octets) of the unencrypted Key-Length
      and Key sub-fields is not an even multiple of 16, then the Padding
      sub-field MUST be present.  If it is present, the length of the
      Padding sub-field is variable, between 1 and 15 octets.  The
      String field MUST be encrypted as follows, prior to transmission:

         Construct a plaintext version of the String field by concate-
         nating the Key-Length and Key sub-fields.  If necessary, pad
         the resulting string until its length (in octets) is an even
         multiple of 16.  It is recommended that zero octets (0x00) be
         used for padding.  Call this plaintext P.

         Call the shared secret S, the pseudo-random 128-bit Request
         Authenticator (from the corresponding Access-Request packet) R,
         and the contents of the Salt field A.  Break P into 16 octet
         chunks p(1), p(2)...p(i), where i = len(P)/16.  Call the
         ciphertext blocks c(1), c(2)...c(i) and the final ciphertext C.
         Intermediate values b(1), b(2)...c(i) are required.  Encryption
         is performed in the following manner ('+' indicates
         concatenation):

      b(1) = MD5(S + R + A)    c(1) = p(1) xor b(1)   C = c(1)
      b(2) = MD5(S + c(1))     c(2) = p(2) xor b(2)   C = C + c(2)
                  .                      .
                  .                      .
                  .                      .
      b(i) = MD5(S + c(i-1))   c(i) = p(i) xor b(i)   C = C + c(i)

      The   resulting   encrypted   String   field    will    contain
      c(1)+c(2)+...+c(i).

   On receipt, the process is reversed to yield the plaintext String.

   Implementation Notes
      It is possible that the length of the key returned may be larger
      than needed for the encryption scheme in use.  In this case, the
      RADIUS client is responsible for performing any necessary
      truncation.

      This attribute MAY be used to pass a key from an external (e.g.,
      EAP [15]) server to the RADIUS server.  In this case, it may be
      impossible for the external server to correctly encrypt the key,
      since the RADIUS shared secret might be unavailable.  The external
      server SHOULD, however, return the attribute as defined above; the
      Salt field SHOULD be zero-filled and padding of the String field
      SHOULD be done.  When the RADIUS server receives the attribute
      from the external server, it MUST correctly set the Salt field and
      encrypt the String field before transmitting it to the RADIUS
      client.  If the channel used to communicate the MS-MPPE-Send-Key
      attribute is not secure from eavesdropping, the attribute MUST be
      cryptographically protected.

2.4.3.  MS-MPPE-Recv-Key

   Description

      The MS-MPPE-Recv-Key Attribute contains a session key for use by
      the Microsoft Point-to-Point Encryption Protocol (MPPE).  As the
      name implies, this key is intended for encrypting packets received
      by the NAS from the remote host.  This Attribute is only included
      in Access-Accept packets.

   A summary of the MS-MPPE-Recv-Key Attribute format is given below.
   The fields are transmitted left to right.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Vendor-Type  | Vendor-Length |             Salt
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                               String...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Vendor-Type
      17 for MS-MPPE-Recv-Key.

   Vendor-Length
      > 4

   Salt
      The Salt field is two octets in length and is used to ensure the
      uniqueness of the keys used to encrypt each of the encrypted
      attributes occurring in a given Access-Accept packet.  The most
      significant bit (leftmost) of the Salt field MUST be set (1).  The
      contents of each Salt field in a given Access-Accept packet MUST
      be unique.

   String
      The plaintext String field consists of three logical sub-fields:
      the Key-Length and Key sub-fields (both of which are required),
      and the optional Padding sub-field.  The Key-Length sub-field is
      one octet in length and contains the length of the unencrypted Key
      sub-field.  The Key sub-field contains the actual encryption key.
      If the combined length (in octets) of the unencrypted Key-Length
      and Key sub-fields is not an even multiple of 16, then the Padding
      sub-field MUST be present.  If it is present, the length of the
      Padding sub-field is variable, between 1 and 15 octets.  The
      String field MUST be encrypted as follows, prior to transmission:

         Construct a plaintext version of the String field by
         concatenating the Key-Length and Key sub-fields.  If necessary,
         pad the resulting string until its length (in octets) is an
         even multiple of 16.  It is recommended that zero octets (0x00)
         be used for padding.  Call this plaintext P.

         Call the shared secret S, the pseudo-random 128-bit Request
         Authenticator (from the corresponding Access-Request packet) R,
         and the contents of the Salt field A.  Break P into 16 octet
         chunks p(1), p(2)...p(i), where i = len(P)/16.  Call the
         ciphertext blocks c(1), c(2)...c(i) and the final ciphertext C.
         Intermediate values b(1), b(2)...c(i) are required.  Encryption
         is performed in the following manner ('+' indicates
         concatenation):

         b(1) = MD5(S + R + A)    c(1) = p(1) xor b(1)   C = c(1)
         b(2) = MD5(S + c(1))     c(2) = p(2) xor b(2)   C = C + c(2)
                     .                      .
                     .                      .
                     .                      .
         b(i) = MD5(S + c(i-1))   c(i) = p(i) xor b(i)   C = C + c(i)

         The resulting encrypted String field will contain
         c(1)+c(2)+...+c(i).

      On receipt, the process is reversed to yield the plaintext String.

   Implementation Notes
      It is possible that the length of the key returned may be larger
      than needed for the encryption scheme in use.  In this case, the
      RADIUS client is responsible for performing any necessary
      truncation.

      This attribute MAY be used to pass a key from an external (e.g.,
      EAP [15]) server to the RADIUS server.  In this case, it may be
      impossible for the external server to correctly encrypt the key,
      since the RADIUS shared secret might be unavailable.  The external
      server SHOULD, however, return the attribute as defined above; the
      Salt field SHOULD be zero-filled and padding of the String field
      SHOULD be done.  When the RADIUS server receives the attribute
      from the external server, it MUST correctly set the Salt field and
      encrypt the String field before transmitting it to the RADIUS
      client.  If the channel used to communicate the MS-MPPE-Recv-Key
      attribute is not secure from eavesdropping, the attribute MUST be
      cryptographically protected.

2.4.4.  MS-MPPE-Encryption-Policy

   Description

      The MS-MPPE-Encryption-Policy Attribute may be used to signify
      whether the use of encryption is allowed or required.  If the
      Policy field is equal to 1 (Encryption-Allowed), any or none of
      the encryption types specified in the MS-MPPE-Encryption-Types
      Attribute MAY be used.  If the Policy field is equal to 2
      (Encryption-Required), any of the encryption types specified in
      the MS-MPPE-Encryption-Types Attribute MAY be used, but at least
      one MUST be used.

   A summary of the MS-MPPE-Encryption-Policy Attribute format is given
   below.  The fields are transmitted left to right.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Vendor-Type  | Vendor-Length |             Policy
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              Policy (cont)        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Vendor-Type
      7 for MS-MPPE-Encryption-Policy.

   Vendor-Length
      6

   Policy
      The Policy field is 4 octets in length.  Defined values are:

         1      Encryption-Allowed 2      Encryption-Required

2.4.5.  MS-MPPE-Encryption-Types

   Description

      The MS-MPPE-Encryption-Types Attribute is used to signify the
      types of encryption available for use with MPPE.  It is a four
      octet integer that is interpreted as a string of bits.

   A summary of the MS-MPPE-Encryption-Policy Attribute format is given
   below.  The fields are transmitted left to right.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Vendor-Type  | Vendor-Length |             Types
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
               Types (cont)        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Vendor-Type
      8 for MS-MPPE-Encryption-Types.

   Vendor-Length
      6

   Policy
      The Types field is 4 octets in length.  The following diagram
      illustrates the Types field.

         3                   2                   1
       1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                         |S|L| |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

      If the L bit is set, RC4[5] encryption using a 40-bit key is
      allowed.  If the S bit is set, RC4 encryption using a 128-bit key
      is allowed.  If both the L and S bits are set, then either 40- or
      128-bit keys may be used with the RC4 algorithm.

*/

struct _rhp_proto_radius_attr {

#define RHP_RADIUS_ATTR_TYPE_USER_NAME						1
#define RHP_RADIUS_ATTR_TYPE_NAS_IP_ADDRESS				4
#define RHP_RADIUS_ATTR_TYPE_NAS_IPV6_ADDRESS			95
#define RHP_RADIUS_ATTR_TYPE_NAS_ID								32
#define RHP_RADIUS_ATTR_TYPE_FRAMED_MTU						12
#define RHP_RADIUS_ATTR_TYPE_CALLED_STATION_ID		30
#define RHP_RADIUS_ATTR_TYPE_CALLING_STATION_ID		31
#define RHP_RADIUS_ATTR_TYPE_NAS_PORT_TYPE				61
#define RHP_RADIUS_ATTR_TYPE_EAP									79
#define RHP_RADIUS_ATTR_TYPE_MESG_AUTH						80
#define RHP_RADIUS_ATTR_TYPE_NAS_PORT							5
#define RHP_RADIUS_ATTR_TYPE_NAS_PORT_ID					87
#define RHP_RADIUS_ATTR_TYPE_CONNECT_INFO					77
#define RHP_RADIUS_ATTR_TYPE_SESSION_TIMEOUT			27
#define RHP_RADIUS_ATTR_TYPE_REPLY_MESG						18
#define RHP_RADIUS_ATTR_TYPE_STATE								24
#define RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC			26
#define RHP_RADIUS_ATTR_TYPE_TERMINATION_ACTION		29
#define RHP_RADIUS_ATTR_TYPE_FRAMED_IP_ADDRESS		8
#define RHP_RADIUS_ATTR_TYPE_FRAMED_IP_NETMASK		9
#define RHP_RADIUS_ATTR_TYPE_FRAMED_IPV6_ADDRESS	168
#define RHP_RADIUS_ATTR_TYPE_DNS_IPV6_ADDRESS			169
#define RHP_RADIUS_ATTR_TYPE_TUNNEL_PRIVATE_GROUP_ID		81
#define RHP_RADIUS_ATTR_TYPE_TUNNEL_CLIENT_AUTH_ID			90

#define RHP_RADIUS_ATTR_TYPE_ACCT_STATUS_TYPE					40
#define RHP_RADIUS_ATTR_TYPE_ACCT_DELAY_TIME					41
#define RHP_RADIUS_ATTR_TYPE_ACCT_INPUT_OCTETS				42
#define RHP_RADIUS_ATTR_TYPE_ACCT_OUTPUT_OCTETS				43
#define RHP_RADIUS_ATTR_TYPE_ACCT_SESSION_ID					44
#define RHP_RADIUS_ATTR_TYPE_ACCT_AUTHENTIC						45
#define RHP_RADIUS_ATTR_TYPE_ACCT_SESSION_TIME				46
#define RHP_RADIUS_ATTR_TYPE_ACCT_INPUT_PACKETS				47
#define RHP_RADIUS_ATTR_TYPE_ACCT_OUTPUT_PACKETS			48
#define RHP_RADIUS_ATTR_TYPE_ACCT_TERMINATE_CAUSE			49
#define RHP_RADIUS_ATTR_TYPE_ACCT_MULTI_SESSION_ID		50
#define RHP_RADIUS_ATTR_TYPE_ACCT_LINK_COUNT					51


// (RFC3579 2.2.  Invalid Packets)
// EAP messages are protected by IKEv2 and so Error-Cause=202
// (Invalid EAP Packet - Ignored) is not implemented currently.
#define RHP_RADIUS_ATTR_TYPE_ERROR_CAUSE					101
	u8 type;

	u8 len;

#define RHP_RADIUS_ATTR_TYPE_NAS_PORT_TYPE_VIRTUAL	5

#define RHP_RADIUS_ATTR_TYPE_TERMINATION_ACTION_DEFAULT		0
#define RHP_RADIUS_ATTR_TYPE_TERMINATION_ACTION_REQUEST		1

#define RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC_CISCO			9
#define RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC_MICROSOFT	311


#define RHP_RADIUS_ATTR_TYPE_ACCT_STATUS_START					1
#define RHP_RADIUS_ATTR_TYPE_ACCT_STATUS_STOP						2
#define RHP_RADIUS_ATTR_TYPE_ACCT_STATUS_INTERIM_UPDATE	3
#define RHP_RADIUS_ATTR_TYPE_ACCT_STATUS_ACCOUNTING_ON	7
#define RHP_RADIUS_ATTR_TYPE_ACCT_STATUS_ACCOUNTING_OFF	8

#define RHP_RADIUS_ATTR_TYPE_ACCT_AUTHENTIC_RADIUS		1
#define RHP_RADIUS_ATTR_TYPE_ACCT_AUTHENTIC_LOCAL			2
#define RHP_RADIUS_ATTR_TYPE_ACCT_AUTHENTIC_REMOTE		3

#define RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_USER_REQUEST					1
#define RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_LOST_CARRIER					2
#define RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_LOST_SERVICE					3
#define RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_IDLE_TIMEOUT					4
#define RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_SESSION_TIMEOUT			5
#define RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_ADMIN_RESET					6
#define RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_ADMIN_REBOOT					7
#define RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_PORT_ERROR						8
#define RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_NAS_ERROR						9
#define RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_NAS_REQUEST					10
#define RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_NAS_REBOOT						11
#define RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_PORT_UNNEEDED				12
#define RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_PORT_PREEMPTED				13
#define RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_PORT_SUSPENDED				14
#define RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_SERVICE_UNAVAILABLE	15
#define RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_CALLBACK							16
#define RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_USER_ERROR						17
#define RHP_RADIUS_ATTR_TYPE_ACCT_TERM_CAUSE_HOST_REQUEST					18

	/* Followed by value. */
};
typedef struct _rhp_proto_radius_attr	rhp_proto_radius_attr;

#define RHP_RADIUS_ATTR_VAL_MAX_LEN		253	// (255 - sizeof(rhp_proto_radius_attr))


struct _rhp_proto_radius_attr_vendor {

	u8 type; // RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC

	u8 len;

	u32 vendor_id;

	/* Followed by vendor-specific data like rhp_proto_radius_attr_vendor_ms
	   or rhp_proto_radius_attr_vendor_ms_mppe_send_key */
};
typedef struct _rhp_proto_radius_attr_vendor	rhp_proto_radius_attr_vendor;


struct _rhp_proto_radius_attr_vendor_ms {

#define RHP_RADIUS_VENDOR_MS_ATTR_TYPE_MPPE_SEND_KEY						16
#define RHP_RADIUS_VENDOR_MS_ATTR_TYPE_MPPE_RECV_KEY						17
#define RHP_RADIUS_VENDOR_MS_ATTR_TYPE_MPPE_ENCRYPTION_POLICY		7
#define RHP_RADIUS_VENDOR_MS_ATTR_TYPE_MPPE_ENCRYPTION_TYPES		8
#define RHP_RADIUS_VENDOR_MS_ATTR_TYPE_PRIMARY_DNS_SERVER				28
#define RHP_RADIUS_VENDOR_MS_ATTR_TYPE_SECONDARY_DNS_SERVER			29
#define RHP_RADIUS_VENDOR_MS_ATTR_TYPE_PRIMARY_NBNS_SERVER			30
#define RHP_RADIUS_VENDOR_MS_ATTR_TYPE_SECONDARY_NBNS_SERVER		31
	u8 vendor_type;

	u8 vendor_len;

	/* Followed by value*/
};
typedef struct _rhp_proto_radius_attr_vendor_ms	rhp_proto_radius_attr_vendor_ms;


struct _rhp_proto_radius_attr_vendor_ms_mppe_key {

	u8 vendor_type;

	u8 vendor_len;

	u8 salt[2];

	/* Followed by encrypted key value. */
};
typedef struct _rhp_proto_radius_attr_vendor_ms_mppe_key	rhp_proto_radius_attr_vendor_ms_mppe_send_key;
typedef struct _rhp_proto_radius_attr_vendor_ms_mppe_key	rhp_proto_radius_attr_vendor_ms_mppe_recv_key;



//
// IKEv1
//

/*

 - RFC2408

 3.3 Data Attributes

   There are several instances within ISAKMP where it is necessary to
   represent Data Attributes.  An example of this is the Security
   Association (SA) Attributes contained in the Transform payload
   (described in section 3.6).  These Data Attributes are not an ISAKMP
   payload, but are contained within ISAKMP payloads.  The format of the
   Data Attributes provides the flexibility for representation of many
   different types of information.  There can be multiple Data
   Attributes within a payload.  The length of the Data Attributes will
   either be 4 octets or defined by the Attribute Length field.  This is
   done using the Attribute Format bit described below.  Specific
   information about the attributes for each domain will be described in
   a DOI document, e.g.  IPSEC DOI [IPDOI].

                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !A!       Attribute Type        !    AF=0  Attribute Length     !
     !F!                             !    AF=1  Attribute Value      !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     .                   AF=0  Attribute Value                       .
     .                   AF=1  Not Transmitted                       .
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


                     Figure 4:  Data Attributes

   The Data Attributes fields are defined as follows:

    o  Attribute Type (2 octets) - Unique identifier for each type of
       attribute.  These attributes are defined as part of the DOI-
       specific information.

       The most significant bit, or Attribute Format (AF), indicates
       whether the data attributes follow the Type/Length/Value (TLV)
       format or a shortened Type/Value (TV) format.  If the AF bit is a
       zero (0), then the Data Attributes are of the Type/Length/Value
       (TLV) form.  If the AF bit is a one (1), then the Data Attributes
       are of the Type/Value form.

    o  Attribute Length (2 octets) - Length in octets of the Attribute
       Value.  When the AF bit is a one (1), the Attribute Value is only
       2 octets and the Attribute Length field is not present.

    o  Attribute Value (variable length) - Value of the attribute
       associated with the DOI-specific Attribute Type.  If the AF bit
       is a zero (0), this field has a variable length defined by the
       Attribute Length field.  If the AF bit is a one (1), the
       Attribute Value has a length of 2 octets.
*/
struct _rhp_proto_ikev1_attr {

// P1: Phase 1
#define RHP_PROTO_IKEV1_P1_ATTR_TYPE_ENCRYPTION			1
#define RHP_PROTO_IKEV1_P1_ATTR_TYPE_HASH						2
#define RHP_PROTO_IKEV1_P1_ATTR_TYPE_AUTH_METHOD		3
#define RHP_PROTO_IKEV1_P1_ATTR_TYPE_GROUP_DESC			4
#define RHP_PROTO_IKEV1_P1_ATTR_TYPE_LIFE_TYPE			11
#define RHP_PROTO_IKEV1_P1_ATTR_TYPE_LIFE_DURATION	12
#define RHP_PROTO_IKEV1_P1_ATTR_TYPE_KEY_LEN				14

// P2: Phase 2
#define RHP_PROTO_IKEV1_P2_ATTR_TYPE_LIFE_TYPE			1
#define RHP_PROTO_IKEV1_P2_ATTR_TYPE_LIFE_DURATION	2
#define RHP_PROTO_IKEV1_P2_ATTR_TYPE_GROUP_DESC			3
#define RHP_PROTO_IKEV1_P2_ATTR_TYPE_ENCAP_MODE			4
#define RHP_PROTO_IKEV1_P2_ATTR_TYPE_AUTH						5
#define RHP_PROTO_IKEV1_P2_ATTR_TYPE_KEY_LEN				6
#define RHP_PROTO_IKEV1_P2_ATTR_TYPE_ESN						11
	u16 attr_type;

#define RHP_PROTO_IKEV1_P1_ATTR_ENC_NONE			0
#define RHP_PROTO_IKEV1_P1_ATTR_ENC_3DES_CBC	5
#define RHP_PROTO_IKEV1_P1_ATTR_ENC_AES_CBC		7

#define RHP_PROTO_IKEV1_P1_ATTR_HASH_NONE						0
#define RHP_PROTO_IKEV1_P1_ATTR_HASH_MD5						1
#define RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA1						2
#define RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA2_256				4
#define RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA2_384				5
#define RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA2_512				6

#define RHP_PROTO_IKEV1_P1_ATTR_AUTH_METHOD_PSK			1
#define RHP_PROTO_IKEV1_P1_ATTR_AUTH_METHOD_RSASIG	3

#define RHP_PROTO_IKEV1_ATTR_GROUP_NONE				0
#define RHP_PROTO_IKEV1_ATTR_GROUP_MODP_768		1
#define RHP_PROTO_IKEV1_ATTR_GROUP_MODP_1024	2
#define RHP_PROTO_IKEV1_ATTR_GROUP_MODP_1536	5
#define RHP_PROTO_IKEV1_ATTR_GROUP_MODP_2048	14
#define RHP_PROTO_IKEV1_ATTR_GROUP_MODP_3072	15
#define RHP_PROTO_IKEV1_ATTR_GROUP_MODP_4096	16
#define RHP_PROTO_IKEV1_ATTR_GROUP_MODP_6144	17
#define RHP_PROTO_IKEV1_ATTR_GROUP_MODP_8192	18

#define RHP_PROTO_IKEV1_ATTR_LIFE_TYPE_SECONDS		1
#define RHP_PROTO_IKEV1_ATTR_LIFE_TYPE_KILOBYTES	2

#define RHP_PROTO_IKEV1_P2_ATTR_ENCAP_MODE_TUNNEL					1
#define RHP_PROTO_IKEV1_P2_ATTR_ENCAP_MODE_TRANSPORT			2
#define RHP_PROTO_IKEV1_P2_ATTR_ENCAP_MODE_UDP_TUNNEL			3
#define RHP_PROTO_IKEV1_P2_ATTR_ENCAP_MODE_UDP_TRANSPORT	4

#define RHP_PROTO_IKEV1_P2_ATTR_AUTH_NONE						0
#define RHP_PROTO_IKEV1_P2_ATTR_AUTH_HMAC_MD5				1
#define RHP_PROTO_IKEV1_P2_ATTR_AUTH_HMAC_SHA1			2
#define RHP_PROTO_IKEV1_P2_ATTR_AUTH_HMAC_SHA2_256	5
#define RHP_PROTO_IKEV1_P2_ATTR_AUTH_HMAC_SHA2_384	6
#define RHP_PROTO_IKEV1_P2_ATTR_AUTH_HMAC_SHA2_512	7
#define RHP_PROTO_IKEV1_P2_ATTR_AUTH_AES_XCBC_MAC		9

#define RHP_PROTO_IKEV1_P2_ATTR_ESN_DISABLE		0
#define RHP_PROTO_IKEV1_P2_ATTR_ESN_ENABLE		1
	u16 len_or_value;
};
typedef struct _rhp_proto_ikev1_attr	rhp_proto_ikev1_attr;


/*

 3.4 Security Association Payload

   The Security Association Payload is used to negotiate security
   attributes and to indicate the Domain of Interpretation (DOI) and
   Situation under which the negotiation is taking place.  Figure 5
   shows the format of the Security Association payload.

                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     ! Next Payload  !   RESERVED    !         Payload Length        !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !              Domain of Interpretation  (DOI)                  !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !                                                               !
     ~                           Situation                           ~
     !                                                               !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


              Figure 5:  Security Association Payload

    o  Next Payload (1 octet) - Identifier for the payload type of the
       next payload in the message.  If the current payload is the last
       in the message, then this field will be 0.  This field MUST NOT
       contain the values for the Proposal or Transform payloads as they
       are considered part of the security association negotiation.  For
       example, this field would contain the value "10" (Nonce payload)
       in the first message of a Base Exchange (see Section 4.4) and the
       value "0" in the first message of an Identity Protect Exchange
       (see Section 4.5).

    o  RESERVED (1 octet) - Unused, set to 0.

    o  Payload Length (2 octets) - Length in octets of the entire
       Security Association payload, including the SA payload, all
       Proposal payloads, and all Transform payloads associated with the
       proposed Security Association.

    o  Domain of Interpretation (4 octets) - Identifies the DOI (as
       described in Section 2.1) under which this negotiation is taking
       place.  The DOI is a 32-bit unsigned integer.  A DOI value of 0
       during a Phase 1 exchange specifies a Generic ISAKMP SA which can
       be used for any protocol during the Phase 2 exchange.  The
       necessary SA Attributes are defined in A.4.  A DOI value of 1 is
       assigned to the IPsec DOI [IPDOI].  All other DOI values are
       reserved to IANA for future use.  IANA will not normally assign a
       DOI value without referencing some public specification, such as
       an Internet RFC. Other DOI's can be defined using the description
       in appendix B.  This field MUST be present within the Security
       Association payload.

    o  Situation (variable length) - A DOI-specific field that
       identifies the situation under which this negotiation is taking
       place.  The Situation is used to make policy decisions regarding
       the security attributes being negotiated.  Specifics for the IETF
       IP Security DOI Situation are detailed in [IPDOI].  This field
       MUST be present within the Security Association payload.

3.5 Proposal Payload

   The Proposal Payload contains information used during Security
   Association negotiation.  The proposal consists of security
   mechanisms, or transforms, to be used to secure the communications
   channel.  Figure 6 shows the format of the Proposal Payload.  A
   description of its use can be found in section 4.2.

                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     ! Next Payload  !   RESERVED    !         Payload Length        !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !  Proposal #   !  Protocol-Id  !    SPI Size   !# of Transforms!
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !                        SPI (variable)                         !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


                 Figure 6:  Proposal Payload Format

   The Proposal Payload fields are defined as follows:

    o  Next Payload (1 octet) - Identifier for the payload type of the
       next payload in the message.  This field MUST only contain the
       value "2" or "0".  If there are additional Proposal payloads in
       the message, then this field will be 2.  If the current Proposal
       payload is the last within the security association proposal,
       then this field will be 0.

    o  RESERVED (1 octet) - Unused, set to 0.

    o  Payload Length (2 octets) - Length in octets of the entire
       Proposal payload, including generic payload header, the Proposal
       payload, and all Transform payloads associated with this
       proposal.  In the event there are multiple proposals with the
       same proposal number (see section 4.2), the Payload Length field
       only applies to the current Proposal payload and not to all
       Proposal payloads.

    o  Proposal # (1 octet) - Identifies the Proposal number for the
       current payload.  A description of the use of this field is found
       in section 4.2.

    o  Protocol-Id (1 octet) - Specifies the protocol identifier for the
       current negotiation.  Examples might include IPSEC ESP, IPSEC AH,
       OSPF, TLS, etc.

    o  SPI Size (1 octet) - Length in octets of the SPI as defined by
       the Protocol-Id.  In the case of ISAKMP, the Initiator and
       Responder cookie pair from the ISAKMP Header is the ISAKMP SPI,
       therefore, the SPI Size is irrelevant and MAY be from zero (0) to
       sixteen (16).  If the SPI Size is non-zero, the content of the
       SPI field MUST be ignored.  If the SPI Size is not a multiple of
       4 octets it will have some impact on the SPI field and the
       alignment of all payloads in the message.  The Domain of
       Interpretation (DOI) will dictate the SPI Size for other
       protocols.

    o  # of Transforms (1 octet) - Specifies the number of transforms
       for the Proposal.  Each of these is contained in a Transform
       payload.

    o  SPI (variable) - The sending entity's SPI. In the event the SPI
       Size is not a multiple of 4 octets, there is no padding applied
       to the payload, however, it can be applied at the end of the
       message.

   The payload type for the Proposal Payload is two (2).

3.6 Transform Payload

   The Transform Payload contains information used during Security
   Association negotiation.  The Transform payload consists of a
   specific security mechanism, or transforms, to be used to secure the
   communications channel.  The Transform payload also contains the
   security association attributes associated with the specific
   transform.  These SA attributes are DOI-specific.  Figure 7 shows the
   format of the Transform Payload.  A description of its use can be
   found in section 4.2.

                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     ! Next Payload  !   RESERVED    !         Payload Length        !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !  Transform #  !  Transform-Id !           RESERVED2           !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !                                                               !
     ~                        SA Attributes                          ~
     !                                                               !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


                Figure 7:  Transform Payload Format

   The Transform Payload fields are defined as follows:

    o  Next Payload (1 octet) - Identifier for the payload type of the
       next payload in the message.  This field MUST only contain the
       value "3" or "0".  If there are additional Transform payloads in
       the proposal, then this field will be 3.  If the current
       Transform payload is the last within the proposal, then this
       field will be 0.

    o  RESERVED (1 octet) - Unused, set to 0.

    o  Payload Length (2 octets) - Length in octets of the current
       payload, including the generic payload header, Transform values,
       and all SA Attributes.

    o  Transform # (1 octet) - Identifies the Transform number for the
       current payload.  If there is more than one transform proposed
       for a specific protocol within the Proposal payload, then each
       Transform payload has a unique Transform number.  A description
       of the use of this field is found in section 4.2.

    o  Transform-Id (1 octet) - Specifies the Transform identifier for
       the protocol within the current proposal.  These transforms are
       defined by the DOI and are dependent on the protocol being
       negotiated.

    o  RESERVED2 (2 octets) - Unused, set to 0.

    o  SA Attributes (variable length) - This field contains the
       security association attributes as defined for the transform
       given in the Transform-Id field.  The SA Attributes SHOULD be
       represented using the Data Attributes format described in section
       3.3.  If the SA Attributes are not aligned on 4-byte boundaries,
       then subsequent payloads will not be aligned and any padding will
       be added at the end of the message to make the message 4-octet
       aligned.

   The payload type for the Transform Payload is three (3).

*/

struct _rhp_proto_ikev1_sa_payload {

	u8 next_payload;

	u8 reserved;

	u16 len;

#define RHP_PROTO_IKEV1_DOI_IPSEC		1
	u32 doi;

#define RHP_PROTO_IKEV1_SIT_IDENTITY_ONLY		0x01
	u32 situation;
};
typedef struct _rhp_proto_ikev1_sa_payload	rhp_proto_ikev1_sa_payload;

struct _rhp_proto_ikev1_proposal_payload {

	u8 next_payload;

	u8 reserved;

	u16 len;

	u8 proposal_number;

#define RHP_PROTO_IKEV1_PROP_PROTO_ID_ISAKMP	1
#define RHP_PROTO_IKEV1_PROP_PROTO_ID_AH			2
#define RHP_PROTO_IKEV1_PROP_PROTO_ID_ESP			3
#define RHP_PROTO_IKEV1_PROP_PROTO_ID_IPCOMP	4
	u8 protocol_id;

	u8 spi_len;

	u8 transform_num;

	/* SPI value (if any) */
};
typedef struct _rhp_proto_ikev1_proposal_payload	rhp_proto_ikev1_proposal_payload;

struct _rhp_proto_ikev1_transform_payload {

	u8 next_payload;

	u8 reserved;

	u16 len;

	u8 transform_number;

#define RHP_PROTO_IKEV1_TF_ISAKMP_KEY_IKE	1

#define RHP_PROTO_IKEV1_TF_ESP_3DES				3
#define RHP_PROTO_IKEV1_TF_ESP_NULL				11
#define RHP_PROTO_IKEV1_TF_ESP_AES_CBC		12
	u8 transform_id;

	u16 reserved2;

	/* SA attributes */
};
typedef struct _rhp_proto_ikev1_transform_payload	rhp_proto_ikev1_transform_payload;


/*

 3.7 Key Exchange Payload

   The Key Exchange Payload supports a variety of key exchange
   techniques.  Example key exchanges are Oakley [Oakley], Diffie-
   Hellman, the enhanced Diffie-Hellman key exchange described in X9.42
   [ANSI], and the RSA-based key exchange used by PGP. Figure 8 shows
   the format of the Key Exchange payload.

   The Key Exchange Payload fields are defined as follows:

    o  Next Payload (1 octet) - Identifier for the payload type of the
       nextpayload in the message.  If the current payload is the last
       in the message, then this field will be 0.

                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     ! Next Payload  !   RESERVED    !         Payload Length        !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !                                                               !
     ~                       Key Exchange Data                       ~
     !                                                               !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


               Figure 8:  Key Exchange Payload Format

    o  RESERVED (1 octet) - Unused, set to 0.

    o  Payload Length (2 octets) - Length in octets of the current
       payload, including the generic payload header.

    o  Key Exchange Data (variable length) - Data required to generate a
       session key.  The interpretation of this data is specified by the
       DOI and the associated Key Exchange algorithm.  This field may
       also contain pre-placed key indicators.

   The payload type for the Key Exchange Payload is four (4).
*/

struct _rhp_proto_ikev1_ke_payload {

	u8 next_payload;

	u8 reserved;

	u16 len;

	/* Key Exchange data */
};
typedef struct _rhp_proto_ikev1_ke_payload	rhp_proto_ikev1_ke_payload;

/*

 3.8 Identification Payload

   The Identification Payload contains DOI-specific data used to
   exchange identification information.  This information is used for
   determining the identities of communicating peers and may be used for
   determining authenticity of information.  Figure 9 shows the format
   of the Identification Payload.

   The Identification Payload fields are defined as follows:

    o  Next Payload (1 octet) - Identifier for the payload type of the
       next payload in the message.  If the current payload is the last
       in the message, then this field will be 0.

    o  RESERVED (1 octet) - Unused, set to 0.

    o  Payload Length (2 octets) - Length in octets of the current
       payload, including the generic payload header.

    o  ID Type (1 octet) - Specifies the type of Identification being
       used.

                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     ! Next Payload  !   RESERVED    !         Payload Length        !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !   ID Type     !             DOI Specific ID Data              !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !                                                               !
     ~                   Identification Data                         ~
     !                                                               !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


              Figure 9:  Identification Payload Format

       This field is DOI-dependent.

    o  DOI Specific ID Data (3 octets) - Contains DOI specific
       Identification data.  If unused, then this field MUST be set to
       0.

    o  Identification Data (variable length) - Contains identity
       information.  The values for this field are DOI-specific and the
       format is specified by the ID Type field.  Specific details for
       the IETF IP Security DOI Identification Data are detailed in
       [IPDOI].

			 The payload type for the Identification Payload is five (5).
*/

/*

 4.6.2 Identification Payload Content

   The Identification Payload is used to identify the initiator of the
   Security Association.  The identity of the initiator SHOULD be used
   by the responder to determine the correct host system security policy
   requirement for the association.  For example, a host might choose to
   require authentication and integrity without confidentiality (AH)
   from a certain set of IP addresses and full authentication with
   confidentiality (ESP) from another range of IP addresses.  The
   Identification Payload provides information that can be used by the
   responder to make this decision.

   During Phase I negotiations, the ID port and protocol fields MUST be
   set to zero or to UDP port 500.  If an implementation receives any
   other values, this MUST be treated as an error and the security
   association setup MUST be aborted.  This event SHOULD be auditable.

   The following diagram illustrates the content of the Identification
   Payload.

    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   !  Next Payload !   RESERVED    !        Payload Length         !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   !   ID Type     !  Protocol ID  !             Port              !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                     Identification Data                       ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                  Figure 2: Identification Payload Format

   The Identification Payload fields are defined as follows:

     o  Next Payload (1 octet) - Identifier for the payload type of
        the next payload in the message.  If the current payload is the
        last in the message, this field will be zero (0).

     o  RESERVED (1 octet) - Unused, must be zero (0).

     o  Payload Length (2 octets) - Length, in octets, of the
        identification data, including the generic header.

     o  Identification Type (1 octet) - Value describing the identity
        information found in the Identification Data field.

     o  Protocol ID (1 octet) - Value specifying an associated IP
        protocol ID (e.g. UDP/TCP).  A value of zero means that the
        Protocol ID field should be ignored.

     o  Port (2 octets) - Value specifying an associated port.  A value
        of zero means that the Port field should be ignored.

     o  Identification Data (variable length) - Value, as indicated by
        the Identification Type.

4.6.2.1 Identification Type Values

   The following table lists the assigned values for the Identification
   Type field found in the Identification Payload.

       ID Type                   Value
       -------                   -----
       RESERVED                            0
       ID_IPV4_ADDR                        1
       ID_FQDN                             2
       ID_USER_FQDN                        3
       ID_IPV4_ADDR_SUBNET                 4
       ID_IPV6_ADDR                        5
       ID_IPV6_ADDR_SUBNET                 6
       ID_IPV4_ADDR_RANGE                  7
       ID_IPV6_ADDR_RANGE                  8
       ID_DER_ASN1_DN                      9
       ID_DER_ASN1_GN                      10
       ID_KEY_ID                           11

   For types where the ID entity is variable length, the size of the ID
   entity is computed from size in the ID payload header.

   When an IKE exchange is authenticated using certificates (of any
   format), any ID's used for input to local policy decisions SHOULD be
   contained in the certificate used in the authentication of the
   exchange.

4.6.2.2 ID_IPV4_ADDR

   The ID_IPV4_ADDR type specifies a single four (4) octet IPv4 address.

4.6.2.3 ID_FQDN

   The ID_FQDN type specifies a fully-qualified domain name string.  An
   example of a ID_FQDN is, "foo.bar.com".  The string should not
   contain any terminators.

4.6.2.4 ID_USER_FQDN

   The ID_USER_FQDN type specifies a fully-qualified username string, An
   example of a ID_USER_FQDN is, "piper@foo.bar.com".  The string should
   not contain any terminators.

4.6.2.5 ID_IPV4_ADDR_SUBNET

   The ID_IPV4_ADDR_SUBNET type specifies a range of IPv4 addresses,
   represented by two four (4) octet values.  The first value is an IPv4
   address.  The second is an IPv4 network mask.  Note that ones (1s) in
   the network mask indicate that the corresponding bit in the address
   is fixed, while zeros (0s) indicate a "wildcard" bit.

4.6.2.6 ID_IPV6_ADDR

   The ID_IPV6_ADDR type specifies a single sixteen (16) octet IPv6
   address.

4.6.2.7 ID_IPV6_ADDR_SUBNET

   The ID_IPV6_ADDR_SUBNET type specifies a range of IPv6 addresses,
   represented by two sixteen (16) octet values.  The first value is an
   IPv6 address.  The second is an IPv6 network mask.  Note that ones
   (1s) in the network mask indicate that the corresponding bit in the
   address is fixed, while zeros (0s) indicate a "wildcard" bit.

4.6.2.8 ID_IPV4_ADDR_RANGE

   The ID_IPV4_ADDR_RANGE type specifies a range of IPv4 addresses,
   represented by two four (4) octet values.  The first value is the
   beginning IPv4 address (inclusive) and the second value is the ending
   IPv4 address (inclusive).  All addresses falling between the two
   specified addresses are considered to be within the list.

4.6.2.9 ID_IPV6_ADDR_RANGE

   The ID_IPV6_ADDR_RANGE type specifies a range of IPv6 addresses,
   represented by two sixteen (16) octet values.  The first value is the
   beginning IPv6 address (inclusive) and the second value is the ending
   IPv6 address (inclusive).  All addresses falling between the two
   specified addresses are considered to be within the list.

4.6.2.10 ID_DER_ASN1_DN

   The ID_DER_ASN1_DN type specifies the binary DER encoding of an ASN.1
   X.500 Distinguished Name [X.501] of the principal whose certificates
   are being exchanged to establish the SA.

4.6.2.11 ID_DER_ASN1_GN

   The ID_DER_ASN1_GN type specifies the binary DER encoding of an ASN.1
   X.500 GeneralName [X.509] of the principal whose certificates are
   being exchanged to establish the SA.

4.6.2.12 ID_KEY_ID

   The ID_KEY_ID type specifies an opaque byte stream which may be used
   to pass vendor-specific information necessary to identify which pre-
   shared key should be used to authenticate Aggressive mode
   negotiations.
*/

struct _rhp_proto_ikev1_id_payload {

	u8 next_payload;

	u8 reserved;

	u16 len;

#define RHP_PROTO_IKEV1_ID_IPV4_ADDR					1
#define RHP_PROTO_IKEV1_ID_FQDN								2
#define RHP_PROTO_IKEV1_ID_USER_FQDN					3
#define RHP_PROTO_IKEV1_ID_IPV4_ADDR_SUBNET		4
#define RHP_PROTO_IKEV1_ID_IPV6_ADDR					5
#define RHP_PROTO_IKEV1_ID_IPV6_ADDR_SUBNET		6
#define RHP_PROTO_IKEV1_ID_IPV4_ADDR_RANGE		7
#define RHP_PROTO_IKEV1_ID_IPV6_ADDR_RANGE		8
#define RHP_PROTO_IKEV1_ID_DER_ASN1_DN				9
#define RHP_PROTO_IKEV1_ID_LIST								12 // [NOTICE] IKEv2's FC_NAME is assigned to the same number.
	u8 id_type;

	u8 protocol_id;

	u16 port;

	/* ID data */
};
typedef struct _rhp_proto_ikev1_id_payload	rhp_proto_ikev1_id_payload;


/*

 3.9 Certificate Payload

   The Certificate Payload provides a means to transport certificates or
   other certificate-related information via ISAKMP and can appear in
   any ISAKMP message.  Certificate payloads SHOULD be included in an
   exchange whenever an appropriate directory service (e.g.  Secure DNS
   [DNSSEC]) is not available to distribute certificates.  The
   Certificate payload MUST be accepted at any point during an exchange.
   Figure 10 shows the format of the Certificate Payload.

   NOTE: Certificate types and formats are not generally bound to a DOI
   - it is expected that there will only be a few certificate types, and
   that most DOIs will accept all of these types.

   The Certificate Payload fields are defined as follows:

    o  Next Payload (1 octet) - Identifier for the payload type of the
       next payload in the message.  If the current payload is the last
       in the message, then this field will be 0.

                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     ! Next Payload  !   RESERVED    !         Payload Length        !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     ! Cert Encoding !                                               !
     +-+-+-+-+-+-+-+-+                                               !
     ~                       Certificate Data                        ~
     !                                                               !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


               Figure 10:  Certificate Payload Format

    o  RESERVED (1 octet) - Unused, set to 0.

    o  Payload Length (2 octets) - Length in octets of the current
       payload, including the generic payload header.

    o  Certificate Encoding (1 octet) - This field indicates the type of
       certificate or certificate-related information contained in the
       Certificate Data field.

                          Certificate Type            Value
                  NONE                                   0
                  PKCS #7 wrapped X.509 certificate      1
                  PGP Certificate                        2
                  DNS Signed Key                         3
                  X.509 Certificate - Signature          4
                  X.509 Certificate - Key Exchange       5
                  Kerberos Tokens                        6
                  Certificate Revocation List (CRL)      7
                  Authority Revocation List (ARL)        8
                  SPKI Certificate                       9
                  X.509 Certificate - Attribute         10
                  RESERVED                           11 - 255

    o  Certificate Data (variable length) - Actual encoding of
       certificate data.  The type of certificate is indicated by the
       Certificate Encoding field.

   The payload type for the Certificate Payload is six (6).
*/

struct _rhp_proto_ikev1_cert_payload {

	u8 next_payload;

	u8 reserved;

	u16 len;

#define RHP_PROTO_IKEV1_CERT_ENC_X509_CERT_SIG			4
	u8 cert_encode;

	/* Certificate data */
};
typedef struct _rhp_proto_ikev1_cert_payload	rhp_proto_ikev1_cert_payload;


/*

 3.10 Certificate Request Payload

   The Certificate Request Payload provides a means to request
   certificates via ISAKMP and can appear in any message.  Certificate
   Request payloads SHOULD be included in an exchange whenever an
   appropriate directory service (e.g.  Secure DNS [DNSSEC]) is not
   available to distribute certificates.  The Certificate Request
   payload MUST be accepted at any point during the exchange.  The
   responder to the Certificate Request payload MUST send its
   certificate, if certificates are supported, based on the values
   contained in the payload.  If multiple certificates are required,
   then multiple Certificate Request payloads SHOULD be transmitted.
   Figure 11 shows the format of the Certificate Request Payload.

                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     ! Next Payload  !   RESERVED    !         Payload Length        !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !  Cert. Type   !                                               !
     +-+-+-+-+-+-+-+-+                                               !
     ~                    Certificate Authority                      ~
     !                                                               !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


           Figure 11:  Certificate Request Payload Format

   The Certificate Payload fields are defined as follows:

    o  Next Payload (1 octet) - Identifier for the payload type of the
       next payload in the message.  If the current payload is the last
       in the message, then this field will be 0.

    o  RESERVED (1 octet) - Unused, set to 0.

    o  Payload Length (2 octets) - Length in octets of the current
       payload, including the generic payload header.

    o  Certificate Type (1 octet) - Contains an encoding of the type of
       certificate requested.  Acceptable values are listed in section
       3.9.

    o  Certificate Authority (variable length) - Contains an encoding of
       an acceptable certificate authority for the type of certificate
       requested.  As an example, for an X.509 certificate this field
       would contain the Distinguished Name encoding of the Issuer Name
       of an X.509 certificate authority acceptable to the sender of
       this payload.  This would be included to assist the responder in
       determining how much of the certificate chain would need to be
       sent in response to this request.  If there is no specific
       certificate authority requested, this field SHOULD not be
       included.

   The payload type for the Certificate Request Payload is seven (7).

*/

struct _rhp_proto_ikev1_cr_payload {

	u8 next_payload;

	u8 reserved;

	u16 len;

#define RHP_PROTO_IKEV1_CERT_ENC_X509_CERT_SIG			4
	u8 cert_encoding;

	/* CA data */
};
typedef struct _rhp_proto_ikev1_cr_payload	rhp_proto_ikev1_cr_payload;


/*

 3.11 Hash Payload

   The Hash Payload contains data generated by the hash function
   (selected during the SA establishment exchange), over some part of
   the message and/or ISAKMP state.  This payload may be used to verify
   the integrity of the data in an ISAKMP message or for authentication
   of the negotiating entities.  Figure 12 shows the format of the Hash
   Payload.

                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     ! Next Payload  !   RESERVED    !         Payload Length        !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !                                                               !
     ~                           Hash Data                           ~
     !                                                               !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


                  Figure 12:  Hash Payload Format

   The Hash Payload fields are defined as follows:

    o  Next Payload (1 octet) - Identifier for the payload type of the
       next payload in the message.  If the current payload is the last
       in the message, then this field will be 0.

    o  RESERVED (1 octet) - Unused, set to 0.

    o  Payload Length (2 octets) - Length in octets of the current
       payload, including the generic payload header.

    o  Hash Data (variable length) - Data that results from applying the
       hash routine to the ISAKMP message and/or state.
*/

struct _rhp_proto_ikev1_hash_payload {

	u8 next_payload;

	u8 reserved;

	u16 len;

	/* Hash data */
};
typedef struct _rhp_proto_ikev1_hash_payload	rhp_proto_ikev1_hash_payload;


/*

 3.12 Signature Payload

   The Signature Payload contains data generated by the digital
   signature function (selected during the SA establishment exchange),
   over some part of the message and/or ISAKMP state.  This payload is
   used to verify the integrity of the data in the ISAKMP message, and
   may be of use for non-repudiation services.  Figure 13 shows the
   format of the Signature Payload.

                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     ! Next Payload  !   RESERVED    !         Payload Length        !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !                                                               !
     ~                         Signature Data                        ~
     !                                                               !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


                Figure 13:  Signature Payload Format

   The Signature Payload fields are defined as follows:

    o  Next Payload (1 octet) - Identifier for the payload type of the
       next payload in the message.  If the current payload is the last
       in the message, then this field will be 0.

    o  RESERVED (1 octet) - Unused, set to 0.

    o  Payload Length (2 octets) - Length in octets of the current
       payload, including the generic payload header.

    o  Signature Data (variable length) - Data that results from
       applying the digital signature function to the ISAKMP message
       and/or state.

   The payload type for the Signature Payload is nine (9).

*/

struct _rhp_proto_ikev1_sig_payload {

	u8 next_payload;

	u8 reserved;

	u16 len;

	/* Signature data */
};
typedef struct _rhp_proto_ikev1_sig_payload	rhp_proto_ikev1_sig_payload;


/*

 3.13 Nonce Payload

   The Nonce Payload contains random data used to guarantee liveness
   during an exchange and protect against replay attacks.  Figure 14
   shows the format of the Nonce Payload.  If nonces are used by a
   particular key exchange, the use of the Nonce payload will be
   dictated by the key exchange.  The nonces may be transmitted as part
   of the key exchange data, or as a separate payload.  However, this is
   defined by the key exchange, not by ISAKMP.

                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     ! Next Payload  !   RESERVED    !         Payload Length        !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !                                                               !
     ~                            Nonce Data                         ~
     !                                                               !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


                  Figure 14:  Nonce Payload Format

   The Nonce Payload fields are defined as follows:

    o  Next Payload (1 octet) - Identifier for the payload type of the
       next payload in the message.  If the current payload is the last
       in the message, then this field will be 0.

    o  RESERVED (1 octet) - Unused, set to 0.

    o  Payload Length (2 octets) - Length in octets of the current
       payload, including the generic payload header.

    o  Nonce Data (variable length) - Contains the random data generated
       by the transmitting entity.

   The payload type for the Nonce Payload is ten (10).

*/

struct _rhp_proto_ikev1_nonce_payload {

	u8 next_payload;

	u8 reserved;

	u16 len;

	/* Nonce data */
};
typedef struct _rhp_proto_ikev1_nonce_payload	rhp_proto_ikev1_nonce_payload;


/*

 3.14 Notification Payload

   The Notification Payload can contain both ISAKMP and DOI-specific
   data and is used to transmit informational data, such as error
   conditions, to an ISAKMP peer.  It is possible to send multiple
   Notification payloads in a single ISAKMP message.  Figure 15 shows
   the format of the Notification Payload.

   Notification which occurs during, or is concerned with, a Phase 1
   negotiation is identified by the Initiator and Responder cookie pair
   in the ISAKMP Header.  The Protocol Identifier, in this case, is
   ISAKMP and the SPI value is 0 because the cookie pair in the ISAKMP
   Header identifies the ISAKMP SA. If the notification takes place
   prior to the completed exchange of keying information, then the
   notification will be unprotected.

   Notification which occurs during, or is concerned with, a Phase 2
   negotiation is identified by the Initiator and Responder cookie pair
   in the ISAKMP Header and the Message ID and SPI associated with the
   current negotiation.  One example for this type of notification is to
   indicate why a proposal was rejected.

                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     ! Next Payload  !   RESERVED    !         Payload Length        !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !              Domain of Interpretation  (DOI)                  !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !  Protocol-ID  !   SPI Size    !      Notify Message Type      !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !                                                               !
     ~                Security Parameter Index (SPI)                 ~
     !                                                               !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !                                                               !
     ~                       Notification Data                       ~
     !                                                               !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


              Figure 15:  Notification Payload Format

   The Notification Payload fields are defined as follows:

    o  Next Payload (1 octet) - Identifier for the payload type of the
       next payload in the message.  If the current payload is the last
       in the message, then this field will be 0.

    o  RESERVED (1 octet) - Unused, set to 0.

    o  Payload Length (2 octets) - Length in octets of the current
       payload, including the generic payload header.

    o  Domain of Interpretation (4 octets) - Identifies the DOI (as
       described in Section 2.1) under which this notification is taking
       place.  For ISAKMP this value is zero (0) and for the IPSEC DOI
       it is one (1).  Other DOI's can be defined using the description
       in appendix B.

    o  Protocol-Id (1 octet) - Specifies the protocol identifier for the
       current notification.  Examples might include ISAKMP, IPSEC ESP,
       IPSEC AH, OSPF, TLS, etc.

    o  SPI Size (1 octet) - Length in octets of the SPI as defined by
       the Protocol-Id.  In the case of ISAKMP, the Initiator and
       Responder cookie pair from the ISAKMP Header is the ISAKMP SPI,
       therefore, the SPI Size is irrelevant and MAY be from zero (0) to
       sixteen (16).  If the SPI Size is non-zero, the content of the
       SPI field MUST be ignored.  The Domain of Interpretation (DOI)
       will dictate the SPI Size for other protocols.

    o  Notify Message Type (2 octets) - Specifies the type of
       notification message (see section 3.14.1).  Additional text, if
       specified by the DOI, is placed in the Notification Data field.

    o  SPI (variable length) - Security Parameter Index.  The receiving
       entity's SPI. The use of the SPI field is described in section
       2.4.  The length of this field is determined by the SPI Size
       field and is not necessarily aligned to a 4 octet boundary.

    o  Notification Data (variable length) - Informational or error data
       transmitted in addition to the Notify Message Type.  Values for
       this field are DOI-specific.

   The payload type for the Notification Payload is eleven (11).

3.14.1 Notify Message Types

   Notification information can be error messages specifying why an SA
   could not be established.  It can also be status data that a process
   managing an SA database wishes to communicate with a peer process.
   For example, a secure front end or security gateway may use the
   Notify message to synchronize SA communication.  The table below
   lists the Nofitication messages and their corresponding values.
   Values in the Private Use range are expected to be DOI-specific
   values.

                      NOTIFY MESSAGES - ERROR TYPES

                           Errors               Value
                 INVALID-PAYLOAD-TYPE             1
                 DOI-NOT-SUPPORTED                2
                 SITUATION-NOT-SUPPORTED          3
                 INVALID-COOKIE                   4
                 INVALID-MAJOR-VERSION            5
                 INVALID-MINOR-VERSION            6
                 INVALID-EXCHANGE-TYPE            7
                 INVALID-FLAGS                    8
                 INVALID-MESSAGE-ID               9
                 INVALID-PROTOCOL-ID             10
                 INVALID-SPI                     11
                 INVALID-TRANSFORM-ID            12
                 ATTRIBUTES-NOT-SUPPORTED        13
                 NO-PROPOSAL-CHOSEN              14
                 BAD-PROPOSAL-SYNTAX             15
                 PAYLOAD-MALFORMED               16
                 INVALID-KEY-INFORMATION         17
                 INVALID-ID-INFORMATION          18
                 INVALID-CERT-ENCODING           19
                 INVALID-CERTIFICATE             20
                 CERT-TYPE-UNSUPPORTED           21
                 INVALID-CERT-AUTHORITY          22
                 INVALID-HASH-INFORMATION        23
                 AUTHENTICATION-FAILED           24
                 INVALID-SIGNATURE               25
                 ADDRESS-NOTIFICATION            26
                 NOTIFY-SA-LIFETIME              27
                 CERTIFICATE-UNAVAILABLE         28
                 UNSUPPORTED-EXCHANGE-TYPE       29
                 UNEQUAL-PAYLOAD-LENGTHS         30
                 RESERVED (Future Use)        31 - 8191
                 Private Use                8192 - 16383



                      NOTIFY MESSAGES - STATUS TYPES
                          Status              Value
                  CONNECTED                   16384
                  RESERVED (Future Use)   16385 - 24575
                  DOI-specific codes     24576 - 32767
                  Private Use            32768 - 40959
                  RESERVED (Future Use)  40960 - 65535
*/

/*

 - RFC3706 Detecting Dead IKE Peers

5.1.  DPD Vendor ID

   To demonstrate DPD capability, an entity must send the DPD vendor ID.
   Both peers of an IKE session MUST send the DPD vendor ID before DPD
   exchanges can begin.  The format of the DPD Vendor ID is:

                                     1
                0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                !                           !M!M!
                !      HASHED_VENDOR_ID     !J!N!
                !                           !R!R!
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   where HASHED_VENDOR_ID = {0xAF, 0xCA, 0xD7, 0x13, 0x68, 0xA1, 0xF1,
   0xC9, 0x6B, 0x86, 0x96, 0xFC, 0x77, 0x57}, and MJR and MNR correspond
   to the current major and minor version of this protocol (1 and 0
   respectively).  An IKE peer MUST send the Vendor ID if it wishes to
   take part in DPD exchanges.

5.2.  Message Exchanges

   The DPD exchange is a bidirectional (HELLO/ACK) Notify message.  The
   exchange is defined as:

            Sender                                      Responder
           --------                                    -----------
   HDR*, NOTIFY(R-U-THERE), HASH   ------>

                                 <------    HDR*, NOTIFY(R-U-THERE-
                                            ACK), HASH

   The R-U-THERE message corresponds to a "HELLO" and the R-U-THERE-ACK
   corresponds to an "ACK."  Both messages are simply ISAKMP Notify
   payloads, and as such, this document defines these two new ISAKMP
   Notify message types:

      Notify                      Message Value
      R-U-THERE                   36136
      R-U-THERE-ACK               36137

   An entity that has sent the DPD Vendor ID MUST respond to an R-U-
   THERE query.  Furthermore, an entity MUST reject unencrypted R-U-
   THERE and R-U-THERE-ACK messages.

5.3.  NOTIFY(R-U-THERE/R-U-THERE-ACK) Message Format

   When sent, the R-U-THERE message MUST take the following form:

                       1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ! Next Payload  !   RESERVED    !         Payload Length        !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   !              Domain of Interpretation  (DOI)                  !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   !  Protocol-ID  !    SPI Size   !      Notify Message Type      !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   !                                                               !
   ~                Security Parameter Index (SPI)                 ~
   !                                                               !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   !                    Notification Data                          !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   As this message is an ISAKMP NOTIFY, the Next Payload, RESERVED, and
   Payload Length fields should be set accordingly.  The remaining
   fields are set as:

   -  Domain of Interpretation (4 octets) - SHOULD be set to IPSEC-DOI.

   -  Protocol ID (1 octet) - MUST be set to the protocol ID for ISAKMP.

   -  SPI Size (1 octet) - SHOULD be set to sixteen (16), the length of
      two octet-sized ISAKMP cookies.

   -  Notify Message Type (2 octets) - MUST be set to R-U-THERE

   -  Security Parameter Index (16 octets) - SHOULD be set to the
      cookies of the Initiator and Responder of the IKE SA (in that
      order)

   -  Notification Data (4 octets) - MUST be set to the sequence number
      corresponding to this message

   The format of the R-U-THERE-ACK message is the same, with the
   exception that the Notify Message Type MUST be set to R-U-THERE-ACK.
   Again, the Notification Data MUST be sent to the sequence number
   corresponding to the received R-U-THERE message.

*/

struct _rhp_proto_ikev1_n_payload {

	u8 next_payload;

	u8 reserved;

	u16 len;

	u32 doi;

	u8 protocol_id;

	u8 spi_len;

#define RHP_PROTO_IKEV1_N_ERR_INVALID_PAYLOAD_TYPE			1
#define RHP_PROTO_IKEV1_N_ERR_DOI_NOT_SUPPORTED					2
#define RHP_PROTO_IKEV1_N_ERR_SITUATION_NOT_SUPPORTED		3
#define RHP_PROTO_IKEV1_N_ERR_INVALID_COOKIE						4
#define RHP_PROTO_IKEV1_N_ERR_INVALID_MAJOR_VERSION			5
#define RHP_PROTO_IKEV1_N_ERR_INVALID_MINOR_VERSION			6
#define RHP_PROTO_IKEV1_N_ERR_INVALID_EXCHANGE_TYPE			7
#define RHP_PROTO_IKEV1_N_ERR_INVALID_FLAGS							8
#define RHP_PROTO_IKEV1_N_ERR_INVALID_MESSAGE_ID				9
#define RHP_PROTO_IKEV1_N_ERR_INVALID_PROTOCOL_ID				10
#define RHP_PROTO_IKEV1_N_ERR_INVALID_SPI								11
#define RHP_PROTO_IKEV1_N_ERR_INVALID_TRANSFORM_ID			12
#define RHP_PROTO_IKEV1_N_ERR_ATTRIBUTES_NOT_SUPPORTED	13
#define RHP_PROTO_IKEV1_N_ERR_NO_PROPOSAL_CHOSEN				14
#define RHP_PROTO_IKEV1_N_ERR_BAD_PROPOSAL_SYNTAX				15
#define RHP_PROTO_IKEV1_N_ERR_PAYLOAD_MALFORMED					16
#define RHP_PROTO_IKEV1_N_ERR_INVALID_KEY_INFORMATION		17
#define RHP_PROTO_IKEV1_N_ERR_INVALID_ID_INFORMATION		18
#define RHP_PROTO_IKEV1_N_ERR_INVALID_CERT_ENCODING			19
#define RHP_PROTO_IKEV1_N_ERR_INVALID_CERTIFICATE				20
#define RHP_PROTO_IKEV1_N_ERR_CERT_TYPE_UNSUPPORTED			21
#define RHP_PROTO_IKEV1_N_ERR_INVALID_CERT_AUTHORITY		22
#define RHP_PROTO_IKEV1_N_ERR_INVALID_HASH_INFORMATION	23
#define RHP_PROTO_IKEV1_N_ERR_AUTHENTICATION_FAILED			24
#define RHP_PROTO_IKEV1_N_ERR_INVALID_SIGNATURE					25
#define RHP_PROTO_IKEV1_N_ERR_ADDRESS_NOTIFICATION			26
#define RHP_PROTO_IKEV1_N_ERR_NOTIFY_SA_LIFETIME				27
#define RHP_PROTO_IKEV1_N_ERR_CERTIFICATE_UNAVAILABLE		28
#define RHP_PROTO_IKEV1_N_ERR_UNSUPPORTED_EXCHANGE_TYPE	29
#define RHP_PROTO_IKEV1_N_ERR_UNEQUAL_PAYLOAD_LENGTHS		30

#define RHP_PROTO_IKEV1_N_ERR_MIN								        1
#define RHP_PROTO_IKEV1_N_ERR_END								        16383

#define RHP_PROTO_IKEV1_N_ST_CONNECTED								16384
#define RHP_PROTO_IKEV1_N_ST_RESPONDER_LIFETIME				24576
#define RHP_PROTO_IKEV1_N_ST_REPLAY_STATUS						24577
#define RHP_PROTO_IKEV1_N_ST_INITIAL_CONTACT					24578

#define RHP_PROTO_IKEV1_N_ST_DPD_R_U_THERE					36136
#define RHP_PROTO_IKEV1_N_ST_DPD_R_U_THERE_ACK			36137
	u16 notify_mesg_type;

	/* SPI value (if any) */
	/* Notification data */
};
typedef struct _rhp_proto_ikev1_n_payload	rhp_proto_ikev1_n_payload;



/*

 3.15 Delete Payload

   The Delete Payload contains a protocol-specific security association
   identifier that the sender has removed from its security association
   database and is, therefore, no longer valid.  Figure 16 shows the
   format of the Delete Payload.  It is possible to send multiple SPIs
   in a Delete payload, however, each SPI MUST be for the same protocol.
   Mixing of Protocol Identifiers MUST NOT be performed with the Delete
   payload.

   Deletion which is concerned with an ISAKMP SA will contain a
   Protocol-Id of ISAKMP and the SPIs are the initiator and responder
   cookies from the ISAKMP Header.  Deletion which is concerned with a
   Protocol SA, such as ESP or AH, will contain the Protocol-Id of that
   protocol (e.g.  ESP, AH) and the SPI is the sending entity's SPI(s).

   NOTE: The Delete Payload is not a request for the responder to delete
   an SA, but an advisory from the initiator to the responder.  If the
   responder chooses to ignore the message, the next communication from
   the responder to the initiator, using that security association, will
   fail.  A responder is not expected to acknowledge receipt of a Delete
   payload.

                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     ! Next Payload  !   RESERVED    !         Payload Length        !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !              Domain of Interpretation  (DOI)                  !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !  Protocol-Id  !   SPI Size    !           # of SPIs           !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !                                                               !
     ~               Security Parameter Index(es) (SPI)              ~
     !                                                               !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


                 Figure 16:  Delete Payload Format

   The Delete Payload fields are defined as follows:

    o  Next Payload (1 octet) - Identifier for the payload type of the
       next payload in the message.  If the current payload is the last
       in the message, then this field will be 0.

    o  RESERVED (1 octet) - Unused, set to 0.

    o  Payload Length (2 octets) - Length in octets of the current
       payload, including the generic payload header.

    o  Domain of Interpretation (4 octets) - Identifies the DOI (as
       described in Section 2.1) under which this deletion is taking
       place.  For ISAKMP this value is zero (0) and for the IPSEC DOI
       it is one (1).  Other DOI's can be defined using the description
       in appendix B.

    o  Protocol-Id (1 octet) - ISAKMP can establish security
       associations for various protocols, including ISAKMP and IPSEC.
       This field identifies which security association database to
       apply the delete request.

    o  SPI Size (1 octet) - Length in octets of the SPI as defined by
       the Protocol-Id.  In the case of ISAKMP, the Initiator and
       Responder cookie pair is the ISAKMP SPI. In this case, the SPI
       Size would be 16 octets for each SPI being deleted.

    o  # of SPIs (2 octets) - The number of SPIs contained in the Delete
       payload.  The size of each SPI is defined by the SPI Size field.

    o  Security Parameter Index(es) (variable length) - Identifies the
       specific security association(s) to delete.  Values for this
       field are DOI and protocol specific.  The length of this field is
       determined by the SPI Size and # of SPIs fields.

   The payload type for the Delete Payload is twelve (12).
*/

struct _rhp_proto_ikev1_d_payload {

	u8 next_payload;

	u8 reserved;

	u16 len;

	u32 doi;

	u8 protocol_id;

	u8 spi_len;

	u16 spi_num;

	/* SPI value(s) */
};
typedef struct _rhp_proto_ikev1_d_payload	rhp_proto_ikev1_d_payload;


/*

 3.16 Vendor ID Payload

   The Vendor ID Payload contains a vendor defined constant.  The
   constant is used by vendors to identify and recognize remote
   instances of their implementations.  This mechanism allows a vendor
   to experiment with new features while maintaining backwards
   compatibility.  This is not a general extension facility of ISAKMP.
   Figure 17 shows the format of the Vendor ID Payload.

   The Vendor ID payload is not an announcement from the sender that it
   will send private payload types.  A vendor sending the Vendor ID MUST
   not make any assumptions about private payloads that it may send
   unless a Vendor ID is received as well.  Multiple Vendor ID payloads
   MAY be sent.  An implementation is NOT REQUIRED to understand any
   Vendor ID payloads.  An implementation is NOT REQUIRED to send any
   Vendor ID payload at all.  If a private payload was sent without
   prior agreement to send it, a compliant implementation may reject a
   proposal with a notify message of type INVALID-PAYLOAD-TYPE.

   If a Vendor ID payload is sent, it MUST be sent during the Phase 1
   negotiation.  Reception of a familiar Vendor ID payload in the Phase
   1 negotiation allows an implementation to make use of Private USE
   payload numbers (128-255), described in section 3.1 for vendor
   specific extensions during Phase 2 negotiations.  The definition of
   "familiar" is left to implementations to determine.  Some vendors may
   wish to implement another vendor's extension prior to
   standardization.  However, this practice SHOULD not be widespread and
   vendors should work towards standardization instead.

   The vendor defined constant MUST be unique.  The choice of hash and
   text to hash is left to the vendor to decide.  As an example, vendors
   could generate their vendor id by taking a plain (non-keyed) hash of
   a string containing the product name, and the version of the product.

   A hash is used instead of a vendor registry to avoid local
   cryptographic policy problems with having a list of "approved"
   products, to keep away from maintaining a list of vendors, and to
   allow classified products to avoid having to appear on any list.  For
   instance:

   "Example Company IPsec.  Version 97.1"

   (not including the quotes) has MD5 hash:
   48544f9b1fe662af98b9b39e50c01a5a, when using MD5file.  Vendors may
   include all of the hash, or just a portion of it, as the payload
   length will bound the data.  There are no security implications of
   this hash, so its choice is arbitrary.

                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     ! Next Payload  !   RESERVED    !         Payload Length        !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !                                                               !
     ~                        Vendor ID (VID)                        ~
     !                                                               !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


                Figure 17:  Vendor ID Payload Format

   The Vendor ID Payload fields are defined as follows:

    o  Next Payload (1 octet) - Identifier for the payload type of the
       next payload in the message.  If the current payload is the last
       in the message, then this field will be 0.

    o  RESERVED (1 octet) - Unused, set to 0.

    o  Payload Length (2 octets) - Length in octets of the current
       payload, including the generic payload header.

    o  Vendor ID (variable length) - Hash of the vendor string plus
       version (as described above).

   The payload type for the Vendor ID Payload is thirteen (13).

*/

struct _rhp_proto_ikev1_vid_payload {

	u8 next_payload;

	u8 reserved;

	u16 len;

	/* Vendor ID value */
};
typedef struct _rhp_proto_ikev1_vid_payload	rhp_proto_ikev1_vid_payload;


/*

 - RFC 3947 Negotiation of NAT-Traversal in the IKE

3.1.  Detecting Support of NAT-Traversal

   The NAT-Traversal capability of the remote host is determined by an
   exchange of vendor ID payloads.  In the first two messages of Phase
   1, the vendor id payload for this specification MUST be sent if
   supported (and it MUST be received by both sides) for the NAT-
   Traversal probe to continue. The content of the payload is the MD5
   hash of

      RFC 3947

   The exact content in hex for the payload is

      4a131c81070358455c5728f20e95452f


3.2.  Detecting the Presence of NAT

   The NAT-D payload not only detects the presence of NAT between the
   two IKE peers, but also detects where the NAT is.  The location of
   the NAT device is important, as the keepalives have to initiate from
   the peer "behind" the NAT.

   To detect NAT between the two hosts, we have to detect whether the IP
   address or the port changes along the path.  This is done by sending
   the hashes of the IP addresses and ports of both IKE peers from each
   end to the other.  If both ends calculate those hashes and get same
   result, they know there is no NAT between.  If the hashes do not
   match, somebody has translated the address or port.  This means that
   we have to do NAT-Traversal to get IPsec packets through.

   If the sender of the packet does not know his own IP address (in case
   of multiple interfaces, and the implementation does not know which IP
   address is used to route the packet out), the sender can include
   multiple local hashes to the packet (as separate NAT-D payloads).  In
   this case, NAT is detected if and only if none of the hashes match.

   The hashes are sent as a series of NAT-D (NAT discovery) payloads.
   Each payload contains one hash, so in case of multiple hashes,
   multiple NAT-D payloads are sent.  In the normal case there are only
   two NAT-D payloads.

   The NAT-D payloads are included in the third and fourth packets of
   Main Mode, and in the second and third packets in the Aggressive
   Mode.

   The format of the NAT-D packet is

        1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
      +---------------+---------------+---------------+---------------+
      | Next Payload  | RESERVED      | Payload length                |
      +---------------+---------------+---------------+---------------+
      ~                 HASH of the address and port                  ~
      +---------------+---------------+---------------+---------------+

   The payload type for the NAT discovery payload is 20.

   The HASH is calculated as follows:

         HASH = HASH(CKY-I | CKY-R | IP | Port)

   This uses the negotiated HASH algorithm.  All data inside the HASH is
   in the network byte-order.  The IP is 4 octets for an IPv4 address
   and 16 octets for an IPv6 address.  The port number is encoded as a 2
   octet number in network byte-order.  The first NAT-D payload contains
   the remote end's IP address and port (i.e., the destination address
   of the UDP packet).  The remaining NAT-D payloads contain possible
   local-end IP addresses and ports (i.e., all possible source addresses
   of the UDP packet).

   If there is no NAT between the peers, the first NAT-D payload
   received should match one of the local NAT-D payloads (i.e., the
   local NAT-D payloads this host is sending out), and one of the other
   NAT-D payloads must match the remote end's IP address and port.  If
   the first check fails (i.e., first NAT-D payload does not match any
   of the local IP addresses and ports), it means that there is dynamic
   NAT between the peers, and this end should start sending keepalives
   as defined in the [RFC3948] (this end is behind the NAT).

   The CKY-I and CKY-R are the initiator and responder cookies.  They
   are added to the hash to make precomputation attacks for the IP
   address and port impossible.

   The following example is of a Phase 1 exchange using NAT-Traversal in
   Main Mode (authentication with signatures):

   Initiator                           Responder
   ------------                        ------------
   HDR, SA, VID -->
                                       <-- HDR, SA, VID
   HDR, KE, Ni, NAT-D, NAT-D -->
                                       <-- HDR, KE, Nr, NAT-D, NAT-D
   HDR*#, IDii, [CERT, ] SIG_I -->
                                       <-- HDR*#, IDir, [CERT, ], SIG_R

   The following example is of Phase 1 exchange using NAT-Traversal in
   Aggressive Mode (authentication with signatures):

   Initiator                           Responder
   ------------                        ------------
   HDR, SA, KE, Ni, IDii, VID -->
                                       <-- HDR, SA, KE, Nr, IDir,
                                               [CERT, ], VID, NAT-D,
                                               NAT-D, SIG_R
   HDR*#, [CERT, ], NAT-D, NAT-D,
       SIG_I -->

   The # sign indicates that those packets are sent to the changed port
   if NAT is detected.
*/


struct _rhp_proto_ikev1_nat_d_payload {

	u8 next_payload;

	u8 reserved;

	u16 len;

	/* Hash of the adderss and port */
};
typedef struct _rhp_proto_ikev1_nat_d_payload	rhp_proto_ikev1_nat_d_payload;


/*

  5.  Quick Mode

   After Phase 1, both ends know whether there is a NAT present between
   them.  The final decision of using NAT-Traversal is left to Quick
   Mode.  The use of NAT-Traversal is negotiated inside the SA payloads
   of Quick Mode.  In Quick Mode, both ends can also send the original
   addresses of the IPsec packets (in case of the transport mode) to the
   other end so that each can fix the TCP/IP checksum field after the
   NAT transformation.

  5.1.  Negotiation of the NAT-Traversal Encapsulation

   The negotiation of the NAT-Traversal happens by adding two new
   encapsulation modes.  These encapsulation modes are

   UDP-Encapsulated-Tunnel         3
   UDP-Encapsulated-Transport      4

   It is not normally useful to propose both normal tunnel or transport
   mode and UDP-Encapsulated modes.  UDP encapsulation is required to
   fix the inability to handle non-UDP/TCP traffic by NATs (see
   [RFC3715], section 2.2, case i).

   If there is a NAT box between hosts, normal tunnel or transport
   encapsulations may not work.  In this case, UDP-Encapsulation SHOULD
   be used.

   If there is no NAT box between, there is no point in wasting
   bandwidth by adding UDP encapsulation of packets.  Thus, UDP-
   Encapsulation SHOULD NOT be used.

   Also, the initiator SHOULD NOT include both normal tunnel or
   transport mode and UDP-Encapsulated-Tunnel or UDP-Encapsulated-
   Transport in its proposals.

  5.2.  Sending the Original Source and Destination Addresses

   To perform incremental TCP checksum updates, both peers may need to
   know the original IP addresses used by their peers when those peers
   constructed the packet (see [RFC3715], section 2.1, case b).  For the
   initiator, the original Initiator address is defined to be the
   Initiator's IP address.  The original Responder address is defined to
   be the perceived peer's IP address.  For the responder, the original
   Initiator address is defined to be the perceived peer's address.  The
   original Responder address is defined to be the Responder's IP
   address.

   The original addresses are sent by using NAT-OA (NAT Original
   Address) payloads.

   The Initiator NAT-OA payload is first.  The Responder NAT-OA payload
   is second.

   Example 1:

         Initiator <---------> NAT <---------> Responder
                  ^               ^           ^
                Iaddr           NatPub      Raddr

   The initiator is behind a NAT talking to the publicly available
   responder.  Initiator and Responder have the IP addresses Iaddr and
   Raddr.  NAT has public IP address NatPub.

   Initiator:

                     NAT-OAi = Iaddr
                     NAT-OAr = Raddr

   Responder:
                     NAT-OAi = NATPub
                     NAT-OAr = Raddr

   Example 2:

         Initiator <------> NAT1 <---------> NAT2 <-------> Responder
                  ^             ^           ^              ^
                Iaddr        Nat1Pub     Nat2Pub         Raddr

   Here, NAT2 "publishes" Nat2Pub for Responder and forwards all traffic
   to that address to Responder.

   Initiator:
                     NAT-OAi = Iaddr
                     NAT-OAr = Nat2Pub

   Responder:
                     NAT-OAi = Nat1Pub
                     NAT-OAr = Raddr

   In the case of transport mode, both ends MUST send both original
   Initiator and Responder addresses to the other end.  For tunnel mode,
   both ends SHOULD NOT send original addresses to the other end.

   The NAT-OA payloads are sent inside the first and second packets of
   Quick Mode.  The initiator MUST send the payloads if it proposes any
   UDP-Encapsulated-Transport mode, and the responder MUST send the
   payload only if it selected UDP-Encapsulated-Transport mode.  It is
   possible that the initiator sends the NAT-OA payload but proposes
   both UDP-Encapsulated transport and tunnel mode.  Then the responder
   selects the UDP-Encapsulated tunnel mode and does not send the NAT-OA
   payload back.

   The format of the NAT-OA packet is

         1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
       +---------------+---------------+---------------+---------------+
       | Next Payload  | RESERVED      | Payload length                |
       +---------------+---------------+---------------+---------------+
       | ID Type       | RESERVED      | RESERVED                      |
       +---------------+---------------+---------------+---------------+
       |           IPv4 (4 octets) or IPv6 address (16 octets)         |
       +---------------+---------------+---------------+---------------+

   The payload type for the NAT original address payload is 21.

   The ID type is defined in the [RFC2407].  Only ID_IPV4_ADDR and
   ID_IPV6_ADDR types are allowed.  The two reserved fields after the ID
   Type must be zero.

   The following example is of Quick Mode using NAT-OA payloads:

   Initiator                           Responder
   ------------                        ------------
   HDR*, HASH(1), SA, Ni, [, KE]
       [, IDci, IDcr ]
       [, NAT-OAi, NAT-OAr] -->
                                       <-- HDR*, HASH(2), SA, Nr, [, KE]
                                                 [, IDci, IDcr ]
                                                 [, NAT-OAi, NAT-OAr]
   HDR*, HASH(3) -->

 */

struct _rhp_proto_ikev1_nat_oa_payload {

	u8 next_payload;

	u8 reserved;

	u16 len;

	u8 id_type;

	u8 reserved1;
	u16 reserved2;

	/* IPv4(4 bytes) or IPv6(16 bytes) address */
};
typedef struct _rhp_proto_ikev1_nat_oa_payload	rhp_proto_ikev1_nat_oa_payload;


/*

 - The ISAKMP Configuration Method (draft-dukes-ike-mode-cfg-02)

3.2. Attribute Payload

   A new payload is defined to carry attributes as well as the type of
   transaction message.

                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     ! Next Payload  !   RESERVED    !         Payload Length        !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !     Type      !   RESERVED    !           Identifier          !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !                                                               !
     ~                           Attributes                          ~
     !                                                               !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   The Attributes Payload fields are defined as follows:

   o Next Payload (1 octet) - Identifier for the payload type of the
   next payload in the message.  If the current payload is the last in
   the message, then this field will be 0.

   o RESERVED (1 octet) - Unused, set to 0.

   o Payload Length (2 octets) - Length in octets of the current
   payload, including the generic payload header, the transaction-
   specific header and all attributes.  If the length does not match
   the length of the payload headers plus the attributes, (i.e. an
   attribute is half contained within this payload) then entire payload
   MUST be discarded.

   o Attribute Message Type (1 octet) - Specifies the type of message
   represented by the attributes.  These are defined in the next
   section.

   o RESERVED (1 octet) - Unused, set to 0.

   o Identifier (2 octets) - An identifier used to reference a
   configuration transaction within the individual messages.

   o Attributes (variable length) - Zero or more ISAKMP Data Attributes
   as defined in [ISAKMP].  The attribute types are defined in a later
   section.

   The payload type for the Attributes Payload is 14.


3.3. Configuration Message Types

   These values are to be used within the Type field of an Attribute
   ISAKMP payload.

    Types                      Value
   ========================== ===========
    RESERVED                   0
    ISAKMP_CFG_REQUEST         1
    ISAKMP_CFG_REPLY           2
    ISAKMP_CFG_SET             3
    ISAKMP_CFG_ACK             4
    Reserved for Future Use    5-127
    Reserved for Private Use   128-255

   Messages with unknown types SHOULD be silently discarded.


3.4. Configuration Attributes

   Zero or more ISAKMP attributes [ISAKMP] are contained within an
   Attributes Payload. Zero length attribute values are usually sent in
   a Request and MUST NOT be sent in a Response.

   All IPv6 specific attributes are mandatory only if the
   implementation supports IPv6 and vice versa for IPv4.  Mandatory
   attributes are stated below.

   Unknown private attributes SHOULD be silently discarded.

   The following attributes are currently defined:

    Attribute                 Value   Type       Length
   ========================= ======= ========== =====================
    RESERVED                    0
    INTERNAL_IP4_ADDRESS        1     Variable   0 or 4 octets
    INTERNAL_IP4_NETMASK        2     Variable   0 or 4 octets
    INTERNAL_IP4_DNS            3     Variable   0 or 4 octets
    INTERNAL_IP4_NBNS           4     Variable   0 or 4 octets
    INTERNAL_ADDRESS_EXPIRY     5     Variable   0 or 4 octets
    INTERNAL_IP4_DHCP           6     Variable   0 or 4 octets
    APPLICATION_VERSION         7     Variable   0 or more
    INTERNAL_IP6_ADDRESS        8     Variable   0 or 16 octets
    INTERNAL_IP6_NETMASK        9     Variable   0 or 16 octets
    INTERNAL_IP6_DNS           10     Variable   0 or 16 octets
    INTERNAL_IP6_NBNS          11     Variable   0 or 16 octets
    INTERNAL_IP6_DHCP          12     Variable   0 or 16 octets
    INTERNAL_IP4_SUBNET        13     Variable   0 or 8 octets
    SUPPORTED_ATTRIBUTES       14     Variable   0 or multiples of 2
    INTERNAL_IP6_SUBNET        15     Variable   0 or 17 octets
    Reserved for future use    16-16383
    Reserved for private use   16384-32767

   o INTERNAL_IP4_ADDRESS, INTERNAL_IP6_ADDRESS - Specifies an address
   within the internal network.  This address is sometimes called a red
   node address or a private address and MAY be a private address on
   the Internet.  Multiple internal addresses MAY be requested by
   requesting multiple internal address attributes.  The responder MAY
   only send up to the number of addresses requested.

   The requested address is valid until the expiry time defined with
   the INTERNAL_ADDRESS EXPIRY attribute or until the ISAKMP SA that
   was used to secure the request expires.  The address MAY also expire
   when the IPSec (phase 2) SA expires, if the request is associated
   with a phase 2 negotiation.  If no ISAKMP SA was used to secure the
   request, then the response MUST include an
   expiry or the host MUST expire the SA after an implementation-
   defined time.

   An implementation MUST support this attribute.

   o INTERNAL_IP4_NETMASK, INTERNAL_IP6_NETMASK - The internal
   network's netmask.  Only one netmask is allowed in the request and
   reply messages (e.g. 255.255.255.0) and it MUST be used only with an
   INTERNAL_ADDRESS attribute.

   An implementation MUST support this attribute.

   o INTERNAL_IP4_DNS, INTERNAL_IP6_DNS - Specifies an address of a DNS
   server within the network.  Multiple DNS servers MAY be requested.
   The responder MAY respond with zero or more DNS server attributes.

   o INTERNAL_IP4_NBNS, INTERNAL_IP6_NBNS - Specifies an address of a
   NetBios Name Server (WINS) within the network.  Multiple NBNS
   servers MAY be requested.  The responder MAY respond with zero or
   more NBNS server attributes.

   o INTERNAL_ADDRESS_EXPIRY - Specifies the number of seconds that the
   host can use the internal IP address.  The host MUST renew the IP
   address before this expiry time.  Only one attribute MAY be present
   in the reply.

   An implementation MUST support this attribute.

   o INTERNAL_IP4_DHCP, INTERNAL_IP6_DHCP - Instructs the host to send
   any internal DHCP requests to the address contained within the
   attribute.  Multiple DHCP servers MAY be requested.  The responder
   MAY respond with zero or more DHCP server attributes.

   o APPLICATION_VERSION - The version or application information of
   the IPSec host.  This is a string of printable ASCII characters that
   is NOT null terminated.

   This attribute does not need to be secured.

   An implementation MUST support this attribute.

   o INTERNAL_IP4_SUBNET - The protected sub-networks that this edge-
   device protects.  This attribute is made up of two fields; the first
   being an IP address and the second being a netmask.  Multiple sub-
   networks MAY be requested.  The responder MAY  respond with zero or
   more sub-network attributes.

   An implementation MUST support this attribute.

   o SUPPORTED_ATTRIBUTES - When used within a Request, this attribute
   must be zero length and specifies a query to the responder to reply
   back with all of the attributes that it supports.  The response
   contains an attribute that contains a set of attribute identifiers
   each in 2 octets.  The length divided by 2 (bytes) would state the
   number of supported attributes contained in the response.

   An implementation MUST support this attribute.

   o INTERNAL_IP6_SUBNET - The protected sub-networks that this edge-
   device protects.  This attribute is made up of two fields; the first
   being a 16 octet IPv6 address the second being a one octet prefix-
   mask as defined in [ADDRIPV6].  Multiple sub-networks MAY be

   requested.  The responder MAY respond with zero or more sub-network
   attributes.

   An implementation MUST support this attribute.

   Note that no recommendations are made in this document how an
   implementation actually figures out what information to send in a
   reply.  i.e. we do not recommend any specific method of (an edge
   device) determining which DNS server should be returned to a
   requesting host.

*/

/*

 - Extended Authentication within IKE (XAUTH)(draft-beaulieu-ike-xauth-02)

6 Extensions to ISAKMP-Config

   This protocol uses the mechanisms described in ISAKMP-Config
   [IKECFG] to accomplish its authentication transaction.  This
   protocol uses Configuration Attributes from the private range of
   Isakmp-Config [IKECFG].  To ensure interoperability with past and
   future versions of Extended Authentication, a Vendor ID is provided
   in section 2.

   All ISAKMP-Config messages in an extended authentication transaction
   MUST contain the same ISAKMP-Config transaction identifier.  The
   Message ID in the ISAKMP header follows the rules defined by the
   ISAKMP-Config protocol.

   This protocol can therefore be used in conjunction with any existing
   basic ISAKMP authentication method as defined in [IKE].

   This authentication MUST be used after a phase 1 exchange has
   completed and before any other exchange with the exception of Info
   mode exchanges. If the extended authentication fails, then the phase
   1 SA MUST be immediately deleted.  The edge device MAY choose to
   retry an extended authentication request if the user failed to be
   authenticated, but must do so in the same ISAKMP-Config transaction,
   and MUST NOT send the SET message until the user is authenticated,
   or until the edge device wishes to stop retrying and fail the user.

   Extended Authentication MAY be initiated by the edge device at any
   time after the initial authentication exchange.  For example, RADIUS
   servers may specify that a user only be authenticated for a certain
   time period.  Once that time period has elapsed (minus a possible
   jitter), the edge device may request a new Extended Authentication
   exchange.  If the Extended Authentication exchange fails, the edge
   device MUST tear down all phase 1 and phase 2 SAs associated with
   the user.

   The following are extensions to the ISAKMP-Config [IKECFG]
   specification to support Extended Authentication.

6.1 Message Types

   Type                        Value
   --------------------------  -----------------------------
    ISAKMP-CFG-REQUEST         ( as defined in [IKECFG] )
    ISAKMP-CFG-REPLY           ( as defined in [IKECFG] )
    ISAKMP-CFG-SET             ( as defined in [IKECFG] )
    ISAKMP-CFG-ACK             ( as defined in [IKECFG] )

   ISAKMP-CFG-REQUEST - This message is sent from an edge device to an
   IPsec host trying to request extended authentication.  Attributes
   that it requires sent back in the reply MUST be included with a
   length of zero (0).  Attributes required for the authentication
   reply, such as a challenge string MUST be included with the proper
   values filled in.

   ISAKMP-CFG-REPLY - This message MUST contain the filled in
   authentication attributes that were requested by the edge device or
   if the proper authentication attributes can not be retrieved, then
   this message MUST contain the XAUTH-STATUS attribute with a value of
   FAIL.

   ISAKMP-CFG-SET - This message is sent from an edge device and is
   only used, within the scope of this document, to state the success
   of the authentication.  This message MUST only include the success
   of failure of the authentication and MAY contain some clarification
   text.

   ISAKMP-CFG-ACK - This message is sent from the IPsec host
   acknowledging receipt of the authentication result.  Its attributes
   are not relevant and MAY be skipped entirely, thus no attributes
   SHOULD be included.  This last message in the authentication
   transaction is used solely as an acknowledgement of the previous
   message and to eliminate problems with unacknowledged messages over
   UDP.

6.2 Attributes

    Attribute                 Value      Type
    ---------------------     ------     ---------------------
    XAUTH-TYPE                16520         Basic
    XAUTH-USER-NAME           16521         Variable ASCII string
    XAUTH-USER-PASSWORD       16522         Variable ASCII string
    XAUTH-PASSCODE            16523         Variable ASCII string
    XAUTH-MESSAGE             16524         Variable ASCII string
    XAUTH-CHALLENGE           16525         Variable ASCII string
    XAUTH-DOMAIN              16526         Variable ASCII string
    XAUTH-STATUS              16527         Basic
    XAUTH-NEXT-PIN            16528         Variable ASCII string
    XAUTH-ANSWER              16529         Variable ASCII string

   NOTE: Variable ASCII strings need not be NULL-terminated, as the
   length field in the attribute header is sufficient to properly
   format the strings.

   XAUTH-TYPE - The type of extended authentication requested whose
   values are described in the next section.  This is an optional
   attribute for the ISAKMP_CFG_REQUEST and ISAKMP_CFG_REPLY messages.
   If the XAUTH-TYPE is not present, then it is assumed to be Generic.
   The XAUTH-TYPE in a REPLY MUST be identical to the XAUTH-TYPE in the
   REQUEST.  If the XAUTH-TYPE was not present in the REQUEST, then it
   MUST NOT be present in the REPLY.  However, an XAUTH transaction MAY
   have multiple REQUEST/REPLY pairs with different XAUTH-TYPE values
   in each pair.

   XAUTH-USER-NAME - The user name MAY be any unique identifier of the
   user such as a login name, an email address, or a X.500
   Distinguished Name.

   XAUTH-USER-PASSWORD - The user's password.

   XAUTH-PASSCODE - A token card's passcode.

   XAUTH-MESSAGE - A textual message from an edge device to an IPsec
   host.  The message may contain a textual challenge or instruction.
   An example of this would be "Enter your password followed by your
   pin number".  The message may also contain a reason why
   authentication failed or succeeded.  This message SHOULD be
   displayed to the user.

   XAUTH-CHALLENGE - A challenge string sent from the edge device to
   the IPsec host for it to include in its calculation of a password.
   This attribute SHOULD only be sent in an ISAKMP-CFG-REQUEST message.
   Typically, the XAUTH-TYPE attribute dictates how the receiving
   device should handle the challenge.  For example, RADIUS-CHAP uses
   the challenge to hide the password.  The XAUTH-CHALLENGE attribute
   MUST NOT be used when XAUTH-TYPE is set to generic.

   XAUTH-DOMAIN - The domain to be authenticated in.  This value will
   have different meaning depending on the authentication type.

   XAUTH-STATUS - A variable that is used to denote authentication
   success (OK=1) or failure (FAIL=0).  This attribute MUST be sent in
   the ISAKMP-CFG-SET message, in which case it may be set to either OK
   or FAIL, and MAY be sent in a REPLY message by a remote peer, in
   which case it MUST be set to FAIL.

   XAUTH-NEXT-PIN - A variable which is used when the edge device is
   requesting that the user choose a new pin number.  This attribute
   MUST NOT be used in conjunction with any attributes other than
   XAUTH-MESSAGE and / or XAUTH-TYPE.

   XAUTH-ANSWER - A variable length ASCII string used to send input to
   the edge device.  An edge device MAY include this attribute in a
   REQUEST message in order to prompt an answer from the user, though
   it MUST be accompanied by an XAUTH-MESSAGE attribute. This attribute
   MUST NOT be used in conjunction with any attributes other than
   XAUTH-TYPE or XAUTH-MESSAGE.

6.3 Authentication Types

    Value         Authentication Required
    -----         ---------------------------------
       0           Generic
       1           RADIUS-CHAP
       2           OTP
       3           S/KEY
       4-32767     Reserved for future use
       32768-65535  Reserved for private use

   Generic - A catch-all type that allows for future extensibility and
   a generic mechanism to request authentication information. This
   method allows for any type of extended authentication which does not
   require specific processing, and should be used whenever possible.
   This is the default setting if no XAUTH_TYPE is present.

   RADIUS-CHAP - RADIUS-CHAP is one method of authentication defined in
   [RADIUS] which uses a challenge to hide the password.  In order to
   use the CHAP functionality defined in [RADIUS], the XAUTH_TYPE MUST
   be set to RADIUS-CHAP.  For all other methods defined in [RADIUS]
   (i.e. PAP), the XAUTH_TYPE MUST be set to Generic.

   OTP - One-Time-Passwords as defined in [OTP] uses a challenge string
   to request a certain generated password.  The request SHOULD contain
   a user name, password and a challenge string while the reply MUST
   contain the user name and the generated password.  The challenge
   string is formatted as defined in [OTPEXT].
   S/KEY - This one-time-password scheme defined in [SKEY] was the
   precursor to OTP, thus the same rules applies.
*/

struct _rhp_proto_ikev1_attribute_payload {

	u8 next_payload;

	u8 reserved;

	u16 len;

#define RHP_PROTO_IKEV1_CFG_REQUEST		1
#define RHP_PROTO_IKEV1_CFG_REPLY     2
#define RHP_PROTO_IKEV1_CFG_SET       3
#define RHP_PROTO_IKEV1_CFG_ACK       4
	u8 type;

	u8 reserved1;
	u16 id;

#define RHP_PROTO_IKEV1_CFG_ATTR_RESERVED									0
#define RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_ADDRESS			1
#define RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_NETMASK			2
#define RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_DNS					3
#define RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_NBNS				4
#define RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_ADDRESS_EXPIRY	5
#define RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_DHCP				6
#define RHP_PROTO_IKEV1_CFG_ATTR_APPLICATION_VERSION			7
#define RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_ADDRESS			8
#define RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_NETMASK			9
#define RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_DNS					10
#define RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_NBNS				11
#define RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_DHCP				12
#define RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_SUBNET			13
#define RHP_PROTO_IKEV1_CFG_ATTR_SUPPORTED_ATTRIBUTES			14
#define RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_SUBNET			15

#define RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_TYPE								16520
#define RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_USER_NAME          16521
#define RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_USER_PASSWORD      16522
#define RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_PASSCODE           16523
#define RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_MESSAGE            16524
#define RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_CHALLENGE          16525
#define RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_DOMAIN             16526
#define RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_STATUS             16527
#define RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_NEXT_PIN           16528
#define RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_ANSWER             16529


#define RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_TYPE_GENERIC				0
#define RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_TYPE_RADIUS_CHAP		1
#define RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_TYPE_OTP						2
#define RHP_PROTO_IKEV1_CFG_ATTR_XAUTH_TYPE_SKEY					3

	/* Attributes: rhp_proto_ikev1_attr(s) */
};
typedef struct _rhp_proto_ikev1_attribute_payload	rhp_proto_ikev1_attribute_payload;


#pragma pack()

#endif // _RHP_PROTOCOL_H_


