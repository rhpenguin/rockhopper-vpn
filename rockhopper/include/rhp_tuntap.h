/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifndef _RHP_TUNTAP_H_
#define _RHP_TUNTAP_H_

struct epoll_event;
struct _rhp_packet;
struct _rhp_ifc_entry;

extern int rhp_tuntap_init();

extern int rhp_tuntap_handle_event(struct epoll_event* epoll_evt);

extern int rhp_tuntap_write(struct _rhp_ifc_entry* v_ifc,struct _rhp_packet* pkt);

extern void rhp_tuntap_close(struct _rhp_ifc_entry* v_ifc);


#define RHP_TUNTAP_EPOLL_IFC(epoll_ctx) ((epoll_ctx)->params[0])

extern void rhp_tuntap_dmy_pkt_read(unsigned long rlm_id,u8 protocol,u8* src_mac,u8* dst_mac,
		rhp_ip_addr* src_ip_addr,rhp_ip_addr* dst_ip_addr,unsigned int data_len,u64 esp_tx_seq);


#endif // _RHP_TUNTAP_H_



