/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifndef _RHP_NETSOCK_H_
#define _RHP_NETSOCK_H_

struct epoll_event;

extern int rhp_netsock_init();

extern int rhp_netsock_handle_event(struct epoll_event* epoll_evt);

extern int rhp_netsock_open(rhp_ifc_entry *ifc,rhp_ifc_addr* ifc_addr);
extern void rhp_netsock_close(rhp_ifc_entry *ifc,rhp_ifc_addr* ifc_addr);
extern int rhp_netsock_send(rhp_ifc_entry* ifc,rhp_packet* pkt);

extern int rhp_netsock_check_and_open_all(rhp_ifc_entry *ifc,int addr_family);
extern void rhp_netsock_close_all(rhp_ifc_entry *ifc,int addr_family);


#define RHP_NETSOCK_EPOLL_IFC(epoll_ctx) ((epoll_ctx)->params[0])				// (rhp_ifc_entry*)
#define RHP_NETSOCK_EPOLL_IFC_ADDR(epoll_ctx) ((epoll_ctx)->params[1])	// (rhp_ifc_addr*)

extern int rhp_netsock_rx_dispach_packet(rhp_packet *pkt);


struct _rhp_netsock_stat {

	int rx_cur_buffer_size;
	int rx_ike_cur_buffer_size;
	int rx_def_pkt_size_cnt;

	long max_rx_pkt_ike_sk;
	long max_rx_pkt_esp_sk;
	long max_rx_pkt_ike_natt_sk;
};
typedef struct _rhp_netsock_stat rhp_netsock_stat;

extern void rhp_netsock_get_stat(rhp_netsock_stat* netsock_stat);


#endif // _RHP_NETSOCK_H_
