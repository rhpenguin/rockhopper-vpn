/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifndef _RHP_DNS_PXY_H_
#define _RHP_DNS_PXY_H_


#define RHP_DNS_PXY_MAX_DNS_SERVERS		3


struct _rhp_ifc_entry;
struct _rhp_packet;

extern int rhp_dns_pxy_main_start(int addr_family);
extern void rhp_dns_pxy_main_end(int addr_family);

extern int rhp_dns_pxy_main_handle_event(struct epoll_event* epoll_evt);

extern void rhp_dns_pxy_exec_gc();

extern void rhp_dns_pxy_inc_users();
extern int rhp_dns_pxy_dec_and_test_users();
extern int rhp_dns_pxy_get_users();

extern int rhp_dns_pxy_resolv_conf_info(int addr_family,rhp_ip_addr* addrs_r,int* addrs_num_r);

#endif // _RHP_DNS_PXY_H_
