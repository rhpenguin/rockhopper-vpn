/*

	Copyright (C) 2015-2016 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/

//
// librhppcap.so
//

#ifndef _RHP_PCAP_H_
#define _RHP_PCAP_H_


struct _rhp_pcap_cfg {
	
	char* file_name;

	unsigned long max_packets;

	unsigned long max_bytes; // bytes

	time_t capture_interval; // secs
};
typedef struct _rhp_pcap_cfg rhp_pcap_cfg;


struct _rhp_pcap_status {

	int is_active;

	unsigned long captured_bytes;
	unsigned long captured_packets;

	time_t expire_time;
	time_t elapsed_time;

	int capture_finished;
};
typedef struct _rhp_pcap_status	rhp_pcap_status;


extern int rhp_pcap_init(time_t timer_check_interval,
		void (*timer_update_cb)(rhp_pcap_status* status,void* ctx),void* ctx);
extern int rhp_pcap_cleanup();

extern int rhp_pcap_start(rhp_pcap_cfg* cap_cfg);
extern int rhp_pcap_stop();
extern void rhp_pcap_get_status(rhp_pcap_status* status_r);

extern int rhp_pcap_write(int pkt_len,u8* pkt_head,int dmy_l23_hdr_len,u8* dmy_l23_hdr);
extern int rhp_pcap_write_pkt(rhp_packet* pkt);


#endif // _RHP_PCAP_H_
