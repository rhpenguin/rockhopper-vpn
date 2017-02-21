/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifndef _RHP_EOIP_H_
#define _RHP_EOIP_H_

extern int rhp_eoip_send(rhp_vpn* tx_vpn,rhp_packet* pkt);

extern int rhp_eoip_send_flooding(unsigned long rlm_id,rhp_packet* pkt,
		rhp_vpn* rx_vpn,int dont_fwd_pkts_btwn_clts);

extern int rhp_eoip_send_access_point(rhp_vpn_realm* tx_rlm,rhp_packet* pkt);

extern int rhp_eoip_recv(rhp_packet* pkt,rhp_vpn* rx_vpn);

extern int rhp_eoip_check_header(rhp_proto_etherip* ethiph);

#endif // _RHP_EOIP_H_

