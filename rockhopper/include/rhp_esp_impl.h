/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


//
// librhpesp.so
//

#ifndef _RHP_ESP_IMPL_H_
#define _RHP_ESP_IMPL_H_

#include "rhp_vpn.h"

extern int rhp_esp_impl_init();
extern void rhp_esp_impl_cleanup();

extern void* rhp_esp_impl_childsa_init(rhp_vpn* vpn,rhp_vpn_realm* rlm,u32 spi_inb,u32 spi_outb);
extern void rhp_esp_impl_childsa_cleanup(void* impl_ctx);


extern int rhp_esp_impl_enc_packet(rhp_packet* pkt,rhp_vpn* tx_vpn,
		rhp_vpn_realm* rlm,u32 spi_outb,void* pend_ctx);

extern int rhp_esp_impl_dec_packet(rhp_packet* pkt,rhp_vpn* rx_vpn,
		rhp_vpn_realm* rlm,u32 spi_inb,u8* next_header,void* pend_ctx);

#endif // _RHP_ESP_IMPL_H_

