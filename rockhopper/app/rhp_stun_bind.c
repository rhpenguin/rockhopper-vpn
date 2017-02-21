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
#include "rhp_crypto.h"
#include "rhp_stun.h"


int rhp_stun_bind_tx_new_req_mesg(rhp_stun_mesg** stun_req_r)
{
	int err = -EINVAL;
	rhp_stun_mesg* stun_req = NULL;

  RHP_TRC(0,RHPTRCID_STUN_BIND_TX_NEW_REQ_MESG,"x",stun_req_r);

	stun_req = rhp_stun_mesg_new_tx(RHP_PROTO_STUN_CLASS_REQ,RHP_PROTO_STUN_METHOD_BIND,NULL);
	if( stun_req ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	*stun_req_r = stun_req;

  RHP_TRC(0,RHPTRCID_STUN_BIND_TX_NEW_REQ_MESG_RTRN,"xx",stun_req_r,*stun_req_r);
	return 0;

error:
	if( stun_req ){
		rhp_stun_mesg_free(stun_req);
	}
  RHP_TRC(0,RHPTRCID_STUN_BIND_TX_NEW_REQ_MESG_ERR,"xE",stun_req_r,err);
	return err;
}


int rhp_stun_bind_tx_new_resp_mesg(rhp_stun_mesg* rx_stun_req, rhp_ip_addr* mapped_addr, rhp_stun_mesg** tx_stun_resp_r)
{
	int err = -EINVAL;
	rhp_stun_mesg* stun_resp = NULL;
	u8* txn_id;
	rhp_ip_addr maddr_tmp;

  RHP_TRC(0,RHPTRCID_STUN_BIND_TX_NEW_RESP_MESG,"xxx",rx_stun_req,mapped_addr,tx_stun_resp_r);
	rhp_ip_addr_dump("rhp_stun_bind_tx_new_resp_mesg: mapped_addr",mapped_addr);

	memcpy(&maddr_tmp,mapped_addr,sizeof(rhp_ip_addr));

	txn_id =   rx_stun_req->get_mesg_txnid(rx_stun_req);
	if( txn_id == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	stun_resp = rhp_stun_mesg_new_tx(RHP_PROTO_STUN_CLASS_RESP,RHP_PROTO_STUN_METHOD_BIND,txn_id);
	if( stun_resp ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	err = rhp_stun_mesg_attr_xor_addr(&maddr_tmp,txn_id);
	if( err ){
		goto error;
	}

	err = stun_resp->put_attr_mapped_addr(stun_resp,&maddr_tmp,1);
	if( err ){
		goto error;
	}

	*tx_stun_resp_r = stun_resp;

  RHP_TRC(0,RHPTRCID_STUN_BIND_TX_NEW_RESP_MESG_RTRN,"xx",rx_stun_req,*tx_stun_resp_r);
	return 0;

error:
	if( stun_resp ){
		rhp_stun_mesg_free(stun_resp);
	}
  RHP_TRC(0,RHPTRCID_STUN_BIND_TX_NEW_RESP_MESG_ERR,"xE",rx_stun_req,err);
	return err;
}


int rhp_stun_bind_resp_attr_mapped_addr(rhp_stun_mesg* stun_resp,rhp_ip_addr** mapped_addr_r)
{
	int err = -EINVAL;
	rhp_ip_addr* mapped_addr = NULL;

  RHP_TRC(0,RHPTRCID_STUN_BIND_RESP_ATTR_MAPPED_ADDR,"xx",stun_resp,mapped_addr_r);

	mapped_addr = stun_resp->get_attr_mapped_addr(stun_resp);
	if( mapped_addr == NULL ){
		goto error;
	}

	*mapped_addr_r = mapped_addr;

  RHP_TRC(0,RHPTRCID_STUN_BIND_RESP_ATTR_MAPPED_ADDR_RTRN,"xx",stun_resp,*mapped_addr_r);
	rhp_ip_addr_dump("rhp_stun_bind_resp_attr_mapped_addr: mapped_addr_r",*mapped_addr_r);
	return 0;

error:
	if( mapped_addr ){
		_rhp_free(mapped_addr);
	}
  RHP_TRC(0,RHPTRCID_STUN_BIND_RESP_ATTR_MAPPED_ADDR_ERR,"xE",stun_resp,err);
	return err;
}

