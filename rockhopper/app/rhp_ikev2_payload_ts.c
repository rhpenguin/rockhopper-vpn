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
#include "rhp_ikesa.h"
#include "rhp_ikev2_mesg.h"
#include "rhp_childsa.h"

static void _rhp_ikev2_ts_payload_set_ts_type(rhp_ikev2_traffic_selector* ts,u8 ts_type)
{
  ts->ts_type = ts_type;
  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_SET_TS_TYPE,"xLb",ts,"PROTO_IKE_TS",ts_type);
  return;
}

static u8 __rhp_ikev2_ts_payload_get_ts_type(rhp_ikev2_traffic_selector* ts)
{
  u8 ret;
  if( ts->tsh ){
    ret = ts->tsh->ts_type;
  }else{
    ret = ts->ts_type;
  }

  return ret;
}

static u8 _rhp_ikev2_ts_payload_get_ts_type(rhp_ikev2_traffic_selector* ts)
{
  u8 ret = __rhp_ikev2_ts_payload_get_ts_type(ts);
  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_GET_TS_TYPE,"xLb",ts,"PROTO_IKE_TS",ret);
  return ret;
}

static void _rhp_ikev2_ts_payload_set_protocol(rhp_ikev2_traffic_selector* ts,u8 protocol)
{
  ts->protocol = protocol;
  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_SET_PROTOCOL,"xLb",ts,"PROTO_IP",protocol);
  return;
}

static u8 __rhp_ikev2_ts_payload_get_protocol(rhp_ikev2_traffic_selector* ts)
{
  u8 ret;
  if( ts->tsh ){
    ret = ts->tsh->ip_protocol_id;
  }else{
    ret = ts->protocol;
  }
  return ret;
}

static u8 _rhp_ikev2_ts_payload_get_protocol(rhp_ikev2_traffic_selector* ts)
{
  u8 protocol = __rhp_ikev2_ts_payload_get_protocol(ts);
  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_GET_PROTOCOL,"xLb",ts,"PROTO_IP",protocol);
  return protocol;
}

static void _rhp_ikev2_ts_payload_set_start_port(rhp_ikev2_traffic_selector* ts,u16 start_port)
{
  ts->start_port = start_port;
  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_SET_START_PORT,"xW",ts,htons(start_port));
  return;
}

static u16 __rhp_ikev2_ts_payload_get_start_port(rhp_ikev2_traffic_selector* ts)
{
  u16 ret;
  if( ts->tsh ){
    ret = ts->tsh->start_port.port;
  }else{
    ret = ts->start_port;
  }

  return ret;
}

static u16 _rhp_ikev2_ts_payload_get_start_port(rhp_ikev2_traffic_selector* ts)
{
  u16 start_port = __rhp_ikev2_ts_payload_get_start_port(ts);
  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_GET_START_PORT,"xW",ts,start_port);
  return start_port;
}

static void _rhp_ikev2_ts_payload_set_end_port(rhp_ikev2_traffic_selector* ts,u16 end_port)
{
  ts->end_port = end_port;
  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_SET_END_PORT,"xW",ts,htons(end_port));
  return;
}

static u16 __rhp_ikev2_ts_payload_get_end_port(rhp_ikev2_traffic_selector* ts)
{
  u16 end_port;
  if( ts->tsh ){
  	end_port = ts->tsh->end_port.port;
  }else{
  	end_port = ts->end_port;
  }

  return end_port;
}

static u16 _rhp_ikev2_ts_payload_get_end_port(rhp_ikev2_traffic_selector* ts)
{
  u16 end_port = __rhp_ikev2_ts_payload_get_end_port(ts);
  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_GET_END_PORT,"xW",ts,end_port);
  return end_port;
}

static void _rhp_ikev2_ts_payload_set_icmp_start_type(rhp_ikev2_traffic_selector* ts,u8 start_type)
{
  ts->icmp_start_type = start_type;
  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_SET_ICMP_START_TYPE,"xb",ts,start_type);
  return;
}

static u8 __rhp_ikev2_ts_payload_get_icmp_start_type(rhp_ikev2_traffic_selector* ts)
{
  u8 start_type;
  if( ts->tsh ){
  	start_type = ts->tsh->start_port.icmp.type;
  }else{
  	start_type = ts->icmp_start_type;
  }

  return start_type;
}

static u8 _rhp_ikev2_ts_payload_get_icmp_start_type(rhp_ikev2_traffic_selector* ts)
{
  u8 start_type = __rhp_ikev2_ts_payload_get_icmp_start_type(ts);
  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_GET_ICMP_START_TYPE,"xb",ts,start_type);
  return start_type;
}

static void _rhp_ikev2_ts_payload_set_icmp_end_type(rhp_ikev2_traffic_selector* ts,u8 end_type)
{
  ts->icmp_end_type = end_type;
  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_SET_ICMP_END_TYPE,"xb",ts,end_type);
  return;
}

static u8 __rhp_ikev2_ts_payload_get_icmp_end_type(rhp_ikev2_traffic_selector* ts)
{
  u8 end_type;
  if( ts->tsh ){
  	end_type = ts->tsh->end_port.icmp.type;
  }else{
  	end_type = ts->icmp_end_type;
  }

  return end_type;
}

static u8 _rhp_ikev2_ts_payload_get_icmp_end_type(rhp_ikev2_traffic_selector* ts)
{
  u8 end_type = __rhp_ikev2_ts_payload_get_icmp_end_type(ts);
  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_GET_ICMP_END_TYPE,"xb",ts,end_type);
  return end_type;
}

static void _rhp_ikev2_ts_payload_set_icmp_start_code(rhp_ikev2_traffic_selector* ts,u8 start_code)
{
  ts->icmp_start_code = start_code;
  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_SET_ICMP_START_CODE,"xb",ts,start_code);
  return;
}

static u8 __rhp_ikev2_ts_payload_get_icmp_start_code(rhp_ikev2_traffic_selector* ts)
{
  u8 start_code;
  if( ts->tsh ){
  	start_code = ts->tsh->start_port.icmp.code;
  }else{
  	start_code = ts->icmp_start_code;
  }

  return start_code;
}

static u8 _rhp_ikev2_ts_payload_get_icmp_start_code(rhp_ikev2_traffic_selector* ts)
{
  u8 start_code = __rhp_ikev2_ts_payload_get_icmp_start_code(ts);
  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_GET_ICMP_START_CODE,"xb",ts,start_code);
  return start_code;
}

static void _rhp_ikev2_ts_payload_set_icmp_end_code(rhp_ikev2_traffic_selector* ts,u8 end_code)
{
  ts->icmp_end_code = end_code;
  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_SET_ICMP_END_CODE,"xb",ts,end_code);
  return;
}

static u8 __rhp_ikev2_ts_payload_get_icmp_end_code(rhp_ikev2_traffic_selector* ts)
{
  u8 end_code;
  if( ts->tsh ){
  	end_code = ts->tsh->end_port.icmp.code;
  }else{
  	end_code = ts->icmp_end_code;
  }

  return end_code;
}

static u8 _rhp_ikev2_ts_payload_get_icmp_end_code(rhp_ikev2_traffic_selector* ts)
{
  u8 end_code = __rhp_ikev2_ts_payload_get_icmp_end_code(ts);
  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_GET_ICMP_END_CODE,"xb",ts,end_code);
  return end_code;
}

static void _rhp_ikev2_ts_payload_set_start_addr(rhp_ikev2_traffic_selector* ts,rhp_ip_addr* start_addr)
{
  memcpy(&(ts->start_addr),start_addr,sizeof(rhp_ip_addr));
  rhp_ip_addr_dump("_rhp_ikev2_ts_payload_set_start_addr",start_addr);
  return;
}

static int __rhp_ikev2_ts_payload_get_start_addr(rhp_ikev2_traffic_selector* ts,rhp_ip_addr* start_addr_r)
{
  u8 ret = 0;

  memset(start_addr_r,0,sizeof(rhp_ip_addr));

  if( ts->tsh ){
    if( ts->tsh->ts_type == RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE ){
      start_addr_r->addr_family = AF_INET;
      start_addr_r->addr.v4 = *((u32*)(ts->tsh + 1));
    }else if( ts->tsh->ts_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){
      start_addr_r->addr_family = AF_INET6;
      memcpy(start_addr_r->addr.v6,((u8*)(ts->tsh + 1)),16);
    }else{
      ret = -EINVAL;
    }
  }else{
    memcpy(start_addr_r,&(ts->start_addr),sizeof(rhp_ip_addr));
    ret = 0;
  }

  return ret;
}

static int _rhp_ikev2_ts_payload_get_start_addr(rhp_ikev2_traffic_selector* ts,rhp_ip_addr* start_addr_r)
{
  u8 ret = __rhp_ikev2_ts_payload_get_start_addr(ts,start_addr_r);

  if( ret == 0 ){
  	rhp_ip_addr_dump("_rhp_ikev2_ts_payload_get_start_addr",start_addr_r);
  }else{
  	rhp_ip_addr_dump("_rhp_ikev2_ts_payload_get_start_addr ERROR!",start_addr_r);
  }
  return ret;
}

static void _rhp_ikev2_ts_payload_set_end_addr(rhp_ikev2_traffic_selector* ts,rhp_ip_addr* end_addr)
{
  memcpy(&(ts->end_addr),end_addr,sizeof(rhp_ip_addr));
  rhp_ip_addr_dump("_rhp_ikev2_ts_payload_set_end_addr",end_addr);
  return;
}

static int __rhp_ikev2_ts_payload_get_end_addr(rhp_ikev2_traffic_selector* ts,rhp_ip_addr* end_addr_r)
{
  u8 ret = 0;

  memset(end_addr_r,0,sizeof(rhp_ip_addr));

  if( ts->tsh ){
    if( ts->tsh->ts_type == RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE ){
      end_addr_r->addr_family = AF_INET;
      end_addr_r->addr.v4 = *((u32*)(((u8*)(ts->tsh + 1)) + sizeof(u32)));
    }else if( ts->tsh->ts_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){
      end_addr_r->addr_family = AF_INET6;
      memcpy(end_addr_r->addr.v6,((u8*)(((u8*)(ts->tsh + 1)) + 16)),16);
    }else{
      ret = -EINVAL;
    }
  }else{
    memcpy(end_addr_r,&(ts->end_addr),sizeof(rhp_ip_addr));
    ret = 0;
  }

  return ret;
}

static int _rhp_ikev2_ts_payload_get_end_addr(rhp_ikev2_traffic_selector* ts,rhp_ip_addr* end_addr_r)
{
  u8 ret = __rhp_ikev2_ts_payload_get_end_addr(ts,end_addr_r);

  if( ret == 0 ){
  	rhp_ip_addr_dump("_rhp_ikev2_ts_payload_get_end_addr",end_addr_r);
  }else{
  	rhp_ip_addr_dump("_rhp_ikev2_ts_payload_get_end_addr ERROR!",end_addr_r);
  }
  return ret;
}

static void _rhp_ikev2_ts_payload_dump_impl(rhp_ikev2_traffic_selector* ts_head,char* label,int dump2log,unsigned long rlm_id)
{
  u8 ts_type;
  u8 protocol;
  u16 start_port;
  u16 end_port;
  u8 icmp_start_type;
  u8 icmp_end_type;
  u8 icmp_start_code;
  u8 icmp_end_code;
  rhp_ip_addr start_addr;
  rhp_ip_addr end_addr;
  int i = 1;
	rhp_ikev2_traffic_selector* ts = ts_head;

	if( !dump2log ){
		_RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
	  if( !_RHP_TRC_COND(_rhp_trc_user_id(),0) ){
	  	return;
	  }
	}

	while( ts ){

		ts_type = __rhp_ikev2_ts_payload_get_ts_type(ts);

		protocol = __rhp_ikev2_ts_payload_get_protocol(ts);

		start_port = __rhp_ikev2_ts_payload_get_start_port(ts);
		end_port = __rhp_ikev2_ts_payload_get_end_port(ts);

		icmp_start_type = __rhp_ikev2_ts_payload_get_icmp_start_type(ts);
		icmp_end_type = __rhp_ikev2_ts_payload_get_icmp_end_type(ts);
		icmp_start_code = __rhp_ikev2_ts_payload_get_icmp_start_code(ts);
		icmp_end_code = __rhp_ikev2_ts_payload_get_icmp_end_code(ts);

		__rhp_ikev2_ts_payload_get_start_addr(ts,&start_addr);
		__rhp_ikev2_ts_payload_get_end_addr(ts,&end_addr);

		if( !dump2log ){
			RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_TS_DUMP,"sudLbLbWWbbbbd",label,rlm_id,i,"PROTO_IKE_TS",ts_type,"PROTO_IP",protocol,start_port,end_port,icmp_start_type,icmp_end_type,icmp_start_code,icmp_end_code,ts->is_pending);
			rhp_ip_addr_dump(label,&start_addr);
			rhp_ip_addr_dump(label,&end_addr);
		}else{
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,rlm_id,RHP_LOG_ID_DUMP_TS_PAYLOAD,"sLLWWbbbbAA",label,"PROTO_IKE_TS",ts_type,"PROTO_IP",protocol,start_port,end_port,icmp_start_type,icmp_end_type,icmp_start_code,icmp_end_code,&start_addr,&end_addr);
		}

	  i++;
	  ts = ts->next;
	}

	return;
}

static void _rhp_ikev2_ts_payload_dump(rhp_ikev2_traffic_selector* ts_head,char* label)
{
	_rhp_ikev2_ts_payload_dump_impl(ts_head,label,0,0);
}

static void _rhp_ikev2_ts_payload_dump_log(rhp_ikev2_traffic_selector* ts_head,char* label,unsigned long rlm_id)
{
	_rhp_ikev2_ts_payload_dump_impl(ts_head,label,1,rlm_id);
}

int rhp_ikev2_ts_payload_addr_is_included(rhp_ikev2_traffic_selector* ts,rhp_ip_addr* addr)
{

	rhp_ip_addr_dump("addr_is_included: addr",addr);
	rhp_ip_addr_dump("addr_is_included: ts->start_addr",&(ts->start_addr));
	rhp_ip_addr_dump("addr_is_included: ts->end_addr",&(ts->end_addr));

	if( !rhp_ip_addr_gteq_ip(addr,&(ts->start_addr)) &&
			!rhp_ip_addr_lteq_ip(addr,&(ts->end_addr))){

		if( addr->addr_family == AF_INET ){
			RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_ADDR_IS_INCLUDED_INCLUDED,"xx4",ts,addr,addr->addr.v4);
		}else if( addr->addr_family == AF_INET6 ){
			RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_ADDR_IS_INCLUDED_INCLUDED_V6,"xx6",ts,addr,addr->addr.v6);
		}
		return 1;
	}

	if( addr->addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_ADDR_IS_INCLUDED_NOT_INCLUDED,"xx4",ts,addr,addr->addr.v4);
	}else if( addr->addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_ADDR_IS_INCLUDED_NOT_INCLUDED_V6,"xx6",ts,addr,addr->addr.v6);
	}
	return 0;
}

int rhp_ikev2_ts_payload_cfg_addr_is_included(rhp_traffic_selector* cfg_ts,rhp_ip_addr* addr)
{
	rhp_ip_addr start_addr, end_addr;

	rhp_ip_addr_dump("cfg_addr_is_included: addr",addr);

	if( cfg_ts->ts_is_subnet ){

		memset(&start_addr,0,sizeof(rhp_ip_addr));
		memset(&end_addr,0,sizeof(rhp_ip_addr));

		if( cfg_ts->addr.subnet.addr_family == AF_INET ){

			start_addr.addr_family = AF_INET;
			end_addr.addr_family = AF_INET;

		rhp_ipv4_subnet_addr_range(cfg_ts->addr.subnet.addr.v4,
				cfg_ts->addr.subnet.netmask.v4,&(start_addr.addr.v4),&(end_addr.addr.v4));

		}else if( cfg_ts->addr.subnet.addr_family == AF_INET6 ){

			start_addr.addr_family = AF_INET6;
			end_addr.addr_family = AF_INET6;

			rhp_ipv6_subnet_addr_range(cfg_ts->addr.subnet.addr.v6,cfg_ts->addr.subnet.prefixlen,
				start_addr.addr.v6,end_addr.addr.v6);

		}else{

			RHP_BUG("%d",cfg_ts->addr.subnet.addr_family);
			return 0;
		}

	}else{

		memcpy(&start_addr,&(cfg_ts->addr.range.start),sizeof(rhp_ip_addr));
		memcpy(&end_addr,&(cfg_ts->addr.range.end),sizeof(rhp_ip_addr));
	}

	rhp_ip_addr_dump("cfg_addr_is_included: start_addr",&start_addr);
	rhp_ip_addr_dump("cfg_addr_is_included: end_addr",&end_addr);

	if( !rhp_ip_addr_gteq_ip(addr,&start_addr) &&
			!rhp_ip_addr_lteq_ip(addr,&end_addr)){

		if( addr->addr_family == AF_INET ){
			RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_CFG_ADDR_IS_INCLUDED_INCLUDED,"xx4",cfg_ts,addr,addr->addr.v4);
		}else if( addr->addr_family == AF_INET6 ){
			RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_CFG_ADDR_IS_INCLUDED_INCLUDED_V6,"xx6",cfg_ts,addr,addr->addr.v6);
		}
		return 1;
	}

	if( addr->addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_CFG_ADDR_IS_INCLUDED_NOT_INCLUDED,"xx4",cfg_ts,addr,addr->addr.v4);
	}else if( addr->addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_CFG_ADDR_IS_INCLUDED_NOT_INCLUDED_V6,"xx6",cfg_ts,addr,addr->addr.v6);
	}
	return 0;
}

static int _rhp_ikev2_ts_payload_replace_start_addr(rhp_ikev2_traffic_selector* ts,rhp_ip_addr* addr)
{
	rhp_ip_addr_dump("_rhp_ikev2_ts_payload_replace_start_addr: ts->start_addr",&(ts->start_addr));
	rhp_ip_addr_dump("_rhp_ikev2_ts_payload_replace_start_addr: addr",addr);

	memcpy(&(ts->start_addr),addr,sizeof(rhp_ip_addr));
	return 0;
}

static int _rhp_ikev2_ts_payload_replace_end_addr(rhp_ikev2_traffic_selector* ts,rhp_ip_addr* addr)
{
	rhp_ip_addr_dump("_rhp_ikev2_ts_payload_replace_start_addr: ts->end_addr",&(ts->end_addr));
	rhp_ip_addr_dump("_rhp_ikev2_ts_payload_replace_start_addr: addr",addr);

	memcpy(&(ts->end_addr),addr,sizeof(rhp_ip_addr));
	return 0;
}

int rhp_ikev2_ts_cmp_ts2tsh(rhp_ikev2_traffic_selector* ts, rhp_proto_ike_ts_selector* tsh)
{
	u8 *start_addr, *end_addr;
	int addr_len;

	start_addr = (u8*)(tsh + 1);
	if( tsh->ts_type == RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE ){
		end_addr = start_addr + 4;
		addr_len = 4;
	}else if( tsh->ts_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){
		end_addr = start_addr + 16;
		addr_len = 16;
	}else{
		return -1;
	}

  if( ts->ts_type != tsh->ts_type ){
  	return -1;
  }

  if( ts->protocol != tsh->ip_protocol_id ){
  	return -1;
  }

  if( ts->protocol == RHP_PROTO_IP_ICMP || ts->protocol == RHP_PROTO_IP_IPV6_ICMP  ){

    if( ts->icmp_start_type != tsh->start_port.icmp.type ){
    	return -1;
    }

    if( ts->icmp_end_type != tsh->end_port.icmp.type ){
    	return -1;
    }

    if( ts->icmp_start_code != tsh->start_port.icmp.code ){
    	return -1;
    }

    if( ts->icmp_end_code != tsh->end_port.icmp.code ){
    	return -1;
    }

  }else{

		if( ts->start_port != tsh->start_port.port ){
			return -1;
		}

		if( ts->end_port != tsh->end_port.port ){
			return -1;
		}
  }

  if( rhp_ip_addr_cmp_value(&(ts->start_addr),addr_len,start_addr) ){
  	return -1;
  }

  if( rhp_ip_addr_cmp_value(&(ts->end_addr),addr_len,end_addr) ){
  	return -1;
  }

  return 0;
}

int rhp_ikev2_ts_cmp_ts2cfg(rhp_ikev2_traffic_selector* ts, rhp_traffic_selector* cfg_ts)
{
	rhp_ip_addr* start_addr;
	rhp_ip_addr* end_addr;
	rhp_ip_addr end_addr_subnet;

	if( cfg_ts->ts_is_subnet ){

		memset(&end_addr_subnet,0,sizeof(rhp_ip_addr));
		start_addr = &(cfg_ts->addr.subnet);

		if( cfg_ts->addr.subnet.addr_family == AF_INET ){

			end_addr_subnet.addr_family = AF_INET;

			rhp_ipv4_subnet_addr_range(cfg_ts->addr.subnet.addr.v4,
					cfg_ts->addr.subnet.netmask.v4,NULL,&(end_addr_subnet.addr.v4));

		}else if( cfg_ts->addr.subnet.addr_family == AF_INET6 ){

			end_addr_subnet.addr_family = AF_INET6;

			rhp_ipv6_subnet_addr_range(cfg_ts->addr.subnet.addr.v6,
					cfg_ts->addr.subnet.prefixlen,NULL,end_addr_subnet.addr.v6);

		}else{

			RHP_BUG("%d",cfg_ts->addr.subnet.addr_family);
			return -1;
		}

		end_addr = &end_addr_subnet;

	}else{

		start_addr = &(cfg_ts->addr.range.start);
		end_addr = &(cfg_ts->addr.range.end);
	}


	if( ts->ts_type != RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE &&
			ts->ts_type != RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){
		RHP_BUG("%d",ts->ts_type);
		return -1;
	}

  if( ts->ts_type != cfg_ts->ts_type ){
  	return -1;
  }

  if( ts->protocol != cfg_ts->protocol ){
  	return -1;
  }

  if( ts->protocol == RHP_PROTO_IP_ICMP || ts->protocol == RHP_PROTO_IP_IPV6_ICMP  ){

    if( ts->icmp_start_type != cfg_ts->icmp_start_type ){
    	return -1;
    }

    if( ts->icmp_end_type != cfg_ts->icmp_end_type ){
    	return -1;
    }

    if( ts->icmp_start_code != cfg_ts->icmp_start_code ){
    	return -1;
    }

    if( ts->icmp_end_code != cfg_ts->icmp_end_code ){
    	return -1;
    }

  }else{

		if( ts->start_port != cfg_ts->start_port ){
			return -1;
		}

		if( ts->end_port != cfg_ts->end_port ){
			return -1;
		}
  }

  if( rhp_ip_addr_cmp_ip_only(&(ts->start_addr),start_addr) ){
  	return -1;
  }

  if( rhp_ip_addr_cmp_ip_only(&(ts->end_addr),end_addr) ){
  	return -1;
  }

  return 0;
}

int rhp_ikev2_ts_cmp_ts2ts(rhp_ikev2_traffic_selector* ts0, rhp_ikev2_traffic_selector* ts1)
{
  if( ts0->ts_type != ts1->ts_type ){
  	return -1;
  }

  if( ts0->protocol != ts1->protocol ){
  	return -1;
  }

  if( ts0->protocol == RHP_PROTO_IP_ICMP || ts0->protocol == RHP_PROTO_IP_IPV6_ICMP  ){

    if( ts0->icmp_start_type != ts1->icmp_start_type ){
    	return -1;
    }

    if( ts0->icmp_end_type != ts1->icmp_end_type ){
    	return -1;
    }

    if( ts0->icmp_start_code != ts1->icmp_start_code ){
    	return -1;
    }

    if( ts0->icmp_end_code != ts1->icmp_end_code ){
    	return -1;
    }

  }else{

		if( ts0->start_port != ts1->start_port ){
			return -1;
		}

		if( ts0->end_port != ts1->end_port ){
			return -1;
		}
  }

  if( rhp_ip_addr_cmp_ip_only(&(ts0->start_addr),&(ts1->start_addr)) ){
  	return -1;
  }

  if( rhp_ip_addr_cmp_ip_only(&(ts0->end_addr),&(ts1->end_addr)) ){
  	return -1;
  }

  return 0;
}

int rhp_ikev2_ts_cmp(rhp_ikev2_traffic_selector* ts0, rhp_ikev2_traffic_selector* ts1)
{
	if( ts0->tsh && ts1->tsh ){

		if( ts0->tsh->ts_type != ts1->tsh->ts_type ){
			return -1;
		}

		if( ts0->tsh->len != ts1->tsh->len ){
			return -1;
		}

		return memcmp(ts0->tsh,ts1->tsh,ntohs(ts0->tsh->len));

	}else if( ts0->tsh == NULL && ts1->tsh == NULL ){

		return rhp_ikev2_ts_cmp_ts2ts(ts0,ts1);

	}else if( ts0->tsh && ts1->tsh == NULL ){

		return rhp_ikev2_ts_cmp_ts2tsh(ts1,ts0->tsh);

	}else if( ts1->tsh && ts0->tsh == NULL ){

		return rhp_ikev2_ts_cmp_ts2tsh(ts0,ts1->tsh);
	}

	return -1;
}

int rhp_ikev2_ts_is_included(rhp_ikev2_traffic_selector* tss_head,rhp_ikev2_traffic_selector* ts)
{
	rhp_ikev2_traffic_selector* ts_d = tss_head;
	while( ts_d ){

		if( !rhp_ikev2_ts_cmp(ts_d,ts) ){
			return 1;
		}

		ts_d = ts_d->next;
	}

	return 0;
}

int rhp_ikev2_alloc_ts(u8 ts_type,rhp_ikev2_traffic_selector** ts_r)
{
  rhp_ikev2_traffic_selector* ts = NULL;

  if( ts_type != RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE &&
  		ts_type != RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){

  	RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_ALLOC_TS_NOT_SUPPORTED,"Lb","PROTO_IKE_TS",ts_type);
  	return RHP_STATUS_IKEV2_NOT_SUPPORTED_PROTO;
  }

  ts = (rhp_ikev2_traffic_selector*)_rhp_malloc(sizeof(rhp_ikev2_traffic_selector));
  if( ts == NULL ){
  	RHP_BUG("");
  	return -ENOMEM;
  }

  memset(ts,0,sizeof(rhp_ikev2_traffic_selector));


  ts->ts_type = ts_type;

  ts->set_ts_type = _rhp_ikev2_ts_payload_set_ts_type;
  ts->get_ts_type = _rhp_ikev2_ts_payload_get_ts_type;
  ts->set_protocol = _rhp_ikev2_ts_payload_set_protocol;
  ts->get_protocol = _rhp_ikev2_ts_payload_get_protocol;
  ts->set_start_port = _rhp_ikev2_ts_payload_set_start_port;
  ts->get_start_port = _rhp_ikev2_ts_payload_get_start_port;
  ts->set_end_port = _rhp_ikev2_ts_payload_set_end_port;
  ts->get_end_port = _rhp_ikev2_ts_payload_get_end_port;
  ts->set_icmp_start_type = _rhp_ikev2_ts_payload_set_icmp_start_type;
  ts->get_icmp_start_type = _rhp_ikev2_ts_payload_get_icmp_start_type;
  ts->set_icmp_end_type = _rhp_ikev2_ts_payload_set_icmp_end_type;
  ts->get_icmp_end_type = _rhp_ikev2_ts_payload_get_icmp_end_type;
  ts->set_icmp_start_code = _rhp_ikev2_ts_payload_set_icmp_start_code;
  ts->get_icmp_start_code = _rhp_ikev2_ts_payload_get_icmp_start_code;
  ts->set_icmp_end_code = _rhp_ikev2_ts_payload_set_icmp_end_code;
  ts->get_icmp_end_code = _rhp_ikev2_ts_payload_get_icmp_end_code;
  ts->set_start_addr = _rhp_ikev2_ts_payload_set_start_addr;
  ts->get_start_addr = _rhp_ikev2_ts_payload_get_start_addr;
  ts->set_end_addr = _rhp_ikev2_ts_payload_set_end_addr;
  ts->get_end_addr = _rhp_ikev2_ts_payload_get_end_addr;
  ts->addr_is_included = rhp_ikev2_ts_payload_addr_is_included;
  ts->replace_start_addr = _rhp_ikev2_ts_payload_replace_start_addr;
  ts->replace_end_addr = _rhp_ikev2_ts_payload_replace_end_addr;
  ts->dump = _rhp_ikev2_ts_payload_dump;
  ts->dump2log = _rhp_ikev2_ts_payload_dump_log;

  *ts_r = ts;

  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_ALLOC_TS,"Lbx","PROTO_IKE_TS",ts_type,*ts_r);
  return 0;
}

int rhp_ikev2_ts_tx_dup(rhp_ikev2_traffic_selector* from,rhp_ikev2_traffic_selector** to_r)
{
	int err;
	rhp_ikev2_traffic_selector* to = NULL;

	if( (err = rhp_ikev2_alloc_ts(from->ts_type,&to)) ){
		RHP_BUG("");
		return err;
	}

  to->protocol = from->protocol;
  to->is_pending = from->is_pending;
  to->apdx_ts_ignored = from->apdx_ts_ignored;

  to->start_port = from->start_port;
  to->end_port = from->end_port;

  to->icmp_start_type = from->icmp_start_type;
  to->icmp_end_type = from->icmp_end_type;

  to->icmp_start_code = from->icmp_start_code;
  to->icmp_end_code = from->icmp_end_code;

  memcpy(&(to->start_addr),(&from->start_addr),sizeof(rhp_ip_addr));
  memcpy(&(to->end_addr),(&from->end_addr),sizeof(rhp_ip_addr));

  *to_r = to;

  return 0;
}


int rhp_ikev2_dup_ts(rhp_ikev2_traffic_selector* ts,rhp_ikev2_traffic_selector** ts_r)
{
	int err = -EINVAL;
  rhp_ikev2_traffic_selector* ts_d = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_DUP_TS,"xx",ts,ts_r);

  ts_d = (rhp_ikev2_traffic_selector*)_rhp_malloc(sizeof(rhp_ikev2_traffic_selector));
  if( ts_d == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }

  memcpy(ts_d,ts,sizeof(rhp_ikev2_traffic_selector));
  ts_d->next = NULL;
	ts_d->tsh = NULL;

  if( ts->tsh ){

  	int tsh_d_len = 0;

  	if( ts->tsh->ts_type == RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE ){
  		tsh_d_len = sizeof(rhp_proto_ike_ts_selector) + 8;
  	}else if( ts->tsh->ts_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){
  		tsh_d_len = sizeof(rhp_proto_ike_ts_selector) + 32;
  	}

  	if( tsh_d_len ){

  		ts_d->tsh = (rhp_proto_ike_ts_selector*)_rhp_malloc(tsh_d_len);
  		if( ts_d->tsh == NULL ){
  			err = -ENOMEM;
  			RHP_BUG("");
  			goto error;
  		}

  		memcpy(ts_d->tsh,ts->tsh,tsh_d_len);
  	}

  }else{

  	RHP_TRC(0,RHPTRCID_IKEV2_DUP_TS_NO_TS_HEADER,"xx",ts,ts_r);
  }

  *ts_r = ts_d;

	RHP_TRC(0,RHPTRCID_IKEV2_DUP_TS_RTRN,"xxx",ts,ts_r,*ts_r);
  return 0;

error:
	if( ts_d ){
		if( ts_d->tsh ){
			_rhp_free(ts_d->tsh);
		}
		_rhp_free(ts_d);
	}
	RHP_TRC(0,RHPTRCID_IKEV2_DUP_TS_ERR,"xxE",ts,ts_r,err);
	return err;
}

int rhp_ikev2_dup_tss(rhp_ikev2_traffic_selector* tss_head,
		rhp_ikev2_traffic_selector** tss_head_r,
		int (*eval)(rhp_ikev2_traffic_selector* ts,void* cb_ctx),void* ctx)
{
	int err = -EINVAL;
	rhp_ikev2_traffic_selector *ts = tss_head, *ts_d = NULL, *ts_d_tail = NULL, *ts_d_head = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_DUP_TSS,"xxYx",tss_head,tss_head_r,eval,ctx);

	while( ts ){

		if( eval == NULL || eval(ts,ctx) ){

			err = rhp_ikev2_dup_ts(ts,&ts_d);
			if( err ){
				goto error;
			}

			if( ts_d_head == NULL ){
				ts_d_head = ts_d;
			}else{
				ts_d_tail->next = ts_d;
			}
			ts_d_tail = ts_d;
		}

		ts = ts->next;
	}

	if( ts_d_head == NULL ){
		err = -ENOENT;
		goto error;
	}

	*tss_head_r = ts_d_head;

	ts_d_head->dump(ts_d_head,"rhp_ikev2_dup_tss");
	RHP_TRC(0,RHPTRCID_IKEV2_DUP_TSS_RTRN,"xxx",tss_head,tss_head_r,*tss_head_r);
	return 0;

error:
	ts_d = ts_d_head;
	while(ts_d){
		rhp_ikev2_traffic_selector* ts_d_n = ts_d->next;
		if( ts_d->tsh ){
			_rhp_free(ts_d->tsh);
		}
		_rhp_free(ts_d);
		ts_d = ts_d_n;
	}
	RHP_TRC(0,RHPTRCID_IKEV2_DUP_TSS_ERR,"xxYxE",tss_head,tss_head_r,eval,ctx,err);
	return err;
}

int rhp_ikev2_ts_is_any(rhp_ikev2_traffic_selector* ts)
{
	rhp_ip_addr start_addr, end_addr;

	if( ts->get_protocol(ts) ){
		return 0;
	}

	if( ts->get_start_port(ts) != 0 ){
		return 0;
	}

	if( ts->get_end_port(ts) != 0xFFFF ){
		return 0;
	}

	if( ts->get_start_addr(ts,&start_addr) ){
		return 0;
	}

	if( ts->get_end_addr(ts,&end_addr) ){
		return 0;
	}

	if( ts->get_ts_type(ts) == RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE ){

		if( start_addr.addr.v4 != 0 ){
			return 0;
		}

		if( end_addr.addr.v4 != 0xFFFFFFFF ){
			return 0;
		}

	}else if( ts->get_ts_type(ts) == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){

		u64* b = (u64*)start_addr.addr.v6;

		if( b[0] || b[1] ){
			return 0;
		}

		b = (u64*)end_addr.addr.v6;
		if( b[0] != 0xFFFFFFFFFFFFFFFFUL || b[1] != 0xFFFFFFFFFFFFFFFFUL ){
			return 0;
		}

	}else{

		return 0;
	}

	return 1;
}


static u8 _rhp_ikev2_ts_payload_get_ts_num(rhp_ikev2_payload* payload)
{
  u8 number;
  rhp_proto_ike_ts_payload* ts_payloadh = (rhp_proto_ike_ts_payload*)payload->payloadh;
  if( ts_payloadh ){
  	number = ts_payloadh->ts_num;
  }else{
  	number = payload->ext.ts->tss_num;
  }
  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_GET_TS_NUM,"xxb",payload,ts_payloadh,number);
  return number;
}

static void _rhp_ikev2_ts_payload_put_ts(rhp_ikev2_payload* payload,rhp_ikev2_traffic_selector* ts)
{
  if( payload->ext.ts->tss_head == NULL ){
    payload->ext.ts->tss_head = ts;
  }else{
    payload->ext.ts->tss_tail->next = ts;
  }
  payload->ext.ts->tss_tail = ts;
  payload->ext.ts->tss_num++;

  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_PUT_TS,"xx",payload,ts);
  if( ts ){
  	ts->dump(ts,"_rhp_ikev2_ts_payload_put_ts");
  }
  return;
}

static int _rhp_ikev2_ts_payload_alloc_and_put_ts(rhp_ikev2_payload* payload,u8 ts_type,u8 protocol,u16 start_port,u16 end_port,
		  u8 icmp_start_type,u8 icmp_end_type,u8 icmp_start_code,u8 icmp_end_code,
		  rhp_ip_addr* start_addr,rhp_ip_addr* end_addr)
{
	int err = -EINVAL;
  rhp_ikev2_traffic_selector* ts = NULL;

  err = rhp_ikev2_alloc_ts(ts_type,&ts);
  if( err ){
  	RHP_BUG("");
  	return -ENOMEM;
  }

  ts->protocol = protocol;
  ts->start_port = start_port;
  ts->end_port = end_port;
  ts->icmp_start_type = icmp_start_type;
  ts->icmp_end_type = icmp_end_type;
  ts->icmp_start_code = icmp_start_code;
  ts->icmp_end_code = icmp_end_code;
  memcpy(&(ts->start_addr),start_addr,sizeof(rhp_ip_addr));
  memcpy(&(ts->end_addr),end_addr,sizeof(rhp_ip_addr));

  _rhp_ikev2_ts_payload_put_ts(payload,ts);

  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_ALLOC_AND_PUT_TS,"xx",payload,ts);
  return 0;
}

static int _rhp_ikev2_ts_payload_put_ts_rx(rhp_ikev2_payload* payload,rhp_proto_ike_ts_selector* tsh)
{
	int err = -EINVAL;
  rhp_ikev2_traffic_selector* ts = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_PUT_TS_RX,"xp",payload,ntohs(tsh->len),tsh);

  err = rhp_ikev2_alloc_ts(tsh->ts_type,&ts);

  if( err == RHP_STATUS_IKEV2_NOT_SUPPORTED_PROTO ){
    RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_PUT_TS_RX_NOT_SUP_PROTO_IGNORED,"xp",payload,ntohs(tsh->len),tsh);
  	return 0;
  }else if( err ){
    RHP_BUG("");
    return -ENOMEM;
  }

  ts->tsh = tsh;
  ts->tsh_is_ref = 1;
  _rhp_ikev2_ts_payload_put_ts(payload,ts);

  return 0;
}

//
// For Child SA Respnder's API
//
// rlm->lock must be acquired. -ENOENT : Acceptable traffic selector(s) not found.
static int _rhp_ikev2_ts_payload_get_matched_tss(rhp_ikev2_payload* payload,rhp_vpn_realm* rlm,
		rhp_cfg_peer* cfg_peer,rhp_ikev2_traffic_selector** res_tss)
{
  rhp_traffic_selector* tss;
  int tss_num;
  int ret;

  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_GET_MATCHED_TSS,"xxxxd",payload,rlm,cfg_peer,res_tss,rlm->childsa.exact_match_ts);

  if( payload->payload_id == RHP_PROTO_IKE_PAYLOAD_TS_I ){
    tss = cfg_peer->peer_tss;
    tss_num = cfg_peer->peer_tss_num;
  }else{
    tss = cfg_peer->my_tss;
    tss_num = cfg_peer->my_tss_num;
  }


  if( rlm->childsa.exact_match_ts ){

  	ret = rhp_childsa_exact_match_traffic_selectors_cfg(tss_num,tss,
  					payload->ext.ts->tss_num,payload->ext.ts->tss_head);

  }else{

		ret = rhp_childsa_search_traffic_selectors(tss,payload->ext.ts->tss_head,res_tss);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_GET_MATCHED_TSS_RTRN,"xxxxE",payload,rlm,cfg_peer,res_tss,ret);
  return ret;
}

int rhp_ikev2_ts_payload_ts2childsa_ts(rhp_ikev2_traffic_selector* ts,rhp_childsa_ts* csa_ts)
{
	csa_ts->ts_or_id_type = ts->get_ts_type(ts);

	csa_ts->protocol = ts->get_protocol(ts);

	csa_ts->start_port = ts->get_start_port(ts);
	csa_ts->end_port = ts->get_end_port(ts);

	csa_ts->icmp_start_type = ts->get_icmp_start_type(ts);
	csa_ts->icmp_end_type = ts->get_icmp_end_type(ts);
	csa_ts->icmp_start_code = ts->get_icmp_start_code(ts);
	csa_ts->icmp_end_code = ts->get_icmp_end_code(ts);

  if( ts->get_start_addr(ts,&(csa_ts->start_addr)) ){
  	RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_TS2CHILDSA_TS_START_ADDR_ERR,"xx",ts,csa_ts);
    return -1;
  }

  if( ts->get_end_addr(ts,&(csa_ts->end_addr)) ){
  	RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_TS2CHILDSA_TS_END_ADDR_ERR,"xx",ts,csa_ts);
    return -1;
  }

  return 0;
}

// This means 'ts' is included within 'ts_cmp'.
static int _rhp_ikev2_ts_payload_ts_included(rhp_ikev2_traffic_selector* ts_cmp, rhp_ikev2_traffic_selector* ts)
{
	rhp_childsa_ts ts_cmp_csa, ts_csa;

	memset(&ts_cmp_csa,0,sizeof(rhp_childsa_ts));
	memset(&ts_csa,0,sizeof(rhp_childsa_ts));

	ts_cmp_csa.tag[0] = '#';
	ts_cmp_csa.tag[1] = 'C';
	ts_cmp_csa.tag[2] = 'S';
	ts_cmp_csa.tag[3] = 'T';

	ts_csa.tag[0] = '#';
	ts_csa.tag[1] = 'C';
	ts_csa.tag[2] = 'S';
	ts_csa.tag[3] = 'T';

	if( rhp_ikev2_ts_payload_ts2childsa_ts(ts_cmp,&ts_cmp_csa) ){
		RHP_BUG("");
		return -1;
	}

	if( rhp_ikev2_ts_payload_ts2childsa_ts(ts,&ts_csa) ){
		RHP_BUG("");
		return -1;
	}

	return rhp_childsa_ts_included(&ts_cmp_csa,&ts_csa);
}


//
// For Child SA Initiator's API.
//
// rlm->lock must be acquired.
//
// -ENOENT : Acceptable traffic selector(s) not found.
//
static int _rhp_ikev2_ts_payload_check_tss(rhp_ikev2_payload* payload,rhp_vpn_realm* rlm,
		rhp_cfg_peer* cfg_peer,rhp_childsa_ts* extended_tss,rhp_ikev2_traffic_selector** res_tss)
{
  rhp_traffic_selector* cfg_tss;
  int cfg_tss_num;
	int ret;

  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_CHECK_TSS,"xxxd",payload,rlm,cfg_peer,rlm->childsa.exact_match_ts);

  if( payload->payload_id == RHP_PROTO_IKE_PAYLOAD_TS_I ){
  	cfg_tss = cfg_peer->my_tss;
  	cfg_tss_num = cfg_peer->my_tss_num;
  }else{
  	cfg_tss = cfg_peer->peer_tss;
  	cfg_tss_num = cfg_peer->peer_tss_num;
  }

  if( rlm->childsa.exact_match_ts ){

  	ret = rhp_childsa_exact_match_traffic_selectors_cfg(cfg_tss_num,cfg_tss,
  					payload->ext.ts->tss_num,payload->ext.ts->tss_head);

  }else{

  	ret = rhp_childsa_check_traffic_selectors_cfg(cfg_tss,payload->ext.ts->tss_head);

  	if( ret && extended_tss ){

  		rhp_ikev2_traffic_selector* ts = payload->ext.ts->tss_head;
  		while( ts ){

  			rhp_childsa_ts* extended_ts = extended_tss;
  			while( extended_ts ){

  				rhp_childsa_ts ts_csa;

  				memset(&ts_csa,0,sizeof(rhp_childsa_ts));
  				ts_csa.tag[0] = '#';
  				ts_csa.tag[1] = 'C';
  				ts_csa.tag[2] = 'S';
  				ts_csa.tag[3] = 'T';

  				if( !rhp_ikev2_ts_payload_ts2childsa_ts(ts,&ts_csa) ){

  					if( !rhp_childsa_ts_included(extended_ts,&ts_csa) ){
  						break;
  					}
  				}

  				extended_ts = extended_ts->next;
  			}

  			if( extended_ts == NULL ){
  				ret = -ENOENT;
  				break;
  			}

  			ts = ts->next;
  		}

  		if( ts == NULL ){
  			ret = 0;
  		}
  	}
  }

  if( ret == 0 ){
  	*res_tss = payload->ext.ts->tss_head;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_CHECK_TSS_RTRN,"xxxE",payload,rlm,cfg_peer,ret);
  return ret;
}


static int _rhp_ikev2_ts_payload_reconfirm_tss(rhp_ikev2_payload* payload,rhp_ikev2_payload* tx_payload)
{
	rhp_ikev2_traffic_selector* tx_ts = tx_payload->ext.ts->tss_head;

	RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_RECONFIRM_TSS,"xx",payload,tx_payload);

	while( tx_ts ){

		rhp_ikev2_traffic_selector* ts = payload->ext.ts->tss_head;
		while( ts ){

			if( !_rhp_ikev2_ts_payload_ts_included(ts,tx_ts) ){
				break;
			}

			ts = ts->next;
		}

		if( ts == NULL ){
			RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_RECONFIRM_TSS_NG,"xx",payload,tx_payload);
			return -1;
		}

		tx_ts = tx_ts->next;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_RECONFIRM_TSS_OK,"xx",payload,tx_payload);
	return 0;
}


static int _rhp_ikev2_ts_payload_set_cfg_tss(rhp_ikev2_payload* payload,rhp_traffic_selector *tss,
		rhp_ip_addr_list* cp_internal_addrs,rhp_ikev2_traffic_selector* apdx_tss)
{
  int err;
  rhp_traffic_selector *cfg_ts;
  rhp_ip_addr_list *cp_internal_addr,
  								 *cp_internal_addr_v4 = NULL, *cp_internal_addr_v6 = NULL;
	rhp_ikev2_traffic_selector* apdx_ts;

  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_SET_CFG_TSS,"xxxx",payload,tss,cp_internal_addrs,apdx_tss);

	apdx_ts = apdx_tss;
	while( apdx_ts ){
		apdx_ts->apdx_ts_ignored = 0;
		apdx_ts = apdx_ts->next;
	}


  cp_internal_addr = cp_internal_addrs;
  while( cp_internal_addr ){

  	if( cp_internal_addr->ip_addr.addr_family == AF_INET ){

  		cp_internal_addr_v4 = cp_internal_addr;

  	}else if( cp_internal_addr->ip_addr.addr_family == AF_INET6 ){

  		cp_internal_addr_v6 = cp_internal_addr;
  	}

  	cp_internal_addr = cp_internal_addr->next;
  }


	cfg_ts = tss;
	while( cfg_ts ){

		rhp_traffic_selector cfg_ts_d;

		memcpy(&cfg_ts_d,cfg_ts,sizeof(rhp_traffic_selector));
		cfg_ts_d.ts_is_subnet = 0;
		cfg_ts_d.next = NULL;

		rhp_cfg_traffic_selectors_dump("_rhp_ikev2_ts_payload_set_cfg_tss",cfg_ts,NULL);

		if( cfg_ts->ts_type == RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE &&
				cp_internal_addr_v4 ){

			memcpy(&(cfg_ts_d.addr.range.start),&(cp_internal_addr_v4->ip_addr),sizeof(rhp_ip_addr));
			memcpy(&(cfg_ts_d.addr.range.end),&(cp_internal_addr_v4->ip_addr),sizeof(rhp_ip_addr));

		}else	if( cfg_ts->ts_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE &&
							cp_internal_addr_v6 ){

			memcpy(&(cfg_ts_d.addr.range.start),&(cp_internal_addr_v6->ip_addr),sizeof(rhp_ip_addr));
			memcpy(&(cfg_ts_d.addr.range.end),&(cp_internal_addr_v6->ip_addr),sizeof(rhp_ip_addr));

		}else if( cfg_ts->ts_is_subnet ){

			memcpy(&(cfg_ts_d.addr.range.start),&(cfg_ts->addr.subnet),sizeof(rhp_ip_addr));

			memset(&(cfg_ts_d.addr.range.end),0,sizeof(rhp_ip_addr));

			if( cfg_ts->addr.subnet.addr_family == AF_INET ){

				cfg_ts_d.addr.range.end.addr_family = AF_INET;

				rhp_ipv4_subnet_addr_range(cfg_ts->addr.subnet.addr.v4,
						cfg_ts->addr.subnet.netmask.v4,NULL,&(cfg_ts_d.addr.range.end.addr.v4));

			}else if( cfg_ts->addr.subnet.addr_family == AF_INET6 ){

				cfg_ts_d.addr.range.end.addr_family = AF_INET6;

				rhp_ipv6_subnet_addr_range(cfg_ts->addr.subnet.addr.v6,
						cfg_ts->addr.subnet.prefixlen,NULL,cfg_ts_d.addr.range.end.addr.v6);

			}else{
				RHP_BUG("%d",cfg_ts->addr.subnet.addr_family);
				err = -EINVAL;
				goto error;
			}
		}

		rhp_cfg_traffic_selectors_dump("_rhp_ikev2_ts_payload_set_cfg_tss.cfg_ts_d",&cfg_ts_d,NULL);

		apdx_ts = apdx_tss;
		while( apdx_ts ){

			if( !apdx_ts->apdx_ts_ignored ){

				apdx_ts->apdx_ts_ignored
				= !rhp_ikev2_ts_cmp_ts2cfg_tss_same_or_any(apdx_ts,&cfg_ts_d);

			}

			apdx_ts = apdx_ts->next;
		}

		err = payload->ext.ts->alloc_and_put_ts(payload,
						cfg_ts_d.ts_type,cfg_ts_d.protocol,
						cfg_ts_d.start_port,cfg_ts_d.end_port,
						cfg_ts_d.icmp_start_type,cfg_ts_d.icmp_end_type,
						cfg_ts_d.icmp_start_code,cfg_ts_d.icmp_end_code,
						&(cfg_ts_d.addr.range.start),&(cfg_ts_d.addr.range.end));
		if( err ){
			RHP_BUG("");
			goto error;
		}

		cfg_ts = cfg_ts->next;
	}

	apdx_ts = apdx_tss;
	while( apdx_ts ){

		rhp_ip_addr apdx_start_addr;
		rhp_ip_addr apdx_end_addr;

	  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_SET_CFG_TSS_APDX_TS,"xxd",payload,apdx_ts,apdx_ts->apdx_ts_ignored);

		if( !apdx_ts->apdx_ts_ignored ){

			apdx_ts->get_start_addr(apdx_ts,&apdx_start_addr);
			apdx_ts->get_end_addr(apdx_ts,&apdx_end_addr);

			err = payload->ext.ts->alloc_and_put_ts(payload,
							apdx_ts->get_ts_type(apdx_ts),
							apdx_ts->get_protocol(apdx_ts),
							apdx_ts->get_start_port(apdx_ts),
							apdx_ts->get_end_port(apdx_ts),
							apdx_ts->get_icmp_start_type(apdx_ts),
							apdx_ts->get_icmp_end_type(apdx_ts),
							apdx_ts->get_icmp_start_code(apdx_ts),
							apdx_ts->get_icmp_end_code(apdx_ts),
							&apdx_start_addr,&apdx_end_addr);

			if( err ){
				RHP_BUG("");
				goto error;
			}
		}

		apdx_ts = apdx_ts->next;
	}

  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_SET_CFG_TSS_RTRN,"xxxx",payload,tss,cp_internal_addr_v4,cp_internal_addr_v6);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_SET_CFG_TSS_ERR,"xxE",payload,tss,err);
	return err;
}

// rlm->lock must be acquired.
static int _rhp_ikev2_ts_payload_set_i_tss(rhp_ikev2_payload* payload,rhp_vpn_realm* rlm,
		rhp_cfg_peer* cfg_peer,rhp_ip_addr_list* cp_internal_addrs,rhp_ikev2_traffic_selector* apdx_tss)
{
  int err;
  rhp_traffic_selector *tss;

  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_SET_I_TSS,"xxxxx",payload,rlm,cfg_peer,cp_internal_addrs,apdx_tss);

  if( payload->payload_id == RHP_PROTO_IKE_PAYLOAD_TS_I ){
    tss = cfg_peer->my_tss;
    cp_internal_addrs = NULL;
  }else{
    tss = cfg_peer->peer_tss;
  }

  err = _rhp_ikev2_ts_payload_set_cfg_tss(payload,tss,cp_internal_addrs,apdx_tss);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_SET_I_TSS_RTRN,"xxx",payload,rlm,cfg_peer);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_SET_I_TSS_ERR,"xxxE",payload,rlm,cfg_peer,err);
  return err;
}

static int _rhp_ikev2_ts_payload_set_tss(rhp_ikev2_payload* payload,rhp_childsa_ts* tss)
{
	int err = -EINVAL;
	rhp_childsa_ts* ts = tss;

	RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_SET_TSS,"xx",payload,tss);

	while( ts ){

		err = payload->ext.ts->alloc_and_put_ts(payload,
						ts->ts_or_id_type,ts->protocol,
						ts->start_port,ts->end_port,
						ts->icmp_start_type,ts->icmp_end_type,
						ts->icmp_start_code,ts->icmp_end_code,
						&(ts->start_addr),&(ts->end_addr));

		if( err ){
			RHP_BUG("");
			goto error;
		}

		ts = ts->next;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_SET_TSS_RTRN,"xx",payload,tss);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_SET_TSS_ERR,"xxE",payload,tss,err);
	return err;
}


static void _rhp_ikev2_ts_payload_set_matched_r_tss(rhp_ikev2_payload* payload,rhp_ikev2_traffic_selector* res_tss)
{
  rhp_ikev2_traffic_selector* ts = res_tss;

  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_SET_MATCHED_R_TSS,"xx",payload,res_tss);
  if( res_tss ){
  	res_tss->dump(res_tss,"_rhp_ikev2_ts_payload_set_matched_r_tss");
  }

  payload->ext.ts->tss_head = res_tss;
  while( ts ){
    payload->ext.ts->tss_num++;
    if( ts->next == NULL ){
      break;
    }
    ts = ts->next;
  }

  payload->ext.ts->tss_tail = ts;

  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_SET_MATCHED_R_TSS_RTRN,"xx",payload,res_tss);
  return;
}

void rhp_ikev2_ts_payload_free_ts(rhp_ikev2_traffic_selector* ts)
{
  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_FREE_TS,"xxd",ts,ts->tsh,ts->tsh_is_ref);
  if( ts->tsh && !ts->tsh_is_ref ){
  	_rhp_free(ts->tsh);
  }
  _rhp_free(ts);
}

void rhp_ikev2_ts_payload_free_tss(rhp_ikev2_traffic_selector* tss)
{
  rhp_ikev2_traffic_selector *ts,*ts2;

  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_FREE_TSS,"x",tss);

  ts = tss;
  while( ts ){
    ts2 = ts->next;
    rhp_ikev2_ts_payload_free_ts(ts);
    ts = ts2;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_FREE_TSS_RTRN,"x",tss);
  return;
}

static void _rhp_ikev2_ts_payload_destructor(rhp_ikev2_payload* payload)
{
  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_DESTRUCTOR,"xxx",payload,payload->ext.ts,payload->ext.ts->tss_head);

  if( payload->ext.ts->tss_head ){

  	rhp_ikev2_ts_payload_free_tss(payload->ext.ts->tss_head);
  	payload->ext.ts->tss_head = NULL;
  }

  return;
}

static int _rhp_ikev2_ts_payload_serialize(rhp_ikev2_payload* payload,rhp_packet* pkt)
{
  int err = -EINVAL;
  rhp_ikev2_traffic_selector* ts = payload->ext.ts->tss_head;

  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_SERIALIZE,"xx",payload,pkt);

  if( ts ){

    int len = sizeof(rhp_proto_ike_ts_payload);
    rhp_proto_ike_ts_payload* pldh;
    rhp_proto_ike_ts_selector* tsh;
    int ts_offset = 0;
    int n = 0;

    pldh = (rhp_proto_ike_ts_payload*)rhp_pkt_expand_tail(pkt,len);
    if( pldh == NULL ){
      RHP_BUG("");
      return -ENOMEM;
    }
    ts_offset = ((u8*)pldh) - pkt->head;

    pldh->next_payload = payload->get_next_payload(payload);
    pldh->critical_rsv = RHP_PROTO_IKE_PLD_SET_CRITICAL;

    while( ts ){

      int ts_len;
      rhp_ip_addr start_addr, end_addr;

      if( ts->is_pending ){
      	goto next;
      }

      if( ts->ts_type == RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE ){
        ts_len = RHP_PROTO_IKE_TS_IPV4_SIZE;
      }else if( ts->ts_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){
        ts_len = RHP_PROTO_IKE_TS_IPV6_SIZE;
      }else{
      	err = -EINVAL;
        RHP_BUG("%d",ts->ts_type);
        goto error;
      }

      tsh = (rhp_proto_ike_ts_selector*)rhp_pkt_expand_tail(pkt,ts_len);
      if( tsh == NULL ){
        err = -ENOMEM;
        RHP_BUG("");
        goto error;
      }

      tsh->ts_type = ts->get_ts_type(ts);
      tsh->ip_protocol_id = ts->get_protocol(ts);
      tsh->len = htons(ts_len);

      if( tsh->ip_protocol_id == RHP_PROTO_IP_ICMP ||
      		tsh->ip_protocol_id == RHP_PROTO_IP_IPV6_ICMP ){ // ICMP
        tsh->start_port.icmp.type = ts->get_icmp_start_type(ts);
        tsh->start_port.icmp.code = ts->get_icmp_start_code(ts);
        tsh->end_port.icmp.type = ts->get_icmp_end_type(ts);
        tsh->end_port.icmp.code = ts->get_icmp_end_code(ts);
      }else{
        tsh->start_port.port = ts->get_start_port(ts);
        tsh->end_port.port = ts->get_end_port(ts);
      }

      ts->get_start_addr(ts,&start_addr);
      ts->get_end_addr(ts,&end_addr);

      if( ts->ts_type == RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE ){
   	    memcpy((u8*)(tsh + 1),&(start_addr.addr.v4),4);
   	    memcpy((((u8*)(tsh + 1)) + 4),&(end_addr.addr.v4),4);
      }else if( ts->ts_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){
   	    memcpy((u8*)(tsh + 1),start_addr.addr.v6,16);
   	    memcpy((((u8*)(tsh + 1)) + 16),end_addr.addr.v6,16);
      }

      len += ts_len;
      n++;

      if( n >= 255 ){
        err = -EINVAL;
        RHP_BUG("%d",n);
        goto error;
      }

next:
      ts = ts->next;
    }

    pldh->ts_num = (u8)n;

    pldh = (rhp_proto_ike_ts_payload*)(pkt->head + ts_offset);

    pldh->len = htons(len);
    payload->ikemesg->tx_mesg_len += len;

    pldh->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
    if( payload->next ){
      pldh->next_payload = payload->next->get_payload_id(payload->next);
    }

    RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_SERIALIZE_RTRN,"xx",payload,pkt);
    rhp_pkt_trace_dump("_rhp_ikev2_ts_payload_serialize",pkt);
    return 0;
  }

error:
  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_SERIALIZE_ERR,"xxE",payload,pkt,err);
  return err;
}

rhp_ikev2_ts_payload* rhp_ikev2_alloc_ts_payload()
{
  rhp_ikev2_ts_payload* ts_payload;

  ts_payload = (rhp_ikev2_ts_payload*)_rhp_malloc(sizeof(rhp_ikev2_ts_payload));
  if( ts_payload == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(ts_payload,0,sizeof(rhp_ikev2_ts_payload));

  ts_payload->get_ts_num = _rhp_ikev2_ts_payload_get_ts_num;
  ts_payload->alloc_and_put_ts = _rhp_ikev2_ts_payload_alloc_and_put_ts;
  ts_payload->put_ts_rx = _rhp_ikev2_ts_payload_put_ts_rx;
  ts_payload->get_matched_tss = _rhp_ikev2_ts_payload_get_matched_tss;
  ts_payload->set_i_tss = _rhp_ikev2_ts_payload_set_i_tss;
  ts_payload->set_matched_r_tss = _rhp_ikev2_ts_payload_set_matched_r_tss;
  ts_payload->check_tss = _rhp_ikev2_ts_payload_check_tss;
  ts_payload->set_tss = _rhp_ikev2_ts_payload_set_tss;
  ts_payload->reconfirm_tss = _rhp_ikev2_ts_payload_reconfirm_tss;

  RHP_TRC(0,RHPTRCID_IKEV2_ALLOC_TS_PAYLOAD,"x",ts_payload);
  return ts_payload;
}


int rhp_ikev2_ts_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_ts_payload* ts_payload;
  rhp_proto_ike_ts_payload* ts_payloadh = (rhp_proto_ike_ts_payload*)payloadh;
  rhp_proto_ike_ts_selector* tsh;
  int tsslen;
  int i;
  u8 *p,*end;

  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_NEW_RX,"xLbxdxp",ikemesg,"PROTO_IKE_PAYLOAD",payload_id,payloadh,payload_len,payload,payload_len,payloadh);

  if( payload_len <= (int)sizeof(rhp_proto_ike_ts_payload) ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_NEW_RX_INVALID_MESG_1,"xdd",ikemesg,payload_len,sizeof(rhp_proto_ike_ts_payload));
    goto error;
  }

  tsslen = payload_len - sizeof(rhp_proto_ike_ts_payload);
  if( tsslen < (int)RHP_PROTO_IKE_TS_MIN_SIZE ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_NEW_RX_INVALID_MESG_2,"xdd",ikemesg,tsslen,RHP_PROTO_IKE_TS_MIN_SIZE);
    goto error;
  }

  ts_payload = rhp_ikev2_alloc_ts_payload();
  if( ts_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.ts = ts_payload;
  payload->ext_destructor = _rhp_ikev2_ts_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_ts_payload_serialize;

  ts_payloadh = (rhp_proto_ike_ts_payload*)_rhp_pkt_pull(ikemesg->rx_pkt,payload_len);
  if( ts_payloadh == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_NEW_RX_INVALID_MESG_3,"x",ikemesg);
    goto error;
  }

  p = (u8*)(ts_payloadh + 1);
  end = ((u8*)ts_payloadh) + payload_len;

  if( ts_payloadh->ts_num == 0 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_NEW_RX_INVALID_MESG_4,"x",ikemesg);
    goto error;
  }

  for( i = 0; i < ts_payloadh->ts_num;i++ ){

  	int ts_len;

  	if( p >= end ){
  		break;
  	}

  	tsh = (rhp_proto_ike_ts_selector*)p;
  	ts_len = ntohs(tsh->len);

  	if( tsh->ts_type == RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE ){

  		if( ts_len != RHP_PROTO_IKE_TS_IPV4_SIZE ){
  			err = RHP_STATUS_INVALID_MSG;
  			RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_NEW_RX_INVALID_MESG_5,"x",ikemesg,ts_len,RHP_PROTO_IKE_TS_IPV4_SIZE);
  			goto error;
      }

  	}else if( tsh->ts_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){

    	if( ts_len != RHP_PROTO_IKE_TS_IPV6_SIZE ){
    		err = RHP_STATUS_INVALID_MSG;
  			RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_NEW_RX_INVALID_MESG_6,"x",ikemesg,ts_len,RHP_PROTO_IKE_TS_IPV6_SIZE);
    		goto error;
      }

  	}else{
  		err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_NEW_RX_INVALID_MESG_7,"x",ikemesg);
			goto error;
    }

  	err = ts_payload->put_ts_rx(payload,tsh);
  	if( err ){
			RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_NEW_RX_PUT_TS_ERR,"xE",ikemesg,err);
  		goto error;
    }

  	p = ((u8*)tsh) + ts_len;
  }

  if( i != ts_payloadh->ts_num ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_NEW_RX_INVALID_MESG_8,"xdd",ikemesg,i,ts_payloadh->ts_num);
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_NEW_RX_RTRN,"xx",ikemesg,payload);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_NEW_RX_ERR,"xxE",ikemesg,payload,err);
  return err;
}

int rhp_ikev2_ts_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_ts_payload* ts_payload;

  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_NEW_TX,"xLbx",ikemesg,"PROTO_IKE_PAYLOAD",payload_id,payload);

  ts_payload = rhp_ikev2_alloc_ts_payload();
  if( ts_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.ts = ts_payload;
  payload->ext_destructor = _rhp_ikev2_ts_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_ts_payload_serialize;

  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_NEW_TX_RTRN,"xx",ikemesg,payload);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_TS_PAYLOAD_NEW_TX_ERR,"xxE",ikemesg,payload,err);
  return err;
}

int rhp_ikev2_ts_cmp_ts2tss_same_or_any(rhp_ikev2_traffic_selector* ts,rhp_ikev2_traffic_selector* tss_head)
{
	rhp_ikev2_traffic_selector* ts_d = tss_head;

  RHP_TRC(0,RHPTRCID_IKEV2_TS_CMP_TS2TSS_SAME_OR_ANY,"xx",ts,tss_head);

	while( ts_d ){

		if( ts->get_ts_type(ts) == ts_d->get_ts_type(ts_d) &&
				rhp_ikev2_ts_is_any(ts_d) ){
		  RHP_TRC(0,RHPTRCID_IKEV2_TS_CMP_TS2TSS_SAME_OR_ANY_ANY,"xx",ts,ts_d);
			return 0;
		}

		if( !rhp_ikev2_ts_cmp(ts,ts_d) ){
		  RHP_TRC(0,RHPTRCID_IKEV2_TS_CMP_TS2TSS_SAME_OR_ANY_SAME,"xx",ts,ts_d);
			return 0;
		}

		{
			u8 ts_d_proto = ts_d->get_protocol(ts_d);
			rhp_ip_addr ts_start_addr, ts_end_addr;

			if( !ts->get_start_addr(ts,&ts_start_addr) &&
					!ts->get_end_addr(ts,&ts_end_addr) ){

				if( ts_d_proto == 0 &&
						ts_d->addr_is_included(ts_d,&ts_start_addr) &&
						ts_d->addr_is_included(ts_d,&ts_end_addr) ){
				  RHP_TRC(0,RHPTRCID_IKEV2_TS_CMP_TS2TSS_SAME_OR_ANY_ADDR_INCLUDED_AND_PROTO_ANY,"xx",ts,ts_d);
					return 0;
				}
			}
		}

		ts_d = ts_d->next;
	}

  RHP_TRC(0,RHPTRCID_IKEV2_TS_CMP_TS2TSS_SAME_OR_ANY_RTRN,"x",ts);
	return 1;
}

int rhp_ikev2_ts_cmp_ts2cfg_tss_same_or_any(rhp_ikev2_traffic_selector* ts,rhp_traffic_selector* cfg_tss_head)
{
	rhp_traffic_selector* cfg_ts_d = cfg_tss_head;

  RHP_TRC(0,RHPTRCID_IKEV2_TS_CMP_TS2TSS_CFG_SAME_OR_ANY,"xx",ts,cfg_tss_head);

	while( cfg_ts_d ){

		if( ts->get_ts_type(ts) == cfg_ts_d->ts_type &&
				rhp_cfg_is_any_traffic_selector(cfg_ts_d) ){
		  RHP_TRC(0,RHPTRCID_IKEV2_TS_CMP_TS2TSS_CFG_SAME_OR_ANY_IS_ANY,"xx",ts,cfg_ts_d);
			return 0;
		}

		if( !rhp_ikev2_ts_cmp_ts2cfg(ts,cfg_ts_d) ){
		  RHP_TRC(0,RHPTRCID_IKEV2_TS_CMP_TS2TSS_CFG_SAME_OR_ANY_IS_SAME,"xx",ts,cfg_ts_d);
			return 0;
		}

		cfg_ts_d = cfg_ts_d->next;
	}

  RHP_TRC(0,RHPTRCID_IKEV2_TS_CMP_TS2TSS_CFG_SAME_OR_ANY_RTRN,"x",ts);
	return 1;
}

