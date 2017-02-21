/*

	Copyright (C) 2009-2016 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.

	This library may be distributed, used, and modified under the terms of
	BSD license:

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are
	met:

	1. Redistributions of source code must retain the above copyright
		 notice, this list of conditions and the following disclaimer.

	2. Redistributions in binary form must reproduce the above copyright
		 notice, this list of conditions and the following disclaimer in the
		 documentation and/or other materials provided with the distribution.

	3. Neither the name(s) of the above-listed copyright holder(s) nor the
		 names of its contributors may be used to endorse or promote products
		 derived from this software without specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
	"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
	LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
	A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
	OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
	SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
	LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
	DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
	THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
	OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <stdarg.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <byteswap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <sys/capability.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <linux/errqueue.h>
#include <net/if.h>


#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_protocol.h"
#include "rhp_packet.h"
#include "rhp_netsock.h"
#include "rhp_wthreads.h"
#include "rhp_process.h"
#include "rhp_packet.h"
#include "rhp_config.h"
#include "rhp_ikev2_mesg.h"
#include "rhp_vpn.h"
#include "rhp_ikev2.h"
#include "rhp_eap.h"
#include "rhp_radius_impl.h"
#include "rhp_nhrp.h"

static __thread char _rhp_log_record_buf[RHP_LOG_MAX_RECORD_BUF_SIZE];
static __thread int _rhp_log_record_buf_rem;
static __thread char* _rhp_log_record_buf_cur_pt;

extern void rhp_ui_log_write(unsigned long event_source,unsigned long vpn_realm_id,
		unsigned long level,unsigned long log_id,struct timeval* timestamp,char* log_content,int log_conntent_len,int misc_log);

extern int rhp_ui_log_get_record_num(RHP_LOG_GET_RECORD_NUM_CB callback,void* ctx);
extern int rhp_ui_log_reset(RHP_LOG_RESET_CB callback,void* ctx);
extern int rhp_ui_log_save(int file_type,char* file_name,unsigned long vpn_realm_id,int limit_num,RHP_LOG_SAVE_CB callback,void* ctx);


static int _rhp_log_debug_level = 0;
static int _rhp_log_disabled = 0;

#define RHP_LOG_LIB_INVALID_DATA_LEN	16
static char _rhp_log_dmy_invalid_data[RHP_LOG_LIB_INVALID_DATA_LEN];


void rhp_log_enable_debug_level(int flag)
{
	_rhp_log_debug_level = flag;
}

int rhp_log_debug_level_enabled()
{
	return _rhp_log_debug_level;
}


void rhp_log_disable(int flag)
{
	_rhp_log_disabled = flag;
}

static void _rhp_log_record_init(unsigned long event_source,unsigned long vpn_realm_id,
		unsigned long level,unsigned long log_id,struct timeval* timestamp)
{
  int n;
  struct tm ts;

  if( vpn_realm_id == RHP_VPN_REALM_ID_UNKNOWN ){
  	vpn_realm_id = 0;
  }

  _rhp_log_record_buf_rem = RHP_LOG_MAX_RECORD_BUF_SIZE - 2; // ']}'
  _rhp_log_record_buf_cur_pt = _rhp_log_record_buf + 1; // '{'

  _rhp_log_record_buf[0] = '{';
  _rhp_log_record_buf[1] = '\0';

  n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
  		"\"src\":\"%lu\",\"realm\":\"%lu\",\"lv\":\"%lu\",\"id\":\"%lu\"",event_source,vpn_realm_id,level,log_id);
  _rhp_log_record_buf_cur_pt += n;
  _rhp_log_record_buf_rem -= n;

  localtime_r( &(timestamp->tv_sec), &ts );

  n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
  		",\"ts\":\"%d-%02d-%02d %02d:%02d:%02d.%06ld\"",
  		ts.tm_year + 1900,ts.tm_mon + 1, ts.tm_mday, ts.tm_hour, ts.tm_min, ts.tm_sec,
  		timestamp->tv_usec);
  _rhp_log_record_buf_cur_pt += n;
  _rhp_log_record_buf_rem -= n;

  n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,",\"args\":[");
  _rhp_log_record_buf_cur_pt += n;
  _rhp_log_record_buf_rem -= n;

  return;
}

static int _rhp_log_record_term()
{
	int n;

  n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"]}");
  if( n == _rhp_log_record_buf_rem ){
  	RHP_BUG("");
  	return -EINVAL;
  }
  _rhp_log_record_buf_cur_pt += n;
  _rhp_log_record_buf_rem -= n;

  return 0;
}


static __thread char _rhp_log_bin_record_buf[RHP_LOG_MAX_BIN_RECORD_BUF_SIZE];
static __thread int _rhp_log_bin_record_buf_rem;
static __thread char* _rhp_log_bin_record_buf_cur_pt;

static int _rhp_log_bin_dump_check(int n)
{
  if( n >= _rhp_log_bin_record_buf_rem ){
  	return -EINVAL;
  }
  _rhp_log_bin_record_buf_cur_pt += n;
  _rhp_log_bin_record_buf_rem -= n;
  return 0;
}

static void _rhp_log_bin_dump_term(char* buf)
{
	buf[0] = '<';
	buf[1] = 'b';
	buf[2] = 'r';
	buf[3] = '>';
	buf[4] = '\0';
}

static void _rhp_log_bin_dump(int len,unsigned char* d,int scale,int str)
{
  int i, n;

  _rhp_log_bin_record_buf_cur_pt = _rhp_log_bin_record_buf;
  _rhp_log_bin_record_buf_rem = RHP_LOG_MAX_BIN_RECORD_BUF_SIZE - 5; // last '<br>\0'

	if( !str ){
		n = snprintf(_rhp_log_bin_record_buf_cur_pt,_rhp_log_bin_record_buf_rem, "<br>" );
	}else{
		n = snprintf(_rhp_log_bin_record_buf_cur_pt,_rhp_log_bin_record_buf_rem, " " );
	}
	_rhp_log_bin_dump_check(n);

  if( scale ){

    n = snprintf(_rhp_log_bin_record_buf_cur_pt,_rhp_log_bin_record_buf_rem,
    		"%d(bytes)<br>*0 *1 *2 *3 *4 *5 *6 *7 *8 *9 *A *B *C *D *E *F<br>", len );
    _rhp_log_bin_dump_check(n);
  }

  if( len <= 0 || d == NULL ){
  	n = snprintf(_rhp_log_bin_record_buf_cur_pt,_rhp_log_bin_record_buf_rem, "--NO DATA--<br>" );
    _rhp_log_bin_dump_term(_rhp_log_bin_record_buf_cur_pt);
    return;
  }

  for(i = 0; i < len; i++){

    int pd;

    if(i && (i % 16) == 0){

    	if( !str ){
    		n = snprintf(_rhp_log_bin_record_buf_cur_pt,_rhp_log_bin_record_buf_rem, "<br>" );
    		if( _rhp_log_bin_dump_check(n) ){
    			_rhp_log_bin_dump_term(_rhp_log_bin_record_buf_cur_pt);
    			return;
    		}
    	}
    }

    pd = ((*(int *) d) & 0x000000FF);

    if( str ){

    	if( pd == '\\' ){
    		n = snprintf(_rhp_log_bin_record_buf_cur_pt,_rhp_log_bin_record_buf_rem, "%s", "\\" );
    	}else	if( pd == '"' ){
    		n = snprintf(_rhp_log_bin_record_buf_cur_pt,_rhp_log_bin_record_buf_rem, "%s", "\\\"" );
    	}else	if( pd == '\r' ){
    		n = snprintf(_rhp_log_bin_record_buf_cur_pt,_rhp_log_bin_record_buf_rem, "%s", " CR " );
    	}else	if( pd == '\n' ){
    		n = snprintf(_rhp_log_bin_record_buf_cur_pt,_rhp_log_bin_record_buf_rem, "%s", " LF " );
    	}else if( pd >= 32 && pd <= 126 ){
    		n = snprintf(_rhp_log_bin_record_buf_cur_pt,_rhp_log_bin_record_buf_rem, "%c", pd );
    	}else{
  			n = snprintf(_rhp_log_bin_record_buf_cur_pt,_rhp_log_bin_record_buf_rem, " %02x ", pd );
    	}

    }else{

    	n = snprintf(_rhp_log_bin_record_buf_cur_pt,_rhp_log_bin_record_buf_rem, "%02x ", pd );
    }

		if( _rhp_log_bin_dump_check(n) ){
			_rhp_log_bin_dump_term(_rhp_log_bin_record_buf_cur_pt);
			return;
		}

    d++;
  }

  _rhp_log_bin_dump_term(_rhp_log_bin_record_buf_cur_pt);
  return;
}

extern char* rhp_eap_method2str_def(int method);

static int _rhp_log_record_add_arg2(char fmt_type,int value_len,void* value,
		int value_len2,void* value2)
{
	int n = 0;

	if( strncmp((_rhp_log_record_buf_cur_pt - 8),"\"args\":[",8) ){

    n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,",");

		if( n == _rhp_log_record_buf_rem ){
			RHP_BUG("");
			return -EINVAL;
		}

		_rhp_log_record_buf_cur_pt += n;
		_rhp_log_record_buf_rem -= n;
	}

	switch(fmt_type){

    case 'b':
      n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"%d\"",*((u_int8_t*)value));
      break;

    case 'w':
    case 'W':
      n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"%d\"",*((u_int16_t*)value));
      break;

    case 'd':
    case 'D':
      n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"%d\"",*((int*)value));
      break;

    case 'j':
    case 'J':
      n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"%u\"",*((unsigned int*)value));
      break;

    case 'x':
    case 'X':
      n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"0x%lx\"",*((unsigned long*)value));
      break;

    case 'u':
    case 'U':
      n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"%lu\"",*((unsigned long*)value));
      break;

    case '4':
      n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"%d.%d.%d.%d\"",
      		((u_int8_t*)value)[0],((u_int8_t*)value)[1],((u_int8_t*)value)[2],((u_int8_t*)value)[3]);
      break;

    case 'E':
      n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"#E(%d)#\"",*((int*)value));
      break;

    case 'q':
    case 'Q':
      n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"%llu\"",
      		(long long unsigned int)*((u_int64_t*)value));
      break;

    case 's':
      n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"%s\"",(char*)value);
      break;

    case '6':

    	if( value == NULL ){

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>null<br>\"");

    	}else{

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
						"\"%s\"",rhp_ipv6_string((u8*)value));
    	}
      break;

    case 'M':

    	if( value == NULL ){

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>null<br>\"");

    	}else{

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
						"\"%02x:%02x:%02x:%02x:%02x:%02x\"",
						((u_int8_t*)value)[0],((u_int8_t*)value)[1],((u_int8_t*)value)[2],((u_int8_t*)value)[3],
						((u_int8_t*)value)[4],((u_int8_t*)value)[5]);
    	}
      break;

    case 'H':

      n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
      		"\"%u(0x%02x)\"",ntohl( *((u_int32_t*)value) ),ntohl( *((u_int32_t*)value) ));
      break;

    case 'G':

    	if( value == NULL ){

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>null<br>\"");

    	}else{

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
						"\"%llu(0x%02x%02x%02x%02x%02x%02x%02x%02x)\"", (long long unsigned int)bswap_64(*(u_int64_t*)value),
						(((u_int8_t*)value)[0]), (((u_int8_t*)value)[1]),
						(((u_int8_t*)value)[2]), (((u_int8_t*)value)[3]),
						(((u_int8_t*)value)[4]), (((u_int8_t*)value)[5]),
						(((u_int8_t*)value)[6]), (((u_int8_t*)value)[7]));
    	}
      break;

    case 'I':
    {
    	rhp_ikev2_id* id = (rhp_ikev2_id*)value;
    	char* id_type_r;
    	char* id_str_r;
    	char* alt_id_type_r = NULL;
    	char* alt_id_str_r = NULL;

    	if( value == NULL ){

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>null<br>\"");

    	}else{

				if( !rhp_ikev2_id_to_string(id,&id_type_r,&id_str_r) ){

					if( id->alt_id ){
						rhp_ikev2_id_to_string(id->alt_id,&alt_id_type_r,&alt_id_str_r);
					}

					n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
							"\"%s[%s] (alt: %s[%s])\"",id_str_r,id_type_r,
							(alt_id_str_r ? alt_id_str_r : "-"),
							(alt_id_type_r ? alt_id_type_r : "-"));

					_rhp_free(id_type_r);
					_rhp_free(id_str_r);

					if( alt_id_str_r ){
						_rhp_free(alt_id_str_r);
						_rhp_free(alt_id_type_r);
					}

				}else{

					n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"null\"");
				}
    	}
    }
      break;

    case 'e':
    {
    	rhp_eap_id* id = (rhp_eap_id*)value;

    	if( value == NULL ){

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>null<br>\"");

    	}else{

    		if( id->method != RHP_PROTO_EAP_TYPE_PRIV_RADIUS ){

					n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
							"\"%s: %s(%d)\"",
							rhp_eap_method2str_def(id->method),
							((id->identity && id->identity_len > 0 && id->identity[id->identity_len] == '\0') ? (char*)id->identity : "unknown"),
							id->identity_len);

    		}else{

					n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
							"\"%s-%s: %s(%d) usr_idx:%s assigned_ipv4:%d.%d.%d.%d assigned_ipv6:%s salt:0x%x\"",
							rhp_eap_method2str_def(id->method),
							rhp_eap_method2str_def(id->radius.eap_method),
							(id->identity && id->identity_len > 0 && id->identity[id->identity_len] == '\0' ? (char*)id->identity : "unknown"),
							id->identity_len,
							(id->radius.user_index ? id->radius.user_index : "null"),
							(id->radius.assigned_addr_v4 ? ((u8*)&(id->radius.assigned_addr_v4->addr.v4))[0] : 0),
							(id->radius.assigned_addr_v4 ? ((u8*)&(id->radius.assigned_addr_v4->addr.v4))[1] : 0),
							(id->radius.assigned_addr_v4 ? ((u8*)&(id->radius.assigned_addr_v4->addr.v4))[2] : 0),
							(id->radius.assigned_addr_v4 ? ((u8*)&(id->radius.assigned_addr_v4->addr.v4))[3] : 0),
							(id->radius.assigned_addr_v6 ? rhp_ipv6_string(id->radius.assigned_addr_v6->addr.v6) : " ::"),
							id->radius.salt);
    		}
    	}
    }
      break;

    case 'A':
    {
    	rhp_ip_addr* ip = (rhp_ip_addr*)value;

    	if( value == NULL ){

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>null<br>\"");

    	}else{

    		if( ip->addr_family == AF_INET ){

					if( ip->prefixlen ){

						n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"%d.%d.%d.%d/%d\"",
								((u_int8_t*)&(ip->addr.v4))[0],((u_int8_t*)&(ip->addr.v4))[1],
								((u_int8_t*)&(ip->addr.v4))[2],((u_int8_t*)&(ip->addr.v4))[3],ip->prefixlen);

					}else if( ip->port ){

						n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"%d.%d.%d.%d:%d\"",
								((u_int8_t*)&(ip->addr.v4))[0],((u_int8_t*)&(ip->addr.v4))[1],
								((u_int8_t*)&(ip->addr.v4))[2],((u_int8_t*)&(ip->addr.v4))[3],ntohs(ip->port));

					}else{

						n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"%d.%d.%d.%d\"",
								((u_int8_t*)&(ip->addr.v4))[0],((u_int8_t*)&(ip->addr.v4))[1],
								((u_int8_t*)&(ip->addr.v4))[2],((u_int8_t*)&(ip->addr.v4))[3]);
					}

				}else if( ip->addr_family == AF_INET6 ){

					if( ip->prefixlen ){

						n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
								"\"%s/%d\"",rhp_ipv6_string(ip->addr.v6),ip->prefixlen);

					}else if( ip->port ){

						n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
								"\"%s:%d\"",rhp_ipv6_string(ip->addr.v6),ntohs(ip->port));

					}else{

						n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
								"\"%s\"",rhp_ipv6_string(ip->addr.v6));
					}

				}else{

					n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"unknown\"");
				}
    	}
    }
      break;

    case 'F':
    {
    	rhp_if_entry* ifent = (rhp_if_entry*)value;

    	if( value == NULL ){

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>null<br>\"");

    	}else if( ifent->addr_family == AF_INET ){

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
								"\"%s(%d.%d.%d.%d/%d, %02x:%02x:%02x:%02x:%02x:%02x) ifindex: %d  MTU: %u  %s\"",
								ifent->if_name,
								((u_int8_t*)&(ifent->addr.v4))[0],((u_int8_t*)&(ifent->addr.v4))[1],
								((u_int8_t*)&(ifent->addr.v4))[2],((u_int8_t*)&(ifent->addr.v4))[3],ifent->prefixlen,
								ifent->mac[0],ifent->mac[1],ifent->mac[2],
								ifent->mac[3],ifent->mac[4],ifent->mac[5],
								ifent->if_index,ifent->mtu,((ifent->if_flags & IFF_UP) ? "UP" : "DOWN"));

    	}else if( ifent->addr_family == AF_INET6 ){

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
								"\"%s(%s/%d, %02x:%02x:%02x:%02x:%02x:%02x) ifindex: %d  MTU: %u  %s\"",
								ifent->if_name,
								rhp_ipv6_string(ifent->addr.v6),
								ifent->prefixlen,
								ifent->mac[0],ifent->mac[1],ifent->mac[2],
								ifent->mac[3],ifent->mac[4],ifent->mac[5],
								ifent->if_index,ifent->mtu,((ifent->if_flags & IFF_UP) ? "UP" : "DOWN"));

    	}else{

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
								"\"%s(No IP, %02x:%02x:%02x:%02x:%02x:%02x) ifindex: %d  MTU: %u  %s\"",
								ifent->if_name,
								ifent->mac[0],ifent->mac[1],ifent->mac[2],
								ifent->mac[3],ifent->mac[4],ifent->mac[5],
								ifent->if_index,ifent->mtu,((ifent->if_flags & IFF_UP) ? "UP" : "DOWN"));
    	}
    }
      break;

    case 'N':

    	if( value == NULL ){

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>null<br>\"");

    	}else{

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
						"\"0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\"",
						(((u_int8_t*)value)[0]), (((u_int8_t*)value)[1]),
						(((u_int8_t*)value)[2]), (((u_int8_t*)value)[3]),
						(((u_int8_t*)value)[4]), (((u_int8_t*)value)[5]),
						(((u_int8_t*)value)[6]), (((u_int8_t*)value)[7]),
						(((u_int8_t*)value)[8]), (((u_int8_t*)value)[9]),
						(((u_int8_t*)value)[10]), (((u_int8_t*)value)[11]),
						(((u_int8_t*)value)[12]), (((u_int8_t*)value)[13]),
						(((u_int8_t*)value)[14]), (((u_int8_t*)value)[15]));
    	}
      break;

    case 'L':

    	if( value == NULL ){

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>null<br>\"");

    	}else{

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
      		"\"#L#%s,%d##\"",(char*)value,*((int*)value2));
    	}
      break;

    case 'p':

      _rhp_log_bin_dump(*((int*)value),(unsigned char*)value2,0,0);
      n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"%s\"",(char*)_rhp_log_bin_record_buf);
      break;

    case 'a':

      _rhp_log_bin_dump(*((int*)value),(unsigned char*)value2,0,1);
      n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"%s\"",(char*)_rhp_log_bin_record_buf);
      break;

    case 'K':
    {
    	if( value == NULL ){

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>null<br>\"");

    	}else{

    		rhp_ikev2_mesg* ikemesg = (rhp_ikev2_mesg*)value;
    		u8 spi_dmy[8] = {0,0,0,0,0,0,0,0};

    		{
					if( ((u8*)value)[0] != '#' || ((u8*)value)[1] != 'I' || ((u8*)value)[2] != 'K' || ((u8*)value)[3] != 'M' ){
	      		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>Invalid ikemesg<br>\"");
						break;
					}
/*
					if( ikemesg->rx_pkt == NULL ){

						n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>null<br>\"");

					}else*/{

						u8* init_spi = ikemesg->get_init_spi(ikemesg);
						u8* resp_spi = ikemesg->get_resp_spi(ikemesg);
						u8  exchg_type = ikemesg->get_exchange_type(ikemesg);
						int is_initiator = ikemesg->is_initiator(ikemesg);
						int is_request = ikemesg->is_request(ikemesg);
						u32 mesg_id = ikemesg->get_mesg_id(ikemesg);
						rhp_ip_addr src_addr;
						rhp_ip_addr dst_addr;


						if( init_spi == NULL ){
							init_spi = spi_dmy;
						}
						if( resp_spi == NULL ){
							resp_spi = spi_dmy;
						}
						memset(&src_addr,0,sizeof(rhp_ip_addr));
						memset(&dst_addr,0,sizeof(rhp_ip_addr));
						src_addr.addr_family = AF_UNSPEC;
						dst_addr.addr_family = AF_UNSPEC;

						if( ikemesg->rx_pkt ){
							ikemesg->rx_get_src_addr(ikemesg,&src_addr);
							ikemesg->rx_get_dst_addr(ikemesg,&dst_addr);
						}

						if( src_addr.addr_family == AF_INET && dst_addr.addr_family == AF_INET ){

							n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
									"\"<br>%d.%d.%d.%d:%d --> %d.%d.%d.%d:%d<br>[%s] #L#%s,%lu##(%s) ID:%u<br>SPI_I: %llu(0x%02x%02x%02x%02x%02x%02x%02x%02x)<br>SPI_R: %llu(0x%02x%02x%02x%02x%02x%02x%02x%02x)<br>\"",
									((u_int8_t*)&(src_addr.addr.v4))[0],((u_int8_t*)&(src_addr.addr.v4))[1],
									((u_int8_t*)&(src_addr.addr.v4))[2],((u_int8_t*)&(src_addr.addr.v4))[3],
									(int)ntohs(src_addr.port),
									((u_int8_t*)&(dst_addr.addr.v4))[0],((u_int8_t*)&(dst_addr.addr.v4))[1],
									((u_int8_t*)&(dst_addr.addr.v4))[2],((u_int8_t*)&(dst_addr.addr.v4))[3],
									(int)ntohs(dst_addr.port),
									(is_initiator ? "INITIATOR" : "RESPONDER"),
									"PROTO_IKE_EXCHG",(unsigned long)exchg_type,
									(is_request ? "REQ" : "RESP"),
									mesg_id,
									(long long unsigned int)bswap_64(*((u_int64_t*)init_spi)),
									(((u_int8_t*)init_spi)[0]), (((u_int8_t*)init_spi)[1]),
									(((u_int8_t*)init_spi)[2]), (((u_int8_t*)init_spi)[3]),
									(((u_int8_t*)init_spi)[4]), (((u_int8_t*)init_spi)[5]),
									(((u_int8_t*)init_spi)[6]), (((u_int8_t*)init_spi)[7]),
									(long long unsigned int)bswap_64(*((u_int64_t*)resp_spi)),
									(((u_int8_t*)resp_spi)[0]), (((u_int8_t*)resp_spi)[1]),
									(((u_int8_t*)resp_spi)[2]), (((u_int8_t*)resp_spi)[3]),
									(((u_int8_t*)resp_spi)[4]), (((u_int8_t*)resp_spi)[5]),
									(((u_int8_t*)resp_spi)[6]), (((u_int8_t*)resp_spi)[7])
									);

						}else	if( src_addr.addr_family == AF_INET6 && dst_addr.addr_family == AF_INET6 ){

							char ipv6_src_addr_str[INET6_ADDRSTRLEN + 1],
									 ipv6_dst_addr_str[INET6_ADDRSTRLEN + 1];

							n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
									"\"<br>%s:%d --> %s:%d<br>[%s]<br>#L#%s,%lu##(%s) ID:%u<br>SPI_I: %llu(0x%02x%02x%02x%02x%02x%02x%02x%02x)<br>SPI_R: %llu(0x%02x%02x%02x%02x%02x%02x%02x%02x)<br>\"",
									rhp_ipv6_string2(src_addr.addr.v6,ipv6_src_addr_str),
									(int)ntohs(src_addr.port),
									rhp_ipv6_string2(dst_addr.addr.v6,ipv6_dst_addr_str),
									(int)ntohs(dst_addr.port),
									(is_initiator ? "INITIATOR" : "RESPONDER"),
									"PROTO_IKE_EXCHG",(unsigned long)exchg_type,
									(is_request ? "REQ" : "RESP"),
									mesg_id,
									(long long unsigned int)bswap_64(*((u_int64_t*)init_spi)),
									(((u_int8_t*)init_spi)[0]), (((u_int8_t*)init_spi)[1]),
									(((u_int8_t*)init_spi)[2]), (((u_int8_t*)init_spi)[3]),
									(((u_int8_t*)init_spi)[4]), (((u_int8_t*)init_spi)[5]),
									(((u_int8_t*)init_spi)[6]), (((u_int8_t*)init_spi)[7]),
									(long long unsigned int)bswap_64(*((u_int64_t*)resp_spi)),
									(((u_int8_t*)resp_spi)[0]), (((u_int8_t*)resp_spi)[1]),
									(((u_int8_t*)resp_spi)[2]), (((u_int8_t*)resp_spi)[3]),
									(((u_int8_t*)resp_spi)[4]), (((u_int8_t*)resp_spi)[5]),
									(((u_int8_t*)resp_spi)[6]), (((u_int8_t*)resp_spi)[7])
									);

						}else{

							n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
									"\"<br>unknown --> unknown<br>[%s] #L#%s,%lu##(%s) ID:%u<br>SPI_I: %llu(0x%02x%02x%02x%02x%02x%02x%02x%02x)<br>SPI_R: %llu(0x%02x%02x%02x%02x%02x%02x%02x%02x)<br>\"",
									(is_initiator ? "INITIATOR" : "RESPONDER"),
									"PROTO_IKE_EXCHG",(unsigned long)exchg_type,
									(is_request ? "REQ" : "RESP"),
									mesg_id,
									(long long unsigned int)bswap_64(*((u_int64_t*)init_spi)),
									(((u_int8_t*)init_spi)[0]), (((u_int8_t*)init_spi)[1]),
									(((u_int8_t*)init_spi)[2]), (((u_int8_t*)init_spi)[3]),
									(((u_int8_t*)init_spi)[4]), (((u_int8_t*)init_spi)[5]),
									(((u_int8_t*)init_spi)[6]), (((u_int8_t*)init_spi)[7]),
									(long long unsigned int)bswap_64(*((u_int64_t*)resp_spi)),
									(((u_int8_t*)resp_spi)[0]), (((u_int8_t*)resp_spi)[1]),
									(((u_int8_t*)resp_spi)[2]), (((u_int8_t*)resp_spi)[3]),
									(((u_int8_t*)resp_spi)[4]), (((u_int8_t*)resp_spi)[5]),
									(((u_int8_t*)resp_spi)[6]), (((u_int8_t*)resp_spi)[7])
									);
						}
					}
				}
    	}
    }
      break;

    case 'V':
    {
    	if( value == NULL ){

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>null<br>\"");

    	}else{

    		rhp_vpn* vpn = (rhp_vpn*)value;
      	char* myid_type_r = NULL;
      	char* myid_str_r = NULL;
      	char* peerid_type_r = NULL;
      	char* peerid_str_r = NULL;
      	char* alt_peerid_type_r = NULL;
      	char* alt_peerid_str_r = NULL;
      	char* eap_my_id = NULL;
      	char* eap_peer_id = NULL;

    		if( ((u8*)value)[0] != '#' || ((u8*)value)[1] != 'V' || ((u8*)value)[2] != 'P' || ((u8*)value)[3] != 'N' ){
      		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>Invalid vpn<br>\"");
    			break;
    		}

      	rhp_ikev2_id_to_string(&(vpn->my_id),&myid_type_r,&myid_str_r);
      	rhp_ikev2_id_to_string(&(vpn->peer_id),&peerid_type_r,&peerid_str_r);

      	if( vpn->peer_id.alt_id ){
        	rhp_ikev2_id_to_string(vpn->peer_id.alt_id,&alt_peerid_type_r,&alt_peerid_str_r);
      	}

      	if( vpn->eap.my_id.method ){
      		eap_my_id = (char*)vpn->eap.my_id.identity;
      	}
      	if( vpn->eap.peer_id.method ){
      		eap_peer_id = (char*)vpn->eap.peer_id.identity;
      	}

				n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"");
    	  if( n >= _rhp_log_record_buf_rem ){
    	  	RHP_BUG("%d, %d",n,_rhp_log_record_buf_rem);
    	  	return -EINVAL;
    	  }
    	  _rhp_log_record_buf_cur_pt += n;
    	  _rhp_log_record_buf_rem -= n;

      	if( vpn->local.if_info.addr_family == AF_INET && vpn->peer_addr.addr_family == AF_INET ){

					n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
							"<br>Realm: %lu<br>%s[%s]:%s [%d.%d.%d.%d] --> %s[%s]:%s(alt: %s[%s]) [%d.%d.%d.%d]<br>UID: 0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x<br>",
							vpn->vpn_realm_id,
							myid_str_r,myid_type_r,(eap_my_id ? eap_my_id : "-"),
							((u_int8_t*)&(vpn->local.if_info.addr.v4))[0],((u_int8_t*)&(vpn->local.if_info.addr.v4))[1],
							((u_int8_t*)&(vpn->local.if_info.addr.v4))[2],((u_int8_t*)&(vpn->local.if_info.addr.v4))[3],
							peerid_str_r,peerid_type_r,(eap_peer_id ? eap_peer_id : "-"),
							( alt_peerid_str_r ? alt_peerid_str_r : "-"),( alt_peerid_type_r ? alt_peerid_type_r : "-"),
							((u_int8_t*)&(vpn->peer_addr.addr.v4))[0],((u_int8_t*)&(vpn->peer_addr.addr.v4))[1],
							((u_int8_t*)&(vpn->peer_addr.addr.v4))[2],((u_int8_t*)&(vpn->peer_addr.addr.v4))[3],
							(((u_int8_t*)vpn->unique_id)[0]), (((u_int8_t*)vpn->unique_id)[1]),
							(((u_int8_t*)vpn->unique_id)[2]), (((u_int8_t*)vpn->unique_id)[3]),
							(((u_int8_t*)vpn->unique_id)[4]), (((u_int8_t*)vpn->unique_id)[5]),
							(((u_int8_t*)vpn->unique_id)[6]), (((u_int8_t*)vpn->unique_id)[7]),
							(((u_int8_t*)vpn->unique_id)[8]), (((u_int8_t*)vpn->unique_id)[9]),
							(((u_int8_t*)vpn->unique_id)[10]), (((u_int8_t*)vpn->unique_id)[11]),
							(((u_int8_t*)vpn->unique_id)[12]), (((u_int8_t*)vpn->unique_id)[13]),
							(((u_int8_t*)vpn->unique_id)[14]), (((u_int8_t*)vpn->unique_id)[15])
					);

      	}else	if( vpn->local.if_info.addr_family == AF_INET6 && vpn->peer_addr.addr_family == AF_INET6 ){

					char ipv6_src_addr_str[INET6_ADDRSTRLEN + 1],
							 ipv6_dst_addr_str[INET6_ADDRSTRLEN + 1];

					n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
							"<br>Realm: %lu<br>%s[%s]:%s [%s] --> %s[%s]:%s(alt: %s[%s]) [%s]<br>UID: 0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x<br>",
							vpn->vpn_realm_id,
							myid_str_r,myid_type_r,(eap_my_id ? eap_my_id : "-"),
							rhp_ipv6_string2(vpn->local.if_info.addr.v6,ipv6_src_addr_str),
							peerid_str_r,peerid_type_r,(eap_peer_id ? eap_peer_id : "-"),
							( alt_peerid_str_r ? alt_peerid_str_r : "-"),( alt_peerid_type_r ? alt_peerid_type_r : "-"),
							rhp_ipv6_string2(vpn->peer_addr.addr.v6,ipv6_dst_addr_str),
							(((u_int8_t*)vpn->unique_id)[0]), (((u_int8_t*)vpn->unique_id)[1]),
							(((u_int8_t*)vpn->unique_id)[2]), (((u_int8_t*)vpn->unique_id)[3]),
							(((u_int8_t*)vpn->unique_id)[4]), (((u_int8_t*)vpn->unique_id)[5]),
							(((u_int8_t*)vpn->unique_id)[6]), (((u_int8_t*)vpn->unique_id)[7]),
							(((u_int8_t*)vpn->unique_id)[8]), (((u_int8_t*)vpn->unique_id)[9]),
							(((u_int8_t*)vpn->unique_id)[10]), (((u_int8_t*)vpn->unique_id)[11]),
							(((u_int8_t*)vpn->unique_id)[12]), (((u_int8_t*)vpn->unique_id)[13]),
							(((u_int8_t*)vpn->unique_id)[14]), (((u_int8_t*)vpn->unique_id)[15])
					);

      	}else{

					n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
							"<br>Realm: %lu<br>%s[%s]:%s [%s] --> %s[%s]:%s(alt: %s[%s]) [%s]<br>UID: 0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x<br>",
							vpn->vpn_realm_id,
							myid_str_r,myid_type_r,(eap_my_id ? eap_my_id : "-"),
							"unknown",
							peerid_str_r,peerid_type_r,(eap_peer_id ? eap_peer_id : "-"),
							( alt_peerid_str_r ? alt_peerid_str_r : "-"),( alt_peerid_type_r ? alt_peerid_type_r : "-"),
							"unknown",
							(((u_int8_t*)vpn->unique_id)[0]), (((u_int8_t*)vpn->unique_id)[1]),
							(((u_int8_t*)vpn->unique_id)[2]), (((u_int8_t*)vpn->unique_id)[3]),
							(((u_int8_t*)vpn->unique_id)[4]), (((u_int8_t*)vpn->unique_id)[5]),
							(((u_int8_t*)vpn->unique_id)[6]), (((u_int8_t*)vpn->unique_id)[7]),
							(((u_int8_t*)vpn->unique_id)[8]), (((u_int8_t*)vpn->unique_id)[9]),
							(((u_int8_t*)vpn->unique_id)[10]), (((u_int8_t*)vpn->unique_id)[11]),
							(((u_int8_t*)vpn->unique_id)[12]), (((u_int8_t*)vpn->unique_id)[13]),
							(((u_int8_t*)vpn->unique_id)[14]), (((u_int8_t*)vpn->unique_id)[15])
					);
      	}
    	  if( n >= _rhp_log_record_buf_rem ){
    	  	RHP_BUG("%d, %d",n,_rhp_log_record_buf_rem);
    	  	return -EINVAL;
    	  }
    	  _rhp_log_record_buf_cur_pt += n;
    	  _rhp_log_record_buf_rem -= n;


      	if( vpn->eap.eap_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS &&
      			vpn->eap.peer_id.radius.eap_method != RHP_PROTO_EAP_TYPE_NONE ){

        	rhp_eap_id* id = &(vpn->eap.peer_id);

					n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
							"[RADIUS peer-id] %s: %s(%d) usr_idx:%s assigned_ipv4:%d.%d.%d.%d assigned_ipv6:%s salt:0x%x<br>",
							rhp_eap_method2str_def(id->radius.eap_method),
							(id->identity && id->identity_len > 0 && id->identity[id->identity_len] == '\0' ? (char*)id->identity : "unknown"),
							id->identity_len,
							(id->radius.user_index ? id->radius.user_index : "null"),
							(id->radius.assigned_addr_v4 ? ((u8*)&(id->radius.assigned_addr_v4->addr.v4))[0] : 0),
							(id->radius.assigned_addr_v4 ? ((u8*)&(id->radius.assigned_addr_v4->addr.v4))[1] : 0),
							(id->radius.assigned_addr_v4 ? ((u8*)&(id->radius.assigned_addr_v4->addr.v4))[2] : 0),
							(id->radius.assigned_addr_v4 ? ((u8*)&(id->radius.assigned_addr_v4->addr.v4))[3] : 0),
							(id->radius.assigned_addr_v6 ? rhp_ipv6_string(id->radius.assigned_addr_v6->addr.v6) : " ::"),
							id->radius.salt);

					if( n >= _rhp_log_record_buf_rem ){
	    	  	RHP_BUG("%d, %d",n,_rhp_log_record_buf_rem);
	    	  	return -EINVAL;
	    	  }
	    	  _rhp_log_record_buf_cur_pt += n;
	    	  _rhp_log_record_buf_rem -= n;
      	}


      	n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"");


      	if( myid_type_r ){
      		_rhp_free(myid_type_r);
      		_rhp_free(myid_str_r);
      	}
      	if( peerid_type_r ){
      		_rhp_free(peerid_type_r);
      		_rhp_free(peerid_str_r);
      	}
      	if( alt_peerid_type_r ){
      		_rhp_free(alt_peerid_type_r);
      		_rhp_free(alt_peerid_str_r);
      	}
    	}
    }
      break;

    case 'P':
    {
    	if( value == NULL ){

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>null<br>\"");

    	}else{

    		rhp_ikesa* ikesa = (rhp_ikesa*)value;

    		if( ((u8*)value)[0] != '#' || ((u8*)value)[1] != 'I' || ((u8*)value)[2] != 'S' || ((u8*)value)[3] != 'A' ){
      		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>Invalid ikesa<br>\"");
    			break;
    		}

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
    				"\"<br>#L#%s,%lu##<br>SPI_I: %llu(0x%02x%02x%02x%02x%02x%02x%02x%02x)<br>SPI_R: %llu(0x%02x%02x%02x%02x%02x%02x%02x%02x)<br>#L#%s,%lu## REKEY: %d<br>\"",
						"IKE_SIDE",(unsigned long)ikesa->side,
						(long long unsigned int)bswap_64(*(u_int64_t*)ikesa->init_spi),
						(((u_int8_t*)ikesa->init_spi)[0]), (((u_int8_t*)ikesa->init_spi)[1]),
						(((u_int8_t*)ikesa->init_spi)[2]), (((u_int8_t*)ikesa->init_spi)[3]),
						(((u_int8_t*)ikesa->init_spi)[4]), (((u_int8_t*)ikesa->init_spi)[5]),
						(((u_int8_t*)ikesa->init_spi)[6]), (((u_int8_t*)ikesa->init_spi)[7]),
						(long long unsigned int)bswap_64(*(u_int64_t*)ikesa->resp_spi),
						(((u_int8_t*)ikesa->resp_spi)[0]), (((u_int8_t*)ikesa->resp_spi)[1]),
						(((u_int8_t*)ikesa->resp_spi)[2]), (((u_int8_t*)ikesa->resp_spi)[3]),
						(((u_int8_t*)ikesa->resp_spi)[4]), (((u_int8_t*)ikesa->resp_spi)[5]),
						(((u_int8_t*)ikesa->resp_spi)[6]), (((u_int8_t*)ikesa->resp_spi)[7]),
						"IKESA_STAT",(unsigned long)ikesa->state,ikesa->rekeyed_gen
    		);
    	}
    }
      break;

    case 'C':
    {
    	if( value == NULL ){

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>null<br>\"");

    	}else{

    		rhp_childsa* childsa = (rhp_childsa*)value;

    		if( ((u8*)value)[0] != '#' || ((u8*)value)[1] != 'C' || ((u8*)value)[2] != 'S' || ((u8*)value)[3] != 'A' ){
      		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>Invalid childsa<br>\"");
    			break;
    		}

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
    				"\"<br>#L#%s,%lu##<br>SPI_I: %u(0x%02x) SPI_O: %u(0x%02x)<br>#L#%s,%lu## REKEY: %d<br>\"",
						"IKE_SIDE",(unsigned long)childsa->side,
	      		ntohl(childsa->spi_inb),ntohl(childsa->spi_inb),
	      		ntohl(childsa->spi_outb),ntohl(childsa->spi_outb),
						"CHILDSA_STAT",(unsigned long)childsa->state,childsa->rekeyed_gen
    		);
    	}
    }
      break;

    case 'i':
    {
    	char if_name[IF_NAMESIZE];

    	if_name[0] = '\0';
    	if_indextoname(*((unsigned int*)value),if_name);

    	n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"%s(%u)\"",if_name,*((unsigned int*)value));
      break;
    }

    case 't':
    {
    	time_t t = *((time_t*)value);
    	time_t rt = _rhp_get_realtime() + t - _rhp_get_time();
			struct tm ts;

			localtime_r(&rt,&ts);

      n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
      		"\"%ld(RT: %ld - %d-%02d-%02d %02d:%02d:%02d)\"",t,rt,
      		ts.tm_year + 1900,ts.tm_mon + 1, ts.tm_mday, ts.tm_hour, ts.tm_min, ts.tm_sec);
      break;
    }

    case 'T':
    {
    	time_t rt = *((time_t*)value);
			struct tm ts;

			localtime_r(&rt,&ts);

      n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
      		"\"%ld(%d-%02d-%02d %02d:%02d:%02d)\"",rt,
      		ts.tm_year + 1900,ts.tm_mon + 1, ts.tm_mday, ts.tm_hour, ts.tm_min, ts.tm_sec);
      break;
    }

    case 'R':
    {
    	if( value == NULL ){

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>null<br>\"");

    	}else{

    		rhp_radius_mesg* radius_mesg = (rhp_radius_mesg*)value;

    		{
					if( ((u8*)value)[0] != '#' || ((u8*)value)[1] != 'R' || ((u8*)value)[2] != 'M' || ((u8*)value)[3] != 'G' ){
	      		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>Invalid radius_mesg<br>\"");
						break;
					}

					{
						u8 code = radius_mesg->get_code(radius_mesg);
						u8 id = radius_mesg->get_id(radius_mesg);
						u8* authenticator = radius_mesg->get_authenticator(radius_mesg);
		    		u8 authenticator_dmy[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
						rhp_ip_addr src_addr;
						rhp_ip_addr dst_addr;
					  rhp_radius_attr* radius_eap_attr = radius_mesg->get_attr_eap(radius_mesg,0,0);
					  rhp_proto_eap* eaph = NULL;
					  rhp_proto_eap_request eaph_r;

						memset(&src_addr,0,sizeof(rhp_ip_addr));
						memset(&dst_addr,0,sizeof(rhp_ip_addr));
						memset(&eaph_r,0,sizeof(rhp_proto_eap_request));

						radius_mesg->get_src_addr_port(radius_mesg,&src_addr);
						radius_mesg->get_dst_addr_port(radius_mesg,&dst_addr);

						if( authenticator == NULL ){
							authenticator = authenticator_dmy;
						}

						if( radius_eap_attr ){
							int eap_len = 0;
							eaph = radius_eap_attr->ext.eap->get_eap_packet(radius_eap_attr,&eap_len);
							if( eaph ){
								if( eap_len >= sizeof(rhp_proto_eap_request) && (eaph->code == RHP_PROTO_EAP_CODE_REQUEST || eaph->code == RHP_PROTO_EAP_CODE_RESPONSE) ){
									memcpy(&eaph_r,eaph,sizeof(rhp_proto_eap_request));
								}else if( eap_len >= sizeof(rhp_proto_eap) && (eaph->code == RHP_PROTO_EAP_CODE_SUCCESS || eaph->code == RHP_PROTO_EAP_CODE_FAILURE) ){
									memcpy(&eaph_r,eaph,sizeof(rhp_proto_eap));
								}
							}
						}

						if( src_addr.addr_family == AF_INET || dst_addr.addr_family == AF_INET ){

							n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
									"\"<br>%d.%d.%d.%d:%d --> %d.%d.%d.%d:%d<br> #L#%s,%lu## ID:%u<br>Authenticator: 0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x<br>%s code: #L#%s,%lu## id: %d type: #L#%s,%lu##<br>\"",
									((u_int8_t*)&(src_addr.addr.v4))[0],((u_int8_t*)&(src_addr.addr.v4))[1],
									((u_int8_t*)&(src_addr.addr.v4))[2],((u_int8_t*)&(src_addr.addr.v4))[3],
									(int)ntohs(src_addr.port),
									((u_int8_t*)&(dst_addr.addr.v4))[0],((u_int8_t*)&(dst_addr.addr.v4))[1],
									((u_int8_t*)&(dst_addr.addr.v4))[2],((u_int8_t*)&(dst_addr.addr.v4))[3],
									(int)ntohs(dst_addr.port),
									"RADIUS_CODE",(unsigned long)code,
									id,
									(((u_int8_t*)authenticator)[0]), (((u_int8_t*)authenticator)[1]),
									(((u_int8_t*)authenticator)[2]), (((u_int8_t*)authenticator)[3]),
									(((u_int8_t*)authenticator)[4]), (((u_int8_t*)authenticator)[5]),
									(((u_int8_t*)authenticator)[6]), (((u_int8_t*)authenticator)[7]),
									(((u_int8_t*)authenticator)[0]), (((u_int8_t*)authenticator)[1]),
									(((u_int8_t*)authenticator)[2]), (((u_int8_t*)authenticator)[3]),
									(((u_int8_t*)authenticator)[4]), (((u_int8_t*)authenticator)[5]),
									(((u_int8_t*)authenticator)[6]), (((u_int8_t*)authenticator)[7]),
									(eaph ? "EAP" : "No EAP Mesg"),
									"EAP_CODE",(unsigned long)eaph_r.code,
									eaph_r.identifier,
									"EAP_TYPE",(unsigned long)eaph_r.type
									);

						}else	if( src_addr.addr_family == AF_INET6 || dst_addr.addr_family == AF_INET6 ){

							char ipv6_src_addr_str[INET6_ADDRSTRLEN + 1],
									 ipv6_dst_addr_str[INET6_ADDRSTRLEN + 1];

							n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
									"\"<br>%s:%d --> %s:%d<br> #L#%s,%lu## ID:%u<br>Authenticator: 0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x<br>%s code: #L#%s,%lu## id: %d type: #L#%s,%lu##<br>\"",
									rhp_ipv6_string2(src_addr.addr.v6,ipv6_src_addr_str),
									(int)ntohs(src_addr.port),
									rhp_ipv6_string2(dst_addr.addr.v6,ipv6_dst_addr_str),
									(int)ntohs(dst_addr.port),
									"RADIUS_CODE",(unsigned long)code,
									id,
									(((u_int8_t*)authenticator)[0]), (((u_int8_t*)authenticator)[1]),
									(((u_int8_t*)authenticator)[2]), (((u_int8_t*)authenticator)[3]),
									(((u_int8_t*)authenticator)[4]), (((u_int8_t*)authenticator)[5]),
									(((u_int8_t*)authenticator)[6]), (((u_int8_t*)authenticator)[7]),
									(((u_int8_t*)authenticator)[0]), (((u_int8_t*)authenticator)[1]),
									(((u_int8_t*)authenticator)[2]), (((u_int8_t*)authenticator)[3]),
									(((u_int8_t*)authenticator)[4]), (((u_int8_t*)authenticator)[5]),
									(((u_int8_t*)authenticator)[6]), (((u_int8_t*)authenticator)[7]),
									(eaph ? "EAP" : "No EAP Mesg"),
									"EAP_CODE",(unsigned long)eaph_r.code,
									eaph_r.identifier,
									"EAP_TYPE",(unsigned long)eaph_r.type
									);

						}else{

							n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
									"\"<br>unknown --> unknown<br> #L#%s,%lu## ID:%u<br>Authenticator: 0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x<br>%s code: #L#%s,%lu## id: %d type: #L#%s,%lu##<br>\"",
									"RADIUS_CODE",(unsigned long)code,
									id,
									(((u_int8_t*)authenticator)[0]), (((u_int8_t*)authenticator)[1]),
									(((u_int8_t*)authenticator)[2]), (((u_int8_t*)authenticator)[3]),
									(((u_int8_t*)authenticator)[4]), (((u_int8_t*)authenticator)[5]),
									(((u_int8_t*)authenticator)[6]), (((u_int8_t*)authenticator)[7]),
									(((u_int8_t*)authenticator)[0]), (((u_int8_t*)authenticator)[1]),
									(((u_int8_t*)authenticator)[2]), (((u_int8_t*)authenticator)[3]),
									(((u_int8_t*)authenticator)[4]), (((u_int8_t*)authenticator)[5]),
									(((u_int8_t*)authenticator)[6]), (((u_int8_t*)authenticator)[7]),
									(eaph ? "EAP" : "No EAP Mesg"),
									"EAP_CODE",(unsigned long)eaph_r.code,
									eaph_r.identifier,
									"EAP_TYPE",(unsigned long)eaph_r.type
									);
						}
					}
				}
    	}
    }
      break;

    case 'r':
    {
    	if( value == NULL ){

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>null<br>\"");

    	}else{

    		rhp_radius_session* radius_sess = (rhp_radius_session*)value;

    		{
					if( ((u8*)value)[0] != '#' || ((u8*)value)[1] != 'R' || ((u8*)value)[2] != 'D' || ((u8*)value)[3] != 'S' ){
	      		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>Invalid radius_session<br>\"");
						break;
					}

					{
						unsigned long vpn_realm_id = radius_sess->get_realm_id(radius_sess);
						char* user_name = radius_sess->get_user_name(radius_sess);
						char* nas_id = radius_sess->get_nas_id(radius_sess);
						char* calling_station_id = radius_sess->get_calling_station_id(radius_sess);
						rhp_ikev2_id* gateway_id = radius_sess->get_gateway_id(radius_sess);
						u8 eap_method = radius_sess->get_eap_method(radius_sess);
						rhp_ip_addr src_addr;
						rhp_ip_addr dst_addr;
						char *gateway_id_type = NULL,*gateway_id_str = NULL;

						memset(&src_addr,0,sizeof(rhp_ip_addr));
						memset(&dst_addr,0,sizeof(rhp_ip_addr));

						radius_sess->get_nas_addr(radius_sess,&src_addr);
						radius_sess->get_server_addr(radius_sess,&dst_addr);

						if( gateway_id ){
							rhp_ikev2_id_to_string(gateway_id,&gateway_id_type,&gateway_id_str);
						}

						if( src_addr.addr_family == AF_INET && dst_addr.addr_family == AF_INET ){

							n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
									"\"<br>[%s] NAS: %s(%d.%d.%d.%d:%d) <--> Server: %d.%d.%d.%d:%d (%s) <br>Realm: %lu EAP:#L#%s,%lu## User-Name:%s CS-ID:%s <br>\"",
									(radius_sess->usage == RHP_RADIUS_USAGE_AUTHENTICATION ? "AUTH" : (radius_sess->usage == RHP_RADIUS_USAGE_ACCOUNTING ? "ACCT" : "UNKNOWN")),
									(nas_id ? nas_id : (gateway_id_str ? gateway_id_str : "null")),
									((u_int8_t*)&(src_addr.addr.v4))[0],((u_int8_t*)&(src_addr.addr.v4))[1],
									((u_int8_t*)&(src_addr.addr.v4))[2],((u_int8_t*)&(src_addr.addr.v4))[3],
									(int)ntohs(src_addr.port),
									((u_int8_t*)&(dst_addr.addr.v4))[0],((u_int8_t*)&(dst_addr.addr.v4))[1],
									((u_int8_t*)&(dst_addr.addr.v4))[2],((u_int8_t*)&(dst_addr.addr.v4))[3],
									(int)ntohs(dst_addr.port),
									(radius_sess->server_fqdn ? radius_sess->server_fqdn : "-"),
									(vpn_realm_id != RHP_VPN_REALM_ID_UNKNOWN ? vpn_realm_id : 0),
									"EAP_TYPE",(unsigned long)eap_method,
									(user_name ? user_name : "null"),
									(calling_station_id ? calling_station_id : "null")
									);

						}else	if( src_addr.addr_family == AF_INET6 && dst_addr.addr_family == AF_INET6 ){

							char ipv6_src_addr_str[INET6_ADDRSTRLEN + 1],
									 ipv6_dst_addr_str[INET6_ADDRSTRLEN + 1];

							n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
									"\"<br>[%s] NAS: %s(%s:%d) <--> Server: %s:%d (%s)<br>Realm: %lu EAP:#L#%s,%lu## User-Name:%s CS-ID:%s <br>\"",
									(radius_sess->usage == RHP_RADIUS_USAGE_AUTHENTICATION ? "AUTH" : (radius_sess->usage == RHP_RADIUS_USAGE_ACCOUNTING ? "ACCT" : "UNKNOWN")),
									(nas_id ? nas_id : (gateway_id_str ? gateway_id_str : "null")),
									rhp_ipv6_string2(src_addr.addr.v6,ipv6_src_addr_str),
									(int)ntohs(src_addr.port),
									rhp_ipv6_string2(dst_addr.addr.v6,ipv6_dst_addr_str),
									(int)ntohs(dst_addr.port),
									(radius_sess->server_fqdn ? radius_sess->server_fqdn : "-"),
									(vpn_realm_id != RHP_VPN_REALM_ID_UNKNOWN ? vpn_realm_id : 0),
									"EAP_TYPE",(unsigned long)eap_method,
									(user_name ? user_name : "null"),
									(calling_station_id ? calling_station_id : "null")
									);

						}else{

							n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
									"\"<br>[%s] NAS: %s(unknown) <--> Server: unknown (%s) <br>Realm: %lu EAP:#L#%s,%lu## User-Name:%s CS-ID:%s <br>\"",
									(radius_sess->usage == RHP_RADIUS_USAGE_AUTHENTICATION ? "AUTH" : (radius_sess->usage == RHP_RADIUS_USAGE_ACCOUNTING ? "ACCT" : "UNKNOWN")),
									(nas_id ? nas_id : (gateway_id_str ? gateway_id_str : "null")),
									(radius_sess->server_fqdn ? radius_sess->server_fqdn : "-"),
									(vpn_realm_id != RHP_VPN_REALM_ID_UNKNOWN ? vpn_realm_id : 0),
									"EAP_TYPE",(unsigned long)eap_method,
									(user_name ? user_name : "null"),
									(calling_station_id ? calling_station_id : "null")
									);
						}

						if( gateway_id_type ){
							_rhp_free(gateway_id_type);
						}
						if( gateway_id_str ){
							_rhp_free(gateway_id_str);
						}
					}
				}
    	}
    }
      break;

    case 'n':

    	if( value == NULL ){

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>null<br>\"");

    	}else{

    		rhp_nhrp_req_session* nhrp_sess = (rhp_nhrp_req_session*)value;
				char proto_addr_str[INET6_ADDRSTRLEN + 1],
						 nbma_addr_str[INET6_ADDRSTRLEN + 1];

				if( ((u8*)value)[0] != '#' || ((u8*)value)[1] != 'N' || ((u8*)value)[2] != 'R' || ((u8*)value)[3] != 'S' ){
      		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>Invalid nhrp_sess<br>\"");
					break;
				}

				if( nhrp_sess->target_protocol_ip.addr_family == AF_INET ){

					snprintf(proto_addr_str,(INET6_ADDRSTRLEN + 1),"%d.%d.%d.%d",
							((u_int8_t*)&(nhrp_sess->target_protocol_ip.addr.v4))[0],((u_int8_t*)&(nhrp_sess->target_protocol_ip.addr.v4))[1],
							((u_int8_t*)&(nhrp_sess->target_protocol_ip.addr.v4))[2],((u_int8_t*)&(nhrp_sess->target_protocol_ip.addr.v4))[3]);

				}else if( nhrp_sess->target_protocol_ip.addr_family == AF_INET6 ){

					rhp_ipv6_string2(nhrp_sess->target_protocol_ip.addr.v6,proto_addr_str);

				}else{

					snprintf(proto_addr_str,(INET6_ADDRSTRLEN + 1),"%s","N/A");
				}

				if( nhrp_sess->src_nbma_ip.addr_family == AF_INET ){

					snprintf(nbma_addr_str,(INET6_ADDRSTRLEN + 1),"%d.%d.%d.%d",
							((u_int8_t*)&(nhrp_sess->src_nbma_ip.addr.v4))[0],((u_int8_t*)&(nhrp_sess->src_nbma_ip.addr.v4))[1],
							((u_int8_t*)&(nhrp_sess->src_nbma_ip.addr.v4))[2],((u_int8_t*)&(nhrp_sess->src_nbma_ip.addr.v4))[3]);

				}else if( nhrp_sess->src_nbma_ip.addr_family == AF_INET6 ){

					rhp_ipv6_string2(nhrp_sess->src_nbma_ip.addr.v6,nbma_addr_str);

				}else{

					snprintf(nbma_addr_str,(INET6_ADDRSTRLEN + 1),"%s","N/A");
				}

				n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
						"\"<br>Realm: %lu VPN UID: 0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x<br>PKT_TYPE:#L#%s,%u## Proto: %s NBMA: %s ReqID: %u<br>retries: %d\"",
						nhrp_sess->vpn_realm_id,
						(((u_int8_t*)nhrp_sess->vpn_uid)[0]), (((u_int8_t*)nhrp_sess->vpn_uid)[1]),
						(((u_int8_t*)nhrp_sess->vpn_uid)[2]), (((u_int8_t*)nhrp_sess->vpn_uid)[3]),
						(((u_int8_t*)nhrp_sess->vpn_uid)[4]), (((u_int8_t*)nhrp_sess->vpn_uid)[5]),
						(((u_int8_t*)nhrp_sess->vpn_uid)[6]), (((u_int8_t*)nhrp_sess->vpn_uid)[7]),
						(((u_int8_t*)nhrp_sess->vpn_uid)[8]), (((u_int8_t*)nhrp_sess->vpn_uid)[9]),
						(((u_int8_t*)nhrp_sess->vpn_uid)[10]), (((u_int8_t*)nhrp_sess->vpn_uid)[11]),
						(((u_int8_t*)nhrp_sess->vpn_uid)[12]), (((u_int8_t*)nhrp_sess->vpn_uid)[13]),
						(((u_int8_t*)nhrp_sess->vpn_uid)[14]), (((u_int8_t*)nhrp_sess->vpn_uid)[15]),
						"NHRP_PKT_TYPE",nhrp_sess->request_type,
						proto_addr_str,nbma_addr_str,
						nhrp_sess->tx_request_id,nhrp_sess->retries
						);

    	}
    	break;

    case 'B':

    	if( value == NULL ){

    		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>null<br>\"");

    	}else{

    		rhp_nhrp_mesg* nhrp_mesg = (rhp_nhrp_mesg*)value;
    		u8 pkt_type;
    		u16 addr_family;
				char nbma_src_addr_str[INET6_ADDRSTRLEN + 1],
						 proto_src_addr_str[INET6_ADDRSTRLEN + 1],
						 proto_dst_addr_str[INET6_ADDRSTRLEN + 1];
  			rhp_ip_addr rx_src_nbma_addr,rx_dst_nbma_addr;
  			rhp_ip_addr src_nbma_addr,src_protocol_addr,dst_protocol_addr;

				if( ((u8*)value)[0] != '#' || ((u8*)value)[1] != 'N' || ((u8*)value)[2] != 'H' || ((u8*)value)[3] != 'R' ){
      		n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"<br>Invalid nhrp_mesg<br>\"");
					break;
				}

  			rx_src_nbma_addr.addr_family = AF_UNSPEC;
  			rx_dst_nbma_addr.addr_family = AF_UNSPEC;

  			src_nbma_addr.addr_family = AF_UNSPEC;
  			src_protocol_addr.addr_family = AF_UNSPEC;
  			dst_protocol_addr.addr_family = AF_UNSPEC;

				addr_family = nhrp_mesg->get_addr_family(nhrp_mesg);
				pkt_type = nhrp_mesg->get_packet_type(nhrp_mesg);

  			nhrp_mesg->get_rx_nbma_src_addr(nhrp_mesg,&rx_src_nbma_addr);
  			nhrp_mesg->get_rx_nbma_dst_addr(nhrp_mesg,&rx_dst_nbma_addr);

				n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"");
    	  if( n >= _rhp_log_record_buf_rem ){
    	  	RHP_BUG("%d, %d",n,_rhp_log_record_buf_rem);
    	  	return -EINVAL;
    	  }
    	  _rhp_log_record_buf_cur_pt += n;
    	  _rhp_log_record_buf_rem -= n;


    	  {
					if( rx_src_nbma_addr.addr_family == AF_INET ){

						snprintf(proto_src_addr_str,(INET6_ADDRSTRLEN + 1),"%d.%d.%d.%d",
								((u_int8_t*)&(rx_src_nbma_addr.addr.v4))[0],((u_int8_t*)&(rx_src_nbma_addr.addr.v4))[1],
								((u_int8_t*)&(rx_src_nbma_addr.addr.v4))[2],((u_int8_t*)&(rx_src_nbma_addr.addr.v4))[3]);

						snprintf(proto_dst_addr_str,(INET6_ADDRSTRLEN + 1),"%d.%d.%d.%d",
								((u_int8_t*)&(rx_dst_nbma_addr.addr.v4))[0],((u_int8_t*)&(rx_dst_nbma_addr.addr.v4))[1],
								((u_int8_t*)&(rx_dst_nbma_addr.addr.v4))[2],((u_int8_t*)&(rx_dst_nbma_addr.addr.v4))[3]);

						n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
								"<br>Encap Rx: %s -> %s",proto_src_addr_str,proto_dst_addr_str);

					}else if( rx_src_nbma_addr.addr_family == AF_INET6 ){

						rhp_ipv6_string2(rx_dst_nbma_addr.addr.v6,proto_dst_addr_str);

						rhp_ipv6_string2(rx_dst_nbma_addr.addr.v6,proto_dst_addr_str);

						n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
								"<br>Encap Rx: %s -> %s",proto_src_addr_str,proto_dst_addr_str);

					}else{

						n = 0;
					}

					if( n ){

						if( n >= _rhp_log_record_buf_rem ){
							RHP_BUG("%d, %d",n,_rhp_log_record_buf_rem);
							return -EINVAL;
						}
						_rhp_log_record_buf_cur_pt += n;
						_rhp_log_record_buf_rem -= n;
					}
    	  }


    		if( pkt_type == RHP_PROTO_NHRP_PKT_RESOLUTION_REQ 	||
    				pkt_type == RHP_PROTO_NHRP_PKT_RESOLUTION_REP 	||
    				pkt_type == RHP_PROTO_NHRP_PKT_REGISTRATION_REQ ||
    				pkt_type == RHP_PROTO_NHRP_PKT_REGISTRATION_REP ||
    				pkt_type == RHP_PROTO_NHRP_PKT_PURGE_REQ 				||
    				pkt_type == RHP_PROTO_NHRP_PKT_PURGE_REP ){

    			int i;

    			u32 request_id = nhrp_mesg->m.mandatory->get_request_id(nhrp_mesg);

    			rhp_nhrp_cie* nhrp_cie;

    			nhrp_mesg->m.mandatory->get_src_nbma_addr(nhrp_mesg,&src_nbma_addr);
    			nhrp_mesg->m.mandatory->get_src_protocol_addr(nhrp_mesg,&src_protocol_addr);
    			nhrp_mesg->m.mandatory->get_dst_protocol_addr(nhrp_mesg,&dst_protocol_addr);


      	  {
						if( src_nbma_addr.addr_family == AF_INET ){

							snprintf(nbma_src_addr_str,(INET6_ADDRSTRLEN + 1),"%d.%d.%d.%d",
									((u_int8_t*)&(src_nbma_addr.addr.v4))[0],((u_int8_t*)&(src_nbma_addr.addr.v4))[1],
									((u_int8_t*)&(src_nbma_addr.addr.v4))[2],((u_int8_t*)&(src_nbma_addr.addr.v4))[3]);

						}else if( src_protocol_addr.addr_family == AF_INET6 ){

							rhp_ipv6_string2(src_nbma_addr.addr.v6,nbma_src_addr_str);

						}else{

							snprintf(nbma_src_addr_str,(INET6_ADDRSTRLEN + 1),"%s","N/A");
						}

						if( src_protocol_addr.addr_family == AF_INET ){

							snprintf(proto_src_addr_str,(INET6_ADDRSTRLEN + 1),"%d.%d.%d.%d",
									((u_int8_t*)&(src_protocol_addr.addr.v4))[0],((u_int8_t*)&(src_protocol_addr.addr.v4))[1],
									((u_int8_t*)&(src_protocol_addr.addr.v4))[2],((u_int8_t*)&(src_protocol_addr.addr.v4))[3]);

							snprintf(proto_dst_addr_str,(INET6_ADDRSTRLEN + 1),"%d.%d.%d.%d",
									((u_int8_t*)&(dst_protocol_addr.addr.v4))[0],((u_int8_t*)&(dst_protocol_addr.addr.v4))[1],
									((u_int8_t*)&(dst_protocol_addr.addr.v4))[2],((u_int8_t*)&(dst_protocol_addr.addr.v4))[3]);

						}else if( src_protocol_addr.addr_family == AF_INET6 ){

							rhp_ipv6_string2(src_protocol_addr.addr.v6,proto_src_addr_str);

							rhp_ipv6_string2(dst_protocol_addr.addr.v6,proto_dst_addr_str);

						}else{

							snprintf(proto_src_addr_str,(INET6_ADDRSTRLEN + 1),"%s","N/A");
							snprintf(proto_dst_addr_str,(INET6_ADDRSTRLEN + 1),"%s","N/A");
						}


						n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
								"<br>PKT_TYPE:#L#%s,%u## AF:#L#%s,%u## ID: %u NBMA: %s Proto %s -> %s",
								"NHRP_PKT_TYPE",pkt_type,
								"NHRP_AF",addr_family,
								request_id,
								nbma_src_addr_str,proto_src_addr_str,proto_dst_addr_str);
						if( n >= _rhp_log_record_buf_rem ){
							RHP_BUG("%d, %d",n,_rhp_log_record_buf_rem);
							return -EINVAL;
						}
						_rhp_log_record_buf_cur_pt += n;
						_rhp_log_record_buf_rem -= n;
      	  }

      	  i = 0;
      		nhrp_cie = nhrp_mesg->m.mandatory->cie_list_head;
      		while( nhrp_cie ){

      			u8 cie_code = nhrp_cie->get_code(nhrp_cie);
      			u8 cie_prefix_len = nhrp_cie->get_prefix_len(nhrp_cie);
      			u16 cie_mtu = nhrp_cie->get_mtu(nhrp_cie);
      			u16 cie_hold_time = nhrp_cie->get_hold_time(nhrp_cie);
      			rhp_ip_addr cie_clt_nbma_addr;
      			rhp_ip_addr cie_clt_protocol_addr;

      			nhrp_cie->get_clt_nbma_addr(nhrp_cie,&cie_clt_nbma_addr);
      			nhrp_cie->get_clt_protocol_addr(nhrp_cie,&cie_clt_protocol_addr);

						if( cie_clt_nbma_addr.addr_family == AF_INET ){

							snprintf(nbma_src_addr_str,(INET6_ADDRSTRLEN + 1),"%d.%d.%d.%d",
									((u_int8_t*)&(cie_clt_nbma_addr.addr.v4))[0],((u_int8_t*)&(cie_clt_nbma_addr.addr.v4))[1],
									((u_int8_t*)&(cie_clt_nbma_addr.addr.v4))[2],((u_int8_t*)&(cie_clt_nbma_addr.addr.v4))[3]);

							snprintf(proto_src_addr_str,(INET6_ADDRSTRLEN + 1),"%d.%d.%d.%d",
									((u_int8_t*)&(cie_clt_protocol_addr.addr.v4))[0],((u_int8_t*)&(cie_clt_protocol_addr.addr.v4))[1],
									((u_int8_t*)&(cie_clt_protocol_addr.addr.v4))[2],((u_int8_t*)&(cie_clt_protocol_addr.addr.v4))[3]);

						}else if( cie_clt_nbma_addr.addr_family == AF_INET6 ){

							rhp_ipv6_string2(cie_clt_nbma_addr.addr.v6,nbma_src_addr_str);

							rhp_ipv6_string2(cie_clt_protocol_addr.addr.v6,proto_src_addr_str);

						}else{

							snprintf(nbma_src_addr_str,(INET6_ADDRSTRLEN + 1),"%s","N/A");
							snprintf(proto_src_addr_str,(INET6_ADDRSTRLEN + 1),"%s","N/A");
						}

						n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
								"<br>CIE[%d] Code:#L#%s,%u## Plen:%d MTU:%d Holding-Time:%d Clt NBMA:%s Clt Proto: %s",i,
								"NHRP_CIE_CODE",cie_code,cie_prefix_len,cie_mtu,cie_hold_time,
								proto_src_addr_str,proto_src_addr_str);

        	  if( n >= _rhp_log_record_buf_rem ){
        	  	RHP_BUG("%d, %d",n,_rhp_log_record_buf_rem);
        	  	return -EINVAL;
        	  }
        	  _rhp_log_record_buf_cur_pt += n;
        	  _rhp_log_record_buf_rem -= n;

        	  i++;
      			nhrp_cie = nhrp_cie->next;
      	  }

    		}else if( pkt_type == RHP_PROTO_NHRP_PKT_ERROR_INDICATION ){

    			u16 err_code = nhrp_mesg->m.error->get_error_code(nhrp_mesg);

					nhrp_mesg->m.error->get_src_nbma_addr(nhrp_mesg,&src_nbma_addr);
					nhrp_mesg->m.error->get_src_protocol_addr(nhrp_mesg,&src_protocol_addr);
					nhrp_mesg->m.error->get_dst_protocol_addr(nhrp_mesg,&dst_protocol_addr);
					err_code = nhrp_mesg->m.error->get_error_code(nhrp_mesg);

      	  {
						if( src_nbma_addr.addr_family == AF_INET ){

							snprintf(nbma_src_addr_str,(INET6_ADDRSTRLEN + 1),"%d.%d.%d.%d",
									((u_int8_t*)&(src_nbma_addr.addr.v4))[0],((u_int8_t*)&(src_nbma_addr.addr.v4))[1],
									((u_int8_t*)&(src_nbma_addr.addr.v4))[2],((u_int8_t*)&(src_nbma_addr.addr.v4))[3]);

						}else if( src_protocol_addr.addr_family == AF_INET6 ){

							rhp_ipv6_string2(src_nbma_addr.addr.v6,nbma_src_addr_str);

						}else{

							snprintf(nbma_src_addr_str,(INET6_ADDRSTRLEN + 1),"%s","N/A");
						}

						if( src_protocol_addr.addr_family == AF_INET ){

							snprintf(proto_src_addr_str,(INET6_ADDRSTRLEN + 1),"%d.%d.%d.%d",
									((u_int8_t*)&(src_protocol_addr.addr.v4))[0],((u_int8_t*)&(src_protocol_addr.addr.v4))[1],
									((u_int8_t*)&(src_protocol_addr.addr.v4))[2],((u_int8_t*)&(src_protocol_addr.addr.v4))[3]);

							snprintf(proto_dst_addr_str,(INET6_ADDRSTRLEN + 1),"%d.%d.%d.%d",
									((u_int8_t*)&(dst_protocol_addr.addr.v4))[0],((u_int8_t*)&(dst_protocol_addr.addr.v4))[1],
									((u_int8_t*)&(dst_protocol_addr.addr.v4))[2],((u_int8_t*)&(dst_protocol_addr.addr.v4))[3]);

						}else if( src_protocol_addr.addr_family == AF_INET6 ){

							rhp_ipv6_string2(src_protocol_addr.addr.v6,proto_src_addr_str);
							rhp_ipv6_string2(dst_protocol_addr.addr.v6,proto_dst_addr_str);

						}else{

							snprintf(proto_src_addr_str,(INET6_ADDRSTRLEN + 1),"%s","N/A");
							snprintf(proto_dst_addr_str,(INET6_ADDRSTRLEN + 1),"%s","N/A");
						}

						n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
								"<br>PKT_TYPE:#L#%s,%u## AF:#L#%s,%u## NBMA: %s Proto %s -> %s Err: #L#%s,%u##",
								"NHRP_PKT_TYPE",pkt_type,
								"NHRP_AF",addr_family,
								nbma_src_addr_str,proto_src_addr_str,proto_dst_addr_str,
								"NHRP_ERR_CODE",err_code);
						if( n >= _rhp_log_record_buf_rem ){
							RHP_BUG("%d, %d",n,_rhp_log_record_buf_rem);
							return -EINVAL;
						}
						_rhp_log_record_buf_cur_pt += n;
						_rhp_log_record_buf_rem -= n;
      	  }


    		}else if( pkt_type == RHP_PROTO_NHRP_PKT_TRAFFIC_INDICATION ){

    			rhp_ip_addr org_src_addr, org_dst_addr;
  				char org_src_addr_str[INET6_ADDRSTRLEN + 1],
  						 org_dst_addr_str[INET6_ADDRSTRLEN + 1];
    			u16 trf_code = nhrp_mesg->m.traffic->get_traffic_code(nhrp_mesg);

    			org_src_addr.addr_family = AF_UNSPEC;
    			org_dst_addr.addr_family = AF_UNSPEC;

					nhrp_mesg->m.traffic->get_src_nbma_addr(nhrp_mesg,&src_nbma_addr);
					nhrp_mesg->m.traffic->get_src_protocol_addr(nhrp_mesg,&src_protocol_addr);
					nhrp_mesg->m.traffic->get_dst_protocol_addr(nhrp_mesg,&dst_protocol_addr);

					nhrp_mesg->m.traffic->get_org_mesg_addrs(nhrp_mesg,&org_src_addr,&org_dst_addr);

      	  {
						if( src_nbma_addr.addr_family == AF_INET ){

							snprintf(nbma_src_addr_str,(INET6_ADDRSTRLEN + 1),"%d.%d.%d.%d",
									((u_int8_t*)&(src_nbma_addr.addr.v4))[0],((u_int8_t*)&(src_nbma_addr.addr.v4))[1],
									((u_int8_t*)&(src_nbma_addr.addr.v4))[2],((u_int8_t*)&(src_nbma_addr.addr.v4))[3]);

						}else if( src_protocol_addr.addr_family == AF_INET6 ){

							rhp_ipv6_string2(src_nbma_addr.addr.v6,nbma_src_addr_str);

						}else{

							snprintf(nbma_src_addr_str,(INET6_ADDRSTRLEN + 1),"%s","N/A");
						}

						if( src_protocol_addr.addr_family == AF_INET ){

							snprintf(proto_src_addr_str,(INET6_ADDRSTRLEN + 1),"%d.%d.%d.%d",
									((u_int8_t*)&(src_protocol_addr.addr.v4))[0],((u_int8_t*)&(src_protocol_addr.addr.v4))[1],
									((u_int8_t*)&(src_protocol_addr.addr.v4))[2],((u_int8_t*)&(src_protocol_addr.addr.v4))[3]);

							snprintf(proto_dst_addr_str,(INET6_ADDRSTRLEN + 1),"%d.%d.%d.%d",
									((u_int8_t*)&(dst_protocol_addr.addr.v4))[0],((u_int8_t*)&(dst_protocol_addr.addr.v4))[1],
									((u_int8_t*)&(dst_protocol_addr.addr.v4))[2],((u_int8_t*)&(dst_protocol_addr.addr.v4))[3]);

						}else if( src_protocol_addr.addr_family == AF_INET6 ){

							rhp_ipv6_string2(src_protocol_addr.addr.v6,proto_src_addr_str);
							rhp_ipv6_string2(dst_protocol_addr.addr.v6,proto_dst_addr_str);

						}else{

							snprintf(proto_src_addr_str,(INET6_ADDRSTRLEN + 1),"%s","N/A");
							snprintf(proto_dst_addr_str,(INET6_ADDRSTRLEN + 1),"%s","N/A");
						}

						if( org_src_addr.addr_family == AF_INET ){

							snprintf(org_src_addr_str,(INET6_ADDRSTRLEN + 1),"%d.%d.%d.%d",
									((u_int8_t*)&(org_src_addr.addr.v4))[0],((u_int8_t*)&(org_src_addr.addr.v4))[1],
									((u_int8_t*)&(org_src_addr.addr.v4))[2],((u_int8_t*)&(org_src_addr.addr.v4))[3]);

							snprintf(org_dst_addr_str,(INET6_ADDRSTRLEN + 1),"%d.%d.%d.%d",
									((u_int8_t*)&(org_dst_addr.addr.v4))[0],((u_int8_t*)&(org_dst_addr.addr.v4))[1],
									((u_int8_t*)&(org_dst_addr.addr.v4))[2],((u_int8_t*)&(org_dst_addr.addr.v4))[3]);

						}else if( org_src_addr.addr_family == AF_INET6 ){

							rhp_ipv6_string2(org_src_addr.addr.v6,org_src_addr_str);
							rhp_ipv6_string2(org_dst_addr.addr.v6,org_dst_addr_str);

						}else{

							snprintf(org_src_addr_str,(INET6_ADDRSTRLEN + 1),"%s","N/A");
							snprintf(org_dst_addr_str,(INET6_ADDRSTRLEN + 1),"%s","N/A");
						}


						n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
								"<br>PKT_TYPE:#L#%s,%u## AF:#L#%s,%u## NBMA: %s Proto %s -> %s Trf: #L#%s,%u## Org Pkt: %s -> %s",
								"NHRP_PKT_TYPE",pkt_type,
								"NHRP_AF",addr_family,
								nbma_src_addr_str,proto_src_addr_str,proto_dst_addr_str,
								"NHRP_TRF_CODE",trf_code,
								org_src_addr_str,org_dst_addr_str);
						if( n >= _rhp_log_record_buf_rem ){
							RHP_BUG("%d, %d",n,_rhp_log_record_buf_rem);
							return -EINVAL;
						}
						_rhp_log_record_buf_cur_pt += n;
						_rhp_log_record_buf_rem -= n;
      	  }


    		}else{

					n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,
							"<br>PKT_TYPE:%d AF:%d Unknown NHRP mesg",pkt_type,addr_family);
					if( n >= _rhp_log_record_buf_rem ){
						RHP_BUG("%d, %d",n,_rhp_log_record_buf_rem);
						return -EINVAL;
					}
					_rhp_log_record_buf_cur_pt += n;
					_rhp_log_record_buf_rem -= n;
    		}

      	n = snprintf(_rhp_log_record_buf_cur_pt,_rhp_log_record_buf_rem,"\"");
    	}
      break;

    default:
    	RHP_BUG("%d",fmt_type);
    	n = 0;
    	break;
	}

  if( n >= _rhp_log_record_buf_rem ){
  	RHP_BUG("%d, %d",n,_rhp_log_record_buf_rem);
  	return -EINVAL;
  }

  _rhp_log_record_buf_cur_pt += n;
  _rhp_log_record_buf_rem -= n;

  return 0;
}

static int _rhp_log_record_add_arg(char fmt_type,int value_len,void* value)
{
	return _rhp_log_record_add_arg2(fmt_type,value_len,value,0,NULL);
}

static __thread int _rhp_logging = 0;

void rhp_log(unsigned long event_source,unsigned long vpn_realm_id,
		unsigned long level,unsigned long log_id, /*char* format,(top of va_args)*/ ... )
{
  int err;
  va_list args;
  int b;
  u_int16_t w;
  u_int32_t d;
  u_int64_t q;
  unsigned long ld;
  unsigned char* s;
  unsigned char* bm = NULL;
  time_t t;
  int lval;
  char *fmt, *fmt_start;
  struct timeval timestamp;

  if( _rhp_log_disabled ){
  	return;
  }

  if( _rhp_logging ){ // Avoid recursive calls.
  	return;
  }

  _rhp_logging = 1;

  if( (level ==  RHP_LOG_LV_DEBUG || level == RHP_LOG_LV_DBGERR) &&
  		!_rhp_log_debug_level ){
  	_rhp_logging = 0;
  	return;
  }

  gettimeofday(&timestamp,NULL);

  va_start(args,log_id);
  fmt = va_arg(args,char*);
  fmt_start = fmt;

  RHP_TRC_FREQ(0,RHPTRCID_RHP_LOG,"uuuus",event_source,vpn_realm_id,level,log_id,fmt_start);

  _rhp_log_record_init(event_source,vpn_realm_id,level,log_id,&timestamp);

  if( fmt == NULL || *fmt == '\0'){
    goto no_data;
  }


  while(*fmt != '\0'){

  	err = 0;

#ifdef RHP_LOG_LIB_DEBUG
  	RHP_BUG("%c",*fmt);
#endif

    switch(*fmt){

    case 'b':

      b = (u_int8_t) va_arg(args,int);
      err = _rhp_log_record_add_arg(*fmt,0,&b);

      break;

    case 'W':
#ifndef RHP_BIG_ENDIAN
      w = (u_int16_t) va_arg(args,int);
      w = bswap_16(w);
      err = _rhp_log_record_add_arg(*fmt,0,&w);

      break;
#endif // RHP_BIG_ENDIAN
    case 'w':
      w = (u_int16_t) va_arg(args,int);
      err = _rhp_log_record_add_arg(*fmt,0,&w);
      break;

    case 'J':
    case 'D':
#ifndef RHP_BIG_ENDIAN
      d = va_arg(args,u_int32_t);
      d = bswap_32(d);
      err = _rhp_log_record_add_arg(*fmt,0,&d);

      break;
#endif // RHP_BIG_ENDIAN
    case 'j':
    case 'd':
    case '4':
    case 'E':
    case 'H':
    case 'i':

      d = va_arg(args,u_int32_t);
      err = _rhp_log_record_add_arg(*fmt,0,&d);

      break;

    case 'U':
    case 'X':
#ifndef RHP_BIG_ENDIAN

      ld = va_arg(args,unsigned long);
      if( sizeof(unsigned long) == 8 ){
      	ld = bswap_64(ld);
      }else{
      	ld = bswap_32(ld);
      }
      err = _rhp_log_record_add_arg(*fmt,0,&ld);

      break;
#endif // RHP_BIG_ENDIAN

    case 'Q':
#ifndef RHP_BIG_ENDIAN

      q = va_arg(args,u_int64_t);
      q = bswap_64(q);
      err = _rhp_log_record_add_arg(*fmt,0,&q);

      break;
#endif // RHP_BIG_ENDIAN

    case 'u':
    case 'x':

    	ld = va_arg(args,unsigned long);
      err = _rhp_log_record_add_arg(*fmt,0,&ld);
      break;

    case 'q':

      q = va_arg(args,u_int64_t);
      err = _rhp_log_record_add_arg(*fmt,0,&q);

      break;

    case 's':

      s = va_arg(args,unsigned char *);

      if( s == NULL ){
      	err = _rhp_log_record_add_arg(*fmt,0,"null");
      }else{
      	err = _rhp_log_record_add_arg(*fmt,0,s);
      }
      break;

    case '6':

      bm = va_arg(args,unsigned char *);

      if(bm){
      	err = _rhp_log_record_add_arg(*fmt,0,bm);
      }else{

        unsigned char dummy_ipv6[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        err = _rhp_log_record_add_arg(*fmt,0,dummy_ipv6);
      }
      break;

    case 'M':

      bm = va_arg(args,unsigned char *);

      if(bm){
      	err = _rhp_log_record_add_arg(*fmt,0,bm);
      }else{

        unsigned char dummy_mac[6] = { 0, 0, 0, 0, 0, 0 };
        err = _rhp_log_record_add_arg(*fmt,0,dummy_mac);
      }
      break;

    case 'G':

      bm = va_arg(args,unsigned char *);

      if(bm){
      	err = _rhp_log_record_add_arg(*fmt,0,bm);
      }else{

        unsigned char dummy_ike_spi[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
        err = _rhp_log_record_add_arg(*fmt,0,dummy_ike_spi);
      }
      break;

    case 'I':

    	bm = va_arg(args,unsigned char *);

      if(bm){
      	err = _rhp_log_record_add_arg(*fmt,0,bm);
      }else{

      	rhp_ikev2_id dummy;
      	memset(&dummy,0,sizeof(rhp_ikev2_id));
        err = _rhp_log_record_add_arg(*fmt,0,&dummy);
      }
      break;

    case 'e':

    	bm = va_arg(args,unsigned char *);

      if(bm){
      	err = _rhp_log_record_add_arg(*fmt,0,bm);
      }else{

      	rhp_eap_id dummy;
      	memset(&dummy,0,sizeof(rhp_eap_id));
        err = _rhp_log_record_add_arg(*fmt,0,&dummy);
      }
      break;

    case 'A':

    	bm = va_arg(args,unsigned char *);

      if(bm){
      	err = _rhp_log_record_add_arg(*fmt,0,bm);
      }else{

      	rhp_ip_addr dummy;
      	memset(&dummy,0,sizeof(rhp_ip_addr));
        err = _rhp_log_record_add_arg(*fmt,0,&dummy);
      }
      break;

    case 'F':

    	bm = va_arg(args,unsigned char *);

      if(bm){
      	err = _rhp_log_record_add_arg(*fmt,0,bm);
      }else{

      	rhp_if_entry dummy;
      	memset(&dummy,0,sizeof(rhp_if_entry));
        err = _rhp_log_record_add_arg(*fmt,0,&dummy);
      }
      break;

    case 'N':

      bm = va_arg(args,unsigned char *);

      if(bm){
      	err = _rhp_log_record_add_arg(*fmt,0,bm);
      }else{

        unsigned char dummy[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        err = _rhp_log_record_add_arg(*fmt,0,dummy);
      }
      break;

    case 'L':

      bm = va_arg(args,unsigned char *);
      lval = va_arg(args,int);

      if(bm){
      	err = _rhp_log_record_add_arg2(*fmt,0,(void*)bm,0,(void*)&lval);
      }else{
      	err = _rhp_log_record_add_arg2(*fmt,0,"NOLABEL",0,(void*)&lval);
      }
      break;

    case 'p':
    case 'a':

    	lval = va_arg(args,int);

      if(lval < 0){
      	lval = RHP_LOG_LIB_INVALID_DATA_LEN;
        bm = (unsigned char*)_rhp_log_dmy_invalid_data;
      }else{
        bm = va_arg(args,unsigned char *);
        if(bm == NULL){
        	lval = 0;
        }
      }

    	err = _rhp_log_record_add_arg2(*fmt,0,(void*)&lval,0,(void*)bm);
      break;

    case 'K':
    case 'V':
    case 'P':
    case 'C':
    case 'r':
    case 'R':
    case 'n':
    case 'B':

      bm = va_arg(args,unsigned char *);
      err = _rhp_log_record_add_arg(*fmt,0,bm);
      break;

    case 't':
    case 'T':

      t = va_arg(args,time_t);
      err = _rhp_log_record_add_arg(*fmt,0,&t);

      break;

    default:
      goto error;
    }

    if( err ){
    	RHP_BUG("%d",err);
      goto error;
    }

    fmt++;
  }
  va_end(args);

no_data:
	err = _rhp_log_record_term();
	if( err ){
		goto error;
	}


	rhp_ui_log_write(event_source,vpn_realm_id,level,log_id,
			&timestamp,_rhp_log_record_buf,(_rhp_log_record_buf_cur_pt - _rhp_log_record_buf) + 1,1);

error:
	RHP_TRC_FREQ(0,RHPTRCID_RHP_LOG_RTRN,"uuuus",event_source,vpn_realm_id,level,log_id,fmt_start);
	_rhp_logging = 0;
  return;
}


int rhp_log_get_record_num(RHP_LOG_GET_RECORD_NUM_CB callback,void* ctx)
{
  if( _rhp_log_disabled ){
  	return 0;
  }
	return rhp_ui_log_get_record_num(callback,ctx);
}

int rhp_log_reset(RHP_LOG_RESET_CB callback,void* ctx)
{
  if( _rhp_log_disabled ){
  	return 0;
  }
	return rhp_ui_log_reset(callback,ctx);
}

int rhp_log_save(int file_type,char* file_name,unsigned long vpn_realm_id,int limit_num,RHP_LOG_SAVE_CB callback,void* ctx)
{
  if( _rhp_log_disabled ){
  	return 0;
  }
	return rhp_ui_log_save(file_type,file_name,vpn_realm_id,limit_num,callback,ctx);
}

int rhp_log_init(int process_role)
{

  memset( _rhp_log_dmy_invalid_data, 0, RHP_LOG_LIB_INVALID_DATA_LEN);
  _rhp_log_dmy_invalid_data[0] = 'I';
  _rhp_log_dmy_invalid_data[1] = 'N';
  _rhp_log_dmy_invalid_data[2] = 'V';
  _rhp_log_dmy_invalid_data[3] = 'A';
  _rhp_log_dmy_invalid_data[4] = 'L';
  _rhp_log_dmy_invalid_data[5] = 'I';
  _rhp_log_dmy_invalid_data[6] = 'D';
  _rhp_log_dmy_invalid_data[7] = ' ';
  _rhp_log_dmy_invalid_data[8] = 'D';
  _rhp_log_dmy_invalid_data[9] = 'A';
  _rhp_log_dmy_invalid_data[10] = 'T';
  _rhp_log_dmy_invalid_data[11] = 'A';
  _rhp_log_dmy_invalid_data[12] = '!';

	return 0;
}

int rhp_log_cleanup(int process_role)
{
  if( _rhp_log_disabled ){
  	return 0;
  }
	return 0;
}


