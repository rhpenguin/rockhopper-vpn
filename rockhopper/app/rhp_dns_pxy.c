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
#include <linux/errqueue.h>
#include <sys/inotify.h>
#include <fcntl.h>

#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_protocol.h"
#include "rhp_packet.h"
#include "rhp_netsock.h"
#include "rhp_wthreads.h"
#include "rhp_timer.h"
#include "rhp_config.h"
#include "rhp_crypto.h"
#include "rhp_tuntap.h"
#include "rhp_esp.h"
#include "rhp_dns_pxy.h"


//
// iptables/ip6tables and netfilter themselves require CAP_NET_ADMIN and CAP_NET_RAW.
// CAP_NET_RAW is necessary for iptables to open a NETLINK socket.
// Required netfilter modules should be loaded on boot. (/etc/modules)
//
//
// sudo setcap cap_net_admin,cap_net_raw=eip ./iptables (local copy)
// sudo setcap cap_net_admin,cap_net_raw=eip ./ip6tables (local copy)
//
//
//
// [CAUTION]
//  For IPv6, this DNS proxy service requires kernel v3.7 and later (supporting IPv6 NAT)
//  and corresponding ip6tables.
//  - Ubuntu 13.04 -
//
//
// [ iptables REDIRECT ]
//
// sudo iptables -t nat -A OUTPUT -d <DNS-Server-IPv4> -p udp --dport 53 -m owner ! --uid-owner <User-Name> -j REDIRECT --to-port <DNS-Pxy-Port>
// sudo ip6tables -t nat -A OUTPUT -d <DNS-Server-IPv6> -p udp --dport 53 -m owner ! --uid-owner <User-Name> -j REDIRECT --to-port <DNS-Pxy-Port>
//
//

static rhp_mutex_t _rhp_dns_pxy_lock;

rhp_atomic_t rhp_dns_pxy_users;

static rhp_epoll_ctx _rhp_dns_pxy_epoll_ctx_resolv_conf;

static int _rhp_resolv_conf_trying = 0;
#define RHP_DNS_PXY_RSLV_TRY_MAX			5


// [0] : Primary DNS server, [1] : Secondary one, ...
static rhp_ip_addr _rhp_resolv_conf_name_server_ips_v4[RHP_DNS_PXY_MAX_DNS_SERVERS];
static rhp_ip_addr _rhp_resolv_conf_name_server_ips_v6[RHP_DNS_PXY_MAX_DNS_SERVERS];
static int _rhp_resolv_conf_name_server_ips_v4_num = 0;
static int _rhp_resolv_conf_name_server_ips_v6_num = 0;
static rhp_epoll_ctx _rhp_dns_pxy_epoll_ctx_rx_v4[RHP_DNS_PXY_MAX_DNS_SERVERS];
static rhp_epoll_ctx _rhp_dns_pxy_epoll_ctx_rx_v6[RHP_DNS_PXY_MAX_DNS_SERVERS];

#define RHP_DNS_PXY_MAX_DNS_PKT_LEN		2048
static int _rhp_dns_pxy_rx_buf_max_size	= 512;
static int _rhp_dns_pxy_rx_max_packets = 16;


#define RHP_DNS_PXY_TRS_TBL_HASH_TABLE_SIZE   1277
static u32 _rhp_dns_pxy_trans_tbl_hashtbl_rnd;

static rhp_atomic_t _rhp_dns_pxy_sk_num;


static int _rhp_dns_pxy_main_active_v4 = 0;
static int _rhp_dns_pxy_main_active_v6 = 0;
static int _rhp_dnx_pxy_reading_resolv_conf = 0;

#define RHP_DNS_PXY_EPOLL_CTX_INOTIFY_FD(epoll_ctx)			((epoll_ctx)->params[0])
#define RHP_DNS_PXY_EPOLL_CTX_INOTIFY_WD(epoll_ctx)			((epoll_ctx)->params[1])

#define RHP_DNS_PXY_EPOLL_CTX_SK(epoll_ctx) 						((epoll_ctx)->params[0])

#define RHP_DNS_PXY_EPOLL_CTX_RX_PORT(epoll_ctx) 				((epoll_ctx)->params[1])
#define RHP_DNS_PXY_EPOLL_CTX_RX_NMSVR_IDX(epoll_ctx)		((epoll_ctx)->params[2])

#define RHP_DNS_PXY_EPOLL_CTX_FWD_DNX_TXNID(epoll_ctx)	((epoll_ctx)->params[1])


int rhp_dns_pxy_resolv_conf_info(int addr_family,rhp_ip_addr* addrs_r,int* addrs_num_r)
{
	int err = -EINVAL;

	if( *addrs_num_r != RHP_DNS_PXY_MAX_DNS_SERVERS ){
		RHP_BUG("%d",*addrs_num_r);
		return -EINVAL;
	}

	RHP_LOCK(&_rhp_dns_pxy_lock);

	if( addr_family == AF_INET ){
		if( !_rhp_resolv_conf_name_server_ips_v4_num ){
			err = -ENOENT;
		}else{
			memcpy(addrs_r,_rhp_resolv_conf_name_server_ips_v4,sizeof(rhp_ip_addr)*RHP_DNS_PXY_MAX_DNS_SERVERS);
			*addrs_num_r = _rhp_resolv_conf_name_server_ips_v4_num;
			err = 0;
		}
	}else if( addr_family == AF_INET6 ){
		if( !_rhp_resolv_conf_name_server_ips_v6_num ){
			err = -ENOENT;
		}else{
			memcpy(addrs_r,_rhp_resolv_conf_name_server_ips_v6,sizeof(rhp_ip_addr)*RHP_DNS_PXY_MAX_DNS_SERVERS);
			*addrs_num_r = _rhp_resolv_conf_name_server_ips_v6_num;
			err = 0;
		}
	}else{
		RHP_BUG("%d",addr_family);
	}

	RHP_UNLOCK(&_rhp_dns_pxy_lock);

	return err;
}


struct _rhp_dns_pxy_trans_tbl {

	u8 tag[4]; // "#DXT"

	struct _rhp_dns_pxy_trans_tbl* hash_next;

	struct _rhp_dns_pxy_trans_tbl* lst_prev;
	struct _rhp_dns_pxy_trans_tbl* lst_next;

	int hval;

	rhp_ip_addr orig_src;
	rhp_ip_addr orig_dst;

	rhp_ip_addr trans_src;
	rhp_ip_addr trans_dst;

	u16 dns_txn_id;
	u16 reseved;

	rhp_epoll_ctx* epoll_ctx;
	time_t expire;
	time_t expire2;

	int orig_nsvr_idx;

#define RHP_DNSPXY_FWD_TO_INET	1
#define RHP_DNSPXY_FWD_TO_VPN		2
	int fwdto;
};
typedef struct _rhp_dns_pxy_trans_tbl	rhp_dns_pxy_trans_tbl;

static rhp_dns_pxy_trans_tbl*	_rhp_dns_pxy_trans_tbl_hashtbl[RHP_DNS_PXY_TRS_TBL_HASH_TABLE_SIZE];
static int _rhp_dns_pxy_trans_tbl_num = 0;

static rhp_dns_pxy_trans_tbl _rhp_dns_pxy_trans_tbl_head;

static void _rhp_dns_pxy_close_sk(int* sk)
{
  RHP_TRC_FREQ(0,RHPTRCID_DNS_PXY_CLOSE_SK,"xdf",sk,*sk,_rhp_atomic_read(&_rhp_dns_pxy_sk_num));

	if( *sk < 0 ){
		RHP_BUG("");
		return;
	}

	_rhp_atomic_dec(&_rhp_dns_pxy_sk_num);
	close(*sk);
	*sk = -1;

	return;
}

long rhp_dns_pxy_get_open_sk_num()
{
	long n = _rhp_atomic_read(&_rhp_dns_pxy_sk_num);
  RHP_TRC_FREQ(0,RHPTRCID_DNS_PXY_OPEN_SK_NUM,"f",n);
	return n;
}


void rhp_dns_pxy_inc_users()
{
	RHP_TRC(0,RHPTRCID_DNS_PXY_INC_USERS,"d",rhp_dns_pxy_users.c);
	_rhp_atomic_inc(&rhp_dns_pxy_users);
}

int rhp_dns_pxy_dec_and_test_users()
{
	RHP_TRC(0,RHPTRCID_DNS_PXY_DEC_AND_TEST_USERS,"d",rhp_dns_pxy_users.c);

	if( _rhp_atomic_read(&rhp_dns_pxy_users) == 0 ){
		return 0;
	}
	return _rhp_atomic_dec_and_test(&rhp_dns_pxy_users);
}

int rhp_dns_pxy_get_users()
{
	RHP_TRC(0,RHPTRCID_DNS_PXY_GET_USERS,"d",rhp_dns_pxy_users.c);

	return _rhp_atomic_read(&rhp_dns_pxy_users);
}

static int _rhp_dns_pxy_read_resolv_conf(int addr_family,rhp_ip_addr* name_server_ips,int *servers_num_r)
{
	int err = -EINVAL;
	int fd = -1;
	char* line;
	int servers_num = 0;

	RHP_TRC(0,RHPTRCID_DNS_PXY_READ_RESOLV_CONF,"Ldxx","AF",addr_family,name_server_ips,servers_num_r);

	fd = open("/etc/resolv.conf",O_RDONLY);
	if( fd < 0 ){
		err = -errno;
		RHP_BUG("%d",err);
		goto error;
	}


	while( servers_num < RHP_DNS_PXY_MAX_DNS_SERVERS ){

		int n;
		char *pt,*pt_end;

		line = NULL;
		n = rhp_file_read_line(fd,&line);
		if( n < 0 ){
			err = n;
			goto error;
		}

		RHP_TRC(0,RHPTRCID_DNS_PXY_READ_RESOLV_CONF_READ_LINE,"sd",line,n);

		if( n == 0 ){
			goto next;
		}

		if( line[0] == '#' || line[0] == ';' || line[0] == '\0' ){
			goto next;
		}

		pt_end = line + n;

		pt = strstr((char*)line,"nameserver");
		if( pt == NULL ){
			goto next;
		}

		pt += strlen("nameserver");
		while( pt < pt_end &&
				   *pt != '\0' &&
				   *pt != ':'  &&
				   (*pt < '0' || *pt > '9') &&
				   (*pt < 'a' || *pt > 'f') &&
				   (*pt < 'A' || *pt > 'F') ){
			pt++;
		}

		if( pt >= pt_end || *pt == '\0' ){
			goto next;
		}

		{
			union {
				struct in_addr addr_v4;
				struct in6_addr addr_v6;
			} addr;

			err = inet_pton(addr_family,pt,&addr);
			if( err != 1 ){
				goto next;
			}

			rhp_ip_addr_set2(&(name_server_ips[servers_num]),addr_family,
					(addr_family == AF_INET ? (u8*)&(addr.addr_v4.s_addr) : (u8*)&(addr.addr_v6.s6_addr)),
					htons(RHP_PROTO_DNS_PORT));
		}

		RHP_TRC(0,RHPTRCID_DNS_PXY_READ_RESOLV_CONF_NAMESVR,"sd",pt,(servers_num+1));
		rhp_ip_addr_dump("_rhp_dns_pxy_read_resolv_conf.nameserver",&(name_server_ips[servers_num]));

		if( addr_family == AF_INET ){
			RHP_LOG_D(RHP_LOG_SRC_NETMNG,0,RHP_LOG_ID_DNS_PXY_READ_RESOLV_CONF,"d4W",(servers_num+1),name_server_ips[servers_num].addr.v4,name_server_ips[servers_num].port);
		}else if( addr_family == AF_INET6 ){
			RHP_LOG_D(RHP_LOG_SRC_NETMNG,0,RHP_LOG_ID_DNS_PXY_READ_RESOLV_CONF_V6,"d6W",(servers_num+1),name_server_ips[servers_num].addr.v6,name_server_ips[servers_num].port);
		}

		servers_num++;

next:
		if( line ){
			_rhp_free(line);
			line = NULL;
		}

		if( n == RHP_STATUS_EOF ){
			break;
		}
	}

	if( servers_num == 0 ){
		RHP_TRC(0,RHPTRCID_DNS_PXY_READ_RESOLV_CONF_NO_ENTRY,"");
		err = -ENOENT;
		goto error;
	}

	close(fd);
	if( line ){
		_rhp_free(line);
	}

	*servers_num_r = servers_num;

	RHP_TRC(0,RHPTRCID_DNS_PXY_READ_RESOLV_CONF_RTRN,"d",servers_num);
	return 0;

error:
	if( fd > -1 ){
		close(fd);
	}
	if( line ){
		_rhp_free(line);
	}

	if( addr_family == AF_INET ){
		RHP_LOG_DE(RHP_LOG_SRC_NETMNG,0,RHP_LOG_ID_DNS_PXY_READ_RESOLV_CONF_ERR,"E",err);
	}else if( addr_family == AF_INET6 ){
		RHP_LOG_DE(RHP_LOG_SRC_NETMNG,0,RHP_LOG_ID_DNS_PXY_READ_RESOLV_CONF_ERR_V6,"E",err);
	}

	RHP_TRC(0,RHPTRCID_DNS_PXY_READ_RESOLV_CONF_ERR,"E",err);
	return err;
}

static void _rhp_dns_pxy_resolv_conf_cleanup(rhp_epoll_ctx* epoll_ctx)
{
  struct epoll_event ep_evt;
  int fd = RHP_DNS_PXY_EPOLL_CTX_INOTIFY_FD(epoll_ctx);
  int wd = RHP_DNS_PXY_EPOLL_CTX_INOTIFY_WD(epoll_ctx);

	RHP_TRC(0,RHPTRCID_DNS_PXY_RESOLV_CONF_CLEANUP,"x",epoll_ctx);

	memset(&ep_evt,0,sizeof(struct epoll_event));

  if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_DEL,fd,&ep_evt) < 0 ){
    RHP_BUG("");
  }

	inotify_rm_watch(fd,wd);
	close(fd);

  RHP_DNS_PXY_EPOLL_CTX_INOTIFY_FD(epoll_ctx)  = -1;
  RHP_DNS_PXY_EPOLL_CTX_INOTIFY_WD(epoll_ctx) = -1;

	RHP_TRC(0,RHPTRCID_DNS_PXY_RESOLV_CONF_CLEANUP_RTRN,"x",epoll_ctx);
}

static int _rhp_dns_pxy_resolv_conf_init()
{
	int err = -EINVAL;
  int fd = -1,wd = -1;
  rhp_epoll_ctx* epoll_ctx = &_rhp_dns_pxy_epoll_ctx_resolv_conf;
  struct epoll_event ep_evt;

	RHP_TRC(0,RHPTRCID_DNS_PXY_RESOLV_CONF_INIT,"");

  memset(epoll_ctx,0,sizeof(rhp_epoll_ctx));

  fd = inotify_init1(IN_NONBLOCK);
  if( fd < 0 ){
  	err = -errno;
  	RHP_BUG("%d",err);
  	goto error;
  }

//  wd = inotify_add_watch(fd,"/etc/resolv.conf",(IN_CLOSE_WRITE | IN_MOVE_SELF | IN_MODIFY));
  wd = inotify_add_watch(fd,"/etc/resolv.conf",IN_CLOSE_WRITE);
  if( wd < 0 ){
  	err = -errno;
  	RHP_BUG("%d",err);
  	goto error;
  }

  RHP_DNS_PXY_EPOLL_CTX_INOTIFY_FD(epoll_ctx) = fd;
  RHP_DNS_PXY_EPOLL_CTX_INOTIFY_WD(epoll_ctx) = wd;

  {
  	epoll_ctx->event_type = RHP_MAIN_EPOLL_DNSPXY_RSLVR;

    memset(&ep_evt,0,sizeof(struct epoll_event));
    ep_evt.events = EPOLLIN;
    ep_evt.data.ptr = (void*)epoll_ctx;

    if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_ADD,fd,&ep_evt) < 0 ){
      err = -errno;
      RHP_BUG("%d",err);
      goto error;
    }
  }

	RHP_TRC(0,RHPTRCID_DNS_PXY_RESOLV_CONF_INIT_RTRN,"");
	return 0;

error:
	if( wd > -1 ){
		inotify_rm_watch(fd,wd);
	}

	RHP_TRC(0,RHPTRCID_DNS_PXY_RESOLV_CONF_INIT_ERR,"E",err);
	return err;
}


static int _rhp_dns_pxy_ipc_send_redirect_ctrl(rhp_ip_addr* name_server_addr,
		u16 internal_port,int start_or_end)
{
	int err = -EINVAL;
	rhp_ipcmsg_netmng_dns_pxy_rdir dns_pxy_rdir;

	if( name_server_addr->addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_DNS_PXY_IPC_SEND_REDIRECT_CTRL,"x4Wd",name_server_addr,name_server_addr->addr.v4,internal_port,start_or_end);
	}else if(name_server_addr->addr_family == AF_INET6){
		RHP_TRC(0,RHPTRCID_DNS_PXY_IPC_SEND_REDIRECT_CTRL_V6,"x6Wd",name_server_addr,name_server_addr->addr.v6,internal_port,start_or_end);
	}else{
		RHP_BUG("%d",name_server_addr->addr_family);
		return -EINVAL;
	}

	dns_pxy_rdir.tag[0] = '#';
	dns_pxy_rdir.tag[1] = 'I';
	dns_pxy_rdir.tag[2] = 'M';
	dns_pxy_rdir.tag[3] = 'S';

	dns_pxy_rdir.len = sizeof(rhp_ipcmsg_netmng_dns_pxy_rdir);

	if( start_or_end ){
		dns_pxy_rdir.type = RHP_IPC_NETMNG_DNSPXY_RDIR_START;
	}else{
		dns_pxy_rdir.type = RHP_IPC_NETMNG_DNSPXY_RDIR_END;
	}

	dns_pxy_rdir.reserved = 0;
	dns_pxy_rdir.internal_port = internal_port;

	memcpy(&(dns_pxy_rdir.inet_name_server_addr),name_server_addr,sizeof(rhp_ip_addr));

  err = rhp_ipc_send(RHP_MY_PROCESS,(void*)&dns_pxy_rdir,dns_pxy_rdir.len,0);
  if( err < 0 ){
  	RHP_BUG("");
  }

  return err;
}

static int _rhp_dns_pxy_get_servers(void *ctx,int addr_family)
{
	int err = -EINVAL;
	rhp_ip_addr name_server_ips[RHP_DNS_PXY_MAX_DNS_SERVERS];
	int servers_num = 0;
	int diff_ent = 0;
	struct {
		int addr_family;
		rhp_ip_addr* name_server_ips;
		int* name_server_ips_num;
		rhp_epoll_ctx* epoll_ctx_rx;
	} params[2] = {
			{
			 AF_INET,
			 _rhp_resolv_conf_name_server_ips_v4,
			 &_rhp_resolv_conf_name_server_ips_v4_num,
			 _rhp_dns_pxy_epoll_ctx_rx_v4
			},{
			 AF_INET6,
			 _rhp_resolv_conf_name_server_ips_v6,
			 &_rhp_resolv_conf_name_server_ips_v6_num,
			 _rhp_dns_pxy_epoll_ctx_rx_v6
			}
	};
	int params_idx = (addr_family == AF_INET ? 0 : 1);
	int i,j;

	RHP_TRC(0,RHPTRCID_DNS_PXY_GET_SERVERS,"Ld","AF",addr_family);

	memset(name_server_ips,0,sizeof(rhp_ip_addr)*RHP_DNS_PXY_MAX_DNS_SERVERS);

	err = _rhp_dns_pxy_read_resolv_conf(params[params_idx].addr_family,name_server_ips,&servers_num);
	if( err == -ENOENT ){

		RHP_TRC(0,RHPTRCID_DNS_PXY_GET_SERVERS_NO_ENT,"xLd",ctx,"AF",addr_family);
		goto error;

	}else if( err ){
		RHP_BUG("%d",err);
		goto error;
	}


	if( *(params[params_idx].name_server_ips_num) ||
			!rhp_ip_addr_null(&(params[params_idx].name_server_ips[0]))  ){

		if( *(params[params_idx].name_server_ips_num) == servers_num ){

			for( j = 0; j < servers_num; j++ ){

				rhp_ip_addr* g_name_server_addr = &(params[params_idx].name_server_ips[j]);
				u16 internal_port = RHP_DNS_PXY_EPOLL_CTX_RX_PORT(&(params[params_idx].epoll_ctx_rx[j]));

				for( i = 0; i < servers_num; i++ ){

					if( !rhp_ip_addr_cmp_ip_only(g_name_server_addr,&(name_server_ips[i])) ){

						if( g_name_server_addr[i].addr_family == AF_INET ){
							RHP_TRC(0,RHPTRCID_DNS_PXY_GET_SERVERS_SAME_ENTRY,"x4W",ctx,g_name_server_addr->addr.v4,internal_port);
						}else if( g_name_server_addr[i].addr_family == AF_INET6 ){
							RHP_TRC(0,RHPTRCID_DNS_PXY_GET_SERVERS_SAME_ENTRY_V6,"x6W",ctx,g_name_server_addr->addr.v6,internal_port);
						}

						break;
					}
				}

				if( i == servers_num ){

					if( g_name_server_addr[i].addr_family == AF_INET ){
						RHP_TRC(0,RHPTRCID_DNS_PXY_GET_SERVERS_DIFF_ENTRY,"x4W",ctx,g_name_server_addr->addr.v4,internal_port);
					}else if( g_name_server_addr[i].addr_family == AF_INET6 ){
						RHP_TRC(0,RHPTRCID_DNS_PXY_GET_SERVERS_DIFF_ENTRY_V6,"x6W",ctx,g_name_server_addr->addr.v6,internal_port);
					}

					diff_ent++;
					break;
				}
			}

		}else{

			diff_ent++;
		}

		if( !diff_ent ){

			RHP_TRC(0,RHPTRCID_DNS_PXY_GET_SERVERS_NOT_CHANGED,"x",ctx);
			goto not_changed;
		}

		for( j = 0; j < *(params[params_idx].name_server_ips_num); j++ ){

			rhp_ip_addr* g_name_server_addr = &(params[params_idx].name_server_ips[j]);
			u16 internal_port = RHP_DNS_PXY_EPOLL_CTX_RX_PORT(&(params[params_idx].epoll_ctx_rx[j]));

			if( !rhp_ip_addr_null(g_name_server_addr) ){

				if( g_name_server_addr->addr_family == AF_INET ){
					RHP_TRC(0,RHPTRCID_DNS_PXY_GET_SERVERS_DELETED_ENTRY,"x4d",ctx,g_name_server_addr->addr.v4,_rhp_dns_pxy_main_active_v4);
				}else if( g_name_server_addr->addr_family == AF_INET6 ){
					RHP_TRC(0,RHPTRCID_DNS_PXY_GET_SERVERS_DELETED_ENTRY_V6,"x6d",ctx,g_name_server_addr->addr.v6,_rhp_dns_pxy_main_active_v6);
				}

				if( (_rhp_dns_pxy_main_active_v4 && g_name_server_addr->addr_family == AF_INET) ||
						(_rhp_dns_pxy_main_active_v6 && g_name_server_addr->addr_family == AF_INET6) ){

					_rhp_dns_pxy_ipc_send_redirect_ctrl(g_name_server_addr,internal_port,0); // Delete/flush old entry
				}
			}
		}

	}else{

		RHP_TRC(0,RHPTRCID_DNS_PXY_GET_SERVERS_FIRST_TIME,"x",ctx);
	}


	memset(params[params_idx].name_server_ips,0,sizeof(rhp_ip_addr)*RHP_DNS_PXY_MAX_DNS_SERVERS);
	*(params[params_idx].name_server_ips_num) = servers_num;

	for( i = 0; i < servers_num ; i++ ){

		rhp_ip_addr* name_server_addr = &(name_server_ips[i]);
		u16 internal_port = RHP_DNS_PXY_EPOLL_CTX_RX_PORT(&(params[params_idx].epoll_ctx_rx[i]));

		if( name_server_addr->addr_family == AF_INET ){
			RHP_TRC(0,RHPTRCID_DNS_PXY_GET_SERVERS_ADDED_ENTRY,"xd4Wd",ctx,i,name_server_addr->addr.v4,internal_port,_rhp_dns_pxy_main_active_v4);
		}else if( name_server_addr->addr_family == AF_INET6 ){
			RHP_TRC(0,RHPTRCID_DNS_PXY_GET_SERVERS_ADDED_ENTRY_V6,"xd6Wd",ctx,i,name_server_addr->addr.v6,internal_port,_rhp_dns_pxy_main_active_v6);
		}

		if( (_rhp_dns_pxy_main_active_v4 && name_server_addr->addr_family == AF_INET) ||
				(_rhp_dns_pxy_main_active_v6 && name_server_addr->addr_family == AF_INET6) ){

			_rhp_dns_pxy_ipc_send_redirect_ctrl(name_server_addr,internal_port,1); // Add new entry
		}

		memcpy(&(params[params_idx].name_server_ips[i]),name_server_addr,sizeof(rhp_ip_addr));
	}

not_changed:
	RHP_TRC(0,RHPTRCID_DNS_PXY_GET_SERVERS_RTRN,"Ld","AF",addr_family);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_DNS_PXY_GET_SERVERS_ERR,"LdE","AF",addr_family,err);
	return err;
}

static void _rhp_dns_pxy_handle_rslvr_task(void *ctx)
{
	int err = -EINVAL;
	int noent_err = 0;

	RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_HANDLE_RSLVR_TASK,"xddd",ctx,_rhp_dns_pxy_main_active_v4,_rhp_dns_pxy_main_active_v6,_rhp_resolv_conf_trying);

	RHP_LOCK(&_rhp_dns_pxy_lock);

	err = _rhp_dns_pxy_get_servers(ctx,AF_INET);
	if( err == -ENOENT ){
		noent_err++;
	}else if( err ){
		RHP_BUG("%d",err);
		goto error_l;
	}
	err = 0;


	if( !rhp_gcfg_ipv6_disabled ){

		err = _rhp_dns_pxy_get_servers(ctx,AF_INET6);
		if( err == -ENOENT ){
			noent_err++;
		}else if( err ){
			RHP_BUG("%d",err);
			goto error_l;
		}
		err = 0;
	}


	if( noent_err ){

		if( _rhp_resolv_conf_trying < RHP_DNS_PXY_RSLV_TRY_MAX ){

			err = rhp_timer_oneshot(_rhp_dns_pxy_handle_rslvr_task,NULL,
							rhp_gcfg_dns_pxy_retry_interval); // Retry!
			if( err ){
				RHP_BUG("%d",err);
			}

			_rhp_resolv_conf_trying++;

			goto error_l;

		}else{

			RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_HANDLE_RSLVR_TASK_RETRY_EXPIRED,"xd",ctx,_rhp_resolv_conf_trying);
		}
	}

	_rhp_resolv_conf_trying = 0;


error_l:
	_rhp_dnx_pxy_reading_resolv_conf = 0;

	RHP_UNLOCK(&_rhp_dns_pxy_lock);

	RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_HANDLE_RSLVR_TASK_RTRN,"x",ctx);
	return;
}

static int _rhp_dns_pxy_handle_rslvr(struct epoll_event* epoll_evt,rhp_epoll_ctx* epoll_ctx)
{
	int err = -EINVAL;
#define RHP_DNS_PXY_INOTIFY_BUF_LEN		((sizeof(struct inotify_event) + 64)*4)
	u8 buf[RHP_DNS_PXY_INOTIFY_BUF_LEN];
	ssize_t n;
	int fd = RHP_DNS_PXY_EPOLL_CTX_INOTIFY_FD(epoll_ctx);

	RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_HANDLE_RSLVR,"xxd",epoll_evt,epoll_ctx,fd);

  RHP_LOCK(&(_rhp_dns_pxy_lock));

	while( 1 ){

		n = read(fd,buf,RHP_DNS_PXY_INOTIFY_BUF_LEN);
		if( n < 0 ){
			break;
		}

		// Just drop/consume events!
	}

  if( !_rhp_dnx_pxy_reading_resolv_conf ){

  	err = rhp_timer_oneshot(_rhp_dns_pxy_handle_rslvr_task,NULL,rhp_gcfg_dns_pxy_convergence_interval);
  	if( err ){
  		RHP_BUG("%d");
  		goto error;
  	}

  	_rhp_dnx_pxy_reading_resolv_conf = 1;
  }

	_rhp_dns_pxy_resolv_conf_cleanup(epoll_ctx);

  err = _rhp_dns_pxy_resolv_conf_init();
  if( err ){
  	RHP_BUG("%d");
  	goto error;
  }

error:
  RHP_UNLOCK(&(_rhp_dns_pxy_lock));

	RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_HANDLE_RSLVR_RTRN,"xxE",epoll_evt,epoll_ctx,err);
	return err;
}


static int _rhp_dns_pxy_trans_tbl_hash(rhp_ip_addr* trans_src,rhp_ip_addr* trans_dst,int* hval_r)
{
	u32 hval;

	if( trans_src->addr_family == AF_INET ){

		RHP_TRC(0,RHPTRCID_DNS_PXY_TRANS_TBL_HASH,"4W4W",trans_src->addr.v4,trans_src->port,trans_dst->addr.v4,trans_dst->port);

		hval = _rhp_hash_ipv4_udp(trans_src->addr.v4,trans_src->port,trans_dst->addr.v4,trans_dst->port,_rhp_dns_pxy_trans_tbl_hashtbl_rnd);

	}else if( trans_src->addr_family == AF_INET6 ){

		RHP_TRC(0,RHPTRCID_DNS_PXY_TRANS_TBL_HASH_V6,"6W6W",trans_src->addr.v6,trans_src->port,trans_dst->addr.v6,trans_dst->port);

		hval = _rhp_hash_ipv6_udp(trans_src->addr.v6,trans_src->port,trans_dst->addr.v6,trans_dst->port,_rhp_dns_pxy_trans_tbl_hashtbl_rnd);

	}else{
		RHP_BUG("%d",trans_src->addr_family);
		return -EINVAL;
	}

	*hval_r = (int)( hval % RHP_DNS_PXY_TRS_TBL_HASH_TABLE_SIZE );

	return 0;
}


static int _rhp_dns_pxy_trans_tbl_hash_pkt_ipv4_rvs(rhp_proto_ip_v4* iph,rhp_proto_udp* udph)
{
	u32 hval;

	RHP_TRC(0,RHPTRCID_DNS_PXY_TRANS_TBL_HASH_RVS,"4W4W",iph->dst_addr,udph->dst_port,iph->src_addr,udph->src_port);

	hval = _rhp_hash_ipv4_udp(iph->dst_addr,udph->dst_port,iph->src_addr,udph->src_port,_rhp_dns_pxy_trans_tbl_hashtbl_rnd);

	return (int)( hval % RHP_DNS_PXY_TRS_TBL_HASH_TABLE_SIZE );
}

static int _rhp_dns_pxy_trans_tbl_hash_pkt_ipv6_rvs(rhp_proto_ip_v6* ip6h,rhp_proto_udp* udph)
{
	u32 hval;

	RHP_TRC(0,RHPTRCID_DNS_PXY_TRANS_TBL_HASH_RVS_V6,"6W6W",ip6h->dst_addr,udph->dst_port,ip6h->src_addr,udph->src_port);

	hval = _rhp_hash_ipv6_udp(ip6h->dst_addr,udph->dst_port,ip6h->src_addr,udph->src_port,_rhp_dns_pxy_trans_tbl_hashtbl_rnd);

	return (int)( hval % RHP_DNS_PXY_TRS_TBL_HASH_TABLE_SIZE );
}

// Caller must acquire _rhp_dns_pxy_lock.
static int _rhp_dns_pxy_trans_tbl_add(rhp_packet* tx_pkt,rhp_ip_addr* orig_src,rhp_ip_addr* orig_dst,
		rhp_epoll_ctx* epoll_ctx,int orig_nsvr_idx,int fwdto)
{
	int err = -EINVAL;
	rhp_dns_pxy_trans_tbl* ttbl = NULL;
	rhp_proto_dns* dnsh;
	int hval;

	RHP_TRC(0,RHPTRCID_DNS_PXY_TRANS_TBL_ADD,"xxxdd",tx_pkt,orig_src,orig_dst,_rhp_dns_pxy_trans_tbl_num,fwdto);
	rhp_ip_addr_dump("orig_src",orig_src);
	rhp_ip_addr_dump("orig_dst",orig_dst);

	if( _rhp_dns_pxy_trans_tbl_num > rhp_gcfg_dns_pxy_trans_tbl_max_num ){
		RHP_TRC(0,RHPTRCID_DNS_PXY_TRANS_TBL_ADD_MAX_ERR,"xdd",tx_pkt,_rhp_dns_pxy_trans_tbl_num,rhp_gcfg_dns_pxy_trans_tbl_max_num);
		goto error;
	}

	{
		ttbl = (rhp_dns_pxy_trans_tbl*)_rhp_malloc(sizeof(rhp_dns_pxy_trans_tbl));
		if( ttbl == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}

		memset(ttbl,0,sizeof(rhp_dns_pxy_trans_tbl));

		ttbl->tag[0] = '#';
		ttbl->tag[1] = 'D';
		ttbl->tag[2] = 'X';
		ttbl->tag[3] = 'T';

		memcpy(&(ttbl->orig_src),orig_src,sizeof(rhp_ip_addr));
		memcpy(&(ttbl->orig_dst),orig_dst,sizeof(rhp_ip_addr));

		if( tx_pkt->type == RHP_PKT_IPV4_DNS ){

			rhp_ip_addr_set2(&(ttbl->trans_src),
					AF_INET,(u8*)&(tx_pkt->l3.iph_v4->src_addr),tx_pkt->l4.udph->src_port);

			rhp_ip_addr_set2(&(ttbl->trans_dst),
					AF_INET,(u8*)&(tx_pkt->l3.iph_v4->dst_addr),tx_pkt->l4.udph->dst_port);

		}else	if( tx_pkt->type == RHP_PKT_IPV6_DNS ){

			rhp_ip_addr_set2(&(ttbl->trans_src),
					AF_INET6,tx_pkt->l3.iph_v6->src_addr,tx_pkt->l4.udph->src_port);

			rhp_ip_addr_set2(&(ttbl->trans_dst),
					AF_INET6,tx_pkt->l3.iph_v6->dst_addr,tx_pkt->l4.udph->dst_port);

		}else{
			err = -EINVAL;
			RHP_BUG("%d",err);
			goto error;
		}

		dnsh = (rhp_proto_dns*)tx_pkt->app.raw;
		ttbl->dns_txn_id = dnsh->txn_id;

		ttbl->expire = _rhp_get_time() + (time_t)rhp_gcfg_dns_pxy_trans_tbl_timeout;
		ttbl->expire2 = _rhp_get_time() + (time_t)rhp_gcfg_dns_pxy_trans_tbl_timeout2;
		ttbl->epoll_ctx = epoll_ctx;

		ttbl->orig_nsvr_idx = orig_nsvr_idx;
		ttbl->fwdto = fwdto;

		if( ttbl->trans_src.addr_family == AF_INET ){
			RHP_TRC(0,RHPTRCID_DNS_PXY_TRANS_TBL_ADD_DNS_INFO,"xWddd4W4Wd",tx_pkt,ttbl->dns_txn_id,ttbl->expire,ttbl->expire2,ttbl->orig_nsvr_idx,ttbl->trans_src.addr.v4,ttbl->trans_src.port,ttbl->trans_dst.addr.v4,ttbl->trans_dst.port,ttbl->fwdto);
		}else if( ttbl->trans_src.addr_family == AF_INET6 ){
			RHP_TRC(0,RHPTRCID_DNS_PXY_TRANS_TBL_ADD_DNS_INFO_V6,"xWddd6W6Wd",tx_pkt,ttbl->dns_txn_id,ttbl->expire,ttbl->expire2,ttbl->orig_nsvr_idx,ttbl->trans_src.addr.v6,ttbl->trans_src.port,ttbl->trans_dst.addr.v6,ttbl->trans_dst.port,ttbl->fwdto);
		}
	}

	err = _rhp_dns_pxy_trans_tbl_hash(&(ttbl->trans_src),&(ttbl->trans_dst),&hval);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	ttbl->hval = hval;

	ttbl->hash_next = _rhp_dns_pxy_trans_tbl_hashtbl[hval];
	_rhp_dns_pxy_trans_tbl_hashtbl[hval] = ttbl;

	ttbl->lst_next = _rhp_dns_pxy_trans_tbl_head.lst_next;
	if( ttbl->lst_next ){
		ttbl->lst_next->lst_prev = ttbl;
	}
	ttbl->lst_prev = &_rhp_dns_pxy_trans_tbl_head;
	 _rhp_dns_pxy_trans_tbl_head.lst_next = ttbl;


	_rhp_dns_pxy_trans_tbl_num++;

	RHP_TRC(0,RHPTRCID_DNS_PXY_TRANS_TBL_ADD_RTRN,"xxx",tx_pkt,orig_src,orig_dst);
	return 0;

error:
	if( ttbl ){
		_rhp_free(ttbl);
	}

	RHP_TRC(0,RHPTRCID_DNS_PXY_TRANS_TBL_ADD_ERR,"xxxE",tx_pkt,orig_src,orig_dst,err);
	return err;
}

static void _rhp_dns_pxy_trans_tbl_delete(rhp_dns_pxy_trans_tbl* ttbl)
{
	rhp_dns_pxy_trans_tbl *tmp,*tmp_p = NULL;

	RHP_TRC(0,RHPTRCID_DNS_PXY_TRANS_TBL_DELETE,"x",ttbl);

	tmp = _rhp_dns_pxy_trans_tbl_hashtbl[ttbl->hval];
	while( tmp ){

		if( tmp == ttbl ){
			break;
		}

		tmp_p = tmp;
		tmp = tmp->hash_next;
	}

	if( tmp == NULL ){
		RHP_BUG("");
		goto error;
	}

	if( ttbl->trans_src.addr_family == AF_INET ){
		if( ttbl->orig_src.addr_family == AF_INET ){
			RHP_TRC(0,RHPTRCID_DNS_PXY_TRANS_TBL_DELETE_TTBL_INFO_44,"Wddd4W4W4W4W",ttbl->dns_txn_id,ttbl->expire,ttbl->orig_nsvr_idx,ttbl->hval,ttbl->orig_src.addr.v4,ttbl->orig_src.port,ttbl->orig_dst.addr.v4,ttbl->orig_dst.port,ttbl->trans_src.addr.v4,ttbl->trans_src.port,ttbl->trans_dst.addr.v4,ttbl->trans_dst.port);
		}else{
			RHP_TRC(0,RHPTRCID_DNS_PXY_TRANS_TBL_DELETE_TTBL_INFO_46,"Wddd6W6W4W4W",ttbl->dns_txn_id,ttbl->expire,ttbl->orig_nsvr_idx,ttbl->hval,ttbl->orig_src.addr.v6,ttbl->orig_src.port,ttbl->orig_dst.addr.v6,ttbl->orig_dst.port,ttbl->trans_src.addr.v4,ttbl->trans_src.port,ttbl->trans_dst.addr.v4,ttbl->trans_dst.port);
		}
	}else if( ttbl->trans_src.addr_family == AF_INET6 ){
		if( ttbl->orig_src.addr_family == AF_INET ){
			RHP_TRC(0,RHPTRCID_DNS_PXY_TRANS_TBL_DELETE_TTBL_INFO_V6_64,"Wddd4W4W6W6W",ttbl->dns_txn_id,ttbl->expire,ttbl->orig_nsvr_idx,ttbl->hval,ttbl->orig_src.addr.v4,ttbl->orig_src.port,ttbl->orig_dst.addr.v4,ttbl->orig_dst.port,ttbl->trans_src.addr.v6,ttbl->trans_src.port,ttbl->trans_dst.addr.v6,ttbl->trans_dst.port);
		}else{
			RHP_TRC(0,RHPTRCID_DNS_PXY_TRANS_TBL_DELETE_TTBL_INFO_V6_66,"Wddd6W6W6W6W",ttbl->dns_txn_id,ttbl->expire,ttbl->orig_nsvr_idx,ttbl->hval,ttbl->orig_src.addr.v6,ttbl->orig_src.port,ttbl->orig_dst.addr.v6,ttbl->orig_dst.port,ttbl->trans_src.addr.v6,ttbl->trans_src.port,ttbl->trans_dst.addr.v6,ttbl->trans_dst.port);
		}
	}

	if( tmp_p == NULL ){
		_rhp_dns_pxy_trans_tbl_hashtbl[ttbl->hval] = ttbl->hash_next;
	}else{
		tmp_p->hash_next = ttbl->hash_next;
	}

	ttbl->lst_prev->lst_next = ttbl->lst_next;
  if( ttbl->lst_next ){
  	ttbl->lst_next->lst_prev = ttbl->lst_prev;
  }
  ttbl->lst_prev = NULL;
  ttbl->lst_next = NULL;


  if( ttbl->epoll_ctx ){

	  struct epoll_event ep_evt;
  	int dns_fwd_sk = RHP_DNS_PXY_EPOLL_CTX_SK(ttbl->epoll_ctx);

  	memset(&ep_evt,0,sizeof(struct epoll_event));

    if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_DEL,dns_fwd_sk,&ep_evt) < 0 ){
      RHP_BUG("");
    }

    _rhp_dns_pxy_close_sk(&dns_fwd_sk);

    _rhp_free(ttbl->epoll_ctx);
    ttbl->epoll_ctx = NULL;
  }

	_rhp_dns_pxy_trans_tbl_num--;

error:
	RHP_TRC(0,RHPTRCID_DNS_PXY_TRANS_TBL_DELETE_RTRN,"xxd",ttbl,tmp,_rhp_dns_pxy_trans_tbl_num);
	return;
}

rhp_dns_pxy_trans_tbl* _rhp_dns_pxy_trans_tbl_get_by_rx_pkt(rhp_packet* rx_pkt)
{
  rhp_proto_ip_v4* iph = NULL;
  rhp_proto_ip_v6* ip6h = NULL;
  rhp_proto_udp* udph;
  rhp_proto_dns* dnsh;
	rhp_dns_pxy_trans_tbl* ttbl = NULL;
  int hval = 0;

	RHP_TRC(0,RHPTRCID_DNS_PXY_TRANS_TBL_GET_BY_RX_PKT,"xLd",rx_pkt,"PKT",rx_pkt->type);

	if( rx_pkt->type == RHP_PKT_IPV4_DNS ){
		iph = rx_pkt->l3.iph_v4;
	}else if( rx_pkt->type == RHP_PKT_IPV6_DNS ){
		ip6h = rx_pkt->l3.iph_v6;
	}else{
		RHP_BUG("");
		return NULL;
	}

	udph = rx_pkt->l4.udph;
	dnsh = (rhp_proto_dns*)(rx_pkt->app.raw);

	RHP_TRC(0,RHPTRCID_DNS_PXY_TRANS_TBL_GET_BY_RX_PKT_RX_PKT,"xa",rx_pkt,((((u8*)udph) + ntohs(udph->len)) - (u8*)rx_pkt->l2.raw),RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,rx_pkt->l2.raw);

	if( iph ){

		hval = _rhp_dns_pxy_trans_tbl_hash_pkt_ipv4_rvs(iph,udph);

	}else if( ip6h ){

		hval = _rhp_dns_pxy_trans_tbl_hash_pkt_ipv6_rvs(ip6h,udph);
	}

	{
		ttbl =  _rhp_dns_pxy_trans_tbl_hashtbl[hval];
		while( ttbl ){

			if( ttbl->dns_txn_id == dnsh->txn_id &&
					((iph && ttbl->trans_dst.addr.v4 == iph->src_addr &&
							     ttbl->trans_src.addr.v4 == iph->dst_addr) ||
					 (ip6h && rhp_ipv6_is_same_addr(ttbl->trans_dst.addr.v6,ip6h->src_addr) &&
							      rhp_ipv6_is_same_addr(ttbl->trans_src.addr.v6,ip6h->dst_addr))) &&
					ttbl->trans_dst.port == udph->src_port &&
					ttbl->trans_src.port == udph->dst_port ){

				break;
			}

			ttbl = ttbl->hash_next;
		}

		if( ttbl == NULL ){
			RHP_TRC(0,RHPTRCID_DNS_PXY_TRANS_TBL_GET_BY_RX_PKT_TBL_NOT_FOUND,"x",rx_pkt);
			goto ignore;
		}
	}

	if( ttbl->orig_src.addr_family == AF_INET ){
		if( ttbl->trans_src.addr_family == AF_INET ){
			RHP_TRC(0,RHPTRCID_DNS_PXY_TRANS_TBL_GET_BY_RX_PKT_TTBL_INFO_44,"WLdddd4W4WLd4W4Wd",ttbl->dns_txn_id,"AF",ttbl->orig_src.addr_family,ttbl->expire,ttbl->orig_nsvr_idx,ttbl->hval,ttbl->orig_src.addr.v4,ttbl->orig_src.port,ttbl->orig_dst.addr.v4,ttbl->orig_dst.port,"AF",ttbl->trans_src.addr_family,ttbl->trans_src.addr.v4,ttbl->trans_src.port,ttbl->trans_dst.addr.v4,ttbl->trans_dst.port,ttbl->fwdto);
		}else{
			RHP_TRC(0,RHPTRCID_DNS_PXY_TRANS_TBL_GET_BY_RX_PKT_TTBL_INFO_46,"WLdddd4W4WLd6W6Wd",ttbl->dns_txn_id,"AF",ttbl->orig_src.addr_family,ttbl->expire,ttbl->orig_nsvr_idx,ttbl->hval,ttbl->orig_src.addr.v4,ttbl->orig_src.port,ttbl->orig_dst.addr.v4,ttbl->orig_dst.port,"AF",ttbl->trans_src.addr_family,ttbl->trans_src.addr.v6,ttbl->trans_src.port,ttbl->trans_dst.addr.v6,ttbl->trans_dst.port,ttbl->fwdto);
		}
	}else if( ttbl->orig_src.addr_family == AF_INET6 ){
		if( ttbl->trans_src.addr_family == AF_INET ){
			RHP_TRC(0,RHPTRCID_DNS_PXY_TRANS_TBL_GET_BY_RX_PKT_TTBL_INFO_V6_64,"WLdddd6W6WLd4W4Wd",ttbl->dns_txn_id,"AF",ttbl->orig_src.addr_family,ttbl->expire,ttbl->orig_nsvr_idx,ttbl->hval,ttbl->orig_src.addr.v6,ttbl->orig_src.port,ttbl->orig_dst.addr.v6,ttbl->orig_dst.port,"AF",ttbl->trans_src.addr_family,ttbl->trans_src.addr.v4,ttbl->trans_src.port,ttbl->trans_dst.addr.v4,ttbl->trans_dst.port,ttbl->fwdto);
		}else{
			RHP_TRC(0,RHPTRCID_DNS_PXY_TRANS_TBL_GET_BY_RX_PKT_TTBL_INFO_V6_66,"WLdddd6W6WLd6W6Wd",ttbl->dns_txn_id,"AF",ttbl->orig_src.addr_family,ttbl->expire,ttbl->orig_nsvr_idx,ttbl->hval,ttbl->orig_src.addr.v6,ttbl->orig_src.port,ttbl->orig_dst.addr.v6,ttbl->orig_dst.port,"AF",ttbl->trans_src.addr_family,ttbl->trans_src.addr.v6,ttbl->trans_src.port,ttbl->trans_dst.addr.v6,ttbl->trans_dst.port,ttbl->fwdto);
		}
	}

	RHP_TRC(0,RHPTRCID_DNS_PXY_TRANS_TBL_GET_BY_RX_PKT_RTRN,"x",rx_pkt);
	return ttbl;

ignore:
	RHP_TRC(0,RHPTRCID_DNS_PXY_TRANS_TBL_GET_BY_RX_PKT_ERR,"x",rx_pkt);
	return NULL;
}

static void _rhp_dns_pxy_exec_gc_no_lock(int aggressive)
{
	rhp_dns_pxy_trans_tbl *ttbl,*ttbl_n;
	time_t now = _rhp_get_time();

	RHP_TRC_FREQ(0,RHPTRCID_DNS_PXY_EXEC_GC_NO_LOCK,"dd",now,aggressive);

  ttbl = _rhp_dns_pxy_trans_tbl_head.lst_next;

  while( ttbl ){

  	int flag = 0;

  	ttbl_n = ttbl->lst_next;

  	if( ttbl->expire <= now ){

  		flag = 1;

  	}else if( aggressive ){

  		long fwd_open_sks = _rhp_atomic_read(&_rhp_dns_pxy_sk_num);

  		if( fwd_open_sks < rhp_gcfg_dns_pxy_fwd_max_sockets ){

  			break;

  		}else if( ttbl->expire2 <= now ){

  			flag = 1;
  		}
  	}

  	if( flag ){

  		_rhp_dns_pxy_trans_tbl_delete(ttbl);
    	_rhp_free(ttbl);

			rhp_esp_g_statistics_inc(dns_pxy_gc_drop_queries);
  	}

  	ttbl = ttbl_n;
  }

	RHP_TRC_FREQ(0,RHPTRCID_DNS_PXY_EXEC_GC_NO_LOCK_RTRN,"d",now);
  return;
}

void rhp_dns_pxy_exec_gc()
{
	RHP_TRC_FREQ(0,RHPTRCID_DNS_PXY_EXEC_GC,"");

  RHP_LOCK_FREQ(&_rhp_dns_pxy_lock);

  _rhp_dns_pxy_exec_gc_no_lock(0);

  RHP_UNLOCK_FREQ(&_rhp_dns_pxy_lock);

	RHP_TRC_FREQ(0,RHPTRCID_DNS_PXY_EXEC_GC_RTRN,"");
  return;
}

//
// TODO : Multiple queries (dnsh->qdcount >= 2).
//
#define RHP_DNS_PXY_MAX_DNS_PKT	1024 // Actually, the max size is 512B.
static int _rhp_dns_pxy_parse_dns_pkt(u8* rx_buf,int rx_buf_len,char** queried_domain_r)
{
	int err = -EINVAL;
	rhp_proto_dns* dnsh = (rhp_proto_dns*)rx_buf;
	u16 qnum;
#define RHP_DNS_PXY_PARSE_BUF_LEN		256
	char *queried_domain = NULL,*cur;
	u8 *pt;
	int rem,cur_len,cur_rem;

	RHP_TRC(0,RHPTRCID_DNS_PXY_PARSE_DNS_PKT,"px",rx_buf_len,rx_buf,queried_domain_r);

	if( rx_buf_len < (int)sizeof(rhp_proto_dns) ){
		err = RHP_STATUS_INVALID_DNS_PKT;
		RHP_TRC(0,RHPTRCID_DNS_PXY_PARSE_DNS_PKT_INVALID_DNS,"");
		goto error;
	}

	if( rx_buf_len > RHP_DNS_PXY_MAX_DNS_PKT ){
		err = RHP_STATUS_INVALID_DNS_PKT;
		RHP_TRC(0,RHPTRCID_DNS_PXY_PARSE_DNS_PKT_INVALID_DNS_TOO_BIG,"");
		goto error;
	}

	qnum = ntohs(dnsh->qdcount);

	if( qnum == 0 ){
		err = RHP_STATUS_DNS_PKT_NOT_INTERESTED;
		RHP_TRC(0,RHPTRCID_DNS_PXY_PARSE_DNS_PKT_NO_QUERY,"");
		goto error;
	}

	queried_domain = (char*)_rhp_malloc(RHP_DNS_PXY_PARSE_BUF_LEN);
	if( queried_domain == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	cur = queried_domain;
	cur_len = cur_rem = RHP_DNS_PXY_PARSE_BUF_LEN;

	pt = (u8*)(dnsh + 1);
	rem = rx_buf_len - sizeof(rhp_proto_dns);

	while( rem ){

		u8 label_len = *pt;

		rem--;
		pt++;

		if( label_len == 0 || rem < 1 ){
			break;
		}

		rem -= label_len;
		if( rem < 1 ){
			err = RHP_STATUS_DNS_PKT_NOT_INTERESTED;
			goto error;
		}

		if( cur_rem < (label_len + 1) ){

			char* tmp = queried_domain;
			int exp_len = cur_len + (label_len + 1);

			queried_domain = (char*)_rhp_malloc(cur_len + exp_len);
			if( queried_domain == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				queried_domain = tmp;
				goto error;
			}

			memcpy(queried_domain,tmp,cur_len);
			cur = queried_domain + cur_len;
			cur_rem = exp_len;
			cur_len = cur_len + exp_len;
			_rhp_free(tmp);
		}

		memcpy(cur,pt,label_len);
		cur += label_len;
		*cur = '.';
		cur++;

		pt += label_len;
	}

	if( queried_domain == cur ){
		err = RHP_STATUS_DNS_PKT_NOT_INTERESTED;
		RHP_TRC(0,RHPTRCID_DNS_PXY_PARSE_DNS_PKT_DNAME_NOT_FOUND,"");
		goto error;
	}

	*(cur - 1) = '\0';
	*queried_domain_r = queried_domain;

	RHP_TRC(0,RHPTRCID_DNS_PXY_PARSE_DNS_PKT_RTRN,"s",queried_domain);
	return 0;

error:
	if( queried_domain ){
		_rhp_free(queried_domain);
	}
	RHP_TRC(0,RHPTRCID_DNS_PXY_PARSE_DNS_PKT_ERR,"E",err);
	return err;
}

//
// [IMPL NOTE]
//
//   This func opens a socket per DNS query and doesn't share
//   the socket between the queries.
//   So, the open socket is bound to a randomized local port
//   assigned by network stack.
//   This is for security concerns related to DNS spoofing.
//
static int _rhp_dns_pxy_protected_rx_fwd_pkt(rhp_packet *pkt,
		rhp_ip_addr* orig_src,rhp_ip_addr* orig_dst,rhp_ifc_entry* v_ifc)
{
  int err = 0;
  int tx_len;
  u8* tx_buf;
  struct epoll_event ep_evt;
  rhp_epoll_ctx* epoll_ctx = NULL;
  int dns_fwd_sk = -1;
  union {
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
    unsigned char raw;
  } dst_sin;
  socklen_t dst_sa_len = 0;
  union {
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
    unsigned char raw;
  } my_sin;
  socklen_t my_sin_len;
  int fwdto = RHP_DNSPXY_FWD_TO_INET;
  int addr_family,event_type;

  if( pkt->type == RHP_PKT_IPV4_DNS ){
  	if( orig_src->addr_family == AF_INET ){
  		RHP_TRC(0,RHPTRCID_DNS_PXY_RX_FORWARD_PKT_44,"xxxx4W4Wa",pkt,orig_src,orig_dst,v_ifc,orig_src->addr.v4,orig_src->port,orig_dst->addr.v4,orig_dst->port,((pkt->l4.raw + ntohs(pkt->l4.udph->len)) - pkt->l2.raw),RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,pkt->l2.raw);
  	}else{
  		RHP_TRC(0,RHPTRCID_DNS_PXY_RX_FORWARD_PKT_46,"xxxx6W6Wa",pkt,orig_src,orig_dst,v_ifc,orig_src->addr.v6,orig_src->port,orig_dst->addr.v6,orig_dst->port,((pkt->l4.raw + ntohs(pkt->l4.udph->len)) - pkt->l2.raw),RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,pkt->l2.raw);
  	}
  }else if( pkt->type == RHP_PKT_IPV6_DNS ){
  	if( orig_src->addr_family == AF_INET ){
    	RHP_TRC(0,RHPTRCID_DNS_PXY_RX_FORWARD_PKT_V6_64,"xxxx4W4Wa",pkt,orig_src,orig_dst,v_ifc,orig_src->addr.v4,orig_src->port,orig_dst->addr.v4,orig_dst->port,((pkt->l4.raw + ntohs(pkt->l4.udph->len)) - pkt->l2.raw),RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,pkt->l2.raw);
  	}else{
    	RHP_TRC(0,RHPTRCID_DNS_PXY_RX_FORWARD_PKT_V6_66,"xxxx6W6Wa",pkt,orig_src,orig_dst,v_ifc,orig_src->addr.v6,orig_src->port,orig_dst->addr.v6,orig_dst->port,((pkt->l4.raw + ntohs(pkt->l4.udph->len)) - pkt->l2.raw),RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,pkt->l2.raw);
  	}
  }else{
  	RHP_BUG("%d",pkt->type);
  }

  RHP_LOCK(&(_rhp_dns_pxy_lock));


  if( rhp_gcfg_dns_pxy_fwd_max_sockets ){

  	long fwd_open_sks;

		if( (fwd_open_sks = _rhp_atomic_read(&_rhp_dns_pxy_sk_num))
					>= rhp_gcfg_dns_pxy_fwd_max_sockets ){

			RHP_TRC_FREQ(0,RHPTRCID_DNS_PXY_RX_FORWARD_PKT_TOO_MANY_OPEN_SKS_EXEC_GC,"sf",pkt,fwd_open_sks);

			rhp_esp_g_statistics_inc(dns_pxy_max_pending_queries_reached);

			_rhp_dns_pxy_exec_gc_no_lock(0);
		}

		if( (fwd_open_sks = _rhp_atomic_read(&_rhp_dns_pxy_sk_num))
					>= rhp_gcfg_dns_pxy_fwd_max_sockets ){

			RHP_TRC_FREQ(0,RHPTRCID_DNS_PXY_RX_FORWARD_PKT_TOO_MANY_OPEN_SKS_EXEC_GC_2,"sf",pkt,fwd_open_sks);

			_rhp_dns_pxy_exec_gc_no_lock(1);
		}

		if( (fwd_open_sks = _rhp_atomic_read(&_rhp_dns_pxy_sk_num))
					>= rhp_gcfg_dns_pxy_fwd_max_sockets ){

			RHP_TRC_FREQ(0,RHPTRCID_DNS_PXY_RX_FORWARD_PKT_TOO_MANY_OPEN_SKS,"sf",pkt,fwd_open_sks);
			err = -EMFILE;
			goto error;
		}
  }


  if( pkt->l3.raw == NULL || pkt->app.raw == NULL ){
    err = -EINVAL;
    RHP_BUG("0x%lx,0x%lx",pkt->l3.iph_v4,pkt->app.raw);
    goto error;
  }

  if( pkt->type == RHP_PKT_IPV4_DNS ){

		if( pkt->l3.iph_v4->dst_addr == 0 ){
			err = -EINVAL;
			RHP_BUG("%d",pkt->l3.iph_v4->dst_addr);
			goto error;
		}

		tx_len = ntohs(pkt->l3.iph_v4->total_len) - ((pkt->l3.iph_v4->ihl)*4) - sizeof(rhp_proto_udp);
		addr_family = AF_INET;
		event_type = RHP_MAIN_EPOLL_DNSPXY_INET_V4;

  }else if( pkt->type == RHP_PKT_IPV6_DNS ){

  	if( rhp_ipv6_addr_null(pkt->l3.iph_v6->dst_addr) ){
			err = -EINVAL;
			RHP_BUG("");
			goto error;
  	}

		tx_len = ntohs(pkt->l3.iph_v6->payload_len) - sizeof(rhp_proto_udp);
		addr_family = AF_INET6;
		event_type = RHP_MAIN_EPOLL_DNSPXY_INET_V6;

  }else{
    err = -EINVAL;
    RHP_BUG("%d",pkt->type);
    goto error;
  }

	tx_buf = pkt->app.raw;


	dns_fwd_sk = socket(addr_family, SOCK_DGRAM,0);
  if( dns_fwd_sk < 0 ){
    err = -errno;
    RHP_BUG("%d",err);
    goto error;
  }

  _rhp_atomic_inc(&_rhp_dns_pxy_sk_num);


  //
  // [CAUTION]
  //  O_NONBLOCK is NOT set because MSG_DONTWAIT is set with recvmsg().
  //

  {
  	epoll_ctx = (rhp_epoll_ctx*)_rhp_malloc(sizeof(rhp_epoll_ctx));
		if( epoll_ctx == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		memset(epoll_ctx,0,sizeof(rhp_epoll_ctx));

		epoll_ctx->event_type = event_type;
		RHP_DNS_PXY_EPOLL_CTX_SK(epoll_ctx) = dns_fwd_sk;
		RHP_DNS_PXY_EPOLL_CTX_FWD_DNX_TXNID(epoll_ctx) = ((rhp_proto_dns*)pkt->app.raw)->txn_id;
  }

  if( v_ifc ){

    union {
      struct sockaddr_in v4;
      struct sockaddr_in6 v6;
      unsigned char raw;
    } src_sin;
    socklen_t src_sa_len = 0;

    fwdto = RHP_DNSPXY_FWD_TO_VPN;

    RHP_LOCK(&(v_ifc->lock));
    {
    	rhp_ifc_addr* ifc_addr;
    	u8* dst_addr = NULL;

			RHP_TRC(0,RHPTRCID_DNS_PXY_RX_FORWARD_PKT_TX_VIF,"xxs",pkt,v_ifc,v_ifc->if_name);


    	if( !_rhp_atomic_read(&(v_ifc->is_active)) ){

    		err = -EINVAL;
				RHP_TRC(0,RHPTRCID_DNS_PXY_RX_FORWARD_PKT_VIF_NOT_ACTIVE,"xxs",pkt,v_ifc,v_ifc->if_name);

				RHP_UNLOCK(&(v_ifc->lock));
    		goto error;
    	}


    	if( addr_family == AF_INET ){
    		dst_addr = (u8*)&(pkt->l3.iph_v4->dst_addr);
    	}else if( addr_family == AF_INET6 ){
    		dst_addr = pkt->l3.iph_v6->dst_addr;
    	}

    	ifc_addr = v_ifc->select_src_addr(v_ifc,addr_family,dst_addr,0);
    	if( ifc_addr == NULL ){

    		err = -ENOENT;
				RHP_TRC(0,RHPTRCID_DNS_PXY_RX_FORWARD_PKT_VIF_ADDR_ERR,"xxs",pkt,v_ifc,v_ifc->if_name);

				RHP_UNLOCK(&(v_ifc->lock));
    		goto error;
    	}


    	if( addr_family == AF_INET ){

    		src_sin.v4.sin_family = AF_INET;
				src_sin.v4.sin_port = 0;
				src_sin.v4.sin_addr.s_addr = ifc_addr->addr.addr.v4;
				src_sa_len = sizeof(struct sockaddr_in);

    	}else if( addr_family == AF_INET6 ){

    		src_sin.v6.sin6_family = AF_INET6;
    		src_sin.v6.sin6_port = 0;
    		src_sin.v6.sin6_flowinfo = 0;
    		memcpy( src_sin.v6.sin6_addr.s6_addr, ifc_addr->addr.addr.v6, 16 );
    		src_sin.v6.sin6_scope_id = 0;
    		src_sa_len = sizeof(struct sockaddr_in6);
    	}

			err = bind(dns_fwd_sk,(struct sockaddr*)&src_sin,src_sa_len);
			if( err < 0 ){

				err = -errno;
				RHP_TRC(0,RHPTRCID_DNS_PXY_RX_FORWARD_PKT_BIND_ERR,"xE",pkt,err);

				RHP_UNLOCK(&(v_ifc->lock));
				goto error;
			}

    }
		RHP_UNLOCK(&(v_ifc->lock));
  }

  {
		if( addr_family == AF_INET ){

			dst_sin.v4.sin_family = AF_INET;
			dst_sin.v4.sin_port = htons(RHP_PROTO_DNS_PORT);
			dst_sin.v4.sin_addr.s_addr = pkt->l3.iph_v4->dst_addr;
			dst_sa_len = sizeof(struct sockaddr_in);

		}else if( addr_family == AF_INET6 ){

			dst_sin.v6.sin6_family = AF_INET6;
			dst_sin.v6.sin6_port = htons(RHP_PROTO_DNS_PORT);
			dst_sin.v6.sin6_flowinfo = 0;
			memcpy( dst_sin.v6.sin6_addr.s6_addr, pkt->l3.iph_v6->dst_addr, 16 );
			dst_sin.v6.sin6_scope_id = 0;
			dst_sa_len = sizeof(struct sockaddr_in6);
		}

		err = connect(dns_fwd_sk,(struct sockaddr*)&dst_sin,dst_sa_len);
		if( err < 0 ){
			err = -errno;
			RHP_TRC(0,RHPTRCID_DNS_PXY_RX_FORWARD_PKT_CONNECT_ERR,"xE",pkt,err);
			goto error;
		}
  }

  {
		if( addr_family == AF_INET ){
			my_sin.v4.sin_family = AF_INET;
			my_sin_len = sizeof(struct sockaddr_in);
		}else if( addr_family == AF_INET6 ){
			my_sin.v6.sin6_family = AF_INET6;
			my_sin_len = sizeof(struct sockaddr_in6);
		}

    if( getsockname(dns_fwd_sk,(struct sockaddr*)&(my_sin.raw),&my_sin_len) < 0 ){
      err = -errno;
    	RHP_TRC(0,RHPTRCID_DNS_PXY_RX_FORWARD_PKT_GETSOCKNAME_ERR,"xE",pkt,err);
      goto error;
    }

		if( addr_family == AF_INET ){
			pkt->l3.iph_v4->src_addr = my_sin.v4.sin_addr.s_addr;
			pkt->l4.udph->src_port = my_sin.v4.sin_port;
		}else if( addr_family == AF_INET6 ){
			memcpy(pkt->l3.iph_v6->src_addr,my_sin.v6.sin6_addr.s6_addr,16);
			pkt->l4.udph->src_port = my_sin.v6.sin6_port;
		}

  	err = _rhp_dns_pxy_trans_tbl_add(pkt,orig_src,orig_dst,epoll_ctx,(int)(pkt->priv),fwdto);
		if( err ){
			RHP_BUG("");
			goto error;
		}
  }

  if( pkt->type == RHP_PKT_IPV4_DNS ){
  	RHP_TRC(0,RHPTRCID_DNS_PXY_RX_FORWARD_PKT_TX,"xd4W4Wap",pkt,dns_fwd_sk,my_sin.v4.sin_addr.s_addr,my_sin.v4.sin_port,dst_sin.v4.sin_addr.s_addr,dst_sin.v4.sin_port,((pkt->l4.raw + ntohs(pkt->l4.udph->len)) - pkt->l2.raw),RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,pkt->l2.raw,tx_len,tx_buf);
  }else if( pkt->type == RHP_PKT_IPV6_DNS ){
  	RHP_TRC(0,RHPTRCID_DNS_PXY_RX_FORWARD_PKT_TX_V6,"xd6W6Wap",pkt,dns_fwd_sk,my_sin.v6.sin6_addr.s6_addr,my_sin.v6.sin6_port,dst_sin.v6.sin6_addr.s6_addr,dst_sin.v6.sin6_port,((pkt->l4.raw + ntohs(pkt->l4.udph->len)) - pkt->l2.raw),RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,pkt->l2.raw,tx_len,tx_buf);
  }

  {
		memset(&ep_evt,0,sizeof(struct epoll_event));
		ep_evt.events = EPOLLIN;
		ep_evt.data.ptr = (void*)epoll_ctx;

		if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_ADD,dns_fwd_sk,&ep_evt) < 0 ){
			err = -errno;
			RHP_BUG("%d",err);
			goto error;
		}
  }

  err = send(dns_fwd_sk,tx_buf,tx_len,0);
  if( err < 0 ){
    err = -errno;
  	RHP_TRC(0,RHPTRCID_DNS_PXY_RX_FORWARD_PKT_TX_ERR,"xE",pkt,err);
    goto error;
  }

	RHP_UNLOCK(&(_rhp_dns_pxy_lock));

	RHP_TRC(0,RHPTRCID_DNS_PXY_RX_FORWARD_PKT_RTRN,"x",pkt);
	return 0;


error:
	if( dns_fwd_sk != -1 ){
    _rhp_dns_pxy_close_sk(&dns_fwd_sk);
	}

	if( epoll_ctx ){
		_rhp_free(epoll_ctx);
	}

	rhp_esp_g_statistics_inc(dns_pxy_drop_queries);

	RHP_UNLOCK(&(_rhp_dns_pxy_lock));

	RHP_TRC(0,RHPTRCID_DNS_PXY_RX_FORWARD_PKT_ERR,"xE",pkt,err);
	return err;
}


static int _rhp_dns_pxy_protected_rx_fwd_pkt_to_inet(rhp_packet *rx_pkt)
{
	rhp_ip_addr orig_dst,orig_src;

	RHP_TRC(0,RHPTRCID_DNS_PXY_RX_FORWARD_TO_INET,"x",rx_pkt);

	memset(&orig_src,0,sizeof(rhp_ip_addr));
	memset(&orig_dst,0,sizeof(rhp_ip_addr));

	if( rx_pkt->type == RHP_PKT_IPV4_DNS ){

		rhp_ip_addr_set2(&orig_src,AF_INET,
				(u8*)&(rx_pkt->l3.iph_v4->src_addr),rx_pkt->l4.udph->src_port);

		rhp_ip_addr_set2(&orig_dst,AF_INET,
				(u8*)&(rx_pkt->l3.iph_v4->dst_addr),rx_pkt->l4.udph->dst_port);

		RHP_TRC(0,RHPTRCID_DNS_PXY_RX_FORWARD_TO_INET_ORIG,"x4W4W",rx_pkt,orig_src.addr.v4,orig_src.port,orig_dst.addr.v4,orig_dst.port);

	}else if( rx_pkt->type == RHP_PKT_IPV6_DNS ){

		rhp_ip_addr_set2(&orig_src,AF_INET6,
				rx_pkt->l3.iph_v6->src_addr,rx_pkt->l4.udph->src_port);

		rhp_ip_addr_set2(&orig_dst,AF_INET6,
				rx_pkt->l3.iph_v6->dst_addr,rx_pkt->l4.udph->dst_port);

		RHP_TRC(0,RHPTRCID_DNS_PXY_RX_FORWARD_TO_INET_ORIG_V6,"x6W6W",rx_pkt,orig_src.addr.v6,orig_src.port,orig_dst.addr.v6,orig_dst.port);

	}else{
		RHP_BUG("%d",rx_pkt->type);
		return -EINVAL;
	}


	if( !_rhp_dns_pxy_protected_rx_fwd_pkt(rx_pkt,&orig_src,&orig_dst,NULL) ){
		rhp_esp_g_statistics_inc(dns_pxy_fwd_queries_to_inet);
	}

	RHP_TRC(0,RHPTRCID_DNS_PXY_RX_FORWARD_TO_INET_RTRN,"x",rx_pkt);
	return 0;
}

static int _rhp_dns_pxy_protected_rx_fwd_pkt_to_vpn(rhp_packet *rx_pkt,rhp_vpn_realm* rlm)
{
	int err = -EINVAL;
	rhp_ip_addr* itnl_server_addr;
	rhp_ip_addr orig_dst,orig_src;
	int addr_family;

	RHP_TRC(0,RHPTRCID_DNS_PXY_RX_DISPATCH_PKT_TO_VPN,"x",rx_pkt);

	RHP_LOCK(&(rlm->lock));

	if( rlm->internal_ifc->ifc == NULL ){
		RHP_BUG("");
		goto error_l;
	}

	memset(&orig_src,0,sizeof(rhp_ip_addr));
	memset(&orig_dst,0,sizeof(rhp_ip_addr));

	if( rx_pkt->type == RHP_PKT_IPV4_DNS ){

		rhp_ip_addr_set2(&orig_src,AF_INET,
				(u8*)&(rx_pkt->l3.iph_v4->src_addr),rx_pkt->l4.udph->src_port);

		rhp_ip_addr_set2(&orig_dst,AF_INET,
				(u8*)&(rx_pkt->l3.iph_v4->dst_addr),rx_pkt->l4.udph->dst_port);

		addr_family = AF_INET;

		RHP_TRC(0,RHPTRCID_DNS_PXY_RX_DISPATCH_PKT_TO_VPN_ORIG,"x4W4W",rx_pkt,orig_src.addr.v4,orig_src.port,orig_dst.addr.v4,orig_dst.port);

	}else if( rx_pkt->type == RHP_PKT_IPV6_DNS ){

		rhp_ip_addr_set2(&orig_src,AF_INET6,
				rx_pkt->l3.iph_v6->src_addr,rx_pkt->l4.udph->src_port);

		rhp_ip_addr_set2(&orig_dst,AF_INET6,
				rx_pkt->l3.iph_v6->dst_addr,rx_pkt->l4.udph->dst_port);

		addr_family = AF_INET6;

		RHP_TRC(0,RHPTRCID_DNS_PXY_RX_DISPATCH_PKT_TO_VPN_ORIG_V6,"x6W6W",rx_pkt,orig_src.addr.v6,orig_src.port,orig_dst.addr.v6,orig_dst.port);

	}else{
		RHP_BUG("%d",rx_pkt->type);
		goto error_l;
	}

	{
		rhp_ifc_addr* itnl_ifc_addr = NULL;

		if( addr_family == AF_INET ){
			itnl_server_addr = &(rlm->split_dns.internal_server_addr);
			RHP_TRC(0,RHPTRCID_DNS_PXY_RX_DISPATCH_PKT_TO_VPN_INTERNA_NMSVR_ADDR,"x4W",rx_pkt,itnl_server_addr->addr.v4,itnl_server_addr->port);
		}else if( addr_family == AF_INET6 ){
			itnl_server_addr = &(rlm->split_dns.internal_server_addr_v6);
			RHP_TRC(0,RHPTRCID_DNS_PXY_RX_DISPATCH_PKT_TO_VPN_INTERNA_NMSVR_ADDR_V6,"x6W",rx_pkt,itnl_server_addr->addr.v6,itnl_server_addr->port);
		}

		if( rhp_ip_addr_null(itnl_server_addr) ){

			if( addr_family == AF_INET ){
				itnl_server_addr = &(rlm->split_dns.internal_server_addr_v6);
				RHP_TRC(0,RHPTRCID_DNS_PXY_RX_DISPATCH_PKT_TO_VPN_INTERNA_NMSVR_ADDR_2_V6,"x6W",rx_pkt,itnl_server_addr->addr.v6,itnl_server_addr->port);
			}else if( addr_family == AF_INET6 ){
				itnl_server_addr = &(rlm->split_dns.internal_server_addr);
				RHP_TRC(0,RHPTRCID_DNS_PXY_RX_DISPATCH_PKT_TO_VPN_INTERNA_NMSVR_ADDR_2,"x4W",rx_pkt,itnl_server_addr->addr.v4,itnl_server_addr->port);
			}
		}

		if( rhp_ip_addr_null(itnl_server_addr) ){

			if( addr_family == AF_INET ){
				rhp_esp_g_statistics_inc(dns_pxy_no_internal_nameserver_v4);
			}else if( addr_family == AF_INET6 ){
				rhp_esp_g_statistics_inc(dns_pxy_no_internal_nameserver_v6);
			}

			RHP_TRC(0,RHPTRCID_DNS_PXY_RX_DISPATCH_PKT_TO_VPN_NO_NAMESERVER_ADDR,"x",rx_pkt);
			goto error_l;
		}


		itnl_ifc_addr = rlm->internal_ifc->ifc->select_src_addr(
											rlm->internal_ifc->ifc,
											itnl_server_addr->addr_family,itnl_server_addr->addr.raw,0);
		if( itnl_ifc_addr == NULL ){

			if( addr_family == AF_INET ){
				rhp_esp_g_statistics_inc(dns_pxy_no_valid_src_addr_v4);
			}else if( addr_family == AF_INET6 ){
				rhp_esp_g_statistics_inc(dns_pxy_no_valid_src_addr_v6);
			}

			RHP_TRC(0,RHPTRCID_DNS_PXY_RX_DISPATCH_PKT_TO_VPN_LOCALIF_ADDR_INVALID_ADDR_FAMILY,"x",rx_pkt);
			goto error_l;
		}


		if( itnl_server_addr->addr_family != addr_family ){

			RHP_TRC(0,RHPTRCID_DNS_PXY_RX_DISPATCH_PKT_TO_VPN_NAMESERVER_ADDR_DIFF_ADDR_FAMILY,"xdd",rx_pkt,itnl_server_addr->addr_family,addr_family);

			err = rhp_pkt_rebuild_ip_udp_header(rx_pkt,
							itnl_ifc_addr->addr.addr_family,itnl_ifc_addr->addr.addr.raw,
							itnl_server_addr->addr.raw,0,ntohs(RHP_PROTO_DNS_PORT));
			if( err ){
				goto error_l;
			}

			if( itnl_ifc_addr->addr.addr_family == AF_INET ){
				RHP_TRC(0,RHPTRCID_DNS_PXY_RX_DISPATCH_PKT_TO_VPN_AFTR_6TO4,"x4W4W",rx_pkt,rx_pkt->l3.iph_v4->src_addr,rx_pkt->l4.udph->src_port,rx_pkt->l3.iph_v4->dst_addr,rx_pkt->l4.udph->dst_port);
			}else if( itnl_ifc_addr->addr.addr_family == AF_INET6 ){
				RHP_TRC(0,RHPTRCID_DNS_PXY_RX_DISPATCH_PKT_TO_VPN_AFTR_4TO6,"x6W6W",rx_pkt,rx_pkt->l3.iph_v6->src_addr,rx_pkt->l4.udph->src_port,rx_pkt->l3.iph_v6->dst_addr,rx_pkt->l4.udph->dst_port);
			}

		}else if( addr_family == AF_INET ){

			rx_pkt->l3.iph_v4->dst_addr = itnl_server_addr->addr.v4;
			rx_pkt->l3.iph_v4->src_addr = itnl_ifc_addr->addr.addr.v4;
			rx_pkt->l4.udph->dst_port = ntohs(RHP_PROTO_DNS_PORT);

			RHP_TRC(0,RHPTRCID_DNS_PXY_RX_DISPATCH_PKT_TO_VPN_AFTR,"x4W4W",rx_pkt,rx_pkt->l3.iph_v4->src_addr,rx_pkt->l4.udph->src_port,rx_pkt->l3.iph_v4->dst_addr,rx_pkt->l4.udph->dst_port);

		}else if( addr_family == AF_INET6 ){

			memcpy(rx_pkt->l3.iph_v6->dst_addr,itnl_server_addr->addr.v6,16);
			memcpy(rx_pkt->l3.iph_v6->src_addr,itnl_ifc_addr->addr.addr.v6,16);
			rx_pkt->l4.udph->dst_port = ntohs(RHP_PROTO_DNS_PORT);

			RHP_TRC(0,RHPTRCID_DNS_PXY_RX_DISPATCH_PKT_TO_VPN_AFTR_V6,"x6W6W",rx_pkt,rx_pkt->l3.iph_v6->src_addr,rx_pkt->l4.udph->src_port,rx_pkt->l3.iph_v6->dst_addr,rx_pkt->l4.udph->dst_port);
		}
	}


	if( !_rhp_dns_pxy_protected_rx_fwd_pkt(rx_pkt,&orig_src,&orig_dst,rlm->internal_ifc->ifc) ){
		rhp_esp_g_statistics_inc(dns_pxy_fwd_queries_to_vpn);
	}

	RHP_UNLOCK(&(rlm->lock));

	RHP_TRC(0,RHPTRCID_DNS_PXY_RX_DISPATCH_PKT_TO_VPN_RTRN,"xx",rx_pkt,rlm);
	return 0;

error_l:
	RHP_UNLOCK(&(rlm->lock));

	RHP_TRC(0,RHPTRCID_DNS_PXY_RX_DISPATCH_PKT_TO_VPN_ERR,"xE",rx_pkt,err);
	return err;
}


static int _rhp_dns_pxy_protected_rx_dispach_pkt(rhp_packet *rx_pkt,char* queried_domain)
{
	rhp_vpn_realm* rlm = NULL;

	RHP_TRC(0,RHPTRCID_DNS_PXY_RX_DISPATCH_PKT,"xs",rx_pkt,queried_domain);

	if( rx_pkt->type != RHP_PKT_IPV4_DNS && rx_pkt->type != RHP_PKT_IPV6_DNS ){
		RHP_BUG("%d",rx_pkt->type);
		return -EINVAL;
	}


	rlm = rhp_realm_search_by_split_dns(AF_UNSPEC,queried_domain);

	if( rlm == NULL ){

		_rhp_dns_pxy_protected_rx_fwd_pkt_to_inet(rx_pkt);

	}else{

		_rhp_dns_pxy_protected_rx_fwd_pkt_to_vpn(rx_pkt,rlm);
		rhp_realm_unhold(rlm);
	}

	RHP_TRC(0,RHPTRCID_DNS_PXY_RX_DISPATCH_PKT_RTRN,"xx",rx_pkt,rlm);
	return 0;
}

static void _rhp_dns_pxy_protected_rx_dispached_task(rhp_packet *rx_pkt)
{
	int err = -EINVAL;
	u8* app_data = rx_pkt->app.raw;
	int app_data_len = (rx_pkt->tail - app_data);
	char* queried_domain = NULL;

	RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_RX_DISPATCHED_TASK,"x",rx_pkt);

	err =  _rhp_dns_pxy_parse_dns_pkt(app_data,app_data_len,&queried_domain);

	if( err ){

		RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_RX_DISPATCHED_TASK_PARSE_ERR,"xE",rx_pkt,err);
		goto error;

	}else{

		_rhp_dns_pxy_protected_rx_dispach_pkt(rx_pkt,queried_domain);

		_rhp_free(queried_domain);
	}

	err = 0;

error:
	rhp_pkt_unhold(rx_pkt);

	RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_RX_DISPATCHED_TASK_PARSE_RTRN,"xE",rx_pkt,err);
	return;
}

static void _rhp_dns_pxy_inet_rx_dispached_task(rhp_packet *rx_pkt)
{
	rhp_dns_pxy_trans_tbl* ttbl = NULL;
  union {
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
    unsigned char raw;
  } dst_sin;
  socklen_t dst_sa_len = 0;
	int err;
	int tx_len = htons(rx_pkt->l4.udph->len) - sizeof(rhp_proto_udp);
	int dns_tx_sk = -1;


	RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_FWD_DISPATCHED_TASK,"x",rx_pkt);

  RHP_LOCK(&_rhp_dns_pxy_lock);


	ttbl = _rhp_dns_pxy_trans_tbl_get_by_rx_pkt(rx_pkt);
	if( ttbl == NULL ){

		RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_FWD_DISPATCHED_TASK_NO_TRANS_TBL,"x",rx_pkt);

		rhp_esp_g_statistics_inc(dns_pxy_rx_unknown_txnid_answers);

		goto no_ttbl;
	}


  {

  	//
		// Actually, src_addr and src_port is translated by iptables (netfilter)
		// after sending the packet.
		//

  	if( rx_pkt->type == RHP_PKT_IPV4_DNS && ttbl->orig_src.addr_family == AF_INET ){

			rx_pkt->l3.iph_v4->src_addr = ttbl->orig_dst.addr.v4;
			rx_pkt->l4.udph->src_port = ttbl->orig_dst.port;
			rx_pkt->l3.iph_v4->dst_addr = ttbl->orig_src.addr.v4;
			rx_pkt->l4.udph->dst_port = ttbl->orig_src.port;

		}else if( rx_pkt->type == RHP_PKT_IPV6_DNS && ttbl->orig_src.addr_family == AF_INET6 ){

			memcpy(rx_pkt->l3.iph_v6->src_addr,ttbl->orig_dst.addr.v6,16);
			rx_pkt->l4.udph->src_port = ttbl->orig_dst.port;
			memcpy(rx_pkt->l3.iph_v6->dst_addr,ttbl->orig_src.addr.v6,16);
			rx_pkt->l4.udph->dst_port = ttbl->orig_src.port;

		}else if( (rx_pkt->type == RHP_PKT_IPV6_DNS && ttbl->orig_src.addr_family == AF_INET) ||
							(rx_pkt->type == RHP_PKT_IPV4_DNS && ttbl->orig_src.addr_family == AF_INET6) ){

			err = rhp_pkt_rebuild_ip_udp_header(rx_pkt,
					ttbl->orig_dst.addr_family,ttbl->orig_dst.addr.raw,ttbl->orig_src.addr.raw,
					ttbl->orig_dst.port,ttbl->orig_src.port);
			if( err ){
				RHP_BUG("%d",err);
			}
		}
  }


	if( ttbl->orig_src.addr_family == AF_INET ){

		dns_tx_sk = (int)RHP_DNS_PXY_EPOLL_CTX_SK(&_rhp_dns_pxy_epoll_ctx_rx_v4[ttbl->orig_nsvr_idx]);

		dst_sin.v4.sin_family = AF_INET;
		dst_sin.v4.sin_port = ttbl->orig_src.port;
		dst_sin.v4.sin_addr.s_addr = ttbl->orig_src.addr.v4;
		dst_sa_len = sizeof(struct sockaddr_in);

	}else if( ttbl->orig_src.addr_family == AF_INET6 ){

		dns_tx_sk = (int)RHP_DNS_PXY_EPOLL_CTX_SK(&_rhp_dns_pxy_epoll_ctx_rx_v6[ttbl->orig_nsvr_idx]);

		dst_sin.v6.sin6_family = AF_INET6;
		dst_sin.v6.sin6_port = ttbl->orig_src.port;
		memcpy(dst_sin.v6.sin6_addr.s6_addr,ttbl->orig_src.addr.v6,16);
		dst_sa_len = sizeof(struct sockaddr_in6);
	}

	RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_FWD_DISPATCHED_TASK_TX_PROTECTED,"xda",rx_pkt,dns_tx_sk,((rx_pkt->l4.raw + ntohs(rx_pkt->l4.udph->len)) - rx_pkt->l2.raw),RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,rx_pkt->l2.raw);

	err = sendto(dns_tx_sk,rx_pkt->app.raw,tx_len,0,(struct sockaddr*)&dst_sin,dst_sa_len);
	if( err < 0 ){
		RHP_BUG("%d",-errno);
	}


	if( ttbl->fwdto == RHP_DNSPXY_FWD_TO_INET ){
		rhp_esp_g_statistics_inc(dns_pxy_rx_answers_from_inet);
	}else if( ttbl->fwdto == RHP_DNSPXY_FWD_TO_VPN ){
		rhp_esp_g_statistics_inc(dns_pxy_rx_answers_from_vpn);
	}

	_rhp_dns_pxy_trans_tbl_delete(ttbl);
	_rhp_free(ttbl);

no_ttbl:
  RHP_UNLOCK(&_rhp_dns_pxy_lock);

	rhp_pkt_unhold(rx_pkt);

	RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_FWD_DISPATCHED_TASK_RTRN,"x",rx_pkt);
	return;
}

static int _rhp_dns_pxy_rx_dispatch_packet(rhp_packet *pkt,int event_type)
{
	if( event_type == RHP_MAIN_EPOLL_DNSPXY_PROTECTED_V4 ||
			event_type == RHP_MAIN_EPOLL_DNSPXY_PROTECTED_V6 ){

		pkt->process_packet = _rhp_dns_pxy_protected_rx_dispached_task;

	}else if( event_type == RHP_MAIN_EPOLL_DNSPXY_INET_V4 ||
						event_type == RHP_MAIN_EPOLL_DNSPXY_INET_V6 ){

		pkt->process_packet = _rhp_dns_pxy_inet_rx_dispached_task;

	}else{
		RHP_BUG("%d",event_type);
		return -EINVAL;
	}

	RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_RX_DISPATCH_PACKET,"xLd",pkt,"MAIN_EOPLL_EVENT",event_type);

	return rhp_wts_sta_invoke_task(RHP_WTS_DISP_RULE_NETSOCK,RHP_WTS_STA_TASK_NAME_PKT,
			RHP_WTS_DISP_LEVEL_LOW_1,pkt,pkt);
}


static int _rhp_dns_pxy_handle_recv_pkt_v4(struct epoll_event* epoll_evt,rhp_epoll_ctx* epoll_ctx)
{
  ssize_t rx_len;
	int dns_rx_sk = -1;
	int i;

	RHP_TRC(0,RHPTRCID_DNS_PXY_HANDLE_RX,"xxLd",epoll_evt,epoll_ctx,"MAIN_EOPLL_EVENT",epoll_ctx->event_type);

  RHP_LOCK(&(_rhp_dns_pxy_lock));

	dns_rx_sk = (int)RHP_DNS_PXY_EPOLL_CTX_SK(epoll_ctx);

	RHP_TRC(0,RHPTRCID_DNS_PXY_HANDLE_RX_SK_IDX,"xxddd",epoll_evt,epoll_ctx,dns_rx_sk,_rhp_dns_pxy_rx_max_packets,_rhp_dns_pxy_rx_buf_max_size);

  for( i = 0; i < _rhp_dns_pxy_rx_max_packets; i++ ){

  	rhp_packet* pkt = NULL;
  	struct msghdr msg;
		struct iovec iov[1];
		struct sockaddr_in peer_sin;
		int buf_len = _rhp_dns_pxy_rx_buf_max_size;
		rhp_proto_ether* dmy_ethhdr;
		rhp_proto_ip_v4* dmy_iphdr;
		rhp_proto_udp* dmy_udphdr;
		int mesg_len = 0;
		int pkt_offset = 0;
		u8* data_head;

		if( !RHP_PROCESS_IS_ACTIVE() ){
			rx_len = -EINTR;
			RHP_TRC(0,RHPTRCID_DNS_PXY_HANDLE_RX_PROC_NOT_ACTIVE,"xx",epoll_evt,epoll_ctx);
			goto error;
		}

		buf_len += sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v4) + sizeof(rhp_proto_udp);
		pkt_offset += sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v4) + sizeof(rhp_proto_udp);

		pkt = rhp_pkt_alloc(buf_len);
		if( pkt == NULL ){
			rx_len = -ENOMEM;
			RHP_BUG("%d",buf_len);
			goto error;
		}

		dmy_ethhdr = (rhp_proto_ether*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ether));
		dmy_iphdr = (rhp_proto_ip_v4*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ip_v4));
		dmy_udphdr = (rhp_proto_udp*)_rhp_pkt_push(pkt,sizeof(rhp_proto_udp));

		data_head = pkt->data + pkt_offset;

		msg.msg_name = &peer_sin;
		msg.msg_namelen = sizeof(peer_sin);
		iov[0].iov_base = data_head;
		iov[0].iov_len  = (buf_len - pkt->len);
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		msg.msg_flags = 0;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;

		rx_len = recvmsg(dns_rx_sk,&msg,MSG_TRUNC | MSG_DONTWAIT);
		if( rx_len < 0 ){

			rx_len = -errno;
			RHP_TRC(0,RHPTRCID_DNS_PXY_HANDLE_RX_INVALID_RX_LEN,"xxE",epoll_evt,epoll_ctx,rx_len);

			rhp_pkt_unhold(pkt);
			goto error;
		}

		mesg_len = rx_len;

		if( msg.msg_flags & MSG_TRUNC ){

			RHP_TRC(0,RHPTRCID_DNS_PXY_HANDLE_RX_TRUNC_ERR,"xxdd",epoll_evt,epoll_ctx,rx_len,_rhp_dns_pxy_rx_buf_max_size);

			if( rx_len <= RHP_DNS_PXY_MAX_DNS_PKT_LEN ){
				_rhp_dns_pxy_rx_buf_max_size = rx_len;
      }

			rhp_pkt_unhold(pkt);
			continue;
		}

		if( rx_len <= (int)sizeof(rhp_proto_dns) ){

			RHP_TRC(0,RHPTRCID_DNS_PXY_HANDLE_RX_INVALID_DNS_PKT_LEN,"xxd",epoll_evt,epoll_ctx,rx_len);

			rhp_pkt_unhold(pkt);
			continue;
		}

		pkt->type = RHP_PKT_IPV4_DNS;

		memset(dmy_ethhdr->dst_addr,0,6);
		memset(dmy_ethhdr->src_addr,0,6);
		dmy_ethhdr->protocol = RHP_PROTO_ETH_IP;

		dmy_iphdr->ver = 4;
		dmy_iphdr->ihl = 5;
		dmy_iphdr->tos = 0;
		dmy_iphdr->total_len = htons(mesg_len + sizeof(rhp_proto_ip_v4) + sizeof(rhp_proto_udp));
		dmy_iphdr->id = 0;
		dmy_iphdr->frag = 0;
		dmy_iphdr->ttl = 64;
		dmy_iphdr->protocol = RHP_PROTO_IP_UDP;
		dmy_iphdr->check_sum = 0;

		dmy_iphdr->src_addr = peer_sin.sin_addr.s_addr;
		dmy_udphdr->src_port = peer_sin.sin_port;


		if( epoll_ctx->event_type == RHP_MAIN_EPOLL_DNSPXY_PROTECTED_V4 ){

			int svr_idx = (int)RHP_DNS_PXY_EPOLL_CTX_RX_NMSVR_IDX(epoll_ctx);

			rhp_ip_addr_dump("_rhp_dns_pxy_handle_rx.nameserver",&(_rhp_resolv_conf_name_server_ips_v4[svr_idx]));

			if( rhp_ip_addr_null(&(_rhp_resolv_conf_name_server_ips_v4[svr_idx])) ){

				RHP_TRC(0,RHPTRCID_DNS_PXY_HANDLE_RX_NAMESERVER_ADDR_NULL,"xx",epoll_evt,epoll_ctx);

				rhp_pkt_unhold(pkt);
				continue;
			}

			dmy_iphdr->dst_addr = _rhp_resolv_conf_name_server_ips_v4[svr_idx].addr.v4;
			dmy_udphdr->dst_port = _rhp_resolv_conf_name_server_ips_v4[svr_idx].port;

			pkt->priv = (void*)svr_idx;


		}else if( epoll_ctx->event_type == RHP_MAIN_EPOLL_DNSPXY_INET_V4 ){

	    union {
	      struct sockaddr_in v4;
	      unsigned char raw;
	    } my_sin;
	    socklen_t my_sin_len;

	    my_sin.v4.sin_family = AF_INET;
	    my_sin_len = sizeof(struct sockaddr_in);

	    if( getsockname(dns_rx_sk,(struct sockaddr*)&(my_sin.raw),&my_sin_len) < 0 ){

	    	RHP_BUG("%d",-errno);

	    	rhp_pkt_unhold(pkt);
				continue;
	    }

			dmy_iphdr->dst_addr = my_sin.v4.sin_addr.s_addr;
			dmy_udphdr->dst_port = my_sin.v4.sin_port;

		}else{

			RHP_BUG("%d",epoll_ctx->event_type);

			rhp_pkt_unhold(pkt);
   		continue;
		}


		dmy_udphdr->len = htons(mesg_len + sizeof(rhp_proto_udp));

		pkt->l2.raw = (u8*)dmy_ethhdr;
		pkt->l3.raw = (u8*)dmy_iphdr;
		pkt->l4.raw = (u8*)dmy_udphdr;

		pkt->app.raw = (u8*)_rhp_pkt_push(pkt,mesg_len);
		if( pkt->app.raw == NULL ){

			RHP_TRC(0,RHPTRCID_DNS_PXY_HANDLE_RX_INVALID_PKT_NO_APP_DATA,"xx",epoll_evt,epoll_ctx);

			rhp_pkt_unhold(pkt);
   		continue;
		}


		if( epoll_ctx->event_type == RHP_MAIN_EPOLL_DNSPXY_INET_V4 ){

			if( ((rhp_proto_dns*)pkt->app.raw)->txn_id != RHP_DNS_PXY_EPOLL_CTX_FWD_DNX_TXNID(epoll_ctx) ){

				RHP_TRC(0,RHPTRCID_DNS_PXY_HANDLE_RX_INVALID_PKT_INVALID_DNS_TXNID,"xxWW",epoll_evt,epoll_ctx,((rhp_proto_dns*)pkt->app.raw)->txn_id,RHP_DNS_PXY_EPOLL_CTX_FWD_DNX_TXNID(epoll_ctx));

				rhp_esp_g_statistics_inc(dns_pxy_rx_unknown_txnid_answers);

				rhp_pkt_unhold(pkt);
	   		continue;
			}
		}


		RHP_TRC(0,RHPTRCID_DNS_PXY_HANDLE_RX_RX_PKT,"xda",pkt,dns_rx_sk,((pkt->l4.raw + ntohs(pkt->l4.udph->len)) - pkt->l2.raw),RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,pkt->l2.raw);

		rx_len = _rhp_dns_pxy_rx_dispatch_packet(pkt,epoll_ctx->event_type);
		if( rx_len ){

			RHP_BUG("%d",rx_len);

			rhp_pkt_unhold(pkt);
			continue;
		}
  }

  RHP_UNLOCK(&(_rhp_dns_pxy_lock));

	RHP_TRC(0,RHPTRCID_DNS_PXY_HANDLE_RX_RTRN,"xx",epoll_evt,epoll_ctx);
	return 0;

error:
	RHP_UNLOCK(&(_rhp_dns_pxy_lock));

	RHP_TRC(0,RHPTRCID_DNS_PXY_HANDLE_RX_ERR,"xxE",epoll_evt,epoll_ctx,rx_len);
	return rx_len;
}

static int _rhp_dns_pxy_handle_recv_pkt_v6(struct epoll_event* epoll_evt,rhp_epoll_ctx* epoll_ctx)
{
  ssize_t rx_len;
	int dns_rx_sk = -1;
	int i;

	RHP_TRC(0,RHPTRCID_DNS_PXY_HANDLE_RX_V6,"xxLd",epoll_evt,epoll_ctx,"MAIN_EOPLL_EVENT",epoll_ctx->event_type);

  RHP_LOCK(&(_rhp_dns_pxy_lock));

	dns_rx_sk = (int)RHP_DNS_PXY_EPOLL_CTX_SK(epoll_ctx);

	RHP_TRC(0,RHPTRCID_DNS_PXY_HANDLE_RX_V6_SK_IDX,"xxddd",epoll_evt,epoll_ctx,dns_rx_sk,_rhp_dns_pxy_rx_max_packets,_rhp_dns_pxy_rx_buf_max_size);

  for( i = 0; i < _rhp_dns_pxy_rx_max_packets; i++ ){

  	rhp_packet* pkt = NULL;
  	struct msghdr msg;
		struct iovec iov[1];
		struct sockaddr_in6 peer_sin;
		int buf_len = _rhp_dns_pxy_rx_buf_max_size;
		rhp_proto_ether* dmy_ethhdr;
		rhp_proto_ip_v6* dmy_ip6hdr;
		rhp_proto_udp* dmy_udphdr;
		int mesg_len = 0;
		int pkt_offset = 0;
		u8* data_head;

		if( !RHP_PROCESS_IS_ACTIVE() ){
			rx_len = -EINTR;
			RHP_TRC(0,RHPTRCID_DNS_PXY_HANDLE_RX_V6_PROC_NOT_ACTIVE,"xx",epoll_evt,epoll_ctx);
			goto error;
		}

		buf_len += sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v6) + sizeof(rhp_proto_udp);
		pkt_offset += sizeof(rhp_proto_ether) + sizeof(rhp_proto_ip_v6) + sizeof(rhp_proto_udp);

		pkt = rhp_pkt_alloc(buf_len);
		if( pkt == NULL ){
			rx_len = -ENOMEM;
			RHP_BUG("%d",buf_len);
			goto error;
		}

		dmy_ethhdr = (rhp_proto_ether*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ether));
		dmy_ip6hdr = (rhp_proto_ip_v6*)_rhp_pkt_push(pkt,sizeof(rhp_proto_ip_v6));
		dmy_udphdr = (rhp_proto_udp*)_rhp_pkt_push(pkt,sizeof(rhp_proto_udp));

		data_head = pkt->data + pkt_offset;

		msg.msg_name = &peer_sin;
		msg.msg_namelen = sizeof(peer_sin);
		iov[0].iov_base = data_head;
		iov[0].iov_len  = (buf_len - pkt->len);
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		msg.msg_flags = 0;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;

		rx_len = recvmsg(dns_rx_sk,&msg,MSG_TRUNC | MSG_DONTWAIT);
		if( rx_len < 0 ){

			rx_len = -errno;
			RHP_TRC(0,RHPTRCID_DNS_PXY_HANDLE_RX_V6_INVALID_RX_LEN,"xxE",epoll_evt,epoll_ctx,rx_len);

			rhp_pkt_unhold(pkt);
			goto error;
		}

		mesg_len = rx_len;

		if( msg.msg_flags & MSG_TRUNC ){

			RHP_TRC(0,RHPTRCID_DNS_PXY_HANDLE_RX_V6_TRUNC_ERR,"xxdd",epoll_evt,epoll_ctx,rx_len,_rhp_dns_pxy_rx_buf_max_size);

			if( rx_len <= RHP_DNS_PXY_MAX_DNS_PKT_LEN ){
				_rhp_dns_pxy_rx_buf_max_size = rx_len;
      }

			rhp_pkt_unhold(pkt);
			continue;
		}

		if( rx_len <= (int)sizeof(rhp_proto_dns) ){

			RHP_TRC(0,RHPTRCID_DNS_PXY_HANDLE_RX_V6_INVALID_DNS_PKT_LEN,"xxd",epoll_evt,epoll_ctx,rx_len);

			rhp_pkt_unhold(pkt);
			continue;
		}

		pkt->type = RHP_PKT_IPV6_DNS;

		memset(dmy_ethhdr->dst_addr,0,6);
		memset(dmy_ethhdr->src_addr,0,6);
		dmy_ethhdr->protocol = RHP_PROTO_ETH_IPV6;

		dmy_ip6hdr->ver = 6;
		dmy_ip6hdr->priority = 0;
		dmy_ip6hdr->flow_label[0] = 0;
		dmy_ip6hdr->flow_label[1] = 0;
		dmy_ip6hdr->flow_label[2] = 0;
		dmy_ip6hdr->next_header = RHP_PROTO_IP_UDP;
		dmy_ip6hdr->hop_limit = 64;
		dmy_ip6hdr->payload_len = htons(mesg_len + sizeof(rhp_proto_udp));
		memcpy(dmy_ip6hdr->src_addr,peer_sin.sin6_addr.s6_addr,16);

		dmy_udphdr->src_port = peer_sin.sin6_port;


		if( epoll_ctx->event_type == RHP_MAIN_EPOLL_DNSPXY_PROTECTED_V6 ){

			int svr_idx = (int)RHP_DNS_PXY_EPOLL_CTX_RX_NMSVR_IDX(epoll_ctx);

			rhp_ip_addr_dump("_rhp_dns_pxy_handle_rx.nameserver",&(_rhp_resolv_conf_name_server_ips_v6[svr_idx]));

			if( rhp_ip_addr_null(&(_rhp_resolv_conf_name_server_ips_v6[svr_idx])) ){

				RHP_TRC(0,RHPTRCID_DNS_PXY_HANDLE_RX_V6_NAMESERVER_ADDR_NULL,"xx",epoll_evt,epoll_ctx);

				rhp_pkt_unhold(pkt);
				continue;
			}

			memcpy(dmy_ip6hdr->dst_addr,_rhp_resolv_conf_name_server_ips_v6[svr_idx].addr.v6,16);
			dmy_udphdr->dst_port = _rhp_resolv_conf_name_server_ips_v6[svr_idx].port;

			pkt->priv = (void*)svr_idx;


		}else if( epoll_ctx->event_type == RHP_MAIN_EPOLL_DNSPXY_INET_V6 ){

	    union {
	      struct sockaddr_in6 v6;
	      unsigned char raw;
	    } my_sin;
	    socklen_t my_sin_len;

	    my_sin.v6.sin6_family = AF_INET6;
	    my_sin_len = sizeof(struct sockaddr_in6);

	    if( getsockname(dns_rx_sk,(struct sockaddr*)&(my_sin.raw),&my_sin_len) < 0 ){

	    	RHP_BUG("%d",-errno);

	    	rhp_pkt_unhold(pkt);
				continue;
	    }

			memcpy(dmy_ip6hdr->dst_addr,my_sin.v6.sin6_addr.s6_addr,16);
			dmy_udphdr->dst_port = my_sin.v6.sin6_port;

		}else{

			RHP_BUG("%d",epoll_ctx->event_type);

			rhp_pkt_unhold(pkt);
   		continue;
		}


		dmy_udphdr->len = htons(mesg_len + sizeof(rhp_proto_udp));

		pkt->l2.raw = (u8*)dmy_ethhdr;
		pkt->l3.raw = (u8*)dmy_ip6hdr;
		pkt->l4.raw = (u8*)dmy_udphdr;

		pkt->app.raw = (u8*)_rhp_pkt_push(pkt,mesg_len);
		if( pkt->app.raw == NULL ){

			RHP_TRC(0,RHPTRCID_DNS_PXY_HANDLE_RX_V6_INVALID_PKT_NO_APP_DATA,"xx",epoll_evt,epoll_ctx);

			rhp_pkt_unhold(pkt);
   		continue;
		}


		if( epoll_ctx->event_type == RHP_MAIN_EPOLL_DNSPXY_INET_V6 ){

			if( ((rhp_proto_dns*)pkt->app.raw)->txn_id != RHP_DNS_PXY_EPOLL_CTX_FWD_DNX_TXNID(epoll_ctx) ){

				RHP_TRC(0,RHPTRCID_DNS_PXY_HANDLE_RX_V6_INVALID_PKT_INVALID_DNS_TXNID,"xxWW",epoll_evt,epoll_ctx,((rhp_proto_dns*)pkt->app.raw)->txn_id,RHP_DNS_PXY_EPOLL_CTX_FWD_DNX_TXNID(epoll_ctx));

				rhp_esp_g_statistics_inc(dns_pxy_rx_unknown_txnid_answers);

				rhp_pkt_unhold(pkt);
	   		continue;
			}
		}


		RHP_TRC(0,RHPTRCID_DNS_PXY_HANDLE_RX_V6_RX_PKT,"xda",pkt,dns_rx_sk,((pkt->l4.raw + ntohs(pkt->l4.udph->len)) - pkt->l2.raw),RHP_TRC_FMT_A_FROM_MAC_RAW,0,0,pkt->l2.raw);

		rx_len = _rhp_dns_pxy_rx_dispatch_packet(pkt,epoll_ctx->event_type);
		if( rx_len ){

			RHP_BUG("%d",rx_len);

			rhp_pkt_unhold(pkt);
			continue;
		}
  }

  RHP_UNLOCK(&(_rhp_dns_pxy_lock));

	RHP_TRC(0,RHPTRCID_DNS_PXY_HANDLE_RX_V6_RTRN,"xx",epoll_evt,epoll_ctx);
	return 0;

error:
	RHP_UNLOCK(&(_rhp_dns_pxy_lock));

	RHP_TRC(0,RHPTRCID_DNS_PXY_HANDLE_RX_V6_ERR,"xxE",epoll_evt,epoll_ctx,rx_len);
	return rx_len;
}

int rhp_dns_pxy_main_handle_event(struct epoll_event* epoll_evt)
{
  int err = 0;
  rhp_epoll_ctx* epoll_ctx = (rhp_epoll_ctx*)epoll_evt->data.ptr;

	RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_HANDLE_EVENT,"xxLd",epoll_evt,epoll_ctx,"MAIN_EOPLL_EVENT",epoll_ctx->event_type);

  switch( epoll_ctx->event_type ){

  case RHP_MAIN_EPOLL_DNSPXY_RSLVR:

  	err = _rhp_dns_pxy_handle_rslvr(epoll_evt,epoll_ctx);
  	break;

  case RHP_MAIN_EPOLL_DNSPXY_PROTECTED_V4:
  case RHP_MAIN_EPOLL_DNSPXY_INET_V4:

  	err = _rhp_dns_pxy_handle_recv_pkt_v4(epoll_evt,epoll_ctx);
  	break;

  case RHP_MAIN_EPOLL_DNSPXY_PROTECTED_V6:
  case RHP_MAIN_EPOLL_DNSPXY_INET_V6:

  	err = _rhp_dns_pxy_handle_recv_pkt_v6(epoll_evt,epoll_ctx);
  	break;

  default:
  	break;
  }

	RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_HANDLE_EVENT_RTRN,"xxE",epoll_evt,epoll_ctx,err);
  return err;
}


int rhp_dns_pxy_main_start(int addr_family)
{
	int dns_rx_sks[RHP_DNS_PXY_MAX_DNS_SERVERS];
  int err = 0;
  struct epoll_event ep_evt;
  union {
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
    unsigned char raw;
  } my_sin;
	struct {
		int addr_family;
		int event_type;
	  socklen_t my_sin_len;
		rhp_ip_addr* name_server_ips;
		rhp_epoll_ctx* epoll_ctx_rx;
	} params[2] = {
			{AF_INET,RHP_MAIN_EPOLL_DNSPXY_PROTECTED_V4,
			 sizeof(struct sockaddr_in),
			 _rhp_resolv_conf_name_server_ips_v4,
			 _rhp_dns_pxy_epoll_ctx_rx_v4},
			{AF_INET6,RHP_MAIN_EPOLL_DNSPXY_PROTECTED_V6,
			 sizeof(struct sockaddr_in6),
			 _rhp_resolv_conf_name_server_ips_v6,
			 _rhp_dns_pxy_epoll_ctx_rx_v6}
	};
  int idx = (addr_family == AF_INET ? 0 : 1);
  int i, activated_num = 0;

	RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_START,"Ld","AF",addr_family);

	if( rhp_gcfg_ipv6_disabled && addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_START_IPV6_DISABLED,"Ld","AF",addr_family);
		return 0;
	}

	for(i = 0; i < RHP_DNS_PXY_MAX_DNS_SERVERS; i++){
		dns_rx_sks[i] = -1;
	}

  RHP_LOCK(&(_rhp_dns_pxy_lock));

	if( addr_family == AF_INET ){

	  if( _rhp_dns_pxy_main_active_v4 ){
	  	RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_START_IS_ACTIVE_V4,"");
	  	goto end;
	  }

		my_sin.v4.sin_family = AF_INET;
		my_sin.v4.sin_port = 0;
		my_sin.v4.sin_addr.s_addr = htonl(0x7F000001);

	}else if( addr_family == AF_INET6 ){

	  if( _rhp_dns_pxy_main_active_v6 ){
	  	RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_START_IS_ACTIVE_V6,"");
	  	goto end;
	  }

		my_sin.v6.sin6_family = AF_INET6;
		my_sin.v6.sin6_port = 0;
		memcpy(my_sin.v6.sin6_addr.s6_addr,rhp_ipv6_loopback_addr->addr.v6,16);
	}

  {
    u16 dns_rx_port[RHP_DNS_PXY_MAX_DNS_SERVERS];

  	for(i = 0; i < RHP_DNS_PXY_MAX_DNS_SERVERS; i++){
  		dns_rx_port[i] = 0;
  	}


  	for( i = 0; i < RHP_DNS_PXY_MAX_DNS_SERVERS; i++ ){

			dns_rx_sks[i] = socket(addr_family,SOCK_DGRAM,0);
			if( dns_rx_sks[i] < 0 ){
				err = -errno;
				RHP_BUG("%d",err);
				goto error;
			}

			_rhp_atomic_inc(&_rhp_dns_pxy_sk_num);

			if( !rhp_gcfg_dns_pxy_fixed_internal_port ){

				if( addr_family == AF_INET ){
					my_sin.v4.sin_port = 0;
				}else if( addr_family == AF_INET6 ){
					my_sin.v6.sin6_port = 0;
				}

			}else{

				if( addr_family == AF_INET ){
					my_sin.v4.sin_port
					= htons(rhp_gcfg_dns_pxy_fixed_internal_port + i);
				}else if( addr_family == AF_INET6 ){
					my_sin.v6.sin6_port
					= htons(rhp_gcfg_dns_pxy_fixed_internal_port + i);
				}
			}


			if( bind(dns_rx_sks[i],
						(struct sockaddr*)&(my_sin.raw),params[idx].my_sin_len) < 0 ){
				err = -errno;
				RHP_BUG("%d",err);
				goto error;
			}

			if( getsockname(dns_rx_sks[i],
						(struct sockaddr*)&(my_sin.raw),&(params[idx].my_sin_len)) < 0 ){
				err = -errno;
				RHP_BUG("%d",err);
				goto error;
			}

			if( addr_family == AF_INET ){
				dns_rx_port[i] = my_sin.v4.sin_port;
			}else if( addr_family == AF_INET6 ){
				dns_rx_port[i] = my_sin.v6.sin6_port;
			}

			//
			// [CAUTION]
			//  O_NONBLOCK is NOT set because MSG_DONTWAIT is set with recvmsg().
			//

			RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_START_INTERNAL_DNS_PXY_PORT,"dW",i,dns_rx_port[i]);
		}


		for( i = 0; i < RHP_DNS_PXY_MAX_DNS_SERVERS; i++ ){

			rhp_epoll_ctx* epoll_ctx = &(params[idx].epoll_ctx_rx[i]);

			memset(epoll_ctx,0,sizeof(rhp_epoll_ctx));

			epoll_ctx->event_type = params[idx].event_type;
			RHP_DNS_PXY_EPOLL_CTX_SK(epoll_ctx) = dns_rx_sks[i];
			RHP_DNS_PXY_EPOLL_CTX_RX_PORT(epoll_ctx) = dns_rx_port[i];
			RHP_DNS_PXY_EPOLL_CTX_RX_NMSVR_IDX(epoll_ctx) = i;

			memset(&ep_evt,0,sizeof(struct epoll_event));
			ep_evt.events = EPOLLIN;
			ep_evt.data.ptr = (void*)epoll_ctx;

			if( epoll_ctl(rhp_main_net_epoll_fd,
						EPOLL_CTL_ADD,dns_rx_sks[i],&ep_evt) < 0 ){
				err = -errno;
				RHP_BUG("%d",err);
				goto error;
			}
		}


		for( i = 0; i < RHP_DNS_PXY_MAX_DNS_SERVERS; i++ ){

			rhp_ip_addr* g_name_server_addr = &(params[idx].name_server_ips[i]);
			u16 internal_port = RHP_DNS_PXY_EPOLL_CTX_RX_PORT(&(params[idx].epoll_ctx_rx[i]));

			if( !rhp_ip_addr_null(g_name_server_addr) && internal_port ){

				_rhp_dns_pxy_ipc_send_redirect_ctrl(g_name_server_addr,internal_port,1);

				if( g_name_server_addr->addr_family == AF_INET ){
					RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_START_CMP_ADDR,"d4W",i,g_name_server_addr->addr.v4,internal_port);
					RHP_LOG_D(RHP_LOG_SRC_NETMNG,0,RHP_LOG_ID_DNS_PXY_ACTIVATED,"4W",g_name_server_addr->addr.v4,internal_port);
				}else if( g_name_server_addr->addr_family == AF_INET6 ){
					RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_START_CMP_ADDR_V6,"d6W",i,g_name_server_addr->addr.v6,internal_port);
					RHP_LOG_D(RHP_LOG_SRC_NETMNG,0,RHP_LOG_ID_DNS_PXY_ACTIVATED_V6,"6W",g_name_server_addr->addr.v6,internal_port);
				}

				activated_num++;
			}
		}
  }

  {
		rhp_ip_addr* g_name_server_addr = NULL;
		u16 internal_port = 0;

		if( addr_family == AF_INET ){

			_rhp_dns_pxy_main_active_v4 = 1;

			if( activated_num ){
				rhp_esp_g_statistics_inc(dc.dns_pxy_activated_v4);
			}else{
				g_name_server_addr = &(params[idx].name_server_ips[0]);
				internal_port = RHP_DNS_PXY_EPOLL_CTX_RX_PORT(&(params[idx].epoll_ctx_rx[0]));
				RHP_LOG_DE(RHP_LOG_SRC_NETMNG,0,RHP_LOG_ID_DNS_PXY_FAILED_TO_ACTIVATE,"4W",g_name_server_addr->addr.v4,internal_port);
			}

		}else if( addr_family == AF_INET6 ){

			_rhp_dns_pxy_main_active_v6 = 1;

			if( activated_num ){
				rhp_esp_g_statistics_inc(dc.dns_pxy_activated_v6);
			}else{
				g_name_server_addr = &(params[idx].name_server_ips[0]);
				internal_port = RHP_DNS_PXY_EPOLL_CTX_RX_PORT(&(params[idx].epoll_ctx_rx[0]));
				RHP_LOG_DE(RHP_LOG_SRC_NETMNG,0,RHP_LOG_ID_DNS_PXY_FAILED_TO_ACTIVATE_V6,"6W",g_name_server_addr->addr.v6,internal_port);
			}
		}
  }

end:
	RHP_UNLOCK(&(_rhp_dns_pxy_lock));

	RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_START_RTRN,"");
	return 0;

error:
	RHP_UNLOCK(&(_rhp_dns_pxy_lock));

	for( i = 0; i < RHP_DNS_PXY_MAX_DNS_SERVERS; i++ ){
		if( dns_rx_sks[i] > -1 ){
			_rhp_dns_pxy_close_sk(&(dns_rx_sks[i]));
		}
	}

	RHP_LOG_E(RHP_LOG_SRC_NETMNG,0,RHP_LOG_ID_DNS_PXY_FAILED_TO_START,"E",err);

	RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_START_ERR,"E",err);
	return err;
}

void rhp_dns_pxy_main_end(int addr_family)
{
  struct epoll_event ep_evt;
	struct {
		int addr_family;
		rhp_ip_addr* name_server_ips;
		rhp_epoll_ctx* epoll_ctx_rx;
	} params[2] = {
			{AF_INET,
			 _rhp_resolv_conf_name_server_ips_v4,
			 _rhp_dns_pxy_epoll_ctx_rx_v4},
			{AF_INET6,
			 _rhp_resolv_conf_name_server_ips_v6,
			 _rhp_dns_pxy_epoll_ctx_rx_v6}
	};
	int idx = (addr_family == AF_INET ? 0 : 1);
  int i;

	RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_END,"Ldd","AF",addr_family,rhp_gcfg_ipv6_disabled);

	if( rhp_gcfg_ipv6_disabled && addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_END_V6_DISABLED,"Ldd","AF",addr_family,rhp_gcfg_ipv6_disabled);
		return;
	}

  RHP_LOCK(&(_rhp_dns_pxy_lock));

  if( (addr_family == AF_INET && !_rhp_dns_pxy_main_active_v4) ||
  		(addr_family == AF_INET6 && !_rhp_dns_pxy_main_active_v6) ){

  	RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_END_NOT_ACTIVE,"");
  	goto end;
  }

	for( i = 0; i < RHP_DNS_PXY_MAX_DNS_SERVERS; i++ ){

		rhp_epoll_ctx* epoll_ctx = &(params[idx].epoll_ctx_rx[i]);
		int dns_rx_sk = RHP_DNS_PXY_EPOLL_CTX_SK(epoll_ctx);

		if( dns_rx_sk != -1 ){

			memset(&ep_evt,0,sizeof(struct epoll_event));

			if( epoll_ctl(rhp_main_net_epoll_fd,EPOLL_CTL_DEL,dns_rx_sk,&ep_evt) < 0 ){
				RHP_BUG("%d",-errno);
			}

			_rhp_dns_pxy_close_sk(&dns_rx_sk);

			RHP_DNS_PXY_EPOLL_CTX_SK(epoll_ctx) = -1;
		}
	}

  {
  	rhp_dns_pxy_trans_tbl* ttbl = _rhp_dns_pxy_trans_tbl_head.lst_next;

    while( ttbl ){

    	rhp_dns_pxy_trans_tbl* ttbl_n = ttbl->lst_next;

    	_rhp_dns_pxy_trans_tbl_delete(ttbl);
      _rhp_free(ttbl);

    	ttbl = ttbl_n;
    }
  }

	for( i = 0; i < RHP_DNS_PXY_MAX_DNS_SERVERS; i++ ){

		rhp_ip_addr* g_name_server_addr = &(params[idx].name_server_ips[i]);
		u16 internal_port = RHP_DNS_PXY_EPOLL_CTX_RX_PORT(&(params[idx].epoll_ctx_rx[i]));

		if( !rhp_ip_addr_null(g_name_server_addr) && internal_port ){

			_rhp_dns_pxy_ipc_send_redirect_ctrl(g_name_server_addr,internal_port,0);

			if( g_name_server_addr->addr_family == AF_INET ){
				RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_END_CMP_ADDR,"d4W",i,g_name_server_addr->addr.v4,internal_port);
				RHP_LOG_D(RHP_LOG_SRC_NETMNG,0,RHP_LOG_ID_DNS_PXY_DEACTIVATED,"4W",g_name_server_addr->addr.v4,internal_port);
			}else if( g_name_server_addr->addr_family == AF_INET6 ){
				RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_END_CMP_ADDR_V6,"d6W",i,g_name_server_addr->addr.v6,internal_port);
				RHP_LOG_D(RHP_LOG_SRC_NETMNG,0,RHP_LOG_ID_DNS_PXY_DEACTIVATED_V6,"6W",g_name_server_addr->addr.v6,internal_port);
			}
		}
	}

	if( addr_family == AF_INET ){

		_rhp_dns_pxy_main_active_v4 = 0;

		rhp_esp_g_statistics_inc(dc.dns_pxy_deactivated_v4);

	}else if( addr_family == AF_INET6 ){

		_rhp_dns_pxy_main_active_v6 = 0;

		rhp_esp_g_statistics_inc(dc.dns_pxy_deactivated_v6);
	}

end:
  RHP_UNLOCK(&(_rhp_dns_pxy_lock));

	RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_END_RTRN,"");
	return;
}


int rhp_dns_pxy_main_init()
{
	int err = -EINVAL;
	int i;

  _rhp_mutex_init("DNS",&(_rhp_dns_pxy_lock));

  if( rhp_random_bytes((u8*)&_rhp_dns_pxy_trans_tbl_hashtbl_rnd,sizeof(_rhp_dns_pxy_trans_tbl_hashtbl_rnd)) ){
    RHP_BUG("");
    return -EINVAL;
  }

  memset(_rhp_dns_pxy_trans_tbl_hashtbl,0,sizeof(rhp_dns_pxy_trans_tbl*)*RHP_DNS_PXY_TRS_TBL_HASH_TABLE_SIZE);
  memset(&_rhp_dns_pxy_trans_tbl_head,0,sizeof(rhp_dns_pxy_trans_tbl));

  memset(_rhp_resolv_conf_name_server_ips_v4,0,sizeof(rhp_ip_addr)*RHP_DNS_PXY_MAX_DNS_SERVERS);
  memset(_rhp_resolv_conf_name_server_ips_v6,0,sizeof(rhp_ip_addr)*RHP_DNS_PXY_MAX_DNS_SERVERS);

  for( i = 0; i < RHP_DNS_PXY_MAX_DNS_SERVERS; i++ ){

  	_rhp_resolv_conf_name_server_ips_v4[i].addr_family = AF_INET;
  	_rhp_resolv_conf_name_server_ips_v4[i].port = htons(RHP_PROTO_DNS_PORT);

  	_rhp_resolv_conf_name_server_ips_v6[i].addr_family = AF_INET6;
  	_rhp_resolv_conf_name_server_ips_v6[i].port = htons(RHP_PROTO_DNS_PORT);
  }


  RHP_LOCK(&(_rhp_dns_pxy_lock));

  err = _rhp_dns_pxy_resolv_conf_init();
  if( err ){
  	RHP_BUG("%d");
    RHP_UNLOCK(&(_rhp_dns_pxy_lock));
  	goto error;
  }

  if( !_rhp_dnx_pxy_reading_resolv_conf ){

  	err = rhp_timer_oneshot(_rhp_dns_pxy_handle_rslvr_task,NULL,rhp_gcfg_dns_pxy_convergence_interval);
  	if( err ){
  		RHP_BUG("%d",err);
  	}
  }

  _rhp_dnx_pxy_reading_resolv_conf = 1;


  _rhp_atomic_init(&_rhp_dns_pxy_sk_num);

  RHP_UNLOCK(&(_rhp_dns_pxy_lock));


  if( rhp_dns_pxy_get_users() ){

  	rhp_dns_pxy_main_start(AF_INET);
  	rhp_dns_pxy_main_start(AF_INET6);
  }

	RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_INIT_OK,"");
  return 0;

error:
	RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_INIT_ERR,"E",err);
	return err;
}


int rhp_dns_pxy_main_cleanup()
{

	rhp_dns_pxy_main_end(AF_INET);
	rhp_dns_pxy_main_end(AF_INET6);

	_rhp_atomic_destroy(&_rhp_dns_pxy_sk_num);

	RHP_TRC(0,RHPTRCID_DNS_PXY_MAIN_CLEANUP,"");
	return 0;
}

