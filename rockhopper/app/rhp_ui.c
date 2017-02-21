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
#include <byteswap.h>
#include <net/if.h>
#include <arpa/inet.h>


#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_protocol.h"
#include "rhp_packet.h"
#include "rhp_netsock.h"
#include "rhp_config.h"
#include "rhp_vpn.h"
#include "rhp_ikev2_mesg.h"
#include "rhp_ikev2.h"
#include "rhp_http.h"
#include "rhp_wthreads.h"
#include "rhp_event.h"
#include "rhp_ui.h"

extern int rhp_ui_http_init();
extern int rhp_ui_http_cleanup();

int rhp_ui_init()
{
  int err = -EINVAL;
  
  err = rhp_ui_http_init();
  if( err ){
    RHP_BUG("%d",err);
    return err;
  }

  RHP_TRC(0,RHPTRCID_UI_INIT,"");
  return 0;
}

int rhp_ui_cleanup()
{
  int err = -EINVAL;

  err = rhp_ui_http_cleanup();
  if( err ){
    RHP_BUG("%d",err);
    return err;
  }

  RHP_TRC(0,RHPTRCID_UI_CLEANUP,"");
  return 0;
}

static int _rhp_admin_server_loopback_opened = 0;
static int _rhp_admin_server_ex_opened[RHP_UI_MAX_ADMIN_SERVER_ENTRY_POINTS];

static void _rhp_admin_server_entry(rhp_http_listen* listen_sk)
{
  if( rhp_cfg_admin_services_listen_sks ){
  	listen_sk->cfg_next = rhp_cfg_admin_services_listen_sks;
  }
  rhp_cfg_admin_services_listen_sks = listen_sk;
}

int rhp_admin_servers_start2()
{
	int err = -EINVAL;
	int err_cnt = 0;
  rhp_cfg_admin_service* cfg_admin_srv;
  rhp_http_listen* listen_sk = NULL;
  int loopback = 0;
  rhp_cfg_admin_service* loopbacktmp = NULL;
  int n = 1;

  RHP_TRC(0,RHPTRCID_ADMIN_SERVERS_START,"x",rhp_cfg_admin_services);

  RHP_LOCK(&rhp_cfg_lock);

  cfg_admin_srv = rhp_cfg_admin_services;
  while( cfg_admin_srv ){

  	int nobody_allowed = 0;

  	if( n >= RHP_UI_MAX_ADMIN_SERVER_ENTRY_POINTS ){
  		break;
  	}

  	if( _rhp_admin_server_ex_opened[n-1] ){
    	n++;
  		goto next;
  	}

  	if( cfg_admin_srv->addr.addr_family == AF_INET  ){

  		if( cfg_admin_srv->addr.addr.v4 == htonl(0x7f000001) ){
  			loopback = 1;
  		}else{
  			loopbacktmp = cfg_admin_srv;
  		}

  		if( loopback && _rhp_admin_server_loopback_opened ){

				RHP_TRC(0,RHPTRCID_ADMIN_SERVERS_HTTP_SERVER_OPEN_LO_OPEN,"xd",cfg_admin_srv,nobody_allowed);

  		}else{

  			if( (err = rhp_http_server_open(cfg_admin_srv->id,&(cfg_admin_srv->addr),
										cfg_admin_srv->client_acls,cfg_admin_srv->max_conns,
										cfg_admin_srv->root_dir,cfg_admin_srv->keep_alive_interval,&listen_sk)) ){

					RHP_TRC(0,RHPTRCID_ADMIN_SERVERS_HTTP_SERVER_OPEN_ERR,"xdE",cfg_admin_srv,nobody_allowed,err);
					err_cnt++;
					_rhp_admin_server_ex_opened[n-1] = 0;

				}else{

					RHP_TRC(0,RHPTRCID_ADMIN_SERVERS_HTTP_SERVER_OPEN_OK,"xxd",cfg_admin_srv,listen_sk,nobody_allowed);

					_rhp_admin_server_entry(listen_sk);
					_rhp_admin_server_ex_opened[n-1] = 1;
				}
  		}
  	}
  	n++;


  	if( _rhp_admin_server_ex_opened[n-1] ){
    	n++;
  		goto next;
  	}

  	if( !rhp_gcfg_ipv6_disabled &&
  			cfg_admin_srv->addr_v6.addr_family == AF_INET6 &&
  			!rhp_ip_addr_null(&(cfg_admin_srv->addr_v6)) ){

			if( (err = rhp_http_server_open(cfg_admin_srv->id,&(cfg_admin_srv->addr_v6),
									cfg_admin_srv->client_acls,cfg_admin_srv->max_conns,
									cfg_admin_srv->root_dir,cfg_admin_srv->keep_alive_interval,&listen_sk)) ){

				RHP_TRC(0,RHPTRCID_ADMIN_SERVERS_HTTP_SERVER_OPEN_V6_ERR,"xdE",cfg_admin_srv,nobody_allowed,err);
				err_cnt++;
		  	_rhp_admin_server_ex_opened[n-1] = 0;

			}else{

				RHP_TRC(0,RHPTRCID_ADMIN_SERVERS_HTTP_SERVER_OPEN_V6_OK,"xxd",cfg_admin_srv,listen_sk,nobody_allowed);

				_rhp_admin_server_entry(listen_sk);
		  	_rhp_admin_server_ex_opened[n-1] = 1;
			}
  	}
		n++;

next:
    cfg_admin_srv = cfg_admin_srv->next;
  }

  if( !_rhp_admin_server_loopback_opened && !loopback && loopbacktmp ){

  	rhp_ip_addr lpb_addr;
  	memset(&lpb_addr,0,sizeof(rhp_ip_addr));
  	lpb_addr.addr_family = AF_INET;
  	lpb_addr.addr.v4 = htonl(0x7f000001);
  	lpb_addr.port = loopbacktmp->addr.port;

    if( rhp_http_server_open(0xFFFFFFFF,&lpb_addr,NULL,loopbacktmp->max_conns,
    			loopbacktmp->root_dir,loopbacktmp->keep_alive_interval,&listen_sk) ){

    	err_cnt++;

    }else{

      _rhp_admin_server_entry(listen_sk);

      _rhp_admin_server_loopback_opened = 1;
    }
  }

  RHP_UNLOCK(&rhp_cfg_lock);

  if( err_cnt ){
  	err = -EBUSY;
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_ADMIN_SERVERS_START_RTRN,"x",rhp_cfg_admin_services);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_ADMIN_SERVERS_START_ERR,"xE",rhp_cfg_admin_services,err);
	return err;
}

int rhp_admin_servers_start()
{
	memset(_rhp_admin_server_ex_opened,0,sizeof(int)*RHP_UI_MAX_ADMIN_SERVER_ENTRY_POINTS);
	return rhp_admin_servers_start2();
}


static void rhp_admin_servers_start_retry_hander(void* ctx)
{
	int err;

	if( (err = rhp_admin_servers_start2()) ){

		RHP_TRC_FREQ(0,RHPTRCID_ADMIN_SERVERS_START_RETRY_HANDLER_ERR,"xE",ctx,err);
		RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_HTTP_SERVER_START_RETRY_ERR,"E",err);
	}

	return;
}

int rhp_admin_servers_retry_start()
{
	return rhp_timer_oneshot(rhp_admin_servers_start_retry_hander,NULL,
			rhp_gcfg_net_event_init_convergence_interval);
}


int rhp_admin_servers_stop()
{
  rhp_http_listen *listen_sk = NULL,*listen_sk2 = NULL;

  RHP_TRC(0,RHPTRCID_ADMIN_SERVERS_STOP,"x",rhp_cfg_admin_services_listen_sks);

  RHP_LOCK(&rhp_cfg_lock);

  listen_sk = rhp_cfg_admin_services_listen_sks;
  while( listen_sk ){

    listen_sk2 = listen_sk->cfg_next;

    rhp_http_server_close(listen_sk);
    rhp_http_svr_unhold(listen_sk);

    listen_sk = listen_sk2;
  }

  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_ADMIN_SERVERS_STOP_RTRN,"x",rhp_cfg_admin_services_listen_sks);
  return 0;
}

