/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <asm/types.h>
#include <linux/types.h>
#include <asm/byteorder.h>
#include <unistd.h>
#include <sys/capability.h>
#include <sys/socket.h>
#include <time.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_config.h"

int rhp_nl_sk = -1;
static u32 _rhp_nl_seqno = 1;
static rhp_mutex_t rhp_nm_lock;;

char* rhp_netmng_cmd_path = NULL;
char* rhp_netmng_cmd_dir = NULL;

struct _rhp_nm_req_cb {

  u8 tag[4]; // '#NCB'

  struct _rhp_nm_req_cb* next;

  void* ctx;
  int (*callback)(struct nlmsghdr *nlh,void* ifent_v4,void* ifent_v6,void* ctx);

  u32 nl_seqno;

  int cmp_if_name;

  rhp_if_entry ifent_v4;
  rhp_if_entry ifent_v6;
};
typedef struct _rhp_nm_req_cb rhp_nm_req_cb;

static rhp_nm_req_cb* _rhp_nm_req_cb_head = NULL;


struct _rhp_nm_req_cb_vif {

	unsigned long vpn_realm_id;

  int vif_type;

  int exec_up;

  int v6_disable;  // 1: disable
  int v6_autoconf; // See RHP_IPC_VIF_V6_AUTOCONF_XXXX
};
typedef struct _rhp_nm_req_cb_vif rhp_nm_req_cb_vif;


int rhp_netmng_init(int ipv6_disabled)
{
  int err = 0;
  struct sockaddr_nl sanl;

  _rhp_mutex_init("NMM",&rhp_nm_lock);

  if( (rhp_nl_sk = socket(PF_NETLINK,SOCK_DGRAM,NETLINK_ROUTE)) < 0){
    err = -errno;
    RHP_BUG("%d",err);
    goto error;
  }

  memset(&sanl,0,sizeof(sanl));
  sanl.nl_family = PF_NETLINK;
  sanl.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;
  if( !ipv6_disabled ){
    sanl.nl_groups |= RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE;
  }

  if( bind(rhp_nl_sk,(struct sockaddr*)&sanl,sizeof(sanl)) ){
    close(rhp_nl_sk);
    rhp_nl_sk = -1;
    err = -errno;
    RHP_BUG("%d",err);
    goto error;
  }

  //
  // TODO : We should expand rx_buf size and tx_buf size for system with small memory???
  //

  //
  // TODO : We should retry to send NETLINK requests for system with small memory???
  //

  RHP_TRC(0,RHPTRCID_NETMNG_INIT,"d",rhp_nl_sk);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_NETMNG_INIT_ERR,"E",err);
	return err;
}

void rhp_netmng_cleanup()
{
  if( rhp_nl_sk > 0 ){

  	RHP_TRC(0,RHPTRCID_NETMNG_CLEANUP,"x",rhp_nl_sk);

  	close(rhp_nl_sk);
  	rhp_nl_sk = -1;

  }else{
  	RHP_BUG("");
  }

  _rhp_mutex_destroy(&rhp_nm_lock);

  return;
}

static rhp_nm_req_cb* _rhp_netmng_alloc_callback(
		int (callback)(struct nlmsghdr *nlh,void* ifent_v4,void* ifent_v6,void* ctx),void* ctx)
{
  rhp_nm_req_cb* nm_cb;

  nm_cb = (rhp_nm_req_cb*)_rhp_malloc(sizeof(rhp_nm_req_cb));
  if( nm_cb == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(nm_cb,0,sizeof(rhp_nm_req_cb));

  nm_cb->tag[0] = '#';
  nm_cb->tag[0] = 'N';
  nm_cb->tag[0] = 'C';
  nm_cb->tag[0] = 'B';

  nm_cb->ctx = ctx;
  nm_cb->callback = callback;

	RHP_TRC(0,RHPTRCID_NETMNG_ALLOC_CALLBACK,"xYx",nm_cb,callback,ctx);
	return nm_cb;
}

static void _rhp_netmng_free_callback(rhp_nm_req_cb* nm_cb)
{
	RHP_TRC(0,RHPTRCID_NETMNG_FREE_CALLBACK,"xYx",nm_cb,nm_cb->callback,nm_cb->ctx);
	_rhp_free(nm_cb);
  return;
}

static rhp_nm_req_cb* _rhp_netmng_get_callback(u32 nl_seqno)
{
  rhp_nm_req_cb* nm_cb = _rhp_nm_req_cb_head;

  while( nm_cb ){

  	if( nm_cb->nl_seqno == nl_seqno ){
      break;
  	}

  	nm_cb = nm_cb->next;
  }

  if( nm_cb ){
  	RHP_TRC(0,RHPTRCID_NETMNG_GET_CALLBACK,"uxYx",nl_seqno,nm_cb,nm_cb->callback,nm_cb->ctx);
  	rhp_if_entry_dump("_rhp_netmng_get_callback:nm_cb->ifent_v4",&(nm_cb->ifent_v4));
  	rhp_if_entry_dump("_rhp_netmng_get_callback:nm_cb->ifent_v6",&(nm_cb->ifent_v6));
  }else{
  	RHP_TRC(0,RHPTRCID_NETMNG_GET_CALLBACK_NOT_FOUND,"u",nl_seqno);
  }
  return nm_cb;
}

static rhp_nm_req_cb* _rhp_netmng_get_callback_by_ifname(char* if_name)
{
  rhp_nm_req_cb* nm_cb = _rhp_nm_req_cb_head;

  while( nm_cb ){

  	if( nm_cb->cmp_if_name && !strcmp(nm_cb->ifent_v4.if_name,if_name) ){
      break;
  	}

  	nm_cb = nm_cb->next;
  }

  if( nm_cb ){
  	RHP_TRC(0,RHPTRCID_NETMNG_GET_CALLBACK_BY_IFNAME,"sxYx",if_name,nm_cb,nm_cb->callback,nm_cb->ctx);
  	rhp_if_entry_dump("_rhp_netmng_get_callback_by_ifname:nm_cb->ifent_v4",&(nm_cb->ifent_v4));
  	rhp_if_entry_dump("_rhp_netmng_get_callback_by_ifname:nm_cb->ifent_v6",&(nm_cb->ifent_v6));
  }else{
  	RHP_TRC(0,RHPTRCID_NETMNG_GET_CALLBACK_BY_IFNAME_NOT_FOUND,"s",if_name);
  }

  return nm_cb;
}

static void _rhp_netmng_put_callback(u32 nl_seqno,rhp_nm_req_cb* nm_cb)
{
  nm_cb->nl_seqno = nl_seqno;

	RHP_TRC(0,RHPTRCID_NETMNG_PUT_CALLBACK,"uxYx",nl_seqno,nm_cb,nm_cb->callback,nm_cb->ctx);

  if( _rhp_nm_req_cb_head ){
    nm_cb->next = _rhp_nm_req_cb_head;
  }
  _rhp_nm_req_cb_head = nm_cb;

  return;
}

static void _rhp_netmng_delete_callback(rhp_nm_req_cb* nm_cb_d)
{
  rhp_nm_req_cb *nm_cb = _rhp_nm_req_cb_head,*nm_cb_p = NULL;

  while( nm_cb ){
	 if( nm_cb->nl_seqno == nm_cb_d->nl_seqno ){
      break;
	 }
	 nm_cb_p = nm_cb;
    nm_cb = nm_cb->next;
  }

  if( nm_cb == NULL ){
  	RHP_TRC(0,RHPTRCID_NETMNG_DELETE_CALLBACK_NOT_FOUND,"xu",nm_cb_d,nm_cb_d->nl_seqno);
  	return;
  }

  if( nm_cb_p ){
    nm_cb_p->next = nm_cb->next;
  }else{
    _rhp_nm_req_cb_head = nm_cb->next;
  }

	RHP_TRC(0,RHPTRCID_NETMNG_DELETE_CALLBACK,"xu",nm_cb_d,nm_cb_d->nl_seqno);
	return;
}

int rhp_netmng_send_dumplink(
		int (*callback)(struct nlmsghdr *nlh,void* priv1,void* priv2,void* ctx),void* ctx)
{
  int err;
  struct ifinfomsg ifm = {
    .ifi_family = AF_UNSPEC,
  };
  struct nlmsghdr *nlh;
  int len = NLMSG_ALIGN(sizeof(struct nlmsghdr)) + NLMSG_ALIGN(sizeof(struct ifinfomsg));
  char buf[NLMSG_ALIGN(sizeof(struct nlmsghdr)) + NLMSG_ALIGN(sizeof(struct ifinfomsg))];
  rhp_nm_req_cb* nm_cb = NULL;

  RHP_TRC(0,RHPTRCID_NETMNG_SEND_DUMPLINK,"Yx",callback,ctx);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return -EPERM;
  }

  if( callback ){

  	nm_cb = _rhp_netmng_alloc_callback(callback,ctx);
  	if( nm_cb == NULL ){
    	RHP_BUG("");
    	return -ENOMEM;
    }
  }

  nlh = (struct nlmsghdr*)buf;

  nlh->nlmsg_pid = getpid();
  nlh->nlmsg_seq = _rhp_nl_seqno++;
  nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
  nlh->nlmsg_type = RTM_GETLINK;
  nlh->nlmsg_len = len;
  memcpy((nlh+1),&ifm,sizeof(ifm));

  if( (err = rhp_send(rhp_nl_sk,buf,len,0)) < 0 ){

    RHP_TRC(0,RHPTRCID_NETMNG_SEND_DUMPLINK_SEND_ERR,"E",err);

    if( nm_cb ){
    	_rhp_netmng_free_callback(nm_cb);
    }
    return err;
  }

  if( callback ){
    _rhp_netmng_put_callback(nlh->nlmsg_seq,nm_cb);
  }

  RHP_TRC(0,RHPTRCID_NETMNG_SEND_DUMPLINK_RTRN,"");
  return 0;
}

int rhp_netmng_send_dumpaddr(int (*callback)(struct nlmsghdr *nlh,void* priv1,void* priv2,void* ctx),void* ctx,
		int addr_family)
{
  int err;
  struct ifinfomsg ifm = {
    .ifi_family = addr_family,
  };
  struct nlmsghdr *nlh;
  int len = NLMSG_ALIGN(sizeof(struct nlmsghdr)) + NLMSG_ALIGN(sizeof(struct ifinfomsg));
  char buf[NLMSG_ALIGN(sizeof(struct nlmsghdr)) + NLMSG_ALIGN(sizeof(struct ifinfomsg))];
  rhp_nm_req_cb* nm_cb = NULL;

  RHP_TRC(0,RHPTRCID_NETMNG_SEND_DUMPADDR,"YxLd",callback,ctx,"AF",addr_family);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return -EPERM;
  }

  if( callback ){

  	nm_cb = _rhp_netmng_alloc_callback(callback,ctx);
  	if( nm_cb == NULL ){
    	RHP_BUG("");
    	return -ENOMEM;
    }
  }

  nlh = (struct nlmsghdr*)buf;

  nlh->nlmsg_pid = getpid();
  nlh->nlmsg_seq = _rhp_nl_seqno++;
  nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
  nlh->nlmsg_type = RTM_GETADDR;
  nlh->nlmsg_len = len;
  memcpy((nlh+1),&ifm,sizeof(ifm));

  if( (err = rhp_send(rhp_nl_sk,buf,len,0)) < 0 ){

  	RHP_TRC(0,RHPTRCID_NETMNG_SEND_DUMPADDR_SEND_ERR,"E",err);

  	if( nm_cb ){
    	_rhp_netmng_free_callback(nm_cb);
    }
  	return err;
  }

  if( callback ){
    _rhp_netmng_put_callback(nlh->nlmsg_seq,nm_cb);
  }

  RHP_TRC(0,RHPTRCID_NETMNG_SEND_DUMPADDR_RTRN,"");
  return 0;
}

int rhp_netmng_send_dumproute(int (*callback)(struct nlmsghdr *nlh,void* priv1,void* priv2,void* ctx),void* ctx,
		int addr_family)
{
  int err;
  struct rtmsg* rtmsg_req;
  struct nlmsghdr *nlh;
  int len = NLMSG_ALIGN(sizeof(struct nlmsghdr)) + NLMSG_ALIGN(sizeof(struct rtmsg));
  char buf[NLMSG_ALIGN(sizeof(struct nlmsghdr)) + NLMSG_ALIGN(sizeof(struct rtmsg))];
  rhp_nm_req_cb* nm_cb = NULL;

  RHP_TRC(0,RHPTRCID_NETMNG_SEND_DUMPROUTE,"YxLd",callback,ctx,"AF",addr_family);

  memset(buf,0,len);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return -EPERM;
  }

  if( callback ){

  	nm_cb = _rhp_netmng_alloc_callback(callback,ctx);
  	if( nm_cb == NULL ){
    	RHP_BUG("");
    	return -ENOMEM;
    }
  }

  nlh = (struct nlmsghdr*)buf;
  rtmsg_req = (struct rtmsg*)NLMSG_DATA(nlh);

  nlh->nlmsg_pid = getpid();
  nlh->nlmsg_seq = _rhp_nl_seqno++;
  nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
  nlh->nlmsg_type = RTM_GETROUTE;
  nlh->nlmsg_len = len;

  rtmsg_req->rtm_family = addr_family;
  rtmsg_req->rtm_flags |= RTM_F_NOTIFY;

  if( (err = rhp_send(rhp_nl_sk,buf,len,0)) < 0 ){

    RHP_TRC(0,RHPTRCID_NETMNG_SEND_DUMPROUTE_SEND_ERR,"E",err);

    if( nm_cb ){
    	_rhp_netmng_free_callback(nm_cb);
    }
    return err;
  }

  if( callback ){
    _rhp_netmng_put_callback(nlh->nlmsg_seq,nm_cb);
  }

  RHP_TRC(0,RHPTRCID_NETMNG_SEND_DUMPROUTE_RTRN,"");
  return 0;
}


static ssize_t _rhp_netmng_recv(void *buf,size_t len,int flags)
{
  struct msghdr msg;
  struct iovec iov;
  int err = 0;
  int rx_len;

  RHP_TRC(0,RHPTRCID_NETMNG_RECV,"xdx",buf,len,flags);

  if( rhp_nl_sk == -1 ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  memset(&msg,0,sizeof(msg));
  iov.iov_base = buf;
  iov.iov_len = len;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  if( (err = rhp_recvmsg(rhp_nl_sk,&msg,flags,0)) < 0 ){
    RHP_TRC(0,RHPTRCID_NETMNG_RECV_ERR,"xE",buf,err);
    goto error;
  }

  rx_len = err;
  RHP_TRC(0,RHPTRCID_NETMNG_RECV_BUF,"p",rx_len,buf);

  if( msg.msg_flags & MSG_TRUNC ){
    err = -EMSGSIZE;
    RHP_TRC(0,RHPTRCID_NETMNG_RECV_TRUNC,"xE",buf,err);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_NETMNG_RECV_RTRN,"x",buf);
  return rx_len;

error:
  RHP_TRC(0,RHPTRCID_NETMNG_RECV_ERR,"xE",buf,err);
  return err;
}

int rhp_netmng_recvmsg(void *buf,int len,int flags,
                       void (*callback)(struct nlmsghdr *nlh,void *ctx),void *ctx)
{
  int err = 0;
  rhp_nm_req_cb* nm_cb = NULL;

  RHP_TRC(0,RHPTRCID_NETMNG_RECVMSG,"xdxYx",buf,len,flags,callback,ctx);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return -EPERM;
  }

  while( (err = _rhp_netmng_recv(buf,len,flags)) > 0 ){

  	struct nlmsghdr *rnlh = (struct nlmsghdr*)buf;

  	for( ; NLMSG_OK(rnlh,err) ; rnlh = NLMSG_NEXT(rnlh,err) ){

  		int cb_err;

  		nm_cb = _rhp_netmng_get_callback(rnlh->nlmsg_seq);
  		if( nm_cb ){

  			cb_err = nm_cb->callback(rnlh,&(nm_cb->ifent_v4),&(nm_cb->ifent_v6),nm_cb->ctx);

  		  RHP_TRC(0,RHPTRCID_NETMNG_RECVMSG_CALL_CB_1,"xYxE",nm_cb,nm_cb->callback,nm_cb->ctx,cb_err);

  			if( cb_err == RHP_STATUS_NETMNG_DONE ){

  				_rhp_netmng_delete_callback(nm_cb);
        	_rhp_netmng_free_callback(nm_cb);

  			}else if( (cb_err == RHP_STATUS_NETMNG_NOT_INTERESTED) && callback ){
  				goto exec_callback;
  			}

  		}else if( rnlh->nlmsg_type == RTM_NEWLINK ){

  			rhp_if_entry ifent;
  			memset(&ifent,0,sizeof(rhp_if_entry));

  			if( rhp_netmng_parse_ifinfomsg(rnlh,&ifent) ){
  				RHP_BUG("%d",rnlh->nlmsg_type);
  				goto next;
  			}

  			nm_cb = _rhp_netmng_get_callback_by_ifname(ifent.if_name);
  			if( nm_cb ){

  				cb_err = nm_cb->callback(rnlh,&(nm_cb->ifent_v4),&(nm_cb->ifent_v6),nm_cb->ctx);

    		  RHP_TRC(0,RHPTRCID_NETMNG_RECVMSG_CALL_CB_2,"xYxE",nm_cb,nm_cb->callback,nm_cb->ctx,cb_err);

  				if( cb_err == RHP_STATUS_NETMNG_DONE ){

  					_rhp_netmng_delete_callback(nm_cb);
  					_rhp_netmng_free_callback(nm_cb);

  				}else if( (cb_err == RHP_STATUS_NETMNG_NOT_INTERESTED) && callback ){

  					goto exec_callback;
  				}

  			}else if( callback ){

  				goto exec_callback;
  			}

  		}else if( callback ){

exec_callback:

				callback(rnlh,ctx);
  		}

next:
			if( !(rnlh->nlmsg_flags & NLM_F_MULTI) || rnlh->nlmsg_type == NLMSG_DONE ){
				break;
      }
  	}
  }

  RHP_TRC(0,RHPTRCID_NETMNG_RECVMSG_RTRN,"xE",buf,err);

  return ((err < 0) ? err : 0);
}

int rhp_netmng_parse_routemsg(struct nlmsghdr *nlh,rhp_rt_map_entry* rtmap_ent)
{
  struct rtmsg *rtmap_mesg;
  struct rtattr *rta;
  int rta_len;
  int idx = 0;

	RHP_TRC(0,RHPTRCID_NETMNG_PARSE_ROUTEMSG,"xx",nlh,rtmap_ent);

  rtmap_mesg = (struct rtmsg *)NLMSG_DATA(nlh);

	RHP_TRC(0,RHPTRCID_NETMNG_PARSE_ROUTEMSG_HDR,"xbbbbbLbbLbx",nlh,rtmap_mesg->rtm_family,rtmap_mesg->rtm_dst_len,rtmap_mesg->rtm_src_len,rtmap_mesg->rtm_tos,rtmap_mesg->rtm_table,"RTPROT",rtmap_mesg->rtm_protocol,rtmap_mesg->rtm_scope,"RT_RTN",rtmap_mesg->rtm_type,rtmap_mesg->rtm_flags);


  if ( ((rtmap_mesg->rtm_family != AF_INET) && (rtmap_mesg->rtm_family != AF_INET6)) ||
  		 (rtmap_mesg->rtm_table != RT_TABLE_MAIN)){
  	RHP_TRC(0,RHPTRCID_NETMNG_PARSE_ROUTEMSG_NOT_INTERESTED,"xxbb",nlh,rtmap_ent,rtmap_mesg->rtm_family,rtmap_mesg->rtm_table);
  	return RHP_STATUS_NETMNG_NOT_INTERESTED;
  }

  if( rtmap_mesg->rtm_type != RTN_UNICAST 	&&
  		rtmap_mesg->rtm_type != RTN_LOCAL 		&&
  		rtmap_mesg->rtm_type != RTN_BROADCAST &&
  		rtmap_mesg->rtm_type != RTN_ANYCAST 	&&
  		rtmap_mesg->rtm_type != RTN_MULTICAST ){

  	RHP_TRC(0,RHPTRCID_NETMNG_PARSE_ROUTEMSG_NOT_INTERESTED_RTM_TYPE,"xxb",nlh,rtmap_ent,rtmap_mesg->rtm_type);
  	return RHP_STATUS_NETMNG_NOT_INTERESTED;
  }

  if( rtmap_mesg->rtm_protocol == RTPROT_UNSPEC ||
  		rtmap_mesg->rtm_protocol == RTPROT_REDIRECT ){

  	RHP_TRC(0,RHPTRCID_NETMNG_PARSE_ROUTEMSG_NOT_INTERESTED_RTM_PROTO,"xxb",nlh,rtmap_ent,rtmap_mesg->rtm_protocol);
  	return RHP_STATUS_NETMNG_NOT_INTERESTED;
  }

  rtmap_ent->addr_family = rtmap_mesg->rtm_family;
  rtmap_ent->rtm_type = rtmap_mesg->rtm_type;

  rta = (struct rtattr *)RTM_RTA(rtmap_mesg);
  rta_len = RTM_PAYLOAD(nlh);

  for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {

  	RHP_TRC(0,RHPTRCID_NETMNG_PARSE_ROUTEMSG_ATTR,"xLwp",nlh,"RTA_ATTR_TYPE",rta->rta_type,(int)rta->rta_len,(u8*)rta);

  	switch (rta->rta_type){

  	case RTA_DST:

    	rtmap_ent->dest_network.addr_family = rtmap_mesg->rtm_family;

    	if( rtmap_mesg->rtm_family == AF_INET ){

    		memcpy(rtmap_ent->dest_network.addr.raw,(u8*)RTA_DATA(rta),4);

    		rtmap_ent->dest_network.prefixlen = rtmap_mesg->rtm_dst_len;
    		rtmap_ent->dest_network.netmask.v4 = rhp_ipv4_prefixlen_to_netmask(rtmap_mesg->rtm_dst_len);

    	}else if( rtmap_mesg->rtm_family == AF_INET6 ){

    		memcpy(rtmap_ent->dest_network.addr.v6,(u8*)RTA_DATA(rta),16);

    		rtmap_ent->dest_network.prefixlen = rtmap_mesg->rtm_dst_len;
    		rhp_ipv6_prefixlen_to_netmask(rtmap_mesg->rtm_dst_len,rtmap_ent->dest_network.netmask.v6);
    	}

    	idx++;
      break;

  	case RTA_GATEWAY:

  		rtmap_ent->gateway_addr.addr_family = rtmap_mesg->rtm_family;

    	if( rtmap_mesg->rtm_family == AF_INET ){

    		memcpy(rtmap_ent->gateway_addr.addr.raw,(u8*)RTA_DATA(rta),4);

    	}else if( rtmap_mesg->rtm_family == AF_INET6 ){

    		memcpy(rtmap_ent->gateway_addr.addr.v6,(u8*)RTA_DATA(rta),16);
    	}

  		idx++;
      break;

  	case RTA_OIF:

  		rtmap_ent->oif_index = *(int*)RTA_DATA(rta);
      if_indextoname(rtmap_ent->oif_index,rtmap_ent->oif_name);

      idx++;
      break;

  	case RTA_METRICS:

  		rtmap_ent->metric = *(int*)RTA_DATA(rta);
      break;

  	default:
  		break;
    }
  }

  if( rtmap_mesg->rtm_protocol == RTPROT_STATIC ||
  		rtmap_mesg->rtm_protocol == RTPROT_KERNEL ||
  		rtmap_mesg->rtm_protocol == RTPROT_BOOT){

  	if( (rtmap_mesg->rtm_family == AF_INET &&
  			 rtmap_ent->dest_network.addr.v4 == 0 &&
  			 rtmap_ent->dest_network.prefixlen == 0) ||
  			(rtmap_mesg->rtm_family == AF_INET6 &&
  			 rhp_ip_addr_null(&rtmap_ent->dest_network) &&
  			 rtmap_ent->dest_network.prefixlen == 0) ){

  	  if( strstr(rtmap_ent->oif_name,RHP_VIRTUAL_IF_NAME) ){
  			rtmap_ent->type = RHP_RTMAP_TYPE_DEFAULT_INTERNAL;
  	  }else{
  	  	rtmap_ent->type = RHP_RTMAP_TYPE_DEFAULT;
  	  }

  	}else{

  	  if( strstr(rtmap_ent->oif_name,RHP_VIRTUAL_IF_NAME) ){
  	  	rtmap_ent->type = RHP_RTMAP_TYPE_STATIC_INTERNAL;
  	  }else{
  	  	rtmap_ent->type = RHP_RTMAP_TYPE_STATIC;
  	  }
  	}

  }else if( rtmap_mesg->rtm_protocol > RTPROT_STATIC ){

  	if( (rtmap_mesg->rtm_family == AF_INET &&
  			 rtmap_ent->dest_network.addr.v4 == 0 &&
  			 rtmap_ent->dest_network.prefixlen == 0) ||
  			(rtmap_mesg->rtm_family == AF_INET6 &&
  			 rhp_ip_addr_null(&rtmap_ent->dest_network) &&
  			 rtmap_ent->dest_network.prefixlen == 0) ){

  	  if( strstr(rtmap_ent->oif_name,RHP_VIRTUAL_IF_NAME) ){
  	  	rtmap_ent->type = RHP_RTMAP_TYPE_DYNAMIC_DEFAULT_INTERNAL;
  	  }else{
  	  	rtmap_ent->type = RHP_RTMAP_TYPE_DYNAMIC_DEFAULT;
  	  }

  	}else{

  	  if( strstr(rtmap_ent->oif_name,RHP_VIRTUAL_IF_NAME) ){
  	  	rtmap_ent->type = RHP_RTMAP_TYPE_DYNAMIC_INTERNAL;
  	  }else{
  	  	rtmap_ent->type = RHP_RTMAP_TYPE_DYNAMIC;
  	  }
  	}

  }else{

		rtmap_ent->type = RHP_RTMAP_TYPE_UNKNOWN;
  }

  rhp_rtmap_entry_dump("rhp_netmng_parse_routemsg",rtmap_ent);

  if( idx == 0 ){
  	RHP_TRC(0,RHPTRCID_NETMNG_PARSE_ROUTEMSG_NO_INFO,"xx",nlh,rtmap_ent);
  	return RHP_STATUS_NETMNG_NOT_INTERESTED;
  }

	RHP_TRC(0,RHPTRCID_NETMNG_PARSE_ROUTEMSG_RTRN,"xx",nlh,rtmap_ent);
  return 0;
}

int rhp_netmng_parse_ifinfomsg(struct nlmsghdr *nlh,rhp_if_entry* ifent)
{
  int err = EINVAL;
  struct ifinfomsg *iim = (struct ifinfomsg*)NLMSG_DATA(nlh);
  struct rtattr *rta
      = (struct rtattr*)(((unsigned char*)iim) + NLMSG_ALIGN(sizeof(struct ifinfomsg)));
  int len = nlh->nlmsg_len
      - NLMSG_ALIGN(sizeof(struct nlmsghdr)) - NLMSG_ALIGN(sizeof(struct ifinfomsg));
  char *if_name = NULL;
  unsigned int *mtu = NULL;
  u8* mac = NULL;

  RHP_TRC(0,RHPTRCID_NETMNG_PARSE_IFINFOMSG_1,"xxuLbxxdw",nlh,ifent,nlh->nlmsg_seq,"AF",iim->ifi_family,iim->ifi_change,iim->ifi_flags,iim->ifi_index,iim->ifi_type);

  for( ;RTA_OK(rta,len); rta = RTA_NEXT(rta,len) ){

  	RHP_TRC(0,RHPTRCID_NETMNG_PARSE_IFINFOMSG_2,"xLwp",nlh,"NETLINK_RTA",rta->rta_type,(int)rta->rta_len,(u8*)rta);

  	switch( rta->rta_type ){

  	case IFLA_IFNAME:

  		if_name = (char*)RTA_DATA(rta);
  		if( strlen(if_name) + 1 >= RHP_IFNAMSIZ ){
  			RHP_BUG("%s",if_name);
  			goto error;
  		}
  		break;

  	case IFLA_ADDRESS:

  		mac = (u8*)RTA_DATA(rta);
  		break;

  	case IFLA_MTU:

  		mtu = (unsigned int*)RTA_DATA(rta);
  		break;

  	default:
  		break;
  	}
  }

  if( if_name == NULL ){
    RHP_BUG("");
    goto error;
  }

  ifent->if_name[0] = '\0';
  strcpy(ifent->if_name,if_name);

  ifent->if_index = iim->ifi_index;
  ifent->if_flags = iim->ifi_flags;

  if( mtu ){
    ifent->mtu = *mtu;
  }else{
    ifent->mtu = 1500;
  }

  if( mac ){
  	memcpy(ifent->mac,mac,6);
  }

	rhp_if_entry_dump("rhp_netmng_parse_ifinfomsg",ifent);

  return 0;

error:
  return err;
}

int rhp_netmng_parse_ifaddrmsg(struct nlmsghdr *nlh,rhp_if_entry* ifent)
{
  int err = EINVAL;
  struct ifaddrmsg *iam = (struct ifaddrmsg*)NLMSG_DATA(nlh);
  struct rtattr *rta
      = (struct rtattr*)(((unsigned char*)iam) + NLMSG_ALIGN(sizeof(struct ifaddrmsg)));
  int len = nlh->nlmsg_len
      - NLMSG_ALIGN(sizeof(struct nlmsghdr)) - NLMSG_ALIGN(sizeof(struct ifaddrmsg));
  char *if_name = NULL;
  u8 *address = NULL;
  char if_name_buf[RHP_IFNAMSIZ];

  RHP_TRC(0,RHPTRCID_NETMNG_PARSE_IFADDRMSG,"xxuLbbdbb",nlh,ifent,nlh->nlmsg_seq,"AF",iam->ifa_family,iam->ifa_flags,iam->ifa_index,iam->ifa_prefixlen,iam->ifa_scope);

	memset(if_name_buf,0,sizeof(char)*RHP_IFNAMSIZ);

  for( ;RTA_OK(rta,len); rta = RTA_NEXT(rta,len) ){

  	RHP_TRC(0,RHPTRCID_NETMNG_PARSE_IFADDRMSG_RTA,"xLwp",nlh,"NETLINK_RTA",rta->rta_type,(int)rta->rta_len,(u8*)rta);

  	switch( rta->rta_type ){

  	case IFA_LABEL:

  		if_name = (char*)RTA_DATA(rta);
  		if( strlen(if_name) + 1 >= RHP_IFNAMSIZ ){
  			goto error;
  		}
  		break;

  	case IFA_ADDRESS:

  		address = (u8*)RTA_DATA(rta);
  		break;

  	default:
  		break;
  	}
  }

  if( iam->ifa_family != AF_INET && iam->ifa_family != AF_INET6 ){
    RHP_BUG("%d",iam->ifa_family);
    goto error;
  }

  if( if_name == NULL ){
    if_indextoname(iam->ifa_index,if_name_buf);
    if_name = if_name_buf;
  }

  ifent->if_name[0] = '\0';
  strcpy(ifent->if_name,if_name);

  ifent->if_addr_flags = iam->ifa_flags;
  ifent->if_index = iam->ifa_index;

  ifent->addr_family = iam->ifa_family;

  if( address ){

    if( iam->ifa_family == AF_INET ){
      memcpy(&(ifent->addr.v4),address,sizeof(u32));
    }else if( iam->ifa_family == AF_INET6 ){
      memcpy(&(ifent->addr.v6),address,sizeof(u8)*16);
    }

    ifent->prefixlen = iam->ifa_prefixlen;

  }else{

    u8 dmy_addr[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    u8 dmy_plen = 0;

    if( iam->ifa_family == AF_INET ){
      memcpy(&(ifent->addr.v4),dmy_addr,sizeof(u32));
    }else if( iam->ifa_family == AF_INET6 ){
      memcpy(&(ifent->addr.v6),dmy_addr,sizeof(u8)*16);
    }

    ifent->prefixlen = dmy_plen;
  }

	rhp_if_entry_dump("rhp_netmng_parse_ifaddrmsg",ifent);

  return 0;

error:
  return err;
}


#define RHP_VIF_CREATE_TX_BUF_LEN (sizeof(struct nlmsghdr) + sizeof(struct ifinfomsg) + sizeof(struct rtattr)*2 + 256)


static int _rhp_vif_create_pend = 0;
static rhp_nm_req_cb* _rhp_vif_create_pend_head = NULL;
static rhp_nm_req_cb* _rhp_vif_create_pend_tail = NULL;

static int rhp_netmng_vif_create_exec(rhp_nm_req_cb* nm_cb,rhp_nm_req_cb_vif* nm_cb_vif)
{
  int err = -EINVAL;
  int tunfd = -1;
  struct ifreq req;
  int flag;

	RHP_TRC(0,RHPTRCID_NETMNG_VIF_CREATE_EXEC,"xxLdsxxuddd",nm_cb,nm_cb_vif,"VIF_TYPE",nm_cb_vif->vif_type,nm_cb->ifent_v4.if_name,&(nm_cb->ifent_v4),&(nm_cb->ifent_v6),nm_cb_vif->vpn_realm_id,nm_cb_vif->exec_up,nm_cb_vif->v6_disable,nm_cb_vif->v6_autoconf);
	rhp_if_entry_dump("rhp_netmng_vif_create_exec:ifent_v4",&(nm_cb->ifent_v4));
	rhp_if_entry_dump("rhp_netmng_vif_create_exec:ifent_v6",&(nm_cb->ifent_v6));

  tunfd = open("/dev/net/tun",O_RDWR);
  if( tunfd < 0 ){
    err = -errno;
    RHP_BUG("%d",err);
    goto error;
  }

  memset(&req,0,sizeof(req));

  strcpy(req.ifr_name,nm_cb->ifent_v4.if_name);

  if( nm_cb_vif->vif_type == RHP_VIF_TYPE_IP_TUNNEL ){
    req.ifr_flags |= IFF_TUN;
  }else if( nm_cb_vif->vif_type == RHP_VIF_TYPE_ETHER_TAP ){
    req.ifr_flags |= IFF_TAP;
  }else{
  	RHP_BUG("%d",nm_cb_vif->vif_type);
  	err = -EINVAL;
  	goto error;
  }

	RHP_TRC(0,RHPTRCID_NETMNG_VIF_CREATE_EXEC_IOCTL_1,"dp",tunfd,sizeof(req),&req);

  if( ioctl(tunfd,TUNSETIFF,(void*)&req) < 0 ){
    err = -errno;
    RHP_BUG("%d",err);
    goto error;
  }

  flag = 1;
	RHP_TRC(0,RHPTRCID_NETMNG_VIF_CREATE_EXEC_IOCTL_2,"dx",tunfd,flag);

	if( ioctl(tunfd,TUNSETPERSIST,flag) < 0 ){
    err = -errno;
    RHP_BUG("%d",err);
    goto error;
  }

	RHP_TRC(0,RHPTRCID_NETMNG_VIF_CREATE_EXEC_IOCTL_3,"du",tunfd,RHP_PEER_PROCESS->uid);

	if( ioctl(tunfd,TUNSETOWNER,RHP_PEER_PROCESS->uid) < 0 ){
    err = -errno;
    RHP_BUG("%d",err);
    goto error;
  }

  close(tunfd);

  _rhp_netmng_put_callback(_rhp_nl_seqno++,nm_cb);
  _rhp_vif_create_pend = 1;

  RHP_TRC(0,RHPTRCID_NETMNG_VIF_CREATE_EXEC_RTRN,"xxs",nm_cb,nm_cb_vif,nm_cb->ifent_v4.if_name);
  return 0;

error:
	if( tunfd >= 0 ){
		close(tunfd);
	}
  RHP_TRC(0,RHPTRCID_NETMNG_VIF_CREATE_EXEC_ERR,"xxsE",nm_cb,nm_cb_vif,nm_cb->ifent_v4.if_name,err);
	return err;
}

static int _rhp_netmng_vif_create_cb(struct nlmsghdr *nlh,void* priv1,void* priv2,void *ctx)
{
	rhp_nm_req_cb_vif* nm_cb_vif = (rhp_nm_req_cb_vif*)ctx;
  rhp_if_entry* ifent_v4 = (rhp_if_entry*)priv1;
  rhp_if_entry* ifent_v6 = (rhp_if_entry*)priv2;
  int err = 0;
  rhp_if_entry nl_ifent;
  int doit = 0;
  int addr_updated = 0;
  rhp_cmd_tlv_list tlvlst;
	rhp_ip_addr addr;

	RHP_TRC(0,RHPTRCID_NETMNG_VIF_CREATE_CB,"xLwusxxxddddd",nlh,"NETLINK_MSG",nlh->nlmsg_type,nlh->nlmsg_seq,ifent_v4->if_name,priv1,priv2,nm_cb_vif,nm_cb_vif->exec_up,nm_cb_vif->v6_autoconf,nm_cb_vif->v6_disable,_rhp_vif_create_pend,_rhp_vif_create_pend_head);
	rhp_if_entry_dump("_rhp_netmng_vif_create_cb:ifent_v4",ifent_v4);
	rhp_if_entry_dump("_rhp_netmng_vif_create_cb:ifent_v6",ifent_v6);

	memset(&addr,0,sizeof(rhp_ip_addr));

  if( nlh->nlmsg_type != RTM_NEWLINK ){
  	RHP_TRC(0,RHPTRCID_NETMNG_VIF_CREATE_CB_NOT_INTERESTED_ERR,"x",nlh);
  	return RHP_STATUS_NETMNG_NOT_INTERESTED;
  }

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return RHP_STATUS_NETMNG_NOT_INTERESTED;
  }

  memset(&nl_ifent,0,sizeof(rhp_if_entry));

  if( rhp_netmng_parse_ifinfomsg(nlh,&nl_ifent) ){
    RHP_BUG("%d",nlh->nlmsg_type);
    err = -EINVAL;
    goto error;
  }

	memset(&tlvlst,0,sizeof(rhp_cmd_tlv_list));


  if( nm_cb_vif->vpn_realm_id ){

  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_ULONG,"RHP_REALM_ID",
  					sizeof(unsigned long),&(nm_cb_vif->vpn_realm_id));
		if( err ){
			RHP_BUG("");
			goto error;
		}

  }else{
		RHP_BUG("");
		goto error;
  }


  if( ifent_v4->mtu && (ifent_v4->mtu >= 576) ){

  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_UINT,"RHP_MTU",sizeof(unsigned int),&(ifent_v4->mtu));
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}

  	doit++;
  }


  if( (ifent_v4->addr_family == AF_INET) && ifent_v4->addr.v4 ){

  	if( ifent_v4->prefixlen == 0 ){
  		ifent_v4->prefixlen = 32;
  	}

  	addr.addr_family = AF_INET;
		addr.prefixlen = ifent_v4->prefixlen;
		addr.addr.v4 = ifent_v4->addr.v4;

  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV4,"RHP_IPV4",sizeof(rhp_ip_addr),&addr);
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}

  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV4_SUBNET_MASK,
  					"RHP_IPV4_SUBNET_MASK",sizeof(rhp_ip_addr),&addr);
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}

  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV4_SUBNET_PREFIX,
  					"RHP_IPV4_SUBNET_PREFIXLEN",sizeof(rhp_ip_addr),&addr);
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}

		doit++;
		addr_updated++;
  }

  if( nm_cb_vif->v6_disable ){

  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_IPV6_SERVICE",(strlen("disable") + 1),"disable");
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}

  	doit++;

  }else{

    if( nm_cb_vif->v6_autoconf == RHP_IPC_VIF_V6_AUTOCONF_DISABLE ){

    	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_IPV6_AUTOCONF",(strlen("disable") + 1),"disable");
    	if( err ){
    		RHP_BUG("");
    		goto error;
    	}

    	doit++;

    }else if( nm_cb_vif->v6_autoconf == RHP_IPC_VIF_V6_AUTOCONF_ENABLE_ADDR ){

    	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_IPV6_AUTOCONF",(strlen("address") + 1),"address");
    	if( err ){
    		RHP_BUG("");
    		goto error;
    	}

    	doit++;
    }


		if( (ifent_v6->addr_family == AF_INET6) &&
				!rhp_ipv6_addr_null(ifent_v6->addr.v6) ){

			if( ifent_v6->prefixlen == 0 ){
				ifent_v6->prefixlen = 128;
			}

			addr.addr_family = AF_INET6;
			addr.prefixlen = ifent_v6->prefixlen;
			memcpy(addr.addr.v6,ifent_v6->addr.v6,16);

			err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV6,"RHP_IPV6",sizeof(rhp_ip_addr),&addr);
			if( err ){
				RHP_BUG("");
				goto error;
			}

			err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV6_SUBNET_PREFIX,
							"RHP_IPV6_SUBNET_PREFIXLEN",sizeof(rhp_ip_addr),&addr);
			if( err ){
				RHP_BUG("");
				goto error;
			}

			doit++;
			addr_updated++;
		}
  }

  if( nm_cb_vif->exec_up ){

  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_EXEC_UP_DOWN",(strlen("up") + 1),"up");
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}

  	doit++;
  }

  if( doit ){

  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_ACTION",
  					(strlen("CONFIG_INTERFACE") + 1),"CONFIG_INTERFACE");
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}

  	if( addr_updated ){

  		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_ADDR_ACTION",(strlen("add") + 1),"add");
			if( err ){
				RHP_BUG("");
				goto error;
			}
  	}

  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_INTERFACE",
  					(strlen(ifent_v4->if_name) + 1),ifent_v4->if_name);
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}

  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_SCRIPT_DIR",
  					(strlen(rhp_netmng_cmd_dir) + 1),rhp_netmng_cmd_dir);
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}

		err = rhp_cmd_exec(rhp_netmng_cmd_path,&tlvlst,1);
		if( err ){
			RHP_BUG("%d",err);
		}

		err = 0;
  }

	rhp_cmd_tlv_clear(&tlvlst);

	if( _rhp_vif_create_pend_head ){

		rhp_nm_req_cb* nm_cb_n = _rhp_vif_create_pend_head;
		rhp_nm_req_cb_vif* nm_cb_vif_n = (rhp_nm_req_cb_vif*)nm_cb_n->ctx;

		_rhp_vif_create_pend_head = _rhp_vif_create_pend_head->next;
		if( _rhp_vif_create_pend_head == NULL ){
			_rhp_vif_create_pend_tail = NULL;
		}

		err = rhp_netmng_vif_create_exec(nm_cb_n,nm_cb_vif_n);
		if( err ){

			_rhp_netmng_free_callback(nm_cb_n);
			_rhp_free(nm_cb_vif_n);

			goto error;
		}

	}else{

		_rhp_vif_create_pend = 0;
	}

	_rhp_free(nm_cb_vif);

	RHP_TRC(0,RHPTRCID_NETMNG_VIF_CREATE_CB_RTRN,"x",nlh);
	return RHP_STATUS_NETMNG_DONE;

error:
	rhp_cmd_tlv_clear(&tlvlst);

	if( nm_cb_vif ){
		_rhp_free(nm_cb_vif);
	}
	RHP_TRC(0,RHPTRCID_NETMNG_VIF_CREATE_CB_ERR,"xE",nlh,err);
	return err;
}

int rhp_netmng_vif_create(int type,rhp_if_entry* ifent_v4,rhp_if_entry* ifent_v6,
		unsigned long vpn_realm_id,int exec_up,int v6_disable,int v6_autoconf)
{
  int err = -EINVAL;
  rhp_nm_req_cb* nm_cb = NULL;
  rhp_nm_req_cb_vif* nm_cb_vif = NULL;

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return -EPERM;
  }

	RHP_TRC(0,RHPTRCID_NETMNG_VIF_CREATE,"Ldsxxuddd","VIF_TYPE",type,ifent_v4->if_name,ifent_v4,ifent_v6,vpn_realm_id,exec_up,v6_disable,v6_autoconf);
	rhp_if_entry_dump("rhp_netmng_vif_create:ifent_v4",ifent_v4);
	rhp_if_entry_dump("rhp_netmng_vif_create:ifent_v6",ifent_v6);


	nm_cb_vif = (rhp_nm_req_cb_vif*)_rhp_malloc(sizeof(rhp_nm_req_cb_vif));
	if( nm_cb_vif == NULL ){
		RHP_BUG("");
  	err = -ENOMEM;
		goto error;
	}

	nm_cb_vif->vpn_realm_id = vpn_realm_id;
	nm_cb_vif->exec_up = exec_up;
  nm_cb_vif->v6_disable = v6_disable;
  nm_cb_vif->v6_autoconf = v6_autoconf;
  nm_cb_vif->vif_type = type;


  nm_cb = _rhp_netmng_alloc_callback(_rhp_netmng_vif_create_cb,nm_cb_vif);
  if( nm_cb == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
		goto error;
  }

  nm_cb->cmp_if_name = 1;
  memcpy(&(nm_cb->ifent_v4),ifent_v4,sizeof(rhp_if_entry));
  memcpy(&(nm_cb->ifent_v6),ifent_v6,sizeof(rhp_if_entry));

  if( _rhp_vif_create_pend ){

  	if( _rhp_vif_create_pend_head ){
  		_rhp_vif_create_pend_tail->next = nm_cb;
  	}else{
  		_rhp_vif_create_pend_head = nm_cb;
  	}
		_rhp_vif_create_pend_tail = nm_cb;

		nm_cb->ctx = (void*)nm_cb_vif;

	  RHP_TRC(0,RHPTRCID_NETMNG_VIF_CREATE_PENDING,"Ldsxx","VIF_TYPE",type,ifent_v4->if_name,ifent_v4,ifent_v6);
  	goto pending;
  }


  err = rhp_netmng_vif_create_exec(nm_cb,nm_cb_vif);
  if( err ){
  	goto error;
  }
  _rhp_vif_create_pend = 1;

pending:
  RHP_TRC(0,RHPTRCID_NETMNG_VIF_CREATE_RTRN,"Ldsxx","VIF_TYPE",type,ifent_v4->if_name,ifent_v4,ifent_v6);
	return 0;

error:
  if( nm_cb ){
  	_rhp_netmng_free_callback(nm_cb);
  }
  if( nm_cb_vif ){
  	_rhp_free(nm_cb_vif);
  }

  RHP_TRC(0,RHPTRCID_NETMNG_VIF_CREATE_RTRN,"LdsxxE","VIF_TYPE",type,ifent_v4->if_name,ifent_v4,ifent_v6,err);
  return err;
}

int rhp_netmng_vif_exec_ipv6_autoconf(unsigned long vpn_realm_id,rhp_if_entry* if_info)
{
  int err = 0;
  rhp_cmd_tlv_list tlvlst;

  RHP_TRC(0,RHPTRCID_NETMNG_VIF_EXEC_IPV6_AUTOCONF,"uxs",vpn_realm_id,if_info,if_info->if_name);

	memset(&tlvlst,0,sizeof(rhp_cmd_tlv_list));


  if( vpn_realm_id ){

  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_ULONG,"RHP_REALM_ID",
  					sizeof(unsigned long),&vpn_realm_id);
		if( err ){
			RHP_BUG("");
			goto error;
		}

  }else{
		RHP_BUG("");
		goto error;
  }

	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_IPV6_AUTOCONF",
					(strlen("exec_ipv6_autoconf") + 1),"exec_ipv6_autoconf");
	if( err ){
		RHP_BUG("");
		goto error;
	}

	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_ACTION",
					(strlen("CONFIG_INTERFACE") + 1),"CONFIG_INTERFACE");
	if( err ){
		RHP_BUG("");
		goto error;
	}

	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_INTERFACE",
					(strlen(if_info->if_name) + 1),if_info->if_name);
	if( err ){
		RHP_BUG("");
		goto error;
	}

	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_SCRIPT_DIR",
					(strlen(rhp_netmng_cmd_dir) + 1),rhp_netmng_cmd_dir);
	if( err ){
		RHP_BUG("");
		goto error;
	}

	err = rhp_cmd_exec(rhp_netmng_cmd_path,&tlvlst,1);
	if( err ){
		RHP_BUG("%d",err);
	}

	err = 0;

	rhp_cmd_tlv_clear(&tlvlst);

  RHP_TRC(0,RHPTRCID_NETMNG_VIF_EXEC_IPV6_AUTOCONF_RTRN,"uxs",vpn_realm_id,if_info,if_info->if_name);
	return 0;

error:
	rhp_cmd_tlv_clear(&tlvlst);

  RHP_TRC(0,RHPTRCID_NETMNG_VIF_EXEC_IPV6_AUTOCONF_ERR,"uxsE",vpn_realm_id,if_info,if_info->if_name,err);
	return err;
}

//
// TODO: Delete an old address b4 a new address is updated.
//
int rhp_netmng_vif_update(unsigned int updated_flag,rhp_if_entry* if_info)
{
  int err = -EINVAL;
  int doit = 0;
  int addr_updated = 0;
  rhp_cmd_tlv_list tlvlst;

	RHP_TRC(0,RHPTRCID_NETMNG_VIF_UPDATE,"x",if_info);
	rhp_if_entry_dump("rhp_netmng_vif_update:if_info",if_info);

	memset(&tlvlst,0,sizeof(rhp_cmd_tlv_list));

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return -EPERM;
  }

  if( (updated_flag & RHP_IPC_VIF_UPDATE_MTU) && if_info->mtu && (if_info->mtu >= 576) ){

  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_UINT,"RHP_MTU",sizeof(unsigned int),&(if_info->mtu));
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}

  	doit++;
  }

  if( updated_flag & RHP_IPC_VIF_UPDATE_ADDR ){

		rhp_ip_addr addr;
		memset(&addr,0,sizeof(rhp_ip_addr));

  	if( if_info->addr_family == AF_INET ){

			addr.addr_family = AF_INET;

			if( if_info->addr.v4 ){

				addr.prefixlen = if_info->prefixlen;
				addr.addr.v4 = if_info->addr.v4;

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV4,"RHP_IPV4",sizeof(rhp_ip_addr),&addr);
				if( err ){
					RHP_BUG("");
					goto error;
				}

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV4_SUBNET_MASK,"RHP_IPV4_SUBNET_MASK",sizeof(rhp_ip_addr),&addr);
				if( err ){
					RHP_BUG("");
					goto error;
				}

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV4_SUBNET_PREFIX,"RHP_IPV4_SUBNET_PREFIXLEN",sizeof(rhp_ip_addr),&addr);
				if( err ){
					RHP_BUG("");
					goto error;
				}

				doit++;
				addr_updated++;
			}

  	}else	if( if_info->addr_family == AF_INET6 ){

			addr.addr_family = AF_INET6;

			if( !rhp_ipv6_addr_null(if_info->addr.v6) ){

				addr.prefixlen = if_info->prefixlen;
				memcpy(addr.addr.v6,if_info->addr.v6,16);

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV6,"RHP_IPV6",sizeof(rhp_ip_addr),&addr);
				if( err ){
					RHP_BUG("");
					goto error;
				}

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV6_SUBNET_PREFIX,"RHP_IPV6_SUBNET_PREFIXLEN",sizeof(rhp_ip_addr),&addr);
				if( err ){
					RHP_BUG("");
					goto error;
				}

				doit++;
				addr_updated++;
			}
		}
  }

  if( doit ){

  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_ACTION",(strlen("CONFIG_INTERFACE") + 1),"CONFIG_INTERFACE");
  	if( err ){
			RHP_BUG("");
			goto error;
		}

  	if( addr_updated ){

  		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_ADDR_ACTION",(strlen("add") + 1),"add");
			if( err ){
				RHP_BUG("");
				goto error;
			}
  	}


  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_INTERFACE",(strlen(if_info->if_name) + 1),if_info->if_name);
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}

  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_SCRIPT_DIR",(strlen(rhp_netmng_cmd_dir) + 1),rhp_netmng_cmd_dir);
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}

		err = rhp_cmd_exec(rhp_netmng_cmd_path,&tlvlst,1);
		if( err ){
			RHP_BUG("%d",err);
		}
		err = 0;
  }

	rhp_cmd_tlv_clear(&tlvlst);

	RHP_TRC(0,RHPTRCID_NETMNG_VIF_UPDATE_RTRN,"x",if_info);
	return RHP_STATUS_NETMNG_DONE;

error:
	rhp_cmd_tlv_clear(&tlvlst);

	RHP_TRC(0,RHPTRCID_NETMNG_VIF_UPDATE_ERR,"xE",if_info,err);
	return err;
}

int rhp_netmng_vif_delete_addr(unsigned int updated_flag,rhp_if_entry* if_info)
{
  int err = -EINVAL;
  int doit = 0;
  int addr_updated = 0;
  rhp_cmd_tlv_list tlvlst;

	RHP_TRC(0,RHPTRCID_NETMNG_VIF_DELETE_ADDR,"x",if_info);
	rhp_if_entry_dump("rhp_netmng_vif_delete_addr:if_info",if_info);

	memset(&tlvlst,0,sizeof(rhp_cmd_tlv_list));

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return -EPERM;
  }

  if( updated_flag & RHP_IPC_VIF_DELETE_ADDR ){

		rhp_ip_addr addr;
		memset(&addr,0,sizeof(rhp_ip_addr));

  	if( if_info->addr_family == AF_INET ){

			addr.addr_family = AF_INET;

			if( if_info->addr.v4 ){

				addr.prefixlen = if_info->prefixlen;
				addr.addr.v4 = if_info->addr.v4;

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV4,"RHP_IPV4",sizeof(rhp_ip_addr),&addr);
				if( err ){
					RHP_BUG("");
					goto error;
				}

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV4_SUBNET_MASK,"RHP_IPV4_SUBNET_MASK",sizeof(rhp_ip_addr),&addr);
				if( err ){
					RHP_BUG("");
					goto error;
				}

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV4_SUBNET_PREFIX,"RHP_IPV4_SUBNET_PREFIXLEN",sizeof(rhp_ip_addr),&addr);
				if( err ){
					RHP_BUG("");
					goto error;
				}

				doit++;
				addr_updated++;
			}

  	}else	if( if_info->addr_family == AF_INET6 ){

			addr.addr_family = AF_INET6;

			if( !rhp_ipv6_addr_null(if_info->addr.v6) ){

				addr.prefixlen = if_info->prefixlen;
				memcpy(addr.addr.v6,if_info->addr.v6,16);

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV6,"RHP_IPV6",sizeof(rhp_ip_addr),&addr);
				if( err ){
					RHP_BUG("");
					goto error;
				}

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV6_SUBNET_PREFIX,"RHP_IPV6_SUBNET_PREFIXLEN",sizeof(rhp_ip_addr),&addr);
				if( err ){
					RHP_BUG("");
					goto error;
				}

				doit++;
				addr_updated++;
			}
		}
  }

  if( doit ){

  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_ACTION",(strlen("CONFIG_INTERFACE") + 1),"CONFIG_INTERFACE");
  	if( err ){
			RHP_BUG("");
			goto error;
		}

  	if( addr_updated ){

  		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_ADDR_ACTION",(strlen("delete") + 1),"delete");
  		if( err ){
  			RHP_BUG("");
  			goto error;
  		}
  	}

  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_INTERFACE",(strlen(if_info->if_name) + 1),if_info->if_name);
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}

  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_SCRIPT_DIR",(strlen(rhp_netmng_cmd_dir) + 1),rhp_netmng_cmd_dir);
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}

		err = rhp_cmd_exec(rhp_netmng_cmd_path,&tlvlst,1);
		if( err ){
			RHP_BUG("%d",err);
		}
		err = 0;
  }

	rhp_cmd_tlv_clear(&tlvlst);

	RHP_TRC(0,RHPTRCID_NETMNG_VIF_DELETE_ADDR_RTRN,"x",if_info);
	return RHP_STATUS_NETMNG_DONE;

error:
	rhp_cmd_tlv_clear(&tlvlst);

	RHP_TRC(0,RHPTRCID_NETMNG_VIF_DELETE_ADDR_ERR,"xE",if_info,err);
	return err;
}


int rhp_netmng_vif_delete(int type,char* vif_name)
{
  int err = -EINVAL;
  int tunfd = -1;
  struct ifreq req;
  int flag;

	RHP_TRC(0,RHPTRCID_NETMNG_VIF_DELETE,"s",vif_name);

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return -EPERM;
  }

  tunfd = open("/dev/net/tun",O_RDWR);
  if( tunfd < 0 ){
  	err = -errno;
  	RHP_BUG("%d : %s",err,vif_name);
  	goto error;
  }

  memset(&req,0,sizeof(req));

  strcpy(req.ifr_name,vif_name);

  if( type == RHP_VIF_TYPE_IP_TUNNEL ){
    req.ifr_flags |= IFF_TUN;
  }else if( type == RHP_VIF_TYPE_ETHER_TAP ){
    req.ifr_flags |= IFF_TAP;
  }else{
  	RHP_BUG("%d",type);
  	err = -EINVAL;
  	goto error;
  }

	RHP_TRC(0,RHPTRCID_NETMNG_VIF_DELETE_IOCTL_1,"sp",vif_name,sizeof(req),&req);

  if( ioctl(tunfd,TUNSETIFF,(void*)&req) < 0 ){
  	err = -errno;
  	RHP_BUG("%d : %s",err,vif_name);
  	goto error;
  }

  flag = 0;
  RHP_TRC(0,RHPTRCID_NETMNG_VIF_DELETE_IOCTL_2,"sd",vif_name,flag);

  if( ioctl(tunfd,TUNSETPERSIST,flag) < 0 ){
  	err = -errno;
  	RHP_BUG("%d : %s",err,vif_name);
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_NETMNG_VIF_DELETE_IOCTL_3,"su",vif_name,RHP_PEER_PROCESS->uid);

  if( ioctl(tunfd,TUNSETOWNER,RHP_PEER_PROCESS->uid) < 0 ){
  	err = -errno;
  	RHP_BUG("%d : %s",err,vif_name);
  	goto error;
  }

  close(tunfd);

	RHP_TRC(0,RHPTRCID_NETMNG_VIF_DELETE_RTRN,"s",vif_name);
	return 0;

error:
  if( tunfd >= 0 ){
    close(tunfd);
  }

	RHP_TRC(0,RHPTRCID_NETMNG_VIF_DELETE_ERR,"sE",vif_name,err);
	return err;
}


int rhp_netmng_route_update(char* if_name,rhp_ip_addr* destination,
		rhp_ip_addr* nexthop_addr,unsigned int metric)
{
  int err = -EINVAL;
  int null_flag = 0;
  int doit = 0;
  rhp_cmd_tlv_list tlvlst;

	RHP_TRC(0,RHPTRCID_NETMNG_ROUTE_UPDATE,"sxxu",if_name,destination,nexthop_addr,metric);
	rhp_ip_addr_dump("rhp_netmng_route_update:destination",destination);
	rhp_ip_addr_dump("rhp_netmng_route_update:nexthop_addr",nexthop_addr);

	memset(&tlvlst,0,sizeof(rhp_cmd_tlv_list));


  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return -EPERM;
  }

  if( rhp_ip_addr_null(nexthop_addr) && (if_name == NULL || if_name[0] == '\0') ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( destination->addr_family != AF_INET && destination->addr_family != AF_INET6 ){
  	RHP_BUG("");
  	return -EINVAL;
  }

  if( !strcmp(if_name,RHP_VIRTUAL_NULL_IF_NAME) ){
    null_flag = 1;
  }

  {
  	rhp_ip_addr addr;
  	memset(&addr,0,sizeof(rhp_ip_addr));

  	if( destination->addr_family == AF_INET ){

  		addr.addr_family = AF_INET;

			if( rhp_ip_addr_null(destination) ){ // default route

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_IPV4_DEST",(strlen("default")+1),"default");
				if( err ){
					RHP_BUG("");
					goto error;
				}

			}else{

				addr.prefixlen = destination->prefixlen;
				addr.addr.v4 = destination->addr.v4;

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV4,"RHP_IPV4_DEST",sizeof(rhp_ip_addr),&addr);
				if( err ){
					RHP_BUG("");
					goto error;
				}

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV4_SUBNET_MASK,"RHP_IPV4_DEST_SUBNET_MASK",sizeof(rhp_ip_addr),&addr);
				if( err ){
					RHP_BUG("");
					goto error;
				}

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV4_SUBNET_PREFIX,"RHP_IPV4_DEST_SUBNET_PREFIXLEN",sizeof(rhp_ip_addr),&addr);
				if( err ){
					RHP_BUG("");
					goto error;
				}
			}

  	}else{ // AF_INET6

  		addr.addr_family = AF_INET6;

			if( rhp_ip_addr_null(destination) ){ // default route

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_IPV6_DEST",(strlen("default")+1),"default");
				if( err ){
					RHP_BUG("");
					goto error;
				}

			}else{

				addr.prefixlen = destination->prefixlen;
				memcpy(addr.addr.v6,destination->addr.v6,16);

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV6,"RHP_IPV6_DEST",sizeof(rhp_ip_addr),&addr);
				if( err ){
					RHP_BUG("");
					goto error;
				}

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV6_SUBNET_PREFIX,"RHP_IPV6_DEST_SUBNET_PREFIXLEN",sizeof(rhp_ip_addr),&addr);
				if( err ){
					RHP_BUG("");
					goto error;
				}
			}
  	}

  	memset(&addr,0,sizeof(rhp_ip_addr));

  	if( null_flag ){

    	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_ROUTE_ACTION",(strlen("reject")+1),"reject");
    	if( err ){
    		RHP_BUG("");
    		goto error;
    	}

  	}else if( !rhp_ip_addr_null(nexthop_addr) ){

    	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_ROUTE_ACTION",(strlen("add")+1),"add");
    	if( err ){
    		RHP_BUG("");
    		goto error;
    	}

    	if( destination->addr_family == AF_INET ){

				addr.addr_family = AF_INET;
				addr.addr.v4 = nexthop_addr->addr.v4;

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV4,"RHP_IPV4_GW",sizeof(rhp_ip_addr),&addr);
				if( err ){
					RHP_BUG("");
					goto error;
				}

    	}else{ // AF_INET6

				addr.addr_family = AF_INET6;
				memcpy(addr.addr.v6,nexthop_addr->addr.v6,16);

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV6,"RHP_IPV6_GW",sizeof(rhp_ip_addr),&addr);
				if( err ){
					RHP_BUG("");
					goto error;
				}
    	}

  	}else if( if_name[0] != '\0' ){

    	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_ROUTE_ACTION",(strlen("add")+1),"add");
    	if( err ){
    		RHP_BUG("");
    		goto error;
    	}

    	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_ROUTE_INTERFACE",(strlen(if_name)+1),if_name);
    	if( err ){
    		RHP_BUG("");
    		goto error;
    	}

  	}else{
  		RHP_BUG("");
  		goto error;
  	}

    if( metric ){

    	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_UINT,"RHP_ROUTE_METRIC",sizeof(unsigned int),&metric);
    	if( err ){
    		RHP_BUG("");
    		goto error;
    	}
    }

		doit++;
	}

  if( doit ){

  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_ACTION",(strlen("CONFIG_ROUTE") + 1),"CONFIG_ROUTE");
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}

  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_SCRIPT_DIR",(strlen(rhp_netmng_cmd_dir) + 1),rhp_netmng_cmd_dir);
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}

		err = rhp_cmd_exec(rhp_netmng_cmd_path,&tlvlst,1);
		if( err ){
			RHP_BUG("%d",err);
		}
		err = 0;
  }

	rhp_cmd_tlv_clear(&tlvlst);

  RHP_TRC(0,RHPTRCID_NETMNG_ROUTE_UPDATE_RTRN,"s",if_name);
  return 0;

error:
	rhp_cmd_tlv_clear(&tlvlst);
	RHP_TRC(0,RHPTRCID_NETMNG_ROUTE_UPDATE_ERR,"sE",if_name,err);
	return err;
}

int rhp_netmng_route_delete(char* if_name,rhp_ip_addr* destination,rhp_ip_addr* nexthop_addr)
{
  int err = -EINVAL;
  int null_flag = 0;
  int doit = 0;
  rhp_cmd_tlv_list tlvlst;

  RHP_TRC(0,RHPTRCID_NETMNG_ROUTE_DELETE,"sxx",if_name,destination,nexthop_addr);
	rhp_ip_addr_dump("rhp_netmng_route_delete:destination",destination);
	rhp_ip_addr_dump("rhp_netmng_route_delete:nexthop_addr",nexthop_addr);

	memset(&tlvlst,0,sizeof(rhp_cmd_tlv_list));

  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return -EPERM;
  }

  if( rhp_ip_addr_null(nexthop_addr) && (if_name == NULL || if_name[0] == '\0') ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( destination->addr_family != AF_INET && destination->addr_family != AF_INET6 ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( !strcmp(if_name,RHP_VIRTUAL_NULL_IF_NAME) ){
    null_flag = 1;
  }

  {
  	rhp_ip_addr addr;
  	memset(&addr,0,sizeof(rhp_ip_addr));

  	if( destination->addr_family == AF_INET ){

  		addr.addr_family = AF_INET;

			if( rhp_ip_addr_null(destination) ){ // default route

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_IPV4_DEST",(strlen("default")+1),"default");
				if( err ){
					RHP_BUG("");
					goto error;
				}

			}else{

				addr.prefixlen = destination->prefixlen;
				addr.addr.v4 = destination->addr.v4;

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV4,"RHP_IPV4_DEST",sizeof(rhp_ip_addr),&addr);
				if( err ){
					RHP_BUG("");
					goto error;
				}

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV4_SUBNET_MASK,"RHP_IPV4_DEST_SUBNET_MASK",sizeof(rhp_ip_addr),&addr);
				if( err ){
					RHP_BUG("");
					goto error;
				}

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV4_SUBNET_PREFIX,"RHP_IPV4_DEST_SUBNET_PREFIXLEN",sizeof(rhp_ip_addr),&addr);
				if( err ){
					RHP_BUG("");
					goto error;
				}
			}

  	}else{ // AF_INET6

  		addr.addr_family = AF_INET6;

			if( rhp_ip_addr_null(destination) ){ // default route

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_IPV6_DEST",(strlen("default")+1),"default");
				if( err ){
					RHP_BUG("");
					goto error;
				}

			}else{

				addr.prefixlen = destination->prefixlen;
				memcpy(addr.addr.v6,destination->addr.v6,16);

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV6,"RHP_IPV6_DEST",sizeof(rhp_ip_addr),&addr);
				if( err ){
					RHP_BUG("");
					goto error;
				}

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV6_SUBNET_PREFIX,"RHP_IPV6_DEST_SUBNET_PREFIXLEN",sizeof(rhp_ip_addr),&addr);
				if( err ){
					RHP_BUG("");
					goto error;
				}
			}
  	}

  	memset(&addr,0,sizeof(rhp_ip_addr));

  	if( !rhp_ip_addr_null(nexthop_addr) ){

    	if( destination->addr_family == AF_INET ){

    		addr.addr_family = AF_INET;
    		addr.addr.v4 = nexthop_addr->addr.v4;

    		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV4,"RHP_IPV4_GW",sizeof(rhp_ip_addr),&addr);
    		if( err ){
    			RHP_BUG("");
    			goto error;
    		}

    	}else{

    		addr.addr_family = AF_INET6;
    		memcpy(addr.addr.v6,nexthop_addr->addr.v6,16);

    		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV6,"RHP_IPV6_GW",sizeof(rhp_ip_addr),&addr);
    		if( err ){
    			RHP_BUG("");
    			goto error;
    		}
    	}

  	}else if( if_name[0] != '\0' ){

			err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_ROUTE_INTERFACE",(strlen(if_name)+1),if_name);
			if( err ){
				RHP_BUG("");
				goto error;
			}

  	}else{
  		RHP_BUG("");
  		goto error;
  	}

		doit++;
	}

  if( doit ){

  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_ACTION",(strlen("CONFIG_ROUTE") + 1),"CONFIG_ROUTE");
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}

  	if( null_flag ){

  		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_ROUTE_ACTION",(strlen("delete_reject")+1),"delete_reject");
  		if( err ){
  			RHP_BUG("");
  			goto error;
  		}

  	}else{

  		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_ROUTE_ACTION",(strlen("delete")+1),"delete");
  		if( err ){
  			RHP_BUG("");
  			goto error;
  		}
  	}

  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_SCRIPT_DIR",(strlen(rhp_netmng_cmd_dir) + 1),rhp_netmng_cmd_dir);
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}

		err = rhp_cmd_exec(rhp_netmng_cmd_path,&tlvlst,1);
		if( err ){
			RHP_BUG("%d",err);
		}
		err = 0;
  }

	rhp_cmd_tlv_clear(&tlvlst);

  RHP_TRC(0,RHPTRCID_NETMNG_ROUTE_DELETE_RTRN,"s",if_name);
  return 0;

error:

	rhp_cmd_tlv_clear(&tlvlst);

	RHP_TRC(0,RHPTRCID_NETMNG_ROUTE_DELETE_ERR,"sE",if_name,err);
	return err;
}

int rhp_netmng_dns_pxy_exec_redir(rhp_ip_addr* inet_name_server_addr,
		u16 internal_redir_port,int start_or_end)
{
  int err = -EINVAL;
  rhp_cmd_tlv_list tlvlst;

	RHP_TRC(0,RHPTRCID_NETMNG_DNS_PXY_EXEC_REDIR,"xWd",inet_name_server_addr,internal_redir_port,start_or_end);
	rhp_ip_addr_dump("rhp_netmng_dns_pxy_redir_start:destination",inet_name_server_addr);

	memset(&tlvlst,0,sizeof(rhp_cmd_tlv_list));


  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return -EPERM;
  }

  if( rhp_ip_addr_null(inet_name_server_addr) ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( inet_name_server_addr->addr_family != AF_INET &&
  		inet_name_server_addr->addr_family != AF_INET6 ){
    RHP_BUG("");
    return -EINVAL;
  }

  if( internal_redir_port == 0 ){
    RHP_BUG("");
    return -EINVAL;
  }


  if( inet_name_server_addr->addr_family == AF_INET ){

  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV4,"RHP_IPV4_INET_NAME_SERVER",sizeof(rhp_ip_addr),inet_name_server_addr);
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}

  }else{ // AF_INET6

  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV6,"RHP_IPV6_INET_NAME_SERVER",sizeof(rhp_ip_addr),inet_name_server_addr);
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}
  }

  {
  		unsigned long internal_redir_port_l = (unsigned long)ntohs(internal_redir_port);

  		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_ULONG,"RHP_INTERNAL_DNS_PORT",sizeof(unsigned long),&internal_redir_port_l);
			if( err ){
				RHP_BUG("");
				goto error;
			}
	}

	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_ACTION",(strlen("CONFIG_DNS_PXY_REDIRECT") + 1),"CONFIG_DNS_PXY_REDIRECT");
	if( err ){
		RHP_BUG("");
		goto error;
	}

	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_DNS_PXY_USER",(strlen(RHP_PEER_PROCESS->user_name) + 1),RHP_PEER_PROCESS->user_name);
	if( err ){
		RHP_BUG("");
		goto error;
	}

	if( start_or_end ){

		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_DNS_PXY_ACTION",(strlen("start")+1),"start");
		if( err ){
			RHP_BUG("");
			goto error;
		}

	}else{

		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_DNS_PXY_ACTION",(strlen("end")+1),"end");
		if( err ){
			RHP_BUG("");
			goto error;
		}
	}

	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_SCRIPT_DIR",(strlen(rhp_netmng_cmd_dir) + 1),rhp_netmng_cmd_dir);
	if( err ){
		RHP_BUG("");
		goto error;
	}

	err = rhp_cmd_exec(rhp_netmng_cmd_path,&tlvlst,1);
	if( err ){
		RHP_BUG("%d",err);
	}
	err = 0;

	rhp_cmd_tlv_clear(&tlvlst);

  RHP_TRC(0,RHPTRCID_NETMNG_DNS_PXY_EXEC_REDIR_RTRN,"x",inet_name_server_addr);
  return 0;

error:
	rhp_cmd_tlv_clear(&tlvlst);
	RHP_TRC(0,RHPTRCID_NETMNG_DNS_PXY_EXEC_REDIR_ERR,"xE",inet_name_server_addr,err);
	return err;
}


int rhp_netmng_bridge_ctrl(char* bridge_name,char* vif_name,int add_or_delete)
{
  int err = -EINVAL;
  rhp_cmd_tlv_list tlvlst;

	RHP_TRC(0,RHPTRCID_NETMNG_BRIDGE_CTRL,"ssd",bridge_name,vif_name,add_or_delete);

	memset(&tlvlst,0,sizeof(rhp_cmd_tlv_list));


  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return -EPERM;
  }


	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_ACTION",(strlen("CONFIG_BRIDGE") + 1),"CONFIG_BRIDGE");
	if( err ){
		RHP_BUG("");
		goto error;
	}

	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_BRIDGE_NAME",(strlen(bridge_name) + 1),bridge_name);
	if( err ){
		RHP_BUG("");
		goto error;
	}

	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_BRIDGE_VIF_NAME",(strlen(vif_name) + 1),vif_name);
	if( err ){
		RHP_BUG("");
		goto error;
	}

	if( add_or_delete ){

		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_BRIDGE_ACTION",(strlen("add")+1),"add");
		if( err ){
			RHP_BUG("");
			goto error;
		}

	}else{

		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_BRIDGE_ACTION",(strlen("delete")+1),"delete");
		if( err ){
			RHP_BUG("");
			goto error;
		}
	}

	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_SCRIPT_DIR",(strlen(rhp_netmng_cmd_dir) + 1),rhp_netmng_cmd_dir);
	if( err ){
		RHP_BUG("");
		goto error;
	}

	err = rhp_cmd_exec(rhp_netmng_cmd_path,&tlvlst,1);
	if( err ){
		RHP_BUG("%d",err);
	}
	err = 0;

	rhp_cmd_tlv_clear(&tlvlst);

  RHP_TRC(0,RHPTRCID_NETMNG_BRIDGE_CTRL_RTRN,"ss",bridge_name,vif_name);
  return 0;

error:
	rhp_cmd_tlv_clear(&tlvlst);
	RHP_TRC(0,RHPTRCID_NETMNG_BRIDGE_CTRL_ERR,"ssE",bridge_name,vif_name,err);
	return err;
}


int rhp_netmng_firewall_rules_flush()
{
  int err = -EINVAL;
  rhp_cmd_tlv_list tlvlst;

	RHP_TRC(0,RHPTRCID_NETMNG_FIREWALL_RULES_FLUSH,"");

	memset(&tlvlst,0,sizeof(rhp_cmd_tlv_list));


  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return -EPERM;
  }


	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_ACTION",(strlen("CONFIG_FW_RULES") + 1),"CONFIG_FW_RULES");
	if( err ){
		RHP_BUG("");
		goto error;
	}

	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_FW_ACTION",(strlen("flush") + 1),"flush");
	if( err ){
		RHP_BUG("");
		goto error;
	}

	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_SCRIPT_DIR",(strlen(rhp_netmng_cmd_dir) + 1),rhp_netmng_cmd_dir);
	if( err ){
		RHP_BUG("");
		goto error;
	}

	err = rhp_cmd_exec(rhp_netmng_cmd_path,&tlvlst,1);
	if( err ){
		RHP_BUG("%d",err);
	}
	err = 0;

	rhp_cmd_tlv_clear(&tlvlst);

  RHP_TRC(0,RHPTRCID_NETMNG_FIREWALL_RULES_FLUSH_RTRN,"");
  return 0;

error:
	rhp_cmd_tlv_clear(&tlvlst);
	RHP_TRC(0,RHPTRCID_NETMNG_FIREWALL_RULES_FLUSH_ERR,"E",err);
	return err;
}

int rhp_netmng_firewall_rules_apply(char* traffic,char* action,char* interface,char* filter_pos,
		unsigned int arg0_len,u8* arg0,unsigned int arg1_len,u8* arg1)
{
  int err = -EINVAL;
  rhp_cmd_tlv_list tlvlst;

	RHP_TRC(0,RHPTRCID_NETMNG_FIREWALL_RULES_APPLY,"sssspp",traffic,action,interface,filter_pos,arg0_len,arg0,arg1_len,arg1);

	memset(&tlvlst,0,sizeof(rhp_cmd_tlv_list));


  if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_SYSPXY ){
    RHP_BUG("");
    return -EPERM;
  }


	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_ACTION",(strlen("CONFIG_FW_RULES") + 1),"CONFIG_FW_RULES");
	if( err ){
		RHP_BUG("");
		goto error;
	}

	if( action == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_FW_ACTION",(strlen(action) + 1),action);
	if( err ){
		RHP_BUG("");
		goto error;
	}


	if( traffic ){

		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_FW_TRAFFIC",(strlen(traffic) + 1),traffic);
		if( err ){
			RHP_BUG("");
			goto error;
		}

		if( !strcasecmp(traffic,"web-mng") ){

			if( arg0_len == sizeof(rhp_ip_addr) && ((rhp_ip_addr*)arg0)->addr_family == AF_INET &&
					arg1_len == sizeof(rhp_ip_addr) && ((rhp_ip_addr*)arg1)->addr_family == AF_INET ){

				u16 web_mng_port = ntohs(((rhp_ip_addr*)arg0)->port);

				rhp_ip_addr_dump("arg0",(rhp_ip_addr*)arg0);
				rhp_ip_addr_dump("arg1",(rhp_ip_addr*)arg1);

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV4,"RHP_FW_WEB_MNG_ADDR",sizeof(rhp_ip_addr),arg0);
				if( err ){
					RHP_BUG("");
					goto error;
				}

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_PORT,"RHP_FW_WEB_MNG_PORT",sizeof(u16),&web_mng_port);
				if( err ){
					RHP_BUG("");
					goto error;
				}

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV4_SUBNET_PREFIX,"RHP_FW_WEB_MNG_CL_SUBNET",sizeof(rhp_ip_addr),arg1);
				if( err ){
					RHP_BUG("");
					goto error;
				}

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV4,"RHP_FW_WEB_MNG_CL_ADDR",sizeof(rhp_ip_addr),arg1);
				if( err ){
					RHP_BUG("");
					goto error;
				}

				err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_IPV4_SUBNET_MASK,"RHP_FW_WEB_MNG_CL_SUBNET_MASK",sizeof(rhp_ip_addr),arg1);
				if( err ){
					RHP_BUG("");
					goto error;
				}
			}
		}

	}else{
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}


	if( interface ){

		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_FW_IF",(strlen(interface) + 1),interface);
		if( err ){
			RHP_BUG("");
			goto error;
		}

	}else{
		RHP_BUG("");
	}

	if( filter_pos ){

		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_FW_FILTER_POS",(strlen(filter_pos) + 1),filter_pos);
		if( err ){
			RHP_BUG("");
			goto error;
		}
	}


	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_SCRIPT_DIR",(strlen(rhp_netmng_cmd_dir) + 1),rhp_netmng_cmd_dir);
	if( err ){
		RHP_BUG("");
		goto error;
	}


	err = rhp_cmd_exec(rhp_netmng_cmd_path,&tlvlst,1);
	if( err ){
		RHP_BUG("%d",err);
	}
	err = 0;

	rhp_cmd_tlv_clear(&tlvlst);

  RHP_TRC(0,RHPTRCID_NETMNG_FIREWALL_RULES_APPLY_RTRN,"");
  return 0;

error:
	rhp_cmd_tlv_clear(&tlvlst);
	RHP_TRC(0,RHPTRCID_NETMNG_FIREWALL_RULES_APPLY_ERR,"E",err);
	return err;
}
