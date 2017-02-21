/*

	Copyright (C) 2009-2013 TETSUHARU HANADA <rhpenguine@gmail.com>
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
#include <unistd.h>
#include <sys/capability.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <time.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_tuntap.h"


rhp_mutex_t rhp_rtmapc_lock;
rhp_rtmapc_notifier  rhp_rtmapc_notifiers[RHP_RTMAPC_NOTIFIER_MAX+1];
static rhp_rtmapc_entry* _rhp_rtmapc_list_head = NULL;

int rhp_rtmapc_init()
{
  _rhp_mutex_init("RMC",&rhp_rtmapc_lock);
  memset(rhp_rtmapc_notifiers,0,sizeof(rhp_rtmapc_notifier)*(RHP_RTMAPC_NOTIFIER_MAX+1));

  RHP_TRC(0,RHPTRCID_NETMNG_RTMAPC_INIT,"");
  return 0;
}

int rhp_rtmapc_cleanup()
{
	_rhp_mutex_destroy(&rhp_rtmapc_lock);

	RHP_TRC(0,RHPTRCID_NETMNG_RTMAPC_CLEANUP,"");
	return 0;
}

static void _rhp_rtmapc_dump(char* label,rhp_rtmapc_entry* rtmapc)
{
	rhp_rtmap_entry_dump(label,&(rtmapc->info));
  return;
}

rhp_rtmapc_entry* rhp_rtmapc_alloc()
{
  rhp_rtmapc_entry* rtmapc = (rhp_rtmapc_entry*)_rhp_malloc(sizeof(rhp_rtmapc_entry));

  if( rtmapc == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(rtmapc,0,sizeof(rhp_rtmapc_entry));

  rtmapc->tag[0] = '#';
  rtmapc->tag[1] = 'N';
  rtmapc->tag[2] = 'W';
  rtmapc->tag[3] = 'C';

  _rhp_atomic_init(&(rtmapc->refcnt));
  _rhp_atomic_init(&(rtmapc->is_active));

  _rhp_mutex_init("RML",&(rtmapc->lock));

  rtmapc->dump = _rhp_rtmapc_dump;

  RHP_TRC(0,RHPTRCID_NETMNG_RTMAPC_ALLOC,"x",rtmapc);

  return rtmapc;
}

static void _rhp_rtmapc_free(rhp_rtmapc_entry* rtmapc)
{
  int i;

  RHP_TRC(0,RHPTRCID_NETMNG_RTMAPC_FREE,"x",rtmapc);

  for( i = 0; i <= RHP_RTMAPC_NOTIFIER_MAX;i++ ){
    if( rhp_rtmapc_notifiers[i].callback ){
      rhp_rtmapc_notifiers[i].callback(RHP_RTMAPC_EVT_DESTROY,rtmapc,NULL,rhp_rtmapc_notifiers[i].ctx);
    }
  }

  _rhp_mutex_destroy(&(rtmapc->lock));

  _rhp_atomic_destroy(&(rtmapc->refcnt));
  _rhp_atomic_destroy(&(rtmapc->is_active));

  _rhp_free_zero(rtmapc,sizeof(rhp_rtmapc_entry));

  return;
}

void rhp_rtmapc_hold(rhp_rtmapc_entry* rtmapc)
{
  _rhp_atomic_inc(&(rtmapc->refcnt));
  RHP_TRC(0,RHPTRCID_NETMNG_RTMAPC_HOLD,"xd",rtmapc,_rhp_atomic_read(&(rtmapc->refcnt)));
}

void rhp_rtmapc_unhold(rhp_rtmapc_entry* rtmapc)
{
  RHP_TRC(0,RHPTRCID_NETMNG_RTMAPC_UNHOLD,"xd",rtmapc,_rhp_atomic_read(&(rtmapc->refcnt)));
  if( _rhp_atomic_dec_and_test(&(rtmapc->refcnt)) ){
    _rhp_rtmapc_free(rtmapc);
  }
}


void rhp_rtmapc_put(rhp_rtmapc_entry* rtmapc)
{

  RHP_TRC(0,RHPTRCID_NETMNG_RTMAP_PUT,"x",rtmapc);

  RHP_LOCK(&rhp_rtmapc_lock);

  if( _rhp_rtmapc_list_head ){
    rtmapc->next = _rhp_rtmapc_list_head;
  }
  _rhp_rtmapc_list_head = rtmapc;

  _rhp_atomic_set(&(rtmapc->is_active),1);
  rhp_rtmapc_hold(rtmapc);

  RHP_UNLOCK(&rhp_rtmapc_lock);

  return;
}

#define RHP_RTMAP_ENUM_LST_LEN		128
int rhp_rtmapc_enum(int (*callback)(rhp_rtmapc_entry* rtmapc,void* ctx),void* ctx)
{
	int err = -EINVAL;
	rhp_rtmapc_entry** rtmapc_list_head = NULL;
	rhp_rtmapc_entry* rtmapc;
	int rtmapc_list_num = RHP_RTMAP_ENUM_LST_LEN;
	int n = 0,i;

  RHP_TRC(0,RHPTRCID_NETMNG_RTMAP_ENUM,"Yx",callback,ctx);

	rtmapc_list_head = (rhp_rtmapc_entry**)_rhp_malloc(sizeof(rhp_rtmapc_entry*)*rtmapc_list_num);
	if( rtmapc_list_head == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}
	memset(rtmapc_list_head,0,sizeof(rhp_rtmapc_entry*)*rtmapc_list_num);


  RHP_LOCK(&rhp_rtmapc_lock);

  rtmapc = _rhp_rtmapc_list_head;

  while( rtmapc ){

  	if( n >= rtmapc_list_num ){

  		rhp_rtmapc_entry** tmp;

  		rtmapc_list_num += RHP_RTMAP_ENUM_LST_LEN;

  		tmp = (rhp_rtmapc_entry**)_rhp_malloc(sizeof(rhp_rtmapc_entry*)*rtmapc_list_num);
  		if( tmp == NULL ){

  			RHP_BUG("");

  			for( i = 0; i < n; i++ ){
  				rhp_rtmapc_unhold(rtmapc_list_head[i]);
  			}
  			_rhp_free(rtmapc_list_head);

  			RHP_UNLOCK(&rhp_rtmapc_lock);

  			return -ENOMEM;
  		}

  		memset(tmp,0,sizeof(rhp_rtmapc_entry*)*rtmapc_list_num);

  		memcpy(tmp,rtmapc_list_head,sizeof(rhp_rtmapc_entry*)*n);
			_rhp_free(rtmapc_list_head);

			rtmapc_list_head = tmp;
  	}

  	rtmapc_list_head[n] = rtmapc;
  	rhp_rtmapc_hold(rtmapc);

  	n++;
  	rtmapc = rtmapc->next;
  }

  RHP_UNLOCK(&rhp_rtmapc_lock);

  if( n == 0 ){
  	_rhp_free(rtmapc_list_head);
    RHP_TRC(0,RHPTRCID_NETMNG_RTMAP_ENUM_NO_ENT,"Yx",callback,ctx);
  	return -ENOENT;
  }

  for( i = 0; i < n; i++ ){

  	rtmapc = rtmapc_list_head[i];

  	rhp_rtmap_entry_dump("rhp_rtmapc_enum:cb",&(rtmapc->info));

		err = callback(rtmapc,ctx);
		if( err ){

	  	if( err == RHP_STATUS_ENUM_OK ){
	  		err = 0;
	  	}

			break;
		}
  }

	for( i = 0; i < n; i++ ){
		rhp_rtmapc_unhold(rtmapc_list_head[i]);
	}

	_rhp_free(rtmapc_list_head);

  RHP_TRC(0,RHPTRCID_NETMNG_RTMAP_ENUM_RTRN,"Yx",callback,ctx);
	return 0;
}

void rhp_rtmapc_delete(rhp_rtmapc_entry* rtmapc)
{
  rhp_rtmapc_entry *ret,*retp = NULL;

  RHP_TRC(0,RHPTRCID_NETMNG_RTMAP_DELETE,"x",rtmapc);

  RHP_LOCK(&rhp_rtmapc_lock);

  ret = _rhp_rtmapc_list_head;
  while( ret ){

    if( rtmapc == ret ){
      break;
    }

    retp = ret;
    ret = ret->next;
  }

  if( ret ){

    if( retp ){
      retp->next = ret->next;
    }else{
      _rhp_rtmapc_list_head = ret->next;
    }

    _rhp_atomic_set(&(ret->is_active),0);
    rhp_rtmapc_unhold(ret);

  }else{
    RHP_TRC(0,RHPTRCID_NETMNG_RTMAP_DELETE_NOT_FOUND,"x",rtmapc);
  }

  RHP_UNLOCK(&rhp_rtmapc_lock);
}

rhp_rtmapc_entry* rhp_rtmapc_get(rhp_rt_map_entry* rtmap_ent)
{
  rhp_rtmapc_entry* rtmapc;

  RHP_LOCK(&rhp_rtmapc_lock);

  rtmapc = _rhp_rtmapc_list_head;

  while( rtmapc ){

/*
		if( !rhp_ip_addr_cmp(&(rtmapc->info.dest_network),&(rtmap_ent->dest_network)) ){
			rhp_rtmap_entry_dump("rhp_rtmapc_get:rtmap_ent",rtmap_ent);
	    rtmapc->dump("rhp_rtmapc_get:rtmapc",rtmapc);
		}
*/

  	if( /*rtmapc->info.type == rtmap_ent->type &&*/
  			rtmapc->info.addr_family == rtmap_ent->addr_family &&
  			!strcmp(rtmapc->info.oif_name,rtmap_ent->oif_name) &&
  			!rhp_ip_addr_cmp(&(rtmapc->info.dest_network),&(rtmap_ent->dest_network)) &&
  			((rhp_ip_addr_null(&(rtmapc->info.gateway_addr)) && rhp_ip_addr_null(&(rtmap_ent->gateway_addr)) ) ||
  			!rhp_ip_addr_cmp_ip_only(&(rtmapc->info.gateway_addr),&(rtmap_ent->gateway_addr))) ){

  		break;
    }

  	rtmapc = rtmapc->next;
  }

  if( rtmapc ){
    rhp_rtmapc_hold(rtmapc);
    rtmapc->dump("rhp_rtmapc_get",rtmapc);
  }

  RHP_UNLOCK(&rhp_rtmapc_lock);

  RHP_TRC(0,RHPTRCID_NETMNG_RTMAP_GET,"x",rtmapc);

  return rtmapc;
}


void rhp_rtmapc_call_notifiers(int event,rhp_rtmapc_entry* rtmapc,rhp_rt_map_entry* old)
{
  int i;

  RHP_LOCK(&rhp_rtmapc_lock);

  for( i = 0; i <= RHP_RTMAPC_NOTIFIER_MAX;i++ ){

    if( rhp_rtmapc_notifiers[i].callback ){

      RHP_TRC(0,RHPTRCID_NETMNG_RTMAP_CALL_NOTIFIER,"Ydxppx",rhp_rtmapc_notifiers[i].callback,event,rtmapc,sizeof(rhp_if_entry),&(rtmapc->info),sizeof(rhp_if_entry),old,rhp_rtmapc_notifiers[i].ctx);

      rhp_rtmapc_notifiers[i].callback(event,rtmapc,old,rhp_rtmapc_notifiers[i].ctx);
    }
  }

  RHP_UNLOCK(&rhp_rtmapc_lock);

  return;
}

