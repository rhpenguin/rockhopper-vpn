/*

	Copyright (C) 2015-2016 TETSUHARU HANADA <rhpenguine@gmail.com>
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
#include <pcap/pcap.h>

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
#include "rhp_pcap.h"


static rhp_mutex_t _rhp_pcap_lock;

static int _rhp_pcap_active = 0;
static pcap_t* _rhp_pcap_pd = NULL;
static pcap_dumper_t* _rhp_pcap_pdumper = NULL;

static unsigned long _rhp_pcap_cfg_max_bytes = 0;
static unsigned long _rhp_pcap_cfg_max_packets = 0;
static time_t _rhp_pcap_cfg_interval = 0;

static unsigned long _rhp_pcap_max_bytes = 0;
static unsigned long _rhp_pcap_max_packets = 0;

static time_t _rhp_pcap_start_time = 0;
static int _rhp_pcap_timer_expired = 0;

static time_t _rhp_pcap_timer_check_interval = 10;


static rhp_timer _rhp_pcap_write_timer;

void (*_rhp_pcap_timer_update_cb)(rhp_pcap_status* status,void* ctx) = NULL;
void* _rhp_pcap_timer_update_cb_ctx = NULL;


int rhp_pcap_start(rhp_pcap_cfg* cap_cfg)
{
	int err = -EINVAL;
	pcap_t* pd = NULL;
	pcap_dumper_t* pdumper = NULL;

	RHP_TRC_FREQ(0,RHPTRCID_PCAP_START,"x",cap_cfg);

	RHP_LOCK(&_rhp_pcap_lock);

	if( _rhp_pcap_active ){
		err = -EBUSY;
		goto error;
	}


	if( cap_cfg->file_name == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	if( cap_cfg->max_bytes < 1 && cap_cfg->max_packets < 1 ){
		RHP_BUG("%lu, %lu",cap_cfg->max_bytes,cap_cfg->max_packets);
		err = -EINVAL;
		goto error;
	}

	if( unlink(cap_cfg->file_name) < 0 ){
		RHP_TRC_FREQ(0,RHPTRCID_PCAP_START_UNLINK_FILE_ERR,"xs",cap_cfg,cap_cfg->file_name);
	}


	pd = pcap_open_dead(DLT_EN10MB, sizeof(rhp_proto_ether) + 65535);
	if( pd == NULL ){
		RHP_BUG("%d",-errno);
		err = -EINVAL;
		goto error;
	}

	pdumper = pcap_dump_open(pd, cap_cfg->file_name);
	if( pdumper == NULL ){
		RHP_BUG("%d",-errno);
		err = -EINVAL;
		goto error;
	}

	_rhp_pcap_pd = pd;
	_rhp_pcap_pdumper = pdumper;

	_rhp_pcap_cfg_max_bytes = cap_cfg->max_bytes;
	_rhp_pcap_cfg_max_packets = cap_cfg->max_packets;
	_rhp_pcap_cfg_interval = cap_cfg->capture_interval;

	_rhp_pcap_start_time = _rhp_get_time();

	rhp_timer_reset(&_rhp_pcap_write_timer);
	rhp_timer_add(&_rhp_pcap_write_timer,_rhp_pcap_timer_check_interval);

	_rhp_pcap_active = 1;

	RHP_UNLOCK(&_rhp_pcap_lock);

	RHP_TRC_FREQ(0,RHPTRCID_PCAP_START_RTRN,"x",cap_cfg);
	return 0;

error:
	if( pdumper ){
		pcap_dump_close(pdumper);
	}
	if( pd ){
		pcap_close(pd);
	}
	RHP_UNLOCK(&_rhp_pcap_lock);

	RHP_TRC_FREQ(0,RHPTRCID_PCAP_START_ERR,"xE",cap_cfg,err);
	return err;
}

static int _rhp_pcap_stop_impl()
{
	int err = -EINVAL;

	RHP_TRC_FREQ(0,RHPTRCID_PCAP_STOP_IMPL,"");

	if( !_rhp_pcap_active ){
		err = -ENOENT;
		goto error;
	}

	rhp_timer_delete(&_rhp_pcap_write_timer);


	if( _rhp_pcap_pdumper ){
		pcap_dump_flush(_rhp_pcap_pdumper);
		pcap_dump_close(_rhp_pcap_pdumper);
	}

	if( _rhp_pcap_pd ){
		pcap_close(_rhp_pcap_pd);
	}

	_rhp_pcap_pdumper = NULL;
	_rhp_pcap_pd = NULL;
	_rhp_pcap_max_bytes = 0;
	_rhp_pcap_max_packets = 0;
	_rhp_pcap_start_time = 0;
	_rhp_pcap_timer_expired = 0;

	rhp_timer_reset(&_rhp_pcap_write_timer);

	_rhp_pcap_active = 0;

	RHP_TRC_FREQ(0,RHPTRCID_PCAP_STOP_IMPL_RTRN,"");
	return 0;

error:
	RHP_TRC_FREQ(0,RHPTRCID_PCAP_STOP_IMPL_ERR,"E",err);
	return err;
}

int rhp_pcap_stop()
{
	int err = -EINVAL;

	RHP_TRC_FREQ(0,RHPTRCID_PCAP_STOP,"");

	RHP_LOCK(&_rhp_pcap_lock);

	err = _rhp_pcap_stop_impl();

	RHP_UNLOCK(&_rhp_pcap_lock);

	RHP_TRC_FREQ(0,RHPTRCID_PCAP_STOP_RTRN,"E",err);
	return err;
}


static void _rhp_pcap_get_status_impl(rhp_pcap_status* status_r)
{
	time_t now = _rhp_get_time();

	RHP_TRC_FREQ(0,RHPTRCID_PCAP_GET_STATUS,"");

	status_r->is_active	= _rhp_pcap_active;
	status_r->captured_bytes	= _rhp_pcap_max_bytes;
	status_r->captured_packets	= _rhp_pcap_max_packets;


	if( _rhp_pcap_active &&
			_rhp_pcap_cfg_interval &&
			!_rhp_pcap_timer_expired ){

		status_r->expire_time = (_rhp_pcap_start_time + _rhp_pcap_cfg_interval) - now;

	}else{

		status_r->expire_time = 0;
	}

	status_r->elapsed_time = (now - _rhp_pcap_start_time);

	if( _rhp_pcap_timer_expired ||
			(_rhp_pcap_cfg_max_packets &&
			 _rhp_pcap_max_packets >= _rhp_pcap_cfg_max_packets) ||
				(_rhp_pcap_cfg_max_bytes &&
				 _rhp_pcap_max_bytes >= _rhp_pcap_cfg_max_bytes) ){

		status_r->capture_finished	= 1;
	}

	RHP_TRC_FREQ(0,RHPTRCID_PCAP_GET_STATUS_RTRN,"xduudtt",status_r,status_r->is_active,status_r->captured_bytes,status_r->captured_packets,status_r->capture_finished,status_r->expire_time,status_r->elapsed_time);
	return;
}

void rhp_pcap_get_status(rhp_pcap_status* status_r)
{
	RHP_LOCK(&_rhp_pcap_lock);

	_rhp_pcap_get_status_impl(status_r);

	RHP_UNLOCK(&_rhp_pcap_lock);
	return;
}


static inline void _rhp_pcap_get_timeval(struct timeval* tv_r)
{
	struct timeval tv;
	struct timespec now;

	clock_gettime(CLOCK_REALTIME_COARSE,&now); // > 1ms(resolution)

	tv.tv_sec = now.tv_sec;
	tv.tv_usec = now.tv_nsec/1000;

	memcpy(tv_r,&tv,sizeof(struct timeval));

	return;
}

int rhp_pcap_write(int pkt_len,u8* pkt_head,
		int dmy_l23_hdr_len,u8* dmy_l23_hdr)
{
	int err = -EINVAL;
	struct pcap_pkthdr pkthdr;
	u8* p = NULL;

	RHP_TRC_FREQ(0,RHPTRCID_PCAP_WRITE,"dxdx",pkt_len,pkt_head,dmy_l23_hdr_len,dmy_l23_hdr);

	memset(&pkthdr,0,sizeof(struct pcap_pkthdr));

	RHP_LOCK(&_rhp_pcap_lock);

	if( !_rhp_pcap_active ){
		err = -ENOENT;
		goto error;
	}

	if( _rhp_pcap_pdumper == NULL ){
		err = -EINVAL;
		goto error;
	}

	if( _rhp_pcap_timer_expired ){
		err = -ETIMEDOUT;
		goto error;
	}

	if( _rhp_pcap_cfg_max_packets &&
			_rhp_pcap_max_packets >= _rhp_pcap_cfg_max_packets ){
		err = -EMSGSIZE;
		goto error;
	}

	if( pkt_len < 1 ){
		err = -EINVAL;
		goto error;
	}

	if( pkt_len <= (int)sizeof(rhp_proto_ether) ){
		err = -EINVAL;
		goto error;
	}

	if( _rhp_pcap_cfg_max_bytes &&
			(_rhp_pcap_max_bytes + pkt_len + dmy_l23_hdr_len) >= _rhp_pcap_cfg_max_bytes ){
		err = -EMSGSIZE;
		goto error;
	}


	if( dmy_l23_hdr_len ){

		p = (u8*)_rhp_malloc(pkt_len + dmy_l23_hdr_len);
		if( p == NULL ){
			err = -ENOMEM;
			goto error;
		}

		memcpy(p,dmy_l23_hdr,dmy_l23_hdr_len);
		memcpy((p + dmy_l23_hdr_len),pkt_head,pkt_len);

		pkt_head = p;
		pkt_len += dmy_l23_hdr_len;
	}


	pkthdr.caplen = pkt_len;
	pkthdr.len = pkt_len;
	_rhp_pcap_get_timeval(&(pkthdr.ts));


	pcap_dump((unsigned char*)_rhp_pcap_pdumper,&pkthdr,(unsigned char*)pkt_head);

	_rhp_pcap_max_bytes += pkt_len;
	_rhp_pcap_max_packets++;

	RHP_UNLOCK(&_rhp_pcap_lock);

	if( p ){
		_rhp_free(p);
	}

	RHP_TRC_FREQ(0,RHPTRCID_PCAP_WRITE_RTRN,"dx",pkt_len,pkt_head);
	return 0;

error:
	RHP_UNLOCK(&_rhp_pcap_lock);

	if( p ){
		_rhp_free(p);
	}

	RHP_TRC_FREQ(0,RHPTRCID_PCAP_WRITE_ERR,"dxE",pkt_len,pkt_head,err);
	return err;
}

int rhp_pcap_write_pkt(rhp_packet* pkt)
{
	int len;
	int err;

	RHP_TRC_FREQ(0,RHPTRCID_PCAP_WRITE_PKT,"x",pkt);

	if( pkt->l2.eth && pkt->tail ){

		len = (pkt->tail - (u8*)pkt->l2.eth);

		if( len > 0 ){

			err = rhp_pcap_write(len,(u8*)pkt->l2.eth,0,NULL);

			RHP_TRC_FREQ(0,RHPTRCID_PCAP_WRITE_PKT_RTRN,"xE",pkt,err);
			return err;
		}
	}

	RHP_TRC_FREQ(0,RHPTRCID_PCAP_WRITE_PKT_ERR,"x",pkt);
	return -EINVAL;
}


static void _rhp_pcap_write_timer_hanlder(void *ctx,rhp_timer *timer)
{
	time_t now = _rhp_get_time();
	rhp_pcap_status status;

	RHP_TRC_FREQ(0,RHPTRCID_PCAP_WRITE_TIMER_HANDLER,"xx",ctx,timer);

	memset(&status,0,sizeof(rhp_pcap_status));

	RHP_LOCK(&_rhp_pcap_lock);

	if( !_rhp_pcap_active ){
		goto error;
	}

	if( _rhp_pcap_cfg_interval &&
			now >= _rhp_pcap_start_time + _rhp_pcap_cfg_interval ){

		_rhp_pcap_timer_expired = 1;
	}

	_rhp_pcap_get_status_impl(&status);

	RHP_UNLOCK(&_rhp_pcap_lock);


	if( _rhp_pcap_timer_update_cb ){

		RHP_TRC_FREQ(0,RHPTRCID_PCAP_WRITE_TIMER_HANDLER_CB,"xduudt",&status,status.is_active,status.captured_bytes,status.captured_packets,status.capture_finished,status.expire_time);

		_rhp_pcap_timer_update_cb(&status,_rhp_pcap_timer_update_cb_ctx);
	}

	rhp_timer_reset(&_rhp_pcap_write_timer);
	rhp_timer_add(&_rhp_pcap_write_timer,_rhp_pcap_timer_check_interval);


error:
	RHP_TRC_FREQ(0,RHPTRCID_PCAP_WRITE_TIMER_HANDLER_RTRN,"xx",ctx,timer);
	return;
}

int rhp_pcap_init(time_t timer_check_interval,
		void (*timer_update_cb)(rhp_pcap_status* status,void* ctx),void* ctx)
{

	_rhp_mutex_init("PCP",&_rhp_pcap_lock);

	rhp_timer_init(&_rhp_pcap_write_timer,_rhp_pcap_write_timer_hanlder,NULL);

	if( timer_check_interval ){
		_rhp_pcap_timer_check_interval = timer_check_interval;
	}

	if( timer_update_cb ){
		_rhp_pcap_timer_update_cb = timer_update_cb;
		_rhp_pcap_timer_update_cb_ctx = ctx;
	}

	return 0;
}

int rhp_pcap_cleanup()
{
	rhp_pcap_stop();

	_rhp_mutex_destroy(&_rhp_pcap_lock);

	return 0;
}


