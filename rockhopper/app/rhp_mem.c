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
#include <sched.h>
#include <sys/capability.h>
#include <linux/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_wthreads.h"

int rhp_mem_initialized = 0;
static rhp_mutex_t _rhp_mem_lock_statistics;
static u64 _rhp_mem_statistics_alloc_size = 0;
static u64 _rhp_mem_statistics_free_size = 0;


void rhp_mem_statistics_alloc(size_t size)
{
	long idx = rhp_wts_is_worker();

	if( !rhp_mem_initialized ){
		return;
	}

	if( idx >= 0 ){
		rhp_wts_worker_statistics_tbl[idx].dc.mem_alloc_size += size;
	}else{
		RHP_LOCK(&_rhp_mem_lock_statistics);
		_rhp_mem_statistics_alloc_size += size;
		RHP_UNLOCK(&_rhp_mem_lock_statistics);
	}
}

void rhp_mem_statistics_free(size_t size)
{
	long idx = rhp_wts_is_worker();

	if( !rhp_mem_initialized ){
		return;
	}

	if( idx >= 0 ){
		rhp_wts_worker_statistics_tbl[idx].dc.mem_free_size += size;
	}else{
		RHP_LOCK(&_rhp_mem_lock_statistics);
		_rhp_mem_statistics_free_size += size;
		RHP_UNLOCK(&_rhp_mem_lock_statistics);
	}
}

int rhp_mem_statistics_get(u64* alloc_size_r,u64* free_size_r)
{
	int err = -EINVAL;
	u64 alloc_size = 0;
	u64 free_size = 0;
	int i;
	rhp_wts_worker_statistics* wts_tables = NULL;
	int wts_tables_num = 0;

	err = rhp_wts_get_statistics(&wts_tables,&wts_tables_num);
	if( err ){
		RHP_BUG("%d",err);
		return err;
	}

	for( i = 0; i < wts_tables_num; i++ ){
		alloc_size += wts_tables[i].dc.mem_alloc_size;
		free_size += wts_tables[i].dc.mem_free_size;
	}

	RHP_LOCK(&_rhp_mem_lock_statistics);
	alloc_size += _rhp_mem_statistics_alloc_size;
	free_size +=_rhp_mem_statistics_free_size;
	RHP_UNLOCK(&_rhp_mem_lock_statistics);

	_rhp_free(wts_tables);

	*alloc_size_r = alloc_size;
	*free_size_r = free_size;

	return 0;
}


void rhp_mem_statistics_init()
{
  _rhp_mutex_init("MST",&_rhp_mem_lock_statistics);
  rhp_mem_initialized = 1;
  return;
}
