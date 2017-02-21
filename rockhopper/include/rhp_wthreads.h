/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/

#ifndef _RHP_WORKER_THREADS_H_
#define _RHP_WORKER_THREADS_H_

#define RHP_WTS_MAX_TASKS             		16000
#define RHP_WTS_MAX_TASKS_LOW_PRIORITY		((RHP_WTS_MAX_TASKS/10)*8)
#define RHP_WTS_SYSPXY_WORKERS_NUM    		4
#define RHP_WTS_MAIN_WORKERS_NUM      		4
#define RHP_WTS_YIELD_LIMIT           		1024

#define RHP_WTS_DISP_RULE_NETSOCK   	1
#define RHP_WTS_DISP_RULE_CERTOPR   	2
#define RHP_WTS_DISP_RULE_AUTHREP			3
#define RHP_WTS_DISP_RULE_ESP_TX			4
#define RHP_WTS_DISP_RULE_TUNTAP			5
#define RHP_WTS_DISP_RULE_SESS_RESUME_DEC_TKT			6
#define RHP_WTS_DISP_RULE_DMVPN_HANDLE_SHORTCUT		7
#define RHP_WTS_DISP_RULE_MAX       	7

#define RHP_WTS_DISP_RULE_MISC						(RHP_WTS_DISP_RULE_MAX + 1)
#define RHP_WTS_DISP_RULE_RAND						(RHP_WTS_DISP_RULE_MAX + 2)
#define RHP_WTS_DISP_RULE_SAME_WORKER			(RHP_WTS_DISP_RULE_MAX + 3)
#define RHP_WTS_DISP_RULE_MISC_BLOCKING		(RHP_WTS_DISP_RULE_MAX + 4) // For handlers which may call blocing I/O APIs.

#ifdef RHP_EVENT_FUNCTION
#define RHP_WTS_DISP_RULE_EVENT				(RHP_WTS_DISP_RULE_MAX + 5)
#endif // RHP_EVENT_FUNCTION

																																						// [ Users(main) ]
#define RHP_WTS_DISP_LEVEL_CTRL			0		// 		TLS control
#define RHP_WTS_DISP_LEVEL_HIGH_1		1		// 		IPC (syspxy <==> main)
#define RHP_WTS_DISP_LEVEL_HIGH_2		2		// 		IKEv2
#define RHP_WTS_DISP_LEVEL_HIGH_3		3		// 		Pkt destructor(No limit of Q's length)
#define RHP_WTS_DISP_LEVEL_LOW_1		4		// 		ESP TX, DNS PXY
#define RHP_WTS_DISP_LEVEL_LOW_2		5		// 		TUN TX,  ESP RX
#define RHP_WTS_DISP_LEVEL_LOW_3		6		// 		IKEv2 Cookie, Invalid SPI and Other caches/miscs.
#define RHP_WTS_DISP_LEVEL_MAX			6

#define RHP_WTS_STA_TASK_NAME_PKT								0
#define RHP_WTS_STA_TASK_NAME_HBUS_ASYNC_TX			1
#define RHP_WTS_STA_TASK_NAME_EVENT_LOG					2
#define RHP_WTS_STA_TASK_NAME_MAX								2

extern int rhp_gcfg_wts_workers;

extern int rhp_wts_init(int workers_num);

extern int rhp_wts_register_disp_rule(unsigned long type,u32 (*disp_hash)(void *key_seed,int* err));

extern int rhp_wts_add_task(unsigned long type,int disp_priority,void *key_seed,
		void (*task_handler)(int worker_index,void *task_ctx),void* task_ctx);

extern int rhp_wts_add_ctrl_task(void (*task_handler)(int worker_index,void *task_ctx),
		void (*ctx_destructor)(void* task_ctx),void* task_ctx); // Broadcasts 'task' for 'ALL' worker threads.

extern int rhp_wts_sta_register_task(int task_name,int disp_priority,
		void (*task_handler)(int worker_index,void *task_ctx),
		int (*do_exec)(int worker_index,void* ctx),
		int (*add_ctx)(int worker_index,void* task_ctx,void* ctx),void* task_ctx);

extern int rhp_wts_sta_invoke_task(unsigned long type/*RHP_WTS_DISP_RULE_XXX*/,
		int task_name,int disp_priority,void *key_seed,void* ctx);

extern int rhp_wts_dispach_ok(int disp_priority,int is_fixed_rule);
extern int rhp_wts_dispach_check(int disp_priority,int is_fixed_rule);

extern int rhp_wts_switch_ctx(int disp_priority,void (*task)(int worker_index,void *ctx),void* ctx);

extern int rhp_wts_get_workers_num();
extern long rhp_wts_is_worker();


struct _rhp_wts_worker_statistics_dont_clear {
	u64 mem_alloc_size;
	u64 mem_free_size;
};
typedef struct _rhp_wts_worker_statistics_dont_clear	rhp_wts_worker_statistics_dont_clear;

struct _rhp_wts_worker_statistics {

	u64 exec_tasks_counter;
	u64 exec_sta_pkt_tasks_counter;
	u64 exec_sta_pkt_task_pkts;
	u64 exec_sta_esp_tx_tasks_pkts;
	u64 exec_sta_netsock_rx_tasks_pkts;
	u64 exec_sta_tuntap_rd_tasks_pkts;

	// The followings MUST NOT be cleared by rhp_wts_clear_statistics()
	// and MUST be the tail of this structure.
	rhp_wts_worker_statistics_dont_clear dc;
};
typedef struct _rhp_wts_worker_statistics	rhp_wts_worker_statistics;

extern rhp_wts_worker_statistics* rhp_wts_worker_statistics_tbl;

extern int rhp_wts_get_statistics(rhp_wts_worker_statistics** tables_r,int* tables_num_r);
extern int rhp_wts_clear_statistics();


#endif // _RHP_WORKER_THREADS_H_

