/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifndef _RHP_NETMNG_H_
#define _RHP_NETMNG_H_

extern int rhp_nl_sk;

#define RHP_NETMNG_BUFSZ  4096 // PAGE_SIZE

extern int rhp_netmng_init(int ipv6_disabled);
extern void rhp_netmng_cleanup();

/**************************

  Netlink Handling APIs

***************************/

extern int rhp_netmng_send_dumplink(int (*callback)(struct nlmsghdr *nlh,void* priv1,void* priv2,void* ctx),void* ctx);
extern int rhp_netmng_send_dumpaddr(int (*callback)(struct nlmsghdr *nlh,void* priv1,void* priv2,void* ctx),void* ctx,int addr_family);
extern int rhp_netmng_send_dumproute(int (*callback)(struct nlmsghdr *nlh,void* priv1,void* priv2,void* ctx),void* ctx,int addr_family);
extern int rhp_netmng_recvmsg(void *buf,int len,int flags,
                              void (*callback)(struct nlmsghdr *nlh,void *ctx),void *ctx);

extern int rhp_netmng_parse_ifinfomsg(struct nlmsghdr *nlh,rhp_if_entry* ifent);
extern int rhp_netmng_parse_ifaddrmsg(struct nlmsghdr *nlh,rhp_if_entry* ifent);
extern int rhp_netmng_parse_routemsg(struct nlmsghdr *nlh,rhp_rt_map_entry* rtmap_ent);


#define RHP_VIF_TYPE_ETHER_TAP		1
#define RHP_VIF_TYPE_IP_TUNNEL		2
extern int rhp_netmng_vif_create(int type,rhp_if_entry* ifent_v4,rhp_if_entry* ifent_v6,
		unsigned long vpn_realm_id,int exec_up,int v6_disable,int v6_autoconf);
extern int rhp_netmng_vif_update(unsigned int updated_flag,rhp_if_entry* if_info);
extern int rhp_netmng_vif_delete_addr(unsigned int updated_flag,rhp_if_entry* if_info);
extern int rhp_netmng_vif_delete(int type,char* vif_name);
extern int rhp_netmng_vif_exec_ipv6_autoconf(unsigned long vpn_realm_id,rhp_if_entry* if_info);


extern int rhp_syspxy_netmng_init();
extern int rhp_syspxy_netmng_cleanup();
extern void rhp_syspxy_handle_netmng();
extern int rhp_syspxy_netmng_handle_ipc(rhp_ipcmsg *ipcmsg);

extern int rhp_main_netmng_ipc_start();
extern int rhp_main_ipc_handle(rhp_ipcmsg *ipcmsg);

struct _rhp_vpn_realm;
struct _rhp_cfg_internal_if;
struct _rhp_route_map;
extern int rhp_ipc_send_my_ids_resolve_req();

extern int rhp_ipc_send_create_vif(struct _rhp_vpn_realm* rlm);
extern int rhp_ipc_send_delete_vif(struct _rhp_vpn_realm* rlm);
extern int rhp_ipc_send_create_vif_raw(unsigned long rlm_id,char* vif_name,
		struct _rhp_cfg_internal_if* vif_info,int exec_up,int v6_disable,int v6_autoconf);
extern int rhp_ipc_send_delete_vif_raw(unsigned long rlm_id,char* vif_name);
extern int rhp_ipc_send_update_vif_raw(unsigned long rlm_id,char* vif_name,
		unsigned int updated_flag,rhp_if_entry* if_info);

extern int rhp_ipc_send_vif_exec_ipv6_autoconf(unsigned long rlm_id,char* vif_name);

extern int rhp_ipc_send_my_id_resolve_req(unsigned long rlm_id);


/**************************************

  DNS Proxy Handling APIs (iptables/netfilter)

***************************************/

extern int rhp_netmng_dns_pxy_exec_redir(rhp_ip_addr* inet_name_server_addr,u16 internal_redir_port,int start_or_end);



/**************************

  Routing Handling APIs

***************************/

extern int rhp_netmng_route_update(char* if_name,rhp_ip_addr* destination,rhp_ip_addr* nexthop_addr,unsigned int metric);
extern int rhp_netmng_route_delete(char* if_name,rhp_ip_addr* destination,rhp_ip_addr* nexthop_addr);

extern int rhp_ipc_send_update_route(struct _rhp_vpn_realm* rlm,struct _rhp_route_map* rtmap,rhp_ip_addr* gateway_addr);
extern int rhp_ipc_send_delete_route(struct _rhp_vpn_realm* rlm,struct _rhp_route_map* rtmap,rhp_ip_addr* gateway_addr);
extern int rhp_ipc_send_update_all_static_routes(struct _rhp_vpn_realm* rlm);
extern int rhp_ipc_send_delete_all_static_routes(struct _rhp_vpn_realm* rlm);


/**************************

  Bridge Handling APIs

***************************/

extern int rhp_netmng_bridge_ctrl(char* bridge_name,char* vif_name,int start_or_end);

extern int rhp_ipc_send_bridge_ctrl(char* bridge_name,char* vif_name,int add_or_delete);


/******************************

  Firewall Rules Handling APIs

*******************************/

extern int rhp_netmng_firewall_rules_apply(char* traffic,char* action,char* interface,char* filter_pos,
		unsigned int arg0_len,u8* arg0,unsigned int arg1_len,u8* arg1);

extern int rhp_netmng_firewall_rules_flush();


/******************************

  IPv6 cfg APIs

*******************************/

extern int rhp_ipc_send_ipv6_cfg(unsigned long vpn_realm_id,unsigned int accept_ra);



/*******************************

  Network I/F Info Cache APIs

********************************/

extern int rhp_ifc_init();
extern int rhp_ifc_cleanup();

struct _rhp_ifc_addr {

  unsigned char tag[4]; // "#NEA"

  struct _rhp_ifc_addr* lst_next;
  struct _rhp_ifc_addr* lst_prev;

  rhp_ip_addr addr;

  unsigned int if_addr_flags; // IFA_F_XXX (include/uapi/linux/if_addr.h)

  int net_sk_ike;    // FD for socket. -1 : Not specified.
  int net_sk_esp;    // FD for socket. -1 : Not specified.
  int net_sk_nat_t;  // FD for socket. -1 : Not specified.

  rhp_epoll_ctx net_sk_epoll_ctx_ike;
  rhp_epoll_ctx net_sk_epoll_ctx_esp;
  rhp_epoll_ctx net_sk_epoll_ctx_nat_t;

  rhp_rt_map_entry def_route_map;
};
typedef struct _rhp_ifc_addr	rhp_ifc_addr;



struct _rhp_ifc_entry {

  unsigned char tag[4]; // "#NWC"

  struct _rhp_ifc_entry* next;

  rhp_mutex_t lock;

  rhp_atomic_t refcnt;
  rhp_atomic_t is_active;

  rhp_atomic_t cfg_users_v4;
  rhp_atomic_t cfg_users_v6;


  char if_name[RHP_IFNAMSIZ];
  u8 mac[6];
  u16 mac_reserved0; // 32b boundary.
  int if_index;
  unsigned int if_flags; // IFF_UP etc...
  unsigned int mtu; // bytes


  int ifc_addrs_num;
  rhp_ifc_addr* ifc_addrs;

  rhp_ifc_addr* (*get_addr)(struct _rhp_ifc_entry* ifc,int addr_family,u8* addr);
  int (*delete_addr)(struct _rhp_ifc_entry* ifc,int addr_family,u8* addr);
  rhp_ifc_addr* (*set_addr)(struct _rhp_ifc_entry* ifc,int addr_family,u8* addr,int prefixlen,u32 ipv6_scope_id);
  int (*enum_addrs)(struct _rhp_ifc_entry* ifc,
  		int (*callback)(struct _rhp_ifc_entry* ifc,rhp_ifc_addr* ifc_addr,void* cb_ctx),void* ctx);

  void (*move_addr_to_top)(struct _rhp_ifc_entry* ifc,rhp_ifc_addr* ifc_addr);

  rhp_ifc_addr* (*select_src_addr)(struct _rhp_ifc_entry* ifc,int addr_family,u8* dst_addr,int def_route);

  int (*update_def_route)(struct _rhp_ifc_entry* ifc,rhp_rt_map_entry* def_route_map);
  int (*clear_def_route)(struct _rhp_ifc_entry* ifc,rhp_rt_map_entry* def_route_map);

  rhp_atomic_flag_t tx_esp_pkt_pend_flag;
  rhp_atomic_flag_t rx_esp_pkt_pend_flag;


  unsigned long tuntap_vpn_realm_id;
  int tuntap_type; // RHP_VIF_TYPE_XXX
  int tuntap_fd; // FD for tuntap device. -1 : Not specified.
  rhp_epoll_ctx tuntap_fd_epoll_ctx;
  int tuntap_addrs_type; // RHP_VIF_ADDR_XXX

  u8 tuntap_deleting;
  u8 tuntap_nhrp_service; // RHP_NHRP_SERVICE_XXX
  u8 tuntap_dmvpn_enabled;
  u8 tuntap_reserved0; // 32b boundary.

  rhp_atomic_flag_t tx_tuntap_pkt_pend_flag;
  rhp_atomic_flag_t rx_tuntap_pkt_pend_flag;

  u8 is_dmy_tuntap;
  u8 mac_reserved1; // 32b boundary.
  u8 tuntap_dmy_peer_mac[6];

  u8 ipip_dummy_mac_flag;
  u8 mac_reserved2; // 32b boundary.
  u8 ipip_dummy_mac[6];


  struct {

#define RHP_V6_LINK_LOCAL_ADDR_INIT					0
#define RHP_V6_LINK_LOCAL_ADDR_DAD_PROBING	1
#define RHP_V6_LINK_LOCAL_ADDR_AVAILABLE		2
#define RHP_V6_LINK_LOCAL_ADDR_ERR					3
		int state;

		rhp_ip_addr lladdr;
		u8 lladdr_sol_node_mc[16]; // Solicited Node Multicast address for lladdr.
		u8 mac[6];
	  u16 mac_reserved3; // 32b boundary.

		int fixed_lladdr;
		int gen_retries;
		void* ctx; // rhp_v6_rlm_lladdr_ctx (rhp_ipv6_neigh.c)

  } v6_aux_lladdr;


  union {

  	struct {

  		u64 read_pkts;
			u64 read_arp_pkts;
			u64 read_ipv4_pkts;
			u64 read_ipv4_icmp_pkts;
			u64 read_ipv4_tcp_pkts;
			u64 read_ipv4_udp_pkts;
			u64 read_ipv4_other_pkts;
			u64 read_ipv6_pkts;
			u64 read_ipv6_icmp_pkts;
			u64 read_ipv6_tcp_pkts;
			u64 read_ipv6_udp_pkts;
			u64 read_ipv6_other_pkts;
			u64 read_other_pkts;
			u64 read_err_pkts;
			u64 read_err_arp_pkts;
			u64 read_err_ipv4_pkts;
			u64 read_err_ipv4_icmp_pkts;
			u64 read_err_ipv4_tcp_pkts;
			u64 read_err_ipv4_udp_pkts;
			u64 read_err_ipv4_other_pkts;
			u64 read_err_ipv6_pkts;
			u64 read_err_ipv6_icmp_pkts;
			u64 read_err_ipv6_tcp_pkts;
			u64 read_err_ipv6_udp_pkts;
			u64 read_err_ipv6_other_pkts;
			u64 read_err_other_pkts;
			u64 read_bytes;

			u64 read_stop;
			u64 read_restart;

			u64 write_pkts;
			u64 write_arp_pkts;
			u64 write_ipv4_pkts;
			u64 write_ipv4_icmp_pkts;
			u64 write_ipv4_tcp_pkts;
			u64 write_ipv4_udp_pkts;
			u64 write_ipv4_other_pkts;
			u64 write_ipv6_pkts;
			u64 write_ipv6_icmp_pkts;
			u64 write_ipv6_tcp_pkts;
			u64 write_ipv6_udp_pkts;
			u64 write_ipv6_other_pkts;
			u64 write_other_pkts;
			u64 write_err_pkts;
			u64 write_err_arp_pkts;
			u64 write_err_ipv4_pkts;
			u64 write_err_ipv4_icmp_pkts;
			u64 write_err_ipv4_tcp_pkts;
			u64 write_err_ipv4_udp_pkts;
			u64 write_err_ipv4_other_pkts;
			u64 write_err_ipv6_pkts;
			u64 write_err_ipv6_icmp_pkts;
			u64 write_err_ipv6_tcp_pkts;
			u64 write_err_ipv6_udp_pkts;
			u64 write_err_ipv6_other_pkts;
			u64 write_err_other_pkts;
			u64 write_bytes;

			u64 drop_icmpv6_router_adv;
			u64 drop_icmpv6_router_solicit;

			u64 bridge_rx_from_tuntap;

  	} tuntap;

  	struct {
  		u64 rx_pkts;
			u64 rx_err_pkts;
			u64 rx_trunc_err_pkts;
			u64 rx_invalid_pkts;
			u64 rx_bytes;
			u64 rx_ikev2_pkts;
			u64 rx_ikev2_nat_t_pkts;
			u64 rx_esp_nat_t_pkts;
			u64 rx_esp_pkts;
			u64 rx_ikev2_err_pkts;
			u64 rx_ikev2_nat_t_err_pkts;
			u64 rx_esp_nat_t_err_pkts;
			u64 rx_esp_err_pkts;
			u64 rx_ikev2_invalid_pkts;
			u64 rx_ikev2_nat_t_invalid_pkts;
			u64 rx_esp_nat_t_invalid_pkts;
			u64 rx_esp_invalid_pkts;
			u64 rx_ikev2_sk_trunc_err_pkts;
			u64 rx_nat_t_sk_trunc_err_pkts;
			u64 rx_esp_raw_sk_trunc_err_pkts;
			u64 rx_ikev2_too_large_pkts;
			u64 rx_ikev2_nat_t_too_large_pkts;
			u64 rx_ikev2_bytes;
			u64 rx_ikev2_nat_t_bytes;
			u64 rx_esp_nat_t_bytes;
			u64 rx_esp_bytes;

			u64 rx_stop;
			u64 rx_restart;
			u64 rx_net_events;
			u64 rx_net_err_events;

			u64 tx_pkts;
			u64 tx_ikev2_pkts;
			u64 tx_ikev2_nat_t_pkts;
			u64 tx_esp_nat_t_pkts;
			u64 tx_esp_pkts;
			u64 tx_err_pkts;
			u64 tx_ikev2_err_pkts;
			u64 tx_ikev2_nat_t_err_pkts;
			u64 tx_esp_nat_t_err_pkts;
			u64 tx_esp_err_pkts;
			u64 tx_bytes;
			u64 tx_ikev2_bytes;
			u64 tx_ikev2_nat_t_bytes;
			u64 tx_esp_nat_t_bytes;
			u64 tx_esp_bytes;

			u64 rx_nat_t_keep_alive_pkts;
			u64 tx_nat_t_keep_alive_pkts;
  	} netif;

  	u8 raw;

  } statistics;

  void (*dump_lock)(char* label,struct _rhp_ifc_entry* ifc);

  // ifc->lock must be acquired by caller.
  void (*dump_no_lock)(char* label,struct _rhp_ifc_entry* ifc);
};
typedef struct _rhp_ifc_entry  rhp_ifc_entry;

extern rhp_mutex_t rhp_ifc_lock;


struct _rhp_ifc_notifier {

#define RHP_IFC_EVT_DESTROY					0
#define RHP_IFC_EVT_UPDATE_IF				1
#define RHP_IFC_EVT_UPDATE_ADDR   	2
#define RHP_IFC_EVT_DELETE_IF				3
#define RHP_IFC_EVT_DELETE_ADDR			4
  void (*callback)(int event,rhp_ifc_entry* ifc,rhp_if_entry* new_info,rhp_if_entry* old,void* ctx);
  void* ctx;
};
typedef struct _rhp_ifc_notifier  rhp_ifc_notifier;

#define RHP_IFC_NOTIFIER_CFG  			0
#define RHP_IFC_NOTIFIER_TUNTAP  		1
#define RHP_IFC_NOTIFIER_MOBIKE  		2
#define RHP_IFC_NOTIFIER_ITNL_NET  	3
#define RHP_IFC_NOTIFIER_MAX  			3
extern rhp_ifc_notifier  rhp_ifc_notifiers[RHP_IFC_NOTIFIER_MAX + 1];

extern void rhp_ifc_call_notifiers(int event/*RHP_IFC_EVT_XXX*/,rhp_ifc_entry* ifc,
		rhp_if_entry* new_info,rhp_if_entry* old);

extern rhp_ifc_entry* rhp_ifc_alloc();
extern void rhp_ifc_put(rhp_ifc_entry* ifc);
extern rhp_ifc_entry* rhp_ifc_get(char* if_name);
extern rhp_ifc_entry* rhp_ifc_get_by_if_idx(int if_index);
extern void rhp_ifc_delete(rhp_ifc_entry* ifc);
extern rhp_ifc_entry* rhp_ifc_dmy_vif_get();

extern int rhp_ifc_enum(int (*callback)(rhp_ifc_entry* ifc,void* ctx),void* ctx);


extern void rhp_ifc_hold(rhp_ifc_entry* ifc);
extern void rhp_ifc_unhold(rhp_ifc_entry* ifc);

extern int rhp_ifc_is_active(rhp_ifc_entry* ifc,int addr_family,u8* addr);
extern int rhp_ifc_is_active_ifc_addr(rhp_ifc_entry* ifc,rhp_ifc_addr* ifc_addr);
extern int rhp_ifc_is_active_peer_addr(rhp_ifc_entry* ifc,rhp_ip_addr* peer_addr);
extern int rhp_ifc_addr_is_active(rhp_ifc_entry* ifc,rhp_ifc_addr* ifc_addr);


extern int rhp_ifc_is_my_ip_v4(u32 ip);
extern int rhp_ifc_is_my_ip_v6(u8* ip);
extern void rhp_ifc_my_ip_update(rhp_if_entry* ifent_old,rhp_if_entry* ifent_new);
extern void rhp_ifc_my_ip_clear(rhp_if_entry* ifent);

extern int rhp_ifc_copy_to_if_entry(rhp_ifc_entry* ifc,rhp_if_entry* if_info_r,int addr_family,u8* addr);
extern int rhp_ifc_copy_if_info(rhp_if_entry* if_info,rhp_ifc_entry* ifc);
extern int rhp_ifc_copy_if_info2(rhp_ifc_entry* ifc_from,rhp_if_entry* if_info_to);

extern int rhp_ifc_entry_cmp(rhp_ifc_entry* ifc,rhp_if_entry* if_info);

#ifndef RHP_REFCNT_DEBUG

static inline void rhp_ifc_cfg_users_inc(rhp_ifc_entry* ifc,int addr_family)
{
	if( addr_family == AF_INET ){
		_rhp_atomic_inc(&(ifc->cfg_users_v4));
  }else if( addr_family == AF_INET6 ){
    _rhp_atomic_inc(&(ifc->cfg_users_v6));
  }
}

static inline void rhp_ifc_cfg_users_dec(rhp_ifc_entry* ifc,int addr_family)
{
	if( addr_family == AF_INET ){
		_rhp_atomic_dec(&(ifc->cfg_users_v4));
  }else if( addr_family == AF_INET6 ){
    _rhp_atomic_dec(&(ifc->cfg_users_v6));
  }
}

static inline long rhp_ifc_cfg_users(rhp_ifc_entry* ifc,int addr_family)
{
	if( addr_family == AF_INET ){
		return _rhp_atomic_read(&(ifc->cfg_users_v4));
  }else if( addr_family == AF_INET6 ){
  	return _rhp_atomic_read(&(ifc->cfg_users_v6));
  }
	return 0;
}

#else // RHP_REFCNT_DEBUG

#define rhp_ifc_cfg_users_inc(ifc,addr_family)\
{\
	if( addr_family == AF_INET ){\
		RHP_LINE("#RHP_IFC_CFG_USERS_INC_V4 0x%x:ifc->cfg_users_v4.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",(ifc),(ifc)->cfg_users_v4.c,rhp_func_trc_current());\
		_rhp_atomic_inc(&((ifc)->cfg_users_v4));\
  }else if( addr_family == AF_INET6 ){\
  	RHP_LINE("#RHP_IFC_CFG_USERS_INC_V6 0x%x:ifc->cfg_users_v6.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",(ifc),(ifc)->cfg_users_v6.c,rhp_func_trc_current());\
    _rhp_atomic_inc(&((ifc)->cfg_users_v6));\
  }\
}
#define rhp_ifc_cfg_users_dec(ifc,addr_family)\
{\
	if( addr_family == AF_INET ){\
		RHP_LINE("#RHP_IFC_CFG_USERS_DEC_V4 0x%x:ifc->cfg_users_v4.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",(ifc),(ifc)->cfg_users_v4.c,rhp_func_trc_current());\
		_rhp_atomic_dec(&((ifc)->cfg_users_v4));\
  }else if( addr_family == AF_INET6 ){\
  	RHP_LINE("#RHP_IFC_CFG_USERS_DEC_V6 0x%x:ifc->cfg_users_v6.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",(ifc),(ifc)->cfg_users_v6.c,rhp_func_trc_current());\
    _rhp_atomic_dec(&((ifc)->cfg_users_v6));\
  }\
}
#define rhp_ifc_cfg_users(ifc,addr_family)\
({\
	long __ret__;\
	if( addr_family == AF_INET ){\
		RHP_LINE("#RHP_IFC_CFG_USERS_V4 0x%x:ifc->cfg_users_v4.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",(ifc),(ifc)->cfg_users_v4.c,rhp_func_trc_current());\
		__ret__ = _rhp_atomic_read(&((ifc)->cfg_users_v4));\
  }else if( addr_family == AF_INET6 ){\
  	RHP_LINE("#RHP_IFC_CFG_USERS_V6 0x%x:ifc->cfg_users_v6.c[%d] ##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##",(ifc),(ifc)->cfg_users_v6.c,rhp_func_trc_current());\
		__ret__ = _rhp_atomic_read(&((ifc)->cfg_users_v6));\
  }\
	__ret__;\
})
#endif // RHP_REFCNT_DEBUG



/*******************************

  Network Route Map Cache APIs

********************************/

struct _rhp_rtmapc_entry {

  unsigned char tag[4]; // "#NWR"

  struct _rhp_rtmapc_entry* next;

  rhp_mutex_t lock;

  rhp_atomic_t refcnt;
  rhp_atomic_t is_active;

  rhp_rt_map_entry info;

  void (*dump)(char* label,struct _rhp_rtmapc_entry* rtmapc);
};
typedef struct _rhp_rtmapc_entry rhp_rtmapc_entry;


extern rhp_mutex_t rhp_rtmapc_lock;

struct _rhp_rtmapc_notifier {

#define RHP_RTMAPC_EVT_DESTROY			0
#define RHP_RTMAPC_EVT_UPDATED			1
#define RHP_RTMAPC_EVT_DELETED			2
  void (*callback)(int event,rhp_rtmapc_entry* rtmapc,rhp_rt_map_entry* old,void* ctx);
  void* ctx;
};
typedef struct _rhp_rtmapc_notifier  rhp_rtmapc_notifier;

#define RHP_RTMAPC_NOTIFIER_CFG  				0
#define RHP_RTMAPC_NOTIFIER_IP_ROUTING  1
#define RHP_RTMAPC_NOTIFIER_MAX  				2
extern rhp_rtmapc_notifier  rhp_rtmapc_notifiers[RHP_RTMAPC_NOTIFIER_MAX+1];

extern void rhp_rtmapc_call_notifiers(int event/*RHP_IFC_EVT_XXX*/,rhp_rtmapc_entry* rtmapc,rhp_rt_map_entry* old);

extern rhp_rtmapc_entry* rhp_rtmapc_alloc();
extern void rhp_rtmapc_put(rhp_rtmapc_entry* rtmapc);
extern void rhp_rtmapc_delete(rhp_rtmapc_entry* rtmapc);
extern rhp_rtmapc_entry* rhp_rtmapc_get(rhp_rt_map_entry* rtmap_ent);

extern int rhp_rtmapc_enum(int (*callback)(rhp_rtmapc_entry* rtmapc,void* ctx),void* ctx);


extern void rhp_rtmapc_hold(rhp_rtmapc_entry* rtmapc);
extern void rhp_rtmapc_unhold(rhp_rtmapc_entry* rtmapc);


/**************************

  Socket API wrappers

***************************/

extern ssize_t rhp_send(int sk,const void *buf, size_t len, int flags);
extern ssize_t rhp_recvmsg(int sk, struct msghdr *msg, int flags,int wait_flag);

#endif // _RHP_NETMNG_H_

