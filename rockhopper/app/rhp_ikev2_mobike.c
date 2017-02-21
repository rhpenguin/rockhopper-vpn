/*

	Copyright (C) 2009-2013 TETSUHARU HANADA <rhpenguine@gmail.com>
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
#include "rhp_ikev2_mesg.h"
#include "rhp_vpn.h"
#include "rhp_ikev2.h"
#include "rhp_http.h"
#include "rhp_nhrp.h"

static rhp_mutex_t _rhp_ikev2_mobike_lock;


#define RHP_IKEV2_MOBIKE_RT_CK_MIN_INTERVAL_MSEC	20

struct _rhp_mobike_srch_plds_ctx {

	int dup_flag;

	rhp_vpn* vpn;
	rhp_ikesa* ikesa;

	int peer_enabled;

#define RHP_IKEV2_MOBIKE_MAX_ADDITIONAL_ADDRS		64
	int additional_addrs_num;
	rhp_ip_addr_list* additional_addrs_head;
	rhp_ip_addr_list* additional_addrs_tail;

	int no_additional_addrs;

	int rx_update_sa_address;

	int rx_cookie2_len;
	u8 rx_cookie2[RHP_PROTO_IKE_NOTIFY_COOKIE2_MAX_SZ];

	int nat_t_notify_found;

  u16 notify_error;
  unsigned long notify_error_arg;
};
typedef struct _rhp_mobike_srch_plds_ctx		rhp_mobike_srch_plds_ctx;




int rhp_ikev2_mobike_pending(rhp_vpn* vpn)
{
	int ret = 0;

	if( vpn->exec_mobike &&
			((vpn->origin_side == RHP_IKE_INITIATOR && vpn->mobike.init.rt_ck_pending) ||
			 (vpn->origin_side == RHP_IKE_RESPONDER && vpn->mobike.resp.rt_ck_pending)) ){
		ret = 1;
	}

  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_PENDING,"xLdddd",vpn,"IKE_SIDE",vpn->origin_side,vpn->exec_mobike,(vpn->origin_side == RHP_IKE_RESPONDER ? vpn->mobike.resp.rt_ck_pending : vpn->mobike.init.rt_ck_pending),ret);
	return ret;
}

int rhp_ikev2_mobike_ka_pending(rhp_vpn* vpn)
{
	int ret = 0;

	if( vpn->exec_mobike &&
			vpn->origin_side == RHP_IKE_RESPONDER &&
			vpn->mobike.resp.keepalive_pending ){
		ret = 1;
	}

  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_KA_PENDING,"xLddd",vpn,"IKE_SIDE",vpn->origin_side,vpn->exec_mobike,ret);
	return ret;
}


static rhp_ikesa* _rhp_ikev2_mobike_get_active_ikesa(rhp_vpn* vpn)
{
	rhp_ikesa* ikesa = vpn->ikesa_list_head;
	while( ikesa ){

		if( ikesa->state == RHP_IKESA_STAT_ESTABLISHED ||
				ikesa->state == RHP_IKESA_STAT_REKEYING ){
			break;
		}

		ikesa = ikesa->next_vpn_list;
	}

	if( ikesa ){
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_GET_ACTIVE_IKESA,"xx",vpn,ikesa);
		ikesa->dump(ikesa);
	}else{
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_GET_ACTIVE_IKESA_NO_IKESA,"xx",vpn,ikesa);
	}

	return ikesa;
}

static int _rhp_ikev2_new_pkt_mobike_error_notify(rhp_vpn* vpn,
		rhp_ikesa* ikesa,rhp_ikev2_mesg* tx_ikemesg,
		u8 exchaneg_type,u32 message_id,u16 notify_mesg_type,unsigned long arg0)
{
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_ERROR_NOTIFY,"xxxdbwx",vpn,ikesa,tx_ikemesg,message_id,exchaneg_type,notify_mesg_type,arg0);

  if( exchaneg_type ){
	  tx_ikemesg->set_exchange_type(tx_ikemesg,exchaneg_type);
	  tx_ikemesg->set_mesg_id(tx_ikemesg,message_id);
  }

  {
    if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
      RHP_BUG("");
      goto error;
    }

    tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

    ikepayload->ext.n->set_protocol_id(ikepayload,0);
    ikepayload->ext.n->set_message_type(ikepayload,notify_mesg_type);

    switch( notify_mesg_type ){

    case RHP_PROTO_IKE_NOTIFY_ERR_UNACCEPTABLE_ADDRESSES:
    	break;

    case RHP_PROTO_IKE_NOTIFY_ERR_UNEXPECTED_NAT_DETECTED:
    	break;

    default:
    	RHP_BUG("%d",notify_mesg_type);
    	goto error;
    }
  }

 	tx_ikemesg->tx_flag = RHP_IKEV2_SEND_REQ_FLAG_URGENT;

  RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_TX_ERR_NOTIFY,"VPL",vpn,ikesa,"PROTO_IKE_NOTIFY",(int)notify_mesg_type);

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_ERROR_NOTIFY_RTRN,"xxdx",vpn,ikesa,message_id,tx_ikemesg);
  return 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_ERROR_NOTIFY_ERR,"xxd",vpn,ikesa,message_id);
  return -EINVAL;
}


static void _rhp_ikev2_mobike_srch_clear_ctx(rhp_mobike_srch_plds_ctx* s_pld_ctx)
{
	rhp_ip_addr_list* lst = s_pld_ctx->additional_addrs_head, *lst_nxt = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_CLEAR_CTX,"xx",s_pld_ctx,lst);

	while( lst ){
		lst_nxt = lst->next;
		_rhp_free(lst);
		lst = lst_nxt;
	}
}


struct _rhp_mobike_nat_t_srch_plds_ctx {
	rhp_ikev2_payload* dst_nat_payload;
};
typedef struct _rhp_mobike_nat_t_srch_plds_ctx	rhp_mobike_nat_t_srch_plds_ctx;

static int _rhp_ikev2_mobike_nat_t_srch_n_nat_t_cb(
		rhp_ikev2_mesg* rx_ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
	rhp_mobike_nat_t_srch_plds_ctx* s_pld_ctx = (rhp_mobike_nat_t_srch_plds_ctx*)ctx;

  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_NAT_T_SRCH_N_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

  if( s_pld_ctx->dst_nat_payload == NULL ){

  	s_pld_ctx->dst_nat_payload = payload;

  	return RHP_STATUS_ENUM_OK;
  }

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_NAT_T_SRCH_N_CB_RTRN,"xxx",rx_ikemesg,payload,ctx);
 	return 0;
}

static rhp_ikev2_payload* _rhp_ikev2_mobike_get_nat_dest_ip_payload(
		rhp_vpn* vpn,rhp_ikesa* ikesa,int side)
{
	rhp_mobike_nat_t_srch_plds_ctx s_pld_ctx;
	rhp_ikev2_mesg* ikemesg
	= (side == RHP_IKE_INITIATOR ? ikesa->signed_octets.ikemesg_r_2nd : ikesa->signed_octets.ikemesg_i_1st);

	if( ikemesg == NULL ){
		RHP_BUG("");
		return NULL;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_GET_NAT_DEST_IP_PAYLOAD,"xxxxd",vpn,ikesa,ikemesg,ikemesg->rx_pkt,side);

	memset(&s_pld_ctx,0,sizeof(rhp_mobike_nat_t_srch_plds_ctx));

	u16 nat_t_n_ids[2] = { RHP_PROTO_IKE_NOTIFY_ST_NAT_DETECTION_DESTINATION_IP,
												 RHP_PROTO_IKE_NOTIFY_RESERVED};

	ikemesg->search_payloads(ikemesg,1,
			rhp_ikev2_mesg_srch_cond_n_mesg_ids,nat_t_n_ids,
			_rhp_ikev2_mobike_nat_t_srch_n_nat_t_cb,&s_pld_ctx);

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_GET_NAT_DEST_IP_PAYLOAD_RTRN,"xxx",vpn,ikesa,s_pld_ctx.dst_nat_payload);

	return s_pld_ctx.dst_nat_payload;
}

static void _rhp_ikev2_mobike_r_add_addrs_rx_diff_if_or_addr_family(
		int addr_family,
		rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_payload* n_dst_payload,
		rhp_cfg_if* my_if,rhp_ifc_entry* my_ifc,
		int* additional_addrs_num_r,rhp_ip_addr* additional_addrs_r)
{
	int i;
	int mobike_dnat_addrs_num
	= (addr_family == AF_INET ? my_if->mobike_dnat_addrs_num_v4 : my_if->mobike_dnat_addrs_num_v6);
	rhp_ip_addr* mobike_dnat_addr
	= (addr_family == AF_INET ? my_if->mobike_dnat_addr_v4 : my_if->mobike_dnat_addr_v6);

	if( (*additional_addrs_num_r) >= RHP_MOBIKE_R_MAX_ADDITIONAL_ADDRS ){
		return;
	}

	if( mobike_dnat_addrs_num &&
			(!rhp_gcfg_ikev2_mobike_additional_addr_check_dnat ||
			 (n_dst_payload &&
			 (vpn->nat_t_info.behind_a_nat & RHP_IKESA_BEHIND_A_NAT_LOCAL))) ){

		for( i = 0; i < mobike_dnat_addrs_num; i++ ){

			rhp_ip_addr_dump(
					"_rhp_ikev2_mobike_r_add_addrs_rx_diff_if_or_addr_family:dnat",&(mobike_dnat_addr[i]));

			rhp_ip_addr* dst_nat_addr = &(mobike_dnat_addr[i]);

			if( (*additional_addrs_num_r) < RHP_MOBIKE_R_MAX_ADDITIONAL_ADDRS ){

				memcpy(&(additional_addrs_r[*additional_addrs_num_r]),
						dst_nat_addr,sizeof(rhp_ip_addr));

				(*additional_addrs_num_r)++;

				if( dst_nat_addr->addr_family == AF_INET ){
					RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_TX_ADDITIONAL_IPV4_ADDR_NOTIFY_DST_NAT_ADDR,"VPd4",vpn,ikesa,my_ifc->if_index,dst_nat_addr->addr.v4);
				}else if( dst_nat_addr->addr_family == AF_INET6 ){
					RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_TX_ADDITIONAL_IPV6_ADDR_NOTIFY_DST_NAT_ADDR,"VPd6",vpn,ikesa,my_ifc->if_index,dst_nat_addr->addr.v6);
				}
			}

			if( (*additional_addrs_num_r) >= RHP_MOBIKE_R_MAX_ADDITIONAL_ADDRS ){
				break;
			}
		}

	}else{

		rhp_ifc_addr* ifc_addr = my_ifc->ifc_addrs;

		while( ifc_addr ){

			rhp_ip_addr cand_addr;

			memset(&cand_addr,0,sizeof(rhp_ip_addr));
			cand_addr.addr_family = AF_UNSPEC;

			if( addr_family == AF_INET &&
					ifc_addr->addr.addr_family == AF_INET &&
					ifc_addr->addr.addr.v4 ){

				cand_addr.addr_family = AF_INET;
				cand_addr.addr.v4 = ifc_addr->addr.addr.v4;

			}else if( addr_family == AF_INET6 &&
								ifc_addr->addr.addr_family == AF_INET6 &&
								!rhp_ipv6_addr_null(ifc_addr->addr.addr.v6) &&
								!rhp_ipv6_is_linklocal(ifc_addr->addr.addr.v6) ){

				cand_addr.addr_family = AF_INET6;
				memcpy(cand_addr.addr.v6,ifc_addr->addr.addr.v6,16);
			}

			rhp_ip_addr_dump("_rhp_ikev2_mobike_r_add_addrs_rx_diff_if_or_addr_family",&cand_addr);

			if( cand_addr.addr_family != AF_UNSPEC ){

				if( (*additional_addrs_num_r) < RHP_MOBIKE_R_MAX_ADDITIONAL_ADDRS ){

					memcpy(&(additional_addrs_r[*additional_addrs_num_r]),
							&cand_addr,sizeof(rhp_ip_addr));

					(*additional_addrs_num_r)++;

					if( cand_addr.addr_family == AF_INET ){
						RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_TX_ADDITIONAL_IPV4_ADDR_NOTIFY,"VPd4",vpn,ikesa,my_ifc->if_index,cand_addr.addr.v4);
					}else if( cand_addr.addr_family == AF_INET6 ){
						RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_TX_ADDITIONAL_IPV6_ADDR_NOTIFY,"VPd6",vpn,ikesa,my_ifc->if_index,cand_addr.addr.v6);
					}
				}
			}

			if( (*additional_addrs_num_r) >= RHP_MOBIKE_R_MAX_ADDITIONAL_ADDRS ){
				break;
			}

			ifc_addr = ifc_addr->lst_next;
		}
	}

	return;
}

static void _rhp_ikev2_mobike_r_add_addrs_rx_same_if(
		int addr_family,
		rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_ikemesg,rhp_ikev2_payload* n_dst_payload,
		rhp_cfg_if* my_if,rhp_ifc_entry* my_ifc,
		int* additional_addrs_num_r,rhp_ip_addr* additional_addrs_r)
{
	int i;
	int err = -EINVAL;
	int mobike_dnat_addrs_num
	= (addr_family == AF_INET ? my_if->mobike_dnat_addrs_num_v4 : my_if->mobike_dnat_addrs_num_v6);
	rhp_ip_addr* mobike_dnat_addr
	= (addr_family == AF_INET ? my_if->mobike_dnat_addr_v4 : my_if->mobike_dnat_addr_v6);

	if( (*additional_addrs_num_r) >= RHP_MOBIKE_R_MAX_ADDITIONAL_ADDRS ){
		return;
	}

	if( mobike_dnat_addrs_num &&
			n_dst_payload &&
			(!rhp_gcfg_ikev2_mobike_additional_addr_check_dnat ||
			 (vpn->nat_t_info.behind_a_nat & RHP_IKESA_BEHIND_A_NAT_LOCAL)) ){

		if( rx_ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE ){
			RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_R_ADD_ADDRS_IF_DST_NAT,"xxxs4",vpn,ikesa,my_if,my_if->if_name,rx_ikemesg->rx_pkt->l3.iph_v4->dst_addr);
		}else if( rx_ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE ){
			RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_R_ADD_ADDRS_IF_DST_NAT_V6,"xxxs6",vpn,ikesa,my_if,my_if->if_name,rx_ikemesg->rx_pkt->l3.iph_v6->dst_addr);
		}

		for( i = 0; i < mobike_dnat_addrs_num; i++ ){

			rhp_ip_addr_dump(
					"_rhp_ikev2_mobike_r_add_addrs_rx_same_if:dnat",&(mobike_dnat_addr[i]));

			if( (addr_family == AF_INET && rx_ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE) ||
					(addr_family == AF_INET6 && rx_ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE) ){

				int addr_len = (addr_family == AF_INET) ? 4 : 16;

				err = rhp_ikev2_nat_t_dst_check(vpn,ikesa,n_dst_payload,
								addr_len,mobike_dnat_addr[i].addr.raw);

			}else{

				err = RHP_STATUS_BEHIND_A_NAT;
			}

			if( err == RHP_STATUS_BEHIND_A_NAT ){

				if( (*additional_addrs_num_r) < RHP_MOBIKE_DST_NAT_ADDRS_NUM ){

					memcpy(&(additional_addrs_r[(*additional_addrs_num_r)]),
							&(mobike_dnat_addr[i]),sizeof(rhp_ip_addr));

					(*additional_addrs_num_r)++;

					if( mobike_dnat_addr[i].addr_family == AF_INET ){
						RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_TX_ADDITIONAL_IPV4_ADDR_NOTIFY_DST_NAT_ADDR_2,"VPd4",vpn,ikesa,my_ifc->if_index,mobike_dnat_addr[i].addr.v4);
					}else if( mobike_dnat_addr[i].addr_family == AF_INET6 ){
						RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_TX_ADDITIONAL_IPV6_ADDR_NOTIFY_DST_NAT_ADDR_2,"VPd6",vpn,ikesa,my_ifc->if_index,mobike_dnat_addr[i].addr.v6);
					}
				}

			}else if( !err ){

				//
				// Remote peer's destination addr is this DstNat mapped addr on NAT Gw.
				//
				if( mobike_dnat_addr[i].addr_family == AF_INET ){
					RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_TX_ADDITIONAL_IPV4_ADDR_NOTIFY_DST_NAT_ADDR_IGNORED,"VPd4",vpn,ikesa,my_ifc->if_index,mobike_dnat_addr[i].addr.v4);
				}else if( mobike_dnat_addr[i].addr_family == AF_INET6 ){
					RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_TX_ADDITIONAL_IPV6_ADDR_NOTIFY_DST_NAT_ADDR_IGNORED,"VPd6",vpn,ikesa,my_ifc->if_index,mobike_dnat_addr[i].addr.v6);
				}

			}else{

				if( mobike_dnat_addr[i].addr_family == AF_INET ){
					RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_TX_ADDITIONAL_IPV4_ADDR_NOTIFY_DST_NAT_ADDR_CHECK_ERR,"VPd4",vpn,ikesa,my_ifc->if_index,mobike_dnat_addr[i].addr.v4);
				}else if( mobike_dnat_addr[i].addr_family == AF_INET6 ){
					RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_TX_ADDITIONAL_IPV6_ADDR_NOTIFY_DST_NAT_ADDR_CHECK_ERR,"VPd6",vpn,ikesa,my_ifc->if_index,mobike_dnat_addr[i].addr.v6);
				}
			}

			if( (*additional_addrs_num_r) >= RHP_MOBIKE_R_MAX_ADDITIONAL_ADDRS ){
				break;
			}
		}

	}else{

		rhp_ifc_addr* ifc_addr = my_ifc->ifc_addrs;

		while( ifc_addr ){

			rhp_ip_addr cand_addr;
			int dst_diff = 0;

			cand_addr.addr_family = vpn->local.if_info.addr_family;

			if( addr_family == AF_INET &&
					ifc_addr->addr.addr_family == AF_INET &&
					rx_ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE &&
					ifc_addr->addr.addr.v4 ){

				cand_addr.addr.v4 = ifc_addr->addr.addr.v4;

				if( ifc_addr->addr.addr.v4 != rx_ikemesg->rx_pkt->l3.iph_v4->dst_addr ){

					dst_diff = 1;
				}

			}else if( addr_family == AF_INET6 &&
								ifc_addr->addr.addr_family == AF_INET6 &&
								rx_ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE &&
								!rhp_ipv6_addr_null(ifc_addr->addr.addr.v6) ){

				memcpy(cand_addr.addr.v6,ifc_addr->addr.addr.v6,16);

				if( !rhp_ipv6_is_same_addr(ifc_addr->addr.addr.v6,
							rx_ikemesg->rx_pkt->l3.iph_v6->dst_addr) &&
						!rhp_ipv6_is_linklocal(ifc_addr->addr.addr.v6) ){

					dst_diff = 1;
				}
			}


			if( dst_diff &&
					(*additional_addrs_num_r) < RHP_MOBIKE_DST_NAT_ADDRS_NUM ){

				additional_addrs_r[(*additional_addrs_num_r)].addr_family
				= cand_addr.addr_family;

				memcpy(additional_addrs_r[(*additional_addrs_num_r)].addr.raw,
						cand_addr.addr.raw,16);

				(*additional_addrs_num_r)++;

				rhp_ip_addr_dump(
						"_rhp_ikev2_mobike_r_add_addrs_rx_same_if",&cand_addr);

				if( cand_addr.addr_family == AF_INET ){
					RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_TX_ADDITIONAL_IPV4_ADDR_NOTIFY,"VPd4",vpn,ikesa,my_ifc->if_index,cand_addr.addr.v4);
				}else if( cand_addr.addr_family == AF_INET6 ){
					RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_TX_ADDITIONAL_IPV6_ADDR_NOTIFY,"VPd6",vpn,ikesa,my_ifc->if_index,cand_addr.addr.v6);
				}
			}

			if( (*additional_addrs_num_r) >= RHP_MOBIKE_R_MAX_ADDITIONAL_ADDRS ){
				break;
			}

			ifc_addr = ifc_addr->lst_next;
		}
	}

	return;
}


static int _rhp_ikev2_new_pkt_mobike_r_add_addrs(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_vpn_realm* rlm,rhp_ikev2_mesg* tx_ikemesg,rhp_ikev2_mesg* rx_ikemesg)
{
  int err = -EINVAL;
  rhp_cfg_if* my_if;
	rhp_ikev2_payload* n_dst_payload;
	int a, an = 0;
	int additional_addrs_num = 0;
	rhp_ip_addr additional_addrs[RHP_MOBIKE_R_MAX_ADDITIONAL_ADDRS];

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_R_ADD_ADDRS,"xxxxxx",vpn,ikesa,rlm,tx_ikemesg,rx_ikemesg,rx_ikemesg->rx_pkt->rx_ifc);

	memset(additional_addrs,0,sizeof(rhp_ip_addr)*RHP_MOBIKE_R_MAX_ADDITIONAL_ADDRS);

  n_dst_payload = _rhp_ikev2_mobike_get_nat_dest_ip_payload(vpn,ikesa,RHP_IKE_RESPONDER);

  my_if = rlm->my_interfaces;
  while( my_if ){

    rhp_ifc_entry *my_ifc = NULL;

  	if( !my_if->advertising ){
  	  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_R_ADD_ADDRS_NOT_ADVERTISING,"xxxs",vpn,ikesa,my_if,my_if->if_name);
			goto next;
  	}

  	my_ifc = my_if->ifc;
 		if( my_ifc == NULL ){
  	  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_R_ADD_ADDRS_IFC_NULL,"xxxs",vpn,ikesa,my_if,my_if->if_name);
 			goto next;
 		}

		RHP_LOCK(&(my_ifc->lock));

		if( !_rhp_atomic_read(&(my_ifc->is_active)) ){
  	  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_R_ADD_ADDRS_IFC_NOT_ACTIVE,"xxxs",vpn,ikesa,my_if,my_if->if_name);
			goto next_l;
		}

		if( my_ifc != rx_ikemesg->rx_pkt->rx_ifc ){

			_rhp_ikev2_mobike_r_add_addrs_rx_diff_if_or_addr_family(AF_INET,vpn,ikesa,n_dst_payload,
					my_if,my_ifc,&additional_addrs_num,additional_addrs);

			_rhp_ikev2_mobike_r_add_addrs_rx_diff_if_or_addr_family(AF_INET6,vpn,ikesa,n_dst_payload,
					my_if,my_ifc,&additional_addrs_num,additional_addrs);

		}else{

			if( rx_ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE ){

				_rhp_ikev2_mobike_r_add_addrs_rx_same_if(AF_INET,vpn,ikesa,
						rx_ikemesg,n_dst_payload,my_if,my_ifc,
						&additional_addrs_num,additional_addrs);

				_rhp_ikev2_mobike_r_add_addrs_rx_diff_if_or_addr_family(AF_INET6,vpn,ikesa,n_dst_payload,
						my_if,my_ifc,&additional_addrs_num,additional_addrs);

			}else if( rx_ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE ){

				_rhp_ikev2_mobike_r_add_addrs_rx_same_if(AF_INET6,vpn,ikesa,
						rx_ikemesg,n_dst_payload,my_if,my_ifc,
						&additional_addrs_num,additional_addrs);

				_rhp_ikev2_mobike_r_add_addrs_rx_diff_if_or_addr_family(AF_INET,vpn,ikesa,n_dst_payload,
						my_if,my_ifc,&additional_addrs_num,additional_addrs);
			}
		}

next_l:
		RHP_UNLOCK(&(my_ifc->lock));
next:
		my_if = my_if->next;
  }


	for( a = 0; a < additional_addrs_num && an <= RHP_MOBIKE_R_MAX_ADDITIONAL_ADDRS; a++ ){

		rhp_ikev2_payload* ikepayload = NULL;

		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);

		if( additional_addrs[a].addr_family == AF_INET ){

			ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_ADDITIONAL_IP4_ADDRESS);

			if( ikepayload->ext.n->set_data(ikepayload,4,(u8*)&(additional_addrs[a].addr.v4)) ){
				RHP_BUG("");
				goto error;
			}

		}else if( additional_addrs[a].addr_family == AF_INET6 ){

			ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_ADDITIONAL_IP6_ADDRESS);

			if( ikepayload->ext.n->set_data(ikepayload,16,additional_addrs[a].addr.v6) ){
				RHP_BUG("");
				goto error;
			}

		}else{

			RHP_BUG("%d",additional_addrs[a].addr_family);
		}

		an++;
	}

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_R_ADD_ADDRS_RTRN,"xxxxx",vpn,ikesa,rlm,tx_ikemesg,rx_ikemesg);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_R_ADD_ADDRS_ERR,"xxxxxE",vpn,ikesa,rlm,tx_ikemesg,rx_ikemesg,err);
	return err;
}


static int _rhp_ikev2_new_pkt_mobike_r_ike_auth_rep(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_vpn_realm* rlm,
		rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err = -EINVAL;
	rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_R_IKE_AUTH_REP,"xxxxx",vpn,ikesa,rlm,rx_req_ikemesg,tx_resp_ikemesg);

	{
	 	err = rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload);
	 	if( err ){
	 		RHP_BUG("");
	    goto error;
	 	}

	 	tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

	 	ikepayload->ext.n->set_protocol_id(ikepayload,0);

	 	ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_MOBIKE_SUPPORTED);
  }

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_TX_SUPPORTED_NOTIFY,"VP",vpn,ikesa);


	err = _rhp_ikev2_new_pkt_mobike_r_add_addrs(vpn,ikesa,rlm,tx_resp_ikemesg,rx_req_ikemesg);
	if( err ){
	  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_R_IKE_AUTH_REP_ADD_ADDRS_ERR,"xxxxxE",vpn,ikesa,rlm,rx_req_ikemesg,tx_resp_ikemesg,err);
		goto error;
	}

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_R_IKE_AUTH_REP_RTRN,"xxxxx",vpn,ikesa,rlm,rx_req_ikemesg,tx_resp_ikemesg);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_R_IKE_AUTH_REP_ERR,"xxxxxE",vpn,ikesa,rlm,rx_req_ikemesg,tx_resp_ikemesg,err);
	return err;
}

static int _rhp_ikev2_new_pkt_mobike_i_ike_auth(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err = -EINVAL;
	rhp_vpn_realm* rlm = NULL;
	rhp_ikev2_payload* ikepayload = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_I_IKE_AUTH,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);

  rlm = vpn->rlm;
  if( rlm == NULL ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  {
		RHP_LOCK(&(rlm->lock));

		if( !_rhp_atomic_read(&(rlm->is_active)) ){
			err = -EINVAL;
			RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_I_IKE_AUTH_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
			goto error_l;
		}

		if( !rlm->mobike.enabled || vpn->mobike_disabled ){
			err = 0;
			RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_I_IKE_AUTH_MOBIKE_DISALBED,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
			RHP_UNLOCK(&(rlm->lock));
			goto ignored;
		}

		RHP_UNLOCK(&(rlm->lock));
  }

	{
	 	err = rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload);
	 	if( err ){
	     RHP_BUG("");
	     goto error;
	 	}

	 	tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

	 	ikepayload->ext.n->set_protocol_id(ikepayload,0);

	 	ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_MOBIKE_SUPPORTED);
  }

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_TX_SUPPORTED_NOTIFY,"VP",vpn,ikesa);

ignored:
	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_I_IKE_AUTH_RTRN,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
	return 0;

error_l:
	if( rlm ){
		RHP_UNLOCK(&(rlm->lock));
	}
error:
	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_I_IKE_AUTH_ERR,"xxxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);
	return err;
}


static int _rhp_ikev2_mobike_srch_n_no_nats_allowed_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,rhp_mobike_srch_plds_ctx* s_pld_ctx)
{
	int err = -EINVAL;
	int addr_len = payload->ext.n->get_data_len(payload);
	u8* addr = payload->ext.n->get_data(payload);

  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_NO_NATS_ALLOWED_CB,"xdxx",rx_ikemesg,enum_end,payload,s_pld_ctx);

	if( addr && addr_len == sizeof(rhp_proto_ike_notify_no_nats_allowed_v4) &&
			rx_ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE ){

		rhp_proto_ike_notify_no_nats_allowed_v4* addr_v4
			= (rhp_proto_ike_notify_no_nats_allowed_v4*)addr;

		if( rx_ikemesg->rx_pkt->l3.iph_v4->src_addr != addr_v4->src_addr ||
				rx_ikemesg->rx_pkt->l3.iph_v4->dst_addr != addr_v4->dst_addr ||
				rx_ikemesg->rx_pkt->l4.udph->src_port != addr_v4->src_port ||
				rx_ikemesg->rx_pkt->l4.udph->dst_port != addr_v4->dst_port ){

		  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_NO_NATS_ALLOWED_CB_NAT_DETECTED_ERR,"x4444WWWW",rx_ikemesg,rx_ikemesg->rx_pkt->l3.iph_v4->src_addr,addr_v4->src_addr,rx_ikemesg->rx_pkt->l3.iph_v4->dst_addr,addr_v4->dst_addr,rx_ikemesg->rx_pkt->l4.udph->src_port,addr_v4->src_port,rx_ikemesg->rx_pkt->l4.udph->dst_port,addr_v4->dst_port);

		  RHP_LOG_E(RHP_LOG_SRC_IKEV2,s_pld_ctx->vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_RX_NO_NATS_ALLOWED_DETECTED,"VPK4444WWWW",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg,rx_ikemesg->rx_pkt->l3.iph_v4->src_addr,addr_v4->src_addr,rx_ikemesg->rx_pkt->l3.iph_v4->dst_addr,addr_v4->dst_addr,rx_ikemesg->rx_pkt->l4.udph->src_port,addr_v4->src_port,rx_ikemesg->rx_pkt->l4.udph->dst_port,addr_v4->dst_port);

			s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_UNEXPECTED_NAT_DETECTED;

			err = RHP_STATUS_IKEV2_MOBIKE_NO_NATS_ALLOWED;
			goto error;
		}

	}else if( addr && addr_len == sizeof(rhp_proto_ike_notify_no_nats_allowed_v6) &&
						rx_ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE ){

		rhp_proto_ike_notify_no_nats_allowed_v6* addr_v6
			= (rhp_proto_ike_notify_no_nats_allowed_v6*)addr;

		if( rhp_gcfg_ipv6_disabled ){
			goto ignore;
		}

		if( !rhp_ipv6_is_same_addr(rx_ikemesg->rx_pkt->l3.iph_v6->src_addr,addr_v6->src_addr) ||
				!rhp_ipv6_is_same_addr(rx_ikemesg->rx_pkt->l3.iph_v6->dst_addr,addr_v6->dst_addr) ||
				rx_ikemesg->rx_pkt->l4.udph->src_port != addr_v6->src_port ||
				rx_ikemesg->rx_pkt->l4.udph->dst_port != addr_v6->dst_port ){

		  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_NO_NATS_ALLOWED_CB_NAT_DETECTED_ERR_V6,"x6666WWWW",rx_ikemesg,rx_ikemesg->rx_pkt->l3.iph_v4->src_addr,addr_v6->src_addr,rx_ikemesg->rx_pkt->l3.iph_v6->dst_addr,addr_v6->dst_addr,rx_ikemesg->rx_pkt->l4.udph->src_port,addr_v6->src_port,rx_ikemesg->rx_pkt->l4.udph->dst_port,addr_v6->dst_port);

		  RHP_LOG_E(RHP_LOG_SRC_IKEV2,s_pld_ctx->vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_RX_NO_NATS_ALLOWED_DETECTED_V6,"VPK6666WWWW",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg,rx_ikemesg->rx_pkt->l3.iph_v4->src_addr,addr_v6->src_addr,rx_ikemesg->rx_pkt->l3.iph_v6->dst_addr,addr_v6->dst_addr,rx_ikemesg->rx_pkt->l4.udph->src_port,addr_v6->src_port,rx_ikemesg->rx_pkt->l4.udph->dst_port,addr_v6->dst_port);

			s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_UNEXPECTED_NAT_DETECTED;

			err = RHP_STATUS_IKEV2_MOBIKE_NO_NATS_ALLOWED;
			goto error;
		}

	}else{

		s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_UNACCEPTABLE_ADDRESSES;

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,s_pld_ctx->vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_RX_INVALID_NO_NATS_ALLOWED_NOTIFY,"VPKd",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg,addr_len);

		err = RHP_STATUS_INVALID_MSG;
		goto error;
	}

ignore:
  RHP_LOG_D(RHP_LOG_SRC_IKEV2,s_pld_ctx->vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_RX_NO_NATS_ALLOWED_NOTIFY,"VP",s_pld_ctx->vpn,s_pld_ctx->ikesa);

  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_NO_NATS_ALLOWED_CB_RTRN,"x",rx_ikemesg);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_NO_NATS_ALLOWED_CB_ERR,"xE",rx_ikemesg,err);
	return err;
}

static int _rhp_ikev2_mobike_srch_n_additional_addrs_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,rhp_mobike_srch_plds_ctx* s_pld_ctx)
{
	int err = -EINVAL;
	u16 notify_mesg_type = payload->ext.n->get_message_type(payload);
	int add_addr_len = payload->ext.n->get_data_len(payload);
	u8* add_addr = payload->ext.n->get_data(payload);
	rhp_ip_addr_list* lst = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_ADDITIONAL_ADDRS_CB,"xdxx",rx_ikemesg,enum_end,payload,s_pld_ctx);

	if( s_pld_ctx->additional_addrs_num > RHP_IKEV2_MOBIKE_MAX_ADDITIONAL_ADDRS ){
		err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_ADDITIONAL_ADDRS_CB_TOO_MANY_ADDRS,"xdd",rx_ikemesg,s_pld_ctx->additional_addrs_num,RHP_IKEV2_MOBIKE_MAX_ADDITIONAL_ADDRS);
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,s_pld_ctx->vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_RX_ADDITIONAL_ADDRS_IGNORED_TOO_MANY,"VPd",s_pld_ctx->vpn,s_pld_ctx->ikesa,s_pld_ctx->additional_addrs_num);
		goto ignore;
	}

	if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_ADDITIONAL_IP4_ADDRESS &&
			add_addr_len == 4 && add_addr ){

		if( rx_ikemesg->rx_pkt->type == RHP_PKT_IPV4_IKE &&
				rx_ikemesg->rx_pkt->l3.iph_v4->src_addr == *((u32*)add_addr) ){
		  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_ADDITIONAL_ADDRS_CB_INFO_SAME_SRC_IP,"x44d",rx_ikemesg,rx_ikemesg->rx_pkt->l3.iph_v4->src_addr,*((u32*)add_addr),s_pld_ctx->additional_addrs_num);
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,s_pld_ctx->vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_RX_ADDITIONAL_ADDRS_IGNORED_SAME_SRC_IP,"VP4d",s_pld_ctx->vpn,s_pld_ctx->ikesa,*((u32*)add_addr),s_pld_ctx->additional_addrs_num);
			goto ignore;
		}

		lst = (rhp_ip_addr_list*)_rhp_malloc(sizeof(rhp_ip_addr_list));
		if( lst == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
		memset(lst,0,sizeof(rhp_ip_addr_list));

		lst->ip_addr.addr_family = AF_INET;
		memcpy(lst->ip_addr.addr.raw,add_addr,4);

	  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_ADDITIONAL_ADDRS_CB_INFO,"x4d",rx_ikemesg,*((u32*)add_addr),s_pld_ctx->additional_addrs_num);

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,s_pld_ctx->vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_RX_ADDITIONAL_ADDRS_NOTIFY,"VP4d",s_pld_ctx->vpn,s_pld_ctx->ikesa,*((u32*)add_addr),s_pld_ctx->additional_addrs_num);

	}else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_ADDITIONAL_IP6_ADDRESS &&
						add_addr_len == 16 && add_addr ){

		if( rhp_gcfg_ipv6_disabled ){
			goto ignore;
		}

		if( rx_ikemesg->rx_pkt->type == RHP_PKT_IPV6_IKE &&
				rhp_ipv6_is_same_addr(rx_ikemesg->rx_pkt->l3.iph_v6->src_addr,add_addr) ){
		  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_ADDITIONAL_ADDRS_CB_INFO_SAME_SRC_IP_V6,"x66d",rx_ikemesg,rx_ikemesg->rx_pkt->l3.iph_v6->src_addr,add_addr,s_pld_ctx->additional_addrs_num);
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,s_pld_ctx->vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_RX_ADDITIONAL_ADDRS_IGNORED_SAME_SRC_IP_V6,"VP6d",s_pld_ctx->vpn,s_pld_ctx->ikesa,add_addr,s_pld_ctx->additional_addrs_num);
			goto ignore;
		}

		lst = (rhp_ip_addr_list*)_rhp_malloc(sizeof(rhp_ip_addr_list));
		if( lst == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
		memset(lst,0,sizeof(rhp_ip_addr_list));

		lst->ip_addr.addr_family = AF_INET6;
		memcpy(lst->ip_addr.addr.raw,add_addr,16);

	  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_ADDITIONAL_ADDRS_CB_INFO_V6,"x6d",rx_ikemesg,add_addr,s_pld_ctx->additional_addrs_num);

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,s_pld_ctx->vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_RX_ADDITIONAL_ADDRS_NOTIFY_V6,"VP6d",s_pld_ctx->vpn,s_pld_ctx->ikesa,add_addr,s_pld_ctx->additional_addrs_num);

	}else{

	  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_ADDITIONAL_ADDRS_CB_BAD_VALUE,"xdx",rx_ikemesg,add_addr_len,add_addr);

	  RHP_LOG_DE(RHP_LOG_SRC_IKEV2,s_pld_ctx->vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_RX_INVALID_ADDITIONAL_ADDRS_NOTIFY,"VPd",s_pld_ctx->vpn,s_pld_ctx->ikesa,add_addr_len);
	}

	if( lst ){

		if( s_pld_ctx->additional_addrs_head == NULL ){
			s_pld_ctx->additional_addrs_head = lst;
		}else{
			s_pld_ctx->additional_addrs_tail->next = lst;
		}
		s_pld_ctx->additional_addrs_tail = lst;

		s_pld_ctx->additional_addrs_num++;
	}

ignore:
	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_ADDITIONAL_ADDRS_CB_RTRN,"x",rx_ikemesg);
	return 0;

error:
	if( lst ){
		_rhp_free(lst);
	}
	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_ADDITIONAL_ADDRS_CB_ERR,"xE",rx_ikemesg,err);
	return err;
}

static int _rhp_ikev2_mobike_srch_n_ike_auth_r_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_mobike_srch_plds_ctx* s_pld_ctx = (rhp_mobike_srch_plds_ctx*)ctx;
	rhp_ikev2_n_payload* n_payload = (rhp_ikev2_n_payload*)payload->ext.n;
	u16 notify_mesg_type;

  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_IKE_AUTH_R_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

	if( n_payload == NULL ){
		RHP_BUG("");
  	return -EINVAL;
  }

	notify_mesg_type = n_payload->get_message_type(payload);

	if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_MOBIKE_SUPPORTED ){

		s_pld_ctx->peer_enabled = 1;
	  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_IKE_AUTH_R_CB_MOBIKE_SUPPORTED,"x",rx_ikemesg);

	  RHP_LOG_D(RHP_LOG_SRC_IKEV2,s_pld_ctx->vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_RX_SUPPORTED_NOTIFY,"VP",s_pld_ctx->vpn,s_pld_ctx->ikesa);

	}else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_ADDITIONAL_IP4_ADDRESS ||
						notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_ADDITIONAL_IP6_ADDRESS ){

		err = _rhp_ikev2_mobike_srch_n_additional_addrs_cb(rx_ikemesg,enum_end,payload,s_pld_ctx);
		if( err ){
		  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_IKE_AUTH_R_CB_ADDITIONAL_ADDRS_ERR,"xE",rx_ikemesg,err);
			goto error;
		}

	}else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_NO_NATS_ALLOWED ){

		err = _rhp_ikev2_mobike_srch_n_no_nats_allowed_cb(rx_ikemesg,enum_end,payload,s_pld_ctx);
		if( err ){
		  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_IKE_AUTH_R_CB_NO_NATS_ALLOWED_ERR,"xE",rx_ikemesg,err);
			goto error;
		}
	}

	err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_IKE_AUTH_R_CB_RTRN,"xE",rx_ikemesg,err);
	return err;
}

static int _rhp_ikev2_mobike_srch_n_ike_auth_i_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_mobike_srch_plds_ctx* s_pld_ctx = (rhp_mobike_srch_plds_ctx*)ctx;
	rhp_ikev2_n_payload* n_payload = (rhp_ikev2_n_payload*)payload->ext.n;
	u16 notify_mesg_type;

  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_IKE_AUTH_I_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

	if( n_payload == NULL ){
		RHP_BUG("");
  	return -EINVAL;
  }

	notify_mesg_type = n_payload->get_message_type(payload);

	if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_MOBIKE_SUPPORTED ){

		s_pld_ctx->peer_enabled = 1;
	  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_IKE_AUTH_I_CB_MOBIKE_SUPPORTED,"x",rx_ikemesg);

	  RHP_LOG_D(RHP_LOG_SRC_IKEV2,s_pld_ctx->vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_RX_SUPPORTED_NOTIFY,"VP",s_pld_ctx->vpn,s_pld_ctx->ikesa);

	}else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_ADDITIONAL_IP4_ADDRESS ||
						notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_ADDITIONAL_IP6_ADDRESS ){

		err = _rhp_ikev2_mobike_srch_n_additional_addrs_cb(rx_ikemesg,enum_end,payload,s_pld_ctx);
		if( err ){
		  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_IKE_AUTH_I_CB_ADDITIONAL_ADDRS_ERR,"xE",rx_ikemesg,err);
			goto error;
		}
	}

	err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_IKE_AUTH_I_CB_RTRN,"xE",rx_ikemesg,err);
	return err;
}

static int _rhp_ikev2_mobike_srch_n_info_i_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_mobike_srch_plds_ctx* s_pld_ctx = (rhp_mobike_srch_plds_ctx*)ctx;
	rhp_ikev2_n_payload* n_payload = (rhp_ikev2_n_payload*)payload->ext.n;
	u16 notify_mesg_type;

  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_INFO_I_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

	if( n_payload == NULL ){
		RHP_BUG("");
  	return -EINVAL;
  }

	notify_mesg_type = n_payload->get_message_type(payload);

	if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_NO_ADDITIONAL_ADDRESSES ){

		s_pld_ctx->no_additional_addrs = 1;
	  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_INFO_I_CB_NO_ADDITIONAL_ADDRS,"x",rx_ikemesg);

	  RHP_LOG_D(RHP_LOG_SRC_IKEV2,s_pld_ctx->vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_RX_NO_ADDITIONAL_ADDR_NOTIFY,"VP",s_pld_ctx->vpn,s_pld_ctx->ikesa);

	}else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_ADDITIONAL_IP4_ADDRESS ||
						notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_ADDITIONAL_IP6_ADDRESS ){

		err = _rhp_ikev2_mobike_srch_n_additional_addrs_cb(rx_ikemesg,enum_end,payload,s_pld_ctx);
		if( err ){
		  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_INFO_I_CB_ADDITIONAL_ADDRS_ERR,"xE",rx_ikemesg,err);
			goto error;
		}

	}else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_NO_NATS_ALLOWED ){

		err = _rhp_ikev2_mobike_srch_n_no_nats_allowed_cb(rx_ikemesg,enum_end,payload,s_pld_ctx);
		if( err ){
		  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_INFO_I_CB_NO_NATS_ALLOWED_ERR,"xE",rx_ikemesg,err);
			goto error;
		}

	}else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_COOKIE2 ){

		int cookie2_len = payload->ext.n->get_data_len(payload);
		u8* cookie2 = payload->ext.n->get_data(payload);

		if( cookie2 &&
				cookie2_len >= RHP_PROTO_IKE_NOTIFY_COOKIE2_MIN_SZ &&
				cookie2_len <= RHP_PROTO_IKE_NOTIFY_COOKIE2_MAX_SZ ){

			s_pld_ctx->rx_cookie2_len = cookie2_len;
			memcpy(s_pld_ctx->rx_cookie2,cookie2,cookie2_len);

		  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_INFO_I_CB_COOKIE2,"xp",rx_ikemesg,cookie2_len,cookie2);

		  RHP_LOG_D(RHP_LOG_SRC_IKEV2,s_pld_ctx->vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_INFO_RX_COOKIE2_NOTIFY_2,"VPKp",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg,cookie2_len,cookie2);
		}
	}

	err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_INFO_I_CB_RTRN,"xE",rx_ikemesg,err);
	return err;
}

static int _rhp_ikev2_mobike_i_update_additional_addr_cache(rhp_vpn* vpn,rhp_vpn_realm* rlm)
{

	if( rlm->mobike.init_cache_additional_addr &&
			vpn->mobike.init.additional_addrs ){

		rhp_cfg_peer* rlm_cfg_peer;
		u16 cached_port = htons(rhp_gcfg_ike_port);
		rhp_ip_addr* new_addr_cache = &(vpn->mobike.init.additional_addrs->ip_addr);

		if( rlm->ikesa.use_nat_t_port ){
			cached_port = htons(rhp_gcfg_ike_port_nat_t);
		}

		rlm_cfg_peer = rlm->get_peer_by_id(rlm,&(vpn->cfg_peer->id));
		if( rlm_cfg_peer &&
				rhp_ip_addr_cmp(&(rlm_cfg_peer->primary_addr),new_addr_cache) &&
				rhp_ip_addr_cmp(&(rlm_cfg_peer->secondary_addr),new_addr_cache) ){

			memcpy(&(rlm_cfg_peer->mobike_additional_addr_cache),new_addr_cache,sizeof(rhp_ip_addr));
			rlm_cfg_peer->mobike_additional_addr_cache.port = cached_port;

	    rhp_ip_addr_dump("i_ike_auth_rep:rlm_additional_addr_cache",&(rlm_cfg_peer->mobike_additional_addr_cache));
		}

		if( vpn->cfg_peer &&
				rhp_ip_addr_cmp(&(vpn->cfg_peer->primary_addr),new_addr_cache) &&
				rhp_ip_addr_cmp(&(vpn->cfg_peer->secondary_addr),new_addr_cache) ){

			memcpy(&(vpn->cfg_peer->mobike_additional_addr_cache),new_addr_cache,sizeof(rhp_ip_addr));
			vpn->cfg_peer->mobike_additional_addr_cache.port = cached_port;

			rhp_ip_addr_dump("i_ike_auth_rep:vpn_additional_addr_cache",&(vpn->cfg_peer->mobike_additional_addr_cache));
		}

		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_UPDATE_ADDITIONAL_ADDR_CACHE,"xx",vpn,rlm);

	}else{

		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_UPDATE_ADDITIONAL_ADDR_CACHE_NOT_FOUND,"xx",vpn,rlm);
	}

	return 0;
}

static int _rhp_ikev2_rx_mobike_i_ike_auth_rep(rhp_vpn* vpn,
		rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err = -EINVAL;
	rhp_mobike_srch_plds_ctx s_pld_ctx;
	rhp_vpn_realm* rlm = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_IKE_AUTH_REP,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);

	memset(&s_pld_ctx,0,sizeof(rhp_mobike_srch_plds_ctx));

  if( rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  rlm = vpn->rlm;
  if( rlm == NULL ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  {
		RHP_LOCK(&(rlm->lock));

		if( !_rhp_atomic_read(&(rlm->is_active)) ){
			err = -EINVAL;
			RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_IKE_AUTH_REP_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
			goto error_l;
		}

		if( !rlm->mobike.enabled || vpn->mobike_disabled  ){
			err = 0;
			RHP_UNLOCK(&(rlm->lock));
			RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_IKE_AUTH_REP_MOBIKE_DISALBED,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
			goto ignored;
		}

		RHP_UNLOCK(&(rlm->lock));
  }


	s_pld_ctx.vpn = vpn;
	s_pld_ctx.ikesa = ikesa;

	{
		s_pld_ctx.dup_flag = 0;
		u16 mobike_n_ids[4] = { RHP_PROTO_IKE_NOTIFY_ST_MOBIKE_SUPPORTED,
														RHP_PROTO_IKE_NOTIFY_ST_ADDITIONAL_IP4_ADDRESS,
														RHP_PROTO_IKE_NOTIFY_ST_ADDITIONAL_IP6_ADDRESS,
														RHP_PROTO_IKE_NOTIFY_RESERVED};

		err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
						rhp_ikev2_mesg_srch_cond_n_mesg_ids,mobike_n_ids,
						_rhp_ikev2_mobike_srch_n_ike_auth_i_cb,&s_pld_ctx);

		if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){

		  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_IKE_AUTH_NTFY_ERR,"xxxxE",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,err);
			goto error;
		}
		err = 0;
	}

	if( !s_pld_ctx.peer_enabled ){
		err = 0;
    RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_IKE_AUTH_REP_PEER_MOBIKE_DISALBED,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
		goto ignored;
	}


	vpn->exec_mobike = 1;

	//
	// [CAUTION]
	//   If MOBIKE is enabled, all IKEv2 messages will be transmitted from the NAT-T port (4500).
	//
	vpn->nat_t_info.use_nat_t_port = 1;
	if( !vpn->nat_t_info.exec_nat_t ){
		vpn->peer_addr.port = htons(rhp_gcfg_ike_port_nat_t);
	}

	{
		u8* notified_hash;
		rhp_ikev2_payload* n_dst_payload
		= _rhp_ikev2_mobike_get_nat_dest_ip_payload(vpn,ikesa,RHP_IKE_INITIATOR);

		if( n_dst_payload ){

		  notified_hash = n_dst_payload->ext.n->get_data(n_dst_payload);
			if( notified_hash ){

				vpn->mobike.init.nat_t_src_hash_rx_times++;
				memcpy(vpn->mobike.init.rx_nat_t_src_hash,notified_hash,RHP_IKEV2_NAT_T_HASH_LEN);

		    RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_IKE_AUTH_REP_NAT_T_DEST_HASH_PLD,"xxxxp",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,RHP_IKEV2_NAT_T_HASH_LEN,vpn->mobike.init.rx_nat_t_src_hash);

			}else{
				RHP_BUG("");
			}

		}else{
	    RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_IKE_AUTH_REP_NO_NAT_T_DEST_HASH_PLD,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
		}
	}

	if( s_pld_ctx.additional_addrs_num ){

		vpn->mobike.init.additional_addrs_num = s_pld_ctx.additional_addrs_num;
		vpn->mobike.init.additional_addrs = s_pld_ctx.additional_addrs_head;

		s_pld_ctx.additional_addrs_num = 0;
		s_pld_ctx.additional_addrs_head = NULL;
		s_pld_ctx.additional_addrs_tail = NULL;

	  {
			RHP_LOCK(&(rlm->lock));

			if( !_rhp_atomic_read(&(rlm->is_active)) ){
				err = -EINVAL;
				RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_IKE_AUTH_REP_RLM_NOT_ACTIVE_2,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
				goto error_l;
			}

			err = _rhp_ikev2_mobike_i_update_additional_addr_cache(vpn,rlm);
			if( err ){
				RHP_BUG("");
				goto error_l;
			}

			RHP_UNLOCK(&(rlm->lock));
	  }
	}

  {
  	rhp_ip_addr_list* aaddr  = vpn->mobike.init.additional_addrs;

    RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_AUTH_ENABLED,"VPK",vpn,ikesa,rx_resp_ikemesg);

		while( aaddr ){

			if( aaddr->ip_addr.addr_family == AF_INET ){
				RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_PEER_ADDITIONAL_ADDR,"V4",vpn,aaddr->ip_addr.addr.v4);
			}else if( aaddr->ip_addr.addr_family == AF_INET6 ){
				RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_PEER_ADDITIONAL_ADDR_V6,"V6",vpn,aaddr->ip_addr.addr.v6);
			}

			aaddr = aaddr->next;
		}
  }

ignored:
	_rhp_ikev2_mobike_srch_clear_ctx(&s_pld_ctx);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_IKE_AUTH_REP_RTRN,"xxxxdxp",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,vpn->mobike.init.additional_addrs_num,vpn->mobike.init.additional_addrs,RHP_IKEV2_NAT_T_HASH_LEN,vpn->mobike.init.rx_nat_t_src_hash);
	return 0;

error_l:
	RHP_UNLOCK(&(rlm->lock));
error:
	_rhp_ikev2_mobike_srch_clear_ctx(&s_pld_ctx);

  RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_RX_AUTH_REP_ERR,"VPE",vpn,ikesa,err);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_IKE_AUTH_REP_ERR,"xxxxE",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,err);
	return err;
}

static int _rhp_ikev2_rx_mobike_r_ike_auth_req(rhp_vpn* vpn,
		rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err = -EINVAL;
	rhp_mobike_srch_plds_ctx s_pld_ctx;
	time_t keep_alive_interval;
	rhp_vpn_realm* rlm = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_IKE_AUTH_REQ,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);

	memset(&s_pld_ctx,0,sizeof(rhp_mobike_srch_plds_ctx));

  if( rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  rlm = vpn->rlm;
  if( rlm == NULL ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  {
		RHP_LOCK(&(rlm->lock));

		if( !_rhp_atomic_read(&(rlm->is_active)) ){
			err = -EINVAL;
			RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_IKE_AUTH_REQ_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
			goto error_l;
		}

		if( !rlm->mobike.enabled || vpn->mobike_disabled ){
			err = 0;
			RHP_UNLOCK(&(rlm->lock));
			RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_IKE_AUTH_REQ_MOBIKE_DISALBED,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
			goto ignored;
		}

		RHP_UNLOCK(&(rlm->lock));
  }


	s_pld_ctx.vpn = vpn;
	s_pld_ctx.ikesa = ikesa;

	{
		s_pld_ctx.dup_flag = 0;
		u16 mobike_n_ids[5] = { RHP_PROTO_IKE_NOTIFY_ST_MOBIKE_SUPPORTED,
														RHP_PROTO_IKE_NOTIFY_ST_NO_NATS_ALLOWED,
														RHP_PROTO_IKE_NOTIFY_ST_ADDITIONAL_IP4_ADDRESS,
														RHP_PROTO_IKE_NOTIFY_ST_ADDITIONAL_IP6_ADDRESS,
														RHP_PROTO_IKE_NOTIFY_RESERVED};

		err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
				rhp_ikev2_mesg_srch_cond_n_mesg_ids,mobike_n_ids,_rhp_ikev2_mobike_srch_n_ike_auth_r_cb,&s_pld_ctx);

		if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){

			if( s_pld_ctx.notify_error ){
				goto error_notify;
			}

		  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_IKE_AUTH_REQ_NTFY_ERR,"xxxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);
			goto error;
		}
	}

	if( !s_pld_ctx.peer_enabled ){

		err = 0;

	  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_AUTH_PEER_DISABLED,"VP",vpn,ikesa);

		RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_IKE_AUTH_REQ_PEER_MOBIKE_DISALBED,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
		goto ignored;
	}


	//
	// [CAUTION]
	//
	//  Currently, RHP_PROTO_IKE_NOTIFY_ST_ADDITIONAL_IPx_ADDRESSes are NOT used
	//  for anything by responder.
	//  If a responder supports dynamic address updating in the future, these info
	//  can be used.
	//


	{
		RHP_LOCK(&(rlm->lock));

		if( !_rhp_atomic_read(&(rlm->is_active)) ){
			err = -EINVAL;
			RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_IKE_AUTH_REQ_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
			goto error_l;
		}

		err = _rhp_ikev2_new_pkt_mobike_r_ike_auth_rep(vpn,ikesa,rlm,rx_req_ikemesg,tx_resp_ikemesg);
		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_IKE_AUTH_REQ_NEW_PKT_REP_ERR,"xxxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);
			goto error_l;
		}

		if( rlm->null_auth_configured(rlm) ){
			keep_alive_interval = (time_t)rlm->mobike.resp_ka_interval_null_auth;
		}else{
			keep_alive_interval = (time_t)rlm->mobike.resp_ka_interval;
		}

		RHP_UNLOCK(&(rlm->lock));
	}


	vpn->exec_mobike = 1;

	//
	// [CAUTION]
	//   If MOBIKE is enabled, all IKEv2 messages will be transmitted from the NAT-T port (4500).
	//
	vpn->nat_t_info.use_nat_t_port = 1;
	if( !vpn->nat_t_info.exec_nat_t ){
		vpn->peer_addr.port = htons(rhp_gcfg_ike_port_nat_t);
	}

	ikesa->timers->quit_keep_alive_timer(vpn,ikesa);
	ikesa->timers->start_keep_alive_timer(vpn,ikesa,keep_alive_interval);

  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_AUTH_ENABLED,"VPK",vpn,ikesa,rx_req_ikemesg);

ignored:
	_rhp_ikev2_mobike_srch_clear_ctx(&s_pld_ctx);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_IKE_AUTH_REQ_RTRN,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
	return 0;

error_l:
	RHP_UNLOCK(&(rlm->lock));
error:
	_rhp_ikev2_mobike_srch_clear_ctx(&s_pld_ctx);

  RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_RX_AUTH_REQ_ERR,"VPE",vpn,ikesa,err);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_IKE_AUTH_REQ_ERR,"xxxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);
	return err;


error_notify:

	err = _rhp_ikev2_new_pkt_mobike_error_notify(vpn,ikesa,tx_resp_ikemesg,0,0,s_pld_ctx.notify_error,0);
	if( err ){
		RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_IKE_AUTH_REQ_TX_ERR_NOTIFY_ERR,"xxxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);
	}
	// err == 0 is OK.

	goto error;
}


static int _rhp_ikev2_new_pkt_mobike_r_info_rep(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_mobike_srch_plds_ctx* s_pld_ctx,
		rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err = -EINVAL;
	rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_R_INFO_REP,"xxxxxd",vpn,ikesa,s_pld_ctx,rx_req_ikemesg,tx_resp_ikemesg,s_pld_ctx->rx_cookie2_len);


  if( s_pld_ctx->rx_cookie2_len ){

		err = rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload);
	 	if( err ){
	     RHP_BUG("");
	     goto error;
	 	}

	 	tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

	 	ikepayload->ext.n->set_protocol_id(ikepayload,0);

	 	ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_COOKIE2);

	 	err = ikepayload->ext.n->set_data(ikepayload,s_pld_ctx->rx_cookie2_len,s_pld_ctx->rx_cookie2);
	 	if( err ){
			RHP_BUG("");
	 		goto error;
	 	}

	  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_INFO_REP_TX_RX_COOKIE2_RESP,"VPp",vpn,ikesa,s_pld_ctx->rx_cookie2_len,s_pld_ctx->rx_cookie2);
  }


	if( vpn->exec_mobike && s_pld_ctx->rx_update_sa_address ){
		// ....
	}

//  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_TX_INFO_REP,"VPp",vpn,ikesa,s_pld_ctx->rx_cookie2_len,s_pld_ctx->rx_cookie2);

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_R_INFO_REP_RTRN,"xxxxx",vpn,ikesa,s_pld_ctx,rx_req_ikemesg,tx_resp_ikemesg);
	return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_TX_INFO_REP_ERR,"VPE",vpn,ikesa,err);
	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_R_INFO_REP_ERR,"xxxxxE",vpn,ikesa,s_pld_ctx,rx_req_ikemesg,tx_resp_ikemesg,err);
	return err;
}


static int _rhp_ikev2_mobike_srch_n_info_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_mobike_srch_plds_ctx* s_pld_ctx = (rhp_mobike_srch_plds_ctx*)ctx;
	rhp_ikev2_n_payload* n_payload = (rhp_ikev2_n_payload*)payload->ext.n;
	u16 notify_mesg_type;

  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_INFO_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

	if( n_payload == NULL ){
		RHP_BUG("");
  	return -EINVAL;
  }

	notify_mesg_type = n_payload->get_message_type(payload);

	if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_UPDATE_SA_ADDRESSES ){

		s_pld_ctx->rx_update_sa_address = 1;
	  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_INFO_CB_UPDATE_SA_ADDRS,"x",rx_ikemesg);

	  RHP_LOG_D(RHP_LOG_SRC_IKEV2,s_pld_ctx->vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_INFO_RX_UPDATE_SA_ADDRESS_NOTIFY,"VPK",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg);

	  rhp_ikev2_g_statistics_inc(mobike_resp_rx_update_sa_addr_times);

	}else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_COOKIE2 ){

		int cookie2_len = payload->ext.n->get_data_len(payload);
		u8* cookie2 = payload->ext.n->get_data(payload);

		if( cookie2 &&
				cookie2_len >= RHP_PROTO_IKE_NOTIFY_COOKIE2_MIN_SZ &&
				cookie2_len <= RHP_PROTO_IKE_NOTIFY_COOKIE2_MAX_SZ ){

			s_pld_ctx->rx_cookie2_len = cookie2_len;
			memcpy(s_pld_ctx->rx_cookie2,cookie2,cookie2_len);

		  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_INFO_CB_COOKIE2,"xp",rx_ikemesg,cookie2_len,cookie2);

		  RHP_LOG_D(RHP_LOG_SRC_IKEV2,s_pld_ctx->vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_INFO_RX_COOKIE2_NOTIFY,"VPKp",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg,cookie2_len,cookie2);

		}else{

			s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_UNACCEPTABLE_ADDRESSES;

		  RHP_LOG_D(RHP_LOG_SRC_IKEV2,s_pld_ctx->vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_INFO_RX_INVALID_COOKIE2_NOTIFY,"VPKd",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg,cookie2_len);

		  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_INFO_CB_INVALID_COOKIE2,"xxd",rx_ikemesg,cookie2,cookie2_len);

			err = RHP_STATUS_INVALID_MSG;
			goto error;
		}

	}else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ERR_UNACCEPTABLE_ADDRESSES ){

	  RHP_LOG_E(RHP_LOG_SRC_IKEV2,s_pld_ctx->vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_RX_UNACCEPTABLE_ADDR_ERR,"VPK",s_pld_ctx->vpn,s_pld_ctx->ikesa,rx_ikemesg);

		err = RHP_STATUS_IKEV2_MOBIKE_RX_UNACCEPTABLE_ADDR;
		goto error;

	}else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_NO_NATS_ALLOWED ){

		err = _rhp_ikev2_mobike_srch_n_no_nats_allowed_cb(rx_ikemesg,enum_end,payload,s_pld_ctx);
		if( err ){
		  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_INFO_CB_NO_NATS_ALLOWED_ERR,"xE",rx_ikemesg,err);
			goto error;
		}

	}else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_NAT_DETECTION_DESTINATION_IP ){

		s_pld_ctx->nat_t_notify_found = 1;
	}

	err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_N_INFO_CB_RTRN,"xE",rx_ikemesg,err);
	return err;
}


static void _rhp_ikev2_mobike_update_sa_addrs(rhp_vpn* vpn,rhp_ifc_entry *rx_ifc,
		int new_addr_family,u8* local_new_addr,u8* peer_new_addr,u16 peer_new_port)
{
	int old_peer_addr_family = vpn->peer_addr.addr_family;
	u8* old_peer_addr = vpn->peer_addr.addr.raw;

	if( new_addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_UPDATE_SA_ADDRS,"xx44W",vpn,rx_ifc,*((u32*)local_new_addr),*((u32*)peer_new_addr),peer_new_port);
	}else if( new_addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_UPDATE_SA_ADDRS_V6,"xx66W",vpn,rx_ifc,local_new_addr,peer_new_addr,peer_new_port);
	}else{
		RHP_BUG("");
		return;
	}
	rhp_ip_addr_dump("vpn->peer_addr(OLD)",&(vpn->peer_addr));


	if( vpn->ikesa_list_head == NULL ){
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_UPDATE_SA_ADDRS_NO_IKESA,"x",vpn);
		return;
	}


	rhp_vpn_update_by_peer_addr(vpn,new_addr_family,peer_new_addr);

	rhp_ip_addr_set2(&(vpn->peer_addr),new_addr_family,peer_new_addr,peer_new_port);


	{
		RHP_LOCK(&(rx_ifc->lock));

		vpn->set_local_net_info(vpn,rx_ifc,new_addr_family,local_new_addr);

		RHP_UNLOCK(&(rx_ifc->lock));
	}

	if( vpn->peer_addr.addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_UPDATE_SA_ADDRS,"xLd4W",vpn,"AF",vpn->peer_addr.addr_family,vpn->peer_addr.addr.v4,vpn->peer_addr.port);
	}else if( vpn->peer_addr.addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_UPDATE_SA_ADDRS_V6,"xLd6W",vpn,"AF",vpn->peer_addr.addr_family,vpn->peer_addr.addr.v6,vpn->peer_addr.port);
	}

	{
		rhp_childsa* cur_childsa = vpn->childsa_list_head;

		while( cur_childsa ){

			if( cur_childsa->ipsec_mode == RHP_CHILDSA_MODE_TRANSPORT ){

				rhp_childsa_ts* peer_tss = cur_childsa->peer_tss;

				while( peer_tss ){

					if( peer_tss->start_addr.addr_family == old_peer_addr_family ){

						if( (old_peer_addr_family == AF_INET &&
								 peer_tss->start_addr.addr.v4 == *((u32*)old_peer_addr)) ||
								(old_peer_addr_family == AF_INET6 &&
								 rhp_ipv6_is_same_addr(peer_tss->start_addr.addr.v6,old_peer_addr)) ){

							if( new_addr_family == AF_INET ){

								peer_tss->start_addr.addr_family = AF_INET;
								peer_tss->start_addr.addr.v4 = *((u32*)peer_new_addr);

								RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_UPDATE_SA_ADDRS_PEER_TSS_START,"xx4",vpn,peer_tss,peer_tss->start_addr.addr.v4);

							}else if( new_addr_family == AF_INET6 ){

								peer_tss->start_addr.addr_family = AF_INET6;
								memcpy(peer_tss->start_addr.addr.v6,peer_new_addr,16);

								RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_UPDATE_SA_ADDRS_PEER_TSS_START_V6,"xx6",vpn,peer_tss,peer_tss->start_addr.addr.v6);
							}
						}
					}

					if( peer_tss->end_addr.addr_family == old_peer_addr_family ){

						if( (old_peer_addr_family == AF_INET &&
								 peer_tss->end_addr.addr.v4 == *((u32*)old_peer_addr)) ||
								(old_peer_addr_family == AF_INET6 &&
								 rhp_ipv6_is_same_addr(peer_tss->end_addr.addr.v6,old_peer_addr)) ){

							if( new_addr_family == AF_INET ){

								peer_tss->end_addr.addr_family = AF_INET;
								peer_tss->end_addr.addr.v4 = *((u32*)peer_new_addr);

								RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_UPDATE_SA_ADDRS_PEER_TSS_END,"xx4",vpn,peer_tss,peer_tss->end_addr.addr.v4);

							}else	if( new_addr_family == AF_INET6 ){

								peer_tss->end_addr.addr_family = AF_INET6;
								memcpy(peer_tss->end_addr.addr.v6,peer_new_addr,16);

								RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_UPDATE_SA_ADDRS_PEER_TSS_END_V6,"xx6",vpn,peer_tss,peer_tss->end_addr.addr.v6);
							}
						}
					}

					peer_tss = peer_tss->next;
				}
			}

			rhp_childsa_calc_pmtu(vpn,NULL,cur_childsa);

			cur_childsa = cur_childsa->next_vpn_list;
		}
	}


	if( vpn->nhrp.role == RHP_NHRP_SERVICE_CLIENT ){

		rhp_nhrp_invoke_update_addr_task(vpn,1,
				rhp_gcfg_nhrp_registration_req_tx_margin_time);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_UPDATE_SA_ADDRS_RTRN,"x",vpn);
	return;
}

static void _rhp_ikev2_mobike_r_update_sa_addrs(rhp_vpn* vpn,rhp_ikev2_mesg* rx_ikemesg)
{
	rhp_packet* rx_pkt = rx_ikemesg->rx_pkt;
	int addr_family;
	u8 *local_addr,*peer_addr;
	u16 peer_port;

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_R_UPDATE_SA_ADDRS,"xxx",vpn,rx_ikemesg,rx_pkt);

	if( rx_pkt->type == RHP_PKT_IPV4_IKE ){

		addr_family = AF_INET;
		local_addr = (u8*)&(rx_pkt->l3.iph_v4->dst_addr);
		peer_addr = (u8*)&(rx_pkt->l3.iph_v4->src_addr);
		peer_port = rx_pkt->l4.udph->src_port;

		RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_UPDATE_PATH,"VKsd4W4W",vpn,rx_ikemesg,rx_pkt->rx_ifc->if_name,rx_pkt->rx_ifc->if_index,rx_pkt->l3.iph_v4->dst_addr,rx_pkt->l4.udph->dst_port,rx_pkt->l3.iph_v4->src_addr,rx_pkt->l4.udph->src_port);

	}else if( rx_pkt->type == RHP_PKT_IPV6_IKE ){

		addr_family = AF_INET6;
		local_addr = rx_pkt->l3.iph_v6->dst_addr;
		peer_addr = rx_pkt->l3.iph_v6->src_addr;
		peer_port = rx_pkt->l4.udph->src_port;

		RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_UPDATE_PATH_V6,"VKsd6W6W",vpn,rx_ikemesg,rx_pkt->rx_ifc->if_name,rx_pkt->rx_ifc->if_index,rx_pkt->l3.iph_v6->dst_addr,rx_pkt->l4.udph->dst_port,rx_pkt->l3.iph_v6->src_addr,rx_pkt->l4.udph->src_port);

	}else{
		RHP_BUG("%d",rx_pkt->type);
		return;
	}

	_rhp_ikev2_mobike_update_sa_addrs(vpn,rx_pkt->rx_ifc,
			addr_family,local_addr,peer_addr,peer_port);

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_R_UPDATE_SA_ADDRS_RTRN,"xxx",vpn,rx_ikemesg,rx_pkt);
	return;
}

static void _rhp_ikev2_mobike_rt_ck_req_completed(rhp_vpn* vpn,rhp_ikesa* tx_ikesa,
		rhp_ikev2_mesg* ikemesg,rhp_packet* serialized_pkt)
{
	u32 mesg_id = ikemesg->get_mesg_id(ikemesg);
	rhp_vpn_mobike_cookie2* tx_cookie2;

  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_RT_CK_REQ_COMPLETED,"xxxuxLd",vpn,tx_ikesa,ikemesg,mesg_id,serialized_pkt,"IKE_SIDE",vpn->origin_side);

  if( vpn->origin_side == RHP_IKE_RESPONDER ){
  	tx_cookie2 = vpn->mobike.resp.rt_ck_cookie2_head;
  }else{
  	tx_cookie2 = vpn->mobike.init.rt_ck_cookie2_head;
  }

  if( tx_cookie2->mesg_id_valid ){
  	RHP_BUG("");
  }

  while( tx_cookie2 ){

  	if( tx_cookie2->tx_ikemesg == ikemesg ){

  		tx_cookie2->mesg_id = mesg_id;
  		tx_cookie2->mesg_id_valid = 1;

  	  rhp_ikev2_unhold_mesg(tx_cookie2->tx_ikemesg);
  		tx_cookie2->tx_ikemesg = NULL;

  	  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_RT_CK_REQ_COMPLETED_SET_MSGID,"xxxxu",vpn,tx_ikesa,ikemesg,tx_cookie2,tx_cookie2->mesg_id);
  		break;
  	}

  	tx_cookie2 = tx_cookie2->next;
  }

  if( tx_cookie2 == NULL ){
  	RHP_BUG("");
  }

  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_RT_CK_REQ_COMPLETED_RTRN,"xxx",vpn,tx_ikesa,ikemesg);
	return;
}

static rhp_vpn_mobike_cookie2* _rhp_ikev2_mobike_gen_cookie2(int gen_type)
{
	int err = -EINVAL;
	rhp_vpn_mobike_cookie2* tx_cookie2 = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_GEN_COOKIE2,"d",gen_type);

	tx_cookie2 = (rhp_vpn_mobike_cookie2*)_rhp_malloc(sizeof(rhp_vpn_mobike_cookie2));
	if( tx_cookie2 == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memset(tx_cookie2,0,sizeof(rhp_vpn_mobike_cookie2));

	err = rhp_random_bytes(tx_cookie2->cookie2,RHP_IKEV2_MOBIKE_COOKIE2_LEN);
	if( err ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	tx_cookie2->gen_type = gen_type;

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_GEN_COOKIE2_RTRN,"dxp",gen_type,tx_cookie2,RHP_IKEV2_MOBIKE_COOKIE2_LEN,tx_cookie2->cookie2);
	return tx_cookie2;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_GEN_COOKIE2_ERR,"d",gen_type);
	return NULL;
}

void rhp_ikev2_mobike_free_tx_cookie2(rhp_vpn_mobike_cookie2* tx_cookie2)
{
	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_FREE_TX_COOKIE2,"x",tx_cookie2);

	if( tx_cookie2 ){

		if( tx_cookie2->tx_ikemesg ){
			rhp_ikev2_unhold_mesg(tx_cookie2->tx_ikemesg);
		}
		_rhp_free(tx_cookie2);
	}
}

static void _rhp_ikev2_mobike_r_rt_ck_task(int worker_idx,void *ctx)
{
	int err = -EINVAL;
	rhp_vpn* vpn = RHP_VPN_REF(ctx);
  rhp_ikev2_mesg* tx_ikemesg = NULL;
	rhp_vpn_mobike_cookie2* tx_cookie2 = NULL;
	rhp_ikev2_payload* ikepayload = NULL;
	rhp_ikesa* ikesa = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_R_RT_CK_TASK,"dx",worker_idx,vpn);

	RHP_LOCK(&(vpn->lock));

	if( !_rhp_atomic_read(&(vpn->is_active)) ){
	  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_R_RT_CK_TASK_VPN_NOT_ACTIVE,"dx",worker_idx,vpn);
		goto ignore_l;
	}


	ikesa = _rhp_ikev2_mobike_get_active_ikesa(vpn);


	tx_cookie2 = _rhp_ikev2_mobike_gen_cookie2(RHP_IKEV2_MOBIKE_COOKIE2_SA_ADDR);
	if( tx_cookie2 == NULL ){
		RHP_BUG("");
		goto error_l;
	}

	tx_ikemesg = rhp_ikev2_new_mesg_tx(RHP_PROTO_IKE_EXCHG_INFORMATIONAL,0,0);
	if( tx_ikemesg == NULL ){
		RHP_BUG("");
		goto error_l;
	}

	tx_ikemesg->tx_flag = RHP_IKEV2_SEND_REQ_FLAG_URGENT;

	{
		err = rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload);
		if( err ){
			 RHP_BUG("");
			goto error_l;
		}

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);

		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_COOKIE2);

		err = ikepayload->ext.n->set_data(ikepayload,RHP_IKEV2_MOBIKE_COOKIE2_LEN,tx_cookie2->cookie2);
		if( err ){
			RHP_BUG("");
			goto error_l;
		}

	  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_RT_CK_TX_COOKIE2_NOTIFY,"VPp",vpn,ikesa,RHP_IKEV2_MOBIKE_COOKIE2_LEN,tx_cookie2->cookie2);
	}

	{
		tx_ikemesg->packet_serialized = _rhp_ikev2_mobike_rt_ck_req_completed;

		tx_cookie2->tx_ikemesg = tx_ikemesg;
		rhp_ikev2_hold_mesg(tx_ikemesg);

		tx_cookie2->next = vpn->mobike.resp.rt_ck_cookie2_head;
  	vpn->mobike.resp.rt_ck_cookie2_head = tx_cookie2;
  	tx_cookie2 = NULL;
  }

  rhp_ikev2_send_request(vpn,NULL,tx_ikemesg,RHP_IKEV2_MESG_HANDLER_MOBIKE);

  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_RT_CK_TX_PROBE,"VPK",vpn,ikesa,tx_ikemesg);

  rhp_ikev2_unhold_mesg(tx_ikemesg);

ignore_l:
	RHP_UNLOCK(&(vpn->lock));

	rhp_vpn_unhold(ctx);

  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_R_RT_CK_TASK_RTRN,"dx",worker_idx,vpn);
	return;


error_l:

	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_RT_CK_TX_PROBE_ERR,"VPE",vpn,ikesa,err);

	rhp_vpn_destroy(vpn);

	RHP_UNLOCK(&(vpn->lock));

	rhp_vpn_unhold(ctx);

	if( tx_cookie2 ){
		rhp_ikev2_mobike_free_tx_cookie2(tx_cookie2);
	}

  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_R_RT_CK_TASK_ERR,"dxE",worker_idx,vpn,err);
	return;
}


static int _rhp_ikev2_rx_mobike_i_info_req(rhp_vpn* vpn,
		rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err = -EINVAL;
	rhp_mobike_srch_plds_ctx s_pld_ctx;
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_INFO_REQ,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);

	memset(&s_pld_ctx,0,sizeof(rhp_mobike_srch_plds_ctx));

  if( rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

	if( !vpn->exec_mobike ){
		err = 0;
    RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_INFO_REQ_MOBIKE_DISALBED,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
		goto ignored;
	}


	s_pld_ctx.vpn = vpn;
	s_pld_ctx.ikesa = ikesa;

	{
		s_pld_ctx.dup_flag = 0;
		u16 mobike_n_ids[6] = { RHP_PROTO_IKE_NOTIFY_ST_NO_ADDITIONAL_ADDRESSES,
														RHP_PROTO_IKE_NOTIFY_ST_NO_NATS_ALLOWED,
														RHP_PROTO_IKE_NOTIFY_ST_ADDITIONAL_IP4_ADDRESS,
														RHP_PROTO_IKE_NOTIFY_ST_ADDITIONAL_IP6_ADDRESS,
														RHP_PROTO_IKE_NOTIFY_ST_COOKIE2,
														RHP_PROTO_IKE_NOTIFY_RESERVED};

		err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
				rhp_ikev2_mesg_srch_cond_n_mesg_ids,mobike_n_ids,_rhp_ikev2_mobike_srch_n_info_i_cb,&s_pld_ctx);

		if( err == -ENOENT ){

			err = 0;
	    RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_INFO_REQ_NOT_INTERESTED,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
			goto ignored;

		}else if( err && err != RHP_STATUS_ENUM_OK ){

			if( s_pld_ctx.notify_error ){
				goto error_notify;
			}

		  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_IKE_AUTH_NTFY_ERR,"xxxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);
			goto error;
		}
		err = 0;
	}


	if( s_pld_ctx.no_additional_addrs || s_pld_ctx.additional_addrs_num ){

		rhp_ip_addr_list* aaddr = vpn->mobike.init.additional_addrs;
  	while( aaddr ){
  		rhp_ip_addr_list* aaddr_n = aaddr->next;
  		_rhp_free(aaddr);
  		aaddr = aaddr_n;
  	}

  	vpn->mobike.init.additional_addrs_num = 0;
  	vpn->mobike.init.additional_addrs = NULL;
	}


	if( !s_pld_ctx.no_additional_addrs && s_pld_ctx.additional_addrs_num ){

		vpn->mobike.init.additional_addrs_num = s_pld_ctx.additional_addrs_num;
		vpn->mobike.init.additional_addrs = s_pld_ctx.additional_addrs_head;

		s_pld_ctx.additional_addrs_num = 0;
		s_pld_ctx.additional_addrs_head = NULL;
		s_pld_ctx.additional_addrs_tail = NULL;
	}


	if( s_pld_ctx.rx_cookie2_len ){

		if( rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);

		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_COOKIE2);

		err = ikepayload->ext.n->set_data(ikepayload,s_pld_ctx.rx_cookie2_len,s_pld_ctx.rx_cookie2);
		if( !err ){
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_TX_COOKIE2_NOTIFY_RESP,"VPp",vpn,ikesa,s_pld_ctx.rx_cookie2_len,s_pld_ctx.rx_cookie2);
		}else{
			RHP_BUG("");
		}
		err = 0;
	}


	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_RX_INFO_REQ,"VPK",vpn,ikesa,rx_req_ikemesg);

	if( s_pld_ctx.no_additional_addrs ){
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_PEER_NO_ADDITIONAL_ADDR,"VP",vpn,ikesa);
	}

ignored:
	_rhp_ikev2_mobike_srch_clear_ctx(&s_pld_ctx);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_INFO_REQ_RTRN,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
	return 0;

error:
	_rhp_ikev2_mobike_srch_clear_ctx(&s_pld_ctx);

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_RX_INFO_REQ_ERR,"VPKE",vpn,ikesa,rx_req_ikemesg,err);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_INFO_REQ_ERR,"xxxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);
	return err;


error_notify:

	err = _rhp_ikev2_new_pkt_mobike_error_notify(vpn,ikesa,tx_resp_ikemesg,0,0,s_pld_ctx.notify_error,0);
	if( err ){
		RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_INFO_REQ_TX_ERR_NOTIFY_ERR,"xxxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);
	}
	// err == 0 is OK.

	goto error;
}

static int _rhp_ikev2_rx_mobike_r_info_req(rhp_vpn* vpn,
		rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err = -EINVAL;
	rhp_mobike_srch_plds_ctx s_pld_ctx;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REQ,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);

	memset(&s_pld_ctx,0,sizeof(rhp_mobike_srch_plds_ctx));

  if( rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){

  	RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


	s_pld_ctx.vpn = vpn;
	s_pld_ctx.ikesa = ikesa;

	{
		s_pld_ctx.dup_flag = 0;
		u16 mobike_n_ids[5] = { RHP_PROTO_IKE_NOTIFY_ST_UPDATE_SA_ADDRESSES,
														RHP_PROTO_IKE_NOTIFY_ST_NO_NATS_ALLOWED,
														RHP_PROTO_IKE_NOTIFY_ST_COOKIE2,
														RHP_PROTO_IKE_NOTIFY_ST_NAT_DETECTION_DESTINATION_IP,
														RHP_PROTO_IKE_NOTIFY_RESERVED};

		err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
				rhp_ikev2_mesg_srch_cond_n_mesg_ids,mobike_n_ids,_rhp_ikev2_mobike_srch_n_info_cb,&s_pld_ctx);

		if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){

			RHP_TRC(0,RHPTRCID_RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REQ_NTFY_PLD_ERR,"xxxxLwE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,"PROTO_IKE_NOTIFY",s_pld_ctx.notify_error,err);

			if( s_pld_ctx.notify_error ){
				goto error_notify;
			}

			goto error;
		}
	}


	//
	// If a cookie2 payload exists, return it!
	//
	err = _rhp_ikev2_new_pkt_mobike_r_info_rep(vpn,ikesa,&s_pld_ctx,rx_req_ikemesg,tx_resp_ikemesg);
	if( err ){
		RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REQ_NEW_PKT_REP_ERR,"xxxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);
		goto error;
	}


  if( !vpn->exec_mobike ){

  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_INFO_REQ_DISABLED,"VPK",vpn,ikesa,rx_req_ikemesg);

  	err = 0;

  	RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REQ_MOBIKE_DISALBED,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
		goto ignore;

  }else	if( !s_pld_ctx.rx_update_sa_address ){

  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_INFO_REQ_NO_UPDATE_SA_ADDR,"VPK",vpn,ikesa,rx_req_ikemesg);

		err = 0;

		RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REQ_NOT_UPDATE_SA_ADDRS,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
  	goto ignore;

	}else{

		rhp_vpn_realm* rlm = vpn->rlm;
		int routability_check = 0;
		rhp_packet* rx_pkt = rx_req_ikemesg->rx_pkt;

	  if( rlm == NULL ){
	    err = -EINVAL;
	    RHP_BUG("");
	    goto error;
	  }

		{
			RHP_LOCK(&(rlm->lock));

			if( !_rhp_atomic_read(&(rlm->is_active)) ){

				RHP_UNLOCK(&(rlm->lock));

				err = -EINVAL;
				RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REQ_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
				goto error;
			}

			routability_check = rlm->mobike.resp_routability_check;

			RHP_UNLOCK(&(rlm->lock));
		}


		if( s_pld_ctx.nat_t_notify_found ){

			RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REQ_NAT_T_PROC,"xxxxddddW",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,rhp_gcfg_ikev2_mobike_dynamically_disable_nat_t,vpn->nat_t_info.exec_nat_t,rx_req_ikemesg->nat_t_detected,rx_req_ikemesg->nat_t_behind_a_nat,vpn->origin_peer_port);

			if( vpn->nat_t_info.exec_nat_t && !rx_req_ikemesg->nat_t_detected ){

				//
				// [CAUTION]
				//
				//  Even though vpn->nat_t_info.exec_nat_t is disabled here, the responder will keep transmitting
				//  IKEv2 requests from the NAT-T port (4500). This is for an inte-op consideration.
				//  See vpn->nat_t_info.use_nat_t_port.
				//
				//  On the other hand, ESP packets will be transmitted from the RAW socket (Non UDP capsuled).
				//
				if( rhp_gcfg_ikev2_mobike_dynamically_disable_nat_t ){

					vpn->nat_t_info.exec_nat_t = 0;

					vpn->peer_addr.port = rx_req_ikemesg->rx_pkt->l4.udph->src_port;
					if( !vpn->nat_t_info.use_nat_t_port ){

						if( vpn->peer_addr.port != htons((u16)rhp_gcfg_ike_port) ){

							// Umm...
							RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REQ_DYN_DISABLE_NAT_T_USE_NON_NAT_T_PEER_PORT,"xxxxWw",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,vpn->peer_addr.port,rhp_gcfg_ike_port);
							RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_NAT_T_DYN_DISABLED_USE_NON_NAT_T_PEER_PORT,"VPKWw",vpn,ikesa,rx_req_ikemesg,vpn->peer_addr.port,rhp_gcfg_ike_port);

							vpn->peer_addr.port = htons((u16)rhp_gcfg_ike_port);
						}
					}

					RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_NAT_T_DYN_DISABLED,"VPKW",vpn,ikesa,rx_req_ikemesg,vpn->peer_addr.port);
				}

			}else if( !vpn->nat_t_info.exec_nat_t && rx_req_ikemesg->nat_t_detected ){

				vpn->nat_t_info.exec_nat_t = 1;

				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_NAT_T_DYN_ENABLED,"VPKW",vpn,ikesa,rx_req_ikemesg,vpn->peer_addr.port);
			}

			vpn->nat_t_info.behind_a_nat = rx_req_ikemesg->nat_t_behind_a_nat;

		}else{

			RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REQ_NO_NAT_T_NOTIFY_PLD,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
		}


		if( !routability_check ){

	  	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_INFO_REQ_RT_CK_DISABLED,"VPK",vpn,ikesa,rx_req_ikemesg);

			if( rx_pkt->type == RHP_PKT_IPV4_IKE ||
					rx_pkt->type == RHP_PKT_IPV6_IKE ){

				_rhp_ikev2_mobike_r_update_sa_addrs(vpn,rx_req_ikemesg);
			}

		  if( vpn->mobike.resp.keepalive_pending ){

		  	vpn->mobike.resp.keepalive_pending = 0;


		  	rhp_http_bus_broadcast_async(vpn->vpn_realm_id,1,1,
		  			rhp_ui_http_vpn_mobike_r_net_outage_finished_serialize,
		  			rhp_ui_http_vpn_bus_btx_async_cleanup,(void*)rhp_vpn_hold_ref(vpn)); // (*x*)

				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_NET_OUTAGE_FINISHED_NO_RT_CK,"VPK",vpn,ikesa,rx_req_ikemesg);
		  }

		}else{

			u8* rx_dst_addr = NULL; // Just reference!
			int rx_dst_addr_family;

			memset(&vpn->mobike.resp.rt_ck_pend_peer_addr,0,sizeof(rhp_ip_addr));

			if( rx_pkt->type == RHP_PKT_IPV4_IKE ){

				vpn->mobike.resp.rt_ck_pend_peer_addr.addr_family = AF_INET;
				vpn->mobike.resp.rt_ck_pend_peer_addr.addr.v4 = rx_pkt->l3.iph_v4->src_addr;

				rx_dst_addr_family = AF_INET;
				rx_dst_addr = (u8*)&(rx_pkt->l3.iph_v4->dst_addr);

			}else if( rx_pkt->type == RHP_PKT_IPV6_IKE ){

				vpn->mobike.resp.rt_ck_pend_peer_addr.addr_family = AF_INET6;
				memcpy(vpn->mobike.resp.rt_ck_pend_peer_addr.addr.v6,rx_pkt->l3.iph_v6->src_addr,16);

				rx_dst_addr_family = AF_INET6;
				rx_dst_addr = rx_pkt->l3.iph_v6->dst_addr;

			}else{
				RHP_BUG("");
				goto error;
			}

			vpn->mobike.resp.rt_ck_pend_peer_addr.port = rx_pkt->l4.udph->src_port;


			{
				RHP_LOCK(&(rx_pkt->rx_ifc->lock));

				if( rhp_ifc_copy_to_if_entry(rx_pkt->rx_ifc,
							&(vpn->mobike.resp.rt_ck_pend_local_if_info),rx_dst_addr_family,rx_dst_addr) ){

				  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REQ_NO_LOCAL_ADDR_FOUND,"xxx",vpn,ikesa,rx_req_ikemesg);

				  RHP_UNLOCK(&(rx_pkt->rx_ifc->lock));
					goto error;
				}

				RHP_UNLOCK(&(rx_pkt->rx_ifc->lock));
			}

			{
				rhp_vpn_ref* vpn_ref = rhp_vpn_hold_ref(vpn);

				vpn->mobike.resp.rt_ck_pending++;

				err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_2,_rhp_ikev2_mobike_r_rt_ck_task,(void*)vpn_ref);
				if( err ){

					vpn->mobike.resp.rt_ck_pending--;

					RHP_BUG("");

					rhp_vpn_unhold(vpn_ref);
					goto error;
				}
			}


			if( ikesa->req_retx_pkt ){

			  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REQ_OTHER_REQ_TX_QUEUED,"xxxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,ikesa->req_retx_pkt);

				if( !ikesa->timers->quit_retransmit_timer(vpn,ikesa) ){

					ikesa->timers->start_retransmit_timer(vpn,ikesa,1);
				}
			}
		}
	}

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_INFO_REQ,"VPK",vpn,ikesa,rx_req_ikemesg);

ignore:
	_rhp_ikev2_mobike_srch_clear_ctx(&s_pld_ctx);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REQ_RTRN,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
	return 0;

error:

	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_INFO_REQ_ERR,"VPKE",vpn,ikesa,rx_req_ikemesg,err);

	if( err ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
	}

	_rhp_ikev2_mobike_srch_clear_ctx(&s_pld_ctx);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REQ_ERR,"xxxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);
	return err;


error_notify:

	err = _rhp_ikev2_new_pkt_mobike_error_notify(vpn,ikesa,tx_resp_ikemesg,0,0,s_pld_ctx.notify_error,0);
	if( err ){
		RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REQ_TX_ERR_NOTIFY_ERR,"xxxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);
	}
	// err == 0 is OK.

	goto error;
}

static int _rhp_ikev2_new_pkt_mobike_i_update_nat_gw_reflexive_addr(
		rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* tx_ikemesg,rhp_vpn_mobike_cookie2* tx_cookie2)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;
  u8 tx_ikemesg_exchg = tx_ikemesg->get_exchange_type(tx_ikemesg);

	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_I_UPDATE_NAT_GW_REFLEXIVE_ADDR,"xxx",vpn,tx_ikemesg,tx_cookie2);

	tx_ikemesg->tx_flag = RHP_IKEV2_SEND_REQ_FLAG_URGENT;
	tx_ikemesg->mobike_update_sa_addr = 1;
	tx_ikemesg->add_nat_t_info = 1;

	if( tx_ikemesg_exchg == RHP_PROTO_IKE_EXCHG_RESEVED ){
		tx_ikemesg->set_exchange_type(tx_ikemesg,RHP_PROTO_IKE_EXCHG_INFORMATIONAL);
	}

	{
		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);

		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_UPDATE_SA_ADDRESSES);

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_NAT_GW_REF_ADDR_TX_UPDATE_SA_ADDR,"VP",vpn,ikesa);
	}

	{
		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);

		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_COOKIE2);

		err = ikepayload->ext.n->set_data(ikepayload,RHP_IKEV2_MOBIKE_COOKIE2_LEN,tx_cookie2->cookie2);
		if( err ){
			RHP_BUG("");
			goto error;
		}

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_NAT_GW_REF_TX_COOKIE2,"VPp",vpn,ikesa,RHP_IKEV2_MOBIKE_COOKIE2_LEN,tx_cookie2->cookie2);
	}

	rhp_ikev2_g_statistics_inc(mobike_init_tx_update_sa_addr_times);

	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_I_UPDATE_NAT_GW_REFLEXIVE_ADDR_RTRN,"xx",vpn,tx_ikemesg);
	return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_NAT_GW_REF_TX_ERR,"VPE",vpn,ikesa,err);
	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_I_UPDATE_NAT_GW_REFLEXIVE_ADDR_ERR,"xxE",vpn,tx_ikemesg,err);
	return err;
}

static int _rhp_ikev2_mobike_srch_nat_t_dest_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* n_dst_payload,void* ctx)
{
	int err = -EINVAL;
  int notified_hash_len = 0;
  u8* notified_hash = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_NAT_T_DEST_CB,"xdxx",rx_ikemesg,enum_end,n_dst_payload,ctx);

  notified_hash_len = n_dst_payload->ext.n->get_data_len(n_dst_payload);
  if( notified_hash_len != RHP_IKEV2_NAT_T_HASH_LEN ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_NAT_T_DEST_CB_INVALID_DATA_LEN,"xdd",rx_ikemesg,notified_hash_len,RHP_IKEV2_NAT_T_HASH_LEN);
  	goto error;
  }

  notified_hash = n_dst_payload->ext.n->get_data(n_dst_payload);
  if( notified_hash == NULL ){
  	err = RHP_STATUS_INVALID_MSG;
  	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_NAT_T_DEST_CB_NO_DATA,"xdd",rx_ikemesg);
  	goto error;
  }

  memcpy((u8*)ctx,notified_hash,notified_hash_len);

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_NAT_T_DEST_CB_RTRN,"x",rx_ikemesg);
  return RHP_STATUS_ENUM_OK;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_SRCH_NAT_T_DEST_CB_ERR,"xE",rx_ikemesg,err);
	return err;
}

static int _rhp_ikev2_mobike_nat_gw_reflexive_addr_changed(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err = -EINVAL;
	u8 nat_t_dst_hash[RHP_IKEV2_NAT_T_HASH_LEN];
	rhp_vpn_mobike_cookie2* tx_cookie2 = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_NAT_GW_REFLEXIVE_ADDR_CHANGED,"xxxxd",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,rhp_gcfg_ikev2_mobike_watch_nat_gw_reflexive_addr);

	if( !rhp_gcfg_ikev2_mobike_watch_nat_gw_reflexive_addr ){
		err = 0;
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_NAT_GW_REFLEXIVE_ADDR_CHANGED_DISABLED,"xxx",vpn,ikesa,rx_resp_ikemesg);
		goto ignored;
	}

	if( !vpn->nat_t_info.exec_nat_t ){
		err = 0;
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_NAT_GW_REFLEXIVE_ADDR_CHANGED_NAT_T_DISABLED,"xxx",vpn,ikesa,rx_resp_ikemesg);
		goto ignored;
	}

	if( vpn->origin_side != RHP_IKE_INITIATOR ){
		err = 0;
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_NAT_GW_REFLEXIVE_ADDR_CHANGED_NOT_INITIATOR,"xxx",vpn,ikesa,rx_resp_ikemesg);
		goto ignored;
	}

	if( vpn->mobike.init.rt_ck_pending ){
		err = 0;
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_NAT_GW_REFLEXIVE_ADDR_CHANGED_NOW_RT_CK_PENDING,"xxx",vpn,ikesa,rx_resp_ikemesg);
		goto ignored;
	}

	{
		u16 mobike_n_ids[2] = { RHP_PROTO_IKE_NOTIFY_ST_NAT_DETECTION_DESTINATION_IP,
														RHP_PROTO_IKE_NOTIFY_RESERVED};

		err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
				rhp_ikev2_mesg_srch_cond_n_mesg_ids,mobike_n_ids,_rhp_ikev2_mobike_srch_nat_t_dest_cb,nat_t_dst_hash);

		if( err && err != RHP_STATUS_ENUM_OK ){

			err = 0;

			RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_NAT_GW_REFLEXIVE_ADDR_CHANGED_SRCH_PAYLOAD_ERR,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
			goto ignored;
		}

		err = 0;
	}


	if( vpn->mobike.init.nat_t_src_hash_rx_times == 0 ){

		vpn->mobike.init.nat_t_src_hash_rx_times++;
		memcpy(vpn->mobike.init.rx_nat_t_src_hash,nat_t_dst_hash,RHP_IKEV2_NAT_T_HASH_LEN);

		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_NAT_GW_REFLEXIVE_ADDR_CHANGED_UPDATE_HASH,"xxxp",vpn,ikesa,rx_resp_ikemesg,RHP_IKEV2_NAT_T_HASH_LEN,nat_t_dst_hash);
		goto end;
	}


	if( !memcmp(vpn->mobike.init.rx_nat_t_src_hash,nat_t_dst_hash,RHP_IKEV2_NAT_T_HASH_LEN) ){

		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_NAT_GW_REFLEXIVE_ADDR_CHANGED_SAME_HASH,"xxxpp",vpn,ikesa,rx_resp_ikemesg,RHP_IKEV2_NAT_T_HASH_LEN,nat_t_dst_hash,RHP_IKEV2_NAT_T_HASH_LEN,vpn->mobike.init.rx_nat_t_src_hash);
		goto end;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_NAT_GW_REFLEXIVE_ADDR_CHANGED_HASH_CHANGED,"xxxpp",vpn,ikesa,rx_resp_ikemesg,RHP_IKEV2_NAT_T_HASH_LEN,nat_t_dst_hash,RHP_IKEV2_NAT_T_HASH_LEN,vpn->mobike.init.rx_nat_t_src_hash);

	rhp_ikev2_g_statistics_inc(mobike_init_nat_t_addr_changed_times);
	vpn->mobike.init.nat_t_addr_changed_times++;

	{
		tx_cookie2 = _rhp_ikev2_mobike_gen_cookie2(RHP_IKEV2_MOBIKE_COOKIE2_NAT_GW_REFLEXIVE_ADDR);
		if( tx_cookie2 == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}

		err = _rhp_ikev2_new_pkt_mobike_i_update_nat_gw_reflexive_addr(vpn,ikesa,tx_req_ikemesg,tx_cookie2);
		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_NAT_GW_REFLEXIVE_ADDR_CHANGED_NEW_PKT_ERR,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
			goto error;
		}

		tx_req_ikemesg->packet_serialized = _rhp_ikev2_mobike_rt_ck_req_completed;

		tx_cookie2->tx_ikemesg = tx_req_ikemesg;
		rhp_ikev2_hold_mesg(tx_req_ikemesg);

		tx_cookie2->next = vpn->mobike.init.rt_ck_cookie2_head;
		vpn->mobike.init.rt_ck_cookie2_head = tx_cookie2;
		tx_cookie2 = NULL;
	}

	vpn->mobike.init.nat_t_src_hash_rx_times++;
	memcpy(vpn->mobike.init.rx_nat_t_src_hash,nat_t_dst_hash,RHP_IKEV2_NAT_T_HASH_LEN);


	if( vpn->nhrp.role == RHP_NHRP_SERVICE_CLIENT ){

		rhp_nhrp_invoke_update_addr_task(vpn,1,
				rhp_gcfg_net_event_convergence_interval);
	}

	RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_NAT_GW_REF_ADDR_CHANGED,"VPK",vpn,ikesa,rx_resp_ikemesg);

ignored:
end:
	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_NAT_GW_REFLEXIVE_ADDR_CHANGED_RTRN,"xxx",vpn,ikesa,rx_resp_ikemesg);
	return 0;

error:
	if( tx_cookie2 ){
		rhp_ikev2_mobike_free_tx_cookie2(tx_cookie2);
	}

	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_NAT_GW_REF_ADDR_CHANGED_ERR,"VPKE",vpn,ikesa,rx_resp_ikemesg,err);

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_NAT_GW_REFLEXIVE_ADDR_CHANGED_ERR,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
	return err;
}

static int _rhp_ikev2_rx_mobike_i_info_rep(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err = -EINVAL;
	rhp_mobike_srch_plds_ctx s_pld_ctx;
	rhp_vpn_mobike_cookie2* tx_cookie2 = NULL;
	rhp_vpn_realm* rlm = vpn->rlm;
	time_t nat_t_keep_alive_interval;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_INFO_REP,"xxxxxdd",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,rlm,vpn->exec_mobike,vpn->mobike.init.rt_ck_pending);

	memset(&s_pld_ctx,0,sizeof(rhp_mobike_srch_plds_ctx));

  if( rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){

  	RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


  if( !vpn->exec_mobike ){

  	err = 0;
		RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_INFO_REP_MOBIKE_DISALBED,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
  	goto ignore;
  }


	{
	  if( rlm == NULL ){
	    err = -EINVAL;
	    RHP_BUG("");
	    goto error;
	  }

		RHP_LOCK(&(rlm->lock));

		if( !_rhp_atomic_read(&(rlm->is_active)) ){

			RHP_UNLOCK(&(rlm->lock));

			err = -EINVAL;
			RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_INFO_REQ_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
			goto error;
		}

	  nat_t_keep_alive_interval = (time_t)rlm->ikesa.nat_t_keep_alive_interval;

		RHP_UNLOCK(&(rlm->lock));
	}


  {
		rhp_vpn_mobike_cookie2* tx_cookie2_p = NULL;

		tx_cookie2 = vpn->mobike.init.rt_ck_cookie2_head;
  	while( tx_cookie2 ){

  		if( tx_cookie2->mesg_id_valid &&
  				tx_cookie2->mesg_id == rx_resp_ikemesg->get_mesg_id(rx_resp_ikemesg) ){
  			break;
  		}

  		tx_cookie2_p = tx_cookie2;
  		tx_cookie2 = tx_cookie2->next;
  	}

  	if( tx_cookie2 ){

  		if( tx_cookie2_p ){
				tx_cookie2_p->next = tx_cookie2->next;
			}else{
				vpn->mobike.init.rt_ck_cookie2_head = tx_cookie2->next;
			}

  		RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_INFO_REP_MOBIKE_RT_CK_FOUND_PEND_COOKIE2_BY_MESG_ID,"xxxxxU",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,tx_cookie2,tx_cookie2->mesg_id);

  	}else{

  	  if( rx_resp_ikemesg->nat_t_detected ){

  	  	err = _rhp_ikev2_mobike_nat_gw_reflexive_addr_changed(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
  	  	if( err ){
  	    	RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_INFO_REP_MOBIKE_RT_CK_NOT_FOUND_PEND_COOKIE2_BY_MESG_ID_ERR,"xxxxE",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,err);
  	  		goto error;
  	  	}
  	  }

      err = 0;
    	RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_INFO_REP_MOBIKE_RT_CK_NOT_FOUND_PEND_COOKIE2_BY_MESG_ID,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
      goto ignore;
  	}
  }



  s_pld_ctx.vpn = vpn;
	s_pld_ctx.ikesa = ikesa;

	{
		s_pld_ctx.dup_flag = 0;
		u16 mobike_n_ids[5] = { RHP_PROTO_IKE_NOTIFY_ST_COOKIE2,
														RHP_PROTO_IKE_NOTIFY_ERR_UNACCEPTABLE_ADDRESSES,
														RHP_PROTO_IKE_NOTIFY_ST_NO_NATS_ALLOWED,
														RHP_PROTO_IKE_NOTIFY_ST_NAT_DETECTION_DESTINATION_IP,
														RHP_PROTO_IKE_NOTIFY_RESERVED};

		err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
				rhp_ikev2_mesg_srch_cond_n_mesg_ids,mobike_n_ids,_rhp_ikev2_mobike_srch_n_info_cb,&s_pld_ctx);

		if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
			RHP_TRC(0,RHPTRCID_RHPTRCID_IKEV2_RX_MOBIKE_I_INFO_REP_NTFY_PLD_ERR,"xxxxLwE",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,"PROTO_IKE_NOTIFY",s_pld_ctx.notify_error,err);
			goto error;
		}

		err = 0;
	}

	{
		if( s_pld_ctx.rx_cookie2_len == 0 ){

			RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_INFO_REP_MOBIKE_NOT_RT_CK_NO_COOKIE2,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);

			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_RX_INFO_REP_INVALID_COOKIE2_LEN,"VPK",vpn,ikesa,rx_resp_ikemesg);

			err = RHP_STATUS_IKEV2_MOBIKE_RT_CK_INVALID_COOKIE2;
			goto error;
		}

		if( s_pld_ctx.rx_cookie2_len != RHP_IKEV2_MOBIKE_COOKIE2_LEN ||
				memcmp(s_pld_ctx.rx_cookie2,tx_cookie2->cookie2,RHP_IKEV2_MOBIKE_COOKIE2_LEN)){

			RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_INFO_REP_MOBIKE_NOT_RT_CK_COOKIE2_NOT_MATCHED,"xxxxpp",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,s_pld_ctx.rx_cookie2_len,s_pld_ctx.rx_cookie2,RHP_IKEV2_MOBIKE_COOKIE2_LEN,tx_cookie2->cookie2);

			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_RX_INFO_REP_INVALID_COOKIE2,"VPKpp",vpn,ikesa,rx_resp_ikemesg,s_pld_ctx.rx_cookie2_len,s_pld_ctx.rx_cookie2,RHP_IKEV2_MOBIKE_COOKIE2_LEN,tx_cookie2->cookie2);

			err = RHP_STATUS_IKEV2_MOBIKE_RT_CK_INVALID_COOKIE2;
			goto error;
		}
	}


	if( s_pld_ctx.nat_t_notify_found ){

		RHP_TRC(0,RHP_LOG_ID_IKE_MOBIKE_I_RX_INFO_REP_NAT_T_PROC,"xxxxddddW",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,rhp_gcfg_ikev2_mobike_dynamically_disable_nat_t,vpn->nat_t_info.exec_nat_t,rx_resp_ikemesg->nat_t_detected,rx_resp_ikemesg->nat_t_behind_a_nat,vpn->origin_peer_port);

		if( vpn->nat_t_info.exec_nat_t && !rx_resp_ikemesg->nat_t_detected ){

			//
			// [CAUTION]
			//
			//  Even though vpn->nat_t_info.exec_nat_t is disabled here, the initiator will keep transmitting
			//  IKEv2 requests from the NAT-T port (4500). This is for an inte-op consideration.
			//  See vpn->nat_t_info.use_nat_t_port.
			//
			//  On the other hand, ESP packets will be transmitted from the RAW socket (Non UDP capsuled).
			//
			if( rhp_gcfg_ikev2_mobike_dynamically_disable_nat_t ){

				vpn->nat_t_info.exec_nat_t = 0;

				if( !vpn->nat_t_info.use_nat_t_port ){
					vpn->peer_addr.port = vpn->origin_peer_port;
				}

				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_NAT_T_DYN_DISABLED,"VPKW",vpn,ikesa,rx_resp_ikemesg,vpn->peer_addr.port);
			}

			ikesa->timers->quit_nat_t_keep_alive_timer(vpn,ikesa);

		}else if( !vpn->nat_t_info.exec_nat_t && rx_resp_ikemesg->nat_t_detected ){

			vpn->nat_t_info.exec_nat_t = 1;

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_NAT_T_DYN_ENABLED,"VPKW",vpn,ikesa,rx_resp_ikemesg,vpn->peer_addr.port);

	  	ikesa->timers->start_nat_t_keep_alive_timer(vpn,ikesa,nat_t_keep_alive_interval);
		}

		vpn->nat_t_info.behind_a_nat = rx_resp_ikemesg->nat_t_behind_a_nat;

	}else{

		RHP_TRC(0,RHP_LOG_ID_IKE_MOBIKE_I_RX_INFO_REP_NO_NAT_T_NOTIFY_PLD,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
	}


	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_RX_INFO_REP,"VPK",vpn,ikesa,rx_resp_ikemesg);

ignore:
	_rhp_ikev2_mobike_srch_clear_ctx(&s_pld_ctx);

	if( tx_cookie2 ){
		rhp_ikev2_mobike_free_tx_cookie2(tx_cookie2);
	}

  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_INFO_REP_RTRN,"xxxxd",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,vpn->mobike.init.rt_ck_pending);
	return 0;


error:

	if( err == RHP_STATUS_IKEV2_MOBIKE_RT_CK_INVALID_COOKIE2 ){
		RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_RX_INVALID_PEER_COOKIE2,"VPK",vpn,ikesa,rx_resp_ikemesg);
	}
	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_RX_INFO_REP_ERR,"VPKE",vpn,ikesa,rx_resp_ikemesg,err);

	if( err ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
	}

	_rhp_ikev2_mobike_srch_clear_ctx(&s_pld_ctx);

	if( tx_cookie2 ){
		rhp_ikev2_mobike_free_tx_cookie2(tx_cookie2);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_INFO_REP_ERR,"xxxxE",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,err);
	return err;
}


int rhp_ikev2_mobike_rx_resp_rt_ck_addrs(rhp_packet* rx_pkt,rhp_vpn* vpn)
{
	if( ((rx_pkt->type == RHP_PKT_IPV4_IKE &&
			  vpn->mobike.resp.rt_ck_pend_peer_addr.addr_family == AF_INET &&
			  rx_pkt->l3.iph_v4->src_addr == vpn->mobike.resp.rt_ck_pend_peer_addr.addr.v4 &&
			  rx_pkt->l3.iph_v4->dst_addr == vpn->mobike.resp.rt_ck_pend_local_if_info.addr.v4) ||
			 (rx_pkt->type == RHP_PKT_IPV6_IKE &&
				vpn->mobike.resp.rt_ck_pend_peer_addr.addr_family == AF_INET6 &&
			  rhp_ipv6_is_same_addr(rx_pkt->l3.iph_v6->src_addr,vpn->mobike.resp.rt_ck_pend_peer_addr.addr.v6) &&
			  rhp_ipv6_is_same_addr(rx_pkt->l3.iph_v6->dst_addr,vpn->mobike.resp.rt_ck_pend_local_if_info.addr.v6))) &&
			(rx_pkt->l4.udph->src_port == vpn->mobike.resp.rt_ck_pend_peer_addr.port) ){

		return 1;
	}

	return 0;
}

static int _rhp_ikev2_rx_mobike_r_info_rep(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err = -EINVAL;
	rhp_mobike_srch_plds_ctx s_pld_ctx;
	rhp_vpn_mobike_cookie2* tx_cookie2 = NULL;
	rhp_packet* rx_pkt = rx_resp_ikemesg->rx_pkt;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REP,"xxxxdd",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,vpn->exec_mobike,vpn->mobike.resp.rt_ck_pending);

	memset(&s_pld_ctx,0,sizeof(rhp_mobike_srch_plds_ctx));

  if( rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
   		rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){

  	RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


  if( !vpn->exec_mobike ){

  	err = 0;
		RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REP_MOBIKE_DISALBED,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
  	goto ignore;
  }

  if( !vpn->mobike.resp.rt_ck_pending ){

  	err = 0;
		RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REP_MOBIKE_RT_CK_NOT_PENDING,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
  	goto ignore;
  }


  {
		rhp_vpn_mobike_cookie2* tx_cookie2_p = NULL;

		tx_cookie2 = vpn->mobike.resp.rt_ck_cookie2_head;
  	while( tx_cookie2 ){

  		if( tx_cookie2->mesg_id_valid &&
  				tx_cookie2->mesg_id == rx_resp_ikemesg->get_mesg_id(rx_resp_ikemesg) ){
  			break;
  		}

  		tx_cookie2_p = tx_cookie2;
  		tx_cookie2 = tx_cookie2->next;
  	}

  	if( tx_cookie2 == NULL ){
    	err = 0;
  		RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REP_MOBIKE_RT_CK_NOT_FOUND_PEND_COOKIE2_BY_MESG_ID,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
    	goto ignore;
  	}

  	if( tx_cookie2_p ){
  		tx_cookie2_p->next = tx_cookie2->next;
  	}else{
  		vpn->mobike.resp.rt_ck_cookie2_head = tx_cookie2->next;
  	}

		RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REP_MOBIKE_RT_CK_FOUND_PEND_COOKIE2_BY_MESG_ID,"xxxxxU",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,tx_cookie2,tx_cookie2->mesg_id);
  }



  s_pld_ctx.vpn = vpn;
	s_pld_ctx.ikesa = ikesa;

	{
		s_pld_ctx.dup_flag = 0;
		u16 mobike_n_ids[2] = { RHP_PROTO_IKE_NOTIFY_ST_COOKIE2,
														RHP_PROTO_IKE_NOTIFY_RESERVED};

		err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
				rhp_ikev2_mesg_srch_cond_n_mesg_ids,mobike_n_ids,_rhp_ikev2_mobike_srch_n_info_cb,&s_pld_ctx);

		if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
			RHP_TRC(0,RHPTRCID_RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REP_NTFY_PLD_ERR,"xxxxLwE",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,"PROTO_IKE_NOTIFY",s_pld_ctx.notify_error,err);
			goto error;
		}

		err = 0;
	}


	if( s_pld_ctx.rx_cookie2_len == 0 ){

		RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REP_MOBIKE_NOT_RT_CK_NO_COOKIE2,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_RX_INFO_REP_INVALID_COOKIE2_LEN,"VPK",vpn,ikesa,rx_resp_ikemesg);

		err = RHP_STATUS_IKEV2_MOBIKE_RT_CK_INVALID_COOKIE2;
		goto error;
	}

	if( s_pld_ctx.rx_cookie2_len != RHP_IKEV2_MOBIKE_COOKIE2_LEN ||
			memcmp(s_pld_ctx.rx_cookie2,tx_cookie2->cookie2,RHP_IKEV2_MOBIKE_COOKIE2_LEN)){

		RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REP_MOBIKE_NOT_RT_CK_COOKIE2_NOT_MATCHED,"xxxxpp",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,s_pld_ctx.rx_cookie2_len,s_pld_ctx.rx_cookie2,RHP_IKEV2_MOBIKE_COOKIE2_LEN,tx_cookie2->cookie2);

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_RX_INFO_REP_INVALID_COOKIE2,"VPKpp",vpn,ikesa,rx_resp_ikemesg,s_pld_ctx.rx_cookie2_len,s_pld_ctx.rx_cookie2,RHP_IKEV2_MOBIKE_COOKIE2_LEN,tx_cookie2->cookie2);

		err = RHP_STATUS_IKEV2_MOBIKE_RT_CK_INVALID_COOKIE2;
		goto error;
	}


	if( rhp_ikev2_mobike_rx_resp_rt_ck_addrs(rx_pkt,vpn) ){

		_rhp_ikev2_mobike_r_update_sa_addrs(vpn,rx_resp_ikemesg);

	}else{

		if( rx_pkt->type == RHP_PKT_IPV4_IKE ){
			RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REP_MOBIKE_NOT_RT_CK_ADDR_NOT_MATCHED,"xxxx4444WW",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,rx_pkt->l3.iph_v4->src_addr,vpn->mobike.resp.rt_ck_pend_peer_addr.addr.v4,rx_pkt->l3.iph_v4->dst_addr,vpn->mobike.resp.rt_ck_pend_local_if_info.addr.v4,rx_pkt->l4.udph->src_port,vpn->mobike.resp.rt_ck_pend_peer_addr.port);
		}else if( rx_pkt->type == RHP_PKT_IPV6_IKE ){
			RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REP_MOBIKE_NOT_RT_CK_ADDR_NOT_MATCHED_V6,"xxxx6666WW",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,rx_pkt->l3.iph_v6->src_addr,vpn->mobike.resp.rt_ck_pend_peer_addr.addr.v6,rx_pkt->l3.iph_v6->dst_addr,vpn->mobike.resp.rt_ck_pend_local_if_info.addr.v6,rx_pkt->l4.udph->src_port,vpn->mobike.resp.rt_ck_pend_peer_addr.port);
		}
	}

	vpn->mobike.resp.rt_ck_pending--;

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_RX_INFO_REP,"VPK",vpn,ikesa,rx_resp_ikemesg);

ignore:
	_rhp_ikev2_mobike_srch_clear_ctx(&s_pld_ctx);

	if( tx_cookie2 ){
		rhp_ikev2_mobike_free_tx_cookie2(tx_cookie2);
	}

  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REP_RTRN,"xxxxd",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,vpn->mobike.resp.rt_ck_pending);
	return 0;


error:

	if( err == RHP_STATUS_IKEV2_MOBIKE_RT_CK_INVALID_COOKIE2 ){
		RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_RX_INVALID_PEER_COOKIE2,"VPK",vpn,ikesa,rx_resp_ikemesg);
	}
	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_R_RX_INFO_REP_ERR,"VPKE",vpn,ikesa,rx_resp_ikemesg,err);

	if( err ){
		rhp_ikesa_set_state(ikesa,RHP_IKESA_STAT_DELETE_WAIT);
		ikesa->timers->schedule_delete(vpn,ikesa,0);
	}

	_rhp_ikev2_mobike_srch_clear_ctx(&s_pld_ctx);

	if( tx_cookie2 ){
		rhp_ikev2_mobike_free_tx_cookie2(tx_cookie2);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REP_ERR,"xxxxE",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,err);
	return err;
}


int rhp_ikev2_rx_mobike_req(rhp_ikev2_mesg* rx_req_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err = -EINVAL;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_req_ikemesg->get_exchange_type(rx_req_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_REQ,"xxLdGxLb",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_resp_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

	if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ||
			exchange_type == RHP_PROTO_IKE_EXCHG_SESS_RESUME ){

		err = 0;
  	goto error;

	}else if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_AUTH ){

		if( !RHP_PROTO_IKE_HDR_INITIATOR(rx_req_ikemesg->rx_pkt->app.ikeh->flag) ){
			err = RHP_STATUS_INVALID_MSG;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_REQ_INVALID_MESG1,"xx",rx_req_ikemesg,vpn);
			goto error;
	  }
	}

  if( !rx_req_ikemesg->decrypted ){
  	err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_REQ_NOT_DECRYPTED,"xx",rx_req_ikemesg,vpn);
  	goto error;
  }

	if( my_ikesa_spi == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

	ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
	if( ikesa == NULL ){
		err = -ENOENT;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_REQ_NO_IKESA,"xxLdG",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
		goto error;
	}

	if( ikesa->state != RHP_IKESA_STAT_ESTABLISHED && ikesa->state != RHP_IKESA_STAT_REKEYING ){
		err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_REQ_IKESA_STATE_NOT_INTERESTED,"xxLdGLd",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state);
		goto error;
	}

  if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_AUTH ){

  	err = _rhp_ikev2_rx_mobike_r_ike_auth_req(vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
  	if( err ){
    	RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_IKE_AUTH_REQ_CALL_ERR,"xxxE",rx_req_ikemesg,vpn,tx_resp_ikemesg,err);
  		goto error;
  	}

  }else if( exchange_type == RHP_PROTO_IKE_EXCHG_INFORMATIONAL ){

  	if( vpn->origin_side == RHP_IKE_RESPONDER ){

  		err = _rhp_ikev2_rx_mobike_r_info_req(vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
    	if( err ){
      	RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REQ_CALL_ERR,"xxxE",rx_req_ikemesg,vpn,tx_resp_ikemesg,err);
    		goto error;
    	}

  	}else{

  		err = _rhp_ikev2_rx_mobike_i_info_req(vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
    	if( err ){
      	RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_INFO_REQ_CALL_ERR,"xxxE",rx_req_ikemesg,vpn,tx_resp_ikemesg,err);
    		goto error;
    	}
  	}
  }

  err = 0;

error:
	if( err ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_RX_REQ_ERR,"VPKE",vpn,ikesa,rx_req_ikemesg,err);
	}
	RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_REQ_RTRN,"xxxE",rx_req_ikemesg,vpn,tx_resp_ikemesg,err);
  return err;
}


int rhp_ikev2_rx_mobike_rep(rhp_ikev2_mesg* rx_resp_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err = -EINVAL;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_resp_ikemesg->get_exchange_type(rx_resp_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_REP,"xxLdGxLb",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_req_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

	if( my_ikesa_spi == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

	ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
	if( ikesa == NULL ){
		err = -ENOENT;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_REP_NO_IKESA,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
		goto error;
	}

	if( exchange_type != RHP_PROTO_IKE_EXCHG_IKE_SA_INIT &&
			exchange_type != RHP_PROTO_IKE_EXCHG_SESS_RESUME){

	  if( !rx_resp_ikemesg->decrypted ){
	  	err = 0;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_REP_NOT_DECRYPTED,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
	  	goto error;
	  }

		if( ikesa->state != RHP_IKESA_STAT_ESTABLISHED && ikesa->state != RHP_IKESA_STAT_REKEYING ){
			err = 0;
			RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_REP_IKESA_STATE_NOT_INTERESTED,"xxLdGLd",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state);
			goto error;
		}
	}


	if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ||
			exchange_type == RHP_PROTO_IKE_EXCHG_SESS_RESUME ){

		if( RHP_PROTO_IKE_HDR_INITIATOR(rx_resp_ikemesg->rx_pkt->app.ikeh->flag) ){
			err = RHP_STATUS_INVALID_MSG;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_REP_INVALID_MESG_IKE_SA_INIT_NOT_RESPONDER,"xx",rx_resp_ikemesg,vpn);
			goto error;
	  }

		err = _rhp_ikev2_new_pkt_mobike_i_ike_auth(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
		if( err ){
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_REP_IKE_SA_INIT_NEW_PKT_ERR,"xxE",rx_resp_ikemesg,vpn,err);
			goto error;
		}

	}else if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_AUTH ){

		if( RHP_PROTO_IKE_HDR_INITIATOR(rx_resp_ikemesg->rx_pkt->app.ikeh->flag) ){
			err = RHP_STATUS_INVALID_MSG;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_REP_INVALID_MESG_IKE_AUTH_NOT_RESPONDER,"xx",rx_resp_ikemesg,vpn);
			goto error;
	  }

		err = _rhp_ikev2_rx_mobike_i_ike_auth_rep(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
		if( err ){
    	RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_IKE_AUTH_REP_CALL_ERR,"xxxE",rx_resp_ikemesg,vpn,tx_req_ikemesg,err);
  		goto error;
		}

  }else if( exchange_type == RHP_PROTO_IKE_EXCHG_INFORMATIONAL ){

  	if( vpn->origin_side == RHP_IKE_INITIATOR ){

  		// Initiator...
  		err = _rhp_ikev2_rx_mobike_i_info_rep(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
    	if( err ){
      	RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_I_INFO_REP_CALL_ERR,"xxxE",rx_resp_ikemesg,vpn,tx_req_ikemesg,err);
    		goto error;
    	}

  	}else{

  		// Responder
  		err = _rhp_ikev2_rx_mobike_r_info_rep(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
    	if( err ){
      	RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_R_INFO_REP_CALL_ERR,"xxxE",rx_resp_ikemesg,vpn,tx_req_ikemesg,err);
    		goto error;
    	}
  	}
  }

  err = 0;

error:
	if( err ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_RX_REP_ERR,"VPKE",vpn,ikesa,rx_resp_ikemesg,err);
	}
	RHP_TRC(0,RHPTRCID_IKEV2_RX_MOBIKE_REP_RTRN,"xxxE",rx_resp_ikemesg,vpn,tx_req_ikemesg,err);
  return err;
}


void rhp_ikev2_mobike_free_path_maps(rhp_vpn* vpn)
{
	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_FREE_PATH_MAPS,"xLd",vpn,"IKE_SIDE",vpn->origin_side);

	if( vpn->origin_side == RHP_IKE_INITIATOR ){

		int i;

		for( i = 0; i < vpn->mobike.init.cand_path_maps_num; i++){

			rhp_mobike_path_map* pmap = &(vpn->mobike.init.cand_path_maps[i]);

			if( pmap->rx_probe_pend_pkt_ref ){
				rhp_pkt_unhold(pmap->rx_probe_pend_pkt_ref);
				pmap->rx_probe_pend_pkt_ref = NULL;
			}
		}

		if( vpn->mobike.init.cand_path_maps ){

			_rhp_free(vpn->mobike.init.cand_path_maps);

			vpn->mobike.init.cand_path_maps_num = 0;
			vpn->mobike.init.cand_path_maps = NULL;
		}
	}

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_FREE_PATH_MAPS_RTRN,"x",vpn);
	return;
}

static int _rhp_ikev2_mobike_i_active_src_addr(rhp_ifc_addr* ifc_addr)
{
	if( (ifc_addr->addr.addr_family == AF_INET &&
			 ifc_addr->addr.addr.v4 &&
			 !rhp_ipv4_is_loopback(ifc_addr->addr.addr.v4)) ||
			(ifc_addr->addr.addr_family == AF_INET6 &&
			 !rhp_ipv6_addr_null(ifc_addr->addr.addr.v6) &&
			 !rhp_ipv6_is_loopback(ifc_addr->addr.addr.v6)) ){

		return 1;
	}

	return 0;
}

static int _rhp_ikev2_mobike_i_valid_src_dst_pair(rhp_ifc_addr* my_ifc_addr,rhp_ip_addr* peer_addr)
{
	// Don't trust the IP address value. This may be changed or may be zero.
	if( peer_addr->addr_family == my_ifc_addr->addr.addr_family &&
			_rhp_ikev2_mobike_i_active_src_addr(my_ifc_addr) ){

		int paddr_flag, maddr_flag;

		if( my_ifc_addr->addr.addr_family == AF_INET ){

			paddr_flag = rhp_ipv4_is_linklocal(peer_addr->addr.v4);
			maddr_flag = rhp_ipv4_is_linklocal(my_ifc_addr->addr.addr.v4);

			if( (paddr_flag && !maddr_flag) || (!paddr_flag && maddr_flag) ){
				return 0;
			}

		}else if( my_ifc_addr->addr.addr_family == AF_INET6 ){

			paddr_flag = rhp_ipv6_is_linklocal(peer_addr->addr.v6);
			maddr_flag = rhp_ipv6_is_linklocal(my_ifc_addr->addr.addr.v6);

			if( (paddr_flag && !maddr_flag) || (!paddr_flag && maddr_flag) ||
					(paddr_flag && maddr_flag && peer_addr->ipv6_scope_id != my_ifc_addr->addr.ipv6_scope_id ) ){
				return 0;
			}

		}else{
			return 0;
		}

		return 1;
	}

	return 0;
}

static void _rhp_ikev2_mobike_i_clear_cand_path_maps_res(rhp_vpn* vpn)
{
	if( vpn->mobike.init.cand_path_maps_result ){

		_rhp_free(vpn->mobike.init.cand_path_maps_result);

		vpn->mobike.init.cand_path_maps_result = NULL;
		vpn->mobike.init.cand_path_maps_num_result = 0;
	}
}

static int _rhp_ikev2_mobike_i_build_path_maps(rhp_vpn* vpn,rhp_vpn_realm* rlm)
{
	int err = -EINVAL;
	int my_if_num = 0;
	int peers_num = vpn->mobike.init.additional_addrs_num;
	rhp_cfg_if* cfg_if = NULL;
	rhp_ip_addr_list* peer_additional_addr = NULL;
	int pmap_num, i, end;
	rhp_ip_addr_list *peer_addr_head = NULL,*peer_addr_tail = NULL, *peer_addr_tmp;
	rhp_ip_addr_list cfg_primary_peer_addr;
	rhp_ip_addr_list cfg_secondary_peer_addr;
	rhp_ip_addr_list additional_addr_cache;
	rhp_ifc_addr* my_ifc_addr = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_BUILD_PATH_MAPS,"xxd",vpn,rlm,peers_num);

	memset(&cfg_primary_peer_addr,0,sizeof(rhp_ip_addr_list));
	cfg_primary_peer_addr.ip_addr.addr_family = AF_UNSPEC;
	memset(&cfg_secondary_peer_addr,0,sizeof(rhp_ip_addr_list));
	cfg_secondary_peer_addr.ip_addr.addr_family = AF_UNSPEC;
	memset(&additional_addr_cache,0,sizeof(rhp_ip_addr_list));
	additional_addr_cache.ip_addr.addr_family = AF_UNSPEC;

	if( vpn->cfg_peer == NULL ){
		err = -ENOENT;
		goto error;
	}

	if( !rhp_ip_addr_null(&(vpn->cfg_peer->primary_addr)) ){

		memcpy(&(cfg_primary_peer_addr.ip_addr),&(vpn->cfg_peer->primary_addr),sizeof(rhp_ip_addr));

		if( peer_addr_head == NULL ){
			peer_addr_head = &cfg_primary_peer_addr;
		}else{
			peer_addr_tail->next = &cfg_primary_peer_addr;
		}
		peer_addr_tail = &cfg_primary_peer_addr;

		peers_num++;
	}

	if( !rhp_ip_addr_null(&(vpn->cfg_peer->secondary_addr)) ){

		memcpy(&(cfg_secondary_peer_addr.ip_addr),&(vpn->cfg_peer->secondary_addr),sizeof(rhp_ip_addr));

		if( peer_addr_head == NULL ){
			peer_addr_head = &cfg_secondary_peer_addr;
		}else{
			peer_addr_tail->next = &cfg_secondary_peer_addr;
		}
		peer_addr_tail = &cfg_secondary_peer_addr;

		peers_num++;
	}

	if( !rhp_ip_addr_null(&(vpn->cfg_peer->mobike_additional_addr_cache)) ){

		memcpy(&(additional_addr_cache.ip_addr),&(vpn->cfg_peer->mobike_additional_addr_cache),sizeof(rhp_ip_addr));

		if( peer_addr_head == NULL ){
			peer_addr_head = &additional_addr_cache;
		}else{
			peer_addr_tail->next = &additional_addr_cache;
		}
		peer_addr_tail = &additional_addr_cache;

		peers_num++;
	}

	{
		cfg_if = rlm->my_interfaces;
	  while( cfg_if ){

	  	if( cfg_if->ifc ){

	  		my_ifc_addr = cfg_if->ifc->ifc_addrs;

	  		while( my_ifc_addr ){

	  			if( _rhp_ikev2_mobike_i_active_src_addr(my_ifc_addr) ){
	  				my_if_num++;
	  			}

	  			my_ifc_addr = my_ifc_addr->lst_next;
	  		}
	    }

	  	cfg_if = cfg_if->next;
	  }
	}


	pmap_num = peers_num * my_if_num;

	if( pmap_num == 0 ){
		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_BUILD_PATH_MAPS_NO_PMAP_NUM,"xx",vpn,rlm);
		goto error;
	}

	{
		if( vpn->mobike.init.cand_path_maps ){
			rhp_ikev2_mobike_free_path_maps(vpn);
		}

		vpn->mobike.init.cand_path_maps
		= (rhp_mobike_path_map*)_rhp_malloc(sizeof(rhp_mobike_path_map)*pmap_num);

		if( vpn->mobike.init.cand_path_maps == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		memset(vpn->mobike.init.cand_path_maps,0,sizeof(rhp_mobike_path_map)*pmap_num);
	}


	end = 0;
	peer_addr_tmp = peer_addr_head;
	peer_additional_addr = vpn->mobike.init.additional_addrs;

	for( i = 0; i < peers_num; i++ ){

		int j;
		rhp_ip_addr peer_addr;
		int peer_type = 0;
		rhp_mobike_path_map* pmap;

		memset(&peer_addr,0,sizeof(rhp_ip_addr));
		peer_addr.addr_family = AF_UNSPEC;

		if( peer_addr_tmp ){

			memcpy(&peer_addr,&(peer_addr_tmp->ip_addr),sizeof(rhp_ip_addr));
			peer_type = RHP_MOBIKE_PEER_CFG;

			peer_addr_tmp = peer_addr_tmp->next;
		}

		if( peer_addr.addr_family == AF_UNSPEC ){

			if( peer_additional_addr ){

				if( peer_additional_addr->ip_addr.addr_family == AF_INET ||
						peer_additional_addr->ip_addr.addr_family == AF_INET6 ){

					memcpy(&peer_addr,&(peer_additional_addr->ip_addr),sizeof(rhp_ip_addr));
					peer_type = RHP_MOBIKE_PEER_ADDITIONAL;
				}

				peer_additional_addr = peer_additional_addr->next;
			}
		}

		if( peer_addr.addr_family == AF_UNSPEC ){
			break;
		}


		for( j = 0; j < pmap_num; j++ ){

			pmap = &(vpn->mobike.init.cand_path_maps[j]);

			if( !rhp_ip_addr_cmp_ip_only(&(pmap->peer_addr),&peer_addr) ){
				goto next_peer_addr;
			}
		}


		if( rhp_gcfg_ikev2_mobike_rt_check_on_nat_t_port &&
				peer_addr.port == htons(rhp_gcfg_ike_port) ){

			peer_addr.port = htons(rhp_gcfg_ike_port_nat_t); // The peer node is a responder!
		}

		if( peer_addr.port == 0 ){
			peer_addr.port = vpn->peer_addr.port;
		}


		cfg_if = rlm->my_interfaces;
	  while( cfg_if ){

	  	if( cfg_if->addr_family != AF_UNSPEC &&
	  			cfg_if->addr_family != peer_addr.addr_family ){
	  		goto next_cfg_if;
	  	}

	  	if( cfg_if->ifc ){

				RHP_LOCK(&(cfg_if->ifc->lock));

	  		my_ifc_addr = cfg_if->ifc->ifc_addrs;
	  		while( my_ifc_addr ){

					pmap = &(vpn->mobike.init.cand_path_maps[vpn->mobike.init.cand_path_maps_num]);

					// Don't trust the IP address value. This may be changed or may be zero.

					if( _rhp_ikev2_mobike_i_valid_src_dst_pair(my_ifc_addr,&peer_addr) ){

						if( rhp_ifc_copy_to_if_entry(cfg_if->ifc,&(pmap->my_if_info),
									my_ifc_addr->addr.addr_family,my_ifc_addr->addr.addr.raw) ){

							goto next_ifc_addr;
						}

						memcpy(&(pmap->peer_addr),&peer_addr,sizeof(rhp_ip_addr));
						pmap->peer_type = peer_type;

						vpn->mobike.init.cand_path_maps_num++;

						RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_BUILD_PATH_MAPS_PMAP_INFO,"xxxdd",vpn,rlm,pmap,vpn->mobike.init.cand_path_maps_num,pmap->peer_type);
						rhp_if_entry_dump("_rhp_ikev2_mobike_i_build_path_maps",&(pmap->my_if_info));
						rhp_ip_addr_dump("_rhp_ikev2_mobike_i_build_path_maps",&(pmap->peer_addr));

						if( my_ifc_addr->addr.addr_family == AF_INET ){
							RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_BUILD_PATH_MAP,"Vdd44W",vpn,vpn->mobike.init.cand_path_maps_num,pmap->my_if_info.if_index,pmap->my_if_info.addr.v4,pmap->peer_addr.addr.v4,pmap->peer_addr.port);
						}else if( my_ifc_addr->addr.addr_family == AF_INET6 ){
							RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_BUILD_PATH_MAP_V6,"Vdd66W",vpn,vpn->mobike.init.cand_path_maps_num,pmap->my_if_info.if_index,pmap->my_if_info.addr.v6,pmap->peer_addr.addr.v6,pmap->peer_addr.port);
						}

						if( vpn->mobike.init.cand_path_maps_num >= pmap_num ){
							end = 1;
							break;
						}
					}

next_ifc_addr:
					my_ifc_addr = my_ifc_addr->lst_next;
	  		}

				RHP_UNLOCK(&(cfg_if->ifc->lock));
	  	}

next_cfg_if:
	  	if( end ){
				break;
			}

	  	cfg_if = cfg_if->next;
	  }

next_peer_addr:
		if( end ){
			break;
		}
	}

	if( vpn->mobike.init.cand_path_maps_num == 0 ){
		err = -ENOENT;
		goto error;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_BUILD_PATH_MAPS_RTRN,"xxd",vpn,rlm,vpn->mobike.init.cand_path_maps_num);
	return 0;

error:

	if( vpn->mobike.init.cand_path_maps ){
		rhp_ikev2_mobike_free_path_maps(vpn);
	}

	_rhp_ikev2_mobike_i_clear_cand_path_maps_res(vpn);

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_BUILD_PATH_MAP_ERR,"VE",vpn,err);

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_BUILD_PATH_MAPS_ERR,"xxE",vpn,rlm,err);
	return err;
}

int rhp_ikev2_mobike_i_rx_probe_pkt(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_packet* rx_pkt)
{
	int err = -EINVAL;
	rhp_proto_ike *ikeh_rep = rx_pkt->app.ikeh, *ikeh_req;
	rhp_packet* probe_pkt = RHP_PKT_REF(vpn->mobike.init.tx_probe_pkt_ref);
	rhp_mobike_path_map* pmap = NULL;
	int i;

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RX_PROBE_PKT,"xxxx",vpn,ikesa,rx_pkt,probe_pkt);

	if( probe_pkt == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	if( rx_pkt->type != RHP_PKT_IPV4_IKE &&
			rx_pkt->type != RHP_PKT_IPV6_IKE ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	if( !vpn->mobike.init.rt_ck_pending ){
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RX_PROBE_PKT_NOT_RT_CK_PENDING,"xxx",vpn,ikesa,rx_pkt);
		goto ignored;
	}

  if( probe_pkt->l4.udph->src_port == htons(rhp_gcfg_ike_port_nat_t) ){
  	ikeh_req = (rhp_proto_ike*)(probe_pkt->app.raw + RHP_PROTO_NON_ESP_MARKER_SZ);
  }else{
  	ikeh_req = (rhp_proto_ike*)(probe_pkt->app.raw);
  }


  if( memcmp(ikeh_req->init_spi,ikeh_rep->init_spi,RHP_PROTO_IKE_SPI_SIZE) ||
  		memcmp(ikeh_req->resp_spi,ikeh_rep->resp_spi,RHP_PROTO_IKE_SPI_SIZE) ){
  	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RX_PROBE_PKT_SPI_NOT_MATCHED,"xxxGG",vpn,ikesa,rx_pkt,ikeh_req->init_spi,ikeh_req->resp_spi);
  	goto ignored;
  }

	if( ikeh_req->message_id != ikeh_rep->message_id ){
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RX_PROBE_PKT_MESG_ID_NOT_MATCHED,"xxxUU",vpn,ikesa,rx_pkt,ikeh_req->message_id,ikeh_rep->message_id);
		goto ignored;
	}


	for( i = 0; i < vpn->mobike.init.cand_path_maps_num;i++ ){

		pmap = &(vpn->mobike.init.cand_path_maps[i]);

		if( rx_pkt->rx_if_index == pmap->my_if_info.if_index &&
				((pmap->peer_addr.addr_family == AF_INET &&
					rx_pkt->type == RHP_PKT_IPV4_IKE &&
				  rx_pkt->l3.iph_v4->src_addr == pmap->peer_addr.addr.v4 &&
				  rx_pkt->l3.iph_v4->dst_addr == pmap->my_if_info.addr.v4) ||
				 (pmap->peer_addr.addr_family == AF_INET6 &&
					rx_pkt->type == RHP_PKT_IPV6_IKE &&
					rhp_ipv6_is_same_addr(rx_pkt->l3.iph_v6->src_addr,pmap->peer_addr.addr.v6) &&
					rhp_ipv6_is_same_addr(rx_pkt->l3.iph_v6->dst_addr,pmap->my_if_info.addr.v6))) ){

			pmap->result = 1;
			vpn->mobike.init.cand_path_maps_active++;

			if( pmap->peer_addr.addr_family == AF_INET ){
				RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RX_PROBE_PKT_PMAP_FOUND,"xxxd4W4Wdd",vpn,ikesa,rx_pkt,rx_pkt->rx_if_index,rx_pkt->l3.iph_v4->src_addr,rx_pkt->l4.udph->src_port,rx_pkt->l3.iph_v4->dst_addr,rx_pkt->l4.udph->dst_port,i,vpn->mobike.init.cand_path_maps_active);
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_RX_RT_CK_PROBE_REP,"VPd4W4W",vpn,ikesa,pmap->my_if_info.if_index,pmap->my_if_info.addr.v4,rx_pkt->l4.udph->dst_port,rx_pkt->l3.iph_v4->src_addr,rx_pkt->l4.udph->src_port);
			}else if( pmap->peer_addr.addr_family == AF_INET6 ){
				RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RX_PROBE_PKT_PMAP_FOUND_V6,"xxxd6W6Wdd",vpn,ikesa,rx_pkt,rx_pkt->rx_if_index,rx_pkt->l3.iph_v6->src_addr,rx_pkt->l4.udph->src_port,rx_pkt->l3.iph_v6->dst_addr,rx_pkt->l4.udph->dst_port,i,vpn->mobike.init.cand_path_maps_active);
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_RX_RT_CK_PROBE_REP_V6,"VPd6W6W",vpn,ikesa,pmap->my_if_info.if_index,pmap->my_if_info.addr.v6,rx_pkt->l4.udph->dst_port,rx_pkt->l3.iph_v6->src_addr,rx_pkt->l4.udph->src_port);
			}

			break;
		}

		pmap = NULL;
	}

	if( pmap == NULL ){
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RX_PROBE_PKT_RT_PATH_MAP_NOT_FOUND,"xxx",vpn,ikesa,rx_pkt);
		goto ignored;
	}

	if( pmap->rx_probe_pend_pkt_ref == NULL ){

		rx_pkt->mobike_verified = 1;

		pmap->rx_probe_pend_pkt_ref = rhp_pkt_hold_ref(rx_pkt);

		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RX_PROBE_PKT_MARK_VERIFIED,"xxxx",vpn,ikesa,pmap,rx_pkt);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RX_PROBE_PKT_PENDING_RTRN,"xxxx",vpn,ikesa,rx_pkt,pmap);
	return RHP_STATUS_IKEV2_MOBIKE_RT_CK_PENDING;

ignored:
	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_RX_RT_CK_PROBE_REP_IGNORED,"VP",vpn,ikesa);
	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RX_PROBE_PKT_NOT_INTERESTED_RTRN,"xxx",vpn,ikesa,rx_pkt);
	return RHP_STATUS_IKEV2_MOBIKE_NOT_INTERESTED;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_RX_RT_CK_PROBE_REP_ERR,"VPE",vpn,ikesa,err);
	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RX_PROBE_PKT_PENDING_ERR,"xxxxE",vpn,ikesa,rx_pkt,pmap,err);
	return err;
}


static int _rhp_ikev2_mobike_i_probe_pkt_build_header(rhp_vpn* vpn,
		rhp_packet* pkt,rhp_mobike_path_map* pmap)
{
	int err;
	rhp_proto_udp* udph = pkt->l4.udph;
	int addr_family = pmap->my_if_info.addr_family;
	u8 *src_addr = NULL,*dst_addr = NULL;
	u16 src_port = udph->src_port,dst_port = pmap->peer_addr.port;

	RHP_TRC_FREQ(0,RHPTRCID_RHPTRCID_IKEV2_MOBIKE_I_PROBE_PKT_BUILD_HEADER,"xxx",vpn,pkt,pmap);

	if( rhp_gcfg_ikev2_mobike_rt_check_on_nat_t_port ){

		if( dst_port == htons(rhp_gcfg_ike_port) ){

			dst_port = htons(rhp_gcfg_ike_port_nat_t); // The peer node is a responder!
		}

		if( src_port == vpn->local.port ){

			src_port = vpn->local.port_nat_t;
		}
	}

	src_addr = pmap->my_if_info.addr.raw;
	dst_addr = pmap->peer_addr.addr.raw;

	err = rhp_pkt_rebuild_ip_udp_header(pkt,
					addr_family,src_addr,dst_addr,src_port,dst_port);

	RHP_TRC_FREQ(0,RHPTRCID_RHPTRCID_IKEV2_MOBIKE_I_PROBE_PKT_BUILD_HEADER_RTRN,"xxxE",vpn,pkt,pmap,err);
	return err;
}

static void _rhp_ikev2_mobike_i_tx_probe_pkt(rhp_vpn* vpn,rhp_mobike_path_map* pmap)
{
	int err = -EINVAL;
	rhp_ifc_entry* tx_ifc = NULL;
	rhp_packet* pkt = RHP_PKT_REF(vpn->mobike.init.tx_probe_pkt_ref);
	rhp_packet* pkt_d = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_TX_PROBE_PKT,"xxx",vpn,pmap,pkt);

	if( pkt == NULL ){
		RHP_BUG("");
		return;
	}

	if( pkt->l2.eth->protocol == RHP_PROTO_ETH_IP && pkt->type == RHP_PKT_IPV6_IKE ){
		RHP_BUG("pkt->type == RHP_PKT_IPV6_IKE");
	}else if( pkt->l2.eth->protocol == RHP_PROTO_ETH_IPV6 && pkt->type == RHP_PKT_IPV4_IKE ){
		RHP_BUG("pkt->type == RHP_PKT_IPV4_IKE");
	}

	pkt_d = rhp_pkt_dup(pkt);
	if( pkt_d ){

		tx_ifc = rhp_ifc_get_by_if_idx(pmap->my_if_info.if_index);  // (***)
		if( tx_ifc ){

			rhp_ifc_addr* ifc_addr;

			RHP_LOCK(&(tx_ifc->lock));

			ifc_addr = tx_ifc->get_addr(tx_ifc,pmap->my_if_info.addr_family,pmap->my_if_info.addr.raw);
			if( ifc_addr == NULL ){

				RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_TX_PROBE_PKT_NO_TX_IFC_ADDR,"xx",vpn,pmap);
				RHP_UNLOCK(&(tx_ifc->lock));

			}else{

				err = _rhp_ikev2_mobike_i_probe_pkt_build_header(vpn,pkt_d,pmap);
				if( err ){

					RHP_BUG("%d",err);

					RHP_UNLOCK(&(tx_ifc->lock));
					goto error;
				}

				RHP_UNLOCK(&(tx_ifc->lock));


				pkt_d->tx_ifc = tx_ifc;
				rhp_ifc_hold(pkt_d->tx_ifc);


				// rhp_ifc_is_active(tx_ifc) is internally called. Don't acquire tx_ifc's lock here.
				err = rhp_netsock_send(pkt_d->tx_ifc,pkt_d);
				if( err < 0 ){
					RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_TX_PROBE_PKT_NETSOCK_SEND_ERR,"xxE",vpn,pmap,err);
				}else{
					rhp_ikev2_g_statistics_inc(mobike_init_tx_probe_packets);
				}
			}

		}else{

			RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_TX_PROBE_PKT_NO_TX_IFC,"xx",vpn,pmap);
		}

	}else{

		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_TX_PROBE_PKT_NO_PKT_D,"xx",vpn,pmap);
		rhp_ikev2_g_statistics_inc(tx_ikev2_req_alloc_packet_err);
	}

error:
	if( pkt_d ){

		if( pkt_d->type == RHP_PKT_IPV4_IKE ){
	  	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_TX_PROBE_PKT_DUMP,"Ldxxa","AF",AF_INET,pkt,pkt_d,(pkt_d->tail - pkt_d->l2.raw),RHP_TRC_FMT_A_MAC_IPV4_IKEV2,0,0,pkt_d->l2.raw);
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_ROUTABILITY_CHECK_TX_PROBE_2,"Vsd4W4W",vpn,pmap->my_if_info.if_name,pmap->my_if_info.if_index,pkt_d->l3.iph_v4->src_addr,pkt_d->l4.udph->src_port,pkt_d->l3.iph_v4->dst_addr,pkt_d->l4.udph->dst_port);
	  }else if( pkt_d->type == RHP_PKT_IPV6_IKE ){
	  	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_TX_PROBE_PKT_DUMP_V6,"Ldxxa","AF",AF_INET6,pkt,pkt_d,(pkt_d->tail - pkt_d->l2.raw),RHP_TRC_FMT_A_MAC_IPV6_IKEV2,0,0,pkt_d->l2.raw);
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_ROUTABILITY_CHECK_TX_PROBE_2_V6,"Vsd6W6W",vpn,pmap->my_if_info.if_name,pmap->my_if_info.if_index,pkt_d->l3.iph_v6->src_addr,pkt_d->l4.udph->src_port,pkt_d->l3.iph_v6->dst_addr,pkt_d->l4.udph->dst_port);
	  }else{
	  	RHP_BUG("%d",pkt_d->type);
	  }

		rhp_pkt_unhold(pkt_d);
	}

	if( tx_ifc ){
		rhp_ifc_unhold(tx_ifc); // (***)
	}

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_TX_PROBE_PKT_RTRN,"xxxx",vpn,pmap,pkt,pkt_d);
	return;
}

static rhp_ikev2_mesg* _rhp_ikev2_new_pkt_mobike_i_update_sa_addr(rhp_vpn* vpn,
		rhp_vpn_mobike_cookie2* tx_cookie2,int no_nats_allowed)
{
	int err = -EINVAL;
	rhp_ikev2_mesg* tx_ikemesg = NULL;
  rhp_ikev2_payload* ikepayload = NULL;
  rhp_ikesa* ikesa = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_I_UPDATE_SA_ADDR,"xxd",vpn,tx_cookie2,no_nats_allowed);

	ikesa = _rhp_ikev2_mobike_get_active_ikesa(vpn);


	tx_ikemesg = rhp_ikev2_new_mesg_tx(RHP_PROTO_IKE_EXCHG_INFORMATIONAL,0,0);
	if( tx_ikemesg == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	tx_ikemesg->tx_flag = RHP_IKEV2_SEND_REQ_FLAG_URGENT;
	tx_ikemesg->mobike_update_sa_addr = 1;
	tx_ikemesg->add_nat_t_info = 1;

	if( rhp_gcfg_ikev2_mobike_rt_check_on_nat_t_port ){
		tx_ikemesg->tx_from_nat_t_port = 1;
	}

	{
		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);

		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_UPDATE_SA_ADDRESSES);

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_TX_UPDATE_SA_ADDR_NOTIFY,"VP",vpn,ikesa);
	}

	{
		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
			RHP_BUG("");
			goto error;
		}

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

		ikepayload->ext.n->set_protocol_id(ikepayload,0);

		ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_COOKIE2);

		err = ikepayload->ext.n->set_data(ikepayload,RHP_IKEV2_MOBIKE_COOKIE2_LEN,tx_cookie2->cookie2);
		if( err ){
			RHP_BUG("");
			goto error;
		}

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_TX_COOKIE2_NOTIFY,"VPp",vpn,ikesa,RHP_IKEV2_MOBIKE_COOKIE2_LEN,tx_cookie2->cookie2);
	}


	if( no_nats_allowed ){

		union {
			rhp_proto_ike_notify_no_nats_allowed_v4 v4;
			rhp_proto_ike_notify_no_nats_allowed_v6 v6;
		} n_no_nats_allowed;
		u8* nnat_addr = NULL;
		int nnat_addr_len;

		if( vpn->peer_addr.addr_family == AF_INET ){

			n_no_nats_allowed.v4.dst_addr = vpn->peer_addr.addr.v4;
			n_no_nats_allowed.v4.dst_port = vpn->peer_addr.port;
			n_no_nats_allowed.v4.src_addr = vpn->local.if_info.addr.v4;
			if( vpn->peer_addr.port == htons(rhp_gcfg_ike_port) ){
				n_no_nats_allowed.v4.src_port = vpn->local.port;
			}else{
				n_no_nats_allowed.v4.src_port = vpn->local.port_nat_t;
			}
			nnat_addr_len = sizeof(rhp_proto_ike_notify_no_nats_allowed_v4);
			nnat_addr = (u8*)&n_no_nats_allowed;

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_TX_NO_NATS_ALLOWED_NOTIFY,"VP4W4W",vpn,ikesa,n_no_nats_allowed.v4.src_addr,n_no_nats_allowed.v4.src_port,n_no_nats_allowed.v4.dst_addr,n_no_nats_allowed.v4.dst_port);

		}else if( vpn->peer_addr.addr_family == AF_INET6 ){

			memcpy(n_no_nats_allowed.v6.dst_addr,vpn->peer_addr.addr.v6,16);
			n_no_nats_allowed.v6.dst_port = vpn->peer_addr.port;
			memcpy(n_no_nats_allowed.v6.src_addr,vpn->local.if_info.addr.v6,16);
			if( vpn->peer_addr.port == htons(rhp_gcfg_ike_port) ){
				n_no_nats_allowed.v6.src_port = vpn->local.port;
			}else{
				n_no_nats_allowed.v6.src_port = vpn->local.port_nat_t;
			}
			nnat_addr_len = sizeof(rhp_proto_ike_notify_no_nats_allowed_v6);
			nnat_addr = (u8*)&n_no_nats_allowed;

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_TX_NO_NATS_ALLOWED_NOTIFY_V6,"VP6W6W",vpn,ikesa,n_no_nats_allowed.v6.src_addr,n_no_nats_allowed.v6.src_port,n_no_nats_allowed.v6.dst_addr,n_no_nats_allowed.v6.dst_port);
		}

		if( nnat_addr ){

			if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
				RHP_BUG("");
				goto error;
			}

			tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

			ikepayload->ext.n->set_protocol_id(ikepayload,0);

			ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_NO_NATS_ALLOWED);

			err = ikepayload->ext.n->set_data(ikepayload,nnat_addr_len,nnat_addr);
			if( err ){
				RHP_BUG("");
				goto error;
			}
		}
	}

	rhp_ikev2_g_statistics_inc(mobike_init_tx_update_sa_addr_times);

	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_I_UPDATE_SA_ADDR_RTRN,"xx",vpn,tx_ikemesg);
	return tx_ikemesg;

error:
	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_TX_ERR,"VPE",vpn,ikesa,err);
	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_MOBIKE_I_UPDATE_SA_ADDR_ERR,"x",vpn);
	return NULL;
}


static rhp_mobike_path_map* _rhp_ikev2_mobike_i_select_src_addr_2(int addr_family,rhp_vpn* vpn,rhp_ikesa* ikesa,int* r_idx_r)
{
	int err = -EINVAL;
	rhp_mobike_path_map* pmap_w = NULL;
	int i, r_idx = 0;
	rhp_mobike_path_map* pmap = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_SELECT_SRC_ADDR_2,"Ldxxx","AF",addr_family,vpn,pmap_w,r_idx_r);

	for( i = 0; i < vpn->mobike.init.cand_path_maps_num; i++ ){

		pmap = &(vpn->mobike.init.cand_path_maps[i]);

		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_SELECT_SRC_ADDR_2_PMAP,"xdxddx",vpn,i,pmap,pmap->result,pmap->peer_type,pmap->rx_probe_pend_pkt_ref);
		rhp_if_entry_dump("mobike_i_select_src_addr_2_pmap",&(pmap->my_if_info));
		rhp_ip_addr_dump("mobike_i_select_src_addr_2_pmap",&(pmap->peer_addr));

		if( pmap->result &&
				pmap->peer_addr.addr_family == addr_family ){

			if( pmap_w == NULL ){

				if( rhp_ip_valid_peer_addrs(addr_family,pmap->my_if_info.addr.raw,pmap->peer_addr.addr.raw) ){
					pmap_w = pmap;
					r_idx = i;
				}

			}else{

				rhp_ip_addr pmap_addr,pmap_addr_w;

				if( rhp_ip_addr_cmp_ip_only(&(pmap->peer_addr),&(pmap_w->peer_addr)) ){
					RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_SELECT_SRC_ADDR_2_DIFF_PEER_DST_ADDR,"xxdxx",vpn,ikesa,i,pmap,pmap_w);
					rhp_ip_addr_dump("mobike_i_select_src_addr_2_pmap2",&(pmap->peer_addr));
					rhp_ip_addr_dump("mobike_i_select_src_addr_2_pmap_w2",&(pmap_w->peer_addr));
					break;
				}

				{
					memset(&pmap_addr,0,sizeof(rhp_ip_addr));
					pmap_addr.addr_family = addr_family;
					pmap_addr.prefixlen = pmap->my_if_info.prefixlen;

					memset(&pmap_addr_w,0,sizeof(rhp_ip_addr));
					pmap_addr_w.addr_family = addr_family;
					pmap_addr_w.prefixlen = pmap_w->my_if_info.prefixlen;
				}

				if( addr_family == AF_INET ){

					memcpy(pmap_addr.addr.raw,pmap->my_if_info.addr.raw,4);
					memcpy(pmap_addr_w.addr.raw,pmap_w->my_if_info.addr.raw,4);

					err = rhp_ipv4_cmp_src_addr(
									&pmap_addr,&pmap_addr_w,&(pmap_w->peer_addr));

				}else if( addr_family == AF_INET6 ){

					memcpy(pmap_addr.addr.raw,pmap->my_if_info.addr.raw,16);
					memcpy(pmap_addr_w.addr.raw,pmap_w->my_if_info.addr.raw,16);

					err = rhp_ipv6_cmp_src_addr(
									&pmap_addr,pmap->my_if_info.if_addr_flags,
									&pmap_addr_w,pmap_w->my_if_info.if_addr_flags,&(pmap_w->peer_addr));

				}else{

					err = -1;
				}

				if( err == 1 ){

					pmap_w = pmap;
					r_idx = i;
				} // else pmap_w wins.
			}
		}
	}

	*r_idx_r = r_idx;

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_SELECT_SRC_ADDR_2_RTRN,"xxd",vpn,pmap_w,r_idx);
	return pmap_w;
}

static rhp_mobike_path_map* _rhp_ikev2_mobike_i_select_src_addr(rhp_vpn* vpn,rhp_ikesa* ikesa)
{
	rhp_mobike_path_map* pmap_w = NULL;
	int r_idx = 0;
	int srch_addr_family_seq[2] = {AF_INET6,AF_INET}; // AF_INET6 > AF_INET by default.

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_SELECT_SRC_ADDR,"xxd",vpn,ikesa,vpn->mobike.init.cand_path_maps_num);

	if( !rhp_ip_addr_null(&(vpn->cfg_peer->primary_addr)) &&
			vpn->cfg_peer->primary_addr.addr_family == AF_INET ){

		srch_addr_family_seq[0] = AF_INET;
		srch_addr_family_seq[1] = AF_INET6;
	}

	// First, search srch_addr_family_seq[0] addrs.
	pmap_w = _rhp_ikev2_mobike_i_select_src_addr_2(srch_addr_family_seq[0],vpn,ikesa,&r_idx);
	if( pmap_w ){

		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_SELECT_SRC_ADDR_PATH_FOUND_0,"Ldxxdd","AF",srch_addr_family_seq[0],vpn,pmap_w,pmap_w->peer_type,r_idx);

		if( srch_addr_family_seq[0] == AF_INET6 ){
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_RT_CK_FOUND_NEW_PATH_V6,"VPd66Wd",vpn,ikesa,pmap_w->my_if_info.if_index,pmap_w->my_if_info.addr.v6,pmap_w->peer_addr.addr.v6,pmap_w->peer_addr.port,r_idx);
		}else{
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_RT_CK_FOUND_NEW_PATH,"VPd44Wd",vpn,ikesa,pmap_w->my_if_info.if_index,pmap_w->my_if_info.addr.v4,pmap_w->peer_addr.addr.v4,pmap_w->peer_addr.port,r_idx);
		}
		rhp_if_entry_dump("mobike_i_select_src_addr_0",&(pmap_w->my_if_info));
		rhp_ip_addr_dump("mobike_i_select_src_addr_0",&(pmap_w->peer_addr));

	}else{

		// Next, search srch_addr_family_seq[1] addrs.
		pmap_w = _rhp_ikev2_mobike_i_select_src_addr_2(srch_addr_family_seq[1],vpn,ikesa,&r_idx);
		if( pmap_w ){

			RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_SELECT_SRC_ADDR_PATH_FOUND_1,"Ldxxdd","AF",srch_addr_family_seq[1],vpn,pmap_w,pmap_w->peer_type,r_idx);
			if( srch_addr_family_seq[0] == AF_INET6 ){
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_RT_CK_FOUND_NEW_PATH_V6,"VPd66Wd",vpn,ikesa,pmap_w->my_if_info.if_index,pmap_w->my_if_info.addr.v6,pmap_w->peer_addr.addr.v6,pmap_w->peer_addr.port,r_idx);
			}else{
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_RT_CK_FOUND_NEW_PATH,"VPd44Wd",vpn,ikesa,pmap_w->my_if_info.if_index,pmap_w->my_if_info.addr.v4,pmap_w->peer_addr.addr.v4,pmap_w->peer_addr.port,r_idx);
			}
			rhp_if_entry_dump("mobike_i_select_src_addr_1",&(pmap_w->my_if_info));
			rhp_ip_addr_dump("mobike_i_select_src_addr_1",&(pmap_w->peer_addr));
		}
	}

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_SELECT_SRC_ADDR_RTRN,"xxLdLd",vpn,pmap_w,"AF",srch_addr_family_seq[0],"AF",srch_addr_family_seq[1]);
	return pmap_w;
}

static int _rhp_ikev2_mobike_i_rt_ck_finieshed(rhp_vpn* vpn)
{
	int err = -EINVAL;
	rhp_vpn_realm* rlm = NULL;
	rhp_mobike_path_map* pmap = NULL;
	rhp_ifc_entry* ifc = NULL;
	rhp_ikev2_mesg* tx_ikemesg = NULL;
	rhp_vpn_mobike_cookie2* tx_cookie2 = NULL;
	int no_nats_allowed = 0;
	rhp_ikesa* ikesa = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_FINISHED,"x",vpn);

	ikesa = _rhp_ikev2_mobike_get_active_ikesa(vpn);


	rlm = vpn->rlm;
	if( rlm == NULL ){
		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_FINISHED_NO_RLM,"x",vpn);
		goto error;
	}

	{
		RHP_LOCK(&(rlm->lock));

		if( !_rhp_atomic_read(&(rlm->is_active)) ){
			err = -ENOENT;
			RHP_UNLOCK(&(rlm->lock));
			RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_FINISHED_RLM_NOT_ACTIVE,"xx",vpn,rlm);
			goto error;
		}

		if( !rlm->ikesa.nat_t ){
			no_nats_allowed = 1;
		}

		RHP_UNLOCK(&(rlm->lock));
	}

	if( vpn->mobike.init.cand_path_maps_num < 1 ){
		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_FINISHED_NO_PATH_FOUND,"x",vpn);
		goto error;
	}


	pmap = _rhp_ikev2_mobike_i_select_src_addr(vpn,ikesa);
	if( pmap == NULL ){
		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_FINISHED_NO_PATH_FOUND_2,"x",vpn);
		goto error;
	}


	if( pmap->peer_addr.addr_family != AF_INET &&
			pmap->peer_addr.addr_family != AF_INET6 ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	ifc = rhp_ifc_get_by_if_idx(pmap->my_if_info.if_index);
	if( ifc == NULL ){
		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_FINISHED_NO_IFC,"x",vpn);
		goto error;
	}


	{
		_rhp_ikev2_mobike_update_sa_addrs(vpn,ifc,pmap->my_if_info.addr_family,
				pmap->my_if_info.addr.raw,pmap->peer_addr.addr.raw,pmap->peer_addr.port);

		if( pmap->my_if_info.addr_family == AF_INET ){
			RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_UPDATE_PATH,"Vsd44W",vpn,ifc->if_name,ifc->if_index,pmap->my_if_info.addr.v4,pmap->peer_addr.addr.v4,pmap->peer_addr.port);
		}else if( pmap->my_if_info.addr_family == AF_INET6 ){
			RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_UPDATE_PATH_V6,"Vsd66W",vpn,ifc->if_name,ifc->if_index,pmap->my_if_info.addr.v6,pmap->peer_addr.addr.v6,pmap->peer_addr.port);
		}
	}


	if( pmap->rx_probe_pend_pkt_ref ){

		rhp_packet_ref* rx_pend_pkt_ref = pmap->rx_probe_pend_pkt_ref;
		rhp_packet* rx_pend_pkt = RHP_PKT_REF(rx_pend_pkt_ref);
		pmap->rx_probe_pend_pkt_ref = NULL;

		if( rhp_wts_dispach_ok(RHP_WTS_DISP_LEVEL_HIGH_2,0) ){

			err = rhp_netsock_rx_dispach_packet(rx_pend_pkt);
			if( err ){
				RHP_BUG("%d",err);
				rhp_pkt_unhold(rx_pend_pkt_ref);
				goto error;
			}

		}else{

			RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_FINISHED_DISP_BUSY_ERR,"x",vpn);

			rhp_pkt_unhold(rx_pend_pkt_ref);
			err = -EINVAL;
			goto error;
		}
	}

	{
		tx_cookie2 = _rhp_ikev2_mobike_gen_cookie2(RHP_IKEV2_MOBIKE_COOKIE2_SA_ADDR);
		if( tx_cookie2 == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}


		tx_ikemesg = _rhp_ikev2_new_pkt_mobike_i_update_sa_addr(vpn,tx_cookie2,no_nats_allowed);
		if( tx_ikemesg == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}


		tx_ikemesg->packet_serialized = _rhp_ikev2_mobike_rt_ck_req_completed;

		tx_cookie2->tx_ikemesg = tx_ikemesg;
		rhp_ikev2_hold_mesg(tx_ikemesg);

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_TX_UPDATE_SA_ADDR,"KVPpd",tx_ikemesg,vpn,ikesa,RHP_IKEV2_MOBIKE_COOKIE2_LEN,tx_cookie2->cookie2,no_nats_allowed);

		tx_cookie2->next = vpn->mobike.init.rt_ck_cookie2_head;
		vpn->mobike.init.rt_ck_cookie2_head = tx_cookie2;
		tx_cookie2 = NULL;
	}


	rhp_ikev2_send_request(vpn,NULL,tx_ikemesg,RHP_IKEV2_MESG_HANDLER_MOBIKE);
	rhp_ikev2_unhold_mesg(tx_ikemesg);

	rhp_ifc_unhold(ifc);

	if( vpn->mobike.init.tx_probe_pkt_ref ){
		rhp_pkt_unhold(vpn->mobike.init.tx_probe_pkt_ref);
		vpn->mobike.init.tx_probe_pkt_ref = NULL;
	}


	rhp_http_bus_broadcast_async(vpn->vpn_realm_id,1,1,
			rhp_ui_http_vpn_mobike_i_rt_check_finished_serialize,
			rhp_ui_http_vpn_bus_btx_async_cleanup,(void*)rhp_vpn_hold_ref(vpn)); // (*x*)


	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_FINISHED_RTRN,"x",vpn);
	return 0;


error:

	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_ROUTABILITY_CHECK_ERR,"VE",vpn,err);

	if( ifc ){
		rhp_ifc_unhold(ifc);
	}

	if( tx_ikemesg ){
		rhp_ikev2_unhold_mesg(tx_ikemesg);
	}

	if( tx_cookie2 ){
		rhp_ikev2_mobike_free_tx_cookie2(tx_cookie2);
	}

	if( vpn->mobike.init.tx_probe_pkt_ref ){
		rhp_pkt_unhold(vpn->mobike.init.tx_probe_pkt_ref);
		vpn->mobike.init.tx_probe_pkt_ref = NULL;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_FINISHED_ERR,"xE",vpn,err);
	return err;
}


static void _rhp_ikev2_mobike_i_rt_ck_task(void* ctx);


static void _rhp_ikev2_mobike_i_rt_ck_task_impl(void* ctx /* (rhp_vpn_ref*) */ ,int by_waiting_timer)
{
	int err = -EINVAL;
	rhp_vpn_ref* timer_vpn_ref;
	rhp_vpn* vpn = RHP_VPN_REF(ctx);
	int cur_idx = 0;
	rhp_mobike_path_map* pmap = NULL;
	long ck_interval_msec;
	int tx_probe = 0;
	int finished = 0;
	int waiting_max_retries = 0, waiting_hold_time = 0, waiting_interval = 0;

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_TASK_IMPL,"xd",vpn,by_waiting_timer);

	RHP_LOCK(&(vpn->lock));

	if( !_rhp_atomic_read(&(vpn->is_active)) ){
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_TASK_IMPL_VPN_NOT_ACTIVE,"x",vpn);
		goto error_vpn_l;
	}

	{
		rhp_vpn_realm* rlm = vpn->rlm;
		if( rlm == NULL ){

			err = -ENOENT;

			RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_INIT_TASK_NO_RLM,"x",vpn);
			goto error_vpn_l;
		}


		RHP_LOCK(&(rlm->lock));
		{
			if( !_rhp_atomic_read(&(rlm->is_active)) ){

				err = -ENOENT;

				RHP_UNLOCK(&(rlm->lock));

				RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_TASK_IMPL_RLM_NOT_ACTIVE,"xx",vpn,rlm);
				goto error_vpn_l;
			}

			waiting_hold_time = rlm->mobike.init_hold_time;
			waiting_interval = rlm->mobike.init_hold_ka_interval;
			waiting_max_retries = rlm->mobike.init_hold_ka_max_retries;

			if( by_waiting_timer ){

				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_ROUTABILITY_CHECK_REVOKED,"Vd",vpn,vpn->mobike.init.rt_ck_waiting);

				vpn->mobike.init.cand_path_maps_cur_idx = 0;

				err = _rhp_ikev2_mobike_i_build_path_maps(vpn,rlm);
				if( err ){

					RHP_UNLOCK(&(rlm->lock));

					RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_TASK_IMPL_BUILD_PATH_ERR,"xxE",vpn,rlm,err);
					goto next_waiting_interval;
				}
			}
		}
		RHP_UNLOCK(&(rlm->lock));
	}


	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_TASK_IMPL_VPN_INFO,"xdddddd",vpn,vpn->mobike.init.cand_path_maps_cur_idx,vpn->mobike.init.cand_path_maps_retries,vpn->mobike.init.cand_path_maps_num,waiting_hold_time,waiting_interval,waiting_max_retries);
	vpn->dump("_rhp_ikev2_mobike_i_rt_ck_task",vpn);


	if( vpn->mobike.init.cand_path_maps_cur_idx >= (vpn->mobike.init.cand_path_maps_num - 1) ){

		cur_idx = vpn->mobike.init.cand_path_maps_cur_idx = 0;
		vpn->mobike.init.cand_path_maps_retries++;

	}else{

		cur_idx = (vpn->mobike.init.cand_path_maps_cur_idx + 1);
	}


	if( vpn->mobike.init.cand_path_maps_retries <= rhp_gcfg_ikev2_mobike_rt_check_max_retries ){

		for( ;cur_idx < vpn->mobike.init.cand_path_maps_num; cur_idx++ ){

			pmap = &(vpn->mobike.init.cand_path_maps[cur_idx]);

			if( !pmap->result ){

				RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_TASK_IMPL_TX_PATH,"xxd",vpn,pmap,pmap->peer_type);
				rhp_if_entry_dump("_rhp_ikev2_mobike_i_rt_ck_task",&(pmap->my_if_info));
				rhp_ip_addr_dump("_rhp_ikev2_mobike_i_rt_ck_task",&(pmap->peer_addr));

				_rhp_ikev2_mobike_i_tx_probe_pkt(vpn,pmap);

				tx_probe = 1;
				break;
			}
		}

		if( !tx_probe ){

			RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_TASK_IMPL_NOT_TX_PROBE,"xdd",vpn,vpn->mobike.init.cand_path_maps_active,vpn->mobike.init.cand_path_maps_num);

			finished = 0;
			if( vpn->mobike.init.cand_path_maps_active >= vpn->mobike.init.cand_path_maps_num ){
				finished = 1;
			}
		}

		if( tx_probe || !finished ){

			if( cur_idx >= (vpn->mobike.init.cand_path_maps_num - 1) ){
				ck_interval_msec = (long)rhp_gcfg_ikev2_mobike_rt_check_retry_interval_msec;
				cur_idx = vpn->mobike.init.cand_path_maps_num - 1;
			}else{
				ck_interval_msec = (long)rhp_gcfg_ikev2_mobike_rt_check_interval_msec;
			}

			if( ck_interval_msec > 999 ){
				ck_interval_msec = 999;
			}else if( ck_interval_msec < RHP_IKEV2_MOBIKE_RT_CK_MIN_INTERVAL_MSEC ){
				ck_interval_msec = RHP_IKEV2_MOBIKE_RT_CK_MIN_INTERVAL_MSEC;
			}

			vpn->mobike.init.cand_path_maps_cur_idx = cur_idx;

			timer_vpn_ref = rhp_vpn_hold_ref(vpn);

			err = rhp_timer_oneshot_msec(_rhp_ikev2_mobike_i_rt_ck_task,timer_vpn_ref,ck_interval_msec);
			if( err ){
				RHP_BUG("%d",err);
				rhp_vpn_unhold(timer_vpn_ref);
				goto error_vpn_l;
			}

			RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_TASK_IMPL_NEXT_INTERVAL,"xf",vpn,ck_interval_msec);
		}

	}else{

		time_t now;

next_waiting_interval:

		now = _rhp_get_time();

		if( waiting_hold_time &&
				!vpn->mobike.init.cand_path_maps_active &&
				(vpn->mobike.init.rt_ck_hold_start_time + waiting_hold_time > now) &&
				(waiting_max_retries ? (vpn->mobike.init.rt_ck_waiting <= waiting_max_retries) : 1) ){

			if( cur_idx >= (vpn->mobike.init.cand_path_maps_num - 1) ){
				cur_idx = vpn->mobike.init.cand_path_maps_num - 1;
			}
			vpn->mobike.init.cand_path_maps_cur_idx = cur_idx;


			if( vpn->mobike.init.rt_ck_waiting == 0 ){
				rhp_ikev2_g_statistics_inc(mobike_init_net_outage_times);
			}
			vpn->mobike.init.rt_ck_waiting++;
			vpn->mobike.init.cand_path_maps_retries = 0;


		  rhp_timer_reset(&(vpn->mobike.init.rt_ck_waiting_timer));

		  timer_vpn_ref = rhp_vpn_hold_ref(vpn);

		  err = rhp_timer_add_with_ctx(&(vpn->mobike.init.rt_ck_waiting_timer),(time_t)waiting_interval,timer_vpn_ref);
		  if( err ){
				RHP_BUG("%d",err);
				rhp_vpn_unhold(timer_vpn_ref);
				vpn->mobike.init.rt_ck_waiting = 0;
				goto error_vpn_l;
			}

			RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_TASK_IMPL_WAITING_NEXT_INTERVAL,"x",vpn);

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_ROUTABILITY_CHECK_WAITING,"Vd",vpn,vpn->mobike.init.rt_ck_waiting);

		}else{

			RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_TASK_IMPL_RETRY_FINISHED,"x",vpn);
			finished = 1;
		}
	}


	if( finished ){

		err = _rhp_ikev2_mobike_i_rt_ck_finieshed(vpn);
		if( err ){
			goto error_vpn_l;
		}

		vpn->mobike.init.rt_ck_pending = 0;
		vpn->mobike.init.rt_ck_waiting = 0;
		vpn->mobike.init.cand_path_maps_active = 0;

		_rhp_ikev2_mobike_i_clear_cand_path_maps_res(vpn);

		if( vpn->mobike.init.cand_path_maps_num ){

			vpn->mobike.init.cand_path_maps_result
			= (rhp_mobike_path_map*)_rhp_malloc(sizeof(rhp_mobike_path_map)*vpn->mobike.init.cand_path_maps_num);

			if( vpn->mobike.init.cand_path_maps_result ){

				memcpy(vpn->mobike.init.cand_path_maps_result,
							 vpn->mobike.init.cand_path_maps,sizeof(rhp_mobike_path_map)*vpn->mobike.init.cand_path_maps_num);

				vpn->mobike.init.cand_path_maps_num_result = vpn->mobike.init.cand_path_maps_num;

			}else{
				RHP_BUG("");
			}
		}

		rhp_ikev2_mobike_free_path_maps(vpn);

	}else{

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_ROUTABILITY_CHECK_CONT,"Vd",vpn,vpn->mobike.init.cand_path_maps_retries);

		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_TASK_IMPL_NOT_FINISHED,"x",vpn);
	}


	RHP_UNLOCK(&(vpn->lock));
	rhp_vpn_unhold(ctx);

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_TASK_IMPL_RTRN,"xd",vpn,by_waiting_timer);
	return;


error_vpn_l:

	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_ROUTABILITY_CHECK_CONT_ERR,"VE",vpn,err);

	rhp_ikev2_mobike_free_path_maps(vpn);

	rhp_vpn_destroy(vpn);

	RHP_UNLOCK(&(vpn->lock));
	rhp_vpn_unhold(ctx);

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_TASK_IMPL_ERR,"xd",vpn,by_waiting_timer);
  return;
}

void rhp_ikev2_mobike_i_rt_ck_waiting_timer(void* ctx,rhp_timer *timer)
{
	rhp_vpn* vpn = RHP_VPN_REF(ctx);

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_WAITING_TIMER,"xx",vpn,timer);

	_rhp_ikev2_mobike_i_rt_ck_task_impl(ctx,1);

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_WAITING_TIMER_RTRN,"xx",vpn,timer);

	return;
}

static void _rhp_ikev2_mobike_i_rt_ck_task(void* ctx)
{
	rhp_vpn* vpn = RHP_VPN_REF(ctx);

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_TASK,"x",vpn);

	_rhp_ikev2_mobike_i_rt_ck_task_impl(ctx,0);

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_TASK_RTRN,"x",vpn);
	return;
}

static void _rhp_ikev2_mobike_i_rt_ck_init_task(void* ctx)
{
	int err = -EINVAL;
	rhp_vpn* vpn = RHP_VPN_REF(ctx);
	rhp_vpn_realm* rlm = NULL;
	rhp_ikesa* tx_ikesa = NULL;
	rhp_ikev2_mesg* tx_ikemesg = NULL;
	long ck_interval_msec;
	int waiting_hold_time = 0, waiting_interval = 0;
	int no_cand_maps = 0;

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_INIT_TASK,"x",vpn);

	RHP_LOCK(&(vpn->lock));

	if( !_rhp_atomic_read(&(vpn->is_active)) ){
		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_INIT_TASK_VPN_NOT_ACTIVE,"x",vpn);
		goto error_vpn_l;
	}

	vpn->dump("_rhp_ikev2_mobike_i_rt_ck_init_task",vpn);

	{
		tx_ikesa = _rhp_ikev2_mobike_get_active_ikesa(vpn);

		if( tx_ikesa == NULL ){
			err = -ENOENT;
			RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_INIT_TASK_NO_IKESA,"x",vpn);
			goto error_vpn_l;
		}
	}


	rlm = vpn->rlm;
	if( rlm == NULL ){
		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_INIT_TASK_NO_RLM,"x",vpn);
		goto error_vpn_l;
	}

	{
		RHP_LOCK(&(rlm->lock));

		if( !_rhp_atomic_read(&(rlm->is_active)) ){
			err = -ENOENT;
			RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_INIT_TASK_RLM_NOT_ACTIVE,"xx",vpn,rlm);
			goto error_rlm_l;
		}


		waiting_hold_time = rlm->mobike.init_hold_time;
		waiting_interval = rlm->mobike.init_hold_ka_interval;


		vpn->mobike.init.cand_path_maps_cur_idx = 0;

		err = _rhp_ikev2_mobike_i_build_path_maps(vpn,rlm);
		if( err ){

			RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_INIT_TASK_BUILD_PATH_ERR,"xE",vpn,err);

			no_cand_maps = 1;
			err = 0;
		}

		RHP_UNLOCK(&(rlm->lock));
	}


	if( tx_ikesa->req_retx_ikemesg == NULL ){

		tx_ikemesg = rhp_ikev2_new_mesg_tx(RHP_PROTO_IKE_EXCHG_INFORMATIONAL,0,0);
		if( tx_ikemesg == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error_vpn_l;
		}

		tx_ikemesg->activated++;
		tx_ikemesg->mobike_probe_req = 1;

		if( rhp_gcfg_ikev2_mobike_rt_check_on_nat_t_port ){
			tx_ikemesg->tx_from_nat_t_port = 1;
		}

		// Sending a request may fail. But, tx_ikemesg is serialized anyway.
    rhp_ikev2_send_request(vpn,tx_ikesa,tx_ikemesg,RHP_IKEV2_MESG_HANDLER_MOBIKE); // (**o**)

    if( tx_ikesa->req_retx_ikemesg && tx_ikesa->req_retx_ikemesg->tx_pkt ){

    	rhp_packet* pkt_d = tx_ikesa->req_retx_ikemesg->tx_pkt;

    	if( pkt_d->type == RHP_PKT_IPV4_IKE ){
    		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_ROUTABILITY_CHECK_TX_PROBE_1,"VP4W4W",vpn,tx_ikesa,pkt_d->l3.iph_v4->src_addr,pkt_d->l4.udph->src_port,pkt_d->l3.iph_v4->dst_addr,pkt_d->l4.udph->dst_port);
    	}else if( pkt_d->type == RHP_PKT_IPV6_IKE ){
    		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_ROUTABILITY_CHECK_TX_PROBE_1_V6,"VP6W6W",vpn,tx_ikesa,pkt_d->l3.iph_v6->src_addr,pkt_d->l4.udph->src_port,pkt_d->l3.iph_v6->dst_addr,pkt_d->l4.udph->dst_port);
    	}
    }

	}else{

		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_INIT_TASK_USE_RETX_PKT_FOR_PROBE,"xxx",vpn,tx_ikesa,tx_ikesa->req_retx_ikemesg);

		if( tx_ikesa->req_retx_ikemesg->mobike_update_sa_addr ){
			err = RHP_STATUS_IKEV2_MOBIKE_UPDATE_SA_ADDR_NOT_COMP;
			goto error_vpn_l;
		}
	}

	{
		if( tx_ikesa->req_retx_ikemesg == NULL ){ // Serialization failed at (**o**) ???
			err = -EINVAL;
			RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_INIT_TASK_NO_RETX_PKT_SERIALIZED,"xxx",vpn,tx_ikesa,tx_ikesa->req_retx_ikemesg);
			goto error_vpn_l;
		}

		if( tx_ikesa->req_retx_ikemesg->tx_pkt == NULL ){
			err = -EINVAL;
			RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_INIT_TASK_NO_RETX_PKT_SERIALIZED_2,"xxx",vpn,tx_ikesa,tx_ikesa->req_retx_ikemesg);
			goto error_vpn_l;
		}


		tx_ikesa->timers->quit_retransmit_timer(vpn,tx_ikesa);


		if( vpn->mobike.init.tx_probe_pkt_ref ){
			rhp_pkt_unhold(vpn->mobike.init.tx_probe_pkt_ref);
		}

		vpn->mobike.init.tx_probe_pkt_ref = rhp_pkt_hold_ref(tx_ikesa->req_retx_ikemesg->tx_pkt);
	}


	if( no_cand_maps ){

		time_t now = _rhp_get_time();

		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_INIT_TASK_NO_CAND,"xd",vpn,waiting_hold_time);

		if( waiting_hold_time &&
				(vpn->mobike.init.rt_ck_hold_start_time + waiting_hold_time > now) ){

			rhp_vpn_ref* vpn_ref;

			if( vpn->mobike.init.rt_ck_waiting == 0 ){
				rhp_ikev2_g_statistics_inc(mobike_init_net_outage_times);
			}
			vpn->mobike.init.rt_ck_waiting++;
			vpn->mobike.init.cand_path_maps_retries = 0;


		  rhp_timer_reset(&(vpn->mobike.init.rt_ck_waiting_timer));

			vpn_ref = rhp_vpn_hold_ref(vpn);

		  err = rhp_timer_add_with_ctx(&(vpn->mobike.init.rt_ck_waiting_timer),(time_t)waiting_interval,vpn_ref);
		  if( err ){

		  	vpn->mobike.init.rt_ck_waiting = 0;

		  	rhp_vpn_unhold(vpn_ref);

				RHP_BUG("");
				err = -EINVAL;

				goto error_vpn_l;
			}

			RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_INIT_TASK_WAITING_NO_CAND,"x",vpn);

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_ROUTABILITY_CHECK_WAITING_NO_CAND,"Vd",vpn,vpn->mobike.init.rt_ck_waiting);

		}else{

			RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_INIT_TASK_NO_CAND_DONT_HOLD_VPN,"x",vpn);

			err = -ENOENT;
			goto error_vpn_l;
		}

	}else{

		if( tx_ikemesg == NULL ){

			//
			// Use on-the-fly request as probe packet.
			//

			rhp_mobike_path_map* pmap;

			RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_INIT_TASK_TX_RETX_PKT_AS_PROBE,"xxdd",vpn,tx_ikesa,vpn->mobike.init.cand_path_maps_cur_idx,vpn->mobike.init.cand_path_maps_num);

			if( vpn->mobike.init.cand_path_maps_cur_idx >= vpn->mobike.init.cand_path_maps_num ){
				RHP_BUG("");
				err = -EINVAL;
				goto error_vpn_l;
			}


			pmap = &(vpn->mobike.init.cand_path_maps[vpn->mobike.init.cand_path_maps_cur_idx]);

			_rhp_ikev2_mobike_i_tx_probe_pkt(vpn,pmap);

		}else{

			// A probe_pkt is already transmitted at (**o**).
		}


		{
			rhp_vpn_ref* vpn_ref;

			if( vpn->mobike.init.cand_path_maps_num == 1 ){
				ck_interval_msec = (long)rhp_gcfg_ikev2_mobike_rt_check_retry_interval_msec;
			}else{
				ck_interval_msec = (long)rhp_gcfg_ikev2_mobike_rt_check_interval_msec;
			}

			if( ck_interval_msec > 999 ){
				ck_interval_msec = 999;
			}else if( ck_interval_msec < RHP_IKEV2_MOBIKE_RT_CK_MIN_INTERVAL_MSEC ){
				ck_interval_msec = RHP_IKEV2_MOBIKE_RT_CK_MIN_INTERVAL_MSEC;
			}

			vpn_ref = rhp_vpn_hold_ref(vpn);

			err = rhp_timer_oneshot_msec(_rhp_ikev2_mobike_i_rt_ck_task,vpn_ref,ck_interval_msec);
			if( err ){
				RHP_BUG("%d",err);
				rhp_vpn_unhold(vpn_ref);
				goto error_vpn_l;
			}
		}
	}

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_ROUTABILITY_CHECK_INIT,"VP",vpn,tx_ikesa);

	RHP_UNLOCK(&(vpn->lock));
	rhp_vpn_unhold(ctx);


	if( tx_ikemesg ){
  	rhp_ikev2_unhold_mesg(tx_ikemesg);
  	tx_ikemesg = NULL;
  }


	rhp_http_bus_broadcast_async(vpn->vpn_realm_id,1,1,
			rhp_ui_http_vpn_mobike_i_rt_check_start_serialize,
			rhp_ui_http_vpn_bus_btx_async_cleanup,(void*)rhp_vpn_hold_ref(vpn)); // (*x*)


	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_INIT_TASK_RTRN,"xx",vpn,tx_ikesa);
	return;

error_rlm_l:
	if( rlm ){
		RHP_UNLOCK(&(rlm->lock));
	}
error_vpn_l:
	if( vpn ){

		RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_ROUTABILITY_CHECK_INIT_ERR,"VPE",vpn,tx_ikesa,err);

		rhp_ikev2_mobike_free_path_maps(vpn);

		rhp_vpn_destroy(vpn);

		RHP_UNLOCK(&(vpn->lock));
		rhp_vpn_unhold(ctx);
	}

  if( tx_ikemesg ){
  	rhp_ikev2_unhold_mesg(tx_ikemesg);
  }

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_CK_INIT_TASK_ERR,"xxE",vpn,tx_ikesa,err);
  return;
}

int rhp_ikev2_mobike_i_start_routability_check(rhp_vpn* vpn,rhp_ikesa* ikesa,int wait_conv_interval)
{
	int err = -EINVAL;

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_START_ROUTABILITY_CHECK,"xxd",vpn,ikesa,wait_conv_interval);

	if( !vpn->exec_mobike ){
		err = -EINVAL;
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_START_ROUTABILITY_CHECK_MOBIKE_DISABLED,"x",vpn);
		goto error;
	}

	if( vpn->origin_side != RHP_IKE_INITIATOR ){
		err = -EINVAL;
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_START_ROUTABILITY_CHECK_NOT_INITIATOR,"x",vpn);
		goto error;
	}

	if( vpn->mobike.init.rt_ck_pending ){
		err = 0;
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_START_ROUTABILITY_CHECK_NOT_RT_CK_PENDING,"x",vpn);
		goto ignored;
	}


	if( ikesa == NULL ){

		ikesa = _rhp_ikev2_mobike_get_active_ikesa(vpn);
		if( ikesa == NULL ){
			err = RHP_STATUS_INVALID_STATE;
			RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_START_ROUTABILITY_CHECK_NO_IKESA,"x",vpn);
			goto error;
		}

	}else{

		if( ikesa->state != RHP_IKESA_STAT_ESTABLISHED &&
				ikesa->state != RHP_IKESA_STAT_REKEYING ){
			RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_START_ROUTABILITY_CHECK_BAD_IKESA_STATE,"xxLd",vpn,ikesa,"IKESA_STAT",ikesa->state);
			err = RHP_STATUS_INVALID_STATE;
			goto error;
		}
	}

	if( ikesa->req_retx_ikemesg &&
			ikesa->req_retx_ikemesg->mobike_update_sa_addr ){
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_START_ROUTABILITY_CHECK_UPDATE_SA_ADDR_TXN_NOT_COMP,"xxx",vpn,ikesa,ikesa->req_retx_ikemesg);
		err = RHP_STATUS_IKEV2_MOBIKE_UPDATE_SA_ADDR_NOT_COMP;
		goto error;
	}


	rhp_ikev2_mobike_free_path_maps(vpn);

	vpn->mobike.init.nat_t_src_hash_rx_times = 0;
	memset(vpn->mobike.init.rx_nat_t_src_hash,0,RHP_IKEV2_NAT_T_HASH_LEN);

	vpn->mobike.init.cand_path_maps_retries = 0;
	vpn->mobike.init.cand_path_maps_active = 0;

	vpn->mobike.init.rt_ck_pending = 1;
	vpn->mobike.init.rt_ck_hold_start_time = _rhp_get_time();

	{
		rhp_vpn_ref* vpn_ref = rhp_vpn_hold_ref(vpn);

		err = rhp_timer_oneshot(_rhp_ikev2_mobike_i_rt_ck_init_task,vpn_ref,(time_t)wait_conv_interval);
		if( err ){
			RHP_BUG("%d",err);
			vpn->mobike.init.rt_ck_pending = 0;
			rhp_vpn_unhold(vpn_ref);
			goto error;
		}
	}

	RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_START_ROUTABILITY_CHECK,"VP",vpn,ikesa);
	vpn->mobike_exec_rt_ck_times++;

	rhp_ikev2_g_statistics_inc(mobike_init_exec_rt_check_times);

ignored:
	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_START_ROUTABILITY_CHECK_RTRN,"x",vpn);
	return 0;

error:
	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_MOBIKE_I_START_ROUTABILITY_CHECK_ERR,"VPE",vpn,ikesa,err);
	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_START_ROUTABILITY_CHECK_ERR,"xE",vpn,err);
	return err;
}


struct _rhp_ikev2_mobike_ifc_ctx {

	u8 tag[4]; // '#MBI'

	struct _rhp_ikev2_mobike_ifc_ctx* next;

	int if_index;
};
typedef struct _rhp_ikev2_mobike_ifc_ctx	rhp_ikev2_mobike_ifc_ctx;

static rhp_ikev2_mobike_ifc_ctx* _rhp_ikev2_mobike_ifc_ctx_list = NULL;

static rhp_ikev2_mobike_ifc_ctx* _rhp_ikev2_mobike_ifcx_delete(int if_index)
{
	rhp_ikev2_mobike_ifc_ctx *ifcx, *ifcx_p = NULL;

	ifcx = _rhp_ikev2_mobike_ifc_ctx_list;
	while( ifcx ){

		if( ifcx->if_index == if_index ){
			break;
		}

		ifcx_p = ifcx;
		ifcx = ifcx->next;
	}

	if( ifcx ){

		if( ifcx_p ){
			ifcx_p->next = ifcx->next;
		}else{
			_rhp_ikev2_mobike_ifc_ctx_list = ifcx->next;
		}

	}else{

		RHP_BUG("%d",if_index);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_IFCX_DELETE,"dx",if_index,ifcx);
	return ifcx;
}

static rhp_ikev2_mobike_ifc_ctx* _rhp_ikev2_mobike_ifcx_get(int if_index)
{
	rhp_ikev2_mobike_ifc_ctx *ifcx;

	ifcx = _rhp_ikev2_mobike_ifc_ctx_list;
	while( ifcx ){

		if( ifcx->if_index == if_index ){
			break;
		}

		ifcx = ifcx->next;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_IFCX_GET,"dx",if_index,ifcx);
	return ifcx;
}

static rhp_ikev2_mobike_ifc_ctx* _rhp_ikev2_mobike_ifcx_alloc(int if_index)
{
	rhp_ikev2_mobike_ifc_ctx* ifcx = (rhp_ikev2_mobike_ifc_ctx*)_rhp_malloc(sizeof(rhp_ikev2_mobike_ifc_ctx));
	if( ifcx == NULL ){
		RHP_BUG("");
		goto error;
	}

	memset(ifcx,0,sizeof(rhp_ikev2_mobike_ifc_ctx));

	ifcx->tag[0] = '#';
	ifcx->tag[1] = 'M';
	ifcx->tag[2] = 'B';
	ifcx->tag[3] = 'I';

	ifcx->if_index = if_index;

	return ifcx;

error:
	return NULL;
}


int rhp_ikev2_mobike_i_rt_invoke_waiting_timer(rhp_vpn* vpn)
{
	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_INVOKE_WAITING_TIMER,"xd",vpn,vpn->mobike.init.rt_ck_waiting);

	if( vpn->exec_mobike &&
  		vpn->origin_side == RHP_IKE_INITIATOR &&
  		vpn->mobike.init.rt_ck_waiting ){

		if( rhp_timer_pending(&(vpn->mobike.init.rt_ck_waiting_timer)) ){

			rhp_timer_update(&(vpn->mobike.init.rt_ck_waiting_timer),0);
		}

	}else{
		RHP_BUG("");
	}

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_RT_INVOKE_WAITING_TIMER_RTRN,"x",vpn);
	return 0;
}

static int _rhp_ikev2_mobike_ifc_notifier_cb(rhp_vpn* vpn,void* ctx)
{
	int err = -EINVAL;
	rhp_ifc_entry* ifc = (rhp_ifc_entry*)ctx;
	int do_rt_ck = 0;

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_IFC_NOTIFIER_CB,"xxddd",vpn,ifc,vpn->exec_mobike,vpn->mobike.init.rt_ck_pending,vpn->mobike.init.rt_ck_waiting);


  RHP_LOCK(&(vpn->lock));

	if( vpn->origin_side != RHP_IKE_INITIATOR ){
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_IFC_NOTIFIER_CB_VPN_NOT_INITIATOR,"xx",vpn,ifc);
		goto ignored;
	}

	if( !vpn->exec_mobike ){
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_IFC_NOTIFIER_CB_MOBIKE_DISABLED,"xx",vpn,ifc);
		goto ignored;
	}


	if( vpn->mobike.init.rt_ck_waiting ){

		RHP_LOCK(&(ifc->lock));
		{
			if( rhp_ifc_is_active_peer_addr(ifc,&(vpn->peer_addr)) ){
				do_rt_ck = 1;
			}
		}
		RHP_UNLOCK(&(ifc->lock));

	}else{

		int checked_if_index;

		RHP_LOCK(&(ifc->lock));

		checked_if_index = ifc->if_index;

		if( vpn->local.if_info.if_index != checked_if_index ){

			RHP_UNLOCK(&(ifc->lock));

			if( vpn->rlm ){

				RHP_LOCK(&(vpn->rlm->lock));
				{
					do_rt_ck = vpn->rlm->my_interface_cmp_priority(vpn->rlm,
										 	 vpn->local.if_info.if_index,checked_if_index,&(vpn->peer_addr));
				}
				RHP_UNLOCK(&(vpn->rlm->lock));
			}

			if( do_rt_ck ){
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_MOBIKE_IF_STATE_CHANGED_EQ_OR_HIGHER_IF_EXISTS,"sdsd",vpn->local.if_info.if_name,vpn->local.if_info.if_index,ifc->if_name,ifc->if_index);
			}

		}else{

			rhp_ifc_addr* ifc_addr
				= ifc->get_addr(ifc,vpn->local.if_info.addr_family,vpn->local.if_info.addr.raw);

			if( ifc_addr ){

				if( ((ifc_addr->addr.addr_family == AF_INET &&
						  vpn->local.if_info.addr.v4 == ifc_addr->addr.addr.v4) ||
						 (ifc_addr->addr.addr_family == AF_INET6 &&
						  rhp_ipv6_is_same_addr(vpn->local.if_info.addr.v6,ifc_addr->addr.addr.v6))) &&
						rhp_ifc_is_active(ifc,ifc_addr->addr.addr_family,ifc_addr->addr.addr.raw) ){

					RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_IFC_NOTIFIER_CB_MOBIKE_IFC_NOT_CHANGED,"xx",vpn,ifc);

				}else{

					do_rt_ck = 1;
				}

			}else{

				RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_IFC_NOTIFIER_CB_MOBIKE_IFC_NO_IFC_ADDR,"xx",vpn,ifc);

				do_rt_ck = 1;
			}

			RHP_UNLOCK(&(ifc->lock));
		}
  }

	if( do_rt_ck ){

  	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_IFC_NOTIFIER_CB_EXEC,"xxd",vpn,ifc,vpn->mobike.init.rt_ck_waiting);

		if( !vpn->mobike.init.rt_ck_waiting ){

			err = rhp_ikev2_mobike_i_start_routability_check(vpn,NULL,0);
			if( err ){
				goto error;
			}

		}else{

			rhp_ikev2_mobike_i_rt_invoke_waiting_timer(vpn);
		}

	}else{

		RHP_LOCK(&(ifc->lock));
		{
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_MOBIKE_IF_STATE_CHANGED_BUT_IGNORED,"sdsd",vpn->local.if_info.if_name,vpn->local.if_info.if_index,ifc->if_name,ifc->if_index);
		}
		RHP_UNLOCK(&(ifc->lock));
	}

ignored:
error:
  RHP_UNLOCK(&(vpn->lock));

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_IFC_NOTIFIER_CB_RTRN,"xx",vpn,ifc);
  return 0;
}

static void _rhp_ikev2_mobike_ifc_notifier_task(void* ctx)
{
	int err = -EINVAL;
	int if_index = (int)ctx;
	rhp_ifc_entry* ifc = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_IFC_NOTIFIER_TASK,"d",if_index);

	ifc = rhp_ifc_get_by_if_idx(if_index);
	if( ifc == NULL ){
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_IFC_NOTIFIER_TASK_NO_IFC,"d",if_index);
		err = -ENOENT;
		goto error;
	}

	err = rhp_vpn_enum(0,_rhp_ikev2_mobike_ifc_notifier_cb,ifc);
	if( err ){
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_IFC_NOTIFIER_TASK_ENUM_VPN_ERR,"dE",if_index,err);
		goto error;
	}


error:
	{
		rhp_ikev2_mobike_ifc_ctx* ifcx;

		RHP_LOCK(&(_rhp_ikev2_mobike_lock));

		ifcx = _rhp_ikev2_mobike_ifcx_delete(if_index);
		if( ifcx ){
			_rhp_free(ifcx);
		}

		RHP_UNLOCK(&(_rhp_ikev2_mobike_lock));
	}

	if( ifc ){
		rhp_ifc_unhold(ifc);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_IFC_NOTIFIER_TASK_RTRN,"dE",if_index,err);
	return;
}

static void _rhp_ikev2_mobike_ifc_notifier(int event,rhp_ifc_entry* ifc,
		rhp_if_entry* new_info,rhp_if_entry* old_info,void* ctx)
{
	int err = -EINVAL;
	rhp_ikev2_mobike_ifc_ctx* ifcx = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_IFC_NOTIFIER,"Ldxxxx","IFC_EVT",event,ifc,new_info,old_info,ctx);

	if( !_rhp_atomic_read(&(ifc->is_active)) ){
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_IFC_NOT_ACTIVE,"Ldxxx","IFC_EVT",event,ifc,old_info,ctx);
		return;
	}

	if( old_info == NULL ){
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_IFC_NOTIFIER_IGNORED,"Ldxxx","IFC_EVT",event,ifc,old_info,ctx);
		return;
	}

  if( strstr(old_info->if_name,RHP_VIRTUAL_IF_NAME) || !strcmp(old_info->if_name,"lo") ){
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_IFC_NOTIFIER_NOT_INTERESTED_IF,"Ldxxs","IFC_EVT",event,ifc,old_info,old_info->if_name);
		return;
  }

	{
		RHP_LOCK(&(ifc->lock));

		if( !rhp_if_entry_cmp(new_info,old_info) ){

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_MOBIKE_IF_STATE_CHANGED_BUT_IGNORED_0,"Lsd","IFC_EVT",event,old_info->if_name,old_info->if_index);

			RHP_UNLOCK(&(ifc->lock));
			RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_IFC_NOTIFIER_NOT_CHANGED,"Ldxxs","IFC_EVT",event,ifc,old_info,old_info->if_name);
			return;
		}

		RHP_UNLOCK(&(ifc->lock));
	}


	RHP_LOCK(&(_rhp_ikev2_mobike_lock));
	{

		ifcx = _rhp_ikev2_mobike_ifcx_get(old_info->if_index);
		if( ifcx ){

			// Don't goto error_l and free ifcx here!

			RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_IFC_NOTIFIER_ALREADY_PENDING,"xsd",ifc,old_info->if_name,old_info->if_index);

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_MOBIKE_IF_STATE_CHANGED_PENDING,"sd",old_info->if_name,old_info->if_index);

			RHP_UNLOCK(&(_rhp_ikev2_mobike_lock));

			return;
		}


		ifcx = _rhp_ikev2_mobike_ifcx_alloc(old_info->if_index);
		if( ifcx == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error_l;
		}


		err = rhp_timer_oneshot(_rhp_ikev2_mobike_ifc_notifier_task,(void*)old_info->if_index,
			(time_t)rhp_gcfg_ikev2_mobike_rt_check_convergence_interval);

		if( !err ){

			ifcx->next = _rhp_ikev2_mobike_ifc_ctx_list;
			_rhp_ikev2_mobike_ifc_ctx_list = ifcx;

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_MOBIKE_IF_STATE_CHANGED,"sd",old_info->if_name,ifcx->if_index);

		}else{

			RHP_BUG("");
			goto error_l;
		}
	}
	RHP_UNLOCK(&(_rhp_ikev2_mobike_lock));


	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_IFC_NOTIFIER_RTRN,"xx",ifc,ifcx);
	return;

error_l:
	if( ifcx ){

		_rhp_ikev2_mobike_ifcx_delete(old_info->if_index);
		_rhp_free(ifcx);
	}

	RHP_UNLOCK(&(_rhp_ikev2_mobike_lock));

	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_IKE_MOBIKE_IF_STATE_CHANGED_ERR,"sdE",old_info->if_name,old_info->if_index,err);

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_IFC_NOTIFIER_ERR,"xE",ifc,err);
	return;
}

int rhp_ikev2_mobike_i_start_ui(unsigned long rlm_id,rhp_ikev2_id* peer_id,
		u8* vpn_unique_id,rhp_ui_ctx* ui_info)
{
  int err = -EINVAL;
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;
  int unique_id_len = (vpn_unique_id ? RHP_VPN_UNIQUE_ID_SIZE : 0);

  if( ui_info ){
  	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_START_UI,"uxxLdsuqp",rlm_id,peer_id,ui_info,"UI",ui_info->ui_type,ui_info->user_name,ui_info->vpn_realm_id,ui_info->http.http_bus_sess_id,unique_id_len,vpn_unique_id);
  }else{
  	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_START_UI_NO_UI_INFO,"uxxp",rlm_id,peer_id,ui_info,unique_id_len,vpn_unique_id);
  }
  rhp_ikev2_id_dump("mobike_i_start_ui.peer_id",peer_id);

  if( (peer_id == NULL) && (vpn_unique_id == NULL) ){
  	RHP_BUG("");
  	goto error;
  }

  if( vpn_unique_id ){

  	vpn_ref = rhp_vpn_get_by_unique_id(vpn_unique_id);

	}else if( peer_id && (peer_id->type != RHP_PROTO_IKE_ID_ANY) ){

		if( peer_id->alt_id ){
			vpn_ref = rhp_vpn_get(rlm_id,peer_id,NULL);
		}else{
			vpn_ref = rhp_vpn_get_no_alt_id(rlm_id,peer_id,NULL);
		}
	}
	vpn = RHP_VPN_REF(vpn_ref);

	if( vpn == NULL ){
		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_START_UI_NO_VPN,"u",rlm_id);
		goto error;
	}

	if( vpn->vpn_realm_id != rlm_id ){
		err = -EPERM;
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_START_UI_INVALID_RLM_ID,"uu",rlm_id,vpn->vpn_realm_id);
  	rhp_vpn_unhold(vpn);
		goto error;
	}


	RHP_LOCK(&(vpn->lock));
	{
		RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_START_UI_VPN,"xpuxddd",vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm,vpn->ikesa_num,vpn->childsa_num,vpn->exec_mobike);
		rhp_ikev2_id_dump("vpn->my_id",&(vpn->my_id));
		rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));

		if( !_rhp_atomic_read(&(vpn->is_active)) ){
			RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_START_UI_OLD_VPN_NOT_ACTIVE,"x",vpn);
			err = -EINVAL;
			goto error_vpn_l;
		}

		if( !vpn->exec_mobike ){
			RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_START_UI_MOBIKE_DISABLED,"x",vpn);
			err = -EINVAL;
			goto error_vpn_l;
		}

		if( !vpn->mobike.init.rt_ck_waiting ){

			if( vpn->mobike.init.rt_ck_pending ){
				RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_START_UI_RT_CK_PENDING,"x",vpn);
				err = -EBUSY;
				goto error_vpn_l;
			}

			err = rhp_ikev2_mobike_i_start_routability_check(vpn,NULL,0);
			if( err ){
				goto error_vpn_l;
			}

		}else{

			if( rhp_timer_pending(&(vpn->mobike.init.rt_ck_waiting_timer)) ){

				rhp_timer_update(&(vpn->mobike.init.rt_ck_waiting_timer),0);
			}
		}

		RHP_LOG_I(RHP_LOG_SRC_VPNMNG,vpn->vpn_realm_id,RHP_LOG_ID_MOBIKE_I_START_RT_CHECK_BY_UI,"IAs",&(vpn->peer_id),&(vpn->peer_addr),vpn->peer_fqdn);
	}
	RHP_UNLOCK(&(vpn->lock));

	rhp_vpn_unhold(vpn_ref);

  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_START_UI_RTRN,"uxxx",rlm_id,peer_id,ui_info,vpn);
  return 0;

error_vpn_l:
  if( vpn ){
  	if( err == -EBUSY ){
  		RHP_LOG_N(RHP_LOG_SRC_VPNMNG,vpn->vpn_realm_id,RHP_LOG_ID_MOBIKE_I_START_RT_CHECK_BY_UI_PENDING,"IAs",&(vpn->peer_id),&(vpn->peer_addr),vpn->peer_fqdn);
  	}else{
  		RHP_LOG_E(RHP_LOG_SRC_VPNMNG,vpn->vpn_realm_id,RHP_LOG_ID_MOBIKE_I_START_RT_CHECK_BY_UI_ERR,"IAs",&(vpn->peer_id),&(vpn->peer_addr),vpn->peer_fqdn);
  	}
  	RHP_UNLOCK(&(vpn->lock));
  	rhp_vpn_unhold(vpn_ref);
  }

error:
  RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_I_START_UI_ERR,"uxxxE",rlm_id,peer_id,ui_info,vpn,err);
  return err;
}


int rhp_ikev2_mobike_init()
{

	rhp_ifc_notifiers[RHP_IFC_NOTIFIER_MOBIKE].callback = _rhp_ikev2_mobike_ifc_notifier;
  rhp_ifc_notifiers[RHP_IFC_NOTIFIER_MOBIKE].ctx = NULL;
  RHP_LINE("rhp_ikev2_mobike_init() : 0x%x,0x%x",_rhp_ikev2_mobike_ifc_notifier,NULL);

  _rhp_mutex_init("MBK",&(_rhp_ikev2_mobike_lock));

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_INIT,"");
  return 0;
}

int rhp_ikev2_mobike_cleanup()
{

  _rhp_mutex_destroy(&(_rhp_ikev2_mobike_lock));

	RHP_TRC(0,RHPTRCID_IKEV2_MOBIKE_CLEANUP,"");
	return 0;
}


